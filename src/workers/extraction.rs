use std::time::Duration;

use base64::Engine;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::domain::IntegrationError;
use crate::integrations::odoo::OdooClient;
use crate::integrations::paperless::PaperlessClient;
use crate::persistence::{LeasedOperation, Store};
use crate::worker::{extraction_broker, secret, service};

pub(crate) async fn invoice(
    store: &Store,
    operation: &LeasedOperation,
) -> Result<(), IntegrationError> {
    let workshop = operation
        .workshop_id
        .ok_or(IntegrationError::ContractDrift)?;
    let database_ready = sqlx::query_scalar::<_, bool>(
        "select exists(select 1 from control.odoo_databases where workshop_id=$1 and kind='primary' and state='ready' and deleted_at is null)",
    )
    .bind(workshop)
    .fetch_one(store.pool())
    .await
    .map_err(|_| IntegrationError::Unavailable)?;
    if !database_ready {
        return Err(IntegrationError::Unavailable);
    }
    let document_id = operation
        .payload
        .get("document_id")
        .and_then(Value::as_i64)
        .ok_or(IntegrationError::ContractDrift)?;
    let (paperless_url, paperless_ref, _) = service(store, workshop, "paperless").await?;
    let paperless = PaperlessClient::new(
        &paperless_url,
        &secret(&paperless_ref)?,
        Duration::from_secs(30),
    )
    .map_err(|_| IntegrationError::ContractDrift)?;
    let metadata = paperless.document(document_id).await?;
    let (mimetype, source) = paperless.original(document_id).await?;
    let slug = sqlx::query_scalar::<_, String>("select slug from control.workshops where id=$1")
        .bind(workshop)
        .fetch_optional(store.pool())
        .await
        .map_err(|_| IntegrationError::Unavailable)?
        .ok_or(IntegrationError::NotFound)?;
    let paperless_public_url = format!(
        "https://docs-{slug}.{}/documents/{document_id}/details",
        crate::worker::configuration("CONTROL_TENANT_DOMAIN")?
    );
    let digest = format!("{:x}", Sha256::digest(&source));
    let (provider, invoice, confidence, pages) = if let Some(invoice) =
        crate::invoice::structured(&source)
    {
        ("structured", invoice, json!({}), 1_i64)
    } else {
        if !module_enabled(store, workshop, "azure-invoice-extraction").await? {
            tracing::info!(
                workshop = %workshop,
                "unstructured invoice retained in Paperless because Azure extraction is disabled"
            );
            return Ok(());
        }
        reserve_azure(
            store,
            operation.id,
            workshop,
            estimated_pages(&source, &mimetype),
        )
        .await?;
        throttle_azure_submission(store).await?;
        let result = extraction_broker(Duration::from_secs(120))?
            .invoice(&source, &mimetype)
            .await?;
        let invoice = result
            .get("invoice")
            .cloned()
            .ok_or(IntegrationError::ContractDrift)?;
        let confidence = result
            .get("confidence")
            .cloned()
            .ok_or(IntegrationError::ContractDrift)?;
        let pages = result
            .get("pages")
            .and_then(Value::as_i64)
            .ok_or(IntegrationError::ContractDrift)?;
        ("azure", invoice, confidence, pages)
    };
    let requires_review = crate::invoice::requires_review(&invoice, &confidence);
    let (odoo_url, odoo_ref, database_ref) = service(store, workshop, "odoo").await?;
    let odoo = OdooClient::new(
        &odoo_url,
        &secret(&odoo_ref)?,
        database_ref.as_deref(),
        Duration::from_secs(45),
    )
    .map_err(|_| IntegrationError::ContractDrift)?;
    odoo.capture_invoice(&json!({"operation_key":format!("invoice:{workshop}:{document_id}:{digest}"),"workshop_id":workshop,"external_document_id":format!("paperless:{document_id}"),"source_document_url":paperless_public_url,"content_digest":digest,"source_filename":metadata.filename,"source_mimetype":mimetype,"source_base64":base64::engine::general_purpose::STANDARD.encode(&source),"provider":provider,"model":if provider=="azure"{"prebuilt-invoice"}else{"structured"},"page_count":pages,"requires_review":requires_review,"field_confidence":confidence,"invoice":invoice})).await?;
    if let Ok(tags) = std::env::var("CONTROL_PAPERLESS_CAPTURED_TAG_IDS") {
        let mut ids = tags
            .split(',')
            .filter_map(|v| v.trim().parse().ok())
            .collect::<Vec<_>>();
        ids.extend(metadata.tags.iter().copied());
        ids.sort_unstable();
        ids.dedup();
        if !ids.is_empty() {
            paperless.mark_capture(document_id, &ids).await?
        }
    }
    Ok(())
}

pub(crate) async fn inventory_capture(
    store: &Store,
    operation: &LeasedOperation,
) -> Result<(), IntegrationError> {
    let workshop = operation
        .workshop_id
        .ok_or(IntegrationError::ContractDrift)?;
    let capture_id = operation
        .payload
        .get("capture_id")
        .and_then(Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok())
        .ok_or(IntegrationError::ContractDrift)?;
    let descriptors = operation
        .payload
        .get("assets")
        .and_then(Value::as_array)
        .filter(|assets| !assets.is_empty() && assets.len() <= 2)
        .ok_or(IntegrationError::ContractDrift)?;
    let (odoo_url, odoo_ref, database_ref) = service(store, workshop, "odoo").await?;
    let odoo = OdooClient::new(
        &odoo_url,
        &secret(&odoo_ref)?,
        database_ref.as_deref(),
        Duration::from_secs(45),
    )
    .map_err(|_| IntegrationError::ContractDrift)?;
    if let Some(checkpoint) = store
        .operation_checkpoint(operation.id)
        .await
        .map_err(|_| IntegrationError::Unavailable)?
    {
        return deliver_inventory_checkpoint(&odoo, &checkpoint).await;
    }
    let mut assets = Vec::with_capacity(descriptors.len());
    let mut input_digests = Vec::with_capacity(descriptors.len());
    for descriptor in descriptors {
        let asset_id = descriptor
            .get("asset_id")
            .and_then(Value::as_str)
            .and_then(|value| Uuid::parse_str(value).ok())
            .ok_or(IntegrationError::ContractDrift)?;
        let expected = descriptor
            .get("content_sha256")
            .and_then(Value::as_str)
            .ok_or(IntegrationError::ContractDrift)?
            .to_ascii_lowercase();
        let asset = odoo.inventory_asset(capture_id, asset_id).await?;
        let actual = format!("{:x}", Sha256::digest(&asset.content));
        if asset.sha256 != expected || actual != expected {
            return Err(IntegrationError::ContractDrift);
        }
        input_digests.push(expected);
        assets.push((asset_id, asset));
    }
    let attempt_id = Uuid::new_v4();
    let operation_key = format!("inventory:{capture_id}:{}", operation.id);
    if !module_enabled(store, workshop, "azure-label-extraction").await? {
        let checkpoint = json!({"callbacks": [json!({
            "operation_key": operation_key,
            "capture_id": capture_id,
            "attempt_id": attempt_id,
            "kind": "ocr",
            "provider": "manual-only",
            "model": "none",
            "version": env!("CARGO_PKG_VERSION"),
            "state": "failed",
            "input_digests": input_digests,
            "normalized_response": {"candidates": [], "warnings": ["label extraction is not enabled"]},
            "raw_response": {},
            "usage": {"images": 0},
            "failure_code": "provider_disabled"
        })]});
        store
            .save_operation_checkpoint(operation, &checkpoint)
            .await
            .map_err(|_| IntegrationError::Unavailable)?;
        return deliver_inventory_checkpoint(&odoo, &checkpoint).await;
    }
    reserve_azure_inventory(store, operation.id, workshop, assets.len() as i64).await?;
    let broker = extraction_broker(Duration::from_secs(120))?;
    let mut tokens = Vec::new();
    let mut codes = Vec::new();
    let mut candidates = Vec::new();
    for (asset_id, asset) in &assets {
        throttle_azure_submission(store).await?;
        let result = broker
            .inventory_label(&asset.content, &asset.mimetype, &asset_id.to_string())
            .await?;
        let normalized = result
            .get("normalized")
            .cloned()
            .ok_or(IntegrationError::ContractDrift)?;
        tokens.extend(
            normalized["ocr_tokens"]
                .as_array()
                .cloned()
                .unwrap_or_default(),
        );
        codes.extend(normalized["codes"].as_array().cloned().unwrap_or_default());
        candidates.extend(
            normalized["candidates"]
                .as_array()
                .cloned()
                .unwrap_or_default(),
        );
    }
    let lot_focused = descriptors.iter().all(|descriptor| {
        matches!(
            descriptor.get("role").and_then(Value::as_str),
            Some("lot_detail" | "crop" | "ocr_variant")
        )
    });
    let needs_vision =
        inventory_needs_vision(lot_focused, !codes.is_empty(), !candidates.is_empty());
    let ocr_tokens = Value::Array(tokens.clone());
    let ocr_callback = json!({
        "operation_key": operation_key,
        "capture_id": capture_id,
        "attempt_id": attempt_id,
        "kind": "ocr",
        "provider": "azure-document-intelligence",
        "model": "prebuilt-read",
        "version": "broker-v1",
        "state": "succeeded",
        "input_digests": input_digests,
        "normalized_response": {"ocr_tokens": tokens, "codes": codes, "candidates": candidates},
        "raw_response": {"retained": false},
        "usage": {"images": assets.len()}
    });
    let mut callbacks = vec![ocr_callback];
    let tenant_allows_ai = operation
        .payload
        .pointer("/hints/allow_ai")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if needs_vision
        && tenant_allows_ai
        && module_enabled(store, workshop, "inventory-ai-fallback").await?
    {
        let vision_inputs = assets
            .iter()
            .zip(descriptors.iter())
            .filter(|(_, descriptor)| {
                descriptor.get("role").and_then(Value::as_str) != Some("ocr_variant")
            })
            .collect::<Vec<_>>();
        reserve_inventory_ai(store, operation.id, workshop, vision_inputs.len() as i64).await?;
        let vision_assets = assets
            .iter()
            .zip(descriptors.iter())
            .filter(|(_, descriptor)| {
                descriptor.get("role").and_then(Value::as_str) != Some("ocr_variant")
            })
            .map(|((asset_id, asset), _)| {
                (
                    asset_id.to_string(),
                    asset.mimetype.clone(),
                    asset.content.clone(),
                )
            })
            .collect::<Vec<_>>();
        let vision_digests = assets
            .iter()
            .zip(descriptors.iter())
            .filter(|(_, descriptor)| {
                descriptor.get("role").and_then(Value::as_str) != Some("ocr_variant")
            })
            .map(|((_, asset), _)| asset.sha256.clone())
            .collect::<Vec<_>>();
        let provider_order = operation
            .payload
            .pointer("/hints/provider_order")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let vision = broker
            .inventory_vision(&vision_assets, &ocr_tokens, &provider_order)
            .await?;
        let normalized = vision
            .get("normalized")
            .cloned()
            .ok_or(IntegrationError::ContractDrift)?;
        callbacks.push(json!({
            "operation_key": format!("inventory:{capture_id}:{}:vision", operation.id),
            "capture_id": capture_id,
            "attempt_id": Uuid::new_v4(),
            "parent_attempt_id": attempt_id,
            "kind": "multimodal",
            "provider": vision.get("provider").and_then(Value::as_str).unwrap_or("multimodal-vision"),
            "model": vision.get("model").and_then(Value::as_str).unwrap_or("configured"),
            "version": vision.get("version").and_then(Value::as_str).unwrap_or("broker-v1"),
            "request_id": vision.get("request_id").and_then(Value::as_str).unwrap_or(""),
            "state": "succeeded",
            "input_digests": vision_digests,
            "normalized_response": normalized,
            "raw_response": {"retained": false},
            "usage": vision.get("usage").cloned().unwrap_or_else(|| json!({"images":vision_assets.len()})),
            "latency_ms": vision.get("latency_ms").and_then(Value::as_u64)
        }));
    }
    let checkpoint = json!({"callbacks": callbacks});
    store
        .save_operation_checkpoint(operation, &checkpoint)
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
    deliver_inventory_checkpoint(&odoo, &checkpoint).await
}

async fn deliver_inventory_checkpoint(
    odoo: &OdooClient,
    checkpoint: &Value,
) -> Result<(), IntegrationError> {
    let callbacks = checkpoint
        .get("callbacks")
        .and_then(Value::as_array)
        .filter(|items| !items.is_empty() && items.len() <= 2)
        .ok_or(IntegrationError::ContractDrift)?;
    for callback in callbacks {
        odoo.capture_inventory_result(callback).await?;
    }
    Ok(())
}

pub(crate) fn inventory_needs_vision(
    lot_focused: bool,
    has_codes: bool,
    has_lot_candidates: bool,
) -> bool {
    !has_lot_candidates || (!lot_focused && !has_codes)
}

async fn reserve_azure_inventory(
    store: &Store,
    operation: Uuid,
    workshop: Uuid,
    images: i64,
) -> Result<(), IntegrationError> {
    reserve_inventory_usage(
        store,
        operation,
        workshop,
        images,
        "azure_inventory_images",
        "CONTROL_AZURE_MONTHLY_IMAGE_LIMIT",
    )
    .await
}

async fn reserve_inventory_ai(
    store: &Store,
    operation: Uuid,
    workshop: Uuid,
    images: i64,
) -> Result<(), IntegrationError> {
    reserve_inventory_usage(
        store,
        operation,
        workshop,
        images,
        "inventory_ai_images",
        "CONTROL_INVENTORY_AI_MONTHLY_IMAGE_LIMIT",
    )
    .await
}

async fn reserve_inventory_usage(
    store: &Store,
    operation: Uuid,
    workshop: Uuid,
    images: i64,
    metric: &str,
    limit_variable: &str,
) -> Result<(), IntegrationError> {
    let limit = std::env::var(limit_variable)
        .ok()
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(500);
    let mut transaction = store
        .begin()
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
    let reserved = sqlx::query_scalar::<_, i64>(
        "insert into control.usage_reservations(operation_id,workshop_id,metric,quantity)
         values($1,$2,$3,$4)
         on conflict(operation_id,metric) do nothing returning quantity",
    )
    .bind(operation)
    .bind(workshop)
    .bind(metric)
    .bind(images)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| IntegrationError::Unavailable)?;
    if reserved.is_none() {
        transaction
            .rollback()
            .await
            .map_err(|_| IntegrationError::Unavailable)?;
        return Ok(());
    }
    let quantity = sqlx::query_scalar::<_, i64>(
        "insert into control.usage_counters(workshop_id,period,metric,quantity)
         select $1,date_trunc('month',current_date)::date,$2,$3 where $3<=$4
         on conflict(workshop_id,period,metric) do update set
         quantity=control.usage_counters.quantity+excluded.quantity,updated_at=now()
         where control.usage_counters.quantity+excluded.quantity<=$4 returning quantity",
    )
    .bind(workshop)
    .bind(metric)
    .bind(images)
    .bind(limit)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| IntegrationError::Unavailable)?;
    if quantity.is_none() {
        transaction
            .rollback()
            .await
            .map_err(|_| IntegrationError::Unavailable)?;
        return Err(IntegrationError::Rejected);
    }
    transaction
        .commit()
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
    Ok(())
}

async fn module_enabled(
    store: &Store,
    workshop: Uuid,
    module_key: &str,
) -> Result<bool, IntegrationError> {
    sqlx::query_scalar(
        "select exists(select 1 from control.workshop_modules
         where workshop_id=$1 and module_key=$2 and state='enabled')",
    )
    .bind(workshop)
    .bind(module_key)
    .fetch_one(store.pool())
    .await
    .map_err(|_| IntegrationError::Unavailable)
}

pub(crate) fn estimated_pages(source: &[u8], mimetype: &str) -> i64 {
    if mimetype == "application/pdf" {
        source
            .windows(11)
            .filter(|window| *window == b"/Type /Page")
            .count()
            .max(1) as i64
    } else {
        1
    }
}
async fn reserve_azure(
    store: &Store,
    operation: Uuid,
    workshop: Uuid,
    pages: i64,
) -> Result<(), IntegrationError> {
    let limit = std::env::var("CONTROL_AZURE_MONTHLY_PAGE_LIMIT")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(1000);
    let mut transaction = store
        .begin()
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
    let reserved = sqlx::query_scalar::<_, i64>(
        "insert into control.usage_reservations(operation_id,workshop_id,metric,quantity)
         values($1,$2,'azure_invoice_pages',$3)
         on conflict(operation_id,metric) do nothing returning quantity",
    )
    .bind(operation)
    .bind(workshop)
    .bind(pages)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| IntegrationError::Unavailable)?;
    if reserved.is_none() {
        transaction
            .rollback()
            .await
            .map_err(|_| IntegrationError::Unavailable)?;
        return Ok(());
    }
    let quantity=sqlx::query_scalar::<_,i64>("insert into control.usage_counters(workshop_id,period,metric,quantity) select $1,date_trunc('month',current_date)::date,'azure_invoice_pages',$2 where $2<=$3 on conflict(workshop_id,period,metric) do update set quantity=control.usage_counters.quantity+excluded.quantity,updated_at=now() where control.usage_counters.quantity+excluded.quantity<=$3 returning quantity")
        .bind(workshop).bind(pages).bind(limit).fetch_optional(&mut *transaction).await.map_err(|_|IntegrationError::Unavailable)?;
    if quantity.is_none() {
        transaction
            .rollback()
            .await
            .map_err(|_| IntegrationError::Unavailable)?;
        return Err(IntegrationError::Rejected);
    }
    transaction
        .commit()
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
    Ok(())
}

async fn throttle_azure_submission(store: &Store) -> Result<(), IntegrationError> {
    let interval_ms = std::env::var("CONTROL_AZURE_ANALYZE_MIN_INTERVAL_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(1_100)
        .clamp(100, 60_000);
    let interval_seconds = interval_ms as f64 / 1_000.0;
    let delay_seconds = sqlx::query_scalar::<_, f64>(
        "insert into control.provider_rate_limits(provider,next_allowed_at)
         values('azure_document_analyze',now()+make_interval(secs=>$1))
         on conflict(provider) do update set
           next_allowed_at=greatest(control.provider_rate_limits.next_allowed_at,now())+make_interval(secs=>$1),
           updated_at=now()
         returning greatest(0,extract(epoch from
           (next_allowed_at-make_interval(secs=>$1)-now())))::float8",
    )
    .bind(interval_seconds)
    .fetch_one(store.pool())
    .await
    .map_err(|_| IntegrationError::Unavailable)?;
    if delay_seconds > 0.0 {
        tokio::time::sleep(Duration::from_secs_f64(delay_seconds)).await;
    }
    Ok(())
}
