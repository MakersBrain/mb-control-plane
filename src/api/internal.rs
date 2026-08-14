use super::*;

pub(super) async fn paperless_event(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(workshop_id): Path<Uuid>,
    Json(payload): Json<Value>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    tenant_bridge(&state, &headers, workshop_id).await?;
    let document_id = payload
        .get("document_id")
        .and_then(Value::as_i64)
        .filter(|id| *id > 0)
        .ok_or(ApiError::Validation("document_id is required"))?;
    let capture_enabled = sqlx::query_scalar::<_, bool>(
        "select exists(select 1 from control.workshop_modules
         where workshop_id=$1 and module_key='invoice-capture' and state='enabled')",
    )
    .bind(workshop_id)
    .fetch_one(state.store.pool())
    .await?;
    if !capture_enabled {
        return Ok((StatusCode::OK, Json(json!({"ignored":true}))));
    }
    let mut tx = state.store.begin().await?;
    let correlation = Uuid::new_v4();
    let key = format!(
        "paperless:{workshop_id}:{document_id}:{}",
        payload
            .get("revision")
            .and_then(Value::as_str)
            .unwrap_or("current")
    );
    let operation = Store::enqueue(
        &mut tx,
        NewOperation {
            kind: OperationKind::InvoiceCapture,
            workshop_id: Some(workshop_id),
            target_user_id: None,
            desired_epoch: None,
            payload: &json!({"document_id":document_id}),
            requested_by: None,
            correlation_id: correlation,
            idempotency_key: &key,
        },
    )
    .await?;
    tx.commit().await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(json!({"operation_id":operation})),
    ))
}

pub(super) async fn inventory_capture(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(workshop_id): Path<Uuid>,
    Json(payload): Json<Value>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    tenant_bridge(&state, &headers, workshop_id).await?;
    let object = payload
        .as_object()
        .filter(|value| {
            value.len() == 4
                && value
                    .keys()
                    .all(|key| matches!(key.as_str(), "capture_id" | "assets" | "task" | "hints"))
        })
        .ok_or(ApiError::Validation("inventory capture payload is invalid"))?;
    let _hints = object
        .get("hints")
        .and_then(Value::as_object)
        .filter(|value| {
            value.len() <= 4
                && value.keys().all(|key| {
                    matches!(
                        key.as_str(),
                        "brand" | "languages" | "allow_ai" | "provider_order"
                    )
                })
                && value.get("brand").is_none_or(|brand| {
                    brand
                        .as_str()
                        .is_some_and(|text| !text.is_empty() && text.len() <= 100)
                })
                && value.get("languages").is_none_or(|languages| {
                    languages.as_array().is_some_and(|items| {
                        items.len() <= 5
                            && items.iter().all(|item| {
                                item.as_str()
                                    .is_some_and(|text| !text.is_empty() && text.len() <= 16)
                            })
                    })
                })
                && value.get("allow_ai").is_none_or(Value::is_boolean)
                && value.get("provider_order").is_none_or(|providers| {
                    providers.as_array().is_some_and(|items| {
                        items.len() <= 2
                            && items.iter().all(|item| {
                                item.as_str().is_some_and(|name| {
                                    matches!(name, "azure" | "gemini" | "openai" | "claude")
                                })
                            })
                            && (items.len() < 2 || items[0] != items[1])
                    })
                })
        })
        .ok_or(ApiError::Validation("inventory capture hints are invalid"))?;
    let capture_id = payload
        .get("capture_id")
        .and_then(Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok())
        .ok_or(ApiError::Validation("capture_id must be a UUID"))?;
    if payload.get("task").and_then(Value::as_str) != Some("inventory_label") {
        return Err(ApiError::Validation("task must be inventory_label"));
    }
    let assets = payload
        .get("assets")
        .and_then(Value::as_array)
        .filter(|assets| !assets.is_empty() && assets.len() <= 2)
        .ok_or(ApiError::Validation("one or two assets are required"))?;
    for asset in assets {
        let valid_id = asset
            .get("asset_id")
            .and_then(Value::as_str)
            .is_some_and(|value| Uuid::parse_str(value).is_ok());
        let valid_role = matches!(
            asset.get("role").and_then(Value::as_str),
            Some("front" | "lot_detail" | "crop" | "ocr_variant")
        );
        let valid_digest = asset
            .get("content_sha256")
            .and_then(Value::as_str)
            .is_some_and(|value| {
                value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
            });
        if !valid_id
            || !valid_role
            || !valid_digest
            || asset.as_object().is_none_or(|v| v.len() != 3)
        {
            return Err(ApiError::Validation("asset descriptor is invalid"));
        }
    }
    let enabled = sqlx::query_scalar::<_, bool>(
        "select exists(select 1 from control.workshop_modules
         where workshop_id=$1 and module_key='inventory-capture' and state='enabled')",
    )
    .bind(workshop_id)
    .fetch_one(state.store.pool())
    .await?;
    if !enabled {
        return Err(ApiError::Forbidden);
    }
    let key = idempotency(&headers)?;
    let mut tx = state.store.begin().await?;
    let operation = Store::enqueue(
        &mut tx,
        NewOperation {
            kind: OperationKind::InventoryCaptureExtract,
            workshop_id: Some(workshop_id),
            target_user_id: None,
            desired_epoch: None,
            payload: &payload,
            requested_by: None,
            correlation_id: Uuid::new_v4(),
            idempotency_key: key,
        },
    )
    .await?;
    tx.commit().await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(json!({"operation_id": operation, "capture_id": capture_id})),
    ))
}

const PRODUCT_LOOKUP_SCHEMA_VERSION: i32 = 1;

pub(super) async fn inventory_product_lookup(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(workshop_id): Path<Uuid>,
    Json(payload): Json<Value>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    tenant_bridge(&state, &headers, workshop_id).await?;
    let object = payload
        .as_object()
        .filter(|value| value.len() == 1 && value.contains_key("gtin14"))
        .ok_or(ApiError::Validation("product lookup payload is invalid"))?;
    let gtin14 = object
        .get("gtin14")
        .and_then(Value::as_str)
        .filter(|value| valid_gtin14(value))
        .ok_or(ApiError::Validation("gtin14 must be checksum-valid"))?;
    let enabled = sqlx::query_scalar::<_, bool>(
        "select exists(select 1 from control.workshop_modules
         where workshop_id=$1 and module_key='inventory-capture' and state='enabled')",
    )
    .bind(workshop_id)
    .fetch_one(state.store.pool())
    .await?;
    if !enabled {
        return Err(ApiError::Forbidden);
    }
    sqlx::query(
        "delete from control.product_lookup_cache where ctid in (
            select ctid from control.product_lookup_cache
            where expires_at < now() - interval '7 days' limit 100
        )",
    )
    .execute(state.store.pool())
    .await?;
    let provider = "upcitemdb";
    if let Some(candidates) = cached_product_lookup(
        state.store.pool(),
        provider,
        PRODUCT_LOOKUP_SCHEMA_VERSION,
        gtin14,
    )
    .await?
    {
        return Ok((
            StatusCode::OK,
            Json(json!({
                "provider":provider,"schema_version":PRODUCT_LOOKUP_SCHEMA_VERSION,
                "gtin14":gtin14,"cache":"hit","candidates":candidates
            })),
        ));
    }

    let lease_owner = Uuid::new_v4();
    let mut tx = state.store.begin().await?;
    let acquired = sqlx::query_scalar::<_, Uuid>(
        "insert into control.product_lookup_fills(provider,schema_version,gtin14,state,leased_by,lease_expires_at)
         values($1,$2,$3,'filling',$4,now()+interval '20 seconds')
         on conflict(provider,schema_version,gtin14) do update set
           state='filling',leased_by=excluded.leased_by,lease_expires_at=excluded.lease_expires_at,
           last_error_class=null,updated_at=now()
         where control.product_lookup_fills.state<>'filling'
            or control.product_lookup_fills.lease_expires_at<=now()
         returning leased_by",
    )
    .bind(provider)
    .bind(PRODUCT_LOOKUP_SCHEMA_VERSION)
    .bind(gtin14)
    .bind(lease_owner)
    .fetch_optional(&mut *tx)
    .await?
    .is_some_and(|owner| owner == lease_owner);
    tx.commit().await?;
    if !acquired {
        if let Some(candidates) = cached_product_lookup(
            state.store.pool(),
            provider,
            PRODUCT_LOOKUP_SCHEMA_VERSION,
            gtin14,
        )
        .await?
        {
            return Ok((
                StatusCode::OK,
                Json(json!({
                    "provider":provider,"schema_version":PRODUCT_LOOKUP_SCHEMA_VERSION,
                    "gtin14":gtin14,"cache":"coalesced_hit","candidates":candidates
                })),
            ));
        }
        return Ok((
            StatusCode::ACCEPTED,
            Json(json!({
                "provider":provider,"schema_version":PRODUCT_LOOKUP_SCHEMA_VERSION,
                "gtin14":gtin14,"cache":"filling","retry_after_seconds":2
            })),
        ));
    }

    let broker_url = std::env::var("CONTROL_EXTRACTION_BROKER_URL")
        .map_err(|error| ApiError::Internal(error.into()))?;
    let broker_token = crate::runtime_secret::required("CONTROL_EXTRACTION_BROKER_TOKEN")
        .map_err(|error| ApiError::Internal(anyhow::anyhow!(error)))?;
    let broker = ExtractionBrokerClient::new(&broker_url, &broker_token, Duration::from_secs(12))
        .map_err(ApiError::Internal)?;
    let response = match broker.product_lookup(provider, gtin14).await {
        Ok(response) => response,
        Err(error) => {
            sqlx::query("update control.product_lookup_fills set state='failed',leased_by=null,lease_expires_at=null,last_error_class='provider_unavailable',updated_at=now() where provider=$1 and schema_version=$2 and gtin14=$3 and leased_by=$4")
                .bind(provider).bind(PRODUCT_LOOKUP_SCHEMA_VERSION).bind(gtin14).bind(lease_owner).execute(state.store.pool()).await?;
            return Err(ApiError::Internal(anyhow::anyhow!(error)));
        }
    };
    let candidates_result = response
        .get("candidates")
        .and_then(Value::as_array)
        .filter(|items| items.len() <= 5 && items.iter().all(Value::is_object))
        .cloned();
    let contract_valid = response.get("provider").and_then(Value::as_str) == Some(provider)
        && response.get("schema_version").and_then(Value::as_i64)
            == Some(i64::from(PRODUCT_LOOKUP_SCHEMA_VERSION))
        && response.get("gtin14").and_then(Value::as_str) == Some(gtin14);
    let Some(candidates) = candidates_result.filter(|_| contract_valid) else {
        sqlx::query("update control.product_lookup_fills set state='failed',leased_by=null,lease_expires_at=null,last_error_class='contract_drift',updated_at=now() where provider=$1 and schema_version=$2 and gtin14=$3 and leased_by=$4")
            .bind(provider).bind(PRODUCT_LOOKUP_SCHEMA_VERSION).bind(gtin14).bind(lease_owner).execute(state.store.pool()).await?;
        return Err(ApiError::Internal(anyhow::anyhow!(
            "product lookup contract drift"
        )));
    };
    if response.get("provider").and_then(Value::as_str) != Some(provider)
        || response.get("schema_version").and_then(Value::as_i64)
            != Some(i64::from(PRODUCT_LOOKUP_SCHEMA_VERSION))
        || response.get("gtin14").and_then(Value::as_str) != Some(gtin14)
    {
        return Err(ApiError::Internal(anyhow::anyhow!(
            "product lookup contract drift"
        )));
    }
    let outcome = if candidates.is_empty() {
        "negative"
    } else {
        "positive"
    };
    let ttl_seconds = if candidates.is_empty() {
        24 * 60 * 60
    } else {
        30 * 24 * 60 * 60
    };
    let candidates = Value::Array(candidates);
    let mut tx = state.store.begin().await?;
    sqlx::query(
        "insert into control.product_lookup_cache
            (provider,schema_version,gtin14,outcome,candidates,retrieved_at,expires_at)
         values ($1,$2,$3,$4,$5,now(),now()+($6::bigint * interval '1 second'))
         on conflict (provider,schema_version,gtin14) do update set
            outcome=excluded.outcome,candidates=excluded.candidates,
            retrieved_at=excluded.retrieved_at,expires_at=excluded.expires_at",
    )
    .bind(provider)
    .bind(PRODUCT_LOOKUP_SCHEMA_VERSION)
    .bind(gtin14)
    .bind(outcome)
    .bind(&candidates)
    .bind(ttl_seconds)
    .execute(&mut *tx)
    .await?;
    sqlx::query("update control.product_lookup_fills set state='idle',leased_by=null,lease_expires_at=null,last_error_class=null,updated_at=now() where provider=$1 and schema_version=$2 and gtin14=$3 and leased_by=$4")
        .bind(provider).bind(PRODUCT_LOOKUP_SCHEMA_VERSION).bind(gtin14).bind(lease_owner).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok((
        StatusCode::OK,
        Json(json!({
            "provider":provider,"schema_version":PRODUCT_LOOKUP_SCHEMA_VERSION,
            "gtin14":gtin14,"cache":"miss","candidates":candidates
        })),
    ))
}

async fn cached_product_lookup(
    pool: &sqlx::PgPool,
    provider: &str,
    schema_version: i32,
    gtin14: &str,
) -> ApiResult<Option<Value>> {
    Ok(sqlx::query_scalar(
        "select candidates from control.product_lookup_cache
         where provider=$1 and schema_version=$2 and gtin14=$3 and expires_at>now()",
    )
    .bind(provider)
    .bind(schema_version)
    .bind(gtin14)
    .fetch_optional(pool)
    .await?)
}

pub(crate) fn valid_gtin14(value: &str) -> bool {
    if value.len() != 14 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    let digits = value.bytes().map(|byte| byte - b'0').collect::<Vec<_>>();
    let sum = digits[..13]
        .iter()
        .rev()
        .enumerate()
        .map(|(index, digit)| u32::from(*digit) * if index % 2 == 0 { 3 } else { 1 })
        .sum::<u32>();
    ((10 - sum % 10) % 10) as u8 == digits[13]
}

pub(super) async fn reconcile_tenant(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(workshop_id): Path<Uuid>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    internal(&state, &headers)?;
    let correlation = Uuid::new_v4();
    queue_tenant_reconciliation(&state, workshop_id, None, &format!("manual:{correlation}")).await
}

async fn queue_tenant_reconciliation(
    state: &AppState,
    workshop_id: Uuid,
    requested_by: Option<Uuid>,
    key: &str,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let tenant = sqlx::query_as::<_, (Uuid, String, String, String)>(
        "select d.id,w.slug,d.database_ref,d.public_hostname
         from control.workshops w
         join control.odoo_databases d on d.workshop_id=w.id
         where w.id=$1 and w.status<>'deleted' and d.kind='primary'
           and d.deleted_at is null and d.public_hostname is not null",
    )
    .bind(workshop_id)
    .fetch_optional(state.store.pool())
    .await?
    .ok_or(ApiError::NotFound)?;
    let paperless_hostname = format!("docs-{}.{}", tenant.1, state.config.tenant_domain);
    let paperless_enabled = sqlx::query_scalar::<_, bool>(
        "select exists(select 1 from control.workshop_modules
         where workshop_id=$1 and module_key='documents' and state='enabled')",
    )
    .bind(workshop_id)
    .fetch_one(state.store.pool())
    .await?;
    let payload = json!({
        "database_id": tenant.0,
        "database_ref": tenant.2,
        "public_hostname": tenant.3,
        "paperless_hostname": paperless_hostname,
        "paperless_enabled": paperless_enabled,
    });
    let mut tx = state.store.begin().await?;
    let correlation = Uuid::new_v4();
    let op = Store::enqueue(
        &mut tx,
        NewOperation {
            kind: OperationKind::TenantReconcile,
            workshop_id: Some(workshop_id),
            target_user_id: None,
            desired_epoch: None,
            payload: &payload,
            requested_by,
            correlation_id: correlation,
            idempotency_key: key,
        },
    )
    .await?;
    audit(
        &mut tx,
        requested_by,
        Some(workshop_id),
        "tenant.reconcile",
        "workshop",
        workshop_id.to_string(),
        correlation,
    )
    .await?;
    tx.commit().await?;
    Ok((StatusCode::ACCEPTED, Json(json!({"operation_id":op}))))
}

#[derive(Deserialize)]
pub(super) struct EntitlementAck {
    version: i64,
    service: String,
}
pub(super) async fn ack_entitlement(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(workshop_id): Path<Uuid>,
    Json(body): Json<EntitlementAck>,
) -> ApiResult<StatusCode> {
    internal(&state, &headers)?;
    if body.service != "odoo" && body.service != "paperless" {
        return Err(ApiError::Validation("unknown service"));
    }
    sqlx::query("update control.service_instances set applied_epoch=greatest(applied_epoch,$3::integer),last_observed_at=now() where workshop_id=$1 and service=$2").bind(workshop_id).bind(body.service).bind(i32::try_from(body.version).map_err(|_|ApiError::Validation("version out of range"))?).execute(state.store.pool()).await?;
    Ok(StatusCode::NO_CONTENT)
}
