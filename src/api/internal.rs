use super::*;
use base64::Engine as _;

const ID_TOKEN_REQUEST_MAX_BYTES: usize = 128 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct VerifyIdTokenBody {
    id_token: String,
    access_token: String,
    nonce: String,
}

#[derive(serde::Serialize)]
pub(super) struct VerifiedIdTokenResponse {
    subject: String,
}

pub(super) async fn verify_odoo_id_token(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(workshop_id): Path<Uuid>,
    body: bytes::Bytes,
) -> ApiResult<Json<VerifiedIdTokenResponse>> {
    // Authenticate the workshop selected by the path before parsing any token
    // or accepting any identity assertion from the request payload.
    tenant_bridge(&state, &headers, workshop_id).await?;
    if body.is_empty() || body.len() > ID_TOKEN_REQUEST_MAX_BYTES {
        return Err(ApiError::Validation(
            "ID-token verification body is invalid",
        ));
    }
    let body: VerifyIdTokenBody = serde_json::from_slice(&body)
        .map_err(|_| ApiError::Validation("ID-token verification body is invalid"))?;
    if body.id_token.is_empty()
        || body.id_token.len() > 64 * 1024
        || body.access_token.is_empty()
        || body.access_token.len() > 64 * 1024
        || body.nonce.is_empty()
        || body.nonce.len() > 1024
        || body.nonce.chars().any(char::is_control)
    {
        return Err(ApiError::Validation(
            "ID-token verification body is invalid",
        ));
    }
    let audience = format!("mb-odoo-{}", workshop_id.simple());
    let identity = state
        .auth
        .verify_id_token(&body.id_token, &body.access_token, &body.nonce, &audience)
        .await?;
    Ok(Json(VerifiedIdTokenResponse {
        subject: identity.subject,
    }))
}

#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct TransactionalMailAttachment {
    name: String,
    content_type: String,
    content_base64: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct MailDeliveryEventBody {
    schema_version: u8,
    event_id: Uuid,
    sns_message_id: Uuid,
    email_id: Uuid,
    delivery_id: Uuid,
    domain_id: Uuid,
    event_type: String,
    created_at: String,
}

pub(super) async fn mail_delivery_event(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<MailDeliveryEventBody>,
) -> ApiResult<StatusCode> {
    mail_event_gateway(&state, &headers)?;
    if body.schema_version != 1
        || !matches!(
            body.event_type.as_str(),
            "email_queued"
                | "email_deferred"
                | "email_delivered"
                | "email_dropped"
                | "email_spam"
                | "email_mailbox_not_found"
                | "email_blocklisted"
        )
    {
        return Err(ApiError::Validation("mail delivery event is invalid"));
    }
    let occurred_at = OffsetDateTime::parse(&body.created_at, &Rfc3339)
        .map_err(|_| ApiError::Validation("mail delivery event timestamp is invalid"))?;
    if occurred_at > OffsetDateTime::now_utc() + time::Duration::minutes(5) {
        return Err(ApiError::Validation(
            "mail delivery event timestamp is invalid",
        ));
    }
    let delivery_state = match body.event_type.as_str() {
        "email_queued" => "submitted",
        "email_deferred" => "deferred",
        "email_delivered" => "delivered",
        "email_dropped" | "email_mailbox_not_found" => "bounced",
        "email_spam" => "complained",
        "email_blocklisted" => "suppressed",
        _ => unreachable!(),
    };
    let mut tx = state.store.begin().await?;
    let outbox = sqlx::query_as::<_, (Uuid, String)>(
        "select workshop_id,recipient from control.outbox
          where id=$1 and kind='odoo_transactional'
            and (provider_message_id is null or provider_message_id=$2)
            and (provider_domain_id is null or provider_domain_id=$3)
          for update",
    )
    .bind(body.delivery_id)
    .bind(body.email_id)
    .bind(body.domain_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(outbox) = outbox else {
        // The provider topic also carries mail that is intentionally outside the
        // webshop outbox (for example platform invitations). It is authenticated
        // provider evidence, but there is no tenant delivery row to mutate.
        tx.rollback().await?;
        return Ok(StatusCode::NO_CONTENT);
    };
    let inserted = sqlx::query_scalar::<_, Uuid>(
        "insert into control.email_delivery_events(
             event_id,outbox_id,provider_message_id,sns_message_id,event_type,occurred_at
         ) values($1,$2,$3,$4,$5,$6)
         on conflict(event_id) do nothing returning event_id",
    )
    .bind(body.event_id)
    .bind(body.delivery_id)
    .bind(body.email_id)
    .bind(body.sns_message_id)
    .bind(&body.event_type)
    .bind(occurred_at)
    .fetch_optional(&mut *tx)
    .await?;
    if inserted.is_none() {
        let existing = sqlx::query_as::<_, (Uuid, Uuid, String, OffsetDateTime)>(
            "select outbox_id,provider_message_id,event_type,occurred_at
               from control.email_delivery_events where event_id=$1",
        )
        .bind(body.event_id)
        .fetch_one(&mut *tx)
        .await?;
        if existing
            != (
                body.delivery_id,
                body.email_id,
                body.event_type.clone(),
                occurred_at,
            )
        {
            return Err(ApiError::Conflict(
                "delivery event identity was already used for different content",
            ));
        }
    }
    sqlx::query(
        "update control.outbox
            set delivery_state=$2,last_event_at=$3,
                provider_message_id=coalesce(provider_message_id,$4),
                provider_domain_id=coalesce(provider_domain_id,$5),
                state=case when state='sending' then 'sent' else state end,
                sent_at=case when state='sending' then coalesce(sent_at,now()) else sent_at end
          where id=$1 and (last_event_at is null or last_event_at <= $3)",
    )
    .bind(body.delivery_id)
    .bind(delivery_state)
    .bind(occurred_at)
    .bind(body.email_id)
    .bind(body.domain_id)
    .execute(&mut *tx)
    .await?;
    if body.event_type == "email_delivered" {
        sqlx::query("update control.webshop_email_domains set test_delivered_at=coalesce(test_delivered_at,$2),updated_at=now(),version=version+1 where test_outbox_id=$1 and desired_state='active'")
            .bind(body.delivery_id).bind(occurred_at).execute(&mut *tx).await?;
    }
    let suppression_reason = match body.event_type.as_str() {
        "email_dropped" => Some("dropped"),
        "email_spam" => Some("spam"),
        "email_mailbox_not_found" => Some("mailbox_not_found"),
        "email_blocklisted" => Some("blocklisted"),
        _ => None,
    };
    if let Some(reason) = suppression_reason {
        sqlx::query(
            "insert into control.email_suppressions(
                 workshop_id,recipient,reason,source_event_id
             ) values($1,$2,$3,$4)
             on conflict(workshop_id,recipient) do update set
                 reason=excluded.reason,source_event_id=excluded.source_event_id,updated_at=now()",
        )
        .bind(outbox.0)
        .bind(outbox.1)
        .bind(reason)
        .bind(body.event_id)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(if inserted.is_some() {
        StatusCode::CREATED
    } else {
        StatusCode::NO_CONTENT
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TransactionalMailBody {
    source_key: String,
    recipient: String,
    subject: String,
    text: String,
    html: String,
    sender_name: String,
    reply_to: String,
    model: String,
    #[serde(default)]
    attachments: Vec<TransactionalMailAttachment>,
}

pub(super) async fn webshop_transactional_mail(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(workshop_id): Path<Uuid>,
    Json(body): Json<TransactionalMailBody>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    tenant_bridge(&state, &headers, workshop_id).await?;
    let key = idempotency(&headers)?;
    if key != body.source_key
        || !(1..=255).contains(&body.source_key.len())
        || !body.source_key.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'-')
        })
    {
        return Err(ApiError::Validation("source_key is invalid"));
    }
    if !matches!(
        body.model.as_str(),
        "sale.order" | "account.move" | "stock.picking" | "mb.webshop.return"
    ) {
        return Err(ApiError::Validation(
            "model is not an approved webshop transactional source",
        ));
    }
    let recipient = normalize_email(&body.recipient).map_err(ApiError::Validation)?;
    let reply_to = normalize_email(&body.reply_to).map_err(ApiError::Validation)?;
    if body.sender_name.trim().is_empty()
        || body.sender_name.len() > 100
        || body.sender_name.chars().any(char::is_control)
        || body.subject.trim().is_empty()
        || body.subject.len() > 255
        || body.subject.chars().any(char::is_control)
        || body.text.len() > 256 * 1024
        || body.html.len() > 512 * 1024
        || (body.text.trim().is_empty() && body.html.trim().is_empty())
        || body.text.contains('\0')
        || body.html.contains('\0')
    {
        return Err(ApiError::Validation(
            "transactional mail content is invalid or exceeds its bound",
        ));
    }
    if body.attachments.len() > 5 {
        return Err(ApiError::Validation(
            "too many transactional mail attachments",
        ));
    }
    let mut attachment_bytes = 0usize;
    for attachment in &body.attachments {
        if attachment.name.is_empty()
            || attachment.name.len() > 255
            || attachment.name.contains('/')
            || attachment.name.contains('\\')
            || attachment.name.chars().any(char::is_control)
            || attachment.content_type.is_empty()
            || attachment.content_type.len() > 127
            || attachment
                .content_type
                .chars()
                .any(|character| character.is_control() || character.is_ascii_whitespace())
        {
            return Err(ApiError::Validation(
                "transactional mail attachment is invalid",
            ));
        }
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&attachment.content_base64)
            .map_err(|_| ApiError::Validation("transactional mail attachment is invalid"))?;
        attachment_bytes = attachment_bytes.saturating_add(decoded.len());
    }
    if attachment_bytes > 8 * 1024 * 1024 {
        return Err(ApiError::Validation(
            "transactional mail attachments exceed 8 MiB",
        ));
    }
    let enabled = sqlx::query_scalar::<_, bool>(
        "select exists(select 1 from control.workshop_modules
          where workshop_id=$1 and module_key='webshop' and state='enabled')",
    )
    .bind(workshop_id)
    .fetch_one(state.store.pool())
    .await?;
    if !enabled {
        return Err(ApiError::Forbidden);
    }
    let suppressed = sqlx::query_scalar::<_, bool>(
        "select exists(select 1 from control.email_suppressions
          where workshop_id=$1 and recipient=$2)",
    )
    .bind(workshop_id)
    .bind(&recipient)
    .fetch_one(state.store.pool())
    .await?;
    if suppressed {
        return Err(ApiError::Conflict(
            "recipient is suppressed by a delivery failure",
        ));
    }
    let payload = json!({
        "content":{"subject":body.subject,"text":body.text,"html":body.html},
        "sender_name":body.sender_name,"reply_to":reply_to,"model":body.model,
        "attachments":body.attachments
    });
    let mut tx = state.store.begin().await?;
    let proposed = Uuid::new_v4();
    let inserted = sqlx::query_scalar::<_, Uuid>(
        "insert into control.outbox(
             id,kind,recipient,template,payload,workshop_id,source_key
         ) values($1,'odoo_transactional',$2,'odoo-rendered-v1',$3,$4,$5)
         on conflict(workshop_id,source_key) where source_key is not null do nothing
         returning id",
    )
    .bind(proposed)
    .bind(&recipient)
    .bind(&payload)
    .bind(workshop_id)
    .bind(&body.source_key)
    .fetch_optional(&mut *tx)
    .await?;
    let outbox_id = if let Some(id) = inserted {
        id
    } else {
        let existing = sqlx::query_as::<_, (Uuid, String, Value)>(
            "select id,recipient,payload from control.outbox
              where workshop_id=$1 and source_key=$2 for update",
        )
        .bind(workshop_id)
        .bind(&body.source_key)
        .fetch_one(&mut *tx)
        .await?;
        if existing.1 != recipient || existing.2 != payload {
            return Err(ApiError::Conflict(
                "source_key was already used for different mail content",
            ));
        }
        existing.0
    };
    let operation_id = Store::enqueue(
        &mut tx,
        NewOperation {
            kind: OperationKind::EmailDelivery,
            workshop_id: Some(workshop_id),
            target_user_id: None,
            desired_epoch: None,
            payload: &json!({"outbox_id":outbox_id}),
            requested_by: None,
            correlation_id: Uuid::new_v4(),
            idempotency_key: &format!("odoo-mail:{workshop_id}:{}", body.source_key),
        },
    )
    .await?;
    tx.commit().await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(json!({"outbox_id":outbox_id,"operation_id":operation_id})),
    ))
}

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
          "custom_hostnames": crate::worker::routable_custom_hostnames(&state.store, workshop_id).await?,
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
