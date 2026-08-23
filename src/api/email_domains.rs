use super::*;
use crate::auth::WorkshopScope;
use axum::extract::Extension;
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Deserialize, ToSchema)]
pub(crate) struct EmailDomainCreateBody {
    domain_name: String,
    #[serde(default = "default_sender")]
    sender_local_part: String,
}
fn default_sender() -> String {
    "bonjour".into()
}

#[derive(Serialize, ToSchema)]
pub(crate) struct EmailDnsRecordResponse {
    name: Option<String>,
    value: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct EmailDomainVerificationResponse {
    status: String,
}

#[derive(Serialize, ToSchema, sqlx::FromRow)]
pub(crate) struct EmailDomainResponse {
    id: Uuid,
    domain_name: String,
    sender_local_part: String,
    state: String,
    desired_state: String,
    provider_status: Option<String>,
    dns_records: BTreeMap<String, EmailDnsRecordResponse>,
    verification: BTreeMap<String, EmailDomainVerificationResponse>,
    test_delivered_at: Option<String>,
    last_health_checked_at: Option<String>,
    last_error_class: Option<String>,
    operation_id: Option<Uuid>,
    version: i64,
    can_manage: bool,
}

#[derive(sqlx::FromRow)]
struct Row {
    id: Uuid,
    domain_name: String,
    sender_local_part: String,
    state: String,
    desired_state: String,
    provider_status: Option<String>,
    dns_records: Value,
    verification: Value,
    test_delivered_at: Option<OffsetDateTime>,
    last_health_checked_at: Option<OffsetDateTime>,
    last_error_class: Option<String>,
    operation_id: Option<Uuid>,
    version: i64,
}
fn optional_string(value: Option<&Value>, maximum: usize) -> Option<String> {
    value
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= maximum)
        .map(ToOwned::to_owned)
}

fn dns_records(value: Value) -> BTreeMap<String, EmailDnsRecordResponse> {
    value
        .as_object()
        .into_iter()
        .flatten()
        .take(32)
        .filter_map(|(kind, candidate)| {
            if kind.is_empty() || kind.len() > 64 {
                return None;
            }
            let candidate = candidate.as_object()?;
            let name = optional_string(candidate.get("name"), 253);
            let value = optional_string(candidate.get("value"), 4096);
            if name.is_none() && value.is_none() {
                return None;
            }
            Some((kind.clone(), EmailDnsRecordResponse { name, value }))
        })
        .collect()
}

fn verification(value: Value) -> BTreeMap<String, EmailDomainVerificationResponse> {
    value
        .as_object()
        .into_iter()
        .flatten()
        .take(32)
        .filter_map(|(kind, candidate)| {
            if kind.is_empty() || kind.len() > 64 {
                return None;
            }
            let candidate = candidate.as_object()?;
            let status = optional_string(candidate.get("status"), 64)?;
            Some((kind.clone(), EmailDomainVerificationResponse { status }))
        })
        .collect()
}

fn response(row: Row, can_manage: bool) -> EmailDomainResponse {
    EmailDomainResponse {
        id: row.id,
        domain_name: row.domain_name,
        sender_local_part: row.sender_local_part,
        state: row.state,
        desired_state: row.desired_state,
        provider_status: row.provider_status,
        dns_records: dns_records(row.dns_records),
        verification: verification(row.verification),
        test_delivered_at: row.test_delivered_at.map(api_timestamp),
        last_health_checked_at: row.last_health_checked_at.map(api_timestamp),
        last_error_class: row.last_error_class,
        operation_id: row.operation_id,
        version: row.version,
        can_manage,
    }
}
async fn require_webshop_enabled(state: &AppState, workshop: Uuid) -> ApiResult<()> {
    let enabled=sqlx::query_scalar::<_,bool>("select exists(select 1 from control.workshop_modules where workshop_id=$1 and module_key='webshop' and state='enabled')").bind(workshop).fetch_one(state.store.pool()).await?;
    if !enabled {
        return Err(ApiError::Conflict("The webshop must be enabled first"));
    }
    Ok(())
}
fn local_part(value: &str) -> Result<String, ApiError> {
    let value = value.trim().to_ascii_lowercase();
    if value.is_empty()
        || value.len() > 64
        || !value.bytes().enumerate().all(|(i, b)| {
            b.is_ascii_lowercase()
                || b.is_ascii_digit()
                || matches!(b, b'.' | b'_' | b'+' | b'-') && i > 0
        })
    {
        return Err(ApiError::Validation("sender local part is invalid"));
    }
    Ok(value)
}

pub(super) async fn list(
    State(state): State<Arc<AppState>>,
    Extension(scope): Extension<WorkshopScope>,
) -> ApiResult<Json<Vec<EmailDomainResponse>>> {
    let workshop = scope.workshop_id;
    let mut tx = state.tenant_store.begin(workshop).await?;
    let rows = sqlx::query_as::<_, Row>(
        "select id,domain_name,sender_local_part,state,desired_state,provider_status,dns_records,verification,test_delivered_at,last_health_checked_at,last_error_class,operation_id,version from control.webshop_email_domains where workshop_id=$1 and state<>'disconnected' order by created_at"
    )
    .bind(workshop)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Json(
        rows.into_iter()
            .map(|r| response(r, scope.role.can_manage_modules()))
            .collect(),
    ))
}

pub(super) async fn create(
    State(state): State<Arc<AppState>>,
    Extension(scope): Extension<WorkshopScope>,
    headers: HeaderMap,
    Json(body): Json<EmailDomainCreateBody>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let workshop = scope.workshop_id;
    require_webshop_enabled(&state, workshop).await?;
    let domain = domains::normalize_custom_hostname(&body.domain_name, &state.config.tenant_domain)
        .map_err(ApiError::Validation)?;
    let sender = local_part(&body.sender_local_part)?;
    let client_key = idempotency(&headers)?;
    let semantic = json!({"domain_name":domain,"sender_local_part":sender});
    let command_scope = format!("workshop:{workshop}:webshop-email-domains");
    let mut tx = state.tenant_store.begin(scope.workshop_id).await?;
    revalidate_workshop_scope(&mut tx, &scope).await?;
    let command_id = match admit_command(
        &mut tx,
        NewCommand {
            actor_user_id: scope.principal_id,
            scope: &command_scope,
            command_kind: "webshop-email-domain.create",
            idempotency_key: client_key,
            semantic_request: &semantic,
            expected_version: None,
        },
    )
    .await
    .map_err(command_error)?
    {
        CommandAdmission::New { command_id } => command_id,
        CommandAdmission::Replay {
            response_status,
            response_body,
            ..
        } => {
            tx.commit().await?;
            return Ok((
                StatusCode::from_u16(response_status).unwrap_or(StatusCode::ACCEPTED),
                Json(response_body.unwrap_or_else(|| json!({"replayed":true}))),
            ));
        }
        CommandAdmission::InProgress {
            command_id,
            operation_id,
        } => {
            tx.commit().await?;
            return Ok((
                StatusCode::ACCEPTED,
                Json(json!({
                    "command_id":command_id,"operation_id":operation_id,"in_progress":true
                })),
            ));
        }
    };
    let id = Uuid::new_v4();
    sqlx::query("insert into control.webshop_email_domains(id,workshop_id,domain_name,sender_local_part,created_by) values($1,$2,$3,$4,$5)").bind(id).bind(workshop).bind(domain).bind(sender).bind(scope.principal_id).execute(&mut *tx).await.map_err(|e|if e.as_database_error().is_some_and(|d|d.is_unique_violation()){ApiError::Conflict("This email domain is already claimed")}else{e.into()})?;
    let operation = Store::enqueue(
        &mut tx,
        NewOperation {
            kind: OperationKind::WebshopEmailDomainReconcile,
            workshop_id: Some(workshop),
            target_user_id: None,
            desired_epoch: None,
            payload: &json!({"email_domain_id":id,"reason":"created"}),
            requested_by: Some(scope.principal_id),
            correlation_id: Uuid::new_v4(),
            idempotency_key: &format!("command:{command_id}"),
        },
    )
    .await?;
    sqlx::query(
        "update control.webshop_email_domains set operation_id=$2 where id=$1 and workshop_id=$3",
    )
    .bind(id)
    .bind(operation)
    .bind(workshop)
    .execute(&mut *tx)
    .await?;
    let row = sqlx::query_as::<_, Row>("select id,domain_name,sender_local_part,state,desired_state,provider_status,dns_records,verification,test_delivered_at,last_health_checked_at,last_error_class,operation_id,version from control.webshop_email_domains where id=$1 and workshop_id=$2")
        .bind(id)
        .bind(workshop)
        .fetch_one(&mut *tx)
        .await?;
    let public = serde_json::to_value(response(row, true))
        .map_err(|error| ApiError::Internal(error.into()))?;
    audit_command(
        &mut tx,
        (Some(scope.principal_id), Some(workshop)),
        "webshop-email-domain.create",
        "webshop-email-domain",
        id.to_string(),
        Uuid::new_v4(),
        command_id,
    )
    .await?;
    complete_command(
        &mut tx,
        command_id,
        CommandResult {
            operation_id: Some(operation),
            response_status: StatusCode::ACCEPTED.as_u16(),
            response_body: Some(&public),
            result_ref: None,
        },
    )
    .await
    .map_err(command_error)?;
    tx.commit().await?;
    Ok((StatusCode::ACCEPTED, Json(public)))
}

pub(super) async fn check(
    State(state): State<Arc<AppState>>,
    Extension(scope): Extension<WorkshopScope>,
    headers: HeaderMap,
    Path((_workshop, id)): Path<(Uuid, Uuid)>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let workshop = scope.workshop_id;
    require_webshop_enabled(&state, workshop).await?;
    let client_key = idempotency(&headers)?;
    queue(&state, &scope, id, "manual-check", false, client_key).await
}
pub(super) async fn disconnect(
    State(state): State<Arc<AppState>>,
    Extension(scope): Extension<WorkshopScope>,
    headers: HeaderMap,
    Path((_workshop, id)): Path<(Uuid, Uuid)>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let workshop = scope.workshop_id;
    require_webshop_enabled(&state, workshop).await?;
    let client_key = idempotency(&headers)?;
    queue(&state, &scope, id, "disconnect", true, client_key).await
}

async fn queue(
    state: &AppState,
    scope: &WorkshopScope,
    id: Uuid,
    reason: &str,
    disconnect: bool,
    client_key: &str,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let workshop = scope.workshop_id;
    let user = scope.principal_id;
    let mut tx = state.tenant_store.begin(scope.workshop_id).await?;
    revalidate_workshop_scope(&mut tx, scope).await?;
    let semantic = json!({"email_domain_id":id,"reason":reason});
    let command_scope = format!("workshop:{workshop}:webshop-email-domain:{id}");
    let command_kind = if disconnect {
        "webshop-email-domain.disconnect"
    } else {
        "webshop-email-domain.check"
    };
    let command_id = match admit_command(
        &mut tx,
        NewCommand {
            actor_user_id: user,
            scope: &command_scope,
            command_kind,
            idempotency_key: client_key,
            semantic_request: &semantic,
            expected_version: None,
        },
    )
    .await
    .map_err(command_error)?
    {
        CommandAdmission::New { command_id } => command_id,
        CommandAdmission::Replay {
            response_status,
            response_body,
            ..
        } => {
            tx.commit().await?;
            return Ok((
                StatusCode::from_u16(response_status).unwrap_or(StatusCode::ACCEPTED),
                Json(response_body.unwrap_or_else(|| json!({"replayed":true}))),
            ));
        }
        CommandAdmission::InProgress {
            command_id,
            operation_id,
        } => {
            tx.commit().await?;
            return Ok((
                StatusCode::ACCEPTED,
                Json(json!({
                    "command_id":command_id,"operation_id":operation_id,"in_progress":true
                })),
            ));
        }
    };
    sqlx::query_scalar::<_, i64>("select version from control.webshop_email_domains where id=$1 and workshop_id=$2 and state<>'disconnected' for update").bind(id).bind(workshop).fetch_optional(&mut *tx).await?.ok_or(ApiError::NotFound)?;
    let operation = Store::enqueue(
        &mut tx,
        NewOperation {
            kind: OperationKind::WebshopEmailDomainReconcile,
            workshop_id: Some(workshop),
            target_user_id: None,
            desired_epoch: None,
            payload: &json!({"email_domain_id":id,"reason":reason}),
            requested_by: Some(user),
            correlation_id: Uuid::new_v4(),
            idempotency_key: &format!("command:{command_id}"),
        },
    )
    .await?;
    sqlx::query("update control.webshop_email_domains set operation_id=$2,desired_state=case when $3 then 'disconnected' else desired_state end,state=case when $3 then 'disconnecting' else state end,updated_at=now(),version=version+1 where id=$1 and workshop_id=$4").bind(id).bind(operation).bind(disconnect).bind(workshop).execute(&mut *tx).await?;
    let public = json!({"command_id":command_id,"operation_id":operation});
    audit_command(
        &mut tx,
        (Some(user), Some(workshop)),
        command_kind,
        "webshop-email-domain",
        id.to_string(),
        Uuid::new_v4(),
        command_id,
    )
    .await?;
    complete_command(
        &mut tx,
        command_id,
        CommandResult {
            operation_id: Some(operation),
            response_status: StatusCode::ACCEPTED.as_u16(),
            response_body: Some(&public),
            result_ref: None,
        },
    )
    .await
    .map_err(command_error)?;
    tx.commit().await?;
    Ok((StatusCode::ACCEPTED, Json(public)))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sender_local_part_is_bounded() {
        assert_eq!(local_part("Bonjour").unwrap(), "bonjour");
        assert!(local_part(".bad").is_err());
        assert!(local_part("bad address").is_err());
    }

    #[test]
    fn email_provider_evidence_is_projected_to_allowlisted_fields() {
        let records = dns_records(json!({
            "spf_record":{"name":"example.test","value":"v=spf1","provider_id":"private"},
            "invalid":"not-an-object"
        }));
        let checks = verification(json!({
            "spf_record":{"status":"valid","error":"none","provider_debug":"private"}
        }));

        assert_eq!(
            serde_json::to_value(records).unwrap(),
            json!({"spf_record":{"name":"example.test","value":"v=spf1"}})
        );
        assert_eq!(
            serde_json::to_value(checks).unwrap(),
            json!({"spf_record":{"status":"valid"}})
        );
    }
}
