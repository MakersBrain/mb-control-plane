use super::*;
use serde::Serialize;

#[derive(Deserialize, ToSchema)]
pub(crate) struct EmailDomainCreateBody {
    domain_name: String,
    #[serde(default = "default_sender")]
    sender_local_part: String,
}
fn default_sender() -> String {
    "bonjour".into()
}

#[derive(Serialize, ToSchema, sqlx::FromRow)]
pub(crate) struct EmailDomainResponse {
    id: Uuid,
    domain_name: String,
    sender_local_part: String,
    state: String,
    desired_state: String,
    provider_status: Option<String>,
    dns_records: Value,
    verification: Value,
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
fn response(row: Row, can_manage: bool) -> EmailDomainResponse {
    EmailDomainResponse {
        id: row.id,
        domain_name: row.domain_name,
        sender_local_part: row.sender_local_part,
        state: row.state,
        desired_state: row.desired_state,
        provider_status: row.provider_status,
        dns_records: row.dns_records,
        verification: row.verification,
        test_delivered_at: row.test_delivered_at.map(api_timestamp),
        last_health_checked_at: row.last_health_checked_at.map(api_timestamp),
        last_error_class: row.last_error_class,
        operation_id: row.operation_id,
        version: row.version,
        can_manage,
    }
}
async fn manager(state: &AppState, user: Uuid, workshop: Uuid) -> ApiResult<()> {
    if !authority(state, user, workshop)
        .await?
        .0
        .can_manage_modules()
    {
        return Err(ApiError::Forbidden);
    }
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
    headers: HeaderMap,
    Path(workshop): Path<Uuid>,
) -> ApiResult<Json<Vec<EmailDomainResponse>>> {
    let who = principal(&state, &headers).await?;
    let role = authority(&state, who.user_id, workshop).await?.0;
    let rows = sqlx::query_as::<_, Row>(
        "select id,domain_name,sender_local_part,state,desired_state,provider_status,dns_records,verification,test_delivered_at,last_health_checked_at,last_error_class,operation_id,version from control.webshop_email_domains where workshop_id=$1 and state<>'disconnected' order by created_at"
    )
    .bind(workshop)
    .fetch_all(state.store.pool())
    .await?;
    Ok(Json(
        rows.into_iter()
            .map(|r| response(r, role.can_manage_modules()))
            .collect(),
    ))
}

pub(super) async fn create(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(workshop): Path<Uuid>,
    Json(body): Json<EmailDomainCreateBody>,
) -> ApiResult<(StatusCode, Json<EmailDomainResponse>)> {
    let who = principal(&state, &headers).await?;
    manager(&state, who.user_id, workshop).await?;
    let domain = domains::normalize_custom_hostname(&body.domain_name, &state.config.tenant_domain)
        .map_err(ApiError::Validation)?;
    let sender = local_part(&body.sender_local_part)?;
    let mut tx = state.store.begin().await?;
    let id = Uuid::new_v4();
    sqlx::query("insert into control.webshop_email_domains(id,workshop_id,domain_name,sender_local_part,created_by) values($1,$2,$3,$4,$5)").bind(id).bind(workshop).bind(domain).bind(sender).bind(who.user_id).execute(&mut *tx).await.map_err(|e|if e.as_database_error().is_some_and(|d|d.is_unique_violation()){ApiError::Conflict("This email domain is already claimed")}else{e.into()})?;
    let operation = Store::enqueue(
        &mut tx,
        NewOperation {
            kind: OperationKind::WebshopEmailDomainReconcile,
            workshop_id: Some(workshop),
            target_user_id: None,
            desired_epoch: None,
            payload: &json!({"email_domain_id":id,"reason":"created"}),
            requested_by: Some(who.user_id),
            correlation_id: Uuid::new_v4(),
            idempotency_key: &format!("email-domain-create:{id}"),
        },
    )
    .await?;
    sqlx::query("update control.webshop_email_domains set operation_id=$2 where id=$1")
        .bind(id)
        .bind(operation)
        .execute(&mut *tx)
        .await?;
    let row = sqlx::query_as::<_, Row>("select id,domain_name,sender_local_part,state,desired_state,provider_status,dns_records,verification,test_delivered_at,last_health_checked_at,last_error_class,operation_id,version from control.webshop_email_domains where id=$1")
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok((StatusCode::ACCEPTED, Json(response(row, true))))
}

pub(super) async fn check(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((workshop, id)): Path<(Uuid, Uuid)>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let who = principal(&state, &headers).await?;
    manager(&state, who.user_id, workshop).await?;
    queue(&state, workshop, id, who.user_id, "manual-check", false).await
}
pub(super) async fn disconnect(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((workshop, id)): Path<(Uuid, Uuid)>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let who = principal(&state, &headers).await?;
    manager(&state, who.user_id, workshop).await?;
    queue(&state, workshop, id, who.user_id, "disconnect", true).await
}

async fn queue(
    state: &AppState,
    workshop: Uuid,
    id: Uuid,
    user: Uuid,
    reason: &str,
    disconnect: bool,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let mut tx = state.store.begin().await?;
    let current=sqlx::query_scalar::<_,i64>("select version from control.webshop_email_domains where id=$1 and workshop_id=$2 and state<>'disconnected' for update").bind(id).bind(workshop).fetch_optional(&mut *tx).await?.ok_or(ApiError::NotFound)?;
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
            idempotency_key: &format!("email-domain:{id}:{reason}:{current}"),
        },
    )
    .await?;
    sqlx::query("update control.webshop_email_domains set operation_id=$2,desired_state=case when $3 then 'disconnected' else desired_state end,state=case when $3 then 'disconnecting' else state end,updated_at=now(),version=version+1 where id=$1").bind(id).bind(operation).bind(disconnect).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(json!({"operation_id":operation})),
    ))
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
}
