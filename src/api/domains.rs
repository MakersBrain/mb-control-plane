use super::*;

use crate::auth::WorkshopScope;
use crate::outbound_http::TraceRequestBuilderExt as _;
use axum::extract::Extension;
use rand::distr::{Alphanumeric, SampleString};
use serde::Serialize;
use url::{Host, Url};

#[derive(Deserialize, ToSchema)]
pub(crate) struct CustomDomainCreateBody {
    hostname: String,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct EdgeVerificationRecordResponse {
    #[serde(rename = "type")]
    record_type: String,
    name: String,
    value: String,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct WebshopDomainResponse {
    id: Option<Uuid>,
    hostname: String,
    kind: String,
    state: String,
    desired_state: String,
    dns_state: String,
    certificate_state: String,
    verification_name: Option<String>,
    verification_value: Option<String>,
    routing_name: Option<String>,
    routing_target: Option<String>,
    ownership_verified_at: Option<String>,
    last_health_checked_at: Option<String>,
    last_error_class: Option<String>,
    canonical: bool,
    redirect_target: Option<String>,
    edge_verification_records: Vec<EdgeVerificationRecordResponse>,
    operation_id: Option<Uuid>,
    version: i64,
    can_manage: bool,
}

#[derive(sqlx::FromRow)]
struct DomainRow {
    id: Uuid,
    hostname: String,
    state: String,
    desired_state: String,
    dns_state: String,
    certificate_state: String,
    verification_name: String,
    verification_value: String,
    routing_target: String,
    ownership_verified_at: Option<OffsetDateTime>,
    last_health_checked_at: Option<OffsetDateTime>,
    last_error_class: Option<String>,
    canonical: bool,
    redirect_target: Option<String>,
    edge_verification_records: Value,
    operation_id: Option<Uuid>,
    version: i64,
}

fn reserved_suffix(hostname: &str) -> bool {
    const RESERVED: [&str; 9] = [
        "localhost",
        "local",
        "internal",
        "invalid",
        "example",
        "test",
        "onion",
        "home",
        "corp",
    ];
    RESERVED
        .iter()
        .any(|suffix| hostname == *suffix || hostname.ends_with(&format!(".{suffix}")))
}

pub(crate) fn normalize_custom_hostname(
    value: &str,
    tenant_domain: &str,
) -> Result<String, &'static str> {
    let candidate = value
        .trim()
        .trim_end_matches('.')
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    if candidate.contains('/') || candidate.contains(':') || candidate.len() > 253 {
        return Err("enter a hostname without a path or port");
    }
    let normalized = match Host::parse(candidate).map_err(|_| "hostname is invalid")? {
        Host::Domain(domain) => domain.to_ascii_lowercase(),
        Host::Ipv4(_) | Host::Ipv6(_) => return Err("IP addresses cannot be connected"),
    };
    if psl::domain_str(&normalized).is_none() {
        return Err("a registrable domain or subdomain is required");
    }
    if reserved_suffix(&normalized) {
        return Err("reserved hostnames cannot be connected");
    }
    if normalized == tenant_domain
        || normalized.ends_with(&format!(".{tenant_domain}"))
        || [
            "makersbrain.com",
            "makersbrain.app",
            "makersbrain.net",
            "makersbrain.org",
        ]
        .iter()
        .any(|zone| normalized == *zone || normalized.ends_with(&format!(".{zone}")))
    {
        return Err("MakersBrain-owned hostnames cannot be connected as custom domains");
    }
    if normalized.split('.').any(|label| {
        label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    }) {
        return Err("hostname labels are invalid");
    }
    Ok(normalized)
}

async fn require_webshop_enabled(state: &AppState, workshop: Uuid) -> ApiResult<()> {
    let enabled = sqlx::query_scalar::<_, bool>(
        "select exists(select 1 from control.workshop_modules
          where workshop_id=$1 and module_key='webshop' and state='enabled')",
    )
    .bind(workshop)
    .fetch_one(state.store.pool())
    .await?;
    if !enabled {
        return Err(ApiError::Conflict("The webshop must be enabled first"));
    }
    Ok(())
}

fn edge_verification_records(value: Value) -> Vec<EdgeVerificationRecordResponse> {
    value
        .as_array()
        .into_iter()
        .flatten()
        .take(32)
        .filter_map(|candidate| {
            let candidate = candidate.as_object()?;
            let bounded = |key: &str, maximum: usize| {
                candidate
                    .get(key)?
                    .as_str()
                    .filter(|value| !value.is_empty() && value.len() <= maximum)
                    .map(ToOwned::to_owned)
            };
            Some(EdgeVerificationRecordResponse {
                record_type: bounded("type", 16)?,
                name: bounded("name", 253)?,
                value: bounded("value", 4096)?,
            })
        })
        .collect()
}

fn response(row: DomainRow, can_manage: bool) -> WebshopDomainResponse {
    WebshopDomainResponse {
        id: Some(row.id),
        hostname: row.hostname.clone(),
        kind: "custom_domain".into(),
        state: row.state,
        desired_state: row.desired_state,
        dns_state: row.dns_state,
        certificate_state: row.certificate_state,
        verification_name: Some(row.verification_name),
        verification_value: Some(row.verification_value),
        routing_name: Some(row.hostname),
        routing_target: Some(row.routing_target),
        ownership_verified_at: row.ownership_verified_at.map(api_timestamp),
        last_health_checked_at: row.last_health_checked_at.map(api_timestamp),
        last_error_class: row.last_error_class,
        canonical: row.canonical,
        redirect_target: row.redirect_target,
        edge_verification_records: edge_verification_records(row.edge_verification_records),
        operation_id: row.operation_id,
        version: row.version,
        can_manage,
    }
}

fn txt_answer_matches(payload: &Value, expected: &str) -> bool {
    payload
        .get("Answer")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|answer| answer.get("type").and_then(Value::as_u64) == Some(16))
        .filter_map(|answer| answer.get("data").and_then(Value::as_str))
        .any(|data| {
            data.chars()
                .filter(|character| *character != '"' && !character.is_ascii_whitespace())
                .collect::<String>()
                == expected
        })
}

async fn ownership_txt_present(
    client: &reqwest::Client,
    name: &str,
    expected: &str,
) -> ApiResult<bool> {
    let mut endpoint = Url::parse("https://cloudflare-dns.com/dns-query")
        .map_err(|error| ApiError::Internal(error.into()))?;
    endpoint
        .query_pairs_mut()
        .append_pair("name", name)
        .append_pair("type", "TXT");
    let response = client
        .get(endpoint)
        .header(header::ACCEPT, "application/dns-json")
        .with_current_trace_context()
        .send()
        .await
        .map_err(|_| ApiError::Conflict("DNS verification is temporarily unavailable"))?;
    if !response.status().is_success() {
        return Err(ApiError::Conflict(
            "DNS verification is temporarily unavailable",
        ));
    }
    let payload = response
        .json::<Value>()
        .await
        .map_err(|_| ApiError::Conflict("DNS verification returned an invalid response"))?;
    Ok(txt_answer_matches(&payload, expected))
}

pub(super) async fn list(
    State(state): State<Arc<AppState>>,
    Extension(scope): Extension<WorkshopScope>,
) -> ApiResult<Json<Vec<WebshopDomainResponse>>> {
    let workshop = scope.workshop_id;
    let mut tx = state.tenant_store.begin(workshop).await?;
    let platform = sqlx::query_scalar::<_, String>(
        "select public_hostname from control.odoo_databases
          where workshop_id=$1 and kind='primary' and deleted_at is null",
    )
    .bind(workshop)
    .fetch_one(&mut *tx)
    .await?;
    let rows = sqlx::query_as::<_, DomainRow>(
        "select id,hostname,state,desired_state,dns_state,certificate_state,
                verification_name,verification_value,routing_target,ownership_verified_at,
                last_health_checked_at,last_error_class,canonical,redirect_target,
                edge_verification_records,operation_id,version
           from control.webshop_domains
          where workshop_id=$1 and state<>'disconnected'
          order by canonical desc,hostname",
    )
    .bind(workshop)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    let can_manage = scope.role.can_manage_modules();
    let mut result = vec![WebshopDomainResponse {
        id: None,
        hostname: platform.clone(),
        kind: "platform_subdomain".into(),
        state: "active".into(),
        desired_state: "active".into(),
        dns_state: "verified".into(),
        certificate_state: "active".into(),
        verification_name: None,
        verification_value: None,
        routing_name: None,
        routing_target: None,
        ownership_verified_at: None,
        last_health_checked_at: None,
        last_error_class: None,
        canonical: rows.iter().all(|row| !row.canonical),
        redirect_target: None,
        edge_verification_records: Vec::new(),
        operation_id: None,
        version: 1,
        can_manage,
    }];
    result.extend(rows.into_iter().map(|row| response(row, can_manage)));
    Ok(Json(result))
}

pub(super) async fn create(
    State(state): State<Arc<AppState>>,
    Extension(scope): Extension<WorkshopScope>,
    headers: HeaderMap,
    Json(body): Json<CustomDomainCreateBody>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let workshop = scope.workshop_id;
    require_webshop_enabled(&state, workshop).await?;
    let hostname = normalize_custom_hostname(&body.hostname, &state.config.tenant_domain)
        .map_err(ApiError::Validation)?;
    let client_key = idempotency(&headers)?;
    let semantic = json!({"hostname":hostname});
    let command_scope = format!("workshop:{workshop}:webshop-domains");
    let mut tx = state.tenant_store.begin(scope.workshop_id).await?;
    revalidate_workshop_scope(&mut tx, &scope).await?;
    let command_id = match admit_command(
        &mut tx,
        NewCommand {
            actor_user_id: scope.principal_id,
            scope: &command_scope,
            command_kind: "webshop-domain.create",
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
                StatusCode::from_u16(response_status).unwrap_or(StatusCode::OK),
                Json(response_body.unwrap_or_else(|| json!({"replayed":true}))),
            ));
        }
        CommandAdmission::InProgress { command_id, .. } => {
            tx.commit().await?;
            return Ok((
                StatusCode::ACCEPTED,
                Json(json!({"command_id":command_id,"in_progress":true})),
            ));
        }
    };
    let proposed_id = Uuid::new_v4();
    let token = Alphanumeric.sample_string(&mut rand::rng(), 32);
    let verification_name = format!("_mb-challenge.{hostname}");
    let verification_value = format!("mb-verification={token}");
    let routing_target = format!("shops.{}", state.config.tenant_domain);
    let (outcome, id, version) = sqlx::query_as::<_, (String, Option<Uuid>, Option<i64>)>(
        "select outcome,domain_id,domain_version
           from control.claim_webshop_domain($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(proposed_id)
    .bind(workshop)
    .bind(&hostname)
    .bind(&verification_name)
    .bind(&verification_value)
    .bind(&routing_target)
    .bind(scope.principal_id)
    .fetch_one(&mut *tx)
    .await?;
    if outcome == "conflict" {
        return Err(ApiError::Conflict("This hostname is already claimed"));
    }
    if !matches!(outcome.as_str(), "created" | "reclaimed") {
        return Err(ApiError::Internal(anyhow::anyhow!(
            "webshop domain claim contract drift"
        )));
    }
    let id = id.ok_or_else(|| {
        ApiError::Internal(anyhow::anyhow!("webshop domain claim omitted its identity"))
    })?;
    let version = version.ok_or_else(|| {
        ApiError::Internal(anyhow::anyhow!("webshop domain claim omitted its version"))
    })?;
    let public = json!({
        "id":id,"hostname":hostname,"kind":"custom_domain",
        "state":"ownership_pending","desired_state":"active",
        "dns_state":"pending","certificate_state":"pending",
        "verification_name":verification_name,"verification_value":verification_value,
        "routing_name":hostname,"routing_target":routing_target,
        "canonical":false,"edge_verification_records":[],"operation_id":null,
        "version":version,"can_manage":true
    });
    audit_command(
        &mut tx,
        (Some(scope.principal_id), Some(workshop)),
        "webshop-domain.create",
        "webshop-domain",
        id.to_string(),
        Uuid::new_v4(),
        command_id,
    )
    .await?;
    complete_command(
        &mut tx,
        command_id,
        CommandResult {
            operation_id: None,
            response_status: StatusCode::CREATED.as_u16(),
            response_body: Some(&public),
            result_ref: None,
        },
    )
    .await
    .map_err(command_error)?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(public)))
}

pub(super) async fn verify(
    State(state): State<Arc<AppState>>,
    Extension(scope): Extension<WorkshopScope>,
    headers: HeaderMap,
    Path((_workshop, domain_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let workshop = scope.workshop_id;
    require_webshop_enabled(&state, workshop).await?;
    let client_key = idempotency(&headers)?;
    let semantic = json!({"domain_id":domain_id});
    let command_scope = format!("workshop:{workshop}:webshop-domain:{domain_id}");
    let mut tx = state.tenant_store.begin(scope.workshop_id).await?;
    revalidate_workshop_scope(&mut tx, &scope).await?;
    let command_id = match admit_command(
        &mut tx,
        NewCommand {
            actor_user_id: scope.principal_id,
            scope: &command_scope,
            command_kind: "webshop-domain.verify-ownership",
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
                StatusCode::from_u16(response_status).unwrap_or(StatusCode::OK),
                Json(response_body.unwrap_or_else(|| json!({"replayed":true}))),
            ));
        }
        CommandAdmission::InProgress { command_id, .. } => {
            tx.commit().await?;
            return Ok((
                StatusCode::ACCEPTED,
                Json(json!({"command_id":command_id,"in_progress":true})),
            ));
        }
    };
    let existing = sqlx::query_as::<_, DomainRow>(
        "select id,hostname,state,desired_state,dns_state,certificate_state,
                verification_name,verification_value,routing_target,ownership_verified_at,
                last_health_checked_at,last_error_class,canonical,redirect_target,
                edge_verification_records,operation_id,version
           from control.webshop_domains
          where id=$1 and workshop_id=$2 and desired_state='active'
            and state in ('ownership_pending','action_required')",
    )
    .bind(domain_id)
    .bind(workshop)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(ApiError::NotFound)?;
    let present = ownership_txt_present(
        &state.dns_client,
        &existing.verification_name,
        &existing.verification_value,
    )
    .await?;
    sqlx::query(
        "update control.webshop_domains
            set state=case when $3 then 'dns_pending' else 'ownership_pending' end,
                ownership_verified_at=case when $3 then coalesce(ownership_verified_at,now()) else ownership_verified_at end,
                last_health_checked_at=now(),
                last_error_class=case when $3 then null else 'ownership_txt_missing' end,
                version=version+1,updated_at=now()
          where id=$1 and workshop_id=$2 and desired_state='active'
            and state in ('ownership_pending','action_required')",
    )
    .bind(domain_id)
    .bind(workshop)
    .bind(present)
    .execute(&mut *tx)
    .await?;
    let operation_id = if present {
        let operation_id = Store::enqueue(
            &mut tx,
            NewOperation {
                kind: OperationKind::WebshopDomainReconcile,
                workshop_id: Some(workshop),
                target_user_id: None,
                desired_epoch: None,
                payload: &json!({"domain_id":domain_id}),
                requested_by: Some(scope.principal_id),
                correlation_id: Uuid::new_v4(),
                idempotency_key: &format!("command:{command_id}"),
            },
        )
        .await?;
        sqlx::query(
            "update control.webshop_domains set operation_id=$2 where id=$1 and workshop_id=$3",
        )
        .bind(domain_id)
        .bind(operation_id)
        .bind(workshop)
        .execute(&mut *tx)
        .await?;
        Some(operation_id)
    } else {
        None
    };
    let row = sqlx::query_as::<_, DomainRow>(
        "select id,hostname,state,desired_state,dns_state,certificate_state,
                verification_name,verification_value,routing_target,ownership_verified_at,
                last_health_checked_at,last_error_class,canonical,redirect_target,
                edge_verification_records,operation_id,version
           from control.webshop_domains where id=$1 and workshop_id=$2",
    )
    .bind(domain_id)
    .bind(workshop)
    .fetch_one(&mut *tx)
    .await?;
    let public = serde_json::to_value(response(row, true))
        .map_err(|error| ApiError::Internal(error.into()))?;
    audit_command(
        &mut tx,
        (Some(scope.principal_id), Some(workshop)),
        if present {
            "webshop-domain.ownership-verified"
        } else {
            "webshop-domain.ownership-pending"
        },
        "webshop-domain",
        domain_id.to_string(),
        Uuid::new_v4(),
        command_id,
    )
    .await?;
    complete_command(
        &mut tx,
        command_id,
        CommandResult {
            operation_id,
            response_status: StatusCode::OK.as_u16(),
            response_body: Some(&public),
            result_ref: None,
        },
    )
    .await
    .map_err(command_error)?;
    tx.commit().await?;
    Ok((StatusCode::OK, Json(public)))
}

pub(super) async fn make_canonical(
    State(state): State<Arc<AppState>>,
    Extension(scope): Extension<WorkshopScope>,
    headers: HeaderMap,
    Path((_workshop, domain_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let workshop = scope.workshop_id;
    require_webshop_enabled(&state, workshop).await?;
    let version = expected_version(&headers, &format!("webshop-domain-{domain_id}"))?;
    let client_key = idempotency(&headers)?;
    let semantic = json!({"domain_id":domain_id,"version":version});
    let command_scope = format!("workshop:{workshop}:webshop-domain:{domain_id}");
    let mut tx = state.tenant_store.begin(scope.workshop_id).await?;
    revalidate_workshop_scope(&mut tx, &scope).await?;
    let command_id = match admit_command(
        &mut tx,
        NewCommand {
            actor_user_id: scope.principal_id,
            scope: &command_scope,
            command_kind: "webshop-domain.make-canonical",
            idempotency_key: client_key,
            semantic_request: &semantic,
            expected_version: Some(version),
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
    let hostname = sqlx::query_scalar::<_, String>(
        "select hostname from control.webshop_domains
          where id=$1 and workshop_id=$2 and state='active'
            and certificate_state='active' and version=$3 for update",
    )
    .bind(domain_id)
    .bind(workshop)
    .bind(version)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(ApiError::PreconditionFailed(
        "Only an active, current custom domain can become canonical",
    ))?;
    let operation_id = Store::enqueue(
        &mut tx,
        NewOperation {
            kind: OperationKind::WebshopDomainReconcile,
            workshop_id: Some(workshop),
            target_user_id: None,
            desired_epoch: None,
            payload: &json!({"domain_id":domain_id,"reason":"canonical_changed"}),
            requested_by: Some(scope.principal_id),
            correlation_id: Uuid::new_v4(),
            idempotency_key: &format!("command:{command_id}"),
        },
    )
    .await?;
    sqlx::query(
        "update control.webshop_domains
            set canonical=false,redirect_target=$2,updated_at=now(),version=version+1
          where workshop_id=$1 and canonical and id<>$3 and state<>'disconnected'",
    )
    .bind(workshop)
    .bind(&hostname)
    .bind(domain_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "update control.webshop_domains
            set canonical=true,redirect_target=null,operation_id=$3,updated_at=now(),version=version+1
          where id=$1 and workshop_id=$2",
    )
    .bind(domain_id)
    .bind(workshop)
    .bind(operation_id)
    .execute(&mut *tx)
    .await?;
    let row = sqlx::query_as::<_, DomainRow>(
        "select id,hostname,state,desired_state,dns_state,certificate_state,
                verification_name,verification_value,routing_target,ownership_verified_at,
                last_health_checked_at,last_error_class,canonical,redirect_target,
                edge_verification_records,operation_id,version
           from control.webshop_domains where id=$1 and workshop_id=$2",
    )
    .bind(domain_id)
    .bind(workshop)
    .fetch_one(&mut *tx)
    .await?;
    let public = serde_json::to_value(response(row, true))
        .map_err(|error| ApiError::Internal(error.into()))?;
    audit_command(
        &mut tx,
        (Some(scope.principal_id), Some(workshop)),
        "webshop-domain.make-canonical",
        "webshop-domain",
        domain_id.to_string(),
        Uuid::new_v4(),
        command_id,
    )
    .await?;
    complete_command(
        &mut tx,
        command_id,
        CommandResult {
            operation_id: Some(operation_id),
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

pub(super) async fn disconnect(
    State(state): State<Arc<AppState>>,
    Extension(scope): Extension<WorkshopScope>,
    headers: HeaderMap,
    Path((_workshop, domain_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let workshop = scope.workshop_id;
    require_webshop_enabled(&state, workshop).await?;
    let version = expected_version(&headers, &format!("webshop-domain-{domain_id}"))?;
    let client_key = idempotency(&headers)?;
    let semantic = json!({"domain_id":domain_id,"version":version});
    let command_scope = format!("workshop:{workshop}:webshop-domain:{domain_id}");
    let mut tx = state.tenant_store.begin(scope.workshop_id).await?;
    revalidate_workshop_scope(&mut tx, &scope).await?;
    let command_id = match admit_command(
        &mut tx,
        NewCommand {
            actor_user_id: scope.principal_id,
            scope: &command_scope,
            command_kind: "webshop-domain.disconnect",
            idempotency_key: client_key,
            semantic_request: &semantic,
            expected_version: Some(version),
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
    let was_canonical = sqlx::query_scalar::<_, bool>(
        "select canonical from control.webshop_domains
          where id=$1 and workshop_id=$2 and state<>'disconnected'
            and desired_state='active' and version=$3 for update",
    )
    .bind(domain_id)
    .bind(workshop)
    .bind(version)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(ApiError::PreconditionFailed(
        "Only a connected, current custom domain can be disconnected",
    ))?;
    let operation_id = Store::enqueue(
        &mut tx,
        NewOperation {
            kind: OperationKind::WebshopDomainReconcile,
            workshop_id: Some(workshop),
            target_user_id: None,
            desired_epoch: None,
            payload: &json!({
                "domain_id":domain_id,
                "reason":"disconnect",
                "restore_platform_canonical":was_canonical
            }),
            requested_by: Some(scope.principal_id),
            correlation_id: Uuid::new_v4(),
            idempotency_key: &format!("command:{command_id}"),
        },
    )
    .await?;
    let platform_hostname = sqlx::query_scalar::<_, String>(
        "select public_hostname from control.odoo_databases
          where workshop_id=$1 and kind='primary' and deleted_at is null",
    )
    .bind(workshop)
    .fetch_one(&mut *tx)
    .await?;
    sqlx::query(
        "update control.webshop_domains
            set state='disconnecting',desired_state='disconnected',canonical=false,
                redirect_target=case when $4 then $5 else null end,
                operation_id=$3,last_error_class=null,
                updated_at=now(),version=version+1
          where id=$1 and workshop_id=$2",
    )
    .bind(domain_id)
    .bind(workshop)
    .bind(operation_id)
    .bind(was_canonical)
    .bind(&platform_hostname)
    .execute(&mut *tx)
    .await?;
    if was_canonical {
        sqlx::query(
            "update control.webshop_domains set redirect_target=$2,updated_at=now(),version=version+1
              where workshop_id=$1 and desired_state='active' and id<>$3",
        )
        .bind(workshop)
        .bind(platform_hostname)
        .bind(domain_id)
        .execute(&mut *tx)
        .await?;
    }
    let row = sqlx::query_as::<_, DomainRow>(
        "select id,hostname,state,desired_state,dns_state,certificate_state,
                verification_name,verification_value,routing_target,ownership_verified_at,
                last_health_checked_at,last_error_class,canonical,redirect_target,
                edge_verification_records,operation_id,version
           from control.webshop_domains where id=$1 and workshop_id=$2",
    )
    .bind(domain_id)
    .bind(workshop)
    .fetch_one(&mut *tx)
    .await?;
    let public = serde_json::to_value(response(row, true))
        .map_err(|error| ApiError::Internal(error.into()))?;
    audit_command(
        &mut tx,
        (Some(scope.principal_id), Some(workshop)),
        "webshop-domain.disconnect",
        "webshop-domain",
        domain_id.to_string(),
        Uuid::new_v4(),
        command_id,
    )
    .await?;
    complete_command(
        &mut tx,
        command_id,
        CommandResult {
            operation_id: Some(operation_id),
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
    fn custom_hostname_normalization_is_idna_safe_and_rejects_unsafe_targets() {
        assert_eq!(
            normalize_custom_hostname(" HTTPS://Atelier-Café.FR./ ", "makersbrain.com"),
            Err("enter a hostname without a path or port")
        );
        assert_eq!(
            normalize_custom_hostname("Atelier-Café.FR.", "makersbrain.com").unwrap(),
            "xn--atelier-caf-lbb.fr"
        );
        assert!(normalize_custom_hostname("127.0.0.1", "makersbrain.com").is_err());
        assert!(normalize_custom_hostname("co.uk", "makersbrain.com").is_err());
        assert!(normalize_custom_hostname("shop.makersbrain.com", "makersbrain.com").is_err());
        for zone in [
            "makersbrain.com",
            "makersbrain.app",
            "makersbrain.net",
            "makersbrain.org",
        ] {
            assert!(normalize_custom_hostname(&format!("shop.{zone}"), "tenant.invalid").is_err());
        }
        assert!(normalize_custom_hostname("shop.example", "makersbrain.com").is_err());
    }

    #[test]
    fn dns_json_txt_matching_handles_quoted_and_split_txt_answers() {
        let payload = json!({"Answer":[
            {"type":1,"data":"192.0.2.1"},
            {"type":16,"data":"\"mb-\" \"verification=abc\""}
        ]});
        assert!(txt_answer_matches(&payload, "mb-verification=abc"));
        assert!(!txt_answer_matches(&payload, "mb-verification=other"));
    }

    #[test]
    fn edge_verification_projection_exposes_only_complete_typed_records() {
        let records = edge_verification_records(json!([
            {"type":"txt","name":"_acme.example.test","value":"proof","provider_debug":"private"},
            {"type":"txt","name":"missing-value.example.test"},
            "invalid"
        ]));

        assert_eq!(records.len(), 1);
        let public = serde_json::to_value(&records).unwrap();
        assert_eq!(
            public,
            json!([{"type":"txt","name":"_acme.example.test","value":"proof"}])
        );
    }
}
