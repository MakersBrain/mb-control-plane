use std::str::FromStr;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::{delete, get, patch, post};
use axum::{Json, Router};
use base64::Engine;
use rand::RngCore;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::cors::CorsLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::sensitive_headers::SetSensitiveRequestHeadersLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;
use uuid::Uuid;

use crate::Config;
use crate::api_error::ApiError;
use crate::auth::{Authenticator, Principal};
use crate::domain::{OperationKind, WorkshopRole, normalize_email, opaque_database_ref};
use crate::persistence::{NewOperation, Store};

type ApiResult<T> = Result<T, ApiError>;

#[derive(Clone)]
pub struct AppState {
    pub store: Store,
    pub config: Config,
    pub auth: Arc<Authenticator>,
}

pub fn app(state: AppState) -> Router {
    let origin: HeaderValue = state
        .config
        .cors_origin
        .as_str()
        .trim_end_matches('/')
        .parse()
        .expect("validated CORS origin is a header value");
    Router::new()
        .route("/health/live", get(live))
        .route("/health/ready", get(ready))
        .route("/v1/version", get(version))
        .route("/openapi.json", get(openapi))
        .route("/v1/me", get(me))
        .route("/v1/identity/link", post(link_identity))
        .route("/v1/workshops", get(workshops).post(create_workshop))
        .route("/v1/workshops/{id}", get(workshop))
        .route("/v1/workshops/{id}/members", get(members))
        .route(
            "/v1/workshops/{id}/invitations",
            get(invitations).post(invite),
        )
        .route("/v1/invitations/{id}/resend", post(resend_invitation))
        .route("/v1/invitations/{id}", delete(revoke_invitation))
        .route("/v1/invitations/{token}/validate", get(validate_invitation))
        .route("/v1/invitations/{token}/accept", post(accept_invitation))
        .route(
            "/v1/workshops/{id}/members/{user_id}",
            patch(update_member).delete(remove_member),
        )
        .route(
            "/v1/workshops/{id}/ownership-transfers",
            get(ownership_transfers).post(create_ownership_transfer),
        )
        .route(
            "/v1/ownership-transfers/{id}/accept",
            post(accept_ownership_transfer),
        )
        .route("/v1/workshops/{id}/integrations", get(integrations))
        .route("/v1/workshops/{id}/modules", get(modules))
        .route(
            "/v1/workshops/{id}/modules/{module_key}/enable",
            post(enable_module),
        )
        .route("/v1/workshops/{id}/database", get(database))
        .route(
            "/v1/workshops/{id}/database/snapshots",
            post(create_snapshot),
        )
        .route("/v1/workshops/{id}/database/backups", post(create_backup))
        .route(
            "/v1/workshops/{id}/database/restores",
            post(restore_database),
        )
        .route(
            "/v1/workshops/{id}/database/duplicates",
            post(duplicate_database),
        )
        .route("/v1/operations/{id}", get(operation))
        .route("/v1/operations/{id}/retry", post(retry_operation))
        .route(
            "/internal/v1/paperless/{workshop_id}/events",
            post(paperless_event),
        )
        .route(
            "/internal/v1/tenants/{workshop_id}/reconcile",
            post(reconcile_tenant),
        )
        .route(
            "/internal/v1/entitlements/{workshop_id}/ack",
            post(ack_entitlement),
        )
        .layer(
            CorsLayer::new()
                .allow_origin(origin)
                .allow_methods([Method::GET, Method::POST, Method::PATCH, Method::DELETE])
                .allow_headers([
                    header::AUTHORIZATION,
                    header::CONTENT_TYPE,
                    header::IF_MATCH,
                    header::HeaderName::from_static("idempotency-key"),
                ]),
        )
        .layer(RequestBodyLimitLayer::new(1024 * 1024))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::GATEWAY_TIMEOUT,
            state.config.request_timeout,
        ))
        .layer(CatchPanicLayer::new())
        .layer(TraceLayer::new_for_http())
        .layer(SetSensitiveRequestHeadersLayer::new([
            header::AUTHORIZATION,
            header::COOKIE,
        ]))
        .with_state(Arc::new(state))
}

async fn principal(state: &AppState, headers: &HeaderMap) -> ApiResult<Principal> {
    state.auth.authenticate(headers, &state.store).await
}

async fn authority(state: &AppState, user: Uuid, workshop: Uuid) -> ApiResult<(WorkshopRole, i32)> {
    let (role, epoch) = sqlx::query_as::<_, (String, i32)>(
        "select role,authority_epoch from control.memberships
         where workshop_id=$1 and user_id=$2 and status='active'",
    )
    .bind(workshop)
    .bind(user)
    .fetch_optional(state.store.pool())
    .await?
    .ok_or(ApiError::NotFound)?;
    Ok((
        WorkshopRole::from_str(&role)
            .map_err(|_| ApiError::Internal(anyhow::anyhow!("invalid stored role")))?,
        epoch,
    ))
}

fn idempotency(headers: &HeaderMap) -> ApiResult<&str> {
    headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty() && value.len() <= 200)
        .ok_or(ApiError::Precondition("Idempotency-Key is required"))
}

fn internal(state: &AppState, headers: &HeaderMap) -> ApiResult<()> {
    let supplied = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    if supplied != Some(state.config.internal_token.as_str()) {
        return Err(ApiError::Unauthenticated);
    }
    Ok(())
}

async fn live() -> impl IntoResponse {
    Json(json!({"status": "live"}))
}

async fn ready(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    if state.store.ready().await && state.auth.ready().await {
        (StatusCode::OK, Json(json!({"status": "ready"})))
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"status": "unavailable"})),
        )
    }
}

async fn version() -> impl IntoResponse {
    Json(json!({"name": "makersbrain-control-plane", "version": env!("CARGO_PKG_VERSION")}))
}

async fn openapi() -> impl IntoResponse {
    Json(crate::openapi::document())
}

async fn me(State(state): State<Arc<AppState>>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let who = principal(&state, &headers).await?;
    Ok(Json(
        json!({"id": who.user_id, "email": who.email, "subject": who.subject}),
    ))
}

async fn link_identity(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let verified = state.auth.verify_headers(&headers).await?;
    let mut tx = state.store.begin().await?;
    if let Some(user_id) = sqlx::query_scalar::<_, Uuid>(
        "select user_id from control.external_identities where issuer=$1 and subject=$2 and disabled_at is null",
    )
    .bind(&verified.issuer)
    .bind(&verified.subject)
    .fetch_optional(&mut *tx)
    .await?
    {
        tx.commit().await?;
        return Ok((StatusCode::OK, Json(json!({"user_id":user_id,"linked":false}))));
    }
    let user_id = match sqlx::query_scalar::<_, Uuid>(
        "select u.id from control.users u where u.email=$1 and u.disabled_at is null and not exists(select 1 from control.external_identities i where i.user_id=u.id)",
    )
    .bind(&verified.email)
    .fetch_optional(&mut *tx)
    .await?
    {
        Some(user_id) => user_id,
        None if state.config.allow_self_signup => {
            let user_id = Uuid::new_v4();
            sqlx::query("insert into control.users(id,email) values($1,$2)")
                .bind(user_id).bind(&verified.email).execute(&mut *tx).await?;
            user_id
        }
        None => return Err(ApiError::Unauthenticated),
    };
    sqlx::query("insert into control.external_identities(id,user_id,issuer,subject,email_at_link) values($1,$2,$3,$4,$5)")
        .bind(Uuid::new_v4()).bind(user_id).bind(&verified.issuer).bind(&verified.subject).bind(&verified.email).execute(&mut *tx).await?;
    let correlation = Uuid::new_v4();
    audit(
        &mut tx,
        Some(user_id),
        None,
        "identity.link",
        "user",
        user_id.to_string(),
        correlation,
    )
    .await?;
    tx.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({"user_id":user_id,"linked":true})),
    ))
}

async fn workshops(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    let who = principal(&state, &headers).await?;
    let rows = sqlx::query_as::<_, (Uuid, String, String, String, String, i64, String, i32)>(
        "select w.id,w.slug,w.display_name,w.status,w.plan,w.version,m.role,m.authority_epoch
         from control.workshops w join control.memberships m on m.workshop_id=w.id
         where m.user_id=$1 and m.status='active' and w.status<>'deleted' order by w.display_name,w.id",
    ).bind(who.user_id).fetch_all(state.store.pool()).await?;
    Ok(Json(Value::Array(rows.into_iter().map(|r| json!({
        "id":r.0,"slug":r.1,"display_name":r.2,"status":r.3,"plan":r.4,"version":r.5,"role":r.6,"authority_epoch":r.7
    })).collect())))
}

#[derive(Deserialize)]
struct CreateWorkshop {
    slug: String,
    display_name: String,
    country_code: Option<String>,
    time_zone: String,
}

async fn create_workshop(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<CreateWorkshop>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let who = principal(&state, &headers).await?;
    let key = idempotency(&headers)?.to_owned();
    if body.display_name.trim().is_empty() {
        return Err(ApiError::Validation("display_name is required"));
    }
    let workshop_id = Uuid::new_v4();
    let database_id = Uuid::new_v4();
    let database_ref = opaque_database_ref(database_id);
    let public_hostname = format!("{}.{}", body.slug, state.config.tenant_domain);
    let paperless_hostname = format!("docs-{}.{}", body.slug, state.config.tenant_domain);
    let operation_id = Uuid::new_v4();
    let correlation_id = Uuid::new_v4();
    let mut tx = state.store.begin().await?;
    let inserted = sqlx::query_scalar::<_, Uuid>(
        "insert into control.workshops(id,slug,display_name,country_code,time_zone)
         values($1,$2,$3,$4,$5) on conflict(slug) do nothing returning id",
    )
    .bind(workshop_id)
    .bind(&body.slug)
    .bind(body.display_name.trim())
    .bind(&body.country_code)
    .bind(&body.time_zone)
    .fetch_optional(&mut *tx)
    .await?;
    if inserted.is_none() {
        return Err(ApiError::Conflict("workshop slug already exists"));
    }
    sqlx::query("insert into control.memberships(workshop_id,user_id,role) values($1,$2,'owner')")
        .bind(workshop_id)
        .bind(who.user_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("insert into control.odoo_databases(id,workshop_id,kind,database_ref,public_hostname,label,routable) values($1,$2,'primary',$3,$4,'Primary database',true)")
        .bind(database_id).bind(workshop_id).bind(&database_ref).bind(&public_hostname).execute(&mut *tx).await?;
    sqlx::query("insert into control.operations(id,kind,queue,workshop_id,target_user_id,desired_epoch,payload,requested_by,correlation_id,idempotency_key)
                 values($1,'tenant.provision','tenant-provisioning',$2,$3,1,$4,$3,$5,$6)")
        .bind(operation_id).bind(workshop_id).bind(who.user_id).bind(json!({"generation":1,"database_id":database_id,"database_ref":database_ref,"public_hostname":public_hostname,"paperless_hostname":paperless_hostname,"paperless_enabled":false})).bind(correlation_id).bind(&key).execute(&mut *tx).await?;
    audit(
        &mut tx,
        Some(who.user_id),
        Some(workshop_id),
        "workshop.create",
        "workshop",
        workshop_id.to_string(),
        correlation_id,
    )
    .await?;
    tx.commit().await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(json!({"id":workshop_id,"operation_id":operation_id})),
    ))
}

async fn workshop(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let who = principal(&state, &headers).await?;
    let (role, epoch) = authority(&state, who.user_id, id).await?;
    let row = sqlx::query_as::<_, (String, String, String, String, i64)>(
        "select slug,display_name,status,plan,version from control.workshops where id=$1",
    )
    .bind(id)
    .fetch_one(state.store.pool())
    .await?;
    Ok(Json(
        json!({"id":id,"slug":row.0,"display_name":row.1,"status":row.2,"plan":row.3,"version":row.4,"role":role,"authority_epoch":epoch}),
    ))
}

async fn members(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let who = principal(&state, &headers).await?;
    authority(&state, who.user_id, id).await?;
    let rows = sqlx::query_as::<_, (Uuid,String,Option<String>,String,String,i32,Value)>(
        "select u.id,u.email,u.display_name,m.role,m.status,m.authority_epoch,
           coalesce(jsonb_object_agg(t.target,jsonb_build_object('state',t.state,'desired_epoch',t.desired_epoch,'applied_epoch',t.applied_epoch,'error',t.safe_error_class)) filter(where t.target is not null),'{}')
         from control.memberships m join control.users u on u.id=m.user_id
         left join control.membership_targets t on t.workshop_id=m.workshop_id and t.user_id=m.user_id
         where m.workshop_id=$1 group by u.id,u.email,u.display_name,m.role,m.status,m.authority_epoch order by u.email",
    ).bind(id).fetch_all(state.store.pool()).await?;
    Ok(Json(Value::Array(rows.into_iter().map(|r| json!({"id":r.0,"email":r.1,"display_name":r.2,"role":r.3,"status":r.4,"authority_epoch":r.5,"targets":r.6})).collect())))
}

#[derive(Deserialize)]
struct InviteBody {
    email: String,
    role: WorkshopRole,
    #[serde(default = "default_locale")]
    locale: String,
}
fn default_locale() -> String {
    "en".into()
}

fn new_token() -> (String, Vec<u8>) {
    let mut bytes = [0_u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    let digest = Sha256::digest(token.as_bytes()).to_vec();
    (token, digest)
}

async fn invitations(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let who = principal(&state, &headers).await?;
    if !authority(&state, who.user_id, id)
        .await?
        .0
        .can_manage_members()
    {
        return Err(ApiError::Forbidden);
    }
    let rows = sqlx::query_as::<_, (Uuid, String, String, String, OffsetDateTime, i32, OffsetDateTime)>(
        "select id,email,role,locale,expires_at,sent_count,last_sent_at from control.invitations where workshop_id=$1 and accepted_at is null and revoked_at is null order by created_at desc",
    ).bind(id).fetch_all(state.store.pool()).await?;
    Ok(Json(Value::Array(rows.into_iter().map(|r|json!({"id":r.0,"email":r.1,"role":r.2,"locale":r.3,"expires_at":r.4,"sent_count":r.5,"last_sent_at":r.6})).collect())))
}

async fn invite(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(body): Json<InviteBody>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let who = principal(&state, &headers).await?;
    let (role, _) = authority(&state, who.user_id, id).await?;
    if !role.can_manage_members() || !body.role.can_invite() {
        return Err(ApiError::Forbidden);
    }
    if !matches!(body.locale.as_str(), "en" | "fr") {
        return Err(ApiError::Validation("locale must be en or fr"));
    }
    let key = idempotency(&headers)?.to_owned();
    let email = normalize_email(&body.email).map_err(ApiError::Validation)?;
    let (token, digest) = new_token();
    let invitation_id = Uuid::new_v4();
    let outbox_id = Uuid::new_v4();
    let correlation_id = Uuid::new_v4();
    let mut tx = state.store.begin().await?;
    if let Some((existing_id, existing_email, existing_role)) = sqlx::query_as::<
        _,
        (Uuid, String, String),
    >(
        "select id,email,role from control.invitations where invited_by=$1 and idempotency_key=$2",
    )
    .bind(who.user_id)
    .bind(&key)
    .fetch_optional(&mut *tx)
    .await?
    {
        tx.commit().await?;
        return Ok((
            StatusCode::ACCEPTED,
            Json(
                json!({"id":existing_id,"email":existing_email,"role":existing_role,"replayed":true}),
            ),
        ));
    }
    let existing = sqlx::query_scalar::<_, Uuid>("select id from control.invitations where workshop_id=$1 and email=$2 and accepted_at is null and revoked_at is null")
        .bind(id).bind(&email).fetch_optional(&mut *tx).await?;
    if existing.is_some() {
        return Err(ApiError::Conflict("a pending invitation already exists"));
    }
    sqlx::query("insert into control.invitations(id,workshop_id,email,role,token_hash,locale,invited_by,idempotency_key,expires_at) values($1,$2,$3,$4,$5,$6,$7,$8,now()+interval '7 days')")
        .bind(invitation_id).bind(id).bind(&email).bind(body.role.as_str()).bind(digest).bind(&body.locale).bind(who.user_id).bind(&key).execute(&mut *tx).await?;
    let link = state
        .config
        .public_origin
        .join(&format!("invitations/{token}"))
        .map_err(|error| ApiError::Internal(error.into()))?
        .to_string();
    sqlx::query("insert into control.outbox(id,kind,recipient,template,payload) values($1,'invitation',$2,'workshop-invitation',$3)")
        .bind(outbox_id).bind(&email).bind(json!({"invitation_id":invitation_id,"workshop_id":id,"role":body.role,"locale":body.locale,"accept_url":link,"idempotency_key":key})).execute(&mut *tx).await?;
    Store::enqueue(
        &mut tx,
        NewOperation {
            kind: OperationKind::EmailDelivery,
            workshop_id: Some(id),
            target_user_id: None,
            desired_epoch: None,
            payload: &json!({"outbox_id":outbox_id}),
            requested_by: Some(who.user_id),
            correlation_id,
            idempotency_key: &key,
        },
    )
    .await?;
    audit(
        &mut tx,
        Some(who.user_id),
        Some(id),
        "invitation.create",
        "invitation",
        invitation_id.to_string(),
        correlation_id,
    )
    .await?;
    tx.commit().await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(
            json!({"id":invitation_id,"email":email,"role":body.role,"expires_in_seconds":604800}),
        ),
    ))
}

async fn resend_invitation(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let who = principal(&state, &headers).await?;
    let key = idempotency(&headers)?.to_owned();
    let row=sqlx::query_as::<_,(Uuid,String,String,String)>("select workshop_id,email,role,locale from control.invitations where id=$1 and accepted_at is null and revoked_at is null and expires_at>now()")
        .bind(id).fetch_optional(state.store.pool()).await?.ok_or(ApiError::NotFound)?;
    if !authority(&state, who.user_id, row.0)
        .await?
        .0
        .can_manage_members()
    {
        return Err(ApiError::Forbidden);
    }
    let (token, digest) = new_token();
    let outbox_id = Uuid::new_v4();
    let correlation_id = Uuid::new_v4();
    let mut tx = state.store.begin().await?;
    sqlx::query("update control.invitations set token_hash=$2,sent_count=sent_count+1,last_sent_at=now(),expires_at=now()+interval '7 days' where id=$1")
        .bind(id).bind(digest).execute(&mut *tx).await?;
    let link = state
        .config
        .public_origin
        .join(&format!("invitations/{token}"))
        .map_err(|error| ApiError::Internal(error.into()))?
        .to_string();
    sqlx::query("insert into control.outbox(id,kind,recipient,template,payload) values($1,'invitation',$2,'workshop-invitation',$3)")
        .bind(outbox_id).bind(&row.1).bind(json!({"invitation_id":id,"workshop_id":row.0,"role":row.2,"locale":row.3,"accept_url":link})).execute(&mut *tx).await?;
    Store::enqueue(
        &mut tx,
        NewOperation {
            kind: OperationKind::EmailDelivery,
            workshop_id: Some(row.0),
            target_user_id: None,
            desired_epoch: None,
            payload: &json!({"outbox_id":outbox_id}),
            requested_by: Some(who.user_id),
            correlation_id,
            idempotency_key: &key,
        },
    )
    .await?;
    tx.commit().await?;
    Ok((StatusCode::ACCEPTED, Json(json!({"id":id,"resent":true}))))
}

async fn revoke_invitation(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    let who = principal(&state, &headers).await?;
    let workshop=sqlx::query_scalar::<_,Uuid>("select workshop_id from control.invitations where id=$1 and accepted_at is null and revoked_at is null").bind(id).fetch_optional(state.store.pool()).await?.ok_or(ApiError::NotFound)?;
    if !authority(&state, who.user_id, workshop)
        .await?
        .0
        .can_manage_members()
    {
        return Err(ApiError::Forbidden);
    }
    sqlx::query("update control.invitations set revoked_at=now() where id=$1")
        .bind(id)
        .execute(state.store.pool())
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

fn token_digest(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

async fn validate_invitation(
    State(state): State<Arc<AppState>>,
    Path(token): Path<String>,
) -> ApiResult<Json<Value>> {
    let row=sqlx::query_as::<_,(String,String,String,String)>("select i.email,i.role,i.locale,w.display_name from control.invitations i join control.workshops w on w.id=i.workshop_id where i.token_hash=$1 and i.accepted_at is null and i.revoked_at is null and i.expires_at>now()")
        .bind(token_digest(&token)).fetch_optional(state.store.pool()).await?.ok_or(ApiError::NotFound)?;
    Ok(Json(
        json!({"email":row.0,"role":row.1,"locale":row.2,"workshop_name":row.3}),
    ))
}

async fn accept_invitation(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(token): Path<String>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let verified = state.auth.verify_headers(&headers).await?;
    let digest = token_digest(&token);
    let correlation_id = Uuid::new_v4();
    let mut tx = state.store.begin().await?;
    let invitation=sqlx::query_as::<_,(Uuid,Uuid,String,String)>("select id,workshop_id,email,role from control.invitations where token_hash=$1 and accepted_at is null and revoked_at is null and expires_at>now() for update")
        .bind(digest).fetch_optional(&mut *tx).await?.ok_or(ApiError::NotFound)?;
    if invitation.2 != verified.email {
        return Err(ApiError::Forbidden);
    }
    let linked=sqlx::query_scalar::<_,Uuid>("select user_id from control.external_identities where issuer=$1 and subject=$2 and disabled_at is null").bind(&verified.issuer).bind(&verified.subject).fetch_optional(&mut *tx).await?;
    let user_id = if let Some(id) = linked {
        id
    } else {
        let id=sqlx::query_scalar::<_,Uuid>("insert into control.users(id,email) values($1,$2) on conflict(email) do update set email=excluded.email returning id").bind(Uuid::new_v4()).bind(&verified.email).fetch_one(&mut *tx).await?;
        sqlx::query("insert into control.external_identities(id,user_id,issuer,subject,email_at_link) values($1,$2,$3,$4,$5)").bind(Uuid::new_v4()).bind(id).bind(&verified.issuer).bind(&verified.subject).bind(&verified.email).execute(&mut *tx).await?;
        id
    };
    sqlx::query("insert into control.memberships(workshop_id,user_id,role) values($1,$2,$3) on conflict(workshop_id,user_id) do update set role=excluded.role,status='active',revoked_at=null,authority_epoch=control.memberships.authority_epoch+1")
        .bind(invitation.1).bind(user_id).bind(&invitation.3).execute(&mut *tx).await?;
    let epoch = sqlx::query_scalar::<_, i32>(
        "select authority_epoch from control.memberships where workshop_id=$1 and user_id=$2",
    )
    .bind(invitation.1)
    .bind(user_id)
    .fetch_one(&mut *tx)
    .await?;
    sqlx::query("update control.invitations set accepted_at=now(),accepted_user_id=$2 where id=$1")
        .bind(invitation.0)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    seed_targets(&mut tx, invitation.1, user_id, epoch).await?;
    let operation_id = Store::enqueue(
        &mut tx,
        NewOperation {
            kind: OperationKind::MembershipReconcile,
            workshop_id: Some(invitation.1),
            target_user_id: Some(user_id),
            desired_epoch: Some(epoch),
            payload: &json!({"active":true}),
            requested_by: Some(user_id),
            correlation_id,
            idempotency_key: &format!("accept:{}", invitation.0),
        },
    )
    .await?;
    tx.commit().await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(json!({"workshop_id":invitation.1,"user_id":user_id,"operation_id":operation_id})),
    ))
}

#[derive(Deserialize)]
struct RoleBody {
    role: WorkshopRole,
}
async fn update_member(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((id, user_id)): Path<(Uuid, Uuid)>,
    Json(body): Json<RoleBody>,
) -> ApiResult<Json<Value>> {
    let who = principal(&state, &headers).await?;
    let role = authority(&state, who.user_id, id).await?.0;
    if !role.can_manage_members() || matches!(body.role, WorkshopRole::Owner) {
        return Err(ApiError::Forbidden);
    }
    let key = idempotency(&headers)?.to_owned();
    let correlation_id = Uuid::new_v4();
    let mut tx = state.store.begin().await?;
    let epoch=sqlx::query_scalar::<_,i32>("update control.memberships set role=$3,authority_epoch=authority_epoch+1 where workshop_id=$1 and user_id=$2 and status='active' and role<>'owner' returning authority_epoch")
        .bind(id).bind(user_id).bind(body.role.as_str()).fetch_optional(&mut *tx).await?.ok_or(ApiError::NotFound)?;
    seed_targets(&mut tx, id, user_id, epoch).await?;
    let op = Store::enqueue(
        &mut tx,
        NewOperation {
            kind: OperationKind::MembershipReconcile,
            workshop_id: Some(id),
            target_user_id: Some(user_id),
            desired_epoch: Some(epoch),
            payload: &json!({"active":true,"role":body.role}),
            requested_by: Some(who.user_id),
            correlation_id,
            idempotency_key: &key,
        },
    )
    .await?;
    tx.commit().await?;
    Ok(Json(
        json!({"user_id":user_id,"role":body.role,"authority_epoch":epoch,"operation_id":op}),
    ))
}

async fn remove_member(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((id, user_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let who = principal(&state, &headers).await?;
    if !authority(&state, who.user_id, id)
        .await?
        .0
        .can_manage_members()
    {
        return Err(ApiError::Forbidden);
    }
    let key = idempotency(&headers)?.to_owned();
    let correlation_id = Uuid::new_v4();
    let mut tx = state.store.begin().await?;
    let epoch=sqlx::query_scalar::<_,i32>("update control.memberships set status='revoked',revoked_at=now(),authority_epoch=authority_epoch+1 where workshop_id=$1 and user_id=$2 and status='active' and role<>'owner' returning authority_epoch")
        .bind(id).bind(user_id).fetch_optional(&mut *tx).await?.ok_or(ApiError::Conflict("owner must be transferred before removal"))?;
    seed_targets(&mut tx, id, user_id, epoch).await?;
    let op = Store::enqueue(
        &mut tx,
        NewOperation {
            kind: OperationKind::MembershipReconcile,
            workshop_id: Some(id),
            target_user_id: Some(user_id),
            desired_epoch: Some(epoch),
            payload: &json!({"active":false}),
            requested_by: Some(who.user_id),
            correlation_id,
            idempotency_key: &key,
        },
    )
    .await?;
    tx.commit().await?;
    Ok((StatusCode::ACCEPTED, Json(json!({"operation_id":op}))))
}

#[derive(Deserialize)]
struct TransferBody {
    to_user_id: Uuid,
}
async fn ownership_transfers(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let who = principal(&state, &headers).await?;
    authority(&state, who.user_id, id).await?;
    let rows=sqlx::query_as::<_,(Uuid,Uuid,Uuid,OffsetDateTime)>("select id,from_user_id,to_user_id,expires_at from control.ownership_transfers where workshop_id=$1 and accepted_at is null and revoked_at is null and expires_at>now() and (from_user_id=$2 or to_user_id=$2) order by created_at desc").bind(id).bind(who.user_id).fetch_all(state.store.pool()).await?;
    Ok(Json(Value::Array(rows.into_iter().map(|r|json!({"id":r.0,"from_user_id":r.1,"to_user_id":r.2,"expires_at":r.3,"can_accept":r.2==who.user_id})).collect())))
}

async fn create_ownership_transfer(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(body): Json<TransferBody>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let who = principal(&state, &headers).await?;
    if authority(&state, who.user_id, id).await?.0 != WorkshopRole::Owner {
        return Err(ApiError::Forbidden);
    }
    let key = idempotency(&headers)?.to_owned();
    authority(&state, body.to_user_id, id).await?;
    let transfer = Uuid::new_v4();
    let transfer = sqlx::query_scalar::<_,Uuid>("insert into control.ownership_transfers(id,workshop_id,from_user_id,to_user_id,idempotency_key,expires_at) values($1,$2,$3,$4,$5,now()+interval '48 hours') on conflict(from_user_id,idempotency_key) do update set idempotency_key=excluded.idempotency_key returning id").bind(transfer).bind(id).bind(who.user_id).bind(body.to_user_id).bind(key).fetch_one(state.store.pool()).await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(json!({"id":transfer,"expires_in_seconds":172800})),
    ))
}

async fn accept_ownership_transfer(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let who = principal(&state, &headers).await?;
    let key = idempotency(&headers)?.to_owned();
    let correlation_id = Uuid::new_v4();
    let mut tx = state.store.begin().await?;
    let row=sqlx::query_as::<_,(Uuid,Uuid,Uuid)>("select workshop_id,from_user_id,to_user_id from control.ownership_transfers where id=$1 and accepted_at is null and revoked_at is null and expires_at>now() for update").bind(id).fetch_optional(&mut *tx).await?.ok_or(ApiError::NotFound)?;
    if row.2 != who.user_id {
        return Err(ApiError::Forbidden);
    }
    sqlx::query("update control.memberships set role=case when user_id=$2 then 'studio_manager' else 'owner' end,authority_epoch=authority_epoch+1 where workshop_id=$1 and user_id in($2,$3) and status='active'").bind(row.0).bind(row.1).bind(row.2).execute(&mut *tx).await?;
    sqlx::query("update control.ownership_transfers set accepted_at=now() where id=$1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    for user in [row.1, row.2] {
        let epoch = sqlx::query_scalar::<_, i32>(
            "select authority_epoch from control.memberships where workshop_id=$1 and user_id=$2",
        )
        .bind(row.0)
        .bind(user)
        .fetch_one(&mut *tx)
        .await?;
        seed_targets(&mut tx, row.0, user, epoch).await?;
        Store::enqueue(
            &mut tx,
            NewOperation {
                kind: OperationKind::MembershipReconcile,
                workshop_id: Some(row.0),
                target_user_id: Some(user),
                desired_epoch: Some(epoch),
                payload: &json!({"active":true}),
                requested_by: Some(who.user_id),
                correlation_id,
                idempotency_key: &format!("{key}:{user}"),
            },
        )
        .await?;
    }
    tx.commit().await?;
    Ok(Json(json!({"id":id,"accepted":true})))
}

async fn integrations(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let who = principal(&state, &headers).await?;
    authority(&state, who.user_id, id).await?;
    let rows=sqlx::query_as::<_,(String,String,String,i32,i32,Option<String>)>("select service,base_url,health,desired_epoch,applied_epoch,safe_error_class from control.service_instances where workshop_id=$1 order by service").bind(id).fetch_all(state.store.pool()).await?;
    Ok(Json(Value::Array(rows.into_iter().map(|r|json!({"service":r.0,"url":r.1,"health":r.2,"desired_epoch":r.3,"applied_epoch":r.4,"error":r.5})).collect())))
}

async fn modules(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let who = principal(&state, &headers).await?;
    let (role, _) = authority(&state, who.user_id, id).await?;
    let rows = sqlx::query_as::<_, (String, String, Option<Uuid>, Option<String>, Option<String>)>(
        "select wm.module_key,wm.state,wm.operation_id,o.state,o.failure_class
         from control.workshop_modules wm
         left join control.operations o on o.id=wm.operation_id
         where wm.workshop_id=$1",
    )
    .bind(id)
    .fetch_all(state.store.pool())
    .await?;
    let states = rows
        .into_iter()
        .map(|row| (row.0, (row.1, row.2, row.3, row.4)))
        .collect::<std::collections::HashMap<_, _>>();
    Ok(Json(Value::Array(
        crate::modules::CATALOG
            .iter()
            .map(|bundle| {
                let state = states.get(bundle.key);
                let operation_state = state.and_then(|value| value.2.as_deref());
                let visible_state = match operation_state {
                    Some("dead_letter") => "failed",
                    _ => state.map_or("available", |value| value.0.as_str()),
                };
                json!({
                    "key":bundle.key,
                    "name":bundle.name,
                    "description":bundle.description,
                    "state":visible_state,
                    "operation_id":state.and_then(|value|value.1),
                    "error":state.and_then(|value|value.3.as_deref()),
                    "can_manage":role.can_manage_modules(),
                    "dependencies":bundle.dependencies,
                })
            })
            .collect(),
    )))
}

async fn enable_module(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((id, module_key)): Path<(Uuid, String)>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let who = principal(&state, &headers).await?;
    let (role, _) = authority(&state, who.user_id, id).await?;
    if !role.can_manage_modules() {
        return Err(ApiError::Forbidden);
    }
    let bundle = crate::modules::bundle(&module_key).ok_or(ApiError::NotFound)?;
    if !bundle.dependencies.is_empty() {
        let enabled = sqlx::query_scalar::<_, String>(
            "select module_key from control.workshop_modules
             where workshop_id=$1 and state='enabled' and module_key = any($2)",
        )
        .bind(id)
        .bind(bundle.dependencies)
        .fetch_all(state.store.pool())
        .await?
        .into_iter()
        .collect::<std::collections::HashSet<_>>();
        if let Some(missing) = bundle
            .dependencies
            .iter()
            .find(|dependency| !enabled.contains(**dependency))
        {
            return Err(ApiError::Conflict(match *missing {
                "documents" => "enable Documents first",
                "invoice-capture" => "enable Invoice capture first",
                _ => "enable the required module first",
            }));
        }
    }
    let client_key = idempotency(&headers)?;
    let stored_key = format!("module:{id}:{module_key}:{client_key}");
    if let Some(existing) = sqlx::query_scalar::<_, Uuid>(
        "select id from control.operations
         where kind='module.enable' and requested_by=$1 and idempotency_key=$2",
    )
    .bind(who.user_id)
    .bind(&stored_key)
    .fetch_optional(state.store.pool())
    .await?
    {
        return Ok((
            StatusCode::ACCEPTED,
            Json(json!({"operation_id":existing,"replayed":true})),
        ));
    }
    if let Some((module_state, operation_id)) = sqlx::query_as::<_, (String, Option<Uuid>)>(
        "select state,operation_id from control.workshop_modules
         where workshop_id=$1 and module_key=$2",
    )
    .bind(id)
    .bind(&module_key)
    .fetch_optional(state.store.pool())
    .await?
    {
        if module_state == "enabled" {
            return Ok((StatusCode::OK, Json(json!({"state":"enabled"}))));
        }
        if let Some(operation_id) = operation_id {
            let active = sqlx::query_scalar::<_, bool>(
                "select state in ('pending','in_flight','awaiting_reconciliation')
                 from control.operations where id=$1",
            )
            .bind(operation_id)
            .fetch_optional(state.store.pool())
            .await?
            .unwrap_or(false);
            if active {
                return Ok((
                    StatusCode::ACCEPTED,
                    Json(json!({"operation_id":operation_id,"replayed":true})),
                ));
            }
        }
    }
    let correlation = Uuid::new_v4();
    let payload = json!({"module_key":module_key});
    let mut tx = state.store.begin().await?;
    let operation_id = Store::enqueue(
        &mut tx,
        NewOperation {
            kind: OperationKind::ModuleEnable,
            workshop_id: Some(id),
            target_user_id: None,
            desired_epoch: None,
            payload: &payload,
            requested_by: Some(who.user_id),
            correlation_id: correlation,
            idempotency_key: &stored_key,
        },
    )
    .await?;
    sqlx::query(
        "insert into control.workshop_modules(workshop_id,module_key,state,operation_id,requested_by)
         values($1,$2,'requested',$3,$4)
         on conflict(workshop_id,module_key) do update set
           state='requested',operation_id=excluded.operation_id,requested_by=excluded.requested_by,
           requested_at=now(),enabled_at=null",
    )
    .bind(id)
    .bind(&module_key)
    .bind(operation_id)
    .bind(who.user_id)
    .execute(&mut *tx)
    .await?;
    audit(
        &mut tx,
        Some(who.user_id),
        Some(id),
        "module.enable",
        "workshop_module",
        module_key,
        correlation,
    )
    .await?;
    tx.commit().await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(json!({"operation_id":operation_id})),
    ))
}

async fn database(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let who = principal(&state, &headers).await?;
    let (role, _) = authority(&state, who.user_id, id).await?;
    let primary =
        sqlx::query_as::<_, (Uuid, String, String, OffsetDateTime, Option<OffsetDateTime>)>(
            "select id,public_hostname,state,created_at,last_restored_at
         from control.odoo_databases
         where workshop_id=$1 and kind='primary' and deleted_at is null",
        )
        .bind(id)
        .fetch_optional(state.store.pool())
        .await?;
    let duplicates = sqlx::query_as::<_, (Uuid, String, String, OffsetDateTime)>(
        "select id,label,state,created_at from control.odoo_databases
         where workshop_id=$1 and kind='duplicate' and deleted_at is null
         order by created_at desc",
    )
    .bind(id)
    .fetch_all(state.store.pool())
    .await?;
    let recovery = sqlx::query_as::<
        _,
        (
            Uuid,
            String,
            String,
            String,
            Option<i64>,
            OffsetDateTime,
            Option<OffsetDateTime>,
            Option<Uuid>,
            Option<String>,
            Vec<String>,
            String,
            String,
            Option<OffsetDateTime>,
            Option<OffsetDateTime>,
        ),
    >(
        "select r.id,r.kind,r.label,r.state,r.size_bytes,r.created_at,r.ready_at,
                r.operation_id,o.state,r.component_scope,r.format_version,
                r.storage_location,r.verified_at,r.expires_at
         from control.workshop_recovery_points r
         left join control.operations o on o.id=r.operation_id
         where r.workshop_id=$1 and r.state<>'deleted'
         order by r.created_at desc",
    )
    .bind(id)
    .fetch_all(state.store.pool())
    .await?;
    Ok(Json(json!({
        "can_manage": role.can_manage_database(),
        "primary": primary.map(|row| json!({"id":row.0,"public_hostname":row.1,"state":row.2,"created_at":row.3,"last_restored_at":row.4})),
        "duplicates": duplicates.into_iter().map(|row| json!({"id":row.0,"label":row.1,"state":row.2,"routable":false,"created_at":row.3})).collect::<Vec<_>>(),
        "recovery_points": recovery.into_iter().map(|row| json!({"id":row.0,"kind":row.1,"label":row.2,"state":row.3,"size_bytes":row.4,"created_at":row.5,"ready_at":row.6,"operation_id":row.7,"operation_state":row.8,"component_scope":row.9,"format_version":row.10,"storage_location":row.11,"verified_at":row.12,"expires_at":row.13})).collect::<Vec<_>>()
    })))
}

#[derive(Deserialize)]
struct RecoveryPointBody {
    label: Option<String>,
}

async fn create_snapshot(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(body): Json<RecoveryPointBody>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    create_recovery_point(&state, &headers, id, body.label, "snapshot").await
}

async fn create_backup(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(body): Json<RecoveryPointBody>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    create_recovery_point(&state, &headers, id, body.label, "backup").await
}

async fn create_recovery_point(
    state: &AppState,
    headers: &HeaderMap,
    workshop: Uuid,
    label: Option<String>,
    kind: &'static str,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let who = principal(state, headers).await?;
    require_database_owner(state, who.user_id, workshop).await?;
    let client_key = idempotency(headers)?;
    let stored_key = format!("database:{workshop}:{kind}:{client_key}");
    if let Some(existing) = existing_lifecycle_operation(state, who.user_id, &stored_key).await? {
        return Ok((
            StatusCode::ACCEPTED,
            Json(json!({"operation_id":existing,"replayed":true})),
        ));
    }
    let label = lifecycle_label(
        label,
        if kind == "snapshot" {
            "Manual snapshot"
        } else {
            "Portable backup"
        },
    )?;
    let recovery_id = Uuid::new_v4();
    let correlation = Uuid::new_v4();
    let mut tx = state.store.begin().await?;
    lock_lifecycle(&mut tx, workshop).await?;
    let database_id = primary_database(&mut tx, workshop).await?;
    ensure_lifecycle_idle(&mut tx, workshop).await?;
    let documents_enabled = sqlx::query_scalar::<_, bool>(
        "select exists(select 1 from control.workshop_modules where workshop_id=$1 and module_key='documents' and state='enabled')",
    )
    .bind(workshop)
    .fetch_one(&mut *tx)
    .await?;
    let component_scope = if documents_enabled {
        vec!["odoo", "paperless"]
    } else {
        vec!["odoo"]
    };
    let payload = json!({"action":kind,"database_id":database_id,"recovery_point_id":recovery_id});
    let operation_id = Store::enqueue(
        &mut tx,
        NewOperation {
            kind: OperationKind::TenantLifecycle,
            workshop_id: Some(workshop),
            target_user_id: None,
            desired_epoch: None,
            payload: &payload,
            requested_by: Some(who.user_id),
            correlation_id: correlation,
            idempotency_key: &stored_key,
        },
    )
    .await?;
    sqlx::query("insert into control.workshop_recovery_points(id,workshop_id,database_id,operation_id,kind,label,requested_by,component_scope,format_version) values($1,$2,$3,$4,$5,$6,$7,$8,'makersbrain-workshop-recovery-v2')")
        .bind(recovery_id).bind(workshop).bind(database_id).bind(operation_id).bind(kind).bind(label).bind(who.user_id).bind(&component_scope).execute(&mut *tx).await?;
    audit(
        &mut tx,
        Some(who.user_id),
        Some(workshop),
        &format!("database.{kind}"),
        "workshop_recovery_point",
        recovery_id.to_string(),
        correlation,
    )
    .await?;
    tx.commit().await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(json!({"id":recovery_id,"operation_id":operation_id})),
    ))
}

async fn restore_database(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(body): Json<RestoreBody>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let who = principal(&state, &headers).await?;
    require_database_owner(&state, who.user_id, id).await?;
    confirm_slug(&state, id, &body.confirmation).await?;
    let client_key = idempotency(&headers)?;
    let stored_key = format!("database:{id}:restore:{client_key}");
    if let Some(existing) = existing_lifecycle_operation(&state, who.user_id, &stored_key).await? {
        return Ok((
            StatusCode::ACCEPTED,
            Json(json!({"operation_id":existing,"replayed":true})),
        ));
    }
    let correlation = Uuid::new_v4();
    let safety_id = Uuid::new_v4();
    let mut tx = state.store.begin().await?;
    lock_lifecycle(&mut tx, id).await?;
    let database_id = primary_database(&mut tx, id).await?;
    ensure_lifecycle_idle(&mut tx, id).await?;
    let recovery_scope = sqlx::query_scalar::<_, Vec<String>>("select component_scope from control.workshop_recovery_points where id=$1 and workshop_id=$2 and database_id=$3 and state='ready' and verification_state='verified' and storage_ref is not null and (expires_at is null or expires_at > now())")
        .bind(body.recovery_point_id).bind(id).bind(database_id).fetch_optional(&mut *tx).await?.ok_or(ApiError::Validation("recovery point is not ready and verified"))?;
    let documents_enabled = sqlx::query_scalar::<_, bool>(
        "select exists(select 1 from control.workshop_modules where workshop_id=$1 and module_key='documents' and state='enabled')",
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await?;
    if recovery_scope.iter().any(|item| item == "paperless") != documents_enabled {
        return Err(ApiError::Validation(
            "recovery point module scope does not match the workshop",
        ));
    }
    let safety_scope = if documents_enabled {
        vec!["odoo", "paperless"]
    } else {
        vec!["odoo"]
    };
    let payload = json!({"action":"restore","database_id":database_id,"recovery_point_id":body.recovery_point_id,"safety_recovery_point_id":safety_id});
    let operation_id = Store::enqueue(
        &mut tx,
        NewOperation {
            kind: OperationKind::TenantLifecycle,
            workshop_id: Some(id),
            target_user_id: None,
            desired_epoch: None,
            payload: &payload,
            requested_by: Some(who.user_id),
            correlation_id: correlation,
            idempotency_key: &stored_key,
        },
    )
    .await?;
    sqlx::query("insert into control.workshop_recovery_points(id,workshop_id,database_id,kind,label,requested_by,component_scope,format_version) values($1,$2,$3,'backup','Automatic pre-restore safety backup',$4,$5,'makersbrain-workshop-recovery-v2')")
        .bind(safety_id).bind(id).bind(database_id).bind(who.user_id).bind(&safety_scope).execute(&mut *tx).await?;
    sqlx::query("update control.odoo_databases set state='restoring' where id=$1")
        .bind(database_id)
        .execute(&mut *tx)
        .await?;
    audit(
        &mut tx,
        Some(who.user_id),
        Some(id),
        "database.restore",
        "workshop_recovery_point",
        body.recovery_point_id.to_string(),
        correlation,
    )
    .await?;
    tx.commit().await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(json!({"operation_id":operation_id,"safety_recovery_point_id":safety_id})),
    ))
}

#[derive(Deserialize)]
struct RestoreBody {
    recovery_point_id: Uuid,
    confirmation: String,
}

#[derive(Deserialize)]
struct DuplicateBody {
    label: String,
    confirmation: String,
}

async fn duplicate_database(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(body): Json<DuplicateBody>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let who = principal(&state, &headers).await?;
    require_database_owner(&state, who.user_id, id).await?;
    confirm_slug(&state, id, &body.confirmation).await?;
    let label = lifecycle_label(Some(body.label), "Database duplicate")?;
    let client_key = idempotency(&headers)?;
    let stored_key = format!("database:{id}:duplicate:{client_key}");
    if let Some(existing) = existing_lifecycle_operation(&state, who.user_id, &stored_key).await? {
        return Ok((
            StatusCode::ACCEPTED,
            Json(json!({"operation_id":existing,"replayed":true})),
        ));
    }
    let duplicate_id = Uuid::new_v4();
    let duplicate_ref = opaque_database_ref(duplicate_id);
    let correlation = Uuid::new_v4();
    let mut tx = state.store.begin().await?;
    lock_lifecycle(&mut tx, id).await?;
    let source_id = primary_database(&mut tx, id).await?;
    ensure_lifecycle_idle(&mut tx, id).await?;
    sqlx::query("insert into control.odoo_databases(id,workshop_id,kind,database_ref,label,state,source_database_id,routable) values($1,$2,'duplicate',$3,$4,'duplicating',$5,false)")
        .bind(duplicate_id).bind(id).bind(&duplicate_ref).bind(label).bind(source_id).execute(&mut *tx).await?;
    let payload = json!({"action":"duplicate","database_id":source_id,"target_database_id":duplicate_id,"target_database_ref":duplicate_ref,"routable":false});
    let operation_id = Store::enqueue(
        &mut tx,
        NewOperation {
            kind: OperationKind::TenantLifecycle,
            workshop_id: Some(id),
            target_user_id: None,
            desired_epoch: None,
            payload: &payload,
            requested_by: Some(who.user_id),
            correlation_id: correlation,
            idempotency_key: &stored_key,
        },
    )
    .await?;
    audit(
        &mut tx,
        Some(who.user_id),
        Some(id),
        "database.duplicate",
        "odoo_database",
        duplicate_id.to_string(),
        correlation,
    )
    .await?;
    tx.commit().await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(json!({"id":duplicate_id,"operation_id":operation_id,"routable":false})),
    ))
}

async fn require_database_owner(state: &AppState, user: Uuid, workshop: Uuid) -> ApiResult<()> {
    if !authority(state, user, workshop)
        .await?
        .0
        .can_manage_database()
    {
        return Err(ApiError::Forbidden);
    }
    Ok(())
}

async fn confirm_slug(state: &AppState, workshop: Uuid, confirmation: &str) -> ApiResult<()> {
    let slug = sqlx::query_scalar::<_, String>("select slug from control.workshops where id=$1")
        .bind(workshop)
        .fetch_one(state.store.pool())
        .await?;
    if confirmation != slug {
        return Err(ApiError::Validation(
            "confirmation must exactly match the workshop slug",
        ));
    }
    Ok(())
}

fn lifecycle_label(value: Option<String>, fallback: &str) -> ApiResult<String> {
    let value = value.unwrap_or_else(|| fallback.to_owned());
    let value = value.trim();
    if value.is_empty() || value.len() > 120 {
        return Err(ApiError::Validation(
            "label must contain 1 to 120 characters",
        ));
    }
    Ok(value.to_owned())
}

async fn existing_lifecycle_operation(
    state: &AppState,
    user: Uuid,
    key: &str,
) -> ApiResult<Option<Uuid>> {
    Ok(sqlx::query_scalar::<_, Uuid>("select id from control.operations where kind='tenant.lifecycle' and requested_by=$1 and idempotency_key=$2")
        .bind(user).bind(key).fetch_optional(state.store.pool()).await?)
}

async fn lock_lifecycle(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    workshop: Uuid,
) -> ApiResult<()> {
    sqlx::query("select pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(workshop.to_string())
        .execute(&mut **tx)
        .await?;
    Ok(())
}

async fn primary_database(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    workshop: Uuid,
) -> ApiResult<Uuid> {
    sqlx::query_scalar::<_, Uuid>("select id from control.odoo_databases where workshop_id=$1 and kind='primary' and deleted_at is null")
        .bind(workshop).fetch_optional(&mut **tx).await?.ok_or(ApiError::Conflict("Odoo database is not provisioned"))
}

async fn ensure_lifecycle_idle(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    workshop: Uuid,
) -> ApiResult<()> {
    let active = sqlx::query_scalar::<_, bool>("select exists(select 1 from control.operations where workshop_id=$1 and kind='tenant.lifecycle' and state in ('pending','in_flight','awaiting_reconciliation'))")
        .bind(workshop).fetch_one(&mut **tx).await?;
    if active {
        return Err(ApiError::Conflict(
            "another database operation is already running",
        ));
    }
    Ok(())
}

async fn operation(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let who = principal(&state, &headers).await?;
    let row=sqlx::query_as::<_,(String,String,Option<Uuid>,i32,i32,Option<String>,OffsetDateTime,Option<OffsetDateTime>)>("select kind,state,workshop_id,attempt,max_attempts,failure_class,created_at,finished_at from control.operations where id=$1").bind(id).fetch_optional(state.store.pool()).await?.ok_or(ApiError::NotFound)?;
    if let Some(workshop) = row.2 {
        authority(&state, who.user_id, workshop).await?;
    } else if who.user_id
        != sqlx::query_scalar::<_, Uuid>("select requested_by from control.operations where id=$1")
            .bind(id)
            .fetch_one(state.store.pool())
            .await?
    {
        return Err(ApiError::NotFound);
    }
    Ok(Json(
        json!({"id":id,"kind":row.0,"state":row.1,"workshop_id":row.2,"attempt":row.3,"max_attempts":row.4,"failure_class":row.5,"created_at":row.6,"finished_at":row.7}),
    ))
}

async fn retry_operation(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let who = principal(&state, &headers).await?;
    let row = sqlx::query_as::<_, (Option<Uuid>, String)>(
        "select workshop_id,kind from control.operations where id=$1",
    )
    .bind(id)
    .fetch_optional(state.store.pool())
    .await?
    .ok_or(ApiError::NotFound)?;
    if let Some(workshop) = row.0 {
        let role = authority(&state, who.user_id, workshop).await?.0;
        if (row.1 == "tenant.lifecycle" && !role.can_manage_database())
            || (row.1 != "tenant.lifecycle" && !role.can_manage_members())
        {
            return Err(ApiError::Forbidden);
        }
    }
    let changed=sqlx::query("update control.operations set state='pending',attempt=0,next_attempt_at=now(),failure_class=null,finished_at=null where id=$1 and state='dead_letter'").bind(id).execute(state.store.pool()).await?;
    if changed.rows_affected() != 1 {
        return Err(ApiError::Conflict(
            "only dead-letter operations can be retried",
        ));
    }
    Ok((
        StatusCode::ACCEPTED,
        Json(json!({"id":id,"state":"pending"})),
    ))
}

async fn paperless_event(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(workshop_id): Path<Uuid>,
    Json(payload): Json<Value>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    internal(&state, &headers)?;
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

async fn reconcile_tenant(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(workshop_id): Path<Uuid>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    internal(&state, &headers)?;
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
            requested_by: None,
            correlation_id: correlation,
            idempotency_key: &format!("manual:{correlation}"),
        },
    )
    .await?;
    tx.commit().await?;
    Ok((StatusCode::ACCEPTED, Json(json!({"operation_id":op}))))
}

#[derive(Deserialize)]
struct EntitlementAck {
    version: i64,
    service: String,
}
async fn ack_entitlement(
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

async fn seed_targets(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    workshop: Uuid,
    user: Uuid,
    epoch: i32,
) -> Result<(), sqlx::Error> {
    sqlx::query("insert into control.membership_targets(workshop_id,user_id,target,desired_epoch)
        select $1,$2,target,$3 from unnest(array['rauthy','odoo']) target
        union all
        select $1,$2,'paperless',$3 where exists (
            select 1 from control.workshop_modules
            where workshop_id=$1 and module_key='documents' and state='enabled'
        )
        on conflict(workshop_id,user_id,target) do update set desired_epoch=excluded.desired_epoch,state='pending',safe_error_class=null")
        .bind(workshop).bind(user).bind(epoch).execute(&mut **tx).await?;
    Ok(())
}

async fn audit(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    actor: Option<Uuid>,
    workshop: Option<Uuid>,
    action: &str,
    target_type: &str,
    target_id: String,
    correlation: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query("insert into control.audit_events(id,actor_user_id,workshop_id,action,target_type,target_id,correlation_id,outcome) values($1,$2,$3,$4,$5,$6,$7,'accepted')")
        .bind(Uuid::new_v4()).bind(actor).bind(workshop).bind(action).bind(target_type).bind(target_id).bind(correlation).execute(&mut **tx).await?;
    Ok(())
}
