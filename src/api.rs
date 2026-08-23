use std::str::FromStr;
use std::sync::Arc;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use axum::body::Body;
use axum::extract::{MatchedPath, Path, Query, State};
use axum::http::Request;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Json, Router};
use opentelemetry::propagation::Extractor;
use opentelemetry::trace::TraceContextExt as _;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::Digest;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::cors::CorsLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::sensitive_headers::SetSensitiveRequestHeadersLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;
use tracing_opentelemetry::OpenTelemetrySpanExt as _;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::Config;
use crate::api_error::ApiError;
use crate::auth::{Authenticator, PlatformScope, Principal, VerifiedToken, WorkshopScope};
use crate::command::{
    CommandAdmission, CommandError, CommandResult, NewCommand, admit_command, complete_command,
};
use crate::domain::{OperationKind, WorkshopRole, normalize_email, opaque_database_ref};
use crate::integrations::extraction::ExtractionBrokerClient;
use crate::invitation::InvitationVerifier;
use crate::persistence::{NewOperation, Store, TenantStore};

const REQUEST_ID_HEADER: header::HeaderName = header::HeaderName::from_static("x-request-id");

#[derive(Clone, Copy, Debug)]
struct HttpRequestId(Uuid);

struct HttpHeaderExtractor<'a>(&'a HeaderMap);

impl Extractor for HttpHeaderExtractor<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|value| value.to_str().ok())
    }

    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(header::HeaderName::as_str).collect()
    }
}

fn remote_trace_context(headers: &HeaderMap) -> Result<Option<opentelemetry::Context>, ()> {
    if !headers.contains_key("traceparent") {
        return Ok(None);
    }
    let context = opentelemetry::global::get_text_map_propagator(|propagator| {
        propagator.extract(&HttpHeaderExtractor(headers))
    });
    context
        .span()
        .span_context()
        .is_valid()
        .then_some(context)
        .ok_or(())
        .map(Some)
}

pub(crate) mod governance;
use governance::*;
pub(crate) mod contracts;
use contracts::*;
pub(crate) mod carrier_secrets;
pub(crate) mod domains;
pub(crate) mod email_domains;
pub(crate) mod recovery;
pub(crate) mod smtp;
pub(crate) mod webshop;
pub(crate) use recovery::{DuplicateBody, RecoveryPointBody, RestoreBody};
use recovery::{confirm_slug, ensure_lifecycle_idle, lock_lifecycle, primary_database};
pub(crate) mod internal;
#[cfg(test)]
use internal::valid_gtin14;
pub(crate) mod platform;
pub(crate) mod routes;
pub(crate) use platform::{AdoptReleaseBody, DeleteWorkshopBody};
pub(crate) mod workshops;
pub(crate) use workshops::{
    CreateWorkshop, InvitationTokenBody, InviteBody, RoleBody, TransferBody,
};

type ApiResult<T> = Result<T, ApiError>;

#[derive(Default, Clone, Copy)]
struct HttpMetric {
    requests: u64,
    latency_micros: u128,
}

static HTTP_METRICS: OnceLock<Mutex<std::collections::HashMap<(String, u16), HttpMetric>>> =
    OnceLock::new();

async fn record_http_metric(request: Request<Body>, next: Next) -> Response {
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map_or("unmatched", MatchedPath::as_str)
        .to_owned();
    let started = std::time::Instant::now();
    let response = next.run(request).await;
    let status_class = response.status().as_u16() / 100;
    if let Ok(mut metrics) = HTTP_METRICS
        .get_or_init(|| Mutex::new(std::collections::HashMap::new()))
        .lock()
    {
        let metric = metrics.entry((route, status_class)).or_default();
        metric.requests = metric.requests.saturating_add(1);
        metric.latency_micros = metric
            .latency_micros
            .saturating_add(started.elapsed().as_micros());
    }
    response
}

fn api_timestamp(value: OffsetDateTime) -> String {
    value
        .format(&Rfc3339)
        .expect("database timestamp is representable as RFC 3339")
}

#[derive(Clone)]
pub struct AppState {
    /// Fleet/platform/internal pool. Tenant handlers must not use this after
    /// their `WorkshopScope` has been authorized.
    pub store: Store,
    /// Human workshop pool. SQL is available only through a transaction-local
    /// workshop scope, never as a bare pooled connection.
    pub tenant_store: TenantStore,
    pub config: Config,
    pub auth: Arc<Authenticator>,
    pub invitation_verifier: Arc<InvitationVerifier>,
    dns_client: reqwest::Client,
    deployment_driver_client: reqwest::Client,
    extraction_broker: ExtractionBrokerClient,
}

impl AppState {
    pub fn new(
        store: Store,
        tenant_store: TenantStore,
        config: Config,
        auth: Arc<Authenticator>,
        invitation_verifier: Arc<InvitationVerifier>,
    ) -> anyhow::Result<Self> {
        let dns_client = crate::outbound_http::external_api_builder("mb-control-api-dns")
            .timeout(Duration::from_secs(10))
            .build()?;
        let deployment_driver_client = crate::deployment_driver_transport::client(
            config.request_timeout,
            config.deployment_driver_socket.as_deref(),
        )?;
        let extraction_broker = ExtractionBrokerClient::new(
            config.extraction_broker_url.as_str(),
            &config.extraction_broker_token,
            Duration::from_secs(12),
        )?;
        Ok(Self {
            store,
            tenant_store,
            config,
            auth,
            invitation_verifier,
            dns_client,
            deployment_driver_client,
            extraction_broker,
        })
    }
}

pub fn app(state: AppState) -> Router {
    let origin: HeaderValue = state
        .config
        .cors_origin
        .as_str()
        .trim_end_matches('/')
        .parse()
        .expect("validated CORS origin is a header value");
    let state = Arc::new(state);
    routes::build(state.clone())
        .merge(routes::build_internal(state.clone()))
        .route("/health/live", get(live))
        .route("/health/ready", get(ready))
        .route("/openapi.json", get(openapi))
        .layer(
            CorsLayer::new()
                .allow_origin(origin)
                .allow_methods([Method::GET, Method::POST, Method::PATCH, Method::DELETE])
                .allow_headers([
                    header::AUTHORIZATION,
                    header::CONTENT_TYPE,
                    header::IF_MATCH,
                    header::HeaderName::from_static("idempotency-key"),
                    REQUEST_ID_HEADER,
                ])
                .expose_headers([REQUEST_ID_HEADER]),
        )
        // Transactional mail accepts bounded HTML, text, and 8 MiB of raw
        // attachments. Base64 and JSON escaping make the valid wire envelope larger.
        .layer(RequestBodyLimitLayer::new(16 * 1024 * 1024))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::GATEWAY_TIMEOUT,
            state.config.request_timeout,
        ))
        .layer(CatchPanicLayer::new())
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            enforce_privacy_production_gate,
        ))
        .layer(axum::middleware::from_fn(record_http_metric))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(|request: &Request<Body>| {
                    let span = tracing::info_span!(
                        "http_request",
                        http_request_method = %request.method(),
                        http_route = request.extensions().get::<MatchedPath>().map_or("unmatched", MatchedPath::as_str),
                        request_id = %request.extensions().get::<HttpRequestId>().expect("request ID middleware runs before tracing").0,
                        trace_id = tracing::field::Empty,
                        http_response_status = tracing::field::Empty,
                        latency_ms = tracing::field::Empty,
                    );
                    match remote_trace_context(request.headers()) {
                        Ok(Some(parent)) => {
                            let _ = span.set_parent(parent);
                        }
                        Ok(None) => {}
                        Err(()) => tracing::warn!(
                            parent: &span,
                            error_class = "trace_parent_rejected",
                            "inbound HTTP trace context was rejected"
                        ),
                    }
                    let context = span.context();
                    let context_span = context.span();
                    let span_context = context_span.span_context();
                    if span_context.is_valid() {
                        span.record("trace_id", span_context.trace_id().to_string());
                    }
                    span
                })
                .on_response(
                    |response: &Response, latency: Duration, span: &tracing::Span| {
                        span.record("http_response_status", response.status().as_u16());
                        span.record("latency_ms", latency.as_millis() as u64);
                    },
                ),
        )
        .layer(SetSensitiveRequestHeadersLayer::new([
            header::AUTHORIZATION,
            header::COOKIE,
        ]))
        .layer(axum::middleware::from_fn(ensure_request_id))
        .with_state(state)
}

async fn ensure_request_id(mut request: Request<Body>, next: Next) -> Response {
    let request_id = request
        .headers()
        .get(&REQUEST_ID_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| Uuid::parse_str(value).ok())
        .unwrap_or_else(Uuid::new_v4);
    let header_value = HeaderValue::from_str(&request_id.to_string())
        .expect("a UUID is always a valid HTTP header value");
    request
        .headers_mut()
        .insert(REQUEST_ID_HEADER, header_value.clone());
    request.extensions_mut().insert(HttpRequestId(request_id));
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert(REQUEST_ID_HEADER, header_value);
    response
}

async fn enforce_privacy_production_gate(
    State(state): State<Arc<AppState>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    if state.config.synthetic_data_only {
        return next.run(request).await;
    }
    let path = request.uri().path();
    let allowed_without_approval = path.starts_with("/health/")
        || matches!(
            path,
            "/openapi.json"
                | "/v1/version"
                | "/v1/me"
                | "/v1/identity/link"
                | "/internal/metrics"
                | "/internal/metrics/live"
                | "/internal/v1/application-releases"
        )
        || path.starts_with("/v1/privacy/requests")
        || path.starts_with("/v1/platform/privacy")
        || path.starts_with("/v1/platform/roles")
        || path.starts_with("/v1/platform/releases")
        || matches!(path, "/v1/platform/status" | "/v1/platform/overview");
    if allowed_without_approval {
        return next.run(request).await;
    }
    let allowed = sqlx::query_scalar::<_, bool>(
        "select production_personal_data_allowed from control.privacy_platform_state where singleton",
    )
    .fetch_one(state.store.pool())
    .await;
    match allowed {
        Ok(true) => next.run(request).await,
        Ok(false) => ApiError::PrivacyGate(
            "personal-data processing is blocked until controller, retention, processing-register and DPIA approvals are recorded",
        )
        .into_response(),
        Err(error) => ApiError::Internal(error.into()).into_response(),
    }
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

async fn revalidate_workshop_scope(
    tx: &mut sqlx::postgres::PgConnection,
    scope: &WorkshopScope,
) -> ApiResult<()> {
    let current = sqlx::query_as::<_, (String, i32)>(
        "select role,authority_epoch from control.memberships
         where workshop_id=$1 and user_id=$2 and status='active'
         for share",
    )
    .bind(scope.workshop_id)
    .bind(scope.principal_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(ApiError::NotFound)?;
    let role = WorkshopRole::from_str(&current.0)
        .map_err(|_| ApiError::Internal(anyhow::anyhow!("invalid stored workshop role")))?;
    if !workshop_scope_is_current(scope, role, current.1) {
        return Err(ApiError::Forbidden);
    }
    Ok(())
}

async fn revalidate_platform_scope(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    scope: &PlatformScope,
) -> ApiResult<()> {
    // Row locks keep every currently-authorizing grant active until the
    // mutation commits. A concurrent revocation therefore either wins before
    // this query (and is rejected below) or waits until this command finishes.
    let roles = sqlx::query_scalar::<_, String>(
        "select role from control.platform_role_assignments
         where user_id=$1 and revoked_at is null
         order by role for share",
    )
    .bind(scope.principal().user_id)
    .fetch_all(&mut **tx)
    .await?;
    if !platform_scope_is_current(scope, &roles) {
        return Err(ApiError::Forbidden);
    }
    Ok(())
}

fn platform_scope_is_current(scope: &PlatformScope, current_roles: &[String]) -> bool {
    scope.permission().allows(current_roles)
}

fn workshop_scope_is_current(
    scope: &WorkshopScope,
    current_role: WorkshopRole,
    current_epoch: i32,
) -> bool {
    current_epoch == scope.authority_epoch
        && current_role == scope.role
        && current_role.allows(scope.permission)
}

fn idempotency(headers: &HeaderMap) -> ApiResult<&str> {
    headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| {
            (1..=255).contains(&value.len())
                && value.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'-')
                })
        })
        .ok_or(ApiError::Precondition("Idempotency-Key is required"))
}

fn command_error(error: CommandError) -> ApiError {
    match error {
        CommandError::InvalidIdempotencyKey => {
            ApiError::Validation("Idempotency-Key contains invalid characters")
        }
        CommandError::PayloadMismatch => {
            ApiError::Conflict("Idempotency-Key was already used for another request")
        }
        CommandError::Database(error) => ApiError::from(error),
    }
}

fn expected_version(headers: &HeaderMap, resource_prefix: &str) -> ApiResult<i64> {
    let value = headers
        .get(header::IF_MATCH)
        .and_then(|value| value.to_str().ok())
        .ok_or(ApiError::Precondition("If-Match is required"))?;
    let prefix = format!("\"{resource_prefix}-v");
    value
        .strip_prefix(&prefix)
        .and_then(|value| value.strip_suffix('"'))
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|version| *version > 0)
        .ok_or(ApiError::PreconditionFailed(
            "If-Match does not match this resource",
        ))
}

fn etag(resource_prefix: &str, version: i64) -> ApiResult<HeaderMap> {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::ETAG,
        HeaderValue::from_str(&format!("\"{resource_prefix}-v{version}\""))
            .map_err(|error| ApiError::Internal(error.into()))?,
    );
    Ok(headers)
}

fn exact_bearer(headers: &HeaderMap, expected: &str) -> bool {
    let Some(supplied) = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
    else {
        return false;
    };
    let supplied = supplied.as_bytes();
    let expected = expected.as_bytes();
    let mut difference = supplied.len() ^ expected.len();
    for index in 0..supplied.len().max(expected.len()) {
        difference |= usize::from(
            supplied.get(index).copied().unwrap_or_default()
                ^ expected.get(index).copied().unwrap_or_default(),
        );
    }
    difference == 0
}

fn internal(state: &AppState, headers: &HeaderMap) -> ApiResult<()> {
    if !exact_bearer(headers, &state.config.internal_token) {
        return Err(ApiError::Unauthenticated);
    }
    Ok(())
}

fn metrics_reader(state: &AppState, headers: &HeaderMap) -> ApiResult<()> {
    if !exact_bearer(headers, &state.config.metrics_token) {
        return Err(ApiError::Unauthenticated);
    }
    Ok(())
}

fn mail_event_gateway(state: &AppState, headers: &HeaderMap) -> ApiResult<()> {
    if !exact_bearer(headers, &state.config.mail_event_token) {
        return Err(ApiError::Unauthenticated);
    }
    Ok(())
}

fn release_publisher(state: &AppState, headers: &HeaderMap) -> ApiResult<()> {
    if !exact_bearer(headers, &state.config.release_publish_token) {
        return Err(ApiError::Unauthenticated);
    }
    Ok(())
}

async fn tenant_bridge(state: &AppState, headers: &HeaderMap, workshop: Uuid) -> ApiResult<()> {
    let supplied = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or(ApiError::Unauthenticated)?;
    let reference = sqlx::query_scalar::<_, String>(
        "select secret_ref from control.service_instances
         where workshop_id=$1 and service='odoo'",
    )
    .bind(workshop)
    .fetch_optional(state.store.pool())
    .await?
    .ok_or(ApiError::Unauthenticated)?;
    let expected = crate::worker::secret(&reference).map_err(|_| ApiError::Unauthenticated)?;
    let supplied = supplied.as_bytes();
    let expected = expected.as_bytes();
    let mut difference = supplied.len() ^ expected.len();
    for index in 0..supplied.len().max(expected.len()) {
        difference |= usize::from(
            supplied.get(index).copied().unwrap_or_default()
                ^ expected.get(index).copied().unwrap_or_default(),
        );
    }
    if difference != 0 {
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
    Json(json!({"name": "mb-control-plane", "version": env!("CARGO_PKG_VERSION")}))
}

async fn openapi() -> impl IntoResponse {
    Json(crate::openapi::document())
}

async fn metrics(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> ApiResult<(HeaderMap, String)> {
    metrics_reader(&state, &headers)?;
    let queues=sqlx::query_as::<_,(String,i64,i64,f64)>("with known(queue) as (values ('tenant-provisioning'),('membership-provisioning'),('invoice-capture'),('inventory-capture'),('email-delivery'),('tenant-reconciliation'),('tenant-lifecycle'),('release-adoption'),('privacy-operations')) select known.queue,count(o.id) filter(where o.state in ('pending','awaiting_reconciliation')),count(o.id) filter(where o.state='dead_letter'),coalesce(extract(epoch from now()-min(o.next_attempt_at) filter(where o.state in ('pending','awaiting_reconciliation') and o.next_attempt_at<=now())),0)::float8 from known left join control.operations o on o.queue=known.queue group by known.queue order by known.queue")
        .fetch_all(state.store.pool()).await?;
    let workers=sqlx::query_as::<_,(String,i64)>("with known(queue) as (values ('tenant-provisioning'),('membership-provisioning'),('invoice-capture'),('inventory-capture'),('email-delivery'),('tenant-reconciliation'),('tenant-lifecycle'),('release-adoption'),('privacy-operations')) select known.queue,count(h.worker_id) filter(where h.shutdown_at is null and h.last_heartbeat_at>now()-interval '30 seconds') from known left join control.worker_heartbeats h on h.queue=known.queue group by known.queue order by known.queue")
        .fetch_all(state.store.pool()).await?;
    let adoptions = sqlx::query_as::<_, (String, i64)>(
        "select state,count(*) from control.tenant_release_adoptions group by state order by state",
    )
    .fetch_all(state.store.pool())
    .await?;
    let integrations = sqlx::query_as::<_, (String, String, i64)>(
        "select service,health,count(*) from control.service_instances group by service,health order by service,health",
    )
    .fetch_all(state.store.pool())
    .await?;
    let identity_available = state.auth.ready().await;
    let backup_age=sqlx::query_scalar::<_,Option<f64>>("select extract(epoch from now()-max(ready_at))::float8 from control.workshop_recovery_points where kind='backup' and state='ready' and verification_state='verified'")
        .fetch_one(state.store.pool()).await?;
    let rehearsal_age=sqlx::query_scalar::<_,Option<f64>>("select extract(epoch from now()-max(finished_at))::float8 from control.workshop_recovery_rehearsals where state='succeeded'")
        .fetch_one(state.store.pool()).await?;
    let abandoned=sqlx::query_scalar::<_,i64>("select count(*) from control.operations where state='in_flight' and lease_expires_at<now()")
        .fetch_one(state.store.pool()).await?;
    let mut body = String::from(
        "# HELP mb_queue_depth Due or queued durable operations.\n# TYPE mb_queue_depth gauge\n",
    );
    for (queue, depth, dead, age) in queues {
        body.push_str(&format!("mb_queue_depth{{queue=\"{queue}\"}} {depth}\nmb_queue_dead_letters{{queue=\"{queue}\"}} {dead}\nmb_queue_oldest_due_age_seconds{{queue=\"{queue}\"}} {age}\n"));
    }
    body.push_str(
        "# HELP mb_worker_fresh Fresh worker heartbeats by queue.\n# TYPE mb_worker_fresh gauge\n",
    );
    for (queue, count) in workers {
        body.push_str(&format!("mb_worker_fresh{{queue=\"{queue}\"}} {count}\n"));
    }
    for (adoption_state, count) in adoptions {
        body.push_str(&format!(
            "mb_release_adoptions{{state=\"{adoption_state}\"}} {count}\n"
        ));
    }
    body.push_str("# HELP mb_integration_instances Connected integration instances by bounded integration and health.\n# TYPE mb_integration_instances gauge\n");
    for (integration, health, count) in integrations {
        body.push_str(&format!(
            "mb_integration_instances{{integration=\"{integration}\",health=\"{health}\"}} {count}\n"
        ));
    }
    body.push_str(&format!(
        "mb_integration_instances{{integration=\"rauthy\",health=\"{}\"}} 1\n",
        if identity_available {
            "ready"
        } else {
            "failed"
        }
    ));
    body.push_str(&format!("mb_abandoned_operation_leases {abandoned}\nmb_backup_freshness_seconds {}\nmb_restore_rehearsal_age_seconds {}\n",backup_age.unwrap_or(-1.0),rehearsal_age.unwrap_or(-1.0)));
    body.push_str("# HELP mb_http_requests_total HTTP requests by templated route and status class.\n# TYPE mb_http_requests_total counter\n# HELP mb_http_latency_seconds_sum Accumulated HTTP latency by templated route and status class.\n# TYPE mb_http_latency_seconds_sum counter\n");
    if let Ok(metrics) = HTTP_METRICS
        .get_or_init(|| Mutex::new(std::collections::HashMap::new()))
        .lock()
    {
        let mut rows = metrics.iter().collect::<Vec<_>>();
        rows.sort_by(|left, right| left.0.cmp(right.0));
        for ((route, status_class), metric) in rows {
            body.push_str(&format!("mb_http_requests_total{{route=\"{route}\",status_class=\"{status_class}xx\"}} {}\nmb_http_latency_seconds_sum{{route=\"{route}\",status_class=\"{status_class}xx\"}} {}\n",metric.requests,metric.latency_micros as f64/1_000_000.0));
        }
    }
    let mut response_headers = HeaderMap::new();
    response_headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
    );
    response_headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok((response_headers, body))
}

async fn live_metrics(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> ApiResult<(HeaderMap, &'static str)> {
    metrics_reader(&state, &headers)?;
    let mut response_headers = HeaderMap::new();
    response_headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
    );
    response_headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok((
        response_headers,
        "# TYPE mb_application_live gauge\nmb_application_live 1\n",
    ))
}

async fn me(
    State(state): State<Arc<AppState>>,
    Extension(who): Extension<Principal>,
) -> ApiResult<Json<MeResponse>> {
    let roles = platform_roles(&state, &who).await?;
    Ok(Json(MeResponse {
        id: who.user_id,
        email: who.email,
        subject: who.subject,
        is_operator: !roles.is_empty(),
        platform_roles: roles,
        recent_strong_authentication: who.recent_strong_authentication,
    }))
}

async fn platform_roles(state: &AppState, who: &Principal) -> ApiResult<Vec<String>> {
    let roles = sqlx::query_scalar::<_, String>(
        "select role from control.platform_role_assignments where user_id=$1 and revoked_at is null order by role",
    )
    .bind(who.user_id)
    .fetch_all(state.store.pool())
    .await?;
    if !roles.is_empty() || !state.config.operator_emails.contains(&who.email) {
        return Ok(roles);
    }

    // CONTROL_OPERATOR_EMAILS is only a one-time bootstrap input. Once the
    // initial technical administrator is recorded, authorization is entirely
    // database-backed and changing the environment cannot grant authority.
    let mut tx = state.store.begin().await?;
    let bootstrapped = sqlx::query_scalar::<_, bool>(
        "select initial_admin_bootstrapped from control.platform_authority_state where singleton for update",
    )
    .fetch_one(&mut *tx)
    .await?;
    if !bootstrapped {
        sqlx::query("insert into control.platform_role_assignments(id,user_id,role,granted_by,grant_reason_code) values($1,$2,'technical_admin',$2,'initial_project_owner')")
            .bind(Uuid::new_v4())
            .bind(who.user_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("update control.platform_authority_state set initial_admin_bootstrapped=true,bootstrapped_at=now() where singleton")
            .execute(&mut *tx)
            .await?;
        audit(
            &mut tx,
            Some(who.user_id),
            None,
            "platform.authority.bootstrap",
            "user",
            who.user_id.to_string(),
            Uuid::new_v4(),
        )
        .await?;
    }
    tx.commit().await?;
    sqlx::query_scalar::<_, String>(
        "select role from control.platform_role_assignments where user_id=$1 and revoked_at is null order by role",
    )
    .bind(who.user_id)
    .fetch_all(state.store.pool())
    .await
    .map_err(ApiError::from)
}

async fn is_operator(state: &AppState, who: &Principal) -> ApiResult<bool> {
    Ok(!platform_roles(state, who).await?.is_empty())
}

fn require_step_up(who: &Principal) -> ApiResult<()> {
    if !who.recent_strong_authentication {
        return Err(ApiError::Precondition(
            "recent multi-factor or phishing-resistant authentication is required",
        ));
    }
    Ok(())
}

async fn link_identity(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Extension(verified): Extension<VerifiedToken>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let client_key = if headers.contains_key("idempotency-key") {
        idempotency(&headers)?.to_owned()
    } else {
        "identity-link".to_owned()
    };
    let mut tx = state.store.begin().await?;
    let existing_user_id = sqlx::query_scalar::<_, Uuid>(
        "select user_id from control.external_identities where issuer=$1 and subject=$2 and disabled_at is null",
    )
    .bind(&verified.issuer)
    .bind(&verified.subject)
    .fetch_optional(&mut *tx)
    .await?
    ;
    let user_id = if let Some(user_id) = existing_user_id {
        user_id
    } else {
        match sqlx::query_scalar::<_, Uuid>(
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
                    .bind(user_id)
                    .bind(&verified.email)
                    .execute(&mut *tx)
                    .await?;
                user_id
            }
            None => return Err(ApiError::Unauthenticated),
        }
    };
    let semantic = json!({
        "issuer": verified.issuer,
        "subject": verified.subject,
        "email": verified.email,
    });
    let scope = format!("user:{user_id}");
    let command_id = match admit_command(
        &mut tx,
        NewCommand {
            actor_user_id: user_id,
            scope: &scope,
            command_kind: "identity.link",
            idempotency_key: &client_key,
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
        CommandAdmission::InProgress {
            command_id,
            operation_id,
        } => {
            tx.commit().await?;
            return Ok((
                StatusCode::ACCEPTED,
                Json(json!({
                    "command_id": command_id,
                    "operation_id": operation_id,
                    "in_progress": true
                })),
            ));
        }
    };
    let linked = existing_user_id.is_none();
    if linked {
        sqlx::query("insert into control.external_identities(id,user_id,issuer,subject,email_at_link) values($1,$2,$3,$4,$5)")
            .bind(Uuid::new_v4()).bind(user_id).bind(&verified.issuer).bind(&verified.subject).bind(&verified.email).execute(&mut *tx).await?;
    }
    let correlation = Uuid::new_v4();
    audit_command(
        &mut tx,
        (Some(user_id), None),
        "identity.link",
        "user",
        user_id.to_string(),
        correlation,
        command_id,
    )
    .await?;
    let response = json!({"user_id":user_id,"linked":linked});
    let status = if linked {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    complete_command(
        &mut tx,
        command_id,
        CommandResult {
            operation_id: None,
            response_status: status.as_u16(),
            response_body: Some(&response),
            result_ref: None,
        },
    )
    .await
    .map_err(command_error)?;
    tx.commit().await?;
    Ok((status, Json(response)))
}

async fn integrations(
    State(state): State<Arc<AppState>>,
    Extension(scope): Extension<WorkshopScope>,
) -> ApiResult<Json<Vec<IntegrationResponse>>> {
    let id = scope.workshop_id;
    let mut tx = state.tenant_store.begin(id).await?;
    let route = sqlx::query_as::<_, (String, Option<String>)>(
        "select w.slug,d.public_hostname from control.workshops w
         left join control.odoo_databases d on d.workshop_id=w.id and d.kind='primary'
           and d.deleted_at is null
         where w.id=$1",
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await?;
    let rows=sqlx::query_as::<_,(String,String,String,i32,i32,Option<String>)>("select service,base_url,health,desired_epoch,applied_epoch,safe_error_class from control.service_instances where workshop_id=$1 order by service").bind(id).fetch_all(&mut *tx).await?;
    tx.commit().await?;
    Ok(Json(
        rows.into_iter()
            .map(|row| {
                let external_url =
                    service_external_url(&state.config, &row.0, &route.0, route.1.as_deref());
                IntegrationResponse {
                    service: row.0,
                    url: row.1,
                    external_url,
                    health: row.2,
                    desired_epoch: row.3,
                    applied_epoch: row.4,
                    error: row.5,
                }
            })
            .collect(),
    ))
}

fn service_external_url(
    config: &Config,
    service: &str,
    workshop_slug: &str,
    primary_hostname: Option<&str>,
) -> Option<String> {
    let hostname = match service {
        "odoo" => primary_hostname?.to_owned(),
        "paperless" => format!("docs-{workshop_slug}.{}", config.tenant_domain),
        _ => return None,
    };
    Some(config.tenant_origin(&hostname))
}

async fn modules(
    State(state): State<Arc<AppState>>,
    Extension(scope): Extension<WorkshopScope>,
) -> ApiResult<Json<Vec<ModuleResponse>>> {
    let id = scope.workshop_id;
    let role = scope.role;
    let mut tx = state.tenant_store.begin(id).await?;
    let entitlement_limits = sqlx::query_scalar::<_, Value>(
        "select limits from control.entitlements
         where workshop_id=$1 and status='active'
           and (expires_at is null or expires_at>now())",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?;
    let entitled = entitlement_limits
        .as_ref()
        .and_then(|limits| limits.get("capabilities"))
        .and_then(Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .filter_map(Value::as_str)
                .collect::<std::collections::HashSet<_>>()
        })
        .unwrap_or_default();
    let active_release = sqlx::query_as::<_, (String, i32)>(
        "select release_id,registry_version from control.tenant_release_adoptions
         where workshop_id=$1 and state='active' order by activated_at desc,id limit 1",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?;
    let release_capabilities = if let Some((_, registry_version)) = &active_release {
        sqlx::query_scalar::<_, String>(
            "select capability_key from control.capability_registry_entries
             where registry_version=$1",
        )
        .bind(registry_version)
        .fetch_all(&mut *tx)
        .await?
        .into_iter()
        .collect::<std::collections::HashSet<_>>()
    } else {
        std::collections::HashSet::new()
    };
    let rows = sqlx::query_as::<
        _,
        (
            String,
            String,
            Option<Uuid>,
            Option<String>,
            Option<String>,
            i64,
        ),
    >(
        "select wm.module_key,wm.state,wm.operation_id,o.state,o.failure_class,wm.version
         from control.workshop_modules wm
         left join control.operations o on o.id=wm.operation_id
         where wm.workshop_id=$1",
    )
    .bind(id)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    let states = rows
        .into_iter()
        .map(|row| (row.0, (row.1, row.2, row.3, row.4, row.5)))
        .collect::<std::collections::HashMap<_, _>>();
    Ok(Json(
        crate::modules::CATALOG
            .iter()
            .map(|bundle| {
                let state = states.get(bundle.key);
                let operation_state = state.and_then(|value| value.2.as_deref());
                let version = state.map_or(1, |value| value.4);
                let is_entitled = entitled.contains("*") || entitled.contains(bundle.key);
                let release_available = release_capabilities.contains(bundle.key);
                let visible_state = match operation_state {
                    Some("dead_letter") => "failed",
                    _ if !release_available && state.is_none() => "unavailable",
                    _ if state.is_some_and(|value| value.0 == "enabled") && !is_entitled => {
                        "restricted"
                    }
                    _ => state.map_or("available", |value| value.0.as_str()),
                };
                ModuleResponse {
                    key: bundle.key.to_owned(),
                    name: bundle.name.to_owned(),
                    description: bundle.description.to_owned(),
                    state: visible_state.to_owned(),
                    operation_id: state.and_then(|value| value.1),
                    error: state.and_then(|value| value.3.clone()),
                    version,
                    etag: format!("\"capability-{id}-{}-v{version}\"", bundle.key),
                    can_manage: role.can_manage_modules() && is_entitled && release_available,
                    entitled: is_entitled,
                    release_available,
                    application_release_id: active_release.as_ref().map(|value| value.0.clone()),
                    registry_version: active_release
                        .as_ref()
                        .and_then(|value| u32::try_from(value.1).ok())
                        .unwrap_or(crate::modules::REGISTRY_VERSION),
                    minimum_release: bundle.minimum_release.to_owned(),
                    dependencies: bundle
                        .dependencies
                        .iter()
                        .map(|value| (*value).to_owned())
                        .collect(),
                }
            })
            .collect(),
    ))
}

#[derive(Deserialize)]
struct ModulePath {
    module_key: String,
}

async fn enable_module(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Extension(scope): Extension<WorkshopScope>,
    Path(ModulePath { module_key }): Path<ModulePath>,
) -> ApiResult<(StatusCode, HeaderMap, Json<Value>)> {
    let id = scope.workshop_id;
    let actor = scope.principal_id;
    let client_key = idempotency(&headers)?.to_owned();
    let resource = format!("capability-{id}-{module_key}");
    let expected = expected_version(&headers, &resource)?;
    let bundle = crate::modules::bundle(&module_key).ok_or(ApiError::NotFound)?;
    let activation = sqlx::query_as::<
        _,
        (i64, String, i32, Vec<String>, Vec<String>, Option<String>),
    >(
        "select e.version,a.release_id,a.registry_version,c.dependencies,c.odoo_modules,c.service
         from control.entitlements e
         join lateral (
           select release_id,registry_version from control.tenant_release_adoptions
           where workshop_id=e.workshop_id and state='active'
           order by activated_at desc,id limit 1
         ) a on true
         join control.capability_registry_entries c
           on c.registry_version=a.registry_version and c.capability_key=$2
         where e.workshop_id=$1 and e.status='active'
           and (e.expires_at is null or e.expires_at>now())
           and (coalesce(e.limits->'capabilities','[]'::jsonb) ? $2
                or coalesce(e.limits->'capabilities','[]'::jsonb) ? '*')",
    )
    .bind(id)
    .bind(&module_key)
    .fetch_optional(state.store.pool())
    .await?;
    let Some(activation) = activation else {
        return Err(ApiError::Forbidden);
    };
    if activation.3 != bundle.dependencies
        || activation.4 != bundle.odoo_modules
        || activation.5.as_deref() != bundle.service
    {
        return Err(ApiError::Conflict(
            "active release capability registry does not match this control release",
        ));
    }
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
    let correlation = Uuid::new_v4();
    let payload = json!({
        "module_key":module_key,
        "registry_version":activation.2,
        "application_release_id":activation.1,
        "entitlement_version":activation.0,
        "resolved_implementation":{
            "odoo_modules":activation.4,
            "service":activation.5
        }
    });
    let mut tx = state.tenant_store.begin(scope.workshop_id).await?;
    revalidate_workshop_scope(&mut tx, &scope).await?;
    let command_scope = format!("workshop:{id}:capability:{module_key}");
    let command_id = match admit_command(
        &mut tx,
        NewCommand {
            actor_user_id: actor,
            scope: &command_scope,
            command_kind: "capability.enable",
            idempotency_key: &client_key,
            semantic_request: &payload,
            expected_version: Some(expected),
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
            let response = response_body.unwrap_or_else(|| json!({"replayed":true}));
            let version = response["version"].as_i64().unwrap_or(expected);
            tx.commit().await?;
            return Ok((
                StatusCode::from_u16(response_status).unwrap_or(StatusCode::ACCEPTED),
                etag(&resource, version)?,
                Json(response),
            ));
        }
        CommandAdmission::InProgress {
            command_id,
            operation_id,
        } => {
            tx.commit().await?;
            return Ok((
                StatusCode::ACCEPTED,
                etag(&resource, expected)?,
                Json(
                    json!({"command_id":command_id,"operation_id":operation_id,"in_progress":true}),
                ),
            ));
        }
    };
    lock_lifecycle(&mut tx, id).await?;
    ensure_lifecycle_idle(&mut tx, id).await?;
    let current = sqlx::query_as::<_, (String, Option<Uuid>, i64)>(
        "select state,operation_id,version from control.workshop_modules
         where workshop_id=$1 and module_key=$2 for update",
    )
    .bind(id)
    .bind(&module_key)
    .fetch_optional(&mut *tx)
    .await?;
    if current.as_ref().map_or(1, |row| row.2) != expected {
        return Err(ApiError::PreconditionFailed("If-Match is stale"));
    }
    if current.as_ref().is_some_and(|row| row.0 == "enabled") {
        let response = json!({"state":"enabled","version":expected});
        complete_command(
            &mut tx,
            command_id,
            CommandResult {
                operation_id: None,
                response_status: StatusCode::OK.as_u16(),
                response_body: Some(&response),
                result_ref: None,
            },
        )
        .await
        .map_err(command_error)?;
        tx.commit().await?;
        return Ok((StatusCode::OK, etag(&resource, expected)?, Json(response)));
    }
    let operation_id = Store::enqueue(
        &mut tx,
        NewOperation {
            kind: OperationKind::ModuleEnable,
            workshop_id: Some(id),
            target_user_id: None,
            desired_epoch: None,
            payload: &payload,
            requested_by: Some(actor),
            correlation_id: correlation,
            idempotency_key: &format!("command:{command_id}"),
        },
    )
    .await?;
    let changed = sqlx::query(
        "insert into control.workshop_modules(workshop_id,module_key,state,operation_id,requested_by,version,registry_version,application_release_id,entitlement_version,resolved_implementation)
         values($1,$2,'requested',$3,$4,2,$6,$7,$8,$9)
         on conflict(workshop_id,module_key) do update set
           state='requested',operation_id=excluded.operation_id,requested_by=excluded.requested_by,
           requested_at=now(),enabled_at=null,version=control.workshop_modules.version+1,
           registry_version=excluded.registry_version,application_release_id=excluded.application_release_id,
           entitlement_version=excluded.entitlement_version,resolved_implementation=excluded.resolved_implementation
         where control.workshop_modules.version=$5",
    )
    .bind(id)
    .bind(&module_key)
    .bind(operation_id)
    .bind(actor)
    .bind(expected)
    .bind(activation.2)
    .bind(&activation.1)
    .bind(activation.0)
    .bind(&payload["resolved_implementation"])
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if changed != 1 {
        return Err(ApiError::PreconditionFailed("If-Match is stale"));
    }
    let version = expected + 1;
    audit_command(
        &mut tx,
        (Some(actor), Some(id)),
        "module.enable",
        "workshop_module",
        module_key.clone(),
        correlation,
        command_id,
    )
    .await?;
    let response = json!({"operation_id":operation_id,"version":version,"state":"requested"});
    complete_command(
        &mut tx,
        command_id,
        CommandResult {
            operation_id: Some(operation_id),
            response_status: StatusCode::ACCEPTED.as_u16(),
            response_body: Some(&response),
            result_ref: None,
        },
    )
    .await
    .map_err(command_error)?;
    tx.commit().await?;
    Ok((
        StatusCode::ACCEPTED,
        etag(&resource, version)?,
        Json(response),
    ))
}

async fn operation(
    State(state): State<Arc<AppState>>,
    Extension(who): Extension<Principal>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<OperationResponse>> {
    let row=sqlx::query_as::<_,(String,String,Option<Uuid>,i32,i32,Option<String>,OffsetDateTime,Option<OffsetDateTime>,i16,Option<String>,Option<String>,Option<OffsetDateTime>)>("select kind,state,workshop_id,attempt,max_attempts,failure_class,created_at,finished_at,progress_percent,progress_phase,progress_message,progress_updated_at from control.operations where id=$1").bind(id).fetch_optional(state.store.pool()).await?.ok_or(ApiError::NotFound)?;
    if let Some(workshop) = row.2 {
        if !is_operator(&state, &who).await? {
            authority(&state, who.user_id, workshop).await?;
        }
    } else if who.user_id
        != sqlx::query_scalar::<_, Uuid>("select requested_by from control.operations where id=$1")
            .bind(id)
            .fetch_one(state.store.pool())
            .await?
    {
        return Err(ApiError::NotFound);
    }
    Ok(Json(OperationResponse {
        id,
        kind: row.0,
        state: row.1,
        workshop_id: row.2,
        attempt: row.3,
        max_attempts: row.4,
        failure_class: row.5,
        created_at: api_timestamp(row.6),
        finished_at: row.7.map(api_timestamp),
        progress_percent: row.8,
        progress_phase: row.9,
        progress_message: row.10,
        progress_updated_at: row.11.map(api_timestamp),
    }))
}

async fn retry_operation(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Extension(who): Extension<Principal>,
    Path(id): Path<Uuid>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let key = idempotency(&headers)?.to_owned();
    let row = sqlx::query_as::<_, (Option<Uuid>, String)>(
        "select workshop_id,kind from control.operations where id=$1",
    )
    .bind(id)
    .fetch_optional(state.store.pool())
    .await?
    .ok_or(ApiError::NotFound)?;
    if !is_operator(&state, &who).await? {
        let role = match row.0 {
            Some(workshop) => Some(authority(&state, who.user_id, workshop).await?.0),
            None => None,
        };
        if !non_operator_can_retry_operation(role, &row.1) {
            return Err(if row.0.is_some() {
                ApiError::Forbidden
            } else {
                ApiError::NotFound
            });
        }
    }
    let semantic = json!({"operation_id":id});
    let correlation = Uuid::new_v4();
    let command_scope = row.0.map_or_else(
        || "platform:operations".to_owned(),
        |workshop| format!("workshop:{workshop}:operations"),
    );
    let mut tx = state.store.begin().await?;
    let command_id = match admit_command(
        &mut tx,
        NewCommand {
            actor_user_id: who.user_id,
            scope: &command_scope,
            command_kind: "operation.retry",
            idempotency_key: &key,
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
        CommandAdmission::InProgress { command_id, .. } => {
            tx.commit().await?;
            return Ok((
                StatusCode::ACCEPTED,
                Json(json!({"command_id":command_id,"in_progress":true})),
            ));
        }
    };
    let changed=sqlx::query("update control.operations set state='pending',attempt=0,next_attempt_at=now(),failure_class=null,finished_at=null where id=$1 and state='dead_letter'").bind(id).execute(&mut *tx).await?;
    if changed.rows_affected() != 1 {
        return Err(ApiError::Conflict(
            "only dead-letter operations can be retried",
        ));
    }
    audit_command(
        &mut tx,
        (Some(who.user_id), row.0),
        "operation.retry",
        "operation",
        id.to_string(),
        correlation,
        command_id,
    )
    .await?;
    let response = json!({"id":id,"state":"pending"});
    let result_ref = id.to_string();
    complete_command(
        &mut tx,
        command_id,
        CommandResult {
            operation_id: Some(id),
            response_status: StatusCode::ACCEPTED.as_u16(),
            response_body: Some(&response),
            result_ref: Some(&result_ref),
        },
    )
    .await
    .map_err(command_error)?;
    tx.commit().await?;
    Ok((StatusCode::ACCEPTED, Json(response)))
}

fn non_operator_can_retry_operation(role: Option<WorkshopRole>, kind: &str) -> bool {
    role.is_some_and(|role| {
        if kind == "tenant.lifecycle" {
            role.can_manage_database()
        } else {
            role.can_manage_members()
        }
    })
}

async fn seed_targets(
    tx: &mut sqlx::postgres::PgConnection,
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
        .bind(workshop).bind(user).bind(epoch).execute(&mut *tx).await?;
    Ok(())
}

async fn audit(
    tx: &mut sqlx::postgres::PgConnection,
    actor: Option<Uuid>,
    workshop: Option<Uuid>,
    action: &str,
    target_type: &str,
    target_id: String,
    correlation: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query("insert into control.audit_events(id,actor_audit_subject_id,workshop_id,action,target_type,target_id,correlation_id,outcome) values($1,(select audit_subject_id from control.users where id=$2),$3,$4,$5,$6,$7,'accepted')")
        .bind(Uuid::new_v4()).bind(actor).bind(workshop).bind(action).bind(target_type).bind(target_id).bind(correlation).execute(&mut *tx).await?;
    Ok(())
}

async fn audit_command(
    tx: &mut sqlx::postgres::PgConnection,
    authority: (Option<Uuid>, Option<Uuid>),
    action: &str,
    target_type: &str,
    target_id: String,
    correlation: Uuid,
    command_id: Uuid,
) -> Result<(), sqlx::Error> {
    let (actor, workshop) = authority;
    sqlx::query(
        "insert into control.audit_events(
           id,actor_audit_subject_id,workshop_id,action,target_type,target_id,
           correlation_id,outcome,detail
         )
         select $1,(select audit_subject_id from control.users where id=$2),$3,$4,$5,$6,$7,
                'accepted',jsonb_build_object(
                    'command_id',$8,
                    'request_digest',encode(c.request_digest,'hex'),
                    'result_class','accepted'
                )
         from control.commands c where c.id=$8",
    )
    .bind(Uuid::new_v4())
    .bind(actor)
    .bind(workshop)
    .bind(action)
    .bind(target_type)
    .bind(target_id)
    .bind(correlation)
    .bind(command_id)
    .execute(&mut *tx)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use axum::Router;
    use axum::body::Body;
    use axum::http::{HeaderMap, HeaderValue, Request, StatusCode, header};
    use axum::routing::get;
    use opentelemetry::trace::TraceContextExt as _;
    use tower::ServiceExt as _;
    use uuid::Uuid;

    use super::{
        ApiError, REQUEST_ID_HEADER, WorkshopRole, api_timestamp, ensure_request_id, etag,
        exact_bearer, expected_version, non_operator_can_retry_operation,
        platform_scope_is_current, remote_trace_context, valid_gtin14, workshop_scope_is_current,
    };

    #[test]
    fn inbound_w3c_trace_context_is_validated_before_attachment() {
        opentelemetry::global::set_text_map_propagator(
            opentelemetry_sdk::propagation::TraceContextPropagator::new(),
        );
        let mut headers = HeaderMap::new();
        assert!(remote_trace_context(&headers).unwrap().is_none());

        headers.insert(
            "traceparent",
            HeaderValue::from_static("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"),
        );
        headers.insert("tracestate", HeaderValue::from_static("vendor=value"));
        let context = remote_trace_context(&headers).unwrap().unwrap();
        assert!(context.span().span_context().is_remote());
        assert_eq!(
            context.span().span_context().trace_id().to_string(),
            "4bf92f3577b34da6a3ce929d0e0e4736"
        );

        headers.insert(
            "traceparent",
            HeaderValue::from_static("subject@example.test"),
        );
        assert!(remote_trace_context(&headers).is_err());
    }
    use crate::auth::{PlatformPermission, PlatformScope, Principal, WorkshopScope};
    use crate::domain::WorkshopPermission;

    #[test]
    fn mutation_scope_requires_the_same_role_epoch_and_permission() {
        let scope = WorkshopScope {
            workshop_id: Uuid::new_v4(),
            principal_id: Uuid::new_v4(),
            role: WorkshopRole::StudioManager,
            authority_epoch: 7,
            permission: WorkshopPermission::ManageMembers,
        };
        assert!(workshop_scope_is_current(
            &scope,
            WorkshopRole::StudioManager,
            7
        ));
        assert!(!workshop_scope_is_current(
            &scope,
            WorkshopRole::StudioManager,
            8
        ));
        assert!(!workshop_scope_is_current(&scope, WorkshopRole::Viewer, 7));
    }

    #[test]
    fn platform_mutation_scope_requires_a_current_authorizing_role() {
        let principal = Principal {
            user_id: Uuid::new_v4(),
            issuer: "https://auth.example.test".into(),
            subject: "operator".into(),
            email: "operator@example.test".into(),
            recent_strong_authentication: true,
        };
        let scope = PlatformScope::new(principal, PlatformPermission::OperateFleet);

        assert!(platform_scope_is_current(
            &scope,
            &["release_operator".into()]
        ));
        assert!(platform_scope_is_current(
            &scope,
            &["technical_admin".into()]
        ));
        assert!(!platform_scope_is_current(&scope, &[]));
        assert!(!platform_scope_is_current(
            &scope,
            &["privacy_reviewer".into()]
        ));
    }

    #[tokio::test]
    async fn request_ids_are_validated_and_returned() {
        let app = Router::new()
            .route("/", get(|| async { StatusCode::NO_CONTENT }))
            .layer(axum::middleware::from_fn(ensure_request_id));
        let supplied = Uuid::new_v4();
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(REQUEST_ID_HEADER, supplied.to_string())
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(
            response.headers().get(REQUEST_ID_HEADER),
            Some(&HeaderValue::from_str(&supplied.to_string()).unwrap())
        );

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(REQUEST_ID_HEADER, "unbounded-client-value")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        let generated = response
            .headers()
            .get(REQUEST_ID_HEADER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| Uuid::parse_str(value).ok());
        assert!(generated.is_some());
        assert_ne!(generated, Some(supplied));
    }

    #[test]
    fn api_timestamps_are_rfc3339_for_browser_parsers() {
        assert_eq!(
            api_timestamp(time::OffsetDateTime::UNIX_EPOCH),
            "1970-01-01T00:00:00Z"
        );
    }

    #[test]
    fn product_lookup_accepts_only_checksum_valid_gtin14() {
        assert!(valid_gtin14("00097539118054"));
        assert!(!valid_gtin14("00097539118055"));
        assert!(!valid_gtin14("097539118054"));
    }

    #[test]
    fn version_preconditions_require_an_exact_strong_etag() {
        let mut headers = HeaderMap::new();
        assert!(matches!(
            expected_version(&headers, "member-a-b"),
            Err(ApiError::Precondition(_))
        ));
        headers.insert(
            header::IF_MATCH,
            HeaderValue::from_static("W/\"member-a-b-v3\""),
        );
        assert!(matches!(
            expected_version(&headers, "member-a-b"),
            Err(ApiError::PreconditionFailed(_))
        ));
        headers.insert(
            header::IF_MATCH,
            HeaderValue::from_static("\"member-a-b-v3\""),
        );
        assert_eq!(expected_version(&headers, "member-a-b").unwrap(), 3);
        assert_eq!(
            etag("member-a-b", 4).unwrap().get(header::ETAG).unwrap(),
            "\"member-a-b-v4\""
        );
    }

    #[test]
    fn internal_bearers_are_exact_and_scheme_sensitive() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer metrics-only-secret"),
        );
        assert!(exact_bearer(&headers, "metrics-only-secret"));
        assert!(!exact_bearer(&headers, "metrics-only-secret-extra"));
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("bearer metrics-only-secret"),
        );
        assert!(!exact_bearer(&headers, "metrics-only-secret"));
    }

    #[test]
    fn platform_operations_cannot_be_retried_by_ordinary_members() {
        assert!(!non_operator_can_retry_operation(None, "privacy.retention"));
    }

    #[test]
    fn workshop_operation_retry_permissions_preserve_current_policy() {
        assert!(non_operator_can_retry_operation(
            Some(WorkshopRole::StudioManager),
            "module.enable"
        ));
        assert!(!non_operator_can_retry_operation(
            Some(WorkshopRole::StudioManager),
            "tenant.lifecycle"
        ));
        assert!(non_operator_can_retry_operation(
            Some(WorkshopRole::Owner),
            "tenant.lifecycle"
        ));
        assert!(!non_operator_can_retry_operation(
            Some(WorkshopRole::Viewer),
            "module.enable"
        ));
    }
}
