use super::*;

use async_trait::async_trait;
use axum::extract::rejection::RawPathParamsRejection;
use axum::extract::{RawPathParams, Request as AxumRequest};
use axum::routing::MethodRouter;

use crate::auth::{
    PlatformPermission, PlatformScope, Principal, VerifiedToken, WorkshopAuthority, WorkshopScope,
};
use crate::domain::WorkshopPermission;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RouteAccess {
    Public,
    VerifiedBearer,
    Authenticated,
    Workshop(WorkshopPermission),
    Platform(PlatformPermission),
}

impl RouteAccess {
    pub(crate) fn security_scheme(self) -> Option<&'static str> {
        match self {
            Self::Public => None,
            Self::VerifiedBearer | Self::Authenticated | Self::Workshop(_) => Some("rauthy"),
            Self::Platform(_) => Some("rauthyOperator"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PublicRouteSpec {
    pub path: &'static str,
    pub method: &'static str,
    pub handler: &'static str,
    pub access: RouteAccess,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum InternalRouteAccess {
    TenantBridgePath,
    TenantBridgeBody,
    InternalService,
    MailEventGateway,
    ReleasePublisher,
    MetricsReader,
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct InternalRouteSpec {
    pub path: &'static str,
    pub method: &'static str,
    pub handler: &'static str,
    pub access: InternalRouteAccess,
}

#[async_trait]
pub(crate) trait InternalRouteAuthorizationLookup: Send + Sync {
    async fn authorize_internal_route(
        &self,
        access: InternalRouteAccess,
        workshop_id: Option<Uuid>,
        headers: &HeaderMap,
    ) -> ApiResult<()>;
}

#[async_trait]
impl InternalRouteAuthorizationLookup for AppState {
    async fn authorize_internal_route(
        &self,
        access: InternalRouteAccess,
        workshop_id: Option<Uuid>,
        headers: &HeaderMap,
    ) -> ApiResult<()> {
        match access {
            InternalRouteAccess::TenantBridgePath => {
                let workshop_id = workshop_id.ok_or_else(|| {
                    ApiError::Internal(anyhow::anyhow!(
                        "path-scoped tenant bridge route has no workshop id"
                    ))
                })?;
                super::tenant_bridge(self, headers, workshop_id).await
            }
            InternalRouteAccess::TenantBridgeBody => Err(ApiError::Internal(anyhow::anyhow!(
                "body-scoped tenant bridge route was passed to authorization middleware"
            ))),
            InternalRouteAccess::InternalService => super::internal(self, headers),
            InternalRouteAccess::MailEventGateway => super::mail_event_gateway(self, headers),
            InternalRouteAccess::ReleasePublisher => super::release_publisher(self, headers),
            InternalRouteAccess::MetricsReader => super::metrics_reader(self, headers),
        }
    }
}

#[async_trait]
pub(crate) trait RouteAuthorizationLookup: Send + Sync {
    async fn verify_bearer(&self, headers: &HeaderMap) -> ApiResult<VerifiedToken>;
    async fn principal(&self, headers: &HeaderMap) -> ApiResult<Principal>;
    async fn membership(
        &self,
        principal_id: Uuid,
        workshop_id: Uuid,
    ) -> ApiResult<WorkshopAuthority>;
    async fn platform_roles(&self, principal: &Principal) -> ApiResult<Vec<String>>;
}

#[async_trait]
impl RouteAuthorizationLookup for AppState {
    async fn verify_bearer(&self, headers: &HeaderMap) -> ApiResult<VerifiedToken> {
        self.auth.verify_headers(headers).await
    }

    async fn principal(&self, headers: &HeaderMap) -> ApiResult<Principal> {
        super::principal(self, headers).await
    }

    async fn membership(
        &self,
        principal_id: Uuid,
        workshop_id: Uuid,
    ) -> ApiResult<WorkshopAuthority> {
        let (role, epoch) = super::authority(self, principal_id, workshop_id).await?;
        Ok(WorkshopAuthority {
            workshop_id,
            role,
            epoch,
        })
    }

    async fn platform_roles(&self, principal: &Principal) -> ApiResult<Vec<String>> {
        super::platform_roles(self, principal).await
    }
}

#[derive(Clone)]
struct RouteAuthorization {
    lookup: Arc<dyn RouteAuthorizationLookup>,
    access: RouteAccess,
}

async fn enforce_route_access(
    State(authorization): State<RouteAuthorization>,
    raw_path: Result<RawPathParams, RawPathParamsRejection>,
    headers: HeaderMap,
    mut request: AxumRequest,
    next: axum::middleware::Next,
) -> Response {
    let result = authorize_request(&authorization, raw_path.as_ref().ok(), &headers).await;
    match result {
        Ok(RouteIdentity::Verified(token)) => {
            request.extensions_mut().insert(token);
        }
        Ok(RouteIdentity::Principal(principal)) => {
            request.extensions_mut().insert(principal);
        }
        Ok(RouteIdentity::Workshop { principal, scope }) => {
            request.extensions_mut().insert(principal);
            request.extensions_mut().insert(scope);
        }
        Ok(RouteIdentity::Platform { principal, scope }) => {
            request.extensions_mut().insert(principal);
            request.extensions_mut().insert(scope);
        }
        Err(error) => return error.into_response(),
    }
    next.run(request).await
}

enum RouteIdentity {
    Verified(VerifiedToken),
    Principal(Principal),
    Workshop {
        principal: Principal,
        scope: WorkshopScope,
    },
    Platform {
        principal: Principal,
        scope: PlatformScope,
    },
}

async fn authorize_request(
    authorization: &RouteAuthorization,
    raw_path: Option<&RawPathParams>,
    headers: &HeaderMap,
) -> ApiResult<RouteIdentity> {
    match authorization.access {
        RouteAccess::Public => Err(ApiError::Internal(anyhow::anyhow!(
            "public route was passed to authorization middleware"
        ))),
        RouteAccess::VerifiedBearer => authorization
            .lookup
            .verify_bearer(headers)
            .await
            .map(RouteIdentity::Verified),
        RouteAccess::Authenticated => authorization
            .lookup
            .principal(headers)
            .await
            .map(RouteIdentity::Principal),
        RouteAccess::Workshop(permission) => {
            let principal = authorization.lookup.principal(headers).await?;
            let workshop_id = workshop_id(raw_path)?;
            let authority = authorization
                .lookup
                .membership(principal.user_id, workshop_id)
                .await?;
            if !authority.role.allows(permission) {
                return Err(ApiError::Forbidden);
            }
            Ok(RouteIdentity::Workshop {
                scope: WorkshopScope {
                    workshop_id,
                    principal_id: principal.user_id,
                    role: authority.role,
                    authority_epoch: authority.epoch,
                    permission,
                },
                principal,
            })
        }
        RouteAccess::Platform(permission) => {
            let principal = authorization.lookup.principal(headers).await?;
            let roles = authorization.lookup.platform_roles(&principal).await?;
            if !permission.allows(&roles) {
                return Err(ApiError::Forbidden);
            }
            Ok(RouteIdentity::Platform {
                scope: PlatformScope::new(principal.clone(), permission),
                principal,
            })
        }
    }
}

fn workshop_id(raw_path: Option<&RawPathParams>) -> ApiResult<Uuid> {
    let raw = raw_path
        .ok_or_else(|| ApiError::Internal(anyhow::anyhow!("workshop route has no path state")))?;
    let value = raw
        .iter()
        .find_map(|(name, value)| (name == "id").then_some(value))
        .ok_or_else(|| {
            ApiError::Internal(anyhow::anyhow!(
                "workshop route does not declare an id path parameter"
            ))
        })?;
    value
        .parse()
        .map_err(|_| ApiError::Validation("workshop id must be a UUID"))
}

fn guarded_method<S>(
    method: MethodRouter<S>,
    lookup: Arc<dyn RouteAuthorizationLookup>,
    access: RouteAccess,
) -> MethodRouter<S>
where
    S: Clone + Send + Sync + 'static,
{
    if access == RouteAccess::Public {
        method
    } else {
        method.route_layer(axum::middleware::from_fn_with_state(
            RouteAuthorization { lookup, access },
            enforce_route_access,
        ))
    }
}

#[derive(Clone)]
struct InternalRouteAuthorization {
    lookup: Arc<dyn InternalRouteAuthorizationLookup>,
    access: InternalRouteAccess,
}

async fn enforce_internal_route_access(
    State(authorization): State<InternalRouteAuthorization>,
    raw_path: Result<RawPathParams, RawPathParamsRejection>,
    headers: HeaderMap,
    request: AxumRequest,
    next: axum::middleware::Next,
) -> Response {
    let workshop_id = match authorization.access {
        InternalRouteAccess::TenantBridgePath => {
            match internal_workshop_id(raw_path.as_ref().ok()) {
                Ok(workshop_id) => Some(workshop_id),
                Err(error) => return error.into_response(),
            }
        }
        _ => None,
    };
    if let Err(error) = authorization
        .lookup
        .authorize_internal_route(authorization.access, workshop_id, &headers)
        .await
    {
        return error.into_response();
    }
    next.run(request).await
}

fn internal_workshop_id(raw_path: Option<&RawPathParams>) -> ApiResult<Uuid> {
    let raw = raw_path.ok_or_else(|| {
        ApiError::Internal(anyhow::anyhow!("tenant bridge route has no path state"))
    })?;
    let value = raw
        .iter()
        .find_map(|(name, value)| (name == "workshop_id").then_some(value))
        .ok_or_else(|| {
            ApiError::Internal(anyhow::anyhow!(
                "tenant bridge route does not declare a workshop_id path parameter"
            ))
        })?;
    value
        .parse()
        .map_err(|_| ApiError::Validation("workshop id must be a UUID"))
}

fn guarded_internal_method<S>(
    method: MethodRouter<S>,
    lookup: Arc<dyn InternalRouteAuthorizationLookup>,
    access: InternalRouteAccess,
) -> MethodRouter<S>
where
    S: Clone + Send + Sync + 'static,
{
    // The carrier-secret resolver carries its workshop identity in a bounded,
    // validated JSON body. Its handler therefore remains the explicit exception
    // that authenticates after extraction; every path/header-scoped route is
    // rejected by middleware before its handler runs.
    if access == InternalRouteAccess::TenantBridgeBody {
        method
    } else {
        method.route_layer(axum::middleware::from_fn_with_state(
            InternalRouteAuthorization { lookup, access },
            enforce_internal_route_access,
        ))
    }
}

macro_rules! route_access {
    (Public) => {
        RouteAccess::Public
    };
    (VerifiedBearer) => {
        RouteAccess::VerifiedBearer
    };
    (Authenticated) => {
        RouteAccess::Authenticated
    };
    (Workshop($permission:ident)) => {
        RouteAccess::Workshop(WorkshopPermission::$permission)
    };
    (Platform($permission:ident)) => {
        RouteAccess::Platform(PlatformPermission::$permission)
    };
}

macro_rules! public_routes {
    ($($path:literal => [$($method:ident($handler:path) => $access:ident $(($permission:ident))?),+ $(,)?];)+) => {
        pub(super) fn build(lookup: Arc<dyn RouteAuthorizationLookup>) -> Router<Arc<AppState>> {
            let mut router = Router::<Arc<AppState>>::new();
            $(
                let mut methods = MethodRouter::<Arc<AppState>>::new();
                $(
                    methods = methods.merge(guarded_method(
                        MethodRouter::<Arc<AppState>>::new().$method($handler),
                        lookup.clone(),
                        route_access!($access $(($permission))?),
                    ));
                )+
                router = router.route($path, methods);
            )+
            router
        }

        pub(crate) fn specs() -> Vec<PublicRouteSpec> {
            vec![
                $($(
                    PublicRouteSpec {
                    path: $path,
                    method: stringify!($method),
                    handler: stringify!($handler),
                    access: route_access!($access $(($permission))?),
                    },
                )+)+
            ]
        }
    };
}

public_routes! {
    "/v1/version" => [get(version) => Public];
    "/v1/me" => [get(me) => Authenticated];
    "/v1/platform/overview" => [get(platform::platform_overview) => Platform(ViewPlatform)];
    "/v1/platform/workshops" => [get(platform::platform_workshops) => Platform(ViewPlatform)];
    "/v1/platform/workshops/{id}" => [get(platform::platform_workshop) => Platform(ViewPlatform)];
    "/v1/platform/workshops/{id}/webshop" => [get(webshop::platform_get) => Platform(ViewPlatform)];
    "/v1/platform/workshops/{id}/deletion" => [post(platform::platform_delete_workshop) => Platform(AdministerPlatform)];
    "/v1/platform/workshops/{id}/reconcile" => [post(platform::platform_reconcile_workshop) => Platform(OperateFleet)];
    "/v1/platform/operations" => [get(platform::platform_operations) => Platform(ViewPlatform)];
    "/v1/platform/users" => [get(platform::platform_users) => Platform(ViewPlatform)];
    "/v1/platform/status" => [get(platform::platform_status) => Platform(ViewPlatform)];
    "/v1/platform/releases" => [get(platform::platform_releases) => Platform(ViewPlatform)];
    "/v1/platform/releases/{id}" => [get(platform::platform_release) => Platform(ViewPlatform)];
    "/v1/platform/releases/{id}/preflight" => [post(platform::platform_release_preflight) => Platform(OperateFleet)];
    "/v1/platform/releases/{id}/adopt" => [post(platform::platform_release_adopt) => Platform(OperateFleet)];
    "/v1/platform/releases/{id}/retry-failed-tenants" => [post(platform::platform_release_retry_failed) => Platform(OperateFleet)];
    "/v1/platform/releases/{id}/tenants" => [get(platform::platform_release_tenants) => Platform(ViewPlatform)];
    "/v1/platform/email-deliveries" => [get(platform::platform_email_deliveries) => Platform(ViewPlatform)];
    "/v1/platform/audit-events" => [get(platform::platform_audit_events) => Platform(ViewPlatform)];
    "/v1/platform/roles" => [
        get(platform_roles_list) => Platform(ViewPlatform),
        post(platform_role_grant) => Platform(AdministerPlatform)
    ];
    "/v1/platform/roles/{id}" => [delete(platform_role_revoke) => Platform(AdministerPlatform)];
    "/v1/platform/privacy" => [get(platform_privacy_overview) => Platform(ViewPlatform)];
    "/v1/platform/privacy/retention-runs" => [post(platform_privacy_retention_run) => Platform(RunRetention)];
    "/v1/platform/privacy/requests" => [get(platform_privacy_requests) => Platform(ViewPlatform)];
    "/v1/platform/privacy/requests/{id}/decision" => [post(platform_privacy_request_decision) => Platform(ReviewPrivacy)];
    "/v1/platform/privacy/processor-tasks/{id}/acknowledge" => [post(platform_privacy_processor_task_acknowledge) => Platform(ReviewPrivacy)];
    "/v1/platform/privacy/incidents" => [post(platform_privacy_incident_create) => Platform(RespondSecurity)];
    "/v1/platform/privacy/incidents/{id}/assessment" => [post(platform_privacy_incident_assess) => Platform(AssessIncident)];
    "/v1/platform/privacy/legal-holds" => [post(platform_privacy_legal_hold_create) => Platform(ReviewPrivacy)];
    "/v1/platform/privacy/legal-holds/{id}/release" => [post(platform_privacy_legal_hold_release) => Platform(ReviewPrivacy)];
    "/v1/privacy/requests" => [get(privacy_requests) => Authenticated, post(create_privacy_request) => Authenticated];
    "/v1/privacy/requests/{id}" => [get(privacy_request) => Authenticated];
    "/v1/privacy/requests/{id}/export" => [post(consume_privacy_export) => Authenticated];
    "/v1/identity/link" => [post(link_identity) => VerifiedBearer];
    "/v1/workshops" => [get(workshops::workshops) => Authenticated, post(workshops::create_workshop) => Authenticated];
    "/v1/workshops/{id}" => [get(workshops::workshop) => Workshop(ViewWorkshop)];
    "/v1/workshops/{id}/members" => [get(workshops::members) => Workshop(ViewWorkshop)];
    "/v1/workshops/{id}/invitations" => [get(workshops::invitations) => Workshop(ManageMembers), post(workshops::invite) => Workshop(ManageMembers)];
    "/v1/invitations/{id}/resend" => [post(workshops::resend_invitation) => Authenticated];
    "/v1/invitations/{id}" => [delete(workshops::revoke_invitation) => Authenticated];
    "/v1/invitations/validate" => [post(workshops::validate_invitation) => Public];
    "/v1/invitations/accept" => [post(workshops::accept_invitation) => VerifiedBearer];
    "/v1/workshops/{id}/members/{user_id}" => [
        get(workshops::member) => Workshop(ViewWorkshop),
        patch(workshops::update_member) => Workshop(ManageMembers),
        delete(workshops::remove_member) => Workshop(ManageMembers)
    ];
    "/v1/workshops/{id}/ownership-transfers" => [get(workshops::ownership_transfers) => Workshop(ViewWorkshop), post(workshops::create_ownership_transfer) => Workshop(TransferOwnership)];
    "/v1/ownership-transfers/{id}/accept" => [post(workshops::accept_ownership_transfer) => Authenticated];
    "/v1/workshops/{id}/integrations" => [get(integrations) => Workshop(ViewWorkshop)];
    "/v1/workshops/{id}/modules" => [get(modules) => Workshop(ViewWorkshop)];
    "/v1/workshops/{id}/modules/{module_key}/enable" => [post(enable_module) => Workshop(ManageModules)];
    "/v1/workshops/{id}/webshop" => [get(webshop::get) => Workshop(ViewWorkshop)];
    "/v1/workshops/{id}/webshop/onboarding/refresh" => [post(webshop::refresh) => Workshop(ManageModules)];
    "/v1/workshops/{id}/webshop/onboarding/complete" => [post(webshop::complete) => Workshop(ManageModules)];
    "/v1/workshops/{id}/webshop/deactivate" => [post(webshop::deactivate) => Workshop(ManageModules)];
    "/v1/workshops/{id}/carrier-secrets" => [get(carrier_secrets::list) => Workshop(ViewWorkshop), post(carrier_secrets::upsert) => Workshop(ManageModules)];
    "/v1/workshops/{id}/carrier-targets" => [get(carrier_secrets::targets) => Workshop(ViewWorkshop)];
    "/v1/workshops/{id}/carrier-secrets/{secret_id}" => [delete(carrier_secrets::delete) => Workshop(ManageModules)];
    "/v1/workshops/{id}/domains" => [get(domains::list) => Workshop(ViewWorkshop), post(domains::create) => Workshop(ManageModules)];
    "/v1/workshops/{id}/domains/{domain_id}/verify" => [post(domains::verify) => Workshop(ManageModules)];
    "/v1/workshops/{id}/domains/{domain_id}/canonical" => [post(domains::make_canonical) => Workshop(ManageModules)];
    "/v1/workshops/{id}/domains/{domain_id}" => [delete(domains::disconnect) => Workshop(ManageModules)];
    "/v1/workshops/{id}/email-domains" => [get(email_domains::list) => Workshop(ViewWorkshop), post(email_domains::create) => Workshop(ManageModules)];
    "/v1/workshops/{id}/email-domains/{domain_id}/check" => [post(email_domains::check) => Workshop(ManageModules)];
    "/v1/workshops/{id}/email-domains/{domain_id}" => [delete(email_domains::disconnect) => Workshop(ManageModules)];
    "/v1/workshops/{id}/email/smtp" => [get(smtp::get) => Workshop(ViewWorkshop), post(smtp::configure) => Workshop(ManageModules), delete(smtp::reset) => Workshop(ManageModules)];
    "/v1/workshops/{id}/database" => [get(recovery::database) => Workshop(ViewWorkshop)];
    "/v1/workshops/{id}/database/snapshots" => [post(recovery::create_snapshot) => Workshop(ManageDatabase)];
    "/v1/workshops/{id}/database/backups" => [post(recovery::create_backup) => Workshop(ManageDatabase)];
    "/v1/workshops/{id}/database/backups/{recovery_id}/download" => [post(recovery::download_backup) => Workshop(ManageDatabase)];
    "/v1/workshops/{id}/database/restores" => [post(recovery::restore_database) => Workshop(ManageDatabase)];
    "/v1/workshops/{id}/database/duplicates" => [post(recovery::duplicate_database) => Workshop(ManageDatabase)];
    "/v1/operations/{id}" => [get(operation) => Authenticated];
    "/v1/operations/{id}/retry" => [post(retry_operation) => Authenticated];
}

macro_rules! internal_routes {
    ($($path:literal => [$method:ident($handler:path) => $access:ident];)+) => {
        pub(super) fn build_internal(
            lookup: Arc<dyn InternalRouteAuthorizationLookup>,
        ) -> Router<Arc<AppState>> {
            let mut router = Router::<Arc<AppState>>::new();
            $(
                router = router.route(
                    $path,
                    guarded_internal_method(
                        MethodRouter::<Arc<AppState>>::new().$method($handler),
                        lookup.clone(),
                        InternalRouteAccess::$access,
                    ),
                );
            )+
            router
        }

        #[cfg(test)]
        pub(crate) fn internal_specs() -> Vec<InternalRouteSpec> {
            vec![
                $(InternalRouteSpec {
                    path: $path,
                    method: stringify!($method),
                    handler: stringify!($handler),
                    access: InternalRouteAccess::$access,
                },)+
            ]
        }
    };
}

internal_routes! {
    "/internal/v1/paperless/{workshop_id}/events" => [post(internal::paperless_event) => TenantBridgePath];
    "/internal/v1/workshops/{workshop_id}/inventory-captures" => [post(internal::inventory_capture) => TenantBridgePath];
    "/internal/v1/workshops/{workshop_id}/inventory-product-lookups" => [post(internal::inventory_product_lookup) => TenantBridgePath];
    "/internal/v1/workshops/{workshop_id}/webshop-mails" => [post(internal::webshop_transactional_mail) => TenantBridgePath];
    "/internal/v1/workshops/{workshop_id}/oidc/verify" => [post(internal::verify_odoo_id_token) => TenantBridgePath];
    "/internal/v1/mail-events" => [post(internal::mail_delivery_event) => MailEventGateway];
    "/internal/v1/tenants/{workshop_id}/reconcile" => [post(internal::reconcile_tenant) => InternalService];
    "/internal/v1/entitlements/{workshop_id}/ack" => [post(internal::ack_entitlement) => InternalService];
    "/internal/v1/carrier-secrets/resolve" => [post(carrier_secrets::resolve) => TenantBridgeBody];
    "/internal/v1/application-releases" => [post(platform::publish_release) => ReleasePublisher];
    "/internal/metrics" => [get(metrics) => MetricsReader];
    "/internal/metrics/live" => [get(live_metrics) => MetricsReader];
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use axum::Extension;
    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};
    use tower::ServiceExt as _;

    use super::*;

    #[derive(Clone)]
    struct FakeLookup {
        principal: Principal,
        authority: Option<WorkshopAuthority>,
        platform_roles: Vec<String>,
        platform_role_lookups: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl RouteAuthorizationLookup for FakeLookup {
        async fn verify_bearer(&self, headers: &HeaderMap) -> ApiResult<VerifiedToken> {
            if headers.contains_key(header::AUTHORIZATION) {
                Ok(VerifiedToken {
                    issuer: self.principal.issuer.clone(),
                    subject: self.principal.subject.clone(),
                    email: self.principal.email.clone(),
                    recent_strong_authentication: false,
                })
            } else {
                Err(ApiError::Unauthenticated)
            }
        }

        async fn principal(&self, headers: &HeaderMap) -> ApiResult<Principal> {
            if headers.contains_key(header::AUTHORIZATION) {
                Ok(self.principal.clone())
            } else {
                Err(ApiError::Unauthenticated)
            }
        }

        async fn membership(
            &self,
            principal_id: Uuid,
            workshop_id: Uuid,
        ) -> ApiResult<WorkshopAuthority> {
            self.authority
                .clone()
                .filter(|authority| {
                    principal_id == self.principal.user_id && authority.workshop_id == workshop_id
                })
                .ok_or(ApiError::NotFound)
        }

        async fn platform_roles(&self, _principal: &Principal) -> ApiResult<Vec<String>> {
            self.platform_role_lookups.fetch_add(1, Ordering::SeqCst);
            Ok(self.platform_roles.clone())
        }
    }

    struct ProbeState {
        hits: AtomicUsize,
        scope: Mutex<Option<WorkshopScope>>,
    }

    #[derive(Clone)]
    struct FakeInternalLookup {
        expected_access: InternalRouteAccess,
        expected_workshop: Option<Uuid>,
        calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl InternalRouteAuthorizationLookup for FakeInternalLookup {
        async fn authorize_internal_route(
            &self,
            access: InternalRouteAccess,
            workshop_id: Option<Uuid>,
            headers: &HeaderMap,
        ) -> ApiResult<()> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if access != self.expected_access {
                return Err(ApiError::Forbidden);
            }
            if headers.get(header::AUTHORIZATION)
                != Some(&HeaderValue::from_static("Bearer internal-test"))
            {
                return Err(ApiError::Unauthenticated);
            }
            if workshop_id != self.expected_workshop {
                return Err(ApiError::Unauthenticated);
            }
            Ok(())
        }
    }

    async fn internal_probe(State(hits): State<Arc<AtomicUsize>>) -> StatusCode {
        hits.fetch_add(1, Ordering::SeqCst);
        StatusCode::NO_CONTENT
    }

    async fn internal_probe_request(
        access: InternalRouteAccess,
        expected_workshop: Option<Uuid>,
        requested_workshop: Option<Uuid>,
        authenticated: bool,
    ) -> (StatusCode, Arc<AtomicUsize>, Arc<AtomicUsize>) {
        let authorization_calls = Arc::new(AtomicUsize::new(0));
        let lookup: Arc<dyn InternalRouteAuthorizationLookup> = Arc::new(FakeInternalLookup {
            expected_access: access,
            expected_workshop,
            calls: authorization_calls.clone(),
        });
        let handler_hits = Arc::new(AtomicUsize::new(0));
        let method = guarded_internal_method(
            MethodRouter::<Arc<AtomicUsize>>::new().get(internal_probe),
            lookup,
            access,
        );
        let (route, uri) = if let Some(workshop_id) = requested_workshop {
            ("/{workshop_id}", format!("/{workshop_id}"))
        } else {
            ("/", "/".to_owned())
        };
        let app = Router::new()
            .route(route, method)
            .with_state(handler_hits.clone());
        let mut request = Request::builder().uri(uri);
        if authenticated {
            request = request.header(header::AUTHORIZATION, "Bearer internal-test");
        }
        let response = app
            .oneshot(request.body(Body::empty()).expect("internal probe request"))
            .await
            .expect("internal probe response");
        (response.status(), handler_hits, authorization_calls)
    }

    async fn workshop_probe(
        State(state): State<Arc<ProbeState>>,
        Extension(scope): Extension<WorkshopScope>,
    ) -> StatusCode {
        state.hits.fetch_add(1, Ordering::SeqCst);
        *state.scope.lock().expect("probe scope lock") = Some(scope);
        StatusCode::NO_CONTENT
    }

    fn fake_lookup(
        workshop_id: Uuid,
        role: Option<WorkshopRole>,
    ) -> (Arc<dyn RouteAuthorizationLookup>, Principal) {
        let principal = Principal {
            user_id: Uuid::new_v4(),
            issuer: "https://auth.example.test".into(),
            subject: "test-subject".into(),
            email: "member@example.test".into(),
            recent_strong_authentication: false,
        };
        let authority = role.map(|role| WorkshopAuthority {
            workshop_id,
            role,
            epoch: 7,
        });
        (
            Arc::new(FakeLookup {
                principal: principal.clone(),
                authority,
                platform_roles: Vec::new(),
                platform_role_lookups: Arc::new(AtomicUsize::new(0)),
            }),
            principal,
        )
    }

    async fn probe_request(
        workshop_path: &str,
        permission: WorkshopPermission,
        role: Option<WorkshopRole>,
        authenticated: bool,
    ) -> (StatusCode, Arc<ProbeState>, Principal) {
        let expected_workshop = workshop_path.parse().unwrap_or_else(|_| Uuid::nil());
        probe_request_with_authority(
            workshop_path,
            expected_workshop,
            permission,
            role,
            authenticated,
        )
        .await
    }

    async fn probe_request_with_authority(
        workshop_path: &str,
        authority_workshop: Uuid,
        permission: WorkshopPermission,
        role: Option<WorkshopRole>,
        authenticated: bool,
    ) -> (StatusCode, Arc<ProbeState>, Principal) {
        let (lookup, principal) = fake_lookup(authority_workshop, role);
        let state = Arc::new(ProbeState {
            hits: AtomicUsize::new(0),
            scope: Mutex::new(None),
        });
        let method = guarded_method(
            MethodRouter::<Arc<ProbeState>>::new().get(workshop_probe),
            lookup,
            RouteAccess::Workshop(permission),
        );
        let app = Router::new()
            .route("/{id}", method)
            .with_state(state.clone());
        let mut request = Request::builder().uri(format!("/{workshop_path}"));
        if authenticated {
            request = request.header(header::AUTHORIZATION, "Bearer test");
        }
        let response = app
            .oneshot(request.body(Body::empty()).expect("probe request"))
            .await
            .expect("probe response");
        (response.status(), state, principal)
    }

    #[test]
    fn workshop_paths_declare_method_specific_workshop_access() {
        let routes = specs()
            .into_iter()
            .filter(|route| route.path.starts_with("/v1/workshops/{id}"))
            .collect::<Vec<_>>();
        assert!(!routes.is_empty());
        for route in routes {
            assert!(
                matches!(route.access, RouteAccess::Workshop(_)),
                "{} {} must declare workshop access",
                route.method,
                route.path
            );
            assert!(
                route.path.split('/').any(|segment| segment == "{id}"),
                "{} {} must expose the workshop id to middleware",
                route.method,
                route.path
            );
        }
    }

    #[test]
    fn platform_paths_declare_method_specific_platform_access() {
        let routes = specs()
            .into_iter()
            .filter(|route| route.path.starts_with("/v1/platform/"))
            .collect::<Vec<_>>();
        assert!(!routes.is_empty());
        for route in routes {
            assert!(
                matches!(route.access, RouteAccess::Platform(_)),
                "{} {} must declare platform access",
                route.method,
                route.path
            );
        }
    }

    #[test]
    fn bootstrap_identity_routes_verify_bearers_before_local_identity_exists() {
        for path in ["/v1/identity/link", "/v1/invitations/accept"] {
            let route = specs()
                .into_iter()
                .find(|route| route.path == path)
                .unwrap_or_else(|| panic!("missing identity bootstrap route {path}"));
            assert_eq!(route.access, RouteAccess::VerifiedBearer);
        }
    }

    #[test]
    fn platform_permission_role_matrix_is_explicit() {
        let roles = |values: &[&str]| {
            values
                .iter()
                .map(|value| (*value).to_owned())
                .collect::<Vec<_>>()
        };
        assert!(PlatformPermission::ViewPlatform.allows(&roles(&["audit_reader"])));
        assert!(!PlatformPermission::ViewPlatform.allows(&[]));
        assert!(PlatformPermission::AdministerPlatform.allows(&roles(&["technical_admin"])));
        assert!(!PlatformPermission::AdministerPlatform.allows(&roles(&["release_operator"])));
        assert!(PlatformPermission::OperateFleet.allows(&roles(&["release_operator"])));
        assert!(PlatformPermission::RunRetention.allows(&roles(&["privacy_reviewer"])));
        assert!(PlatformPermission::AssessIncident.allows(&roles(&["security_responder"])));
        assert!(PlatformPermission::AssessIncident.allows(&roles(&["privacy_reviewer"])));
    }

    #[test]
    fn route_registry_has_one_policy_per_method_and_builds_without_overlap() {
        let mut operations = HashSet::new();
        for route in specs() {
            assert!(
                operations.insert((route.method, route.path)),
                "duplicate policy for {} {}",
                route.method,
                route.path
            );
        }
        let workshop = Uuid::new_v4();
        let (lookup, _) = fake_lookup(workshop, Some(WorkshopRole::Owner));
        let _router = build(lookup);
    }

    #[test]
    fn checked_in_security_inventory_matches_the_route_registries() {
        let mut actual = String::from("family\tmethod\tpath\taccess\thandler\n");
        for route in specs() {
            actual.push_str(&format!(
                "public\t{}\t{}\t{:?}\t{}\n",
                route.method.to_ascii_uppercase(),
                route.path,
                route.access,
                route.handler
            ));
        }
        for route in internal_specs() {
            actual.push_str(&format!(
                "internal\t{}\t{}\t{:?}\t{}\n",
                route.method.to_ascii_uppercase(),
                route.path,
                route.access,
                route.handler
            ));
        }
        assert_eq!(
            actual,
            include_str!("../../docs/control-plane-route-security-inventory.tsv"),
            "regenerate the checked-in route security inventory"
        );
    }

    #[test]
    fn internal_route_registry_is_complete_explicit_and_builds_without_overlap() {
        let expected = HashSet::from([
            ("post", "/internal/v1/paperless/{workshop_id}/events"),
            (
                "post",
                "/internal/v1/workshops/{workshop_id}/inventory-captures",
            ),
            (
                "post",
                "/internal/v1/workshops/{workshop_id}/inventory-product-lookups",
            ),
            ("post", "/internal/v1/workshops/{workshop_id}/webshop-mails"),
            ("post", "/internal/v1/workshops/{workshop_id}/oidc/verify"),
            ("post", "/internal/v1/mail-events"),
            ("post", "/internal/v1/tenants/{workshop_id}/reconcile"),
            ("post", "/internal/v1/entitlements/{workshop_id}/ack"),
            ("post", "/internal/v1/carrier-secrets/resolve"),
            ("post", "/internal/v1/application-releases"),
            ("get", "/internal/metrics"),
            ("get", "/internal/metrics/live"),
        ]);
        let specs = internal_specs();
        let actual = specs
            .iter()
            .map(|route| (route.method, route.path))
            .collect::<HashSet<_>>();
        assert_eq!(actual, expected);
        assert_eq!(specs.len(), actual.len(), "duplicate internal route policy");

        let calls = Arc::new(AtomicUsize::new(0));
        let lookup: Arc<dyn InternalRouteAuthorizationLookup> = Arc::new(FakeInternalLookup {
            expected_access: InternalRouteAccess::InternalService,
            expected_workshop: None,
            calls,
        });
        let _router = build_internal(lookup);
    }

    #[test]
    fn internal_route_credential_domains_and_body_exception_are_explicit() {
        let specs = internal_specs();
        for route in &specs {
            assert!(route.path.starts_with("/internal/"));
            if route.access == InternalRouteAccess::TenantBridgePath {
                assert!(
                    route.path.split('/').any(|part| part == "{workshop_id}"),
                    "{} {} must expose workshop_id to its guard",
                    route.method,
                    route.path
                );
            }
        }
        let body_scoped = specs
            .iter()
            .filter(|route| route.access == InternalRouteAccess::TenantBridgeBody)
            .collect::<Vec<_>>();
        assert_eq!(body_scoped.len(), 1);
        assert_eq!(body_scoped[0].path, "/internal/v1/carrier-secrets/resolve");
    }

    #[tokio::test]
    async fn every_guardable_internal_credential_domain_rejects_before_the_handler() {
        let workshop = Uuid::new_v4();
        let accesses = internal_specs()
            .into_iter()
            .filter_map(|route| {
                (route.access != InternalRouteAccess::TenantBridgeBody).then_some(route.access)
            })
            .collect::<HashSet<_>>();
        assert_eq!(accesses.len(), 5);

        for access in accesses {
            let scoped = (access == InternalRouteAccess::TenantBridgePath).then_some(workshop);
            let (status, hits, calls) = internal_probe_request(access, scoped, scoped, false).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{access:?}");
            assert_eq!(hits.load(Ordering::SeqCst), 0, "{access:?}");
            assert_eq!(calls.load(Ordering::SeqCst), 1, "{access:?}");

            let (status, hits, calls) = internal_probe_request(access, scoped, scoped, true).await;
            assert_eq!(status, StatusCode::NO_CONTENT, "{access:?}");
            assert_eq!(hits.load(Ordering::SeqCst), 1, "{access:?}");
            assert_eq!(calls.load(Ordering::SeqCst), 1, "{access:?}");
        }
    }

    #[tokio::test]
    async fn tenant_bridge_guard_rejects_a_token_bound_to_another_workshop() {
        let expected = Uuid::new_v4();
        let requested = Uuid::new_v4();
        let (status, hits, calls) = internal_probe_request(
            InternalRouteAccess::TenantBridgePath,
            Some(expected),
            Some(requested),
            true,
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(hits.load(Ordering::SeqCst), 0);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn workshop_route_permission_declarations_have_an_executable_role_matrix() {
        let workshop = Uuid::new_v4();
        let routes = specs()
            .into_iter()
            .filter_map(|route| match route.access {
                RouteAccess::Workshop(permission) => Some((route, permission)),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert!(!routes.is_empty());

        for (route, permission) in routes {
            let (minimum, insufficient) = match permission {
                WorkshopPermission::ViewWorkshop => (WorkshopRole::Viewer, None),
                WorkshopPermission::ManageMembers | WorkshopPermission::ManageModules => {
                    (WorkshopRole::StudioManager, Some(WorkshopRole::Viewer))
                }
                WorkshopPermission::ManageDatabase | WorkshopPermission::TransferOwnership => {
                    (WorkshopRole::Owner, Some(WorkshopRole::StudioManager))
                }
            };

            let (status, state, _) =
                probe_request(&workshop.to_string(), permission, Some(minimum), false).await;
            assert_eq!(
                status,
                StatusCode::UNAUTHORIZED,
                "{} {}",
                route.method,
                route.path
            );
            assert_eq!(state.hits.load(Ordering::SeqCst), 0);

            let (status, state, _) =
                probe_request(&workshop.to_string(), permission, None, true).await;
            assert_eq!(
                status,
                StatusCode::NOT_FOUND,
                "{} {}",
                route.method,
                route.path
            );
            assert_eq!(state.hits.load(Ordering::SeqCst), 0);

            let (status, state, _) = probe_request_with_authority(
                &workshop.to_string(),
                Uuid::new_v4(),
                permission,
                Some(minimum),
                true,
            )
            .await;
            assert_eq!(
                status,
                StatusCode::NOT_FOUND,
                "{} {} accepted authority for another workshop",
                route.method,
                route.path
            );
            assert_eq!(state.hits.load(Ordering::SeqCst), 0);

            if let Some(insufficient) = insufficient {
                let (status, state, _) =
                    probe_request(&workshop.to_string(), permission, Some(insufficient), true)
                        .await;
                assert_eq!(
                    status,
                    StatusCode::FORBIDDEN,
                    "{} {}",
                    route.method,
                    route.path
                );
                assert_eq!(state.hits.load(Ordering::SeqCst), 0);
            }

            let (status, state, _) =
                probe_request(&workshop.to_string(), permission, Some(minimum), true).await;
            assert_eq!(
                status,
                StatusCode::NO_CONTENT,
                "{} {}",
                route.method,
                route.path
            );
            assert_eq!(state.hits.load(Ordering::SeqCst), 1);
        }
    }

    fn concrete_route_path(path: &str, workshop: Uuid) -> String {
        let child = Uuid::new_v4().to_string();
        path.replace("{id}", &workshop.to_string())
            .replace("{user_id}", &child)
            .replace("{secret_id}", &child)
            .replace("{domain_id}", &child)
            .replace("{recovery_id}", &child)
            .replace("{module_key}", "webshop")
    }

    async fn actual_route_status(
        route: PublicRouteSpec,
        lookup: Arc<dyn RouteAuthorizationLookup>,
        state: Arc<AppState>,
        workshop: Uuid,
        authenticated: bool,
    ) -> StatusCode {
        let app = build(lookup).with_state(state);
        let method = Method::from_bytes(route.method.to_ascii_uppercase().as_bytes())
            .expect("registry method");
        let mut request = Request::builder()
            .method(method)
            .uri(concrete_route_path(route.path, workshop));
        if authenticated {
            request = request.header(header::AUTHORIZATION, "Bearer route-matrix-test");
        }
        app.oneshot(request.body(Body::empty()).expect("route matrix request"))
            .await
            .expect("route matrix response")
            .status()
    }

    #[tokio::test(flavor = "current_thread")]
    #[ignore = "requires a disposable CONTROL_TEST_DATABASE_URL"]
    async fn actual_workshop_routes_reject_before_handler_database_or_external_effects() {
        let database_url = std::env::var("CONTROL_TEST_DATABASE_URL")
            .expect("CONTROL_TEST_DATABASE_URL for handler-level route matrix");
        let state = Arc::new(
            AppState::for_route_test(&database_url)
                .await
                .expect("route matrix application state"),
        );
        let operation_count_before: i64 =
            sqlx::query_scalar("select count(*) from control.operations")
                .fetch_one(state.store.pool())
                .await
                .expect("operation count before denied requests");
        let workshop = Uuid::new_v4();
        let routes = specs()
            .into_iter()
            .filter_map(|route| match route.access {
                RouteAccess::Workshop(permission) => Some((route, permission)),
                _ => None,
            })
            .collect::<Vec<_>>();

        for (route, permission) in routes {
            let minimum = match permission {
                WorkshopPermission::ViewWorkshop => WorkshopRole::Viewer,
                WorkshopPermission::ManageMembers | WorkshopPermission::ManageModules => {
                    WorkshopRole::StudioManager
                }
                WorkshopPermission::ManageDatabase | WorkshopPermission::TransferOwnership => {
                    WorkshopRole::Owner
                }
            };
            let (authorized, _) = fake_lookup(workshop, Some(minimum));
            assert_eq!(
                actual_route_status(route, authorized, state.clone(), workshop, false).await,
                StatusCode::UNAUTHORIZED,
                "{} {} entered its real handler without authentication",
                route.method,
                route.path
            );

            let (non_member, _) = fake_lookup(workshop, None);
            assert_eq!(
                actual_route_status(route, non_member, state.clone(), workshop, true).await,
                StatusCode::NOT_FOUND,
                "{} {} entered its real handler for a non-member",
                route.method,
                route.path
            );

            let (other_workshop, _) = fake_lookup(Uuid::new_v4(), Some(minimum));
            assert_eq!(
                actual_route_status(route, other_workshop, state.clone(), workshop, true).await,
                StatusCode::NOT_FOUND,
                "{} {} accepted authority for another workshop",
                route.method,
                route.path
            );

            let insufficient = match permission {
                WorkshopPermission::ViewWorkshop => None,
                WorkshopPermission::ManageMembers | WorkshopPermission::ManageModules => {
                    Some(WorkshopRole::Viewer)
                }
                WorkshopPermission::ManageDatabase | WorkshopPermission::TransferOwnership => {
                    Some(WorkshopRole::StudioManager)
                }
            };
            if let Some(insufficient) = insufficient {
                let (lookup, _) = fake_lookup(workshop, Some(insufficient));
                assert_eq!(
                    actual_route_status(route, lookup, state.clone(), workshop, true).await,
                    StatusCode::FORBIDDEN,
                    "{} {} entered its real handler with insufficient authority",
                    route.method,
                    route.path
                );
            }
        }

        let other_workshop = Uuid::new_v4();
        let actor = Uuid::new_v4();
        let other_member = Uuid::new_v4();
        let fixture_owner = Uuid::new_v4();
        for (user, label) in [
            (actor, "actor"),
            (other_member, "other-member"),
            (fixture_owner, "owner"),
        ] {
            sqlx::query("insert into control.users(id,email) values($1,$2)")
                .bind(user)
                .bind(format!("{label}-{}@example.test", user.simple()))
                .execute(state.store.pool())
                .await
                .expect("route matrix user fixture");
        }
        for (id, label) in [(workshop, "authorized"), (other_workshop, "other")] {
            sqlx::query("insert into control.workshops(id,slug,display_name,time_zone) values($1,$2,$3,'Europe/Paris')")
                .bind(id)
                .bind(format!("route-matrix-{}", id.simple()))
                .bind(label)
                .execute(state.store.pool())
                .await
                .expect("route matrix workshop fixture");
        }
        for id in [workshop, other_workshop] {
            sqlx::query(
                "insert into control.memberships(workshop_id,user_id,role) values($1,$2,'owner')",
            )
            .bind(id)
            .bind(fixture_owner)
            .execute(state.store.pool())
            .await
            .expect("route matrix owner fixture");
        }
        sqlx::query("insert into control.memberships(workshop_id,user_id,role,authority_epoch) values($1,$2,'studio_manager',7)")
            .bind(workshop)
            .bind(actor)
            .execute(state.store.pool())
            .await
            .expect("authorized membership fixture");
        sqlx::query("insert into control.memberships(workshop_id,user_id,role) values($1,$2,'studio_manager')")
            .bind(other_workshop)
            .bind(other_member)
            .execute(state.store.pool())
            .await
            .expect("other-workshop child fixture");
        let command_count_before: i64 = sqlx::query_scalar("select count(*) from control.commands")
            .fetch_one(state.store.pool())
            .await
            .expect("command count before cross-workshop requests");
        let (lookup, _) = fake_lookup(workshop, Some(WorkshopRole::StudioManager));
        let member_path = format!("/v1/workshops/{workshop}/members/{other_member}");
        let response = build(lookup.clone())
            .with_state(state.clone())
            .oneshot(
                Request::builder()
                    .uri(&member_path)
                    .header(header::AUTHORIZATION, "Bearer route-matrix-test")
                    .body(Body::empty())
                    .expect("cross-workshop member read"),
            )
            .await
            .expect("cross-workshop member read response");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let response = build(lookup)
            .with_state(state.clone())
            .oneshot(
                Request::builder()
                    .method(Method::PATCH)
                    .uri(&member_path)
                    .header(header::AUTHORIZATION, "Bearer route-matrix-test")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("idempotency-key", Uuid::new_v4().to_string())
                    .header(
                        header::IF_MATCH,
                        format!("\"member-{workshop}-{other_member}-v1\""),
                    )
                    .body(Body::from(r#"{"role":"viewer"}"#))
                    .expect("cross-workshop member mutation"),
            )
            .await
            .expect("cross-workshop member mutation response");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let other_role: String = sqlx::query_scalar(
            "select role from control.memberships where workshop_id=$1 and user_id=$2",
        )
        .bind(other_workshop)
        .bind(other_member)
        .fetch_one(state.store.pool())
        .await
        .expect("other-workshop membership after rejected mutation");
        assert_eq!(other_role, "studio_manager");
        let command_count_after: i64 = sqlx::query_scalar("select count(*) from control.commands")
            .fetch_one(state.store.pool())
            .await
            .expect("command count after cross-workshop requests");
        assert_eq!(command_count_after, command_count_before);

        let operation_count_after: i64 =
            sqlx::query_scalar("select count(*) from control.operations")
                .fetch_one(state.store.pool())
                .await
                .expect("operation count after denied requests");
        assert_eq!(
            operation_count_after, operation_count_before,
            "rejected production routes admitted a durable operation"
        );
    }

    #[tokio::test]
    async fn workshop_guard_rejects_before_the_handler_and_inserts_validated_scope() {
        let workshop = Uuid::new_v4();
        let (status, state, _) = probe_request(
            &workshop.to_string(),
            WorkshopPermission::ViewWorkshop,
            Some(WorkshopRole::Viewer),
            false,
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(state.hits.load(Ordering::SeqCst), 0);

        let (status, state, _) = probe_request(
            &workshop.to_string(),
            WorkshopPermission::ViewWorkshop,
            None,
            true,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(state.hits.load(Ordering::SeqCst), 0);

        let (status, state, _) = probe_request(
            &workshop.to_string(),
            WorkshopPermission::ManageMembers,
            Some(WorkshopRole::Viewer),
            true,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(state.hits.load(Ordering::SeqCst), 0);

        let (status, state, principal) = probe_request(
            &workshop.to_string(),
            WorkshopPermission::ManageMembers,
            Some(WorkshopRole::StudioManager),
            true,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert_eq!(state.hits.load(Ordering::SeqCst), 1);
        let scope = state
            .scope
            .lock()
            .expect("probe scope lock")
            .clone()
            .expect("validated workshop scope");
        assert_eq!(scope.workshop_id, workshop);
        assert_eq!(scope.principal_id, principal.user_id);
        assert_eq!(scope.role, WorkshopRole::StudioManager);
        assert_eq!(scope.authority_epoch, 7);
        assert_eq!(scope.permission, WorkshopPermission::ManageMembers);
    }

    #[tokio::test]
    async fn workshop_guard_rejects_invalid_ids_before_the_handler() {
        let (status, state, _) = probe_request(
            "not-a-uuid",
            WorkshopPermission::ViewWorkshop,
            Some(WorkshopRole::Owner),
            true,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(state.hits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn workshop_guard_rejects_membership_from_another_workshop() {
        let authorized_workshop = Uuid::new_v4();
        let requested_workshop = Uuid::new_v4();
        let (lookup, _) = fake_lookup(authorized_workshop, Some(WorkshopRole::Owner));
        let state = Arc::new(ProbeState {
            hits: AtomicUsize::new(0),
            scope: Mutex::new(None),
        });
        let method = guarded_method(
            MethodRouter::<Arc<ProbeState>>::new().get(workshop_probe),
            lookup,
            RouteAccess::Workshop(WorkshopPermission::ViewWorkshop),
        );
        let app = Router::new()
            .route("/{id}", method)
            .with_state(state.clone());
        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/{requested_workshop}"))
                    .header(header::AUTHORIZATION, "Bearer test")
                    .body(Body::empty())
                    .expect("probe request"),
            )
            .await
            .expect("probe response");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(state.hits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn platform_guard_authorizes_once_and_inserts_platform_scope() {
        struct PlatformProbeState {
            hits: AtomicUsize,
            principal_id: Mutex<Option<Uuid>>,
            permission: Mutex<Option<PlatformPermission>>,
        }

        async fn platform_probe(
            State(state): State<Arc<PlatformProbeState>>,
            Extension(scope): Extension<PlatformScope>,
        ) -> StatusCode {
            state.hits.fetch_add(1, Ordering::SeqCst);
            *state.principal_id.lock().expect("probe principal lock") =
                Some(scope.principal().user_id);
            *state.permission.lock().expect("probe permission lock") = Some(scope.permission());
            StatusCode::NO_CONTENT
        }

        let principal = Principal {
            user_id: Uuid::new_v4(),
            issuer: "https://auth.example.test".into(),
            subject: "platform-subject".into(),
            email: "operator@example.test".into(),
            recent_strong_authentication: true,
        };
        let role_lookups = Arc::new(AtomicUsize::new(0));
        let lookup: Arc<dyn RouteAuthorizationLookup> = Arc::new(FakeLookup {
            principal: principal.clone(),
            authority: None,
            platform_roles: vec!["release_operator".into()],
            platform_role_lookups: role_lookups.clone(),
        });
        let state = Arc::new(PlatformProbeState {
            hits: AtomicUsize::new(0),
            principal_id: Mutex::new(None),
            permission: Mutex::new(None),
        });
        let denied_method = guarded_method(
            MethodRouter::<Arc<PlatformProbeState>>::new().get(platform_probe),
            lookup.clone(),
            RouteAccess::Platform(PlatformPermission::AdministerPlatform),
        );
        let denied_app = Router::new()
            .route("/", denied_method)
            .with_state(state.clone());
        let denied = denied_app
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(header::AUTHORIZATION, "Bearer test")
                    .body(Body::empty())
                    .expect("probe request"),
            )
            .await
            .expect("probe response");
        assert_eq!(denied.status(), StatusCode::FORBIDDEN);
        assert_eq!(state.hits.load(Ordering::SeqCst), 0);
        assert_eq!(role_lookups.load(Ordering::SeqCst), 1);

        let method = guarded_method(
            MethodRouter::<Arc<PlatformProbeState>>::new().get(platform_probe),
            lookup,
            RouteAccess::Platform(PlatformPermission::OperateFleet),
        );
        let app = Router::new().route("/", method).with_state(state.clone());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(header::AUTHORIZATION, "Bearer test")
                    .body(Body::empty())
                    .expect("probe request"),
            )
            .await
            .expect("probe response");

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(state.hits.load(Ordering::SeqCst), 1);
        assert_eq!(role_lookups.load(Ordering::SeqCst), 2);
        assert_eq!(
            *state.principal_id.lock().expect("probe principal lock"),
            Some(principal.user_id)
        );
        assert_eq!(
            *state.permission.lock().expect("probe permission lock"),
            Some(PlatformPermission::OperateFleet)
        );
    }
}
