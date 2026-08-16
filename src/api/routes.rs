use super::*;
use axum::routing::MethodRouter;

#[derive(Clone, Copy)]
pub(crate) struct PublicRouteSpec {
    pub path: &'static str,
    pub method: &'static str,
    pub secured: bool,
}

macro_rules! public_routes {
    ($($path:literal, $secured:literal => [$($method:ident($handler:path)),+ $(,)?];)+) => {
        pub(super) fn build() -> (Router<Arc<AppState>>, Vec<PublicRouteSpec>) {
            let mut router = Router::<Arc<AppState>>::new();
            let mut specs = Vec::new();
            $(
                let methods = MethodRouter::<Arc<AppState>>::new()
                    $(.$method($handler))+;
                $(specs.push(PublicRouteSpec {
                    path: $path,
                    method: stringify!($method),
                    secured: $secured,
                });)+
                router = router.route($path, methods);
            )+
            (router, specs)
        }
    };
}

public_routes! {
    "/v1/version", false => [get(version)];
    "/v1/me", true => [get(me)];
    "/v1/platform/overview", true => [get(platform::platform_overview)];
    "/v1/platform/workshops", true => [get(platform::platform_workshops)];
    "/v1/platform/workshops/{id}", true => [get(platform::platform_workshop)];
    "/v1/platform/workshops/{id}/deletion", true => [post(platform::platform_delete_workshop)];
    "/v1/platform/workshops/{id}/reconcile", true => [post(platform::platform_reconcile_workshop)];
    "/v1/platform/operations", true => [get(platform::platform_operations)];
    "/v1/platform/users", true => [get(platform::platform_users)];
    "/v1/platform/status", true => [get(platform::platform_status)];
    "/v1/platform/releases", true => [get(platform::platform_releases)];
    "/v1/platform/releases/{id}", true => [get(platform::platform_release)];
    "/v1/platform/releases/{id}/preflight", true => [post(platform::platform_release_preflight)];
    "/v1/platform/releases/{id}/adopt", true => [post(platform::platform_release_adopt)];
    "/v1/platform/releases/{id}/retry-failed-tenants", true => [post(platform::platform_release_retry_failed)];
    "/v1/platform/releases/{id}/tenants", true => [get(platform::platform_release_tenants)];
    "/v1/platform/email-deliveries", true => [get(platform::platform_email_deliveries)];
    "/v1/platform/audit-events", true => [get(platform::platform_audit_events)];
    "/v1/platform/roles", true => [get(platform_roles_list), post(platform_role_grant)];
    "/v1/platform/roles/{id}", true => [delete(platform_role_revoke)];
    "/v1/platform/privacy", true => [get(platform_privacy_overview)];
    "/v1/platform/privacy/retention-runs", true => [post(platform_privacy_retention_run)];
    "/v1/platform/privacy/requests", true => [get(platform_privacy_requests)];
    "/v1/platform/privacy/requests/{id}/decision", true => [post(platform_privacy_request_decision)];
    "/v1/platform/privacy/processor-tasks/{id}/acknowledge", true => [post(platform_privacy_processor_task_acknowledge)];
    "/v1/platform/privacy/incidents", true => [post(platform_privacy_incident_create)];
    "/v1/platform/privacy/incidents/{id}/assessment", true => [post(platform_privacy_incident_assess)];
    "/v1/platform/privacy/legal-holds", true => [post(platform_privacy_legal_hold_create)];
    "/v1/platform/privacy/legal-holds/{id}/release", true => [post(platform_privacy_legal_hold_release)];
    "/v1/privacy/requests", true => [get(privacy_requests), post(create_privacy_request)];
    "/v1/privacy/requests/{id}", true => [get(privacy_request)];
    "/v1/privacy/requests/{id}/export", true => [post(consume_privacy_export)];
    "/v1/identity/link", true => [post(link_identity)];
    "/v1/workshops", true => [get(workshops::workshops), post(workshops::create_workshop)];
    "/v1/workshops/{id}", true => [get(workshops::workshop)];
    "/v1/workshops/{id}/members", true => [get(workshops::members)];
    "/v1/workshops/{id}/invitations", true => [get(workshops::invitations), post(workshops::invite)];
    "/v1/invitations/{id}/resend", true => [post(workshops::resend_invitation)];
    "/v1/invitations/{id}", true => [delete(workshops::revoke_invitation)];
    "/v1/invitations/validate", false => [post(workshops::validate_invitation)];
    "/v1/invitations/accept", true => [post(workshops::accept_invitation)];
    "/v1/workshops/{id}/members/{user_id}", true => [get(workshops::member), patch(workshops::update_member), delete(workshops::remove_member)];
    "/v1/workshops/{id}/ownership-transfers", true => [get(workshops::ownership_transfers), post(workshops::create_ownership_transfer)];
    "/v1/ownership-transfers/{id}/accept", true => [post(workshops::accept_ownership_transfer)];
    "/v1/workshops/{id}/integrations", true => [get(integrations)];
    "/v1/workshops/{id}/modules", true => [get(modules)];
    "/v1/workshops/{id}/modules/{module_key}/enable", true => [post(enable_module)];
    "/v1/workshops/{id}/carrier-secrets", true => [get(carrier_secrets::list), post(carrier_secrets::upsert)];
    "/v1/workshops/{id}/carrier-targets", true => [get(carrier_secrets::targets)];
    "/v1/workshops/{id}/carrier-secrets/{secret_id}", true => [delete(carrier_secrets::delete)];
    "/v1/workshops/{id}/database", true => [get(recovery::database)];
    "/v1/workshops/{id}/database/snapshots", true => [post(recovery::create_snapshot)];
    "/v1/workshops/{id}/database/backups", true => [post(recovery::create_backup)];
    "/v1/workshops/{id}/database/backups/{recovery_id}/download", true => [post(recovery::download_backup)];
    "/v1/workshops/{id}/database/restores", true => [post(recovery::restore_database)];
    "/v1/workshops/{id}/database/duplicates", true => [post(recovery::duplicate_database)];
    "/v1/operations/{id}", true => [get(operation)];
    "/v1/operations/{id}/retry", true => [post(retry_operation)];
}

pub(crate) fn specs() -> Vec<PublicRouteSpec> {
    build().1
}
