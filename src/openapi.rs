use serde_json::{Map, Value, json};
use utoipa::OpenApi;

use crate::api::carrier_secrets::{
    CarrierCredentials, CarrierSecretBody, CarrierSecretDeleteResponse, CarrierSecretResponse,
    CarrierTargetResponse,
};
use crate::api::contracts::{
    ApplicationReleaseDetailResponse, ApplicationReleaseResponse, AttentionOperationResponse,
    AuditEventResponse, BackupStatusResponse, CommandInProgressResponse, CountDisabledResponse,
    CountHealthResponse, CountOperationsResponse, DataSubjectExportStatusResponse,
    DatabaseResponse, DuplicateCommandResponse, DuplicateDatabaseResponse, EmailDeliveryResponse,
    EntitlementResponse, ErasureRestoreReplayResponse, IdentityLinkResponse, IntegrationResponse,
    InvitationAcceptanceResponse, InvitationCreateResponse, InvitationResendResponse,
    InvitationResponse, InvitationValidationResponse, LegalHoldCreateResponse, LegalHoldResponse,
    LegalHoldScopeResponse, MeResponse, MemberDetailResponse, MemberResponse,
    MemberUpdateCommandResponse, ModuleEnableCommandResponse, ModuleResponse,
    OperationCommandResponse, OperationResponse, OperationRetryResponse,
    OwnershipTransferAcceptResponse, OwnershipTransferCreateResponse, OwnershipTransferResponse,
    PlatformMemberResponse, PlatformOperationResponse, PlatformOverviewResponse,
    PlatformReleaseIdentityResponse, PlatformRoleResponse, PlatformServiceInstanceResponse,
    PlatformStatusResponse, PlatformUserResponse, PlatformWorkshopDetailResponse,
    PlatformWorkshopResponse, PrimaryDatabaseResponse, PrivacyDecisionCommandResponse,
    PrivacyIncidentAssessmentResponse, PrivacyIncidentCreateResponse, PrivacyIncidentResponse,
    PrivacyOverviewResponse, PrivacyPlatformStateResponse, PrivacyPolicyVersionResponse,
    PrivacyRequestCommandResponse, PrivacyRequestResponse, ProcessorApprovalResponse,
    ProcessorTaskResponse, QueueStatusResponse, RecoveryPointCommandResponse,
    RecoveryPointResponse, RehearsalStatusResponse, ReleaseAdoptionCommandResponse,
    ReleasePreflightCommandResponse, ReleasedCommandResponse, ReplayResponse,
    RestoreCommandResponse, RetentionRunCommandResponse, RetentionRunResponse,
    RoleGrantCommandResponse, RoleRevokeCommandResponse, RuntimeReleaseSlotResponse,
    ServiceStatusResponse, StateCommandResponse, TargetStateResponse,
    TenantReleaseAdoptionResponse, UsageCounterResponse, VersionedOperationCommandResponse,
    WorkerStatusResponse, WorkshopCreateCommandResponse, WorkshopDeletionCommandResponse,
    WorkshopDeletionResponse, WorkshopSummaryResponse,
};
use crate::api::domains::{CustomDomainCreateBody, WebshopDomainResponse};
use crate::api::email_domains::{EmailDomainCreateBody, EmailDomainResponse};
use crate::api::governance::{
    CreateLegalHold, CreatePrivacyIncident, CreatePrivacyRequest, CreateRetentionRun,
    PlatformRoleGrant, PlatformRoleRevoke, PrivacyDecision, PrivacyIncidentAssessment,
    ProcessorTaskAcknowledgement, ReleaseLegalHold,
};
use crate::api::smtp::{WebshopSmtpBody, WebshopSmtpResponse};
use crate::api::webshop::{
    WebshopCheckResponse, WebshopDashboardResponse, WebshopIssueResponse,
    WebshopOnboardingCommandResponse,
};
use crate::api::{
    AdoptReleaseBody, CreateWorkshop, DeleteWorkshopBody, DuplicateBody, InvitationTokenBody,
    InviteBody, RecoveryPointBody, RestoreBody, RoleBody, TransferBody,
};
use crate::domain::WorkshopRole;

#[derive(OpenApi)]
#[openapi(components(schemas(
    MeResponse,
    WorkshopRole,
    WorkshopSummaryResponse,
    TargetStateResponse,
    MemberResponse,
    MemberDetailResponse,
    IntegrationResponse,
    InvitationResponse,
    OwnershipTransferResponse,
    ModuleResponse,
    PrimaryDatabaseResponse,
    DuplicateDatabaseResponse,
    RecoveryPointResponse,
    DatabaseResponse,
    OperationResponse,
    ApplicationReleaseResponse,
    PrivacyRequestResponse,
    DataSubjectExportStatusResponse,
    PlatformOperationResponse,
    PlatformUserResponse,
    PlatformReleaseIdentityResponse,
    QueueStatusResponse,
    ServiceStatusResponse,
    BackupStatusResponse,
    RehearsalStatusResponse,
    WorkerStatusResponse,
    PlatformStatusResponse,
    PlatformRoleResponse,
    EmailDeliveryResponse,
    AuditEventResponse,
    CountHealthResponse,
    CountDisabledResponse,
    CountOperationsResponse,
    AttentionOperationResponse,
    PlatformOverviewResponse,
    PlatformWorkshopResponse,
    RuntimeReleaseSlotResponse,
    ApplicationReleaseDetailResponse,
    TenantReleaseAdoptionResponse,
    PrivacyPlatformStateResponse,
    PrivacyPolicyVersionResponse,
    ProcessorApprovalResponse,
    RetentionRunResponse,
    PrivacyIncidentResponse,
    ProcessorTaskResponse,
    LegalHoldScopeResponse,
    LegalHoldResponse,
    ErasureRestoreReplayResponse,
    PrivacyOverviewResponse,
    PlatformMemberResponse,
    PlatformServiceInstanceResponse,
    EntitlementResponse,
    UsageCounterResponse,
    WorkshopDeletionResponse,
    PlatformWorkshopDetailResponse,
    RetentionRunCommandResponse,
    CommandInProgressResponse,
    ReplayResponse,
    OperationCommandResponse,
    VersionedOperationCommandResponse,
    RoleGrantCommandResponse,
    RoleRevokeCommandResponse,
    PrivacyRequestCommandResponse,
    PrivacyDecisionCommandResponse,
    StateCommandResponse,
    PrivacyIncidentCreateResponse,
    PrivacyIncidentAssessmentResponse,
    LegalHoldCreateResponse,
    ReleasedCommandResponse,
    WorkshopDeletionCommandResponse,
    ReleasePreflightCommandResponse,
    ReleaseAdoptionCommandResponse,
    IdentityLinkResponse,
    WorkshopCreateCommandResponse,
    InvitationCreateResponse,
    InvitationResendResponse,
    InvitationValidationResponse,
    InvitationAcceptanceResponse,
    MemberUpdateCommandResponse,
    OwnershipTransferCreateResponse,
    OwnershipTransferAcceptResponse,
    ModuleEnableCommandResponse,
    RecoveryPointCommandResponse,
    RestoreCommandResponse,
    DuplicateCommandResponse,
    OperationRetryResponse,
    DeleteWorkshopBody,
    AdoptReleaseBody,
    CreateWorkshop,
    InviteBody,
    InvitationTokenBody,
    RoleBody,
    TransferBody,
    RecoveryPointBody,
    RestoreBody,
    DuplicateBody,
    PlatformRoleGrant,
    PlatformRoleRevoke,
    CreatePrivacyRequest,
    CreateRetentionRun,
    PrivacyDecision,
    ProcessorTaskAcknowledgement,
    CreatePrivacyIncident,
    PrivacyIncidentAssessment,
    CreateLegalHold,
    ReleaseLegalHold,
    CarrierCredentials,
    CarrierSecretBody,
    CarrierSecretDeleteResponse,
    CarrierSecretResponse,
    CarrierTargetResponse,
    CustomDomainCreateBody,
    WebshopDomainResponse,
    EmailDomainCreateBody,
    EmailDomainResponse,
    WebshopSmtpBody,
    WebshopSmtpResponse,
    WebshopCheckResponse,
    WebshopIssueResponse,
    WebshopDashboardResponse,
    WebshopOnboardingCommandResponse
)))]
struct PublicSchemas;

fn operation_id(method: &str, path: &str) -> String {
    let mut result = method.to_owned();
    let mut uppercase = true;
    for character in path.chars() {
        if character.is_ascii_alphanumeric() {
            if uppercase {
                result.extend(character.to_uppercase());
                uppercase = false;
            } else {
                result.push(character);
            }
        } else {
            uppercase = true;
        }
    }
    result
}

fn success_statuses(path: &str, method: &str) -> &'static [&'static str] {
    if method == "get" {
        return &["200"];
    }
    match (path, method) {
        ("/v1/privacy/requests/{id}/export", "post")
        | ("/v1/workshops/{id}/database/backups/{recovery_id}/download", "post")
        | ("/v1/invitations/validate", "post")
        | ("/v1/workshops/{id}/email/smtp", "post")
        | ("/v1/workshops/{id}/email/smtp", "delete") => &["200"],
        ("/v1/invitations/{id}", "delete") => &["202", "204"],
        ("/v1/platform/releases/{id}/retry-failed-tenants", "post") => &[],
        ("/v1/identity/link", "post") => &["200", "201", "202"],
        ("/v1/platform/roles", "post")
        | ("/v1/privacy/requests", "post")
        | ("/v1/platform/privacy/incidents", "post")
        | ("/v1/platform/privacy/legal-holds", "post")
        | ("/v1/workshops/{id}/domains", "post") => &["201", "202"],
        ("/v1/platform/roles/{id}", "delete")
        | ("/v1/platform/privacy/requests/{id}/decision", "post")
        | ("/v1/platform/privacy/processor-tasks/{id}/acknowledge", "post")
        | ("/v1/platform/privacy/incidents/{id}/assessment", "post")
        | ("/v1/platform/privacy/legal-holds/{id}/release", "post")
        | ("/v1/workshops/{id}/modules/{module_key}/enable", "post")
        | ("/v1/ownership-transfers/{id}/accept", "post")
        | ("/v1/workshops/{id}/webshop/onboarding/complete", "post")
        | ("/v1/workshops/{id}/webshop/deactivate", "post")
        | ("/v1/workshops/{id}/carrier-secrets", "post")
        | ("/v1/workshops/{id}/carrier-secrets/{secret_id}", "delete")
        | ("/v1/workshops/{id}/domains/{domain_id}/verify", "post") => &["200", "202"],
        _ => &["202"],
    }
}

/// The public contract is emitted from the executable so deployments and
/// generated clients can inspect the exact route release they are running.
pub fn document() -> Value {
    let routes = crate::api::routes::specs();
    let no_idempotency = [
        ("/v1/identity/link", "post"),
        ("/v1/privacy/requests/{id}/export", "post"),
        ("/v1/invitations/validate", "post"),
        (
            "/v1/workshops/{id}/database/backups/{recovery_id}/download",
            "post",
        ),
    ];
    let versioned_mutations = [
        "/v1/platform/workshops/{id}/deletion",
        "/v1/platform/releases/{id}/preflight",
        "/v1/platform/releases/{id}/adopt",
        "/v1/platform/releases/{id}/retry-failed-tenants",
        "/v1/platform/roles/{id}",
        "/v1/platform/privacy/requests/{id}/decision",
        "/v1/platform/privacy/processor-tasks/{id}/acknowledge",
        "/v1/platform/privacy/incidents/{id}/assessment",
        "/v1/platform/privacy/legal-holds/{id}/release",
        "/v1/workshops/{id}/members/{user_id}",
        "/v1/workshops/{id}/ownership-transfers",
        "/v1/ownership-transfers/{id}/accept",
        "/v1/workshops/{id}/modules/{module_key}/enable",
        "/v1/workshops/{id}/domains/{domain_id}/canonical",
        "/v1/workshops/{id}/domains/{domain_id}",
        "/v1/workshops/{id}/webshop/onboarding/refresh",
        "/v1/workshops/{id}/webshop/onboarding/complete",
        "/v1/workshops/{id}/webshop/deactivate",
    ];
    let mut paths = Map::new();
    let typed = |name: &str| json!({"$ref":format!("#/components/schemas/{name}")});
    let command = |name: &str| {
        json!({"oneOf":[
            {"$ref":format!("#/components/schemas/{name}")},
            {"$ref":"#/components/schemas/CommandInProgressResponse"},
            {"$ref":"#/components/schemas/ReplayResponse"}
        ]})
    };
    for route in routes {
        let path = route.path;
        let method = route.method;
        let security_scheme = route.access.security_scheme();
        let item = paths
            .entry(path)
            .or_insert_with(|| Value::Object(Map::new()))
            .as_object_mut()
            .expect("path item");
        let mut parameters = path
            .split('/')
            .filter_map(|part| {
                part.strip_prefix('{')
                    .and_then(|part| part.strip_suffix('}'))
            })
            .map(|name| {
                let schema = if (name == "id" || name.ends_with("_id"))
                    && !path.starts_with("/v1/platform/releases/")
                {
                    json!({"type":"string","format":"uuid"})
                } else {
                    json!({"type":"string"})
                };
                json!({"name":name,"in":"path","required":true,"schema":schema})
            })
            .collect::<Vec<_>>();
        match (path, method) {
            ("/v1/platform/operations", "get") => {
                parameters.extend([
                    json!({"name":"state","in":"query","required":false,"schema":{"type":"string"}}),
                    json!({"name":"workshop_id","in":"query","required":false,"schema":{"type":"string","format":"uuid"}}),
                    json!({"name":"limit","in":"query","required":false,"schema":{"type":"integer","format":"int64","minimum":1,"maximum":200}}),
                ]);
            }
            ("/v1/platform/audit-events", "get") => {
                parameters.push(json!({"name":"limit","in":"query","required":false,"schema":{"type":"integer","format":"int64","minimum":1,"maximum":200}}));
            }
            _ => {}
        }
        if method != "get" && !no_idempotency.contains(&(path, method)) {
            parameters.push(json!({"name":"Idempotency-Key","in":"header","required":true,"description":"Bounded command key. Identical semantic requests replay the stored result; reuse with another request returns 409.","schema":{"type":"string","minLength":1,"maxLength":255}}));
        }
        if (path, method) == ("/v1/identity/link", "post") {
            parameters.push(json!({"name":"Idempotency-Key","in":"header","required":false,"description":"Optional v1-compatible command key. If omitted, the server uses the stable identity-link key; identical requests still replay the stored result.","schema":{"type":"string","minLength":1,"maxLength":255}}));
        }
        if method != "get" && versioned_mutations.contains(&path) {
            parameters.push(json!({"name":"If-Match","in":"header","required":true,"description":"Exact strong resource ETag. Stale versions return 412.","schema":{"type":"string"}}));
        }
        let tag = if path.starts_with("/v1/platform/privacy") || path.starts_with("/v1/privacy") {
            "privacy"
        } else if path.starts_with("/v1/platform/releases") {
            "releases"
        } else if path.starts_with("/v1/platform") {
            "platform"
        } else if path.contains("invitations") {
            "invitations"
        } else if path.contains("database") {
            "recovery"
        } else {
            "workshops"
        };
        let security = match security_scheme {
            None => json!([]),
            Some(scheme) => json!([{scheme: []}]),
        };
        let success_schema = match (path, method) {
            ("/v1/me", "get") => json!({"$ref":"#/components/schemas/MeResponse"}),
            ("/v1/workshops", "get") => {
                json!({"type":"array","items":{"$ref":"#/components/schemas/WorkshopSummaryResponse"}})
            }
            ("/v1/workshops/{id}", "get") => {
                json!({"$ref":"#/components/schemas/WorkshopSummaryResponse"})
            }
            ("/v1/workshops/{id}/members", "get") => {
                json!({"type":"array","items":{"$ref":"#/components/schemas/MemberResponse"}})
            }
            ("/v1/workshops/{id}/members/{user_id}", "get") => {
                json!({"$ref":"#/components/schemas/MemberDetailResponse"})
            }
            ("/v1/workshops/{id}/integrations", "get") => {
                json!({"type":"array","items":{"$ref":"#/components/schemas/IntegrationResponse"}})
            }
            ("/v1/workshops/{id}/invitations", "get") => {
                json!({"type":"array","items":{"$ref":"#/components/schemas/InvitationResponse"}})
            }
            ("/v1/workshops/{id}/ownership-transfers", "get") => {
                json!({"type":"array","items":{"$ref":"#/components/schemas/OwnershipTransferResponse"}})
            }
            ("/v1/workshops/{id}/modules", "get") => {
                json!({"type":"array","items":{"$ref":"#/components/schemas/ModuleResponse"}})
            }
            ("/v1/workshops/{id}/webshop", "get")
            | ("/v1/platform/workshops/{id}/webshop", "get") => typed("WebshopDashboardResponse"),
            ("/v1/workshops/{id}/webshop/onboarding/refresh", "post")
            | ("/v1/workshops/{id}/webshop/onboarding/complete", "post") => {
                command("WebshopOnboardingCommandResponse")
            }
            ("/v1/workshops/{id}/webshop/deactivate", "post") => {
                command("ModuleEnableCommandResponse")
            }
            ("/v1/workshops/{id}/carrier-secrets", "get") => {
                json!({"type":"array","items":{"$ref":"#/components/schemas/CarrierSecretResponse"}})
            }
            ("/v1/workshops/{id}/carrier-targets", "get") => {
                json!({"type":"array","items":{"$ref":"#/components/schemas/CarrierTargetResponse"}})
            }
            ("/v1/workshops/{id}/domains", "get") => {
                json!({"type":"array","items":{"$ref":"#/components/schemas/WebshopDomainResponse"}})
            }
            ("/v1/workshops/{id}/domains", "post") => command("WebshopDomainResponse"),
            ("/v1/workshops/{id}/domains/{domain_id}/verify", "post") => {
                command("WebshopDomainResponse")
            }
            ("/v1/workshops/{id}/domains/{domain_id}/canonical", "post") => {
                command("WebshopDomainResponse")
            }
            ("/v1/workshops/{id}/domains/{domain_id}", "delete") => {
                command("WebshopDomainResponse")
            }
            ("/v1/workshops/{id}/email-domains", "get") => {
                json!({"type":"array","items":{"$ref":"#/components/schemas/EmailDomainResponse"}})
            }
            ("/v1/workshops/{id}/email-domains", "post") => command("EmailDomainResponse"),
            ("/v1/workshops/{id}/email-domains/{domain_id}/check", "post")
            | ("/v1/workshops/{id}/email-domains/{domain_id}", "delete") => {
                command("OperationCommandResponse")
            }
            ("/v1/workshops/{id}/email/smtp", "get")
            | ("/v1/workshops/{id}/email/smtp", "post")
            | ("/v1/workshops/{id}/email/smtp", "delete") => typed("WebshopSmtpResponse"),
            ("/v1/workshops/{id}/carrier-secrets", "post") => command("CarrierSecretResponse"),
            ("/v1/workshops/{id}/carrier-secrets/{secret_id}", "delete") => {
                command("CarrierSecretDeleteResponse")
            }
            ("/v1/workshops/{id}/database", "get") => {
                json!({"$ref":"#/components/schemas/DatabaseResponse"})
            }
            ("/v1/operations/{id}", "get") => {
                json!({"$ref":"#/components/schemas/OperationResponse"})
            }
            ("/v1/platform/releases", "get") => {
                json!({"type":"array","items":{"$ref":"#/components/schemas/ApplicationReleaseResponse"}})
            }
            ("/v1/privacy/requests", "get") | ("/v1/platform/privacy/requests", "get") => {
                json!({"type":"array","items":{"$ref":"#/components/schemas/PrivacyRequestResponse"}})
            }
            ("/v1/privacy/requests/{id}", "get") => {
                json!({"$ref":"#/components/schemas/PrivacyRequestResponse"})
            }
            ("/v1/platform/operations", "get") => {
                json!({"type":"array","items":{"$ref":"#/components/schemas/PlatformOperationResponse"}})
            }
            ("/v1/platform/users", "get") => {
                json!({"type":"array","items":{"$ref":"#/components/schemas/PlatformUserResponse"}})
            }
            ("/v1/platform/status", "get") => {
                json!({"$ref":"#/components/schemas/PlatformStatusResponse"})
            }
            ("/v1/platform/roles", "get") => {
                json!({"type":"array","items":{"$ref":"#/components/schemas/PlatformRoleResponse"}})
            }
            ("/v1/platform/email-deliveries", "get") => {
                json!({"type":"array","items":{"$ref":"#/components/schemas/EmailDeliveryResponse"}})
            }
            ("/v1/platform/audit-events", "get") => {
                json!({"type":"array","items":{"$ref":"#/components/schemas/AuditEventResponse"}})
            }
            ("/v1/platform/overview", "get") => {
                json!({"$ref":"#/components/schemas/PlatformOverviewResponse"})
            }
            ("/v1/platform/workshops", "get") => {
                json!({"type":"array","items":{"$ref":"#/components/schemas/PlatformWorkshopResponse"}})
            }
            ("/v1/platform/workshops/{id}", "get") => {
                json!({"$ref":"#/components/schemas/PlatformWorkshopDetailResponse"})
            }
            ("/v1/platform/releases/{id}", "get") => {
                json!({"$ref":"#/components/schemas/ApplicationReleaseDetailResponse"})
            }
            ("/v1/platform/releases/{id}/tenants", "get") => {
                json!({"type":"array","items":{"$ref":"#/components/schemas/TenantReleaseAdoptionResponse"}})
            }
            ("/v1/platform/privacy", "get") => {
                json!({"$ref":"#/components/schemas/PrivacyOverviewResponse"})
            }
            ("/v1/platform/privacy/retention-runs", "post") => {
                command("RetentionRunCommandResponse")
            }
            ("/v1/platform/workshops/{id}/deletion", "post") => {
                command("WorkshopDeletionCommandResponse")
            }
            ("/v1/platform/workshops/{id}/reconcile", "post") => {
                command("OperationCommandResponse")
            }
            ("/v1/platform/releases/{id}/preflight", "post") => {
                command("ReleasePreflightCommandResponse")
            }
            ("/v1/platform/releases/{id}/adopt", "post") => {
                command("ReleaseAdoptionCommandResponse")
            }
            ("/v1/platform/roles", "post") => command("RoleGrantCommandResponse"),
            ("/v1/platform/roles/{id}", "delete") => command("RoleRevokeCommandResponse"),
            ("/v1/platform/privacy/requests/{id}/decision", "post") => {
                command("PrivacyDecisionCommandResponse")
            }
            ("/v1/platform/privacy/processor-tasks/{id}/acknowledge", "post") => {
                command("StateCommandResponse")
            }
            ("/v1/platform/privacy/incidents", "post") => command("PrivacyIncidentCreateResponse"),
            ("/v1/platform/privacy/incidents/{id}/assessment", "post") => {
                command("PrivacyIncidentAssessmentResponse")
            }
            ("/v1/platform/privacy/legal-holds", "post") => command("LegalHoldCreateResponse"),
            ("/v1/platform/privacy/legal-holds/{id}/release", "post") => {
                command("ReleasedCommandResponse")
            }
            ("/v1/privacy/requests", "post") => command("PrivacyRequestCommandResponse"),
            ("/v1/identity/link", "post") => command("IdentityLinkResponse"),
            ("/v1/workshops", "post") => command("WorkshopCreateCommandResponse"),
            ("/v1/workshops/{id}/invitations", "post") => command("InvitationCreateResponse"),
            ("/v1/invitations/{id}/resend", "post") => command("InvitationResendResponse"),
            ("/v1/invitations/validate", "post") => typed("InvitationValidationResponse"),
            ("/v1/invitations/accept", "post") => command("InvitationAcceptanceResponse"),
            ("/v1/workshops/{id}/members/{user_id}", "patch") => {
                command("MemberUpdateCommandResponse")
            }
            ("/v1/workshops/{id}/members/{user_id}", "delete") => {
                command("VersionedOperationCommandResponse")
            }
            ("/v1/workshops/{id}/ownership-transfers", "post") => {
                command("OwnershipTransferCreateResponse")
            }
            ("/v1/ownership-transfers/{id}/accept", "post") => {
                command("OwnershipTransferAcceptResponse")
            }
            ("/v1/workshops/{id}/modules/{module_key}/enable", "post") => {
                command("ModuleEnableCommandResponse")
            }
            ("/v1/workshops/{id}/database/snapshots", "post")
            | ("/v1/workshops/{id}/database/backups", "post") => {
                command("RecoveryPointCommandResponse")
            }
            ("/v1/workshops/{id}/database/restores", "post") => command("RestoreCommandResponse"),
            ("/v1/workshops/{id}/database/duplicates", "post") => {
                command("DuplicateCommandResponse")
            }
            ("/v1/operations/{id}/retry", "post") => command("OperationRetryResponse"),
            ("/v1/invitations/{id}", "delete")
            | ("/v1/platform/releases/{id}/retry-failed-tenants", "post") => {
                json!({"type":"null"})
            }
            ("/v1/privacy/requests/{id}/export", "post")
            | ("/v1/workshops/{id}/database/backups/{recovery_id}/download", "post") => {
                json!({"type":"string","format":"binary"})
            }
            _ => json!({"type":"object","additionalProperties":true}),
        };
        let request_schema = match (path, method) {
            ("/v1/platform/workshops/{id}/deletion", "post") => Some("DeleteWorkshopBody"),
            ("/v1/platform/releases/{id}/adopt", "post") => Some("AdoptReleaseBody"),
            ("/v1/platform/roles", "post") => Some("PlatformRoleGrant"),
            ("/v1/platform/roles/{id}", "delete") => Some("PlatformRoleRevoke"),
            ("/v1/platform/privacy/retention-runs", "post") => Some("CreateRetentionRun"),
            ("/v1/platform/privacy/requests/{id}/decision", "post") => Some("PrivacyDecision"),
            ("/v1/platform/privacy/processor-tasks/{id}/acknowledge", "post") => {
                Some("ProcessorTaskAcknowledgement")
            }
            ("/v1/platform/privacy/incidents", "post") => Some("CreatePrivacyIncident"),
            ("/v1/platform/privacy/incidents/{id}/assessment", "post") => {
                Some("PrivacyIncidentAssessment")
            }
            ("/v1/platform/privacy/legal-holds", "post") => Some("CreateLegalHold"),
            ("/v1/platform/privacy/legal-holds/{id}/release", "post") => Some("ReleaseLegalHold"),
            ("/v1/privacy/requests", "post") => Some("CreatePrivacyRequest"),
            ("/v1/workshops", "post") => Some("CreateWorkshop"),
            ("/v1/workshops/{id}/invitations", "post") => Some("InviteBody"),
            ("/v1/invitations/validate", "post") | ("/v1/invitations/accept", "post") => {
                Some("InvitationTokenBody")
            }
            ("/v1/workshops/{id}/members/{user_id}", "patch") => Some("RoleBody"),
            ("/v1/workshops/{id}/ownership-transfers", "post") => Some("TransferBody"),
            ("/v1/workshops/{id}/database/snapshots", "post")
            | ("/v1/workshops/{id}/database/backups", "post") => Some("RecoveryPointBody"),
            ("/v1/workshops/{id}/database/restores", "post") => Some("RestoreBody"),
            ("/v1/workshops/{id}/database/duplicates", "post") => Some("DuplicateBody"),
            ("/v1/workshops/{id}/carrier-secrets", "post") => Some("CarrierSecretBody"),
            ("/v1/workshops/{id}/domains", "post") => Some("CustomDomainCreateBody"),
            ("/v1/workshops/{id}/email-domains", "post") => Some("EmailDomainCreateBody"),
            ("/v1/workshops/{id}/email/smtp", "post") => Some("WebshopSmtpBody"),
            _ => None,
        };
        let mut responses = json!({
            "400":{"$ref":"#/components/responses/ValidationError"},
            "401":{"$ref":"#/components/responses/AuthenticationError"},
            "403":{"$ref":"#/components/responses/AuthorityError"},
            "409":{"$ref":"#/components/responses/ConflictError"},
            "410":{"$ref":"#/components/responses/GoneError"},
            "412":{"$ref":"#/components/responses/StaleWriteError"},
            "428":{"$ref":"#/components/responses/PreconditionError"},
            "503":{"$ref":"#/components/responses/PrivacyGateError"}
        });
        for status in success_statuses(path, method) {
            let response = match (*status, path, method) {
                ("202" | "204", "/v1/invitations/{id}", "delete") => {
                    json!({"description":"Successful response with no content"})
                }
                (
                    "200",
                    "/v1/privacy/requests/{id}/export"
                    | "/v1/workshops/{id}/database/backups/{recovery_id}/download",
                    "post",
                ) => {
                    json!({"description":"Successful binary response","content":{"application/octet-stream":{"schema":{"type":"string","format":"binary"}}}})
                }
                ("201", _, _) => {
                    json!({"description":"Resource created","content":{"application/json":{"schema":success_schema.clone()}}})
                }
                ("202", _, _) => {
                    json!({"description":"Durable operation accepted","content":{"application/json":{"schema":success_schema.clone()}}})
                }
                _ => {
                    json!({"description":"Successful response","content":{"application/json":{"schema":success_schema.clone()}}})
                }
            };
            responses
                .as_object_mut()
                .expect("responses")
                .insert((*status).into(), response);
        }
        let mut operation = json!({
            "operationId":operation_id(method,path),
            "tags":[tag],
            "parameters":parameters,
            "responses":responses,
            "security":security
        });
        if let Some(schema) = request_schema {
            operation.as_object_mut().unwrap().insert(
                "requestBody".into(),
                json!({"required":true,"content":{"application/json":{"schema":{"$ref":format!("#/components/schemas/{schema}")}}}}),
            );
        }
        if versioned_mutations.contains(&path) {
            for status in success_statuses(path, method) {
                if *status == "204" {
                    continue;
                }
                operation["responses"][*status]["headers"] = json!({
                    "ETag": {
                        "description":"Strong resource version returned after the command.",
                        "schema":{"type":"string"}
                    }
                });
            }
        }
        item.insert(method.into(), operation);
    }
    let error_schema = json!({"type":"object","required":["error"],"properties":{"error":{"type":"string"},"message":{"type":"string"}},"additionalProperties":false});
    let mut schemas = serde_json::to_value(PublicSchemas::openapi())
        .expect("serialize typed schemas")["components"]["schemas"]
        .as_object()
        .expect("typed schemas")
        .clone();
    schemas.insert("Error".into(), error_schema);
    let response = |description: &str| json!({"description":description,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/Error"}}}});
    json!({"openapi":"3.1.0","info":{"title":"MakersBrain control API","version":env!("CARGO_PKG_VERSION")},"servers":[{"url":"/"}],"paths":paths,"components":{"schemas":schemas,"responses":{"ValidationError":response("Validation failed"),"AuthenticationError":response("Authentication required"),"AuthorityError":response("Authority refused"),"ConflictError":response("Command conflict or illegal state"),"GoneError":response("The one-time resource is expired, consumed, or unavailable"),"StaleWriteError":response("If-Match is stale"),"PreconditionError":response("A required command header is absent"),"PrivacyGateError":response("Personal-data processing is blocked pending formal approvals")},"securitySchemes":{"rauthy":{"type":"http","scheme":"bearer","bearerFormat":"JWT","description":"Rauthy member access token; workshop authority is resolved from PostgreSQL."},"rauthyOperator":{"type":"http","scheme":"bearer","bearerFormat":"JWT","description":"Rauthy operator-client token plus a current platform role. Sensitive operations require recent strong authentication."}}}})
}

fn typescript_type(schema: &Value) -> String {
    if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        return reference.rsplit('/').next().unwrap_or("unknown").to_owned();
    }
    if let Some(values) = schema.get("enum").and_then(Value::as_array) {
        return values
            .iter()
            .map(|value| serde_json::to_string(value).expect("serialize enum value"))
            .collect::<Vec<_>>()
            .join(" | ");
    }
    if let Some(variants) = schema
        .get("oneOf")
        .or_else(|| schema.get("anyOf"))
        .and_then(Value::as_array)
    {
        return variants
            .iter()
            .map(typescript_type)
            .collect::<Vec<_>>()
            .join(" | ");
    }
    if let Some(types) = schema.get("type").and_then(Value::as_array) {
        return types
            .iter()
            .map(|kind| typescript_type(&json!({"type":kind})))
            .collect::<Vec<_>>()
            .join(" | ");
    }
    match schema.get("type").and_then(Value::as_str) {
        Some("string") => "string".into(),
        Some("integer" | "number") => "number".into(),
        Some("boolean") => "boolean".into(),
        Some("null") => "null".into(),
        Some("array") => format!(
            "Array<{}>",
            typescript_type(schema.get("items").unwrap_or(&Value::Null))
        ),
        Some("object") => {
            let properties = schema
                .get("properties")
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default();
            if properties.is_empty() {
                return match schema.get("additionalProperties") {
                    Some(Value::Object(additional)) => format!(
                        "Record<string, {}>",
                        typescript_type(&Value::Object(additional.clone()))
                    ),
                    _ => "Record<string, unknown>".into(),
                };
            }
            let required = schema
                .get("required")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect::<std::collections::HashSet<_>>();
            let fields = properties
                .iter()
                .map(|(name, value)| {
                    format!(
                        "{}{}: {}",
                        name,
                        if required.contains(name.as_str()) {
                            ""
                        } else {
                            "?"
                        },
                        typescript_type(value)
                    )
                })
                .collect::<Vec<_>>()
                .join("; ");
            format!("{{ {fields} }}")
        }
        _ => "unknown".into(),
    }
}

pub fn typescript_client() -> String {
    let contract = document();
    let mut operations = Map::new();
    for (path, item) in contract["paths"].as_object().expect("OpenAPI paths") {
        for (method, operation) in item.as_object().expect("OpenAPI path item") {
            let parameters = operation["parameters"]
                .as_array()
                .expect("operation parameters");
            let header = |name: &str| {
                parameters.iter().any(|parameter| {
                    parameter["in"] == "header"
                        && parameter["name"] == name
                        && parameter["required"] == true
                })
            };
            let path_parameters = parameters
                .iter()
                .filter(|parameter| parameter["in"] == "path")
                .filter_map(|parameter| parameter["name"].as_str())
                .collect::<Vec<_>>();
            operations.insert(
                operation["operationId"]
                    .as_str()
                    .expect("operation ID")
                    .into(),
                json!({
                    "method":method.to_ascii_uppercase(),
                    "path":path,
                    "pathParameters":path_parameters,
                    "requiresIdempotencyKey":header("Idempotency-Key"),
                    "requiresIfMatch":header("If-Match")
                }),
            );
        }
    }
    let serialized = serde_json::to_string_pretty(&operations).expect("serialize operations");
    let schema_types = contract["components"]["schemas"]
        .as_object()
        .expect("component schemas")
        .iter()
        .filter(|(name, _)| name.as_str() != "Error")
        .map(|(name, schema)| format!("export type {name} = {};", typescript_type(schema)))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "// Generated by control-openapi. Do not edit by hand.\n\
export interface ControlApiError {{ error: string; message?: string }}\n\
{schema_types}\n\
export const controlApiOperations = {serialized} as const;\n\
export type ControlApiOperationId = keyof typeof controlApiOperations;\n\
export interface ControlApiCallOptions {{\n\
  path?: Record<string, string>;\n\
  query?: Record<string, string | number | boolean | undefined>;\n\
  body?: unknown;\n\
  idempotencyKey?: string;\n\
  ifMatch?: string;\n\
  signal?: AbortSignal;\n\
}}\n\
export async function callControlApi<T = unknown>(baseUrl: string, bearerToken: string, operationId: ControlApiOperationId, options: ControlApiCallOptions = {{}}): Promise<T> {{\n\
  const operation = controlApiOperations[operationId];\n\
  let path: string = operation.path;\n\
  for (const name of operation.pathParameters) {{\n\
    const value = options.path?.[name];\n\
    if (!value) throw new Error(`Missing path parameter ${{name}}`);\n\
    path = path.replace(`{{${{name}}}}`, encodeURIComponent(value));\n\
  }}\n\
  if (operation.requiresIdempotencyKey && !options.idempotencyKey) throw new Error('Idempotency-Key is required');\n\
  if (operation.requiresIfMatch && !options.ifMatch) throw new Error('If-Match is required');\n\
  const url = new URL(path, baseUrl || window.location.origin);\n\
  for (const [name, value] of Object.entries(options.query ?? {{}})) if (value !== undefined) url.searchParams.set(name, String(value));\n\
  const response = await fetch(url, {{method: operation.method, signal: options.signal, headers: {{authorization: `Bearer ${{bearerToken}}`, 'content-type': 'application/json', ...(options.idempotencyKey ? {{'idempotency-key': options.idempotencyKey}} : {{}}), ...(options.ifMatch ? {{'if-match': options.ifMatch}} : {{}})}}, ...(options.body === undefined ? {{}} : {{body: JSON.stringify(options.body)}})}});\n\
  if (response.status === 204) return undefined as T;\n\
  const value: unknown = await response.json().catch(() => ({{error: 'invalid_response'}}));\n\
  if (!response.ok) {{ const error = value as ControlApiError; throw new Error(error.message ?? error.error ?? `Request failed (${{response.status}})`); }}\n\
  return value as T;\n\
}}\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn contract_uses_the_handler_owned_route_registrations() {
        let router_operations = crate::api::routes::specs()
            .into_iter()
            .map(|route| (route.path.to_owned(), route.method.to_owned()))
            .collect::<BTreeSet<_>>();
        let document = document();
        let contract_operations = document["paths"]
            .as_object()
            .unwrap()
            .iter()
            .flat_map(|(path, item)| {
                item.as_object()
                    .unwrap()
                    .keys()
                    .map(move |method| (path.clone(), method.clone()))
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(contract_operations, router_operations);
    }

    #[test]
    fn route_access_drives_openapi_security() {
        let contract = document();
        for route in crate::api::routes::specs() {
            let actual = &contract["paths"][route.path][route.method]["security"];
            let expected = match route.access.security_scheme() {
                None => json!([]),
                Some(scheme) => json!([{scheme: []}]),
            };
            assert_eq!(
                actual, &expected,
                "{} {} has security metadata inconsistent with its route access policy",
                route.method, route.path
            );
        }
    }

    #[test]
    fn operation_ids_and_command_headers_are_machine_readable() {
        let contract = document();
        let mut operation_ids = BTreeSet::new();
        for item in contract["paths"].as_object().unwrap().values() {
            for operation in item.as_object().unwrap().values() {
                let operation_id = operation["operationId"].as_str().unwrap();
                assert!(
                    operation_ids.insert(operation_id),
                    "duplicate {operation_id}"
                );
            }
        }
        let adoption = &contract["paths"]["/v1/platform/releases/{id}/adopt"]["post"];
        let names = adoption["parameters"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|parameter| parameter["name"].as_str())
            .collect::<BTreeSet<_>>();
        assert!(names.contains("id"));
        assert!(names.contains("Idempotency-Key"));
        assert!(names.contains("If-Match"));
        assert_eq!(
            adoption["responses"]["503"]["$ref"],
            "#/components/responses/PrivacyGateError"
        );

        let identity_link = &contract["paths"]["/v1/identity/link"]["post"];
        let identity_command_key = identity_link["parameters"]
            .as_array()
            .unwrap()
            .iter()
            .find(|parameter| parameter["name"] == "Idempotency-Key")
            .expect("identity linking must document centralized command admission");
        assert_eq!(
            identity_command_key["required"], false,
            "persistent identity linking must use centralized command admission"
        );
        assert_eq!(
            identity_link["responses"]["200"]["content"]["application/json"]["schema"]["oneOf"]
                .as_array()
                .unwrap()
                .len(),
            3,
            "identity linking must expose new, in-progress and replay response shapes"
        );

        let member_read = &contract["paths"]["/v1/workshops/{id}/members/{user_id}"]["get"];
        assert!(
            member_read["parameters"]
                .as_array()
                .unwrap()
                .iter()
                .all(|parameter| parameter["name"] != "If-Match")
        );
    }

    #[test]
    fn success_responses_match_executable_statuses() {
        let contract = document();
        let statuses = |path: &str, method: &str| {
            contract["paths"][path][method]["responses"]
                .as_object()
                .unwrap()
                .keys()
                .filter(|status| status.starts_with('2'))
                .cloned()
                .collect::<BTreeSet<_>>()
        };
        assert_eq!(statuses("/v1/me", "get"), BTreeSet::from(["200".into()]));
        assert_eq!(
            statuses("/v1/identity/link", "post"),
            BTreeSet::from(["200".into(), "201".into(), "202".into()])
        );
        assert_eq!(
            statuses("/v1/invitations/{id}", "delete"),
            BTreeSet::from(["202".into(), "204".into()])
        );
        assert!(statuses("/v1/platform/releases/{id}/retry-failed-tenants", "post").is_empty());
        let serialized = serde_json::to_string(&contract).unwrap();
        assert!(!serialized.contains("Reserved compatibility response"));
    }

    #[test]
    fn generated_client_contains_authoritative_public_response_types() {
        let client = typescript_client();
        for name in [
            "MeResponse",
            "WorkshopSummaryResponse",
            "MemberResponse",
            "IntegrationResponse",
            "OperationResponse",
            "TargetStateResponse",
            "WorkshopRole",
            "ApplicationReleaseResponse",
            "PrivacyRequestResponse",
            "PlatformOperationResponse",
            "PlatformUserResponse",
            "PlatformStatusResponse",
        ] {
            assert!(
                client.contains(&format!("export type {name} =")),
                "missing generated type {name}"
            );
        }
        assert!(client.contains("newest_verified_backup?: null | BackupStatusResponse"));
        assert!(client.contains(
            r#""postV1IdentityLink": {
    "method": "POST",
    "path": "/v1/identity/link",
    "pathParameters": [],
    "requiresIdempotencyKey": false"#
        ));
    }

    #[test]
    fn request_bodies_match_handler_deserialization() {
        let contract = document();
        let invitation =
            &contract["paths"]["/v1/workshops/{id}/invitations"]["post"]["requestBody"];
        assert_eq!(invitation["required"], true);
        assert_eq!(
            invitation["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/InviteBody"
        );
        assert!(
            contract["paths"]["/v1/invitations/{id}/resend"]["post"]
                .get("requestBody")
                .is_none(),
            "bodyless commands must not advertise a generic JSON body"
        );
        assert!(
            contract["paths"]["/v1/platform/releases/{id}/preflight"]["post"]
                .get("requestBody")
                .is_none()
        );
    }

    #[test]
    fn mutation_success_responses_are_never_untyped_objects() {
        let contract = document();
        for (path, item) in contract["paths"].as_object().unwrap() {
            for (method, operation) in item.as_object().unwrap() {
                if method == "get" {
                    continue;
                }
                for (status, response) in operation["responses"].as_object().unwrap() {
                    if !status.starts_with('2') {
                        continue;
                    }
                    for media in response["content"]
                        .as_object()
                        .into_iter()
                        .flat_map(|content| content.values())
                    {
                        assert_ne!(
                            media["schema"]["additionalProperties"], true,
                            "untyped success response for {method} {path} ({status})"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn contract_contains_every_required_members_route() {
        let value = document();
        for path in [
            "/v1/me",
            "/v1/workshops/{id}/members",
            "/v1/workshops/{id}/invitations",
            "/v1/invitations/accept",
            "/v1/operations/{id}/retry",
            "/v1/workshops/{id}/database",
            "/v1/workshops/{id}/database/restores",
        ] {
            assert!(value["paths"].get(path).is_some(), "missing {path}")
        }
    }

    #[test]
    fn contract_contains_operator_observability_and_repair_routes() {
        let value = document();
        for path in [
            "/v1/platform/overview",
            "/v1/platform/workshops",
            "/v1/platform/workshops/{id}",
            "/v1/platform/workshops/{id}/reconcile",
            "/v1/platform/workshops/{id}/deletion",
            "/v1/platform/operations",
            "/v1/platform/users",
            "/v1/platform/status",
            "/v1/platform/releases",
            "/v1/platform/releases/{id}/adopt",
            "/v1/platform/email-deliveries",
            "/v1/platform/audit-events",
            "/v1/platform/roles",
            "/v1/platform/privacy",
            "/v1/platform/privacy/requests",
            "/v1/platform/privacy/requests/{id}/decision",
            "/v1/platform/privacy/processor-tasks/{id}/acknowledge",
            "/v1/platform/privacy/incidents",
            "/v1/platform/privacy/incidents/{id}/assessment",
            "/v1/platform/privacy/legal-holds",
            "/v1/platform/privacy/legal-holds/{id}/release",
        ] {
            assert!(value["paths"].get(path).is_some(), "missing {path}")
        }
    }
}
