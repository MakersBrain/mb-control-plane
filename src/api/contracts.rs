use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::domain::WorkshopRole;

#[derive(Serialize, ToSchema)]
pub(crate) struct MeResponse {
    pub id: Uuid,
    pub email: String,
    pub subject: String,
    pub is_operator: bool,
    pub platform_roles: Vec<String>,
    pub recent_strong_authentication: bool,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct WorkshopSummaryResponse {
    pub id: Uuid,
    pub slug: String,
    pub display_name: String,
    pub status: String,
    pub plan: String,
    pub version: i64,
    pub role: WorkshopRole,
    pub authority_epoch: i32,
}

#[derive(Deserialize, Serialize, ToSchema)]
pub(crate) struct TargetStateResponse {
    pub state: String,
    pub desired_epoch: i32,
    pub applied_epoch: i32,
    pub error: Option<String>,
    pub observed_at: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct MemberResponse {
    pub id: Uuid,
    pub email: String,
    pub display_name: Option<String>,
    pub role: WorkshopRole,
    pub status: String,
    pub authority_epoch: i32,
    pub version: i64,
    pub etag: String,
    pub targets: BTreeMap<String, TargetStateResponse>,
    pub operation_id: Option<Uuid>,
    pub operation_state: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct MemberDetailResponse {
    pub id: Uuid,
    pub email: String,
    pub display_name: Option<String>,
    pub role: WorkshopRole,
    pub status: String,
    pub authority_epoch: i32,
    pub version: i64,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct IntegrationResponse {
    pub service: String,
    pub url: String,
    pub health: String,
    pub desired_epoch: i32,
    pub applied_epoch: i32,
    pub error: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct InvitationResponse {
    pub id: Uuid,
    pub email: String,
    pub role: WorkshopRole,
    pub locale: String,
    pub expires_at: String,
    pub sent_count: i32,
    pub last_sent_at: String,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct OwnershipTransferResponse {
    pub id: Uuid,
    pub from_user_id: Uuid,
    pub to_user_id: Uuid,
    pub expires_at: String,
    pub can_accept: bool,
    pub etag: String,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct ModuleResponse {
    pub key: String,
    pub name: String,
    pub description: String,
    pub state: String,
    pub operation_id: Option<Uuid>,
    pub error: Option<String>,
    pub version: i64,
    pub etag: String,
    pub can_manage: bool,
    pub entitled: bool,
    pub release_available: bool,
    pub application_release_id: Option<String>,
    pub registry_version: u32,
    pub minimum_release: String,
    pub dependencies: Vec<String>,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct PrimaryDatabaseResponse {
    pub id: Uuid,
    pub public_hostname: String,
    pub state: String,
    pub created_at: String,
    pub last_restored_at: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct DuplicateDatabaseResponse {
    pub id: Uuid,
    pub label: String,
    pub state: String,
    pub routable: bool,
    pub created_at: String,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct RecoveryPointResponse {
    pub id: Uuid,
    pub kind: String,
    pub label: String,
    pub state: String,
    pub size_bytes: Option<i64>,
    pub created_at: String,
    pub ready_at: Option<String>,
    pub operation_id: Option<Uuid>,
    pub operation_state: Option<String>,
    pub component_scope: Vec<String>,
    pub format_version: String,
    pub storage_location: String,
    pub verified_at: Option<String>,
    pub expires_at: Option<String>,
    pub progress_percent: i16,
    pub progress_phase: Option<String>,
    pub progress_message: Option<String>,
    pub progress_updated_at: Option<String>,
    pub archive_size_bytes: Option<i64>,
    pub downloadable: bool,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct DatabaseResponse {
    pub can_manage: bool,
    pub primary: Option<PrimaryDatabaseResponse>,
    pub duplicates: Vec<DuplicateDatabaseResponse>,
    pub recovery_points: Vec<RecoveryPointResponse>,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct OperationResponse {
    pub id: Uuid,
    pub kind: String,
    pub state: String,
    pub workshop_id: Option<Uuid>,
    pub attempt: i32,
    pub max_attempts: i32,
    pub failure_class: Option<String>,
    pub created_at: String,
    pub finished_at: Option<String>,
    pub progress_percent: i16,
    pub progress_phase: Option<String>,
    pub progress_message: Option<String>,
    pub progress_updated_at: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct ApplicationReleaseResponse {
    pub id: String,
    pub status: String,
    pub source_commit: String,
    pub image_digest: String,
    pub change_class: String,
    pub odoo_version: String,
    pub version: i64,
    pub published_at: String,
    pub updated_at: String,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct DataSubjectExportStatusResponse {
    pub id: Uuid,
    pub state: String,
    pub ready_at: Option<String>,
    pub expires_at: String,
    pub consumed_at: Option<String>,
    pub filename: Option<String>,
    pub plaintext_size: Option<i64>,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct PrivacyRequestResponse {
    pub id: Uuid,
    pub subject_user_id: Uuid,
    pub subject_email: String,
    pub request_type: String,
    pub status: String,
    pub requested_at: String,
    pub due_at: String,
    pub extended_due_at: Option<String>,
    pub decision_code: Option<String>,
    pub version: i64,
    pub updated_at: String,
    pub export: Option<DataSubjectExportStatusResponse>,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct PlatformOperationResponse {
    pub id: Uuid,
    pub kind: String,
    pub state: String,
    pub failure_class: Option<String>,
    pub workshop_id: Option<Uuid>,
    pub workshop_name: Option<String>,
    pub attempt: i32,
    pub max_attempts: i32,
    pub created_at: String,
    pub finished_at: Option<String>,
    pub progress_percent: i16,
    pub progress_phase: Option<String>,
    pub progress_message: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct PlatformUserResponse {
    pub id: Uuid,
    pub email: String,
    pub display_name: Option<String>,
    pub locale: String,
    pub created_at: String,
    pub disabled_at: Option<String>,
    pub identity_linked: bool,
    pub workshop_count: i64,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct PlatformReleaseIdentityResponse {
    pub api: String,
    pub schema: String,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct QueueStatusResponse {
    pub queue: String,
    pub queued: i64,
    pub running: i64,
    pub failed: i64,
    pub oldest_active_at: Option<String>,
    pub last_finished_at: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct ServiceStatusResponse {
    pub service: String,
    pub health: String,
    pub count: i64,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct BackupStatusResponse {
    pub id: Uuid,
    pub workshop_id: Uuid,
    pub workshop_name: String,
    pub ready_at: String,
    pub source_release: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct RehearsalStatusResponse {
    pub id: Uuid,
    pub workshop_id: Uuid,
    pub state: String,
    pub safe_error: Option<String>,
    pub started_at: String,
    pub finished_at: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct WorkerStatusResponse {
    pub worker_id: String,
    pub queue: String,
    pub release_id: String,
    pub started_at: String,
    pub last_heartbeat_at: String,
    pub active_operation_id: Option<Uuid>,
    pub shutdown_at: Option<String>,
    pub fresh: bool,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct PlatformStatusResponse {
    pub release: PlatformReleaseIdentityResponse,
    pub queues: Vec<QueueStatusResponse>,
    pub services: Vec<ServiceStatusResponse>,
    pub newest_verified_backup: Option<BackupStatusResponse>,
    pub latest_rehearsal: Option<RehearsalStatusResponse>,
    pub workers: Vec<WorkerStatusResponse>,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct PlatformRoleResponse {
    pub id: Uuid,
    pub user_id: Uuid,
    pub email: String,
    pub role: String,
    pub granted_by_email: Option<String>,
    pub grant_reason_code: String,
    pub granted_at: String,
    pub revoked_at: Option<String>,
    pub revoke_reason_code: Option<String>,
    pub version: i64,
    pub etag: String,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct EmailDeliveryResponse {
    pub id: Uuid,
    pub recipient: String,
    pub template: String,
    pub state: String,
    pub attempts: i32,
    pub next_attempt_at: String,
    pub created_at: String,
    pub sent_at: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct AuditEventResponse {
    pub id: Uuid,
    pub actor_email: Option<String>,
    pub workshop_id: Option<Uuid>,
    pub workshop_name: Option<String>,
    pub action: String,
    pub target_type: Option<String>,
    pub target_id: Option<String>,
    pub correlation_id: Uuid,
    pub outcome: String,
    #[schema(value_type = Object)]
    pub detail: serde_json::Value,
    pub created_at: String,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct CountHealthResponse {
    pub total: i64,
    pub healthy: i64,
    pub attention: i64,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct CountDisabledResponse {
    pub total: i64,
    pub disabled: i64,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct CountOperationsResponse {
    pub queued: i64,
    pub running: i64,
    pub failed: i64,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct AttentionOperationResponse {
    pub id: Uuid,
    pub kind: String,
    pub state: String,
    pub failure_class: Option<String>,
    pub workshop_id: Option<Uuid>,
    pub workshop_name: Option<String>,
    pub created_at: String,
    pub progress_percent: i16,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct PlatformOverviewResponse {
    pub workshops: CountHealthResponse,
    pub users: CountDisabledResponse,
    pub operations: CountOperationsResponse,
    pub degraded_services: i64,
    pub attention: Vec<AttentionOperationResponse>,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct PlatformWorkshopResponse {
    pub id: Uuid,
    pub slug: String,
    pub display_name: String,
    pub status: String,
    pub plan: String,
    pub created_at: String,
    pub member_count: i64,
    pub degraded_service_count: i64,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct RuntimeReleaseSlotResponse {
    pub runtime_key: String,
    pub slot: String,
    pub release_id: String,
    pub state: String,
    pub image_digest: String,
    pub version: i64,
    #[schema(value_type = Object)]
    pub evidence: serde_json::Value,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct ApplicationReleaseDetailResponse {
    pub id: String,
    pub status: String,
    pub source_commit: String,
    pub image_digest: String,
    pub manifest_digest: String,
    pub change_class: String,
    #[schema(value_type = Object)]
    pub addon_versions: serde_json::Value,
    #[schema(value_type = Object)]
    pub compatibility: serde_json::Value,
    pub bridge_contract: String,
    pub schema_epoch: i64,
    #[schema(value_type = Object)]
    pub required_postconditions: serde_json::Value,
    #[schema(value_type = Object)]
    pub manifest: serde_json::Value,
    pub version: i64,
    pub published_at: String,
    pub updated_at: String,
    pub runtime_slots: Vec<RuntimeReleaseSlotResponse>,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct TenantReleaseAdoptionResponse {
    pub workshop_id: Uuid,
    pub workshop_name: String,
    pub database_id: Uuid,
    pub release_id: String,
    pub source_release_id: Option<String>,
    pub state: String,
    pub operation_id: Option<Uuid>,
    pub backup_recovery_id: Option<Uuid>,
    pub failure_class: Option<String>,
    #[schema(value_type = Object)]
    pub evidence: serde_json::Value,
    pub version: i64,
    pub updated_at: String,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct PrivacyPlatformStateResponse {
    pub controller_ref: Option<String>,
    pub dpo_ref: Option<String>,
    pub production_personal_data_allowed: bool,
    pub approved_retention_policy_version: Option<i32>,
    pub approved_processing_register_version: Option<i32>,
    pub dpia_approval_ref: Option<String>,
    pub version: i64,
    pub updated_at: String,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct PrivacyPolicyVersionResponse {
    pub version: i32,
    pub status: String,
    pub digest: String,
    pub approval_ref: Option<String>,
    pub approved_at: Option<String>,
    pub created_at: String,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct ProcessorApprovalResponse {
    pub provider_key: String,
    pub purpose_key: String,
    pub region: String,
    pub eea: bool,
    pub status: String,
    pub valid_until: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct RetentionRunResponse {
    pub id: Uuid,
    pub policy_version: Option<i32>,
    pub dry_run: bool,
    pub state: String,
    #[schema(value_type = Object)]
    pub evidence: serde_json::Value,
    pub created_at: String,
    pub completed_at: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct PrivacyIncidentResponse {
    pub id: Uuid,
    pub discovered_at: String,
    pub controller_awareness_at: Option<String>,
    pub authority_deadline_at: Option<String>,
    pub containment_state: String,
    pub risk_level: Option<String>,
    pub notification_required: Option<bool>,
    pub version: i64,
    pub etag: String,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct ProcessorTaskResponse {
    pub id: Uuid,
    pub data_subject_request_id: Uuid,
    pub processor_key: String,
    pub action: String,
    pub state: String,
    pub acknowledgement_ref: Option<String>,
    pub safe_error_class: Option<String>,
    pub version: i64,
    pub updated_at: String,
    pub etag: String,
}

#[derive(Deserialize, Serialize, ToSchema)]
pub(crate) struct LegalHoldScopeResponse {
    pub datasets: Vec<String>,
    pub workshop_ids: Vec<Uuid>,
    pub subject_user_ids: Vec<Uuid>,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct LegalHoldResponse {
    pub id: Uuid,
    pub scope: LegalHoldScopeResponse,
    pub reason_code: String,
    pub approval_ref: String,
    pub imposed_at: String,
    pub expires_at: String,
    pub released_at: Option<String>,
    pub release_reason_code: Option<String>,
    pub version: i64,
    pub etag: String,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct ErasureRestoreReplayResponse {
    pub id: Uuid,
    pub tombstone_id: Uuid,
    pub recovery_point_id: Uuid,
    pub operation_id: Uuid,
    pub required_locations: Vec<String>,
    pub completed_locations: Vec<String>,
    pub state: String,
    pub safe_error_class: Option<String>,
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
    pub created_at: String,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct PrivacyOverviewResponse {
    pub state: PrivacyPlatformStateResponse,
    pub retention_policies: Vec<PrivacyPolicyVersionResponse>,
    pub processing_registers: Vec<PrivacyPolicyVersionResponse>,
    pub processors: Vec<ProcessorApprovalResponse>,
    pub retention_runs: Vec<RetentionRunResponse>,
    pub incidents: Vec<PrivacyIncidentResponse>,
    pub processor_tasks: Vec<ProcessorTaskResponse>,
    pub legal_holds: Vec<LegalHoldResponse>,
    pub erasure_restore_replays: Vec<ErasureRestoreReplayResponse>,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct PlatformMemberResponse {
    pub id: Uuid,
    pub email: String,
    pub display_name: Option<String>,
    pub role: WorkshopRole,
    pub status: String,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct PlatformServiceInstanceResponse {
    pub service: String,
    pub url: String,
    pub health: String,
    pub release_id: Option<String>,
    pub error: Option<String>,
    pub desired_epoch: i32,
    pub applied_epoch: i32,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct EntitlementResponse {
    pub version: i64,
    pub plan: String,
    pub status: String,
    #[schema(value_type = Object)]
    pub limits: serde_json::Value,
    pub expires_at: Option<String>,
    pub updated_at: String,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct UsageCounterResponse {
    pub metric: String,
    pub quantity: i64,
    pub updated_at: String,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct WorkshopDeletionResponse {
    pub state: String,
    pub operation_id: Uuid,
    pub final_recovery_point_id: Uuid,
    pub requested_at: String,
    pub quarantined_at: Option<String>,
    pub purge_after: String,
    pub failure_class: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct PlatformWorkshopDetailResponse {
    pub id: Uuid,
    pub slug: String,
    pub display_name: String,
    pub status: String,
    pub plan: String,
    pub legal_name: Option<String>,
    pub country_code: Option<String>,
    pub created_at: String,
    pub version: i64,
    pub etag: String,
    pub members: Vec<PlatformMemberResponse>,
    pub services: Vec<PlatformServiceInstanceResponse>,
    pub entitlement: Option<EntitlementResponse>,
    pub usage: Vec<UsageCounterResponse>,
    pub primary_hostname: Option<String>,
    pub operations: Vec<PlatformOperationResponse>,
    pub deletion: Option<WorkshopDeletionResponse>,
}

#[derive(Deserialize, Serialize, ToSchema)]
pub(crate) struct RetentionRunCommandResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_version: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dry_run: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub in_progress: Option<bool>,
}

#[derive(Deserialize, Serialize, ToSchema)]
pub(crate) struct CommandInProgressResponse {
    pub command_id: Option<Uuid>,
    pub operation_id: Option<Uuid>,
    pub in_progress: bool,
}

#[derive(Deserialize, Serialize, ToSchema)]
pub(crate) struct ReplayResponse {
    pub replayed: bool,
}

#[derive(Deserialize, Serialize, ToSchema)]
pub(crate) struct OperationCommandResponse {
    pub operation_id: Uuid,
}

#[derive(Deserialize, Serialize, ToSchema)]
pub(crate) struct VersionedOperationCommandResponse {
    pub operation_id: Uuid,
    pub version: i64,
}

#[derive(Deserialize, Serialize, ToSchema)]
pub(crate) struct RoleGrantCommandResponse {
    pub id: Uuid,
    pub user_id: Uuid,
    pub role: String,
    pub version: i64,
}

#[derive(Deserialize, Serialize, ToSchema)]
pub(crate) struct RoleRevokeCommandResponse {
    pub id: Uuid,
    pub revoked: bool,
    pub version: i64,
}

#[derive(Deserialize, Serialize, ToSchema)]
pub(crate) struct PrivacyRequestCommandResponse {
    pub id: Uuid,
    pub request_type: String,
    pub status: String,
    pub version: i64,
}

#[derive(Deserialize, Serialize, ToSchema)]
pub(crate) struct PrivacyDecisionCommandResponse {
    pub id: Uuid,
    pub status: String,
    pub version: i64,
    pub operation_id: Option<Uuid>,
}

#[derive(Deserialize, Serialize, ToSchema)]
pub(crate) struct StateCommandResponse {
    pub id: Uuid,
    pub state: String,
    pub version: i64,
}

#[derive(Deserialize, Serialize, ToSchema)]
pub(crate) struct PrivacyIncidentCreateResponse {
    pub id: Uuid,
    pub version: i64,
    pub containment_state: String,
}

#[derive(Deserialize, Serialize, ToSchema)]
pub(crate) struct PrivacyIncidentAssessmentResponse {
    pub id: Uuid,
    pub containment_state: String,
    pub notification_required: bool,
    pub version: i64,
}

#[derive(Deserialize, Serialize, ToSchema)]
pub(crate) struct LegalHoldCreateResponse {
    pub id: Uuid,
    pub version: i64,
    pub expires_at: Option<OffsetDateTime>,
}

#[derive(Deserialize, Serialize, ToSchema)]
pub(crate) struct ReleasedCommandResponse {
    pub id: Uuid,
    pub released: bool,
    pub version: i64,
}

#[derive(Deserialize, Serialize, ToSchema)]
pub(crate) struct WorkshopDeletionCommandResponse {
    pub operation_id: Uuid,
    pub recovery_point_id: Uuid,
    pub retention_days: i64,
    pub version: i64,
}

#[derive(Deserialize, Serialize, ToSchema)]
pub(crate) struct ReleasePreflightCommandResponse {
    pub operation_id: Uuid,
    pub status: String,
    pub version: i64,
}

#[derive(Deserialize, Serialize, ToSchema)]
pub(crate) struct ReleaseAdoptionCommandResponse {
    pub operation_id: Uuid,
    pub fleet_run_id: Uuid,
    pub tenant_count: usize,
    pub status: String,
    pub version: i64,
}

#[derive(Deserialize, Serialize, ToSchema)]
pub(crate) struct IdentityLinkResponse {
    pub user_id: Uuid,
    pub linked: bool,
}

#[derive(Deserialize, Serialize, ToSchema)]
pub(crate) struct WorkshopCreateCommandResponse {
    pub id: Uuid,
    pub operation_id: Uuid,
}

#[derive(Deserialize, Serialize, ToSchema)]
pub(crate) struct InvitationCreateResponse {
    pub id: Uuid,
    pub email: String,
    pub role: String,
    pub expires_at: OffsetDateTime,
}

#[derive(Deserialize, Serialize, ToSchema)]
pub(crate) struct InvitationResendResponse {
    pub id: Uuid,
    pub resent: bool,
    pub generation: i64,
}

#[derive(Deserialize, Serialize, ToSchema)]
pub(crate) struct InvitationValidationResponse {
    pub email: String,
    pub role: String,
    pub locale: String,
    pub workshop_name: String,
}

#[derive(Deserialize, Serialize, ToSchema)]
pub(crate) struct InvitationAcceptanceResponse {
    pub workshop_id: Uuid,
    pub user_id: Uuid,
    pub operation_id: Uuid,
}

#[derive(Deserialize, Serialize, ToSchema)]
pub(crate) struct MemberUpdateCommandResponse {
    pub user_id: Uuid,
    pub role: String,
    pub authority_epoch: i64,
    pub version: i64,
    pub operation_id: Option<Uuid>,
}

#[derive(Deserialize, Serialize, ToSchema)]
pub(crate) struct OwnershipTransferCreateResponse {
    pub id: Uuid,
    pub expires_in_seconds: i64,
    pub version: i64,
}

#[derive(Deserialize, Serialize, ToSchema)]
pub(crate) struct OwnershipTransferAcceptResponse {
    pub id: Uuid,
    pub accepted: bool,
    pub version: i64,
    pub operation_ids: Vec<Uuid>,
}

#[derive(Deserialize, Serialize, ToSchema)]
pub(crate) struct ModuleEnableCommandResponse {
    pub operation_id: Option<Uuid>,
    pub version: i64,
    pub state: String,
}

#[derive(Deserialize, Serialize, ToSchema)]
pub(crate) struct RecoveryPointCommandResponse {
    pub id: Uuid,
    pub operation_id: Uuid,
}

#[derive(Deserialize, Serialize, ToSchema)]
pub(crate) struct RestoreCommandResponse {
    pub operation_id: Uuid,
    pub safety_recovery_point_id: Uuid,
}

#[derive(Deserialize, Serialize, ToSchema)]
pub(crate) struct DuplicateCommandResponse {
    pub id: Uuid,
    pub operation_id: Uuid,
    pub routable: bool,
}

#[derive(Deserialize, Serialize, ToSchema)]
pub(crate) struct OperationRetryResponse {
    pub id: Uuid,
    pub state: String,
}
