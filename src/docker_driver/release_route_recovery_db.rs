//! Dormant typed database boundary for migration 0037 release-route recovery.
//!
//! Claims, durable filesystem authorizations, immutable observations, and
//! terminal decisions are deliberately separate capabilities. Registering the
//! module performs no query and there is no active production callsite.
#![allow(dead_code)]

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use super::gateway::{ReleaseOverlayGenerationIdentity, ReleaseOverlayKind, ReleaseTargetSlot};
use super::release_generation_fs::ReleaseGenerationName;
use super::release_route_publication_db::{
    ReleaseRouteCompletionResponse, ReleaseRouteSnapshotItem, validate_completion_identity,
    validate_release_snapshot_rows,
};
use super::release_route_recovery_observation::VerifiedReleaseRecoveryRouteObservation;
use super::release_runtime_observation::VerifiedReleaseRuntimeObservation;
use super::route_generation_fs::{PriorSelector, validate_digest, validate_selector_target};
use super::{ControlOperationLease, DriverError};

const MIN_TTL_SECONDS: i32 = 60;
const MAX_TTL_SECONDS: i32 = 1_200;
const MAX_DISCOVERY_LIMIT: usize = 100;
const MAX_ROUTES: usize = 500;
const MAX_RESPONSE_BYTES: usize = 1_048_576;
const MAX_EVIDENCE_BYTES: usize = 16_384;

type DiscoveryRow = (
    Uuid,
    Uuid,
    String,
    String,
    i64,
    bool,
    String,
    String,
    OffsetDateTime,
);
type ClaimRow = (String, Option<i64>, Option<String>);
type StateRow = (String, Option<Value>);
type RuntimeExpectationRow = (String, Option<Value>);
type RuntimeObservationRow = (String, Option<String>, Option<Value>);
type FinishRow = (String, Option<Value>);
type RecoverySnapshotRow = (
    String,
    Option<Uuid>,
    Option<Uuid>,
    Option<String>,
    Option<bool>,
    Option<i64>,
    Option<String>,
    Option<String>,
    Option<Value>,
    Option<String>,
    Option<i64>,
    Option<i64>,
    Option<String>,
);

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum ReleaseRecoveryClaimMode {
    WriteCleanup,
    RestorePrior,
    ForwardOnly,
}

impl ReleaseRecoveryClaimMode {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "write_cleanup" => Some(Self::WriteCleanup),
            "restore_prior" => Some(Self::RestorePrior),
            "forward_only" => Some(Self::ForwardOnly),
            _ => None,
        }
    }

    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::WriteCleanup => "write_cleanup",
            Self::RestorePrior => "restore_prior",
            Self::ForwardOnly => "forward_only",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum ReleaseRecoveryPhase {
    MaintenanceStaging,
    MaintenanceSealed,
    MaintenancePublicationStarted,
    MaintenanceObserved,
    CandidateStaging,
    CandidateSealed,
    CandidatePublicationStarted,
    AwaitingWorkerFinalize,
}

impl ReleaseRecoveryPhase {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "maintenance_staging" => Some(Self::MaintenanceStaging),
            "maintenance_sealed" => Some(Self::MaintenanceSealed),
            "maintenance_publication_started" => Some(Self::MaintenancePublicationStarted),
            "maintenance_observed" => Some(Self::MaintenanceObserved),
            "candidate_staging" => Some(Self::CandidateStaging),
            "candidate_sealed" => Some(Self::CandidateSealed),
            "candidate_publication_started" => Some(Self::CandidatePublicationStarted),
            "awaiting_worker_finalize" => Some(Self::AwaitingWorkerFinalize),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct InterruptedReleaseRoutePublication {
    pub driver_operation_id: Uuid,
    pub fleet_run_id: Uuid,
    pub interrupted_phase: ReleaseRecoveryPhase,
    pub claim_mode: ReleaseRecoveryClaimMode,
    pub claim_fence: i64,
    pub claim_available: bool,
    pub maintenance_selector: String,
    pub candidate_selector: String,
    pub updated_at: OffsetDateTime,
}

#[derive(Clone)]
pub(super) struct ReleaseRecoveryClaimRequest {
    pub driver_operation_id: Uuid,
    pub control_operation: ControlOperationLease,
    pub reconciliation_owner: Uuid,
    pub reconciliation_token: Uuid,
    pub ttl_seconds: i32,
}

#[derive(Clone)]
pub(super) struct ReleaseRecoveryClaim {
    pub driver_operation_id: Uuid,
    pub control_operation: ControlOperationLease,
    pub reconciliation_owner: Uuid,
    pub reconciliation_token: Uuid,
    pub claim_fence: i64,
    pub claim_mode: ReleaseRecoveryClaimMode,
    pub ttl_seconds: i32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ClaimReleaseRecovery {
    Acquired,
    Replay,
    Busy,
    Terminal,
    Invalid,
    NotFound,
    ProtocolIncompatible,
    AuthorityLost,
    NotExpired,
    AuthorityInconsistent,
}

impl ClaimReleaseRecovery {
    const fn trace_outcome(self) -> &'static str {
        match self {
            Self::Acquired => "acquired",
            Self::Replay => "replay",
            Self::Busy => "busy",
            Self::Terminal => "terminal",
            Self::Invalid => "invalid",
            Self::NotFound => "not_found",
            Self::ProtocolIncompatible => "protocol_incompatible",
            Self::AuthorityLost => "authority_lost",
            Self::NotExpired => "not_expired",
            Self::AuthorityInconsistent => "authority_inconsistent",
        }
    }
}

pub(super) struct ReleaseRecoveryClaimResult {
    pub outcome: ClaimReleaseRecovery,
    pub claim: Option<ReleaseRecoveryClaim>,
    pub observed_claim_fence: Option<i64>,
    pub observed_claim_mode: Option<ReleaseRecoveryClaimMode>,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct RawRecoveryState {
    driver_operation_id: Uuid,
    fleet_run_id: Uuid,
    claim_fence: i64,
    claim_mode: ReleaseRecoveryClaimMode,
    interrupted_phase: ReleaseRecoveryPhase,
    target_slot: ReleaseTargetSlot,
    original_global_fence_token: i64,
    snapshot_count: i32,
    prior_selector: Option<String>,
    prior_directory_device: Option<i64>,
    prior_directory_inode: Option<i64>,
    prior_loaded_identity: Option<Value>,
    maintenance_selector: String,
    maintenance_route_set_digest: Option<String>,
    maintenance_directory_device: Option<i64>,
    maintenance_directory_inode: Option<i64>,
    candidate_selector: String,
    candidate_route_set_digest: Option<String>,
    candidate_directory_device: Option<i64>,
    candidate_directory_inode: Option<i64>,
    external_effects_started_at: Option<OffsetDateTime>,
}

#[derive(Clone, Debug, PartialEq)]
pub(super) struct ReleaseRecoveryState {
    pub driver_operation_id: Uuid,
    pub fleet_run_id: Uuid,
    pub claim_fence: i64,
    pub claim_mode: ReleaseRecoveryClaimMode,
    pub interrupted_phase: ReleaseRecoveryPhase,
    pub target_slot: ReleaseTargetSlot,
    pub original_global_fence_token: i64,
    pub snapshot_count: usize,
    pub prior: Option<PriorSelector>,
    pub prior_loaded_identity: Option<Value>,
    pub maintenance_selector: String,
    pub maintenance_artifact: Option<ReleaseRecoveryArtifact>,
    pub candidate_selector: String,
    pub candidate_artifact: Option<ReleaseRecoveryArtifact>,
    pub external_effects_started: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ReleaseRecoveryArtifact {
    pub identity: ReleaseOverlayGenerationIdentity,
    pub directory_device: u64,
    pub directory_inode: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ReadReleaseRecoveryState {
    Claimed,
    ClaimLost,
    Terminal,
    NotFound,
}

impl ReadReleaseRecoveryState {
    const fn trace_outcome(self) -> &'static str {
        match self {
            Self::Claimed => "claimed",
            Self::ClaimLost => "claim_lost",
            Self::Terminal => "terminal",
            Self::NotFound => "not_found",
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(super) enum ReadReleaseRecoverySnapshot {
    Page(Vec<ReleaseRouteSnapshotItem>),
    Complete,
    ClaimLost,
    WrongPhase,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct ReleaseRuntimePreparedTenant {
    pub adoption_id: Uuid,
    pub workshop_id: Uuid,
    pub database_id: Uuid,
    pub database_ref: String,
    pub public_hostname: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct ReleaseRuntimeTenantSnapshotItem {
    pub workshop_id: Uuid,
    pub database_id: Uuid,
    pub database_ref: String,
    pub paperless_enabled: bool,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct ReleaseRecoveryRuntimeExpectation {
    pub protocol_version: u8,
    pub release_executor_protocol_version: u8,
    pub driver_operation_id: Uuid,
    pub fleet_run_id: Uuid,
    pub release_id: String,
    pub control_operation_id: Uuid,
    pub original_instance_owner: Uuid,
    pub original_global_fence_token: i64,
    pub target_slot: ReleaseTargetSlot,
    pub release_manifest: crate::release::ApplicationReleaseManifest,
    pub release_manifest_digest: String,
    pub odoo_subject_digest: String,
    pub extension_subject_digest: String,
    pub pair_qualification_digest: String,
    pub prepared_tenants: Vec<ReleaseRuntimePreparedTenant>,
    pub fleet_generation: i64,
    pub tenant_snapshot: Vec<ReleaseRuntimeTenantSnapshotItem>,
    pub gateway_configuration_digest: String,
    pub driver_action_id: Uuid,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum ReadReleaseRecoveryRuntimeExpectation {
    Claimed(Box<ReleaseRecoveryRuntimeExpectation>),
    ClaimLost,
    WrongPhase,
    StateDrift,
}

impl ReadReleaseRecoveryRuntimeExpectation {
    const fn trace_outcome(&self) -> &'static str {
        match self {
            Self::Claimed(_) => "claimed",
            Self::ClaimLost => "claim_lost",
            Self::WrongPhase => "wrong_phase",
            Self::StateDrift => "state_drift",
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(super) struct ReleaseRecoveryRuntimeReceipt {
    pub observation_digest: String,
    pub completion_response: ReleaseRouteCompletionResponse,
}

/// Opaque durable authority to publish the exact candidate selected by a
/// recovery claim. Only the database adapter can mint this value, and only
/// after migration 0041 has bound the immutable runtime receipt to the
/// candidate authorization row.
#[derive(Clone)]
pub(super) struct ReleaseRecoveryCandidatePublicationAuthorization {
    facts: ReleaseRecoveryCandidatePublicationFacts,
    observation_digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ReleaseRecoveryCandidatePublicationFacts {
    driver_operation_id: Uuid,
    control_operation_id: Uuid,
    control_operation_attempt: i32,
    control_operation_owner: String,
    reconciliation_owner: Uuid,
    reconciliation_token: Uuid,
    claim_fence: i64,
    fleet_run_id: Uuid,
    original_global_fence_token: i64,
    target_slot: ReleaseTargetSlot,
    interrupted_phase: ReleaseRecoveryPhase,
    candidate_selector: PriorSelector,
    candidate_identity: ReleaseOverlayGenerationIdentity,
    route_count: usize,
    prior_selector: PriorSelector,
}

impl ReleaseRecoveryCandidatePublicationAuthorization {
    #[cfg(test)]
    pub(super) fn for_test(
        claim: &ReleaseRecoveryClaim,
        state: &ReleaseRecoveryState,
        observation_digest: &str,
    ) -> Self {
        Self::mint(claim, state, observation_digest).expect("valid test publication authority")
    }

    fn mint(
        claim: &ReleaseRecoveryClaim,
        state: &ReleaseRecoveryState,
        observation_digest: &str,
    ) -> Result<Self, DriverError> {
        if !digest(observation_digest) {
            return Err(invalid("release recovery observation digest is invalid"));
        }
        Ok(Self {
            facts: candidate_publication_facts(claim, state)?,
            observation_digest: observation_digest.to_owned(),
        })
    }

    pub(super) fn validate_for(
        &self,
        claim: &ReleaseRecoveryClaim,
        state: &ReleaseRecoveryState,
    ) -> Result<(), DriverError> {
        if !digest(&self.observation_digest)
            || self.facts != candidate_publication_facts(claim, state)?
        {
            return Err(invalid(
                "release recovery candidate publication authorization differs",
            ));
        }
        Ok(())
    }

    pub(super) fn validate_publication_request(
        &self,
        request: &super::release_route_recovery::ReleasePublicationRecoveryRequest<'_>,
    ) -> Result<(), DriverError> {
        let phase_matches = matches!(
            (self.facts.interrupted_phase, request.phase),
            (
                ReleaseRecoveryPhase::CandidateStaging,
                super::release_route_recovery::ReleaseRecoveryPhase::CandidateSealed
            ) | (
                ReleaseRecoveryPhase::CandidateSealed,
                super::release_route_recovery::ReleaseRecoveryPhase::CandidateSealed
            ) | (
                ReleaseRecoveryPhase::CandidatePublicationStarted,
                super::release_route_recovery::ReleaseRecoveryPhase::CandidatePublicationStarted
            ) | (
                ReleaseRecoveryPhase::AwaitingWorkerFinalize,
                super::release_route_recovery::ReleaseRecoveryPhase::AwaitingWorkerFinalize
            )
        );
        if !digest(&self.observation_digest)
            || !phase_matches
            || request.intent.driver_operation_id != self.facts.driver_operation_id
            || request.intent.fleet_run_id != self.facts.fleet_run_id
            || request.intent.original_global_fence_token != self.facts.original_global_fence_token
            || request.intent.target_slot != self.facts.target_slot
            || request.intent.overlay_kind != ReleaseOverlayKind::Candidate
            || request.overlay_identity != &self.facts.candidate_identity
            || request.route_count != self.facts.route_count
            || request.overlay_selector != &self.facts.candidate_selector
            || request.prior_selector != &self.facts.prior_selector
        {
            return Err(invalid(
                "release recovery candidate publication request is unauthorized",
            ));
        }
        Ok(())
    }
}

fn candidate_publication_facts(
    claim: &ReleaseRecoveryClaim,
    state: &ReleaseRecoveryState,
) -> Result<ReleaseRecoveryCandidatePublicationFacts, DriverError> {
    validate_claim(claim)?;
    validate_state_for_claim(claim, state)?;
    if state.claim_mode != ReleaseRecoveryClaimMode::ForwardOnly
        || !state.external_effects_started
        || !matches!(
            state.interrupted_phase,
            ReleaseRecoveryPhase::CandidateStaging
                | ReleaseRecoveryPhase::CandidateSealed
                | ReleaseRecoveryPhase::CandidatePublicationStarted
                | ReleaseRecoveryPhase::AwaitingWorkerFinalize
        )
        || !(1..=MAX_ROUTES).contains(&state.snapshot_count)
    {
        return Err(invalid(
            "release recovery state cannot authorize candidate publication",
        ));
    }
    let candidate = state
        .candidate_artifact
        .as_ref()
        .ok_or_else(|| invalid("release recovery candidate artifact is absent"))?;
    candidate.identity.validate()?;
    if candidate.identity.fleet_run_id != state.fleet_run_id
        || candidate.identity.driver_operation_id != state.driver_operation_id
        || candidate.identity.original_global_fence_token != state.original_global_fence_token
        || candidate.identity.overlay_kind != ReleaseOverlayKind::Candidate
        || candidate.identity.target_slot != state.target_slot
        || state.candidate_selector
            != ReleaseGenerationName::new(state.fleet_run_id, ReleaseOverlayKind::Candidate)
                .selector_target()
    {
        return Err(invalid(
            "release recovery candidate artifact cannot be authorized",
        ));
    }
    let candidate_selector = PriorSelector::from_recorded(
        state.candidate_selector.clone(),
        candidate.directory_device,
        candidate.directory_inode,
    )
    .map_err(DriverError::internal)?;
    let prior_selector = state
        .prior
        .clone()
        .ok_or_else(|| invalid("release recovery prior selector is absent"))?;
    if candidate_selector == prior_selector {
        return Err(invalid(
            "release recovery candidate and prior selectors are equal",
        ));
    }
    Ok(ReleaseRecoveryCandidatePublicationFacts {
        driver_operation_id: claim.driver_operation_id,
        control_operation_id: claim.control_operation.id,
        control_operation_attempt: claim.control_operation.attempt,
        control_operation_owner: claim.control_operation.owner.clone(),
        reconciliation_owner: claim.reconciliation_owner,
        reconciliation_token: claim.reconciliation_token,
        claim_fence: claim.claim_fence,
        fleet_run_id: state.fleet_run_id,
        original_global_fence_token: state.original_global_fence_token,
        target_slot: state.target_slot,
        interrupted_phase: state.interrupted_phase,
        candidate_selector,
        candidate_identity: candidate.identity.clone(),
        route_count: state.snapshot_count,
        prior_selector,
    })
}

#[derive(Clone, Debug, PartialEq)]
pub(super) enum RecordReleaseRecoveryRuntimeObservation {
    Recorded(ReleaseRecoveryRuntimeReceipt),
    Replay(ReleaseRecoveryRuntimeReceipt),
    ClaimLost,
    WrongPhase,
    StateDrift,
    Conflict,
}

impl RecordReleaseRecoveryRuntimeObservation {
    const fn trace_outcome(&self) -> &'static str {
        match self {
            Self::Recorded(_) => "recorded",
            Self::Replay(_) => "replay",
            Self::ClaimLost => "claim_lost",
            Self::WrongPhase => "wrong_phase",
            Self::StateDrift => "state_drift",
            Self::Conflict => "conflict",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum ReleaseRecoveryResolutionKind {
    Candidate,
    Prior,
    Unstarted,
    Inconclusive,
}

impl ReleaseRecoveryResolutionKind {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Candidate => "candidate",
            Self::Prior => "prior",
            Self::Unstarted => "unstarted",
            Self::Inconclusive => "inconclusive",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(super) struct ReleaseRecoveryObservationEvidence {
    pub protocol_version: u8,
    pub driver_operation_id: Uuid,
    pub fleet_run_id: Uuid,
    pub claim_fence: i64,
    pub resolution_kind: ReleaseRecoveryResolutionKind,
    pub observed_selector: Option<String>,
    pub observed_directory_device: Option<i64>,
    pub observed_directory_inode: Option<i64>,
    pub observed_loaded_identity: Option<Value>,
    pub maintenance_artifact: Option<ReleaseRecoveryObservedArtifact>,
    pub candidate_artifact: Option<ReleaseRecoveryObservedArtifact>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct ReleaseRecoveryObservedArtifact {
    pub selector: String,
    pub directory_device: i64,
    pub directory_inode: i64,
    pub loaded_identity: ReleaseOverlayGenerationIdentity,
    pub publication_started: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub(super) struct ReleaseRecoveryObservation {
    pub resolution_kind: ReleaseRecoveryResolutionKind,
    pub selector: Option<String>,
    pub directory_device: Option<u64>,
    pub directory_inode: Option<u64>,
    pub loaded_identity: Option<Value>,
    pub maintenance_artifact: Option<ReleaseRecoveryObservedArtifact>,
    pub candidate_artifact: Option<ReleaseRecoveryObservedArtifact>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ReleaseRecoveryTransition {
    Recorded,
    Sealed,
    Authorized,
    Replay,
    ClaimLost,
    WrongPhase,
    Conflict,
    Invalid,
    OutOfOrder,
    SnapshotDrift,
    DigestMismatch,
    ObservationMismatch,
    UnsupportedResolution,
    RuntimeObservationRequired,
    ObservationAbsent,
}

impl ReleaseRecoveryTransition {
    const fn trace_outcome(self) -> &'static str {
        match self {
            Self::Recorded => "recorded",
            Self::Sealed => "sealed",
            Self::Authorized => "authorized",
            Self::Replay => "replay",
            Self::ClaimLost => "claim_lost",
            Self::WrongPhase => "wrong_phase",
            Self::Conflict => "conflict",
            Self::Invalid => "invalid",
            Self::OutOfOrder => "out_of_order",
            Self::SnapshotDrift => "snapshot_drift",
            Self::DigestMismatch => "digest_mismatch",
            Self::ObservationMismatch => "observation_mismatch",
            Self::UnsupportedResolution => "unsupported_resolution",
            Self::RuntimeObservationRequired => "runtime_observation_required",
            Self::ObservationAbsent => "observation_absent",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ReleaseExchangeAuthorizationKind {
    DisposeOverlay,
    RestorePrior,
    PublishCandidate,
}

impl ReleaseExchangeAuthorizationKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::DisposeOverlay => "dispose_overlay",
            Self::RestorePrior => "restore_prior",
            Self::PublishCandidate => "publish_candidate",
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct ReleaseRecoveryNotApplied {
    pub outcome: String,
    pub driver_operation_id: Uuid,
    pub fleet_run_id: Uuid,
    pub resolution_kind: ReleaseRecoveryResolutionKind,
    pub decision_digest: String,
}

#[derive(Clone, Debug, PartialEq)]
pub(super) enum ReleaseRecoveryTerminal {
    AppliedRecovered(Box<ReleaseRouteCompletionResponse>),
    NotApplied(ReleaseRecoveryNotApplied),
}

#[derive(Clone, Debug, PartialEq)]
pub(super) enum FinishReleaseRecovery {
    Completed(ReleaseRecoveryTerminal),
    Replay(ReleaseRecoveryTerminal),
    Conflict(Option<ReleaseRecoveryTerminal>),
    ClaimLost,
    ResolutionAbsent,
    Blocked,
    DecisionMismatch,
    StateDrift,
    UnsupportedResolution,
    ReviewRequired,
}

impl FinishReleaseRecovery {
    const fn trace_outcome(&self) -> &'static str {
        match self {
            Self::Completed(_) => "completed",
            Self::Replay(_) => "replay",
            Self::Conflict(_) => "conflict",
            Self::ClaimLost => "claim_lost",
            Self::ResolutionAbsent => "resolution_absent",
            Self::Blocked => "blocked",
            Self::DecisionMismatch => "decision_mismatch",
            Self::StateDrift => "state_drift",
            Self::UnsupportedResolution => "unsupported_resolution",
            Self::ReviewRequired => "review_required",
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(super) enum ReadReleaseRecoveryResult {
    NotFound,
    Conflict,
    Pending,
    Quarantined,
    Applied(Box<ReleaseRouteCompletionResponse>),
    AppliedRecovered(Box<ReleaseRouteCompletionResponse>),
    NotApplied(ReleaseRecoveryNotApplied),
}

impl ReadReleaseRecoveryResult {
    const fn trace_outcome(&self) -> &'static str {
        match self {
            Self::NotFound => "not_found",
            Self::Conflict => "conflict",
            Self::Pending => "pending",
            Self::Quarantined => "quarantined",
            Self::Applied(_) => "replay",
            Self::AppliedRecovered(_) => "applied_recovered",
            Self::NotApplied(_) => "not_applied",
        }
    }
}

#[tracing::instrument(name = "deployment_driver.release_route_recovery.discover_dormant", skip_all, fields(page.limit = limit, page.returned = tracing::field::Empty))]
pub(super) async fn discover_interrupted_release_route_publications(
    ledger: &PgPool,
    after: Option<Uuid>,
    limit: usize,
) -> Result<Vec<InterruptedReleaseRoutePublication>, DriverError> {
    if after.is_some_and(|id| id.is_nil()) || !(1..=MAX_DISCOVERY_LIMIT).contains(&limit) {
        return Err(invalid("release recovery discovery request is invalid"));
    }
    let rows: Vec<DiscoveryRow> = sqlx::query_as("select driver_operation_id,fleet_run_id,interrupted_phase,claim_mode,claim_fence,claim_available,maintenance_selector,candidate_selector,updated_at from control.discover_interrupted_immutable_release_route_publications($1,$2)")
        .bind(after).bind(i32::try_from(limit).map_err(DriverError::internal)?)
        .fetch_all(ledger).await.map_err(DriverError::internal)?;
    let parsed = parse_discovery(after, rows)?;
    tracing::Span::current().record("page.returned", parsed.len());
    Ok(parsed)
}

#[tracing::instrument(name = "deployment_driver.release_route_recovery.claim_dormant", skip_all, fields(driver.operation_id = %request.driver_operation_id, claim.outcome = tracing::field::Empty))]
pub(super) async fn claim_interrupted_release_route_publication(
    ledger: &PgPool,
    request: &ReleaseRecoveryClaimRequest,
) -> Result<ReleaseRecoveryClaimResult, DriverError> {
    validate_claim_request(request)?;
    let row: ClaimRow = sqlx::query_as("select outcome,claim_fence,claim_mode from control.claim_interrupted_immutable_release_route_publication($1,$2,$3,$4,$5,$6)")
        .bind(request.driver_operation_id).bind(request.control_operation.attempt)
        .bind(&request.control_operation.owner).bind(request.reconciliation_owner)
        .bind(request.reconciliation_token).bind(request.ttl_seconds)
        .fetch_one(ledger).await.map_err(DriverError::internal)?;
    let parsed = parse_claim(request, row);
    record_parsed_outcome("claim.outcome", &parsed, |result| {
        result.outcome.trace_outcome()
    });
    parsed
}

#[tracing::instrument(name = "deployment_driver.release_route_recovery.renew_dormant", skip_all, fields(driver.operation_id = %claim.driver_operation_id, claim.renewed = tracing::field::Empty))]
pub(super) async fn renew_interrupted_release_route_claim(
    ledger: &PgPool,
    claim: &ReleaseRecoveryClaim,
) -> Result<bool, DriverError> {
    validate_claim(claim)?;
    let renewed: bool = sqlx::query_scalar("select control.renew_interrupted_immutable_release_route_publication_claim($1,$2,$3,$4,$5,$6,$7)")
        .bind(claim.driver_operation_id).bind(claim.control_operation.attempt)
        .bind(&claim.control_operation.owner).bind(claim.reconciliation_owner)
        .bind(claim.reconciliation_token).bind(claim.claim_fence).bind(claim.ttl_seconds)
        .fetch_one(ledger).await.map_err(DriverError::internal)?;
    tracing::Span::current().record("claim.renewed", renewed);
    Ok(renewed)
}

#[tracing::instrument(name = "deployment_driver.release_route_recovery.read_state_dormant", skip_all, fields(driver.operation_id = %claim.driver_operation_id, state.outcome = tracing::field::Empty))]
pub(super) async fn read_interrupted_release_route_state(
    ledger: &PgPool,
    claim: &ReleaseRecoveryClaim,
) -> Result<(ReadReleaseRecoveryState, Option<ReleaseRecoveryState>), DriverError> {
    validate_claim(claim)?;
    let row: StateRow = sqlx::query_as("select outcome,state from control.read_interrupted_immutable_release_route_publication_state($1,$2,$3,$4,$5,$6)")
        .bind(claim.driver_operation_id).bind(claim.control_operation.attempt)
        .bind(&claim.control_operation.owner).bind(claim.reconciliation_owner)
        .bind(claim.reconciliation_token).bind(claim.claim_fence)
        .fetch_one(ledger).await.map_err(DriverError::internal)?;
    let parsed =
        match (row.0.as_str(), row.1) {
            ("claimed", Some(value)) => parse_state(claim, value)
                .map(|state| (ReadReleaseRecoveryState::Claimed, Some(state))),
            ("claim_lost", Some(value)) => parse_state_identity(claim, &value)
                .map(|()| (ReadReleaseRecoveryState::ClaimLost, None)),
            ("terminal", Some(value)) => parse_state_identity(claim, &value)
                .map(|()| (ReadReleaseRecoveryState::Terminal, None)),
            ("not_found", None) => Ok((ReadReleaseRecoveryState::NotFound, None)),
            _ => Err(invalid("release recovery state response is malformed")),
        };
    record_parsed_outcome("state.outcome", &parsed, |result| result.0.trace_outcome());
    parsed
}

/// Read the immutable protocol-v2 snapshot only through the current recovery
/// claim. A distinct completion sentinel prevents an expired or malformed
/// capability from being mistaken for the end of a keyset scan.
#[tracing::instrument(name = "deployment_driver.release_route_recovery.read_snapshot_dormant", skip_all, fields(driver.operation_id = %claim.driver_operation_id, page.limit = limit, page.outcome = tracing::field::Empty, page.returned = tracing::field::Empty))]
pub(super) async fn read_interrupted_release_route_snapshot_batch(
    ledger: &PgPool,
    claim: &ReleaseRecoveryClaim,
    state: &ReleaseRecoveryState,
    after: Option<Uuid>,
    limit: usize,
) -> Result<ReadReleaseRecoverySnapshot, DriverError> {
    validate_claim(claim)?;
    validate_state_for_claim(claim, state)?;
    if state.claim_mode != ReleaseRecoveryClaimMode::ForwardOnly
        || state.interrupted_phase != ReleaseRecoveryPhase::CandidateStaging
        || !state.external_effects_started
        || after.is_some_and(|id| id.is_nil())
        || !(1..=MAX_ROUTES).contains(&limit)
    {
        return Err(invalid("release recovery snapshot request is invalid"));
    }
    let rows: Vec<RecoverySnapshotRow> = sqlx::query_as(
        "select outcome,workshop_id,database_id,database_ref,paperless_enabled,generation,
         projection_digest,disposition,canonical_projection,applied_rendered_digest,applied_fence_token,
         route_fence_token,target_slot
         from control.read_interrupted_immutable_release_route_snapshot_batch(
          $1,$2,$3,$4,$5,$6,$7,$8)",
    )
    .bind(claim.driver_operation_id)
    .bind(claim.control_operation.attempt)
    .bind(&claim.control_operation.owner)
    .bind(claim.reconciliation_owner)
    .bind(claim.reconciliation_token)
    .bind(claim.claim_fence)
    .bind(after)
    .bind(i32::try_from(limit).map_err(DriverError::internal)?)
    .fetch_all(ledger)
    .await
    .map_err(DriverError::internal)?;
    let parsed = parse_recovery_snapshot_rows(state, after, limit, rows)?;
    let (outcome, returned) = match &parsed {
        ReadReleaseRecoverySnapshot::Page(items) => ("claimed", items.len()),
        ReadReleaseRecoverySnapshot::Complete => ("complete", 0),
        ReadReleaseRecoverySnapshot::ClaimLost => ("claim_lost", 0),
        ReadReleaseRecoverySnapshot::WrongPhase => ("wrong_phase", 0),
    };
    tracing::Span::current().record("page.outcome", outcome);
    tracing::Span::current().record("page.returned", returned);
    Ok(parsed)
}

/// Read only database-owned expected inputs. Live runtime facts remain the
/// responsibility of an independent observer and are deliberately absent.
#[tracing::instrument(name = "deployment_driver.release_route_recovery.read_runtime_expectation_dormant", skip_all, fields(driver.operation_id = %claim.driver_operation_id, runtime.outcome = tracing::field::Empty))]
pub(super) async fn read_interrupted_release_runtime_expectation(
    ledger: &PgPool,
    claim: &ReleaseRecoveryClaim,
    state: &ReleaseRecoveryState,
) -> Result<ReadReleaseRecoveryRuntimeExpectation, DriverError> {
    validate_claim(claim)?;
    validate_state_for_claim(claim, state)?;
    if state.claim_mode != ReleaseRecoveryClaimMode::ForwardOnly
        || !matches!(
            state.interrupted_phase,
            ReleaseRecoveryPhase::CandidateStaging
                | ReleaseRecoveryPhase::CandidateSealed
                | ReleaseRecoveryPhase::CandidatePublicationStarted
                | ReleaseRecoveryPhase::AwaitingWorkerFinalize
        )
        || !state.external_effects_started
    {
        return Err(invalid(
            "release recovery runtime expectation request is invalid",
        ));
    }
    let row: RuntimeExpectationRow = sqlx::query_as(
        "select outcome,expectation
         from control.read_interrupted_immutable_release_runtime_expectation(
          $1,$2,$3,$4,$5,$6)",
    )
    .bind(claim.driver_operation_id)
    .bind(claim.control_operation.attempt)
    .bind(&claim.control_operation.owner)
    .bind(claim.reconciliation_owner)
    .bind(claim.reconciliation_token)
    .bind(claim.claim_fence)
    .fetch_one(ledger)
    .await
    .map_err(DriverError::internal)?;
    let parsed = parse_runtime_expectation(claim, state, row);
    record_parsed_outcome("runtime.outcome", &parsed, |result| result.trace_outcome());
    parsed
}

#[tracing::instrument(name = "deployment_driver.release_route_recovery.record_runtime_observation_dormant", skip_all, fields(driver.operation_id = %claim.driver_operation_id, runtime.outcome = tracing::field::Empty))]
pub(super) async fn record_interrupted_release_runtime_observation(
    ledger: &PgPool,
    claim: &ReleaseRecoveryClaim,
    state: &ReleaseRecoveryState,
    expectation: &ReleaseRecoveryRuntimeExpectation,
    observation: &VerifiedReleaseRuntimeObservation,
) -> Result<RecordReleaseRecoveryRuntimeObservation, DriverError> {
    validate_claim(claim)?;
    validate_state_for_claim(claim, state)?;
    validate_runtime_expectation(claim, state, expectation)?;
    observation.validate_for_recovery_expectation(expectation)?;
    let observation_json = observation.as_database_value()?;
    validate_json(
        &observation_json,
        MAX_EVIDENCE_BYTES,
        "release recovery runtime observation",
    )?;
    let row: RuntimeObservationRow = sqlx::query_as(
        "select outcome,observation_digest,completion_response
         from control.record_interrupted_immutable_release_runtime_observation(
          $1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(claim.driver_operation_id)
    .bind(claim.control_operation.attempt)
    .bind(&claim.control_operation.owner)
    .bind(claim.reconciliation_owner)
    .bind(claim.reconciliation_token)
    .bind(claim.claim_fence)
    .bind(observation_json)
    .fetch_one(ledger)
    .await
    .map_err(DriverError::internal)?;
    let parsed = parse_runtime_observation_receipt(claim, state, expectation, row);
    record_parsed_outcome("runtime.outcome", &parsed, |result| result.trace_outcome());
    parsed
}

#[tracing::instrument(name = "deployment_driver.release_route_recovery.record_candidate_dormant", skip_all, fields(driver.operation_id = %claim.driver_operation_id, transition.outcome = tracing::field::Empty))]
pub(super) async fn record_release_recovery_candidate_entry(
    ledger: &PgPool,
    claim: &ReleaseRecoveryClaim,
    workshop_id: Uuid,
    generation: i64,
    projection_digest: &str,
    applied_rendered_digest: &str,
    rendered_digest: &str,
) -> Result<ReleaseRecoveryTransition, DriverError> {
    validate_claim(claim)?;
    if workshop_id.is_nil()
        || generation <= 0
        || [projection_digest, applied_rendered_digest, rendered_digest]
            .iter()
            .any(|d| validate_digest(d, "release recovery route digest").is_err())
    {
        return Err(invalid("release recovery candidate record is invalid"));
    }
    let outcome: String = sqlx::query_scalar("select control.record_interrupted_immutable_release_route_candidate_entry($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)")
        .bind(claim.driver_operation_id).bind(claim.control_operation.attempt).bind(&claim.control_operation.owner)
        .bind(claim.reconciliation_owner).bind(claim.reconciliation_token).bind(claim.claim_fence)
        .bind(workshop_id).bind(generation).bind(projection_digest).bind(applied_rendered_digest).bind(rendered_digest)
        .fetch_one(ledger).await.map_err(DriverError::internal)?;
    let parsed = parse_transition(&outcome);
    record_parsed_outcome("transition.outcome", &parsed, |result| {
        result.trace_outcome()
    });
    parsed
}

#[tracing::instrument(name = "deployment_driver.release_route_recovery.seal_candidate_dormant", skip_all, fields(driver.operation_id = %claim.driver_operation_id, transition.outcome = tracing::field::Empty))]
pub(super) async fn seal_release_recovery_candidate(
    ledger: &PgPool,
    claim: &ReleaseRecoveryClaim,
    selector: &PriorSelector,
    record_count: usize,
    route_set_digest: &str,
) -> Result<ReleaseRecoveryTransition, DriverError> {
    validate_claim(claim)?;
    if !(1..=MAX_ROUTES).contains(&record_count)
        || validate_digest(route_set_digest, "release recovery route-set digest").is_err()
    {
        return Err(invalid("release recovery candidate seal is invalid"));
    }
    let outcome: String = sqlx::query_scalar("select control.seal_interrupted_immutable_release_route_candidate($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)")
        .bind(claim.driver_operation_id).bind(claim.control_operation.attempt).bind(&claim.control_operation.owner)
        .bind(claim.reconciliation_owner).bind(claim.reconciliation_token).bind(claim.claim_fence)
        .bind(selector.target()).bind(pg_identity(selector.directory_device())?).bind(pg_identity(selector.directory_inode())?)
        .bind(i32::try_from(record_count).map_err(DriverError::internal)?).bind(route_set_digest)
        .fetch_one(ledger).await.map_err(DriverError::internal)?;
    let parsed = parse_transition(&outcome);
    record_parsed_outcome("transition.outcome", &parsed, |result| {
        result.trace_outcome()
    });
    parsed
}

#[tracing::instrument(name = "deployment_driver.release_route_recovery.authorize_exchange_dormant", skip_all, fields(driver.operation_id = %claim.driver_operation_id, authorization.kind = kind.as_str(), transition.outcome = tracing::field::Empty))]
pub(super) async fn authorize_release_recovery_exchange(
    ledger: &PgPool,
    claim: &ReleaseRecoveryClaim,
    kind: ReleaseExchangeAuthorizationKind,
    overlay_kind: Option<ReleaseOverlayKind>,
) -> Result<ReleaseRecoveryTransition, DriverError> {
    validate_claim(claim)?;
    let shape_is_valid = match kind {
        ReleaseExchangeAuthorizationKind::DisposeOverlay => overlay_kind.is_some(),
        ReleaseExchangeAuthorizationKind::RestorePrior => overlay_kind.is_none(),
        ReleaseExchangeAuthorizationKind::PublishCandidate => false,
    };
    if !shape_is_valid {
        return Err(invalid(
            "release recovery authorization response is invalid",
        ));
    }
    let outcome: String = sqlx::query_scalar("select control.authorize_interrupted_immutable_release_route_exchange($1,$2,$3,$4,$5,$6,$7,$8,$9)")
        .bind(claim.driver_operation_id).bind(claim.control_operation.attempt).bind(&claim.control_operation.owner)
        .bind(claim.reconciliation_owner).bind(claim.reconciliation_token).bind(claim.claim_fence)
        .bind(kind.as_str()).bind(overlay_kind.map(ReleaseOverlayKind::as_str)).bind(Option::<Value>::None)
        .fetch_one(ledger).await.map_err(DriverError::internal)?;
    let parsed = parse_transition(&outcome);
    record_parsed_outcome("transition.outcome", &parsed, |result| {
        result.trace_outcome()
    });
    parsed
}

#[tracing::instrument(name = "deployment_driver.release_route_recovery.authorize_candidate_from_observation_dormant", skip_all, fields(driver.operation_id = %claim.driver_operation_id, transition.outcome = tracing::field::Empty))]
pub(super) async fn authorize_release_recovery_candidate_from_observation(
    ledger: &PgPool,
    claim: &ReleaseRecoveryClaim,
    state: &ReleaseRecoveryState,
    observation_digest: &str,
) -> Result<
    (
        ReleaseRecoveryTransition,
        Option<ReleaseRecoveryCandidatePublicationAuthorization>,
    ),
    DriverError,
> {
    validate_claim(claim)?;
    validate_state_for_claim(claim, state)?;
    if !digest(observation_digest) {
        return Err(invalid("release recovery observation digest is invalid"));
    }
    let outcome: String = sqlx::query_scalar("select control.authorize_interrupted_immutable_release_route_candidate_from_observation($1,$2,$3,$4,$5,$6,$7)")
        .bind(claim.driver_operation_id).bind(claim.control_operation.attempt).bind(&claim.control_operation.owner)
        .bind(claim.reconciliation_owner).bind(claim.reconciliation_token).bind(claim.claim_fence)
        .bind(observation_digest).fetch_one(ledger).await.map_err(DriverError::internal)?;
    let parsed = parse_transition(&outcome);
    record_parsed_outcome("transition.outcome", &parsed, |result| {
        result.trace_outcome()
    });
    let transition = parsed?;
    let authorization = if matches!(
        transition,
        ReleaseRecoveryTransition::Authorized | ReleaseRecoveryTransition::Replay
    ) {
        Some(ReleaseRecoveryCandidatePublicationAuthorization::mint(
            claim,
            state,
            observation_digest,
        )?)
    } else {
        None
    };
    Ok((transition, authorization))
}

/// Candidate resolution accepts only the opaque result of the guarded local /
/// runtime / local observer. This prevents a coordinator from assembling
/// positive candidate evidence from individually plausible fields.
#[tracing::instrument(name = "deployment_driver.release_route_recovery.resolve_candidate_dormant", skip_all, fields(driver.operation_id = %claim.driver_operation_id, resolution.kind = "candidate", transition.outcome = tracing::field::Empty))]
pub(super) async fn resolve_interrupted_release_candidate_route_observation(
    ledger: &PgPool,
    claim: &ReleaseRecoveryClaim,
    state: &ReleaseRecoveryState,
    observation: &VerifiedReleaseRecoveryRouteObservation,
) -> Result<
    (
        ReleaseRecoveryTransition,
        ReleaseRecoveryObservationEvidence,
    ),
    DriverError,
> {
    resolve_interrupted_release_route_publication(
        ledger,
        claim,
        state,
        observation.database_observation(),
    )
    .await
}

async fn resolve_interrupted_release_route_publication(
    ledger: &PgPool,
    claim: &ReleaseRecoveryClaim,
    state: &ReleaseRecoveryState,
    observation: &ReleaseRecoveryObservation,
) -> Result<
    (
        ReleaseRecoveryTransition,
        ReleaseRecoveryObservationEvidence,
    ),
    DriverError,
> {
    validate_claim(claim)?;
    validate_state_for_claim(claim, state)?;
    validate_observation(claim, state, observation)?;
    let evidence = ReleaseRecoveryObservationEvidence {
        protocol_version: 1,
        driver_operation_id: state.driver_operation_id,
        fleet_run_id: state.fleet_run_id,
        claim_fence: claim.claim_fence,
        resolution_kind: observation.resolution_kind,
        observed_selector: observation.selector.clone(),
        observed_directory_device: observation.directory_device.map(pg_identity).transpose()?,
        observed_directory_inode: observation.directory_inode.map(pg_identity).transpose()?,
        observed_loaded_identity: observation.loaded_identity.clone(),
        maintenance_artifact: observation.maintenance_artifact.clone(),
        candidate_artifact: observation.candidate_artifact.clone(),
    };
    let evidence_json = serde_json::to_value(&evidence).map_err(DriverError::internal)?;
    validate_json(
        &evidence_json,
        MAX_EVIDENCE_BYTES,
        "release recovery observation evidence",
    )?;
    let outcome: String = sqlx::query_scalar("select control.resolve_interrupted_immutable_release_route_publication($1,$2,$3,$4,$5,$6,$7,$8,$9)")
        .bind(claim.driver_operation_id).bind(claim.control_operation.attempt).bind(&claim.control_operation.owner)
        .bind(claim.reconciliation_owner).bind(claim.reconciliation_token).bind(claim.claim_fence)
        .bind(observation.resolution_kind.as_str()).bind(evidence_json).bind(Option::<Value>::None)
        .fetch_one(ledger).await.map_err(DriverError::internal)?;
    let parsed = parse_transition(&outcome);
    record_parsed_outcome("transition.outcome", &parsed, |result| {
        result.trace_outcome()
    });
    Ok((parsed?, evidence))
}

/// The digest must come from a separate review step. PostgreSQL recomputes it
/// from the immutable JSONB evidence before making any terminal transition.
#[tracing::instrument(name = "deployment_driver.release_route_recovery.finish_dormant", skip_all, fields(driver.operation_id = %claim.driver_operation_id, resolution.kind = resolution_kind.as_str(), terminal.outcome = tracing::field::Empty))]
pub(super) async fn finish_interrupted_release_route_publication(
    ledger: &PgPool,
    claim: &ReleaseRecoveryClaim,
    state: &ReleaseRecoveryState,
    resolution_kind: ReleaseRecoveryResolutionKind,
    reviewed_decision_digest: &str,
) -> Result<FinishReleaseRecovery, DriverError> {
    validate_claim(claim)?;
    validate_state_for_claim(claim, state)?;
    if matches!(
        resolution_kind,
        ReleaseRecoveryResolutionKind::Candidate | ReleaseRecoveryResolutionKind::Inconclusive
    ) || !digest(reviewed_decision_digest)
    {
        return Err(invalid("release recovery terminal decision is invalid"));
    }
    let row: FinishRow = sqlx::query_as("select outcome,stored_response from control.finish_interrupted_immutable_release_route_publication($1,$2,$3,$4,$5,$6,$7,$8)")
        .bind(claim.driver_operation_id).bind(claim.control_operation.attempt).bind(&claim.control_operation.owner)
        .bind(claim.reconciliation_owner).bind(claim.reconciliation_token).bind(claim.claim_fence)
        .bind(resolution_kind.as_str()).bind(reviewed_decision_digest)
        .fetch_one(ledger).await.map_err(DriverError::internal)?;
    let parsed = parse_finish(claim, state, resolution_kind, reviewed_decision_digest, row);
    record_parsed_outcome("terminal.outcome", &parsed, |result| result.trace_outcome());
    parsed
}

#[tracing::instrument(name = "deployment_driver.release_route_recovery.finish_reviewed_candidate_dormant", skip_all, fields(driver.operation_id = %claim.driver_operation_id, terminal.outcome = tracing::field::Empty))]
pub(super) async fn finish_reviewed_interrupted_release_route_publication(
    ledger: &PgPool,
    claim: &ReleaseRecoveryClaim,
    state: &ReleaseRecoveryState,
) -> Result<FinishReleaseRecovery, DriverError> {
    validate_claim(claim)?;
    validate_state_for_claim(claim, state)?;
    if claim.claim_mode != ReleaseRecoveryClaimMode::ForwardOnly {
        return Err(invalid("reviewed release recovery finish mode is invalid"));
    }
    let row: FinishRow = sqlx::query_as(
        "select outcome,stored_response
         from control.finish_reviewed_interrupted_immutable_release_route_publication(
          $1,$2,$3,$4,$5,$6)",
    )
    .bind(claim.driver_operation_id)
    .bind(claim.control_operation.attempt)
    .bind(&claim.control_operation.owner)
    .bind(claim.reconciliation_owner)
    .bind(claim.reconciliation_token)
    .bind(claim.claim_fence)
    .fetch_one(ledger)
    .await
    .map_err(DriverError::internal)?;
    let parsed = if row.0 == "review_required" && row.1.is_none() {
        Ok(FinishReleaseRecovery::ReviewRequired)
    } else {
        parse_finish(
            claim,
            state,
            ReleaseRecoveryResolutionKind::Candidate,
            "",
            row,
        )
    };
    record_parsed_outcome("terminal.outcome", &parsed, |result| result.trace_outcome());
    parsed
}

#[tracing::instrument(name = "deployment_driver.release_route_recovery.read_result_dormant", skip_all, fields(driver.operation_id = %driver_operation_id, result.outcome = tracing::field::Empty))]
pub(super) async fn read_release_recovery_result(
    ledger: &PgPool,
    driver_operation_id: Uuid,
    fleet_run_id: Uuid,
) -> Result<ReadReleaseRecoveryResult, DriverError> {
    if driver_operation_id.is_nil() || fleet_run_id.is_nil() {
        return Err(invalid("release recovery result identity is invalid"));
    }
    let row: FinishRow = sqlx::query_as(
        "select outcome,stored_response from control.read_immutable_release_route_publication_result($1,$2)",
    )
    .bind(driver_operation_id)
    .bind(fleet_run_id)
    .fetch_one(ledger)
    .await
    .map_err(DriverError::internal)?;
    let parsed = match (row.0.as_str(), row.1) {
        ("not_found", None) => Ok(ReadReleaseRecoveryResult::NotFound),
        ("conflict", None) => Ok(ReadReleaseRecoveryResult::Conflict),
        ("pending", None) => Ok(ReadReleaseRecoveryResult::Pending),
        ("quarantined", None) => Ok(ReadReleaseRecoveryResult::Quarantined),
        ("replay", Some(value)) => parse_terminal_unbound(driver_operation_id, fleet_run_id, value)
            .and_then(|terminal| match terminal {
                ReleaseRecoveryTerminal::AppliedRecovered(response) => {
                    Ok(ReadReleaseRecoveryResult::Applied(response))
                }
                ReleaseRecoveryTerminal::NotApplied(_) => {
                    Err(invalid("release recovery replay response is malformed"))
                }
            }),
        ("applied_recovered", Some(value)) => {
            parse_terminal_unbound(driver_operation_id, fleet_run_id, value).and_then(|terminal| {
                match terminal {
                    ReleaseRecoveryTerminal::AppliedRecovered(response) => {
                        Ok(ReadReleaseRecoveryResult::AppliedRecovered(response))
                    }
                    ReleaseRecoveryTerminal::NotApplied(_) => {
                        Err(invalid("release recovered result is malformed"))
                    }
                }
            })
        }
        ("not_applied", Some(value)) => {
            parse_terminal_unbound(driver_operation_id, fleet_run_id, value).and_then(|terminal| {
                match terminal {
                    ReleaseRecoveryTerminal::NotApplied(response) => {
                        Ok(ReadReleaseRecoveryResult::NotApplied(response))
                    }
                    ReleaseRecoveryTerminal::AppliedRecovered(_) => {
                        Err(invalid("release not-applied result is malformed"))
                    }
                }
            })
        }
        _ => Err(invalid("release recovery result row is malformed")),
    };
    record_parsed_outcome("result.outcome", &parsed, |result| result.trace_outcome());
    parsed
}

fn record_parsed_outcome<T>(
    field: &'static str,
    parsed: &Result<T, DriverError>,
    outcome: impl FnOnce(&T) -> &'static str,
) {
    tracing::Span::current().record(field, parsed.as_ref().map_or("contract_drift", outcome));
}

fn parse_discovery(
    after: Option<Uuid>,
    rows: Vec<DiscoveryRow>,
) -> Result<Vec<InterruptedReleaseRoutePublication>, DriverError> {
    let mut result = Vec::with_capacity(rows.len());
    let mut previous = after;
    for row in rows {
        if row.0.is_nil()
            || row.1.is_nil()
            || row.4 < 0
            || previous.is_some_and(|id| id >= row.0)
            || validate_selector_target(&row.6).is_err()
            || validate_selector_target(&row.7).is_err()
            || row.6 == row.7
        {
            return Err(invalid("release recovery discovery row is invalid"));
        }
        let phase = ReleaseRecoveryPhase::parse(&row.2)
            .ok_or_else(|| invalid("release recovery phase is invalid"))?;
        let mode = ReleaseRecoveryClaimMode::parse(&row.3)
            .ok_or_else(|| invalid("release recovery claim mode is invalid"))?;
        previous = Some(row.0);
        result.push(InterruptedReleaseRoutePublication {
            driver_operation_id: row.0,
            fleet_run_id: row.1,
            interrupted_phase: phase,
            claim_mode: mode,
            claim_fence: row.4,
            claim_available: row.5,
            maintenance_selector: row.6,
            candidate_selector: row.7,
            updated_at: row.8,
        });
    }
    Ok(result)
}

fn parse_recovery_snapshot_rows(
    state: &ReleaseRecoveryState,
    after: Option<Uuid>,
    limit: usize,
    rows: Vec<RecoverySnapshotRow>,
) -> Result<ReadReleaseRecoverySnapshot, DriverError> {
    if rows.is_empty() || rows.len() > limit {
        return Err(invalid("release recovery snapshot response is malformed"));
    }
    if rows.len() == 1 && rows[0].0 != "claimed" {
        let row = rows.into_iter().next().expect("one row was checked");
        let sentinel_is_empty = row.1.is_none()
            && row.2.is_none()
            && row.3.is_none()
            && row.4.is_none()
            && row.5.is_none()
            && row.6.is_none()
            && row.7.is_none()
            && row.8.is_none()
            && row.9.is_none()
            && row.10.is_none()
            && row.11.is_none()
            && row.12.is_none();
        if !sentinel_is_empty {
            return Err(invalid("release recovery snapshot sentinel is malformed"));
        }
        return match row.0.as_str() {
            "complete" => Ok(ReadReleaseRecoverySnapshot::Complete),
            "claim_lost" => Ok(ReadReleaseRecoverySnapshot::ClaimLost),
            "wrong_phase" => Ok(ReadReleaseRecoverySnapshot::WrongPhase),
            _ => Err(invalid("release recovery snapshot outcome is invalid")),
        };
    }
    let mut snapshot_rows = Vec::with_capacity(rows.len());
    for row in rows {
        let (
            outcome,
            workshop_id,
            database_id,
            database_ref,
            paperless_enabled,
            generation,
            projection_digest,
            disposition,
            canonical_projection,
            applied_rendered_digest,
            applied_fence_token,
            route_fence_token,
            target_slot,
        ) = row;
        if outcome != "claimed" {
            return Err(invalid("release recovery snapshot outcomes are mixed"));
        }
        if disposition.as_deref() != Some("present") {
            return Err(invalid("release recovery disposition is invalid"));
        }
        snapshot_rows.push((
            workshop_id.ok_or_else(|| invalid("release recovery workshop is absent"))?,
            database_id.ok_or_else(|| invalid("release recovery database is absent"))?,
            database_ref.ok_or_else(|| invalid("release recovery database reference is absent"))?,
            paperless_enabled
                .ok_or_else(|| invalid("release recovery Paperless state is absent"))?,
            generation.ok_or_else(|| invalid("release recovery generation is absent"))?,
            projection_digest
                .ok_or_else(|| invalid("release recovery projection digest is absent"))?,
            canonical_projection.ok_or_else(|| invalid("release recovery projection is absent"))?,
            applied_rendered_digest
                .ok_or_else(|| invalid("release recovery rendered digest is absent"))?,
            applied_fence_token
                .ok_or_else(|| invalid("release recovery applied fence is absent"))?,
            route_fence_token.ok_or_else(|| invalid("release recovery route fence is absent"))?,
            target_slot.ok_or_else(|| invalid("release recovery target slot is absent"))?,
        ));
    }
    if snapshot_rows.len() > state.snapshot_count {
        return Err(invalid("release recovery snapshot exceeds frozen count"));
    }
    Ok(ReadReleaseRecoverySnapshot::Page(
        validate_release_snapshot_rows(state.target_slot, None, after, limit, snapshot_rows)?,
    ))
}

fn parse_claim(
    request: &ReleaseRecoveryClaimRequest,
    row: ClaimRow,
) -> Result<ReleaseRecoveryClaimResult, DriverError> {
    let outcome = match row.0.as_str() {
        "acquired" => ClaimReleaseRecovery::Acquired,
        "replay" => ClaimReleaseRecovery::Replay,
        "busy" => ClaimReleaseRecovery::Busy,
        "terminal" => ClaimReleaseRecovery::Terminal,
        "invalid" => ClaimReleaseRecovery::Invalid,
        "not_found" => ClaimReleaseRecovery::NotFound,
        "protocol_incompatible" => ClaimReleaseRecovery::ProtocolIncompatible,
        "authority_lost" => ClaimReleaseRecovery::AuthorityLost,
        "not_expired" => ClaimReleaseRecovery::NotExpired,
        "authority_inconsistent" => ClaimReleaseRecovery::AuthorityInconsistent,
        _ => return Err(invalid("release recovery claim outcome is invalid")),
    };
    let owns_claim = matches!(
        outcome,
        ClaimReleaseRecovery::Acquired | ClaimReleaseRecovery::Replay
    );
    let observed = match (row.1, row.2.as_deref()) {
        (Some(fence), Some(mode)) if fence > 0 => Some((
            fence,
            ReleaseRecoveryClaimMode::parse(mode)
                .ok_or_else(|| invalid("release recovery claim mode is invalid"))?,
        )),
        (None, None)
            if !matches!(
                outcome,
                ClaimReleaseRecovery::Acquired
                    | ClaimReleaseRecovery::Replay
                    | ClaimReleaseRecovery::Busy
                    | ClaimReleaseRecovery::Terminal
            ) =>
        {
            None
        }
        _ => return Err(invalid("release recovery claim row is malformed")),
    };
    let claim = match (owns_claim, observed) {
        (true, Some((fence, mode))) => Some(ReleaseRecoveryClaim {
            driver_operation_id: request.driver_operation_id,
            control_operation: request.control_operation.clone(),
            reconciliation_owner: request.reconciliation_owner,
            reconciliation_token: request.reconciliation_token,
            claim_fence: fence,
            claim_mode: mode,
            ttl_seconds: request.ttl_seconds,
        }),
        (false, _) => None,
        _ => return Err(invalid("release recovery claim row is malformed")),
    };
    Ok(ReleaseRecoveryClaimResult {
        outcome,
        claim,
        observed_claim_fence: observed.map(|value| value.0),
        observed_claim_mode: observed.map(|value| value.1),
    })
}

fn parse_state(
    claim: &ReleaseRecoveryClaim,
    value: Value,
) -> Result<ReleaseRecoveryState, DriverError> {
    parse_state_identity(claim, &value)?;
    let raw: RawRecoveryState = serde_json::from_value(value).map_err(DriverError::internal)?;
    let count = usize::try_from(raw.snapshot_count)
        .ok()
        .filter(|n| (1..=MAX_ROUTES).contains(n))
        .ok_or_else(|| invalid("release recovery snapshot count is invalid"))?;
    if raw.original_global_fence_token <= 0 {
        return Err(invalid("release recovery global fence is invalid"));
    }
    validate_selector_target(&raw.maintenance_selector).map_err(DriverError::internal)?;
    validate_selector_target(&raw.candidate_selector).map_err(DriverError::internal)?;
    if raw.maintenance_selector == raw.candidate_selector
        || raw.maintenance_selector
            != ReleaseGenerationName::new(raw.fleet_run_id, ReleaseOverlayKind::Maintenance)
                .selector_target()
        || raw.candidate_selector
            != ReleaseGenerationName::new(raw.fleet_run_id, ReleaseOverlayKind::Candidate)
                .selector_target()
    {
        return Err(invalid("release recovery selectors are invalid"));
    }
    let maintenance_artifact = parse_artifact(&raw, ReleaseOverlayKind::Maintenance)?;
    let candidate_artifact = parse_artifact(&raw, ReleaseOverlayKind::Candidate)?;
    let prior = parse_prior(
        raw.prior_selector,
        raw.prior_directory_device,
        raw.prior_directory_inode,
    )?;
    if prior.is_none() && raw.prior_loaded_identity.is_some() {
        return Err(invalid(
            "release recovery prior loaded identity is orphaned",
        ));
    }
    let expected_mode = if raw.external_effects_started_at.is_some() {
        ReleaseRecoveryClaimMode::ForwardOnly
    } else if matches!(
        raw.interrupted_phase,
        ReleaseRecoveryPhase::MaintenancePublicationStarted
            | ReleaseRecoveryPhase::MaintenanceObserved
    ) {
        ReleaseRecoveryClaimMode::RestorePrior
    } else {
        ReleaseRecoveryClaimMode::WriteCleanup
    };
    if raw.claim_mode != expected_mode {
        return Err(invalid("release recovery phase and claim mode differ"));
    }
    let state = ReleaseRecoveryState {
        driver_operation_id: raw.driver_operation_id,
        fleet_run_id: raw.fleet_run_id,
        claim_fence: raw.claim_fence,
        claim_mode: raw.claim_mode,
        interrupted_phase: raw.interrupted_phase,
        target_slot: raw.target_slot,
        original_global_fence_token: raw.original_global_fence_token,
        snapshot_count: count,
        prior,
        prior_loaded_identity: raw.prior_loaded_identity,
        maintenance_selector: raw.maintenance_selector,
        maintenance_artifact,
        candidate_selector: raw.candidate_selector,
        candidate_artifact,
        external_effects_started: raw.external_effects_started_at.is_some(),
    };
    validate_state_for_claim(claim, &state)?;
    Ok(state)
}

fn parse_state_identity(claim: &ReleaseRecoveryClaim, value: &Value) -> Result<(), DriverError> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid("release recovery state is not an object"))?;
    if object.len() != 21
        || object.get("driver_operation_id").and_then(Value::as_str)
            != Some(&claim.driver_operation_id.to_string())
        || object.get("claim_fence").and_then(Value::as_i64) != Some(claim.claim_fence)
    {
        return Err(invalid("release recovery state identity differs"));
    }
    Ok(())
}

fn parse_prior(
    target: Option<String>,
    device: Option<i64>,
    inode: Option<i64>,
) -> Result<Option<PriorSelector>, DriverError> {
    match (target, device, inode) {
        (None, None, None) => Ok(None),
        (Some(target), Some(device), Some(inode)) => Ok(Some(
            PriorSelector::from_recorded(target, positive_u64(device)?, positive_u64(inode)?)
                .map_err(DriverError::internal)?,
        )),
        _ => Err(invalid("release recovery prior identity is incomplete")),
    }
}

fn parse_artifact(
    state: &RawRecoveryState,
    overlay_kind: ReleaseOverlayKind,
) -> Result<Option<ReleaseRecoveryArtifact>, DriverError> {
    let (route_digest, device, inode) = match overlay_kind {
        ReleaseOverlayKind::Maintenance => (
            state.maintenance_route_set_digest.as_ref(),
            state.maintenance_directory_device,
            state.maintenance_directory_inode,
        ),
        ReleaseOverlayKind::Candidate => (
            state.candidate_route_set_digest.as_ref(),
            state.candidate_directory_device,
            state.candidate_directory_inode,
        ),
    };
    match (route_digest, device, inode) {
        (None, None, None) => Ok(None),
        (Some(route_digest), Some(device), Some(inode)) => {
            validate_digest(route_digest, "release recovery route-set digest")
                .map_err(DriverError::internal)?;
            let identity = ReleaseOverlayGenerationIdentity::new(
                state.fleet_run_id,
                state.driver_operation_id,
                state.original_global_fence_token,
                overlay_kind,
                route_digest.clone(),
                state.target_slot.as_str(),
            )?;
            Ok(Some(ReleaseRecoveryArtifact {
                identity,
                directory_device: positive_u64(device)?,
                directory_inode: positive_u64(inode)?,
            }))
        }
        _ => Err(invalid(
            "release recovery generation identity is incomplete",
        )),
    }
}

fn validate_claim_request(request: &ReleaseRecoveryClaimRequest) -> Result<(), DriverError> {
    if request.driver_operation_id.is_nil()
        || request.control_operation.id.is_nil()
        || request.control_operation.attempt <= 0
        || request.control_operation.owner.trim().is_empty()
        || request.reconciliation_owner.is_nil()
        || request.reconciliation_token.is_nil()
        || !(MIN_TTL_SECONDS..=MAX_TTL_SECONDS).contains(&request.ttl_seconds)
    {
        Err(invalid("release recovery claim request is invalid"))
    } else {
        Ok(())
    }
}

fn validate_claim(claim: &ReleaseRecoveryClaim) -> Result<(), DriverError> {
    validate_claim_request(&ReleaseRecoveryClaimRequest {
        driver_operation_id: claim.driver_operation_id,
        control_operation: claim.control_operation.clone(),
        reconciliation_owner: claim.reconciliation_owner,
        reconciliation_token: claim.reconciliation_token,
        ttl_seconds: claim.ttl_seconds,
    })?;
    if claim.claim_fence <= 0 {
        Err(invalid("release recovery claim fence is invalid"))
    } else {
        Ok(())
    }
}

fn validate_state_for_claim(
    claim: &ReleaseRecoveryClaim,
    state: &ReleaseRecoveryState,
) -> Result<(), DriverError> {
    if state.driver_operation_id != claim.driver_operation_id
        || state.claim_fence != claim.claim_fence
        || state.claim_mode != claim.claim_mode
        || state.fleet_run_id.is_nil()
    {
        Err(invalid("release recovery state differs from claim"))
    } else {
        Ok(())
    }
}

fn validate_observation(
    claim: &ReleaseRecoveryClaim,
    state: &ReleaseRecoveryState,
    observation: &ReleaseRecoveryObservation,
) -> Result<(), DriverError> {
    match (
        &observation.selector,
        observation.directory_device,
        observation.directory_inode,
    ) {
        (Some(selector), Some(device), Some(inode)) if device > 0 && inode > 0 => {
            validate_selector_target(selector).map_err(DriverError::internal)?
        }
        (None, None, None)
            if observation.resolution_kind == ReleaseRecoveryResolutionKind::Inconclusive => {}
        _ => {
            return Err(invalid(
                "release recovery observation identity is incomplete",
            ));
        }
    }
    if observation
        .loaded_identity
        .as_ref()
        .is_some_and(|v| !v.is_object())
    {
        return Err(invalid("release recovery loaded identity is invalid"));
    }
    validate_observed_artifact(
        state,
        observation.maintenance_artifact.as_ref(),
        ReleaseOverlayKind::Maintenance,
    )?;
    validate_observed_artifact(
        state,
        observation.candidate_artifact.as_ref(),
        ReleaseOverlayKind::Candidate,
    )?;
    let artifact_shape_is_valid = match (claim.claim_mode, observation.resolution_kind) {
        (
            ReleaseRecoveryClaimMode::WriteCleanup,
            ReleaseRecoveryResolutionKind::Prior | ReleaseRecoveryResolutionKind::Unstarted,
        ) => observation.maintenance_artifact.is_none() && observation.candidate_artifact.is_none(),
        (ReleaseRecoveryClaimMode::RestorePrior, ReleaseRecoveryResolutionKind::Prior) => {
            observation
                .maintenance_artifact
                .as_ref()
                .is_some_and(|artifact| artifact.publication_started)
                && observation.candidate_artifact.is_none()
        }
        (ReleaseRecoveryClaimMode::ForwardOnly, ReleaseRecoveryResolutionKind::Candidate) => {
            observation
                .maintenance_artifact
                .as_ref()
                .is_some_and(|artifact| artifact.publication_started)
                && observation
                    .candidate_artifact
                    .as_ref()
                    .is_some_and(|artifact| artifact.publication_started)
                && observation
                    .candidate_artifact
                    .as_ref()
                    .is_some_and(|artifact| {
                        serde_json::to_value(&artifact.loaded_identity)
                            .ok()
                            .as_ref()
                            == observation.loaded_identity.as_ref()
                    })
        }
        (_, ReleaseRecoveryResolutionKind::Inconclusive) => true,
        _ => false,
    };
    if !artifact_shape_is_valid {
        return Err(invalid(
            "release recovery observed artifact facts are inconsistent",
        ));
    }
    Ok(())
}

fn validate_observed_artifact(
    state: &ReleaseRecoveryState,
    artifact: Option<&ReleaseRecoveryObservedArtifact>,
    expected_kind: ReleaseOverlayKind,
) -> Result<(), DriverError> {
    let Some(artifact) = artifact else {
        return Ok(());
    };
    validate_selector_target(&artifact.selector).map_err(DriverError::internal)?;
    artifact.loaded_identity.validate()?;
    let expected_selector = match expected_kind {
        ReleaseOverlayKind::Maintenance => &state.maintenance_selector,
        ReleaseOverlayKind::Candidate => &state.candidate_selector,
    };
    let recorded = match expected_kind {
        ReleaseOverlayKind::Maintenance => state.maintenance_artifact.as_ref(),
        ReleaseOverlayKind::Candidate => state.candidate_artifact.as_ref(),
    };
    if artifact.selector != *expected_selector
        || artifact.directory_device <= 0
        || artifact.directory_inode <= 0
        || artifact.loaded_identity.fleet_run_id != state.fleet_run_id
        || artifact.loaded_identity.driver_operation_id != state.driver_operation_id
        || artifact.loaded_identity.original_global_fence_token != state.original_global_fence_token
        || artifact.loaded_identity.overlay_kind != expected_kind
        || artifact.loaded_identity.target_slot != state.target_slot
        || recorded.is_some_and(|expected| {
            expected.identity != artifact.loaded_identity
                || expected.directory_device != artifact.directory_device as u64
                || expected.directory_inode != artifact.directory_inode as u64
        })
    {
        return Err(invalid("release recovery observed artifact is invalid"));
    }
    Ok(())
}

fn parse_runtime_expectation(
    claim: &ReleaseRecoveryClaim,
    state: &ReleaseRecoveryState,
    row: RuntimeExpectationRow,
) -> Result<ReadReleaseRecoveryRuntimeExpectation, DriverError> {
    match (row.0.as_str(), row.1) {
        ("claimed", Some(value)) => {
            validate_json(
                &value,
                MAX_RESPONSE_BYTES,
                "release recovery runtime expectation",
            )?;
            let expectation: ReleaseRecoveryRuntimeExpectation =
                serde_json::from_value(value).map_err(DriverError::internal)?;
            validate_runtime_expectation(claim, state, &expectation)?;
            Ok(ReadReleaseRecoveryRuntimeExpectation::Claimed(Box::new(
                expectation,
            )))
        }
        ("claim_lost", None) => Ok(ReadReleaseRecoveryRuntimeExpectation::ClaimLost),
        ("wrong_phase", None) => Ok(ReadReleaseRecoveryRuntimeExpectation::WrongPhase),
        ("state_drift", None) => Ok(ReadReleaseRecoveryRuntimeExpectation::StateDrift),
        _ => Err(invalid(
            "release recovery runtime expectation response is malformed",
        )),
    }
}

fn parse_runtime_observation_receipt(
    claim: &ReleaseRecoveryClaim,
    state: &ReleaseRecoveryState,
    expectation: &ReleaseRecoveryRuntimeExpectation,
    row: RuntimeObservationRow,
) -> Result<RecordReleaseRecoveryRuntimeObservation, DriverError> {
    match (row.0.as_str(), row.1, row.2) {
        (outcome @ ("recorded" | "replay"), Some(observation_digest), Some(response)) => {
            if !digest(&observation_digest) {
                return Err(invalid(
                    "release recovery observation receipt digest is invalid",
                ));
            }
            validate_json(
                &response,
                MAX_RESPONSE_BYTES,
                "release recovery completion response",
            )?;
            let completion_response: ReleaseRouteCompletionResponse =
                serde_json::from_value(response).map_err(DriverError::internal)?;
            validate_completion_identity(
                claim.driver_operation_id,
                state.fleet_run_id,
                &completion_response,
            )?;
            let evidence = &completion_response.evidence;
            if evidence.release_id != expectation.release_id
                || evidence.target_slot != expectation.target_slot.as_str()
                || evidence.driver_fence_token != expectation.original_global_fence_token
                || evidence.odoo_subject_digest != expectation.odoo_subject_digest
                || evidence.extension_subject_digest != expectation.extension_subject_digest
                || evidence.pair_qualification_digest != expectation.pair_qualification_digest
                || evidence.gateway_configuration_digest != expectation.gateway_configuration_digest
                || evidence.driver_action_id != expectation.driver_action_id
                || evidence.prepared_tenants
                    != serde_json::to_value(&expectation.prepared_tenants)
                        .map_err(DriverError::internal)?
                || evidence.tenant_snapshot
                    != serde_json::to_value(&expectation.tenant_snapshot)
                        .map_err(DriverError::internal)?
            {
                return Err(invalid(
                    "release recovery completion response differs from expectation",
                ));
            }
            let receipt = ReleaseRecoveryRuntimeReceipt {
                observation_digest,
                completion_response,
            };
            if outcome == "recorded" {
                Ok(RecordReleaseRecoveryRuntimeObservation::Recorded(receipt))
            } else {
                Ok(RecordReleaseRecoveryRuntimeObservation::Replay(receipt))
            }
        }
        ("claim_lost", None, None) => Ok(RecordReleaseRecoveryRuntimeObservation::ClaimLost),
        ("wrong_phase", None, None) => Ok(RecordReleaseRecoveryRuntimeObservation::WrongPhase),
        ("state_drift", None, None) => Ok(RecordReleaseRecoveryRuntimeObservation::StateDrift),
        ("conflict", None, None) => Ok(RecordReleaseRecoveryRuntimeObservation::Conflict),
        _ => Err(invalid(
            "release recovery runtime observation response is malformed",
        )),
    }
}

fn validate_runtime_expectation(
    claim: &ReleaseRecoveryClaim,
    state: &ReleaseRecoveryState,
    expectation: &ReleaseRecoveryRuntimeExpectation,
) -> Result<(), DriverError> {
    if expectation.protocol_version != 1
        || expectation.release_executor_protocol_version != 1
        || expectation.driver_operation_id != claim.driver_operation_id
        || expectation.fleet_run_id != state.fleet_run_id
        || expectation.control_operation_id != claim.control_operation.id
        || expectation.original_instance_owner.is_nil()
        || expectation.original_global_fence_token != state.original_global_fence_token
        || expectation.target_slot != state.target_slot
        || expectation.driver_action_id.is_nil()
        || expectation.fleet_generation <= 0
        || expectation.release_id != expectation.release_manifest.release_id
        || expectation.odoo_subject_digest
            != expectation.release_manifest.odoo_runtime.subject_digest
        || expectation.extension_subject_digest
            != expectation.release_manifest.extension_bundle.subject_digest
        || expectation.prepared_tenants.is_empty()
        || expectation.prepared_tenants.len() > crate::release::MAX_FLEET_TENANTS
        || expectation.prepared_tenants.len() != expectation.tenant_snapshot.len()
    {
        return Err(invalid(
            "release recovery runtime expectation identity differs",
        ));
    }
    expectation
        .release_manifest
        .validate()
        .map_err(DriverError::internal)?;
    let computed_manifest_digest = format!(
        "sha256:{:x}",
        Sha256::digest(
            serde_jcs::to_vec(&expectation.release_manifest).map_err(DriverError::internal)?
        )
    );
    if computed_manifest_digest != expectation.release_manifest_digest {
        return Err(invalid("release recovery manifest digest differs"));
    }
    let (_, _, pair) = super::release::selected_release_platform(&expectation.release_manifest)?;
    if pair.qualification_digest != expectation.pair_qualification_digest {
        return Err(invalid("release recovery platform qualification differs"));
    }
    for value in [
        &expectation.release_manifest_digest,
        &expectation.odoo_subject_digest,
        &expectation.extension_subject_digest,
        &expectation.pair_qualification_digest,
        &expectation.gateway_configuration_digest,
    ] {
        validate_digest(value, "release recovery runtime expectation digest")
            .map_err(DriverError::internal)?;
    }
    let mut prepared_ids = HashSet::with_capacity(expectation.prepared_tenants.len());
    let mut prepared_workshops = HashSet::with_capacity(expectation.prepared_tenants.len());
    let mut prepared_databases = HashMap::with_capacity(expectation.prepared_tenants.len());
    for tenant in &expectation.prepared_tenants {
        if tenant.adoption_id.is_nil()
            || tenant.workshop_id.is_nil()
            || tenant.database_id.is_nil()
            || tenant.database_ref.trim().is_empty()
            || tenant.public_hostname.trim().is_empty()
            || !prepared_ids.insert(tenant.adoption_id)
            || !prepared_workshops.insert(tenant.workshop_id)
            || prepared_databases
                .insert(
                    tenant.workshop_id,
                    (tenant.database_id, tenant.database_ref.as_str()),
                )
                .is_some()
        {
            return Err(invalid(
                "release recovery prepared tenant expectation is invalid",
            ));
        }
    }
    let mut snapshot_workshops = HashSet::with_capacity(expectation.tenant_snapshot.len());
    let mut previous = None;
    for tenant in &expectation.tenant_snapshot {
        if tenant.workshop_id.is_nil()
            || tenant.database_id.is_nil()
            || tenant.database_ref.trim().is_empty()
            || !snapshot_workshops.insert(tenant.workshop_id)
            || previous.is_some_and(|id| id >= tenant.workshop_id)
            || prepared_databases.get(&tenant.workshop_id)
                != Some(&(tenant.database_id, tenant.database_ref.as_str()))
        {
            return Err(invalid(
                "release recovery tenant snapshot expectation is invalid",
            ));
        }
        previous = Some(tenant.workshop_id);
    }
    if prepared_workshops != snapshot_workshops {
        return Err(invalid("release recovery runtime tenant sets differ"));
    }
    Ok(())
}

fn parse_transition(value: &str) -> Result<ReleaseRecoveryTransition, DriverError> {
    let outcome = match value {
        "recorded" => ReleaseRecoveryTransition::Recorded,
        "sealed" => ReleaseRecoveryTransition::Sealed,
        "authorized" => ReleaseRecoveryTransition::Authorized,
        "replay" => ReleaseRecoveryTransition::Replay,
        "claim_lost" => ReleaseRecoveryTransition::ClaimLost,
        "wrong_phase" => ReleaseRecoveryTransition::WrongPhase,
        "conflict" => ReleaseRecoveryTransition::Conflict,
        "invalid" => ReleaseRecoveryTransition::Invalid,
        "out_of_order" => ReleaseRecoveryTransition::OutOfOrder,
        "snapshot_drift" => ReleaseRecoveryTransition::SnapshotDrift,
        "digest_mismatch" => ReleaseRecoveryTransition::DigestMismatch,
        "observation_mismatch" => ReleaseRecoveryTransition::ObservationMismatch,
        "unsupported_resolution" => ReleaseRecoveryTransition::UnsupportedResolution,
        "runtime_observation_required" => ReleaseRecoveryTransition::RuntimeObservationRequired,
        "observation_absent" => ReleaseRecoveryTransition::ObservationAbsent,
        _ => return Err(invalid("release recovery transition outcome is invalid")),
    };
    Ok(outcome)
}

fn parse_finish(
    claim: &ReleaseRecoveryClaim,
    state: &ReleaseRecoveryState,
    kind: ReleaseRecoveryResolutionKind,
    digest_value: &str,
    row: FinishRow,
) -> Result<FinishReleaseRecovery, DriverError> {
    match row.0.as_str() {
        "applied_recovered" | "not_applied" => {
            let terminal = parse_terminal(
                claim,
                state,
                kind,
                digest_value,
                row.1
                    .ok_or_else(|| invalid("release recovery terminal response is absent"))?,
            )?;
            Ok(FinishReleaseRecovery::Completed(terminal))
        }
        "replay" => {
            let terminal = parse_terminal(
                claim,
                state,
                kind,
                digest_value,
                row.1
                    .ok_or_else(|| invalid("release recovery replay response is absent"))?,
            )?;
            Ok(FinishReleaseRecovery::Replay(terminal))
        }
        "conflict" => Ok(FinishReleaseRecovery::Conflict(
            row.1
                .map(|v| parse_terminal_unbound(claim.driver_operation_id, state.fleet_run_id, v))
                .transpose()?,
        )),
        "claim_lost" if row.1.is_none() => Ok(FinishReleaseRecovery::ClaimLost),
        "resolution_absent" if row.1.is_none() => Ok(FinishReleaseRecovery::ResolutionAbsent),
        "blocked" if row.1.is_none() => Ok(FinishReleaseRecovery::Blocked),
        "decision_mismatch" if row.1.is_none() => Ok(FinishReleaseRecovery::DecisionMismatch),
        "state_drift" if row.1.is_none() => Ok(FinishReleaseRecovery::StateDrift),
        "unsupported_resolution" if row.1.is_none() => {
            Ok(FinishReleaseRecovery::UnsupportedResolution)
        }
        _ => Err(invalid("release recovery finish row is malformed")),
    }
}

fn parse_terminal(
    claim: &ReleaseRecoveryClaim,
    state: &ReleaseRecoveryState,
    kind: ReleaseRecoveryResolutionKind,
    digest_value: &str,
    value: Value,
) -> Result<ReleaseRecoveryTerminal, DriverError> {
    let terminal = parse_terminal_unbound(claim.driver_operation_id, state.fleet_run_id, value)?;
    match &terminal {
        ReleaseRecoveryTerminal::AppliedRecovered(response)
            if kind == ReleaseRecoveryResolutionKind::Candidate
                && response.evidence.driver_operation_id == claim.driver_operation_id => {}
        ReleaseRecoveryTerminal::NotApplied(response)
            if kind != ReleaseRecoveryResolutionKind::Candidate
                && response.resolution_kind == kind
                && response.decision_digest == digest_value => {}
        _ => return Err(invalid("release recovery terminal identity differs")),
    }
    Ok(terminal)
}

fn parse_terminal_unbound(
    driver: Uuid,
    fleet: Uuid,
    value: Value,
) -> Result<ReleaseRecoveryTerminal, DriverError> {
    validate_json(
        &value,
        MAX_RESPONSE_BYTES,
        "release recovery terminal response",
    )?;
    if value.get("outcome").and_then(Value::as_str) == Some("not_applied") {
        let response: ReleaseRecoveryNotApplied =
            serde_json::from_value(value).map_err(DriverError::internal)?;
        if response.driver_operation_id != driver
            || response.fleet_run_id != fleet
            || !digest(&response.decision_digest)
        {
            return Err(invalid("release recovery not-applied identity differs"));
        }
        Ok(ReleaseRecoveryTerminal::NotApplied(response))
    } else {
        let response: ReleaseRouteCompletionResponse =
            serde_json::from_value(value).map_err(DriverError::internal)?;
        validate_completion_identity(driver, fleet, &response)?;
        Ok(ReleaseRecoveryTerminal::AppliedRecovered(Box::new(
            response,
        )))
    }
}

fn validate_json(value: &Value, max: usize, label: &'static str) -> Result<(), DriverError> {
    if !value.is_object()
        || serde_json::to_vec(value)
            .map_err(DriverError::internal)?
            .len()
            > max
    {
        Err(invalid(label))
    } else {
        Ok(())
    }
}

fn pg_identity(value: u64) -> Result<i64, DriverError> {
    i64::try_from(value)
        .ok()
        .filter(|v| *v > 0)
        .ok_or_else(|| invalid("release recovery file identity is invalid"))
}
fn positive_u64(value: i64) -> Result<u64, DriverError> {
    u64::try_from(value)
        .ok()
        .filter(|v| *v > 0)
        .ok_or_else(|| invalid("release recovery file identity is invalid"))
}
fn digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}
fn invalid(message: &'static str) -> DriverError {
    DriverError::internal(message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recovery_state() -> ReleaseRecoveryState {
        ReleaseRecoveryState {
            driver_operation_id: Uuid::new_v4(),
            fleet_run_id: Uuid::new_v4(),
            claim_fence: 1,
            claim_mode: ReleaseRecoveryClaimMode::ForwardOnly,
            interrupted_phase: ReleaseRecoveryPhase::CandidateStaging,
            target_slot: ReleaseTargetSlot::Blue,
            original_global_fence_token: 1,
            snapshot_count: 1,
            prior: None,
            prior_loaded_identity: None,
            maintenance_selector:
                "generations/release-00000000000000000000000000000001-maintenance".into(),
            maintenance_artifact: None,
            candidate_selector: "generations/release-00000000000000000000000000000001-candidate"
                .into(),
            candidate_artifact: None,
            external_effects_started: true,
        }
    }

    fn snapshot_sentinel(outcome: &str) -> RecoverySnapshotRow {
        (
            outcome.into(),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
    }

    fn recovery_claim(state: &ReleaseRecoveryState) -> ReleaseRecoveryClaim {
        ReleaseRecoveryClaim {
            driver_operation_id: state.driver_operation_id,
            control_operation: ControlOperationLease {
                id: Uuid::new_v4(),
                attempt: 2,
                owner: "release-recovery-test".into(),
            },
            reconciliation_owner: Uuid::new_v4(),
            reconciliation_token: Uuid::new_v4(),
            claim_fence: state.claim_fence,
            claim_mode: state.claim_mode,
            ttl_seconds: 300,
        }
    }

    fn publication_state() -> ReleaseRecoveryState {
        let mut state = recovery_state();
        state.candidate_selector =
            ReleaseGenerationName::new(state.fleet_run_id, ReleaseOverlayKind::Candidate)
                .selector_target();
        state.prior =
            Some(PriorSelector::from_recorded("generations/boot-live".into(), 10, 11).unwrap());
        state.candidate_artifact = Some(ReleaseRecoveryArtifact {
            identity: ReleaseOverlayGenerationIdentity::new(
                state.fleet_run_id,
                state.driver_operation_id,
                state.original_global_fence_token,
                ReleaseOverlayKind::Candidate,
                format!("sha256:{}", "a".repeat(64)),
                state.target_slot.as_str(),
            )
            .unwrap(),
            directory_device: 20,
            directory_inode: 21,
        });
        state
    }

    #[test]
    fn candidate_publication_authority_binds_the_whole_request() {
        let state = publication_state();
        let claim = recovery_claim(&state);
        let authorization = ReleaseRecoveryCandidatePublicationAuthorization::for_test(
            &claim,
            &state,
            &format!("sha256:{}", "b".repeat(64)),
        );
        authorization.validate_for(&claim, &state).unwrap();

        let candidate = state.candidate_artifact.as_ref().unwrap();
        let selector = PriorSelector::from_recorded(
            state.candidate_selector.clone(),
            candidate.directory_device,
            candidate.directory_inode,
        )
        .unwrap();
        let prior = state.prior.as_ref().unwrap();
        let intent = super::super::release_generation_fs::ReleaseGenerationIntent::new(
            state.fleet_run_id,
            state.driver_operation_id,
            state.original_global_fence_token,
            ReleaseOverlayKind::Candidate,
            state.target_slot.as_str(),
        )
        .unwrap();
        let exact = super::super::release_route_recovery::ReleasePublicationRecoveryRequest {
            phase: super::super::release_route_recovery::ReleaseRecoveryPhase::CandidateSealed,
            intent: intent.clone(),
            overlay_identity: &candidate.identity,
            route_count: state.snapshot_count,
            overlay_selector: &selector,
            prior_selector: prior,
        };
        authorization.validate_publication_request(&exact).unwrap();

        let route_count_drift =
            super::super::release_route_recovery::ReleasePublicationRecoveryRequest {
                route_count: exact.route_count + 1,
                ..exact
            };
        assert!(
            authorization
                .validate_publication_request(&route_count_drift)
                .is_err()
        );
        let selector_drift = PriorSelector::from_recorded(
            selector.target().to_owned(),
            selector.directory_device(),
            selector.directory_inode() + 1,
        )
        .unwrap();
        let wrong_selector =
            super::super::release_route_recovery::ReleasePublicationRecoveryRequest {
                phase: super::super::release_route_recovery::ReleaseRecoveryPhase::CandidateSealed,
                intent: intent.clone(),
                overlay_identity: &candidate.identity,
                route_count: state.snapshot_count,
                overlay_selector: &selector_drift,
                prior_selector: prior,
            };
        assert!(
            authorization
                .validate_publication_request(&wrong_selector)
                .is_err()
        );
        let prior_drift = PriorSelector::from_recorded(
            prior.target().to_owned(),
            prior.directory_device(),
            prior.directory_inode() + 1,
        )
        .unwrap();
        let wrong_prior = super::super::release_route_recovery::ReleasePublicationRecoveryRequest {
            phase: super::super::release_route_recovery::ReleaseRecoveryPhase::CandidateSealed,
            intent: intent.clone(),
            overlay_identity: &candidate.identity,
            route_count: state.snapshot_count,
            overlay_selector: &selector,
            prior_selector: &prior_drift,
        };
        assert!(
            authorization
                .validate_publication_request(&wrong_prior)
                .is_err()
        );
        let wrong_phase = super::super::release_route_recovery::ReleasePublicationRecoveryRequest {
            phase:
                super::super::release_route_recovery::ReleaseRecoveryPhase::CandidatePublicationStarted,
            intent: intent.clone(),
            overlay_identity: &candidate.identity,
            route_count: state.snapshot_count,
            overlay_selector: &selector,
            prior_selector: prior,
        };
        assert!(
            authorization
                .validate_publication_request(&wrong_phase)
                .is_err()
        );
        let mut identity_drift = candidate.identity.clone();
        identity_drift.route_set_digest = format!("sha256:{}", "c".repeat(64));
        let wrong_identity =
            super::super::release_route_recovery::ReleasePublicationRecoveryRequest {
                phase: super::super::release_route_recovery::ReleaseRecoveryPhase::CandidateSealed,
                intent,
                overlay_identity: &identity_drift,
                route_count: state.snapshot_count,
                overlay_selector: &selector,
                prior_selector: prior,
            };
        assert!(
            authorization
                .validate_publication_request(&wrong_identity)
                .is_err()
        );

        let mut changed = state.clone();
        changed.candidate_artifact.as_mut().unwrap().directory_inode += 1;
        assert!(authorization.validate_for(&claim, &changed).is_err());
        let mut changed = state.clone();
        changed.snapshot_count += 1;
        assert!(authorization.validate_for(&claim, &changed).is_err());
        let mut changed = state;
        changed.prior = Some(prior_drift);
        assert!(authorization.validate_for(&claim, &changed).is_err());
    }

    #[test]
    fn closed_database_enums_reject_unknown_values() {
        assert_eq!(
            ReleaseRecoveryClaimMode::parse("forward_only"),
            Some(ReleaseRecoveryClaimMode::ForwardOnly)
        );
        assert_eq!(ReleaseRecoveryClaimMode::parse("observe_only"), None);
        assert_eq!(
            ReleaseRecoveryPhase::parse("awaiting_worker_finalize"),
            Some(ReleaseRecoveryPhase::AwaitingWorkerFinalize)
        );
        assert_eq!(ReleaseRecoveryPhase::parse("finished"), None);
        assert!(parse_transition("surprise").is_err());
    }

    #[test]
    fn runtime_expectation_sentinels_are_closed_and_null_strict() {
        let state = recovery_state();
        let claim = recovery_claim(&state);
        assert_eq!(
            parse_runtime_expectation(&claim, &state, ("claim_lost".into(), None)).unwrap(),
            ReadReleaseRecoveryRuntimeExpectation::ClaimLost
        );
        assert_eq!(
            parse_runtime_expectation(&claim, &state, ("wrong_phase".into(), None)).unwrap(),
            ReadReleaseRecoveryRuntimeExpectation::WrongPhase
        );
        assert_eq!(
            parse_runtime_expectation(&claim, &state, ("state_drift".into(), None)).unwrap(),
            ReadReleaseRecoveryRuntimeExpectation::StateDrift
        );
        assert!(parse_runtime_expectation(&claim, &state, ("claimed".into(), None),).is_err());
        assert!(
            parse_runtime_expectation(
                &claim,
                &state,
                ("claim_lost".into(), Some(serde_json::json!({}))),
            )
            .is_err()
        );
        assert!(parse_runtime_expectation(&claim, &state, ("future".into(), None)).is_err());
    }

    #[test]
    fn evidence_rejects_unknown_fields() {
        let value = serde_json::json!({"protocol_version":1,"driver_operation_id":Uuid::new_v4(),"fleet_run_id":Uuid::new_v4(),"claim_fence":1,"resolution_kind":"inconclusive","observed_selector":null,"observed_directory_device":null,"observed_directory_inode":null,"observed_loaded_identity":null,"maintenance_artifact":null,"candidate_artifact":null,"extra":true});
        assert!(serde_json::from_value::<ReleaseRecoveryObservationEvidence>(value).is_err());
    }

    #[test]
    fn evidence_has_exact_closed_artifact_facts() {
        let evidence = ReleaseRecoveryObservationEvidence {
            protocol_version: 1,
            driver_operation_id: Uuid::new_v4(),
            fleet_run_id: Uuid::new_v4(),
            claim_fence: 3,
            resolution_kind: ReleaseRecoveryResolutionKind::Unstarted,
            observed_selector: Some("generations/boot-live".into()),
            observed_directory_device: Some(1),
            observed_directory_inode: Some(2),
            observed_loaded_identity: None,
            maintenance_artifact: None,
            candidate_artifact: None,
        };
        let value = serde_json::to_value(&evidence).unwrap();
        assert_eq!(value.as_object().unwrap().len(), 11);
        assert!(value.get("maintenance_artifact").unwrap().is_null());
        assert!(value.get("candidate_artifact").unwrap().is_null());

        let invalid_artifact = serde_json::json!({
            "selector":"generations/release-candidate",
            "directory_device":1,
            "directory_inode":2,
            "loaded_identity":{},
            "publication_started":true,
            "unexpected":false
        });
        assert!(
            serde_json::from_value::<ReleaseRecoveryObservedArtifact>(invalid_artifact).is_err()
        );
    }

    #[test]
    fn busy_claim_never_mints_the_callers_capability() {
        let request = ReleaseRecoveryClaimRequest {
            driver_operation_id: Uuid::new_v4(),
            control_operation: ControlOperationLease {
                id: Uuid::new_v4(),
                attempt: 2,
                owner: "release-worker".into(),
            },
            reconciliation_owner: Uuid::new_v4(),
            reconciliation_token: Uuid::new_v4(),
            ttl_seconds: 60,
        };
        let result = parse_claim(
            &request,
            ("busy".into(), Some(7), Some("restore_prior".into())),
        )
        .unwrap();
        assert_eq!(result.outcome, ClaimReleaseRecovery::Busy);
        assert!(result.claim.is_none());
        assert_eq!(result.observed_claim_fence, Some(7));
        assert_eq!(
            result.observed_claim_mode,
            Some(ReleaseRecoveryClaimMode::RestorePrior)
        );
    }

    #[test]
    fn recovery_snapshot_sentinels_are_closed_and_never_look_like_eof() {
        let state = recovery_state();
        assert_eq!(
            parse_recovery_snapshot_rows(&state, None, 25, vec![snapshot_sentinel("complete")])
                .unwrap(),
            ReadReleaseRecoverySnapshot::Complete
        );
        assert_eq!(
            parse_recovery_snapshot_rows(&state, None, 25, vec![snapshot_sentinel("claim_lost")])
                .unwrap(),
            ReadReleaseRecoverySnapshot::ClaimLost
        );
        assert!(
            parse_recovery_snapshot_rows(&state, None, 25, Vec::new()).is_err(),
            "an empty SQL response is not authenticated completion"
        );
        assert!(
            parse_recovery_snapshot_rows(
                &state,
                None,
                25,
                vec![snapshot_sentinel("future_outcome")]
            )
            .is_err()
        );
        let mut malformed = snapshot_sentinel("complete");
        malformed.1 = Some(Uuid::new_v4());
        assert!(parse_recovery_snapshot_rows(&state, None, 25, vec![malformed]).is_err());
    }

    #[test]
    fn unsupported_resolution_matches_the_authoritative_sql_contract() {
        assert_eq!(
            parse_transition("unsupported_resolution").unwrap(),
            ReleaseRecoveryTransition::UnsupportedResolution
        );
        assert!(parse_transition("unsafe_resolution").is_err());

        let state = recovery_state();
        let claim = ReleaseRecoveryClaim {
            driver_operation_id: state.driver_operation_id,
            control_operation: ControlOperationLease {
                id: Uuid::new_v4(),
                attempt: 1,
                owner: "release-worker".into(),
            },
            reconciliation_owner: Uuid::new_v4(),
            reconciliation_token: Uuid::new_v4(),
            claim_fence: state.claim_fence,
            claim_mode: state.claim_mode,
            ttl_seconds: 60,
        };
        let decision_digest = format!("sha256:{}", "a".repeat(64));
        assert_eq!(
            parse_finish(
                &claim,
                &state,
                ReleaseRecoveryResolutionKind::Prior,
                &decision_digest,
                ("unsupported_resolution".into(), None),
            )
            .unwrap(),
            FinishReleaseRecovery::UnsupportedResolution
        );
        assert!(
            parse_finish(
                &claim,
                &state,
                ReleaseRecoveryResolutionKind::Prior,
                &decision_digest,
                ("unsafe_resolution".into(), None),
            )
            .is_err()
        );
    }

    #[test]
    fn tracing_outcome_vocabularies_are_closed() {
        let claims = [
            ClaimReleaseRecovery::Acquired,
            ClaimReleaseRecovery::Replay,
            ClaimReleaseRecovery::Busy,
            ClaimReleaseRecovery::Terminal,
            ClaimReleaseRecovery::Invalid,
            ClaimReleaseRecovery::NotFound,
            ClaimReleaseRecovery::ProtocolIncompatible,
            ClaimReleaseRecovery::AuthorityLost,
            ClaimReleaseRecovery::NotExpired,
            ClaimReleaseRecovery::AuthorityInconsistent,
        ];
        assert_eq!(
            claims.map(ClaimReleaseRecovery::trace_outcome),
            [
                "acquired",
                "replay",
                "busy",
                "terminal",
                "invalid",
                "not_found",
                "protocol_incompatible",
                "authority_lost",
                "not_expired",
                "authority_inconsistent",
            ]
        );

        let transitions = [
            ReleaseRecoveryTransition::Recorded,
            ReleaseRecoveryTransition::Sealed,
            ReleaseRecoveryTransition::Authorized,
            ReleaseRecoveryTransition::Replay,
            ReleaseRecoveryTransition::ClaimLost,
            ReleaseRecoveryTransition::WrongPhase,
            ReleaseRecoveryTransition::Conflict,
            ReleaseRecoveryTransition::Invalid,
            ReleaseRecoveryTransition::OutOfOrder,
            ReleaseRecoveryTransition::SnapshotDrift,
            ReleaseRecoveryTransition::DigestMismatch,
            ReleaseRecoveryTransition::ObservationMismatch,
            ReleaseRecoveryTransition::UnsupportedResolution,
            ReleaseRecoveryTransition::RuntimeObservationRequired,
            ReleaseRecoveryTransition::ObservationAbsent,
        ];
        assert_eq!(
            transitions.map(ReleaseRecoveryTransition::trace_outcome),
            [
                "recorded",
                "sealed",
                "authorized",
                "replay",
                "claim_lost",
                "wrong_phase",
                "conflict",
                "invalid",
                "out_of_order",
                "snapshot_drift",
                "digest_mismatch",
                "observation_mismatch",
                "unsupported_resolution",
                "runtime_observation_required",
                "observation_absent",
            ]
        );
        assert_eq!(
            FinishReleaseRecovery::ReviewRequired.trace_outcome(),
            "review_required"
        );
        assert_eq!(
            FinishReleaseRecovery::Conflict(None).trace_outcome(),
            "conflict"
        );
    }

    #[test]
    fn tracing_records_only_parsed_outcomes_and_safe_identity() {
        let source = include_str!("release_route_recovery_db.rs");
        let production = source.split("#[cfg(test)]\nmod tests").next().unwrap();
        assert!(!production.contains("route.workshop_id"));
        for field in [
            "claim.outcome",
            "state.outcome",
            "runtime.outcome",
            "transition.outcome",
            "terminal.outcome",
            "result.outcome",
        ] {
            assert!(
                !production.contains(&format!("record(\"{field}\", row.0")),
                "{field} must never record an unparsed database value"
            );
        }
        assert_eq!(
            production
                .matches("record_parsed_outcome(\"transition.outcome\"")
                .count(),
            5,
            "every declared transition outcome must be populated"
        );
        assert!(production.contains("map_or(\"contract_drift\", outcome)"));
    }

    #[test]
    fn module_is_private_and_has_no_active_callsite() {
        let root = include_str!("../docker_driver.rs");
        assert_eq!(root.matches("mod release_route_recovery_db;").count(), 1);
        assert_eq!(root.matches("release_route_recovery_db::").count(), 0);
        assert!(!root.contains("use release_route_recovery_db::*"));
    }

    #[test]
    fn adapter_binds_every_0037_through_0041_runtime_function() {
        let source = include_str!("release_route_recovery_db.rs");
        for function in [
            "discover_interrupted_immutable_release_route_publications(",
            "claim_interrupted_immutable_release_route_publication(",
            "renew_interrupted_immutable_release_route_publication_claim(",
            "read_interrupted_immutable_release_route_publication_state(",
            "read_interrupted_immutable_release_route_snapshot_batch(",
            "read_interrupted_immutable_release_runtime_expectation(",
            "record_interrupted_immutable_release_runtime_observation(",
            "authorize_interrupted_immutable_release_route_candidate_from_observation(",
            "record_interrupted_immutable_release_route_candidate_entry(",
            "seal_interrupted_immutable_release_route_candidate(",
            "authorize_interrupted_immutable_release_route_exchange(",
            "resolve_interrupted_immutable_release_route_publication(",
            "finish_interrupted_immutable_release_route_publication(",
            "finish_reviewed_interrupted_immutable_release_route_publication(",
            "read_immutable_release_route_publication_result(",
        ] {
            assert!(source.contains(function), "missing {function}");
        }
        assert!(source.contains(
            "authorize_interrupted_immutable_release_route_exchange($1,$2,$3,$4,$5,$6,$7,$8,$9)"
        ));
        let production = source.split("#[cfg(test)]\nmod tests").next().unwrap();
        for instrument in production.match_indices("#[tracing::instrument") {
            let tail = &production[instrument.0..];
            let block = tail.split("pub(super) async fn").next().unwrap();
            assert!(block.contains("skip_all"));
            assert!(!block.contains("token"));
        }
    }
}
