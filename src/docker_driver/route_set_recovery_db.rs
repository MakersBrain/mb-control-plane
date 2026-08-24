//! Dormant typed boundary for migration 0030 observations and migration 0031
//! reviewed terminal decisions.
//!
//! The terminal adapter requires a separately supplied reviewed digest that is
//! verified against exact immutable observation evidence. Merely registering
//! the module performs no query, filesystem action, or terminal transition.
#![allow(dead_code)]

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use super::gateway::{
    GatewayGenerationIdentity, ReleaseOverlayGenerationIdentity, RouteSetGenerationIdentity,
    RouteSetPublicationKind,
};
use super::route_generation_fs::{PriorSelector, validate_digest, validate_selector_target};
use super::route_projection::RouteDisposition;
use super::route_set_generation_fs::RouteSetGenerationName;
use super::route_set_publication_db::{
    PublicationResponseExpectation, RouteSetAppliedDisposition, RouteSetPublicationResponse,
    parse_publication_response, validate_publication_response_common,
};
use super::route_set_recovery_publication_db::{
    RecoveryRouteSetPublicationResponse, parse_recovery_response_for_kind,
};
use super::{ControlOperationLease, DriverError};

const MIN_TTL_SECONDS: i32 = 60;
const MAX_TTL_SECONDS: i32 = 1200;
const MAX_DISCOVERY_LIMIT: usize = 100;
const STATE_KEYS: [&str; 27] = [
    "protocol_version",
    "publication_id",
    "publication_kind",
    "recovery_effect_run_id",
    "interrupted_phase",
    "claim_mode",
    "claim_fence",
    "target_workshop_id",
    "original_global_fence_token",
    "target_route_fence_token",
    "target_generation",
    "target_projection_digest",
    "target_disposition",
    "selector",
    "prior_selector",
    "prior_directory_device",
    "prior_directory_inode",
    "prior_loaded_identity",
    "candidate_directory_device",
    "candidate_directory_inode",
    "sealed_count",
    "sealed_present_count",
    "route_set_digest",
    "record_count",
    "publication_started_at",
    "observed_selector",
    "observed_loaded_identity",
];
const EVIDENCE_KEYS: [&str; 12] = [
    "publication_id",
    "claim_fence",
    "claim_mode",
    "reconciliation_operation_id",
    "reconciliation_operation_attempt",
    "reconciliation_operation_lease_owner",
    "resolution_kind",
    "interrupted_phase",
    "observed_selector",
    "observed_directory_device",
    "observed_directory_inode",
    "observed_loaded_identity",
];

type DiscoveryRow = (
    Uuid,
    Uuid,
    String,
    String,
    String,
    i64,
    bool,
    String,
    Option<String>,
    OffsetDateTime,
);
type ClaimRow = (String, Option<i64>, Option<String>);
type StateRow = (String, Option<Value>);
type ResolutionRow = (String, Option<Value>);
type FinishRecoveryRow = (String, Option<Value>);
const TERMINAL_RESPONSE_KEYS: [&str; 11] = [
    "outcome",
    "publication_id",
    "driver_operation_id",
    "target_workshop_id",
    "resolution_claim_fence",
    "resolution_kind",
    "reconciliation_operation_id",
    "reconciliation_operation_attempt",
    "reconciliation_operation_lease_owner",
    "decision_digest",
    "driver_response",
];
const RECOVERY_TERMINAL_RESPONSE_KEYS: [&str; 12] = [
    "outcome",
    "publication_id",
    "effect_run_id",
    "publication_kind",
    "target_workshop_id",
    "resolution_claim_fence",
    "resolution_kind",
    "reconciliation_operation_id",
    "reconciliation_operation_attempt",
    "reconciliation_operation_lease_owner",
    "decision_digest",
    "effect_response",
];

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum RecoveryClaimMode {
    WriteCleanup,
    ObserveOnly,
}

impl RecoveryClaimMode {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "write_cleanup" => Some(Self::WriteCleanup),
            "observe_only" => Some(Self::ObserveOnly),
            _ => None,
        }
    }
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::WriteCleanup => "write_cleanup",
            Self::ObserveOnly => "observe_only",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum InterruptedPhase {
    Staging,
    Sealed,
    PublicationStarted,
    Observed,
}

impl InterruptedPhase {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "staging" => Some(Self::Staging),
            "sealed" => Some(Self::Sealed),
            "publication_started" => Some(Self::PublicationStarted),
            "observed" => Some(Self::Observed),
            _ => None,
        }
    }
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Staging => "staging",
            Self::Sealed => "sealed",
            Self::PublicationStarted => "publication_started",
            Self::Observed => "observed",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct InterruptedPublicationSummary {
    pub publication_id: Uuid,
    pub target_workshop_id: Uuid,
    pub publication_kind: RouteSetPublicationKind,
    pub interrupted_phase: InterruptedPhase,
    pub claim_mode: RecoveryClaimMode,
    pub claim_fence: i64,
    pub claim_available: bool,
    pub selector: String,
    pub route_set_digest: Option<String>,
    pub updated_at: OffsetDateTime,
}

#[derive(Clone)]
pub(super) struct RouteSetRecoveryClaimRequest {
    pub publication_id: Uuid,
    pub reconciliation_operation: ControlOperationLease,
    pub reconciliation_owner: Uuid,
    pub reconciliation_token: Uuid,
    pub ttl_seconds: i32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct RouteSetRecoveryClaim {
    pub publication_id: Uuid,
    pub reconciliation_operation_id: Uuid,
    pub reconciliation_operation_attempt: i32,
    pub reconciliation_operation_lease_owner: String,
    pub reconciliation_owner: Uuid,
    pub reconciliation_token: Uuid,
    pub claim_fence: i64,
    pub claim_mode: RecoveryClaimMode,
    pub ttl_seconds: i32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ClaimRefusal {
    Invalid,
    Absent,
    ProtocolInactive,
    ReconciliationLeaseLost,
    WrongPhase,
    AuthorityInconsistent,
    NotExpired,
}

pub(super) enum ClaimInterruptedPublication {
    Acquired(RouteSetRecoveryClaim),
    Replay(RouteSetRecoveryClaim),
    Busy {
        claim_fence: i64,
        claim_mode: RecoveryClaimMode,
    },
    Terminal {
        claim_fence: i64,
    },
    Refused(ClaimRefusal),
}

impl ClaimInterruptedPublication {
    const fn trace_outcome(&self) -> &'static str {
        match self {
            Self::Acquired(_) => "acquired",
            Self::Replay(_) => "replay",
            Self::Busy { .. } => "busy",
            Self::Terminal { .. } => "terminal",
            Self::Refused(ClaimRefusal::Invalid) => "invalid",
            Self::Refused(ClaimRefusal::Absent) => "absent",
            Self::Refused(ClaimRefusal::ProtocolInactive) => "protocol_inactive",
            Self::Refused(ClaimRefusal::ReconciliationLeaseLost) => "reconciliation_lease_lost",
            Self::Refused(ClaimRefusal::WrongPhase) => "wrong_phase",
            Self::Refused(ClaimRefusal::AuthorityInconsistent) => "authority_inconsistent",
            Self::Refused(ClaimRefusal::NotExpired) => "not_expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RenewRecoveryClaimOutcome {
    Renewed,
    ClaimLost,
    Invalid,
}

impl RenewRecoveryClaimOutcome {
    const fn trace_outcome(self) -> &'static str {
        match self {
            Self::Renewed => "renewed",
            Self::ClaimLost => "claim_lost",
            Self::Invalid => "invalid",
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct RawRecoveryState {
    protocol_version: u8,
    publication_id: Uuid,
    publication_kind: RouteSetPublicationKind,
    recovery_effect_run_id: Option<Uuid>,
    interrupted_phase: InterruptedPhase,
    claim_mode: RecoveryClaimMode,
    claim_fence: i64,
    target_workshop_id: Uuid,
    original_global_fence_token: i64,
    target_route_fence_token: i64,
    target_generation: i64,
    target_projection_digest: String,
    target_disposition: String,
    selector: String,
    prior_selector: Option<String>,
    prior_directory_device: Option<i64>,
    prior_directory_inode: Option<i64>,
    prior_loaded_identity: Option<Value>,
    candidate_directory_device: Option<i64>,
    candidate_directory_inode: Option<i64>,
    sealed_count: Option<i32>,
    sealed_present_count: Option<i32>,
    route_set_digest: Option<String>,
    record_count: i64,
    publication_started_at: Option<OffsetDateTime>,
    observed_selector: Option<String>,
    observed_loaded_identity: Option<RouteSetGenerationIdentity>,
}

#[derive(Clone, Debug, PartialEq)]
pub(super) struct RouteSetRecoveryState {
    pub publication_id: Uuid,
    pub publication_kind: RouteSetPublicationKind,
    pub recovery_effect_run_id: Option<Uuid>,
    pub interrupted_phase: InterruptedPhase,
    pub claim_mode: RecoveryClaimMode,
    pub claim_fence: i64,
    pub target_workshop_id: Uuid,
    pub original_global_fence_token: i64,
    pub target_route_fence_token: i64,
    pub target_generation: i64,
    pub target_projection_digest: String,
    pub target_disposition: RouteDisposition,
    pub selector: String,
    pub prior: Option<PriorSelector>,
    pub prior_loaded_identity: Option<Value>,
    pub candidate: Option<PriorSelector>,
    pub sealed_count: Option<usize>,
    pub sealed_present_count: Option<usize>,
    pub route_set_digest: Option<String>,
    pub record_count: usize,
    pub publication_started: bool,
    pub observed_selector: Option<String>,
    pub observed_loaded_identity: Option<RouteSetGenerationIdentity>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ReadRecoveryState {
    Claimed,
    ClaimLost,
}

impl ReadRecoveryState {
    const fn trace_outcome(self) -> &'static str {
        match self {
            Self::Claimed => "claimed",
            Self::ClaimLost => "claim_lost",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum ResolutionKind {
    Candidate,
    Prior,
    Unstarted,
    Inconclusive,
}
impl ResolutionKind {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Candidate => "candidate",
            Self::Prior => "prior",
            Self::Unstarted => "unstarted",
            Self::Inconclusive => "inconclusive",
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(super) struct ResolutionObservation {
    pub kind: ResolutionKind,
    pub selector: Option<String>,
    pub directory_device: Option<u64>,
    pub directory_inode: Option<u64>,
    pub loaded_identity: Option<Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(super) struct ResolutionEvidence {
    pub publication_id: Uuid,
    pub claim_fence: i64,
    pub claim_mode: RecoveryClaimMode,
    pub reconciliation_operation_id: Uuid,
    pub reconciliation_operation_attempt: i32,
    pub reconciliation_operation_lease_owner: String,
    pub resolution_kind: ResolutionKind,
    pub interrupted_phase: InterruptedPhase,
    pub observed_selector: Option<String>,
    pub observed_directory_device: Option<i64>,
    pub observed_directory_inode: Option<i64>,
    pub observed_loaded_identity: Option<Value>,
}

#[derive(Clone, Debug, PartialEq)]
pub(super) enum ResolveObservationOutcome {
    Recorded(ResolutionEvidence),
    Replay(ResolutionEvidence),
    Conflict,
    ClaimLost,
    EvidenceMismatch,
    Invalid,
}

impl ResolveObservationOutcome {
    const fn trace_outcome(&self) -> &'static str {
        match self {
            Self::Recorded(_) => "recorded",
            Self::Replay(_) => "replay",
            Self::Conflict => "conflict",
            Self::ClaimLost => "claim_lost",
            Self::EvidenceMismatch => "evidence_mismatch",
            Self::Invalid => "invalid",
        }
    }
}

/// A locally reviewed acceptance of one exact immutable 0030 observation.
/// Construction refuses inconclusive evidence, so this capability cannot be
/// used to turn uncertainty into a terminal database mutation.
pub(super) struct ReviewedTerminalDecision {
    evidence: ResolutionEvidence,
    digest: String,
}

impl ReviewedTerminalDecision {
    pub(super) fn verify_accept(
        claim: &RouteSetRecoveryClaim,
        evidence: ResolutionEvidence,
        reviewed_digest: &str,
    ) -> Result<Self, DriverError> {
        validate_claim(claim)?;
        validate_evidence_for_claim(claim, &evidence)?;
        if evidence.resolution_kind == ResolutionKind::Inconclusive {
            return Err(invalid(
                "inconclusive route-set recovery evidence cannot be terminalized",
            ));
        }
        let digest = terminal_decision_digest(claim, &evidence, "accept")?;
        if reviewed_digest != digest {
            return Err(invalid(
                "reviewed route-set recovery decision digest is invalid",
            ));
        }
        Ok(Self { evidence, digest })
    }

    pub(super) fn evidence(&self) -> &ResolutionEvidence {
        &self.evidence
    }

    pub(super) fn digest(&self) -> &str {
        &self.digest
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct RouteSetRecoveryNotApplied {
    pub publication_id: Uuid,
    pub driver_operation_id: Uuid,
    pub target_workshop_id: Uuid,
    pub resolution_kind: ResolutionKind,
    pub decision_digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct RecoveryRouteSetRecoveryNotApplied {
    pub publication_id: Uuid,
    pub effect_run_id: Uuid,
    pub publication_kind: RouteSetPublicationKind,
    pub target_workshop_id: Uuid,
    pub resolution_kind: ResolutionKind,
    pub decision_digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum RouteSetRecoveryTerminalResult {
    Applied(Box<RouteSetPublicationResponse>),
    NotApplied(RouteSetRecoveryNotApplied),
    RecoveryApplied(Box<RecoveryRouteSetPublicationResponse>),
    RecoveryNotApplied(RecoveryRouteSetRecoveryNotApplied),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum FinishRecoveryRefusal {
    Invalid,
    Absent,
    Conflict,
    ProtocolInactive,
    ObservationMismatch,
    ReconciliationLeaseLost,
    AuthorityInconsistent,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum FinishRouteSetRecoveryOutcome {
    Completed(RouteSetRecoveryTerminalResult),
    Replay(RouteSetRecoveryTerminalResult),
    Refused(FinishRecoveryRefusal),
}

impl FinishRouteSetRecoveryOutcome {
    const fn trace_outcome(&self) -> &'static str {
        match self {
            Self::Completed(_) => "completed",
            Self::Replay(_) => "replay",
            Self::Refused(FinishRecoveryRefusal::Invalid) => "invalid",
            Self::Refused(FinishRecoveryRefusal::Absent) => "absent",
            Self::Refused(FinishRecoveryRefusal::Conflict) => "conflict",
            Self::Refused(FinishRecoveryRefusal::ProtocolInactive) => "protocol_inactive",
            Self::Refused(FinishRecoveryRefusal::ObservationMismatch) => "observation_mismatch",
            Self::Refused(FinishRecoveryRefusal::ReconciliationLeaseLost) => {
                "reconciliation_lease_lost"
            }
            Self::Refused(FinishRecoveryRefusal::AuthorityInconsistent) => "authority_inconsistent",
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTerminalResponse {
    outcome: String,
    publication_id: Uuid,
    driver_operation_id: Uuid,
    target_workshop_id: Uuid,
    resolution_claim_fence: i64,
    resolution_kind: ResolutionKind,
    reconciliation_operation_id: Uuid,
    reconciliation_operation_attempt: i32,
    reconciliation_operation_lease_owner: String,
    decision_digest: String,
    driver_response: Option<Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRecoveryTerminalResponse {
    outcome: String,
    publication_id: Uuid,
    effect_run_id: Uuid,
    publication_kind: RouteSetPublicationKind,
    target_workshop_id: Uuid,
    resolution_claim_fence: i64,
    resolution_kind: ResolutionKind,
    reconciliation_operation_id: Uuid,
    reconciliation_operation_attempt: i32,
    reconciliation_operation_lease_owner: String,
    decision_digest: String,
    effect_response: Option<Value>,
}

#[tracing::instrument(name="deployment_driver.route_set_recovery.discover_dormant", skip_all, fields(page.limit=limit, page.returned=tracing::field::Empty))]
pub(super) async fn discover_interrupted_route_set_publications(
    ledger: &PgPool,
    after: Option<Uuid>,
    limit: usize,
) -> Result<Vec<InterruptedPublicationSummary>, DriverError> {
    if after.is_some_and(|id| id.is_nil()) || !(1..=MAX_DISCOVERY_LIMIT).contains(&limit) {
        return Err(invalid("route-set recovery discovery request is invalid"));
    }
    let limit = i32::try_from(limit)
        .map_err(|_| invalid("route-set recovery discovery limit is invalid"))?;
    let rows = sqlx::query_as::<_, DiscoveryRow>("select publication_id,target_workshop_id,publication_kind,interrupted_phase,claim_mode,claim_fence,claim_available,selector,route_set_digest,updated_at from control.discover_interrupted_route_set_publications($1,$2)")
        .bind(after).bind(limit).fetch_all(ledger).await.map_err(DriverError::internal)?;
    let rows = validate_discovery(after, rows)?;
    tracing::Span::current().record("page.returned", rows.len());
    Ok(rows)
}

#[tracing::instrument(name="deployment_driver.route_set_recovery.claim_dormant", skip_all, fields(publication.id=%request.publication_id, claim.outcome=tracing::field::Empty))]
pub(super) async fn claim_interrupted_route_set_publication(
    ledger: &PgPool,
    request: &RouteSetRecoveryClaimRequest,
) -> Result<ClaimInterruptedPublication, DriverError> {
    validate_claim_request(request)?;
    let row: ClaimRow = sqlx::query_as("select outcome,claim_fence,claim_mode from control.claim_interrupted_route_set_publication($1,$2,$3,$4,$5,$6,$7)")
        .bind(request.publication_id).bind(request.reconciliation_operation.id)
        .bind(request.reconciliation_operation.attempt).bind(&request.reconciliation_operation.owner)
        .bind(request.reconciliation_owner).bind(request.reconciliation_token).bind(request.ttl_seconds)
        .fetch_one(ledger).await.map_err(DriverError::internal)?;
    let parsed = parse_claim(request, row);
    record_parsed_outcome("claim.outcome", &parsed, |outcome| outcome.trace_outcome());
    parsed
}

#[tracing::instrument(name="deployment_driver.route_set_recovery.renew_dormant", skip_all, fields(publication.id=%claim.publication_id, claim.outcome=tracing::field::Empty))]
pub(super) async fn renew_interrupted_route_set_publication_claim(
    ledger: &PgPool,
    claim: &RouteSetRecoveryClaim,
) -> Result<RenewRecoveryClaimOutcome, DriverError> {
    validate_claim(claim)?;
    let outcome: String = sqlx::query_scalar(
        "select control.renew_interrupted_route_set_publication_claim($1,$2,$3,$4,$5)",
    )
    .bind(claim.publication_id)
    .bind(claim.reconciliation_owner)
    .bind(claim.reconciliation_token)
    .bind(claim.claim_fence)
    .bind(claim.ttl_seconds)
    .fetch_one(ledger)
    .await
    .map_err(DriverError::internal)?;
    let parsed = match outcome.as_str() {
        "renewed" => Ok(RenewRecoveryClaimOutcome::Renewed),
        "claim_lost" => Ok(RenewRecoveryClaimOutcome::ClaimLost),
        "invalid" => Ok(RenewRecoveryClaimOutcome::Invalid),
        _ => Err(invalid("route-set recovery renewal outcome is invalid")),
    };
    record_parsed_outcome("claim.outcome", &parsed, |outcome| outcome.trace_outcome());
    parsed
}

#[tracing::instrument(name="deployment_driver.route_set_recovery.read_state_dormant", skip_all, fields(publication.id=%claim.publication_id, state.outcome=tracing::field::Empty))]
pub(super) async fn read_interrupted_route_set_publication_state(
    ledger: &PgPool,
    claim: &RouteSetRecoveryClaim,
) -> Result<(ReadRecoveryState, Option<RouteSetRecoveryState>), DriverError> {
    validate_claim(claim)?;
    let row: StateRow = sqlx::query_as("select outcome,state from control.read_interrupted_route_set_publication_state($1,$2,$3,$4)")
        .bind(claim.publication_id).bind(claim.reconciliation_owner).bind(claim.reconciliation_token).bind(claim.claim_fence)
        .fetch_one(ledger).await.map_err(DriverError::internal)?;
    let parsed = match (row.0.as_str(), row.1) {
        ("claim_lost", None) => Ok((ReadRecoveryState::ClaimLost, None)),
        ("claimed", Some(value)) => {
            Ok((ReadRecoveryState::Claimed, Some(parse_state(claim, value)?)))
        }
        _ => Err(invalid("route-set recovery state response is malformed")),
    };
    record_parsed_outcome("state.outcome", &parsed, |outcome| {
        outcome.0.trace_outcome()
    });
    parsed
}

#[tracing::instrument(name="deployment_driver.route_set_recovery.resolve_observation_dormant", skip_all, fields(publication.id=%claim.publication_id, resolution.kind=observation.kind.as_str(), resolution.outcome=tracing::field::Empty))]
pub(super) async fn resolve_interrupted_route_set_publication_observation(
    ledger: &PgPool,
    claim: &RouteSetRecoveryClaim,
    state: &RouteSetRecoveryState,
    observation: &ResolutionObservation,
) -> Result<ResolveObservationOutcome, DriverError> {
    validate_claim(claim)?;
    validate_observation(state, observation)?;
    let device = pg_identity(observation.directory_device)?;
    let inode = pg_identity(observation.directory_inode)?;
    let row: ResolutionRow = sqlx::query_as("select outcome,evidence from control.resolve_interrupted_route_set_publication_observation($1,$2,$3,$4,$5,$6,$7,$8,$9)")
        .bind(claim.publication_id).bind(claim.reconciliation_owner).bind(claim.reconciliation_token).bind(claim.claim_fence)
        .bind(observation.kind.as_str()).bind(&observation.selector).bind(device).bind(inode).bind(&observation.loaded_identity)
        .fetch_one(ledger).await.map_err(DriverError::internal)?;
    let parsed = parse_resolution(claim, state, observation, row);
    record_parsed_outcome("resolution.outcome", &parsed, |outcome| {
        outcome.trace_outcome()
    });
    parsed
}

#[tracing::instrument(name="deployment_driver.route_set_recovery.finish_dormant", skip_all, fields(publication.id=%claim.publication_id, resolution.kind=decision.evidence.resolution_kind.as_str(), terminal.outcome=tracing::field::Empty))]
pub(super) async fn finish_route_set_publication_recovery(
    ledger: &PgPool,
    claim: &RouteSetRecoveryClaim,
    state: &RouteSetRecoveryState,
    decision: &ReviewedTerminalDecision,
) -> Result<FinishRouteSetRecoveryOutcome, DriverError> {
    validate_claim(claim)?;
    validate_evidence_for_claim(claim, &decision.evidence)?;
    validate_terminal_state(state, claim, &decision.evidence)?;
    if decision.evidence.resolution_kind == ResolutionKind::Inconclusive
        || decision.digest != terminal_decision_digest(claim, &decision.evidence, "accept")?
    {
        return Err(invalid("route-set recovery terminal decision is invalid"));
    }
    let row: FinishRecoveryRow = sqlx::query_as(
        "select outcome,response from control.finish_route_set_publication_recovery($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
    )
    .bind(claim.publication_id)
    .bind(claim.claim_fence)
    .bind(claim.reconciliation_operation_id)
    .bind(claim.reconciliation_operation_attempt)
    .bind(&claim.reconciliation_operation_lease_owner)
    .bind(claim.reconciliation_owner)
    .bind(claim.reconciliation_token)
    .bind(decision.evidence.resolution_kind.as_str())
    .bind("accept")
    .bind(&decision.digest)
    .fetch_one(ledger)
    .await
    .map_err(DriverError::internal)?;
    let parsed = parse_finish_recovery(claim, state, decision, row);
    record_parsed_outcome("terminal.outcome", &parsed, |outcome| {
        outcome.trace_outcome()
    });
    parsed
}

fn record_parsed_outcome<T>(
    field: &'static str,
    parsed: &Result<T, DriverError>,
    outcome: impl FnOnce(&T) -> &'static str,
) {
    tracing::Span::current().record(field, parsed.as_ref().map_or("contract_drift", outcome));
}

fn validate_discovery(
    after: Option<Uuid>,
    rows: Vec<DiscoveryRow>,
) -> Result<Vec<InterruptedPublicationSummary>, DriverError> {
    let mut result = Vec::with_capacity(rows.len());
    let mut previous = after;
    for row in rows {
        if row.0.is_nil() || row.1.is_nil() || previous.is_some_and(|id| id >= row.0) || row.5 < 0 {
            return Err(invalid("route-set recovery discovery row is invalid"));
        }
        let publication_kind = parse_publication_kind(&row.2)?;
        let phase = InterruptedPhase::parse(&row.3)
            .ok_or_else(|| invalid("route-set recovery discovery phase is invalid"))?;
        let mode = RecoveryClaimMode::parse(&row.4)
            .ok_or_else(|| invalid("route-set recovery discovery mode is invalid"))?;
        if mode == RecoveryClaimMode::WriteCleanup
            && !matches!(phase, InterruptedPhase::Staging | InterruptedPhase::Sealed)
        {
            return Err(invalid(
                "route-set recovery discovery mode conflicts with phase",
            ));
        }
        if row.7 != RouteSetGenerationName::new(row.0, publication_kind).selector_target() {
            return Err(invalid(
                "route-set recovery discovery selector is not canonical",
            ));
        }
        if let Some(digest) = &row.8 {
            validate_digest(digest, "route-set recovery digest").map_err(DriverError::internal)?;
        }
        if matches!(phase, InterruptedPhase::Staging) != row.8.is_none() {
            return Err(invalid(
                "route-set recovery discovery digest conflicts with phase",
            ));
        }
        previous = Some(row.0);
        result.push(InterruptedPublicationSummary {
            publication_id: row.0,
            target_workshop_id: row.1,
            publication_kind,
            interrupted_phase: phase,
            claim_mode: mode,
            claim_fence: row.5,
            claim_available: row.6,
            selector: row.7,
            route_set_digest: row.8,
            updated_at: row.9,
        });
    }
    Ok(result)
}

fn parse_publication_kind(value: &str) -> Result<RouteSetPublicationKind, DriverError> {
    match value {
        "projection" => Ok(RouteSetPublicationKind::Projection),
        "recovery_maintenance" => Ok(RouteSetPublicationKind::RecoveryMaintenance),
        "recovery_restore" => Ok(RouteSetPublicationKind::RecoveryRestore),
        _ => Err(invalid("route-set recovery discovery kind is invalid")),
    }
}

fn validate_evidence_for_claim(
    claim: &RouteSetRecoveryClaim,
    evidence: &ResolutionEvidence,
) -> Result<(), DriverError> {
    if evidence.publication_id != claim.publication_id
        || evidence.claim_fence != claim.claim_fence
        || evidence.claim_mode != claim.claim_mode
        || evidence.reconciliation_operation_id != claim.reconciliation_operation_id
        || evidence.reconciliation_operation_attempt != claim.reconciliation_operation_attempt
        || evidence.reconciliation_operation_lease_owner
            != claim.reconciliation_operation_lease_owner
    {
        return Err(invalid(
            "route-set recovery evidence differs from its authenticated claim",
        ));
    }
    let has_selector = evidence.observed_selector.is_some();
    let has_device = evidence.observed_directory_device.is_some();
    let has_inode = evidence.observed_directory_inode.is_some();
    if has_selector != has_device || has_selector != has_inode {
        return Err(invalid(
            "route-set recovery evidence filesystem identity is incomplete",
        ));
    }
    match evidence.resolution_kind {
        ResolutionKind::Candidate
            if !has_selector || evidence.observed_loaded_identity.is_none() =>
        {
            Err(invalid("candidate recovery evidence is incomplete"))
        }
        ResolutionKind::Prior if !has_selector || evidence.observed_loaded_identity.is_none() => {
            Err(invalid("prior recovery evidence is incomplete"))
        }
        ResolutionKind::Unstarted | ResolutionKind::Inconclusive
            if has_selector || evidence.observed_loaded_identity.is_some() =>
        {
            Err(invalid("empty recovery evidence contains an identity"))
        }
        _ => Ok(()),
    }
}

fn validate_terminal_state(
    state: &RouteSetRecoveryState,
    claim: &RouteSetRecoveryClaim,
    evidence: &ResolutionEvidence,
) -> Result<(), DriverError> {
    if state.publication_id != claim.publication_id
        || state.claim_fence != claim.claim_fence
        || state.claim_mode != claim.claim_mode
        || evidence.interrupted_phase != state.interrupted_phase
    {
        return Err(invalid(
            "route-set recovery terminal state differs from its claim",
        ));
    }
    let expected_candidate_identity = if evidence.resolution_kind == ResolutionKind::Candidate {
        let identity = RouteSetGenerationIdentity::new(
            state.publication_id,
            state.publication_kind,
            state.original_global_fence_token,
            state.target_workshop_id,
            state.target_route_fence_token,
            state
                .route_set_digest
                .clone()
                .ok_or_else(|| invalid("route-set recovery candidate digest is absent"))?,
        )?;
        Some(serde_json::to_value(identity).map_err(DriverError::internal)?)
    } else {
        None
    };
    match evidence.resolution_kind {
        ResolutionKind::Candidate
            if matches!(
                state.interrupted_phase,
                InterruptedPhase::PublicationStarted | InterruptedPhase::Observed
            ) && evidence.observed_selector.as_deref() == Some(state.selector.as_str())
                && evidence.observed_directory_device
                    == state
                        .candidate
                        .as_ref()
                        .and_then(|candidate| i64::try_from(candidate.directory_device()).ok())
                && evidence.observed_directory_inode
                    == state
                        .candidate
                        .as_ref()
                        .and_then(|candidate| i64::try_from(candidate.directory_inode()).ok())
                && evidence.observed_loaded_identity == expected_candidate_identity => {}
        ResolutionKind::Prior
            if matches!(
                state.interrupted_phase,
                InterruptedPhase::Staging
                    | InterruptedPhase::Sealed
                    | InterruptedPhase::PublicationStarted
            ) && evidence.observed_selector.as_deref()
                == state.prior.as_ref().map(PriorSelector::target)
                && evidence.observed_directory_device
                    == state
                        .prior
                        .as_ref()
                        .and_then(|prior| i64::try_from(prior.directory_device()).ok())
                && evidence.observed_directory_inode
                    == state
                        .prior
                        .as_ref()
                        .and_then(|prior| i64::try_from(prior.directory_inode()).ok())
                && evidence.observed_loaded_identity == state.prior_loaded_identity => {}
        ResolutionKind::Unstarted
            if state.interrupted_phase == InterruptedPhase::Staging
                && state.record_count == 0
                && state.prior.is_none()
                && state.candidate.is_none()
                && !state.publication_started => {}
        _ => {
            return Err(invalid(
                "route-set recovery evidence cannot terminalize this state",
            ));
        }
    }
    Ok(())
}

fn terminal_decision_digest(
    claim: &RouteSetRecoveryClaim,
    evidence: &ResolutionEvidence,
    decision: &str,
) -> Result<String, DriverError> {
    let resolution_kind = evidence.resolution_kind;
    let evidence = serde_json::to_value(evidence)
        .map_err(|_| invalid("route-set recovery evidence cannot be serialized"))?;
    let evidence_text = postgres_jsonb_text(&evidence)?;
    let token_digest = Sha256::digest(
        [
            b"mb-route-set-reconciliation-token-v1".as_slice(),
            claim.reconciliation_token.as_bytes(),
        ]
        .concat(),
    );
    let mut digest = Sha256::new();
    digest.update(b"mb-route-set-terminal-decision-v1");
    digest.update(claim.publication_id.as_bytes());
    digest.update(claim.claim_fence.to_be_bytes());
    digest.update(claim.reconciliation_operation_id.as_bytes());
    digest.update(claim.reconciliation_operation_attempt.to_be_bytes());
    update_length_prefixed(
        &mut digest,
        claim.reconciliation_operation_lease_owner.as_bytes(),
    )?;
    digest.update(claim.reconciliation_owner.as_bytes());
    digest.update(token_digest);
    update_length_prefixed(&mut digest, resolution_kind.as_str().as_bytes())?;
    update_length_prefixed(&mut digest, decision.as_bytes())?;
    digest.update(Sha256::digest(evidence_text.as_bytes()));
    Ok(format!("{:x}", digest.finalize()))
}

fn update_length_prefixed(hasher: &mut Sha256, value: &[u8]) -> Result<(), DriverError> {
    let length = i32::try_from(value.len())
        .map_err(|_| invalid("route-set terminal digest field exceeded its bound"))?;
    hasher.update(length.to_be_bytes());
    hasher.update(value);
    Ok(())
}

/// PostgreSQL `jsonb::text` orders object keys by UTF-8 byte length and then
/// byte value, with one space after separators. The 0031 digest deliberately
/// hashes that representation, so this renderer is closed to JSON values and
/// never accepts non-finite numeric data.
fn postgres_jsonb_text(value: &Value) -> Result<String, DriverError> {
    match value {
        Value::Null => Ok("null".into()),
        Value::Bool(value) => Ok(value.to_string()),
        Value::Number(value) => Ok(value.to_string()),
        Value::String(value) => serde_json::to_string(value).map_err(DriverError::internal),
        Value::Array(values) => {
            let values = values
                .iter()
                .map(postgres_jsonb_text)
                .collect::<Result<Vec<_>, _>>()?;
            Ok(format!("[{}]", values.join(", ")))
        }
        Value::Object(values) => {
            let mut entries = values.iter().collect::<Vec<_>>();
            entries.sort_by(|(left, _), (right, _)| {
                left.len()
                    .cmp(&right.len())
                    .then_with(|| left.as_bytes().cmp(right.as_bytes()))
            });
            let entries = entries
                .into_iter()
                .map(|(key, value)| {
                    Ok(format!(
                        "{}: {}",
                        serde_json::to_string(key).map_err(DriverError::internal)?,
                        postgres_jsonb_text(value)?
                    ))
                })
                .collect::<Result<Vec<_>, DriverError>>()?;
            Ok(format!("{{{}}}", entries.join(", ")))
        }
    }
}

fn parse_finish_recovery(
    claim: &RouteSetRecoveryClaim,
    state: &RouteSetRecoveryState,
    decision: &ReviewedTerminalDecision,
    row: FinishRecoveryRow,
) -> Result<FinishRouteSetRecoveryOutcome, DriverError> {
    let terminal = match row.0.as_str() {
        "completed" | "replay" => {
            let value = row
                .1
                .ok_or_else(|| invalid("route-set recovery terminal response is absent"))?;
            let keys: &[&str] = if state.publication_kind == RouteSetPublicationKind::Projection {
                &TERMINAL_RESPONSE_KEYS
            } else {
                &RECOVERY_TERMINAL_RESPONSE_KEYS
            };
            exact_keys(&value, keys, "route-set recovery terminal response")?;
            if state.publication_kind == RouteSetPublicationKind::Projection {
                parse_projection_terminal_response(claim, state, decision, value)?
            } else {
                parse_recovery_terminal_response(claim, state, decision, value)?
            }
        }
        "invalid" if row.1.is_none() => {
            return Ok(FinishRouteSetRecoveryOutcome::Refused(
                FinishRecoveryRefusal::Invalid,
            ));
        }
        "absent" if row.1.is_none() => {
            return Ok(FinishRouteSetRecoveryOutcome::Refused(
                FinishRecoveryRefusal::Absent,
            ));
        }
        "conflict" if row.1.is_none() => {
            return Ok(FinishRouteSetRecoveryOutcome::Refused(
                FinishRecoveryRefusal::Conflict,
            ));
        }
        "protocol_inactive" if row.1.is_none() => {
            return Ok(FinishRouteSetRecoveryOutcome::Refused(
                FinishRecoveryRefusal::ProtocolInactive,
            ));
        }
        "observation_mismatch" if row.1.is_none() => {
            return Ok(FinishRouteSetRecoveryOutcome::Refused(
                FinishRecoveryRefusal::ObservationMismatch,
            ));
        }
        "reconciliation_lease_lost" if row.1.is_none() => {
            return Ok(FinishRouteSetRecoveryOutcome::Refused(
                FinishRecoveryRefusal::ReconciliationLeaseLost,
            ));
        }
        "authority_inconsistent" if row.1.is_none() => {
            return Ok(FinishRouteSetRecoveryOutcome::Refused(
                FinishRecoveryRefusal::AuthorityInconsistent,
            ));
        }
        _ => return Err(invalid("route-set recovery finish response is malformed")),
    };
    if row.0 == "completed" {
        Ok(FinishRouteSetRecoveryOutcome::Completed(terminal))
    } else {
        Ok(FinishRouteSetRecoveryOutcome::Replay(terminal))
    }
}

fn parse_projection_terminal_response(
    claim: &RouteSetRecoveryClaim,
    state: &RouteSetRecoveryState,
    decision: &ReviewedTerminalDecision,
    value: Value,
) -> Result<RouteSetRecoveryTerminalResult, DriverError> {
    let raw: RawTerminalResponse = serde_json::from_value(value)
        .map_err(|_| invalid("route-set recovery terminal response is invalid"))?;
    if raw.publication_id != claim.publication_id
        || raw.target_workshop_id != state.target_workshop_id
        || raw.resolution_claim_fence != claim.claim_fence
        || raw.resolution_kind != decision.evidence.resolution_kind
        || raw.reconciliation_operation_id != claim.reconciliation_operation_id
        || raw.reconciliation_operation_attempt != claim.reconciliation_operation_attempt
        || raw.reconciliation_operation_lease_owner != claim.reconciliation_operation_lease_owner
        || raw.decision_digest != decision.digest
        || raw.driver_operation_id.is_nil()
    {
        return Err(invalid(
            "route-set recovery terminal response authority is invalid",
        ));
    }
    match raw.resolution_kind {
        ResolutionKind::Candidate if raw.outcome == "applied_recovered" => {
            let response = parse_publication_response(
                raw.driver_response
                    .ok_or_else(|| invalid("recovered driver response is absent"))?,
            )?;
            let expected_disposition = match state.target_disposition {
                RouteDisposition::Present => RouteSetAppliedDisposition::Present,
                RouteDisposition::Absent => RouteSetAppliedDisposition::Absent,
            };
            validate_publication_response_common(
                &response,
                &PublicationResponseExpectation {
                    publication_id: state.publication_id,
                    publication_kind: state.publication_kind,
                    driver_operation_id: raw.driver_operation_id,
                    workshop_id: state.target_workshop_id,
                    projection_generation: state.target_generation,
                    projection_digest: &state.target_projection_digest,
                    expected_disposition: Some(expected_disposition),
                },
            )?;
            let set = &response.route_set_evidence;
            let route = &response.route_evidence;
            let candidate = state
                .candidate
                .as_ref()
                .ok_or_else(|| invalid("recovered candidate identity is absent"))?;
            if route.route_fence_token != state.target_route_fence_token
                || set.selector != state.selector
                || Some(set.route_set_digest.as_str()) != state.route_set_digest.as_deref()
                || Some(set.snapshot_count) != state.sealed_count
                || Some(set.present_count) != state.sealed_present_count
                || set.global_fence_token != state.original_global_fence_token
                || set.directory_device != candidate.directory_device()
                || set.directory_inode != candidate.directory_inode()
            {
                return Err(invalid(
                    "recovered route-set response differs from its observation",
                ));
            }
            Ok(RouteSetRecoveryTerminalResult::Applied(Box::new(response)))
        }
        ResolutionKind::Prior | ResolutionKind::Unstarted
            if raw.outcome == "not_applied" && raw.driver_response.is_none() =>
        {
            Ok(RouteSetRecoveryTerminalResult::NotApplied(
                RouteSetRecoveryNotApplied {
                    publication_id: raw.publication_id,
                    driver_operation_id: raw.driver_operation_id,
                    target_workshop_id: raw.target_workshop_id,
                    resolution_kind: raw.resolution_kind,
                    decision_digest: raw.decision_digest,
                },
            ))
        }
        _ => Err(invalid(
            "route-set recovery terminal response outcome is invalid",
        )),
    }
}

fn parse_recovery_terminal_response(
    claim: &RouteSetRecoveryClaim,
    state: &RouteSetRecoveryState,
    decision: &ReviewedTerminalDecision,
    value: Value,
) -> Result<RouteSetRecoveryTerminalResult, DriverError> {
    let raw: RawRecoveryTerminalResponse = serde_json::from_value(value)
        .map_err(|_| invalid("recovery-kind terminal response is invalid"))?;
    let effect_run_id = state
        .recovery_effect_run_id
        .ok_or_else(|| invalid("recovery-kind effect owner is absent"))?;
    if raw.publication_id != claim.publication_id
        || raw.effect_run_id != effect_run_id
        || raw.publication_kind != state.publication_kind
        || raw.target_workshop_id != state.target_workshop_id
        || raw.resolution_claim_fence != claim.claim_fence
        || raw.resolution_kind != decision.evidence.resolution_kind
        || raw.reconciliation_operation_id != claim.reconciliation_operation_id
        || raw.reconciliation_operation_attempt != claim.reconciliation_operation_attempt
        || raw.reconciliation_operation_lease_owner != claim.reconciliation_operation_lease_owner
        || raw.decision_digest != decision.digest
    {
        return Err(invalid(
            "recovery-kind terminal response authority is invalid",
        ));
    }
    match raw.resolution_kind {
        ResolutionKind::Candidate => {
            let expected_outcome = match state.publication_kind {
                RouteSetPublicationKind::RecoveryMaintenance => "maintenance_recovered",
                RouteSetPublicationKind::RecoveryRestore => "restored_recovered",
                RouteSetPublicationKind::Projection | RouteSetPublicationKind::Startup => {
                    return Err(invalid("projection used recovery-kind terminal response"));
                }
            };
            if raw.outcome != expected_outcome {
                return Err(invalid("recovery-kind terminal outcome is invalid"));
            }
            let response = parse_recovery_response_for_kind(
                raw.effect_response
                    .ok_or_else(|| invalid("recovery-kind effect response is absent"))?,
                state.publication_kind,
            )?;
            validate_recovered_effect_response(&response, state, effect_run_id)?;
            Ok(RouteSetRecoveryTerminalResult::RecoveryApplied(Box::new(
                response,
            )))
        }
        ResolutionKind::Prior | ResolutionKind::Unstarted
            if raw.outcome == "not_applied" && raw.effect_response.is_none() =>
        {
            Ok(RouteSetRecoveryTerminalResult::RecoveryNotApplied(
                RecoveryRouteSetRecoveryNotApplied {
                    publication_id: raw.publication_id,
                    effect_run_id,
                    publication_kind: raw.publication_kind,
                    target_workshop_id: raw.target_workshop_id,
                    resolution_kind: raw.resolution_kind,
                    decision_digest: raw.decision_digest,
                },
            ))
        }
        _ => Err(invalid(
            "recovery-kind terminal response outcome is invalid",
        )),
    }
}

fn validate_recovered_effect_response(
    response: &RecoveryRouteSetPublicationResponse,
    state: &RouteSetRecoveryState,
    effect_run_id: Uuid,
) -> Result<(), DriverError> {
    let route = &response.route_evidence;
    let set = &response.route_set_evidence;
    let expected_outcome = match state.publication_kind {
        RouteSetPublicationKind::RecoveryMaintenance => "maintenance",
        RouteSetPublicationKind::RecoveryRestore => "restored",
        RouteSetPublicationKind::Projection | RouteSetPublicationKind::Startup => {
            return Err(invalid("projection used recovered effect response"));
        }
    };
    let expected_mode = match state.publication_kind {
        RouteSetPublicationKind::RecoveryMaintenance => {
            super::route_set_recovery_publication_db::RecoveryRouteMode::Maintenance
        }
        RouteSetPublicationKind::RecoveryRestore => {
            super::route_set_recovery_publication_db::RecoveryRouteMode::Restored
        }
        RouteSetPublicationKind::Projection | RouteSetPublicationKind::Startup => unreachable!(),
    };
    let expected_disposition = match state.target_disposition {
        RouteDisposition::Present => RouteSetAppliedDisposition::Present,
        RouteDisposition::Absent => RouteSetAppliedDisposition::Absent,
    };
    let candidate = state
        .candidate
        .as_ref()
        .ok_or_else(|| invalid("recovery-kind candidate identity is absent"))?;
    if response.outcome != expected_outcome
        || response.effect_run_id != effect_run_id
        || response.route_fence_token
            != (state.publication_kind == RouteSetPublicationKind::RecoveryMaintenance)
                .then_some(state.target_route_fence_token)
        || route.effect_run_id != effect_run_id
        || route.workshop_id != state.target_workshop_id
        || route.generation != state.target_generation
        || route.projection_digest != state.target_projection_digest
        || route.disposition != expected_disposition
        || route.route_fence_token != state.target_route_fence_token
        || route.mode != expected_mode
        || validate_digest(&route.rendered_digest, "recovered effect rendered digest").is_err()
        || (route.disposition == RouteSetAppliedDisposition::Absent
            && route.rendered_digest
                != "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        || set.protocol_version != 1
        || set.publication_id != state.publication_id
        || set.publication_kind != state.publication_kind
        || set.selector != state.selector
        || Some(set.route_set_digest.as_str()) != state.route_set_digest.as_deref()
        || Some(set.snapshot_count) != state.sealed_count
        || Some(set.present_count) != state.sealed_present_count
        || set.global_fence_token != state.original_global_fence_token
        || set.directory_device != candidate.directory_device()
        || set.directory_inode != candidate.directory_inode()
    {
        return Err(invalid(
            "recovered effect response differs from its observation",
        ));
    }
    Ok(())
}

fn validate_claim_request(request: &RouteSetRecoveryClaimRequest) -> Result<(), DriverError> {
    if request.publication_id.is_nil()
        || request.reconciliation_operation.id.is_nil()
        || request.reconciliation_operation.attempt <= 0
        || request.reconciliation_operation.owner.trim().is_empty()
        || request.reconciliation_owner.is_nil()
        || request.reconciliation_token.is_nil()
        || !(MIN_TTL_SECONDS..=MAX_TTL_SECONDS).contains(&request.ttl_seconds)
    {
        Err(invalid("route-set recovery claim request is invalid"))
    } else {
        Ok(())
    }
}
fn validate_claim(claim: &RouteSetRecoveryClaim) -> Result<(), DriverError> {
    let request = RouteSetRecoveryClaimRequest {
        publication_id: claim.publication_id,
        reconciliation_operation: ControlOperationLease {
            id: claim.reconciliation_operation_id,
            attempt: claim.reconciliation_operation_attempt,
            owner: claim.reconciliation_operation_lease_owner.clone(),
        },
        reconciliation_owner: claim.reconciliation_owner,
        reconciliation_token: claim.reconciliation_token,
        ttl_seconds: claim.ttl_seconds,
    };
    validate_claim_request(&request)?;
    if claim.claim_fence <= 0 {
        Err(invalid("route-set recovery claim fence is invalid"))
    } else {
        Ok(())
    }
}
fn parse_claim(
    request: &RouteSetRecoveryClaimRequest,
    row: ClaimRow,
) -> Result<ClaimInterruptedPublication, DriverError> {
    let acquired = matches!(row.0.as_str(), "acquired" | "replay");
    if acquired {
        let fence = row
            .1
            .filter(|v| *v > 0)
            .ok_or_else(|| invalid("route-set recovery claim response is malformed"))?;
        let mode = row
            .2
            .as_deref()
            .and_then(RecoveryClaimMode::parse)
            .ok_or_else(|| invalid("route-set recovery claim response is malformed"))?;
        let claim = RouteSetRecoveryClaim {
            publication_id: request.publication_id,
            reconciliation_operation_id: request.reconciliation_operation.id,
            reconciliation_operation_attempt: request.reconciliation_operation.attempt,
            reconciliation_operation_lease_owner: request.reconciliation_operation.owner.clone(),
            reconciliation_owner: request.reconciliation_owner,
            reconciliation_token: request.reconciliation_token,
            claim_fence: fence,
            claim_mode: mode,
            ttl_seconds: request.ttl_seconds,
        };
        return Ok(if row.0 == "acquired" {
            ClaimInterruptedPublication::Acquired(claim)
        } else {
            ClaimInterruptedPublication::Replay(claim)
        });
    }
    if row.0 == "busy" {
        let claim_fence = row
            .1
            .filter(|value| *value > 0)
            .ok_or_else(|| invalid("route-set recovery busy response fence is malformed"))?;
        let claim_mode = row
            .2
            .as_deref()
            .and_then(RecoveryClaimMode::parse)
            .ok_or_else(|| invalid("route-set recovery busy response mode is malformed"))?;
        return Ok(ClaimInterruptedPublication::Busy {
            claim_fence,
            claim_mode,
        });
    }
    if row.0 == "terminal" {
        let claim_fence = row
            .1
            .filter(|value| *value >= 0)
            .ok_or_else(|| invalid("route-set recovery terminal response fence is malformed"))?;
        if row.2.is_some() {
            return Err(invalid(
                "route-set recovery terminal response mode is malformed",
            ));
        }
        return Ok(ClaimInterruptedPublication::Terminal { claim_fence });
    }
    let refusal = match row.0.as_str() {
        "invalid" => ClaimRefusal::Invalid,
        "absent" => ClaimRefusal::Absent,
        "protocol_inactive" => ClaimRefusal::ProtocolInactive,
        "reconciliation_lease_lost" => ClaimRefusal::ReconciliationLeaseLost,
        "wrong_phase" => ClaimRefusal::WrongPhase,
        "authority_inconsistent" => ClaimRefusal::AuthorityInconsistent,
        "not_expired" => ClaimRefusal::NotExpired,
        _ => return Err(invalid("route-set recovery claim outcome is invalid")),
    };
    if row.1.is_some() || row.2.is_some() {
        return Err(invalid("route-set recovery refusal shape is malformed"));
    }
    Ok(ClaimInterruptedPublication::Refused(refusal))
}

fn parse_state(
    claim: &RouteSetRecoveryClaim,
    value: Value,
) -> Result<RouteSetRecoveryState, DriverError> {
    exact_keys(&value, &STATE_KEYS, "route-set recovery state")?;
    let raw: RawRecoveryState = serde_json::from_value(value)
        .map_err(|_| invalid("route-set recovery state is malformed"))?;
    if raw.protocol_version != 1
        || raw.publication_id != claim.publication_id
        || match raw.publication_kind {
            RouteSetPublicationKind::Projection => raw.recovery_effect_run_id.is_some(),
            RouteSetPublicationKind::RecoveryMaintenance
            | RouteSetPublicationKind::RecoveryRestore => raw
                .recovery_effect_run_id
                .is_none_or(|effect_run_id| effect_run_id.is_nil()),
            RouteSetPublicationKind::Startup => true,
        }
        || raw.claim_fence != claim.claim_fence
        || raw.claim_mode != claim.claim_mode
        || raw.target_workshop_id.is_nil()
        || raw.original_global_fence_token <= 0
        || raw.target_route_fence_token <= 0
        || raw.target_generation <= 0
        || raw.record_count < 0
        || raw.record_count > 500
    {
        return Err(invalid("route-set recovery state authority is invalid"));
    }
    let expected_selector =
        RouteSetGenerationName::new(raw.publication_id, raw.publication_kind).selector_target();
    if raw.selector != expected_selector {
        return Err(invalid(
            "route-set recovery candidate selector is not canonical",
        ));
    }
    validate_digest(&raw.target_projection_digest, "target projection digest")
        .map_err(DriverError::internal)?;
    let target_disposition = RouteDisposition::parse(&raw.target_disposition)?;
    let prior = selector_from_nullable_parts(
        raw.prior_selector.clone(),
        raw.prior_directory_device,
        raw.prior_directory_inode,
        "prior",
    )?;
    validate_prior_identity(prior.as_ref(), raw.prior_loaded_identity.as_ref())?;
    let candidate = selector_from_known_target(
        &raw.selector,
        raw.candidate_directory_device,
        raw.candidate_directory_inode,
    )?;
    let sealed_count = valid_count(raw.sealed_count)?;
    let present_count = valid_count(raw.sealed_present_count)?;
    if sealed_count.is_some() != present_count.is_some()
        || present_count.zip(sealed_count).is_some_and(|(p, t)| p > t)
    {
        return Err(invalid("route-set recovery sealed counts are invalid"));
    }
    if let Some(digest) = &raw.route_set_digest {
        validate_digest(digest, "route-set digest").map_err(DriverError::internal)?;
    }
    let sealed_shape = candidate.is_some()
        && sealed_count.is_some()
        && raw.route_set_digest.is_some()
        && usize::try_from(raw.record_count).ok() == sealed_count
        && prior.is_some();
    match raw.interrupted_phase {
        InterruptedPhase::Staging => {
            if candidate.is_some()
                || sealed_count.is_some()
                || raw.route_set_digest.is_some()
                || raw.publication_started_at.is_some()
                || raw.observed_selector.is_some()
                || raw.observed_loaded_identity.is_some()
            {
                return Err(invalid("staging recovery state is invalid"));
            }
        }
        InterruptedPhase::Sealed => {
            if !sealed_shape
                || raw.publication_started_at.is_some()
                || raw.observed_selector.is_some()
                || raw.observed_loaded_identity.is_some()
            {
                return Err(invalid("sealed recovery state is invalid"));
            }
        }
        InterruptedPhase::PublicationStarted => {
            if !sealed_shape
                || raw.publication_started_at.is_none()
                || raw.observed_selector.is_some()
                || raw.observed_loaded_identity.is_some()
            {
                return Err(invalid("started recovery state is invalid"));
            }
        }
        InterruptedPhase::Observed => {
            if !sealed_shape
                || raw.publication_started_at.is_none()
                || raw.observed_selector.as_deref() != Some(raw.selector.as_str())
                || raw.observed_loaded_identity.as_ref() != Some(&expected_identity(&raw)?)
            {
                return Err(invalid("observed recovery state is invalid"));
            }
        }
    }
    if raw.claim_mode == RecoveryClaimMode::WriteCleanup
        && (!matches!(
            raw.interrupted_phase,
            InterruptedPhase::Staging | InterruptedPhase::Sealed
        ) || raw.publication_started_at.is_some())
    {
        return Err(invalid("route-set recovery write-cleanup mode is invalid"));
    }
    Ok(RouteSetRecoveryState {
        publication_id: raw.publication_id,
        publication_kind: raw.publication_kind,
        recovery_effect_run_id: raw.recovery_effect_run_id,
        interrupted_phase: raw.interrupted_phase,
        claim_mode: raw.claim_mode,
        claim_fence: raw.claim_fence,
        target_workshop_id: raw.target_workshop_id,
        original_global_fence_token: raw.original_global_fence_token,
        target_route_fence_token: raw.target_route_fence_token,
        target_generation: raw.target_generation,
        target_projection_digest: raw.target_projection_digest,
        target_disposition,
        selector: raw.selector,
        prior,
        prior_loaded_identity: raw.prior_loaded_identity,
        candidate,
        sealed_count,
        sealed_present_count: present_count,
        route_set_digest: raw.route_set_digest,
        record_count: usize::try_from(raw.record_count)
            .map_err(|_| invalid("route-set recovery record count is invalid"))?,
        publication_started: raw.publication_started_at.is_some(),
        observed_selector: raw.observed_selector,
        observed_loaded_identity: raw.observed_loaded_identity,
    })
}

fn expected_identity(raw: &RawRecoveryState) -> Result<RouteSetGenerationIdentity, DriverError> {
    RouteSetGenerationIdentity::new(
        raw.publication_id,
        raw.publication_kind,
        raw.original_global_fence_token,
        raw.target_workshop_id,
        raw.target_route_fence_token,
        raw.route_set_digest
            .clone()
            .ok_or_else(|| invalid("route-set recovery digest is absent"))?,
    )
}
fn selector_from_nullable_parts(
    target: Option<String>,
    dev: Option<i64>,
    ino: Option<i64>,
    name: &str,
) -> Result<Option<PriorSelector>, DriverError> {
    match (target, dev, ino) {
        (None, None, None) => Ok(None),
        (Some(t), Some(d), Some(i)) if d > 0 && i > 0 => PriorSelector::from_recorded(
            t,
            u64::try_from(d)
                .map_err(|_| invalid(format!("route-set recovery {name} device is invalid")))?,
            u64::try_from(i)
                .map_err(|_| invalid(format!("route-set recovery {name} inode is invalid")))?,
        )
        .map(Some)
        .map_err(DriverError::internal),
        _ => Err(invalid(format!(
            "route-set recovery {name} selector is incomplete"
        ))),
    }
}
fn selector_from_known_target(
    target: &str,
    dev: Option<i64>,
    ino: Option<i64>,
) -> Result<Option<PriorSelector>, DriverError> {
    match (dev, ino) {
        (None, None) => Ok(None),
        (Some(d), Some(i)) if d > 0 && i > 0 => PriorSelector::from_recorded(
            target.to_owned(),
            u64::try_from(d)
                .map_err(|_| invalid("route-set recovery candidate device is invalid"))?,
            u64::try_from(i)
                .map_err(|_| invalid("route-set recovery candidate inode is invalid"))?,
        )
        .map(Some)
        .map_err(DriverError::internal),
        _ => Err(invalid(
            "route-set recovery candidate identity is incomplete",
        )),
    }
}
fn validate_prior_identity(
    prior: Option<&PriorSelector>,
    identity: Option<&Value>,
) -> Result<(), DriverError> {
    match prior {
        None if identity.is_none() => Ok(()),
        Some(prior) if prior.target() == "generations/boot-live" && identity.is_none() => Ok(()),
        Some(prior) => {
            let value = identity
                .ok_or_else(|| invalid("route-set recovery prior loaded identity is absent"))?;
            if prior.target().starts_with("generations/startup-") {
                let parsed: GatewayGenerationIdentity = serde_json::from_value(value.clone())
                    .map_err(|_| invalid("route-set recovery startup prior identity is invalid"))?;
                validate_digest(&parsed.sealed_digest, "startup prior digest")
                    .map_err(DriverError::internal)?;
                if parsed.effect_run_id.is_nil()
                    || prior.target() != format!("generations/startup-{}", parsed.effect_run_id)
                {
                    return Err(invalid("route-set recovery startup prior selector differs"));
                }
            } else if prior.target().starts_with("generations/release-") {
                let parsed: ReleaseOverlayGenerationIdentity =
                    serde_json::from_value(value.clone()).map_err(|_| {
                        invalid("route-set recovery release prior identity is invalid")
                    })?;
                parsed.validate()?;
                if prior.target()
                    != format!(
                        "generations/release-{}-{}",
                        parsed.fleet_run_id.simple(),
                        parsed.overlay_kind.as_str()
                    )
                {
                    return Err(invalid("route-set recovery release prior selector differs"));
                }
            } else {
                let parsed: RouteSetGenerationIdentity = serde_json::from_value(value.clone())
                    .map_err(|_| {
                        invalid("route-set recovery route-set prior identity is invalid")
                    })?;
                parsed.validate()?;
                if prior.target()
                    != RouteSetGenerationName::new(parsed.publication_id, parsed.publication_kind)
                        .selector_target()
                {
                    return Err(invalid(
                        "route-set recovery route-set prior selector differs",
                    ));
                }
            }
            Ok(())
        }
        _ => Err(invalid("route-set recovery prior identity is invalid")),
    }
}
fn valid_count(value: Option<i32>) -> Result<Option<usize>, DriverError> {
    value
        .map(|v| {
            usize::try_from(v)
                .ok()
                .filter(|v| *v <= 500)
                .ok_or_else(|| invalid("route-set recovery count is invalid"))
        })
        .transpose()
}
fn pg_identity(value: Option<u64>) -> Result<Option<i64>, DriverError> {
    value
        .map(|v| {
            i64::try_from(v)
                .ok()
                .filter(|v| *v > 0)
                .ok_or_else(|| invalid("route-set recovery file identity is invalid"))
        })
        .transpose()
}

fn validate_observation(
    state: &RouteSetRecoveryState,
    o: &ResolutionObservation,
) -> Result<(), DriverError> {
    let exact = o.selector.is_some()
        && o.directory_device.is_some()
        && o.directory_inode.is_some()
        && o.loaded_identity.is_some();
    let empty = o.selector.is_none()
        && o.directory_device.is_none()
        && o.directory_inode.is_none()
        && o.loaded_identity.is_none();
    if !match o.kind {
        ResolutionKind::Candidate | ResolutionKind::Prior => exact,
        ResolutionKind::Unstarted | ResolutionKind::Inconclusive => empty,
    } {
        return Err(invalid("route-set recovery observation shape is invalid"));
    }
    if let Some(selector) = &o.selector {
        validate_selector_target(selector).map_err(DriverError::internal)?;
    }
    match o.kind {
        ResolutionKind::Candidate => {
            let candidate = state
                .candidate
                .as_ref()
                .ok_or_else(|| invalid("candidate recovery state is incomplete"))?;
            let identity = RouteSetGenerationIdentity::new(
                state.publication_id,
                state.publication_kind,
                state.original_global_fence_token,
                state.target_workshop_id,
                state.target_route_fence_token,
                state
                    .route_set_digest
                    .clone()
                    .ok_or_else(|| invalid("candidate recovery digest is absent"))?,
            )?;
            if !matches!(
                state.interrupted_phase,
                InterruptedPhase::PublicationStarted | InterruptedPhase::Observed
            ) || o.selector.as_deref() != Some(candidate.target())
                || o.directory_device != Some(candidate.directory_device())
                || o.directory_inode != Some(candidate.directory_inode())
                || o.loaded_identity.as_ref()
                    != Some(&serde_json::to_value(identity).map_err(DriverError::internal)?)
            {
                return Err(invalid("candidate recovery observation differs"));
            }
        }
        ResolutionKind::Prior => {
            let prior = state
                .prior
                .as_ref()
                .ok_or_else(|| invalid("prior recovery state is incomplete"))?;
            if !matches!(
                state.interrupted_phase,
                InterruptedPhase::Staging
                    | InterruptedPhase::Sealed
                    | InterruptedPhase::PublicationStarted
            ) || o.selector.as_deref() != Some(prior.target())
                || o.directory_device != Some(prior.directory_device())
                || o.directory_inode != Some(prior.directory_inode())
                || o.loaded_identity != state.prior_loaded_identity
            {
                return Err(invalid("prior recovery observation differs"));
            }
        }
        ResolutionKind::Unstarted => {
            if state.interrupted_phase != InterruptedPhase::Staging
                || state.record_count != 0
                || state.prior.is_some()
                || state.candidate.is_some()
                || state.sealed_count.is_some()
                || state.route_set_digest.is_some()
                || state.publication_started
            {
                return Err(invalid("unstarted recovery observation differs"));
            }
        }
        ResolutionKind::Inconclusive => {}
    }
    Ok(())
}
fn parse_resolution(
    claim: &RouteSetRecoveryClaim,
    state: &RouteSetRecoveryState,
    o: &ResolutionObservation,
    row: ResolutionRow,
) -> Result<ResolveObservationOutcome, DriverError> {
    match row.0.as_str() {
        "recorded" | "replay" => {
            let value = row
                .1
                .ok_or_else(|| invalid("route-set recovery resolution evidence is absent"))?;
            exact_keys(
                &value,
                &EVIDENCE_KEYS,
                "route-set recovery resolution evidence",
            )?;
            let evidence: ResolutionEvidence = serde_json::from_value(value)
                .map_err(|_| invalid("route-set recovery resolution evidence is malformed"))?;
            if evidence.publication_id != claim.publication_id
                || evidence.claim_fence != claim.claim_fence
                || evidence.claim_mode != claim.claim_mode
                || evidence.reconciliation_operation_id != claim.reconciliation_operation_id
                || evidence.reconciliation_operation_attempt
                    != claim.reconciliation_operation_attempt
                || evidence.reconciliation_operation_lease_owner
                    != claim.reconciliation_operation_lease_owner
                || evidence.resolution_kind != o.kind
                || evidence.interrupted_phase != state.interrupted_phase
                || evidence.observed_selector != o.selector
                || evidence.observed_directory_device != pg_identity(o.directory_device)?
                || evidence.observed_directory_inode != pg_identity(o.directory_inode)?
                || evidence.observed_loaded_identity != o.loaded_identity
            {
                return Err(invalid("route-set recovery resolution evidence differs"));
            }
            if row.0 == "recorded" {
                Ok(ResolveObservationOutcome::Recorded(evidence))
            } else {
                Ok(ResolveObservationOutcome::Replay(evidence))
            }
        }
        "conflict" if row.1.is_none() => Ok(ResolveObservationOutcome::Conflict),
        "claim_lost" if row.1.is_none() => Ok(ResolveObservationOutcome::ClaimLost),
        "evidence_mismatch" if row.1.is_none() => Ok(ResolveObservationOutcome::EvidenceMismatch),
        "invalid" if row.1.is_none() => Ok(ResolveObservationOutcome::Invalid),
        _ => Err(invalid(
            "route-set recovery resolution response is malformed",
        )),
    }
}
fn exact_keys(value: &Value, expected: &[&str], description: &str) -> Result<(), DriverError> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid(format!("{description} is not an object")))?;
    let actual = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    if actual != expected {
        Err(invalid(format!("{description} keys are invalid")))
    } else {
        Ok(())
    }
}
fn invalid(message: impl Into<String>) -> DriverError {
    DriverError::internal(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn claim(mode: RecoveryClaimMode) -> RouteSetRecoveryClaim {
        RouteSetRecoveryClaim {
            publication_id: Uuid::parse_str("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap(),
            reconciliation_operation_id: Uuid::new_v4(),
            reconciliation_operation_attempt: 2,
            reconciliation_operation_lease_owner: "reconciler".into(),
            reconciliation_owner: Uuid::new_v4(),
            reconciliation_token: Uuid::new_v4(),
            claim_fence: 4,
            claim_mode: mode,
            ttl_seconds: 60,
        }
    }

    fn state_json(claim: &RouteSetRecoveryClaim, phase: &str) -> Value {
        state_json_kind(claim, phase, RouteSetPublicationKind::Projection)
    }

    fn state_json_kind(
        claim: &RouteSetRecoveryClaim,
        phase: &str,
        publication_kind: RouteSetPublicationKind,
    ) -> Value {
        let target = Uuid::parse_str("10000000-0000-0000-0000-000000000001").unwrap();
        let selector =
            RouteSetGenerationName::new(claim.publication_id, publication_kind).selector_target();
        let sealed = phase != "staging";
        json!({
            "protocol_version":1,"publication_id":claim.publication_id,
            "publication_kind":publication_kind,
            "recovery_effect_run_id":if publication_kind == RouteSetPublicationKind::Projection { Value::Null } else { json!(Uuid::new_v4()) },
            "interrupted_phase":phase,
            "claim_mode":claim.claim_mode,"claim_fence":claim.claim_fence,
            "target_workshop_id":target,"original_global_fence_token":11,
            "target_route_fence_token":12,"target_generation":7,
            "target_projection_digest":format!("sha256:{}","a".repeat(64)),
            "target_disposition":"present","selector":selector,
            "prior_selector":Value::Null,"prior_directory_device":Value::Null,
            "prior_directory_inode":Value::Null,"prior_loaded_identity":Value::Null,
            "candidate_directory_device":if sealed {json!(31)} else {Value::Null},
            "candidate_directory_inode":if sealed {json!(32)} else {Value::Null},
            "sealed_count":if sealed {json!(2)} else {Value::Null},
            "sealed_present_count":if sealed {json!(1)} else {Value::Null},
            "route_set_digest":if sealed {json!(format!("sha256:{}","b".repeat(64)))} else {Value::Null},
            "record_count":if sealed {2} else {0},"publication_started_at":Value::Null,
            "observed_selector":Value::Null,"observed_loaded_identity":Value::Null
        })
    }

    #[test]
    fn recovery_publication_kinds_are_observable_and_terminal_reviewable() {
        for kind in [
            RouteSetPublicationKind::RecoveryMaintenance,
            RouteSetPublicationKind::RecoveryRestore,
        ] {
            let claim = claim(RecoveryClaimMode::ObserveOnly);
            let state = parse_state(&claim, state_json_kind(&claim, "staging", kind)).unwrap();
            assert_eq!(state.publication_kind, kind);
            assert_eq!(
                state.selector,
                RouteSetGenerationName::new(claim.publication_id, kind).selector_target()
            );
            let evidence = evidence(&claim, InterruptedPhase::Staging, ResolutionKind::Unstarted);
            let digest = terminal_decision_digest(&claim, &evidence, "accept").unwrap();
            assert!(ReviewedTerminalDecision::verify_accept(&claim, evidence, &digest).is_ok());
        }
    }

    fn evidence(
        claim: &RouteSetRecoveryClaim,
        phase: InterruptedPhase,
        kind: ResolutionKind,
    ) -> ResolutionEvidence {
        ResolutionEvidence {
            publication_id: claim.publication_id,
            claim_fence: claim.claim_fence,
            claim_mode: claim.claim_mode,
            reconciliation_operation_id: claim.reconciliation_operation_id,
            reconciliation_operation_attempt: claim.reconciliation_operation_attempt,
            reconciliation_operation_lease_owner: claim
                .reconciliation_operation_lease_owner
                .clone(),
            resolution_kind: kind,
            interrupted_phase: phase,
            observed_selector: None,
            observed_directory_device: None,
            observed_directory_inode: None,
            observed_loaded_identity: None,
        }
    }

    #[test]
    fn tracing_outcome_vocabularies_are_closed() {
        let claim = claim(RecoveryClaimMode::ObserveOnly);
        let claims = [
            ClaimInterruptedPublication::Acquired(claim.clone()),
            ClaimInterruptedPublication::Replay(claim.clone()),
            ClaimInterruptedPublication::Busy {
                claim_fence: claim.claim_fence,
                claim_mode: claim.claim_mode,
            },
            ClaimInterruptedPublication::Terminal {
                claim_fence: claim.claim_fence,
            },
            ClaimInterruptedPublication::Refused(ClaimRefusal::Invalid),
            ClaimInterruptedPublication::Refused(ClaimRefusal::Absent),
            ClaimInterruptedPublication::Refused(ClaimRefusal::ProtocolInactive),
            ClaimInterruptedPublication::Refused(ClaimRefusal::ReconciliationLeaseLost),
            ClaimInterruptedPublication::Refused(ClaimRefusal::WrongPhase),
            ClaimInterruptedPublication::Refused(ClaimRefusal::AuthorityInconsistent),
            ClaimInterruptedPublication::Refused(ClaimRefusal::NotExpired),
        ];
        assert_eq!(
            claims.map(|outcome| outcome.trace_outcome()),
            [
                "acquired",
                "replay",
                "busy",
                "terminal",
                "invalid",
                "absent",
                "protocol_inactive",
                "reconciliation_lease_lost",
                "wrong_phase",
                "authority_inconsistent",
                "not_expired",
            ]
        );
        assert_eq!(
            [
                RenewRecoveryClaimOutcome::Renewed,
                RenewRecoveryClaimOutcome::ClaimLost,
                RenewRecoveryClaimOutcome::Invalid,
            ]
            .map(RenewRecoveryClaimOutcome::trace_outcome),
            ["renewed", "claim_lost", "invalid"]
        );
        assert_eq!(
            [ReadRecoveryState::Claimed, ReadRecoveryState::ClaimLost]
                .map(ReadRecoveryState::trace_outcome),
            ["claimed", "claim_lost"]
        );

        let resolution_evidence = evidence(
            &claim,
            InterruptedPhase::PublicationStarted,
            ResolutionKind::Inconclusive,
        );
        let resolutions = [
            ResolveObservationOutcome::Recorded(resolution_evidence.clone()),
            ResolveObservationOutcome::Replay(resolution_evidence),
            ResolveObservationOutcome::Conflict,
            ResolveObservationOutcome::ClaimLost,
            ResolveObservationOutcome::EvidenceMismatch,
            ResolveObservationOutcome::Invalid,
        ];
        assert_eq!(
            resolutions.map(|outcome| outcome.trace_outcome()),
            [
                "recorded",
                "replay",
                "conflict",
                "claim_lost",
                "evidence_mismatch",
                "invalid",
            ]
        );

        let terminal = RouteSetRecoveryTerminalResult::NotApplied(RouteSetRecoveryNotApplied {
            publication_id: claim.publication_id,
            driver_operation_id: Uuid::new_v4(),
            target_workshop_id: Uuid::new_v4(),
            resolution_kind: ResolutionKind::Prior,
            decision_digest: "a".repeat(64),
        });
        let finishes = [
            FinishRouteSetRecoveryOutcome::Completed(terminal.clone()),
            FinishRouteSetRecoveryOutcome::Replay(terminal),
            FinishRouteSetRecoveryOutcome::Refused(FinishRecoveryRefusal::Invalid),
            FinishRouteSetRecoveryOutcome::Refused(FinishRecoveryRefusal::Absent),
            FinishRouteSetRecoveryOutcome::Refused(FinishRecoveryRefusal::Conflict),
            FinishRouteSetRecoveryOutcome::Refused(FinishRecoveryRefusal::ProtocolInactive),
            FinishRouteSetRecoveryOutcome::Refused(FinishRecoveryRefusal::ObservationMismatch),
            FinishRouteSetRecoveryOutcome::Refused(FinishRecoveryRefusal::ReconciliationLeaseLost),
            FinishRouteSetRecoveryOutcome::Refused(FinishRecoveryRefusal::AuthorityInconsistent),
        ];
        assert_eq!(
            finishes.map(|outcome| outcome.trace_outcome()),
            [
                "completed",
                "replay",
                "invalid",
                "absent",
                "conflict",
                "protocol_inactive",
                "observation_mismatch",
                "reconciliation_lease_lost",
                "authority_inconsistent",
            ]
        );
    }

    #[test]
    fn tracing_records_only_parsed_database_outcomes() {
        let source = include_str!("route_set_recovery_db.rs");
        let production = source.split("#[cfg(test)]\nmod tests").next().unwrap();
        for field in [
            "claim.outcome",
            "state.outcome",
            "resolution.outcome",
            "terminal.outcome",
        ] {
            assert!(
                !production.contains(&format!("record(\"{field}\", row.0")),
                "{field} must never record an unparsed database value"
            );
            assert!(production.contains(&format!("record_parsed_outcome(\"{field}\"")));
        }
        assert!(!production.contains("record(\"claim.outcome\", outcome.as_str())"));
        assert!(production.contains("map_or(\"contract_drift\", outcome)"));
    }

    #[test]
    fn migration_0030_and_0033_signatures_and_privacy_are_exact_and_dormant() {
        let source = include_str!("route_set_recovery_db.rs");
        for signature in [
            "discover_interrupted_route_set_publications($1,$2)",
            "claim_interrupted_route_set_publication($1,$2,$3,$4,$5,$6,$7)",
            "renew_interrupted_route_set_publication_claim($1,$2,$3,$4,$5)",
            "read_interrupted_route_set_publication_state($1,$2,$3,$4)",
            "resolve_interrupted_route_set_publication_observation($1,$2,$3,$4,$5,$6,$7,$8,$9)",
            "finish_route_set_publication_recovery($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
        ] {
            assert!(source.contains(signature));
        }
        assert_eq!(STATE_KEYS.len(), 27);
        assert_eq!(EVIDENCE_KEYS.len(), 12);
        let production = source.split("#[cfg(test)]\nmod tests").next().unwrap();
        for instrument in production.match_indices("#[tracing::instrument") {
            let tail = &production[instrument.0..];
            let block = tail.split("pub(super) async fn").next().unwrap();
            assert!(block.contains("skip_all"));
            assert!(!block.contains("token"));
        }
        let root = include_str!("../docker_driver.rs");
        assert_eq!(root.matches("mod route_set_recovery_db;").count(), 1);
        for active in [
            include_str!("startup.rs"),
            include_str!("release.rs"),
            include_str!("recovery.rs"),
        ] {
            assert!(!active.contains("route_set_recovery_db"));
        }
        let coordinator = include_str!("route_set_recovery.rs");
        assert!(!coordinator.contains("finish_route_set_publication_recovery("));
    }

    #[test]
    fn reviewed_terminal_decision_requires_external_exact_digest_and_refuses_inconclusive() {
        let mut claim = claim(RecoveryClaimMode::WriteCleanup);
        claim.reconciliation_operation_id =
            Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        claim.reconciliation_owner =
            Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap();
        claim.reconciliation_token =
            Uuid::parse_str("33333333-3333-3333-3333-333333333333").unwrap();
        let unstarted = evidence(&claim, InterruptedPhase::Staging, ResolutionKind::Unstarted);
        let digest = terminal_decision_digest(&claim, &unstarted, "accept").unwrap();
        assert_eq!(
            digest,
            "579cb9194f8d9b00c8fb85124fd1de09802a0afe01ffb86575bb9308a354f8a3"
        );
        assert!(
            digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        );
        assert!(
            ReviewedTerminalDecision::verify_accept(&claim, unstarted.clone(), &digest).is_ok()
        );
        assert!(
            ReviewedTerminalDecision::verify_accept(&claim, unstarted.clone(), &"0".repeat(64))
                .is_err()
        );
        let mut changed = unstarted.clone();
        changed.interrupted_phase = InterruptedPhase::Sealed;
        assert_ne!(
            terminal_decision_digest(&claim, &changed, "accept").unwrap(),
            digest
        );
        let inconclusive = evidence(
            &claim,
            InterruptedPhase::Staging,
            ResolutionKind::Inconclusive,
        );
        let inconclusive_digest =
            terminal_decision_digest(&claim, &inconclusive, "accept").unwrap();
        assert!(
            ReviewedTerminalDecision::verify_accept(&claim, inconclusive, &inconclusive_digest)
                .is_err()
        );
        let mut boot_live = evidence(&claim, InterruptedPhase::Sealed, ResolutionKind::Prior);
        boot_live.observed_selector = Some("generations/boot-live".into());
        boot_live.observed_directory_device = Some(21);
        boot_live.observed_directory_inode = Some(22);
        let boot_digest = terminal_decision_digest(&claim, &boot_live, "accept").unwrap();
        assert!(ReviewedTerminalDecision::verify_accept(&claim, boot_live, &boot_digest).is_err());
    }

    #[test]
    fn postgres_jsonb_digest_text_is_canonical_and_length_then_byte_ordered() {
        let value = json!({"longer":1,"b":2,"aa":{"z":null,"c":true}});
        assert_eq!(
            postgres_jsonb_text(&value).unwrap(),
            r#"{"b": 2, "aa": {"c": true, "z": null}, "longer": 1}"#
        );
    }

    #[test]
    fn terminal_not_applied_response_is_exact_bound_and_closed() {
        let claim = claim(RecoveryClaimMode::WriteCleanup);
        let state = parse_state(&claim, state_json(&claim, "staging")).unwrap();
        let evidence = evidence(&claim, InterruptedPhase::Staging, ResolutionKind::Unstarted);
        let digest = terminal_decision_digest(&claim, &evidence, "accept").unwrap();
        let decision = ReviewedTerminalDecision::verify_accept(&claim, evidence, &digest).unwrap();
        let driver = Uuid::new_v4();
        let response = json!({
            "outcome":"not_applied",
            "publication_id":claim.publication_id,
            "driver_operation_id":driver,
            "target_workshop_id":state.target_workshop_id,
            "resolution_claim_fence":claim.claim_fence,
            "resolution_kind":"unstarted",
            "reconciliation_operation_id":claim.reconciliation_operation_id,
            "reconciliation_operation_attempt":claim.reconciliation_operation_attempt,
            "reconciliation_operation_lease_owner":claim.reconciliation_operation_lease_owner,
            "decision_digest":digest,
            "driver_response":Value::Null
        });
        assert!(matches!(
            parse_finish_recovery(
                &claim,
                &state,
                &decision,
                ("completed".into(), Some(response.clone()))
            )
            .unwrap(),
            FinishRouteSetRecoveryOutcome::Completed(RouteSetRecoveryTerminalResult::NotApplied(_))
        ));
        let mut extra = response.clone();
        extra["foreign"] = json!(true);
        assert!(
            parse_finish_recovery(&claim, &state, &decision, ("completed".into(), Some(extra)))
                .is_err()
        );
        let mut wrong = response;
        wrong["resolution_kind"] = json!("candidate");
        assert!(
            parse_finish_recovery(&claim, &state, &decision, ("replay".into(), Some(wrong)))
                .is_err()
        );
        for refusal in [
            "invalid",
            "absent",
            "conflict",
            "protocol_inactive",
            "observation_mismatch",
            "reconciliation_lease_lost",
            "authority_inconsistent",
        ] {
            assert!(matches!(
                parse_finish_recovery(&claim, &state, &decision, (refusal.into(), None)).unwrap(),
                FinishRouteSetRecoveryOutcome::Refused(_)
            ));
        }
        assert!(
            parse_finish_recovery(&claim, &state, &decision, ("blocked".into(), None)).is_err()
        );
    }

    #[test]
    fn recovered_candidate_driver_response_is_validated_against_state() {
        let claim = claim(RecoveryClaimMode::ObserveOnly);
        let mut value = state_json(&claim, "sealed");
        value["interrupted_phase"] = json!("publication_started");
        value["publication_started_at"] = serde_json::to_value(OffsetDateTime::UNIX_EPOCH).unwrap();
        value["prior_selector"] = json!("generations/boot-live");
        value["prior_directory_device"] = json!(21);
        value["prior_directory_inode"] = json!(22);
        let state = parse_state(&claim, value).unwrap();
        let identity = RouteSetGenerationIdentity::new(
            state.publication_id,
            state.publication_kind,
            state.original_global_fence_token,
            state.target_workshop_id,
            state.target_route_fence_token,
            state.route_set_digest.clone().unwrap(),
        )
        .unwrap();
        let mut evidence = evidence(
            &claim,
            InterruptedPhase::PublicationStarted,
            ResolutionKind::Candidate,
        );
        evidence.observed_selector = Some(state.selector.clone());
        evidence.observed_directory_device = Some(31);
        evidence.observed_directory_inode = Some(32);
        evidence.observed_loaded_identity = Some(serde_json::to_value(identity).unwrap());
        let digest = terminal_decision_digest(&claim, &evidence, "accept").unwrap();
        let decision = ReviewedTerminalDecision::verify_accept(&claim, evidence, &digest).unwrap();
        let driver = Uuid::new_v4();
        let driver_response = json!({
            "outcome":"applied","workshop_id":state.target_workshop_id,
            "route_evidence":{
                "driver_operation_id":driver,"workshop_id":state.target_workshop_id,
                "route_generation":state.target_generation,
                "projection_digest":state.target_projection_digest,
                "disposition":"present","rendered_digest":format!("sha256:{}","c".repeat(64)),
                "route_fence_token":state.target_route_fence_token
            },
            "route_set_evidence":{
                "protocol_version":1,"publication_id":state.publication_id,
                "publication_kind":"projection","selector":state.selector,
                "route_set_digest":state.route_set_digest,"snapshot_count":2,
                "present_count":1,"global_fence_token":state.original_global_fence_token,
                "directory_device":31,"directory_inode":32
            }
        });
        let response = json!({
            "outcome":"applied_recovered","publication_id":claim.publication_id,
            "driver_operation_id":driver,"target_workshop_id":state.target_workshop_id,
            "resolution_claim_fence":claim.claim_fence,"resolution_kind":"candidate",
            "reconciliation_operation_id":claim.reconciliation_operation_id,
            "reconciliation_operation_attempt":claim.reconciliation_operation_attempt,
            "reconciliation_operation_lease_owner":claim.reconciliation_operation_lease_owner,
            "decision_digest":digest,"driver_response":driver_response
        });
        assert!(matches!(
            parse_finish_recovery(
                &claim,
                &state,
                &decision,
                ("completed".into(), Some(response.clone()))
            )
            .unwrap(),
            FinishRouteSetRecoveryOutcome::Completed(RouteSetRecoveryTerminalResult::Applied(_))
        ));
        let mut drift = response;
        drift["driver_response"]["route_set_evidence"]["directory_inode"] = json!(99);
        assert!(
            parse_finish_recovery(&claim, &state, &decision, ("completed".into(), Some(drift)))
                .is_err()
        );
    }

    #[test]
    fn recovery_kind_terminal_candidate_and_not_applied_are_exactly_bound() {
        for kind in [
            RouteSetPublicationKind::RecoveryMaintenance,
            RouteSetPublicationKind::RecoveryRestore,
        ] {
            let observe_claim = claim(RecoveryClaimMode::ObserveOnly);
            let mut value = state_json_kind(&observe_claim, "sealed", kind);
            value["interrupted_phase"] = json!("publication_started");
            value["publication_started_at"] =
                serde_json::to_value(OffsetDateTime::UNIX_EPOCH).unwrap();
            value["prior_selector"] = json!("generations/boot-live");
            value["prior_directory_device"] = json!(21);
            value["prior_directory_inode"] = json!(22);
            let state = parse_state(&observe_claim, value).unwrap();
            let identity = RouteSetGenerationIdentity::new(
                state.publication_id,
                state.publication_kind,
                state.original_global_fence_token,
                state.target_workshop_id,
                state.target_route_fence_token,
                state.route_set_digest.clone().unwrap(),
            )
            .unwrap();
            let mut observed = evidence(
                &observe_claim,
                InterruptedPhase::PublicationStarted,
                ResolutionKind::Candidate,
            );
            observed.observed_selector = Some(state.selector.clone());
            observed.observed_directory_device = Some(31);
            observed.observed_directory_inode = Some(32);
            observed.observed_loaded_identity = Some(serde_json::to_value(identity).unwrap());
            let digest = terminal_decision_digest(&observe_claim, &observed, "accept").unwrap();
            let decision =
                ReviewedTerminalDecision::verify_accept(&observe_claim, observed, &digest).unwrap();
            let effect = state.recovery_effect_run_id.unwrap();
            let maintenance = kind == RouteSetPublicationKind::RecoveryMaintenance;
            let mut effect_response = json!({
                "outcome":if maintenance { "maintenance" } else { "restored" },
                "effect_run_id":effect,
                "route_fence_token":state.target_route_fence_token,
                "route_evidence":{
                    "effect_run_id":effect,"workshop_id":state.target_workshop_id,
                    "generation":state.target_generation,
                    "projection_digest":state.target_projection_digest,
                    "disposition":"present","rendered_digest":format!("sha256:{}","c".repeat(64)),
                    "route_fence_token":state.target_route_fence_token,
                    "mode":if maintenance { "maintenance" } else { "restored" }
                },
                "route_set_evidence":{
                    "protocol_version":1,"publication_id":state.publication_id,
                    "publication_kind":kind,"selector":state.selector,
                    "route_set_digest":state.route_set_digest,"snapshot_count":2,
                    "present_count":1,"global_fence_token":state.original_global_fence_token,
                    "directory_device":31,"directory_inode":32
                }
            });
            if !maintenance {
                effect_response
                    .as_object_mut()
                    .unwrap()
                    .remove("route_fence_token");
            }
            let terminal = json!({
                "outcome":if maintenance { "maintenance_recovered" } else { "restored_recovered" },
                "publication_id":state.publication_id,"effect_run_id":effect,
                "publication_kind":kind,"target_workshop_id":state.target_workshop_id,
                "resolution_claim_fence":observe_claim.claim_fence,"resolution_kind":"candidate",
                "reconciliation_operation_id":observe_claim.reconciliation_operation_id,
                "reconciliation_operation_attempt":observe_claim.reconciliation_operation_attempt,
                "reconciliation_operation_lease_owner":observe_claim.reconciliation_operation_lease_owner,
                "decision_digest":digest,"effect_response":effect_response
            });
            assert!(matches!(
                parse_finish_recovery(
                    &observe_claim,
                    &state,
                    &decision,
                    ("completed".into(), Some(terminal.clone()))
                )
                .unwrap(),
                FinishRouteSetRecoveryOutcome::Completed(
                    RouteSetRecoveryTerminalResult::RecoveryApplied(_)
                )
            ));
            let mut drift = terminal;
            drift["effect_run_id"] = json!(Uuid::new_v4());
            assert!(
                parse_finish_recovery(
                    &observe_claim,
                    &state,
                    &decision,
                    ("replay".into(), Some(drift))
                )
                .is_err()
            );

            let cleanup_claim = claim(RecoveryClaimMode::WriteCleanup);
            let cleanup_state = parse_state(
                &cleanup_claim,
                state_json_kind(&cleanup_claim, "staging", kind),
            )
            .unwrap();
            let cleanup_evidence = evidence(
                &cleanup_claim,
                InterruptedPhase::Staging,
                ResolutionKind::Unstarted,
            );
            let cleanup_digest =
                terminal_decision_digest(&cleanup_claim, &cleanup_evidence, "accept").unwrap();
            let cleanup_decision = ReviewedTerminalDecision::verify_accept(
                &cleanup_claim,
                cleanup_evidence,
                &cleanup_digest,
            )
            .unwrap();
            let not_applied = json!({
                "outcome":"not_applied","publication_id":cleanup_state.publication_id,
                "effect_run_id":cleanup_state.recovery_effect_run_id.unwrap(),
                "publication_kind":kind,"target_workshop_id":cleanup_state.target_workshop_id,
                "resolution_claim_fence":cleanup_claim.claim_fence,"resolution_kind":"unstarted",
                "reconciliation_operation_id":cleanup_claim.reconciliation_operation_id,
                "reconciliation_operation_attempt":cleanup_claim.reconciliation_operation_attempt,
                "reconciliation_operation_lease_owner":cleanup_claim.reconciliation_operation_lease_owner,
                "decision_digest":cleanup_digest,"effect_response":Value::Null
            });
            assert!(matches!(
                parse_finish_recovery(
                    &cleanup_claim,
                    &cleanup_state,
                    &cleanup_decision,
                    ("completed".into(), Some(not_applied))
                )
                .unwrap(),
                FinishRouteSetRecoveryOutcome::Completed(
                    RouteSetRecoveryTerminalResult::RecoveryNotApplied(_)
                )
            ));
        }
    }
    #[test]
    fn exact_key_validation_rejects_missing_and_extra() {
        let mut value = serde_json::Map::new();
        for key in STATE_KEYS {
            value.insert(key.to_owned(), Value::Null);
        }
        let exact = Value::Object(value.clone());
        assert!(exact_keys(&exact, &STATE_KEYS, "state").is_ok());
        value.remove("selector");
        assert!(exact_keys(&Value::Object(value.clone()), &STATE_KEYS, "state").is_err());
        value.insert("selector".into(), Value::Null);
        value.insert("foreign".into(), Value::Null);
        assert!(exact_keys(&Value::Object(value), &STATE_KEYS, "state").is_err());
    }
    #[test]
    fn claim_outcomes_are_closed_and_shape_checked() {
        let request = RouteSetRecoveryClaimRequest {
            publication_id: Uuid::new_v4(),
            reconciliation_operation: ControlOperationLease {
                id: Uuid::new_v4(),
                attempt: 2,
                owner: "worker".into(),
            },
            reconciliation_owner: Uuid::new_v4(),
            reconciliation_token: Uuid::new_v4(),
            ttl_seconds: 60,
        };
        assert!(matches!(
            parse_claim(
                &request,
                ("acquired".into(), Some(1), Some("observe_only".into()))
            )
            .unwrap(),
            ClaimInterruptedPublication::Acquired(_)
        ));
        assert!(parse_claim(&request, ("acquired".into(), None, None)).is_err());
        assert!(parse_claim(&request, ("unknown".into(), None, None)).is_err());
        assert!(matches!(
            parse_claim(
                &request,
                ("busy".into(), Some(3), Some("write_cleanup".into()))
            )
            .unwrap(),
            ClaimInterruptedPublication::Busy {
                claim_fence: 3,
                claim_mode: RecoveryClaimMode::WriteCleanup
            }
        ));
        assert!(matches!(
            parse_claim(&request, ("terminal".into(), Some(0), None)).unwrap(),
            ClaimInterruptedPublication::Terminal { claim_fence: 0 }
        ));
    }

    #[test]
    fn staging_unstarted_and_boot_live_prior_shapes_are_accepted() {
        let staging_claim = claim(RecoveryClaimMode::WriteCleanup);
        let staging = parse_state(&staging_claim, state_json(&staging_claim, "staging")).unwrap();
        assert!(staging.prior.is_none());
        assert!(staging.candidate.is_none());
        assert_eq!(staging.record_count, 0);

        let sealed_claim = claim(RecoveryClaimMode::ObserveOnly);
        let mut sealed = state_json(&sealed_claim, "sealed");
        sealed["prior_selector"] = json!("generations/boot-live");
        sealed["prior_directory_device"] = json!(21);
        sealed["prior_directory_inode"] = json!(22);
        let parsed = parse_state(&sealed_claim, sealed).unwrap();
        assert_eq!(parsed.prior.unwrap().target(), "generations/boot-live");
        assert!(parsed.prior_loaded_identity.is_none());
    }

    #[test]
    fn cross_phase_and_selector_drift_are_rejected() {
        let claim = claim(RecoveryClaimMode::ObserveOnly);
        let mut sealed = state_json(&claim, "sealed");
        sealed["prior_selector"] = json!("generations/boot-live");
        sealed["prior_directory_device"] = json!(21);
        sealed["prior_directory_inode"] = json!(22);
        let mut started = sealed.clone();
        started["interrupted_phase"] = json!("publication_started");
        assert!(parse_state(&claim, started).is_err());
        sealed["selector"] = json!("generations/route-foreign-projection");
        assert!(parse_state(&claim, sealed).is_err());
    }

    #[test]
    fn resolution_refusals_and_malformed_payloads_are_closed() {
        let claim = claim(RecoveryClaimMode::WriteCleanup);
        let state = parse_state(&claim, state_json(&claim, "staging")).unwrap();
        let observation = ResolutionObservation {
            kind: ResolutionKind::Inconclusive,
            selector: None,
            directory_device: None,
            directory_inode: None,
            loaded_identity: None,
        };
        for (outcome, expected) in [
            ("conflict", ResolveObservationOutcome::Conflict),
            ("claim_lost", ResolveObservationOutcome::ClaimLost),
            (
                "evidence_mismatch",
                ResolveObservationOutcome::EvidenceMismatch,
            ),
            ("invalid", ResolveObservationOutcome::Invalid),
        ] {
            assert_eq!(
                parse_resolution(&claim, &state, &observation, (outcome.into(), None)).unwrap(),
                expected
            );
        }
        assert!(parse_resolution(&claim, &state, &observation, ("recorded".into(), None)).is_err());
        assert!(parse_resolution(&claim, &state, &observation, ("unknown".into(), None)).is_err());
    }

    #[test]
    fn discovery_pagination_order_selector_and_phase_shape_are_strict() {
        let first = Uuid::parse_str("10000000-0000-0000-0000-000000000001").unwrap();
        let second = Uuid::parse_str("20000000-0000-0000-0000-000000000001").unwrap();
        let row = |publication_id, phase: &str, digest: Option<String>| {
            (
                publication_id,
                Uuid::new_v4(),
                "projection".to_owned(),
                phase.to_owned(),
                "observe_only".to_owned(),
                0,
                true,
                RouteSetGenerationName::new(publication_id, RouteSetPublicationKind::Projection)
                    .selector_target(),
                digest,
                OffsetDateTime::UNIX_EPOCH,
            )
        };
        assert_eq!(
            validate_discovery(
                None,
                vec![
                    row(first, "staging", None),
                    row(second, "sealed", Some(format!("sha256:{}", "a".repeat(64))),),
                ],
            )
            .unwrap()
            .len(),
            2
        );
        assert!(
            validate_discovery(
                None,
                vec![row(second, "staging", None), row(first, "staging", None)],
            )
            .is_err()
        );
        assert!(validate_discovery(None, vec![row(first, "sealed", None)]).is_err());
        let mut foreign = row(first, "staging", None);
        foreign.7 = "generations/foreign".into();
        assert!(validate_discovery(None, vec![foreign]).is_err());
    }
}
