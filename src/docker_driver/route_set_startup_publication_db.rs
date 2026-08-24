//! Typed, dormant persistence boundary for fleet-scoped startup route-set publication.
#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use super::DriverError;
use super::gateway::RouteSetPublicationKind;
use super::route_generation_fs::validate_digest;
use super::route_set_generation_fs::{MAX_ROUTES, RouteSetGenerationName};
use super::startup_publication;

const MIN_TTL_SECONDS: i32 = 60;
const MAX_TTL_SECONDS: i32 = 1200;
const MAX_RECOVERY_DISCOVERY: usize = 100;

#[derive(Clone)]
pub(super) struct StartupRouteSetAdmissionRequest {
    pub boot_id: Uuid,
    pub idempotency_key: String,
    pub request_digest: String,
    pub instance_owner: Uuid,
    pub execution_token: Uuid,
    pub global_lease_token: Uuid,
    pub route_lease_token: Uuid,
    pub ttl_seconds: i32,
}

impl StartupRouteSetAdmissionRequest {
    fn validate(&self) -> Result<(), DriverError> {
        if self.boot_id.is_nil()
            || self.idempotency_key.trim().is_empty()
            || self.idempotency_key.len() > 180
            || !valid_bare_sha256(&self.request_digest)
            || self.instance_owner.is_nil()
            || self.execution_token.is_nil()
            || self.global_lease_token.is_nil()
            || self.route_lease_token.is_nil()
            || !(MIN_TTL_SECONDS..=MAX_TTL_SECONDS).contains(&self.ttl_seconds)
        {
            return Err(invalid("startup route-set request is invalid"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct StartupRouteSetResponse {
    pub effect_run_id: Uuid,
    pub global_fence_token: i64,
    pub workshop_count: usize,
    pub projection_set_digest: String,
    pub gateway_reload_digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum StartupFrozenRuntime {
    Absent,
    Active {
        slot: String,
        release_id: String,
        subject_digest: String,
        deployment_ref: String,
        config_digest: String,
        slot_version: i64,
    },
}

#[derive(Clone)]
pub(super) struct StartupRouteSetLease {
    pub publication_id: Uuid,
    pub effect_run_id: Uuid,
    pub boot_id: Uuid,
    pub global_fence_token: i64,
    pub snapshot_count: usize,
    pub selector: String,
    pub runtime: StartupFrozenRuntime,
    pub fleet_release_unresolved: bool,
    pub instance_owner: Uuid,
    pub execution_token: Uuid,
    pub global_lease_token: Uuid,
    pub route_lease_token: Uuid,
    pub ttl_seconds: i32,
}

impl StartupRouteSetLease {
    pub(super) fn legacy_runtime_lease(&self) -> startup_publication::StartupPublicationLease {
        startup_publication::StartupPublicationLease {
            effect_run_id: self.effect_run_id,
            instance_owner: self.instance_owner,
            execution_token: self.execution_token,
            global_lease_token: self.global_lease_token,
            route_lease_token: self.route_lease_token,
            global_fence_token: self.global_fence_token,
            reserved_count: self.snapshot_count,
            staging_selector: self.selector.clone(),
            active_runtime: match &self.runtime {
                StartupFrozenRuntime::Absent => None,
                StartupFrozenRuntime::Active {
                    slot,
                    release_id,
                    subject_digest,
                    deployment_ref,
                    config_digest,
                    slot_version,
                } => Some(startup_publication::ActiveRuntimeIdentity {
                    slot: slot.clone(),
                    release_id: release_id.clone(),
                    subject_digest: subject_digest.clone(),
                    deployment_ref: deployment_ref.clone(),
                    config_digest: config_digest.clone(),
                    slot_version: *slot_version,
                }),
            },
            fleet_release_unresolved: self.fleet_release_unresolved,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum StartupRouteSetRefusal {
    Invalid,
    ProtocolInactive,
    FleetTooLarge,
    Busy,
    Conflict,
    FleetBusy,
    FleetQuarantined,
    RouteBusy,
    RouteQuarantined,
    InitializationRequired,
    RuntimeAmbiguous,
    RuntimeIdentityMissing,
    AuthorityLost,
}

pub(super) enum StartupRouteSetAdmission {
    Acquired(Box<StartupRouteSetLease>),
    Replay(StartupRouteSetResponse),
    NotApplied(StartupRouteSetNotApplied),
    Refused(StartupRouteSetRefusal),
}

pub(super) enum ReadStartupRouteSetAdmission {
    Absent,
    Replay(StartupRouteSetResponse),
    NotApplied(StartupRouteSetNotApplied),
    Refused(StartupRouteSetRefusal),
}

#[derive(Clone, Debug, sqlx::FromRow)]
pub(super) struct StartupSnapshotRow {
    pub workshop_id: Uuid,
    pub generation: i64,
    pub projection_digest: String,
    pub disposition: String,
    pub canonical_projection: Value,
    pub baseline_applied_generation: Option<i64>,
    pub baseline_applied_digest: Option<String>,
    pub baseline_applied_disposition: Option<String>,
    pub baseline_applied_rendered_digest: Option<String>,
    pub baseline_applied_driver_operation_id: Option<Uuid>,
    pub baseline_applied_effect_run_id: Option<Uuid>,
    pub baseline_applied_fence_token: Option<i64>,
    pub route_fence_token: i64,
    pub database_id: Option<Uuid>,
    pub database_ref: Option<String>,
    pub public_hostname: Option<String>,
    pub action: String,
    pub paperless_mode: String,
    pub paperless_hostname: Option<String>,
    pub paperless_service_id: Option<Uuid>,
    pub paperless_service_health: Option<String>,
    pub paperless_service_base_url: Option<String>,
    pub paperless_service_desired_epoch: Option<i32>,
    pub paperless_service_applied_epoch: Option<i32>,
    pub paperless_runtime_spec: Option<Value>,
    pub unresolved_operation: bool,
}

impl StartupSnapshotRow {
    pub(super) fn legacy_route(
        &self,
    ) -> Result<startup_publication::StagedStartupRoute, DriverError> {
        Ok(startup_publication::StagedStartupRoute {
            workshop_id: self.workshop_id,
            database_id: self.database_id,
            database_ref: self.database_ref.clone(),
            public_hostname: self.public_hostname.clone(),
            generation: self.generation,
            projection_digest: self.projection_digest.clone(),
            disposition: match self.disposition.as_str() {
                "present" => startup_publication::RouteDisposition::Present,
                "absent" => startup_publication::RouteDisposition::Absent,
                _ => return Err(invalid("startup disposition is invalid")),
            },
            action: match self.action.as_str() {
                "render" => startup_publication::RouteAction::Render,
                "remove-absent" => startup_publication::RouteAction::RemoveAbsent,
                _ => return Err(invalid("startup action is invalid")),
            },
            paperless_mode: match self.paperless_mode.as_str() {
                "absent" => startup_publication::PaperlessRouteMode::Absent,
                "read_only" => startup_publication::PaperlessRouteMode::ReadOnly,
                "read_write" => startup_publication::PaperlessRouteMode::ReadWrite,
                _ => return Err(invalid("startup Paperless mode is invalid")),
            },
            paperless_hostname: self.paperless_hostname.clone(),
            paperless_service_id: self.paperless_service_id,
            paperless_service_health: self.paperless_service_health.clone(),
            paperless_service_base_url: self.paperless_service_base_url.clone(),
            paperless_service_desired_epoch: self.paperless_service_desired_epoch,
            paperless_service_applied_epoch: self.paperless_service_applied_epoch,
            paperless_runtime_spec: self.paperless_runtime_spec.clone(),
            unresolved_operation: self.unresolved_operation,
            route_fence_token: self.route_fence_token,
            projection: self.canonical_projection.clone(),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum StartupTransitionOutcome {
    Recorded,
    Sealed,
    Started,
    Observed,
    Replay,
    AuthorityLost,
    Conflict,
    Invalid,
    WrongPhase,
    OutOfOrder,
    SnapshotDrift,
    RuntimeDrift,
    RuntimeMismatch,
    RenderInvariantMismatch,
    ObservationMismatch,
}

pub(super) struct StartupRecordEntry<'a> {
    pub workshop_id: Uuid,
    pub generation: i64,
    pub projection_digest: &'a str,
    pub disposition: &'a str,
    pub baseline_applied_rendered_digest: Option<&'a str>,
    pub route_fence_token: i64,
    pub runtime_outcome: &'a str,
    pub runtime_evidence: &'a Value,
    pub rendered_digest: &'a str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum FinishStartupRouteSetOutcome {
    Applied(StartupRouteSetResponse),
    Replay(StartupRouteSetResponse),
    AuthorityLost,
    SnapshotDrift,
    WrongPhase,
    NotFound,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum ReadStartupRouteSetResult {
    Absent,
    Replay(StartupRouteSetResponse),
    Busy,
    FleetQuarantined,
    AppliedRecovered(StartupRouteSetResponse),
    NotApplied(StartupRouteSetNotApplied),
    Conflict,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct StartupRouteSetNotApplied {
    pub outcome: String,
    pub publication_id: Uuid,
    pub effect_run_id: Uuid,
    pub resolution_kind: String,
    pub decision_digest: String,
}

#[derive(Clone)]
pub(super) struct StartupRecoveryClaim {
    pub publication_id: Uuid,
    pub owner: Uuid,
    pub token: Uuid,
    pub claim_fence: i64,
    pub claim_mode: String,
}

pub(super) enum ClaimStartupRecoveryOutcome {
    Acquired(StartupRecoveryClaim),
    Replay(StartupRecoveryClaim),
    Refused,
    Terminal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum StartupRecoveryPhase {
    Staging,
    Sealed,
    PublicationStarted,
    Observed,
}

impl StartupRecoveryPhase {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "staging" => Some(Self::Staging),
            "sealed" => Some(Self::Sealed),
            "publication_started" => Some(Self::PublicationStarted),
            "observed" => Some(Self::Observed),
            _ => None,
        }
    }

    const fn requires_digest(self) -> bool {
        !matches!(self, Self::Staging)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum StartupRecoveryClaimMode {
    WriteCleanup,
    ObserveOnly,
}

impl StartupRecoveryClaimMode {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "write_cleanup" => Some(Self::WriteCleanup),
            "observe_only" => Some(Self::ObserveOnly),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct InterruptedStartupPublication {
    pub publication_id: Uuid,
    pub effect_run_id: Uuid,
    pub interrupted_phase: StartupRecoveryPhase,
    pub claim_mode: StartupRecoveryClaimMode,
    pub selector: String,
    pub route_set_digest: Option<String>,
    pub snapshot_count: usize,
    pub updated_at: OffsetDateTime,
}

type StartupDiscoveryRow = (
    Uuid,
    Uuid,
    String,
    String,
    String,
    Option<String>,
    i32,
    OffsetDateTime,
);

#[tracing::instrument(
    name = "deployment_driver.route_set_startup_recovery.discover_dormant",
    skip_all,
    fields(page.limit=limit, page.returned=tracing::field::Empty)
)]
pub(super) async fn discover_interrupted_startup_publications(
    ledger: &PgPool,
    after: Option<Uuid>,
    limit: usize,
) -> Result<Vec<InterruptedStartupPublication>, DriverError> {
    if after.is_some_and(|id| id.is_nil()) || !(1..=MAX_RECOVERY_DISCOVERY).contains(&limit) {
        return Err(invalid("startup recovery discovery request is invalid"));
    }
    let rows: Vec<StartupDiscoveryRow> = sqlx::query_as(
        "select publication_id,effect_run_id,interrupted_phase,claim_mode,selector,
                route_set_digest,snapshot_count,updated_at
           from control.discover_interrupted_route_set_startup_publications($1,$2)",
    )
    .bind(after)
    .bind(i32::try_from(limit).map_err(DriverError::internal)?)
    .fetch_all(ledger)
    .await
    .map_err(DriverError::internal)?;
    let rows = validate_startup_discovery(after, rows)?;
    tracing::Span::current().record("page.returned", rows.len());
    Ok(rows)
}

fn validate_startup_discovery(
    after: Option<Uuid>,
    rows: Vec<StartupDiscoveryRow>,
) -> Result<Vec<InterruptedStartupPublication>, DriverError> {
    if rows.len() > MAX_RECOVERY_DISCOVERY {
        return Err(invalid("startup recovery discovery page exceeds its bound"));
    }
    let mut previous = after;
    rows.into_iter()
        .map(
            |(
                publication_id,
                effect_run_id,
                phase,
                mode,
                selector,
                route_set_digest,
                snapshot_count,
                updated_at,
            )| {
                let interrupted_phase = StartupRecoveryPhase::parse(&phase)
                    .ok_or_else(|| invalid("startup recovery discovery phase is invalid"))?;
                let claim_mode = StartupRecoveryClaimMode::parse(&mode)
                    .ok_or_else(|| invalid("startup recovery discovery mode is invalid"))?;
                let digest_valid = match (interrupted_phase.requires_digest(), &route_set_digest) {
                    (false, None) => true,
                    (true, Some(digest)) => validate_digest(digest, "startup digest").is_ok(),
                    _ => false,
                };
                if publication_id.is_nil()
                    || effect_run_id.is_nil()
                    || previous.is_some_and(|prior| prior >= publication_id)
                    || !(0..=i32::try_from(MAX_ROUTES).unwrap_or(i32::MAX))
                        .contains(&snapshot_count)
                    || selector
                        != RouteSetGenerationName::new(
                            publication_id,
                            RouteSetPublicationKind::Startup,
                        )
                        .selector_target()
                    || (claim_mode == StartupRecoveryClaimMode::WriteCleanup
                        && !matches!(
                            interrupted_phase,
                            StartupRecoveryPhase::Staging | StartupRecoveryPhase::Sealed
                        ))
                    || !digest_valid
                {
                    return Err(invalid("startup recovery discovery row is malformed"));
                }
                previous = Some(publication_id);
                Ok(InterruptedStartupPublication {
                    publication_id,
                    effect_run_id,
                    interrupted_phase,
                    claim_mode,
                    selector,
                    route_set_digest,
                    snapshot_count: usize::try_from(snapshot_count)
                        .map_err(DriverError::internal)?,
                    updated_at,
                })
            },
        )
        .collect()
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StartupRecoveryState {
    pub protocol_version: u8,
    pub publication_id: Uuid,
    pub publication_kind: RouteSetPublicationKind,
    pub startup_effect_run_id: Uuid,
    pub interrupted_phase: String,
    pub claim_mode: String,
    pub claim_fence: i64,
    pub selector: String,
    pub snapshot_count: usize,
    pub route_set_digest: Option<String>,
    pub prior_selector: Option<String>,
    pub prior_directory_device: Option<i64>,
    pub prior_directory_inode: Option<i64>,
    pub prior_loaded_identity: Option<Value>,
    pub candidate_directory_device: Option<i64>,
    pub candidate_directory_inode: Option<i64>,
    pub observed_selector: Option<String>,
    pub observed_loaded_identity: Option<Value>,
}

#[tracing::instrument(
    name = "deployment_driver.route_set_startup_recovery.claim_dormant",
    skip_all,
    fields(publication.id=%publication_id, recovery.outcome=tracing::field::Empty)
)]
pub(super) async fn claim_startup_recovery(
    ledger: &PgPool,
    publication_id: Uuid,
    owner: Uuid,
    token: Uuid,
    ttl_seconds: i32,
) -> Result<ClaimStartupRecoveryOutcome, DriverError> {
    let (outcome, fence, mode): (String, Option<i64>, Option<String>) = sqlx::query_as(
        "select outcome,claim_fence,claim_mode
           from control.claim_interrupted_route_set_startup_publication($1,$2,$3,$4)",
    )
    .bind(publication_id)
    .bind(owner)
    .bind(token)
    .bind(ttl_seconds)
    .fetch_one(ledger)
    .await
    .map_err(DriverError::internal)?;
    tracing::Span::current().record("recovery.outcome", outcome.as_str());
    match outcome.as_str() {
        "acquired" | "replay" => {
            let claim = StartupRecoveryClaim {
                publication_id,
                owner,
                token,
                claim_fence: fence
                    .filter(|value| *value > 0)
                    .ok_or_else(|| invalid("startup recovery fence is invalid"))?,
                claim_mode: mode
                    .filter(|value| matches!(value.as_str(), "write_cleanup" | "observe_only"))
                    .ok_or_else(|| invalid("startup recovery mode is invalid"))?,
            };
            Ok(if outcome == "acquired" {
                ClaimStartupRecoveryOutcome::Acquired(claim)
            } else {
                ClaimStartupRecoveryOutcome::Replay(claim)
            })
        }
        "terminal" if fence.is_none() && mode.is_none() => {
            Ok(ClaimStartupRecoveryOutcome::Terminal)
        }
        "invalid" | "not_found" | "not_expired" | "authority_inconsistent" | "busy" => {
            Ok(ClaimStartupRecoveryOutcome::Refused)
        }
        _ => Err(invalid("startup recovery claim row is malformed")),
    }
}

pub(super) async fn read_startup_recovery_state(
    ledger: &PgPool,
    claim: &StartupRecoveryClaim,
) -> Result<Option<StartupRecoveryState>, DriverError> {
    let (outcome, value): (String, Option<Value>) = sqlx::query_as(
        "select outcome,state from control.read_interrupted_route_set_startup_publication_state($1,$2,$3,$4)",
    ).bind(claim.publication_id).bind(claim.owner).bind(claim.token).bind(claim.claim_fence)
      .fetch_one(ledger).await.map_err(DriverError::internal)?;
    if outcome != "claimed" {
        return Ok(None);
    }
    let state: StartupRecoveryState =
        serde_json::from_value(value.ok_or_else(|| invalid("startup recovery state is absent"))?)
            .map_err(|_| invalid("startup recovery state is malformed"))?;
    if state.protocol_version != 1
        || state.publication_id != claim.publication_id
        || state.publication_kind != RouteSetPublicationKind::Startup
        || state.startup_effect_run_id.is_nil()
        || state.claim_fence != claim.claim_fence
        || state.claim_mode != claim.claim_mode
        || state.snapshot_count > MAX_ROUTES
        || !matches!(
            state.interrupted_phase.as_str(),
            "staging" | "sealed" | "publication_started" | "observed"
        )
    {
        return Err(invalid("startup recovery state identity is invalid"));
    }
    Ok(Some(state))
}

#[tracing::instrument(
    name = "deployment_driver.route_set_startup_recovery.resolve_dormant",
    skip_all,
    fields(publication.id=%claim.publication_id, resolution.kind=resolution_kind,
        recovery.outcome=tracing::field::Empty)
)]
pub(super) async fn resolve_startup_recovery_observation(
    ledger: &PgPool,
    claim: &StartupRecoveryClaim,
    resolution_kind: &str,
    evidence: &Value,
) -> Result<StartupTransitionOutcome, DriverError> {
    let outcome: String = sqlx::query_scalar(
        "select control.resolve_interrupted_route_set_startup_publication_observation($1,$2,$3,$4,$5,$6)",
    ).bind(claim.publication_id).bind(claim.owner).bind(claim.token).bind(claim.claim_fence)
      .bind(resolution_kind).bind(evidence).fetch_one(ledger).await.map_err(DriverError::internal)?;
    tracing::Span::current().record("recovery.outcome", outcome.as_str());
    parse_transition(&outcome)
}

#[tracing::instrument(
    name = "deployment_driver.route_set_startup_recovery.finish_dormant",
    skip_all,
    fields(publication.id=%claim.publication_id, effect.id=%state.startup_effect_run_id,
        resolution.kind=resolution_kind, recovery.outcome=tracing::field::Empty)
)]
pub(super) async fn finish_startup_recovery(
    ledger: &PgPool,
    claim: &StartupRecoveryClaim,
    state: &StartupRecoveryState,
    resolution_kind: &str,
) -> Result<ReadStartupRouteSetResult, DriverError> {
    let decision = if resolution_kind == "candidate" {
        "finish_candidate"
    } else {
        "cancel_unstarted"
    };
    let digest: String = sqlx::query_scalar(
        "select control.route_set_startup_terminal_decision_digest($1,$2,$3,$4,$5)",
    )
    .bind(claim.publication_id)
    .bind(claim.claim_fence)
    .bind(claim.owner)
    .bind(resolution_kind)
    .bind(decision)
    .fetch_one(ledger)
    .await
    .map_err(DriverError::internal)?;
    let (outcome, response): (String, Option<Value>) = sqlx::query_as(
        "select outcome,response from control.finish_route_set_startup_publication_recovery($1,$2,$3,$4,$5,$6,$7)",
    ).bind(claim.publication_id).bind(claim.claim_fence).bind(claim.owner).bind(claim.token)
      .bind(resolution_kind).bind(decision).bind(&digest).fetch_one(ledger).await.map_err(DriverError::internal)?;
    tracing::Span::current().record("recovery.outcome", outcome.as_str());
    match (outcome.as_str(), response) {
        ("applied_recovered" | "replay", Some(value)) if resolution_kind == "candidate" => {
            let object = value
                .as_object()
                .ok_or_else(|| invalid("startup recovered response is malformed"))?;
            let response: StartupRouteSetResponse =
                serde_json::from_value(Value::Object(object.clone()))
                    .map_err(|_| invalid("startup recovered response is malformed"))?;
            if response.effect_run_id != state.startup_effect_run_id
                || response.workshop_count != state.snapshot_count
                || response.projection_set_digest != response.gateway_reload_digest
                || Some(response.projection_set_digest.as_str())
                    != state.route_set_digest.as_deref()
                || response.global_fence_token <= 0
            {
                return Err(invalid("startup recovered response identity differs"));
            }
            Ok(ReadStartupRouteSetResult::AppliedRecovered(response))
        }
        ("not_applied" | "replay", Some(value)) => {
            let result: StartupRouteSetNotApplied = serde_json::from_value(value)
                .map_err(|_| invalid("startup recovery not-applied response is malformed"))?;
            if result.outcome != "not_applied"
                || result.publication_id != state.publication_id
                || result.effect_run_id != state.startup_effect_run_id
                || result.resolution_kind != resolution_kind
                || !valid_sha256(&result.decision_digest)
            {
                return Err(invalid("startup recovery not-applied identity differs"));
            }
            Ok(ReadStartupRouteSetResult::NotApplied(result))
        }
        _ => Err(invalid("startup recovery finish outcome is not terminal")),
    }
}

type AdmissionRow = (
    String,
    Option<Uuid>,
    Option<Uuid>,
    Option<i64>,
    Option<i32>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<i64>,
    Option<bool>,
    Option<Value>,
);

#[tracing::instrument(
    name = "deployment_driver.route_set_startup.read_admission_dormant",
    skip_all,
    fields(startup.boot_id = %request.boot_id, result.outcome = tracing::field::Empty)
)]
pub(super) async fn read_startup_admission(
    ledger: &PgPool,
    request: &StartupRouteSetAdmissionRequest,
) -> Result<ReadStartupRouteSetAdmission, DriverError> {
    request.validate()?;
    let row: AdmissionRow = sqlx::query_as(
        "select outcome,publication_id,effect_run_id,global_fence_token,snapshot_count,selector,
                active_runtime_slot,active_runtime_release_id,active_runtime_subject_digest,
                active_runtime_deployment_ref,active_runtime_config_digest,active_runtime_slot_version,
                fleet_release_unresolved,stored_response
           from control.read_route_set_startup_admission($1,$2,$3)",
    )
        .bind(request.boot_id)
        .bind(&request.idempotency_key)
        .bind(&request.request_digest)
        .fetch_one(ledger)
        .await
        .map_err(DriverError::internal)?;
    tracing::Span::current().record("result.outcome", row.0.as_str());
    if row.0 == "absent" {
        if admission_payload_is_empty(&row) {
            return Ok(ReadStartupRouteSetAdmission::Absent);
        }
        return Err(invalid("absent startup admission row is malformed"));
    }
    match parse_admission(request, row, false)? {
        StartupRouteSetAdmission::Replay(response) => {
            Ok(ReadStartupRouteSetAdmission::Replay(response))
        }
        StartupRouteSetAdmission::NotApplied(response) => {
            Ok(ReadStartupRouteSetAdmission::NotApplied(response))
        }
        StartupRouteSetAdmission::Refused(refusal) => {
            Ok(ReadStartupRouteSetAdmission::Refused(refusal))
        }
        StartupRouteSetAdmission::Acquired(_) => {
            Err(invalid("read-only startup admission acquired authority"))
        }
    }
}

#[tracing::instrument(
    name = "deployment_driver.route_set_startup.admit_dormant",
    skip_all,
    fields(startup.boot_id = %request.boot_id, publication.id = tracing::field::Empty,
        result.outcome = tracing::field::Empty)
)]
pub(super) async fn admit_startup_publication(
    ledger: &PgPool,
    request: &StartupRouteSetAdmissionRequest,
) -> Result<StartupRouteSetAdmission, DriverError> {
    request.validate()?;
    let row: AdmissionRow = sqlx::query_as(
        "select outcome,publication_id,effect_run_id,global_fence_token,snapshot_count,selector,
                active_runtime_slot,active_runtime_release_id,active_runtime_subject_digest,
                active_runtime_deployment_ref,active_runtime_config_digest,active_runtime_slot_version,
                fleet_release_unresolved,stored_response
           from control.admit_route_set_startup_publication(
             $1,$2,$3,$4,$5,$6,$7,$8,$9)",
    )
        .bind(request.boot_id)
        .bind(&request.idempotency_key)
        .bind(&request.request_digest)
        .bind(request.instance_owner)
        .bind(request.execution_token)
        .bind(request.global_lease_token)
        .bind(request.route_lease_token)
        .bind(request.ttl_seconds)
        .bind(1_i16)
        .fetch_one(ledger)
        .await
        .map_err(DriverError::internal)?;
    tracing::Span::current().record("result.outcome", row.0.as_str());
    if let Some(publication_id) = row.1 {
        tracing::Span::current().record("publication.id", tracing::field::display(publication_id));
    }
    parse_admission(request, row, true)
}

pub(super) async fn renew_startup_publication(
    ledger: &PgPool,
    lease: &StartupRouteSetLease,
) -> Result<bool, DriverError> {
    sqlx::query_scalar("select control.renew_route_set_startup_publication($1,$2,$3,$4,$5,$6,$7)")
        .bind(lease.publication_id)
        .bind(lease.instance_owner)
        .bind(lease.execution_token)
        .bind(lease.global_lease_token)
        .bind(lease.route_lease_token)
        .bind(lease.global_fence_token)
        .bind(lease.ttl_seconds)
        .fetch_one(ledger)
        .await
        .map_err(DriverError::internal)
}

pub(super) async fn record_startup_prior(
    ledger: &PgPool,
    lease: &StartupRouteSetLease,
    selector: &str,
    directory_device: u64,
    directory_inode: u64,
    loaded_identity: Option<&Value>,
) -> Result<StartupTransitionOutcome, DriverError> {
    let boot_live = selector == "generations/boot-live";
    if boot_live != loaded_identity.is_none()
        || loaded_identity
            .map(|identity| identity.to_string().len() > 4_096)
            .unwrap_or(false)
    {
        return Err(invalid("startup prior identity is invalid"));
    }
    let outcome: String = sqlx::query_scalar(
        "select control.record_route_set_startup_prior($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
    )
    .bind(lease.publication_id)
    .bind(lease.instance_owner)
    .bind(lease.execution_token)
    .bind(lease.global_lease_token)
    .bind(lease.route_lease_token)
    .bind(lease.global_fence_token)
    .bind(selector)
    .bind(pg_identity(directory_device)?)
    .bind(pg_identity(directory_inode)?)
    .bind(loaded_identity)
    .fetch_one(ledger)
    .await
    .map_err(DriverError::internal)?;
    parse_transition(&outcome)
}

pub(super) async fn read_startup_snapshot_batch(
    ledger: &PgPool,
    lease: &StartupRouteSetLease,
    after: Option<Uuid>,
    limit: usize,
) -> Result<Vec<StartupSnapshotRow>, DriverError> {
    if !(1..=MAX_ROUTES).contains(&limit) {
        return Err(invalid("startup snapshot batch limit is invalid"));
    }
    let rows = sqlx::query_as(
        "select workshop_id,generation,projection_digest,disposition,canonical_projection,
                baseline_applied_generation,baseline_applied_digest,baseline_applied_disposition,
                baseline_applied_rendered_digest,baseline_applied_driver_operation_id,
                baseline_applied_effect_run_id,baseline_applied_fence_token,route_fence_token,
                database_id,database_ref,public_hostname,action,paperless_mode,paperless_hostname,
                paperless_service_id,paperless_service_health,paperless_service_base_url,
                paperless_service_desired_epoch,paperless_service_applied_epoch,
                paperless_runtime_spec,unresolved_operation
           from control.read_route_set_startup_snapshot_batch($1,$2,$3,$4,$5,$6,$7,$8)",
    )
    .bind(lease.publication_id)
    .bind(lease.instance_owner)
    .bind(lease.execution_token)
    .bind(lease.global_lease_token)
    .bind(lease.route_lease_token)
    .bind(lease.global_fence_token)
    .bind(after)
    .bind(i32::try_from(limit).map_err(DriverError::internal)?)
    .fetch_all(ledger)
    .await
    .map_err(DriverError::internal)?;
    validate_snapshot_batch(after, &rows)?;
    Ok(rows)
}

pub(super) async fn record_startup_entry(
    ledger: &PgPool,
    lease: &StartupRouteSetLease,
    entry: &StartupRecordEntry<'_>,
) -> Result<StartupTransitionOutcome, DriverError> {
    let outcome: String = sqlx::query_scalar(
        "select control.record_route_set_startup_entry(
          $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)",
    )
    .bind(lease.publication_id)
    .bind(lease.instance_owner)
    .bind(lease.execution_token)
    .bind(lease.global_lease_token)
    .bind(lease.route_lease_token)
    .bind(lease.global_fence_token)
    .bind(entry.workshop_id)
    .bind(entry.generation)
    .bind(entry.projection_digest)
    .bind(entry.disposition)
    .bind(entry.baseline_applied_rendered_digest)
    .bind(entry.route_fence_token)
    .bind(entry.runtime_outcome)
    .bind(entry.runtime_evidence)
    .bind(entry.rendered_digest)
    .fetch_one(ledger)
    .await
    .map_err(DriverError::internal)?;
    parse_transition(&outcome)
}

pub(super) async fn seal_startup_publication(
    ledger: &PgPool,
    lease: &StartupRouteSetLease,
    candidate_count: usize,
    present_count: usize,
    route_set_digest: &str,
    directory_device: u64,
    directory_inode: u64,
) -> Result<StartupTransitionOutcome, DriverError> {
    if candidate_count != lease.snapshot_count
        || present_count > candidate_count
        || !valid_sha256(route_set_digest)
    {
        return Err(invalid("startup seal is invalid"));
    }
    let outcome: String = sqlx::query_scalar(
        "select control.seal_route_set_startup_publication($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
    )
    .bind(lease.publication_id)
    .bind(lease.instance_owner)
    .bind(lease.execution_token)
    .bind(lease.global_lease_token)
    .bind(lease.route_lease_token)
    .bind(lease.global_fence_token)
    .bind(i32::try_from(candidate_count).map_err(DriverError::internal)?)
    .bind(i32::try_from(present_count).map_err(DriverError::internal)?)
    .bind(route_set_digest)
    .bind(pg_identity(directory_device)?)
    .bind(pg_identity(directory_inode)?)
    .fetch_one(ledger)
    .await
    .map_err(DriverError::internal)?;
    parse_transition(&outcome)
}

pub(super) async fn start_startup_publication(
    ledger: &PgPool,
    lease: &StartupRouteSetLease,
) -> Result<StartupTransitionOutcome, DriverError> {
    transition_six(
        ledger,
        lease,
        "select control.start_route_set_startup_publication($1,$2,$3,$4,$5,$6)",
    )
    .await
}

pub(super) async fn observe_startup_publication(
    ledger: &PgPool,
    lease: &StartupRouteSetLease,
    selector: &str,
    loaded_identity: &Value,
) -> Result<StartupTransitionOutcome, DriverError> {
    let outcome: String = sqlx::query_scalar(
        "select control.observe_route_set_startup_publication($1,$2,$3,$4,$5,$6,$7,$8)",
    )
    .bind(lease.publication_id)
    .bind(lease.instance_owner)
    .bind(lease.execution_token)
    .bind(lease.global_lease_token)
    .bind(lease.route_lease_token)
    .bind(lease.global_fence_token)
    .bind(selector)
    .bind(loaded_identity)
    .fetch_one(ledger)
    .await
    .map_err(DriverError::internal)?;
    parse_transition(&outcome)
}

pub(super) async fn finish_startup_publication(
    ledger: &PgPool,
    lease: &StartupRouteSetLease,
) -> Result<FinishStartupRouteSetOutcome, DriverError> {
    let (outcome, response): (String, Option<Value>) = sqlx::query_as(
        "select outcome,response from control.finish_route_set_startup_publication($1,$2,$3,$4,$5,$6)",
    )
    .bind(lease.publication_id).bind(lease.instance_owner).bind(lease.execution_token)
    .bind(lease.global_lease_token).bind(lease.route_lease_token).bind(lease.global_fence_token)
    .fetch_one(ledger).await.map_err(DriverError::internal)?;
    match (outcome.as_str(), response) {
        ("applied", Some(value)) => Ok(FinishStartupRouteSetOutcome::Applied(parse_response(
            value, lease,
        )?)),
        ("replay", Some(value)) => Ok(FinishStartupRouteSetOutcome::Replay(parse_response(
            value, lease,
        )?)),
        ("authority_lost", None) => Ok(FinishStartupRouteSetOutcome::AuthorityLost),
        ("snapshot_drift", None) => Ok(FinishStartupRouteSetOutcome::SnapshotDrift),
        ("wrong_phase", None) => Ok(FinishStartupRouteSetOutcome::WrongPhase),
        ("not_found", None) => Ok(FinishStartupRouteSetOutcome::NotFound),
        _ => Err(invalid("startup finish outcome is malformed")),
    }
}

pub(super) async fn read_startup_result(
    ledger: &PgPool,
    lease: &StartupRouteSetLease,
) -> Result<ReadStartupRouteSetResult, DriverError> {
    let row: Option<(String, Uuid, Uuid, Option<Value>)> = sqlx::query_as(
        "select outcome,publication_id,effect_run_id,response
           from control.read_route_set_startup_publication_result($1,$2,$3)",
    )
    .bind(lease.publication_id)
    .bind(lease.effect_run_id)
    .bind(lease.boot_id)
    .fetch_optional(ledger)
    .await
    .map_err(DriverError::internal)?;
    let Some((outcome, publication_id, effect_run_id, response)) = row else {
        return Ok(ReadStartupRouteSetResult::Absent);
    };
    if publication_id != lease.publication_id || effect_run_id != lease.effect_run_id {
        return Ok(ReadStartupRouteSetResult::Conflict);
    }
    match (outcome.as_str(), response) {
        ("replay", Some(value)) => Ok(ReadStartupRouteSetResult::Replay(parse_response(
            value, lease,
        )?)),
        ("applied_recovered", Some(value)) => Ok(ReadStartupRouteSetResult::AppliedRecovered(
            parse_response(value, lease)?,
        )),
        ("not_applied", Some(value)) => {
            let result: StartupRouteSetNotApplied = serde_json::from_value(value)
                .map_err(|_| invalid("startup not-applied result is malformed"))?;
            if result.outcome != "not_applied"
                || result.publication_id != lease.publication_id
                || result.effect_run_id != lease.effect_run_id
                || !matches!(result.resolution_kind.as_str(), "prior" | "unstarted")
                || !valid_bare_sha256(&result.decision_digest)
            {
                return Err(invalid("startup not-applied result identity is invalid"));
            }
            Ok(ReadStartupRouteSetResult::NotApplied(result))
        }
        ("busy", None) => Ok(ReadStartupRouteSetResult::Busy),
        ("fleet_quarantined", None) => Ok(ReadStartupRouteSetResult::FleetQuarantined),
        _ => Err(invalid("startup result row is malformed")),
    }
}

pub(super) async fn quarantine_startup_publication(
    ledger: &PgPool,
    lease: &StartupRouteSetLease,
) -> Result<bool, DriverError> {
    sqlx::query_scalar(
        "select control.quarantine_route_set_startup_publication($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(lease.publication_id)
    .bind(lease.instance_owner)
    .bind(lease.execution_token)
    .bind(lease.global_lease_token)
    .bind(lease.route_lease_token)
    .bind(lease.global_fence_token)
    .bind("route_set_publication_outcome_unknown")
    .fetch_one(ledger)
    .await
    .map_err(DriverError::internal)
}

async fn transition_six(
    ledger: &PgPool,
    lease: &StartupRouteSetLease,
    query: &'static str,
) -> Result<StartupTransitionOutcome, DriverError> {
    let outcome: String = sqlx::query_scalar(query)
        .bind(lease.publication_id)
        .bind(lease.instance_owner)
        .bind(lease.execution_token)
        .bind(lease.global_lease_token)
        .bind(lease.route_lease_token)
        .bind(lease.global_fence_token)
        .fetch_one(ledger)
        .await
        .map_err(DriverError::internal)?;
    parse_transition(&outcome)
}

fn parse_admission(
    request: &StartupRouteSetAdmissionRequest,
    row: AdmissionRow,
    allow_acquired: bool,
) -> Result<StartupRouteSetAdmission, DriverError> {
    match row.0.as_str() {
        "acquired" if allow_acquired && row.13.is_none() => Ok(StartupRouteSetAdmission::Acquired(
            Box::new(lease_from_row(request, &row)?),
        )),
        "replay" => {
            let lease = lease_from_row(request, &row)?;
            let response = parse_response(
                row.13
                    .ok_or_else(|| invalid("startup replay response is absent"))?,
                &lease,
            )?;
            Ok(StartupRouteSetAdmission::Replay(response))
        }
        "not_applied" => {
            let lease = lease_from_row(request, &row)?;
            let response = parse_not_applied(
                row.13
                    .ok_or_else(|| invalid("startup not-applied response is absent"))?,
                &lease,
            )?;
            Ok(StartupRouteSetAdmission::NotApplied(response))
        }
        outcome => {
            let refusal = parse_refusal(outcome)
                .ok_or_else(|| invalid("startup admission outcome is invalid"))?;
            validate_refusal_shape(request, outcome, &row)?;
            Ok(StartupRouteSetAdmission::Refused(refusal))
        }
    }
}

fn parse_not_applied(
    value: Value,
    lease: &StartupRouteSetLease,
) -> Result<StartupRouteSetNotApplied, DriverError> {
    let result: StartupRouteSetNotApplied = serde_json::from_value(value)
        .map_err(|_| invalid("startup not-applied response is malformed"))?;
    if result.outcome != "not_applied"
        || result.publication_id != lease.publication_id
        || result.effect_run_id != lease.effect_run_id
        || !matches!(result.resolution_kind.as_str(), "prior" | "unstarted")
        || !valid_bare_sha256(&result.decision_digest)
    {
        return Err(invalid("startup not-applied response identity differs"));
    }
    Ok(result)
}

fn lease_from_row(
    request: &StartupRouteSetAdmissionRequest,
    row: &AdmissionRow,
) -> Result<StartupRouteSetLease, DriverError> {
    let publication_id = required_uuid(row.1, "publication id")?;
    let effect_run_id = required_uuid(row.2, "effect run id")?;
    let global_fence_token = row
        .3
        .filter(|value| *value > 0)
        .ok_or_else(|| invalid("startup global fence is invalid"))?;
    let snapshot_count = usize::try_from(row.4.ok_or_else(|| invalid("startup count is absent"))?)
        .ok()
        .filter(|count| *count <= MAX_ROUTES)
        .ok_or_else(|| invalid("startup count is invalid"))?;
    let selector = row
        .5
        .clone()
        .ok_or_else(|| invalid("startup selector is absent"))?;
    if selector
        != RouteSetGenerationName::new(publication_id, RouteSetPublicationKind::Startup)
            .selector_target()
    {
        return Err(invalid("startup selector is invalid"));
    }
    let runtime = parse_runtime(row)?;
    Ok(StartupRouteSetLease {
        publication_id,
        effect_run_id,
        boot_id: request.boot_id,
        global_fence_token,
        snapshot_count,
        selector,
        runtime,
        fleet_release_unresolved: row
            .12
            .ok_or_else(|| invalid("startup release observation is absent"))?,
        instance_owner: request.instance_owner,
        execution_token: request.execution_token,
        global_lease_token: request.global_lease_token,
        route_lease_token: request.route_lease_token,
        ttl_seconds: request.ttl_seconds,
    })
}

fn parse_runtime(row: &AdmissionRow) -> Result<StartupFrozenRuntime, DriverError> {
    match (&row.6, &row.7, &row.8, &row.9, &row.10, row.11) {
        (None, None, None, None, None, None) => Ok(StartupFrozenRuntime::Absent),
        (
            Some(slot),
            Some(release),
            Some(subject),
            Some(deployment),
            Some(config),
            Some(version),
        ) if matches!(slot.as_str(), "blue" | "green")
            && !release.trim().is_empty()
            && valid_sha256(subject)
            && !deployment.trim().is_empty()
            && valid_sha256(config)
            && version > 0 =>
        {
            Ok(StartupFrozenRuntime::Active {
                slot: slot.clone(),
                release_id: release.clone(),
                subject_digest: subject.clone(),
                deployment_ref: deployment.clone(),
                config_digest: config.clone(),
                slot_version: version,
            })
        }
        _ => Err(invalid("startup runtime identity is incomplete")),
    }
}

fn parse_response(
    value: Value,
    lease: &StartupRouteSetLease,
) -> Result<StartupRouteSetResponse, DriverError> {
    let object = value
        .as_object()
        .filter(|object| object.len() == 5)
        .ok_or_else(|| invalid("startup response shape is invalid"))?;
    for key in [
        "effect_run_id",
        "global_fence_token",
        "workshop_count",
        "projection_set_digest",
        "gateway_reload_digest",
    ] {
        if !object.contains_key(key) {
            return Err(invalid("startup response keys are invalid"));
        }
    }
    let response: StartupRouteSetResponse =
        serde_json::from_value(value).map_err(|_| invalid("startup response is malformed"))?;
    if response.effect_run_id != lease.effect_run_id
        || response.global_fence_token != lease.global_fence_token
        || response.workshop_count != lease.snapshot_count
        || !valid_sha256(&response.projection_set_digest)
        || !valid_sha256(&response.gateway_reload_digest)
        || response.gateway_reload_digest != response.projection_set_digest
    {
        return Err(invalid("startup response identity is invalid"));
    }
    Ok(response)
}

fn validate_refusal_shape(
    request: &StartupRouteSetAdmissionRequest,
    outcome: &str,
    row: &AdmissionRow,
) -> Result<(), DriverError> {
    let only_count = row.1.is_none()
        && row.2.is_none()
        && row.3.is_none()
        && row.4.is_some()
        && row.5.is_none()
        && runtime_and_tail_are_empty(row);
    let legacy_partial = row.1.is_none()
        && row.2.is_some_and(|id| !id.is_nil())
        && row.3.is_some_and(|fence| fence > 0)
        && row.4.is_some_and(|count| count >= 0)
        && row.5.is_none()
        && runtime_and_tail_are_empty(row);
    let durable_identity = row.1.is_some_and(|id| !id.is_nil())
        && row.2.is_some_and(|id| !id.is_nil())
        && row.3.is_some_and(|fence| fence > 0)
        && row.4.is_some_and(|count| count >= 0)
        && row
            .5
            .as_deref()
            .is_some_and(|selector| !selector.is_empty())
        && row.13.is_none();
    let valid = match outcome {
        "invalid" | "protocol_inactive" => admission_payload_is_empty(row),
        "fleet_too_large" => only_count && row.4.is_some_and(|count| count > MAX_ROUTES as i32),
        "conflict" => {
            admission_payload_is_empty(row) || (durable_identity && runtime_and_tail_are_empty(row))
        }
        "busy" | "fleet_quarantined" => lease_from_row(request, row).is_ok() || legacy_partial,
        "fleet_busy"
        | "route_busy"
        | "route_quarantined"
        | "initialization_required"
        | "runtime_ambiguous"
        | "runtime_identity_missing"
        | "authority_lost" => legacy_partial,
        _ => false,
    };
    if !valid {
        return Err(invalid("startup refusal row shape is malformed"));
    }
    Ok(())
}

fn runtime_and_tail_are_empty(row: &AdmissionRow) -> bool {
    row.6.is_none()
        && row.7.is_none()
        && row.8.is_none()
        && row.9.is_none()
        && row.10.is_none()
        && row.11.is_none()
        && row.12.is_none()
        && row.13.is_none()
}

fn parse_refusal(value: &str) -> Option<StartupRouteSetRefusal> {
    Some(match value {
        "invalid" => StartupRouteSetRefusal::Invalid,
        "protocol_inactive" => StartupRouteSetRefusal::ProtocolInactive,
        "fleet_too_large" => StartupRouteSetRefusal::FleetTooLarge,
        "busy" => StartupRouteSetRefusal::Busy,
        "conflict" => StartupRouteSetRefusal::Conflict,
        "fleet_busy" => StartupRouteSetRefusal::FleetBusy,
        "fleet_quarantined" => StartupRouteSetRefusal::FleetQuarantined,
        "route_busy" => StartupRouteSetRefusal::RouteBusy,
        "route_quarantined" => StartupRouteSetRefusal::RouteQuarantined,
        "initialization_required" => StartupRouteSetRefusal::InitializationRequired,
        "runtime_ambiguous" => StartupRouteSetRefusal::RuntimeAmbiguous,
        "runtime_identity_missing" => StartupRouteSetRefusal::RuntimeIdentityMissing,
        "authority_lost" => StartupRouteSetRefusal::AuthorityLost,
        _ => return None,
    })
}

fn parse_transition(value: &str) -> Result<StartupTransitionOutcome, DriverError> {
    Ok(match value {
        "recorded" => StartupTransitionOutcome::Recorded,
        "sealed" => StartupTransitionOutcome::Sealed,
        "started" => StartupTransitionOutcome::Started,
        "observed" => StartupTransitionOutcome::Observed,
        "replay" => StartupTransitionOutcome::Replay,
        "authority_lost" => StartupTransitionOutcome::AuthorityLost,
        "conflict" => StartupTransitionOutcome::Conflict,
        "invalid" => StartupTransitionOutcome::Invalid,
        "wrong_phase" => StartupTransitionOutcome::WrongPhase,
        "out_of_order" => StartupTransitionOutcome::OutOfOrder,
        "snapshot_drift" => StartupTransitionOutcome::SnapshotDrift,
        "runtime_drift" => StartupTransitionOutcome::RuntimeDrift,
        "runtime_mismatch" => StartupTransitionOutcome::RuntimeMismatch,
        "render_invariant_mismatch" => StartupTransitionOutcome::RenderInvariantMismatch,
        "observation_mismatch" => StartupTransitionOutcome::ObservationMismatch,
        _ => return Err(invalid("startup transition outcome is invalid")),
    })
}

fn validate_snapshot_batch(
    after: Option<Uuid>,
    rows: &[StartupSnapshotRow],
) -> Result<(), DriverError> {
    if rows.len() > MAX_ROUTES {
        return Err(invalid("startup snapshot batch exceeds its bound"));
    }
    let mut previous = after;
    for row in rows {
        if row.workshop_id.is_nil()
            || previous.is_some_and(|id| id >= row.workshop_id)
            || row.generation <= 0
            || !valid_sha256(&row.projection_digest)
            || !matches!(row.disposition.as_str(), "present" | "absent")
            || row.route_fence_token <= 0
            || !matches!(row.action.as_str(), "render" | "remove-absent")
            || !matches!(
                row.paperless_mode.as_str(),
                "absent" | "read_only" | "read_write"
            )
        {
            return Err(invalid("startup snapshot row is invalid"));
        }
        let baselines = [
            row.baseline_applied_generation.is_some(),
            row.baseline_applied_digest.is_some(),
            row.baseline_applied_disposition.is_some(),
            row.baseline_applied_rendered_digest.is_some(),
            row.baseline_applied_fence_token.is_some(),
        ];
        if baselines.iter().any(|present| *present) && !baselines.iter().all(|present| *present) {
            return Err(invalid("startup snapshot applied baseline is incomplete"));
        }
        if row
            .baseline_applied_generation
            .is_some_and(|value| value <= 0)
            || row
                .baseline_applied_fence_token
                .is_some_and(|value| value <= 0)
            || row
                .baseline_applied_digest
                .as_deref()
                .is_some_and(|value| !valid_sha256(value))
            || row
                .baseline_applied_rendered_digest
                .as_deref()
                .is_some_and(|value| !valid_sha256(value))
            || row
                .baseline_applied_disposition
                .as_deref()
                .is_some_and(|value| !matches!(value, "present" | "absent"))
        {
            return Err(invalid("startup snapshot applied baseline is invalid"));
        }
        previous = Some(row.workshop_id);
    }
    Ok(())
}

fn pg_identity(value: u64) -> Result<i64, DriverError> {
    i64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| invalid("startup filesystem identity is invalid"))
}

fn admission_payload_is_empty(row: &AdmissionRow) -> bool {
    row.1.is_none()
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
        && row.12.is_none()
        && row.13.is_none()
}

fn required_uuid(value: Option<Uuid>, name: &str) -> Result<Uuid, DriverError> {
    value
        .filter(|id| !id.is_nil())
        .ok_or_else(|| invalid(format!("startup {name} is invalid")))
}

fn valid_bare_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn valid_sha256(value: &str) -> bool {
    validate_digest(value, "startup digest").is_ok()
}

fn invalid(message: impl Into<String>) -> DriverError {
    DriverError::internal(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn request() -> StartupRouteSetAdmissionRequest {
        StartupRouteSetAdmissionRequest {
            boot_id: Uuid::new_v4(),
            idempotency_key: "startup/boot".into(),
            request_digest: "a".repeat(64),
            instance_owner: Uuid::new_v4(),
            execution_token: Uuid::new_v4(),
            global_lease_token: Uuid::new_v4(),
            route_lease_token: Uuid::new_v4(),
            ttl_seconds: 120,
        }
    }

    fn acquired_row() -> AdmissionRow {
        let publication_id = Uuid::new_v4();
        (
            "acquired".into(),
            Some(publication_id),
            Some(Uuid::new_v4()),
            Some(11),
            Some(0),
            Some(
                RouteSetGenerationName::new(publication_id, RouteSetPublicationKind::Startup)
                    .selector_target(),
            ),
            None,
            None,
            None,
            None,
            None,
            None,
            Some(false),
            None,
        )
    }

    fn discovery_row(publication_id: Uuid, phase: &str, mode: &str) -> StartupDiscoveryRow {
        (
            publication_id,
            Uuid::new_v4(),
            phase.into(),
            mode.into(),
            RouteSetGenerationName::new(publication_id, RouteSetPublicationKind::Startup)
                .selector_target(),
            (phase != "staging").then(|| format!("sha256:{}", "a".repeat(64))),
            3,
            OffsetDateTime::now_utc(),
        )
    }

    #[test]
    fn startup_recovery_discovery_is_ordered_closed_and_phase_shaped() {
        let first = Uuid::from_u128(10);
        let second = Uuid::from_u128(20);
        let parsed = validate_startup_discovery(
            None,
            vec![
                discovery_row(first, "staging", "write_cleanup"),
                discovery_row(second, "publication_started", "observe_only"),
            ],
        )
        .unwrap();
        assert_eq!(parsed[0].publication_id, first);
        assert_eq!(parsed[1].publication_id, second);
        assert!(
            validate_startup_discovery(
                Some(second),
                vec![discovery_row(first, "staging", "write_cleanup")]
            )
            .is_err()
        );
        assert!(
            validate_startup_discovery(
                None,
                vec![discovery_row(first, "observed", "write_cleanup")]
            )
            .is_err()
        );
        let mut malformed = discovery_row(first, "sealed", "observe_only");
        malformed.5 = None;
        assert!(validate_startup_discovery(None, vec![malformed]).is_err());
    }

    #[test]
    fn request_and_fleet_lease_are_exact_without_a_fake_target() {
        let request = request();
        assert!(request.validate().is_ok());
        let lease = match parse_admission(&request, acquired_row(), true).unwrap() {
            StartupRouteSetAdmission::Acquired(lease) => lease,
            _ => panic!("expected acquired"),
        };
        assert_eq!(lease.snapshot_count, 0);
        assert_eq!(lease.runtime, StartupFrozenRuntime::Absent);
        let source = include_str!("route_set_startup_publication_db.rs");
        assert!(
            !source
                .split("#[cfg(test)]")
                .next()
                .unwrap()
                .contains("target_workshop_id")
        );
    }

    #[test]
    fn replay_receipt_is_exact_and_uses_the_published_digest() {
        let request = request();
        let row = acquired_row();
        let lease = lease_from_row(&request, &row).unwrap();
        let digest = format!("sha256:{}", "b".repeat(64));
        let response = json!({
            "effect_run_id":lease.effect_run_id,
            "global_fence_token":lease.global_fence_token,
            "workshop_count":0,
            "projection_set_digest":digest,
            "gateway_reload_digest":digest,
        });
        assert!(parse_response(response.clone(), &lease).is_ok());
        let mut drifted = response;
        drifted["gateway_reload_digest"] = json!(format!("sha256:{}", "c".repeat(64)));
        assert!(parse_response(drifted, &lease).is_err());
    }

    #[test]
    fn terminal_admission_replays_success_or_returns_typed_not_applied() {
        let request = request();
        let mut candidate = acquired_row();
        let lease = lease_from_row(&request, &candidate).unwrap();
        let digest = format!("sha256:{}", "b".repeat(64));
        candidate.0 = "replay".into();
        candidate.13 = Some(json!({
            "effect_run_id":lease.effect_run_id,
            "global_fence_token":lease.global_fence_token,
            "workshop_count":lease.snapshot_count,
            "projection_set_digest":digest,
            "gateway_reload_digest":digest,
        }));
        assert!(matches!(
            parse_admission(&request, candidate, false).unwrap(),
            StartupRouteSetAdmission::Replay(_)
        ));

        let mut prior = acquired_row();
        let lease = lease_from_row(&request, &prior).unwrap();
        prior.0 = "not_applied".into();
        prior.13 = Some(json!({
            "outcome":"not_applied",
            "publication_id":lease.publication_id,
            "effect_run_id":lease.effect_run_id,
            "resolution_kind":"prior",
            "decision_digest":"c".repeat(64),
        }));
        assert!(matches!(
            parse_admission(&request, prior.clone(), false).unwrap(),
            StartupRouteSetAdmission::NotApplied(StartupRouteSetNotApplied {
                resolution_kind,
                ..
            }) if resolution_kind == "prior"
        ));
        prior.13.as_mut().unwrap()["private_extra"] = json!(true);
        assert!(parse_admission(&request, prior, false).is_err());
    }

    #[test]
    fn read_only_and_refusal_rows_are_closed() {
        let request = request();
        let absent: AdmissionRow = (
            "absent".into(),
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
            None,
        );
        assert!(admission_payload_is_empty(&absent));
        let inactive: AdmissionRow = (
            "protocol_inactive".into(),
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
            None,
        );
        assert!(matches!(
            parse_admission(&request, inactive, false).unwrap(),
            StartupRouteSetAdmission::Refused(StartupRouteSetRefusal::ProtocolInactive)
        ));
        let malformed: AdmissionRow = (
            "protocol_inactive".into(),
            None,
            Some(Uuid::new_v4()),
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
        );
        assert!(parse_admission(&request, malformed, false).is_err());
    }

    #[test]
    fn sql_surfaces_are_exact_and_dormant() {
        let source = include_str!("route_set_startup_publication_db.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        let migration = include_str!("../../migrations/0034_route_set_startup_publications.sql");
        assert!(source.contains("read_route_set_startup_admission($1,$2,$3)"));
        assert!(source.contains(
            "admit_route_set_startup_publication(\n             $1,$2,$3,$4,$5,$6,$7,$8,$9)"
        ));
        assert!(migration.contains("read_route_set_startup_admission(\n p_boot_id uuid,p_idempotency_key text,p_request_digest text"));
        assert!(source.contains("discover_interrupted_route_set_startup_publications($1,$2)"));
        for signature in [
            "discover_interrupted_route_set_startup_publications(",
            "claim_interrupted_route_set_startup_publication(",
            "read_interrupted_route_set_startup_publication_state(",
            "resolve_interrupted_route_set_startup_publication_observation(",
            "route_set_startup_terminal_decision_digest(",
            "finish_route_set_startup_publication_recovery(",
        ] {
            assert!(source.contains(signature));
            assert!(migration.contains(signature));
        }
        for function in [
            "claim_startup_recovery(",
            "resolve_startup_recovery_observation(",
            "finish_startup_recovery(",
        ] {
            let annotation = production
                .split(function)
                .next()
                .unwrap()
                .rsplit("#[tracing::instrument(")
                .next()
                .unwrap();
            assert!(annotation.contains("skip_all"));
            assert!(annotation.contains("publication.id"));
            for private in [
                "token",
                "selector",
                "hostname",
                "database_ref",
                "digest",
                "error",
            ] {
                assert!(
                    !annotation.contains(private),
                    "private trace field {private}"
                );
            }
        }
        let active = include_str!("../docker_driver.rs");
        assert!(!active.contains("admit_startup_publication("));
    }
}
