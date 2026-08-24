//! Typed persistence boundary for protocol-v1 staged startup publication.
//!
//! This module deliberately contains no filesystem or gateway side effects.
//! Each transition is delegated to the function-only ledger API introduced by
//! migration 0024, and every returned row is validated before it is exposed to
//! the startup orchestrator.

#![allow(dead_code)] // Protocol substrate becomes reachable in the startup-orchestrator cutover.

pub(super) use super::route_projection::PaperlessRouteMode;
use super::route_projection::{RouteDisposition as ProjectionDisposition, RouteProjection};
use super::*;

pub(super) const STARTUP_PUBLICATION_PROTOCOL_VERSION: i16 = 1;
pub(super) const STARTUP_PUBLICATION_MAX_BATCH: usize = 500;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RouteDisposition {
    Present,
    Absent,
}

impl RouteDisposition {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Present => "present",
            Self::Absent => "absent",
        }
    }

    fn parse(value: &str) -> Result<Self, DriverError> {
        match value {
            "present" => Ok(Self::Present),
            "absent" => Ok(Self::Absent),
            _ => Err(contract_error("startup publication disposition is invalid")),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RouteAction {
    Render,
    RemoveAbsent,
}

impl RouteAction {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Render => "render",
            Self::RemoveAbsent => "remove-absent",
        }
    }

    fn parse(value: &str) -> Result<Self, DriverError> {
        match value {
            "render" => Ok(Self::Render),
            "remove-absent" => Ok(Self::RemoveAbsent),
            _ => Err(contract_error("startup publication action is invalid")),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RuntimeOutcome {
    Ready,
    Absent,
}

impl RuntimeOutcome {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Absent => "absent",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ActiveRuntimeIdentity {
    pub(super) slot: String,
    pub(super) release_id: String,
    pub(super) subject_digest: String,
    pub(super) deployment_ref: String,
    pub(super) config_digest: String,
    pub(super) slot_version: i64,
}

#[derive(Clone, Debug)]
pub(super) struct StartupPublicationLease {
    pub(super) effect_run_id: Uuid,
    pub(super) instance_owner: Uuid,
    pub(super) execution_token: Uuid,
    pub(super) global_lease_token: Uuid,
    pub(super) route_lease_token: Uuid,
    pub(super) global_fence_token: i64,
    pub(super) reserved_count: usize,
    pub(super) staging_selector: String,
    pub(super) active_runtime: Option<ActiveRuntimeIdentity>,
    pub(super) fleet_release_unresolved: bool,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct StartupPublicationAdmissionRequest<'a> {
    pub(super) boot_id: Uuid,
    pub(super) idempotency_key: &'a str,
    /// Lower-case, unprefixed SHA-256 digest used by the legacy admission API.
    pub(super) request_digest: &'a str,
    pub(super) ttl_seconds: i32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum StartupPublicationUnavailable {
    Busy,
    Quarantined,
    DigestConflict,
    InitializationRequired,
    RuntimeAmbiguous,
    RuntimeIdentityMissing,
    Invalid,
}

#[derive(Debug)]
pub(super) enum StartupPublicationAdmission {
    Acquired(Box<StartupPublicationLease>),
    Replay(Value),
    Unavailable(StartupPublicationUnavailable),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct GatewayPublicationObservation {
    pub(super) selector: String,
    /// Device/inode identity of the selected generation directory at the time
    /// it was opened without following attacker-controlled path components.
    pub(super) directory_device: u64,
    pub(super) directory_inode: u64,
    pub(super) effect_run_id: Option<Uuid>,
    pub(super) projection_set_digest: Option<String>,
}

#[derive(Clone, Debug)]
pub(super) struct StagedStartupRoute {
    pub(super) workshop_id: Uuid,
    pub(super) database_id: Option<Uuid>,
    pub(super) database_ref: Option<String>,
    pub(super) public_hostname: Option<String>,
    pub(super) generation: i64,
    pub(super) projection_digest: String,
    pub(super) disposition: RouteDisposition,
    pub(super) action: RouteAction,
    pub(super) paperless_mode: PaperlessRouteMode,
    pub(super) paperless_hostname: Option<String>,
    pub(super) paperless_service_id: Option<Uuid>,
    pub(super) paperless_service_health: Option<String>,
    pub(super) paperless_service_base_url: Option<String>,
    pub(super) paperless_service_desired_epoch: Option<i32>,
    pub(super) paperless_service_applied_epoch: Option<i32>,
    pub(super) paperless_runtime_spec: Option<Value>,
    pub(super) unresolved_operation: bool,
    pub(super) route_fence_token: i64,
    pub(super) projection: Value,
}

#[derive(Debug)]
pub(super) struct StartupRouteBatch {
    pub(super) routes: Vec<StagedStartupRoute>,
    pub(super) next_cursor: Option<Uuid>,
}

#[derive(Clone, Debug)]
pub(super) struct StartupRuntimeObservation {
    pub(super) outcome: RuntimeOutcome,
    /// Exact nine-key observation object required by migration 0024.
    pub(super) evidence: Value,
}

impl StartupRuntimeObservation {
    pub(super) fn absent(
        lease: &StartupPublicationLease,
        route: &StagedStartupRoute,
        verified_at: String,
    ) -> Result<Self, DriverError> {
        let observation = Self {
            outcome: RuntimeOutcome::Absent,
            evidence: runtime_evidence(
                lease,
                route,
                RuntimeOutcome::Absent,
                Value::Null,
                Value::Null,
                verified_at,
            ),
        };
        validate_runtime_observation(lease, route, &observation)?;
        Ok(observation)
    }

    pub(super) fn ready(
        lease: &StartupPublicationLease,
        route: &StagedStartupRoute,
        verified_at: String,
    ) -> Result<Self, DriverError> {
        let observation = Self {
            outcome: RuntimeOutcome::Ready,
            evidence: runtime_evidence(
                lease,
                route,
                RuntimeOutcome::Ready,
                expected_odoo_runtime(lease, route)?,
                expected_paperless_runtime(route)?,
                verified_at,
            ),
        };
        validate_runtime_observation(lease, route, &observation)?;
        Ok(observation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct StartupPublicationSeal {
    pub(super) candidate_count: usize,
    pub(super) projection_set_digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct InterruptedPublicationSeal {
    pub(super) candidate_count: usize,
    pub(super) present_count: usize,
    pub(super) projection_set_digest: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum InterruptedPublicationPhase {
    Staging,
    Sealed,
    PublicationStarted,
    Observed,
}

impl InterruptedPublicationPhase {
    fn parse(value: &str) -> Result<Self, DriverError> {
        match value {
            "staging" => Ok(Self::Staging),
            "sealed" => Ok(Self::Sealed),
            "publication_started" => Ok(Self::PublicationStarted),
            "observed" => Ok(Self::Observed),
            _ => Err(contract_error(
                "interrupted startup publication phase is invalid",
            )),
        }
    }
}

#[derive(Clone, Debug)]
pub(super) struct InterruptedStartupPublication {
    pub(super) effect_run_id: Uuid,
    pub(super) reconciliation_owner: Uuid,
    pub(super) reconciliation_token: Uuid,
    pub(super) interrupted_phase: InterruptedPublicationPhase,
    pub(super) original_instance_owner: Uuid,
    pub(super) original_global_fence_token: i64,
    pub(super) prior: Option<GatewayPublicationObservation>,
    pub(super) staging_selector: String,
    pub(super) seal: Option<InterruptedPublicationSeal>,
}

#[derive(Debug)]
pub(super) enum InterruptedPublicationClaim {
    None,
    Acquired(Box<InterruptedStartupPublication>),
    Invalid,
}

#[derive(Clone, Debug)]
pub(super) enum InterruptedPublicationResolution {
    Candidate {
        observation: GatewayPublicationObservation,
        gateway_reload_digest: String,
    },
    Prior {
        observation: GatewayPublicationObservation,
    },
    Unstarted,
    Inconclusive,
}

#[derive(sqlx::FromRow)]
struct AdmissionRow {
    outcome: String,
    effect_run_id: Option<Uuid>,
    global_fence_token: Option<i64>,
    reserved_count: Option<i32>,
    staging_selector: Option<String>,
    prior_selector: Option<String>,
    active_runtime_slot: Option<String>,
    active_runtime_release_id: Option<String>,
    active_runtime_subject_digest: Option<String>,
    active_runtime_deployment_ref: Option<String>,
    active_runtime_config_digest: Option<String>,
    active_runtime_slot_version: Option<i64>,
    fleet_release_unresolved: Option<bool>,
    stored_response: Option<Value>,
}

#[derive(sqlx::FromRow)]
struct RouteRow {
    workshop_id: Uuid,
    database_id: Option<Uuid>,
    database_ref: Option<String>,
    public_hostname: Option<String>,
    generation: i64,
    projection_digest: String,
    disposition: String,
    action: String,
    paperless_mode: String,
    paperless_hostname: Option<String>,
    paperless_service_id: Option<Uuid>,
    paperless_service_health: Option<String>,
    paperless_service_base_url: Option<String>,
    paperless_service_desired_epoch: Option<i32>,
    paperless_service_applied_epoch: Option<i32>,
    paperless_runtime_spec: Option<Value>,
    unresolved_operation: bool,
    route_fence_token: i64,
    projection: Value,
}

#[derive(sqlx::FromRow)]
struct ClaimRow {
    outcome: String,
    effect_run_id: Option<Uuid>,
    interrupted_phase: Option<String>,
    original_instance_owner: Option<Uuid>,
    original_global_fence_token: Option<i64>,
    prior_selector: Option<String>,
    prior_directory_device: Option<i64>,
    prior_directory_inode: Option<i64>,
    staging_selector: Option<String>,
    prior_gateway_effect_run_id: Option<Uuid>,
    prior_gateway_set_digest: Option<String>,
    sealed_count: Option<i32>,
    sealed_present_count: Option<i32>,
    projection_set_digest: Option<String>,
}

#[tracing::instrument(
    name = "deployment_driver.startup_publication.admit",
    skip_all,
    fields(driver.instance_id = %state.instance_id, publication.outcome = tracing::field::Empty)
)]
pub(super) async fn admit(
    state: &DriverState,
    request: StartupPublicationAdmissionRequest<'_>,
) -> Result<StartupPublicationAdmission, DriverError> {
    validate_admission_request(request)?;
    let execution_token = Uuid::new_v4();
    let global_lease_token = Uuid::new_v4();
    let route_lease_token = Uuid::new_v4();
    let rows = sqlx::query_as::<_, AdmissionRow>(
        "select outcome,effect_run_id,global_fence_token,reserved_count,
                staging_selector,prior_selector,active_runtime_slot,
                active_runtime_release_id,active_runtime_subject_digest,
                active_runtime_deployment_ref,active_runtime_config_digest,
                active_runtime_slot_version,fleet_release_unresolved,stored_response
           from control.admit_staged_startup_route_publication(
                $1,$2,$3,$4,$5,$6,$7,$8,$9)",
    )
    .bind(request.boot_id)
    .bind(request.idempotency_key)
    .bind(request.request_digest)
    .bind(state.instance_id)
    .bind(execution_token)
    .bind(global_lease_token)
    .bind(route_lease_token)
    .bind(request.ttl_seconds)
    .bind(STARTUP_PUBLICATION_PROTOCOL_VERSION)
    .fetch_all(&state.ledger)
    .await
    .map_err(DriverError::internal)?;
    let row = exactly_one(
        rows,
        "startup publication admission returned an invalid row count",
    )?;
    tracing::Span::current().record("publication.outcome", row.outcome.as_str());
    parse_admission(
        row,
        state.instance_id,
        execution_token,
        global_lease_token,
        route_lease_token,
    )
}

#[tracing::instrument(
    name = "deployment_driver.startup_publication.record_prior",
    skip_all,
    fields(publication.effect_run_id = %lease.effect_run_id)
)]
pub(super) async fn record_prior(
    state: &DriverState,
    lease: &StartupPublicationLease,
    observation: &GatewayPublicationObservation,
) -> Result<(), DriverError> {
    validate_gateway_observation(observation)?;
    transition(
        sqlx::query_scalar::<_, bool>(
            "select control.record_staged_startup_route_prior(
                $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
        )
        .bind(lease.effect_run_id)
        .bind(lease.instance_owner)
        .bind(lease.execution_token)
        .bind(lease.global_lease_token)
        .bind(lease.route_lease_token)
        .bind(lease.global_fence_token)
        .bind(&observation.selector)
        .bind(pg_file_identity(observation.directory_device)?)
        .bind(pg_file_identity(observation.directory_inode)?)
        .bind(observation.effect_run_id)
        .bind(observation.projection_set_digest.as_deref())
        .fetch_one(&state.ledger)
        .await
        .map_err(DriverError::internal)?,
        "startup publication prior observation was fenced",
    )
}

pub(super) async fn begin(
    state: &DriverState,
    lease: &StartupPublicationLease,
) -> Result<(), DriverError> {
    transition(
        lease_transition_query(
            "control.begin_staged_startup_route_publication",
            state,
            lease,
        )
        .await?,
        "startup publication begin was fenced",
    )
}

/// Renew through the protocol-v0 function retained by migration 0024 for a
/// rolling binary/schema cutover. The lease identity is unchanged.
pub(super) async fn renew(
    state: &DriverState,
    lease: &StartupPublicationLease,
    ttl_seconds: i32,
) -> Result<(), DriverError> {
    validate_ttl(ttl_seconds)?;
    let renewed = sqlx::query_scalar::<_, bool>(
        "select control.renew_startup_route_rebuild($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(lease.effect_run_id)
    .bind(lease.instance_owner)
    .bind(lease.execution_token)
    .bind(lease.global_lease_token)
    .bind(lease.route_lease_token)
    .bind(lease.global_fence_token)
    .bind(ttl_seconds)
    .fetch_one(&state.ledger)
    .await
    .map_err(DriverError::internal)?;
    transition(renewed, "startup publication lease was lost")
}

#[tracing::instrument(
    name = "deployment_driver.startup_publication.read_batch",
    skip_all,
    fields(publication.effect_run_id = %lease.effect_run_id, publication.batch_limit = limit)
)]
pub(super) async fn read_batch(
    state: &DriverState,
    lease: &StartupPublicationLease,
    after: Option<Uuid>,
    limit: usize,
) -> Result<StartupRouteBatch, DriverError> {
    let limit = validate_batch_limit(limit)?;
    let rows = sqlx::query_as::<_, RouteRow>(
        "select workshop_id,database_id,database_ref,public_hostname,generation,
                projection_digest,disposition,action,paperless_mode,paperless_hostname,
                paperless_service_id,paperless_service_health,
                paperless_service_base_url,paperless_service_desired_epoch,
                paperless_service_applied_epoch,paperless_runtime_spec,
                unresolved_operation,route_fence_token,projection
           from control.read_staged_startup_route_batch($1,$2,$3,$4,$5,$6,$7,$8)",
    )
    .bind(lease.effect_run_id)
    .bind(lease.instance_owner)
    .bind(lease.execution_token)
    .bind(lease.global_lease_token)
    .bind(lease.route_lease_token)
    .bind(lease.global_fence_token)
    .bind(after)
    .bind(limit)
    .fetch_all(&state.ledger)
    .await
    .map_err(DriverError::internal)?;
    if rows.len() > limit as usize {
        return Err(contract_error(
            "startup publication batch exceeded its bound",
        ));
    }
    let routes = validate_route_rows(rows, after)?;
    let next_cursor = routes.last().map(|route| route.workshop_id);
    Ok(StartupRouteBatch {
        routes,
        next_cursor,
    })
}

#[tracing::instrument(
    name = "deployment_driver.startup_publication.record_candidate",
    skip_all,
    fields(publication.effect_run_id = %lease.effect_run_id, workshop.id = %route.workshop_id)
)]
pub(super) async fn record_candidate(
    state: &DriverState,
    lease: &StartupPublicationLease,
    expected_after: Option<Uuid>,
    route: &StagedStartupRoute,
    observation: &StartupRuntimeObservation,
    rendered_digest: &str,
) -> Result<(), DriverError> {
    validate_route(route)?;
    validate_sha256(rendered_digest, "startup rendered digest is invalid")?;
    validate_runtime_observation(lease, route, observation)?;
    let candidate_evidence = json!({
        "effect_run_id": lease.effect_run_id,
        "workshop_id": route.workshop_id,
        "generation": route.generation,
        "projection_digest": route.projection_digest,
        "disposition": route.disposition.as_str(),
        "action": route.action.as_str(),
        "route_fence_token": route.route_fence_token,
        "rendered_digest": rendered_digest,
        "runtime_evidence": observation.evidence,
    });
    let recorded = sqlx::query_scalar::<_, bool>(
        "select control.record_staged_startup_route_candidate(
            $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)",
    )
    .bind(lease.effect_run_id)
    .bind(lease.instance_owner)
    .bind(lease.execution_token)
    .bind(lease.global_lease_token)
    .bind(lease.route_lease_token)
    .bind(lease.global_fence_token)
    .bind(expected_after)
    .bind(route.workshop_id)
    .bind(route.generation)
    .bind(&route.projection_digest)
    .bind(route.disposition.as_str())
    .bind(route.action.as_str())
    .bind(route.route_fence_token)
    .bind(observation.outcome.as_str())
    .bind(&observation.evidence)
    .bind(rendered_digest)
    .bind(candidate_evidence)
    .fetch_one(&state.ledger)
    .await
    .map_err(DriverError::internal)?;
    transition(recorded, "startup publication candidate was fenced")
}

pub(super) async fn seal(
    state: &DriverState,
    lease: &StartupPublicationLease,
    seal: &StartupPublicationSeal,
) -> Result<(), DriverError> {
    let count = i32::try_from(seal.candidate_count)
        .map_err(|_| contract_error("startup publication candidate count is invalid"))?;
    validate_sha256(
        &seal.projection_set_digest,
        "startup publication set digest is invalid",
    )?;
    let sealed = sqlx::query_scalar::<_, bool>(
        "select control.seal_staged_startup_route_publication($1,$2,$3,$4,$5,$6,$7,$8)",
    )
    .bind(lease.effect_run_id)
    .bind(lease.instance_owner)
    .bind(lease.execution_token)
    .bind(lease.global_lease_token)
    .bind(lease.route_lease_token)
    .bind(lease.global_fence_token)
    .bind(count)
    .bind(&seal.projection_set_digest)
    .fetch_one(&state.ledger)
    .await
    .map_err(DriverError::internal)?;
    transition(sealed, "startup publication seal was fenced")
}

pub(super) async fn start_publication(
    state: &DriverState,
    lease: &StartupPublicationLease,
    projection_set_digest: &str,
) -> Result<(), DriverError> {
    validate_sha256(
        projection_set_digest,
        "startup publication set digest is invalid",
    )?;
    let started = sqlx::query_scalar::<_, bool>(
        "select control.start_staged_startup_route_publication($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(lease.effect_run_id)
    .bind(lease.instance_owner)
    .bind(lease.execution_token)
    .bind(lease.global_lease_token)
    .bind(lease.route_lease_token)
    .bind(lease.global_fence_token)
    .bind(projection_set_digest)
    .fetch_one(&state.ledger)
    .await
    .map_err(DriverError::internal)?;
    transition(started, "startup publication start was fenced")
}

pub(super) async fn observe(
    state: &DriverState,
    lease: &StartupPublicationLease,
    observation: &GatewayPublicationObservation,
) -> Result<(), DriverError> {
    validate_gateway_observation(observation)?;
    if observation.selector != lease.staging_selector
        || observation.effect_run_id != Some(lease.effect_run_id)
        || observation.projection_set_digest.is_none()
    {
        return Err(contract_error(
            "startup publication observation does not identify the candidate",
        ));
    }
    let observed = sqlx::query_scalar::<_, bool>(
        "select control.observe_staged_startup_route_publication($1,$2,$3,$4,$5,$6,$7,$8,$9)",
    )
    .bind(lease.effect_run_id)
    .bind(lease.instance_owner)
    .bind(lease.execution_token)
    .bind(lease.global_lease_token)
    .bind(lease.route_lease_token)
    .bind(lease.global_fence_token)
    .bind(&observation.selector)
    .bind(observation.effect_run_id)
    .bind(observation.projection_set_digest.as_deref())
    .fetch_one(&state.ledger)
    .await
    .map_err(DriverError::internal)?;
    transition(observed, "startup publication observation was fenced")
}

pub(super) async fn finish(
    state: &DriverState,
    lease: &StartupPublicationLease,
    seal: &StartupPublicationSeal,
    gateway_reload_digest: &str,
) -> Result<Value, DriverError> {
    validate_sha256(gateway_reload_digest, "gateway reload digest is invalid")?;
    if seal.candidate_count != lease.reserved_count {
        return Err(contract_error(
            "startup publication response count is invalid",
        ));
    }
    let response = completion_response(
        lease.effect_run_id,
        lease.global_fence_token,
        seal,
        gateway_reload_digest,
    )?;
    let finished = sqlx::query_scalar::<_, bool>(
        "select control.finish_staged_startup_route_publication($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(lease.effect_run_id)
    .bind(lease.instance_owner)
    .bind(lease.execution_token)
    .bind(lease.global_lease_token)
    .bind(lease.route_lease_token)
    .bind(lease.global_fence_token)
    .bind(&response)
    .fetch_one(&state.ledger)
    .await
    .map_err(DriverError::internal)?;
    transition(finished, "startup publication finalization was fenced")?;
    Ok(response)
}

pub(super) async fn abort(
    state: &DriverState,
    lease: &StartupPublicationLease,
    observed_prior: &GatewayPublicationObservation,
) -> Result<(), DriverError> {
    validate_gateway_observation(observed_prior)?;
    let aborted = sqlx::query_scalar::<_, bool>(
        "select control.abort_staged_startup_route_publication(
            $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
    )
    .bind(lease.effect_run_id)
    .bind(lease.instance_owner)
    .bind(lease.execution_token)
    .bind(lease.global_lease_token)
    .bind(lease.route_lease_token)
    .bind(lease.global_fence_token)
    .bind(&observed_prior.selector)
    .bind(pg_file_identity(observed_prior.directory_device)?)
    .bind(pg_file_identity(observed_prior.directory_inode)?)
    .bind(observed_prior.effect_run_id)
    .bind(observed_prior.projection_set_digest.as_deref())
    .fetch_one(&state.ledger)
    .await
    .map_err(DriverError::internal)?;
    transition(aborted, "startup publication abort was fenced")
}

#[tracing::instrument(
    name = "deployment_driver.startup_publication.claim_interrupted",
    skip_all,
    fields(driver.instance_id = %state.instance_id, reconciliation.outcome = tracing::field::Empty)
)]
pub(super) async fn claim_interrupted(
    state: &DriverState,
    ttl_seconds: i32,
) -> Result<InterruptedPublicationClaim, DriverError> {
    validate_ttl(ttl_seconds)?;
    let reconciliation_token = Uuid::new_v4();
    let rows = sqlx::query_as::<_, ClaimRow>(
        "select outcome,effect_run_id,interrupted_phase,original_instance_owner,
                original_global_fence_token,prior_selector,prior_directory_device,
                prior_directory_inode,staging_selector,
                prior_gateway_effect_run_id,prior_gateway_set_digest,sealed_count,
                sealed_present_count,projection_set_digest
           from control.claim_interrupted_startup_route_publication($1,$2,$3)",
    )
    .bind(state.instance_id)
    .bind(reconciliation_token)
    .bind(ttl_seconds)
    .fetch_all(&state.ledger)
    .await
    .map_err(DriverError::internal)?;
    let row = exactly_one(
        rows,
        "interrupted startup publication claim returned an invalid row count",
    )?;
    tracing::Span::current().record("reconciliation.outcome", row.outcome.as_str());
    parse_claim(row, state.instance_id, reconciliation_token)
}

#[tracing::instrument(
    name = "deployment_driver.startup_publication.finish_interrupted",
    skip_all,
    fields(publication.effect_run_id = %claim.effect_run_id, reconciliation.outcome = tracing::field::Empty)
)]
pub(super) async fn finish_interrupted(
    state: &DriverState,
    claim: &InterruptedStartupPublication,
    resolution: &InterruptedPublicationResolution,
) -> Result<(), DriverError> {
    let (outcome, observation, response) = interrupted_resolution(claim, resolution)?;
    tracing::Span::current().record("reconciliation.outcome", outcome);
    let finished = sqlx::query_scalar::<_, bool>(
        "select control.finish_interrupted_startup_route_publication(
            $1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
    )
    .bind(claim.effect_run_id)
    .bind(claim.reconciliation_owner)
    .bind(claim.reconciliation_token)
    .bind(outcome)
    .bind(observation.as_ref().map(|value| value.selector.as_str()))
    .bind(
        observation
            .as_ref()
            .map(|value| pg_file_identity(value.directory_device))
            .transpose()?,
    )
    .bind(
        observation
            .as_ref()
            .map(|value| pg_file_identity(value.directory_inode))
            .transpose()?,
    )
    .bind(observation.as_ref().and_then(|value| value.effect_run_id))
    .bind(
        observation
            .as_ref()
            .and_then(|value| value.projection_set_digest.as_deref()),
    )
    .bind(response)
    .fetch_one(&state.ledger)
    .await
    .map_err(DriverError::internal)?;
    transition(
        finished,
        "interrupted startup publication finalization was fenced",
    )
}

async fn lease_transition_query(
    function: &str,
    state: &DriverState,
    lease: &StartupPublicationLease,
) -> Result<bool, DriverError> {
    if function != "control.begin_staged_startup_route_publication" {
        return Err(contract_error("unsupported startup publication transition"));
    }
    sqlx::query_scalar::<_, bool>(
        "select control.begin_staged_startup_route_publication($1,$2,$3,$4,$5,$6)",
    )
    .bind(lease.effect_run_id)
    .bind(lease.instance_owner)
    .bind(lease.execution_token)
    .bind(lease.global_lease_token)
    .bind(lease.route_lease_token)
    .bind(lease.global_fence_token)
    .fetch_one(&state.ledger)
    .await
    .map_err(DriverError::internal)
}

fn parse_admission(
    row: AdmissionRow,
    instance_owner: Uuid,
    execution_token: Uuid,
    global_lease_token: Uuid,
    route_lease_token: Uuid,
) -> Result<StartupPublicationAdmission, DriverError> {
    match row.outcome.as_str() {
        "acquired" => {
            let effect_run_id = required(row.effect_run_id, "startup publication run is missing")?;
            let global_fence_token = positive(
                required(
                    row.global_fence_token,
                    "startup publication fence is missing",
                )?,
                "startup publication fence is invalid",
            )?;
            let reserved_count = nonnegative_count(row.reserved_count)?;
            let active_runtime = parse_active_runtime(&row)?;
            let staging_selector = required(
                row.staging_selector,
                "startup publication staging selector is missing",
            )?;
            validate_selector(&staging_selector)?;
            if staging_selector != format!("generations/startup-{effect_run_id}")
                || row.prior_selector.is_some()
                || row.stored_response.is_some()
            {
                return Err(contract_error(
                    "startup publication admission shape is invalid",
                ));
            }
            let fleet_release_unresolved = required(
                row.fleet_release_unresolved,
                "startup publication release state is missing",
            )?;
            Ok(StartupPublicationAdmission::Acquired(Box::new(
                StartupPublicationLease {
                    effect_run_id,
                    instance_owner,
                    execution_token,
                    global_lease_token,
                    route_lease_token,
                    global_fence_token,
                    reserved_count,
                    staging_selector,
                    active_runtime,
                    fleet_release_unresolved,
                },
            )))
        }
        "replay" => {
            let response = required(row.stored_response, "startup publication replay is missing")?;
            let effect_run_id = required(
                row.effect_run_id,
                "startup publication replay run is missing",
            )?;
            let fence = positive(
                required(
                    row.global_fence_token,
                    "startup publication replay fence is missing",
                )?,
                "startup publication replay fence is invalid",
            )?;
            let count = nonnegative_count(row.reserved_count)?;
            validate_completion_response(&response, effect_run_id, fence, count, None)?;
            Ok(StartupPublicationAdmission::Replay(response))
        }
        "busy" | "route_busy" => unavailable(row, StartupPublicationUnavailable::Busy),
        "quarantined" | "route_quarantined" => {
            unavailable(row, StartupPublicationUnavailable::Quarantined)
        }
        "digest_conflict" => unavailable(row, StartupPublicationUnavailable::DigestConflict),
        "initialization_required" => {
            unavailable(row, StartupPublicationUnavailable::InitializationRequired)
        }
        "runtime_ambiguous" => unavailable(row, StartupPublicationUnavailable::RuntimeAmbiguous),
        "runtime_identity_missing" => {
            unavailable(row, StartupPublicationUnavailable::RuntimeIdentityMissing)
        }
        "invalid" => unavailable(row, StartupPublicationUnavailable::Invalid),
        _ => Err(contract_error(
            "startup publication admission outcome is invalid",
        )),
    }
}

fn unavailable(
    row: AdmissionRow,
    reason: StartupPublicationUnavailable,
) -> Result<StartupPublicationAdmission, DriverError> {
    if row.stored_response.is_some()
        || matches!(reason, StartupPublicationUnavailable::Invalid)
            && !admission_payload_is_empty(&row)
    {
        return Err(contract_error(
            "unavailable startup publication returned an invalid shape",
        ));
    }
    if let Some(fence) = row.global_fence_token {
        positive(fence, "unavailable startup publication fence is invalid")?;
    }
    if let Some(count) = row.reserved_count {
        nonnegative_count(Some(count))?;
    }
    if let Some(selector) = row.staging_selector.as_deref() {
        validate_selector(selector)?;
        let effect_run_id = required(
            row.effect_run_id,
            "unavailable startup publication run is missing",
        )?;
        if selector != format!("generations/startup-{effect_run_id}")
            || row.fleet_release_unresolved.is_none()
        {
            return Err(contract_error(
                "unavailable startup publication identity is invalid",
            ));
        }
    }
    if let Some(prior) = row.prior_selector.as_deref() {
        validate_selector(prior)?;
    }
    parse_active_runtime(&row)?;
    Ok(StartupPublicationAdmission::Unavailable(reason))
}

fn admission_payload_is_empty(row: &AdmissionRow) -> bool {
    row.effect_run_id.is_none()
        && row.global_fence_token.is_none()
        && row.reserved_count.is_none()
        && row.staging_selector.is_none()
        && row.prior_selector.is_none()
        && row.active_runtime_slot.is_none()
        && row.active_runtime_release_id.is_none()
        && row.active_runtime_subject_digest.is_none()
        && row.active_runtime_deployment_ref.is_none()
        && row.active_runtime_config_digest.is_none()
        && row.active_runtime_slot_version.is_none()
        && row.fleet_release_unresolved.is_none()
        && row.stored_response.is_none()
}

fn parse_active_runtime(row: &AdmissionRow) -> Result<Option<ActiveRuntimeIdentity>, DriverError> {
    let all_absent = row.active_runtime_slot.is_none()
        && row.active_runtime_release_id.is_none()
        && row.active_runtime_subject_digest.is_none()
        && row.active_runtime_deployment_ref.is_none()
        && row.active_runtime_config_digest.is_none()
        && row.active_runtime_slot_version.is_none();
    if all_absent {
        return Ok(None);
    }
    let identity = ActiveRuntimeIdentity {
        slot: required(
            row.active_runtime_slot.clone(),
            "active runtime slot is missing",
        )?,
        release_id: nonempty(
            required(
                row.active_runtime_release_id.clone(),
                "active runtime release is missing",
            )?,
            "active runtime release is invalid",
        )?,
        subject_digest: required(
            row.active_runtime_subject_digest.clone(),
            "active runtime subject digest is missing",
        )?,
        deployment_ref: nonempty(
            required(
                row.active_runtime_deployment_ref.clone(),
                "active runtime deployment is missing",
            )?,
            "active runtime deployment is invalid",
        )?,
        config_digest: required(
            row.active_runtime_config_digest.clone(),
            "active runtime config digest is missing",
        )?,
        slot_version: positive(
            required(
                row.active_runtime_slot_version,
                "active runtime version is missing",
            )?,
            "active runtime version is invalid",
        )?,
    };
    if !matches!(identity.slot.as_str(), "blue" | "green") {
        return Err(contract_error("active runtime slot is invalid"));
    }
    validate_sha256(
        &identity.subject_digest,
        "active runtime subject digest is invalid",
    )?;
    validate_sha256(
        &identity.config_digest,
        "active runtime config digest is invalid",
    )?;
    Ok(Some(identity))
}

fn validate_route_rows(
    rows: Vec<RouteRow>,
    after: Option<Uuid>,
) -> Result<Vec<StagedStartupRoute>, DriverError> {
    let mut routes = Vec::with_capacity(rows.len());
    let mut previous = after;
    for row in rows {
        if previous.is_some_and(|cursor| row.workshop_id <= cursor) {
            return Err(contract_error(
                "startup publication batch is not strictly ordered",
            ));
        }
        let route = StagedStartupRoute {
            workshop_id: row.workshop_id,
            database_id: row.database_id,
            database_ref: row.database_ref,
            public_hostname: row.public_hostname,
            generation: row.generation,
            projection_digest: row.projection_digest,
            disposition: RouteDisposition::parse(&row.disposition)?,
            action: RouteAction::parse(&row.action)?,
            paperless_mode: PaperlessRouteMode::parse(&row.paperless_mode)?,
            paperless_hostname: row.paperless_hostname,
            paperless_service_id: row.paperless_service_id,
            paperless_service_health: row.paperless_service_health,
            paperless_service_base_url: row.paperless_service_base_url,
            paperless_service_desired_epoch: row.paperless_service_desired_epoch,
            paperless_service_applied_epoch: row.paperless_service_applied_epoch,
            paperless_runtime_spec: row.paperless_runtime_spec,
            unresolved_operation: row.unresolved_operation,
            route_fence_token: row.route_fence_token,
            projection: row.projection,
        };
        validate_route(&route)?;
        previous = Some(route.workshop_id);
        routes.push(route);
    }
    Ok(routes)
}

fn validate_route(route: &StagedStartupRoute) -> Result<(), DriverError> {
    positive(
        route.generation,
        "startup publication generation is invalid",
    )?;
    positive(
        route.route_fence_token,
        "startup publication route fence is invalid",
    )?;
    validate_sha256(
        &route.projection_digest,
        "startup projection digest is invalid",
    )?;
    let projection_disposition = match route.disposition {
        RouteDisposition::Present => ProjectionDisposition::Present,
        RouteDisposition::Absent => ProjectionDisposition::Absent,
    };
    let projection = RouteProjection::parse(
        &route.projection,
        &route.projection_digest,
        projection_disposition,
    )
    .map_err(|_| contract_error("startup projection payload does not match its digest"))?;
    match (route.disposition, route.action) {
        (RouteDisposition::Present, RouteAction::Render) => {
            if route.database_id.is_none()
                || route.database_ref.as_deref().is_none_or(str::is_empty)
                || route.public_hostname.as_deref().is_none_or(str::is_empty)
                || projection.database_id() != route.database_id
                || projection.database_ref() != route.database_ref.as_deref()
                || projection.public_hostname() != route.public_hostname.as_deref()
                || projection.paperless_mode() != route.paperless_mode
                || projection.paperless_hostname() != route.paperless_hostname.as_deref()
            {
                return Err(contract_error("present startup route shape is invalid"));
            }
            match route.paperless_mode {
                PaperlessRouteMode::Absent
                    if route.paperless_hostname.is_none() && frozen_paperless_is_absent(route) => {}
                PaperlessRouteMode::ReadOnly | PaperlessRouteMode::ReadWrite
                    if route
                        .paperless_hostname
                        .as_deref()
                        .is_some_and(|value| !value.is_empty()) =>
                {
                    validate_frozen_paperless(route)?;
                }
                _ => return Err(contract_error("startup Paperless route shape is invalid")),
            }
        }
        (RouteDisposition::Absent, RouteAction::RemoveAbsent) => {
            if route.database_id.is_some()
                || route.database_ref.is_some()
                || route.public_hostname.is_some()
                || route.paperless_mode != PaperlessRouteMode::Absent
                || route.paperless_hostname.is_some()
                || !frozen_paperless_is_absent(route)
                || projection.disposition() != ProjectionDisposition::Absent
            {
                return Err(contract_error("absent startup route shape is invalid"));
            }
        }
        _ => {
            return Err(contract_error(
                "startup publication route action is invalid",
            ));
        }
    }
    Ok(())
}

fn frozen_paperless_is_absent(route: &StagedStartupRoute) -> bool {
    route.paperless_service_id.is_none()
        && route.paperless_service_health.is_none()
        && route.paperless_service_base_url.is_none()
        && route.paperless_service_desired_epoch.is_none()
        && route.paperless_service_applied_epoch.is_none()
        && route.paperless_runtime_spec.is_none()
}

fn validate_frozen_paperless(route: &StagedStartupRoute) -> Result<(), DriverError> {
    required(
        route.paperless_service_id,
        "frozen Paperless service identity is missing",
    )?;
    if route.paperless_service_health.as_deref() != Some("ready") {
        return Err(contract_error("frozen Paperless service is not ready"));
    }
    let base_url = route
        .paperless_service_base_url
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| contract_error("frozen Paperless base URL is missing"))?;
    let parsed_url =
        Url::parse(base_url).map_err(|_| contract_error("frozen Paperless base URL is invalid"))?;
    if !matches!(parsed_url.scheme(), "http" | "https") || parsed_url.host_str().is_none() {
        return Err(contract_error("frozen Paperless base URL is invalid"));
    }
    let desired = required(
        route.paperless_service_desired_epoch,
        "frozen Paperless desired epoch is missing",
    )?;
    let applied = required(
        route.paperless_service_applied_epoch,
        "frozen Paperless applied epoch is missing",
    )?;
    if desired <= 0 || !(0..=desired).contains(&applied) {
        return Err(contract_error("frozen Paperless service epoch is invalid"));
    }
    let spec = route
        .paperless_runtime_spec
        .as_ref()
        .ok_or_else(|| contract_error("frozen Paperless runtime specification is missing"))?;
    if serde_json::to_vec(spec)
        .map_err(DriverError::internal)?
        .len()
        > 15_000
    {
        return Err(contract_error(
            "frozen Paperless runtime specification is too large",
        ));
    }
    let object = spec
        .as_object()
        .filter(|value| value.len() == 9)
        .ok_or_else(|| contract_error("frozen Paperless runtime specification is invalid"))?;
    for key in [
        "version",
        "image",
        "config_digest",
        "container_name",
        "database_ref",
        "database_role",
        "redis_identity",
        "public_hostname",
        "volumes",
    ] {
        if !object.contains_key(key) {
            return Err(contract_error(
                "frozen Paperless runtime specification is invalid",
            ));
        }
    }
    if object.get("version").and_then(Value::as_i64) != Some(1)
        || object
            .get("image")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        || object
            .get("container_name")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        || object.get("database_ref").and_then(Value::as_str) != route.database_ref.as_deref()
        || object
            .get("database_role")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        || object
            .get("redis_identity")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        || object.get("public_hostname").and_then(Value::as_str)
            != route.paperless_hostname.as_deref()
    {
        return Err(contract_error(
            "frozen Paperless runtime specification identity is invalid",
        ));
    }
    let config_digest = object
        .get("config_digest")
        .and_then(Value::as_str)
        .ok_or_else(|| contract_error("frozen Paperless runtime digest is missing"))?;
    if !is_lower_hex_64(config_digest) {
        return Err(contract_error("frozen Paperless runtime digest is invalid"));
    }
    let volumes = object
        .get("volumes")
        .and_then(Value::as_array)
        .filter(|values| {
            values.len() == 3
                && values
                    .iter()
                    .all(|value| value.as_str().is_some_and(|value| !value.is_empty()))
        })
        .ok_or_else(|| contract_error("frozen Paperless volume identity is invalid"))?;
    let mut unique_volumes = std::collections::BTreeSet::new();
    if !volumes
        .iter()
        .filter_map(Value::as_str)
        .all(|volume| unique_volumes.insert(volume))
    {
        return Err(contract_error(
            "frozen Paperless volume identity is invalid",
        ));
    }
    Ok(())
}

fn validate_runtime_observation(
    lease: &StartupPublicationLease,
    route: &StagedStartupRoute,
    observation: &StartupRuntimeObservation,
) -> Result<(), DriverError> {
    let object = observation
        .evidence
        .as_object()
        .filter(|value| value.len() == 9)
        .ok_or_else(|| contract_error("startup runtime evidence shape is invalid"))?;
    if serde_json::to_vec(&observation.evidence)
        .map_err(DriverError::internal)?
        .len()
        > 15_000
        || object.get("effect_run_id") != Some(&json!(lease.effect_run_id))
        || object.get("workshop_id") != Some(&json!(route.workshop_id))
        || object.get("database_id") != Some(&json!(route.database_id))
        || object.get("database_ref") != Some(&json!(route.database_ref))
        || object.get("unresolved_operation") != Some(&json!(route.unresolved_operation))
        || object.get("outcome").and_then(Value::as_str) != Some(observation.outcome.as_str())
        || object
            .get("verified_at")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
    {
        return Err(contract_error(
            "startup runtime evidence identity is invalid",
        ));
    }
    let (expected_odoo, expected_paperless) = match (route.disposition, observation.outcome) {
        (RouteDisposition::Present, RuntimeOutcome::Ready) => (
            expected_odoo_runtime(lease, route)?,
            expected_paperless_runtime(route)?,
        ),
        (RouteDisposition::Absent, RuntimeOutcome::Absent) => (Value::Null, Value::Null),
        _ => return Err(contract_error("startup runtime outcome is invalid")),
    };
    if object.get("odoo_runtime") != Some(&expected_odoo)
        || object.get("paperless_runtime") != Some(&expected_paperless)
    {
        return Err(contract_error(
            "startup runtime evidence does not match the frozen runtime identity",
        ));
    }
    Ok(())
}

fn expected_odoo_runtime(
    lease: &StartupPublicationLease,
    route: &StagedStartupRoute,
) -> Result<Value, DriverError> {
    if route.disposition != RouteDisposition::Present {
        return Ok(Value::Null);
    }
    let runtime = lease
        .active_runtime
        .as_ref()
        .ok_or_else(|| contract_error("frozen active Odoo runtime is missing"))?;
    Ok(json!({
        "slot": runtime.slot,
        "release_id": runtime.release_id,
        "subject_digest": runtime.subject_digest,
        "deployment_ref": runtime.deployment_ref,
        "config_digest": runtime.config_digest,
        "slot_version": runtime.slot_version,
    }))
}

fn expected_paperless_runtime(route: &StagedStartupRoute) -> Result<Value, DriverError> {
    if route.paperless_mode == PaperlessRouteMode::Absent {
        if !frozen_paperless_is_absent(route) {
            return Err(contract_error(
                "absent Paperless runtime has frozen service identity",
            ));
        }
        return Ok(Value::Null);
    }
    validate_frozen_paperless(route)?;
    let spec = route
        .paperless_runtime_spec
        .as_ref()
        .and_then(Value::as_object)
        .ok_or_else(|| contract_error("frozen Paperless runtime specification is missing"))?;
    Ok(json!({
        "service_id": route.paperless_service_id,
        "config_digest": spec.get("config_digest").and_then(Value::as_str),
    }))
}

fn runtime_evidence(
    lease: &StartupPublicationLease,
    route: &StagedStartupRoute,
    outcome: RuntimeOutcome,
    odoo_runtime: Value,
    paperless_runtime: Value,
    verified_at: String,
) -> Value {
    json!({
        "effect_run_id": lease.effect_run_id,
        "workshop_id": route.workshop_id,
        "database_id": route.database_id,
        "database_ref": route.database_ref,
        "unresolved_operation": route.unresolved_operation,
        "outcome": outcome.as_str(),
        "odoo_runtime": odoo_runtime,
        "paperless_runtime": paperless_runtime,
        "verified_at": verified_at,
    })
}

fn parse_claim(
    row: ClaimRow,
    reconciliation_owner: Uuid,
    reconciliation_token: Uuid,
) -> Result<InterruptedPublicationClaim, DriverError> {
    match row.outcome.as_str() {
        "none" => {
            if !claim_payload_is_empty(&row) {
                return Err(contract_error(
                    "empty startup publication claim has an invalid shape",
                ));
            }
            Ok(InterruptedPublicationClaim::None)
        }
        "invalid" if claim_payload_is_empty(&row) => Ok(InterruptedPublicationClaim::Invalid),
        "invalid" => Err(contract_error(
            "invalid startup publication claim has an invalid shape",
        )),
        "acquired" => {
            let effect_run_id =
                required(row.effect_run_id, "interrupted publication run is missing")?;
            let interrupted_phase = InterruptedPublicationPhase::parse(&required(
                row.interrupted_phase,
                "interrupted publication phase is missing",
            )?)?;
            let prior = parse_prior_observation(
                row.prior_selector,
                row.prior_directory_device,
                row.prior_directory_inode,
                row.prior_gateway_effect_run_id,
                row.prior_gateway_set_digest,
            )?;
            let staging_selector = required(
                row.staging_selector,
                "interrupted publication selector is missing",
            )?;
            validate_selector(&staging_selector)?;
            if staging_selector != format!("generations/startup-{effect_run_id}") {
                return Err(contract_error(
                    "interrupted publication selector is invalid",
                ));
            }
            let seal = parse_interrupted_seal(
                row.sealed_count,
                row.sealed_present_count,
                row.projection_set_digest,
            )?;
            let shape_is_valid = match interrupted_phase {
                InterruptedPublicationPhase::Staging => seal.is_none(),
                _ => seal.is_some() && prior.is_some(),
            };
            if !shape_is_valid {
                return Err(contract_error(
                    "interrupted publication seal shape is invalid",
                ));
            }
            Ok(InterruptedPublicationClaim::Acquired(Box::new(
                InterruptedStartupPublication {
                    effect_run_id,
                    reconciliation_owner,
                    reconciliation_token,
                    interrupted_phase,
                    original_instance_owner: required(
                        row.original_instance_owner,
                        "interrupted publication owner is missing",
                    )?,
                    original_global_fence_token: positive(
                        required(
                            row.original_global_fence_token,
                            "interrupted publication fence is missing",
                        )?,
                        "interrupted publication fence is invalid",
                    )?,
                    prior,
                    staging_selector,
                    seal,
                },
            )))
        }
        _ => Err(contract_error(
            "interrupted startup publication claim outcome is invalid",
        )),
    }
}

fn claim_payload_is_empty(row: &ClaimRow) -> bool {
    row.effect_run_id.is_none()
        && row.interrupted_phase.is_none()
        && row.original_instance_owner.is_none()
        && row.original_global_fence_token.is_none()
        && row.prior_selector.is_none()
        && row.prior_directory_device.is_none()
        && row.prior_directory_inode.is_none()
        && row.staging_selector.is_none()
        && row.prior_gateway_effect_run_id.is_none()
        && row.prior_gateway_set_digest.is_none()
        && row.sealed_count.is_none()
        && row.sealed_present_count.is_none()
        && row.projection_set_digest.is_none()
}

fn interrupted_resolution(
    claim: &InterruptedStartupPublication,
    resolution: &InterruptedPublicationResolution,
) -> Result<
    (
        &'static str,
        Option<GatewayPublicationObservation>,
        Option<Value>,
    ),
    DriverError,
> {
    match resolution {
        InterruptedPublicationResolution::Candidate {
            observation,
            gateway_reload_digest,
        } => {
            validate_gateway_observation(observation)?;
            validate_sha256(gateway_reload_digest, "gateway reload digest is invalid")?;
            let seal = claim
                .seal
                .as_ref()
                .ok_or_else(|| contract_error("interrupted candidate publication is not sealed"))?;
            if !matches!(
                claim.interrupted_phase,
                InterruptedPublicationPhase::PublicationStarted
                    | InterruptedPublicationPhase::Observed
            ) || observation.selector != claim.staging_selector
                || observation.effect_run_id != Some(claim.effect_run_id)
                || observation.projection_set_digest.as_deref()
                    != Some(seal.projection_set_digest.as_str())
            {
                return Err(contract_error(
                    "interrupted candidate observation is invalid",
                ));
            }
            let response = completion_response(
                claim.effect_run_id,
                claim.original_global_fence_token,
                &StartupPublicationSeal {
                    candidate_count: seal.candidate_count,
                    projection_set_digest: seal.projection_set_digest.clone(),
                },
                gateway_reload_digest,
            )?;
            Ok(("candidate", Some(observation.clone()), Some(response)))
        }
        InterruptedPublicationResolution::Prior { observation } => {
            validate_gateway_observation(observation)?;
            if claim.interrupted_phase == InterruptedPublicationPhase::Observed
                || claim.prior.as_ref() != Some(observation)
            {
                return Err(contract_error("interrupted prior observation is invalid"));
            }
            Ok(("prior", Some(observation.clone()), None))
        }
        InterruptedPublicationResolution::Unstarted => {
            if claim.interrupted_phase != InterruptedPublicationPhase::Staging
                || claim.prior.is_some()
                || claim.seal.is_some()
            {
                return Err(contract_error(
                    "interrupted startup publication was not provably unstarted",
                ));
            }
            Ok(("unstarted", None, None))
        }
        InterruptedPublicationResolution::Inconclusive => Ok(("inconclusive", None, None)),
    }
}

fn parse_prior_observation(
    selector: Option<String>,
    directory_device: Option<i64>,
    directory_inode: Option<i64>,
    effect_run_id: Option<Uuid>,
    digest: Option<String>,
) -> Result<Option<GatewayPublicationObservation>, DriverError> {
    let Some(selector) = selector else {
        if directory_device.is_some()
            || directory_inode.is_some()
            || effect_run_id.is_some()
            || digest.is_some()
        {
            return Err(contract_error("prior gateway observation is incomplete"));
        }
        return Ok(None);
    };
    let observation = GatewayPublicationObservation {
        selector,
        directory_device: positive_file_identity(required(
            directory_device,
            "prior selector device is missing",
        )?)?,
        directory_inode: positive_file_identity(required(
            directory_inode,
            "prior selector inode is missing",
        )?)?,
        effect_run_id,
        projection_set_digest: digest,
    };
    validate_gateway_observation(&observation)?;
    Ok(Some(observation))
}

fn parse_interrupted_seal(
    count: Option<i32>,
    present_count: Option<i32>,
    digest: Option<String>,
) -> Result<Option<InterruptedPublicationSeal>, DriverError> {
    match (count, present_count, digest) {
        (None, None, None) => Ok(None),
        (Some(count), Some(present_count), Some(digest)) => {
            validate_sha256(&digest, "interrupted publication set digest is invalid")?;
            let candidate_count = nonnegative_count(Some(count))?;
            let present_count = nonnegative_count(Some(present_count))?;
            if present_count > candidate_count {
                return Err(contract_error(
                    "interrupted publication present count is invalid",
                ));
            }
            Ok(Some(InterruptedPublicationSeal {
                candidate_count,
                present_count,
                projection_set_digest: digest,
            }))
        }
        _ => Err(contract_error("interrupted publication seal is incomplete")),
    }
}

fn completion_response(
    effect_run_id: Uuid,
    global_fence_token: i64,
    seal: &StartupPublicationSeal,
    gateway_reload_digest: &str,
) -> Result<Value, DriverError> {
    validate_sha256(
        &seal.projection_set_digest,
        "startup publication set digest is invalid",
    )?;
    validate_sha256(gateway_reload_digest, "gateway reload digest is invalid")?;
    Ok(json!({
        "effect_run_id": effect_run_id,
        "global_fence_token": global_fence_token,
        "workshop_count": seal.candidate_count,
        "projection_set_digest": seal.projection_set_digest,
        "gateway_reload_digest": gateway_reload_digest,
    }))
}

fn validate_completion_response(
    response: &Value,
    effect_run_id: Uuid,
    global_fence_token: i64,
    candidate_count: usize,
    expected_set_digest: Option<&str>,
) -> Result<(), DriverError> {
    let object = response
        .as_object()
        .filter(|value| value.len() == 5)
        .ok_or_else(|| contract_error("startup publication response shape is invalid"))?;
    let set_digest = object
        .get("projection_set_digest")
        .and_then(Value::as_str)
        .ok_or_else(|| contract_error("startup publication response digest is missing"))?;
    let reload_digest = object
        .get("gateway_reload_digest")
        .and_then(Value::as_str)
        .ok_or_else(|| contract_error("gateway reload response digest is missing"))?;
    validate_sha256(set_digest, "startup publication response digest is invalid")?;
    validate_sha256(reload_digest, "gateway reload response digest is invalid")?;
    if object.get("effect_run_id") != Some(&json!(effect_run_id))
        || object.get("global_fence_token") != Some(&json!(global_fence_token))
        || object.get("workshop_count") != Some(&json!(candidate_count))
        || expected_set_digest.is_some_and(|expected| set_digest != expected)
    {
        return Err(contract_error(
            "startup publication response identity is invalid",
        ));
    }
    Ok(())
}

fn validate_gateway_observation(
    observation: &GatewayPublicationObservation,
) -> Result<(), DriverError> {
    validate_selector(&observation.selector)?;
    pg_file_identity(observation.directory_device)?;
    pg_file_identity(observation.directory_inode)?;
    if observation.effect_run_id.is_some() != observation.projection_set_digest.is_some() {
        return Err(contract_error("gateway publication identity is incomplete"));
    }
    if let Some(digest) = observation.projection_set_digest.as_deref() {
        validate_sha256(digest, "gateway publication digest is invalid")?;
    }
    Ok(())
}

fn validate_admission_request(
    request: StartupPublicationAdmissionRequest<'_>,
) -> Result<(), DriverError> {
    if request.idempotency_key.trim().is_empty() || request.idempotency_key.len() > 180 {
        return Err(contract_error(
            "startup publication idempotency key is invalid",
        ));
    }
    validate_unprefixed_sha256(request.request_digest)?;
    validate_ttl(request.ttl_seconds)
}

fn validate_ttl(ttl_seconds: i32) -> Result<(), DriverError> {
    if !(60..=1200).contains(&ttl_seconds) {
        return Err(contract_error("startup publication lease TTL is invalid"));
    }
    Ok(())
}

fn validate_batch_limit(limit: usize) -> Result<i32, DriverError> {
    if !(1..=STARTUP_PUBLICATION_MAX_BATCH).contains(&limit) {
        return Err(contract_error("startup publication batch limit is invalid"));
    }
    i32::try_from(limit).map_err(|_| contract_error("startup publication batch limit is invalid"))
}

fn validate_selector(value: &str) -> Result<(), DriverError> {
    let Some(name) = value.strip_prefix("generations/") else {
        return Err(contract_error("startup publication selector is invalid"));
    };
    if name.is_empty()
        || name.len() > 64
        || !name.as_bytes()[0].is_ascii_alphanumeric()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(contract_error("startup publication selector is invalid"));
    }
    Ok(())
}

fn validate_sha256(value: &str, message: &'static str) -> Result<(), DriverError> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(contract_error(message));
    };
    if !is_lower_hex_64(hex) {
        return Err(contract_error(message));
    }
    Ok(())
}

fn validate_unprefixed_sha256(value: &str) -> Result<(), DriverError> {
    if !is_lower_hex_64(value) {
        return Err(contract_error(
            "startup publication request digest is invalid",
        ));
    }
    Ok(())
}

fn is_lower_hex_64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn transition(changed: bool, message: &'static str) -> Result<(), DriverError> {
    if !changed {
        return Err(contract_error(message));
    }
    Ok(())
}

fn exactly_one<T>(mut rows: Vec<T>, message: &'static str) -> Result<T, DriverError> {
    if rows.len() != 1 {
        return Err(contract_error(message));
    }
    Ok(rows.remove(0))
}

fn required<T>(value: Option<T>, message: &'static str) -> Result<T, DriverError> {
    value.ok_or_else(|| contract_error(message))
}

fn positive(value: i64, message: &'static str) -> Result<i64, DriverError> {
    if value <= 0 {
        return Err(contract_error(message));
    }
    Ok(value)
}

fn positive_file_identity(value: i64) -> Result<u64, DriverError> {
    if value <= 0 {
        return Err(contract_error(
            "startup selector filesystem identity is invalid",
        ));
    }
    u64::try_from(value)
        .map_err(|_| contract_error("startup selector filesystem identity is invalid"))
}

fn pg_file_identity(value: u64) -> Result<i64, DriverError> {
    let value = i64::try_from(value)
        .map_err(|_| contract_error("startup selector filesystem identity is invalid"))?;
    if value <= 0 {
        return Err(contract_error(
            "startup selector filesystem identity is invalid",
        ));
    }
    Ok(value)
}

fn nonnegative_count(value: Option<i32>) -> Result<usize, DriverError> {
    let value = required(value, "startup publication count is missing")?;
    usize::try_from(value).map_err(|_| contract_error("startup publication count is invalid"))
}

fn nonempty(value: String, message: &'static str) -> Result<String, DriverError> {
    if value.trim().is_empty() {
        return Err(contract_error(message));
    }
    Ok(value)
}

fn contract_error(message: &'static str) -> DriverError {
    DriverError::internal(message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(marker: char) -> String {
        format!("sha256:{}", marker.to_string().repeat(64))
    }

    fn present_route() -> StagedStartupRoute {
        let database_id = Uuid::new_v4();
        let database_ref = crate::domain::opaque_database_ref(database_id);
        let projection = json!({
            "database_id": database_id,
            "database_ref": database_ref,
            "public_hostname": "tenant.example.test",
            "paperless_mode": "read_only",
            "paperless_hostname": "documents.example.test",
            "custom_hostnames": [],
        });
        let projection_digest = format!(
            "sha256:{:x}",
            Sha256::digest(serde_jcs::to_vec(&projection).unwrap())
        );
        StagedStartupRoute {
            workshop_id: Uuid::new_v4(),
            database_id: Some(database_id),
            database_ref: Some(database_ref.clone()),
            public_hostname: Some("tenant.example.test".into()),
            generation: 3,
            projection_digest,
            disposition: RouteDisposition::Present,
            action: RouteAction::Render,
            paperless_mode: PaperlessRouteMode::ReadOnly,
            paperless_hostname: Some("documents.example.test".into()),
            paperless_service_id: Some(Uuid::new_v4()),
            paperless_service_health: Some("ready".into()),
            paperless_service_base_url: Some("http://paperless.internal".into()),
            paperless_service_desired_epoch: Some(4),
            paperless_service_applied_epoch: Some(4),
            paperless_runtime_spec: Some(json!({
                "version": 1,
                "image": "paperless@sha256:test",
                "config_digest": "c".repeat(64),
                "container_name": "mb-paperless-test",
                "database_ref": database_ref,
                "database_role": "mb_paperless_test",
                "redis_identity": "paperless-test",
                "public_hostname": "documents.example.test",
                "volumes": ["paperless-data", "paperless-media", "paperless-consume"],
            })),
            unresolved_operation: false,
            route_fence_token: 8,
            projection,
        }
    }

    fn lease() -> StartupPublicationLease {
        StartupPublicationLease {
            effect_run_id: Uuid::new_v4(),
            instance_owner: Uuid::new_v4(),
            execution_token: Uuid::new_v4(),
            global_lease_token: Uuid::new_v4(),
            route_lease_token: Uuid::new_v4(),
            global_fence_token: 9,
            reserved_count: 1,
            staging_selector: format!("generations/startup-{}", Uuid::new_v4()),
            active_runtime: Some(ActiveRuntimeIdentity {
                slot: "blue".into(),
                release_id: "release-1".into(),
                subject_digest: digest('a'),
                deployment_ref: "deployment-1".into(),
                config_digest: digest('b'),
                slot_version: 2,
            }),
            fleet_release_unresolved: false,
        }
    }

    #[test]
    fn selectors_are_single_safe_generation_children() {
        assert!(
            validate_selector("generations/startup-00000000-0000-0000-0000-000000000000").is_ok()
        );
        for value in [
            "current",
            "generations/../current",
            "generations/nested/child",
            "generations/-bad",
            "generations/bad.name",
        ] {
            assert!(validate_selector(value).is_err(), "accepted {value}");
        }
    }

    #[test]
    fn batch_limit_is_bounded_by_protocol() {
        assert!(validate_batch_limit(1).is_ok());
        assert!(validate_batch_limit(500).is_ok());
        assert!(validate_batch_limit(0).is_err());
        assert!(validate_batch_limit(501).is_err());
    }

    #[test]
    fn gateway_identity_is_an_all_or_none_pair() {
        let observation = GatewayPublicationObservation {
            selector: "generations/prior".into(),
            directory_device: 1,
            directory_inode: 2,
            effect_run_id: Some(Uuid::nil()),
            projection_set_digest: None,
        };
        assert!(validate_gateway_observation(&observation).is_err());
    }

    #[test]
    fn completion_response_has_the_exact_database_shape() {
        let effect_run_id = Uuid::new_v4();
        let seal = StartupPublicationSeal {
            candidate_count: 7,
            projection_set_digest: digest('a'),
        };
        let response = completion_response(effect_run_id, 9, &seal, &digest('b')).unwrap();
        validate_completion_response(
            &response,
            effect_run_id,
            9,
            7,
            Some(&seal.projection_set_digest),
        )
        .unwrap();
        assert_eq!(response.as_object().unwrap().len(), 5);
    }

    #[test]
    fn admission_request_uses_legacy_unprefixed_digest() {
        assert!(validate_unprefixed_sha256(&"a".repeat(64)).is_ok());
        assert!(validate_unprefixed_sha256(&digest('a')).is_err());
        assert!(validate_unprefixed_sha256(&"A".repeat(64)).is_err());
    }

    #[test]
    fn ready_evidence_is_derived_from_both_frozen_runtime_identities() {
        let lease = lease();
        let route = present_route();
        validate_route(&route).unwrap();
        let observation =
            StartupRuntimeObservation::ready(&lease, &route, "2026-08-22T12:00:00Z".into())
                .unwrap();
        assert_eq!(
            observation.evidence.pointer("/odoo_runtime/release_id"),
            Some(&json!("release-1"))
        );
        assert_eq!(
            observation
                .evidence
                .pointer("/paperless_runtime/service_id"),
            Some(&json!(route.paperless_service_id))
        );
        assert_eq!(
            observation
                .evidence
                .pointer("/paperless_runtime/config_digest"),
            Some(&json!("c".repeat(64)))
        );
    }

    #[test]
    fn runtime_evidence_rejects_identity_drift() {
        let lease = lease();
        let route = present_route();
        let mut observation =
            StartupRuntimeObservation::ready(&lease, &route, "2026-08-22T12:00:00Z".into())
                .unwrap();
        observation.evidence["paperless_runtime"]["config_digest"] = json!("d".repeat(64));
        assert!(validate_runtime_observation(&lease, &route, &observation).is_err());
    }

    #[test]
    fn interrupted_seal_bounds_present_routes_by_total_routes() {
        let seal = parse_interrupted_seal(Some(5), Some(3), Some(digest('e')))
            .unwrap()
            .unwrap();
        assert_eq!(seal.candidate_count, 5);
        assert_eq!(seal.present_count, 3);
        assert!(parse_interrupted_seal(Some(2), Some(3), Some(digest('e'))).is_err());
        assert!(parse_interrupted_seal(Some(2), None, Some(digest('e'))).is_err());
    }

    #[test]
    fn unstarted_resolution_requires_a_pristine_staging_claim() {
        let mut claim = InterruptedStartupPublication {
            effect_run_id: Uuid::new_v4(),
            reconciliation_owner: Uuid::new_v4(),
            reconciliation_token: Uuid::new_v4(),
            interrupted_phase: InterruptedPublicationPhase::Staging,
            original_instance_owner: Uuid::new_v4(),
            original_global_fence_token: 4,
            prior: None,
            staging_selector: format!("generations/startup-{}", Uuid::new_v4()),
            seal: None,
        };
        let resolution =
            interrupted_resolution(&claim, &InterruptedPublicationResolution::Unstarted).unwrap();
        assert_eq!(resolution, ("unstarted", None, None));

        claim.prior = Some(GatewayPublicationObservation {
            selector: "generations/prior".into(),
            directory_device: 1,
            directory_inode: 2,
            effect_run_id: None,
            projection_set_digest: None,
        });
        assert!(
            interrupted_resolution(&claim, &InterruptedPublicationResolution::Unstarted).is_err()
        );
    }

    #[test]
    fn prior_resolution_rejects_an_observed_candidate() {
        let observation = GatewayPublicationObservation {
            selector: "generations/prior".into(),
            directory_device: 1,
            directory_inode: 2,
            effect_run_id: None,
            projection_set_digest: None,
        };
        let claim = InterruptedStartupPublication {
            effect_run_id: Uuid::new_v4(),
            reconciliation_owner: Uuid::new_v4(),
            reconciliation_token: Uuid::new_v4(),
            interrupted_phase: InterruptedPublicationPhase::Observed,
            original_instance_owner: Uuid::new_v4(),
            original_global_fence_token: 4,
            prior: Some(observation.clone()),
            staging_selector: format!("generations/startup-{}", Uuid::new_v4()),
            seal: Some(InterruptedPublicationSeal {
                candidate_count: 1,
                present_count: 1,
                projection_set_digest: digest('f'),
            }),
        };
        assert!(
            interrupted_resolution(
                &claim,
                &InterruptedPublicationResolution::Prior { observation },
            )
            .is_err()
        );
    }
}
