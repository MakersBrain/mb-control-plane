//! Dormant typed database boundary for immutable fleet-release route overlays.
//!
//! Migrations 0025/0026 own authority and transitions. Merely registering this
//! adapter performs no I/O and it intentionally has no active release callsite.
#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

use super::gateway::{ReleaseOverlayGenerationIdentity, ReleaseOverlayKind, ReleaseTargetSlot};
use super::release_generation_fs::{
    ReleaseGenerationName, ReleaseRouteSealEvidence, SealedReleaseGeneration,
};
use super::route_generation_fs::PriorSelector;
use super::route_projection::{RouteDisposition, RouteProjection};
use super::route_set_generation_fs::RouteSetGenerationName;
use super::route_set_publication_db::RouteSetPriorLoadedIdentity;
use super::{ControlOperationLease, DriverError};

const MIN_TTL: i32 = 60;
const MAX_TTL: i32 = 1_200;
const MAX_ROUTES: usize = 500;
const MAX_RESPONSE_BYTES: usize = 1_048_576;

type DriverAdmissionRow = (
    String,
    Option<Uuid>,
    Option<i64>,
    Option<Value>,
    Option<Vec<Uuid>>,
);
type PublicationAdmissionRow = (
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<Vec<Uuid>>,
);
pub(super) type ReleaseSnapshotRow = (
    Uuid,
    Uuid,
    String,
    bool,
    i64,
    String,
    Value,
    String,
    i64,
    i64,
    String,
);

#[derive(Clone)]
pub(super) struct ReleaseRouteDriverAdmissionRequest {
    pub control_operation: ControlOperationLease,
    pub idempotency_key: String,
    pub fleet_run_id: Uuid,
    pub request_digest: String,
    pub instance_owner: Uuid,
    pub execution_token: Uuid,
    pub global_lease_token: Uuid,
    pub ttl_seconds: i32,
}

impl ReleaseRouteDriverAdmissionRequest {
    fn validate(&self) -> Result<(), DriverError> {
        if self.control_operation.id.is_nil()
            || self.control_operation.attempt <= 0
            || self.control_operation.owner.trim().is_empty()
            || self.idempotency_key.trim().is_empty()
            || self.idempotency_key.len() > 200
            || self.fleet_run_id.is_nil()
            || !bare_digest(&self.request_digest)
            || self.instance_owner.is_nil()
            || self.execution_token.is_nil()
            || self.global_lease_token.is_nil()
            || !(MIN_TTL..=MAX_TTL).contains(&self.ttl_seconds)
        {
            return Err(invalid("release route driver request is invalid"));
        }
        Ok(())
    }
}

#[derive(Clone)]
pub(super) struct ReleaseRouteDriverLease {
    pub driver_operation_id: Uuid,
    pub fleet_run_id: Uuid,
    pub control_operation: ControlOperationLease,
    pub instance_owner: Uuid,
    pub execution_token: Uuid,
    pub global_lease_token: Uuid,
    pub global_fence_token: i64,
    pub reserved_workshops: Vec<Uuid>,
    pub ttl_seconds: i32,
}

impl ReleaseRouteDriverLease {
    fn validate(&self) -> Result<(), DriverError> {
        if self.driver_operation_id.is_nil()
            || self.fleet_run_id.is_nil()
            || self.control_operation.id.is_nil()
            || self.control_operation.attempt <= 0
            || self.control_operation.owner.trim().is_empty()
            || self.instance_owner.is_nil()
            || self.execution_token.is_nil()
            || self.global_lease_token.is_nil()
            || self.global_fence_token <= 0
            || !(1..=MAX_ROUTES).contains(&self.reserved_workshops.len())
            || !ordered_uuids(&self.reserved_workshops)
            || !(MIN_TTL..=MAX_TTL).contains(&self.ttl_seconds)
        {
            return Err(invalid("release route driver lease is invalid"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ReleaseRouteDriverRefusal {
    Invalid,
    InvalidFleet,
    UpstreamLeaseLost,
    ProtocolConflict,
    DigestConflict,
    Failed,
    Busy,
    Quarantined,
    RouteBusy,
    RouteUninitialized,
    FleetNotEmpty,
}

pub(super) enum ReleaseRouteDriverAdmission {
    Acquired(ReleaseRouteDriverLease),
    Replay(Value),
    Refused(ReleaseRouteDriverRefusal),
}

#[derive(Clone)]
pub(super) struct ReleaseRoutePublicationAdmissionRequest {
    pub driver: ReleaseRouteDriverLease,
    pub route_lease_token: Uuid,
}

#[derive(Clone)]
pub(super) struct ReleaseRoutePublicationLease {
    pub driver_operation_id: Uuid,
    pub fleet_run_id: Uuid,
    pub control_operation: ControlOperationLease,
    pub instance_owner: Uuid,
    pub execution_token: Uuid,
    pub global_lease_token: Uuid,
    pub route_lease_token: Uuid,
    pub global_fence_token: i64,
    pub target_slot: ReleaseTargetSlot,
    pub maintenance_selector: String,
    pub candidate_selector: String,
    pub reserved_workshops: Vec<Uuid>,
    pub ttl_seconds: i32,
}

impl ReleaseRoutePublicationLease {
    fn validate(&self) -> Result<(), DriverError> {
        ReleaseRouteDriverLease {
            driver_operation_id: self.driver_operation_id,
            fleet_run_id: self.fleet_run_id,
            control_operation: self.control_operation.clone(),
            instance_owner: self.instance_owner,
            execution_token: self.execution_token,
            global_lease_token: self.global_lease_token,
            global_fence_token: self.global_fence_token,
            reserved_workshops: self.reserved_workshops.clone(),
            ttl_seconds: self.ttl_seconds,
        }
        .validate()?;
        let maintenance =
            ReleaseGenerationName::new(self.fleet_run_id, ReleaseOverlayKind::Maintenance)
                .selector_target();
        let candidate =
            ReleaseGenerationName::new(self.fleet_run_id, ReleaseOverlayKind::Candidate)
                .selector_target();
        if self.route_lease_token.is_nil()
            || self.maintenance_selector != maintenance
            || self.candidate_selector != candidate
        {
            return Err(invalid("release route publication lease is invalid"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ReleaseRoutePublicationRefusal {
    Invalid,
    NotFound,
    AuthorityLost,
    Conflict,
    RouteDrift,
    Quarantined,
}

pub(super) enum ReleaseRoutePublicationAdmission {
    Acquired(ReleaseRoutePublicationLease),
    Replay(ReleaseRoutePublicationLease),
    Refused(ReleaseRoutePublicationRefusal),
}

#[derive(Clone, Debug, PartialEq)]
pub(super) struct ReleaseRouteSnapshotItem {
    pub workshop_id: Uuid,
    pub database_id: Uuid,
    pub database_ref: String,
    pub paperless_enabled: bool,
    pub generation: i64,
    pub projection_digest: String,
    pub canonical_projection: Value,
    pub applied_rendered_digest: String,
    pub applied_fence_token: i64,
    pub route_fence_token: i64,
    pub target_slot: ReleaseTargetSlot,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ReleaseRouteTransitionOutcome {
    Recorded,
    Sealed,
    Started,
    Observed,
    Replay,
    AuthorityLost,
    NotFound,
    Conflict,
    WrongPhase,
    Invalid,
    PriorAbsent,
    OutOfOrder,
    SnapshotDrift,
    CountMismatch,
    DigestMismatch,
    IdentityMismatch,
    ObservationMismatch,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(super) struct ReleaseRouteCompletionResponse {
    pub evidence: ReleaseRouteCompletionEvidence,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(super) struct ReleaseRouteCompletionEvidence {
    pub release_id: String,
    pub odoo_subject_digest: String,
    pub extension_subject_digest: String,
    pub odoo_manifest_digest: String,
    pub odoo_config_digest: String,
    pub extension_manifest_digest: String,
    pub extension_config_digest: String,
    pub payload_digest: String,
    pub extension_volume: String,
    pub pair_qualification_digest: String,
    pub bridge_contract_digest: String,
    pub installed_addon_versions: Value,
    pub runtime_key: String,
    pub target_slot: String,
    pub runtime_container: String,
    pub runtime_role: String,
    pub runtime_deployment_ref: String,
    pub runtime_config_digest: String,
    pub prepared_tenants: Value,
    pub fleet_generation: i64,
    pub tenant_snapshot: Value,
    pub gateway_configuration_digest: String,
    pub driver_action_id: Uuid,
    pub driver_operation_id: Uuid,
    pub driver_fence_token: i64,
    pub old_runtime_database_access_revoked: bool,
    pub tenant_recovery_verified: bool,
    pub candidate_smoke_verified: bool,
    pub candidate_restart_policy: String,
    pub retained_restart_policy: String,
}

pub(super) enum FinishReleaseRoutePublication {
    Finished(ReleaseRouteCompletionResponse),
    Replay(ReleaseRouteCompletionResponse),
    AuthorityLost,
    NotFound,
    StateDrift,
    WrongPhase,
    Invalid,
    Conflict(Option<ReleaseRouteCompletionResponse>),
}

pub(super) enum ReadReleaseRoutePublicationResult {
    NotFound,
    Conflict,
    Pending,
    Quarantined,
    Replay(Box<ReleaseRouteCompletionResponse>),
}

#[tracing::instrument(name="deployment_driver.release_route.driver_admit_dormant", skip_all,
    fields(release.fleet_run_id=%request.fleet_run_id, admission.outcome=tracing::field::Empty))]
pub(super) async fn admit_release_route_driver_operation(
    ledger: &PgPool,
    request: &ReleaseRouteDriverAdmissionRequest,
) -> Result<ReleaseRouteDriverAdmission, DriverError> {
    request.validate()?;
    let row = sqlx::query_as::<_, DriverAdmissionRow>(
        "select outcome,driver_operation_id,fence_token,stored_response,reserved_workshops
         from control.admit_release_driver_operation($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
    )
    .bind(request.control_operation.id)
    .bind(request.control_operation.attempt)
    .bind(&request.control_operation.owner)
    .bind(&request.idempotency_key)
    .bind(format!("fleet/{}", request.fleet_run_id))
    .bind(request.fleet_run_id)
    .bind(&request.request_digest)
    .bind(request.instance_owner)
    .bind(request.execution_token)
    .bind(request.global_lease_token)
    .bind(request.ttl_seconds)
    .bind(1_i16)
    .bind(2_i16)
    .fetch_one(ledger)
    .await
    .map_err(DriverError::internal)?;
    tracing::Span::current().record("admission.outcome", row.0.as_str());
    parse_driver_admission(request, row)
}

#[tracing::instrument(name="deployment_driver.release_route.publication_admit_dormant", skip_all,
    fields(release.driver_operation_id=%request.driver.driver_operation_id, admission.outcome=tracing::field::Empty))]
pub(super) async fn admit_release_route_publication(
    ledger: &PgPool,
    request: &ReleaseRoutePublicationAdmissionRequest,
) -> Result<ReleaseRoutePublicationAdmission, DriverError> {
    request.driver.validate()?;
    if request.route_lease_token.is_nil() {
        return Err(invalid("release route token is invalid"));
    }
    let row = sqlx::query_as::<_, PublicationAdmissionRow>(
        "select outcome,target_slot,maintenance_selector,candidate_selector,reserved_workshops
         from control.admit_immutable_release_route_publication($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(request.driver.driver_operation_id)
    .bind(request.driver.instance_owner)
    .bind(request.driver.execution_token)
    .bind(request.driver.global_lease_token)
    .bind(request.route_lease_token)
    .bind(request.driver.global_fence_token)
    .bind(request.driver.ttl_seconds)
    .fetch_one(ledger)
    .await
    .map_err(DriverError::internal)?;
    tracing::Span::current().record("admission.outcome", row.0.as_str());
    parse_publication_admission(request, row)
}

pub(super) async fn renew_release_route_publication(
    ledger: &PgPool,
    lease: &ReleaseRoutePublicationLease,
) -> Result<bool, DriverError> {
    lease.validate()?;
    sqlx::query_scalar::<_, bool>(
        "select control.renew_immutable_release_route_publication($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(lease.driver_operation_id)
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

pub(super) async fn record_release_route_prior(
    ledger: &PgPool,
    lease: &ReleaseRoutePublicationLease,
    prior: &PriorSelector,
    loaded: Option<&RouteSetPriorLoadedIdentity>,
) -> Result<ReleaseRouteTransitionOutcome, DriverError> {
    lease.validate()?;
    let identity = validate_prior(prior, loaded)?;
    let outcome = sqlx::query_scalar::<_, String>(
        "select control.record_immutable_release_route_prior($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
    )
    .bind(lease.driver_operation_id)
    .bind(lease.instance_owner)
    .bind(lease.execution_token)
    .bind(lease.global_lease_token)
    .bind(lease.route_lease_token)
    .bind(lease.global_fence_token)
    .bind(prior.target())
    .bind(pg_identity(prior.directory_device())?)
    .bind(pg_identity(prior.directory_inode())?)
    .bind(identity)
    .fetch_one(ledger)
    .await
    .map_err(DriverError::internal)?;
    transition(&outcome)
}

pub(super) async fn read_release_route_snapshot_batch(
    ledger: &PgPool,
    lease: &ReleaseRoutePublicationLease,
    after: Option<Uuid>,
    limit: usize,
) -> Result<Vec<ReleaseRouteSnapshotItem>, DriverError> {
    lease.validate()?;
    if limit == 0 || limit > MAX_ROUTES || after.is_some_and(|id| id.is_nil()) {
        return Err(invalid("release route snapshot request is invalid"));
    }
    let rows = sqlx::query_as::<_, ReleaseSnapshotRow>(
        "select workshop_id,database_id,database_ref,paperless_enabled,generation,projection_digest,
         canonical_projection,applied_rendered_digest,applied_fence_token,route_fence_token,target_slot
         from control.read_immutable_release_route_snapshot_batch($1,$2,$3,$4,$5,$6,$7,$8)")
        .bind(lease.driver_operation_id).bind(lease.instance_owner).bind(lease.execution_token)
        .bind(lease.global_lease_token).bind(lease.route_lease_token).bind(lease.global_fence_token)
        .bind(after).bind(i32::try_from(limit).map_err(|_| invalid("release route limit is invalid"))?)
        .fetch_all(ledger).await.map_err(DriverError::internal)?;
    validate_release_snapshot_rows(
        lease.target_slot,
        Some(&lease.reserved_workshops),
        after,
        limit,
        rows,
    )
}

pub(super) async fn record_release_route_overlay_entry(
    ledger: &PgPool,
    lease: &ReleaseRoutePublicationLease,
    kind: ReleaseOverlayKind,
    evidence: &ReleaseRouteSealEvidence,
) -> Result<ReleaseRouteTransitionOutcome, DriverError> {
    lease.validate()?;
    validate_evidence(lease, evidence)?;
    let outcome = sqlx::query_scalar::<_, String>(
        "select control.record_immutable_release_route_candidate($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)")
        .bind(lease.driver_operation_id).bind(lease.instance_owner).bind(lease.execution_token)
        .bind(lease.global_lease_token).bind(lease.route_lease_token).bind(lease.global_fence_token)
        .bind(kind.as_str()).bind(evidence.workshop_id).bind(evidence.projection_generation)
        .bind(&evidence.projection_digest).bind(&evidence.applied_rendered_digest).bind(&evidence.rendered_digest)
        .fetch_one(ledger).await.map_err(DriverError::internal)?;
    transition(&outcome)
}

pub(super) async fn seal_release_route_overlay(
    ledger: &PgPool,
    lease: &ReleaseRoutePublicationLease,
    kind: ReleaseOverlayKind,
    sealed: &SealedReleaseGeneration,
) -> Result<ReleaseRouteTransitionOutcome, DriverError> {
    lease.validate()?;
    validate_sealed(lease, kind, sealed)?;
    let outcome = sqlx::query_scalar::<_, String>(
        "select control.seal_immutable_release_route_overlay($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)")
        .bind(lease.driver_operation_id).bind(lease.instance_owner).bind(lease.execution_token)
        .bind(lease.global_lease_token).bind(lease.route_lease_token).bind(lease.global_fence_token)
        .bind(kind.as_str()).bind(sealed.selector.target())
        .bind(pg_identity(sealed.selector.directory_device())?).bind(pg_identity(sealed.selector.directory_inode())?)
        .bind(i32::try_from(sealed.route_count).map_err(|_| invalid("release route count is invalid"))?)
        .bind(&sealed.identity.route_set_digest).fetch_one(ledger).await.map_err(DriverError::internal)?;
    transition(&outcome)
}

pub(super) async fn start_release_route_publication(
    ledger: &PgPool,
    lease: &ReleaseRoutePublicationLease,
    kind: ReleaseOverlayKind,
) -> Result<ReleaseRouteTransitionOutcome, DriverError> {
    lease.validate()?;
    let outcome = sqlx::query_scalar::<_, String>(
        "select control.start_immutable_release_route_publication($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(lease.driver_operation_id)
    .bind(lease.instance_owner)
    .bind(lease.execution_token)
    .bind(lease.global_lease_token)
    .bind(lease.route_lease_token)
    .bind(lease.global_fence_token)
    .bind(kind.as_str())
    .fetch_one(ledger)
    .await
    .map_err(DriverError::internal)?;
    transition(&outcome)
}

pub(super) async fn observe_release_route_publication(
    ledger: &PgPool,
    lease: &ReleaseRoutePublicationLease,
    kind: ReleaseOverlayKind,
    observed: &PriorSelector,
    identity: &ReleaseOverlayGenerationIdentity,
) -> Result<ReleaseRouteTransitionOutcome, DriverError> {
    lease.validate()?;
    validate_observation(lease, kind, observed, identity)?;
    let outcome = sqlx::query_scalar::<_, String>(
        "select control.observe_immutable_release_route_publication(
         $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)",
    )
    .bind(lease.driver_operation_id)
    .bind(lease.instance_owner)
    .bind(lease.execution_token)
    .bind(lease.global_lease_token)
    .bind(lease.route_lease_token)
    .bind(lease.global_fence_token)
    .bind(kind.as_str())
    .bind(i16::from(identity.protocol_version))
    .bind(identity.fleet_run_id)
    .bind(identity.driver_operation_id)
    .bind(identity.original_global_fence_token)
    .bind(identity.overlay_kind.as_str())
    .bind(&identity.route_set_digest)
    .bind(identity.target_slot.as_str())
    .bind(observed.target())
    .bind(pg_identity(observed.directory_device())?)
    .bind(pg_identity(observed.directory_inode())?)
    .fetch_one(ledger)
    .await
    .map_err(DriverError::internal)?;
    transition(&outcome)
}

pub(super) async fn begin_release_external_effects(
    ledger: &PgPool,
    lease: &ReleaseRoutePublicationLease,
) -> Result<ReleaseRouteTransitionOutcome, DriverError> {
    lease.validate()?;
    let outcome = sqlx::query_scalar::<_, String>(
        "select control.begin_immutable_release_external_effects($1,$2,$3,$4,$5,$6)",
    )
    .bind(lease.driver_operation_id)
    .bind(lease.instance_owner)
    .bind(lease.execution_token)
    .bind(lease.global_lease_token)
    .bind(lease.route_lease_token)
    .bind(lease.global_fence_token)
    .fetch_one(ledger)
    .await
    .map_err(DriverError::internal)?;
    transition(&outcome)
}

pub(super) async fn quarantine_release_route_publication(
    ledger: &PgPool,
    lease: &ReleaseRoutePublicationLease,
) -> Result<bool, DriverError> {
    lease.validate()?;
    sqlx::query_scalar::<_, bool>(
        "select control.quarantine_immutable_release_route_publication($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(lease.driver_operation_id)
    .bind(lease.instance_owner)
    .bind(lease.execution_token)
    .bind(lease.global_lease_token)
    .bind(lease.route_lease_token)
    .bind(lease.global_fence_token)
    .bind("release_route_publication_outcome_unknown")
    .fetch_one(ledger)
    .await
    .map_err(DriverError::internal)
}

#[tracing::instrument(name="deployment_driver.release_route.finish_dormant", skip_all,
    fields(release.driver_operation_id=%lease.driver_operation_id, transition.outcome=tracing::field::Empty))]
pub(super) async fn finish_release_route_publication(
    ledger: &PgPool,
    lease: &ReleaseRoutePublicationLease,
    response: &ReleaseRouteCompletionResponse,
) -> Result<FinishReleaseRoutePublication, DriverError> {
    lease.validate()?;
    validate_completion_response(lease, response)?;
    let response_value = serde_json::to_value(response).map_err(DriverError::internal)?;
    validate_response(&response_value)?;
    let (outcome, stored) = sqlx::query_as::<_, (String, Option<Value>)>(
        "select outcome,stored_response from control.finish_immutable_release_route_publication(
         $1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(lease.driver_operation_id)
    .bind(lease.instance_owner)
    .bind(lease.execution_token)
    .bind(lease.global_lease_token)
    .bind(lease.route_lease_token)
    .bind(lease.global_fence_token)
    .bind(response_value)
    .fetch_one(ledger)
    .await
    .map_err(DriverError::internal)?;
    tracing::Span::current().record("transition.outcome", outcome.as_str());
    match outcome.as_str() {
        "finished" | "replay" => {
            let parsed = parse_completion(stored, lease)?;
            if &parsed != response {
                return Err(invalid("stored release completion response differs"));
            }
            if outcome == "finished" {
                Ok(FinishReleaseRoutePublication::Finished(parsed))
            } else {
                Ok(FinishReleaseRoutePublication::Replay(parsed))
            }
        }
        "conflict" => Ok(FinishReleaseRoutePublication::Conflict(
            stored
                .map(|value| parse_completion(Some(value), lease))
                .transpose()?,
        )),
        "authority_lost" if stored.is_none() => Ok(FinishReleaseRoutePublication::AuthorityLost),
        "not_found" if stored.is_none() => Ok(FinishReleaseRoutePublication::NotFound),
        "state_drift" if stored.is_none() => Ok(FinishReleaseRoutePublication::StateDrift),
        "wrong_phase" if stored.is_none() => Ok(FinishReleaseRoutePublication::WrongPhase),
        "invalid" if stored.is_none() => Ok(FinishReleaseRoutePublication::Invalid),
        _ => Err(invalid("release completion outcome row is invalid")),
    }
}

pub(super) async fn read_release_route_publication_result(
    ledger: &PgPool,
    driver_operation_id: Uuid,
    fleet_run_id: Uuid,
) -> Result<ReadReleaseRoutePublicationResult, DriverError> {
    if driver_operation_id.is_nil() || fleet_run_id.is_nil() {
        return Err(invalid("release result identity is invalid"));
    }
    let (outcome, stored) = sqlx::query_as::<_, (String, Option<Value>)>(
        "select outcome,stored_response
         from control.read_immutable_release_route_publication_result($1,$2)",
    )
    .bind(driver_operation_id)
    .bind(fleet_run_id)
    .fetch_one(ledger)
    .await
    .map_err(DriverError::internal)?;
    match outcome.as_str() {
        "not_found" if stored.is_none() => Ok(ReadReleaseRoutePublicationResult::NotFound),
        "conflict" if stored.is_none() => Ok(ReadReleaseRoutePublicationResult::Conflict),
        "pending" if stored.is_none() => Ok(ReadReleaseRoutePublicationResult::Pending),
        "quarantined" if stored.is_none() => Ok(ReadReleaseRoutePublicationResult::Quarantined),
        "replay" => {
            let value = stored.ok_or_else(|| invalid("release result response is absent"))?;
            let response: ReleaseRouteCompletionResponse =
                serde_json::from_value(value).map_err(DriverError::internal)?;
            validate_completion_identity(driver_operation_id, fleet_run_id, &response)?;
            Ok(ReadReleaseRoutePublicationResult::Replay(Box::new(
                response,
            )))
        }
        _ => Err(invalid("release result outcome row is invalid")),
    }
}

fn parse_driver_admission(
    request: &ReleaseRouteDriverAdmissionRequest,
    row: DriverAdmissionRow,
) -> Result<ReleaseRouteDriverAdmission, DriverError> {
    match row.0.as_str() {
        "acquired" => {
            if row.3.is_some() {
                return Err(invalid("acquired release response is nonnull"));
            }
            let lease = ReleaseRouteDriverLease {
                driver_operation_id: uuid(row.1, "driver operation")?,
                fleet_run_id: request.fleet_run_id,
                control_operation: request.control_operation.clone(),
                instance_owner: request.instance_owner,
                execution_token: request.execution_token,
                global_lease_token: request.global_lease_token,
                global_fence_token: fence(row.2, "global fence")?,
                reserved_workshops: workshops(row.4)?,
                ttl_seconds: request.ttl_seconds,
            };
            lease.validate()?;
            Ok(ReleaseRouteDriverAdmission::Acquired(lease))
        }
        "replay" => {
            uuid(row.1, "replay operation")?;
            fence(row.2, "replay fence")?;
            optional_workshops(row.4)?;
            let response = row
                .3
                .ok_or_else(|| invalid("release replay response is absent"))?;
            validate_response(&response)?;
            Ok(ReleaseRouteDriverAdmission::Replay(response))
        }
        outcome => {
            if row.3.is_some() {
                return Err(invalid("release refusal response is nonnull"));
            }
            optional_uuid(row.1)?;
            optional_fence(row.2)?;
            optional_workshops(row.4)?;
            let refusal = match outcome {
                "invalid" => ReleaseRouteDriverRefusal::Invalid,
                "invalid_fleet" => ReleaseRouteDriverRefusal::InvalidFleet,
                "upstream_lease_lost" => ReleaseRouteDriverRefusal::UpstreamLeaseLost,
                "protocol_conflict" => ReleaseRouteDriverRefusal::ProtocolConflict,
                "digest_conflict" => ReleaseRouteDriverRefusal::DigestConflict,
                "failed" => ReleaseRouteDriverRefusal::Failed,
                "busy" => ReleaseRouteDriverRefusal::Busy,
                "quarantined" => ReleaseRouteDriverRefusal::Quarantined,
                "route_busy" => ReleaseRouteDriverRefusal::RouteBusy,
                "route_uninitialized" => ReleaseRouteDriverRefusal::RouteUninitialized,
                "fleet_not_empty" => ReleaseRouteDriverRefusal::FleetNotEmpty,
                _ => return Err(invalid("release driver admission outcome is invalid")),
            };
            Ok(ReleaseRouteDriverAdmission::Refused(refusal))
        }
    }
}

fn parse_publication_admission(
    request: &ReleaseRoutePublicationAdmissionRequest,
    row: PublicationAdmissionRow,
) -> Result<ReleaseRoutePublicationAdmission, DriverError> {
    if matches!(row.0.as_str(), "acquired" | "replay" | "quarantined") {
        let slot = ReleaseTargetSlot::parse(
            row.1
                .as_deref()
                .ok_or_else(|| invalid("release slot is absent"))?,
        )?;
        let maintenance = row
            .2
            .ok_or_else(|| invalid("maintenance selector is absent"))?;
        let candidate = row
            .3
            .ok_or_else(|| invalid("candidate selector is absent"))?;
        let owners = workshops(row.4)?;
        if owners != request.driver.reserved_workshops {
            return Err(invalid("release publication owners differ"));
        }
        let lease = ReleaseRoutePublicationLease {
            driver_operation_id: request.driver.driver_operation_id,
            fleet_run_id: request.driver.fleet_run_id,
            control_operation: request.driver.control_operation.clone(),
            instance_owner: request.driver.instance_owner,
            execution_token: request.driver.execution_token,
            global_lease_token: request.driver.global_lease_token,
            route_lease_token: request.route_lease_token,
            global_fence_token: request.driver.global_fence_token,
            target_slot: slot,
            maintenance_selector: maintenance,
            candidate_selector: candidate,
            reserved_workshops: owners,
            ttl_seconds: request.driver.ttl_seconds,
        };
        lease.validate()?;
        return Ok(match row.0.as_str() {
            "acquired" => ReleaseRoutePublicationAdmission::Acquired(lease),
            "replay" => ReleaseRoutePublicationAdmission::Replay(lease),
            _ => ReleaseRoutePublicationAdmission::Refused(
                ReleaseRoutePublicationRefusal::Quarantined,
            ),
        });
    }
    if row.1.is_some() || row.2.is_some() || row.3.is_some() || row.4.is_some() {
        return Err(invalid("release publication refusal row is malformed"));
    }
    Ok(ReleaseRoutePublicationAdmission::Refused(
        match row.0.as_str() {
            "invalid" => ReleaseRoutePublicationRefusal::Invalid,
            "not_found" => ReleaseRoutePublicationRefusal::NotFound,
            "authority_lost" => ReleaseRoutePublicationRefusal::AuthorityLost,
            "conflict" => ReleaseRoutePublicationRefusal::Conflict,
            "route_drift" => ReleaseRoutePublicationRefusal::RouteDrift,
            _ => return Err(invalid("release publication admission outcome is invalid")),
        },
    ))
}

pub(super) fn validate_release_snapshot_rows(
    expected_target_slot: ReleaseTargetSlot,
    expected_workshops: Option<&[Uuid]>,
    after: Option<Uuid>,
    limit: usize,
    rows: Vec<ReleaseSnapshotRow>,
) -> Result<Vec<ReleaseRouteSnapshotItem>, DriverError> {
    if rows.len() > limit {
        return Err(invalid("release snapshot exceeded limit"));
    }
    let mut previous = after;
    rows.into_iter()
        .map(|row| {
            if row.0.is_nil()
                || row.1.is_nil()
                || previous.is_some_and(|id| id >= row.0)
                || row.4 <= 0
                || !digest(&row.5)
                || !digest(&row.7)
                || row.8 <= 0
                || row.9 <= 0
                || expected_workshops
                    .is_some_and(|workshops| workshops.binary_search(&row.0).is_err())
            {
                return Err(invalid("release snapshot row is invalid"));
            }
            let slot = ReleaseTargetSlot::parse(&row.10)?;
            if slot != expected_target_slot {
                return Err(invalid("release snapshot slot differs"));
            }
            RouteProjection::parse(&row.6, &row.5, RouteDisposition::Present)?;
            let database_id = row.1.to_string();
            if row.6.get("database_id").and_then(Value::as_str) != Some(database_id.as_str())
                || row.6.get("database_ref").and_then(Value::as_str) != Some(row.2.as_str())
                || ((row.6.get("paperless_mode").and_then(Value::as_str) != Some("absent"))
                    != row.3)
            {
                return Err(invalid("release snapshot projection differs"));
            }
            previous = Some(row.0);
            Ok(ReleaseRouteSnapshotItem {
                workshop_id: row.0,
                database_id: row.1,
                database_ref: row.2,
                paperless_enabled: row.3,
                generation: row.4,
                projection_digest: row.5,
                canonical_projection: row.6,
                applied_rendered_digest: row.7,
                applied_fence_token: row.8,
                route_fence_token: row.9,
                target_slot: slot,
            })
        })
        .collect()
}

fn validate_prior(
    prior: &PriorSelector,
    loaded: Option<&RouteSetPriorLoadedIdentity>,
) -> Result<Option<Value>, DriverError> {
    if prior.target() == "generations/boot-live" {
        return if loaded.is_none() {
            Ok(None)
        } else {
            Err(invalid("BootLive identity is nonnull"))
        };
    }
    let loaded = loaded.ok_or_else(|| invalid("release prior identity is absent"))?;
    let expected = match loaded {
        RouteSetPriorLoadedIdentity::Startup(identity) => {
            if identity.effect_run_id.is_nil() || !digest(&identity.sealed_digest) {
                return Err(invalid("startup prior identity is invalid"));
            }
            format!("generations/startup-{}", identity.effect_run_id)
        }
        RouteSetPriorLoadedIdentity::Release(identity) => {
            identity.validate()?;
            ReleaseGenerationName::new(identity.fleet_run_id, identity.overlay_kind)
                .selector_target()
        }
        RouteSetPriorLoadedIdentity::RouteSet(identity) => {
            identity.validate()?;
            RouteSetGenerationName::new(identity.publication_id, identity.publication_kind)
                .selector_target()
        }
    };
    if prior.target() != expected {
        return Err(invalid("release prior selector differs from identity"));
    }
    let value = match loaded {
        RouteSetPriorLoadedIdentity::Startup(identity) => serde_json::to_value(identity),
        RouteSetPriorLoadedIdentity::Release(identity) => serde_json::to_value(identity),
        RouteSetPriorLoadedIdentity::RouteSet(identity) => serde_json::to_value(identity),
    }
    .map_err(DriverError::internal)?;
    if serde_json::to_vec(&value)
        .map_err(DriverError::internal)?
        .len()
        > 4096
    {
        return Err(invalid("release prior identity exceeded its bound"));
    }
    Ok(Some(value))
}

fn validate_evidence(
    lease: &ReleaseRoutePublicationLease,
    evidence: &ReleaseRouteSealEvidence,
) -> Result<(), DriverError> {
    if evidence.workshop_id.is_nil()
        || lease
            .reserved_workshops
            .binary_search(&evidence.workshop_id)
            .is_err()
        || evidence.projection_generation <= 0
        || !digest(&evidence.projection_digest)
        || !digest(&evidence.applied_rendered_digest)
        || !digest(&evidence.rendered_digest)
    {
        return Err(invalid("release route evidence is invalid"));
    }
    Ok(())
}

fn validate_sealed(
    lease: &ReleaseRoutePublicationLease,
    kind: ReleaseOverlayKind,
    sealed: &SealedReleaseGeneration,
) -> Result<(), DriverError> {
    sealed.identity.validate()?;
    let selector = if kind == ReleaseOverlayKind::Maintenance {
        &lease.maintenance_selector
    } else {
        &lease.candidate_selector
    };
    if sealed.route_count != lease.reserved_workshops.len()
        || sealed.selector.target() != selector
        || sealed.identity.fleet_run_id != lease.fleet_run_id
        || sealed.identity.driver_operation_id != lease.driver_operation_id
        || sealed.identity.original_global_fence_token != lease.global_fence_token
        || sealed.identity.overlay_kind != kind
        || sealed.identity.target_slot != lease.target_slot
    {
        return Err(invalid("sealed release generation differs"));
    }
    Ok(())
}

fn validate_observation(
    lease: &ReleaseRoutePublicationLease,
    kind: ReleaseOverlayKind,
    observed: &PriorSelector,
    identity: &ReleaseOverlayGenerationIdentity,
) -> Result<(), DriverError> {
    identity.validate()?;
    let selector = if kind == ReleaseOverlayKind::Maintenance {
        &lease.maintenance_selector
    } else {
        &lease.candidate_selector
    };
    if observed.target() != selector
        || identity.fleet_run_id != lease.fleet_run_id
        || identity.driver_operation_id != lease.driver_operation_id
        || identity.original_global_fence_token != lease.global_fence_token
        || identity.overlay_kind != kind
        || identity.target_slot != lease.target_slot
    {
        return Err(invalid("release observation differs"));
    }
    Ok(())
}

fn transition(value: &str) -> Result<ReleaseRouteTransitionOutcome, DriverError> {
    Ok(match value {
        "recorded" => ReleaseRouteTransitionOutcome::Recorded,
        "sealed" => ReleaseRouteTransitionOutcome::Sealed,
        "started" => ReleaseRouteTransitionOutcome::Started,
        "observed" => ReleaseRouteTransitionOutcome::Observed,
        "replay" => ReleaseRouteTransitionOutcome::Replay,
        "authority_lost" => ReleaseRouteTransitionOutcome::AuthorityLost,
        "not_found" => ReleaseRouteTransitionOutcome::NotFound,
        "conflict" => ReleaseRouteTransitionOutcome::Conflict,
        "wrong_phase" => ReleaseRouteTransitionOutcome::WrongPhase,
        "invalid" => ReleaseRouteTransitionOutcome::Invalid,
        "prior_absent" => ReleaseRouteTransitionOutcome::PriorAbsent,
        "out_of_order" => ReleaseRouteTransitionOutcome::OutOfOrder,
        "snapshot_drift" => ReleaseRouteTransitionOutcome::SnapshotDrift,
        "count_mismatch" => ReleaseRouteTransitionOutcome::CountMismatch,
        "digest_mismatch" => ReleaseRouteTransitionOutcome::DigestMismatch,
        "identity_mismatch" => ReleaseRouteTransitionOutcome::IdentityMismatch,
        "observation_mismatch" => ReleaseRouteTransitionOutcome::ObservationMismatch,
        _ => return Err(invalid("release route transition outcome is invalid")),
    })
}

fn uuid(value: Option<Uuid>, name: &str) -> Result<Uuid, DriverError> {
    value
        .filter(|id| !id.is_nil())
        .ok_or_else(|| invalid(format!("release {name} is invalid")))
}
fn fence(value: Option<i64>, name: &str) -> Result<i64, DriverError> {
    value
        .filter(|n| *n > 0)
        .ok_or_else(|| invalid(format!("release {name} is invalid")))
}
fn optional_uuid(value: Option<Uuid>) -> Result<(), DriverError> {
    if value.is_some_and(|id| id.is_nil()) {
        Err(invalid("release optional UUID is invalid"))
    } else {
        Ok(())
    }
}
fn optional_fence(value: Option<i64>) -> Result<(), DriverError> {
    if value.is_some_and(|n| n <= 0) {
        Err(invalid("release optional fence is invalid"))
    } else {
        Ok(())
    }
}
fn workshops(value: Option<Vec<Uuid>>) -> Result<Vec<Uuid>, DriverError> {
    let value = value.ok_or_else(|| invalid("release owners are absent"))?;
    if !(1..=MAX_ROUTES).contains(&value.len()) || !ordered_uuids(&value) {
        return Err(invalid("release owners are invalid"));
    }
    Ok(value)
}
fn optional_workshops(value: Option<Vec<Uuid>>) -> Result<(), DriverError> {
    if value.is_some_and(|v| v.len() > MAX_ROUTES || (!v.is_empty() && !ordered_uuids(&v))) {
        Err(invalid("release optional owners are invalid"))
    } else {
        Ok(())
    }
}
fn ordered_uuids(value: &[Uuid]) -> bool {
    value.iter().all(|id| !id.is_nil()) && value.windows(2).all(|w| w[0] < w[1])
}
fn pg_identity(value: u64) -> Result<i64, DriverError> {
    i64::try_from(value)
        .ok()
        .filter(|n| *n > 0)
        .ok_or_else(|| invalid("release file identity is invalid"))
}
fn validate_response(value: &Value) -> Result<(), DriverError> {
    if !value.is_object()
        || serde_json::to_vec(value)
            .map_err(DriverError::internal)?
            .len()
            > MAX_RESPONSE_BYTES
    {
        Err(invalid("release response is invalid"))
    } else {
        Ok(())
    }
}

fn parse_completion(
    value: Option<Value>,
    lease: &ReleaseRoutePublicationLease,
) -> Result<ReleaseRouteCompletionResponse, DriverError> {
    let value = value.ok_or_else(|| invalid("release completion response is absent"))?;
    validate_response(&value)?;
    let response = serde_json::from_value(value).map_err(DriverError::internal)?;
    validate_completion_response(lease, &response)?;
    Ok(response)
}

fn validate_completion_response(
    lease: &ReleaseRoutePublicationLease,
    response: &ReleaseRouteCompletionResponse,
) -> Result<(), DriverError> {
    validate_completion_identity(lease.driver_operation_id, lease.fleet_run_id, response)?;
    let evidence = &response.evidence;
    if evidence.target_slot != lease.target_slot.as_str()
        || evidence.driver_fence_token != lease.global_fence_token
    {
        return Err(invalid("release completion lease evidence differs"));
    }
    Ok(())
}

pub(super) fn validate_completion_identity(
    driver_operation_id: Uuid,
    _fleet_run_id: Uuid,
    response: &ReleaseRouteCompletionResponse,
) -> Result<(), DriverError> {
    let evidence = &response.evidence;
    let digests = [
        &evidence.odoo_manifest_digest,
        &evidence.odoo_config_digest,
        &evidence.extension_manifest_digest,
        &evidence.extension_config_digest,
        &evidence.payload_digest,
        &evidence.bridge_contract_digest,
        &evidence.runtime_config_digest,
        &evidence.gateway_configuration_digest,
    ];
    if evidence.release_id.trim().is_empty()
        || !digest(&evidence.odoo_subject_digest)
        || !digest(&evidence.extension_subject_digest)
        || !digest(&evidence.pair_qualification_digest)
        || digests.into_iter().any(|value| !digest(value))
        || !evidence.installed_addon_versions.is_object()
        || !evidence.prepared_tenants.is_array()
        || !evidence.tenant_snapshot.is_array()
        || evidence.runtime_key != "shared-odoo"
        || !matches!(evidence.target_slot.as_str(), "blue" | "green")
        || !valid_runtime_container(&evidence.runtime_container, &evidence.target_slot)
        || evidence.runtime_role != format!("mb_runtime_{}", &evidence.odoo_subject_digest[7..23])
        || !valid_runtime_deployment_ref(
            &evidence.runtime_deployment_ref,
            &evidence.odoo_subject_digest,
        )
        || !valid_extension_volume(
            &evidence.extension_volume,
            &evidence.extension_manifest_digest,
            &evidence.payload_digest,
        )
        || evidence.fleet_generation <= 0
        || evidence.driver_action_id.is_nil()
        || evidence.driver_operation_id != driver_operation_id
        || evidence.driver_fence_token <= 0
        || !evidence.old_runtime_database_access_revoked
        || !evidence.tenant_recovery_verified
        || !evidence.candidate_smoke_verified
        || evidence.candidate_restart_policy != "unless-stopped"
        || evidence.retained_restart_policy != "no"
    {
        return Err(invalid("release completion response is invalid"));
    }
    Ok(())
}

fn valid_runtime_container(value: &str, target_slot: &str) -> bool {
    let suffix = format!("-odoo-{target_slot}");
    let Some(namespace) = value.strip_suffix(&suffix) else {
        return false;
    };
    (1..=111).contains(&namespace.len())
        && namespace
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && namespace
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn valid_runtime_deployment_ref(value: &str, subject_digest: &str) -> bool {
    if value.is_empty() || value.len() > 512 || !digest(subject_digest) {
        return false;
    }
    let suffix = format!("@{subject_digest}");
    let Some(repository) = value.strip_suffix(&suffix) else {
        return false;
    };
    !repository.is_empty()
        && !repository.starts_with("http")
        && repository.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'/' | b':' | b'_' | b'-')
        })
}

pub(super) fn valid_extension_volume(
    value: &str,
    manifest_digest: &str,
    payload_digest: &str,
) -> bool {
    if !digest(manifest_digest) || !digest(payload_digest) {
        return false;
    }
    let Some(suffix) = value.strip_prefix("mb-") else {
        return false;
    };
    let suffix = suffix
        .strip_prefix("control-")
        .or_else(|| {
            let rest = suffix.strip_prefix("dev")?;
            let (number, rest) = rest.split_at_checked(1)?;
            matches!(number, "1" | "2" | "3" | "4")
                .then(|| rest.strip_prefix('-'))
                .flatten()
        })
        .unwrap_or(suffix);
    let Some(digests) = suffix.strip_prefix("ext-") else {
        return false;
    };
    let Some((manifest, payload)) = digests.split_once('-') else {
        return false;
    };
    [manifest, payload].into_iter().all(|part| {
        part.len() == 16
            && part
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }) && manifest == &manifest_digest[7..23]
        && payload == &payload_digest[7..23]
}
fn digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(bare_digest)
}
fn bare_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn invalid(message: impl Into<String>) -> DriverError {
    DriverError::internal(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> ReleaseRouteDriverAdmissionRequest {
        ReleaseRouteDriverAdmissionRequest {
            control_operation: ControlOperationLease {
                id: Uuid::new_v4(),
                attempt: 2,
                owner: "worker".into(),
            },
            idempotency_key: "release:test".into(),
            fleet_run_id: Uuid::new_v4(),
            request_digest: "a".repeat(64),
            instance_owner: Uuid::new_v4(),
            execution_token: Uuid::new_v4(),
            global_lease_token: Uuid::new_v4(),
            ttl_seconds: 1200,
        }
    }

    fn completion() -> ReleaseRouteCompletionResponse {
        let subject = format!("sha256:{}", "a".repeat(64));
        ReleaseRouteCompletionResponse {
            evidence: ReleaseRouteCompletionEvidence {
                release_id: "odoo-2026.08.23-deadbeef".into(),
                odoo_subject_digest: subject.clone(),
                extension_subject_digest: format!("sha256:{}", "b".repeat(64)),
                odoo_manifest_digest: format!("sha256:{}", "c".repeat(64)),
                odoo_config_digest: format!("sha256:{}", "d".repeat(64)),
                extension_manifest_digest: format!("sha256:{}", "e".repeat(64)),
                extension_config_digest: format!("sha256:{}", "f".repeat(64)),
                payload_digest: format!("sha256:{}", "1".repeat(64)),
                extension_volume: "mb-control-ext-eeeeeeeeeeeeeeee-1111111111111111".into(),
                pair_qualification_digest: format!("sha256:{}", "2".repeat(64)),
                bridge_contract_digest: format!("sha256:{}", "3".repeat(64)),
                installed_addon_versions: serde_json::json!({}),
                runtime_key: "shared-odoo".into(),
                target_slot: "blue".into(),
                runtime_container: "mb-control-odoo-blue".into(),
                runtime_role: format!("mb_runtime_{}", &subject[7..23]),
                runtime_deployment_ref: format!("docker.io/library/odoo@{subject}"),
                runtime_config_digest: format!("sha256:{}", "4".repeat(64)),
                prepared_tenants: serde_json::json!([]),
                fleet_generation: 1,
                tenant_snapshot: serde_json::json!([]),
                gateway_configuration_digest: format!("sha256:{}", "5".repeat(64)),
                driver_action_id: Uuid::new_v4(),
                driver_operation_id: Uuid::new_v4(),
                driver_fence_token: 7,
                old_runtime_database_access_revoked: true,
                tenant_recovery_verified: true,
                candidate_smoke_verified: true,
                candidate_restart_policy: "unless-stopped".into(),
                retained_restart_policy: "no".into(),
            },
        }
    }

    #[test]
    fn acquired_requires_strict_owner_order() {
        let request = request();
        let a = Uuid::parse_str("10000000-0000-4000-8000-000000000001").unwrap();
        let b = Uuid::parse_str("20000000-0000-4000-8000-000000000001").unwrap();
        assert!(matches!(
            parse_driver_admission(
                &request,
                (
                    "acquired".into(),
                    Some(Uuid::new_v4()),
                    Some(3),
                    None,
                    Some(vec![a, b])
                )
            )
            .unwrap(),
            ReleaseRouteDriverAdmission::Acquired(_)
        ));
        assert!(
            parse_driver_admission(
                &request,
                (
                    "acquired".into(),
                    Some(Uuid::new_v4()),
                    Some(3),
                    None,
                    Some(vec![b, a])
                )
            )
            .is_err()
        );
    }

    #[test]
    fn unknown_outcomes_fail_closed() {
        assert!(
            parse_driver_admission(&request(), ("future".into(), None, None, None, None)).is_err()
        );
        assert!(transition("future").is_err());
    }

    #[test]
    fn completion_runtime_identifiers_are_exact() {
        let response = completion();
        let operation = response.evidence.driver_operation_id;
        assert!(validate_completion_identity(operation, Uuid::new_v4(), &response).is_ok());

        for field in [
            "volume",
            "volume_binding",
            "container",
            "role",
            "deployment",
        ] {
            let mut malformed = response.clone();
            match field {
                "volume" => malformed.evidence.extension_volume = "mb-ext-short-bad".into(),
                "volume_binding" => {
                    malformed.evidence.extension_volume =
                        "mb-control-ext-aaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb".into()
                }
                "container" => {
                    malformed.evidence.runtime_container = "mb-control-odoo-green".into()
                }
                "role" => malformed.evidence.runtime_role = "mb_runtime_attacker".into(),
                "deployment" => {
                    malformed.evidence.runtime_deployment_ref =
                        "https://example.invalid/odoo:latest".into()
                }
                _ => unreachable!(),
            }
            assert!(
                validate_completion_identity(operation, Uuid::new_v4(), &malformed).is_err(),
                "accepted malformed {field}"
            );
        }
    }

    #[test]
    fn registered_without_activation() {
        let driver = include_str!("../docker_driver.rs");
        assert_eq!(
            driver.matches("mod release_route_publication_db;").count(),
            1
        );
        assert_eq!(driver.matches("release_route_publication_db::").count(), 0);
        assert!(!driver.contains("use release_route_publication_db::*"));
    }

    #[test]
    fn source_pins_all_existing_apis_and_no_missing_finalizer() {
        let source = include_str!("release_route_publication_db.rs");
        for name in [
            "admit_release_driver_operation(",
            "admit_immutable_release_route_publication(",
            "renew_immutable_release_route_publication(",
            "record_immutable_release_route_prior(",
            "read_immutable_release_route_snapshot_batch(",
            "record_immutable_release_route_candidate(",
            "seal_immutable_release_route_overlay(",
            "start_immutable_release_route_publication(",
            "observe_immutable_release_route_publication(",
            "begin_immutable_release_external_effects(",
            "quarantine_immutable_release_route_publication(",
        ] {
            assert!(source.contains(name));
        }
        assert!(source.contains("finish_immutable_release_route_publication("));
        assert!(source.contains("read_immutable_release_route_publication_result("));
    }
}
