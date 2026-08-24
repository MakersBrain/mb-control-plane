//! Dormant typed database boundary for recovery-maintenance route-set writers.
//!
//! Migration 0033 keeps one recovery effect run as the logical owner of both
//! publications. Entry freezes the applied fleet and masks only its target;
//! restore freezes the then-current desired target plus every other applied
//! row. This module has no active call site and cannot activate generation-v1.
#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

use super::gateway::RouteSetPublicationKind;
use super::route_generation_fs::validate_digest;
use super::route_set_generation_fs::{MAX_ROUTES, RouteSetGenerationName};
use super::route_set_publication_db::{
    CompletedRouteSetEvidence, RouteSetAppliedDisposition, RouteSetPublicationLease,
};
use super::{ControlOperationLease, DriverError};

const MIN_TTL_SECONDS: i32 = 60;
const MAX_TTL_SECONDS: i32 = 1200;
const EMPTY_RENDERED_DIGEST: &str =
    "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

#[derive(Clone)]
pub(super) enum RecoveryRouteSetAdmissionRequest {
    Maintenance {
        control_operation: ControlOperationLease,
        workshop_id: Uuid,
        idempotency_key: String,
        request_digest: String,
        instance_owner: Uuid,
        execution_token: Uuid,
        global_lease_token: Uuid,
        route_lease_token: Uuid,
        ttl_seconds: i32,
    },
    Restore {
        effect_run_id: Uuid,
        control_operation: ControlOperationLease,
        workshop_id: Uuid,
        instance_owner: Uuid,
        execution_token: Uuid,
        global_lease_token: Uuid,
        route_lease_token: Uuid,
        ttl_seconds: i32,
    },
}

impl RecoveryRouteSetAdmissionRequest {
    pub(super) const fn publication_kind(&self) -> RouteSetPublicationKind {
        match self {
            Self::Maintenance { .. } => RouteSetPublicationKind::RecoveryMaintenance,
            Self::Restore { .. } => RouteSetPublicationKind::RecoveryRestore,
        }
    }

    pub(super) const fn effect_run_id(&self) -> Option<Uuid> {
        match self {
            Self::Maintenance { .. } => None,
            Self::Restore { effect_run_id, .. } => Some(*effect_run_id),
        }
    }

    pub(super) const fn workshop_id(&self) -> Uuid {
        match self {
            Self::Maintenance { workshop_id, .. } | Self::Restore { workshop_id, .. } => {
                *workshop_id
            }
        }
    }

    pub(super) fn control_operation(&self) -> &ControlOperationLease {
        match self {
            Self::Maintenance {
                control_operation, ..
            }
            | Self::Restore {
                control_operation, ..
            } => control_operation,
        }
    }

    fn authority(&self) -> (Uuid, Uuid, Uuid, Uuid, i32) {
        match self {
            Self::Maintenance {
                instance_owner,
                execution_token,
                global_lease_token,
                route_lease_token,
                ttl_seconds,
                ..
            }
            | Self::Restore {
                instance_owner,
                execution_token,
                global_lease_token,
                route_lease_token,
                ttl_seconds,
                ..
            } => (
                *instance_owner,
                *execution_token,
                *global_lease_token,
                *route_lease_token,
                *ttl_seconds,
            ),
        }
    }

    fn validate(&self) -> Result<(), DriverError> {
        let operation = self.control_operation();
        let (owner, execution, global, route, ttl) = self.authority();
        let common_invalid = operation.id.is_nil()
            || operation.attempt <= 0
            || operation.owner.trim().is_empty()
            || self.workshop_id().is_nil()
            || owner.is_nil()
            || execution.is_nil()
            || global.is_nil()
            || route.is_nil()
            || !(MIN_TTL_SECONDS..=MAX_TTL_SECONDS).contains(&ttl);
        let kind_invalid = match self {
            Self::Maintenance {
                idempotency_key,
                request_digest,
                ..
            } => {
                idempotency_key.is_empty()
                    || idempotency_key.len() > 180
                    || !valid_bare_sha256(request_digest)
            }
            Self::Restore { effect_run_id, .. } => effect_run_id.is_nil(),
        };
        if common_invalid || kind_invalid {
            return Err(invalid("recovery route-set admission request is invalid"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RecoveryRouteSetAdmissionRefusal {
    Invalid,
    ProtocolInactive,
    UpstreamLeaseLost,
    Conflict,
    Busy,
    FleetBusy,
    FleetQuarantined,
    FleetNotReady,
    NotMaintenance,
    AuthorityLost,
    ProjectionMissing,
}

#[derive(Clone)]
pub(super) struct RecoveryRouteSetPublicationLease {
    pub effect_run_id: Uuid,
    pub core: RouteSetPublicationLease,
}

pub(super) enum RecoveryRouteSetAdmission {
    Acquired(RecoveryRouteSetPublicationLease),
    Replay(RecoveryRouteSetPublicationResponse),
    NotApplied(RecoveryRouteSetNotAppliedResult),
    Refused(RecoveryRouteSetAdmissionRefusal),
}

pub(super) enum ReadRecoveryRouteSetAdmission {
    Absent,
    Replay(RecoveryRouteSetPublicationResponse),
    NotApplied(RecoveryRouteSetNotAppliedResult),
    Refused(RecoveryRouteSetAdmissionRefusal),
}

type AdmissionRow = (
    String,
    Option<Uuid>,
    Option<Uuid>,
    Option<Uuid>,
    Option<i64>,
    Option<i64>,
    Option<String>,
    Option<i32>,
    Option<i64>,
    Option<String>,
    Option<String>,
    Option<Value>,
);

#[tracing::instrument(
    name = "deployment_driver.route_set_recovery_publication.read_admission_dormant",
    skip_all,
    fields(
        workshop_id = %request.workshop_id(),
        publication.kind = request.publication_kind().as_str(),
        result.outcome = tracing::field::Empty
    )
)]
pub(super) async fn read_route_set_recovery_admission(
    ledger: &PgPool,
    request: &RecoveryRouteSetAdmissionRequest,
) -> Result<ReadRecoveryRouteSetAdmission, DriverError> {
    request.validate()?;
    let operation = request.control_operation();
    let row: AdmissionRow =
        match request {
            RecoveryRouteSetAdmissionRequest::Maintenance {
                workshop_id,
                idempotency_key,
                request_digest,
                ..
            } => sqlx::query_as(
                "select outcome,publication_id,effect_run_id,target_workshop_id,global_fence_token,
                    target_route_fence_token,selector,snapshot_count,target_generation,
                    target_projection_digest,target_disposition,stored_response
               from control.read_route_set_recovery_maintenance_admission(
                 $1,$2,$3,$4,$5,$6)",
            )
            .bind(workshop_id)
            .bind(operation.id)
            .bind(operation.attempt)
            .bind(&operation.owner)
            .bind(idempotency_key)
            .bind(request_digest)
            .fetch_one(ledger)
            .await,
            RecoveryRouteSetAdmissionRequest::Restore {
                effect_run_id,
                workshop_id,
                ..
            } => sqlx::query_as(
                "select outcome,publication_id,effect_run_id,target_workshop_id,global_fence_token,
                    target_route_fence_token,selector,snapshot_count,target_generation,
                    target_projection_digest,target_disposition,stored_response
               from control.read_route_set_recovery_restore_admission(
                 $1,$2,$3,$4,$5)",
            )
            .bind(effect_run_id)
            .bind(workshop_id)
            .bind(operation.id)
            .bind(operation.attempt)
            .bind(&operation.owner)
            .fetch_one(ledger)
            .await,
        }
        .map_err(DriverError::internal)?;
    tracing::Span::current().record("result.outcome", row.0.as_str());
    parse_read_admission(request, row)
}

fn parse_read_admission(
    request: &RecoveryRouteSetAdmissionRequest,
    row: AdmissionRow,
) -> Result<ReadRecoveryRouteSetAdmission, DriverError> {
    if row.0 == "absent" {
        if row.1.is_none()
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
        {
            return Ok(ReadRecoveryRouteSetAdmission::Absent);
        }
        return Err(invalid(
            "absent recovery route-set admission result is malformed",
        ));
    }
    match parse_admission(request, row)? {
        RecoveryRouteSetAdmission::Replay(response) => {
            Ok(ReadRecoveryRouteSetAdmission::Replay(response))
        }
        RecoveryRouteSetAdmission::NotApplied(result) => {
            Ok(ReadRecoveryRouteSetAdmission::NotApplied(result))
        }
        RecoveryRouteSetAdmission::Refused(refusal) => {
            Ok(ReadRecoveryRouteSetAdmission::Refused(refusal))
        }
        RecoveryRouteSetAdmission::Acquired(_) => Err(invalid(
            "read-only recovery route-set admission acquired authority",
        )),
    }
}

#[tracing::instrument(
    name = "deployment_driver.route_set_recovery_publication.admit_dormant",
    skip_all,
    fields(
        workshop_id = %request.workshop_id(),
        publication.kind = request.publication_kind().as_str(),
        publication.id = tracing::field::Empty,
        publication.outcome = tracing::field::Empty
    )
)]
pub(super) async fn admit_route_set_recovery_publication(
    ledger: &PgPool,
    request: &RecoveryRouteSetAdmissionRequest,
) -> Result<RecoveryRouteSetAdmission, DriverError> {
    request.validate()?;
    let operation = request.control_operation();
    let (instance, execution, global, route, ttl) = request.authority();
    let row: AdmissionRow =
        match request {
            RecoveryRouteSetAdmissionRequest::Maintenance {
                workshop_id,
                idempotency_key,
                request_digest,
                ..
            } => sqlx::query_as(
                "select outcome,publication_id,effect_run_id,target_workshop_id,global_fence_token,
                    target_route_fence_token,selector,snapshot_count,target_generation,
                    target_projection_digest,target_disposition,stored_response
               from control.admit_route_set_recovery_maintenance(
                 $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",
            )
            .bind(operation.id)
            .bind(operation.attempt)
            .bind(&operation.owner)
            .bind(workshop_id)
            .bind("restore")
            .bind(idempotency_key)
            .bind(request_digest)
            .bind(instance)
            .bind(execution)
            .bind(global)
            .bind(route)
            .bind(ttl)
            .fetch_one(ledger)
            .await,
            RecoveryRouteSetAdmissionRequest::Restore { effect_run_id, .. } => sqlx::query_as(
                "select outcome,publication_id,effect_run_id,target_workshop_id,global_fence_token,
                    target_route_fence_token,selector,snapshot_count,target_generation,
                    target_projection_digest,target_disposition,stored_response
               from control.admit_route_set_recovery_restore(
                 $1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
            )
            .bind(effect_run_id)
            .bind(request.workshop_id())
            .bind(operation.id)
            .bind(operation.attempt)
            .bind(&operation.owner)
            .bind(instance)
            .bind(execution)
            .bind(global)
            .bind(route)
            .bind(ttl)
            .fetch_one(ledger)
            .await,
        }
        .map_err(DriverError::internal)?;
    tracing::Span::current().record("publication.outcome", row.0.as_str());
    if let Some(id) = row.1 {
        tracing::Span::current().record("publication.id", tracing::field::display(id));
    }
    parse_admission(request, row)
}

fn parse_admission(
    request: &RecoveryRouteSetAdmissionRequest,
    row: AdmissionRow,
) -> Result<RecoveryRouteSetAdmission, DriverError> {
    match row.0.as_str() {
        "acquired" => {
            if row.11.is_some() {
                return Err(invalid("acquired recovery route-set response is malformed"));
            }
            Ok(RecoveryRouteSetAdmission::Acquired(lease_from_row(
                request, &row,
            )?))
        }
        "replay" => {
            let lease = lease_from_row(request, &row)?;
            let response = parse_and_validate_response(
                row.11
                    .ok_or_else(|| invalid("replayed recovery route-set response is absent"))?,
                &lease,
            )?;
            Ok(RecoveryRouteSetAdmission::Replay(response))
        }
        "not_applied" => {
            let lease = lease_from_row(request, &row)?;
            Ok(RecoveryRouteSetAdmission::NotApplied(
                parse_not_applied_result(
                    row.11.ok_or_else(|| {
                        invalid("not-applied recovery route-set response is absent")
                    })?,
                    &lease,
                )?,
            ))
        }
        outcome => {
            let refusal = match outcome {
                "invalid" => RecoveryRouteSetAdmissionRefusal::Invalid,
                "protocol_inactive" => RecoveryRouteSetAdmissionRefusal::ProtocolInactive,
                "upstream_lease_lost" => RecoveryRouteSetAdmissionRefusal::UpstreamLeaseLost,
                "conflict" => RecoveryRouteSetAdmissionRefusal::Conflict,
                "busy" => RecoveryRouteSetAdmissionRefusal::Busy,
                "fleet_busy" => RecoveryRouteSetAdmissionRefusal::FleetBusy,
                "fleet_quarantined" => RecoveryRouteSetAdmissionRefusal::FleetQuarantined,
                "fleet_not_ready" => RecoveryRouteSetAdmissionRefusal::FleetNotReady,
                "not_maintenance" => RecoveryRouteSetAdmissionRefusal::NotMaintenance,
                "authority_lost" => RecoveryRouteSetAdmissionRefusal::AuthorityLost,
                "projection_missing" => RecoveryRouteSetAdmissionRefusal::ProjectionMissing,
                _ => return Err(invalid("recovery route-set admission outcome is invalid")),
            };
            if row.11.is_some() {
                return Err(invalid("recovery route-set refusal response is malformed"));
            }
            Ok(RecoveryRouteSetAdmission::Refused(refusal))
        }
    }
}

fn lease_from_row(
    request: &RecoveryRouteSetAdmissionRequest,
    row: &AdmissionRow,
) -> Result<RecoveryRouteSetPublicationLease, DriverError> {
    let publication_id = required_uuid(row.1, "publication id")?;
    let effect_run_id = required_uuid(row.2, "effect run id")?;
    let target_workshop_id = required_uuid(row.3, "target workshop id")?;
    if request
        .effect_run_id()
        .is_some_and(|expected| expected != effect_run_id)
    {
        return Err(invalid("recovery route-set effect owner changed"));
    }
    if target_workshop_id != request.workshop_id() {
        return Err(invalid("recovery route-set target workshop changed"));
    }
    let target_disposition = parse_disposition(
        row.10
            .as_deref()
            .ok_or_else(|| invalid("target disposition is absent"))?,
    )?;
    let (instance, execution, global, route, ttl) = request.authority();
    let core = RouteSetPublicationLease {
        publication_id,
        // Shared transition SQL does not consume this field. For recovery it
        // carries the effect-run logical owner and is never reinterpreted as a
        // deployment-driver operation by a recovery response validator.
        driver_operation_id: effect_run_id,
        publication_kind: request.publication_kind(),
        control_operation: request.control_operation().clone(),
        target_workshop_id,
        target_projection_generation: required_positive(row.8, "target generation")?,
        target_projection_digest: row
            .9
            .clone()
            .ok_or_else(|| invalid("target projection digest is absent"))?,
        expected_disposition: target_disposition,
        instance_owner: instance,
        execution_token: execution,
        global_lease_token: global,
        route_lease_token: route,
        global_fence_token: required_positive(row.4, "global fence")?,
        target_route_fence_token: required_positive(row.5, "target route fence")?,
        selector: row
            .6
            .clone()
            .ok_or_else(|| invalid("recovery route-set selector is absent"))?,
        snapshot_count: required_count(row.7)?,
        ttl_seconds: ttl,
    };
    validate_digest(&core.target_projection_digest, "target projection digest")
        .map_err(DriverError::internal)?;
    if core.selector
        != RouteSetGenerationName::new(publication_id, request.publication_kind()).selector_target()
        || (request.publication_kind() == RouteSetPublicationKind::RecoveryMaintenance
            && target_disposition != RouteSetAppliedDisposition::Present)
    {
        return Err(invalid("recovery route-set lease target is invalid"));
    }
    core.validate()?;
    Ok(RecoveryRouteSetPublicationLease {
        effect_run_id,
        core,
    })
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct RecoveryRouteEvidence {
    pub effect_run_id: Uuid,
    pub workshop_id: Uuid,
    pub generation: i64,
    pub projection_digest: String,
    pub disposition: RouteSetAppliedDisposition,
    pub rendered_digest: String,
    pub route_fence_token: i64,
    pub mode: RecoveryRouteMode,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum RecoveryRouteMode {
    Maintenance,
    Restored,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct RecoveryRouteSetPublicationResponse {
    pub outcome: String,
    pub effect_run_id: Uuid,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_fence_token: Option<i64>,
    pub route_evidence: RecoveryRouteEvidence,
    pub route_set_evidence: CompletedRouteSetEvidence,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum FinishRecoveryRouteSetPublicationOutcome {
    Completed(Box<RecoveryRouteSetPublicationResponse>),
    Replay(Box<RecoveryRouteSetPublicationResponse>),
    AuthorityLost,
    Conflict,
    WrongPhase,
    ProjectionDrift,
    Invalid,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum ReadRecoveryRouteSetPublicationResult {
    Absent,
    Pending,
    Completed(Box<RecoveryRouteSetPublicationResponse>),
    NotApplied(RecoveryRouteSetNotAppliedResult),
    Conflict,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct RecoveryRouteSetNotAppliedResult {
    pub publication_id: Uuid,
    pub effect_run_id: Uuid,
    pub publication_kind: RouteSetPublicationKind,
    pub target_workshop_id: Uuid,
    pub resolution_kind: String,
    pub decision_digest: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawNotAppliedResult {
    outcome: String,
    publication_id: Uuid,
    effect_run_id: Uuid,
    publication_kind: RouteSetPublicationKind,
    target_workshop_id: Uuid,
    resolution_claim_fence: i64,
    resolution_kind: String,
    reconciliation_operation_id: Uuid,
    reconciliation_operation_attempt: i32,
    reconciliation_operation_lease_owner: String,
    decision_digest: String,
    effect_response: Option<Value>,
}

type ResultRow = (
    String,
    Option<Uuid>,
    Option<Uuid>,
    Option<String>,
    Option<Value>,
);

#[tracing::instrument(
    name = "deployment_driver.route_set_recovery_publication.read_result_dormant",
    skip_all,
    fields(
        publication.id = %lease.core.publication_id,
        publication.kind = lease.core.publication_kind.as_str(),
        workshop_id = %lease.core.target_workshop_id,
        result.outcome = tracing::field::Empty
    )
)]
pub(super) async fn read_route_set_recovery_publication_result(
    ledger: &PgPool,
    lease: &RecoveryRouteSetPublicationLease,
) -> Result<ReadRecoveryRouteSetPublicationResult, DriverError> {
    lease.core.validate()?;
    let row: ResultRow = sqlx::query_as(
        "select outcome,publication_id,effect_run_id,publication_kind,response
           from control.read_route_set_recovery_publication_result($1,$2,$3)",
    )
    .bind(lease.core.publication_id)
    .bind(lease.effect_run_id)
    .bind(lease.core.control_operation.id)
    .fetch_one(ledger)
    .await
    .map_err(DriverError::internal)?;
    tracing::Span::current().record("result.outcome", row.0.as_str());
    parse_result_row(row, lease)
}

fn parse_result_row(
    row: ResultRow,
    lease: &RecoveryRouteSetPublicationLease,
) -> Result<ReadRecoveryRouteSetPublicationResult, DriverError> {
    match row.0.as_str() {
        "absent" if row.1.is_none() && row.2.is_none() && row.3.is_none() && row.4.is_none() => {
            Ok(ReadRecoveryRouteSetPublicationResult::Absent)
        }
        "conflict" if row.4.is_none() => Ok(ReadRecoveryRouteSetPublicationResult::Conflict),
        "pending" if row.4.is_none() => {
            validate_result_identity(&row, lease)?;
            Ok(ReadRecoveryRouteSetPublicationResult::Pending)
        }
        "completed" => {
            validate_result_identity(&row, lease)?;
            Ok(ReadRecoveryRouteSetPublicationResult::Completed(Box::new(
                parse_and_validate_response(
                    row.4.ok_or_else(|| {
                        invalid("completed recovery route-set response is absent")
                    })?,
                    lease,
                )?,
            )))
        }
        "not_applied" => {
            validate_result_identity(&row, lease)?;
            Ok(ReadRecoveryRouteSetPublicationResult::NotApplied(
                parse_not_applied_result(
                    row.4.ok_or_else(|| {
                        invalid("not-applied recovery route-set result is absent")
                    })?,
                    lease,
                )?,
            ))
        }
        _ => Err(invalid("recovery route-set result row is malformed")),
    }
}

fn parse_not_applied_result(
    value: Value,
    lease: &RecoveryRouteSetPublicationLease,
) -> Result<RecoveryRouteSetNotAppliedResult, DriverError> {
    exact_keys(
        &value,
        &[
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
        ],
        "not-applied recovery route-set result",
    )?;
    let raw: RawNotAppliedResult = serde_json::from_value(value)
        .map_err(|_| invalid("not-applied recovery route-set result is malformed"))?;
    if raw.outcome != "not_applied"
        || raw.publication_id != lease.core.publication_id
        || raw.effect_run_id != lease.effect_run_id
        || raw.publication_kind != lease.core.publication_kind
        || raw.target_workshop_id != lease.core.target_workshop_id
        || raw.resolution_claim_fence <= 0
        || !matches!(raw.resolution_kind.as_str(), "prior" | "unstarted")
        || raw.reconciliation_operation_id.is_nil()
        || raw.reconciliation_operation_attempt <= 0
        || raw.reconciliation_operation_lease_owner.trim().is_empty()
        || !valid_bare_sha256(&raw.decision_digest)
        || raw.effect_response.is_some()
    {
        return Err(invalid(
            "not-applied recovery route-set result identity is invalid",
        ));
    }
    Ok(RecoveryRouteSetNotAppliedResult {
        publication_id: raw.publication_id,
        effect_run_id: raw.effect_run_id,
        publication_kind: raw.publication_kind,
        target_workshop_id: raw.target_workshop_id,
        resolution_kind: raw.resolution_kind,
        decision_digest: raw.decision_digest,
    })
}

fn validate_result_identity(
    row: &ResultRow,
    lease: &RecoveryRouteSetPublicationLease,
) -> Result<(), DriverError> {
    if row.1 != Some(lease.core.publication_id)
        || row.2 != Some(lease.effect_run_id)
        || row.3.as_deref() != Some(lease.core.publication_kind.as_str())
    {
        return Err(invalid("recovery route-set result identity is invalid"));
    }
    Ok(())
}

#[tracing::instrument(
    name = "deployment_driver.route_set_recovery_publication.finish_dormant",
    skip_all,
    fields(
        publication.id = %lease.core.publication_id,
        publication.kind = lease.core.publication_kind.as_str(),
        workshop_id = %lease.core.target_workshop_id,
        transition.outcome = tracing::field::Empty
    )
)]
pub(super) async fn finish_route_set_recovery_publication(
    ledger: &PgPool,
    lease: &RecoveryRouteSetPublicationLease,
) -> Result<FinishRecoveryRouteSetPublicationOutcome, DriverError> {
    lease.core.validate()?;
    let (outcome, response): (String, Option<Value>) = sqlx::query_as(
        "select outcome,response from control.finish_route_set_recovery_publication(
           $1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(lease.core.publication_id)
    .bind(lease.core.instance_owner)
    .bind(lease.core.execution_token)
    .bind(lease.core.global_lease_token)
    .bind(lease.core.route_lease_token)
    .bind(lease.core.global_fence_token)
    .bind(lease.core.target_route_fence_token)
    .fetch_one(ledger)
    .await
    .map_err(DriverError::internal)?;
    tracing::Span::current().record("transition.outcome", outcome.as_str());
    match outcome.as_str() {
        "completed" | "replay" => {
            let response = parse_and_validate_response(
                response.ok_or_else(|| invalid("recovery route-set response is absent"))?,
                lease,
            )?;
            if outcome == "completed" {
                Ok(FinishRecoveryRouteSetPublicationOutcome::Completed(
                    Box::new(response),
                ))
            } else {
                Ok(FinishRecoveryRouteSetPublicationOutcome::Replay(Box::new(
                    response,
                )))
            }
        }
        "authority_lost" if response.is_none() => {
            Ok(FinishRecoveryRouteSetPublicationOutcome::AuthorityLost)
        }
        "conflict" if response.is_none() => Ok(FinishRecoveryRouteSetPublicationOutcome::Conflict),
        "wrong_phase" if response.is_none() => {
            Ok(FinishRecoveryRouteSetPublicationOutcome::WrongPhase)
        }
        "projection_drift" if response.is_none() => {
            Ok(FinishRecoveryRouteSetPublicationOutcome::ProjectionDrift)
        }
        "invalid" if response.is_none() => Ok(FinishRecoveryRouteSetPublicationOutcome::Invalid),
        _ => Err(invalid("finish recovery route-set outcome is invalid")),
    }
}

pub(super) fn parse_and_validate_response(
    value: Value,
    lease: &RecoveryRouteSetPublicationLease,
) -> Result<RecoveryRouteSetPublicationResponse, DriverError> {
    let expected_keys: &[&str] = match lease.core.publication_kind {
        RouteSetPublicationKind::RecoveryMaintenance => &[
            "outcome",
            "effect_run_id",
            "route_fence_token",
            "route_evidence",
            "route_set_evidence",
        ],
        RouteSetPublicationKind::RecoveryRestore => &[
            "outcome",
            "effect_run_id",
            "route_evidence",
            "route_set_evidence",
        ],
        RouteSetPublicationKind::Projection | RouteSetPublicationKind::Startup => {
            return Err(invalid("projection response used recovery validator"));
        }
    };
    exact_keys(&value, expected_keys, "recovery route-set response")?;
    let response: RecoveryRouteSetPublicationResponse = serde_json::from_value(value)
        .map_err(|_| invalid("recovery route-set response is malformed"))?;
    validate_response(&response, lease)?;
    Ok(response)
}

pub(super) fn parse_recovery_response_for_kind(
    value: Value,
    publication_kind: RouteSetPublicationKind,
) -> Result<RecoveryRouteSetPublicationResponse, DriverError> {
    let expected_keys: &[&str] = match publication_kind {
        RouteSetPublicationKind::RecoveryMaintenance => &[
            "outcome",
            "effect_run_id",
            "route_fence_token",
            "route_evidence",
            "route_set_evidence",
        ],
        RouteSetPublicationKind::RecoveryRestore => &[
            "outcome",
            "effect_run_id",
            "route_evidence",
            "route_set_evidence",
        ],
        RouteSetPublicationKind::Projection | RouteSetPublicationKind::Startup => {
            return Err(invalid("projection response used recovery parser"));
        }
    };
    exact_keys(&value, expected_keys, "recovery route-set response")?;
    serde_json::from_value(value).map_err(|_| invalid("recovery route-set response is malformed"))
}

fn validate_response(
    response: &RecoveryRouteSetPublicationResponse,
    lease: &RecoveryRouteSetPublicationLease,
) -> Result<(), DriverError> {
    let core = &lease.core;
    let evidence = &response.route_evidence;
    let set = &response.route_set_evidence;
    let (outcome, mode, top_fence) = match core.publication_kind {
        RouteSetPublicationKind::RecoveryMaintenance => (
            "maintenance",
            RecoveryRouteMode::Maintenance,
            Some(core.target_route_fence_token),
        ),
        RouteSetPublicationKind::RecoveryRestore => ("restored", RecoveryRouteMode::Restored, None),
        RouteSetPublicationKind::Projection | RouteSetPublicationKind::Startup => {
            return Err(invalid("projection response used recovery validator"));
        }
    };
    if response.outcome != outcome
        || response.effect_run_id != lease.effect_run_id
        || response.route_fence_token != top_fence
        || evidence.effect_run_id != lease.effect_run_id
        || evidence.workshop_id != core.target_workshop_id
        || evidence.generation != core.target_projection_generation
        || evidence.projection_digest != core.target_projection_digest
        || evidence.disposition != core.expected_disposition
        || evidence.route_fence_token != core.target_route_fence_token
        || evidence.mode != mode
        || !valid_sha256(&evidence.rendered_digest)
        || (evidence.disposition == RouteSetAppliedDisposition::Absent
            && evidence.rendered_digest != EMPTY_RENDERED_DIGEST)
        || set.protocol_version != 1
        || set.publication_id != core.publication_id
        || set.publication_kind != core.publication_kind
        || set.selector != core.selector
        || !valid_sha256(&set.route_set_digest)
        || set.snapshot_count != core.snapshot_count
        || set.present_count > set.snapshot_count
        || set.global_fence_token != core.global_fence_token
        || set.directory_device == 0
        || set.directory_inode == 0
        || i64::try_from(set.directory_device).is_err()
        || i64::try_from(set.directory_inode).is_err()
    {
        return Err(invalid("recovery route-set response identity is invalid"));
    }
    Ok(())
}

fn exact_keys(value: &Value, expected: &[&str], name: &str) -> Result<(), DriverError> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid(format!("{name} is not an object")))?;
    if object.len() != expected.len() || expected.iter().any(|key| !object.contains_key(*key)) {
        return Err(invalid(format!("{name} keys are invalid")));
    }
    Ok(())
}

fn parse_disposition(value: &str) -> Result<RouteSetAppliedDisposition, DriverError> {
    match value {
        "present" => Ok(RouteSetAppliedDisposition::Present),
        "absent" => Ok(RouteSetAppliedDisposition::Absent),
        _ => Err(invalid("recovery route-set target disposition is invalid")),
    }
}

fn required_uuid(value: Option<Uuid>, name: &str) -> Result<Uuid, DriverError> {
    value
        .filter(|value| !value.is_nil())
        .ok_or_else(|| invalid(format!("recovery route-set {name} is invalid")))
}

fn required_positive(value: Option<i64>, name: &str) -> Result<i64, DriverError> {
    value
        .filter(|value| *value > 0)
        .ok_or_else(|| invalid(format!("recovery route-set {name} is invalid")))
}

fn required_count(value: Option<i32>) -> Result<usize, DriverError> {
    value
        .and_then(|value| usize::try_from(value).ok())
        .filter(|value| (1..=MAX_ROUTES).contains(value))
        .ok_or_else(|| invalid("recovery route-set snapshot count is invalid"))
}

fn valid_bare_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn valid_sha256(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(valid_bare_sha256)
}

fn invalid(message: impl Into<String>) -> DriverError {
    DriverError::internal(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn operation() -> ControlOperationLease {
        ControlOperationLease {
            id: Uuid::new_v4(),
            attempt: 3,
            owner: "tenant-lifecycle-1".into(),
        }
    }

    fn request(kind: RouteSetPublicationKind) -> RecoveryRouteSetAdmissionRequest {
        let common = (
            operation(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
        );
        match kind {
            RouteSetPublicationKind::RecoveryMaintenance => {
                RecoveryRouteSetAdmissionRequest::Maintenance {
                    control_operation: common.0,
                    workshop_id: common.1,
                    idempotency_key: "recovery-entry".into(),
                    request_digest: "a".repeat(64),
                    instance_owner: common.2,
                    execution_token: common.3,
                    global_lease_token: common.4,
                    route_lease_token: common.5,
                    ttl_seconds: 120,
                }
            }
            RouteSetPublicationKind::RecoveryRestore => RecoveryRouteSetAdmissionRequest::Restore {
                effect_run_id: Uuid::new_v4(),
                control_operation: common.0,
                workshop_id: common.1,
                instance_owner: common.2,
                execution_token: common.3,
                global_lease_token: common.4,
                route_lease_token: common.5,
                ttl_seconds: 120,
            },
            RouteSetPublicationKind::Projection | RouteSetPublicationKind::Startup => {
                unreachable!()
            }
        }
    }

    fn lease(kind: RouteSetPublicationKind, disposition: &str) -> RecoveryRouteSetPublicationLease {
        let request = request(kind);
        let publication = Uuid::new_v4();
        let effect = request.effect_run_id().unwrap_or_else(Uuid::new_v4);
        lease_from_row(
            &request,
            &(
                "acquired".into(),
                Some(publication),
                Some(effect),
                Some(request.workshop_id()),
                Some(8),
                Some(13),
                Some(RouteSetGenerationName::new(publication, kind).selector_target()),
                Some(2),
                Some(17),
                Some(format!("sha256:{}", "b".repeat(64))),
                Some(disposition.into()),
                None,
            ),
        )
        .unwrap()
    }

    fn response(lease: &RecoveryRouteSetPublicationLease) -> Value {
        let maintenance =
            lease.core.publication_kind == RouteSetPublicationKind::RecoveryMaintenance;
        let mut value = json!({
            "outcome": if maintenance { "maintenance" } else { "restored" },
            "effect_run_id": lease.effect_run_id,
            "route_evidence": {
                "effect_run_id": lease.effect_run_id,
                "workshop_id": lease.core.target_workshop_id,
                "generation": lease.core.target_projection_generation,
                "projection_digest": lease.core.target_projection_digest,
                "disposition": if lease.core.expected_disposition == RouteSetAppliedDisposition::Present { "present" } else { "absent" },
                "rendered_digest": if lease.core.expected_disposition == RouteSetAppliedDisposition::Present { format!("sha256:{}", "c".repeat(64)) } else { EMPTY_RENDERED_DIGEST.into() },
                "route_fence_token": lease.core.target_route_fence_token,
                "mode": if maintenance { "maintenance" } else { "restored" }
            },
            "route_set_evidence": {
                "protocol_version": 1,
                "publication_id": lease.core.publication_id,
                "publication_kind": lease.core.publication_kind,
                "selector": lease.core.selector,
                "route_set_digest": format!("sha256:{}", "d".repeat(64)),
                "snapshot_count": lease.core.snapshot_count,
                "present_count": 1,
                "global_fence_token": lease.core.global_fence_token,
                "directory_device": 7,
                "directory_inode": 9
            }
        });
        if maintenance {
            value["route_fence_token"] = json!(lease.core.target_route_fence_token);
        }
        value
    }

    #[test]
    fn recovery_admission_requests_are_closed_by_kind() {
        assert!(
            request(RouteSetPublicationKind::RecoveryMaintenance)
                .validate()
                .is_ok()
        );
        assert!(
            request(RouteSetPublicationKind::RecoveryRestore)
                .validate()
                .is_ok()
        );
        let mut bad = request(RouteSetPublicationKind::RecoveryMaintenance);
        if let RecoveryRouteSetAdmissionRequest::Maintenance { request_digest, .. } = &mut bad {
            *request_digest = "A".repeat(64);
        }
        assert!(bad.validate().is_err());

        let request = request(RouteSetPublicationKind::RecoveryRestore);
        let publication = Uuid::new_v4();
        let effect = request.effect_run_id().unwrap();
        assert!(
            lease_from_row(
                &request,
                &(
                    "acquired".into(),
                    Some(publication),
                    Some(effect),
                    Some(Uuid::new_v4()),
                    Some(8),
                    Some(13),
                    Some(
                        RouteSetGenerationName::new(publication, request.publication_kind())
                            .selector_target()
                    ),
                    Some(2),
                    Some(17),
                    Some(format!("sha256:{}", "b".repeat(64))),
                    Some("present".into()),
                    None,
                )
            )
            .is_err()
        );
    }

    #[test]
    fn read_only_admission_is_exactly_absent_and_can_never_acquire() {
        let request = request(RouteSetPublicationKind::RecoveryRestore);
        assert!(matches!(
            parse_read_admission(
                &request,
                (
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
                ),
            )
            .unwrap(),
            ReadRecoveryRouteSetAdmission::Absent
        ));
        let publication_id = Uuid::new_v4();
        assert!(
            parse_read_admission(
                &request,
                (
                    "acquired".into(),
                    Some(publication_id),
                    request.effect_run_id(),
                    Some(request.workshop_id()),
                    Some(8),
                    Some(13),
                    Some(
                        RouteSetGenerationName::new(publication_id, request.publication_kind())
                            .selector_target()
                    ),
                    Some(2),
                    Some(17),
                    Some(format!("sha256:{}", "b".repeat(64))),
                    Some("present".into()),
                    None,
                ),
            )
            .is_err()
        );
    }

    #[test]
    fn exact_maintenance_and_changed_or_absent_restore_responses_validate() {
        let maintenance = lease(RouteSetPublicationKind::RecoveryMaintenance, "present");
        assert!(parse_and_validate_response(response(&maintenance), &maintenance).is_ok());
        let restore = lease(RouteSetPublicationKind::RecoveryRestore, "present");
        assert!(parse_and_validate_response(response(&restore), &restore).is_ok());
        let absent = lease(RouteSetPublicationKind::RecoveryRestore, "absent");
        assert!(parse_and_validate_response(response(&absent), &absent).is_ok());
    }

    #[test]
    fn response_validation_rejects_cross_kind_extra_keys_and_absent_bytes() {
        let restore = lease(RouteSetPublicationKind::RecoveryRestore, "absent");
        let mut value = response(&restore);
        value["route_fence_token"] = json!(restore.core.target_route_fence_token);
        assert!(parse_and_validate_response(value, &restore).is_err());
        let mut value = response(&restore);
        value["route_evidence"]["rendered_digest"] = json!(format!("sha256:{}", "e".repeat(64)));
        assert!(parse_and_validate_response(value, &restore).is_err());
    }

    #[test]
    fn result_reader_has_a_typed_exact_not_applied_terminal() {
        let lease = lease(RouteSetPublicationKind::RecoveryRestore, "present");
        let value = json!({
            "outcome":"not_applied",
            "publication_id":lease.core.publication_id,
            "effect_run_id":lease.effect_run_id,
            "publication_kind":lease.core.publication_kind,
            "target_workshop_id":lease.core.target_workshop_id,
            "resolution_claim_fence":4,
            "resolution_kind":"prior",
            "reconciliation_operation_id":Uuid::new_v4(),
            "reconciliation_operation_attempt":2,
            "reconciliation_operation_lease_owner":"reconciler",
            "decision_digest":"e".repeat(64),
            "effect_response":Value::Null
        });
        assert!(matches!(
            parse_result_row(
                (
                    "not_applied".into(),
                    Some(lease.core.publication_id),
                    Some(lease.effect_run_id),
                    Some(lease.core.publication_kind.as_str().into()),
                    Some(value.clone()),
                ),
                &lease,
            )
            .unwrap(),
            ReadRecoveryRouteSetPublicationResult::NotApplied(_)
        ));
        let mut extra = value;
        extra["foreign"] = json!(true);
        assert!(
            parse_result_row(
                (
                    "not_applied".into(),
                    Some(lease.core.publication_id),
                    Some(lease.effect_run_id),
                    Some(lease.core.publication_kind.as_str().into()),
                    Some(extra),
                ),
                &lease,
            )
            .is_err()
        );
    }

    #[test]
    fn admission_not_applied_is_a_closed_typed_terminal() {
        let request = request(RouteSetPublicationKind::RecoveryRestore);
        let publication_id = Uuid::new_v4();
        let effect_run_id = request.effect_run_id().unwrap();
        let response = json!({
            "outcome":"not_applied",
            "publication_id":publication_id,
            "effect_run_id":effect_run_id,
            "publication_kind":"recovery_restore",
            "target_workshop_id":request.workshop_id(),
            "resolution_claim_fence":4,
            "resolution_kind":"unstarted",
            "reconciliation_operation_id":Uuid::new_v4(),
            "reconciliation_operation_attempt":2,
            "reconciliation_operation_lease_owner":"reconciler",
            "decision_digest":"e".repeat(64),
            "effect_response":Value::Null
        });
        assert!(matches!(
            parse_admission(
                &request,
                (
                    "not_applied".into(),
                    Some(publication_id),
                    Some(effect_run_id),
                    Some(request.workshop_id()),
                    Some(8),
                    Some(13),
                    Some(
                        RouteSetGenerationName::new(publication_id, request.publication_kind())
                            .selector_target()
                    ),
                    Some(2),
                    Some(17),
                    Some(format!("sha256:{}", "b".repeat(64))),
                    Some("present".into()),
                    Some(response),
                ),
            )
            .unwrap(),
            RecoveryRouteSetAdmission::NotApplied(_)
        ));
    }

    #[test]
    fn sql_bindings_are_exact_dormant_and_privacy_safe() {
        let source = include_str!("route_set_recovery_publication_db.rs");
        let migration = include_str!("../../migrations/0033_route_set_recovery_publications.sql");
        assert!(migration.contains(
            "outcome text,publication_id uuid,effect_run_id uuid,target_workshop_id uuid,global_fence_token bigint"
        ));
        assert!(migration.contains(
            "read_route_set_recovery_publication_result(\n p_publication_id uuid,p_effect_run_id uuid,p_control_operation_id uuid"
        ));
        assert!(migration.contains("read_route_set_recovery_maintenance_admission(\n p_workshop_id uuid,p_control_operation_id uuid,p_control_operation_attempt integer,"));
        assert!(migration.contains("read_route_set_recovery_restore_admission(\n p_effect_run_id uuid,p_workshop_id uuid,p_control_operation_id uuid,"));
        assert!(source.contains("admit_route_set_recovery_maintenance(\n                 $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)"));
        assert!(source.contains(
            "admit_route_set_recovery_restore(\n                 $1,$2,$3,$4,$5,$6,$7,$8,$9,$10)"
        ));
        assert!(
            source.contains(
                "finish_route_set_recovery_publication(\n           $1,$2,$3,$4,$5,$6,$7)"
            )
        );
        assert!(source.contains(
            "read_route_set_recovery_maintenance_admission(\n                 $1,$2,$3,$4,$5,$6)"
        ));
        assert!(source.contains(
            "read_route_set_recovery_restore_admission(\n                 $1,$2,$3,$4,$5)"
        ));
        assert!(source.contains("read_route_set_recovery_publication_result($1,$2,$3)"));
        let production = source.split("#[cfg(test)]").next().unwrap();
        for private in [
            "execution_token = %",
            "global_lease_token = %",
            "route_lease_token = %",
        ] {
            assert!(!production.contains(private));
        }
        let active = include_str!("../docker_driver.rs");
        assert!(!active.contains("admit_route_set_recovery_publication("));
    }
}
