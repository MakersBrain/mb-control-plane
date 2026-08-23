//! Dormant typed database boundary for migration 0027 route-set admission.
//!
//! Migration 0027 exposes only projection admission, authority renewal, and a
//! bounded immutable snapshot read. Later selector transitions and recovery
//! admissions deliberately do not belong here. Merely registering this module
//! must not call any function or acquire any authority.
#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

use super::gateway::{
    GatewayGenerationIdentity, ReleaseOverlayGenerationIdentity, RouteSetGenerationIdentity,
    RouteSetPublicationKind,
};
use super::route_generation_fs::PriorSelector;
use super::route_projection::RouteDisposition;
use super::route_set_generation_fs::{
    MAX_ROUTES, RouteSetGenerationName, RouteSetSealEvidence, SealedRouteSetGeneration,
};
use super::route_set_staging::FrozenRouteSetSnapshotItem;
use super::{ControlOperationLease, DriverError};

const MIN_LEASE_SECONDS: i32 = 60;
const MAX_LEASE_SECONDS: i32 = 1200;
const MAX_CANONICAL_PROJECTION_BYTES: usize = 65_536;
const EMPTY_RENDERED_DIGEST: &str =
    "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

#[derive(Clone)]
pub(super) struct RouteSetPublicationAdmissionRequest {
    pub control_operation: ControlOperationLease,
    pub workshop_id: Uuid,
    pub publication_kind: RouteSetPublicationKind,
    pub idempotency_key: String,
    pub request_digest: String,
    pub projection_generation: i64,
    pub projection_digest: String,
    /// Trusted local expectation used to validate completed result replay. It
    /// is not caller-supplied to the admission SQL; the database still derives
    /// the frozen target disposition from its immutable projection row.
    pub expected_disposition: RouteSetAppliedDisposition,
    pub instance_owner: Uuid,
    pub execution_token: Uuid,
    pub global_lease_token: Uuid,
    pub route_lease_token: Uuid,
    pub ttl_seconds: i32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct RouteSetPublicationResultRequest {
    pub control_operation_id: Uuid,
    pub workshop_id: Uuid,
    pub idempotency_key: String,
    pub request_digest: String,
    pub expected_generation: i64,
    pub expected_projection_digest: String,
    pub expected_disposition: RouteSetAppliedDisposition,
}

#[derive(Clone)]
pub(super) struct RouteSetPublicationLease {
    pub publication_id: Uuid,
    pub driver_operation_id: Uuid,
    pub publication_kind: RouteSetPublicationKind,
    pub control_operation: ControlOperationLease,
    pub target_workshop_id: Uuid,
    pub target_projection_generation: i64,
    pub target_projection_digest: String,
    pub expected_disposition: RouteSetAppliedDisposition,
    pub instance_owner: Uuid,
    pub execution_token: Uuid,
    pub global_lease_token: Uuid,
    pub route_lease_token: Uuid,
    pub global_fence_token: i64,
    pub target_route_fence_token: i64,
    pub selector: String,
    pub snapshot_count: usize,
    pub ttl_seconds: i32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RouteSetPublicationRefusalKind {
    Invalid,
    UpstreamLeaseLost,
    ProtocolInactive,
    LegacyReceipt,
    Conflict,
    AuthorityLost,
    FleetQuarantined,
    FleetBusy,
    FleetNotReady,
}

impl RouteSetPublicationRefusalKind {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "invalid" => Some(Self::Invalid),
            "upstream_lease_lost" => Some(Self::UpstreamLeaseLost),
            "protocol_inactive" => Some(Self::ProtocolInactive),
            "legacy_receipt" => Some(Self::LegacyReceipt),
            "conflict" => Some(Self::Conflict),
            "authority_lost" => Some(Self::AuthorityLost),
            "fleet_quarantined" => Some(Self::FleetQuarantined),
            "fleet_busy" => Some(Self::FleetBusy),
            "fleet_not_ready" => Some(Self::FleetNotReady),
            _ => None,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Invalid => "invalid",
            Self::UpstreamLeaseLost => "upstream_lease_lost",
            Self::ProtocolInactive => "protocol_inactive",
            Self::LegacyReceipt => "legacy_receipt",
            Self::Conflict => "conflict",
            Self::AuthorityLost => "authority_lost",
            Self::FleetQuarantined => "fleet_quarantined",
            Self::FleetBusy => "fleet_busy",
            Self::FleetNotReady => "fleet_not_ready",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct RouteSetPublicationRefusal {
    pub kind: RouteSetPublicationRefusalKind,
    pub publication_id: Option<Uuid>,
    pub driver_operation_id: Option<Uuid>,
    pub global_fence_token: Option<i64>,
    pub target_route_fence_token: Option<i64>,
    pub selector: Option<String>,
    pub snapshot_count: Option<usize>,
}

pub(super) enum RouteSetPublicationAdmission {
    Acquired(RouteSetPublicationLease),
    Replay(RouteSetPublicationLease),
    Refused(RouteSetPublicationRefusal),
}

#[derive(Clone, Debug, PartialEq)]
pub(super) struct FrozenSnapshotItem {
    pub workshop_id: Uuid,
    pub projection_generation: i64,
    pub projection_digest: String,
    pub disposition: RouteDisposition,
    pub canonical_projection: Value,
    pub applied_rendered_digest: String,
    pub is_target: bool,
}

impl FrozenSnapshotItem {
    pub(super) fn into_staging_item(self) -> FrozenRouteSetSnapshotItem {
        FrozenRouteSetSnapshotItem {
            workshop_id: self.workshop_id,
            projection_generation: self.projection_generation,
            projection_digest: self.projection_digest,
            disposition: self.disposition,
            canonical_projection: Some(self.canonical_projection),
            applied_rendered_digest: self.applied_rendered_digest,
        }
    }
}

type AdmissionRow = (
    String,
    Option<Uuid>,
    Option<Uuid>,
    Option<i64>,
    Option<i64>,
    Option<String>,
    Option<i32>,
);

type SnapshotRow = (Uuid, i64, String, String, Value, String, bool);
type PublicationResultRow = (String, Option<Uuid>, Option<Uuid>, Option<Value>);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RecordRouteSetPriorOutcome {
    Recorded,
    Replay,
    AuthorityLost,
    Conflict,
    WrongPhase,
    Invalid,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RecordRouteSetEntryOutcome {
    Recorded,
    Replay,
    AuthorityLost,
    Invalid,
    Conflict,
    WrongPhase,
    PriorAbsent,
    OutOfOrder,
    SnapshotDrift,
    RenderInvariantMismatch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SealRouteSetPublicationOutcome {
    Sealed,
    Replay,
    AuthorityLost,
    WrongPhase,
    PriorAbsent,
    Invalid,
    PriorDirectoryReused,
    CountMismatch,
    PresentCountMismatch,
    DigestMismatch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum StartRouteSetPublicationOutcome {
    Started,
    Replay,
    AuthorityLost,
    WrongPhase,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ObserveRouteSetPublicationOutcome {
    Observed,
    Replay,
    AuthorityLost,
    ObservationMismatch,
    WrongPhase,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct RouteSetAppliedEvidence {
    pub driver_operation_id: Uuid,
    pub workshop_id: Uuid,
    pub route_generation: i64,
    pub projection_digest: String,
    pub disposition: RouteSetAppliedDisposition,
    pub rendered_digest: String,
    pub route_fence_token: i64,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum RouteSetAppliedDisposition {
    Present,
    Absent,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct CompletedRouteSetEvidence {
    pub protocol_version: u8,
    pub publication_id: Uuid,
    pub publication_kind: RouteSetPublicationKind,
    pub selector: String,
    pub route_set_digest: String,
    pub snapshot_count: usize,
    pub present_count: usize,
    pub global_fence_token: i64,
    pub directory_device: u64,
    pub directory_inode: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct RouteSetPublicationResponse {
    pub outcome: String,
    pub workshop_id: Uuid,
    pub route_evidence: RouteSetAppliedEvidence,
    pub route_set_evidence: CompletedRouteSetEvidence,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum FinishRouteSetPublicationOutcome {
    Completed(RouteSetPublicationResponse),
    Replay(RouteSetPublicationResponse),
    AuthorityLost,
    Conflict,
    WrongPhase,
    Invalid,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum ReadRouteSetPublicationResult {
    Absent,
    Conflict,
    Pending {
        publication_id: Uuid,
        driver_operation_id: Uuid,
    },
    Completed {
        publication_id: Uuid,
        driver_operation_id: Uuid,
        response: Box<RouteSetPublicationResponse>,
    },
    NotApplied(RouteSetPublicationNotApplied),
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct RouteSetPublicationNotApplied {
    pub outcome: String,
    pub publication_id: Uuid,
    pub driver_operation_id: Uuid,
    pub resolution_kind: String,
    pub safe_error: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum RouteSetPriorLoadedIdentity {
    Startup(GatewayGenerationIdentity),
    Release(ReleaseOverlayGenerationIdentity),
    RouteSet(RouteSetGenerationIdentity),
}

impl RouteSetPriorLoadedIdentity {
    fn validate_for_selector(&self, selector: &str) -> Result<Value, DriverError> {
        let expected = match self {
            Self::Startup(identity) => {
                if identity.effect_run_id.is_nil() || !valid_sha256(&identity.sealed_digest) {
                    return Err(DriverError::internal(
                        "startup prior route identity is invalid",
                    ));
                }
                format!("generations/startup-{}", identity.effect_run_id)
            }
            Self::Release(identity) => {
                identity.validate()?;
                format!(
                    "generations/release-{}-{}",
                    identity.fleet_run_id.simple(),
                    identity.overlay_kind.as_str()
                )
            }
            Self::RouteSet(identity) => {
                identity.validate()?;
                RouteSetGenerationName::new(identity.publication_id, identity.publication_kind)
                    .selector_target()
            }
        };
        if selector != expected {
            return Err(DriverError::internal(
                "prior route selector differs from its loaded identity",
            ));
        }
        let value = match self {
            Self::Startup(identity) => serde_json::to_value(identity),
            Self::Release(identity) => serde_json::to_value(identity),
            Self::RouteSet(identity) => serde_json::to_value(identity),
        }
        .map_err(DriverError::internal)?;
        if serde_json::to_vec(&value)
            .map_err(DriverError::internal)?
            .len()
            > 4096
        {
            return Err(DriverError::internal(
                "prior route identity exceeded its bound",
            ));
        }
        Ok(value)
    }
}

#[tracing::instrument(
    name = "deployment_driver.route_set_publication.admit_dormant",
    skip_all,
    fields(
        workshop_id = %request.workshop_id,
        publication.kind = request.publication_kind.as_str(),
        publication.id = tracing::field::Empty,
        publication.outcome = tracing::field::Empty,
        snapshot.count = tracing::field::Empty
    )
)]
pub(super) async fn admit_route_set_publication(
    ledger: &PgPool,
    request: &RouteSetPublicationAdmissionRequest,
) -> Result<RouteSetPublicationAdmission, DriverError> {
    request.validate()?;
    let row = sqlx::query_as::<_, AdmissionRow>(
        "select outcome,publication_id,driver_operation_id,global_fence_token,
                target_route_fence_token,selector,snapshot_count
           from control.admit_route_set_publication(
             $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)",
    )
    .bind(request.control_operation.id)
    .bind(request.control_operation.attempt)
    .bind(&request.control_operation.owner)
    .bind(request.workshop_id)
    .bind(request.publication_kind.as_str())
    .bind(&request.idempotency_key)
    .bind(&request.request_digest)
    .bind(request.projection_generation)
    .bind(&request.projection_digest)
    .bind(request.instance_owner)
    .bind(request.execution_token)
    .bind(request.global_lease_token)
    .bind(request.route_lease_token)
    .bind(request.ttl_seconds)
    .fetch_one(ledger)
    .await
    .map_err(DriverError::internal)?;

    tracing::Span::current().record("publication.outcome", row.0.as_str());
    if let Some(publication_id) = row.1 {
        tracing::Span::current().record("publication.id", tracing::field::display(publication_id));
    }
    if let Some(snapshot_count) = row.6 {
        tracing::Span::current().record("snapshot.count", snapshot_count);
    }

    match row.0.as_str() {
        "acquired" | "replay" => {
            let lease = lease_from_admission_row(request, &row)?;
            if row.0 == "acquired" {
                Ok(RouteSetPublicationAdmission::Acquired(lease))
            } else {
                Ok(RouteSetPublicationAdmission::Replay(lease))
            }
        }
        outcome => {
            let kind = RouteSetPublicationRefusalKind::parse(outcome).ok_or_else(|| {
                DriverError::internal("route-set publication admission outcome is invalid")
            })?;
            Ok(RouteSetPublicationAdmission::Refused(
                RouteSetPublicationRefusal {
                    kind,
                    publication_id: valid_optional_uuid(row.1)?,
                    driver_operation_id: valid_optional_uuid(row.2)?,
                    global_fence_token: valid_optional_fence(row.3)?,
                    target_route_fence_token: valid_optional_fence(row.4)?,
                    selector: validate_optional_selector(row.1, request.publication_kind, row.5)?,
                    snapshot_count: valid_optional_count(row.6)?,
                },
            ))
        }
    }
}

#[tracing::instrument(
    name = "deployment_driver.route_set_publication.renew_dormant",
    skip_all,
    fields(
        publication.id = %lease.publication_id,
        publication.kind = lease.publication_kind.as_str(),
        workshop_id = %lease.target_workshop_id,
        publication.global_fence = lease.global_fence_token,
        publication.route_fence = lease.target_route_fence_token,
        lease.renewed = tracing::field::Empty
    )
)]
pub(super) async fn renew_route_set_publication(
    ledger: &PgPool,
    lease: &RouteSetPublicationLease,
) -> Result<bool, DriverError> {
    lease.validate()?;
    let renewed = sqlx::query_scalar::<_, bool>(
        "select control.renew_route_set_publication($1,$2,$3,$4,$5,$6,$7,$8)",
    )
    .bind(lease.publication_id)
    .bind(lease.instance_owner)
    .bind(lease.execution_token)
    .bind(lease.global_lease_token)
    .bind(lease.route_lease_token)
    .bind(lease.global_fence_token)
    .bind(lease.target_route_fence_token)
    .bind(lease.ttl_seconds)
    .fetch_one(ledger)
    .await
    .map_err(DriverError::internal)?;
    tracing::Span::current().record("lease.renewed", renewed);
    Ok(renewed)
}

#[tracing::instrument(
    name = "deployment_driver.route_set_publication.read_snapshot_dormant",
    skip_all,
    fields(
        publication.id = %lease.publication_id,
        publication.kind = lease.publication_kind.as_str(),
        workshop_id = %lease.target_workshop_id,
        snapshot.limit = limit,
        snapshot.returned = tracing::field::Empty
    )
)]
pub(super) async fn read_route_set_publication_snapshot_batch(
    ledger: &PgPool,
    lease: &RouteSetPublicationLease,
    after_workshop_id: Option<Uuid>,
    limit: usize,
) -> Result<Vec<FrozenSnapshotItem>, DriverError> {
    // Migration 0027 deliberately represents failed authority as an empty
    // batch. A future orchestrator must renew first and require the cumulative
    // row count to equal `lease.snapshot_count`; this adapter does not invent a
    // stronger read outcome than the SQL contract provides.
    lease.validate()?;
    if limit == 0
        || limit > MAX_ROUTES
        || after_workshop_id.is_some_and(|workshop| workshop.is_nil())
    {
        return Err(DriverError::internal(
            "route-set snapshot batch request is invalid",
        ));
    }
    let sql_limit = i32::try_from(limit)
        .map_err(|_| DriverError::internal("route-set snapshot batch limit is invalid"))?;
    let rows = sqlx::query_as::<_, SnapshotRow>(
        "select workshop_id,generation,projection_digest,disposition,
                canonical_projection,applied_rendered_digest,is_target
           from control.read_route_set_publication_snapshot_batch(
             $1,$2,$3,$4,$5,$6,$7,$8,$9)",
    )
    .bind(lease.publication_id)
    .bind(lease.instance_owner)
    .bind(lease.execution_token)
    .bind(lease.global_lease_token)
    .bind(lease.route_lease_token)
    .bind(lease.global_fence_token)
    .bind(lease.target_route_fence_token)
    .bind(after_workshop_id)
    .bind(sql_limit)
    .fetch_all(ledger)
    .await
    .map_err(DriverError::internal)?;
    let items = validate_snapshot_rows(lease, after_workshop_id, limit, rows)?;
    tracing::Span::current().record("snapshot.returned", items.len());
    Ok(items)
}

#[tracing::instrument(
    name = "deployment_driver.route_set_publication.record_prior_dormant",
    skip_all,
    fields(
        publication.id = %lease.publication_id,
        publication.kind = lease.publication_kind.as_str(),
        workshop_id = %lease.target_workshop_id,
        transition.outcome = tracing::field::Empty
    )
)]
pub(super) async fn record_route_set_publication_prior(
    ledger: &PgPool,
    lease: &RouteSetPublicationLease,
    prior: &PriorSelector,
    loaded_identity: Option<&RouteSetPriorLoadedIdentity>,
) -> Result<RecordRouteSetPriorOutcome, DriverError> {
    lease.validate()?;
    let loaded_identity = validate_prior_evidence(prior, loaded_identity)?;
    let outcome = sqlx::query_scalar::<_, String>(
        "select control.record_route_set_publication_prior(
           $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
    )
    .bind(lease.publication_id)
    .bind(lease.instance_owner)
    .bind(lease.execution_token)
    .bind(lease.global_lease_token)
    .bind(lease.route_lease_token)
    .bind(lease.global_fence_token)
    .bind(lease.target_route_fence_token)
    .bind(prior.target())
    .bind(pg_file_identity(prior.directory_device())?)
    .bind(pg_file_identity(prior.directory_inode())?)
    .bind(loaded_identity)
    .fetch_one(ledger)
    .await
    .map_err(DriverError::internal)?;
    tracing::Span::current().record("transition.outcome", outcome.as_str());
    parse_record_prior_outcome(&outcome)
}

#[tracing::instrument(
    name = "deployment_driver.route_set_publication.record_entry_dormant",
    skip_all,
    fields(
        publication.id = %lease.publication_id,
        publication.kind = lease.publication_kind.as_str(),
        workshop_id = %evidence.workshop_id,
        transition.outcome = tracing::field::Empty
    )
)]
pub(super) async fn record_route_set_publication_entry(
    ledger: &PgPool,
    lease: &RouteSetPublicationLease,
    evidence: &RouteSetSealEvidence,
) -> Result<RecordRouteSetEntryOutcome, DriverError> {
    lease.validate()?;
    validate_seal_evidence(evidence)?;
    let outcome = sqlx::query_scalar::<_, String>(
        "select control.record_route_set_publication_entry(
           $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
    )
    .bind(lease.publication_id)
    .bind(lease.instance_owner)
    .bind(lease.execution_token)
    .bind(lease.global_lease_token)
    .bind(lease.route_lease_token)
    .bind(lease.global_fence_token)
    .bind(lease.target_route_fence_token)
    .bind(evidence.workshop_id)
    .bind(evidence.projection_generation)
    .bind(&evidence.projection_digest)
    .bind(evidence.disposition.as_str())
    .bind(&evidence.applied_rendered_digest)
    .bind(&evidence.rendered_digest)
    .fetch_one(ledger)
    .await
    .map_err(DriverError::internal)?;
    tracing::Span::current().record("transition.outcome", outcome.as_str());
    parse_record_entry_outcome(&outcome)
}

#[tracing::instrument(
    name = "deployment_driver.route_set_publication.seal_dormant",
    skip_all,
    fields(
        publication.id = %lease.publication_id,
        publication.kind = lease.publication_kind.as_str(),
        workshop_id = %lease.target_workshop_id,
        route.count = sealed.route_count,
        route.present_count = sealed.present_route_count,
        transition.outcome = tracing::field::Empty
    )
)]
pub(super) async fn seal_route_set_publication(
    ledger: &PgPool,
    lease: &RouteSetPublicationLease,
    sealed: &SealedRouteSetGeneration,
) -> Result<SealRouteSetPublicationOutcome, DriverError> {
    lease.validate()?;
    validate_sealed_generation(lease, sealed)?;
    let record_count = pg_count(sealed.route_count, "route count")?;
    let present_count = pg_count(sealed.present_route_count, "present route count")?;
    let outcome = sqlx::query_scalar::<_, String>(
        "select control.seal_route_set_publication(
           $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
    )
    .bind(lease.publication_id)
    .bind(lease.instance_owner)
    .bind(lease.execution_token)
    .bind(lease.global_lease_token)
    .bind(lease.route_lease_token)
    .bind(lease.global_fence_token)
    .bind(lease.target_route_fence_token)
    .bind(sealed.selector.target())
    .bind(pg_file_identity(sealed.selector.directory_device())?)
    .bind(pg_file_identity(sealed.selector.directory_inode())?)
    .bind(record_count)
    .bind(present_count)
    .bind(&sealed.identity.route_set_digest)
    .fetch_one(ledger)
    .await
    .map_err(DriverError::internal)?;
    tracing::Span::current().record("transition.outcome", outcome.as_str());
    parse_seal_outcome(&outcome)
}

#[tracing::instrument(
    name = "deployment_driver.route_set_publication.start_dormant",
    skip_all,
    fields(
        publication.id = %lease.publication_id,
        publication.kind = lease.publication_kind.as_str(),
        workshop_id = %lease.target_workshop_id,
        transition.outcome = tracing::field::Empty
    )
)]
pub(super) async fn start_route_set_publication(
    ledger: &PgPool,
    lease: &RouteSetPublicationLease,
) -> Result<StartRouteSetPublicationOutcome, DriverError> {
    lease.validate()?;
    let outcome = sqlx::query_scalar::<_, String>(
        "select control.start_route_set_publication($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(lease.publication_id)
    .bind(lease.instance_owner)
    .bind(lease.execution_token)
    .bind(lease.global_lease_token)
    .bind(lease.route_lease_token)
    .bind(lease.global_fence_token)
    .bind(lease.target_route_fence_token)
    .fetch_one(ledger)
    .await
    .map_err(DriverError::internal)?;
    tracing::Span::current().record("transition.outcome", outcome.as_str());
    parse_start_outcome(&outcome)
}

#[tracing::instrument(
    name = "deployment_driver.route_set_publication.observe_dormant",
    skip_all,
    fields(
        publication.id = %lease.publication_id,
        publication.kind = lease.publication_kind.as_str(),
        workshop_id = %lease.target_workshop_id,
        transition.outcome = tracing::field::Empty
    )
)]
pub(super) async fn observe_route_set_publication(
    ledger: &PgPool,
    lease: &RouteSetPublicationLease,
    observed: &PriorSelector,
    loaded_identity: &RouteSetGenerationIdentity,
) -> Result<ObserveRouteSetPublicationOutcome, DriverError> {
    lease.validate()?;
    validate_observation(lease, observed, loaded_identity)?;
    let identity = serde_json::to_value(loaded_identity).map_err(DriverError::internal)?;
    let outcome = sqlx::query_scalar::<_, String>(
        "select control.observe_route_set_publication(
           $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
    )
    .bind(lease.publication_id)
    .bind(lease.instance_owner)
    .bind(lease.execution_token)
    .bind(lease.global_lease_token)
    .bind(lease.route_lease_token)
    .bind(lease.global_fence_token)
    .bind(lease.target_route_fence_token)
    .bind(observed.target())
    .bind(pg_file_identity(observed.directory_device())?)
    .bind(pg_file_identity(observed.directory_inode())?)
    .bind(identity)
    .fetch_one(ledger)
    .await
    .map_err(DriverError::internal)?;
    tracing::Span::current().record("transition.outcome", outcome.as_str());
    parse_observe_outcome(&outcome)
}

#[tracing::instrument(
    name = "deployment_driver.route_set_publication.finish_dormant",
    skip_all,
    fields(
        publication.id = %lease.publication_id,
        publication.kind = lease.publication_kind.as_str(),
        workshop_id = %lease.target_workshop_id,
        transition.outcome = tracing::field::Empty
    )
)]
pub(super) async fn finish_route_set_publication(
    ledger: &PgPool,
    lease: &RouteSetPublicationLease,
    sealed: &SealedRouteSetGeneration,
    target_evidence: &RouteSetSealEvidence,
) -> Result<FinishRouteSetPublicationOutcome, DriverError> {
    lease.validate()?;
    validate_sealed_generation(lease, sealed)?;
    validate_target_evidence(lease, target_evidence)?;
    let (outcome, response) = sqlx::query_as::<_, (String, Option<Value>)>(
        "select outcome,response from control.finish_route_set_publication(
           $1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(lease.publication_id)
    .bind(lease.instance_owner)
    .bind(lease.execution_token)
    .bind(lease.global_lease_token)
    .bind(lease.route_lease_token)
    .bind(lease.global_fence_token)
    .bind(lease.target_route_fence_token)
    .fetch_one(ledger)
    .await
    .map_err(DriverError::internal)?;
    tracing::Span::current().record("transition.outcome", outcome.as_str());
    match outcome.as_str() {
        "completed" | "replay" => {
            let response = response
                .ok_or_else(|| DriverError::internal("completed route-set response is absent"))?;
            let response = parse_publication_response(response)?;
            validate_publication_response_for_lease(&response, lease, sealed, target_evidence)?;
            if outcome == "completed" {
                Ok(FinishRouteSetPublicationOutcome::Completed(response))
            } else {
                Ok(FinishRouteSetPublicationOutcome::Replay(response))
            }
        }
        "authority_lost" if response.is_none() => {
            Ok(FinishRouteSetPublicationOutcome::AuthorityLost)
        }
        "conflict" if response.is_none() => Ok(FinishRouteSetPublicationOutcome::Conflict),
        "wrong_phase" if response.is_none() => Ok(FinishRouteSetPublicationOutcome::WrongPhase),
        "invalid" if response.is_none() => Ok(FinishRouteSetPublicationOutcome::Invalid),
        _ => Err(DriverError::internal(
            "finish route-set publication outcome is invalid",
        )),
    }
}

#[tracing::instrument(
    name = "deployment_driver.route_set_publication.read_result_dormant",
    skip_all,
    fields(
        workshop_id = %request.workshop_id,
        result.outcome = tracing::field::Empty,
        publication.id = tracing::field::Empty
    )
)]
pub(super) async fn read_route_set_publication_result(
    ledger: &PgPool,
    request: &RouteSetPublicationResultRequest,
) -> Result<ReadRouteSetPublicationResult, DriverError> {
    request.validate()?;
    let row = sqlx::query_as::<_, PublicationResultRow>(
        "select outcome,publication_id,driver_operation_id,response
           from control.read_route_set_publication_result($1,$2,$3,$4)",
    )
    .bind(request.control_operation_id)
    .bind(request.workshop_id)
    .bind(&request.idempotency_key)
    .bind(&request.request_digest)
    .fetch_one(ledger)
    .await
    .map_err(DriverError::internal)?;
    tracing::Span::current().record("result.outcome", row.0.as_str());
    let result = parse_publication_result_row(request, row)?;
    if let ReadRouteSetPublicationResult::Pending { publication_id, .. }
    | ReadRouteSetPublicationResult::Completed { publication_id, .. } = &result
    {
        tracing::Span::current().record("publication.id", tracing::field::display(publication_id));
    }
    Ok(result)
}

fn parse_publication_result_row(
    request: &RouteSetPublicationResultRequest,
    row: PublicationResultRow,
) -> Result<ReadRouteSetPublicationResult, DriverError> {
    let (outcome, publication_id, driver_operation_id, response) = row;
    match outcome.as_str() {
        "absent"
            if publication_id.is_none() && driver_operation_id.is_none() && response.is_none() =>
        {
            Ok(ReadRouteSetPublicationResult::Absent)
        }
        "conflict"
            if publication_id.is_none() && driver_operation_id.is_none() && response.is_none() =>
        {
            Ok(ReadRouteSetPublicationResult::Conflict)
        }
        "pending" if response.is_none() => {
            let publication_id = required_uuid(publication_id, "result publication id")?;
            let driver_operation_id = required_uuid(driver_operation_id, "result driver id")?;
            Ok(ReadRouteSetPublicationResult::Pending {
                publication_id,
                driver_operation_id,
            })
        }
        "completed" => {
            let publication_id = required_uuid(publication_id, "result publication id")?;
            let driver_operation_id = required_uuid(driver_operation_id, "result driver id")?;
            let response =
                parse_publication_response(response.ok_or_else(|| {
                    DriverError::internal("route-set result response is absent")
                })?)?;
            validate_publication_response_common(
                &response,
                &PublicationResponseExpectation {
                    publication_id,
                    publication_kind: RouteSetPublicationKind::Projection,
                    driver_operation_id,
                    workshop_id: request.workshop_id,
                    projection_generation: request.expected_generation,
                    projection_digest: &request.expected_projection_digest,
                    expected_disposition: Some(request.expected_disposition),
                },
            )?;
            Ok(ReadRouteSetPublicationResult::Completed {
                publication_id,
                driver_operation_id,
                response: Box::new(response),
            })
        }
        "not_applied" => {
            let publication_id = required_uuid(publication_id, "result publication id")?;
            let driver_operation_id = required_uuid(driver_operation_id, "result driver id")?;
            let value = response
                .ok_or_else(|| DriverError::internal("not-applied route-set result is absent"))?;
            exact_response_keys(
                &value,
                &[
                    "outcome",
                    "publication_id",
                    "driver_operation_id",
                    "resolution_kind",
                    "safe_error",
                ],
                "not-applied route-set result",
            )?;
            let result: RouteSetPublicationNotApplied = serde_json::from_value(value)
                .map_err(|_| DriverError::internal("not-applied route-set result is invalid"))?;
            if result.outcome != "not_applied"
                || result.publication_id != publication_id
                || result.driver_operation_id != driver_operation_id
                || !matches!(result.resolution_kind.as_str(), "prior" | "unstarted")
                || result.safe_error != "route_set_publication_not_applied"
            {
                return Err(DriverError::internal(
                    "not-applied route-set result identity is invalid",
                ));
            }
            Ok(ReadRouteSetPublicationResult::NotApplied(result))
        }
        _ => Err(DriverError::internal(
            "read route-set publication result outcome is invalid",
        )),
    }
}

#[tracing::instrument(
    name = "deployment_driver.route_set_publication.quarantine_dormant",
    skip_all,
    fields(
        publication.id = %lease.publication_id,
        publication.kind = lease.publication_kind.as_str(),
        workshop_id = %lease.target_workshop_id,
        quarantine.accepted = tracing::field::Empty
    )
)]
pub(super) async fn quarantine_route_set_publication(
    ledger: &PgPool,
    lease: &RouteSetPublicationLease,
) -> Result<bool, DriverError> {
    lease.validate()?;
    let accepted = sqlx::query_scalar::<_, bool>(
        "select control.quarantine_route_set_publication($1,$2,$3,$4,$5,$6,$7,$8)",
    )
    .bind(lease.publication_id)
    .bind(lease.instance_owner)
    .bind(lease.execution_token)
    .bind(lease.global_lease_token)
    .bind(lease.route_lease_token)
    .bind(lease.global_fence_token)
    .bind(lease.target_route_fence_token)
    .bind("route_set_publication_outcome_unknown")
    .fetch_one(ledger)
    .await
    .map_err(DriverError::internal)?;
    tracing::Span::current().record("quarantine.accepted", accepted);
    Ok(accepted)
}

pub(super) fn parse_publication_response(
    value: Value,
) -> Result<RouteSetPublicationResponse, DriverError> {
    serde_json::from_value(value)
        .map_err(|_| DriverError::internal("route-set publication response is invalid"))
}

pub(super) struct PublicationResponseExpectation<'a> {
    pub publication_id: Uuid,
    pub publication_kind: RouteSetPublicationKind,
    pub driver_operation_id: Uuid,
    pub workshop_id: Uuid,
    pub projection_generation: i64,
    pub projection_digest: &'a str,
    pub expected_disposition: Option<RouteSetAppliedDisposition>,
}

pub(super) fn validate_publication_response_common(
    response: &RouteSetPublicationResponse,
    expected: &PublicationResponseExpectation<'_>,
) -> Result<(), DriverError> {
    let route = &response.route_evidence;
    let set = &response.route_set_evidence;
    if response.outcome != "applied"
        || response.workshop_id != expected.workshop_id
        || route.driver_operation_id != expected.driver_operation_id
        || route.workshop_id != expected.workshop_id
        || route.route_generation != expected.projection_generation
        || route.projection_digest != expected.projection_digest
        || expected
            .expected_disposition
            .is_some_and(|disposition| route.disposition != disposition)
        || !valid_sha256(&route.rendered_digest)
        || (route.disposition == RouteSetAppliedDisposition::Absent
            && route.rendered_digest != EMPTY_RENDERED_DIGEST)
        || route.route_fence_token <= 0
        || set.protocol_version != 1
        || set.publication_id != expected.publication_id
        || set.publication_kind != expected.publication_kind
        || set.selector
            != RouteSetGenerationName::new(expected.publication_id, set.publication_kind)
                .selector_target()
        || !valid_sha256(&set.route_set_digest)
        || !(1..=MAX_ROUTES).contains(&set.snapshot_count)
        || set.present_count > set.snapshot_count
        || set.global_fence_token <= 0
        || set.directory_device == 0
        || i64::try_from(set.directory_device).is_err()
        || set.directory_inode == 0
        || i64::try_from(set.directory_inode).is_err()
    {
        return Err(DriverError::internal(
            "route-set publication response identity is invalid",
        ));
    }
    Ok(())
}

fn exact_response_keys(
    value: &Value,
    expected: &[&str],
    description: &str,
) -> Result<(), DriverError> {
    let object = value
        .as_object()
        .ok_or_else(|| DriverError::internal(format!("{description} is not an object")))?;
    if object.len() != expected.len() || expected.iter().any(|key| !object.contains_key(*key)) {
        return Err(DriverError::internal(format!(
            "{description} keys are invalid"
        )));
    }
    Ok(())
}

fn validate_publication_response_for_lease(
    response: &RouteSetPublicationResponse,
    lease: &RouteSetPublicationLease,
    sealed: &SealedRouteSetGeneration,
    target_evidence: &RouteSetSealEvidence,
) -> Result<(), DriverError> {
    let expected_disposition = match target_evidence.disposition {
        super::route_set_generation_fs::RouteDisposition::Present => {
            RouteSetAppliedDisposition::Present
        }
        super::route_set_generation_fs::RouteDisposition::Absent => {
            RouteSetAppliedDisposition::Absent
        }
    };
    validate_publication_response_common(
        response,
        &PublicationResponseExpectation {
            publication_id: lease.publication_id,
            publication_kind: lease.publication_kind,
            driver_operation_id: lease.driver_operation_id,
            workshop_id: lease.target_workshop_id,
            projection_generation: lease.target_projection_generation,
            projection_digest: &lease.target_projection_digest,
            expected_disposition: Some(expected_disposition),
        },
    )?;
    let route = &response.route_evidence;
    let set = &response.route_set_evidence;
    if route.route_fence_token != lease.target_route_fence_token
        || route.rendered_digest != target_evidence.rendered_digest
        || set.selector != lease.selector
        || set.route_set_digest != sealed.identity.route_set_digest
        || set.snapshot_count != lease.snapshot_count
        || set.snapshot_count != sealed.route_count
        || set.present_count != sealed.present_route_count
        || set.global_fence_token != lease.global_fence_token
        || set.directory_device != sealed.selector.directory_device()
        || set.directory_inode != sealed.selector.directory_inode()
    {
        return Err(DriverError::internal(
            "route-set publication response differs from its lease",
        ));
    }
    Ok(())
}

fn validate_target_evidence(
    lease: &RouteSetPublicationLease,
    evidence: &RouteSetSealEvidence,
) -> Result<(), DriverError> {
    validate_seal_evidence(evidence)?;
    if evidence.workshop_id != lease.target_workshop_id
        || evidence.projection_generation != lease.target_projection_generation
        || evidence.projection_digest != lease.target_projection_digest
        || !matches!(
            (lease.expected_disposition, evidence.disposition),
            (
                RouteSetAppliedDisposition::Present,
                super::route_set_generation_fs::RouteDisposition::Present,
            ) | (
                RouteSetAppliedDisposition::Absent,
                super::route_set_generation_fs::RouteDisposition::Absent,
            )
        )
    {
        return Err(DriverError::internal(
            "route-set target evidence differs from its lease",
        ));
    }
    Ok(())
}

fn validate_prior_evidence(
    prior: &PriorSelector,
    loaded_identity: Option<&RouteSetPriorLoadedIdentity>,
) -> Result<Option<Value>, DriverError> {
    pg_file_identity(prior.directory_device())?;
    pg_file_identity(prior.directory_inode())?;
    let is_boot_live = prior.target() == "generations/boot-live";
    if is_boot_live != loaded_identity.is_none() {
        return Err(DriverError::internal(
            "route-set prior evidence identity is invalid",
        ));
    }
    loaded_identity
        .map(|identity| identity.validate_for_selector(prior.target()))
        .transpose()
}

fn validate_seal_evidence(evidence: &RouteSetSealEvidence) -> Result<(), DriverError> {
    if evidence.workshop_id.is_nil()
        || evidence.projection_generation <= 0
        || !valid_sha256(&evidence.projection_digest)
        || evidence
            .applied_rendered_digest
            .as_deref()
            .is_none_or(|digest| !valid_sha256(digest))
        || !valid_sha256(&evidence.rendered_digest)
        || (evidence.disposition.as_str() == "absent"
            && evidence.rendered_digest != EMPTY_RENDERED_DIGEST)
    {
        return Err(DriverError::internal("route-set entry evidence is invalid"));
    }
    Ok(())
}

fn validate_sealed_generation(
    lease: &RouteSetPublicationLease,
    sealed: &SealedRouteSetGeneration,
) -> Result<(), DriverError> {
    sealed.identity.validate()?;
    if sealed.name.as_str()
        != RouteSetGenerationName::new(lease.publication_id, lease.publication_kind).as_str()
        || sealed.selector.target() != lease.selector
        || sealed.identity.publication_id != lease.publication_id
        || sealed.identity.publication_kind != lease.publication_kind
        || sealed.identity.global_fence_token != lease.global_fence_token
        || sealed.identity.target_workshop_id() != Some(lease.target_workshop_id)
        || sealed.identity.target_route_fence_token() != Some(lease.target_route_fence_token)
        || sealed.route_count != lease.snapshot_count
        || sealed.present_route_count > sealed.route_count
    {
        return Err(DriverError::internal(
            "sealed route-set generation differs from its publication lease",
        ));
    }
    pg_file_identity(sealed.selector.directory_device())?;
    pg_file_identity(sealed.selector.directory_inode())?;
    Ok(())
}

fn validate_observation(
    lease: &RouteSetPublicationLease,
    observed: &PriorSelector,
    identity: &RouteSetGenerationIdentity,
) -> Result<(), DriverError> {
    identity.validate()?;
    if observed.target() != lease.selector
        || identity.publication_id != lease.publication_id
        || identity.publication_kind != lease.publication_kind
        || identity.global_fence_token != lease.global_fence_token
        || identity.target_workshop_id() != Some(lease.target_workshop_id)
        || identity.target_route_fence_token() != Some(lease.target_route_fence_token)
    {
        return Err(DriverError::internal(
            "observed route-set identity differs from its publication lease",
        ));
    }
    pg_file_identity(observed.directory_device())?;
    pg_file_identity(observed.directory_inode())?;
    Ok(())
}

fn pg_file_identity(value: u64) -> Result<i64, DriverError> {
    i64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| DriverError::internal("route-set directory identity is invalid"))
}

fn pg_count(value: usize, name: &str) -> Result<i32, DriverError> {
    i32::try_from(value)
        .ok()
        .filter(|value| *value >= 0)
        .ok_or_else(|| DriverError::internal(format!("route-set {name} is invalid")))
}

fn parse_record_prior_outcome(value: &str) -> Result<RecordRouteSetPriorOutcome, DriverError> {
    match value {
        "recorded" => Ok(RecordRouteSetPriorOutcome::Recorded),
        "replay" => Ok(RecordRouteSetPriorOutcome::Replay),
        "authority_lost" => Ok(RecordRouteSetPriorOutcome::AuthorityLost),
        "conflict" => Ok(RecordRouteSetPriorOutcome::Conflict),
        "wrong_phase" => Ok(RecordRouteSetPriorOutcome::WrongPhase),
        "invalid" => Ok(RecordRouteSetPriorOutcome::Invalid),
        _ => Err(DriverError::internal(
            "record route-set prior outcome is invalid",
        )),
    }
}

fn parse_record_entry_outcome(value: &str) -> Result<RecordRouteSetEntryOutcome, DriverError> {
    match value {
        "recorded" => Ok(RecordRouteSetEntryOutcome::Recorded),
        "replay" => Ok(RecordRouteSetEntryOutcome::Replay),
        "authority_lost" => Ok(RecordRouteSetEntryOutcome::AuthorityLost),
        "invalid" => Ok(RecordRouteSetEntryOutcome::Invalid),
        "conflict" => Ok(RecordRouteSetEntryOutcome::Conflict),
        "wrong_phase" => Ok(RecordRouteSetEntryOutcome::WrongPhase),
        "prior_absent" => Ok(RecordRouteSetEntryOutcome::PriorAbsent),
        "out_of_order" => Ok(RecordRouteSetEntryOutcome::OutOfOrder),
        "snapshot_drift" => Ok(RecordRouteSetEntryOutcome::SnapshotDrift),
        "render_invariant_mismatch" => Ok(RecordRouteSetEntryOutcome::RenderInvariantMismatch),
        _ => Err(DriverError::internal(
            "record route-set entry outcome is invalid",
        )),
    }
}

fn parse_seal_outcome(value: &str) -> Result<SealRouteSetPublicationOutcome, DriverError> {
    match value {
        "sealed" => Ok(SealRouteSetPublicationOutcome::Sealed),
        "replay" => Ok(SealRouteSetPublicationOutcome::Replay),
        "authority_lost" => Ok(SealRouteSetPublicationOutcome::AuthorityLost),
        "wrong_phase" => Ok(SealRouteSetPublicationOutcome::WrongPhase),
        "prior_absent" => Ok(SealRouteSetPublicationOutcome::PriorAbsent),
        "invalid" => Ok(SealRouteSetPublicationOutcome::Invalid),
        "prior_directory_reused" => Ok(SealRouteSetPublicationOutcome::PriorDirectoryReused),
        "count_mismatch" => Ok(SealRouteSetPublicationOutcome::CountMismatch),
        "present_count_mismatch" => Ok(SealRouteSetPublicationOutcome::PresentCountMismatch),
        "digest_mismatch" => Ok(SealRouteSetPublicationOutcome::DigestMismatch),
        _ => Err(DriverError::internal(
            "seal route-set publication outcome is invalid",
        )),
    }
}

fn parse_start_outcome(value: &str) -> Result<StartRouteSetPublicationOutcome, DriverError> {
    match value {
        "started" => Ok(StartRouteSetPublicationOutcome::Started),
        "replay" => Ok(StartRouteSetPublicationOutcome::Replay),
        "authority_lost" => Ok(StartRouteSetPublicationOutcome::AuthorityLost),
        "wrong_phase" => Ok(StartRouteSetPublicationOutcome::WrongPhase),
        _ => Err(DriverError::internal(
            "start route-set publication outcome is invalid",
        )),
    }
}

fn parse_observe_outcome(value: &str) -> Result<ObserveRouteSetPublicationOutcome, DriverError> {
    match value {
        "observed" => Ok(ObserveRouteSetPublicationOutcome::Observed),
        "replay" => Ok(ObserveRouteSetPublicationOutcome::Replay),
        "authority_lost" => Ok(ObserveRouteSetPublicationOutcome::AuthorityLost),
        "observation_mismatch" => Ok(ObserveRouteSetPublicationOutcome::ObservationMismatch),
        "wrong_phase" => Ok(ObserveRouteSetPublicationOutcome::WrongPhase),
        _ => Err(DriverError::internal(
            "observe route-set publication outcome is invalid",
        )),
    }
}

impl RouteSetPublicationAdmissionRequest {
    fn validate(&self) -> Result<(), DriverError> {
        if self.publication_kind != RouteSetPublicationKind::Projection
            || self.control_operation.id.is_nil()
            || self.control_operation.attempt <= 0
            || self.control_operation.owner.trim().is_empty()
            || self.idempotency_key.is_empty()
            || self.idempotency_key.len() > 180
            || !valid_bare_sha256(&self.request_digest)
            || self.projection_generation <= 0
            || !valid_sha256(&self.projection_digest)
            || self.workshop_id.is_nil()
            || self.instance_owner.is_nil()
            || self.execution_token.is_nil()
            || self.global_lease_token.is_nil()
            || self.route_lease_token.is_nil()
            || !(MIN_LEASE_SECONDS..=MAX_LEASE_SECONDS).contains(&self.ttl_seconds)
        {
            return Err(DriverError::internal(
                "route-set publication admission request is invalid",
            ));
        }
        Ok(())
    }
}

impl RouteSetPublicationResultRequest {
    pub(super) fn from_admission(request: &RouteSetPublicationAdmissionRequest) -> Self {
        Self {
            control_operation_id: request.control_operation.id,
            workshop_id: request.workshop_id,
            idempotency_key: request.idempotency_key.clone(),
            request_digest: request.request_digest.clone(),
            expected_generation: request.projection_generation,
            expected_projection_digest: request.projection_digest.clone(),
            expected_disposition: request.expected_disposition,
        }
    }

    fn validate(&self) -> Result<(), DriverError> {
        if self.control_operation_id.is_nil()
            || self.workshop_id.is_nil()
            || self.idempotency_key.is_empty()
            || self.idempotency_key.len() > 180
            || !valid_bare_sha256(&self.request_digest)
            || self.expected_generation <= 0
            || !valid_sha256(&self.expected_projection_digest)
        {
            return Err(DriverError::internal(
                "route-set publication result request is invalid",
            ));
        }
        Ok(())
    }
}

impl RouteSetPublicationLease {
    pub(super) fn validate(&self) -> Result<(), DriverError> {
        if self.publication_id.is_nil()
            || self.driver_operation_id.is_nil()
            || !matches!(
                self.publication_kind,
                RouteSetPublicationKind::Projection
                    | RouteSetPublicationKind::RecoveryMaintenance
                    | RouteSetPublicationKind::RecoveryRestore
            )
            || self.control_operation.id.is_nil()
            || self.control_operation.attempt <= 0
            || self.control_operation.owner.trim().is_empty()
            || self.target_workshop_id.is_nil()
            || self.target_projection_generation <= 0
            || !valid_sha256(&self.target_projection_digest)
            || self.instance_owner.is_nil()
            || self.execution_token.is_nil()
            || self.global_lease_token.is_nil()
            || self.route_lease_token.is_nil()
            || self.global_fence_token <= 0
            || self.target_route_fence_token <= 0
            || self.selector
                != RouteSetGenerationName::new(self.publication_id, self.publication_kind)
                    .selector_target()
            || !(1..=MAX_ROUTES).contains(&self.snapshot_count)
            || !(MIN_LEASE_SECONDS..=MAX_LEASE_SECONDS).contains(&self.ttl_seconds)
        {
            return Err(DriverError::internal(
                "route-set publication lease identity is invalid",
            ));
        }
        Ok(())
    }
}

fn lease_from_admission_row(
    request: &RouteSetPublicationAdmissionRequest,
    row: &AdmissionRow,
) -> Result<RouteSetPublicationLease, DriverError> {
    let publication_id = required_uuid(row.1, "publication id")?;
    let lease = RouteSetPublicationLease {
        publication_id,
        driver_operation_id: required_uuid(row.2, "driver operation id")?,
        publication_kind: request.publication_kind,
        control_operation: request.control_operation.clone(),
        target_workshop_id: request.workshop_id,
        target_projection_generation: request.projection_generation,
        target_projection_digest: request.projection_digest.clone(),
        expected_disposition: request.expected_disposition,
        instance_owner: request.instance_owner,
        execution_token: request.execution_token,
        global_lease_token: request.global_lease_token,
        route_lease_token: request.route_lease_token,
        global_fence_token: required_fence(row.3, "global fence")?,
        target_route_fence_token: required_fence(row.4, "target route fence")?,
        selector: row
            .5
            .clone()
            .ok_or_else(|| DriverError::internal("route-set selector is absent"))?,
        snapshot_count: valid_optional_count(row.6)?
            .ok_or_else(|| DriverError::internal("route-set snapshot count is absent"))?,
        ttl_seconds: request.ttl_seconds,
    };
    lease.validate()?;
    Ok(lease)
}

fn validate_snapshot_rows(
    lease: &RouteSetPublicationLease,
    after_workshop_id: Option<Uuid>,
    limit: usize,
    rows: Vec<SnapshotRow>,
) -> Result<Vec<FrozenSnapshotItem>, DriverError> {
    if rows.len() > limit {
        return Err(DriverError::internal(
            "route-set snapshot batch exceeded its bound",
        ));
    }
    let mut previous = after_workshop_id;
    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        if row.0.is_nil() || previous.is_some_and(|previous| previous >= row.0) {
            return Err(DriverError::internal(
                "route-set snapshot batch is not strictly UUID ordered",
            ));
        }
        let disposition = RouteDisposition::parse(&row.3)?;
        if row.1 <= 0
            || !valid_sha256(&row.2)
            || !row.4.is_object()
            || serde_json::to_vec(&row.4)
                .map_err(DriverError::internal)?
                .len()
                > MAX_CANONICAL_PROJECTION_BYTES
            || !valid_sha256(&row.5)
            || row.6 != (row.0 == lease.target_workshop_id)
            || (row.6
                && (row.1 != lease.target_projection_generation
                    || row.2 != lease.target_projection_digest
                    || !matches!(
                        (lease.expected_disposition, disposition),
                        (
                            RouteSetAppliedDisposition::Present,
                            RouteDisposition::Present
                        ) | (RouteSetAppliedDisposition::Absent, RouteDisposition::Absent)
                    )))
        {
            return Err(DriverError::internal(
                "route-set snapshot row identity is invalid",
            ));
        }
        previous = Some(row.0);
        items.push(FrozenSnapshotItem {
            workshop_id: row.0,
            projection_generation: row.1,
            projection_digest: row.2,
            disposition,
            canonical_projection: row.4,
            applied_rendered_digest: row.5,
            is_target: row.6,
        });
    }
    Ok(items)
}

fn required_uuid(value: Option<Uuid>, name: &str) -> Result<Uuid, DriverError> {
    value
        .filter(|value| !value.is_nil())
        .ok_or_else(|| DriverError::internal(format!("route-set {name} is invalid")))
}

fn required_fence(value: Option<i64>, name: &str) -> Result<i64, DriverError> {
    value
        .filter(|value| *value > 0)
        .ok_or_else(|| DriverError::internal(format!("route-set {name} is invalid")))
}

fn valid_optional_uuid(value: Option<Uuid>) -> Result<Option<Uuid>, DriverError> {
    if value.is_some_and(|value| value.is_nil()) {
        return Err(DriverError::internal("route-set optional UUID is invalid"));
    }
    Ok(value)
}

fn valid_optional_fence(value: Option<i64>) -> Result<Option<i64>, DriverError> {
    if value.is_some_and(|value| value <= 0) {
        return Err(DriverError::internal("route-set optional fence is invalid"));
    }
    Ok(value)
}

fn valid_optional_count(value: Option<i32>) -> Result<Option<usize>, DriverError> {
    match value {
        Some(value) => usize::try_from(value)
            .ok()
            .map(Some)
            .ok_or_else(|| DriverError::internal("route-set diagnostic count is invalid")),
        None => Ok(None),
    }
}

fn validate_optional_selector(
    publication_id: Option<Uuid>,
    kind: RouteSetPublicationKind,
    selector: Option<String>,
) -> Result<Option<String>, DriverError> {
    match (publication_id, selector) {
        (Some(publication_id), Some(selector))
            if !publication_id.is_nil()
                && selector
                    == RouteSetGenerationName::new(publication_id, kind).selector_target() =>
        {
            Ok(Some(selector))
        }
        (_, None) => Ok(None),
        _ => Err(DriverError::internal(
            "route-set optional selector identity is invalid",
        )),
    }
}

fn valid_sha256(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(valid_hex_sha256)
}

fn valid_bare_sha256(value: &str) -> bool {
    valid_hex_sha256(value)
}

fn valid_hex_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> RouteSetPublicationAdmissionRequest {
        RouteSetPublicationAdmissionRequest {
            control_operation: ControlOperationLease {
                id: Uuid::new_v4(),
                attempt: 3,
                owner: "worker-a".into(),
            },
            workshop_id: Uuid::parse_str("10000000-0000-0000-0000-000000000001").unwrap(),
            publication_kind: RouteSetPublicationKind::Projection,
            idempotency_key: "route-set:test".into(),
            request_digest: "a".repeat(64),
            projection_generation: 7,
            projection_digest: format!("sha256:{}", "b".repeat(64)),
            expected_disposition: RouteSetAppliedDisposition::Present,
            instance_owner: Uuid::new_v4(),
            execution_token: Uuid::new_v4(),
            global_lease_token: Uuid::new_v4(),
            route_lease_token: Uuid::new_v4(),
            ttl_seconds: 1200,
        }
    }

    fn result_request() -> RouteSetPublicationResultRequest {
        let request = request();
        RouteSetPublicationResultRequest::from_admission(&request)
    }

    fn lease() -> RouteSetPublicationLease {
        let request = request();
        let publication_id = Uuid::new_v4();
        RouteSetPublicationLease {
            publication_id,
            driver_operation_id: Uuid::new_v4(),
            publication_kind: request.publication_kind,
            control_operation: request.control_operation,
            target_workshop_id: request.workshop_id,
            target_projection_generation: request.projection_generation,
            target_projection_digest: request.projection_digest,
            expected_disposition: request.expected_disposition,
            instance_owner: request.instance_owner,
            execution_token: request.execution_token,
            global_lease_token: request.global_lease_token,
            route_lease_token: request.route_lease_token,
            global_fence_token: 19,
            target_route_fence_token: 23,
            selector: RouteSetGenerationName::new(
                publication_id,
                RouteSetPublicationKind::Projection,
            )
            .selector_target(),
            snapshot_count: 2,
            ttl_seconds: request.ttl_seconds,
        }
    }

    fn sealed(lease: &RouteSetPublicationLease) -> SealedRouteSetGeneration {
        let identity = RouteSetGenerationIdentity::new(
            lease.publication_id,
            lease.publication_kind,
            lease.global_fence_token,
            lease.target_workshop_id,
            lease.target_route_fence_token,
            format!("sha256:{}", "c".repeat(64)),
        )
        .unwrap();
        SealedRouteSetGeneration {
            name: RouteSetGenerationName::new(lease.publication_id, lease.publication_kind),
            identity,
            route_count: lease.snapshot_count,
            present_route_count: 1,
            selector: PriorSelector::from_recorded(lease.selector.clone(), 31, 37).unwrap(),
        }
    }

    fn response_value(
        lease: &RouteSetPublicationLease,
        sealed: &SealedRouteSetGeneration,
    ) -> Value {
        serde_json::json!({
            "outcome": "applied",
            "workshop_id": lease.target_workshop_id,
            "route_evidence": {
                "driver_operation_id": lease.driver_operation_id,
                "workshop_id": lease.target_workshop_id,
                "route_generation": lease.target_projection_generation,
                "projection_digest": lease.target_projection_digest,
                "disposition": "present",
                "rendered_digest": format!("sha256:{}", "d".repeat(64)),
                "route_fence_token": lease.target_route_fence_token
            },
            "route_set_evidence": {
                "protocol_version": 1,
                "publication_id": lease.publication_id,
                "publication_kind": "projection",
                "selector": lease.selector,
                "route_set_digest": sealed.identity.route_set_digest,
                "snapshot_count": lease.snapshot_count,
                "present_count": sealed.present_route_count,
                "global_fence_token": lease.global_fence_token,
                "directory_device": sealed.selector.directory_device(),
                "directory_inode": sealed.selector.directory_inode()
            }
        })
    }

    fn target_evidence(lease: &RouteSetPublicationLease) -> RouteSetSealEvidence {
        RouteSetSealEvidence {
            workshop_id: lease.target_workshop_id,
            projection_generation: lease.target_projection_generation,
            projection_digest: lease.target_projection_digest.clone(),
            disposition: super::super::route_set_generation_fs::RouteDisposition::Present,
            applied_rendered_digest: Some(format!("sha256:{}", "e".repeat(64))),
            rendered_digest: format!("sha256:{}", "d".repeat(64)),
        }
    }

    #[test]
    fn request_and_lease_validation_are_closed_to_0027_projection_admission() {
        let mut request = request();
        request.validate().unwrap();
        request.publication_kind = RouteSetPublicationKind::RecoveryMaintenance;
        assert!(request.validate().is_err());

        let mut lease = lease();
        lease.validate().unwrap();
        lease.selector.push_str("-drift");
        assert!(lease.validate().is_err());

        let mut result = result_request();
        result.validate().unwrap();
        result.expected_generation = 0;
        assert!(result.validate().is_err());
    }

    #[test]
    fn snapshot_rows_are_ordered_target_bound_and_convert_to_staging() {
        let lease = lease();
        let other = Uuid::parse_str("20000000-0000-0000-0000-000000000002").unwrap();
        let projection = serde_json::json!({});
        let rows = vec![
            (
                lease.target_workshop_id,
                lease.target_projection_generation,
                lease.target_projection_digest.clone(),
                "present".into(),
                projection.clone(),
                format!("sha256:{}", "c".repeat(64)),
                true,
            ),
            (
                other,
                4,
                format!("sha256:{}", "d".repeat(64)),
                "absent".into(),
                projection,
                format!("sha256:{}", "e".repeat(64)),
                false,
            ),
        ];
        let items = validate_snapshot_rows(&lease, None, 2, rows).unwrap();
        assert!(items[0].is_target);
        let staged = items[0].clone().into_staging_item();
        assert_eq!(staged.workshop_id, lease.target_workshop_id);
        assert_eq!(staged.disposition, RouteDisposition::Present);
    }

    #[test]
    fn snapshot_rows_reject_order_kind_and_target_drift() {
        let lease = lease();
        let target = (
            lease.target_workshop_id,
            lease.target_projection_generation,
            lease.target_projection_digest.clone(),
            "unknown".into(),
            serde_json::json!({}),
            format!("sha256:{}", "c".repeat(64)),
            true,
        );
        assert!(validate_snapshot_rows(&lease, None, 1, vec![target]).is_err());

        let wrong_target = (
            lease.target_workshop_id,
            lease.target_projection_generation,
            lease.target_projection_digest.clone(),
            "present".into(),
            serde_json::json!({}),
            format!("sha256:{}", "c".repeat(64)),
            false,
        );
        assert!(validate_snapshot_rows(&lease, None, 1, vec![wrong_target]).is_err());
    }

    #[test]
    fn sql_signatures_and_binding_order_match_migration_0027() {
        let migration = include_str!("../../migrations/0027_route_set_publication_admission.sql");
        for signature in [
            "control.admit_route_set_publication(uuid,integer,text,uuid,text,text,text,bigint,text,uuid,uuid,uuid,uuid,integer)",
            "control.renew_route_set_publication(uuid,uuid,uuid,uuid,uuid,bigint,bigint,integer)",
            "control.read_route_set_publication_snapshot_batch(uuid,uuid,uuid,uuid,uuid,bigint,bigint,uuid,integer)",
        ] {
            assert!(migration.contains(signature), "missing {signature}");
        }

        let source = include_str!("route_set_publication_db.rs");
        for placeholders in [
            "$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14",
            "renew_route_set_publication($1,$2,$3,$4,$5,$6,$7,$8)",
            "$1,$2,$3,$4,$5,$6,$7,$8,$9)",
        ] {
            assert!(source.contains(placeholders));
        }
        let admission = source
            .split("pub(super) async fn admit_route_set_publication(")
            .nth(1)
            .unwrap()
            .split("#[tracing::instrument(")
            .next()
            .unwrap();
        assert_binding_order(
            admission,
            &[
                ".bind(request.control_operation.id)",
                ".bind(request.control_operation.attempt)",
                ".bind(&request.control_operation.owner)",
                ".bind(request.workshop_id)",
                ".bind(request.publication_kind.as_str())",
                ".bind(&request.idempotency_key)",
                ".bind(&request.request_digest)",
                ".bind(request.projection_generation)",
                ".bind(&request.projection_digest)",
                ".bind(request.instance_owner)",
                ".bind(request.execution_token)",
                ".bind(request.global_lease_token)",
                ".bind(request.route_lease_token)",
                ".bind(request.ttl_seconds)",
            ],
        );
        let renewal = source
            .split("pub(super) async fn renew_route_set_publication(")
            .nth(1)
            .unwrap()
            .split("#[tracing::instrument(")
            .next()
            .unwrap();
        assert_binding_order(
            renewal,
            &[
                ".bind(lease.publication_id)",
                ".bind(lease.instance_owner)",
                ".bind(lease.execution_token)",
                ".bind(lease.global_lease_token)",
                ".bind(lease.route_lease_token)",
                ".bind(lease.global_fence_token)",
                ".bind(lease.target_route_fence_token)",
                ".bind(lease.ttl_seconds)",
            ],
        );
        let read = source
            .split("pub(super) async fn read_route_set_publication_snapshot_batch(")
            .nth(1)
            .unwrap()
            .split("impl RouteSetPublicationAdmissionRequest")
            .next()
            .unwrap();
        assert_binding_order(
            read,
            &[
                ".bind(lease.publication_id)",
                ".bind(lease.instance_owner)",
                ".bind(lease.execution_token)",
                ".bind(lease.global_lease_token)",
                ".bind(lease.route_lease_token)",
                ".bind(lease.global_fence_token)",
                ".bind(lease.target_route_fence_token)",
                ".bind(after_workshop_id)",
                ".bind(sql_limit)",
            ],
        );
    }

    fn assert_binding_order(source: &str, bindings: &[&str]) {
        let mut prior = 0;
        for binding in bindings {
            let found = source
                .find(binding)
                .unwrap_or_else(|| panic!("missing {binding}"));
            assert!(found > prior, "binding order drifted at {binding}");
            prior = found;
        }
    }

    #[test]
    fn refusal_vocabulary_exactly_covers_0027_non_authority_outcomes() {
        let migration = include_str!("../../migrations/0027_route_set_publication_admission.sql");
        for value in [
            "invalid",
            "upstream_lease_lost",
            "protocol_inactive",
            "legacy_receipt",
            "conflict",
            "authority_lost",
            "fleet_quarantined",
            "fleet_busy",
            "fleet_not_ready",
        ] {
            let parsed = RouteSetPublicationRefusalKind::parse(value).unwrap();
            assert_eq!(parsed.as_str(), value);
            assert!(migration.contains(&format!("'{value}'")));
        }
        assert!(RouteSetPublicationRefusalKind::parse("acquired").is_none());
        assert!(RouteSetPublicationRefusalKind::parse("replay").is_none());
        assert!(RouteSetPublicationRefusalKind::parse("future_outcome").is_none());
    }

    #[test]
    fn transition_vocabulary_is_closed_and_matches_migration_0028() {
        let migration = include_str!("../../migrations/0028_route_set_publication_transitions.sql");
        for value in [
            "recorded",
            "replay",
            "authority_lost",
            "conflict",
            "wrong_phase",
            "invalid",
        ] {
            assert!(parse_record_prior_outcome(value).is_ok(), "missing {value}");
            assert!(migration.contains(&format!("'{value}'")));
        }
        for value in [
            "recorded",
            "replay",
            "authority_lost",
            "invalid",
            "conflict",
            "wrong_phase",
            "prior_absent",
            "out_of_order",
            "snapshot_drift",
            "render_invariant_mismatch",
        ] {
            assert!(parse_record_entry_outcome(value).is_ok(), "missing {value}");
            assert!(migration.contains(&format!("'{value}'")));
        }
        for value in [
            "sealed",
            "replay",
            "authority_lost",
            "wrong_phase",
            "prior_absent",
            "invalid",
            "prior_directory_reused",
            "count_mismatch",
            "present_count_mismatch",
            "digest_mismatch",
        ] {
            assert!(parse_seal_outcome(value).is_ok(), "missing {value}");
            assert!(migration.contains(&format!("'{value}'")));
        }
        for value in ["started", "replay", "authority_lost", "wrong_phase"] {
            assert!(parse_start_outcome(value).is_ok(), "missing {value}");
            assert!(migration.contains(&format!("'{value}'")));
        }
        for value in [
            "observed",
            "replay",
            "authority_lost",
            "observation_mismatch",
            "wrong_phase",
        ] {
            assert!(parse_observe_outcome(value).is_ok(), "missing {value}");
            assert!(migration.contains(&format!("'{value}'")));
        }
        assert!(parse_record_prior_outcome("future_outcome").is_err());
        assert!(parse_record_entry_outcome("future_outcome").is_err());
        assert!(parse_seal_outcome("future_outcome").is_err());
        assert!(parse_start_outcome("future_outcome").is_err());
        assert!(parse_observe_outcome("future_outcome").is_err());
    }

    #[test]
    fn prior_identity_is_typed_and_selector_bound() {
        let startup = GatewayGenerationIdentity {
            effect_run_id: Uuid::new_v4(),
            sealed_digest: format!("sha256:{}", "a".repeat(64)),
        };
        let selector = PriorSelector::from_recorded(
            format!("generations/startup-{}", startup.effect_run_id),
            1,
            2,
        )
        .unwrap();
        let identity = RouteSetPriorLoadedIdentity::Startup(startup);
        assert!(validate_prior_evidence(&selector, Some(&identity)).is_ok());

        let mismatched =
            PriorSelector::from_recorded("generations/startup-mismatch".into(), 1, 2).unwrap();
        assert!(validate_prior_evidence(&mismatched, Some(&identity)).is_err());

        let boot = PriorSelector::from_recorded("generations/boot-live".into(), 3, 4).unwrap();
        assert!(validate_prior_evidence(&boot, None).is_ok());
        assert!(validate_prior_evidence(&boot, Some(&identity)).is_err());
    }

    #[test]
    fn transition_inputs_reject_identity_and_absent_render_drift() {
        let lease = lease();
        let identity = RouteSetGenerationIdentity::new(
            lease.publication_id,
            lease.publication_kind,
            lease.global_fence_token,
            lease.target_workshop_id,
            lease.target_route_fence_token,
            format!("sha256:{}", "f".repeat(64)),
        )
        .unwrap();
        let observed = PriorSelector::from_recorded(lease.selector.clone(), 5, 6).unwrap();
        assert!(validate_observation(&lease, &observed, &identity).is_ok());

        let mut drifted = identity;
        drifted.set_workshop_scope_for_test(
            drifted.target_workshop_id().unwrap(),
            drifted.target_route_fence_token().unwrap() + 1,
        );
        assert!(validate_observation(&lease, &observed, &drifted).is_err());

        let absent = RouteSetSealEvidence {
            workshop_id: Uuid::new_v4(),
            projection_generation: 1,
            projection_digest: format!("sha256:{}", "a".repeat(64)),
            disposition: super::super::route_set_generation_fs::RouteDisposition::Absent,
            applied_rendered_digest: Some(format!("sha256:{}", "b".repeat(64))),
            rendered_digest: format!("sha256:{}", "c".repeat(64)),
        };
        assert!(validate_seal_evidence(&absent).is_err());
        let valid_absent = RouteSetSealEvidence {
            rendered_digest: EMPTY_RENDERED_DIGEST.into(),
            ..absent
        };
        assert!(validate_seal_evidence(&valid_absent).is_ok());
    }

    #[test]
    fn final_response_is_exactly_shaped_and_worker_identity_bound() {
        let lease = lease();
        let sealed = sealed(&lease);
        let target = target_evidence(&lease);
        let parsed = parse_publication_response(response_value(&lease, &sealed)).unwrap();
        validate_publication_response_for_lease(&parsed, &lease, &sealed, &target).unwrap();

        let mut extra = response_value(&lease, &sealed);
        extra["private_payload"] = serde_json::json!(true);
        assert!(parse_publication_response(extra).is_err());

        let mut wrong_worker = response_value(&lease, &sealed);
        wrong_worker["route_set_evidence"]["route_set_digest"] =
            serde_json::json!(format!("sha256:{}", "e".repeat(64)));
        let wrong_worker = parse_publication_response(wrong_worker).unwrap();
        assert!(
            validate_publication_response_for_lease(&wrong_worker, &lease, &sealed, &target)
                .is_err()
        );

        let mut wrong_route = response_value(&lease, &sealed);
        wrong_route["route_evidence"]["route_fence_token"] = serde_json::json!(999);
        let wrong_route = parse_publication_response(wrong_route).unwrap();
        assert!(
            validate_publication_response_for_lease(&wrong_route, &lease, &sealed, &target)
                .is_err()
        );

        let mut wrong_disposition = response_value(&lease, &sealed);
        wrong_disposition["route_evidence"]["disposition"] = serde_json::json!("absent");
        let wrong_disposition = parse_publication_response(wrong_disposition).unwrap();
        assert!(
            validate_publication_response_for_lease(&wrong_disposition, &lease, &sealed, &target,)
                .is_err()
        );

        let mut wrong_render = response_value(&lease, &sealed);
        wrong_render["route_evidence"]["rendered_digest"] =
            serde_json::json!(format!("sha256:{}", "f".repeat(64)));
        let wrong_render = parse_publication_response(wrong_render).unwrap();
        assert!(
            validate_publication_response_for_lease(&wrong_render, &lease, &sealed, &target)
                .is_err()
        );

        let mut absent_nonempty = response_value(&lease, &sealed);
        absent_nonempty["route_evidence"]["disposition"] = serde_json::json!("absent");
        let absent_nonempty = parse_publication_response(absent_nonempty).unwrap();
        assert!(
            validate_publication_response_common(
                &absent_nonempty,
                &PublicationResponseExpectation {
                    publication_id: lease.publication_id,
                    publication_kind: lease.publication_kind,
                    driver_operation_id: lease.driver_operation_id,
                    workshop_id: lease.target_workshop_id,
                    projection_generation: lease.target_projection_generation,
                    projection_digest: &lease.target_projection_digest,
                    expected_disposition: Some(RouteSetAppliedDisposition::Absent),
                },
            )
            .is_err()
        );
    }

    #[test]
    fn finalization_and_result_reader_signatures_are_exact_and_dormant() {
        let migration =
            include_str!("../../migrations/0029_route_set_publication_finalization.sql");
        for signature in [
            "control.finish_route_set_publication(uuid,uuid,uuid,uuid,uuid,bigint,bigint)",
            "control.read_route_set_publication_result(uuid,uuid,text,text)",
        ] {
            assert!(migration.contains(signature), "missing {signature}");
        }
        let source = include_str!("route_set_publication_db.rs");
        assert!(source.contains("finish_route_set_publication(\n           $1,$2,$3,$4,$5,$6,$7)"));
        assert!(source.contains("read_route_set_publication_result($1,$2,$3,$4)"));
        let finish = source
            .split("pub(super) async fn finish_route_set_publication(")
            .nth(1)
            .unwrap()
            .split("pub(super) async fn read_route_set_publication_result(")
            .next()
            .unwrap();
        assert_binding_order(
            finish,
            &[
                ".bind(lease.publication_id)",
                ".bind(lease.instance_owner)",
                ".bind(lease.execution_token)",
                ".bind(lease.global_lease_token)",
                ".bind(lease.route_lease_token)",
                ".bind(lease.global_fence_token)",
                ".bind(lease.target_route_fence_token)",
            ],
        );
        let read = source
            .split("pub(super) async fn read_route_set_publication_result(")
            .nth(1)
            .unwrap()
            .split("pub(super) async fn quarantine_route_set_publication(")
            .next()
            .unwrap();
        assert_binding_order(
            read,
            &[
                ".bind(request.control_operation_id)",
                ".bind(request.workshop_id)",
                ".bind(&request.idempotency_key)",
                ".bind(&request.request_digest)",
            ],
        );
    }

    #[test]
    fn result_reader_closes_all_outcomes_and_rejects_malformed_row_shapes() {
        let lease = lease();
        let sealed = sealed(&lease);
        let request = RouteSetPublicationResultRequest {
            control_operation_id: lease.control_operation.id,
            workshop_id: lease.target_workshop_id,
            idempotency_key: "result:test".into(),
            request_digest: "a".repeat(64),
            expected_generation: lease.target_projection_generation,
            expected_projection_digest: lease.target_projection_digest.clone(),
            expected_disposition: RouteSetAppliedDisposition::Present,
        };
        assert_eq!(
            parse_publication_result_row(&request, ("absent".into(), None, None, None)).unwrap(),
            ReadRouteSetPublicationResult::Absent
        );
        assert_eq!(
            parse_publication_result_row(&request, ("conflict".into(), None, None, None)).unwrap(),
            ReadRouteSetPublicationResult::Conflict
        );
        assert!(matches!(
            parse_publication_result_row(
                &request,
                (
                    "pending".into(),
                    Some(lease.publication_id),
                    Some(lease.driver_operation_id),
                    None,
                ),
            )
            .unwrap(),
            ReadRouteSetPublicationResult::Pending { .. }
        ));
        assert!(matches!(
            parse_publication_result_row(
                &request,
                (
                    "completed".into(),
                    Some(lease.publication_id),
                    Some(lease.driver_operation_id),
                    Some(response_value(&lease, &sealed)),
                ),
            )
            .unwrap(),
            ReadRouteSetPublicationResult::Completed { .. }
        ));
        let not_applied = serde_json::json!({
            "outcome":"not_applied",
            "publication_id":lease.publication_id,
            "driver_operation_id":lease.driver_operation_id,
            "resolution_kind":"prior",
            "safe_error":"route_set_publication_not_applied"
        });
        assert!(matches!(
            parse_publication_result_row(
                &request,
                (
                    "not_applied".into(),
                    Some(lease.publication_id),
                    Some(lease.driver_operation_id),
                    Some(not_applied.clone()),
                ),
            )
            .unwrap(),
            ReadRouteSetPublicationResult::NotApplied(_)
        ));
        let mut malformed_not_applied = not_applied;
        malformed_not_applied["foreign"] = serde_json::json!(true);
        assert!(
            parse_publication_result_row(
                &request,
                (
                    "not_applied".into(),
                    Some(lease.publication_id),
                    Some(lease.driver_operation_id),
                    Some(malformed_not_applied),
                ),
            )
            .is_err()
        );

        for malformed in [
            ("absent".into(), Some(lease.publication_id), None, None),
            (
                "pending".into(),
                None,
                Some(lease.driver_operation_id),
                None,
            ),
            (
                "completed".into(),
                Some(lease.publication_id),
                Some(lease.driver_operation_id),
                None,
            ),
            ("future".into(), None, None, None),
        ] {
            assert!(parse_publication_result_row(&request, malformed).is_err());
        }

        let mut wrong_disposition = response_value(&lease, &sealed);
        wrong_disposition["route_evidence"]["disposition"] = serde_json::json!("absent");
        wrong_disposition["route_evidence"]["rendered_digest"] =
            serde_json::json!(EMPTY_RENDERED_DIGEST);
        assert!(
            parse_publication_result_row(
                &request,
                (
                    "completed".into(),
                    Some(lease.publication_id),
                    Some(lease.driver_operation_id),
                    Some(wrong_disposition),
                ),
            )
            .is_err()
        );
    }

    #[test]
    fn transition_sql_signatures_and_bind_counts_match_migration_0028() {
        let migration = include_str!("../../migrations/0028_route_set_publication_transitions.sql");
        for signature in [
            "control.record_route_set_publication_prior(uuid,uuid,uuid,uuid,uuid,bigint,bigint,text,bigint,bigint,jsonb)",
            "control.record_route_set_publication_entry(uuid,uuid,uuid,uuid,uuid,bigint,bigint,uuid,bigint,text,text,text,text)",
            "control.seal_route_set_publication(uuid,uuid,uuid,uuid,uuid,bigint,bigint,text,bigint,bigint,integer,integer,text)",
            "control.start_route_set_publication(uuid,uuid,uuid,uuid,uuid,bigint,bigint)",
            "control.observe_route_set_publication(uuid,uuid,uuid,uuid,uuid,bigint,bigint,text,bigint,bigint,jsonb)",
            "control.quarantine_route_set_publication(uuid,uuid,uuid,uuid,uuid,bigint,bigint,text)",
        ] {
            assert!(migration.contains(signature), "missing {signature}");
        }
        let source = include_str!("route_set_publication_db.rs");
        for call in [
            "record_route_set_publication_prior(\n           $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
            "record_route_set_publication_entry(\n           $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
            "seal_route_set_publication(\n           $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
            "start_route_set_publication($1,$2,$3,$4,$5,$6,$7)",
            "observe_route_set_publication(\n           $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
            "quarantine_route_set_publication($1,$2,$3,$4,$5,$6,$7,$8)",
        ] {
            assert!(source.contains(call), "missing SQL call {call}");
        }
        for (function, tail, bindings) in [
            (
                "record_route_set_publication_prior",
                "record_route_set_publication_entry",
                vec![
                    ".bind(lease.publication_id)",
                    ".bind(lease.instance_owner)",
                    ".bind(lease.execution_token)",
                    ".bind(lease.global_lease_token)",
                    ".bind(lease.route_lease_token)",
                    ".bind(lease.global_fence_token)",
                    ".bind(lease.target_route_fence_token)",
                    ".bind(prior.target())",
                    ".bind(pg_file_identity(prior.directory_device())?)",
                    ".bind(pg_file_identity(prior.directory_inode())?)",
                    ".bind(loaded_identity)",
                ],
            ),
            (
                "record_route_set_publication_entry",
                "seal_route_set_publication",
                vec![
                    ".bind(lease.publication_id)",
                    ".bind(lease.instance_owner)",
                    ".bind(lease.execution_token)",
                    ".bind(lease.global_lease_token)",
                    ".bind(lease.route_lease_token)",
                    ".bind(lease.global_fence_token)",
                    ".bind(lease.target_route_fence_token)",
                    ".bind(evidence.workshop_id)",
                    ".bind(evidence.projection_generation)",
                    ".bind(&evidence.projection_digest)",
                    ".bind(evidence.disposition.as_str())",
                    ".bind(&evidence.applied_rendered_digest)",
                    ".bind(&evidence.rendered_digest)",
                ],
            ),
            (
                "seal_route_set_publication",
                "start_route_set_publication",
                vec![
                    ".bind(lease.publication_id)",
                    ".bind(lease.instance_owner)",
                    ".bind(lease.execution_token)",
                    ".bind(lease.global_lease_token)",
                    ".bind(lease.route_lease_token)",
                    ".bind(lease.global_fence_token)",
                    ".bind(lease.target_route_fence_token)",
                    ".bind(sealed.selector.target())",
                    ".bind(pg_file_identity(sealed.selector.directory_device())?)",
                    ".bind(pg_file_identity(sealed.selector.directory_inode())?)",
                    ".bind(record_count)",
                    ".bind(present_count)",
                    ".bind(&sealed.identity.route_set_digest)",
                ],
            ),
            (
                "start_route_set_publication",
                "observe_route_set_publication",
                vec![
                    ".bind(lease.publication_id)",
                    ".bind(lease.instance_owner)",
                    ".bind(lease.execution_token)",
                    ".bind(lease.global_lease_token)",
                    ".bind(lease.route_lease_token)",
                    ".bind(lease.global_fence_token)",
                    ".bind(lease.target_route_fence_token)",
                ],
            ),
            (
                "observe_route_set_publication",
                "quarantine_route_set_publication",
                vec![
                    ".bind(lease.publication_id)",
                    ".bind(lease.instance_owner)",
                    ".bind(lease.execution_token)",
                    ".bind(lease.global_lease_token)",
                    ".bind(lease.route_lease_token)",
                    ".bind(lease.global_fence_token)",
                    ".bind(lease.target_route_fence_token)",
                    ".bind(observed.target())",
                    ".bind(pg_file_identity(observed.directory_device())?)",
                    ".bind(pg_file_identity(observed.directory_inode())?)",
                    ".bind(identity)",
                ],
            ),
            (
                "quarantine_route_set_publication",
                "validate_prior_evidence",
                vec![
                    ".bind(lease.publication_id)",
                    ".bind(lease.instance_owner)",
                    ".bind(lease.execution_token)",
                    ".bind(lease.global_lease_token)",
                    ".bind(lease.route_lease_token)",
                    ".bind(lease.global_fence_token)",
                    ".bind(lease.target_route_fence_token)",
                    ".bind(\"route_set_publication_outcome_unknown\")",
                ],
            ),
        ] {
            let body = source
                .split(&format!("pub(super) async fn {function}("))
                .nth(1)
                .unwrap()
                .split(&format!("pub(super) async fn {tail}("))
                .next()
                .unwrap();
            assert_binding_order(body, &bindings);
        }
    }

    #[test]
    fn adapter_is_registered_but_has_no_active_writer_callsite() {
        let driver_root = include_str!("../docker_driver.rs");
        assert_eq!(
            driver_root.matches("mod route_set_publication_db;").count(),
            1
        );
        assert!(!driver_root.contains("use route_set_publication_db"));
        assert!(!driver_root.contains("route_set_publication_db::"));
        for active_source in [
            include_str!("startup.rs"),
            include_str!("release.rs"),
            include_str!("recovery.rs"),
            include_str!("gateway.rs"),
        ] {
            assert!(!active_source.contains("admit_route_set_publication"));
            assert!(!active_source.contains("renew_route_set_publication"));
            assert!(!active_source.contains("read_route_set_publication_snapshot_batch"));
            assert!(!active_source.contains("record_route_set_publication_prior"));
            assert!(!active_source.contains("record_route_set_publication_entry"));
            assert!(!active_source.contains("seal_route_set_publication"));
            assert!(!active_source.contains("start_route_set_publication"));
            assert!(!active_source.contains("observe_route_set_publication"));
            assert!(!active_source.contains("quarantine_route_set_publication"));
            assert!(!active_source.contains("finish_route_set_publication"));
            assert!(!active_source.contains("read_route_set_publication_result"));
        }
    }

    #[test]
    fn tracing_contract_excludes_private_tokens_and_projection_payloads() {
        let source = include_str!("route_set_publication_db.rs");
        let attributes = source
            .split("#[tracing::instrument(")
            .skip(1)
            .take(11)
            .map(|part| part.split("\n)]").next().unwrap())
            .collect::<String>();
        for private in [
            "execution_token",
            "global_lease_token",
            "route_lease_token",
            "idempotency_key",
            "request_digest",
            "projection_digest",
            "canonical_projection",
        ] {
            assert!(!attributes.contains(private), "tracing exposes {private}");
        }
    }
}
