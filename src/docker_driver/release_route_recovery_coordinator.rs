//! Dormant candidate-forward coordinator for interrupted release-v2 recovery.
//!
//! This module owns orchestration only. All durable transitions, runtime
//! inspection, selector publication, and post-publication route observation
//! enter through narrow injected ports. A successful execution stops at an
//! [`AwaitingIndependentReview`] handoff; this module deliberately has no
//! review, terminal-finish, scheduler-registration, or dispatch surface.
#![allow(dead_code)]

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use uuid::Uuid;

use super::gateway::{ReleaseOverlayKind, reload_gateway_runtime};
use super::host_guard::SharedOdooHostGuard;
use super::release_generation_fs::{
    ReleaseGenerationDirectory, ReleaseGenerationIntent, SealedReleaseGeneration,
};
use super::release_route_recovery::{
    ReleaseMutationOutcome, ReleasePublicationRecoveryRequest,
    ReleaseRecoveryPhase as FsRecoveryPhase, publish_release_candidate_forward_authorized,
};
use super::release_route_recovery_db::{
    self, ClaimReleaseRecovery, ReadReleaseRecoveryRuntimeExpectation, ReadReleaseRecoverySnapshot,
    ReadReleaseRecoveryState, RecordReleaseRecoveryRuntimeObservation,
    ReleaseRecoveryCandidatePublicationAuthorization, ReleaseRecoveryClaim,
    ReleaseRecoveryClaimMode, ReleaseRecoveryClaimRequest, ReleaseRecoveryPhase,
    ReleaseRecoveryRuntimeExpectation, ReleaseRecoveryState, ReleaseRecoveryTransition,
};
use super::release_route_recovery_observation::{
    VerifiedReleaseRecoveryRouteObservation, observe_release_recovery_candidate_route,
};
use super::release_route_staging::{
    FrozenReleaseRouteSnapshot, FrozenReleaseRouteSnapshotRow, ReleaseRoutePublicationRecord,
    ReleaseRuntimeNameResolver, VerifiedReleaseRuntimeContext, prepare_release_candidate_overlay,
};
use super::release_runtime_observation::{
    VerifiedReleaseRuntimeObservation, observe_recovery_release_runtime,
};
use super::route_projection::RouteDisposition;
use super::{DriverError, DriverState};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CandidateForwardPhase {
    CandidateStaging,
    CandidateSealed,
    CandidatePublicationStarted,
    AwaitingWorkerFinalize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CandidateForwardContext {
    driver_operation_id: Uuid,
    fleet_run_id: Uuid,
    claim_fence: i64,
    phase: CandidateForwardPhase,
}

impl CandidateForwardContext {
    fn validate(&self) -> Result<(), DriverError> {
        if self.driver_operation_id.is_nil() || self.fleet_run_id.is_nil() || self.claim_fence <= 0
        {
            return Err(failed("release candidate-forward identity is invalid"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum ReadCandidateForwardState {
    Ready(CandidateForwardContext),
    ClaimLost,
    Terminal,
    NotForwardOnly,
    WrongPhase,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum DurableStepOutcome {
    Applied,
    Replay,
    ClaimLost,
    WrongPhase,
    OutOfOrder,
    Conflict,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CandidatePublicationOutcome {
    Published,
    AlreadyPublished,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CandidateStagingOutcome {
    Sealed,
    AlreadySealed,
}

/// Capability emitted only after the durable runtime observation has been
/// recorded. Its fields are private so orchestration cannot invent a digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct RecordedRuntimeReceipt {
    observation_digest: String,
}

impl RecordedRuntimeReceipt {
    fn validate(&self) -> Result<(), DriverError> {
        if !valid_sha256_digest(&self.observation_digest) {
            return Err(failed("release runtime receipt digest is invalid"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct AwaitingIndependentReview {
    driver_operation_id: Uuid,
    fleet_run_id: Uuid,
    claim_fence: i64,
    runtime_observation_digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum CandidateForwardRecoveryOutcome {
    AwaitingIndependentReview(AwaitingIndependentReview),
    ClaimLost,
    Terminal,
    NotEligible,
}

#[async_trait]
pub(super) trait CandidateForwardDatabase {
    type RuntimeExpectation: Send + Sync;
    type RuntimeObservation: Send + Sync;
    /// Opaque durable authority issued by the database adapter and consumable
    /// only by the publication port.
    type CandidateAuthorization: Send + Sync;
    type CandidateRouteProof: Send + Sync;

    async fn read_state(&mut self) -> Result<ReadCandidateForwardState, DriverError>;

    async fn read_runtime_expectation(
        &mut self,
        context: &CandidateForwardContext,
    ) -> Result<Self::RuntimeExpectation, DriverError>;

    async fn record_runtime_observation(
        &mut self,
        context: &CandidateForwardContext,
        observation: &Self::RuntimeObservation,
    ) -> Result<(DurableStepOutcome, Option<RecordedRuntimeReceipt>), DriverError>;

    async fn renew(&mut self, context: &CandidateForwardContext) -> Result<bool, DriverError>;

    async fn authorize_candidate(
        &mut self,
        context: &CandidateForwardContext,
        receipt: &RecordedRuntimeReceipt,
    ) -> Result<(DurableStepOutcome, Option<Self::CandidateAuthorization>), DriverError>;

    async fn resolve_candidate(
        &mut self,
        context: &CandidateForwardContext,
        proof: &Self::CandidateRouteProof,
    ) -> Result<DurableStepOutcome, DriverError>;
}

#[async_trait]
pub(super) trait RuntimeObservationPort<E, O> {
    async fn observe_runtime(&mut self, expectation: &E) -> Result<O, DriverError>;
}

#[async_trait]
pub(super) trait CandidatePublicationPort<A> {
    async fn publish_candidate(
        &mut self,
        context: &CandidateForwardContext,
        authorization: &A,
    ) -> Result<CandidatePublicationOutcome, DriverError>;
}

/// This associated proof type is intentionally opaque to the coordinator. The
/// observer constructs it and the database adapter serializes/validates it.
#[async_trait]
pub(super) trait CandidateRouteObservationPort<A, P> {
    async fn observe_candidate_route(
        &mut self,
        context: &CandidateForwardContext,
        authorization: &A,
    ) -> Result<P, DriverError>;
}

#[async_trait]
pub(super) trait CandidateStagingPort {
    /// Reconstruct an exact immutable candidate from the bounded durable
    /// snapshot, recording every entry in order and sealing it before return.
    /// Implementations must make `AlreadySealed` an exact replay only.
    async fn stage_and_seal_candidate(
        &mut self,
        context: &CandidateForwardContext,
    ) -> Result<CandidateStagingOutcome, DriverError>;
}

#[tracing::instrument(
    name = "deployment_driver.release_route_recovery.candidate_forward_dormant",
    skip_all,
    fields(recovery.outcome = tracing::field::Empty)
)]
pub(super) async fn execute_candidate_forward_recovery_dormant<D, R, S, P, O>(
    database: &mut D,
    runtime: &mut R,
    staging: &mut S,
    publication: &mut P,
    route_observer: &mut O,
) -> Result<CandidateForwardRecoveryOutcome, DriverError>
where
    D: CandidateForwardDatabase + Send,
    R: RuntimeObservationPort<D::RuntimeExpectation, D::RuntimeObservation> + Send,
    S: CandidateStagingPort + Send,
    P: CandidatePublicationPort<D::CandidateAuthorization> + Send,
    O: CandidateRouteObservationPort<D::CandidateAuthorization, D::CandidateRouteProof> + Send,
{
    let context = match database.read_state().await? {
        ReadCandidateForwardState::Ready(context) => context,
        ReadCandidateForwardState::ClaimLost => {
            return outcome(CandidateForwardRecoveryOutcome::ClaimLost);
        }
        ReadCandidateForwardState::Terminal => {
            return outcome(CandidateForwardRecoveryOutcome::Terminal);
        }
        ReadCandidateForwardState::NotForwardOnly | ReadCandidateForwardState::WrongPhase => {
            return outcome(CandidateForwardRecoveryOutcome::NotEligible);
        }
    };
    context.validate()?;

    if context.phase == CandidateForwardPhase::CandidateStaging {
        if !database.renew(&context).await? {
            return outcome(CandidateForwardRecoveryOutcome::ClaimLost);
        }
        staging.stage_and_seal_candidate(&context).await?;
        // Do not trust successful filesystem staging after an await unless the
        // same durable claim can still be renewed. A crash here safely replays
        // the bounded entry recording and exact seal.
        if !database.renew(&context).await? {
            return outcome(CandidateForwardRecoveryOutcome::ClaimLost);
        }
    }

    let expectation = database.read_runtime_expectation(&context).await?;
    let observation = runtime.observe_runtime(&expectation).await?;
    let (recorded, receipt) = database
        .record_runtime_observation(&context, &observation)
        .await?;
    if recorded == DurableStepOutcome::ClaimLost {
        return outcome(CandidateForwardRecoveryOutcome::ClaimLost);
    }
    let receipt = require_capability(recorded, receipt, "runtime observation")?;
    receipt.validate()?;

    // Renew immediately before obtaining durable effect authority. Once the
    // authorization is recorded, replay is safe even if the process crashes.
    if !database.renew(&context).await? {
        return outcome(CandidateForwardRecoveryOutcome::ClaimLost);
    }
    let (authorized, authorization) = database.authorize_candidate(&context, &receipt).await?;
    if authorized == DurableStepOutcome::ClaimLost {
        return outcome(CandidateForwardRecoveryOutcome::ClaimLost);
    }
    let authorization = require_capability(authorized, authorization, "candidate authorization")?;

    publication
        .publish_candidate(&context, &authorization)
        .await?;

    // A post-effect renewal prevents stale claim owners from recording route
    // evidence. Publication remains replayable from its durable authority.
    if !database.renew(&context).await? {
        return outcome(CandidateForwardRecoveryOutcome::ClaimLost);
    }
    let proof = route_observer
        .observe_candidate_route(&context, &authorization)
        .await?;
    if !database.renew(&context).await? {
        return outcome(CandidateForwardRecoveryOutcome::ClaimLost);
    }
    match database.resolve_candidate(&context, &proof).await? {
        DurableStepOutcome::Applied | DurableStepOutcome::Replay => outcome(
            CandidateForwardRecoveryOutcome::AwaitingIndependentReview(AwaitingIndependentReview {
                driver_operation_id: context.driver_operation_id,
                fleet_run_id: context.fleet_run_id,
                claim_fence: context.claim_fence,
                runtime_observation_digest: receipt.observation_digest,
            }),
        ),
        DurableStepOutcome::ClaimLost => outcome(CandidateForwardRecoveryOutcome::ClaimLost),
        DurableStepOutcome::WrongPhase
        | DurableStepOutcome::OutOfOrder
        | DurableStepOutcome::Conflict => Err(failed(
            "release candidate resolution was not durably recorded",
        )),
    }
}

fn require_capability<T>(
    durable: DurableStepOutcome,
    capability: Option<T>,
    label: &'static str,
) -> Result<T, DriverError> {
    match (durable, capability) {
        (DurableStepOutcome::Applied | DurableStepOutcome::Replay, Some(capability)) => {
            Ok(capability)
        }
        _ => Err(failed(format!(
            "release candidate-forward {label} response is invalid"
        ))),
    }
}

fn outcome(
    value: CandidateForwardRecoveryOutcome,
) -> Result<CandidateForwardRecoveryOutcome, DriverError> {
    let label = match &value {
        CandidateForwardRecoveryOutcome::AwaitingIndependentReview(_) => "awaiting_review",
        CandidateForwardRecoveryOutcome::ClaimLost => "claim_lost",
        CandidateForwardRecoveryOutcome::Terminal => "terminal",
        CandidateForwardRecoveryOutcome::NotEligible => "not_eligible",
    };
    tracing::Span::current().record("recovery.outcome", label);
    Ok(value)
}

type SharedRecoveryState = Arc<Mutex<Option<ReleaseRecoveryState>>>;
type SharedSealedCandidate = Arc<Mutex<Option<SealedReleaseGeneration>>>;

struct PgCandidateForwardDatabase<'a> {
    ledger: &'a sqlx::PgPool,
    claim: &'a ReleaseRecoveryClaim,
    state: SharedRecoveryState,
}

#[async_trait]
impl CandidateForwardDatabase for PgCandidateForwardDatabase<'_> {
    type RuntimeExpectation = ReleaseRecoveryRuntimeExpectation;
    type RuntimeObservation = VerifiedReleaseRuntimeObservation;
    type CandidateAuthorization = ReleaseRecoveryCandidatePublicationAuthorization;
    type CandidateRouteProof = VerifiedReleaseRecoveryRouteObservation;

    async fn read_state(&mut self) -> Result<ReadCandidateForwardState, DriverError> {
        let (outcome, state) = release_route_recovery_db::read_interrupted_release_route_state(
            self.ledger,
            self.claim,
        )
        .await?;
        match outcome {
            ReadReleaseRecoveryState::Claimed => {
                let state =
                    state.ok_or_else(|| failed("claimed release recovery state is absent"))?;
                let result = classify_pg_state(&state);
                *lock(&self.state)? = Some(state);
                Ok(result)
            }
            ReadReleaseRecoveryState::ClaimLost => Ok(ReadCandidateForwardState::ClaimLost),
            ReadReleaseRecoveryState::Terminal => Ok(ReadCandidateForwardState::Terminal),
            ReadReleaseRecoveryState::NotFound => Ok(ReadCandidateForwardState::WrongPhase),
        }
    }

    async fn read_runtime_expectation(
        &mut self,
        _: &CandidateForwardContext,
    ) -> Result<Self::RuntimeExpectation, DriverError> {
        // Refresh after candidate-staging so the database-proven seal becomes
        // the authoritative candidate artifact for publication/observation.
        let (outcome, refreshed) = release_route_recovery_db::read_interrupted_release_route_state(
            self.ledger,
            self.claim,
        )
        .await?;
        if outcome != ReadReleaseRecoveryState::Claimed {
            return Err(failed("release recovery claim was lost after staging"));
        }
        let refreshed =
            refreshed.ok_or_else(|| failed("refreshed release recovery state is absent"))?;
        let expectation =
            match release_route_recovery_db::read_interrupted_release_runtime_expectation(
                self.ledger,
                self.claim,
                &refreshed,
            )
            .await?
            {
                ReadReleaseRecoveryRuntimeExpectation::Claimed(expectation) => *expectation,
                ReadReleaseRecoveryRuntimeExpectation::ClaimLost => {
                    return Err(failed("release runtime expectation claim was lost"));
                }
                ReadReleaseRecoveryRuntimeExpectation::WrongPhase
                | ReadReleaseRecoveryRuntimeExpectation::StateDrift => {
                    return Err(failed("release runtime expectation is unavailable"));
                }
            };
        *lock(&self.state)? = Some(refreshed);
        Ok(expectation)
    }

    async fn record_runtime_observation(
        &mut self,
        _: &CandidateForwardContext,
        observation: &Self::RuntimeObservation,
    ) -> Result<(DurableStepOutcome, Option<RecordedRuntimeReceipt>), DriverError> {
        let state = current_state(&self.state)?;
        let expectation = release_route_recovery_db::read_interrupted_release_runtime_expectation(
            self.ledger,
            self.claim,
            &state,
        )
        .await?;
        let expectation = match expectation {
            ReadReleaseRecoveryRuntimeExpectation::Claimed(value) => value,
            ReadReleaseRecoveryRuntimeExpectation::ClaimLost => {
                return Ok((DurableStepOutcome::ClaimLost, None));
            }
            _ => return Ok((DurableStepOutcome::WrongPhase, None)),
        };
        let result = release_route_recovery_db::record_interrupted_release_runtime_observation(
            self.ledger,
            self.claim,
            &state,
            &expectation,
            observation,
        )
        .await?;
        Ok(match result {
            RecordReleaseRecoveryRuntimeObservation::Recorded(receipt) => (
                DurableStepOutcome::Applied,
                Some(RecordedRuntimeReceipt {
                    observation_digest: receipt.observation_digest,
                }),
            ),
            RecordReleaseRecoveryRuntimeObservation::Replay(receipt) => (
                DurableStepOutcome::Replay,
                Some(RecordedRuntimeReceipt {
                    observation_digest: receipt.observation_digest,
                }),
            ),
            RecordReleaseRecoveryRuntimeObservation::ClaimLost => {
                (DurableStepOutcome::ClaimLost, None)
            }
            RecordReleaseRecoveryRuntimeObservation::WrongPhase
            | RecordReleaseRecoveryRuntimeObservation::StateDrift => {
                (DurableStepOutcome::WrongPhase, None)
            }
            RecordReleaseRecoveryRuntimeObservation::Conflict => {
                (DurableStepOutcome::Conflict, None)
            }
        })
    }

    async fn renew(&mut self, _: &CandidateForwardContext) -> Result<bool, DriverError> {
        release_route_recovery_db::renew_interrupted_release_route_claim(self.ledger, self.claim)
            .await
    }

    async fn authorize_candidate(
        &mut self,
        _: &CandidateForwardContext,
        receipt: &RecordedRuntimeReceipt,
    ) -> Result<(DurableStepOutcome, Option<Self::CandidateAuthorization>), DriverError> {
        let state = current_state(&self.state)?;
        let (transition, authorization) =
            release_route_recovery_db::authorize_release_recovery_candidate_from_observation(
                self.ledger,
                self.claim,
                &state,
                &receipt.observation_digest,
            )
            .await?;
        Ok((map_transition(transition), authorization))
    }

    async fn resolve_candidate(
        &mut self,
        _: &CandidateForwardContext,
        proof: &Self::CandidateRouteProof,
    ) -> Result<DurableStepOutcome, DriverError> {
        let state = current_state(&self.state)?;
        let (transition, _) =
            release_route_recovery_db::resolve_interrupted_release_candidate_route_observation(
                self.ledger,
                self.claim,
                &state,
                proof,
            )
            .await?;
        Ok(map_transition(transition))
    }
}

struct LiveRuntimeObservationPort<'a>(&'a DriverState);

#[async_trait]
impl RuntimeObservationPort<ReleaseRecoveryRuntimeExpectation, VerifiedReleaseRuntimeObservation>
    for LiveRuntimeObservationPort<'_>
{
    async fn observe_runtime(
        &mut self,
        expectation: &ReleaseRecoveryRuntimeExpectation,
    ) -> Result<VerifiedReleaseRuntimeObservation, DriverError> {
        observe_recovery_release_runtime(self.0, expectation).await
    }
}

struct PgCandidateStagingPort<'a> {
    driver: &'a DriverState,
    claim: &'a ReleaseRecoveryClaim,
    state: SharedRecoveryState,
    guard: &'a SharedOdooHostGuard,
    sealed: SharedSealedCandidate,
}

#[async_trait]
impl CandidateStagingPort for PgCandidateStagingPort<'_> {
    async fn stage_and_seal_candidate(
        &mut self,
        _: &CandidateForwardContext,
    ) -> Result<CandidateStagingOutcome, DriverError> {
        let state = current_state(&self.state)?;
        let mut rows = Vec::with_capacity(state.snapshot_count);
        let mut after = None;
        loop {
            match release_route_recovery_db::read_interrupted_release_route_snapshot_batch(
                &self.driver.ledger,
                self.claim,
                &state,
                after,
                100,
            )
            .await?
            {
                ReadReleaseRecoverySnapshot::Page(page) => {
                    after = page.last().map(|row| row.workshop_id);
                    rows.extend(page);
                }
                ReadReleaseRecoverySnapshot::Complete => break,
                ReadReleaseRecoverySnapshot::ClaimLost => {
                    return Err(failed("release snapshot claim was lost"));
                }
                ReadReleaseRecoverySnapshot::WrongPhase => {
                    return Err(failed("release snapshot phase changed"));
                }
            }
        }
        if rows.len() != state.snapshot_count {
            return Err(failed("release recovery snapshot count differs"));
        }
        let snapshot = frozen_snapshot(&state, rows);
        let runtime = ReleaseRuntimeNameResolver::from_config(&self.driver.config)
            .candidate_runtime_for_snapshot(
                state.target_slot,
                snapshot
                    .rows
                    .iter()
                    .filter(|row| row.paperless_enabled)
                    .map(|row| row.workshop_id),
            )?;
        let root = self.driver.config.route_root.clone();
        let retained_guard = self.guard.try_clone().map_err(DriverError::internal)?;
        let (records, sealed) = tokio::task::spawn_blocking(move || {
            let _guard = retained_guard;
            stage_or_reopen_exact_candidate(&root, &snapshot, &runtime)
        })
        .await
        .map_err(DriverError::internal)??;
        for record in records {
            require_staging_transition(
                release_route_recovery_db::record_release_recovery_candidate_entry(
                    &self.driver.ledger,
                    self.claim,
                    record.workshop_id,
                    record.generation,
                    &record.projection_digest,
                    &record.applied_rendered_digest,
                    &record.rendered_digest,
                )
                .await?,
            )?;
        }
        let transition = release_route_recovery_db::seal_release_recovery_candidate(
            &self.driver.ledger,
            self.claim,
            &sealed.selector,
            sealed.route_count,
            &sealed.identity.route_set_digest,
        )
        .await?;
        let outcome = match transition {
            ReleaseRecoveryTransition::Sealed => CandidateStagingOutcome::Sealed,
            ReleaseRecoveryTransition::Replay => CandidateStagingOutcome::AlreadySealed,
            other => return Err(failed(format!("release candidate seal failed: {other:?}"))),
        };
        *lock(&self.sealed)? = Some(sealed);
        Ok(outcome)
    }
}

fn stage_or_reopen_exact_candidate(
    route_root: &std::path::Path,
    snapshot: &FrozenReleaseRouteSnapshot,
    runtime: &VerifiedReleaseRuntimeContext,
) -> Result<(Vec<ReleaseRoutePublicationRecord>, SealedReleaseGeneration), DriverError> {
    let mut prepared = prepare_release_candidate_overlay(snapshot, runtime)?;
    let expected_records = prepared.records();
    let expected_digest = prepared.expected_route_set_digest()?;
    let intent = ReleaseGenerationIntent::new(
        snapshot.fleet_run_id,
        snapshot.driver_operation_id,
        snapshot.original_global_fence_token,
        ReleaseOverlayKind::Candidate,
        snapshot.rows[0].target_slot.as_str(),
    )
    .map_err(DriverError::internal)?;
    match ReleaseGenerationDirectory::create_or_open(route_root, intent.clone()) {
        Ok(mut generation) => {
            let mut sealer = generation.begin_seal().map_err(DriverError::internal)?;
            let mut records = Vec::with_capacity(prepared.len());
            while let Some(record) = prepared.stage_next(&mut sealer)? {
                records.push(record);
            }
            let sealed = sealer.finish().map_err(DriverError::internal)?.clone();
            Ok((records, sealed))
        }
        Err(create_error) => {
            // Never infer replay from the create error. Reopen only if the
            // sealed directory proves the exact intent, count, digest, modes,
            // manifest, route bytes, and directory identity.
            let generation = ReleaseGenerationDirectory::open_existing_sealed(
                route_root,
                intent,
                &expected_digest,
                expected_records.len(),
            )
            .map_err(|_| DriverError::internal(create_error))?;
            Ok((
                expected_records,
                generation
                    .sealed_evidence()
                    .map_err(DriverError::internal)?
                    .clone(),
            ))
        }
    }
}

struct GuardedCandidatePublicationPort<'a> {
    driver: &'a DriverState,
    claim: &'a ReleaseRecoveryClaim,
    state: SharedRecoveryState,
    guard: &'a SharedOdooHostGuard,
    sealed: SharedSealedCandidate,
}

#[async_trait]
impl CandidatePublicationPort<ReleaseRecoveryCandidatePublicationAuthorization>
    for GuardedCandidatePublicationPort<'_>
{
    async fn publish_candidate(
        &mut self,
        _: &CandidateForwardContext,
        authorization: &ReleaseRecoveryCandidatePublicationAuthorization,
    ) -> Result<CandidatePublicationOutcome, DriverError> {
        let state = current_state(&self.state)?;
        authorization.validate_for(self.claim, &state)?;
        let sealed = candidate_seal(&state, &self.sealed)?;
        let prior = state
            .prior
            .clone()
            .ok_or_else(|| failed("release candidate recovery prior is absent"))?;
        let intent = ReleaseGenerationIntent::new(
            state.fleet_run_id,
            state.driver_operation_id,
            state.original_global_fence_token,
            ReleaseOverlayKind::Candidate,
            state.target_slot.as_str(),
        )
        .map_err(DriverError::internal)?;
        let phase = fs_phase(state.interrupted_phase)?;
        let root = self.driver.config.route_root.clone();
        let retained_guard = self.guard.try_clone().map_err(DriverError::internal)?;
        let authorization = authorization.clone();
        let identity = sealed.identity.clone();
        let selector = sealed.selector.clone();
        let route_count = sealed.route_count;
        let mutation = tokio::task::spawn_blocking(move || {
            let guard = retained_guard;
            publish_release_candidate_forward_authorized(
                &guard,
                &root,
                ReleasePublicationRecoveryRequest {
                    phase,
                    intent,
                    overlay_identity: &identity,
                    route_count,
                    overlay_selector: &selector,
                    prior_selector: &prior,
                },
                &authorization,
            )
            .map_err(DriverError::internal)
        })
        .await
        .map_err(DriverError::internal)??;
        reload_gateway_runtime(self.driver, &sealed.identity.route_set_digest).await?;
        Ok(match mutation {
            ReleaseMutationOutcome::Applied => CandidatePublicationOutcome::Published,
            ReleaseMutationOutcome::AlreadyApplied => CandidatePublicationOutcome::AlreadyPublished,
            ReleaseMutationOutcome::AlreadyAbsent => {
                return Err(failed("authorized release candidate became absent"));
            }
        })
    }
}

struct GuardedCandidateRouteObserver<'a> {
    driver: &'a DriverState,
    claim: &'a ReleaseRecoveryClaim,
    state: SharedRecoveryState,
    guard: &'a SharedOdooHostGuard,
}

#[async_trait]
impl
    CandidateRouteObservationPort<
        ReleaseRecoveryCandidatePublicationAuthorization,
        VerifiedReleaseRecoveryRouteObservation,
    > for GuardedCandidateRouteObserver<'_>
{
    async fn observe_candidate_route(
        &mut self,
        _: &CandidateForwardContext,
        authorization: &ReleaseRecoveryCandidatePublicationAuthorization,
    ) -> Result<VerifiedReleaseRecoveryRouteObservation, DriverError> {
        let state = current_state(&self.state)?;
        observe_release_recovery_candidate_route(
            self.guard,
            self.claim,
            authorization,
            self.driver,
            &self.driver.config.route_root,
            &state,
        )
        .await
    }
}

/// Concrete dormant composition. Guard acquisition deliberately precedes the
/// database claim. There is no production call site and success remains an
/// independent-review handoff rather than a terminal release response.
pub(super) async fn execute_pg_candidate_forward_recovery_dormant(
    driver: &DriverState,
    request: &ReleaseRecoveryClaimRequest,
) -> Result<CandidateForwardRecoveryOutcome, DriverError> {
    let guard = SharedOdooHostGuard::acquire(&driver.config.route_root)
        .await
        .map_err(DriverError::internal)?;
    let claimed = release_route_recovery_db::claim_interrupted_release_route_publication(
        &driver.ledger,
        request,
    )
    .await?;
    let claim = match (claimed.outcome, claimed.claim) {
        (ClaimReleaseRecovery::Acquired | ClaimReleaseRecovery::Replay, Some(claim)) => claim,
        (ClaimReleaseRecovery::Terminal, None) => {
            return Ok(CandidateForwardRecoveryOutcome::Terminal);
        }
        _ => return Ok(CandidateForwardRecoveryOutcome::NotEligible),
    };
    let state = Arc::new(Mutex::new(None));
    let sealed = Arc::new(Mutex::new(None));
    let mut database = PgCandidateForwardDatabase {
        ledger: &driver.ledger,
        claim: &claim,
        state: state.clone(),
    };
    let mut runtime = LiveRuntimeObservationPort(driver);
    let mut staging = PgCandidateStagingPort {
        driver,
        claim: &claim,
        state: state.clone(),
        guard: &guard,
        sealed: sealed.clone(),
    };
    let mut publication = GuardedCandidatePublicationPort {
        driver,
        claim: &claim,
        state: state.clone(),
        guard: &guard,
        sealed,
    };
    let mut observer = GuardedCandidateRouteObserver {
        driver,
        claim: &claim,
        state,
        guard: &guard,
    };
    execute_candidate_forward_recovery_dormant(
        &mut database,
        &mut runtime,
        &mut staging,
        &mut publication,
        &mut observer,
    )
    .await
}

fn classify_pg_state(state: &ReleaseRecoveryState) -> ReadCandidateForwardState {
    if state.claim_mode != ReleaseRecoveryClaimMode::ForwardOnly {
        return ReadCandidateForwardState::NotForwardOnly;
    }
    let phase = match state.interrupted_phase {
        ReleaseRecoveryPhase::CandidateStaging => CandidateForwardPhase::CandidateStaging,
        ReleaseRecoveryPhase::CandidateSealed => CandidateForwardPhase::CandidateSealed,
        ReleaseRecoveryPhase::CandidatePublicationStarted => {
            CandidateForwardPhase::CandidatePublicationStarted
        }
        ReleaseRecoveryPhase::AwaitingWorkerFinalize => {
            CandidateForwardPhase::AwaitingWorkerFinalize
        }
        _ => return ReadCandidateForwardState::WrongPhase,
    };
    ReadCandidateForwardState::Ready(CandidateForwardContext {
        driver_operation_id: state.driver_operation_id,
        fleet_run_id: state.fleet_run_id,
        claim_fence: state.claim_fence,
        phase,
    })
}

fn frozen_snapshot(
    state: &ReleaseRecoveryState,
    rows: Vec<super::release_route_publication_db::ReleaseRouteSnapshotItem>,
) -> FrozenReleaseRouteSnapshot {
    FrozenReleaseRouteSnapshot {
        fleet_run_id: state.fleet_run_id,
        driver_operation_id: state.driver_operation_id,
        original_global_fence_token: state.original_global_fence_token,
        protocol_version: 2,
        snapshot_count: state.snapshot_count,
        rows: rows
            .into_iter()
            .map(|row| FrozenReleaseRouteSnapshotRow {
                workshop_id: row.workshop_id,
                database_id: row.database_id,
                database_ref: row.database_ref,
                paperless_enabled: row.paperless_enabled,
                generation: row.generation,
                projection_digest: row.projection_digest,
                disposition: RouteDisposition::Present,
                canonical_projection: row.canonical_projection,
                applied_rendered_digest: row.applied_rendered_digest,
                applied_fence_token: row.applied_fence_token,
                route_fence_token: row.route_fence_token,
                target_slot: row.target_slot,
            })
            .collect(),
    }
}

fn candidate_seal(
    state: &ReleaseRecoveryState,
    staged: &SharedSealedCandidate,
) -> Result<SealedReleaseGeneration, DriverError> {
    if let Some(sealed) = lock(staged)?.clone() {
        return Ok(sealed);
    }
    let artifact = state
        .candidate_artifact
        .as_ref()
        .ok_or_else(|| failed("release recovery candidate seal is absent"))?;
    Ok(SealedReleaseGeneration {
        name: super::release_generation_fs::ReleaseGenerationName::new(
            state.fleet_run_id,
            ReleaseOverlayKind::Candidate,
        ),
        identity: artifact.identity.clone(),
        route_count: state.snapshot_count,
        selector: super::route_generation_fs::PriorSelector::from_recorded(
            state.candidate_selector.clone(),
            artifact.directory_device,
            artifact.directory_inode,
        )
        .map_err(DriverError::internal)?,
    })
}

fn fs_phase(phase: ReleaseRecoveryPhase) -> Result<FsRecoveryPhase, DriverError> {
    match phase {
        // The immutable interruption phase remains CandidateStaging after the
        // coordinator reconstructs and durably seals the exact candidate.
        ReleaseRecoveryPhase::CandidateStaging => Ok(FsRecoveryPhase::CandidateSealed),
        ReleaseRecoveryPhase::CandidateSealed => Ok(FsRecoveryPhase::CandidateSealed),
        ReleaseRecoveryPhase::CandidatePublicationStarted => {
            Ok(FsRecoveryPhase::CandidatePublicationStarted)
        }
        ReleaseRecoveryPhase::AwaitingWorkerFinalize => Ok(FsRecoveryPhase::AwaitingWorkerFinalize),
        _ => Err(failed("release recovery phase cannot publish candidate")),
    }
}

fn require_staging_transition(transition: ReleaseRecoveryTransition) -> Result<(), DriverError> {
    match transition {
        ReleaseRecoveryTransition::Recorded | ReleaseRecoveryTransition::Replay => Ok(()),
        other => Err(failed(format!(
            "release recovery candidate record failed: {other:?}"
        ))),
    }
}

fn map_transition(transition: ReleaseRecoveryTransition) -> DurableStepOutcome {
    match transition {
        ReleaseRecoveryTransition::Recorded
        | ReleaseRecoveryTransition::Sealed
        | ReleaseRecoveryTransition::Authorized => DurableStepOutcome::Applied,
        ReleaseRecoveryTransition::Replay => DurableStepOutcome::Replay,
        ReleaseRecoveryTransition::ClaimLost => DurableStepOutcome::ClaimLost,
        ReleaseRecoveryTransition::WrongPhase => DurableStepOutcome::WrongPhase,
        ReleaseRecoveryTransition::OutOfOrder => DurableStepOutcome::OutOfOrder,
        _ => DurableStepOutcome::Conflict,
    }
}

fn current_state(shared: &SharedRecoveryState) -> Result<ReleaseRecoveryState, DriverError> {
    lock(shared)?
        .clone()
        .ok_or_else(|| failed("release recovery state is absent"))
}

fn lock<T>(mutex: &Mutex<T>) -> Result<std::sync::MutexGuard<'_, T>, DriverError> {
    mutex
        .lock()
        .map_err(|_| failed("release recovery shared state lock is poisoned"))
}

fn valid_sha256_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn failed(message: impl std::fmt::Display) -> DriverError {
    DriverError::internal(message)
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::fs::DirBuilder;
    use std::os::unix::fs::DirBuilderExt as _;

    use super::*;
    use serde_json::json;
    use sha2::{Digest as _, Sha256};

    const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct Expectation;
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct RuntimeObservation;
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct CandidateProof;
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct CandidateAuthorization {
        driver_operation_id: Uuid,
        claim_fence: i64,
        observation_digest: String,
    }

    struct FakeDatabase {
        calls: Vec<&'static str>,
        state: ReadCandidateForwardState,
        recorded: DurableStepOutcome,
        authorized: DurableStepOutcome,
        resolved: DurableStepOutcome,
        renewals: VecDeque<bool>,
    }

    impl FakeDatabase {
        fn ready() -> Self {
            Self {
                calls: Vec::new(),
                state: ReadCandidateForwardState::Ready(context()),
                recorded: DurableStepOutcome::Applied,
                authorized: DurableStepOutcome::Applied,
                resolved: DurableStepOutcome::Applied,
                renewals: VecDeque::from([true, true, true]),
            }
        }
    }

    #[async_trait]
    impl CandidateForwardDatabase for FakeDatabase {
        type RuntimeExpectation = Expectation;
        type RuntimeObservation = RuntimeObservation;
        type CandidateAuthorization = CandidateAuthorization;
        type CandidateRouteProof = CandidateProof;

        async fn read_state(&mut self) -> Result<ReadCandidateForwardState, DriverError> {
            self.calls.push("read_state");
            Ok(self.state.clone())
        }

        async fn read_runtime_expectation(
            &mut self,
            _: &CandidateForwardContext,
        ) -> Result<Expectation, DriverError> {
            self.calls.push("read_expectation");
            Ok(Expectation)
        }

        async fn record_runtime_observation(
            &mut self,
            _: &CandidateForwardContext,
            _: &RuntimeObservation,
        ) -> Result<(DurableStepOutcome, Option<RecordedRuntimeReceipt>), DriverError> {
            self.calls.push("record_runtime");
            let receipt = matches!(
                self.recorded,
                DurableStepOutcome::Applied | DurableStepOutcome::Replay
            )
            .then(receipt);
            Ok((self.recorded, receipt))
        }

        async fn renew(&mut self, _: &CandidateForwardContext) -> Result<bool, DriverError> {
            self.calls.push("renew");
            Ok(self.renewals.pop_front().unwrap_or(false))
        }

        async fn authorize_candidate(
            &mut self,
            context: &CandidateForwardContext,
            receipt: &RecordedRuntimeReceipt,
        ) -> Result<(DurableStepOutcome, Option<CandidateAuthorization>), DriverError> {
            self.calls.push("authorize");
            let authorization = matches!(
                self.authorized,
                DurableStepOutcome::Applied | DurableStepOutcome::Replay
            )
            .then(|| CandidateAuthorization {
                driver_operation_id: context.driver_operation_id,
                claim_fence: context.claim_fence,
                observation_digest: receipt.observation_digest.clone(),
            });
            Ok((self.authorized, authorization))
        }

        async fn resolve_candidate(
            &mut self,
            _: &CandidateForwardContext,
            _: &CandidateProof,
        ) -> Result<DurableStepOutcome, DriverError> {
            self.calls.push("resolve");
            Ok(self.resolved)
        }
    }

    #[derive(Default)]
    struct FakeRuntime(Vec<&'static str>);
    #[async_trait]
    impl RuntimeObservationPort<Expectation, RuntimeObservation> for FakeRuntime {
        async fn observe_runtime(
            &mut self,
            _: &Expectation,
        ) -> Result<RuntimeObservation, DriverError> {
            self.0.push("observe_runtime");
            Ok(RuntimeObservation)
        }
    }

    #[derive(Default)]
    struct FakePublication {
        calls: usize,
        already_published: bool,
        fail: bool,
    }

    #[derive(Default)]
    struct FakeStaging {
        calls: usize,
        already_sealed: bool,
        fail: bool,
    }
    #[async_trait]
    impl CandidateStagingPort for FakeStaging {
        async fn stage_and_seal_candidate(
            &mut self,
            _: &CandidateForwardContext,
        ) -> Result<CandidateStagingOutcome, DriverError> {
            self.calls += 1;
            if self.fail {
                return Err(failed("simulated staging crash"));
            }
            Ok(if self.already_sealed {
                CandidateStagingOutcome::AlreadySealed
            } else {
                CandidateStagingOutcome::Sealed
            })
        }
    }
    #[async_trait]
    impl CandidatePublicationPort<CandidateAuthorization> for FakePublication {
        async fn publish_candidate(
            &mut self,
            _: &CandidateForwardContext,
            authorization: &CandidateAuthorization,
        ) -> Result<CandidatePublicationOutcome, DriverError> {
            self.calls += 1;
            assert_eq!(authorization.driver_operation_id, Uuid::from_u128(1));
            assert_eq!(authorization.claim_fence, 7);
            assert_eq!(authorization.observation_digest, DIGEST);
            if self.fail {
                return Err(failed("simulated publication crash"));
            }
            Ok(if self.already_published {
                CandidatePublicationOutcome::AlreadyPublished
            } else {
                CandidatePublicationOutcome::Published
            })
        }
    }

    #[derive(Default)]
    struct FakeObserver(usize);
    #[async_trait]
    impl CandidateRouteObservationPort<CandidateAuthorization, CandidateProof> for FakeObserver {
        async fn observe_candidate_route(
            &mut self,
            _: &CandidateForwardContext,
            _: &CandidateAuthorization,
        ) -> Result<CandidateProof, DriverError> {
            self.0 += 1;
            Ok(CandidateProof)
        }
    }

    fn context() -> CandidateForwardContext {
        CandidateForwardContext {
            driver_operation_id: Uuid::from_u128(1),
            fleet_run_id: Uuid::from_u128(2),
            claim_fence: 7,
            phase: CandidateForwardPhase::CandidatePublicationStarted,
        }
    }

    fn receipt() -> RecordedRuntimeReceipt {
        RecordedRuntimeReceipt {
            observation_digest: DIGEST.to_owned(),
        }
    }

    struct TestRouteRoot(std::path::PathBuf);

    impl TestRouteRoot {
        fn new() -> Self {
            let path = std::env::temp_dir()
                .join(format!("mb-release-coordinator-replay-{}", Uuid::new_v4()));
            DirBuilder::new().mode(0o750).create(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestRouteRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn concrete_snapshot() -> FrozenReleaseRouteSnapshot {
        let workshop_id = Uuid::parse_str("10000000-0000-4000-8000-000000000001").unwrap();
        let database_id = Uuid::parse_str("30000000-0000-4000-8000-000000000003").unwrap();
        let database_ref = crate::domain::opaque_database_ref(database_id);
        let projection = json!({
            "database_id": database_id,
            "database_ref": database_ref,
            "public_hostname": "replay.example.test",
            "paperless_mode": "absent",
            "paperless_hostname": null,
            "custom_hostnames": []
        });
        let digest = |bytes: &[u8]| format!("sha256:{:x}", Sha256::digest(bytes));
        FrozenReleaseRouteSnapshot {
            fleet_run_id: Uuid::parse_str("40000000-0000-4000-8000-000000000004").unwrap(),
            driver_operation_id: Uuid::parse_str("50000000-0000-4000-8000-000000000005").unwrap(),
            original_global_fence_token: 15,
            protocol_version: 2,
            snapshot_count: 1,
            rows: vec![FrozenReleaseRouteSnapshotRow {
                workshop_id,
                database_id,
                database_ref,
                paperless_enabled: false,
                generation: 16,
                projection_digest: digest(&serde_jcs::to_vec(&projection).unwrap()),
                disposition: RouteDisposition::Present,
                canonical_projection: projection,
                applied_rendered_digest: digest(b"applied-route"),
                applied_fence_token: 17,
                route_fence_token: 18,
                target_slot: super::super::gateway::ReleaseTargetSlot::Green,
            }],
        }
    }

    #[tokio::test]
    async fn exact_order_stops_at_independent_review_handoff() {
        let mut database = FakeDatabase::ready();
        let mut runtime = FakeRuntime::default();
        let mut publication = FakePublication::default();
        let mut observer = FakeObserver::default();

        let result = execute_candidate_forward_recovery_dormant(
            &mut database,
            &mut runtime,
            &mut FakeStaging::default(),
            &mut publication,
            &mut observer,
        )
        .await
        .unwrap();

        assert_eq!(
            result,
            CandidateForwardRecoveryOutcome::AwaitingIndependentReview(AwaitingIndependentReview {
                driver_operation_id: Uuid::from_u128(1),
                fleet_run_id: Uuid::from_u128(2),
                claim_fence: 7,
                runtime_observation_digest: DIGEST.to_owned(),
            })
        );
        assert_eq!(runtime.0, ["observe_runtime"]);
        assert_eq!(publication.calls, 1);
        assert_eq!(observer.0, 1);
        assert_eq!(
            database.calls,
            [
                "read_state",
                "read_expectation",
                "record_runtime",
                "renew",
                "authorize",
                "renew",
                "renew",
                "resolve",
            ]
        );
    }

    #[tokio::test]
    async fn replay_after_publication_crash_is_idempotent() {
        let mut first_database = FakeDatabase::ready();
        let mut first_publication = FakePublication {
            fail: true,
            ..FakePublication::default()
        };
        let first = execute_candidate_forward_recovery_dormant(
            &mut first_database,
            &mut FakeRuntime::default(),
            &mut FakeStaging::default(),
            &mut first_publication,
            &mut FakeObserver::default(),
        )
        .await;
        assert!(first.is_err());
        assert_eq!(first_publication.calls, 1);
        assert!(!first_database.calls.contains(&"resolve"));

        let mut replay_database = FakeDatabase::ready();
        replay_database.recorded = DurableStepOutcome::Replay;
        replay_database.authorized = DurableStepOutcome::Replay;
        replay_database.resolved = DurableStepOutcome::Replay;
        let mut replay_publication = FakePublication {
            already_published: true,
            ..FakePublication::default()
        };
        let replay = execute_candidate_forward_recovery_dormant(
            &mut replay_database,
            &mut FakeRuntime::default(),
            &mut FakeStaging::default(),
            &mut replay_publication,
            &mut FakeObserver::default(),
        )
        .await
        .unwrap();
        assert!(matches!(
            replay,
            CandidateForwardRecoveryOutcome::AwaitingIndependentReview(_)
        ));
    }

    #[tokio::test]
    async fn claim_loss_after_publication_prevents_observation_and_resolution() {
        let mut database = FakeDatabase::ready();
        database.renewals = VecDeque::from([true, false]);
        let mut observer = FakeObserver::default();
        let result = execute_candidate_forward_recovery_dormant(
            &mut database,
            &mut FakeRuntime::default(),
            &mut FakeStaging::default(),
            &mut FakePublication::default(),
            &mut observer,
        )
        .await
        .unwrap();
        assert_eq!(result, CandidateForwardRecoveryOutcome::ClaimLost);
        assert_eq!(observer.0, 0);
        assert!(!database.calls.contains(&"resolve"));
    }

    #[tokio::test]
    async fn claim_loss_before_authorization_prevents_publication() {
        let mut database = FakeDatabase::ready();
        database.renewals = VecDeque::from([false]);
        let mut publication = FakePublication::default();
        let result = execute_candidate_forward_recovery_dormant(
            &mut database,
            &mut FakeRuntime::default(),
            &mut FakeStaging::default(),
            &mut publication,
            &mut FakeObserver::default(),
        )
        .await
        .unwrap();
        assert_eq!(result, CandidateForwardRecoveryOutcome::ClaimLost);
        assert_eq!(publication.calls, 0);
    }

    #[tokio::test]
    async fn out_of_order_authorization_fails_closed() {
        let mut database = FakeDatabase::ready();
        database.authorized = DurableStepOutcome::OutOfOrder;
        let mut publication = FakePublication::default();
        let result = execute_candidate_forward_recovery_dormant(
            &mut database,
            &mut FakeRuntime::default(),
            &mut FakeStaging::default(),
            &mut publication,
            &mut FakeObserver::default(),
        )
        .await;
        assert!(result.is_err());
        assert_eq!(publication.calls, 0);
    }

    #[tokio::test]
    async fn claim_loss_during_durable_transitions_never_reaches_publication() {
        for lose_at_record in [true, false] {
            let mut database = FakeDatabase::ready();
            if lose_at_record {
                database.recorded = DurableStepOutcome::ClaimLost;
            } else {
                database.authorized = DurableStepOutcome::ClaimLost;
            }
            let mut publication = FakePublication::default();
            let result = execute_candidate_forward_recovery_dormant(
                &mut database,
                &mut FakeRuntime::default(),
                &mut FakeStaging::default(),
                &mut publication,
                &mut FakeObserver::default(),
            )
            .await
            .unwrap();
            assert_eq!(result, CandidateForwardRecoveryOutcome::ClaimLost);
            assert_eq!(publication.calls, 0);
        }
    }

    #[tokio::test]
    async fn candidate_staging_is_sealed_before_runtime_receipt_and_authorization() {
        let mut database = FakeDatabase::ready();
        if let ReadCandidateForwardState::Ready(context) = &mut database.state {
            context.phase = CandidateForwardPhase::CandidateStaging;
        }
        database.renewals = VecDeque::from([true, true, true, true, true]);
        let mut staging = FakeStaging::default();
        let result = execute_candidate_forward_recovery_dormant(
            &mut database,
            &mut FakeRuntime::default(),
            &mut staging,
            &mut FakePublication::default(),
            &mut FakeObserver::default(),
        )
        .await
        .unwrap();
        assert!(matches!(
            result,
            CandidateForwardRecoveryOutcome::AwaitingIndependentReview(_)
        ));
        assert_eq!(staging.calls, 1);
        assert_eq!(
            database.calls,
            [
                "read_state",
                "renew",
                "renew",
                "read_expectation",
                "record_runtime",
                "renew",
                "authorize",
                "renew",
                "renew",
                "resolve",
            ]
        );
    }

    #[tokio::test]
    async fn staging_crash_replays_exact_seal_before_any_authorization() {
        let mut crashed_database = FakeDatabase::ready();
        if let ReadCandidateForwardState::Ready(context) = &mut crashed_database.state {
            context.phase = CandidateForwardPhase::CandidateStaging;
        }
        let mut crashed_staging = FakeStaging {
            fail: true,
            ..FakeStaging::default()
        };
        let crashed = execute_candidate_forward_recovery_dormant(
            &mut crashed_database,
            &mut FakeRuntime::default(),
            &mut crashed_staging,
            &mut FakePublication::default(),
            &mut FakeObserver::default(),
        )
        .await;
        assert!(crashed.is_err());
        assert!(!crashed_database.calls.contains(&"authorize"));

        let mut replay_database = FakeDatabase::ready();
        if let ReadCandidateForwardState::Ready(context) = &mut replay_database.state {
            context.phase = CandidateForwardPhase::CandidateStaging;
        }
        replay_database.renewals = VecDeque::from([true, true, true, true, true]);
        let mut replay_staging = FakeStaging {
            already_sealed: true,
            ..FakeStaging::default()
        };
        let replay = execute_candidate_forward_recovery_dormant(
            &mut replay_database,
            &mut FakeRuntime::default(),
            &mut replay_staging,
            &mut FakePublication::default(),
            &mut FakeObserver::default(),
        )
        .await
        .unwrap();
        assert!(matches!(
            replay,
            CandidateForwardRecoveryOutcome::AwaitingIndependentReview(_)
        ));
        assert_eq!(replay_staging.calls, 1);
    }

    #[test]
    fn sealed_filesystem_before_database_records_reopens_as_exact_replay() {
        let root = TestRouteRoot::new();
        let snapshot = concrete_snapshot();
        let runtime = ReleaseRuntimeNameResolver::from_test_namespace("mb-test")
            .candidate_runtime_for_snapshot(
                super::super::gateway::ReleaseTargetSlot::Green,
                std::iter::empty(),
            )
            .unwrap();
        prepare_release_candidate_overlay(&snapshot, &runtime).unwrap();

        // First execution seals the filesystem. Deliberately simulate a crash
        // before any database candidate record or seal transition is made.
        let (first_records, first_seal) =
            stage_or_reopen_exact_candidate(&root.0, &snapshot, &runtime).unwrap();
        assert_eq!(first_records.len(), 1);

        // The retry must authenticate and reopen that exact sealed generation,
        // returning the same records for database replay instead of requiring
        // a staging-mode directory.
        let (replay_records, replay_seal) =
            stage_or_reopen_exact_candidate(&root.0, &snapshot, &runtime).unwrap();
        assert_eq!(replay_records, first_records);
        assert_eq!(replay_seal.identity, first_seal.identity);
        assert_eq!(replay_seal.selector, first_seal.selector);

        let mut drifted = snapshot;
        drifted.rows[0].applied_rendered_digest =
            format!("sha256:{:x}", Sha256::digest(b"different-applied-route"));
        assert!(stage_or_reopen_exact_candidate(&root.0, &drifted, &runtime).is_err());
    }

    #[test]
    fn source_has_no_review_finish_or_dispatch_surface() {
        let source = include_str!("release_route_recovery_coordinator.rs");
        let root = include_str!("../docker_driver.rs");
        assert_eq!(
            root.matches("mod release_route_recovery_coordinator;")
                .count(),
            1
        );
        assert!(!root.contains("execute_pg_candidate_forward_recovery_dormant("));
        assert!(
            !source
                .contains(&["finish_reviewed_interrupted_release_route_publication", "("].concat())
        );
        assert!(
            !source.contains(&["review_interrupted_release_runtime_observation", "("].concat())
        );
        assert!(!source.contains(&["tokio::", "spawn("].concat()));
        assert!(!source.contains(&["block", "_on("].concat()));

        let stage = source.find("stage_and_seal_candidate(&context)").unwrap();
        let authorize = source
            .find("authorize_candidate(&context, &receipt)")
            .unwrap();
        let publish = source
            .find("publish_candidate(&context, &authorization)")
            .unwrap();
        let observe = source
            .find("observe_candidate_route(&context, &authorization)")
            .unwrap();
        let resolve = source.find("resolve_candidate(&context, &proof)").unwrap();
        assert!(stage < authorize && authorize < publish && publish < observe && observe < resolve);
    }
}
