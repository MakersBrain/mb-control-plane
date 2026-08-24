//! Dormant host-guarded, non-terminal route-set recovery observation.
//!
//! The coordinator records evidence while all publication authority remains
//! quarantined. It has no selector-writing surface and no active call site.
#![allow(dead_code)]

use std::path::Path;

use async_trait::async_trait;
use serde_json::Value;

use super::gateway::{
    RouteSetGenerationIdentity, RunningRouteWorkerIdentity, observe_running_route_worker_identity,
};
use super::host_guard;
use super::route_generation_fs::{PriorSelector, observe_current_selector};
use super::route_set_generation_fs::{
    ExpectedPreStartState, PostStartPublicationInspection, PreStartCandidateInspection,
    RouteSetGenerationIntent, RouteSetPublicationEvidence, dispose_startup_recovery_candidate,
    inspect_post_start_publication, inspect_pre_start_candidate,
};
use super::route_set_prior::{PriorLoadedIdentity, observe_prior_loaded_identity};
use super::route_set_recovery_db::{
    self, ClaimInterruptedPublication, ClaimRefusal, InterruptedPhase, ReadRecoveryState,
    RecoveryClaimMode, RenewRecoveryClaimOutcome, ResolutionEvidence, ResolutionKind,
    ResolutionObservation, ResolveObservationOutcome, ReviewedTerminalDecision,
    RouteSetRecoveryClaim, RouteSetRecoveryClaimRequest, RouteSetRecoveryState,
};
use super::route_set_startup_publication_db::{
    self, ClaimStartupRecoveryOutcome, ReadStartupRouteSetResult, StartupRecoveryState,
    StartupTransitionOutcome,
};
use super::{DriverError, DriverState};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FilesystemClassification {
    Candidate,
    Prior,
    Unstarted,
    Inconclusive,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WorkerMatch {
    Exact,
    Different,
}

fn compare_worker_identity<T: PartialEq>(observed: &T, expected: &T) -> WorkerMatch {
    if observed == expected {
        WorkerMatch::Exact
    } else {
        WorkerMatch::Different
    }
}

/// Convert an exact recorded/replayed observation into the dormant 0031
/// terminal capability. The active observer deliberately stops before this
/// review boundary and never calls the terminal database adapter.
pub(super) fn review_route_set_terminal_decision_dormant(
    claim: &RouteSetRecoveryClaim,
    evidence: ResolutionEvidence,
    reviewed_digest: &str,
) -> Result<ReviewedTerminalDecision, DriverError> {
    ReviewedTerminalDecision::verify_accept(claim, evidence, reviewed_digest)
}

#[derive(Clone, Debug, PartialEq)]
pub(super) enum RecoveryExecutionOutcome {
    Refused(ClaimRefusal),
    Busy {
        claim_fence: i64,
        claim_mode: RecoveryClaimMode,
    },
    Terminal {
        claim_fence: i64,
    },
    Recorded(ResolutionEvidence),
    Replay(ResolutionEvidence),
}

#[async_trait]
trait RecoveryDatabase {
    async fn claim(
        &mut self,
        request: &RouteSetRecoveryClaimRequest,
    ) -> Result<ClaimInterruptedPublication, DriverError>;
    async fn read(
        &mut self,
        claim: &RouteSetRecoveryClaim,
    ) -> Result<(ReadRecoveryState, Option<RouteSetRecoveryState>), DriverError>;
    async fn renew(
        &mut self,
        claim: &RouteSetRecoveryClaim,
    ) -> Result<RenewRecoveryClaimOutcome, DriverError>;
    async fn resolve(
        &mut self,
        claim: &RouteSetRecoveryClaim,
        state: &RouteSetRecoveryState,
        observation: &ResolutionObservation,
    ) -> Result<ResolveObservationOutcome, DriverError>;
}

#[async_trait]
trait RecoveryGuard {
    type Guard;
    async fn acquire(&mut self) -> Result<Self::Guard, DriverError>;
}

trait RetainRecoveryGuard: Send + 'static {
    fn retain(&self) -> Result<Self, DriverError>
    where
        Self: Sized;
}

#[async_trait]
trait RecoveryFilesystem<H> {
    async fn classify(
        &mut self,
        state: &RouteSetRecoveryState,
        retained_guard: H,
    ) -> Result<FilesystemClassification, DriverError>;
}

#[async_trait]
trait RecoveryWorker {
    async fn candidate(
        &mut self,
        expected: &RouteSetGenerationIdentity,
    ) -> Result<WorkerMatch, DriverError>;
    async fn prior(&mut self, expected: &PriorLoadedIdentity) -> Result<WorkerMatch, DriverError>;
}

#[tracing::instrument(
    name = "deployment_driver.route_set_recovery.execute_dormant",
    skip_all,
    fields(publication.id=%request.publication_id, recovery.outcome=tracing::field::Empty)
)]
async fn execute_route_set_recovery_dormant<D, G, F, W>(
    request: &RouteSetRecoveryClaimRequest,
    database: &mut D,
    guard: &mut G,
    filesystem: &mut F,
    worker: &mut W,
) -> Result<RecoveryExecutionOutcome, DriverError>
where
    D: RecoveryDatabase + Send,
    G: RecoveryGuard + Send,
    G::Guard: RetainRecoveryGuard,
    F: RecoveryFilesystem<G::Guard> + Send,
    W: RecoveryWorker + Send,
{
    // Guard acquisition deliberately precedes the database claim. Thus an
    // admitted replacement never observes concurrently with an in-host writer.
    let _host_guard = guard.acquire().await?;
    let claim = match database.claim(request).await? {
        ClaimInterruptedPublication::Acquired(claim)
        | ClaimInterruptedPublication::Replay(claim) => claim,
        ClaimInterruptedPublication::Refused(refusal) => {
            tracing::Span::current().record("recovery.outcome", "refused");
            return Ok(RecoveryExecutionOutcome::Refused(refusal));
        }
        ClaimInterruptedPublication::Busy {
            claim_fence,
            claim_mode,
        } => {
            return Ok(RecoveryExecutionOutcome::Busy {
                claim_fence,
                claim_mode,
            });
        }
        ClaimInterruptedPublication::Terminal { claim_fence } => {
            return Ok(RecoveryExecutionOutcome::Terminal { claim_fence });
        }
    };
    let (read, state) = database.read(&claim).await?;
    if read != ReadRecoveryState::Claimed {
        return Err(failed(
            "route-set recovery claim was lost before observation",
        ));
    }
    let state = state.ok_or_else(|| failed("route-set recovery claimed state is absent"))?;
    let sampled = filesystem.classify(&state, _host_guard.retain()?).await?;
    let initial = gate_classification(&state, sampled);
    let observation = match initial {
        FilesystemClassification::Candidate => {
            renew(database, &claim).await?;
            let identity = candidate_identity(&state)?;
            match worker.candidate(&identity).await? {
                WorkerMatch::Different => {
                    renew(database, &claim).await?;
                    ResolutionObservation::inconclusive()
                }
                WorkerMatch::Exact => {
                    renew(database, &claim).await?;
                    if gate_classification(
                        &state,
                        filesystem.classify(&state, _host_guard.retain()?).await?,
                    ) != FilesystemClassification::Candidate
                    {
                        ResolutionObservation::inconclusive()
                    } else {
                        let candidate = state
                            .candidate
                            .as_ref()
                            .ok_or_else(|| failed("candidate identity is absent"))?;
                        ResolutionObservation::exact(
                            ResolutionKind::Candidate,
                            candidate,
                            serde_json::to_value(identity).map_err(DriverError::internal)?,
                        )
                    }
                }
            }
        }
        FilesystemClassification::Prior => {
            if state.interrupted_phase == InterruptedPhase::Observed {
                renew(database, &claim).await?;
                ResolutionObservation::inconclusive()
            } else {
                let expected = typed_prior(&state)?;
                renew(database, &claim).await?;
                match worker.prior(&expected).await? {
                    WorkerMatch::Different => {
                        renew(database, &claim).await?;
                        ResolutionObservation::inconclusive()
                    }
                    WorkerMatch::Exact => {
                        renew(database, &claim).await?;
                        if gate_classification(
                            &state,
                            filesystem.classify(&state, _host_guard.retain()?).await?,
                        ) != FilesystemClassification::Prior
                        {
                            ResolutionObservation::inconclusive()
                        } else {
                            let prior = state
                                .prior
                                .as_ref()
                                .ok_or_else(|| failed("prior identity is absent"))?;
                            let identity = state
                                .prior_loaded_identity
                                .clone()
                                .ok_or_else(|| failed("prior loaded identity is absent"))?;
                            ResolutionObservation::exact(ResolutionKind::Prior, prior, identity)
                        }
                    }
                }
            }
        }
        FilesystemClassification::Unstarted => {
            renew(database, &claim).await?;
            if gate_classification(
                &state,
                filesystem.classify(&state, _host_guard.retain()?).await?,
            ) == FilesystemClassification::Unstarted
            {
                ResolutionObservation::unstarted()
            } else {
                ResolutionObservation::inconclusive()
            }
        }
        FilesystemClassification::Inconclusive => {
            renew(database, &claim).await?;
            ResolutionObservation::inconclusive()
        }
    };
    // Every branch renewed immediately before its final filesystem sample (or
    // immediately before an inconclusive resolve). No await separates that
    // final sample from this non-terminal database write.
    match database.resolve(&claim, &state, &observation).await? {
        ResolveObservationOutcome::Recorded(evidence) => {
            tracing::Span::current().record("recovery.outcome", "recorded");
            Ok(RecoveryExecutionOutcome::Recorded(evidence))
        }
        ResolveObservationOutcome::Replay(evidence) => {
            tracing::Span::current().record("recovery.outcome", "replay");
            Ok(RecoveryExecutionOutcome::Replay(evidence))
        }
        _ => Err(failed("route-set recovery observation was not recorded")),
    }
}

impl ResolutionObservation {
    fn exact(kind: ResolutionKind, selector: &PriorSelector, loaded_identity: Value) -> Self {
        Self {
            kind,
            selector: Some(selector.target().to_owned()),
            directory_device: Some(selector.directory_device()),
            directory_inode: Some(selector.directory_inode()),
            loaded_identity: Some(loaded_identity),
        }
    }
    const fn unstarted() -> Self {
        Self {
            kind: ResolutionKind::Unstarted,
            selector: None,
            directory_device: None,
            directory_inode: None,
            loaded_identity: None,
        }
    }
    const fn inconclusive() -> Self {
        Self {
            kind: ResolutionKind::Inconclusive,
            selector: None,
            directory_device: None,
            directory_inode: None,
            loaded_identity: None,
        }
    }
}

async fn renew<D: RecoveryDatabase + Send>(
    database: &mut D,
    claim: &RouteSetRecoveryClaim,
) -> Result<(), DriverError> {
    match database.renew(claim).await? {
        RenewRecoveryClaimOutcome::Renewed => Ok(()),
        RenewRecoveryClaimOutcome::ClaimLost | RenewRecoveryClaimOutcome::Invalid => {
            Err(failed("route-set recovery claim renewal failed"))
        }
    }
}

fn gate_classification(
    state: &RouteSetRecoveryState,
    sampled: FilesystemClassification,
) -> FilesystemClassification {
    let allowed = match sampled {
        FilesystemClassification::Candidate => {
            matches!(
                state.interrupted_phase,
                InterruptedPhase::PublicationStarted | InterruptedPhase::Observed
            ) && state.candidate.is_some()
                && state.sealed_count.is_some()
                && state.route_set_digest.is_some()
                && state.publication_started
        }
        FilesystemClassification::Prior => {
            matches!(
                state.interrupted_phase,
                InterruptedPhase::Staging
                    | InterruptedPhase::Sealed
                    | InterruptedPhase::PublicationStarted
            ) && state.prior.is_some()
        }
        FilesystemClassification::Unstarted => {
            state.interrupted_phase == InterruptedPhase::Staging
                && state.record_count == 0
                && state.prior.is_none()
                && state.prior_loaded_identity.is_none()
                && state.candidate.is_none()
                && state.sealed_count.is_none()
                && state.sealed_present_count.is_none()
                && state.route_set_digest.is_none()
                && !state.publication_started
                && state.observed_selector.is_none()
                && state.observed_loaded_identity.is_none()
        }
        FilesystemClassification::Inconclusive => true,
    };
    if allowed {
        sampled
    } else {
        FilesystemClassification::Inconclusive
    }
}

fn candidate_identity(
    state: &RouteSetRecoveryState,
) -> Result<RouteSetGenerationIdentity, DriverError> {
    RouteSetGenerationIdentity::new(
        state.publication_id,
        state.publication_kind,
        state.original_global_fence_token,
        state.target_workshop_id,
        state.target_route_fence_token,
        state
            .route_set_digest
            .clone()
            .ok_or_else(|| failed("route-set recovery digest is absent"))?,
    )
}

fn typed_prior(state: &RouteSetRecoveryState) -> Result<PriorLoadedIdentity, DriverError> {
    let prior = state
        .prior
        .as_ref()
        .ok_or_else(|| failed("route-set recovery prior is absent"))?;
    if prior.target() == "generations/boot-live" && state.prior_loaded_identity.is_none() {
        return Ok(PriorLoadedIdentity::BootLive);
    }
    let value = state
        .prior_loaded_identity
        .clone()
        .ok_or_else(|| failed("route-set recovery prior has no exact worker identity"))?;
    if prior.target().starts_with("generations/startup-") {
        serde_json::from_value(value)
            .map(PriorLoadedIdentity::Startup)
            .map_err(|_| failed("startup prior identity is malformed"))
    } else if prior.target().starts_with("generations/release-") {
        serde_json::from_value(value)
            .map(PriorLoadedIdentity::ReleaseOverlay)
            .map_err(|_| failed("release prior identity is malformed"))
    } else {
        serde_json::from_value(value)
            .map(PriorLoadedIdentity::RouteSet)
            .map_err(|_| failed("route-set prior identity is malformed"))
    }
}

struct PgRecoveryDatabase<'a>(&'a sqlx::PgPool);
#[async_trait]
impl RecoveryDatabase for PgRecoveryDatabase<'_> {
    async fn claim(
        &mut self,
        r: &RouteSetRecoveryClaimRequest,
    ) -> Result<ClaimInterruptedPublication, DriverError> {
        route_set_recovery_db::claim_interrupted_route_set_publication(self.0, r).await
    }
    async fn read(
        &mut self,
        c: &RouteSetRecoveryClaim,
    ) -> Result<(ReadRecoveryState, Option<RouteSetRecoveryState>), DriverError> {
        route_set_recovery_db::read_interrupted_route_set_publication_state(self.0, c).await
    }
    async fn renew(
        &mut self,
        c: &RouteSetRecoveryClaim,
    ) -> Result<RenewRecoveryClaimOutcome, DriverError> {
        route_set_recovery_db::renew_interrupted_route_set_publication_claim(self.0, c).await
    }
    async fn resolve(
        &mut self,
        c: &RouteSetRecoveryClaim,
        s: &RouteSetRecoveryState,
        o: &ResolutionObservation,
    ) -> Result<ResolveObservationOutcome, DriverError> {
        route_set_recovery_db::resolve_interrupted_route_set_publication_observation(
            self.0, c, s, o,
        )
        .await
    }
}

struct SharedHostGuardPort<'a>(&'a Path);
#[async_trait]
impl RecoveryGuard for SharedHostGuardPort<'_> {
    type Guard = host_guard::SharedOdooHostGuard;
    async fn acquire(&mut self) -> Result<Self::Guard, DriverError> {
        host_guard::SharedOdooHostGuard::acquire(self.0)
            .await
            .map_err(DriverError::internal)
    }
}

impl RetainRecoveryGuard for host_guard::SharedOdooHostGuard {
    fn retain(&self) -> Result<Self, DriverError> {
        self.try_clone().map_err(DriverError::internal)
    }
}

struct LocalRecoveryFilesystem(std::path::PathBuf);
#[async_trait]
impl RecoveryFilesystem<host_guard::SharedOdooHostGuard> for LocalRecoveryFilesystem {
    async fn classify(
        &mut self,
        state: &RouteSetRecoveryState,
        retained_guard: host_guard::SharedOdooHostGuard,
    ) -> Result<FilesystemClassification, DriverError> {
        let route_root = self.0.clone();
        let state = state.clone();
        run_guarded_blocking(retained_guard, move || classify_local(&route_root, &state)).await
    }
}

async fn run_guarded_blocking<H, T, F>(guard: H, work: F) -> Result<T, DriverError>
where
    H: Send + 'static,
    T: Send + 'static,
    F: FnOnce() -> Result<T, DriverError> + Send + 'static,
{
    tokio::task::spawn_blocking(move || {
        let _guard = guard;
        work()
    })
    .await
    .map_err(DriverError::internal)?
}

fn classify_local(
    route_root: &Path,
    state: &RouteSetRecoveryState,
) -> Result<FilesystemClassification, DriverError> {
    let intent = RouteSetGenerationIntent::new(
        state.publication_id,
        state.publication_kind,
        state.original_global_fence_token,
        state.target_workshop_id,
        state.target_route_fence_token,
    )
    .map_err(DriverError::internal)?;
    match state.interrupted_phase {
        InterruptedPhase::Staging => {
            let observed = observe_current_selector(route_root).map_err(DriverError::internal)?;
            let inspection = inspect_pre_start_candidate(
                route_root,
                &intent,
                &observed,
                ExpectedPreStartState::Staging,
            )
            .map_err(DriverError::internal)?;
            match inspection {
                PreStartCandidateInspection::UnstartedAbsent
                | PreStartCandidateInspection::Pristine
                    if state.prior.is_none() && state.record_count == 0 =>
                {
                    Ok(FilesystemClassification::Unstarted)
                }
                PreStartCandidateInspection::UnstartedAbsent
                | PreStartCandidateInspection::Pristine
                    if state.prior.as_ref() == Some(&observed)
                        && prior_filesystem_matches(route_root, state)? =>
                {
                    Ok(FilesystemClassification::Prior)
                }
                PreStartCandidateInspection::StagedPartial { record_count, .. }
                    if record_count == state.record_count =>
                {
                    Ok(FilesystemClassification::Inconclusive)
                }
                _ => Ok(FilesystemClassification::Inconclusive),
            }
        }
        InterruptedPhase::Sealed => {
            let identity = candidate_identity(state)?;
            let prior = state
                .prior
                .as_ref()
                .ok_or_else(|| failed("sealed recovery prior is absent"))?;
            let evidence = publication_evidence(state, &identity)?;
            Ok(
                match inspect_pre_start_candidate(
                    route_root,
                    &intent,
                    prior,
                    ExpectedPreStartState::Sealed(evidence),
                )
                .map_err(DriverError::internal)?
                {
                    PreStartCandidateInspection::SealedNotPublished
                        if prior_filesystem_matches(route_root, state)? =>
                    {
                        FilesystemClassification::Prior
                    }
                    _ => FilesystemClassification::Inconclusive,
                },
            )
        }
        InterruptedPhase::PublicationStarted | InterruptedPhase::Observed => {
            let identity = candidate_identity(state)?;
            let prior = state
                .prior
                .as_ref()
                .ok_or_else(|| failed("started recovery prior is absent"))?;
            let inspection = inspect_post_start_publication(
                route_root,
                &intent,
                publication_evidence(state, &identity)?,
                prior,
            )
            .map_err(DriverError::internal)?;
            Ok(match (state.interrupted_phase, inspection) {
                (
                    _,
                    PostStartPublicationInspection::CandidateSelected
                    | PostStartPublicationInspection::ExchangeDone,
                ) => FilesystemClassification::Candidate,
                (
                    InterruptedPhase::PublicationStarted,
                    PostStartPublicationInspection::SealedBeforeMarker
                    | PostStartPublicationInspection::MarkerBeforeExchange
                    | PostStartPublicationInspection::PreparedExchange,
                ) if prior_filesystem_matches(route_root, state)? => {
                    FilesystemClassification::Prior
                }
                _ => FilesystemClassification::Inconclusive,
            })
        }
    }
}

fn publication_evidence<'a>(
    state: &'a RouteSetRecoveryState,
    identity: &'a RouteSetGenerationIdentity,
) -> Result<RouteSetPublicationEvidence<'a>, DriverError> {
    Ok(RouteSetPublicationEvidence {
        identity,
        route_count: state
            .sealed_count
            .ok_or_else(|| failed("sealed count is absent"))?,
        present_route_count: state
            .sealed_present_count
            .ok_or_else(|| failed("present count is absent"))?,
        candidate: state
            .candidate
            .as_ref()
            .ok_or_else(|| failed("candidate selector is absent"))?,
    })
}

fn prior_filesystem_matches(
    route_root: &Path,
    state: &RouteSetRecoveryState,
) -> Result<bool, DriverError> {
    let prior = state
        .prior
        .as_ref()
        .ok_or_else(|| failed("route-set recovery prior is absent"))?;
    let observed =
        observe_prior_loaded_identity(route_root, prior).map_err(DriverError::internal)?;
    Ok(observed.as_database_json()? == state.prior_loaded_identity)
}

struct GatewayRecoveryWorker<'a>(&'a DriverState);
#[async_trait]
impl RecoveryWorker for GatewayRecoveryWorker<'_> {
    async fn candidate(
        &mut self,
        expected: &RouteSetGenerationIdentity,
    ) -> Result<WorkerMatch, DriverError> {
        Ok(match observe_running_route_worker_identity(self.0).await? {
            RunningRouteWorkerIdentity::RouteSet(observed) => {
                compare_worker_identity(&observed, expected)
            }
            RunningRouteWorkerIdentity::Startup(_)
            | RunningRouteWorkerIdentity::ReleaseOverlay(_) => WorkerMatch::Different,
        })
    }
    async fn prior(&mut self, expected: &PriorLoadedIdentity) -> Result<WorkerMatch, DriverError> {
        let expected = match expected {
            PriorLoadedIdentity::BootLive => return Ok(WorkerMatch::Different),
            PriorLoadedIdentity::Startup(identity) => {
                RunningRouteWorkerIdentity::Startup(identity.clone())
            }
            PriorLoadedIdentity::ReleaseOverlay(identity) => {
                RunningRouteWorkerIdentity::ReleaseOverlay(identity.clone())
            }
            PriorLoadedIdentity::RouteSet(identity) => {
                RunningRouteWorkerIdentity::RouteSet(identity.clone())
            }
        };
        Ok(compare_worker_identity(
            &observe_running_route_worker_identity(self.0).await?,
            &expected,
        ))
    }
}

#[tracing::instrument(name="deployment_driver.route_set_recovery.execute_pg_dormant",skip_all,fields(publication.id=%request.publication_id))]
pub(super) async fn execute_pg_route_set_recovery_dormant(
    state: &DriverState,
    ledger: &sqlx::PgPool,
    request: &RouteSetRecoveryClaimRequest,
) -> Result<RecoveryExecutionOutcome, DriverError> {
    let mut database = PgRecoveryDatabase(ledger);
    let mut guard = SharedHostGuardPort(&state.config.route_root);
    let mut filesystem = LocalRecoveryFilesystem(state.config.route_root.clone());
    let mut worker = GatewayRecoveryWorker(state);
    execute_route_set_recovery_dormant(
        request,
        &mut database,
        &mut guard,
        &mut filesystem,
        &mut worker,
    )
    .await
}

/// Dormant startup-specific terminal recovery. It deliberately has no active
/// call site. The host guard covers claim, two-point filesystem/runtime proof,
/// any exact pre-start cleanup, and the durable terminal transition.
#[tracing::instrument(
    name = "deployment_driver.route_set_startup_recovery.execute_dormant",
    skip_all,
    fields(publication.id=%publication_id, effect.id=tracing::field::Empty,
        recovery.phase="claim", resolution.kind=tracing::field::Empty,
        recovery.outcome=tracing::field::Empty)
)]
pub(super) async fn execute_pg_startup_recovery_dormant(
    state: &DriverState,
    publication_id: uuid::Uuid,
    reconciliation_owner: uuid::Uuid,
    reconciliation_token: uuid::Uuid,
    ttl_seconds: i32,
) -> Result<Option<ReadStartupRouteSetResult>, DriverError> {
    let _host_guard = host_guard::SharedOdooHostGuard::acquire(&state.config.route_root)
        .await
        .map_err(DriverError::internal)?;
    let claim = match route_set_startup_publication_db::claim_startup_recovery(
        &state.ledger,
        publication_id,
        reconciliation_owner,
        reconciliation_token,
        ttl_seconds,
    )
    .await?
    {
        ClaimStartupRecoveryOutcome::Acquired(claim)
        | ClaimStartupRecoveryOutcome::Replay(claim) => claim,
        ClaimStartupRecoveryOutcome::Refused | ClaimStartupRecoveryOutcome::Terminal => {
            return Ok(None);
        }
    };
    let recovery =
        route_set_startup_publication_db::read_startup_recovery_state(&state.ledger, &claim)
            .await?
            .ok_or_else(|| failed("startup recovery claim was lost before observation"))?;
    tracing::Span::current().record(
        "effect.id",
        tracing::field::display(recovery.startup_effect_run_id),
    );
    tracing::Span::current().record("recovery.phase", "observation");
    let (resolution_kind, evidence) =
        classify_startup_recovery(state, &claim.claim_mode, &recovery).await?;
    tracing::Span::current().record("resolution.kind", resolution_kind);
    tracing::Span::current().record("recovery.phase", "resolve");
    let transition = route_set_startup_publication_db::resolve_startup_recovery_observation(
        &state.ledger,
        &claim,
        resolution_kind,
        &evidence,
    )
    .await?;
    if !matches!(
        transition,
        StartupTransitionOutcome::Recorded | StartupTransitionOutcome::Replay
    ) {
        return Err(failed("startup recovery observation was not recorded"));
    }
    if resolution_kind == "inconclusive" {
        tracing::Span::current().record("recovery.outcome", "inconclusive");
        return Ok(None);
    }
    if matches!(resolution_kind, "prior" | "unstarted") && claim.claim_mode == "write_cleanup" {
        tracing::Span::current().record("recovery.phase", "write_cleanup");
        dispose_startup_recovery_candidate(
            &state.config.route_root,
            recovery.publication_id,
            recovery.startup_effect_run_id,
        )
        .map_err(DriverError::internal)?;
    }
    tracing::Span::current().record("recovery.phase", "finish");
    let terminal = route_set_startup_publication_db::finish_startup_recovery(
        &state.ledger,
        &claim,
        &recovery,
        resolution_kind,
    )
    .await?;
    tracing::Span::current().record("recovery.outcome", resolution_kind);
    Ok(Some(terminal))
}

async fn classify_startup_recovery(
    driver: &DriverState,
    claim_mode: &str,
    state: &StartupRecoveryState,
) -> Result<(&'static str, Value), DriverError> {
    let null_evidence = |kind: &'static str| {
        serde_json::json!({
            "publication_id": state.publication_id,
            "resolution_kind": kind,
            "observed_selector": Value::Null,
            "observed_directory_device": Value::Null,
            "observed_directory_inode": Value::Null,
            "observed_loaded_identity": Value::Null,
        })
    };
    if claim_mode == "observe_only"
        && matches!(
            state.interrupted_phase.as_str(),
            "publication_started" | "observed"
        )
    {
        let first =
            observe_current_selector(&driver.config.route_root).map_err(DriverError::internal)?;
        let selected_prior = state
            .prior_selector
            .as_deref()
            .zip(state.prior_directory_device)
            .zip(state.prior_directory_inode)
            .is_some_and(|((selector, device), inode)| {
                selector == first.target()
                    && u64::try_from(device).ok() == Some(first.directory_device())
                    && u64::try_from(inode).ok() == Some(first.directory_inode())
            });
        match startup_observe_only_probe(
            &state.interrupted_phase,
            first.target() == state.selector,
            selected_prior,
        ) {
            StartupObserveOnlyProbe::Candidate => {
                let identity = observe_prior_loaded_identity(&driver.config.route_root, &first)
                    .map_err(DriverError::internal)?;
                let identity = match identity {
                    PriorLoadedIdentity::RouteSet(identity)
                        if identity.publication_id == state.publication_id
                            && identity.publication_kind
                                == super::gateway::RouteSetPublicationKind::Startup
                            && identity.startup_effect_run_id()
                                == Some(state.startup_effect_run_id)
                            && Some(identity.route_set_digest.as_str())
                                == state.route_set_digest.as_deref()
                            && identity.global_fence_token > 0
                            && state
                                .candidate_directory_device
                                .and_then(|value| u64::try_from(value).ok())
                                == Some(first.directory_device())
                            && state
                                .candidate_directory_inode
                                .and_then(|value| u64::try_from(value).ok())
                                == Some(first.directory_inode()) =>
                    {
                        identity
                    }
                    _ => return Ok(("inconclusive", null_evidence("inconclusive"))),
                };
                if observe_running_route_worker_identity(driver).await?
                    != RunningRouteWorkerIdentity::RouteSet(identity.clone())
                    || observe_current_selector(&driver.config.route_root)
                        .map_err(DriverError::internal)?
                        != first
                {
                    return Ok(("inconclusive", null_evidence("inconclusive")));
                }
                return Ok((
                    "candidate",
                    serde_json::json!({
                        "publication_id": state.publication_id,
                        "resolution_kind": "candidate",
                        "observed_selector": first.target(),
                        "observed_directory_device": first.directory_device(),
                        "observed_directory_inode": first.directory_inode(),
                        "observed_loaded_identity": identity,
                    }),
                ));
            }
            StartupObserveOnlyProbe::Prior => {}
            StartupObserveOnlyProbe::Inconclusive => {
                return Ok(("inconclusive", null_evidence("inconclusive")));
            }
        }
    }
    let prior_may_terminalize = startup_prior_may_terminalize(claim_mode, &state.interrupted_phase);
    if prior_may_terminalize {
        if let (Some(selector), Some(device), Some(inode)) = (
            state.prior_selector.clone(),
            state.prior_directory_device,
            state.prior_directory_inode,
        ) {
            let prior = PriorSelector::from_recorded(
                selector,
                u64::try_from(device).map_err(DriverError::internal)?,
                u64::try_from(inode).map_err(DriverError::internal)?,
            )
            .map_err(DriverError::internal)?;
            let identity =
                super::route_set_prior::observe_startup_prior_loaded_identity(driver, &prior)
                    .await?;
            let identity_json = identity.as_database_json()?;
            if identity_json == state.prior_loaded_identity
                && observe_current_selector(&driver.config.route_root)
                    .map_err(DriverError::internal)?
                    == prior
            {
                return Ok((
                    "prior",
                    serde_json::json!({
                        "publication_id": state.publication_id,
                        "resolution_kind": "prior",
                        "observed_selector": prior.target(),
                        "observed_directory_device": prior.directory_device(),
                        "observed_directory_inode": prior.directory_inode(),
                        "observed_loaded_identity": identity_json,
                    }),
                ));
            }
        } else if claim_mode == "write_cleanup"
            && state.interrupted_phase == "staging"
            && state.prior_selector.is_none()
            && state.prior_directory_device.is_none()
            && state.prior_directory_inode.is_none()
            && state.prior_loaded_identity.is_none()
            && state.route_set_digest.is_none()
        {
            return Ok(("unstarted", null_evidence("unstarted")));
        }
    }
    Ok(("inconclusive", null_evidence("inconclusive")))
}

fn startup_prior_may_terminalize(claim_mode: &str, interrupted_phase: &str) -> bool {
    (claim_mode == "write_cleanup" && matches!(interrupted_phase, "staging" | "sealed"))
        || (claim_mode == "observe_only" && interrupted_phase == "publication_started")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StartupObserveOnlyProbe {
    Candidate,
    Prior,
    Inconclusive,
}

fn startup_observe_only_probe(
    interrupted_phase: &str,
    selected_candidate: bool,
    selected_prior: bool,
) -> StartupObserveOnlyProbe {
    match (interrupted_phase, selected_candidate, selected_prior) {
        ("publication_started" | "observed", true, false) => StartupObserveOnlyProbe::Candidate,
        ("publication_started", false, true) => StartupObserveOnlyProbe::Prior,
        _ => StartupObserveOnlyProbe::Inconclusive,
    }
}

fn failed(message: impl Into<String>) -> DriverError {
    DriverError::internal(message.into())
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::fs::DirBuilder;
    use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _, symlink};
    use std::path::PathBuf;
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    use super::super::ControlOperationLease;
    use super::super::gateway::RouteSetPublicationKind;
    use super::super::route_projection::RouteDisposition;
    use super::*;
    use uuid::Uuid;

    struct LocalRoot(PathBuf);
    impl LocalRoot {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("mb-route-recovery-{}", Uuid::new_v4()));
            DirBuilder::new()
                .mode(super::super::route_generation_fs::ROUTE_ROOT_MODE)
                .create(&path)
                .unwrap();
            std::fs::create_dir_all(
                path.join(super::super::route_generation_fs::GENERATIONS_DIRECTORY)
                    .join("boot-live"),
            )
            .unwrap();
            std::fs::set_permissions(
                path.join(super::super::route_generation_fs::GENERATIONS_DIRECTORY),
                std::fs::Permissions::from_mode(
                    super::super::route_generation_fs::GENERATIONS_MODE,
                ),
            )
            .unwrap();
            std::fs::set_permissions(
                path.join(super::super::route_generation_fs::GENERATIONS_DIRECTORY)
                    .join("boot-live"),
                std::fs::Permissions::from_mode(super::super::route_generation_fs::SEALED_MODE),
            )
            .unwrap();
            symlink(
                "generations/boot-live",
                path.join(super::super::route_generation_fs::CURRENT_SELECTOR),
            )
            .unwrap();
            Self(path)
        }
    }
    impl Drop for LocalRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn request() -> RouteSetRecoveryClaimRequest {
        RouteSetRecoveryClaimRequest {
            publication_id: Uuid::new_v4(),
            reconciliation_operation: ControlOperationLease {
                id: Uuid::new_v4(),
                attempt: 3,
                owner: "reconciler".into(),
            },
            reconciliation_owner: Uuid::new_v4(),
            reconciliation_token: Uuid::new_v4(),
            ttl_seconds: 60,
        }
    }
    fn claim(request: &RouteSetRecoveryClaimRequest) -> RouteSetRecoveryClaim {
        RouteSetRecoveryClaim {
            publication_id: request.publication_id,
            reconciliation_operation_id: request.reconciliation_operation.id,
            reconciliation_operation_attempt: request.reconciliation_operation.attempt,
            reconciliation_operation_lease_owner: request.reconciliation_operation.owner.clone(),
            reconciliation_owner: request.reconciliation_owner,
            reconciliation_token: request.reconciliation_token,
            claim_fence: 5,
            claim_mode: route_set_recovery_db::RecoveryClaimMode::ObserveOnly,
            ttl_seconds: 60,
        }
    }
    fn state(
        request: &RouteSetRecoveryClaimRequest,
        phase: InterruptedPhase,
    ) -> RouteSetRecoveryState {
        let target = Uuid::new_v4();
        let digest = format!("sha256:{}", "a".repeat(64));
        let selector = super::super::route_set_generation_fs::RouteSetGenerationName::new(
            request.publication_id,
            RouteSetPublicationKind::Projection,
        )
        .selector_target();
        let candidate = PriorSelector::from_recorded(selector.clone(), 31, 32).unwrap();
        let staging = phase == InterruptedPhase::Staging;
        let prior_identity = RouteSetGenerationIdentity::new(
            Uuid::new_v4(),
            RouteSetPublicationKind::Projection,
            8,
            Uuid::new_v4(),
            9,
            format!("sha256:{}", "c".repeat(64)),
        )
        .unwrap();
        let prior_selector = super::super::route_set_generation_fs::RouteSetGenerationName::new(
            prior_identity.publication_id,
            prior_identity.publication_kind,
        )
        .selector_target();
        RouteSetRecoveryState {
            publication_id: request.publication_id,
            publication_kind: RouteSetPublicationKind::Projection,
            recovery_effect_run_id: None,
            interrupted_phase: phase,
            claim_mode: route_set_recovery_db::RecoveryClaimMode::ObserveOnly,
            claim_fence: 5,
            target_workshop_id: target,
            original_global_fence_token: 11,
            target_route_fence_token: 12,
            target_generation: 7,
            target_projection_digest: format!("sha256:{}", "b".repeat(64)),
            target_disposition: RouteDisposition::Present,
            selector,
            prior: (!staging)
                .then(|| PriorSelector::from_recorded(prior_selector, 21, 22).unwrap()),
            prior_loaded_identity: (!staging)
                .then(|| serde_json::to_value(prior_identity).unwrap()),
            candidate: (!staging).then_some(candidate),
            sealed_count: (!staging).then_some(2),
            sealed_present_count: (!staging).then_some(1),
            route_set_digest: (!staging).then_some(digest),
            record_count: if staging { 0 } else { 2 },
            publication_started: matches!(
                phase,
                InterruptedPhase::PublicationStarted | InterruptedPhase::Observed
            ),
            observed_selector: None,
            observed_loaded_identity: None,
        }
    }
    fn evidence(
        claim: &RouteSetRecoveryClaim,
        state: &RouteSetRecoveryState,
        o: &ResolutionObservation,
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
            resolution_kind: o.kind,
            interrupted_phase: state.interrupted_phase,
            observed_selector: o.selector.clone(),
            observed_directory_device: o.directory_device.map(|v| i64::try_from(v).unwrap()),
            observed_directory_inode: o.directory_inode.map(|v| i64::try_from(v).unwrap()),
            observed_loaded_identity: o.loaded_identity.clone(),
        }
    }

    struct FakeDb {
        state: RouteSetRecoveryState,
        events: Arc<Mutex<Vec<&'static str>>>,
        renew: VecDeque<RenewRecoveryClaimOutcome>,
        resolved: Arc<Mutex<Option<ResolutionKind>>>,
    }
    #[async_trait]
    impl RecoveryDatabase for FakeDb {
        async fn claim(
            &mut self,
            r: &RouteSetRecoveryClaimRequest,
        ) -> Result<ClaimInterruptedPublication, DriverError> {
            self.events.lock().unwrap().push("claim");
            Ok(ClaimInterruptedPublication::Acquired(claim(r)))
        }
        async fn read(
            &mut self,
            _: &RouteSetRecoveryClaim,
        ) -> Result<(ReadRecoveryState, Option<RouteSetRecoveryState>), DriverError> {
            self.events.lock().unwrap().push("read");
            Ok((ReadRecoveryState::Claimed, Some(self.state.clone())))
        }
        async fn renew(
            &mut self,
            _: &RouteSetRecoveryClaim,
        ) -> Result<RenewRecoveryClaimOutcome, DriverError> {
            self.events.lock().unwrap().push("renew");
            Ok(self
                .renew
                .pop_front()
                .unwrap_or(RenewRecoveryClaimOutcome::Renewed))
        }
        async fn resolve(
            &mut self,
            c: &RouteSetRecoveryClaim,
            s: &RouteSetRecoveryState,
            o: &ResolutionObservation,
        ) -> Result<ResolveObservationOutcome, DriverError> {
            self.events.lock().unwrap().push("resolve");
            *self.resolved.lock().unwrap() = Some(o.kind);
            Ok(ResolveObservationOutcome::Recorded(evidence(c, s, o)))
        }
    }
    struct Held {
        active: Arc<AtomicUsize>,
    }
    impl Drop for Held {
        fn drop(&mut self) {
            self.active.fetch_sub(1, Ordering::SeqCst);
        }
    }
    impl RetainRecoveryGuard for Held {
        fn retain(&self) -> Result<Self, DriverError> {
            self.active.fetch_add(1, Ordering::SeqCst);
            Ok(Self {
                active: self.active.clone(),
            })
        }
    }
    struct FakeGuard {
        active: Arc<AtomicUsize>,
        events: Arc<Mutex<Vec<&'static str>>>,
    }
    #[async_trait]
    impl RecoveryGuard for FakeGuard {
        type Guard = Held;
        async fn acquire(&mut self) -> Result<Held, DriverError> {
            self.events.lock().unwrap().push("guard");
            self.active.fetch_add(1, Ordering::SeqCst);
            Ok(Held {
                active: self.active.clone(),
            })
        }
    }
    struct FakeFs {
        classes: VecDeque<FilesystemClassification>,
        events: Arc<Mutex<Vec<&'static str>>>,
    }
    #[async_trait]
    impl RecoveryFilesystem<Held> for FakeFs {
        async fn classify(
            &mut self,
            _: &RouteSetRecoveryState,
            _: Held,
        ) -> Result<FilesystemClassification, DriverError> {
            self.events.lock().unwrap().push("fs");
            Ok(self
                .classes
                .pop_front()
                .unwrap_or(FilesystemClassification::Inconclusive))
        }
    }
    struct FakeWorker {
        candidate: WorkerMatch,
        error: bool,
        events: Arc<Mutex<Vec<&'static str>>>,
    }
    #[async_trait]
    impl RecoveryWorker for FakeWorker {
        async fn candidate(
            &mut self,
            _: &RouteSetGenerationIdentity,
        ) -> Result<WorkerMatch, DriverError> {
            self.events.lock().unwrap().push("worker");
            if self.error {
                Err(failed("transport"))
            } else {
                Ok(self.candidate)
            }
        }
        async fn prior(&mut self, _: &PriorLoadedIdentity) -> Result<WorkerMatch, DriverError> {
            self.events.lock().unwrap().push("worker");
            Ok(self.candidate)
        }
    }

    #[allow(clippy::type_complexity)]
    fn ports(
        classes: &[FilesystemClassification],
        worker: WorkerMatch,
        renew: &[RenewRecoveryClaimOutcome],
        phase: InterruptedPhase,
    ) -> (
        RouteSetRecoveryClaimRequest,
        FakeDb,
        FakeGuard,
        FakeFs,
        FakeWorker,
        Arc<Mutex<Vec<&'static str>>>,
        Arc<Mutex<Option<ResolutionKind>>>,
        Arc<AtomicUsize>,
    ) {
        let request = request();
        let events = Arc::new(Mutex::new(Vec::new()));
        let resolved = Arc::new(Mutex::new(None));
        let active = Arc::new(AtomicUsize::new(0));
        (
            request.clone(),
            FakeDb {
                state: state(&request, phase),
                events: events.clone(),
                renew: renew.iter().copied().collect(),
                resolved: resolved.clone(),
            },
            FakeGuard {
                active: active.clone(),
                events: events.clone(),
            },
            FakeFs {
                classes: classes.iter().copied().collect(),
                events: events.clone(),
            },
            FakeWorker {
                candidate: worker,
                error: false,
                events: events.clone(),
            },
            events,
            resolved,
            active,
        )
    }

    #[tokio::test]
    async fn candidate_is_fs_worker_fs_and_guard_precedes_claim() {
        let (request, mut db, mut guard, mut fs, mut worker, events, resolved, active) = ports(
            &[
                FilesystemClassification::Candidate,
                FilesystemClassification::Candidate,
            ],
            WorkerMatch::Exact,
            &[],
            InterruptedPhase::PublicationStarted,
        );
        let result =
            execute_route_set_recovery_dormant(&request, &mut db, &mut guard, &mut fs, &mut worker)
                .await
                .unwrap();
        assert!(matches!(result, RecoveryExecutionOutcome::Recorded(_)));
        assert_eq!(*resolved.lock().unwrap(), Some(ResolutionKind::Candidate));
        assert_eq!(
            *events.lock().unwrap(),
            vec![
                "guard", "claim", "read", "fs", "renew", "worker", "renew", "fs", "resolve"
            ]
        );
        assert_eq!(active.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn drift_unstarted_and_lease_loss_close_safely() {
        for (classes, worker, phase, expected) in [
            (
                vec![FilesystemClassification::Candidate],
                WorkerMatch::Different,
                InterruptedPhase::PublicationStarted,
                ResolutionKind::Inconclusive,
            ),
            (
                vec![
                    FilesystemClassification::Unstarted,
                    FilesystemClassification::Unstarted,
                ],
                WorkerMatch::Exact,
                InterruptedPhase::Staging,
                ResolutionKind::Unstarted,
            ),
            (
                vec![FilesystemClassification::Inconclusive],
                WorkerMatch::Exact,
                InterruptedPhase::PublicationStarted,
                ResolutionKind::Inconclusive,
            ),
        ] {
            let (request, mut db, mut guard, mut fs, mut worker, _, resolved, _) =
                ports(&classes, worker, &[], phase);
            execute_route_set_recovery_dormant(&request, &mut db, &mut guard, &mut fs, &mut worker)
                .await
                .unwrap();
            assert_eq!(*resolved.lock().unwrap(), Some(expected));
        }
        let (request, mut db, mut guard, mut fs, mut worker, _, resolved, _) = ports(
            &[
                FilesystemClassification::Candidate,
                FilesystemClassification::Candidate,
            ],
            WorkerMatch::Exact,
            &[
                RenewRecoveryClaimOutcome::Renewed,
                RenewRecoveryClaimOutcome::ClaimLost,
            ],
            InterruptedPhase::PublicationStarted,
        );
        assert!(
            execute_route_set_recovery_dormant(&request, &mut db, &mut guard, &mut fs, &mut worker)
                .await
                .is_err()
        );
        assert_eq!(*resolved.lock().unwrap(), None);
    }

    #[tokio::test]
    async fn worker_transport_error_aborts_without_persisting_evidence() {
        let (request, mut db, mut guard, mut fs, mut worker, _, resolved, _) = ports(
            &[FilesystemClassification::Candidate],
            WorkerMatch::Exact,
            &[],
            InterruptedPhase::PublicationStarted,
        );
        worker.error = true;
        assert!(
            execute_route_set_recovery_dormant(&request, &mut db, &mut guard, &mut fs, &mut worker)
                .await
                .is_err()
        );
        assert_eq!(*resolved.lock().unwrap(), None);
    }

    #[tokio::test]
    async fn exact_prior_is_rechecked_and_boot_live_is_only_inconclusive() {
        let (request, mut db, mut guard, mut fs, mut worker, _, resolved, _) = ports(
            &[
                FilesystemClassification::Prior,
                FilesystemClassification::Prior,
            ],
            WorkerMatch::Exact,
            &[],
            InterruptedPhase::PublicationStarted,
        );
        execute_route_set_recovery_dormant(&request, &mut db, &mut guard, &mut fs, &mut worker)
            .await
            .unwrap();
        assert_eq!(*resolved.lock().unwrap(), Some(ResolutionKind::Prior));

        let (request, mut db, mut guard, mut fs, mut worker, _, resolved, _) = ports(
            &[FilesystemClassification::Prior],
            WorkerMatch::Different,
            &[],
            InterruptedPhase::PublicationStarted,
        );
        db.state.prior =
            Some(PriorSelector::from_recorded("generations/boot-live".into(), 51, 52).unwrap());
        db.state.prior_loaded_identity = None;
        execute_route_set_recovery_dormant(&request, &mut db, &mut guard, &mut fs, &mut worker)
            .await
            .unwrap();
        assert_eq!(
            *resolved.lock().unwrap(),
            Some(ResolutionKind::Inconclusive)
        );

        let (request, mut db, mut guard, mut fs, mut worker, events, resolved, _) = ports(
            &[FilesystemClassification::Prior],
            WorkerMatch::Exact,
            &[],
            InterruptedPhase::Observed,
        );
        execute_route_set_recovery_dormant(&request, &mut db, &mut guard, &mut fs, &mut worker)
            .await
            .unwrap();
        assert_eq!(
            *resolved.lock().unwrap(),
            Some(ResolutionKind::Inconclusive)
        );
        assert!(!events.lock().unwrap().contains(&"worker"));
    }

    #[test]
    fn phase_classification_matrix_is_closed() {
        let request = request();
        for phase in [
            InterruptedPhase::Staging,
            InterruptedPhase::Sealed,
            InterruptedPhase::PublicationStarted,
            InterruptedPhase::Observed,
        ] {
            let mut state = state(&request, phase);
            if phase == InterruptedPhase::Staging {
                assert_eq!(
                    gate_classification(&state, FilesystemClassification::Unstarted),
                    FilesystemClassification::Unstarted
                );
                assert_eq!(
                    gate_classification(&state, FilesystemClassification::Candidate),
                    FilesystemClassification::Inconclusive
                );
                let prior_identity = RouteSetGenerationIdentity::new(
                    Uuid::new_v4(),
                    RouteSetPublicationKind::Projection,
                    3,
                    Uuid::new_v4(),
                    4,
                    format!("sha256:{}", "d".repeat(64)),
                )
                .unwrap();
                state.prior = Some(
                    PriorSelector::from_recorded(
                        super::super::route_set_generation_fs::RouteSetGenerationName::new(
                            prior_identity.publication_id,
                            prior_identity.publication_kind,
                        )
                        .selector_target(),
                        41,
                        42,
                    )
                    .unwrap(),
                );
                state.prior_loaded_identity = Some(serde_json::to_value(prior_identity).unwrap());
                assert_eq!(
                    gate_classification(&state, FilesystemClassification::Prior),
                    FilesystemClassification::Prior
                );
                assert_eq!(
                    gate_classification(&state, FilesystemClassification::Unstarted),
                    FilesystemClassification::Inconclusive
                );
            } else {
                let candidate_allowed = matches!(
                    phase,
                    InterruptedPhase::PublicationStarted | InterruptedPhase::Observed
                );
                let prior_allowed = phase != InterruptedPhase::Observed;
                assert_eq!(
                    gate_classification(&state, FilesystemClassification::Candidate),
                    if candidate_allowed {
                        FilesystemClassification::Candidate
                    } else {
                        FilesystemClassification::Inconclusive
                    }
                );
                assert_eq!(
                    gate_classification(&state, FilesystemClassification::Prior),
                    if prior_allowed {
                        FilesystemClassification::Prior
                    } else {
                        FilesystemClassification::Inconclusive
                    }
                );
                assert_eq!(
                    gate_classification(&state, FilesystemClassification::Unstarted),
                    FilesystemClassification::Inconclusive
                );
            }
        }
    }

    #[test]
    fn valid_different_worker_identity_is_distinct_from_parse_or_transport_error() {
        let expected = RouteSetGenerationIdentity::new(
            Uuid::new_v4(),
            RouteSetPublicationKind::Projection,
            3,
            Uuid::new_v4(),
            4,
            format!("sha256:{}", "e".repeat(64)),
        )
        .unwrap();
        let mut different = expected.clone();
        different.set_workshop_scope_for_test(
            different.target_workshop_id().unwrap(),
            different.target_route_fence_token().unwrap() + 1,
        );
        assert_eq!(
            compare_worker_identity(&expected, &expected),
            WorkerMatch::Exact
        );
        assert_eq!(
            compare_worker_identity(&different, &expected),
            WorkerMatch::Different
        );
        let startup =
            RunningRouteWorkerIdentity::Startup(super::super::gateway::GatewayGenerationIdentity {
                effect_run_id: Uuid::new_v4(),
                sealed_digest: format!("sha256:{}", "f".repeat(64)),
            });
        let route_set = RunningRouteWorkerIdentity::RouteSet(expected);
        assert_eq!(
            compare_worker_identity(&route_set, &startup),
            WorkerMatch::Different
        );
        let gateway = include_str!("gateway.rs");
        let body = gateway
            .split("pub(super) async fn observe_running_route_worker_identity")
            .nth(1)
            .unwrap()
            .split("async fn observe_generation_endpoint")
            .next()
            .unwrap();
        assert!(body.contains("ROUTE_WORKER_IDENTITY_ENDPOINT"));
        assert!(body.contains("observe_generation_endpoint"));
        assert!(body.contains("parse_running_route_worker_identity"));
        assert!(!body.contains("if let Ok"));
    }

    #[test]
    fn concrete_staging_classifies_absent_pristine_prior_partial_and_artifact_safely() {
        let request = request();
        let absent = LocalRoot::new();
        let state = state(&request, InterruptedPhase::Staging);
        assert_eq!(
            classify_local(&absent.0, &state).unwrap(),
            FilesystemClassification::Unstarted
        );

        let pristine = LocalRoot::new();
        let intent = RouteSetGenerationIntent::new(
            state.publication_id,
            state.publication_kind,
            state.original_global_fence_token,
            state.target_workshop_id,
            state.target_route_fence_token,
        )
        .unwrap();
        let mut generation =
            super::super::route_set_generation_fs::RouteSetGenerationDirectory::create_or_open(
                &pristine.0,
                intent.clone(),
            )
            .unwrap();
        assert_eq!(
            classify_local(&pristine.0, &state).unwrap(),
            FilesystemClassification::Unstarted
        );
        let mut prior_state = state.clone();
        prior_state.prior = Some(observe_current_selector(&pristine.0).unwrap());
        assert_eq!(
            classify_local(&pristine.0, &prior_state).unwrap(),
            FilesystemClassification::Prior
        );
        {
            let mut sealer = generation.begin_seal().unwrap();
            sealer
                .stage_present(
                    Uuid::parse_str("10000000-0000-0000-0000-000000000001").unwrap(),
                    1,
                    &format!("sha256:{}", "a".repeat(64)),
                    &format!("sha256:{}", "b".repeat(64)),
                    b"server { return 204; }\n",
                )
                .unwrap();
        }
        let mut partial = state.clone();
        partial.record_count = 1;
        assert_eq!(
            classify_local(&pristine.0, &partial).unwrap(),
            FilesystemClassification::Inconclusive
        );

        let artifact = LocalRoot::new();
        let name = format!(
            ".current-route-publish-{}-projection",
            state.publication_id.simple()
        );
        symlink(&state.selector, artifact.0.join(&name)).unwrap();
        assert!(classify_local(&artifact.0, &state).is_err());
        assert!(artifact.0.join(name).is_symlink());
    }

    struct PendingWorker {
        entered: Arc<tokio::sync::Notify>,
    }
    #[async_trait]
    impl RecoveryWorker for PendingWorker {
        async fn candidate(
            &mut self,
            _: &RouteSetGenerationIdentity,
        ) -> Result<WorkerMatch, DriverError> {
            self.entered.notify_one();
            std::future::pending().await
        }
        async fn prior(&mut self, _: &PriorLoadedIdentity) -> Result<WorkerMatch, DriverError> {
            std::future::pending().await
        }
    }

    #[tokio::test]
    async fn cancellation_during_worker_probe_releases_guard_only_after_owned_work_stops() {
        let (request, mut db, mut guard, mut fs, _, _, _, active) = ports(
            &[FilesystemClassification::Candidate],
            WorkerMatch::Exact,
            &[],
            InterruptedPhase::PublicationStarted,
        );
        let entered = Arc::new(tokio::sync::Notify::new());
        let waiting = entered.notified();
        let mut worker = PendingWorker {
            entered: entered.clone(),
        };
        let task = tokio::spawn(async move {
            execute_route_set_recovery_dormant(&request, &mut db, &mut guard, &mut fs, &mut worker)
                .await
        });
        waiting.await;
        assert_eq!(active.load(Ordering::SeqCst), 1);
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_eq!(active.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn cancelled_blocking_observation_retains_guard_until_joined_work_exits() {
        let active = Arc::new(AtomicUsize::new(1));
        let guard = Held {
            active: active.clone(),
        };
        let entered = Arc::new(tokio::sync::Notify::new());
        let waiting = entered.notified();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let notify = entered.clone();
        let task = tokio::spawn(async move {
            run_guarded_blocking(guard, move || {
                notify.notify_one();
                release_rx.recv().map_err(DriverError::internal)?;
                Ok(())
            })
            .await
        });
        waiting.await;
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_eq!(active.load(Ordering::SeqCst), 1);
        release_tx.send(()).unwrap();
        for _ in 0..100 {
            if active.load(Ordering::SeqCst) == 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(active.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn coordinator_is_registered_once_dormant_observe_only_and_privacy_safe() {
        let root = include_str!("../docker_driver.rs");
        assert_eq!(root.matches("mod route_set_recovery;").count(), 1);
        for active in [
            include_str!("startup.rs"),
            include_str!("release.rs"),
            include_str!("recovery.rs"),
        ] {
            assert!(!active.contains("route_set_recovery::"));
            assert!(!active.contains("execute_pg_route_set_recovery_dormant"));
        }
        let production = include_str!("route_set_recovery.rs")
            .split("#[cfg(test)]\nmod tests")
            .next()
            .unwrap();
        for forbidden in [
            "dispose_pre_start_candidate",
            "resume_post_start_publication_forward",
            "restore_prior",
            "recover_exchange_artifact",
            "ExclusiveOriginalWriterResumeAuthority",
            ".publish(",
        ] {
            assert!(!production.contains(forbidden));
        }
        assert!(production.contains("spawn_blocking"));
        for startup_recovery_step in [
            "claim_startup_recovery",
            "read_startup_recovery_state",
            "observe_startup_prior_loaded_identity",
            "dispose_startup_recovery_candidate",
            "resolve_startup_recovery_observation",
            "finish_startup_recovery",
        ] {
            assert!(production.contains(startup_recovery_step));
        }
        assert_eq!(
            root.matches("execute_pg_startup_recovery_dormant").count(),
            0
        );
        for instrument in production.match_indices("#[tracing::instrument") {
            let annotation = &production[instrument.0..].split("async fn").next().unwrap();
            assert!(annotation.contains("skip_all"));
            assert!(!annotation.contains("token"));
        }
    }

    #[test]
    fn startup_prior_terminal_gate_includes_post_start_before_exchange_only() {
        assert!(startup_prior_may_terminalize("write_cleanup", "staging"));
        assert!(startup_prior_may_terminalize("write_cleanup", "sealed"));
        assert!(startup_prior_may_terminalize(
            "observe_only",
            "publication_started"
        ));
        assert!(!startup_prior_may_terminalize("observe_only", "observed"));
        assert!(!startup_prior_may_terminalize("observe_only", "sealed"));
        assert!(!startup_prior_may_terminalize(
            "write_cleanup",
            "publication_started"
        ));
    }

    #[test]
    fn startup_observe_only_classifier_falls_through_to_prior_before_exchange() {
        assert_eq!(
            startup_observe_only_probe("publication_started", true, false),
            StartupObserveOnlyProbe::Candidate
        );
        assert_eq!(
            startup_observe_only_probe("publication_started", false, true),
            StartupObserveOnlyProbe::Prior
        );
        assert_eq!(
            startup_observe_only_probe("observed", true, false),
            StartupObserveOnlyProbe::Candidate
        );
        assert_eq!(
            startup_observe_only_probe("observed", false, true),
            StartupObserveOnlyProbe::Inconclusive
        );
        assert_eq!(
            startup_observe_only_probe("sealed", false, true),
            StartupObserveOnlyProbe::Inconclusive
        );
        assert_eq!(
            startup_observe_only_probe("publication_started", false, false),
            StartupObserveOnlyProbe::Inconclusive
        );
        assert_eq!(
            startup_observe_only_probe("publication_started", true, true),
            StartupObserveOnlyProbe::Inconclusive
        );
    }
}
