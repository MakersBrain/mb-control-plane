//! Dormant coordinator for one immutable full-fleet route-set publication.
//!
//! The coordinator makes the selector exchange boundary explicit: failures
//! before `start` leave no claim of success, while every failure at or after
//! the attempted start is quarantined and never restores the prior selector.
//! This module has no active call site and does not activate generation-v1.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::future::Future;
use std::path::Path;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use async_trait::async_trait;
use axum::http::StatusCode;
use sqlx::PgPool;
use uuid::Uuid;

use super::gateway::{
    RouteSetGenerationIdentity, observe_running_gateway_generation,
    observe_running_release_overlay_generation, observe_running_route_set_generation,
    reload_gateway_runtime,
};
use super::route_generation_fs::{PriorSelector, observe_current_selector};
use super::route_projection::{PaperlessRouteMode, RouteProjection};
use super::route_set_generation_fs::{
    RouteSetGenerationDirectory, RouteSetGenerationIntent, RouteSetSealEvidence,
    SealedRouteSetGeneration,
};
use super::route_set_prior::PriorLoadedIdentity;
use super::route_set_publication_db::{
    self, FinishRouteSetPublicationOutcome, FrozenSnapshotItem, ObserveRouteSetPublicationOutcome,
    ReadRouteSetPublicationResult, RecordRouteSetEntryOutcome, RecordRouteSetPriorOutcome,
    RouteSetPriorLoadedIdentity, RouteSetPublicationAdmission, RouteSetPublicationAdmissionRequest,
    RouteSetPublicationLease, RouteSetPublicationResponse, RouteSetPublicationResultRequest,
    SealRouteSetPublicationOutcome, StartRouteSetPublicationOutcome,
};
use super::route_set_recovery_publication_db::{
    self, FinishRecoveryRouteSetPublicationOutcome, ReadRecoveryRouteSetAdmission,
    ReadRecoveryRouteSetPublicationResult, RecoveryRouteSetAdmission,
    RecoveryRouteSetAdmissionRequest, RecoveryRouteSetNotAppliedResult,
    RecoveryRouteSetPublicationLease, RecoveryRouteSetPublicationResponse,
};
use super::route_set_staging::{
    FrozenRouteRuntimeContext, PreparedFrozenRouteSet, prepare_frozen_route_set,
};
use super::route_set_startup_publication_db::{
    self, FinishStartupRouteSetOutcome, ReadStartupRouteSetAdmission, StartupFrozenRuntime,
    StartupRecordEntry, StartupRouteSetAdmission, StartupRouteSetAdmissionRequest,
    StartupRouteSetLease, StartupRouteSetNotApplied, StartupRouteSetResponse,
    StartupTransitionOutcome,
};
use super::task_supervisor::{
    DriverTaskFailure, DriverTaskKind, DriverTaskMetadata, DriverTaskWaitError,
    OwnedTaskCapability, TryAdmitError,
};
use super::{DriverError, DriverState, host_guard};
use super::{startup, startup_publication};

const DEFAULT_SNAPSHOT_BATCH_SIZE: usize = 128;
const MAX_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);
const MAX_HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PublicationRisk {
    Reversible,
    StartAttempted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PublicationPhase {
    Admission,
    PriorObservation,
    SnapshotRead,
    Preparation,
    Staging,
    Sealing,
    StartAttempted,
    Publishing,
    RuntimeReload,
    Observation,
    Finalization,
}

struct PublicationFailure {
    phase: PublicationPhase,
    risk: PublicationRisk,
    safe_class: &'static str,
    source: DriverError,
}

pub(super) struct RouteSetPublicationPlan<'a> {
    pub admission: &'a RouteSetPublicationAdmissionRequest,
    pub snapshot_batch_size: usize,
}

impl<'a> RouteSetPublicationPlan<'a> {
    pub(super) fn new(admission: &'a RouteSetPublicationAdmissionRequest) -> Self {
        Self {
            admission,
            snapshot_batch_size: DEFAULT_SNAPSHOT_BATCH_SIZE,
        }
    }
}

struct ObservedPendingFinalization<G, Q, H>
where
    Q: CancellationQuarantine<H>,
{
    lease: RouteSetPublicationLease,
    prior: PriorSelector,
    sealed: SealedRouteSetGeneration,
    target_evidence: RouteSetSealEvidence,
    observed: PriorSelector,
    result_request: RouteSetPublicationResultRequest,
    _host_guard: G,
    _cancellation: ArmedCancellationQuarantine<Q, H>,
}

impl<G, Q, H> ObservedPendingFinalization<G, Q, H>
where
    Q: CancellationQuarantine<H>,
{
    #[tracing::instrument(
        name = "deployment_driver.route_set_publication.finalize_dormant",
        skip_all,
        fields(
            publication.id = %self.lease.publication_id,
            publication.kind = self.lease.publication_kind.as_str(),
            workshop_id = %self.lease.target_workshop_id,
            publication.phase = "finalization",
            transition.outcome = tracing::field::Empty
        )
    )]
    async fn finalize<D, F, R, B>(
        mut self,
        database: &mut D,
        filesystem: &mut F,
        runtime: &mut R,
        heartbeat: &mut B,
    ) -> Result<RouteSetPublicationResponse, DriverError>
    where
        D: PublicationDatabase + Send,
        F: PublicationFilesystem,
        R: PublicationRuntime,
        B: PublicationHeartbeat + Send,
    {
        let heartbeat_lease = self.lease.clone();
        let result = with_publication_heartbeat(
            async {
                if self.observed != self.sealed.selector {
                    return Err(failure(PublicationPhase::Finalization));
                }
                let runtime_identity = runtime.observe_candidate(&self.sealed.identity).await?;
                if runtime_identity != self.sealed.identity {
                    return Err(failure(PublicationPhase::Finalization));
                }
                // This final descriptor-safe observation follows the awaited worker
                // probe and is therefore the last local fact sampled before the
                // atomic database finish call.
                let (selected, filesystem_identity) = filesystem.observe_candidate()?;
                if selected != self.observed
                    || selected != self.sealed.selector
                    || filesystem_identity != self.sealed.identity
                {
                    return Err(failure(PublicationPhase::Finalization));
                }
                match database
                    .finish(&self.lease, &self.sealed, &self.target_evidence)
                    .await?
                {
                    FinishRouteSetPublicationOutcome::Completed(response) => {
                        tracing::Span::current().record("transition.outcome", "completed");
                        Ok(response)
                    }
                    FinishRouteSetPublicationOutcome::Replay(response) => {
                        tracing::Span::current().record("transition.outcome", "replay");
                        Ok(response)
                    }
                    FinishRouteSetPublicationOutcome::AuthorityLost => {
                        tracing::Span::current().record("transition.outcome", "authority_lost");
                        Err(failure(PublicationPhase::Finalization))
                    }
                    FinishRouteSetPublicationOutcome::Conflict => {
                        tracing::Span::current().record("transition.outcome", "conflict");
                        Err(failure(PublicationPhase::Finalization))
                    }
                    FinishRouteSetPublicationOutcome::WrongPhase => {
                        tracing::Span::current().record("transition.outcome", "wrong_phase");
                        Err(failure(PublicationPhase::Finalization))
                    }
                    FinishRouteSetPublicationOutcome::Invalid => {
                        tracing::Span::current().record("transition.outcome", "invalid");
                        Err(failure(PublicationPhase::Finalization))
                    }
                }
            },
            heartbeat.monitor(&heartbeat_lease),
        )
        .await;
        match result {
            Ok(response) => {
                // A completed/replay receipt is the only state that makes a
                // cancellation quarantine unnecessary. The host guard remains
                // owned by `self` until after this terminal confirmation.
                self._cancellation.disarm();
                Ok(response)
            }
            Err(source) => match database.read_result(&self.result_request).await {
                Ok(ReadRouteSetPublicationResult::Completed { response, .. }) => {
                    self._cancellation.disarm();
                    Ok(*response)
                }
                _ => Err(report_failure(PublicationFailure::new(
                    PublicationPhase::Finalization,
                    PublicationRisk::StartAttempted,
                    source,
                ))),
            },
        }
    }
}

struct ObservedPublicationEvidence {
    prior: PriorSelector,
    sealed: SealedRouteSetGeneration,
    target_evidence: RouteSetSealEvidence,
    observed: PriorSelector,
}

type RetainedGuard<G> = <<G as PublicationGuard>::Guard as RetainHostGuard>::Retained;
type CoordinateOutcome<G, Q> =
    ObservedPendingFinalization<<G as PublicationGuard>::Guard, Q, RetainedGuard<G>>;

#[async_trait]
trait PublicationDatabase {
    async fn read_result(
        &mut self,
        request: &RouteSetPublicationResultRequest,
    ) -> Result<ReadRouteSetPublicationResult, DriverError>;
    async fn admit(
        &mut self,
        request: &RouteSetPublicationAdmissionRequest,
    ) -> Result<RouteSetPublicationAdmission, DriverError>;
    async fn renew(&mut self, lease: &RouteSetPublicationLease) -> Result<bool, DriverError>;
    async fn read_snapshot(
        &mut self,
        lease: &RouteSetPublicationLease,
        after: Option<Uuid>,
        limit: usize,
    ) -> Result<Vec<FrozenSnapshotItem>, DriverError>;
    async fn record_prior(
        &mut self,
        lease: &RouteSetPublicationLease,
        prior: &PriorSelector,
        loaded: Option<&RouteSetPriorLoadedIdentity>,
    ) -> Result<RecordRouteSetPriorOutcome, DriverError>;
    async fn record_entry(
        &mut self,
        lease: &RouteSetPublicationLease,
        evidence: &RouteSetSealEvidence,
    ) -> Result<RecordRouteSetEntryOutcome, DriverError>;
    async fn seal(
        &mut self,
        lease: &RouteSetPublicationLease,
        sealed: &SealedRouteSetGeneration,
    ) -> Result<SealRouteSetPublicationOutcome, DriverError>;
    async fn start(
        &mut self,
        lease: &RouteSetPublicationLease,
    ) -> Result<StartRouteSetPublicationOutcome, DriverError>;
    async fn observe(
        &mut self,
        lease: &RouteSetPublicationLease,
        observed: &PriorSelector,
        identity: &RouteSetGenerationIdentity,
    ) -> Result<ObserveRouteSetPublicationOutcome, DriverError>;
    async fn finish(
        &mut self,
        lease: &RouteSetPublicationLease,
        sealed: &SealedRouteSetGeneration,
        target_evidence: &RouteSetSealEvidence,
    ) -> Result<FinishRouteSetPublicationOutcome, DriverError>;
    async fn quarantine(&mut self, lease: &RouteSetPublicationLease) -> Result<bool, DriverError>;
}

#[async_trait]
trait PublicationHeartbeat {
    async fn monitor(&mut self, lease: &RouteSetPublicationLease) -> DriverError;
}

/// Race one publication phase against its authority heartbeat. Neither future
/// is detached: completion of either branch drops the other before returning.
async fn with_publication_heartbeat<T>(
    effect: impl Future<Output = Result<T, DriverError>>,
    heartbeat: impl Future<Output = DriverError>,
) -> Result<T, DriverError> {
    tokio::pin!(effect);
    tokio::pin!(heartbeat);
    tokio::select! {
        biased;
        error = &mut heartbeat => Err(error),
        result = &mut effect => result,
    }
}

#[async_trait]
trait PublicationFilesystem {
    fn observe_prior(&mut self) -> Result<(PriorSelector, PriorLoadedIdentity), DriverError>;
    fn prepare(
        &mut self,
        lease: &RouteSetPublicationLease,
        runtime: &FrozenRouteRuntimeContext,
        snapshot: &[FrozenSnapshotItem],
    ) -> Result<(), DriverError>;
    fn begin(&mut self, lease: &RouteSetPublicationLease) -> Result<(), DriverError>;
    async fn stage_and_seal(
        &mut self,
        recorder: &mut (dyn DurableRowRecorder + Send),
    ) -> Result<SealedRouteSetGeneration, DriverError>;
    fn publish(&mut self, prior: &PriorSelector) -> Result<(), DriverError>;
    fn observe_candidate(
        &mut self,
    ) -> Result<(PriorSelector, RouteSetGenerationIdentity), DriverError>;
}

#[async_trait]
trait DurableRowRecorder {
    async fn record(&mut self, evidence: &RouteSetSealEvidence) -> Result<(), DriverError>;
}

struct DatabaseRowRecorder<'a, D> {
    database: &'a mut D,
    lease: &'a RouteSetPublicationLease,
    target_evidence: Option<RouteSetSealEvidence>,
}

#[async_trait]
impl<D: PublicationDatabase + Send> DurableRowRecorder for DatabaseRowRecorder<'_, D> {
    async fn record(&mut self, evidence: &RouteSetSealEvidence) -> Result<(), DriverError> {
        if evidence.workshop_id == self.lease.target_workshop_id {
            let expected = match evidence.disposition {
                super::route_set_generation_fs::RouteDisposition::Present => {
                    route_set_publication_db::RouteSetAppliedDisposition::Present
                }
                super::route_set_generation_fs::RouteDisposition::Absent => {
                    route_set_publication_db::RouteSetAppliedDisposition::Absent
                }
            };
            if expected != self.lease.expected_disposition {
                return Err(failure(PublicationPhase::Staging));
            }
            if self
                .target_evidence
                .as_ref()
                .is_some_and(|stored| stored != evidence)
            {
                return Err(failure(PublicationPhase::Staging));
            }
            self.target_evidence = Some(evidence.clone());
        }
        accept_entry(self.database.record_entry(self.lease, evidence).await?)?;
        require_renewal(self.database, self.lease, PublicationPhase::Staging).await
    }
}

#[async_trait]
trait PublicationGuard {
    type Guard: RetainHostGuard;

    async fn acquire(&mut self) -> Result<Self::Guard, DriverError>;
}

trait RetainHostGuard {
    type Retained: Send + 'static;

    fn retain_for_quarantine(&self) -> Result<Self::Retained, DriverError>;
}

trait CancellationQuarantine<H>: Clone {
    fn schedule(&self, lease: RouteSetPublicationLease, host_guard: H);
}

struct ArmedCancellationQuarantine<Q, H>
where
    Q: CancellationQuarantine<H>,
{
    scheduler: Q,
    lease: RouteSetPublicationLease,
    retained_host_guard: Option<H>,
    armed: bool,
}

struct AcquiredPublicationContext<'a, Q, H>
where
    Q: CancellationQuarantine<H>,
{
    plan: &'a RouteSetPublicationPlan<'a>,
    lease: &'a RouteSetPublicationLease,
    risk: &'a mut PublicationRisk,
    phase: &'a StdMutex<PublicationPhase>,
    cancellation: &'a mut ArmedCancellationQuarantine<Q, H>,
    preflight: &'a (PriorSelector, PriorLoadedIdentity),
}

impl<Q, H> ArmedCancellationQuarantine<Q, H>
where
    Q: CancellationQuarantine<H>,
{
    fn new(scheduler: Q, lease: RouteSetPublicationLease, retained_host_guard: H) -> Self {
        Self {
            scheduler,
            lease,
            retained_host_guard: Some(retained_host_guard),
            armed: false,
        }
    }

    fn arm(&mut self) {
        self.armed = true;
    }

    fn disarm(&mut self) {
        self.armed = false;
        self.retained_host_guard.take();
    }
}

impl<Q, H> Drop for ArmedCancellationQuarantine<Q, H>
where
    Q: CancellationQuarantine<H>,
{
    fn drop(&mut self) {
        if self.armed
            && let Some(host_guard) = self.retained_host_guard.take()
        {
            self.scheduler.schedule(self.lease.clone(), host_guard);
        }
    }
}

#[async_trait]
trait PublicationRuntime {
    async fn observe_prior(&mut self, identity: &PriorLoadedIdentity) -> Result<(), DriverError>;
    async fn reload(&mut self, expected_digest: &str) -> Result<(), DriverError>;
    async fn freeze_context(
        &mut self,
        snapshot: &[FrozenSnapshotItem],
    ) -> Result<FrozenRouteRuntimeContext, DriverError>;
    async fn observe_candidate(
        &mut self,
        expected: &RouteSetGenerationIdentity,
    ) -> Result<RouteSetGenerationIdentity, DriverError>;
}

struct SqlPublicationDatabase<'a> {
    ledger: &'a PgPool,
}

struct SqlPublicationHeartbeat<'a> {
    ledger: &'a PgPool,
    next_renewal: Option<tokio::time::Instant>,
}

#[async_trait]
impl PublicationHeartbeat for SqlPublicationHeartbeat<'_> {
    #[tracing::instrument(
        name = "deployment_driver.route_set_publication.heartbeat_dormant",
        skip_all,
        fields(
            publication.id = %lease.publication_id,
            workshop_id = %lease.target_workshop_id,
            heartbeat.interval_seconds = heartbeat_interval(lease).as_secs(),
            heartbeat.outcome = tracing::field::Empty
        )
    )]
    async fn monitor(&mut self, lease: &RouteSetPublicationLease) -> DriverError {
        let interval_duration = heartbeat_interval(lease);
        let timeout_duration = heartbeat_timeout(interval_duration);
        loop {
            let deadline = heartbeat_deadline(
                &mut self.next_renewal,
                tokio::time::Instant::now(),
                interval_duration,
            );
            tokio::time::sleep_until(deadline).await;
            match tokio::time::timeout(
                timeout_duration,
                route_set_publication_db::renew_route_set_publication(self.ledger, lease),
            )
            .await
            {
                Ok(Ok(true)) => {
                    self.next_renewal = Some(tokio::time::Instant::now() + interval_duration);
                }
                Ok(Ok(false)) => {
                    tracing::Span::current().record("heartbeat.outcome", "authority_lost");
                    return failure(PublicationPhase::Admission);
                }
                Ok(Err(error)) => {
                    tracing::Span::current().record("heartbeat.outcome", "error");
                    return error;
                }
                Err(_) => {
                    tracing::Span::current().record("heartbeat.outcome", "timeout");
                    return DriverError::internal("route-set publication heartbeat timed out");
                }
            }
        }
    }
}

fn heartbeat_interval(lease: &RouteSetPublicationLease) -> Duration {
    Duration::from_secs((u64::try_from(lease.ttl_seconds).unwrap_or(60) / 3).max(1))
        .min(MAX_HEARTBEAT_INTERVAL)
}

fn heartbeat_timeout(interval: Duration) -> Duration {
    (interval / 2).min(MAX_HEARTBEAT_TIMEOUT)
}

fn heartbeat_deadline(
    next: &mut Option<tokio::time::Instant>,
    now: tokio::time::Instant,
    interval: Duration,
) -> tokio::time::Instant {
    *next.get_or_insert(now + interval)
}

#[async_trait]
impl PublicationDatabase for SqlPublicationDatabase<'_> {
    async fn read_result(
        &mut self,
        request: &RouteSetPublicationResultRequest,
    ) -> Result<ReadRouteSetPublicationResult, DriverError> {
        route_set_publication_db::read_route_set_publication_result(self.ledger, request).await
    }

    async fn admit(
        &mut self,
        request: &RouteSetPublicationAdmissionRequest,
    ) -> Result<RouteSetPublicationAdmission, DriverError> {
        route_set_publication_db::admit_route_set_publication(self.ledger, request).await
    }

    async fn renew(&mut self, lease: &RouteSetPublicationLease) -> Result<bool, DriverError> {
        route_set_publication_db::renew_route_set_publication(self.ledger, lease).await
    }

    async fn read_snapshot(
        &mut self,
        lease: &RouteSetPublicationLease,
        after: Option<Uuid>,
        limit: usize,
    ) -> Result<Vec<FrozenSnapshotItem>, DriverError> {
        route_set_publication_db::read_route_set_publication_snapshot_batch(
            self.ledger,
            lease,
            after,
            limit,
        )
        .await
    }

    async fn record_prior(
        &mut self,
        lease: &RouteSetPublicationLease,
        prior: &PriorSelector,
        loaded: Option<&RouteSetPriorLoadedIdentity>,
    ) -> Result<RecordRouteSetPriorOutcome, DriverError> {
        route_set_publication_db::record_route_set_publication_prior(
            self.ledger,
            lease,
            prior,
            loaded,
        )
        .await
    }

    async fn record_entry(
        &mut self,
        lease: &RouteSetPublicationLease,
        evidence: &RouteSetSealEvidence,
    ) -> Result<RecordRouteSetEntryOutcome, DriverError> {
        route_set_publication_db::record_route_set_publication_entry(self.ledger, lease, evidence)
            .await
    }

    async fn seal(
        &mut self,
        lease: &RouteSetPublicationLease,
        sealed: &SealedRouteSetGeneration,
    ) -> Result<SealRouteSetPublicationOutcome, DriverError> {
        route_set_publication_db::seal_route_set_publication(self.ledger, lease, sealed).await
    }

    async fn start(
        &mut self,
        lease: &RouteSetPublicationLease,
    ) -> Result<StartRouteSetPublicationOutcome, DriverError> {
        route_set_publication_db::start_route_set_publication(self.ledger, lease).await
    }

    async fn observe(
        &mut self,
        lease: &RouteSetPublicationLease,
        observed: &PriorSelector,
        identity: &RouteSetGenerationIdentity,
    ) -> Result<ObserveRouteSetPublicationOutcome, DriverError> {
        route_set_publication_db::observe_route_set_publication(
            self.ledger,
            lease,
            observed,
            identity,
        )
        .await
    }

    async fn finish(
        &mut self,
        lease: &RouteSetPublicationLease,
        sealed: &SealedRouteSetGeneration,
        target_evidence: &RouteSetSealEvidence,
    ) -> Result<FinishRouteSetPublicationOutcome, DriverError> {
        route_set_publication_db::finish_route_set_publication(
            self.ledger,
            lease,
            sealed,
            target_evidence,
        )
        .await
    }

    async fn quarantine(&mut self, lease: &RouteSetPublicationLease) -> Result<bool, DriverError> {
        route_set_publication_db::quarantine_route_set_publication(self.ledger, lease).await
    }
}

struct SharedHostGuardPort<'a> {
    route_root: &'a Path,
}

impl RetainHostGuard for host_guard::SharedOdooHostGuard {
    type Retained = host_guard::SharedOdooHostGuard;

    fn retain_for_quarantine(&self) -> Result<Self::Retained, DriverError> {
        self.try_clone().map_err(DriverError::internal)
    }
}

#[derive(Clone)]
struct PgCancellationQuarantine {
    ledger: PgPool,
    result_request: RouteSetPublicationResultRequest,
    cleanup: Arc<CleanupTracker>,
    supervisor: Arc<OwnedTaskCapability>,
}

#[derive(Default)]
struct CleanupTracker {
    pending: std::sync::atomic::AtomicUsize,
    changed: tokio::sync::Notify,
}

impl CleanupTracker {
    async fn wait(&self) {
        loop {
            let notified = self.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.pending.load(std::sync::atomic::Ordering::SeqCst) == 0 {
                return;
            }
            notified.await;
        }
    }
}

struct CleanupFinished(Arc<CleanupTracker>);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CleanupDecision {
    Durable,
    Retry,
}

fn cleanup_decision(
    quarantine: Result<bool, ()>,
    result: Option<&ReadRouteSetPublicationResult>,
) -> CleanupDecision {
    if quarantine == Ok(true)
        || matches!(
            result,
            Some(
                ReadRouteSetPublicationResult::Completed { .. }
                    | ReadRouteSetPublicationResult::NotApplied(_)
            )
        )
    {
        CleanupDecision::Durable
    } else {
        CleanupDecision::Retry
    }
}

fn cleanup_retry_delay(initial: Duration, failure_count: u32, seed: Uuid) -> Duration {
    const MAX_DELAY: Duration = Duration::from_secs(30);
    let exponent = failure_count.saturating_sub(1).min(10);
    let base = initial.saturating_mul(1_u32 << exponent).min(MAX_DELAY);
    let seed_bytes = seed.as_bytes();
    let jitter_percent =
        80 + u32::from(seed_bytes[usize::try_from(failure_count % 16).unwrap_or(0)] % 41);
    base.saturating_mul(jitter_percent)
        .div_f32(100.0)
        .min(MAX_DELAY)
}

const fn report_cleanup_retry(failure_count: u32) -> bool {
    failure_count == 1 || failure_count.is_power_of_two()
}

impl Drop for CleanupFinished {
    fn drop(&mut self) {
        self.0
            .pending
            .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        self.0.changed.notify_waiters();
    }
}

impl CancellationQuarantine<host_guard::SharedOdooHostGuard> for PgCancellationQuarantine {
    fn schedule(
        &self,
        lease: RouteSetPublicationLease,
        host_guard: host_guard::SharedOdooHostGuard,
    ) {
        let ledger = self.ledger.clone();
        let request = self.result_request.clone();
        let cleanup = self.cleanup.clone();
        let cleanup_registration = cleanup.clone();
        cleanup
            .pending
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let cleanup_task = self.supervisor.try_spawn_cleanup(move |_| async move {
            let _finished = CleanupFinished(cleanup);
            let _host_guard = host_guard;
            let mut failure_count = 0_u32;
            loop {
                let quarantine =
                    route_set_publication_db::quarantine_route_set_publication(&ledger, &lease)
                        .await;
                let result = if matches!(quarantine, Ok(false)) {
                    route_set_publication_db::read_route_set_publication_result(&ledger, &request)
                        .await
                        .ok()
                } else {
                    None
                };
                let decision = cleanup_decision(quarantine.map_err(|_| ()), result.as_ref());
                if decision == CleanupDecision::Durable {
                    tracing::warn!(publication.id = %lease.publication_id,
                        "cancelled route-set publication reached durable cleanup");
                    return Ok(());
                }
                failure_count = failure_count.saturating_add(1);
                let delay = cleanup_retry_delay(
                    Duration::from_secs(1),
                    failure_count,
                    lease.publication_id,
                );
                if report_cleanup_retry(failure_count) {
                    tracing::warn!(
                        publication.id = %lease.publication_id,
                        retry.count = failure_count,
                        retry.delay_ms = delay.as_millis(),
                        error_class = "publication_cleanup_pending",
                        "route-set publication cleanup awaits durable confirmation"
                    );
                }
                tokio::time::sleep(delay).await;
            }
        });
        if cleanup_task.is_err() {
            drop(CleanupFinished(cleanup_registration));
            tracing::error!(
                error_class = "publication_cleanup_registration_failed",
                "route-set publication cleanup registration failed"
            );
        }
    }
}

fn supervisor_wait_error(_error: DriverTaskWaitError) -> DriverError {
    DriverError::internal("driver task supervisor stopped")
}

fn supervisor_admit_error(_error: TryAdmitError) -> DriverError {
    DriverError(
        StatusCode::SERVICE_UNAVAILABLE,
        "driver task admission is unavailable".into(),
    )
}

#[async_trait]
impl PublicationGuard for SharedHostGuardPort<'_> {
    type Guard = host_guard::SharedOdooHostGuard;

    async fn acquire(&mut self) -> Result<Self::Guard, DriverError> {
        host_guard::SharedOdooHostGuard::acquire(self.route_root)
            .await
            .map_err(DriverError::internal)
    }
}

struct GatewayPublicationRuntime<'a> {
    state: &'a DriverState,
}

#[async_trait]
impl PublicationRuntime for GatewayPublicationRuntime<'_> {
    async fn observe_prior(&mut self, identity: &PriorLoadedIdentity) -> Result<(), DriverError> {
        match identity {
            PriorLoadedIdentity::BootLive => Err(failure(PublicationPhase::PriorObservation)),
            PriorLoadedIdentity::Startup(identity) => {
                observe_running_gateway_generation(self.state, identity)
                    .await
                    .map(drop)
            }
            PriorLoadedIdentity::ReleaseOverlay(identity) => {
                observe_running_release_overlay_generation(self.state, identity)
                    .await
                    .map(drop)
            }
            PriorLoadedIdentity::RouteSet(identity) => {
                observe_running_route_set_generation(self.state, identity)
                    .await
                    .map(drop)
            }
        }
    }

    async fn reload(&mut self, expected_digest: &str) -> Result<(), DriverError> {
        reload_gateway_runtime(self.state, expected_digest).await
    }

    async fn freeze_context(
        &mut self,
        snapshot: &[FrozenSnapshotItem],
    ) -> Result<FrozenRouteRuntimeContext, DriverError> {
        let odoo_upstream = super::active_odoo_runtime_container(self.state).await?;
        let mut paperless_upstreams = BTreeMap::new();
        for item in snapshot {
            let projection = RouteProjection::parse_optional(
                Some(&item.canonical_projection),
                &item.projection_digest,
                item.disposition,
            )?;
            if matches!(
                projection.paperless_mode(),
                PaperlessRouteMode::ReadOnly | PaperlessRouteMode::ReadWrite
            ) {
                paperless_upstreams.insert(
                    item.workshop_id,
                    self.state.config.docker_resource(format!(
                        "paperless-{}",
                        super::tenant_key(item.workshop_id)
                    )),
                );
            }
        }
        Ok(FrozenRouteRuntimeContext {
            odoo_upstream,
            paperless_upstreams,
        })
    }

    async fn observe_candidate(
        &mut self,
        expected: &RouteSetGenerationIdentity,
    ) -> Result<RouteSetGenerationIdentity, DriverError> {
        observe_running_route_set_generation(self.state, expected).await
    }
}

struct LocalPublicationFilesystem<'a> {
    route_root: &'a Path,
    prepared: Option<PreparedFrozenRouteSet>,
    generation: Option<RouteSetGenerationDirectory>,
    sealed: Option<SealedRouteSetGeneration>,
}

impl LocalPublicationFilesystem<'_> {
    fn generation_mut(&mut self) -> Result<&mut RouteSetGenerationDirectory, DriverError> {
        self.generation
            .as_mut()
            .ok_or_else(|| failure(PublicationPhase::Staging))
    }
}

#[async_trait]
impl PublicationFilesystem for LocalPublicationFilesystem<'_> {
    fn observe_prior(&mut self) -> Result<(PriorSelector, PriorLoadedIdentity), DriverError> {
        let prior = observe_current_selector(self.route_root).map_err(DriverError::internal)?;
        let loaded = super::route_set_prior::observe_prior_loaded_identity(self.route_root, &prior)
            .map_err(DriverError::internal)?;
        Ok((prior, loaded))
    }

    fn prepare(
        &mut self,
        lease: &RouteSetPublicationLease,
        runtime: &FrozenRouteRuntimeContext,
        snapshot: &[FrozenSnapshotItem],
    ) -> Result<(), DriverError> {
        if self.prepared.is_some() || self.generation.is_some() {
            return Err(failure(PublicationPhase::Preparation));
        }
        let items = snapshot
            .iter()
            .cloned()
            .map(FrozenSnapshotItem::into_staging_item)
            .collect::<Vec<_>>();
        self.prepared = Some(prepare_frozen_route_set(
            lease.publication_kind,
            lease.target_workshop_id,
            runtime,
            &items,
        )?);
        Ok(())
    }

    fn begin(&mut self, lease: &RouteSetPublicationLease) -> Result<(), DriverError> {
        if self.prepared.is_none() || self.generation.is_some() {
            return Err(failure(PublicationPhase::Preparation));
        }
        let intent = RouteSetGenerationIntent::new(
            lease.publication_id,
            lease.publication_kind,
            lease.global_fence_token,
            lease.target_workshop_id,
            lease.target_route_fence_token,
        )
        .map_err(DriverError::internal)?;
        self.generation = Some(
            RouteSetGenerationDirectory::create_or_open(self.route_root, intent)
                .map_err(DriverError::internal)?,
        );
        Ok(())
    }

    async fn stage_and_seal(
        &mut self,
        recorder: &mut (dyn DurableRowRecorder + Send),
    ) -> Result<SealedRouteSetGeneration, DriverError> {
        let mut prepared = self
            .prepared
            .take()
            .ok_or_else(|| failure(PublicationPhase::Staging))?;
        let sealed = {
            let mut sealer = self
                .generation_mut()?
                .begin_seal()
                .map_err(DriverError::internal)?;
            while let Some(evidence) = prepared.stage_next(&mut sealer)? {
                recorder.record(&evidence).await?;
            }
            if !prepared.is_complete() {
                return Err(failure(PublicationPhase::Staging));
            }
            sealer.finish().map_err(DriverError::internal)?.clone()
        };
        self.prepared = Some(prepared);
        self.sealed = Some(sealed.clone());
        Ok(sealed)
    }

    fn publish(&mut self, prior: &PriorSelector) -> Result<(), DriverError> {
        let captured = self
            .generation_mut()?
            .publish(prior)
            .map_err(DriverError::internal)?;
        if &captured != prior {
            return Err(failure(PublicationPhase::Publishing));
        }
        Ok(())
    }

    fn observe_candidate(
        &mut self,
    ) -> Result<(PriorSelector, RouteSetGenerationIdentity), DriverError> {
        let sealed = self
            .generation_mut()?
            .observe_selected()
            .map_err(DriverError::internal)?
            .clone();
        Ok((sealed.selector, sealed.identity))
    }
}

/// Fully wired but deliberately uncalled entry point. Activation belongs to a
/// later migration after finalization, recovery, and writer cutover exist.
async fn execute_route_set_dormant(
    state: Arc<DriverState>,
    admission: RouteSetPublicationAdmissionRequest,
) -> Result<RouteSetPublicationResponse, DriverError> {
    let supervisor = state.task_supervisor.clone();
    let subject_id = admission.workshop_id;
    let receipt = supervisor
        .try_spawn_admitted(
            DriverTaskMetadata::new(DriverTaskKind::RouteSetPublication, Some(subject_id)),
            move |capability| async move {
                let capability = Arc::new(capability);
                Ok::<_, DriverTaskFailure>(
                    execute_route_set_owned(&capability, &state, &admission).await,
                )
            },
        )
        .map_err(supervisor_admit_error)?;
    receipt.wait().await.map_err(supervisor_wait_error)?
}

async fn execute_route_set_owned(
    supervisor: &Arc<OwnedTaskCapability>,
    state: &DriverState,
    admission: &RouteSetPublicationAdmissionRequest,
) -> Result<RouteSetPublicationResponse, DriverError> {
    let mut guard = SharedHostGuardPort {
        route_root: &state.config.route_root,
    };
    let mut database = SqlPublicationDatabase {
        ledger: &state.ledger,
    };
    let mut heartbeat = SqlPublicationHeartbeat {
        ledger: &state.ledger,
        next_renewal: None,
    };
    let cleanup = Arc::new(CleanupTracker::default());
    let cancellation_scheduler = PgCancellationQuarantine {
        ledger: state.ledger.clone(),
        result_request: RouteSetPublicationResultRequest::from_admission(admission),
        cleanup: cleanup.clone(),
        supervisor: supervisor.clone(),
    };
    let mut filesystem = LocalPublicationFilesystem {
        route_root: &state.config.route_root,
        prepared: None,
        generation: None,
        sealed: None,
    };
    let mut runtime = GatewayPublicationRuntime { state };
    let result = execute_route_set_with_ports(
        &mut guard,
        cancellation_scheduler,
        &mut database,
        &mut heartbeat,
        &mut filesystem,
        &mut runtime,
        admission,
    )
    .await;
    cleanup.wait().await;
    result
}

/// Fully wired recovery-kind entry point. Like the projection entry point it
/// is deliberately private and uncalled until the protocol activation
/// migration proves every writer cohort ready. Once registered, the
/// supervisor owns the operation even if its request waiter is cancelled.
async fn execute_recovery_route_set_dormant(
    state: Arc<DriverState>,
    request: RecoveryRouteSetAdmissionRequest,
) -> Result<RecoveryRouteSetExecutionResult, DriverError> {
    let supervisor = state.task_supervisor.clone();
    let subject_id = request.workshop_id();
    let receipt = supervisor
        .try_spawn_admitted(
            DriverTaskMetadata::new(DriverTaskKind::RouteSetRecovery, Some(subject_id)),
            move |capability| async move {
                let capability = Arc::new(capability);
                Ok::<_, DriverTaskFailure>(
                    execute_recovery_route_set_owned(&capability, &state, &request).await,
                )
            },
        )
        .map_err(supervisor_admit_error)?;
    receipt.wait().await.map_err(supervisor_wait_error)?
}

enum RecoveryRouteSetExecutionResult {
    Completed(Box<RecoveryRouteSetPublicationResponse>),
    NotApplied(RecoveryRouteSetNotAppliedResult),
}

async fn read_durable_recovery_result(
    state: &DriverState,
    request: &RecoveryRouteSetAdmissionRequest,
) -> Result<Option<RecoveryRouteSetExecutionResult>, DriverError> {
    match route_set_recovery_publication_db::read_route_set_recovery_admission(
        &state.ledger,
        request,
    )
    .await?
    {
        ReadRecoveryRouteSetAdmission::Absent => Ok(None),
        ReadRecoveryRouteSetAdmission::Replay(response) => Ok(Some(
            RecoveryRouteSetExecutionResult::Completed(Box::new(response)),
        )),
        ReadRecoveryRouteSetAdmission::NotApplied(result) => {
            Ok(Some(RecoveryRouteSetExecutionResult::NotApplied(result)))
        }
        ReadRecoveryRouteSetAdmission::Refused(_) => Err(failure(PublicationPhase::Admission)),
    }
}

struct RecoverySqlPublicationDatabase<'a> {
    ledger: &'a PgPool,
}

#[async_trait]
impl PublicationDatabase for RecoverySqlPublicationDatabase<'_> {
    async fn read_result(
        &mut self,
        _request: &RouteSetPublicationResultRequest,
    ) -> Result<ReadRouteSetPublicationResult, DriverError> {
        Err(failure(PublicationPhase::Admission))
    }

    async fn admit(
        &mut self,
        _request: &RouteSetPublicationAdmissionRequest,
    ) -> Result<RouteSetPublicationAdmission, DriverError> {
        Err(failure(PublicationPhase::Admission))
    }

    async fn renew(&mut self, lease: &RouteSetPublicationLease) -> Result<bool, DriverError> {
        route_set_publication_db::renew_route_set_publication(self.ledger, lease).await
    }

    async fn read_snapshot(
        &mut self,
        lease: &RouteSetPublicationLease,
        after: Option<Uuid>,
        limit: usize,
    ) -> Result<Vec<FrozenSnapshotItem>, DriverError> {
        route_set_publication_db::read_route_set_publication_snapshot_batch(
            self.ledger,
            lease,
            after,
            limit,
        )
        .await
    }

    async fn record_prior(
        &mut self,
        lease: &RouteSetPublicationLease,
        prior: &PriorSelector,
        loaded: Option<&RouteSetPriorLoadedIdentity>,
    ) -> Result<RecordRouteSetPriorOutcome, DriverError> {
        route_set_publication_db::record_route_set_publication_prior(
            self.ledger,
            lease,
            prior,
            loaded,
        )
        .await
    }

    async fn record_entry(
        &mut self,
        lease: &RouteSetPublicationLease,
        evidence: &RouteSetSealEvidence,
    ) -> Result<RecordRouteSetEntryOutcome, DriverError> {
        route_set_publication_db::record_route_set_publication_entry(self.ledger, lease, evidence)
            .await
    }

    async fn seal(
        &mut self,
        lease: &RouteSetPublicationLease,
        sealed: &SealedRouteSetGeneration,
    ) -> Result<SealRouteSetPublicationOutcome, DriverError> {
        route_set_publication_db::seal_route_set_publication(self.ledger, lease, sealed).await
    }

    async fn start(
        &mut self,
        lease: &RouteSetPublicationLease,
    ) -> Result<StartRouteSetPublicationOutcome, DriverError> {
        route_set_publication_db::start_route_set_publication(self.ledger, lease).await
    }

    async fn observe(
        &mut self,
        lease: &RouteSetPublicationLease,
        observed: &PriorSelector,
        identity: &RouteSetGenerationIdentity,
    ) -> Result<ObserveRouteSetPublicationOutcome, DriverError> {
        route_set_publication_db::observe_route_set_publication(
            self.ledger,
            lease,
            observed,
            identity,
        )
        .await
    }

    async fn finish(
        &mut self,
        _lease: &RouteSetPublicationLease,
        _sealed: &SealedRouteSetGeneration,
        _target_evidence: &RouteSetSealEvidence,
    ) -> Result<FinishRouteSetPublicationOutcome, DriverError> {
        Err(failure(PublicationPhase::Finalization))
    }

    async fn quarantine(&mut self, lease: &RouteSetPublicationLease) -> Result<bool, DriverError> {
        route_set_publication_db::quarantine_route_set_publication(self.ledger, lease).await
    }
}

#[derive(Clone)]
struct PgRecoveryCancellationQuarantine {
    ledger: PgPool,
    effect_run_id: Uuid,
    cleanup: Arc<CleanupTracker>,
    supervisor: Arc<OwnedTaskCapability>,
}

impl CancellationQuarantine<host_guard::SharedOdooHostGuard> for PgRecoveryCancellationQuarantine {
    fn schedule(
        &self,
        lease: RouteSetPublicationLease,
        host_guard: host_guard::SharedOdooHostGuard,
    ) {
        let ledger = self.ledger.clone();
        let effect_run_id = self.effect_run_id;
        let cleanup = self.cleanup.clone();
        let cleanup_registration = cleanup.clone();
        cleanup
            .pending
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let cleanup_task = self.supervisor.try_spawn_cleanup(move |_| async move {
            let _finished = CleanupFinished(cleanup);
            let _host_guard = host_guard;
            let recovery_lease = RecoveryRouteSetPublicationLease {
                effect_run_id,
                core: lease.clone(),
            };
            let mut failure_count = 0_u32;
            loop {
                let durable = matches!(
                    route_set_recovery_publication_db::read_route_set_recovery_publication_result(
                        &ledger,
                        &recovery_lease,
                    )
                    .await,
                    Ok(ReadRecoveryRouteSetPublicationResult::Completed(_)
                        | ReadRecoveryRouteSetPublicationResult::NotApplied(_))
                );
                if durable
                    || matches!(
                        route_set_publication_db::quarantine_route_set_publication(&ledger, &lease)
                            .await,
                        Ok(true)
                    )
                {
                    return Ok(());
                }
                failure_count = failure_count.saturating_add(1);
                let delay = cleanup_retry_delay(
                    Duration::from_millis(100),
                    failure_count,
                    lease.publication_id,
                );
                if report_cleanup_retry(failure_count) {
                    tracing::warn!(
                        publication.id = %lease.publication_id,
                        retry.count = failure_count,
                        retry.delay_ms = delay.as_millis(),
                        error_class = "recovery_cleanup_pending",
                        "route-set recovery cleanup awaits durable confirmation"
                    );
                }
                tokio::time::sleep(delay).await;
            }
        });
        if cleanup_task.is_err() {
            drop(CleanupFinished(cleanup_registration));
            tracing::error!(
                error_class = "recovery_cleanup_registration_failed",
                "route-set recovery cleanup registration failed"
            );
        }
    }
}

struct RecoveryObservedPendingFinalization<Q, H>
where
    Q: CancellationQuarantine<H>,
{
    lease: RecoveryRouteSetPublicationLease,
    sealed: SealedRouteSetGeneration,
    target_evidence: RouteSetSealEvidence,
    observed: PriorSelector,
    _host_guard: host_guard::SharedOdooHostGuard,
    _cancellation: ArmedCancellationQuarantine<Q, H>,
}

impl<Q, H> RecoveryObservedPendingFinalization<Q, H>
where
    Q: CancellationQuarantine<H>,
{
    #[tracing::instrument(
        name = "deployment_driver.route_set_recovery_publication.finalize_dormant",
        skip_all,
        fields(
            publication.id = %self.lease.core.publication_id,
            publication.kind = self.lease.core.publication_kind.as_str(),
            workshop_id = %self.lease.core.target_workshop_id,
            transition.outcome = tracing::field::Empty
        )
    )]
    async fn finalize<F, R, B>(
        mut self,
        ledger: &PgPool,
        filesystem: &mut F,
        runtime: &mut R,
        heartbeat: &mut B,
    ) -> Result<RecoveryRouteSetPublicationResponse, DriverError>
    where
        F: PublicationFilesystem,
        R: PublicationRuntime,
        B: PublicationHeartbeat + Send,
    {
        let heartbeat_lease = self.lease.core.clone();
        let result = with_publication_heartbeat(
            async {
                if self.observed != self.sealed.selector {
                    return Err(failure(PublicationPhase::Finalization));
                }
                let runtime_identity = runtime.observe_candidate(&self.sealed.identity).await?;
                if runtime_identity != self.sealed.identity {
                    return Err(failure(PublicationPhase::Finalization));
                }
                let (selected, filesystem_identity) = filesystem.observe_candidate()?;
                if selected != self.observed
                    || selected != self.sealed.selector
                    || filesystem_identity != self.sealed.identity
                {
                    return Err(failure(PublicationPhase::Finalization));
                }
                let outcome =
                    route_set_recovery_publication_db::finish_route_set_recovery_publication(
                        ledger,
                        &self.lease,
                    )
                    .await?;
                let response = match outcome {
                    FinishRecoveryRouteSetPublicationOutcome::Completed(response) => {
                        tracing::Span::current().record("transition.outcome", "completed");
                        *response
                    }
                    FinishRecoveryRouteSetPublicationOutcome::Replay(response) => {
                        tracing::Span::current().record("transition.outcome", "replay");
                        *response
                    }
                    _ => return Err(failure(PublicationPhase::Finalization)),
                };
                validate_recovery_finish_evidence(&response, &self.sealed, &self.target_evidence)?;
                Ok(response)
            },
            heartbeat.monitor(&heartbeat_lease),
        )
        .await;
        match result {
            Ok(response) => {
                self._cancellation.disarm();
                Ok(response)
            }
            Err(source) => {
                match route_set_recovery_publication_db::read_route_set_recovery_publication_result(
                    ledger,
                    &self.lease,
                )
                .await
                {
                    Ok(ReadRecoveryRouteSetPublicationResult::Completed(response)) => {
                        validate_recovery_finish_evidence(
                            &response,
                            &self.sealed,
                            &self.target_evidence,
                        )?;
                        self._cancellation.disarm();
                        Ok(*response)
                    }
                    _ => Err(report_failure(PublicationFailure::new(
                        PublicationPhase::Finalization,
                        PublicationRisk::StartAttempted,
                        source,
                    ))),
                }
            }
        }
    }
}

fn validate_recovery_finish_evidence(
    response: &RecoveryRouteSetPublicationResponse,
    sealed: &SealedRouteSetGeneration,
    target: &RouteSetSealEvidence,
) -> Result<(), DriverError> {
    let set = &response.route_set_evidence;
    if response.route_evidence.rendered_digest != target.rendered_digest
        || set.route_set_digest != sealed.identity.route_set_digest
        || set.snapshot_count != sealed.route_count
        || set.present_count != sealed.present_route_count
        || set.directory_device != sealed.selector.directory_device()
        || set.directory_inode != sealed.selector.directory_inode()
    {
        return Err(failure(PublicationPhase::Finalization));
    }
    Ok(())
}

async fn execute_recovery_route_set_owned(
    supervisor: &Arc<OwnedTaskCapability>,
    state: &DriverState,
    request: &RecoveryRouteSetAdmissionRequest,
) -> Result<RecoveryRouteSetExecutionResult, DriverError> {
    if let Some(result) = read_durable_recovery_result(state, request).await? {
        return Ok(result);
    }
    let mut guard = SharedHostGuardPort {
        route_root: &state.config.route_root,
    };
    let host_guard = guard.acquire().await?;
    // Close the race where another supervised owner terminalized the exact
    // request while this owner was waiting for the host-wide guard. Holding
    // the guard makes the following filesystem/runtime preflight exclusive.
    if let Some(result) = read_durable_recovery_result(state, request).await? {
        return Ok(result);
    }
    let retained_host_guard = host_guard.retain_for_quarantine()?;
    let mut filesystem = LocalPublicationFilesystem {
        route_root: &state.config.route_root,
        prepared: None,
        generation: None,
        sealed: None,
    };
    let mut runtime = GatewayPublicationRuntime { state };
    let preflight = observe_bound_prior(&mut filesystem, &mut runtime).await?;
    let admission = route_set_recovery_publication_db::admit_route_set_recovery_publication(
        &state.ledger,
        request,
    )
    .await?;
    let lease = match admission {
        RecoveryRouteSetAdmission::Acquired(lease) => lease,
        RecoveryRouteSetAdmission::Replay(response) => {
            return Ok(RecoveryRouteSetExecutionResult::Completed(Box::new(
                response,
            )));
        }
        RecoveryRouteSetAdmission::NotApplied(result) => {
            return Ok(RecoveryRouteSetExecutionResult::NotApplied(result));
        }
        RecoveryRouteSetAdmission::Refused(_) => {
            return Err(failure(PublicationPhase::Admission));
        }
    };
    let cleanup = Arc::new(CleanupTracker::default());
    let cancellation_scheduler = PgRecoveryCancellationQuarantine {
        ledger: state.ledger.clone(),
        effect_run_id: lease.effect_run_id,
        cleanup: cleanup.clone(),
        supervisor: supervisor.clone(),
    };
    let mut cancellation = ArmedCancellationQuarantine::new(
        cancellation_scheduler,
        lease.core.clone(),
        retained_host_guard,
    );
    let mut database = RecoverySqlPublicationDatabase {
        ledger: &state.ledger,
    };
    let mut heartbeat = SqlPublicationHeartbeat {
        ledger: &state.ledger,
        next_renewal: None,
    };
    let fake_admission = RouteSetPublicationAdmissionRequest {
        control_operation: lease.core.control_operation.clone(),
        workshop_id: lease.core.target_workshop_id,
        publication_kind: lease.core.publication_kind,
        idempotency_key: format!("recovery-effect/{}", lease.effect_run_id),
        request_digest: "0".repeat(64),
        projection_generation: lease.core.target_projection_generation,
        projection_digest: lease.core.target_projection_digest.clone(),
        expected_disposition: lease.core.expected_disposition,
        instance_owner: lease.core.instance_owner,
        execution_token: lease.core.execution_token,
        global_lease_token: lease.core.global_lease_token,
        route_lease_token: lease.core.route_lease_token,
        ttl_seconds: lease.core.ttl_seconds,
    };
    let plan = RouteSetPublicationPlan::new(&fake_admission);
    let mut risk = PublicationRisk::Reversible;
    let phase = StdMutex::new(PublicationPhase::PriorObservation);
    let result = with_publication_heartbeat(
        coordinate_acquired(
            &mut database,
            &mut filesystem,
            &mut runtime,
            AcquiredPublicationContext {
                plan: &plan,
                lease: &lease.core,
                risk: &mut risk,
                phase: &phase,
                cancellation: &mut cancellation,
                preflight: &preflight,
            },
        ),
        heartbeat.monitor(&lease.core),
    )
    .await;
    let observed = match result {
        Ok(observed) => observed,
        Err(error) => {
            if risk == PublicationRisk::StartAttempted
                && matches!(database.quarantine(&lease.core).await, Ok(true))
            {
                cancellation.disarm();
            }
            cleanup.wait().await;
            return Err(report_failure(PublicationFailure::new(
                *phase.lock().expect("publication phase mutex is poisoned"),
                risk,
                error,
            )));
        }
    };
    let pending = RecoveryObservedPendingFinalization {
        lease,
        sealed: observed.sealed,
        target_evidence: observed.target_evidence,
        observed: observed.observed,
        _host_guard: host_guard,
        _cancellation: cancellation,
    };
    let result = pending
        .finalize(&state.ledger, &mut filesystem, &mut runtime, &mut heartbeat)
        .await;
    cleanup.wait().await;
    result.map(|response| RecoveryRouteSetExecutionResult::Completed(Box::new(response)))
}

/// Dormant fleet-scoped startup route-set entrypoint. The supervisor owns the
/// complete effect after registration; cancelling the request waiter cannot
/// cancel publication or release its host guard.
enum StartupRouteSetExecutionResult {
    Completed(StartupRouteSetResponse),
    NotApplied(StartupRouteSetNotApplied),
}

async fn execute_startup_route_set_dormant(
    state: Arc<DriverState>,
    request: StartupRouteSetAdmissionRequest,
) -> Result<StartupRouteSetExecutionResult, DriverError> {
    let supervisor = state.task_supervisor.clone();
    let receipt = supervisor
        .try_spawn_admitted(
            DriverTaskMetadata::new(DriverTaskKind::RouteSetStartup, None),
            move |capability| async move {
                let capability = Arc::new(capability);
                Ok::<_, DriverTaskFailure>(
                    execute_startup_route_set_owned(&capability, &state, &request).await,
                )
            },
        )
        .map_err(supervisor_admit_error)?;
    receipt.wait().await.map_err(supervisor_wait_error)?
}

async fn read_startup_durable(
    state: &DriverState,
    request: &StartupRouteSetAdmissionRequest,
) -> Result<Option<StartupRouteSetExecutionResult>, DriverError> {
    match route_set_startup_publication_db::read_startup_admission(&state.ledger, request).await? {
        ReadStartupRouteSetAdmission::Absent => Ok(None),
        ReadStartupRouteSetAdmission::Replay(response) => {
            Ok(Some(StartupRouteSetExecutionResult::Completed(response)))
        }
        ReadStartupRouteSetAdmission::NotApplied(response) => {
            Ok(Some(StartupRouteSetExecutionResult::NotApplied(response)))
        }
        ReadStartupRouteSetAdmission::Refused(_) => Err(failure(PublicationPhase::Admission)),
    }
}

async fn execute_startup_route_set_owned(
    supervisor: &Arc<OwnedTaskCapability>,
    state: &DriverState,
    request: &StartupRouteSetAdmissionRequest,
) -> Result<StartupRouteSetExecutionResult, DriverError> {
    if let Some(response) = read_startup_durable(state, request).await? {
        return Ok(response);
    }
    let host_guard = host_guard::SharedOdooHostGuard::acquire(&state.config.route_root)
        .await
        .map_err(DriverError::internal)?;
    let retained_host_guard = host_guard.retain_for_quarantine()?;
    if let Some(response) = read_startup_durable(state, request).await? {
        return Ok(response);
    }
    let prior =
        observe_current_selector(&state.config.route_root).map_err(DriverError::internal)?;
    let prior_loaded =
        super::route_set_prior::observe_startup_prior_loaded_identity(state, &prior).await?;
    let lease =
        match route_set_startup_publication_db::admit_startup_publication(&state.ledger, request)
            .await?
        {
            StartupRouteSetAdmission::Acquired(lease) => *lease,
            StartupRouteSetAdmission::Replay(response) => {
                return Ok(StartupRouteSetExecutionResult::Completed(response));
            }
            StartupRouteSetAdmission::NotApplied(response) => {
                return Ok(StartupRouteSetExecutionResult::NotApplied(response));
            }
            StartupRouteSetAdmission::Refused(_) => {
                return Err(failure(PublicationPhase::Admission));
            }
        };
    let started = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut cancellation = StartupCancellationQuarantine {
        supervisor: supervisor.clone(),
        ledger: state.ledger.clone(),
        lease: lease.clone(),
        host_guard: Some(retained_host_guard),
        started: started.clone(),
        armed: true,
    };
    let effect = coordinate_startup_acquired(state, &lease, &prior, &prior_loaded, started.clone());
    let heartbeat = monitor_startup_heartbeat(state, &lease);
    let result = with_publication_heartbeat(effect, heartbeat).await;
    let error = match result {
        Ok(response) => {
            cancellation.disarm();
            return Ok(StartupRouteSetExecutionResult::Completed(response));
        }
        Err(error) => error,
    };
    if started.load(std::sync::atomic::Ordering::SeqCst) {
        match route_set_startup_publication_db::read_startup_result(&state.ledger, &lease).await {
            Ok(
                route_set_startup_publication_db::ReadStartupRouteSetResult::Replay(response)
                | route_set_startup_publication_db::ReadStartupRouteSetResult::AppliedRecovered(
                    response,
                ),
            ) => {
                cancellation.disarm();
                return Ok(StartupRouteSetExecutionResult::Completed(response));
            }
            Ok(route_set_startup_publication_db::ReadStartupRouteSetResult::NotApplied(
                response,
            )) => {
                cancellation.disarm();
                return Ok(StartupRouteSetExecutionResult::NotApplied(response));
            }
            _ => {}
        }
    }
    drop(host_guard);
    Err(error)
}

struct StartupCancellationQuarantine {
    supervisor: Arc<OwnedTaskCapability>,
    ledger: PgPool,
    lease: StartupRouteSetLease,
    host_guard: Option<host_guard::SharedOdooHostGuard>,
    started: Arc<std::sync::atomic::AtomicBool>,
    armed: bool,
}

impl StartupCancellationQuarantine {
    fn disarm(&mut self) {
        self.armed = false;
        self.host_guard.take();
    }
}

impl Drop for StartupCancellationQuarantine {
    fn drop(&mut self) {
        if !self.armed || !self.started.load(std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        let ledger = self.ledger.clone();
        let lease = self.lease.clone();
        let Some(host_guard) = self.host_guard.take() else {
            return;
        };
        let cleanup_task = self.supervisor.try_spawn_cleanup(move |_| async move {
            let _host_guard = host_guard;
            let mut failure_count = 0_u32;
            loop {
                if matches!(
                    route_set_startup_publication_db::quarantine_startup_publication(&ledger, &lease).await,
                    Ok(true)
                ) {
                    return Ok(());
                }
                if matches!(
                    route_set_startup_publication_db::read_startup_result(&ledger, &lease).await,
                    Ok(route_set_startup_publication_db::ReadStartupRouteSetResult::Replay(_)
                        | route_set_startup_publication_db::ReadStartupRouteSetResult::AppliedRecovered(_)
                        | route_set_startup_publication_db::ReadStartupRouteSetResult::NotApplied(_)
                        | route_set_startup_publication_db::ReadStartupRouteSetResult::FleetQuarantined)
                ) {
                    return Ok(());
                }
                failure_count = failure_count.saturating_add(1);
                let delay = cleanup_retry_delay(
                    Duration::from_secs(1),
                    failure_count,
                    lease.publication_id,
                );
                if report_cleanup_retry(failure_count) {
                    tracing::warn!(
                        publication.id = %lease.publication_id,
                        retry.count = failure_count,
                        retry.delay_ms = delay.as_millis(),
                        error_class = "startup_cleanup_pending",
                        "route-set startup cleanup awaits durable confirmation"
                    );
                }
                tokio::time::sleep(delay).await;
            }
        });
        if cleanup_task.is_err() {
            tracing::error!(
                error_class = "startup_cleanup_registration_failed",
                "route-set startup cleanup registration failed"
            );
        }
    }
}

async fn monitor_startup_heartbeat(
    state: &DriverState,
    lease: &StartupRouteSetLease,
) -> DriverError {
    let interval =
        Duration::from_secs((u64::try_from(lease.ttl_seconds).unwrap_or(60) / 3).clamp(1, 30));
    loop {
        tokio::time::sleep(interval).await;
        match tokio::time::timeout(
            interval.min(Duration::from_secs(10)),
            route_set_startup_publication_db::renew_startup_publication(&state.ledger, lease),
        )
        .await
        {
            Ok(Ok(true)) => {}
            _ => return failure(PublicationPhase::Admission),
        }
    }
}

struct StartupTraceOutcomeGuard {
    applied: bool,
}

impl StartupTraceOutcomeGuard {
    const fn new() -> Self {
        Self { applied: false }
    }

    fn record_applied(&mut self) {
        self.applied = true;
        tracing::Span::current().record("result.outcome", "applied");
    }
}

impl Drop for StartupTraceOutcomeGuard {
    fn drop(&mut self) {
        if !self.applied {
            tracing::Span::current().record("result.outcome", "failed");
        }
    }
}

#[tracing::instrument(
    name = "deployment_driver.route_set_startup.coordinate_dormant",
    skip_all,
    fields(
        publication.id = %lease.publication_id,
        effect.id = %lease.effect_run_id,
        publication.kind = "startup",
        publication.phase = "prior_observation",
        publication.risk = "reversible",
        route.count = lease.snapshot_count,
        result.outcome = "in_progress"
    )
)]
async fn coordinate_startup_acquired(
    state: &DriverState,
    lease: &StartupRouteSetLease,
    prior: &PriorSelector,
    prior_loaded: &PriorLoadedIdentity,
    started: Arc<std::sync::atomic::AtomicBool>,
) -> Result<StartupRouteSetResponse, DriverError> {
    let mut trace_outcome = StartupTraceOutcomeGuard::new();
    let prior_json = prior_loaded.as_database_json()?;
    match route_set_startup_publication_db::record_startup_prior(
        &state.ledger,
        lease,
        prior.target(),
        prior.directory_device(),
        prior.directory_inode(),
        prior_json.as_ref(),
    )
    .await?
    {
        StartupTransitionOutcome::Recorded | StartupTransitionOutcome::Replay => {}
        _ => return Err(failure(PublicationPhase::PriorObservation)),
    }
    if lease.fleet_release_unresolved {
        tracing::Span::current().record("result.outcome", "fleet_release_unresolved");
        return Err(failure(PublicationPhase::Preparation));
    }
    tracing::Span::current().record("publication.phase", "preparation");
    let legacy_lease = lease.legacy_runtime_lease();
    let inventory_bound = lease
        .snapshot_count
        .checked_add(1_024)
        .ok_or_else(|| failure(PublicationPhase::Preparation))?;
    startup::observe_runtime_inventory_bounded(state, inventory_bound).await?;
    let active_container = match (&lease.runtime, &legacy_lease.active_runtime) {
        (StartupFrozenRuntime::Absent, None) => None,
        (StartupFrozenRuntime::Active { .. }, Some(identity)) => {
            Some(startup::reconcile_frozen_active_odoo(state, identity).await?)
        }
        _ => return Err(failure(PublicationPhase::Preparation)),
    };
    let intent = RouteSetGenerationIntent::new_startup(
        lease.publication_id,
        lease.effect_run_id,
        lease.global_fence_token,
    )
    .map_err(DriverError::internal)?;
    let mut generation =
        RouteSetGenerationDirectory::create_or_open(&state.config.route_root, intent)
            .map_err(DriverError::internal)?;
    let mut sealer = generation.begin_seal().map_err(DriverError::internal)?;
    let mut after = None;
    let mut recorded = 0_usize;
    tracing::Span::current().record("publication.phase", "snapshot_read");
    loop {
        let rows = route_set_startup_publication_db::read_startup_snapshot_batch(
            &state.ledger,
            lease,
            after,
            DEFAULT_SNAPSHOT_BATCH_SIZE,
        )
        .await?;
        if rows.is_empty() {
            break;
        }
        for row in &rows {
            tracing::Span::current().record("publication.phase", "staging");
            if row.unresolved_operation {
                return Err(failure(PublicationPhase::Preparation));
            }
            let route = row.legacy_route()?;
            let observation = match route.disposition {
                startup_publication::RouteDisposition::Absent => {
                    startup_publication::StartupRuntimeObservation::absent(
                        &legacy_lease,
                        &route,
                        time::OffsetDateTime::now_utc().unix_timestamp().to_string(),
                    )?
                }
                startup_publication::RouteDisposition::Present => {
                    let container = active_container
                        .as_deref()
                        .ok_or_else(|| failure(PublicationPhase::Preparation))?;
                    let tenant = startup::TenantRoute {
                        workshop: route.workshop_id,
                        database_ref: route
                            .database_ref
                            .clone()
                            .ok_or_else(|| failure(PublicationPhase::Preparation))?,
                        paperless_base_url: route.paperless_service_base_url.clone(),
                        unresolved_operation: false,
                    };
                    startup::verify_odoo_tenant(state, container, &tenant).await?;
                    startup::reconcile_frozen_paperless(state, &route).await?;
                    startup_publication::StartupRuntimeObservation::ready(
                        &legacy_lease,
                        &route,
                        time::OffsetDateTime::now_utc().unix_timestamp().to_string(),
                    )?
                }
            };
            let contents = startup::render_staged_startup_route(
                state,
                &route,
                active_container
                    .as_deref()
                    .unwrap_or("startup-no-active-runtime"),
            )?;
            let baseline = row.baseline_applied_rendered_digest.as_deref();
            let evidence = match contents.as_deref() {
                Some(bytes) => sealer.stage_startup_present(
                    row.workshop_id,
                    row.generation,
                    &row.projection_digest,
                    baseline,
                    bytes.as_bytes(),
                ),
                None => sealer.stage_startup_absent(
                    row.workshop_id,
                    row.generation,
                    &row.projection_digest,
                    baseline,
                ),
            }
            .map_err(DriverError::internal)?;
            match route_set_startup_publication_db::record_startup_entry(
                &state.ledger,
                lease,
                &StartupRecordEntry {
                    workshop_id: row.workshop_id,
                    generation: row.generation,
                    projection_digest: &row.projection_digest,
                    disposition: &row.disposition,
                    baseline_applied_rendered_digest: baseline,
                    route_fence_token: row.route_fence_token,
                    runtime_outcome: observation.outcome.as_str(),
                    runtime_evidence: &observation.evidence,
                    rendered_digest: &evidence.rendered_digest,
                },
            )
            .await?
            {
                StartupTransitionOutcome::Recorded | StartupTransitionOutcome::Replay => {}
                _ => return Err(failure(PublicationPhase::Staging)),
            }
            recorded += 1;
            after = Some(row.workshop_id);
        }
        if rows.len() < DEFAULT_SNAPSHOT_BATCH_SIZE {
            break;
        }
    }
    if recorded != lease.snapshot_count {
        return Err(failure(PublicationPhase::SnapshotRead));
    }
    let sealed = sealer.finish().map_err(DriverError::internal)?.clone();
    tracing::Span::current().record("publication.phase", "sealing");
    match route_set_startup_publication_db::seal_startup_publication(
        &state.ledger,
        lease,
        sealed.route_count,
        sealed.present_route_count,
        &sealed.identity.route_set_digest,
        sealed.selector.directory_device(),
        sealed.selector.directory_inode(),
    )
    .await?
    {
        StartupTransitionOutcome::Sealed | StartupTransitionOutcome::Replay => {}
        _ => return Err(failure(PublicationPhase::Sealing)),
    }
    started.store(true, std::sync::atomic::Ordering::SeqCst);
    tracing::Span::current().record("publication.phase", "start_attempted");
    tracing::Span::current().record("publication.risk", "start_attempted");
    match route_set_startup_publication_db::start_startup_publication(&state.ledger, lease).await? {
        StartupTransitionOutcome::Started | StartupTransitionOutcome::Replay => {}
        _ => return Err(failure(PublicationPhase::StartAttempted)),
    }
    tracing::Span::current().record("publication.phase", "publishing");
    generation.publish(prior).map_err(DriverError::internal)?;
    tracing::Span::current().record("publication.phase", "runtime_reload");
    reload_gateway_runtime(state, &sealed.identity.route_set_digest).await?;
    tracing::Span::current().record("publication.phase", "observation");
    let observed = observe_running_route_set_generation(state, &sealed.identity).await?;
    let identity = serde_json::to_value(&observed).map_err(DriverError::internal)?;
    match route_set_startup_publication_db::observe_startup_publication(
        &state.ledger,
        lease,
        sealed.selector.target(),
        &identity,
    )
    .await?
    {
        StartupTransitionOutcome::Observed | StartupTransitionOutcome::Replay => {}
        _ => return Err(failure(PublicationPhase::Observation)),
    }
    tracing::Span::current().record("publication.phase", "finalization");
    match route_set_startup_publication_db::finish_startup_publication(&state.ledger, lease).await?
    {
        FinishStartupRouteSetOutcome::Applied(response)
        | FinishStartupRouteSetOutcome::Replay(response) => {
            trace_outcome.record_applied();
            Ok(response)
        }
        _ => {
            tracing::Span::current().record("result.outcome", "finalization_refused");
            Err(failure(PublicationPhase::Finalization))
        }
    }
}

#[tracing::instrument(
    name = "deployment_driver.route_set_publication.execute_dormant",
    skip_all,
    fields(
        workshop_id = %admission.workshop_id,
        publication.kind = admission.publication_kind.as_str(),
        result.outcome = tracing::field::Empty
    )
)]
async fn execute_route_set_with_ports<G, Q, D, B, F, R>(
    guard: &mut G,
    cancellation_scheduler: Q,
    database: &mut D,
    heartbeat: &mut B,
    filesystem: &mut F,
    runtime: &mut R,
    admission: &RouteSetPublicationAdmissionRequest,
) -> Result<RouteSetPublicationResponse, DriverError>
where
    G: PublicationGuard,
    Q: CancellationQuarantine<<<G as PublicationGuard>::Guard as RetainHostGuard>::Retained>,
    D: PublicationDatabase + Send,
    B: PublicationHeartbeat + Send,
    F: PublicationFilesystem,
    R: PublicationRuntime,
{
    let result_request = RouteSetPublicationResultRequest::from_admission(admission);
    match database.read_result(&result_request).await? {
        ReadRouteSetPublicationResult::Completed { response, .. } => {
            tracing::Span::current().record("result.outcome", "completed");
            Ok(*response)
        }
        ReadRouteSetPublicationResult::Conflict => {
            tracing::Span::current().record("result.outcome", "conflict");
            Err(failure(PublicationPhase::Admission))
        }
        ReadRouteSetPublicationResult::Pending { .. } => {
            tracing::Span::current().record("result.outcome", "pending");
            Err(failure(PublicationPhase::Admission))
        }
        ReadRouteSetPublicationResult::NotApplied(_) => {
            tracing::Span::current().record("result.outcome", "not_applied");
            Err(failure(PublicationPhase::Admission))
        }
        ReadRouteSetPublicationResult::Absent => {
            tracing::Span::current().record("result.outcome", "absent");
            let pending = coordinate_route_set_publication(
                guard,
                cancellation_scheduler,
                database,
                heartbeat,
                filesystem,
                runtime,
                RouteSetPublicationPlan::new(admission),
            )
            .await?;
            pending
                .finalize(database, filesystem, runtime, heartbeat)
                .await
        }
    }
}

#[tracing::instrument(
    name = "deployment_driver.route_set_publication.coordinate_dormant",
    skip_all,
    fields(
        workshop_id = %plan.admission.workshop_id,
        publication.kind = plan.admission.publication_kind.as_str(),
        publication.id = tracing::field::Empty,
        publication.phase = "admission",
        publication.risk = "reversible",
        publication.outcome = tracing::field::Empty,
        snapshot.count = tracing::field::Empty
    )
)]
async fn coordinate_route_set_publication<G, Q, D, B, F, R>(
    guard: &mut G,
    cancellation_scheduler: Q,
    database: &mut D,
    heartbeat: &mut B,
    filesystem: &mut F,
    runtime: &mut R,
    plan: RouteSetPublicationPlan<'_>,
) -> Result<CoordinateOutcome<G, Q>, DriverError>
where
    G: PublicationGuard,
    Q: CancellationQuarantine<<<G as PublicationGuard>::Guard as RetainHostGuard>::Retained>,
    D: PublicationDatabase + Send,
    B: PublicationHeartbeat + Send,
    F: PublicationFilesystem,
    R: PublicationRuntime,
{
    if plan.snapshot_batch_size == 0 {
        return Err(report_failure(PublicationFailure::new(
            PublicationPhase::Admission,
            PublicationRisk::Reversible,
            failure(PublicationPhase::Admission),
        )));
    }
    // This RAII value deliberately remains in scope through the final durable
    // observation (or quarantine attempt) and is acquired before admission.
    let host_guard = guard.acquire().await.map_err(|source| {
        report_failure(PublicationFailure::new(
            PublicationPhase::Admission,
            PublicationRisk::Reversible,
            source,
        ))
    })?;
    let retained_host_guard = host_guard.retain_for_quarantine().map_err(|source| {
        report_failure(PublicationFailure::new(
            PublicationPhase::Admission,
            PublicationRisk::Reversible,
            source,
        ))
    })?;
    let preflight = observe_bound_prior(filesystem, runtime)
        .await
        .map_err(|source| {
            report_failure(PublicationFailure::new(
                PublicationPhase::PriorObservation,
                PublicationRisk::Reversible,
                source,
            ))
        })?;
    let admission = database.admit(plan.admission).await.map_err(|source| {
        report_failure(PublicationFailure::new(
            PublicationPhase::Admission,
            PublicationRisk::Reversible,
            source,
        ))
    })?;
    let lease = match admission {
        RouteSetPublicationAdmission::Acquired(lease) => lease,
        RouteSetPublicationAdmission::Replay(_) | RouteSetPublicationAdmission::Refused(_) => {
            return Err(report_failure(PublicationFailure::new(
                PublicationPhase::Admission,
                PublicationRisk::Reversible,
                failure(PublicationPhase::Admission),
            )));
        }
    };
    let mut cancellation = ArmedCancellationQuarantine::new(
        cancellation_scheduler,
        lease.clone(),
        retained_host_guard,
    );
    let span = tracing::Span::current();
    span.record(
        "publication.id",
        tracing::field::display(lease.publication_id),
    );
    span.record("snapshot.count", lease.snapshot_count);

    let mut risk = PublicationRisk::Reversible;
    let phase = StdMutex::new(PublicationPhase::PriorObservation);
    let result = with_publication_heartbeat(
        coordinate_acquired(
            database,
            filesystem,
            runtime,
            AcquiredPublicationContext {
                plan: &plan,
                lease: &lease,
                risk: &mut risk,
                phase: &phase,
                cancellation: &mut cancellation,
                preflight: &preflight,
            },
        ),
        heartbeat.monitor(&lease),
    )
    .await;
    match result {
        Ok(result) => {
            span.record("publication.outcome", "observed_pending_finalization");
            Ok(ObservedPendingFinalization {
                lease,
                prior: result.prior,
                sealed: result.sealed,
                target_evidence: result.target_evidence,
                observed: result.observed,
                result_request: RouteSetPublicationResultRequest::from_admission(plan.admission),
                _host_guard: host_guard,
                _cancellation: cancellation,
            })
        }
        Err(error) => {
            if risk == PublicationRisk::StartAttempted {
                span.record("publication.risk", "start_attempted");
                let quarantine_confirmed = match database.quarantine(&lease).await {
                    Ok(true) => {
                        tracing::warn!(
                        publication.id = %lease.publication_id,
                        "route-set publication outcome was quarantined"
                        );
                        true
                    }
                    Ok(false) | Err(_) => {
                        tracing::error!(
                        publication.id = %lease.publication_id,
                        "route-set publication quarantine was not confirmed"
                        );
                        false
                    }
                };
                if quarantine_confirmed {
                    cancellation.disarm();
                }
            }
            span.record("publication.outcome", "failed");
            span.record(
                "publication.phase",
                phase
                    .lock()
                    .expect("publication phase mutex is poisoned")
                    .as_str(),
            );
            Err(report_failure(PublicationFailure::new(
                *phase.lock().expect("publication phase mutex is poisoned"),
                risk,
                error,
            )))
        }
    }
}

async fn observe_bound_prior<F, R>(
    filesystem: &mut F,
    runtime: &mut R,
) -> Result<(PriorSelector, PriorLoadedIdentity), DriverError>
where
    F: PublicationFilesystem,
    R: PublicationRuntime,
{
    let (prior, loaded) = filesystem.observe_prior()?;
    if loaded == PriorLoadedIdentity::BootLive {
        return Err(failure(PublicationPhase::PriorObservation));
    }
    runtime.observe_prior(&loaded).await?;
    let (confirmed_prior, confirmed_loaded) = filesystem.observe_prior()?;
    if confirmed_prior != prior || confirmed_loaded != loaded {
        return Err(failure(PublicationPhase::PriorObservation));
    }
    Ok((prior, loaded))
}

async fn coordinate_acquired<D, F, R, Q, H>(
    database: &mut D,
    filesystem: &mut F,
    runtime: &mut R,
    context: AcquiredPublicationContext<'_, Q, H>,
) -> Result<ObservedPublicationEvidence, DriverError>
where
    D: PublicationDatabase + Send,
    F: PublicationFilesystem,
    R: PublicationRuntime,
    Q: CancellationQuarantine<H>,
{
    let AcquiredPublicationContext {
        plan,
        lease,
        risk,
        phase,
        cancellation,
        preflight,
    } = context;
    require_renewal(database, lease, PublicationPhase::PriorObservation).await?;
    set_phase(phase, PublicationPhase::PriorObservation);
    let (confirmed_prior, confirmed_loaded) = observe_bound_prior(filesystem, runtime).await?;
    if confirmed_prior != preflight.0 || confirmed_loaded != preflight.1 {
        return Err(failure(PublicationPhase::PriorObservation));
    }
    let prior = preflight.0.clone();
    let database_loaded = database_prior_identity(&preflight.1);
    accept_prior(
        database
            .record_prior(lease, &prior, database_loaded.as_ref())
            .await?,
    )?;

    set_phase(phase, PublicationPhase::SnapshotRead);
    let snapshot = read_complete_snapshot(database, lease, plan.snapshot_batch_size).await?;

    set_phase(phase, PublicationPhase::Preparation);
    let frozen_runtime = runtime.freeze_context(&snapshot).await?;
    filesystem.prepare(lease, &frozen_runtime, &snapshot)?;
    require_renewal(database, lease, PublicationPhase::Preparation).await?;
    filesystem.begin(lease)?;

    set_phase(phase, PublicationPhase::Staging);
    require_renewal(database, lease, PublicationPhase::Staging).await?;
    let mut recorder = DatabaseRowRecorder {
        database,
        lease,
        target_evidence: None,
    };
    let sealed = filesystem.stage_and_seal(&mut recorder).await?;
    let target_evidence = recorder
        .target_evidence
        .take()
        .ok_or_else(|| failure(PublicationPhase::Staging))?;
    drop(recorder);

    set_phase(phase, PublicationPhase::Sealing);
    accept_seal(database.seal(lease, &sealed).await?)?;
    require_renewal(database, lease, PublicationPhase::Sealing).await?;

    // From immediately before this awaited call onward, the durable outcome
    // can be ambiguous. No error path beyond this assignment may restore.
    *risk = PublicationRisk::StartAttempted;
    cancellation.arm();
    set_phase(phase, PublicationPhase::StartAttempted);
    accept_start(database.start(lease).await?)?;

    set_phase(phase, PublicationPhase::Publishing);
    filesystem.publish(&prior)?;

    set_phase(phase, PublicationPhase::RuntimeReload);
    runtime.reload(&sealed.identity.route_set_digest).await?;

    set_phase(phase, PublicationPhase::Observation);
    let runtime_identity = runtime.observe_candidate(&sealed.identity).await?;
    if runtime_identity != sealed.identity {
        return Err(failure(PublicationPhase::Observation));
    }
    let (observed, filesystem_identity) = filesystem.observe_candidate()?;
    if observed != sealed.selector || filesystem_identity != sealed.identity {
        return Err(failure(PublicationPhase::Observation));
    }
    accept_observe(
        database
            .observe(lease, &observed, &filesystem_identity)
            .await?,
    )?;
    Ok(ObservedPublicationEvidence {
        prior,
        sealed,
        target_evidence,
        observed,
    })
}

async fn read_complete_snapshot<D: PublicationDatabase>(
    database: &mut D,
    lease: &RouteSetPublicationLease,
    batch_size: usize,
) -> Result<Vec<FrozenSnapshotItem>, DriverError> {
    let mut snapshot = Vec::with_capacity(lease.snapshot_count);
    let mut after = None;
    while snapshot.len() < lease.snapshot_count {
        require_renewal(database, lease, PublicationPhase::SnapshotRead).await?;
        let remaining = lease.snapshot_count - snapshot.len();
        let requested = batch_size.min(remaining);
        let batch = database.read_snapshot(lease, after, requested).await?;
        if batch.is_empty() || batch.len() > requested || batch.len() > remaining {
            return Err(failure(PublicationPhase::SnapshotRead));
        }
        for item in &batch {
            if after.is_some_and(|previous| previous >= item.workshop_id) {
                return Err(failure(PublicationPhase::SnapshotRead));
            }
            after = Some(item.workshop_id);
        }
        snapshot.extend(batch);
    }
    if snapshot.len() != lease.snapshot_count {
        return Err(failure(PublicationPhase::SnapshotRead));
    }
    Ok(snapshot)
}

async fn require_renewal<D: PublicationDatabase>(
    database: &mut D,
    lease: &RouteSetPublicationLease,
    phase: PublicationPhase,
) -> Result<(), DriverError> {
    if database.renew(lease).await? {
        Ok(())
    } else {
        Err(failure(phase))
    }
}

fn database_prior_identity(identity: &PriorLoadedIdentity) -> Option<RouteSetPriorLoadedIdentity> {
    match identity {
        PriorLoadedIdentity::BootLive => None,
        PriorLoadedIdentity::Startup(identity) => {
            Some(RouteSetPriorLoadedIdentity::Startup(identity.clone()))
        }
        PriorLoadedIdentity::ReleaseOverlay(identity) => {
            Some(RouteSetPriorLoadedIdentity::Release(identity.clone()))
        }
        PriorLoadedIdentity::RouteSet(identity) => {
            Some(RouteSetPriorLoadedIdentity::RouteSet(identity.clone()))
        }
    }
}

fn accept_prior(outcome: RecordRouteSetPriorOutcome) -> Result<(), DriverError> {
    match outcome {
        RecordRouteSetPriorOutcome::Recorded | RecordRouteSetPriorOutcome::Replay => Ok(()),
        _ => Err(failure(PublicationPhase::PriorObservation)),
    }
}

fn accept_entry(outcome: RecordRouteSetEntryOutcome) -> Result<(), DriverError> {
    match outcome {
        RecordRouteSetEntryOutcome::Recorded | RecordRouteSetEntryOutcome::Replay => Ok(()),
        _ => Err(failure(PublicationPhase::Staging)),
    }
}

fn accept_seal(outcome: SealRouteSetPublicationOutcome) -> Result<(), DriverError> {
    match outcome {
        SealRouteSetPublicationOutcome::Sealed | SealRouteSetPublicationOutcome::Replay => Ok(()),
        _ => Err(failure(PublicationPhase::Sealing)),
    }
}

fn accept_start(outcome: StartRouteSetPublicationOutcome) -> Result<(), DriverError> {
    match outcome {
        StartRouteSetPublicationOutcome::Started | StartRouteSetPublicationOutcome::Replay => {
            Ok(())
        }
        _ => Err(failure(PublicationPhase::StartAttempted)),
    }
}

fn accept_observe(outcome: ObserveRouteSetPublicationOutcome) -> Result<(), DriverError> {
    match outcome {
        ObserveRouteSetPublicationOutcome::Observed | ObserveRouteSetPublicationOutcome::Replay => {
            Ok(())
        }
        _ => Err(failure(PublicationPhase::Observation)),
    }
}

fn set_phase(current: &StdMutex<PublicationPhase>, phase: PublicationPhase) {
    *current.lock().expect("publication phase mutex is poisoned") = phase;
    tracing::Span::current().record("publication.phase", phase.as_str());
}

impl PublicationPhase {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Admission => "admission",
            Self::PriorObservation => "prior_observation",
            Self::SnapshotRead => "snapshot_read",
            Self::Preparation => "preparation",
            Self::Staging => "staging",
            Self::Sealing => "sealing",
            Self::StartAttempted => "start_attempted",
            Self::Publishing => "publishing",
            Self::RuntimeReload => "runtime_reload",
            Self::Observation => "observation",
            Self::Finalization => "finalization",
        }
    }
}

fn failure(phase: PublicationPhase) -> DriverError {
    let _ = phase;
    DriverError(
        StatusCode::SERVICE_UNAVAILABLE,
        "deployment backend unavailable".into(),
    )
}

impl PublicationFailure {
    fn new(phase: PublicationPhase, risk: PublicationRisk, source: DriverError) -> Self {
        Self {
            phase,
            risk,
            safe_class: source.safe_class(),
            source,
        }
    }
}

fn report_failure(failure: PublicationFailure) -> DriverError {
    tracing::error!(
        publication.phase = failure.phase.as_str(),
        publication.risk = match failure.risk {
            PublicationRisk::Reversible => "reversible",
            PublicationRisk::StartAttempted => "start_attempted",
        },
        error_class = failure.safe_class,
        "route-set publication failed"
    );
    failure.source
}

#[cfg(test)]
mod tests {
    use std::fs::DirBuilder;
    use std::os::unix::fs::DirBuilderExt as _;
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };
    use std::time::Duration;

    use serde_json::json;
    use sha2::{Digest as _, Sha256};

    use super::*;
    use crate::docker_driver::ControlOperationLease;
    use crate::docker_driver::gateway::{RouteSetGenerationIdentity, RouteSetPublicationKind};
    use crate::docker_driver::route_projection::RouteDisposition as ProjectionDisposition;
    use crate::docker_driver::route_set_generation_fs::{
        RouteDisposition as EvidenceDisposition, RouteSetGenerationName,
    };

    const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SET_DIGEST: &str =
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    #[derive(Default)]
    struct CollectRecorder(Vec<Uuid>);

    #[async_trait]
    impl DurableRowRecorder for CollectRecorder {
        async fn record(&mut self, evidence: &RouteSetSealEvidence) -> Result<(), DriverError> {
            self.0.push(evidence.workshop_id);
            Ok(())
        }
    }

    struct FakeGuard {
        held: Arc<AtomicUsize>,
        fail: bool,
        acquisitions: usize,
        sequence: Arc<Mutex<Vec<String>>>,
    }

    struct FakeGuardLease(Arc<AtomicUsize>);
    struct FakeRetainedGuard(Arc<AtomicUsize>);

    impl Drop for FakeGuardLease {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }

    impl Drop for FakeRetainedGuard {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }

    impl RetainHostGuard for FakeGuardLease {
        type Retained = FakeRetainedGuard;

        fn retain_for_quarantine(&self) -> Result<Self::Retained, DriverError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(FakeRetainedGuard(self.0.clone()))
        }
    }

    #[async_trait]
    impl PublicationGuard for FakeGuard {
        type Guard = FakeGuardLease;

        async fn acquire(&mut self) -> Result<Self::Guard, DriverError> {
            self.acquisitions += 1;
            self.sequence.lock().unwrap().push("guard:acquire".into());
            if self.fail {
                return Err(DriverError::internal("injected guard failure"));
            }
            assert_eq!(self.held.fetch_add(1, Ordering::SeqCst), 0);
            Ok(FakeGuardLease(self.held.clone()))
        }
    }

    #[derive(Clone, Default)]
    struct FakeCancellationScheduler {
        scheduled: Arc<AtomicUsize>,
        retained: Arc<Mutex<Vec<FakeRetainedGuard>>>,
    }

    impl CancellationQuarantine<FakeRetainedGuard> for FakeCancellationScheduler {
        fn schedule(&self, _: RouteSetPublicationLease, host_guard: FakeRetainedGuard) {
            assert!(host_guard.0.load(Ordering::SeqCst) > 0);
            self.scheduled.fetch_add(1, Ordering::SeqCst);
            self.retained.lock().unwrap().push(host_guard);
        }
    }

    struct FakeHeartbeat {
        starts: Arc<AtomicUsize>,
        stops: Arc<AtomicUsize>,
        loss_after: Option<String>,
        sequence: Arc<Mutex<Vec<String>>>,
    }

    struct HeartbeatStopped(Arc<AtomicUsize>);

    impl Drop for HeartbeatStopped {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[async_trait]
    impl PublicationHeartbeat for FakeHeartbeat {
        async fn monitor(&mut self, _: &RouteSetPublicationLease) -> DriverError {
            self.starts.fetch_add(1, Ordering::SeqCst);
            let _stopped = HeartbeatStopped(self.stops.clone());
            let Some(loss_after) = self.loss_after.clone() else {
                return std::future::pending().await;
            };
            loop {
                if self.sequence.lock().unwrap().contains(&loss_after) {
                    return DriverError::internal("injected publication heartbeat loss");
                }
                tokio::task::yield_now().await;
            }
        }
    }

    struct FakeDatabase {
        lease: RouteSetPublicationLease,
        result_outcome: ReadRouteSetPublicationResult,
        snapshot: Vec<FrozenSnapshotItem>,
        events: Vec<String>,
        fail: Option<&'static str>,
        quarantine_result: Result<bool, ()>,
        guard_held: Arc<AtomicUsize>,
        renewals: usize,
        snapshot_fault: SnapshotFault,
        prior_outcome: RecordRouteSetPriorOutcome,
        entry_outcome: RecordRouteSetEntryOutcome,
        seal_outcome: SealRouteSetPublicationOutcome,
        start_outcome: StartRouteSetPublicationOutcome,
        observe_outcome: ObserveRouteSetPublicationOutcome,
        finish_outcome: FinishRouteSetPublicationOutcome,
        pause: Option<&'static str>,
        sequence: Arc<Mutex<Vec<String>>>,
    }

    #[derive(Clone, Copy, Default)]
    enum SnapshotFault {
        #[default]
        None,
        Empty,
        NonAdvancing,
        OverLimit,
    }

    impl FakeDatabase {
        fn event(&mut self, name: impl Into<String>) -> Result<(), DriverError> {
            let name = name.into();
            self.events.push(name.clone());
            self.sequence.lock().unwrap().push(format!("db:{name}"));
            if self.fail == Some(name.as_str()) {
                Err(DriverError::internal("injected database failure"))
            } else {
                Ok(())
            }
        }
    }

    #[async_trait]
    impl PublicationDatabase for FakeDatabase {
        async fn read_result(
            &mut self,
            _: &RouteSetPublicationResultRequest,
        ) -> Result<ReadRouteSetPublicationResult, DriverError> {
            self.event("read_result")?;
            Ok(self.result_outcome.clone())
        }

        async fn admit(
            &mut self,
            _: &RouteSetPublicationAdmissionRequest,
        ) -> Result<RouteSetPublicationAdmission, DriverError> {
            assert!(self.guard_held.load(Ordering::SeqCst) > 0);
            self.event("admit")?;
            Ok(RouteSetPublicationAdmission::Acquired(self.lease.clone()))
        }

        async fn renew(&mut self, _: &RouteSetPublicationLease) -> Result<bool, DriverError> {
            self.renewals += 1;
            self.event(format!("renew:{}", self.renewals))?;
            Ok(true)
        }

        async fn read_snapshot(
            &mut self,
            _: &RouteSetPublicationLease,
            after: Option<Uuid>,
            limit: usize,
        ) -> Result<Vec<FrozenSnapshotItem>, DriverError> {
            self.event(format!("read:{limit}"))?;
            if matches!(self.snapshot_fault, SnapshotFault::Empty) {
                return Ok(Vec::new());
            }
            if matches!(self.snapshot_fault, SnapshotFault::NonAdvancing) && after.is_some() {
                return Ok(vec![self.snapshot[0].clone()]);
            }
            if matches!(self.snapshot_fault, SnapshotFault::OverLimit) {
                return Ok(self.snapshot.clone());
            }
            Ok(self
                .snapshot
                .iter()
                .filter(|item| after.is_none_or(|after| item.workshop_id > after))
                .take(limit)
                .cloned()
                .collect())
        }

        async fn record_prior(
            &mut self,
            _: &RouteSetPublicationLease,
            _: &PriorSelector,
            loaded: Option<&RouteSetPriorLoadedIdentity>,
        ) -> Result<RecordRouteSetPriorOutcome, DriverError> {
            assert!(matches!(
                loaded,
                Some(RouteSetPriorLoadedIdentity::RouteSet(_))
            ));
            self.event("record_prior")?;
            Ok(self.prior_outcome)
        }

        async fn record_entry(
            &mut self,
            _: &RouteSetPublicationLease,
            evidence: &RouteSetSealEvidence,
        ) -> Result<RecordRouteSetEntryOutcome, DriverError> {
            self.event(format!("record:{}", evidence.projection_generation))?;
            Ok(self.entry_outcome)
        }

        async fn seal(
            &mut self,
            _: &RouteSetPublicationLease,
            _: &SealedRouteSetGeneration,
        ) -> Result<SealRouteSetPublicationOutcome, DriverError> {
            self.event("db_seal")?;
            Ok(self.seal_outcome)
        }

        async fn start(
            &mut self,
            _: &RouteSetPublicationLease,
        ) -> Result<StartRouteSetPublicationOutcome, DriverError> {
            self.event("start")?;
            if self.pause == Some("start") {
                std::future::pending::<()>().await;
            }
            Ok(self.start_outcome)
        }

        async fn observe(
            &mut self,
            _: &RouteSetPublicationLease,
            _: &PriorSelector,
            _: &RouteSetGenerationIdentity,
        ) -> Result<ObserveRouteSetPublicationOutcome, DriverError> {
            assert!(self.guard_held.load(Ordering::SeqCst) > 0);
            self.event("db_observe")?;
            if self.pause == Some("db_observe") {
                std::future::pending::<()>().await;
            }
            Ok(self.observe_outcome)
        }

        async fn finish(
            &mut self,
            _: &RouteSetPublicationLease,
            _: &SealedRouteSetGeneration,
            _: &RouteSetSealEvidence,
        ) -> Result<FinishRouteSetPublicationOutcome, DriverError> {
            assert!(self.guard_held.load(Ordering::SeqCst) > 0);
            self.event("finish")?;
            if self.pause == Some("finish") {
                std::future::pending::<()>().await;
            }
            Ok(self.finish_outcome.clone())
        }

        async fn quarantine(&mut self, _: &RouteSetPublicationLease) -> Result<bool, DriverError> {
            assert!(self.guard_held.load(Ordering::SeqCst) > 0);
            self.events.push("quarantine".into());
            self.sequence.lock().unwrap().push("db:quarantine".into());
            if self.pause == Some("quarantine") {
                std::future::pending::<()>().await;
            }
            self.quarantine_result
                .map_err(|()| DriverError::internal("injected quarantine failure"))
        }
    }

    struct FakeFilesystem {
        prior: PriorSelector,
        prior_loaded: PriorLoadedIdentity,
        sealed: SealedRouteSetGeneration,
        rows: Vec<FrozenSnapshotItem>,
        next: usize,
        events: Vec<String>,
        fail: Option<&'static str>,
        prior_observations: usize,
        sequence: Arc<Mutex<Vec<String>>>,
    }

    impl FakeFilesystem {
        fn event(&mut self, name: impl Into<String>) -> Result<(), DriverError> {
            let name = name.into();
            self.events.push(name.clone());
            self.sequence.lock().unwrap().push(format!("fs:{name}"));
            if self.fail == Some(name.as_str()) {
                Err(DriverError::internal("injected filesystem failure"))
            } else {
                Ok(())
            }
        }
    }

    #[async_trait]
    impl PublicationFilesystem for FakeFilesystem {
        fn observe_prior(&mut self) -> Result<(PriorSelector, PriorLoadedIdentity), DriverError> {
            self.prior_observations += 1;
            self.event(format!("fs_prior:{}", self.prior_observations))?;
            Ok((self.prior.clone(), self.prior_loaded.clone()))
        }

        fn prepare(
            &mut self,
            _: &RouteSetPublicationLease,
            _: &FrozenRouteRuntimeContext,
            snapshot: &[FrozenSnapshotItem],
        ) -> Result<(), DriverError> {
            self.event("prepare")?;
            self.rows = snapshot.to_vec();
            Ok(())
        }

        fn begin(&mut self, _: &RouteSetPublicationLease) -> Result<(), DriverError> {
            self.event("begin")
        }

        async fn stage_and_seal(
            &mut self,
            recorder: &mut (dyn DurableRowRecorder + Send),
        ) -> Result<SealedRouteSetGeneration, DriverError> {
            while self.next < self.rows.len() {
                let generation = self.rows[self.next].projection_generation;
                self.event(format!("stage:{generation}"))?;
                let row = &self.rows[self.next];
                let evidence = RouteSetSealEvidence {
                    workshop_id: row.workshop_id,
                    projection_generation: row.projection_generation,
                    projection_digest: row.projection_digest.clone(),
                    disposition: EvidenceDisposition::Present,
                    applied_rendered_digest: Some(DIGEST.into()),
                    rendered_digest: DIGEST.into(),
                };
                self.next += 1;
                recorder.record(&evidence).await?;
            }
            self.event("stage_end")?;
            self.event("fs_seal")?;
            Ok(self.sealed.clone())
        }

        fn publish(&mut self, _: &PriorSelector) -> Result<(), DriverError> {
            self.event("publish")
        }

        fn observe_candidate(
            &mut self,
        ) -> Result<(PriorSelector, RouteSetGenerationIdentity), DriverError> {
            self.event("fs_candidate")?;
            Ok((self.sealed.selector.clone(), self.sealed.identity.clone()))
        }
    }

    struct FakeRuntime {
        candidate: RouteSetGenerationIdentity,
        events: Vec<String>,
        fail: Option<&'static str>,
        pause: Option<&'static str>,
        prior_observations: usize,
        sequence: Arc<Mutex<Vec<String>>>,
    }

    impl FakeRuntime {
        fn event(&mut self, name: &'static str) -> Result<(), DriverError> {
            self.events.push(name.into());
            self.sequence
                .lock()
                .unwrap()
                .push(format!("runtime:{name}"));
            if self.fail == Some(name) {
                Err(DriverError::internal("injected runtime failure"))
            } else {
                Ok(())
            }
        }
    }

    #[async_trait]
    impl PublicationRuntime for FakeRuntime {
        async fn observe_prior(&mut self, _: &PriorLoadedIdentity) -> Result<(), DriverError> {
            self.prior_observations += 1;
            self.event(if self.prior_observations == 1 {
                "runtime_prior:1"
            } else {
                "runtime_prior:2"
            })
        }

        async fn reload(&mut self, _: &str) -> Result<(), DriverError> {
            self.event("reload")?;
            if self.pause == Some("reload") {
                std::future::pending::<()>().await;
            }
            Ok(())
        }

        async fn freeze_context(
            &mut self,
            _: &[FrozenSnapshotItem],
        ) -> Result<FrozenRouteRuntimeContext, DriverError> {
            self.event("freeze_context")?;
            if self.pause == Some("freeze_context") {
                std::future::pending::<()>().await;
            }
            Ok(FrozenRouteRuntimeContext {
                odoo_upstream: "odoo".into(),
                paperless_upstreams: BTreeMap::new(),
            })
        }

        async fn observe_candidate(
            &mut self,
            _: &RouteSetGenerationIdentity,
        ) -> Result<RouteSetGenerationIdentity, DriverError> {
            self.event("runtime_candidate")?;
            if self.pause == Some("runtime_candidate") {
                std::future::pending::<()>().await;
            }
            Ok(self.candidate.clone())
        }
    }

    struct Fixture {
        guard: FakeGuard,
        cancellation_scheduler: FakeCancellationScheduler,
        heartbeat: FakeHeartbeat,
        request: RouteSetPublicationAdmissionRequest,
        database: FakeDatabase,
        filesystem: FakeFilesystem,
        runtime: FakeRuntime,
        sequence: Arc<Mutex<Vec<String>>>,
    }

    fn completed_response(
        lease: &RouteSetPublicationLease,
        sealed: &SealedRouteSetGeneration,
    ) -> RouteSetPublicationResponse {
        route_set_publication_db::RouteSetPublicationResponse {
            outcome: "applied".into(),
            workshop_id: lease.target_workshop_id,
            route_evidence: route_set_publication_db::RouteSetAppliedEvidence {
                driver_operation_id: lease.driver_operation_id,
                workshop_id: lease.target_workshop_id,
                route_generation: lease.target_projection_generation,
                projection_digest: lease.target_projection_digest.clone(),
                disposition: route_set_publication_db::RouteSetAppliedDisposition::Present,
                rendered_digest: DIGEST.into(),
                route_fence_token: lease.target_route_fence_token,
            },
            route_set_evidence: route_set_publication_db::CompletedRouteSetEvidence {
                protocol_version: 1,
                publication_id: lease.publication_id,
                publication_kind: lease.publication_kind,
                selector: lease.selector.clone(),
                route_set_digest: sealed.identity.route_set_digest.clone(),
                snapshot_count: sealed.route_count,
                present_count: sealed.present_route_count,
                global_fence_token: lease.global_fence_token,
                directory_device: sealed.selector.directory_device(),
                directory_inode: sealed.selector.directory_inode(),
            },
        }
    }

    fn fixture(fail: Option<&'static str>) -> Fixture {
        fixture_kind(fail, RouteSetPublicationKind::Projection)
    }

    fn fixture_kind(
        fail: Option<&'static str>,
        publication_kind: RouteSetPublicationKind,
    ) -> Fixture {
        let guard_held = Arc::new(AtomicUsize::new(0));
        let sequence = Arc::new(Mutex::new(Vec::new()));
        let publication_id = Uuid::from_u128(10);
        let workshops = [
            Uuid::from_u128(20),
            Uuid::from_u128(30),
            Uuid::from_u128(40),
        ];
        let identity = RouteSetGenerationIdentity::new(
            publication_id,
            publication_kind,
            51,
            workshops[1],
            61,
            SET_DIGEST.into(),
        )
        .unwrap();
        let selector = PriorSelector::from_recorded(
            RouteSetGenerationName::new(publication_id, publication_kind).selector_target(),
            7,
            8,
        )
        .unwrap();
        let lease = RouteSetPublicationLease {
            publication_id,
            driver_operation_id: Uuid::from_u128(11),
            publication_kind,
            control_operation: ControlOperationLease {
                id: Uuid::from_u128(12),
                attempt: 1,
                owner: "fixture".into(),
            },
            target_workshop_id: workshops[1],
            target_projection_generation: 2,
            target_projection_digest: DIGEST.into(),
            expected_disposition: route_set_publication_db::RouteSetAppliedDisposition::Present,
            instance_owner: Uuid::from_u128(13),
            execution_token: Uuid::from_u128(14),
            global_lease_token: Uuid::from_u128(15),
            route_lease_token: Uuid::from_u128(16),
            global_fence_token: 51,
            target_route_fence_token: 61,
            selector: selector.target().into(),
            snapshot_count: workshops.len(),
            ttl_seconds: 120,
        };
        let snapshot = workshops
            .into_iter()
            .enumerate()
            .map(|(index, workshop_id)| FrozenSnapshotItem {
                workshop_id,
                projection_generation: i64::try_from(index + 1).unwrap(),
                projection_digest: DIGEST.into(),
                disposition: ProjectionDisposition::Present,
                canonical_projection: json!({}),
                applied_rendered_digest: DIGEST.into(),
                is_target: workshop_id == lease.target_workshop_id,
            })
            .collect();
        let prior_identity = RouteSetGenerationIdentity::new(
            Uuid::from_u128(9),
            RouteSetPublicationKind::Projection,
            31,
            workshops[0],
            41,
            DIGEST.into(),
        )
        .unwrap();
        let prior = PriorSelector::from_recorded(
            RouteSetGenerationName::new(
                prior_identity.publication_id,
                prior_identity.publication_kind,
            )
            .selector_target(),
            3,
            4,
        )
        .unwrap();
        let sealed = SealedRouteSetGeneration {
            name: RouteSetGenerationName::new(publication_id, publication_kind),
            identity: identity.clone(),
            route_count: 3,
            present_route_count: 3,
            selector,
        };
        let request = RouteSetPublicationAdmissionRequest {
            control_operation: lease.control_operation.clone(),
            workshop_id: lease.target_workshop_id,
            publication_kind,
            idempotency_key: "fixture".into(),
            request_digest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .into(),
            projection_generation: 2,
            projection_digest: DIGEST.into(),
            expected_disposition: route_set_publication_db::RouteSetAppliedDisposition::Present,
            instance_owner: lease.instance_owner,
            execution_token: lease.execution_token,
            global_lease_token: lease.global_lease_token,
            route_lease_token: lease.route_lease_token,
            ttl_seconds: lease.ttl_seconds,
        };
        let finish_outcome =
            FinishRouteSetPublicationOutcome::Completed(completed_response(&lease, &sealed));
        Fixture {
            guard: FakeGuard {
                held: guard_held.clone(),
                fail: false,
                acquisitions: 0,
                sequence: sequence.clone(),
            },
            cancellation_scheduler: FakeCancellationScheduler::default(),
            heartbeat: FakeHeartbeat {
                starts: Arc::new(AtomicUsize::new(0)),
                stops: Arc::new(AtomicUsize::new(0)),
                loss_after: None,
                sequence: sequence.clone(),
            },
            request,
            database: FakeDatabase {
                lease,
                result_outcome: ReadRouteSetPublicationResult::Absent,
                snapshot,
                events: Vec::new(),
                fail,
                quarantine_result: Ok(true),
                guard_held,
                renewals: 0,
                snapshot_fault: SnapshotFault::None,
                prior_outcome: RecordRouteSetPriorOutcome::Recorded,
                entry_outcome: RecordRouteSetEntryOutcome::Recorded,
                seal_outcome: SealRouteSetPublicationOutcome::Sealed,
                start_outcome: StartRouteSetPublicationOutcome::Started,
                observe_outcome: ObserveRouteSetPublicationOutcome::Observed,
                finish_outcome,
                pause: None,
                sequence: sequence.clone(),
            },
            filesystem: FakeFilesystem {
                prior,
                prior_loaded: PriorLoadedIdentity::RouteSet(prior_identity),
                sealed,
                rows: Vec::new(),
                next: 0,
                events: Vec::new(),
                fail,
                prior_observations: 0,
                sequence: sequence.clone(),
            },
            runtime: FakeRuntime {
                candidate: identity,
                events: Vec::new(),
                fail,
                pause: None,
                prior_observations: 0,
                sequence: sequence.clone(),
            },
            sequence,
        }
    }

    async fn run(
        fixture: &mut Fixture,
    ) -> Result<
        ObservedPendingFinalization<FakeGuardLease, FakeCancellationScheduler, FakeRetainedGuard>,
        DriverError,
    > {
        let mut plan = RouteSetPublicationPlan::new(&fixture.request);
        plan.snapshot_batch_size = 2;
        coordinate_route_set_publication(
            &mut fixture.guard,
            fixture.cancellation_scheduler.clone(),
            &mut fixture.database,
            &mut fixture.heartbeat,
            &mut fixture.filesystem,
            &mut fixture.runtime,
            plan,
        )
        .await
    }

    #[tokio::test]
    async fn recovery_kinds_share_the_full_guarded_heartbeat_state_machine() {
        for kind in [
            RouteSetPublicationKind::RecoveryMaintenance,
            RouteSetPublicationKind::RecoveryRestore,
        ] {
            let mut fixture = fixture_kind(None, kind);
            let pending = run(&mut fixture).await.unwrap();
            assert_eq!(pending.lease.publication_kind, kind);
            assert_eq!(fixture.heartbeat.starts.load(Ordering::SeqCst), 1);
            assert_eq!(fixture.heartbeat.stops.load(Ordering::SeqCst), 1);
            assert_eq!(fixture.guard.held.load(Ordering::SeqCst), 2);
            assert!(fixture.database.events.contains(&"start".into()));
            assert!(fixture.database.events.contains(&"db_observe".into()));
            drop(pending);
            assert_eq!(
                fixture
                    .cancellation_scheduler
                    .scheduled
                    .load(Ordering::SeqCst),
                1
            );
            fixture
                .cancellation_scheduler
                .retained
                .lock()
                .unwrap()
                .clear();
            assert_eq!(fixture.guard.held.load(Ordering::SeqCst), 0);
        }
    }

    #[tokio::test]
    async fn recovery_kind_heartbeat_loss_obeys_the_start_boundary() {
        for kind in [
            RouteSetPublicationKind::RecoveryMaintenance,
            RouteSetPublicationKind::RecoveryRestore,
        ] {
            let mut pre_start = fixture_kind(None, kind);
            pre_start.runtime.pause = Some("freeze_context");
            pre_start.heartbeat.loss_after = Some("runtime:freeze_context".into());
            assert!(run(&mut pre_start).await.is_err());
            assert_eq!(
                pre_start
                    .cancellation_scheduler
                    .scheduled
                    .load(Ordering::SeqCst),
                0
            );
            assert_eq!(pre_start.guard.held.load(Ordering::SeqCst), 0);

            let mut post_start = fixture_kind(None, kind);
            post_start.runtime.pause = Some("reload");
            post_start.heartbeat.loss_after = Some("db:start".into());
            assert!(run(&mut post_start).await.is_err());
            assert!(post_start.database.events.contains(&"quarantine".into()));
            assert_eq!(
                post_start
                    .cancellation_scheduler
                    .scheduled
                    .load(Ordering::SeqCst),
                0
            );
            assert_eq!(post_start.guard.held.load(Ordering::SeqCst), 0);
        }
    }

    #[test]
    fn recovery_kind_entrypoint_is_supervised_dormant_and_privacy_safe() {
        let source = include_str!("route_set_publication.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        assert_eq!(
            production
                .matches("async fn execute_recovery_route_set_dormant(")
                .count(),
            1
        );
        let body = production
            .split("async fn execute_recovery_route_set_dormant(")
            .nth(1)
            .unwrap()
            .split("struct RecoverySqlPublicationDatabase")
            .next()
            .unwrap();
        assert!(body.contains("try_spawn_admitted"));
        assert!(body.contains("execute_recovery_route_set_owned"));
        assert!(!body.contains("execution_token = %"));
        assert!(!body.contains("global_lease_token = %"));
        assert!(!body.contains("route_lease_token = %"));
        let owned = production
            .split("async fn execute_recovery_route_set_owned(")
            .nth(1)
            .unwrap()
            .split("#[tracing::instrument(")
            .next()
            .unwrap();
        let durable_reads = owned
            .match_indices("read_durable_recovery_result")
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        let host_guard = owned.find("SharedHostGuardPort").unwrap();
        let preflight = owned.find("observe_bound_prior").unwrap();
        assert_eq!(durable_reads.len(), 2);
        assert!(
            durable_reads[0] < host_guard
                && host_guard < durable_reads[1]
                && durable_reads[1] < preflight
        );
        let active = include_str!("../docker_driver.rs");
        assert!(!active.contains("execute_recovery_route_set_dormant("));
    }

    #[test]
    fn startup_entrypoint_is_supervised_full_fleet_and_dormant() {
        let source = include_str!("route_set_publication.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        assert_eq!(
            production
                .matches("async fn execute_startup_route_set_dormant(")
                .count(),
            1
        );
        let owned = production
            .split("async fn execute_startup_route_set_owned(")
            .nth(1)
            .unwrap()
            .split("async fn monitor_startup_heartbeat(")
            .next()
            .unwrap();
        let reads = owned
            .match_indices("read_startup_durable")
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        assert_eq!(reads.len(), 2);
        assert!(reads[0] < owned.find("SharedOdooHostGuard::acquire").unwrap());
        assert!(owned.find("SharedOdooHostGuard::acquire").unwrap() < reads[1]);
        let lifecycle = production
            .split("async fn coordinate_startup_acquired(")
            .nth(1)
            .unwrap();
        for transition in [
            "record_startup_prior",
            "read_startup_snapshot_batch",
            "record_startup_entry",
            "seal_startup_publication",
            "start_startup_publication",
            "publish(prior)",
            "reload_gateway_runtime",
            "observe_running_route_set_generation",
            "observe_startup_publication",
            "finish_startup_publication",
        ] {
            assert!(lifecycle.contains(transition), "missing {transition}");
        }
        assert!(lifecycle.contains("fleet_release_unresolved"));
        assert!(lifecycle.contains("stage_startup_present"));
        for phase in [
            "publishing",
            "runtime_reload",
            "observation",
            "finalization",
        ] {
            assert!(lifecycle.contains(phase), "missing trace phase {phase}");
        }
        assert!(production.contains("impl Drop for StartupTraceOutcomeGuard"));
        assert!(production.contains("record(\"result.outcome\", \"failed\")"));
        assert!(production.contains("ReadStartupRouteSetAdmission::NotApplied"));
        assert!(owned.contains("StartupRouteSetAdmission::NotApplied"));
        for field in [
            "publication.id",
            "effect.id",
            "publication.kind",
            "publication.phase",
            "publication.risk",
            "route.count",
            "result.outcome",
        ] {
            assert!(
                production.contains(field),
                "missing safe trace field {field}"
            );
        }
        let annotation = production
            .split("async fn coordinate_startup_acquired(")
            .next()
            .unwrap()
            .rsplit("#[tracing::instrument(")
            .next()
            .unwrap();
        assert!(annotation.contains("skip_all"));
        for private in [
            "selector",
            "hostname",
            "database_ref",
            "token",
            "digest",
            "raw_error",
        ] {
            assert!(
                !annotation.contains(private),
                "private trace field {private}"
            );
        }
        assert!(
            !include_str!("../docker_driver.rs").contains("execute_startup_route_set_dormant(")
        );
    }

    async fn execute(fixture: &mut Fixture) -> Result<RouteSetPublicationResponse, DriverError> {
        execute_route_set_with_ports(
            &mut fixture.guard,
            fixture.cancellation_scheduler.clone(),
            &mut fixture.database,
            &mut fixture.heartbeat,
            &mut fixture.filesystem,
            &mut fixture.runtime,
            &fixture.request,
        )
        .await
    }

    #[tokio::test]
    async fn top_level_result_read_precedes_admission_and_closes_every_outcome() {
        let mut completed = fixture(None);
        let response = completed_response(&completed.database.lease, &completed.filesystem.sealed);
        completed.database.result_outcome = ReadRouteSetPublicationResult::Completed {
            publication_id: completed.database.lease.publication_id,
            driver_operation_id: completed.database.lease.driver_operation_id,
            response: Box::new(response.clone()),
        };
        assert_eq!(execute(&mut completed).await.unwrap(), response);
        assert_eq!(completed.database.events, ["read_result"]);
        assert_eq!(completed.guard.acquisitions, 0);

        let mut absent = fixture(None);
        assert_eq!(execute(&mut absent).await.unwrap().outcome, "applied");
        assert_eq!(
            absent.database.events.first().map(String::as_str),
            Some("read_result")
        );
        assert_eq!(
            absent
                .database
                .events
                .iter()
                .filter(|event| event.as_str() == "admit")
                .count(),
            1
        );
        assert_eq!(
            absent.database.events.last().map(String::as_str),
            Some("finish")
        );
        assert_eq!(absent.guard.acquisitions, 1);
        assert_eq!(absent.guard.held.load(Ordering::SeqCst), 0);

        for result in [
            ReadRouteSetPublicationResult::Conflict,
            ReadRouteSetPublicationResult::Pending {
                publication_id: Uuid::from_u128(90),
                driver_operation_id: Uuid::from_u128(91),
            },
        ] {
            let mut fixture = fixture(None);
            fixture.database.result_outcome = result;
            assert!(execute(&mut fixture).await.is_err());
            assert_eq!(fixture.database.events, ["read_result"]);
            assert_eq!(fixture.guard.acquisitions, 0);
        }

        let mut read_error = fixture(Some("read_result"));
        assert!(execute(&mut read_error).await.is_err());
        assert_eq!(read_error.database.events, ["read_result"]);
        assert_eq!(read_error.guard.acquisitions, 0);
    }

    #[tokio::test]
    async fn successful_execution_structurally_stops_every_heartbeat() {
        let mut fixture = fixture(None);
        assert_eq!(execute(&mut fixture).await.unwrap().outcome, "applied");
        assert_eq!(fixture.heartbeat.starts.load(Ordering::SeqCst), 2);
        assert_eq!(fixture.heartbeat.stops.load(Ordering::SeqCst), 2);
        assert_eq!(fixture.guard.held.load(Ordering::SeqCst), 0);
        assert_eq!(
            fixture
                .cancellation_scheduler
                .scheduled
                .load(Ordering::SeqCst),
            0
        );
    }

    #[tokio::test]
    async fn heartbeat_loss_before_start_is_reversible_and_releases_the_guard() {
        let mut fixture = fixture(None);
        fixture.runtime.pause = Some("freeze_context");
        fixture.heartbeat.loss_after = Some("runtime:freeze_context".into());
        assert!(execute(&mut fixture).await.is_err());
        assert!(!fixture.database.events.iter().any(|event| event == "start"));
        assert!(
            !fixture
                .database
                .events
                .iter()
                .any(|event| event == "quarantine")
        );
        assert_eq!(fixture.heartbeat.starts.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.heartbeat.stops.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.guard.held.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn heartbeat_loss_after_start_quarantines_while_the_guard_is_held() {
        for boundary in ["reload", "runtime_candidate"] {
            let mut fixture = fixture(None);
            fixture.runtime.pause = Some(boundary);
            fixture.heartbeat.loss_after = Some(format!("runtime:{boundary}"));
            assert!(execute(&mut fixture).await.is_err(), "{boundary}");
            assert_eq!(
                fixture.database.events.last().map(String::as_str),
                Some("quarantine"),
                "{boundary}"
            );
            assert_eq!(fixture.heartbeat.starts.load(Ordering::SeqCst), 1);
            assert_eq!(fixture.heartbeat.stops.load(Ordering::SeqCst), 1);
            assert_eq!(fixture.guard.held.load(Ordering::SeqCst), 0);
            assert_eq!(
                fixture
                    .cancellation_scheduler
                    .scheduled
                    .load(Ordering::SeqCst),
                0,
                "confirmed synchronous quarantine must disarm cancellation"
            );
        }
    }

    #[tokio::test]
    async fn heartbeat_loss_retains_the_guard_until_quarantine_is_durable() {
        let mut fixture = fixture(None);
        fixture.runtime.pause = Some("reload");
        fixture.database.pause = Some("quarantine");
        fixture.heartbeat.loss_after = Some("runtime:reload".into());
        let timed = tokio::time::timeout(Duration::from_millis(10), execute(&mut fixture)).await;
        assert!(timed.is_err());
        assert_eq!(
            fixture.database.events.last().map(String::as_str),
            Some("quarantine")
        );
        assert_eq!(fixture.heartbeat.starts.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.heartbeat.stops.load(Ordering::SeqCst), 1);
        assert_eq!(
            fixture
                .cancellation_scheduler
                .scheduled
                .load(Ordering::SeqCst),
            1
        );
        assert_eq!(fixture.guard.held.load(Ordering::SeqCst), 1);
        fixture
            .cancellation_scheduler
            .retained
            .lock()
            .unwrap()
            .clear();
        assert_eq!(fixture.guard.held.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn heartbeat_loss_during_finalization_transfers_guard_to_quarantine() {
        for boundary in ["runtime_candidate", "finish"] {
            let mut fixture = fixture(None);
            let pending = run(&mut fixture).await.unwrap();
            fixture.sequence.lock().unwrap().clear();
            if boundary == "runtime_candidate" {
                fixture.runtime.pause = Some(boundary);
                fixture.heartbeat.loss_after = Some(format!("runtime:{boundary}"));
            } else {
                fixture.database.pause = Some(boundary);
                fixture.heartbeat.loss_after = Some(format!("db:{boundary}"));
            }
            assert!(
                pending
                    .finalize(
                        &mut fixture.database,
                        &mut fixture.filesystem,
                        &mut fixture.runtime,
                        &mut fixture.heartbeat,
                    )
                    .await
                    .is_err(),
                "{boundary}"
            );
            assert_eq!(fixture.heartbeat.starts.load(Ordering::SeqCst), 2);
            assert_eq!(fixture.heartbeat.stops.load(Ordering::SeqCst), 2);
            assert_eq!(
                fixture
                    .cancellation_scheduler
                    .scheduled
                    .load(Ordering::SeqCst),
                1
            );
            assert_eq!(fixture.guard.held.load(Ordering::SeqCst), 1);
            fixture
                .cancellation_scheduler
                .retained
                .lock()
                .unwrap()
                .clear();
            assert_eq!(fixture.guard.held.load(Ordering::SeqCst), 0);
        }
    }

    #[test]
    fn heartbeat_period_and_timeout_keep_a_safe_lease_margin() {
        let mut fixture = fixture(None);
        let interval = heartbeat_interval(&fixture.database.lease);
        let timeout = heartbeat_timeout(interval);
        assert_eq!(interval, Duration::from_secs(30));
        assert_eq!(timeout, Duration::from_secs(10));
        assert!(interval + timeout < Duration::from_secs(60));
        assert!(interval + timeout < Duration::from_secs(120));
        fixture.database.lease.ttl_seconds = 1;
        assert_eq!(
            heartbeat_interval(&fixture.database.lease),
            Duration::from_secs(1)
        );
        fixture.database.lease.ttl_seconds = 2;
        assert_eq!(
            heartbeat_interval(&fixture.database.lease),
            Duration::from_secs(1)
        );
        let now = tokio::time::Instant::now();
        let mut next = None;
        let first = heartbeat_deadline(&mut next, now, Duration::from_secs(20));
        assert_eq!(first, now + Duration::from_secs(20));
        assert_eq!(
            heartbeat_deadline(
                &mut next,
                now + Duration::from_secs(19),
                Duration::from_secs(20)
            ),
            first,
            "finalization must inherit the coordinate renewal deadline"
        );
    }

    #[tokio::test]
    async fn heartbeat_first_finalization_recovers_an_already_committed_receipt() {
        let mut fixture = fixture(None);
        let pending = run(&mut fixture).await.unwrap();
        let response = completed_response(&fixture.database.lease, &fixture.filesystem.sealed);
        fixture.database.result_outcome = ReadRouteSetPublicationResult::Completed {
            publication_id: fixture.database.lease.publication_id,
            driver_operation_id: fixture.database.lease.driver_operation_id,
            response: Box::new(response.clone()),
        };
        // The coordinate pass already recorded this event, so the heartbeat
        // is ready on its first finalization poll and wins the biased race.
        fixture.heartbeat.loss_after = Some("runtime:runtime_candidate".into());
        let recovered = pending
            .finalize(
                &mut fixture.database,
                &mut fixture.filesystem,
                &mut fixture.runtime,
                &mut fixture.heartbeat,
            )
            .await
            .unwrap();
        assert_eq!(recovered, response);
        assert!(
            !fixture
                .database
                .events
                .iter()
                .any(|event| event == "finish")
        );
        assert_eq!(fixture.guard.held.load(Ordering::SeqCst), 0);
        assert_eq!(
            fixture
                .cancellation_scheduler
                .scheduled
                .load(Ordering::SeqCst),
            0
        );
    }

    #[tokio::test]
    async fn cleanup_wait_cannot_lose_the_completion_notification() {
        for _ in 0..100 {
            let tracker = Arc::new(CleanupTracker::default());
            tracker.pending.store(1, Ordering::SeqCst);
            let waiting = tracker.clone();
            let waiter = tokio::spawn(async move { waiting.wait().await });
            tokio::task::yield_now().await;
            drop(CleanupFinished(tracker));
            tokio::time::timeout(Duration::from_secs(1), waiter)
                .await
                .unwrap()
                .unwrap();
        }
    }

    #[test]
    fn production_cleanup_retries_false_and_errors_until_durable_evidence() {
        let pending = ReadRouteSetPublicationResult::Pending {
            publication_id: Uuid::new_v4(),
            driver_operation_id: Uuid::new_v4(),
        };
        assert_eq!(cleanup_decision(Ok(true), None), CleanupDecision::Durable);
        assert_eq!(cleanup_decision(Ok(false), None), CleanupDecision::Retry);
        assert_eq!(
            cleanup_decision(Ok(false), Some(&pending)),
            CleanupDecision::Retry
        );
        assert_eq!(cleanup_decision(Err(()), None), CleanupDecision::Retry);
        let fixture = fixture(None);
        let completed = ReadRouteSetPublicationResult::Completed {
            publication_id: fixture.database.lease.publication_id,
            driver_operation_id: fixture.database.lease.driver_operation_id,
            response: Box::new(completed_response(
                &fixture.database.lease,
                &fixture.filesystem.sealed,
            )),
        };
        assert_eq!(
            cleanup_decision(Ok(false), Some(&completed)),
            CleanupDecision::Durable
        );
    }

    #[test]
    fn cleanup_retry_is_capped_jittered_and_reported_sparsely() {
        let seed = Uuid::from_u128(0x1020_3040_5060_7080_90a0_b0c0_d0e0_f001);
        let delays = (1..=20)
            .map(|attempt| cleanup_retry_delay(Duration::from_millis(100), attempt, seed))
            .collect::<Vec<_>>();
        assert!(delays[0] >= Duration::from_millis(80));
        assert!(delays[0] <= Duration::from_millis(120));
        assert!(delays.iter().all(|delay| *delay <= Duration::from_secs(30)));
        assert!(delays.last().unwrap() >= &Duration::from_secs(24));
        let reported = (1..=20)
            .filter(|attempt| report_cleanup_retry(*attempt))
            .collect::<Vec<_>>();
        assert_eq!(reported, [1, 2, 4, 8, 16]);
    }

    #[tokio::test]
    async fn acquired_publication_is_ordered_paginated_and_stops_at_observed() {
        let mut fixture = fixture(None);
        let result = run(&mut fixture).await.unwrap();
        assert_eq!(result.observed, result.sealed.selector);
        assert!(result.prior.target().starts_with("generations/route-"));
        assert_eq!(
            fixture.database.events,
            [
                "admit",
                "renew:1",
                "record_prior",
                "renew:2",
                "read:2",
                "renew:3",
                "read:1",
                "renew:4",
                "renew:5",
                "record:1",
                "renew:6",
                "record:2",
                "renew:7",
                "record:3",
                "renew:8",
                "db_seal",
                "renew:9",
                "start",
                "db_observe"
            ]
        );
        assert_eq!(
            fixture.filesystem.events,
            [
                "fs_prior:1",
                "fs_prior:2",
                "fs_prior:3",
                "fs_prior:4",
                "prepare",
                "begin",
                "stage:1",
                "stage:2",
                "stage:3",
                "stage_end",
                "fs_seal",
                "publish",
                "fs_candidate"
            ]
        );
        assert_eq!(
            fixture.runtime.events,
            [
                "runtime_prior:1",
                "runtime_prior:2",
                "freeze_context",
                "reload",
                "runtime_candidate"
            ]
        );
        let sequence = fixture.sequence.lock().unwrap();
        let position = |event: &str| sequence.iter().position(|seen| seen == event).unwrap();
        assert!(position("guard:acquire") < position("fs:fs_prior:1"));
        assert!(position("fs:fs_prior:2") < position("db:admit"));
        assert!(position("db:renew:1") < position("fs:fs_prior:3"));
        assert!(position("runtime:runtime_prior:2") < position("fs:fs_prior:4"));
        assert!(position("fs:fs_prior:4") < position("db:record_prior"));
        assert!(position("db:read:1") < position("runtime:freeze_context"));
        assert!(position("runtime:freeze_context") < position("fs:prepare"));
        drop(sequence);
        assert!(
            !fixture
                .database
                .events
                .iter()
                .any(|event| event == "quarantine")
        );
        assert_eq!(fixture.guard.acquisitions, 1);
        assert_eq!(fixture.guard.held.load(Ordering::SeqCst), 2);
        assert_eq!(
            fixture
                .cancellation_scheduler
                .scheduled
                .load(Ordering::SeqCst),
            0
        );
        drop(result);
        assert_eq!(
            fixture
                .cancellation_scheduler
                .scheduled
                .load(Ordering::SeqCst),
            1
        );
        assert_eq!(fixture.guard.held.load(Ordering::SeqCst), 1);
        fixture
            .cancellation_scheduler
            .retained
            .lock()
            .unwrap()
            .clear();
        assert_eq!(fixture.guard.held.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn observed_publication_finalizes_once_and_releases_both_guard_handles() {
        for replay in [false, true] {
            let mut fixture = fixture(None);
            if replay {
                let response =
                    completed_response(&fixture.database.lease, &fixture.filesystem.sealed);
                fixture.database.finish_outcome =
                    FinishRouteSetPublicationOutcome::Replay(response);
            }
            let pending = run(&mut fixture).await.unwrap();
            assert_eq!(fixture.guard.held.load(Ordering::SeqCst), 2);
            let response = pending
                .finalize(
                    &mut fixture.database,
                    &mut fixture.filesystem,
                    &mut fixture.runtime,
                    &mut fixture.heartbeat,
                )
                .await
                .unwrap();
            assert_eq!(response.outcome, "applied");
            assert_eq!(
                fixture.database.events.last().map(String::as_str),
                Some("finish")
            );
            assert_eq!(fixture.guard.held.load(Ordering::SeqCst), 0);
            assert_eq!(
                fixture
                    .cancellation_scheduler
                    .scheduled
                    .load(Ordering::SeqCst),
                0
            );
        }
    }

    #[tokio::test]
    async fn finalization_drift_or_nonterminal_database_outcome_keeps_quarantine_armed() {
        for boundary in [
            "filesystem",
            "worker",
            "authority",
            "conflict",
            "wrong_phase",
            "invalid",
            "finish_error",
        ] {
            let mut fixture = fixture(None);
            let pending = run(&mut fixture).await.unwrap();
            match boundary {
                "filesystem" => {
                    fixture.filesystem.sealed.selector = fixture.filesystem.prior.clone()
                }
                "worker" => fixture.runtime.candidate.global_fence_token += 1,
                "authority" => {
                    fixture.database.finish_outcome =
                        FinishRouteSetPublicationOutcome::AuthorityLost;
                }
                "conflict" => {
                    fixture.database.finish_outcome = FinishRouteSetPublicationOutcome::Conflict;
                }
                "wrong_phase" => {
                    fixture.database.finish_outcome = FinishRouteSetPublicationOutcome::WrongPhase;
                }
                "invalid" => {
                    fixture.database.finish_outcome = FinishRouteSetPublicationOutcome::Invalid;
                }
                "finish_error" => fixture.database.fail = Some("finish"),
                _ => unreachable!(),
            }
            assert!(
                pending
                    .finalize(
                        &mut fixture.database,
                        &mut fixture.filesystem,
                        &mut fixture.runtime,
                        &mut fixture.heartbeat,
                    )
                    .await
                    .is_err(),
                "{boundary}"
            );
            assert_eq!(
                fixture
                    .cancellation_scheduler
                    .scheduled
                    .load(Ordering::SeqCst),
                1,
                "{boundary}"
            );
            assert_eq!(fixture.guard.held.load(Ordering::SeqCst), 1, "{boundary}");
            fixture
                .cancellation_scheduler
                .retained
                .lock()
                .unwrap()
                .clear();
            assert_eq!(fixture.guard.held.load(Ordering::SeqCst), 0);
        }
    }

    #[tokio::test]
    async fn cancellation_during_finish_transfers_the_guard_to_quarantine() {
        let mut fixture = fixture(None);
        let pending = run(&mut fixture).await.unwrap();
        fixture.database.pause = Some("finish");
        let timed = tokio::time::timeout(
            Duration::from_millis(1),
            pending.finalize(
                &mut fixture.database,
                &mut fixture.filesystem,
                &mut fixture.runtime,
                &mut fixture.heartbeat,
            ),
        )
        .await;
        assert!(timed.is_err());
        assert_eq!(
            fixture
                .cancellation_scheduler
                .scheduled
                .load(Ordering::SeqCst),
            1
        );
        assert_eq!(fixture.guard.held.load(Ordering::SeqCst), 1);
        fixture
            .cancellation_scheduler
            .retained
            .lock()
            .unwrap()
            .clear();
        assert_eq!(fixture.guard.held.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn every_fault_obeys_the_start_attempted_quarantine_boundary() {
        let reversible = [
            "admit",
            "renew:1",
            "fs_prior:1",
            "runtime_prior:1",
            "fs_prior:2",
            "fs_prior:3",
            "runtime_prior:2",
            "fs_prior:4",
            "record_prior",
            "renew:2",
            "read:2",
            "renew:3",
            "read:1",
            "freeze_context",
            "prepare",
            "renew:4",
            "begin",
            "renew:5",
            "stage:1",
            "record:1",
            "renew:6",
            "stage:2",
            "record:2",
            "renew:7",
            "stage:3",
            "record:3",
            "renew:8",
            "stage_end",
            "fs_seal",
            "db_seal",
            "renew:9",
        ];
        for boundary in reversible {
            let mut fixture = fixture(Some(boundary));
            assert!(run(&mut fixture).await.is_err(), "{boundary}");
            assert!(
                !fixture
                    .database
                    .events
                    .iter()
                    .any(|event| event == "quarantine"),
                "pre-start boundary {boundary} quarantined"
            );
        }
        let irreversible = [
            "start",
            "publish",
            "reload",
            "runtime_candidate",
            "fs_candidate",
            "db_observe",
        ];
        for boundary in irreversible {
            let mut fixture = fixture(Some(boundary));
            assert!(run(&mut fixture).await.is_err(), "{boundary}");
            assert_eq!(
                fixture.database.events.last().map(String::as_str),
                Some("quarantine")
            );
        }
    }

    #[tokio::test]
    async fn quarantine_failure_never_replaces_or_restores_after_start() {
        for quarantine_result in [Ok(false), Err(())] {
            let mut fixture = fixture(Some("reload"));
            fixture.database.quarantine_result = quarantine_result;
            assert!(run(&mut fixture).await.is_err());
            assert_eq!(
                fixture.database.events.last().map(String::as_str),
                Some("quarantine")
            );
            assert_eq!(
                fixture
                    .cancellation_scheduler
                    .scheduled
                    .load(Ordering::SeqCst),
                1
            );
            assert_eq!(fixture.guard.held.load(Ordering::SeqCst), 1);
            assert_eq!(
                fixture
                    .filesystem
                    .events
                    .iter()
                    .filter(|event| event.as_str() == "publish")
                    .count(),
                1
            );
            assert!(
                !fixture
                    .filesystem
                    .events
                    .iter()
                    .any(|event| event.contains("restore"))
            );
            fixture
                .cancellation_scheduler
                .retained
                .lock()
                .unwrap()
                .clear();
            assert_eq!(fixture.guard.held.load(Ordering::SeqCst), 0);
        }
    }

    #[tokio::test]
    async fn boot_live_prior_is_refused_before_runtime_or_database_evidence() {
        let mut fixture = fixture(None);
        fixture.filesystem.prior =
            PriorSelector::from_recorded("generations/boot-live".into(), 3, 4).unwrap();
        fixture.filesystem.prior_loaded = PriorLoadedIdentity::BootLive;
        assert!(run(&mut fixture).await.is_err());
        assert_eq!(fixture.runtime.events, Vec::<String>::new());
        assert!(fixture.database.events.is_empty());
    }

    #[tokio::test]
    async fn host_guard_is_acquired_before_admission_and_released_on_failure() {
        let mut fixture = fixture(None);
        fixture.guard.fail = true;
        assert!(run(&mut fixture).await.is_err());
        assert_eq!(fixture.guard.acquisitions, 1);
        assert!(fixture.database.events.is_empty());
        assert_eq!(fixture.guard.held.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn malformed_pagination_is_rejected_before_filesystem_preparation() {
        for fault in [
            SnapshotFault::Empty,
            SnapshotFault::NonAdvancing,
            SnapshotFault::OverLimit,
        ] {
            let mut fixture = fixture(None);
            fixture.database.snapshot_fault = fault;
            assert!(run(&mut fixture).await.is_err());
            assert!(
                !fixture
                    .filesystem
                    .events
                    .iter()
                    .any(|event| event == "prepare")
            );
            assert!(
                !fixture
                    .database
                    .events
                    .iter()
                    .any(|event| event == "quarantine")
            );
        }
    }

    #[tokio::test]
    async fn exact_transition_replays_are_accepted() {
        let mut fixture = fixture(None);
        fixture.database.prior_outcome = RecordRouteSetPriorOutcome::Replay;
        fixture.database.entry_outcome = RecordRouteSetEntryOutcome::Replay;
        fixture.database.seal_outcome = SealRouteSetPublicationOutcome::Replay;
        fixture.database.start_outcome = StartRouteSetPublicationOutcome::Replay;
        fixture.database.observe_outcome = ObserveRouteSetPublicationOutcome::Replay;
        assert!(run(&mut fixture).await.is_ok());
        assert!(
            !fixture
                .database
                .events
                .iter()
                .any(|event| event == "quarantine")
        );
    }

    #[tokio::test]
    async fn closed_transition_outcomes_follow_the_risk_boundary() {
        let mut prior_conflict = fixture(None);
        prior_conflict.database.prior_outcome = RecordRouteSetPriorOutcome::Conflict;
        assert!(run(&mut prior_conflict).await.is_err());
        assert!(
            !prior_conflict
                .database
                .events
                .iter()
                .any(|event| event == "quarantine")
        );

        let mut entry_wrong_phase = fixture(None);
        entry_wrong_phase.database.entry_outcome = RecordRouteSetEntryOutcome::WrongPhase;
        assert!(run(&mut entry_wrong_phase).await.is_err());
        assert!(
            !entry_wrong_phase
                .database
                .events
                .iter()
                .any(|event| event == "quarantine")
        );

        let mut seal_conflict = fixture(None);
        seal_conflict.database.seal_outcome = SealRouteSetPublicationOutcome::WrongPhase;
        assert!(run(&mut seal_conflict).await.is_err());
        assert!(
            !seal_conflict
                .database
                .events
                .iter()
                .any(|event| event == "quarantine")
        );

        let mut start_wrong_phase = fixture(None);
        start_wrong_phase.database.start_outcome = StartRouteSetPublicationOutcome::WrongPhase;
        assert!(run(&mut start_wrong_phase).await.is_err());
        assert_eq!(
            start_wrong_phase.database.events.last().map(String::as_str),
            Some("quarantine")
        );

        let mut observe_mismatch = fixture(None);
        observe_mismatch.database.observe_outcome =
            ObserveRouteSetPublicationOutcome::ObservationMismatch;
        assert!(run(&mut observe_mismatch).await.is_err());
        assert_eq!(
            observe_mismatch.database.events.last().map(String::as_str),
            Some("quarantine")
        );
    }

    #[tokio::test]
    async fn cancellation_after_start_schedules_quarantine_and_retains_host_lock() {
        for boundary in ["start", "reload", "runtime_candidate", "db_observe"] {
            let mut fixture = fixture(None);
            if matches!(boundary, "start" | "db_observe") {
                fixture.database.pause = Some(boundary);
            } else {
                fixture.runtime.pause = Some(boundary);
            }
            let timed = tokio::time::timeout(Duration::from_millis(1), run(&mut fixture)).await;
            assert!(timed.is_err(), "{boundary}");
            assert_eq!(
                fixture
                    .cancellation_scheduler
                    .scheduled
                    .load(Ordering::SeqCst),
                1,
                "{boundary}"
            );
            assert_eq!(
                fixture.guard.held.load(Ordering::SeqCst),
                1,
                "retained host lock missing at {boundary}"
            );
            assert!(
                !fixture
                    .filesystem
                    .events
                    .iter()
                    .any(|event| event.contains("restore"))
            );
            fixture
                .cancellation_scheduler
                .retained
                .lock()
                .unwrap()
                .clear();
            assert_eq!(fixture.guard.held.load(Ordering::SeqCst), 0);
        }
    }

    #[tokio::test]
    async fn concrete_filesystem_stages_multiple_rows_with_one_sealer_and_finishes() {
        let path = std::env::temp_dir().join(format!("mb-route-coordinator-{}", Uuid::new_v4()));
        DirBuilder::new().mode(0o750).create(&path).unwrap();
        let base = fixture(None);
        let lease = base.database.lease.clone();
        let canonical = json!({
            "database_id": null,
            "database_ref": null,
            "public_hostname": null,
            "paperless_mode": "absent",
            "paperless_hostname": null,
            "custom_hostnames": []
        });
        let projection_digest = format!(
            "sha256:{:x}",
            Sha256::digest(serde_jcs::to_vec(&canonical).unwrap())
        );
        let empty_digest =
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let snapshot = [
            Uuid::from_u128(20),
            Uuid::from_u128(30),
            Uuid::from_u128(40),
        ]
        .into_iter()
        .enumerate()
        .map(|(index, workshop_id)| FrozenSnapshotItem {
            workshop_id,
            projection_generation: i64::try_from(index + 1).unwrap(),
            projection_digest: projection_digest.clone(),
            disposition: ProjectionDisposition::Absent,
            canonical_projection: canonical.clone(),
            applied_rendered_digest: empty_digest.into(),
            is_target: workshop_id == lease.target_workshop_id,
        })
        .collect::<Vec<_>>();
        let mut filesystem = LocalPublicationFilesystem {
            route_root: &path,
            prepared: None,
            generation: None,
            sealed: None,
        };
        let runtime = FrozenRouteRuntimeContext {
            odoo_upstream: "odoo".into(),
            paperless_upstreams: BTreeMap::new(),
        };
        filesystem.prepare(&lease, &runtime, &snapshot).unwrap();
        filesystem.begin(&lease).unwrap();
        let mut recorder = CollectRecorder::default();
        let sealed = filesystem.stage_and_seal(&mut recorder).await.unwrap();
        assert_eq!(recorder.0.len(), 3);
        assert_eq!(sealed.route_count, 3);
        assert_eq!(sealed.present_route_count, 0);
        drop(filesystem);
        std::fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn coordinator_is_registered_once_dormant_and_privacy_safe() {
        let root = include_str!("../docker_driver.rs");
        assert_eq!(root.matches("mod route_set_publication;").count(), 1);
        assert!(!root.contains("use route_set_publication"));
        assert!(!root.contains("route_set_publication::"));
        for active in [
            include_str!("release.rs"),
            include_str!("recovery.rs"),
            include_str!("startup.rs"),
        ] {
            assert!(!active.contains("coordinate_route_set_publication"));
            assert!(!active.contains("execute_route_set_dormant"));
            assert!(!active.contains("execute_route_set_with_ports"));
        }

        let source = include_str!("route_set_publication.rs");
        let before_coordinator = source
            .split("async fn coordinate_route_set_publication")
            .next()
            .unwrap();
        let root_span = before_coordinator
            .rsplit("#[tracing::instrument(")
            .next()
            .unwrap();
        for secret in [
            "execution_token",
            "global_lease_token",
            "route_lease_token",
            "request_digest",
            "projection_digest",
            "odoo_upstream",
            "paperless_upstreams",
        ] {
            assert!(!root_span.contains(secret), "root span exposed {secret}");
        }
        let production_source = source.split("#[cfg(test)]").next().unwrap();
        assert!(!production_source.contains("restore_prior("));
        assert!(!production_source.contains("finalize_route_set"));
        assert!(!production_source.contains("generation_v1 = true"));
    }
}
