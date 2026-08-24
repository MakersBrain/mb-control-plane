//! Dormant, bounded scheduling policy for immutable generation retention.
//!
//! The module is registered for compile-time verification, but has no active
//! call site. Creating a scheduler performs no I/O and spawns no task; a later
//! activation tranche must explicitly start it through the driver supervisor.
#![allow(dead_code)]

use std::collections::VecDeque;
use std::path::PathBuf;
use std::time::Duration;

use async_trait::async_trait;
use sqlx::PgPool;
use uuid::Uuid;

use super::gateway::ReleaseOverlayKind;
use super::release_route_retention::{
    DormantReleaseGenerationRetentionCoordinator, DormantReleaseGenerationRetentionError,
    DormantReleaseGenerationRetentionResult,
};
use super::release_route_retention_db::{
    ClaimReleaseGenerationRetentionOutcome, ReleaseGenerationRetentionClaimRequest,
    ReleaseGenerationRetentionCursor, discover_release_retention_candidates,
};
use super::route_set_retention::{
    DormantRouteSetRetentionCoordinator, DormantRouteSetRetentionError,
    DormantRouteSetRetentionResult,
};
use super::route_set_retention_db::{
    ClaimRouteSetRetentionOutcome, RouteSetRetentionClaimRequest, discover_retention_candidates,
};
use super::task_supervisor::{
    DriverServiceStop, DriverTaskFailure, DriverTaskKind, DriverTaskReceipt,
    DriverTaskSupervisorHandle, TryAdmitError, TryServiceError,
};

const MAX_PAGE_SIZE: usize = 100;
const MAX_EPOCH_ITEMS: usize = 1_000;
const MAX_JITTER_BASIS_POINTS: u16 = 2_500;
const MAX_DELAY: Duration = Duration::from_secs(24 * 60 * 60);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum ReleaseRetentionOverlay {
    Candidate,
    Maintenance,
}

impl ReleaseRetentionOverlay {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Candidate => "candidate",
            Self::Maintenance => "maintenance",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RetentionLane {
    Universal,
    Release,
}

impl RetentionLane {
    const fn other(self) -> Self {
        match self {
            Self::Universal => Self::Release,
            Self::Release => Self::Universal,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Universal => "universal",
            Self::Release => "release",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum RetentionCursor {
    Universal(Uuid),
    Release {
        driver_operation_id: Uuid,
        overlay: ReleaseRetentionOverlay,
    },
}

impl RetentionCursor {
    fn lane(&self) -> RetentionLane {
        match self {
            Self::Universal(_) => RetentionLane::Universal,
            Self::Release { .. } => RetentionLane::Release,
        }
    }

    fn strictly_after(&self, prior: Option<&Self>) -> bool {
        let Some(prior) = prior else {
            return self.valid();
        };
        match (prior, self) {
            (Self::Universal(left), Self::Universal(right)) => left < right,
            (
                Self::Release {
                    driver_operation_id: left_id,
                    overlay: left_kind,
                },
                Self::Release {
                    driver_operation_id: right_id,
                    overlay: right_kind,
                },
            ) => (left_id, left_kind) < (right_id, right_kind),
            _ => false,
        }
    }

    fn valid(&self) -> bool {
        match self {
            Self::Universal(id) => !id.is_nil(),
            Self::Release {
                driver_operation_id,
                ..
            } => !driver_operation_id.is_nil(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct RetentionCandidate {
    pub key: RetentionCursor,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RetentionExecutionOutcome {
    Completed,
    Replay,
    Busy,
    Ineligible,
    NotFound,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RetentionPortError {
    AtCapacity,
    Transient,
    Protocol,
}

#[async_trait]
pub(super) trait RetentionDiscoveryPort: Send + Sync {
    async fn discover(
        &self,
        lane: RetentionLane,
        after: Option<&RetentionCursor>,
        limit: usize,
    ) -> Result<Vec<RetentionCandidate>, RetentionPortError>;
}

#[async_trait]
pub(super) trait RetentionExecutionPort: Send + Sync {
    /// The implementation must submit the effect to the driver task supervisor
    /// before awaiting it. Cancellation of this waiter must not cancel an
    /// already admitted claim/filesystem operation.
    async fn execute(
        &self,
        candidate: RetentionCandidate,
    ) -> Result<RetentionExecutionOutcome, RetentionPortError>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum StopAwareSleep {
    Elapsed,
    StopRequested,
}

#[async_trait]
pub(super) trait StopSignal: Send {
    fn is_stopping(&self) -> bool;

    async fn sleep_or_stop(&mut self, duration: Duration) -> StopAwareSleep;
}

#[async_trait]
impl StopSignal for DriverServiceStop {
    fn is_stopping(&self) -> bool {
        self.is_requested()
    }

    async fn sleep_or_stop(&mut self, duration: Duration) -> StopAwareSleep {
        if self.is_requested() {
            return StopAwareSleep::StopRequested;
        }
        tokio::select! {
            biased;
            () = self.requested() => StopAwareSleep::StopRequested,
            () = tokio::time::sleep(duration) => {
                if self.is_requested() {
                    StopAwareSleep::StopRequested
                } else {
                    StopAwareSleep::Elapsed
                }
            }
        }
    }
}

pub(super) trait JitterSource: Send {
    /// Return a duration near `base`. The scheduler clamps hostile or buggy
    /// implementations to its configured jitter envelope.
    fn jitter(&mut self, base: Duration, basis_points: u16) -> Duration;
}

#[derive(Clone)]
pub(super) struct PgGenerationRetentionPorts {
    ledger: PgPool,
    route_set: DormantRouteSetRetentionCoordinator,
    release: DormantReleaseGenerationRetentionCoordinator,
    instance_owner: Uuid,
    claim_ttl_seconds: i32,
}

impl PgGenerationRetentionPorts {
    pub(super) fn new(
        ledger: PgPool,
        route_root: PathBuf,
        supervisor: DriverTaskSupervisorHandle,
        instance_owner: Uuid,
        claim_ttl_seconds: i32,
    ) -> Result<Self, InvalidRetentionSchedulerPorts> {
        if instance_owner.is_nil() || !(30..=3_600).contains(&claim_ttl_seconds) {
            return Err(InvalidRetentionSchedulerPorts);
        }
        Ok(Self {
            route_set: DormantRouteSetRetentionCoordinator::new(
                ledger.clone(),
                route_root.clone(),
                supervisor.clone(),
            ),
            release: DormantReleaseGenerationRetentionCoordinator::new(
                ledger.clone(),
                route_root,
                supervisor,
            ),
            ledger,
            instance_owner,
            claim_ttl_seconds,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct InvalidRetentionSchedulerPorts;

#[async_trait]
impl RetentionDiscoveryPort for PgGenerationRetentionPorts {
    async fn discover(
        &self,
        lane: RetentionLane,
        after: Option<&RetentionCursor>,
        limit: usize,
    ) -> Result<Vec<RetentionCandidate>, RetentionPortError> {
        let limit = i32::try_from(limit).map_err(|_| RetentionPortError::Protocol)?;
        match lane {
            RetentionLane::Universal => {
                let after = match after {
                    None => None,
                    Some(RetentionCursor::Universal(publication_id)) => Some(*publication_id),
                    Some(RetentionCursor::Release { .. }) => {
                        return Err(RetentionPortError::Protocol);
                    }
                };
                discover_retention_candidates(&self.ledger, after, limit)
                    .await
                    .map_err(|_| RetentionPortError::Transient)
                    .map(|rows| {
                        rows.into_iter()
                            .map(|row| RetentionCandidate {
                                key: RetentionCursor::Universal(row.publication_id),
                            })
                            .collect()
                    })
            }
            RetentionLane::Release => {
                let after = match after {
                    None => None,
                    Some(RetentionCursor::Release {
                        driver_operation_id,
                        overlay,
                    }) => Some(ReleaseGenerationRetentionCursor {
                        driver_operation_id: *driver_operation_id,
                        overlay_kind: release_overlay_kind(*overlay),
                    }),
                    Some(RetentionCursor::Universal(_)) => {
                        return Err(RetentionPortError::Protocol);
                    }
                };
                discover_release_retention_candidates(&self.ledger, after, limit)
                    .await
                    .map_err(|_| RetentionPortError::Transient)
                    .map(|rows| {
                        rows.into_iter()
                            .map(|row| RetentionCandidate {
                                key: RetentionCursor::Release {
                                    driver_operation_id: row.driver_operation_id,
                                    overlay: scheduler_overlay(row.overlay_kind),
                                },
                            })
                            .collect()
                    })
            }
        }
    }
}

#[async_trait]
impl RetentionExecutionPort for PgGenerationRetentionPorts {
    async fn execute(
        &self,
        candidate: RetentionCandidate,
    ) -> Result<RetentionExecutionOutcome, RetentionPortError> {
        match candidate.key {
            RetentionCursor::Universal(publication_id) => {
                let request = RouteSetRetentionClaimRequest {
                    publication_id,
                    instance_owner: self.instance_owner,
                    claim_token: Uuid::new_v4(),
                    ttl_seconds: self.claim_ttl_seconds,
                };
                match self.route_set.execute(request).await {
                    Ok(DormantRouteSetRetentionResult::Finished {
                        database_outcome, ..
                    }) if database_outcome == "replay" => Ok(RetentionExecutionOutcome::Replay),
                    Ok(DormantRouteSetRetentionResult::Finished { .. }) => {
                        Ok(RetentionExecutionOutcome::Completed)
                    }
                    Ok(DormantRouteSetRetentionResult::Refused(outcome)) => {
                        map_route_set_refusal(outcome)
                    }
                    Err(error) => map_route_set_error(error),
                }
            }
            RetentionCursor::Release {
                driver_operation_id,
                overlay,
            } => {
                let request = ReleaseGenerationRetentionClaimRequest {
                    driver_operation_id,
                    overlay_kind: release_overlay_kind(overlay),
                    instance_owner: self.instance_owner,
                    claim_token: Uuid::new_v4(),
                    ttl_seconds: self.claim_ttl_seconds,
                };
                match self.release.execute(request).await {
                    Ok(DormantReleaseGenerationRetentionResult::Finished {
                        database_outcome,
                        ..
                    }) if database_outcome == "replay" => Ok(RetentionExecutionOutcome::Replay),
                    Ok(DormantReleaseGenerationRetentionResult::Finished { .. }) => {
                        Ok(RetentionExecutionOutcome::Completed)
                    }
                    Ok(DormantReleaseGenerationRetentionResult::Refused(outcome)) => {
                        map_release_refusal(outcome)
                    }
                    Err(error) => map_release_error(error),
                }
            }
        }
    }
}

const fn release_overlay_kind(overlay: ReleaseRetentionOverlay) -> ReleaseOverlayKind {
    match overlay {
        ReleaseRetentionOverlay::Candidate => ReleaseOverlayKind::Candidate,
        ReleaseRetentionOverlay::Maintenance => ReleaseOverlayKind::Maintenance,
    }
}

const fn scheduler_overlay(kind: ReleaseOverlayKind) -> ReleaseRetentionOverlay {
    match kind {
        ReleaseOverlayKind::Candidate => ReleaseRetentionOverlay::Candidate,
        ReleaseOverlayKind::Maintenance => ReleaseRetentionOverlay::Maintenance,
    }
}

fn map_route_set_refusal(
    outcome: ClaimRouteSetRetentionOutcome,
) -> Result<RetentionExecutionOutcome, RetentionPortError> {
    match outcome {
        ClaimRouteSetRetentionOutcome::Busy => Ok(RetentionExecutionOutcome::Busy),
        ClaimRouteSetRetentionOutcome::Ineligible => Ok(RetentionExecutionOutcome::Ineligible),
        ClaimRouteSetRetentionOutcome::NotFound => Ok(RetentionExecutionOutcome::NotFound),
        ClaimRouteSetRetentionOutcome::Invalid
        | ClaimRouteSetRetentionOutcome::Acquired
        | ClaimRouteSetRetentionOutcome::Replay => Err(RetentionPortError::Protocol),
    }
}

fn map_release_refusal(
    outcome: ClaimReleaseGenerationRetentionOutcome,
) -> Result<RetentionExecutionOutcome, RetentionPortError> {
    match outcome {
        ClaimReleaseGenerationRetentionOutcome::Busy => Ok(RetentionExecutionOutcome::Busy),
        ClaimReleaseGenerationRetentionOutcome::Ineligible => {
            Ok(RetentionExecutionOutcome::Ineligible)
        }
        ClaimReleaseGenerationRetentionOutcome::NotFound => Ok(RetentionExecutionOutcome::NotFound),
        ClaimReleaseGenerationRetentionOutcome::Invalid
        | ClaimReleaseGenerationRetentionOutcome::Acquired
        | ClaimReleaseGenerationRetentionOutcome::Replay => Err(RetentionPortError::Protocol),
    }
}

fn map_route_set_error(
    error: DormantRouteSetRetentionError,
) -> Result<RetentionExecutionOutcome, RetentionPortError> {
    match error {
        DormantRouteSetRetentionError::Admission(TryAdmitError::AtCapacity) => {
            Err(RetentionPortError::AtCapacity)
        }
        DormantRouteSetRetentionError::Admission(TryAdmitError::InternalKind) => {
            Err(RetentionPortError::Protocol)
        }
        DormantRouteSetRetentionError::Admission(_)
        | DormantRouteSetRetentionError::Supervisor(_)
        | DormantRouteSetRetentionError::Effect(_) => Err(RetentionPortError::Transient),
    }
}

fn map_release_error(
    error: DormantReleaseGenerationRetentionError,
) -> Result<RetentionExecutionOutcome, RetentionPortError> {
    match error {
        DormantReleaseGenerationRetentionError::Admission(TryAdmitError::AtCapacity) => {
            Err(RetentionPortError::AtCapacity)
        }
        DormantReleaseGenerationRetentionError::Admission(TryAdmitError::InternalKind) => {
            Err(RetentionPortError::Protocol)
        }
        DormantReleaseGenerationRetentionError::Admission(_)
        | DormantReleaseGenerationRetentionError::Supervisor(_)
        | DormantReleaseGenerationRetentionError::Effect(_) => Err(RetentionPortError::Transient),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct RetentionSchedulerConfig {
    page_size: usize,
    max_epoch_items: usize,
    idle_delay: Duration,
    contention_delay: Duration,
    capacity_delay: Duration,
    error_initial_delay: Duration,
    error_max_delay: Duration,
    jitter_basis_points: u16,
}

impl RetentionSchedulerConfig {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        page_size: usize,
        max_epoch_items: usize,
        idle_delay: Duration,
        contention_delay: Duration,
        capacity_delay: Duration,
        error_initial_delay: Duration,
        error_max_delay: Duration,
        jitter_basis_points: u16,
    ) -> Result<Self, InvalidRetentionSchedulerConfig> {
        let config = Self {
            page_size,
            max_epoch_items,
            idle_delay,
            contention_delay,
            capacity_delay,
            error_initial_delay,
            error_max_delay,
            jitter_basis_points,
        };
        if !(1..=MAX_PAGE_SIZE).contains(&config.page_size)
            || !(1..=MAX_EPOCH_ITEMS).contains(&config.max_epoch_items)
            || !valid_delay(config.idle_delay)
            || !valid_delay(config.contention_delay)
            || !valid_delay(config.capacity_delay)
            || !valid_delay(config.error_initial_delay)
            || !valid_delay(config.error_max_delay)
            || config.error_initial_delay > config.error_max_delay
            || config.jitter_basis_points > MAX_JITTER_BASIS_POINTS
        {
            return Err(InvalidRetentionSchedulerConfig);
        }
        Ok(config)
    }
}

fn valid_delay(delay: Duration) -> bool {
    !delay.is_zero() && delay <= MAX_DELAY
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct InvalidRetentionSchedulerConfig;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct RetentionSchedulerReport {
    pub epochs: u64,
    pub discovered: u64,
    pub executed: u64,
    pub refused: u64,
    pub errors: u64,
}

struct LaneState {
    cursor: Option<RetentionCursor>,
    buffered: VecDeque<RetentionCandidate>,
    exhausted: bool,
}

impl LaneState {
    fn new() -> Self {
        Self {
            cursor: None,
            buffered: VecDeque::new(),
            exhausted: false,
        }
    }

    fn reset(&mut self) {
        self.cursor = None;
        self.buffered.clear();
        self.exhausted = false;
    }
}

pub(super) struct GenerationRetentionScheduler<D, E, J> {
    discovery: D,
    execution: E,
    jitter: J,
    config: RetentionSchedulerConfig,
}

impl<D, E, J> GenerationRetentionScheduler<D, E, J>
where
    D: RetentionDiscoveryPort,
    E: RetentionExecutionPort,
    J: JitterSource,
{
    /// Pure construction: no timer, task, database query, or filesystem action.
    pub(super) fn new(
        discovery: D,
        execution: E,
        jitter: J,
        config: RetentionSchedulerConfig,
    ) -> Self {
        Self {
            discovery,
            execution,
            jitter,
            config,
        }
    }

    /// Explicit dormant entrypoint. Work is strictly sequential: the scheduler
    /// never has more than one discovery or retention execution in flight.
    #[tracing::instrument(
        name = "deployment_driver.generation_retention_scheduler.run_dormant",
        skip_all,
        fields(scheduler.outcome = "running")
    )]
    pub(super) async fn run(&mut self, stop: &mut dyn StopSignal) -> RetentionSchedulerReport {
        let mut report = RetentionSchedulerReport::default();
        let mut universal = LaneState::new();
        let mut release = LaneState::new();
        let mut next_lane = RetentionLane::Universal;
        let mut next_epoch_first = RetentionLane::Release;
        let mut epoch_items = 0_usize;
        let mut consecutive_errors = 0_u32;

        loop {
            if stop.is_stopping() {
                return report;
            }
            if epoch_items >= self.config.max_epoch_items
                || (universal.exhausted && release.exhausted)
            {
                report.epochs = report.epochs.saturating_add(1);
                universal.reset();
                release.reset();
                epoch_items = 0;
                next_lane = next_epoch_first;
                next_epoch_first = next_epoch_first.other();
                if self.sleep(stop, self.config.idle_delay).await.is_stopping() {
                    return report;
                }
                continue;
            }

            let lane = choose_lane(next_lane, &universal, &release);
            next_lane = lane.other();
            let state = match lane {
                RetentionLane::Universal => &mut universal,
                RetentionLane::Release => &mut release,
            };
            if state.buffered.is_empty() && !state.exhausted {
                match self
                    .discovery
                    .discover(lane, state.cursor.as_ref(), self.config.page_size)
                    .await
                {
                    Ok(page) => {
                        if validate_page(lane, state.cursor.as_ref(), &page, self.config.page_size)
                            .is_err()
                        {
                            tracing::warn!(
                                scheduler.lane = lane.as_str(),
                                error_class = "retention_discovery_protocol",
                                "generation retention discovery page was rejected"
                            );
                            report.errors = report.errors.saturating_add(1);
                            consecutive_errors = consecutive_errors.saturating_add(1);
                            let delay = self.error_delay(consecutive_errors);
                            if self.sleep(stop, delay).await.is_stopping() {
                                return report;
                            }
                            continue;
                        }
                        consecutive_errors = 0;
                        report.discovered = report
                            .discovered
                            .saturating_add(u64::try_from(page.len()).unwrap_or(u64::MAX));
                        if page.is_empty() {
                            state.exhausted = true;
                            continue;
                        }
                        state.buffered.extend(page);
                    }
                    Err(RetentionPortError::AtCapacity) => {
                        tracing::debug!(
                            scheduler.lane = lane.as_str(),
                            scheduler.outcome = "capacity",
                            "generation retention discovery deferred"
                        );
                        if self
                            .sleep(stop, self.config.capacity_delay)
                            .await
                            .is_stopping()
                        {
                            return report;
                        }
                        continue;
                    }
                    Err(RetentionPortError::Transient | RetentionPortError::Protocol) => {
                        tracing::warn!(
                            scheduler.lane = lane.as_str(),
                            error_class = "retention_discovery_failed",
                            "generation retention discovery failed"
                        );
                        report.errors = report.errors.saturating_add(1);
                        consecutive_errors = consecutive_errors.saturating_add(1);
                        let delay = self.error_delay(consecutive_errors);
                        if self.sleep(stop, delay).await.is_stopping() {
                            return report;
                        }
                        continue;
                    }
                }
            }

            let Some(candidate) = state.buffered.pop_front() else {
                continue;
            };
            if stop.is_stopping() {
                state.buffered.push_front(candidate);
                return report;
            }
            let retained_candidate = candidate.clone();
            match self.execution.execute(candidate).await {
                Ok(RetentionExecutionOutcome::Completed | RetentionExecutionOutcome::Replay) => {
                    state.cursor = Some(retained_candidate.key);
                    epoch_items = epoch_items.saturating_add(1);
                    report.executed = report.executed.saturating_add(1);
                    consecutive_errors = 0;
                    tracing::debug!(
                        scheduler.lane = lane.as_str(),
                        scheduler.outcome = "completed",
                        "generation retention candidate completed"
                    );
                }
                Ok(
                    RetentionExecutionOutcome::Busy
                    | RetentionExecutionOutcome::Ineligible
                    | RetentionExecutionOutcome::NotFound,
                ) => {
                    state.cursor = Some(retained_candidate.key);
                    epoch_items = epoch_items.saturating_add(1);
                    report.refused = report.refused.saturating_add(1);
                    consecutive_errors = 0;
                    tracing::debug!(
                        scheduler.lane = lane.as_str(),
                        scheduler.outcome = "refused",
                        "generation retention candidate was refused"
                    );
                    if self
                        .sleep(stop, self.config.contention_delay)
                        .await
                        .is_stopping()
                    {
                        return report;
                    }
                }
                Err(RetentionPortError::AtCapacity) => {
                    state.buffered.push_front(retained_candidate);
                    tracing::debug!(
                        scheduler.lane = lane.as_str(),
                        scheduler.outcome = "capacity",
                        "generation retention execution deferred"
                    );
                    if self
                        .sleep(stop, self.config.capacity_delay)
                        .await
                        .is_stopping()
                    {
                        return report;
                    }
                }
                Err(RetentionPortError::Transient | RetentionPortError::Protocol) => {
                    state.buffered.push_front(retained_candidate);
                    report.errors = report.errors.saturating_add(1);
                    consecutive_errors = consecutive_errors.saturating_add(1);
                    tracing::warn!(
                        scheduler.lane = lane.as_str(),
                        error_class = "retention_execution_failed",
                        "generation retention execution failed"
                    );
                    let delay = self.error_delay(consecutive_errors);
                    if self.sleep(stop, delay).await.is_stopping() {
                        return report;
                    }
                }
            }
        }
    }

    fn error_delay(&mut self, attempt: u32) -> Duration {
        let exponent = attempt.saturating_sub(1).min(31);
        let multiplier = 1_u32 << exponent;
        self.config
            .error_initial_delay
            .saturating_mul(multiplier)
            .min(self.config.error_max_delay)
    }

    async fn sleep(&mut self, stop: &mut dyn StopSignal, base: Duration) -> StopAwareSleep {
        let lower = scale_duration(base, 10_000 - self.config.jitter_basis_points);
        let upper = scale_duration(base, 10_000 + self.config.jitter_basis_points);
        let proposed = self.jitter.jitter(base, self.config.jitter_basis_points);
        let delay = proposed.clamp(lower, upper);
        tracing::debug!(
            scheduler.delay_bucket = delay_bucket(delay),
            "generation retention scheduler waiting"
        );
        stop.sleep_or_stop(delay).await
    }
}

/// Explicit activation seam. It is intentionally uncalled: registering the
/// module compiles and tests the lifecycle contract without starting polling.
pub(super) fn start_generation_retention_scheduler_dormant<D, E, J>(
    supervisor: &DriverTaskSupervisorHandle,
    mut scheduler: GenerationRetentionScheduler<D, E, J>,
) -> Result<DriverTaskReceipt<()>, TryServiceError>
where
    D: RetentionDiscoveryPort + 'static,
    E: RetentionExecutionPort + 'static,
    J: JitterSource + 'static,
{
    supervisor.try_spawn_service(
        DriverTaskKind::GenerationRetentionScheduler,
        move |mut stop| async move {
            let _report = scheduler.run(&mut stop).await;
            Ok::<_, DriverTaskFailure>(())
        },
    )
}

impl StopAwareSleep {
    const fn is_stopping(self) -> bool {
        matches!(self, Self::StopRequested)
    }
}

fn choose_lane(next: RetentionLane, universal: &LaneState, release: &LaneState) -> RetentionLane {
    match next {
        RetentionLane::Universal if universal.exhausted => RetentionLane::Release,
        RetentionLane::Release if release.exhausted => RetentionLane::Universal,
        lane => lane,
    }
}

fn validate_page(
    lane: RetentionLane,
    after: Option<&RetentionCursor>,
    page: &[RetentionCandidate],
    limit: usize,
) -> Result<(), RetentionPortError> {
    if page.len() > limit {
        return Err(RetentionPortError::Protocol);
    }
    let mut previous = after;
    for candidate in page {
        if candidate.key.lane() != lane || !candidate.key.strictly_after(previous) {
            return Err(RetentionPortError::Protocol);
        }
        previous = Some(&candidate.key);
    }
    Ok(())
}

fn scale_duration(duration: Duration, basis_points: u16) -> Duration {
    let nanos = duration.as_nanos();
    let scaled = nanos
        .saturating_mul(u128::from(basis_points))
        .checked_div(10_000)
        .unwrap_or(u128::MAX)
        .min(u128::from(u64::MAX));
    Duration::from_nanos(u64::try_from(scaled).unwrap_or(u64::MAX))
}

fn delay_bucket(delay: Duration) -> &'static str {
    match delay.as_secs() {
        0 => "subsecond",
        1..=9 => "seconds",
        10..=59 => "under_minute",
        60..=599 => "minutes",
        _ => "long",
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::docker_driver::task_supervisor::{
        DriverTaskSupervisorConfig, new_driver_task_supervisor,
    };

    type DiscoveryReply = Result<Vec<RetentionCandidate>, RetentionPortError>;
    type ExecutionReply = Result<RetentionExecutionOutcome, RetentionPortError>;

    #[derive(Clone)]
    struct FakeDiscovery {
        calls: Arc<Mutex<Vec<RetentionLane>>>,
        replies: Arc<Mutex<VecDeque<DiscoveryReply>>>,
    }

    #[async_trait]
    impl RetentionDiscoveryPort for FakeDiscovery {
        async fn discover(
            &self,
            lane: RetentionLane,
            _after: Option<&RetentionCursor>,
            _limit: usize,
        ) -> Result<Vec<RetentionCandidate>, RetentionPortError> {
            self.calls.lock().unwrap().push(lane);
            self.replies
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(Ok(vec![]))
        }
    }

    #[derive(Clone)]
    struct FakeExecution {
        active: Arc<std::sync::atomic::AtomicUsize>,
        maximum: Arc<std::sync::atomic::AtomicUsize>,
        keys: Arc<Mutex<Vec<RetentionCursor>>>,
        replies: Arc<Mutex<VecDeque<ExecutionReply>>>,
    }

    #[async_trait]
    impl RetentionExecutionPort for FakeExecution {
        async fn execute(
            &self,
            candidate: RetentionCandidate,
        ) -> Result<RetentionExecutionOutcome, RetentionPortError> {
            let active = self
                .active
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                + 1;
            self.maximum
                .fetch_max(active, std::sync::atomic::Ordering::SeqCst);
            self.keys.lock().unwrap().push(candidate.key);
            self.active
                .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            self.replies
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(Ok(RetentionExecutionOutcome::Completed))
        }
    }

    struct FakeStop {
        sleeps: Vec<Duration>,
        stop_after_sleeps: usize,
        stopping: bool,
    }

    #[async_trait]
    impl StopSignal for FakeStop {
        fn is_stopping(&self) -> bool {
            self.stopping
        }

        async fn sleep_or_stop(&mut self, duration: Duration) -> StopAwareSleep {
            self.sleeps.push(duration);
            if self.sleeps.len() >= self.stop_after_sleeps {
                self.stopping = true;
                StopAwareSleep::StopRequested
            } else {
                StopAwareSleep::Elapsed
            }
        }
    }

    struct ExactJitter;

    impl JitterSource for ExactJitter {
        fn jitter(&mut self, base: Duration, _basis_points: u16) -> Duration {
            base
        }
    }

    fn config() -> RetentionSchedulerConfig {
        RetentionSchedulerConfig::new(
            2,
            10,
            Duration::from_secs(30),
            Duration::from_secs(5),
            Duration::from_secs(2),
            Duration::from_secs(1),
            Duration::from_secs(8),
            1_000,
        )
        .unwrap()
    }

    fn universal(value: u128) -> RetentionCandidate {
        RetentionCandidate {
            key: RetentionCursor::Universal(Uuid::from_u128(value)),
        }
    }

    fn release(value: u128, overlay: ReleaseRetentionOverlay) -> RetentionCandidate {
        RetentionCandidate {
            key: RetentionCursor::Release {
                driver_operation_id: Uuid::from_u128(value),
                overlay,
            },
        }
    }

    fn ports(replies: Vec<DiscoveryReply>) -> (FakeDiscovery, FakeExecution) {
        (
            FakeDiscovery {
                calls: Arc::new(Mutex::new(Vec::new())),
                replies: Arc::new(Mutex::new(replies.into())),
            },
            FakeExecution {
                active: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                maximum: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                keys: Arc::new(Mutex::new(Vec::new())),
                replies: Arc::new(Mutex::new(VecDeque::new())),
            },
        )
    }

    #[test]
    fn configuration_is_closed_and_constructor_has_no_effect() {
        assert!(
            RetentionSchedulerConfig::new(
                0,
                1,
                Duration::from_secs(1),
                Duration::from_secs(1),
                Duration::from_secs(1),
                Duration::from_secs(1),
                Duration::from_secs(1),
                0,
            )
            .is_err()
        );
        assert!(
            RetentionSchedulerConfig::new(
                1,
                1,
                Duration::ZERO,
                Duration::from_secs(1),
                Duration::from_secs(1),
                Duration::from_secs(1),
                Duration::from_secs(1),
                0,
            )
            .is_err()
        );
        let (discovery, execution) = ports(vec![]);
        let calls = discovery.calls.clone();
        let keys = execution.keys.clone();
        let _scheduler =
            GenerationRetentionScheduler::new(discovery, execution, ExactJitter, config());
        assert!(calls.lock().unwrap().is_empty());
        assert!(keys.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn scans_lanes_round_robin_and_never_executes_concurrently() {
        let (discovery, execution) = ports(vec![
            Ok(vec![universal(1), universal(2)]),
            Ok(vec![release(3, ReleaseRetentionOverlay::Candidate)]),
            Ok(vec![]),
            Ok(vec![]),
        ]);
        let calls = discovery.calls.clone();
        let keys = execution.keys.clone();
        let maximum = execution.maximum.clone();
        let mut scheduler =
            GenerationRetentionScheduler::new(discovery, execution, ExactJitter, config());
        let mut stop = FakeStop {
            sleeps: vec![],
            stop_after_sleeps: 1,
            stopping: false,
        };
        let report = scheduler.run(&mut stop).await;
        assert_eq!(report.executed, 3);
        assert_eq!(maximum.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(
            *keys.lock().unwrap(),
            vec![
                RetentionCursor::Universal(Uuid::from_u128(1)),
                RetentionCursor::Release {
                    driver_operation_id: Uuid::from_u128(3),
                    overlay: ReleaseRetentionOverlay::Candidate,
                },
                RetentionCursor::Universal(Uuid::from_u128(2)),
            ]
        );
        assert_eq!(
            &calls.lock().unwrap()[..2],
            &[RetentionLane::Universal, RetentionLane::Release]
        );
    }

    #[tokio::test]
    async fn supervisor_service_owns_scheduler_and_wakes_it_for_drain() {
        let (discovery, execution) = ports(vec![Ok(vec![]), Ok(vec![])]);
        let calls = discovery.calls.clone();
        let scheduler =
            GenerationRetentionScheduler::new(discovery, execution, ExactJitter, config());
        let (supervisor, lifecycle) = new_driver_task_supervisor(DriverTaskSupervisorConfig {
            admitted_capacity: 1,
        })
        .unwrap();
        let receipt = start_generation_retention_scheduler_dormant(&supervisor, scheduler).unwrap();
        for _ in 0..1_000 {
            if calls.lock().unwrap().len() >= 2 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(calls.lock().unwrap().len(), 2);
        assert_eq!(supervisor.snapshot().admitted_available, 1);
        assert_eq!(supervisor.snapshot().service_active, 1);
        let snapshot = lifecycle.drain().await.unwrap();
        receipt.wait().await.unwrap();
        assert_eq!(snapshot.service_active, 0);
        assert_eq!(snapshot.cancelled, 0);
    }

    #[tokio::test]
    async fn malformed_page_backs_off_without_execution() {
        let (discovery, execution) = ports(vec![Ok(vec![universal(2), universal(1)])]);
        let keys = execution.keys.clone();
        let mut scheduler =
            GenerationRetentionScheduler::new(discovery, execution, ExactJitter, config());
        let mut stop = FakeStop {
            sleeps: vec![],
            stop_after_sleeps: 1,
            stopping: false,
        };
        let report = scheduler.run(&mut stop).await;
        assert_eq!(report.errors, 1);
        assert!(keys.lock().unwrap().is_empty());
        assert_eq!(stop.sleeps, vec![Duration::from_secs(1)]);
    }

    #[tokio::test]
    async fn capacity_contention_and_error_delays_are_closed_and_stop_aware() {
        let (discovery, execution) = ports(vec![
            Err(RetentionPortError::AtCapacity),
            Err(RetentionPortError::Transient),
            Err(RetentionPortError::Transient),
        ]);
        let mut scheduler =
            GenerationRetentionScheduler::new(discovery, execution, ExactJitter, config());
        let mut stop = FakeStop {
            sleeps: vec![],
            stop_after_sleeps: 3,
            stopping: false,
        };
        let report = scheduler.run(&mut stop).await;
        assert_eq!(report.errors, 2);
        assert_eq!(
            stop.sleeps,
            vec![
                Duration::from_secs(2),
                Duration::from_secs(1),
                Duration::from_secs(2)
            ]
        );
    }

    #[tokio::test]
    async fn busy_is_a_refusal_and_uses_contention_not_error_backoff() {
        let (discovery, execution) = ports(vec![Ok(vec![universal(1)])]);
        execution
            .replies
            .lock()
            .unwrap()
            .push_back(Ok(RetentionExecutionOutcome::Busy));
        let mut scheduler =
            GenerationRetentionScheduler::new(discovery, execution, ExactJitter, config());
        let mut stop = FakeStop {
            sleeps: vec![],
            stop_after_sleeps: 1,
            stopping: false,
        };
        let report = scheduler.run(&mut stop).await;
        assert_eq!(report.refused, 1);
        assert_eq!(report.errors, 0);
        assert_eq!(stop.sleeps, vec![Duration::from_secs(5)]);
    }

    #[tokio::test]
    async fn capacity_rejection_retains_and_retries_the_exact_candidate() {
        let (discovery, execution) = ports(vec![Ok(vec![universal(1)]), Ok(vec![]), Ok(vec![])]);
        execution.replies.lock().unwrap().extend([
            Err(RetentionPortError::AtCapacity),
            Ok(RetentionExecutionOutcome::Completed),
        ]);
        let keys = execution.keys.clone();
        let mut scheduler =
            GenerationRetentionScheduler::new(discovery, execution, ExactJitter, config());
        let mut stop = FakeStop {
            sleeps: vec![],
            stop_after_sleeps: 2,
            stopping: false,
        };
        let report = scheduler.run(&mut stop).await;
        assert_eq!(report.executed, 1);
        assert_eq!(
            *keys.lock().unwrap(),
            vec![
                RetentionCursor::Universal(Uuid::from_u128(1)),
                RetentionCursor::Universal(Uuid::from_u128(1)),
            ]
        );
        assert_eq!(stop.sleeps[0], Duration::from_secs(2));
    }

    #[test]
    fn jitter_is_clamped_and_backoff_is_saturating() {
        struct Hostile;
        impl JitterSource for Hostile {
            fn jitter(&mut self, _base: Duration, _basis_points: u16) -> Duration {
                MAX_DELAY
            }
        }
        let (discovery, execution) = ports(vec![]);
        let mut scheduler =
            GenerationRetentionScheduler::new(discovery, execution, Hostile, config());
        assert_eq!(scheduler.error_delay(1), Duration::from_secs(1));
        assert_eq!(scheduler.error_delay(4), Duration::from_secs(8));
        assert_eq!(scheduler.error_delay(u32::MAX), Duration::from_secs(8));
        assert_eq!(
            scale_duration(Duration::from_secs(10), 11_000),
            Duration::from_secs(11)
        );
    }

    #[test]
    fn module_has_no_spawn_or_active_registration_surface() {
        let production = include_str!("generation_retention_scheduler.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        assert!(!production.contains("tokio::spawn"));
        assert!(!production.contains("build_application"));
        assert!(!production.contains("DriverState"));
        assert!(!production.contains("std::env"));
        let root = include_str!("../docker_driver.rs");
        assert_eq!(
            root.matches("mod generation_retention_scheduler;").count(),
            1
        );
        assert_eq!(root.matches("generation_retention_scheduler::").count(), 0);
        let tracing_surface = production
            .lines()
            .filter(|line| line.contains("scheduler.") || line.contains("error_class"))
            .collect::<Vec<_>>()
            .join("\n");
        for forbidden in [
            "selector",
            "digest",
            "token",
            "identity",
            "device",
            "inode",
            "raw_error",
        ] {
            assert!(!tracing_surface.contains(forbidden));
        }
    }
}
