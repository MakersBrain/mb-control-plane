//! Structured ownership for detached driver effects.
//!
//! The application lifecycle owns this supervisor even though the generation
//! publication protocols remain dormant. Its actor owns every `JoinSet`
//! handle, continuously reaps completed work, and keeps post-admission safety
//! cleanup alive while shutdown drains.
#![allow(dead_code)]

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Instant;

use tokio::sync::{Mutex, Notify, Semaphore, mpsc, oneshot, watch};
use tokio::task::{Id as TaskId, JoinHandle, JoinSet};
use tracing::Instrument as _;
use uuid::Uuid;

type BoxTask = Pin<Box<dyn Future<Output = TaskReport> + Send + 'static>>;

const ACCEPTING: u8 = 0;
const DRAINING: u8 = 1;
const STOPPED: u8 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum DriverTaskKind {
    RouteSetPublication,
    RouteSetRecovery,
    RouteSetStartup,
    RouteSetRetention,
    ReleaseOverlayPublication,
    ReleaseOverlayRecovery,
    ReleaseOverlayStartup,
    ReleaseOverlayRetention,
    GenerationRetentionScheduler,
    SafetyCleanup,
}

impl DriverTaskKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::RouteSetPublication => "route_set_publication",
            Self::RouteSetRecovery => "route_set_recovery",
            Self::RouteSetStartup => "route_set_startup",
            Self::RouteSetRetention => "route_set_retention",
            Self::ReleaseOverlayPublication => "release_overlay_publication",
            Self::ReleaseOverlayRecovery => "release_overlay_recovery",
            Self::ReleaseOverlayStartup => "release_overlay_startup",
            Self::ReleaseOverlayRetention => "release_overlay_retention",
            Self::GenerationRetentionScheduler => "generation_retention_scheduler",
            Self::SafetyCleanup => "safety_cleanup",
        }
    }

    const fn is_internal(self) -> bool {
        matches!(self, Self::SafetyCleanup)
    }

    const fn is_service(self) -> bool {
        matches!(self, Self::GenerationRetentionScheduler)
    }

    const fn service_bit(self) -> Option<u64> {
        match self {
            Self::GenerationRetentionScheduler => Some(1 << 0),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct DriverTaskMetadata {
    kind: DriverTaskKind,
    subject_id: Option<Uuid>,
}

impl DriverTaskMetadata {
    pub(super) const fn new(kind: DriverTaskKind, subject_id: Option<Uuid>) -> Self {
        Self { kind, subject_id }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct DriverTaskFailure {
    error_class: &'static str,
}

impl DriverTaskFailure {
    pub(super) fn new(error_class: &'static str) -> Result<Self, InvalidFailureClass> {
        if error_class.is_empty()
            || error_class.len() > 64
            || !error_class
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Err(InvalidFailureClass);
        }
        Ok(Self { error_class })
    }

    pub(super) const fn error_class(&self) -> &'static str {
        self.error_class
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct InvalidFailureClass;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum DriverTaskWaitError {
    Failed(DriverTaskFailure),
    SupervisorStopped,
}

pub(super) struct DriverTaskReceipt<T> {
    result: oneshot::Receiver<Result<T, DriverTaskFailure>>,
}

impl<T> DriverTaskReceipt<T> {
    pub(super) async fn wait(self) -> Result<T, DriverTaskWaitError> {
        self.result
            .await
            .map_err(|_| DriverTaskWaitError::SupervisorStopped)?
            .map_err(DriverTaskWaitError::Failed)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum TryAdmitError {
    Draining,
    AtCapacity,
    QueueClosed,
    InternalKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum TryCleanupError {
    SupervisorStopped,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum TryServiceError {
    Draining,
    AlreadyStarted,
    QueueClosed,
    NotServiceKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SupervisorState {
    Accepting,
    Draining,
    Stopped,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct DriverTaskSupervisorSnapshot {
    pub state: SupervisorState,
    pub admitted_capacity: usize,
    pub admitted_available: usize,
    pub admitted_queued: usize,
    pub internal_queued: usize,
    pub service_queued: usize,
    pub admitted_active: usize,
    pub internal_active: usize,
    pub service_active: usize,
    pub owned_capabilities: usize,
    pub completed: u64,
    pub failed: u64,
    pub panicked: u64,
    pub cancelled: u64,
}

impl DriverTaskSupervisorSnapshot {
    pub const fn active(self) -> usize {
        self.admitted_active + self.internal_active + self.service_active
    }

    pub const fn queued(self) -> usize {
        self.admitted_queued + self.internal_queued + self.service_queued
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct DriverTaskSupervisorConfig {
    pub admitted_capacity: usize,
}

impl DriverTaskSupervisorConfig {
    pub(super) fn validate(self) -> Result<Self, InvalidSupervisorConfig> {
        if self.admitted_capacity == 0 || self.admitted_capacity > 4_096 {
            return Err(InvalidSupervisorConfig);
        }
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct InvalidSupervisorConfig;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum DrainError {
    ActorStopped,
    TasksFailed {
        failed: u64,
        panicked: u64,
        cancelled: u64,
    },
}

struct Shared {
    state: AtomicU8,
    admitted_capacity: usize,
    admitted_slots: Arc<Semaphore>,
    admission_gate: StdMutex<()>,
    drain_started: Notify,
    admitted_queued: AtomicUsize,
    internal_queued: AtomicUsize,
    service_queued: AtomicUsize,
    admitted_active: AtomicUsize,
    internal_active: AtomicUsize,
    service_active: AtomicUsize,
    service_started_bits: AtomicU64,
    owned_capabilities: AtomicUsize,
    completed: AtomicU64,
    failed: AtomicU64,
    panicked: AtomicU64,
    cancelled: AtomicU64,
}

impl Shared {
    fn snapshot(&self) -> DriverTaskSupervisorSnapshot {
        DriverTaskSupervisorSnapshot {
            state: match self.state.load(Ordering::SeqCst) {
                ACCEPTING => SupervisorState::Accepting,
                DRAINING => SupervisorState::Draining,
                _ => SupervisorState::Stopped,
            },
            admitted_capacity: self.admitted_capacity,
            admitted_available: self.admitted_slots.available_permits(),
            admitted_queued: self.admitted_queued.load(Ordering::SeqCst),
            internal_queued: self.internal_queued.load(Ordering::SeqCst),
            service_queued: self.service_queued.load(Ordering::SeqCst),
            admitted_active: self.admitted_active.load(Ordering::SeqCst),
            internal_active: self.internal_active.load(Ordering::SeqCst),
            service_active: self.service_active.load(Ordering::SeqCst),
            owned_capabilities: self.owned_capabilities.load(Ordering::SeqCst),
            completed: self.completed.load(Ordering::SeqCst),
            failed: self.failed.load(Ordering::SeqCst),
            panicked: self.panicked.load(Ordering::SeqCst),
            cancelled: self.cancelled.load(Ordering::SeqCst),
        }
    }
}

struct SpawnCommand {
    metadata: TaskMetadata,
    task: BoxTask,
}

enum InternalCommand {
    Spawn(SpawnCommand),
    CapabilityDropped,
}

#[derive(Clone, Copy)]
struct TaskMetadata {
    task_id: Uuid,
    root_id: Uuid,
    kind: DriverTaskKind,
    subject_id: Option<Uuid>,
}

enum ControlCommand {
    Drain,
    #[cfg(test)]
    AbortAll,
}

#[derive(Clone)]
pub(super) struct DriverTaskSupervisorHandle {
    admitted_tx: mpsc::Sender<SpawnCommand>,
    service_tx: mpsc::UnboundedSender<SpawnCommand>,
    internal_tx: mpsc::UnboundedSender<InternalCommand>,
    shared: Arc<Shared>,
}

impl DriverTaskSupervisorHandle {
    pub(super) fn is_accepting(&self) -> bool {
        self.shared.state.load(Ordering::SeqCst) == ACCEPTING
    }

    pub(super) fn try_spawn_admitted<T, Factory, Task>(
        &self,
        metadata: DriverTaskMetadata,
        factory: Factory,
    ) -> Result<DriverTaskReceipt<T>, TryAdmitError>
    where
        T: Send + 'static,
        Factory: FnOnce(OwnedTaskCapability) -> Task,
        Task: Future<Output = Result<T, DriverTaskFailure>> + Send + 'static,
    {
        if metadata.kind.is_internal() || metadata.kind.is_service() {
            return Err(TryAdmitError::InternalKind);
        }
        let _gate = self
            .shared
            .admission_gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.shared.state.load(Ordering::SeqCst) != ACCEPTING {
            return Err(TryAdmitError::Draining);
        }
        let permit = self
            .shared
            .admitted_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| TryAdmitError::AtCapacity)?;
        let task_metadata = TaskMetadata {
            task_id: Uuid::new_v4(),
            root_id: Uuid::new_v4(),
            kind: metadata.kind,
            subject_id: metadata.subject_id,
        };
        let capability = OwnedTaskCapability::new(
            task_metadata.root_id,
            metadata.subject_id,
            self.internal_tx.clone(),
            self.shared.clone(),
        );
        let (result_tx, result_rx) = oneshot::channel();
        let task = wrap_task(task_metadata, Some(permit), factory(capability), result_tx);
        self.shared.admitted_queued.fetch_add(1, Ordering::SeqCst);
        match self.admitted_tx.try_send(SpawnCommand {
            metadata: task_metadata,
            task,
        }) {
            Ok(()) => Ok(DriverTaskReceipt { result: result_rx }),
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.shared.admitted_queued.fetch_sub(1, Ordering::SeqCst);
                Err(TryAdmitError::AtCapacity)
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.shared.admitted_queued.fetch_sub(1, Ordering::SeqCst);
                Err(TryAdmitError::QueueClosed)
            }
        }
    }

    pub(super) fn try_spawn_service<Factory, Task>(
        &self,
        kind: DriverTaskKind,
        factory: Factory,
    ) -> Result<DriverTaskReceipt<()>, TryServiceError>
    where
        Factory: FnOnce(DriverServiceStop) -> Task,
        Task: Future<Output = Result<(), DriverTaskFailure>> + Send + 'static,
    {
        let service_bit = kind.service_bit().ok_or(TryServiceError::NotServiceKind)?;
        let _gate = self
            .shared
            .admission_gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.shared.state.load(Ordering::SeqCst) != ACCEPTING {
            return Err(TryServiceError::Draining);
        }
        if self
            .shared
            .service_started_bits
            .fetch_or(service_bit, Ordering::SeqCst)
            & service_bit
            != 0
        {
            return Err(TryServiceError::AlreadyStarted);
        }
        let metadata = TaskMetadata {
            task_id: Uuid::new_v4(),
            root_id: Uuid::new_v4(),
            kind,
            subject_id: None,
        };
        let (result_tx, result_rx) = oneshot::channel();
        let shared = self.shared.clone();
        let service = factory(DriverServiceStop {
            shared: shared.clone(),
        });
        let task = wrap_task(
            metadata,
            None,
            async move {
                let result = service.await;
                if result.is_ok() && shared.state.load(Ordering::SeqCst) == ACCEPTING {
                    Err(DriverTaskFailure {
                        error_class: "driver_service_exited",
                    })
                } else {
                    result
                }
            },
            result_tx,
        );
        self.shared.service_queued.fetch_add(1, Ordering::SeqCst);
        match self.service_tx.send(SpawnCommand { metadata, task }) {
            Ok(()) => Ok(DriverTaskReceipt { result: result_rx }),
            Err(_) => {
                self.shared.service_queued.fetch_sub(1, Ordering::SeqCst);
                self.shared
                    .service_started_bits
                    .fetch_and(!service_bit, Ordering::SeqCst);
                Err(TryServiceError::QueueClosed)
            }
        }
    }

    pub(super) fn snapshot(&self) -> DriverTaskSupervisorSnapshot {
        self.shared.snapshot()
    }

    #[cfg(test)]
    fn abort_all_for_test(&self, control_tx: &mpsc::UnboundedSender<ControlCommand>) {
        let _ = control_tx.send(ControlCommand::AbortAll);
    }
}

#[derive(Clone)]
pub(super) struct DriverServiceStop {
    shared: Arc<Shared>,
}

impl DriverServiceStop {
    pub(super) fn is_requested(&self) -> bool {
        self.shared.state.load(Ordering::SeqCst) != ACCEPTING
    }

    pub(super) async fn requested(&self) {
        loop {
            let notified = self.shared.drain_started.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.is_requested() {
                return;
            }
            notified.await;
        }
    }
}

pub(super) struct OwnedTaskCapability {
    root_id: Uuid,
    subject_id: Option<Uuid>,
    internal_tx: mpsc::UnboundedSender<InternalCommand>,
    shared: Arc<Shared>,
}

impl OwnedTaskCapability {
    fn new(
        root_id: Uuid,
        subject_id: Option<Uuid>,
        internal_tx: mpsc::UnboundedSender<InternalCommand>,
        shared: Arc<Shared>,
    ) -> Self {
        shared.owned_capabilities.fetch_add(1, Ordering::SeqCst);
        Self {
            root_id,
            subject_id,
            internal_tx,
            shared,
        }
    }

    pub(super) fn try_spawn_cleanup<T, Factory, Task>(
        &self,
        factory: Factory,
    ) -> Result<DriverTaskReceipt<T>, TryCleanupError>
    where
        T: Send + 'static,
        Factory: FnOnce(OwnedTaskCapability) -> Task,
        Task: Future<Output = Result<T, DriverTaskFailure>> + Send + 'static,
    {
        if self.shared.state.load(Ordering::SeqCst) == STOPPED {
            return Err(TryCleanupError::SupervisorStopped);
        }
        let metadata = TaskMetadata {
            task_id: Uuid::new_v4(),
            root_id: self.root_id,
            kind: DriverTaskKind::SafetyCleanup,
            subject_id: self.subject_id,
        };
        let child_capability = Self::new(
            self.root_id,
            self.subject_id,
            self.internal_tx.clone(),
            self.shared.clone(),
        );
        let (result_tx, result_rx) = oneshot::channel();
        let task = wrap_task(metadata, None, factory(child_capability), result_tx);
        self.shared.internal_queued.fetch_add(1, Ordering::SeqCst);
        if self
            .internal_tx
            .send(InternalCommand::Spawn(SpawnCommand { metadata, task }))
            .is_err()
        {
            self.shared.internal_queued.fetch_sub(1, Ordering::SeqCst);
            return Err(TryCleanupError::SupervisorStopped);
        }
        Ok(DriverTaskReceipt { result: result_rx })
    }

    pub(super) fn is_draining(&self) -> bool {
        self.shared.state.load(Ordering::SeqCst) != ACCEPTING
    }

    pub(super) async fn wait_for_drain(&self) {
        loop {
            let notified = self.shared.drain_started.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.is_draining() {
                return;
            }
            notified.await;
        }
    }
}

impl Drop for OwnedTaskCapability {
    fn drop(&mut self) {
        self.shared
            .owned_capabilities
            .fetch_sub(1, Ordering::SeqCst);
        let _ = self.internal_tx.send(InternalCommand::CapabilityDropped);
    }
}

pub(super) struct DriverTaskSupervisorLifecycle {
    control_tx: mpsc::UnboundedSender<ControlCommand>,
    stopped: watch::Receiver<SupervisorState>,
    actor: Mutex<Option<JoinHandle<()>>>,
    shared: Arc<Shared>,
    drained: std::sync::atomic::AtomicBool,
}

impl DriverTaskSupervisorLifecycle {
    pub(super) fn is_accepting(&self) -> bool {
        self.shared.state.load(Ordering::SeqCst) == ACCEPTING
    }

    pub(super) fn begin_draining(&self) {
        let _gate = self
            .shared
            .admission_gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self
            .shared
            .state
            .compare_exchange(ACCEPTING, DRAINING, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            self.shared.drain_started.notify_waiters();
            let _ = self.control_tx.send(ControlCommand::Drain);
        }
        self.drained.store(true, Ordering::SeqCst);
    }

    pub(super) async fn drain(&self) -> Result<DriverTaskSupervisorSnapshot, DrainError> {
        self.begin_draining();
        if self.shared.state.load(Ordering::SeqCst) == STOPPED {
            return drain_result(self.shared.snapshot());
        }

        if let Some(actor) = self.actor.lock().await.take() {
            if actor.await.is_err() {
                self.shared.state.store(STOPPED, Ordering::SeqCst);
                tracing::error!(
                    error_class = "driver_task_supervisor_actor",
                    "driver task supervisor actor stopped unexpectedly"
                );
                return Err(DrainError::ActorStopped);
            }
        } else {
            let mut stopped = self.stopped.clone();
            while *stopped.borrow_and_update() != SupervisorState::Stopped {
                stopped
                    .changed()
                    .await
                    .map_err(|_| DrainError::ActorStopped)?;
            }
        }
        drain_result(self.shared.snapshot())
    }

    pub(super) fn snapshot(&self) -> DriverTaskSupervisorSnapshot {
        self.shared.snapshot()
    }
}

fn drain_result(
    snapshot: DriverTaskSupervisorSnapshot,
) -> Result<DriverTaskSupervisorSnapshot, DrainError> {
    if snapshot.failed != 0 || snapshot.panicked != 0 || snapshot.cancelled != 0 {
        Err(DrainError::TasksFailed {
            failed: snapshot.failed,
            panicked: snapshot.panicked,
            cancelled: snapshot.cancelled,
        })
    } else {
        Ok(snapshot)
    }
}

impl Drop for DriverTaskSupervisorLifecycle {
    fn drop(&mut self) {
        if !self.drained.swap(true, Ordering::SeqCst) {
            tracing::error!(
                error_class = "driver_task_supervisor_undrained",
                "driver task supervisor lifecycle was dropped before drain"
            );
            self.begin_draining();
        }
    }
}

pub(super) fn new_driver_task_supervisor(
    config: DriverTaskSupervisorConfig,
) -> Result<(DriverTaskSupervisorHandle, DriverTaskSupervisorLifecycle), InvalidSupervisorConfig> {
    let config = config.validate()?;
    let shared = Arc::new(Shared {
        state: AtomicU8::new(ACCEPTING),
        admitted_capacity: config.admitted_capacity,
        admitted_slots: Arc::new(Semaphore::new(config.admitted_capacity)),
        admission_gate: StdMutex::new(()),
        drain_started: Notify::new(),
        admitted_queued: AtomicUsize::new(0),
        internal_queued: AtomicUsize::new(0),
        service_queued: AtomicUsize::new(0),
        admitted_active: AtomicUsize::new(0),
        internal_active: AtomicUsize::new(0),
        service_active: AtomicUsize::new(0),
        service_started_bits: AtomicU64::new(0),
        owned_capabilities: AtomicUsize::new(0),
        completed: AtomicU64::new(0),
        failed: AtomicU64::new(0),
        panicked: AtomicU64::new(0),
        cancelled: AtomicU64::new(0),
    });
    let (admitted_tx, admitted_rx) = mpsc::channel(config.admitted_capacity);
    // The closed service-kind enum plus one bit per kind is the bound here.
    let (service_tx, service_rx) = mpsc::unbounded_channel();
    let (internal_tx, internal_rx) = mpsc::unbounded_channel();
    let (control_tx, control_rx) = mpsc::unbounded_channel();
    let (stopped_tx, stopped) = watch::channel(SupervisorState::Accepting);
    let actor_shared = shared.clone();
    let actor = tokio::spawn(async move {
        run_actor(
            actor_shared,
            admitted_rx,
            service_rx,
            internal_rx,
            control_rx,
            stopped_tx,
        )
        .await;
    });
    Ok((
        DriverTaskSupervisorHandle {
            admitted_tx,
            service_tx,
            internal_tx,
            shared: shared.clone(),
        },
        DriverTaskSupervisorLifecycle {
            control_tx,
            stopped,
            actor: Mutex::new(Some(actor)),
            shared,
            drained: std::sync::atomic::AtomicBool::new(false),
        },
    ))
}

fn wrap_task<T, Task>(
    metadata: TaskMetadata,
    permit: Option<tokio::sync::OwnedSemaphorePermit>,
    task: Task,
    result_tx: oneshot::Sender<Result<T, DriverTaskFailure>>,
) -> BoxTask
where
    T: Send + 'static,
    Task: Future<Output = Result<T, DriverTaskFailure>> + Send + 'static,
{
    let span = tracing::info_span!(
        "deployment_driver.supervised_task",
        task.id = %metadata.task_id,
        task.root_id = %metadata.root_id,
        task.kind = metadata.kind.as_str(),
        subject.id = ?metadata.subject_id,
        task.outcome = "in_progress"
    );
    Box::pin(
        async move {
            let _permit = permit;
            let started = Instant::now();
            match task.await {
                Ok(value) => {
                    tracing::Span::current().record("task.outcome", "completed");
                    let _ = result_tx.send(Ok(value));
                    TaskReport {
                        outcome: TaskOutcome::Completed,
                        elapsed_millis: elapsed_millis(started),
                    }
                }
                Err(failure) => {
                    tracing::Span::current().record("task.outcome", "failed");
                    let _ = result_tx.send(Err(failure.clone()));
                    TaskReport {
                        outcome: TaskOutcome::Failed(failure),
                        elapsed_millis: elapsed_millis(started),
                    }
                }
            }
        }
        .instrument(span),
    )
}

fn elapsed_millis(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

struct TaskReport {
    outcome: TaskOutcome,
    elapsed_millis: u64,
}

enum TaskOutcome {
    Completed,
    Failed(DriverTaskFailure),
}

async fn run_actor(
    shared: Arc<Shared>,
    mut admitted_rx: mpsc::Receiver<SpawnCommand>,
    mut service_rx: mpsc::UnboundedReceiver<SpawnCommand>,
    mut internal_rx: mpsc::UnboundedReceiver<InternalCommand>,
    mut control_rx: mpsc::UnboundedReceiver<ControlCommand>,
    stopped_tx: watch::Sender<SupervisorState>,
) {
    let mut tasks = JoinSet::new();
    let mut metadata = HashMap::<TaskId, TaskMetadata>::new();
    let mut draining = false;
    let mut control_open = true;
    let mut internal_open = true;
    let mut admitted_open = true;
    let mut service_open = true;
    loop {
        if draining && tasks.is_empty() {
            drain_ready_commands(
                &shared,
                &mut admitted_rx,
                &mut service_rx,
                &mut internal_rx,
                &mut tasks,
                &mut metadata,
            );
            if tasks.is_empty()
                && shared.admitted_queued.load(Ordering::SeqCst) == 0
                && shared.internal_queued.load(Ordering::SeqCst) == 0
                && shared.service_queued.load(Ordering::SeqCst) == 0
                && shared.owned_capabilities.load(Ordering::SeqCst) == 0
            {
                break;
            }
        }
        tokio::select! {
            biased;
            command = control_rx.recv(), if control_open => match command {
                Some(ControlCommand::Drain) => {
                    draining = true;
                    shared.state.store(DRAINING, Ordering::SeqCst);
                    let _ = stopped_tx.send(SupervisorState::Draining);
                }
                #[cfg(test)]
                Some(ControlCommand::AbortAll) => tasks.abort_all(),
                None => control_open = false,
            },
            command = internal_rx.recv(), if internal_open => {
                match command {
                    Some(InternalCommand::Spawn(command)) => {
                        shared.internal_queued.fetch_sub(1, Ordering::SeqCst);
                        spawn_joined(&shared, &mut tasks, &mut metadata, command);
                    }
                    Some(InternalCommand::CapabilityDropped) => {}
                    None => internal_open = false,
                }
            },
            command = admitted_rx.recv(), if admitted_open => {
                if let Some(command) = command {
                    shared.admitted_queued.fetch_sub(1, Ordering::SeqCst);
                    spawn_joined(&shared, &mut tasks, &mut metadata, command);
                } else {
                    admitted_open = false;
                }
            },
            command = service_rx.recv(), if service_open => {
                if let Some(command) = command {
                    shared.service_queued.fetch_sub(1, Ordering::SeqCst);
                    spawn_joined(&shared, &mut tasks, &mut metadata, command);
                } else {
                    service_open = false;
                }
            },
            joined = tasks.join_next_with_id(), if !tasks.is_empty() => {
                if let Some(joined) = joined
                    && reap_joined(&shared, &mut metadata, joined)
                {
                        let _gate = shared
                            .admission_gate
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        if shared
                            .state
                            .compare_exchange(
                                ACCEPTING,
                                DRAINING,
                                Ordering::SeqCst,
                                Ordering::SeqCst,
                            )
                            .is_ok()
                        {
                            shared.drain_started.notify_waiters();
                            let _ = stopped_tx.send(SupervisorState::Draining);
                        }
                    draining = true;
                }
            },
        }
    }
    shared.state.store(STOPPED, Ordering::SeqCst);
    let _ = stopped_tx.send(SupervisorState::Stopped);
    tracing::info!(
        task.completed = shared.completed.load(Ordering::SeqCst),
        task.failed = shared.failed.load(Ordering::SeqCst),
        task.panicked = shared.panicked.load(Ordering::SeqCst),
        task.cancelled = shared.cancelled.load(Ordering::SeqCst),
        "driver task supervisor drained"
    );
}

fn drain_ready_commands(
    shared: &Shared,
    admitted_rx: &mut mpsc::Receiver<SpawnCommand>,
    service_rx: &mut mpsc::UnboundedReceiver<SpawnCommand>,
    internal_rx: &mut mpsc::UnboundedReceiver<InternalCommand>,
    tasks: &mut JoinSet<TaskReport>,
    metadata: &mut HashMap<TaskId, TaskMetadata>,
) {
    while let Ok(command) = admitted_rx.try_recv() {
        shared.admitted_queued.fetch_sub(1, Ordering::SeqCst);
        spawn_joined(shared, tasks, metadata, command);
    }
    while let Ok(command) = service_rx.try_recv() {
        shared.service_queued.fetch_sub(1, Ordering::SeqCst);
        spawn_joined(shared, tasks, metadata, command);
    }
    while let Ok(command) = internal_rx.try_recv() {
        if let InternalCommand::Spawn(command) = command {
            shared.internal_queued.fetch_sub(1, Ordering::SeqCst);
            spawn_joined(shared, tasks, metadata, command);
        }
    }
}

fn spawn_joined(
    shared: &Shared,
    tasks: &mut JoinSet<TaskReport>,
    metadata_by_id: &mut HashMap<TaskId, TaskMetadata>,
    command: SpawnCommand,
) {
    if command.metadata.kind.is_internal() {
        shared.internal_active.fetch_add(1, Ordering::SeqCst);
    } else if command.metadata.kind.is_service() {
        shared.service_active.fetch_add(1, Ordering::SeqCst);
    } else {
        shared.admitted_active.fetch_add(1, Ordering::SeqCst);
    }
    let abort = tasks.spawn(command.task);
    metadata_by_id.insert(abort.id(), command.metadata);
}

fn reap_joined(
    shared: &Shared,
    metadata_by_id: &mut HashMap<TaskId, TaskMetadata>,
    joined: Result<(TaskId, TaskReport), tokio::task::JoinError>,
) -> bool {
    match joined {
        Ok((task_id, report)) => {
            let Some(metadata) = metadata_by_id.remove(&task_id) else {
                tracing::error!(
                    error_class = "driver_task_metadata_missing",
                    "supervised driver task metadata was absent"
                );
                return false;
            };
            decrement_active(shared, metadata.kind);
            let service_exited_while_accepting =
                metadata.kind.is_service() && shared.state.load(Ordering::SeqCst) == ACCEPTING;
            match report.outcome {
                TaskOutcome::Completed => {
                    shared.completed.fetch_add(1, Ordering::SeqCst);
                    tracing::debug!(
                        task.id = %metadata.task_id,
                        task.root_id = %metadata.root_id,
                        task.kind = metadata.kind.as_str(),
                        subject.id = ?metadata.subject_id,
                        task.elapsed_ms = report.elapsed_millis,
                        "supervised driver task completed"
                    );
                }
                TaskOutcome::Failed(failure) => {
                    shared.failed.fetch_add(1, Ordering::SeqCst);
                    tracing::error!(
                        task.id = %metadata.task_id,
                        task.root_id = %metadata.root_id,
                        task.kind = metadata.kind.as_str(),
                        subject.id = ?metadata.subject_id,
                        task.elapsed_ms = report.elapsed_millis,
                        error_class = failure.error_class(),
                        "supervised driver task failed"
                    );
                }
            }
            service_exited_while_accepting
        }
        Err(join_error) => {
            let task_id = join_error.id();
            let metadata = metadata_by_id.remove(&task_id);
            if let Some(metadata) = metadata {
                let service_exited_while_accepting =
                    metadata.kind.is_service() && shared.state.load(Ordering::SeqCst) == ACCEPTING;
                decrement_active(shared, metadata.kind);
                if join_error.is_cancelled() {
                    shared.cancelled.fetch_add(1, Ordering::SeqCst);
                    tracing::error!(
                        task.id = %metadata.task_id,
                        task.root_id = %metadata.root_id,
                        task.kind = metadata.kind.as_str(),
                        subject.id = ?metadata.subject_id,
                        error_class = "driver_task_cancelled",
                        "supervised driver task was cancelled"
                    );
                } else {
                    shared.panicked.fetch_add(1, Ordering::SeqCst);
                    tracing::error!(
                        task.id = %metadata.task_id,
                        task.root_id = %metadata.root_id,
                        task.kind = metadata.kind.as_str(),
                        subject.id = ?metadata.subject_id,
                        error_class = "driver_task_panicked",
                        "supervised driver task panicked"
                    );
                }
                service_exited_while_accepting
            } else {
                tracing::error!(
                    error_class = "driver_task_metadata_missing",
                    "failed supervised driver task metadata was absent"
                );
                false
            }
        }
    }
}

fn decrement_active(shared: &Shared, kind: DriverTaskKind) {
    if kind.is_internal() {
        shared.internal_active.fetch_sub(1, Ordering::SeqCst);
    } else if kind.is_service() {
        shared.service_active.fetch_sub(1, Ordering::SeqCst);
    } else {
        shared.admitted_active.fetch_sub(1, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize};

    use super::*;

    fn supervisor(
        capacity: usize,
    ) -> (
        DriverTaskSupervisorHandle,
        Arc<DriverTaskSupervisorLifecycle>,
    ) {
        let (handle, lifecycle) = new_driver_task_supervisor(DriverTaskSupervisorConfig {
            admitted_capacity: capacity,
        })
        .unwrap();
        (handle, Arc::new(lifecycle))
    }

    async fn wait_until(mut predicate: impl FnMut() -> bool) {
        for _ in 0..1_000 {
            if predicate() {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!("condition did not become true");
    }

    #[test]
    fn configuration_and_failure_classes_are_closed_and_safe() {
        assert!(
            DriverTaskSupervisorConfig {
                admitted_capacity: 0
            }
            .validate()
            .is_err()
        );
        assert!(
            DriverTaskSupervisorConfig {
                admitted_capacity: 4_097
            }
            .validate()
            .is_err()
        );
        assert!(DriverTaskFailure::new("database_unavailable").is_ok());
        for invalid in ["", "Raw Error", "secret=value", "UPPER", "slash/error"] {
            assert!(DriverTaskFailure::new(invalid).is_err());
        }
    }

    #[tokio::test]
    async fn admitted_capacity_bounds_queued_plus_active_and_reaps_continuously() {
        let (handle, lifecycle) = supervisor(1);
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let task_entered = entered.clone();
        let task_release = release.clone();
        let receipt = handle
            .try_spawn_admitted(
                DriverTaskMetadata::new(DriverTaskKind::RouteSetPublication, Some(Uuid::new_v4())),
                move |_| async move {
                    task_entered.notify_one();
                    task_release.notified().await;
                    Ok(41_u8)
                },
            )
            .unwrap();
        entered.notified().await;
        assert_eq!(handle.snapshot().admitted_available, 0);
        assert!(matches!(
            handle.try_spawn_admitted(
                DriverTaskMetadata::new(DriverTaskKind::RouteSetRecovery, None),
                |_| async { Ok(()) }
            ),
            Err(TryAdmitError::AtCapacity)
        ));
        release.notify_one();
        assert_eq!(receipt.wait().await.unwrap(), 41);
        wait_until(|| handle.snapshot().completed == 1).await;
        assert_eq!(handle.snapshot().active(), 0);
        assert_eq!(handle.snapshot().admitted_available, 1);
        lifecycle.drain().await.unwrap();
    }

    #[tokio::test]
    async fn dropped_waiter_does_not_cancel_owned_work() {
        let (handle, lifecycle) = supervisor(1);
        let completed = Arc::new(AtomicBool::new(false));
        let task_completed = completed.clone();
        let receipt = handle
            .try_spawn_admitted(
                DriverTaskMetadata::new(DriverTaskKind::RouteSetStartup, None),
                move |_| async move {
                    tokio::task::yield_now().await;
                    task_completed.store(true, Ordering::SeqCst);
                    Ok(())
                },
            )
            .unwrap();
        drop(receipt);
        wait_until(|| completed.load(Ordering::SeqCst) && handle.snapshot().completed == 1).await;
        lifecycle.drain().await.unwrap();
    }

    #[tokio::test]
    async fn dropping_an_undrained_lifecycle_still_reaps_owned_work() {
        let (handle, lifecycle) = supervisor(1);
        let release = Arc::new(tokio::sync::Notify::new());
        let task_release = release.clone();
        let receipt = handle
            .try_spawn_admitted(
                DriverTaskMetadata::new(DriverTaskKind::RouteSetPublication, None),
                move |_| async move {
                    task_release.notified().await;
                    Ok(())
                },
            )
            .unwrap();
        wait_until(|| handle.snapshot().active() == 1).await;
        drop(lifecycle);
        release.notify_one();
        receipt.wait().await.unwrap();
        wait_until(|| handle.snapshot().state == SupervisorState::Stopped).await;
        assert_eq!(handle.snapshot().completed, 1);
    }

    #[tokio::test]
    async fn begin_draining_runs_every_already_accepted_queued_task() {
        let (handle, lifecycle) = supervisor(2);
        let ran = Arc::new(AtomicUsize::new(0));
        let mut receipts = Vec::new();
        for _ in 0..2 {
            let ran = ran.clone();
            receipts.push(
                handle
                    .try_spawn_admitted(
                        DriverTaskMetadata::new(DriverTaskKind::ReleaseOverlayPublication, None),
                        move |_| async move {
                            ran.fetch_add(1, Ordering::SeqCst);
                            Ok(())
                        },
                    )
                    .unwrap(),
            );
        }
        assert_eq!(handle.snapshot().admitted_queued, 2);
        assert!(handle.is_accepting());
        lifecycle.begin_draining();
        lifecycle.begin_draining();
        assert!(!handle.is_accepting());
        assert!(!lifecycle.is_accepting());
        for receipt in receipts {
            receipt.wait().await.unwrap();
        }
        let snapshot = lifecycle.drain().await.unwrap();
        assert_eq!(ran.load(Ordering::SeqCst), 2);
        assert_eq!(snapshot.completed, 2);
    }

    #[tokio::test]
    async fn owned_long_lived_task_observes_drain_without_being_aborted() {
        let (handle, lifecycle) = supervisor(1);
        let observed = Arc::new(AtomicBool::new(false));
        let task_observed = observed.clone();
        let receipt = handle
            .try_spawn_admitted(
                DriverTaskMetadata::new(DriverTaskKind::RouteSetRecovery, None),
                move |capability| async move {
                    assert!(!capability.is_draining());
                    capability.wait_for_drain().await;
                    assert!(capability.is_draining());
                    task_observed.store(true, Ordering::SeqCst);
                    Ok(())
                },
            )
            .unwrap();
        wait_until(|| handle.snapshot().active() == 1).await;
        let snapshot = lifecycle.drain().await.unwrap();
        receipt.wait().await.unwrap();
        assert!(observed.load(Ordering::SeqCst));
        assert_eq!(snapshot.cancelled, 0);
    }

    #[tokio::test]
    async fn drain_waits_for_an_escaped_owned_capability() {
        let (handle, lifecycle) = supervisor(1);
        let (capability_tx, capability_rx) = std::sync::mpsc::sync_channel(1);
        let receipt = handle
            .try_spawn_admitted(
                DriverTaskMetadata::new(DriverTaskKind::ReleaseOverlayRecovery, None),
                move |capability| {
                    capability_tx.send(capability).unwrap();
                    async { Ok(()) }
                },
            )
            .unwrap();
        let escaped = capability_rx.recv().unwrap();
        receipt.wait().await.unwrap();
        wait_until(|| handle.snapshot().completed == 1).await;
        assert_eq!(handle.snapshot().owned_capabilities, 1);
        let drain_lifecycle = lifecycle.clone();
        let drain = tokio::spawn(async move { drain_lifecycle.drain().await });
        tokio::task::yield_now().await;
        assert!(!drain.is_finished());
        drop(escaped);
        let snapshot = drain.await.unwrap().unwrap();
        assert_eq!(snapshot.owned_capabilities, 0);
    }

    #[tokio::test]
    async fn singleton_service_is_separate_from_admitted_capacity() {
        let (handle, lifecycle) = supervisor(1);
        let service_entered = Arc::new(tokio::sync::Notify::new());
        let entered = service_entered.clone();
        let service = handle
            .try_spawn_service(
                DriverTaskKind::GenerationRetentionScheduler,
                move |stop| async move {
                    entered.notify_one();
                    stop.requested().await;
                    Ok(())
                },
            )
            .unwrap();
        service_entered.notified().await;
        assert_eq!(handle.snapshot().service_active, 1);
        assert_eq!(handle.snapshot().admitted_available, 1);
        assert!(matches!(
            handle.try_spawn_service(DriverTaskKind::GenerationRetentionScheduler, |_| async {
                Ok(())
            }),
            Err(TryServiceError::AlreadyStarted)
        ));
        assert!(matches!(
            handle.try_spawn_service(DriverTaskKind::RouteSetRetention, |_| async { Ok(()) }),
            Err(TryServiceError::NotServiceKind)
        ));

        let admitted_release = Arc::new(tokio::sync::Notify::new());
        let task_release = admitted_release.clone();
        let admitted = handle
            .try_spawn_admitted(
                DriverTaskMetadata::new(DriverTaskKind::RouteSetRetention, None),
                move |_| async move {
                    task_release.notified().await;
                    Ok(())
                },
            )
            .unwrap();
        wait_until(|| handle.snapshot().admitted_active == 1).await;
        assert_eq!(handle.snapshot().admitted_available, 0);
        admitted_release.notify_one();
        admitted.wait().await.unwrap();
        let snapshot = lifecycle.drain().await.unwrap();
        service.wait().await.unwrap();
        assert_eq!(snapshot.completed, 2);
        assert_eq!(snapshot.service_active, 0);
    }

    #[tokio::test]
    async fn unexpected_clean_service_exit_fails_closed_and_starts_drain() {
        let (handle, lifecycle) = supervisor(1);
        let receipt = handle
            .try_spawn_service(DriverTaskKind::GenerationRetentionScheduler, |_| async {
                Ok(())
            })
            .unwrap();

        assert!(matches!(
            receipt.wait().await,
            Err(DriverTaskWaitError::Failed(failure))
                if failure.error_class() == "driver_service_exited"
        ));
        wait_until(|| !lifecycle.is_accepting()).await;
        assert!(matches!(
            lifecycle.drain().await,
            Err(DrainError::TasksFailed {
                failed: 1,
                panicked: 0,
                cancelled: 0,
            })
        ));
    }

    #[tokio::test]
    async fn queued_service_observes_stop_and_is_joined_during_drain() {
        let (handle, lifecycle) = supervisor(1);
        let observed = Arc::new(AtomicBool::new(false));
        let task_observed = observed.clone();
        let receipt = handle
            .try_spawn_service(
                DriverTaskKind::GenerationRetentionScheduler,
                move |stop| async move {
                    assert!(stop.is_requested());
                    stop.requested().await;
                    task_observed.store(true, Ordering::SeqCst);
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(handle.snapshot().service_queued, 1);
        lifecycle.begin_draining();
        assert!(matches!(
            handle.try_spawn_service(DriverTaskKind::GenerationRetentionScheduler, |_| async {
                Ok(())
            }),
            Err(TryServiceError::Draining)
        ));
        let snapshot = lifecycle.drain().await.unwrap();
        receipt.wait().await.unwrap();
        assert!(observed.load(Ordering::SeqCst));
        assert_eq!(snapshot.service_queued, 0);
        assert_eq!(snapshot.service_active, 0);
        assert_eq!(snapshot.completed, 1);
    }

    #[tokio::test]
    async fn active_service_stop_is_visible_synchronously_on_begin_draining() {
        let (handle, lifecycle) = supervisor(1);
        let stop_slot = Arc::new(StdMutex::new(None));
        let task_slot = stop_slot.clone();
        let entered = Arc::new(tokio::sync::Notify::new());
        let task_entered = entered.clone();
        let receipt = handle
            .try_spawn_service(
                DriverTaskKind::GenerationRetentionScheduler,
                move |stop| async move {
                    *task_slot
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(stop.clone());
                    task_entered.notify_one();
                    stop.requested().await;
                    Ok(())
                },
            )
            .unwrap();
        entered.notified().await;
        lifecycle.begin_draining();
        assert!(
            stop_slot
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_ref()
                .unwrap()
                .is_requested()
        );
        lifecycle.drain().await.unwrap();
        receipt.wait().await.unwrap();
    }

    #[tokio::test]
    async fn service_failure_panic_and_cancellation_contribute_to_drain() {
        async fn assert_outcome(mode: &'static str, expected: (u64, u64, u64)) {
            let (handle, lifecycle) = supervisor(1);
            let entered = Arc::new(tokio::sync::Notify::new());
            let proceed = Arc::new(tokio::sync::Notify::new());
            let task_entered = entered.clone();
            let task_proceed = proceed.clone();
            let _receipt: DriverTaskReceipt<()> = handle
                .try_spawn_service(
                    DriverTaskKind::GenerationRetentionScheduler,
                    move |_| async move {
                        task_entered.notify_one();
                        task_proceed.notified().await;
                        match mode {
                            "failure" => Err(DriverTaskFailure::new("scheduler_failed").unwrap()),
                            "panic" => panic!("private service panic payload"),
                            "cancel" => Ok(()),
                            _ => unreachable!(),
                        }
                    },
                )
                .unwrap();
            entered.notified().await;
            if mode == "cancel" {
                handle.abort_all_for_test(&lifecycle.control_tx);
            } else {
                proceed.notify_one();
            }
            wait_until(|| {
                let snapshot = handle.snapshot();
                (snapshot.failed, snapshot.panicked, snapshot.cancelled) == expected
            })
            .await;
            assert!(matches!(
                lifecycle.drain().await,
                Err(DrainError::TasksFailed {
                    failed,
                    panicked,
                    cancelled
                }) if (failed, panicked, cancelled) == expected
            ));
        }

        assert_outcome("failure", (1, 0, 0)).await;
        assert_outcome("panic", (0, 1, 0)).await;
        assert_outcome("cancel", (0, 0, 1)).await;
    }

    #[tokio::test]
    async fn drain_rejects_admission_but_accepts_owned_cleanup_and_waits_for_it() {
        let (handle, lifecycle) = supervisor(1);
        let parent_entered = Arc::new(tokio::sync::Notify::new());
        let let_parent_finish = Arc::new(tokio::sync::Notify::new());
        let cleanup_entered = Arc::new(tokio::sync::Notify::new());
        let let_cleanup_finish = Arc::new(tokio::sync::Notify::new());
        let parent_entered_task = parent_entered.clone();
        let parent_finish_task = let_parent_finish.clone();
        let cleanup_entered_task = cleanup_entered.clone();
        let cleanup_finish_task = let_cleanup_finish.clone();
        let receipt = handle
            .try_spawn_admitted(
                DriverTaskMetadata::new(DriverTaskKind::RouteSetPublication, None),
                move |capability| async move {
                    parent_entered_task.notify_one();
                    parent_finish_task.notified().await;
                    capability
                        .try_spawn_cleanup(move |_| async move {
                            cleanup_entered_task.notify_one();
                            cleanup_finish_task.notified().await;
                            Ok(())
                        })
                        .unwrap();
                    Ok(())
                },
            )
            .unwrap();
        parent_entered.notified().await;
        let drain_lifecycle = lifecycle.clone();
        let drain = tokio::spawn(async move { drain_lifecycle.drain().await });
        wait_until(|| lifecycle.snapshot().state == SupervisorState::Draining).await;
        assert!(matches!(
            handle.try_spawn_admitted(
                DriverTaskMetadata::new(DriverTaskKind::RouteSetRecovery, None),
                |_| async { Ok(()) }
            ),
            Err(TryAdmitError::Draining)
        ));
        let_parent_finish.notify_one();
        receipt.wait().await.unwrap();
        cleanup_entered.notified().await;
        assert!(!drain.is_finished());
        assert_eq!(lifecycle.snapshot().internal_active, 1);
        let_cleanup_finish.notify_one();
        let snapshot = drain.await.unwrap().unwrap();
        assert_eq!(snapshot.state, SupervisorState::Stopped);
        assert_eq!(snapshot.completed, 2);
    }

    #[tokio::test]
    async fn failures_panics_and_cancellation_are_safely_reaped() {
        let (handle, lifecycle) = supervisor(3);
        let failed = handle
            .try_spawn_admitted(
                DriverTaskMetadata::new(DriverTaskKind::RouteSetRecovery, None),
                |_| async { Err::<(), _>(DriverTaskFailure::new("lease_lost").unwrap()) },
            )
            .unwrap();
        assert_eq!(
            failed.wait().await,
            Err(DriverTaskWaitError::Failed(
                DriverTaskFailure::new("lease_lost").unwrap()
            ))
        );
        let _panicked: DriverTaskReceipt<()> = handle
            .try_spawn_admitted(
                DriverTaskMetadata::new(DriverTaskKind::RouteSetRetention, None),
                |_| async move { panic!("private panic payload must not be supervisor-logged") },
            )
            .unwrap();
        let blocked = Arc::new(tokio::sync::Notify::new());
        let task_blocked = blocked.clone();
        let _cancelled = handle
            .try_spawn_admitted(
                DriverTaskMetadata::new(DriverTaskKind::RouteSetStartup, None),
                move |_| async move {
                    task_blocked.notified().await;
                    Ok(())
                },
            )
            .unwrap();
        wait_until(|| handle.snapshot().admitted_active >= 1).await;
        handle.abort_all_for_test(&lifecycle.control_tx);
        wait_until(|| {
            let snapshot = handle.snapshot();
            snapshot.failed == 1 && snapshot.panicked == 1 && snapshot.cancelled == 1
        })
        .await;
        assert!(matches!(
            lifecycle.drain().await,
            Err(DrainError::TasksFailed {
                failed: 1,
                panicked: 1,
                cancelled: 1
            })
        ));
    }

    #[tokio::test]
    async fn concurrent_drain_waiters_share_one_terminal_state() {
        let (handle, lifecycle) = supervisor(2);
        let release = Arc::new(tokio::sync::Notify::new());
        let task_release = release.clone();
        let _receipt = handle
            .try_spawn_admitted(
                DriverTaskMetadata::new(DriverTaskKind::RouteSetPublication, None),
                move |_| async move {
                    task_release.notified().await;
                    Ok(())
                },
            )
            .unwrap();
        wait_until(|| handle.snapshot().active() == 1).await;
        let mut waiters = Vec::new();
        for _ in 0..8 {
            let lifecycle = lifecycle.clone();
            waiters.push(tokio::spawn(async move { lifecycle.drain().await }));
        }
        wait_until(|| lifecycle.snapshot().state == SupervisorState::Draining).await;
        release.notify_one();
        for waiter in waiters {
            let snapshot = waiter.await.unwrap().unwrap();
            assert_eq!(snapshot.state, SupervisorState::Stopped);
            assert_eq!(snapshot.completed, 1);
        }
    }

    #[tokio::test]
    async fn internal_cleanup_can_spawn_a_nested_cleanup_during_drain() {
        let (handle, lifecycle) = supervisor(1);
        let nested = Arc::new(AtomicUsize::new(0));
        let nested_task = nested.clone();
        let receipt = handle
            .try_spawn_admitted(
                DriverTaskMetadata::new(DriverTaskKind::RouteSetPublication, None),
                move |capability| async move {
                    capability
                        .try_spawn_cleanup(move |child| async move {
                            child
                                .try_spawn_cleanup(move |_| async move {
                                    nested_task.fetch_add(1, Ordering::SeqCst);
                                    Ok(())
                                })
                                .unwrap();
                            Ok(())
                        })
                        .unwrap();
                    Ok(())
                },
            )
            .unwrap();
        let drain_lifecycle = lifecycle.clone();
        let drain = tokio::spawn(async move { drain_lifecycle.drain().await });
        receipt.wait().await.unwrap();
        let snapshot = drain.await.unwrap().unwrap();
        assert_eq!(nested.load(Ordering::SeqCst), 1);
        assert_eq!(snapshot.completed, 3);
        assert_eq!(snapshot.active(), 0);
        assert_eq!(snapshot.queued(), 0);
    }

    #[test]
    fn supervisor_logging_surface_contains_only_safe_fields() {
        let source = include_str!("task_supervisor.rs");
        let forbidden = [
            ["?", "join_error"].concat(),
            ["%", "join_error"].concat(),
            ["panic", ".payload"].concat(),
            ["execution", "_token"].concat(),
            ["lease", "_token"].concat(),
            ["request", "_digest"].concat(),
            ["raw", "_error"].concat(),
        ];
        for forbidden in forbidden {
            assert!(
                !source.contains(&forbidden),
                "unsafe log surface: {forbidden}"
            );
        }
        for required in [
            "task.id",
            "task.root_id",
            "task.kind",
            "task.outcome",
            "error_class",
        ] {
            assert!(source.contains(required), "missing safe field: {required}");
        }
    }
}
