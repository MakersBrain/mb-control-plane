//! Dormant coordinator for database-authorized immutable generation retention.
//!
//! This module is intentionally not called by the active driver. The spawned
//! operation owns the host guard and database claim independently of its
//! waiter so cancellation cannot abandon an in-flight filesystem deletion.
#![allow(dead_code)]

use std::path::PathBuf;
use std::time::Duration;

use serde_json::Value;
use sqlx::PgPool;
use tokio::task::JoinHandle;

use super::DriverError;
use super::host_guard::SharedOdooHostGuard;
use super::route_generation_fs::observe_current_selector;
use super::route_set_generation_fs::{
    RouteSetRetentionDeletion, RouteSetRetentionMismatch, RouteSetRetentionStep,
    step_retained_route_set_generation_deletion,
};
use super::route_set_prior::observe_prior_loaded_identity;
use super::route_set_retention_db::{
    ClaimRouteSetRetentionOutcome, RouteSetRetentionClaim, RouteSetRetentionClaimRequest,
    RouteSetRetentionEvidence, RouteSetRetentionResolution, claim_retention, finish_retention,
    renew_retention_claim,
};
use super::task_supervisor::{
    DriverTaskFailure, DriverTaskKind, DriverTaskMetadata, DriverTaskSupervisorHandle,
    DriverTaskWaitError, TryAdmitError,
};

struct LifecycleTraceOutcome {
    span: tracing::Span,
    closed: bool,
}

impl Drop for LifecycleTraceOutcome {
    fn drop(&mut self) {
        if !self.closed {
            self.span.record("retention.outcome", "error");
        }
    }
}

#[derive(Clone)]
pub(super) struct DormantRouteSetRetentionCoordinator {
    ledger: PgPool,
    route_root: PathBuf,
    supervisor: DriverTaskSupervisorHandle,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum DormantRouteSetRetentionResult {
    Finished {
        resolution: RouteSetRetentionResolution,
        database_outcome: String,
    },
    Refused(ClaimRouteSetRetentionOutcome),
}

pub(super) enum DormantRouteSetRetentionError {
    Admission(TryAdmitError),
    Supervisor(DriverTaskWaitError),
    Effect(DriverError),
}

impl DormantRouteSetRetentionCoordinator {
    pub(super) fn new(
        ledger: PgPool,
        route_root: PathBuf,
        supervisor: DriverTaskSupervisorHandle,
    ) -> Self {
        Self {
            ledger,
            route_root,
            supervisor,
        }
    }

    /// Admission transfers ownership to the process supervisor before this
    /// waiter observes the result. Dropping the waiter cannot cancel the task.
    pub(super) async fn execute(
        &self,
        request: RouteSetRetentionClaimRequest,
    ) -> Result<DormantRouteSetRetentionResult, DormantRouteSetRetentionError> {
        let coordinator = self.clone();
        let publication_id = request.publication_id;
        let receipt = self
            .supervisor
            .try_spawn_admitted(
                DriverTaskMetadata::new(DriverTaskKind::RouteSetRetention, Some(publication_id)),
                move |_| async move {
                    Ok::<_, DriverTaskFailure>(coordinator.execute_owned(request).await)
                },
            )
            .map_err(DormantRouteSetRetentionError::Admission)?;
        receipt
            .wait()
            .await
            .map_err(DormantRouteSetRetentionError::Supervisor)?
            .map_err(DormantRouteSetRetentionError::Effect)
    }

    #[tracing::instrument(
        name = "deployment_driver.route_set_retention.lifecycle_dormant",
        skip_all,
        fields(
            publication.id = %request.publication_id,
            retention.phase = "host_guard",
            retention.kind = tracing::field::Empty,
            retention.resolution = tracing::field::Empty,
            retention.outcome = "in_progress"
        )
    )]
    async fn execute_owned(
        self,
        request: RouteSetRetentionClaimRequest,
    ) -> Result<DormantRouteSetRetentionResult, DriverError> {
        let mut trace = LifecycleTraceOutcome {
            span: tracing::Span::current(),
            closed: false,
        };
        let result = self.execute_guarded(request).await;
        if result.is_err() {
            tracing::Span::current().record("retention.outcome", "error");
        }
        trace.closed = true;
        result
    }

    async fn execute_guarded(
        &self,
        request: RouteSetRetentionClaimRequest,
    ) -> Result<DormantRouteSetRetentionResult, DriverError> {
        let host_guard = SharedOdooHostGuard::acquire(&self.route_root)
            .await
            .map_err(DriverError::internal)?;
        tracing::Span::current().record("retention.phase", "claim");
        let admitted = claim_retention(&self.ledger, &request).await?;
        let Some(claim) = admitted.claim else {
            tracing::Span::current()
                .record("retention.outcome", admitted_outcome(admitted.outcome));
            return Ok(DormantRouteSetRetentionResult::Refused(admitted.outcome));
        };
        tracing::Span::current().record("retention.kind", claim.publication_kind.as_str());
        tracing::Span::current().record("retention.phase", "observation");
        // The host guard excludes every local selector writer while the global
        // database claim excludes other replicas. The deletion primitive also
        // repeats the selector proof before each destructive transition.
        let current = observe_current_selector(&self.route_root).map_err(DriverError::internal)?;
        let current_identity = observe_prior_loaded_identity(&self.route_root, &current)
            .map_err(DriverError::internal)?
            .as_database_json()?
            .unwrap_or(Value::Null);

        tracing::Span::current().record("retention.phase", "deletion");
        let deletion = self.delete_with_fenced_steps(&claim, &host_guard).await?;
        let observed_identity_json;
        let (resolution, target_present, device, inode, mismatch_kind, target_identity) =
            match &deletion {
                RouteSetRetentionDeletion::Deleted {
                    directory_device,
                    directory_inode,
                } => (
                    RouteSetRetentionResolution::Deleted,
                    true,
                    Some(*directory_device),
                    Some(*directory_inode),
                    None,
                    &Value::Null,
                ),
                RouteSetRetentionDeletion::AlreadyAbsent => (
                    RouteSetRetentionResolution::AlreadyAbsent,
                    false,
                    None,
                    None,
                    None,
                    &Value::Null,
                ),
                RouteSetRetentionDeletion::ProtectedCurrent {
                    directory_device,
                    directory_inode,
                } => (
                    RouteSetRetentionResolution::ProtectedCurrent,
                    true,
                    Some(*directory_device),
                    Some(*directory_inode),
                    None,
                    &Value::Null,
                ),
                RouteSetRetentionDeletion::IdentityMismatch {
                    directory_device,
                    directory_inode,
                    mismatch,
                    observed_identity,
                } => {
                    observed_identity_json = observed_identity
                        .as_ref()
                        .map(serde_json::to_value)
                        .transpose()
                        .map_err(DriverError::internal)?
                        .unwrap_or(Value::Null);
                    (
                        RouteSetRetentionResolution::IdentityMismatch,
                        true,
                        Some(*directory_device),
                        Some(*directory_inode),
                        Some(match mismatch {
                            RouteSetRetentionMismatch::DirectoryIdentity => "directory_identity",
                            RouteSetRetentionMismatch::ContentIdentity => "content_identity",
                            RouteSetRetentionMismatch::ContentIntegrity => "content_identity",
                        }),
                        &observed_identity_json,
                    )
                }
            };
        tracing::Span::current().record("retention.resolution", resolution.as_str());
        let evidence = RouteSetRetentionEvidence {
            protocol_version: 1,
            publication_id: claim.publication_id,
            claim_fence: claim.claim_fence,
            resolution: resolution.as_str(),
            selector: &claim.selector,
            expected_intent: &claim.expected_intent,
            expected_identity: &claim.expected_identity,
            observed_current_selector: current.target(),
            observed_current_identity: &current_identity,
            target_present,
            observed_target_device: device,
            observed_target_inode: inode,
            mismatch_kind,
            observed_target_identity: target_identity,
        };
        tracing::Span::current().record("retention.phase", "finish");
        let database_outcome =
            finish_retention(&self.ledger, &claim, resolution, &evidence).await?;
        if database_outcome != resolution.as_str() && database_outcome != "replay" {
            drop(host_guard);
            return Err(DriverError::internal(format!(
                "route-set retention finish refused with {database_outcome}"
            )));
        }
        tracing::Span::current().record("retention.outcome", database_outcome.as_str());
        drop(host_guard);
        Ok(DormantRouteSetRetentionResult::Finished {
            resolution,
            database_outcome,
        })
    }

    async fn delete_with_fenced_steps(
        &self,
        claim: &RouteSetRetentionClaim,
        host_guard: &SharedOdooHostGuard,
    ) -> Result<RouteSetRetentionDeletion, DriverError> {
        let period = Duration::from_secs((claim.ttl_seconds as u64 / 3).max(1));
        loop {
            match renew_retention_claim(&self.ledger, claim).await {
                Ok(true) => {}
                Ok(false) => {
                    return Err(DriverError::internal(
                        "route-set retention authority was lost before the next step",
                    ));
                }
                Err(error) => return Err(error),
            }
            let route_root = self.route_root.clone();
            let owned = claim.clone();
            let intent = claim.filesystem_intent()?;
            let retained_guard = host_guard.try_clone().map_err(DriverError::internal)?;
            let mut step: JoinHandle<_> = tokio::task::spawn_blocking(move || {
                let _retained_guard = retained_guard;
                step_retained_route_set_generation_deletion(
                    &route_root,
                    &intent,
                    &owned.identity,
                    owned.directory_device,
                    owned.directory_inode,
                    owned.route_count,
                    owned.present_count,
                )
            });
            let start = tokio::time::Instant::now() + period;
            let mut heartbeat = tokio::time::interval_at(start, period);
            heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let outcome = loop {
                tokio::select! {
                    result = &mut step => {
                        break result.map_err(DriverError::internal)?
                            .map_err(DriverError::internal)?;
                    }
                    _ = heartbeat.tick() => {
                        match renew_retention_claim(&self.ledger, claim).await {
                            Ok(true) => {}
                            Ok(false) => {
                                // Never start another unlink after lease loss. The
                                // cloned host guard remains in this single bounded
                                // step until it has stopped touching the filesystem.
                                step.await.map_err(DriverError::internal)?
                                    .map_err(DriverError::internal)?;
                                return Err(DriverError::internal(
                                    "route-set retention authority was lost",
                                ));
                            }
                            Err(error) => {
                                let step_result = step.await.map_err(DriverError::internal)?;
                                if let Err(filesystem_error) = step_result {
                                    return Err(DriverError::internal(filesystem_error));
                                }
                                return Err(error);
                            }
                        }
                    }
                }
            };
            match outcome {
                RouteSetRetentionStep::InProgress => {}
                RouteSetRetentionStep::Complete(deletion) => return Ok(deletion),
            }
        }
    }
}

const fn admitted_outcome(outcome: ClaimRouteSetRetentionOutcome) -> &'static str {
    match outcome {
        ClaimRouteSetRetentionOutcome::Acquired => "acquired",
        ClaimRouteSetRetentionOutcome::Replay => "replay",
        ClaimRouteSetRetentionOutcome::Busy => "busy",
        ClaimRouteSetRetentionOutcome::Ineligible => "ineligible",
        ClaimRouteSetRetentionOutcome::NotFound => "not_found",
        ClaimRouteSetRetentionOutcome::Invalid => "invalid",
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn dormant_coordinator_orders_authority_and_keeps_tracing_privacy_safe() {
        let source = include_str!("route_set_retention.rs");
        let guard = source.find("SharedOdooHostGuard::acquire").unwrap();
        let claim = source.find("claim_retention(&self.ledger").unwrap();
        assert!(guard < claim);
        assert!(source.contains("tokio::task::spawn_blocking"));
        assert!(source.contains("renew_retention_claim"));
        assert!(source.contains("finish_retention"));
        let steps = source.find("async fn delete_with_fenced_steps").unwrap();
        let step_source = &source[steps..];
        assert!(
            step_source.find("renew_retention_claim").unwrap()
                < step_source.find("tokio::task::spawn_blocking").unwrap()
        );
        assert!(step_source.contains("RouteSetRetentionStep::InProgress"));
        for field in [
            "retention.phase",
            "retention.kind",
            "retention.resolution",
            "retention.outcome",
        ] {
            assert!(source.contains(field));
        }
        for (left, right) in [
            ("retention.", "selector"),
            ("retention.", "token"),
            ("retention.", "digest"),
            ("retention.", "device"),
            ("retention.", "inode"),
            ("error", "=%"),
        ] {
            assert!(!source.contains(&format!("{left}{right}")));
        }
        let driver = include_str!("../docker_driver.rs");
        assert_eq!(driver.matches("mod route_set_retention;").count(), 1);
        assert!(!driver.contains("route_set_retention::"));
    }
}
