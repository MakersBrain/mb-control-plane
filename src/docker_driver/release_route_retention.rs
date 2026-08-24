//! Dormant coordinator for database-authorized release-overlay retention.
//!
//! The spawned task owns both the shared host guard and the database claim so
//! cancellation of its waiter cannot abandon an in-flight filesystem step.
#![allow(dead_code)]

use std::path::PathBuf;
use std::time::Duration;

use serde_json::Value;
use sqlx::PgPool;
use tokio::task::JoinHandle;

use super::DriverError;
use super::host_guard::SharedOdooHostGuard;
use super::release_generation_fs::{
    ReleaseGenerationRetentionDeletion, ReleaseGenerationRetentionMismatch,
    ReleaseGenerationRetentionStep, step_retained_release_generation_deletion,
};
use super::release_route_retention_db::{
    ClaimReleaseGenerationRetentionOutcome, ReleaseGenerationRetentionClaim,
    ReleaseGenerationRetentionClaimRequest, ReleaseGenerationRetentionEvidence,
    ReleaseGenerationRetentionResolution, claim_release_retention, finish_release_retention,
    renew_release_retention_claim,
};
use super::route_generation_fs::observe_current_selector;
use super::route_set_prior::observe_prior_loaded_identity;
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
pub(super) struct DormantReleaseGenerationRetentionCoordinator {
    ledger: PgPool,
    route_root: PathBuf,
    supervisor: DriverTaskSupervisorHandle,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum DormantReleaseGenerationRetentionResult {
    Finished {
        resolution: ReleaseGenerationRetentionResolution,
        database_outcome: String,
    },
    Refused(ClaimReleaseGenerationRetentionOutcome),
}

pub(super) enum DormantReleaseGenerationRetentionError {
    Admission(TryAdmitError),
    Supervisor(DriverTaskWaitError),
    Effect(DriverError),
}

impl DormantReleaseGenerationRetentionCoordinator {
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

    /// Admission transfers ownership before awaiting; caller cancellation does
    /// not abandon the host guard, claim, or final database write.
    pub(super) async fn execute(
        &self,
        request: ReleaseGenerationRetentionClaimRequest,
    ) -> Result<DormantReleaseGenerationRetentionResult, DormantReleaseGenerationRetentionError>
    {
        let coordinator = self.clone();
        let operation_id = request.driver_operation_id;
        let receipt = self
            .supervisor
            .try_spawn_admitted(
                DriverTaskMetadata::new(
                    DriverTaskKind::ReleaseOverlayRetention,
                    Some(operation_id),
                ),
                move |_| async move {
                    Ok::<_, DriverTaskFailure>(coordinator.execute_owned(request).await)
                },
            )
            .map_err(DormantReleaseGenerationRetentionError::Admission)?;
        receipt
            .wait()
            .await
            .map_err(DormantReleaseGenerationRetentionError::Supervisor)?
            .map_err(DormantReleaseGenerationRetentionError::Effect)
    }

    #[tracing::instrument(
        name = "deployment_driver.release_route_retention.lifecycle_dormant",
        skip_all,
        fields(
            operation.id=%request.driver_operation_id,
            retention.kind=request.overlay_kind.as_str(),
            retention.phase="host_guard",
            retention.resolution=tracing::field::Empty,
            retention.outcome="in_progress"
        )
    )]
    async fn execute_owned(
        self,
        request: ReleaseGenerationRetentionClaimRequest,
    ) -> Result<DormantReleaseGenerationRetentionResult, DriverError> {
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
        request: ReleaseGenerationRetentionClaimRequest,
    ) -> Result<DormantReleaseGenerationRetentionResult, DriverError> {
        let host_guard = SharedOdooHostGuard::acquire(&self.route_root)
            .await
            .map_err(DriverError::internal)?;
        tracing::Span::current().record("retention.phase", "claim");
        let admitted = claim_release_retention(&self.ledger, &request).await?;
        let Some(claim) = admitted.claim else {
            tracing::Span::current()
                .record("retention.outcome", admitted_outcome(admitted.outcome));
            return Ok(DormantReleaseGenerationRetentionResult::Refused(
                admitted.outcome,
            ));
        };

        tracing::Span::current().record("retention.phase", "observation");
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
                ReleaseGenerationRetentionDeletion::Deleted {
                    directory_device,
                    directory_inode,
                } => (
                    ReleaseGenerationRetentionResolution::Deleted,
                    true,
                    Some(*directory_device),
                    Some(*directory_inode),
                    None,
                    &Value::Null,
                ),
                ReleaseGenerationRetentionDeletion::AlreadyAbsent => (
                    ReleaseGenerationRetentionResolution::AlreadyAbsent,
                    false,
                    None,
                    None,
                    None,
                    &Value::Null,
                ),
                ReleaseGenerationRetentionDeletion::ProtectedCurrent {
                    directory_device,
                    directory_inode,
                } => (
                    ReleaseGenerationRetentionResolution::ProtectedCurrent,
                    true,
                    Some(*directory_device),
                    Some(*directory_inode),
                    None,
                    &Value::Null,
                ),
                ReleaseGenerationRetentionDeletion::IdentityMismatch {
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
                        ReleaseGenerationRetentionResolution::IdentityMismatch,
                        true,
                        Some(*directory_device),
                        Some(*directory_inode),
                        Some(match mismatch {
                            ReleaseGenerationRetentionMismatch::DirectoryIdentity => {
                                "directory_identity"
                            }
                            ReleaseGenerationRetentionMismatch::ContentIdentity => {
                                "content_identity"
                            }
                            ReleaseGenerationRetentionMismatch::ContentIntegrity => {
                                "content_integrity"
                            }
                        }),
                        &observed_identity_json,
                    )
                }
            };
        tracing::Span::current().record("retention.resolution", resolution.as_str());
        let evidence = ReleaseGenerationRetentionEvidence {
            protocol_version: 1,
            driver_operation_id: claim.driver_operation_id,
            overlay_kind: claim.overlay_kind.as_str(),
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
            finish_release_retention(&self.ledger, &claim, resolution, &evidence).await?;
        if database_outcome != resolution.as_str() && database_outcome != "replay" {
            return Err(DriverError::internal(format!(
                "release retention finish refused with {database_outcome}"
            )));
        }
        tracing::Span::current().record("retention.outcome", database_outcome.as_str());
        drop(host_guard);
        Ok(DormantReleaseGenerationRetentionResult::Finished {
            resolution,
            database_outcome,
        })
    }

    async fn delete_with_fenced_steps(
        &self,
        claim: &ReleaseGenerationRetentionClaim,
        host_guard: &SharedOdooHostGuard,
    ) -> Result<ReleaseGenerationRetentionDeletion, DriverError> {
        let period = Duration::from_secs((claim.ttl_seconds as u64 / 3).max(1));
        loop {
            match renew_release_retention_claim(&self.ledger, claim).await {
                Ok(true) => {}
                Ok(false) => {
                    return Err(DriverError::internal(
                        "release retention authority was lost before the next step",
                    ));
                }
                Err(error) => return Err(error),
            }
            let route_root = self.route_root.clone();
            let owned = claim.clone();
            let retained_guard = host_guard.try_clone().map_err(DriverError::internal)?;
            let mut step: JoinHandle<_> = tokio::task::spawn_blocking(move || {
                let _retained_guard = retained_guard;
                step_retained_release_generation_deletion(
                    &route_root,
                    &owned.intent,
                    &owned.identity,
                    owned.directory_device,
                    owned.directory_inode,
                    owned.route_count,
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
                        match renew_release_retention_claim(&self.ledger, claim).await {
                            Ok(true) => {}
                            Ok(false) => {
                                step.await.map_err(DriverError::internal)?
                                    .map_err(DriverError::internal)?;
                                return Err(DriverError::internal(
                                    "release retention authority was lost",
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
                ReleaseGenerationRetentionStep::InProgress => {}
                ReleaseGenerationRetentionStep::Complete(deletion) => return Ok(deletion),
            }
        }
    }
}

const fn admitted_outcome(outcome: ClaimReleaseGenerationRetentionOutcome) -> &'static str {
    match outcome {
        ClaimReleaseGenerationRetentionOutcome::Acquired => "acquired",
        ClaimReleaseGenerationRetentionOutcome::Replay => "replay",
        ClaimReleaseGenerationRetentionOutcome::Busy => "busy",
        ClaimReleaseGenerationRetentionOutcome::Ineligible => "ineligible",
        ClaimReleaseGenerationRetentionOutcome::NotFound => "not_found",
        ClaimReleaseGenerationRetentionOutcome::Invalid => "invalid",
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn dormant_coordinator_orders_authority_and_has_privacy_safe_tracing() {
        let source = include_str!("release_route_retention.rs");
        let guard = source.find("SharedOdooHostGuard::acquire").unwrap();
        let claim = source.find("claim_release_retention(&self.ledger").unwrap();
        assert!(guard < claim);
        let steps = source.find("async fn delete_with_fenced_steps").unwrap();
        let step_source = &source[steps..];
        assert!(
            step_source.find("renew_release_retention_claim").unwrap()
                < step_source.find("tokio::task::spawn_blocking").unwrap()
        );
        assert!(source.contains("ReleaseGenerationRetentionStep::InProgress"));
        for (field, value) in [
            ("claim_token", "=%"),
            ("selector", "=%"),
            ("digest", "=%"),
            ("device", "=%"),
            ("inode", "=%"),
        ] {
            assert!(!source.contains(&format!("{field}{value}")));
        }
        let driver = include_str!("../docker_driver.rs");
        assert_eq!(driver.matches("mod release_route_retention;").count(), 1);
        assert!(!driver.contains("release_route_retention::"));
    }
}
