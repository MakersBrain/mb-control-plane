//! Dormant, read-only proof that a forward-only release recovery candidate is
//! both selected locally and loaded by the route worker.
//!
//! The positive result is intentionally opaque. Filesystem identity is
//! observed on both sides of the two independent runtime identity endpoints,
//! so a coordinator cannot turn a partial or stale observation into durable
//! candidate evidence.
#![allow(dead_code)]

use std::future::Future;
use std::path::{Path, PathBuf};

use super::gateway::{
    ReleaseOverlayGenerationIdentity, ReleaseOverlayKind, RunningRouteWorkerIdentity,
    observe_running_release_overlay_generation, observe_running_route_worker_identity,
};
use super::host_guard::SharedOdooHostGuard;
use super::release_generation_fs::{
    ReleaseGenerationIntent, ReleaseGenerationName, observe_selected_identity,
};
use super::release_route_recovery_db::{
    ReleaseRecoveryArtifact, ReleaseRecoveryCandidatePublicationAuthorization,
    ReleaseRecoveryClaim, ReleaseRecoveryClaimMode, ReleaseRecoveryObservation,
    ReleaseRecoveryObservedArtifact, ReleaseRecoveryPhase, ReleaseRecoveryResolutionKind,
    ReleaseRecoveryState,
};
use super::route_generation_fs::PriorSelector;
use super::{DriverError, DriverState};

const MAX_RELEASE_ROUTES: usize = 500;

/// Type-enforced evidence for the database resolution boundary. There is no
/// field constructor: only the complete local/runtime/local proof below can
/// create this value.
#[derive(Clone, Debug, PartialEq)]
pub(super) struct VerifiedReleaseRecoveryRouteObservation {
    observation: ReleaseRecoveryObservation,
}

impl VerifiedReleaseRecoveryRouteObservation {
    /// Adapter-only projection. The sibling-visible database entry point
    /// accepts this opaque type, while its field-built implementation remains
    /// private to the database module.
    pub(super) fn database_observation(&self) -> &ReleaseRecoveryObservation {
        &self.observation
    }
}

#[derive(Clone)]
struct ExpectedCandidate {
    intent: ReleaseGenerationIntent,
    identity: ReleaseOverlayGenerationIdentity,
    selector: PriorSelector,
    maintenance: ReleaseRecoveryObservedArtifact,
    route_count: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct LocalCandidateObservation {
    selector: PriorSelector,
    identity: ReleaseOverlayGenerationIdentity,
}

/// Observe a post-publication candidate without writing the database,
/// filesystem, selector, gateway, or runtime. A failure is deliberately only
/// an error; there is no weaker positive observation variant.
#[tracing::instrument(
    name = "deployment_driver.release_route_recovery.observe_candidate_route_dormant",
    skip_all,
    fields(
        driver.operation_id = %recovery.driver_operation_id,
        observation.outcome = tracing::field::Empty
    )
)]
pub(super) async fn observe_release_recovery_candidate_route(
    _guard: &SharedOdooHostGuard,
    claim: &ReleaseRecoveryClaim,
    authorization: &ReleaseRecoveryCandidatePublicationAuthorization,
    driver: &DriverState,
    route_root: &Path,
    recovery: &ReleaseRecoveryState,
) -> Result<VerifiedReleaseRecoveryRouteObservation, DriverError> {
    authorization.validate_for(claim, recovery)?;
    let expected = expected_candidate(recovery)?;
    let root = route_root.to_path_buf();
    let local_expected = expected.clone();
    let overlay_identity = expected.identity.clone();

    let result = observe_candidate_route_with(
        expected,
        move || {
            let root = root.clone();
            let expected = local_expected.clone();
            async move { observe_local_candidate(root, expected).await }
        },
        || observe_running_release_overlay_generation(driver, &overlay_identity),
        || observe_running_route_worker_identity(driver),
    )
    .await;
    tracing::Span::current().record(
        "observation.outcome",
        if result.is_ok() {
            "verified"
        } else {
            "inconclusive"
        },
    );
    result
}

async fn observe_local_candidate(
    route_root: PathBuf,
    expected: ExpectedCandidate,
) -> Result<LocalCandidateObservation, DriverError> {
    tokio::task::spawn_blocking(move || {
        let selector = observe_selected_identity(
            &route_root,
            &expected.intent,
            &expected.identity,
            expected.route_count,
        )
        .map_err(DriverError::internal)?;
        Ok(LocalCandidateObservation {
            selector,
            identity: expected.identity,
        })
    })
    .await
    .map_err(DriverError::internal)?
}

async fn observe_candidate_route_with<L, LFut, O, OFut, W, WFut>(
    expected: ExpectedCandidate,
    mut observe_local: L,
    observe_overlay: O,
    observe_worker: W,
) -> Result<VerifiedReleaseRecoveryRouteObservation, DriverError>
where
    L: FnMut() -> LFut,
    LFut: Future<Output = Result<LocalCandidateObservation, DriverError>>,
    O: FnOnce() -> OFut,
    OFut: Future<Output = Result<ReleaseOverlayGenerationIdentity, DriverError>>,
    W: FnOnce() -> WFut,
    WFut: Future<Output = Result<RunningRouteWorkerIdentity, DriverError>>,
{
    let first = observe_local().await?;
    require_exact_local(&first, &expected)?;

    let overlay = observe_overlay().await?;
    if overlay != expected.identity {
        return Err(invalid("loaded release overlay identity differs"));
    }

    let worker = observe_worker().await?;
    if worker != RunningRouteWorkerIdentity::ReleaseOverlay(expected.identity.clone()) {
        return Err(invalid("tagged route worker identity differs"));
    }

    let second = observe_local().await?;
    require_exact_local(&second, &expected)?;
    if second != first {
        return Err(invalid(
            "candidate local identity changed during observation",
        ));
    }

    verified_observation(expected, second)
}

fn expected_candidate(recovery: &ReleaseRecoveryState) -> Result<ExpectedCandidate, DriverError> {
    if recovery.claim_mode != ReleaseRecoveryClaimMode::ForwardOnly
        || recovery.claim_fence <= 0
        || !recovery.external_effects_started
        || !matches!(
            recovery.interrupted_phase,
            ReleaseRecoveryPhase::CandidateStaging
                | ReleaseRecoveryPhase::CandidateSealed
                | ReleaseRecoveryPhase::CandidatePublicationStarted
                | ReleaseRecoveryPhase::AwaitingWorkerFinalize
        )
        || !(1..=MAX_RELEASE_ROUTES).contains(&recovery.snapshot_count)
        || recovery.maintenance_selector == recovery.candidate_selector
    {
        return Err(invalid(
            "release recovery state does not permit candidate route observation",
        ));
    }
    let maintenance = recovery
        .maintenance_artifact
        .as_ref()
        .ok_or_else(|| invalid("maintenance observation evidence is absent"))?;
    let candidate = recovery
        .candidate_artifact
        .as_ref()
        .ok_or_else(|| invalid("candidate artifact evidence is absent"))?;
    validate_recorded_artifact(recovery, maintenance, ReleaseOverlayKind::Maintenance)?;
    validate_recorded_artifact(recovery, candidate, ReleaseOverlayKind::Candidate)?;

    let intent = ReleaseGenerationIntent::new(
        recovery.fleet_run_id,
        recovery.driver_operation_id,
        recovery.original_global_fence_token,
        ReleaseOverlayKind::Candidate,
        recovery.target_slot.as_str(),
    )
    .map_err(DriverError::internal)?;
    let expected_target =
        ReleaseGenerationName::new(recovery.fleet_run_id, ReleaseOverlayKind::Candidate)
            .selector_target();
    if recovery.candidate_selector != expected_target {
        return Err(invalid("candidate selector differs from recovery identity"));
    }
    let selector = PriorSelector::from_recorded(
        recovery.candidate_selector.clone(),
        candidate.directory_device,
        candidate.directory_inode,
    )
    .map_err(DriverError::internal)?;
    let maintenance_device = i64::try_from(maintenance.directory_device)
        .map_err(|_| invalid("maintenance directory identity exceeds its bound"))?;
    let maintenance_inode = i64::try_from(maintenance.directory_inode)
        .map_err(|_| invalid("maintenance directory identity exceeds its bound"))?;
    Ok(ExpectedCandidate {
        intent,
        identity: candidate.identity.clone(),
        selector,
        maintenance: ReleaseRecoveryObservedArtifact {
            selector: recovery.maintenance_selector.clone(),
            directory_device: maintenance_device,
            directory_inode: maintenance_inode,
            loaded_identity: maintenance.identity.clone(),
            publication_started: true,
        },
        route_count: recovery.snapshot_count,
    })
}

fn validate_recorded_artifact(
    recovery: &ReleaseRecoveryState,
    artifact: &ReleaseRecoveryArtifact,
    kind: ReleaseOverlayKind,
) -> Result<(), DriverError> {
    artifact.identity.validate()?;
    let expected_selector =
        ReleaseGenerationName::new(recovery.fleet_run_id, kind).selector_target();
    let recorded_selector = match kind {
        ReleaseOverlayKind::Maintenance => &recovery.maintenance_selector,
        ReleaseOverlayKind::Candidate => &recovery.candidate_selector,
    };
    if artifact.directory_device == 0
        || artifact.directory_inode == 0
        || *recorded_selector != expected_selector
        || artifact.identity.fleet_run_id != recovery.fleet_run_id
        || artifact.identity.driver_operation_id != recovery.driver_operation_id
        || artifact.identity.original_global_fence_token != recovery.original_global_fence_token
        || artifact.identity.overlay_kind != kind
        || artifact.identity.target_slot != recovery.target_slot
    {
        return Err(invalid("recorded release recovery artifact differs"));
    }
    Ok(())
}

fn require_exact_local(
    observed: &LocalCandidateObservation,
    expected: &ExpectedCandidate,
) -> Result<(), DriverError> {
    if observed.selector != expected.selector || observed.identity != expected.identity {
        Err(invalid("selected candidate local identity differs"))
    } else {
        Ok(())
    }
}

fn verified_observation(
    expected: ExpectedCandidate,
    local: LocalCandidateObservation,
) -> Result<VerifiedReleaseRecoveryRouteObservation, DriverError> {
    let device = i64::try_from(local.selector.directory_device())
        .map_err(|_| invalid("candidate directory identity exceeds its bound"))?;
    let inode = i64::try_from(local.selector.directory_inode())
        .map_err(|_| invalid("candidate directory identity exceeds its bound"))?;
    let loaded_identity = serde_json::to_value(&local.identity).map_err(DriverError::internal)?;
    Ok(VerifiedReleaseRecoveryRouteObservation {
        observation: ReleaseRecoveryObservation {
            resolution_kind: ReleaseRecoveryResolutionKind::Candidate,
            selector: Some(local.selector.target().to_owned()),
            directory_device: Some(local.selector.directory_device()),
            directory_inode: Some(local.selector.directory_inode()),
            loaded_identity: Some(loaded_identity),
            maintenance_artifact: Some(expected.maintenance),
            candidate_artifact: Some(ReleaseRecoveryObservedArtifact {
                selector: local.selector.target().to_owned(),
                directory_device: device,
                directory_inode: inode,
                loaded_identity: local.identity,
                publication_started: true,
            }),
        },
    })
}

fn invalid(message: &'static str) -> DriverError {
    DriverError::internal(message)
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use uuid::Uuid;

    use super::*;
    use crate::docker_driver::gateway::ReleaseTargetSlot;

    fn digest(marker: char) -> String {
        format!("sha256:{}", marker.to_string().repeat(64))
    }

    fn identity(
        fleet: Uuid,
        operation: Uuid,
        fence: i64,
        kind: ReleaseOverlayKind,
    ) -> ReleaseOverlayGenerationIdentity {
        ReleaseOverlayGenerationIdentity::new(
            fleet,
            operation,
            fence,
            kind,
            digest(match kind {
                ReleaseOverlayKind::Maintenance => 'a',
                ReleaseOverlayKind::Candidate => 'b',
            }),
            "green",
        )
        .unwrap()
    }

    fn state() -> ReleaseRecoveryState {
        let fleet = Uuid::parse_str("10000000-0000-4000-8000-000000000001").unwrap();
        let operation = Uuid::parse_str("20000000-0000-4000-8000-000000000002").unwrap();
        ReleaseRecoveryState {
            driver_operation_id: operation,
            fleet_run_id: fleet,
            claim_fence: 7,
            claim_mode: ReleaseRecoveryClaimMode::ForwardOnly,
            interrupted_phase: ReleaseRecoveryPhase::CandidatePublicationStarted,
            target_slot: ReleaseTargetSlot::parse("green").unwrap(),
            original_global_fence_token: 11,
            snapshot_count: 2,
            prior: None,
            prior_loaded_identity: None,
            maintenance_selector: ReleaseGenerationName::new(
                fleet,
                ReleaseOverlayKind::Maintenance,
            )
            .selector_target(),
            maintenance_artifact: Some(ReleaseRecoveryArtifact {
                identity: identity(fleet, operation, 11, ReleaseOverlayKind::Maintenance),
                directory_device: 20,
                directory_inode: 21,
            }),
            candidate_selector: ReleaseGenerationName::new(fleet, ReleaseOverlayKind::Candidate)
                .selector_target(),
            candidate_artifact: Some(ReleaseRecoveryArtifact {
                identity: identity(fleet, operation, 11, ReleaseOverlayKind::Candidate),
                directory_device: 30,
                directory_inode: 31,
            }),
            external_effects_started: true,
        }
    }

    fn local(expected: &ExpectedCandidate) -> LocalCandidateObservation {
        LocalCandidateObservation {
            selector: expected.selector.clone(),
            identity: expected.identity.clone(),
        }
    }

    #[tokio::test]
    async fn exact_candidate_requires_two_local_and_two_runtime_identities() {
        let recovery = state();
        let expected = expected_candidate(&recovery).unwrap();
        let calls = Cell::new(0);
        let proof = observe_candidate_route_with(
            expected.clone(),
            || {
                calls.set(calls.get() + 1);
                std::future::ready(Ok(local(&expected)))
            },
            || std::future::ready(Ok(expected.identity.clone())),
            || {
                std::future::ready(Ok(RunningRouteWorkerIdentity::ReleaseOverlay(
                    expected.identity.clone(),
                )))
            },
        )
        .await
        .unwrap();
        assert_eq!(calls.get(), 2);
        let observation = proof.database_observation();
        assert_eq!(
            observation.resolution_kind,
            ReleaseRecoveryResolutionKind::Candidate
        );
        assert_eq!(
            observation.selector.as_deref(),
            Some(expected.selector.target())
        );
        assert_eq!(observation.directory_device, Some(30));
        assert_eq!(observation.directory_inode, Some(31));
        assert!(
            observation
                .maintenance_artifact
                .as_ref()
                .unwrap()
                .publication_started
        );
        assert!(
            observation
                .candidate_artifact
                .as_ref()
                .unwrap()
                .publication_started
        );
    }

    #[tokio::test]
    async fn rejects_overlay_worker_or_toctou_identity_drift() {
        let recovery = state();
        let expected = expected_candidate(&recovery).unwrap();
        let wrong = identity(
            recovery.fleet_run_id,
            recovery.driver_operation_id,
            recovery.original_global_fence_token,
            ReleaseOverlayKind::Candidate,
        );
        let mut wrong = wrong;
        wrong.route_set_digest = digest('c');
        assert!(
            observe_candidate_route_with(
                expected.clone(),
                || std::future::ready(Ok(local(&expected))),
                || std::future::ready(Ok(wrong.clone())),
                || std::future::ready(Ok(RunningRouteWorkerIdentity::ReleaseOverlay(
                    expected.identity.clone()
                ))),
            )
            .await
            .is_err()
        );
        assert!(
            observe_candidate_route_with(
                expected.clone(),
                || std::future::ready(Ok(local(&expected))),
                || std::future::ready(Ok(expected.identity.clone())),
                || std::future::ready(Ok(RunningRouteWorkerIdentity::ReleaseOverlay(
                    wrong.clone()
                ))),
            )
            .await
            .is_err()
        );

        let calls = Cell::new(0);
        assert!(
            observe_candidate_route_with(
                expected.clone(),
                || {
                    calls.set(calls.get() + 1);
                    let mut observed = local(&expected);
                    if calls.get() == 2 {
                        observed.selector = PriorSelector::from_recorded(
                            observed.selector.target().to_owned(),
                            30,
                            99,
                        )
                        .unwrap();
                    }
                    std::future::ready(Ok(observed))
                },
                || std::future::ready(Ok(expected.identity.clone())),
                || std::future::ready(Ok(RunningRouteWorkerIdentity::ReleaseOverlay(
                    expected.identity.clone()
                ))),
            )
            .await
            .is_err()
        );
    }

    #[test]
    fn only_exact_forward_post_publication_state_is_admitted() {
        let base = state();
        assert!(expected_candidate(&base).is_ok());
        for origin_phase in [
            ReleaseRecoveryPhase::CandidateStaging,
            ReleaseRecoveryPhase::CandidateSealed,
            ReleaseRecoveryPhase::CandidatePublicationStarted,
            ReleaseRecoveryPhase::AwaitingWorkerFinalize,
        ] {
            let mut origin = base.clone();
            origin.interrupted_phase = origin_phase;
            assert!(expected_candidate(&origin).is_ok());
        }
        for mutate in [
            |state: &mut ReleaseRecoveryState| {
                state.claim_mode = ReleaseRecoveryClaimMode::RestorePrior
            },
            |state: &mut ReleaseRecoveryState| state.external_effects_started = false,
            |state: &mut ReleaseRecoveryState| {
                state.interrupted_phase = ReleaseRecoveryPhase::MaintenanceObserved
            },
            |state: &mut ReleaseRecoveryState| state.snapshot_count = 0,
            |state: &mut ReleaseRecoveryState| state.claim_fence = 0,
            |state: &mut ReleaseRecoveryState| state.candidate_artifact = None,
            |state: &mut ReleaseRecoveryState| state.maintenance_artifact = None,
        ] {
            let mut changed = base.clone();
            mutate(&mut changed);
            assert!(expected_candidate(&changed).is_err());
        }
        let mut identity_drift = base.clone();
        identity_drift
            .candidate_artifact
            .as_mut()
            .unwrap()
            .identity
            .driver_operation_id = Uuid::new_v4();
        assert!(expected_candidate(&identity_drift).is_err());
        let mut local_drift = base;
        local_drift
            .candidate_artifact
            .as_mut()
            .unwrap()
            .directory_inode += 1;
        let expected = expected_candidate(&local_drift).unwrap();
        let observed = LocalCandidateObservation {
            selector: PriorSelector::from_recorded(
                expected.selector.target().to_owned(),
                expected.selector.directory_device(),
                expected.selector.directory_inode() - 1,
            )
            .unwrap(),
            identity: expected.identity.clone(),
        };
        assert!(require_exact_local(&observed, &expected).is_err());
    }

    #[test]
    fn module_is_dormant_opaque_and_observation_only() {
        let root = include_str!("../docker_driver.rs");
        assert_eq!(
            root.matches("mod release_route_recovery_observation;")
                .count(),
            1
        );
        assert_eq!(
            root.matches("release_route_recovery_observation::").count(),
            0
        );
        let source = include_str!("release_route_recovery_observation.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        let exposed_field = ["pub ", "observation:"].concat();
        assert!(!production.contains(&exposed_field));
        for forbidden in [
            "sqlx::",
            "publish_release_candidate_forward",
            "authorize_release_recovery",
            "resolve_interrupted",
            "std::fs::write",
            "std::fs::remove",
            "Command::new",
        ] {
            assert!(
                !production.contains(forbidden),
                "forbidden mutation: {forbidden}"
            );
        }
        assert!(source.contains("\"verified\""));
        assert!(source.contains("\"inconclusive\""));
        assert!(source.contains("authorization.validate_for(claim, recovery)?"));
        assert!(
            source.contains("authorization: &ReleaseRecoveryCandidatePublicationAuthorization")
        );

        let adapter = include_str!("release_route_recovery_db.rs");
        assert!(adapter.contains("observation: &VerifiedReleaseRecoveryRouteObservation"));
        assert!(
            !adapter.contains("pub(super) async fn resolve_interrupted_release_route_publication(")
        );
    }
}
