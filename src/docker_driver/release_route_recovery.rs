//! Dormant, descriptor-safe filesystem foundation for release-v2 recovery.
//!
//! This module has no database dependency. Callers must hold the shared-host
//! guard and provide a durable-intent callback before any filesystem mutation.
//! Classification uses selector metadata and closed identity files only; live
//! route configuration bytes are never read.
#![allow(dead_code)]

use std::io;
use std::path::Path;

use super::gateway::{
    ReleaseOverlayGenerationIdentity, ReleaseOverlayKind, RunningRouteWorkerIdentity,
};
use super::host_guard::SharedOdooHostGuard;
use super::release_generation_fs::{
    ReleaseGenerationDirectory, ReleaseGenerationIntent, ReleaseGenerationName,
    ReleasePostStartInspection, ReleaseSelectorExchange, dispose_exact_unpublished,
    inspect_post_start_release_publication, observe_candidate_selector,
    observe_generation_identity, recover_exchange_artifact,
};
use super::route_generation_fs::{PriorSelector, observe_current_selector};
use super::route_set_prior::{PriorLoadedIdentity, observe_prior_loaded_identity};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ReleaseRecoveryPhase {
    MaintenanceStaging,
    MaintenanceSealed,
    MaintenancePublicationStarted,
    MaintenanceObserved,
    CandidateStaging,
    CandidateSealed,
    CandidatePublicationStarted,
    AwaitingWorkerFinalize,
}

impl ReleaseRecoveryPhase {
    fn permits_pre_start_disposal(self, kind: ReleaseOverlayKind) -> bool {
        matches!(
            (self, kind),
            (
                Self::MaintenanceStaging | Self::MaintenanceSealed,
                ReleaseOverlayKind::Maintenance
            ) | (
                Self::CandidateStaging | Self::CandidateSealed,
                ReleaseOverlayKind::Candidate
            )
        )
    }

    fn permits_prior_restore(self) -> bool {
        matches!(
            self,
            Self::MaintenancePublicationStarted | Self::MaintenanceObserved
        )
    }

    fn permits_candidate_forward(self) -> bool {
        matches!(
            self,
            Self::CandidateSealed
                | Self::CandidatePublicationStarted
                | Self::AwaitingWorkerFinalize
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ReleaseCurrentKind {
    Prior,
    Maintenance,
    Candidate,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ReleaseCurrentClassification {
    pub kind: ReleaseCurrentKind,
    pub selector: PriorSelector,
    pub loaded_identity: PriorLoadedIdentity,
}

pub(super) struct ReleaseCurrentExpectation<'a> {
    pub prior: &'a PriorSelector,
    pub prior_identity: &'a PriorLoadedIdentity,
    pub maintenance_selector: &'a PriorSelector,
    pub maintenance_identity: &'a ReleaseOverlayGenerationIdentity,
    pub candidate_selector: &'a PriorSelector,
    pub candidate_identity: &'a ReleaseOverlayGenerationIdentity,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum ReleaseArtifactInspection {
    Absent,
    Exact {
        selector: PriorSelector,
        identity: ReleaseOverlayGenerationIdentity,
        publication_started: bool,
    },
    PresentUnverified,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ReleaseMutationOutcome {
    Applied,
    AlreadyApplied,
    AlreadyAbsent,
}

pub(super) struct ReleasePublicationRecoveryRequest<'a> {
    pub phase: ReleaseRecoveryPhase,
    pub intent: ReleaseGenerationIntent,
    pub overlay_identity: &'a ReleaseOverlayGenerationIdentity,
    pub route_count: usize,
    pub overlay_selector: &'a PriorSelector,
    pub prior_selector: &'a PriorSelector,
}

/// Classify `current` only after binding its directory dev/inode, parsing its
/// one closed identity, comparing the loopback-worker identity, and observing
/// the selector a second time. A valid third generation remains typed Unknown.
pub(super) fn classify_release_current(
    route_root: &Path,
    expected: &ReleaseCurrentExpectation<'_>,
    running: Option<&RunningRouteWorkerIdentity>,
) -> io::Result<ReleaseCurrentClassification> {
    let selector = observe_current_selector(route_root)?;
    let loaded = observe_prior_loaded_identity(route_root, &selector)?;
    require_running_identity(&loaded, running)?;
    if observe_current_selector(route_root)? != selector {
        return Err(invalid(
            "release current selector changed during classification",
        ));
    }
    let kind = if selector == *expected.prior && loaded == *expected.prior_identity {
        ReleaseCurrentKind::Prior
    } else if selector == *expected.maintenance_selector
        && loaded == PriorLoadedIdentity::ReleaseOverlay(expected.maintenance_identity.clone())
    {
        ReleaseCurrentKind::Maintenance
    } else if selector == *expected.candidate_selector
        && loaded == PriorLoadedIdentity::ReleaseOverlay(expected.candidate_identity.clone())
    {
        ReleaseCurrentKind::Candidate
    } else {
        ReleaseCurrentKind::Unknown
    };
    Ok(ReleaseCurrentClassification {
        kind,
        selector,
        loaded_identity: loaded,
    })
}

/// Inspect a deterministic child without consulting `current`. NotFound is a
/// typed absence; any present child that cannot prove the exact seal/marker is
/// retained as unverified evidence rather than guessed from an error message.
pub(super) fn inspect_release_artifact(
    route_root: &Path,
    intent: &ReleaseGenerationIntent,
    expected_identity: &ReleaseOverlayGenerationIdentity,
    expected_route_count: usize,
    publication_started: bool,
) -> io::Result<ReleaseArtifactInspection> {
    let selector = match observe_candidate_selector(route_root, intent) {
        Ok(selector) => selector,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(ReleaseArtifactInspection::Absent);
        }
        Err(_) => return Ok(ReleaseArtifactInspection::PresentUnverified),
    };
    match observe_generation_identity(
        route_root,
        intent,
        expected_route_count,
        publication_started,
    ) {
        Ok(identity) if identity == *expected_identity => Ok(ReleaseArtifactInspection::Exact {
            selector,
            identity,
            publication_started,
        }),
        Ok(_) | Err(_) => Ok(ReleaseArtifactInspection::PresentUnverified),
    }
}

/// Remove one exact, unselected, marker-free child. The durable callback runs
/// first. A missing child is an idempotent replay, never an inferred success.
pub(super) fn dispose_release_pre_start(
    _guard: &SharedOdooHostGuard,
    route_root: &Path,
    phase: ReleaseRecoveryPhase,
    intent: &ReleaseGenerationIntent,
    mut authorize_before_effect: impl FnMut() -> io::Result<()>,
) -> io::Result<ReleaseMutationOutcome> {
    if !phase.permits_pre_start_disposal(intent.overlay_kind) {
        return Err(invalid("release phase does not permit pre-start disposal"));
    }
    if observe_current_selector(route_root)?.target()
        == ReleaseGenerationName::new(intent.fleet_run_id, intent.overlay_kind).selector_target()
    {
        return Err(invalid("selected release generation is not disposable"));
    }
    authorize_before_effect()?;
    match dispose_exact_unpublished(route_root, intent) {
        Ok(()) => Ok(ReleaseMutationOutcome::Applied),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            Ok(ReleaseMutationOutcome::AlreadyAbsent)
        }
        Err(error) => Err(error),
    }
}

/// Restore only the exact recorded prior from an exact selected maintenance
/// generation. Retry after an exchange crash authenticates and removes only
/// the release-owned exchange artifact.
pub(super) fn restore_release_prior_authorized(
    _guard: &SharedOdooHostGuard,
    route_root: &Path,
    request: ReleasePublicationRecoveryRequest<'_>,
    mut authorize_before_effect: impl FnMut() -> io::Result<()>,
) -> io::Result<ReleaseMutationOutcome> {
    if !request.phase.permits_prior_restore()
        || request.intent.overlay_kind != ReleaseOverlayKind::Maintenance
        || request.overlay_selector == request.prior_selector
    {
        return Err(invalid("release prior restoration request is invalid"));
    }
    let current = observe_current_selector(route_root)?;
    if current == *request.prior_selector {
        authorize_before_effect()?;
        recover_exchange_artifact(
            route_root,
            &request.intent,
            request.overlay_identity,
            request.route_count,
            request.overlay_selector,
            request.prior_selector,
            ReleaseSelectorExchange::RestorePrior,
        )?;
        return Ok(ReleaseMutationOutcome::AlreadyApplied);
    }
    if current != *request.overlay_selector {
        return Err(invalid("unknown selector blocks release prior restoration"));
    }
    let mut generation = ReleaseGenerationDirectory::open_existing_published(
        route_root,
        request.intent,
        &request.overlay_identity.route_set_digest,
        request.route_count,
    )?;
    if generation.observe_selected()?.identity != *request.overlay_identity {
        return Err(invalid("maintenance identity differs before restoration"));
    }
    authorize_before_effect()?;
    generation.restore_prior(request.prior_selector)?;
    Ok(ReleaseMutationOutcome::Applied)
}

/// Publish or resume an exact candidate in the forward direction only.
pub(super) fn publish_release_candidate_forward(
    _guard: &SharedOdooHostGuard,
    route_root: &Path,
    request: ReleasePublicationRecoveryRequest<'_>,
    mut authorize_before_effect: impl FnMut() -> io::Result<()>,
) -> io::Result<ReleaseMutationOutcome> {
    if !request.phase.permits_candidate_forward()
        || request.intent.overlay_kind != ReleaseOverlayKind::Candidate
        || request.overlay_selector == request.prior_selector
    {
        return Err(invalid("release candidate forward request is invalid"));
    }
    let inspection = inspect_post_start_release_publication(
        route_root,
        &request.intent,
        request.overlay_identity,
        request.route_count,
        request.overlay_selector,
        request.prior_selector,
    )?;
    match inspection {
        ReleasePostStartInspection::ForeignOrInconclusive => {
            Err(invalid("release candidate outcome is inconclusive"))
        }
        ReleasePostStartInspection::CandidateSelected => {
            // A takeover must durably bind the already-selected candidate to
            // its current recovery fence before accepting it as success.
            authorize_before_effect()?;
            Ok(ReleaseMutationOutcome::AlreadyApplied)
        }
        ReleasePostStartInspection::ExchangeDone => {
            authorize_before_effect()?;
            recover_exchange_artifact(
                route_root,
                &request.intent,
                request.overlay_identity,
                request.route_count,
                request.overlay_selector,
                request.prior_selector,
                ReleaseSelectorExchange::Publish,
            )?;
            Ok(ReleaseMutationOutcome::Applied)
        }
        ReleasePostStartInspection::SealedBeforeMarker => {
            let mut generation = ReleaseGenerationDirectory::open_existing_sealed(
                route_root,
                request.intent,
                &request.overlay_identity.route_set_digest,
                request.route_count,
            )?;
            authorize_before_effect()?;
            generation.publish(request.prior_selector)?;
            Ok(ReleaseMutationOutcome::Applied)
        }
        ReleasePostStartInspection::MarkerBeforeExchange
        | ReleasePostStartInspection::PreparedExchange => {
            if inspection == ReleasePostStartInspection::PreparedExchange {
                authorize_before_effect()?;
                recover_exchange_artifact(
                    route_root,
                    &request.intent,
                    request.overlay_identity,
                    request.route_count,
                    request.overlay_selector,
                    request.prior_selector,
                    ReleaseSelectorExchange::Publish,
                )?;
            }
            let mut generation = ReleaseGenerationDirectory::open_existing_published(
                route_root,
                request.intent,
                &request.overlay_identity.route_set_digest,
                request.route_count,
            )?;
            authorize_before_effect()?;
            generation.resume_published_from_prior(request.prior_selector)?;
            Ok(ReleaseMutationOutcome::Applied)
        }
    }
}

fn require_running_identity(
    loaded: &PriorLoadedIdentity,
    running: Option<&RunningRouteWorkerIdentity>,
) -> io::Result<()> {
    let exact = match (loaded, running) {
        (PriorLoadedIdentity::BootLive, None) => true,
        (PriorLoadedIdentity::Startup(left), Some(RunningRouteWorkerIdentity::Startup(right))) => {
            left == right
        }
        (
            PriorLoadedIdentity::ReleaseOverlay(left),
            Some(RunningRouteWorkerIdentity::ReleaseOverlay(right)),
        ) => left == right,
        (
            PriorLoadedIdentity::RouteSet(left),
            Some(RunningRouteWorkerIdentity::RouteSet(right)),
        ) => left == right,
        _ => false,
    };
    if exact {
        Ok(())
    } else {
        Err(invalid(
            "running route worker identity differs from current",
        ))
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::other(message)
}

#[cfg(test)]
mod tests {
    use std::fs::{DirBuilder, Permissions};
    use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _, symlink};
    use std::path::PathBuf;

    use uuid::Uuid;

    use super::*;
    use crate::docker_driver::release_generation_fs::SealedReleaseGeneration;

    struct Root(PathBuf);

    impl Root {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("mb-release-recovery-{}", Uuid::new_v4()));
            DirBuilder::new().mode(0o750).create(&path).unwrap();
            std::fs::create_dir(path.join("generations")).unwrap();
            std::fs::set_permissions(path.join("generations"), Permissions::from_mode(0o750))
                .unwrap();
            SharedOdooHostGuard::prepare(&path).unwrap();
            Self(path)
        }

        fn install_plain(&self, name: &str) -> PriorSelector {
            let directory = self.0.join("generations").join(name);
            std::fs::create_dir(&directory).unwrap();
            std::fs::set_permissions(&directory, Permissions::from_mode(0o750)).unwrap();
            symlink(format!("generations/{name}"), self.0.join("current")).unwrap();
            observe_current_selector(&self.0).unwrap()
        }
    }

    impl Drop for Root {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn digest(marker: char) -> String {
        format!("sha256:{}", marker.to_string().repeat(64))
    }

    fn intent(fleet: Uuid, operation: Uuid, kind: ReleaseOverlayKind) -> ReleaseGenerationIntent {
        ReleaseGenerationIntent::new(fleet, operation, 9, kind, "green").unwrap()
    }

    fn seal(
        root: &Root,
        intent: ReleaseGenerationIntent,
    ) -> (ReleaseGenerationDirectory, SealedReleaseGeneration) {
        let mut generation = ReleaseGenerationDirectory::create_or_open(&root.0, intent).unwrap();
        let workshop = Uuid::parse_str("10000000-0000-4000-8000-000000000001").unwrap();
        let mut sealer = generation.begin_seal().unwrap();
        sealer
            .stage_route(
                workshop,
                1,
                &digest('a'),
                &digest('b'),
                b"server { return 204; }\n",
            )
            .unwrap();
        let sealed = sealer.finish().unwrap().clone();
        (generation, sealed)
    }

    #[tokio::test]
    async fn callback_crash_precedes_marker_and_exchange() {
        let root = Root::new();
        let prior = root.install_plain("boot-live");
        let candidate_intent = intent(
            Uuid::new_v4(),
            Uuid::new_v4(),
            ReleaseOverlayKind::Candidate,
        );
        let (_directory, sealed) = seal(&root, candidate_intent.clone());
        let guard = SharedOdooHostGuard::acquire(&root.0).await.unwrap();
        assert!(
            publish_release_candidate_forward(
                &guard,
                &root.0,
                ReleasePublicationRecoveryRequest {
                    phase: ReleaseRecoveryPhase::CandidateSealed,
                    intent: candidate_intent.clone(),
                    overlay_identity: &sealed.identity,
                    route_count: 1,
                    overlay_selector: &sealed.selector,
                    prior_selector: &prior,
                },
                || Err(io::Error::other("database intent failed"))
            )
            .is_err()
        );
        assert_eq!(observe_current_selector(&root.0).unwrap(), prior);
        assert_eq!(
            inspect_release_artifact(&root.0, &candidate_intent, &sealed.identity, 1, false)
                .unwrap(),
            ReleaseArtifactInspection::Exact {
                selector: sealed.selector,
                identity: sealed.identity,
                publication_started: false
            }
        );
    }

    #[tokio::test]
    async fn marker_and_prepared_exchange_resume_forward() {
        for shape in ["marker", "prepared"] {
            let root = Root::new();
            let prior = root.install_plain("boot-live");
            let candidate_intent = intent(
                Uuid::new_v4(),
                Uuid::new_v4(),
                ReleaseOverlayKind::Candidate,
            );
            let (mut generation, sealed) = seal(&root, candidate_intent.clone());
            if shape == "marker" {
                generation.test_install_publication_marker().unwrap();
            } else {
                generation.test_prepare_publish_exchange().unwrap();
            }
            drop(generation);
            let guard = SharedOdooHostGuard::acquire(&root.0).await.unwrap();
            let mut authorizations = 0;
            assert_eq!(
                publish_release_candidate_forward(
                    &guard,
                    &root.0,
                    ReleasePublicationRecoveryRequest {
                        phase: ReleaseRecoveryPhase::CandidatePublicationStarted,
                        intent: candidate_intent,
                        overlay_identity: &sealed.identity,
                        route_count: 1,
                        overlay_selector: &sealed.selector,
                        prior_selector: &prior,
                    },
                    || {
                        authorizations += 1;
                        Ok(())
                    },
                )
                .unwrap(),
                ReleaseMutationOutcome::Applied
            );
            assert_eq!(observe_current_selector(&root.0).unwrap(), sealed.selector);
            assert!(authorizations >= 1);
        }
    }

    #[tokio::test]
    async fn exchanged_artifact_is_authenticated_and_cleaned() {
        let root = Root::new();
        let prior = root.install_plain("boot-live");
        let candidate_intent = intent(
            Uuid::new_v4(),
            Uuid::new_v4(),
            ReleaseOverlayKind::Candidate,
        );
        let (mut generation, sealed) = seal(&root, candidate_intent.clone());
        assert!(
            generation
                .test_crash_after_publish_exchange(&prior)
                .is_err()
        );
        drop(generation);
        assert_eq!(observe_current_selector(&root.0).unwrap(), sealed.selector);
        let guard = SharedOdooHostGuard::acquire(&root.0).await.unwrap();
        assert_eq!(
            publish_release_candidate_forward(
                &guard,
                &root.0,
                ReleasePublicationRecoveryRequest {
                    phase: ReleaseRecoveryPhase::CandidatePublicationStarted,
                    intent: candidate_intent.clone(),
                    overlay_identity: &sealed.identity,
                    route_count: 1,
                    overlay_selector: &sealed.selector,
                    prior_selector: &prior,
                },
                || Ok(()),
            )
            .unwrap(),
            ReleaseMutationOutcome::Applied
        );
        assert_eq!(observe_current_selector(&root.0).unwrap(), sealed.selector);
        let selected_before = observe_current_selector(&root.0).unwrap();
        assert!(
            publish_release_candidate_forward(
                &guard,
                &root.0,
                ReleasePublicationRecoveryRequest {
                    phase: ReleaseRecoveryPhase::AwaitingWorkerFinalize,
                    intent: candidate_intent,
                    overlay_identity: &sealed.identity,
                    route_count: 1,
                    overlay_selector: &sealed.selector,
                    prior_selector: &prior,
                },
                || Err(io::Error::other("current claim authorization failed")),
            )
            .is_err()
        );
        assert_eq!(observe_current_selector(&root.0).unwrap(), selected_before);
    }

    #[tokio::test]
    async fn pre_start_disposal_is_exact_and_idempotent() {
        let root = Root::new();
        root.install_plain("boot-live");
        let release_intent = intent(
            Uuid::new_v4(),
            Uuid::new_v4(),
            ReleaseOverlayKind::Maintenance,
        );
        let _generation =
            ReleaseGenerationDirectory::create_or_open(&root.0, release_intent.clone()).unwrap();
        let guard = SharedOdooHostGuard::acquire(&root.0).await.unwrap();
        assert!(
            dispose_release_pre_start(
                &guard,
                &root.0,
                ReleaseRecoveryPhase::MaintenanceStaging,
                &release_intent,
                || Err(io::Error::other("disposal authorization failed")),
            )
            .is_err()
        );
        assert!(
            root.0
                .join("generations")
                .join(
                    ReleaseGenerationName::new(
                        release_intent.fleet_run_id,
                        release_intent.overlay_kind,
                    )
                    .as_str()
                )
                .is_dir()
        );
        assert_eq!(
            dispose_release_pre_start(
                &guard,
                &root.0,
                ReleaseRecoveryPhase::MaintenanceStaging,
                &release_intent,
                || Ok(())
            )
            .unwrap(),
            ReleaseMutationOutcome::Applied
        );
        assert_eq!(
            dispose_release_pre_start(
                &guard,
                &root.0,
                ReleaseRecoveryPhase::MaintenanceStaging,
                &release_intent,
                || Ok(())
            )
            .unwrap(),
            ReleaseMutationOutcome::AlreadyAbsent
        );
    }

    #[test]
    fn third_selector_is_unknown_and_worker_identity_race_fails() {
        let root = Root::new();
        let current = root.install_plain("boot-live");
        let other_path = root.0.join("generations/other-live");
        std::fs::create_dir(&other_path).unwrap();
        std::fs::set_permissions(&other_path, Permissions::from_mode(0o750)).unwrap();
        let other = super::super::route_generation_fs::observe_generation_selector(
            &root.0,
            "generations/other-live",
        )
        .unwrap();
        let identity = ReleaseOverlayGenerationIdentity::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            9,
            ReleaseOverlayKind::Maintenance,
            digest('a'),
            "green",
        )
        .unwrap();
        let candidate_identity = ReleaseOverlayGenerationIdentity::new(
            identity.fleet_run_id,
            identity.driver_operation_id,
            9,
            ReleaseOverlayKind::Candidate,
            digest('b'),
            "green",
        )
        .unwrap();
        let expected = ReleaseCurrentExpectation {
            prior: &other,
            prior_identity: &PriorLoadedIdentity::BootLive,
            maintenance_selector: &other,
            maintenance_identity: &identity,
            candidate_selector: &other,
            candidate_identity: &candidate_identity,
        };
        let classified = classify_release_current(&root.0, &expected, None).unwrap();
        assert_eq!(classified.kind, ReleaseCurrentKind::Unknown);
        assert_eq!(classified.selector, current);
        assert!(
            classify_release_current(
                &root.0,
                &expected,
                Some(&RunningRouteWorkerIdentity::ReleaseOverlay(
                    identity.clone()
                ))
            )
            .is_err()
        );

        let wrong_prior = ReleaseCurrentExpectation {
            prior: &current,
            prior_identity: &PriorLoadedIdentity::ReleaseOverlay(identity.clone()),
            maintenance_selector: &other,
            maintenance_identity: &identity,
            candidate_selector: &other,
            candidate_identity: &candidate_identity,
        };
        assert_eq!(
            classify_release_current(&root.0, &wrong_prior, None)
                .unwrap()
                .kind,
            ReleaseCurrentKind::Unknown
        );
    }

    #[test]
    fn module_is_registered_without_callsite() {
        let source = include_str!("../docker_driver.rs");
        assert_eq!(source.matches("mod release_route_recovery;").count(), 1);
        assert_eq!(source.matches("release_route_recovery::").count(), 0);
        assert!(!source.contains("use release_route_recovery::*"));
    }
}
