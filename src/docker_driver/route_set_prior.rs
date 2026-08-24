//! Dormant universal observation of the generation selected before a route-set publication.
//!
//! The selector and directory identity are filesystem facts. The loaded identity
//! is parsed according to the selected generation's closed naming protocol and
//! then bound to the matching loopback-only Nginx endpoint. Merely registering
//! this module performs no observation and changes no active writer.
#![allow(dead_code)]

use std::fs::File;
use std::io;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

use serde_json::Value;

use super::gateway::{
    GatewayGenerationIdentity, RELEASE_OVERLAY_GENERATION_FILE, ROUTE_SET_GENERATION_FILE,
    ReleaseOverlayGenerationIdentity, RouteSetGenerationIdentity,
    observe_running_gateway_generation, observe_running_release_overlay_generation,
    observe_running_route_set_generation, parse_gateway_generation_config,
    parse_release_overlay_generation_config, parse_route_set_generation_config,
};
use super::route_generation_fs::{
    FILE_MODE, GENERATIONS_DIRECTORY, GENERATIONS_MODE, MAX_ROUTE_BYTES, PriorSelector,
    ROUTE_ROOT_MODE, SEALED_MODE, cstring, ensure_same_filesystem, invalid_state,
    observe_current_selector, open_at_directory, open_at_file, open_directory, read_bounded,
    selector_generation_name, validate_directory, validate_regular_file,
};
use super::startup_generation_fs::STARTUP_GATEWAY_GENERATION_FILE;
use super::{DriverError, DriverState};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum PriorLoadedIdentity {
    /// Mutable compatibility state with no exact loopback worker identity.
    /// It may be classified by recovery tooling but cannot authorize a new
    /// route-set publication; startup must establish an identity-bearing
    /// immutable generation first.
    BootLive,
    Startup(GatewayGenerationIdentity),
    ReleaseOverlay(ReleaseOverlayGenerationIdentity),
    RouteSet(RouteSetGenerationIdentity),
}

impl PriorLoadedIdentity {
    pub(super) fn as_database_json(&self) -> Result<Option<Value>, DriverError> {
        match self {
            Self::BootLive => Ok(None),
            Self::Startup(identity) => serde_json::to_value(identity).map(Some),
            Self::ReleaseOverlay(identity) => serde_json::to_value(identity).map(Some),
            Self::RouteSet(identity) => serde_json::to_value(identity).map(Some),
        }
        .map_err(DriverError::internal)
    }

    async fn observe_running(&self, state: &DriverState) -> Result<(), DriverError> {
        match self {
            Self::BootLive => Err(DriverError::internal(
                "boot-live has no exact loaded-worker identity; establish an identity-bearing generation first",
            )),
            Self::Startup(identity) => observe_running_gateway_generation(state, identity)
                .await
                .map(drop),
            Self::ReleaseOverlay(identity) => {
                observe_running_release_overlay_generation(state, identity)
                    .await
                    .map(drop)
            }
            Self::RouteSet(identity) => observe_running_route_set_generation(state, identity)
                .await
                .map(drop),
        }
    }

    const fn has_exact_worker_endpoint(&self) -> bool {
        !matches!(self, Self::BootLive)
    }
}

/// Observe the selected filesystem identity, require the corresponding worker
/// endpoint to serve it, and then prove that neither fact changed meanwhile.
#[tracing::instrument(
    name = "deployment_driver.route_set.observe_prior_loaded_identity_dormant",
    skip_all,
    fields(prior.selector = prior.target(), prior.kind = tracing::field::Empty)
)]
pub(super) async fn observe_bound_prior_loaded_identity(
    state: &DriverState,
    prior: &PriorSelector,
) -> Result<PriorLoadedIdentity, DriverError> {
    let first = observe_prior_loaded_identity(&state.config.route_root, prior)
        .map_err(DriverError::internal)?;
    tracing::Span::current().record("prior.kind", first.kind());
    if !first.has_exact_worker_endpoint() {
        return Err(DriverError::internal(
            "boot-live cannot be bound to an exact running worker; establish an identity-bearing generation first",
        ));
    }
    first.observe_running(state).await?;
    let second = observe_prior_loaded_identity(&state.config.route_root, prior)
        .map_err(DriverError::internal)?;
    if second != first {
        return Err(DriverError::internal(
            "prior loaded generation changed during worker observation",
        ));
    }
    Ok(first)
}

/// Startup is the sole route-set writer allowed to replace the compatibility
/// boot-live selector. The host-wide guard must be held by the caller; this
/// double observation prevents silently accepting a selector/identity race.
pub(super) fn observe_startup_boot_live_prior(
    route_root: &Path,
    prior: &PriorSelector,
) -> Result<PriorLoadedIdentity, DriverError> {
    let first = observe_prior_loaded_identity(route_root, prior).map_err(DriverError::internal)?;
    if first != PriorLoadedIdentity::BootLive {
        return Err(DriverError::internal(
            "startup route-set prior is not boot-live",
        ));
    }
    let second = observe_prior_loaded_identity(route_root, prior).map_err(DriverError::internal)?;
    if second != first {
        return Err(DriverError::internal(
            "startup boot-live prior changed during observation",
        ));
    }
    Ok(first)
}

pub(super) async fn observe_startup_prior_loaded_identity(
    state: &DriverState,
    prior: &PriorSelector,
) -> Result<PriorLoadedIdentity, DriverError> {
    let first = observe_prior_loaded_identity(&state.config.route_root, prior)
        .map_err(DriverError::internal)?;
    if first == PriorLoadedIdentity::BootLive {
        return observe_startup_boot_live_prior(&state.config.route_root, prior);
    }
    first.observe_running(state).await?;
    let second = observe_prior_loaded_identity(&state.config.route_root, prior)
        .map_err(DriverError::internal)?;
    if second != first {
        return Err(DriverError::internal(
            "startup prior changed during worker observation",
        ));
    }
    Ok(first)
}

impl PriorLoadedIdentity {
    const fn kind(&self) -> &'static str {
        match self {
            Self::BootLive => "boot_live",
            Self::Startup(_) => "startup",
            Self::ReleaseOverlay(_) => "release_overlay",
            Self::RouteSet(_) => "route_set",
        }
    }
}

pub(super) fn observe_prior_loaded_identity(
    route_root: &Path,
    prior: &PriorSelector,
) -> io::Result<PriorLoadedIdentity> {
    observe_prior_loaded_identity_with_hook(route_root, prior, || {})
}

fn observe_prior_loaded_identity_with_hook(
    route_root: &Path,
    prior: &PriorSelector,
    before_final_observation: impl FnOnce(),
) -> io::Result<PriorLoadedIdentity> {
    if observe_current_selector(route_root)? != *prior {
        return Err(invalid_state(
            "current selector differs from recorded prior",
        ));
    }
    let root = open_directory(route_root)?;
    validate_directory(&root, ROUTE_ROOT_MODE, "route root")?;
    let generations = open_at_directory(&root, &cstring(GENERATIONS_DIRECTORY)?)?;
    validate_directory(
        &generations,
        GENERATIONS_MODE,
        "route generations directory",
    )?;
    ensure_same_filesystem(&root, &generations)?;
    let generation_name = selector_generation_name(prior.target())?;
    let directory = open_at_directory(&generations, &cstring(generation_name)?)?;
    validate_directory(&directory, SEALED_MODE, "prior route generation")?;
    ensure_same_filesystem(&generations, &directory)?;
    let metadata = directory.metadata()?;
    if metadata.dev() != prior.directory_device() || metadata.ino() != prior.directory_inode() {
        return Err(invalid_state("recorded prior directory identity changed"));
    }

    let startup = read_optional_identity(&directory, STARTUP_GATEWAY_GENERATION_FILE)?;
    let release = read_optional_identity(&directory, RELEASE_OVERLAY_GENERATION_FILE)?;
    let route_set = read_optional_identity(&directory, ROUTE_SET_GENERATION_FILE)?;
    let identity_count = usize::from(startup.is_some())
        + usize::from(release.is_some())
        + usize::from(route_set.is_some());
    let identity = if generation_name == "boot-live" {
        if identity_count != 0 {
            return Err(invalid_state("boot-live generation has an identity file"));
        }
        PriorLoadedIdentity::BootLive
    } else {
        if identity_count != 1 {
            return Err(invalid_state(
                "prior generation must contain exactly one loaded identity",
            ));
        }
        match (startup, release, route_set) {
            (Some(bytes), None, None) => {
                let parsed = parse_gateway_generation_config(&bytes).map_err(driver_io)?;
                if generation_name != format!("startup-{}", parsed.effect_run_id) {
                    return Err(invalid_state("startup selector and identity differ"));
                }
                PriorLoadedIdentity::Startup(parsed)
            }
            (None, Some(bytes), None) => {
                let parsed = parse_release_overlay_generation_config(&bytes).map_err(driver_io)?;
                let expected = format!(
                    "release-{}-{}",
                    parsed.fleet_run_id.simple(),
                    parsed.overlay_kind.as_str()
                );
                if generation_name != expected {
                    return Err(invalid_state("release selector and identity differ"));
                }
                PriorLoadedIdentity::ReleaseOverlay(parsed)
            }
            (None, None, Some(bytes)) => {
                let parsed = parse_route_set_generation_config(&bytes).map_err(driver_io)?;
                let suffix = match parsed.publication_kind {
                    super::gateway::RouteSetPublicationKind::Projection => "projection",
                    super::gateway::RouteSetPublicationKind::RecoveryMaintenance => {
                        "recovery-maintenance"
                    }
                    super::gateway::RouteSetPublicationKind::RecoveryRestore => "recovery-restore",
                    super::gateway::RouteSetPublicationKind::Startup => "startup",
                };
                let expected = format!("route-{}-{suffix}", parsed.publication_id.simple());
                if generation_name != expected {
                    return Err(invalid_state("route-set selector and identity differ"));
                }
                PriorLoadedIdentity::RouteSet(parsed)
            }
            _ => unreachable!("identity count was exactly one"),
        }
    };

    before_final_observation();
    if observe_current_selector(route_root)? != *prior {
        return Err(invalid_state(
            "current selector changed during prior identity observation",
        ));
    }
    Ok(identity)
}

fn read_optional_identity(directory: &File, name: &str) -> io::Result<Option<Vec<u8>>> {
    let file = match open_at_file(directory, &cstring(name)?) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    validate_regular_file(&file, FILE_MODE, "prior generation identity")?;
    read_bounded(file, MAX_ROUTE_BYTES).map(Some)
}

fn driver_io(error: DriverError) -> io::Error {
    io::Error::other(error.1)
}

#[cfg(test)]
mod tests {
    use std::fs::DirBuilder;
    use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
    use std::path::PathBuf;

    use uuid::Uuid;

    use super::*;
    use crate::docker_driver::gateway::{
        ReleaseOverlayGenerationIdentity, ReleaseOverlayKind, RouteSetGenerationIdentity,
        RouteSetPublicationKind, gateway_generation_config, release_overlay_generation_config,
        route_set_generation_config,
    };

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("mb-prior-{}", Uuid::new_v4()));
            DirBuilder::new()
                .mode(ROUTE_ROOT_MODE)
                .create(&path)
                .unwrap();
            DirBuilder::new()
                .mode(GENERATIONS_MODE)
                .create(path.join(GENERATIONS_DIRECTORY))
                .unwrap();
            Self(path)
        }

        fn select(&self, name: &str, files: &[(&str, String)]) -> PriorSelector {
            let directory = self.0.join(GENERATIONS_DIRECTORY).join(name);
            DirBuilder::new()
                .mode(SEALED_MODE)
                .create(&directory)
                .unwrap();
            for (file, contents) in files {
                let path = directory.join(file);
                std::fs::write(&path, contents).unwrap();
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(FILE_MODE)).unwrap();
            }
            std::os::unix::fs::symlink(
                format!("{GENERATIONS_DIRECTORY}/{name}"),
                self.0.join("current"),
            )
            .unwrap();
            observe_current_selector(&self.0).unwrap()
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn digest(marker: char) -> String {
        format!("sha256:{}", marker.to_string().repeat(64))
    }

    #[test]
    fn observes_each_closed_prior_identity_kind() {
        let boot = TestRoot::new();
        let prior = boot.select("boot-live", &[]);
        assert_eq!(
            observe_prior_loaded_identity(&boot.0, &prior).unwrap(),
            PriorLoadedIdentity::BootLive
        );
        assert_eq!(
            observe_startup_boot_live_prior(&boot.0, &prior).unwrap(),
            PriorLoadedIdentity::BootLive
        );

        let startup = TestRoot::new();
        let startup_identity = GatewayGenerationIdentity {
            effect_run_id: Uuid::new_v4(),
            sealed_digest: digest('a'),
        };
        let name = format!("startup-{}", startup_identity.effect_run_id);
        let prior = startup.select(
            &name,
            &[(
                STARTUP_GATEWAY_GENERATION_FILE,
                gateway_generation_config(&startup_identity).unwrap(),
            )],
        );
        assert_eq!(
            observe_prior_loaded_identity(&startup.0, &prior).unwrap(),
            PriorLoadedIdentity::Startup(startup_identity.clone())
        );
        let database_identity = PriorLoadedIdentity::Startup(startup_identity.clone())
            .as_database_json()
            .unwrap();
        assert_eq!(
            database_identity,
            Some(serde_json::json!({
                "effect_run_id": startup_identity.effect_run_id,
                "sealed_digest": startup_identity.sealed_digest,
            }))
        );
        assert_eq!(database_identity.unwrap().as_object().unwrap().len(), 2);
        assert!(observe_startup_boot_live_prior(&startup.0, &prior).is_err());

        let release = TestRoot::new();
        let release_identity = ReleaseOverlayGenerationIdentity::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            7,
            ReleaseOverlayKind::Candidate,
            digest('b'),
            "blue",
        )
        .unwrap();
        let name = format!(
            "release-{}-candidate",
            release_identity.fleet_run_id.simple()
        );
        let prior = release.select(
            &name,
            &[(
                RELEASE_OVERLAY_GENERATION_FILE,
                release_overlay_generation_config(&release_identity).unwrap(),
            )],
        );
        assert_eq!(
            observe_prior_loaded_identity(&release.0, &prior).unwrap(),
            PriorLoadedIdentity::ReleaseOverlay(release_identity)
        );

        let route_set = TestRoot::new();
        let route_identity = RouteSetGenerationIdentity::new(
            Uuid::new_v4(),
            RouteSetPublicationKind::Projection,
            8,
            Uuid::new_v4(),
            9,
            digest('c'),
        )
        .unwrap();
        let name = format!(
            "route-{}-projection",
            route_identity.publication_id.simple()
        );
        let prior = route_set.select(
            &name,
            &[(
                ROUTE_SET_GENERATION_FILE,
                route_set_generation_config(&route_identity).unwrap(),
            )],
        );
        assert_eq!(
            observe_prior_loaded_identity(&route_set.0, &prior).unwrap(),
            PriorLoadedIdentity::RouteSet(route_identity)
        );
    }

    #[test]
    fn boot_live_is_classifiable_but_cannot_satisfy_worker_binding() {
        let root = TestRoot::new();
        let prior = root.select("boot-live", &[]);
        let identity = observe_prior_loaded_identity(&root.0, &prior).unwrap();
        assert_eq!(identity, PriorLoadedIdentity::BootLive);
        assert!(!identity.has_exact_worker_endpoint());

        let source = include_str!("route_set_prior.rs");
        let bound_observer = source
            .split("pub(super) async fn observe_bound_prior_loaded_identity(")
            .nth(1)
            .unwrap()
            .split("impl PriorLoadedIdentity")
            .next()
            .unwrap();
        assert!(bound_observer.contains("if !first.has_exact_worker_endpoint()"));
        assert!(bound_observer.contains("identity-bearing generation first"));
    }

    #[test]
    fn rejects_ambiguous_noncanonical_and_selector_mismatched_identity() {
        let ambiguous = TestRoot::new();
        let startup_identity = GatewayGenerationIdentity {
            effect_run_id: Uuid::new_v4(),
            sealed_digest: digest('d'),
        };
        let route_identity = RouteSetGenerationIdentity::new(
            Uuid::new_v4(),
            RouteSetPublicationKind::Projection,
            1,
            Uuid::new_v4(),
            2,
            digest('e'),
        )
        .unwrap();
        let name = format!("startup-{}", startup_identity.effect_run_id);
        let prior = ambiguous.select(
            &name,
            &[
                (
                    STARTUP_GATEWAY_GENERATION_FILE,
                    gateway_generation_config(&startup_identity).unwrap(),
                ),
                (
                    ROUTE_SET_GENERATION_FILE,
                    route_set_generation_config(&route_identity).unwrap(),
                ),
            ],
        );
        assert!(observe_prior_loaded_identity(&ambiguous.0, &prior).is_err());

        let noncanonical = TestRoot::new();
        let prior = noncanonical.select(
            &name,
            &[(STARTUP_GATEWAY_GENERATION_FILE, "not canonical\n".into())],
        );
        assert!(observe_prior_loaded_identity(&noncanonical.0, &prior).is_err());

        let mismatch = TestRoot::new();
        let prior = mismatch.select(
            &format!("startup-{}", Uuid::new_v4()),
            &[(
                STARTUP_GATEWAY_GENERATION_FILE,
                gateway_generation_config(&startup_identity).unwrap(),
            )],
        );
        assert!(observe_prior_loaded_identity(&mismatch.0, &prior).is_err());
    }

    #[test]
    fn rejects_selector_drift_during_identity_observation() {
        let root = TestRoot::new();
        let identity = GatewayGenerationIdentity {
            effect_run_id: Uuid::new_v4(),
            sealed_digest: digest('f'),
        };
        let name = format!("startup-{}", identity.effect_run_id);
        let prior = root.select(
            &name,
            &[(
                STARTUP_GATEWAY_GENERATION_FILE,
                gateway_generation_config(&identity).unwrap(),
            )],
        );
        let other = root.0.join(GENERATIONS_DIRECTORY).join("boot-live");
        DirBuilder::new().mode(SEALED_MODE).create(other).unwrap();
        let result = observe_prior_loaded_identity_with_hook(&root.0, &prior, || {
            std::fs::remove_file(root.0.join("current")).unwrap();
            std::os::unix::fs::symlink("generations/boot-live", root.0.join("current")).unwrap();
        });
        assert!(result.is_err());
    }

    #[test]
    fn module_is_registered_but_has_no_active_callsite() {
        let driver_root = include_str!("../docker_driver.rs");
        assert_eq!(driver_root.matches("mod route_set_prior;").count(), 1);
        assert!(!driver_root.contains("use route_set_prior"));
        assert!(!driver_root.contains("route_set_prior::"));
        for active in [
            include_str!("gateway.rs"),
            include_str!("startup.rs"),
            include_str!("release.rs"),
            include_str!("recovery.rs"),
        ] {
            assert!(!active.contains("route_set_prior"));
        }
    }
}
