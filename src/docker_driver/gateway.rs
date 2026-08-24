use super::*;
use std::path::{Component, PathBuf};

const GATEWAY_GENERATION_ENDPOINT: &str = "http://127.0.0.1:8081/_mb/generation";
const RELEASE_GATEWAY_GENERATION_ENDPOINT: &str = "http://127.0.0.1:8082/_mb/release-generation";
#[allow(dead_code)] // consumed when dormant release-overlay protocol v2 is wired
const RELEASE_OVERLAY_GENERATION_ENDPOINT: &str =
    "http://127.0.0.1:8083/_mb/release-overlay-generation";
#[allow(dead_code)] // consumed when immutable normal route publication is wired
const ROUTE_SET_GENERATION_ENDPOINT: &str = "http://127.0.0.1:8084/_mb/route-generation";
const ROUTE_WORKER_IDENTITY_ENDPOINT: &str = "http://127.0.0.1:8085/_mb/route-worker-identity";
const IDENTITY_SERVER_END: &[u8] = b"';\n  }\n  location / { return 404; }\n}\n";
pub(super) const RELEASE_GATEWAY_GENERATION_FILE: &str = "mb-release-generation.conf";
pub(super) const RELEASE_OVERLAY_GENERATION_FILE: &str = "mb-release-overlay-generation.conf";
#[allow(dead_code)] // consumed when immutable normal route publication is wired
pub(super) const ROUTE_SET_GENERATION_FILE: &str = "mb-route-generation.conf";
const RELEASE_GATEWAY_IDENTITY_PROTOCOL_VERSION: u8 = 1;
const SELECTED_ROUTE_LINK: &str = "current";
const ROUTE_GENERATIONS_DIRECTORY: &str = "generations";

/// Resolve the route generation selected by the driver-owned `current` link.
///
/// Route effects resolve this once before constructing their live and temporary
/// paths. The selector is deliberately restricted to one relative child of the
/// generations directory: an absolute link, traversal, nested target, symlinked
/// generations directory, or non-directory target fails closed.
pub(super) fn selected_route_root(route_root: &Path) -> Result<PathBuf, DriverError> {
    let selector =
        std::fs::read_link(route_root.join(SELECTED_ROUTE_LINK)).map_err(DriverError::internal)?;
    let mut components = selector.components();
    let generation_directory = components.next();
    let generation_name = components.next();
    if generation_directory != Some(Component::Normal(ROUTE_GENERATIONS_DIRECTORY.as_ref()))
        || !matches!(generation_name, Some(Component::Normal(_)))
        || components.next().is_some()
    {
        return Err(DriverError::internal(
            "gateway route selector has an invalid target",
        ));
    }

    let canonical_root = std::fs::canonicalize(route_root).map_err(DriverError::internal)?;
    let generations_path = route_root.join(ROUTE_GENERATIONS_DIRECTORY);
    if std::fs::symlink_metadata(&generations_path)
        .map_err(DriverError::internal)?
        .file_type()
        .is_symlink()
    {
        return Err(DriverError::internal(
            "gateway route generations directory must not be a symlink",
        ));
    }
    let generations = std::fs::canonicalize(&generations_path).map_err(DriverError::internal)?;
    if generations.parent() != Some(canonical_root.as_path()) {
        return Err(DriverError::internal(
            "gateway route generations directory escapes its root",
        ));
    }
    let selected_path = route_root.join(&selector);
    if std::fs::symlink_metadata(&selected_path)
        .map_err(DriverError::internal)?
        .file_type()
        .is_symlink()
    {
        return Err(DriverError::internal(
            "gateway route generation must not be a symlink",
        ));
    }
    let selected = std::fs::canonicalize(selected_path).map_err(DriverError::internal)?;
    if selected.parent() != Some(generations.as_path()) || !selected.is_dir() {
        return Err(DriverError::internal(
            "gateway route selector target is not a generation directory",
        ));
    }
    Ok(selected)
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct GatewayGenerationIdentity {
    pub effect_run_id: Uuid,
    pub sealed_digest: String,
}

impl GatewayGenerationIdentity {
    fn validate(&self) -> Result<(), DriverError> {
        if self.effect_run_id.is_nil() {
            return Err(DriverError::internal(
                "gateway generation identity is invalid",
            ));
        }
        let Some(hex) = self.sealed_digest.strip_prefix("sha256:") else {
            return Err(DriverError::internal(
                "gateway generation digest is invalid",
            ));
        };
        if hex.len() != 64
            || !hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(DriverError::internal(
                "gateway generation digest is invalid",
            ));
        }
        Ok(())
    }
}

/// Render the driver-only endpoint embedded in a selected Nginx generation.
///
/// The response is a literal in the parsed Nginx configuration, not a file
/// read at request time. An exact response therefore proves which generation a
/// running worker loaded. The staged publisher will place this server beside
/// the candidate tenant routes; it is deliberately not installed by today's
/// flat live-directory writer.
#[allow(dead_code)]
pub(super) fn gateway_generation_config(
    identity: &GatewayGenerationIdentity,
) -> Result<String, DriverError> {
    identity.validate()?;
    let body = serde_json::to_string(identity).map_err(DriverError::internal)?;
    let universal = running_route_worker_identity_config(&RunningRouteWorkerIdentity::Startup(
        identity.clone(),
    ))?;
    Ok(format!(
        "server {{\n  listen 127.0.0.1:8081;\n  server_name _;\n  location = /_mb/generation {{\n    default_type application/json;\n    add_header Cache-Control 'no-store' always;\n    return 200 '{body}';\n  }}\n  location / {{ return 404; }}\n}}\n{universal}"
    ))
}

fn parse_gateway_generation(bytes: &[u8]) -> Result<GatewayGenerationIdentity, DriverError> {
    if bytes.len() > 1024 {
        return Err(DriverError::internal(
            "gateway generation observation exceeded its bound",
        ));
    }
    let identity: GatewayGenerationIdentity = serde_json::from_slice(bytes)
        .map_err(|_| DriverError::internal("invalid gateway generation observation"))?;
    identity.validate()?;
    Ok(identity)
}

/// Parse the exact canonical Nginx snippet stored by a startup generation.
pub(super) fn parse_gateway_generation_config(
    bytes: &[u8],
) -> Result<GatewayGenerationIdentity, DriverError> {
    if bytes.len() > 65_536 {
        return Err(DriverError::internal(
            "gateway generation configuration exceeded its bound",
        ));
    }
    let prefix = b"server {\n  listen 127.0.0.1:8081;\n  server_name _;\n  location = /_mb/generation {\n    default_type application/json;\n    add_header Cache-Control 'no-store' always;\n    return 200 '";
    let body = primary_identity_body(bytes, prefix, "gateway generation identity")?;
    let identity = parse_gateway_generation(body)?;
    if gateway_generation_config(&identity)?.as_bytes() != bytes {
        return Err(DriverError::internal(
            "gateway generation identity is not canonical",
        ));
    }
    Ok(identity)
}

/// Observe the generation from the running Nginx worker through a loopback-only
/// endpoint and require an exact effect-run/digest match.
///
/// Kept dormant until the staged selector protocol publishes generation
/// snippets. Calling this against today's flat layout fails closed because no
/// endpoint is installed.
#[allow(dead_code)]
pub(super) async fn observe_running_gateway_generation(
    state: &DriverState,
    expected: &GatewayGenerationIdentity,
) -> Result<GatewayGenerationIdentity, DriverError> {
    expected.validate()?;
    let observed = observe_running_gateway_generation_identity(state).await?;
    if &observed != expected {
        tracing::warn!(
            expected_effect_run_id = %expected.effect_run_id,
            observed_effect_run_id = %observed.effect_run_id,
            "running gateway generation did not match the sealed candidate"
        );
        return Err(DriverError::internal(
            "running gateway generation differs from the sealed candidate",
        ));
    }
    tracing::info!(
        effect_run_id = %observed.effect_run_id,
        "running gateway generation observed"
    );
    Ok(observed)
}

/// Read the bounded, canonical identity embedded in the running Nginx worker.
///
/// Reconciliation uses the unconstrained observation to distinguish an exact
/// prior generation from an exact candidate generation. Callers must still
/// bind the result to a twice-observed filesystem selector before resolving an
/// interrupted publication.
pub(super) async fn observe_running_gateway_generation_identity(
    state: &DriverState,
) -> Result<GatewayGenerationIdentity, DriverError> {
    let bytes = match &state.backend {
        RuntimeBackend::Docker => {
            docker_exec_capture(
                state,
                &state.config.gateway_container,
                &["wget", "-qO-", GATEWAY_GENERATION_ENDPOINT],
                1024,
            )
            .await?
        }
        RuntimeBackend::Quadlet(backend) => {
            backend
                .observe_gateway_generation(
                    &state.config.gateway_container,
                    GATEWAY_GENERATION_ENDPOINT,
                )
                .await?
        }
    };
    parse_gateway_generation(&bytes)
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum ReleaseTargetSlot {
    Blue,
    Green,
}

impl ReleaseTargetSlot {
    pub(super) fn parse(value: &str) -> Result<Self, DriverError> {
        match value {
            "blue" => Ok(Self::Blue),
            "green" => Ok(Self::Green),
            _ => Err(DriverError::internal("release target slot is invalid")),
        }
    }

    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Blue => "blue",
            Self::Green => "green",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct ReleaseGatewayGenerationIdentity {
    pub protocol_version: u8,
    pub fleet_run_id: Uuid,
    pub driver_action_id: Uuid,
    pub original_driver_fence_token: i64,
    pub gateway_configuration_digest: String,
    pub target_slot: ReleaseTargetSlot,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum ReleaseOverlayKind {
    Maintenance,
    Candidate,
}

impl ReleaseOverlayKind {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Maintenance => "maintenance",
            Self::Candidate => "candidate",
        }
    }
}

/// Identity served by an immutable release-overlay generation. It is distinct
/// from `ReleaseGatewayGenerationIdentity`: the latter is the rolling v1
/// activation contract, while this identity binds a complete staged route set
/// to its durable v2 operation before the selector publication boundary.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct ReleaseOverlayGenerationIdentity {
    pub protocol_version: u8,
    pub fleet_run_id: Uuid,
    pub driver_operation_id: Uuid,
    pub original_global_fence_token: i64,
    pub overlay_kind: ReleaseOverlayKind,
    pub route_set_digest: String,
    pub target_slot: ReleaseTargetSlot,
}

impl ReleaseOverlayGenerationIdentity {
    pub(super) fn new(
        fleet_run_id: Uuid,
        driver_operation_id: Uuid,
        original_global_fence_token: i64,
        overlay_kind: ReleaseOverlayKind,
        route_set_digest: String,
        target_slot: &str,
    ) -> Result<Self, DriverError> {
        let identity = Self {
            protocol_version: 1,
            fleet_run_id,
            driver_operation_id,
            original_global_fence_token,
            overlay_kind,
            route_set_digest,
            target_slot: ReleaseTargetSlot::parse(target_slot)?,
        };
        identity.validate()?;
        Ok(identity)
    }

    pub(super) fn validate(&self) -> Result<(), DriverError> {
        if self.protocol_version != 1
            || self.fleet_run_id.is_nil()
            || self.driver_operation_id.is_nil()
            || self.original_global_fence_token <= 0
        {
            return Err(DriverError::internal(
                "release overlay generation identity is invalid",
            ));
        }
        validate_sha256_digest(&self.route_set_digest)
    }
}

pub(super) fn release_overlay_generation_config(
    identity: &ReleaseOverlayGenerationIdentity,
) -> Result<String, DriverError> {
    identity.validate()?;
    let body = serde_json::to_string(identity).map_err(DriverError::internal)?;
    if body.len() > 1024 {
        return Err(DriverError::internal(
            "release overlay generation identity exceeded its bound",
        ));
    }
    let universal = running_route_worker_identity_config(
        &RunningRouteWorkerIdentity::ReleaseOverlay(identity.clone()),
    )?;
    Ok(format!(
        "server {{\n  listen 127.0.0.1:8083;\n  server_name _;\n  location = /_mb/release-overlay-generation {{\n    default_type application/json;\n    add_header Cache-Control 'no-store' always;\n    return 200 '{body}';\n  }}\n  location / {{ return 404; }}\n}}\n{universal}"
    ))
}

pub(super) fn parse_release_overlay_generation_config(
    bytes: &[u8],
) -> Result<ReleaseOverlayGenerationIdentity, DriverError> {
    if bytes.len() > 65_536 {
        return Err(DriverError::internal(
            "release overlay generation configuration exceeded its bound",
        ));
    }
    let prefix = b"server {\n  listen 127.0.0.1:8083;\n  server_name _;\n  location = /_mb/release-overlay-generation {\n    default_type application/json;\n    add_header Cache-Control 'no-store' always;\n    return 200 '";
    let body = primary_identity_body(bytes, prefix, "release overlay identity")?;
    let identity = parse_release_overlay_generation(body)?;
    if release_overlay_generation_config(&identity)?.as_bytes() != bytes {
        return Err(DriverError::internal(
            "release overlay identity is not canonical",
        ));
    }
    Ok(identity)
}

fn parse_release_overlay_generation(
    bytes: &[u8],
) -> Result<ReleaseOverlayGenerationIdentity, DriverError> {
    if bytes.len() > 1024 {
        return Err(DriverError::internal(
            "release overlay generation observation exceeded its bound",
        ));
    }
    let identity: ReleaseOverlayGenerationIdentity = serde_json::from_slice(bytes)
        .map_err(|_| DriverError::internal("invalid release overlay generation observation"))?;
    identity.validate()?;
    Ok(identity)
}

fn release_overlay_observation_matches(
    bytes: &[u8],
    expected: &ReleaseOverlayGenerationIdentity,
) -> bool {
    parse_release_overlay_generation(bytes).is_ok_and(|observed| observed == *expected)
}

#[tracing::instrument(
    name = "deployment_driver.release_overlay.observe_loaded_generation",
    skip_all,
    fields(
        release.fleet_run_id = %expected.fleet_run_id,
        release.driver_operation_id = %expected.driver_operation_id,
        release.overlay_kind = expected.overlay_kind.as_str(),
        release.target_slot = expected.target_slot.as_str(),
        observation.outcome = tracing::field::Empty
    )
)]
#[allow(dead_code)] // consumed when dormant release-overlay protocol v2 is wired
pub(super) async fn observe_running_release_overlay_generation(
    state: &DriverState,
    expected: &ReleaseOverlayGenerationIdentity,
) -> Result<ReleaseOverlayGenerationIdentity, DriverError> {
    expected.validate()?;
    for _ in 0..20 {
        let bytes = match &state.backend {
            RuntimeBackend::Docker => {
                docker_exec_capture(
                    state,
                    &state.config.gateway_container,
                    &["wget", "-qO-", RELEASE_OVERLAY_GENERATION_ENDPOINT],
                    1024,
                )
                .await
            }
            RuntimeBackend::Quadlet(backend) => {
                backend
                    .observe_gateway_generation(
                        &state.config.gateway_container,
                        RELEASE_OVERLAY_GENERATION_ENDPOINT,
                    )
                    .await
            }
        };
        if let Ok(bytes) = bytes
            && release_overlay_observation_matches(&bytes, expected)
        {
            tracing::Span::current().record("observation.outcome", "matched");
            return Ok(expected.clone());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    tracing::Span::current().record("observation.outcome", "mismatched");
    Err(DriverError::internal(
        "running release overlay generation differs from its activation intent",
    ))
}

/// Durable source that authorized a complete immutable route-set generation.
///
/// This identity is shared by future normal projection publication and the
/// two recovery publications. Keeping the kind closed prevents a generation
/// from being reinterpreted by a different writer protocol.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum RouteSetPublicationKind {
    Projection,
    RecoveryMaintenance,
    RecoveryRestore,
    Startup,
}

impl RouteSetPublicationKind {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Projection => "projection",
            Self::RecoveryMaintenance => "recovery_maintenance",
            Self::RecoveryRestore => "recovery_restore",
            Self::Startup => "startup",
        }
    }
}

/// Universal loaded-worker identity for an immutable full route set.
///
/// The identity is intentionally independent of the writer's database row
/// shape. It binds the selected bytes to the publication authority and the
/// one route fence whose operation caused the complete fleet rebuild.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct RouteSetGenerationIdentity {
    pub protocol_version: u8,
    pub publication_id: Uuid,
    pub publication_kind: RouteSetPublicationKind,
    pub global_fence_token: i64,
    pub route_set_digest: String,
    scope: RouteSetPublicationScope,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum RouteSetPublicationScope {
    Fleet {
        startup_effect_run_id: Uuid,
    },
    Workshop {
        target_workshop_id: Uuid,
        target_route_fence_token: i64,
    },
}

impl RouteSetGenerationIdentity {
    pub(super) fn new(
        publication_id: Uuid,
        publication_kind: RouteSetPublicationKind,
        global_fence_token: i64,
        target_workshop_id: Uuid,
        target_route_fence_token: i64,
        route_set_digest: String,
    ) -> Result<Self, DriverError> {
        let identity = Self {
            protocol_version: 1,
            publication_id,
            publication_kind,
            global_fence_token,
            route_set_digest,
            scope: RouteSetPublicationScope::Workshop {
                target_workshop_id,
                target_route_fence_token,
            },
        };
        identity.validate()?;
        Ok(identity)
    }

    pub(super) fn new_startup(
        publication_id: Uuid,
        startup_effect_run_id: Uuid,
        global_fence_token: i64,
        route_set_digest: String,
    ) -> Result<Self, DriverError> {
        let identity = Self {
            protocol_version: 1,
            publication_id,
            publication_kind: RouteSetPublicationKind::Startup,
            global_fence_token,
            route_set_digest,
            scope: RouteSetPublicationScope::Fleet {
                startup_effect_run_id,
            },
        };
        identity.validate()?;
        Ok(identity)
    }

    pub(super) fn validate(&self) -> Result<(), DriverError> {
        let scope_valid = match (self.publication_kind, &self.scope) {
            (
                RouteSetPublicationKind::Startup,
                RouteSetPublicationScope::Fleet {
                    startup_effect_run_id,
                },
            ) => !startup_effect_run_id.is_nil(),
            (
                RouteSetPublicationKind::Projection
                | RouteSetPublicationKind::RecoveryMaintenance
                | RouteSetPublicationKind::RecoveryRestore,
                RouteSetPublicationScope::Workshop {
                    target_workshop_id,
                    target_route_fence_token,
                },
            ) => !target_workshop_id.is_nil() && *target_route_fence_token > 0,
            _ => false,
        };
        if self.protocol_version != 1
            || self.publication_id.is_nil()
            || self.global_fence_token <= 0
            || !scope_valid
        {
            return Err(DriverError::internal(
                "route-set generation identity is invalid",
            ));
        }
        validate_sha256_digest(&self.route_set_digest)
    }

    pub(super) const fn startup_effect_run_id(&self) -> Option<Uuid> {
        match &self.scope {
            RouteSetPublicationScope::Fleet {
                startup_effect_run_id,
            } => Some(*startup_effect_run_id),
            RouteSetPublicationScope::Workshop { .. } => None,
        }
    }

    pub(super) const fn target_workshop_id(&self) -> Option<Uuid> {
        match &self.scope {
            RouteSetPublicationScope::Fleet { .. } => None,
            RouteSetPublicationScope::Workshop {
                target_workshop_id, ..
            } => Some(*target_workshop_id),
        }
    }

    pub(super) const fn target_route_fence_token(&self) -> Option<i64> {
        match &self.scope {
            RouteSetPublicationScope::Fleet { .. } => None,
            RouteSetPublicationScope::Workshop {
                target_route_fence_token,
                ..
            } => Some(*target_route_fence_token),
        }
    }

    #[cfg(test)]
    pub(super) fn set_workshop_scope_for_test(&mut self, workshop_id: Uuid, route_fence: i64) {
        assert!(!workshop_id.is_nil() && route_fence > 0);
        self.scope = RouteSetPublicationScope::Workshop {
            target_workshop_id: workshop_id,
            target_route_fence_token: route_fence,
        };
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StartupRouteSetGenerationIdentityWire {
    protocol_version: u8,
    publication_id: Uuid,
    publication_kind: RouteSetPublicationKind,
    startup_effect_run_id: Uuid,
    global_fence_token: i64,
    route_set_digest: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WorkshopRouteSetGenerationIdentityWire {
    protocol_version: u8,
    publication_id: Uuid,
    publication_kind: RouteSetPublicationKind,
    global_fence_token: i64,
    target_workshop_id: Uuid,
    target_route_fence_token: i64,
    route_set_digest: String,
}

#[derive(Deserialize, Serialize)]
#[serde(untagged)]
enum RouteSetGenerationIdentityWire {
    Startup(StartupRouteSetGenerationIdentityWire),
    Workshop(WorkshopRouteSetGenerationIdentityWire),
}

impl Serialize for RouteSetGenerationIdentity {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match &self.scope {
            RouteSetPublicationScope::Fleet {
                startup_effect_run_id,
            } => StartupRouteSetGenerationIdentityWire {
                protocol_version: self.protocol_version,
                publication_id: self.publication_id,
                publication_kind: self.publication_kind,
                startup_effect_run_id: *startup_effect_run_id,
                global_fence_token: self.global_fence_token,
                route_set_digest: self.route_set_digest.clone(),
            }
            .serialize(serializer),
            RouteSetPublicationScope::Workshop {
                target_workshop_id,
                target_route_fence_token,
            } => WorkshopRouteSetGenerationIdentityWire {
                protocol_version: self.protocol_version,
                publication_id: self.publication_id,
                publication_kind: self.publication_kind,
                global_fence_token: self.global_fence_token,
                target_workshop_id: *target_workshop_id,
                target_route_fence_token: *target_route_fence_token,
                route_set_digest: self.route_set_digest.clone(),
            }
            .serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for RouteSetGenerationIdentity {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let identity = match RouteSetGenerationIdentityWire::deserialize(deserializer)? {
            RouteSetGenerationIdentityWire::Startup(wire) => Self {
                protocol_version: wire.protocol_version,
                publication_id: wire.publication_id,
                publication_kind: wire.publication_kind,
                global_fence_token: wire.global_fence_token,
                route_set_digest: wire.route_set_digest,
                scope: RouteSetPublicationScope::Fleet {
                    startup_effect_run_id: wire.startup_effect_run_id,
                },
            },
            RouteSetGenerationIdentityWire::Workshop(wire) => Self {
                protocol_version: wire.protocol_version,
                publication_id: wire.publication_id,
                publication_kind: wire.publication_kind,
                global_fence_token: wire.global_fence_token,
                route_set_digest: wire.route_set_digest,
                scope: RouteSetPublicationScope::Workshop {
                    target_workshop_id: wire.target_workshop_id,
                    target_route_fence_token: wire.target_route_fence_token,
                },
            },
        };
        identity
            .validate()
            .map_err(|error| serde::de::Error::custom(error.1))?;
        Ok(identity)
    }
}

/// Render the loopback-only literal identity embedded in a route generation.
#[allow(dead_code)] // consumed when immutable normal route publication is wired
pub(super) fn route_set_generation_config(
    identity: &RouteSetGenerationIdentity,
) -> Result<String, DriverError> {
    identity.validate()?;
    let body = serde_json::to_string(identity).map_err(DriverError::internal)?;
    if body.len() > 1024 {
        return Err(DriverError::internal(
            "route-set generation identity exceeded its bound",
        ));
    }
    let universal = running_route_worker_identity_config(&RunningRouteWorkerIdentity::RouteSet(
        identity.clone(),
    ))?;
    Ok(format!(
        "server {{\n  listen 127.0.0.1:8084;\n  server_name _;\n  location = /_mb/route-generation {{\n    default_type application/json;\n    add_header Cache-Control 'no-store' always;\n    return 200 '{body}';\n  }}\n  location / {{ return 404; }}\n}}\n{universal}"
    ))
}

#[allow(dead_code)] // consumed when immutable normal route publication is wired
pub(super) fn parse_route_set_generation_config(
    bytes: &[u8],
) -> Result<RouteSetGenerationIdentity, DriverError> {
    if bytes.len() > 65_536 {
        return Err(DriverError::internal(
            "route-set generation configuration exceeded its bound",
        ));
    }
    let prefix = b"server {\n  listen 127.0.0.1:8084;\n  server_name _;\n  location = /_mb/route-generation {\n    default_type application/json;\n    add_header Cache-Control 'no-store' always;\n    return 200 '";
    let body = primary_identity_body(bytes, prefix, "route-set generation identity")?;
    let identity = parse_route_set_generation(body)?;
    if route_set_generation_config(&identity)?.as_bytes() != bytes {
        return Err(DriverError::internal(
            "route-set generation identity is not canonical",
        ));
    }
    Ok(identity)
}

fn parse_route_set_generation(bytes: &[u8]) -> Result<RouteSetGenerationIdentity, DriverError> {
    if bytes.len() > 1024 {
        return Err(DriverError::internal(
            "route-set generation observation exceeded its bound",
        ));
    }
    let identity: RouteSetGenerationIdentity = serde_json::from_slice(bytes)
        .map_err(|_| DriverError::internal("invalid route-set generation observation"))?;
    identity.validate()?;
    Ok(identity)
}

fn route_set_observation_matches(bytes: &[u8], expected: &RouteSetGenerationIdentity) -> bool {
    parse_route_set_generation(bytes).is_ok_and(|observed| observed == *expected)
}

#[tracing::instrument(
    name = "deployment_driver.route_set.observe_loaded_generation",
    skip_all,
    fields(
        route_set.publication_kind = expected.publication_kind.as_str(),
        route_set.publication_id = %expected.publication_id,
        route_set.target_workshop_id = tracing::field::debug(expected.target_workshop_id()),
        route_set.global_fence_token = expected.global_fence_token,
        route_set.target_route_fence_token = tracing::field::debug(expected.target_route_fence_token()),
        route_set.digest = %expected.route_set_digest,
        observation.outcome = tracing::field::Empty
    )
)]
#[allow(dead_code)] // consumed when immutable normal route publication is wired
pub(super) async fn observe_running_route_set_generation(
    state: &DriverState,
    expected: &RouteSetGenerationIdentity,
) -> Result<RouteSetGenerationIdentity, DriverError> {
    expected.validate()?;
    for _ in 0..20 {
        let bytes = match &state.backend {
            RuntimeBackend::Docker => {
                docker_exec_capture(
                    state,
                    &state.config.gateway_container,
                    &["wget", "-qO-", ROUTE_SET_GENERATION_ENDPOINT],
                    1024,
                )
                .await
            }
            RuntimeBackend::Quadlet(backend) => {
                backend
                    .observe_gateway_generation(
                        &state.config.gateway_container,
                        ROUTE_SET_GENERATION_ENDPOINT,
                    )
                    .await
            }
        };
        if let Ok(bytes) = bytes
            && route_set_observation_matches(&bytes, expected)
        {
            tracing::Span::current().record("observation.outcome", "matched");
            return Ok(expected.clone());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    tracing::Span::current().record("observation.outcome", "mismatched");
    Err(DriverError::internal(
        "running route-set generation differs from its publication identity",
    ))
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", content = "identity", rename_all = "snake_case")]
pub(super) enum RunningRouteWorkerIdentity {
    Startup(GatewayGenerationIdentity),
    ReleaseOverlay(ReleaseOverlayGenerationIdentity),
    RouteSet(RouteSetGenerationIdentity),
}

fn running_route_worker_identity_config(
    identity: &RunningRouteWorkerIdentity,
) -> Result<String, DriverError> {
    validate_running_route_worker_identity(identity)?;
    let body = serde_json::to_string(identity).map_err(DriverError::internal)?;
    if body.len() > 2048 {
        return Err(DriverError::internal(
            "route worker identity exceeded its bound",
        ));
    }
    Ok(format!(
        "server {{\n  listen 127.0.0.1:8085;\n  server_name _;\n  location = /_mb/route-worker-identity {{\n    default_type application/json;\n    add_header Cache-Control 'no-store' always;\n    return 200 '{body}';\n  }}\n  location / {{ return 404; }}\n}}\n"
    ))
}

fn validate_running_route_worker_identity(
    identity: &RunningRouteWorkerIdentity,
) -> Result<(), DriverError> {
    match identity {
        RunningRouteWorkerIdentity::Startup(identity) => identity.validate(),
        RunningRouteWorkerIdentity::ReleaseOverlay(identity) => identity.validate(),
        RunningRouteWorkerIdentity::RouteSet(identity) => identity.validate(),
    }
}

fn parse_running_route_worker_identity(
    bytes: &[u8],
) -> Result<RunningRouteWorkerIdentity, DriverError> {
    if bytes.len() > 2048 {
        return Err(DriverError::internal(
            "route worker identity observation exceeded its bound",
        ));
    }
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|_| DriverError::internal("invalid route worker identity observation"))?;
    let object = value
        .as_object()
        .ok_or_else(|| DriverError::internal("invalid route worker identity observation"))?;
    if object.len() != 2 || !object.contains_key("kind") || !object.contains_key("identity") {
        return Err(DriverError::internal(
            "invalid route worker identity observation",
        ));
    }
    let identity: RunningRouteWorkerIdentity = serde_json::from_value(value)
        .map_err(|_| DriverError::internal("invalid route worker identity observation"))?;
    validate_running_route_worker_identity(&identity)?;
    if serde_json::to_vec(&identity).map_err(DriverError::internal)? != bytes {
        return Err(DriverError::internal(
            "route worker identity observation is not canonical",
        ));
    }
    Ok(identity)
}

fn primary_identity_body<'a>(
    bytes: &'a [u8],
    prefix: &[u8],
    description: &str,
) -> Result<&'a [u8], DriverError> {
    let rest = bytes
        .strip_prefix(prefix)
        .ok_or_else(|| DriverError::internal(format!("invalid {description} configuration")))?;
    let end = rest
        .windows(IDENTITY_SERVER_END.len())
        .position(|window| window == IDENTITY_SERVER_END)
        .ok_or_else(|| DriverError::internal(format!("invalid {description} configuration")))?;
    Ok(&rest[..end])
}

/// Observe the single strict tagged identity endpoint from the running route
/// worker. A transport or parse failure is never treated as a missing protocol;
/// a valid identity of another kind remains typed evidence of worker drift.
pub(super) async fn observe_running_route_worker_identity(
    state: &DriverState,
) -> Result<RunningRouteWorkerIdentity, DriverError> {
    let bytes = observe_generation_endpoint(state, ROUTE_WORKER_IDENTITY_ENDPOINT).await?;
    parse_running_route_worker_identity(&bytes)
}

async fn observe_generation_endpoint(
    state: &DriverState,
    endpoint: &str,
) -> Result<Vec<u8>, DriverError> {
    match &state.backend {
        RuntimeBackend::Docker => {
            docker_exec_capture(
                state,
                &state.config.gateway_container,
                &["wget", "-qO-", endpoint],
                2048,
            )
            .await
        }
        RuntimeBackend::Quadlet(backend) => {
            backend
                .observe_gateway_generation(&state.config.gateway_container, endpoint)
                .await
        }
    }
}

impl ReleaseGatewayGenerationIdentity {
    pub(super) fn new(
        fleet_run_id: Uuid,
        driver_action_id: Uuid,
        original_driver_fence_token: i64,
        gateway_configuration_digest: String,
        target_slot: &str,
    ) -> Result<Self, DriverError> {
        let identity = Self {
            protocol_version: RELEASE_GATEWAY_IDENTITY_PROTOCOL_VERSION,
            fleet_run_id,
            driver_action_id,
            original_driver_fence_token,
            gateway_configuration_digest,
            target_slot: ReleaseTargetSlot::parse(target_slot)?,
        };
        identity.validate()?;
        Ok(identity)
    }

    fn validate(&self) -> Result<(), DriverError> {
        if self.protocol_version != RELEASE_GATEWAY_IDENTITY_PROTOCOL_VERSION
            || self.original_driver_fence_token <= 0
        {
            return Err(DriverError::internal(
                "release gateway generation identity is invalid",
            ));
        }
        validate_sha256_digest(&self.gateway_configuration_digest)
    }
}

fn validate_sha256_digest(value: &str) -> Result<(), DriverError> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(DriverError::internal(
            "gateway generation digest is invalid",
        ));
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(DriverError::internal(
            "gateway generation digest is invalid",
        ));
    }
    Ok(())
}

pub(super) fn release_gateway_generation_config(
    identity: &ReleaseGatewayGenerationIdentity,
) -> Result<String, DriverError> {
    identity.validate()?;
    let body = serde_json::to_string(identity).map_err(DriverError::internal)?;
    if body.len() > 1024 {
        return Err(DriverError::internal(
            "release gateway generation identity exceeded its bound",
        ));
    }
    Ok(format!(
        "server {{\n  listen 127.0.0.1:8082;\n  server_name _;\n  location = /_mb/release-generation {{\n    default_type application/json;\n    add_header Cache-Control 'no-store' always;\n    return 200 '{body}';\n  }}\n  location / {{ return 404; }}\n}}\n"
    ))
}

fn parse_release_gateway_generation(
    bytes: &[u8],
) -> Result<ReleaseGatewayGenerationIdentity, DriverError> {
    if bytes.len() > 1024 {
        return Err(DriverError::internal(
            "release gateway generation observation exceeded its bound",
        ));
    }
    let identity: ReleaseGatewayGenerationIdentity = serde_json::from_slice(bytes)
        .map_err(|_| DriverError::internal("invalid release gateway generation observation"))?;
    identity.validate()?;
    Ok(identity)
}

#[tracing::instrument(
    name = "deployment_driver.release_gateway.observe_loaded_generation",
    skip_all,
    fields(
        release.fleet_run_id = %expected.fleet_run_id,
        release.driver_action_id = %expected.driver_action_id,
        release.target_slot = expected.target_slot.as_str(),
        observation.outcome = tracing::field::Empty
    )
)]
pub(super) async fn observe_running_release_gateway_generation(
    state: &DriverState,
    expected: &ReleaseGatewayGenerationIdentity,
) -> Result<ReleaseGatewayGenerationIdentity, DriverError> {
    expected.validate()?;
    for _ in 0..20 {
        let bytes = match &state.backend {
            RuntimeBackend::Docker => {
                docker_exec_capture(
                    state,
                    &state.config.gateway_container,
                    &["wget", "-qO-", RELEASE_GATEWAY_GENERATION_ENDPOINT],
                    1024,
                )
                .await
            }
            RuntimeBackend::Quadlet(backend) => {
                backend
                    .observe_gateway_generation(
                        &state.config.gateway_container,
                        RELEASE_GATEWAY_GENERATION_ENDPOINT,
                    )
                    .await
            }
        };
        if let Ok(bytes) = bytes
            && let Ok(observed) = parse_release_gateway_generation(&bytes)
            && &observed == expected
        {
            tracing::Span::current().record("observation.outcome", "matched");
            return Ok(observed);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    tracing::Span::current().record("observation.outcome", "mismatched");
    Err(DriverError::internal(
        "running release gateway generation differs from its activation intent",
    ))
}

pub(super) struct RouteRenderSpec<'a> {
    pub database_ref: &'a str,
    pub odoo_hostname: &'a str,
    pub paperless: Option<(&'a str, &'a str)>,
    pub paperless_read_only: bool,
    pub custom_hostnames: &'a [CustomHostnameRoute],
}

pub(super) fn write_gateway_file(path: &Path, contents: impl AsRef<[u8]>) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, contents)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o640))
}

pub(super) async fn apply_fenced_routes(
    state: &DriverState,
    workshop: Uuid,
    route: RouteRenderSpec<'_>,
    route_lease: &RouteApplicationLease,
) -> Result<String, DriverError> {
    let odoo_container = super::active_odoo_runtime_container(state).await?;
    let config = route_config_for_upstream(
        route.database_ref,
        route.odoo_hostname,
        &odoo_container,
        route.paperless,
        route.paperless_read_only,
        route.custom_hostnames,
    );
    let selected = selected_route_root(&state.config.route_root)?;
    let path = selected.join(format!("{workshop}.conf"));
    let temporary = selected.join(format!("{workshop}.conf.tmp"));
    let previous = std::fs::read(&path).ok();
    renew_route_application(state, route_lease).await?;
    write_gateway_file(&temporary, &config).map_err(DriverError::internal)?;
    std::fs::rename(temporary, &path).map_err(DriverError::internal)?;
    let digest = format!("sha256:{:x}", Sha256::digest(config.as_bytes()));
    // Rename is already a physical effect. A failed renewal after this point
    // is an unknown outcome and the outer finalizer quarantines it.
    renew_route_application(state, route_lease).await?;
    if let Err(error) = reload_gateway_runtime(state, &digest).await {
        if let Some(previous) = previous {
            let _ = write_gateway_file(&path, previous);
        } else {
            let _ = std::fs::remove_file(&path);
        }
        return Err(error);
    }
    renew_route_application(state, route_lease).await?;
    Ok(digest)
}

pub(super) async fn apply_fenced_route_absence(
    state: &DriverState,
    workshop: Uuid,
    route_lease: &RouteApplicationLease,
) -> Result<String, DriverError> {
    let selected = selected_route_root(&state.config.route_root)?;
    let path = selected.join(format!("{workshop}.conf"));
    let previous = std::fs::read(&path).ok();
    renew_route_application(state, route_lease).await?;
    match std::fs::remove_file(&path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(DriverError::internal(error)),
    }
    // Absence is represented by the canonical digest of empty route bytes.
    let digest = format!("sha256:{:x}", Sha256::digest([]));
    renew_route_application(state, route_lease).await?;
    if let Err(error) = reload_gateway_runtime(state, &digest).await {
        if let Some(previous) = previous {
            let _ = write_gateway_file(&path, previous);
        }
        return Err(error);
    }
    renew_route_application(state, route_lease).await?;
    Ok(digest)
}

pub(super) async fn reload_gateway_runtime(
    state: &DriverState,
    expected_digest: &str,
) -> Result<(), DriverError> {
    match &state.backend {
        RuntimeBackend::Docker => {
            docker_exec(state, &state.config.gateway_container, &["nginx", "-t"]).await?;
            docker_signal_container(state, &state.config.gateway_container, "HUP").await
        }
        RuntimeBackend::Quadlet(backend) => backend
            .reload_gateway(&state.config.gateway_container, expected_digest)
            .await
            .map(|_| ()),
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub(super) struct CustomHostnameRoute {
    pub hostname: String,
    pub canonical: bool,
}

#[cfg(test)]
pub(super) fn route_config(
    database_ref: &str,
    odoo_hostname: &str,
    paperless: Option<(&str, &str)>,
    paperless_read_only: bool,
) -> String {
    route_config_with_custom_hostnames(
        database_ref,
        odoo_hostname,
        paperless,
        paperless_read_only,
        &[],
    )
}

#[cfg(test)]
pub(super) fn route_config_with_custom_hostnames(
    database_ref: &str,
    odoo_hostname: &str,
    paperless: Option<(&str, &str)>,
    paperless_read_only: bool,
    custom_hostnames: &[CustomHostnameRoute],
) -> String {
    route_config_for_upstream(
        database_ref,
        odoo_hostname,
        "odoo",
        paperless,
        paperless_read_only,
        custom_hostnames,
    )
}

pub(super) fn route_config_for_upstream(
    database_ref: &str,
    odoo_hostname: &str,
    odoo_container: &str,
    paperless: Option<(&str, &str)>,
    paperless_read_only: bool,
    custom_hostnames: &[CustomHostnameRoute],
) -> String {
    let custom_canonical = custom_hostnames
        .iter()
        .find(|route| route.canonical)
        .map(|route| route.hostname.as_str());
    let canonical = custom_canonical.unwrap_or(odoo_hostname);
    // The stable platform hostname remains a direct route because it is the registered
    // OIDC origin and the durable staff/back-office entry point. A custom canonical name
    // controls storefront redirects without invalidating that operational origin.
    let proxy_names = if custom_canonical.is_some() {
        vec![canonical, odoo_hostname]
    } else {
        vec![canonical]
    };
    let mut config = format!(
        "server {{\n  listen 8080;\n  server_name {};\n  location / {{\n    proxy_http_version 1.1;\n    proxy_set_header Host $host;\n    proxy_set_header X-Forwarded-Host $host;\n    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n    proxy_set_header X-Forwarded-Proto $forwarded_proto;\n    proxy_set_header Upgrade $http_upgrade;\n    proxy_set_header Connection $connection_upgrade;\n    proxy_set_header X-Odoo-Dbfilter '^{}\\Z';\n    set $tenant_upstream \"{odoo_container}:8069\";\n    proxy_pass http://$tenant_upstream;\n  }}\n}}\n",
        proxy_names.join(" "),
        database_ref
    );
    let redirects = if custom_canonical.is_some() {
        custom_hostnames
            .iter()
            .filter(|route| !route.canonical)
            .map(|route| route.hostname.as_str())
            .collect::<Vec<_>>()
    } else {
        custom_hostnames
            .iter()
            .map(|route| route.hostname.as_str())
            .collect::<Vec<_>>()
    };
    if !redirects.is_empty() {
        config.push_str(&format!(
            "server {{\n  listen 8080;\n  server_name {};\n  return 308 https://{canonical}$request_uri;\n}}\n",
            redirects.join(" ")
        ));
    }
    if let Some((paperless_hostname, paperless_container)) = paperless {
        let mutation_gate = if paperless_read_only {
            "    limit_except GET HEAD OPTIONS { deny all; }\n"
        } else {
            ""
        };
        config.push_str(&format!(
            "server {{\n  listen 8080;\n  server_name {paperless_hostname};\n  location / {{\n{mutation_gate}    proxy_http_version 1.1;\n    proxy_set_header Host $host;\n    proxy_set_header X-Forwarded-Host $host;\n    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n    proxy_set_header X-Forwarded-Proto $forwarded_proto;\n    proxy_set_header Upgrade $http_upgrade;\n    proxy_set_header Connection $connection_upgrade;\n    set $tenant_upstream \"{paperless_container}:8000\";\n    proxy_pass http://$tenant_upstream;\n  }}\n}}\n"
        ));
    }
    config
}

pub(super) async fn restrict_capability(
    _state: &DriverState,
    _workshop: Uuid,
    payload: &Value,
) -> Result<Value, DriverError> {
    if payload.get("capability").and_then(Value::as_str) != Some("documents") {
        return Err(DriverError::bad("unsupported gateway restriction"));
    }
    Err(DriverError(
        StatusCode::CONFLICT,
        "document restriction must be applied through a fenced route projection".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generation(marker: char) -> GatewayGenerationIdentity {
        GatewayGenerationIdentity {
            effect_run_id: Uuid::new_v4(),
            sealed_digest: format!("sha256:{}", marker.to_string().repeat(64)),
        }
    }

    fn release_generation(marker: char) -> ReleaseGatewayGenerationIdentity {
        ReleaseGatewayGenerationIdentity::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            42,
            format!("sha256:{}", marker.to_string().repeat(64)),
            "green",
        )
        .unwrap()
    }

    fn route_set_generation(marker: char) -> RouteSetGenerationIdentity {
        RouteSetGenerationIdentity::new(
            Uuid::new_v4(),
            RouteSetPublicationKind::Projection,
            43,
            Uuid::new_v4(),
            44,
            format!("sha256:{}", marker.to_string().repeat(64)),
        )
        .unwrap()
    }

    #[test]
    fn route_set_identity_has_closed_exact_fleet_and_workshop_wire_shapes() {
        let workshop = route_set_generation('a');
        let workshop_value = serde_json::to_value(&workshop).unwrap();
        assert_eq!(workshop_value.as_object().unwrap().len(), 7);
        assert!(workshop_value.get("startup_effect_run_id").is_none());
        assert_eq!(
            serde_json::from_value::<RouteSetGenerationIdentity>(workshop_value).unwrap(),
            workshop
        );

        let startup = RouteSetGenerationIdentity::new_startup(
            Uuid::new_v4(),
            Uuid::new_v4(),
            19,
            format!("sha256:{}", "b".repeat(64)),
        )
        .unwrap();
        let mut startup_value = serde_json::to_value(&startup).unwrap();
        assert_eq!(startup_value.as_object().unwrap().len(), 6);
        assert!(startup_value.get("target_workshop_id").is_none());
        assert!(startup_value.get("target_route_fence_token").is_none());
        assert_eq!(
            serde_json::from_value::<RouteSetGenerationIdentity>(startup_value.clone()).unwrap(),
            startup
        );
        startup_value["target_workshop_id"] = serde_json::json!(Uuid::new_v4());
        assert!(serde_json::from_value::<RouteSetGenerationIdentity>(startup_value).is_err());
    }

    fn release_overlay_generation(marker: char) -> ReleaseOverlayGenerationIdentity {
        ReleaseOverlayGenerationIdentity::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            42,
            ReleaseOverlayKind::Candidate,
            format!("sha256:{}", marker.to_string().repeat(64)),
            "green",
        )
        .unwrap()
    }

    #[test]
    fn universal_route_worker_identity_is_strict_tagged_and_canonical() {
        let identities = [
            RunningRouteWorkerIdentity::Startup(generation('a')),
            RunningRouteWorkerIdentity::ReleaseOverlay(release_overlay_generation('b')),
            RunningRouteWorkerIdentity::RouteSet(route_set_generation('c')),
        ];
        for identity in identities {
            let bytes = serde_json::to_vec(&identity).unwrap();
            assert_eq!(
                parse_running_route_worker_identity(&bytes).unwrap(),
                identity
            );
            let config = running_route_worker_identity_config(&identity).unwrap();
            assert!(config.contains("listen 127.0.0.1:8085;"));
            assert!(config.contains("location = /_mb/route-worker-identity"));
        }

        let startup = generation('e');
        let overlay = release_overlay_generation('f');
        let route_set = route_set_generation('a');
        for config in [
            gateway_generation_config(&startup).unwrap(),
            release_overlay_generation_config(&overlay).unwrap(),
            route_set_generation_config(&route_set).unwrap(),
        ] {
            assert!(config.contains("listen 127.0.0.1:8085;"));
            assert!(config.contains("location = /_mb/route-worker-identity"));
        }

        let valid =
            serde_json::to_value(RunningRouteWorkerIdentity::Startup(generation('d'))).unwrap();
        let mut extra = valid.as_object().unwrap().clone();
        extra.insert("extra".into(), serde_json::json!(true));
        assert!(parse_running_route_worker_identity(&serde_json::to_vec(&extra).unwrap()).is_err());
        assert!(
            parse_running_route_worker_identity(br#"{"kind":"unknown","identity":{}}"#).is_err()
        );
        assert!(parse_running_route_worker_identity(br#"{"kind":"startup"}"#).is_err());
        assert!(parse_running_route_worker_identity(b"not-json").is_err());
    }

    struct RouteRootGuard(PathBuf);

    impl Drop for RouteRootGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn route_root() -> RouteRootGuard {
        let root = std::env::temp_dir().join(format!("mb-route-selector-{}", Uuid::new_v4()));
        std::fs::create_dir_all(root.join("generations/boot-live")).unwrap();
        std::os::unix::fs::symlink("generations/boot-live", root.join("current")).unwrap();
        RouteRootGuard(root)
    }

    #[test]
    fn selected_route_root_accepts_only_one_local_generation_directory() {
        let root = route_root();
        assert_eq!(
            selected_route_root(&root.0).unwrap(),
            std::fs::canonicalize(root.0.join("generations/boot-live")).unwrap()
        );

        std::fs::remove_file(root.0.join("current")).unwrap();
        std::os::unix::fs::symlink("../escape", root.0.join("current")).unwrap();
        assert!(selected_route_root(&root.0).is_err());

        std::fs::remove_file(root.0.join("current")).unwrap();
        std::os::unix::fs::symlink("generations/boot-live/nested", root.0.join("current")).unwrap();
        assert!(selected_route_root(&root.0).is_err());

        std::fs::remove_file(root.0.join("current")).unwrap();
        std::fs::write(root.0.join("generations/not-a-directory"), b"route").unwrap();
        std::os::unix::fs::symlink("generations/not-a-directory", root.0.join("current")).unwrap();
        assert!(selected_route_root(&root.0).is_err());

        std::fs::remove_file(root.0.join("current")).unwrap();
        std::os::unix::fs::symlink("boot-live", root.0.join("generations/alias")).unwrap();
        std::os::unix::fs::symlink("generations/alias", root.0.join("current")).unwrap();
        assert!(selected_route_root(&root.0).is_err());
    }

    #[test]
    fn selected_route_root_rejects_a_symlinked_generations_directory() {
        let root = std::env::temp_dir().join(format!("mb-route-selector-{}", Uuid::new_v4()));
        let outside = std::env::temp_dir().join(format!("mb-route-outside-{}", Uuid::new_v4()));
        let _root_guard = RouteRootGuard(root.clone());
        let _outside_guard = RouteRootGuard(outside.clone());
        std::fs::create_dir_all(outside.join("candidate")).unwrap();
        std::fs::create_dir_all(&root).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("generations")).unwrap();
        std::os::unix::fs::symlink("generations/candidate", root.join("current")).unwrap();
        assert!(selected_route_root(&root).is_err());
    }

    #[test]
    fn generation_endpoint_is_loopback_literal_and_strictly_parsed() {
        let identity = generation('a');
        let config = gateway_generation_config(&identity).unwrap();
        let body = serde_json::to_string(&identity).unwrap();
        assert!(config.contains("listen 127.0.0.1:8081;"));
        assert!(config.contains("location = /_mb/generation"));
        assert!(config.contains(&format!("return 200 '{body}';")));
        assert!(!config.contains("root "));
        assert!(!config.contains("alias "));
        assert_eq!(parse_gateway_generation(body.as_bytes()).unwrap(), identity);

        let extra = format!(
            "{{\"effect_run_id\":\"{}\",\"sealed_digest\":\"{}\",\"extra\":true}}",
            identity.effect_run_id, identity.sealed_digest
        );
        assert!(parse_gateway_generation(extra.as_bytes()).is_err());
        assert!(parse_gateway_generation(&vec![b'x'; 1025]).is_err());
        assert!(
            gateway_generation_config(&GatewayGenerationIdentity {
                effect_run_id: identity.effect_run_id,
                sealed_digest: "sha256:ABC".into(),
            })
            .is_err()
        );
    }

    #[test]
    fn release_generation_endpoint_is_closed_bounded_and_exact() {
        let identity = release_generation('c');
        let body = serde_json::to_string(&identity).unwrap();
        let config = release_gateway_generation_config(&identity).unwrap();
        assert!(body.len() <= 1024);
        assert!(config.contains("listen 127.0.0.1:8082;"));
        assert!(config.contains("location = /_mb/release-generation"));
        assert!(config.contains(&format!("return 200 '{body}';")));
        assert_eq!(
            parse_release_gateway_generation(body.as_bytes()).unwrap(),
            identity
        );

        let mut extra = serde_json::to_value(&identity).unwrap();
        extra["unknown"] = json!(true);
        assert!(
            parse_release_gateway_generation(serde_json::to_vec(&extra).unwrap().as_slice())
                .is_err()
        );
        assert!(parse_release_gateway_generation(&vec![b'x'; 1025]).is_err());

        for invalid in [
            json!({
                "protocol_version":2,
                "fleet_run_id":identity.fleet_run_id,
                "driver_action_id":identity.driver_action_id,
                "original_driver_fence_token":42,
                "gateway_configuration_digest":identity.gateway_configuration_digest,
                "target_slot":"green"
            }),
            json!({
                "protocol_version":1,
                "fleet_run_id":identity.fleet_run_id,
                "driver_action_id":identity.driver_action_id,
                "original_driver_fence_token":0,
                "gateway_configuration_digest":identity.gateway_configuration_digest,
                "target_slot":"green"
            }),
            json!({
                "protocol_version":1,
                "fleet_run_id":identity.fleet_run_id,
                "driver_action_id":identity.driver_action_id,
                "original_driver_fence_token":42,
                "gateway_configuration_digest":"sha256:ABC",
                "target_slot":"green"
            }),
            json!({
                "protocol_version":1,
                "fleet_run_id":identity.fleet_run_id,
                "driver_action_id":identity.driver_action_id,
                "original_driver_fence_token":42,
                "gateway_configuration_digest":identity.gateway_configuration_digest,
                "target_slot":"red"
            }),
        ] {
            assert!(
                parse_release_gateway_generation(serde_json::to_vec(&invalid).unwrap().as_slice())
                    .is_err()
            );
        }
    }

    #[test]
    fn universal_route_set_endpoint_is_loopback_canonical_and_closed() {
        let identity = route_set_generation('e');
        let config = route_set_generation_config(&identity).unwrap();
        let body = serde_json::to_vec(&identity).unwrap();

        assert_eq!(ROUTE_SET_GENERATION_FILE, "mb-route-generation.conf");
        assert!(config.contains("listen 127.0.0.1:8084;"));
        assert!(config.contains("location = /_mb/route-generation"));
        assert!(!config.contains("0.0.0.0"));
        assert_eq!(parse_route_set_generation(&body).unwrap(), identity);
        assert_eq!(
            parse_route_set_generation_config(config.as_bytes()).unwrap(),
            identity
        );

        for (kind, expected) in [
            (RouteSetPublicationKind::Projection, "projection"),
            (
                RouteSetPublicationKind::RecoveryMaintenance,
                "recovery_maintenance",
            ),
            (RouteSetPublicationKind::RecoveryRestore, "recovery_restore"),
        ] {
            assert_eq!(kind.as_str(), expected);
            assert_eq!(
                serde_json::to_string(&kind).unwrap(),
                format!("\"{expected}\"")
            );
        }
    }

    #[test]
    fn universal_route_set_identity_rejects_malformed_or_noncanonical_evidence() {
        let identity = route_set_generation('a');
        let mut value = serde_json::to_value(&identity).unwrap();
        value["unexpected"] = serde_json::json!(true);
        assert!(parse_route_set_generation(&serde_json::to_vec(&value).unwrap()).is_err());
        let mut missing = serde_json::to_value(&identity).unwrap();
        missing.as_object_mut().unwrap().remove("publication_id");
        assert!(parse_route_set_generation(&serde_json::to_vec(&missing).unwrap()).is_err());

        for (field, value) in [
            ("protocol_version", serde_json::json!(2)),
            ("publication_id", serde_json::json!(Uuid::nil())),
            ("global_fence_token", serde_json::json!(0)),
            ("target_workshop_id", serde_json::json!(Uuid::nil())),
            ("target_route_fence_token", serde_json::json!(0)),
            ("route_set_digest", serde_json::json!("sha256:ABC")),
            ("publication_kind", serde_json::json!("recovery")),
        ] {
            let mut malformed = serde_json::to_value(&identity).unwrap();
            malformed[field] = value;
            assert!(
                parse_route_set_generation(&serde_json::to_vec(&malformed).unwrap()).is_err(),
                "accepted malformed {field}"
            );
        }

        assert!(parse_route_set_generation(&vec![b'x'; 1025]).is_err());
        assert!(parse_route_set_generation_config(&vec![b'x'; 65_537]).is_err());
        let noncanonical = route_set_generation_config(&identity)
            .unwrap()
            .replace("server {\n", "server { \n");
        assert!(parse_route_set_generation_config(noncanonical.as_bytes()).is_err());
    }

    #[test]
    fn universal_route_set_matcher_requires_every_identity_field() {
        let identity = route_set_generation('b');
        let bytes = serde_json::to_vec(&identity).unwrap();
        assert!(route_set_observation_matches(&bytes, &identity));

        let mut mismatches = Vec::new();
        let mut changed = identity.clone();
        changed.publication_id = Uuid::new_v4();
        mismatches.push(changed);
        let mut changed = identity.clone();
        changed.publication_kind = RouteSetPublicationKind::RecoveryMaintenance;
        mismatches.push(changed);
        let mut changed = identity.clone();
        changed.global_fence_token += 1;
        mismatches.push(changed);
        let mut changed = identity.clone();
        changed.set_workshop_scope_for_test(
            Uuid::new_v4(),
            changed.target_route_fence_token().unwrap(),
        );
        mismatches.push(changed);
        let mut changed = identity.clone();
        changed.set_workshop_scope_for_test(
            changed.target_workshop_id().unwrap(),
            changed.target_route_fence_token().unwrap() + 1,
        );
        mismatches.push(changed);
        let mut changed = identity.clone();
        changed.route_set_digest = format!("sha256:{}", "c".repeat(64));
        mismatches.push(changed);

        for mismatch in mismatches {
            assert!(!route_set_observation_matches(&bytes, &mismatch));
        }
    }

    #[test]
    fn release_overlay_identity_is_distinct_canonical_bounded_and_strict() {
        let identity = ReleaseOverlayGenerationIdentity::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            91,
            ReleaseOverlayKind::Maintenance,
            format!("sha256:{}", "a".repeat(64)),
            "blue",
        )
        .unwrap();
        assert!(
            ReleaseOverlayGenerationIdentity::new(
                Uuid::nil(),
                Uuid::new_v4(),
                91,
                ReleaseOverlayKind::Candidate,
                format!("sha256:{}", "a".repeat(64)),
                "blue",
            )
            .is_err()
        );
        let config = release_overlay_generation_config(&identity).unwrap();
        let body = serde_json::to_vec(&identity).unwrap();
        assert!(config.contains("listen 127.0.0.1:8083"));
        assert!(config.contains("location = /_mb/release-overlay-generation"));
        assert!(!config.contains("/_mb/release-generation "));
        assert_eq!(
            parse_release_overlay_generation_config(config.as_bytes()).unwrap(),
            identity
        );
        assert_eq!(parse_release_overlay_generation(&body).unwrap(), identity);
        assert!(release_overlay_observation_matches(&body, &identity));
        let other = ReleaseOverlayGenerationIdentity::new(
            identity.fleet_run_id,
            identity.driver_operation_id,
            identity.original_global_fence_token,
            ReleaseOverlayKind::Candidate,
            identity.route_set_digest.clone(),
            identity.target_slot.as_str(),
        )
        .unwrap();
        assert!(!release_overlay_observation_matches(&body, &other));
        let mut unknown = serde_json::to_value(&identity).unwrap();
        unknown["unknown"] = json!(true);
        assert!(parse_release_overlay_generation(&serde_json::to_vec(&unknown).unwrap()).is_err());
        assert!(parse_release_overlay_generation(&vec![b'x'; 1025]).is_err());

        let mut noncanonical = config.into_bytes();
        noncanonical.push(b'\n');
        assert!(parse_release_overlay_generation_config(&noncanonical).is_err());
        assert!(parse_release_overlay_generation_config(&vec![b'x'; 65_537]).is_err());

        for invalid in [
            json!({
                "protocol_version":2,
                "fleet_run_id":identity.fleet_run_id,
                "driver_operation_id":identity.driver_operation_id,
                "original_global_fence_token":91,
                "overlay_kind":"maintenance",
                "route_set_digest":identity.route_set_digest,
                "target_slot":"blue"
            }),
            json!({
                "protocol_version":1,
                "fleet_run_id":identity.fleet_run_id,
                "driver_operation_id":identity.driver_operation_id,
                "original_global_fence_token":0,
                "overlay_kind":"candidate",
                "route_set_digest":identity.route_set_digest,
                "target_slot":"blue"
            }),
        ] {
            let body = serde_json::to_string(&invalid).unwrap();
            let candidate = format!(
                "server {{\n  listen 127.0.0.1:8083;\n  server_name _;\n  location = /_mb/release-overlay-generation {{\n    default_type application/json;\n    add_header Cache-Control 'no-store' always;\n    return 200 '{body}';\n  }}\n  location / {{ return 404; }}\n}}\n"
            );
            assert!(parse_release_overlay_generation_config(candidate.as_bytes()).is_err());
        }
    }

    #[test]
    #[ignore = "requires a local Docker daemon and nginx:1.29-alpine"]
    fn real_nginx_observation_reports_loaded_generation_not_changed_disk() {
        use std::process::Command;

        struct ContainerGuard {
            name: String,
            root: PathBuf,
        }
        impl Drop for ContainerGuard {
            fn drop(&mut self) {
                let _ = Command::new("docker")
                    .args(["rm", "-f", &self.name])
                    .output();
                let _ = std::fs::remove_dir_all(&self.root);
            }
        }

        let root = std::env::temp_dir().join(format!("mb-gateway-generation-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            root.join("nginx.conf"),
            "worker_processes 1;\nevents {}\nhttp { include /etc/nginx/generation.conf; }\n",
        )
        .unwrap();
        let first = generation('a');
        let second = generation('b');
        std::fs::write(
            root.join("generation.conf"),
            gateway_generation_config(&first).unwrap(),
        )
        .unwrap();
        let name = format!("mb-gateway-generation-{}", Uuid::new_v4().simple());
        let mount = format!("type=bind,src={},dst=/etc/nginx,readonly", root.display());
        let started = Command::new("docker")
            .args([
                "run",
                "--detach",
                "--name",
                &name,
                "--mount",
                &mount,
                "nginx:1.29-alpine",
            ])
            .output()
            .unwrap();
        assert!(started.status.success());
        let _guard = ContainerGuard {
            name: name.clone(),
            root: root.clone(),
        };

        let observe = || {
            for _ in 0..20 {
                let output = Command::new("docker")
                    .args(["exec", &name, "wget", "-qO-", GATEWAY_GENERATION_ENDPOINT])
                    .output()
                    .unwrap();
                if output.status.success() {
                    return parse_gateway_generation(&output.stdout).unwrap();
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            panic!("Nginx generation endpoint did not become ready")
        };
        assert_eq!(observe(), first);

        std::fs::write(
            root.join("generation.conf"),
            gateway_generation_config(&second).unwrap(),
        )
        .unwrap();
        assert_eq!(
            observe(),
            first,
            "changing candidate bytes must not change the running observation"
        );
        let reloaded = Command::new("docker")
            .args(["exec", &name, "nginx", "-s", "reload"])
            .output()
            .unwrap();
        assert!(reloaded.status.success());
        let mut startup_reloaded = false;
        for _ in 0..20 {
            if observe() == second {
                startup_reloaded = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(
            startup_reloaded,
            "Nginx did not serve the reloaded generation"
        );

        let first_release = release_generation('c');
        let second_release = release_generation('d');
        std::fs::write(
            root.join("generation.conf"),
            release_gateway_generation_config(&first_release).unwrap(),
        )
        .unwrap();
        let reloaded = Command::new("docker")
            .args(["exec", &name, "nginx", "-s", "reload"])
            .output()
            .unwrap();
        assert!(reloaded.status.success());
        let observe_release = || {
            for _ in 0..20 {
                let output = Command::new("docker")
                    .args([
                        "exec",
                        &name,
                        "wget",
                        "-qO-",
                        RELEASE_GATEWAY_GENERATION_ENDPOINT,
                    ])
                    .output()
                    .unwrap();
                if output.status.success() {
                    return parse_release_gateway_generation(&output.stdout).unwrap();
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            panic!("Nginx release-generation endpoint did not become ready")
        };
        assert_eq!(observe_release(), first_release);
        std::fs::write(
            root.join("generation.conf"),
            release_gateway_generation_config(&second_release).unwrap(),
        )
        .unwrap();
        assert_eq!(observe_release(), first_release);
        let reloaded = Command::new("docker")
            .args(["exec", &name, "nginx", "-s", "reload"])
            .output()
            .unwrap();
        assert!(reloaded.status.success());
        for _ in 0..20 {
            if observe_release() == second_release {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("Nginx did not serve the reloaded release generation")
    }

    #[test]
    fn custom_canonical_keeps_the_platform_oidc_origin_routable() {
        let config = route_config_with_custom_hostnames(
            "mb_0123456789abcdef0123456789abcdef",
            "atelier.makersbrain.test",
            None,
            false,
            &[
                CustomHostnameRoute {
                    hostname: "shop.atelier.test".into(),
                    canonical: true,
                },
                CustomHostnameRoute {
                    hostname: "www.atelier.test".into(),
                    canonical: false,
                },
            ],
        );
        assert!(config.contains("server_name shop.atelier.test atelier.makersbrain.test;"));
        assert!(config.contains(
            "server_name www.atelier.test;\n  return 308 https://shop.atelier.test$request_uri;"
        ));
        assert!(!config.contains("server_name atelier.makersbrain.test;\n  return 308"));
    }
}
