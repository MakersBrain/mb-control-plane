//! Pure, dormant adapter from a protocol-v2 release snapshot to immutable overlays.
//!
//! The database freezes the logical projections and their applied evidence. This
//! module validates that frozen envelope, renders either maintenance or candidate
//! bytes, and stages one UUID-ordered row at a time. It deliberately has no path,
//! selector, or route-file input, so live route bytes cannot influence an overlay.
#![allow(dead_code)]

use std::collections::BTreeMap;

use serde_json::Value;
use uuid::Uuid;

use super::gateway::{ReleaseOverlayKind, ReleaseTargetSlot};
use super::release_generation_fs::{
    ReleaseGenerationSealer, ReleaseRouteSealEvidence, release_route_set_digest,
};
use super::route_generation_fs::{validate_digest, validate_route_bytes};
use super::route_projection::{
    PaperlessRouteMode, RouteDisposition, RouteProjection, RouteRuntime,
};
use super::{DockerDriverConfig, DriverError};

const RELEASE_SNAPSHOT_PROTOCOL_VERSION: i16 = 2;
const MAX_RELEASE_SNAPSHOT_ROWS: usize = 500;

/// Trusted deterministic runtime-name resolver. Its namespace comes only from
/// validated driver configuration; callers cannot substitute another tenant's
/// runtime name while retaining a different typed workshop identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ReleaseRuntimeNameResolver {
    workspace_namespace: String,
}

impl ReleaseRuntimeNameResolver {
    pub(super) fn from_config(config: &DockerDriverConfig) -> Self {
        Self {
            workspace_namespace: config.workspace_namespace.clone(),
        }
    }

    pub(super) fn verify_candidate_runtime(
        &self,
        target_slot: ReleaseTargetSlot,
        observed_odoo_upstream: &str,
        observed_paperless_upstreams: &BTreeMap<Uuid, String>,
    ) -> Result<VerifiedReleaseRuntimeContext, DriverError> {
        let expected_odoo = self.odoo_upstream(target_slot);
        if observed_odoo_upstream != expected_odoo {
            return Err(DriverError::internal(
                "release target runtime does not match its slot",
            ));
        }
        let mut paperless_upstreams = BTreeMap::new();
        for (workshop_id, observed) in observed_paperless_upstreams {
            if workshop_id.is_nil() || observed != &self.paperless_upstream(*workshop_id) {
                return Err(DriverError::internal(
                    "release Paperless runtime does not match its workshop",
                ));
            }
            paperless_upstreams.insert(*workshop_id, observed.clone());
        }
        Ok(VerifiedReleaseRuntimeContext {
            target_slot,
            odoo_upstream: expected_odoo,
            paperless_upstreams,
        })
    }

    /// Resolve deterministic candidate upstream names from trusted driver
    /// configuration and the frozen snapshot membership. Live runtime
    /// existence is proved separately by the opaque runtime observer before
    /// recovery publication can be authorized.
    pub(super) fn candidate_runtime_for_snapshot(
        &self,
        target_slot: ReleaseTargetSlot,
        paperless_workshops: impl IntoIterator<Item = Uuid>,
    ) -> Result<VerifiedReleaseRuntimeContext, DriverError> {
        let mut paperless_upstreams = BTreeMap::new();
        for workshop_id in paperless_workshops {
            if workshop_id.is_nil()
                || paperless_upstreams
                    .insert(workshop_id, self.paperless_upstream(workshop_id))
                    .is_some()
            {
                return Err(DriverError::internal(
                    "release snapshot Paperless membership is invalid",
                ));
            }
        }
        Ok(VerifiedReleaseRuntimeContext {
            target_slot,
            odoo_upstream: self.odoo_upstream(target_slot),
            paperless_upstreams,
        })
    }

    fn odoo_upstream(&self, target_slot: ReleaseTargetSlot) -> String {
        format!("{}-odoo-{}", self.workspace_namespace, target_slot.as_str())
    }

    fn paperless_upstream(&self, workshop_id: Uuid) -> String {
        format!(
            "{}-paperless-{}",
            self.workspace_namespace,
            workshop_id.simple()
        )
    }

    #[cfg(test)]
    pub(super) fn from_test_namespace(workspace_namespace: &str) -> Self {
        Self {
            workspace_namespace: workspace_namespace.to_owned(),
        }
    }
}

/// Candidate names after exact deterministic slot/workshop verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct VerifiedReleaseRuntimeContext {
    target_slot: ReleaseTargetSlot,
    odoo_upstream: String,
    paperless_upstreams: BTreeMap<Uuid, String>,
}

/// One row returned from the bounded protocol-v2 release snapshot reader.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct FrozenReleaseRouteSnapshotRow {
    pub workshop_id: Uuid,
    pub database_id: Uuid,
    pub database_ref: String,
    pub paperless_enabled: bool,
    pub generation: i64,
    pub projection_digest: String,
    pub disposition: RouteDisposition,
    pub canonical_projection: Value,
    pub applied_rendered_digest: String,
    pub applied_fence_token: i64,
    pub route_fence_token: i64,
    pub target_slot: ReleaseTargetSlot,
}

/// Complete snapshot metadata plus its already UUID-ordered rows.
pub(super) struct FrozenReleaseRouteSnapshot {
    pub fleet_run_id: Uuid,
    pub driver_operation_id: Uuid,
    pub original_global_fence_token: i64,
    pub protocol_version: i16,
    pub snapshot_count: usize,
    pub rows: Vec<FrozenReleaseRouteSnapshotRow>,
}

/// Exact fields accepted by `record_immutable_release_route_candidate` and
/// reproduced by `ReleaseGenerationSealer::stage_route`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ReleaseRoutePublicationRecord {
    pub overlay_kind: ReleaseOverlayKind,
    pub workshop_id: Uuid,
    pub generation: i64,
    pub projection_digest: String,
    pub applied_rendered_digest: String,
    pub rendered_digest: String,
}

struct PreparedReleaseRouteRow {
    record: ReleaseRoutePublicationRecord,
    contents: Vec<u8>,
}

/// A validated overlay plan. Staging remains incremental so a future
/// coordinator can renew durable authority before every filesystem boundary.
pub(super) struct PreparedReleaseRouteOverlay {
    fleet_run_id: Uuid,
    driver_operation_id: Uuid,
    original_global_fence_token: i64,
    overlay_kind: ReleaseOverlayKind,
    target_slot: ReleaseTargetSlot,
    rows: Vec<PreparedReleaseRouteRow>,
    next_row: usize,
}

impl PreparedReleaseRouteOverlay {
    pub(super) const fn overlay_kind(&self) -> ReleaseOverlayKind {
        self.overlay_kind
    }

    pub(super) fn len(&self) -> usize {
        self.rows.len()
    }

    pub(super) fn is_complete(&self) -> bool {
        self.next_row == self.rows.len()
    }

    /// Exact records expected from a complete staging pass. Used to replay the
    /// database rows after authenticating a sealed filesystem generation left
    /// by a crash before the first database record.
    pub(super) fn records(&self) -> Vec<ReleaseRoutePublicationRecord> {
        self.rows.iter().map(|row| row.record.clone()).collect()
    }

    pub(super) fn expected_route_set_digest(&self) -> Result<String, DriverError> {
        let evidence = self
            .rows
            .iter()
            .map(|row| ReleaseRouteSealEvidence {
                workshop_id: row.record.workshop_id,
                projection_generation: row.record.generation,
                projection_digest: row.record.projection_digest.clone(),
                applied_rendered_digest: row.record.applied_rendered_digest.clone(),
                rendered_digest: row.record.rendered_digest.clone(),
            })
            .collect::<Vec<_>>();
        release_route_set_digest(&evidence).map_err(DriverError::internal)
    }

    /// Cross exactly one sealer durability boundary and return the identical
    /// typed record that the database transition must authenticate.
    pub(super) fn stage_next(
        &mut self,
        sealer: &mut ReleaseGenerationSealer<'_>,
    ) -> Result<Option<ReleaseRoutePublicationRecord>, DriverError> {
        if sealer.fleet_run_id() != self.fleet_run_id
            || sealer.driver_operation_id() != self.driver_operation_id
            || sealer.original_global_fence_token() != self.original_global_fence_token
            || sealer.overlay_kind() != self.overlay_kind
            || sealer.target_slot() != self.target_slot
        {
            return Err(DriverError::internal(
                "prepared release overlay differs from generation intent",
            ));
        }
        let Some(row) = self.rows.get(self.next_row) else {
            return Ok(None);
        };
        let evidence = sealer
            .stage_route(
                row.record.workshop_id,
                row.record.generation,
                &row.record.projection_digest,
                &row.record.applied_rendered_digest,
                &row.contents,
            )
            .map_err(DriverError::internal)?;
        validate_staged_evidence(&row.record, &evidence)?;
        self.next_row += 1;
        Ok(Some(row.record.clone()))
    }
}

/// Validate and render maintenance without requiring any candidate runtime.
pub(super) fn prepare_release_maintenance_overlay(
    snapshot: &FrozenReleaseRouteSnapshot,
) -> Result<PreparedReleaseRouteOverlay, DriverError> {
    prepare_release_route_overlay(ReleaseOverlayKind::Maintenance, snapshot, None)
}

/// Validate and render the candidate from an exact verified runtime binding.
pub(super) fn prepare_release_candidate_overlay(
    snapshot: &FrozenReleaseRouteSnapshot,
    runtime: &VerifiedReleaseRuntimeContext,
) -> Result<PreparedReleaseRouteOverlay, DriverError> {
    prepare_release_route_overlay(ReleaseOverlayKind::Candidate, snapshot, Some(runtime))
}

fn prepare_release_route_overlay(
    overlay_kind: ReleaseOverlayKind,
    snapshot: &FrozenReleaseRouteSnapshot,
    runtime: Option<&VerifiedReleaseRuntimeContext>,
) -> Result<PreparedReleaseRouteOverlay, DriverError> {
    let target_slot = validate_snapshot_shape(snapshot)?;
    if let Some(runtime) = runtime
        && runtime.target_slot != target_slot
    {
        return Err(DriverError::internal(
            "verified release runtime target slot drifted",
        ));
    }

    let mut rows = Vec::with_capacity(snapshot.rows.len());
    let mut required_paperless = Vec::new();
    for item in &snapshot.rows {
        validate_row_identity(item, target_slot)?;
        let projection = RouteProjection::parse(
            &item.canonical_projection,
            &item.projection_digest,
            item.disposition,
        )?;
        validate_projection_bindings(item, &projection)?;

        let rendered = match overlay_kind {
            ReleaseOverlayKind::Maintenance => projection.render_maintenance()?,
            ReleaseOverlayKind::Candidate => {
                let runtime = runtime.ok_or_else(|| {
                    DriverError::internal("verified release candidate runtime is absent")
                })?;
                let paperless_upstream = match projection.paperless_mode() {
                    PaperlessRouteMode::Absent => None,
                    PaperlessRouteMode::ReadOnly | PaperlessRouteMode::ReadWrite => {
                        required_paperless.push(item.workshop_id);
                        Some(
                            runtime
                                .paperless_upstreams
                                .get(&item.workshop_id)
                                .ok_or_else(|| {
                                    DriverError::internal(
                                        "frozen release Paperless runtime is absent",
                                    )
                                })?
                                .as_str(),
                        )
                    }
                };
                projection.render(Some(RouteRuntime {
                    odoo_upstream: &runtime.odoo_upstream,
                    paperless_upstream,
                }))?
            }
        };
        let contents = rendered
            .contents()
            .ok_or_else(|| DriverError::internal("release snapshot route is not present"))?
            .as_bytes()
            .to_vec();
        validate_route_bytes(&contents).map_err(DriverError::internal)?;
        rows.push(PreparedReleaseRouteRow {
            record: ReleaseRoutePublicationRecord {
                overlay_kind,
                workshop_id: item.workshop_id,
                generation: item.generation,
                projection_digest: item.projection_digest.clone(),
                applied_rendered_digest: item.applied_rendered_digest.clone(),
                rendered_digest: rendered.rendered_digest().to_owned(),
            },
            contents,
        });
    }

    if overlay_kind == ReleaseOverlayKind::Candidate
        && !runtime
            .ok_or_else(|| DriverError::internal("verified release candidate runtime is absent"))?
            .paperless_upstreams
            .keys()
            .copied()
            .eq(required_paperless)
    {
        return Err(DriverError::internal(
            "frozen release Paperless runtime context is not exact",
        ));
    }

    Ok(PreparedReleaseRouteOverlay {
        fleet_run_id: snapshot.fleet_run_id,
        driver_operation_id: snapshot.driver_operation_id,
        original_global_fence_token: snapshot.original_global_fence_token,
        overlay_kind,
        target_slot,
        rows,
        next_row: 0,
    })
}

fn validate_snapshot_shape(
    snapshot: &FrozenReleaseRouteSnapshot,
) -> Result<ReleaseTargetSlot, DriverError> {
    if snapshot.fleet_run_id.is_nil()
        || snapshot.driver_operation_id.is_nil()
        || snapshot.original_global_fence_token <= 0
        || snapshot.protocol_version != RELEASE_SNAPSHOT_PROTOCOL_VERSION
        || !(1..=MAX_RELEASE_SNAPSHOT_ROWS).contains(&snapshot.snapshot_count)
        || snapshot.rows.len() != snapshot.snapshot_count
    {
        return Err(DriverError::internal(
            "frozen release snapshot shape is invalid",
        ));
    }
    let mut previous = None;
    let target_slot = snapshot.rows[0].target_slot;
    for row in &snapshot.rows {
        if row.workshop_id.is_nil() || previous.is_some_and(|previous| previous >= row.workshop_id)
        {
            return Err(DriverError::internal(
                "frozen release snapshot is not strictly UUID ordered",
            ));
        }
        previous = Some(row.workshop_id);
    }
    Ok(target_slot)
}

fn validate_row_identity(
    row: &FrozenReleaseRouteSnapshotRow,
    target_slot: ReleaseTargetSlot,
) -> Result<(), DriverError> {
    if row.database_id.is_nil()
        || row.generation <= 0
        || row.applied_fence_token <= 0
        || row.route_fence_token <= 0
        || row.disposition != RouteDisposition::Present
        || row.target_slot != target_slot
    {
        return Err(DriverError::internal(
            "frozen release snapshot row identity is invalid",
        ));
    }
    validate_digest(&row.projection_digest, "projection digest").map_err(DriverError::internal)?;
    validate_digest(&row.applied_rendered_digest, "applied rendered digest")
        .map_err(DriverError::internal)
}

fn validate_projection_bindings(
    row: &FrozenReleaseRouteSnapshotRow,
    projection: &RouteProjection,
) -> Result<(), DriverError> {
    let projection_has_paperless = projection.paperless_mode() != PaperlessRouteMode::Absent;
    if projection.disposition() != RouteDisposition::Present
        || projection.database_id() != Some(row.database_id)
        || projection.database_ref() != Some(row.database_ref.as_str())
        || projection.projection_digest() != row.projection_digest
        || projection_has_paperless != row.paperless_enabled
    {
        return Err(DriverError::internal(
            "frozen release projection bindings do not match the snapshot",
        ));
    }
    Ok(())
}

fn validate_staged_evidence(
    record: &ReleaseRoutePublicationRecord,
    evidence: &ReleaseRouteSealEvidence,
) -> Result<(), DriverError> {
    if evidence.workshop_id != record.workshop_id
        || evidence.projection_generation != record.generation
        || evidence.projection_digest != record.projection_digest
        || evidence.applied_rendered_digest != record.applied_rendered_digest
        || evidence.rendered_digest != record.rendered_digest
    {
        return Err(DriverError::internal(
            "release sealer evidence differs from its database record",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs::DirBuilder;
    use std::os::unix::fs::DirBuilderExt as _;

    use serde_json::json;
    use sha2::{Digest as _, Sha256};

    use super::*;
    use crate::docker_driver::release_generation_fs::{
        ReleaseGenerationDirectory, ReleaseGenerationIntent,
    };
    use crate::docker_driver::route_generation_fs::ROUTE_ROOT_MODE;

    struct TestRoot(std::path::PathBuf);

    impl TestRoot {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("mb-release-stage-{}", Uuid::new_v4()));
            DirBuilder::new()
                .mode(ROUTE_ROOT_MODE)
                .create(&path)
                .unwrap();
            Self(path)
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn workshops() -> [Uuid; 2] {
        [
            Uuid::parse_str("10000000-0000-4000-8000-000000000001").unwrap(),
            Uuid::parse_str("20000000-0000-4000-8000-000000000002").unwrap(),
        ]
    }

    fn digest(bytes: &[u8]) -> String {
        format!("sha256:{:x}", Sha256::digest(bytes))
    }

    fn projection(database_id: Uuid, hostname: &str, paperless: bool) -> Value {
        json!({
            "database_id": database_id,
            "database_ref": crate::domain::opaque_database_ref(database_id),
            "public_hostname": hostname,
            "paperless_mode": if paperless { "read_write" } else { "absent" },
            "paperless_hostname": if paperless { Value::String(format!("docs.{hostname}")) } else { Value::Null },
            "custom_hostnames": []
        })
    }

    fn row(workshop_id: Uuid, hostname: &str, paperless: bool) -> FrozenReleaseRouteSnapshotRow {
        let database_id = Uuid::new_v4();
        let projection = projection(database_id, hostname, paperless);
        FrozenReleaseRouteSnapshotRow {
            workshop_id,
            database_id,
            database_ref: crate::domain::opaque_database_ref(database_id),
            paperless_enabled: paperless,
            generation: 7,
            projection_digest: digest(&serde_jcs::to_vec(&projection).unwrap()),
            disposition: RouteDisposition::Present,
            canonical_projection: projection,
            applied_rendered_digest: digest(b"frozen-applied-route"),
            applied_fence_token: 11,
            route_fence_token: 12,
            target_slot: ReleaseTargetSlot::Green,
        }
    }

    fn snapshot() -> FrozenReleaseRouteSnapshot {
        FrozenReleaseRouteSnapshot {
            fleet_run_id: Uuid::new_v4(),
            driver_operation_id: Uuid::new_v4(),
            original_global_fence_token: 17,
            protocol_version: 2,
            snapshot_count: 2,
            rows: vec![
                row(workshops()[0], "alpha.example.test", false),
                row(workshops()[1], "beta.example.test", true),
            ],
        }
    }

    fn resolver() -> ReleaseRuntimeNameResolver {
        ReleaseRuntimeNameResolver::from_test_namespace("mb-test")
    }

    fn runtime() -> VerifiedReleaseRuntimeContext {
        resolver()
            .verify_candidate_runtime(
                ReleaseTargetSlot::Green,
                "mb-test-odoo-green",
                &BTreeMap::from([(
                    workshops()[1],
                    format!("mb-test-paperless-{}", workshops()[1].simple()),
                )]),
            )
            .unwrap()
    }

    #[test]
    fn frozen_snapshot_prepares_exact_maintenance_and_candidate_records() {
        let snapshot = snapshot();
        let maintenance = prepare_release_maintenance_overlay(&snapshot).unwrap();
        let candidate = prepare_release_candidate_overlay(&snapshot, &runtime()).unwrap();

        assert_eq!(maintenance.len(), 2);
        assert_eq!(candidate.len(), 2);
        assert_eq!(
            maintenance.rows[0].record.overlay_kind,
            ReleaseOverlayKind::Maintenance
        );
        assert_eq!(
            candidate.rows[0].record.overlay_kind,
            ReleaseOverlayKind::Candidate
        );
        assert_ne!(maintenance.rows[0].contents, candidate.rows[0].contents);
        assert!(
            String::from_utf8(candidate.rows[0].contents.clone())
                .unwrap()
                .contains("mb-test-odoo-green:8069")
        );
        assert_eq!(
            candidate.rows[0].record.applied_rendered_digest,
            snapshot.rows[0].applied_rendered_digest
        );
    }

    #[test]
    fn staged_record_is_exactly_the_release_sealer_evidence() {
        let root = TestRoot::new();
        let snapshot = snapshot();
        let intent = ReleaseGenerationIntent::new(
            snapshot.fleet_run_id,
            snapshot.driver_operation_id,
            snapshot.original_global_fence_token,
            ReleaseOverlayKind::Candidate,
            "green",
        )
        .unwrap();
        let mut generation = ReleaseGenerationDirectory::create_or_open(&root.0, intent).unwrap();
        let mut sealer = generation.begin_seal().unwrap();
        let mut prepared = prepare_release_candidate_overlay(&snapshot, &runtime()).unwrap();

        let first = prepared.stage_next(&mut sealer).unwrap().unwrap();
        let second = prepared.stage_next(&mut sealer).unwrap().unwrap();
        assert!(prepared.stage_next(&mut sealer).unwrap().is_none());
        assert!(prepared.is_complete());
        assert!(first.workshop_id < second.workshop_id);
        assert_eq!(sealer.finish().unwrap().route_count, 2);
    }

    #[test]
    fn prepared_overlay_must_match_the_generation_intent() {
        let root = TestRoot::new();
        let snapshot = snapshot();
        let intent = ReleaseGenerationIntent::new(
            Uuid::new_v4(),
            snapshot.driver_operation_id,
            snapshot.original_global_fence_token,
            ReleaseOverlayKind::Candidate,
            "green",
        )
        .unwrap();
        let mut generation = ReleaseGenerationDirectory::create_or_open(&root.0, intent).unwrap();
        let mut sealer = generation.begin_seal().unwrap();
        let mut candidate = prepare_release_candidate_overlay(&snapshot, &runtime()).unwrap();

        assert!(candidate.stage_next(&mut sealer).is_err());
    }

    #[test]
    fn rejects_non_v2_unbounded_unordered_or_non_present_snapshots() {
        let mut invalid = snapshot();
        invalid.protocol_version = 1;
        assert!(prepare_release_candidate_overlay(&invalid, &runtime()).is_err());

        let mut invalid = snapshot();
        invalid.snapshot_count = 1;
        assert!(prepare_release_candidate_overlay(&invalid, &runtime()).is_err());

        let template = row(workshops()[0], "alpha.example.test", false);
        let invalid = FrozenReleaseRouteSnapshot {
            fleet_run_id: Uuid::new_v4(),
            driver_operation_id: Uuid::new_v4(),
            original_global_fence_token: 17,
            protocol_version: 2,
            snapshot_count: 501,
            rows: vec![template; 501],
        };
        assert!(prepare_release_candidate_overlay(&invalid, &runtime()).is_err());

        let mut invalid = snapshot();
        invalid.rows.swap(0, 1);
        assert!(prepare_release_candidate_overlay(&invalid, &runtime()).is_err());

        let mut invalid = snapshot();
        invalid.rows[0].disposition = RouteDisposition::Absent;
        assert!(prepare_release_candidate_overlay(&invalid, &runtime()).is_err());
    }

    #[test]
    fn rejects_database_paperless_slot_and_baseline_digest_drift() {
        let mut invalid = snapshot();
        invalid.rows[0].database_id = Uuid::new_v4();
        assert!(prepare_release_candidate_overlay(&invalid, &runtime()).is_err());

        let mut invalid = snapshot();
        invalid.rows[1].paperless_enabled = false;
        assert!(prepare_release_candidate_overlay(&invalid, &runtime()).is_err());

        let mut invalid = snapshot();
        invalid.rows[0].target_slot = ReleaseTargetSlot::Blue;
        assert!(prepare_release_candidate_overlay(&invalid, &runtime()).is_err());

        let mut invalid = snapshot();
        invalid.rows[0].applied_rendered_digest = "sha256:not-a-digest".into();
        assert!(prepare_release_candidate_overlay(&invalid, &runtime()).is_err());
    }

    #[test]
    fn candidate_runtime_rejects_wrong_slot_and_cross_workshop_names() {
        let snapshot = snapshot();
        assert!(
            resolver()
                .verify_candidate_runtime(
                    ReleaseTargetSlot::Green,
                    "mb-test-odoo-blue",
                    &BTreeMap::new(),
                )
                .is_err()
        );

        let first_name = format!("mb-test-paperless-{}", workshops()[0].simple());
        assert!(
            resolver()
                .verify_candidate_runtime(
                    ReleaseTargetSlot::Green,
                    "mb-test-odoo-green",
                    &BTreeMap::from([(workshops()[1], first_name)]),
                )
                .is_err()
        );
        assert!(prepare_release_maintenance_overlay(&snapshot).is_ok());
    }

    #[test]
    fn candidate_runtime_inventory_must_match_paperless_projection_exactly() {
        let snapshot = snapshot();
        let empty = resolver()
            .verify_candidate_runtime(
                ReleaseTargetSlot::Green,
                "mb-test-odoo-green",
                &BTreeMap::new(),
            )
            .unwrap();
        assert!(prepare_release_candidate_overlay(&snapshot, &empty).is_err());
    }

    #[test]
    fn module_is_private_and_has_no_active_callsite() {
        let driver_root = include_str!("../docker_driver.rs");
        assert_eq!(driver_root.matches("mod release_route_staging;").count(), 1);
        assert!(!driver_root.contains("use release_route_staging"));
        assert!(!driver_root.contains("release_route_staging::"));
        let source = include_str!("release_route_staging.rs");
        assert!(!source.contains(&["CURRENT", "_SELECTOR"].concat()));
        assert!(!source.contains(&["read", "_to_string"].concat()));
    }
}
