//! Pure, dormant adapter from a frozen route snapshot to an immutable route set.
//!
//! The future database publication protocol owns how the snapshot and runtime
//! identity are frozen. This module accepts those values as data, renders them,
//! and stages deterministic evidence. It performs no database access, runtime
//! discovery, selector publication, reload, or observation.
#![allow(dead_code)]

use std::collections::BTreeMap;

use serde_json::Value;
use uuid::Uuid;

use super::gateway::RouteSetPublicationKind;
use super::route_generation_fs::{validate_digest, validate_route_bytes};
use super::route_projection::{
    PaperlessRouteMode, RouteDisposition, RouteProjection, RouteRuntime,
};
use super::route_set_generation_fs::{MAX_ROUTES, RouteSetGenerationSealer, RouteSetSealEvidence};
use super::{DriverError, runtime_backend};

/// Runtime names captured by the same authority that froze the route snapshot.
/// A Paperless entry is required exactly when that workshop's projection routes
/// to Paperless. The adapter never derives a mutable container name.
pub(super) struct FrozenRouteRuntimeContext {
    pub odoo_upstream: String,
    pub paperless_upstreams: BTreeMap<Uuid, String>,
}

/// One effective candidate row from an already-frozen, UUID-ordered snapshot.
///
/// For the target this is the admitted projection (normal publication), the
/// applied projection to mask (maintenance), or the projection to restore. For
/// every other workshop it is the exact frozen applied projection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct FrozenRouteSetSnapshotItem {
    pub workshop_id: Uuid,
    pub projection_generation: i64,
    pub projection_digest: String,
    pub disposition: RouteDisposition,
    pub canonical_projection: Option<Value>,
    pub applied_rendered_digest: String,
}

/// A fully validated and rendered route set that has not touched the generation
/// directory yet. Keeping preparation separate from staging lets the caller
/// renew durable authority between individual filesystem durability boundaries.
pub(super) struct PreparedFrozenRouteSet {
    publication_kind: RouteSetPublicationKind,
    target_workshop_id: Option<Uuid>,
    rows: Vec<PreparedFrozenRouteSetRow>,
    next_row: usize,
}

struct PreparedFrozenRouteSetRow {
    workshop_id: Uuid,
    projection_generation: i64,
    projection_digest: String,
    applied_rendered_digest: String,
    contents: Option<Vec<u8>>,
}

impl PreparedFrozenRouteSet {
    pub(super) fn len(&self) -> usize {
        self.rows.len()
    }

    pub(super) fn is_complete(&self) -> bool {
        self.next_row == self.rows.len()
    }

    /// Stage exactly one UUID-ordered row and return only after its route bytes
    /// and manifest evidence have crossed the sealer's durability boundary.
    pub(super) fn stage_next(
        &mut self,
        sealer: &mut RouteSetGenerationSealer<'_>,
    ) -> Result<Option<RouteSetSealEvidence>, DriverError> {
        if self.publication_kind != sealer.publication_kind()
            || self.target_workshop_id != sealer.target_workshop_id()
        {
            return Err(DriverError::internal(
                "prepared route-set differs from generation intent",
            ));
        }
        let Some(row) = self.rows.get(self.next_row) else {
            return Ok(None);
        };
        let evidence = match &row.contents {
            Some(contents) => sealer.stage_present(
                row.workshop_id,
                row.projection_generation,
                &row.projection_digest,
                &row.applied_rendered_digest,
                contents,
            ),
            None => sealer.stage_absent(
                row.workshop_id,
                row.projection_generation,
                &row.projection_digest,
                &row.applied_rendered_digest,
            ),
        }
        .map_err(DriverError::internal)?;
        self.next_row += 1;
        Ok(Some(evidence))
    }
}

/// Validate and render the entire frozen snapshot without performing any
/// filesystem operation. If this succeeds, every row is ready for ordered,
/// incremental staging.
pub(super) fn prepare_frozen_route_set(
    publication_kind: RouteSetPublicationKind,
    target_workshop_id: Uuid,
    runtime: &FrozenRouteRuntimeContext,
    items: &[FrozenRouteSetSnapshotItem],
) -> Result<PreparedFrozenRouteSet, DriverError> {
    prepare_frozen_route_set_scoped(publication_kind, Some(target_workshop_id), runtime, items)
}

/// Prepare a fleet-scoped startup generation. Empty fleets are valid and no
/// workshop is privileged as a synthetic target.
pub(super) fn prepare_startup_frozen_route_set(
    runtime: &FrozenRouteRuntimeContext,
    items: &[FrozenRouteSetSnapshotItem],
) -> Result<PreparedFrozenRouteSet, DriverError> {
    prepare_frozen_route_set_scoped(RouteSetPublicationKind::Startup, None, runtime, items)
}

fn prepare_frozen_route_set_scoped(
    publication_kind: RouteSetPublicationKind,
    target_workshop_id: Option<Uuid>,
    runtime: &FrozenRouteRuntimeContext,
    items: &[FrozenRouteSetSnapshotItem],
) -> Result<PreparedFrozenRouteSet, DriverError> {
    validate_snapshot_shape(target_workshop_id, runtime, items)?;

    let mut rows = Vec::with_capacity(items.len());
    let mut required_paperless_upstreams = Vec::new();
    for item in items {
        if item.projection_generation <= 0 {
            return Err(DriverError::internal(
                "frozen route projection generation is not positive",
            ));
        }
        validate_digest(&item.projection_digest, "projection digest")
            .map_err(DriverError::internal)?;
        validate_digest(&item.applied_rendered_digest, "applied rendered digest")
            .map_err(DriverError::internal)?;
        let projection = RouteProjection::parse_optional(
            item.canonical_projection.as_ref(),
            &item.projection_digest,
            item.disposition,
        )?;
        let is_target = target_workshop_id == Some(item.workshop_id);
        let rendered =
            if is_target && publication_kind == RouteSetPublicationKind::RecoveryMaintenance {
                if item.disposition != RouteDisposition::Present {
                    return Err(DriverError::internal(
                        "recovery maintenance target projection is absent",
                    ));
                }
                projection.render_maintenance()?
            } else {
                let route_runtime = match item.disposition {
                    RouteDisposition::Absent => None,
                    RouteDisposition::Present => Some(RouteRuntime {
                        odoo_upstream: &runtime.odoo_upstream,
                        paperless_upstream: match projection.paperless_mode() {
                            PaperlessRouteMode::Absent => None,
                            PaperlessRouteMode::ReadOnly | PaperlessRouteMode::ReadWrite => {
                                required_paperless_upstreams.push(item.workshop_id);
                                Some(runtime
                                .paperless_upstreams
                                .get(&item.workshop_id)
                                .ok_or_else(|| {
                                    DriverError::internal(
                                        "frozen Paperless runtime is absent for route projection",
                                    )
                                })?
                                .as_str())
                            }
                        },
                    }),
                };
                projection.render(route_runtime)?
            };

        // Every non-target row must reproduce the frozen applied fleet byte for
        // byte. A restore target is intentionally different: maintenance can
        // span a later desired projection, so its candidate is rendered from
        // the desired row while `applied_rendered_digest` remains the immutable
        // pre-publication baseline used by database CAS/finalization.
        let must_reproduce_applied =
            !is_target && publication_kind != RouteSetPublicationKind::Startup;
        if must_reproduce_applied && rendered.rendered_digest() != item.applied_rendered_digest {
            return Err(DriverError::internal(
                "frozen applied route rendered digest drifted",
            ));
        }

        let contents = rendered
            .contents()
            .map(|contents| contents.as_bytes().to_vec());
        if let Some(contents) = &contents {
            validate_route_bytes(contents).map_err(DriverError::internal)?;
        }
        rows.push(PreparedFrozenRouteSetRow {
            workshop_id: item.workshop_id,
            projection_generation: item.projection_generation,
            projection_digest: item.projection_digest.clone(),
            applied_rendered_digest: item.applied_rendered_digest.clone(),
            contents,
        });
    }
    if !runtime
        .paperless_upstreams
        .keys()
        .copied()
        .eq(required_paperless_upstreams)
    {
        return Err(DriverError::internal(
            "frozen Paperless runtime context is not exact for route projections",
        ));
    }
    Ok(PreparedFrozenRouteSet {
        publication_kind,
        target_workshop_id,
        rows,
        next_row: 0,
    })
}

/// Render and stage a complete frozen route set without publishing it.
///
/// Returning evidence separately lets a future durable protocol record and
/// replay every row before it permits sealing or selector publication.
pub(super) fn stage_frozen_route_set(
    sealer: &mut RouteSetGenerationSealer<'_>,
    publication_kind: RouteSetPublicationKind,
    target_workshop_id: Uuid,
    runtime: &FrozenRouteRuntimeContext,
    items: &[FrozenRouteSetSnapshotItem],
) -> Result<Vec<RouteSetSealEvidence>, DriverError> {
    if publication_kind != sealer.publication_kind()
        || Some(target_workshop_id) != sealer.target_workshop_id()
    {
        return Err(DriverError::internal(
            "route-set staging plan differs from generation intent",
        ));
    }
    let mut prepared =
        prepare_frozen_route_set(publication_kind, target_workshop_id, runtime, items)?;
    let mut evidence = Vec::with_capacity(prepared.len());
    while let Some(row) = prepared.stage_next(sealer)? {
        evidence.push(row);
    }
    Ok(evidence)
}

pub(super) fn stage_startup_frozen_route_set(
    sealer: &mut RouteSetGenerationSealer<'_>,
    runtime: &FrozenRouteRuntimeContext,
    items: &[FrozenRouteSetSnapshotItem],
) -> Result<Vec<RouteSetSealEvidence>, DriverError> {
    if sealer.publication_kind() != RouteSetPublicationKind::Startup
        || sealer.target_workshop_id().is_some()
    {
        return Err(DriverError::internal(
            "startup staging requires fleet-scoped generation intent",
        ));
    }
    let mut prepared = prepare_startup_frozen_route_set(runtime, items)?;
    let mut evidence = Vec::with_capacity(prepared.len());
    while let Some(row) = prepared.stage_next(sealer)? {
        evidence.push(row);
    }
    Ok(evidence)
}

fn validate_snapshot_shape(
    target_workshop_id: Option<Uuid>,
    runtime: &FrozenRouteRuntimeContext,
    items: &[FrozenRouteSetSnapshotItem],
) -> Result<(), DriverError> {
    if target_workshop_id.is_some_and(|id| id.is_nil())
        || (target_workshop_id.is_some() && items.is_empty())
        || items.len() > MAX_ROUTES
    {
        return Err(DriverError::internal(
            "frozen route-set snapshot shape is invalid",
        ));
    }
    runtime_backend::validate_name(&runtime.odoo_upstream)?;
    if runtime.paperless_upstreams.len() > MAX_ROUTES
        || runtime.paperless_upstreams.iter().any(|(workshop, name)| {
            workshop.is_nil() || runtime_backend::validate_name(name).is_err()
        })
    {
        return Err(DriverError::internal(
            "frozen route-set runtime context is invalid",
        ));
    }

    let mut previous = None;
    let mut target_count = 0;
    for item in items {
        if item.workshop_id.is_nil()
            || previous.is_some_and(|previous| previous >= item.workshop_id)
        {
            return Err(DriverError::internal(
                "frozen route-set snapshot is not strictly UUID ordered",
            ));
        }
        target_count += usize::from(target_workshop_id == Some(item.workshop_id));
        previous = Some(item.workshop_id);
    }
    if target_count != usize::from(target_workshop_id.is_some()) {
        return Err(DriverError::internal(
            "frozen route-set snapshot does not contain its target exactly once",
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
    use crate::docker_driver::route_generation_fs::{GENERATIONS_DIRECTORY, ROUTE_ROOT_MODE};
    use crate::docker_driver::route_set_generation_fs::{
        RouteDisposition as SealDisposition, RouteSetGenerationDirectory, RouteSetGenerationIntent,
        RouteSetGenerationName,
    };

    struct TestRoot(std::path::PathBuf);

    impl TestRoot {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("mb-route-stage-{}", Uuid::new_v4()));
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
            Uuid::parse_str("10000000-0000-0000-0000-000000000001").unwrap(),
            Uuid::parse_str("20000000-0000-0000-0000-000000000002").unwrap(),
        ]
    }

    fn digest_bytes(bytes: &[u8]) -> String {
        format!("sha256:{:x}", Sha256::digest(bytes))
    }

    fn projection_digest(projection: &Value) -> String {
        digest_bytes(&serde_jcs::to_vec(projection).unwrap())
    }

    fn present(database_id: Uuid, hostname: &str, paperless: bool) -> Value {
        json!({
            "database_id":database_id,
            "database_ref":crate::domain::opaque_database_ref(database_id),
            "public_hostname":hostname,
            "paperless_mode":if paperless { "read_only" } else { "absent" },
            "paperless_hostname":if paperless { json!(format!("docs.{hostname}")) } else { Value::Null },
            "custom_hostnames":[],
        })
    }

    fn absent() -> Value {
        json!({"database_id":null,"database_ref":null,"public_hostname":null,
            "paperless_mode":"absent","paperless_hostname":null,"custom_hostnames":[]})
    }

    fn item(workshop_id: Uuid, generation: i64, projection: Value) -> FrozenRouteSetSnapshotItem {
        let disposition = if projection["database_id"].is_null() {
            RouteDisposition::Absent
        } else {
            RouteDisposition::Present
        };
        let projection_digest = projection_digest(&projection);
        FrozenRouteSetSnapshotItem {
            workshop_id,
            projection_generation: generation,
            projection_digest,
            disposition,
            canonical_projection: Some(projection),
            applied_rendered_digest: digest_bytes(b"prior"),
        }
    }

    fn runtime() -> FrozenRouteRuntimeContext {
        FrozenRouteRuntimeContext {
            odoo_upstream: "odoo-frozen".into(),
            paperless_upstreams: BTreeMap::from([(workshops()[1], "paperless-frozen".into())]),
        }
    }

    fn runtime_without_paperless() -> FrozenRouteRuntimeContext {
        FrozenRouteRuntimeContext {
            odoo_upstream: "odoo-frozen".into(),
            paperless_upstreams: BTreeMap::new(),
        }
    }

    #[test]
    fn startup_scope_has_no_fake_target_and_accepts_empty_or_changed_fleet() {
        assert!(prepare_startup_frozen_route_set(&runtime_without_paperless(), &[]).is_ok());
        let [first, _] = workshops();
        let changed = item(first, 7, present(Uuid::new_v4(), "one.example", false));
        assert_ne!(expected_normal(&changed), changed.applied_rendered_digest);
        let prepared = prepare_startup_frozen_route_set(
            &runtime_without_paperless(),
            std::slice::from_ref(&changed),
        )
        .unwrap();
        assert_eq!(prepared.target_workshop_id, None);
        assert_eq!(prepared.publication_kind, RouteSetPublicationKind::Startup);
    }

    fn expected_normal(item: &FrozenRouteSetSnapshotItem) -> String {
        let projection = RouteProjection::parse_optional(
            item.canonical_projection.as_ref(),
            &item.projection_digest,
            item.disposition,
        )
        .unwrap();
        projection
            .render(match item.disposition {
                RouteDisposition::Absent => None,
                RouteDisposition::Present => Some(RouteRuntime {
                    odoo_upstream: "odoo-frozen",
                    paperless_upstream: (projection.paperless_mode() != PaperlessRouteMode::Absent)
                        .then_some("paperless-frozen"),
                }),
            })
            .unwrap()
            .rendered_digest()
            .to_owned()
    }

    fn intent(kind: RouteSetPublicationKind, target: Uuid) -> RouteSetGenerationIntent {
        RouteSetGenerationIntent::new(Uuid::new_v4(), kind, 11, target, 17).unwrap()
    }

    #[test]
    fn adapter_is_registered_but_has_no_active_writer_callsite() {
        let driver_root = include_str!("../docker_driver.rs");
        assert_eq!(driver_root.matches("mod route_set_staging;").count(), 1);
        assert!(!driver_root.contains("use route_set_staging"));
        assert!(!driver_root.contains("route_set_staging::"));
        for active_source in [
            include_str!("startup.rs"),
            include_str!("release.rs"),
            include_str!("recovery.rs"),
            include_str!("gateway.rs"),
        ] {
            assert!(!active_source.contains("stage_frozen_route_set"));
            assert!(!active_source.contains("prepare_frozen_route_set"));
        }
    }

    #[test]
    fn stages_projection_target_and_unchanged_fleet() {
        let root = TestRoot::new();
        let target = workshops()[0];
        let mut items = vec![
            item(
                target,
                4,
                present(Uuid::new_v4(), "one.example.test", false),
            ),
            item(
                workshops()[1],
                8,
                present(Uuid::new_v4(), "two.example.test", true),
            ),
        ];
        items[1].applied_rendered_digest = expected_normal(&items[1]);
        let mut generation = RouteSetGenerationDirectory::create_or_open(
            &root.0,
            intent(RouteSetPublicationKind::Projection, target),
        )
        .unwrap();
        let mut sealer = generation.begin_seal().unwrap();
        let evidence = stage_frozen_route_set(
            &mut sealer,
            RouteSetPublicationKind::Projection,
            target,
            &runtime(),
            &items,
        )
        .unwrap();
        assert_eq!(evidence.len(), 2);
        assert_eq!(
            evidence[1].rendered_digest,
            items[1].applied_rendered_digest
        );
        assert_ne!(
            evidence[0].rendered_digest,
            items[0].applied_rendered_digest
        );
        assert_eq!(sealer.finish().unwrap().route_count, 2);
    }

    #[test]
    fn stages_recovery_maintenance_only_for_target() {
        let root = TestRoot::new();
        let target = workshops()[0];
        let mut items = vec![
            item(
                target,
                4,
                present(Uuid::new_v4(), "one.example.test", false),
            ),
            item(
                workshops()[1],
                8,
                present(Uuid::new_v4(), "two.example.test", true),
            ),
        ];
        items[1].applied_rendered_digest = expected_normal(&items[1]);
        let intent = intent(RouteSetPublicationKind::RecoveryMaintenance, target);
        let mut generation = RouteSetGenerationDirectory::create_or_open(&root.0, intent).unwrap();
        let mut sealer = generation.begin_seal().unwrap();
        let evidence = stage_frozen_route_set(
            &mut sealer,
            RouteSetPublicationKind::RecoveryMaintenance,
            target,
            &runtime(),
            &items,
        )
        .unwrap();
        let expected = RouteProjection::parse_optional(
            items[0].canonical_projection.as_ref(),
            &items[0].projection_digest,
            RouteDisposition::Present,
        )
        .unwrap()
        .render_maintenance()
        .unwrap()
        .rendered_digest()
        .to_owned();
        assert_eq!(evidence[0].rendered_digest, expected);
        assert_eq!(
            evidence[1].rendered_digest,
            items[1].applied_rendered_digest
        );
    }

    #[test]
    fn stages_recovery_restore_absence_without_route_bytes() {
        let root = TestRoot::new();
        let target = workshops()[0];
        let mut target_item = item(target, 9, absent());
        target_item.canonical_projection = None;
        target_item.applied_rendered_digest = digest_bytes(&[]);
        let mut other = item(
            workshops()[1],
            8,
            present(Uuid::new_v4(), "two.example.test", true),
        );
        other.applied_rendered_digest = expected_normal(&other);
        let items = vec![target_item, other];
        let intent = intent(RouteSetPublicationKind::RecoveryRestore, target);
        let mut generation = RouteSetGenerationDirectory::create_or_open(&root.0, intent).unwrap();
        let mut sealer = generation.begin_seal().unwrap();
        let evidence = stage_frozen_route_set(
            &mut sealer,
            RouteSetPublicationKind::RecoveryRestore,
            target,
            &runtime(),
            &items,
        )
        .unwrap();
        assert_eq!(evidence[0].disposition, SealDisposition::Absent);
        assert_eq!(evidence[0].rendered_digest, digest_bytes(&[]));
    }

    #[test]
    fn recovery_restore_renders_changed_desired_target_and_keeps_baseline_digest() {
        let root = TestRoot::new();
        let target = workshops()[0];
        let target_item = item(
            target,
            9,
            present(Uuid::new_v4(), "one.example.test", false),
        );
        let baseline_digest = target_item.applied_rendered_digest.clone();
        let mut other = item(workshops()[1], 8, absent());
        other.applied_rendered_digest = digest_bytes(&[]);
        let items = vec![target_item, other];
        let intent = intent(RouteSetPublicationKind::RecoveryRestore, target);
        let mut generation = RouteSetGenerationDirectory::create_or_open(&root.0, intent).unwrap();
        let mut sealer = generation.begin_seal().unwrap();
        let evidence = stage_frozen_route_set(
            &mut sealer,
            RouteSetPublicationKind::RecoveryRestore,
            target,
            &runtime_without_paperless(),
            &items,
        )
        .unwrap();
        assert_eq!(evidence[0].applied_rendered_digest, Some(baseline_digest));
        assert_ne!(
            evidence[0].rendered_digest,
            evidence[0].applied_rendered_digest.clone().unwrap()
        );
    }

    #[test]
    fn rejects_non_target_render_drift_before_recording_that_row() {
        let root = TestRoot::new();
        let target = workshops()[0];
        let items = vec![
            item(
                target,
                4,
                present(Uuid::new_v4(), "one.example.test", false),
            ),
            item(
                workshops()[1],
                8,
                present(Uuid::new_v4(), "two.example.test", true),
            ),
        ];
        let mut generation = RouteSetGenerationDirectory::create_or_open(
            &root.0,
            intent(RouteSetPublicationKind::Projection, target),
        )
        .unwrap();
        let mut sealer = generation.begin_seal().unwrap();
        assert!(
            stage_frozen_route_set(
                &mut sealer,
                RouteSetPublicationKind::Projection,
                target,
                &runtime(),
                &items,
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_order_count_and_target_shape_before_staging() {
        let root = TestRoot::new();
        let target = workshops()[0];
        let first = item(target, 1, absent());
        let second = item(workshops()[1], 2, absent());
        let intent = intent(RouteSetPublicationKind::Projection, target);
        let mut generation = RouteSetGenerationDirectory::create_or_open(&root.0, intent).unwrap();
        let mut sealer = generation.begin_seal().unwrap();
        assert!(
            stage_frozen_route_set(
                &mut sealer,
                RouteSetPublicationKind::Projection,
                target,
                &runtime(),
                &[second, first],
            )
            .is_err()
        );

        let oversized = (1..=(MAX_ROUTES + 1))
            .map(|value| item(Uuid::from_u128(value as u128), 1, absent()))
            .collect::<Vec<_>>();
        assert!(
            stage_frozen_route_set(
                &mut sealer,
                RouteSetPublicationKind::Projection,
                Uuid::from_u128(1),
                &runtime(),
                &oversized,
            )
            .is_err()
        );
    }

    #[test]
    fn identical_retry_replays_compatible_evidence() {
        let root = TestRoot::new();
        let target = workshops()[0];
        let mut items = vec![
            item(
                target,
                4,
                present(Uuid::new_v4(), "one.example.test", false),
            ),
            item(workshops()[1], 8, absent()),
        ];
        items[1].applied_rendered_digest = digest_bytes(&[]);
        let intent = intent(RouteSetPublicationKind::Projection, target);
        let first = {
            let mut generation =
                RouteSetGenerationDirectory::create_or_open(&root.0, intent.clone()).unwrap();
            let mut sealer = generation.begin_seal().unwrap();
            stage_frozen_route_set(
                &mut sealer,
                RouteSetPublicationKind::Projection,
                target,
                &runtime_without_paperless(),
                &items,
            )
            .unwrap()
        };
        let mut generation = RouteSetGenerationDirectory::create_or_open(&root.0, intent).unwrap();
        let mut sealer = generation.begin_seal().unwrap();
        let retry = stage_frozen_route_set(
            &mut sealer,
            RouteSetPublicationKind::Projection,
            target,
            &runtime_without_paperless(),
            &items,
        )
        .unwrap();
        assert_eq!(retry, first);
        assert_eq!(sealer.finish().unwrap().route_count, items.len());
    }

    #[test]
    fn preparation_rejects_a_late_invalid_row_before_any_route_bytes() {
        let root = TestRoot::new();
        let target = workshops()[0];
        let mut items = vec![
            item(
                target,
                4,
                present(Uuid::new_v4(), "one.example.test", false),
            ),
            item(
                workshops()[1],
                8,
                present(Uuid::new_v4(), "two.example.test", true),
            ),
        ];
        // The second row is deliberately invalid. The old streaming renderer
        // could already have written the first route before discovering this.
        items[1].applied_rendered_digest = digest_bytes(b"not-the-frozen-route");
        let intent = intent(RouteSetPublicationKind::Projection, target);
        let name = RouteSetGenerationName::new(intent.publication_id, intent.publication_kind);
        let mut generation = RouteSetGenerationDirectory::create_or_open(&root.0, intent).unwrap();
        let mut sealer = generation.begin_seal().unwrap();
        assert!(
            stage_frozen_route_set(
                &mut sealer,
                RouteSetPublicationKind::Projection,
                target,
                &runtime(),
                &items,
            )
            .is_err()
        );
        assert!(
            !root
                .0
                .join(GENERATIONS_DIRECTORY)
                .join(name.as_str())
                .join(format!("{target}.conf"))
                .exists()
        );
    }

    #[test]
    fn preparation_checks_late_sealer_inputs_before_any_route_bytes() {
        for invalid_generation in [true, false] {
            let root = TestRoot::new();
            let target = workshops()[0];
            let mut items = vec![
                item(
                    target,
                    4,
                    present(Uuid::new_v4(), "one.example.test", false),
                ),
                item(
                    workshops()[1],
                    8,
                    present(Uuid::new_v4(), "two.example.test", true),
                ),
            ];
            items[1].applied_rendered_digest = expected_normal(&items[1]);
            if invalid_generation {
                items[1].projection_generation = 0;
            } else {
                items[1].applied_rendered_digest = "sha256:not-a-digest".into();
            }

            let intent = intent(RouteSetPublicationKind::Projection, target);
            let name = RouteSetGenerationName::new(intent.publication_id, intent.publication_kind);
            let mut generation =
                RouteSetGenerationDirectory::create_or_open(&root.0, intent).unwrap();
            let mut sealer = generation.begin_seal().unwrap();
            assert!(
                stage_frozen_route_set(
                    &mut sealer,
                    RouteSetPublicationKind::Projection,
                    target,
                    &runtime(),
                    &items,
                )
                .is_err()
            );
            assert!(
                !root
                    .0
                    .join(GENERATIONS_DIRECTORY)
                    .join(name.as_str())
                    .join(format!("{target}.conf"))
                    .exists()
            );
        }
    }

    #[test]
    fn prepared_rows_stage_incrementally_in_uuid_order() {
        let root = TestRoot::new();
        let target = workshops()[0];
        let mut items = vec![
            item(
                target,
                4,
                present(Uuid::new_v4(), "one.example.test", false),
            ),
            item(workshops()[1], 8, absent()),
        ];
        items[1].applied_rendered_digest = digest_bytes(&[]);
        let mut prepared = prepare_frozen_route_set(
            RouteSetPublicationKind::Projection,
            target,
            &runtime_without_paperless(),
            &items,
        )
        .unwrap();
        assert_eq!(prepared.len(), 2);
        assert!(!prepared.is_complete());

        let mut generation = RouteSetGenerationDirectory::create_or_open(
            &root.0,
            intent(RouteSetPublicationKind::Projection, target),
        )
        .unwrap();
        let mut sealer = generation.begin_seal().unwrap();
        let first = prepared.stage_next(&mut sealer).unwrap().unwrap();
        assert_eq!(first.workshop_id, items[0].workshop_id);
        assert!(!prepared.is_complete());
        let second = prepared.stage_next(&mut sealer).unwrap().unwrap();
        assert_eq!(second.workshop_id, items[1].workshop_id);
        assert!(prepared.is_complete());
        assert!(prepared.stage_next(&mut sealer).unwrap().is_none());
        assert_eq!(sealer.finish().unwrap().route_count, 2);
    }

    #[test]
    fn absent_payload_omission_still_requires_the_canonical_digest() {
        let target = workshops()[0];
        let mut target_item = item(target, 4, absent());
        target_item.canonical_projection = None;
        target_item.applied_rendered_digest = digest_bytes(&[]);
        let prepared = prepare_frozen_route_set(
            RouteSetPublicationKind::RecoveryRestore,
            target,
            &runtime_without_paperless(),
            std::slice::from_ref(&target_item),
        )
        .unwrap();
        assert_eq!(prepared.len(), 1);

        target_item.projection_digest = digest_bytes(b"not-canonical-absent");
        assert!(
            prepare_frozen_route_set(
                RouteSetPublicationKind::RecoveryRestore,
                target,
                &runtime(),
                &[target_item],
            )
            .is_err()
        );
    }

    #[test]
    fn preparation_enforces_target_and_non_target_render_invariants() {
        let target = workshops()[0];
        let absent_target = item(target, 4, absent());
        let mut other = item(workshops()[1], 8, absent());
        other.applied_rendered_digest = digest_bytes(&[]);
        assert!(
            prepare_frozen_route_set(
                RouteSetPublicationKind::RecoveryMaintenance,
                target,
                &runtime(),
                &[absent_target, other.clone()],
            )
            .is_err()
        );

        let target_item = item(
            target,
            4,
            present(Uuid::new_v4(), "one.example.test", false),
        );
        other.applied_rendered_digest = digest_bytes(b"drifted");
        assert!(
            prepare_frozen_route_set(
                RouteSetPublicationKind::Projection,
                target,
                &runtime(),
                &[target_item, other],
            )
            .is_err()
        );
    }

    #[test]
    fn paperless_runtime_context_is_exact_for_rendered_rows() {
        let target = workshops()[0];
        let mut items = vec![
            item(
                target,
                4,
                present(Uuid::new_v4(), "one.example.test", false),
            ),
            item(workshops()[1], 8, absent()),
        ];
        items[1].applied_rendered_digest = digest_bytes(&[]);
        assert!(
            prepare_frozen_route_set(
                RouteSetPublicationKind::Projection,
                target,
                &runtime(),
                &items,
            )
            .is_err()
        );

        items[1] = item(
            workshops()[1],
            8,
            present(Uuid::new_v4(), "two.example.test", true),
        );
        items[1].applied_rendered_digest = expected_normal(&items[1]);
        assert!(
            prepare_frozen_route_set(
                RouteSetPublicationKind::Projection,
                target,
                &runtime_without_paperless(),
                &items,
            )
            .is_err()
        );
        assert!(
            prepare_frozen_route_set(
                RouteSetPublicationKind::Projection,
                target,
                &runtime(),
                &items,
            )
            .is_ok()
        );
    }

    #[test]
    fn batch_wrapper_matches_incremental_staging() {
        let target = workshops()[0];
        let mut items = vec![
            item(
                target,
                4,
                present(Uuid::new_v4(), "one.example.test", false),
            ),
            item(workshops()[1], 8, absent()),
        ];
        items[1].applied_rendered_digest = digest_bytes(&[]);
        let publication_id = Uuid::new_v4();
        let make_intent = || {
            RouteSetGenerationIntent::new(
                publication_id,
                RouteSetPublicationKind::Projection,
                11,
                target,
                17,
            )
            .unwrap()
        };

        let batch_root = TestRoot::new();
        let mut batch_generation =
            RouteSetGenerationDirectory::create_or_open(&batch_root.0, make_intent()).unwrap();
        let mut batch_sealer = batch_generation.begin_seal().unwrap();
        let batch = stage_frozen_route_set(
            &mut batch_sealer,
            RouteSetPublicationKind::Projection,
            target,
            &runtime_without_paperless(),
            &items,
        )
        .unwrap();

        let incremental_root = TestRoot::new();
        let mut incremental_generation =
            RouteSetGenerationDirectory::create_or_open(&incremental_root.0, make_intent())
                .unwrap();
        let mut incremental_sealer = incremental_generation.begin_seal().unwrap();
        let mut prepared = prepare_frozen_route_set(
            RouteSetPublicationKind::Projection,
            target,
            &runtime_without_paperless(),
            &items,
        )
        .unwrap();
        let mut incremental = Vec::new();
        while let Some(row) = prepared.stage_next(&mut incremental_sealer).unwrap() {
            incremental.push(row);
        }
        assert_eq!(incremental, batch);
        assert_eq!(
            incremental_sealer
                .finish()
                .unwrap()
                .identity
                .route_set_digest,
            batch_sealer.finish().unwrap().identity.route_set_digest
        );
    }
}
