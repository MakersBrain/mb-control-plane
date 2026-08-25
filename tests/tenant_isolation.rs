use mb_control_plane::persistence::{OperationOutcome, Store, TenantStore};
use sqlx::Acquire as _;
use sqlx::AssertSqlSafe;
use sqlx::postgres::PgPoolOptions;
use std::collections::BTreeSet;
use uuid::Uuid;

const RUNTIME_ROLES: &[&str] = &[
    "control_api",
    "control_tenant_api",
    "control_membership_worker",
    "control_provisioning_worker",
    "control_invoice_worker",
    "control_inventory_worker",
    "control_email_worker",
    "control_reconciliation_worker",
    "control_lifecycle_worker",
    "control_backup_scheduler",
    "control_driver_ledger",
    "control_release_worker",
    "control_privacy_worker",
];

const FIRST_WAVE_TABLES: &[&str] = &[
    "memberships",
    "invitations",
    "outbox",
    "email_delivery_events",
    "email_suppressions",
    "ownership_transfers",
    "carrier_secrets",
    "webshop_domains",
    "webshop_email_domains",
    "workshop_modules",
    "service_instances",
    "odoo_databases",
    "workshop_recovery_points",
    "workshop_recovery_components",
    "workshop_recovery_rehearsals",
];

fn first_wave_manifest() -> serde_json::Value {
    serde_json::from_str(include_str!("../docs/tenant-isolation-first-wave.json"))
        .expect("the first-wave tenant-isolation manifest must be valid JSON")
}

#[derive(Debug)]
struct RoleSurface {
    role: &'static str,
    reads_workshops: bool,
    updates_workshops: bool,
    reads_operations: bool,
    updates_operations: bool,
}

const CURRENT_ROLE_SURFACE: &[RoleSurface] = &[
    RoleSurface {
        role: "control_api",
        reads_workshops: true,
        updates_workshops: true,
        reads_operations: true,
        updates_operations: true,
    },
    RoleSurface {
        role: "control_tenant_api",
        reads_workshops: true,
        updates_workshops: true,
        reads_operations: true,
        updates_operations: false,
    },
    RoleSurface {
        role: "control_membership_worker",
        reads_workshops: true,
        updates_workshops: false,
        reads_operations: true,
        updates_operations: true,
    },
    RoleSurface {
        role: "control_provisioning_worker",
        reads_workshops: true,
        updates_workshops: false,
        reads_operations: true,
        updates_operations: true,
    },
    RoleSurface {
        role: "control_invoice_worker",
        reads_workshops: true,
        updates_workshops: false,
        reads_operations: true,
        updates_operations: true,
    },
    RoleSurface {
        role: "control_inventory_worker",
        reads_workshops: true,
        updates_workshops: false,
        reads_operations: true,
        updates_operations: true,
    },
    RoleSurface {
        role: "control_email_worker",
        reads_workshops: false,
        updates_workshops: false,
        reads_operations: true,
        updates_operations: true,
    },
    RoleSurface {
        role: "control_reconciliation_worker",
        reads_workshops: true,
        updates_workshops: false,
        reads_operations: true,
        updates_operations: true,
    },
    RoleSurface {
        role: "control_lifecycle_worker",
        reads_workshops: true,
        updates_workshops: true,
        reads_operations: true,
        updates_operations: true,
    },
    RoleSurface {
        role: "control_backup_scheduler",
        reads_workshops: true,
        updates_workshops: false,
        reads_operations: true,
        updates_operations: true,
    },
    RoleSurface {
        role: "control_driver_ledger",
        reads_workshops: false,
        updates_workshops: false,
        reads_operations: true,
        updates_operations: true,
    },
    RoleSurface {
        role: "control_release_worker",
        reads_workshops: true,
        updates_workshops: true,
        reads_operations: true,
        updates_operations: true,
    },
    RoleSurface {
        role: "control_privacy_worker",
        reads_workshops: true,
        updates_workshops: false,
        reads_operations: true,
        updates_operations: true,
    },
];

#[test]
fn characterization_matrix_covers_the_deployed_runtime_roles() {
    let matrix_roles = CURRENT_ROLE_SURFACE
        .iter()
        .map(|surface| surface.role)
        .collect::<Vec<_>>();
    assert_eq!(matrix_roles, RUNTIME_ROLES);

    let bootstrap = include_str!("../deploy/init-databases.sh");
    let reconcile = include_str!("../deploy/reconcile-database-identities.sh");
    let migrations = [
        include_str!("../migrations/0001_control_plane_base.sql"),
        include_str!("../migrations/0005_tenant_api_identity.sql"),
        include_str!("../migrations/0006_outbox_tenant_ownership.sql"),
        include_str!("../migrations/0007_lifecycle_resource_ownership.sql"),
        include_str!("../migrations/0008_scheduler_rehearsal_leases.sql"),
        include_str!("../migrations/0009_driver_idempotency_scope.sql"),
        include_str!("../migrations/0010_release_driver_lease.sql"),
        include_str!("../migrations/0011_webshop_domain_reconciliation.sql"),
        include_str!("../migrations/0014_webshop_domain_provider_deletion.sql"),
        include_str!("../migrations/0015_webshop_email_domain_reconciliation.sql"),
        include_str!("../migrations/0016_recovery_component_tenant_rls.sql"),
        include_str!("../migrations/0017_privacy_export_cleanup_lease.sql"),
        include_str!("../migrations/0018_initial_release_reconciliation.sql"),
        include_str!("../migrations/0019_startup_route_heartbeat_fences.sql"),
        include_str!("../migrations/0020_privacy_retention_batches.sql"),
        include_str!("../migrations/0021_webshop_domain_claim_compatibility.sql"),
        include_str!("../migrations/0022_release_gateway_generation_identity.sql"),
        include_str!("../migrations/0023_fleet_release_forward_reconciliation.sql"),
        include_str!("../migrations/0024_staged_startup_route_publication.sql"),
        include_str!("../migrations/0025_release_route_projection_snapshot.sql"),
        include_str!("../migrations/0026_immutable_release_route_publication.sql"),
        include_str!("../migrations/0027_route_set_publication_admission.sql"),
        include_str!("../migrations/0028_route_set_publication_transitions.sql"),
        include_str!("../migrations/0029_route_set_publication_finalization.sql"),
        include_str!("../migrations/0030_route_set_publication_recovery.sql"),
        include_str!("../migrations/0031_route_set_publication_terminal_recovery.sql"),
        include_str!("../migrations/0032_route_set_flat_writer_guardrails.sql"),
        include_str!("../migrations/0041_interrupted_release_runtime_receipt_review.sql"),
        include_str!("../migrations/0042_rehearsal_tenant_rls.sql"),
        include_str!("../migrations/0043_recovery_point_runtime_acl_pruning.sql"),
        include_str!("../migrations/0044_platform_recovery_capabilities.sql"),
        include_str!("../migrations/0045_driver_recovery_read_capabilities.sql"),
        include_str!("../migrations/0046_recovery_point_tenant_rls.sql"),
        include_str!("../migrations/0047_membership_tenant_rls.sql"),
        include_str!("../migrations/0048_invitation_tenant_rls.sql"),
        include_str!("../migrations/0049_outbox_tenant_rls.sql"),
        include_str!("../migrations/0050_email_delivery_evidence_tenant_rls.sql"),
        include_str!("../migrations/0051_webshop_domain_tenant_rls.sql"),
    ]
    .join("\n")
    .to_ascii_lowercase();
    for role in RUNTIME_ROLES {
        assert!(
            bootstrap.contains(role),
            "{role} is absent from database bootstrap"
        );
        assert!(
            reconcile.contains(role),
            "{role} is absent from identity reconciliation"
        );
        assert!(
            migrations.contains(&format!("to {role}")),
            "{role} has no migrated object grant"
        );
    }
}

#[test]
fn first_wave_manifest_covers_the_adr_candidates_and_deployed_roles() {
    let manifest = first_wave_manifest();
    assert_eq!(manifest["schema_version"], 1);
    assert_eq!(manifest["status"], "staged_policies_enforced");

    let manifest_roles = manifest["deployed_runtime_roles"]
        .as_array()
        .expect("deployed_runtime_roles must be an array")
        .iter()
        .map(|role| role.as_str().expect("runtime role must be a string"))
        .collect::<Vec<_>>();
    assert_eq!(manifest_roles, RUNTIME_ROLES);

    let tables = manifest["tables"]
        .as_array()
        .expect("tables must be an array");
    let manifest_tables = tables
        .iter()
        .map(|table| table["name"].as_str().expect("table name must be a string"))
        .collect::<Vec<_>>();
    assert_eq!(manifest_tables, FIRST_WAVE_TABLES);

    let adr = include_str!("../docs/adr/0008-staged-hybrid-tenant-isolation.md");
    for table in FIRST_WAVE_TABLES {
        assert!(
            adr.contains(&format!("`{table}`")),
            "ADR 0008 does not name the manifest candidate {table} explicitly"
        );
    }
}

#[test]
fn first_wave_manifest_tracks_touch_paths_grants_and_staged_rls_readiness() {
    let manifest = first_wave_manifest();
    let migrations = [
        include_str!("../migrations/0001_control_plane_base.sql"),
        include_str!("../migrations/0002_backup_scheduler_permissions.sql"),
        include_str!("../migrations/0004_paperless_runtime_spec.sql"),
        include_str!("../migrations/0005_tenant_api_identity.sql"),
        include_str!("../migrations/0006_outbox_tenant_ownership.sql"),
        include_str!("../migrations/0007_lifecycle_resource_ownership.sql"),
        include_str!("../migrations/0008_scheduler_rehearsal_leases.sql"),
        include_str!("../migrations/0009_driver_idempotency_scope.sql"),
        include_str!("../migrations/0010_release_driver_lease.sql"),
        include_str!("../migrations/0011_webshop_domain_reconciliation.sql"),
        include_str!("../migrations/0014_webshop_domain_provider_deletion.sql"),
        include_str!("../migrations/0015_webshop_email_domain_reconciliation.sql"),
        include_str!("../migrations/0016_recovery_component_tenant_rls.sql"),
        include_str!("../migrations/0017_privacy_export_cleanup_lease.sql"),
        include_str!("../migrations/0018_initial_release_reconciliation.sql"),
        include_str!("../migrations/0019_startup_route_heartbeat_fences.sql"),
        include_str!("../migrations/0020_privacy_retention_batches.sql"),
        include_str!("../migrations/0021_webshop_domain_claim_compatibility.sql"),
        include_str!("../migrations/0022_release_gateway_generation_identity.sql"),
        include_str!("../migrations/0023_fleet_release_forward_reconciliation.sql"),
        include_str!("../migrations/0024_staged_startup_route_publication.sql"),
        include_str!("../migrations/0025_release_route_projection_snapshot.sql"),
        include_str!("../migrations/0026_immutable_release_route_publication.sql"),
        include_str!("../migrations/0027_route_set_publication_admission.sql"),
        include_str!("../migrations/0028_route_set_publication_transitions.sql"),
        include_str!("../migrations/0029_route_set_publication_finalization.sql"),
        include_str!("../migrations/0030_route_set_publication_recovery.sql"),
        include_str!("../migrations/0031_route_set_publication_terminal_recovery.sql"),
        include_str!("../migrations/0032_route_set_flat_writer_guardrails.sql"),
        include_str!("../migrations/0041_interrupted_release_runtime_receipt_review.sql"),
        include_str!("../migrations/0042_rehearsal_tenant_rls.sql"),
        include_str!("../migrations/0043_recovery_point_runtime_acl_pruning.sql"),
        include_str!("../migrations/0044_platform_recovery_capabilities.sql"),
        include_str!("../migrations/0045_driver_recovery_read_capabilities.sql"),
        include_str!("../migrations/0046_recovery_point_tenant_rls.sql"),
        include_str!("../migrations/0047_membership_tenant_rls.sql"),
        include_str!("../migrations/0048_invitation_tenant_rls.sql"),
        include_str!("../migrations/0049_outbox_tenant_rls.sql"),
        include_str!("../migrations/0050_email_delivery_evidence_tenant_rls.sql"),
        include_str!("../migrations/0051_webshop_domain_tenant_rls.sql"),
    ]
    .join("\n");
    let blockers = manifest["common_readiness_blockers"]
        .as_array()
        .expect("common_readiness_blockers must be an array");
    assert!(
        !blockers.is_empty(),
        "pre-RLS inventory must retain its common blockers"
    );

    let allowed_roles = RUNTIME_ROLES.iter().copied().collect::<BTreeSet<_>>();
    let mut roles_with_a_first_wave_grant = BTreeSet::new();
    let allowed_privileges = [
        "SELECT",
        "INSERT",
        "UPDATE",
        "DELETE",
        "UPDATE(runtime_spec)",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();

    for table in manifest["tables"].as_array().unwrap() {
        let table_name = table["name"].as_str().unwrap();
        let is_enforced_candidate = matches!(
            table_name,
            "memberships"
                | "invitations"
                | "outbox"
                | "email_delivery_events"
                | "email_suppressions"
                | "ownership_transfers"
                | "webshop_domains"
                | "webshop_email_domains"
                | "workshop_recovery_points"
                | "workshop_recovery_components"
                | "workshop_recovery_rehearsals"
        );
        assert_eq!(
            table["migration_readiness"]["ready"], is_enforced_candidate,
            "only reviewed staged candidates may be marked migrated"
        );
        assert!(
            table["migration_readiness"]["next_review"]
                .as_str()
                .is_some_and(|review| !review.is_empty()),
            "{table_name} needs an explicit next review"
        );

        let key_kind = table["tenant_key"]["kind"]
            .as_str()
            .expect("tenant key kind must be explicit");
        assert!(
            matches!(key_kind, "direct" | "indirect" | "direct_and_parent"),
            "{table_name} has an unknown tenant key strategy"
        );

        for category in ["api", "workers", "schedulers", "drivers"] {
            let paths = table["application_touch_paths"][category]
                .as_array()
                .unwrap_or_else(|| panic!("{table_name} is missing {category} touch paths"));
            for path in paths {
                let path = path.as_str().expect("touch path must be a string");
                let absolute = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(path);
                let source = std::fs::read_to_string(&absolute)
                    .unwrap_or_else(|_| panic!("{table_name} touch path {path} does not exist"));
                assert!(
                    source.contains(table_name),
                    "{table_name} touch path {path} no longer names the table"
                );
            }
        }

        let database_paths = table["database_touch_paths"]
            .as_object()
            .expect("database touch paths must be an object");
        for category in ["triggers", "foreign_keys", "security_definer_functions"] {
            assert!(
                database_paths
                    .get(category)
                    .is_some_and(serde_json::Value::is_array),
                "{table_name} is missing database category {category}"
            );
            for database_object in database_paths[category].as_array().unwrap() {
                let marker = match category {
                    "triggers" => database_object["name"].as_str(),
                    "foreign_keys" => database_object["constraint"].as_str(),
                    "security_definer_functions" => database_object["name"].as_str(),
                    _ => unreachable!(),
                }
                .expect("database object must have a stable name");
                assert!(
                    migrations.contains(marker),
                    "{table_name} database object {marker} is absent from migrations"
                );
            }
        }

        let grants = table["current_grants"]
            .as_object()
            .expect("current grants must be an object");
        assert!(
            !grants.is_empty()
                || !database_paths["security_definer_functions"]
                    .as_array()
                    .unwrap()
                    .is_empty(),
            "{table_name} must inventory direct grants or its function-only boundary"
        );
        let lowercase_migrations = migrations.to_ascii_lowercase();
        let table_grant_marker = format!("table control.{table_name} to ");
        let migration_grant_lines = lowercase_migrations
            .lines()
            .filter(|line| line.contains(&table_grant_marker))
            .collect::<Vec<_>>();
        let mut granted_roles_in_migrations = migration_grant_lines
            .iter()
            .map(|line| {
                line.split(&table_grant_marker)
                    .nth(1)
                    .and_then(|suffix| suffix.split(';').next())
                    .map(|role| role.trim_end_matches('\''))
                    .expect("grant statement must name one role")
            })
            .collect::<BTreeSet<_>>();
        let normalized_migrations = lowercase_migrations
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        for role in RUNTIME_ROLES {
            let historical_privileges = ["select", "insert", "update", "delete"]
                .into_iter()
                .filter(|privilege| {
                    migration_grant_lines.iter().any(|line| {
                        line.contains(&format!(" to {role}")) && line.contains(privilege)
                    })
                })
                .collect::<BTreeSet<_>>();
            let revoke_marker = format!(" on table control.{table_name} from {role}");
            let revoked_privileges = normalized_migrations
                .split("revoke ")
                .skip(1)
                .filter_map(|suffix| {
                    suffix
                        .split_once(&revoke_marker)
                        .map(|(privileges, _)| privileges)
                })
                .flat_map(|privileges| privileges.split(','))
                .map(str::trim)
                .collect::<BTreeSet<_>>();
            if revoked_privileges.contains("all")
                || (!historical_privileges.is_empty()
                    && historical_privileges.is_subset(&revoked_privileges))
            {
                granted_roles_in_migrations.remove(role);
            }
        }
        let granted_roles_in_manifest = grants.keys().map(String::as_str).collect::<BTreeSet<_>>();
        assert_eq!(
            granted_roles_in_manifest, granted_roles_in_migrations,
            "{table_name} grant inventory drifted from migrations"
        );
        for (role, privileges) in grants {
            assert!(
                allowed_roles.contains(role.as_str()),
                "{table_name} names undeployed role {role}"
            );
            roles_with_a_first_wave_grant.insert(role.as_str());
            let privileges = privileges
                .as_array()
                .expect("grant privileges must be an array");
            assert!(
                !privileges.is_empty(),
                "{table_name}/{role} has no privilege"
            );
            for privilege in privileges {
                let privilege = privilege.as_str().expect("privilege must be a string");
                assert!(
                    allowed_privileges.contains(privilege),
                    "{table_name}/{role} has unknown privilege {privilege}"
                );
                let migration_grant_exists = migration_grant_lines.iter().any(|line| {
                    line.contains(&format!(" to {role}"))
                        && line.contains(&privilege.to_ascii_lowercase())
                });
                assert!(
                    migration_grant_exists,
                    "{table_name}/{role} privilege {privilege} drifted from migrations"
                );
            }
        }

        if is_enforced_candidate {
            let rls = table["rls"]
                .as_object()
                .expect("enforced table needs RLS metadata");
            assert_eq!(rls["state"], "enforced");
            assert_eq!(rls["enabled"], true);
            assert_eq!(rls["forced"], true);
            assert_eq!(rls["context_helper"], "control.current_workshop_id");
            for policy in rls["policies"]
                .as_array()
                .expect("policies must be an array")
            {
                let name = policy["name"].as_str().expect("policy needs a name");
                assert!(
                    migrations.contains(name),
                    "manifest policy {name} is absent from migrations"
                );
            }
        } else {
            assert!(
                table.get("rls").is_none(),
                "{table_name} must remain a pending policy candidate"
            );
        }
    }

    assert_eq!(
        roles_with_a_first_wave_grant, allowed_roles,
        "every deployed runtime role must have its present first-wave grant surface represented"
    );

    let components = manifest["tables"]
        .as_array()
        .unwrap()
        .iter()
        .find(|table| table["name"] == "workshop_recovery_components")
        .unwrap();
    assert_eq!(components["tenant_key"]["kind"], "direct_and_parent");
    assert_eq!(components["tenant_key"]["columns"][0], "workshop_id");
    assert_eq!(
        components["tenant_key"]["parent_table"],
        "workshop_recovery_points"
    );
}

#[test]
fn recovery_component_policy_has_no_machine_or_platform_bypass() {
    let migration = include_str!("../migrations/0016_recovery_component_tenant_rls.sql");
    assert!(
        migration
            .contains("alter table control.workshop_recovery_components enable row level security")
    );
    assert!(
        migration
            .contains("alter table control.workshop_recovery_components force row level security")
    );
    assert!(
        migration
            .contains("revoke all on table control.workshop_recovery_components from control_api")
    );
    assert!(!migration.contains("control.platform"));
    assert!(!migration.contains("to public"));

    for (policy, role) in [
        (
            "workshop_recovery_components_lifecycle_tenant",
            "control_lifecycle_worker",
        ),
        (
            "workshop_recovery_components_driver_tenant",
            "control_driver_ledger",
        ),
    ] {
        assert!(migration.contains(policy));
        assert!(migration.contains(&format!("to {role}")));
    }
    assert!(
        migration
            .matches("workshop_id = control.current_workshop_id()")
            .count()
            >= 8,
        "both runtime policies must bind the row and its parent on read and write"
    );

    let lifecycle = include_str!("../src/workers/lifecycle.rs");
    assert!(lifecycle.contains("tenant_store.begin(workshop)"));
    assert!(lifecycle.contains(
        "insert into control.workshop_recovery_components(recovery_point_id,workshop_id"
    ));
    let driver = include_str!("../src/docker_driver/recovery.rs");
    assert!(driver.contains(".store\n        .begin(ledger.workshop)"));
    assert!(driver.contains("where recovery_point_id=$1 and workshop_id=$2 order by component"));
}

#[test]
fn recovery_rehearsal_policy_separates_fleet_reads_from_tenant_writes() {
    let migration = include_str!("../migrations/0042_rehearsal_tenant_rls.sql");
    assert!(
        migration
            .contains("alter table control.workshop_recovery_rehearsals enable row level security")
    );
    assert!(
        migration
            .contains("alter table control.workshop_recovery_rehearsals force row level security")
    );
    assert!(migration.contains("revoke insert, update, delete"));
    assert!(migration.contains("from control_api"));
    assert!(migration.contains("workshop_recovery_rehearsals_platform_read"));
    assert!(migration.contains("workshop_recovery_rehearsals_scheduler_discovery"));
    assert!(migration.contains("workshop_recovery_rehearsals_scheduler_insert"));
    assert!(migration.contains("workshop_recovery_rehearsals_scheduler_update"));
    assert!(migration.contains("for select\n        to control_api"));
    assert!(migration.contains("for select\n        to control_backup_scheduler"));
    assert!(migration.contains("for insert\n        to control_backup_scheduler"));
    assert!(migration.contains("for update\n        to control_backup_scheduler"));
    assert!(!migration.contains("for delete"));
    assert!(!migration.contains("control.platform"));
    assert!(!migration.contains("to public"));
    assert!(
        migration
            .matches("workshop_id = control.current_workshop_id()")
            .count()
            >= 6,
        "scheduler insert and update policies must bind both row and parent"
    );

    let scheduler = include_str!("../src/backup_scheduler.rs");
    assert!(scheduler.contains("fetch_all(&self.fleet_discovery)"));
    assert!(scheduler.contains("self.tenant_store.begin(claim.workshop)"));
    assert!(scheduler.contains("self.tenant_store.begin(workshop)"));
}

#[test]
fn recovery_point_acl_pruning_removes_unused_worker_table_access() {
    let migration = include_str!("../migrations/0043_recovery_point_runtime_acl_pruning.sql");
    let normalized = migration.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(normalized.contains(
        "revoke select, insert, update on table control.workshop_recovery_points from control_release_worker"
    ));
    assert!(normalized.contains(
        "revoke select on table control.workshop_recovery_points from control_privacy_worker"
    ));
    assert!(!migration.contains("enable row level security"));
    assert!(!migration.contains("grant "));

    for source in [
        include_str!("../src/workers/release.rs"),
        include_str!("../src/workers/privacy.rs"),
    ] {
        assert!(
            !source.contains("workshop_recovery_points"),
            "a worker with no direct recovery-point ACL must not add direct table SQL"
        );
    }

    let bounded_release_review =
        include_str!("../migrations/0041_interrupted_release_runtime_receipt_review.sql");
    assert!(bounded_release_review.contains(
        "grant execute on function control.review_interrupted_immutable_release_runtime_observation"
    ));
    assert!(bounded_release_review.contains("language plpgsql security definer"));
}

#[test]
fn platform_recovery_writes_use_bounded_database_capabilities() {
    let migration = include_str!("../migrations/0044_platform_recovery_capabilities.sql");
    let normalized = migration.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(normalized.contains(
        "revoke insert, update, delete on table control.workshop_recovery_points from control_api"
    ));
    assert!(
        normalized
            .contains("grant select on table control.workshop_recovery_points to control_api")
    );
    for function in [
        "control.insert_platform_deletion_recovery_point",
        "control.insert_platform_release_recovery_point",
    ] {
        assert!(normalized.contains(&format!("revoke all on function {function}")));
        assert!(normalized.contains(&format!("grant execute on function {function}")));
    }
    assert!(normalized.matches("from public").count() >= 2);
    assert!(normalized.matches("to control_api").count() >= 3);
    assert!(migration.matches("security definer").count() >= 2);
    assert!(
        migration
            .matches("set search_path = pg_catalog, control")
            .count()
            >= 2
    );
    assert!(!migration.contains("to control_tenant_api"));

    let platform = include_str!("../src/api/platform.rs");
    assert!(platform.contains("control.insert_platform_deletion_recovery_point($1,$2,$3,$4)"));
    assert!(platform.contains("control.insert_platform_release_recovery_point($1,$2,$3,$4,$5,$6)"));
    assert_eq!(
        platform
            .matches("insert into control.workshop_recovery_points")
            .count(),
        0,
        "platform handlers must not regain direct recovery-point write authority"
    );
    assert!(platform.contains(
        "select r.id,r.workshop_id,w.display_name,r.ready_at,r.source_release from control.workshop_recovery_points"
    ));
    let api = include_str!("../src/api.rs");
    assert!(api.contains(
        "select extract(epoch from now()-max(ready_at))::float8 from control.workshop_recovery_points"
    ));
}

#[test]
fn fleet_recovery_reads_use_live_driver_capabilities() {
    let migration = include_str!("../migrations/0045_driver_recovery_read_capabilities.sql");
    let normalized = migration.split_whitespace().collect::<Vec<_>>().join(" ");
    for function in [
        "control.read_release_driver_tenants",
        "control.read_release_reconciliation_tenants",
    ] {
        assert!(normalized.contains(&format!("create function {function}")));
        assert!(normalized.contains(&format!("revoke all on function {function}")));
        assert!(normalized.contains(&format!("grant execute on function {function}")));
    }
    assert_eq!(migration.matches("security definer").count(), 2);
    assert_eq!(
        migration
            .matches("set search_path = pg_catalog, control")
            .count(),
        2
    );
    assert_eq!(migration.matches("limit 501").count(), 2);
    assert_eq!(migration.matches("errcode = '42501'").count(), 2);
    assert!(!migration.contains("to public"));

    for source in [
        include_str!("../src/docker_driver/release.rs"),
        include_str!("../src/docker_driver/release_runtime_observation.rs"),
    ] {
        assert!(source.contains("control.read_release_"));
        assert!(
            !source.contains(&["join control.", "workshop_recovery_points"].concat()),
            "fleet release modules must not regain direct recovery-point reads"
        );
    }
}

#[test]
fn recovery_point_policy_separates_fleet_reads_from_tenant_workflows() {
    let migration = include_str!("../migrations/0046_recovery_point_tenant_rls.sql");
    let normalized = migration.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        normalized
            .contains("alter table control.workshop_recovery_points enable row level security")
    );
    assert!(
        normalized
            .contains("alter table control.workshop_recovery_points force row level security")
    );
    assert!(normalized.contains(
        "revoke insert, delete on table control.workshop_recovery_points from control_lifecycle_worker"
    ));
    for policy in [
        "workshop_recovery_points_platform_read",
        "workshop_recovery_points_tenant_api_read",
        "workshop_recovery_points_tenant_api_insert",
        "workshop_recovery_points_lifecycle_read",
        "workshop_recovery_points_lifecycle_update",
        "workshop_recovery_points_scheduler_discovery",
        "workshop_recovery_points_scheduler_insert",
        "workshop_recovery_points_driver_read",
        "workshop_recovery_points_driver_update",
    ] {
        assert!(migration.contains(policy));
    }
    assert_eq!(migration.matches("using (true)").count(), 3);
    assert!(migration.matches("control.current_workshop_id()").count() >= 12);
    assert!(!migration.contains("for delete"));
    assert!(!migration.contains("to public"));

    for source in [
        include_str!("../src/api/recovery.rs"),
        include_str!("../src/workers/lifecycle.rs"),
        include_str!("../src/backup_scheduler.rs"),
        include_str!("../src/docker_driver/recovery.rs"),
    ] {
        assert!(source.contains("workshop_recovery_points"));
    }
    assert!(
        include_str!("../src/api/recovery.rs").contains("tenant_store.begin(scope.workshop_id)")
    );
    assert!(include_str!("../src/workers/lifecycle.rs").contains("tenant_store.begin(workshop)"));
    assert!(
        include_str!("../src/backup_scheduler.rs").contains("self.tenant_store.begin(workshop)")
    );
    assert!(
        include_str!("../src/docker_driver/recovery.rs")
            .contains(".tenant_ledger\n        .begin(workshop)")
    );
}

#[test]
fn membership_policy_uses_scoped_reads_and_bounded_fleet_capabilities() {
    let migration = include_str!("../migrations/0047_membership_tenant_rls.sql");
    let normalized = migration.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(normalized.contains("alter table control.memberships enable row level security"));
    assert!(normalized.contains("alter table control.memberships force row level security"));
    assert!(
        normalized.contains(
            "revoke insert, update, delete on table control.memberships from control_api"
        )
    );
    assert!(
        normalized
            .contains("revoke select on table control.memberships from control_invoice_worker")
    );
    assert!(
        normalized
            .contains("revoke select on table control.memberships from control_inventory_worker")
    );
    for function in [
        "control.insert_initial_workshop_owner",
        "control.accept_invitation_membership",
        "control.discover_due_backup_memberships",
        "control.read_privacy_subject_workshops",
    ] {
        assert!(normalized.contains(&format!("create function {function}")));
        assert!(normalized.contains(&format!("revoke all on function {function}")));
    }
    assert_eq!(migration.matches("security definer").count(), 4);
    assert_eq!(
        migration
            .matches("set search_path = pg_catalog, control")
            .count(),
        4
    );
    assert!(!migration.contains("to public"));
    assert!(!migration.contains("for delete"));
    assert_eq!(migration.matches("using (true)").count(), 2);

    let api = include_str!("../src/api/workshops.rs");
    assert!(api.contains("control.insert_initial_workshop_owner($1,$2,$3)"));
    assert!(api.contains("control.accept_invitation_membership($1,$2,$3,$4)"));
    assert_eq!(api.matches("insert into control.memberships").count(), 0);

    let scheduler = include_str!("../src/backup_scheduler.rs");
    assert!(scheduler.contains("control.discover_due_backup_memberships(100)"));
    assert!(!scheduler.contains("select user_id from control.memberships"));
    let privacy = include_str!("../src/workers/privacy.rs");
    assert!(privacy.contains("control.read_privacy_subject_workshops($1,$2,$3,$4,$5)"));
    assert!(!privacy.contains("select workshop_id from control.memberships where user_id=$1"));
    let driver = include_str!("../src/docker_driver/privacy.rs");
    assert!(driver.contains("tenant_ledger\n        .begin(workshop)"));
}

#[test]
fn invitation_policy_uses_scoped_access_and_exact_bootstrap_capabilities() {
    let migration = include_str!("../migrations/0048_invitation_tenant_rls.sql");
    let normalized = migration.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(normalized.contains("alter table control.invitations enable row level security"));
    assert!(normalized.contains("alter table control.invitations force row level security"));
    assert!(normalized.contains(
        "revoke select, insert, update, delete on table control.invitations from control_api"
    ));
    assert!(normalized.contains(
        "revoke select, update, delete on table control.invitations from control_privacy_worker"
    ));
    for function in [
        "control.lock_live_invitation",
        "control.read_managed_invitation",
    ] {
        assert!(normalized.contains(&format!("create function {function}")));
        assert!(normalized.contains(&format!("revoke all on function {function}")));
    }
    assert_eq!(migration.matches("security definer").count(), 2);
    assert_eq!(
        migration
            .matches("set search_path = pg_catalog, control")
            .count(),
        2
    );
    assert!(!migration.contains("to public"));
    assert!(!migration.contains("for delete"));
    assert_eq!(migration.matches("using (true)").count(), 1);

    let api = include_str!("../src/api/workshops.rs");
    assert!(api.contains("control.lock_live_invitation($1,$2)"));
    assert!(api.contains("control.read_managed_invitation($1,$2)"));
    assert!(!api.contains("select workshop_id from control.invitations where id=$1"));
    assert!(!api.contains("from control.invitations i join control.workshops w"));
    assert!(!api.contains("from control.invitations where id=$1 and token_generation=$2"));
    let email = include_str!("../src/workers/email.rs");
    assert!(email.contains(".begin(workshop)"));
    let privacy = include_str!("../src/workers/privacy.rs");
    assert!(privacy.contains("control.run_privacy_retention_batch($1,$2,$3,$4,$5)"));
}

#[test]
fn outbox_policy_uses_scoped_producers_and_exact_provider_event_capability() {
    let migration = include_str!("../migrations/0049_outbox_tenant_rls.sql");
    let normalized = migration.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(normalized.contains("alter table control.outbox enable row level security"));
    assert!(normalized.contains("alter table control.outbox force row level security"));
    assert!(
        normalized
            .contains("revoke insert, update, delete on table control.outbox from control_api")
    );
    assert!(normalized.contains(
        "revoke select, update, delete on table control.outbox from control_privacy_worker"
    ));
    assert!(
        normalized
            .contains("revoke select on table control.outbox from control_reconciliation_worker")
    );
    assert!(
        normalized.contains("create function control.record_transactional_outbox_delivery_event")
    );
    assert!(
        normalized
            .contains("revoke all on function control.record_transactional_outbox_delivery_event")
    );
    assert_eq!(migration.matches("security definer").count(), 1);
    assert_eq!(
        migration
            .matches("set search_path = pg_catalog, control")
            .count(),
        1
    );
    assert!(!migration.contains("to public"));
    assert!(!migration.contains("for delete"));
    assert_eq!(migration.matches("using (true)").count(), 2);

    let internal = include_str!("../src/api/internal.rs");
    assert!(internal.contains("control.record_transactional_outbox_delivery_event("));
    assert!(internal.contains("state.tenant_store.begin(workshop_id)"));
    assert!(!internal.contains("update control.outbox"));
    assert!(!internal.contains("select workshop_id,recipient from control.outbox"));
    let email_domains = include_str!("../src/workers/email_domains.rs");
    assert!(email_domains.contains("tenant_store\n            .begin(workshop)"));
    let email = include_str!("../src/workers/email.rs");
    assert!(email.contains(".begin(workshop)"));
    let platform = include_str!("../src/api/platform.rs");
    assert!(platform.contains("from control.outbox order by created_at desc,id desc limit 200"));
    let privacy = include_str!("../src/workers/privacy.rs");
    assert!(privacy.contains("control.run_privacy_retention_batch($1,$2,$3,$4,$5)"));
}

#[test]
fn email_delivery_evidence_policy_is_parent_bound_and_tenant_scoped() {
    let migration = include_str!("../migrations/0050_email_delivery_evidence_tenant_rls.sql");
    let normalized = migration.split_whitespace().collect::<Vec<_>>().join(" ");
    for table in [
        "email_delivery_events",
        "email_suppressions",
        "webshop_email_domains",
    ] {
        assert!(normalized.contains(&format!(
            "alter table control.{table} enable row level security"
        )));
        assert!(normalized.contains(&format!(
            "alter table control.{table} force row level security"
        )));
    }
    assert!(normalized.contains(
        "foreign key (outbox_id, workshop_id) references control.outbox(id, workshop_id)"
    ));
    assert!(normalized.contains(
        "foreign key (source_event_id, workshop_id) references control.email_delivery_events(event_id, workshop_id)"
    ));
    assert!(
        normalized.contains(
            "revoke select, insert on table control.email_delivery_events from control_api"
        )
    );
    assert!(normalized.contains(
        "revoke select, insert, update on table control.email_suppressions from control_api"
    ));
    assert!(normalized.contains(
        "revoke select, insert, update on table control.webshop_email_domains from control_api"
    ));
    assert!(normalized.contains("v_existing.workshop_id is distinct from v_outbox.workshop_id"));
    assert!(normalized.contains("domain.workshop_id = v_outbox.workshop_id"));

    let internal = include_str!("../src/api/internal.rs");
    assert!(internal.contains("state.tenant_store.begin(workshop_id)"));
    let webshop = include_str!("../src/api/webshop.rs");
    assert!(webshop.contains("fetch_one(&mut *domain_tx)"));
    let worker = include_str!("../src/workers/email_domains.rs");
    assert!(worker.matches(".begin(workshop)").count() >= 7);
    assert!(
        worker.contains("control.webshop_email_domains set provider_ref=$3,provider_status=$4")
    );
    assert!(!worker.contains("execute(store.pool())"));
    assert!(worker.contains("fetch_one(&mut *suppression_tx)"));
}

#[test]
fn webshop_domain_policy_has_live_uniqueness_and_a_stable_scoped_claim() {
    let preparation = include_str!("../migrations/0021_webshop_domain_claim_compatibility.sql");
    let migration = include_str!("../migrations/0051_webshop_domain_tenant_rls.sql");
    assert!(preparation.contains("create function control.claim_webshop_domain("));
    assert!(migration.contains("create or replace function control.claim_webshop_domain("));
    assert!(migration.contains("language plpgsql security definer"));
    assert!(migration.contains("set search_path = pg_catalog, control"));
    assert!(migration.contains("control.current_workshop_id() is distinct from p_workshop_id"));
    assert!(migration.contains("membership.role in ('owner', 'studio_manager')"));
    assert!(migration.contains("drop constraint webshop_domains_hostname_key"));
    assert!(migration.contains("create unique index webshop_domains_live_hostname_unique"));
    assert!(migration.contains("where state <> 'disconnected'"));
    assert!(!migration.contains("set workshop_id = p_workshop_id"));
    assert!(migration.contains("alter table control.webshop_domains enable row level security"));
    assert!(migration.contains("alter table control.webshop_domains force row level security"));
    assert!(migration.contains(
        "revoke select, insert, update on table control.webshop_domains from control_api"
    ));
    assert!(
        migration
            .contains("revoke insert on table control.webshop_domains from control_tenant_api")
    );
    assert!(migration.contains(
        "revoke all on function control.claim_webshop_domain(uuid,uuid,text,text,text,text,uuid)"
    ));
    assert!(migration.contains("to control_tenant_api"));
    assert!(!migration.contains("to public"));

    let api = include_str!("../src/api/domains.rs");
    assert!(api.contains("from control.claim_webshop_domain($1,$2,$3,$4,$5,$6,$7)"));
    assert!(
        !api.to_ascii_lowercase()
            .contains("on conflict(hostname) do update")
    );
    assert!(
        !api.replace(' ', "")
            .contains("workshop_id=excluded.workshop_id")
    );
    assert!(api.contains("This hostname is already claimed"));
}

fn database_url(admin_url: &str, database: &str) -> String {
    let mut url = url::Url::parse(admin_url).expect("CONTROL_TEST_ADMIN_URL must be a URL");
    url.set_path(database);
    url.to_string()
}

fn login_database_url(admin_url: &str, database: &str, role: &str, password: &str) -> String {
    let mut url = url::Url::parse(admin_url).expect("CONTROL_TEST_ADMIN_URL must be a URL");
    url.set_path(database);
    url.set_username(role).expect("curated role is URL-safe");
    url.set_password(Some(password))
        .expect("test password is URL-safe");
    url.to_string()
}

async fn create_runtime_roles(admin: &sqlx::PgPool) {
    sqlx::query(AssertSqlSafe(format!(
        "do $roles$ begin
           if not exists(select 1 from pg_roles where rolname='control_runtime_read') then
             create role control_runtime_read nologin nosuperuser nocreatedb nocreaterole noreplication nobypassrls;
           end if;
           {};
           grant control_runtime_read to {};
           alter role control_tenant_api login password 'tenant-isolation-password';
           alter role control_membership_worker login password 'membership-isolation-password';
           alter role control_reconciliation_worker login password 'reconciliation-isolation-password';
           alter role control_lifecycle_worker login password 'lifecycle-isolation-password';
           alter role control_backup_scheduler login password 'backup-scheduler-isolation-password';
           alter role control_driver_ledger login password 'driver-ledger-isolation-password';
         end $roles$",
        RUNTIME_ROLES
            .iter()
            .map(|role| format!(
                "if not exists(select 1 from pg_roles where rolname='{role}') then create role {role} nologin nosuperuser nocreatedb nocreaterole noreplication nobypassrls; end if"
            ))
            .collect::<Vec<_>>()
            .join("; "),
        RUNTIME_ROLES.join(",")
    )))
    .execute(admin)
    .await
    .expect("create runtime roles on a disposable PostgreSQL instance");
}

async fn claim_webshop_domain(
    tx: &mut mb_control_plane::persistence::WorkshopTransaction<'_>,
    domain_id: Uuid,
    workshop: Uuid,
    hostname: &str,
    verification_name: &str,
    manager: Uuid,
) -> Result<(String, Option<Uuid>, Option<i64>), sqlx::Error> {
    sqlx::query_as::<_, (String, Option<Uuid>, Option<i64>)>(
        "select outcome,domain_id,domain_version
           from control.claim_webshop_domain($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(domain_id)
    .bind(workshop)
    .bind(hostname)
    .bind(verification_name)
    .bind(format!("mb-verification={}", domain_id.simple()))
    .bind("shops.example.test")
    .bind(manager)
    .fetch_one(&mut **tx)
    .await
}

async fn assert_webshop_domain_claim_compatibility(
    admin_url: &str,
    database: &str,
    owner_store: &Store,
    first_workshop: Uuid,
    second_workshop: Uuid,
    manager: Uuid,
) {
    let identity = "control.claim_webshop_domain(uuid,uuid,text,text,text,text,uuid)";
    let metadata = sqlx::query_as::<_, (bool, bool, bool, bool, bool, bool, bool)>(
        "select procedure.prosecdef,
                coalesce(procedure.proconfig,'{}'::text[])
                    @> array['search_path=pg_catalog, control'],
                has_function_privilege('control_tenant_api',procedure.oid,'EXECUTE'),
                has_function_privilege('control_api',procedure.oid,'EXECUTE'),
                has_function_privilege('control_reconciliation_worker',procedure.oid,'EXECUTE'),
                has_function_privilege('control_lifecycle_worker',procedure.oid,'EXECUTE'),
                not exists(
                    select 1 from aclexplode(coalesce(
                        procedure.proacl,acldefault('f',procedure.proowner)
                    )) privilege
                    where privilege.grantee=0 and privilege.privilege_type='EXECUTE'
                )
           from pg_proc procedure
           join pg_namespace namespace on namespace.oid=procedure.pronamespace
          where namespace.nspname='control' and procedure.oid=$1::regprocedure",
    )
    .bind(identity)
    .fetch_one(owner_store.pool())
    .await
    .unwrap();
    assert!(metadata.0, "hostname claims must remain SECURITY DEFINER");
    assert!(metadata.1, "hostname claims must pin their search path");
    assert!(metadata.2, "the tenant API must execute hostname claims");
    assert!(
        !metadata.3,
        "the platform API must not execute hostname claims"
    );
    assert!(
        !metadata.4,
        "the reconciliation worker must not execute human hostname claims"
    );
    assert!(
        !metadata.5,
        "the lifecycle worker must not execute human hostname claims"
    );
    assert!(metadata.6, "PUBLIC hostname-claim execute must be revoked");

    let flags = sqlx::query_as::<_, (bool, bool)>(
        "select relrowsecurity,relforcerowsecurity
           from pg_class relation
           join pg_namespace namespace on namespace.oid=relation.relnamespace
          where namespace.nspname='control' and relation.relname='webshop_domains'",
    )
    .fetch_one(owner_store.pool())
    .await
    .unwrap();
    assert_eq!(flags, (true, true));
    let privileges = sqlx::query_as::<_, (String, String)>(
        "select role_name,privilege
           from unnest(array[
                  'control_api','control_tenant_api','control_reconciliation_worker',
                  'control_lifecycle_worker'
                ]::text[]) role_name
          cross join unnest(array['SELECT','INSERT','UPDATE','DELETE']::text[]) privilege
          where has_table_privilege(role_name,'control.webshop_domains',privilege)
          order by role_name,privilege",
    )
    .fetch_all(owner_store.pool())
    .await
    .unwrap();
    assert_eq!(
        privileges,
        vec![
            ("control_lifecycle_worker".into(), "SELECT".into()),
            ("control_lifecycle_worker".into(), "UPDATE".into()),
            ("control_reconciliation_worker".into(), "SELECT".into()),
            ("control_reconciliation_worker".into(), "UPDATE".into()),
            ("control_tenant_api".into(), "SELECT".into()),
            ("control_tenant_api".into(), "UPDATE".into()),
        ]
    );
    let policy_count = sqlx::query_scalar::<_, i64>(
        "select count(*) from pg_policies
          where schemaname='control' and tablename='webshop_domains'
            and policyname<>'webshop_domains_migration_owner'",
    )
    .fetch_one(owner_store.pool())
    .await
    .unwrap();
    assert_eq!(policy_count, 6);

    let tenant_url = login_database_url(
        admin_url,
        database,
        "control_tenant_api",
        "tenant-isolation-password",
    );
    let tenant_store = TenantStore::connect(&tenant_url).await.unwrap();
    let domain = Uuid::new_v4();
    let hostname = format!("claim-compat-{}.example.test", domain.simple());
    let verification_name = format!("_mb-challenge.{hostname}");

    let mut first = tenant_store.begin(first_workshop).await.unwrap();
    let created = claim_webshop_domain(
        &mut first,
        domain,
        first_workshop,
        &hostname,
        &verification_name,
        manager,
    )
    .await
    .unwrap();
    assert_eq!(created.0, "created");
    assert_eq!(created.1, Some(domain));
    first.commit().await.unwrap();

    let mut first = tenant_store.begin(first_workshop).await.unwrap();
    let conflict = claim_webshop_domain(
        &mut first,
        Uuid::new_v4(),
        first_workshop,
        &hostname,
        &verification_name,
        manager,
    )
    .await
    .unwrap();
    assert_eq!(conflict, ("conflict".into(), None, None));
    first.rollback().await.unwrap();

    sqlx::query(
        "update control.webshop_domains
            set state='disconnected',desired_state='disconnected',disconnected_at=now()
          where id=$1 and workshop_id=$2",
    )
    .bind(domain)
    .bind(first_workshop)
    .execute(owner_store.pool())
    .await
    .unwrap();
    let replacement = Uuid::new_v4();
    let mut second = tenant_store.begin(second_workshop).await.unwrap();
    let reclaimed = claim_webshop_domain(
        &mut second,
        replacement,
        second_workshop,
        &hostname,
        &verification_name,
        manager,
    )
    .await
    .unwrap();
    assert_eq!(reclaimed.0, "created");
    assert_eq!(reclaimed.1, Some(replacement));
    second.commit().await.unwrap();
    let history = sqlx::query_as::<_, (Uuid, Uuid, String)>(
        "select id,workshop_id,state from control.webshop_domains
          where hostname=$1 order by id",
    )
    .bind(&hostname)
    .fetch_all(owner_store.pool())
    .await
    .unwrap();
    let mut expected_history = vec![
        (domain, first_workshop, "disconnected".into()),
        (replacement, second_workshop, "ownership_pending".into()),
    ];
    expected_history.sort_unstable();
    assert_eq!(history, expected_history);

    for role in [
        "control_tenant_api",
        "control_reconciliation_worker",
        "control_lifecycle_worker",
    ] {
        let mut missing = owner_store.begin().await.unwrap();
        set_local_role(&mut missing, role).await;
        assert_eq!(
            sqlx::query_scalar::<_, i64>("select count(*) from control.webshop_domains")
                .fetch_one(&mut *missing)
                .await
                .unwrap(),
            0,
            "{role} must fail closed without workshop context"
        );
        missing.rollback().await.unwrap();

        let mut scoped = owner_store.begin().await.unwrap();
        set_local_role_and_workshop(&mut scoped, role, first_workshop).await;
        assert_eq!(
            sqlx::query_scalar::<_, Vec<Uuid>>(
                "select coalesce(array_agg(id order by id),'{}') from control.webshop_domains",
            )
            .fetch_one(&mut *scoped)
            .await
            .unwrap(),
            vec![domain]
        );
        assert_eq!(
            sqlx::query("update control.webshop_domains set updated_at=updated_at where id=$1")
                .bind(replacement)
                .execute(&mut *scoped)
                .await
                .unwrap()
                .rows_affected(),
            0,
            "{role} must not update another workshop's hostname"
        );
        scoped.rollback().await.unwrap();
    }

    let mut platform = owner_store.begin().await.unwrap();
    set_local_role(&mut platform, "control_api").await;
    let denied = sqlx::query("select id from control.webshop_domains limit 1")
        .execute(&mut *platform)
        .await
        .expect_err("platform API direct hostname access must be removed");
    assert_insufficient_privilege(denied, "platform API direct hostname access");
    platform.rollback().await.unwrap();

    let mut direct_insert = owner_store.begin().await.unwrap();
    set_local_role_and_workshop(&mut direct_insert, "control_tenant_api", first_workshop).await;
    let denied = sqlx::query("insert into control.webshop_domains(id,workshop_id,hostname,verification_name,verification_value,routing_target,created_by) values($1,$2,$3,$4,$5,'shops.example.test',$6)")
        .bind(Uuid::new_v4())
        .bind(first_workshop)
        .bind(format!("direct-{}.example.test", Uuid::new_v4().simple()))
        .bind(format!("_mb-challenge.direct-{}.example.test", Uuid::new_v4().simple()))
        .bind(format!("mb-verification={}", Uuid::new_v4().simple()))
        .bind(manager)
        .execute(&mut *direct_insert)
        .await
        .expect_err("tenant hostname inserts must use the claim capability");
    assert_insufficient_privilege(denied, "direct tenant hostname insert");
    direct_insert.rollback().await.unwrap();

    let raw = PgPoolOptions::new()
        .max_connections(1)
        .connect(&tenant_url)
        .await
        .unwrap();
    let missing_context =
        sqlx::query("select * from control.claim_webshop_domain($1,$2,$3,$4,$5,$6,$7)")
            .bind(Uuid::new_v4())
            .bind(first_workshop)
            .bind(format!("missing-{}.example.test", Uuid::new_v4().simple()))
            .bind("_mb-challenge.missing.example.test")
            .bind(format!("mb-verification={}", Uuid::new_v4().simple()))
            .bind("shops.example.test")
            .bind(manager)
            .execute(&raw)
            .await
            .expect_err("a hostname claim without workshop context must fail");
    assert_insufficient_privilege(missing_context, "context-free hostname claim");
    let mut wrong = tenant_store.begin(first_workshop).await.unwrap();
    let wrong_context = claim_webshop_domain(
        &mut wrong,
        Uuid::new_v4(),
        second_workshop,
        &format!("wrong-{}.example.test", Uuid::new_v4().simple()),
        "_mb-challenge.wrong.example.test",
        manager,
    )
    .await
    .expect_err("a hostname claim cannot name a different workshop");
    assert_insufficient_privilege(wrong_context, "wrong-context hostname claim");
    wrong.rollback().await.unwrap();
    raw.close().await;
}

async fn assert_production_webshop_domain_admission(
    admin_url: &str,
    database: &str,
    owner_store: &Store,
    first_workshop: Uuid,
    second_workshop: Uuid,
    created_by: Uuid,
) {
    let function = "control.admit_due_webshop_domain_reconciliations(integer,text,text)";
    let metadata = sqlx::query_as::<_, (bool, bool, bool, bool, bool)>(
        "select procedure.prosecdef,
                coalesce(procedure.proconfig,'{}'::text[])
                    @> array['search_path=pg_catalog, control'],
                has_function_privilege(
                    'control_reconciliation_worker',procedure.oid,'EXECUTE'
                ),
                not exists(
                    select 1
                      from aclexplode(coalesce(
                          procedure.proacl,
                          acldefault('f',procedure.proowner)
                      )) privilege
                     where privilege.grantee=0
                       and privilege.privilege_type='EXECUTE'
                ),
                has_function_privilege('control_api',procedure.oid,'EXECUTE')
           from pg_proc procedure
           join pg_namespace namespace on namespace.oid=procedure.pronamespace
          where namespace.nspname='control' and procedure.oid=$1::regprocedure",
    )
    .bind(function)
    .fetch_one(owner_store.pool())
    .await
    .unwrap();
    assert!(metadata.0, "{function} must remain SECURITY DEFINER");
    assert!(
        metadata.1,
        "{function} must pin search_path to pg_catalog, control"
    );
    assert!(
        metadata.2,
        "the production reconciliation identity must execute {function}"
    );
    assert!(metadata.3, "PUBLIC execute must be revoked from {function}");
    assert!(
        !metadata.4,
        "the platform API identity must not execute {function}"
    );

    for function in [
        "control.admit_due_webshop_email_domain_reconciliations(integer,text,text)",
        "control.admit_due_tenant_reconciliations(integer,text,text,text)",
        "control.advance_webshop_domain_provider_deletion(uuid,integer,text,uuid,uuid,text,text,text)",
    ] {
        let metadata = sqlx::query_as::<_, (bool, bool, bool, bool, bool)>(
            "select procedure.prosecdef,
                    coalesce(procedure.proconfig,'{}'::text[])
                        @> array['search_path=pg_catalog, control'],
                    has_function_privilege(
                        'control_reconciliation_worker',procedure.oid,'EXECUTE'
                    ),
                    not exists(
                        select 1
                          from aclexplode(coalesce(
                              procedure.proacl,
                              acldefault('f',procedure.proowner)
                          )) privilege
                         where privilege.grantee=0
                           and privilege.privilege_type='EXECUTE'
                    ),
                    has_function_privilege('control_api',procedure.oid,'EXECUTE')
               from pg_proc procedure
               join pg_namespace namespace on namespace.oid=procedure.pronamespace
              where namespace.nspname='control' and procedure.oid=$1::regprocedure",
        )
        .bind(function)
        .fetch_one(owner_store.pool())
        .await
        .unwrap();
        assert!(metadata.0, "{function} must remain SECURITY DEFINER");
        assert!(
            metadata.1,
            "{function} must pin search_path to pg_catalog, control"
        );
        assert!(
            metadata.2,
            "the reconciliation identity must execute {function}"
        );
        assert!(metadata.3, "PUBLIC execute must be revoked from {function}");
        assert!(!metadata.4, "the platform API must not execute {function}");
    }

    let cursor_acl = sqlx::query_as::<_, (bool, bool, bool, bool)>(
        "select
            not exists(
                select 1
                  from aclexplode(coalesce(
                      table_class.relacl,
                      acldefault('r',table_class.relowner)
                  )) privilege
                 where privilege.grantee=0
            ),
            not has_table_privilege(
                'control_api','control.periodic_admission_cursors','SELECT'
            ),
            not has_table_privilege(
                'control_reconciliation_worker',
                'control.periodic_admission_cursors','SELECT'
            ),
            not has_table_privilege(
                'control_reconciliation_worker',
                'control.periodic_admission_cursors','UPDATE'
            )
           from pg_class table_class
           join pg_namespace namespace on namespace.oid=table_class.relnamespace
          where namespace.nspname='control'
            and table_class.relname='periodic_admission_cursors'",
    )
    .fetch_one(owner_store.pool())
    .await
    .unwrap();
    assert!(cursor_acl.0, "PUBLIC must have no cursor-table privileges");
    assert!(
        cursor_acl.1,
        "the platform API must not read admission cursors"
    );
    assert!(
        cursor_acl.2 && cursor_acl.3,
        "the reconciliation role must use the claim functions, not mutate cursors"
    );

    let deletion_acl = sqlx::query_as::<_, (bool, bool, bool)>(
        "select
            not exists(
                select 1 from aclexplode(coalesce(
                    table_class.relacl,acldefault('r',table_class.relowner)
                )) privilege where privilege.grantee=0
            ),
            not has_table_privilege(
                'control_api','control.webshop_domain_provider_deletion_attempts','SELECT'
            ),
            not has_table_privilege(
                'control_reconciliation_worker',
                'control.webshop_domain_provider_deletion_attempts','SELECT,INSERT,UPDATE,DELETE'
            )
         from pg_class table_class
         join pg_namespace namespace on namespace.oid=table_class.relnamespace
         where namespace.nspname='control'
           and table_class.relname='webshop_domain_provider_deletion_attempts'",
    )
    .fetch_one(owner_store.pool())
    .await
    .unwrap();
    assert!(
        deletion_acl.0,
        "PUBLIC must have no deletion-ledger privileges"
    );
    assert!(
        deletion_acl.1,
        "the platform API must not read deletion evidence"
    );
    assert!(
        deletion_acl.2,
        "the reconciliation role must use the fenced deletion function"
    );

    let mut api_attempt = owner_store.begin().await.unwrap();
    sqlx::query("set local role control_api")
        .execute(&mut *api_attempt)
        .await
        .unwrap();
    let api_execute = sqlx::query(
        "select operation_id,workshop_id,domain_id
           from control.admit_due_webshop_domain_reconciliations(1,null,null)",
    )
    .execute(&mut *api_attempt)
    .await
    .expect_err("the platform API must not invoke fleet domain admission");
    assert_insufficient_privilege(api_execute, "platform API domain admission");
    api_attempt.rollback().await.unwrap();

    let mut api_attempt = owner_store.begin().await.unwrap();
    sqlx::query("set local role control_api")
        .execute(&mut *api_attempt)
        .await
        .unwrap();
    let api_execute = sqlx::query(
        "select * from control.advance_webshop_domain_provider_deletion(
            null,1,'api',null,null,'provider','example.test','begin'
         )",
    )
    .execute(&mut *api_attempt)
    .await
    .expect_err("the platform API must not advance provider deletion evidence");
    assert_insufficient_privilege(api_execute, "platform API provider deletion");
    api_attempt.rollback().await.unwrap();

    let mut api_attempt = owner_store.begin().await.unwrap();
    sqlx::query("set local role control_api")
        .execute(&mut *api_attempt)
        .await
        .unwrap();
    let api_execute = sqlx::query(
        "select operation_id,workshop_id,email_domain_id
           from control.admit_due_webshop_email_domain_reconciliations(1,null,null)",
    )
    .execute(&mut *api_attempt)
    .await
    .expect_err("the platform API must not invoke fleet email-domain admission");
    assert_insufficient_privilege(api_execute, "platform API email-domain admission");
    api_attempt.rollback().await.unwrap();

    let mut api_attempt = owner_store.begin().await.unwrap();
    sqlx::query("set local role control_api")
        .execute(&mut *api_attempt)
        .await
        .unwrap();
    let api_execute = sqlx::query(
        "select operation_id,workshop_id
           from control.admit_due_tenant_reconciliations(1,'example.test',null,null)",
    )
    .execute(&mut *api_attempt)
    .await
    .expect_err("the platform API must not invoke fleet tenant admission");
    assert_insufficient_privilege(api_execute, "platform API tenant admission");
    api_attempt.rollback().await.unwrap();

    let domain_id = Uuid::new_v4();
    let hostname = format!("claim-{}.example.test", domain_id.simple());
    let verification_name = format!("_mb-challenge.{hostname}");
    let verification_value = format!("mb-verification={}", domain_id.simple());
    sqlx::query(
        "insert into control.webshop_domains(
             id,workshop_id,hostname,verification_name,verification_value,
             routing_target,state,ownership_verified_at,created_by
         ) values($1,$2,$3,$4,$5,'shops.example.test','dns_pending',now(),$6)",
    )
    .bind(domain_id)
    .bind(first_workshop)
    .bind(&hostname)
    .bind(&verification_name)
    .bind(&verification_value)
    .bind(created_by)
    .execute(owner_store.pool())
    .await
    .unwrap();

    let reconciliation_url = login_database_url(
        admin_url,
        database,
        "control_reconciliation_worker",
        "reconciliation-isolation-password",
    );
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&reconciliation_url)
        .await
        .unwrap();
    let first_claim = sqlx::query_as::<_, (Uuid, Uuid, Uuid)>(
        "select operation_id,workshop_id,domain_id
           from control.admit_due_webshop_domain_reconciliations(1,null,null)",
    )
    .fetch_all(&pool);
    let second_claim = sqlx::query_as::<_, (Uuid, Uuid, Uuid)>(
        "select operation_id,workshop_id,domain_id
           from control.admit_due_webshop_domain_reconciliations(1,null,null)",
    )
    .fetch_all(&pool);
    let (first_claim, second_claim) = tokio::join!(first_claim, second_claim);
    let claims = first_claim
        .unwrap()
        .into_iter()
        .chain(second_claim.unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        claims.len(),
        1,
        "concurrent production workers must admit one durable operation"
    );
    assert_eq!(claims[0].1, first_workshop);
    assert_eq!(claims[0].2, domain_id);
    let admitted_operation = claims[0].0;
    let binding = sqlx::query_as::<_, (Option<Uuid>, i64)>(
        "select domain.operation_id,
                (select count(*) from control.operations operation
                  where operation.id=domain.operation_id
                    and operation.workshop_id=domain.workshop_id
                    and operation.kind='webshop-domain.reconcile'
                    and operation.state='pending')
           from control.webshop_domains domain where domain.id=$1",
    )
    .bind(domain_id)
    .fetch_one(owner_store.pool())
    .await
    .unwrap();
    assert_eq!(binding, (Some(admitted_operation), 1));

    let direct_insert = sqlx::query(
        "insert into control.webshop_domains(
             id,workshop_id,hostname,verification_name,verification_value,
             routing_target,created_by
         ) values($1,$2,$3,$4,$5,'shops.example.test',$6)",
    )
    .bind(Uuid::new_v4())
    .bind(first_workshop)
    .bind(format!("forged-{}.example.test", Uuid::new_v4().simple()))
    .bind(format!(
        "_mb-challenge.forged-{}.example.test",
        Uuid::new_v4().simple()
    ))
    .bind(format!("mb-verification={}", Uuid::new_v4().simple()))
    .bind(created_by)
    .execute(&pool)
    .await
    .expect_err("the reconciliation role must not create human domain records");
    assert_insufficient_privilege(direct_insert, "direct webshop-domain insert");
    let direct_delete = sqlx::query("delete from control.webshop_domains where id=$1")
        .bind(domain_id)
        .execute(&pool)
        .await
        .expect_err("the reconciliation role must not delete domain ownership records");
    assert_insufficient_privilege(direct_delete, "direct webshop-domain delete");
    pool.close().await;

    let other_operation = Uuid::new_v4();
    sqlx::query(
        "insert into control.operations(
             id,kind,queue,workshop_id,payload,correlation_id,idempotency_key
         ) values($1,'webshop-domain.reconcile','tenant-reconciliation',$2,'{}',$3,$4)",
    )
    .bind(other_operation)
    .bind(second_workshop)
    .bind(Uuid::new_v4())
    .bind(format!("cross-tenant-domain-binding:{other_operation}"))
    .execute(owner_store.pool())
    .await
    .unwrap();
    let cross_tenant =
        sqlx::query("update control.webshop_domains set operation_id=$2 where id=$1")
            .bind(domain_id)
            .bind(other_operation)
            .execute(owner_store.pool())
            .await
            .expect_err("a domain must not bind an operation owned by another workshop");
    let code = cross_tenant
        .as_database_error()
        .and_then(|database_error| database_error.code());
    assert_eq!(
        code.as_deref(),
        Some("23503"),
        "cross-workshop operation binding must fail at the composite foreign key"
    );
}

async fn assert_production_tenant_pool(
    admin_url: &str,
    database: &str,
    first_workshop: Uuid,
    second_workshop: Uuid,
) {
    let tenant_url = login_database_url(
        admin_url,
        database,
        "control_tenant_api",
        "tenant-isolation-password",
    );
    let tenant_store = TenantStore::connect(&tenant_url).await.unwrap();
    let mut first = tenant_store.begin(first_workshop).await.unwrap();
    let first_visible: i64 = sqlx::query_scalar("select count(*) from control.ownership_transfers")
        .fetch_one(&mut *first)
        .await
        .unwrap();
    assert_eq!(first_visible, 1);
    first.commit().await.unwrap();

    let mut second = tenant_store.begin(second_workshop).await.unwrap();
    let second_visible: i64 =
        sqlx::query_scalar("select count(*) from control.ownership_transfers")
            .fetch_one(&mut *second)
            .await
            .unwrap();
    assert_eq!(second_visible, 1);
    second.commit().await.unwrap();
    drop(tenant_store);

    // A raw single-connection pool exists only in this acceptance test. It
    // proves production-login connection reuse cannot retain tenant A after a
    // commit and that an unset context sees no tenant rows.
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&tenant_url)
        .await
        .unwrap();
    let without_context: i64 =
        sqlx::query_scalar("select count(*) from control.ownership_transfers")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(without_context, 0);
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("select set_config('control.workshop_id',$1,true)")
        .bind(first_workshop.to_string())
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let after_commit: i64 = sqlx::query_scalar("select count(*) from control.ownership_transfers")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        after_commit, 0,
        "tenant context leaked on a reused connection"
    );
    pool.close().await;
}

async fn assert_production_worker_execution_scopes(
    admin_url: &str,
    database: &str,
    owner_store: &Store,
    workshop: Uuid,
) {
    let operation_id = Uuid::new_v4();
    sqlx::query(
        "insert into control.operations(
            id,kind,queue,workshop_id,payload,correlation_id,idempotency_key
         ) values($1,'membership.reconcile','membership-provisioning',$2,'{}',$3,$4)",
    )
    .bind(operation_id)
    .bind(workshop)
    .bind(Uuid::new_v4())
    .bind(format!("worker-scope:{operation_id}"))
    .execute(owner_store.pool())
    .await
    .unwrap();

    let worker_url = login_database_url(
        admin_url,
        database,
        "control_membership_worker",
        "membership-isolation-password",
    );
    let fleet_store = Store::connect(&worker_url).await.unwrap();
    let tenant_store = fleet_store.worker_tenant_scope();
    let worker_id = format!("membership-scope-test-{}", Uuid::new_v4());
    fleet_store
        .start_worker(&worker_id, "membership-provisioning", "scope-test-release")
        .await
        .unwrap();
    let leased = fleet_store
        .lease("membership-provisioning", &worker_id)
        .await
        .unwrap()
        .expect("the real worker login must lease fleet work");
    assert_eq!(leased.id, operation_id);
    assert_eq!(leased.workshop_id, Some(workshop));

    let mut tenant_tx = tenant_store.begin(workshop).await.unwrap();
    let installed: String =
        sqlx::query_scalar("select current_setting('control.workshop_id',true)")
            .fetch_one(&mut *tenant_tx)
            .await
            .unwrap();
    assert_eq!(installed, workshop.to_string());
    let workshop_visible: bool =
        sqlx::query_scalar("select exists(select 1 from control.workshops where id=$1)")
            .bind(workshop)
            .fetch_one(&mut *tenant_tx)
            .await
            .unwrap();
    assert!(workshop_visible);
    tenant_tx.commit().await.unwrap();

    assert!(
        fleet_store
            .heartbeat_worker(&worker_id, Some(operation_id))
            .await
            .unwrap()
    );
    fleet_store
        .finish(&leased, OperationOutcome::Succeeded)
        .await
        .unwrap();
    let state: String = sqlx::query_scalar("select state from control.operations where id=$1")
        .bind(operation_id)
        .fetch_one(owner_store.pool())
        .await
        .unwrap();
    assert_eq!(state, "succeeded");
    fleet_store.shutdown_worker(&worker_id).await.unwrap();
}

async fn assert_production_lifecycle_execution_scope(
    admin_url: &str,
    database: &str,
    owner_store: &Store,
    workshop: Uuid,
) {
    let service = Uuid::new_v4();
    sqlx::query("insert into control.service_instances(id,workshop_id,service,base_url,secret_ref,health) values($1,$2,'odoo','http://odoo.internal','docker/test/odoo','ready')")
        .bind(service).bind(workshop).execute(owner_store.pool()).await.unwrap();
    let operation_id = Uuid::new_v4();
    sqlx::query("insert into control.operations(id,kind,queue,workshop_id,payload,correlation_id,idempotency_key) values($1,'tenant.lifecycle','tenant-lifecycle',$2,'{}',$3,$4)")
        .bind(operation_id).bind(workshop).bind(Uuid::new_v4())
        .bind(format!("lifecycle-worker-scope:{operation_id}"))
        .execute(owner_store.pool()).await.unwrap();

    let lifecycle_url = login_database_url(
        admin_url,
        database,
        "control_lifecycle_worker",
        "lifecycle-isolation-password",
    );
    let fleet_store = Store::connect(&lifecycle_url).await.unwrap();
    let tenant_store = fleet_store.worker_tenant_scope();
    let worker_id = format!("lifecycle-scope-test-{}", Uuid::new_v4());
    fleet_store
        .start_worker(&worker_id, "tenant-lifecycle", "scope-test-release")
        .await
        .unwrap();
    let leased = fleet_store
        .lease("tenant-lifecycle", &worker_id)
        .await
        .unwrap()
        .expect("the lifecycle login must lease fleet work");
    assert_eq!(leased.id, operation_id);

    let mut tx = tenant_store.begin(workshop).await.unwrap();
    let identity = sqlx::query_as::<_, (String, String)>(
        "select current_user,current_setting('control.workshop_id')",
    )
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert_eq!(
        identity,
        ("control_lifecycle_worker".into(), workshop.to_string())
    );
    assert_eq!(
        sqlx::query(
            "update control.service_instances set health='suspended' where id=$1 and workshop_id=$2"
        )
        .bind(service)
        .bind(workshop)
        .execute(&mut *tx)
        .await
        .unwrap()
        .rows_affected(),
        1,
        "the production lifecycle role needs its reviewed deletion-finalization grant"
    );
    tx.commit().await.unwrap();

    fleet_store
        .finish(&leased, OperationOutcome::Succeeded)
        .await
        .unwrap();
    fleet_store.shutdown_worker(&worker_id).await.unwrap();
}

async fn assert_production_backup_scheduler_grants(
    admin_url: &str,
    database: &str,
    owner_store: &Store,
    first_workshop: Uuid,
    second_workshop: Uuid,
    requested_by: Uuid,
) {
    let mut fixtures = Vec::new();
    for workshop in [first_workshop, second_workshop] {
        let database_id = Uuid::new_v4();
        let recovery = Uuid::new_v4();
        let rehearsal = Uuid::new_v4();
        sqlx::query("insert into control.odoo_databases(id,workshop_id,kind,database_ref,public_hostname,label,state,routable) values($1,$2,'primary',$3,$4,'Scheduler grant fixture','ready',true)")
            .bind(database_id).bind(workshop).bind(format!("mb_{}",database_id.simple()))
            .bind(format!("{}.example.test",database_id.simple())).execute(owner_store.pool()).await.unwrap();
        sqlx::query("insert into control.workshop_recovery_points(id,workshop_id,database_id,kind,label,requested_by,state,ready_at,storage_location,verification_state,verified_at) values($1,$2,$3,'backup','Scheduler grant fixture',$4,'ready',now(),'s3','verified',now())")
            .bind(recovery).bind(workshop).bind(database_id).bind(requested_by)
            .execute(owner_store.pool()).await.unwrap();
        sqlx::query("insert into control.workshop_recovery_rehearsals(id,recovery_point_id,workshop_id,state,finished_at) values($1,$2,$3,'succeeded',now())")
            .bind(rehearsal).bind(recovery).bind(workshop)
            .execute(owner_store.pool()).await.unwrap();
        fixtures.push((recovery, rehearsal));
    }
    let (first_recovery, first_rehearsal) = fixtures[0];
    let (second_recovery, second_rehearsal) = fixtures[1];

    let flags = sqlx::query_as::<_, (bool, bool)>(
        "select relrowsecurity,relforcerowsecurity
           from pg_class relation
           join pg_namespace namespace on namespace.oid=relation.relnamespace
          where namespace.nspname='control'
            and relation.relname='workshop_recovery_rehearsals'",
    )
    .fetch_one(owner_store.pool())
    .await
    .unwrap();
    assert_eq!(flags, (true, true));
    let privileges = sqlx::query_as::<_, (bool, bool, bool, bool, bool, bool, bool, bool, bool)>(
        "select
           has_table_privilege('control_api','control.workshop_recovery_rehearsals','select'),
           has_table_privilege('control_api','control.workshop_recovery_rehearsals','insert'),
           has_table_privilege('control_api','control.workshop_recovery_rehearsals','update'),
           has_table_privilege('control_api','control.workshop_recovery_rehearsals','delete'),
           has_table_privilege('control_backup_scheduler','control.workshop_recovery_rehearsals','select'),
           has_table_privilege('control_backup_scheduler','control.workshop_recovery_rehearsals','insert'),
           has_any_column_privilege('control_backup_scheduler','control.workshop_recovery_rehearsals','update'),
           has_table_privilege('control_backup_scheduler','control.workshop_recovery_rehearsals','delete'),
           has_function_privilege('control_backup_scheduler','control.current_workshop_id()','execute')",
    )
    .fetch_one(owner_store.pool())
    .await
    .unwrap();
    assert_eq!(
        privileges,
        (true, false, false, false, true, true, true, false, true)
    );
    let migration_owner_policy_matches_role = sqlx::query_scalar::<_, bool>(
        "select
           exists(select 1 from pg_roles where rolname='control') =
           exists(
             select 1 from pg_policies
              where schemaname='control'
                and tablename='workshop_recovery_rehearsals'
                and policyname='workshop_recovery_rehearsals_migration_owner'
                and cmd='ALL'
                and roles::text[]=array['control']::text[]
           )",
    )
    .fetch_one(owner_store.pool())
    .await
    .unwrap();
    assert!(
        migration_owner_policy_matches_role,
        "the migration-owner policy must exist exactly when its optional role exists"
    );
    let policies = sqlx::query_as::<_, (String, String, Vec<String>)>(
        "select policyname,cmd,roles::text[]
           from pg_policies
          where schemaname='control'
            and tablename='workshop_recovery_rehearsals'
            and policyname <> 'workshop_recovery_rehearsals_migration_owner'
          order by policyname",
    )
    .fetch_all(owner_store.pool())
    .await
    .unwrap();
    assert_eq!(
        policies,
        vec![
            (
                "workshop_recovery_rehearsals_platform_read".into(),
                "SELECT".into(),
                vec!["control_api".into()],
            ),
            (
                "workshop_recovery_rehearsals_scheduler_discovery".into(),
                "SELECT".into(),
                vec!["control_backup_scheduler".into()],
            ),
            (
                "workshop_recovery_rehearsals_scheduler_insert".into(),
                "INSERT".into(),
                vec!["control_backup_scheduler".into()],
            ),
            (
                "workshop_recovery_rehearsals_scheduler_update".into(),
                "UPDATE".into(),
                vec!["control_backup_scheduler".into()],
            ),
        ]
    );

    let scheduler_url = login_database_url(
        admin_url,
        database,
        "control_backup_scheduler",
        "backup-scheduler-isolation-password",
    );
    let scheduler_store = Store::connect(&scheduler_url).await.unwrap();
    let tenant_store = scheduler_store.worker_tenant_scope();
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "select count(*) from control.workshop_recovery_rehearsals where id=any($1)"
        )
        .bind(vec![first_rehearsal, second_rehearsal])
        .fetch_one(scheduler_store.pool())
        .await
        .unwrap(),
        2,
        "bounded scheduler discovery deliberately remains fleet-readable"
    );
    assert_eq!(
        sqlx::query(
            "update control.workshop_recovery_rehearsals set started_at=started_at where id=$1"
        )
        .bind(first_rehearsal)
        .execute(scheduler_store.pool())
        .await
        .unwrap()
        .rows_affected(),
        0,
        "a scheduler write without transaction-local workshop context must fail closed"
    );

    let mut first_tx = tenant_store.begin(first_workshop).await.unwrap();
    assert_eq!(
        sqlx::query(
            "update control.workshop_recovery_rehearsals set started_at=started_at where id=$1"
        )
        .bind(first_rehearsal)
        .execute(&mut *first_tx)
        .await
        .unwrap()
        .rows_affected(),
        1
    );
    assert_eq!(
        sqlx::query(
            "update control.workshop_recovery_rehearsals set started_at=started_at where id=$1"
        )
        .bind(second_rehearsal)
        .execute(&mut *first_tx)
        .await
        .unwrap()
        .rows_affected(),
        0,
        "one workshop capability must not update another workshop's rehearsal"
    );
    assert!(
        sqlx::query("insert into control.workshop_recovery_rehearsals(id,recovery_point_id,workshop_id,state) values($1,$2,$3,'running')")
            .bind(Uuid::new_v4()).bind(second_recovery).bind(first_workshop)
            .execute(&mut *first_tx).await.is_err(),
        "a rehearsal insert must match both workshop context and recovery parent"
    );
    first_tx.rollback().await.unwrap();

    let mut malformed_tx = scheduler_store.begin().await.unwrap();
    sqlx::query("select set_config('control.workshop_id','not-a-uuid',true)")
        .execute(&mut *malformed_tx)
        .await
        .unwrap();
    assert_eq!(
        sqlx::query(
            "update control.workshop_recovery_rehearsals set started_at=started_at where id=$1"
        )
        .bind(first_rehearsal)
        .execute(&mut *malformed_tx)
        .await
        .unwrap()
        .rows_affected(),
        0
    );
    malformed_tx.rollback().await.unwrap();

    assert!(
        sqlx::query("update control.workshop_recovery_rehearsals set recovery_point_id=recovery_point_id where id=$1")
            .bind(first_rehearsal).execute(scheduler_store.pool()).await.is_err(),
        "the scheduler must not rewrite rehearsal ownership"
    );
    assert!(
        sqlx::query("delete from control.workshop_recovery_rehearsals where id=$1")
            .bind(first_rehearsal)
            .execute(scheduler_store.pool())
            .await
            .is_err(),
        "the scheduler must not delete its durable claim ledger"
    );
    sqlx::query("insert into control.audit_events(id,actor_audit_subject_id,workshop_id,action,target_type,target_id,correlation_id,outcome,detail) values($1,null,$2,'database.recovery.rehearse','workshop_recovery_point',$3,$4,'failed','{}')")
        .bind(Uuid::new_v4()).bind(first_workshop).bind(first_recovery.to_string()).bind(first_rehearsal)
        .execute(scheduler_store.pool()).await.unwrap();
    scheduler_store.pool().close().await;
}

async fn assert_recovery_point_stale_worker_grants_removed(owner_store: &Store, workshop: Uuid) {
    let privileges = sqlx::query_as::<_, (bool, bool, bool, bool)>(
        "select
           has_table_privilege('control_release_worker','control.workshop_recovery_points','select'),
           has_table_privilege('control_release_worker','control.workshop_recovery_points','insert'),
           has_table_privilege('control_release_worker','control.workshop_recovery_points','update'),
           has_table_privilege('control_privacy_worker','control.workshop_recovery_points','select')",
    )
    .fetch_one(owner_store.pool())
    .await
    .unwrap();
    assert_eq!(privileges, (false, false, false, false));

    let bounded_release_review = sqlx::query_as::<_, (bool, bool)>(
        "select procedure.prosecdef,
                has_function_privilege('control_release_worker',procedure.oid,'execute')
           from pg_proc procedure
           join pg_namespace namespace on namespace.oid=procedure.pronamespace
          where namespace.nspname='control'
            and procedure.oid='control.review_interrupted_immutable_release_runtime_observation(uuid,bigint,uuid,integer,text,text,text)'::regprocedure",
    )
    .fetch_one(owner_store.pool())
    .await
    .unwrap();
    assert_eq!(
        bounded_release_review,
        (true, true),
        "release review must retain only its bounded SECURITY DEFINER capability"
    );

    for (role, operation) in [
        ("control_release_worker", "select"),
        ("control_release_worker", "insert"),
        ("control_release_worker", "update"),
        ("control_privacy_worker", "select"),
    ] {
        let mut tx = owner_store.begin().await.unwrap();
        set_local_role_and_workshop(&mut tx, role, workshop).await;
        let denied =
            match operation {
                "select" => {
                    sqlx::query("select id from control.workshop_recovery_points limit 1")
                        .execute(&mut *tx)
                        .await
                }
                "insert" => {
                    sqlx::query("insert into control.workshop_recovery_points default values")
                        .execute(&mut *tx)
                        .await
                }
                "update" => sqlx::query(
                    "update control.workshop_recovery_points set state=state where workshop_id=$1",
                )
                .bind(workshop)
                .execute(&mut *tx)
                .await,
                _ => unreachable!(),
            }
            .expect_err("the stale direct recovery-point privilege must be removed");
        assert_insufficient_privilege(denied, &format!("{role} direct recovery-point {operation}"));
        tx.rollback().await.unwrap();
    }
}

async fn assert_invitation_rls(owner_store: &Store, workshops: (Uuid, Uuid), manager: Uuid) {
    let (first_workshop, second_workshop) = workshops;
    let first_invitation = Uuid::new_v4();
    let second_invitation = Uuid::new_v4();
    for (invitation, workshop, label) in [
        (first_invitation, first_workshop, "first"),
        (second_invitation, second_workshop, "second"),
    ] {
        sqlx::query("insert into control.invitations(id,workshop_id,email,role,invited_by,idempotency_key,expires_at) values($1,$2,$3,'artisan',$4,$5,now()+interval '1 day')")
            .bind(invitation)
            .bind(workshop)
            .bind(format!("invitation-{label}-{invitation}@example.test"))
            .bind(manager)
            .bind(format!("invitation-rls:{invitation}"))
            .execute(owner_store.pool())
            .await
            .unwrap();
    }

    let flags = sqlx::query_as::<_, (bool, bool)>(
        "select relrowsecurity,relforcerowsecurity
           from pg_class relation
           join pg_namespace namespace on namespace.oid=relation.relnamespace
          where namespace.nspname='control' and relation.relname='invitations'",
    )
    .fetch_one(owner_store.pool())
    .await
    .unwrap();
    assert_eq!(flags, (true, true));

    let privileges = sqlx::query_as::<_, (String, String)>(
        "select role_name,privilege
           from unnest(array[
                  'control_api','control_tenant_api','control_email_worker','control_privacy_worker'
                ]::text[]) role_name
          cross join unnest(array['SELECT','INSERT','UPDATE','DELETE']::text[]) privilege
          where has_table_privilege(role_name,'control.invitations',privilege)
          order by role_name,privilege",
    )
    .fetch_all(owner_store.pool())
    .await
    .unwrap();
    assert_eq!(
        privileges,
        vec![
            ("control_email_worker".into(), "SELECT".into()),
            ("control_tenant_api".into(), "INSERT".into()),
            ("control_tenant_api".into(), "SELECT".into()),
            ("control_tenant_api".into(), "UPDATE".into()),
        ]
    );

    let policies = sqlx::query_as::<_, (String, String, Vec<String>)>(
        "select policyname,cmd,roles::text[] from pg_policies
          where schemaname='control' and tablename='invitations'
            and policyname <> 'invitations_migration_owner'
          order by policyname",
    )
    .fetch_all(owner_store.pool())
    .await
    .unwrap();
    assert_eq!(policies.len(), 4);
    assert!(policies.iter().all(|(_, command, roles)| {
        roles == &["control_tenant_api"]
            || (command == "SELECT" && roles == &["control_email_worker"])
    }));

    for identity in [
        "control.lock_live_invitation(uuid,integer)",
        "control.read_managed_invitation(uuid,uuid)",
    ] {
        let metadata = sqlx::query_as::<_, (bool, bool, bool, bool)>(
            "select procedure.prosecdef,
                    coalesce(procedure.proconfig,'{}'::text[])
                        @> array['search_path=pg_catalog, control'],
                    has_function_privilege('control_api',procedure.oid,'EXECUTE'),
                    not exists(
                        select 1 from aclexplode(coalesce(
                            procedure.proacl,acldefault('f',procedure.proowner)
                        )) privilege
                        where privilege.grantee=0 and privilege.privilege_type='EXECUTE'
                    )
               from pg_proc procedure
               join pg_namespace namespace on namespace.oid=procedure.pronamespace
              where namespace.nspname='control' and procedure.oid=$1::regprocedure",
        )
        .bind(identity)
        .fetch_one(owner_store.pool())
        .await
        .unwrap();
        assert_eq!(metadata, (true, true, true, true));
    }

    for role in ["control_tenant_api", "control_email_worker"] {
        let mut missing = owner_store.begin().await.unwrap();
        set_local_role(&mut missing, role).await;
        assert_eq!(
            sqlx::query_scalar::<_, i64>("select count(*) from control.invitations")
                .fetch_one(&mut *missing)
                .await
                .unwrap(),
            0,
            "{role} must fail closed without workshop context"
        );
        missing.rollback().await.unwrap();

        let mut scoped = owner_store.begin().await.unwrap();
        set_local_role_and_workshop(&mut scoped, role, first_workshop).await;
        assert_eq!(
            sqlx::query_scalar::<_, Vec<Uuid>>(
                "select coalesce(array_agg(id order by id),'{}') from control.invitations",
            )
            .fetch_one(&mut *scoped)
            .await
            .unwrap(),
            vec![first_invitation]
        );
        scoped.rollback().await.unwrap();
    }

    let tenant_invitation = Uuid::new_v4();
    let mut tenant_insert = owner_store.begin().await.unwrap();
    set_local_role_and_workshop(&mut tenant_insert, "control_tenant_api", first_workshop).await;
    assert_eq!(
        sqlx::query("insert into control.invitations(id,workshop_id,email,role,invited_by,idempotency_key,expires_at) values($1,$2,$3,'viewer',$4,$5,now()+interval '1 day')")
            .bind(tenant_invitation)
            .bind(first_workshop)
            .bind(format!("tenant-invite-{tenant_invitation}@example.test"))
            .bind(manager)
            .bind(format!("tenant-invite:{tenant_invitation}"))
            .execute(&mut *tenant_insert)
            .await
            .unwrap()
            .rows_affected(),
        1
    );
    tenant_insert.rollback().await.unwrap();

    let mut cross_insert = owner_store.begin().await.unwrap();
    set_local_role_and_workshop(&mut cross_insert, "control_tenant_api", first_workshop).await;
    let denied = sqlx::query("insert into control.invitations(id,workshop_id,email,role,invited_by,idempotency_key,expires_at) values($1,$2,$3,'viewer',$4,$5,now()+interval '1 day')")
        .bind(Uuid::new_v4())
        .bind(second_workshop)
        .bind(format!("cross-invite-{}@example.test", Uuid::new_v4()))
        .bind(manager)
        .bind(format!("cross-invite:{}", Uuid::new_v4()))
        .execute(&mut *cross_insert)
        .await
        .expect_err("tenant API must not insert a cross-workshop invitation");
    assert_insufficient_privilege(denied, "cross-workshop invitation insert");
    cross_insert.rollback().await.unwrap();

    let mut tenant_update = owner_store.begin().await.unwrap();
    set_local_role_and_workshop(&mut tenant_update, "control_tenant_api", first_workshop).await;
    assert_eq!(
        sqlx::query("update control.invitations set last_sent_at=last_sent_at where id=$1")
            .bind(first_invitation)
            .execute(&mut *tenant_update)
            .await
            .unwrap()
            .rows_affected(),
        1
    );
    assert_eq!(
        sqlx::query("update control.invitations set last_sent_at=last_sent_at where id=$1")
            .bind(second_invitation)
            .execute(&mut *tenant_update)
            .await
            .unwrap()
            .rows_affected(),
        0
    );
    tenant_update.rollback().await.unwrap();

    for role in ["control_api", "control_privacy_worker"] {
        for statement in [
            "select id from control.invitations limit 1",
            "update control.invitations set last_sent_at=last_sent_at where false",
            "delete from control.invitations where false",
        ] {
            let mut direct = owner_store.begin().await.unwrap();
            set_local_role(&mut direct, role).await;
            let denied = sqlx::query(statement)
                .execute(&mut *direct)
                .await
                .expect_err("fleet identities must not directly access invitations");
            assert_insufficient_privilege(denied, &format!("{role} direct invitation access"));
            direct.rollback().await.unwrap();
        }
    }

    let mut email_mutation = owner_store.begin().await.unwrap();
    set_local_role_and_workshop(&mut email_mutation, "control_email_worker", first_workshop).await;
    let denied =
        sqlx::query("update control.invitations set last_sent_at=last_sent_at where false")
            .execute(&mut *email_mutation)
            .await
            .expect_err("email worker invitation access must be read-only");
    assert_insufficient_privilege(denied, "email-worker invitation update");
    email_mutation.rollback().await.unwrap();

    let mut capability = owner_store.begin().await.unwrap();
    set_local_role(&mut capability, "control_api").await;
    assert_eq!(
        sqlx::query_scalar::<_, Uuid>(
            "select invitation_id from control.lock_live_invitation($1,1)",
        )
        .bind(first_invitation)
        .fetch_one(&mut *capability)
        .await
        .unwrap(),
        first_invitation
    );
    assert!(
        sqlx::query_scalar::<_, Uuid>(
            "select invitation_id from control.lock_live_invitation($1,2)",
        )
        .bind(first_invitation)
        .fetch_optional(&mut *capability)
        .await
        .unwrap()
        .is_none(),
        "the token bootstrap capability must bind the generation"
    );
    assert_eq!(
        sqlx::query_scalar::<_, Uuid>(
            "select invitation_id from control.read_managed_invitation($1,$2)",
        )
        .bind(second_invitation)
        .bind(manager)
        .fetch_one(&mut *capability)
        .await
        .unwrap(),
        second_invitation
    );
    assert!(
        sqlx::query_scalar::<_, Uuid>(
            "select invitation_id from control.read_managed_invitation($1,$2)",
        )
        .bind(first_invitation)
        .bind(Uuid::new_v4())
        .fetch_optional(&mut *capability)
        .await
        .unwrap()
        .is_none(),
        "manager discovery must require active membership authority"
    );
    capability.rollback().await.unwrap();
}

async fn assert_outbox_rls(owner_store: &Store, workshops: (Uuid, Uuid)) {
    let (first_workshop, second_workshop) = workshops;
    let first_outbox = Uuid::new_v4();
    let second_outbox = Uuid::new_v4();
    for (outbox, workshop, label) in [
        (first_outbox, first_workshop, "first"),
        (second_outbox, second_workshop, "second"),
    ] {
        sqlx::query("insert into control.outbox(id,kind,recipient,template,payload,workshop_id,source_key) values($1,'odoo_transactional',$2,'odoo-rendered-v1','{}',$3,$4)")
            .bind(outbox)
            .bind(format!("outbox-{label}-{outbox}@example.test"))
            .bind(workshop)
            .bind(format!("outbox-rls:{outbox}"))
            .execute(owner_store.pool())
            .await
            .unwrap();
    }

    let flags = sqlx::query_as::<_, (bool, bool)>(
        "select relrowsecurity,relforcerowsecurity
           from pg_class relation
           join pg_namespace namespace on namespace.oid=relation.relnamespace
          where namespace.nspname='control' and relation.relname='outbox'",
    )
    .fetch_one(owner_store.pool())
    .await
    .unwrap();
    assert_eq!(flags, (true, true));

    let privileges = sqlx::query_as::<_, (String, String)>(
        "select role_name,privilege
           from unnest(array[
                  'control_api','control_tenant_api','control_email_worker',
                  'control_reconciliation_worker','control_privacy_worker'
                ]::text[]) role_name
          cross join unnest(array['SELECT','INSERT','UPDATE','DELETE']::text[]) privilege
          where has_table_privilege(role_name,'control.outbox',privilege)
          order by role_name,privilege",
    )
    .fetch_all(owner_store.pool())
    .await
    .unwrap();
    assert_eq!(
        privileges,
        vec![
            ("control_api".into(), "SELECT".into()),
            ("control_email_worker".into(), "SELECT".into()),
            ("control_email_worker".into(), "UPDATE".into()),
            ("control_reconciliation_worker".into(), "INSERT".into()),
            ("control_tenant_api".into(), "INSERT".into()),
            ("control_tenant_api".into(), "SELECT".into()),
        ]
    );

    let policies = sqlx::query_as::<_, (String, String, Vec<String>)>(
        "select policyname,cmd,roles::text[] from pg_policies
          where schemaname='control' and tablename='outbox'
            and policyname <> 'outbox_migration_owner'
          order by policyname",
    )
    .fetch_all(owner_store.pool())
    .await
    .unwrap();
    assert_eq!(policies.len(), 6);

    let metadata = sqlx::query_as::<_, (bool, bool, bool, bool)>(
        "select procedure.prosecdef,
                coalesce(procedure.proconfig,'{}'::text[])
                    @> array['search_path=pg_catalog, control'],
                has_function_privilege('control_api',procedure.oid,'EXECUTE'),
                not exists(
                    select 1 from aclexplode(coalesce(
                        procedure.proacl,acldefault('f',procedure.proowner)
                    )) privilege
                    where privilege.grantee=0 and privilege.privilege_type='EXECUTE'
                )
           from pg_proc procedure
           join pg_namespace namespace on namespace.oid=procedure.pronamespace
          where namespace.nspname='control'
            and procedure.oid='control.record_transactional_outbox_delivery_event(uuid,uuid,uuid,uuid,uuid,text,timestamptz)'::regprocedure",
    )
    .fetch_one(owner_store.pool())
    .await
    .unwrap();
    assert_eq!(metadata, (true, true, true, true));

    let mut platform = owner_store.begin().await.unwrap();
    set_local_role(&mut platform, "control_api").await;
    assert_eq!(
        sqlx::query_scalar::<_, i64>("select count(*) from control.outbox")
            .fetch_one(&mut *platform)
            .await
            .unwrap(),
        2
    );
    platform.rollback().await.unwrap();
    for statement in [
        "insert into control.outbox(id,kind,recipient,template,payload,workshop_id,source_key) values(gen_random_uuid(),'odoo_transactional','denied@example.test','odoo-rendered-v1','{}',gen_random_uuid(),'denied')",
        "update control.outbox set state=state where false",
        "delete from control.outbox where false",
    ] {
        let mut direct = owner_store.begin().await.unwrap();
        set_local_role(&mut direct, "control_api").await;
        let denied = sqlx::query(statement)
            .execute(&mut *direct)
            .await
            .expect_err("platform outbox mutations must use scoped paths or capabilities");
        assert_insufficient_privilege(denied, "platform direct outbox mutation");
        direct.rollback().await.unwrap();
    }

    for role in ["control_tenant_api", "control_email_worker"] {
        let mut missing = owner_store.begin().await.unwrap();
        set_local_role(&mut missing, role).await;
        assert_eq!(
            sqlx::query_scalar::<_, i64>("select count(*) from control.outbox")
                .fetch_one(&mut *missing)
                .await
                .unwrap(),
            0,
            "{role} must fail closed without workshop context"
        );
        missing.rollback().await.unwrap();

        let mut scoped = owner_store.begin().await.unwrap();
        set_local_role_and_workshop(&mut scoped, role, first_workshop).await;
        assert_eq!(
            sqlx::query_scalar::<_, Vec<Uuid>>(
                "select coalesce(array_agg(id order by id),'{}') from control.outbox",
            )
            .fetch_one(&mut *scoped)
            .await
            .unwrap(),
            vec![first_outbox]
        );
        scoped.rollback().await.unwrap();
    }

    let tenant_outbox = Uuid::new_v4();
    let mut tenant_insert = owner_store.begin().await.unwrap();
    set_local_role_and_workshop(&mut tenant_insert, "control_tenant_api", first_workshop).await;
    assert_eq!(
        sqlx::query("insert into control.outbox(id,kind,recipient,template,payload,workshop_id,source_key) values($1,'odoo_transactional',$2,'odoo-rendered-v1','{}',$3,$4)")
            .bind(tenant_outbox)
            .bind(format!("tenant-outbox-{tenant_outbox}@example.test"))
            .bind(first_workshop)
            .bind(format!("tenant-outbox:{tenant_outbox}"))
            .execute(&mut *tenant_insert)
            .await
            .unwrap()
            .rows_affected(),
        1
    );
    tenant_insert.rollback().await.unwrap();

    let mut tenant_cross = owner_store.begin().await.unwrap();
    set_local_role_and_workshop(&mut tenant_cross, "control_tenant_api", first_workshop).await;
    let denied = sqlx::query("insert into control.outbox(id,kind,recipient,template,payload,workshop_id,source_key) values($1,'odoo_transactional',$2,'odoo-rendered-v1','{}',$3,$4)")
        .bind(Uuid::new_v4())
        .bind(format!("tenant-cross-{}@example.test", Uuid::new_v4()))
        .bind(second_workshop)
        .bind(format!("tenant-cross:{}", Uuid::new_v4()))
        .execute(&mut *tenant_cross)
        .await
        .expect_err("tenant API must not insert a cross-workshop outbox row");
    assert_insufficient_privilege(denied, "cross-workshop tenant outbox insert");
    tenant_cross.rollback().await.unwrap();

    let reconciliation_outbox = Uuid::new_v4();
    let mut reconciliation = owner_store.begin().await.unwrap();
    set_local_role_and_workshop(
        &mut reconciliation,
        "control_reconciliation_worker",
        first_workshop,
    )
    .await;
    assert_eq!(
        sqlx::query("insert into control.outbox(id,kind,recipient,template,payload,workshop_id,source_key) values($1,'odoo_transactional',$2,'odoo-rendered-v1','{}',$3,$4)")
            .bind(reconciliation_outbox)
            .bind(format!("reconciliation-{reconciliation_outbox}@example.test"))
            .bind(first_workshop)
            .bind(format!("reconciliation:{reconciliation_outbox}"))
            .execute(&mut *reconciliation)
            .await
            .unwrap()
            .rows_affected(),
        1
    );
    reconciliation.rollback().await.unwrap();
    let mut reconciliation_read = owner_store.begin().await.unwrap();
    set_local_role_and_workshop(
        &mut reconciliation_read,
        "control_reconciliation_worker",
        first_workshop,
    )
    .await;
    let denied = sqlx::query("select id from control.outbox limit 1")
        .execute(&mut *reconciliation_read)
        .await
        .expect_err("reconciliation outbox authority is insert-only");
    assert_insufficient_privilege(denied, "reconciliation direct outbox read");
    reconciliation_read.rollback().await.unwrap();

    let mut email_update = owner_store.begin().await.unwrap();
    set_local_role_and_workshop(&mut email_update, "control_email_worker", first_workshop).await;
    assert_eq!(
        sqlx::query("update control.outbox set next_attempt_at=next_attempt_at where id=$1")
            .bind(first_outbox)
            .execute(&mut *email_update)
            .await
            .unwrap()
            .rows_affected(),
        1
    );
    assert_eq!(
        sqlx::query("update control.outbox set next_attempt_at=next_attempt_at where id=$1")
            .bind(second_outbox)
            .execute(&mut *email_update)
            .await
            .unwrap()
            .rows_affected(),
        0
    );
    email_update.rollback().await.unwrap();

    for statement in [
        "select id from control.outbox limit 1",
        "update control.outbox set state=state where false",
        "delete from control.outbox where false",
    ] {
        let mut privacy = owner_store.begin().await.unwrap();
        set_local_role(&mut privacy, "control_privacy_worker").await;
        let denied = sqlx::query(statement)
            .execute(&mut *privacy)
            .await
            .expect_err("privacy retention must remain function-only");
        assert_insufficient_privilege(denied, "privacy direct outbox access");
        privacy.rollback().await.unwrap();
    }

    let provider_message = Uuid::new_v4();
    let provider_domain = Uuid::new_v4();
    let event = Uuid::new_v4();
    let sns = Uuid::new_v4();
    let occurred_at = time::OffsetDateTime::now_utc();
    let mut capability = owner_store.begin().await.unwrap();
    set_local_role(&mut capability, "control_api").await;
    let invoke = |event_id: Uuid, sns_id: Uuid, message_id: Uuid| {
        sqlx::query_scalar::<_, String>(
            "select control.record_transactional_outbox_delivery_event($1,$2,$3,$4,$5,'email_deferred',$6)",
        )
        .bind(event_id)
        .bind(first_outbox)
        .bind(message_id)
        .bind(sns_id)
        .bind(provider_domain)
        .bind(occurred_at)
    };
    assert_eq!(
        invoke(event, sns, provider_message)
            .fetch_one(&mut *capability)
            .await
            .unwrap(),
        "created"
    );
    assert_eq!(
        invoke(event, sns, provider_message)
            .fetch_one(&mut *capability)
            .await
            .unwrap(),
        "replayed"
    );
    assert_eq!(
        invoke(event, Uuid::new_v4(), provider_message)
            .fetch_one(&mut *capability)
            .await
            .unwrap(),
        "conflict"
    );
    assert_eq!(
        invoke(Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4())
            .fetch_one(&mut *capability)
            .await
            .unwrap(),
        "ignored"
    );
    capability.rollback().await.unwrap();
}

async fn assert_email_delivery_evidence_rls(
    owner_store: &Store,
    workshops: (Uuid, Uuid),
    owner_user: Uuid,
) {
    let (first_workshop, second_workshop) = workshops;
    let first_outbox = Uuid::new_v4();
    let second_outbox = Uuid::new_v4();
    for (outbox, workshop, label) in [
        (first_outbox, first_workshop, "first"),
        (second_outbox, second_workshop, "second"),
    ] {
        sqlx::query("insert into control.outbox(id,kind,recipient,template,payload,workshop_id,source_key) values($1,'odoo_transactional',$2,'odoo-rendered-v1','{}',$3,$4)")
            .bind(outbox)
            .bind(format!("evidence-{label}-{outbox}@example.test"))
            .bind(workshop)
            .bind(format!("evidence:{outbox}"))
            .execute(owner_store.pool())
            .await
            .unwrap();
    }

    let first_domain = Uuid::new_v4();
    let second_domain = Uuid::new_v4();
    for (domain, workshop, label) in [
        (first_domain, first_workshop, "first"),
        (second_domain, second_workshop, "second"),
    ] {
        sqlx::query("insert into control.webshop_email_domains(id,workshop_id,domain_name,created_by) values($1,$2,$3,$4)")
            .bind(domain)
            .bind(workshop)
            .bind(format!("{label}-{domain}.example.test"))
            .bind(owner_user)
            .execute(owner_store.pool())
            .await
            .unwrap();
    }

    let first_event = Uuid::new_v4();
    let second_event = Uuid::new_v4();
    let mut provider = owner_store.begin().await.unwrap();
    set_local_role(&mut provider, "control_api").await;
    for (event, outbox) in [(first_event, first_outbox), (second_event, second_outbox)] {
        let outcome = sqlx::query_scalar::<_, String>(
            "select control.record_transactional_outbox_delivery_event($1,$2,$3,$4,$5,'email_spam',now())",
        )
        .bind(event)
        .bind(outbox)
        .bind(Uuid::new_v4())
        .bind(Uuid::new_v4())
        .bind(Uuid::new_v4())
        .fetch_one(&mut *provider)
        .await
        .unwrap();
        assert_eq!(outcome, "created");
    }
    provider.commit().await.unwrap();

    let event_owners = sqlx::query_as::<_, (Uuid, Uuid)>(
        "select event_id,workshop_id from control.email_delivery_events
          where event_id=any($1) order by event_id",
    )
    .bind(vec![first_event, second_event])
    .fetch_all(owner_store.pool())
    .await
    .unwrap();
    let mut expected_owners = vec![
        (first_event, first_workshop),
        (second_event, second_workshop),
    ];
    expected_owners.sort_unstable();
    assert_eq!(event_owners, expected_owners);

    let mismatched_suppression = sqlx::query(
        "insert into control.email_suppressions(
             workshop_id,recipient,reason,source_event_id
         ) values($1,$2,'spam',$3)",
    )
    .bind(second_workshop)
    .bind(format!("mismatched-{}@example.test", Uuid::new_v4()))
    .bind(first_event)
    .execute(owner_store.pool())
    .await
    .expect_err("suppression ownership must match its source delivery event");
    assert_eq!(
        mismatched_suppression
            .as_database_error()
            .and_then(|error| error.constraint()),
        Some("email_suppressions_source_event_tenant_fkey")
    );

    let flags = sqlx::query_as::<_, (String, bool, bool)>(
        "select relation.relname,relation.relrowsecurity,relation.relforcerowsecurity
           from pg_class relation
           join pg_namespace namespace on namespace.oid=relation.relnamespace
          where namespace.nspname='control'
            and relation.relname=any($1)
          order by relation.relname",
    )
    .bind(vec![
        "email_delivery_events",
        "email_suppressions",
        "webshop_email_domains",
    ])
    .fetch_all(owner_store.pool())
    .await
    .unwrap();
    assert_eq!(
        flags,
        vec![
            ("email_delivery_events".into(), true, true),
            ("email_suppressions".into(), true, true),
            ("webshop_email_domains".into(), true, true),
        ]
    );

    let privileges = sqlx::query_as::<_, (String, String, String)>(
        "select role_name,table_name,privilege
           from unnest(array[
                  'control_api','control_tenant_api','control_email_worker',
                  'control_reconciliation_worker','control_privacy_worker'
                ]::text[]) role_name
          cross join unnest(array[
                  'email_delivery_events','email_suppressions','webshop_email_domains'
                ]::text[]) table_name
          cross join unnest(array['SELECT','INSERT','UPDATE','DELETE']::text[]) privilege
          where has_table_privilege(role_name,'control.'||table_name,privilege)
          order by role_name,table_name,privilege",
    )
    .fetch_all(owner_store.pool())
    .await
    .unwrap();
    assert_eq!(
        privileges,
        vec![
            (
                "control_email_worker".into(),
                "webshop_email_domains".into(),
                "SELECT".into(),
            ),
            (
                "control_reconciliation_worker".into(),
                "email_suppressions".into(),
                "SELECT".into(),
            ),
            (
                "control_reconciliation_worker".into(),
                "webshop_email_domains".into(),
                "SELECT".into(),
            ),
            (
                "control_reconciliation_worker".into(),
                "webshop_email_domains".into(),
                "UPDATE".into(),
            ),
            (
                "control_tenant_api".into(),
                "email_suppressions".into(),
                "SELECT".into(),
            ),
            (
                "control_tenant_api".into(),
                "webshop_email_domains".into(),
                "INSERT".into(),
            ),
            (
                "control_tenant_api".into(),
                "webshop_email_domains".into(),
                "SELECT".into(),
            ),
            (
                "control_tenant_api".into(),
                "webshop_email_domains".into(),
                "UPDATE".into(),
            ),
        ]
    );

    let policies = sqlx::query_as::<_, (String, i64)>(
        "select tablename,count(*)
           from pg_policies
          where schemaname='control'
            and tablename=any($1)
            and policyname not like '%migration_owner'
          group by tablename order by tablename",
    )
    .bind(vec![
        "email_delivery_events",
        "email_suppressions",
        "webshop_email_domains",
    ])
    .fetch_all(owner_store.pool())
    .await
    .unwrap();
    assert_eq!(
        policies,
        vec![
            ("email_suppressions".into(), 2),
            ("webshop_email_domains".into(), 6),
        ]
    );

    for role in RUNTIME_ROLES {
        let mut direct = owner_store.begin().await.unwrap();
        set_local_role(&mut direct, role).await;
        let denied = sqlx::query("select event_id from control.email_delivery_events limit 1")
            .execute(&mut *direct)
            .await
            .expect_err("delivery events must be function-only for runtime roles");
        assert_insufficient_privilege(denied, "direct delivery-event access");
        direct.rollback().await.unwrap();
    }

    for role in ["control_tenant_api", "control_reconciliation_worker"] {
        let mut missing = owner_store.begin().await.unwrap();
        set_local_role(&mut missing, role).await;
        assert_eq!(
            sqlx::query_scalar::<_, i64>("select count(*) from control.email_suppressions")
                .fetch_one(&mut *missing)
                .await
                .unwrap(),
            0
        );
        missing.rollback().await.unwrap();

        let mut scoped = owner_store.begin().await.unwrap();
        set_local_role_and_workshop(&mut scoped, role, first_workshop).await;
        assert_eq!(
            sqlx::query_scalar::<_, i64>("select count(*) from control.email_suppressions")
                .fetch_one(&mut *scoped)
                .await
                .unwrap(),
            1
        );
        scoped.rollback().await.unwrap();
    }

    for role in [
        "control_tenant_api",
        "control_reconciliation_worker",
        "control_email_worker",
    ] {
        let mut missing = owner_store.begin().await.unwrap();
        set_local_role(&mut missing, role).await;
        assert_eq!(
            sqlx::query_scalar::<_, i64>("select count(*) from control.webshop_email_domains")
                .fetch_one(&mut *missing)
                .await
                .unwrap(),
            0
        );
        missing.rollback().await.unwrap();

        let mut scoped = owner_store.begin().await.unwrap();
        set_local_role_and_workshop(&mut scoped, role, first_workshop).await;
        assert_eq!(
            sqlx::query_scalar::<_, Vec<Uuid>>(
                "select coalesce(array_agg(id order by id),'{}') from control.webshop_email_domains",
            )
            .fetch_one(&mut *scoped)
            .await
            .unwrap(),
            vec![first_domain]
        );
        scoped.rollback().await.unwrap();
    }

    for role in ["control_tenant_api", "control_reconciliation_worker"] {
        let mut scoped = owner_store.begin().await.unwrap();
        set_local_role_and_workshop(&mut scoped, role, first_workshop).await;
        assert_eq!(
            sqlx::query(
                "update control.webshop_email_domains set updated_at=updated_at where id=$1"
            )
            .bind(first_domain)
            .execute(&mut *scoped)
            .await
            .unwrap()
            .rows_affected(),
            1
        );
        assert_eq!(
            sqlx::query(
                "update control.webshop_email_domains set updated_at=updated_at where id=$1"
            )
            .bind(second_domain)
            .execute(&mut *scoped)
            .await
            .unwrap()
            .rows_affected(),
            0
        );
        scoped.rollback().await.unwrap();
    }

    let mut email_mutation = owner_store.begin().await.unwrap();
    set_local_role_and_workshop(&mut email_mutation, "control_email_worker", first_workshop).await;
    let denied =
        sqlx::query("update control.webshop_email_domains set updated_at=updated_at where id=$1")
            .bind(first_domain)
            .execute(&mut *email_mutation)
            .await
            .expect_err("email worker must remain read-only for branded domains");
    assert_insufficient_privilege(denied, "email worker branded-domain update");
    email_mutation.rollback().await.unwrap();

    for statement in [
        "select * from control.email_suppressions limit 1",
        "select * from control.webshop_email_domains limit 1",
    ] {
        let mut platform = owner_store.begin().await.unwrap();
        set_local_role(&mut platform, "control_api").await;
        let denied = sqlx::query(statement)
            .execute(&mut *platform)
            .await
            .expect_err("platform API direct delivery evidence access must be removed");
        assert_insufficient_privilege(denied, "platform delivery evidence access");
        platform.rollback().await.unwrap();
    }
}

async fn assert_membership_rls(owner_store: &Store, workshops: (Uuid, Uuid), owner_user: Uuid) {
    let (first_workshop, second_workshop) = workshops;
    let flags = sqlx::query_as::<_, (bool, bool)>(
        "select relrowsecurity,relforcerowsecurity
           from pg_class relation
           join pg_namespace namespace on namespace.oid=relation.relnamespace
          where namespace.nspname='control' and relation.relname='memberships'",
    )
    .fetch_one(owner_store.pool())
    .await
    .unwrap();
    assert_eq!(flags, (true, true));

    let privileges = sqlx::query_as::<_, (String, String)>(
        "select role_name,privilege
           from unnest(array[
                  'control_api','control_tenant_api','control_membership_worker',
                  'control_provisioning_worker','control_invoice_worker',
                  'control_inventory_worker','control_reconciliation_worker',
                  'control_backup_scheduler','control_privacy_worker','control_driver_ledger'
                ]::text[]) role_name
          cross join unnest(array['SELECT','INSERT','UPDATE','DELETE']::text[]) privilege
          where has_table_privilege(role_name,'control.memberships',privilege)
          order by role_name,privilege",
    )
    .fetch_all(owner_store.pool())
    .await
    .unwrap();
    assert_eq!(
        privileges,
        vec![
            ("control_api".into(), "SELECT".into()),
            ("control_backup_scheduler".into(), "SELECT".into()),
            ("control_driver_ledger".into(), "SELECT".into()),
            ("control_membership_worker".into(), "SELECT".into()),
            ("control_privacy_worker".into(), "SELECT".into()),
            ("control_provisioning_worker".into(), "SELECT".into()),
            ("control_reconciliation_worker".into(), "SELECT".into()),
            ("control_tenant_api".into(), "SELECT".into()),
            ("control_tenant_api".into(), "UPDATE".into()),
        ]
    );

    let policies = sqlx::query_as::<_, (String, String, Vec<String>)>(
        "select policyname,cmd,roles::text[] from pg_policies
          where schemaname='control' and tablename='memberships'
            and policyname <> 'memberships_migration_owner'
          order by policyname",
    )
    .fetch_all(owner_store.pool())
    .await
    .unwrap();
    assert_eq!(policies.len(), 9);
    assert_eq!(
        policies
            .iter()
            .filter(|(_, _, roles)| roles == &vec!["control_api".to_owned()])
            .map(|(name, command, _)| (name.as_str(), command.as_str()))
            .collect::<Vec<_>>(),
        vec![("memberships_platform_read", "SELECT")]
    );
    assert!(policies.iter().all(|(_, command, roles)| {
        command == "SELECT" || (command == "UPDATE" && roles == &["control_tenant_api"])
    }));

    let mut platform = owner_store.begin().await.unwrap();
    set_local_role(&mut platform, "control_api").await;
    assert_eq!(
        sqlx::query_scalar::<_, i64>("select count(*) from control.memberships where user_id=$1",)
            .bind(owner_user)
            .fetch_one(&mut *platform)
            .await
            .unwrap(),
        2,
        "platform reporting deliberately remains fleet-readable"
    );
    platform.rollback().await.unwrap();
    for statement in [
        "insert into control.memberships(workshop_id,user_id,role) values(gen_random_uuid(),gen_random_uuid(),'owner')",
        "update control.memberships set version=version where false",
        "delete from control.memberships where false",
    ] {
        let mut platform_mutation = owner_store.begin().await.unwrap();
        set_local_role(&mut platform_mutation, "control_api").await;
        let error = sqlx::query(statement)
            .execute(&mut *platform_mutation)
            .await
            .expect_err("platform API membership mutation must use a bounded capability");
        assert_insufficient_privilege(error, "control_api membership mutation");
        platform_mutation.rollback().await.unwrap();
    }

    for role in [
        "control_tenant_api",
        "control_membership_worker",
        "control_provisioning_worker",
        "control_reconciliation_worker",
        "control_backup_scheduler",
        "control_privacy_worker",
        "control_driver_ledger",
    ] {
        let mut missing = owner_store.begin().await.unwrap();
        set_local_role(&mut missing, role).await;
        assert_eq!(
            sqlx::query_scalar::<_, i64>("select count(*) from control.memberships")
                .fetch_one(&mut *missing)
                .await
                .unwrap(),
            0,
            "{role} must fail closed without workshop context"
        );
        missing.rollback().await.unwrap();

        let mut scoped = owner_store.begin().await.unwrap();
        set_local_role_and_workshop(&mut scoped, role, first_workshop).await;
        assert!(
            sqlx::query_scalar::<_, bool>(
                "select exists(select 1 from control.memberships where workshop_id=$1 and user_id=$2)",
            )
            .bind(first_workshop)
            .bind(owner_user)
            .fetch_one(&mut *scoped)
            .await
            .unwrap()
        );
        assert!(
            !sqlx::query_scalar::<_, bool>(
                "select exists(select 1 from control.memberships where workshop_id=$1 and user_id=$2)",
            )
            .bind(second_workshop)
            .bind(owner_user)
            .fetch_one(&mut *scoped)
            .await
            .unwrap()
        );
        scoped.rollback().await.unwrap();
    }

    let mut tenant_update = owner_store.begin().await.unwrap();
    set_local_role_and_workshop(&mut tenant_update, "control_tenant_api", first_workshop).await;
    assert_eq!(
        sqlx::query("update control.memberships set version=version where workshop_id=$1")
            .bind(first_workshop)
            .execute(&mut *tenant_update)
            .await
            .unwrap()
            .rows_affected(),
        1
    );
    assert_eq!(
        sqlx::query("update control.memberships set version=version where workshop_id=$1")
            .bind(second_workshop)
            .execute(&mut *tenant_update)
            .await
            .unwrap()
            .rows_affected(),
        0
    );
    tenant_update.rollback().await.unwrap();

    let new_workshop = Uuid::new_v4();
    sqlx::query("insert into control.workshops(id,slug,display_name,time_zone) values($1,$2,'Membership capability workshop','Europe/Paris')")
        .bind(new_workshop).bind(format!("membership-capability-{}", new_workshop.simple()))
        .execute(owner_store.pool()).await.unwrap();
    let create_command = Uuid::new_v4();
    sqlx::query("insert into control.commands(id,actor_user_id,scope,command_kind,idempotency_key,request_digest) values($1,$2,'platform:workshops','workshop.create',$3,$4)")
        .bind(create_command).bind(owner_user).bind(format!("membership-create:{create_command}"))
        .bind(vec![7_u8; 32]).execute(owner_store.pool()).await.unwrap();
    let mut create_tx = owner_store.begin().await.unwrap();
    set_local_role(&mut create_tx, "control_api").await;
    assert_eq!(
        sqlx::query_scalar::<_, i32>("select control.insert_initial_workshop_owner($1,$2,$3)")
            .bind(create_command)
            .bind(new_workshop)
            .bind(owner_user)
            .fetch_one(&mut *create_tx)
            .await
            .unwrap(),
        1
    );
    let forged = sqlx::query("select control.insert_initial_workshop_owner($1,$2,$3)")
        .bind(Uuid::new_v4())
        .bind(Uuid::new_v4())
        .bind(owner_user)
        .execute(&mut *create_tx)
        .await
        .expect_err("forged creation authority must fail");
    assert_insufficient_privilege(forged, "forged initial-owner capability");
    create_tx.rollback().await.unwrap();

    let invited_user = Uuid::new_v4();
    let invited_email = format!("invited-{}@example.test", invited_user.simple());
    sqlx::query("insert into control.users(id,email) values($1,$2)")
        .bind(invited_user)
        .bind(&invited_email)
        .execute(owner_store.pool())
        .await
        .unwrap();
    let invitation = Uuid::new_v4();
    sqlx::query("insert into control.invitations(id,workshop_id,email,role,invited_by,idempotency_key,expires_at) values($1,$2,$3,'artisan',$4,$5,now()+interval '1 day')")
        .bind(invitation).bind(first_workshop).bind(&invited_email).bind(owner_user)
        .bind(format!("membership-invite:{invitation}")).execute(owner_store.pool()).await.unwrap();
    let accept_command = Uuid::new_v4();
    sqlx::query("insert into control.commands(id,actor_user_id,scope,command_kind,idempotency_key,request_digest) values($1,$2,$3,'invitation.accept',$4,$5)")
        .bind(accept_command).bind(invited_user).bind(format!("workshop:{first_workshop}"))
        .bind(format!("membership-accept:{accept_command}")).bind(vec![8_u8; 32])
        .execute(owner_store.pool()).await.unwrap();
    let mut accept_tx = owner_store.begin().await.unwrap();
    set_local_role(&mut accept_tx, "control_api").await;
    let accepted = sqlx::query_as::<_, (Uuid, i32)>(
        "select workshop_id,authority_epoch from control.accept_invitation_membership($1,1,$2,$3)",
    )
    .bind(invitation)
    .bind(invited_user)
    .bind(accept_command)
    .fetch_one(&mut *accept_tx)
    .await
    .unwrap();
    assert_eq!(accepted, (first_workshop, 1));
    accept_tx.rollback().await.unwrap();

    let operation = Uuid::new_v4();
    let request = Uuid::new_v4();
    let lease_owner = format!("membership-privacy-{operation}");
    sqlx::query("insert into control.operations(id,kind,queue,target_user_id,payload,state,attempt,leased_by,lease_expires_at,correlation_id,idempotency_key) values($1,'privacy.data_subject_request','privacy-operations',$2,$3,'in_flight',1,$4,now()+interval '10 minutes',$5,$6)")
        .bind(operation).bind(owner_user).bind(serde_json::json!({"request_id": request}))
        .bind(&lease_owner).bind(Uuid::new_v4()).bind(format!("membership-privacy:{operation}"))
        .execute(owner_store.pool()).await.unwrap();
    sqlx::query("insert into control.data_subject_requests(id,subject_user_id,request_type,scope,status,operation_id) values($1,$2,'access','{}','executing',$3)")
        .bind(request).bind(owner_user).bind(operation).execute(owner_store.pool()).await.unwrap();
    let mut privacy_tx = owner_store.begin().await.unwrap();
    set_local_role(&mut privacy_tx, "control_privacy_worker").await;
    let mut visible = sqlx::query_scalar::<_, Uuid>(
        "select workshop_id from control.read_privacy_subject_workshops($1,$2,1,$3,51)",
    )
    .bind(request)
    .bind(operation)
    .bind(&lease_owner)
    .fetch_all(&mut *privacy_tx)
    .await
    .unwrap();
    visible.sort_unstable();
    let mut expected = vec![first_workshop, second_workshop];
    expected.sort_unstable();
    assert_eq!(visible, expected);
    let forged = sqlx::query("select * from control.read_privacy_subject_workshops($1,$2,2,$3,51)")
        .bind(request)
        .bind(operation)
        .bind(&lease_owner)
        .execute(&mut *privacy_tx)
        .await
        .expect_err("forged privacy lease must fail");
    assert_insufficient_privilege(forged, "forged privacy membership capability");
    privacy_tx.rollback().await.unwrap();

    let mut scheduler_tx = owner_store.begin().await.unwrap();
    set_local_role(&mut scheduler_tx, "control_backup_scheduler").await;
    let discovered = sqlx::query_scalar::<_, i64>(
        "select count(*) from control.discover_due_backup_memberships(100)",
    )
    .fetch_one(&mut *scheduler_tx)
    .await
    .unwrap();
    assert!((0..=100).contains(&discovered));
    assert!(
        sqlx::query("select * from control.discover_due_backup_memberships(101)")
            .execute(&mut *scheduler_tx)
            .await
            .is_err()
    );
    scheduler_tx.rollback().await.unwrap();
}

async fn assert_recovery_point_rls(
    admin_url: &str,
    database: &str,
    owner_store: &Store,
    workshops: (Uuid, Uuid),
    recoveries: (Uuid, Uuid),
    requested_by: Uuid,
) {
    let (first_workshop, second_workshop) = workshops;
    let (first_recovery, second_recovery) = recoveries;
    let flags = sqlx::query_as::<_, (bool, bool)>(
        "select relrowsecurity,relforcerowsecurity
           from pg_class relation
           join pg_namespace namespace on namespace.oid=relation.relnamespace
          where namespace.nspname='control'
            and relation.relname='workshop_recovery_points'",
    )
    .fetch_one(owner_store.pool())
    .await
    .unwrap();
    assert_eq!(flags, (true, true));

    let privileges = sqlx::query_as::<_, (String, String)>(
        "select role_name,privilege
           from unnest(array[
                  'control_api','control_tenant_api','control_lifecycle_worker',
                  'control_backup_scheduler','control_driver_ledger',
                  'control_release_worker','control_privacy_worker'
                ]::text[]) role_name
          cross join unnest(array['SELECT','INSERT','UPDATE','DELETE']::text[]) privilege
          where has_table_privilege(
                  role_name,'control.workshop_recovery_points',privilege
                )
          order by role_name,privilege",
    )
    .fetch_all(owner_store.pool())
    .await
    .unwrap();
    assert_eq!(
        privileges,
        vec![
            ("control_api".into(), "SELECT".into()),
            ("control_backup_scheduler".into(), "INSERT".into()),
            ("control_backup_scheduler".into(), "SELECT".into()),
            ("control_driver_ledger".into(), "SELECT".into()),
            ("control_driver_ledger".into(), "UPDATE".into()),
            ("control_lifecycle_worker".into(), "SELECT".into()),
            ("control_lifecycle_worker".into(), "UPDATE".into()),
            ("control_tenant_api".into(), "INSERT".into()),
            ("control_tenant_api".into(), "SELECT".into()),
        ]
    );

    let policies = sqlx::query_as::<_, (String, String, Vec<String>)>(
        "select policyname,cmd,roles::text[]
           from pg_policies
          where schemaname='control'
            and tablename='workshop_recovery_points'
            and policyname <> 'workshop_recovery_points_migration_owner'
          order by policyname",
    )
    .fetch_all(owner_store.pool())
    .await
    .unwrap();
    assert_eq!(
        policies,
        vec![
            (
                "workshop_recovery_points_driver_read".into(),
                "SELECT".into(),
                vec!["control_driver_ledger".into()],
            ),
            (
                "workshop_recovery_points_driver_update".into(),
                "UPDATE".into(),
                vec!["control_driver_ledger".into()],
            ),
            (
                "workshop_recovery_points_lifecycle_read".into(),
                "SELECT".into(),
                vec!["control_lifecycle_worker".into()],
            ),
            (
                "workshop_recovery_points_lifecycle_update".into(),
                "UPDATE".into(),
                vec!["control_lifecycle_worker".into()],
            ),
            (
                "workshop_recovery_points_platform_read".into(),
                "SELECT".into(),
                vec!["control_api".into()],
            ),
            (
                "workshop_recovery_points_scheduler_discovery".into(),
                "SELECT".into(),
                vec!["control_backup_scheduler".into()],
            ),
            (
                "workshop_recovery_points_scheduler_insert".into(),
                "INSERT".into(),
                vec!["control_backup_scheduler".into()],
            ),
            (
                "workshop_recovery_points_tenant_api_insert".into(),
                "INSERT".into(),
                vec!["control_tenant_api".into()],
            ),
            (
                "workshop_recovery_points_tenant_api_read".into(),
                "SELECT".into(),
                vec!["control_tenant_api".into()],
            ),
        ]
    );

    let mut platform_tx = owner_store.begin().await.unwrap();
    set_local_role(&mut platform_tx, "control_api").await;
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "select count(*) from control.workshop_recovery_points where id=any($1)",
        )
        .bind(vec![first_recovery, second_recovery])
        .fetch_one(&mut *platform_tx)
        .await
        .unwrap(),
        2,
        "platform status deliberately remains fleet-readable"
    );
    platform_tx.rollback().await.unwrap();

    let first_database = sqlx::query_scalar::<_, Uuid>(
        "select database_id from control.workshop_recovery_points where id=$1",
    )
    .bind(first_recovery)
    .fetch_one(owner_store.pool())
    .await
    .unwrap();
    let second_database = sqlx::query_scalar::<_, Uuid>(
        "select database_id from control.workshop_recovery_points where id=$1",
    )
    .bind(second_recovery)
    .fetch_one(owner_store.pool())
    .await
    .unwrap();

    let tenant_url = login_database_url(
        admin_url,
        database,
        "control_tenant_api",
        "tenant-isolation-password",
    );
    let tenant_store = TenantStore::connect(&tenant_url).await.unwrap();
    let mut tenant_tx = tenant_store.begin(first_workshop).await.unwrap();
    assert!(
        sqlx::query_scalar::<_, bool>(
            "select exists(select 1 from control.workshop_recovery_points where id=$1)",
        )
        .bind(first_recovery)
        .fetch_one(&mut *tenant_tx)
        .await
        .unwrap()
    );
    assert!(
        !sqlx::query_scalar::<_, bool>(
            "select exists(select 1 from control.workshop_recovery_points where id=$1)",
        )
        .bind(second_recovery)
        .fetch_one(&mut *tenant_tx)
        .await
        .unwrap()
    );
    sqlx::query("insert into control.workshop_recovery_points(id,workshop_id,database_id,kind,label,requested_by) values($1,$2,$3,'snapshot','Scoped API fixture',$4)")
        .bind(Uuid::new_v4()).bind(first_workshop).bind(first_database).bind(requested_by)
        .execute(&mut *tenant_tx).await.unwrap();
    assert!(
        sqlx::query("insert into control.workshop_recovery_points(id,workshop_id,database_id,kind,label,requested_by) values($1,$2,$3,'snapshot','Cross API fixture',$4)")
            .bind(Uuid::new_v4()).bind(second_workshop).bind(second_database).bind(requested_by)
            .execute(&mut *tenant_tx).await.is_err()
    );
    tenant_tx.rollback().await.unwrap();
    drop(tenant_store);

    for (role, password) in [
        ("control_lifecycle_worker", "lifecycle-isolation-password"),
        ("control_driver_ledger", "driver-ledger-isolation-password"),
    ] {
        let role_url = login_database_url(admin_url, database, role, password);
        let role_store = Store::connect(&role_url).await.unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>("select count(*) from control.workshop_recovery_points")
                .fetch_one(role_store.pool())
                .await
                .unwrap(),
            0,
            "{role} must fail closed without workshop context"
        );
        let scoped = role_store.worker_tenant_scope();
        let mut tx = scoped.begin(first_workshop).await.unwrap();
        assert_eq!(
            sqlx::query("update control.workshop_recovery_points set state=state where id=$1")
                .bind(first_recovery)
                .execute(&mut *tx)
                .await
                .unwrap()
                .rows_affected(),
            1
        );
        assert_eq!(
            sqlx::query("update control.workshop_recovery_points set state=state where id=$1")
                .bind(second_recovery)
                .execute(&mut *tx)
                .await
                .unwrap()
                .rows_affected(),
            0,
            "{role} must not update another workshop's recovery point"
        );
        let denied = sqlx::query("delete from control.workshop_recovery_points where id=$1")
            .bind(first_recovery)
            .execute(&mut *tx)
            .await
            .expect_err("no runtime role may delete recovery points");
        assert_insufficient_privilege(denied, &format!("{role} recovery-point delete"));
        tx.rollback().await.unwrap();
        role_store.pool().close().await;
    }

    let scheduler_url = login_database_url(
        admin_url,
        database,
        "control_backup_scheduler",
        "backup-scheduler-isolation-password",
    );
    let scheduler_store = Store::connect(&scheduler_url).await.unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "select count(*) from control.workshop_recovery_points where id=any($1)",
        )
        .bind(vec![first_recovery, second_recovery])
        .fetch_one(scheduler_store.pool())
        .await
        .unwrap(),
        2,
        "scheduler discovery deliberately remains fleet-readable"
    );
    assert!(
        sqlx::query("insert into control.workshop_recovery_points(id,workshop_id,database_id,kind,label,requested_by) values($1,$2,$3,'backup','Missing scheduler context',$4)")
            .bind(Uuid::new_v4()).bind(first_workshop).bind(first_database).bind(requested_by)
            .execute(scheduler_store.pool()).await.is_err()
    );
    let scheduler_tenant = scheduler_store.worker_tenant_scope();
    let mut scheduler_tx = scheduler_tenant.begin(first_workshop).await.unwrap();
    sqlx::query("insert into control.workshop_recovery_points(id,workshop_id,database_id,kind,label,requested_by) values($1,$2,$3,'backup','Scoped scheduler fixture',$4)")
        .bind(Uuid::new_v4()).bind(first_workshop).bind(first_database).bind(requested_by)
        .execute(&mut *scheduler_tx).await.unwrap();
    assert!(
        sqlx::query("insert into control.workshop_recovery_points(id,workshop_id,database_id,kind,label,requested_by) values($1,$2,$3,'backup','Cross scheduler fixture',$4)")
            .bind(Uuid::new_v4()).bind(second_workshop).bind(second_database).bind(requested_by)
            .execute(&mut *scheduler_tx).await.is_err()
    );
    scheduler_tx.rollback().await.unwrap();
    scheduler_store.pool().close().await;

    let driver_url = login_database_url(
        admin_url,
        database,
        "control_driver_ledger",
        "driver-ledger-isolation-password",
    );
    let driver_store = Store::connect(&driver_url).await.unwrap();
    let mut malformed = driver_store.begin().await.unwrap();
    sqlx::query("select set_config('control.workshop_id','not-a-uuid',true)")
        .execute(&mut *malformed)
        .await
        .unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>("select count(*) from control.workshop_recovery_points")
            .fetch_one(&mut *malformed)
            .await
            .unwrap(),
        0,
        "malformed workshop context must fail closed"
    );
    malformed.rollback().await.unwrap();
    driver_store.pool().close().await;
}

async fn seed_platform_capability_release(
    owner_store: &Store,
    status: &str,
    marker: char,
) -> String {
    let release_id = format!("odoo-2026.08.24-{}", Uuid::new_v4().simple());
    let digest = |value: char| format!("sha256:{}", value.to_string().repeat(64));
    sqlx::query(
        "insert into control.application_releases(
           id,source_commit,odoo_version,odoo_subject_digest,extension_subject_digest,
           odoo_runtime,extension_bundle,pair_qualifications,manifest_digest,addon_versions,
           compatibility,bridge_contract,schema_epoch,change_class,required_postconditions,
           manifest,signature_bundle_ref,extension_signature_ref,sbom_ref,published_at,status,
           publication_idempotency_key,publication_request_digest
         ) values($1,$2,'19.0',$3,$4,'{}','{}','[{}]',$5,'{}','{}','>=3.2.0,<4.0.0',1,'A','[]',
           jsonb_build_object('capability_registry_version',1),
           'oci://signature','oci://extension-signature','oci://sbom',now(),$6,$7,$8)",
    )
    .bind(&release_id)
    .bind(marker.to_string().repeat(40))
    .bind(digest(marker))
    .bind(digest(char::from_u32(marker as u32 + 1).unwrap()))
    .bind(digest(char::from_u32(marker as u32 + 2).unwrap()))
    .bind(status)
    .bind(format!("platform-capability:{release_id}"))
    .bind(vec![marker as u8; 32])
    .execute(owner_store.pool())
    .await
    .unwrap();
    release_id
}

async fn assert_platform_recovery_point_capabilities(
    owner_store: &Store,
    deletion_workshop: Uuid,
    release_workshop: Uuid,
    requested_by: Uuid,
) {
    let privileges = sqlx::query_as::<_, (bool, bool, bool, bool)>(
        "select
           has_table_privilege('control_api','control.workshop_recovery_points','select'),
           has_table_privilege('control_api','control.workshop_recovery_points','insert'),
           has_table_privilege('control_api','control.workshop_recovery_points','update'),
           has_table_privilege('control_api','control.workshop_recovery_points','delete')",
    )
    .fetch_one(owner_store.pool())
    .await
    .unwrap();
    assert_eq!(privileges, (true, false, false, false));

    for identity in [
        "control.insert_platform_deletion_recovery_point(uuid,uuid,uuid,uuid)",
        "control.insert_platform_release_recovery_point(uuid,uuid,uuid,uuid,uuid,text)",
    ] {
        let metadata = sqlx::query_as::<_, (bool, bool, bool, bool, bool)>(
            "select procedure.prosecdef,
                    coalesce(procedure.proconfig,'{}'::text[])
                        @> array['search_path=pg_catalog, control'],
                    has_function_privilege('control_api',procedure.oid,'execute'),
                    has_function_privilege('control_tenant_api',procedure.oid,'execute'),
                    not exists(
                        select 1
                          from aclexplode(coalesce(
                              procedure.proacl,
                              acldefault('f',procedure.proowner)
                          )) privilege
                         where privilege.grantee=0
                           and privilege.privilege_type='EXECUTE'
                    )
               from pg_proc procedure
               join pg_namespace namespace on namespace.oid=procedure.pronamespace
              where namespace.nspname='control' and procedure.oid=$1::regprocedure",
        )
        .bind(identity)
        .fetch_one(owner_store.pool())
        .await
        .unwrap();
        assert_eq!(
            metadata,
            (true, true, true, false, true),
            "{identity} must be a fixed-path API-only capability"
        );
    }

    for operation in ["insert", "update", "delete"] {
        let mut tx = owner_store.begin().await.unwrap();
        set_local_role(&mut tx, "control_api").await;
        let denied = match operation {
            "insert" => {
                sqlx::query("insert into control.workshop_recovery_points default values")
                    .execute(&mut *tx)
                    .await
            }
            "update" => {
                sqlx::query("update control.workshop_recovery_points set state=state where false")
                    .execute(&mut *tx)
                    .await
            }
            "delete" => {
                sqlx::query("delete from control.workshop_recovery_points where false")
                    .execute(&mut *tx)
                    .await
            }
            _ => unreachable!(),
        }
        .expect_err("control_api must not retain direct recovery-point mutation authority");
        assert_insufficient_privilege(denied, &format!("control_api recovery-point {operation}"));
        tx.rollback().await.unwrap();
    }

    let visible = {
        let mut tx = owner_store.begin().await.unwrap();
        set_local_role(&mut tx, "control_api").await;
        let visible =
            sqlx::query_scalar::<_, i64>("select count(*) from control.workshop_recovery_points")
                .fetch_one(&mut *tx)
                .await
                .unwrap();
        tx.rollback().await.unwrap();
        visible
    };
    assert!(
        visible >= 0,
        "platform fleet status must retain read access"
    );

    let deletion_database = sqlx::query_scalar::<_, Uuid>(
        "select id from control.odoo_databases
          where workshop_id=$1 and kind='primary' and deleted_at is null",
    )
    .bind(deletion_workshop)
    .fetch_one(owner_store.pool())
    .await
    .unwrap();
    let deletion_recovery = Uuid::new_v4();
    let deletion_operation = Uuid::new_v4();
    sqlx::query(
        "insert into control.operations(
           id,kind,queue,workshop_id,payload,requested_by,correlation_id,idempotency_key
         ) values($1,'tenant.lifecycle','tenant-lifecycle',$2,$3,$4,$5,$6)",
    )
    .bind(deletion_operation)
    .bind(deletion_workshop)
    .bind(serde_json::json!({
        "action": "delete",
        "database_id": deletion_database,
        "recovery_point_id": deletion_recovery,
    }))
    .bind(requested_by)
    .bind(Uuid::new_v4())
    .bind(format!("platform-capability-delete:{deletion_operation}"))
    .execute(owner_store.pool())
    .await
    .unwrap();
    let mut deletion_tx = owner_store.begin().await.unwrap();
    set_local_role(&mut deletion_tx, "control_api").await;
    let inserted = sqlx::query_scalar::<_, Uuid>(
        "select control.insert_platform_deletion_recovery_point($1,$2,$3,$4)",
    )
    .bind(deletion_recovery)
    .bind(deletion_workshop)
    .bind(deletion_database)
    .bind(deletion_operation)
    .fetch_one(&mut *deletion_tx)
    .await
    .unwrap();
    assert_eq!(inserted, deletion_recovery);
    let derived = sqlx::query_as::<_, (Uuid, Vec<String>, String, String)>(
        "select requested_by,component_scope,label,format_version
           from control.workshop_recovery_points where id=$1",
    )
    .bind(deletion_recovery)
    .fetch_one(&mut *deletion_tx)
    .await
    .unwrap();
    assert_eq!(
        derived,
        (
            requested_by,
            vec!["odoo".to_owned()],
            "Final pre-deletion backup".to_owned(),
            "mb-workshop-recovery-v2".to_owned(),
        )
    );
    deletion_tx.rollback().await.unwrap();
    assert!(
        !sqlx::query_scalar::<_, bool>(
            "select exists(select 1 from control.workshop_recovery_points where id=$1)",
        )
        .bind(deletion_recovery)
        .fetch_one(owner_store.pool())
        .await
        .unwrap()
    );

    let (release_database, database_ref) = sqlx::query_as::<_, (Uuid, String)>(
        "select id,database_ref from control.odoo_databases
          where workshop_id=$1 and kind='primary' and deleted_at is null",
    )
    .bind(release_workshop)
    .fetch_one(owner_store.pool())
    .await
    .unwrap();
    let source_release = seed_platform_capability_release(owner_store, "active", 'a').await;
    let target_release = seed_platform_capability_release(owner_store, "prepared", 'd').await;
    sqlx::query(
        "insert into control.tenant_release_adoptions(
           id,workshop_id,database_id,release_id,registry_version,state,target_schema_epoch
         ) values($1,$2,$3,$4,1,'active',1)",
    )
    .bind(Uuid::new_v4())
    .bind(release_workshop)
    .bind(release_database)
    .bind(&source_release)
    .execute(owner_store.pool())
    .await
    .unwrap();
    let release_operation = Uuid::new_v4();
    sqlx::query(
        "insert into control.operations(
           id,kind,queue,payload,requested_by,correlation_id,idempotency_key
         ) values($1,'odoo.release.adopt','release-adoption',$2,$3,$4,$5)",
    )
    .bind(release_operation)
    .bind(serde_json::json!({
        "release_id": target_release,
        "phase": "adopt",
        "confirmation": target_release,
    }))
    .bind(requested_by)
    .bind(Uuid::new_v4())
    .bind(format!("platform-capability-release:{release_operation}"))
    .execute(owner_store.pool())
    .await
    .unwrap();
    let fleet_run = Uuid::new_v4();
    let generation = sqlx::query_scalar::<_, i64>(
        "select coalesce(max(fleet_generation),0)+1 from control.release_fleet_runs",
    )
    .fetch_one(owner_store.pool())
    .await
    .unwrap();
    sqlx::query(
        "insert into control.release_fleet_runs(
           id,release_id,operation_id,fleet_generation,state,tenant_snapshot,canary_workshop_id
         ) values($1,$2,$3,$4,'preparing',$5,$6)",
    )
    .bind(fleet_run)
    .bind(&target_release)
    .bind(release_operation)
    .bind(generation)
    .bind(serde_json::json!([{
        "workshop_id": release_workshop,
        "database_id": release_database,
        "database_ref": database_ref,
        "paperless_enabled": false,
    }]))
    .bind(release_workshop)
    .execute(owner_store.pool())
    .await
    .unwrap();
    let release_recovery = Uuid::new_v4();
    let mut release_tx = owner_store.begin().await.unwrap();
    set_local_role(&mut release_tx, "control_api").await;
    let returned = sqlx::query_as::<_, (Uuid, Option<String>)>(
        "select recovery_id,source_release_id
           from control.insert_platform_release_recovery_point($1,$2,$3,$4,$5,$6)",
    )
    .bind(release_recovery)
    .bind(fleet_run)
    .bind(release_workshop)
    .bind(release_database)
    .bind(release_operation)
    .bind(&target_release)
    .fetch_one(&mut *release_tx)
    .await
    .unwrap();
    assert_eq!(returned, (release_recovery, Some(source_release.clone())));
    let derived = sqlx::query_as::<_, (Uuid, Vec<String>, Option<String>, String)>(
        "select requested_by,component_scope,source_release,label
           from control.workshop_recovery_points where id=$1",
    )
    .bind(release_recovery)
    .fetch_one(&mut *release_tx)
    .await
    .unwrap();
    assert_eq!(
        derived,
        (
            requested_by,
            vec!["odoo".to_owned()],
            Some(source_release),
            format!("Pre-release recovery for {target_release}"),
        )
    );
    release_tx.rollback().await.unwrap();
    assert!(
        !sqlx::query_scalar::<_, bool>(
            "select exists(select 1 from control.workshop_recovery_points where id=$1)",
        )
        .bind(release_recovery)
        .fetch_one(owner_store.pool())
        .await
        .unwrap()
    );

    for call in [
        "select control.insert_platform_deletion_recovery_point($1,$2,$3,$4)",
        "select * from control.insert_platform_release_recovery_point($1,$2,$3,$4,$5,$6)",
    ] {
        let mut tx = owner_store.begin().await.unwrap();
        set_local_role(&mut tx, "control_api").await;
        let random = Uuid::new_v4();
        let mut query = sqlx::query(call)
            .bind(random)
            .bind(Uuid::new_v4())
            .bind(Uuid::new_v4())
            .bind(Uuid::new_v4());
        if call.contains("release_recovery") {
            query = query.bind(Uuid::new_v4()).bind("missing-release");
        }
        let error = query
            .execute(&mut *tx)
            .await
            .expect_err("a capability must reject unmatched durable state");
        let code = error
            .as_database_error()
            .and_then(|database_error| database_error.code());
        assert_ne!(
            code.as_deref(),
            Some("42501"),
            "control_api must reach the bounded capability before its validation fails"
        );
        tx.rollback().await.unwrap();
    }
}

async fn assert_privacy_retention_batch_capability(owner_store: &Store) {
    let identity = "control.run_privacy_retention_batch(uuid,uuid,integer,text,integer)";
    let metadata = sqlx::query_as::<_, (bool, bool, bool, bool, bool, bool)>(
        "select procedure.prosecdef,
                coalesce(procedure.proconfig,'{}'::text[])
                    @> array['search_path=pg_catalog, control'],
                has_function_privilege(
                    'control_privacy_worker',procedure.oid,'EXECUTE'
                ),
                not exists(
                    select 1
                      from aclexplode(coalesce(
                          procedure.proacl,
                          acldefault('f',procedure.proowner)
                      )) privilege
                     where privilege.grantee=0
                       and privilege.privilege_type='EXECUTE'
                ),
                has_function_privilege('control_api',procedure.oid,'EXECUTE'),
                has_table_privilege('control_api','control.retention_runs','INSERT')
           from pg_proc procedure
           join pg_namespace namespace on namespace.oid=procedure.pronamespace
          where namespace.nspname='control' and procedure.oid=$1::regprocedure",
    )
    .bind(identity)
    .fetch_one(owner_store.pool())
    .await
    .unwrap();
    assert!(metadata.0, "retention batches must remain SECURITY DEFINER");
    assert!(metadata.1, "retention batches must pin their search path");
    assert!(
        metadata.2,
        "the privacy worker must execute retention batches"
    );
    assert!(
        metadata.3,
        "PUBLIC retention-batch execution must be revoked"
    );
    assert!(
        !metadata.4,
        "the API must not execute destructive retention batches"
    );
    assert!(metadata.5, "the API must be able to admit retention runs");

    let mut tx = owner_store.begin().await.unwrap();
    sqlx::query("set local role control_privacy_worker")
        .execute(&mut *tx)
        .await
        .unwrap();
    let direct_update = sqlx::query("update control.retention_runs set state=state where false")
        .execute(&mut *tx)
        .await
        .expect_err("the privacy worker must use its fenced retention capability");
    assert_insufficient_privilege(direct_update, "direct retention-run update");
    tx.rollback().await.unwrap();
}

fn assert_insufficient_privilege(error: sqlx::Error, operation: &str) {
    let code = error
        .as_database_error()
        .and_then(|database_error| database_error.code());
    assert_eq!(
        code.as_deref(),
        Some("42501"),
        "{operation} must be denied by PostgreSQL privileges, not by a coincidental constraint: {error}"
    );
}

async fn assert_production_driver_ledger_grants(
    admin_url: &str,
    database: &str,
    owner_store: &Store,
    workshop: Uuid,
) {
    let driver_url = login_database_url(
        admin_url,
        database,
        "control_driver_ledger",
        "driver-ledger-isolation-password",
    );
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&driver_url)
        .await
        .unwrap();
    let key = format!("driver-role:{}", Uuid::new_v4());
    let digest = "4".repeat(64);
    sqlx::query("insert into control.deployment_driver_operations(idempotency_key,workshop_id,action,request_digest) values($1,$2,'lifecycle',$3)")
        .bind(&key).bind(workshop).bind(&digest).execute(&pool).await.unwrap();
    assert_eq!(
        sqlx::query("update control.deployment_driver_operations set safe_error='runtime_outcome_unknown' where workshop_id=$1 and action='lifecycle' and idempotency_key=$2")
            .bind(workshop).bind(&key).execute(&pool).await.unwrap().rows_affected(),
        1
    );
    assert!(
        sqlx::query("update control.deployment_driver_operations set request_digest=request_digest where workshop_id=$1 and action='lifecycle' and idempotency_key=$2")
            .bind(workshop).bind(&key).execute(&pool).await.is_err(),
        "the driver ledger role must not rewrite request identity"
    );
    assert!(
        sqlx::query("delete from control.deployment_driver_operations where workshop_id=$1 and action='lifecycle' and idempotency_key=$2")
            .bind(workshop).bind(&key).execute(&pool).await.is_err(),
        "the driver ledger role must not delete idempotency evidence"
    );
    assert!(
        sqlx::query("insert into control.deployment_driver_operations(idempotency_key,workshop_id,action,request_digest,state) values($1,$2,'lifecycle',$3,'failed')")
            .bind(format!("driver-forged-state:{}",Uuid::new_v4())).bind(workshop).bind(&digest)
            .execute(&pool).await.is_err(),
        "initial state must come only from the database default"
    );

    for (function, arguments) in [
        (
            "admit_release_driver_operation",
            "uuid,integer,text,text,text,uuid,text,uuid,uuid,uuid,integer",
        ),
        (
            "renew_release_driver_lease",
            "uuid,uuid,integer,text,uuid,uuid,uuid,bigint,integer",
        ),
        (
            "finish_release_driver_operation",
            "uuid,uuid,uuid,uuid,bigint,text,jsonb,text",
        ),
        (
            "admit_initial_release_reconciliation",
            "uuid,integer,text,text,text,text,uuid,uuid,integer",
        ),
        (
            "finish_initial_release_reconciliation",
            "uuid,uuid,uuid,text,jsonb",
        ),
    ] {
        let identity = format!("control.{function}({arguments})");
        let metadata = sqlx::query_as::<_, (bool, bool, bool, bool, bool)>(
            "select procedure.prosecdef,
                    coalesce(procedure.proconfig,'{}'::text[])
                        @> array['search_path=pg_catalog, control'],
                    has_function_privilege('control_driver_ledger',procedure.oid,'EXECUTE'),
                    not exists(
                        select 1
                          from aclexplode(coalesce(
                              procedure.proacl,
                              acldefault('f',procedure.proowner)
                          )) privilege
                         where privilege.grantee=0
                           and privilege.privilege_type='EXECUTE'
                    ),
                    has_function_privilege('control_api',procedure.oid,'EXECUTE')
               from pg_proc procedure
               join pg_namespace namespace on namespace.oid=procedure.pronamespace
              where namespace.nspname='control' and procedure.oid=$1::regprocedure",
        )
        .bind(&identity)
        .fetch_one(owner_store.pool())
        .await
        .unwrap();
        assert!(metadata.0, "{identity} must remain SECURITY DEFINER");
        assert!(
            metadata.1,
            "{identity} must pin search_path to pg_catalog, control"
        );
        assert!(
            metadata.2,
            "the production driver identity must execute {identity}"
        );
        assert!(metadata.3, "PUBLIC execute must be revoked from {identity}");
        assert!(
            !metadata.4,
            "an unrelated production identity must not execute {identity}"
        );
    }

    let direct_insert = sqlx::query(
        "insert into control.deployment_driver_resource_leases(resource_key) values('runtime/shared-odoo')",
    )
    .execute(&pool)
    .await
    .expect_err("the driver must not directly insert a shared-runtime lease");
    assert_insufficient_privilege(direct_insert, "direct release-lease insert");
    let direct_update = sqlx::query(
        "update control.deployment_driver_resource_leases set updated_at=now() where resource_key='runtime/shared-odoo'",
    )
    .execute(&pool)
    .await
    .expect_err("the driver must not directly update a shared-runtime lease");
    assert_insufficient_privilege(direct_update, "direct release-lease update");
    let direct_delete = sqlx::query(
        "delete from control.deployment_driver_resource_leases where resource_key='runtime/shared-odoo'",
    )
    .execute(&pool)
    .await
    .expect_err("the driver must not directly delete a shared-runtime lease");
    assert_insufficient_privilege(direct_delete, "direct release-lease delete");
    let direct_reconciliation_read =
        sqlx::query("select id from control.release_driver_reconciliations limit 1")
            .execute(&pool)
            .await
            .expect_err("the driver must use fenced release reconciliation functions");
    assert_insufficient_privilege(
        direct_reconciliation_read,
        "direct release reconciliation read",
    );

    let control_operation = Uuid::new_v4();
    let release_id = format!("role-test-{}", Uuid::new_v4().simple());
    let control_lease_owner = format!("release-role-test-{}", Uuid::new_v4());
    sqlx::query(
        "insert into control.operations(
             id,kind,queue,workshop_id,payload,correlation_id,idempotency_key,
             state,attempt,leased_by,lease_expires_at
         ) values(
             $1,'odoo.release.adopt','release-adoption',null,$2,$3,$4,
             'in_flight',1,$5,now()+interval '10 minutes'
         )",
    )
    .bind(control_operation)
    .bind(serde_json::json!({"phase":"preflight","release_id":&release_id}))
    .bind(Uuid::new_v4())
    .bind(format!("release-driver-role:{control_operation}"))
    .bind(&control_lease_owner)
    .execute(owner_store.pool())
    .await
    .unwrap();
    let idempotency_key = format!("release-driver-role:{}", Uuid::new_v4());
    let target_key = format!("initial/{release_id}");
    let request_digest = "5".repeat(64);
    let instance_owner = Uuid::new_v4();
    let execution_token = Uuid::new_v4();
    let resource_lease_token = Uuid::new_v4();
    let admitted = sqlx::query_as::<
        _,
        (
            String,
            Option<Uuid>,
            Option<i64>,
            Option<serde_json::Value>,
            Option<Vec<Uuid>>,
        ),
    >(
        "select outcome,driver_operation_id,fence_token,stored_response,reserved_workshops
           from control.admit_release_driver_operation($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
    )
    .bind(control_operation)
    .bind(1_i32)
    .bind(&control_lease_owner)
    .bind(&idempotency_key)
    .bind(&target_key)
    .bind(Option::<Uuid>::None)
    .bind(&request_digest)
    .bind(instance_owner)
    .bind(execution_token)
    .bind(resource_lease_token)
    .bind(120_i32)
    .fetch_one(&pool)
    .await
    .expect("the production driver role must invoke the reviewed function");
    // This characterization database already contains workshops, so the
    // initial-release precondition must refuse effects after privilege checks.
    assert_eq!(admitted.0, "fleet_not_empty");
    assert!(admitted.1.is_none());
    assert!(admitted.2.is_some());
    assert!(admitted.3.is_none());
    assert_eq!(admitted.4, Some(Vec::new()));

    let unknown_driver_operation = Uuid::new_v4();
    let renewed: bool =
        sqlx::query_scalar("select control.renew_release_driver_lease($1,$2,$3,$4,$5,$6,$7,$8,$9)")
            .bind(unknown_driver_operation)
            .bind(control_operation)
            .bind(1_i32)
            .bind(&control_lease_owner)
            .bind(instance_owner)
            .bind(execution_token)
            .bind(resource_lease_token)
            .bind(1_i64)
            .bind(120_i32)
            .fetch_one(&pool)
            .await
            .expect("the production driver role must renew through the reviewed function");
    assert!(!renewed, "an unknown driver operation must fail closed");

    let finished: bool = sqlx::query_scalar(
        "select control.finish_release_driver_operation($1,$2,$3,$4,$5,'succeeded',$6,null)",
    )
    .bind(unknown_driver_operation)
    .bind(instance_owner)
    .bind(execution_token)
    .bind(resource_lease_token)
    .bind(1_i64)
    .bind(serde_json::json!({"evidence":{"driver_fence_token":1}}))
    .fetch_one(&pool)
    .await
    .expect("the production driver role must finish through the reviewed function");
    assert!(!finished, "an unknown driver operation must not finish");
    pool.close().await;
}

async fn set_local_role(tx: &mut sqlx::Transaction<'_, sqlx::Postgres>, role: &str) {
    assert!(
        RUNTIME_ROLES.contains(&role),
        "role identifier must be curated"
    );
    sqlx::query(AssertSqlSafe(format!("set local role {role}")))
        .execute(&mut **tx)
        .await
        .unwrap();
    // SQLx migrations deliberately disable row_security on their owner
    // connection. SET LOCAL ROLE does not reset that session setting, whereas
    // a real runtime login starts with row_security=on.
    sqlx::query("set local row_security=on")
        .execute(&mut **tx)
        .await
        .unwrap();
}

async fn set_local_role_and_workshop(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    role: &str,
    workshop: Uuid,
) {
    set_local_role(tx, role).await;
    sqlx::query("select set_config('control.workshop_id',$1,true)")
        .bind(workshop.to_string())
        .execute(&mut **tx)
        .await
        .unwrap();
    let current_user: String = sqlx::query_scalar("select current_user")
        .fetch_one(&mut **tx)
        .await
        .unwrap();
    assert_eq!(current_user, role);
}

async fn can_read_other_workshop(
    pool: &sqlx::PgPool,
    role: &str,
    current_workshop: Uuid,
    other_workshop: Uuid,
) -> bool {
    let mut tx = pool.begin().await.unwrap();
    set_local_role_and_workshop(&mut tx, role, current_workshop).await;
    let result =
        sqlx::query_scalar::<_, bool>("select exists(select 1 from control.workshops where id=$1)")
            .bind(other_workshop)
            .fetch_one(&mut *tx)
            .await;
    tx.rollback().await.unwrap();
    result.unwrap_or(false)
}

async fn can_update_other_workshop(
    pool: &sqlx::PgPool,
    role: &str,
    current_workshop: Uuid,
    other_workshop: Uuid,
) -> bool {
    let mut tx = pool.begin().await.unwrap();
    set_local_role_and_workshop(&mut tx, role, current_workshop).await;
    let result = sqlx::query("update control.workshops set display_name=display_name where id=$1")
        .bind(other_workshop)
        .execute(&mut *tx)
        .await;
    let changed = result
        .map(|done| done.rows_affected() == 1)
        .unwrap_or(false);
    tx.rollback().await.unwrap();
    changed
}

async fn can_read_other_operation(
    pool: &sqlx::PgPool,
    role: &str,
    current_workshop: Uuid,
    other_operation: Uuid,
) -> bool {
    let mut tx = pool.begin().await.unwrap();
    set_local_role_and_workshop(&mut tx, role, current_workshop).await;
    let visible: bool =
        sqlx::query_scalar("select exists(select 1 from control.operations where id=$1)")
            .bind(other_operation)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    tx.rollback().await.unwrap();
    visible
}

async fn can_update_other_operation(
    pool: &sqlx::PgPool,
    role: &str,
    current_workshop: Uuid,
    other_operation: Uuid,
) -> bool {
    let mut tx = pool.begin().await.unwrap();
    set_local_role_and_workshop(&mut tx, role, current_workshop).await;
    // Migration 0002 gives the backup scheduler UPDATE only on this column.
    // Other operation-processing runtime roles have table-level UPDATE.
    let result =
        sqlx::query("update control.operations set idempotency_key=idempotency_key where id=$1")
            .bind(other_operation)
            .execute(&mut *tx)
            .await;
    let changed = result
        .map(|done| done.rows_affected() == 1)
        .unwrap_or(false);
    tx.rollback().await.unwrap();
    changed
}

async fn assert_transaction_local_context_does_not_leak(pool: &sqlx::PgPool, workshop: Uuid) {
    // Hold one physical connection so this proves transaction cleanup rather
    // than merely observing a different member of the pool.
    let mut connection = pool.acquire().await.unwrap();
    let mut tx = connection.begin().await.unwrap();
    sqlx::query("select set_config('control.workshop_id',$1,true)")
        .bind(workshop.to_string())
        .execute(&mut *tx)
        .await
        .unwrap();
    let inside: String = sqlx::query_scalar("select current_setting('control.workshop_id')")
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    assert_eq!(inside, workshop.to_string());
    tx.commit().await.unwrap();

    let after_commit: bool =
        sqlx::query_scalar("select nullif(current_setting('control.workshop_id',true),'') is null")
            .fetch_one(&mut *connection)
            .await
            .unwrap();
    assert!(
        after_commit,
        "transaction-local context leaked after commit"
    );

    let mut tx = connection.begin().await.unwrap();
    sqlx::query("select set_config('control.workshop_id',$1,true)")
        .bind(workshop.to_string())
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("select 1/0")
        .execute(&mut *tx)
        .await
        .expect_err("force an aborted transaction");
    tx.rollback().await.unwrap();
    let after_rollback: bool =
        sqlx::query_scalar("select nullif(current_setting('control.workshop_id',true),'') is null")
            .fetch_one(&mut *connection)
            .await
            .unwrap();
    assert!(
        after_rollback,
        "transaction-local context leaked after rollback"
    );
}

async fn seed_recovery_component(
    store: &Store,
    workshop: Uuid,
    requested_by: Uuid,
    marker: char,
) -> (Uuid, Uuid) {
    let database = sqlx::query_scalar(
        "select id from control.odoo_databases
          where workshop_id=$1 and kind='primary' and deleted_at is null",
    )
    .bind(workshop)
    .fetch_optional(store.pool())
    .await
    .unwrap()
    .unwrap_or_else(Uuid::new_v4);
    let recovery = Uuid::new_v4();
    sqlx::query(
        "insert into control.odoo_databases(
           id,workshop_id,kind,database_ref,public_hostname,label,state,routable
         ) values($1,$2,'primary',$3,$4,'RLS component fixture','ready',true)
         on conflict(id) do nothing",
    )
    .bind(database)
    .bind(workshop)
    .bind(format!("mb_{}", database.simple()))
    .bind(format!("{}.example.test", database.simple()))
    .execute(store.pool())
    .await
    .unwrap();
    sqlx::query(
        "insert into control.workshop_recovery_points(
           id,workshop_id,database_id,kind,label,requested_by,state
         ) values($1,$2,$3,'backup','RLS component fixture',$4,'creating')",
    )
    .bind(recovery)
    .bind(workshop)
    .bind(database)
    .bind(requested_by)
    .execute(store.pool())
    .await
    .unwrap();
    sqlx::query(
        "insert into control.workshop_recovery_components(
           recovery_point_id,workshop_id,component,object_key,size_bytes,digest,state,verified_at
         ) values($1,$2,'manifest',$3,1,$4,'verified',now())",
    )
    .bind(recovery)
    .bind(workshop)
    .bind(format!("{marker}/manifest.json"))
    .bind(marker.to_string().repeat(64))
    .execute(store.pool())
    .await
    .unwrap();
    (database, recovery)
}

async fn assert_recovery_component_rls(
    admin_url: &str,
    database: &str,
    owner_store: &Store,
    first_workshop: Uuid,
    second_workshop: Uuid,
    first_recovery: Uuid,
    second_recovery: Uuid,
) {
    let catalog = sqlx::query_as::<_, (bool, bool, bool, bool, bool, i64)>(
        "select class.relrowsecurity,class.relforcerowsecurity,
                not has_table_privilege(
                    'control_api','control.workshop_recovery_components','SELECT,INSERT,UPDATE,DELETE'
                ),
                has_function_privilege(
                    'control_lifecycle_worker','control.current_workshop_id()','EXECUTE'
                ),
                has_function_privilege(
                    'control_driver_ledger','control.current_workshop_id()','EXECUTE'
                ),
                (select count(*) from pg_policies
                  where schemaname='control'
                    and tablename='workshop_recovery_components'
                    and policyname in (
                        'workshop_recovery_components_lifecycle_tenant',
                        'workshop_recovery_components_driver_tenant'
                    ))
           from pg_class class
           join pg_namespace namespace on namespace.oid=class.relnamespace
          where namespace.nspname='control'
            and class.relname='workshop_recovery_components'",
    )
    .fetch_one(owner_store.pool())
    .await
    .unwrap();
    assert_eq!(catalog, (true, true, true, true, true, 2));

    for role in ["control_lifecycle_worker", "control_driver_ledger"] {
        let mut tx = owner_store.begin().await.unwrap();
        set_local_role_and_workshop(&mut tx, role, first_workshop).await;
        let own_visible: bool = sqlx::query_scalar(
            "select exists(
                select 1 from control.workshop_recovery_components
                 where recovery_point_id=$1
             )",
        )
        .bind(first_recovery)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
        let other_visible: bool = sqlx::query_scalar(
            "select exists(
                select 1 from control.workshop_recovery_components
                 where recovery_point_id=$1
             )",
        )
        .bind(second_recovery)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
        assert!(own_visible, "{role} lost its scoped component read");
        assert!(!other_visible, "{role} read another workshop's component");

        let cross_insert = sqlx::query(
            "insert into control.workshop_recovery_components(
               recovery_point_id,workshop_id,component,object_key,size_bytes,digest,state,verified_at
             ) values($1,$2,'commit-marker','cross/commit',1,$3,'verified',now())",
        )
        .bind(second_recovery)
        .bind(second_workshop)
        .bind("c".repeat(64))
        .execute(&mut *tx)
        .await;
        assert!(
            cross_insert.is_err(),
            "{role} inserted across the RLS boundary"
        );
        tx.rollback().await.unwrap();

        let mut tx = owner_store.begin().await.unwrap();
        set_local_role_and_workshop(&mut tx, role, first_workshop).await;
        let cross_update = sqlx::query(
            "update control.workshop_recovery_components
                set object_key=object_key
              where recovery_point_id=$1 and workshop_id=$2",
        )
        .bind(second_recovery)
        .bind(second_workshop)
        .execute(&mut *tx)
        .await;
        if role == "control_lifecycle_worker" {
            assert_eq!(
                cross_update.unwrap().rows_affected(),
                0,
                "the lifecycle role updated across the RLS boundary"
            );
        } else {
            let error = cross_update.expect_err("driver UPDATE is outside its table grant");
            assert_insufficient_privilege(error, "driver cross-workshop component update");
        }
        tx.rollback().await.unwrap();

        let mut tx = owner_store.begin().await.unwrap();
        set_local_role_and_workshop(&mut tx, role, first_workshop).await;
        let cross_delete = sqlx::query(
            "delete from control.workshop_recovery_components
              where recovery_point_id=$1 and workshop_id=$2",
        )
        .bind(second_recovery)
        .bind(second_workshop)
        .execute(&mut *tx)
        .await
        .unwrap()
        .rows_affected();
        assert_eq!(cross_delete, 0, "{role} deleted across the RLS boundary");
        tx.rollback().await.unwrap();
    }

    for role in RUNTIME_ROLES
        .iter()
        .copied()
        .filter(|role| !matches!(*role, "control_lifecycle_worker" | "control_driver_ledger"))
    {
        for operation in ["select", "insert", "update", "delete"] {
            let mut tx = owner_store.begin().await.unwrap();
            set_local_role_and_workshop(&mut tx, role, first_workshop).await;
            let result = match operation {
                "select" => sqlx::query(
                    "select recovery_point_id from control.workshop_recovery_components limit 1",
                )
                .execute(&mut *tx)
                .await,
                "insert" => sqlx::query(
                    "insert into control.workshop_recovery_components(
                       recovery_point_id,workshop_id,component,object_key,size_bytes,digest,state,verified_at
                     ) values($1,$2,'commit-marker','denied/commit',1,$3,'verified',now())",
                )
                .bind(first_recovery)
                .bind(first_workshop)
                .bind("d".repeat(64))
                .execute(&mut *tx)
                .await,
                "update" => sqlx::query(
                    "update control.workshop_recovery_components
                        set object_key=object_key where recovery_point_id=$1",
                )
                .bind(first_recovery)
                .execute(&mut *tx)
                .await,
                "delete" => sqlx::query(
                    "delete from control.workshop_recovery_components
                      where recovery_point_id=$1",
                )
                .bind(first_recovery)
                .execute(&mut *tx)
                .await,
                _ => unreachable!(),
            };
            assert!(
                result.is_err(),
                "{role} unexpectedly gained {operation} on recovery components"
            );
            tx.rollback().await.unwrap();
        }
    }

    let mut lifecycle = owner_store.begin().await.unwrap();
    set_local_role_and_workshop(&mut lifecycle, "control_lifecycle_worker", first_workshop).await;
    assert_eq!(
        sqlx::query(
            "update control.workshop_recovery_components
                set object_key=object_key
              where recovery_point_id=$1 and workshop_id=$2",
        )
        .bind(first_recovery)
        .bind(first_workshop)
        .execute(&mut *lifecycle)
        .await
        .unwrap()
        .rows_affected(),
        1
    );
    lifecycle.rollback().await.unwrap();

    let mut driver = owner_store.begin().await.unwrap();
    set_local_role_and_workshop(&mut driver, "control_driver_ledger", first_workshop).await;
    let forbidden_update = sqlx::query(
        "update control.workshop_recovery_components
            set object_key=object_key
          where recovery_point_id=$1 and workshop_id=$2",
    )
    .bind(first_recovery)
    .bind(first_workshop)
    .execute(&mut *driver)
    .await
    .expect_err("the driver component capability intentionally excludes UPDATE");
    assert_insufficient_privilege(forbidden_update, "driver component update");
    driver.rollback().await.unwrap();

    for configured in [None, Some(""), Some("not-a-uuid")] {
        let mut tx = owner_store.begin().await.unwrap();
        sqlx::query("set local role control_lifecycle_worker")
            .execute(&mut *tx)
            .await
            .unwrap();
        sqlx::query("set local row_security=on")
            .execute(&mut *tx)
            .await
            .unwrap();
        if let Some(configured) = configured {
            sqlx::query("select set_config('control.workshop_id',$1,true)")
                .bind(configured)
                .execute(&mut *tx)
                .await
                .unwrap();
        }
        let visible: i64 =
            sqlx::query_scalar("select count(*) from control.workshop_recovery_components")
                .fetch_one(&mut *tx)
                .await
                .unwrap();
        assert_eq!(visible, 0, "invalid component context must fail closed");
        tx.rollback().await.unwrap();
    }

    for (role, password) in [
        ("control_lifecycle_worker", "lifecycle-isolation-password"),
        ("control_driver_ledger", "driver-ledger-isolation-password"),
    ] {
        let url = login_database_url(admin_url, database, role, password);
        let tenant_store = TenantStore::connect(&url).await.unwrap();
        let mut first = tenant_store.begin(first_workshop).await.unwrap();
        let visible: i64 =
            sqlx::query_scalar("select count(*) from control.workshop_recovery_components")
                .fetch_one(&mut *first)
                .await
                .unwrap();
        assert_eq!(visible, 1, "{role} must see exactly its scoped component");
        first.commit().await.unwrap();
        let mut second = tenant_store.begin(second_workshop).await.unwrap();
        let visible: i64 =
            sqlx::query_scalar("select count(*) from control.workshop_recovery_components")
                .fetch_one(&mut *second)
                .await
                .unwrap();
        assert_eq!(visible, 1, "{role} must switch cleanly to the next scope");
        second.commit().await.unwrap();
    }
}

async fn assert_ownership_transfer_rls(
    pool: &sqlx::PgPool,
    first_workshop: Uuid,
    second_workshop: Uuid,
    first_transfer: Uuid,
    second_transfer: Uuid,
    from_user: Uuid,
    to_user: Uuid,
) {
    let mut tx = pool.begin().await.unwrap();
    set_local_role_and_workshop(&mut tx, "control_tenant_api", first_workshop).await;
    let own_visible: bool =
        sqlx::query_scalar("select exists(select 1 from control.ownership_transfers where id=$1)")
            .bind(first_transfer)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    let other_visible: bool =
        sqlx::query_scalar("select exists(select 1 from control.ownership_transfers where id=$1)")
            .bind(second_transfer)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    assert!(own_visible);
    assert!(!other_visible, "tenant SELECT crossed the RLS boundary");

    let updated =
        sqlx::query("update control.ownership_transfers set expires_at=expires_at where id=$1")
            .bind(second_transfer)
            .execute(&mut *tx)
            .await
            .unwrap()
            .rows_affected();
    assert_eq!(updated, 0, "tenant UPDATE crossed the RLS boundary");

    let cross_insert = sqlx::query(
        "insert into control.ownership_transfers(
           id,workshop_id,from_user_id,to_user_id,idempotency_key,expires_at
         ) values($1,$2,$3,$4,$5,now()+interval '1 day')",
    )
    .bind(Uuid::new_v4())
    .bind(second_workshop)
    .bind(from_user)
    .bind(to_user)
    .bind(format!("tenant-isolation-cross-insert-{}", Uuid::new_v4()))
    .execute(&mut *tx)
    .await;
    assert!(
        cross_insert.is_err(),
        "tenant INSERT crossed the RLS boundary"
    );
    tx.rollback().await.unwrap();

    // DELETE is intentionally absent from the tenant API table grant. That is
    // a stronger operation-level denial than relying on a row policy.
    let mut tx = pool.begin().await.unwrap();
    set_local_role_and_workshop(&mut tx, "control_tenant_api", first_workshop).await;
    assert!(
        sqlx::query("delete from control.ownership_transfers where id=$1")
            .bind(second_transfer)
            .execute(&mut *tx)
            .await
            .is_err(),
        "tenant DELETE must remain outside the granted operation surface"
    );
    tx.rollback().await.unwrap();

    for configured in [None, Some(""), Some("not-a-uuid")] {
        let mut tx = pool.begin().await.unwrap();
        sqlx::query("set local role control_tenant_api")
            .execute(&mut *tx)
            .await
            .unwrap();
        sqlx::query("set local row_security=on")
            .execute(&mut *tx)
            .await
            .unwrap();
        if let Some(configured) = configured {
            sqlx::query("select set_config('control.workshop_id',$1,true)")
                .bind(configured)
                .execute(&mut *tx)
                .await
                .unwrap();
        }
        let visible: i64 = sqlx::query_scalar("select count(*) from control.ownership_transfers")
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        assert_eq!(visible, 0, "missing or malformed context must fail closed");
        tx.rollback().await.unwrap();
    }

    let tenant_is_platform_member: bool =
        sqlx::query_scalar("select pg_has_role('control_tenant_api','control_api','member')")
            .fetch_one(pool)
            .await
            .unwrap();
    assert!(!tenant_is_platform_member);
}

async fn assert_ownership_transfer_role_matrix(
    pool: &sqlx::PgPool,
    first_workshop: Uuid,
    second_workshop: Uuid,
    second_transfer: Uuid,
    from_user: Uuid,
    to_user: Uuid,
) {
    let mut platform = pool.begin().await.unwrap();
    set_local_role_and_workshop(&mut platform, "control_api", first_workshop).await;
    let cross_visible: bool =
        sqlx::query_scalar("select exists(select 1 from control.ownership_transfers where id=$1)")
            .bind(second_transfer)
            .fetch_one(&mut *platform)
            .await
            .unwrap();
    assert!(
        cross_visible,
        "platform discovery policy must remain explicit"
    );
    assert_eq!(
        sqlx::query("update control.ownership_transfers set expires_at=expires_at where id=$1")
            .bind(second_transfer)
            .execute(&mut *platform)
            .await
            .unwrap()
            .rows_affected(),
        1
    );
    sqlx::query(
        "insert into control.ownership_transfers(
           id,workshop_id,from_user_id,to_user_id,idempotency_key,expires_at
         ) values($1,$2,$3,$4,$5,now()+interval '1 day')",
    )
    .bind(Uuid::new_v4())
    .bind(second_workshop)
    .bind(from_user)
    .bind(to_user)
    .bind(format!("platform-matrix:{}", Uuid::new_v4()))
    .execute(&mut *platform)
    .await
    .unwrap();
    assert_eq!(
        sqlx::query("delete from control.ownership_transfers where id=$1")
            .bind(second_transfer)
            .execute(&mut *platform)
            .await
            .unwrap()
            .rows_affected(),
        1
    );
    platform.rollback().await.unwrap();

    for role in RUNTIME_ROLES
        .iter()
        .copied()
        .filter(|role| !matches!(*role, "control_api" | "control_tenant_api"))
    {
        for operation in ["select", "insert", "update", "delete"] {
            let mut tx = pool.begin().await.unwrap();
            set_local_role_and_workshop(&mut tx, role, first_workshop).await;
            let result =
                match operation {
                    "select" => {
                        sqlx::query("select id from control.ownership_transfers limit 1")
                            .execute(&mut *tx)
                            .await
                    }
                    "insert" => {
                        sqlx::query(
                            "insert into control.ownership_transfers(
                       id,workshop_id,from_user_id,to_user_id,idempotency_key,expires_at
                     ) values($1,$2,$3,$4,$5,now()+interval '1 day')",
                        )
                        .bind(Uuid::new_v4())
                        .bind(first_workshop)
                        .bind(from_user)
                        .bind(to_user)
                        .bind(format!("denied-matrix:{role}:{}", Uuid::new_v4()))
                        .execute(&mut *tx)
                        .await
                    }
                    "update" => sqlx::query(
                        "update control.ownership_transfers set expires_at=expires_at where id=$1",
                    )
                    .bind(second_transfer)
                    .execute(&mut *tx)
                    .await,
                    "delete" => {
                        sqlx::query("delete from control.ownership_transfers where id=$1")
                            .bind(second_transfer)
                            .execute(&mut *tx)
                            .await
                    }
                    _ => unreachable!(),
                };
            assert!(
                result.is_err(),
                "{role} unexpectedly gained {operation} on ownership_transfers"
            );
            tx.rollback().await.unwrap();
        }
    }
}

#[tokio::test]
#[ignore = "requires a disposable PostgreSQL 17 CONTROL_TEST_ADMIN_URL with CREATEDB and CREATEROLE"]
async fn runtime_role_cross_tenant_surface_is_characterized() {
    let admin_url = std::env::var("CONTROL_TEST_ADMIN_URL").expect("CONTROL_TEST_ADMIN_URL");
    let database = format!("control_tenant_spike_{}", Uuid::new_v4().simple());
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&admin_url)
        .await
        .expect("connect disposable PostgreSQL administrator");
    create_runtime_roles(&admin).await;
    sqlx::query(AssertSqlSafe(format!("create database \"{database}\"")))
        .execute(&admin)
        .await
        .unwrap();

    let store = Store::connect(&database_url(&admin_url, &database))
        .await
        .unwrap();
    store.migrate().await.unwrap();

    let role_attributes = sqlx::query_as::<_, (String, bool, bool)>(
        "select rolname,rolsuper,rolbypassrls from pg_roles where rolname=any($1) order by rolname",
    )
    .bind(RUNTIME_ROLES)
    .fetch_all(store.pool())
    .await
    .unwrap();
    assert_eq!(role_attributes.len(), RUNTIME_ROLES.len());
    assert!(
        role_attributes
            .iter()
            .all(|(_, superuser, bypass_rls)| !superuser && !bypass_rls)
    );

    let protected_tables = sqlx::query_as::<_, (String, bool, bool)>(
        "select c.relname::text,c.relrowsecurity,c.relforcerowsecurity
         from pg_class c join pg_namespace n on n.oid=c.relnamespace
         where n.nspname='control' and c.relkind='r' and (c.relrowsecurity or c.relforcerowsecurity)
         order by c.relname",
    )
    .fetch_all(store.pool())
    .await
    .unwrap();
    assert_eq!(
        protected_tables,
        vec![
            ("email_delivery_events".to_owned(), true, true),
            ("email_suppressions".to_owned(), true, true),
            ("invitations".to_owned(), true, true),
            ("memberships".to_owned(), true, true),
            ("outbox".to_owned(), true, true),
            ("ownership_transfers".to_owned(), true, true),
            ("webshop_domains".to_owned(), true, true),
            ("webshop_email_domains".to_owned(), true, true),
            ("workshop_recovery_components".to_owned(), true, true),
            ("workshop_recovery_points".to_owned(), true, true),
            ("workshop_recovery_rehearsals".to_owned(), true, true),
        ],
        "the characterization must name every protected table"
    );

    let first = Uuid::new_v4();
    let second = Uuid::new_v4();
    for (id, label) in [(first, "first"), (second, "second")] {
        sqlx::query(
            "insert into control.workshops(id,slug,display_name,time_zone) values($1,$2,$3,'Europe/Paris')",
        )
        .bind(id)
        .bind(format!("tenant-spike-{}", id.simple()))
        .bind(label)
        .execute(store.pool())
        .await
        .unwrap();
    }
    assert_transaction_local_context_does_not_leak(store.pool(), first).await;
    let from_user = Uuid::new_v4();
    let to_user = Uuid::new_v4();
    for (id, email) in [
        (
            from_user,
            format!("from-{}@example.test", from_user.simple()),
        ),
        (to_user, format!("to-{}@example.test", to_user.simple())),
    ] {
        sqlx::query("insert into control.users(id,email) values($1,$2)")
            .bind(id)
            .bind(email)
            .execute(store.pool())
            .await
            .unwrap();
    }
    for workshop in [first, second] {
        sqlx::query(
            "insert into control.memberships(workshop_id,user_id,role)
             values($1,$2,'owner')",
        )
        .bind(workshop)
        .bind(from_user)
        .execute(store.pool())
        .await
        .unwrap();
    }
    assert_invitation_rls(&store, (first, second), from_user).await;
    assert_outbox_rls(&store, (first, second)).await;
    assert_email_delivery_evidence_rls(&store, (first, second), from_user).await;
    assert_membership_rls(&store, (first, second), from_user).await;
    assert_webshop_domain_claim_compatibility(
        &admin_url, &database, &store, first, second, from_user,
    )
    .await;
    assert_production_webshop_domain_admission(
        &admin_url, &database, &store, first, second, from_user,
    )
    .await;
    let first_transfer = Uuid::new_v4();
    let second_transfer = Uuid::new_v4();
    for (id, workshop) in [(first_transfer, first), (second_transfer, second)] {
        sqlx::query(
            "insert into control.ownership_transfers(
               id,workshop_id,from_user_id,to_user_id,idempotency_key,expires_at
             ) values($1,$2,$3,$4,$5,now()+interval '1 day')",
        )
        .bind(id)
        .bind(workshop)
        .bind(from_user)
        .bind(to_user)
        .bind(format!("tenant-isolation:{id}"))
        .execute(store.pool())
        .await
        .unwrap();
    }
    assert_ownership_transfer_rls(
        store.pool(),
        first,
        second,
        first_transfer,
        second_transfer,
        from_user,
        to_user,
    )
    .await;
    assert_ownership_transfer_role_matrix(
        store.pool(),
        first,
        second,
        second_transfer,
        from_user,
        to_user,
    )
    .await;
    assert_production_tenant_pool(&admin_url, &database, first, second).await;
    assert_production_worker_execution_scopes(&admin_url, &database, &store, first).await;
    assert_production_lifecycle_execution_scope(&admin_url, &database, &store, first).await;
    assert_production_backup_scheduler_grants(
        &admin_url, &database, &store, first, second, from_user,
    )
    .await;
    assert_recovery_point_stale_worker_grants_removed(&store, first).await;
    assert_platform_recovery_point_capabilities(&store, first, second, from_user).await;
    assert_privacy_retention_batch_capability(&store).await;
    let (_, first_recovery) = seed_recovery_component(&store, first, from_user, 'a').await;
    let (_, second_recovery) = seed_recovery_component(&store, second, from_user, 'b').await;
    assert_recovery_point_rls(
        &admin_url,
        &database,
        &store,
        (first, second),
        (first_recovery, second_recovery),
        from_user,
    )
    .await;
    assert_recovery_component_rls(
        &admin_url,
        &database,
        &store,
        first,
        second,
        first_recovery,
        second_recovery,
    )
    .await;
    assert_production_driver_ledger_grants(&admin_url, &database, &store, first).await;
    let second_operation = Uuid::new_v4();
    sqlx::query(
        "insert into control.operations(id,kind,queue,workshop_id,payload,correlation_id,idempotency_key)
         values($1,'tenant.reconcile','reconciliation',$2,'{}',$3,$4)",
    )
    .bind(second_operation)
    .bind(second)
    .bind(Uuid::new_v4())
    .bind(format!("tenant-spike:{second_operation}"))
    .execute(store.pool())
    .await
    .unwrap();

    for expected in CURRENT_ROLE_SURFACE {
        assert_eq!(
            can_read_other_workshop(store.pool(), expected.role, first, second).await,
            expected.reads_workshops,
            "unexpected workshop read surface for {}",
            expected.role
        );
        assert_eq!(
            can_update_other_workshop(store.pool(), expected.role, first, second).await,
            expected.updates_workshops,
            "unexpected workshop update surface for {}",
            expected.role
        );
        assert_eq!(
            can_read_other_operation(store.pool(), expected.role, first, second_operation).await,
            expected.reads_operations,
            "unexpected operation read surface for {}",
            expected.role
        );
        assert_eq!(
            can_update_other_operation(store.pool(), expected.role, first, second_operation).await,
            expected.updates_operations,
            "unexpected operation update surface for {}",
            expected.role
        );
    }

    store.pool().close().await;
    sqlx::query(AssertSqlSafe(format!(
        "drop database \"{database}\" with (force)"
    )))
    .execute(&admin)
    .await
    .unwrap();
}
