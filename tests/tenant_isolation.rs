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
            "ownership_transfers" | "workshop_recovery_components" | "workshop_recovery_rehearsals"
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
        assert!(!grants.is_empty(), "{table_name} must inventory its grants");
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
fn webshop_domain_claim_preparation_has_a_stable_scoped_boundary() {
    let migration = include_str!("../migrations/0021_webshop_domain_claim_compatibility.sql");
    assert!(migration.contains("create function control.claim_webshop_domain("));
    assert!(migration.contains("language plpgsql security definer"));
    assert!(migration.contains("set search_path = pg_catalog, control"));
    assert!(migration.contains("control.current_workshop_id() is distinct from p_workshop_id"));
    assert!(migration.contains("membership.role in ('owner', 'studio_manager')"));
    assert!(migration.contains("v_existing.state <> 'disconnected'"));
    assert!(migration.contains("control.webshop_domain_provider_deletion_attempts"));
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
    let mut second = tenant_store.begin(second_workshop).await.unwrap();
    let reclaimed = claim_webshop_domain(
        &mut second,
        Uuid::new_v4(),
        second_workshop,
        &hostname,
        &verification_name,
        manager,
    )
    .await
    .unwrap();
    assert_eq!(reclaimed.0, "reclaimed");
    assert_eq!(reclaimed.1, Some(domain));
    second.commit().await.unwrap();
    let owner: Uuid =
        sqlx::query_scalar("select workshop_id from control.webshop_domains where id=$1")
            .bind(domain)
            .fetch_one(owner_store.pool())
            .await
            .unwrap();
    assert_eq!(owner, second_workshop);

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

async fn set_local_role_and_workshop(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    role: &str,
    workshop: Uuid,
) {
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
            ("ownership_transfers".to_owned(), true, true),
            ("workshop_recovery_components".to_owned(), true, true),
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
    assert_privacy_retention_batch_capability(&store).await;
    let (_, first_recovery) = seed_recovery_component(&store, first, from_user, 'a').await;
    let (_, second_recovery) = seed_recovery_component(&store, second, from_user, 'b').await;
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
