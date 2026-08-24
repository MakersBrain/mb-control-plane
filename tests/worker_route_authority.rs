fn production(source: &'static str) -> &'static str {
    source
        .split("\n#[cfg(test)]\nmod tests")
        .next()
        .unwrap_or(source)
}

fn section<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    source
        .split(start)
        .nth(1)
        .unwrap_or_else(|| panic!("missing source marker {start:?}"))
        .split(end)
        .next()
        .unwrap_or_else(|| panic!("missing source marker {end:?}"))
}

fn startup_route_root_accesses_are_safe(source: &str) -> bool {
    let lines = source.lines().collect::<Vec<_>>();
    lines.iter().enumerate().all(|(index, line)| {
        if !line.contains("config.route_root") {
            return true;
        }
        let context = lines[index.saturating_sub(2)..=index].join("\n");
        context.contains("selected_route_root(")
            || context.contains("startup_generation_fs::")
            || context.contains("StartupGenerationDirectory::create(")
            || context.contains("SharedOdooHostGuard::acquire(")
            || context.contains("reconcile_interrupted_startup_publications(")
    })
}

#[test]
fn generic_driver_actions_have_no_physical_route_writer() {
    let driver = production(include_str!("../src/docker_driver.rs"));
    let gateway = production(include_str!("../src/docker_driver/gateway.rs"));

    let provision = section(
        driver,
        "async fn provision(",
        "async fn apply_route_projection(",
    );
    assert!(!provision.contains("write_routes("));
    assert!(!provision.contains("apply_fenced_routes("));
    assert!(!provision.contains("replace_route_config("));

    let restriction = section(
        gateway,
        "pub(super) async fn restrict_capability(",
        "#[cfg(test)]",
    );
    assert!(!restriction.contains("write_gateway_file("));
    assert!(!restriction.contains("replace_route_config("));
    assert!(!restriction.contains("reload_gateway_runtime("));

    assert!(driver.contains("\"route-project\" => {"));
    assert_eq!(
        driver.matches("apply_route_projection(").count(),
        2,
        "only the function definition and dedicated route-project dispatch may apply a route"
    );
}

#[test]
fn shared_worker_materializer_owns_modes_and_commits_before_route_io() {
    let worker = production(include_str!("../src/worker.rs"));
    let routes = production(include_str!("../src/workers/routes.rs"));
    assert_eq!(
        routes
            .matches("materialize_workshop_route_projection")
            .count(),
        1,
        "provisioning and module changes must share one projection materializer"
    );
    assert!(routes.contains("when module.state in ('installing','enabled') then 'read_write'"));
    assert!(routes.contains("when module.state in ('restricting','restricted') then 'read_only'"));
    assert!(routes.contains("\"route-project\""));

    let mut remaining = worker;
    let mut producers = 0;
    while let Some(materialized) = remaining.find("crate::workers::routes::materialize(") {
        let after_materialize = &remaining[materialized..];
        let commit = after_materialize
            .find(".commit()")
            .expect("the source transaction must commit explicitly");
        let route_io = after_materialize
            .find("crate::workers::routes::apply(")
            .expect("materialized projections must use the dedicated driver action");
        assert!(
            commit < route_io,
            "no worker transaction may span deployment-driver route I/O"
        );
        producers += 1;
        remaining = &after_materialize["crate::workers::routes::materialize(".len()..];
    }
    assert!(
        producers >= 3,
        "provision, enable, and restrict must project routes"
    );
}

#[test]
fn durable_route_evidence_precedes_producer_final_state() {
    let worker = production(include_str!("../src/worker.rs"));
    let routes = production(include_str!("../src/workers/routes.rs"));
    let confirmation = section(
        routes,
        "pub(crate) fn confirm_application(",
        "pub(crate) async fn apply(",
    );
    for evidence_field in [
        "route_evidence",
        "workshop_id",
        "route_generation",
        "projection_digest",
    ] {
        assert!(
            confirmation.contains(evidence_field),
            "route success must validate {evidence_field}"
        );
    }
    assert!(confirmation.contains("applied"));
    assert!(confirmation.contains("replayed"));
    let apply = section(routes, "pub(crate) async fn apply(", "#[cfg(test)]");
    assert!(
        apply.find("driver_request_with_key(").unwrap()
            < apply.find("confirm_application(").unwrap()
    );

    let provision = section(
        worker,
        "pub(crate) async fn driver(",
        "async fn driver_request(",
    );
    assert!(
        provision.find("crate::workers::routes::apply(").unwrap()
            < provision
                .find("update control.workshops set status='trial'")
                .unwrap()
    );

    let enable = section(
        worker,
        "async fn enable_module(",
        "async fn admit_capability_restriction(",
    );
    assert!(
        enable.find("enable_paperless(").unwrap()
            < enable
                .find("update control.workshop_modules set state='enabled'")
                .unwrap()
    );
    let enable_paperless = section(
        worker,
        "async fn enable_paperless(",
        "pub(crate) async fn service(",
    );
    assert!(enable_paperless.contains("crate::workers::routes::apply("));

    let restrict = section(
        worker,
        "async fn restrict_module(",
        "async fn enable_paperless(",
    );
    assert!(
        restrict.find("crate::workers::routes::apply(").unwrap()
            < restrict
                .find("update control.workshop_modules set state='restricted'")
                .unwrap()
    );
}

#[test]
fn lifecycle_delete_applies_an_exact_absent_projection_before_driver_effects() {
    let lifecycle = production(include_str!("../src/workers/lifecycle.rs"));
    let routes = production(include_str!("../src/workers/routes.rs"));
    let driver = production(include_str!("../src/docker_driver.rs"));
    let gateway = production(include_str!("../src/docker_driver/gateway.rs"));

    assert!(routes.contains("materialize_workshop_route_tombstone"));
    assert!(routes.contains("\"route_disposition\".into(), Value::String(\"absent\".into())"));
    let run = section(lifecycle, "pub(crate) async fn run(", "async fn prepare(");
    let tombstone = run.find("materialize_tombstone(").unwrap();
    let commit = run[tombstone..].find(".commit()").unwrap() + tombstone;
    let apply = run.find("super::routes::apply(").unwrap();
    let lifecycle_io = run.find("\"lifecycle\",").unwrap();
    assert!(tombstone < commit && commit < apply && apply < lifecycle_io);

    let contract = section(
        driver,
        "fn route_projection_contract(",
        "fn release_control_operation(",
    );
    assert!(contract.contains("route_disposition"));
    assert!(contract.contains("object.remove(\"route_disposition\")"));
    let application = section(driver, "async fn apply_route_projection(", "fn tenant_key(");
    assert!(application.contains("apply_fenced_route_absence("));
    assert!(application.contains("\"disposition\":lease.disposition"));

    let present = section(
        gateway,
        "pub(super) async fn apply_fenced_routes(",
        "pub(super) async fn apply_fenced_route_absence(",
    );
    let absent = section(
        gateway,
        "pub(super) async fn apply_fenced_route_absence(",
        "pub(super) async fn reload_gateway_runtime(",
    );
    assert_eq!(present.matches("renew_route_application(").count(), 3);
    assert_eq!(absent.matches("renew_route_application(").count(), 3);
    assert!(absent.find("remove_file(").unwrap() < absent.find("reload_gateway_runtime(").unwrap());
}

#[test]
fn recovery_maintenance_is_worker_orchestrated_and_never_restores_backup_bytes() {
    let worker = production(include_str!("../src/workers/lifecycle.rs"));
    let recovery = production(include_str!("../src/docker_driver/recovery.rs"));
    let lifecycle = section(
        recovery,
        "pub(super) async fn lifecycle(",
        "pub(super) async fn apply_restored_erasure(",
    );
    assert!(!lifecycle.contains("enter_workshop_maintenance("));
    assert!(!lifecycle.contains("leave_workshop_maintenance("));
    assert!(worker.contains("\"route-maintenance-enter\""));
    assert!(worker.contains("\"route-maintenance-exit\""));
    let run = section(worker, "pub(crate) async fn run(", "async fn prepare(");
    assert!(
        run.find("finalize(").unwrap() < run.rfind("exit_maintenance(").unwrap(),
        "maintenance exit must follow restore finalization"
    );
    let finalize = section(
        worker,
        "async fn finalize(",
        "async fn replay_restored_erasures(",
    );
    assert!(finalize.contains("replay_restored_erasures("));

    let exit = section(
        recovery,
        "pub(super) async fn apply_recovery_maintenance_exit(",
        "pub(super) async fn leave_workshop_maintenance(",
    );
    assert!(exit.contains("route_projection::RouteProjection::parse_optional("));
    assert!(exit.contains("projection.render("));
    assert!(!exit.contains("route_config_for_upstream("));
    assert!(!exit.contains("recovery.bak"));
    assert!(!exit.contains("std::fs::read("));
}

#[test]
fn startup_routes_are_rebuilt_only_under_durable_projection_authority() {
    let driver = production(include_str!("../src/docker_driver.rs"));
    let startup = production(include_str!("../src/docker_driver/startup.rs"));
    let app = section(driver, "pub async fn build_application(", "async fn ready(");

    assert!(
        !app.contains("install_fail_closed_routes("),
        "startup must connect to the ledger before deleting a route"
    );
    for protocol_step in [
        "admit_startup_route_rebuild",
        "read_startup_route_rebuild_batch",
        "initialize_startup_route_projection",
        "read_startup_route_projection_source",
        "begin_startup_route_rebuild",
        "renew_startup_route_rebuild",
        "assert_startup_route_global_fence",
        "assert_startup_route_workshop_fence",
        "record_startup_route_candidate_v2",
        "finish_startup_route_rebuild_v2",
    ] {
        assert!(
            startup.contains(protocol_step),
            "startup route rebuild must use {protocol_step}"
        );
    }
    assert!(startup.contains("routes_authoritative"));
    assert!(startup.contains("self.backend_ready && self.routes_authoritative"));
    assert!(startup.contains("(\"absent\", \"remove-absent\")"));
    let fail_closed = section(
        startup,
        "async fn fail_closed_startup_route_rebuild(",
        "pub(super) async fn reconcile(",
    );
    assert!(
        fail_closed.find("if !began").unwrap()
            < fail_closed.find("install_fail_closed_routes(").unwrap(),
        "a rejected begin fence must cause zero route mutations"
    );
}

#[test]
fn startup_projection_source_is_function_only_for_the_driver() {
    let startup = production(include_str!("../src/docker_driver/startup.rs"));
    let source = section(
        startup,
        "async fn startup_projection_source(",
        "async fn initialize_startup_route_projections(",
    );
    assert!(source.contains("control.read_startup_route_projection_source"));
    for table in [
        "control.workshops",
        "control.odoo_databases",
        "control.webshop_domains",
        "control.workshop_modules",
        "control.service_instances",
    ] {
        assert!(
            !source.contains(table),
            "driver must not directly read {table}"
        );
    }
}

#[test]
fn startup_route_effects_use_exact_assertions_without_inline_fleet_renewal() {
    let startup = production(include_str!("../src/docker_driver/startup.rs"));
    let migration = include_str!("../migrations/0019_startup_route_heartbeat_fences.sql");
    let apply = section(
        startup,
        "async fn apply_startup_route_rebuild(",
        "async fn fail_closed_startup_route_rebuild(",
    );
    let route_loop = section(apply, "for route in routes {", "let projection_evidence");
    assert_eq!(
        route_loop.matches("assert_startup_workshop_fence(").count(),
        2,
        "each workshop filesystem mutation needs exact pre/post assertions"
    );
    assert!(!route_loop.contains("renew_startup_route_rebuild("));
    assert_eq!(
        apply.matches("assert_startup_global_fence(").count(),
        4,
        "fail-closed cleanup and gateway reload need global pre/post assertions"
    );

    let renewal = section(
        migration,
        "create or replace function control.renew_startup_route_rebuild(",
        "create function control.assert_startup_route_global_fence(",
    );
    let first_update = renewal.find("update control.").unwrap();
    assert!(renewal[..first_update].contains("if v_exact<>v_expected then return false"));
    assert!(renewal.contains("if v_changed<>v_expected then raise exception"));

    for assertion in [
        section(
            migration,
            "create function control.assert_startup_route_global_fence(",
            "create function control.assert_startup_route_workshop_fence(",
        ),
        section(
            migration,
            "create function control.assert_startup_route_workshop_fence(",
            "create function control.record_startup_route_candidate_v2(",
        ),
    ] {
        assert!(!assertion.contains("update control."));
        assert!(!assertion.contains("lease_expires_at="));
    }
}

#[test]
fn startup_route_snapshot_uses_gap_free_bounded_keyset_pages() {
    let startup = production(include_str!("../src/docker_driver/startup.rs"));
    let migration = include_str!("../migrations/0013_route_effect_authority.sql");
    let reader = section(
        startup,
        "async fn read_startup_route_rebuild(",
        "async fn startup_projection_source(",
    );

    assert!(reader.contains("loop {"));
    assert!(reader.contains(".bind(after)"));
    assert!(reader.contains(".bind(500_i32)"));
    assert!(reader.contains("after = batch.last().map(|row| row.0)"));
    assert!(reader.contains("let full = batch.len() == 500"));
    assert!(reader.contains("if !full"));

    let database_reader = section(
        migration,
        "create or replace function control.read_startup_route_rebuild_batch(",
        "-- Initialize only an uninitialized reservation",
    );
    assert!(
        database_reader
            .contains("p_after_workshop is null or reservation.workshop_id>p_after_workshop")
    );
    assert!(database_reader.contains("order by reservation.workshop_id limit p_limit"));
    assert!(database_reader.contains("p_limit between 1 and 500"));
}

#[test]
fn every_route_effect_resolves_the_selected_generation_boundary() {
    for (name, source) in [
        (
            "gateway",
            production(include_str!("../src/docker_driver/gateway.rs")),
        ),
        (
            "recovery",
            production(include_str!("../src/docker_driver/recovery.rs")),
        ),
        (
            "release",
            production(include_str!("../src/docker_driver/release.rs")),
        ),
    ] {
        assert_eq!(
            source.matches("config.route_root").count(),
            source
                .matches("selected_route_root(&state.config.route_root)")
                .count(),
            "{name} contains a route-root access outside the selected generation boundary"
        );
    }

    let startup = production(include_str!("../src/docker_driver/startup.rs"));
    assert!(
        startup_route_root_accesses_are_safe(startup),
        "startup route-root access must use the selected boundary, descriptor-safe generation API, or host guard"
    );
    assert!(startup_route_root_accesses_are_safe(
        "let selected = selected_route_root(&state.config.route_root)?;"
    ));
    assert!(!startup_route_root_accesses_are_safe(
        "std::fs::write(&state.config.route_root, bytes)?;"
    ));
    assert!(!startup_route_root_accesses_are_safe(
        "let route_root = &state.config.route_root;\nstd::fs::write(route_root, bytes)?;"
    ));

    let gateway = include_str!("../deploy/gateway.conf");
    assert!(gateway.contains("include /etc/nginx/tenants/current/*.conf;"));
    assert!(!gateway.contains("include /etc/nginx/tenants/*.conf;"));

    let reset = include_str!("../deploy/gateway-route-reset.sh");
    for step in [
        "mkdir -p /routes/generations/boot-live",
        "ln -s generations/boot-live /routes/current.next",
        "mv -Tf /routes/current.next /routes/current",
    ] {
        assert!(
            reset.contains(step),
            "route reset is missing atomic selector step {step}"
        );
    }
}

#[test]
fn fleet_activation_requires_an_exact_loaded_release_generation() {
    let gateway = production(include_str!("../src/docker_driver/gateway.rs"));
    let release = production(include_str!("../src/docker_driver/release.rs"));
    let migration = include_str!("../migrations/0022_release_gateway_generation_identity.sql");

    for field in [
        "protocol_version",
        "fleet_run_id",
        "driver_action_id",
        "original_driver_fence_token",
        "gateway_configuration_digest",
        "target_slot",
    ] {
        assert!(
            gateway.contains(field),
            "release identity is missing {field}"
        );
    }
    assert!(gateway.contains("#[serde(deny_unknown_fields)]"));
    assert!(gateway.contains("bytes.len() > 1024"));
    assert!(gateway.contains("listen 127.0.0.1:8082;"));

    let trace_fields = section(
        gateway,
        "name = \"deployment_driver.release_gateway.observe_loaded_generation\"",
        "pub(super) async fn observe_running_release_gateway_generation(",
    );
    for sensitive in ["fence", "token", "digest", "route."] {
        assert!(
            !trace_fields.contains(sensitive),
            "release observation tracing exposes {sensitive}"
        );
    }

    let activation = section(
        release,
        "let gateway_identity = ReleaseGatewayGenerationIdentity::new(",
        "let changed = sqlx::query(",
    );
    assert!(activation.contains("activate_release_routes("));
    assert!(activation.contains("publish_release_gateway_identity("));
    assert!(activation.contains("observe_running_release_gateway_generation("));
    assert!(
        activation
            .find("observe_running_release_gateway_generation(")
            .unwrap()
            < activation.find("remove_release_route_backups(").unwrap(),
        "recovery bytes must remain until the running identity is observed"
    );
    assert!(migration.contains("gateway_identity_version smallint"));
    assert!(migration.contains("new.driver_fence_token is distinct from old.driver_fence_token"));
    assert!(
        migration
            .contains("new.gateway_identity_version is distinct from old.gateway_identity_version")
    );
    assert!(migration.contains("legacy fleet activation intent requires reconciliation"));
}
