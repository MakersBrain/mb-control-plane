use std::collections::BTreeSet;

use super::*;

#[derive(Clone, Debug, Default, Serialize)]
pub(super) struct StartupReport {
    pub backend_ready: bool,
    pub routes_opened: usize,
    pub degraded_resources: Vec<String>,
    pub unknown_resources: Vec<String>,
}

impl StartupReport {
    pub(super) fn command_ready(&self) -> bool {
        self.backend_ready
    }

    fn degraded(&mut self, resource: impl Into<String>, error: impl std::fmt::Display) {
        let resource = resource.into();
        tracing::error!(%resource, %error, "startup reconciliation left a managed resource degraded");
        self.degraded_resources.push(resource);
    }
}

#[derive(Debug)]
struct TenantRoute {
    workshop: Uuid,
    database_ref: String,
    public_hostname: String,
    paperless_base_url: Option<String>,
    paperless_restricted: bool,
    custom_hostnames: Value,
    unresolved_operation: bool,
}

#[derive(Debug, PartialEq, Eq)]
struct SlotStartupPlan {
    active_count: usize,
    candidate_present: bool,
}

fn slot_startup_plan<'a>(states: impl IntoIterator<Item = &'a str>) -> SlotStartupPlan {
    let mut plan = SlotStartupPlan {
        active_count: 0,
        candidate_present: false,
    };
    for state in states {
        if state == "active" {
            plan.active_count += 1;
        }
        if matches!(state, "starting" | "verifying" | "prepared") {
            plan.candidate_present = true;
        }
    }
    plan
}

fn unknown_resources(
    observed: impl IntoIterator<Item = String>,
    expected: &BTreeSet<String>,
) -> Vec<String> {
    observed
        .into_iter()
        .filter(|name| !expected.contains(name))
        .collect()
}

pub(super) fn install_fail_closed_routes(route_root: &Path) -> anyhow::Result<usize> {
    let mut removed = 0;
    for entry in std::fs::read_dir(route_root)? {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let generated = name
            .strip_suffix(".conf")
            .or_else(|| name.strip_suffix(".conf.tmp"))
            .or_else(|| name.strip_suffix(".release.tmp"))
            .or_else(|| name.strip_suffix(".startup.tmp"))
            .is_some_and(|stem| Uuid::parse_str(stem).is_ok());
        if generated {
            std::fs::remove_file(entry.path())?;
            removed += 1;
        }
    }
    Ok(removed)
}

pub(super) async fn reconcile(state: &DriverState) -> StartupReport {
    let mut report = StartupReport::default();
    let observed_result = match &state.backend {
        RuntimeBackend::Docker => docker_workspace_containers(state).await,
        RuntimeBackend::Quadlet(backend) => backend.workspace_resources(),
    };
    let observed = match observed_result {
        Ok(value) => {
            report.backend_ready = true;
            value
        }
        Err(error) => {
            report.degraded("runtime-backend", error.1);
            return report;
        }
    };
    let mut expected = BTreeSet::new();

    let slots = match sqlx::query_as::<_, (String, String, String, String)>(
        "select slot,state,coalesce(evidence->>'runtime_deployment_ref',''),
                coalesce(evidence->>'runtime_config_digest','')
           from control.runtime_release_slots where runtime_key='shared-odoo' order by slot",
    )
    .fetch_all(&state.ledger)
    .await
    {
        Ok(value) => value,
        Err(error) => {
            report.backend_ready = false;
            report.degraded("driver-ledger", error);
            return report;
        }
    };
    let release_unresolved = sqlx::query_scalar::<_, bool>(
        "select exists(select 1 from control.release_fleet_runs
          where state in ('preflighting','preparing','paused','activating'))",
    )
    .fetch_one(&state.ledger)
    .await
    .unwrap_or(true);
    let slot_plan = slot_startup_plan(slots.iter().map(|(_, state, _, _)| state.as_str()));
    let active_count = slot_plan.active_count;
    let candidate_present = slot_plan.candidate_present;
    if active_count > 1 {
        report
            .degraded_resources
            .push("ambiguous-active-odoo-slots".into());
    }

    let mut active_container = None;
    for (slot, slot_state, image_digest, config_digest) in &slots {
        let container = state.config.docker_resource(format!("odoo-{slot}"));
        expected.insert(match state.backend {
            RuntimeBackend::Docker => container.clone(),
            RuntimeBackend::Quadlet(_) => format!("mb-odoo-{slot}"),
        });
        match slot_state.as_str() {
            "active" => {
                if active_count != 1 {
                    continue;
                }
                match reconcile_active_odoo(state, &container, image_digest, config_digest).await {
                    Ok(()) => active_container = Some(container),
                    Err(error) => report.degraded(format!("odoo-slot:{slot}"), error.1),
                }
            }
            "inactive" | "retained" | "failed" => {
                if let Err(error) = stop_non_active_runtime(state, &container).await {
                    report.degraded(format!("odoo-slot:{slot}"), error.1);
                }
            }
            // Candidate state is owned by the interrupted release operation. Do not
            // start, stop, delete, or otherwise reinterpret it during boot.
            "starting" | "verifying" | "prepared" => {}
            other => report.degraded(
                format!("odoo-slot:{slot}"),
                format!("unknown slot state {other}"),
            ),
        }
    }

    let tenants = match load_tenant_routes(state).await {
        Ok(value) => value,
        Err(error) => {
            report.backend_ready = false;
            report.degraded("driver-ledger", error.1);
            return report;
        }
    };
    let mut paperless_ready = BTreeSet::new();
    for tenant in &tenants {
        if tenant.paperless_base_url.is_none() {
            continue;
        }
        let container = state
            .config
            .docker_resource(format!("paperless-{}", tenant_key(tenant.workshop)));
        expected.insert(match state.backend {
            RuntimeBackend::Docker => container.clone(),
            RuntimeBackend::Quadlet(_) => format!("mb-paperless-{}", tenant.workshop.simple()),
        });
        if tenant.unresolved_operation {
            let fenced = match &state.backend {
                RuntimeBackend::Docker => {
                    async {
                        if docker_container_exists(state, &container).await? {
                            docker_ensure_restart_policy(
                                state,
                                &container,
                                DockerRestartPolicy::No,
                            )
                            .await?;
                            let inspect = docker_inspect_container(state, &container).await?;
                            if inspect.pointer("/State/Running").and_then(Value::as_bool)
                                == Some(true)
                            {
                                docker_stop_container(state, &container).await?;
                            }
                        }
                        Ok::<(), DriverError>(())
                    }
                    .await
                }
                RuntimeBackend::Quadlet(backend) => match backend.workspace_resources() {
                    Ok(resources)
                        if resources
                            .contains(&format!("mb-paperless-{}", tenant.workshop.simple())) =>
                    {
                        backend.set_container_boot_selected(&container, false).await
                    }
                    Ok(_) => Ok(()),
                    Err(error) => Err(error),
                },
            };
            if let Err(error) = fenced {
                report.degraded(format!("paperless-fence:{}", tenant.workshop), error.1);
            }
            continue;
        }
        match reconcile_paperless(state, tenant.workshop, &container).await {
            Ok(()) => {
                paperless_ready.insert(tenant.workshop);
            }
            Err(error) => report.degraded(format!("paperless:{}", tenant.workshop), error.1),
        }
    }

    report.unknown_resources = unknown_resources(observed, &expected);
    for resource in &report.unknown_resources {
        tracing::warn!(%resource, "leaving unknown workspace runtime untouched during startup");
    }

    if release_unresolved || candidate_present || active_container.is_none() {
        if release_unresolved || candidate_present {
            report.degraded_resources.push("release-fence".into());
        }
        return report;
    }
    let active_container = active_container.expect("checked above");
    let mut opened = Vec::new();
    for tenant in tenants {
        if tenant.unresolved_operation {
            report
                .degraded_resources
                .push(format!("tenant-fence:{}", tenant.workshop));
            continue;
        }
        if let Err(error) = verify_odoo_tenant(state, &active_container, &tenant).await {
            report.degraded(format!("odoo-tenant:{}", tenant.workshop), error.1);
            continue;
        }
        let custom_hostnames = match serde_json::from_value::<Vec<CustomHostnameRoute>>(
            tenant.custom_hostnames.clone(),
        ) {
            Ok(value) => value,
            Err(error) => {
                report.degraded(format!("gateway:{}", tenant.workshop), error);
                continue;
            }
        };
        let paperless = tenant
            .paperless_base_url
            .as_deref()
            .and_then(|base| Url::parse(base).ok())
            .and_then(|url| url.host_str().map(str::to_owned))
            .filter(|_| paperless_ready.contains(&tenant.workshop))
            .map(|hostname| {
                let container = state
                    .config
                    .docker_resource(format!("paperless-{}", tenant_key(tenant.workshop)));
                (hostname, container)
            });
        let config = route_config_for_upstream(
            &tenant.database_ref,
            &tenant.public_hostname,
            &active_container,
            paperless
                .as_ref()
                .map(|(hostname, container)| (hostname.as_str(), container.as_str())),
            tenant.paperless_restricted,
            &custom_hostnames,
        );
        let path = state
            .config
            .route_root
            .join(format!("{}.conf", tenant.workshop));
        let temporary = state
            .config
            .route_root
            .join(format!("{}.startup.tmp", tenant.workshop));
        if let Err(error) =
            write_gateway_file(&temporary, config).and_then(|()| std::fs::rename(&temporary, &path))
        {
            report.degraded(format!("gateway:{}", tenant.workshop), error);
            continue;
        }
        opened.push(tenant.workshop);
    }
    if opened.is_empty() {
        return report;
    }
    let mut route_hasher = Sha256::new();
    for workshop in &opened {
        route_hasher.update(workshop.as_bytes());
        match std::fs::read(state.config.route_root.join(format!("{workshop}.conf"))) {
            Ok(bytes) => route_hasher.update(bytes),
            Err(error) => {
                report.degraded("gateway", error);
                return report;
            }
        }
    }
    let route_digest = format!("sha256:{:x}", route_hasher.finalize());
    if let Err(error) = reload_gateway_runtime(state, &route_digest).await {
        for workshop in &opened {
            let _ = std::fs::remove_file(state.config.route_root.join(format!("{workshop}.conf")));
        }
        report.degraded("gateway", error.1);
        return report;
    }
    for workshop in &opened {
        let backup = state
            .config
            .route_root
            .join(format!("{workshop}.recovery.bak"));
        if backup.exists() {
            let _ = std::fs::remove_file(backup);
        }
    }
    report.routes_opened = opened.len();
    report
}

async fn reconcile_active_odoo(
    state: &DriverState,
    container: &str,
    image_digest: &str,
    config_digest: &str,
) -> Result<(), DriverError> {
    if let RuntimeBackend::Quadlet(backend) = &state.backend {
        let slot = if container.ends_with("-blue") {
            "blue"
        } else if container.ends_with("-green") {
            "green"
        } else {
            return Err(DriverError::internal("invalid Odoo slot runtime name"));
        };
        backend.set_odoo_boot_selected(slot, true).await?;
        backend
            .reconcile_persistent_unit(
                "odoo-slots",
                &format!("mb-odoo-{slot}"),
                Some(image_digest),
                config_digest,
                RuntimeState::Running,
            )
            .await?;
        return Ok(());
    }
    if !docker_container_exists(state, container).await? {
        return Err(DriverError::internal("active Odoo runtime is missing"));
    }
    let inspect = docker_inspect_container(state, container).await?;
    for (pointer, expected) in [
        ("/Config/Labels/mb.kind", "odoo-release-runtime"),
        ("/Config/Labels/mb.image-digest", image_digest),
        ("/Config/Labels/mb.config-digest", config_digest),
        (
            "/Config/Labels/mb.workspace",
            state.config.workspace_namespace.as_str(),
        ),
    ] {
        if inspect.pointer(pointer).and_then(Value::as_str) != Some(expected) {
            return Err(DriverError::internal(format!(
                "active Odoo identity mismatch at {pointer}"
            )));
        }
    }
    docker_ensure_restart_policy(state, container, DockerRestartPolicy::UnlessStopped).await?;
    if inspect.pointer("/State/Running").and_then(Value::as_bool) != Some(true) {
        docker_start_container(state, container).await?;
    }
    Ok(())
}

async fn stop_non_active_runtime(state: &DriverState, container: &str) -> Result<(), DriverError> {
    if let RuntimeBackend::Quadlet(backend) = &state.backend {
        let slot = if container.ends_with("-blue") {
            "blue"
        } else if container.ends_with("-green") {
            "green"
        } else {
            return Err(DriverError::internal("invalid Odoo slot runtime name"));
        };
        if backend
            .workspace_resources()?
            .contains(&format!("mb-odoo-{slot}"))
        {
            backend.set_odoo_boot_selected(slot, false).await?;
        }
        return Ok(());
    }
    if !docker_container_exists(state, container).await? {
        return Ok(());
    }
    docker_ensure_restart_policy(state, container, DockerRestartPolicy::No).await?;
    let inspect = docker_inspect_container(state, container).await?;
    if inspect.pointer("/State/Running").and_then(Value::as_bool) == Some(true) {
        docker_stop_container(state, container).await?;
    }
    Ok(())
}

async fn reconcile_paperless(
    state: &DriverState,
    workshop: Uuid,
    container: &str,
) -> Result<(), DriverError> {
    if let RuntimeBackend::Quadlet(backend) = &state.backend {
        let spec = sqlx::query_scalar::<_, Value>(
            "select runtime_spec
               from control.service_instances
              where workshop_id=$1 and service='paperless' and runtime_spec is not null",
        )
        .bind(workshop)
        .fetch_optional(&state.ledger)
        .await
        .map_err(DriverError::internal)?
        .ok_or_else(|| DriverError::internal("Paperless runtime specification is missing"))?;
        let image = spec
            .get("image")
            .and_then(Value::as_str)
            .ok_or_else(|| DriverError::internal("Paperless runtime image is missing"))?;
        let digest = spec
            .get("config_digest")
            .and_then(Value::as_str)
            .ok_or_else(|| DriverError::internal("Paperless runtime digest is missing"))?;
        let unit = format!("mb-paperless-{}", workshop.simple());
        if !backend.workspace_resources()?.contains(&unit) {
            reconstruct_paperless(state, workshop, container, &spec).await?;
            return Ok(());
        }
        backend
            .reconcile_persistent_unit(
                "paperless",
                &unit,
                Some(image),
                digest,
                RuntimeState::Running,
            )
            .await?;
        return Ok(());
    }
    if !docker_container_exists(state, container).await? {
        return Err(DriverError::internal("Paperless runtime is missing"));
    }
    let inspect = docker_inspect_container(state, container).await?;
    if inspect
        .pointer("/Config/Labels/mb.kind")
        .and_then(Value::as_str)
        != Some("paperless")
        || inspect
            .pointer("/Config/Labels/mb.workshop")
            .and_then(Value::as_str)
            != Some(workshop.to_string().as_str())
        || inspect
            .pointer("/Config/Labels/mb.workspace")
            .and_then(Value::as_str)
            != Some(state.config.workspace_namespace.as_str())
        || inspect
            .pointer("/Config/Labels/mb.config-digest")
            .and_then(Value::as_str)
            .is_none()
    {
        return Err(DriverError::internal("Paperless runtime identity mismatch"));
    }
    docker_ensure_restart_policy(state, container, DockerRestartPolicy::UnlessStopped).await?;
    if inspect.pointer("/State/Running").and_then(Value::as_bool) != Some(true) {
        docker_start_container(state, container).await?;
    }
    wait_for_healthy_container(state, container, "Paperless").await
}

async fn reconstruct_paperless(
    state: &DriverState,
    workshop: Uuid,
    container: &str,
    spec: &Value,
) -> Result<(), DriverError> {
    let field = |name: &str| {
        spec.get(name)
            .and_then(Value::as_str)
            .ok_or_else(|| DriverError::internal(format!("Paperless runtime {name} is missing")))
    };
    if field("container_name")? != container {
        return Err(DriverError::internal(
            "Paperless runtime name is not deterministic",
        ));
    }
    let secret_root = driver_runtime_secret_root(state)
        .join("paperless")
        .join(workshop.to_string());
    let read = |name: &str| -> Result<String, DriverError> {
        let value =
            std::fs::read_to_string(secret_root.join(name)).map_err(DriverError::internal)?;
        let value = value.trim().to_owned();
        if value.is_empty() {
            return Err(DriverError::internal(
                "Paperless reconstruction credential is empty",
            ));
        }
        Ok(value)
    };
    let compact = tenant_key(workshop);
    ensure_paperless(
        state,
        workshop,
        container,
        field("database_ref")?,
        field("database_role")?,
        &read("database-password")?,
        &read("admin-password")?,
        &read("secret-key")?,
        field("redis_identity")?,
        &read("redis-password")?,
        &format!("mb:{compact}:"),
        &format!("mb-paperless-{compact}"),
        &read("oidc-secret")?,
        &read("webhook-secret")?,
        field("public_hostname")?,
    )
    .await
}

async fn verify_odoo_tenant(
    state: &DriverState,
    container: &str,
    tenant: &TenantRoute,
) -> Result<(), DriverError> {
    let token = std::fs::read_to_string(
        state
            .config
            .secret_root
            .join("docker")
            .join(tenant.workshop.to_string())
            .join("odoo"),
    )
    .map_err(DriverError::internal)?;
    for _ in 0..3 {
        let base_url = match state.backend {
            RuntimeBackend::Docker => format!("http://{container}:8069"),
            RuntimeBackend::Quadlet(_) if container.ends_with("-blue") => {
                "http://127.0.0.1:18069".into()
            }
            RuntimeBackend::Quadlet(_) if container.ends_with("-green") => {
                "http://127.0.0.1:18070".into()
            }
            RuntimeBackend::Quadlet(_) => {
                return Err(DriverError::internal("invalid Odoo slot runtime name"));
            }
        };
        let response = reqwest::Client::new()
            .get(format!("{base_url}/mb_control/v1/health"))
            .header("X-Odoo-Dbfilter", &tenant.database_ref)
            .bearer_auth(token.trim())
            .timeout(Duration::from_secs(3))
            .send()
            .await;
        if let Ok(response) = response
            && response.status().is_success()
            && let Ok(body) = response.json::<Value>().await
            && body.get("status").and_then(Value::as_str) == Some("ready")
            && body.get("database").and_then(Value::as_str) == Some(&tenant.database_ref)
            && body.get("workshop_id").and_then(Value::as_str)
                == Some(tenant.workshop.to_string().as_str())
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    Err(DriverError::internal(
        "active Odoo runtime failed startup identity verification",
    ))
}

async fn load_tenant_routes(state: &DriverState) -> Result<Vec<TenantRoute>, DriverError> {
    let rows = sqlx::query_as::<_, (Uuid, String, String, Option<String>, bool, Value, bool)>(
        "select w.id,d.database_ref,d.public_hostname,
                (select s.base_url from control.service_instances s
                  where s.workshop_id=w.id and s.service='paperless'
                    and s.health not in ('suspended','failed')),
                exists(select 1 from control.workshop_modules m
                  where m.workshop_id=w.id and m.module_key='documents'
                    and m.state='restricted'),
                coalesce((select jsonb_agg(jsonb_build_object(
                  'hostname',h.hostname,'canonical',h.canonical) order by h.hostname)
                  from control.webshop_domains h where h.workshop_id=w.id
                    and h.state in ('testing','active') and h.desired_state='active'),'[]'::jsonb),
                (exists(select 1 from control.operations o
                   where o.workshop_id=w.id
                     and o.state in ('pending','in_flight','awaiting_reconciliation')
                     and o.kind in ('tenant.provision','tenant.reconcile','tenant.lifecycle','odoo.release.adopt'))
                 or exists(select 1 from control.deployment_driver_operations ddo
                   where ddo.workshop_id=w.id and ddo.state='in_progress'))
           from control.workshops w
           join control.odoo_databases d on d.workshop_id=w.id
          where w.status in ('trial','active','past_due','restricted','suspended')
            and d.kind='primary' and d.routable and d.deleted_at is null
            and d.state not in ('restoring','deleted') and d.public_hostname is not null
          order by w.id",
    )
    .fetch_all(&state.ledger)
    .await
    .map_err(DriverError::internal)?;
    Ok(rows
        .into_iter()
        .map(
            |(
                workshop,
                database_ref,
                public_hostname,
                paperless_base_url,
                paperless_restricted,
                custom_hostnames,
                unresolved_operation,
            )| TenantRoute {
                workshop,
                database_ref,
                public_hostname,
                paperless_base_url,
                paperless_restricted,
                custom_hostnames,
                unresolved_operation,
            },
        )
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fail_closed_cleanup_removes_only_generated_live_routes() {
        let root = std::env::temp_dir().join(format!("mb-route-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let workshop = Uuid::new_v4();
        std::fs::write(root.join(format!("{workshop}.conf")), "unsafe").unwrap();
        std::fs::write(root.join(format!("{workshop}.recovery.bak")), "saved").unwrap();
        std::fs::write(root.join("README"), "operator-owned").unwrap();

        assert_eq!(install_fail_closed_routes(&root).unwrap(), 1);
        assert!(!root.join(format!("{workshop}.conf")).exists());
        assert!(root.join(format!("{workshop}.recovery.bak")).exists());
        assert!(root.join("README").exists());
        assert_eq!(install_fail_closed_routes(&root).unwrap(), 0);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn two_active_slots_are_ambiguous_and_candidates_are_fenced() {
        let ambiguous = slot_startup_plan(["active", "active"]);
        assert_eq!(ambiguous.active_count, 2);
        assert!(!ambiguous.candidate_present);

        let interrupted = slot_startup_plan(["active", "prepared"]);
        assert_eq!(interrupted.active_count, 1);
        assert!(interrupted.candidate_present);
    }

    #[test]
    fn startup_planning_is_idempotent_and_unknown_resources_stay_unknown() {
        let states = ["active", "retained", "failed"];
        assert_eq!(slot_startup_plan(states), slot_startup_plan(states));
        let expected = BTreeSet::from(["mb-odoo-blue".to_owned()]);
        assert_eq!(
            unknown_resources(
                ["mb-odoo-blue".to_owned(), "operator-debug".to_owned()],
                &expected,
            ),
            vec!["operator-debug"]
        );
    }
}
