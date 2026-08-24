use std::collections::{BTreeMap, BTreeSet};

use super::*;

use crate::outbound_http::TraceRequestBuilderExt as _;

static ODOO_READINESS_HTTP: std::sync::OnceLock<Result<reqwest::Client, String>> =
    std::sync::OnceLock::new();

#[cfg(test)]
static ODOO_READINESS_HTTP_BUILDS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

pub(super) fn odoo_readiness_client() -> Result<reqwest::Client, DriverError> {
    let client = ODOO_READINESS_HTTP.get_or_init(|| {
        #[cfg(test)]
        ODOO_READINESS_HTTP_BUILDS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);

        crate::outbound_http::internal_service_builder("mb-control-container-driver/odoo-readiness")
            .build()
            .map_err(|error| error.to_string())
    });
    client
        .as_ref()
        .cloned()
        .map_err(|error| DriverError::internal(error.clone()))
}

pub(super) fn odoo_readiness_request(
    client: &reqwest::Client,
    url: impl reqwest::IntoUrl,
    database_ref: &str,
    token: &str,
    timeout: Option<Duration>,
) -> reqwest::RequestBuilder {
    let request = client
        .get(url)
        .header("X-Odoo-Dbfilter", database_ref)
        .bearer_auth(token);
    if let Some(timeout) = timeout {
        request.timeout(timeout)
    } else {
        request
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub(super) struct StartupReport {
    pub backend_ready: bool,
    pub routes_authoritative: bool,
    pub routes_opened: usize,
    pub degraded_resources: Vec<String>,
    pub unknown_resources: Vec<String>,
}

impl StartupReport {
    pub(super) fn command_ready(&self) -> bool {
        self.backend_ready && self.routes_authoritative
    }

    fn degraded(&mut self, resource: impl Into<String>, error_class: &'static str) {
        let resource = resource.into();
        let resource_class = safe_startup_resource_class(&resource);
        tracing::error!(
            resource_class,
            error_class,
            "startup reconciliation left a managed resource degraded"
        );
        self.degraded_resources.push(resource);
    }
}

fn safe_startup_resource_class(resource: &str) -> &'static str {
    match resource.split(':').next() {
        Some("runtime-backend") => "runtime_backend",
        Some("driver-ledger") => "driver_ledger",
        Some("odoo-slot") => "odoo_slot",
        Some("paperless-fence") => "paperless_fence",
        Some("paperless") => "paperless",
        Some("odoo-tenant") => "odoo_tenant",
        Some("gateway") => "gateway",
        _ => "unknown",
    }
}

#[derive(Debug)]
pub(super) struct TenantRoute {
    pub(super) workshop: Uuid,
    pub(super) database_ref: String,
    pub(super) paperless_base_url: Option<String>,
    pub(super) unresolved_operation: bool,
}

#[derive(Debug)]
struct StartupRouteLease {
    effect_run_id: Uuid,
    execution_token: Uuid,
    global_lease_token: Uuid,
    route_lease_token: Uuid,
    global_fence_token: i64,
}

#[derive(Debug)]
struct StartupRouteProjection {
    workshop: Uuid,
    generation: i64,
    projection_digest: String,
    disposition: String,
    action: String,
    route_fence_token: i64,
}

#[derive(Debug)]
struct StartupRenderedRoute {
    projection: StartupRouteProjection,
    contents: Option<String>,
    rendered_digest: String,
}

enum StartupRouteAdmission {
    Acquired(StartupRouteLease),
    Replay,
    Unavailable(&'static str),
}

const STARTUP_ROUTE_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(20);
const STARTUP_ROUTE_HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(15);
const STARTUP_INTERRUPTED_RECONCILIATION_LIMIT: usize = 32;

type StartupRouteRow = (
    Uuid,
    Option<i64>,
    Option<String>,
    Option<String>,
    String,
    i64,
    Option<Value>,
);

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

#[tracing::instrument(
    name = "deployment_driver.startup_routes.admit",
    skip_all,
    fields(driver.instance_id = %state.instance_id, route.outcome = tracing::field::Empty)
)]
async fn admit_startup_route_rebuild(
    state: &DriverState,
) -> Result<StartupRouteAdmission, DriverError> {
    let boot_id = state.instance_id;
    let request = json!({"boot_id":boot_id,"kind":"startup-rebuild"});
    let request_digest = format!(
        "{:x}",
        Sha256::digest(
            serde_jcs::to_vec(&request)
                .map_err(|_| DriverError::internal("startup route request is not canonical"))?
        )
    );
    let execution_token = Uuid::new_v4();
    let global_lease_token = Uuid::new_v4();
    let route_lease_token = Uuid::new_v4();
    let row = sqlx::query_as::<
        _,
        (
            String,
            Option<Uuid>,
            Option<i64>,
            Option<i32>,
            Option<Value>,
        ),
    >(
        "select outcome,effect_run_id,global_fence_token,reserved_count,stored_response
           from control.admit_startup_route_rebuild($1,$2,$3,$4,$5,$6,$7,$8)",
    )
    .bind(boot_id)
    .bind(format!("startup/{boot_id}"))
    .bind(request_digest)
    .bind(state.instance_id)
    .bind(execution_token)
    .bind(global_lease_token)
    .bind(route_lease_token)
    .bind(ROUTE_APPLICATION_LEASE_SECONDS)
    .fetch_one(&state.ledger)
    .await
    .map_err(DriverError::internal)?;
    tracing::Span::current().record("route.outcome", row.0.as_str());
    match row.0.as_str() {
        "acquired" => Ok(StartupRouteAdmission::Acquired(StartupRouteLease {
            effect_run_id: row
                .1
                .ok_or_else(|| DriverError::internal("startup route run identity is missing"))?,
            execution_token,
            global_lease_token,
            route_lease_token,
            global_fence_token: row
                .2
                .ok_or_else(|| DriverError::internal("startup route fence is missing"))?,
        })),
        "replay" if row.4.is_some() => Ok(StartupRouteAdmission::Replay),
        "busy" | "route_busy" => Ok(StartupRouteAdmission::Unavailable("route_authority_busy")),
        "quarantined" | "route_quarantined" => Ok(StartupRouteAdmission::Unavailable(
            "route_authority_quarantined",
        )),
        "digest_conflict" => Ok(StartupRouteAdmission::Unavailable(
            "route_authority_conflict",
        )),
        _ => Ok(StartupRouteAdmission::Unavailable(
            "route_authority_invalid",
        )),
    }
}

async fn renew_startup_route_rebuild(
    state: &DriverState,
    lease: &StartupRouteLease,
) -> Result<(), DriverError> {
    let renewed = sqlx::query_scalar::<_, bool>(
        "select control.renew_startup_route_rebuild($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(lease.effect_run_id)
    .bind(state.instance_id)
    .bind(lease.execution_token)
    .bind(lease.global_lease_token)
    .bind(lease.route_lease_token)
    .bind(lease.global_fence_token)
    .bind(ROUTE_APPLICATION_LEASE_SECONDS)
    .fetch_one(&state.ledger)
    .await
    .map_err(DriverError::internal)?;
    if !renewed {
        return Err(DriverError::internal(
            "startup route rebuild lease was lost",
        ));
    }
    Ok(())
}

async fn with_startup_route_heartbeat<T>(
    effect: impl Future<Output = Result<T, DriverError>>,
    heartbeat: impl Future<Output = DriverError>,
) -> Result<T, DriverError> {
    tokio::pin!(effect);
    tokio::pin!(heartbeat);
    tokio::select! {
        biased;
        result = &mut effect => result,
        error = &mut heartbeat => Err(error),
    }
}

#[tracing::instrument(
    name = "deployment_driver.startup_routes.heartbeat",
    skip_all,
    fields(
        route.effect_run_id = %lease.effect_run_id,
        heartbeat.interval_seconds = STARTUP_ROUTE_HEARTBEAT_INTERVAL.as_secs()
    )
)]
async fn startup_route_heartbeat(state: &DriverState, lease: &StartupRouteLease) -> DriverError {
    let first_renewal = tokio::time::Instant::now() + STARTUP_ROUTE_HEARTBEAT_INTERVAL;
    let mut interval = tokio::time::interval_at(first_renewal, STARTUP_ROUTE_HEARTBEAT_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        interval.tick().await;
        let renewal = tokio::time::timeout(
            STARTUP_ROUTE_HEARTBEAT_TIMEOUT,
            renew_startup_route_rebuild(state, lease),
        )
        .await;
        match renewal {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                tracing::warn!(
                    route.effect_run_id = %lease.effect_run_id,
                    error_class = error.safe_class(),
                    "startup route heartbeat lost authority"
                );
                return error;
            }
            Err(_) => {
                tracing::warn!(
                    route.effect_run_id = %lease.effect_run_id,
                    "startup route heartbeat timed out"
                );
                return DriverError::internal("startup route heartbeat timed out");
            }
        }
    }
}

async fn assert_startup_global_fence(
    state: &DriverState,
    lease: &StartupRouteLease,
) -> Result<(), DriverError> {
    let current = sqlx::query_scalar::<_, bool>(
        "select control.assert_startup_route_global_fence($1,$2,$3,$4,$5)",
    )
    .bind(lease.effect_run_id)
    .bind(state.instance_id)
    .bind(lease.execution_token)
    .bind(lease.global_lease_token)
    .bind(lease.global_fence_token)
    .fetch_one(&state.ledger)
    .await
    .map_err(DriverError::internal)?;
    if !current {
        return Err(DriverError::internal(
            "startup global route authority was lost",
        ));
    }
    Ok(())
}

async fn assert_startup_workshop_fence(
    state: &DriverState,
    lease: &StartupRouteLease,
    route: &StartupRouteProjection,
) -> Result<(), DriverError> {
    let current = sqlx::query_scalar::<_, bool>(
        "select control.assert_startup_route_workshop_fence(
            $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",
    )
    .bind(lease.effect_run_id)
    .bind(state.instance_id)
    .bind(lease.execution_token)
    .bind(lease.global_lease_token)
    .bind(lease.route_lease_token)
    .bind(lease.global_fence_token)
    .bind(route.workshop)
    .bind(route.generation)
    .bind(&route.projection_digest)
    .bind(&route.disposition)
    .bind(&route.action)
    .bind(route.route_fence_token)
    .fetch_one(&state.ledger)
    .await
    .map_err(DriverError::internal)?;
    if !current {
        return Err(DriverError::internal(
            "startup workshop route authority was lost",
        ));
    }
    Ok(())
}

async fn finish_startup_route_rebuild(
    state: &DriverState,
    lease: &StartupRouteLease,
    outcome: &str,
    response: Option<&Value>,
) -> Result<(), DriverError> {
    let finished = sqlx::query_scalar::<_, bool>(
        "select control.finish_startup_route_rebuild_v2($1,$2,$3,$4,$5,$6,$7,$8,$9)",
    )
    .bind(lease.effect_run_id)
    .bind(state.instance_id)
    .bind(lease.execution_token)
    .bind(lease.global_lease_token)
    .bind(lease.route_lease_token)
    .bind(lease.global_fence_token)
    .bind(outcome)
    .bind(response)
    .bind(Option::<&str>::None)
    .fetch_one(&state.ledger)
    .await
    .map_err(DriverError::internal)?;
    if !finished {
        return Err(DriverError::internal(
            "startup route rebuild finalization was fenced",
        ));
    }
    Ok(())
}

async fn read_startup_route_rebuild(
    state: &DriverState,
    lease: &StartupRouteLease,
) -> Result<Vec<StartupRouteRow>, DriverError> {
    let mut rows = Vec::new();
    let mut after = None;
    loop {
        let batch = sqlx::query_as::<_, StartupRouteRow>(
            "select workshop_id,generation,projection_digest,disposition,action,
                    route_fence_token,projection
               from control.read_startup_route_rebuild_batch($1,$2,$3,$4,$5,$6,$7)",
        )
        .bind(lease.effect_run_id)
        .bind(state.instance_id)
        .bind(lease.execution_token)
        .bind(lease.global_lease_token)
        .bind(lease.global_fence_token)
        .bind(after)
        .bind(500_i32)
        .fetch_all(&state.ledger)
        .await
        .map_err(DriverError::internal)?;
        if batch.is_empty() {
            break;
        }
        after = batch.last().map(|row| row.0);
        let full = batch.len() == 500;
        rows.extend(batch);
        if !full {
            break;
        }
    }
    Ok(rows)
}

async fn startup_projection_source(
    state: &DriverState,
    lease: &StartupRouteLease,
    workshop: Uuid,
) -> Result<(String, Value, String), DriverError> {
    let source = sqlx::query_as::<_, (String, Option<String>, Option<Value>)>(
        "select outcome,disposition,projection
           from control.read_startup_route_projection_source(
               $1,$2,$3,$4,$5,$6,$7,$8)",
    )
    .bind(lease.effect_run_id)
    .bind(state.instance_id)
    .bind(lease.execution_token)
    .bind(lease.global_lease_token)
    .bind(lease.route_lease_token)
    .bind(lease.global_fence_token)
    .bind(workshop)
    .bind(&state.config.tenant_domain)
    .fetch_one(&state.ledger)
    .await
    .map_err(DriverError::internal)?;
    if source.0 != "read" {
        return Err(DriverError::internal(
            "startup route projection source is ambiguous",
        ));
    }
    let disposition = source
        .1
        .ok_or_else(|| DriverError::internal("startup route disposition is missing"))?;
    let projection = source
        .2
        .ok_or_else(|| DriverError::internal("startup route projection is missing"))?;
    let digest = format!(
        "sha256:{:x}",
        Sha256::digest(
            serde_jcs::to_vec(&projection)
                .map_err(|_| DriverError::internal("startup route projection is not canonical"))?
        )
    );
    Ok((disposition, projection, digest))
}

async fn initialize_startup_route_projections(
    state: &DriverState,
    lease: &StartupRouteLease,
) -> Result<(), DriverError> {
    for row in read_startup_route_rebuild(state, lease).await? {
        if row.4 != "remove-uninitialized" {
            continue;
        }
        let (disposition, projection, digest) =
            startup_projection_source(state, lease, row.0).await?;
        let initialized = sqlx::query_as::<_, (String, Option<i64>)>(
            "select outcome,generation from control.initialize_startup_route_projection(
                $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
        )
        .bind(lease.effect_run_id)
        .bind(state.instance_id)
        .bind(lease.execution_token)
        .bind(lease.global_lease_token)
        .bind(lease.route_lease_token)
        .bind(lease.global_fence_token)
        .bind(row.0)
        .bind(&state.config.tenant_domain)
        .bind(disposition)
        .bind(projection)
        .bind(digest)
        .fetch_one(&state.ledger)
        .await
        .map_err(DriverError::internal)?;
        if initialized.0 != "initialized" && initialized.0 != "already_initialized" {
            return Err(DriverError::internal(format!(
                "startup route initialization was rejected: {}",
                initialized.0
            )));
        }
    }
    Ok(())
}

fn render_startup_routes(
    state: &DriverState,
    active_container: Option<&str>,
    verified_tenants: &BTreeMap<Uuid, String>,
    rows: Vec<StartupRouteRow>,
) -> Result<Vec<StartupRenderedRoute>, DriverError> {
    rows.into_iter()
        .map(
            |(workshop, generation, digest, disposition, action, fence, projection)| {
                let generation = generation.ok_or_else(|| {
                    DriverError::internal("startup route projection generation is missing")
                })?;
                let projection_digest = digest.ok_or_else(|| {
                    DriverError::internal("startup route projection digest is missing")
                })?;
                let disposition = disposition.ok_or_else(|| {
                    DriverError::internal("startup route projection disposition is missing")
                })?;
                let projection = projection.ok_or_else(|| {
                    DriverError::internal("startup route projection payload is missing")
                })?;
                let canonical = serde_jcs::to_vec(&projection).map_err(|_| {
                    DriverError::internal("startup route projection is not canonical")
                })?;
                if format!("sha256:{:x}", Sha256::digest(canonical)) != projection_digest {
                    return Err(DriverError::internal(
                        "startup route projection digest does not match its payload",
                    ));
                }
                if projection.as_object().map(serde_json::Map::len) != Some(6) {
                    return Err(DriverError::internal(
                        "startup route projection has an invalid shape",
                    ));
                }
                let contents = match (disposition.as_str(), action.as_str()) {
                    ("absent", "remove-absent")
                        if projection
                            == json!({"database_id":null,"database_ref":null,
                                "public_hostname":null,"paperless_mode":"absent",
                                "paperless_hostname":null,"custom_hostnames":[]}) =>
                    {
                        None
                    }
                    ("present", "render") => {
                        let active_container = active_container.ok_or_else(|| {
                            DriverError::internal("active Odoo runtime is unavailable")
                        })?;
                        let database_ref = projection
                            .get("database_ref")
                            .and_then(Value::as_str)
                            .ok_or_else(|| {
                            DriverError::internal("route database reference is missing")
                        })?;
                        if !safe_pg_identifier(database_ref)
                            || projection
                                .get("database_id")
                                .and_then(Value::as_str)
                                .and_then(|value| Uuid::parse_str(value).ok())
                                .is_none()
                        {
                            return Err(DriverError::internal(
                                "route database identity is invalid",
                            ));
                        }
                        if verified_tenants.get(&workshop).map(String::as_str) != Some(database_ref)
                        {
                            return Err(DriverError::internal(
                                "tenant route identity was not verified",
                            ));
                        }
                        let public_hostname = hostname(&projection, "public_hostname")?;
                        let custom_hostnames = custom_hostname_routes(&projection)?;
                        let paperless_mode = projection
                            .get("paperless_mode")
                            .and_then(Value::as_str)
                            .ok_or_else(|| {
                                DriverError::internal("Paperless route mode is missing")
                            })?;
                        let paperless_hostname = match paperless_mode {
                            "absent"
                                if projection
                                    .get("paperless_hostname")
                                    .is_some_and(Value::is_null) =>
                            {
                                None
                            }
                            "read_write" | "read_only" => {
                                Some(hostname(&projection, "paperless_hostname")?)
                            }
                            _ => {
                                return Err(DriverError::internal(
                                    "Paperless route mode is invalid",
                                ));
                            }
                        };
                        let paperless_container = paperless_hostname.as_ref().map(|_| {
                            state
                                .config
                                .docker_resource(format!("paperless-{}", tenant_key(workshop)))
                        });
                        Some(route_config_for_upstream(
                            database_ref,
                            public_hostname,
                            active_container,
                            paperless_hostname.zip(paperless_container.as_deref()),
                            paperless_mode == "read_only",
                            &custom_hostnames,
                        ))
                    }
                    _ => {
                        return Err(DriverError::internal(
                            "startup route reservation shape is invalid",
                        ));
                    }
                };
                let rendered_digest = format!(
                    "sha256:{:x}",
                    Sha256::digest(contents.as_deref().unwrap_or_default().as_bytes())
                );
                Ok(StartupRenderedRoute {
                    projection: StartupRouteProjection {
                        workshop,
                        generation,
                        projection_digest,
                        disposition,
                        action,
                        route_fence_token: fence,
                    },
                    contents,
                    rendered_digest,
                })
            },
        )
        .collect()
}

async fn record_startup_route_candidate(
    state: &DriverState,
    lease: &StartupRouteLease,
    route: &StartupRenderedRoute,
) -> Result<(), DriverError> {
    let evidence = json!({
        "effect_run_id":lease.effect_run_id,
        "workshop_id":route.projection.workshop,
        "generation":route.projection.generation,
        "projection_digest":route.projection.projection_digest,
        "disposition":route.projection.disposition,
        "rendered_digest":route.rendered_digest,
        "route_fence_token":route.projection.route_fence_token,
    });
    let recorded = sqlx::query_scalar::<_, bool>(
        "select control.record_startup_route_candidate_v2(
            $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)",
    )
    .bind(lease.effect_run_id)
    .bind(state.instance_id)
    .bind(lease.execution_token)
    .bind(lease.global_lease_token)
    .bind(lease.route_lease_token)
    .bind(lease.global_fence_token)
    .bind(route.projection.workshop)
    .bind(route.projection.generation)
    .bind(&route.projection.projection_digest)
    .bind(&route.projection.disposition)
    .bind(&route.projection.action)
    .bind(route.projection.route_fence_token)
    .bind(&route.rendered_digest)
    .bind(evidence)
    .fetch_one(&state.ledger)
    .await
    .map_err(DriverError::internal)?;
    if !recorded {
        return Err(DriverError::internal(
            "startup route candidate evidence was fenced",
        ));
    }
    Ok(())
}

#[tracing::instrument(
    name = "deployment_driver.startup_routes.apply",
    skip_all,
    fields(
        route.effect_run_id = %lease.effect_run_id,
        route.workshop_count = routes.len()
    )
)]
async fn apply_startup_route_rebuild(
    state: &DriverState,
    lease: &StartupRouteLease,
    routes: &[StartupRenderedRoute],
) -> Result<usize, DriverError> {
    let began = sqlx::query_scalar::<_, bool>(
        "select control.begin_startup_route_rebuild($1,$2,$3,$4,$5,$6)",
    )
    .bind(lease.effect_run_id)
    .bind(state.instance_id)
    .bind(lease.execution_token)
    .bind(lease.global_lease_token)
    .bind(lease.route_lease_token)
    .bind(lease.global_fence_token)
    .fetch_one(&state.ledger)
    .await
    .map_err(DriverError::internal)?;
    if !began {
        return Err(DriverError::internal(
            "startup route rebuild could not begin",
        ));
    }

    let selected_routes = selected_route_root(&state.config.route_root)?;

    assert_startup_global_fence(state, lease).await?;
    install_fail_closed_routes(&selected_routes).map_err(DriverError::internal)?;
    assert_startup_global_fence(state, lease).await?;

    for route in routes {
        assert_startup_workshop_fence(state, lease, &route.projection).await?;
        let path = selected_routes.join(format!("{}.conf", route.projection.workshop));
        if let Some(contents) = &route.contents {
            let temporary =
                selected_routes.join(format!("{}.startup.tmp", route.projection.workshop));
            write_gateway_file(&temporary, contents).map_err(DriverError::internal)?;
            std::fs::rename(&temporary, &path).map_err(DriverError::internal)?;
        } else if path.exists() {
            std::fs::remove_file(&path).map_err(DriverError::internal)?;
        }
        assert_startup_workshop_fence(state, lease, &route.projection).await?;
        record_startup_route_candidate(state, lease, route).await?;
    }

    let projection_evidence = routes
        .iter()
        .map(|route| {
            json!({"workshop_id":route.projection.workshop,
                "generation":route.projection.generation,
                "projection_digest":route.projection.projection_digest,
                "disposition":route.projection.disposition,
                "rendered_digest":route.rendered_digest})
        })
        .collect::<Vec<_>>();
    let projection_set_digest = format!(
        "sha256:{:x}",
        Sha256::digest(
            serde_jcs::to_vec(&projection_evidence)
                .map_err(|_| DriverError::internal("route evidence is not canonical"))?
        )
    );
    let gateway_reload_digest = projection_set_digest.clone();
    assert_startup_global_fence(state, lease).await?;
    reload_gateway_runtime(state, &gateway_reload_digest).await?;
    assert_startup_global_fence(state, lease).await?;
    let response = json!({
        "effect_run_id":lease.effect_run_id,
        "global_fence_token":lease.global_fence_token,
        "workshop_count":routes.len(),
        "projection_set_digest":projection_set_digest,
        "gateway_reload_digest":gateway_reload_digest,
    });
    finish_startup_route_rebuild(state, lease, "succeeded", Some(&response)).await?;
    Ok(routes
        .iter()
        .filter(|route| route.contents.is_some())
        .count())
}

#[tracing::instrument(
    name = "deployment_driver.startup_routes.fail_closed",
    skip_all,
    fields(route.effect_run_id = %lease.effect_run_id)
)]
async fn fail_closed_startup_route_rebuild(
    state: &DriverState,
    lease: &StartupRouteLease,
) -> Result<(), DriverError> {
    let began = sqlx::query_scalar::<_, bool>(
        "select control.begin_startup_route_rebuild($1,$2,$3,$4,$5,$6)",
    )
    .bind(lease.effect_run_id)
    .bind(state.instance_id)
    .bind(lease.execution_token)
    .bind(lease.global_lease_token)
    .bind(lease.route_lease_token)
    .bind(lease.global_fence_token)
    .fetch_one(&state.ledger)
    .await
    .map_err(DriverError::internal)?;
    if !began {
        return Err(DriverError::internal(
            "fail-closed startup route rebuild could not begin",
        ));
    }
    let selected_routes = selected_route_root(&state.config.route_root)?;
    let effect_result = async {
        assert_startup_global_fence(state, lease).await?;
        install_fail_closed_routes(&selected_routes).map_err(DriverError::internal)?;
        assert_startup_global_fence(state, lease).await?;
        let fail_closed_digest = format!("sha256:{:x}", Sha256::digest([]));
        assert_startup_global_fence(state, lease).await?;
        reload_gateway_runtime(state, &fail_closed_digest).await?;
        assert_startup_global_fence(state, lease).await
    }
    .await;
    let finish_result = finish_startup_route_rebuild(state, lease, "unknown", None).await;
    effect_result.and(finish_result)
}

async fn execute_startup_route_rebuild(
    state: &DriverState,
    lease: &StartupRouteLease,
    active_container: Option<&str>,
    verified_tenants: &BTreeMap<Uuid, String>,
) -> Result<usize, DriverError> {
    initialize_startup_route_projections(state, lease).await?;
    let rows = read_startup_route_rebuild(state, lease).await?;
    let routes = render_startup_routes(state, active_container, verified_tenants, rows)?;
    apply_startup_route_rebuild(state, lease, &routes).await
}

async fn admit_staged_startup_publication(
    state: &DriverState,
) -> Result<startup_publication::StartupPublicationAdmission, DriverError> {
    let request = json!({"boot_id":state.instance_id,"kind":"staged-startup-publication-v1"});
    let request_digest = format!(
        "{:x}",
        Sha256::digest(
            serde_jcs::to_vec(&request).map_err(|_| DriverError::internal(
                "startup publication request is not canonical"
            ))?
        )
    );
    let idempotency_key = format!("startup/v1/{}", state.instance_id);
    startup_publication::admit(
        state,
        startup_publication::StartupPublicationAdmissionRequest {
            boot_id: state.instance_id,
            idempotency_key: &idempotency_key,
            request_digest: &request_digest,
            ttl_seconds: ROUTE_APPLICATION_LEASE_SECONDS,
        },
    )
    .await
}

fn prior_gateway_observation(
    prior: &startup_generation_fs::PriorSelector,
    identity: Option<&GatewayGenerationIdentity>,
) -> startup_publication::GatewayPublicationObservation {
    startup_publication::GatewayPublicationObservation {
        selector: prior.target().to_owned(),
        directory_device: prior.directory_device(),
        directory_inode: prior.directory_inode(),
        effect_run_id: identity.map(|value| value.effect_run_id),
        projection_set_digest: identity.map(|value| value.sealed_digest.clone()),
    }
}

fn recorded_prior_selector(
    prior: &startup_publication::GatewayPublicationObservation,
) -> Result<startup_generation_fs::PriorSelector, DriverError> {
    startup_generation_fs::PriorSelector::from_recorded(
        prior.selector.clone(),
        prior.directory_device,
        prior.directory_inode,
    )
    .map_err(DriverError::internal)
}

fn recorded_gateway_identity(
    prior: &startup_publication::GatewayPublicationObservation,
) -> Result<Option<GatewayGenerationIdentity>, DriverError> {
    match (&prior.effect_run_id, &prior.projection_set_digest) {
        (Some(effect_run_id), Some(sealed_digest)) => Ok(Some(GatewayGenerationIdentity {
            effect_run_id: *effect_run_id,
            sealed_digest: sealed_digest.clone(),
        })),
        (None, None) => Ok(None),
        _ => Err(DriverError::internal(
            "recorded prior gateway identity is incomplete",
        )),
    }
}

fn selector_is_recorded_prior(
    selected: &startup_generation_fs::PriorSelector,
    prior: &startup_publication::GatewayPublicationObservation,
) -> bool {
    selected.target() == prior.selector
        && selected.directory_device() == prior.directory_device
        && selected.directory_inode() == prior.directory_inode
}

async fn reconcile_interrupted_publication_claim(
    state: &DriverState,
    route_root: &Path,
    claim: &startup_publication::InterruptedStartupPublication,
) -> Result<startup_publication::InterruptedPublicationResolution, DriverError> {
    use startup_publication::{
        InterruptedPublicationPhase as Phase, InterruptedPublicationResolution as Resolution,
    };

    if claim.interrupted_phase == Phase::Staging && claim.prior.is_none() && claim.seal.is_none() {
        return Ok(Resolution::Unstarted);
    }

    let prior_observation = claim
        .prior
        .as_ref()
        .ok_or_else(|| DriverError::internal("interrupted startup publication prior is missing"))?;
    let prior = recorded_prior_selector(prior_observation)?;
    let expected_prior_identity = recorded_gateway_identity(prior_observation)?;
    let filesystem_prior_identity =
        startup_generation_fs::observe_prior_gateway_identity(route_root, &prior)
            .map_err(DriverError::internal)?;
    if filesystem_prior_identity != expected_prior_identity {
        return Ok(Resolution::Inconclusive);
    }

    let selected = startup_generation_fs::observe_current_selector(route_root)
        .map_err(DriverError::internal)?;
    if matches!(claim.interrupted_phase, Phase::Staging | Phase::Sealed) {
        if !selector_is_recorded_prior(&selected, prior_observation) {
            return Ok(Resolution::Inconclusive);
        }
        match claim.interrupted_phase {
            Phase::Staging => {
                match startup_generation_fs::dispose_exact_unpublished_candidate(
                    route_root,
                    claim.effect_run_id,
                ) {
                    Ok(()) => {}
                    // Admission can expire before candidate directory creation.
                    // With the exact prior still selected, absence is the exact
                    // expected pre-effect state rather than guessed cleanup.
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(DriverError::internal(error)),
                }
            }
            Phase::Sealed => {
                let seal = claim.seal.as_ref().ok_or_else(|| {
                    DriverError::internal("interrupted startup publication seal is missing")
                })?;
                startup_generation_fs::StartupGenerationDirectory::open_existing_sealed(
                    route_root,
                    claim.effect_run_id,
                    &seal.projection_set_digest,
                    seal.candidate_count,
                    seal.present_count,
                )
                .map_err(DriverError::internal)?
                .dispose()
                .map_err(DriverError::internal)?;
            }
            _ => unreachable!("prepublication phases were matched above"),
        }
        return Ok(Resolution::Prior {
            observation: prior_observation.clone(),
        });
    }

    let seal = claim
        .seal
        .as_ref()
        .ok_or_else(|| DriverError::internal("interrupted startup publication seal is missing"))?;
    if selected.target() == claim.staging_selector {
        let generation =
            startup_generation_fs::StartupGenerationDirectory::open_existing_published(
                route_root,
                claim.effect_run_id,
                &seal.projection_set_digest,
                seal.candidate_count,
                seal.present_count,
            )
            .map_err(DriverError::internal)?;
        generation
            .observe_selected()
            .map_err(DriverError::internal)?;
        reload_gateway_runtime(state, &seal.projection_set_digest).await?;
        let expected = GatewayGenerationIdentity {
            effect_run_id: claim.effect_run_id,
            sealed_digest: seal.projection_set_digest.clone(),
        };
        observe_running_gateway_generation(state, &expected).await?;
        let confirmed = startup_generation_fs::observe_current_selector(route_root)
            .map_err(DriverError::internal)?;
        if confirmed != selected {
            return Ok(Resolution::Inconclusive);
        }
        generation
            .observe_selected()
            .map_err(DriverError::internal)?;
        return Ok(Resolution::Candidate {
            observation: startup_publication::GatewayPublicationObservation {
                selector: confirmed.target().to_owned(),
                directory_device: confirmed.directory_device(),
                directory_inode: confirmed.directory_inode(),
                effect_run_id: Some(claim.effect_run_id),
                projection_set_digest: Some(seal.projection_set_digest.clone()),
            },
            gateway_reload_digest: seal.projection_set_digest.clone(),
        });
    }

    if !selector_is_recorded_prior(&selected, prior_observation)
        || claim.interrupted_phase == Phase::Observed
    {
        return Ok(Resolution::Inconclusive);
    }
    let runtime_matches_prior = match expected_prior_identity.as_ref() {
        Some(expected) => gateway::observe_running_gateway_generation_identity(state)
            .await
            .is_ok_and(|observed| observed == *expected),
        // `boot-live` is the sole legacy generation without an embedded
        // identity endpoint. Its exact selector, directory identity, canonical
        // filesystem absence, and nullable database identity are the complete
        // legacy proof. A transport or parse failure is never reclassified as
        // evidence.
        None => true,
    };
    let confirmed = startup_generation_fs::observe_current_selector(route_root)
        .map_err(DriverError::internal)?;
    if !runtime_matches_prior || confirmed != selected {
        return Ok(Resolution::Inconclusive);
    }

    // A database publication-start transition can commit before the local
    // marker is installed. Exact sealed-without-marker bytes are still safely
    // disposable when both selector and worker prove the prior generation.
    match startup_generation_fs::StartupGenerationDirectory::open_existing_sealed(
        route_root,
        claim.effect_run_id,
        &seal.projection_set_digest,
        seal.candidate_count,
        seal.present_count,
    ) {
        Ok(candidate) => candidate.dispose().map_err(DriverError::internal)?,
        Err(_) => {
            startup_generation_fs::StartupGenerationDirectory::open_existing_published(
                route_root,
                claim.effect_run_id,
                &seal.projection_set_digest,
                seal.candidate_count,
                seal.present_count,
            )
            .map_err(DriverError::internal)?;
        }
    }
    Ok(Resolution::Prior {
        observation: prior_observation.clone(),
    })
}

async fn reconcile_interrupted_startup_publications(
    state: &DriverState,
    route_root: &Path,
) -> Result<bool, DriverError> {
    for _ in 0..STARTUP_INTERRUPTED_RECONCILIATION_LIMIT {
        let claim =
            startup_publication::claim_interrupted(state, ROUTE_APPLICATION_LEASE_SECONDS).await?;
        let startup_publication::InterruptedPublicationClaim::Acquired(claim) = claim else {
            return match claim {
                startup_publication::InterruptedPublicationClaim::None => Ok(true),
                startup_publication::InterruptedPublicationClaim::Invalid => Err(
                    DriverError::internal("interrupted startup publication claim is invalid"),
                ),
                startup_publication::InterruptedPublicationClaim::Acquired(_) => unreachable!(),
            };
        };
        let resolution =
            match reconcile_interrupted_publication_claim(state, route_root, &claim).await {
                Ok(resolution) => resolution,
                Err(error) => {
                    tracing::warn!(
                        error_class = error.safe_class(),
                        "interrupted startup publication evidence was inconclusive"
                    );
                    startup_publication::InterruptedPublicationResolution::Inconclusive
                }
            };
        let inconclusive = matches!(
            resolution,
            startup_publication::InterruptedPublicationResolution::Inconclusive
        );
        startup_publication::finish_interrupted(state, &claim, &resolution).await?;
        if inconclusive {
            return Ok(false);
        }
    }
    Err(DriverError::internal(
        "interrupted startup publication reconciliation bound was exhausted",
    ))
}

pub(super) async fn observe_runtime_inventory_bounded(
    state: &DriverState,
    maximum_items: usize,
) -> Result<usize, DriverError> {
    if maximum_items == 0 {
        return Err(DriverError::internal(
            "runtime inventory observation bound is invalid",
        ));
    }
    let mut observed_count = 0_usize;
    match &state.backend {
        RuntimeBackend::Docker => {
            let mut before = None;
            loop {
                let page = docker_workspace_container_page(
                    state,
                    before.as_deref(),
                    WORKSPACE_RUNTIME_PAGE_LIMIT,
                )
                .await?;
                observed_count = observed_count
                    .checked_add(page.names.len())
                    .ok_or_else(|| DriverError::internal("runtime inventory count overflowed"))?;
                if observed_count > maximum_items {
                    return Err(DriverError::internal(
                        "runtime inventory exceeded its startup observation bound",
                    ));
                }
                let full = page.names.len() == WORKSPACE_RUNTIME_PAGE_LIMIT;
                if full && page.next_cursor.as_deref() == before.as_deref() {
                    return Err(DriverError::internal(
                        "workspace runtime cursor did not advance",
                    ));
                }
                before = page.next_cursor;
                if !full {
                    break;
                }
            }
        }
        RuntimeBackend::Quadlet(backend) => {
            let mut after = None;
            loop {
                let page = backend
                    .workspace_resource_page(after.as_deref(), WORKSPACE_RUNTIME_PAGE_LIMIT)?;
                observed_count = observed_count
                    .checked_add(page.len())
                    .ok_or_else(|| DriverError::internal("runtime inventory count overflowed"))?;
                if observed_count > maximum_items {
                    return Err(DriverError::internal(
                        "runtime inventory exceeded its startup observation bound",
                    ));
                }
                let full = page.len() == WORKSPACE_RUNTIME_PAGE_LIMIT;
                let next = page.last().cloned();
                if full && next.as_ref() == after.as_ref() {
                    return Err(DriverError::internal(
                        "workspace runtime cursor did not advance",
                    ));
                }
                after = next;
                if !full {
                    break;
                }
            }
        }
    }
    tracing::info!(
        runtime.observed_count = observed_count,
        runtime.page_limit = WORKSPACE_RUNTIME_PAGE_LIMIT,
        runtime.maximum_items = maximum_items,
        "observed bounded startup runtime inventory"
    );
    Ok(observed_count)
}

pub(super) async fn reconcile_frozen_active_odoo(
    state: &DriverState,
    identity: &startup_publication::ActiveRuntimeIdentity,
) -> Result<String, DriverError> {
    let container = state
        .config
        .docker_resource(format!("odoo-{}", identity.slot));
    match &state.backend {
        RuntimeBackend::Quadlet(_) => {
            reconcile_active_odoo(
                state,
                &container,
                &identity.deployment_ref,
                &identity.config_digest,
            )
            .await?;
        }
        RuntimeBackend::Docker => {
            if !docker_container_exists(state, &container).await? {
                return Err(DriverError::internal(
                    "frozen active Odoo runtime is missing",
                ));
            }
            let inspect = docker_inspect_container(state, &container).await?;
            for (pointer, expected) in [
                ("/Config/Labels/mb.kind", "odoo-release-runtime"),
                (
                    "/Config/Labels/mb.workspace",
                    state.config.workspace_namespace.as_str(),
                ),
                (
                    "/Config/Labels/mb.image-digest",
                    identity.deployment_ref.as_str(),
                ),
                (
                    "/Config/Labels/mb.config-digest",
                    identity.config_digest.as_str(),
                ),
                ("/Config/Image", identity.deployment_ref.as_str()),
            ] {
                if inspect.pointer(pointer).and_then(Value::as_str) != Some(expected) {
                    return Err(DriverError::internal(
                        "frozen active Odoo runtime identity mismatch",
                    ));
                }
            }
            docker_ensure_restart_policy(state, &container, DockerRestartPolicy::UnlessStopped)
                .await?;
            if inspect.pointer("/State/Running").and_then(Value::as_bool) != Some(true) {
                docker_start_container(state, &container).await?;
            }
        }
    }
    Ok(container)
}

pub(super) fn render_staged_startup_route(
    state: &DriverState,
    route: &startup_publication::StagedStartupRoute,
    active_container: &str,
) -> Result<Option<String>, DriverError> {
    match (route.disposition, route.action) {
        (
            startup_publication::RouteDisposition::Absent,
            startup_publication::RouteAction::RemoveAbsent,
        ) => route_projection::RouteProjection::parse(
            &route.projection,
            &route.projection_digest,
            route_projection::RouteDisposition::Absent,
        )?
        .render(None)
        .map(route_projection::RenderedRoute::into_contents),
        (
            startup_publication::RouteDisposition::Present,
            startup_publication::RouteAction::Render,
        ) => {
            let projection = route_projection::RouteProjection::parse(
                &route.projection,
                &route.projection_digest,
                route_projection::RouteDisposition::Present,
            )?;
            let paperless_container =
                match route.paperless_mode {
                    startup_publication::PaperlessRouteMode::Absent => None,
                    startup_publication::PaperlessRouteMode::ReadOnly
                    | startup_publication::PaperlessRouteMode::ReadWrite => {
                        route.paperless_hostname.as_deref().ok_or_else(|| {
                            DriverError::internal("frozen Paperless hostname is missing")
                        })?;
                        Some(state.config.docker_resource(format!(
                            "paperless-{}",
                            tenant_key(route.workshop_id)
                        )))
                    }
                };
            projection
                .render(Some(route_projection::RouteRuntime {
                    odoo_upstream: active_container,
                    paperless_upstream: paperless_container.as_deref(),
                }))
                .map(route_projection::RenderedRoute::into_contents)
        }
        _ => Err(DriverError::internal(
            "frozen startup route disposition is invalid",
        )),
    }
}

pub(super) async fn reconcile_frozen_paperless(
    state: &DriverState,
    route: &startup_publication::StagedStartupRoute,
) -> Result<(), DriverError> {
    if route.paperless_mode == startup_publication::PaperlessRouteMode::Absent {
        return Ok(());
    }
    route
        .paperless_service_id
        .ok_or_else(|| DriverError::internal("frozen Paperless service identity is missing"))?;
    let spec = route.paperless_runtime_spec.as_ref().ok_or_else(|| {
        DriverError::internal("frozen Paperless runtime specification is missing")
    })?;
    let config_digest = spec
        .get("config_digest")
        .and_then(Value::as_str)
        .ok_or_else(|| DriverError::internal("frozen Paperless runtime digest is missing"))?;
    let image = spec
        .get("image")
        .and_then(Value::as_str)
        .ok_or_else(|| DriverError::internal("frozen Paperless runtime image is missing"))?;
    let container = state
        .config
        .docker_resource(format!("paperless-{}", tenant_key(route.workshop_id)));
    if spec.get("container_name").and_then(Value::as_str) != Some(container.as_str()) {
        return Err(DriverError::internal(
            "frozen Paperless runtime name is not deterministic",
        ));
    }
    match &state.backend {
        RuntimeBackend::Quadlet(backend) => {
            let unit = format!("mb-paperless-{}", route.workshop_id.simple());
            if !backend.workspace_resource_exists(&unit)? {
                reconstruct_paperless(state, route.workshop_id, &container, spec).await?;
            } else {
                backend
                    .reconcile_persistent_unit(
                        "paperless",
                        &unit,
                        Some(image),
                        config_digest,
                        RuntimeState::Running,
                    )
                    .await?;
            }
        }
        RuntimeBackend::Docker => {
            if !docker_container_exists(state, &container).await? {
                return Err(DriverError::internal("frozen Paperless runtime is missing"));
            }
            let inspect = docker_inspect_container(state, &container).await?;
            for (pointer, expected) in [
                ("/Config/Labels/mb.kind", "paperless"),
                (
                    "/Config/Labels/mb.workspace",
                    state.config.workspace_namespace.as_str(),
                ),
                ("/Config/Labels/mb.config-digest", config_digest),
                ("/Config/Image", image),
            ] {
                if inspect.pointer(pointer).and_then(Value::as_str) != Some(expected) {
                    return Err(DriverError::internal(
                        "frozen Paperless runtime identity mismatch",
                    ));
                }
            }
            if inspect
                .pointer("/Config/Labels/mb.workshop")
                .and_then(Value::as_str)
                != Some(route.workshop_id.to_string().as_str())
            {
                return Err(DriverError::internal(
                    "frozen Paperless workshop identity mismatch",
                ));
            }
            docker_ensure_restart_policy(state, &container, DockerRestartPolicy::UnlessStopped)
                .await?;
            if inspect.pointer("/State/Running").and_then(Value::as_bool) != Some(true) {
                docker_start_container(state, &container).await?;
            }
            wait_for_healthy_container(state, &container, "Paperless").await?;
        }
    }
    Ok(())
}

async fn staged_startup_heartbeat(
    state: &DriverState,
    lease: &startup_publication::StartupPublicationLease,
) -> DriverError {
    let first_renewal = tokio::time::Instant::now() + STARTUP_ROUTE_HEARTBEAT_INTERVAL;
    let mut interval = tokio::time::interval_at(first_renewal, STARTUP_ROUTE_HEARTBEAT_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        interval.tick().await;
        match tokio::time::timeout(
            STARTUP_ROUTE_HEARTBEAT_TIMEOUT,
            startup_publication::renew(state, lease, ROUTE_APPLICATION_LEASE_SECONDS),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(error)) => return error,
            Err(_) => return DriverError::internal("startup publication heartbeat timed out"),
        }
    }
}

#[tracing::instrument(
    name = "deployment_driver.startup_publication.execute",
    skip_all,
    fields(publication.effect_run_id = %lease.effect_run_id)
)]
async fn execute_staged_startup_publication(
    state: &DriverState,
    lease: &startup_publication::StartupPublicationLease,
) -> Result<usize, DriverError> {
    let prior = startup_generation_fs::observe_current_selector(&state.config.route_root)
        .map_err(DriverError::internal)?;
    let prior_identity =
        startup_generation_fs::observe_prior_gateway_identity(&state.config.route_root, &prior)
            .map_err(DriverError::internal)?;
    if let Some(identity) = prior_identity.as_ref() {
        observe_running_gateway_generation(state, identity).await?;
    }
    let confirmed_prior = startup_generation_fs::observe_current_selector(&state.config.route_root)
        .map_err(DriverError::internal)?;
    if confirmed_prior != prior {
        return Err(DriverError::internal(
            "startup selector changed during prior gateway observation",
        ));
    }
    let prior_observation = prior_gateway_observation(&prior, prior_identity.as_ref());
    startup_publication::record_prior(state, lease, &prior_observation).await?;
    startup_publication::begin(state, lease).await?;

    let mut generation = None;
    let mut publication_started = false;
    let effect = async {
        if lease.fleet_release_unresolved {
            return Err(DriverError::internal(
                "frozen startup publication release authority is unresolved",
            ));
        }
        let active_runtime = lease.active_runtime.as_ref().ok_or_else(|| {
            DriverError::internal("frozen active Odoo runtime identity is unavailable")
        })?;
        let inventory_bound = lease
            .reserved_count
            .checked_add(1_024)
            .ok_or_else(|| DriverError::internal("runtime inventory bound overflowed"))?;
        observe_runtime_inventory_bounded(state, inventory_bound).await?;
        let active_container = reconcile_frozen_active_odoo(state, active_runtime).await?;

        generation = Some(
            startup_generation_fs::StartupGenerationDirectory::create(
                &state.config.route_root,
                lease.effect_run_id,
            )
            .map_err(DriverError::internal)?,
        );
        let (sealed, opened) = {
            let mut sealer = generation
                .as_mut()
                .expect("startup generation was created")
                .begin_seal()
                .map_err(DriverError::internal)?;
            let mut after = None;
            let mut candidate_count = 0_usize;
            let mut opened = 0_usize;
            loop {
                let batch = startup_publication::read_batch(
                    state,
                    lease,
                    after,
                    startup_publication::STARTUP_PUBLICATION_MAX_BATCH,
                )
                .await?;
                let full = batch.routes.len() == startup_publication::STARTUP_PUBLICATION_MAX_BATCH;
                if full && batch.next_cursor == after {
                    return Err(DriverError::internal(
                        "startup publication route cursor did not advance",
                    ));
                }
                for route in &batch.routes {
                    if route.unresolved_operation {
                        return Err(DriverError::internal(
                            "frozen startup route has unresolved tenant authority",
                        ));
                    }
                    let (runtime, contents) = match route.disposition {
                        startup_publication::RouteDisposition::Absent => (
                            startup_publication::StartupRuntimeObservation::absent(
                                lease,
                                route,
                                time::OffsetDateTime::now_utc().unix_timestamp().to_string(),
                            )?,
                            None,
                        ),
                        startup_publication::RouteDisposition::Present => {
                            let database_ref = route.database_ref.clone().ok_or_else(|| {
                                DriverError::internal(
                                    "frozen startup database reference is missing",
                                )
                            })?;
                            let tenant = TenantRoute {
                                workshop: route.workshop_id,
                                database_ref,
                                paperless_base_url: route.paperless_service_base_url.clone(),
                                unresolved_operation: false,
                            };
                            verify_odoo_tenant(state, &active_container, &tenant).await?;
                            reconcile_frozen_paperless(state, route).await?;
                            (
                                startup_publication::StartupRuntimeObservation::ready(
                                    lease,
                                    route,
                                    time::OffsetDateTime::now_utc().unix_timestamp().to_string(),
                                )?,
                                render_staged_startup_route(state, route, &active_container)?,
                            )
                        }
                    };
                    let seal_evidence = if let Some(contents) = contents.as_deref() {
                        opened = opened.checked_add(1).ok_or_else(|| {
                            DriverError::internal("startup opened route count overflowed")
                        })?;
                        sealer
                            .stage_present(
                                route.workshop_id,
                                route.generation,
                                &route.projection_digest,
                                contents.as_bytes(),
                            )
                            .map_err(DriverError::internal)?
                    } else {
                        sealer
                            .stage_absent(
                                route.workshop_id,
                                route.generation,
                                &route.projection_digest,
                            )
                            .map_err(DriverError::internal)?
                    };
                    startup_publication::record_candidate(
                        state,
                        lease,
                        after,
                        route,
                        &runtime,
                        &seal_evidence.rendered_digest,
                    )
                    .await?;
                    after = Some(route.workshop_id);
                    candidate_count = candidate_count.checked_add(1).ok_or_else(|| {
                        DriverError::internal("startup publication candidate count overflowed")
                    })?;
                }
                if !full {
                    break;
                }
            }
            if candidate_count != lease.reserved_count {
                return Err(DriverError::internal(
                    "startup publication reserved count changed while staging",
                ));
            }
            let sealed = sealer.finish().map_err(DriverError::internal)?.clone();
            (sealed, opened)
        };

        let seal = startup_publication::StartupPublicationSeal {
            candidate_count: sealed.route_count,
            projection_set_digest: sealed.sealed_digest.clone(),
        };
        if seal.candidate_count != lease.reserved_count {
            return Err(DriverError::internal(
                "filesystem and database startup publication counts differ",
            ));
        }
        startup_publication::seal(state, lease, &seal).await?;

        // From immediately before this durable transition onward, every error
        // is an unknown publication outcome and must be left to reconciliation.
        publication_started = true;
        startup_publication::start_publication(state, lease, &seal.projection_set_digest).await?;
        generation
            .as_mut()
            .expect("sealed startup generation is retained")
            .publish(&prior)
            .map_err(DriverError::internal)?;
        reload_gateway_runtime(state, &seal.projection_set_digest).await?;
        observe_running_gateway_generation(state, &sealed.identity).await?;
        generation
            .as_ref()
            .expect("published startup generation is retained")
            .observe_selected()
            .map_err(DriverError::internal)?;
        let selected = startup_generation_fs::observe_generation_selector(
            &state.config.route_root,
            &lease.staging_selector,
        )
        .map_err(DriverError::internal)?;
        let observation = startup_publication::GatewayPublicationObservation {
            selector: selected.target().to_owned(),
            directory_device: selected.directory_device(),
            directory_inode: selected.directory_inode(),
            effect_run_id: Some(lease.effect_run_id),
            projection_set_digest: Some(seal.projection_set_digest.clone()),
        };
        startup_publication::observe(state, lease, &observation).await?;
        startup_publication::finish(state, lease, &seal, &seal.projection_set_digest).await?;
        Ok(opened)
    }
    .await;

    if effect.is_err() && !publication_started {
        let observed_prior =
            startup_generation_fs::observe_current_selector(&state.config.route_root)
                .map_err(DriverError::internal)?;
        if observed_prior != prior {
            return Err(DriverError::internal(
                "startup selector changed before prepublication cleanup",
            ));
        }
        if let Some(candidate) = generation.take() {
            candidate.dispose().map_err(DriverError::internal)?;
        }
        startup_publication::abort(state, lease, &prior_observation).await?;
    }
    effect
}

fn staged_unavailable_error_class(
    reason: startup_publication::StartupPublicationUnavailable,
) -> &'static str {
    match reason {
        startup_publication::StartupPublicationUnavailable::Busy => "route_authority_busy",
        startup_publication::StartupPublicationUnavailable::Quarantined => {
            "route_authority_quarantined"
        }
        startup_publication::StartupPublicationUnavailable::DigestConflict => {
            "route_authority_conflict"
        }
        startup_publication::StartupPublicationUnavailable::RuntimeIdentityMissing => {
            "runtime_identity_missing"
        }
        startup_publication::StartupPublicationUnavailable::RuntimeAmbiguous => {
            "runtime_identity_ambiguous"
        }
        startup_publication::StartupPublicationUnavailable::InitializationRequired => {
            "route_initialization_required"
        }
        startup_publication::StartupPublicationUnavailable::Invalid => "route_authority_invalid",
    }
}

pub(super) async fn reconcile(state: &DriverState) -> StartupReport {
    let mut report = StartupReport::default();
    let _shared_odoo_host_guard =
        match host_guard::SharedOdooHostGuard::acquire(&state.config.route_root).await {
            Ok(guard) => guard,
            Err(error) => {
                report.degraded("runtime-backend", DriverError::internal(error).safe_class());
                return report;
            }
        };
    // Resolve expired staged publications while holding the same host guard
    // as normal admission. An inconclusive claim retains quarantine and must
    // keep both backend and command readiness false for this boot.
    match reconcile_interrupted_startup_publications(state, &state.config.route_root).await {
        Ok(true) => {}
        Ok(false) => {
            report.degraded("gateway", "route_authority_quarantined");
            return report;
        }
        Err(error) => {
            report.degraded("gateway", error.safe_class());
            return report;
        }
    }
    // Admission freezes runtime and route authority before the first runtime
    // discovery call or host effect in this boot.
    let admission = match admit_staged_startup_publication(state).await {
        Ok(admission) => admission,
        Err(error) => {
            report.degraded("gateway", error.safe_class());
            return report;
        }
    };
    match admission {
        startup_publication::StartupPublicationAdmission::Replay(response) => {
            let inventory_bound = response
                .get("workshop_count")
                .and_then(Value::as_u64)
                .and_then(|count| usize::try_from(count).ok())
                .and_then(|count| count.checked_add(1_024))
                .unwrap_or(1_024);
            match observe_runtime_inventory_bounded(state, inventory_bound).await {
                Ok(_) => report.backend_ready = true,
                Err(error) => report.degraded("runtime-backend", error.safe_class()),
            }
            report.routes_authoritative = true;
        }
        startup_publication::StartupPublicationAdmission::Unavailable(reason) => {
            report.degraded("gateway", staged_unavailable_error_class(reason));
        }
        startup_publication::StartupPublicationAdmission::Acquired(lease) => {
            let execution = execute_staged_startup_publication(state, &lease);
            match with_startup_route_heartbeat(execution, staged_startup_heartbeat(state, &lease))
                .await
            {
                Ok(opened) => {
                    report.backend_ready = true;
                    report.routes_opened = opened;
                    report.routes_authoritative = true;
                }
                Err(error) => report.degraded("gateway", error.safe_class()),
            }
        }
    }
    report
}

#[allow(dead_code)]
async fn reconcile_legacy(state: &DriverState) -> StartupReport {
    let mut report = StartupReport::default();
    // Startup observes and may reconcile the same shared Odoo runtime and
    // gateway selector as a fleet release. Keep the cross-process host guard
    // for the complete observation/effect/finalization interval; database
    // admission happens only after this non-transactional wait.
    let _shared_odoo_host_guard =
        match host_guard::SharedOdooHostGuard::acquire(&state.config.route_root).await {
            Ok(guard) => guard,
            Err(error) => {
                report.degraded("runtime-backend", DriverError::internal(error).safe_class());
                return report;
            }
        };
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
            report.degraded("runtime-backend", error.safe_class());
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
            report.degraded(
                "driver-ledger",
                crate::error_reporting::safe_error_class(&error),
            );
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
                    Err(error) => report.degraded(format!("odoo-slot:{slot}"), error.safe_class()),
                }
            }
            "inactive" | "retained" | "failed" => {
                if let Err(error) = stop_non_active_runtime(state, &container).await {
                    report.degraded(format!("odoo-slot:{slot}"), error.safe_class());
                }
            }
            // Candidate state is owned by the interrupted release operation. Do not
            // start, stop, delete, or otherwise reinterpret it during boot.
            "starting" | "verifying" | "prepared" => {}
            _ => report.degraded(format!("odoo-slot:{slot}"), "runtime_state_contract"),
        }
    }

    let tenants = match load_tenant_routes(state).await {
        Ok(value) => value,
        Err(error) => {
            report.backend_ready = false;
            report.degraded("driver-ledger", error.safe_class());
            return report;
        }
    };
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
                report.degraded(
                    format!("paperless-fence:{}", tenant.workshop),
                    error.safe_class(),
                );
            }
            continue;
        }
        match reconcile_paperless(state, tenant.workshop, &container).await {
            Ok(()) => {}
            Err(error) => {
                report.degraded(format!("paperless:{}", tenant.workshop), error.safe_class())
            }
        }
    }

    report.unknown_resources = unknown_resources(observed, &expected);
    if !report.unknown_resources.is_empty() {
        tracing::warn!(
            resource_class = "unknown_workspace_runtime",
            count = report.unknown_resources.len(),
            "leaving unknown workspace runtimes untouched during startup"
        );
    }

    if release_unresolved || candidate_present {
        if release_unresolved || candidate_present {
            report.degraded_resources.push("release-fence".into());
        }
        return report;
    }
    let mut verified_tenants = BTreeMap::new();
    for tenant in &tenants {
        if tenant.unresolved_operation {
            report
                .degraded_resources
                .push(format!("tenant-fence:{}", tenant.workshop));
            continue;
        }
        let Some(active_container) = active_container.as_deref() else {
            report.degraded(
                format!("odoo-tenant:{}", tenant.workshop),
                "runtime_unavailable",
            );
            continue;
        };
        if let Err(error) = verify_odoo_tenant(state, active_container, tenant).await {
            report.degraded(
                format!("odoo-tenant:{}", tenant.workshop),
                error.safe_class(),
            );
            continue;
        }
        verified_tenants.insert(tenant.workshop, tenant.database_ref.clone());
    }

    let admission = match admit_startup_route_rebuild(state).await {
        Ok(admission) => admission,
        Err(error) => {
            report.degraded("gateway", error.safe_class());
            return report;
        }
    };
    let lease = match admission {
        StartupRouteAdmission::Replay => {
            report.routes_authoritative = true;
            return report;
        }
        StartupRouteAdmission::Unavailable(error_class) => {
            report.degraded("gateway", error_class);
            return report;
        }
        StartupRouteAdmission::Acquired(lease) => lease,
    };
    let execution = execute_startup_route_rebuild(
        state,
        &lease,
        active_container.as_deref(),
        &verified_tenants,
    );
    match with_startup_route_heartbeat(execution, startup_route_heartbeat(state, &lease)).await {
        Ok(opened) => {
            report.routes_opened = opened;
            report.routes_authoritative = true;
        }
        Err(error) => {
            let _ = fail_closed_startup_route_rebuild(state, &lease).await;
            report.degraded("gateway", error.safe_class());
        }
    }
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

pub(super) async fn verify_odoo_tenant(
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
    let client = odoo_readiness_client()?;
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
        let response = odoo_readiness_request(
            &client,
            format!("{base_url}/mb_control/v1/health"),
            &tenant.database_ref,
            token.trim(),
            Some(Duration::from_secs(3)),
        )
        .with_current_trace_context()
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
    const BATCH_SIZE: usize = 500;

    let mut transaction = state.ledger.begin().await.map_err(DriverError::internal)?;
    sqlx::query("set transaction isolation level repeatable read read only")
        .execute(&mut *transaction)
        .await
        .map_err(DriverError::internal)?;
    let mut after = None;
    let mut tenants = Vec::new();
    loop {
        let rows = sqlx::query_as::<_, (Uuid, String, Option<String>, bool)>(
            "select w.id,d.database_ref,
                (select s.base_url from control.service_instances s
                  where s.workshop_id=w.id and s.service='paperless'
                    and s.health not in ('suspended','failed')),
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
            and ($1::uuid is null or w.id>$1)
          order by w.id
          limit $2",
        )
        .bind(after)
        .bind(i64::try_from(BATCH_SIZE).expect("startup batch size is bounded"))
        .fetch_all(&mut *transaction)
        .await
        .map_err(DriverError::internal)?;
        if rows.is_empty() {
            break;
        }
        after = rows.last().map(|row| row.0);
        let complete = rows.len() < BATCH_SIZE;
        tenants.extend(rows.into_iter().map(
            |(workshop, database_ref, paperless_base_url, unresolved_operation)| TenantRoute {
                workshop,
                database_ref,
                paperless_base_url,
                unresolved_operation,
            },
        ));
        if complete {
            break;
        }
    }
    transaction.commit().await.map_err(DriverError::internal)?;
    Ok(tenants)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    struct CancellationGuard(Arc<AtomicBool>);

    impl Drop for CancellationGuard {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn heartbeat_loss_cancels_the_startup_route_effect() {
        let cancelled = Arc::new(AtomicBool::new(false));
        let effect_cancelled = Arc::clone(&cancelled);
        let effect = async move {
            let _guard = CancellationGuard(effect_cancelled);
            std::future::pending::<Result<(), DriverError>>().await
        };
        let heartbeat = async { DriverError::internal("simulated heartbeat loss") };

        let result = with_startup_route_heartbeat(effect, heartbeat).await;

        assert!(result.is_err());
        assert!(cancelled.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn completed_startup_route_effect_cancels_its_heartbeat() {
        let cancelled = Arc::new(AtomicBool::new(false));
        let heartbeat_cancelled = Arc::clone(&cancelled);
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let heartbeat = async move {
            let _guard = CancellationGuard(heartbeat_cancelled);
            let _ = started_tx.send(());
            std::future::pending::<DriverError>().await
        };
        let effect = async move {
            started_rx.await.unwrap();
            Ok::<_, DriverError>(7)
        };

        let result = with_startup_route_heartbeat(effect, heartbeat)
            .await
            .unwrap();

        assert_eq!(result, 7);
        assert!(cancelled.load(Ordering::SeqCst));
    }

    #[test]
    fn startup_route_heartbeat_has_timeout_margin() {
        assert!(STARTUP_ROUTE_HEARTBEAT_TIMEOUT < STARTUP_ROUTE_HEARTBEAT_INTERVAL);
        assert!(
            STARTUP_ROUTE_HEARTBEAT_INTERVAL * 3
                < Duration::from_secs(ROUTE_APPLICATION_LEASE_SECONDS as u64)
        );
    }

    #[test]
    fn readiness_requires_backend_and_authoritative_route_rebuild() {
        let mut report = StartupReport {
            backend_ready: true,
            ..StartupReport::default()
        };
        assert!(!report.command_ready());
        report.routes_authoritative = true;
        assert!(report.command_ready());
        report.backend_ready = false;
        assert!(!report.command_ready());
    }

    #[test]
    fn startup_log_resource_classes_are_closed_and_low_cardinality() {
        assert_eq!(
            safe_startup_resource_class("odoo-tenant:00000000-0000-0000-0000-000000000001"),
            "odoo_tenant"
        );
        assert_eq!(
            safe_startup_resource_class("private-workshop.example.test:/run/secrets/token"),
            "unknown"
        );
    }

    #[test]
    fn staged_publication_unavailability_is_low_cardinality() {
        use startup_publication::StartupPublicationUnavailable as Unavailable;

        assert_eq!(
            staged_unavailable_error_class(Unavailable::Busy),
            "route_authority_busy"
        );
        assert_eq!(
            staged_unavailable_error_class(Unavailable::Quarantined),
            "route_authority_quarantined"
        );
        assert_eq!(
            staged_unavailable_error_class(Unavailable::RuntimeIdentityMissing),
            "runtime_identity_missing"
        );
        assert_eq!(
            staged_unavailable_error_class(Unavailable::RuntimeAmbiguous),
            "runtime_identity_ambiguous"
        );
    }

    #[test]
    fn staged_publication_has_one_explicit_unknown_outcome_boundary() {
        let source = include_str!("startup.rs");
        let staged = source
            .split_once("async fn execute_staged_startup_publication")
            .unwrap()
            .1
            .split_once("fn staged_unavailable_error_class")
            .unwrap()
            .0;
        let start = staged
            .find("publication_started = true;")
            .expect("publication boundary must be explicit");
        let database_start = staged
            .find("startup_publication::start_publication")
            .expect("database publication transition must exist");
        let filesystem_publish = staged
            .find(".publish(&prior)")
            .expect("filesystem selector publication must exist");
        let cleanup = staged
            .find("if effect.is_err() && !publication_started")
            .expect("prepublication cleanup must be phase-gated");

        assert!(start < database_start);
        assert!(database_start < filesystem_publish);
        assert!(filesystem_publish < cleanup);
        assert!(!staged.contains("fail_closed_startup_route_rebuild"));
    }

    #[test]
    fn interrupted_publication_reconciliation_precedes_new_admission_and_is_bounded() {
        let source = include_str!("startup.rs");
        let reconcile = source
            .split_once("pub(super) async fn reconcile(state: &DriverState)")
            .unwrap()
            .1
            .split_once("async fn reconcile_legacy")
            .unwrap()
            .0;
        let interrupted = reconcile
            .find("reconcile_interrupted_startup_publications(state, &state.config.route_root)")
            .unwrap();
        let admission = reconcile
            .find("admit_staged_startup_publication(state)")
            .unwrap();
        assert!(interrupted < admission);

        let recovery = source
            .split_once("async fn reconcile_interrupted_startup_publications")
            .unwrap()
            .1
            .split_once("async fn observe_runtime_inventory_bounded")
            .unwrap()
            .0;
        assert!(recovery.contains("0..STARTUP_INTERRUPTED_RECONCILIATION_LIMIT"));
        assert!(recovery.contains("InterruptedPublicationResolution::Inconclusive"));
    }

    #[test]
    fn interrupted_publication_crash_matrix_preserves_selector_evidence_order() {
        let source = include_str!("startup.rs");
        let recovery = source
            .split_once("async fn reconcile_interrupted_publication_claim")
            .unwrap()
            .1
            .split_once("async fn reconcile_interrupted_startup_publications")
            .unwrap()
            .0;

        assert!(recovery.contains("Resolution::Unstarted"));
        assert!(recovery.contains("Phase::Staging | Phase::Sealed"));
        assert!(recovery.contains("dispose_exact_unpublished_candidate"));
        assert!(recovery.contains("std::io::ErrorKind::NotFound"));
        assert!(recovery.contains("open_existing_sealed"));
        assert!(recovery.contains("open_existing_published"));
        assert!(!recovery.contains(".publish("));
        assert!(!recovery.contains("restore_prior"));

        let selected = recovery.find("let selected =").unwrap();
        let candidate = recovery
            .find("if selected.target() == claim.staging_selector")
            .unwrap();
        let published = recovery[candidate..]
            .find("open_existing_published")
            .unwrap()
            + candidate;
        let reload = recovery[candidate..]
            .find("reload_gateway_runtime")
            .unwrap()
            + candidate;
        let worker = recovery[candidate..]
            .find("observe_running_gateway_generation(state, &expected)")
            .unwrap()
            + candidate;
        let confirmed = recovery[candidate..].find("let confirmed =").unwrap() + candidate;
        assert!(selected < candidate);
        assert!(candidate < published);
        assert!(published < reload);
        assert!(reload < worker);
        assert!(worker < confirmed);

        let nullable_prior = recovery
            .split_once("None => true")
            .expect("boot-live uses explicit nullable identity evidence");
        assert!(
            !nullable_prior
                .0
                .rsplit_once("Some(expected) =>")
                .unwrap()
                .1
                .contains(".is_err()")
        );
    }

    #[test]
    fn staged_route_loop_uses_the_protocol_batch_bound() {
        let source = include_str!("startup.rs");
        let staged = source
            .split_once("async fn execute_staged_startup_publication")
            .unwrap()
            .1
            .split_once("fn staged_unavailable_error_class")
            .unwrap()
            .0;
        assert!(staged.contains("startup_publication::STARTUP_PUBLICATION_MAX_BATCH"));
        assert!(staged.contains(".stage_present("));
        assert!(staged.contains(".stage_absent("));
        assert!(!staged.contains("Vec<StartupRenderedRoute>"));
        assert!(!staged.contains("BTreeMap<Uuid, String>"));
    }

    #[test]
    fn startup_tenant_discovery_is_keyset_batched_from_one_coherent_snapshot() {
        let startup = include_str!("startup.rs");
        let production = startup.rsplit_once("#[cfg(test)]").unwrap().0;
        assert!(production.contains("set transaction isolation level repeatable read read only"));
        assert!(production.contains("and ($1::uuid is null or w.id>$1)"));
        assert!(production.contains("limit $2"));
        assert!(!production.contains(
            "and d.state not in ('restoring','deleted') and d.public_hostname is not null\n          order by w.id"
        ));
    }

    #[test]
    fn odoo_readiness_transport_is_reused_with_request_local_tenant_authority() {
        let first_transport = odoo_readiness_client().unwrap();
        let second_transport = odoo_readiness_client().unwrap();
        assert_eq!(
            ODOO_READINESS_HTTP_BUILDS.load(std::sync::atomic::Ordering::SeqCst),
            1
        );

        let first = odoo_readiness_request(
            &first_transport,
            "http://odoo.example.test/mb_control/v1/health",
            "mb_00000000000000000000000000000001",
            "first-tenant-token",
            Some(Duration::from_secs(3)),
        )
        .build()
        .unwrap();
        let second = odoo_readiness_request(
            &second_transport,
            "http://odoo.example.test/mb_control/v1/health",
            "mb_00000000000000000000000000000002",
            "second-tenant-token",
            None,
        )
        .build()
        .unwrap();
        let bare = first_transport
            .get("http://odoo.example.test/mb_control/v1/health")
            .build()
            .unwrap();

        assert_eq!(
            first.headers()[reqwest::header::AUTHORIZATION],
            "Bearer first-tenant-token"
        );
        assert_eq!(
            first.headers()["x-odoo-dbfilter"],
            "mb_00000000000000000000000000000001"
        );
        assert_eq!(first.timeout(), Some(&Duration::from_secs(3)));
        assert_eq!(
            second.headers()[reqwest::header::AUTHORIZATION],
            "Bearer second-tenant-token"
        );
        assert_eq!(
            second.headers()["x-odoo-dbfilter"],
            "mb_00000000000000000000000000000002"
        );
        assert_eq!(second.timeout(), None);
        assert!(bare.headers().get(reqwest::header::AUTHORIZATION).is_none());
        assert!(bare.headers().get("x-odoo-dbfilter").is_none());
    }

    #[tokio::test]
    async fn odoo_readiness_transport_sends_its_identity_and_tenant_authority() {
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/mb_control/v1/health"))
            .and(header(
                "user-agent",
                "mb-control-container-driver/odoo-readiness",
            ))
            .and(header("authorization", "Bearer tenant-token"))
            .and(header(
                "x-odoo-dbfilter",
                "mb_00000000000000000000000000000001",
            ))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&server)
            .await;

        let response = odoo_readiness_request(
            &odoo_readiness_client().unwrap(),
            format!("{}/mb_control/v1/health", server.uri()),
            "mb_00000000000000000000000000000001",
            "tenant-token",
            Some(Duration::from_secs(2)),
        )
        .send()
        .await
        .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::NO_CONTENT);
    }

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
