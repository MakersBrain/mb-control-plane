use super::*;

pub(super) async fn release_fleet(
    state: &DriverState,
    payload: &Value,
) -> Result<Value, DriverError> {
    if payload.get("phase").and_then(Value::as_str) != Some("adopt-fleet") {
        return Err(DriverError::bad("invalid release fleet request"));
    }
    let fleet_run = payload_uuid(payload, "fleet_run_id")?;
    let release_id = payload
        .get("release_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| DriverError::bad("release_id is required"))?;
    let run =
        sqlx::query("select state from control.release_fleet_runs where id=$1 and release_id=$2")
            .bind(fleet_run)
            .bind(release_id)
            .fetch_optional(&state.ledger)
            .await
            .map_err(DriverError::internal)?
            .ok_or_else(|| DriverError(StatusCode::NOT_FOUND, "fleet run not found".into()))?;
    let run_state: String = run.get("state");
    if run_state == "active" {
        let evidence = sqlx::query_scalar::<_, Value>(
            "select evidence from control.release_fleet_runs where id=$1",
        )
        .bind(fleet_run)
        .fetch_one(&state.ledger)
        .await
        .map_err(DriverError::internal)?;
        return Ok(json!({"evidence":evidence,"observed":true}));
    }
    if !matches!(run_state.as_str(), "preparing" | "activating") {
        return Err(DriverError::bad("fleet run is not adoptable"));
    }
    let release_row = sqlx::query(
        "select manifest,status,image_digest from control.application_releases where id=$1",
    )
    .bind(release_id)
    .fetch_optional(&state.ledger)
    .await
    .map_err(DriverError::internal)?
    .ok_or_else(|| {
        DriverError(
            StatusCode::NOT_FOUND,
            "application release not found".into(),
        )
    })?;
    if release_row.get::<String, _>("status") != "prepared" {
        return Err(DriverError::bad("application release is not prepared"));
    }
    let manifest: crate::release::ApplicationReleaseManifest =
        serde_json::from_value(release_row.get("manifest"))
            .map_err(|_| DriverError::bad("stored release manifest is invalid"))?;
    manifest
        .validate()
        .map_err(|_| DriverError::bad("stored release manifest is invalid"))?;
    if manifest.release_id != release_id
        || manifest.image_digest != release_row.get::<String, _>("image_digest")
    {
        return Err(DriverError::bad(
            "release identity does not match its manifest",
        ));
    }

    let active_slot = sqlx::query_as::<_, (String, String)>(
        "select slot,release_id from control.runtime_release_slots
         where runtime_key='shared-odoo' and state='active'",
    )
    .fetch_optional(&state.ledger)
    .await
    .map_err(DriverError::internal)?;
    let target_slot = if active_slot.as_ref().is_some_and(|row| row.0 == "blue") {
        "green"
    } else {
        "blue"
    };
    let runtime_role = release_runtime_role(&manifest.image_digest);
    let runtime_password = ensure_release_runtime_role(state, &runtime_role).await?;
    let tenants = release_tenants(state, fleet_run, release_id).await?;
    if tenants.is_empty() {
        return Err(DriverError::bad("fleet run contains no tenants"));
    }

    for tenant in &tenants {
        if let Err(error) =
            prepare_release_tenant(state, tenant, &manifest, &runtime_role, &runtime_password).await
        {
            mark_release_tenant_failed(state, tenant.id, "release_preparation_failed").await?;
            sqlx::query(
                "update control.release_fleet_runs set state='paused',failure_class='tenant_preparation_failed',updated_at=now()
                 where id=$1 and state='preparing'",
            )
            .bind(fleet_run)
            .execute(&state.ledger)
            .await
            .map_err(DriverError::internal)?;
            return Err(error);
        }
    }

    let runtime_container = format!("makersbrain-odoo-{target_slot}");
    ensure_release_runtime(
        state,
        &runtime_container,
        &manifest.provenance.oci_ref,
        &runtime_role,
        &runtime_password,
    )
    .await?;
    for tenant in &tenants {
        smoke_release_runtime(state, &runtime_container, tenant).await?;
    }

    sqlx::query(
        "update control.release_fleet_runs set state='activating',target_slot=$2,updated_at=now()
         where id=$1 and state='preparing'",
    )
    .bind(fleet_run)
    .bind(target_slot)
    .execute(&state.ledger)
    .await
    .map_err(DriverError::internal)?;
    let prepared_tenants = release_tenant_evidence(&tenants);
    let existing_intent = sqlx::query_as::<_, (String, Uuid, Option<String>, Value)>(
        "select gateway_configuration_digest,driver_action_id,
                observed_configuration_digest,prepared_tenants
         from control.fleet_activation_intents where fleet_run_id=$1",
    )
    .bind(fleet_run)
    .fetch_optional(&state.ledger)
    .await
    .map_err(DriverError::internal)?;
    let (gateway_digest, action_id) = if let Some(existing) = existing_intent {
        if existing.3 != prepared_tenants {
            return Err(DriverError::internal(
                "stored fleet activation intent tenant set drifted",
            ));
        }
        (existing.0, existing.1)
    } else {
        let digest = planned_release_route_digest(state, &runtime_container, &tenants)?;
        let action_id = Uuid::new_v4();
        sqlx::query(
            "insert into control.fleet_activation_intents(
           id,fleet_run_id,release_id,runtime_key,target_slot,image_digest,
           prepared_tenants,gateway_configuration_digest,driver_action_id
         ) values($1,$2,$3,'shared-odoo',$4,$5,$6,$7,$8)",
        )
        .bind(Uuid::new_v4())
        .bind(fleet_run)
        .bind(release_id)
        .bind(target_slot)
        .bind(&manifest.image_digest)
        .bind(&prepared_tenants)
        .bind(&digest)
        .bind(action_id)
        .execute(&state.ledger)
        .await
        .map_err(DriverError::internal)?;
        (digest, action_id)
    };
    let observed = observed_release_route_digest(state, &tenants)?;
    if observed.as_deref() != Some(&gateway_digest) {
        let activated = activate_release_routes(state, &runtime_container, &tenants).await?;
        if activated != gateway_digest {
            return Err(DriverError::internal(
                "activated gateway configuration differs from its intent",
            ));
        }
    }
    sqlx::query(
        "update control.fleet_activation_intents
         set observed_configuration_digest=$2,activated_at=coalesce(activated_at,now())
         where fleet_run_id=$1 and gateway_configuration_digest=$2",
    )
    .bind(fleet_run)
    .bind(&gateway_digest)
    .execute(&state.ledger)
    .await
    .map_err(DriverError::internal)?;
    let evidence = json!({
        "release_id":release_id,
        "image_digest":manifest.image_digest,
        "runtime_key":"shared-odoo",
        "target_slot":target_slot,
        "runtime_container":runtime_container,
        "runtime_role":runtime_role,
        "prepared_tenants":prepared_tenants,
        "gateway_configuration_digest":gateway_digest,
        "driver_action_id":action_id,
        "old_runtime_database_access_revoked":true,
        "tenant_recovery_verified":true,
        "candidate_smoke_verified":true
    });
    Ok(json!({"evidence":evidence}))
}

#[derive(Debug, sqlx::FromRow)]
struct ReleaseTenant {
    id: Uuid,
    workshop_id: Uuid,
    database_id: Uuid,
    database_ref: String,
    public_hostname: String,
    backup_recovery_id: Uuid,
    component_scope: Vec<String>,
}

async fn release_tenants(
    state: &DriverState,
    fleet_run: Uuid,
    release_id: &str,
) -> Result<Vec<ReleaseTenant>, DriverError> {
    sqlx::query_as::<_, ReleaseTenant>(
        "select a.id,a.workshop_id,a.database_id,d.database_ref,d.public_hostname,
                a.backup_recovery_id,r.component_scope
         from control.tenant_release_adoptions a
         join control.release_fleet_runs f on f.operation_id=a.operation_id
         join control.odoo_databases d on d.id=a.database_id and d.workshop_id=a.workshop_id
         join control.workshop_recovery_points r on r.id=a.backup_recovery_id
         where f.id=$1 and a.release_id=$2
         order by a.created_at,a.id",
    )
    .bind(fleet_run)
    .bind(release_id)
    .fetch_all(&state.ledger)
    .await
    .map_err(DriverError::internal)
}

fn release_runtime_role(image_digest: &str) -> String {
    format!("mb_runtime_{}", &image_digest[7..23])
}

async fn ensure_release_runtime_role(
    state: &DriverState,
    role: &str,
) -> Result<String, DriverError> {
    if !safe_pg_identifier(role) {
        return Err(DriverError::bad("unsafe release runtime role"));
    }
    let directory = driver_runtime_secret_root(state).join("releases");
    secure_directory(&directory).map_err(DriverError::internal)?;
    let password_path = directory.join(role);
    let exists =
        sqlx::query_scalar::<_, bool>("select exists(select 1 from pg_roles where rolname=$1)")
            .bind(role)
            .fetch_one(&state.postgres)
            .await
            .map_err(DriverError::internal)?;
    if exists && !password_path.is_file() {
        return Err(DriverError::internal(
            "release runtime role exists without its credential",
        ));
    }
    let password = secret_value(&password_path, 48).map_err(DriverError::internal)?;
    write_secret(
        &directory.join("bridge-token"),
        &state.config.odoo_bridge_token,
    )
    .map_err(DriverError::internal)?;
    if !exists {
        sqlx::query(AssertSqlSafe(format!(
            "create role \"{role}\" login password '{password}' in role odoo"
        )))
        .execute(&state.postgres)
        .await
        .map_err(DriverError::internal)?;
    }
    Ok(password)
}

async fn transition_release_tenant(
    state: &DriverState,
    adoption: Uuid,
    from: &str,
    to: &str,
    evidence: Option<&Value>,
) -> Result<(), DriverError> {
    let changed = sqlx::query(
        "update control.tenant_release_adoptions set state=$3,version=version+1,
                started_at=case when $3='isolating' then coalesce(started_at,now()) else started_at end,
                verified_at=case when $3='prepared' then now() else verified_at end,
                evidence=case when $4::jsonb is null then evidence else evidence || $4 end
         where id=$1 and state=$2",
    )
    .bind(adoption)
    .bind(from)
    .bind(to)
    .bind(evidence)
    .execute(&state.ledger)
    .await
    .map_err(DriverError::internal)?
    .rows_affected();
    if changed != 1 {
        return Err(DriverError::internal(format!(
            "tenant adoption transition {from} -> {to} lost its compare-and-set"
        )));
    }
    Ok(())
}

async fn prepare_release_tenant(
    state: &DriverState,
    tenant: &ReleaseTenant,
    manifest: &crate::release::ApplicationReleaseManifest,
    runtime_role: &str,
    runtime_password: &str,
) -> Result<(), DriverError> {
    let mut phase = sqlx::query_scalar::<_, String>(
        "select state from control.tenant_release_adoptions where id=$1",
    )
    .bind(tenant.id)
    .fetch_one(&state.ledger)
    .await
    .map_err(DriverError::internal)?;
    if phase == "pending" {
        transition_release_tenant(state, tenant.id, "pending", "isolating", None).await?;
        phase = "isolating".into();
    }
    if phase == "isolating" {
        enter_workshop_maintenance(state, tenant.workshop_id).await?;
        drain_workshop_operations(state, tenant.workshop_id).await?;
        isolate_release_database(state, &tenant.database_ref, runtime_role).await?;
        transition_release_tenant(
            state,
            tenant.id,
            "isolating",
            "backing_up",
            Some(&json!({"old_runtime_access_revoked":true})),
        )
        .await?;
        phase = "backing_up".into();
    }
    if phase == "backing_up" {
        create_recovery_set(
            state,
            tenant.workshop_id,
            tenant.backup_recovery_id,
            &tenant.database_ref,
            "backup",
            &tenant.component_scope,
        )
        .await?;
        transition_release_tenant(
            state,
            tenant.id,
            "backing_up",
            "upgrading",
            Some(&json!({"verified_recovery_point_id":tenant.backup_recovery_id})),
        )
        .await?;
        phase = "upgrading".into();
    }
    if phase == "upgrading" {
        run_odoo_release_upgrade(
            state,
            tenant,
            &manifest.provenance.oci_ref,
            runtime_role,
            runtime_password,
        )
        .await?;
        transition_release_tenant(state, tenant.id, "upgrading", "verifying", None).await?;
        phase = "verifying".into();
    }
    if phase == "verifying" {
        verify_release_database(state, tenant, manifest).await?;
        transition_release_tenant(
            state,
            tenant.id,
            "verifying",
            "prepared",
            Some(&json!({
                "image_digest":manifest.image_digest,
                "addon_versions":manifest.addons,
                "postconditions":manifest.required_postconditions,
            })),
        )
        .await?;
        phase = "prepared".into();
    }
    if phase != "prepared" {
        return Err(DriverError::bad("tenant adoption is not preparable"));
    }
    Ok(())
}

async fn mark_release_tenant_failed(
    state: &DriverState,
    adoption: Uuid,
    failure_class: &str,
) -> Result<(), DriverError> {
    sqlx::query(
        "update control.tenant_release_adoptions
         set state='failed',failure_class=$2,version=version+1
         where id=$1 and state in ('pending','isolating','backing_up','upgrading','verifying')",
    )
    .bind(adoption)
    .bind(failure_class)
    .execute(&state.ledger)
    .await
    .map_err(DriverError::internal)?;
    Ok(())
}

async fn isolate_release_database(
    state: &DriverState,
    database: &str,
    target_role: &str,
) -> Result<(), DriverError> {
    if !safe_pg_identifier(database) || !safe_pg_identifier(target_role) {
        return Err(DriverError::bad("unsafe release database identity"));
    }
    sqlx::query(AssertSqlSafe(format!(
        "alter database \"{database}\" owner to postgres"
    )))
    .execute(&state.postgres)
    .await
    .map_err(DriverError::internal)?;
    sqlx::query(AssertSqlSafe(format!(
        "revoke connect on database \"{database}\" from public,odoo"
    )))
    .execute(&state.postgres)
    .await
    .map_err(DriverError::internal)?;
    let old_roles = sqlx::query_scalar::<_, String>(
        "select rolname from pg_roles where rolname like 'mb_runtime_%' and rolname<>$1",
    )
    .bind(target_role)
    .fetch_all(&state.postgres)
    .await
    .map_err(DriverError::internal)?;
    for role in &old_roles {
        if !safe_pg_identifier(role) {
            return Err(DriverError::internal("unsafe stored runtime role"));
        }
        sqlx::query(AssertSqlSafe(format!(
            "revoke connect on database \"{database}\" from \"{role}\""
        )))
        .execute(&state.postgres)
        .await
        .map_err(DriverError::internal)?;
    }
    sqlx::query(AssertSqlSafe(format!(
        "grant connect on database \"{database}\" to \"{target_role}\""
    )))
    .execute(&state.postgres)
    .await
    .map_err(DriverError::internal)?;
    drain_database_sessions(state, database).await?;
    let old_odoo_can_connect =
        sqlx::query_scalar::<_, bool>("select has_database_privilege('odoo',$1,'connect')")
            .bind(database)
            .fetch_one(&state.postgres)
            .await
            .map_err(DriverError::internal)?;
    let target_can_connect =
        sqlx::query_scalar::<_, bool>("select has_database_privilege($1,$2,'connect')")
            .bind(target_role)
            .bind(database)
            .fetch_one(&state.postgres)
            .await
            .map_err(DriverError::internal)?;
    if old_odoo_can_connect || !target_can_connect {
        return Err(DriverError::internal(
            "database isolation privilege proof failed",
        ));
    }
    Ok(())
}

async fn run_odoo_release_upgrade(
    state: &DriverState,
    tenant: &ReleaseTenant,
    image: &str,
    runtime_role: &str,
    runtime_password: &str,
) -> Result<(), DriverError> {
    let container = format!(
        "mb-release-upgrade-{}",
        &tenant.id.simple().to_string()[..12]
    );
    run_docker_job_with_secrets(
        state,
        &container,
        json!({
            "Image":image,
            "Cmd":[
                "/bin/sh","-ec",
                "password=$(cat /run/makersbrain-job-secrets/runtime-password); export MB_CONTROL_BRIDGE_TOKEN=$(cat /run/makersbrain-job-secrets/bridge-token); exec odoo --database=\"$MB_ODOO_DATABASE\" --stop-after-init --no-http --no-database-list --db_host=\"$HOST\" --db_port=\"$PORT\" --db_user=\"$USER\" --db_password=\"$password\" --addons-path=/mnt/makersbrain-addons,/mnt/oca-addons,/usr/lib/python3/dist-packages/odoo/addons --update=all --without-demo=all"
            ],
            "Env":[
                format!("MB_ODOO_DATABASE={}",tenant.database_ref),
                format!("HOST={}",state.config.postgres_host),
                format!("PORT={}",state.config.postgres_port),
                format!("USER={runtime_role}")
            ],
            "Labels":{
                "makersbrain.kind":"odoo-release-upgrade",
                "makersbrain.workshop":tenant.workshop_id.to_string(),
                "makersbrain.database":tenant.database_id.to_string()
            },
            "HostConfig":{
                "NetworkMode":state.config.docker_network,
                "Binds":[format!("{}:/var/lib/odoo",state.config.odoo_volume)]
            }
        }),
        &[
            ("runtime-password", runtime_password),
            ("bridge-token", state.config.odoo_bridge_token.as_str()),
        ],
    )
    .await
}

async fn verify_release_database(
    state: &DriverState,
    tenant: &ReleaseTenant,
    manifest: &crate::release::ApplicationReleaseManifest,
) -> Result<(), DriverError> {
    let pool = database_pool(state, &tenant.database_ref).await?;
    let registry = sqlx::query_scalar::<_, bool>(
        "select to_regclass('public.ir_module_module') is not null
             and to_regclass('public.ir_model_data') is not null",
    )
    .fetch_one(&pool)
    .await
    .map_err(DriverError::internal)?;
    if !registry {
        pool.close().await;
        return Err(DriverError::internal(
            "Odoo registry tables are unavailable",
        ));
    }
    for (module, expected_version) in &manifest.addons {
        let installed = sqlx::query_as::<_, (String, Option<String>)>(
            "select state,latest_version from ir_module_module where name=$1",
        )
        .bind(module)
        .fetch_optional(&pool)
        .await
        .map_err(DriverError::internal)?;
        if !matches!(installed,Some((ref state,Some(ref version))) if state=="installed" && version==expected_version)
        {
            pool.close().await;
            return Err(DriverError::internal(format!(
                "installed addon {module} does not match the release manifest"
            )));
        }
    }
    let workshop = sqlx::query_scalar::<_, Option<String>>(
        "select mb_control_workshop_id from res_company where mb_control_workshop_id is not null limit 1",
    )
    .fetch_one(&pool)
    .await
    .map_err(DriverError::internal)?;
    pool.close().await;
    if workshop.as_deref() != Some(tenant.workshop_id.to_string().as_str()) {
        return Err(DriverError::internal(
            "tenant postcondition resolved another workshop identity",
        ));
    }
    Ok(())
}

async fn ensure_release_runtime(
    state: &DriverState,
    container: &str,
    image: &str,
    runtime_role: &str,
    runtime_password: &str,
) -> Result<(), DriverError> {
    let config_digest = format!(
        "{:x}",
        Sha256::digest(
            format!(
                "{image}\0{runtime_role}\0{runtime_password}\0{}\0driver-secret-runtime-v2",
                state.config.backup_secret_volume
            )
            .as_bytes()
        )
    );
    if docker_container_exists(state, container).await? {
        let inspect = docker_inspect_container(state, container).await?;
        if inspect
            .pointer("/Config/Labels/makersbrain.config-digest")
            .and_then(Value::as_str)
            != Some(&config_digest)
        {
            docker_stop_container(state, container).await?;
            docker_delete_container(state, container).await?;
        } else if inspect.pointer("/State/Running").and_then(Value::as_bool) != Some(true) {
            docker_start_container(state, container).await?;
        }
    }
    if !docker_container_exists(state, container).await? {
        docker_create_container(
            state,
            container,
            json!({
                "Image":image,
                "Cmd":[
                    "/bin/sh","-ec",
                    "password=$(cat \"$MB_RUNTIME_PASSWORD_FILE\"); export MB_CONTROL_BRIDGE_TOKEN=$(cat /run/makersbrain-release-secrets/bridge-token); exec odoo --no-database-list --db_host=\"$HOST\" --db_port=\"$PORT\" --db_user=\"$USER\" --db_password=\"$password\" --addons-path=/mnt/makersbrain-addons,/mnt/oca-addons,/usr/lib/python3/dist-packages/odoo/addons --load=base,web,mb_dbfilter_gateway --proxy-mode"
                ],
                "Env":[
                    format!("HOST={}",state.config.postgres_host),format!("PORT={}",state.config.postgres_port),
                    format!("USER={runtime_role}"),
                    format!("MB_RUNTIME_PASSWORD_FILE=/run/makersbrain-release-secrets/{runtime_role}")
                ],
                "Labels":{
                    "makersbrain.kind":"odoo-release-runtime",
                    "makersbrain.config-digest":config_digest,
                    "makersbrain.image-digest":image
                },
                "HostConfig":{
                    "NetworkMode":state.config.docker_network,
                    "Binds":[format!("{}:/var/lib/odoo",state.config.odoo_volume)],
                    "GroupAdd":["0"],
                    "Mounts":[{
                        "Type":"volume",
                        "Source":state.config.backup_secret_volume,
                        "Target":"/run/makersbrain-release-secrets",
                        "ReadOnly":true,
                        "VolumeOptions":{"Subpath":"runtime/releases"}
                    }]
                }
            }),
        )
        .await?;
        docker_start_container(state, container).await?;
    }
    Ok(())
}

async fn smoke_release_runtime(
    state: &DriverState,
    container: &str,
    tenant: &ReleaseTenant,
) -> Result<(), DriverError> {
    let tenant_bridge_token = std::fs::read_to_string(
        state
            .config
            .secret_root
            .join("docker")
            .join(tenant.workshop_id.to_string())
            .join("odoo"),
    )
    .map_err(DriverError::internal)?
    .trim()
    .to_owned();
    if tenant_bridge_token.is_empty() {
        return Err(DriverError::internal(
            "tenant bridge credential is empty during release verification",
        ));
    }
    for _ in 0..90 {
        let response = reqwest::Client::new()
            .get(format!("http://{container}:8069/mb_control/v1/health"))
            .header("X-Odoo-Dbfilter", &tenant.database_ref)
            .bearer_auth(&tenant_bridge_token)
            .send()
            .await;
        if let Ok(response) = response
            && response.status().is_success()
            && let Ok(body) = response.json::<Value>().await
            && body.get("status").and_then(Value::as_str) == Some("ready")
            && body.get("database").and_then(Value::as_str) == Some(&tenant.database_ref)
            && body.get("workshop_id").and_then(Value::as_str)
                == Some(tenant.workshop_id.to_string().as_str())
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    Err(DriverError::internal(
        "candidate runtime failed an isolated tenant smoke test",
    ))
}

async fn activate_release_routes(
    state: &DriverState,
    runtime_container: &str,
    tenants: &[ReleaseTenant],
) -> Result<String, DriverError> {
    let mut replacements = Vec::with_capacity(tenants.len());
    for tenant in tenants {
        let backup = state
            .config
            .route_root
            .join(format!("{}.recovery.bak", tenant.workshop_id));
        let previous = std::fs::read(&backup).map_err(DriverError::internal)?;
        let previous_text = std::str::from_utf8(&previous)
            .map_err(|_| DriverError::internal("saved tenant route is not UTF-8"))?;
        if !previous_text.contains("odoo:8069") {
            return Err(DriverError::internal(
                "saved tenant route does not identify the retained runtime",
            ));
        }
        let candidate = previous_text
            .replace("odoo:8069", &format!("{runtime_container}:8069"))
            .into_bytes();
        replacements.push((tenant.workshop_id, previous, candidate));
    }
    let digest = route_set_digest(
        replacements
            .iter()
            .map(|(workshop, _, candidate)| (*workshop, candidate.as_slice())),
    );
    for (workshop, _, candidate) in &replacements {
        let path = state.config.route_root.join(format!("{workshop}.conf"));
        let temporary = state
            .config
            .route_root
            .join(format!("{workshop}.release.tmp"));
        std::fs::write(&temporary, candidate).map_err(DriverError::internal)?;
        std::fs::rename(&temporary, &path).map_err(DriverError::internal)?;
    }
    if let Err(error) = docker_exec(state, &state.config.gateway_container, &["nginx", "-t"]).await
    {
        for (workshop, previous, _) in &replacements {
            let maintenance = previous_route_maintenance(previous)?;
            std::fs::write(
                state.config.route_root.join(format!("{workshop}.conf")),
                maintenance,
            )
            .map_err(DriverError::internal)?;
        }
        return Err(error);
    }
    let response = state
        .docker
        .post(format!(
            "http://localhost/v1.47/containers/{}/kill?signal=HUP",
            state.config.gateway_container
        ))
        .send()
        .await
        .map_err(DriverError::internal)?;
    if !response.status().is_success() {
        return Err(DriverError::internal(format!(
            "gateway release activation returned {}",
            response.status()
        )));
    }
    for (workshop, _, _) in &replacements {
        let backup = state
            .config
            .route_root
            .join(format!("{workshop}.recovery.bak"));
        std::fs::remove_file(backup).map_err(DriverError::internal)?;
    }
    Ok(digest)
}

fn release_tenant_evidence(tenants: &[ReleaseTenant]) -> Value {
    Value::Array(
        tenants
            .iter()
            .map(|tenant| {
                json!({
                    "adoption_id":tenant.id,
                    "workshop_id":tenant.workshop_id,
                    "database_id":tenant.database_id,
                    "database_ref":tenant.database_ref,
                    "public_hostname":tenant.public_hostname,
                })
            })
            .collect(),
    )
}

fn planned_release_route_digest(
    state: &DriverState,
    runtime_container: &str,
    tenants: &[ReleaseTenant],
) -> Result<String, DriverError> {
    let mut routes = Vec::with_capacity(tenants.len());
    for tenant in tenants {
        let previous = std::fs::read(
            state
                .config
                .route_root
                .join(format!("{}.recovery.bak", tenant.workshop_id)),
        )
        .map_err(DriverError::internal)?;
        let candidate = std::str::from_utf8(&previous)
            .map_err(|_| DriverError::internal("saved tenant route is not UTF-8"))?
            .replace("odoo:8069", &format!("{runtime_container}:8069"));
        routes.push((tenant.workshop_id, candidate.into_bytes()));
    }
    Ok(route_set_digest(
        routes
            .iter()
            .map(|(workshop, route)| (*workshop, route.as_slice())),
    ))
}

fn observed_release_route_digest(
    state: &DriverState,
    tenants: &[ReleaseTenant],
) -> Result<Option<String>, DriverError> {
    let mut routes = Vec::with_capacity(tenants.len());
    for tenant in tenants {
        let path = state
            .config
            .route_root
            .join(format!("{}.conf", tenant.workshop_id));
        let route = std::fs::read(path).map_err(DriverError::internal)?;
        if route
            .windows("Retry-After".len())
            .any(|value| value == b"Retry-After")
        {
            return Ok(None);
        }
        routes.push((tenant.workshop_id, route));
    }
    Ok(Some(route_set_digest(
        routes
            .iter()
            .map(|(workshop, route)| (*workshop, route.as_slice())),
    )))
}

fn route_set_digest<'a>(routes: impl Iterator<Item = (Uuid, &'a [u8])>) -> String {
    let digest_input = routes
        .map(|(workshop, route)| format!("{workshop}:{}", String::from_utf8_lossy(route)))
        .collect::<Vec<_>>()
        .join("\n");
    format!("sha256:{:x}", Sha256::digest(digest_input.as_bytes()))
}

fn previous_route_maintenance(previous: &[u8]) -> Result<Vec<u8>, DriverError> {
    let text = std::str::from_utf8(previous)
        .map_err(|_| DriverError::internal("saved tenant route is not UTF-8"))?;
    let hostnames = text
        .lines()
        .filter_map(|line| line.trim().strip_prefix("server_name "))
        .map(|value| value.trim_end_matches(';'))
        .collect::<Vec<_>>();
    if hostnames.is_empty() {
        return Err(DriverError::internal("saved tenant route has no hostname"));
    }
    Ok(hostnames
        .iter()
        .map(|name| format!("server {{\n  listen 8080;\n  server_name {name};\n  add_header Retry-After 120 always;\n  location / {{ return 503; }}\n}}\n"))
        .collect::<String>()
        .into_bytes())
}
