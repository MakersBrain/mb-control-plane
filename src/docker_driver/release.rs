use super::*;

use super::executor_quiescence::ReleaseExecutorIdentity;
use crate::outbound_http::TraceRequestBuilderExt as _;

#[tracing::instrument(
    name = "deployment_driver.release.execute",
    skip_all,
    fields(
        release.route_reservations = lease.reserved_workshops.len(),
        release.route_reservations_match = tracing::field::Empty
    )
)]
pub(super) async fn release_fleet(
    state: &DriverState,
    payload: &Value,
    lease: &ReleaseDriverLease,
) -> Result<Value, DriverError> {
    renew_release_driver_lease(state, lease).await?;
    match payload.get("phase").and_then(Value::as_str) {
        Some("prepare-initial") => return prepare_initial_release(state, payload, lease).await,
        Some("adopt-fleet") => {}
        _ => return Err(DriverError::bad("invalid release fleet request")),
    }
    let fleet_run = payload_uuid(payload, "fleet_run_id")?;
    if lease.fleet_run_id != Some(fleet_run) {
        return Err(DriverError::internal(
            "release lease fleet identity differs from its payload",
        ));
    }
    let release_id = payload
        .get("release_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| DriverError::bad("release_id is required"))?;
    let run = sqlx::query_as::<_, (String, Value, i64)>(
        "select state,tenant_snapshot,fleet_generation
         from control.release_fleet_runs where id=$1 and release_id=$2",
    )
    .bind(fleet_run)
    .bind(release_id)
    .fetch_optional(&state.ledger)
    .await
    .map_err(DriverError::internal)?
    .ok_or_else(|| DriverError(StatusCode::NOT_FOUND, "fleet run not found".into()))?;
    if run.0 == "active" {
        let evidence = sqlx::query_scalar::<_, Value>(
            "select evidence from control.release_fleet_runs where id=$1",
        )
        .bind(fleet_run)
        .fetch_one(&state.ledger)
        .await
        .map_err(DriverError::internal)?;
        return Ok(json!({"evidence":evidence,"observed":true}));
    }
    if !matches!(run.0.as_str(), "preparing" | "activating") {
        return Err(DriverError::bad("fleet run is not adoptable"));
    }
    let fenced = sqlx::query(
        "update control.release_fleet_runs set driver_fence_token=$3,updated_at=now()
         where id=$1 and release_id=$2 and state in ('preparing','activating')
           and (driver_fence_token is null or driver_fence_token=$3)",
    )
    .bind(fleet_run)
    .bind(release_id)
    .bind(lease.fence_token)
    .execute(&state.ledger)
    .await
    .map_err(DriverError::internal)?
    .rows_affected();
    if fenced != 1 {
        return Err(DriverError::internal(
            "fleet run is fenced by another driver attempt",
        ));
    }
    let release_row = sqlx::query(
        "select manifest,status,odoo_subject_digest from control.application_releases where id=$1",
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
        || manifest.odoo_runtime.subject_digest
            != release_row.get::<String, _>("odoo_subject_digest")
    {
        return Err(DriverError::bad(
            "release identity does not match its manifest",
        ));
    }
    let tenants = release_tenants(state, lease, fleet_run, release_id).await?;
    if tenants.is_empty() {
        return Err(DriverError::bad("fleet run contains no tenants"));
    }
    if tenants.len() > crate::release::MAX_FLEET_TENANTS {
        return Err(DriverError::bad(
            "fleet release exceeds the bounded tenant limit",
        ));
    }
    if release_tenant_snapshot(&tenants) != run.1 {
        return Err(DriverError::bad(
            "fleet release tenant snapshot differs from its adoption ledger",
        ));
    }
    let tenant_workshops = release_tenant_workshops(&tenants)?;
    let reservations_match = tenant_workshops == lease.reserved_workshops;
    tracing::Span::current().record("release.route_reservations_match", reservations_match);
    if !reservations_match {
        return Err(DriverError::bad(
            "fleet release tenant set differs from its route reservation",
        ));
    }
    renew_release_driver_lease(state, lease).await?;
    let extension_volume = materialize_extension(state, &manifest).await?;
    let (runtime_platform, extension_platform, pair_qualification) =
        selected_release_platform(&manifest)?;

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
    let runtime_role = release_runtime_role(&manifest.odoo_runtime.subject_digest);
    let runtime_password = ensure_release_runtime_role(state, &runtime_role).await?;

    for tenant in &tenants {
        renew_release_driver_lease(state, lease).await?;
        if let Err(error) = prepare_release_tenant(
            state,
            tenant,
            &manifest,
            &extension_volume,
            &runtime_role,
            &runtime_password,
            lease,
        )
        .await
        {
            renew_release_driver_lease(state, lease).await?;
            let failure_class = match rollback_failed_release_tenant(
                state,
                tenant,
                &runtime_role,
                lease,
            )
            .await
            {
                Ok(()) => "release_preparation_failed_rolled_back",
                Err(rollback_error) => {
                    tracing::error!(
                        adoption_id=%tenant.id,
                        error_class=rollback_error.safe_class(),
                        "release preparation and verified recovery rollback both failed; maintenance remains enabled"
                    );
                    "release_preparation_rollback_failed"
                }
            };
            mark_release_tenant_failed(state, tenant.workshop_id, tenant.id, failure_class).await?;
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

    renew_release_driver_lease(state, lease).await?;
    let runtime_container = state.config.docker_resource(format!("odoo-{target_slot}"));
    ensure_release_runtime(
        state,
        &runtime_container,
        &manifest.odoo_runtime.deployment_ref,
        &extension_volume,
        &runtime_role,
        &runtime_password,
        false,
    )
    .await?;
    for tenant in &tenants {
        renew_release_driver_lease(state, lease).await?;
        smoke_release_runtime(state, &runtime_container, tenant).await?;
    }

    renew_release_driver_lease(state, lease).await?;
    let changed = sqlx::query(
        "update control.release_fleet_runs set state='activating',target_slot=$2,updated_at=now()
         where id=$1 and state='preparing'",
    )
    .bind(fleet_run)
    .bind(target_slot)
    .execute(&state.ledger)
    .await
    .map_err(DriverError::internal)?
    .rows_affected();
    if changed != 1 && run.0 != "activating" {
        return Err(DriverError::internal(
            "fleet activation transition lost its compare-and-set",
        ));
    }
    if matches!(state.backend, RuntimeBackend::Docker) {
        docker_ensure_restart_policy(
            state,
            &runtime_container,
            DockerRestartPolicy::UnlessStopped,
        )
        .await?;
    } else {
        ensure_release_runtime(
            state,
            &runtime_container,
            &manifest.odoo_runtime.deployment_ref,
            &extension_volume,
            &runtime_role,
            &runtime_password,
            true,
        )
        .await?;
    }
    let prepared_tenants = release_tenant_evidence(&tenants);
    let existing_intent = sqlx::query_as::<
        _,
        (
            String,
            Uuid,
            Option<String>,
            Value,
            Option<i64>,
            String,
            Option<i16>,
        ),
    >(
        "select gateway_configuration_digest,driver_action_id,
                observed_configuration_digest,prepared_tenants,driver_fence_token,
                target_slot,gateway_identity_version
         from control.fleet_activation_intents
         where fleet_run_id=$1 and abandoned_at is null",
    )
    .bind(fleet_run)
    .fetch_optional(&state.ledger)
    .await
    .map_err(DriverError::internal)?;
    let (gateway_digest, action_id) = if let Some(existing) = existing_intent {
        if existing.3 != prepared_tenants
            || existing.4 != Some(lease.fence_token)
            || existing.5 != target_slot
        {
            return Err(DriverError::internal(
                "stored fleet activation intent tenant set drifted",
            ));
        }
        if existing.6 != Some(1) {
            return Err(DriverError::internal(
                "legacy fleet activation intent requires reconciliation",
            ));
        }
        (existing.0, existing.1)
    } else {
        let digest = planned_release_route_digest(state, &runtime_container, &tenants)?;
        let action_id = Uuid::new_v4();
        sqlx::query(
            "insert into control.fleet_activation_intents(
           id,fleet_run_id,release_id,runtime_key,target_slot,odoo_subject_digest,
           extension_subject_digest,pair_qualification_digest,prepared_tenants,
           gateway_configuration_digest,driver_action_id,driver_fence_token,
           gateway_identity_version
         ) values($1,$2,$3,'shared-odoo',$4,$5,$6,$7,$8,$9,$10,$11,1)",
        )
        .bind(Uuid::new_v4())
        .bind(fleet_run)
        .bind(release_id)
        .bind(target_slot)
        .bind(&manifest.odoo_runtime.subject_digest)
        .bind(&manifest.extension_bundle.subject_digest)
        .bind(&pair_qualification.qualification_digest)
        .bind(&prepared_tenants)
        .bind(&digest)
        .bind(action_id)
        .bind(lease.fence_token)
        .execute(&state.ledger)
        .await
        .map_err(DriverError::internal)?;
        (digest, action_id)
    };
    let gateway_identity = ReleaseGatewayGenerationIdentity::new(
        fleet_run,
        action_id,
        lease.fence_token,
        gateway_digest.clone(),
        target_slot,
    )?;
    renew_release_driver_lease(state, lease).await?;
    let observed = observed_release_route_digest(state, &tenants)?;
    if observed.as_deref() != Some(&gateway_digest) {
        let activated = activate_release_routes(
            state,
            &runtime_container,
            &tenants,
            lease,
            &gateway_identity,
        )
        .await?;
        if activated != gateway_digest {
            return Err(DriverError::internal(
                "activated gateway configuration differs from its intent",
            ));
        }
    } else {
        publish_release_gateway_identity(state, lease, &gateway_identity).await?;
    }
    observe_running_release_gateway_generation(state, &gateway_identity).await?;
    remove_release_route_backups(state, lease, &tenants).await?;
    let changed = sqlx::query(
        "update control.fleet_activation_intents
         set observed_configuration_digest=$2,activated_at=coalesce(activated_at,now())
         where fleet_run_id=$1 and gateway_configuration_digest=$2
           and driver_fence_token=$3 and gateway_identity_version=1
           and abandoned_at is null",
    )
    .bind(fleet_run)
    .bind(&gateway_digest)
    .bind(lease.fence_token)
    .execute(&state.ledger)
    .await
    .map_err(DriverError::internal)?
    .rows_affected();
    if changed != 1 {
        return Err(DriverError::internal(
            "fleet activation intent observation lost its compare-and-set",
        ));
    }
    renew_release_driver_lease(state, lease).await?;
    if let Some((old_slot, _)) = &active_slot {
        let old_container = state.config.docker_resource(format!("odoo-{old_slot}"));
        match &state.backend {
            RuntimeBackend::Docker => {
                if docker_container_exists(state, &old_container).await? {
                    docker_ensure_restart_policy(state, &old_container, DockerRestartPolicy::No)
                        .await?;
                    docker_stop_container(state, &old_container).await?;
                }
            }
            RuntimeBackend::Quadlet(backend) => {
                backend.set_odoo_boot_selected(old_slot, false).await?;
            }
        }
    }
    renew_release_driver_lease(state, lease).await?;
    let evidence = json!({
        "release_id":release_id,
        "odoo_subject_digest":manifest.odoo_runtime.subject_digest,
        "extension_subject_digest":manifest.extension_bundle.subject_digest,
        "odoo_manifest_digest":runtime_platform.manifest_digest,
        "odoo_config_digest":runtime_platform.config_digest,
        "extension_manifest_digest":extension_platform.manifest_digest,
        "extension_config_digest":extension_platform.config_digest,
        "payload_digest":extension_platform.payload_digest,
        "extension_volume":extension_volume,
        "pair_qualification_digest":pair_qualification.qualification_digest,
        "bridge_contract_digest":manifest.bridge_contract_digest,
        "installed_addon_versions":manifest.addons,
        "runtime_key":"shared-odoo",
        "target_slot":target_slot,
        "runtime_container":runtime_container,
        "runtime_role":runtime_role,
        "runtime_deployment_ref":manifest.odoo_runtime.deployment_ref,
        "runtime_config_digest":release_runtime_config_digest(state, &manifest.odoo_runtime.deployment_ref, &runtime_role, &runtime_password),
        "prepared_tenants":prepared_tenants,
        "fleet_generation":run.2,
        "tenant_snapshot":run.1,
        "gateway_configuration_digest":gateway_digest,
        "driver_action_id":action_id,
        "driver_operation_id":lease.driver_operation_id,
        "driver_fence_token":lease.fence_token,
        "old_runtime_database_access_revoked":true,
        "tenant_recovery_verified":true,
        "candidate_smoke_verified":true
        ,"candidate_restart_policy":"unless-stopped"
        ,"retained_restart_policy":"no"
    });
    Ok(json!({"evidence":evidence}))
}

async fn rollback_failed_release_tenant(
    state: &DriverState,
    tenant: &ReleaseTenant,
    failed_runtime_role: &str,
    lease: &ReleaseDriverLease,
) -> Result<(), DriverError> {
    let recovery = resolve_stored_recovery(
        WorkshopRecoveryLedger::new(state, tenant.workshop_id),
        tenant.backup_recovery_id,
    )
    .await?;
    restore_recovery_set(
        state,
        tenant.workshop_id,
        &tenant.database_ref,
        &recovery.storage_ref,
        &recovery.component_scope,
        &recovery.format_version,
    )
    .await?;

    let (prior_slot, prior_subject) = sqlx::query_as::<_, (String, String)>(
        "select slot,odoo_subject_digest from control.runtime_release_slots
         where runtime_key='shared-odoo' and state='active'",
    )
    .fetch_one(&state.ledger)
    .await
    .map_err(DriverError::internal)?;
    let prior_role = release_runtime_role(&prior_subject);
    if !safe_pg_identifier(&tenant.database_ref)
        || !safe_pg_identifier(&prior_role)
        || !safe_pg_identifier(failed_runtime_role)
    {
        return Err(DriverError::internal(
            "unsafe release rollback database identity",
        ));
    }
    sqlx::query(AssertSqlSafe(format!(
        "alter database \"{}\" owner to postgres",
        tenant.database_ref
    )))
    .execute(&state.postgres)
    .await
    .map_err(DriverError::internal)?;
    sqlx::query(AssertSqlSafe(format!(
        "revoke connect on database \"{}\" from public,odoo,\"{}\"",
        tenant.database_ref, failed_runtime_role
    )))
    .execute(&state.postgres)
    .await
    .map_err(DriverError::internal)?;
    sqlx::query(AssertSqlSafe(format!(
        "grant connect on database \"{}\" to \"{}\"",
        tenant.database_ref, prior_role
    )))
    .execute(&state.postgres)
    .await
    .map_err(DriverError::internal)?;
    drain_database_sessions(state, &tenant.database_ref).await?;
    let prior_can_connect =
        sqlx::query_scalar::<_, bool>("select has_database_privilege($1,$2,'connect')")
            .bind(&prior_role)
            .bind(&tenant.database_ref)
            .fetch_one(&state.postgres)
            .await
            .map_err(DriverError::internal)?;
    let failed_can_connect =
        sqlx::query_scalar::<_, bool>("select has_database_privilege($1,$2,'connect')")
            .bind(failed_runtime_role)
            .bind(&tenant.database_ref)
            .fetch_one(&state.postgres)
            .await
            .map_err(DriverError::internal)?;
    if !prior_can_connect || failed_can_connect {
        return Err(DriverError::internal(
            "release rollback database privilege proof failed",
        ));
    }

    let prior_container = state.config.docker_resource(format!("odoo-{prior_slot}"));
    smoke_release_runtime(state, &prior_container, tenant).await?;
    let selected = selected_route_root(&state.config.route_root)?;
    let route_backup = selected.join(format!("{}.recovery.bak", tenant.workshop_id));
    let previous_route = std::fs::read(route_backup).map_err(DriverError::internal)?;
    leave_release_maintenance(state, tenant.workshop_id, &previous_route, lease).await?;
    let mut evidence_tx = state
        .tenant_ledger
        .begin(tenant.workshop_id)
        .await
        .map_err(DriverError::internal)?;
    let changed = sqlx::query(
        "update control.tenant_release_adoptions
         set evidence=evidence || $3::jsonb
         where id=$1 and workshop_id=$2
           and state in ('backing_up','upgrading','verifying')",
    )
    .bind(tenant.id)
    .bind(tenant.workshop_id)
    .bind(json!({
        "rollback_recovery_point_id":tenant.backup_recovery_id,
        "prior_runtime_subject_digest":prior_subject,
        "prior_runtime_reconnected":true,
        "maintenance_removed_after_reconnect":true
    }))
    .execute(&mut *evidence_tx)
    .await
    .map_err(DriverError::internal)?
    .rows_affected();
    if changed != 1 {
        return Err(DriverError::internal(
            "scoped release rollback evidence target was lost",
        ));
    }
    evidence_tx.commit().await.map_err(DriverError::internal)?;
    Ok(())
}

async fn prepare_initial_release(
    state: &DriverState,
    payload: &Value,
    lease: &ReleaseDriverLease,
) -> Result<Value, DriverError> {
    if !lease.reserved_workshops.is_empty() {
        return Err(DriverError::internal(
            "initial release unexpectedly owns workshop route reservations",
        ));
    }
    let release_id = payload
        .get("release_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| DriverError::bad("release_id is required"))?;
    let expected_manifest_digest = payload
        .get("manifest_digest")
        .and_then(Value::as_str)
        .ok_or_else(|| DriverError::bad("manifest_digest is required"))?;
    let release_row = sqlx::query_as::<_, (Value, String, String, String)>(
        "select manifest,status,odoo_subject_digest,manifest_digest
         from control.application_releases where id=$1",
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
    if !matches!(
        release_row.1.as_str(),
        "preflighting" | "canary" | "prepared"
    ) || release_row.3 != expected_manifest_digest
    {
        return Err(DriverError::bad(
            "initial runtime preparation requires the verified preflight release",
        ));
    }
    let manifest: crate::release::ApplicationReleaseManifest =
        serde_json::from_value(release_row.0)
            .map_err(|_| DriverError::bad("stored release manifest is invalid"))?;
    manifest
        .validate()
        .map_err(|_| DriverError::bad("stored release manifest is invalid"))?;
    if manifest.release_id != release_id || manifest.odoo_runtime.subject_digest != release_row.2 {
        return Err(DriverError::bad(
            "release identity does not match its manifest",
        ));
    }
    let initial_preparable =
        sqlx::query_scalar::<_, bool>("select control.initial_release_preparable($1,$2)")
            .bind(release_id)
            .bind(
                i32::try_from(manifest.capability_registry_version)
                    .map_err(DriverError::internal)?,
            )
            .fetch_one(&state.ledger)
            .await
            .map_err(DriverError::internal)?;
    if !initial_preparable {
        return Err(DriverError::bad(
            "initial runtime preparation requires an active registry and completely empty fleet",
        ));
    }
    renew_release_driver_lease(state, lease).await?;
    let extension_volume = materialize_extension(state, &manifest).await?;
    let (runtime_platform, extension_platform, pair_qualification) =
        selected_release_platform(&manifest)?;
    if let Some((stored_image, mut evidence)) = sqlx::query_as::<_, (String, Value)>(
        "select odoo_subject_digest,evidence from control.runtime_release_slots
         where runtime_key='shared-odoo' and release_id=$1 and state='prepared'",
    )
    .bind(release_id)
    .fetch_optional(&state.ledger)
    .await
    .map_err(DriverError::internal)?
    {
        if stored_image == manifest.odoo_runtime.subject_digest
            && evidence.get("manifest_digest").and_then(Value::as_str)
                == Some(expected_manifest_digest)
        {
            evidence["driver_operation_id"] = json!(lease.driver_operation_id);
            evidence["driver_fence_token"] = json!(lease.fence_token);
            return Ok(json!({"evidence":evidence,"observed":true}));
        }
        return Err(DriverError::bad(
            "prepared initial runtime evidence drifted",
        ));
    }
    let runtime_role = release_runtime_role(&manifest.odoo_runtime.subject_digest);
    let runtime_password = ensure_release_runtime_role(state, &runtime_role).await?;
    let target_slot = sqlx::query_scalar::<_, String>(
        "select candidate.slot
         from (values ('blue',1),('green',2)) candidate(slot,preference)
         left join control.runtime_release_slots existing
           on existing.runtime_key='shared-odoo' and existing.slot=candidate.slot
         where existing.slot is null or existing.state in ('inactive','retained','failed')
         order by candidate.preference limit 1",
    )
    .fetch_optional(&state.ledger)
    .await
    .map_err(DriverError::internal)?
    .ok_or_else(|| DriverError::bad("no reusable initial runtime slot is available"))?;
    let runtime_container = state.config.docker_resource(format!("odoo-{target_slot}"));
    renew_release_driver_lease(state, lease).await?;
    ensure_release_runtime(
        state,
        &runtime_container,
        &manifest.odoo_runtime.deployment_ref,
        &extension_volume,
        &runtime_role,
        &runtime_password,
        false,
    )
    .await?;
    if matches!(state.backend, RuntimeBackend::Docker) {
        let inspect = docker_inspect_container(state, &runtime_container).await?;
        if !initial_runtime_inspection_matches(
            &inspect,
            &manifest.odoo_runtime.deployment_ref,
            &runtime_platform.config_digest,
            &extension_volume,
        ) {
            return Err(DriverError::internal(
                "initial release runtime inspection did not match the prepared image",
            ));
        }
    }
    renew_release_driver_lease(state, lease).await?;
    let evidence = json!({
        "release_id":release_id,
        "odoo_subject_digest":manifest.odoo_runtime.subject_digest,
        "extension_subject_digest":manifest.extension_bundle.subject_digest,
        "extension_volume":extension_volume,
        "odoo_manifest_digest":runtime_platform.manifest_digest,
        "odoo_config_digest":runtime_platform.config_digest,
        "extension_manifest_digest":extension_platform.manifest_digest,
        "extension_config_digest":extension_platform.config_digest,
        "payload_digest":extension_platform.payload_digest,
        "pair_qualification_digest":pair_qualification.qualification_digest,
        "bridge_contract_digest":manifest.bridge_contract_digest,
        "installed_addon_versions":manifest.addons,
        "manifest_digest":expected_manifest_digest,
        "runtime_key":"shared-odoo",
        "target_slot":target_slot,
        "runtime_container":runtime_container,
        "runtime_role":runtime_role,
        "runtime_deployment_ref":manifest.odoo_runtime.deployment_ref,
        "runtime_config_digest":release_runtime_config_digest(state, &manifest.odoo_runtime.deployment_ref, &runtime_role, &runtime_password),
        "provenance_verified":true,
        "runtime_inspection_verified":true,
        "verification":"empty_fleet_runtime_started_and_inspected"
        ,"driver_operation_id":lease.driver_operation_id
        ,"driver_fence_token":lease.fence_token
    });
    let inserted = sqlx::query(
        "insert into control.runtime_release_slots(
            runtime_key,slot,release_id,state,odoo_subject_digest,odoo_manifest_digest,
            odoo_config_digest,extension_subject_digest,extension_manifest_digest,
            extension_config_digest,payload_digest,extension_volume,pair_qualification_digest,
            bridge_contract_digest,installed_addon_versions,started_at,verified_at,evidence
         ) values('shared-odoo',$1,$2,'prepared',$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,now(),now(),$14)
         on conflict(runtime_key,slot) do update set
           release_id=excluded.release_id,state='prepared',odoo_subject_digest=excluded.odoo_subject_digest,
           odoo_manifest_digest=excluded.odoo_manifest_digest,odoo_config_digest=excluded.odoo_config_digest,
           extension_subject_digest=excluded.extension_subject_digest,extension_manifest_digest=excluded.extension_manifest_digest,
           extension_config_digest=excluded.extension_config_digest,payload_digest=excluded.payload_digest,
           extension_volume=excluded.extension_volume,pair_qualification_digest=excluded.pair_qualification_digest,
           bridge_contract_digest=excluded.bridge_contract_digest,installed_addon_versions=excluded.installed_addon_versions,
           started_at=excluded.started_at,verified_at=excluded.verified_at,
           activated_at=null,evidence=excluded.evidence,
           version=control.runtime_release_slots.version+1
         where control.runtime_release_slots.state in ('inactive','retained','failed')",
    )
    .bind(target_slot)
    .bind(release_id)
    .bind(&manifest.odoo_runtime.subject_digest)
    .bind(&runtime_platform.manifest_digest)
    .bind(&runtime_platform.config_digest)
    .bind(&manifest.extension_bundle.subject_digest)
    .bind(&extension_platform.manifest_digest)
    .bind(&extension_platform.config_digest)
    .bind(&extension_platform.payload_digest)
    .bind(&extension_volume)
    .bind(&pair_qualification.qualification_digest)
    .bind(&manifest.bridge_contract_digest)
    .bind(serde_json::to_value(&manifest.addons).map_err(DriverError::internal)?)
    .bind(&evidence)
    .execute(&state.ledger)
    .await
    .map_err(DriverError::internal)?
    .rows_affected();
    if inserted != 1 {
        return Err(DriverError::bad("initial runtime slot is already occupied"));
    }
    Ok(json!({"evidence":evidence}))
}

pub(super) fn initial_runtime_inspection_matches(
    inspect: &Value,
    expected_image: &str,
    expected_config: &str,
    expected_extension_volume: &str,
) -> bool {
    inspect.pointer("/State/Running").and_then(Value::as_bool) == Some(true)
        && inspect.pointer("/Config/Image").and_then(Value::as_str) == Some(expected_image)
        && inspect.get("Image").and_then(Value::as_str) == Some(expected_config)
        && inspect
            .pointer("/HostConfig/ReadonlyRootfs")
            .and_then(Value::as_bool)
            == Some(true)
        && inspect
            .get("Mounts")
            .and_then(Value::as_array)
            .is_some_and(|mounts| {
                mounts.iter().any(|mount| {
                    mount.get("Source").and_then(Value::as_str) == Some(expected_extension_volume)
                        && mount.get("Destination").and_then(Value::as_str)
                            == Some("/opt/mb-extension")
                        && mount.get("RW").and_then(Value::as_bool) == Some(false)
                })
            })
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
    lease: &ReleaseDriverLease,
    fleet_run: Uuid,
    release_id: &str,
) -> Result<Vec<ReleaseTenant>, DriverError> {
    sqlx::query_as::<_, ReleaseTenant>(
        "select * from control.read_release_driver_tenants(
            $1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
    )
    .bind(fleet_run)
    .bind(release_id)
    .bind(lease.driver_operation_id)
    .bind(lease.control_operation.id)
    .bind(lease.control_operation.attempt)
    .bind(&lease.control_operation.owner)
    .bind(lease.instance_owner)
    .bind(lease.execution_token)
    .bind(lease.resource_lease_token)
    .bind(lease.fence_token)
    .fetch_all(&state.ledger)
    .await
    .map_err(DriverError::internal)
}

fn release_tenant_snapshot(tenants: &[ReleaseTenant]) -> Value {
    let mut tenants = tenants.iter().collect::<Vec<_>>();
    tenants.sort_by_key(|tenant| (tenant.workshop_id, tenant.database_id));
    Value::Array(
        tenants
        .into_iter()
        .map(|tenant| {
            json!({
                "workshop_id":tenant.workshop_id,
                "database_id":tenant.database_id,
                "database_ref":tenant.database_ref,
                "paperless_enabled":tenant.component_scope.iter().any(|value| value == "paperless"),
            })
        })
        .collect(),
    )
}

fn release_tenant_workshops(tenants: &[ReleaseTenant]) -> Result<Vec<Uuid>, DriverError> {
    let mut workshops = tenants
        .iter()
        .map(|tenant| tenant.workshop_id)
        .collect::<Vec<_>>();
    workshops.sort_unstable();
    if workshops.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(DriverError::bad(
            "fleet release contains duplicate workshop route reservations",
        ));
    }
    Ok(workshops)
}

pub(super) fn release_runtime_role(image_digest: &str) -> String {
    format!("mb_runtime_{}", &image_digest[7..23])
}

pub(super) fn odoo_configuration(
    state: &DriverState,
    runtime_role: &str,
    runtime_password: &str,
) -> Result<String, DriverError> {
    let values = [
        ("db_host", state.config.postgres_host.as_str()),
        ("db_port", &state.config.postgres_port.to_string()),
        ("db_user", runtime_role),
        ("db_password", runtime_password),
    ];
    for (_, value) in &values {
        if value.is_empty()
            || value.len() > 1024
            || !value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':')
            })
        {
            return Err(DriverError::internal("unsafe Odoo configuration value"));
        }
    }
    Ok(format!(
        "[options]\ndb_host = {}\ndb_port = {}\ndb_user = {}\ndb_password = {}\n",
        state.config.postgres_host, state.config.postgres_port, runtime_role, runtime_password
    ))
}

fn deployment_architecture() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        architecture => architecture,
    }
}

pub(super) fn selected_release_platform(
    manifest: &crate::release::ApplicationReleaseManifest,
) -> Result<
    (
        &crate::release::OdooRuntimePlatform,
        &crate::release::ExtensionPlatform,
        &crate::release::PairQualification,
    ),
    DriverError,
> {
    let runtime = manifest
        .odoo_runtime
        .platforms
        .iter()
        .find(|value| {
            value.platform.os == "linux" && value.platform.architecture == deployment_architecture()
        })
        .ok_or_else(|| {
            DriverError::bad("release has no descriptor for the deployment host platform")
        })?;
    let extension = manifest
        .extension_bundle
        .platforms
        .iter()
        .find(|value| value.platform == runtime.platform)
        .ok_or_else(|| DriverError::bad("extension platform descriptor is absent"))?;
    let pair = manifest
        .pair_qualifications
        .iter()
        .find(|value| value.platform == runtime.platform)
        .ok_or_else(|| DriverError::bad("pair qualification is absent"))?;
    Ok((runtime, extension, pair))
}

async fn materialize_extension(
    state: &DriverState,
    manifest: &crate::release::ApplicationReleaseManifest,
) -> Result<String, DriverError> {
    const MAX_ARCHIVE_BYTES: usize = 256 * 1024 * 1024;
    let (runtime, extension, _) = selected_release_platform(manifest)?;
    docker_pull_image(state, &manifest.odoo_runtime.deployment_ref).await?;
    docker_pull_image(state, &manifest.extension_bundle.oci_ref).await?;
    if state.config.extension_helper_image.contains("@sha256:") {
        docker_pull_image(state, &state.config.extension_helper_image).await?;
    }
    verify_engine_image_identity(
        &docker_inspect_image(state, &manifest.odoo_runtime.deployment_ref).await?,
        &manifest.odoo_runtime.subject_digest,
        &runtime.manifest_digest,
        &runtime.config_digest,
    )?;
    verify_engine_image_identity(
        &docker_inspect_image(state, &manifest.extension_bundle.oci_ref).await?,
        &manifest.extension_bundle.subject_digest,
        &extension.manifest_digest,
        &extension.config_digest,
    )?;
    let volume = state.config.docker_resource(format!(
        "ext-{}-{}",
        &extension.manifest_digest[7..23],
        &extension.payload_digest[7..23]
    ));
    garbage_collect_failed_extension_volumes(state).await?;
    let preparation_lease = acquire_extension_volume_lease(
        state,
        &volume,
        &manifest.release_id,
        &extension.manifest_digest,
        &extension.payload_digest,
    )
    .await?;
    if docker_volume_exists(state, &volume).await? {
        let verifier = state
            .config
            .docker_resource(format!("ext-verify-{}", &extension.manifest_digest[7..19]));
        run_docker_job(state, &verifier, json!({
            "Image":state.config.extension_helper_image,
            "Entrypoint":["/usr/local/bin/control-extension-helper"],
            "Cmd":["verify","--staged","/target","--target","/target","--manifest","/target/manifest.json","--expected-payload",extension.payload_digest,"--max-files","20000","--max-file-bytes","67108864","--max-bytes",MAX_ARCHIVE_BYTES.to_string(),"--write-marker-last","/target/.mb-complete"],
            "User":"0:0","NetworkDisabled":true,
            "HostConfig":{"NetworkMode":"none","ReadonlyRootfs":true,"CapDrop":["ALL"],"PidsLimit":64,"Memory":536870912,"Tmpfs":{"/tmp":"rw,noexec,nosuid,size=64m"},"Binds":[format!("{volume}:/target:ro")]}
        })).await?;
        mark_extension_volume_verified(state, &volume, preparation_lease).await?;
        return Ok(volume);
    }
    docker_create_extension_volume(
        state,
        &volume,
        &extension.manifest_digest,
        &extension.payload_digest,
    )
    .await?;
    let source = state
        .config
        .docker_resource(format!("ext-source-{}", &extension.manifest_digest[7..19]));
    if docker_container_exists(state, &source).await? {
        docker_delete_container(state, &source).await?;
    }
    docker_create_container(state, &source, DockerRestartPolicy::No, json!({
        "Image":manifest.extension_bundle.oci_ref,
        "Entrypoint":["/bin/false"],
        "Cmd":[],
        "NetworkDisabled":true,
        "Labels":{"mb.kind":"odoo-extension-source"},
        "HostConfig":{"NetworkMode":"none","ReadonlyRootfs":true,"CapDrop":["ALL"],"PidsLimit":16,"Memory":134217728}
    })).await?;
    let extraction = async {
        let archive = tokio::time::timeout(
            Duration::from_secs(120),
            docker_get_archive_bounded(state, &source, "/payload/.", MAX_ARCHIVE_BYTES),
        ).await.map_err(|_| DriverError::bad("extension extraction exceeded its time limit"))??;
        // Docker's archive API writes directly into the otherwise empty target
        // volume; no executable from the transport image is ever started.
        let staging = state
            .config
            .docker_resource(format!("ext-stage-{}", &extension.manifest_digest[7..19]));
        docker_create_container(state, &staging, DockerRestartPolicy::No, json!({
            "Image":state.config.extension_helper_image,
            "Entrypoint":["/bin/false"],"Cmd":[],"NetworkDisabled":true,
            "HostConfig":{"NetworkMode":"none","ReadonlyRootfs":true,"CapDrop":["ALL"],"Binds":[format!("{volume}:/target")]}
        })).await?;
        let put = docker_put_archive(state, &staging, "/target", archive).await;
        let cleanup = docker_delete_container(state, &staging).await;
        put?; cleanup?;
        let helper = state
            .config
            .docker_resource(format!("ext-helper-{}", &extension.manifest_digest[7..19]));
        run_docker_job(state, &helper, json!({
            "Image":state.config.extension_helper_image,
            "Entrypoint":["/usr/local/bin/control-extension-helper"],
            "Cmd":["seal","--staged","/target","--target","/target","--manifest","/target/manifest.json","--expected-payload",extension.payload_digest,"--max-files","20000","--max-file-bytes","67108864","--max-bytes",MAX_ARCHIVE_BYTES.to_string(),"--write-marker-last","/target/.mb-complete"],
            "User":"0:0",
            "NetworkDisabled":true,
            "Labels":{"mb.kind":"odoo-extension-helper","mb.payload":extension.payload_digest},
            "HostConfig":{"NetworkMode":"none","ReadonlyRootfs":true,"CapDrop":["ALL"],"PidsLimit":64,"Memory":536870912,"Tmpfs":{"/tmp":"rw,noexec,nosuid,size=64m"},"Binds":[format!("{volume}:/target")]}
        })).await?;
        Ok::<(), DriverError>(())
    }.await;
    let cleanup = docker_delete_container(state, &source).await;
    extraction?;
    cleanup?;
    mark_extension_volume_verified(state, &volume, preparation_lease).await?;
    Ok(volume)
}

async fn acquire_extension_volume_lease(
    state: &DriverState,
    volume: &str,
    release_id: &str,
    manifest_digest: &str,
    payload_digest: &str,
) -> Result<Uuid, DriverError> {
    let lease = Uuid::new_v4();
    let acquired = sqlx::query_scalar::<_, Uuid>(
        "insert into control.extension_volume_preparations(
           volume_name,release_id,extension_manifest_digest,payload_digest,lease_id,lease_expires_at
         ) values($1,$2,$3,$4,$5,now()+interval '2 hours')
         on conflict(volume_name) do update set
           release_id=excluded.release_id,lease_id=excluded.lease_id,
           lease_expires_at=excluded.lease_expires_at,verified_at=null,updated_at=now()
         where control.extension_volume_preparations.extension_manifest_digest=excluded.extension_manifest_digest
           and control.extension_volume_preparations.payload_digest=excluded.payload_digest
           and (control.extension_volume_preparations.lease_expires_at<=now()
                or control.extension_volume_preparations.verified_at is not null)
         returning lease_id",
    )
    .bind(volume)
    .bind(release_id)
    .bind(manifest_digest)
    .bind(payload_digest)
    .bind(lease)
    .fetch_optional(&state.ledger)
    .await
    .map_err(DriverError::internal)?;
    if acquired != Some(lease) {
        return Err(DriverError::bad(
            "extension volume has an active preparation lease or conflicting identity",
        ));
    }
    Ok(lease)
}

async fn mark_extension_volume_verified(
    state: &DriverState,
    volume: &str,
    lease: Uuid,
) -> Result<(), DriverError> {
    let changed = sqlx::query(
        "update control.extension_volume_preparations
         set verified_at=now(),updated_at=now()
         where volume_name=$1 and lease_id=$2 and lease_expires_at>now()",
    )
    .bind(volume)
    .bind(lease)
    .execute(&state.ledger)
    .await
    .map_err(DriverError::internal)?
    .rows_affected();
    if changed != 1 {
        return Err(DriverError::bad(
            "extension volume preparation lease expired before verification",
        ));
    }
    Ok(())
}

async fn garbage_collect_failed_extension_volumes(state: &DriverState) -> Result<(), DriverError> {
    let candidates = sqlx::query_scalar::<_, String>(
        "select p.volume_name
         from control.extension_volume_preparations p
         join control.application_releases r on r.id=p.release_id
         where p.lease_expires_at<=now() and r.status='failed'
           and not exists(
             select 1 from control.runtime_release_slots s
             where s.extension_volume=p.volume_name
               and s.state in ('starting','verifying','prepared','active','retained')
           )
         order by p.updated_at,p.volume_name limit 16",
    )
    .fetch_all(&state.ledger)
    .await
    .map_err(DriverError::internal)?;
    for volume in candidates {
        let gc_lease = Uuid::new_v4();
        let claimed = sqlx::query(
            "update control.extension_volume_preparations p
             set lease_id=$2,lease_expires_at=now()+interval '10 minutes',updated_at=now()
             from control.application_releases r
             where p.volume_name=$1 and r.id=p.release_id and r.status='failed'
               and p.lease_expires_at<=now()
               and not exists(select 1 from control.runtime_release_slots s where s.extension_volume=p.volume_name)",
        )
        .bind(&volume)
        .bind(gc_lease)
        .execute(&state.ledger)
        .await
        .map_err(DriverError::internal)?
        .rows_affected();
        if claimed != 1 {
            continue;
        }
        docker_delete_extension_volume(state, &volume).await?;
        sqlx::query(
            "delete from control.extension_volume_preparations p
             using control.application_releases r
             where p.volume_name=$1 and p.lease_id=$2 and r.id=p.release_id and r.status='failed'
               and not exists(select 1 from control.runtime_release_slots s where s.extension_volume=p.volume_name)",
        )
        .bind(&volume)
        .bind(gc_lease)
        .execute(&state.ledger)
        .await
        .map_err(DriverError::internal)?;
    }
    Ok(())
}

fn verify_engine_image_identity(
    inspect: &Value,
    expected_subject: &str,
    expected_manifest: &str,
    expected_config: &str,
) -> Result<(), DriverError> {
    if inspect.get("Id").and_then(Value::as_str) != Some(expected_config) {
        return Err(DriverError::bad(
            "selected image configuration digest differs from the release contract",
        ));
    }
    let suffix = format!("@{expected_subject}");
    if !inspect
        .get("RepoDigests")
        .and_then(Value::as_array)
        .is_some_and(|values| {
            values.iter().any(|value| {
                value
                    .as_str()
                    .is_some_and(|reference| reference.ends_with(&suffix))
            })
        })
    {
        return Err(DriverError::bad(
            "local image subject digest differs from the release contract",
        ));
    }
    // API 1.48 exposes the OCI descriptor selected from an index. Requiring it
    // prevents a subject/config-only check from silently accepting a different
    // platform manifest that happens to point at the same configuration.
    if inspect
        .pointer("/Descriptor/digest")
        .and_then(Value::as_str)
        != Some(expected_manifest)
    {
        return Err(DriverError::bad(
            "selected platform manifest digest differs from the release contract",
        ));
    }
    Ok(())
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
    workshop: Uuid,
    adoption: Uuid,
    from: &str,
    to: &str,
    evidence: Option<&Value>,
) -> Result<(), DriverError> {
    let mut tx = state
        .tenant_ledger
        .begin(workshop)
        .await
        .map_err(DriverError::internal)?;
    let changed = sqlx::query(
        "update control.tenant_release_adoptions set state=$4,version=version+1,
                started_at=case when $4='isolating' then coalesce(started_at,now()) else started_at end,
                verified_at=case when $4='prepared' then now() else verified_at end,
                evidence=case when $5::jsonb is null then evidence else evidence || $5 end
         where id=$1 and workshop_id=$2 and state=$3",
    )
    .bind(adoption)
    .bind(workshop)
    .bind(from)
    .bind(to)
    .bind(evidence)
    .execute(&mut *tx)
    .await
    .map_err(DriverError::internal)?
    .rows_affected();
    if changed != 1 {
        return Err(DriverError::internal(format!(
            "tenant adoption transition {from} -> {to} lost its compare-and-set"
        )));
    }
    tx.commit().await.map_err(DriverError::internal)?;
    Ok(())
}

async fn prepare_release_tenant(
    state: &DriverState,
    tenant: &ReleaseTenant,
    manifest: &crate::release::ApplicationReleaseManifest,
    extension_volume: &str,
    runtime_role: &str,
    runtime_password: &str,
    lease: &ReleaseDriverLease,
) -> Result<(), DriverError> {
    renew_release_driver_lease(state, lease).await?;
    let mut phase_tx = state
        .tenant_ledger
        .begin(tenant.workshop_id)
        .await
        .map_err(DriverError::internal)?;
    let mut phase = sqlx::query_scalar::<_, String>(
        "select state from control.tenant_release_adoptions where id=$1 and workshop_id=$2",
    )
    .bind(tenant.id)
    .bind(tenant.workshop_id)
    .fetch_one(&mut *phase_tx)
    .await
    .map_err(DriverError::internal)?;
    phase_tx.commit().await.map_err(DriverError::internal)?;
    if phase == "pending" {
        renew_release_driver_lease(state, lease).await?;
        transition_release_tenant(
            state,
            tenant.workshop_id,
            tenant.id,
            "pending",
            "isolating",
            None,
        )
        .await?;
        phase = "isolating".into();
    }
    if phase == "isolating" {
        renew_release_driver_lease(state, lease).await?;
        enter_release_maintenance(state, tenant.workshop_id, lease).await?;
        drain_workshop_operations(state, tenant.workshop_id).await?;
        isolate_release_database(state, &tenant.database_ref, runtime_role).await?;
        renew_release_driver_lease(state, lease).await?;
        transition_release_tenant(
            state,
            tenant.workshop_id,
            tenant.id,
            "isolating",
            "backing_up",
            Some(&json!({"old_runtime_access_revoked":true})),
        )
        .await?;
        phase = "backing_up".into();
    }
    if phase == "backing_up" {
        renew_release_driver_lease(state, lease).await?;
        create_recovery_set(
            state,
            tenant.workshop_id,
            tenant.backup_recovery_id,
            &tenant.database_ref,
            "backup",
            &tenant.component_scope,
        )
        .await?;
        renew_release_driver_lease(state, lease).await?;
        transition_release_tenant(
            state,
            tenant.workshop_id,
            tenant.id,
            "backing_up",
            "upgrading",
            Some(&json!({"verified_recovery_point_id":tenant.backup_recovery_id})),
        )
        .await?;
        phase = "upgrading".into();
    }
    if phase == "upgrading" {
        renew_release_driver_lease(state, lease).await?;
        run_odoo_release_upgrade(
            state,
            tenant,
            lease,
            &manifest.odoo_runtime.deployment_ref,
            extension_volume,
            runtime_role,
            runtime_password,
        )
        .await?;
        renew_release_driver_lease(state, lease).await?;
        transition_release_tenant(
            state,
            tenant.workshop_id,
            tenant.id,
            "upgrading",
            "verifying",
            None,
        )
        .await?;
        phase = "verifying".into();
    }
    if phase == "verifying" {
        renew_release_driver_lease(state, lease).await?;
        verify_release_database(state, tenant, manifest).await?;
        renew_release_driver_lease(state, lease).await?;
        transition_release_tenant(
            state,
            tenant.workshop_id,
            tenant.id,
            "verifying",
            "prepared",
            Some(&json!({
                "odoo_subject_digest":manifest.odoo_runtime.subject_digest,
                "extension_subject_digest":manifest.extension_bundle.subject_digest,
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
    workshop: Uuid,
    adoption: Uuid,
    failure_class: &str,
) -> Result<(), DriverError> {
    let mut tx = state
        .tenant_ledger
        .begin(workshop)
        .await
        .map_err(DriverError::internal)?;
    let changed = sqlx::query(
        "update control.tenant_release_adoptions
         set state='failed',failure_class=$3,version=version+1
         where id=$1 and workshop_id=$2
           and state in ('pending','isolating','backing_up','upgrading','verifying')",
    )
    .bind(adoption)
    .bind(workshop)
    .bind(failure_class)
    .execute(&mut *tx)
    .await
    .map_err(DriverError::internal)?
    .rows_affected();
    if changed != 1 {
        return Err(DriverError::internal(
            "scoped release failure target was lost",
        ));
    }
    tx.commit().await.map_err(DriverError::internal)?;
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
    lease: &ReleaseDriverLease,
    image: &str,
    extension_volume: &str,
    runtime_role: &str,
    runtime_password: &str,
) -> Result<(), DriverError> {
    let executor = ReleaseExecutorIdentity::new(
        lease
            .fleet_run_id
            .ok_or_else(|| DriverError::internal("release executor fleet identity is absent"))?,
        lease.driver_operation_id,
        lease.fence_token,
        tenant.id,
    )?;
    let executor_application_name = executor.postgres_application_name();
    let job_configuration = format!(
        "{}db_app_name = {executor_application_name}\n",
        odoo_configuration(state, runtime_role, runtime_password)?
    );
    let container = state.config.docker_resource(format!(
        "release-upgrade-{}",
        &tenant.id.simple().to_string()[..12]
    ));
    run_docker_job_with_secrets(
        state,
        &container,
        json!({
            "Image":image,
            "Cmd":[
                "/bin/sh","-ec",
                "exec odoo --database=\"$MB_ODOO_DATABASE\" --stop-after-init --no-http --no-database-list --addons-path=/opt/mb-extension/addons,/usr/lib/python3/dist-packages/odoo/addons --update=all --without-demo=all"
            ],
            "Env":[
                format!("MB_ODOO_DATABASE={}",tenant.database_ref),
                format!("HOST={}",state.config.postgres_host),
                format!("PORT={}",state.config.postgres_port),
                format!("USER={runtime_role}"),
                "ODOO_RC=/run/mb-job-secrets/odoo.conf".to_owned(),
                "PYTHONPATH=/opt/mb-extension/python".to_owned(),
                format!("PGAPPNAME={executor_application_name}"),
                "MB_CONTROL_BRIDGE_TOKEN_FILE=/run/mb-job-secrets/bridge-token".to_owned()
            ],
            "Labels": executor.labels().as_object().cloned().unwrap_or_default().into_iter().chain(serde_json::Map::from_iter([
                ("mb.kind".to_owned(), json!("odoo-release-upgrade")),
                ("mb.workshop".to_owned(), json!(tenant.workshop_id.to_string())),
                ("mb.database".to_owned(), json!(tenant.database_id.to_string())),
            ])).collect::<serde_json::Map<String, Value>>(),
            "HostConfig":{
                "NetworkMode":state.config.docker_network,
                "ReadonlyRootfs":true,
                "Binds":[format!("{}:/var/lib/odoo",state.config.odoo_volume),format!("{extension_volume}:/opt/mb-extension:ro")],
                "Tmpfs":{"/tmp":"rw,noexec,nosuid,size=64m","/var/run/odoo":"rw,noexec,nosuid,size=16m"},
                "CapDrop":["ALL"]
            }
        }),
        &[
            ("odoo.conf", &job_configuration),
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
    verify_release_database_identity(state, &tenant.database_ref, tenant.workshop_id, manifest)
        .await
}

pub(super) async fn verify_release_database_identity(
    state: &DriverState,
    database_ref: &str,
    workshop_id: Uuid,
    manifest: &crate::release::ApplicationReleaseManifest,
) -> Result<(), DriverError> {
    let pool = database_pool(state, database_ref).await?;
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
    if workshop.as_deref() != Some(workshop_id.to_string().as_str()) {
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
    extension_volume: &str,
    runtime_role: &str,
    runtime_password: &str,
    boot_selected: bool,
) -> Result<(), DriverError> {
    let release_secret_directory = driver_runtime_secret_root(state).join("releases");
    secure_directory(&release_secret_directory).map_err(DriverError::internal)?;
    let configuration_name = format!("{runtime_role}.conf");
    write_protected_configuration(
        &release_secret_directory.join(&configuration_name),
        &odoo_configuration(state, runtime_role, runtime_password)?,
    )
    .map_err(DriverError::internal)?;
    let config_digest = release_runtime_config_digest(state, image, runtime_role, runtime_password);
    let mut environment = vec![
        format!("HOST={}", state.config.postgres_host),
        format!("PORT={}", state.config.postgres_port),
        format!("USER={runtime_role}"),
        format!("MB_CONTROL_API_URL={}", state.config.control_internal_url),
        "MB_ODOO_CLIENT_TOKEN_ROOT=/run/mb-odoo-client-secrets".into(),
        "MB_CONTROL_BRIDGE_TOKEN_FILE=/run/mb-release-secrets/bridge-token".into(),
        format!("ODOO_RC=/run/mb-release-secrets/{configuration_name}"),
        "PYTHONPATH=/opt/mb-extension/python".into(),
    ];
    if state.config.postgres_ca_source.is_some() {
        environment.push("PGSSLMODE=verify-full".into());
        environment.push("PGSSLROOTCERT=/run/mb-postgres-ca/postgres-ca.crt".into());
    }
    if let RuntimeBackend::Quadlet(backend) = &state.backend {
        let slot = container
            .strip_suffix("-blue")
            .map(|_| "blue")
            .or_else(|| container.strip_suffix("-green").map(|_| "green"))
            .ok_or_else(|| DriverError::internal("Odoo slot container name is invalid"))?;
        backend
            .ensure_odoo_slot(&OdooSlotDesired {
                slot: slot.into(),
                container_name: container.into(),
                image: image.into(),
                config_digest,
                environment: environment
                    .iter()
                    .map(|entry| {
                        entry
                            .split_once('=')
                            .map(|(key, value)| (key.into(), value.into()))
                            .ok_or_else(|| DriverError::internal("invalid Odoo environment entry"))
                    })
                    .collect::<Result<Vec<_>, _>>()?,
                secret_directory: release_secret_directory,
                client_secret_directory: Path::new(&state.config.runtime_secret_source)
                    .join("runtime/odoo-clients"),
                postgres_ca: state.config.postgres_ca_source.clone(),
                extension_volume: extension_volume.into(),
                data_volume: state.config.odoo_volume.clone(),
                network: state.config.docker_network.clone(),
                boot_selected,
            })
            .await?;
        return Ok(());
    }
    if docker_container_exists(state, container).await? {
        let inspect = docker_inspect_container(state, container).await?;
        if inspect
            .pointer("/Config/Labels/mb.config-digest")
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
        let mut mounts = vec![
            runtime_secret_mount(state, Path::new("releases"), "/run/mb-release-secrets")?,
            runtime_secret_mount(
                state,
                Path::new("odoo-clients"),
                "/run/mb-odoo-client-secrets",
            )?,
        ];
        if let Some(ca_mount) = postgres_ca_mount(state)? {
            mounts.push(ca_mount);
        }
        docker_create_container(
            state,
            container,
            DockerRestartPolicy::No,
            json!({
                "Image":image,
                "Cmd":[
                    "odoo","--no-database-list","--addons-path=/opt/mb-extension/addons,/usr/lib/python3/dist-packages/odoo/addons","--load=base,web,mb_dbfilter_gateway","--proxy-mode"
                ],
                "Env":environment,
                "Labels":{
                    "mb.kind":"odoo-release-runtime",
                    "mb.config-digest":config_digest,
                    "mb.image-digest":image
                },
                "HostConfig":{
                    "NetworkMode":state.config.docker_network,
                    "ReadonlyRootfs":true,
                    "Binds":[format!("{}:/var/lib/odoo",state.config.odoo_volume),format!("{extension_volume}:/opt/mb-extension:ro")],
                    "Tmpfs":{"/tmp":"rw,noexec,nosuid,size=64m","/var/run/odoo":"rw,noexec,nosuid,size=16m"},
                    "CapDrop":["ALL"],
                    "GroupAdd":["0"],
                    "Mounts":mounts
                }
            }),
        )
        .await?;
        docker_start_container(state, container).await?;
    }
    Ok(())
}

pub(super) fn release_runtime_config_digest(
    state: &DriverState,
    image: &str,
    runtime_role: &str,
    runtime_password: &str,
) -> String {
    format!(
        "sha256:{:x}",
        Sha256::digest(
            format!(
                "{image}\0{runtime_role}\0{runtime_password}\0{}\0driver-secret-runtime-v2",
                state.config.runtime_secret_source
            )
            .as_bytes()
        )
    )
}

async fn smoke_release_runtime(
    state: &DriverState,
    container: &str,
    tenant: &ReleaseTenant,
) -> Result<(), DriverError> {
    smoke_release_runtime_identity(state, container, tenant.workshop_id, &tenant.database_ref).await
}

pub(super) async fn smoke_release_runtime_identity(
    state: &DriverState,
    container: &str,
    workshop: Uuid,
    database_ref: &str,
) -> Result<(), DriverError> {
    let tenant_bridge_token = std::fs::read_to_string(
        state
            .config
            .secret_root
            .join("docker")
            .join(workshop.to_string())
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
    let client = super::startup::odoo_readiness_client()?;
    for _ in 0..90 {
        let runtime_url = match state.backend {
            RuntimeBackend::Docker => format!("http://{container}:8069"),
            RuntimeBackend::Quadlet(_) => {
                if container.ends_with("-blue") {
                    "http://127.0.0.1:18069".into()
                } else if container.ends_with("-green") {
                    "http://127.0.0.1:18070".into()
                } else {
                    return Err(DriverError::internal("invalid Odoo slot runtime name"));
                }
            }
        };
        let response = super::startup::odoo_readiness_request(
            &client,
            format!("{runtime_url}/mb_control/v1/health"),
            database_ref,
            &tenant_bridge_token,
            None,
        )
        .with_current_trace_context()
        .send()
        .await;
        if let Ok(response) = response
            && response.status().is_success()
            && let Ok(body) = response.json::<Value>().await
            && body.get("status").and_then(Value::as_str) == Some("ready")
            && body.get("database").and_then(Value::as_str) == Some(database_ref)
            && body.get("workshop_id").and_then(Value::as_str)
                == Some(workshop.to_string().as_str())
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    Err(DriverError::internal(
        "candidate runtime failed an isolated tenant smoke test",
    ))
}

/// One read-only readiness observation for reconciliation. Unlike the normal
/// release path this does not retry under a fixed reconciliation claim.
pub(super) async fn observe_release_runtime_identity_once(
    state: &DriverState,
    container: &str,
    workshop: Uuid,
    database_ref: &str,
    tenant_bridge_token: &str,
) -> Result<bool, DriverError> {
    if tenant_bridge_token.is_empty() {
        return Ok(false);
    }
    let runtime_url = match state.backend {
        RuntimeBackend::Docker => format!("http://{container}:8069"),
        RuntimeBackend::Quadlet(_) if container.ends_with("-blue") => {
            "http://127.0.0.1:18069".into()
        }
        RuntimeBackend::Quadlet(_) if container.ends_with("-green") => {
            "http://127.0.0.1:18070".into()
        }
        RuntimeBackend::Quadlet(_) => return Ok(false),
    };
    let response = super::startup::odoo_readiness_request(
        &super::startup::odoo_readiness_client()?,
        format!("{runtime_url}/mb_control/v1/health"),
        database_ref,
        tenant_bridge_token,
        None,
    )
    .with_current_trace_context()
    .send()
    .await;
    let Ok(response) = response else {
        return Ok(false);
    };
    if !response.status().is_success() {
        return Ok(false);
    }
    let body = response
        .json::<Value>()
        .await
        .map_err(DriverError::internal)?;
    Ok(body.get("status").and_then(Value::as_str) == Some("ready")
        && body.get("database").and_then(Value::as_str) == Some(database_ref)
        && body.get("workshop_id").and_then(Value::as_str) == Some(workshop.to_string().as_str()))
}

async fn activate_release_routes(
    state: &DriverState,
    runtime_container: &str,
    tenants: &[ReleaseTenant],
    lease: &ReleaseDriverLease,
    gateway_identity: &ReleaseGatewayGenerationIdentity,
) -> Result<String, DriverError> {
    for tenant in tenants {
        require_release_route_reservation(lease, tenant.workshop_id)?;
    }
    renew_release_driver_lease(state, lease).await?;
    let selected = selected_route_root(&state.config.route_root)?;
    let mut replacements = Vec::with_capacity(tenants.len());
    for tenant in tenants {
        let backup = selected.join(format!("{}.recovery.bak", tenant.workshop_id));
        let previous = std::fs::read(&backup).map_err(DriverError::internal)?;
        let previous_text = std::str::from_utf8(&previous)
            .map_err(|_| DriverError::internal("saved tenant route is not UTF-8"))?;
        let candidate = select_odoo_route_upstream(previous_text, runtime_container)?.into_bytes();
        replacements.push((tenant.workshop_id, previous, candidate));
    }
    let digest = route_set_digest(
        replacements
            .iter()
            .map(|(workshop, _, candidate)| (*workshop, candidate.as_slice())),
    );
    if gateway_identity.gateway_configuration_digest != digest {
        return Err(DriverError::internal(
            "release gateway identity differs from its route candidate",
        ));
    }
    let generation_path = selected.join(RELEASE_GATEWAY_GENERATION_FILE);
    let previous_generation = std::fs::read(&generation_path).ok();
    for (workshop, _, candidate) in &replacements {
        renew_release_driver_lease(state, lease).await?;
        let path = selected.join(format!("{workshop}.conf"));
        let temporary = selected.join(format!("{workshop}.release.tmp"));
        write_gateway_file(&temporary, candidate).map_err(DriverError::internal)?;
        std::fs::rename(&temporary, &path).map_err(DriverError::internal)?;
    }
    let generation_temporary = selected.join(format!("{RELEASE_GATEWAY_GENERATION_FILE}.tmp"));
    write_gateway_file(
        &generation_temporary,
        release_gateway_generation_config(gateway_identity)?,
    )
    .map_err(DriverError::internal)?;
    std::fs::rename(&generation_temporary, &generation_path).map_err(DriverError::internal)?;
    renew_release_driver_lease(state, lease).await?;
    if let Err(error) = reload_gateway_runtime(state, &digest).await {
        for (workshop, previous, _) in &replacements {
            renew_release_driver_lease(state, lease).await?;
            let maintenance = previous_route_maintenance(previous)?;
            write_gateway_file(&selected.join(format!("{workshop}.conf")), maintenance)
                .map_err(DriverError::internal)?;
        }
        restore_release_gateway_identity(&generation_path, previous_generation.as_deref())?;
        return Err(error);
    }
    Ok(digest)
}

async fn remove_release_route_backups(
    state: &DriverState,
    lease: &ReleaseDriverLease,
    tenants: &[ReleaseTenant],
) -> Result<(), DriverError> {
    let selected = selected_route_root(&state.config.route_root)?;
    for tenant in tenants {
        renew_release_driver_lease(state, lease).await?;
        let backup = selected.join(format!("{}.recovery.bak", tenant.workshop_id));
        match std::fs::remove_file(backup) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(DriverError::internal(error)),
        }
    }
    renew_release_driver_lease(state, lease).await
}

fn restore_release_gateway_identity(
    path: &Path,
    previous: Option<&[u8]>,
) -> Result<(), DriverError> {
    if let Some(previous) = previous {
        write_gateway_file(path, previous).map_err(DriverError::internal)
    } else {
        match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(DriverError::internal(error)),
        }
    }
}

async fn publish_release_gateway_identity(
    state: &DriverState,
    lease: &ReleaseDriverLease,
    identity: &ReleaseGatewayGenerationIdentity,
) -> Result<(), DriverError> {
    let selected = selected_route_root(&state.config.route_root)?;
    let path = selected.join(RELEASE_GATEWAY_GENERATION_FILE);
    let temporary = selected.join(format!("{RELEASE_GATEWAY_GENERATION_FILE}.tmp"));
    let previous = std::fs::read(&path).ok();
    renew_release_driver_lease(state, lease).await?;
    write_gateway_file(&temporary, release_gateway_generation_config(identity)?)
        .map_err(DriverError::internal)?;
    std::fs::rename(&temporary, &path).map_err(DriverError::internal)?;
    renew_release_driver_lease(state, lease).await?;
    if let Err(error) = reload_gateway_runtime(state, &identity.gateway_configuration_digest).await
    {
        restore_release_gateway_identity(&path, previous.as_deref())?;
        return Err(error);
    }
    renew_release_driver_lease(state, lease).await
}

fn require_release_route_reservation(
    lease: &ReleaseDriverLease,
    workshop: Uuid,
) -> Result<(), DriverError> {
    if lease.reserved_workshops.binary_search(&workshop).is_err() {
        return Err(DriverError::internal(
            "release attempted a route effect outside its frozen reservation",
        ));
    }
    Ok(())
}

async fn enter_release_maintenance(
    state: &DriverState,
    workshop: Uuid,
    lease: &ReleaseDriverLease,
) -> Result<Vec<u8>, DriverError> {
    require_release_route_reservation(lease, workshop)?;
    renew_release_driver_lease(state, lease).await?;
    let previous = enter_workshop_maintenance(state, workshop).await?;
    renew_release_driver_lease(state, lease).await?;
    Ok(previous)
}

async fn leave_release_maintenance(
    state: &DriverState,
    workshop: Uuid,
    previous: &[u8],
    lease: &ReleaseDriverLease,
) -> Result<(), DriverError> {
    require_release_route_reservation(lease, workshop)?;
    renew_release_driver_lease(state, lease).await?;
    leave_workshop_maintenance(state, workshop, previous).await?;
    renew_release_driver_lease(state, lease).await
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
    let selected = selected_route_root(&state.config.route_root)?;
    let mut routes = Vec::with_capacity(tenants.len());
    for tenant in tenants {
        let previous = std::fs::read(selected.join(format!("{}.recovery.bak", tenant.workshop_id)))
            .map_err(DriverError::internal)?;
        let candidate = select_odoo_route_upstream(
            std::str::from_utf8(&previous)
                .map_err(|_| DriverError::internal("saved tenant route is not UTF-8"))?,
            runtime_container,
        )?;
        routes.push((tenant.workshop_id, candidate.into_bytes()));
    }
    Ok(route_set_digest(
        routes
            .iter()
            .map(|(workshop, route)| (*workshop, route.as_slice())),
    ))
}

fn select_odoo_route_upstream(
    previous: &str,
    runtime_container: &str,
) -> Result<String, DriverError> {
    let marker = "set $tenant_upstream \"";
    let start = previous
        .find(marker)
        .map(|index| index + marker.len())
        .ok_or_else(|| DriverError::internal("saved tenant route has no Odoo upstream"))?;
    let relative_end = previous[start..]
        .find(":8069\";")
        .ok_or_else(|| DriverError::internal("saved tenant route has no Odoo upstream"))?;
    let end = start + relative_end + ":8069".len();
    let mut selected = previous.to_owned();
    selected.replace_range(start..end, &format!("{runtime_container}:8069"));
    Ok(selected)
}

fn observed_release_route_digest(
    state: &DriverState,
    tenants: &[ReleaseTenant],
) -> Result<Option<String>, DriverError> {
    let selected = selected_route_root(&state.config.route_root)?;
    let mut routes = Vec::with_capacity(tenants.len());
    for tenant in tenants {
        let path = selected.join(format!("{}.conf", tenant.workshop_id));
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

pub(super) fn route_set_digest<'a>(routes: impl Iterator<Item = (Uuid, &'a [u8])>) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn initial_runtime_requires_the_running_declared_image() {
        let image = format!("registry.example/odoo@sha256:{}", "a".repeat(64));
        let config = format!("sha256:{}", "b".repeat(64));
        let volume = "mb-ext-example";
        let inspect = json!({
            "State":{"Running":true},"Config":{"Image":image},"Image":config,
            "HostConfig":{"ReadonlyRootfs":true},
            "Mounts":[{"Source":volume,"Destination":"/opt/mb-extension","RW":false}]
        });
        assert!(initial_runtime_inspection_matches(
            &inspect, &image, &config, volume,
        ));
        let mut stopped = inspect.clone();
        stopped["State"]["Running"] = json!(false);
        assert!(!initial_runtime_inspection_matches(
            &stopped, &image, &config, volume,
        ));
        let mut wrong_image = inspect.clone();
        wrong_image["Config"]["Image"] = json!("registry.example/odoo@sha256:wrong");
        assert!(!initial_runtime_inspection_matches(
            &wrong_image,
            &image,
            &config,
            volume,
        ));
        let mut writable_extension = inspect;
        writable_extension["Mounts"][0]["RW"] = json!(true);
        assert!(!initial_runtime_inspection_matches(
            &writable_extension,
            &image,
            &config,
            volume,
        ));
    }

    #[test]
    fn engine_identity_binds_subject_selected_manifest_and_configuration() {
        let subject = format!("sha256:{}", "a".repeat(64));
        let manifest = format!("sha256:{}", "b".repeat(64));
        let config = format!("sha256:{}", "c".repeat(64));
        let inspect = json!({
            "Id":config,
            "RepoDigests":[format!("registry.example/odoo@{subject}")],
            "Descriptor":{"digest":manifest}
        });
        assert!(verify_engine_image_identity(&inspect, &subject, &manifest, &config).is_ok());

        let mut wrong_manifest = inspect.clone();
        wrong_manifest["Descriptor"]["digest"] = json!(format!("sha256:{}", "d".repeat(64)));
        assert!(
            verify_engine_image_identity(&wrong_manifest, &subject, &manifest, &config).is_err()
        );
    }

    #[test]
    fn release_adoption_reads_and_mutations_use_composite_tenant_identity() {
        let source = include_str!("release.rs");

        assert!(source.contains("control.read_release_driver_tenants("));
        assert!(!source.contains(&["join control.", "workshop_recovery_points"].concat()));
        assert!(source.contains(
            "select state from control.tenant_release_adoptions where id=$1 and workshop_id=$2"
        ));
        assert!(source.contains("where id=$1 and workshop_id=$2 and state=$3"));
        assert_eq!(
            source
                .matches("where id=$1 and workshop_id=$2\n           and state in")
                .count(),
            2,
            "rollback evidence and failure transitions must both be tenant scoped"
        );
    }

    #[test]
    fn fleet_snapshot_is_canonical_and_verified_before_external_effects() {
        let first_workshop = Uuid::parse_str("00000000-0000-0000-0000-000000000202").unwrap();
        let second_workshop = Uuid::parse_str("00000000-0000-0000-0000-000000000201").unwrap();
        let tenant = |workshop_id: Uuid, paperless: bool| ReleaseTenant {
            id: Uuid::new_v4(),
            workshop_id,
            database_id: Uuid::new_v4(),
            database_ref: format!("mb_{}", workshop_id.simple()),
            public_hostname: format!("{}.example.test", workshop_id.simple()),
            backup_recovery_id: Uuid::new_v4(),
            component_scope: if paperless {
                vec!["odoo".into(), "paperless".into()]
            } else {
                vec!["odoo".into()]
            },
        };
        let first = tenant(first_workshop, false);
        let second = tenant(second_workshop, true);
        let snapshot = release_tenant_snapshot(&[first, second]);
        let rows = snapshot.as_array().unwrap();
        assert_eq!(rows[0]["workshop_id"], json!(second_workshop));
        assert_eq!(rows[0]["paperless_enabled"], json!(true));
        assert_eq!(rows[1]["workshop_id"], json!(first_workshop));
        assert_eq!(rows[1]["paperless_enabled"], json!(false));

        let reservations = release_tenant_workshops(&[
            tenant(first_workshop, false),
            tenant(second_workshop, true),
        ])
        .unwrap();
        assert_eq!(reservations, vec![second_workshop, first_workshop]);
        assert!(
            release_tenant_workshops(&[
                tenant(first_workshop, false),
                tenant(first_workshop, true),
            ])
            .is_err()
        );

        let source = include_str!("release.rs");
        let fleet = source
            .split("pub(super) async fn release_fleet(")
            .nth(1)
            .unwrap();
        assert!(
            fleet.find("release_tenant_snapshot(&tenants)").unwrap()
                < fleet.find("materialize_extension(").unwrap(),
            "immutable tenant identity must be checked before Docker or PostgreSQL effects"
        );
        assert!(
            fleet.find("release_tenant_workshops(&tenants)").unwrap()
                < fleet.find("materialize_extension(").unwrap(),
            "the admitted route reservation must be verified before external effects"
        );
    }

    #[test]
    fn initial_empty_fleet_precondition_precedes_materialization() {
        let source = include_str!("release.rs");
        let initial = source
            .split("async fn prepare_initial_release(")
            .nth(1)
            .unwrap()
            .split("fn release_runtime_config_digest(")
            .next()
            .unwrap();
        assert!(
            initial.find("initial_release_preparable").unwrap()
                < initial
                    .find("materialize_extension(state, &manifest)")
                    .unwrap(),
            "initial runtime materialization must follow the authoritative empty-fleet check"
        );
        assert!(initial.contains("lease.reserved_workshops.is_empty()"));
    }

    #[test]
    fn release_effects_checkpoint_the_database_lease_and_publish_fenced_evidence() {
        let source = include_str!("release.rs");
        let fleet = source
            .split("pub(super) async fn release_fleet(")
            .nth(1)
            .unwrap()
            .split("async fn rollback_failed_release_tenant(")
            .next()
            .unwrap();
        assert!(
            fleet
                .matches("renew_release_driver_lease(state, lease).await?")
                .count()
                >= 9,
            "fleet-wide materialization, tenant, runtime, routing, retirement and evidence boundaries must renew the database lease"
        );
        for effect in [
            "materialize_extension(state, &manifest)",
            "prepare_release_tenant(",
            "ensure_release_runtime(",
            "smoke_release_runtime(",
            "activate_release_routes(",
            "docker_stop_container(state, &old_container)",
        ] {
            assert!(
                fleet.contains(effect),
                "missing release effect boundary {effect}"
            );
        }
        assert!(fleet.contains("\"driver_operation_id\":lease.driver_operation_id"));
        assert!(fleet.contains("\"driver_fence_token\":lease.fence_token"));

        let tenant = source
            .split("async fn prepare_release_tenant(")
            .nth(1)
            .unwrap()
            .split("async fn mark_release_tenant_failed(")
            .next()
            .unwrap();
        assert!(
            tenant
                .matches("renew_release_driver_lease(state, lease).await?")
                .count()
                >= 9,
            "every resumable tenant phase must renew before and after its external effect"
        );
    }
}
