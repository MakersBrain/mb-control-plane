use super::*;

pub(super) async fn download_backup(
    state: &DriverState,
    workshop: Uuid,
    payload: &Value,
) -> Result<Value, DriverError> {
    let recovery = payload_uuid(payload, "recovery_point_id")?;
    let object_key = sqlx::query_scalar::<_, String>(
        "select archive_object_key from control.workshop_recovery_points
         where id=$1 and workshop_id=$2 and kind='backup' and state='ready'
           and verification_state='verified' and archive_object_key is not null",
    )
    .bind(recovery)
    .bind(workshop)
    .fetch_optional(&state.ledger)
    .await
    .map_err(DriverError::internal)?
    .ok_or_else(|| DriverError::bad("backup archive is not ready for download"))?;
    let s3 = state
        .config
        .s3_backup
        .as_ref()
        .ok_or_else(|| DriverError::bad("portable S3 backups are not configured"))?;
    let image = state
        .config
        .backup_agent_image
        .as_ref()
        .ok_or_else(|| DriverError::bad("backup agent image is not configured"))?;
    let result_name = format!("presigned-{}.txt", Uuid::new_v4());
    let result_path = state.config.backup_root.join(&result_name);
    run_docker_job_with_secrets(
        state,
        &format!("mb-presign-{}", &recovery.simple().to_string()[..12]),
        json!({
            "Image": image,
            "User": "0:0",
            "Cmd": ["sh", "-ec", format!("set -eu; umask 077; {}; aws --endpoint-url \"$S3_ENDPOINT\" s3 presign --expires-in 600 \"s3://$S3_BUCKET/$ARCHIVE_KEY\" > /backups/{result_name}", aws_secret_prelude())],
            "Env": [
                format!("AWS_DEFAULT_REGION={}", s3.region),
                format!("S3_ENDPOINT={}", s3.endpoint),
                format!("S3_BUCKET={}", s3.bucket),
                format!("ARCHIVE_KEY={object_key}"),
            ],
            "Labels": {"makersbrain.kind":"s3-backup-presign-job"},
            "HostConfig": {"Binds": [format!("{}:/backups", state.config.backup_volume)]}
        }),
        &s3_job_secrets(s3, false),
    )
    .await?;
    let url = std::fs::read_to_string(&result_path)
        .map_err(DriverError::internal)?
        .trim()
        .to_owned();
    let _ = std::fs::remove_file(&result_path);
    Url::parse(&url).map_err(DriverError::internal)?;
    Ok(json!({"url":url,"expires_in":600,"filename":format!("makersbrain-{recovery}.tar")}))
}

pub(super) async fn rehearse(
    state: &DriverState,
    workshop: Uuid,
    payload: &Value,
) -> Result<Value, DriverError> {
    let recovery = payload_uuid(payload, "recovery_point_id")?;
    let stored = resolve_stored_recovery(state, workshop, recovery).await?;
    if !stored.storage_ref.starts_with("s3://") || stored.format_version != RECOVERY_FORMAT_V2 {
        return Err(DriverError::bad(
            "only verified portable recovery sets can be rehearsed",
        ));
    }
    restore_remote_recovery_set(
        state,
        workshop,
        "rehearsal-does-not-cut-over",
        &stored.storage_ref,
        &stored.component_scope,
        true,
    )
    .await?;
    Ok(json!({"action":"rehearse","recovery_point_id":recovery,"status":"succeeded"}))
}

pub(super) async fn lifecycle(
    state: &DriverState,
    workshop: Uuid,
    payload: &Value,
) -> Result<Value, DriverError> {
    let deleting = payload.get("action").and_then(Value::as_str) == Some("delete");
    let paperless_container = format!("mb-paperless-{}", tenant_key(workshop));
    let paperless_running = if docker_container_exists(state, &paperless_container).await? {
        docker_inspect_container(state, &paperless_container)
            .await?
            .pointer("/State/Running")
            .and_then(Value::as_bool)
            == Some(true)
    } else {
        false
    };
    let previous_routes = enter_workshop_maintenance(state, workshop).await?;
    let result = async {
        let operation = async {
            if paperless_running {
                docker_stop_container(state, &paperless_container).await?;
            }
            drain_workshop_operations(state, workshop).await?;
            lifecycle_quiesced(state, workshop, payload).await
        }
        .await;
        let restart = if paperless_running && !(deleting && operation.is_ok()) {
            match docker_start_container(state, &paperless_container).await {
                Ok(()) => {
                    wait_for_healthy_container(state, &paperless_container, "Paperless").await
                }
                Err(error) => Err(error),
            }
        } else {
            Ok(())
        };
        match (operation, restart) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), Ok(())) => Err(error),
            (_, Err(error)) => Err(error),
        }
    }
    .await;
    let is_restore = payload.get("action").and_then(Value::as_str) == Some("restore");
    if is_restore && result.is_err() {
        tracing::error!(%workshop, "leaving workshop route in maintenance after unresolved restore failure");
        return result;
    }
    if is_restore && result.is_ok() && requires_erasure_replay_fence(payload) {
        tracing::info!(%workshop, "retaining maintenance route until erasure replay is evidenced");
        return result;
    }
    if deleting && result.is_ok() {
        let carrier_secrets = state
            .config
            .secret_root
            .join("docker")
            .join(workshop.to_string())
            .join("carrier");
        if carrier_secrets.exists() {
            std::fs::remove_dir_all(&carrier_secrets).map_err(DriverError::internal)?;
        }
        tracing::info!(%workshop, "workshop final backup verified; retaining maintenance quarantine");
        return result;
    }
    let route_restore = leave_workshop_maintenance(state, workshop, &previous_routes).await;
    match (result, route_restore) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (_, Err(error)) => Err(error),
    }
}

pub(super) fn requires_erasure_replay_fence(payload: &Value) -> bool {
    payload
        .get("action")
        .and_then(Value::as_str)
        .is_some_and(|action| action == "restore")
        && payload
            .get("erasure_replay_required")
            .and_then(Value::as_bool)
            == Some(true)
}

pub(super) async fn resume_after_erasure_replay(
    state: &DriverState,
    workshop: Uuid,
    payload: &Value,
) -> Result<Value, DriverError> {
    let operation = payload_uuid(payload, "restore_operation_id")?;
    let database = payload_uuid(payload, "database_id")?;
    let safe = sqlx::query_scalar::<_, bool>(
        "select exists(
             select 1 from control.odoo_databases
             where id=$1 and workshop_id=$2 and kind='primary' and state='ready'
         ) and exists(
             select 1 from control.operations
             where id=$3 and workshop_id=$2 and kind='tenant.lifecycle'
         ) and not exists(
             select 1 from control.erasure_restore_replays
             where operation_id=$3 and state<>'complete'
         )",
    )
    .bind(database)
    .bind(workshop)
    .bind(operation)
    .fetch_one(&state.ledger)
    .await
    .map_err(DriverError::internal)?;
    if !safe {
        return Err(DriverError::bad(
            "restore erasure replay is not complete; maintenance must remain active",
        ));
    }
    let backup = state
        .config
        .route_root
        .join(format!("{workshop}.recovery.bak"));
    if backup.is_file() {
        let previous = std::fs::read(&backup).map_err(DriverError::internal)?;
        leave_workshop_maintenance(state, workshop, &previous).await?;
    }
    Ok(json!({"action":"resume","routable":true,"restore_operation_id":operation}))
}

pub(super) async fn apply_restored_erasure(
    state: &DriverState,
    workshop: Uuid,
    payload: &Value,
) -> Result<Value, DriverError> {
    let restore_operation = payload_uuid(payload, "restore_operation_id")?;
    let replay = payload_uuid(payload, "replay_id")?;
    let tombstone = payload_uuid(payload, "tombstone_id")?;
    let user = payload_uuid(payload, "control_user_id")?;
    let subject_key = payload_uuid(payload, "subject_key")?;
    let location = payload
        .get("location")
        .and_then(Value::as_str)
        .filter(|value| matches!(*value, "odoo" | "paperless"))
        .ok_or_else(|| DriverError::bad("invalid erasure replay location"))?;
    let rauthy_subject = payload
        .get("rauthy_subject")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 255)
        .ok_or_else(|| DriverError::bad("invalid erasure subject lookup"))?;
    let authorized = sqlx::query_scalar::<_, bool>(
        "select exists(
             select 1 from control.erasure_restore_replays r
             join control.erasure_tombstones t on t.id=r.tombstone_id
             where r.id=$1 and r.tombstone_id=$2 and r.operation_id=$3
               and t.workshop_id=$4 and r.state='applying' and $5=any(r.required_locations)
         )",
    )
    .bind(replay)
    .bind(tombstone)
    .bind(restore_operation)
    .bind(workshop)
    .bind(location)
    .fetch_one(&state.ledger)
    .await
    .map_err(DriverError::internal)?;
    if !authorized {
        return Err(DriverError::bad("erasure replay is not authorized"));
    }
    let row = sqlx::query_as::<_, (String, String, Option<String>)>(
        "select si.base_url,si.secret_ref,od.database_ref
         from control.service_instances si
         left join control.odoo_databases od on od.workshop_id=si.workshop_id
           and od.kind='primary' and od.deleted_at is null and si.service='odoo'
         where si.workshop_id=$1 and si.service=$2",
    )
    .bind(workshop)
    .bind(location)
    .fetch_optional(&state.ledger)
    .await
    .map_err(DriverError::internal)?
    .ok_or_else(|| DriverError(StatusCode::NOT_FOUND, "processor service not found".into()))?;
    let expected_reference = format!("docker/{workshop}/{location}");
    if row.1 != expected_reference {
        return Err(DriverError::bad(
            "processor secret reference is not tenant-scoped",
        ));
    }
    let secret_root = if location == "paperless" {
        &state.config.paperless_client_secret_root
    } else {
        &state.config.secret_root
    };
    let secret_path = secret_root
        .join("docker")
        .join(workshop.to_string())
        .join(location);
    let token = std::fs::read_to_string(secret_path)
        .map_err(DriverError::internal)?
        .trim()
        .to_owned();
    if token.is_empty() {
        return Err(DriverError::internal("processor credential is empty"));
    }
    match location {
        "odoo" => {
            let client = OdooClient::new(&row.0, &token, row.2.as_deref(), Duration::from_secs(30))
                .map_err(DriverError::internal)?;
            client
                .replay_erasure(&ErasureReplayCommand {
                    operation_key: format!("erasure-replay:{tombstone}"),
                    workshop_id: workshop,
                    user_id: user,
                    subject_key,
                })
                .await
                .map_err(|_| DriverError::internal("Odoo erasure replay failed"))?;
        }
        "paperless" => {
            let client = PaperlessClient::new(&row.0, &token, Duration::from_secs(30))
                .map_err(DriverError::internal)?;
            client
                .replay_erasure(rauthy_subject, subject_key)
                .await
                .map_err(|_| DriverError::internal("Paperless erasure replay failed"))?;
        }
        _ => unreachable!(),
    }
    Ok(json!({"action":"erasure","location":location,"applied":true}))
}

async fn lifecycle_quiesced(
    state: &DriverState,
    workshop: Uuid,
    payload: &Value,
) -> Result<Value, DriverError> {
    let action = payload
        .get("action")
        .and_then(Value::as_str)
        .ok_or_else(|| DriverError::bad("lifecycle action is required"))?;
    let database_id = payload_uuid(payload, "database_id")?;
    let database_ref = database_ref(state, workshop, database_id).await?;
    let previous_limit =
        sqlx::query_scalar::<_, i32>("select datconnlimit from pg_database where datname=$1")
            .bind(&database_ref)
            .fetch_one(&state.postgres)
            .await
            .map_err(DriverError::internal)?;
    sqlx::query(
        "update control.odoo_databases set connection_limit_before_lifecycle=$2 where id=$1",
    )
    .bind(database_id)
    .bind(previous_limit)
    .execute(&state.ledger)
    .await
    .map_err(DriverError::internal)?;
    set_database_connection_limit(state, &database_ref, 0).await?;
    let result = async {
        drain_database_sessions(state, &database_ref).await?;
        match action {
        "snapshot" | "backup" | "delete" => {
            let recovery = payload_uuid(payload, "recovery_point_id")?;
            let scope = recovery_scope(state, workshop, recovery).await?;
            let recovery_point =
                create_recovery_set(state, workshop, recovery, &database_ref, if action == "delete" { "backup" } else { action }, &scope)
                    .await?;
            Ok(json!({"action":action,"recovery_point":recovery_point}))
        }
        "restore" => {
            let safety = payload_uuid(payload, "safety_recovery_point_id")?;
            let safety_scope = recovery_scope(state, workshop, safety).await?;
            let safety_recovery_point = create_recovery_set(
                state,
                workshop,
                safety,
                &database_ref,
                "backup",
                &safety_scope,
            )
            .await?;
            mark_recovery_ready_in_driver(state, safety, &safety_recovery_point).await?;
            let recovery_id = payload_uuid(payload, "recovery_point_id")?;
            let stored = resolve_stored_recovery(state, workshop, recovery_id).await?;
            let restored = restore_recovery_set(
                state,
                workshop,
                &database_ref,
                &stored.storage_ref,
                &stored.component_scope,
                &stored.format_version,
            )
            .await;
            match restored {
                Ok(()) => Ok(
                    json!({"action":"restore","restore_status":"restored","safety_recovery_point":safety_recovery_point}),
                ),
                Err(original_error) => {
                    let safety_storage = safety_recovery_point
                        .get("storage_ref")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            DriverError::internal("safety backup storage reference missing")
                        })?;
                    match restore_recovery_set(
                        state,
                        workshop,
                        &database_ref,
                        safety_storage,
                        &safety_scope,
                        RECOVERY_FORMAT_V2,
                    )
                    .await
                    {
                        Ok(()) => {
                            sqlx::query("update control.odoo_databases set state='ready' where id=$1 and workshop_id=$2")
                                .bind(database_id).bind(workshop).execute(&state.ledger).await.map_err(DriverError::internal)?;
                            tracing::error!(workshop=%workshop,recovery=%recovery_id,"restore failed and was rolled back to the verified safety backup");
                            Ok(
                                json!({"action":"restore","restore_status":"rolled_back","safe_error":"restore_failed_rolled_back","safety_recovery_point":safety_recovery_point}),
                            )
                        }
                        Err(rollback_error) => {
                            tracing::error!(workshop=%workshop,recovery=%recovery_id,error=%rollback_error.1,"restore and automatic rollback both failed");
                            Err(original_error)
                        }
                    }
                }
            }
        }
        "duplicate" => {
            if payload.get("routable").and_then(Value::as_bool) != Some(false) {
                return Err(DriverError::bad("database duplicates must be non-routable"));
            }
            let target_id = payload_uuid(payload, "target_database_id")?;
            let target_ref = opaque_database(payload, "target_database_ref")?;
            let temporary = create_recovery_set(
                state,
                workshop,
                target_id,
                &database_ref,
                "duplicate-source",
                &["odoo".to_owned()],
            )
            .await?;
            restore_recovery_set(
                state,
                workshop,
                target_ref,
                temporary
                    .get("storage_ref")
                    .and_then(Value::as_str)
                    .ok_or_else(|| DriverError::internal("duplicate storage reference missing"))?,
                &["odoo".to_owned()],
                RECOVERY_FORMAT_V2,
            )
            .await?;
            neutralize_duplicate_carriers(state, target_ref).await?;
            Ok(
                json!({"action":"duplicate","database":{"database_ref":target_ref,"routable":false}}),
            )
        }
            _ => Err(DriverError::bad("unsupported lifecycle action")),
        }
    }
    .await;
    let retain_quarantine = action == "delete" && result.is_ok();
    let resume = if retain_quarantine {
        Ok(())
    } else {
        set_database_connection_limit(state, &database_ref, previous_limit).await
    };
    if resume.is_ok() && !retain_quarantine {
        sqlx::query(
            "update control.odoo_databases set connection_limit_before_lifecycle=null where id=$1",
        )
        .bind(database_id)
        .execute(&state.ledger)
        .await
        .map_err(DriverError::internal)?;
    }
    match (result, resume) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (_, Err(error)) => Err(error),
    }
}

async fn neutralize_duplicate_carriers(
    state: &DriverState,
    database: &str,
) -> Result<(), DriverError> {
    if !safe_pg_identifier(database) {
        return Err(DriverError::bad("unsafe duplicate database reference"));
    }
    let sql = "do $neutralize$ begin if to_regclass('public.delivery_carrier') is not null and exists (select 1 from information_schema.columns where table_schema='public' and table_name='delivery_carrier' and column_name='mb_secret_ref') then update public.delivery_carrier set mb_secret_ref=null,mb_subscription_id=null,mb_credential_state='unconfigured',mb_provider_enabled=false,prod_environment=false where mb_provider_code is not null; end if; end $neutralize$;";
    run_postgres_job(
        state,
        &format!(
            "mb-pg-neutralize-{}",
            &Uuid::new_v4().simple().to_string()[..12]
        ),
        vec![
            "psql".into(),
            "--no-psqlrc".into(),
            "--set=ON_ERROR_STOP=1".into(),
            format!("--host={}", state.config.postgres_host),
            format!("--port={}", state.config.postgres_port),
            format!("--username={}", state.config.postgres_admin_user),
            format!("--dbname={database}"),
            format!("--command={sql}"),
        ],
    )
    .await
}

pub(super) async fn set_database_connection_limit(
    state: &DriverState,
    database: &str,
    limit: i32,
) -> Result<(), DriverError> {
    if !safe_pg_identifier(database) || limit < -1 {
        return Err(DriverError::bad("unsafe PostgreSQL connection limit"));
    }
    sqlx::query(AssertSqlSafe(format!(
        "alter database \"{database}\" connection limit {limit}"
    )))
    .execute(&state.postgres)
    .await
    .map_err(DriverError::internal)?;
    Ok(())
}

pub(super) async fn drain_database_sessions(
    state: &DriverState,
    database: &str,
) -> Result<(), DriverError> {
    if !safe_pg_identifier(database) {
        return Err(DriverError::bad("unsafe database reference"));
    }
    sqlx::query("select pg_terminate_backend(pid) from pg_stat_activity where datname=$1 and pid<>pg_backend_pid()")
        .bind(database)
        .execute(&state.postgres)
        .await
        .map_err(DriverError::internal)?;
    Ok(())
}

pub(super) async fn drain_workshop_operations(
    state: &DriverState,
    workshop: Uuid,
) -> Result<(), DriverError> {
    for _ in 0..60 {
        let active = sqlx::query_scalar::<_, i64>(
            "select count(*) from control.operations where workshop_id=$1 and kind='invoice.capture' and state='in_flight'",
        )
        .bind(workshop)
        .fetch_one(&state.ledger)
        .await
        .map_err(DriverError::internal)?;
        if active == 0 {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    Err(DriverError::internal(
        "timed out draining in-flight workshop operations",
    ))
}

pub(super) async fn enter_workshop_maintenance(
    state: &DriverState,
    workshop: Uuid,
) -> Result<Vec<u8>, DriverError> {
    let path = state.config.route_root.join(format!("{workshop}.conf"));
    let backup = state
        .config
        .route_root
        .join(format!("{workshop}.recovery.bak"));
    let previous = if backup.is_file() {
        std::fs::read(&backup).map_err(DriverError::internal)?
    } else {
        let contents = std::fs::read(&path).map_err(DriverError::internal)?;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        use std::io::Write;
        options
            .open(&backup)
            .and_then(|mut file| {
                file.write_all(&contents)?;
                file.sync_all()
            })
            .map_err(DriverError::internal)?;
        contents
    };
    let text = std::str::from_utf8(&previous)
        .map_err(|_| DriverError::internal("workshop route is not UTF-8"))?;
    let hostnames = text
        .lines()
        .filter_map(|line| line.trim().strip_prefix("server_name "))
        .map(|value| value.trim_end_matches(';'))
        .collect::<Vec<_>>();
    if hostnames.is_empty()
        || hostnames
            .iter()
            .any(|name| hostname(&json!({"host":name}), "host").is_err())
    {
        return Err(DriverError::internal(
            "workshop route contains no safe hostnames",
        ));
    }
    let maintenance = hostnames
        .iter()
        .map(|name| format!("server {{\n  listen 8080;\n  server_name {name};\n  add_header Retry-After 120 always;\n  location / {{ return 503; }}\n}}\n"))
        .collect::<String>();
    replace_route_config(state, workshop, maintenance.as_bytes()).await?;
    Ok(previous)
}

pub(super) async fn leave_workshop_maintenance(
    state: &DriverState,
    workshop: Uuid,
    previous: &[u8],
) -> Result<(), DriverError> {
    replace_route_config(state, workshop, previous).await?;
    let backup = state
        .config
        .route_root
        .join(format!("{workshop}.recovery.bak"));
    if backup.exists() {
        std::fs::remove_file(backup).map_err(DriverError::internal)?;
    }
    Ok(())
}

pub(super) async fn replace_route_config(
    state: &DriverState,
    workshop: Uuid,
    contents: &[u8],
) -> Result<(), DriverError> {
    let path = state.config.route_root.join(format!("{workshop}.conf"));
    let temporary = state
        .config
        .route_root
        .join(format!("{workshop}.recovery.tmp"));
    std::fs::write(&temporary, contents).map_err(DriverError::internal)?;
    std::fs::rename(&temporary, &path).map_err(DriverError::internal)?;
    docker_exec(state, &state.config.gateway_container, &["nginx", "-t"]).await?;
    docker_signal_container(state, &state.config.gateway_container, "HUP").await?;
    Ok(())
}

async fn mark_recovery_ready_in_driver(
    state: &DriverState,
    recovery: Uuid,
    result: &Value,
) -> Result<(), DriverError> {
    let get = |key| {
        result
            .get(key)
            .and_then(Value::as_str)
            .ok_or_else(|| DriverError::internal(format!("recovery result missing {key}")))
    };
    let size = result
        .get("size_bytes")
        .and_then(Value::as_i64)
        .ok_or_else(|| DriverError::internal("recovery result missing size_bytes"))?;
    let components = result
        .get("components")
        .and_then(Value::as_array)
        .ok_or_else(|| DriverError::internal("recovery result missing components"))?;
    let mut tx = state.ledger.begin().await.map_err(DriverError::internal)?;
    let retention_days = result
        .get("retention_days")
        .and_then(Value::as_i64)
        .unwrap_or(35);
    sqlx::query("update control.workshop_recovery_points set state='ready',storage_ref=$2,size_bytes=$3,ready_at=now(),verification_state='verified',verified_at=now(),manifest_digest=$4,format_version=$5,storage_location=$6,source_release=$7,paperless_version=$8,encryption_key_id=$9,object_prefix=$10,expires_at=now()+make_interval(days=>$11) where id=$1")
        .bind(recovery)
        .bind(get("storage_ref")?)
        .bind(size)
        .bind(get("manifest_digest")?)
        .bind(get("format_version")?)
        .bind(get("storage_location")?)
        .bind(get("source_release")?)
        .bind(result.get("paperless_version").and_then(Value::as_str))
        .bind(result.get("encryption_key_id").and_then(Value::as_str))
        .bind(result.get("object_prefix").and_then(Value::as_str))
        .bind(i32::try_from(retention_days).map_err(DriverError::internal)?)
        .execute(&mut *tx)
        .await
        .map_err(DriverError::internal)?;
    sqlx::query("delete from control.workshop_recovery_components where recovery_point_id=$1")
        .bind(recovery)
        .execute(&mut *tx)
        .await
        .map_err(DriverError::internal)?;
    for component in components {
        let string = |key| {
            component
                .get(key)
                .and_then(Value::as_str)
                .ok_or_else(|| DriverError::internal(format!("recovery component missing {key}")))
        };
        let bytes = component
            .get("size_bytes")
            .and_then(Value::as_i64)
            .ok_or_else(|| DriverError::internal("recovery component missing size_bytes"))?;
        sqlx::query("insert into control.workshop_recovery_components(recovery_point_id,component,object_key,size_bytes,digest,plaintext_digest,state,verified_at) values($1,$2,$3,$4,$5,$6,'verified',now())")
            .bind(recovery).bind(string("name")?).bind(string("path")?).bind(bytes).bind(string("sha256")?).bind(component.get("plaintext_sha256").and_then(Value::as_str)).execute(&mut *tx).await.map_err(DriverError::internal)?;
    }
    tx.commit().await.map_err(DriverError::internal)
}

async fn recovery_scope(
    state: &DriverState,
    workshop: Uuid,
    recovery: Uuid,
) -> Result<Vec<String>, DriverError> {
    sqlx::query_scalar(
        "select component_scope from control.workshop_recovery_points where id=$1 and workshop_id=$2",
    )
    .bind(recovery)
    .bind(workshop)
    .fetch_optional(&state.ledger)
    .await
    .map_err(DriverError::internal)?
    .ok_or_else(|| DriverError(StatusCode::NOT_FOUND, "recovery point not found".into()))
}

async fn resolve_stored_recovery(
    state: &DriverState,
    workshop: Uuid,
    recovery: Uuid,
) -> Result<StoredRecovery, DriverError> {
    let row = sqlx::query(
        "select storage_ref,component_scope,format_version from control.workshop_recovery_points where id=$1 and workshop_id=$2 and state='ready' and verification_state='verified' and storage_ref is not null and (expires_at is null or expires_at > now())",
    )
    .bind(recovery)
    .bind(workshop)
    .fetch_optional(&state.ledger)
    .await
    .map_err(DriverError::internal)?
    .ok_or_else(|| DriverError::bad("recovery point is not ready and verified"))?;
    Ok(StoredRecovery {
        storage_ref: row.get("storage_ref"),
        component_scope: row.get("component_scope"),
        format_version: row.get("format_version"),
    })
}

pub(super) fn payload_uuid(payload: &Value, key: &str) -> Result<Uuid, DriverError> {
    payload
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| DriverError::bad(format!("{key} is required")))?
        .parse()
        .map_err(|_| DriverError::bad(format!("{key} is invalid")))
}

async fn database_ref(
    state: &DriverState,
    workshop: Uuid,
    database_id: Uuid,
) -> Result<String, DriverError> {
    sqlx::query_scalar(
        "select database_ref from control.odoo_databases where id=$1 and workshop_id=$2 and deleted_at is null",
    )
    .bind(database_id)
    .bind(workshop)
    .fetch_optional(&state.ledger)
    .await
    .map_err(DriverError::internal)?
    .ok_or_else(|| DriverError(StatusCode::NOT_FOUND, "database not found".into()))
}

pub(super) async fn active_platform_release(state: &DriverState) -> Result<String, DriverError> {
    sqlx::query_scalar("select id from control.application_releases where status='active'")
        .fetch_optional(&state.ledger)
        .await
        .map_err(DriverError::internal)?
        .ok_or_else(|| DriverError::bad("an active immutable application release is required"))
}

async fn source_workshop_release(
    state: &DriverState,
    workshop: Uuid,
    database_ref: &str,
) -> Result<String, DriverError> {
    sqlx::query_scalar(
        "select coalesce(
            (select a.source_release_id from control.tenant_release_adoptions a
             join control.odoo_databases d on d.id=a.database_id
             where a.workshop_id=$1 and d.database_ref=$2
               and a.state in ('isolating','backing_up','upgrading','verifying','prepared','failed','restoring')
               and a.source_release_id is not null order by a.created_at desc limit 1),
            (select a.release_id from control.tenant_release_adoptions a
             join control.odoo_databases d on d.id=a.database_id
             where a.workshop_id=$1 and d.database_ref=$2 and a.state='active'
             order by a.activated_at desc limit 1),
            (select s.release_id from control.service_instances s
             join control.application_releases r on r.id=s.release_id
             where s.workshop_id=$1 and s.service='odoo' limit 1)
        )",
    )
    .bind(workshop)
    .bind(database_ref)
    .fetch_optional(&state.ledger)
    .await
    .map_err(DriverError::internal)?
    .flatten()
    .ok_or_else(|| {
        DriverError::bad("the workshop has no recorded immutable application release")
    })
}

pub(super) async fn create_recovery_set(
    state: &DriverState,
    workshop: Uuid,
    recovery: Uuid,
    database_ref: &str,
    kind: &str,
    component_scope: &[String],
) -> Result<Value, DriverError> {
    if !safe_pg_identifier(database_ref) {
        return Err(DriverError::bad("unsafe database reference"));
    }
    if let Some(existing) = existing_recovery_response(state, recovery).await? {
        return Ok(existing);
    }
    if kind == "backup" {
        return create_remote_recovery_set(
            state,
            workshop,
            recovery,
            database_ref,
            kind,
            component_scope,
        )
        .await;
    }
    let source_release = source_workshop_release(state, workshop, database_ref).await?;
    let relative = PathBuf::from("docker-backup")
        .join(workshop.to_string())
        .join(recovery.to_string());
    let directory = state.config.backup_root.join(&relative);
    let complete = directory.join("complete.json");
    if complete.is_file() {
        let size = directory_size(&directory).map_err(DriverError::internal)?;
        let manifest = read_v2_manifest(&directory)?;
        let manifest_digest =
            digest_file(&directory.join("manifest.json")).map_err(DriverError::internal)?;
        return recovery_response(&directory, &relative, size, &manifest, manifest_digest);
    }
    if directory.exists() {
        std::fs::remove_dir_all(&directory).map_err(DriverError::internal)?;
    }
    secure_directory(&directory).map_err(DriverError::internal)?;
    let odoo_directory = directory.join("odoo");
    secure_directory(&odoo_directory).map_err(DriverError::internal)?;
    let dump_relative = relative.join("odoo/database.dump");
    run_postgres_job(
        state,
        &format!("mb-pg-dump-{}", &recovery.simple().to_string()[..12]),
        vec![
            "pg_dump".into(),
            "--format=custom".into(),
            "--no-owner".into(),
            "--no-acl".into(),
            format!("--host={}", state.config.postgres_host),
            format!("--port={}", state.config.postgres_port),
            format!("--username={}", state.config.postgres_admin_user),
            format!("--file=/backups/{}", dump_relative.to_string_lossy()),
            database_ref.into(),
        ],
    )
    .await?;
    let source_filestore = state
        .config
        .odoo_data_root
        .join("filestore")
        .join(database_ref);
    let target_filestore = odoo_directory.join("filestore");
    copy_directory(&source_filestore, &target_filestore, None).map_err(DriverError::internal)?;
    let mut components = vec![
        recovery_component("odoo-database", "odoo/database.dump", &directory)?,
        recovery_component("odoo-filestore", "odoo/filestore", &directory)?,
    ];
    let paperless_version = if component_scope.iter().any(|item| item == "paperless") {
        backup_paperless(
            state,
            workshop,
            recovery,
            &relative,
            &directory,
            &mut components,
        )
        .await?;
        state.config.paperless_image.clone()
    } else {
        None
    };
    let manifest = RecoveryManifest {
        format: RECOVERY_FORMAT_V2.to_owned(),
        recovery_id: recovery,
        workshop_id: workshop,
        database_ref: database_ref.to_owned(),
        kind: kind.to_owned(),
        source_release,
        odoo_version: state.config.odoo_image.clone(),
        paperless_version,
        paperless_database_ref: component_scope
            .iter()
            .any(|item| item == "paperless")
            .then(|| format!("pl_{}", tenant_key(workshop))),
        created_at_unix: time::OffsetDateTime::now_utc().unix_timestamp(),
        expires_at_unix: None,
        encryption: None,
        encryption_key_id: None,
        component_scope: component_scope.to_vec(),
        components,
    };
    let manifest_path = directory.join("manifest.json");
    std::fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).map_err(DriverError::internal)?,
    )
    .map_err(DriverError::internal)?;
    let manifest_digest = digest_file(&manifest_path).map_err(DriverError::internal)?;
    std::fs::write(
        &complete,
        serde_json::to_vec_pretty(&json!({
            "format": RECOVERY_FORMAT_V2,
            "manifest_sha256": manifest_digest,
        }))
        .map_err(DriverError::internal)?,
    )
    .map_err(DriverError::internal)?;
    verify_recovery_directory(&directory, workshop, component_scope)?;
    let size = directory_size(&directory).map_err(DriverError::internal)?;
    recovery_response(&directory, &relative, size, &manifest, manifest_digest)
}

async fn existing_recovery_response(
    state: &DriverState,
    recovery: Uuid,
) -> Result<Option<Value>, DriverError> {
    let row = sqlx::query("select storage_ref,storage_location,size_bytes,manifest_digest,format_version,source_release,paperless_version,encryption_key_id,object_prefix from control.workshop_recovery_points where id=$1 and state='ready' and verification_state='verified' and storage_ref is not null")
        .bind(recovery)
        .fetch_optional(&state.ledger)
        .await
        .map_err(DriverError::internal)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let components = sqlx::query("select component,object_key,size_bytes,digest,plaintext_digest from control.workshop_recovery_components where recovery_point_id=$1 order by component")
        .bind(recovery)
        .fetch_all(&state.ledger)
        .await
        .map_err(DriverError::internal)?
        .into_iter()
        .map(|component| json!({
            "name": component.get::<String,_>("component"),
            "path": component.get::<String,_>("object_key"),
            "size_bytes": component.get::<i64,_>("size_bytes"),
            "sha256": component.get::<String,_>("digest"),
            "plaintext_sha256": component.get::<Option<String>,_>("plaintext_digest"),
        }))
        .collect::<Vec<_>>();
    Ok(Some(json!({
        "storage_ref": row.get::<String,_>("storage_ref"),
        "storage_location": row.get::<String,_>("storage_location"),
        "size_bytes": row.get::<Option<i64>,_>("size_bytes").ok_or_else(|| DriverError::internal("ready recovery is missing size_bytes"))?,
        "manifest_digest": row.get::<Option<String>,_>("manifest_digest").ok_or_else(|| DriverError::internal("ready recovery is missing manifest_digest"))?,
        "format_version": row.get::<String,_>("format_version"),
        "source_release": row.get::<Option<String>,_>("source_release").ok_or_else(|| DriverError::internal("ready recovery is missing source_release"))?,
        "paperless_version": row.get::<Option<String>,_>("paperless_version"),
        "encryption_key_id": row.get::<Option<String>,_>("encryption_key_id"),
        "object_prefix": row.get::<Option<String>,_>("object_prefix"),
        "components": components,
    })))
}

async fn restore_recovery_set(
    state: &DriverState,
    workshop: Uuid,
    target_database: &str,
    storage_ref: &str,
    expected_scope: &[String],
    format_version: &str,
) -> Result<(), DriverError> {
    if !safe_pg_identifier(target_database) {
        return Err(DriverError::bad("unsafe target database reference"));
    }
    if format_version != RECOVERY_FORMAT_V2 {
        return Err(DriverError::bad("unsupported recovery format"));
    }
    if storage_ref.starts_with("s3://") {
        return restore_remote_recovery_set(
            state,
            workshop,
            target_database,
            storage_ref,
            expected_scope,
            false,
        )
        .await;
    }
    let relative = safe_storage_ref(storage_ref, workshop)?;
    let directory = state.config.backup_root.join(&relative);
    let resolved = std::fs::canonicalize(&directory).map_err(DriverError::internal)?;
    let root = std::fs::canonicalize(&state.config.backup_root).map_err(DriverError::internal)?;
    if !resolved.starts_with(&root) || !resolved.join("complete.json").is_file() {
        return Err(DriverError::bad("recovery set is incomplete"));
    }
    let manifest = verify_recovery_directory(&resolved, workshop, expected_scope)?;
    validate_paperless_version(state, &manifest)?;
    validate_local_dump(state, &relative.join("odoo/database.dump"), "odoo").await?;
    if manifest
        .component_scope
        .iter()
        .any(|item| item == "paperless")
    {
        validate_local_dump(
            state,
            &relative.join("paperless/database.dump"),
            &format!("pl_{}", tenant_key(workshop)),
        )
        .await?;
    }
    replace_database(state, target_database).await?;
    run_postgres_job(
        state,
        &format!(
            "mb-pg-restore-{}",
            &Uuid::new_v4().simple().to_string()[..12]
        ),
        vec![
            "pg_restore".into(),
            "--exit-on-error".into(),
            "--no-owner".into(),
            "--no-acl".into(),
            format!("--host={}", state.config.postgres_host),
            format!("--port={}", state.config.postgres_port),
            format!("--username={}", state.config.postgres_admin_user),
            format!("--dbname={target_database}"),
            format!("/backups/{}/odoo/database.dump", relative.to_string_lossy()),
        ],
    )
    .await?;
    let target_filestore = state
        .config
        .odoo_data_root
        .join("filestore")
        .join(target_database);
    if target_filestore.exists() {
        std::fs::remove_dir_all(&target_filestore).map_err(DriverError::internal)?;
    }
    copy_directory(
        &resolved.join("odoo/filestore"),
        &target_filestore,
        Some((state.config.odoo_uid, state.config.odoo_gid)),
    )
    .map_err(DriverError::internal)?;
    if manifest
        .component_scope
        .iter()
        .any(|item| item == "paperless")
    {
        restore_paperless(state, workshop, &relative, &resolved).await?;
    }
    validate_restored_databases(state, workshop, target_database, &manifest.component_scope).await
}

async fn create_remote_recovery_set(
    state: &DriverState,
    workshop: Uuid,
    recovery: Uuid,
    database_ref: &str,
    kind: &str,
    component_scope: &[String],
) -> Result<Value, DriverError> {
    let source_release = source_workshop_release(state, workshop, database_ref).await?;
    update_recovery_progress(
        state,
        recovery,
        10,
        "capturing",
        "Capturing workshop databases and files",
    )
    .await?;
    let s3 = state
        .config
        .s3_backup
        .as_ref()
        .ok_or_else(|| DriverError::bad("portable S3 backups are not configured"))?;
    let image = state
        .config
        .backup_agent_image
        .as_ref()
        .ok_or_else(|| DriverError::bad("backup agent image is not configured"))?;
    let relative = PathBuf::from("docker-upload")
        .join(workshop.to_string())
        .join(recovery.to_string());
    let directory = state.config.backup_root.join(&relative);
    if directory.exists() {
        std::fs::remove_dir_all(&directory).map_err(DriverError::internal)?;
    }
    secure_directory(&directory).map_err(DriverError::internal)?;

    let compact = tenant_key(workshop);
    let paperless_database = format!("pl_{compact}");
    let includes_paperless = component_scope.iter().any(|item| item == "paperless");
    let binds = backup_writer_binds(
        &state.config.backup_volume,
        &state.config.odoo_volume,
        workshop,
        includes_paperless,
    );
    let pgpass = postgres_admin_pgpass(state);
    let mut command = format!(
        "set -eu; set -o pipefail; umask 077; export PGPASSFILE=/run/makersbrain-job-secrets/pgpass; AGE_RECIPIENT=$(cat /run/makersbrain-job-secrets/age-recipient); reject_special() {{ test ! -d \"$1\" || test -z \"$(find \"$1\" -mindepth 1 ! -type d ! -type f -print -quit)\"; }}; encrypt_stream() {{ output=$1; checksum=$2; fifo=\"${{checksum}}.fifo\"; mkfifo \"$fifo\"; sha256sum <\"$fifo\" | cut -d' ' -f1 >\"$checksum\" & hash_pid=$!; tee \"$fifo\" | zstd -q -T0 | age -r \"$AGE_RECIPIENT\" -o \"$output\"; wait \"$hash_pid\"; rm -f \"$fifo\"; }}; out=/backups/{}; mkdir -p \"$out/odoo\"; pg_dump --format=custom --no-owner --no-acl --host=\"$PGHOST\" --port=\"$PGPORT\" --username=\"$PGUSER\" \"$ODOO_DATABASE\" | encrypt_stream \"$out/odoo/database.dump.enc\" \"$out/odoo/database.dump.plain.sha256\"; reject_special \"/odoo/filestore/$ODOO_DATABASE\"; if [ -d \"/odoo/filestore/$ODOO_DATABASE\" ]; then tar -C \"/odoo/filestore/$ODOO_DATABASE\" -cf - .; else tar -cf - --files-from /dev/null; fi | encrypt_stream \"$out/odoo/filestore.tar.zst.enc\" \"$out/odoo/filestore.plain.sha256\"",
        relative.to_string_lossy()
    );
    if includes_paperless {
        command.push_str("; mkdir -p \"$out/paperless\"; pg_dump --format=custom --no-owner --no-acl --host=\"$PGHOST\" --port=\"$PGPORT\" --username=\"$PGUSER\" \"$PAPERLESS_DATABASE\" | encrypt_stream \"$out/paperless/database.dump.enc\" \"$out/paperless/database.dump.plain.sha256\"; for part in data media consume; do reject_special /paperless/$part; tar -C /paperless/$part -cf - . | encrypt_stream \"$out/paperless/$part.tar.zst.enc\" \"$out/paperless/$part.plain.sha256\"; done");
    }
    run_docker_job_with_secrets(
        state,
        &format!("mb-encrypt-{}", &recovery.simple().to_string()[..12]),
        json!({
            "Image": image,
            "User": "0:0",
            "Cmd": ["sh", "-ec", command],
            "Env": [
                format!("PGHOST={}", state.config.postgres_host),
                format!("PGPORT={}", state.config.postgres_port),
                format!("PGUSER={}", state.config.postgres_admin_user),
                format!("ODOO_DATABASE={database_ref}"),
                format!("PAPERLESS_DATABASE={paperless_database}"),
            ],
            "Labels": {"makersbrain.kind":"encrypted-backup-job"},
            "HostConfig": {"NetworkMode": state.config.docker_network, "Binds": binds}
        }),
        &[("pgpass", &pgpass), ("age-recipient", &s3.age_recipient)],
    )
    .await?;
    update_recovery_progress(
        state,
        recovery,
        45,
        "encrypting",
        "Encrypted workshop components created",
    )
    .await?;

    let mut components = vec![
        encrypted_recovery_component(
            "odoo-database",
            "odoo/database.dump.enc",
            "odoo/database.dump.plain.sha256",
            &directory,
        )?,
        encrypted_recovery_component(
            "odoo-filestore",
            "odoo/filestore.tar.zst.enc",
            "odoo/filestore.plain.sha256",
            &directory,
        )?,
    ];
    if includes_paperless {
        for (name, path, checksum) in [
            (
                "paperless-database",
                "paperless/database.dump.enc",
                "paperless/database.dump.plain.sha256",
            ),
            (
                "paperless-data",
                "paperless/data.tar.zst.enc",
                "paperless/data.plain.sha256",
            ),
            (
                "paperless-media",
                "paperless/media.tar.zst.enc",
                "paperless/media.plain.sha256",
            ),
            (
                "paperless-consume",
                "paperless/consume.tar.zst.enc",
                "paperless/consume.plain.sha256",
            ),
        ] {
            components.push(encrypted_recovery_component(
                name, path, checksum, &directory,
            )?);
        }
    }
    let manifest = RecoveryManifest {
        format: RECOVERY_FORMAT_V2.to_owned(),
        recovery_id: recovery,
        workshop_id: workshop,
        database_ref: database_ref.to_owned(),
        kind: kind.to_owned(),
        source_release,
        odoo_version: state.config.odoo_image.clone(),
        paperless_version: includes_paperless
            .then(|| state.config.paperless_image.clone())
            .flatten(),
        paperless_database_ref: includes_paperless.then_some(paperless_database),
        created_at_unix: time::OffsetDateTime::now_utc().unix_timestamp(),
        expires_at_unix: Some(
            (time::OffsetDateTime::now_utc() + time::Duration::days(i64::from(s3.retention_days)))
                .unix_timestamp(),
        ),
        encryption: Some("age-x25519".to_owned()),
        encryption_key_id: Some(s3.encryption_key_id.clone()),
        component_scope: component_scope.to_vec(),
        components,
    };
    let serialized_manifest = serde_json::to_vec(&manifest).map_err(DriverError::internal)?;
    let plaintext_manifest_digest = format!("{:x}", Sha256::digest(&serialized_manifest));
    let manifest_b64 = base64::engine::general_purpose::STANDARD.encode(serialized_manifest);
    run_docker_job_with_secrets(
        state,
        &format!("mb-manifest-{}", &recovery.simple().to_string()[..12]),
        json!({
            "Image": image,
            "User": "0:0",
            "Cmd": ["sh", "-ec", format!("set -eu; umask 077; base64 -d < /run/makersbrain-job-secrets/manifest-b64 | age -r \"$(cat /run/makersbrain-job-secrets/age-recipient)\" -o /backups/{}/manifest.json.enc", relative.to_string_lossy())],
            "Labels": {"makersbrain.kind":"encrypted-backup-manifest-job"},
            "HostConfig": {"Binds": [format!("{}:/backups", state.config.backup_volume)]}
        }),
        &[("manifest-b64", &manifest_b64), ("age-recipient", &s3.age_recipient)],
    )
    .await?;
    let encrypted_manifest_digest =
        digest_file(&directory.join("manifest.json.enc")).map_err(DriverError::internal)?;
    let complete = json!({
        "format": RECOVERY_FORMAT_V2,
        "recovery_id": recovery,
        "manifest_sha256": encrypted_manifest_digest,
        "encryption": "age-x25519",
        "encryption_key_id": s3.encryption_key_id,
        "created_at_unix": manifest.created_at_unix,
        "expires_at_unix": manifest.expires_at_unix,
    });
    std::fs::write(
        directory.join("complete.json"),
        serde_json::to_vec_pretty(&complete).map_err(DriverError::internal)?,
    )
    .map_err(DriverError::internal)?;
    update_recovery_progress(
        state,
        recovery,
        60,
        "packaging",
        "Building portable archive",
    )
    .await?;
    const ARCHIVE_NAME: &str = "makersbrain-workshop-backup.tar";
    run_docker_job(
        state,
        &format!("mb-archive-{}", &recovery.simple().to_string()[..12]),
        json!({
            "Image": image,
            "User": "0:0",
            "Cmd": ["sh", "-ec", format!("set -eu; umask 077; root=/backups/{}; tar -C \"$root\" -cf \"$root/{ARCHIVE_NAME}\" odoo {} manifest.json.enc complete.json", relative.to_string_lossy(), if includes_paperless { "paperless" } else { "" })],
            "Labels": {"makersbrain.kind":"portable-backup-archive-job"},
            "HostConfig": {"Binds": [format!("{}:/backups", state.config.backup_volume)]}
        }),
    )
    .await?;
    let object_prefix = format!("workshops/{workshop}/recovery/{recovery}");
    update_recovery_progress(
        state,
        recovery,
        72,
        "uploading",
        "Uploading encrypted archive to S3",
    )
    .await?;
    upload_and_verify_s3(state, &relative, &object_prefix, &manifest).await?;
    update_recovery_progress(
        state,
        recovery,
        92,
        "verifying",
        "Verifying the uploaded archive",
    )
    .await?;
    let archive_component = recovery_component("portable-archive", ARCHIVE_NAME, &directory)?;
    let size_bytes = archive_component.size_bytes;
    let storage_ref = format!("s3://{}/{object_prefix}", s3.bucket);
    let mut recorded_components = manifest.components.clone();
    let mut manifest_component = recovery_component("manifest", "manifest.json.enc", &directory)?;
    manifest_component.plaintext_sha256 = Some(plaintext_manifest_digest);
    recorded_components.push(manifest_component);
    recorded_components.push(recovery_component(
        "commit-marker",
        "complete.json",
        &directory,
    )?);
    recorded_components.push(archive_component.clone());
    std::fs::remove_dir_all(&directory).map_err(DriverError::internal)?;
    Ok(json!({
        "storage_ref": storage_ref,
        "storage_location": "s3",
        "size_bytes": size_bytes,
        "manifest_digest": encrypted_manifest_digest,
        "format_version": RECOVERY_FORMAT_V2,
        "source_release": manifest.source_release,
        "paperless_version": manifest.paperless_version,
        "encryption_key_id": s3.encryption_key_id,
        "object_prefix": object_prefix,
        "retention_days": s3.retention_days,
        "components": recorded_components,
        "archive_object_key": format!("{object_prefix}/{ARCHIVE_NAME}"),
        "archive_size_bytes": archive_component.size_bytes,
        "archive_digest": archive_component.sha256,
    }))
}

fn backup_writer_binds(
    backup_volume: &str,
    odoo_volume: &str,
    workshop: Uuid,
    includes_paperless: bool,
) -> Vec<String> {
    let mut binds = vec![
        format!("{backup_volume}:/backups"),
        format!("{odoo_volume}:/odoo:ro"),
    ];
    if includes_paperless {
        for suffix in ["data", "media", "consume"] {
            binds.push(format!(
                "mb-paperless-{workshop}-{suffix}:/paperless/{suffix}:ro"
            ));
        }
    }
    binds
}

async fn update_recovery_progress(
    state: &DriverState,
    recovery: Uuid,
    percent: i16,
    phase: &str,
    message: &str,
) -> Result<(), DriverError> {
    sqlx::query(
        "update control.operations o set progress_percent=$2,progress_phase=$3,
                progress_message=$4,progress_updated_at=now()
         from control.workshop_recovery_points r
         where r.id=$1 and r.operation_id=o.id and o.state='in_flight'",
    )
    .bind(recovery)
    .bind(percent)
    .bind(phase)
    .bind(message)
    .execute(&state.ledger)
    .await
    .map_err(DriverError::internal)?;
    Ok(())
}

async fn upload_and_verify_s3(
    state: &DriverState,
    relative: &Path,
    object_prefix: &str,
    manifest: &RecoveryManifest,
) -> Result<(), DriverError> {
    let s3 = state.config.s3_backup.as_ref().unwrap();
    let image = state.config.backup_agent_image.as_ref().unwrap();
    let mut object_paths = manifest
        .components
        .iter()
        .map(|component| component.path.clone())
        .collect::<Vec<_>>();
    object_paths.push("manifest.json.enc".to_owned());
    object_paths.push("makersbrain-workshop-backup.tar".to_owned());
    let files = object_paths.join(" ");
    let command = format!(
        "set -eu; set -o pipefail; {}; root=/backups/{}; for file in {files}; do if [ \"$file\" = makersbrain-workshop-backup.tar ]; then aws --endpoint-url \"$S3_ENDPOINT\" s3 cp --only-show-errors --content-type application/x-tar --content-disposition 'attachment; filename=\"makersbrain-workshop-backup.tar\"' \"$root/$file\" \"s3://$S3_BUCKET/$S3_PREFIX/$file\"; else aws --endpoint-url \"$S3_ENDPOINT\" s3 cp --only-show-errors \"$root/$file\" \"s3://$S3_BUCKET/$S3_PREFIX/$file\"; fi; local_sum=$(sha256sum \"$root/$file\" | cut -d' ' -f1); remote_sum=$(aws --endpoint-url \"$S3_ENDPOINT\" s3 cp --only-show-errors \"s3://$S3_BUCKET/$S3_PREFIX/$file\" - | sha256sum | cut -d' ' -f1); test \"$local_sum\" = \"$remote_sum\"; done; aws --endpoint-url \"$S3_ENDPOINT\" s3 cp --only-show-errors \"$root/complete.json\" \"s3://$S3_BUCKET/$S3_PREFIX/complete.json\"; local_sum=$(sha256sum \"$root/complete.json\" | cut -d' ' -f1); remote_sum=$(aws --endpoint-url \"$S3_ENDPOINT\" s3 cp --only-show-errors \"s3://$S3_BUCKET/$S3_PREFIX/complete.json\" - | sha256sum | cut -d' ' -f1); test \"$local_sum\" = \"$remote_sum\"",
        aws_secret_prelude(),
        relative.to_string_lossy()
    );
    run_docker_job_with_secrets(
        state,
        &format!(
            "mb-upload-{}",
            &manifest.recovery_id.simple().to_string()[..12]
        ),
        json!({
            "Image": image,
            "User": "0:0",
            "Cmd": ["sh", "-ec", command],
            "Env": s3_environment(s3, object_prefix),
            "Labels": {"makersbrain.kind":"s3-backup-upload-job"},
            "HostConfig": {"Binds": [format!("{}:/backups:ro", state.config.backup_volume)]}
        }),
        &s3_job_secrets(s3, true),
    )
    .await
}

async fn validate_restored_databases(
    state: &DriverState,
    workshop: Uuid,
    odoo_database: &str,
    scope: &[String],
) -> Result<(), DriverError> {
    let paperless = scope
        .iter()
        .any(|item| item == "paperless")
        .then(|| format!("pl_{}", tenant_key(workshop)));
    validate_recovery_database_content(state, odoo_database, paperless.as_deref()).await
}

async fn validate_recovery_database_content(
    state: &DriverState,
    odoo_database: &str,
    paperless_database: Option<&str>,
) -> Result<(), DriverError> {
    validate_database_table(state, odoo_database, "ir_module_module").await?;
    let Some(paperless_database) = paperless_database else {
        return Ok(());
    };
    validate_database_table(state, paperless_database, "documents_document").await?;
    let paperless = database_pool(state, paperless_database).await?;
    let invalid_checksums = sqlx::query_scalar::<_, i64>(
        "select count(*)::bigint from documents_document where checksum is null or btrim(checksum)=''",
    )
    .fetch_one(&paperless)
    .await
    .map_err(DriverError::internal)?;
    let document_ids =
        sqlx::query_scalar::<_, i64>("select id::bigint from documents_document order by id")
            .fetch_all(&paperless)
            .await
            .map_err(DriverError::internal)?
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>();
    paperless.close().await;
    if invalid_checksums != 0 {
        return Err(DriverError::bad(
            "restored Paperless document checksum validation failed",
        ));
    }
    let odoo = database_pool(state, odoo_database).await?;
    let capture_table = sqlx::query_scalar::<_, bool>(
        "select to_regclass('public.mb_invoice_capture') is not null",
    )
    .fetch_one(&odoo)
    .await
    .map_err(DriverError::internal)?;
    if capture_table {
        let links = sqlx::query_scalar::<_, String>(
            "select external_document_id from mb_invoice_capture where external_document_id like 'paperless:%'",
        )
        .fetch_all(&odoo)
        .await
        .map_err(DriverError::internal)?;
        if links.iter().any(|link| {
            link.strip_prefix("paperless:")
                .and_then(|value| value.parse::<i64>().ok())
                .is_none_or(|id| !document_ids.contains(&id))
        }) {
            odoo.close().await;
            return Err(DriverError::bad(
                "restored Odoo to Paperless document link validation failed",
            ));
        }
    }
    odoo.close().await;
    Ok(())
}

pub(super) async fn database_pool(
    state: &DriverState,
    database: &str,
) -> Result<PgPool, DriverError> {
    if !safe_pg_identifier(database) {
        return Err(DriverError::bad("unsafe database validation target"));
    }
    let mut url = Url::parse(&state.config.postgres_admin_url).map_err(DriverError::internal)?;
    url.set_path(&format!("/{database}"));
    PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(10))
        .connect(url.as_str())
        .await
        .map_err(DriverError::internal)
}

async fn validate_database_table(
    state: &DriverState,
    database: &str,
    table: &str,
) -> Result<(), DriverError> {
    if !safe_pg_identifier(database) || !safe_pg_identifier(table) {
        return Err(DriverError::bad("unsafe database validation target"));
    }
    let pool = database_pool(state, database).await?;
    let exists = sqlx::query_scalar::<_, bool>("select to_regclass($1) is not null")
        .bind(format!("public.{table}"))
        .fetch_one(&pool)
        .await
        .map_err(DriverError::internal)?;
    pool.close().await;
    if !exists {
        return Err(DriverError::bad(
            "restored database health validation failed",
        ));
    }
    Ok(())
}

fn s3_environment(s3: &S3BackupConfig, prefix: &str) -> Vec<String> {
    vec![
        format!("AWS_DEFAULT_REGION={}", s3.region),
        format!("S3_ENDPOINT={}", s3.endpoint),
        format!("S3_BUCKET={}", s3.bucket),
        format!("S3_PREFIX={prefix}"),
    ]
}

fn s3_job_secrets(s3: &S3BackupConfig, writer: bool) -> [(&'static str, &str); 2] {
    let (access_key, secret_key) = if writer {
        (&s3.writer_access_key_id, &s3.writer_secret_access_key)
    } else {
        (&s3.reader_access_key_id, &s3.reader_secret_access_key)
    };
    [
        ("aws-access-key-id", access_key),
        ("aws-secret-access-key", secret_key),
    ]
}

fn recovery_identity_bind(state: &DriverState, s3: &S3BackupConfig) -> Result<String, DriverError> {
    let container_root = Path::new("/run/makersbrain-recovery-secrets");
    let identity = Path::new(&s3.age_identity_file);
    let relative = identity
        .strip_prefix(container_root)
        .map_err(|_| DriverError::internal("age identity escapes recovery-secret mount"))?;
    let relative = validated_secret_relative_path(relative)?;
    Ok(format!(
        "{}:{}:ro",
        Path::new(&state.config.recovery_secret_source)
            .join(relative)
            .display(),
        identity.display()
    ))
}

fn aws_secret_prelude() -> &'static str {
    "export AWS_ACCESS_KEY_ID=$(cat /run/makersbrain-job-secrets/aws-access-key-id); export AWS_SECRET_ACCESS_KEY=$(cat /run/makersbrain-job-secrets/aws-secret-access-key)"
}

async fn restore_remote_recovery_set(
    state: &DriverState,
    workshop: Uuid,
    target_database: &str,
    storage_ref: &str,
    expected_scope: &[String],
    preflight_only: bool,
) -> Result<(), DriverError> {
    let s3 = state
        .config
        .s3_backup
        .as_ref()
        .ok_or_else(|| DriverError::bad("S3 restore is not configured"))?;
    let image = state
        .config
        .backup_agent_image
        .as_ref()
        .ok_or_else(|| DriverError::bad("backup agent image is not configured"))?;
    let (prefix, recovery_id) = safe_s3_storage_ref(storage_ref, &s3.bucket, workshop)?;
    let relative = PathBuf::from("docker-restore")
        .join(workshop.to_string())
        .join(recovery_id.to_string());
    let directory = state.config.backup_root.join(&relative);
    if directory.exists() {
        std::fs::remove_dir_all(&directory).map_err(DriverError::internal)?;
    }
    secure_directory(&directory).map_err(DriverError::internal)?;

    let result = restore_remote_recovery_inner(
        state,
        workshop,
        target_database,
        &prefix,
        &relative,
        &directory,
        expected_scope,
        image,
        s3,
        preflight_only,
    )
    .await;
    let cleanup = std::fs::remove_dir_all(&directory).map_err(DriverError::internal);
    match (result, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), _) => Err(error),
        (_, Err(error)) => Err(error),
    }
}

#[allow(clippy::too_many_arguments)]
async fn restore_remote_recovery_inner(
    state: &DriverState,
    workshop: Uuid,
    target_database: &str,
    prefix: &str,
    relative: &Path,
    directory: &Path,
    expected_scope: &[String],
    image: &str,
    s3: &S3BackupConfig,
    preflight_only: bool,
) -> Result<(), DriverError> {
    // Rehearsals are part of routine backup verification and use the append-only
    // writer's read permission. Live restores use the separately granted,
    // prefix-scoped reader identity.
    let mut environment = s3_environment(s3, prefix);
    environment.push(format!("AGE_IDENTITY={}", s3.age_identity_file));
    let bootstrap = format!(
        "set -eu; set -o pipefail; umask 077; {}; root=/backups/{}; aws --endpoint-url \"$S3_ENDPOINT\" s3 cp --only-show-errors \"s3://$S3_BUCKET/$S3_PREFIX/complete.json\" \"$root/complete.json\"; aws --endpoint-url \"$S3_ENDPOINT\" s3 cp --only-show-errors \"s3://$S3_BUCKET/$S3_PREFIX/manifest.json.enc\" \"$root/manifest.json.enc\"; age -d -i \"$AGE_IDENTITY\" -o \"$root/manifest.json\" \"$root/manifest.json.enc\"",
        aws_secret_prelude(),
        relative.to_string_lossy()
    );
    run_docker_job_with_secrets(
        state,
        &format!("mb-download-{}", &Uuid::new_v4().simple().to_string()[..12]),
        json!({
            "Image": image,
            "User": "0:0",
            "Cmd": ["sh", "-ec", bootstrap],
            "Env": environment,
            "Labels": {"makersbrain.kind":"s3-restore-download-job"},
            "HostConfig": {"Binds": [format!("{}:/backups", state.config.backup_volume), recovery_identity_bind(state, s3)?]}
        }),
        &s3_job_secrets(s3, preflight_only),
    )
    .await?;
    let commit: Value = serde_json::from_slice(
        &std::fs::read(directory.join("complete.json")).map_err(DriverError::internal)?,
    )
    .map_err(|_| DriverError::bad("remote recovery commit marker is invalid"))?;
    if commit.get("format").and_then(Value::as_str) != Some(RECOVERY_FORMAT_V2)
        || commit.get("recovery_id").and_then(Value::as_str)
            != directory.file_name().and_then(std::ffi::OsStr::to_str)
    {
        return Err(DriverError::bad(
            "remote recovery commit marker is incompatible",
        ));
    }
    let manifest_cipher_digest =
        digest_file(&directory.join("manifest.json.enc")).map_err(DriverError::internal)?;
    if commit.get("manifest_sha256").and_then(Value::as_str)
        != Some(manifest_cipher_digest.as_str())
    {
        return Err(DriverError::bad(
            "remote recovery manifest integrity check failed",
        ));
    }
    let manifest: RecoveryManifest = serde_json::from_slice(
        &std::fs::read(directory.join("manifest.json")).map_err(DriverError::internal)?,
    )
    .map_err(|_| DriverError::bad("remote recovery manifest is invalid"))?;
    if manifest.format != RECOVERY_FORMAT_V2
        || manifest.recovery_id.to_string()
            != directory
                .file_name()
                .and_then(std::ffi::OsStr::to_str)
                .unwrap_or("")
        || manifest.workshop_id != workshop
        || normalized_scope(&manifest.component_scope) != normalized_scope(expected_scope)
        || !safe_pg_identifier(&manifest.database_ref)
        || manifest.odoo_version.trim().is_empty()
        || manifest.encryption.as_deref() != Some("age-x25519")
        || manifest.encryption_key_id.as_deref()
            != commit.get("encryption_key_id").and_then(Value::as_str)
        || manifest.expires_at_unix != commit.get("expires_at_unix").and_then(Value::as_i64)
    {
        return Err(DriverError::bad("remote recovery scope is incompatible"));
    }
    let expected_paperless_database = expected_scope
        .iter()
        .any(|item| item == "paperless")
        .then(|| format!("pl_{}", tenant_key(workshop)));
    if manifest.paperless_database_ref != expected_paperless_database {
        return Err(DriverError::bad(
            "remote Paperless database identity is incompatible",
        ));
    }
    validate_paperless_version(state, &manifest)?;
    let mut names = std::collections::BTreeSet::new();
    for component in &manifest.components {
        if !names.insert(component.name.as_str())
            || !safe_component_path(&component.path)
            || component.size_bytes < 0
            || !valid_sha256(&component.sha256)
            || !component
                .plaintext_sha256
                .as_deref()
                .is_some_and(valid_sha256)
        {
            return Err(DriverError::bad(
                "remote recovery component list is invalid",
            ));
        }
    }
    let required = if expected_scope.iter().any(|item| item == "paperless") {
        [
            "odoo-database",
            "odoo-filestore",
            "paperless-database",
            "paperless-data",
            "paperless-media",
            "paperless-consume",
        ]
        .as_slice()
    } else {
        ["odoo-database", "odoo-filestore"].as_slice()
    };
    if required.iter().any(|name| !names.contains(name)) || names.len() != required.len() {
        return Err(DriverError::bad(
            "remote recovery component scope is incomplete",
        ));
    }
    let object_paths = manifest
        .components
        .iter()
        .map(|component| {
            format!(
                "{}:{}",
                component.path,
                component.plaintext_sha256.as_deref().unwrap_or("")
            )
        })
        .collect::<Vec<_>>()
        .join(" ");
    let mut environment = s3_environment(s3, prefix);
    environment.push(format!("AGE_IDENTITY={}", s3.age_identity_file));
    let download = format!(
        "set -eu; set -o pipefail; {}; root=/backups/{}; for item in {object_paths}; do file=${{item%:*}}; expected=${{item##*:}}; mkdir -p \"$root/$(dirname \"$file\")\"; aws --endpoint-url \"$S3_ENDPOINT\" s3 cp --only-show-errors \"s3://$S3_BUCKET/$S3_PREFIX/$file\" \"$root/$file\"; age -d -i \"$AGE_IDENTITY\" \"$root/$file\" | zstd -q -t; actual=$(age -d -i \"$AGE_IDENTITY\" \"$root/$file\" | zstd -q -d | sha256sum | cut -d' ' -f1); test \"$actual\" = \"$expected\"; case \"$file\" in *.tar.zst.enc) if age -d -i \"$AGE_IDENTITY\" \"$root/$file\" | zstd -q -d | tar -tf - | grep -Eq '(^/|(^|/)\\.\\.(/|$))'; then echo unsafe-archive-path >&2; exit 1; fi; if age -d -i \"$AGE_IDENTITY\" \"$root/$file\" | zstd -q -d | tar -tvf - | grep -Eq '^[lh]'; then echo unsafe-archive-link >&2; exit 1; fi;; esac; done",
        aws_secret_prelude(),
        relative.to_string_lossy()
    );
    run_docker_job_with_secrets(
        state,
        &format!("mb-verify-{}", &manifest.recovery_id.simple().to_string()[..12]),
        json!({
            "Image": image,
            "User": "0:0",
            "Cmd": ["sh", "-ec", download],
            "Env": environment,
            "Labels": {"makersbrain.kind":"s3-restore-verify-job"},
            "HostConfig": {"Binds": [format!("{}:/backups", state.config.backup_volume), recovery_identity_bind(state, s3)?]}
        }),
        &s3_job_secrets(s3, preflight_only),
    )
    .await?;
    for component in &manifest.components {
        let path = directory.join(&component.path);
        let metadata = std::fs::metadata(&path).map_err(DriverError::internal)?;
        let digest = digest_file(&path).map_err(DriverError::internal)?;
        if i64::try_from(metadata.len()).unwrap_or(i64::MAX) != component.size_bytes
            || digest != component.sha256
        {
            return Err(DriverError::bad(
                "remote recovery component integrity check failed",
            ));
        }
    }

    validate_remote_database_dumps(state, workshop, relative, expected_scope, image, s3).await?;

    if preflight_only {
        return Ok(());
    }

    replace_database(state, target_database).await?;
    let compact = tenant_key(workshop);
    let paperless_database = format!("pl_{compact}");
    if expected_scope.iter().any(|item| item == "paperless") {
        replace_database_owned(state, &paperless_database, &paperless_database).await?;
    }
    let mut binds = vec![
        format!("{}:/backups:ro", state.config.backup_volume),
        format!("{}:/odoo", state.config.odoo_volume),
        recovery_identity_bind(state, s3)?,
    ];
    if expected_scope.iter().any(|item| item == "paperless") {
        for suffix in ["data", "media", "consume"] {
            binds.push(format!(
                "mb-paperless-{workshop}-{suffix}:/paperless/{suffix}"
            ));
        }
    }
    let mut restore = format!(
        "set -eu; set -o pipefail; root=/backups/{}; age -d -i \"$AGE_IDENTITY\" \"$root/odoo/database.dump.enc\" | zstd -q -d | pg_restore --exit-on-error --no-owner --no-acl --host=\"$PGHOST\" --port=\"$PGPORT\" --username=\"$PGUSER\" --dbname=\"$ODOO_DATABASE\"; target=\"/odoo/filestore/$ODOO_DATABASE\"; mkdir -p \"$target\"; find \"$target\" -mindepth 1 -maxdepth 1 -exec rm -rf -- {{}} +; age -d -i \"$AGE_IDENTITY\" \"$root/odoo/filestore.tar.zst.enc\" | zstd -q -d | tar -xf - -C \"$target\"; chown -R \"$ODOO_UID:$ODOO_GID\" \"$target\"",
        relative.to_string_lossy()
    );
    if expected_scope.iter().any(|item| item == "paperless") {
        restore.push_str("; age -d -i \"$AGE_IDENTITY\" \"$root/paperless/database.dump.enc\" | zstd -q -d | pg_restore --exit-on-error --no-owner --no-acl --host=\"$PGHOST\" --port=\"$PGPORT\" --username=\"$PGUSER\" --dbname=\"$PAPERLESS_DATABASE\"; for part in data media consume; do find /paperless/$part -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +; age -d -i \"$AGE_IDENTITY\" \"$root/paperless/$part.tar.zst.enc\" | zstd -q -d | tar -xf - -C /paperless/$part; done");
    }
    let pgpass = postgres_admin_pgpass(state);
    run_docker_job_with_secrets(
        state,
        &format!(
            "mb-restore-{}",
            &manifest.recovery_id.simple().to_string()[..12]
        ),
        json!({
            "Image": image,
            "User": "0:0",
            "Cmd": ["sh", "-ec", restore],
            "Env": [
                format!("PGHOST={}", state.config.postgres_host),
                format!("PGPORT={}", state.config.postgres_port),
                format!("PGUSER={}", state.config.postgres_admin_user),
                "PGPASSFILE=/run/makersbrain-job-secrets/pgpass",
                format!("ODOO_DATABASE={target_database}"),
                format!("PAPERLESS_DATABASE={paperless_database}"),
                format!("AGE_IDENTITY={}", s3.age_identity_file),
                format!("ODOO_UID={}", state.config.odoo_uid),
                format!("ODOO_GID={}", state.config.odoo_gid),
            ],
            "Labels": {"makersbrain.kind":"encrypted-restore-job"},
            "HostConfig": {"NetworkMode": state.config.docker_network, "Binds": binds}
        }),
        &[("pgpass", &pgpass)],
    )
    .await?;
    validate_restored_databases(state, workshop, target_database, expected_scope).await
}

async fn validate_remote_database_dumps(
    state: &DriverState,
    workshop: Uuid,
    relative: &Path,
    expected_scope: &[String],
    image: &str,
    s3: &S3BackupConfig,
) -> Result<(), DriverError> {
    let odoo_temporary = format!("mb_{}", Uuid::new_v4().simple());
    replace_database_owned(state, &odoo_temporary, "odoo").await?;
    let includes_paperless = expected_scope.iter().any(|item| item == "paperless");
    let paperless_owner = format!("pl_{}", tenant_key(workshop));
    let paperless_temporary = format!("mb_{}", Uuid::new_v4().simple());
    if includes_paperless
        && let Err(error) =
            replace_database_owned(state, &paperless_temporary, &paperless_owner).await
    {
        let _ = drop_database(state, &odoo_temporary).await;
        return Err(error);
    }
    let mut command = format!(
        "set -eu; set -o pipefail; root=/backups/{}; age -d -i \"$AGE_IDENTITY\" \"$root/odoo/database.dump.enc\" | zstd -q -d | pg_restore --exit-on-error --no-owner --no-acl --host=\"$PGHOST\" --port=\"$PGPORT\" --username=\"$PGUSER\" --dbname=\"$ODOO_TEMPORARY\"",
        relative.to_string_lossy()
    );
    if includes_paperless {
        command.push_str("; age -d -i \"$AGE_IDENTITY\" \"$root/paperless/database.dump.enc\" | zstd -q -d | pg_restore --exit-on-error --no-owner --no-acl --host=\"$PGHOST\" --port=\"$PGPORT\" --username=\"$PGUSER\" --dbname=\"$PAPERLESS_TEMPORARY\"");
    }
    let pgpass = postgres_admin_pgpass(state);
    let validation = run_docker_job_with_secrets(
        state,
        &format!("mb-preflight-{}", &Uuid::new_v4().simple().to_string()[..12]),
        json!({
            "Image": image,
            "User": "0:0",
            "Cmd": ["sh", "-ec", command],
            "Env": [
                format!("PGHOST={}", state.config.postgres_host),
                format!("PGPORT={}", state.config.postgres_port),
                format!("PGUSER={}", state.config.postgres_admin_user),
                "PGPASSFILE=/run/makersbrain-job-secrets/pgpass",
                format!("AGE_IDENTITY={}", s3.age_identity_file),
                format!("ODOO_TEMPORARY={odoo_temporary}"),
                format!("PAPERLESS_TEMPORARY={paperless_temporary}"),
            ],
            "Labels": {"makersbrain.kind":"restore-preflight-job"},
            "HostConfig": {"NetworkMode": state.config.docker_network, "Binds": [format!("{}:/backups:ro", state.config.backup_volume), recovery_identity_bind(state, s3)?]}
        }),
        &[("pgpass", &pgpass)],
    )
    .await;
    let validation = match validation {
        Ok(()) => {
            validate_recovery_database_content(
                state,
                &odoo_temporary,
                includes_paperless.then_some(paperless_temporary.as_str()),
            )
            .await
        }
        Err(error) => Err(error),
    };
    let odoo_cleanup = drop_database(state, &odoo_temporary).await;
    let paperless_cleanup = if includes_paperless {
        drop_database(state, &paperless_temporary).await
    } else {
        Ok(())
    };
    match (validation, odoo_cleanup, paperless_cleanup) {
        (Ok(()), Ok(()), Ok(())) => Ok(()),
        (Err(error), _, _) => Err(error),
        (_, Err(error), _) | (_, _, Err(error)) => Err(error),
    }
}

pub(super) fn safe_s3_storage_ref(
    storage_ref: &str,
    expected_bucket: &str,
    workshop: Uuid,
) -> Result<(String, Uuid), DriverError> {
    let prefix = storage_ref
        .strip_prefix(&format!("s3://{expected_bucket}/"))
        .ok_or_else(|| DriverError::bad("S3 recovery bucket is invalid"))?;
    let parts = prefix.split('/').collect::<Vec<_>>();
    if parts.len() != 4
        || parts[0] != "workshops"
        || parts[1] != workshop.to_string()
        || parts[2] != "recovery"
    {
        return Err(DriverError::bad("S3 recovery prefix is invalid"));
    }
    let recovery = parts[3]
        .parse()
        .map_err(|_| DriverError::bad("S3 recovery ID is invalid"))?;
    Ok((prefix.to_owned(), recovery))
}

fn validate_paperless_version(
    state: &DriverState,
    manifest: &RecoveryManifest,
) -> Result<(), DriverError> {
    if manifest
        .component_scope
        .iter()
        .any(|item| item == "paperless")
        && manifest.paperless_version.as_deref() != state.config.paperless_image.as_deref()
    {
        return Err(DriverError::bad(
            "Paperless recovery version does not match the configured image",
        ));
    }
    Ok(())
}

fn recovery_response(
    directory: &Path,
    relative: &Path,
    size_bytes: i64,
    manifest: &RecoveryManifest,
    manifest_digest: String,
) -> Result<Value, DriverError> {
    let mut components = manifest.components.clone();
    components.push(recovery_component("manifest", "manifest.json", directory)?);
    components.push(recovery_component(
        "commit-marker",
        "complete.json",
        directory,
    )?);
    Ok(json!({
        "storage_ref": relative.to_string_lossy(),
        "storage_location": "local",
        "size_bytes": size_bytes,
        "manifest_digest": manifest_digest,
        "format_version": manifest.format,
        "source_release": manifest.source_release,
        "paperless_version": manifest.paperless_version,
        "components": components,
    }))
}

fn read_v2_manifest(directory: &Path) -> Result<RecoveryManifest, DriverError> {
    let bytes = std::fs::read(directory.join("manifest.json")).map_err(DriverError::internal)?;
    serde_json::from_slice(&bytes).map_err(|_| DriverError::bad("recovery manifest is invalid"))
}

pub(super) fn verify_recovery_directory(
    directory: &Path,
    workshop: Uuid,
    expected_scope: &[String],
) -> Result<RecoveryManifest, DriverError> {
    let manifest = read_v2_manifest(directory)?;
    if manifest.format != RECOVERY_FORMAT_V2
        || manifest.workshop_id != workshop
        || normalized_scope(&manifest.component_scope) != normalized_scope(expected_scope)
    {
        return Err(DriverError::bad("recovery manifest scope is incompatible"));
    }
    let commit: Value = serde_json::from_slice(
        &std::fs::read(directory.join("complete.json")).map_err(DriverError::internal)?,
    )
    .map_err(|_| DriverError::bad("recovery commit marker is invalid"))?;
    let expected_manifest_digest = commit
        .get("manifest_sha256")
        .and_then(Value::as_str)
        .ok_or_else(|| DriverError::bad("recovery commit marker is incomplete"))?;
    let actual_manifest_digest =
        digest_file(&directory.join("manifest.json")).map_err(DriverError::internal)?;
    if expected_manifest_digest != actual_manifest_digest {
        return Err(DriverError::bad("recovery manifest integrity check failed"));
    }
    let mut names = std::collections::BTreeSet::new();
    for component in &manifest.components {
        if !names.insert(component.name.as_str())
            || !safe_component_path(&component.path)
            || component.size_bytes < 0
            || !valid_sha256(&component.sha256)
            || component
                .plaintext_sha256
                .as_deref()
                .is_some_and(|digest| !valid_sha256(digest))
        {
            return Err(DriverError::bad("recovery component list is invalid"));
        }
        let path = directory.join(&component.path);
        let (size_bytes, digest) = digest_path(&path).map_err(DriverError::internal)?;
        if size_bytes != component.size_bytes || digest != component.sha256 {
            return Err(DriverError::bad(
                "recovery component integrity check failed",
            ));
        }
    }
    let required = if expected_scope.iter().any(|item| item == "paperless") {
        vec![
            "odoo-database",
            "odoo-filestore",
            "paperless-database",
            "paperless-data",
            "paperless-media",
            "paperless-consume",
        ]
    } else {
        vec!["odoo-database", "odoo-filestore"]
    };
    if required.iter().any(|name| !names.contains(name)) || names.len() != required.len() {
        return Err(DriverError::bad("recovery component scope is incomplete"));
    }
    Ok(manifest)
}

fn normalized_scope(scope: &[String]) -> std::collections::BTreeSet<&str> {
    scope.iter().map(String::as_str).collect()
}

pub(super) fn safe_component_path(path: &str) -> bool {
    let path = Path::new(path);
    !path.is_absolute()
        && !path.as_os_str().is_empty()
        && path.as_os_str().as_encoded_bytes().iter().all(|value| {
            value.is_ascii_alphanumeric() || matches!(value, b'/' | b'.' | b'_' | b'-')
        })
        && path.components().all(|component| {
            matches!(
                component,
                std::path::Component::Normal(_) | std::path::Component::CurDir
            )
        })
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(super) fn recovery_component(
    name: &str,
    relative: &str,
    directory: &Path,
) -> Result<RecoveryComponent, DriverError> {
    let (size_bytes, sha256) =
        digest_path(&directory.join(relative)).map_err(DriverError::internal)?;
    Ok(RecoveryComponent {
        name: name.to_owned(),
        path: relative.to_owned(),
        size_bytes,
        plaintext_sha256: Some(sha256.clone()),
        sha256,
    })
}

pub(super) fn encrypted_recovery_component(
    name: &str,
    relative: &str,
    plaintext_checksum_relative: &str,
    directory: &Path,
) -> Result<RecoveryComponent, DriverError> {
    let checksum_path = directory.join(plaintext_checksum_relative);
    let plaintext_sha256 = std::fs::read_to_string(&checksum_path)
        .map_err(DriverError::internal)?
        .trim()
        .to_owned();
    if !valid_sha256(&plaintext_sha256) {
        return Err(DriverError::bad("invalid plaintext recovery checksum"));
    }
    std::fs::remove_file(checksum_path).map_err(DriverError::internal)?;
    let encrypted_path = directory.join(relative);
    let metadata = std::fs::metadata(&encrypted_path).map_err(DriverError::internal)?;
    if !metadata.is_file() {
        return Err(DriverError::bad(
            "encrypted recovery component is not a regular file",
        ));
    }
    let size_bytes = i64::try_from(metadata.len()).unwrap_or(i64::MAX);
    let sha256 = digest_file(&encrypted_path).map_err(DriverError::internal)?;
    Ok(RecoveryComponent {
        name: name.to_owned(),
        path: relative.to_owned(),
        size_bytes,
        sha256,
        plaintext_sha256: Some(plaintext_sha256),
    })
}

pub(super) fn digest_file(path: &Path) -> std::io::Result<String> {
    use std::io::Read;

    let mut file = std::fs::File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn digest_path(path: &Path) -> std::io::Result<(i64, String)> {
    fn walk(
        root: &Path,
        current: &Path,
        digest: &mut Sha256,
        size: &mut i64,
    ) -> std::io::Result<()> {
        let metadata = std::fs::symlink_metadata(current)?;
        if metadata.file_type().is_symlink() {
            return Err(std::io::Error::other(
                "recovery components do not support symbolic links",
            ));
        }
        let relative = current.strip_prefix(root).unwrap_or(current);
        digest.update(relative.to_string_lossy().as_bytes());
        if metadata.is_file() {
            digest.update(b"file\0");
            *size = size.saturating_add(i64::try_from(metadata.len()).unwrap_or(i64::MAX));
            use std::io::Read;
            let mut file = std::fs::File::open(current)?;
            let mut buffer = [0_u8; 64 * 1024];
            loop {
                let count = file.read(&mut buffer)?;
                if count == 0 {
                    break;
                }
                digest.update(&buffer[..count]);
            }
        } else if metadata.is_dir() {
            digest.update(b"directory\0");
            let mut entries = std::fs::read_dir(current)?.collect::<Result<Vec<_>, _>>()?;
            entries.sort_by_key(std::fs::DirEntry::file_name);
            for entry in entries {
                walk(root, &entry.path(), digest, size)?;
            }
        } else {
            return Err(std::io::Error::other("unsupported recovery component type"));
        }
        Ok(())
    }

    let mut digest = Sha256::new();
    let mut size = 0_i64;
    let root = path.parent().unwrap_or(path);
    walk(root, path, &mut digest, &mut size)?;
    Ok((size, format!("{:x}", digest.finalize())))
}

async fn backup_paperless(
    state: &DriverState,
    workshop: Uuid,
    recovery: Uuid,
    relative: &Path,
    directory: &Path,
    components: &mut Vec<RecoveryComponent>,
) -> Result<(), DriverError> {
    let compact = tenant_key(workshop);
    let paperless_database = format!("pl_{compact}");
    let paperless_directory = directory.join("paperless");
    secure_directory(&paperless_directory).map_err(DriverError::internal)?;
    let dump_relative = relative.join("paperless/database.dump");
    run_postgres_job_as(
        state,
        &format!("mb-pl-dump-{}", &recovery.simple().to_string()[..12]),
        &state.config.postgres_admin_user,
        &state.config.postgres_admin_password,
        vec![
            "pg_dump".into(),
            "--format=custom".into(),
            "--no-owner".into(),
            "--no-acl".into(),
            format!("--host={}", state.config.postgres_host),
            format!("--port={}", state.config.postgres_port),
            format!("--username={}", state.config.postgres_admin_user),
            format!("--file=/backups/{}", dump_relative.to_string_lossy()),
            paperless_database,
        ],
    )
    .await?;
    run_paperless_volume_job(
        state,
        workshop,
        &format!("mb-pl-files-{}", &recovery.simple().to_string()[..12]),
        relative,
        false,
    )
    .await?;
    for (name, path) in [
        ("paperless-database", "paperless/database.dump"),
        ("paperless-data", "paperless/data"),
        ("paperless-media", "paperless/media"),
        ("paperless-consume", "paperless/consume"),
    ] {
        components.push(recovery_component(name, path, directory)?);
    }
    Ok(())
}

async fn restore_paperless(
    state: &DriverState,
    workshop: Uuid,
    relative: &Path,
    _resolved: &Path,
) -> Result<(), DriverError> {
    let compact = tenant_key(workshop);
    let database = format!("pl_{compact}");
    replace_database_owned(state, &database, &database).await?;
    run_postgres_job_as(
        state,
        &format!(
            "mb-pl-restore-{}",
            &Uuid::new_v4().simple().to_string()[..12]
        ),
        &state.config.postgres_admin_user,
        &state.config.postgres_admin_password,
        vec![
            "pg_restore".into(),
            "--exit-on-error".into(),
            "--no-owner".into(),
            "--no-acl".into(),
            format!("--host={}", state.config.postgres_host),
            format!("--port={}", state.config.postgres_port),
            format!("--username={}", state.config.postgres_admin_user),
            format!("--dbname={database}"),
            format!(
                "/backups/{}/paperless/database.dump",
                relative.to_string_lossy()
            ),
        ],
    )
    .await?;
    run_paperless_volume_job(
        state,
        workshop,
        &format!("mb-pl-files-{}", &Uuid::new_v4().simple().to_string()[..12]),
        relative,
        true,
    )
    .await
}

async fn run_paperless_volume_job(
    state: &DriverState,
    workshop: Uuid,
    container: &str,
    relative: &Path,
    restore: bool,
) -> Result<(), DriverError> {
    let mut binds = vec![format!("{}:/backups", state.config.backup_volume)];
    for suffix in ["data", "media", "consume"] {
        binds.push(format!(
            "mb-paperless-{workshop}-{suffix}:/paperless/{suffix}{}",
            if restore { "" } else { ":ro" }
        ));
    }
    let relative = relative.to_string_lossy();
    let command = if restore {
        format!(
            "set -eu; for part in data media consume; do find /paperless/$part -mindepth 1 -maxdepth 1 -exec rm -rf -- {{}} +; cp -a /backups/{relative}/paperless/$part/. /paperless/$part/; done"
        )
    } else {
        format!(
            "set -eu; for part in data media consume; do mkdir -p /backups/{relative}/paperless/$part; cp -a /paperless/$part/. /backups/{relative}/paperless/$part/; done"
        )
    };
    run_docker_job(
        state,
        container,
        json!({
            "Image": state.config.postgres_image,
            "Cmd": ["sh", "-ec", command],
            "Labels": {"makersbrain.kind":"paperless-recovery-job"},
            "HostConfig": {"NetworkMode": state.config.docker_network, "Binds": binds}
        }),
    )
    .await
}

async fn validate_local_dump(
    state: &DriverState,
    dump_relative: &Path,
    owner: &str,
) -> Result<(), DriverError> {
    let temporary = format!("mb_{}", Uuid::new_v4().simple());
    replace_database_owned(state, &temporary, owner).await?;
    let validation = run_postgres_job(
        state,
        &format!(
            "mb-pg-validate-{}",
            &Uuid::new_v4().simple().to_string()[..12]
        ),
        vec![
            "pg_restore".into(),
            "--exit-on-error".into(),
            "--no-owner".into(),
            "--no-acl".into(),
            format!("--host={}", state.config.postgres_host),
            format!("--port={}", state.config.postgres_port),
            format!("--username={}", state.config.postgres_admin_user),
            format!("--dbname={temporary}"),
            format!("/backups/{}", dump_relative.to_string_lossy()),
        ],
    )
    .await;
    let cleanup = drop_database(state, &temporary).await;
    match (validation, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), _) => Err(error),
        (_, Err(error)) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backup_writer_never_receives_recovery_secret_bind() {
        let workshop = Uuid::parse_str("00000000-0000-0000-0000-000000000201").unwrap();
        let binds = backup_writer_binds("mb-backups", "mb-odoo", workshop, true);

        assert_eq!(binds.len(), 5);
        assert!(binds.iter().all(|bind| !bind.contains("recovery-secret")));
        assert!(binds.iter().all(|bind| !bind.contains("age-identity")));
        assert_eq!(binds[0], "mb-backups:/backups");
        assert_eq!(binds[1], "mb-odoo:/odoo:ro");
    }
}
