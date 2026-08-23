use super::*;
use axum::Extension;

use crate::auth::WorkshopScope;
use crate::outbound_http::TraceRequestBuilderExt as _;

pub(super) async fn database(
    State(state): State<Arc<AppState>>,
    Extension(scope): Extension<WorkshopScope>,
) -> ApiResult<Json<DatabaseResponse>> {
    let workshop = scope.workshop_id;
    let mut tx = state.tenant_store.begin(workshop).await?;
    let primary =
        sqlx::query_as::<_, (Uuid, String, String, OffsetDateTime, Option<OffsetDateTime>)>(
            "select id,public_hostname,state,created_at,last_restored_at
         from control.odoo_databases
         where workshop_id=$1 and kind='primary' and deleted_at is null",
        )
        .bind(workshop)
        .fetch_optional(&mut *tx)
        .await?;
    let duplicates = sqlx::query_as::<_, (Uuid, String, String, OffsetDateTime)>(
        "select id,label,state,created_at from control.odoo_databases
         where workshop_id=$1 and kind='duplicate' and deleted_at is null
         order by created_at desc",
    )
    .bind(workshop)
    .fetch_all(&mut *tx)
    .await?;
    let recovery = sqlx::query_as::<_, RecoveryPointRow>(
        "select r.id,r.kind,r.label,r.state,r.size_bytes,r.created_at,r.ready_at,
                r.operation_id,o.state as operation_state,r.component_scope,r.format_version,
                r.storage_location,r.verified_at,r.expires_at,
                coalesce(o.progress_percent,0::smallint) as progress_percent,
                o.progress_phase,o.progress_message,
                o.progress_updated_at,r.archive_size_bytes
         from control.workshop_recovery_points r
         left join control.operations o on o.id=r.operation_id
         where r.workshop_id=$1 and r.state<>'deleted'
         order by r.created_at desc",
    )
    .bind(workshop)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Json(DatabaseResponse {
        can_manage: scope.role.can_manage_database(),
        primary: primary.map(|row| PrimaryDatabaseResponse {
            id: row.0,
            public_hostname: row.1,
            state: row.2,
            created_at: api_timestamp(row.3),
            last_restored_at: row.4.map(api_timestamp),
        }),
        duplicates: duplicates
            .into_iter()
            .map(|row| DuplicateDatabaseResponse {
                id: row.0,
                label: row.1,
                state: row.2,
                routable: false,
                created_at: api_timestamp(row.3),
            })
            .collect(),
        recovery_points: recovery
            .into_iter()
            .map(|row| {
                let downloadable = row.kind == "backup"
                    && row.state == "ready"
                    && row.verified_at.is_some()
                    && row.archive_size_bytes.is_some();
                RecoveryPointResponse {
                    id: row.id,
                    kind: row.kind,
                    label: row.label,
                    state: row.state,
                    size_bytes: row.size_bytes,
                    created_at: api_timestamp(row.created_at),
                    ready_at: row.ready_at.map(api_timestamp),
                    operation_id: row.operation_id,
                    operation_state: row.operation_state,
                    component_scope: row.component_scope,
                    format_version: row.format_version,
                    storage_location: row.storage_location,
                    verified_at: row.verified_at.map(api_timestamp),
                    expires_at: row.expires_at.map(api_timestamp),
                    progress_percent: row.progress_percent,
                    progress_phase: row.progress_phase,
                    progress_message: row.progress_message,
                    progress_updated_at: row.progress_updated_at.map(api_timestamp),
                    archive_size_bytes: row.archive_size_bytes,
                    downloadable,
                }
            })
            .collect(),
    }))
}

#[derive(sqlx::FromRow)]
struct RecoveryPointRow {
    id: Uuid,
    kind: String,
    label: String,
    state: String,
    size_bytes: Option<i64>,
    created_at: OffsetDateTime,
    ready_at: Option<OffsetDateTime>,
    operation_id: Option<Uuid>,
    operation_state: Option<String>,
    component_scope: Vec<String>,
    format_version: String,
    storage_location: String,
    verified_at: Option<OffsetDateTime>,
    expires_at: Option<OffsetDateTime>,
    progress_percent: i16,
    progress_phase: Option<String>,
    progress_message: Option<String>,
    progress_updated_at: Option<OffsetDateTime>,
    archive_size_bytes: Option<i64>,
}

pub(super) async fn download_backup(
    State(state): State<Arc<AppState>>,
    Extension(scope): Extension<WorkshopScope>,
    Path((_, recovery)): Path<(Uuid, Uuid)>,
) -> ApiResult<Json<Value>> {
    let workshop = scope.workshop_id;
    let mut tx = state.tenant_store.begin(workshop).await?;
    let downloadable = sqlx::query_scalar::<_, bool>(
        "select exists(select 1 from control.workshop_recovery_points
         where id=$1 and workshop_id=$2 and kind='backup' and state='ready'
           and verification_state='verified' and archive_object_key is not null)",
    )
    .bind(recovery)
    .bind(workshop)
    .fetch_one(&mut *tx)
    .await?;
    if !downloadable {
        return Err(ApiError::Conflict(
            "backup archive is not ready for download",
        ));
    }
    tx.commit().await?;
    let response = state
        .deployment_driver_client
        .post(format!(
            "{}v1/tenants/{workshop}/download",
            state.config.deployment_driver_url.as_str()
        ))
        .bearer_auth(&state.config.deployment_driver_token)
        .header("idempotency-key", Uuid::new_v4().to_string())
        .json(&json!({"recovery_point_id": recovery}))
        .with_current_trace_context()
        .send()
        .await
        .map_err(|error| ApiError::Internal(error.into()))?;
    let status = response.status();
    let value = response
        .json::<Value>()
        .await
        .map_err(|error| ApiError::Internal(error.into()))?;
    if !status.is_success() {
        return Err(ApiError::Internal(anyhow::anyhow!(
            "deployment driver refused backup download"
        )));
    }
    Ok(Json(value))
}

#[derive(Deserialize, ToSchema)]
pub(crate) struct RecoveryPointBody {
    label: Option<String>,
}

pub(super) async fn create_snapshot(
    State(state): State<Arc<AppState>>,
    Extension(scope): Extension<WorkshopScope>,
    headers: HeaderMap,
    Json(body): Json<RecoveryPointBody>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    create_recovery_point(&state, &scope, &headers, body.label, "snapshot").await
}

pub(super) async fn create_backup(
    State(state): State<Arc<AppState>>,
    Extension(scope): Extension<WorkshopScope>,
    headers: HeaderMap,
    Json(body): Json<RecoveryPointBody>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    create_recovery_point(&state, &scope, &headers, body.label, "backup").await
}

async fn create_recovery_point(
    state: &AppState,
    scope: &WorkshopScope,
    headers: &HeaderMap,
    label: Option<String>,
    kind: &'static str,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let workshop = scope.workshop_id;
    let principal_id = scope.principal_id;
    let client_key = idempotency(headers)?.to_owned();
    let label = lifecycle_label(
        label,
        if kind == "snapshot" {
            "Manual snapshot"
        } else {
            "Portable backup"
        },
    )?;
    let recovery_id = Uuid::new_v4();
    let correlation = Uuid::new_v4();
    let semantic = json!({"kind":kind,"label":label});
    let mut tx = state.tenant_store.begin(scope.workshop_id).await?;
    revalidate_workshop_scope(&mut tx, scope).await?;
    let command_id = match admit_command(
        &mut tx,
        NewCommand {
            actor_user_id: principal_id,
            scope: &format!("workshop:{workshop}:recovery"),
            command_kind: &format!("database.{kind}"),
            idempotency_key: &client_key,
            semantic_request: &semantic,
            expected_version: None,
        },
    )
    .await
    .map_err(command_error)?
    {
        CommandAdmission::New { command_id } => command_id,
        CommandAdmission::Replay {
            response_status,
            response_body,
            ..
        } => {
            tx.commit().await?;
            return Ok((
                StatusCode::from_u16(response_status).unwrap_or(StatusCode::ACCEPTED),
                Json(response_body.unwrap_or_else(|| json!({"replayed":true}))),
            ));
        }
        CommandAdmission::InProgress {
            command_id,
            operation_id,
        } => {
            tx.commit().await?;
            return Ok((
                StatusCode::ACCEPTED,
                Json(
                    json!({"command_id":command_id,"operation_id":operation_id,"in_progress":true}),
                ),
            ));
        }
    };
    lock_lifecycle(&mut tx, workshop).await?;
    let database_id = primary_database(&mut tx, workshop).await?;
    ensure_lifecycle_idle(&mut tx, workshop).await?;
    let documents_enabled = sqlx::query_scalar::<_, bool>(
        "select exists(select 1 from control.workshop_modules where workshop_id=$1 and module_key='documents' and state='enabled')",
    )
    .bind(workshop)
    .fetch_one(&mut *tx)
    .await?;
    let component_scope = if documents_enabled {
        vec!["odoo", "paperless"]
    } else {
        vec!["odoo"]
    };
    let payload = json!({"action":kind,"database_id":database_id,"recovery_point_id":recovery_id});
    let operation_id = Store::enqueue(
        &mut tx,
        NewOperation {
            kind: OperationKind::TenantLifecycle,
            workshop_id: Some(workshop),
            target_user_id: None,
            desired_epoch: None,
            payload: &payload,
            requested_by: Some(principal_id),
            correlation_id: correlation,
            idempotency_key: &format!("command:{command_id}"),
        },
    )
    .await?;
    sqlx::query("insert into control.workshop_recovery_points(id,workshop_id,database_id,operation_id,kind,label,requested_by,component_scope,format_version) values($1,$2,$3,$4,$5,$6,$7,$8,'mb-workshop-recovery-v2')")
        .bind(recovery_id).bind(workshop).bind(database_id).bind(operation_id).bind(kind).bind(label).bind(principal_id).bind(&component_scope).execute(&mut *tx).await?;
    audit_command(
        &mut tx,
        (Some(principal_id), Some(workshop)),
        &format!("database.{kind}"),
        "workshop_recovery_point",
        recovery_id.to_string(),
        correlation,
        command_id,
    )
    .await?;
    let response = json!({"id":recovery_id,"operation_id":operation_id});
    let result_ref = recovery_id.to_string();
    complete_command(
        &mut tx,
        command_id,
        CommandResult {
            operation_id: Some(operation_id),
            response_status: StatusCode::ACCEPTED.as_u16(),
            response_body: Some(&response),
            result_ref: Some(&result_ref),
        },
    )
    .await
    .map_err(command_error)?;
    tx.commit().await?;
    Ok((StatusCode::ACCEPTED, Json(response)))
}

pub(super) async fn restore_database(
    State(state): State<Arc<AppState>>,
    Extension(scope): Extension<WorkshopScope>,
    Extension(principal): Extension<Principal>,
    headers: HeaderMap,
    Json(body): Json<RestoreBody>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let id = scope.workshop_id;
    let principal_id = scope.principal_id;
    require_step_up(&principal)?;
    confirm_slug(&state, id, &body.confirmation).await?;
    let client_key = idempotency(&headers)?.to_owned();
    let correlation = Uuid::new_v4();
    let safety_id = Uuid::new_v4();
    let semantic =
        json!({"recovery_point_id":body.recovery_point_id,"confirmation":body.confirmation});
    let mut tx = state.tenant_store.begin(scope.workshop_id).await?;
    revalidate_workshop_scope(&mut tx, &scope).await?;
    let command_id = match admit_command(
        &mut tx,
        NewCommand {
            actor_user_id: principal_id,
            scope: &format!("workshop:{id}:database"),
            command_kind: "database.restore",
            idempotency_key: &client_key,
            semantic_request: &semantic,
            expected_version: None,
        },
    )
    .await
    .map_err(command_error)?
    {
        CommandAdmission::New { command_id } => command_id,
        CommandAdmission::Replay {
            response_status,
            response_body,
            ..
        } => {
            tx.commit().await?;
            return Ok((
                StatusCode::from_u16(response_status).unwrap_or(StatusCode::ACCEPTED),
                Json(response_body.unwrap_or_else(|| json!({"replayed":true}))),
            ));
        }
        CommandAdmission::InProgress {
            command_id,
            operation_id,
        } => {
            tx.commit().await?;
            return Ok((
                StatusCode::ACCEPTED,
                Json(
                    json!({"command_id":command_id,"operation_id":operation_id,"in_progress":true}),
                ),
            ));
        }
    };
    lock_lifecycle(&mut tx, id).await?;
    let database_id = primary_database(&mut tx, id).await?;
    ensure_lifecycle_idle(&mut tx, id).await?;
    let recovery = sqlx::query_as::<_,(Vec<String>,OffsetDateTime)>("select component_scope,created_at from control.workshop_recovery_points where id=$1 and workshop_id=$2 and database_id=$3 and state='ready' and verification_state='verified' and storage_ref is not null and (expires_at is null or expires_at > now())")
        .bind(body.recovery_point_id).bind(id).bind(database_id).fetch_optional(&mut *tx).await?.ok_or(ApiError::Validation("recovery point is not ready and verified"))?;
    let recovery_scope = recovery.0;
    let tombstones = sqlx::query_as::<_, (Uuid, Vec<String>, bool)>(
        "select t.id,t.required_locations,control.erasure_lookup_available(t.id)
         from control.erasure_tombstones t
         where t.workshop_id=$1 and t.applies_before>$2
           and 'backups'=any(t.required_locations)
         order by t.sequence",
    )
    .bind(id)
    .bind(recovery.1)
    .fetch_all(&mut *tx)
    .await?;
    if tombstones.iter().any(|row| !row.2) {
        return Err(ApiError::Conflict(
            "this recovery point predates an erasure whose protected processor lookup is unavailable",
        ));
    }
    let documents_enabled = sqlx::query_scalar::<_, bool>(
        "select exists(select 1 from control.workshop_modules where workshop_id=$1 and module_key='documents' and state='enabled')",
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await?;
    if recovery_scope.iter().any(|item| item == "paperless") != documents_enabled {
        return Err(ApiError::Validation(
            "recovery point module scope does not match the workshop",
        ));
    }
    let safety_scope = if documents_enabled {
        vec!["odoo", "paperless"]
    } else {
        vec!["odoo"]
    };
    let replay_required = !tombstones.is_empty();
    let payload = json!({
        "action":"restore",
        "database_id":database_id,
        "recovery_point_id":body.recovery_point_id,
        "safety_recovery_point_id":safety_id,
        "erasure_replay_required":replay_required,
        "erasure_tombstone_ids":tombstones.iter().map(|row|row.0).collect::<Vec<_>>()
    });
    let operation_id = Store::enqueue(
        &mut tx,
        NewOperation {
            kind: OperationKind::TenantLifecycle,
            workshop_id: Some(id),
            target_user_id: None,
            desired_epoch: None,
            payload: &payload,
            requested_by: Some(principal_id),
            correlation_id: correlation,
            idempotency_key: &format!("command:{command_id}"),
        },
    )
    .await?;
    for (tombstone_id, required_locations, _) in &tombstones {
        let restored_locations = required_locations
            .iter()
            .filter(|location| recovery_scope.contains(location))
            .cloned()
            .collect::<Vec<_>>();
        if restored_locations.is_empty() {
            return Err(ApiError::Internal(anyhow::anyhow!(
                "erasure tombstone has no restored processor location"
            )));
        }
        sqlx::query(
            "insert into control.erasure_restore_replays(
                 id,workshop_id,tombstone_id,recovery_point_id,operation_id,required_locations
             ) values($1,$2,$3,$4,$5,$6)",
        )
        .bind(Uuid::new_v4())
        .bind(id)
        .bind(tombstone_id)
        .bind(body.recovery_point_id)
        .bind(operation_id)
        .bind(restored_locations)
        .execute(&mut *tx)
        .await?;
    }
    sqlx::query("insert into control.workshop_recovery_points(id,workshop_id,database_id,operation_id,kind,label,requested_by,component_scope,format_version) values($1,$2,$3,$4,'backup','Automatic pre-restore safety backup',$5,$6,'mb-workshop-recovery-v2')")
        .bind(safety_id).bind(id).bind(database_id).bind(operation_id).bind(principal_id).bind(&safety_scope).execute(&mut *tx).await?;
    sqlx::query(
        "update control.odoo_databases set state='restoring' where id=$1 and workshop_id=$2",
    )
    .bind(database_id)
    .bind(id)
    .execute(&mut *tx)
    .await?;
    audit_command(
        &mut tx,
        (Some(principal_id), Some(id)),
        "database.restore",
        "workshop_recovery_point",
        body.recovery_point_id.to_string(),
        correlation,
        command_id,
    )
    .await?;
    let response = json!({"operation_id":operation_id,"safety_recovery_point_id":safety_id});
    let result_ref = body.recovery_point_id.to_string();
    complete_command(
        &mut tx,
        command_id,
        CommandResult {
            operation_id: Some(operation_id),
            response_status: StatusCode::ACCEPTED.as_u16(),
            response_body: Some(&response),
            result_ref: Some(&result_ref),
        },
    )
    .await
    .map_err(command_error)?;
    tx.commit().await?;
    Ok((StatusCode::ACCEPTED, Json(response)))
}

#[derive(Deserialize, ToSchema)]
pub(crate) struct RestoreBody {
    recovery_point_id: Uuid,
    confirmation: String,
}

#[derive(Deserialize, ToSchema)]
pub(crate) struct DuplicateBody {
    label: String,
    confirmation: String,
}

pub(super) async fn duplicate_database(
    State(state): State<Arc<AppState>>,
    Extension(scope): Extension<WorkshopScope>,
    Extension(principal): Extension<Principal>,
    headers: HeaderMap,
    Json(body): Json<DuplicateBody>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let id = scope.workshop_id;
    let principal_id = scope.principal_id;
    require_step_up(&principal)?;
    confirm_slug(&state, id, &body.confirmation).await?;
    let label = lifecycle_label(Some(body.label), "Database duplicate")?;
    let client_key = idempotency(&headers)?.to_owned();
    let duplicate_id = Uuid::new_v4();
    let duplicate_ref = opaque_database_ref(duplicate_id);
    let correlation = Uuid::new_v4();
    let semantic = json!({"label":label,"confirmation":body.confirmation});
    let mut tx = state.tenant_store.begin(scope.workshop_id).await?;
    revalidate_workshop_scope(&mut tx, &scope).await?;
    let command_id = match admit_command(
        &mut tx,
        NewCommand {
            actor_user_id: principal_id,
            scope: &format!("workshop:{id}:database"),
            command_kind: "database.duplicate",
            idempotency_key: &client_key,
            semantic_request: &semantic,
            expected_version: None,
        },
    )
    .await
    .map_err(command_error)?
    {
        CommandAdmission::New { command_id } => command_id,
        CommandAdmission::Replay {
            response_status,
            response_body,
            ..
        } => {
            tx.commit().await?;
            return Ok((
                StatusCode::from_u16(response_status).unwrap_or(StatusCode::ACCEPTED),
                Json(response_body.unwrap_or_else(|| json!({"replayed":true}))),
            ));
        }
        CommandAdmission::InProgress {
            command_id,
            operation_id,
        } => {
            tx.commit().await?;
            return Ok((
                StatusCode::ACCEPTED,
                Json(
                    json!({"command_id":command_id,"operation_id":operation_id,"in_progress":true}),
                ),
            ));
        }
    };
    lock_lifecycle(&mut tx, id).await?;
    let source_id = primary_database(&mut tx, id).await?;
    ensure_lifecycle_idle(&mut tx, id).await?;
    sqlx::query("insert into control.odoo_databases(id,workshop_id,kind,database_ref,label,state,source_database_id,routable) values($1,$2,'duplicate',$3,$4,'duplicating',$5,false)")
        .bind(duplicate_id).bind(id).bind(&duplicate_ref).bind(label).bind(source_id).execute(&mut *tx).await?;
    let payload = json!({"action":"duplicate","database_id":source_id,"target_database_id":duplicate_id,"routable":false});
    let operation_id = Store::enqueue(
        &mut tx,
        NewOperation {
            kind: OperationKind::TenantLifecycle,
            workshop_id: Some(id),
            target_user_id: None,
            desired_epoch: None,
            payload: &payload,
            requested_by: Some(principal_id),
            correlation_id: correlation,
            idempotency_key: &format!("command:{command_id}"),
        },
    )
    .await?;
    audit_command(
        &mut tx,
        (Some(principal_id), Some(id)),
        "database.duplicate",
        "odoo_database",
        duplicate_id.to_string(),
        correlation,
        command_id,
    )
    .await?;
    let response = json!({"id":duplicate_id,"operation_id":operation_id,"routable":false});
    let result_ref = duplicate_id.to_string();
    complete_command(
        &mut tx,
        command_id,
        CommandResult {
            operation_id: Some(operation_id),
            response_status: StatusCode::ACCEPTED.as_u16(),
            response_body: Some(&response),
            result_ref: Some(&result_ref),
        },
    )
    .await
    .map_err(command_error)?;
    tx.commit().await?;
    Ok((StatusCode::ACCEPTED, Json(response)))
}

pub(super) async fn confirm_slug(
    state: &AppState,
    workshop: Uuid,
    confirmation: &str,
) -> ApiResult<()> {
    let slug = sqlx::query_scalar::<_, String>("select slug from control.workshops where id=$1")
        .bind(workshop)
        .fetch_one(state.store.pool())
        .await?;
    if confirmation != slug {
        return Err(ApiError::Validation(
            "confirmation must exactly match the workshop slug",
        ));
    }
    Ok(())
}

fn lifecycle_label(value: Option<String>, fallback: &str) -> ApiResult<String> {
    let value = value.unwrap_or_else(|| fallback.to_owned());
    let value = value.trim();
    if value.is_empty() || value.len() > 120 {
        return Err(ApiError::Validation(
            "label must contain 1 to 120 characters",
        ));
    }
    Ok(value.to_owned())
}

pub(super) async fn lock_lifecycle(
    tx: &mut sqlx::postgres::PgConnection,
    workshop: Uuid,
) -> ApiResult<()> {
    sqlx::query("select pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(workshop.to_string())
        .execute(&mut *tx)
        .await?;
    Ok(())
}

pub(super) async fn primary_database(
    tx: &mut sqlx::postgres::PgConnection,
    workshop: Uuid,
) -> ApiResult<Uuid> {
    sqlx::query_scalar::<_, Uuid>("select id from control.odoo_databases where workshop_id=$1 and kind='primary' and deleted_at is null")
        .bind(workshop).fetch_optional(&mut *tx).await?.ok_or(ApiError::Conflict("Odoo database is not provisioned"))
}

pub(super) async fn ensure_lifecycle_idle(
    tx: &mut sqlx::postgres::PgConnection,
    workshop: Uuid,
) -> ApiResult<()> {
    let active = sqlx::query_scalar::<_, bool>("select
        exists(select 1 from control.operations where workshop_id=$1 and kind='tenant.lifecycle' and state in ('pending','in_flight','awaiting_reconciliation'))
        or exists(select 1 from control.tenant_release_adoptions where workshop_id=$1 and state in ('pending','isolating','backing_up','upgrading','verifying','prepared','failed','restoring'))")
        .bind(workshop).fetch_one(&mut *tx).await?;
    if active {
        return Err(ApiError::Conflict(
            "another database operation is already running",
        ));
    }
    Ok(())
}
