use super::*;

pub(super) async fn platform_overview(
    State(state): State<Arc<AppState>>,
    Extension(_scope): Extension<PlatformScope>,
) -> ApiResult<Json<PlatformOverviewResponse>> {
    let workshops = sqlx::query_as::<_, (i64, i64, i64)>(
        "select count(*),count(*) filter(where status in ('active','trial')),count(*) filter(where status in ('past_due','restricted','suspended','deleting')) from control.workshops where status<>'deleted'",
    )
    .fetch_one(state.store.pool())
    .await?;
    let users = sqlx::query_as::<_, (i64, i64)>(
        "select count(*),count(*) filter(where disabled_at is not null) from control.users",
    )
    .fetch_one(state.store.pool())
    .await?;
    let operations = sqlx::query_as::<_, (i64, i64, i64)>(
        "select count(*) filter(where state in ('pending','awaiting_reconciliation')),count(*) filter(where state='in_flight'),count(*) filter(where state='dead_letter') from control.operations",
    )
    .fetch_one(state.store.pool())
    .await?;
    let degraded_services = sqlx::query_scalar::<_, i64>(
        "select count(*) from control.service_instances where health in ('degraded','failed')",
    )
    .fetch_one(state.store.pool())
    .await?;
    let attention = sqlx::query_as::<_, (Uuid,String,String,Option<String>,Option<Uuid>,Option<String>,OffsetDateTime,i16)>(
        "select o.id,o.kind,o.state,o.failure_class,o.workshop_id,w.display_name,o.created_at,o.progress_percent from control.operations o left join control.workshops w on w.id=o.workshop_id where o.state in ('dead_letter','in_flight','awaiting_reconciliation') order by case when o.state='dead_letter' then 0 else 1 end,o.created_at limit 12",
    )
    .fetch_all(state.store.pool())
    .await?;
    Ok(Json(PlatformOverviewResponse {
        workshops: CountHealthResponse {
            total: workshops.0,
            healthy: workshops.1,
            attention: workshops.2,
        },
        users: CountDisabledResponse {
            total: users.0,
            disabled: users.1,
        },
        operations: CountOperationsResponse {
            queued: operations.0,
            running: operations.1,
            failed: operations.2,
        },
        degraded_services,
        attention: attention
            .into_iter()
            .map(|row| AttentionOperationResponse {
                id: row.0,
                kind: row.1,
                state: row.2,
                failure_class: row.3,
                workshop_id: row.4,
                workshop_name: row.5,
                created_at: api_timestamp(row.6),
                progress_percent: row.7,
            })
            .collect(),
    }))
}

pub(super) async fn platform_workshops(
    State(state): State<Arc<AppState>>,
    Extension(_scope): Extension<PlatformScope>,
) -> ApiResult<Json<Vec<PlatformWorkshopResponse>>> {
    let rows = sqlx::query_as::<_, (Uuid,String,String,String,String,OffsetDateTime,i64,i64)>(
        "select w.id,w.slug,w.display_name,w.status,w.plan,w.created_at,count(distinct m.user_id) filter(where m.status='active'),count(distinct s.id) filter(where s.health in ('degraded','failed')) from control.workshops w left join control.memberships m on m.workshop_id=w.id left join control.service_instances s on s.workshop_id=w.id where w.status<>'deleted' group by w.id order by w.created_at desc,w.id",
    )
    .fetch_all(state.store.pool())
    .await?;
    Ok(Json(
        rows.into_iter()
            .map(|row| PlatformWorkshopResponse {
                id: row.0,
                slug: row.1,
                display_name: row.2,
                status: row.3,
                plan: row.4,
                created_at: api_timestamp(row.5),
                member_count: row.6,
                degraded_service_count: row.7,
            })
            .collect(),
    ))
}

pub(super) async fn platform_workshop(
    State(state): State<Arc<AppState>>,
    Extension(_scope): Extension<PlatformScope>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<PlatformWorkshopDetailResponse>> {
    let workshop = sqlx::query_as::<_, (String,String,String,String,Option<String>,Option<String>,OffsetDateTime,i64)>(
        "select slug,display_name,status,plan,legal_name,country_code,created_at,version from control.workshops where id=$1",
    ).bind(id).fetch_optional(state.store.pool()).await?.ok_or(ApiError::NotFound)?;
    let members = sqlx::query_as::<_, (Uuid,String,Option<String>,String,String)>(
        "select u.id,u.email,u.display_name,m.role,m.status from control.memberships m join control.users u on u.id=m.user_id where m.workshop_id=$1 order by u.email",
    ).bind(id).fetch_all(state.store.pool()).await?;
    let services = sqlx::query_as::<_, (String,String,String,Option<String>,Option<String>,i32,i32)>(
        "select service,base_url,health,release_id,safe_error_class,desired_epoch,applied_epoch from control.service_instances where workshop_id=$1 order by service",
    ).bind(id).fetch_all(state.store.pool()).await?;
    let entitlement = sqlx::query_as::<_, (i64,String,String,Value,Option<OffsetDateTime>,OffsetDateTime)>(
        "select version,plan,status,limits,expires_at,updated_at from control.entitlements where workshop_id=$1",
    ).bind(id).fetch_optional(state.store.pool()).await?;
    let usage = sqlx::query_as::<_, (String,i64,OffsetDateTime)>(
        "select metric,quantity,updated_at from control.usage_counters where workshop_id=$1 and period=date_trunc('month',current_date)::date order by metric",
    ).bind(id).fetch_all(state.store.pool()).await?;
    let primary_hostname = sqlx::query_scalar::<_, String>(
        "select public_hostname from control.odoo_databases where workshop_id=$1 and kind='primary' and deleted_at is null and public_hostname is not null",
    ).bind(id).fetch_optional(state.store.pool()).await?;
    let operations = platform_operation_rows(&state, Some(id), None, 30).await?;
    let workshop_slug = workshop.0.clone();
    let primary_hostname_for_services = primary_hostname.clone();
    let deletion = sqlx::query_as::<_, (String,Uuid,Uuid,OffsetDateTime,Option<OffsetDateTime>,OffsetDateTime,Option<String>)>(
        "select state,operation_id,final_recovery_point_id,requested_at,quarantined_at,purge_after,failure_class from control.workshop_deletions where workshop_id=$1",
    ).bind(id).fetch_optional(state.store.pool()).await?;
    Ok(Json(PlatformWorkshopDetailResponse {
        id,
        slug: workshop.0,
        display_name: workshop.1,
        status: workshop.2,
        plan: workshop.3,
        legal_name: workshop.4,
        country_code: workshop.5,
        created_at: api_timestamp(workshop.6),
        version: workshop.7,
        etag: format!("\"workshop-{id}-v{}\"", workshop.7),
        members: members
            .into_iter()
            .map(|row| PlatformMemberResponse {
                id: row.0,
                email: row.1,
                display_name: row.2,
                role: row.3.parse().expect("database role constraint"),
                status: row.4,
            })
            .collect(),
        services: services
            .into_iter()
            .map(|row| {
                let external_url = service_external_url(
                    &state.config,
                    &row.0,
                    &workshop_slug,
                    primary_hostname_for_services.as_deref(),
                );
                PlatformServiceInstanceResponse {
                    service: row.0,
                    url: row.1,
                    external_url,
                    health: row.2,
                    release_id: row.3,
                    error: row.4,
                    desired_epoch: row.5,
                    applied_epoch: row.6,
                }
            })
            .collect(),
        entitlement: entitlement.map(|row| EntitlementResponse {
            version: row.0,
            plan: row.1,
            status: row.2,
            limits: row.3,
            expires_at: row.4.map(api_timestamp),
            updated_at: api_timestamp(row.5),
        }),
        usage: usage
            .into_iter()
            .map(|row| UsageCounterResponse {
                metric: row.0,
                quantity: row.1,
                updated_at: api_timestamp(row.2),
            })
            .collect(),
        primary_hostname,
        operations,
        deletion: deletion.map(|row| WorkshopDeletionResponse {
            state: row.0,
            operation_id: row.1,
            final_recovery_point_id: row.2,
            requested_at: api_timestamp(row.3),
            quarantined_at: row.4.map(api_timestamp),
            purge_after: api_timestamp(row.5),
            failure_class: row.6,
        }),
    }))
}

#[derive(Deserialize, ToSchema)]
pub(crate) struct DeleteWorkshopBody {
    confirmation: String,
}

pub(super) async fn platform_delete_workshop(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Extension(scope): Extension<PlatformScope>,
    Path(id): Path<Uuid>,
    Json(body): Json<DeleteWorkshopBody>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let who = scope.principal();
    require_step_up(who)?;
    confirm_slug(&state, id, &body.confirmation).await?;
    let client_key = idempotency(&headers)?.to_owned();
    let expected = expected_version(&headers, &format!("workshop-{id}"))?;
    let recovery_id = Uuid::new_v4();
    let correlation = Uuid::new_v4();
    let semantic = json!({"confirmation":body.confirmation});
    let mut tx = state.store.begin().await?;
    revalidate_platform_scope(&mut tx, &scope).await?;
    let command_id = match admit_command(
        &mut tx,
        NewCommand {
            actor_user_id: who.user_id,
            scope: &format!("platform:workshop:{id}"),
            command_kind: "workshop.delete.schedule",
            idempotency_key: &client_key,
            semantic_request: &semantic,
            expected_version: Some(expected),
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
    let (slug, previous_status, current_version) = sqlx::query_as::<_, (String, String, i64)>(
        "select slug,status,version from control.workshops where id=$1 for update",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(ApiError::NotFound)?;
    if current_version != expected {
        return Err(ApiError::PreconditionFailed("If-Match is stale"));
    }
    if slug != body.confirmation {
        return Err(ApiError::Validation(
            "confirmation must exactly match the workshop slug",
        ));
    }
    if matches!(previous_status.as_str(), "deleting" | "deleted")
        || sqlx::query_scalar::<_, bool>(
            "select exists(select 1 from control.workshop_deletions where workshop_id=$1)",
        )
        .bind(id)
        .fetch_one(&mut *tx)
        .await?
    {
        return Err(ApiError::Conflict("workshop deletion is already scheduled"));
    }
    let database_id = primary_database(&mut tx, id).await?;
    ensure_lifecycle_idle(&mut tx, id).await?;
    let documents_enabled = sqlx::query_scalar::<_, bool>(
        "select exists(select 1 from control.workshop_modules where workshop_id=$1 and module_key='documents' and state='enabled')",
    ).bind(id).fetch_one(&mut *tx).await?;
    let component_scope = if documents_enabled {
        vec!["odoo", "paperless"]
    } else {
        vec!["odoo"]
    };
    let payload =
        json!({"action":"delete","database_id":database_id,"recovery_point_id":recovery_id});
    let operation_id = Store::enqueue(
        &mut tx,
        NewOperation {
            kind: OperationKind::TenantLifecycle,
            workshop_id: Some(id),
            target_user_id: None,
            desired_epoch: None,
            payload: &payload,
            requested_by: Some(who.user_id),
            correlation_id: correlation,
            idempotency_key: &format!("command:{command_id}"),
        },
    )
    .await?;
    sqlx::query("insert into control.workshop_recovery_points(id,workshop_id,database_id,operation_id,kind,label,requested_by,component_scope,format_version) values($1,$2,$3,$4,'backup','Final pre-deletion backup',$5,$6,'mb-workshop-recovery-v2')")
        .bind(recovery_id).bind(id).bind(database_id).bind(operation_id).bind(who.user_id).bind(&component_scope).execute(&mut *tx).await?;
    sqlx::query("insert into control.workshop_deletions(workshop_id,previous_status,requested_by,operation_id,final_recovery_point_id,purge_after) values($1,$2,$3,$4,$5,now()+interval '30 days')")
        .bind(id).bind(&previous_status).bind(who.user_id).bind(operation_id).bind(recovery_id).execute(&mut *tx).await?;
    let changed=sqlx::query("update control.workshops set status='restricted',version=version+1 where id=$1 and version=$2")
        .bind(id)
        .bind(expected)
        .execute(&mut *tx)
        .await?.rows_affected();
    if changed != 1 {
        return Err(ApiError::PreconditionFailed("If-Match is stale"));
    }
    audit_command(
        &mut tx,
        (Some(who.user_id), Some(id)),
        "workshop.delete.schedule",
        "workshop",
        id.to_string(),
        correlation,
        command_id,
    )
    .await?;
    let response = json!({"operation_id":operation_id,"recovery_point_id":recovery_id,"retention_days":30,"version":expected+1});
    let result_ref = id.to_string();
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

pub(super) async fn platform_reconcile_workshop(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Extension(scope): Extension<PlatformScope>,
    Path(id): Path<Uuid>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let who = scope.principal();
    let key = idempotency(&headers)?.to_owned();
    let semantic = json!({"workshop_id":id});
    let correlation = Uuid::new_v4();
    let mut tx = state.store.begin().await?;
    revalidate_platform_scope(&mut tx, &scope).await?;
    let command_id = match admit_command(
        &mut tx,
        NewCommand {
            actor_user_id: who.user_id,
            scope: &format!("platform:workshop:{id}"),
            command_kind: "tenant.reconcile",
            idempotency_key: &key,
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
    let mut snapshot_tx = state.tenant_store.begin(id).await?;
    let tenant=sqlx::query_as::<_,(Uuid,String,String,String)>("select d.id,w.slug,d.database_ref,d.public_hostname from control.workshops w join control.odoo_databases d on d.workshop_id=w.id where w.id=$1 and w.status<>'deleted' and d.kind='primary' and d.deleted_at is null and d.public_hostname is not null")
        .bind(id).fetch_optional(&mut *snapshot_tx).await?.ok_or(ApiError::NotFound)?;
    let paperless_enabled=sqlx::query_scalar::<_,bool>("select exists(select 1 from control.workshop_modules where workshop_id=$1 and module_key='documents' and state='enabled')").bind(id).fetch_one(&mut *snapshot_tx).await?;
    let custom_hostnames = crate::worker::routable_custom_hostnames(&mut snapshot_tx).await?;
    snapshot_tx.commit().await?;
    let payload = json!({"database_id":tenant.0,"database_ref":tenant.2,"public_hostname":tenant.3,"paperless_hostname":format!("docs-{}.{}",tenant.1,state.config.tenant_domain),"paperless_enabled":paperless_enabled,"custom_hostnames":custom_hostnames});
    let operation_id = Store::enqueue(
        &mut tx,
        NewOperation {
            kind: OperationKind::TenantReconcile,
            workshop_id: Some(id),
            target_user_id: None,
            desired_epoch: None,
            payload: &payload,
            requested_by: Some(who.user_id),
            correlation_id: correlation,
            idempotency_key: &format!("command:{command_id}"),
        },
    )
    .await?;
    audit_command(
        &mut tx,
        (Some(who.user_id), Some(id)),
        "tenant.reconcile",
        "workshop",
        id.to_string(),
        correlation,
        command_id,
    )
    .await?;
    let response = json!({"operation_id":operation_id});
    let result_ref = id.to_string();
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

#[derive(Deserialize)]
pub(super) struct PlatformOperationQuery {
    state: Option<String>,
    workshop_id: Option<Uuid>,
    limit: Option<i64>,
}

pub(super) async fn platform_operations(
    State(state): State<Arc<AppState>>,
    Extension(_scope): Extension<PlatformScope>,
    Query(query): Query<PlatformOperationQuery>,
) -> ApiResult<Json<Vec<PlatformOperationResponse>>> {
    if query.state.as_deref().is_some_and(|value| {
        !matches!(
            value,
            "pending" | "in_flight" | "awaiting_reconciliation" | "succeeded" | "dead_letter"
        )
    }) {
        return Err(ApiError::Validation("invalid operation state"));
    }
    Ok(Json(
        platform_operation_rows(
            &state,
            query.workshop_id,
            query.state.as_deref(),
            query.limit.unwrap_or(100).clamp(1, 200),
        )
        .await?,
    ))
}

async fn platform_operation_rows(
    state: &AppState,
    workshop: Option<Uuid>,
    operation_state: Option<&str>,
    limit: i64,
) -> ApiResult<Vec<PlatformOperationResponse>> {
    let rows = sqlx::query_as::<_, (Uuid,String,String,Option<String>,Option<Uuid>,Option<String>,i32,i32,OffsetDateTime,Option<OffsetDateTime>,i16,Option<String>,Option<String>)>(
        "select o.id,o.kind,o.state,o.failure_class,o.workshop_id,w.display_name,o.attempt,o.max_attempts,o.created_at,o.finished_at,o.progress_percent,o.progress_phase,o.progress_message from control.operations o left join control.workshops w on w.id=o.workshop_id where ($1::uuid is null or o.workshop_id=$1) and ($2::text is null or o.state=$2) order by o.created_at desc,o.id desc limit $3",
    ).bind(workshop).bind(operation_state).bind(limit).fetch_all(state.store.pool()).await?;
    Ok(rows
        .into_iter()
        .map(|row| PlatformOperationResponse {
            id: row.0,
            kind: row.1,
            state: row.2,
            failure_class: row.3,
            workshop_id: row.4,
            workshop_name: row.5,
            attempt: row.6,
            max_attempts: row.7,
            created_at: api_timestamp(row.8),
            finished_at: row.9.map(api_timestamp),
            progress_percent: row.10,
            progress_phase: row.11,
            progress_message: row.12,
        })
        .collect())
}

pub(super) async fn platform_users(
    State(state): State<Arc<AppState>>,
    Extension(_scope): Extension<PlatformScope>,
) -> ApiResult<Json<Vec<PlatformUserResponse>>> {
    let rows = sqlx::query_as::<_, (Uuid,String,Option<String>,String,OffsetDateTime,Option<OffsetDateTime>,bool,i64)>(
        "select u.id,u.email,u.display_name,u.locale,u.created_at,u.disabled_at,exists(select 1 from control.external_identities i where i.user_id=u.id and i.disabled_at is null),count(m.workshop_id) filter(where m.status='active') from control.users u left join control.memberships m on m.user_id=u.id group by u.id order by u.created_at desc,u.id",
    ).fetch_all(state.store.pool()).await?;
    Ok(Json(
        rows.into_iter()
            .map(|row| PlatformUserResponse {
                id: row.0,
                email: row.1,
                display_name: row.2,
                locale: row.3,
                created_at: api_timestamp(row.4),
                disabled_at: row.5.map(api_timestamp),
                identity_linked: row.6,
                workshop_count: row.7,
            })
            .collect(),
    ))
}

pub(super) async fn platform_status(
    State(state): State<Arc<AppState>>,
    Extension(_scope): Extension<PlatformScope>,
) -> ApiResult<Json<PlatformStatusResponse>> {
    let queues = sqlx::query_as::<_, (String,i64,i64,i64,Option<OffsetDateTime>,Option<OffsetDateTime>)>(
        "with known(queue) as (values ('tenant-provisioning'),('membership-provisioning'),('invoice-capture'),('inventory-capture'),('email-delivery'),('tenant-reconciliation'),('tenant-lifecycle'),('release-adoption'),('privacy-operations')) select known.queue,count(o.id) filter(where o.state in ('pending','awaiting_reconciliation')),count(o.id) filter(where o.state='in_flight'),count(o.id) filter(where o.state='dead_letter'),min(o.created_at) filter(where o.state in ('pending','in_flight','awaiting_reconciliation')),max(o.finished_at) from known left join control.operations o on o.queue=known.queue group by known.queue order by known.queue",
    ).fetch_all(state.store.pool()).await?;
    let services = sqlx::query_as::<_, (String,String,i64)>(
        "select service,health,count(*) from control.service_instances group by service,health order by service,health",
    ).fetch_all(state.store.pool()).await?;
    let newest_backup = sqlx::query_as::<_, (Uuid,Uuid,String,OffsetDateTime,Option<String>)>(
        "select r.id,r.workshop_id,w.display_name,r.ready_at,r.source_release from control.workshop_recovery_points r join control.workshops w on w.id=r.workshop_id where r.kind='backup' and r.state='ready' and r.verification_state='verified' order by r.ready_at desc nulls last limit 1",
    ).fetch_optional(state.store.pool()).await?;
    let rehearsal = sqlx::query_as::<_, (Uuid,Uuid,String,Option<String>,OffsetDateTime,Option<OffsetDateTime>)>(
        "select h.id,h.workshop_id,h.state,h.safe_error,h.started_at,h.finished_at from control.workshop_recovery_rehearsals h order by h.started_at desc limit 1",
    ).fetch_optional(state.store.pool()).await?;
    let workers=sqlx::query_as::<_,(String,String,String,OffsetDateTime,OffsetDateTime,Option<Uuid>,Option<OffsetDateTime>,bool)>("select worker_id,queue,release_id,started_at,last_heartbeat_at,active_operation_id,shutdown_at,shutdown_at is null and last_heartbeat_at>now()-interval '30 seconds' from control.worker_heartbeats order by queue,last_heartbeat_at desc")
        .fetch_all(state.store.pool()).await?;
    Ok(Json(PlatformStatusResponse {
        release: PlatformReleaseIdentityResponse {
            api: env!("CARGO_PKG_VERSION").into(),
            schema: crate::persistence::EMBEDDED_SCHEMA_RELEASE.into(),
        },
        queues: queues
            .into_iter()
            .map(|row| QueueStatusResponse {
                queue: row.0,
                queued: row.1,
                running: row.2,
                failed: row.3,
                oldest_active_at: row.4.map(api_timestamp),
                last_finished_at: row.5.map(api_timestamp),
            })
            .collect(),
        services: services
            .into_iter()
            .map(|row| ServiceStatusResponse {
                service: row.0,
                health: row.1,
                count: row.2,
            })
            .collect(),
        newest_verified_backup: newest_backup.map(|row| BackupStatusResponse {
            id: row.0,
            workshop_id: row.1,
            workshop_name: row.2,
            ready_at: api_timestamp(row.3),
            source_release: row.4,
        }),
        latest_rehearsal: rehearsal.map(|row| RehearsalStatusResponse {
            id: row.0,
            workshop_id: row.1,
            state: row.2,
            safe_error: row.3,
            started_at: api_timestamp(row.4),
            finished_at: row.5.map(api_timestamp),
        }),
        workers: workers
            .into_iter()
            .map(|row| WorkerStatusResponse {
                worker_id: row.0,
                queue: row.1,
                release_id: row.2,
                started_at: api_timestamp(row.3),
                last_heartbeat_at: api_timestamp(row.4),
                active_operation_id: row.5,
                shutdown_at: row.6.map(api_timestamp),
                fresh: row.7,
            })
            .collect(),
    }))
}

pub(super) async fn platform_releases(
    State(state): State<Arc<AppState>>,
    Extension(_scope): Extension<PlatformScope>,
) -> ApiResult<Json<Vec<ApplicationReleaseResponse>>> {
    let rows = sqlx::query_as::<_, (String,String,String,String,String,String,String,i64,OffsetDateTime,OffsetDateTime)>(
        "select id,status,source_commit,odoo_subject_digest,extension_subject_digest,change_class,odoo_version,version,published_at,updated_at
         from control.application_releases order by published_at desc,id desc",
    )
    .fetch_all(state.store.pool())
    .await?;
    Ok(Json(
        rows.into_iter()
            .map(|row| ApplicationReleaseResponse {
                id: row.0,
                status: row.1,
                source_commit: row.2,
                odoo_subject_digest: row.3,
                extension_subject_digest: row.4,
                change_class: row.5,
                odoo_version: row.6,
                version: row.7,
                published_at: api_timestamp(row.8),
                updated_at: api_timestamp(row.9),
            })
            .collect(),
    ))
}

pub(super) async fn publish_release(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(manifest_value): Json<Value>,
) -> ApiResult<(StatusCode, HeaderMap, Json<Value>)> {
    release_publisher(&state, &headers)?;
    let key = idempotency(&headers)?.to_owned();
    let manifest: crate::release::ApplicationReleaseManifest =
        serde_json::from_value(manifest_value)
            .map_err(|_| ApiError::Validation("application release manifest is invalid"))?;
    manifest
        .validate()
        .map_err(|_| ApiError::Validation("application release manifest is invalid"))?;
    let registry_version = i32::try_from(manifest.capability_registry_version)
        .map_err(|_| ApiError::Validation("capability registry version is too large"))?;
    let registry_modules = sqlx::query_scalar::<_, Vec<String>>(
        "select odoo_modules from control.capability_registry_entries
         where registry_version=$1 order by capability_key",
    )
    .bind(registry_version)
    .fetch_all(state.store.pool())
    .await?;
    if registry_modules.is_empty() {
        return Err(ApiError::Validation(
            "application release names an unknown capability registry version",
        ));
    }
    if registry_modules
        .iter()
        .flatten()
        .any(|module| !manifest.addons.contains_key(module))
    {
        return Err(ApiError::Validation(
            "application release does not contain every registry Odoo module",
        ));
    }
    let canonical =
        serde_jcs::to_vec(&manifest).map_err(|error| ApiError::Internal(error.into()))?;
    let manifest_digest = format!("sha256:{:x}", sha2::Sha256::digest(&canonical));
    let semantic =
        serde_json::to_value(&manifest).map_err(|error| ApiError::Internal(error.into()))?;
    let request_digest = crate::command::request_digest(&semantic);
    let published_at = OffsetDateTime::parse(&manifest.built_at, &Rfc3339)
        .map_err(|_| ApiError::Validation("built_at must be an RFC 3339 timestamp"))?;
    let change_class = match manifest.change_class {
        crate::release::ChangeClass::A => "A",
        crate::release::ChangeClass::B => "B",
        crate::release::ChangeClass::C => "C",
    };
    let compatibility = json!({"upgradeable_from":&manifest.upgradeable_from,"database_runtime_compatibility":&manifest.database_runtime_compatibility});
    let postconditions = serde_json::to_value(&manifest.required_postconditions)
        .map_err(|error| ApiError::Internal(error.into()))?;
    let addons =
        serde_json::to_value(&manifest.addons).map_err(|error| ApiError::Internal(error.into()))?;
    let mut tx = state.store.begin().await?;
    let inserted = sqlx::query(
        "insert into control.application_releases(
        id,source_commit,odoo_version,odoo_subject_digest,extension_subject_digest,
        odoo_runtime,extension_bundle,pair_qualifications,manifest_digest,addon_versions,
        compatibility,bridge_contract,schema_epoch,change_class,required_postconditions,
        manifest,signature_bundle_ref,extension_signature_ref,sbom_ref,published_at,
        publication_idempotency_key,publication_request_digest
      ) values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22)
      on conflict do nothing",
    )
    .bind(&manifest.release_id)
    .bind(&manifest.source_commit)
    .bind(&manifest.odoo_runtime.version)
    .bind(&manifest.odoo_runtime.subject_digest)
    .bind(&manifest.extension_bundle.subject_digest)
    .bind(
        serde_json::to_value(&manifest.odoo_runtime)
            .map_err(|error| ApiError::Internal(error.into()))?,
    )
    .bind(
        serde_json::to_value(&manifest.extension_bundle)
            .map_err(|error| ApiError::Internal(error.into()))?,
    )
    .bind(
        serde_json::to_value(&manifest.pair_qualifications)
            .map_err(|error| ApiError::Internal(error.into()))?,
    )
    .bind(&manifest_digest)
    .bind(addons)
    .bind(compatibility)
    .bind(&manifest.bridge_contract)
    .bind(
        i64::try_from(manifest.schema_epoch)
            .map_err(|_| ApiError::Validation("schema_epoch is too large"))?,
    )
    .bind(change_class)
    .bind(postconditions)
    .bind(&semantic)
    .bind(&manifest.admission_signature.reference)
    .bind(&manifest.extension_bundle.platforms[0].signature.reference)
    .bind(&manifest.odoo_runtime.platforms[0].evidence.sbom.reference)
    .bind(published_at)
    .bind(&key)
    .bind(request_digest.as_slice())
    .execute(&mut *tx)
    .await?
    .rows_affected()
        == 1;
    let stored=sqlx::query_as::<_,(String,Vec<u8>,i64,String)>("select id,publication_request_digest,version,status from control.application_releases where id=$1 or publication_idempotency_key=$2 for update")
        .bind(&manifest.release_id).bind(&key).fetch_all(&mut *tx).await?;
    if stored.len() != 1
        || stored[0].0 != manifest.release_id
        || stored[0].1.as_slice() != request_digest
    {
        return Err(ApiError::Conflict(
            "release identity or idempotency key was already used for another manifest",
        ));
    }
    let correlation = Uuid::new_v4();
    if inserted {
        audit(
            &mut tx,
            None,
            None,
            "release.publish",
            "application_release",
            manifest.release_id.clone(),
            correlation,
        )
        .await?;
    }
    tx.commit().await?;
    let response = json!({"id":manifest.release_id,"manifest_digest":manifest_digest,"status":stored[0].3,"version":stored[0].2,"replayed":!inserted});
    Ok((
        if inserted {
            StatusCode::CREATED
        } else {
            StatusCode::OK
        },
        etag(&format!("release-{}", manifest.release_id), stored[0].2)?,
        Json(response),
    ))
}

pub(super) async fn platform_release(
    State(state): State<Arc<AppState>>,
    Extension(_scope): Extension<PlatformScope>,
    Path(id): Path<String>,
) -> ApiResult<(HeaderMap, Json<ApplicationReleaseDetailResponse>)> {
    let row = sqlx::query_as::<
        _,
        (
            String,
            String,
            String,
            String,
            String,
            String,
            String,
            Value,
            Value,
            String,
            i64,
            Value,
            Value,
            i64,
            OffsetDateTime,
            OffsetDateTime,
        ),
    >(
        "select id,status,source_commit,odoo_subject_digest,extension_subject_digest,manifest_digest,change_class,
                addon_versions,compatibility,bridge_contract,schema_epoch,
                required_postconditions,manifest,version,published_at,updated_at
         from control.application_releases where id=$1",
    )
    .bind(&id)
    .fetch_optional(state.store.pool())
    .await?
    .ok_or(ApiError::NotFound)?;
    let slots = sqlx::query_as::<_, (String, String, String, String, String, String, String, String, i64, Value)>(
        "select runtime_key,slot,release_id,state,odoo_subject_digest,extension_subject_digest,extension_volume,pair_qualification_digest,version,evidence
         from control.runtime_release_slots where release_id=$1 order by runtime_key,slot",
    )
    .bind(&id)
    .fetch_all(state.store.pool())
    .await?;
    let version = row.13;
    Ok((
        etag(&format!("release-{id}"), version)?,
        Json(ApplicationReleaseDetailResponse {
            id: row.0,
            status: row.1,
            source_commit: row.2,
            odoo_subject_digest: row.3,
            extension_subject_digest: row.4,
            manifest_digest: row.5,
            change_class: row.6,
            addon_versions: row.7,
            compatibility: row.8,
            bridge_contract: row.9,
            schema_epoch: row.10,
            required_postconditions: row.11,
            manifest: row.12,
            version,
            published_at: api_timestamp(row.14),
            updated_at: api_timestamp(row.15),
            runtime_slots: slots
                .into_iter()
                .map(|slot| RuntimeReleaseSlotResponse {
                    runtime_key: slot.0,
                    slot: slot.1,
                    release_id: slot.2,
                    state: slot.3,
                    odoo_subject_digest: slot.4,
                    extension_subject_digest: slot.5,
                    extension_volume: slot.6,
                    pair_qualification_digest: slot.7,
                    version: slot.8,
                    evidence: slot.9,
                })
                .collect(),
        }),
    ))
}

pub(super) async fn platform_release_tenants(
    State(state): State<Arc<AppState>>,
    Extension(_scope): Extension<PlatformScope>,
    Path(id): Path<String>,
) -> ApiResult<Json<Vec<TenantReleaseAdoptionResponse>>> {
    let exists = sqlx::query_scalar::<_, bool>(
        "select exists(select 1 from control.application_releases where id=$1)",
    )
    .bind(&id)
    .fetch_one(state.store.pool())
    .await?;
    if !exists {
        return Err(ApiError::NotFound);
    }
    let rows = sqlx::query_as::<_, (Uuid,String,Uuid,String,Option<String>,String,Option<Uuid>,Option<Uuid>,Option<String>,Value,i64,OffsetDateTime)>(
        "select a.workshop_id,w.display_name,a.database_id,a.release_id,a.source_release_id,
                a.state,a.operation_id,a.backup_recovery_id,a.failure_class,a.evidence,a.version,a.updated_at
         from control.tenant_release_adoptions a join control.workshops w on w.id=a.workshop_id
         where a.release_id=$1 order by w.created_at,w.id",
    ).bind(&id).fetch_all(state.store.pool()).await?;
    Ok(Json(
        rows.into_iter()
            .map(|row| TenantReleaseAdoptionResponse {
                workshop_id: row.0,
                workshop_name: row.1,
                database_id: row.2,
                release_id: row.3,
                source_release_id: row.4,
                state: row.5,
                operation_id: row.6,
                backup_recovery_id: row.7,
                failure_class: row.8,
                evidence: row.9,
                version: row.10,
                updated_at: api_timestamp(row.11),
            })
            .collect(),
    ))
}

pub(super) async fn platform_release_preflight(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Extension(scope): Extension<PlatformScope>,
    Path(id): Path<String>,
) -> ApiResult<(StatusCode, HeaderMap, Json<Value>)> {
    let who = scope.principal();
    let key = idempotency(&headers)?.to_owned();
    let resource = format!("release-{id}");
    let expected = expected_version(&headers, &resource)?;
    let semantic = json!({"release_id":id,"phase":"preflight"});
    let correlation = Uuid::new_v4();
    let mut tx = state.store.begin().await?;
    revalidate_platform_scope(&mut tx, &scope).await?;
    let command_id = match admit_command(
        &mut tx,
        NewCommand {
            actor_user_id: who.user_id,
            scope: &format!("platform:release:{id}"),
            command_kind: "release.preflight",
            idempotency_key: &key,
            semantic_request: &semantic,
            expected_version: Some(expected),
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
            let response = response_body.unwrap_or_else(|| json!({"replayed":true}));
            let version = response["version"].as_i64().unwrap_or(expected);
            tx.commit().await?;
            return Ok((
                StatusCode::from_u16(response_status).unwrap_or(StatusCode::ACCEPTED),
                etag(&resource, version)?,
                Json(response),
            ));
        }
        CommandAdmission::InProgress {
            command_id,
            operation_id,
        } => {
            tx.commit().await?;
            return Ok((
                StatusCode::ACCEPTED,
                etag(&resource, expected)?,
                Json(
                    json!({"command_id":command_id,"operation_id":operation_id,"in_progress":true}),
                ),
            ));
        }
    };
    let release = sqlx::query_as::<_, (String, i64)>(
        "select status,version from control.application_releases where id=$1 for update",
    )
    .bind(&id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(ApiError::NotFound)?;
    if release.1 != expected {
        return Err(ApiError::PreconditionFailed("If-Match is stale"));
    }
    if release.0 != "candidate" {
        return Err(ApiError::Conflict(
            "only a candidate release can be preflighted",
        ));
    }
    let operation_id = Store::enqueue(
        &mut tx,
        NewOperation {
            kind: OperationKind::OdooReleaseAdopt,
            workshop_id: None,
            target_user_id: None,
            desired_epoch: None,
            payload: &semantic,
            requested_by: Some(who.user_id),
            correlation_id: correlation,
            idempotency_key: &format!("command:{command_id}"),
        },
    )
    .await?;
    let changed=sqlx::query("update control.application_releases set status='preflighting',version=version+1 where id=$1 and version=$2 and status='candidate'")
        .bind(&id).bind(expected).execute(&mut *tx).await?.rows_affected();
    if changed != 1 {
        return Err(ApiError::PreconditionFailed("If-Match is stale"));
    }
    let version = expected + 1;
    audit_command(
        &mut tx,
        (Some(who.user_id), None),
        "release.preflight",
        "application_release",
        id.clone(),
        correlation,
        command_id,
    )
    .await?;
    let response = json!({"operation_id":operation_id,"status":"preflighting","version":version});
    complete_command(
        &mut tx,
        command_id,
        CommandResult {
            operation_id: Some(operation_id),
            response_status: StatusCode::ACCEPTED.as_u16(),
            response_body: Some(&response),
            result_ref: Some(&id),
        },
    )
    .await
    .map_err(command_error)?;
    tx.commit().await?;
    Ok((
        StatusCode::ACCEPTED,
        etag(&resource, version)?,
        Json(response),
    ))
}

#[derive(Deserialize, ToSchema)]
pub(crate) struct AdoptReleaseBody {
    confirmation: String,
}

pub(super) async fn platform_release_adopt(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Extension(scope): Extension<PlatformScope>,
    Path(id): Path<String>,
    Json(body): Json<AdoptReleaseBody>,
) -> ApiResult<(StatusCode, HeaderMap, Json<Value>)> {
    let who = scope.principal();
    require_step_up(who)?;
    if body.confirmation != id {
        return Err(ApiError::Validation(
            "confirmation must exactly match the release id",
        ));
    }
    let key = idempotency(&headers)?.to_owned();
    let resource = format!("release-{id}");
    let expected = expected_version(&headers, &resource)?;
    let semantic = json!({"release_id":id,"phase":"adopt","confirmation":body.confirmation});
    let correlation = Uuid::new_v4();
    let operation_id = Uuid::new_v4();
    let fleet_run_id = Uuid::new_v4();
    let mut tx = state.store.begin().await?;
    revalidate_platform_scope(&mut tx, &scope).await?;
    let command_id = match admit_command(
        &mut tx,
        NewCommand {
            actor_user_id: who.user_id,
            scope: &format!("platform:release:{id}"),
            command_kind: "release.adopt",
            idempotency_key: &key,
            semantic_request: &semantic,
            expected_version: Some(expected),
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
            let response = response_body.unwrap_or_else(|| json!({"replayed":true}));
            tx.commit().await?;
            return Ok((
                StatusCode::from_u16(response_status).unwrap_or(StatusCode::ACCEPTED),
                etag(&resource, expected)?,
                Json(response),
            ));
        }
        CommandAdmission::InProgress {
            command_id,
            operation_id,
        } => {
            tx.commit().await?;
            return Ok((
                StatusCode::ACCEPTED,
                etag(&resource, expected)?,
                Json(
                    json!({"command_id":command_id,"operation_id":operation_id,"in_progress":true}),
                ),
            ));
        }
    };
    let release=sqlx::query_as::<_,(String,i64,i64,i32)>("select status,version,schema_epoch,(manifest->>'capability_registry_version')::integer from control.application_releases where id=$1 for update")
        .bind(&id).fetch_optional(&mut *tx).await?.ok_or(ApiError::NotFound)?;
    if release.1 != expected {
        return Err(ApiError::PreconditionFailed("If-Match is stale"));
    }
    if release.0 != "prepared" {
        return Err(ApiError::Conflict(
            "release preflight must be prepared before adoption",
        ));
    }
    let tenants=sqlx::query_as::<_,(Uuid,Uuid,String,bool)>("select w.id,d.id,d.database_ref,exists(select 1 from control.workshop_modules m where m.workshop_id=w.id and m.module_key='documents' and m.state='enabled') from control.workshops w join control.odoo_databases d on d.workshop_id=w.id where w.status<>'deleted' and d.kind='primary' and d.deleted_at is null order by w.created_at,w.id limit $1 for share of w,d")
        .bind(i64::try_from(crate::release::MAX_FLEET_TENANTS + 1).map_err(|error|ApiError::Internal(error.into()))?)
        .fetch_all(&mut *tx).await?;
    if tenants.len() > crate::release::MAX_FLEET_TENANTS {
        return Err(ApiError::Conflict(
            "fleet release exceeds the bounded tenant snapshot; chunked adoption is required",
        ));
    }
    if tenants.is_empty() {
        let activation = crate::persistence::activate_initial_release(&mut tx, &id)
            .await
            .map_err(|error| match error {
                crate::persistence::InitialReleaseActivationError::Conflict(message) => {
                    ApiError::Conflict(message)
                }
                crate::persistence::InitialReleaseActivationError::Database(error) => {
                    ApiError::from(error)
                }
            })?;
        audit_command(
            &mut tx,
            (Some(who.user_id), None),
            "release.activate_initial",
            "application_release",
            id.clone(),
            correlation,
            command_id,
        )
        .await?;
        let response = json!({
            "release_id":id,
            "runtime_key":"shared-odoo",
            "slot":activation.slot,
            "tenant_count":0,
            "status":"active",
            "version":activation.version,
        });
        complete_command(
            &mut tx,
            command_id,
            CommandResult {
                operation_id: None,
                response_status: StatusCode::OK.as_u16(),
                response_body: Some(&response),
                result_ref: Some(&id),
            },
        )
        .await
        .map_err(command_error)?;
        tx.commit().await?;
        return Ok((
            StatusCode::OK,
            etag(&resource, activation.version)?,
            Json(response),
        ));
    }
    for tenant in &tenants {
        lock_lifecycle(&mut tx, tenant.0).await?;
        ensure_lifecycle_idle(&mut tx, tenant.0).await?;
        let module_change=sqlx::query_scalar::<_,bool>("select exists(select 1 from control.workshop_modules where workshop_id=$1 and state='requested')")
            .bind(tenant.0).fetch_one(&mut *tx).await?;
        if module_change {
            return Err(ApiError::Conflict(
                "a capability activation is already running for a fleet tenant",
            ));
        }
    }
    sqlx::query("insert into control.operations(id,kind,queue,payload,requested_by,correlation_id,idempotency_key) values($1,'odoo.release.adopt','release-adoption',$2,$3,$4,$5)")
        .bind(operation_id).bind(&semantic).bind(who.user_id).bind(correlation).bind(format!("command:{command_id}")).execute(&mut *tx).await?;
    let generation = sqlx::query_scalar::<_, i64>(
        "select coalesce(max(fleet_generation),0)+1 from control.release_fleet_runs",
    )
    .fetch_one(&mut *tx)
    .await?;
    let mut snapshot_tenants = tenants.iter().collect::<Vec<_>>();
    snapshot_tenants.sort_by_key(|tenant| (tenant.0, tenant.1));
    let snapshot = snapshot_tenants
        .into_iter()
        .map(|tenant|json!({"workshop_id":tenant.0,"database_id":tenant.1,"database_ref":tenant.2,"paperless_enabled":tenant.3}))
        .collect::<Vec<_>>();
    let snapshot = Value::Array(snapshot);
    sqlx::query("insert into control.release_fleet_runs(id,release_id,operation_id,fleet_generation,state,tenant_snapshot,canary_workshop_id) values($1,$2,$3,$4,'preparing',$5,$6)")
        .bind(fleet_run_id).bind(&id).bind(operation_id).bind(generation).bind(&snapshot).bind(tenants[0].0).execute(&mut *tx).await?;
    for tenant in &tenants {
        let adoption_id = Uuid::new_v4();
        let recovery_id = Uuid::new_v4();
        let source=sqlx::query_scalar::<_,String>("select release_id from control.tenant_release_adoptions where workshop_id=$1 and database_id=$2 and state='active'")
            .bind(tenant.0).bind(tenant.1).fetch_optional(&mut *tx).await?;
        let component_scope = if tenant.3 {
            vec!["odoo", "paperless"]
        } else {
            vec!["odoo"]
        };
        sqlx::query("insert into control.workshop_recovery_points(id,workshop_id,database_id,operation_id,kind,label,requested_by,component_scope,format_version,source_release) values($1,$2,$3,$4,'backup',$5,$6,$7,'mb-workshop-recovery-v2',$8)")
            .bind(recovery_id).bind(tenant.0).bind(tenant.1).bind(operation_id).bind(format!("Pre-release recovery for {id}")).bind(who.user_id).bind(&component_scope).bind(&source).execute(&mut *tx).await?;
        sqlx::query("insert into control.tenant_release_adoptions(id,workshop_id,database_id,release_id,source_release_id,registry_version,state,operation_id,backup_recovery_id,target_schema_epoch) values($1,$2,$3,$4,$5,$6,'pending',$7,$8,$9)")
            .bind(adoption_id).bind(tenant.0).bind(tenant.1).bind(&id).bind(source).bind(release.3).bind(operation_id).bind(recovery_id).bind(release.2).execute(&mut *tx).await?;
    }
    audit_command(
        &mut tx,
        (Some(who.user_id), None),
        "release.adopt",
        "application_release",
        id.clone(),
        correlation,
        command_id,
    )
    .await?;
    let response = json!({"operation_id":operation_id,"fleet_run_id":fleet_run_id,"tenant_count":tenants.len(),"status":"prepared","version":expected});
    complete_command(
        &mut tx,
        command_id,
        CommandResult {
            operation_id: Some(operation_id),
            response_status: StatusCode::ACCEPTED.as_u16(),
            response_body: Some(&response),
            result_ref: Some(&id),
        },
    )
    .await
    .map_err(command_error)?;
    tx.commit().await?;
    Ok((
        StatusCode::ACCEPTED,
        etag(&resource, expected)?,
        Json(response),
    ))
}

pub(super) async fn platform_release_retry_failed(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Extension(_scope): Extension<PlatformScope>,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let _ = idempotency(&headers)?;
    let resource = format!("release-{id}");
    let _ = expected_version(&headers, &resource)?;
    let failed=sqlx::query_scalar::<_,i64>("select count(*) from control.tenant_release_adoptions where release_id=$1 and state='failed'").bind(&id).fetch_one(state.store.pool()).await?;
    if failed == 0 {
        return Err(ApiError::Conflict("release has no failed tenant adoptions"));
    }
    Err(ApiError::Conflict(
        "failed tenants must be restored or explicitly forward-repaired before retry",
    ))
}

pub(super) async fn platform_email_deliveries(
    State(state): State<Arc<AppState>>,
    Extension(_scope): Extension<PlatformScope>,
) -> ApiResult<Json<Vec<EmailDeliveryResponse>>> {
    let rows = sqlx::query_as::<_, (Uuid,String,String,String,i32,OffsetDateTime,OffsetDateTime,Option<OffsetDateTime>)>(
        "select id,recipient,template,state,attempts,next_attempt_at,created_at,sent_at from control.outbox order by created_at desc,id desc limit 200",
    ).fetch_all(state.store.pool()).await?;
    Ok(Json(
        rows.into_iter()
            .map(|row| EmailDeliveryResponse {
                id: row.0,
                recipient: row.1,
                template: row.2,
                state: row.3,
                attempts: row.4,
                next_attempt_at: api_timestamp(row.5),
                created_at: api_timestamp(row.6),
                sent_at: row.7.map(api_timestamp),
            })
            .collect(),
    ))
}

#[derive(Deserialize)]
pub(super) struct PlatformAuditQuery {
    limit: Option<i64>,
}

pub(super) async fn platform_audit_events(
    State(state): State<Arc<AppState>>,
    Extension(_scope): Extension<PlatformScope>,
    Query(query): Query<PlatformAuditQuery>,
) -> ApiResult<Json<Vec<AuditEventResponse>>> {
    let rows = sqlx::query_as::<_, (Uuid,Option<String>,Option<Uuid>,Option<String>,String,Option<String>,Option<String>,Uuid,String,Value,OffsetDateTime)>(
        "select a.id,u.email,a.workshop_id,w.display_name,a.action,a.target_type,a.target_id,a.correlation_id,a.outcome,a.detail,a.created_at from control.audit_events a left join control.users u on u.audit_subject_id=a.actor_audit_subject_id left join control.workshops w on w.id=a.workshop_id order by a.created_at desc,a.id desc limit $1",
    ).bind(query.limit.unwrap_or(100).clamp(1,200)).fetch_all(state.store.pool()).await?;
    Ok(Json(
        rows.into_iter()
            .map(|row| AuditEventResponse {
                id: row.0,
                actor_email: row.1,
                workshop_id: row.2,
                workshop_name: row.3,
                action: row.4,
                target_type: row.5,
                target_id: row.6,
                correlation_id: row.7,
                outcome: row.8,
                detail: row.9,
                created_at: api_timestamp(row.10),
            })
            .collect(),
    ))
}
