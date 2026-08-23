use super::*;

pub(super) async fn platform_roles_list(
    State(state): State<Arc<AppState>>,
    Extension(_scope): Extension<PlatformScope>,
) -> ApiResult<Json<Vec<PlatformRoleResponse>>> {
    let rows = sqlx::query_as::<_, (Uuid,Uuid,String,String,Option<String>,String,OffsetDateTime,Option<OffsetDateTime>,Option<String>,i64)>(
        "select r.id,r.user_id,u.email,r.role,g.email,r.grant_reason_code,r.granted_at,r.revoked_at,r.revoke_reason_code,r.version from control.platform_role_assignments r join control.users u on u.id=r.user_id left join control.users g on g.id=r.granted_by order by r.granted_at desc,r.id",
    )
    .fetch_all(state.store.pool())
    .await?;
    Ok(Json(
        rows.into_iter()
            .map(|row| PlatformRoleResponse {
                id: row.0,
                user_id: row.1,
                email: row.2,
                role: row.3,
                granted_by_email: row.4,
                grant_reason_code: row.5,
                granted_at: api_timestamp(row.6),
                revoked_at: row.7.map(api_timestamp),
                revoke_reason_code: row.8,
                version: row.9,
                etag: format!("\"platform-role-{}-v{}\"", row.0, row.9),
            })
            .collect(),
    ))
}

#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct PlatformRoleGrant {
    user_id: Uuid,
    role: String,
    reason_code: String,
}

pub(super) async fn platform_role_grant(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Extension(scope): Extension<PlatformScope>,
    Json(body): Json<PlatformRoleGrant>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let who = scope.principal();
    require_step_up(who)?;
    if !matches!(
        body.role.as_str(),
        "technical_admin"
            | "release_operator"
            | "privacy_reviewer"
            | "security_responder"
            | "auditor"
    ) {
        return Err(ApiError::Validation("unknown platform role"));
    }
    if body.reason_code.trim().is_empty() || body.reason_code.len() > 100 {
        return Err(ApiError::Validation("a bounded reason_code is required"));
    }
    let key = idempotency(&headers)?.to_owned();
    let semantic = json!({"user_id":body.user_id,"role":body.role,"reason_code":body.reason_code});
    let correlation = Uuid::new_v4();
    let assignment_id = Uuid::new_v4();
    let mut tx = state.store.begin().await?;
    revalidate_platform_scope(&mut tx, &scope).await?;
    let command_id = match admit_command(
        &mut tx,
        NewCommand {
            actor_user_id: who.user_id,
            scope: "platform:roles",
            command_kind: "platform.role.grant",
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
                StatusCode::from_u16(response_status).unwrap_or(StatusCode::CREATED),
                Json(response_body.unwrap_or_else(|| json!({"replayed":true}))),
            ));
        }
        CommandAdmission::InProgress { command_id, .. } => {
            tx.commit().await?;
            return Ok((
                StatusCode::ACCEPTED,
                Json(json!({"command_id":command_id,"in_progress":true})),
            ));
        }
    };
    let exists = sqlx::query_scalar::<_, bool>(
        "select exists(select 1 from control.platform_role_assignments where user_id=$1 and role=$2 and revoked_at is null)",
    )
    .bind(body.user_id)
    .bind(&body.role)
    .fetch_one(&mut *tx)
    .await?;
    if exists {
        return Err(ApiError::Conflict("this active role is already assigned"));
    }
    sqlx::query("insert into control.platform_role_assignments(id,user_id,role,granted_by,grant_reason_code) values($1,$2,$3,$4,$5)")
        .bind(assignment_id)
        .bind(body.user_id)
        .bind(&body.role)
        .bind(who.user_id)
        .bind(&body.reason_code)
        .execute(&mut *tx)
        .await?;
    audit_command(
        &mut tx,
        (Some(who.user_id), None),
        "platform.role.grant",
        "platform_role_assignment",
        assignment_id.to_string(),
        correlation,
        command_id,
    )
    .await?;
    let response = json!({"id":assignment_id,"user_id":body.user_id,"role":body.role,"version":1});
    let result_ref = assignment_id.to_string();
    complete_command(
        &mut tx,
        command_id,
        CommandResult {
            operation_id: None,
            response_status: StatusCode::CREATED.as_u16(),
            response_body: Some(&response),
            result_ref: Some(&result_ref),
        },
    )
    .await
    .map_err(command_error)?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(response)))
}

#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct PlatformRoleRevoke {
    reason_code: String,
}

pub(super) async fn platform_role_revoke(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Extension(scope): Extension<PlatformScope>,
    Path(id): Path<Uuid>,
    Json(body): Json<PlatformRoleRevoke>,
) -> ApiResult<(HeaderMap, Json<Value>)> {
    let who = scope.principal();
    require_step_up(who)?;
    if body.reason_code.trim().is_empty() || body.reason_code.len() > 100 {
        return Err(ApiError::Validation("a bounded reason_code is required"));
    }
    let resource = format!("platform-role-{id}");
    let expected = expected_version(&headers, &resource)?;
    let key = idempotency(&headers)?.to_owned();
    let semantic = json!({"reason_code":body.reason_code});
    let correlation = Uuid::new_v4();
    let mut tx = state.store.begin().await?;
    revalidate_platform_scope(&mut tx, &scope).await?;
    let command_id = match admit_command(
        &mut tx,
        NewCommand {
            actor_user_id: who.user_id,
            scope: &format!("platform:role:{id}"),
            command_kind: "platform.role.revoke",
            idempotency_key: &key,
            semantic_request: &semantic,
            expected_version: Some(expected),
        },
    )
    .await
    .map_err(command_error)?
    {
        CommandAdmission::New { command_id } => command_id,
        CommandAdmission::Replay { response_body, .. } => {
            let response = response_body.unwrap_or_else(|| json!({"replayed":true}));
            let version = response["version"].as_i64().unwrap_or(expected);
            tx.commit().await?;
            return Ok((etag(&resource, version)?, Json(response)));
        }
        CommandAdmission::InProgress { command_id, .. } => {
            tx.commit().await?;
            return Ok((
                etag(&resource, expected)?,
                Json(json!({"command_id":command_id,"in_progress":true})),
            ));
        }
    };
    let changed=sqlx::query("update control.platform_role_assignments set revoked_at=now(),revoked_by=$2,revoke_reason_code=$3,version=version+1 where id=$1 and revoked_at is null and version=$4")
        .bind(id).bind(who.user_id).bind(&body.reason_code).bind(expected).execute(&mut *tx).await?.rows_affected();
    if changed != 1 {
        return Err(ApiError::PreconditionFailed(
            "If-Match is stale or role is already revoked",
        ));
    }
    audit_command(
        &mut tx,
        (Some(who.user_id), None),
        "platform.role.revoke",
        "platform_role_assignment",
        id.to_string(),
        correlation,
        command_id,
    )
    .await?;
    let response = json!({"id":id,"revoked":true,"version":expected+1});
    let result_ref = id.to_string();
    complete_command(
        &mut tx,
        command_id,
        CommandResult {
            operation_id: None,
            response_status: StatusCode::OK.as_u16(),
            response_body: Some(&response),
            result_ref: Some(&result_ref),
        },
    )
    .await
    .map_err(command_error)?;
    tx.commit().await?;
    Ok((etag(&resource, expected + 1)?, Json(response)))
}

#[cfg(test)]
mod tests {
    #[test]
    fn privacy_scope_and_export_effect_boundaries_are_explicit() {
        let source = include_str!("governance.rs");
        let create = source
            .rsplit_once("pub(super) async fn create_privacy_request(")
            .unwrap()
            .1
            .split("pub(super) async fn privacy_requests(")
            .next()
            .unwrap();
        assert!(create.contains("state.tenant_store.begin(*workshop)"));
        assert!(create.contains("workshop_id=$1 and user_id=$2 and status='active'"));

        let consume = source
            .rsplit_once("pub(super) async fn consume_privacy_export(")
            .unwrap()
            .1
            .split("pub(super) async fn platform_privacy_request_decision(")
            .next()
            .unwrap();
        let consumed = consume.find("consume_data_subject_export").unwrap();
        let commit = consume.find("tx.commit()").unwrap();
        let file_read = consume.find("read_export_artifact").unwrap();
        let decrypt = consume.find("decrypt_export_with_key_id").unwrap();
        assert!(consumed < commit && commit < file_read && file_read < decrypt);
    }
}

#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct CreatePrivacyRequest {
    request_type: String,
    workshop_ids: Option<Vec<Uuid>>,
}

pub(super) async fn create_privacy_request(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Extension(who): Extension<Principal>,
    Json(body): Json<CreatePrivacyRequest>,
) -> ApiResult<(StatusCode, HeaderMap, Json<Value>)> {
    if !matches!(
        body.request_type.as_str(),
        "access" | "rectification" | "erasure" | "restriction" | "portability" | "objection"
    ) {
        return Err(ApiError::Validation("unknown data-subject request type"));
    }
    let workshops = body.workshop_ids.unwrap_or_default();
    if workshops.len() > 50 {
        return Err(ApiError::Validation("too many workshop scopes"));
    }
    let unique = workshops
        .iter()
        .copied()
        .collect::<std::collections::HashSet<_>>();
    if unique.len() != workshops.len() {
        return Err(ApiError::Validation("workshop scopes must be unique"));
    }
    if !workshops.is_empty() {
        for workshop in &workshops {
            let mut tx = state.tenant_store.begin(*workshop).await?;
            let authorized = sqlx::query_scalar::<_, bool>(
                "select exists(select 1 from control.memberships
                 where workshop_id=$1 and user_id=$2 and status='active')",
            )
            .bind(workshop)
            .bind(who.user_id)
            .fetch_one(&mut *tx)
            .await?;
            tx.commit().await?;
            if !authorized {
                return Err(ApiError::Forbidden);
            }
        }
    }
    let client_key = idempotency(&headers)?.to_owned();
    let request_id = Uuid::new_v4();
    let semantic = json!({"request_type":body.request_type,"workshop_ids":workshops});
    let correlation = Uuid::new_v4();
    let mut tx = state.store.begin().await?;
    let command_id = match admit_command(
        &mut tx,
        NewCommand {
            actor_user_id: who.user_id,
            scope: &format!("privacy:subject:{}", who.user_id),
            command_kind: "privacy.request.create",
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
            let response = response_body.unwrap_or_else(|| json!({"replayed":true}));
            let version = response["version"].as_i64().unwrap_or(1);
            tx.commit().await?;
            return Ok((
                StatusCode::from_u16(response_status).unwrap_or(StatusCode::CREATED),
                etag(
                    &format!(
                        "privacy-request-{}",
                        response["id"].as_str().unwrap_or("unknown")
                    ),
                    version,
                )?,
                Json(response),
            ));
        }
        CommandAdmission::InProgress { command_id, .. } => {
            tx.commit().await?;
            return Ok((
                StatusCode::ACCEPTED,
                HeaderMap::new(),
                Json(json!({"command_id":command_id,"in_progress":true})),
            ));
        }
    };
    sqlx::query("insert into control.data_subject_requests(id,subject_user_id,request_type,scope) values($1,$2,$3,$4)")
        .bind(request_id).bind(who.user_id).bind(&body.request_type).bind(&semantic).execute(&mut *tx).await?;
    if body.request_type == "restriction" {
        if workshops.is_empty() {
            sqlx::query("insert into control.processing_holds(id,data_subject_request_id,subject_user_id) values($1,$2,$3)").bind(Uuid::new_v4()).bind(request_id).bind(who.user_id).execute(&mut *tx).await?;
        } else {
            for workshop in &workshops {
                sqlx::query("insert into control.processing_holds(id,data_subject_request_id,subject_user_id,workshop_id) values($1,$2,$3,$4)").bind(Uuid::new_v4()).bind(request_id).bind(who.user_id).bind(workshop).execute(&mut *tx).await?;
            }
        }
    }
    audit_command(
        &mut tx,
        (Some(who.user_id), None),
        "privacy.request.create",
        "data_subject_request",
        request_id.to_string(),
        correlation,
        command_id,
    )
    .await?;
    let response =
        json!({"id":request_id,"request_type":body.request_type,"status":"received","version":1});
    complete_command(
        &mut tx,
        command_id,
        CommandResult {
            operation_id: None,
            response_status: StatusCode::CREATED.as_u16(),
            response_body: Some(&response),
            result_ref: Some(&request_id.to_string()),
        },
    )
    .await
    .map_err(command_error)?;
    tx.commit().await?;
    Ok((
        StatusCode::CREATED,
        etag(&format!("privacy-request-{request_id}"), 1)?,
        Json(response),
    ))
}

pub(super) async fn privacy_requests(
    State(state): State<Arc<AppState>>,
    Extension(who): Extension<Principal>,
) -> ApiResult<Json<Vec<PrivacyRequestResponse>>> {
    Ok(Json(privacy_request_rows(&state, Some(who.user_id)).await?))
}

pub(super) async fn platform_privacy_requests(
    State(state): State<Arc<AppState>>,
    Extension(_scope): Extension<PlatformScope>,
) -> ApiResult<Json<Vec<PrivacyRequestResponse>>> {
    Ok(Json(privacy_request_rows(&state, None).await?))
}

pub(super) async fn platform_privacy_overview(
    State(state): State<Arc<AppState>>,
    Extension(_scope): Extension<PlatformScope>,
) -> ApiResult<Json<PrivacyOverviewResponse>> {
    let platform = sqlx::query_as::<_, (Option<String>,Option<String>,bool,Option<i32>,Option<i32>,Option<String>,i64,OffsetDateTime)>(
        "select controller_ref,dpo_ref,production_personal_data_allowed,approved_retention_policy_version,approved_processing_register_version,dpia_approval_ref,version,updated_at from control.privacy_platform_state where singleton",
    )
    .fetch_one(state.store.pool())
    .await?;
    let policies = sqlx::query_as::<_, (i32,String,String,Option<String>,Option<OffsetDateTime>,OffsetDateTime)>(
        "select version,status,policy_digest,approval_ref,approved_at,created_at from control.retention_policy_versions order by version desc",
    ).fetch_all(state.store.pool()).await?;
    let registers = sqlx::query_as::<_, (i32,String,String,Option<String>,Option<OffsetDateTime>,OffsetDateTime)>(
        "select version,status,register_digest,approval_ref,approved_at,created_at from control.processing_register_versions order by version desc",
    ).fetch_all(state.store.pool()).await?;
    let processors = sqlx::query_as::<_, (String,String,String,bool,String,Option<OffsetDateTime>)>(
        "select provider_key,purpose_key,region,eea,status,valid_until from control.processor_approvals order by provider_key,purpose_key",
    ).fetch_all(state.store.pool()).await?;
    let retention_runs = sqlx::query_as::<_, (Uuid,Option<i32>,bool,String,Value,OffsetDateTime,Option<OffsetDateTime>)>(
        "select id,policy_version,dry_run,state,evidence,created_at,completed_at from control.retention_runs order by created_at desc,id desc limit 25",
    ).fetch_all(state.store.pool()).await?;
    let incidents = sqlx::query_as::<_, (Uuid,OffsetDateTime,Option<OffsetDateTime>,Option<OffsetDateTime>,String,Option<String>,Option<bool>,i64)>(
        "select id,discovered_at,controller_awareness_at,authority_deadline_at,containment_state,risk_level,notification_required,version from control.privacy_incidents order by discovered_at desc,id desc limit 50",
    ).fetch_all(state.store.pool()).await?;
    let processor_tasks=sqlx::query_as::<_,(Uuid,Uuid,String,String,String,Option<String>,Option<String>,i64,OffsetDateTime)>("select id,data_subject_request_id,processor_key,action,state,acknowledgement_ref,safe_error_class,version,updated_at from control.data_subject_processor_tasks order by updated_at desc,id desc limit 200")
        .fetch_all(state.store.pool()).await?;
    let legal_holds=sqlx::query_as::<_,(Uuid,Value,String,String,OffsetDateTime,OffsetDateTime,Option<OffsetDateTime>,Option<String>,i64)>("select id,scope,reason_code,approval_ref,imposed_at,expires_at,released_at,release_reason_code,version from control.legal_holds order by imposed_at desc,id desc limit 100")
        .fetch_all(state.store.pool()).await?;
    let erasure_restore_replays=sqlx::query_as::<_,(Uuid,Uuid,Uuid,Uuid,Vec<String>,Vec<String>,String,Option<String>,Option<OffsetDateTime>,Option<OffsetDateTime>,OffsetDateTime)>("select id,tombstone_id,recovery_point_id,operation_id,required_locations,completed_locations,state,safe_error_class,started_at,completed_at,created_at from control.erasure_restore_replays order by created_at desc,id desc limit 200")
        .fetch_all(state.store.pool()).await?;
    let legal_holds = legal_holds
        .into_iter()
        .map(|row| {
            let scope =
                serde_json::from_value(row.1).map_err(|error| ApiError::Internal(error.into()))?;
            Ok(LegalHoldResponse {
                id: row.0,
                scope,
                reason_code: row.2,
                approval_ref: row.3,
                imposed_at: api_timestamp(row.4),
                expires_at: api_timestamp(row.5),
                released_at: row.6.map(api_timestamp),
                release_reason_code: row.7,
                version: row.8,
                etag: format!("\"privacy-legal-hold-{}-v{}\"", row.0, row.8),
            })
        })
        .collect::<ApiResult<Vec<_>>>()?;
    Ok(Json(PrivacyOverviewResponse {
        state: PrivacyPlatformStateResponse {
            controller_ref: platform.0,
            dpo_ref: platform.1,
            production_personal_data_allowed: platform.2,
            approved_retention_policy_version: platform.3,
            approved_processing_register_version: platform.4,
            dpia_approval_ref: platform.5,
            version: platform.6,
            updated_at: api_timestamp(platform.7),
        },
        retention_policies: policies
            .into_iter()
            .map(|row| PrivacyPolicyVersionResponse {
                version: row.0,
                status: row.1,
                digest: row.2,
                approval_ref: row.3,
                approved_at: row.4.map(api_timestamp),
                created_at: api_timestamp(row.5),
            })
            .collect(),
        processing_registers: registers
            .into_iter()
            .map(|row| PrivacyPolicyVersionResponse {
                version: row.0,
                status: row.1,
                digest: row.2,
                approval_ref: row.3,
                approved_at: row.4.map(api_timestamp),
                created_at: api_timestamp(row.5),
            })
            .collect(),
        processors: processors
            .into_iter()
            .map(|row| ProcessorApprovalResponse {
                provider_key: row.0,
                purpose_key: row.1,
                region: row.2,
                eea: row.3,
                status: row.4,
                valid_until: row.5.map(api_timestamp),
            })
            .collect(),
        retention_runs: retention_runs
            .into_iter()
            .map(|row| RetentionRunResponse {
                id: row.0,
                policy_version: row.1,
                dry_run: row.2,
                state: row.3,
                evidence: row.4,
                created_at: api_timestamp(row.5),
                completed_at: row.6.map(api_timestamp),
            })
            .collect(),
        incidents: incidents
            .into_iter()
            .map(|row| PrivacyIncidentResponse {
                id: row.0,
                discovered_at: api_timestamp(row.1),
                controller_awareness_at: row.2.map(api_timestamp),
                authority_deadline_at: row.3.map(api_timestamp),
                containment_state: row.4,
                risk_level: row.5,
                notification_required: row.6,
                version: row.7,
                etag: format!("\"privacy-incident-{}-v{}\"", row.0, row.7),
            })
            .collect(),
        processor_tasks: processor_tasks
            .into_iter()
            .map(|row| ProcessorTaskResponse {
                id: row.0,
                data_subject_request_id: row.1,
                processor_key: row.2,
                action: row.3,
                state: row.4,
                acknowledgement_ref: row.5,
                safe_error_class: row.6,
                version: row.7,
                updated_at: api_timestamp(row.8),
                etag: format!("\"privacy-processor-task-{}-v{}\"", row.0, row.7),
            })
            .collect(),
        legal_holds,
        erasure_restore_replays: erasure_restore_replays
            .into_iter()
            .map(|row| ErasureRestoreReplayResponse {
                id: row.0,
                tombstone_id: row.1,
                recovery_point_id: row.2,
                operation_id: row.3,
                required_locations: row.4,
                completed_locations: row.5,
                state: row.6,
                safe_error_class: row.7,
                started_at: row.8.map(api_timestamp),
                completed_at: row.9.map(api_timestamp),
                created_at: api_timestamp(row.10),
            })
            .collect(),
    }))
}

#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct CreateRetentionRun {
    policy_version: i32,
    dry_run: bool,
}

pub(super) async fn platform_privacy_retention_run(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Extension(scope): Extension<PlatformScope>,
    Json(body): Json<CreateRetentionRun>,
) -> ApiResult<(StatusCode, Json<RetentionRunCommandResponse>)> {
    let who = scope.principal();
    if !body.dry_run {
        require_step_up(who)?;
    }
    let key = idempotency(&headers)?.to_owned();
    let semantic = json!({"policy_version":body.policy_version,"dry_run":body.dry_run});
    let correlation = Uuid::new_v4();
    let run_id = Uuid::new_v4();
    let mut tx = state.store.begin().await?;
    revalidate_platform_scope(&mut tx, &scope).await?;
    let command_id = match admit_command(
        &mut tx,
        NewCommand {
            actor_user_id: who.user_id,
            scope: "platform:privacy:retention",
            command_kind: "privacy.retention.start",
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
                Json(
                    serde_json::from_value(response_body.ok_or_else(|| {
                        ApiError::Internal(anyhow::anyhow!(
                            "stored retention command response is missing"
                        ))
                    })?)
                    .map_err(|error| ApiError::Internal(error.into()))?,
                ),
            ));
        }
        CommandAdmission::InProgress {
            command_id,
            operation_id,
        } => {
            tx.commit().await?;
            return Ok((
                StatusCode::ACCEPTED,
                Json(RetentionRunCommandResponse {
                    id: None,
                    operation_id,
                    command_id: Some(command_id),
                    policy_version: None,
                    dry_run: None,
                    state: None,
                    in_progress: Some(true),
                }),
            ));
        }
    };
    let status = sqlx::query_scalar::<_, String>(
        "select status from control.retention_policy_versions where version=$1",
    )
    .bind(body.policy_version)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(ApiError::NotFound)?;
    if !body.dry_run && status != "approved" {
        return Err(ApiError::Conflict(
            "live retention requires an approved policy version",
        ));
    }
    let payload = json!({"retention_run_id":run_id});
    let operation_id = Store::enqueue(
        &mut tx,
        NewOperation {
            kind: OperationKind::PrivacyRetention,
            workshop_id: None,
            target_user_id: None,
            desired_epoch: None,
            payload: &payload,
            requested_by: Some(who.user_id),
            correlation_id: correlation,
            idempotency_key: &format!("command:{command_id}"),
        },
    )
    .await?;
    sqlx::query("insert into control.retention_runs(id,policy_version,operation_id,dry_run) values($1,$2,$3,$4)").bind(run_id).bind(body.policy_version).bind(operation_id).bind(body.dry_run).execute(&mut *tx).await?;
    audit_command(
        &mut tx,
        (Some(who.user_id), None),
        "privacy.retention.start",
        "retention_run",
        run_id.to_string(),
        correlation,
        command_id,
    )
    .await?;
    let response = RetentionRunCommandResponse {
        id: Some(run_id),
        operation_id: Some(operation_id),
        command_id: None,
        policy_version: Some(body.policy_version),
        dry_run: Some(body.dry_run),
        state: Some("queued".into()),
        in_progress: None,
    };
    let response_value =
        serde_json::to_value(&response).map_err(|error| ApiError::Internal(error.into()))?;
    let result_ref = run_id.to_string();
    complete_command(
        &mut tx,
        command_id,
        CommandResult {
            operation_id: Some(operation_id),
            response_status: StatusCode::ACCEPTED.as_u16(),
            response_body: Some(&response_value),
            result_ref: Some(&result_ref),
        },
    )
    .await
    .map_err(command_error)?;
    tx.commit().await?;
    Ok((StatusCode::ACCEPTED, Json(response)))
}

pub(super) async fn privacy_request_rows(
    state: &AppState,
    subject: Option<Uuid>,
) -> ApiResult<Vec<PrivacyRequestResponse>> {
    sqlx::query_scalar::<_, i64>("select control.purge_expired_data_subject_exports()")
        .fetch_one(state.store.pool())
        .await?;
    let rows=sqlx::query_as::<_,(Uuid,Uuid,String,String,String,OffsetDateTime,OffsetDateTime,Option<OffsetDateTime>,Option<String>,i64,OffsetDateTime)>("select r.id,r.subject_user_id,u.email,r.request_type,r.status,r.requested_at,r.due_at,r.extended_due_at,r.decision_code,r.version,r.updated_at from control.data_subject_requests r join control.users u on u.id=r.subject_user_id where $1::uuid is null or r.subject_user_id=$1 order by r.requested_at desc,r.id")
        .bind(subject).fetch_all(state.store.pool()).await?;
    let exports = sqlx::query_as::<_,(Uuid,Uuid,String,Option<OffsetDateTime>,OffsetDateTime,Option<OffsetDateTime>,Option<String>,Option<i64>)>(
        "select e.data_subject_request_id,e.id,e.state,e.ready_at,e.expires_at,e.consumed_at,e.filename,e.plaintext_size
         from control.data_subject_export_status e join control.data_subject_requests r on r.id=e.data_subject_request_id
         where $1::uuid is null or r.subject_user_id=$1",
    ).bind(subject).fetch_all(state.store.pool()).await?
        .into_iter().map(|row| (row.0,row)).collect::<std::collections::HashMap<_,_>>();
    Ok(rows
        .into_iter()
        .map(|row| {
            let export = exports
                .get(&row.0)
                .map(|value| DataSubjectExportStatusResponse {
                    id: value.1,
                    state: value.2.clone(),
                    ready_at: value.3.map(api_timestamp),
                    expires_at: api_timestamp(value.4),
                    consumed_at: value.5.map(api_timestamp),
                    filename: value.6.clone(),
                    plaintext_size: value.7,
                });
            PrivacyRequestResponse {
                id: row.0,
                subject_user_id: row.1,
                subject_email: row.2,
                request_type: row.3,
                status: row.4,
                requested_at: api_timestamp(row.5),
                due_at: api_timestamp(row.6),
                extended_due_at: row.7.map(api_timestamp),
                decision_code: row.8,
                version: row.9,
                updated_at: api_timestamp(row.10),
                export,
            }
        })
        .collect())
}

pub(super) async fn consume_privacy_export(
    State(state): State<Arc<AppState>>,
    Extension(who): Extension<Principal>,
    Path(id): Path<Uuid>,
) -> ApiResult<Response> {
    let mut tx = state.store.begin().await?;
    let export_id = sqlx::query_scalar::<_, Uuid>(
        "select e.id from control.data_subject_export_status e
         join control.data_subject_requests r on r.id=e.data_subject_request_id
         where r.id=$1 and r.subject_user_id=$2",
    )
    .bind(id)
    .bind(who.user_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(ApiError::NotFound)?;
    let row = sqlx::query_as::<_, (Uuid,String,String,Vec<u8>,Option<Vec<u8>>,String,String,String,i64)>(
        "select export_id,encryption_key_ref,storage_ref,nonce,ciphertext,manifest_digest,content_type,filename,plaintext_size
         from control.consume_data_subject_export($1,$2)",
    )
    .bind(export_id)
    .bind(who.user_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(ApiError::Gone("the export is expired, consumed, or unavailable"))?;
    tx.commit().await?;
    let ciphertext = match row.4.as_ref() {
        Some(value) if row.2.starts_with("postgres:aead:") => value.clone(),
        None if row.2.starts_with("file:") => {
            crate::privacy_crypto::read_export_artifact(row.0, &row.2).map_err(|_| {
                ApiError::Internal(anyhow::anyhow!("privacy export artifact is unavailable"))
            })?
        }
        _ => {
            return Err(ApiError::Internal(anyhow::anyhow!(
                "privacy export storage contract is invalid"
            )));
        }
    };
    let plaintext =
        crate::privacy_crypto::decrypt_export_with_key_id(row.0, &row.1, &row.3, &ciphertext)
            .map_err(|_| {
                ApiError::Internal(anyhow::anyhow!("privacy export authentication failed"))
            })?;
    if i64::try_from(plaintext.len()).ok() != Some(row.8)
        || format!("sha256:{:x}", sha2::Sha256::digest(&plaintext)) != row.5
    {
        return Err(ApiError::Internal(anyhow::anyhow!(
            "privacy export integrity check failed"
        )));
    }
    if row.2.starts_with("file:")
        && let Err(error) = crate::privacy_crypto::delete_export_artifact(row.0, &row.2)
    {
        tracing::error!(
            export_id = %row.0,
            error_class = crate::error_reporting::safe_error_class(&error),
            "consumed privacy export artifact cleanup failed"
        );
    }
    let mut response = Response::new(Body::from(plaintext));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(&row.6).map_err(|error| ApiError::Internal(error.into()))?,
    );
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("attachment; filename=\"{}\"", row.7))
            .map_err(|error| ApiError::Internal(error.into()))?,
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    Ok(response)
}

pub(super) async fn privacy_request(
    State(state): State<Arc<AppState>>,
    Extension(who): Extension<Principal>,
    Path(id): Path<Uuid>,
) -> ApiResult<(HeaderMap, Json<PrivacyRequestResponse>)> {
    let row = privacy_request_rows(&state, Some(who.user_id))
        .await?
        .into_iter()
        .find(|row| row.id == id)
        .ok_or(ApiError::NotFound)?;
    let version = row.version;
    Ok((etag(&format!("privacy-request-{id}"), version)?, Json(row)))
}

#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct PrivacyDecision {
    decision: String,
    decision_code: Option<String>,
}

pub(super) async fn platform_privacy_request_decision(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Extension(scope): Extension<PlatformScope>,
    Path(id): Path<Uuid>,
    Json(body): Json<PrivacyDecision>,
) -> ApiResult<(StatusCode, HeaderMap, Json<Value>)> {
    let who = scope.principal();
    if !matches!(body.decision.as_str(), "review" | "approve" | "refuse") {
        return Err(ApiError::Validation(
            "decision must be review, approve or refuse",
        ));
    }
    if body.decision != "review"
        && body
            .decision_code
            .as_deref()
            .is_none_or(|value| value.trim().is_empty() || value.len() > 100)
    {
        return Err(ApiError::Validation("a bounded decision_code is required"));
    }
    if body.decision != "review" {
        require_step_up(who)?;
        let controller_recorded = sqlx::query_scalar::<_, bool>(
            "select controller_ref is not null and btrim(controller_ref)<>'' from control.privacy_platform_state where singleton",
        )
        .fetch_one(state.store.pool())
        .await?;
        if !controller_recorded {
            return Err(ApiError::Conflict(
                "a data controller must be formally recorded before a request can be approved or refused",
            ));
        }
    }
    let resource = format!("privacy-request-{id}");
    let expected = expected_version(&headers, &resource)?;
    let key = idempotency(&headers)?.to_owned();
    let semantic = json!({"decision":body.decision,"decision_code":body.decision_code});
    let correlation = Uuid::new_v4();
    let mut tx = state.store.begin().await?;
    revalidate_platform_scope(&mut tx, &scope).await?;
    let command_id = match admit_command(
        &mut tx,
        NewCommand {
            actor_user_id: who.user_id,
            scope: &format!("platform:privacy-request:{id}"),
            command_kind: "privacy.request.decision",
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
                StatusCode::from_u16(response_status).unwrap_or(StatusCode::OK),
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
    let current=sqlx::query_as::<_,(String,String,Uuid,i64)>("select status,request_type,subject_user_id,version from control.data_subject_requests where id=$1 for update")
        .bind(id).fetch_optional(&mut *tx).await?.ok_or(ApiError::NotFound)?;
    if current.3 != expected {
        return Err(ApiError::PreconditionFailed("If-Match is stale"));
    }
    let (from, to) = match body.decision.as_str() {
        "review" if matches!(current.0.as_str(), "received" | "identity_verification") => {
            (current.0.as_str(), "controller_review")
        }
        "approve" if current.0 == "controller_review" => ("controller_review", "approved"),
        "refuse"
            if matches!(
                current.0.as_str(),
                "identity_verification" | "controller_review"
            ) =>
        {
            (current.0.as_str(), "refused")
        }
        _ => {
            return Err(ApiError::Conflict(
                "decision is not legal in the current request state",
            ));
        }
    };
    let changed=sqlx::query("update control.data_subject_requests set status=$3,decision_code=case when $3 in ('approved','refused') then $4 else decision_code end,approver_user_id=case when $3 in ('approved','refused') then $5 else approver_user_id end,decided_at=case when $3 in ('approved','refused') then now() else decided_at end,version=version+1 where id=$1 and status=$2 and version=$6")
        .bind(id).bind(from).bind(to).bind(&body.decision_code).bind(who.user_id).bind(expected).execute(&mut *tx).await?.rows_affected();
    if changed != 1 {
        return Err(ApiError::PreconditionFailed("If-Match is stale"));
    }
    let mut operation_id = None;
    if to == "approved" {
        let action = match current.1.as_str() {
            "access" | "portability" => "export",
            "rectification" => "rectify",
            "erasure" => "erase",
            "restriction" => "restrict",
            "objection" => "object",
            _ => return Err(ApiError::Validation("unknown request type")),
        };
        sqlx::query("insert into control.data_subject_processor_tasks(id,data_subject_request_id,processor_key,action) values($1,$2,'control',$3) on conflict do nothing")
            .bind(Uuid::new_v4()).bind(id).bind(action).execute(&mut *tx).await?;
        let processors=sqlx::query_scalar::<_,String>("select distinct p.provider_key from control.processor_approvals p join control.privacy_platform_state s on s.approved_processing_register_version=p.processing_register_version where s.singleton and p.status='approved' and p.valid_from<=now() and (p.valid_until is null or p.valid_until>now()) order by p.provider_key")
            .fetch_all(&mut *tx).await?;
        for processor in processors {
            sqlx::query("insert into control.data_subject_processor_tasks(id,data_subject_request_id,processor_key,action) values($1,$2,$3,$4) on conflict do nothing")
                .bind(Uuid::new_v4()).bind(id).bind(processor).bind(action).execute(&mut *tx).await?;
        }
        let payload = json!({"request_id":id});
        let op = Store::enqueue(
            &mut tx,
            NewOperation {
                kind: OperationKind::PrivacyDataSubjectRequest,
                workshop_id: None,
                target_user_id: Some(current.2),
                desired_epoch: None,
                payload: &payload,
                requested_by: Some(who.user_id),
                correlation_id: correlation,
                idempotency_key: &format!("command:{command_id}"),
            },
        )
        .await?;
        sqlx::query("update control.data_subject_requests set operation_id=$2,version=version+1 where id=$1 and status='approved'").bind(id).bind(op).execute(&mut *tx).await?;
        operation_id = Some(op);
    }
    let version = expected + if to == "approved" { 2 } else { 1 };
    audit_command(
        &mut tx,
        (Some(who.user_id), None),
        "privacy.request.decision",
        "data_subject_request",
        id.to_string(),
        correlation,
        command_id,
    )
    .await?;
    let response = json!({"id":id,"status":to,"version":version,"operation_id":operation_id});
    let result_ref = id.to_string();
    complete_command(
        &mut tx,
        command_id,
        CommandResult {
            operation_id,
            response_status: if operation_id.is_some() {
                StatusCode::ACCEPTED.as_u16()
            } else {
                StatusCode::OK.as_u16()
            },
            response_body: Some(&response),
            result_ref: Some(&result_ref),
        },
    )
    .await
    .map_err(command_error)?;
    tx.commit().await?;
    Ok((
        if operation_id.is_some() {
            StatusCode::ACCEPTED
        } else {
            StatusCode::OK
        },
        etag(&resource, version)?,
        Json(response),
    ))
}

#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct ProcessorTaskAcknowledgement {
    state: String,
    evidence_ref: String,
}

pub(super) async fn platform_privacy_processor_task_acknowledge(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Extension(scope): Extension<PlatformScope>,
    Path(id): Path<Uuid>,
    Json(body): Json<ProcessorTaskAcknowledgement>,
) -> ApiResult<(HeaderMap, Json<Value>)> {
    let who = scope.principal();
    require_step_up(who)?;
    if !matches!(body.state.as_str(), "acknowledged" | "not_applicable") {
        return Err(ApiError::Validation(
            "state must be acknowledged or not_applicable",
        ));
    }
    if body.evidence_ref.trim().is_empty() || body.evidence_ref.len() > 500 {
        return Err(ApiError::Validation("a bounded evidence_ref is required"));
    }
    let resource = format!("privacy-processor-task-{id}");
    let expected = expected_version(&headers, &resource)?;
    let key = idempotency(&headers)?.to_owned();
    let semantic = json!({"state":body.state,"evidence_ref":body.evidence_ref});
    let correlation = Uuid::new_v4();
    let mut tx = state.store.begin().await?;
    revalidate_platform_scope(&mut tx, &scope).await?;
    let command_id = match admit_command(
        &mut tx,
        NewCommand {
            actor_user_id: who.user_id,
            scope: &format!("platform:privacy:processor-task:{id}"),
            command_kind: "privacy.processor_task.acknowledge",
            idempotency_key: &key,
            semantic_request: &semantic,
            expected_version: Some(expected),
        },
    )
    .await
    .map_err(command_error)?
    {
        CommandAdmission::New { command_id } => command_id,
        CommandAdmission::Replay { response_body, .. } => {
            let response = response_body.unwrap_or_else(|| json!({"replayed":true}));
            let version = response["version"].as_i64().unwrap_or(expected);
            tx.commit().await?;
            return Ok((etag(&resource, version)?, Json(response)));
        }
        CommandAdmission::InProgress { command_id, .. } => {
            tx.commit().await?;
            return Ok((
                etag(&resource, expected)?,
                Json(json!({"command_id":command_id,"in_progress":true})),
            ));
        }
    };
    let changed=sqlx::query("update control.data_subject_processor_tasks set state=$2,acknowledgement_ref=case when $2='acknowledged' then $3 else null end,safe_error_class=case when $2='not_applicable' then $3 else null end,version=version+1 where id=$1 and state in ('pending','sent','failed') and version=$4")
        .bind(id).bind(&body.state).bind(&body.evidence_ref).bind(expected).execute(&mut *tx).await?.rows_affected();
    if changed != 1 {
        return Err(ApiError::PreconditionFailed(
            "If-Match is stale or task is already final",
        ));
    }
    audit_command(
        &mut tx,
        (Some(who.user_id), None),
        "privacy.processor_task.acknowledge",
        "data_subject_processor_task",
        id.to_string(),
        correlation,
        command_id,
    )
    .await?;
    let response = json!({"id":id,"state":body.state,"version":expected+1});
    let result_ref = id.to_string();
    complete_command(
        &mut tx,
        command_id,
        CommandResult {
            operation_id: None,
            response_status: StatusCode::OK.as_u16(),
            response_body: Some(&response),
            result_ref: Some(&result_ref),
        },
    )
    .await
    .map_err(command_error)?;
    tx.commit().await?;
    Ok((etag(&resource, expected + 1)?, Json(response)))
}

fn bounded_privacy_key(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
}

#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct CreatePrivacyIncident {
    discovered_at: OffsetDateTime,
    affected_categories: Vec<String>,
    affected_workshop_ids: Option<Vec<Uuid>>,
    estimated_subject_count: Option<i64>,
    containment_state: String,
    risk_level: Option<String>,
}

pub(super) async fn platform_privacy_incident_create(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Extension(scope): Extension<PlatformScope>,
    Json(body): Json<CreatePrivacyIncident>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let who = scope.principal();
    if body.affected_categories.is_empty()
        || body.affected_categories.len() > 50
        || body
            .affected_categories
            .iter()
            .any(|value| !bounded_privacy_key(value))
    {
        return Err(ApiError::Validation(
            "affected_categories must contain 1 to 50 bounded category keys",
        ));
    }
    if !matches!(
        body.containment_state.as_str(),
        "investigating" | "contained"
    ) {
        return Err(ApiError::Validation(
            "a new incident must be investigating or contained",
        ));
    }
    if body
        .risk_level
        .as_deref()
        .is_some_and(|value| !matches!(value, "undetermined" | "low" | "medium" | "high"))
    {
        return Err(ApiError::Validation("unknown incident risk level"));
    }
    if body.estimated_subject_count.is_some_and(|value| value < 0) {
        return Err(ApiError::Validation(
            "estimated_subject_count cannot be negative",
        ));
    }
    let workshops = body.affected_workshop_ids.unwrap_or_default();
    if workshops.len() > 100
        || workshops
            .iter()
            .copied()
            .collect::<std::collections::HashSet<_>>()
            .len()
            != workshops.len()
    {
        return Err(ApiError::Validation(
            "affected workshop scope must be unique and bounded",
        ));
    }
    let key = idempotency(&headers)?.to_owned();
    let semantic = json!({"discovered_at":body.discovered_at,"affected_categories":body.affected_categories,"affected_workshop_ids":workshops,"estimated_subject_count":body.estimated_subject_count,"containment_state":body.containment_state,"risk_level":body.risk_level});
    let id = Uuid::new_v4();
    let correlation = Uuid::new_v4();
    let mut tx = state.store.begin().await?;
    revalidate_platform_scope(&mut tx, &scope).await?;
    let command_id = match admit_command(
        &mut tx,
        NewCommand {
            actor_user_id: who.user_id,
            scope: "platform:privacy:incidents",
            command_kind: "privacy.incident.create",
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
                StatusCode::from_u16(response_status).unwrap_or(StatusCode::CREATED),
                Json(response_body.unwrap_or_else(|| json!({"replayed":true}))),
            ));
        }
        CommandAdmission::InProgress { command_id, .. } => {
            tx.commit().await?;
            return Ok((
                StatusCode::ACCEPTED,
                Json(json!({"command_id":command_id,"in_progress":true})),
            ));
        }
    };
    if !workshops.is_empty() {
        let known =
            sqlx::query_scalar::<_, i64>("select count(*) from control.workshops where id=any($1)")
                .bind(&workshops)
                .fetch_one(&mut *tx)
                .await?;
        if usize::try_from(known).ok() != Some(workshops.len()) {
            return Err(ApiError::Validation("an affected workshop does not exist"));
        }
    }
    sqlx::query("insert into control.privacy_incidents(id,discovered_at,affected_categories,affected_workshop_ids,estimated_subject_count,containment_state,risk_level,created_by) values($1,$2,$3,$4,$5,$6,$7,$8)")
        .bind(id).bind(body.discovered_at).bind(&body.affected_categories).bind(&workshops).bind(body.estimated_subject_count).bind(&body.containment_state).bind(&body.risk_level).bind(who.user_id).execute(&mut *tx).await?;
    audit_command(
        &mut tx,
        (Some(who.user_id), None),
        "privacy.incident.create",
        "privacy_incident",
        id.to_string(),
        correlation,
        command_id,
    )
    .await?;
    let response = json!({"id":id,"version":1,"containment_state":body.containment_state});
    let result_ref = id.to_string();
    complete_command(
        &mut tx,
        command_id,
        CommandResult {
            operation_id: None,
            response_status: StatusCode::CREATED.as_u16(),
            response_body: Some(&response),
            result_ref: Some(&result_ref),
        },
    )
    .await
    .map_err(command_error)?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(response)))
}

#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct PrivacyIncidentAssessment {
    controller_awareness_at: Option<OffsetDateTime>,
    containment_state: String,
    risk_level: String,
    notification_required: bool,
    decision_ref: String,
    authority_notification_ref: Option<String>,
    subject_notification_ref: Option<String>,
}

pub(super) async fn platform_privacy_incident_assess(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Extension(scope): Extension<PlatformScope>,
    Path(id): Path<Uuid>,
    Json(body): Json<PrivacyIncidentAssessment>,
) -> ApiResult<(HeaderMap, Json<Value>)> {
    let who = scope.principal();
    require_step_up(who)?;
    if !matches!(
        body.containment_state.as_str(),
        "investigating" | "contained" | "eradicated" | "monitoring" | "closed"
    ) {
        return Err(ApiError::Validation("unknown containment state"));
    }
    if !matches!(
        body.risk_level.as_str(),
        "undetermined" | "low" | "medium" | "high"
    ) {
        return Err(ApiError::Validation("unknown incident risk level"));
    }
    if body.decision_ref.trim().is_empty() || body.decision_ref.len() > 500 {
        return Err(ApiError::Validation("a bounded decision_ref is required"));
    }
    if body.notification_required && body.controller_awareness_at.is_none() {
        return Err(ApiError::Validation(
            "controller awareness time is required when notification is required",
        ));
    }
    for evidence in [
        &body.authority_notification_ref,
        &body.subject_notification_ref,
    ]
    .into_iter()
    .flatten()
    {
        if evidence.trim().is_empty() || evidence.len() > 500 {
            return Err(ApiError::Validation(
                "notification evidence references must be bounded",
            ));
        }
    }
    let resource = format!("privacy-incident-{id}");
    let expected = expected_version(&headers, &resource)?;
    let key = idempotency(&headers)?.to_owned();
    let semantic = json!({"controller_awareness_at":body.controller_awareness_at,"containment_state":body.containment_state,"risk_level":body.risk_level,"notification_required":body.notification_required,"decision_ref":body.decision_ref,"authority_notification_ref":body.authority_notification_ref,"subject_notification_ref":body.subject_notification_ref});
    let correlation = Uuid::new_v4();
    let mut tx = state.store.begin().await?;
    revalidate_platform_scope(&mut tx, &scope).await?;
    let command_id = match admit_command(
        &mut tx,
        NewCommand {
            actor_user_id: who.user_id,
            scope: &format!("platform:privacy:incident:{id}"),
            command_kind: "privacy.incident.assess",
            idempotency_key: &key,
            semantic_request: &semantic,
            expected_version: Some(expected),
        },
    )
    .await
    .map_err(command_error)?
    {
        CommandAdmission::New { command_id } => command_id,
        CommandAdmission::Replay { response_body, .. } => {
            let response = response_body.unwrap_or_else(|| json!({"replayed":true}));
            let version = response["version"].as_i64().unwrap_or(expected);
            tx.commit().await?;
            return Ok((etag(&resource, version)?, Json(response)));
        }
        CommandAdmission::InProgress { command_id, .. } => {
            tx.commit().await?;
            return Ok((
                etag(&resource, expected)?,
                Json(json!({"command_id":command_id,"in_progress":true})),
            ));
        }
    };
    let changed=sqlx::query("update control.privacy_incidents set controller_awareness_at=coalesce($2,controller_awareness_at),containment_state=$3,risk_level=$4,notification_required=$5,decision_ref=$6,authority_notification_ref=$7,subject_notification_ref=$8,version=version+1 where id=$1 and version=$9")
        .bind(id).bind(body.controller_awareness_at).bind(&body.containment_state).bind(&body.risk_level).bind(body.notification_required).bind(&body.decision_ref).bind(&body.authority_notification_ref).bind(&body.subject_notification_ref).bind(expected).execute(&mut *tx).await?.rows_affected();
    if changed != 1 {
        return Err(ApiError::PreconditionFailed("If-Match is stale"));
    }
    audit_command(
        &mut tx,
        (Some(who.user_id), None),
        "privacy.incident.assess",
        "privacy_incident",
        id.to_string(),
        correlation,
        command_id,
    )
    .await?;
    let response = json!({"id":id,"containment_state":body.containment_state,"notification_required":body.notification_required,"version":expected+1});
    let result_ref = id.to_string();
    complete_command(
        &mut tx,
        command_id,
        CommandResult {
            operation_id: None,
            response_status: StatusCode::OK.as_u16(),
            response_body: Some(&response),
            result_ref: Some(&result_ref),
        },
    )
    .await
    .map_err(command_error)?;
    tx.commit().await?;
    Ok((etag(&resource, expected + 1)?, Json(response)))
}

#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct CreateLegalHold {
    datasets: Vec<String>,
    workshop_ids: Option<Vec<Uuid>>,
    subject_user_ids: Option<Vec<Uuid>>,
    reason_code: String,
    approval_ref: String,
    expires_at: OffsetDateTime,
}

pub(super) async fn platform_privacy_legal_hold_create(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Extension(scope): Extension<PlatformScope>,
    Json(body): Json<CreateLegalHold>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let who = scope.principal();
    require_step_up(who)?;
    if body.datasets.is_empty()
        || body.datasets.len() > 50
        || body
            .datasets
            .iter()
            .any(|value| value != "*" && !bounded_privacy_key(value))
    {
        return Err(ApiError::Validation(
            "datasets must contain 1 to 50 bounded inventory keys",
        ));
    }
    if body.reason_code.trim().is_empty()
        || body.reason_code.len() > 100
        || body.approval_ref.trim().is_empty()
        || body.approval_ref.len() > 500
    {
        return Err(ApiError::Validation(
            "bounded reason_code and approval_ref are required",
        ));
    }
    if body.expires_at <= OffsetDateTime::now_utc() {
        return Err(ApiError::Validation(
            "legal hold expiry must be in the future",
        ));
    }
    let workshops = body.workshop_ids.unwrap_or_default();
    let subjects = body.subject_user_ids.unwrap_or_default();
    if workshops.len() > 100
        || subjects.len() > 100
        || workshops
            .iter()
            .copied()
            .collect::<std::collections::HashSet<_>>()
            .len()
            != workshops.len()
        || subjects
            .iter()
            .copied()
            .collect::<std::collections::HashSet<_>>()
            .len()
            != subjects.len()
    {
        return Err(ApiError::Validation(
            "legal hold UUID scopes must be unique and bounded",
        ));
    }
    let hold_scope =
        json!({"datasets":body.datasets,"workshop_ids":workshops,"subject_user_ids":subjects});
    let key = idempotency(&headers)?.to_owned();
    let id = Uuid::new_v4();
    let correlation = Uuid::new_v4();
    let semantic = json!({"scope":hold_scope,"reason_code":body.reason_code,"approval_ref":body.approval_ref,"expires_at":body.expires_at});
    let mut tx = state.store.begin().await?;
    revalidate_platform_scope(&mut tx, &scope).await?;
    let command_id = match admit_command(
        &mut tx,
        NewCommand {
            actor_user_id: who.user_id,
            scope: "platform:privacy:legal-holds",
            command_kind: "privacy.legal_hold.create",
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
                StatusCode::from_u16(response_status).unwrap_or(StatusCode::CREATED),
                Json(response_body.unwrap_or_else(|| json!({"replayed":true}))),
            ));
        }
        CommandAdmission::InProgress { command_id, .. } => {
            tx.commit().await?;
            return Ok((
                StatusCode::ACCEPTED,
                Json(json!({"command_id":command_id,"in_progress":true})),
            ));
        }
    };
    if !workshops.is_empty() {
        let count =
            sqlx::query_scalar::<_, i64>("select count(*) from control.workshops where id=any($1)")
                .bind(&workshops)
                .fetch_one(&mut *tx)
                .await?;
        if usize::try_from(count).ok() != Some(workshops.len()) {
            return Err(ApiError::Validation("a scoped workshop does not exist"));
        }
    }
    if !subjects.is_empty() {
        let count =
            sqlx::query_scalar::<_, i64>("select count(*) from control.users where id=any($1)")
                .bind(&subjects)
                .fetch_one(&mut *tx)
                .await?;
        if usize::try_from(count).ok() != Some(subjects.len()) {
            return Err(ApiError::Validation("a scoped subject does not exist"));
        }
    }
    sqlx::query("insert into control.legal_holds(id,scope,reason_code,approval_ref,imposed_by,expires_at) values($1,$2,$3,$4,$5,$6)").bind(id).bind(&hold_scope).bind(&body.reason_code).bind(&body.approval_ref).bind(who.user_id).bind(body.expires_at).execute(&mut *tx).await?;
    audit_command(
        &mut tx,
        (Some(who.user_id), None),
        "privacy.legal_hold.create",
        "legal_hold",
        id.to_string(),
        correlation,
        command_id,
    )
    .await?;
    let response = json!({"id":id,"version":1,"expires_at":body.expires_at});
    let result_ref = id.to_string();
    complete_command(
        &mut tx,
        command_id,
        CommandResult {
            operation_id: None,
            response_status: StatusCode::CREATED.as_u16(),
            response_body: Some(&response),
            result_ref: Some(&result_ref),
        },
    )
    .await
    .map_err(command_error)?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(response)))
}

#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct ReleaseLegalHold {
    reason_code: String,
}

pub(super) async fn platform_privacy_legal_hold_release(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Extension(scope): Extension<PlatformScope>,
    Path(id): Path<Uuid>,
    Json(body): Json<ReleaseLegalHold>,
) -> ApiResult<(HeaderMap, Json<Value>)> {
    let who = scope.principal();
    require_step_up(who)?;
    if body.reason_code.trim().is_empty() || body.reason_code.len() > 100 {
        return Err(ApiError::Validation("a bounded reason_code is required"));
    }
    let resource = format!("privacy-legal-hold-{id}");
    let expected = expected_version(&headers, &resource)?;
    let key = idempotency(&headers)?.to_owned();
    let semantic = json!({"reason_code":body.reason_code});
    let correlation = Uuid::new_v4();
    let mut tx = state.store.begin().await?;
    revalidate_platform_scope(&mut tx, &scope).await?;
    let command_id = match admit_command(
        &mut tx,
        NewCommand {
            actor_user_id: who.user_id,
            scope: &format!("platform:privacy:legal-hold:{id}"),
            command_kind: "privacy.legal_hold.release",
            idempotency_key: &key,
            semantic_request: &semantic,
            expected_version: Some(expected),
        },
    )
    .await
    .map_err(command_error)?
    {
        CommandAdmission::New { command_id } => command_id,
        CommandAdmission::Replay { response_body, .. } => {
            let response = response_body.unwrap_or_else(|| json!({"replayed":true}));
            let version = response["version"].as_i64().unwrap_or(expected);
            tx.commit().await?;
            return Ok((etag(&resource, version)?, Json(response)));
        }
        CommandAdmission::InProgress { command_id, .. } => {
            tx.commit().await?;
            return Ok((
                etag(&resource, expected)?,
                Json(json!({"command_id":command_id,"in_progress":true})),
            ));
        }
    };
    let changed=sqlx::query("update control.legal_holds set released_at=now(),released_by=$2,release_reason_code=$3,version=version+1 where id=$1 and released_at is null and version=$4").bind(id).bind(who.user_id).bind(&body.reason_code).bind(expected).execute(&mut *tx).await?.rows_affected();
    if changed != 1 {
        return Err(ApiError::PreconditionFailed(
            "If-Match is stale or hold is already released",
        ));
    }
    audit_command(
        &mut tx,
        (Some(who.user_id), None),
        "privacy.legal_hold.release",
        "legal_hold",
        id.to_string(),
        correlation,
        command_id,
    )
    .await?;
    let response = json!({"id":id,"released":true,"version":expected+1});
    let result_ref = id.to_string();
    complete_command(
        &mut tx,
        command_id,
        CommandResult {
            operation_id: None,
            response_status: StatusCode::OK.as_u16(),
            response_body: Some(&response),
            result_ref: Some(&result_ref),
        },
    )
    .await
    .map_err(command_error)?;
    tx.commit().await?;
    Ok((etag(&resource, expected + 1)?, Json(response)))
}
