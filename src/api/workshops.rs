use super::*;

pub(super) async fn workshops(
    State(state): State<Arc<AppState>>,
    Extension(who): Extension<Principal>,
) -> ApiResult<Json<Vec<WorkshopSummaryResponse>>> {
    let rows = sqlx::query_as::<_, (Uuid, String, String, String, String, i64, String, i32)>(
        "select w.id,w.slug,w.display_name,w.status,w.plan,w.version,m.role,m.authority_epoch
         from control.workshops w join control.memberships m on m.workshop_id=w.id
         where m.user_id=$1 and m.status='active' and w.status<>'deleted' order by w.display_name,w.id",
    ).bind(who.user_id).fetch_all(state.store.pool()).await?;
    Ok(Json(
        rows.into_iter()
            .map(|row| {
                Ok(WorkshopSummaryResponse {
                    id: row.0,
                    slug: row.1,
                    display_name: row.2,
                    status: row.3,
                    plan: row.4,
                    version: row.5,
                    role: WorkshopRole::from_str(&row.6).map_err(|_| {
                        ApiError::Internal(anyhow::anyhow!("invalid stored workshop role"))
                    })?,
                    authority_epoch: row.7,
                })
            })
            .collect::<ApiResult<Vec<_>>>()?,
    ))
}

#[derive(Deserialize, ToSchema)]
pub(crate) struct CreateWorkshop {
    slug: String,
    display_name: String,
    country_code: Option<String>,
    time_zone: String,
}

pub(super) async fn create_workshop(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Extension(who): Extension<Principal>,
    Json(body): Json<CreateWorkshop>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let key = idempotency(&headers)?.to_owned();
    let fleet_fenced = sqlx::query_scalar::<_, bool>(
        "select exists(select 1 from control.release_fleet_runs
         where state in ('preflighting','preparing','paused','activating'))",
    )
    .fetch_one(state.store.pool())
    .await?;
    if fleet_fenced {
        return Err(ApiError::Conflict(
            "new workshops are held until the active fleet release finishes",
        ));
    }
    if body.display_name.trim().is_empty() {
        return Err(ApiError::Validation("display_name is required"));
    }
    let workshop_id = Uuid::new_v4();
    let database_id = Uuid::new_v4();
    let database_ref = opaque_database_ref(database_id);
    let public_hostname = format!("{}.{}", body.slug, state.config.tenant_domain);
    let paperless_hostname = format!("docs-{}.{}", body.slug, state.config.tenant_domain);
    let operation_id = Uuid::new_v4();
    let correlation_id = Uuid::new_v4();
    let trace_context = crate::telemetry::current_trace_context();
    let mut tx = state.store.begin().await?;
    let semantic_request = json!({
        "slug": body.slug,
        "display_name": body.display_name.trim(),
        "country_code": body.country_code,
        "time_zone": body.time_zone,
    });
    let command_id = match admit_command(
        &mut tx,
        NewCommand {
            actor_user_id: who.user_id,
            scope: "platform:workshops",
            command_kind: "workshop.create",
            idempotency_key: &key,
            semantic_request: &semantic_request,
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
    let inserted = sqlx::query_scalar::<_, Uuid>(
        "insert into control.workshops(id,slug,display_name,country_code,time_zone)
         values($1,$2,$3,$4,$5) on conflict(slug) do nothing returning id",
    )
    .bind(workshop_id)
    .bind(&body.slug)
    .bind(body.display_name.trim())
    .bind(&body.country_code)
    .bind(&body.time_zone)
    .fetch_optional(&mut *tx)
    .await?;
    if inserted.is_none() {
        return Err(ApiError::Conflict("workshop slug already exists"));
    }
    sqlx::query("insert into control.memberships(workshop_id,user_id,role) values($1,$2,'owner')")
        .bind(workshop_id)
        .bind(who.user_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("insert into control.odoo_databases(id,workshop_id,kind,database_ref,public_hostname,label,routable) values($1,$2,'primary',$3,$4,'Primary database',true)")
        .bind(database_id).bind(workshop_id).bind(&database_ref).bind(&public_hostname).execute(&mut *tx).await?;
    sqlx::query("insert into control.operations(id,kind,queue,workshop_id,target_user_id,desired_epoch,payload,requested_by,correlation_id,idempotency_key,trace_parent,trace_state)
                 values($1,'tenant.provision','tenant-provisioning',$2,$3,1,$4,$3,$5,$6,$7,$8)")
        .bind(operation_id).bind(workshop_id).bind(who.user_id).bind(json!({"generation":1,"database_id":database_id,"database_ref":database_ref,"public_hostname":public_hostname,"paperless_hostname":paperless_hostname,"paperless_enabled":false})).bind(correlation_id).bind(format!("command:{command_id}")).bind(trace_context.trace_parent).bind(trace_context.trace_state).execute(&mut *tx).await?;
    audit_command(
        &mut tx,
        (Some(who.user_id), Some(workshop_id)),
        "workshop.create",
        "workshop",
        workshop_id.to_string(),
        correlation_id,
        command_id,
    )
    .await?;
    let response = json!({"id":workshop_id,"operation_id":operation_id});
    complete_command(
        &mut tx,
        command_id,
        CommandResult {
            operation_id: Some(operation_id),
            response_status: StatusCode::ACCEPTED.as_u16(),
            response_body: Some(&response),
            result_ref: None,
        },
    )
    .await
    .map_err(command_error)?;
    tx.commit().await?;
    Ok((StatusCode::ACCEPTED, Json(response)))
}

pub(super) async fn workshop(
    State(state): State<Arc<AppState>>,
    Extension(scope): Extension<WorkshopScope>,
) -> ApiResult<(HeaderMap, Json<WorkshopSummaryResponse>)> {
    let id = scope.workshop_id;
    let mut tx = state.tenant_store.begin(id).await?;
    let row = sqlx::query_as::<_, (String, String, String, String, i64)>(
        "select slug,display_name,status,plan,version from control.workshops where id=$1",
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok((
        etag(&format!("workshop-{id}"), row.4)?,
        Json(WorkshopSummaryResponse {
            id,
            slug: row.0,
            display_name: row.1,
            status: row.2,
            plan: row.3,
            version: row.4,
            role: scope.role,
            authority_epoch: scope.authority_epoch,
        }),
    ))
}

pub(super) async fn members(
    State(state): State<Arc<AppState>>,
    Extension(scope): Extension<WorkshopScope>,
) -> ApiResult<Json<Vec<MemberResponse>>> {
    let id = scope.workshop_id;
    let mut tx = state.tenant_store.begin(id).await?;
    let rows = sqlx::query_as::<_, (Uuid,String,Option<String>,String,String,i32,i64,Value,Option<Uuid>,Option<String>)>(
        "select u.id,u.email,u.display_name,m.role,m.status,m.authority_epoch,m.version,
           coalesce(jsonb_object_agg(t.target,jsonb_build_object('state',t.state,'desired_epoch',t.desired_epoch,'applied_epoch',t.applied_epoch,'error',t.safe_error_class,'observed_at',t.observed_at)) filter(where t.target is not null),'{}'),
           latest.id,latest.state
         from control.memberships m join control.users u on u.id=m.user_id
         left join control.membership_targets t on t.workshop_id=m.workshop_id and t.user_id=m.user_id
         left join lateral (select id,state from control.operations where workshop_id=m.workshop_id and target_user_id=m.user_id and kind='membership.reconcile' order by created_at desc,id desc limit 1) latest on true
         where m.workshop_id=$1 group by u.id,u.email,u.display_name,m.role,m.status,m.authority_epoch,m.version,latest.id,latest.state order by u.email",
    ).bind(id).fetch_all(&mut *tx).await?;
    tx.commit().await?;
    Ok(Json(
        rows.into_iter()
            .map(|row| {
                Ok(MemberResponse {
                    id: row.0,
                    email: row.1,
                    display_name: row.2,
                    role: WorkshopRole::from_str(&row.3).map_err(|_| {
                        ApiError::Internal(anyhow::anyhow!("invalid stored workshop role"))
                    })?,
                    status: row.4,
                    authority_epoch: row.5,
                    version: row.6,
                    etag: format!("\"member-{id}-{}-v{}\"", row.0, row.6),
                    targets: serde_json::from_value(row.7)
                        .map_err(|error| ApiError::Internal(error.into()))?,
                    operation_id: row.8,
                    operation_state: row.9,
                })
            })
            .collect::<ApiResult<Vec<_>>>()?,
    ))
}

#[derive(Deserialize, ToSchema)]
pub(crate) struct InviteBody {
    email: String,
    role: WorkshopRole,
    #[serde(default = "default_locale")]
    locale: String,
}
fn default_locale() -> String {
    "en".into()
}

pub(super) async fn invitations(
    State(state): State<Arc<AppState>>,
    Extension(scope): Extension<WorkshopScope>,
) -> ApiResult<Json<Vec<InvitationResponse>>> {
    let id = scope.workshop_id;
    let mut tx = state.tenant_store.begin(id).await?;
    let rows = sqlx::query_as::<_, (Uuid, String, String, String, OffsetDateTime, i32, OffsetDateTime)>(
        "select id,email,role,locale,expires_at,sent_count,last_sent_at from control.invitations where workshop_id=$1 and accepted_at is null and revoked_at is null order by created_at desc",
    ).bind(id).fetch_all(&mut *tx).await?;
    tx.commit().await?;
    Ok(Json(
        rows.into_iter()
            .map(|row| {
                Ok(InvitationResponse {
                    id: row.0,
                    email: row.1,
                    role: WorkshopRole::from_str(&row.2).map_err(|_| {
                        ApiError::Internal(anyhow::anyhow!("invalid stored workshop role"))
                    })?,
                    locale: row.3,
                    expires_at: api_timestamp(row.4),
                    sent_count: row.5,
                    last_sent_at: api_timestamp(row.6),
                })
            })
            .collect::<ApiResult<Vec<_>>>()?,
    ))
}

pub(super) async fn invite(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Extension(scope): Extension<WorkshopScope>,
    Json(body): Json<InviteBody>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let id = scope.workshop_id;
    let actor = scope.principal_id;
    if !body.role.can_invite() {
        return Err(ApiError::Forbidden);
    }
    if !matches!(body.locale.as_str(), "en" | "fr") {
        return Err(ApiError::Validation("locale must be en or fr"));
    }
    let key = idempotency(&headers)?.to_owned();
    let email = normalize_email(&body.email).map_err(ApiError::Validation)?;
    let invitation_id = Uuid::new_v4();
    let outbox_id = Uuid::new_v4();
    let correlation_id = Uuid::new_v4();
    let issued_at = OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .map_err(|error| ApiError::Internal(error.into()))?;
    let expires_at = issued_at + time::Duration::days(7);
    let mut tx = state.tenant_store.begin(scope.workshop_id).await?;
    revalidate_workshop_scope(&mut tx, &scope).await?;
    let semantic_request = json!({
        "workshop_id": id,
        "email": email,
        "role": body.role,
        "locale": body.locale,
    });
    let command_scope = format!("workshop:{id}");
    let command_id = match admit_command(
        &mut tx,
        NewCommand {
            actor_user_id: actor,
            scope: &command_scope,
            command_kind: "invitation.create",
            idempotency_key: &key,
            semantic_request: &semantic_request,
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
                Json(json!({
                    "command_id": command_id,
                    "operation_id": operation_id,
                    "in_progress": true
                })),
            ));
        }
    };
    let existing = sqlx::query_scalar::<_, Uuid>("select id from control.invitations where workshop_id=$1 and email=$2 and accepted_at is null and revoked_at is null")
        .bind(id).bind(&email).fetch_optional(&mut *tx).await?;
    if existing.is_some() {
        return Err(ApiError::Conflict("a pending invitation already exists"));
    }
    sqlx::query("insert into control.invitations(id,workshop_id,email,role,locale,invited_by,idempotency_key,expires_at) values($1,$2,$3,$4,$5,$6,$7,$8)")
        .bind(invitation_id).bind(id).bind(&email).bind(body.role.as_str()).bind(&body.locale).bind(actor).bind(&key).bind(expires_at).execute(&mut *tx).await?;
    sqlx::query("insert into control.outbox(id,kind,recipient,template,payload,invitation_id,token_generation,capability_issued_at,capability_expires_at,signing_key_id,workshop_id) values($1,'invitation',$2,'workshop-invitation',$3,$4,1,$5,$6,$7,$8)")
        .bind(outbox_id).bind(&email).bind(json!({"invitation_id":invitation_id,"workshop_id":id,"role":body.role,"locale":body.locale,"idempotency_key":key})).bind(invitation_id).bind(issued_at).bind(expires_at).bind(&state.config.invitation_signing_key_id).bind(id).execute(&mut *tx).await?;
    let operation_id = Store::enqueue(
        &mut tx,
        NewOperation {
            kind: OperationKind::EmailDelivery,
            workshop_id: Some(id),
            target_user_id: None,
            desired_epoch: None,
            payload: &json!({"outbox_id":outbox_id}),
            requested_by: Some(actor),
            correlation_id,
            idempotency_key: &format!("command:{command_id}"),
        },
    )
    .await?;
    audit_command(
        &mut tx,
        (Some(actor), Some(id)),
        "invitation.create",
        "invitation",
        invitation_id.to_string(),
        correlation_id,
        command_id,
    )
    .await?;
    let response =
        json!({"id":invitation_id,"email":email,"role":body.role,"expires_at":expires_at});
    complete_command(
        &mut tx,
        command_id,
        CommandResult {
            operation_id: Some(operation_id),
            response_status: StatusCode::ACCEPTED.as_u16(),
            response_body: Some(&response),
            result_ref: None,
        },
    )
    .await
    .map_err(command_error)?;
    tx.commit().await?;
    Ok((StatusCode::ACCEPTED, Json(response)))
}

pub(super) async fn resend_invitation(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Extension(who): Extension<Principal>,
    Path(id): Path<Uuid>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let key = idempotency(&headers)?.to_owned();
    let row=sqlx::query_as::<_,(Uuid,String,String,String)>("select workshop_id,email,role,locale from control.invitations where id=$1 and accepted_at is null and revoked_at is null and expires_at>now()")
        .bind(id).fetch_optional(state.store.pool()).await?.ok_or(ApiError::NotFound)?;
    let (role, authority_epoch) = authority(&state, who.user_id, row.0).await?;
    if !role.can_manage_members() {
        return Err(ApiError::Forbidden);
    }
    let authority_scope = WorkshopScope {
        workshop_id: row.0,
        principal_id: who.user_id,
        role,
        authority_epoch,
        permission: crate::domain::WorkshopPermission::ManageMembers,
    };
    let outbox_id = Uuid::new_v4();
    let correlation_id = Uuid::new_v4();
    let issued_at = OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .map_err(|error| ApiError::Internal(error.into()))?;
    let expires_at = issued_at + time::Duration::days(7);
    let mut tx = state
        .tenant_store
        .begin(authority_scope.workshop_id)
        .await?;
    revalidate_workshop_scope(&mut tx, &authority_scope).await?;
    let semantic_request = json!({"invitation_id": id});
    let command_scope = format!("workshop:{}", row.0);
    let command_id = match admit_command(
        &mut tx,
        NewCommand {
            actor_user_id: who.user_id,
            scope: &command_scope,
            command_kind: "invitation.resend",
            idempotency_key: &key,
            semantic_request: &semantic_request,
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
    let generation = sqlx::query_scalar::<_, i32>("update control.invitations set token_generation=token_generation+1,sent_count=sent_count+1,last_sent_at=$2,expires_at=$3 where id=$1 and workshop_id=$4 and accepted_at is null and revoked_at is null and expires_at>now() returning token_generation")
        .bind(id).bind(issued_at).bind(expires_at).bind(row.0).fetch_optional(&mut *tx).await?.ok_or(ApiError::NotFound)?;
    sqlx::query("insert into control.outbox(id,kind,recipient,template,payload,invitation_id,token_generation,capability_issued_at,capability_expires_at,signing_key_id,workshop_id) values($1,'invitation',$2,'workshop-invitation',$3,$4,$5,$6,$7,$8,$9)")
        .bind(outbox_id).bind(&row.1).bind(json!({"invitation_id":id,"workshop_id":row.0,"role":row.2,"locale":row.3})).bind(id).bind(generation).bind(issued_at).bind(expires_at).bind(&state.config.invitation_signing_key_id).bind(row.0).execute(&mut *tx).await?;
    let operation_id = Store::enqueue(
        &mut tx,
        NewOperation {
            kind: OperationKind::EmailDelivery,
            workshop_id: Some(row.0),
            target_user_id: None,
            desired_epoch: None,
            payload: &json!({"outbox_id":outbox_id}),
            requested_by: Some(who.user_id),
            correlation_id,
            idempotency_key: &format!("command:{command_id}"),
        },
    )
    .await?;
    audit_command(
        &mut tx,
        (Some(who.user_id), Some(row.0)),
        "invitation.resend",
        "invitation",
        id.to_string(),
        correlation_id,
        command_id,
    )
    .await?;
    let response = json!({"id":id,"resent":true,"generation":generation});
    complete_command(
        &mut tx,
        command_id,
        CommandResult {
            operation_id: Some(operation_id),
            response_status: StatusCode::ACCEPTED.as_u16(),
            response_body: Some(&response),
            result_ref: None,
        },
    )
    .await
    .map_err(command_error)?;
    tx.commit().await?;
    Ok((StatusCode::ACCEPTED, Json(response)))
}

pub(super) async fn revoke_invitation(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Extension(who): Extension<Principal>,
    Path(id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    let key = idempotency(&headers)?.to_owned();
    let workshop=sqlx::query_scalar::<_,Uuid>("select workshop_id from control.invitations where id=$1 and accepted_at is null and revoked_at is null").bind(id).fetch_optional(state.store.pool()).await?.ok_or(ApiError::NotFound)?;
    let (role, authority_epoch) = authority(&state, who.user_id, workshop).await?;
    if !role.can_manage_members() {
        return Err(ApiError::Forbidden);
    }
    let authority_scope = WorkshopScope {
        workshop_id: workshop,
        principal_id: who.user_id,
        role,
        authority_epoch,
        permission: crate::domain::WorkshopPermission::ManageMembers,
    };
    let mut tx = state
        .tenant_store
        .begin(authority_scope.workshop_id)
        .await?;
    revalidate_workshop_scope(&mut tx, &authority_scope).await?;
    let semantic_request = json!({"invitation_id": id});
    let command_scope = format!("workshop:{workshop}");
    let command_id = match admit_command(
        &mut tx,
        NewCommand {
            actor_user_id: who.user_id,
            scope: &command_scope,
            command_kind: "invitation.revoke",
            idempotency_key: &key,
            semantic_request: &semantic_request,
            expected_version: None,
        },
    )
    .await
    .map_err(command_error)?
    {
        CommandAdmission::New { command_id } => command_id,
        CommandAdmission::Replay {
            response_status, ..
        } => {
            tx.commit().await?;
            return Ok(StatusCode::from_u16(response_status).unwrap_or(StatusCode::NO_CONTENT));
        }
        CommandAdmission::InProgress { .. } => {
            tx.commit().await?;
            return Ok(StatusCode::ACCEPTED);
        }
    };
    let changed = sqlx::query(
        "update control.invitations set revoked_at=now()
         where id=$1 and workshop_id=$2 and accepted_at is null and revoked_at is null",
    )
    .bind(id)
    .bind(workshop)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if changed != 1 {
        return Err(ApiError::NotFound);
    }
    let correlation = Uuid::new_v4();
    audit_command(
        &mut tx,
        (Some(who.user_id), Some(workshop)),
        "invitation.revoke",
        "invitation",
        id.to_string(),
        correlation,
        command_id,
    )
    .await?;
    complete_command(
        &mut tx,
        command_id,
        CommandResult {
            operation_id: None,
            response_status: StatusCode::NO_CONTENT.as_u16(),
            response_body: None,
            result_ref: Some("invitation:revoked"),
        },
    )
    .await
    .map_err(command_error)?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize, ToSchema)]
pub(crate) struct InvitationTokenBody {
    token: String,
}

pub(super) async fn validate_invitation(
    State(state): State<Arc<AppState>>,
    Json(body): Json<InvitationTokenBody>,
) -> ApiResult<(HeaderMap, Json<Value>)> {
    let claims = state
        .invitation_verifier
        .verify(&body.token)
        .map_err(|_| ApiError::NotFound)?;
    let row=sqlx::query_as::<_,(String,String,String,String)>("select i.email,i.role,i.locale,w.display_name from control.invitations i join control.workshops w on w.id=i.workshop_id where i.id=$1 and i.token_generation=$2 and i.accepted_at is null and i.revoked_at is null and i.expires_at>now()")
        .bind(claims.jti).bind(claims.r#gen).fetch_optional(state.store.pool()).await?.ok_or(ApiError::NotFound)?;
    Ok((
        invitation_response_headers(),
        Json(json!({"email":row.0,"role":row.1,"locale":row.2,"workshop_name":row.3})),
    ))
}

pub(super) async fn accept_invitation(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Extension(verified): Extension<VerifiedToken>,
    Json(body): Json<InvitationTokenBody>,
) -> ApiResult<(StatusCode, HeaderMap, Json<Value>)> {
    let key = idempotency(&headers)?.to_owned();
    let claims = state
        .invitation_verifier
        .verify(&body.token)
        .map_err(|_| ApiError::NotFound)?;
    let correlation_id = Uuid::new_v4();
    let mut tx = state.store.begin().await?;
    let invitation=sqlx::query_as::<_,(Uuid,Uuid,String,String,Option<OffsetDateTime>,Option<OffsetDateTime>,OffsetDateTime)>("select id,workshop_id,email,role,accepted_at,revoked_at,expires_at from control.invitations where id=$1 and token_generation=$2 for update")
        .bind(claims.jti).bind(claims.r#gen).fetch_optional(&mut *tx).await?.ok_or(ApiError::NotFound)?;
    if invitation.2 != verified.email {
        return Err(ApiError::Forbidden);
    }
    let linked=sqlx::query_scalar::<_,Uuid>("select user_id from control.external_identities where issuer=$1 and subject=$2 and disabled_at is null").bind(&verified.issuer).bind(&verified.subject).fetch_optional(&mut *tx).await?;
    let user_id = if let Some(id) = linked {
        id
    } else {
        let id=sqlx::query_scalar::<_,Uuid>("insert into control.users(id,email) values($1,$2) on conflict(email) do update set email=excluded.email returning id").bind(Uuid::new_v4()).bind(&verified.email).fetch_one(&mut *tx).await?;
        sqlx::query("insert into control.external_identities(id,user_id,issuer,subject,email_at_link) values($1,$2,$3,$4,$5)").bind(Uuid::new_v4()).bind(id).bind(&verified.issuer).bind(&verified.subject).bind(&verified.email).execute(&mut *tx).await?;
        id
    };
    let semantic_request = json!({
        "invitation_id": invitation.0,
        "generation": claims.r#gen,
        "issuer": verified.issuer,
        "subject": verified.subject,
    });
    let scope = format!("workshop:{}", invitation.1);
    let command_id = match admit_command(
        &mut tx,
        NewCommand {
            actor_user_id: user_id,
            scope: &scope,
            command_kind: "invitation.accept",
            idempotency_key: &key,
            semantic_request: &semantic_request,
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
                invitation_response_headers(),
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
                invitation_response_headers(),
                Json(
                    json!({"command_id":command_id,"operation_id":operation_id,"in_progress":true}),
                ),
            ));
        }
    };
    if invitation.4.is_some() || invitation.5.is_some() || invitation.6 <= OffsetDateTime::now_utc()
    {
        return Err(ApiError::NotFound);
    }
    sqlx::query("insert into control.memberships(workshop_id,user_id,role) values($1,$2,$3) on conflict(workshop_id,user_id) do update set role=excluded.role,status='active',revoked_at=null,authority_epoch=control.memberships.authority_epoch+1")
        .bind(invitation.1).bind(user_id).bind(&invitation.3).execute(&mut *tx).await?;
    let epoch = sqlx::query_scalar::<_, i32>(
        "select authority_epoch from control.memberships where workshop_id=$1 and user_id=$2",
    )
    .bind(invitation.1)
    .bind(user_id)
    .fetch_one(&mut *tx)
    .await?;
    sqlx::query("update control.invitations set accepted_at=now(),accepted_user_id=$2 where id=$1 and workshop_id=$3")
        .bind(invitation.0)
        .bind(user_id)
        .bind(invitation.1)
        .execute(&mut *tx)
        .await?;
    seed_targets(&mut tx, invitation.1, user_id, epoch).await?;
    let operation_id = Store::enqueue(
        &mut tx,
        NewOperation {
            kind: OperationKind::MembershipReconcile,
            workshop_id: Some(invitation.1),
            target_user_id: Some(user_id),
            desired_epoch: Some(epoch),
            payload: &json!({"active":true}),
            requested_by: Some(user_id),
            correlation_id,
            idempotency_key: &format!("command:{command_id}"),
        },
    )
    .await?;
    audit_command(
        &mut tx,
        (Some(user_id), Some(invitation.1)),
        "invitation.accept",
        "invitation",
        invitation.0.to_string(),
        correlation_id,
        command_id,
    )
    .await?;
    let response =
        json!({"workshop_id":invitation.1,"user_id":user_id,"operation_id":operation_id});
    complete_command(
        &mut tx,
        command_id,
        CommandResult {
            operation_id: Some(operation_id),
            response_status: StatusCode::ACCEPTED.as_u16(),
            response_body: Some(&response),
            result_ref: None,
        },
    )
    .await
    .map_err(command_error)?;
    tx.commit().await?;
    Ok((
        StatusCode::ACCEPTED,
        invitation_response_headers(),
        Json(response),
    ))
}

fn invitation_response_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers
}

#[derive(Deserialize, ToSchema)]
pub(crate) struct RoleBody {
    role: WorkshopRole,
}

#[derive(Deserialize)]
pub(super) struct MemberPath {
    user_id: Uuid,
}

pub(super) async fn member(
    State(state): State<Arc<AppState>>,
    Extension(scope): Extension<WorkshopScope>,
    Path(MemberPath { user_id }): Path<MemberPath>,
) -> ApiResult<(HeaderMap, Json<MemberDetailResponse>)> {
    let id = scope.workshop_id;
    let mut tx = state.tenant_store.begin(id).await?;
    let row = sqlx::query_as::<_, (String, Option<String>, String, String, i32, i64)>(
        "select u.email,u.display_name,m.role,m.status,m.authority_epoch,m.version
         from control.memberships m join control.users u on u.id=m.user_id
         where m.workshop_id=$1 and m.user_id=$2",
    )
    .bind(id)
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(ApiError::NotFound)?;
    tx.commit().await?;
    let prefix = format!("member-{id}-{user_id}");
    Ok((
        etag(&prefix, row.5)?,
        Json(MemberDetailResponse {
            id: user_id,
            email: row.0,
            display_name: row.1,
            role: WorkshopRole::from_str(&row.2)
                .map_err(|_| ApiError::Internal(anyhow::anyhow!("invalid stored role")))?,
            status: row.3,
            authority_epoch: row.4,
            version: row.5,
        }),
    ))
}

pub(super) async fn update_member(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Extension(scope): Extension<WorkshopScope>,
    Path(MemberPath { user_id }): Path<MemberPath>,
    Json(body): Json<RoleBody>,
) -> ApiResult<(HeaderMap, Json<Value>)> {
    let id = scope.workshop_id;
    let actor = scope.principal_id;
    if matches!(body.role, WorkshopRole::Owner) {
        return Err(ApiError::Forbidden);
    }
    let key = idempotency(&headers)?.to_owned();
    let resource = format!("member-{id}-{user_id}");
    let expected = expected_version(&headers, &resource)?;
    let correlation_id = Uuid::new_v4();
    let mut tx = state.tenant_store.begin(scope.workshop_id).await?;
    revalidate_workshop_scope(&mut tx, &scope).await?;
    let semantic_request = json!({"workshop_id":id,"user_id":user_id,"role":body.role});
    let command_scope = format!("workshop:{id}:member:{user_id}");
    let command_id = match admit_command(
        &mut tx,
        NewCommand {
            actor_user_id: actor,
            scope: &command_scope,
            command_kind: "member.role.update",
            idempotency_key: &key,
            semantic_request: &semantic_request,
            expected_version: Some(expected),
        },
    )
    .await
    .map_err(command_error)?
    {
        CommandAdmission::New { command_id } => command_id,
        CommandAdmission::Replay {
            response_body,
            response_status: _,
            ..
        } => {
            let response = response_body.unwrap_or_else(|| json!({"replayed":true}));
            let version = response["version"].as_i64().unwrap_or(expected);
            tx.commit().await?;
            return Ok((etag(&resource, version)?, Json(response)));
        }
        CommandAdmission::InProgress {
            command_id,
            operation_id,
        } => {
            tx.commit().await?;
            return Ok((
                etag(&resource, expected)?,
                Json(
                    json!({"command_id":command_id,"operation_id":operation_id,"in_progress":true}),
                ),
            ));
        }
    };
    let changed=sqlx::query_as::<_,(i32,i64)>("update control.memberships set role=$3,authority_epoch=authority_epoch+1,version=version+1 where workshop_id=$1 and user_id=$2 and status='active' and role<>'owner' and version=$4 returning authority_epoch,version")
        .bind(id).bind(user_id).bind(body.role.as_str()).bind(expected).fetch_optional(&mut *tx).await?;
    let (epoch, version) = match changed {
        Some(changed) => changed,
        None => {
            let current = sqlx::query_as::<_, (String, i64)>(
                "select role,version from control.memberships where workshop_id=$1 and user_id=$2 and status='active'",
            )
            .bind(id)
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await?;
            return match current {
                None => Err(ApiError::NotFound),
                Some((role, _)) if role == "owner" => Err(ApiError::Forbidden),
                Some(_) => Err(ApiError::PreconditionFailed("If-Match is stale")),
            };
        }
    };
    seed_targets(&mut tx, id, user_id, epoch).await?;
    let op = Store::enqueue(
        &mut tx,
        NewOperation {
            kind: OperationKind::MembershipReconcile,
            workshop_id: Some(id),
            target_user_id: Some(user_id),
            desired_epoch: Some(epoch),
            payload: &json!({"active":true,"role":body.role}),
            requested_by: Some(actor),
            correlation_id,
            idempotency_key: &format!("command:{command_id}"),
        },
    )
    .await?;
    audit_command(
        &mut tx,
        (Some(actor), Some(id)),
        "member.role.update",
        "membership",
        user_id.to_string(),
        correlation_id,
        command_id,
    )
    .await?;
    let response = json!({"user_id":user_id,"role":body.role,"authority_epoch":epoch,"version":version,"operation_id":op});
    complete_command(
        &mut tx,
        command_id,
        CommandResult {
            operation_id: Some(op),
            response_status: StatusCode::ACCEPTED.as_u16(),
            response_body: Some(&response),
            result_ref: None,
        },
    )
    .await
    .map_err(command_error)?;
    tx.commit().await?;
    Ok((etag(&resource, version)?, Json(response)))
}

pub(super) async fn remove_member(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Extension(scope): Extension<WorkshopScope>,
    Path(MemberPath { user_id }): Path<MemberPath>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let id = scope.workshop_id;
    let actor = scope.principal_id;
    let key = idempotency(&headers)?.to_owned();
    let resource = format!("member-{id}-{user_id}");
    let expected = expected_version(&headers, &resource)?;
    let correlation_id = Uuid::new_v4();
    let mut tx = state.tenant_store.begin(scope.workshop_id).await?;
    revalidate_workshop_scope(&mut tx, &scope).await?;
    let semantic_request = json!({"workshop_id":id,"user_id":user_id,"active":false});
    let command_scope = format!("workshop:{id}:member:{user_id}");
    let command_id = match admit_command(
        &mut tx,
        NewCommand {
            actor_user_id: actor,
            scope: &command_scope,
            command_kind: "member.remove",
            idempotency_key: &key,
            semantic_request: &semantic_request,
            expected_version: Some(expected),
        },
    )
    .await
    .map_err(command_error)?
    {
        CommandAdmission::New { command_id } => command_id,
        CommandAdmission::Replay {
            response_body,
            response_status,
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
    let changed=sqlx::query_as::<_,(i32,i64)>("update control.memberships set status='revoked',revoked_at=now(),authority_epoch=authority_epoch+1,version=version+1 where workshop_id=$1 and user_id=$2 and status='active' and role<>'owner' and version=$3 returning authority_epoch,version")
        .bind(id).bind(user_id).bind(expected).fetch_optional(&mut *tx).await?;
    let (epoch, version) = match changed {
        Some(changed) => changed,
        None => {
            let current = sqlx::query_as::<_, (String, i64)>(
                "select role,version from control.memberships where workshop_id=$1 and user_id=$2 and status='active'",
            )
            .bind(id)
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await?;
            return match current {
                None => Err(ApiError::NotFound),
                Some((role, _)) if role == "owner" => Err(ApiError::Conflict(
                    "owner must be transferred before removal",
                )),
                Some(_) => Err(ApiError::PreconditionFailed("If-Match is stale")),
            };
        }
    };
    seed_targets(&mut tx, id, user_id, epoch).await?;
    let op = Store::enqueue(
        &mut tx,
        NewOperation {
            kind: OperationKind::MembershipReconcile,
            workshop_id: Some(id),
            target_user_id: Some(user_id),
            desired_epoch: Some(epoch),
            payload: &json!({"active":false}),
            requested_by: Some(actor),
            correlation_id,
            idempotency_key: &format!("command:{command_id}"),
        },
    )
    .await?;
    audit_command(
        &mut tx,
        (Some(actor), Some(id)),
        "member.remove",
        "membership",
        user_id.to_string(),
        correlation_id,
        command_id,
    )
    .await?;
    let response = json!({"operation_id":op,"version":version});
    complete_command(
        &mut tx,
        command_id,
        CommandResult {
            operation_id: Some(op),
            response_status: StatusCode::ACCEPTED.as_u16(),
            response_body: Some(&response),
            result_ref: None,
        },
    )
    .await
    .map_err(command_error)?;
    tx.commit().await?;
    Ok((StatusCode::ACCEPTED, Json(response)))
}

#[derive(Deserialize, ToSchema)]
pub(crate) struct TransferBody {
    to_user_id: Uuid,
}
pub(super) async fn ownership_transfers(
    State(state): State<Arc<AppState>>,
    Extension(scope): Extension<WorkshopScope>,
) -> ApiResult<Json<Vec<OwnershipTransferResponse>>> {
    let id = scope.workshop_id;
    let actor = scope.principal_id;
    let mut tx = state.tenant_store.begin(id).await?;
    let rows=sqlx::query_as::<_,(Uuid,Uuid,Uuid,OffsetDateTime,i64)>("select t.id,t.from_user_id,t.to_user_id,t.expires_at,w.version from control.ownership_transfers t join control.workshops w on w.id=t.workshop_id where t.workshop_id=$1 and t.accepted_at is null and t.revoked_at is null and t.expires_at>now() and (t.from_user_id=$2 or t.to_user_id=$2) order by t.created_at desc").bind(id).bind(actor).fetch_all(&mut *tx).await?;
    tx.commit().await?;
    Ok(Json(
        rows.into_iter()
            .map(|row| OwnershipTransferResponse {
                id: row.0,
                from_user_id: row.1,
                to_user_id: row.2,
                expires_at: api_timestamp(row.3),
                can_accept: row.2 == actor,
                etag: format!("\"workshop-{id}-v{}\"", row.4),
            })
            .collect(),
    ))
}

pub(super) async fn create_ownership_transfer(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Extension(scope): Extension<WorkshopScope>,
    Json(body): Json<TransferBody>,
) -> ApiResult<(StatusCode, HeaderMap, Json<Value>)> {
    let id = scope.workshop_id;
    let actor = scope.principal_id;
    let key = idempotency(&headers)?.to_owned();
    let resource = format!("workshop-{id}");
    let expected = expected_version(&headers, &resource)?;
    let transfer = Uuid::new_v4();
    let mut tx = state.tenant_store.begin(scope.workshop_id).await?;
    revalidate_workshop_scope(&mut tx, &scope).await?;
    sqlx::query_scalar::<_, i32>(
        "select authority_epoch from control.memberships
         where workshop_id=$1 and user_id=$2 and status='active' for share",
    )
    .bind(id)
    .bind(body.to_user_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(ApiError::NotFound)?;
    let semantic_request = json!({"workshop_id":id,"to_user_id":body.to_user_id});
    let command_scope = format!("workshop:{id}:ownership");
    let command_id = match admit_command(
        &mut tx,
        NewCommand {
            actor_user_id: actor,
            scope: &command_scope,
            command_kind: "ownership.transfer.create",
            idempotency_key: &key,
            semantic_request: &semantic_request,
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
        CommandAdmission::InProgress { .. } => {
            tx.commit().await?;
            return Ok((
                StatusCode::ACCEPTED,
                etag(&resource, expected)?,
                Json(json!({"in_progress":true})),
            ));
        }
    };
    let changed =
        sqlx::query("update control.workshops set version=version+1 where id=$1 and version=$2")
            .bind(id)
            .bind(expected)
            .execute(&mut *tx)
            .await?
            .rows_affected();
    if changed != 1 {
        return Err(ApiError::PreconditionFailed("If-Match is stale"));
    }
    sqlx::query("insert into control.ownership_transfers(id,workshop_id,from_user_id,to_user_id,idempotency_key,expires_at) values($1,$2,$3,$4,$5,now()+interval '48 hours')")
        .bind(transfer).bind(id).bind(actor).bind(body.to_user_id).bind(format!("command:{command_id}")).execute(&mut *tx).await?;
    let correlation = Uuid::new_v4();
    audit_command(
        &mut tx,
        (Some(actor), Some(id)),
        "ownership.transfer.create",
        "ownership_transfer",
        transfer.to_string(),
        correlation,
        command_id,
    )
    .await?;
    let response = json!({"id":transfer,"expires_in_seconds":172800,"version":expected+1});
    complete_command(
        &mut tx,
        command_id,
        CommandResult {
            operation_id: None,
            response_status: StatusCode::ACCEPTED.as_u16(),
            response_body: Some(&response),
            result_ref: None,
        },
    )
    .await
    .map_err(command_error)?;
    tx.commit().await?;
    Ok((
        StatusCode::ACCEPTED,
        etag(&resource, expected + 1)?,
        Json(response),
    ))
}

pub(super) async fn accept_ownership_transfer(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Extension(who): Extension<Principal>,
    Path(id): Path<Uuid>,
) -> ApiResult<(HeaderMap, Json<Value>)> {
    let key = idempotency(&headers)?.to_owned();
    let correlation_id = Uuid::new_v4();
    // This opaque-ID endpoint does not carry a workshop path. Use the
    // separately reviewed platform identity only to discover the immutable
    // tenant and intended recipient, authorize the principal, then perform
    // the locked mutation through the tenant-scoped pool.
    let discovered = sqlx::query_as::<_, (Uuid, Uuid)>(
        "select workshop_id,to_user_id from control.ownership_transfers where id=$1",
    )
    .bind(id)
    .fetch_optional(state.store.pool())
    .await?
    .ok_or(ApiError::NotFound)?;
    if discovered.1 != who.user_id {
        return Err(ApiError::Forbidden);
    }
    let mut tx = state.tenant_store.begin(discovered.0).await?;
    let row = sqlx::query_as::<
        _,
        (
            Uuid,
            Uuid,
            Uuid,
            Option<OffsetDateTime>,
            Option<OffsetDateTime>,
            OffsetDateTime,
            i64,
        ),
    >(
        "select t.workshop_id,t.from_user_id,t.to_user_id,t.accepted_at,t.revoked_at,
                t.expires_at,w.version
         from control.ownership_transfers t join control.workshops w on w.id=t.workshop_id
         where t.id=$1 and t.workshop_id=$2 for update of t",
    )
    .bind(id)
    .bind(discovered.0)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(ApiError::NotFound)?;
    if row.2 != who.user_id || row.0 != discovered.0 {
        return Err(ApiError::Forbidden);
    }
    let resource = format!("workshop-{}", row.0);
    let expected = expected_version(&headers, &resource)?;
    let semantic_request = json!({"ownership_transfer_id":id,"workshop_id":row.0});
    let scope = format!("workshop:{}:ownership", row.0);
    let command_id = match admit_command(
        &mut tx,
        NewCommand {
            actor_user_id: who.user_id,
            scope: &scope,
            command_kind: "ownership.transfer.accept",
            idempotency_key: &key,
            semantic_request: &semantic_request,
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
        CommandAdmission::InProgress {
            command_id,
            operation_id,
        } => {
            tx.commit().await?;
            return Ok((
                etag(&resource, expected)?,
                Json(
                    json!({"command_id":command_id,"operation_id":operation_id,"in_progress":true}),
                ),
            ));
        }
    };
    if row.3.is_some() || row.4.is_some() || row.5 <= OffsetDateTime::now_utc() {
        return Err(ApiError::NotFound);
    }
    let changed =
        sqlx::query("update control.workshops set version=version+1 where id=$1 and version=$2")
            .bind(row.0)
            .bind(expected)
            .execute(&mut *tx)
            .await?
            .rows_affected();
    if changed != 1 {
        return Err(ApiError::PreconditionFailed("If-Match is stale"));
    }
    let memberships = sqlx::query("update control.memberships set role=case when user_id=$2 then 'studio_manager' else 'owner' end,authority_epoch=authority_epoch+1,version=version+1 where workshop_id=$1 and user_id in($2,$3) and status='active'").bind(row.0).bind(row.1).bind(row.2).execute(&mut *tx).await?.rows_affected();
    if memberships != 2 {
        return Err(ApiError::Conflict(
            "ownership transfer members are not both active",
        ));
    }
    sqlx::query("update control.ownership_transfers set accepted_at=now() where id=$1 and workshop_id=$2 and accepted_at is null and revoked_at is null")
        .bind(id)
        .bind(row.0)
        .execute(&mut *tx)
        .await?;
    let mut operation_ids = Vec::new();
    for user in [row.1, row.2] {
        let epoch = sqlx::query_scalar::<_, i32>(
            "select authority_epoch from control.memberships where workshop_id=$1 and user_id=$2",
        )
        .bind(row.0)
        .bind(user)
        .fetch_one(&mut *tx)
        .await?;
        seed_targets(&mut tx, row.0, user, epoch).await?;
        let operation_id = Store::enqueue(
            &mut tx,
            NewOperation {
                kind: OperationKind::MembershipReconcile,
                workshop_id: Some(row.0),
                target_user_id: Some(user),
                desired_epoch: Some(epoch),
                payload: &json!({"active":true}),
                requested_by: Some(who.user_id),
                correlation_id,
                idempotency_key: &format!("command:{command_id}:{user}"),
            },
        )
        .await?;
        operation_ids.push(operation_id);
    }
    audit_command(
        &mut tx,
        (Some(who.user_id), Some(row.0)),
        "ownership.transfer.accept",
        "ownership_transfer",
        id.to_string(),
        correlation_id,
        command_id,
    )
    .await?;
    let response =
        json!({"id":id,"accepted":true,"version":expected+1,"operation_ids":operation_ids});
    complete_command(
        &mut tx,
        command_id,
        CommandResult {
            operation_id: operation_ids.first().copied(),
            response_status: StatusCode::OK.as_u16(),
            response_body: Some(&response),
            result_ref: None,
        },
    )
    .await
    .map_err(command_error)?;
    tx.commit().await?;
    Ok((etag(&resource, expected + 1)?, Json(response)))
}
