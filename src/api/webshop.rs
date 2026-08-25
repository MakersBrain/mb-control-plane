use super::*;
use crate::auth::WorkshopScope;
use axum::Extension;
use serde::Serialize;

#[derive(Serialize, ToSchema)]
pub(crate) struct WebshopCheckResponse {
    key: String,
    label: String,
    ready: bool,
    count: Option<i64>,
    next_action: String,
    href: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct WebshopIssueResponse {
    key: String,
    category: String,
    state: String,
    count: i64,
    safe_error_class: Option<String>,
    next_action: String,
    href: Option<String>,
    operation_id: Option<Uuid>,
    can_retry: bool,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct WebshopDashboardResponse {
    state: String,
    version: i64,
    etag: String,
    operation_id: Option<Uuid>,
    operation_state: Option<String>,
    last_checked_at: Option<String>,
    completed_at: Option<String>,
    checks: Vec<WebshopCheckResponse>,
    issues: Vec<WebshopIssueResponse>,
    can_manage: bool,
    odoo_url: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct WebshopOnboardingCommandResponse {
    operation_id: Option<Uuid>,
    state: String,
    version: i64,
}

#[derive(sqlx::FromRow)]
struct OnboardingRow {
    state: String,
    observation: Value,
    odoo_issues: Value,
    operation_id: Option<Uuid>,
    operation_state: Option<String>,
    last_error_class: Option<String>,
    last_checked_at: Option<OffsetDateTime>,
    completed_at: Option<OffsetDateTime>,
    version: i64,
}

fn bool_field(value: &Value, key: &str) -> bool {
    value.get(key).and_then(Value::as_bool).unwrap_or(false)
}

fn count_field(value: &Value, key: &str) -> Option<i64> {
    value.get(key).and_then(Value::as_i64)
}

fn configuration_check(
    observation: &Value,
    key: &str,
    label: &str,
    count_key: Option<&str>,
    odoo_url: Option<&str>,
) -> WebshopCheckResponse {
    WebshopCheckResponse {
        key: key.into(),
        label: label.into(),
        ready: bool_field(observation, key),
        count: count_key.and_then(|name| count_field(observation, name)),
        next_action: format!("Configure {label} in Odoo, then refresh this check."),
        href: odoo_url.map(|url| format!("{url}/odoo/settings")),
    }
}

async fn dashboard(
    state: &AppState,
    workshop: Uuid,
    can_manage: bool,
) -> ApiResult<WebshopDashboardResponse> {
    let route = sqlx::query_as::<_, (String, Option<String>, String, bool)>(
        "select w.slug,d.public_hostname,coalesce(s.health,'failed'),
                exists(select 1 from control.workshop_modules m
                       where m.workshop_id=w.id and m.module_key='webshop' and m.state='enabled')
           from control.workshops w
           left join control.odoo_databases d on d.workshop_id=w.id and d.kind='primary' and d.deleted_at is null
           left join control.service_instances s on s.workshop_id=w.id and s.service='odoo'
          where w.id=$1",
    )
    .bind(workshop)
    .fetch_optional(state.store.pool())
    .await?
    .ok_or(ApiError::NotFound)?;
    let odoo_url = service_external_url(&state.config, "odoo", &route.0, route.1.as_deref());
    let row = sqlx::query_as::<_, OnboardingRow>(
        "select b.state,b.observation,b.odoo_issues,b.operation_id,o.state as operation_state,b.last_error_class,
                b.last_checked_at,b.completed_at,b.version
           from control.webshop_onboarding b
           left join control.operations o on o.id=b.operation_id
          where b.workshop_id=$1",
    )
    .bind(workshop)
    .fetch_optional(state.store.pool())
    .await?;
    let observation = row
        .as_ref()
        .map_or_else(|| json!({}), |value| value.observation.clone());
    let mut checks = vec![WebshopCheckResponse {
        key: "pack".into(),
        label: "Webshop pack".into(),
        ready: route.3,
        count: None,
        next_action: "Enable the Webshop module for this workshop.".into(),
        href: Some(format!("/workshops/{workshop}/modules")),
    }];
    checks.extend([
        configuration_check(
            &observation,
            "catalog",
            "a published catalogue",
            Some("product_count"),
            odoo_url.as_deref(),
        ),
        configuration_check(
            &observation,
            "online_payment",
            "a production online payment provider",
            Some("payment_count"),
            odoo_url.as_deref(),
        ),
        configuration_check(
            &observation,
            "fulfilment",
            "a published shipping or collection method",
            Some("fulfilment_count"),
            odoo_url.as_deref(),
        ),
        configuration_check(
            &observation,
            "sender",
            "the transactional sender",
            None,
            odoo_url.as_deref(),
        ),
        configuration_check(
            &observation,
            "domain",
            "the public store URL",
            None,
            odoo_url.as_deref(),
        ),
        configuration_check(
            &observation,
            "returns",
            "the returns policy",
            None,
            odoo_url.as_deref(),
        ),
        WebshopCheckResponse {
            key: "platform_route".into(),
            label: "Reachable platform service".into(),
            ready: route.1.is_some() && route.2 == "ready",
            count: None,
            next_action:
                "Retry the failed platform operation or ask support to restore the Odoo service."
                    .into(),
            href: None,
        },
    ]);

    let mut issues = Vec::new();
    if let Some(row) = &row {
        if let Some(error) = &row.last_error_class {
            issues.push(WebshopIssueResponse {
                key: "readiness-observation".into(),
                category: "onboarding".into(),
                state: "action_required".into(),
                count: 1,
                safe_error_class: Some(error.clone()),
                next_action: "Retry the readiness check after the Odoo service is available."
                    .into(),
                href: None,
                operation_id: row.operation_id,
                can_retry: row.operation_state.as_deref() == Some("dead_letter"),
            });
        }
        if let Some(entries) = row.odoo_issues.as_array() {
            for entry in entries {
                let Some(kind) = entry.get("kind").and_then(Value::as_str) else {
                    continue;
                };
                let count = entry.get("count").and_then(Value::as_i64).unwrap_or(0);
                let action_path = entry.get("action_path").and_then(Value::as_str);
                let next_action = match kind {
                    "payment" => "Review the captured payment, then retry fulfilment or refund it.",
                    "shipment" => {
                        "Review the provider outcome, then retry or reconcile the shipment."
                    }
                    "return" => "Review the return request or complete its resolution.",
                    _ => continue,
                };
                issues.push(WebshopIssueResponse {
                    key: format!("odoo-{kind}"),
                    category: kind.into(),
                    state: "action_required".into(),
                    count,
                    safe_error_class: None,
                    next_action: next_action.into(),
                    href: odoo_url
                        .as_deref()
                        .zip(action_path)
                        .map(|(url, path)| format!("{url}{path}")),
                    operation_id: None,
                    can_retry: false,
                });
            }
        }
    }
    let control_operations = sqlx::query_as::<_, (Uuid, String, Option<String>)>(
        "select id,kind,failure_class from control.operations
          where workshop_id=$1 and state='dead_letter'
            and kind in ('module.enable','module.restrict','webshop-domain.reconcile',
                         'webshop-email-domain.reconcile','webshop-onboarding.reconcile')
          order by created_at desc limit 25",
    )
    .bind(workshop)
    .fetch_all(state.store.pool())
    .await?;
    for operation in control_operations {
        issues.push(WebshopIssueResponse {
            key: format!("operation-{}", operation.0),
            category: "platform".into(),
            state: "failed".into(),
            count: 1,
            safe_error_class: operation.2,
            next_action: "Retry this safe, durable operation.".into(),
            href: None,
            operation_id: Some(operation.0),
            can_retry: true,
        });
    }
    let mut domain_tx = state.tenant_store.begin(workshop).await?;
    let domains = sqlx::query_as::<_, (i64, Option<Uuid>, Option<String>)>(
        "select count(*),(array_agg(operation_id) filter (where operation_id is not null))[1],max(last_error_class)
           from control.webshop_domains where workshop_id=$1 and state='action_required'",
    ).bind(workshop).fetch_one(&mut *domain_tx).await?;
    if domains.0 > 0 {
        issues.push(WebshopIssueResponse {
            key: "domains".into(),
            category: "domain".into(),
            state: "action_required".into(),
            count: domains.0,
            safe_error_class: domains.2,
            next_action: "Review DNS and TLS evidence, then retry verification.".into(),
            href: Some(format!("/workshops/{workshop}/domains")),
            operation_id: domains.1,
            can_retry: false,
        });
    }
    let email_domains = sqlx::query_as::<_, (i64, Option<Uuid>, Option<String>)>(
        "select count(*),(array_agg(operation_id) filter (where operation_id is not null))[1],max(last_error_class)
           from control.webshop_email_domains where workshop_id=$1 and state='action_required'",
    ).bind(workshop).fetch_one(&mut *domain_tx).await?;
    if email_domains.0 > 0 {
        issues.push(WebshopIssueResponse {
            key: "email-domains".into(),
            category: "email_domain".into(),
            state: "action_required".into(),
            count: email_domains.0,
            safe_error_class: email_domains.2,
            next_action:
                "Review SPF, DKIM and DMARC evidence, then run the sender-domain check again."
                    .into(),
            href: Some(format!("/workshops/{workshop}/domains")),
            operation_id: email_domains.1,
            can_retry: false,
        });
    }
    let delivery_failures = sqlx::query_scalar::<_, i64>(
        "select count(*) from control.outbox where workshop_id=$1
          and (state='dead_letter' or delivery_state in ('deferred','bounced','complained','suppressed'))",
    ).bind(workshop).fetch_one(&mut *domain_tx).await?;
    domain_tx.commit().await?;
    if delivery_failures > 0 {
        issues.push(WebshopIssueResponse {
            key: "email-delivery".into(),
            category: "email_delivery".into(),
            state: "action_required".into(),
            count: delivery_failures,
            safe_error_class: Some("delivery_attention".into()),
            next_action:
                "Correct invalid recipients and review suppressed or deferred transactional mail."
                    .into(),
            href: odoo_url.as_ref().map(|url| format!("{url}/odoo/discuss")),
            operation_id: None,
            can_retry: false,
        });
    }
    let persisted_state = row
        .as_ref()
        .map_or("not_started", |value| value.state.as_str());
    let operation_pending = row.as_ref().is_some_and(|value| {
        matches!(
            value.operation_state.as_deref(),
            Some("pending" | "in_flight" | "awaiting_reconciliation")
        )
    });
    let all_checks_ready = checks.iter().all(|check| check.ready);
    let visible_state = if operation_pending {
        "in_progress"
    } else if matches!(persisted_state, "ready" | "completed")
        && (!all_checks_ready || !issues.is_empty())
    {
        "action_required"
    } else {
        persisted_state
    };
    let version = row.as_ref().map_or(1, |value| value.version);
    Ok(WebshopDashboardResponse {
        state: visible_state.into(),
        version,
        etag: format!("\"webshop-onboarding-{workshop}-v{version}\""),
        operation_id: row.as_ref().and_then(|value| value.operation_id),
        operation_state: row.as_ref().and_then(|value| value.operation_state.clone()),
        last_checked_at: row
            .as_ref()
            .and_then(|value| value.last_checked_at.map(api_timestamp)),
        completed_at: row
            .as_ref()
            .and_then(|value| value.completed_at.map(api_timestamp)),
        checks,
        issues,
        can_manage,
        odoo_url,
    })
}

pub(super) async fn get(
    State(state): State<Arc<AppState>>,
    Extension(scope): Extension<WorkshopScope>,
) -> ApiResult<Json<WebshopDashboardResponse>> {
    Ok(Json(
        dashboard(&state, scope.workshop_id, scope.role.can_manage_modules()).await?,
    ))
}

pub(super) async fn platform_get(
    State(state): State<Arc<AppState>>,
    Extension(_scope): Extension<PlatformScope>,
    Path(workshop): Path<Uuid>,
) -> ApiResult<Json<WebshopDashboardResponse>> {
    Ok(Json(dashboard(&state, workshop, true).await?))
}

pub(super) async fn refresh(
    State(state): State<Arc<AppState>>,
    Extension(scope): Extension<WorkshopScope>,
    headers: HeaderMap,
) -> ApiResult<(StatusCode, HeaderMap, Json<Value>)> {
    if !scope.role.can_manage_modules() {
        return Err(ApiError::Forbidden);
    }
    let workshop = scope.workshop_id;
    let key = idempotency(&headers)?.to_owned();
    let expected = expected_version(&headers, &format!("webshop-onboarding-{workshop}"))?;
    let semantic = json!({"workshop_id":workshop});
    let correlation = Uuid::new_v4();
    let mut tx = state.tenant_store.begin(scope.workshop_id).await?;
    revalidate_workshop_scope(&mut tx, &scope).await?;
    let enabled = sqlx::query_scalar::<_, bool>(
        "select exists(select 1 from control.workshop_modules
          where workshop_id=$1 and module_key='webshop' and state='enabled')",
    )
    .bind(workshop)
    .fetch_one(&mut *tx)
    .await?;
    if !enabled {
        return Err(ApiError::Conflict("The webshop must be enabled first"));
    }
    sqlx::query(
        "insert into control.webshop_onboarding(workshop_id) values($1) on conflict do nothing",
    )
    .bind(workshop)
    .execute(&mut *tx)
    .await?;
    let command_id = match admit_command(
        &mut tx,
        NewCommand {
            actor_user_id: scope.principal_id,
            scope: &format!("workshop:{workshop}:webshop-onboarding"),
            command_kind: "webshop-onboarding.refresh",
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
            tx.commit().await?;
            return Ok((
                StatusCode::from_u16(response_status).unwrap_or(StatusCode::ACCEPTED),
                HeaderMap::new(),
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
                HeaderMap::new(),
                Json(json!({
                    "command_id":command_id,"operation_id":operation_id,"in_progress":true
                })),
            ));
        }
    };
    let version = sqlx::query_scalar::<_, i64>(
        "select version from control.webshop_onboarding where workshop_id=$1 for update",
    )
    .bind(workshop)
    .fetch_one(&mut *tx)
    .await?;
    if version != expected {
        return Err(ApiError::PreconditionFailed("If-Match is stale"));
    }
    let operation = Store::enqueue(
        &mut tx,
        NewOperation {
            kind: OperationKind::WebshopOnboardingReconcile,
            workshop_id: Some(workshop),
            target_user_id: None,
            desired_epoch: None,
            payload: &json!({"version":version}),
            requested_by: Some(scope.principal_id),
            correlation_id: correlation,
            idempotency_key: &format!("command:{command_id}"),
        },
    )
    .await?;
    sqlx::query(
        "update control.webshop_onboarding
            set state=case when state='completed' then state else 'in_progress' end,
                operation_id=$2,last_error_class=null,started_at=coalesce(started_at,now()),
                updated_at=now(),version=version+1 where workshop_id=$1",
    )
    .bind(workshop)
    .bind(operation)
    .execute(&mut *tx)
    .await?;
    let next = version + 1;
    let response = json!({"operation_id":operation,"state":"in_progress","version":next});
    audit_command(
        &mut tx,
        (Some(scope.principal_id), Some(workshop)),
        "webshop-onboarding.refresh",
        "webshop-onboarding",
        workshop.to_string(),
        correlation,
        command_id,
    )
    .await?;
    complete_command(
        &mut tx,
        command_id,
        CommandResult {
            operation_id: Some(operation),
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
        etag(&format!("webshop-onboarding-{workshop}"), next)?,
        Json(response),
    ))
}

pub(super) async fn complete(
    State(state): State<Arc<AppState>>,
    Extension(scope): Extension<WorkshopScope>,
    headers: HeaderMap,
) -> ApiResult<(StatusCode, HeaderMap, Json<Value>)> {
    if !scope.role.can_manage_modules() {
        return Err(ApiError::Forbidden);
    }
    let workshop = scope.workshop_id;
    let key = idempotency(&headers)?.to_owned();
    let expected = expected_version(&headers, &format!("webshop-onboarding-{workshop}"))?;
    let semantic = json!({"workshop_id":workshop,"complete":true});
    let correlation = Uuid::new_v4();
    let mut tx = state.tenant_store.begin(scope.workshop_id).await?;
    revalidate_workshop_scope(&mut tx, &scope).await?;
    let command_id = match admit_command(
        &mut tx,
        NewCommand {
            actor_user_id: scope.principal_id,
            scope: &format!("workshop:{workshop}:webshop-onboarding"),
            command_kind: "webshop-onboarding.complete",
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
            tx.commit().await?;
            return Ok((
                StatusCode::from_u16(response_status).unwrap_or(StatusCode::OK),
                HeaderMap::new(),
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
                HeaderMap::new(),
                Json(json!({
                    "command_id":command_id,"operation_id":operation_id,"in_progress":true
                })),
            ));
        }
    };
    let current = sqlx::query_as::<_, (String, Value, Value, i64)>(
        "select state,observation,odoo_issues,version from control.webshop_onboarding
          where workshop_id=$1 for update",
    )
    .bind(workshop)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(ApiError::Conflict("Run the readiness check first"))?;
    if current.3 != expected {
        return Err(ApiError::PreconditionFailed("If-Match is stale"));
    }
    let platform_ready = sqlx::query_scalar::<_, bool>(
        "select exists(select 1 from control.workshop_modules where workshop_id=$1 and module_key='webshop' and state='enabled')
             and exists(select 1 from control.service_instances where workshop_id=$1 and service='odoo' and health='ready')
             and exists(select 1 from control.odoo_databases where workshop_id=$1 and kind='primary' and deleted_at is null and public_hostname is not null)",
    ).bind(workshop).fetch_one(&mut *tx).await?;
    let blocking = sqlx::query_scalar::<_, i64>(
        "select (select count(*) from control.operations where workshop_id=$1 and state='dead_letter'
                    and kind in ('module.enable','module.restrict','webshop-domain.reconcile','webshop-email-domain.reconcile','webshop-onboarding.reconcile'))
              + (select count(*) from control.webshop_domains where workshop_id=$1 and state='action_required')
              + (select count(*) from control.webshop_email_domains where workshop_id=$1 and state='action_required')
              + (select count(*) from control.outbox where workshop_id=$1 and (state='dead_letter' or delivery_state in ('deferred','bounced','complained','suppressed')))",
    ).bind(workshop).fetch_one(&mut *tx).await?;
    if current.0 != "ready"
        || !bool_field(&current.1, "launch_ready")
        || current.2.as_array().is_none_or(|issues| !issues.is_empty())
        || !platform_ready
        || blocking != 0
    {
        return Err(ApiError::Conflict(
            "Resolve every readiness check and operational issue first",
        ));
    }
    sqlx::query("update control.webshop_onboarding set state='completed',completed_at=now(),updated_at=now(),version=version+1 where workshop_id=$1")
        .bind(workshop).execute(&mut *tx).await?;
    let next = current.3 + 1;
    let response = json!({"state":"completed","version":next});
    audit_command(
        &mut tx,
        (Some(scope.principal_id), Some(workshop)),
        "webshop-onboarding.complete",
        "webshop-onboarding",
        workshop.to_string(),
        correlation,
        command_id,
    )
    .await?;
    complete_command(
        &mut tx,
        command_id,
        CommandResult {
            operation_id: None,
            response_status: StatusCode::OK.as_u16(),
            response_body: Some(&response),
            result_ref: None,
        },
    )
    .await
    .map_err(command_error)?;
    tx.commit().await?;
    Ok((
        StatusCode::OK,
        etag(&format!("webshop-onboarding-{workshop}"), next)?,
        Json(response),
    ))
}

pub(super) async fn deactivate(
    State(state): State<Arc<AppState>>,
    Extension(scope): Extension<WorkshopScope>,
    headers: HeaderMap,
) -> ApiResult<(StatusCode, HeaderMap, Json<Value>)> {
    if !scope.role.can_manage_modules() {
        return Err(ApiError::Forbidden);
    }
    let workshop = scope.workshop_id;
    let key = idempotency(&headers)?.to_owned();
    let resource = format!("capability-{workshop}-webshop");
    let expected = expected_version(&headers, &resource)?;
    let semantic = json!({"module_key":"webshop","reason":"merchant_deactivated"});
    let correlation = Uuid::new_v4();
    let mut tx = state.tenant_store.begin(scope.workshop_id).await?;
    revalidate_workshop_scope(&mut tx, &scope).await?;
    let command_id = match admit_command(
        &mut tx,
        NewCommand {
            actor_user_id: scope.principal_id,
            scope: &format!("workshop:{workshop}:capability:webshop"),
            command_kind: "capability.deactivate",
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
                Json(json!({
                    "command_id":command_id,"operation_id":operation_id,"in_progress":true
                })),
            ));
        }
    };
    lock_lifecycle(&mut tx, workshop).await?;
    ensure_lifecycle_idle(&mut tx, workshop).await?;
    let current = sqlx::query_as::<
        _,
        (
            String,
            Option<Uuid>,
            i64,
            i32,
            Option<String>,
            Option<i64>,
            Value,
        ),
    >(
        "select state,operation_id,version,registry_version,application_release_id,
                entitlement_version,resolved_implementation
           from control.workshop_modules
          where workshop_id=$1 and module_key='webshop' for update",
    )
    .bind(workshop)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(ApiError::Conflict(
        "Enable the webshop before deactivating it",
    ))?;
    if current.2 != expected {
        return Err(ApiError::PreconditionFailed("If-Match is stale"));
    }
    if current.0 == "restricted" {
        let response = json!({"operation_id":current.1,"version":expected,"state":"restricted"});
        complete_command(
            &mut tx,
            command_id,
            CommandResult {
                operation_id: current.1,
                response_status: StatusCode::OK.as_u16(),
                response_body: Some(&response),
                result_ref: None,
            },
        )
        .await
        .map_err(command_error)?;
        tx.commit().await?;
        return Ok((StatusCode::OK, etag(&resource, expected)?, Json(response)));
    }
    if current.0 != "enabled" {
        return Err(ApiError::Conflict(
            "The webshop lifecycle is already changing",
        ));
    }
    let payload = json!({
        "module_key":"webshop","reason":"merchant_deactivated",
        "registry_version":current.3,"application_release_id":current.4,
        "entitlement_version":current.5,"resolved_implementation":current.6
    });
    let operation = Store::enqueue(
        &mut tx,
        NewOperation {
            kind: OperationKind::ModuleRestrict,
            workshop_id: Some(workshop),
            target_user_id: None,
            desired_epoch: None,
            payload: &payload,
            requested_by: Some(scope.principal_id),
            correlation_id: correlation,
            idempotency_key: &format!("command:{command_id}"),
        },
    )
    .await?;
    let changed = sqlx::query(
        "update control.workshop_modules
            set state='restricting',operation_id=$2,restriction_reason='merchant_deactivated',
                restriction_evidence=null,restricted_at=null,version=version+1
          where workshop_id=$1 and module_key='webshop' and state='enabled' and version=$3",
    )
    .bind(workshop)
    .bind(operation)
    .bind(expected)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if changed != 1 {
        return Err(ApiError::PreconditionFailed("If-Match is stale"));
    }
    let version = expected + 1;
    let response = json!({"operation_id":operation,"version":version,"state":"restricting"});
    audit_command(
        &mut tx,
        (Some(scope.principal_id), Some(workshop)),
        "module.deactivate",
        "workshop_module",
        "webshop".into(),
        correlation,
        command_id,
    )
    .await?;
    complete_command(
        &mut tx,
        command_id,
        CommandResult {
            operation_id: Some(operation),
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
        etag(&resource, version)?,
        Json(response),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_observations_are_never_treated_as_ready() {
        let check = configuration_check(&json!({}), "catalog", "a catalogue", None, None);
        assert!(!check.ready);
        assert!(check.href.is_none());
    }
}
