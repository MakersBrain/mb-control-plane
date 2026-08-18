use super::*;

use serde::Serialize;

#[derive(Deserialize, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct CarrierCredentials {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(nullable = false)]
    access_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(nullable = false)]
    secret_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(nullable = false)]
    webhook_secret: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(nullable = false)]
    public_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(nullable = false)]
    private_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(nullable = false)]
    webhook_signature_key: Option<String>,
}

#[derive(Deserialize, ToSchema)]
pub(crate) struct CarrierSecretBody {
    provider: String,
    environment: String,
    company_id: i64,
    carrier_id: i64,
    credentials: CarrierCredentials,
}

#[derive(Deserialize)]
pub(crate) struct ResolveCarrierSecretBody {
    workshop_id: Uuid,
    company_id: i64,
    carrier_id: i64,
    secret_ref: String,
    environment: String,
    purpose: String,
    provider: String,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct CarrierSecretResponse {
    id: Uuid,
    secret_ref: String,
    provider: String,
    environment: String,
    company_id: i64,
    carrier_id: i64,
    version: i64,
    state: String,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct CarrierSecretDeleteResponse {
    id: Uuid,
    deleted: bool,
}

pub(crate) type CarrierTargetResponse = crate::integrations::odoo::CarrierTarget;

async fn odoo(
    state: &AppState,
    workshop: Uuid,
) -> ApiResult<crate::integrations::odoo::OdooClient> {
    let (url, secret_ref, database_ref) = crate::worker::service(&state.store, workshop, "odoo")
        .await
        .map_err(|_| ApiError::Conflict("Odoo carrier configuration is unavailable"))?;
    let token = crate::worker::secret(&secret_ref)
        .map_err(|_| ApiError::Conflict("Odoo carrier configuration is unavailable"))?;
    crate::integrations::odoo::OdooClient::new(
        &url,
        &token,
        database_ref.as_deref(),
        state.config.request_timeout,
    )
    .map_err(ApiError::Internal)
}

fn valid_secret(value: &str, minimum: usize, maximum: usize) -> bool {
    (minimum..=maximum).contains(&value.len())
        && !value
            .chars()
            .any(|character| matches!(character, '\r' | '\n' | '\0'))
}

fn resolve_lifecycle_scope(purpose: &str) -> Option<(Vec<String>, Vec<String>)> {
    match purpose {
        "provider_operation" => Some((vec!["active".into()], vec!["enabled".into()])),
        "cancellation"
        | "document_recovery"
        | "reconciliation"
        | "tracking_lookup"
        | "webhook_verification"
        | "webhook_processing" => Some((
            vec!["active".into()],
            vec!["enabled".into(), "restricted".into()],
        )),
        "webhook_suspension" => Some((vec!["active".into()], vec!["restricting".into()])),
        "webhook_reactivation" => Some((vec!["suspended".into()], vec!["installing".into()])),
        _ => None,
    }
}

fn provider_module(provider: &str) -> Option<&'static str> {
    match provider {
        "boxtal" => Some("shipping-boxtal"),
        "sendcloud" => Some("shipping-sendcloud"),
        _ => None,
    }
}

fn credential_value(body: &CarrierCredentials) -> ApiResult<Value> {
    serde_json::to_value(body).map_err(|error| ApiError::Internal(error.into()))
}

fn validate(body: &CarrierSecretBody) -> ApiResult<()> {
    let boxtal = body.provider == "boxtal"
        && body.credentials.public_key.is_none()
        && body.credentials.private_key.is_none()
        && body.credentials.webhook_signature_key.is_none()
        && body
            .credentials
            .access_key
            .as_deref()
            .is_some_and(|v| valid_secret(v, 8, 256))
        && body
            .credentials
            .secret_key
            .as_deref()
            .is_some_and(|v| valid_secret(v, 24, 512))
        && body
            .credentials
            .webhook_secret
            .as_deref()
            .is_some_and(|v| valid_secret(v, 24, 512));
    let sendcloud = body.provider == "sendcloud"
        && body.credentials.access_key.is_none()
        && body.credentials.secret_key.is_none()
        && body.credentials.webhook_secret.is_none()
        && body
            .credentials
            .public_key
            .as_deref()
            .is_some_and(|v| valid_secret(v, 8, 256))
        && body
            .credentials
            .private_key
            .as_deref()
            .is_some_and(|v| valid_secret(v, 16, 512))
        && body
            .credentials
            .webhook_signature_key
            .as_deref()
            .is_none_or(|v| valid_secret(v, 16, 512));
    if !(boxtal || sendcloud)
        || !matches!(body.environment.as_str(), "test" | "production")
        || body.company_id <= 0
        || body.carrier_id <= 0
    {
        return Err(ApiError::Validation(
            "carrier credential payload is invalid",
        ));
    }
    Ok(())
}

fn parse_storage_id(reference: &str, workshop: Uuid) -> Option<Uuid> {
    let prefix = format!("docker/{workshop}/carrier/");
    reference
        .strip_prefix(&prefix)
        .and_then(|value| Uuid::parse_str(value).ok())
}

async fn delete_storage(
    state: &AppState,
    workshop: Uuid,
    key: Uuid,
    reference: &str,
) -> ApiResult<()> {
    let secret_id = parse_storage_id(reference, workshop).ok_or_else(|| {
        ApiError::Internal(anyhow::anyhow!("carrier cleanup reference contract drift"))
    })?;
    let response = driver(
        state,
        workshop,
        "carrier-secret-delete",
        key,
        &json!({"secret_id":secret_id}),
    )
    .await?;
    if response.get("secret_ref").and_then(Value::as_str) != Some(reference) {
        return Err(ApiError::Internal(anyhow::anyhow!(
            "carrier cleanup response contract drift"
        )));
    }
    Ok(())
}

async fn require_manager(state: &AppState, user: Uuid, workshop: Uuid) -> ApiResult<()> {
    if !authority(state, user, workshop)
        .await?
        .0
        .can_manage_modules()
    {
        return Err(ApiError::Forbidden);
    }
    Ok(())
}

async fn require_enabled(state: &AppState, workshop: Uuid, provider: &str) -> ApiResult<()> {
    let module_key = provider_module(provider).ok_or(ApiError::Validation(
        "carrier credential payload is invalid",
    ))?;
    let enabled = sqlx::query_scalar::<_, bool>(
        "select exists(select 1 from control.workshop_modules
          where workshop_id=$1 and module_key=$2 and state='enabled')",
    )
    .bind(workshop)
    .bind(module_key)
    .fetch_one(state.store.pool())
    .await?;
    if !enabled {
        return Err(ApiError::Conflict("The shipping provider is not enabled"));
    }
    Ok(())
}

async fn driver(
    state: &AppState,
    workshop: Uuid,
    action: &str,
    key: Uuid,
    payload: &Value,
) -> ApiResult<Value> {
    let response = reqwest::Client::builder()
        .timeout(state.config.request_timeout)
        .build()
        .map_err(|error| ApiError::Internal(error.into()))?
        .post(format!(
            "{}v1/tenants/{workshop}/{action}",
            state.config.deployment_driver_url.as_str()
        ))
        .bearer_auth(&state.config.deployment_driver_token)
        .header("idempotency-key", format!("carrier-secret:{key}"))
        .json(payload)
        .send()
        .await
        .map_err(|error| ApiError::Internal(error.into()))?;
    if !response.status().is_success() {
        return Err(ApiError::Internal(anyhow::anyhow!(
            "deployment driver refused carrier secret operation"
        )));
    }
    response
        .json::<Value>()
        .await
        .map_err(|error| ApiError::Internal(error.into()))
}

pub(super) async fn list(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(workshop): Path<Uuid>,
) -> ApiResult<Json<Vec<CarrierSecretResponse>>> {
    let who = principal(&state, &headers).await?;
    authority(&state, who.user_id, workshop).await?;
    let rows = sqlx::query_as::<_, (Uuid, String, String, String, i64, i64, i64, String)>(
        "select id,secret_ref,provider,environment,company_id,carrier_id,version,state
           from control.carrier_secrets where workshop_id=$1 and state<>'deleted'
           order by provider,environment,carrier_id",
    )
    .bind(workshop)
    .fetch_all(state.store.pool())
    .await?;
    Ok(Json(
        rows.into_iter()
            .map(|row| CarrierSecretResponse {
                id: row.0,
                secret_ref: row.1,
                provider: row.2,
                environment: row.3,
                company_id: row.4,
                carrier_id: row.5,
                version: row.6,
                state: row.7,
            })
            .collect(),
    ))
}

pub(super) async fn targets(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(workshop): Path<Uuid>,
) -> ApiResult<Json<Vec<CarrierTargetResponse>>> {
    let who = principal(&state, &headers).await?;
    authority(&state, who.user_id, workshop).await?;
    let targets = odoo(&state, workshop)
        .await?
        .carrier_targets()
        .await
        .map_err(|_| ApiError::Conflict("Odoo carrier configuration is unavailable"))?;
    Ok(Json(targets))
}

pub(super) async fn upsert(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(workshop): Path<Uuid>,
    Json(body): Json<CarrierSecretBody>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    validate(&body)?;
    let who = principal(&state, &headers).await?;
    require_manager(&state, who.user_id, workshop).await?;
    require_enabled(&state, workshop, &body.provider).await?;
    let client_key = idempotency(&headers)?;
    let semantic = json!({
        "provider":body.provider,"environment":body.environment,
        "company_id":body.company_id,"carrier_id":body.carrier_id,
        "credential_digest":format!("sha256:{:x}", sha2::Sha256::digest(
            serde_json::to_vec(&body.credentials).map_err(|error| ApiError::Internal(error.into()))?
        ))
    });
    let scope = format!("workshop:{workshop}:carrier-secrets");
    let mut tx = state.store.begin().await?;
    let command_id = match admit_command(
        &mut tx,
        NewCommand {
            actor_user_id: who.user_id,
            scope: &scope,
            command_kind: "carrier-secret.upsert",
            idempotency_key: client_key,
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
                StatusCode::from_u16(response_status).unwrap_or(StatusCode::OK),
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
    let existing = sqlx::query_as::<_, (Uuid, i64, String, Option<String>)>(
        "select id,version,secret_ref,cleanup_pending_ref from control.carrier_secrets
          where workshop_id=$1 and provider=$2 and environment=$3 and company_id=$4 and carrier_id=$5
          for update",
    )
    .bind(workshop).bind(&body.provider).bind(&body.environment)
    .bind(body.company_id).bind(body.carrier_id)
    .fetch_optional(&mut *tx).await?;
    if let Some(pending_reference) = existing.as_ref().and_then(|row| row.3.as_deref()) {
        delete_storage(&state, workshop, Uuid::new_v4(), pending_reference)
            .await
            .map_err(|_| {
                ApiError::Conflict(
                    "A previous carrier credential rotation is still awaiting secure cleanup",
                )
            })?;
        sqlx::query(
            "update control.carrier_secrets set cleanup_pending_ref=null
              where id=$1 and cleanup_pending_ref=$2",
        )
        .bind(existing.as_ref().expect("existing row").0)
        .bind(pending_reference)
        .execute(&mut *tx)
        .await?;
    }
    let secret_id = existing.as_ref().map_or_else(Uuid::new_v4, |row| row.0);
    // A rotation is written under a new physical reference. Overwriting the
    // active file would destroy the last known-good credential if Odoo rejects
    // the new binding or the control-plane transaction later fails.
    let storage_id = if existing.is_some() {
        Uuid::new_v4()
    } else {
        secret_id
    };
    let response = driver(
        &state,
        workshop,
        "carrier-secret",
        command_id,
        &json!({
            "secret_id":storage_id,
            "provider":body.provider,
            "credentials":credential_value(&body.credentials)?
        }),
    )
    .await?;
    let secret_ref = response
        .get("secret_ref")
        .and_then(Value::as_str)
        .filter(|value| *value == format!("docker/{workshop}/carrier/{storage_id}"))
        .ok_or_else(|| {
            ApiError::Internal(anyhow::anyhow!("carrier secret driver contract drift"))
        })?;
    let binding = crate::integrations::odoo::CarrierSecretBindingCommand {
        workshop_id: workshop,
        company_id: body.company_id,
        carrier_id: body.carrier_id,
        provider: body.provider.clone(),
        environment: body.environment.clone(),
        secret_ref: secret_ref.to_owned(),
        credentials: existing
            .as_ref()
            .map(|_| credential_value(&body.credentials))
            .transpose()?,
    };
    if odoo(&state, workshop)
        .await?
        .bind_carrier_secret(&binding)
        .await
        .is_err()
    {
        let _ = driver(
            &state,
            workshop,
            "carrier-secret-delete",
            Uuid::new_v4(),
            &json!({"secret_id":storage_id}),
        )
        .await;
        return Err(ApiError::Conflict("Odoo rejected the carrier secret scope"));
    }
    let version = if existing.is_some() {
        sqlx::query_scalar::<_, i64>(
            "update control.carrier_secrets set version=version+1,secret_ref=$2,cleanup_pending_ref=$3,state='active',rotated_at=now(),deleted_at=null
              where id=$1 returning version"
        ).bind(secret_id).bind(secret_ref).bind(existing.as_ref().map(|row| row.2.as_str())).fetch_one(&mut *tx).await?
    } else {
        sqlx::query_scalar::<_, i64>(
            "insert into control.carrier_secrets(id,workshop_id,provider,environment,company_id,carrier_id,secret_ref,created_by)
             values($1,$2,$3,$4,$5,$6,$7,$8) returning version"
        ).bind(secret_id).bind(workshop).bind(&body.provider).bind(&body.environment)
         .bind(body.company_id).bind(body.carrier_id).bind(secret_ref).bind(who.user_id)
         .fetch_one(&mut *tx).await?
    };
    let public = json!({
        "id":secret_id,"secret_ref":secret_ref,"provider":body.provider,
        "environment":body.environment,"company_id":body.company_id,
        "carrier_id":body.carrier_id,"version":version,"state":"active"
    });
    audit_command(
        &mut tx,
        (Some(who.user_id), Some(workshop)),
        if existing.is_some() {
            "carrier-secret.rotate"
        } else {
            "carrier-secret.create"
        },
        "carrier-secret",
        secret_id.to_string(),
        Uuid::new_v4(),
        command_id,
    )
    .await?;
    complete_command(
        &mut tx,
        command_id,
        CommandResult {
            operation_id: None,
            response_status: StatusCode::OK.as_u16(),
            response_body: Some(&public),
            result_ref: None,
        },
    )
    .await
    .map_err(command_error)?;
    tx.commit().await?;
    if let Some(old_reference) = existing.as_ref().map(|row| row.2.as_str()) {
        if delete_storage(&state, workshop, Uuid::new_v4(), old_reference)
            .await
            .is_err()
        {
            tracing::error!(
                %workshop,
                credential_id = %secret_id,
                "stale carrier credential cleanup failed"
            );
        } else {
            sqlx::query(
                "update control.carrier_secrets set cleanup_pending_ref=null
                  where id=$1 and cleanup_pending_ref=$2",
            )
            .bind(secret_id)
            .bind(old_reference)
            .execute(state.store.pool())
            .await?;
        }
    }
    Ok((StatusCode::OK, Json(public)))
}

pub(super) async fn delete(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((workshop, secret_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let who = principal(&state, &headers).await?;
    require_manager(&state, who.user_id, workshop).await?;
    let client_key = idempotency(&headers)?;
    let mut tx = state.store.begin().await?;
    let row = sqlx::query_as::<_, (String, String, String, String, i64, i64, Option<String>)>(
        "select secret_ref,state,provider,environment,company_id,carrier_id,cleanup_pending_ref from control.carrier_secrets where id=$1 and workshop_id=$2 for update"
    ).bind(secret_id).bind(workshop).fetch_optional(&mut *tx).await?.ok_or(ApiError::NotFound)?;
    let semantic = json!({"secret_id":secret_id});
    let scope = format!("workshop:{workshop}:carrier-secret:{secret_id}");
    let command_id = match admit_command(
        &mut tx,
        NewCommand {
            actor_user_id: who.user_id,
            scope: &scope,
            command_kind: "carrier-secret.delete",
            idempotency_key: client_key,
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
                StatusCode::from_u16(response_status).unwrap_or(StatusCode::OK),
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
    if row.1 != "deleted" {
        if let Some(pending_reference) = row.6.as_deref() {
            delete_storage(&state, workshop, Uuid::new_v4(), pending_reference)
                .await
                .map_err(|_| {
                    ApiError::Internal(anyhow::anyhow!("stale carrier credential cleanup failed"))
                })?;
            sqlx::query("update control.carrier_secrets set cleanup_pending_ref=null where id=$1")
                .bind(secret_id)
                .execute(&mut *tx)
                .await?;
        }
        let storage_id = parse_storage_id(&row.0, workshop).ok_or_else(|| {
            ApiError::Internal(anyhow::anyhow!("carrier secret reference contract drift"))
        })?;
        let binding = crate::integrations::odoo::CarrierSecretBindingCommand {
            workshop_id: workshop,
            company_id: row.4,
            carrier_id: row.5,
            provider: row.2.clone(),
            environment: row.3.clone(),
            secret_ref: row.0.clone(),
            credentials: None,
        };
        let odoo = odoo(&state, workshop).await?;
        odoo.unbind_carrier_secret(&binding)
            .await
            .map_err(|_| ApiError::Conflict("Odoo rejected the carrier secret scope"))?;
        let deletion = driver(
            &state,
            workshop,
            "carrier-secret-delete",
            command_id,
            &json!({"secret_id":storage_id}),
        )
        .await;
        let response = match deletion {
            Ok(response) => response,
            Err(_) => {
                let _ = odoo.bind_carrier_secret(&binding).await;
                return Err(ApiError::Internal(anyhow::anyhow!(
                    "carrier secret deletion failed"
                )));
            }
        };
        if response.get("secret_ref").and_then(Value::as_str) != Some(row.0.as_str()) {
            let _ = odoo.bind_carrier_secret(&binding).await;
            return Err(ApiError::Internal(anyhow::anyhow!(
                "carrier secret deletion contract drift"
            )));
        }
        sqlx::query("update control.carrier_secrets set state='deleted',deleted_at=now(),version=version+1 where id=$1")
            .bind(secret_id).execute(&mut *tx).await?;
    }
    let public = json!({"id":secret_id,"deleted":true});
    audit_command(
        &mut tx,
        (Some(who.user_id), Some(workshop)),
        "carrier-secret.delete",
        "carrier-secret",
        secret_id.to_string(),
        Uuid::new_v4(),
        command_id,
    )
    .await?;
    complete_command(
        &mut tx,
        command_id,
        CommandResult {
            operation_id: None,
            response_status: StatusCode::OK.as_u16(),
            response_body: Some(&public),
            result_ref: None,
        },
    )
    .await
    .map_err(command_error)?;
    tx.commit().await?;
    Ok((StatusCode::OK, Json(public)))
}

pub(super) async fn resolve(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<ResolveCarrierSecretBody>,
) -> ApiResult<(HeaderMap, Json<Value>)> {
    tenant_bridge(&state, &headers, body.workshop_id).await?;
    let lifecycle_scope = resolve_lifecycle_scope(&body.purpose);
    if body.company_id <= 0
        || body.carrier_id <= 0
        || !matches!(body.environment.as_str(), "test" | "production")
        || provider_module(&body.provider).is_none()
        || lifecycle_scope.is_none()
    {
        return Err(ApiError::Validation("carrier secret scope is invalid"));
    }
    let (secret_states, module_states) = lifecycle_scope.expect("validated lifecycle scope");
    let module_key = provider_module(&body.provider).expect("validated provider");
    let reference = sqlx::query_scalar::<_, String>(
        "select cs.secret_ref from control.carrier_secrets cs
          join control.workshop_modules wm on wm.workshop_id=cs.workshop_id and wm.module_key=$6
         where cs.workshop_id=$1 and cs.company_id=$2 and cs.carrier_id=$3
           and cs.secret_ref=$4 and cs.environment=$5 and cs.provider=$7
           and cs.state=any($8) and wm.state=any($9)",
    )
    .bind(body.workshop_id)
    .bind(body.company_id)
    .bind(body.carrier_id)
    .bind(&body.secret_ref)
    .bind(&body.environment)
    .bind(module_key)
    .bind(&body.provider)
    .bind(secret_states)
    .bind(module_states)
    .fetch_optional(state.store.pool())
    .await?
    .ok_or(ApiError::NotFound)?;
    let serialized = crate::worker::secret(&reference).map_err(|_| ApiError::NotFound)?;
    let credentials: Value =
        serde_json::from_str(&serialized).map_err(|error| ApiError::Internal(error.into()))?;
    let valid = serde_json::from_value::<CarrierCredentials>(credentials.clone())
        .ok()
        .is_some_and(|stored| {
            validate(&CarrierSecretBody {
                provider: body.provider.clone(),
                environment: body.environment.clone(),
                company_id: body.company_id,
                carrier_id: body.carrier_id,
                credentials: stored,
            })
            .is_ok()
        });
    if !valid {
        return Err(ApiError::Internal(anyhow::anyhow!(
            "stored carrier secret contract drift"
        )));
    }
    let mut response_headers = HeaderMap::new();
    response_headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok((response_headers, Json(json!({"credentials":credentials}))))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body() -> CarrierSecretBody {
        CarrierSecretBody {
            provider: "boxtal".into(),
            environment: "test".into(),
            company_id: 1,
            carrier_id: 2,
            credentials: CarrierCredentials {
                access_key: Some("access-key".into()),
                secret_key: Some("s".repeat(24)),
                webhook_secret: Some("w".repeat(24)),
                public_key: None,
                private_key: None,
                webhook_signature_key: None,
            },
        }
    }

    #[test]
    fn exact_boxtal_scope_and_bounded_credentials_are_accepted() {
        assert!(validate(&body()).is_ok());
    }

    #[test]
    fn credential_values_cannot_inject_multiline_secret_files() {
        let mut request = body();
        request.credentials.webhook_secret = Some(format!("{}\nleak", "w".repeat(24)));
        assert!(validate(&request).is_err());
    }

    #[test]
    fn exact_sendcloud_scope_and_optional_webhook_key_are_accepted() {
        let request = CarrierSecretBody {
            provider: "sendcloud".into(),
            environment: "test".into(),
            company_id: 1,
            carrier_id: 2,
            credentials: CarrierCredentials {
                access_key: None,
                secret_key: None,
                webhook_secret: None,
                public_key: Some("public-key".into()),
                private_key: Some("p".repeat(24)),
                webhook_signature_key: Some("w".repeat(24)),
            },
        };
        assert!(validate(&request).is_ok());
    }

    #[test]
    fn unknown_provider_or_environment_fails_closed() {
        let mut request = body();
        request.provider = "other".into();
        assert!(validate(&request).is_err());
        request.provider = "boxtal".into();
        request.environment = "production-copy".into();
        assert!(validate(&request).is_err());
    }

    #[test]
    fn storage_reference_must_belong_to_the_exact_workshop_scope() {
        let workshop = Uuid::new_v4();
        let secret = Uuid::new_v4();
        assert_eq!(
            parse_storage_id(&format!("docker/{workshop}/carrier/{secret}"), workshop),
            Some(secret)
        );
        assert_eq!(
            parse_storage_id(
                &format!("docker/{}/carrier/{secret}", Uuid::new_v4()),
                workshop
            ),
            None
        );
    }

    #[test]
    fn credential_resolution_purposes_are_bound_to_exact_lifecycle_states() {
        assert_eq!(
            resolve_lifecycle_scope("provider_operation"),
            Some((vec!["active".into()], vec!["enabled".into()]))
        );
        assert_eq!(
            resolve_lifecycle_scope("tracking_lookup"),
            Some((
                vec!["active".into()],
                vec!["enabled".into(), "restricted".into()]
            ))
        );
        assert_eq!(
            resolve_lifecycle_scope("webhook_reactivation"),
            Some((vec!["suspended".into()], vec!["installing".into()]))
        );
        assert_eq!(resolve_lifecycle_scope("credential_export"), None);
    }
}
