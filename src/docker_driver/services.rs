use super::*;

use crate::outbound_http::TraceRequestBuilderExt as _;

pub(super) async fn ensure_redis_acl(
    address: &str,
    username: &str,
    password: &str,
    prefix: &str,
) -> Result<(), DriverError> {
    if let Some(path) = address.strip_prefix("unix:") {
        let mut stream = tokio::net::UnixStream::connect(path)
            .await
            .map_err(DriverError::internal)?;
        return send_redis_acl(&mut stream, username, password, prefix).await;
    }
    let mut stream = tokio::net::TcpStream::connect(address)
        .await
        .map_err(DriverError::internal)?;
    send_redis_acl(&mut stream, username, password, prefix).await
}

async fn send_redis_acl<S>(
    stream: &mut S,
    username: &str,
    password: &str,
    prefix: &str,
) -> Result<(), DriverError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let arguments = redis_acl_arguments(username, password, prefix);
    let mut command = format!("*{}\r\n", arguments.len());
    for argument in arguments {
        command.push_str(&format!("${}\r\n{}\r\n", argument.len(), argument));
    }
    stream
        .write_all(command.as_bytes())
        .await
        .map_err(DriverError::internal)?;
    let mut response = [0_u8; 128];
    let count = stream
        .read(&mut response)
        .await
        .map_err(DriverError::internal)?;
    if !response[..count].starts_with(b"+OK") {
        return Err(DriverError::internal("Redis rejected tenant ACL"));
    }
    Ok(())
}

pub(super) fn redis_acl_arguments(username: &str, password: &str, prefix: &str) -> Vec<String> {
    vec![
        "ACL".into(),
        "SETUSER".into(),
        username.into(),
        "reset".into(),
        "on".into(),
        format!(">{password}"),
        format!("~{prefix}*"),
        format!("&{prefix}*"),
        // Redis checks a PSUBSCRIBE pattern literally against ACL channel
        // patterns, so the Celery pidbox subscription needs its own rule.
        format!("&{prefix}/0.celery.pidbox"),
        "+@all".into(),
        // Paperless/Celery needs ordinary data, transaction, Pub/Sub and Lua
        // commands. It must never be able to alter shared Redis configuration,
        // ACL users, persistence, replication, or another tenant's database.
        "-@admin".into(),
        "-@dangerous".into(),
        "+eval".into(),
        "+eval_ro".into(),
        "+evalsha".into(),
        "+evalsha_ro".into(),
        "+script|exists".into(),
        "+script|load".into(),
        "+script|kill".into(),
    ]
}

pub(super) async fn ensure_oidc_clients(
    state: &DriverState,
    tenant_key: &str,
    odoo_hostname: &str,
    paperless_hostname: Option<&str>,
) -> Result<(String, Option<(String, String)>), DriverError> {
    let odoo_id = format!("mb-odoo-{tenant_key}");
    let odoo_origin = state.config.public_origin(odoo_hostname);
    ensure_rauthy_client(
        state,
        &odoo_id,
        "MakersBrain Odoo",
        false,
        &format!("{odoo_origin}/auth_oauth/signin"),
        &format!("{odoo_origin}/web/login"),
    )
    .await?;
    let Some(paperless_hostname) = paperless_hostname else {
        return Ok((odoo_id, None));
    };
    let paperless_id = format!("mb-paperless-{tenant_key}");
    let paperless_origin = state.config.public_origin(paperless_hostname);
    ensure_rauthy_client(
        state,
        &paperless_id,
        "MakersBrain Documents",
        true,
        &format!("{paperless_origin}/accounts/oidc/rauthy/login/callback/"),
        &format!("{paperless_origin}/"),
    )
    .await?;
    let response = state
        .rauthy
        .post(format!(
            "{}/clients/{paperless_id}/secret",
            state.config.rauthy_admin_url
        ))
        .json(&json!({}))
        .with_current_trace_context()
        .send()
        .await
        .map_err(DriverError::internal)?;
    if !response.status().is_success() {
        return Err(DriverError::internal(format!(
            "Rauthy secret endpoint returned {}",
            response.status()
        )));
    }
    let secret = response
        .json::<Value>()
        .await
        .map_err(DriverError::internal)?
        .get("secret")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| DriverError::internal("Rauthy did not return a client secret"))?;
    Ok((odoo_id, Some((paperless_id, secret))))
}

pub(super) async fn ensure_rauthy_client(
    state: &DriverState,
    id: &str,
    name: &str,
    confidential: bool,
    redirect: &str,
    logout: &str,
) -> Result<(), DriverError> {
    let endpoint = format!("{}/clients/{id}", state.config.rauthy_admin_url);
    let response = state
        .rauthy
        .get(&endpoint)
        .with_current_trace_context()
        .send()
        .await
        .map_err(DriverError::internal)?;
    if response.status() == StatusCode::NOT_FOUND {
        let response = state
            .rauthy
            .post(format!("{}/clients", state.config.rauthy_admin_url))
            .json(&json!({"id":id,"name":name,"confidential":confidential,"redirect_uris":[redirect],"post_logout_redirect_uris":[logout]}))
            .with_current_trace_context()
            .send().await.map_err(DriverError::internal)?;
        if !response.status().is_success() {
            return Err(DriverError::internal(format!(
                "Rauthy client create returned {}",
                response.status()
            )));
        }
    } else if !response.status().is_success() {
        return Err(DriverError::internal(format!(
            "Rauthy client lookup returned {}",
            response.status()
        )));
    }
    let origin = Url::parse(redirect)
        .map_err(DriverError::internal)?
        .origin()
        .ascii_serialization();
    let response = state.rauthy.put(endpoint).json(&json!({
        "name":name,"confidential":confidential,"redirect_uris":[redirect],
        "post_logout_redirect_uris":[logout],"allowed_origins":[origin],"enabled":true,
        "flows_enabled":["authorization_code","refresh_token"],"access_token_alg":"RS256",
        // The MakersBrain code-flow adapter and centralized verifier accept RS256 only.
        "id_token_alg":"RS256","auth_code_lifetime":60,"access_token_lifetime":300,
        "scopes":["openid","profile","email"],"default_scopes":["openid","profile","email"],
        "challenges":["S256"],"force_mfa":false,"client_uri":origin,
        "contacts":null,"backchannel_logout_uri":null,"restrict_group_prefix":null,
        "claims":null,"claims_at_root":false,"allowed_resources":null,"default_aud":null,"scim":null
    })).with_current_trace_context().send().await.map_err(DriverError::internal)?;
    if !response.status().is_success() {
        return Err(DriverError::internal(format!(
            "Rauthy client update returned {}",
            response.status()
        )));
    }
    Ok(())
}

pub(super) async fn ensure_odoo_database(
    state: &DriverState,
    database_ref: &str,
    tenant_key: &str,
) -> Result<(), DriverError> {
    let (image, extension_volume) = active_odoo_artifacts(state).await?;
    let container = state
        .config
        .docker_resource(format!("odoo-init-{tenant_key}"));
    if docker_container_exists(state, &container).await? {
        let _ = docker_delete_container(state, &container).await;
    }
    run_docker_job_with_secrets(
        state,
        &container,
        json!({
            "Image":image,
            "Cmd":["odoo","--database",database_ref,"--stop-after-init","--no-http","--no-database-list","--addons-path=/opt/mb-extension/addons,/usr/lib/python3/dist-packages/odoo/addons","--init=mb_control_bridge,mb_brand,mb_workshop_pos,l10n_fr_micro_enterprise","--update=mb_control_bridge","--without-demo=all"],
            "Env":[
                format!("MB_ODOO_DATABASE={database_ref}"),
                format!("HOST={}",state.config.postgres_host),
                format!("PORT={}",state.config.postgres_port),
                "USER=odoo",
                "ODOO_RC=/run/mb-job-secrets/odoo.conf",
                "PYTHONPATH=/opt/mb-extension/python",
                "MB_CONTROL_BRIDGE_TOKEN_FILE=/run/mb-job-secrets/bridge-token"
            ],
            "Labels":{"mb.kind":"odoo-init"},
            "HostConfig":{"NetworkMode":state.config.docker_network,"ReadonlyRootfs":true,"CapDrop":["ALL"],"Tmpfs":{"/tmp":"rw,noexec,nosuid,size=64m","/var/run/odoo":"rw,noexec,nosuid,size=16m"},"Binds":[format!("{}:/var/lib/odoo",state.config.odoo_volume),format!("{extension_volume}:/opt/mb-extension:ro")]}
        }),
        &[
            ("odoo.conf", &super::release::odoo_configuration(state, "odoo", &state.config.odoo_postgres_password)?),
            ("bridge-token", state.config.odoo_bridge_token.as_str()),
        ],
    )
    .await?;
    Ok(())
}

async fn active_odoo_artifacts(state: &DriverState) -> Result<(String, String), DriverError> {
    let (manifest_value, slot_runtime_subject, slot_extension_subject, extension_volume) =
        sqlx::query_as::<_, (Value, String, String, String)>(
            "select r.manifest,s.odoo_subject_digest,s.extension_subject_digest,s.extension_volume
             from control.application_releases r
             join control.runtime_release_slots s on s.release_id=r.id
             where r.status='active' and s.runtime_key='shared-odoo' and s.state='active'",
        )
        .fetch_optional(&state.ledger)
        .await
        .map_err(DriverError::internal)?
        .ok_or_else(|| DriverError::bad("Odoo provisioning requires an active paired release"))?;
    let manifest: crate::release::ApplicationReleaseManifest =
        serde_json::from_value(manifest_value)
            .map_err(|_| DriverError::internal("active application release manifest is invalid"))?;
    manifest
        .validate()
        .map_err(|_| DriverError::internal("active application release manifest is invalid"))?;
    if manifest.odoo_runtime.subject_digest != slot_runtime_subject
        || manifest.extension_bundle.subject_digest != slot_extension_subject
    {
        return Err(DriverError::internal(
            "active runtime slot does not match its paired release",
        ));
    }
    Ok((manifest.odoo_runtime.deployment_ref, extension_volume))
}

pub(super) async fn ensure_odoo_break_glass(
    state: &DriverState,
    workshop: Uuid,
    database_ref: &str,
    tenant_key: &str,
) -> Result<(), DriverError> {
    let (image, extension_volume) = active_odoo_artifacts(state).await?;
    let container = state
        .config
        .docker_resource(format!("odoo-break-glass-{tenant_key}"));
    if docker_container_exists(state, &container).await? {
        let _ = docker_delete_container(state, &container).await;
    }
    run_docker_job_with_secrets(
        state,
        &container,
        json!({
            "Image":image,
            "Cmd":[
                "/bin/sh",
                "-ec",
                "odoo shell --database=\"$MB_ODOO_DATABASE\" --no-http --addons-path=/opt/mb-extension/addons,/usr/lib/python3/dist-packages/odoo/addons < /opt/mb-extension/addons/mb_control_bridge/scripts/set_break_glass_password.py"
            ],
            "Env":[
                format!("MB_ODOO_DATABASE={database_ref}"),
                format!("HOST={}",state.config.postgres_host),
                format!("PORT={}",state.config.postgres_port),
                "USER=odoo",
                "ODOO_RC=/run/mb-job-secrets/odoo.conf",
                "PYTHONPATH=/opt/mb-extension/python",
                "MB_BREAK_GLASS_PASSWORD_FILE=/run/mb-odoo-secrets/admin-password"
            ],
            "Labels":{"mb.kind":"odoo-break-glass"},
            "HostConfig":{
                "NetworkMode":state.config.docker_network,
                "GroupAdd":["0"],
                "ReadonlyRootfs":true,"CapDrop":["ALL"],"Tmpfs":{"/tmp":"rw,noexec,nosuid,size=64m","/var/run/odoo":"rw,noexec,nosuid,size=16m"},
                "Binds":[format!("{}:/var/lib/odoo",state.config.odoo_volume),format!("{extension_volume}:/opt/mb-extension:ro")],
                "Mounts":[runtime_secret_mount(
                    state,
                    &PathBuf::from("odoo").join(workshop.to_string()),
                    "/run/mb-odoo-secrets",
                )?]
            }
        }),
        &[("odoo.conf", &super::release::odoo_configuration(state, "odoo", &state.config.odoo_postgres_password)?)],
    )
    .await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn ensure_paperless(
    state: &DriverState,
    workshop: Uuid,
    container: &str,
    database: &str,
    role: &str,
    database_password: &str,
    admin_password: &str,
    secret_key: &str,
    redis_user: &str,
    redis_password: &str,
    redis_prefix: &str,
    oidc_client_id: &str,
    oidc_secret: &str,
    tenant_bridge_token: &str,
    public_hostname: &str,
) -> Result<(), DriverError> {
    let paperless_image = state
        .config
        .paperless_image
        .as_deref()
        .ok_or_else(|| DriverError::bad("Paperless is not configured for this deployment"))?;
    for suffix in ["data", "media", "consume"] {
        let volume = state
            .config
            .docker_resource(format!("paperless-{workshop}-{suffix}"));
        match &state.backend {
            RuntimeBackend::Docker => docker_create_volume(state, &volume).await?,
            RuntimeBackend::Quadlet(backend) => backend.ensure_volume(&volume).await?,
        }
    }
    let providers = json!({"openid_connect":{"APPS":[{"provider_id":"rauthy","name":"MakersBrain","client_id":oidc_client_id,"secret":oidc_secret,"settings":{"server_url":format!("{}/.well-known/openid-configuration",state.config.oidc_issuer),"oauth_pkce_enabled":true,"email_authentication":true}}]}}).to_string();
    let tenant_secret_dir = driver_runtime_secret_root(state)
        .join("paperless")
        .join(workshop.to_string());
    secure_directory(&tenant_secret_dir).map_err(DriverError::internal)?;
    for (name, value) in [
        ("database-password", database_password),
        ("secret-key", secret_key),
        ("admin-password", admin_password),
        ("webhook-secret", tenant_bridge_token),
    ] {
        write_secret(&tenant_secret_dir.join(name), value).map_err(DriverError::internal)?;
    }
    write_secret(
        &tenant_secret_dir.join("redis-url"),
        &format!(
            "redis://{redis_user}:{redis_password}@{}",
            state.config.redis_address
        ),
    )
    .map_err(DriverError::internal)?;
    write_secret(&tenant_secret_dir.join("providers"), &providers)
        .map_err(DriverError::internal)?;
    let public_origin = state.config.public_origin(public_hostname);
    let mut environment = vec![
        "PAPERLESS_REDIS_FILE=/run/mb-secrets/redis-url".into(),
        format!("PAPERLESS_REDIS_PREFIX={redis_prefix}"),
        "PAPERLESS_DBENGINE=postgresql".into(),
        format!("PAPERLESS_DBHOST={}", state.config.postgres_host),
        format!("PAPERLESS_DBPORT={}", state.config.postgres_port),
        format!("PAPERLESS_DBNAME={database}"),
        format!("PAPERLESS_DBUSER={role}"),
        "PAPERLESS_DBPASS_FILE=/run/mb-secrets/database-password".into(),
        "PAPERLESS_SECRET_KEY_FILE=/run/mb-secrets/secret-key".into(),
        format!("PAPERLESS_URL={public_origin}"),
        "PAPERLESS_TIME_ZONE=Europe/Paris".into(),
        "PAPERLESS_OCR_LANGUAGE=fra+eng".into(),
        "PAPERLESS_APPS=allauth.socialaccount.providers.openid_connect".into(),
        "PAPERLESS_SOCIALACCOUNT_PROVIDERS_FILE=/run/mb-secrets/providers".into(),
        "PAPERLESS_DISABLE_REGULAR_LOGIN=true".into(),
        "PAPERLESS_REDIRECT_LOGIN_TO_SSO=true".into(),
        "PAPERLESS_SOCIAL_AUTO_SIGNUP=false".into(),
        "PAPERLESS_ADMIN_USER=local-admin".into(),
        "PAPERLESS_ADMIN_PASSWORD_FILE=/run/mb-secrets/admin-password".into(),
        "PAPERLESS_POST_CONSUME_SCRIPT=/usr/src/paperless/post-consume.py".into(),
        "PAPERLESS_WEBHOOK_SECRET_FILE=/run/mb-secrets/webhook-secret".into(),
        format!("MAKERSBRAIN_WORKSHOP_ID={workshop}"),
        format!(
            "MAKERSBRAIN_CONTROL_URL={}",
            state.config.control_internal_url
        ),
    ];
    let mut mounts = vec![runtime_secret_mount(
        state,
        &PathBuf::from("paperless").join(workshop.to_string()),
        "/run/mb-secrets",
    )?];
    if let Some(ca_mount) = postgres_ca_mount(state)? {
        environment.push(
            "PAPERLESS_DB_OPTIONS=sslmode=verify-full,sslrootcert=/run/mb-postgres-ca/postgres-ca.crt"
                .into(),
        );
        mounts.push(ca_mount);
    }
    let config_digest = format!(
        "{:x}",
        Sha256::digest(
            serde_json::to_vec(&(
                "paperless-secret-boundary-v2",
                &state.config.runtime_secret_source,
                paperless_image,
                &environment,
                database_password,
                admin_password,
                secret_key,
                redis_password,
                oidc_secret,
                tenant_bridge_token,
            ))
            .map_err(DriverError::internal)?
        )
    );
    if let RuntimeBackend::Quadlet(backend) = &state.backend {
        let environment = environment
            .iter()
            .map(|entry| {
                entry
                    .split_once('=')
                    .map(|(key, value)| (key.to_owned(), value.to_owned()))
                    .ok_or_else(|| DriverError::internal("invalid Paperless environment entry"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        backend
            .ensure_paperless(&PaperlessDesired {
                workshop,
                container_name: container.to_owned(),
                image: paperless_image.to_owned(),
                config_digest: config_digest.clone(),
                environment,
                secret_directory: tenant_secret_dir,
                volumes: ["data", "media", "consume"]
                    .map(|suffix| {
                        (
                            state
                                .config
                                .docker_resource(format!("paperless-{workshop}-{suffix}")),
                            format!("/usr/src/paperless/{suffix}"),
                        )
                    })
                    .to_vec(),
                network: state.config.docker_network.clone(),
            })
            .await?;
        persist_paperless_runtime_spec(
            state,
            workshop,
            container,
            paperless_image,
            &config_digest,
            database,
            role,
            redis_user,
            public_hostname,
        )
        .await?;
        return Ok(());
    }
    if docker_container_exists(state, container).await? {
        let inspect = docker_inspect_container(state, container).await?;
        let current_digest = inspect
            .pointer("/Config/Labels/mb.config-digest")
            .and_then(Value::as_str);
        if current_digest != Some(&config_digest) {
            docker_delete_container(state, container).await?;
        } else {
            if inspect.pointer("/State/Running").and_then(Value::as_bool) != Some(true) {
                docker_start_container(state, container).await?;
            }
            wait_for_healthy_container(state, container, "Paperless").await?;
            persist_paperless_runtime_spec(
                state,
                workshop,
                container,
                paperless_image,
                &config_digest,
                database,
                role,
                redis_user,
                public_hostname,
            )
            .await?;
            return Ok(());
        }
    }
    docker_create_container(
        state,
        container,
        DockerRestartPolicy::UnlessStopped,
        json!({
            "Image":paperless_image,
            "Env":environment,
            "Labels":{"mb.kind":"paperless","mb.workshop":workshop.to_string(),"mb.config-digest":config_digest},
            "HostConfig":{
                "NetworkMode":state.config.docker_network,
                "Binds":[format!("{}:/usr/src/paperless/data",state.config.docker_resource(format!("paperless-{workshop}-data"))),format!("{}:/usr/src/paperless/media",state.config.docker_resource(format!("paperless-{workshop}-media"))),format!("{}:/usr/src/paperless/consume",state.config.docker_resource(format!("paperless-{workshop}-consume")))],
                "GroupAdd":["0"],
                "Mounts":mounts
            }
        }),
    )
    .await?;
    docker_start_container(state, container).await?;
    wait_for_healthy_container(state, container, "Paperless").await?;
    persist_paperless_runtime_spec(
        state,
        workshop,
        container,
        paperless_image,
        &config_digest,
        database,
        role,
        redis_user,
        public_hostname,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn persist_paperless_runtime_spec(
    state: &DriverState,
    workshop: Uuid,
    container: &str,
    image: &str,
    config_digest: &str,
    database_ref: &str,
    database_role: &str,
    redis_identity: &str,
    public_hostname: &str,
) -> Result<(), DriverError> {
    let volumes = ["data", "media", "consume"]
        .map(|suffix| {
            state
                .config
                .docker_resource(format!("paperless-{workshop}-{suffix}"))
        })
        .to_vec();
    let result = sqlx::query(
        "update control.service_instances set runtime_spec=$2
          where workshop_id=$1 and service='paperless'",
    )
    .bind(workshop)
    .bind(json!({
        "version": 1,
        "image": image,
        "config_digest": config_digest,
        "container_name": container,
        "database_ref": database_ref,
        "database_role": database_role,
        "redis_identity": redis_identity,
        "public_hostname": public_hostname,
        "volumes": volumes,
    }))
    .execute(&state.ledger)
    .await
    .map_err(DriverError::internal)?;
    if result.rows_affected() != 1 {
        return Err(DriverError::internal(
            "Paperless service instance is missing while persisting runtime specification",
        ));
    }
    Ok(())
}

pub(super) async fn wait_for_healthy_container(
    state: &DriverState,
    container: &str,
    label: &str,
) -> Result<(), DriverError> {
    for _ in 0..90 {
        let inspect = docker_inspect_container(state, container).await?;
        let health = inspect
            .pointer("/State/Health/Status")
            .and_then(Value::as_str);
        if health == Some("healthy") {
            return Ok(());
        }
        if inspect.pointer("/State/Running").and_then(Value::as_bool) == Some(false) {
            return Err(DriverError::internal(format!(
                "{label} stopped during startup"
            )));
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    Err(DriverError::internal(format!("{label} health timeout")))
}
