use super::*;

pub(super) async fn ensure_redis_acl(
    address: &str,
    username: &str,
    password: &str,
    prefix: &str,
) -> Result<(), DriverError> {
    let mut stream = tokio::net::TcpStream::connect(address)
        .await
        .map_err(DriverError::internal)?;
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
        .send()
        .await
        .map_err(DriverError::internal)?;
    if response.status() == StatusCode::NOT_FOUND {
        let response = state
            .rauthy
            .post(format!("{}/clients", state.config.rauthy_admin_url))
            .json(&json!({"id":id,"name":name,"confidential":confidential,"redirect_uris":[redirect],"post_logout_redirect_uris":[logout]}))
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
        // The pinned OCA auth_oidc verifier intentionally accepts RS256 only.
        "id_token_alg":"RS256","auth_code_lifetime":60,"access_token_lifetime":300,
        "scopes":["openid","profile","email"],"default_scopes":["openid","profile","email"],
        "challenges":["S256"],"force_mfa":false,"client_uri":origin,
        "contacts":null,"backchannel_logout_uri":null,"restrict_group_prefix":null,
        "claims":null,"claims_at_root":false,"allowed_resources":null,"default_aud":null,"scim":null
    })).send().await.map_err(DriverError::internal)?;
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
    let container = format!("mb-odoo-init-{tenant_key}");
    if docker_container_exists(state, &container).await? {
        let _ = docker_delete_container(state, &container).await;
    }
    run_docker_job_with_secrets(
        state,
        &container,
        json!({
            "Image":state.config.odoo_image,
            "Cmd":["/bin/sh","-ec","password=$(cat /run/mb-job-secrets/postgres-password); export MB_CONTROL_BRIDGE_TOKEN=$(cat /run/mb-job-secrets/bridge-token); exec odoo --database=\"$MB_ODOO_DATABASE\" --stop-after-init --no-database-list --db_host=\"$HOST\" --db_port=\"$PORT\" --db_user=odoo --db_password=\"$password\" --addons-path=/mnt/mb-addons,/mnt/oca-addons,/usr/lib/python3/dist-packages/odoo/addons --init=auth_oidc,mb_control_bridge,mb_brand,mb_workshop_pos,l10n_fr_micro_enterprise --update=mb_control_bridge --without-demo=all"],
            "Env":[
                format!("MB_ODOO_DATABASE={database_ref}"),
                format!("HOST={}",state.config.postgres_host),
                format!("PORT={}",state.config.postgres_port),
                "USER=odoo"
            ],
            "Labels":{"mb.kind":"odoo-init"},
            "HostConfig":{"NetworkMode":state.config.docker_network,"Binds":[format!("{}:/var/lib/odoo",state.config.odoo_volume)]}
        }),
        &[
            ("postgres-password", state.config.odoo_postgres_password.as_str()),
            ("bridge-token", state.config.odoo_bridge_token.as_str()),
        ],
    )
    .await?;
    Ok(())
}

pub(super) async fn ensure_odoo_break_glass(
    state: &DriverState,
    workshop: Uuid,
    database_ref: &str,
    tenant_key: &str,
) -> Result<(), DriverError> {
    let container = format!("mb-odoo-break-glass-{tenant_key}");
    if docker_container_exists(state, &container).await? {
        let _ = docker_delete_container(state, &container).await;
    }
    run_docker_job_with_secrets(
        state,
        &container,
        json!({
            "Image":state.config.odoo_image,
            "Cmd":[
                "/bin/sh",
                "-ec",
                "password=$(cat /run/mb-job-secrets/postgres-password); exec odoo shell --database=\"$MB_ODOO_DATABASE\" --no-http --db_host=\"$HOST\" --db_port=\"$PORT\" --db_user=\"$USER\" --db_password=\"$password\" --addons-path=/mnt/mb-addons,/mnt/oca-addons,/usr/lib/python3/dist-packages/odoo/addons < /mnt/mb-addons/mb_control_bridge/scripts/set_break_glass_password.py"
            ],
            "Env":[
                format!("MB_ODOO_DATABASE={database_ref}"),
                format!("HOST={}",state.config.postgres_host),
                format!("PORT={}",state.config.postgres_port),
                "USER=odoo",
                "MB_BREAK_GLASS_PASSWORD_FILE=/run/mb-odoo-secrets/admin-password"
            ],
            "Labels":{"mb.kind":"odoo-break-glass"},
            "HostConfig":{
                "NetworkMode":state.config.docker_network,
                "GroupAdd":["0"],
                "Binds":[format!("{}:/var/lib/odoo",state.config.odoo_volume)],
                "Mounts":[runtime_secret_mount(
                    state,
                    &PathBuf::from("odoo").join(workshop.to_string()),
                    "/run/mb-odoo-secrets",
                )?]
            }
        }),
        &[("postgres-password", state.config.odoo_postgres_password.as_str())],
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
        docker_create_volume(state, &format!("mb-paperless-{workshop}-{suffix}")).await?;
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
            return wait_for_healthy_container(state, container, "Paperless").await;
        }
    }
    docker_create_container(
        state,
        container,
        json!({
            "Image":paperless_image,
            "Env":environment,
            "Labels":{"mb.kind":"paperless","mb.workshop":workshop.to_string(),"mb.config-digest":config_digest},
            "HostConfig":{
                "NetworkMode":state.config.docker_network,
                "Binds":[format!("mb-paperless-{workshop}-data:/usr/src/paperless/data"),format!("mb-paperless-{workshop}-media:/usr/src/paperless/media"),format!("mb-paperless-{workshop}-consume:/usr/src/paperless/consume")],
                "GroupAdd":["0"],
                "Mounts":mounts
            }
        }),
    )
    .await?;
    docker_start_container(state, container).await?;
    wait_for_healthy_container(state, container, "Paperless").await
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
