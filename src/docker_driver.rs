use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Path as AxumPath, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use rand::distr::{Alphanumeric, SampleString};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPoolOptions;
use sqlx::{AssertSqlSafe, PgPool, Row};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use url::Url;
use uuid::Uuid;

#[derive(Clone)]
pub struct DockerDriverConfig {
    pub listen: SocketAddr,
    token: String,
    docker_socket: PathBuf,
    database_url: String,
    postgres_admin_url: String,
    postgres_host: String,
    postgres_port: u16,
    odoo_postgres_password: String,
    odoo_bridge_token: String,
    odoo_image: String,
    paperless_image: String,
    docker_network: String,
    odoo_volume: String,
    redis_address: String,
    secret_root: PathBuf,
    route_root: PathBuf,
    gateway_container: String,
    odoo_base_url: String,
    control_internal_url: String,
    control_internal_token: String,
    rauthy_admin_url: String,
    rauthy_admin_key: String,
    oidc_issuer: String,
}

impl DockerDriverConfig {
    pub fn from_env() -> anyhow::Result<Self> {
        Ok(Self {
            listen: required("DRIVER_LISTEN")?.parse()?,
            token: required("DRIVER_TOKEN")?,
            docker_socket: required("DRIVER_DOCKER_SOCKET")?.into(),
            database_url: required("DRIVER_DATABASE_URL")?,
            postgres_admin_url: required("DRIVER_POSTGRES_ADMIN_URL")?,
            postgres_host: required("DRIVER_POSTGRES_HOST")?,
            postgres_port: required("DRIVER_POSTGRES_PORT")?.parse()?,
            odoo_postgres_password: required("DRIVER_ODOO_POSTGRES_PASSWORD")?,
            odoo_bridge_token: required("DRIVER_ODOO_BRIDGE_TOKEN")?,
            odoo_image: required("DRIVER_ODOO_IMAGE")?,
            paperless_image: required("DRIVER_PAPERLESS_IMAGE")?,
            docker_network: required("DRIVER_DOCKER_NETWORK")?,
            odoo_volume: required("DRIVER_ODOO_VOLUME")?,
            redis_address: required("DRIVER_REDIS_ADDRESS")?,
            secret_root: required("DRIVER_SECRET_ROOT")?.into(),
            route_root: required("DRIVER_ROUTE_ROOT")?.into(),
            gateway_container: required("DRIVER_GATEWAY_CONTAINER")?,
            odoo_base_url: absolute_http("DRIVER_ODOO_BASE_URL")?,
            control_internal_url: absolute_http("DRIVER_CONTROL_INTERNAL_URL")?,
            control_internal_token: required("DRIVER_CONTROL_INTERNAL_TOKEN")?,
            rauthy_admin_url: absolute_http("DRIVER_RAUTHY_ADMIN_URL")?,
            rauthy_admin_key: required("DRIVER_RAUTHY_ADMIN_KEY")?,
            oidc_issuer: absolute_http("DRIVER_OIDC_ISSUER")?,
        })
    }
}

fn required(name: &'static str) -> anyhow::Result<String> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("{name} is required"))
}

fn absolute_http(name: &'static str) -> anyhow::Result<String> {
    let value = required(name)?;
    let url = Url::parse(&value)?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        anyhow::bail!("{name} must be an absolute HTTP(S) URL");
    }
    Ok(value.trim_end_matches('/').to_owned())
}

#[derive(Clone)]
struct DriverState {
    config: DockerDriverConfig,
    ledger: PgPool,
    postgres: PgPool,
    docker: reqwest::Client,
    rauthy: reqwest::Client,
    serial: Arc<Mutex<()>>,
}

pub async fn app(config: DockerDriverConfig) -> anyhow::Result<Router> {
    std::fs::create_dir_all(&config.secret_root)?;
    std::fs::create_dir_all(&config.route_root)?;
    let ledger = PgPoolOptions::new()
        .max_connections(5)
        .connect(&config.database_url)
        .await?;
    let postgres = PgPoolOptions::new()
        .max_connections(2)
        .connect(&config.postgres_admin_url)
        .await?;
    let docker = reqwest::Client::builder()
        .unix_socket(config.docker_socket.clone())
        .timeout(Duration::from_secs(180))
        .build()?;
    let mut authorization =
        reqwest::header::HeaderValue::from_str(&format!("API-Key {}", config.rauthy_admin_key))?;
    authorization.set_sensitive(true);
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(reqwest::header::AUTHORIZATION, authorization);
    let rauthy = reqwest::Client::builder()
        .default_headers(headers)
        .timeout(Duration::from_secs(30))
        .build()?;
    let state = Arc::new(DriverState {
        config,
        ledger,
        postgres,
        docker,
        rauthy,
        serial: Arc::new(Mutex::new(())),
    });
    Ok(Router::new()
        .route("/health/live", get(|| async { "live" }))
        .route("/v1/tenants/{workshop}/{action}", post(tenant))
        .with_state(state))
}

#[derive(Debug)]
struct DriverError(StatusCode, String);

impl DriverError {
    fn bad(message: impl Into<String>) -> Self {
        Self(StatusCode::BAD_REQUEST, message.into())
    }
    fn internal(error: impl std::fmt::Display) -> Self {
        tracing::error!(error = %error, "Docker deployment operation failed");
        Self(
            StatusCode::SERVICE_UNAVAILABLE,
            "deployment backend unavailable".into(),
        )
    }
}

impl IntoResponse for DriverError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({"error": self.1}))).into_response()
    }
}

async fn tenant(
    State(state): State<Arc<DriverState>>,
    AxumPath((workshop, action)): AxumPath<(Uuid, String)>,
    headers: HeaderMap,
    Json(payload): Json<Value>,
) -> Result<Json<Value>, DriverError> {
    if headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        != Some(&format!("Bearer {}", state.config.token))
    {
        return Err(DriverError(StatusCode::UNAUTHORIZED, "unauthorized".into()));
    }
    if !matches!(action.as_str(), "provision" | "reconcile" | "lifecycle") {
        return Err(DriverError(StatusCode::NOT_FOUND, "unknown action".into()));
    }
    let idempotency_key = headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty() && value.len() <= 180)
        .ok_or_else(|| DriverError::bad("idempotency-key is required"))?;
    let digest = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&payload).unwrap())
    );
    if let Some(row) = sqlx::query(
        "select request_digest,state,response from control.deployment_driver_operations where idempotency_key=$1",
    )
    .bind(idempotency_key)
    .fetch_optional(&state.ledger)
    .await
    .map_err(DriverError::internal)?
    {
        if row.get::<String, _>("request_digest") != digest {
            return Err(DriverError(StatusCode::CONFLICT, "idempotency key reused with different payload".into()));
        }
        if row.get::<String, _>("state") == "succeeded" {
            return Ok(Json(row.get("response")));
        }
    } else {
        sqlx::query("insert into control.deployment_driver_operations(idempotency_key,workshop_id,action,request_digest) values($1,$2,$3,$4)")
            .bind(idempotency_key).bind(workshop).bind(&action).bind(&digest)
            .execute(&state.ledger).await.map_err(DriverError::internal)?;
    }
    let _guard = state.serial.lock().await;
    let result = match action.as_str() {
        "provision" | "reconcile" => provision(&state, workshop, &payload).await,
        "lifecycle" => lifecycle(&state, workshop, &payload).await,
        _ => unreachable!(),
    };
    match result {
        Ok(value) => {
            sqlx::query("update control.deployment_driver_operations set state='succeeded',response=$2,safe_error=null,updated_at=now() where idempotency_key=$1")
                .bind(idempotency_key).bind(&value).execute(&state.ledger).await.map_err(DriverError::internal)?;
            Ok(Json(value))
        }
        Err(error) => {
            sqlx::query("update control.deployment_driver_operations set state='failed',safe_error='deployment_unavailable',updated_at=now() where idempotency_key=$1")
                .bind(idempotency_key).execute(&state.ledger).await.map_err(DriverError::internal)?;
            Err(error)
        }
    }
}

async fn provision(
    state: &DriverState,
    workshop: Uuid,
    payload: &Value,
) -> Result<Value, DriverError> {
    let database_ref = opaque_database(payload, "database_ref")?;
    let odoo_hostname = hostname(payload, "public_hostname")?;
    let paperless_hostname = hostname(payload, "paperless_hostname")?;
    let compact = workshop.simple().to_string();
    let short = &compact[..12];
    let paperless_database = format!("pl_{compact}");
    let paperless_role = paperless_database.clone();
    let paperless_container = format!("mb-paperless-{short}");
    let redis_user = format!("pl_{compact}");
    let redis_prefix = format!("mb:{compact}:");
    let tenant_secret_dir = state
        .config
        .secret_root
        .join("docker")
        .join(workshop.to_string());
    secure_directory(&tenant_secret_dir).map_err(DriverError::internal)?;
    let paperless_admin = secret_value(&tenant_secret_dir.join("paperless-admin"), 64)
        .map_err(DriverError::internal)?;
    let paperless_db_password =
        secret_value(&tenant_secret_dir.join("paperless-db"), 64).map_err(DriverError::internal)?;
    let paperless_secret_key = secret_value(&tenant_secret_dir.join("paperless-secret-key"), 96)
        .map_err(DriverError::internal)?;
    let redis_password =
        secret_value(&tenant_secret_dir.join("redis"), 64).map_err(DriverError::internal)?;
    write_secret(
        &tenant_secret_dir.join("odoo"),
        &state.config.odoo_bridge_token,
    )
    .map_err(DriverError::internal)?;
    write_secret(
        &tenant_secret_dir.join("paperless"),
        &format!("basic:local-admin:{paperless_admin}"),
    )
    .map_err(DriverError::internal)?;

    ensure_database(&state.postgres, database_ref, "odoo", None).await?;
    ensure_database(
        &state.postgres,
        &paperless_database,
        &paperless_role,
        Some(&paperless_db_password),
    )
    .await?;
    ensure_redis_acl(
        &state.config.redis_address,
        &redis_user,
        &redis_password,
        &redis_prefix,
    )
    .await?;
    let (odoo_client_id, paperless_client_id, paperless_oidc_secret) =
        ensure_oidc_clients(state, short, odoo_hostname, paperless_hostname).await?;
    write_secret(
        &tenant_secret_dir.join("paperless-oidc"),
        &paperless_oidc_secret,
    )
    .map_err(DriverError::internal)?;
    ensure_odoo_database(state, database_ref, short).await?;
    ensure_paperless(
        state,
        workshop,
        &paperless_container,
        &paperless_database,
        &paperless_role,
        &paperless_db_password,
        &paperless_admin,
        &paperless_secret_key,
        &redis_user,
        &redis_password,
        &redis_prefix,
        &paperless_client_id,
        &paperless_oidc_secret,
        paperless_hostname,
    )
    .await?;
    write_routes(
        state,
        workshop,
        database_ref,
        odoo_hostname,
        paperless_hostname,
        &paperless_container,
    )
    .await?;
    Ok(json!({
        "workshop_id": workshop,
        "action": "provision",
        "release_id": env!("CARGO_PKG_VERSION"),
        "odoo": {
            "base_url": state.config.odoo_base_url,
            "secret_ref": format!("docker/{workshop}/odoo"),
            "database": {"database_ref": database_ref, "public_hostname": odoo_hostname}
        },
        "paperless": {
            "base_url": format!("http://{paperless_container}:8000"),
            "public_hostname": paperless_hostname,
            "secret_ref": format!("docker/{workshop}/paperless")
        },
        "odoo_oidc": {"client_id": odoo_client_id, "issuer": state.config.oidc_issuer},
        "paperless_oidc": {"client_id": paperless_client_id, "issuer": state.config.oidc_issuer},
        "redis": {"shared": true, "prefix": redis_prefix, "acl_user": redis_user}
    }))
}

async fn lifecycle(
    _state: &DriverState,
    _workshop: Uuid,
    _payload: &Value,
) -> Result<Value, DriverError> {
    Err(DriverError(
        StatusCode::NOT_IMPLEMENTED,
        "Docker lifecycle backend is not implemented yet".into(),
    ))
}

fn opaque_database<'a>(payload: &'a Value, key: &str) -> Result<&'a str, DriverError> {
    let value = payload
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| DriverError::bad(format!("{key} is required")))?;
    if value.len() != 35
        || !value.starts_with("mb_")
        || !value[3..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(DriverError::bad(format!("{key} is invalid")));
    }
    Ok(value)
}

fn hostname<'a>(payload: &'a Value, key: &str) -> Result<&'a str, DriverError> {
    let value = payload
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| DriverError::bad(format!("{key} is required")))?;
    if value.len() > 253
        || value.starts_with('.')
        || value.ends_with('.')
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'.')
        })
    {
        return Err(DriverError::bad(format!("{key} is invalid")));
    }
    Ok(value)
}

fn secure_directory(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
}

fn write_secret(path: &Path, value: &str) -> std::io::Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true).mode(0o600);
    let mut file = options.open(path)?;
    std::io::Write::write_all(&mut file, value.as_bytes())?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

fn secret_value(path: &Path, length: usize) -> std::io::Result<String> {
    if path.exists() {
        return std::fs::read_to_string(path).map(|value| value.trim().to_owned());
    }
    let value = Alphanumeric.sample_string(&mut rand::rng(), length);
    write_secret(path, &value)?;
    Ok(value)
}

async fn ensure_database(
    pool: &PgPool,
    database: &str,
    role: &str,
    password: Option<&str>,
) -> Result<(), DriverError> {
    if !safe_pg_identifier(database) || !safe_pg_identifier(role) {
        return Err(DriverError::bad("unsafe PostgreSQL identifier"));
    }
    let exists: bool = sqlx::query_scalar("select exists(select 1 from pg_roles where rolname=$1)")
        .bind(role)
        .fetch_one(pool)
        .await
        .map_err(DriverError::internal)?;
    if !exists {
        let password = password.ok_or_else(|| DriverError::bad("database role is missing"))?;
        if !password.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
            return Err(DriverError::bad("unsafe generated database password"));
        }
        sqlx::query(AssertSqlSafe(format!(
            "create role \"{role}\" login password '{password}'"
        )))
        .execute(pool)
        .await
        .map_err(DriverError::internal)?;
    }
    let exists: bool =
        sqlx::query_scalar("select exists(select 1 from pg_database where datname=$1)")
            .bind(database)
            .fetch_one(pool)
            .await
            .map_err(DriverError::internal)?;
    if !exists {
        sqlx::query(AssertSqlSafe(format!(
            "create database \"{database}\" owner \"{role}\""
        )))
        .execute(pool)
        .await
        .map_err(DriverError::internal)?;
    }
    Ok(())
}

fn safe_pg_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

async fn ensure_redis_acl(
    address: &str,
    username: &str,
    password: &str,
    prefix: &str,
) -> Result<(), DriverError> {
    let mut stream = tokio::net::TcpStream::connect(address)
        .await
        .map_err(DriverError::internal)?;
    let arguments = [
        "ACL".to_owned(),
        "SETUSER".to_owned(),
        username.to_owned(),
        "reset".to_owned(),
        "on".to_owned(),
        format!(">{password}"),
        format!("~{prefix}*"),
        format!("&{prefix}*"),
        "+@all".to_owned(),
    ];
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

async fn ensure_oidc_clients(
    state: &DriverState,
    short: &str,
    odoo_hostname: &str,
    paperless_hostname: &str,
) -> Result<(String, String, String), DriverError> {
    let odoo_id = format!("makersbrain-odoo-{short}");
    let paperless_id = format!("makersbrain-paperless-{short}");
    ensure_rauthy_client(
        state,
        &odoo_id,
        false,
        &format!("https://{odoo_hostname}/auth_oauth/signin"),
        &format!("https://{odoo_hostname}/web/login"),
    )
    .await?;
    ensure_rauthy_client(
        state,
        &paperless_id,
        true,
        &format!("https://{paperless_hostname}/accounts/oidc/rauthy/login/callback/"),
        &format!("https://{paperless_hostname}/"),
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
    Ok((odoo_id, paperless_id, secret))
}

async fn ensure_rauthy_client(
    state: &DriverState,
    id: &str,
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
            .json(&json!({"id":id,"name":id,"confidential":confidential,"redirect_uris":[redirect],"post_logout_redirect_uris":[logout]}))
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
        "name":id,"confidential":confidential,"redirect_uris":[redirect],
        "post_logout_redirect_uris":[logout],"allowed_origins":[origin],"enabled":true,
        "flows_enabled":["authorization_code","refresh_token"],"access_token_alg":"EdDSA",
        "id_token_alg":"EdDSA","auth_code_lifetime":60,"access_token_lifetime":300,
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

async fn ensure_odoo_database(
    state: &DriverState,
    database_ref: &str,
    short: &str,
) -> Result<(), DriverError> {
    let container = format!("mb-odoo-init-{short}");
    if docker_container_exists(state, &container).await? {
        let _ = docker_delete_container(state, &container).await;
    }
    docker_create_container(
        state,
        &container,
        json!({
            "Image":state.config.odoo_image,
            "Cmd":["odoo",format!("--database={database_ref}"),"--stop-after-init","--no-database-list",format!("--db_host={}",state.config.postgres_host),format!("--db_port={}",state.config.postgres_port),"--db_user=odoo",format!("--db_password={}",state.config.odoo_postgres_password),"--addons-path=/mnt/makersbrain-addons,/mnt/oca-addons,/usr/lib/python3/dist-packages/odoo/addons","--init=auth_oidc,mb_control_bridge,mb_invoice_capture","--without-demo=all"],
            "Env":[format!("MB_CONTROL_BRIDGE_TOKEN={}",state.config.odoo_bridge_token)],
            "Labels":{"makersbrain.kind":"odoo-init"},
            "HostConfig":{"NetworkMode":state.config.docker_network,"Binds":[format!("{}:/var/lib/odoo",state.config.odoo_volume)]}
        }),
    )
    .await?;
    docker_start_container(state, &container).await?;
    let code = docker_wait_container(state, &container).await?;
    let _ = docker_delete_container(state, &container).await;
    if code != 0 {
        return Err(DriverError::internal(format!(
            "Odoo initializer exited with {code}"
        )));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn ensure_paperless(
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
    public_hostname: &str,
) -> Result<(), DriverError> {
    if docker_container_exists(state, container).await? {
        return Ok(());
    }
    for suffix in ["data", "media", "consume"] {
        docker_create_volume(state, &format!("mb-paperless-{workshop}-{suffix}")).await?;
    }
    let providers = json!({"openid_connect":{"APPS":[{"provider_id":"rauthy","name":"MakersBrain","client_id":oidc_client_id,"secret":oidc_secret,"settings":{"server_url":format!("{}/.well-known/openid-configuration",state.config.oidc_issuer)}}]}}).to_string();
    docker_create_container(
        state,
        container,
        json!({
            "Image":state.config.paperless_image,
            "Env":[
                format!("PAPERLESS_REDIS=redis://{redis_user}:{redis_password}@{}",state.config.redis_address),
                format!("PAPERLESS_REDIS_PREFIX={redis_prefix}"),format!("PAPERLESS_DBHOST={}",state.config.postgres_host),format!("PAPERLESS_DBPORT={}",state.config.postgres_port),format!("PAPERLESS_DBNAME={database}"),format!("PAPERLESS_DBUSER={role}"),format!("PAPERLESS_DBPASS={database_password}"),format!("PAPERLESS_SECRET_KEY={secret_key}"),format!("PAPERLESS_URL=https://{public_hostname}"),"PAPERLESS_TIME_ZONE=Europe/Paris","PAPERLESS_OCR_LANGUAGE=fra+eng","PAPERLESS_APPS=allauth.socialaccount.providers.openid_connect",format!("PAPERLESS_SOCIALACCOUNT_PROVIDERS={providers}"),"PAPERLESS_DISABLE_REGULAR_LOGIN=true","PAPERLESS_REDIRECT_LOGIN_TO_SSO=true","PAPERLESS_SOCIAL_AUTO_SIGNUP=false","PAPERLESS_ADMIN_USER=local-admin",format!("PAPERLESS_ADMIN_PASSWORD={admin_password}"),"PAPERLESS_POST_CONSUME_SCRIPT=/usr/src/paperless/post-consume.py",format!("PAPERLESS_WEBHOOK_SECRET={}",state.config.control_internal_token),format!("MAKERSBRAIN_WORKSHOP_ID={workshop}"),format!("MAKERSBRAIN_CONTROL_URL={}",state.config.control_internal_url)
            ],
            "Labels":{"makersbrain.kind":"paperless","makersbrain.workshop":workshop.to_string()},
            "HostConfig":{"NetworkMode":state.config.docker_network,"Binds":[format!("mb-paperless-{workshop}-data:/usr/src/paperless/data"),format!("mb-paperless-{workshop}-media:/usr/src/paperless/media"),format!("mb-paperless-{workshop}-consume:/usr/src/paperless/consume")]}
        }),
    )
    .await?;
    docker_start_container(state, container).await?;
    for _ in 0..90 {
        let inspect = docker_inspect_container(state, container).await?;
        let health = inspect
            .pointer("/State/Health/Status")
            .and_then(Value::as_str);
        if health == Some("healthy") {
            return Ok(());
        }
        if inspect.pointer("/State/Running").and_then(Value::as_bool) == Some(false) {
            return Err(DriverError::internal("Paperless stopped during startup"));
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    Err(DriverError::internal("Paperless health timeout"))
}

async fn write_routes(
    state: &DriverState,
    workshop: Uuid,
    database_ref: &str,
    odoo_hostname: &str,
    paperless_hostname: &str,
    paperless_container: &str,
) -> Result<(), DriverError> {
    let config = format!(
        "server {{\n  listen 8080;\n  server_name {odoo_hostname};\n  location / {{\n    proxy_set_header Host $host;\n    proxy_set_header X-Forwarded-Proto $scheme;\n    proxy_set_header X-Odoo-Dbfilter '^{}\\Z';\n    proxy_pass http://odoo:8069;\n  }}\n}}\nserver {{\n  listen 8080;\n  server_name {paperless_hostname};\n  location / {{\n    proxy_set_header Host $host;\n    proxy_set_header X-Forwarded-Proto $scheme;\n    proxy_pass http://{paperless_container}:8000;\n  }}\n}}\n",
        database_ref
    );
    let path = state.config.route_root.join(format!("{workshop}.conf"));
    let temporary = state.config.route_root.join(format!("{workshop}.conf.tmp"));
    std::fs::write(&temporary, config).map_err(DriverError::internal)?;
    std::fs::rename(temporary, path).map_err(DriverError::internal)?;
    let response = state
        .docker
        .post(format!(
            "http://localhost/v1.47/containers/{}/kill?signal=HUP",
            state.config.gateway_container
        ))
        .send()
        .await
        .map_err(DriverError::internal)?;
    if !response.status().is_success() {
        return Err(DriverError::internal(format!(
            "gateway reload returned {}",
            response.status()
        )));
    }
    Ok(())
}

async fn docker_container_exists(state: &DriverState, name: &str) -> Result<bool, DriverError> {
    let response = state
        .docker
        .get(format!("http://localhost/v1.47/containers/{name}/json"))
        .send()
        .await
        .map_err(DriverError::internal)?;
    match response.status() {
        StatusCode::OK => Ok(true),
        StatusCode::NOT_FOUND => Ok(false),
        status => Err(DriverError::internal(format!(
            "Docker inspect returned {status}"
        ))),
    }
}

async fn docker_inspect_container(state: &DriverState, name: &str) -> Result<Value, DriverError> {
    let response = state
        .docker
        .get(format!("http://localhost/v1.47/containers/{name}/json"))
        .send()
        .await
        .map_err(DriverError::internal)?;
    if !response.status().is_success() {
        return Err(DriverError::internal(format!(
            "Docker inspect returned {}",
            response.status()
        )));
    }
    response.json().await.map_err(DriverError::internal)
}

async fn docker_create_container(
    state: &DriverState,
    name: &str,
    body: Value,
) -> Result<(), DriverError> {
    let response = state
        .docker
        .post(format!(
            "http://localhost/v1.47/containers/create?name={name}"
        ))
        .json(&body)
        .send()
        .await
        .map_err(DriverError::internal)?;
    if !response.status().is_success() {
        let status = response.status();
        let detail = response.text().await.unwrap_or_default();
        return Err(DriverError::internal(format!(
            "Docker create returned {status}: {detail}"
        )));
    }
    Ok(())
}

async fn docker_start_container(state: &DriverState, name: &str) -> Result<(), DriverError> {
    let response = state
        .docker
        .post(format!("http://localhost/v1.47/containers/{name}/start"))
        .send()
        .await
        .map_err(DriverError::internal)?;
    if !response.status().is_success() && response.status() != StatusCode::NOT_MODIFIED {
        return Err(DriverError::internal(format!(
            "Docker start returned {}",
            response.status()
        )));
    }
    Ok(())
}

async fn docker_wait_container(state: &DriverState, name: &str) -> Result<i64, DriverError> {
    let response = state
        .docker
        .post(format!(
            "http://localhost/v1.47/containers/{name}/wait?condition=not-running"
        ))
        .send()
        .await
        .map_err(DriverError::internal)?;
    let value: Value = response.json().await.map_err(DriverError::internal)?;
    value
        .get("StatusCode")
        .and_then(Value::as_i64)
        .ok_or_else(|| DriverError::internal("Docker wait response missing status"))
}

async fn docker_delete_container(state: &DriverState, name: &str) -> Result<(), DriverError> {
    let response = state
        .docker
        .delete(format!(
            "http://localhost/v1.47/containers/{name}?force=true"
        ))
        .send()
        .await
        .map_err(DriverError::internal)?;
    if !response.status().is_success() && response.status() != StatusCode::NOT_FOUND {
        return Err(DriverError::internal(format!(
            "Docker delete returned {}",
            response.status()
        )));
    }
    Ok(())
}

async fn docker_create_volume(state: &DriverState, name: &str) -> Result<(), DriverError> {
    let response = state
        .docker
        .post("http://localhost/v1.47/volumes/create")
        .json(&json!({"Name":name,"Labels":{"makersbrain.kind":"paperless-volume"}}))
        .send()
        .await
        .map_err(DriverError::internal)?;
    if !response.status().is_success() {
        return Err(DriverError::internal(format!(
            "Docker volume create returned {}",
            response.status()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn physical_database_names_are_strictly_opaque() {
        let valid = json!({"database_ref":"mb_00000000000000000000000000000001"});
        assert!(opaque_database(&valid, "database_ref").is_ok());
        for invalid in ["atelier", "mb_123", "mb_0000000000000000000000000000000Z"] {
            assert!(opaque_database(&json!({"database_ref":invalid}), "database_ref").is_err());
        }
    }

    #[test]
    fn public_hostnames_cannot_inject_gateway_configuration() {
        assert!(hostname(&json!({"host":"atelier.dev1.makersbrain.net"}), "host").is_ok());
        assert!(hostname(&json!({"host":"atelier; return 200"}), "host").is_err());
    }
}
