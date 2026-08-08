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
    postgres_image: String,
    paperless_image: String,
    docker_network: String,
    odoo_container: String,
    odoo_volume: String,
    odoo_uid: u32,
    odoo_gid: u32,
    backup_volume: String,
    odoo_data_root: PathBuf,
    backup_root: PathBuf,
    redis_address: String,
    secret_root: PathBuf,
    secret_volume: String,
    route_root: PathBuf,
    gateway_container: String,
    odoo_base_url: String,
    control_internal_url: String,
    control_internal_token: String,
    rauthy_admin_url: String,
    rauthy_admin_key: String,
    oidc_issuer: String,
    public_scheme: String,
    public_port: Option<u16>,
}

impl DockerDriverConfig {
    pub fn from_env() -> anyhow::Result<Self> {
        let public_scheme = required("DRIVER_PUBLIC_SCHEME")?;
        if !matches!(public_scheme.as_str(), "http" | "https") {
            anyhow::bail!("DRIVER_PUBLIC_SCHEME must be http or https");
        }
        let public_port = std::env::var("DRIVER_PUBLIC_PORT")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .map(|value| value.parse())
            .transpose()?;
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
            postgres_image: required("DRIVER_POSTGRES_IMAGE")?,
            paperless_image: required("DRIVER_PAPERLESS_IMAGE")?,
            docker_network: required("DRIVER_DOCKER_NETWORK")?,
            odoo_container: required("DRIVER_ODOO_CONTAINER")?,
            odoo_volume: required("DRIVER_ODOO_VOLUME")?,
            odoo_uid: required("DRIVER_ODOO_UID")?.parse()?,
            odoo_gid: required("DRIVER_ODOO_GID")?.parse()?,
            backup_volume: required("DRIVER_BACKUP_VOLUME")?,
            odoo_data_root: required("DRIVER_ODOO_DATA_ROOT")?.into(),
            backup_root: required("DRIVER_BACKUP_ROOT")?.into(),
            redis_address: required("DRIVER_REDIS_ADDRESS")?,
            secret_root: required("DRIVER_SECRET_ROOT")?.into(),
            secret_volume: required("DRIVER_SECRET_VOLUME")?,
            route_root: required("DRIVER_ROUTE_ROOT")?.into(),
            gateway_container: required("DRIVER_GATEWAY_CONTAINER")?,
            odoo_base_url: absolute_http("DRIVER_ODOO_BASE_URL")?,
            control_internal_url: absolute_http("DRIVER_CONTROL_INTERNAL_URL")?,
            control_internal_token: required("DRIVER_CONTROL_INTERNAL_TOKEN")?,
            rauthy_admin_url: absolute_http("DRIVER_RAUTHY_ADMIN_URL")?,
            rauthy_admin_key: required("DRIVER_RAUTHY_ADMIN_KEY")?,
            oidc_issuer: absolute_http("DRIVER_OIDC_ISSUER")?,
            public_scheme,
            public_port,
        })
    }

    fn public_origin(&self, hostname: &str) -> String {
        match self.public_port {
            Some(port) => format!("{}://{hostname}:{port}", self.public_scheme),
            None => format!("{}://{hostname}", self.public_scheme),
        }
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
    normalize_secret_permissions(&config.secret_root)?;
    std::fs::create_dir_all(&config.route_root)?;
    std::fs::create_dir_all(&config.backup_root)?;
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
    let compact = tenant_key(workshop);
    let paperless_database = format!("pl_{compact}");
    let paperless_role = paperless_database.clone();
    let paperless_container = format!("mb-paperless-{compact}");
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
    let _odoo_admin =
        secret_value(&tenant_secret_dir.join("odoo-admin"), 64).map_err(DriverError::internal)?;
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
        ensure_oidc_clients(state, &compact, odoo_hostname, paperless_hostname).await?;
    write_secret(
        &tenant_secret_dir.join("paperless-oidc"),
        &paperless_oidc_secret,
    )
    .map_err(DriverError::internal)?;
    ensure_odoo_database(state, database_ref, &compact).await?;
    ensure_odoo_break_glass(state, workshop, database_ref, &compact).await?;
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
            "break_glass_secret_ref": format!("docker/{workshop}/odoo-admin"),
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

fn tenant_key(workshop: Uuid) -> String {
    workshop.simple().to_string()
}

async fn lifecycle(
    state: &DriverState,
    workshop: Uuid,
    payload: &Value,
) -> Result<Value, DriverError> {
    let running = docker_inspect_container(state, &state.config.odoo_container)
        .await?
        .pointer("/State/Running")
        .and_then(Value::as_bool)
        == Some(true);
    if running {
        docker_stop_container(state, &state.config.odoo_container).await?;
    }
    let result = lifecycle_quiesced(state, workshop, payload).await;
    let restart = if running {
        docker_start_container(state, &state.config.odoo_container).await
    } else {
        Ok(())
    };
    match (result, restart) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (_, Err(error)) => Err(error),
    }
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
    match action {
        "snapshot" | "backup" => {
            let recovery = payload_uuid(payload, "recovery_point_id")?;
            let recovery_point =
                create_recovery_set(state, workshop, recovery, &database_ref, action).await?;
            Ok(json!({"action":action,"recovery_point":recovery_point}))
        }
        "restore" => {
            let safety = payload_uuid(payload, "safety_recovery_point_id")?;
            let safety_recovery_point =
                create_recovery_set(state, workshop, safety, &database_ref, "snapshot").await?;
            let storage_ref = payload
                .get("storage_ref")
                .and_then(Value::as_str)
                .ok_or_else(|| DriverError::bad("storage_ref is required"))?;
            restore_recovery_set(state, workshop, &database_ref, storage_ref).await?;
            Ok(json!({"action":"restore","safety_recovery_point":safety_recovery_point}))
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
            )
            .await?;
            Ok(
                json!({"action":"duplicate","database":{"database_ref":target_ref,"routable":false}}),
            )
        }
        _ => Err(DriverError::bad("unsupported lifecycle action")),
    }
}

fn payload_uuid(payload: &Value, key: &str) -> Result<Uuid, DriverError> {
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

async fn create_recovery_set(
    state: &DriverState,
    workshop: Uuid,
    recovery: Uuid,
    database_ref: &str,
    kind: &str,
) -> Result<Value, DriverError> {
    if !safe_pg_identifier(database_ref) {
        return Err(DriverError::bad("unsafe database reference"));
    }
    let relative = PathBuf::from("docker-backup")
        .join(workshop.to_string())
        .join(recovery.to_string());
    let directory = state.config.backup_root.join(&relative);
    let complete = directory.join("complete.json");
    if complete.is_file() {
        let size = directory_size(&directory).map_err(DriverError::internal)?;
        return Ok(json!({"storage_ref":relative.to_string_lossy(),"size_bytes":size}));
    }
    if directory.exists() {
        std::fs::remove_dir_all(&directory).map_err(DriverError::internal)?;
    }
    secure_directory(&directory).map_err(DriverError::internal)?;
    let dump_relative = relative.join("database.dump");
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
            "--username=odoo".into(),
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
    let target_filestore = directory.join("filestore");
    copy_directory(&source_filestore, &target_filestore, None).map_err(DriverError::internal)?;
    let manifest = json!({
        "format":"makersbrain-odoo-recovery-v1",
        "workshop_id":workshop,
        "database_ref":database_ref,
        "kind":kind
    });
    std::fs::write(
        &complete,
        serde_json::to_vec_pretty(&manifest).map_err(DriverError::internal)?,
    )
    .map_err(DriverError::internal)?;
    let size = directory_size(&directory).map_err(DriverError::internal)?;
    Ok(json!({"storage_ref":relative.to_string_lossy(),"size_bytes":size}))
}

async fn restore_recovery_set(
    state: &DriverState,
    workshop: Uuid,
    target_database: &str,
    storage_ref: &str,
) -> Result<(), DriverError> {
    if !safe_pg_identifier(target_database) {
        return Err(DriverError::bad("unsafe target database reference"));
    }
    let relative = safe_storage_ref(storage_ref, workshop)?;
    let directory = state.config.backup_root.join(&relative);
    let resolved = std::fs::canonicalize(&directory).map_err(DriverError::internal)?;
    let root = std::fs::canonicalize(&state.config.backup_root).map_err(DriverError::internal)?;
    if !resolved.starts_with(&root)
        || !resolved.join("complete.json").is_file()
        || !resolved.join("database.dump").is_file()
    {
        return Err(DriverError::bad("recovery set is incomplete"));
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
            "--username=odoo".into(),
            format!("--dbname={target_database}"),
            format!("/backups/{}/database.dump", relative.to_string_lossy()),
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
        &resolved.join("filestore"),
        &target_filestore,
        Some((state.config.odoo_uid, state.config.odoo_gid)),
    )
    .map_err(DriverError::internal)
}

fn safe_storage_ref(storage_ref: &str, workshop: Uuid) -> Result<PathBuf, DriverError> {
    let components = storage_ref.split('/').collect::<Vec<_>>();
    if components.len() != 3
        || components[0] != "docker-backup"
        || components[1] != workshop.to_string()
        || components[2].parse::<Uuid>().is_err()
    {
        return Err(DriverError::bad("storage_ref is invalid"));
    }
    Ok(components.iter().collect())
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
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o750))
}

fn normalize_secret_permissions(root: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let tenants = root.join("docker");
    std::fs::create_dir_all(&tenants)?;
    std::fs::set_permissions(&tenants, std::fs::Permissions::from_mode(0o750))?;
    for tenant in std::fs::read_dir(&tenants)? {
        let tenant = tenant?;
        let file_type = tenant.file_type()?;
        if !file_type.is_dir()
            || tenant
                .file_name()
                .to_str()
                .and_then(|name| Uuid::parse_str(name).ok())
                .is_none()
        {
            return Err(std::io::Error::other(
                "tenant secret root contains an unexpected entry",
            ));
        }
        std::fs::set_permissions(tenant.path(), std::fs::Permissions::from_mode(0o750))?;
        for secret in std::fs::read_dir(tenant.path())? {
            let secret = secret?;
            if !secret.file_type()?.is_file() {
                return Err(std::io::Error::other(
                    "tenant secret directory contains a non-file entry",
                ));
            }
            std::fs::set_permissions(secret.path(), std::fs::Permissions::from_mode(0o640))?;
        }
    }
    Ok(())
}

fn write_secret(path: &Path, value: &str) -> std::io::Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true).mode(0o640);
    let mut file = options.open(path)?;
    std::io::Write::write_all(&mut file, value.as_bytes())?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o640))
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
) -> Result<bool, DriverError> {
    if !safe_pg_identifier(database) || !safe_pg_identifier(role) {
        return Err(DriverError::bad("unsafe PostgreSQL identifier"));
    }
    let exists: bool = sqlx::query_scalar("select exists(select 1 from pg_roles where rolname=$1)")
        .bind(role)
        .fetch_one(pool)
        .await
        .map_err(DriverError::internal)?;
    let created = !exists;
    if created {
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
    Ok(created)
}

fn safe_pg_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

async fn replace_database(state: &DriverState, database: &str) -> Result<(), DriverError> {
    if !safe_pg_identifier(database) {
        return Err(DriverError::bad("unsafe PostgreSQL identifier"));
    }
    sqlx::query(
        "select pg_terminate_backend(pid) from pg_stat_activity where datname=$1 and pid<>pg_backend_pid()",
    )
    .bind(database)
    .execute(&state.postgres)
    .await
    .map_err(DriverError::internal)?;
    let exists: bool =
        sqlx::query_scalar("select exists(select 1 from pg_database where datname=$1)")
            .bind(database)
            .fetch_one(&state.postgres)
            .await
            .map_err(DriverError::internal)?;
    if exists {
        sqlx::query(AssertSqlSafe(format!("drop database \"{database}\"")))
            .execute(&state.postgres)
            .await
            .map_err(DriverError::internal)?;
    }
    sqlx::query(AssertSqlSafe(format!(
        "create database \"{database}\" owner \"odoo\""
    )))
    .execute(&state.postgres)
    .await
    .map_err(DriverError::internal)?;
    Ok(())
}

async fn run_postgres_job(
    state: &DriverState,
    container: &str,
    command: Vec<String>,
) -> Result<(), DriverError> {
    if docker_container_exists(state, container).await? {
        docker_delete_container(state, container).await?;
    }
    docker_create_container(
        state,
        container,
        json!({
            "Image":state.config.postgres_image,
            "Cmd":command,
            "Env":[format!("PGPASSWORD={}",state.config.odoo_postgres_password)],
            "Labels":{"makersbrain.kind":"postgres-lifecycle-job"},
            "HostConfig":{
                "NetworkMode":state.config.docker_network,
                "Binds":[format!("{}:/backups",state.config.backup_volume)]
            }
        }),
    )
    .await?;
    docker_start_container(state, container).await?;
    let code = docker_wait_container(state, container).await?;
    let _ = docker_delete_container(state, container).await;
    if code != 0 {
        return Err(DriverError::internal(format!(
            "PostgreSQL lifecycle job exited with {code}"
        )));
    }
    Ok(())
}

fn copy_directory(
    source: &Path,
    target: &Path,
    ownership: Option<(u32, u32)>,
) -> std::io::Result<()> {
    use std::os::unix::fs::chown;

    std::fs::create_dir_all(target)?;
    if !source.exists() {
        return Ok(());
    }
    if let Some((uid, gid)) = ownership {
        chown(target, Some(uid), Some(gid))?;
    }
    for entry in std::fs::read_dir(source)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let destination = target.join(entry.file_name());
        if file_type.is_dir() {
            copy_directory(&entry.path(), &destination, ownership)?;
        } else if file_type.is_file() {
            std::fs::copy(entry.path(), &destination)?;
            if let Some((uid, gid)) = ownership {
                chown(&destination, Some(uid), Some(gid))?;
            }
        } else {
            return Err(std::io::Error::other(
                "recovery sets do not support symbolic links",
            ));
        }
    }
    Ok(())
}

fn directory_size(path: &Path) -> std::io::Result<i64> {
    let mut size = 0_i64;
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        let metadata = entry.metadata()?;
        if metadata.is_dir() {
            size = size.saturating_add(directory_size(&entry.path())?);
        } else if metadata.is_file() {
            size = size.saturating_add(i64::try_from(metadata.len()).unwrap_or(i64::MAX));
        }
    }
    Ok(size)
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

fn redis_acl_arguments(username: &str, password: &str, prefix: &str) -> Vec<String> {
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

async fn ensure_oidc_clients(
    state: &DriverState,
    tenant_key: &str,
    odoo_hostname: &str,
    paperless_hostname: &str,
) -> Result<(String, String, String), DriverError> {
    let odoo_id = format!("makersbrain-odoo-{tenant_key}");
    let paperless_id = format!("makersbrain-paperless-{tenant_key}");
    let odoo_origin = state.config.public_origin(odoo_hostname);
    let paperless_origin = state.config.public_origin(paperless_hostname);
    ensure_rauthy_client(
        state,
        &odoo_id,
        "MakersBrain Odoo",
        false,
        &format!("{odoo_origin}/auth_oauth/signin"),
        &format!("{odoo_origin}/web/login"),
    )
    .await?;
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
    Ok((odoo_id, paperless_id, secret))
}

async fn ensure_rauthy_client(
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

async fn ensure_odoo_database(
    state: &DriverState,
    database_ref: &str,
    tenant_key: &str,
) -> Result<(), DriverError> {
    let container = format!("mb-odoo-init-{tenant_key}");
    if docker_container_exists(state, &container).await? {
        let _ = docker_delete_container(state, &container).await;
    }
    docker_create_container(
        state,
        &container,
        json!({
            "Image":state.config.odoo_image,
            "Cmd":["odoo",format!("--database={database_ref}"),"--stop-after-init","--no-database-list",format!("--db_host={}",state.config.postgres_host),format!("--db_port={}",state.config.postgres_port),"--db_user=odoo",format!("--db_password={}",state.config.odoo_postgres_password),"--addons-path=/mnt/makersbrain-addons,/mnt/oca-addons,/usr/lib/python3/dist-packages/odoo/addons","--init=auth_oidc,mb_control_bridge,mb_invoice_capture,l10n_fr_micro_enterprise","--without-demo=all"],
            "Env":[
                format!("HOST={}",state.config.postgres_host),
                format!("PORT={}",state.config.postgres_port),
                "USER=odoo",
                format!("PASSWORD={}",state.config.odoo_postgres_password),
                format!("MB_CONTROL_BRIDGE_TOKEN={}",state.config.odoo_bridge_token)
            ],
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

async fn ensure_odoo_break_glass(
    state: &DriverState,
    workshop: Uuid,
    database_ref: &str,
    tenant_key: &str,
) -> Result<(), DriverError> {
    let container = format!("mb-odoo-break-glass-{tenant_key}");
    if docker_container_exists(state, &container).await? {
        let _ = docker_delete_container(state, &container).await;
    }
    docker_create_container(
        state,
        &container,
        json!({
            "Image":state.config.odoo_image,
            "Cmd":[
                "/bin/sh",
                "-ec",
                "exec odoo shell --database=\"$MB_ODOO_DATABASE\" --no-http --db_host=\"$HOST\" --db_port=\"$PORT\" --db_user=\"$USER\" --db_password=\"$PASSWORD\" --addons-path=/mnt/makersbrain-addons,/mnt/oca-addons,/usr/lib/python3/dist-packages/odoo/addons < /mnt/makersbrain-addons/mb_control_bridge/scripts/set_break_glass_password.py"
            ],
            "Env":[
                format!("MB_ODOO_DATABASE={database_ref}"),
                format!("HOST={}",state.config.postgres_host),
                format!("PORT={}",state.config.postgres_port),
                "USER=odoo",
                format!("PASSWORD={}",state.config.odoo_postgres_password),
                format!("MB_BREAK_GLASS_PASSWORD_FILE=/run/makersbrain-secrets/docker/{workshop}/odoo-admin")
            ],
            "Labels":{"makersbrain.kind":"odoo-break-glass"},
            "HostConfig":{
                "NetworkMode":state.config.docker_network,
                "GroupAdd":["0"],
                "Binds":[format!("{}:/var/lib/odoo",state.config.odoo_volume),format!("{}:/run/makersbrain-secrets:ro",state.config.secret_volume)]
            }
        }),
    )
    .await?;
    docker_start_container(state, &container).await?;
    let code = docker_wait_container(state, &container).await?;
    let _ = docker_delete_container(state, &container).await;
    if code != 0 {
        return Err(DriverError::internal(format!(
            "Odoo break-glass initializer exited with {code}"
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
    for suffix in ["data", "media", "consume"] {
        docker_create_volume(state, &format!("mb-paperless-{workshop}-{suffix}")).await?;
    }
    let providers = json!({"openid_connect":{"APPS":[{"provider_id":"rauthy","name":"MakersBrain","client_id":oidc_client_id,"secret":oidc_secret,"settings":{"server_url":format!("{}/.well-known/openid-configuration",state.config.oidc_issuer),"oauth_pkce_enabled":true,"email_authentication":true}}]}}).to_string();
    let public_origin = state.config.public_origin(public_hostname);
    let environment = vec![
        format!(
            "PAPERLESS_REDIS=redis://{redis_user}:{redis_password}@{}",
            state.config.redis_address
        ),
        format!("PAPERLESS_REDIS_PREFIX={redis_prefix}"),
        format!("PAPERLESS_DBHOST={}", state.config.postgres_host),
        format!("PAPERLESS_DBPORT={}", state.config.postgres_port),
        format!("PAPERLESS_DBNAME={database}"),
        format!("PAPERLESS_DBUSER={role}"),
        format!("PAPERLESS_DBPASS={database_password}"),
        format!("PAPERLESS_SECRET_KEY={secret_key}"),
        format!("PAPERLESS_URL={public_origin}"),
        "PAPERLESS_TIME_ZONE=Europe/Paris".into(),
        "PAPERLESS_OCR_LANGUAGE=fra+eng".into(),
        "PAPERLESS_APPS=allauth.socialaccount.providers.openid_connect".into(),
        format!("PAPERLESS_SOCIALACCOUNT_PROVIDERS={providers}"),
        "PAPERLESS_DISABLE_REGULAR_LOGIN=true".into(),
        "PAPERLESS_REDIRECT_LOGIN_TO_SSO=true".into(),
        "PAPERLESS_SOCIAL_AUTO_SIGNUP=false".into(),
        "PAPERLESS_ADMIN_USER=local-admin".into(),
        format!("PAPERLESS_ADMIN_PASSWORD={admin_password}"),
        "PAPERLESS_POST_CONSUME_SCRIPT=/usr/src/paperless/post-consume.py".into(),
        format!(
            "PAPERLESS_WEBHOOK_SECRET={}",
            state.config.control_internal_token
        ),
        format!("MAKERSBRAIN_WORKSHOP_ID={workshop}"),
        format!(
            "MAKERSBRAIN_CONTROL_URL={}",
            state.config.control_internal_url
        ),
    ];
    let config_digest = format!(
        "{:x}",
        Sha256::digest(
            serde_json::to_vec(&(state.config.paperless_image.as_str(), &environment))
                .map_err(DriverError::internal)?
        )
    );
    if docker_container_exists(state, container).await? {
        let inspect = docker_inspect_container(state, container).await?;
        let current_digest = inspect
            .pointer("/Config/Labels/makersbrain.config-digest")
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
            "Image":state.config.paperless_image,
            "Env":environment,
            "Labels":{"makersbrain.kind":"paperless","makersbrain.workshop":workshop.to_string(),"makersbrain.config-digest":config_digest},
            "HostConfig":{"NetworkMode":state.config.docker_network,"Binds":[format!("mb-paperless-{workshop}-data:/usr/src/paperless/data"),format!("mb-paperless-{workshop}-media:/usr/src/paperless/media"),format!("mb-paperless-{workshop}-consume:/usr/src/paperless/consume")]}
        }),
    )
    .await?;
    docker_start_container(state, container).await?;
    wait_for_healthy_container(state, container, "Paperless").await
}

async fn wait_for_healthy_container(
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

async fn write_routes(
    state: &DriverState,
    workshop: Uuid,
    database_ref: &str,
    odoo_hostname: &str,
    paperless_hostname: &str,
    paperless_container: &str,
) -> Result<(), DriverError> {
    let config = format!(
        "server {{\n  listen 8080;\n  server_name {odoo_hostname};\n  location / {{\n    proxy_http_version 1.1;\n    proxy_set_header Host $host;\n    proxy_set_header X-Forwarded-Host $host;\n    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n    proxy_set_header X-Forwarded-Proto $forwarded_proto;\n    proxy_set_header Upgrade $http_upgrade;\n    proxy_set_header Connection $connection_upgrade;\n    proxy_set_header X-Odoo-Dbfilter '^{}\\Z';\n    proxy_pass http://odoo:8069;\n  }}\n}}\nserver {{\n  listen 8080;\n  server_name {paperless_hostname};\n  location / {{\n    proxy_http_version 1.1;\n    proxy_set_header Host $host;\n    proxy_set_header X-Forwarded-Host $host;\n    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n    proxy_set_header X-Forwarded-Proto $forwarded_proto;\n    proxy_set_header Upgrade $http_upgrade;\n    proxy_set_header Connection $connection_upgrade;\n    proxy_pass http://{paperless_container}:8000;\n  }}\n}}\n",
        database_ref
    );
    let path = state.config.route_root.join(format!("{workshop}.conf"));
    let temporary = state.config.route_root.join(format!("{workshop}.conf.tmp"));
    let previous = std::fs::read(&path).ok();
    std::fs::write(&temporary, config).map_err(DriverError::internal)?;
    std::fs::rename(temporary, &path).map_err(DriverError::internal)?;
    if let Err(error) = docker_exec(state, &state.config.gateway_container, &["nginx", "-t"]).await
    {
        if let Some(previous) = previous {
            let _ = std::fs::write(&path, previous);
        } else {
            let _ = std::fs::remove_file(&path);
        }
        return Err(error);
    }
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

async fn docker_exec(
    state: &DriverState,
    container: &str,
    command: &[&str],
) -> Result<(), DriverError> {
    let response = state
        .docker
        .post(format!(
            "http://localhost/v1.47/containers/{container}/exec"
        ))
        .json(&json!({"AttachStdout":false,"AttachStderr":false,"Cmd":command}))
        .send()
        .await
        .map_err(DriverError::internal)?;
    if !response.status().is_success() {
        return Err(DriverError::internal(format!(
            "Docker exec create returned {}",
            response.status()
        )));
    }
    let id = response
        .json::<Value>()
        .await
        .map_err(DriverError::internal)?
        .get("Id")
        .and_then(Value::as_str)
        .ok_or_else(|| DriverError::internal("Docker exec id missing"))?
        .to_owned();
    let response = state
        .docker
        .post(format!("http://localhost/v1.47/exec/{id}/start"))
        .json(&json!({"Detach":true,"Tty":false}))
        .send()
        .await
        .map_err(DriverError::internal)?;
    if !response.status().is_success() {
        return Err(DriverError::internal(format!(
            "Docker exec start returned {}",
            response.status()
        )));
    }
    for _ in 0..50 {
        let value = state
            .docker
            .get(format!("http://localhost/v1.47/exec/{id}/json"))
            .send()
            .await
            .map_err(DriverError::internal)?
            .json::<Value>()
            .await
            .map_err(DriverError::internal)?;
        if value.get("Running").and_then(Value::as_bool) == Some(false) {
            return match value.get("ExitCode").and_then(Value::as_i64) {
                Some(0) => Ok(()),
                Some(code) => Err(DriverError::internal(format!(
                    "container command exited with {code}"
                ))),
                None => Err(DriverError::internal("Docker exec exit code missing")),
            };
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(DriverError::internal("Docker exec timeout"))
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

async fn docker_stop_container(state: &DriverState, name: &str) -> Result<(), DriverError> {
    let response = state
        .docker
        .post(format!(
            "http://localhost/v1.47/containers/{name}/stop?t=30"
        ))
        .send()
        .await
        .map_err(DriverError::internal)?;
    if !response.status().is_success() && response.status() != StatusCode::NOT_MODIFIED {
        return Err(DriverError::internal(format!(
            "Docker stop returned {}",
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

    #[test]
    fn docker_resource_names_use_the_complete_workshop_identity() {
        let first = Uuid::parse_str("00000000-0000-0000-0000-000000000201").unwrap();
        let second = Uuid::parse_str("00000000-0000-0000-0000-000000000202").unwrap();
        assert_ne!(tenant_key(first), tenant_key(second));
        assert_eq!(tenant_key(first).len(), 32);
    }

    #[test]
    fn existing_tenant_secrets_are_migrated_to_worker_readable_modes() {
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!("mb-secrets-{}", Uuid::new_v4()));
        let tenant = root.join("docker/00000000-0000-0000-0000-000000000201");
        std::fs::create_dir_all(&tenant).unwrap();
        let secret = tenant.join("odoo");
        std::fs::write(&secret, "sensitive").unwrap();
        std::fs::set_permissions(&tenant, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600)).unwrap();

        normalize_secret_permissions(&root).unwrap();

        assert_eq!(
            std::fs::metadata(&tenant).unwrap().permissions().mode() & 0o777,
            0o750
        );
        assert_eq!(
            std::fs::metadata(&secret).unwrap().permissions().mode() & 0o777,
            0o640
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn paperless_redis_acl_excludes_shared_service_administration() {
        let rules = redis_acl_arguments("tenant", "password", "mb:tenant:");
        let position = |rule: &str| {
            rules
                .iter()
                .position(|candidate| candidate == rule)
                .unwrap()
        };
        assert!(rules.iter().any(|rule| rule == "~mb:tenant:*"));
        assert!(rules.iter().any(|rule| rule == "&mb:tenant:*"));
        assert!(
            rules
                .iter()
                .any(|rule| rule == "&mb:tenant:/0.celery.pidbox")
        );
        assert!(position("-@admin") > position("+@all"));
        assert!(position("-@dangerous") > position("+@all"));
        assert!(position("+evalsha") > position("-@dangerous"));
    }

    #[test]
    fn restored_filestore_uses_the_configured_runtime_owner() {
        use std::os::unix::fs::MetadataExt;

        let root = std::env::temp_dir().join(format!("mb-filestore-{}", Uuid::new_v4()));
        let source = root.join("source");
        let target = root.join("target");
        std::fs::create_dir_all(source.join("ab")).unwrap();
        std::fs::write(source.join("ab/attachment"), "asset").unwrap();
        let metadata = std::fs::metadata(&source).unwrap();

        copy_directory(&source, &target, Some((metadata.uid(), metadata.gid()))).unwrap();

        let restored = std::fs::metadata(target.join("ab/attachment")).unwrap();
        assert_eq!(restored.uid(), metadata.uid());
        assert_eq!(restored.gid(), metadata.gid());
        assert_eq!(
            std::fs::read_to_string(target.join("ab/attachment")).unwrap(),
            "asset"
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}
