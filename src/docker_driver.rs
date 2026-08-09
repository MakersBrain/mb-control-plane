use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Path as AxumPath, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use rand::distr::{Alphanumeric, SampleString};
use serde::{Deserialize, Serialize};
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
    postgres_admin_user: String,
    postgres_admin_password: String,
    postgres_host: String,
    postgres_port: u16,
    odoo_postgres_password: String,
    odoo_bridge_token: String,
    odoo_image: String,
    postgres_image: String,
    paperless_image: Option<String>,
    docker_network: String,
    odoo_volume: String,
    odoo_uid: u32,
    odoo_gid: u32,
    backup_volume: String,
    odoo_data_root: PathBuf,
    backup_root: PathBuf,
    backup_agent_image: Option<String>,
    s3_backup: Option<S3BackupConfig>,
    redis_address: String,
    secret_root: PathBuf,
    secret_volume: String,
    backup_secret_volume: String,
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

#[derive(Clone)]
struct S3BackupConfig {
    bucket: String,
    endpoint: String,
    region: String,
    writer_access_key_id: String,
    writer_secret_access_key: String,
    reader_access_key_id: String,
    reader_secret_access_key: String,
    age_recipient: String,
    age_identity_file: String,
    encryption_key_id: String,
    retention_days: i32,
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
        let postgres_admin_url = required("DRIVER_POSTGRES_ADMIN_URL")?;
        let parsed_admin_url = Url::parse(&postgres_admin_url)?;
        let postgres_admin_user = parsed_admin_url.username().to_owned();
        let postgres_admin_password = parsed_admin_url
            .password()
            .ok_or_else(|| anyhow::anyhow!("DRIVER_POSTGRES_ADMIN_URL must contain a password"))?
            .to_owned();
        if postgres_admin_user.is_empty() {
            anyhow::bail!("DRIVER_POSTGRES_ADMIN_URL must contain a username");
        }
        let backup_agent_image = optional("DRIVER_BACKUP_AGENT_IMAGE");
        let s3_values = [
            optional("BACKUP_S3_BUCKET"),
            optional("BACKUP_S3_ENDPOINT"),
            optional("BACKUP_S3_REGION"),
            optional("BACKUP_S3_ACCESS_KEY_ID"),
            optional("BACKUP_S3_SECRET_ACCESS_KEY"),
            optional("RESTORE_S3_ACCESS_KEY_ID"),
            optional("RESTORE_S3_SECRET_ACCESS_KEY"),
            optional("BACKUP_AGE_RECIPIENT"),
            optional("BACKUP_AGE_IDENTITY_FILE"),
            optional("BACKUP_ENCRYPTION_KEY_ID"),
            optional("BACKUP_RETENTION_DAYS"),
        ];
        let s3_backup = if s3_values[0].is_none() {
            None
        } else if let [
            Some(bucket),
            Some(endpoint),
            Some(region),
            Some(writer_access_key_id),
            Some(writer_secret_access_key),
            Some(reader_access_key_id),
            Some(reader_secret_access_key),
            Some(age_recipient),
            Some(age_identity_file),
            Some(encryption_key_id),
            Some(retention_days),
        ] = s3_values
        {
            if backup_agent_image.is_none() {
                anyhow::bail!("DRIVER_BACKUP_AGENT_IMAGE is required when S3 backup is configured");
            }
            let retention_days: i32 = retention_days
                .parse()
                .map_err(|_| anyhow::anyhow!("BACKUP_RETENTION_DAYS must be a positive integer"))?;
            if retention_days <= 0 {
                anyhow::bail!("BACKUP_RETENTION_DAYS must be a positive integer");
            }
            if !age_recipient.starts_with("age1") {
                anyhow::bail!("BACKUP_AGE_RECIPIENT must be an age X25519 recipient");
            }
            if !age_identity_file.starts_with("/run/makersbrain-backup-secrets/") {
                anyhow::bail!("BACKUP_AGE_IDENTITY_FILE must use the isolated backup-secret mount");
            }
            Some(S3BackupConfig {
                bucket,
                endpoint: absolute_http_value("BACKUP_S3_ENDPOINT", endpoint)?,
                region,
                writer_access_key_id,
                writer_secret_access_key,
                reader_access_key_id,
                reader_secret_access_key,
                age_recipient,
                age_identity_file,
                encryption_key_id,
                retention_days,
            })
        } else {
            anyhow::bail!("all S3 backup, restore, and age settings must be configured together");
        };
        Ok(Self {
            listen: required("DRIVER_LISTEN")?.parse()?,
            token: required("DRIVER_TOKEN")?,
            docker_socket: required("DRIVER_DOCKER_SOCKET")?.into(),
            database_url: required("DRIVER_DATABASE_URL")?,
            postgres_admin_url,
            postgres_admin_user,
            postgres_admin_password,
            postgres_host: required("DRIVER_POSTGRES_HOST")?,
            postgres_port: required("DRIVER_POSTGRES_PORT")?.parse()?,
            odoo_postgres_password: required("DRIVER_ODOO_POSTGRES_PASSWORD")?,
            odoo_bridge_token: required("DRIVER_ODOO_BRIDGE_TOKEN")?,
            odoo_image: required("DRIVER_ODOO_IMAGE")?,
            postgres_image: required("DRIVER_POSTGRES_IMAGE")?,
            paperless_image: std::env::var("DRIVER_PAPERLESS_IMAGE")
                .ok()
                .filter(|value| !value.trim().is_empty()),
            docker_network: required("DRIVER_DOCKER_NETWORK")?,
            odoo_volume: required("DRIVER_ODOO_VOLUME")?,
            odoo_uid: required("DRIVER_ODOO_UID")?.parse()?,
            odoo_gid: required("DRIVER_ODOO_GID")?.parse()?,
            backup_volume: required("DRIVER_BACKUP_VOLUME")?,
            odoo_data_root: required("DRIVER_ODOO_DATA_ROOT")?.into(),
            backup_root: required("DRIVER_BACKUP_ROOT")?.into(),
            backup_agent_image,
            s3_backup,
            redis_address: required("DRIVER_REDIS_ADDRESS")?,
            secret_root: required("DRIVER_SECRET_ROOT")?.into(),
            secret_volume: required("DRIVER_SECRET_VOLUME")?,
            backup_secret_volume: required("DRIVER_BACKUP_SECRET_VOLUME")?,
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

fn optional(name: &'static str) -> Option<String> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
}

fn absolute_http_value(name: &'static str, value: String) -> anyhow::Result<String> {
    let url = Url::parse(&value)?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        anyhow::bail!("{name} must be an absolute HTTP(S) URL");
    }
    Ok(value.trim_end_matches('/').to_owned())
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

const RECOVERY_FORMAT_V2: &str = "makersbrain-workshop-recovery-v2";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct RecoveryManifest {
    format: String,
    recovery_id: Uuid,
    workshop_id: Uuid,
    database_ref: String,
    kind: String,
    source_release: String,
    odoo_version: String,
    paperless_version: Option<String>,
    paperless_database_ref: Option<String>,
    created_at_unix: i64,
    expires_at_unix: Option<i64>,
    encryption: Option<String>,
    encryption_key_id: Option<String>,
    component_scope: Vec<String>,
    components: Vec<RecoveryComponent>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct RecoveryComponent {
    name: String,
    path: String,
    size_bytes: i64,
    sha256: String,
    plaintext_sha256: Option<String>,
}

#[derive(Debug)]
struct StoredRecovery {
    storage_ref: String,
    component_scope: Vec<String>,
    format_version: String,
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
    recover_database_connection_limits(&state)
        .await
        .map_err(|error| anyhow::anyhow!(error.1))?;
    recover_maintenance_routes(&state)
        .await
        .map_err(|error| anyhow::anyhow!(error.1))?;
    Ok(Router::new()
        .route("/health/live", get(|| async { "live" }))
        .route("/v1/tenants/{workshop}/{action}", post(tenant))
        .with_state(state))
}

async fn recover_database_connection_limits(state: &DriverState) -> Result<(), DriverError> {
    let rows = sqlx::query("select id,database_ref,connection_limit_before_lifecycle from control.odoo_databases where connection_limit_before_lifecycle is not null")
        .fetch_all(&state.ledger)
        .await
        .map_err(DriverError::internal)?;
    for row in rows {
        let id: Uuid = row.get("id");
        let database: String = row.get("database_ref");
        let limit: i32 = row.get("connection_limit_before_lifecycle");
        set_database_connection_limit(state, &database, limit).await?;
        sqlx::query(
            "update control.odoo_databases set connection_limit_before_lifecycle=null where id=$1",
        )
        .bind(id)
        .execute(&state.ledger)
        .await
        .map_err(DriverError::internal)?;
        tracing::warn!(database_id=%id,"recovered PostgreSQL connection limit left by an interrupted lifecycle operation");
    }
    Ok(())
}

async fn recover_maintenance_routes(state: &DriverState) -> Result<(), DriverError> {
    let entries = std::fs::read_dir(&state.config.route_root).map_err(DriverError::internal)?;
    for entry in entries {
        let entry = entry.map_err(DriverError::internal)?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Some(workshop) = name.strip_suffix(".recovery.bak") else {
            continue;
        };
        let workshop = workshop
            .parse::<Uuid>()
            .map_err(|_| DriverError::internal("invalid maintenance recovery filename"))?;
        let restore_unresolved = sqlx::query_scalar::<_, bool>(
            "select exists(select 1 from control.odoo_databases where workshop_id=$1 and state='restoring' and deleted_at is null)",
        )
        .bind(workshop)
        .fetch_one(&state.ledger)
        .await
        .map_err(DriverError::internal)?;
        if restore_unresolved {
            tracing::error!(%workshop, "leaving workshop in maintenance because restore recovery is unresolved");
            continue;
        }
        let previous = std::fs::read(entry.path()).map_err(DriverError::internal)?;
        leave_workshop_maintenance(state, workshop, &previous).await?;
        tracing::warn!(%workshop, "recovered workshop route left in maintenance by an interrupted lifecycle operation");
    }
    Ok(())
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
    if !matches!(
        action.as_str(),
        "provision" | "reconcile" | "lifecycle" | "rehearse" | "download"
    ) {
        return Err(DriverError(StatusCode::NOT_FOUND, "unknown action".into()));
    }
    if action == "download" {
        return download_backup(&state, workshop, &payload).await.map(Json);
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
        "rehearse" => rehearse(&state, workshop, &payload).await,
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

async fn download_backup(
    state: &DriverState,
    workshop: Uuid,
    payload: &Value,
) -> Result<Value, DriverError> {
    let recovery = payload_uuid(payload, "recovery_point_id")?;
    let object_key = sqlx::query_scalar::<_, String>(
        "select archive_object_key from control.workshop_recovery_points
         where id=$1 and workshop_id=$2 and kind='backup' and state='ready'
           and verification_state='verified' and archive_object_key is not null",
    )
    .bind(recovery)
    .bind(workshop)
    .fetch_optional(&state.ledger)
    .await
    .map_err(DriverError::internal)?
    .ok_or_else(|| DriverError::bad("backup archive is not ready for download"))?;
    let s3 = state
        .config
        .s3_backup
        .as_ref()
        .ok_or_else(|| DriverError::bad("portable S3 backups are not configured"))?;
    let image = state
        .config
        .backup_agent_image
        .as_ref()
        .ok_or_else(|| DriverError::bad("backup agent image is not configured"))?;
    let result_name = format!("presigned-{}.txt", Uuid::new_v4());
    let result_path = state.config.backup_root.join(&result_name);
    run_docker_job(
        state,
        &format!("mb-presign-{}", &recovery.simple().to_string()[..12]),
        json!({
            "Image": image,
            "User": "0:0",
            "Cmd": ["sh", "-ec", format!("set -eu; umask 077; aws --endpoint-url \"$S3_ENDPOINT\" s3 presign --expires-in 600 \"s3://$S3_BUCKET/$ARCHIVE_KEY\" > /backups/{result_name}")],
            "Env": [
                format!("AWS_ACCESS_KEY_ID={}", s3.reader_access_key_id),
                format!("AWS_SECRET_ACCESS_KEY={}", s3.reader_secret_access_key),
                format!("AWS_DEFAULT_REGION={}", s3.region),
                format!("S3_ENDPOINT={}", s3.endpoint),
                format!("S3_BUCKET={}", s3.bucket),
                format!("ARCHIVE_KEY={object_key}"),
            ],
            "Labels": {"makersbrain.kind":"s3-backup-presign-job"},
            "HostConfig": {"Binds": [format!("{}:/backups", state.config.backup_volume)]}
        }),
    )
    .await?;
    let url = std::fs::read_to_string(&result_path)
        .map_err(DriverError::internal)?
        .trim()
        .to_owned();
    let _ = std::fs::remove_file(&result_path);
    Url::parse(&url).map_err(DriverError::internal)?;
    Ok(json!({"url":url,"expires_in":600,"filename":format!("makersbrain-{recovery}.tar")}))
}

async fn rehearse(
    state: &DriverState,
    workshop: Uuid,
    payload: &Value,
) -> Result<Value, DriverError> {
    let recovery = payload_uuid(payload, "recovery_point_id")?;
    let stored = resolve_stored_recovery(state, workshop, recovery).await?;
    if !stored.storage_ref.starts_with("s3://") || stored.format_version != RECOVERY_FORMAT_V2 {
        return Err(DriverError::bad(
            "only verified portable recovery sets can be rehearsed",
        ));
    }
    restore_remote_recovery_set(
        state,
        workshop,
        "rehearsal-does-not-cut-over",
        &stored.storage_ref,
        &stored.component_scope,
        true,
    )
    .await?;
    Ok(json!({"action":"rehearse","recovery_point_id":recovery,"status":"succeeded"}))
}

async fn provision(
    state: &DriverState,
    workshop: Uuid,
    payload: &Value,
) -> Result<Value, DriverError> {
    let database_ref = opaque_database(payload, "database_ref")?;
    let odoo_hostname = hostname(payload, "public_hostname")?;
    let paperless_enabled = payload
        .get("paperless_enabled")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let paperless_hostname = if paperless_enabled {
        Some(hostname(payload, "paperless_hostname")?)
    } else {
        None
    };
    let compact = tenant_key(workshop);
    let tenant_secret_dir = state
        .config
        .secret_root
        .join("docker")
        .join(workshop.to_string());
    secure_directory(&tenant_secret_dir).map_err(DriverError::internal)?;
    let _odoo_admin =
        secret_value(&tenant_secret_dir.join("odoo-admin"), 64).map_err(DriverError::internal)?;
    write_secret(
        &tenant_secret_dir.join("odoo"),
        &state.config.odoo_bridge_token,
    )
    .map_err(DriverError::internal)?;

    ensure_database(&state.postgres, database_ref, "odoo", None).await?;
    let (odoo_client_id, paperless_oidc) =
        ensure_oidc_clients(state, &compact, odoo_hostname, paperless_hostname).await?;
    ensure_odoo_database(state, database_ref, &compact).await?;
    ensure_odoo_break_glass(state, workshop, database_ref, &compact).await?;
    let mut response = json!({
        "workshop_id": workshop,
        "action": "provision",
        "release_id": env!("CARGO_PKG_VERSION"),
        "odoo": {
            "base_url": state.config.odoo_base_url,
            "secret_ref": format!("docker/{workshop}/odoo"),
            "break_glass_secret_ref": format!("docker/{workshop}/odoo-admin"),
            "database": {"database_ref": database_ref, "public_hostname": odoo_hostname}
        },
        "odoo_oidc": {"client_id": odoo_client_id, "issuer": state.config.oidc_issuer},
    });

    let route =
        if let (Some(paperless_hostname), Some((paperless_client_id, paperless_oidc_secret))) =
            (paperless_hostname, paperless_oidc)
        {
            let paperless_database = format!("pl_{compact}");
            let paperless_role = paperless_database.clone();
            let paperless_container = format!("mb-paperless-{compact}");
            let redis_user = format!("pl_{compact}");
            let redis_prefix = format!("mb:{compact}:");
            let paperless_admin = secret_value(&tenant_secret_dir.join("paperless-admin"), 64)
                .map_err(DriverError::internal)?;
            let paperless_db_password = secret_value(&tenant_secret_dir.join("paperless-db"), 64)
                .map_err(DriverError::internal)?;
            let paperless_secret_key =
                secret_value(&tenant_secret_dir.join("paperless-secret-key"), 96)
                    .map_err(DriverError::internal)?;
            let redis_password = secret_value(&tenant_secret_dir.join("redis"), 64)
                .map_err(DriverError::internal)?;
            write_secret(
                &tenant_secret_dir.join("paperless"),
                &format!("basic:local-admin:{paperless_admin}"),
            )
            .map_err(DriverError::internal)?;
            write_secret(
                &tenant_secret_dir.join("paperless-oidc"),
                &paperless_oidc_secret,
            )
            .map_err(DriverError::internal)?;
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
            response["paperless"] = json!({
                "base_url": format!("http://{paperless_container}:8000"),
                "public_hostname": paperless_hostname,
                "secret_ref": format!("docker/{workshop}/paperless")
            });
            response["paperless_oidc"] =
                json!({"client_id": paperless_client_id, "issuer": state.config.oidc_issuer});
            response["redis"] =
                json!({"shared": true, "prefix": redis_prefix, "acl_user": redis_user});
            Some((paperless_hostname, paperless_container))
        } else {
            None
        };
    write_routes(
        state,
        workshop,
        database_ref,
        odoo_hostname,
        route
            .as_ref()
            .map(|(hostname, container)| (*hostname, container.as_str())),
    )
    .await?;
    Ok(response)
}

fn tenant_key(workshop: Uuid) -> String {
    workshop.simple().to_string()
}

async fn lifecycle(
    state: &DriverState,
    workshop: Uuid,
    payload: &Value,
) -> Result<Value, DriverError> {
    let deleting = payload.get("action").and_then(Value::as_str) == Some("delete");
    let paperless_container = format!("mb-paperless-{}", tenant_key(workshop));
    let paperless_running = if docker_container_exists(state, &paperless_container).await? {
        docker_inspect_container(state, &paperless_container)
            .await?
            .pointer("/State/Running")
            .and_then(Value::as_bool)
            == Some(true)
    } else {
        false
    };
    let previous_routes = enter_workshop_maintenance(state, workshop).await?;
    let result = async {
        let operation = async {
            if paperless_running {
                docker_stop_container(state, &paperless_container).await?;
            }
            drain_workshop_operations(state, workshop).await?;
            lifecycle_quiesced(state, workshop, payload).await
        }
        .await;
        let restart = if paperless_running && !(deleting && operation.is_ok()) {
            match docker_start_container(state, &paperless_container).await {
                Ok(()) => {
                    wait_for_healthy_container(state, &paperless_container, "Paperless").await
                }
                Err(error) => Err(error),
            }
        } else {
            Ok(())
        };
        match (operation, restart) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), Ok(())) => Err(error),
            (_, Err(error)) => Err(error),
        }
    }
    .await;
    let is_restore = payload.get("action").and_then(Value::as_str) == Some("restore");
    if is_restore && result.is_err() {
        tracing::error!(%workshop, "leaving workshop route in maintenance after unresolved restore failure");
        return result;
    }
    if deleting && result.is_ok() {
        tracing::info!(%workshop, "workshop final backup verified; retaining maintenance quarantine");
        return result;
    }
    let route_restore = leave_workshop_maintenance(state, workshop, &previous_routes).await;
    match (result, route_restore) {
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
    let previous_limit =
        sqlx::query_scalar::<_, i32>("select datconnlimit from pg_database where datname=$1")
            .bind(&database_ref)
            .fetch_one(&state.postgres)
            .await
            .map_err(DriverError::internal)?;
    sqlx::query(
        "update control.odoo_databases set connection_limit_before_lifecycle=$2 where id=$1",
    )
    .bind(database_id)
    .bind(previous_limit)
    .execute(&state.ledger)
    .await
    .map_err(DriverError::internal)?;
    set_database_connection_limit(state, &database_ref, 0).await?;
    let result = async {
        drain_database_sessions(state, &database_ref).await?;
        match action {
        "snapshot" | "backup" | "delete" => {
            let recovery = payload_uuid(payload, "recovery_point_id")?;
            let scope = recovery_scope(state, workshop, recovery).await?;
            let recovery_point =
                create_recovery_set(state, workshop, recovery, &database_ref, if action == "delete" { "backup" } else { action }, &scope)
                    .await?;
            Ok(json!({"action":action,"recovery_point":recovery_point}))
        }
        "restore" => {
            let safety = payload_uuid(payload, "safety_recovery_point_id")?;
            let safety_scope = recovery_scope(state, workshop, safety).await?;
            let safety_recovery_point = create_recovery_set(
                state,
                workshop,
                safety,
                &database_ref,
                "backup",
                &safety_scope,
            )
            .await?;
            mark_recovery_ready_in_driver(state, safety, &safety_recovery_point).await?;
            let recovery_id = payload_uuid(payload, "recovery_point_id")?;
            let stored = resolve_stored_recovery(state, workshop, recovery_id).await?;
            let restored = restore_recovery_set(
                state,
                workshop,
                &database_ref,
                &stored.storage_ref,
                &stored.component_scope,
                &stored.format_version,
            )
            .await;
            match restored {
                Ok(()) => Ok(
                    json!({"action":"restore","restore_status":"restored","safety_recovery_point":safety_recovery_point}),
                ),
                Err(original_error) => {
                    let safety_storage = safety_recovery_point
                        .get("storage_ref")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            DriverError::internal("safety backup storage reference missing")
                        })?;
                    match restore_recovery_set(
                        state,
                        workshop,
                        &database_ref,
                        safety_storage,
                        &safety_scope,
                        RECOVERY_FORMAT_V2,
                    )
                    .await
                    {
                        Ok(()) => {
                            sqlx::query("update control.odoo_databases set state='ready' where id=$1 and workshop_id=$2")
                                .bind(database_id).bind(workshop).execute(&state.ledger).await.map_err(DriverError::internal)?;
                            tracing::error!(workshop=%workshop,recovery=%recovery_id,"restore failed and was rolled back to the verified safety backup");
                            Ok(
                                json!({"action":"restore","restore_status":"rolled_back","safe_error":"restore_failed_rolled_back","safety_recovery_point":safety_recovery_point}),
                            )
                        }
                        Err(rollback_error) => {
                            tracing::error!(workshop=%workshop,recovery=%recovery_id,error=%rollback_error.1,"restore and automatic rollback both failed");
                            Err(original_error)
                        }
                    }
                }
            }
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
                &["odoo".to_owned()],
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
                &["odoo".to_owned()],
                RECOVERY_FORMAT_V2,
            )
            .await?;
            Ok(
                json!({"action":"duplicate","database":{"database_ref":target_ref,"routable":false}}),
            )
        }
            _ => Err(DriverError::bad("unsupported lifecycle action")),
        }
    }
    .await;
    let retain_quarantine = action == "delete" && result.is_ok();
    let resume = if retain_quarantine {
        Ok(())
    } else {
        set_database_connection_limit(state, &database_ref, previous_limit).await
    };
    if resume.is_ok() && !retain_quarantine {
        sqlx::query(
            "update control.odoo_databases set connection_limit_before_lifecycle=null where id=$1",
        )
        .bind(database_id)
        .execute(&state.ledger)
        .await
        .map_err(DriverError::internal)?;
    }
    match (result, resume) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (_, Err(error)) => Err(error),
    }
}

async fn set_database_connection_limit(
    state: &DriverState,
    database: &str,
    limit: i32,
) -> Result<(), DriverError> {
    if !safe_pg_identifier(database) || limit < -1 {
        return Err(DriverError::bad("unsafe PostgreSQL connection limit"));
    }
    sqlx::query(AssertSqlSafe(format!(
        "alter database \"{database}\" connection limit {limit}"
    )))
    .execute(&state.postgres)
    .await
    .map_err(DriverError::internal)?;
    Ok(())
}

async fn drain_database_sessions(state: &DriverState, database: &str) -> Result<(), DriverError> {
    if !safe_pg_identifier(database) {
        return Err(DriverError::bad("unsafe database reference"));
    }
    sqlx::query("select pg_terminate_backend(pid) from pg_stat_activity where datname=$1 and pid<>pg_backend_pid()")
        .bind(database)
        .execute(&state.postgres)
        .await
        .map_err(DriverError::internal)?;
    Ok(())
}

async fn drain_workshop_operations(state: &DriverState, workshop: Uuid) -> Result<(), DriverError> {
    for _ in 0..60 {
        let active = sqlx::query_scalar::<_, i64>(
            "select count(*) from control.operations where workshop_id=$1 and kind='invoice.capture' and state='in_flight'",
        )
        .bind(workshop)
        .fetch_one(&state.ledger)
        .await
        .map_err(DriverError::internal)?;
        if active == 0 {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    Err(DriverError::internal(
        "timed out draining in-flight workshop operations",
    ))
}

async fn enter_workshop_maintenance(
    state: &DriverState,
    workshop: Uuid,
) -> Result<Vec<u8>, DriverError> {
    let path = state.config.route_root.join(format!("{workshop}.conf"));
    let backup = state
        .config
        .route_root
        .join(format!("{workshop}.recovery.bak"));
    let previous = if backup.is_file() {
        std::fs::read(&backup).map_err(DriverError::internal)?
    } else {
        let contents = std::fs::read(&path).map_err(DriverError::internal)?;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        use std::io::Write;
        options
            .open(&backup)
            .and_then(|mut file| {
                file.write_all(&contents)?;
                file.sync_all()
            })
            .map_err(DriverError::internal)?;
        contents
    };
    let text = std::str::from_utf8(&previous)
        .map_err(|_| DriverError::internal("workshop route is not UTF-8"))?;
    let hostnames = text
        .lines()
        .filter_map(|line| line.trim().strip_prefix("server_name "))
        .map(|value| value.trim_end_matches(';'))
        .collect::<Vec<_>>();
    if hostnames.is_empty()
        || hostnames
            .iter()
            .any(|name| hostname(&json!({"host":name}), "host").is_err())
    {
        return Err(DriverError::internal(
            "workshop route contains no safe hostnames",
        ));
    }
    let maintenance = hostnames
        .iter()
        .map(|name| format!("server {{\n  listen 8080;\n  server_name {name};\n  add_header Retry-After 120 always;\n  location / {{ return 503; }}\n}}\n"))
        .collect::<String>();
    replace_route_config(state, workshop, maintenance.as_bytes()).await?;
    Ok(previous)
}

async fn leave_workshop_maintenance(
    state: &DriverState,
    workshop: Uuid,
    previous: &[u8],
) -> Result<(), DriverError> {
    replace_route_config(state, workshop, previous).await?;
    let backup = state
        .config
        .route_root
        .join(format!("{workshop}.recovery.bak"));
    if backup.exists() {
        std::fs::remove_file(backup).map_err(DriverError::internal)?;
    }
    Ok(())
}

async fn replace_route_config(
    state: &DriverState,
    workshop: Uuid,
    contents: &[u8],
) -> Result<(), DriverError> {
    let path = state.config.route_root.join(format!("{workshop}.conf"));
    let temporary = state
        .config
        .route_root
        .join(format!("{workshop}.recovery.tmp"));
    std::fs::write(&temporary, contents).map_err(DriverError::internal)?;
    std::fs::rename(&temporary, &path).map_err(DriverError::internal)?;
    docker_exec(state, &state.config.gateway_container, &["nginx", "-t"]).await?;
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

async fn mark_recovery_ready_in_driver(
    state: &DriverState,
    recovery: Uuid,
    result: &Value,
) -> Result<(), DriverError> {
    let get = |key| {
        result
            .get(key)
            .and_then(Value::as_str)
            .ok_or_else(|| DriverError::internal(format!("recovery result missing {key}")))
    };
    let size = result
        .get("size_bytes")
        .and_then(Value::as_i64)
        .ok_or_else(|| DriverError::internal("recovery result missing size_bytes"))?;
    let components = result
        .get("components")
        .and_then(Value::as_array)
        .ok_or_else(|| DriverError::internal("recovery result missing components"))?;
    let mut tx = state.ledger.begin().await.map_err(DriverError::internal)?;
    let retention_days = result
        .get("retention_days")
        .and_then(Value::as_i64)
        .unwrap_or(35);
    sqlx::query("update control.workshop_recovery_points set state='ready',storage_ref=$2,size_bytes=$3,ready_at=now(),verification_state='verified',verified_at=now(),manifest_digest=$4,format_version=$5,storage_location=$6,source_release=$7,paperless_version=$8,encryption_key_id=$9,object_prefix=$10,expires_at=now()+make_interval(days=>$11) where id=$1")
        .bind(recovery)
        .bind(get("storage_ref")?)
        .bind(size)
        .bind(get("manifest_digest")?)
        .bind(get("format_version")?)
        .bind(get("storage_location")?)
        .bind(get("source_release")?)
        .bind(result.get("paperless_version").and_then(Value::as_str))
        .bind(result.get("encryption_key_id").and_then(Value::as_str))
        .bind(result.get("object_prefix").and_then(Value::as_str))
        .bind(i32::try_from(retention_days).map_err(DriverError::internal)?)
        .execute(&mut *tx)
        .await
        .map_err(DriverError::internal)?;
    sqlx::query("delete from control.workshop_recovery_components where recovery_point_id=$1")
        .bind(recovery)
        .execute(&mut *tx)
        .await
        .map_err(DriverError::internal)?;
    for component in components {
        let string = |key| {
            component
                .get(key)
                .and_then(Value::as_str)
                .ok_or_else(|| DriverError::internal(format!("recovery component missing {key}")))
        };
        let bytes = component
            .get("size_bytes")
            .and_then(Value::as_i64)
            .ok_or_else(|| DriverError::internal("recovery component missing size_bytes"))?;
        sqlx::query("insert into control.workshop_recovery_components(recovery_point_id,component,object_key,size_bytes,digest,plaintext_digest,state,verified_at) values($1,$2,$3,$4,$5,$6,'verified',now())")
            .bind(recovery).bind(string("name")?).bind(string("path")?).bind(bytes).bind(string("sha256")?).bind(component.get("plaintext_sha256").and_then(Value::as_str)).execute(&mut *tx).await.map_err(DriverError::internal)?;
    }
    tx.commit().await.map_err(DriverError::internal)
}

async fn recovery_scope(
    state: &DriverState,
    workshop: Uuid,
    recovery: Uuid,
) -> Result<Vec<String>, DriverError> {
    sqlx::query_scalar(
        "select component_scope from control.workshop_recovery_points where id=$1 and workshop_id=$2",
    )
    .bind(recovery)
    .bind(workshop)
    .fetch_optional(&state.ledger)
    .await
    .map_err(DriverError::internal)?
    .ok_or_else(|| DriverError(StatusCode::NOT_FOUND, "recovery point not found".into()))
}

async fn resolve_stored_recovery(
    state: &DriverState,
    workshop: Uuid,
    recovery: Uuid,
) -> Result<StoredRecovery, DriverError> {
    let row = sqlx::query(
        "select storage_ref,component_scope,format_version from control.workshop_recovery_points where id=$1 and workshop_id=$2 and state='ready' and verification_state='verified' and storage_ref is not null and (expires_at is null or expires_at > now())",
    )
    .bind(recovery)
    .bind(workshop)
    .fetch_optional(&state.ledger)
    .await
    .map_err(DriverError::internal)?
    .ok_or_else(|| DriverError::bad("recovery point is not ready and verified"))?;
    Ok(StoredRecovery {
        storage_ref: row.get("storage_ref"),
        component_scope: row.get("component_scope"),
        format_version: row.get("format_version"),
    })
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
    component_scope: &[String],
) -> Result<Value, DriverError> {
    if !safe_pg_identifier(database_ref) {
        return Err(DriverError::bad("unsafe database reference"));
    }
    if let Some(existing) = existing_recovery_response(state, recovery).await? {
        return Ok(existing);
    }
    if kind == "backup" {
        return create_remote_recovery_set(
            state,
            workshop,
            recovery,
            database_ref,
            kind,
            component_scope,
        )
        .await;
    }
    let relative = PathBuf::from("docker-backup")
        .join(workshop.to_string())
        .join(recovery.to_string());
    let directory = state.config.backup_root.join(&relative);
    let complete = directory.join("complete.json");
    if complete.is_file() {
        let size = directory_size(&directory).map_err(DriverError::internal)?;
        let manifest = read_v2_manifest(&directory)?;
        let manifest_digest =
            digest_file(&directory.join("manifest.json")).map_err(DriverError::internal)?;
        return recovery_response(&directory, &relative, size, &manifest, manifest_digest);
    }
    if directory.exists() {
        std::fs::remove_dir_all(&directory).map_err(DriverError::internal)?;
    }
    secure_directory(&directory).map_err(DriverError::internal)?;
    let odoo_directory = directory.join("odoo");
    secure_directory(&odoo_directory).map_err(DriverError::internal)?;
    let dump_relative = relative.join("odoo/database.dump");
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
            format!("--username={}", state.config.postgres_admin_user),
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
    let target_filestore = odoo_directory.join("filestore");
    copy_directory(&source_filestore, &target_filestore, None).map_err(DriverError::internal)?;
    let mut components = vec![
        recovery_component("odoo-database", "odoo/database.dump", &directory)?,
        recovery_component("odoo-filestore", "odoo/filestore", &directory)?,
    ];
    let paperless_version = if component_scope.iter().any(|item| item == "paperless") {
        backup_paperless(
            state,
            workshop,
            recovery,
            &relative,
            &directory,
            &mut components,
        )
        .await?;
        state.config.paperless_image.clone()
    } else {
        None
    };
    let manifest = RecoveryManifest {
        format: RECOVERY_FORMAT_V2.to_owned(),
        recovery_id: recovery,
        workshop_id: workshop,
        database_ref: database_ref.to_owned(),
        kind: kind.to_owned(),
        source_release: env!("CARGO_PKG_VERSION").to_owned(),
        odoo_version: state.config.odoo_image.clone(),
        paperless_version,
        paperless_database_ref: component_scope
            .iter()
            .any(|item| item == "paperless")
            .then(|| format!("pl_{}", tenant_key(workshop))),
        created_at_unix: time::OffsetDateTime::now_utc().unix_timestamp(),
        expires_at_unix: None,
        encryption: None,
        encryption_key_id: None,
        component_scope: component_scope.to_vec(),
        components,
    };
    let manifest_path = directory.join("manifest.json");
    std::fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).map_err(DriverError::internal)?,
    )
    .map_err(DriverError::internal)?;
    let manifest_digest = digest_file(&manifest_path).map_err(DriverError::internal)?;
    std::fs::write(
        &complete,
        serde_json::to_vec_pretty(&json!({
            "format": RECOVERY_FORMAT_V2,
            "manifest_sha256": manifest_digest,
        }))
        .map_err(DriverError::internal)?,
    )
    .map_err(DriverError::internal)?;
    verify_recovery_directory(&directory, workshop, component_scope)?;
    let size = directory_size(&directory).map_err(DriverError::internal)?;
    recovery_response(&directory, &relative, size, &manifest, manifest_digest)
}

async fn existing_recovery_response(
    state: &DriverState,
    recovery: Uuid,
) -> Result<Option<Value>, DriverError> {
    let row = sqlx::query("select storage_ref,storage_location,size_bytes,manifest_digest,format_version,source_release,paperless_version,encryption_key_id,object_prefix from control.workshop_recovery_points where id=$1 and state='ready' and verification_state='verified' and storage_ref is not null")
        .bind(recovery)
        .fetch_optional(&state.ledger)
        .await
        .map_err(DriverError::internal)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let components = sqlx::query("select component,object_key,size_bytes,digest,plaintext_digest from control.workshop_recovery_components where recovery_point_id=$1 order by component")
        .bind(recovery)
        .fetch_all(&state.ledger)
        .await
        .map_err(DriverError::internal)?
        .into_iter()
        .map(|component| json!({
            "name": component.get::<String,_>("component"),
            "path": component.get::<String,_>("object_key"),
            "size_bytes": component.get::<i64,_>("size_bytes"),
            "sha256": component.get::<String,_>("digest"),
            "plaintext_sha256": component.get::<Option<String>,_>("plaintext_digest"),
        }))
        .collect::<Vec<_>>();
    Ok(Some(json!({
        "storage_ref": row.get::<String,_>("storage_ref"),
        "storage_location": row.get::<String,_>("storage_location"),
        "size_bytes": row.get::<Option<i64>,_>("size_bytes").ok_or_else(|| DriverError::internal("ready recovery is missing size_bytes"))?,
        "manifest_digest": row.get::<Option<String>,_>("manifest_digest").ok_or_else(|| DriverError::internal("ready recovery is missing manifest_digest"))?,
        "format_version": row.get::<String,_>("format_version"),
        "source_release": row.get::<Option<String>,_>("source_release").ok_or_else(|| DriverError::internal("ready recovery is missing source_release"))?,
        "paperless_version": row.get::<Option<String>,_>("paperless_version"),
        "encryption_key_id": row.get::<Option<String>,_>("encryption_key_id"),
        "object_prefix": row.get::<Option<String>,_>("object_prefix"),
        "components": components,
    })))
}

async fn restore_recovery_set(
    state: &DriverState,
    workshop: Uuid,
    target_database: &str,
    storage_ref: &str,
    expected_scope: &[String],
    format_version: &str,
) -> Result<(), DriverError> {
    if !safe_pg_identifier(target_database) {
        return Err(DriverError::bad("unsafe target database reference"));
    }
    if storage_ref.starts_with("s3://") {
        return restore_remote_recovery_set(
            state,
            workshop,
            target_database,
            storage_ref,
            expected_scope,
            false,
        )
        .await;
    }
    let relative = safe_storage_ref(storage_ref, workshop)?;
    let directory = state.config.backup_root.join(&relative);
    let resolved = std::fs::canonicalize(&directory).map_err(DriverError::internal)?;
    let root = std::fs::canonicalize(&state.config.backup_root).map_err(DriverError::internal)?;
    if !resolved.starts_with(&root) || !resolved.join("complete.json").is_file() {
        return Err(DriverError::bad("recovery set is incomplete"));
    }
    if format_version == "makersbrain-odoo-recovery-v1" {
        return restore_legacy_recovery_set(state, target_database, &relative, &resolved).await;
    }
    let manifest = verify_recovery_directory(&resolved, workshop, expected_scope)?;
    validate_paperless_version(state, &manifest)?;
    validate_local_dump(state, &relative.join("odoo/database.dump"), "odoo").await?;
    if manifest
        .component_scope
        .iter()
        .any(|item| item == "paperless")
    {
        validate_local_dump(
            state,
            &relative.join("paperless/database.dump"),
            &format!("pl_{}", tenant_key(workshop)),
        )
        .await?;
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
            format!("--username={}", state.config.postgres_admin_user),
            format!("--dbname={target_database}"),
            format!("/backups/{}/odoo/database.dump", relative.to_string_lossy()),
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
        &resolved.join("odoo/filestore"),
        &target_filestore,
        Some((state.config.odoo_uid, state.config.odoo_gid)),
    )
    .map_err(DriverError::internal)?;
    if manifest
        .component_scope
        .iter()
        .any(|item| item == "paperless")
    {
        restore_paperless(state, workshop, &relative, &resolved).await?;
    }
    validate_restored_databases(state, workshop, target_database, &manifest.component_scope).await
}

async fn create_remote_recovery_set(
    state: &DriverState,
    workshop: Uuid,
    recovery: Uuid,
    database_ref: &str,
    kind: &str,
    component_scope: &[String],
) -> Result<Value, DriverError> {
    update_recovery_progress(
        state,
        recovery,
        10,
        "capturing",
        "Capturing workshop databases and files",
    )
    .await?;
    let s3 = state
        .config
        .s3_backup
        .as_ref()
        .ok_or_else(|| DriverError::bad("portable S3 backups are not configured"))?;
    let image = state
        .config
        .backup_agent_image
        .as_ref()
        .ok_or_else(|| DriverError::bad("backup agent image is not configured"))?;
    let relative = PathBuf::from("docker-upload")
        .join(workshop.to_string())
        .join(recovery.to_string());
    let directory = state.config.backup_root.join(&relative);
    if directory.exists() {
        std::fs::remove_dir_all(&directory).map_err(DriverError::internal)?;
    }
    secure_directory(&directory).map_err(DriverError::internal)?;

    let compact = tenant_key(workshop);
    let paperless_database = format!("pl_{compact}");
    let includes_paperless = component_scope.iter().any(|item| item == "paperless");
    let mut binds = vec![
        format!("{}:/backups", state.config.backup_volume),
        format!("{}:/odoo:ro", state.config.odoo_volume),
        format!(
            "{}:/run/makersbrain-backup-secrets:ro",
            state.config.backup_secret_volume
        ),
    ];
    if includes_paperless {
        for suffix in ["data", "media", "consume"] {
            binds.push(format!(
                "mb-paperless-{workshop}-{suffix}:/paperless/{suffix}:ro"
            ));
        }
    }
    let mut command = format!(
        "set -eu; set -o pipefail; umask 077; reject_special() {{ test ! -d \"$1\" || test -z \"$(find \"$1\" -mindepth 1 ! -type d ! -type f -print -quit)\"; }}; encrypt_stream() {{ output=$1; checksum=$2; fifo=\"${{checksum}}.fifo\"; mkfifo \"$fifo\"; sha256sum <\"$fifo\" | cut -d' ' -f1 >\"$checksum\" & hash_pid=$!; tee \"$fifo\" | zstd -q -T0 | age -r \"$AGE_RECIPIENT\" -o \"$output\"; wait \"$hash_pid\"; rm -f \"$fifo\"; }}; out=/backups/{}; mkdir -p \"$out/odoo\"; pg_dump --format=custom --no-owner --no-acl --host=\"$PGHOST\" --port=\"$PGPORT\" --username=\"$PGUSER\" \"$ODOO_DATABASE\" | encrypt_stream \"$out/odoo/database.dump.enc\" \"$out/odoo/database.dump.plain.sha256\"; reject_special \"/odoo/filestore/$ODOO_DATABASE\"; if [ -d \"/odoo/filestore/$ODOO_DATABASE\" ]; then tar -C \"/odoo/filestore/$ODOO_DATABASE\" -cf - .; else tar -cf - --files-from /dev/null; fi | encrypt_stream \"$out/odoo/filestore.tar.zst.enc\" \"$out/odoo/filestore.plain.sha256\"",
        relative.to_string_lossy()
    );
    if includes_paperless {
        command.push_str("; mkdir -p \"$out/paperless\"; pg_dump --format=custom --no-owner --no-acl --host=\"$PGHOST\" --port=\"$PGPORT\" --username=\"$PGUSER\" \"$PAPERLESS_DATABASE\" | encrypt_stream \"$out/paperless/database.dump.enc\" \"$out/paperless/database.dump.plain.sha256\"; for part in data media consume; do reject_special /paperless/$part; tar -C /paperless/$part -cf - . | encrypt_stream \"$out/paperless/$part.tar.zst.enc\" \"$out/paperless/$part.plain.sha256\"; done");
    }
    run_docker_job(
        state,
        &format!("mb-encrypt-{}", &recovery.simple().to_string()[..12]),
        json!({
            "Image": image,
            "User": "0:0",
            "Cmd": ["sh", "-ec", command],
            "Env": [
                format!("PGHOST={}", state.config.postgres_host),
                format!("PGPORT={}", state.config.postgres_port),
                format!("PGUSER={}", state.config.postgres_admin_user),
                format!("PGPASSWORD={}", state.config.postgres_admin_password),
                format!("ODOO_DATABASE={database_ref}"),
                format!("PAPERLESS_DATABASE={paperless_database}"),
                format!("AGE_RECIPIENT={}", s3.age_recipient),
            ],
            "Labels": {"makersbrain.kind":"encrypted-backup-job"},
            "HostConfig": {"NetworkMode": state.config.docker_network, "Binds": binds}
        }),
    )
    .await?;
    update_recovery_progress(
        state,
        recovery,
        45,
        "encrypting",
        "Encrypted workshop components created",
    )
    .await?;

    let mut components = vec![
        encrypted_recovery_component(
            "odoo-database",
            "odoo/database.dump.enc",
            "odoo/database.dump.plain.sha256",
            &directory,
        )?,
        encrypted_recovery_component(
            "odoo-filestore",
            "odoo/filestore.tar.zst.enc",
            "odoo/filestore.plain.sha256",
            &directory,
        )?,
    ];
    if includes_paperless {
        for (name, path, checksum) in [
            (
                "paperless-database",
                "paperless/database.dump.enc",
                "paperless/database.dump.plain.sha256",
            ),
            (
                "paperless-data",
                "paperless/data.tar.zst.enc",
                "paperless/data.plain.sha256",
            ),
            (
                "paperless-media",
                "paperless/media.tar.zst.enc",
                "paperless/media.plain.sha256",
            ),
            (
                "paperless-consume",
                "paperless/consume.tar.zst.enc",
                "paperless/consume.plain.sha256",
            ),
        ] {
            components.push(encrypted_recovery_component(
                name, path, checksum, &directory,
            )?);
        }
    }
    let manifest = RecoveryManifest {
        format: RECOVERY_FORMAT_V2.to_owned(),
        recovery_id: recovery,
        workshop_id: workshop,
        database_ref: database_ref.to_owned(),
        kind: kind.to_owned(),
        source_release: env!("CARGO_PKG_VERSION").to_owned(),
        odoo_version: state.config.odoo_image.clone(),
        paperless_version: includes_paperless
            .then(|| state.config.paperless_image.clone())
            .flatten(),
        paperless_database_ref: includes_paperless.then_some(paperless_database),
        created_at_unix: time::OffsetDateTime::now_utc().unix_timestamp(),
        expires_at_unix: Some(
            (time::OffsetDateTime::now_utc() + time::Duration::days(i64::from(s3.retention_days)))
                .unix_timestamp(),
        ),
        encryption: Some("age-x25519".to_owned()),
        encryption_key_id: Some(s3.encryption_key_id.clone()),
        component_scope: component_scope.to_vec(),
        components,
    };
    let serialized_manifest = serde_json::to_vec(&manifest).map_err(DriverError::internal)?;
    let plaintext_manifest_digest = format!("{:x}", Sha256::digest(&serialized_manifest));
    let manifest_b64 = base64::engine::general_purpose::STANDARD.encode(serialized_manifest);
    run_docker_job(
        state,
        &format!("mb-manifest-{}", &recovery.simple().to_string()[..12]),
        json!({
            "Image": image,
            "User": "0:0",
            "Cmd": ["sh", "-ec", format!("set -eu; umask 077; printf %s \"$MANIFEST_B64\" | base64 -d | age -r \"$AGE_RECIPIENT\" -o /backups/{}/manifest.json.enc", relative.to_string_lossy())],
            "Env": [format!("MANIFEST_B64={manifest_b64}"), format!("AGE_RECIPIENT={}", s3.age_recipient)],
            "Labels": {"makersbrain.kind":"encrypted-backup-manifest-job"},
            "HostConfig": {"Binds": [format!("{}:/backups", state.config.backup_volume)]}
        }),
    )
    .await?;
    let encrypted_manifest_digest =
        digest_file(&directory.join("manifest.json.enc")).map_err(DriverError::internal)?;
    let complete = json!({
        "format": RECOVERY_FORMAT_V2,
        "recovery_id": recovery,
        "manifest_sha256": encrypted_manifest_digest,
        "encryption": "age-x25519",
        "encryption_key_id": s3.encryption_key_id,
        "created_at_unix": manifest.created_at_unix,
        "expires_at_unix": manifest.expires_at_unix,
    });
    std::fs::write(
        directory.join("complete.json"),
        serde_json::to_vec_pretty(&complete).map_err(DriverError::internal)?,
    )
    .map_err(DriverError::internal)?;
    update_recovery_progress(
        state,
        recovery,
        60,
        "packaging",
        "Building portable archive",
    )
    .await?;
    const ARCHIVE_NAME: &str = "makersbrain-workshop-backup.tar";
    run_docker_job(
        state,
        &format!("mb-archive-{}", &recovery.simple().to_string()[..12]),
        json!({
            "Image": image,
            "User": "0:0",
            "Cmd": ["sh", "-ec", format!("set -eu; umask 077; root=/backups/{}; tar -C \"$root\" -cf \"$root/{ARCHIVE_NAME}\" odoo {} manifest.json.enc complete.json", relative.to_string_lossy(), if includes_paperless { "paperless" } else { "" })],
            "Labels": {"makersbrain.kind":"portable-backup-archive-job"},
            "HostConfig": {"Binds": [format!("{}:/backups", state.config.backup_volume)]}
        }),
    )
    .await?;
    let object_prefix = format!("workshops/{workshop}/recovery/{recovery}");
    update_recovery_progress(
        state,
        recovery,
        72,
        "uploading",
        "Uploading encrypted archive to S3",
    )
    .await?;
    upload_and_verify_s3(state, &relative, &object_prefix, &manifest).await?;
    update_recovery_progress(
        state,
        recovery,
        92,
        "verifying",
        "Verifying the uploaded archive",
    )
    .await?;
    let archive_component = recovery_component("portable-archive", ARCHIVE_NAME, &directory)?;
    let size_bytes = archive_component.size_bytes;
    let storage_ref = format!("s3://{}/{object_prefix}", s3.bucket);
    let mut recorded_components = manifest.components.clone();
    let mut manifest_component = recovery_component("manifest", "manifest.json.enc", &directory)?;
    manifest_component.plaintext_sha256 = Some(plaintext_manifest_digest);
    recorded_components.push(manifest_component);
    recorded_components.push(recovery_component(
        "commit-marker",
        "complete.json",
        &directory,
    )?);
    recorded_components.push(archive_component.clone());
    std::fs::remove_dir_all(&directory).map_err(DriverError::internal)?;
    Ok(json!({
        "storage_ref": storage_ref,
        "storage_location": "s3",
        "size_bytes": size_bytes,
        "manifest_digest": encrypted_manifest_digest,
        "format_version": RECOVERY_FORMAT_V2,
        "source_release": manifest.source_release,
        "paperless_version": manifest.paperless_version,
        "encryption_key_id": s3.encryption_key_id,
        "object_prefix": object_prefix,
        "retention_days": s3.retention_days,
        "components": recorded_components,
        "archive_object_key": format!("{object_prefix}/{ARCHIVE_NAME}"),
        "archive_size_bytes": archive_component.size_bytes,
        "archive_digest": archive_component.sha256,
    }))
}

async fn update_recovery_progress(
    state: &DriverState,
    recovery: Uuid,
    percent: i16,
    phase: &str,
    message: &str,
) -> Result<(), DriverError> {
    sqlx::query(
        "update control.operations o set progress_percent=$2,progress_phase=$3,
                progress_message=$4,progress_updated_at=now()
         from control.workshop_recovery_points r
         where r.id=$1 and r.operation_id=o.id and o.state='in_flight'",
    )
    .bind(recovery)
    .bind(percent)
    .bind(phase)
    .bind(message)
    .execute(&state.ledger)
    .await
    .map_err(DriverError::internal)?;
    Ok(())
}

async fn upload_and_verify_s3(
    state: &DriverState,
    relative: &Path,
    object_prefix: &str,
    manifest: &RecoveryManifest,
) -> Result<(), DriverError> {
    let s3 = state.config.s3_backup.as_ref().unwrap();
    let image = state.config.backup_agent_image.as_ref().unwrap();
    let mut object_paths = manifest
        .components
        .iter()
        .map(|component| component.path.clone())
        .collect::<Vec<_>>();
    object_paths.push("manifest.json.enc".to_owned());
    object_paths.push("makersbrain-workshop-backup.tar".to_owned());
    let files = object_paths.join(" ");
    let command = format!(
        "set -eu; set -o pipefail; root=/backups/{}; for file in {files}; do if [ \"$file\" = makersbrain-workshop-backup.tar ]; then aws --endpoint-url \"$S3_ENDPOINT\" s3 cp --only-show-errors --content-type application/x-tar --content-disposition 'attachment; filename=\"makersbrain-workshop-backup.tar\"' \"$root/$file\" \"s3://$S3_BUCKET/$S3_PREFIX/$file\"; else aws --endpoint-url \"$S3_ENDPOINT\" s3 cp --only-show-errors \"$root/$file\" \"s3://$S3_BUCKET/$S3_PREFIX/$file\"; fi; local_sum=$(sha256sum \"$root/$file\" | cut -d' ' -f1); remote_sum=$(aws --endpoint-url \"$S3_ENDPOINT\" s3 cp --only-show-errors \"s3://$S3_BUCKET/$S3_PREFIX/$file\" - | sha256sum | cut -d' ' -f1); test \"$local_sum\" = \"$remote_sum\"; done; aws --endpoint-url \"$S3_ENDPOINT\" s3 cp --only-show-errors \"$root/complete.json\" \"s3://$S3_BUCKET/$S3_PREFIX/complete.json\"; local_sum=$(sha256sum \"$root/complete.json\" | cut -d' ' -f1); remote_sum=$(aws --endpoint-url \"$S3_ENDPOINT\" s3 cp --only-show-errors \"s3://$S3_BUCKET/$S3_PREFIX/complete.json\" - | sha256sum | cut -d' ' -f1); test \"$local_sum\" = \"$remote_sum\"",
        relative.to_string_lossy()
    );
    run_docker_job(
        state,
        &format!(
            "mb-upload-{}",
            &manifest.recovery_id.simple().to_string()[..12]
        ),
        json!({
            "Image": image,
            "User": "0:0",
            "Cmd": ["sh", "-ec", command],
            "Env": s3_environment(s3, true, object_prefix),
            "Labels": {"makersbrain.kind":"s3-backup-upload-job"},
            "HostConfig": {"Binds": [format!("{}:/backups:ro", state.config.backup_volume)]}
        }),
    )
    .await
}

async fn validate_restored_databases(
    state: &DriverState,
    workshop: Uuid,
    odoo_database: &str,
    scope: &[String],
) -> Result<(), DriverError> {
    let paperless = scope
        .iter()
        .any(|item| item == "paperless")
        .then(|| format!("pl_{}", tenant_key(workshop)));
    validate_recovery_database_content(state, odoo_database, paperless.as_deref()).await
}

async fn validate_recovery_database_content(
    state: &DriverState,
    odoo_database: &str,
    paperless_database: Option<&str>,
) -> Result<(), DriverError> {
    validate_database_table(state, odoo_database, "ir_module_module").await?;
    let Some(paperless_database) = paperless_database else {
        return Ok(());
    };
    validate_database_table(state, paperless_database, "documents_document").await?;
    let paperless = database_pool(state, paperless_database).await?;
    let invalid_checksums = sqlx::query_scalar::<_, i64>(
        "select count(*)::bigint from documents_document where checksum is null or btrim(checksum)=''",
    )
    .fetch_one(&paperless)
    .await
    .map_err(DriverError::internal)?;
    let document_ids =
        sqlx::query_scalar::<_, i64>("select id::bigint from documents_document order by id")
            .fetch_all(&paperless)
            .await
            .map_err(DriverError::internal)?
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>();
    paperless.close().await;
    if invalid_checksums != 0 {
        return Err(DriverError::bad(
            "restored Paperless document checksum validation failed",
        ));
    }
    let odoo = database_pool(state, odoo_database).await?;
    let capture_table = sqlx::query_scalar::<_, bool>(
        "select to_regclass('public.mb_invoice_capture') is not null",
    )
    .fetch_one(&odoo)
    .await
    .map_err(DriverError::internal)?;
    if capture_table {
        let links = sqlx::query_scalar::<_, String>(
            "select external_document_id from mb_invoice_capture where external_document_id like 'paperless:%'",
        )
        .fetch_all(&odoo)
        .await
        .map_err(DriverError::internal)?;
        if links.iter().any(|link| {
            link.strip_prefix("paperless:")
                .and_then(|value| value.parse::<i64>().ok())
                .is_none_or(|id| !document_ids.contains(&id))
        }) {
            odoo.close().await;
            return Err(DriverError::bad(
                "restored Odoo to Paperless document link validation failed",
            ));
        }
    }
    odoo.close().await;
    Ok(())
}

async fn database_pool(state: &DriverState, database: &str) -> Result<PgPool, DriverError> {
    if !safe_pg_identifier(database) {
        return Err(DriverError::bad("unsafe database validation target"));
    }
    let mut url = Url::parse(&state.config.postgres_admin_url).map_err(DriverError::internal)?;
    url.set_path(&format!("/{database}"));
    PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(10))
        .connect(url.as_str())
        .await
        .map_err(DriverError::internal)
}

async fn validate_database_table(
    state: &DriverState,
    database: &str,
    table: &str,
) -> Result<(), DriverError> {
    if !safe_pg_identifier(database) || !safe_pg_identifier(table) {
        return Err(DriverError::bad("unsafe database validation target"));
    }
    let pool = database_pool(state, database).await?;
    let exists = sqlx::query_scalar::<_, bool>("select to_regclass($1) is not null")
        .bind(format!("public.{table}"))
        .fetch_one(&pool)
        .await
        .map_err(DriverError::internal)?;
    pool.close().await;
    if !exists {
        return Err(DriverError::bad(
            "restored database health validation failed",
        ));
    }
    Ok(())
}

fn s3_environment(s3: &S3BackupConfig, writer: bool, prefix: &str) -> Vec<String> {
    let (access_key, secret_key) = if writer {
        (&s3.writer_access_key_id, &s3.writer_secret_access_key)
    } else {
        (&s3.reader_access_key_id, &s3.reader_secret_access_key)
    };
    vec![
        format!("AWS_ACCESS_KEY_ID={access_key}"),
        format!("AWS_SECRET_ACCESS_KEY={secret_key}"),
        format!("AWS_DEFAULT_REGION={}", s3.region),
        format!("S3_ENDPOINT={}", s3.endpoint),
        format!("S3_BUCKET={}", s3.bucket),
        format!("S3_PREFIX={prefix}"),
    ]
}

async fn restore_remote_recovery_set(
    state: &DriverState,
    workshop: Uuid,
    target_database: &str,
    storage_ref: &str,
    expected_scope: &[String],
    preflight_only: bool,
) -> Result<(), DriverError> {
    let s3 = state
        .config
        .s3_backup
        .as_ref()
        .ok_or_else(|| DriverError::bad("S3 restore is not configured"))?;
    let image = state
        .config
        .backup_agent_image
        .as_ref()
        .ok_or_else(|| DriverError::bad("backup agent image is not configured"))?;
    let (prefix, recovery_id) = safe_s3_storage_ref(storage_ref, &s3.bucket, workshop)?;
    let relative = PathBuf::from("docker-restore")
        .join(workshop.to_string())
        .join(recovery_id.to_string());
    let directory = state.config.backup_root.join(&relative);
    if directory.exists() {
        std::fs::remove_dir_all(&directory).map_err(DriverError::internal)?;
    }
    secure_directory(&directory).map_err(DriverError::internal)?;

    let result = restore_remote_recovery_inner(
        state,
        workshop,
        target_database,
        &prefix,
        &relative,
        &directory,
        expected_scope,
        image,
        s3,
        preflight_only,
    )
    .await;
    let cleanup = std::fs::remove_dir_all(&directory).map_err(DriverError::internal);
    match (result, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), _) => Err(error),
        (_, Err(error)) => Err(error),
    }
}

#[allow(clippy::too_many_arguments)]
async fn restore_remote_recovery_inner(
    state: &DriverState,
    workshop: Uuid,
    target_database: &str,
    prefix: &str,
    relative: &Path,
    directory: &Path,
    expected_scope: &[String],
    image: &str,
    s3: &S3BackupConfig,
    preflight_only: bool,
) -> Result<(), DriverError> {
    // Rehearsals are part of routine backup verification and use the append-only
    // writer's read permission. Live restores use the separately granted,
    // prefix-scoped reader identity.
    let mut environment = s3_environment(s3, preflight_only, prefix);
    environment.push(format!("AGE_IDENTITY={}", s3.age_identity_file));
    let bootstrap = format!(
        "set -eu; set -o pipefail; umask 077; root=/backups/{}; aws --endpoint-url \"$S3_ENDPOINT\" s3 cp --only-show-errors \"s3://$S3_BUCKET/$S3_PREFIX/complete.json\" \"$root/complete.json\"; aws --endpoint-url \"$S3_ENDPOINT\" s3 cp --only-show-errors \"s3://$S3_BUCKET/$S3_PREFIX/manifest.json.enc\" \"$root/manifest.json.enc\"; age -d -i \"$AGE_IDENTITY\" -o \"$root/manifest.json\" \"$root/manifest.json.enc\"",
        relative.to_string_lossy()
    );
    run_docker_job(
        state,
        &format!("mb-download-{}", &Uuid::new_v4().simple().to_string()[..12]),
        json!({
            "Image": image,
            "User": "0:0",
            "Cmd": ["sh", "-ec", bootstrap],
            "Env": environment,
            "Labels": {"makersbrain.kind":"s3-restore-download-job"},
            "HostConfig": {"Binds": [format!("{}:/backups", state.config.backup_volume), format!("{}:/run/makersbrain-backup-secrets:ro", state.config.backup_secret_volume)]}
        }),
    )
    .await?;
    let commit: Value = serde_json::from_slice(
        &std::fs::read(directory.join("complete.json")).map_err(DriverError::internal)?,
    )
    .map_err(|_| DriverError::bad("remote recovery commit marker is invalid"))?;
    if commit.get("format").and_then(Value::as_str) != Some(RECOVERY_FORMAT_V2)
        || commit.get("recovery_id").and_then(Value::as_str)
            != directory.file_name().and_then(std::ffi::OsStr::to_str)
    {
        return Err(DriverError::bad(
            "remote recovery commit marker is incompatible",
        ));
    }
    let manifest_cipher_digest =
        digest_file(&directory.join("manifest.json.enc")).map_err(DriverError::internal)?;
    if commit.get("manifest_sha256").and_then(Value::as_str)
        != Some(manifest_cipher_digest.as_str())
    {
        return Err(DriverError::bad(
            "remote recovery manifest integrity check failed",
        ));
    }
    let manifest: RecoveryManifest = serde_json::from_slice(
        &std::fs::read(directory.join("manifest.json")).map_err(DriverError::internal)?,
    )
    .map_err(|_| DriverError::bad("remote recovery manifest is invalid"))?;
    if manifest.format != RECOVERY_FORMAT_V2
        || manifest.recovery_id.to_string()
            != directory
                .file_name()
                .and_then(std::ffi::OsStr::to_str)
                .unwrap_or("")
        || manifest.workshop_id != workshop
        || normalized_scope(&manifest.component_scope) != normalized_scope(expected_scope)
        || !safe_pg_identifier(&manifest.database_ref)
        || manifest.odoo_version.trim().is_empty()
        || manifest.encryption.as_deref() != Some("age-x25519")
        || manifest.encryption_key_id.as_deref()
            != commit.get("encryption_key_id").and_then(Value::as_str)
        || manifest.expires_at_unix != commit.get("expires_at_unix").and_then(Value::as_i64)
    {
        return Err(DriverError::bad("remote recovery scope is incompatible"));
    }
    let expected_paperless_database = expected_scope
        .iter()
        .any(|item| item == "paperless")
        .then(|| format!("pl_{}", tenant_key(workshop)));
    if manifest.paperless_database_ref != expected_paperless_database {
        return Err(DriverError::bad(
            "remote Paperless database identity is incompatible",
        ));
    }
    validate_paperless_version(state, &manifest)?;
    let mut names = std::collections::BTreeSet::new();
    for component in &manifest.components {
        if !names.insert(component.name.as_str())
            || !safe_component_path(&component.path)
            || component.size_bytes < 0
            || !valid_sha256(&component.sha256)
            || !component
                .plaintext_sha256
                .as_deref()
                .is_some_and(valid_sha256)
        {
            return Err(DriverError::bad(
                "remote recovery component list is invalid",
            ));
        }
    }
    let required = if expected_scope.iter().any(|item| item == "paperless") {
        [
            "odoo-database",
            "odoo-filestore",
            "paperless-database",
            "paperless-data",
            "paperless-media",
            "paperless-consume",
        ]
        .as_slice()
    } else {
        ["odoo-database", "odoo-filestore"].as_slice()
    };
    if required.iter().any(|name| !names.contains(name)) || names.len() != required.len() {
        return Err(DriverError::bad(
            "remote recovery component scope is incomplete",
        ));
    }
    let object_paths = manifest
        .components
        .iter()
        .map(|component| {
            format!(
                "{}:{}",
                component.path,
                component.plaintext_sha256.as_deref().unwrap_or("")
            )
        })
        .collect::<Vec<_>>()
        .join(" ");
    let mut environment = s3_environment(s3, preflight_only, prefix);
    environment.push(format!("AGE_IDENTITY={}", s3.age_identity_file));
    let download = format!(
        "set -eu; set -o pipefail; root=/backups/{}; for item in {object_paths}; do file=${{item%:*}}; expected=${{item##*:}}; mkdir -p \"$root/$(dirname \"$file\")\"; aws --endpoint-url \"$S3_ENDPOINT\" s3 cp --only-show-errors \"s3://$S3_BUCKET/$S3_PREFIX/$file\" \"$root/$file\"; age -d -i \"$AGE_IDENTITY\" \"$root/$file\" | zstd -q -t; actual=$(age -d -i \"$AGE_IDENTITY\" \"$root/$file\" | zstd -q -d | sha256sum | cut -d' ' -f1); test \"$actual\" = \"$expected\"; case \"$file\" in *.tar.zst.enc) if age -d -i \"$AGE_IDENTITY\" \"$root/$file\" | zstd -q -d | tar -tf - | grep -Eq '(^/|(^|/)\\.\\.(/|$))'; then echo unsafe-archive-path >&2; exit 1; fi; if age -d -i \"$AGE_IDENTITY\" \"$root/$file\" | zstd -q -d | tar -tvf - | grep -Eq '^[lh]'; then echo unsafe-archive-link >&2; exit 1; fi;; esac; done",
        relative.to_string_lossy()
    );
    run_docker_job(
        state,
        &format!("mb-verify-{}", &manifest.recovery_id.simple().to_string()[..12]),
        json!({
            "Image": image,
            "User": "0:0",
            "Cmd": ["sh", "-ec", download],
            "Env": environment,
            "Labels": {"makersbrain.kind":"s3-restore-verify-job"},
            "HostConfig": {"Binds": [format!("{}:/backups", state.config.backup_volume), format!("{}:/run/makersbrain-backup-secrets:ro", state.config.backup_secret_volume)]}
        }),
    )
    .await?;
    for component in &manifest.components {
        let path = directory.join(&component.path);
        let metadata = std::fs::metadata(&path).map_err(DriverError::internal)?;
        let digest = digest_file(&path).map_err(DriverError::internal)?;
        if i64::try_from(metadata.len()).unwrap_or(i64::MAX) != component.size_bytes
            || digest != component.sha256
        {
            return Err(DriverError::bad(
                "remote recovery component integrity check failed",
            ));
        }
    }

    validate_remote_database_dumps(state, workshop, relative, expected_scope, image, s3).await?;

    if preflight_only {
        return Ok(());
    }

    replace_database(state, target_database).await?;
    let compact = tenant_key(workshop);
    let paperless_database = format!("pl_{compact}");
    if expected_scope.iter().any(|item| item == "paperless") {
        replace_database_owned(state, &paperless_database, &paperless_database).await?;
    }
    let mut binds = vec![
        format!("{}:/backups:ro", state.config.backup_volume),
        format!("{}:/odoo", state.config.odoo_volume),
        format!(
            "{}:/run/makersbrain-backup-secrets:ro",
            state.config.backup_secret_volume
        ),
    ];
    if expected_scope.iter().any(|item| item == "paperless") {
        for suffix in ["data", "media", "consume"] {
            binds.push(format!(
                "mb-paperless-{workshop}-{suffix}:/paperless/{suffix}"
            ));
        }
    }
    let mut restore = format!(
        "set -eu; set -o pipefail; root=/backups/{}; age -d -i \"$AGE_IDENTITY\" \"$root/odoo/database.dump.enc\" | zstd -q -d | pg_restore --exit-on-error --no-owner --no-acl --host=\"$PGHOST\" --port=\"$PGPORT\" --username=\"$PGUSER\" --dbname=\"$ODOO_DATABASE\"; target=\"/odoo/filestore/$ODOO_DATABASE\"; mkdir -p \"$target\"; find \"$target\" -mindepth 1 -maxdepth 1 -exec rm -rf -- {{}} +; age -d -i \"$AGE_IDENTITY\" \"$root/odoo/filestore.tar.zst.enc\" | zstd -q -d | tar -xf - -C \"$target\"; chown -R \"$ODOO_UID:$ODOO_GID\" \"$target\"",
        relative.to_string_lossy()
    );
    if expected_scope.iter().any(|item| item == "paperless") {
        restore.push_str("; age -d -i \"$AGE_IDENTITY\" \"$root/paperless/database.dump.enc\" | zstd -q -d | pg_restore --exit-on-error --no-owner --no-acl --host=\"$PGHOST\" --port=\"$PGPORT\" --username=\"$PGUSER\" --dbname=\"$PAPERLESS_DATABASE\"; for part in data media consume; do find /paperless/$part -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +; age -d -i \"$AGE_IDENTITY\" \"$root/paperless/$part.tar.zst.enc\" | zstd -q -d | tar -xf - -C /paperless/$part; done");
    }
    run_docker_job(
        state,
        &format!(
            "mb-restore-{}",
            &manifest.recovery_id.simple().to_string()[..12]
        ),
        json!({
            "Image": image,
            "User": "0:0",
            "Cmd": ["sh", "-ec", restore],
            "Env": [
                format!("PGHOST={}", state.config.postgres_host),
                format!("PGPORT={}", state.config.postgres_port),
                format!("PGUSER={}", state.config.postgres_admin_user),
                format!("PGPASSWORD={}", state.config.postgres_admin_password),
                format!("ODOO_DATABASE={target_database}"),
                format!("PAPERLESS_DATABASE={paperless_database}"),
                format!("AGE_IDENTITY={}", s3.age_identity_file),
                format!("ODOO_UID={}", state.config.odoo_uid),
                format!("ODOO_GID={}", state.config.odoo_gid),
            ],
            "Labels": {"makersbrain.kind":"encrypted-restore-job"},
            "HostConfig": {"NetworkMode": state.config.docker_network, "Binds": binds}
        }),
    )
    .await?;
    validate_restored_databases(state, workshop, target_database, expected_scope).await
}

async fn validate_remote_database_dumps(
    state: &DriverState,
    workshop: Uuid,
    relative: &Path,
    expected_scope: &[String],
    image: &str,
    s3: &S3BackupConfig,
) -> Result<(), DriverError> {
    let odoo_temporary = format!("mb_{}", Uuid::new_v4().simple());
    replace_database_owned(state, &odoo_temporary, "odoo").await?;
    let includes_paperless = expected_scope.iter().any(|item| item == "paperless");
    let paperless_owner = format!("pl_{}", tenant_key(workshop));
    let paperless_temporary = format!("mb_{}", Uuid::new_v4().simple());
    if includes_paperless
        && let Err(error) =
            replace_database_owned(state, &paperless_temporary, &paperless_owner).await
    {
        let _ = drop_database(state, &odoo_temporary).await;
        return Err(error);
    }
    let mut command = format!(
        "set -eu; set -o pipefail; root=/backups/{}; age -d -i \"$AGE_IDENTITY\" \"$root/odoo/database.dump.enc\" | zstd -q -d | pg_restore --exit-on-error --no-owner --no-acl --host=\"$PGHOST\" --port=\"$PGPORT\" --username=\"$PGUSER\" --dbname=\"$ODOO_TEMPORARY\"",
        relative.to_string_lossy()
    );
    if includes_paperless {
        command.push_str("; age -d -i \"$AGE_IDENTITY\" \"$root/paperless/database.dump.enc\" | zstd -q -d | pg_restore --exit-on-error --no-owner --no-acl --host=\"$PGHOST\" --port=\"$PGPORT\" --username=\"$PGUSER\" --dbname=\"$PAPERLESS_TEMPORARY\"");
    }
    let validation = run_docker_job(
        state,
        &format!("mb-preflight-{}", &Uuid::new_v4().simple().to_string()[..12]),
        json!({
            "Image": image,
            "User": "0:0",
            "Cmd": ["sh", "-ec", command],
            "Env": [
                format!("PGHOST={}", state.config.postgres_host),
                format!("PGPORT={}", state.config.postgres_port),
                format!("PGUSER={}", state.config.postgres_admin_user),
                format!("PGPASSWORD={}", state.config.postgres_admin_password),
                format!("AGE_IDENTITY={}", s3.age_identity_file),
                format!("ODOO_TEMPORARY={odoo_temporary}"),
                format!("PAPERLESS_TEMPORARY={paperless_temporary}"),
            ],
            "Labels": {"makersbrain.kind":"restore-preflight-job"},
            "HostConfig": {"NetworkMode": state.config.docker_network, "Binds": [format!("{}:/backups:ro", state.config.backup_volume), format!("{}:/run/makersbrain-backup-secrets:ro", state.config.backup_secret_volume)]}
        }),
    )
    .await;
    let validation = match validation {
        Ok(()) => {
            validate_recovery_database_content(
                state,
                &odoo_temporary,
                includes_paperless.then_some(paperless_temporary.as_str()),
            )
            .await
        }
        Err(error) => Err(error),
    };
    let odoo_cleanup = drop_database(state, &odoo_temporary).await;
    let paperless_cleanup = if includes_paperless {
        drop_database(state, &paperless_temporary).await
    } else {
        Ok(())
    };
    match (validation, odoo_cleanup, paperless_cleanup) {
        (Ok(()), Ok(()), Ok(())) => Ok(()),
        (Err(error), _, _) => Err(error),
        (_, Err(error), _) | (_, _, Err(error)) => Err(error),
    }
}

fn safe_s3_storage_ref(
    storage_ref: &str,
    expected_bucket: &str,
    workshop: Uuid,
) -> Result<(String, Uuid), DriverError> {
    let prefix = storage_ref
        .strip_prefix(&format!("s3://{expected_bucket}/"))
        .ok_or_else(|| DriverError::bad("S3 recovery bucket is invalid"))?;
    let parts = prefix.split('/').collect::<Vec<_>>();
    if parts.len() != 4
        || parts[0] != "workshops"
        || parts[1] != workshop.to_string()
        || parts[2] != "recovery"
    {
        return Err(DriverError::bad("S3 recovery prefix is invalid"));
    }
    let recovery = parts[3]
        .parse()
        .map_err(|_| DriverError::bad("S3 recovery ID is invalid"))?;
    Ok((prefix.to_owned(), recovery))
}

fn validate_paperless_version(
    state: &DriverState,
    manifest: &RecoveryManifest,
) -> Result<(), DriverError> {
    if manifest
        .component_scope
        .iter()
        .any(|item| item == "paperless")
        && manifest.paperless_version.as_deref() != state.config.paperless_image.as_deref()
    {
        return Err(DriverError::bad(
            "Paperless recovery version does not match the configured image",
        ));
    }
    Ok(())
}

fn recovery_response(
    directory: &Path,
    relative: &Path,
    size_bytes: i64,
    manifest: &RecoveryManifest,
    manifest_digest: String,
) -> Result<Value, DriverError> {
    let mut components = manifest.components.clone();
    components.push(recovery_component("manifest", "manifest.json", directory)?);
    components.push(recovery_component(
        "commit-marker",
        "complete.json",
        directory,
    )?);
    Ok(json!({
        "storage_ref": relative.to_string_lossy(),
        "storage_location": "local",
        "size_bytes": size_bytes,
        "manifest_digest": manifest_digest,
        "format_version": manifest.format,
        "source_release": manifest.source_release,
        "paperless_version": manifest.paperless_version,
        "components": components,
    }))
}

fn read_v2_manifest(directory: &Path) -> Result<RecoveryManifest, DriverError> {
    let bytes = std::fs::read(directory.join("manifest.json")).map_err(DriverError::internal)?;
    serde_json::from_slice(&bytes).map_err(|_| DriverError::bad("recovery manifest is invalid"))
}

fn verify_recovery_directory(
    directory: &Path,
    workshop: Uuid,
    expected_scope: &[String],
) -> Result<RecoveryManifest, DriverError> {
    let manifest = read_v2_manifest(directory)?;
    if manifest.format != RECOVERY_FORMAT_V2
        || manifest.workshop_id != workshop
        || normalized_scope(&manifest.component_scope) != normalized_scope(expected_scope)
    {
        return Err(DriverError::bad("recovery manifest scope is incompatible"));
    }
    let commit: Value = serde_json::from_slice(
        &std::fs::read(directory.join("complete.json")).map_err(DriverError::internal)?,
    )
    .map_err(|_| DriverError::bad("recovery commit marker is invalid"))?;
    let expected_manifest_digest = commit
        .get("manifest_sha256")
        .and_then(Value::as_str)
        .ok_or_else(|| DriverError::bad("recovery commit marker is incomplete"))?;
    let actual_manifest_digest =
        digest_file(&directory.join("manifest.json")).map_err(DriverError::internal)?;
    if expected_manifest_digest != actual_manifest_digest {
        return Err(DriverError::bad("recovery manifest integrity check failed"));
    }
    let mut names = std::collections::BTreeSet::new();
    for component in &manifest.components {
        if !names.insert(component.name.as_str())
            || !safe_component_path(&component.path)
            || component.size_bytes < 0
            || !valid_sha256(&component.sha256)
            || component
                .plaintext_sha256
                .as_deref()
                .is_some_and(|digest| !valid_sha256(digest))
        {
            return Err(DriverError::bad("recovery component list is invalid"));
        }
        let path = directory.join(&component.path);
        let (size_bytes, digest) = digest_path(&path).map_err(DriverError::internal)?;
        if size_bytes != component.size_bytes || digest != component.sha256 {
            return Err(DriverError::bad(
                "recovery component integrity check failed",
            ));
        }
    }
    let required = if expected_scope.iter().any(|item| item == "paperless") {
        vec![
            "odoo-database",
            "odoo-filestore",
            "paperless-database",
            "paperless-data",
            "paperless-media",
            "paperless-consume",
        ]
    } else {
        vec!["odoo-database", "odoo-filestore"]
    };
    if required.iter().any(|name| !names.contains(name)) || names.len() != required.len() {
        return Err(DriverError::bad("recovery component scope is incomplete"));
    }
    Ok(manifest)
}

fn normalized_scope(scope: &[String]) -> std::collections::BTreeSet<&str> {
    scope.iter().map(String::as_str).collect()
}

fn safe_component_path(path: &str) -> bool {
    let path = Path::new(path);
    !path.is_absolute()
        && !path.as_os_str().is_empty()
        && path.as_os_str().as_encoded_bytes().iter().all(|value| {
            value.is_ascii_alphanumeric() || matches!(value, b'/' | b'.' | b'_' | b'-')
        })
        && path.components().all(|component| {
            matches!(
                component,
                std::path::Component::Normal(_) | std::path::Component::CurDir
            )
        })
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn recovery_component(
    name: &str,
    relative: &str,
    directory: &Path,
) -> Result<RecoveryComponent, DriverError> {
    let (size_bytes, sha256) =
        digest_path(&directory.join(relative)).map_err(DriverError::internal)?;
    Ok(RecoveryComponent {
        name: name.to_owned(),
        path: relative.to_owned(),
        size_bytes,
        plaintext_sha256: Some(sha256.clone()),
        sha256,
    })
}

fn encrypted_recovery_component(
    name: &str,
    relative: &str,
    plaintext_checksum_relative: &str,
    directory: &Path,
) -> Result<RecoveryComponent, DriverError> {
    let checksum_path = directory.join(plaintext_checksum_relative);
    let plaintext_sha256 = std::fs::read_to_string(&checksum_path)
        .map_err(DriverError::internal)?
        .trim()
        .to_owned();
    if !valid_sha256(&plaintext_sha256) {
        return Err(DriverError::bad("invalid plaintext recovery checksum"));
    }
    std::fs::remove_file(checksum_path).map_err(DriverError::internal)?;
    let encrypted_path = directory.join(relative);
    let metadata = std::fs::metadata(&encrypted_path).map_err(DriverError::internal)?;
    if !metadata.is_file() {
        return Err(DriverError::bad(
            "encrypted recovery component is not a regular file",
        ));
    }
    let size_bytes = i64::try_from(metadata.len()).unwrap_or(i64::MAX);
    let sha256 = digest_file(&encrypted_path).map_err(DriverError::internal)?;
    Ok(RecoveryComponent {
        name: name.to_owned(),
        path: relative.to_owned(),
        size_bytes,
        sha256,
        plaintext_sha256: Some(plaintext_sha256),
    })
}

fn digest_file(path: &Path) -> std::io::Result<String> {
    use std::io::Read;

    let mut file = std::fs::File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn digest_path(path: &Path) -> std::io::Result<(i64, String)> {
    fn walk(
        root: &Path,
        current: &Path,
        digest: &mut Sha256,
        size: &mut i64,
    ) -> std::io::Result<()> {
        let metadata = std::fs::symlink_metadata(current)?;
        if metadata.file_type().is_symlink() {
            return Err(std::io::Error::other(
                "recovery components do not support symbolic links",
            ));
        }
        let relative = current.strip_prefix(root).unwrap_or(current);
        digest.update(relative.to_string_lossy().as_bytes());
        if metadata.is_file() {
            digest.update(b"file\0");
            *size = size.saturating_add(i64::try_from(metadata.len()).unwrap_or(i64::MAX));
            use std::io::Read;
            let mut file = std::fs::File::open(current)?;
            let mut buffer = [0_u8; 64 * 1024];
            loop {
                let count = file.read(&mut buffer)?;
                if count == 0 {
                    break;
                }
                digest.update(&buffer[..count]);
            }
        } else if metadata.is_dir() {
            digest.update(b"directory\0");
            let mut entries = std::fs::read_dir(current)?.collect::<Result<Vec<_>, _>>()?;
            entries.sort_by_key(std::fs::DirEntry::file_name);
            for entry in entries {
                walk(root, &entry.path(), digest, size)?;
            }
        } else {
            return Err(std::io::Error::other("unsupported recovery component type"));
        }
        Ok(())
    }

    let mut digest = Sha256::new();
    let mut size = 0_i64;
    let root = path.parent().unwrap_or(path);
    walk(root, path, &mut digest, &mut size)?;
    Ok((size, format!("{:x}", digest.finalize())))
}

async fn backup_paperless(
    state: &DriverState,
    workshop: Uuid,
    recovery: Uuid,
    relative: &Path,
    directory: &Path,
    components: &mut Vec<RecoveryComponent>,
) -> Result<(), DriverError> {
    let compact = tenant_key(workshop);
    let paperless_database = format!("pl_{compact}");
    let paperless_directory = directory.join("paperless");
    secure_directory(&paperless_directory).map_err(DriverError::internal)?;
    let dump_relative = relative.join("paperless/database.dump");
    run_postgres_job_as(
        state,
        &format!("mb-pl-dump-{}", &recovery.simple().to_string()[..12]),
        &state.config.postgres_admin_user,
        &state.config.postgres_admin_password,
        vec![
            "pg_dump".into(),
            "--format=custom".into(),
            "--no-owner".into(),
            "--no-acl".into(),
            format!("--host={}", state.config.postgres_host),
            format!("--port={}", state.config.postgres_port),
            format!("--username={}", state.config.postgres_admin_user),
            format!("--file=/backups/{}", dump_relative.to_string_lossy()),
            paperless_database,
        ],
    )
    .await?;
    run_paperless_volume_job(
        state,
        workshop,
        &format!("mb-pl-files-{}", &recovery.simple().to_string()[..12]),
        relative,
        false,
    )
    .await?;
    for (name, path) in [
        ("paperless-database", "paperless/database.dump"),
        ("paperless-data", "paperless/data"),
        ("paperless-media", "paperless/media"),
        ("paperless-consume", "paperless/consume"),
    ] {
        components.push(recovery_component(name, path, directory)?);
    }
    Ok(())
}

async fn restore_paperless(
    state: &DriverState,
    workshop: Uuid,
    relative: &Path,
    _resolved: &Path,
) -> Result<(), DriverError> {
    let compact = tenant_key(workshop);
    let database = format!("pl_{compact}");
    replace_database_owned(state, &database, &database).await?;
    run_postgres_job_as(
        state,
        &format!(
            "mb-pl-restore-{}",
            &Uuid::new_v4().simple().to_string()[..12]
        ),
        &state.config.postgres_admin_user,
        &state.config.postgres_admin_password,
        vec![
            "pg_restore".into(),
            "--exit-on-error".into(),
            "--no-owner".into(),
            "--no-acl".into(),
            format!("--host={}", state.config.postgres_host),
            format!("--port={}", state.config.postgres_port),
            format!("--username={}", state.config.postgres_admin_user),
            format!("--dbname={database}"),
            format!(
                "/backups/{}/paperless/database.dump",
                relative.to_string_lossy()
            ),
        ],
    )
    .await?;
    run_paperless_volume_job(
        state,
        workshop,
        &format!("mb-pl-files-{}", &Uuid::new_v4().simple().to_string()[..12]),
        relative,
        true,
    )
    .await
}

async fn run_paperless_volume_job(
    state: &DriverState,
    workshop: Uuid,
    container: &str,
    relative: &Path,
    restore: bool,
) -> Result<(), DriverError> {
    let mut binds = vec![format!("{}:/backups", state.config.backup_volume)];
    for suffix in ["data", "media", "consume"] {
        binds.push(format!(
            "mb-paperless-{workshop}-{suffix}:/paperless/{suffix}{}",
            if restore { "" } else { ":ro" }
        ));
    }
    let relative = relative.to_string_lossy();
    let command = if restore {
        format!(
            "set -eu; for part in data media consume; do find /paperless/$part -mindepth 1 -maxdepth 1 -exec rm -rf -- {{}} +; cp -a /backups/{relative}/paperless/$part/. /paperless/$part/; done"
        )
    } else {
        format!(
            "set -eu; for part in data media consume; do mkdir -p /backups/{relative}/paperless/$part; cp -a /paperless/$part/. /backups/{relative}/paperless/$part/; done"
        )
    };
    run_docker_job(
        state,
        container,
        json!({
            "Image": state.config.postgres_image,
            "Cmd": ["sh", "-ec", command],
            "Labels": {"makersbrain.kind":"paperless-recovery-job"},
            "HostConfig": {"NetworkMode": state.config.docker_network, "Binds": binds}
        }),
    )
    .await
}

async fn restore_legacy_recovery_set(
    state: &DriverState,
    target_database: &str,
    relative: &Path,
    resolved: &Path,
) -> Result<(), DriverError> {
    if !resolved.join("database.dump").is_file() {
        return Err(DriverError::bad("legacy recovery set is incomplete"));
    }
    validate_local_dump(state, &relative.join("database.dump"), "odoo").await?;
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
            format!("--username={}", state.config.postgres_admin_user),
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
    .map_err(DriverError::internal)?;
    validate_database_table(state, target_database, "ir_module_module").await
}

async fn validate_local_dump(
    state: &DriverState,
    dump_relative: &Path,
    owner: &str,
) -> Result<(), DriverError> {
    let temporary = format!("mb_{}", Uuid::new_v4().simple());
    replace_database_owned(state, &temporary, owner).await?;
    let validation = run_postgres_job(
        state,
        &format!(
            "mb-pg-validate-{}",
            &Uuid::new_v4().simple().to_string()[..12]
        ),
        vec![
            "pg_restore".into(),
            "--exit-on-error".into(),
            "--no-owner".into(),
            "--no-acl".into(),
            format!("--host={}", state.config.postgres_host),
            format!("--port={}", state.config.postgres_port),
            format!("--username={}", state.config.postgres_admin_user),
            format!("--dbname={temporary}"),
            format!("/backups/{}", dump_relative.to_string_lossy()),
        ],
    )
    .await;
    let cleanup = drop_database(state, &temporary).await;
    match (validation, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), _) => Err(error),
        (_, Err(error)) => Err(error),
    }
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
    if value.is_empty()
        || value.len() > 253
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
    replace_database_owned(state, database, "odoo").await
}

async fn replace_database_owned(
    state: &DriverState,
    database: &str,
    owner: &str,
) -> Result<(), DriverError> {
    if !safe_pg_identifier(database) || !safe_pg_identifier(owner) {
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
        "create database \"{database}\" owner \"{owner}\""
    )))
    .execute(&state.postgres)
    .await
    .map_err(DriverError::internal)?;
    Ok(())
}

async fn drop_database(state: &DriverState, database: &str) -> Result<(), DriverError> {
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
    sqlx::query(AssertSqlSafe(format!(
        "drop database if exists \"{database}\""
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
    run_postgres_job_as(
        state,
        container,
        &state.config.postgres_admin_user,
        &state.config.postgres_admin_password,
        command,
    )
    .await
}

async fn run_postgres_job_as(
    state: &DriverState,
    container: &str,
    _username: &str,
    password: &str,
    command: Vec<String>,
) -> Result<(), DriverError> {
    run_docker_job(
        state,
        container,
        json!({
            "Image":state.config.postgres_image,
            "Cmd":command,
            "Env":[format!("PGPASSWORD={password}")],
            "Labels":{"makersbrain.kind":"postgres-lifecycle-job"},
            "HostConfig":{
                "NetworkMode":state.config.docker_network,
                "Binds":[format!("{}:/backups",state.config.backup_volume)]
            }
        }),
    )
    .await
}

async fn run_docker_job(
    state: &DriverState,
    container: &str,
    body: Value,
) -> Result<(), DriverError> {
    if docker_container_exists(state, container).await? {
        docker_delete_container(state, container).await?;
    }
    docker_create_container(state, container, body).await?;
    if let Err(error) = docker_start_container(state, container).await {
        let _ = docker_delete_container(state, container).await;
        return Err(error);
    }
    let wait = docker_wait_container(state, container).await;
    let cleanup = docker_delete_container(state, container).await;
    match (wait, cleanup) {
        (Ok(0), Ok(())) => Ok(()),
        (Ok(code), Ok(())) => Err(DriverError::internal(format!(
            "recovery helper job exited with {code}"
        ))),
        (Err(error), Ok(())) => Err(error),
        (_, Err(error)) => Err(error),
    }
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
    paperless_hostname: Option<&str>,
) -> Result<(String, Option<(String, String)>), DriverError> {
    let odoo_id = format!("makersbrain-odoo-{tenant_key}");
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
    let paperless_id = format!("makersbrain-paperless-{tenant_key}");
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
            "Cmd":["odoo",format!("--database={database_ref}"),"--stop-after-init","--no-database-list",format!("--db_host={}",state.config.postgres_host),format!("--db_port={}",state.config.postgres_port),"--db_user=odoo",format!("--db_password={}",state.config.odoo_postgres_password),"--addons-path=/mnt/makersbrain-addons,/mnt/oca-addons,/usr/lib/python3/dist-packages/odoo/addons","--init=auth_oidc,mb_control_bridge,l10n_fr_micro_enterprise","--without-demo=all"],
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
    let paperless_image = state
        .config
        .paperless_image
        .as_deref()
        .ok_or_else(|| DriverError::bad("Paperless is not configured for this deployment"))?;
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
            serde_json::to_vec(&(paperless_image, &environment)).map_err(DriverError::internal)?
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
            "Image":paperless_image,
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
    paperless: Option<(&str, &str)>,
) -> Result<(), DriverError> {
    let mut config = format!(
        "server {{\n  listen 8080;\n  server_name {odoo_hostname};\n  location / {{\n    proxy_http_version 1.1;\n    proxy_set_header Host $host;\n    proxy_set_header X-Forwarded-Host $host;\n    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n    proxy_set_header X-Forwarded-Proto $forwarded_proto;\n    proxy_set_header Upgrade $http_upgrade;\n    proxy_set_header Connection $connection_upgrade;\n    proxy_set_header X-Odoo-Dbfilter '^{}\\Z';\n    proxy_pass http://odoo:8069;\n  }}\n}}\n",
        database_ref
    );
    if let Some((paperless_hostname, paperless_container)) = paperless {
        config.push_str(&format!(
            "server {{\n  listen 8080;\n  server_name {paperless_hostname};\n  location / {{\n    proxy_http_version 1.1;\n    proxy_set_header Host $host;\n    proxy_set_header X-Forwarded-Host $host;\n    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n    proxy_set_header X-Forwarded-Proto $forwarded_proto;\n    proxy_set_header Upgrade $http_upgrade;\n    proxy_set_header Connection $connection_upgrade;\n    proxy_pass http://{paperless_container}:8000;\n  }}\n}}\n"
        ));
    }
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

    #[test]
    fn recovery_manifest_rejects_corrupt_components_and_scope_mismatches() {
        let root = std::env::temp_dir().join(format!("mb-recovery-{}", Uuid::new_v4()));
        std::fs::create_dir_all(root.join("odoo/filestore")).unwrap();
        std::fs::write(root.join("odoo/database.dump"), "database").unwrap();
        std::fs::write(root.join("odoo/filestore/asset"), "attachment").unwrap();
        let workshop = Uuid::new_v4();
        let recovery = Uuid::new_v4();
        let manifest = RecoveryManifest {
            format: RECOVERY_FORMAT_V2.into(),
            recovery_id: recovery,
            workshop_id: workshop,
            database_ref: "mb_00000000000000000000000000000001".into(),
            kind: "snapshot".into(),
            source_release: env!("CARGO_PKG_VERSION").into(),
            odoo_version: "odoo:19".into(),
            paperless_version: None,
            paperless_database_ref: None,
            created_at_unix: time::OffsetDateTime::now_utc().unix_timestamp(),
            expires_at_unix: None,
            encryption: None,
            encryption_key_id: None,
            component_scope: vec!["odoo".into()],
            components: vec![
                recovery_component("odoo-database", "odoo/database.dump", &root).unwrap(),
                recovery_component("odoo-filestore", "odoo/filestore", &root).unwrap(),
            ],
        };
        std::fs::write(
            root.join("manifest.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        let manifest_digest = digest_file(&root.join("manifest.json")).unwrap();
        std::fs::write(
            root.join("complete.json"),
            serde_json::to_vec(&json!({"manifest_sha256":manifest_digest})).unwrap(),
        )
        .unwrap();

        assert!(verify_recovery_directory(&root, workshop, &["odoo".into()]).is_ok());
        assert!(
            verify_recovery_directory(&root, workshop, &["odoo".into(), "paperless".into()])
                .is_err()
        );
        std::fs::write(root.join("odoo/filestore/asset"), "tampered").unwrap();
        assert!(verify_recovery_directory(&root, workshop, &["odoo".into()]).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn encrypted_components_record_raw_ciphertext_sha256() {
        let root = std::env::temp_dir().join(format!("mb-encrypted-component-{}", Uuid::new_v4()));
        std::fs::create_dir_all(root.join("odoo")).unwrap();
        std::fs::write(root.join("odoo/database.dump.enc"), b"ciphertext").unwrap();
        std::fs::write(
            root.join("odoo/database.dump.plain.sha256"),
            "0000000000000000000000000000000000000000000000000000000000000000\n",
        )
        .unwrap();
        let component = encrypted_recovery_component(
            "odoo-database",
            "odoo/database.dump.enc",
            "odoo/database.dump.plain.sha256",
            &root,
        )
        .unwrap();
        assert_eq!(component.size_bytes, 10);
        assert_eq!(
            component.sha256,
            format!("{:x}", Sha256::digest(b"ciphertext"))
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn s3_recovery_references_are_bucket_and_workshop_scoped() {
        let workshop = Uuid::new_v4();
        let recovery = Uuid::new_v4();
        let valid =
            format!("s3://makersbrain-production-backups/workshops/{workshop}/recovery/{recovery}");
        assert_eq!(
            safe_s3_storage_ref(&valid, "makersbrain-production-backups", workshop)
                .unwrap()
                .1,
            recovery
        );
        assert!(safe_s3_storage_ref(&valid, "makersbrain-staging-backups", workshop).is_err());
        assert!(
            safe_s3_storage_ref(&valid, "makersbrain-production-backups", Uuid::new_v4()).is_err()
        );
        assert!(
            safe_s3_storage_ref(
                &format!("{valid}/../../other"),
                "makersbrain-production-backups",
                workshop
            )
            .is_err()
        );
    }

    #[test]
    fn component_paths_cannot_escape_the_recovery_root() {
        assert!(safe_component_path("paperless/media.tar.zst.enc"));
        assert!(!safe_component_path("../secrets"));
        assert!(!safe_component_path("/etc/passwd"));
        assert!(!safe_component_path("odoo/file name.enc"));
        assert!(!safe_component_path("odoo/file;touch-pwned.enc"));
    }
}
