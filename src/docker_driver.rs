use std::net::SocketAddr;
use std::path::{Component, Path, PathBuf};
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

use crate::domain::IntegrationError;
use crate::integrations::odoo::{ErasureReplayCommand, OdooClient, TenantBootstrapCommand};
use crate::integrations::paperless::PaperlessClient;

mod docker_client;
mod gateway;
mod postgres;
mod privacy;
mod recovery;
mod release;
mod services;

use docker_client::*;
use gateway::*;
use postgres::*;
use recovery::*;
use services::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ContainerRuntimeKind {
    Docker,
    Podman,
}

impl ContainerRuntimeKind {
    fn parse(value: &str) -> anyhow::Result<Self> {
        match value {
            "docker" => Ok(Self::Docker),
            "podman" => Ok(Self::Podman),
            _ => anyhow::bail!("DRIVER_CONTAINER_RUNTIME must be docker or podman"),
        }
    }

    fn api_version(self) -> &'static str {
        match self {
            Self::Docker => "v1.47",
            // Podman's compatibility API currently targets Docker API v1.40.
            Self::Podman => "v1.40",
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Docker => "Docker",
            Self::Podman => "Podman",
        }
    }
}

#[derive(Clone)]
struct ContainerRuntime {
    kind: ContainerRuntimeKind,
    client: reqwest::Client,
}

impl ContainerRuntime {
    fn endpoint(&self, path: &str) -> String {
        format!("http://localhost/{}{path}", self.kind.api_version())
    }
}

#[derive(Clone)]
pub struct DockerDriverConfig {
    pub listen: SocketAddr,
    token: String,
    privacy_token: String,
    container_runtime: ContainerRuntimeKind,
    runtime_socket: PathBuf,
    database_url: String,
    postgres_admin_url: String,
    postgres_admin_user: String,
    postgres_admin_password: String,
    postgres_host: String,
    postgres_port: u16,
    postgres_ca_source: Option<PathBuf>,
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
    odoo_client_secret_root: PathBuf,
    paperless_client_secret_root: PathBuf,
    runtime_secret_source: String,
    recovery_secret_source: String,
    job_secret_root: PathBuf,
    route_root: PathBuf,
    gateway_container: String,
    odoo_base_url: String,
    control_internal_url: String,
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
        let environment = required("DRIVER_ENVIRONMENT")?;
        let container_runtime =
            ContainerRuntimeKind::parse(&required("DRIVER_CONTAINER_RUNTIME")?)?;
        if container_runtime == ContainerRuntimeKind::Docker && environment != "development" {
            anyhow::bail!(
                "the Docker socket driver is development-only; staging and production must use the infrastructure driver"
            );
        }
        if !matches!(
            environment.as_str(),
            "development" | "staging" | "production"
        ) {
            anyhow::bail!("DRIVER_ENVIRONMENT must be development, staging, or production");
        }
        let runtime_socket = PathBuf::from(required("DRIVER_RUNTIME_SOCKET")?);
        if !runtime_socket.is_absolute() {
            anyhow::bail!("DRIVER_RUNTIME_SOCKET must be an absolute Unix-socket path");
        }
        let public_scheme = required("DRIVER_PUBLIC_SCHEME")?;
        if !matches!(public_scheme.as_str(), "http" | "https") {
            anyhow::bail!("DRIVER_PUBLIC_SCHEME must be http or https");
        }
        let public_port = std::env::var("DRIVER_PUBLIC_PORT")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .map(|value| value.parse())
            .transpose()?;
        let postgres_admin_url = required_secret("DRIVER_POSTGRES_ADMIN_URL")?;
        let parsed_admin_url = Url::parse(&postgres_admin_url)?;
        let postgres_admin_user = parsed_admin_url.username().to_owned();
        let postgres_admin_password = parsed_admin_url
            .password()
            .ok_or_else(|| anyhow::anyhow!("DRIVER_POSTGRES_ADMIN_URL must contain a password"))?
            .to_owned();
        if postgres_admin_user.is_empty() {
            anyhow::bail!("DRIVER_POSTGRES_ADMIN_URL must contain a username");
        }
        let backup_agent_image = optional("DRIVER_BACKUP_AGENT_IMAGE")?;
        let s3_values = [
            optional("BACKUP_S3_BUCKET")?,
            optional("BACKUP_S3_ENDPOINT")?,
            optional("BACKUP_S3_REGION")?,
            optional_secret("BACKUP_S3_ACCESS_KEY_ID")?,
            optional_secret("BACKUP_S3_SECRET_ACCESS_KEY")?,
            optional_secret("RESTORE_S3_ACCESS_KEY_ID")?,
            optional_secret("RESTORE_S3_SECRET_ACCESS_KEY")?,
            optional_secret("BACKUP_AGE_RECIPIENT")?,
            optional("BACKUP_AGE_IDENTITY_FILE")?,
            optional("BACKUP_ENCRYPTION_KEY_ID")?,
            optional("BACKUP_RETENTION_DAYS")?,
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
            if !age_identity_file.starts_with("/run/makersbrain-recovery-secrets/") {
                anyhow::bail!(
                    "BACKUP_AGE_IDENTITY_FILE must use the isolated recovery-secret mount"
                );
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
        let token = required_secret("DRIVER_TOKEN")?;
        let privacy_token = required_secret("DRIVER_PRIVACY_TOKEN")?;
        if token == privacy_token {
            anyhow::bail!("DRIVER_TOKEN and DRIVER_PRIVACY_TOKEN must be distinct");
        }
        let runtime_secret_source = required("DRIVER_RUNTIME_SECRET_SOURCE")?;
        let recovery_secret_source = required("DRIVER_RECOVERY_SECRET_SOURCE")?;
        if container_runtime == ContainerRuntimeKind::Podman
            && !Path::new(&runtime_secret_source).is_absolute()
        {
            anyhow::bail!("DRIVER_RUNTIME_SECRET_SOURCE must be an absolute host path for Podman");
        }
        if container_runtime == ContainerRuntimeKind::Podman
            && !Path::new(&recovery_secret_source).is_absolute()
        {
            anyhow::bail!("DRIVER_RECOVERY_SECRET_SOURCE must be an absolute host path for Podman");
        }
        if recovery_secret_source == runtime_secret_source {
            anyhow::bail!("runtime and recovery secret sources must be distinct");
        }
        let postgres_ca_source = optional("DRIVER_POSTGRES_CA_SOURCE")?.map(PathBuf::from);
        if environment != "development" {
            let expected = Path::new(&runtime_secret_source).join("postgres-ca.crt");
            if postgres_ca_source.as_deref() != Some(expected.as_path()) {
                anyhow::bail!(
                    "DRIVER_POSTGRES_CA_SOURCE must be the scoped runtime PostgreSQL CA outside development"
                );
            }
        }
        Ok(Self {
            listen: required("DRIVER_LISTEN")?.parse()?,
            token,
            privacy_token,
            container_runtime,
            runtime_socket,
            database_url: required_secret("DRIVER_DATABASE_URL")?,
            postgres_admin_url,
            postgres_admin_user,
            postgres_admin_password,
            postgres_host: required("DRIVER_POSTGRES_HOST")?,
            postgres_port: required("DRIVER_POSTGRES_PORT")?.parse()?,
            postgres_ca_source,
            odoo_postgres_password: required_secret("DRIVER_ODOO_POSTGRES_PASSWORD")?,
            odoo_bridge_token: required_secret("DRIVER_ODOO_BRIDGE_TOKEN")?,
            odoo_image: required("DRIVER_ODOO_IMAGE")?,
            postgres_image: required("DRIVER_POSTGRES_IMAGE")?,
            paperless_image: std::env::var("DRIVER_PAPERLESS_IMAGE")
                .ok()
                .filter(|value| !value.trim().is_empty()),
            docker_network: required("DRIVER_RUNTIME_NETWORK")?,
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
            odoo_client_secret_root: required("DRIVER_ODOO_CLIENT_SECRET_ROOT")?.into(),
            paperless_client_secret_root: required("DRIVER_PAPERLESS_CLIENT_SECRET_ROOT")?.into(),
            runtime_secret_source,
            recovery_secret_source,
            job_secret_root: required("DRIVER_JOB_SECRET_ROOT")?.into(),
            route_root: required("DRIVER_ROUTE_ROOT")?.into(),
            gateway_container: required("DRIVER_GATEWAY_CONTAINER")?,
            odoo_base_url: absolute_http("DRIVER_ODOO_BASE_URL")?,
            control_internal_url: absolute_http("DRIVER_CONTROL_INTERNAL_URL")?,
            rauthy_admin_url: absolute_http("DRIVER_RAUTHY_ADMIN_URL")?,
            rauthy_admin_key: required_secret("DRIVER_RAUTHY_ADMIN_KEY")?,
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
    crate::runtime_secret::required_configuration(name).map_err(anyhow::Error::msg)
}

fn optional(name: &'static str) -> anyhow::Result<Option<String>> {
    crate::runtime_secret::configuration(name)
        .map(|value| value.filter(|value| !value.trim().is_empty()))
        .map_err(anyhow::Error::msg)
}

fn required_secret(name: &'static str) -> anyhow::Result<String> {
    crate::runtime_secret::required(name).map_err(anyhow::Error::msg)
}

fn optional_secret(name: &'static str) -> anyhow::Result<Option<String>> {
    crate::runtime_secret::environment(name)
        .map(|value| value.filter(|value| !value.trim().is_empty()))
        .map_err(anyhow::Error::msg)
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
    runtime: ContainerRuntime,
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
    if config.odoo_client_secret_root != Path::new("/run/makersbrain-odoo-client-secrets") {
        anyhow::bail!("DRIVER_ODOO_CLIENT_SECRET_ROOT must use the isolated Odoo client mount");
    }
    std::fs::create_dir_all(&config.odoo_client_secret_root)?;
    normalize_secret_permissions(&config.odoo_client_secret_root)?;
    std::os::unix::fs::chown(
        &config.odoo_client_secret_root,
        Some(config.odoo_uid),
        Some(config.odoo_gid),
    )?;
    if config.paperless_client_secret_root != Path::new("/run/makersbrain-paperless-client-secrets")
    {
        anyhow::bail!(
            "DRIVER_PAPERLESS_CLIENT_SECRET_ROOT must use the isolated Paperless client mount"
        );
    }
    std::fs::create_dir_all(&config.paperless_client_secret_root)?;
    normalize_secret_permissions(&config.paperless_client_secret_root)?;
    let expected_job_root = match config.container_runtime {
        ContainerRuntimeKind::Docker => PathBuf::from("/run/makersbrain-backup-secrets/jobs"),
        ContainerRuntimeKind::Podman => Path::new(&config.runtime_secret_source).join("jobs"),
    };
    if config.job_secret_root != expected_job_root {
        anyhow::bail!("DRIVER_JOB_SECRET_ROOT must use the scoped runtime job-secret directory");
    }
    secure_directory(&config.job_secret_root)?;
    clear_stale_job_secrets(&config.job_secret_root)?;
    secure_directory(
        &config
            .job_secret_root
            .parent()
            .expect("validated job-secret root has a parent")
            .join("runtime"),
    )?;
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
    let runtime_kind = config.container_runtime;
    let runtime_client = reqwest::Client::builder()
        .unix_socket(config.runtime_socket.clone())
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
        runtime: ContainerRuntime {
            kind: runtime_kind,
            client: runtime_client,
        },
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
        .route("/v1/privacy/{workshop}/export", post(privacy::export))
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
    fn integration(error: IntegrationError) -> Self {
        let (status, message) = match error {
            IntegrationError::TooLarge => (
                StatusCode::PAYLOAD_TOO_LARGE,
                "processor export exceeds the secure export limit",
            ),
            IntegrationError::NotFound => {
                (StatusCode::NOT_FOUND, "processor subject was not found")
            }
            IntegrationError::Rejected | IntegrationError::ContractDrift => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "processor export contract was rejected",
            ),
            IntegrationError::Unauthorized => {
                (StatusCode::UNAUTHORIZED, "processor authorization failed")
            }
            _ => (
                StatusCode::SERVICE_UNAVAILABLE,
                "processor export is unavailable",
            ),
        };
        if status.is_server_error() {
            tracing::error!(error=?error,"privacy processor export failed");
        }
        Self(status, message.into())
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
        "provision"
            | "reconcile"
            | "lifecycle"
            | "rehearse"
            | "download"
            | "release"
            | "resume"
            | "erasure"
            | "restrict"
            | "carrier-secret"
            | "carrier-secret-delete"
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
            .bind(idempotency_key)
            .bind((action != "release").then_some(workshop))
            .bind(&action).bind(&digest)
            .execute(&state.ledger).await.map_err(DriverError::internal)?;
    }
    let _guard = state.serial.lock().await;
    let result = match action.as_str() {
        "provision" | "reconcile" => provision(&state, workshop, &payload).await,
        "lifecycle" => lifecycle(&state, workshop, &payload).await,
        "rehearse" => rehearse(&state, workshop, &payload).await,
        "release" => release::release_fleet(&state, &payload).await,
        "resume" => resume_after_erasure_replay(&state, workshop, &payload).await,
        "erasure" => apply_restored_erasure(&state, workshop, &payload).await,
        "restrict" => restrict_capability(&state, workshop, &payload).await,
        "carrier-secret" => write_carrier_secret(&state, workshop, &payload),
        "carrier-secret-delete" => delete_carrier_secret(&state, workshop, &payload),
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

fn carrier_secret_path(
    state: &DriverState,
    workshop: Uuid,
    payload: &Value,
) -> Result<(Uuid, PathBuf), DriverError> {
    let id = payload
        .get("secret_id")
        .and_then(Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok())
        .ok_or_else(|| DriverError::bad("secret_id must be a UUID"))?;
    Ok((
        id,
        state
            .config
            .secret_root
            .join("docker")
            .join(workshop.to_string())
            .join("carrier")
            .join(id.to_string()),
    ))
}

fn write_carrier_secret(
    state: &DriverState,
    workshop: Uuid,
    payload: &Value,
) -> Result<Value, DriverError> {
    let object = payload
        .as_object()
        .filter(|value| {
            value.len() == 3
                && value.contains_key("secret_id")
                && value.contains_key("provider")
                && value.contains_key("credentials")
        })
        .ok_or_else(|| DriverError::bad("carrier secret payload is invalid"))?;
    let provider = object
        .get("provider")
        .and_then(Value::as_str)
        .ok_or_else(|| DriverError::bad("carrier provider is invalid"))?;
    let credentials = object
        .get("credentials")
        .and_then(Value::as_object)
        .ok_or_else(|| DriverError::bad("carrier credentials are invalid"))?;
    let valid_value = |key: &str, minimum: usize, maximum: usize| {
        credentials
            .get(key)
            .and_then(Value::as_str)
            .is_some_and(|secret| {
                (minimum..=maximum).contains(&secret.len())
                    && !secret
                        .chars()
                        .any(|character| matches!(character, '\r' | '\n' | '\0'))
            })
    };
    let valid = match provider {
        "boxtal" => {
            credentials.len() == 3
                && valid_value("access_key", 8, 256)
                && valid_value("secret_key", 24, 512)
                && valid_value("webhook_secret", 24, 512)
        }
        "sendcloud" => {
            matches!(credentials.len(), 2 | 3)
                && valid_value("public_key", 8, 256)
                && valid_value("private_key", 16, 512)
                && (credentials.len() == 2 || valid_value("webhook_signature_key", 16, 512))
        }
        _ => false,
    };
    if !valid {
        return Err(DriverError::bad("carrier credentials are invalid"));
    }
    let (id, path) = carrier_secret_path(state, workshop, payload)?;
    let parent = path
        .parent()
        .ok_or_else(|| DriverError::bad("carrier secret path is invalid"))?;
    secure_directory(parent).map_err(DriverError::internal)?;
    let serialized = serde_json::to_string(credentials).map_err(DriverError::internal)?;
    write_secret(&path, &serialized).map_err(DriverError::internal)?;
    Ok(json!({
        "secret_ref": format!("docker/{workshop}/carrier/{id}"),
        "stored": true
    }))
}

fn delete_carrier_secret(
    state: &DriverState,
    workshop: Uuid,
    payload: &Value,
) -> Result<Value, DriverError> {
    if payload
        .as_object()
        .is_none_or(|value| value.len() != 1 || !value.contains_key("secret_id"))
    {
        return Err(DriverError::bad(
            "carrier secret deletion payload is invalid",
        ));
    }
    let (id, path) = carrier_secret_path(state, workshop, payload)?;
    match std::fs::remove_file(&path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(DriverError::internal(error)),
    }
    Ok(json!({"secret_ref": format!("docker/{workshop}/carrier/{id}"), "deleted": true}))
}

async fn provision(
    state: &DriverState,
    workshop: Uuid,
    payload: &Value,
) -> Result<Value, DriverError> {
    let fleet_fenced = sqlx::query_scalar::<_, bool>(
        "select exists(select 1 from control.release_fleet_runs where state in ('preflighting','preparing','paused','activating'))",
    )
    .fetch_one(&state.ledger)
    .await
    .map_err(DriverError::internal)?;
    if fleet_fenced {
        return Err(DriverError(
            StatusCode::CONFLICT,
            "tenant provisioning is held behind the active fleet release fence".into(),
        ));
    }
    let release_id = active_platform_release(state).await?;
    let database_ref = opaque_database(payload, "database_ref")?;
    let odoo_hostname = hostname(payload, "public_hostname")?;
    let custom_hostnames = custom_hostname_routes(payload)?;
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
    let odoo_runtime = driver_runtime_secret_root(state)
        .join("odoo")
        .join(workshop.to_string());
    secure_directory(&odoo_runtime).map_err(DriverError::internal)?;
    let _odoo_admin =
        secret_value(&odoo_runtime.join("admin-password"), 64).map_err(DriverError::internal)?;
    ensure_database(&state.postgres, database_ref, "odoo", None).await?;
    let (odoo_client_id, paperless_oidc) =
        ensure_oidc_clients(state, &compact, odoo_hostname, paperless_hostname).await?;
    ensure_odoo_database(state, database_ref, &compact).await?;
    let (tenant_bridge_token, tenant_credential_created) =
        tenant_bridge_secret(&tenant_secret_dir.join("odoo")).map_err(DriverError::internal)?;
    write_secret(
        &state
            .config
            .odoo_client_secret_root
            .join(workshop.to_string()),
        &tenant_bridge_token,
    )
    .map_err(DriverError::internal)?;
    let runtime_clients = driver_runtime_secret_root(state).join("odoo-clients");
    secure_directory(&runtime_clients).map_err(DriverError::internal)?;
    write_secret(
        &runtime_clients.join(workshop.to_string()),
        &tenant_bridge_token,
    )
    .map_err(DriverError::internal)?;
    std::os::unix::fs::chown(
        runtime_clients.join(workshop.to_string()),
        Some(state.config.odoo_uid),
        Some(state.config.odoo_gid),
    )
    .map_err(DriverError::internal)?;
    std::os::unix::fs::chown(
        state
            .config
            .odoo_client_secret_root
            .join(workshop.to_string()),
        Some(state.config.odoo_uid),
        Some(state.config.odoo_gid),
    )
    .map_err(DriverError::internal)?;
    // A newly created database has no tenant verifier yet, so its one initial
    // bootstrap is authenticated by the process bootstrap credential. On
    // retries the persisted tenant credential is used directly; an
    // Unauthorized response is never retried with the shared credential.
    let bootstrap_token = if tenant_credential_created {
        &state.config.odoo_bridge_token
    } else {
        &tenant_bridge_token
    };
    let bootstrap_client = OdooClient::new(
        &state.config.odoo_base_url,
        bootstrap_token,
        Some(database_ref),
        Duration::from_secs(30),
    )
    .map_err(DriverError::internal)?;
    let bootstrap = TenantBootstrapCommand {
        operation_key: format!("tenant-bootstrap-v3:{workshop}"),
        workshop_id: workshop,
        oidc_client_id: odoo_client_id.clone(),
        oidc_issuer: state.config.oidc_issuer.clone(),
        bridge_token: tenant_bridge_token.clone(),
        public_hostname: odoo_hostname.to_owned(),
    };
    bootstrap_client
        .bootstrap_tenant(&bootstrap)
        .await
        .map_err(DriverError::internal)?;
    ensure_odoo_break_glass(state, workshop, database_ref, &compact).await?;
    let mut response = json!({
        "workshop_id": workshop,
        "action": "provision",
        "release_id": release_id,
        "odoo": {
            "base_url": state.config.odoo_base_url,
            "secret_ref": format!("docker/{workshop}/odoo"),
            "break_glass_secret_ref": format!("driver-runtime/odoo/{workshop}/admin-password"),
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
            let paperless_runtime = driver_runtime_secret_root(state)
                .join("paperless")
                .join(workshop.to_string());
            secure_directory(&paperless_runtime).map_err(DriverError::internal)?;
            write_secret(
                &paperless_runtime.join("oidc-secret"),
                &paperless_oidc_secret,
            )
            .map_err(DriverError::internal)?;
            let paperless_admin = secret_value(&paperless_runtime.join("admin-password"), 64)
                .map_err(DriverError::internal)?;
            let paperless_db_password =
                secret_value(&paperless_runtime.join("database-password"), 64)
                    .map_err(DriverError::internal)?;
            let paperless_secret_key = secret_value(&paperless_runtime.join("secret-key"), 96)
                .map_err(DriverError::internal)?;
            let redis_password = secret_value(&paperless_runtime.join("redis-password"), 64)
                .map_err(DriverError::internal)?;
            let paperless_client_dir = state
                .config
                .paperless_client_secret_root
                .join("docker")
                .join(workshop.to_string());
            secure_directory(&paperless_client_dir).map_err(DriverError::internal)?;
            write_secret(
                &paperless_client_dir.join("paperless"),
                &format!("basic:local-admin:{paperless_admin}"),
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
                &tenant_bridge_token,
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
        false,
        &custom_hostnames,
    )
    .await?;
    Ok(response)
}

fn tenant_key(workshop: Uuid) -> String {
    workshop.simple().to_string()
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

fn custom_hostname_routes(payload: &Value) -> Result<Vec<CustomHostnameRoute>, DriverError> {
    let Some(values) = payload.get("custom_hostnames") else {
        return Ok(Vec::new());
    };
    let values = values
        .as_array()
        .filter(|values| values.len() <= 20)
        .ok_or_else(|| DriverError::bad("custom_hostnames must be a bounded array"))?;
    let mut result = Vec::with_capacity(values.len());
    let mut canonical_seen = false;
    let mut unique = std::collections::HashSet::new();
    for value in values {
        let object = value
            .as_object()
            .filter(|object| {
                object.len() == 2
                    && object.contains_key("hostname")
                    && object.contains_key("canonical")
            })
            .ok_or_else(|| DriverError::bad("custom hostname route is invalid"))?;
        let hostname = hostname(value, "hostname")?.to_owned();
        let canonical = object
            .get("canonical")
            .and_then(Value::as_bool)
            .ok_or_else(|| DriverError::bad("custom hostname canonical flag is invalid"))?;
        if !unique.insert(hostname.clone()) || (canonical && canonical_seen) {
            return Err(DriverError::bad("custom hostname routes conflict"));
        }
        canonical_seen |= canonical;
        result.push(CustomHostnameRoute {
            hostname,
            canonical,
        });
    }
    Ok(result)
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
            let file_type = secret.file_type()?;
            if file_type.is_dir() && secret.file_name() == "paperless-runtime" {
                std::fs::set_permissions(secret.path(), std::fs::Permissions::from_mode(0o750))?;
                for runtime_secret in std::fs::read_dir(secret.path())? {
                    let runtime_secret = runtime_secret?;
                    if !runtime_secret.file_type()?.is_file() {
                        return Err(std::io::Error::other(
                            "Paperless secret directory contains a non-file entry",
                        ));
                    }
                    std::fs::set_permissions(
                        runtime_secret.path(),
                        std::fs::Permissions::from_mode(0o640),
                    )?;
                }
            } else if file_type.is_dir() && secret.file_name() == "carrier" {
                std::fs::set_permissions(secret.path(), std::fs::Permissions::from_mode(0o750))?;
                for carrier_secret in std::fs::read_dir(secret.path())? {
                    let carrier_secret = carrier_secret?;
                    if !carrier_secret.file_type()?.is_file()
                        || Uuid::parse_str(&carrier_secret.file_name().to_string_lossy()).is_err()
                    {
                        return Err(std::io::Error::other(
                            "carrier secret directory contains an unexpected entry",
                        ));
                    }
                    std::fs::set_permissions(
                        carrier_secret.path(),
                        std::fs::Permissions::from_mode(0o640),
                    )?;
                }
            } else if file_type.is_file() {
                std::fs::set_permissions(secret.path(), std::fs::Permissions::from_mode(0o640))?;
            } else {
                return Err(std::io::Error::other(
                    "tenant secret directory contains a non-file entry",
                ));
            }
        }
    }
    Ok(())
}

fn write_secret(path: &Path, value: &str) -> std::io::Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    if value.is_empty()
        || value.len() > 65_536
        || value.bytes().any(|byte| matches!(byte, b'\r' | b'\n'))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "secret must be a bounded non-empty single line",
        ));
    }
    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::other("secret path has no parent"))?;
    let temporary = parent.join(format!(".secret-{}.tmp", Uuid::new_v4()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true).mode(0o640);
    let result = (|| {
        let mut file = options.open(&temporary)?;
        std::io::Write::write_all(&mut file, value.as_bytes())?;
        file.sync_all()?;
        std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o640))?;
        std::fs::rename(&temporary, path)?;
        std::fs::File::open(parent)?.sync_all()
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(temporary);
    }
    result
}

fn clear_stale_job_secrets(root: &Path) -> std::io::Result<()> {
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        let name = entry.file_name();
        let valid = name
            .to_str()
            .is_some_and(|value| value.len() == 32 && Uuid::parse_str(value).is_ok());
        if !valid || !entry.file_type()?.is_dir() {
            return Err(std::io::Error::other(
                "job-secret root contains an unexpected entry",
            ));
        }
        std::fs::remove_dir_all(entry.path())?;
    }
    Ok(())
}

fn driver_runtime_secret_root(state: &DriverState) -> PathBuf {
    state
        .config
        .job_secret_root
        .parent()
        .expect("validated job-secret root has a parent")
        .join("runtime")
}

fn validated_secret_relative_path(relative: &Path) -> Result<String, DriverError> {
    if relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(DriverError::internal("invalid secret mount scope"));
    }
    relative
        .to_str()
        .map(str::to_owned)
        .ok_or_else(|| DriverError::internal("secret mount scope must be UTF-8"))
}

fn secret_mount_payload(
    runtime: ContainerRuntimeKind,
    source: &str,
    relative: &Path,
    target: &str,
) -> Result<Value, DriverError> {
    let relative = validated_secret_relative_path(relative)?;
    Ok(match runtime {
        ContainerRuntimeKind::Docker => json!({
            "Type":"volume",
            "Source":source,
            "Target":target,
            "ReadOnly":true,
            "VolumeOptions":{"Subpath":relative}
        }),
        ContainerRuntimeKind::Podman => json!({
            "Type":"bind",
            "Source":Path::new(source).join(relative),
            "Target":target,
            "ReadOnly":true
        }),
    })
}

fn runtime_secret_mount(
    state: &DriverState,
    relative: &Path,
    target: &str,
) -> Result<Value, DriverError> {
    secret_mount_payload(
        state.runtime.kind,
        &state.config.runtime_secret_source,
        &Path::new("runtime").join(relative),
        target,
    )
}

fn job_secret_mount(state: &DriverState, job: &str, target: &str) -> Result<Value, DriverError> {
    secret_mount_payload(
        state.runtime.kind,
        &state.config.runtime_secret_source,
        &Path::new("jobs").join(job),
        target,
    )
}

fn postgres_ca_mount(state: &DriverState) -> Result<Option<Value>, DriverError> {
    let Some(source) = &state.config.postgres_ca_source else {
        return Ok(None);
    };
    if !source.is_absolute() {
        return Err(DriverError::internal(
            "PostgreSQL CA source must be an absolute host path",
        ));
    }
    Ok(Some(json!({
        "Type":"bind",
        "Source":source,
        "Target":"/run/makersbrain-postgres-ca/postgres-ca.crt",
        "ReadOnly":true
    })))
}

fn secret_value(path: &Path, length: usize) -> std::io::Result<String> {
    if path.exists() {
        return std::fs::read_to_string(path).map(|value| value.trim().to_owned());
    }
    let value = Alphanumeric.sample_string(&mut rand::rng(), length);
    write_secret(path, &value)?;
    Ok(value)
}

fn tenant_bridge_secret(path: &Path) -> std::io::Result<(String, bool)> {
    if path.exists() {
        let value = std::fs::read_to_string(path)?.trim().to_owned();
        if (48..=128).contains(&value.len())
            && value.bytes().all(|byte| byte.is_ascii_alphanumeric())
        {
            return Ok((value, false));
        }
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "tenant bridge credential has an invalid format",
        ));
    }
    let value = Alphanumeric.sample_string(&mut rand::rng(), 64);
    write_secret(path, &value)?;
    Ok((value, true))
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

async fn run_docker_job_with_secrets(
    state: &DriverState,
    container: &str,
    mut body: Value,
    secrets: &[(&str, &str)],
) -> Result<(), DriverError> {
    let job = Uuid::new_v4().simple().to_string();
    let directory = state.config.job_secret_root.join(&job);
    secure_directory(&directory).map_err(DriverError::internal)?;
    let result = async {
        for (name, value) in secrets {
            if name.is_empty()
                || name.len() > 64
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || matches!(byte, b'-' | b'_'))
            {
                return Err(DriverError::internal("invalid job-secret name"));
            }
            write_secret(&directory.join(name), value).map_err(DriverError::internal)?;
        }
        let host = body
            .get_mut("HostConfig")
            .and_then(Value::as_object_mut)
            .ok_or_else(|| DriverError::internal("job HostConfig is required"))?;
        host.entry("GroupAdd")
            .or_insert_with(|| json!([]))
            .as_array_mut()
            .ok_or_else(|| DriverError::internal("job GroupAdd must be an array"))?
            .push(json!("0"));
        host.entry("Mounts")
            .or_insert_with(|| json!([]))
            .as_array_mut()
            .ok_or_else(|| DriverError::internal("job Mounts must be an array"))?
            .push(job_secret_mount(
                state,
                &job,
                "/run/makersbrain-job-secrets",
            )?);
        if let Some(mount) = postgres_ca_mount(state)? {
            host.get_mut("Mounts")
                .and_then(Value::as_array_mut)
                .expect("Mounts was validated above")
                .push(mount);
            let environment = body
                .as_object_mut()
                .expect("job body is an object")
                .entry("Env")
                .or_insert_with(|| json!([]))
                .as_array_mut()
                .ok_or_else(|| DriverError::internal("job Env must be an array"))?;
            environment.push(json!("PGSSLMODE=verify-full"));
            environment.push(json!(
                "PGSSLROOTCERT=/run/makersbrain-postgres-ca/postgres-ca.crt"
            ));
        }
        run_docker_job(state, container, body).await
    }
    .await;
    let cleanup = std::fs::remove_dir_all(&directory).map_err(DriverError::internal);
    match (result, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn docker_secret_mount_uses_a_named_volume_subpath() {
        let mount = secret_mount_payload(
            ContainerRuntimeKind::Docker,
            "control-secrets",
            Path::new("runtime/paperless/tenant"),
            "/run/secrets",
        )
        .unwrap();
        assert_eq!(mount["Type"], "volume");
        assert_eq!(mount["Source"], "control-secrets");
        assert_eq!(
            mount["VolumeOptions"]["Subpath"],
            "runtime/paperless/tenant"
        );
    }

    #[test]
    fn podman_secret_mount_uses_a_protected_host_path() {
        let mount = secret_mount_payload(
            ContainerRuntimeKind::Podman,
            "/var/lib/makersbrain/tenant-runtime-secrets",
            Path::new("jobs/job-id"),
            "/run/secrets",
        )
        .unwrap();
        assert_eq!(mount["Type"], "bind");
        assert_eq!(
            mount["Source"],
            "/var/lib/makersbrain/tenant-runtime-secrets/jobs/job-id"
        );
        assert!(mount.get("VolumeOptions").is_none());
    }

    #[test]
    fn secret_mount_scope_cannot_escape_its_root() {
        assert!(
            secret_mount_payload(
                ContainerRuntimeKind::Podman,
                "/var/lib/makersbrain/tenant-runtime-secrets",
                Path::new("../other-user"),
                "/run/secrets",
            )
            .is_err()
        );
    }

    #[test]
    fn physical_database_names_are_strictly_opaque() {
        let valid = json!({"database_ref":"mb_00000000000000000000000000000001"});
        assert!(opaque_database(&valid, "database_ref").is_ok());
        for invalid in ["atelier", "mb_123", "mb_0000000000000000000000000000000Z"] {
            assert!(opaque_database(&json!({"database_ref":invalid}), "database_ref").is_err());
        }
    }

    #[test]
    fn pre_erasure_restore_keeps_the_public_route_fenced() {
        assert!(requires_erasure_replay_fence(&json!({
            "action":"restore","erasure_replay_required":true
        })));
        assert!(!requires_erasure_replay_fence(&json!({
            "action":"restore","erasure_replay_required":false
        })));
        assert!(!requires_erasure_replay_fence(&json!({
            "action":"backup","erasure_replay_required":true
        })));
    }

    #[test]
    fn public_hostnames_cannot_inject_gateway_configuration() {
        assert!(hostname(&json!({"host":"atelier.dev1.makersbrain.net"}), "host").is_ok());
        assert!(hostname(&json!({"host":"atelier; return 200"}), "host").is_err());
    }

    #[test]
    fn custom_hostname_routes_are_bounded_unique_and_injection_safe() {
        let routes = custom_hostname_routes(&json!({"custom_hostnames":[
            {"hostname":"www.atelier-luna.fr","canonical":true},
            {"hostname":"shop.atelier-luna.fr","canonical":false}
        ]}))
        .unwrap();
        assert_eq!(routes.len(), 2);
        assert!(routes[0].canonical);
        assert!(
            custom_hostname_routes(&json!({"custom_hostnames":[
                {"hostname":"atelier; return 200","canonical":true}
            ]}))
            .is_err()
        );
        assert!(
            custom_hostname_routes(&json!({"custom_hostnames":[
                {"hostname":"a.example.fr","canonical":true},
                {"hostname":"b.example.fr","canonical":true}
            ]}))
            .is_err()
        );
    }

    #[test]
    fn canonical_custom_hostname_keeps_platform_origin_and_redirects_custom_aliases() {
        let config = route_config_with_custom_hostnames(
            "mb_00000000000000000000000000000001",
            "atelier.makersbrain.com",
            None,
            false,
            &[
                CustomHostnameRoute {
                    hostname: "www.atelier-luna.fr".into(),
                    canonical: true,
                },
                CustomHostnameRoute {
                    hostname: "shop.atelier-luna.fr".into(),
                    canonical: false,
                },
            ],
        );
        assert!(config.contains("server_name www.atelier-luna.fr atelier.makersbrain.com;"));
        assert!(config.contains(
            "server_name shop.atelier-luna.fr;\n  return 308 https://www.atelier-luna.fr$request_uri;"
        ));
        assert_eq!(config.matches("X-Odoo-Dbfilter").count(), 1);
    }

    #[test]
    fn platform_hostname_redirects_active_noncanonical_custom_hosts() {
        let config = route_config_with_custom_hostnames(
            "mb_00000000000000000000000000000001",
            "atelier.makersbrain.com",
            None,
            false,
            &[CustomHostnameRoute {
                hostname: "www.atelier-luna.fr".into(),
                canonical: false,
            }],
        );
        assert!(config.contains("server_name atelier.makersbrain.com;"));
        assert!(config.contains(
            "server_name www.atelier-luna.fr;\n  return 308 https://atelier.makersbrain.com$request_uri;"
        ));
        assert_eq!(config.matches("X-Odoo-Dbfilter").count(), 1);
    }

    #[test]
    fn docker_resource_names_use_the_complete_workshop_identity() {
        let first = Uuid::parse_str("00000000-0000-0000-0000-000000000201").unwrap();
        let second = Uuid::parse_str("00000000-0000-0000-0000-000000000202").unwrap();
        assert_ne!(tenant_key(first), tenant_key(second));
        assert_eq!(tenant_key(first).len(), 32);
    }

    #[test]
    fn tenant_bridge_credentials_are_unique_and_invalid_values_fail_closed() {
        let root = std::env::temp_dir().join(format!("mb-tenant-token-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let first_path = root.join("first");
        let second_path = root.join("second");

        let (first, first_created) = tenant_bridge_secret(&first_path).unwrap();
        let (second, second_created) = tenant_bridge_secret(&second_path).unwrap();

        assert!(first_created && second_created);
        assert_ne!(first, second);
        assert_eq!(first.len(), 64);
        assert!(first.bytes().all(|byte| byte.is_ascii_alphanumeric()));
        assert_eq!(tenant_bridge_secret(&first_path).unwrap(), (first, false));
        write_secret(&first_path, "invalid").unwrap();
        assert!(tenant_bridge_secret(&first_path).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn tenant_routes_resolve_container_addresses_dynamically() {
        let config = route_config(
            "mb_00000000000000000000000000000001",
            "atelier.dev1.makersbrain.net",
            Some((
                "docs-atelier.dev1.makersbrain.net",
                "mb-paperless-00000000000000000000000000000001",
            )),
            false,
        );
        assert!(config.contains("set $tenant_upstream \"odoo:8069\";"));
        assert!(config.contains(
            "set $tenant_upstream \"mb-paperless-00000000000000000000000000000001:8000\";"
        ));
        assert_eq!(
            config
                .matches("proxy_pass http://$tenant_upstream;")
                .count(),
            2
        );
        assert!(!config.contains("proxy_pass http://odoo:8069;"));
    }

    #[test]
    fn paperless_restriction_blocks_mutations_but_retains_reads() {
        let config = route_config(
            "mb_00000000000000000000000000000001",
            "atelier.dev1.makersbrain.net",
            Some(("docs-atelier.dev1.makersbrain.net", "mb-paperless-fixture")),
            true,
        );
        assert!(config.contains("limit_except GET HEAD OPTIONS { deny all; }"));
        assert!(config.contains("proxy_pass http://$tenant_upstream;"));
    }

    #[test]
    fn tenant_secret_permissions_are_normalized_for_worker_access() {
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!("mb-secrets-{}", Uuid::new_v4()));
        let tenant = root.join("docker/00000000-0000-0000-0000-000000000201");
        std::fs::create_dir_all(&tenant).unwrap();
        let secret = tenant.join("odoo");
        std::fs::write(&secret, "sensitive").unwrap();
        let paperless = tenant.join("paperless-runtime");
        std::fs::create_dir(&paperless).unwrap();
        let paperless_secret = paperless.join("database-password");
        std::fs::write(&paperless_secret, "sensitive").unwrap();
        std::fs::set_permissions(&tenant, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::set_permissions(&paperless, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&paperless_secret, std::fs::Permissions::from_mode(0o600))
            .unwrap();

        normalize_secret_permissions(&root).unwrap();

        assert_eq!(
            std::fs::metadata(&tenant).unwrap().permissions().mode() & 0o777,
            0o750
        );
        assert_eq!(
            std::fs::metadata(&secret).unwrap().permissions().mode() & 0o777,
            0o640
        );
        assert_eq!(
            std::fs::metadata(&paperless).unwrap().permissions().mode() & 0o777,
            0o750
        );
        assert_eq!(
            std::fs::metadata(&paperless_secret)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o640
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn driver_secret_writes_are_bounded_atomic_and_do_not_follow_links() {
        let root = std::env::temp_dir().join(format!("mb-secret-write-{}", Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let target = root.join("credential");
        write_secret(&target, "first-value").unwrap();
        write_secret(&target, "rotated-value").unwrap();
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "rotated-value");
        assert!(write_secret(&target, "two\nlines").is_err());
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "rotated-value");
        let victim = root.join("victim");
        std::fs::write(&victim, "must-not-change").unwrap();
        std::fs::remove_file(&target).unwrap();
        std::os::unix::fs::symlink(&victim, &target).unwrap();
        write_secret(&target, "safe-replacement").unwrap();
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "must-not-change");
        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            "safe-replacement"
        );
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 2);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn stale_job_secrets_are_removed_but_unexpected_entries_fail_closed() {
        let root = std::env::temp_dir().join(format!("mb-job-secrets-{}", Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let stale = root.join(Uuid::new_v4().simple().to_string());
        std::fs::create_dir(&stale).unwrap();
        std::fs::write(stale.join("credential"), "sensitive").unwrap();
        clear_stale_job_secrets(&root).unwrap();
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
        std::fs::write(root.join("operator-material"), "preserve").unwrap();
        assert!(clear_stale_job_secrets(&root).is_err());
        assert!(root.join("operator-material").is_file());
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
