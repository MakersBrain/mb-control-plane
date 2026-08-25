use std::collections::HashMap;
use std::future::Future;
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
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{AssertSqlSafe, PgPool, Row};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Mutex, RwLock};
use url::Url;
use uuid::Uuid;

use crate::domain::IntegrationError;
use crate::integrations::odoo::{ErasureReplayCommand, OdooClient, TenantBootstrapCommand};
use crate::integrations::paperless::PaperlessClient;
use crate::persistence::{Store, TenantStore};

mod docker_client;
mod executor_quiescence;
mod fleet_reconciliation;
mod gateway;
mod generation_retention_scheduler;
mod host_guard;
mod postgres;
mod privacy;
mod recovery;
mod release;
mod release_generation_fs;
mod release_route_publication_db;
mod release_route_recovery;
mod release_route_recovery_coordinator;
mod release_route_recovery_db;
mod release_route_recovery_observation;
mod release_route_retention;
mod release_route_retention_db;
mod release_route_staging;
mod release_runtime_observation;
mod route_generation_fs;
mod route_projection;
mod route_set_generation_fs;
mod route_set_prior;
mod route_set_publication;
mod route_set_publication_db;
mod route_set_recovery;
mod route_set_recovery_db;
mod route_set_recovery_publication_db;
mod route_set_retention;
mod route_set_retention_db;
mod route_set_staging;
mod route_set_startup_publication_db;
mod runtime_backend;
mod services;
mod startup;
mod startup_generation_fs;
mod startup_publication;
mod task_supervisor;

use docker_client::*;
use gateway::*;
use postgres::*;
use recovery::*;
use runtime_backend::*;
use services::*;
use startup::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DriverBackendKind {
    Docker,
    Quadlet,
}

impl DriverBackendKind {
    fn parse(value: &str) -> anyhow::Result<Self> {
        match value {
            "docker" => Ok(Self::Docker),
            "quadlet" => Ok(Self::Quadlet),
            _ => anyhow::bail!("DRIVER_BACKEND must be docker or quadlet"),
        }
    }
}

#[derive(Clone)]
struct ContainerRuntime {
    client: reqwest::Client,
}

impl ContainerRuntime {
    fn endpoint(&self, path: &str) -> String {
        format!("http://localhost/v1.47{path}")
    }
}

#[derive(Clone)]
pub struct DockerDriverConfig {
    pub listen: DriverListen,
    token: String,
    privacy_token: String,
    backend: DriverBackendKind,
    runtime_socket: Option<PathBuf>,
    quadlet_root: Option<PathBuf>,
    systemd_runtime_dir: Option<PathBuf>,
    image_grant_root: Option<PathBuf>,
    allow_raw_podman_migration: bool,
    database_url: String,
    postgres_admin_url: String,
    postgres_admin_user: String,
    postgres_admin_password: String,
    postgres_host: String,
    postgres_port: u16,
    postgres_ca_source: Option<PathBuf>,
    odoo_postgres_password: String,
    odoo_bridge_token: String,
    extension_helper_image: String,
    postgres_image: String,
    paperless_image: Option<String>,
    workspace_namespace: String,
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
    redis_admin_address: String,
    secret_root: PathBuf,
    odoo_client_secret_root: PathBuf,
    paperless_client_secret_root: PathBuf,
    runtime_secret_source: String,
    recovery_secret_source: String,
    job_secret_root: PathBuf,
    route_root: PathBuf,
    tenant_domain: String,
    gateway_container: String,
    odoo_base_url: String,
    control_internal_url: String,
    rauthy_admin_url: String,
    rauthy_admin_key: String,
    oidc_issuer: String,
    public_scheme: String,
    public_port: Option<u16>,
}

#[derive(Clone, Debug)]
pub enum DriverListen {
    Tcp(SocketAddr),
    SystemdUnix(PathBuf),
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
        let backend = DriverBackendKind::parse(&required("DRIVER_BACKEND")?)?;
        if backend == DriverBackendKind::Docker && environment != "development" {
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
        let runtime_socket = optional("DRIVER_RUNTIME_SOCKET")?.map(PathBuf::from);
        if backend == DriverBackendKind::Docker
            && runtime_socket
                .as_ref()
                .is_none_or(|path| !path.is_absolute())
        {
            anyhow::bail!("DRIVER_RUNTIME_SOCKET must be an absolute Unix-socket path for Docker");
        }
        if backend == DriverBackendKind::Quadlet && runtime_socket.is_some() {
            anyhow::bail!("DRIVER_RUNTIME_SOCKET is forbidden for the Quadlet backend");
        }
        let quadlet_root = optional("DRIVER_QUADLET_ROOT")?.map(PathBuf::from);
        let systemd_runtime_dir = optional("DRIVER_SYSTEMD_RUNTIME_DIR")?.map(PathBuf::from);
        let image_grant_root = optional("DRIVER_IMAGE_GRANT_ROOT")?.map(PathBuf::from);
        let allow_raw_podman_migration = optional("DRIVER_ALLOW_RAW_PODMAN_MIGRATION")?
            .as_deref()
            .map(str::parse::<bool>)
            .transpose()?
            .unwrap_or(false);
        if allow_raw_podman_migration && environment != "staging" {
            anyhow::bail!("raw Podman migration is allowed only in staging");
        }
        if backend == DriverBackendKind::Quadlet
            && [
                quadlet_root.as_ref(),
                systemd_runtime_dir.as_ref(),
                image_grant_root.as_ref(),
            ]
            .into_iter()
            .any(|path| path.is_none_or(|path| !path.is_absolute()))
        {
            anyhow::bail!(
                "DRIVER_QUADLET_ROOT, DRIVER_SYSTEMD_RUNTIME_DIR and DRIVER_IMAGE_GRANT_ROOT must be absolute for Quadlet"
            );
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
            if !age_identity_file.starts_with("/run/mb-recovery-secrets/") {
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
        if backend == DriverBackendKind::Quadlet && !Path::new(&runtime_secret_source).is_absolute()
        {
            anyhow::bail!("DRIVER_RUNTIME_SECRET_SOURCE must be an absolute host path for Podman");
        }
        if backend == DriverBackendKind::Quadlet
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
        let workspace_namespace = required("DRIVER_WORKSPACE_NAMESPACE")?;
        if backend == DriverBackendKind::Docker
            && !matches!(
                workspace_namespace.as_str(),
                "mb-control" | "mb-dev1" | "mb-dev2" | "mb-dev3" | "mb-dev4"
            )
        {
            anyhow::bail!(
                "DRIVER_WORKSPACE_NAMESPACE must be mb-control or mb-dev1 through mb-dev4 for Docker"
            );
        }
        if !workspace_namespace
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            anyhow::bail!("DRIVER_WORKSPACE_NAMESPACE contains unsafe characters");
        }
        let listen = match backend {
            DriverBackendKind::Docker => DriverListen::Tcp(required("DRIVER_LISTEN")?.parse()?),
            DriverBackendKind::Quadlet => {
                let socket = PathBuf::from(required("DRIVER_UNIX_SOCKET")?);
                let runtime_dir = systemd_runtime_dir
                    .as_ref()
                    .expect("validated Quadlet runtime directory");
                if !socket.is_absolute() || !socket.starts_with(runtime_dir) {
                    anyhow::bail!(
                        "DRIVER_UNIX_SOCKET must be an absolute path below DRIVER_SYSTEMD_RUNTIME_DIR"
                    );
                }
                DriverListen::SystemdUnix(socket)
            }
        };
        Ok(Self {
            listen,
            token,
            privacy_token,
            backend,
            runtime_socket,
            quadlet_root,
            systemd_runtime_dir,
            image_grant_root,
            allow_raw_podman_migration,
            database_url: required_secret("DRIVER_DATABASE_URL")?,
            postgres_admin_url,
            postgres_admin_user,
            postgres_admin_password,
            postgres_host: required("DRIVER_POSTGRES_HOST")?,
            postgres_port: required("DRIVER_POSTGRES_PORT")?.parse()?,
            postgres_ca_source,
            odoo_postgres_password: required_secret("DRIVER_ODOO_POSTGRES_PASSWORD")?,
            odoo_bridge_token: required_secret("DRIVER_ODOO_BRIDGE_TOKEN")?,
            extension_helper_image: {
                let image = required("DRIVER_EXTENSION_HELPER_IMAGE")?;
                if environment == "development" {
                    image
                } else {
                    digest_pinned_image("DRIVER_EXTENSION_HELPER_IMAGE", &image)?
                }
            },
            postgres_image: required("DRIVER_POSTGRES_IMAGE")?,
            paperless_image: std::env::var("DRIVER_PAPERLESS_IMAGE")
                .ok()
                .filter(|value| !value.trim().is_empty())
                .map(|image| {
                    if environment == "development" {
                        Ok(image)
                    } else {
                        digest_pinned_image("DRIVER_PAPERLESS_IMAGE", &image)
                    }
                })
                .transpose()?,
            workspace_namespace,
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
            redis_admin_address: required("DRIVER_REDIS_ADMIN_ADDRESS")?,
            secret_root: required("DRIVER_SECRET_ROOT")?.into(),
            odoo_client_secret_root: required("DRIVER_ODOO_CLIENT_SECRET_ROOT")?.into(),
            paperless_client_secret_root: required("DRIVER_PAPERLESS_CLIENT_SECRET_ROOT")?.into(),
            runtime_secret_source,
            recovery_secret_source,
            job_secret_root: required("DRIVER_JOB_SECRET_ROOT")?.into(),
            route_root: required("DRIVER_ROUTE_ROOT")?.into(),
            tenant_domain: driver_tenant_domain()?,
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

    fn docker_resource(&self, suffix: impl AsRef<str>) -> String {
        format!("{}-{}", self.workspace_namespace, suffix.as_ref())
    }
}

fn required(name: &'static str) -> anyhow::Result<String> {
    crate::runtime_secret::required_configuration(name).map_err(anyhow::Error::msg)
}

fn digest_pinned_image(name: &'static str, value: &str) -> anyhow::Result<String> {
    let valid = value
        .rsplit_once("@sha256:")
        .is_some_and(|(repository, digest)| {
            !repository.trim().is_empty()
                && digest.len() == 64
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        });
    if !valid {
        anyhow::bail!("{name} must be an exact sha256 digest-pinned image reference");
    }
    Ok(value.to_owned())
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

fn driver_tenant_domain() -> anyhow::Result<String> {
    let value = required("DRIVER_TENANT_DOMAIN")?
        .trim()
        .to_ascii_lowercase();
    if value.len() > 253
        || (!value.contains('.') && value != "localhost")
        || value.contains("..")
        || value.starts_with('.')
        || value.ends_with('.')
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'.')
        })
    {
        anyhow::bail!("DRIVER_TENANT_DOMAIN must be a lower-case DNS suffix or localhost");
    }
    Ok(value)
}

#[derive(Clone)]
struct DriverState {
    instance_id: Uuid,
    config: DockerDriverConfig,
    ledger: PgPool,
    tenant_ledger: TenantStore,
    postgres: PgPool,
    runtime: ContainerRuntime,
    backend: RuntimeBackend,
    rauthy: reqwest::Client,
    resource_locks: Arc<std::sync::Mutex<HashMap<String, Arc<Mutex<()>>>>>,
    startup: Arc<RwLock<StartupReport>>,
    task_supervisor: task_supervisor::DriverTaskSupervisorHandle,
}

/// The HTTP router and the asynchronous work lifecycle that must outlive it.
///
/// Keeping these values together prevents production callers from accidentally
/// dropping database/runtime resources before admitted driver effects and their
/// safety cleanup have reached a terminal state.
pub struct DriverApplication {
    router: Router,
    lifecycle: DriverLifecycle,
}

impl DriverApplication {
    pub fn into_parts(self) -> (Router, DriverLifecycle) {
        (self.router, self.lifecycle)
    }
}

#[derive(Clone)]
pub struct DriverLifecycle {
    supervisor: Arc<task_supervisor::DriverTaskSupervisorLifecycle>,
    // The pools and runtime clients must outlive every supervised task.
    _state: Arc<DriverState>,
}

impl DriverLifecycle {
    pub fn begin_draining(&self) {
        self.supervisor.begin_draining();
    }

    pub fn is_accepting(&self) -> bool {
        self.supervisor.is_accepting()
    }

    pub async fn shutdown(&self) -> anyhow::Result<()> {
        self.supervisor
            .drain()
            .await
            .map(|_| ())
            .map_err(|_| anyhow::anyhow!("driver task supervisor did not drain cleanly"))
    }
}

const RECOVERY_FORMAT_V2: &str = "mb-workshop-recovery-v2";

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

pub async fn build_application(config: DockerDriverConfig) -> anyhow::Result<DriverApplication> {
    std::fs::create_dir_all(&config.secret_root)?;
    normalize_secret_permissions(&config.secret_root)?;
    let expected_odoo_client_root = match config.backend {
        DriverBackendKind::Docker => PathBuf::from("/run/mb-odoo-client-secrets"),
        DriverBackendKind::Quadlet => {
            Path::new(&config.runtime_secret_source).join("runtime/odoo-clients")
        }
    };
    if config.odoo_client_secret_root != expected_odoo_client_root {
        anyhow::bail!("DRIVER_ODOO_CLIENT_SECRET_ROOT must use the isolated Odoo client mount");
    }
    std::fs::create_dir_all(&config.odoo_client_secret_root)?;
    normalize_secret_permissions(&config.odoo_client_secret_root)?;
    if config.backend == DriverBackendKind::Docker {
        std::os::unix::fs::chown(
            &config.odoo_client_secret_root,
            Some(config.odoo_uid),
            Some(config.odoo_gid),
        )?;
    }
    let expected_paperless_client_root = match config.backend {
        DriverBackendKind::Docker => PathBuf::from("/run/mb-paperless-client-secrets"),
        DriverBackendKind::Quadlet => {
            Path::new(&config.runtime_secret_source).join("runtime/paperless-clients")
        }
    };
    if config.paperless_client_secret_root != expected_paperless_client_root {
        anyhow::bail!(
            "DRIVER_PAPERLESS_CLIENT_SECRET_ROOT must use the isolated Paperless client mount"
        );
    }
    std::fs::create_dir_all(&config.paperless_client_secret_root)?;
    normalize_secret_permissions(&config.paperless_client_secret_root)?;
    let expected_job_root = match config.backend {
        DriverBackendKind::Docker => PathBuf::from("/run/mb-backup-secrets/jobs"),
        DriverBackendKind::Quadlet => Path::new(&config.runtime_secret_source).join("jobs"),
    };
    if config.job_secret_root != expected_job_root {
        anyhow::bail!("DRIVER_JOB_SECRET_ROOT must use the scoped runtime job-secret directory");
    }
    secure_directory(&config.job_secret_root)?;
    if config.backend == DriverBackendKind::Docker {
        clear_stale_job_secrets(&config.job_secret_root)?;
    } else {
        validate_retained_job_secrets(&config.job_secret_root)?;
    }
    secure_directory(
        &config
            .job_secret_root
            .parent()
            .expect("validated job-secret root has a parent")
            .join("runtime"),
    )?;
    std::fs::create_dir_all(&config.route_root)?;
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&config.route_root, std::fs::Permissions::from_mode(0o750))?;
    }
    host_guard::SharedOdooHostGuard::prepare(&config.route_root)?;
    std::fs::create_dir_all(&config.backup_root)?;
    let instance_id = Uuid::new_v4();
    let ledger_store = Store::connect(&config.database_url).await?;
    let ledger = ledger_store.pool().clone();
    let tenant_ledger = ledger_store.worker_tenant_scope();
    let postgres_options = config
        .postgres_admin_url
        .parse::<PgConnectOptions>()?
        .application_name(&executor_quiescence::driver_postgres_application_name(
            instance_id,
        ));
    let postgres = PgPoolOptions::new()
        .max_connections(2)
        .connect_with(postgres_options)
        .await?;
    let mut runtime_builder =
        crate::outbound_http::internal_service_builder("mb-control-container-driver/runtime")
            .timeout(Duration::from_secs(180));
    if let Some(socket) = &config.runtime_socket {
        runtime_builder = runtime_builder.unix_socket(socket.as_path());
    }
    let runtime_client = runtime_builder.build()?;
    let mut authorization =
        reqwest::header::HeaderValue::from_str(&format!("API-Key {}", config.rauthy_admin_key))?;
    authorization.set_sensitive(true);
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(reqwest::header::AUTHORIZATION, authorization);
    let rauthy =
        crate::outbound_http::internal_service_builder("mb-control-container-driver/rauthy")
            .default_headers(headers)
            .timeout(Duration::from_secs(30))
            .build()?;
    let backend = RuntimeBackend::from_config(&config)?;
    let (task_supervisor, task_lifecycle) =
        task_supervisor::new_driver_task_supervisor(task_supervisor::DriverTaskSupervisorConfig {
            admitted_capacity: 32,
        })
        .map_err(|_| anyhow::anyhow!("driver task supervisor configuration was invalid"))?;
    let state = Arc::new(DriverState {
        instance_id,
        config,
        ledger,
        tenant_ledger,
        postgres,
        runtime: ContainerRuntime {
            client: runtime_client,
        },
        backend,
        rauthy,
        resource_locks: Arc::new(std::sync::Mutex::new(HashMap::new())),
        startup: Arc::new(RwLock::new(StartupReport::default())),
        task_supervisor,
    });
    recover_database_connection_limits(&state)
        .await
        .map_err(|error| anyhow::anyhow!(error.1))?;
    let startup_report = startup::reconcile(&state).await;
    *state.startup.write().await = startup_report;
    let router = Router::new()
        .route("/health/live", get(|| async { "live" }))
        .route("/health/ready", get(ready))
        .route("/v1/tenants/{workshop}/{action}", post(tenant))
        .route("/v1/privacy/{workshop}/export", post(privacy::export))
        .with_state(state.clone());
    Ok(DriverApplication {
        router,
        lifecycle: DriverLifecycle {
            supervisor: Arc::new(task_lifecycle),
            _state: state.clone(),
        },
    })
}

async fn ready(State(state): State<Arc<DriverState>>) -> Response {
    let report = state.startup.read().await.clone();
    let status = readiness_status(report.command_ready(), state.task_supervisor.is_accepting());
    (status, Json(report)).into_response()
}

fn readiness_status(startup_ready: bool, accepting_tasks: bool) -> StatusCode {
    if startup_ready && accepting_tasks {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

#[tracing::instrument(
    name = "driver.startup.recover_database_connection_limits",
    skip_all,
    fields(scope.kind = "bounded_fleet")
)]
async fn recover_database_connection_limits(state: &DriverState) -> Result<(), DriverError> {
    let rows = sqlx::query(
        "select d.id,d.workshop_id,d.database_ref,d.connection_limit_before_lifecycle
           from control.odoo_databases d
          where d.connection_limit_before_lifecycle is not null
            and not exists (
              select 1 from control.deployment_driver_operations o
               where o.workshop_id=d.workshop_id and o.action='lifecycle'
                 and o.state='in_progress'
            )
          order by d.workshop_id,d.id
          limit 100",
    )
    .fetch_all(&state.ledger)
    .await
    .map_err(DriverError::internal)?;
    for row in rows {
        let id: Uuid = row.get("id");
        let workshop: Uuid = row.get("workshop_id");
        let database: String = row.get("database_ref");
        let limit: i32 = row.get("connection_limit_before_lifecycle");
        set_database_connection_limit(state, &database, limit).await?;
        sqlx::query(
            "update control.odoo_databases database
                set connection_limit_before_lifecycle=null
              where database.id=$1 and database.workshop_id=$2
                and database.connection_limit_before_lifecycle=$3
                and not exists(
                    select 1 from control.deployment_driver_operations operation
                     where operation.workshop_id=database.workshop_id
                       and operation.action='lifecycle' and operation.state='in_progress')",
        )
        .bind(id)
        .bind(workshop)
        .bind(limit)
        .execute(&state.ledger)
        .await
        .map_err(DriverError::internal)?;
        tracing::warn!(database_id=%id,"recovered PostgreSQL connection limit left by an interrupted lifecycle operation");
    }
    Ok(())
}

#[derive(Debug)]
struct DriverError(StatusCode, String);

impl DriverError {
    fn bad(message: impl Into<String>) -> Self {
        Self(StatusCode::BAD_REQUEST, message.into())
    }
    fn internal(_error: impl std::fmt::Display) -> Self {
        tracing::error!(
            error_class = "deployment_backend",
            "Docker deployment operation failed"
        );
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
            tracing::error!(
                error_class = crate::error_reporting::safe_error_class(&error),
                "privacy processor export failed"
            );
        }
        Self(status, message.into())
    }

    fn safe_class(&self) -> &'static str {
        match self.0 {
            StatusCode::BAD_REQUEST => "invalid_request",
            StatusCode::UNAUTHORIZED => "unauthorized",
            StatusCode::NOT_FOUND => "not_found",
            StatusCode::CONFLICT => "conflict",
            StatusCode::UNPROCESSABLE_ENTITY => "contract_rejected",
            StatusCode::PAYLOAD_TOO_LARGE => "payload_too_large",
            status if status.is_server_error() => "deployment_backend_failure",
            _ => "deployment_driver_failure",
        }
    }
}

impl IntoResponse for DriverError {
    fn into_response(self) -> Response {
        let mut body = json!({"error": self.1});
        if self.0 == StatusCode::SERVICE_UNAVAILABLE
            && body.get("error").and_then(Value::as_str)
                == Some(FLEET_RECONCILIATION_INCONCLUSIVE_MESSAGE)
        {
            body["error_code"] = json!(FLEET_RECONCILIATION_INCONCLUSIVE_CODE);
        }
        (self.0, Json(body)).into_response()
    }
}

const FLEET_RECONCILIATION_INCONCLUSIVE_CODE: &str = "release_reconciliation_inconclusive";
const FLEET_RECONCILIATION_INCONCLUSIVE_MESSAGE: &str =
    "fleet release forward observation was inconclusive";

fn fleet_reconciliation_inconclusive() -> DriverError {
    DriverError(
        StatusCode::SERVICE_UNAVAILABLE,
        FLEET_RECONCILIATION_INCONCLUSIVE_MESSAGE.into(),
    )
}

#[derive(Debug)]
enum DriverOperationAdmission {
    New,
    Replay(Value),
}

const RELEASE_DRIVER_LEASE_SECONDS: i32 = 1200;
const RELEASE_DRIVER_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(20);
const RELEASE_DRIVER_HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(15);
const ROUTE_APPLICATION_LEASE_SECONDS: i32 = 1200;
const RECOVERY_ROUTE_EFFECT_LEASE_SECONDS: i32 = 1200;

#[derive(Clone)]
struct ControlOperationLease {
    id: Uuid,
    attempt: i32,
    owner: String,
}

struct ReleaseDriverLease {
    driver_operation_id: Uuid,
    fleet_run_id: Option<Uuid>,
    control_operation: ControlOperationLease,
    instance_owner: Uuid,
    execution_token: Uuid,
    resource_lease_token: Uuid,
    fence_token: i64,
    reserved_workshops: Vec<Uuid>,
}

struct InitialReleaseReconciliation {
    id: Uuid,
    driver_operation_id: Uuid,
    instance_owner: Uuid,
    execution_token: Uuid,
    evidence: Value,
}

struct FleetReleaseReconciliation {
    id: Uuid,
    driver_operation_id: Uuid,
    original_fence_token: i64,
    original_instance_owner: Uuid,
    instance_owner: Uuid,
    execution_token: Uuid,
    gateway_identity: gateway::ReleaseGatewayGenerationIdentity,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ReleaseTarget {
    Initial {
        target_key: String,
    },
    Fleet {
        target_key: String,
        fleet_run_id: Uuid,
    },
}

impl ReleaseTarget {
    fn from_payload(payload: &Value) -> Result<Self, DriverError> {
        match payload.get("phase").and_then(Value::as_str) {
            Some("prepare-initial") => payload
                .get("release_id")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .map(|value| Self::Initial {
                    target_key: format!("initial/{value}"),
                }),
            Some("adopt-fleet") => payload
                .get("fleet_run_id")
                .and_then(Value::as_str)
                .and_then(|value| Uuid::parse_str(value).ok())
                .map(|fleet_run_id| Self::Fleet {
                    target_key: format!("fleet/{fleet_run_id}"),
                    fleet_run_id,
                }),
            _ => None,
        }
        .ok_or_else(|| DriverError::bad("release target identity is invalid"))
    }

    fn target_key(&self) -> &str {
        match self {
            Self::Initial { target_key } | Self::Fleet { target_key, .. } => target_key,
        }
    }

    const fn fleet_run_id(&self) -> Option<Uuid> {
        match self {
            Self::Initial { .. } => None,
            Self::Fleet { fleet_run_id, .. } => Some(*fleet_run_id),
        }
    }

    const fn class(&self) -> &'static str {
        match self {
            Self::Initial { .. } => "initial",
            Self::Fleet { .. } => "fleet",
        }
    }
}

#[derive(Clone)]
struct RouteProjectionContract {
    generation: i64,
    digest: String,
    disposition: String,
}

struct RouteApplicationLease {
    driver_operation_id: Uuid,
    control_operation: ControlOperationLease,
    workshop: Uuid,
    generation: i64,
    projection_digest: String,
    disposition: String,
    instance_owner: Uuid,
    execution_token: Uuid,
    resource_lease_token: Uuid,
    fence_token: i64,
}

struct RecoveryRouteEffectLease {
    effect_run_id: Uuid,
    control_operation: ControlOperationLease,
    workshop: Uuid,
    generation: i64,
    projection_digest: String,
    disposition: String,
    instance_owner: Uuid,
    execution_token: Uuid,
    resource_lease_token: Uuid,
    fence_token: i64,
}

enum RecoveryMaintenanceAdmission {
    Acquired(RecoveryRouteEffectLease, Value),
    Maintenance {
        effect_run_id: Uuid,
        fence_token: i64,
        evidence: Value,
    },
    Replay {
        effect_run_id: Uuid,
        response: Value,
    },
}

enum RecoveryMaintenanceExitClaim {
    Acquired(RecoveryRouteEffectLease, Option<Value>),
    Replay(Value),
}

enum RouteApplicationAdmission {
    Acquired(RouteApplicationLease),
    Replay(Value),
    Superseded(Value),
}

enum ReleaseDriverAdmission {
    Acquired(ReleaseDriverLease),
    ReconcileInitial(InitialReleaseReconciliation),
    ReconcileFleet(FleetReleaseReconciliation),
    Replay(Value),
}

#[tracing::instrument(
    name = "deployment_driver.recovery_route.admit",
    skip_all,
    fields(workshop_id = %workshop, route.effect_run_id = tracing::field::Empty,
        route.admission = tracing::field::Empty)
)]
async fn admit_recovery_maintenance(
    state: &DriverState,
    control_operation: ControlOperationLease,
    workshop: Uuid,
    idempotency_key: &str,
    request_digest: &str,
) -> Result<RecoveryMaintenanceAdmission, DriverError> {
    let execution_token = Uuid::new_v4();
    let resource_lease_token = Uuid::new_v4();
    let row = sqlx::query_as::<
        _,
        (
            String,
            Option<Uuid>,
            Option<i64>,
            Option<Value>,
            Option<Value>,
            Option<i64>,
            Option<String>,
            Option<String>,
            Option<Value>,
        ),
    >(
        "with admitted as (
             select * from control.admit_workshop_route_maintenance(
                 $1,$2,$3,$4,'restore',$5,$6,$7,$8,$9,$10))
         select admitted.outcome,admitted.effect_run_id,admitted.route_fence_token,
                admitted.projection,admitted.stored_response,
                reservation.generation,reservation.projection_digest,reservation.disposition,
                reservation.maintenance_evidence
           from admitted
           left join control.workshop_route_effect_reservations reservation
             on reservation.effect_run_id=admitted.effect_run_id
            and reservation.workshop_id=$4",
    )
    .bind(control_operation.id)
    .bind(control_operation.attempt)
    .bind(&control_operation.owner)
    .bind(workshop)
    .bind(idempotency_key)
    .bind(request_digest)
    .bind(state.instance_id)
    .bind(execution_token)
    .bind(resource_lease_token)
    .bind(RECOVERY_ROUTE_EFFECT_LEASE_SECONDS)
    .fetch_one(&state.ledger)
    .await
    .map_err(DriverError::internal)?;
    tracing::Span::current().record("route.admission", row.0.as_str());
    if let Some(run) = row.1 {
        tracing::Span::current().record("route.effect_run_id", tracing::field::display(run));
    }
    match row.0.as_str() {
        "acquired" => Ok(RecoveryMaintenanceAdmission::Acquired(
            RecoveryRouteEffectLease {
                effect_run_id: row
                    .1
                    .ok_or_else(|| DriverError::internal("recovery route effect run is absent"))?,
                control_operation,
                workshop,
                generation: row
                    .5
                    .ok_or_else(|| DriverError::internal("recovery route generation is absent"))?,
                projection_digest: row
                    .6
                    .ok_or_else(|| DriverError::internal("recovery route digest is absent"))?,
                disposition: row
                    .7
                    .ok_or_else(|| DriverError::internal("recovery route disposition is absent"))?,
                instance_owner: state.instance_id,
                execution_token,
                resource_lease_token,
                fence_token: row
                    .2
                    .ok_or_else(|| DriverError::internal("recovery route fence is absent"))?,
            },
            row.3
                .ok_or_else(|| DriverError::internal("recovery route projection is absent"))?,
        )),
        "maintenance" => Ok(RecoveryMaintenanceAdmission::Maintenance {
            effect_run_id: row
                .1
                .ok_or_else(|| DriverError::internal("maintenance effect run is absent"))?,
            fence_token: row
                .2
                .ok_or_else(|| DriverError::internal("maintenance fence is absent"))?,
            evidence: row
                .8
                .ok_or_else(|| DriverError::internal("maintenance evidence is absent"))?,
        }),
        "replay" => Ok(RecoveryMaintenanceAdmission::Replay {
            effect_run_id: row
                .1
                .ok_or_else(|| DriverError::internal("maintenance replay effect run is absent"))?,
            response: row
                .4
                .ok_or_else(|| DriverError::internal("maintenance replay response is absent"))?,
        }),
        "fleet_busy"
        | "fleet_quarantined"
        | "busy"
        | "uninitialized"
        | "quarantined"
        | "projection_pending"
        | "upstream_lease_lost" => Err(DriverError(
            StatusCode::SERVICE_UNAVAILABLE,
            "recovery route maintenance is not currently admissible".into(),
        )),
        "digest_conflict" => Err(DriverError(
            StatusCode::CONFLICT,
            "recovery maintenance identity conflicts with durable state".into(),
        )),
        _ => Err(DriverError::bad(
            "recovery route maintenance admission was invalid",
        )),
    }
}

async fn begin_recovery_maintenance(
    state: &DriverState,
    lease: &RecoveryRouteEffectLease,
) -> Result<(), DriverError> {
    let begun = sqlx::query_scalar::<_, bool>(
        "select control.begin_workshop_route_maintenance($1,$2,$3,$4,$5)",
    )
    .bind(lease.effect_run_id)
    .bind(lease.instance_owner)
    .bind(lease.execution_token)
    .bind(lease.resource_lease_token)
    .bind(lease.fence_token)
    .fetch_one(&state.ledger)
    .await
    .map_err(DriverError::internal)?;
    if !begun {
        return Err(DriverError::internal(
            "recovery maintenance start was fenced",
        ));
    }
    Ok(())
}

async fn renew_recovery_route_effect(
    state: &DriverState,
    lease: &RecoveryRouteEffectLease,
) -> Result<(), DriverError> {
    let renewed = sqlx::query_scalar::<_, bool>(
        "select control.renew_workshop_route_effect($1,$2,$3,$4,$5,$6,$7,$8,$9)",
    )
    .bind(lease.effect_run_id)
    .bind(lease.control_operation.id)
    .bind(lease.control_operation.attempt)
    .bind(&lease.control_operation.owner)
    .bind(lease.instance_owner)
    .bind(lease.execution_token)
    .bind(lease.resource_lease_token)
    .bind(lease.fence_token)
    .bind(RECOVERY_ROUTE_EFFECT_LEASE_SECONDS)
    .fetch_one(&state.ledger)
    .await
    .map_err(DriverError::internal)?;
    if !renewed {
        return Err(DriverError::internal(
            "recovery route effect lease was lost",
        ));
    }
    Ok(())
}

async fn finish_recovery_maintenance_entry(
    state: &DriverState,
    lease: &RecoveryRouteEffectLease,
    outcome: &str,
    rendered_digest: Option<&str>,
    evidence: Option<&Value>,
) -> Result<(), DriverError> {
    let finished = sqlx::query_scalar::<_, bool>(
        "select control.finish_workshop_route_maintenance_entry($1,$2,$3,$4,$5,$6,$7,$8)",
    )
    .bind(lease.effect_run_id)
    .bind(lease.instance_owner)
    .bind(lease.execution_token)
    .bind(lease.resource_lease_token)
    .bind(lease.fence_token)
    .bind(outcome)
    .bind(rendered_digest)
    .bind(evidence)
    .fetch_one(&state.ledger)
    .await
    .map_err(DriverError::internal)?;
    if !finished {
        return Err(DriverError::internal(
            "recovery maintenance finalization was fenced",
        ));
    }
    Ok(())
}

async fn enter_recovery_route_maintenance(
    state: &DriverState,
    admission: RecoveryMaintenanceAdmission,
) -> Result<Value, DriverError> {
    match admission {
        RecoveryMaintenanceAdmission::Maintenance {
            effect_run_id,
            fence_token,
            evidence,
        } => Ok(json!({
            "outcome":"maintenance",
            "effect_run_id":effect_run_id,
            "route_fence_token":fence_token,
            "route_evidence":evidence,
        })),
        RecoveryMaintenanceAdmission::Replay {
            effect_run_id,
            mut response,
        } => {
            response["outcome"] = json!("restored");
            response["effect_run_id"] = json!(effect_run_id);
            Ok(response)
        }
        RecoveryMaintenanceAdmission::Acquired(lease, projection) => {
            if let Err(error) = begin_recovery_maintenance(state, &lease).await {
                finish_recovery_maintenance_entry(state, &lease, "unknown", None, None).await?;
                return Err(error);
            }
            match apply_recovery_maintenance_entry(state, &lease, &projection).await {
                Ok((rendered_digest, evidence)) => {
                    finish_recovery_maintenance_entry(
                        state,
                        &lease,
                        "maintenance",
                        Some(&rendered_digest),
                        Some(&evidence),
                    )
                    .await?;
                    Ok(json!({
                        "outcome":"maintenance",
                        "effect_run_id":lease.effect_run_id,
                        "route_fence_token":lease.fence_token,
                        "route_evidence":evidence,
                    }))
                }
                Err(error) => {
                    finish_recovery_maintenance_entry(state, &lease, "unknown", None, None).await?;
                    Err(error)
                }
            }
        }
    }
}

async fn claim_recovery_maintenance_exit(
    state: &DriverState,
    control_operation: ControlOperationLease,
    workshop: Uuid,
    effect_run_id: Uuid,
) -> Result<RecoveryMaintenanceExitClaim, DriverError> {
    if let Some(response) = sqlx::query_scalar::<_, Value>(
        "select response from control.workshop_route_effect_runs
          where id=$1 and kind='recovery-maintenance' and workshop_id=$2
            and control_operation_id=$3 and state='succeeded' and response is not null",
    )
    .bind(effect_run_id)
    .bind(workshop)
    .bind(control_operation.id)
    .fetch_optional(&state.ledger)
    .await
    .map_err(DriverError::internal)?
    {
        let mut response = response;
        response["outcome"] = json!("restored");
        response["effect_run_id"] = json!(effect_run_id);
        return Ok(RecoveryMaintenanceExitClaim::Replay(response));
    }
    let execution_token = Uuid::new_v4();
    let resource_lease_token = Uuid::new_v4();
    let row = sqlx::query_as::<
        _,
        (
            String,
            Option<i64>,
            Option<String>,
            Option<Value>,
            Option<i64>,
            Option<String>,
        ),
    >(
        "with claimed as (
             select * from control.claim_workshop_route_maintenance_exit(
                 $1,$2,$3,$4,$5,$6,$7,$8))
         select claimed.outcome,claimed.route_fence_token,claimed.disposition,
                claimed.projection,reservation.generation,reservation.projection_digest
           from claimed
           left join control.workshop_route_effect_reservations reservation
             on reservation.effect_run_id=$1 and reservation.workshop_id=$9",
    )
    .bind(effect_run_id)
    .bind(control_operation.id)
    .bind(control_operation.attempt)
    .bind(&control_operation.owner)
    .bind(state.instance_id)
    .bind(execution_token)
    .bind(resource_lease_token)
    .bind(RECOVERY_ROUTE_EFFECT_LEASE_SECONDS)
    .bind(workshop)
    .fetch_one(&state.ledger)
    .await
    .map_err(DriverError::internal)?;
    match row.0.as_str() {
        "acquired" => Ok(RecoveryMaintenanceExitClaim::Acquired(
            RecoveryRouteEffectLease {
                effect_run_id,
                control_operation,
                workshop,
                generation: row
                    .4
                    .ok_or_else(|| DriverError::internal("recovery exit generation is absent"))?,
                projection_digest: row
                    .5
                    .ok_or_else(|| DriverError::internal("recovery exit digest is absent"))?,
                disposition: row
                    .2
                    .ok_or_else(|| DriverError::internal("recovery exit disposition is absent"))?,
                instance_owner: state.instance_id,
                execution_token,
                resource_lease_token,
                fence_token: row
                    .1
                    .ok_or_else(|| DriverError::internal("recovery exit fence is absent"))?,
            },
            row.3,
        )),
        "fleet_busy" | "upstream_lease_lost" | "projection_missing" => Err(DriverError(
            StatusCode::SERVICE_UNAVAILABLE,
            "recovery maintenance exit is not currently admissible".into(),
        )),
        "not_maintenance" | "authority_lost" => Err(DriverError(
            StatusCode::CONFLICT,
            "recovery maintenance authority is no longer current".into(),
        )),
        _ => Err(DriverError::bad(
            "recovery maintenance exit claim was invalid",
        )),
    }
}

async fn finish_recovery_maintenance_exit(
    state: &DriverState,
    lease: &RecoveryRouteEffectLease,
    outcome: &str,
    rendered_digest: Option<&str>,
    evidence: Option<&Value>,
) -> Result<(), DriverError> {
    let finished = sqlx::query_scalar::<_, bool>(
        "select control.finish_workshop_route_maintenance_exit($1,$2,$3,$4,$5,$6,$7,$8,$9)",
    )
    .bind(lease.effect_run_id)
    .bind(lease.instance_owner)
    .bind(lease.execution_token)
    .bind(lease.resource_lease_token)
    .bind(lease.fence_token)
    .bind(outcome)
    .bind(rendered_digest)
    .bind(evidence)
    .bind(Option::<&str>::None)
    .fetch_one(&state.ledger)
    .await
    .map_err(DriverError::internal)?;
    if !finished {
        return Err(DriverError::internal(
            "recovery maintenance exit finalization was fenced",
        ));
    }
    Ok(())
}

async fn exit_recovery_route_maintenance(
    state: &DriverState,
    control_operation: ControlOperationLease,
    workshop: Uuid,
    payload: &Value,
) -> Result<Value, DriverError> {
    let effect_run_id = payload_uuid(payload, "effect_run_id")?;
    let claim =
        claim_recovery_maintenance_exit(state, control_operation, workshop, effect_run_id).await?;
    let (lease, projection) = match claim {
        RecoveryMaintenanceExitClaim::Replay(response) => return Ok(response),
        RecoveryMaintenanceExitClaim::Acquired(lease, projection) => (lease, projection),
    };
    match apply_recovery_maintenance_exit(state, &lease, projection.as_ref()).await {
        Ok((rendered_digest, evidence)) => {
            finish_recovery_maintenance_exit(
                state,
                &lease,
                "succeeded",
                Some(&rendered_digest),
                Some(&evidence),
            )
            .await?;
            Ok(json!({
                "outcome":"restored",
                "effect_run_id":lease.effect_run_id,
                "route_evidence":evidence,
            }))
        }
        Err(error) => {
            finish_recovery_maintenance_exit(state, &lease, "unknown", None, None).await?;
            Err(error)
        }
    }
}

fn route_projection_contract(
    payload: &Value,
) -> Result<Option<RouteProjectionContract>, DriverError> {
    let generation = payload.get("route_generation");
    let digest = payload.get("route_projection_digest");
    if generation.is_none() && digest.is_none() {
        return Ok(None);
    }
    let generation = generation
        .and_then(Value::as_i64)
        .filter(|value| *value > 0)
        .ok_or_else(|| DriverError::bad("route projection generation is invalid"))?;
    let digest = digest
        .and_then(Value::as_str)
        .filter(|value| {
            value.len() == 71
                && value.starts_with("sha256:")
                && value[7..]
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        })
        .ok_or_else(|| DriverError::bad("route projection digest is invalid"))?;
    let disposition = match payload.get("route_disposition") {
        None => "present",
        Some(Value::String(value)) if matches!(value.as_str(), "present" | "absent") => value,
        _ => return Err(DriverError::bad("route projection disposition is invalid")),
    };
    let mut projection = payload.clone();
    let object = projection
        .as_object_mut()
        .ok_or_else(|| DriverError::bad("route projection must be an object"))?;
    object.remove("route_generation");
    object.remove("route_projection_digest");
    object.remove("route_disposition");
    let canonical = serde_jcs::to_vec(&projection)
        .map_err(|_| DriverError::bad("route projection is not canonicalizable"))?;
    let computed = format!("sha256:{:x}", Sha256::digest(canonical));
    if computed != digest {
        return Err(DriverError(
            StatusCode::CONFLICT,
            "route projection digest does not match its payload".into(),
        ));
    }
    Ok(Some(RouteProjectionContract {
        generation,
        digest: digest.to_owned(),
        disposition: disposition.to_owned(),
    }))
}

fn release_control_operation(headers: &HeaderMap) -> Result<ControlOperationLease, DriverError> {
    let value = |name: &'static str| {
        headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .filter(|value| !value.is_empty() && value.len() <= 200)
            .ok_or_else(|| DriverError::bad("release operation lease headers are required"))
    };
    let id = Uuid::parse_str(value("x-control-operation-id")?)
        .map_err(|_| DriverError::bad("release operation id is invalid"))?;
    let attempt = value("x-control-operation-attempt")?
        .parse::<i32>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| DriverError::bad("release operation attempt is invalid"))?;
    Ok(ControlOperationLease {
        id,
        attempt,
        owner: value("x-control-operation-lease-owner")?.to_owned(),
    })
}

fn optional_control_operation(
    headers: &HeaderMap,
) -> Result<Option<ControlOperationLease>, DriverError> {
    let attempt = headers.get("x-control-operation-attempt");
    let owner = headers.get("x-control-operation-lease-owner");
    if attempt.is_none() && owner.is_none() {
        return Ok(None);
    }
    if attempt.is_none() || owner.is_none() {
        return Err(DriverError::bad(
            "operation attempt and lease owner headers must be supplied together",
        ));
    }
    release_control_operation(headers).map(Some)
}

async fn validate_control_operation_lease(
    ledger: &PgPool,
    workshop: Uuid,
    lease: &ControlOperationLease,
) -> Result<(), DriverError> {
    let current = sqlx::query_scalar::<_, bool>(
        "select exists(
             select 1 from control.operations
              where id=$1 and workshop_id=$2 and state='in_flight'
                and attempt=$3 and leased_by=$4 and lease_expires_at>now()
         )",
    )
    .bind(lease.id)
    .bind(workshop)
    .bind(lease.attempt)
    .bind(&lease.owner)
    .fetch_one(ledger)
    .await
    .map_err(DriverError::internal)?;
    if !current {
        return Err(DriverError(
            StatusCode::SERVICE_UNAVAILABLE,
            "control operation lease is no longer current".into(),
        ));
    }
    Ok(())
}

#[tracing::instrument(
    name = "deployment_driver.release_lease.admit",
    skip_all,
    fields(
        resource = "runtime/shared-odoo",
        release.target = target.class(),
        release.reserved_workshops = tracing::field::Empty,
        lease.outcome = tracing::field::Empty
    )
)]
async fn admit_release_driver_operation(
    state: &DriverState,
    operation: ControlOperationLease,
    idempotency_key: &str,
    target: &ReleaseTarget,
    request_digest: &str,
) -> Result<ReleaseDriverAdmission, DriverError> {
    let execution_token = Uuid::new_v4();
    let resource_lease_token = Uuid::new_v4();
    let row = sqlx::query_as::<
        _,
        (
            String,
            Option<Uuid>,
            Option<i64>,
            Option<Value>,
            Option<Vec<Uuid>>,
        ),
    >(
        "select outcome,driver_operation_id,fence_token,stored_response,reserved_workshops
         from control.admit_release_driver_operation(
            $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",
    )
    .bind(operation.id)
    .bind(operation.attempt)
    .bind(&operation.owner)
    .bind(idempotency_key)
    .bind(target.target_key())
    .bind(target.fleet_run_id())
    .bind(request_digest)
    .bind(state.instance_id)
    .bind(execution_token)
    .bind(resource_lease_token)
    .bind(RELEASE_DRIVER_LEASE_SECONDS)
    .bind(1_i16)
    .fetch_one(&state.ledger)
    .await
    .map_err(DriverError::internal)?;
    tracing::Span::current().record("lease.outcome", row.0.as_str());
    let mut reserved_workshops = row.4.unwrap_or_default();
    reserved_workshops.sort_unstable();
    if reserved_workshops.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(DriverError::internal(
            "release route reservation contains duplicate workshops",
        ));
    }
    tracing::Span::current().record("release.reserved_workshops", reserved_workshops.len());
    match row.0.as_str() {
        "acquired" => {
            if matches!(target, ReleaseTarget::Initial { .. }) && !reserved_workshops.is_empty() {
                return Err(DriverError::internal(
                    "initial release unexpectedly reserved workshop routes",
                ));
            }
            Ok(ReleaseDriverAdmission::Acquired(ReleaseDriverLease {
                driver_operation_id: row
                    .1
                    .ok_or_else(|| DriverError::internal("release lease operation id is absent"))?,
                fleet_run_id: target.fleet_run_id(),
                control_operation: operation,
                instance_owner: state.instance_id,
                execution_token,
                resource_lease_token,
                fence_token: row
                    .2
                    .ok_or_else(|| DriverError::internal("release fence token is absent"))?,
                reserved_workshops,
            }))
        }
        "replay" => Ok(ReleaseDriverAdmission::Replay(row.3.ok_or_else(|| {
            DriverError::internal("release replay response is absent")
        })?)),
        "busy" => Err(DriverError(
            StatusCode::SERVICE_UNAVAILABLE,
            "shared release resource is busy".into(),
        )),
        "route_busy" => Err(DriverError(
            StatusCode::SERVICE_UNAVAILABLE,
            "a workshop route executor is busy".into(),
        )),
        "route_uninitialized" => Err(DriverError(
            StatusCode::SERVICE_UNAVAILABLE,
            "a workshop route is not initialized".into(),
        )),
        "fleet_not_empty" => Err(DriverError(
            StatusCode::CONFLICT,
            "initial release preparation requires an empty fleet".into(),
        )),
        "quarantined" if matches!(target, ReleaseTarget::Initial { .. }) => {
            admit_initial_release_reconciliation(
                state,
                operation,
                idempotency_key,
                target,
                request_digest,
            )
            .await
        }
        "quarantined" if matches!(target, ReleaseTarget::Fleet { .. }) => {
            admit_fleet_release_reconciliation(
                state,
                operation,
                idempotency_key,
                target,
                request_digest,
            )
            .await
        }
        "quarantined" | "route_quarantined" => Err(DriverError(
            StatusCode::SERVICE_UNAVAILABLE,
            "release or workshop route state requires reconciliation".into(),
        )),
        "upstream_lease_lost" => Err(DriverError(
            StatusCode::SERVICE_UNAVAILABLE,
            "release worker lease is no longer current".into(),
        )),
        "digest_conflict" => Err(DriverError(
            StatusCode::CONFLICT,
            "release target or idempotency key was reused with different payload".into(),
        )),
        "failed" => Err(DriverError(
            StatusCode::UNPROCESSABLE_ENTITY,
            "release driver operation previously failed".into(),
        )),
        "invalid_fleet" => Err(DriverError::bad("release fleet snapshot is not admissible")),
        _ => Err(DriverError::bad("release lease admission was invalid")),
    }
}

#[tracing::instrument(
    name = "deployment_driver.release_reconciliation.admit_fleet",
    skip_all,
    fields(
        reconciliation.kind = "fleet_activation_forward",
        reconciliation.outcome = tracing::field::Empty,
        driver_operation_id = tracing::field::Empty
    )
)]
async fn admit_fleet_release_reconciliation(
    state: &DriverState,
    operation: ControlOperationLease,
    idempotency_key: &str,
    target: &ReleaseTarget,
    request_digest: &str,
) -> Result<ReleaseDriverAdmission, DriverError> {
    let fleet_run_id = target
        .fleet_run_id()
        .ok_or_else(|| DriverError::internal("fleet reconciliation target is absent"))?;
    let execution_token = Uuid::new_v4();
    let row = sqlx::query_as::<
        _,
        (
            String,
            Option<Uuid>,
            Option<Uuid>,
            Option<i64>,
            Option<Value>,
            Option<Value>,
        ),
    >(
        "select outcome,reconciliation_id,driver_operation_id,
                original_fence_token,activation_identity,stored_response
         from control.admit_fleet_release_reconciliation(
            $1,$2,$3,$4,$5,$6,$7,$8,$9,600)",
    )
    .bind(operation.id)
    .bind(operation.attempt)
    .bind(&operation.owner)
    .bind(idempotency_key)
    .bind(target.target_key())
    .bind(fleet_run_id)
    .bind(request_digest)
    .bind(state.instance_id)
    .bind(execution_token)
    .fetch_one(&state.ledger)
    .await
    .map_err(DriverError::internal)?;
    tracing::Span::current().record("reconciliation.outcome", row.0.as_str());
    if let Some(driver_operation_id) = row.2 {
        tracing::Span::current().record(
            "driver_operation_id",
            tracing::field::display(driver_operation_id),
        );
    }
    match row.0.as_str() {
        "acquired" => {
            let identity = row.4.ok_or_else(|| {
                DriverError::internal("fleet reconciliation activation identity is absent")
            })?;
            if identity
                .get("release_executor_protocol_version")
                .and_then(Value::as_i64)
                != Some(1)
            {
                return Err(DriverError::internal(
                    "fleet reconciliation executor protocol is invalid",
                ));
            }
            let original_instance_owner = identity
                .get("original_instance_owner")
                .and_then(Value::as_str)
                .and_then(|value| Uuid::parse_str(value).ok())
                .ok_or_else(|| {
                    DriverError::internal("fleet reconciliation original owner is invalid")
                })?;
            let gateway_identity = gateway::ReleaseGatewayGenerationIdentity::new(
                identity
                    .get("fleet_run_id")
                    .and_then(Value::as_str)
                    .and_then(|value| Uuid::parse_str(value).ok())
                    .ok_or_else(|| DriverError::internal("fleet identity run is invalid"))?,
                identity
                    .get("driver_action_id")
                    .and_then(Value::as_str)
                    .and_then(|value| Uuid::parse_str(value).ok())
                    .ok_or_else(|| DriverError::internal("fleet action identity is invalid"))?,
                identity
                    .get("original_driver_fence_token")
                    .and_then(Value::as_i64)
                    .ok_or_else(|| DriverError::internal("fleet fence identity is invalid"))?,
                identity
                    .get("gateway_configuration_digest")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    .ok_or_else(|| DriverError::internal("fleet gateway digest is invalid"))?,
                identity
                    .get("target_slot")
                    .and_then(Value::as_str)
                    .ok_or_else(|| DriverError::internal("fleet target slot is invalid"))?,
            )?;
            if gateway_identity.fleet_run_id != fleet_run_id
                || identity.get("protocol_version").and_then(Value::as_i64) != Some(1)
            {
                return Err(DriverError::internal(
                    "fleet reconciliation activation identity drifted",
                ));
            }
            Ok(ReleaseDriverAdmission::ReconcileFleet(
                FleetReleaseReconciliation {
                    id: row.1.ok_or_else(|| {
                        DriverError::internal("fleet release reconciliation id is absent")
                    })?,
                    driver_operation_id: row.2.ok_or_else(|| {
                        DriverError::internal("reconciled fleet driver operation id is absent")
                    })?,
                    original_fence_token: row.3.ok_or_else(|| {
                        DriverError::internal("reconciled fleet fence token is absent")
                    })?,
                    original_instance_owner,
                    instance_owner: state.instance_id,
                    execution_token,
                    gateway_identity,
                },
            ))
        }
        "replay" => Ok(ReleaseDriverAdmission::Replay(row.5.ok_or_else(|| {
            DriverError::internal("fleet reconciliation replay response is absent")
        })?)),
        "busy" => Err(fleet_reconciliation_inconclusive()),
        "activation_identity_absent"
        | "fleet_state_mismatch"
        | "not_reconcilable"
        | "not_quarantined" => Err(fleet_reconciliation_inconclusive()),
        "upstream_lease_lost" => Err(DriverError(
            StatusCode::SERVICE_UNAVAILABLE,
            "release worker lease is no longer current".into(),
        )),
        "conflict" => Err(DriverError::internal(
            "fleet release reconciliation authority conflicted",
        )),
        _ => Err(DriverError::bad(
            "fleet release reconciliation admission was invalid",
        )),
    }
}

#[tracing::instrument(
    name = "deployment_driver.release_reconciliation.admit",
    skip_all,
    fields(
        reconciliation.kind = "initial_runtime_inspection",
        reconciliation.outcome = tracing::field::Empty,
        driver_operation_id = tracing::field::Empty
    )
)]
async fn admit_initial_release_reconciliation(
    state: &DriverState,
    operation: ControlOperationLease,
    idempotency_key: &str,
    target: &ReleaseTarget,
    request_digest: &str,
) -> Result<ReleaseDriverAdmission, DriverError> {
    let execution_token = Uuid::new_v4();
    let row = sqlx::query_as::<
        _,
        (
            String,
            Option<Uuid>,
            Option<Uuid>,
            Option<i64>,
            Option<Value>,
        ),
    >(
        "select outcome,reconciliation_id,driver_operation_id,
                original_fence_token,stored_evidence
         from control.admit_initial_release_reconciliation(
            $1,$2,$3,$4,$5,$6,$7,$8,120)",
    )
    .bind(operation.id)
    .bind(operation.attempt)
    .bind(&operation.owner)
    .bind(idempotency_key)
    .bind(target.target_key())
    .bind(request_digest)
    .bind(state.instance_id)
    .bind(execution_token)
    .fetch_one(&state.ledger)
    .await
    .map_err(DriverError::internal)?;
    tracing::Span::current().record("reconciliation.outcome", row.0.as_str());
    if let Some(driver_operation_id) = row.2 {
        tracing::Span::current().record(
            "driver_operation_id",
            tracing::field::display(driver_operation_id),
        );
    }
    match row.0.as_str() {
        "acquired" => {
            row.3
                .ok_or_else(|| DriverError::internal("reconciled release fence token is absent"))?;
            Ok(ReleaseDriverAdmission::ReconcileInitial(
                InitialReleaseReconciliation {
                    id: row.1.ok_or_else(|| {
                        DriverError::internal("initial release reconciliation id is absent")
                    })?,
                    driver_operation_id: row.2.ok_or_else(|| {
                        DriverError::internal("reconciled release driver operation id is absent")
                    })?,
                    instance_owner: state.instance_id,
                    execution_token,
                    evidence: row.4.ok_or_else(|| {
                        DriverError::internal("initial release reconciliation evidence is absent")
                    })?,
                },
            ))
        }
        "busy" => Err(DriverError(
            StatusCode::SERVICE_UNAVAILABLE,
            "initial release reconciliation is already being observed".into(),
        )),
        "evidence_absent" | "fleet_not_empty" | "not_reconcilable" | "not_quarantined" => {
            Err(DriverError(
                StatusCode::SERVICE_UNAVAILABLE,
                "release outcome cannot yet be reconciled automatically".into(),
            ))
        }
        "upstream_lease_lost" => Err(DriverError(
            StatusCode::SERVICE_UNAVAILABLE,
            "release worker lease is no longer current".into(),
        )),
        "conflict" => Err(DriverError::internal(
            "initial release reconciliation authority conflicted",
        )),
        _ => Err(DriverError::bad(
            "initial release reconciliation admission was invalid",
        )),
    }
}

#[tracing::instrument(
    name = "deployment_driver.release_reconciliation.finish",
    skip_all,
    fields(
        reconciliation.id = %reconciliation.id,
        driver_operation_id = %reconciliation.driver_operation_id,
        reconciliation.outcome = outcome,
        reconciliation.finished = tracing::field::Empty
    )
)]
async fn finish_initial_release_reconciliation(
    state: &DriverState,
    reconciliation: &InitialReleaseReconciliation,
    outcome: &str,
    response: Option<&Value>,
) -> Result<(), DriverError> {
    let finished = sqlx::query_scalar::<_, bool>(
        "select control.finish_initial_release_reconciliation($1,$2,$3,$4,$5)",
    )
    .bind(reconciliation.id)
    .bind(reconciliation.instance_owner)
    .bind(reconciliation.execution_token)
    .bind(outcome)
    .bind(response)
    .fetch_one(&state.ledger)
    .await
    .map_err(DriverError::internal)?;
    tracing::Span::current().record("reconciliation.finished", finished);
    if !finished {
        return Err(DriverError::internal(
            "initial release reconciliation fence was lost",
        ));
    }
    Ok(())
}

#[tracing::instrument(
    name = "deployment_driver.release_reconciliation.observe_initial",
    skip_all,
    fields(
        reconciliation.id = %reconciliation.id,
        driver_operation_id = %reconciliation.driver_operation_id,
        reconciliation.verified = tracing::field::Empty
    )
)]
async fn reconcile_initial_release(
    state: &DriverState,
    payload: &Value,
    reconciliation: &InitialReleaseReconciliation,
) -> Result<Value, DriverError> {
    let release_id = payload.get("release_id").and_then(Value::as_str);
    let target_slot = reconciliation
        .evidence
        .get("target_slot")
        .and_then(Value::as_str);
    let runtime_container = reconciliation
        .evidence
        .get("runtime_container")
        .and_then(Value::as_str);
    let runtime_deployment_ref = reconciliation
        .evidence
        .get("runtime_deployment_ref")
        .and_then(Value::as_str);
    let runtime_config_digest = reconciliation
        .evidence
        .get("odoo_config_digest")
        .and_then(Value::as_str);
    let extension_volume = reconciliation
        .evidence
        .get("extension_volume")
        .and_then(Value::as_str);
    let expected_container = target_slot
        .filter(|slot| matches!(*slot, "blue" | "green"))
        .map(|slot| state.config.docker_resource(format!("odoo-{slot}")));
    let contract_valid = release_id.is_some()
        && release_id
            == reconciliation
                .evidence
                .get("release_id")
                .and_then(Value::as_str)
        && runtime_container == expected_container.as_deref()
        && runtime_deployment_ref.is_some_and(|value| !value.is_empty())
        && runtime_config_digest.is_some_and(|value| value.starts_with("sha256:"))
        && extension_volume.is_some_and(|value| !value.is_empty());
    let verified = if contract_valid && matches!(state.backend, RuntimeBackend::Docker) {
        match docker_inspect_container(
            state,
            runtime_container.expect("validated reconciliation runtime container"),
        )
        .await
        {
            Ok(inspect) => release::initial_runtime_inspection_matches(
                &inspect,
                runtime_deployment_ref.expect("validated reconciliation runtime image"),
                runtime_config_digest.expect("validated reconciliation config digest"),
                extension_volume.expect("validated reconciliation extension volume"),
            ),
            Err(error) => {
                tracing::warn!(
                    error_class = error.safe_class(),
                    "initial release runtime observation was unavailable"
                );
                false
            }
        }
    } else {
        false
    };
    tracing::Span::current().record("reconciliation.verified", verified);
    if !verified {
        finish_initial_release_reconciliation(state, reconciliation, "inconclusive", None).await?;
        return Err(DriverError(
            StatusCode::SERVICE_UNAVAILABLE,
            "initial release runtime observation was inconclusive".into(),
        ));
    }
    let response = json!({
        "evidence": reconciliation.evidence,
        "observed": true,
        "reconciliation": {
            "id": reconciliation.id,
            "kind": "initial_runtime_inspection",
            "runtime_matches_prepared_slot": true
        }
    });
    finish_initial_release_reconciliation(state, reconciliation, "succeeded", Some(&response))
        .await?;
    Ok(response)
}

#[tracing::instrument(
    name = "deployment_driver.release_lease.renew",
    skip_all,
    fields(
        resource = "runtime/shared-odoo",
        lease.renewed = tracing::field::Empty
    )
)]
async fn renew_release_driver_lease(
    state: &DriverState,
    lease: &ReleaseDriverLease,
) -> Result<(), DriverError> {
    let renewed = sqlx::query_scalar::<_, bool>(
        "select control.renew_release_driver_lease($1,$2,$3,$4,$5,$6,$7,$8,$9)",
    )
    .bind(lease.driver_operation_id)
    .bind(lease.control_operation.id)
    .bind(lease.control_operation.attempt)
    .bind(&lease.control_operation.owner)
    .bind(lease.instance_owner)
    .bind(lease.execution_token)
    .bind(lease.resource_lease_token)
    .bind(lease.fence_token)
    .bind(RELEASE_DRIVER_LEASE_SECONDS)
    .fetch_one(&state.ledger)
    .await
    .map_err(DriverError::internal)?;
    tracing::Span::current().record("lease.renewed", renewed);
    if !renewed {
        return Err(DriverError::internal("release driver lease was lost"));
    }
    Ok(())
}

/// Run one release effect while its exact database lease remains renewable.
///
/// This is structured concurrency rather than a detached task: completing the
/// effect drops the heartbeat before durable finalization, while heartbeat
/// failure drops the effect future so it cannot advance to another unfenced
/// phase. The caller then records the already-conservative unknown outcome and
/// quarantines the shared runtime authority.
async fn with_release_driver_heartbeat<T>(
    effect: impl Future<Output = Result<T, DriverError>>,
    heartbeat: impl Future<Output = DriverError>,
) -> Result<T, DriverError> {
    tokio::pin!(effect);
    tokio::pin!(heartbeat);
    tokio::select! {
        biased;
        error = &mut heartbeat => Err(error),
        result = &mut effect => result,
    }
}

#[tracing::instrument(
    name = "deployment_driver.release_lease.heartbeat",
    skip_all,
    fields(
        resource = "runtime/shared-odoo",
        driver_operation_id = %lease.driver_operation_id,
        heartbeat.interval_seconds = RELEASE_DRIVER_HEARTBEAT_INTERVAL.as_secs()
    )
)]
async fn monitor_release_driver_lease(
    state: &DriverState,
    lease: &ReleaseDriverLease,
) -> DriverError {
    let mut interval = tokio::time::interval(RELEASE_DRIVER_HEARTBEAT_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Tokio intervals tick immediately once. Admission and the post-lock check
    // already renewed the lease, so consume that tick before waiting a full
    // heartbeat period.
    interval.tick().await;
    loop {
        interval.tick().await;
        let renewal = tokio::time::timeout(
            RELEASE_DRIVER_HEARTBEAT_TIMEOUT,
            renew_release_driver_lease(state, lease),
        )
        .await;
        let error = match renewal {
            Ok(Ok(())) => continue,
            Ok(Err(error)) => error,
            Err(_) => DriverError::internal("release driver lease renewal timed out"),
        };
        {
            tracing::error!(
                error_class = "release_driver_lease_lost",
                "release execution cancelled after its lease heartbeat failed"
            );
            return error;
        }
    }
}

#[tracing::instrument(
    name = "deployment_driver.release_lease.finish",
    skip_all,
    fields(
        resource = "runtime/shared-odoo",
        lease.outcome = outcome,
        lease.finished = tracing::field::Empty
    )
)]
async fn finish_release_driver_operation(
    state: &DriverState,
    lease: &ReleaseDriverLease,
    outcome: &str,
    response: Option<&Value>,
    safe_error: Option<&str>,
) -> Result<(), DriverError> {
    let finished = sqlx::query_scalar::<_, bool>(
        "select control.finish_release_driver_operation($1,$2,$3,$4,$5,$6,$7,$8)",
    )
    .bind(lease.driver_operation_id)
    .bind(lease.instance_owner)
    .bind(lease.execution_token)
    .bind(lease.resource_lease_token)
    .bind(lease.fence_token)
    .bind(outcome)
    .bind(response)
    .bind(safe_error)
    .fetch_one(&state.ledger)
    .await
    .map_err(DriverError::internal)?;
    tracing::Span::current().record("lease.finished", finished);
    if !finished {
        return Err(DriverError::internal(
            "release driver lease finalization was fenced",
        ));
    }
    Ok(())
}

#[tracing::instrument(
    name = "deployment_driver.route_projection.admit",
    skip_all,
    fields(
        workshop_id = %workshop,
        route_generation = projection.generation,
        route.admission = tracing::field::Empty
    )
)]
async fn admit_route_application(
    state: &DriverState,
    control_operation: ControlOperationLease,
    workshop: Uuid,
    action: &str,
    idempotency_key: &str,
    request_digest: &str,
    projection: &RouteProjectionContract,
) -> Result<RouteApplicationAdmission, DriverError> {
    let stored_disposition = sqlx::query_scalar::<_, String>(
        "select disposition
           from control.read_workshop_route_projection_disposition($1,$2,$3)",
    )
    .bind(workshop)
    .bind(projection.generation)
    .bind(&projection.digest)
    .fetch_optional(&state.ledger)
    .await
    .map_err(DriverError::internal)?
    .ok_or_else(|| {
        DriverError(
            StatusCode::CONFLICT,
            "route projection is not durably materialized".into(),
        )
    })?;
    if stored_disposition != projection.disposition {
        return Err(DriverError(
            StatusCode::CONFLICT,
            "route projection disposition conflicts with durable state".into(),
        ));
    }
    let execution_token = Uuid::new_v4();
    let resource_lease_token = Uuid::new_v4();
    let row = sqlx::query_as::<_, (String, Option<Uuid>, Option<i64>, Option<Value>)>(
        "select outcome,driver_operation_id,fence_token,stored_response
           from control.admit_workshop_route_application(
             $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
    )
    .bind(control_operation.id)
    .bind(control_operation.attempt)
    .bind(&control_operation.owner)
    .bind(workshop)
    .bind(action)
    .bind(idempotency_key)
    .bind(request_digest)
    .bind(projection.generation)
    .bind(&projection.digest)
    .bind(state.instance_id)
    .bind(execution_token)
    .bind(resource_lease_token)
    .bind(ROUTE_APPLICATION_LEASE_SECONDS)
    .fetch_one(&state.ledger)
    .await
    .map_err(DriverError::internal)?;
    tracing::Span::current().record("route.admission", row.0.as_str());
    match row.0.as_str() {
        "acquired" => Ok(RouteApplicationAdmission::Acquired(RouteApplicationLease {
            driver_operation_id: row
                .1
                .ok_or_else(|| DriverError::internal("route application operation id is absent"))?,
            control_operation,
            workshop,
            generation: projection.generation,
            projection_digest: projection.digest.clone(),
            disposition: projection.disposition.clone(),
            instance_owner: state.instance_id,
            execution_token,
            resource_lease_token,
            fence_token: row
                .2
                .ok_or_else(|| DriverError::internal("route application fence token is absent"))?,
        })),
        "replay" => {
            let mut response = row.3.ok_or_else(|| {
                DriverError::internal("route application replay response is absent")
            })?;
            let evidence = response
                .get_mut("route_evidence")
                .and_then(Value::as_object_mut)
                .ok_or_else(|| {
                    DriverError::internal("route application replay evidence is absent")
                })?;
            match evidence.get("disposition").and_then(Value::as_str) {
                Some(value) if value == projection.disposition => {}
                None => {
                    evidence.insert(
                        "disposition".into(),
                        Value::String(projection.disposition.clone()),
                    );
                }
                Some(_) => {
                    return Err(DriverError::internal(
                        "route application replay disposition drifted",
                    ));
                }
            }
            Ok(RouteApplicationAdmission::Replay(response))
        }
        "superseded" => {
            let mut response = row.3.unwrap_or_else(|| json!({}));
            response["outcome"] = json!("superseded");
            Ok(RouteApplicationAdmission::Superseded(response))
        }
        "busy"
        | "fleet_busy"
        | "fleet_quarantined"
        | "quarantined"
        | "upstream_lease_lost"
        | "uninitialized"
        | "legacy_receipt" => Err(DriverError(
            StatusCode::SERVICE_UNAVAILABLE,
            "route application is not currently admissible".into(),
        )),
        "digest_conflict" | "unreserved" => Err(DriverError(
            StatusCode::CONFLICT,
            "route projection identity conflicts with durable state".into(),
        )),
        "failed" => Err(DriverError(
            StatusCode::UNPROCESSABLE_ENTITY,
            "route application previously failed".into(),
        )),
        _ => Err(DriverError::bad("route application admission was invalid")),
    }
}

#[tracing::instrument(
    name = "deployment_driver.route_projection.renew",
    skip_all,
    fields(
        workshop_id = %lease.workshop,
        route_generation = lease.generation,
        route.renewed = tracing::field::Empty
    )
)]
async fn renew_route_application(
    state: &DriverState,
    lease: &RouteApplicationLease,
) -> Result<(), DriverError> {
    let renewed = sqlx::query_scalar::<_, bool>(
        "select control.renew_workshop_route_application(
            $1,$2,$3,$4,$5,$6,$7,$8,$9)",
    )
    .bind(lease.driver_operation_id)
    .bind(lease.control_operation.id)
    .bind(lease.control_operation.attempt)
    .bind(&lease.control_operation.owner)
    .bind(lease.instance_owner)
    .bind(lease.execution_token)
    .bind(lease.resource_lease_token)
    .bind(lease.fence_token)
    .bind(ROUTE_APPLICATION_LEASE_SECONDS)
    .fetch_one(&state.ledger)
    .await
    .map_err(DriverError::internal)?;
    tracing::Span::current().record("route.renewed", renewed);
    if !renewed {
        return Err(DriverError::internal("route application lease was lost"));
    }
    Ok(())
}

#[tracing::instrument(
    name = "deployment_driver.route_projection.finish",
    skip_all,
    fields(
        workshop_id = %lease.workshop,
        route_generation = lease.generation,
        route.outcome = outcome,
        route.finished = tracing::field::Empty
    )
)]
async fn finish_route_application(
    state: &DriverState,
    lease: &RouteApplicationLease,
    outcome: &str,
    response: Option<&Value>,
    rendered_digest: Option<&str>,
    safe_error: Option<&str>,
) -> Result<(), DriverError> {
    let finished = sqlx::query_scalar::<_, bool>(
        "select control.finish_workshop_route_application(
            $1,$2,$3,$4,$5,$6,$7,$8,$9)",
    )
    .bind(lease.driver_operation_id)
    .bind(lease.instance_owner)
    .bind(lease.execution_token)
    .bind(lease.resource_lease_token)
    .bind(lease.fence_token)
    .bind(outcome)
    .bind(response)
    .bind(rendered_digest)
    .bind(safe_error)
    .fetch_one(&state.ledger)
    .await
    .map_err(DriverError::internal)?;
    tracing::Span::current().record("route.finished", finished);
    if !finished {
        return Err(DriverError::internal(
            "route application finalization was fenced",
        ));
    }
    Ok(())
}

#[tracing::instrument(
    name = "deployment_driver.operation.admit",
    skip_all,
    fields(driver_action = action, driver_scope = if workshop.is_some() { "tenant" } else { "fleet" })
)]
async fn admit_driver_operation(
    ledger: &PgPool,
    workshop: Option<Uuid>,
    action: &str,
    idempotency_key: &str,
    request_digest: &str,
) -> Result<DriverOperationAdmission, DriverError> {
    let inserted = sqlx::query(
        "insert into control.deployment_driver_operations(
             idempotency_key,workshop_id,action,request_digest)
         values($1,$2,$3,$4)
         on conflict on constraint deployment_driver_operations_scope_key do nothing",
    )
    .bind(idempotency_key)
    .bind(workshop)
    .bind(action)
    .bind(request_digest)
    .execute(ledger)
    .await
    .map_err(DriverError::internal)?
    .rows_affected();
    if inserted == 1 {
        return Ok(DriverOperationAdmission::New);
    }
    let row = sqlx::query(
        "select request_digest,state,response,safe_error
           from control.deployment_driver_operations
          where workshop_id is not distinct from $1
            and action=$2 and idempotency_key=$3",
    )
    .bind(workshop)
    .bind(action)
    .bind(idempotency_key)
    .fetch_one(ledger)
    .await
    .map_err(DriverError::internal)?;
    if row.get::<String, _>("request_digest") != request_digest {
        return Err(DriverError(
            StatusCode::CONFLICT,
            "idempotency key reused with different payload".into(),
        ));
    }
    match row.get::<String, _>("state").as_str() {
        "succeeded" => Ok(DriverOperationAdmission::Replay(row.get("response"))),
        "in_progress" => {
            let unknown = row.get::<Option<String>, _>("safe_error").as_deref()
                == Some("runtime_outcome_unknown");
            Err(DriverError(
                if unknown {
                    StatusCode::SERVICE_UNAVAILABLE
                } else {
                    StatusCode::CONFLICT
                },
                if unknown {
                    "operation outcome requires reconciliation before retry"
                } else {
                    "operation is already in progress"
                }
                .into(),
            ))
        }
        _ => Err(DriverError(
            StatusCode::UNPROCESSABLE_ENTITY,
            "idempotent operation previously failed".into(),
        )),
    }
}

#[tracing::instrument(
    name = "deployment_driver.operation.finish",
    skip_all,
    fields(driver_action = action, driver_scope = if workshop.is_some() { "tenant" } else { "fleet" }, driver_outcome = state)
)]
async fn finish_driver_operation(
    ledger: &PgPool,
    workshop: Option<Uuid>,
    action: &str,
    idempotency_key: &str,
    state: &str,
    response: Option<&Value>,
    safe_error: Option<&str>,
) -> Result<(), DriverError> {
    let changed = sqlx::query(
        "update control.deployment_driver_operations
            set state=$4,response=$5,safe_error=$6,updated_at=now()
          where workshop_id is not distinct from $1
            and action=$2 and idempotency_key=$3 and state='in_progress'",
    )
    .bind(workshop)
    .bind(action)
    .bind(idempotency_key)
    .bind(state)
    .bind(response)
    .bind(safe_error)
    .execute(ledger)
    .await
    .map_err(DriverError::internal)?
    .rows_affected();
    if changed != 1 {
        return Err(DriverError::internal(
            "deployment driver operation scope was lost",
        ));
    }
    Ok(())
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
            | "erasure"
            | "restrict"
            | "carrier-secret"
            | "carrier-secret-delete"
            | "route-project"
            | "route-maintenance-enter"
            | "route-maintenance-exit"
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
    let tenant_control_operation = if action == "release" {
        None
    } else {
        optional_control_operation(&headers)?
    };
    if let Some(lease) = &tenant_control_operation {
        validate_control_operation_lease(&state.ledger, workshop, lease).await?;
    }
    // This host-wide guard is acquired before release database admission and
    // held through the exact driver receipt transition below. Its async wait
    // owns no database transaction, and admission revalidates the upstream
    // operation lease after the wait.
    let _shared_odoo_host_guard = if action == "release" {
        Some(
            host_guard::SharedOdooHostGuard::acquire(&state.config.route_root)
                .await
                .map_err(DriverError::internal)?,
        )
    } else {
        None
    };
    let operation_workshop = (action != "release").then_some(workshop);
    let route_lease = if action == "route-project" {
        let control_operation = tenant_control_operation
            .clone()
            .ok_or_else(|| DriverError::bad("route projection lease headers are required"))?;
        let projection = route_projection_contract(&payload)?
            .ok_or_else(|| DriverError::bad("route projection authority is required"))?;
        match admit_route_application(
            &state,
            control_operation,
            workshop,
            &action,
            idempotency_key,
            &digest,
            &projection,
        )
        .await?
        {
            RouteApplicationAdmission::Acquired(lease) => Some(lease),
            RouteApplicationAdmission::Replay(response)
            | RouteApplicationAdmission::Superseded(response) => return Ok(Json(response)),
        }
    } else {
        None
    };
    let recovery_maintenance_admission = if action == "route-maintenance-enter" {
        let control_operation = tenant_control_operation
            .clone()
            .ok_or_else(|| DriverError::bad("recovery maintenance lease headers are required"))?;
        Some(
            admit_recovery_maintenance(
                &state,
                control_operation,
                workshop,
                idempotency_key,
                &digest,
            )
            .await?,
        )
    } else {
        None
    };
    let (release_lease, initial_release_reconciliation, fleet_release_reconciliation) =
        if action == "release" {
            let control_operation = release_control_operation(&headers)?;
            let target = ReleaseTarget::from_payload(&payload)?;
            match admit_release_driver_operation(
                &state,
                control_operation,
                idempotency_key,
                &target,
                &digest,
            )
            .await?
            {
                ReleaseDriverAdmission::Acquired(lease) => (Some(lease), None, None),
                ReleaseDriverAdmission::ReconcileInitial(reconciliation) => {
                    (None, Some(reconciliation), None)
                }
                ReleaseDriverAdmission::ReconcileFleet(reconciliation) => {
                    (None, None, Some(reconciliation))
                }
                ReleaseDriverAdmission::Replay(response) => return Ok(Json(response)),
            }
        } else if !matches!(
            action.as_str(),
            "route-project" | "route-maintenance-enter" | "route-maintenance-exit"
        ) {
            if let DriverOperationAdmission::Replay(response) = admit_driver_operation(
                &state.ledger,
                operation_workshop,
                &action,
                idempotency_key,
                &digest,
            )
            .await?
            {
                return Ok(Json(response));
            }
            (None, None, None)
        } else {
            (None, None, None)
        };
    let lock_key = if action == "release" {
        "runtime/shared-odoo".to_owned()
    } else {
        format!("workshop/{workshop}")
    };
    let resource_lock = {
        let mut locks = state
            .resource_locks
            .lock()
            .map_err(|_| DriverError::internal("resource lock registry is poisoned"))?;
        locks
            .entry(lock_key)
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    };
    let _guard = resource_lock.lock().await;
    if let Some(reconciliation) = &initial_release_reconciliation {
        return reconcile_initial_release(&state, &payload, reconciliation)
            .await
            .map(Json);
    }
    if let Some(reconciliation) = &fleet_release_reconciliation {
        return fleet_reconciliation::reconcile_fleet_release(&state, &payload, reconciliation)
            .await
            .map(Json);
    }
    if let Some(lease) = &release_lease {
        renew_release_driver_lease(&state, lease).await?;
    }
    if let Some(lease) = &route_lease {
        renew_route_application(&state, lease).await?;
    }
    if let Some(lease) = &tenant_control_operation {
        // The request may have waited behind another operation after its first
        // admission check. Fence it again immediately before runtime effects.
        if let Err(error) = validate_control_operation_lease(&state.ledger, workshop, lease).await {
            if let Some(route_lease) = &route_lease {
                finish_route_application(
                    &state,
                    route_lease,
                    "failed",
                    None,
                    None,
                    Some("control_operation_lease_lost"),
                )
                .await?;
            } else if let Some(RecoveryMaintenanceAdmission::Acquired(route_lease, _)) =
                &recovery_maintenance_admission
            {
                finish_recovery_maintenance_entry(&state, route_lease, "unknown", None, None)
                    .await?;
            } else if recovery_maintenance_admission.is_none() {
                finish_driver_operation(
                    &state.ledger,
                    operation_workshop,
                    &action,
                    idempotency_key,
                    "failed",
                    None,
                    Some("control_operation_lease_lost"),
                )
                .await?;
            }
            return Err(error);
        }
    }
    if let Some(admission) = recovery_maintenance_admission {
        return enter_recovery_route_maintenance(&state, admission)
            .await
            .map(Json);
    }
    if action == "route-maintenance-exit" {
        let control_operation = tenant_control_operation
            .clone()
            .ok_or_else(|| DriverError::bad("recovery maintenance lease headers are required"))?;
        return exit_recovery_route_maintenance(&state, control_operation, workshop, &payload)
            .await
            .map(Json);
    }
    let result = match action.as_str() {
        "provision" | "reconcile" => provision(&state, workshop, &payload).await,
        "lifecycle" => lifecycle(&state, workshop, &payload).await,
        "rehearse" => rehearse(&state, workshop, &payload).await,
        "release" => {
            let lease = release_lease
                .as_ref()
                .expect("release action has an admitted database lease");
            with_release_driver_heartbeat(
                release::release_fleet(&state, &payload, lease),
                monitor_release_driver_lease(&state, lease),
            )
            .await
        }
        "erasure" => apply_restored_erasure(&state, workshop, &payload).await,
        "restrict" => restrict_capability(&state, workshop, &payload).await,
        "carrier-secret" => write_carrier_secret(&state, workshop, &payload),
        "carrier-secret-delete" => delete_carrier_secret(&state, workshop, &payload),
        "route-project" => {
            apply_route_projection(
                &state,
                workshop,
                &payload,
                route_lease
                    .as_ref()
                    .expect("route projection has an admitted database lease"),
            )
            .await
        }
        _ => unreachable!(),
    };
    match result {
        Ok(value) => {
            if let Some(lease) = &route_lease {
                let rendered_digest = value
                    .get("route_evidence")
                    .and_then(|evidence| evidence.get("rendered_digest"))
                    .and_then(Value::as_str)
                    .ok_or_else(|| DriverError::internal("route evidence digest is absent"))?;
                finish_route_application(
                    &state,
                    lease,
                    "succeeded",
                    Some(&value),
                    Some(rendered_digest),
                    None,
                )
                .await?;
            } else if let Some(lease) = &release_lease {
                finish_release_driver_operation(&state, lease, "succeeded", Some(&value), None)
                    .await?;
            } else {
                finish_driver_operation(
                    &state.ledger,
                    operation_workshop,
                    &action,
                    idempotency_key,
                    "succeeded",
                    Some(&value),
                    None,
                )
                .await?;
            }
            Ok(Json(value))
        }
        Err(error) => {
            if let Some(lease) = &route_lease {
                if error.0.is_client_error() {
                    finish_route_application(
                        &state,
                        lease,
                        "failed",
                        None,
                        None,
                        Some("request_rejected"),
                    )
                    .await?;
                } else {
                    finish_route_application(&state, lease, "unknown", None, None, None).await?;
                }
            } else if let Some(lease) = &release_lease {
                // Once release dispatch owns the shared-runtime lease, an HTTP
                // status class cannot prove that no runtime, database, route,
                // or maintenance effect occurred. Keep the global authority
                // quarantined until authoritative reconciliation.
                finish_release_driver_operation(
                    &state,
                    lease,
                    "unknown",
                    None,
                    Some("runtime_outcome_unknown"),
                )
                .await?;
            } else if error.0.is_client_error() {
                finish_driver_operation(
                    &state.ledger,
                    operation_workshop,
                    &action,
                    idempotency_key,
                    "failed",
                    None,
                    Some("request_rejected"),
                )
                .await?;
            } else {
                // A transport failure may have happened after the host effect.
                // Keep the durable operation reconcilable instead of converting
                // an ambiguous outcome into a blind ordinary retry.
                finish_driver_operation(
                    &state.ledger,
                    operation_workshop,
                    &action,
                    idempotency_key,
                    "in_progress",
                    None,
                    Some("runtime_outcome_unknown"),
                )
                .await?;
            }
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
    let database_id = payload_uuid(payload, "database_id")?;
    let database_ref =
        database_ref(WorkshopRecoveryLedger::new(state, workshop), database_id).await?;
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
    let odoo_runtime = driver_runtime_secret_root(state)
        .join("odoo")
        .join(workshop.to_string());
    secure_directory(&odoo_runtime).map_err(DriverError::internal)?;
    let _odoo_admin =
        secret_value(&odoo_runtime.join("admin-password"), 64).map_err(DriverError::internal)?;
    ensure_database(&state.postgres, &database_ref, "odoo", None).await?;
    let (odoo_client_id, paperless_oidc) =
        ensure_oidc_clients(state, &compact, odoo_hostname, paperless_hostname).await?;
    ensure_odoo_database(state, &database_ref, &compact).await?;
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
    if state.config.backend == DriverBackendKind::Docker {
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
    }
    // A newly created database has no tenant verifier yet, so its one initial
    // bootstrap is authenticated by the process bootstrap credential. On
    // retries the persisted tenant credential is used directly; an
    // Unauthorized response is never retried with the shared credential.
    let bootstrap_token = if tenant_credential_created {
        &state.config.odoo_bridge_token
    } else {
        &tenant_bridge_token
    };
    let odoo_runtime_url = active_odoo_runtime_url(state).await?;
    let bootstrap_client = OdooClient::new(
        &odoo_runtime_url,
        bootstrap_token,
        Some(&database_ref),
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
    ensure_odoo_break_glass(state, workshop, &database_ref, &compact).await?;
    let mut response = json!({
        "workshop_id": workshop,
        "action": "provision",
        "release_id": release_id,
        "odoo": {
            "base_url": odoo_runtime_url,
            "secret_ref": format!("docker/{workshop}/odoo"),
            "break_glass_secret_ref": format!("driver-runtime/odoo/{workshop}/admin-password"),
            "database": {"database_ref": database_ref, "public_hostname": odoo_hostname}
        },
        "odoo_oidc": {"client_id": odoo_client_id, "issuer": state.config.oidc_issuer},
    });

    if let (Some(paperless_hostname), Some((paperless_client_id, paperless_oidc_secret))) =
        (paperless_hostname, paperless_oidc)
    {
        let paperless_database = format!("pl_{compact}");
        let paperless_role = paperless_database.clone();
        let paperless_container = state.config.docker_resource(format!("paperless-{compact}"));
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
        let paperless_db_password = secret_value(&paperless_runtime.join("database-password"), 64)
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
            &state.config.redis_admin_address,
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
        response["redis"] = json!({"shared": true, "prefix": redis_prefix, "acl_user": redis_user});
    }
    Ok(response)
}

async fn apply_route_projection(
    state: &DriverState,
    workshop: Uuid,
    payload: &Value,
    lease: &RouteApplicationLease,
) -> Result<Value, DriverError> {
    let contract = route_projection_contract(payload)?
        .ok_or_else(|| DriverError::bad("route projection authority is required"))?;
    if contract.generation != lease.generation || contract.digest != lease.projection_digest {
        return Err(DriverError(
            StatusCode::CONFLICT,
            "route projection lease does not match the request".into(),
        ));
    }
    if contract.disposition != lease.disposition {
        return Err(DriverError(
            StatusCode::CONFLICT,
            "route projection disposition does not match the lease".into(),
        ));
    }
    if lease.workshop != workshop {
        return Err(DriverError(
            StatusCode::CONFLICT,
            "route projection lease belongs to another workshop".into(),
        ));
    }
    let rendered_digest = if lease.disposition == "absent" {
        let expected = json!({
            "database_id":null,
            "database_ref":null,
            "public_hostname":null,
            "paperless_mode":"absent",
            "paperless_hostname":null,
            "custom_hostnames":[],
            "route_generation":lease.generation,
            "route_projection_digest":lease.projection_digest,
            "route_disposition":"absent",
        });
        if payload != &expected {
            return Err(DriverError(
                StatusCode::CONFLICT,
                "absent route projection payload is invalid".into(),
            ));
        }
        apply_fenced_route_absence(state, workshop, lease).await?
    } else {
        let database_id = payload_uuid(payload, "database_id")?;
        let database_ref =
            database_ref(WorkshopRecoveryLedger::new(state, workshop), database_id).await?;
        if payload.get("database_ref").and_then(Value::as_str) != Some(database_ref.as_str()) {
            return Err(DriverError(
                StatusCode::CONFLICT,
                "route projection database identity drifted".into(),
            ));
        }
        let public_hostname = hostname(payload, "public_hostname")?;
        let custom_hostnames = custom_hostname_routes(payload)?;
        let paperless_mode = payload
            .get("paperless_mode")
            .and_then(Value::as_str)
            .ok_or_else(|| DriverError::bad("paperless route mode is required"))?;
        let paperless_hostname = match paperless_mode {
            "absent"
                if payload
                    .get("paperless_hostname")
                    .is_some_and(Value::is_null) =>
            {
                None
            }
            "read_write" | "read_only" => Some(hostname(payload, "paperless_hostname")?),
            _ => return Err(DriverError::bad("paperless route mode is invalid")),
        };
        let paperless_container = paperless_hostname.as_ref().map(|_| {
            state
                .config
                .docker_resource(format!("paperless-{}", tenant_key(workshop)))
        });
        apply_fenced_routes(
            state,
            workshop,
            RouteRenderSpec {
                database_ref: &database_ref,
                odoo_hostname: public_hostname,
                paperless: paperless_hostname.zip(paperless_container.as_deref()),
                paperless_read_only: paperless_mode == "read_only",
                custom_hostnames: &custom_hostnames,
            },
            lease,
        )
        .await?
    };
    Ok(json!({
        "outcome":"applied",
        "workshop_id":workshop,
        "route_evidence":{
            "workshop_id":workshop,
            "route_generation":lease.generation,
            "projection_digest":lease.projection_digest,
            "disposition":lease.disposition,
            "rendered_digest":rendered_digest,
            "driver_operation_id":lease.driver_operation_id,
            "route_fence_token":lease.fence_token
        }
    }))
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

fn write_protected_configuration(path: &Path, value: &str) -> std::io::Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    if value.is_empty() || value.len() > 65_536 || value.contains('\0') || !value.ends_with('\n') {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "configuration must be bounded UTF-8 text",
        ));
    }
    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::other("configuration path has no parent"))?;
    if path.exists() {
        let metadata = std::fs::symlink_metadata(path)?;
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            return Err(std::io::Error::other(
                "configuration target is not a regular file",
            ));
        }
        if std::fs::read_to_string(path)? == value {
            return Ok(());
        }
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "populated runtime configuration cannot be overwritten",
        ));
    }
    let temporary = parent.join(format!(".odoo-config-{}.tmp", Uuid::new_v4()));
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o640)
            .open(&temporary)?;
        std::io::Write::write_all(&mut file, value.as_bytes())?;
        file.sync_all()?;
        // Docker jobs run as the image's unprivileged user and are explicitly
        // added to group 0.  Keep the configuration private to root and that
        // group, matching the other ephemeral job-secret files.
        std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o640))?;
        std::fs::rename(&temporary, path)?;
        std::fs::File::open(parent)?.sync_all()
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
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

fn validate_retained_job_secrets(root: &Path) -> std::io::Result<()> {
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

async fn active_odoo_runtime_url(state: &DriverState) -> Result<String, DriverError> {
    if state.config.backend == DriverBackendKind::Docker {
        return Ok(state.config.odoo_base_url.clone());
    }
    let slots = sqlx::query_scalar::<_, String>(
        "select slot from control.runtime_release_slots
          where runtime_key='shared-odoo' and state='active' order by slot",
    )
    .fetch_all(&state.ledger)
    .await
    .map_err(DriverError::internal)?;
    match slots.as_slice() {
        [slot] if slot == "blue" => Ok("http://127.0.0.1:18069".into()),
        [slot] if slot == "green" => Ok("http://127.0.0.1:18070".into()),
        [] => Err(DriverError::internal("no active Odoo runtime is available")),
        _ => Err(DriverError::internal("Odoo runtime selection is ambiguous")),
    }
}

async fn active_odoo_runtime_container(state: &DriverState) -> Result<String, DriverError> {
    let slots = sqlx::query_scalar::<_, String>(
        "select slot from control.runtime_release_slots
          where runtime_key='shared-odoo' and state='active' order by slot",
    )
    .fetch_all(&state.ledger)
    .await
    .map_err(DriverError::internal)?;
    match slots.as_slice() {
        [slot] if matches!(slot.as_str(), "blue" | "green") => {
            Ok(state.config.docker_resource(format!("odoo-{slot}")))
        }
        [] => url::Url::parse(&state.config.odoo_base_url)
            .ok()
            .and_then(|url| url.host_str().map(str::to_owned))
            .filter(|host| !host.is_empty())
            .ok_or_else(|| DriverError::internal("configured Odoo runtime has no route host")),
        _ => Err(DriverError::internal(
            "Odoo runtime container selection is ambiguous",
        )),
    }
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
    backend: DriverBackendKind,
    source: &str,
    relative: &Path,
    target: &str,
) -> Result<Value, DriverError> {
    let relative = validated_secret_relative_path(relative)?;
    Ok(match backend {
        DriverBackendKind::Docker => json!({
            "Type":"volume",
            "Source":source,
            "Target":target,
            "ReadOnly":true,
            "VolumeOptions":{"Subpath":relative}
        }),
        DriverBackendKind::Quadlet => json!({
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
        state.config.backend,
        &state.config.runtime_secret_source,
        &Path::new("runtime").join(relative),
        target,
    )
}

fn job_secret_mount(state: &DriverState, job: &str, target: &str) -> Result<Value, DriverError> {
    secret_mount_payload(
        state.config.backend,
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
        "Target":"/run/mb-postgres-ca/postgres-ca.crt",
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
    if let RuntimeBackend::Quadlet(backend) = &state.backend {
        return backend.run_job(container, &body).await;
    }
    if docker_container_exists(state, container).await? {
        docker_delete_container(state, container).await?;
    }
    docker_create_container(state, container, DockerRestartPolicy::No, body).await?;
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
            if !valid_job_secret_name(name) {
                return Err(DriverError::internal("invalid job-secret name"));
            }
            write_job_secret(&directory, name, value).map_err(DriverError::internal)?;
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
            .push(job_secret_mount(state, &job, "/run/mb-job-secrets")?);
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
            environment.push(json!("PGSSLROOTCERT=/run/mb-postgres-ca/postgres-ca.crt"));
        }
        run_docker_job(state, container, body).await
    }
    .await;
    if let RuntimeBackend::Quadlet(backend) = &state.backend
        && backend.job_active(container).await.unwrap_or(true)
    {
        return result.and(Err(DriverError::internal(
            "runtime job secrets retained while its terminal state is unknown",
        )));
    }
    let cleanup = std::fs::remove_dir_all(&directory).map_err(DriverError::internal);
    match (result, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (_, Err(error)) => Err(error),
    }
}

fn write_job_secret(directory: &Path, name: &str, value: &str) -> std::io::Result<()> {
    if name == "odoo.conf" {
        return write_protected_configuration(&directory.join(name), value);
    }
    let path = directory.join(name);
    write_secret(&path, value)?;
    if name == "pgpass" {
        use std::os::unix::fs::PermissionsExt;
        // libpq rejects password files readable by any group, including the
        // explicitly granted job-secret group.
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn valid_job_secret_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        })
        && name != "."
        && name != ".."
        && !name.starts_with('.')
        && !name.ends_with('.')
        && !name.contains("..")
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
    use std::sync::atomic::{AtomicBool, Ordering};
    use tracing::field::{Field, Visit};
    use tracing::{Event, Subscriber};
    use tracing_subscriber::Layer;
    use tracing_subscriber::layer::SubscriberExt as _;

    #[test]
    fn readiness_requires_startup_authority_and_open_task_admission() {
        assert_eq!(readiness_status(true, true), StatusCode::OK);
        assert_eq!(
            readiness_status(true, false),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            readiness_status(false, true),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            readiness_status(false, false),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[test]
    fn release_target_binds_fleet_run_without_forging_initial_scope() {
        let fleet_run_id = Uuid::new_v4();
        let fleet = ReleaseTarget::from_payload(&json!({
            "phase":"adopt-fleet",
            "fleet_run_id":fleet_run_id,
            "release_id":"odoo-2026.08"
        }))
        .unwrap();
        assert_eq!(fleet.fleet_run_id(), Some(fleet_run_id));
        assert_eq!(fleet.target_key(), format!("fleet/{fleet_run_id}"));
        assert_eq!(fleet.class(), "fleet");

        let initial = ReleaseTarget::from_payload(&json!({
            "phase":"prepare-initial",
            "release_id":"odoo-2026.08"
        }))
        .unwrap();
        assert_eq!(initial.fleet_run_id(), None);
        assert_eq!(initial.target_key(), "initial/odoo-2026.08");
        assert_eq!(initial.class(), "initial");

        assert!(
            ReleaseTarget::from_payload(&json!({
                "phase":"adopt-fleet",
                "fleet_run_id":"not-a-uuid"
            }))
            .is_err()
        );
    }

    #[test]
    fn release_dispatch_errors_always_quarantine_shared_authority() {
        let source = include_str!("docker_driver.rs");
        let tenant = source
            .split("async fn tenant(")
            .nth(1)
            .unwrap()
            .split("fn carrier_secret_path(")
            .next()
            .unwrap();
        let error_branch = tenant.split("Err(error) => {").last().unwrap();
        let release_branch = error_branch
            .split("else if let Some(lease) = &release_lease {")
            .nth(1)
            .unwrap()
            .split("} else if error.0.is_client_error()")
            .next()
            .unwrap();
        assert!(release_branch.contains("\"unknown\""));
        assert!(release_branch.contains("runtime_outcome_unknown"));
        assert!(!release_branch.contains("is_client_error"));
        assert!(!release_branch.contains("\"failed\""));
    }

    #[test]
    fn initial_release_reconciliation_binds_the_original_request_identity() {
        let source = include_str!("docker_driver.rs");
        let admission = source
            .split("async fn admit_initial_release_reconciliation(")
            .nth(1)
            .unwrap()
            .split("async fn finish_initial_release_reconciliation(")
            .next()
            .unwrap();
        assert!(admission.contains("$1,$2,$3,$4,$5,$6,$7,$8,120"));
        for binding in [
            ".bind(operation.id)",
            ".bind(operation.attempt)",
            ".bind(&operation.owner)",
            ".bind(idempotency_key)",
            ".bind(target.target_key())",
            ".bind(request_digest)",
            ".bind(state.instance_id)",
            ".bind(execution_token)",
        ] {
            assert!(
                admission.contains(binding),
                "initial reconciliation admission is missing {binding}"
            );
        }
    }

    struct DropSignal(Arc<AtomicBool>);

    impl Drop for DropSignal {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn release_lease_loss_cancels_the_in_flight_effect() {
        let effect_cancelled = Arc::new(AtomicBool::new(false));
        let signal = effect_cancelled.clone();
        let effect = async move {
            let _drop_signal = DropSignal(signal);
            std::future::pending::<()>().await;
            Ok::<(), DriverError>(())
        };
        let heartbeat = async {
            tokio::task::yield_now().await;
            DriverError(StatusCode::SERVICE_UNAVAILABLE, "lease lost".into())
        };

        let result = with_release_driver_heartbeat(effect, heartbeat).await;

        assert!(result.is_err());
        assert!(effect_cancelled.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn release_completion_cancels_its_heartbeat() {
        let heartbeat_cancelled = Arc::new(AtomicBool::new(false));
        let signal = heartbeat_cancelled.clone();
        let heartbeat = async move {
            let _drop_signal = DropSignal(signal);
            std::future::pending::<()>().await;
            unreachable!("heartbeat only terminates when renewal fails")
        };

        let value = with_release_driver_heartbeat(async { Ok(42_u8) }, heartbeat)
            .await
            .expect("completed release effect");

        assert_eq!(value, 42);
        assert!(heartbeat_cancelled.load(Ordering::SeqCst));
    }

    #[test]
    fn release_heartbeat_has_ample_margin_before_lease_expiry() {
        assert!(
            (RELEASE_DRIVER_HEARTBEAT_INTERVAL + RELEASE_DRIVER_HEARTBEAT_TIMEOUT).as_secs() * 3
                < u64::try_from(RELEASE_DRIVER_LEASE_SECONDS).unwrap()
        );
    }

    fn route_projection_payload() -> Value {
        let mut payload = json!({
            "database_id": Uuid::nil(),
            "database_ref": "mb_00000000000000000000000000000000",
            "public_hostname": "shop.example.test",
            "paperless_mode": "absent",
            "paperless_hostname": null,
            "custom_hostnames": []
        });
        let digest = format!(
            "sha256:{:x}",
            Sha256::digest(serde_jcs::to_vec(&payload).unwrap())
        );
        payload["route_generation"] = json!(7);
        payload["route_projection_digest"] = json!(digest);
        payload
    }

    #[test]
    fn route_projection_authority_is_complete_and_payload_bound() {
        let payload = route_projection_payload();
        let contract = route_projection_contract(&payload).unwrap().unwrap();
        assert_eq!(contract.generation, 7);
        assert_eq!(contract.disposition, "present");

        let mut missing_digest = payload.clone();
        missing_digest
            .as_object_mut()
            .unwrap()
            .remove("route_projection_digest");
        assert!(route_projection_contract(&missing_digest).is_err());

        let mut changed = payload;
        changed["public_hostname"] = json!("other.example.test");
        let error = route_projection_contract(&changed).err().unwrap();
        assert_eq!(error.0, StatusCode::CONFLICT);

        let mut tombstone = json!({
            "database_id":null,
            "database_ref":null,
            "public_hostname":null,
            "paperless_mode":"absent",
            "paperless_hostname":null,
            "custom_hostnames":[],
        });
        let digest = format!(
            "sha256:{:x}",
            Sha256::digest(serde_jcs::to_vec(&tombstone).unwrap())
        );
        tombstone["route_generation"] = json!(8);
        tombstone["route_projection_digest"] = json!(digest);
        tombstone["route_disposition"] = json!("absent");
        let contract = route_projection_contract(&tombstone).unwrap().unwrap();
        assert_eq!(contract.generation, 8);
        assert_eq!(contract.disposition, "absent");
    }

    #[test]
    fn tenant_lease_headers_are_all_or_nothing() {
        let mut headers = HeaderMap::new();
        assert!(optional_control_operation(&headers).unwrap().is_none());
        headers.insert("x-control-operation-attempt", "1".parse().unwrap());
        assert!(optional_control_operation(&headers).is_err());
        headers.insert(
            "x-control-operation-lease-owner",
            "worker-a".parse().unwrap(),
        );
        headers.insert(
            "x-control-operation-id",
            Uuid::new_v4().to_string().parse().unwrap(),
        );
        let lease = optional_control_operation(&headers).unwrap().unwrap();
        assert_eq!(lease.attempt, 1);
        assert_eq!(lease.owner, "worker-a");
    }

    #[tokio::test]
    #[ignore = "requires a disposable CONTROL_TEST_DATABASE_URL"]
    async fn tenant_driver_effects_require_the_exact_live_control_lease() {
        let database_url =
            std::env::var("CONTROL_TEST_DATABASE_URL").expect("CONTROL_TEST_DATABASE_URL");
        let store = crate::persistence::Store::connect(&database_url)
            .await
            .unwrap();
        store.migrate().await.unwrap();
        let workshop = Uuid::new_v4();
        sqlx::query("insert into control.workshops(id,slug,display_name,time_zone) values($1,$2,'Driver lease fixture','Europe/Paris')")
            .bind(workshop)
            .bind(format!("driver-lease-{}", workshop.simple()))
            .execute(store.pool())
            .await
            .unwrap();
        let operation = Uuid::new_v4();
        sqlx::query(
            "insert into control.operations(
                 id,kind,queue,workshop_id,payload,correlation_id,idempotency_key,
                 state,attempt,leased_by,lease_expires_at
             ) values($1,'webshop-domain.reconcile','tenant-reconciliation',$2,'{}',$3,$4,
                      'in_flight',2,'worker-current',now()+interval '5 minutes')",
        )
        .bind(operation)
        .bind(workshop)
        .bind(Uuid::new_v4())
        .bind(format!("driver-lease:{operation}"))
        .execute(store.pool())
        .await
        .unwrap();
        let current = ControlOperationLease {
            id: operation,
            attempt: 2,
            owner: "worker-current".into(),
        };
        validate_control_operation_lease(store.pool(), workshop, &current)
            .await
            .unwrap();
        let stale = ControlOperationLease {
            attempt: 1,
            ..current.clone()
        };
        assert_eq!(
            validate_control_operation_lease(store.pool(), workshop, &stale)
                .await
                .unwrap_err()
                .0,
            StatusCode::SERVICE_UNAVAILABLE
        );
        sqlx::query(
            "update control.operations set lease_expires_at=now()-interval '1 second' where id=$1",
        )
        .bind(operation)
        .execute(store.pool())
        .await
        .unwrap();
        assert_eq!(
            validate_control_operation_lease(store.pool(), workshop, &current)
                .await
                .unwrap_err()
                .0,
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[tokio::test]
    #[ignore = "requires a disposable CONTROL_TEST_DATABASE_URL"]
    async fn tenant_driver_idempotency_is_atomic_and_scoped_by_workshop_and_action() {
        let database_url =
            std::env::var("CONTROL_TEST_DATABASE_URL").expect("CONTROL_TEST_DATABASE_URL");
        let store = crate::persistence::Store::connect(&database_url)
            .await
            .unwrap();
        store.migrate().await.unwrap();
        let first = Uuid::new_v4();
        let second = Uuid::new_v4();
        for workshop in [first, second] {
            sqlx::query("insert into control.workshops(id,slug,display_name,time_zone) values($1,$2,'Driver idempotency fixture','Europe/Paris')")
                .bind(workshop).bind(format!("driver-idempotency-{}",workshop.simple()))
                .execute(store.pool()).await.unwrap();
        }
        let key = format!("driver-scope:{}", Uuid::new_v4());
        let digest = "1".repeat(64);
        let first_admission =
            admit_driver_operation(store.pool(), Some(first), "lifecycle", &key, &digest);
        let concurrent_admission =
            admit_driver_operation(store.pool(), Some(first), "lifecycle", &key, &digest);
        let (left, right) = tokio::join!(first_admission, concurrent_admission);
        assert_eq!(
            usize::from(matches!(left, Ok(DriverOperationAdmission::New)))
                + usize::from(matches!(right, Ok(DriverOperationAdmission::New))),
            1,
            "exactly one concurrent caller must own execution"
        );
        assert!(matches!(
            (&left, &right),
            (Ok(DriverOperationAdmission::New), Err(error))
                | (Err(error), Ok(DriverOperationAdmission::New))
                if error.0 == StatusCode::CONFLICT
        ));

        assert!(matches!(
            admit_driver_operation(store.pool(), Some(second), "lifecycle", &key, &digest)
                .await
                .unwrap(),
            DriverOperationAdmission::New
        ));
        assert!(matches!(
            admit_driver_operation(store.pool(), Some(first), "reconcile", &key, &digest)
                .await
                .unwrap(),
            DriverOperationAdmission::New
        ));
        let mismatch = admit_driver_operation(
            store.pool(),
            Some(first),
            "lifecycle",
            &key,
            &"2".repeat(64),
        )
        .await
        .unwrap_err();
        assert_eq!(mismatch.0, StatusCode::CONFLICT);

        let response = json!({"status":"done"});
        finish_driver_operation(
            store.pool(),
            Some(first),
            "lifecycle",
            &key,
            "succeeded",
            Some(&response),
            None,
        )
        .await
        .unwrap();
        assert!(matches!(
            admit_driver_operation(store.pool(), Some(first), "lifecycle", &key, &digest)
                .await
                .unwrap(),
            DriverOperationAdmission::Replay(value) if value == response
        ));

        // Release admission is deliberately excluded from the generic helper:
        // current release rows require the control-operation and fenced resource
        // lease bindings installed by `admit_release_driver_operation`.
        assert!(
            sqlx::query("insert into control.deployment_driver_operations(idempotency_key,workshop_id,action,request_digest) values($1,$2,'release',$3)")
                .bind(format!("invalid-release:{}",Uuid::new_v4())).bind(first).bind(&digest)
                .execute(store.pool()).await.is_err()
        );
        assert!(
            sqlx::query("insert into control.deployment_driver_operations(idempotency_key,workshop_id,action,request_digest) values($1,null,'lifecycle',$2)")
                .bind(format!("invalid-tenant:{}",Uuid::new_v4())).bind(&digest)
                .execute(store.pool()).await.is_err()
        );
    }

    #[derive(Clone, Default)]
    struct RecordedEvents(Arc<std::sync::Mutex<Vec<String>>>);

    struct EventVisitor<'a>(&'a mut String);

    impl Visit for EventVisitor<'_> {
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            use std::fmt::Write as _;
            let _ = write!(self.0, "{}={value:?};", field.name());
        }
    }

    impl<S: Subscriber> Layer<S> for RecordedEvents {
        fn on_event(&self, event: &Event<'_>, _context: tracing_subscriber::layer::Context<'_, S>) {
            let mut rendered = String::new();
            event.record(&mut EventVisitor(&mut rendered));
            self.0.lock().expect("recorded event lock").push(rendered);
        }
    }

    #[test]
    fn driver_error_logs_emit_only_stable_classes() {
        const TOKEN: &str = "Bearer driver-log-token";
        const EMAIL: &str = "artisan@example.test";
        const HOSTNAME: &str = "private-workshop.example.test";
        const PAYLOAD: &str = "{\"private_invoice\":\"kiln purchase\"}";
        const SECRET_PATH: &str = "/run/mb-odoo-client-secrets/private/bridge-token";
        let canary = format!("{TOKEN} {EMAIL} {HOSTNAME} {PAYLOAD} {SECRET_PATH}");
        let recorded = RecordedEvents::default();
        let subscriber = tracing_subscriber::registry().with(recorded.clone());

        tracing::subscriber::with_default(subscriber, || {
            let error = DriverError::internal(canary);
            assert_eq!(error.safe_class(), "deployment_backend_failure");
            let integration = DriverError::integration(IntegrationError::UnknownOutcome);
            assert_eq!(integration.safe_class(), "deployment_backend_failure");
        });

        let rendered = recorded.0.lock().expect("recorded event lock").join("\n");
        assert!(rendered.contains("error_class"));
        assert!(rendered.contains("deployment_backend"));
        assert!(rendered.contains("unknown_outcome"));
        for sensitive in [TOKEN, EMAIL, HOSTNAME, PAYLOAD, SECRET_PATH] {
            assert!(
                !rendered.contains(sensitive),
                "captured driver log leaked {sensitive}"
            );
        }
    }

    #[test]
    fn provision_derives_the_physical_database_identity_before_side_effects() {
        let source = include_str!("docker_driver.rs");
        let provision = source.split("async fn provision(").nth(1).unwrap();
        let derived_identity = provision.find("database_ref(").unwrap();
        let first_database_effect = provision.find("ensure_database(").unwrap();

        assert!(derived_identity < first_database_effect);
        assert!(
            !provision[..first_database_effect].contains("payload.get(\"database_ref\")"),
            "a caller-provided PostgreSQL identifier must not reach privileged effects"
        );
    }

    #[test]
    fn interrupted_lifecycle_recovery_is_bounded_and_uses_composite_identity() {
        let source = include_str!("docker_driver.rs");
        let recovery = source
            .split("async fn recover_database_connection_limits(")
            .nth(1)
            .unwrap()
            .split("#[derive(Debug)]")
            .next()
            .unwrap();

        assert!(recovery.contains("limit 100"));
        assert!(recovery.contains("database.id=$1 and database.workshop_id=$2"));
        assert!(recovery.contains("database.connection_limit_before_lifecycle=$3"));
        assert!(recovery.contains("operation.workshop_id=database.workshop_id"));
    }

    #[test]
    fn job_secret_leaf_accepts_odoo_configuration_without_allowing_paths() {
        for valid in ["odoo.conf", "pgpass", "aws-access-key-id"] {
            assert!(valid_job_secret_name(valid), "{valid}");
        }
        for invalid in ["", ".", "..", ".hidden", "trailing.", "a..b", "a/b"] {
            assert!(!valid_job_secret_name(invalid), "{invalid}");
        }
    }

    #[test]
    fn protected_job_configuration_is_readable_only_by_root_and_its_group() {
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!("mb-job-config-{}", Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let target = root.join("odoo.conf");
        write_protected_configuration(&target, "[options]\ndb_user = odoo\n").unwrap();
        assert_eq!(
            std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o640
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn postgres_job_password_file_is_private_to_root() {
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!("mb-job-pgpass-{}", Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        write_job_secret(&root, "pgpass", "postgres:5432:*:postgres:password").unwrap();
        assert_eq!(
            std::fs::metadata(root.join("pgpass"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn docker_secret_mount_uses_a_named_volume_subpath() {
        let mount = secret_mount_payload(
            DriverBackendKind::Docker,
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
            DriverBackendKind::Quadlet,
            "/var/lib/mb/tenant-runtime-secrets",
            Path::new("jobs/job-id"),
            "/run/secrets",
        )
        .unwrap();
        assert_eq!(mount["Type"], "bind");
        assert_eq!(
            mount["Source"],
            "/var/lib/mb/tenant-runtime-secrets/jobs/job-id"
        );
        assert!(mount.get("VolumeOptions").is_none());
    }

    #[test]
    fn secret_mount_scope_cannot_escape_its_root() {
        assert!(
            secret_mount_payload(
                DriverBackendKind::Quadlet,
                "/var/lib/mb/tenant-runtime-secrets",
                Path::new("../other-user"),
                "/run/secrets",
            )
            .is_err()
        );
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
        let config = route_config_for_upstream(
            "mb_00000000000000000000000000000001",
            "atelier.dev1.makersbrain.net",
            "mb-odoo-green",
            Some(("docs-atelier.dev1.makersbrain.net", "mb-paperless-fixture")),
            true,
            &[
                CustomHostnameRoute {
                    hostname: "shop.atelier.test".into(),
                    canonical: true,
                },
                CustomHostnameRoute {
                    hostname: "www.atelier.test".into(),
                    canonical: false,
                },
            ],
        );
        assert!(config.contains("limit_except GET HEAD OPTIONS { deny all; }"));
        assert!(config.contains("proxy_pass http://$tenant_upstream;"));
        assert!(config.contains("set $tenant_upstream \"mb-odoo-green:8069\";"));
        assert!(config.contains("server_name shop.atelier.test atelier.dev1.makersbrain.net;"));
        assert!(config.contains(
            "server_name www.atelier.test;\n  return 308 https://shop.atelier.test$request_uri;"
        ));
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
        let valid = format!("s3://mb-production-backups/workshops/{workshop}/recovery/{recovery}");
        assert_eq!(
            safe_s3_storage_ref(&valid, "mb-production-backups", workshop)
                .unwrap()
                .1,
            recovery
        );
        assert!(safe_s3_storage_ref(&valid, "mb-staging-backups", workshop).is_err());
        assert!(safe_s3_storage_ref(&valid, "mb-production-backups", Uuid::new_v4()).is_err());
        assert!(
            safe_s3_storage_ref(
                &format!("{valid}/../../other"),
                "mb-production-backups",
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
