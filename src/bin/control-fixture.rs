//! Development-only deployment and mail boundary.
use std::process::ExitCode;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{Value, json};
use uuid::Uuid;

struct FixtureConfig {
    token: String,
    oidc_issuer: String,
}

impl FixtureConfig {
    fn from_env() -> anyhow::Result<Self> {
        let token = mb_control_plane::runtime_secret::required("FIXTURE_TOKEN")
            .map_err(anyhow::Error::msg)?;
        let oidc_issuer = mb_control_plane::runtime_secret::configuration("FIXTURE_OIDC_ISSUER")
            .map_err(anyhow::Error::msg)?
            .unwrap_or_else(|| "http://rauthy.localhost:8092/auth/v1".into());
        let issuer = url::Url::parse(&oidc_issuer)?;
        if !matches!(issuer.scheme(), "http" | "https") || issuer.host_str().is_none() {
            anyhow::bail!("FIXTURE_OIDC_ISSUER must be an absolute HTTP(S) URL");
        }
        Ok(Self { token, oidc_issuer })
    }
}

fn authorized(headers: &HeaderMap, expected: &str) -> bool {
    headers.get("authorization").and_then(|v| v.to_str().ok())
        == Some(&format!("Bearer {expected}"))
}

async fn tenant(
    State(config): State<Arc<FixtureConfig>>,
    Path((workshop, action)): Path<(Uuid, String)>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<Json<Value>, StatusCode> {
    if !authorized(&headers, &config.token) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    if !matches!(action.as_str(), "provision" | "reconcile" | "lifecycle") {
        return Err(StatusCode::NOT_FOUND);
    }
    if action == "lifecycle" {
        let lifecycle = body
            .get("action")
            .and_then(Value::as_str)
            .ok_or(StatusCode::BAD_REQUEST)?;
        let recovery = body
            .get("recovery_point_id")
            .and_then(Value::as_str)
            .unwrap_or("duplicate");
        let result = match lifecycle {
            "snapshot" | "backup" => {
                json!({"workshop_id":workshop,"action":action,"release_id":env!("CARGO_PKG_VERSION"),"recovery_point":{"storage_ref":format!("fixture/{workshop}/{recovery}"),"storage_location":"local","size_bytes":1048576,"manifest_digest":"0000000000000000000000000000000000000000000000000000000000000000","format_version":"mb-workshop-recovery-v2","source_release":env!("CARGO_PKG_VERSION"),"paperless_version":null,"components":[{"name":"odoo-database","path":"odoo/database.dump","size_bytes":524288,"sha256":"0000000000000000000000000000000000000000000000000000000000000000"},{"name":"odoo-filestore","path":"odoo/filestore","size_bytes":524288,"sha256":"0000000000000000000000000000000000000000000000000000000000000000"}]}})
            }
            "restore" => {
                json!({"workshop_id":workshop,"action":action,"release_id":env!("CARGO_PKG_VERSION"),"safety_recovery_point":{"storage_ref":format!("fixture/{workshop}/safety"),"storage_location":"local","size_bytes":1048576,"manifest_digest":"0000000000000000000000000000000000000000000000000000000000000000","format_version":"mb-workshop-recovery-v2","source_release":env!("CARGO_PKG_VERSION"),"paperless_version":null,"components":[{"name":"odoo-database","path":"odoo/database.dump","size_bytes":524288,"sha256":"0000000000000000000000000000000000000000000000000000000000000000"},{"name":"odoo-filestore","path":"odoo/filestore","size_bytes":524288,"sha256":"0000000000000000000000000000000000000000000000000000000000000000"}]}})
            }
            "duplicate" => {
                json!({"workshop_id":workshop,"action":action,"release_id":env!("CARGO_PKG_VERSION"),"duplicate":{"ready":true,"routable":false}})
            }
            _ => return Err(StatusCode::BAD_REQUEST),
        };
        return Ok(Json(result));
    }
    let database = json!({
        "database_ref": body.get("database_ref").and_then(Value::as_str).unwrap_or(""),
        "public_hostname": body.get("public_hostname").and_then(Value::as_str).unwrap_or("")
    });
    Ok(Json(json!({
        "workshop_id":workshop,"action":action,"release_id":env!("CARGO_PKG_VERSION"),
        "odoo":{"base_url":"http://odoo:8069","secret_ref":"local/odoo","database":database},
        "paperless":{"base_url":"http://paperless:8000","secret_ref":"local/paperless"},
        "odoo_oidc":{"client_id":"mb-odoo-local","issuer":&config.oidc_issuer}
    })))
}

async fn mail(
    State(config): State<Arc<FixtureConfig>>,
    headers: HeaderMap,
    Json(_body): Json<Value>,
) -> Result<(StatusCode, Json<Value>), StatusCode> {
    if !authorized(&headers, &config.token) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    tracing::info!("fixture mail accepted");
    Ok((StatusCode::ACCEPTED, Json(json!({"accepted":true}))))
}

fn startup_failure(error_class: &'static str) -> ExitCode {
    eprintln!(
        "{{\"level\":\"ERROR\",\"service\":\"mb-control-fixture\",\"error_class\":\"{error_class}\",\"message\":\"process startup failed\"}}"
    );
    ExitCode::FAILURE
}

#[tokio::main]
async fn main() -> ExitCode {
    let config = match FixtureConfig::from_env() {
        Ok(config) => Arc::new(config),
        Err(_) => return startup_failure("configuration_invalid"),
    };
    let _telemetry = match mb_control_plane::telemetry::init("mb-control-fixture") {
        Ok(telemetry) => telemetry,
        Err(_) => return startup_failure("telemetry_initialization_failed"),
    };
    let app = Router::new()
        .route("/health/live", get(|| async { "live" }))
        .route("/v1/tenants/{workshop}/{action}", post(tenant))
        .route("/send", post(mail))
        .with_state(config);
    let listener = match tokio::net::TcpListener::bind("0.0.0.0:8080").await {
        Ok(listener) => listener,
        Err(error) => {
            tracing::error!(
                error_class = mb_control_plane::error_reporting::safe_error_class(&error),
                "fixture listener bind failed"
            );
            return ExitCode::FAILURE;
        }
    };
    if axum::serve(listener, app).await.is_err() {
        tracing::error!(
            error_class = "server_failed",
            "fixture stopped unexpectedly"
        );
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
