//! Development-only deployment and mail boundary.
use axum::extract::Path;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{Value, json};
use uuid::Uuid;

fn authorized(headers: &HeaderMap) -> bool {
    let expected = std::env::var("FIXTURE_TOKEN").unwrap_or_default();
    headers.get("authorization").and_then(|v| v.to_str().ok())
        == Some(&format!("Bearer {expected}"))
}

async fn tenant(
    Path((workshop, action)): Path<(Uuid, String)>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<Json<Value>, StatusCode> {
    if !authorized(&headers) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    if !matches!(action.as_str(), "provision" | "reconcile" | "lifecycle") {
        return Err(StatusCode::NOT_FOUND);
    }
    let issuer = std::env::var("FIXTURE_OIDC_ISSUER")
        .unwrap_or_else(|_| "http://rauthy.localhost:8092/auth/v1".into());
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
                json!({"workshop_id":workshop,"action":action,"release_id":env!("CARGO_PKG_VERSION"),"recovery_point":{"storage_ref":format!("fixture/{workshop}/{recovery}"),"storage_location":"local","size_bytes":1048576,"manifest_digest":"0000000000000000000000000000000000000000000000000000000000000000","format_version":"makersbrain-workshop-recovery-v2","source_release":env!("CARGO_PKG_VERSION"),"paperless_version":null,"components":[{"name":"odoo-database","path":"odoo/database.dump","size_bytes":524288,"sha256":"0000000000000000000000000000000000000000000000000000000000000000"},{"name":"odoo-filestore","path":"odoo/filestore","size_bytes":524288,"sha256":"0000000000000000000000000000000000000000000000000000000000000000"}]}})
            }
            "restore" => {
                json!({"workshop_id":workshop,"action":action,"release_id":env!("CARGO_PKG_VERSION"),"safety_recovery_point":{"storage_ref":format!("fixture/{workshop}/safety"),"storage_location":"local","size_bytes":1048576,"manifest_digest":"0000000000000000000000000000000000000000000000000000000000000000","format_version":"makersbrain-workshop-recovery-v2","source_release":env!("CARGO_PKG_VERSION"),"paperless_version":null,"components":[{"name":"odoo-database","path":"odoo/database.dump","size_bytes":524288,"sha256":"0000000000000000000000000000000000000000000000000000000000000000"},{"name":"odoo-filestore","path":"odoo/filestore","size_bytes":524288,"sha256":"0000000000000000000000000000000000000000000000000000000000000000"}]}})
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
        "odoo_oidc":{"client_id":"makersbrain-odoo-local","issuer":issuer}
    })))
}

async fn mail(
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<(StatusCode, Json<Value>), StatusCode> {
    if !authorized(&headers) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    tracing::info!(
        recipient = body
            .get("to")
            .and_then(|value| value.as_str())
            .unwrap_or("invalid"),
        template = body
            .get("template")
            .and_then(|value| value.as_str())
            .unwrap_or("invalid"),
        "fixture mail accepted"
    );
    Ok((StatusCode::ACCEPTED, Json(json!({"accepted":true}))))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().json().init();
    let app = Router::new()
        .route("/health/live", get(|| async { "live" }))
        .route("/v1/tenants/{workshop}/{action}", post(tenant))
        .route("/send", post(mail));
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
    axum::serve(listener, app).await?;
    Ok(())
}
