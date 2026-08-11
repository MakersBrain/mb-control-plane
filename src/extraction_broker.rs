use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use serde::Deserialize;
use serde_json::{Value, json};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::sensitive_headers::SetSensitiveRequestHeadersLayer;

use crate::integrations::azure::AzureInvoiceClient;
use crate::integrations::inventory_vision::InventoryVisionClient;

const MAX_SOURCE_BYTES: usize = 32 * 1024 * 1024;

#[derive(Clone)]
pub struct BrokerState {
    token: String,
    azure: Option<AzureInvoiceClient>,
    azure_version: String,
    vision: Option<InventoryVisionClient>,
}

#[derive(Deserialize)]
struct ExtractionRequest {
    task: String,
    mimetype: String,
    source_base64: String,
    asset_id: Option<String>,
}

#[derive(Deserialize)]
struct VisionRequest {
    assets: Vec<VisionAsset>,
    ocr_tokens: Value,
}

#[derive(Deserialize)]
struct VisionAsset {
    asset_id: String,
    mimetype: String,
    source_base64: String,
}

impl BrokerState {
    pub fn from_env() -> anyhow::Result<Self> {
        let required = |name| anyhow::Ok(std::env::var(name)?.trim().to_owned());
        let endpoint = std::env::var("BROKER_AZURE_ENDPOINT").unwrap_or_default();
        let key = std::env::var("BROKER_AZURE_KEY").unwrap_or_default();
        if endpoint.trim().is_empty() != key.trim().is_empty() {
            anyhow::bail!("both Azure endpoint and key must be configured together");
        }
        let azure_version =
            std::env::var("BROKER_AZURE_API_VERSION").unwrap_or_else(|_| "2024-11-30".into());
        let azure = if endpoint.trim().is_empty() {
            None
        } else {
            Some(AzureInvoiceClient::new(
                &endpoint,
                &key,
                &azure_version,
                Duration::from_secs(45),
                Duration::from_millis(
                    std::env::var("BROKER_AZURE_POLL_INTERVAL_MS")
                        .ok()
                        .and_then(|value| value.parse().ok())
                        .unwrap_or(2_000_u64)
                        .max(2_000),
                ),
            )?)
        };
        let vision_endpoint = std::env::var("BROKER_VISION_ENDPOINT").unwrap_or_default();
        let vision_key = std::env::var("BROKER_VISION_KEY").unwrap_or_default();
        let vision_model = std::env::var("BROKER_VISION_MODEL").unwrap_or_default();
        let configured = [
            vision_endpoint.as_str(),
            vision_key.as_str(),
            vision_model.as_str(),
        ]
        .iter()
        .filter(|value| !value.trim().is_empty())
        .count();
        if !matches!(configured, 0 | 3) {
            anyhow::bail!("vision endpoint, key, and model must be configured together");
        }
        let vision = if configured == 3 {
            Some(InventoryVisionClient::new(
                &vision_endpoint,
                &vision_key,
                &vision_model,
            )?)
        } else {
            None
        };
        Ok(Self {
            token: required("BROKER_TOKEN")?,
            azure,
            azure_version,
            vision,
        })
    }
}

pub fn app(state: BrokerState) -> Router {
    Router::new()
        .route(
            "/health/live",
            get(|| async { Json(json!({"status":"live"})) }),
        )
        .route("/health/ready", get(ready))
        .route("/health/vision-ready", get(vision_ready))
        .route("/v1/extract", post(extract))
        .route("/v1/inventory-label/vision", post(inventory_vision))
        .layer(RequestBodyLimitLayer::new(45 * 1024 * 1024))
        .layer(SetSensitiveRequestHeadersLayer::new([
            header::AUTHORIZATION,
        ]))
        .with_state(Arc::new(state))
}

async fn ready(State(state): State<Arc<BrokerState>>) -> StatusCode {
    if state.azure.is_some() {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

async fn vision_ready(State(state): State<Arc<BrokerState>>) -> StatusCode {
    if state.vision.is_some() {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

fn authorized(headers: &HeaderMap, expected: &str) -> bool {
    let Some(supplied) = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
    else {
        return false;
    };
    let supplied = supplied.as_bytes();
    let expected = expected.as_bytes();
    let mut difference = supplied.len() ^ expected.len();
    for index in 0..supplied.len().max(expected.len()) {
        difference |= usize::from(
            supplied.get(index).copied().unwrap_or_default()
                ^ expected.get(index).copied().unwrap_or_default(),
        );
    }
    difference == 0
}

async fn extract(
    State(state): State<Arc<BrokerState>>,
    headers: HeaderMap,
    Json(request): Json<ExtractionRequest>,
) -> Result<Json<Value>, StatusCode> {
    if !authorized(&headers, &state.token) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    if !matches!(
        request.mimetype.as_str(),
        "image/jpeg" | "image/png" | "application/pdf"
    ) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let source = base64::engine::general_purpose::STANDARD
        .decode(request.source_base64)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    if source.is_empty() || source.len() > MAX_SOURCE_BYTES {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    let azure = state
        .azure
        .as_ref()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let response = match request.task.as_str() {
        "invoice" => {
            let result = azure
                .analyze_model("prebuilt-invoice", &source, &request.mimetype)
                .await
                .map_err(|_| StatusCode::BAD_GATEWAY)?;
            let (invoice, confidence, pages) =
                crate::invoice::normalize_azure(&result).map_err(|_| StatusCode::BAD_GATEWAY)?;
            json!({"provider":"azure-document-intelligence","model":"prebuilt-invoice","version":state.azure_version.as_str(),
                   "invoice":invoice,"confidence":confidence,"pages":pages})
        }
        "inventory_label" => {
            if !matches!(request.mimetype.as_str(), "image/jpeg" | "image/png") {
                return Err(StatusCode::BAD_REQUEST);
            }
            let asset_id = request
                .asset_id
                .as_deref()
                .filter(|value| !value.is_empty() && value.len() <= 64)
                .ok_or(StatusCode::BAD_REQUEST)?;
            let result = azure
                .analyze_model("prebuilt-read", &source, &request.mimetype)
                .await
                .map_err(|_| StatusCode::BAD_GATEWAY)?;
            let normalized = crate::inventory_label::normalize_azure_read(&result, asset_id)
                .map_err(|_| StatusCode::BAD_GATEWAY)?;
            json!({"provider":"azure-document-intelligence","model":"prebuilt-read","version":state.azure_version.as_str(),
                   "normalized":normalized})
        }
        _ => return Err(StatusCode::BAD_REQUEST),
    };
    Ok(Json(response))
}

async fn inventory_vision(
    State(state): State<Arc<BrokerState>>,
    headers: HeaderMap,
    Json(request): Json<VisionRequest>,
) -> Result<Json<Value>, StatusCode> {
    if !authorized(&headers, &state.token) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    if request.assets.is_empty() || request.assets.len() > 2 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut assets = Vec::with_capacity(request.assets.len());
    for asset in request.assets {
        if asset.asset_id.is_empty()
            || asset.asset_id.len() > 64
            || !matches!(asset.mimetype.as_str(), "image/jpeg" | "image/png")
        {
            return Err(StatusCode::BAD_REQUEST);
        }
        let source = base64::engine::general_purpose::STANDARD
            .decode(asset.source_base64)
            .map_err(|_| StatusCode::BAD_REQUEST)?;
        if source.is_empty() || source.len() > 15 * 1024 * 1024 {
            return Err(StatusCode::PAYLOAD_TOO_LARGE);
        }
        assets.push((asset.asset_id, asset.mimetype, source));
    }
    let vision = state
        .vision
        .as_ref()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let result = vision
        .analyze(&assets, &request.ocr_tokens)
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;
    let normalized = crate::inventory_label::normalize_vision(&result, &request.ocr_tokens)
        .map_err(|_| StatusCode::BAD_GATEWAY)?;
    Ok(Json(json!({
        "provider":"multimodal-vision","model":vision.model(),"version":"broker-v1",
        "normalized":normalized
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_auth_requires_an_exact_token() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            "Bearer exact-secret".parse().unwrap(),
        );
        assert!(authorized(&headers, "exact-secret"));
        assert!(!authorized(&headers, "exact-secreu"));
        assert!(!authorized(&headers, "exact-secret-longer"));
        assert!(!authorized(&HeaderMap::new(), "exact-secret"));
    }
}
