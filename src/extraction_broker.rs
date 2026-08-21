use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use serde::Deserialize;
use serde_json::{Value, json};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::sensitive_headers::SetSensitiveRequestHeadersLayer;
use tower_http::trace::TraceLayer;

use crate::integrations::azure::AzureInvoiceClient;
use crate::integrations::inventory_vision::{InventoryVisionClient, VisionProviderKind};
use crate::integrations::product_lookup::UpcItemDbClient;

const MAX_SOURCE_BYTES: usize = 32 * 1024 * 1024;

pub struct BrokerState {
    token: String,
    azure: Option<AzureInvoiceClient>,
    azure_version: String,
    vision: Vec<InventoryVisionClient>,
    product_lookup: Option<UpcItemDbClient>,
    metrics: Mutex<BTreeMap<ProviderMetricKey, ProviderMetric>>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ProviderMetricKey {
    provider: &'static str,
    operation: &'static str,
    outcome: &'static str,
}

#[derive(Default)]
struct ProviderMetric {
    requests: u64,
    latency_micros: u128,
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
    #[serde(default)]
    provider_order: Vec<String>,
}

#[derive(Deserialize)]
struct VisionAsset {
    asset_id: String,
    mimetype: String,
    source_base64: String,
}

#[derive(Deserialize)]
struct ProductLookupRequest {
    provider: String,
    gtin14: String,
}

impl BrokerState {
    pub fn from_env() -> anyhow::Result<Self> {
        let endpoint = broker_configuration("BROKER_AZURE_ENDPOINT")?.unwrap_or_default();
        let key = broker_secret("BROKER_AZURE_KEY")?.unwrap_or_default();
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
        let vision = vision_clients_from_env()?;
        let lookup_endpoint =
            broker_configuration("BROKER_UPCITEMDB_ENDPOINT")?.unwrap_or_default();
        let product_lookup = if lookup_endpoint.trim().is_empty() {
            None
        } else {
            let lookup_key = broker_secret("BROKER_UPCITEMDB_KEY")?;
            Some(UpcItemDbClient::new(
                &lookup_endpoint,
                lookup_key.as_deref(),
            )?)
        };
        Ok(Self {
            token: crate::runtime_secret::required("BROKER_TOKEN").map_err(anyhow::Error::msg)?,
            azure,
            azure_version,
            vision,
            product_lookup,
            metrics: Mutex::new(BTreeMap::new()),
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
        .route("/internal/metrics", get(metrics))
        .route("/v1/extract", post(extract))
        .route("/v1/inventory-label/vision", post(inventory_vision))
        .route("/v1/products/lookup", post(product_lookup))
        .layer(RequestBodyLimitLayer::new(45 * 1024 * 1024))
        .layer(SetSensitiveRequestHeadersLayer::new([
            header::AUTHORIZATION,
        ]))
        .layer(TraceLayer::new_for_http().make_span_with(
            |request: &axum::http::Request<axum::body::Body>| {
                tracing::info_span!(
                    "broker_http_request",
                    http_request_method = %request.method(),
                    http_route = %request.uri().path()
                )
            },
        ))
        .with_state(Arc::new(state))
}

fn record_provider_metric(
    state: &BrokerState,
    provider: &'static str,
    operation: &'static str,
    outcome: &'static str,
    elapsed: Duration,
) {
    if let Ok(mut metrics) = state.metrics.lock() {
        let metric = metrics
            .entry(ProviderMetricKey {
                provider,
                operation,
                outcome,
            })
            .or_default();
        metric.requests = metric.requests.saturating_add(1);
        metric.latency_micros = metric.latency_micros.saturating_add(elapsed.as_micros());
    }
}

async fn metrics(
    State(state): State<Arc<BrokerState>>,
    headers: HeaderMap,
) -> Result<(HeaderMap, String), StatusCode> {
    if !authorized(&headers, &state.token) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let metrics = state
        .metrics
        .lock()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let mut body = String::from(
        "# HELP makersbrain_provider_requests_total Provider calls by bounded provider, operation and outcome.\n\
# TYPE makersbrain_provider_requests_total counter\n\
# HELP makersbrain_provider_latency_seconds_sum Accumulated provider latency by bounded provider, operation and outcome.\n\
# TYPE makersbrain_provider_latency_seconds_sum counter\n",
    );
    for (key, metric) in metrics.iter() {
        let labels = format!(
            "provider=\"{}\",operation=\"{}\",outcome=\"{}\"",
            key.provider, key.operation, key.outcome
        );
        body.push_str(&format!(
            "makersbrain_provider_requests_total{{{labels}}} {}\nmakersbrain_provider_latency_seconds_sum{{{labels}}} {}\n",
            metric.requests,
            metric.latency_micros as f64 / 1_000_000.0
        ));
    }
    let mut response_headers = HeaderMap::new();
    response_headers.insert(
        header::CONTENT_TYPE,
        "text/plain; version=0.0.4; charset=utf-8"
            .parse()
            .expect("static metrics content type"),
    );
    response_headers.insert(
        header::CACHE_CONTROL,
        "no-store".parse().expect("static header"),
    );
    Ok((response_headers, body))
}

async fn ready(State(state): State<Arc<BrokerState>>) -> StatusCode {
    if state.azure.is_some() {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

async fn vision_ready(State(state): State<Arc<BrokerState>>) -> StatusCode {
    if !state.vision.is_empty() {
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
            let started = Instant::now();
            let result = azure
                .analyze_model("prebuilt-invoice", &source, &request.mimetype)
                .await;
            record_provider_metric(
                &state,
                "azure-document-intelligence",
                "invoice",
                if result.is_ok() { "success" } else { "failure" },
                started.elapsed(),
            );
            let result = result.map_err(|_| StatusCode::BAD_GATEWAY)?;
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
            let started = Instant::now();
            let result = azure
                .analyze_model("prebuilt-read", &source, &request.mimetype)
                .await;
            record_provider_metric(
                &state,
                "azure-document-intelligence",
                "inventory-ocr",
                if result.is_ok() { "success" } else { "failure" },
                started.elapsed(),
            );
            let result = result.map_err(|_| StatusCode::BAD_GATEWAY)?;
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
    if state.vision.is_empty()
        || request.provider_order.is_empty()
        || request.provider_order.len() > 2
        || request
            .provider_order
            .iter()
            .any(|name| !matches!(name.as_str(), "azure" | "gemini" | "openai" | "claude"))
        || (request.provider_order.len() == 2
            && request.provider_order[0] == request.provider_order[1])
    {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    let requested = request.provider_order;
    let vision_order = requested
        .iter()
        .filter_map(|name| state.vision.iter().find(|client| client.provider() == name))
        .collect::<Vec<_>>();
    if vision_order.len() != requested.len() {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    let mut last_status = StatusCode::BAD_GATEWAY;
    for vision in vision_order {
        let started = Instant::now();
        let result = vision.analyze(&assets, &request.ocr_tokens).await;
        record_provider_metric(
            &state,
            vision.provider(),
            "inventory-vision",
            if result.is_ok() { "success" } else { "failure" },
            started.elapsed(),
        );
        let analysis = match result {
            Ok(result) => result,
            Err(error @ crate::domain::IntegrationError::TooLarge) => {
                last_status = StatusCode::PAYLOAD_TOO_LARGE;
                if vision_failover_allowed(error) {
                    continue;
                }
                return Err(last_status);
            }
            Err(error) if vision_failover_allowed(error) => {
                last_status = StatusCode::BAD_GATEWAY;
                continue;
            }
            Err(_) => return Err(StatusCode::BAD_GATEWAY),
        };
        let normalized =
            match crate::inventory_label::normalize_vision(&analysis.result, &request.ocr_tokens) {
                Ok(normalized) => normalized,
                Err(_) => {
                    last_status = StatusCode::BAD_GATEWAY;
                    continue;
                }
            };
        let mut usage = analysis.usage;
        if let Some(object) = usage.as_object_mut() {
            object.insert("latency_ms".into(), json!(analysis.latency_ms));
        }
        return Ok(Json(json!({
            "provider":vision.provider(),"model":vision.model(),"version":"broker-v2",
            "request_id":analysis.request_id,"latency_ms":analysis.latency_ms,
            "usage":usage,"normalized":normalized
        })));
    }
    Err(last_status)
}

async fn product_lookup(
    State(state): State<Arc<BrokerState>>,
    headers: HeaderMap,
    Json(request): Json<ProductLookupRequest>,
) -> Result<Json<Value>, StatusCode> {
    if !authorized(&headers, &state.token) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    if request.provider != "upcitemdb"
        || request.gtin14.len() != 14
        || !request.gtin14.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let provider = state
        .product_lookup
        .as_ref()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let started = Instant::now();
    let result = provider.lookup(&request.gtin14).await;
    record_provider_metric(
        &state,
        "upcitemdb",
        "product-lookup",
        if result.is_ok() { "success" } else { "failure" },
        started.elapsed(),
    );
    let candidates = result.map_err(|error| match error {
        crate::domain::IntegrationError::RateLimited { .. } => StatusCode::TOO_MANY_REQUESTS,
        crate::domain::IntegrationError::Unauthorized => StatusCode::BAD_GATEWAY,
        _ => StatusCode::BAD_GATEWAY,
    })?;
    Ok(Json(json!({
        "provider":"upcitemdb","schema_version":1,
        "gtin14":request.gtin14,"candidates":candidates
    })))
}

fn vision_clients_from_env() -> anyhow::Result<Vec<InventoryVisionClient>> {
    let primary = broker_environment("BROKER_VISION_PRIMARY")?.unwrap_or_default();
    let secondary = broker_environment("BROKER_VISION_SECONDARY")?.unwrap_or_default();
    if primary.trim().is_empty() && !secondary.trim().is_empty() {
        anyhow::bail!("vision secondary requires a configured primary");
    }
    vision_provider_order(&primary, &secondary)?
        .into_iter()
        .map(vision_client_from_env)
        .collect()
}

fn vision_provider_order(
    primary: &str,
    secondary: &str,
) -> anyhow::Result<Vec<VisionProviderKind>> {
    if primary.trim().is_empty() && !secondary.trim().is_empty() {
        anyhow::bail!("vision secondary requires a configured primary");
    }
    let providers = [primary.trim(), secondary.trim()]
        .into_iter()
        .filter(|name| !name.is_empty())
        .map(str::parse::<VisionProviderKind>)
        .collect::<anyhow::Result<Vec<_>>>()?;
    if providers.len() == 2 && providers[0] == providers[1] {
        anyhow::bail!("vision primary and secondary must be different providers");
    }
    Ok(providers)
}

fn vision_failover_allowed(error: crate::domain::IntegrationError) -> bool {
    error.retryable()
        || matches!(
            error,
            crate::domain::IntegrationError::ContractDrift
                | crate::domain::IntegrationError::TooLarge
        )
}

fn vision_client_from_env(provider: VisionProviderKind) -> anyhow::Result<InventoryVisionClient> {
    let prefix = match provider {
        VisionProviderKind::OpenAi => "BROKER_OPENAI",
        VisionProviderKind::Azure => "BROKER_AZURE_MULTIMODAL",
        VisionProviderKind::Gemini => "BROKER_GEMINI",
        VisionProviderKind::Claude => "BROKER_CLAUDE",
    };
    let endpoint = crate::runtime_secret::required_configuration(&format!("{prefix}_ENDPOINT"))
        .map_err(anyhow::Error::msg)?;
    let key =
        crate::runtime_secret::required(&format!("{prefix}_KEY")).map_err(anyhow::Error::msg)?;
    let model = crate::runtime_secret::required_configuration(&format!("{prefix}_MODEL"))
        .map_err(anyhow::Error::msg)?;
    InventoryVisionClient::new(provider, &endpoint, &key, &model)
}

fn broker_environment(name: &str) -> anyhow::Result<Option<String>> {
    broker_configuration(name)
}

fn broker_configuration(name: &str) -> anyhow::Result<Option<String>> {
    crate::runtime_secret::configuration(name).map_err(anyhow::Error::msg)
}

fn broker_secret(name: &str) -> anyhow::Result<Option<String>> {
    crate::runtime_secret::environment(name).map_err(anyhow::Error::msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn requested_vision<'a>(
        configured: &'a [InventoryVisionClient],
        requested: &[String],
    ) -> Result<Vec<&'a InventoryVisionClient>, StatusCode> {
        if configured.is_empty()
            || requested.is_empty()
            || requested.len() > 2
            || requested
                .iter()
                .any(|name| !matches!(name.as_str(), "azure" | "gemini" | "openai" | "claude"))
            || (requested.len() == 2 && requested[0] == requested[1])
        {
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
        let ordered = requested
            .iter()
            .filter_map(|name| configured.iter().find(|client| client.provider() == name))
            .collect::<Vec<_>>();
        (ordered.len() == requested.len())
            .then_some(ordered)
            .ok_or(StatusCode::SERVICE_UNAVAILABLE)
    }

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

    #[test]
    fn provider_metrics_have_only_bounded_privacy_safe_dimensions() {
        let state = BrokerState {
            token: "secret".into(),
            azure: None,
            azure_version: "fixture".into(),
            vision: Vec::new(),
            product_lookup: None,
            metrics: Mutex::new(BTreeMap::new()),
        };
        record_provider_metric(
            &state,
            "upcitemdb",
            "product-lookup",
            "success",
            Duration::from_millis(125),
        );
        let metrics = state.metrics.lock().unwrap();
        let (key, metric) = metrics.first_key_value().unwrap();
        assert_eq!(key.provider, "upcitemdb");
        assert_eq!(key.operation, "product-lookup");
        assert_eq!(key.outcome, "success");
        assert_eq!(metric.requests, 1);
        assert_eq!(metric.latency_micros, 125_000);
    }

    #[test]
    fn provider_order_is_explicit_distinct_and_bounded() {
        assert_eq!(
            vision_provider_order("gemini", "openai").unwrap(),
            vec![VisionProviderKind::Gemini, VisionProviderKind::OpenAi]
        );
        assert!(vision_provider_order("gemini", "google").is_err());
        assert!(vision_provider_order("", "openai").is_err());
        assert!(vision_provider_order("openai-compatible", "").is_err());
    }

    #[test]
    fn failover_does_not_hide_authentication_or_rejected_requests() {
        use crate::domain::IntegrationError;
        assert!(vision_failover_allowed(IntegrationError::Unavailable));
        assert!(vision_failover_allowed(IntegrationError::ContractDrift));
        assert!(vision_failover_allowed(IntegrationError::TooLarge));
        assert!(!vision_failover_allowed(IntegrationError::Unauthorized));
        assert!(!vision_failover_allowed(IntegrationError::Rejected));
    }

    #[test]
    fn tenant_provider_order_is_explicit_and_must_be_available() {
        let clients = [
            InventoryVisionClient::new(
                VisionProviderKind::OpenAi,
                "https://openai.example/v1/responses",
                "secret",
                "fixture-openai",
            )
            .unwrap(),
            InventoryVisionClient::new(
                VisionProviderKind::Gemini,
                "https://gemini.example/v1/interactions",
                "secret",
                "fixture-gemini",
            )
            .unwrap(),
        ];
        let order = requested_vision(&clients, &["gemini".into(), "openai".into()]).unwrap();
        assert_eq!(
            order
                .iter()
                .map(|client| client.provider())
                .collect::<Vec<_>>(),
            vec!["gemini", "openai"]
        );
        assert!(requested_vision(&clients, &[]).is_err());
        assert!(requested_vision(&clients, &["claude".into()]).is_err());
    }
}
