use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, header};
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
const DEFAULT_AZURE_API_VERSION: &str = "2024-11-30";
const DEFAULT_AZURE_POLL_INTERVAL: Duration = Duration::from_millis(2_000);
const MAX_AZURE_POLL_INTERVAL: Duration = Duration::from_secs(300);

pub struct BrokerConfig {
    pub listen: SocketAddr,
    token: String,
    azure: Option<AzureInvoiceClient>,
    azure_version: String,
    vision: Vec<InventoryVisionClient>,
    product_lookup: Option<UpcItemDbClient>,
}

#[derive(Debug, Eq, PartialEq)]
struct BrokerNetworkConfig {
    listen: SocketAddr,
    azure_api_version: String,
    azure_poll_interval: Duration,
}

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

impl BrokerConfig {
    pub fn from_env() -> anyhow::Result<Self> {
        let network = broker_network_config_with(broker_configuration)?;
        let token = crate::runtime_secret::required("BROKER_TOKEN").map_err(anyhow::Error::msg)?;
        let endpoint = broker_configuration("BROKER_AZURE_ENDPOINT")?.unwrap_or_default();
        let key = broker_secret("BROKER_AZURE_KEY")?.unwrap_or_default();
        if endpoint.trim().is_empty() != key.trim().is_empty() {
            anyhow::bail!("both Azure endpoint and key must be configured together");
        }
        let azure = if endpoint.trim().is_empty() {
            None
        } else {
            Some(AzureInvoiceClient::new(
                &endpoint,
                &key,
                &network.azure_api_version,
                Duration::from_secs(45),
                network.azure_poll_interval,
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
            listen: network.listen,
            token,
            azure,
            azure_version: network.azure_api_version,
            vision,
            product_lookup,
        })
    }
}

impl From<BrokerConfig> for BrokerState {
    fn from(config: BrokerConfig) -> Self {
        Self {
            token: config.token,
            azure: config.azure,
            azure_version: config.azure_version,
            vision: config.vision,
            product_lookup: config.product_lookup,
            metrics: Mutex::new(BTreeMap::new()),
        }
    }
}

fn broker_network_config_with(
    lookup: impl Fn(&str) -> anyhow::Result<Option<String>>,
) -> anyhow::Result<BrokerNetworkConfig> {
    let listen = lookup("BROKER_LISTEN")?
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("BROKER_LISTEN is required"))?
        .parse::<SocketAddr>()
        .map_err(|error| anyhow::anyhow!("BROKER_LISTEN must be a socket address: {error}"))?;

    let azure_api_version = lookup("BROKER_AZURE_API_VERSION")?
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_AZURE_API_VERSION.into());
    if !valid_api_version(&azure_api_version) {
        anyhow::bail!("BROKER_AZURE_API_VERSION must use YYYY-MM-DD format");
    }

    let azure_poll_interval = match lookup("BROKER_AZURE_POLL_INTERVAL_MS")?
        .filter(|value| !value.trim().is_empty())
    {
        Some(value) => {
            let milliseconds = value.parse::<u64>().map_err(|error| {
                anyhow::anyhow!(
                    "BROKER_AZURE_POLL_INTERVAL_MS must be an integer number of milliseconds: {error}"
                )
            })?;
            let interval = Duration::from_millis(milliseconds);
            if !(DEFAULT_AZURE_POLL_INTERVAL..=MAX_AZURE_POLL_INTERVAL).contains(&interval) {
                anyhow::bail!("BROKER_AZURE_POLL_INTERVAL_MS must be between 2000 and 300000");
            }
            interval
        }
        None => DEFAULT_AZURE_POLL_INTERVAL,
    };

    Ok(BrokerNetworkConfig {
        listen,
        azure_api_version,
        azure_poll_interval,
    })
}

fn valid_api_version(value: &str) -> bool {
    value.len() == 10
        && value.bytes().enumerate().all(|(index, byte)| match index {
            4 | 7 => byte == b'-',
            _ => byte.is_ascii_digit(),
        })
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
                    http_request_method = http_method_label(request.method()),
                    http_route = broker_route_label(request.uri().path())
                )
            },
        ))
        .with_state(Arc::new(state))
}

fn http_method_label(method: &Method) -> &'static str {
    match *method {
        Method::GET => "GET",
        Method::POST => "POST",
        _ => "other",
    }
}

fn broker_route_label(path: &str) -> &'static str {
    match path {
        "/health/live" => "/health/live",
        "/health/ready" => "/health/ready",
        "/health/vision-ready" => "/health/vision-ready",
        "/internal/metrics" => "/internal/metrics",
        "/v1/extract" => "/v1/extract",
        "/v1/inventory-label/vision" => "/v1/inventory-label/vision",
        "/v1/products/lookup" => "/v1/products/lookup",
        _ => "unmatched",
    }
}

fn record_provider_failure(
    provider: &'static str,
    operation: &'static str,
    error: &crate::domain::IntegrationError,
) {
    tracing::warn!(
        provider,
        operation,
        outcome = "failure",
        error_class = crate::error_reporting::safe_error_class(error),
        "extraction provider call failed"
    );
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
        "# HELP mb_provider_requests_total Provider calls by bounded provider, operation and outcome.\n\
# TYPE mb_provider_requests_total counter\n\
# HELP mb_provider_latency_seconds_sum Accumulated provider latency by bounded provider, operation and outcome.\n\
# TYPE mb_provider_latency_seconds_sum counter\n",
    );
    for (key, metric) in metrics.iter() {
        let labels = format!(
            "provider=\"{}\",operation=\"{}\",outcome=\"{}\"",
            key.provider, key.operation, key.outcome
        );
        body.push_str(&format!(
            "mb_provider_requests_total{{{labels}}} {}\nmb_provider_latency_seconds_sum{{{labels}}} {}\n",
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
            if let Err(error) = &result {
                record_provider_failure("azure-document-intelligence", "invoice", error);
            }
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
            if let Err(error) = &result {
                record_provider_failure("azure-document-intelligence", "inventory-ocr", error);
            }
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
        if let Err(error) = &result {
            record_provider_failure(vision.provider(), "inventory-vision", error);
        }
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
    if let Err(error) = &result {
        record_provider_failure("upcitemdb", "product-lookup", error);
    }
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
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt as _;
    use tracing::field::{Field, Visit};
    use tracing::{Event, Subscriber};
    use tracing_subscriber::Layer;
    use tracing_subscriber::layer::SubscriberExt as _;

    #[derive(Clone, Default)]
    struct RecordedLogs(Arc<std::sync::Mutex<Vec<String>>>);

    struct LogVisitor<'a>(&'a mut String);

    impl Visit for LogVisitor<'_> {
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            use std::fmt::Write as _;
            let _ = write!(self.0, "{}={value:?};", field.name());
        }
    }

    impl<S: Subscriber> Layer<S> for RecordedLogs {
        fn on_new_span(
            &self,
            attributes: &tracing::span::Attributes<'_>,
            _id: &tracing::span::Id,
            _context: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let mut rendered = format!("span={};", attributes.metadata().name());
            attributes.record(&mut LogVisitor(&mut rendered));
            self.0.lock().unwrap().push(rendered);
        }

        fn on_event(&self, event: &Event<'_>, _context: tracing_subscriber::layer::Context<'_, S>) {
            let mut rendered = String::new();
            event.record(&mut LogVisitor(&mut rendered));
            self.0.lock().unwrap().push(rendered);
        }
    }

    fn network_config(values: &[(&str, &str)]) -> anyhow::Result<BrokerNetworkConfig> {
        broker_network_config_with(|name| {
            Ok(values
                .iter()
                .find_map(|(candidate, value)| (*candidate == name).then(|| (*value).into())))
        })
    }

    #[tokio::test(flavor = "current_thread")]
    async fn request_tracing_never_records_broker_secrets_or_model_content() {
        const TOKEN: &str = "broker-bearer-canary-never-log";
        const EMAIL: &str = "private-broker-canary@example.test";
        const PAYLOAD: &str = "prompt-and-model-result-payload-canary";
        const SECRET_PATH: &str = "/run/secrets/broker-provider-key-canary";

        let recorded = RecordedLogs::default();
        let subscriber = tracing_subscriber::registry().with(recorded.clone());
        let _subscriber = tracing::subscriber::set_default(subscriber);
        let router = app(BrokerState {
            token: TOKEN.into(),
            azure: None,
            azure_version: "fixture".into(),
            vision: Vec::new(),
            product_lookup: None,
            metrics: Mutex::new(BTreeMap::new()),
        });
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/v1/extract")
                    .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({
                            "task": "invoice",
                            "mimetype": "image/png",
                            "source_base64": "cGF5bG9hZA==",
                            "asset_id": EMAIL,
                            "prompt": PAYLOAD,
                            "secret_path": SECRET_PATH
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let unmatched = router
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(SECRET_PATH)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unmatched.status(), StatusCode::NOT_FOUND);

        let rendered = recorded.0.lock().unwrap().join("\n");
        assert!(rendered.contains("broker_http_request"));
        assert!(rendered.contains("/v1/extract"));
        assert!(rendered.contains("unmatched"));
        for canary in [TOKEN, EMAIL, PAYLOAD, SECRET_PATH] {
            assert!(
                !rendered.contains(canary),
                "logged private canary: {canary}"
            );
        }
    }

    #[test]
    fn broker_network_configuration_has_typed_documented_defaults() {
        let config = network_config(&[("BROKER_LISTEN", "127.0.0.1:8080")]).unwrap();
        assert_eq!(config.listen, "127.0.0.1:8080".parse().unwrap());
        assert_eq!(config.azure_api_version, DEFAULT_AZURE_API_VERSION);
        assert_eq!(config.azure_poll_interval, Duration::from_millis(2_000));
    }

    #[test]
    fn broker_network_configuration_rejects_invalid_values_at_startup() {
        assert!(network_config(&[]).is_err());
        assert!(network_config(&[("BROKER_LISTEN", "localhost:8080")]).is_err());
        assert!(
            network_config(&[
                ("BROKER_LISTEN", "127.0.0.1:8080"),
                ("BROKER_AZURE_API_VERSION", "latest"),
            ])
            .is_err()
        );
        for interval in ["fast", "1999", "300001"] {
            assert!(
                network_config(&[
                    ("BROKER_LISTEN", "127.0.0.1:8080"),
                    ("BROKER_AZURE_POLL_INTERVAL_MS", interval),
                ])
                .is_err(),
                "accepted invalid interval {interval}"
            );
        }
    }

    #[test]
    fn broker_network_configuration_accepts_explicit_tuning() {
        let config = network_config(&[
            ("BROKER_LISTEN", "0.0.0.0:9080"),
            ("BROKER_AZURE_API_VERSION", "2025-05-01"),
            ("BROKER_AZURE_POLL_INTERVAL_MS", "5000"),
        ])
        .unwrap();
        assert_eq!(config.listen, "0.0.0.0:9080".parse().unwrap());
        assert_eq!(config.azure_api_version, "2025-05-01");
        assert_eq!(config.azure_poll_interval, Duration::from_secs(5));
    }

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
