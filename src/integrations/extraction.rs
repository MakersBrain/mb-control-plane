use std::sync::OnceLock;
use std::time::Duration;

use base64::Engine;
use serde_json::{Value, json};
use url::Url;

use crate::domain::IntegrationError;
use crate::outbound_http::TraceRequestBuilderExt as _;

use super::{bounded_body, classify_status};

const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

static EXTRACTION_BROKER_HTTP: OnceLock<Result<reqwest::Client, String>> = OnceLock::new();

#[cfg(test)]
static EXTRACTION_BROKER_HTTP_BUILDS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

fn shared_http() -> anyhow::Result<reqwest::Client> {
    let client = EXTRACTION_BROKER_HTTP.get_or_init(|| {
        #[cfg(test)]
        EXTRACTION_BROKER_HTTP_BUILDS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);

        crate::outbound_http::internal_service_builder("mb-extraction-client")
            .build()
            .map_err(|error| error.to_string())
    });
    client
        .as_ref()
        .cloned()
        .map_err(|error| anyhow::anyhow!(error.clone()))
}

#[derive(Clone)]
pub struct ExtractionBrokerClient {
    http: reqwest::Client,
    endpoint: Url,
    authorization: reqwest::header::HeaderValue,
    timeout: Duration,
}

impl ExtractionBrokerClient {
    pub fn new(endpoint: &str, token: &str, timeout: Duration) -> anyhow::Result<Self> {
        Self::with_http(shared_http()?, endpoint, token, timeout)
    }

    fn with_http(
        http: reqwest::Client,
        endpoint: &str,
        token: &str,
        timeout: Duration,
    ) -> anyhow::Result<Self> {
        let endpoint = Url::parse(endpoint.trim_end_matches('/'))?;
        if !matches!(endpoint.scheme(), "http" | "https") || endpoint.host_str().is_none() {
            anyhow::bail!("extraction broker URL must be absolute HTTP(S)");
        }
        if token.trim().is_empty() {
            anyhow::bail!("extraction broker token is empty");
        }
        let mut authorization = reqwest::header::HeaderValue::from_str(&format!("Bearer {token}"))?;
        authorization.set_sensitive(true);
        Ok(Self {
            http,
            endpoint,
            authorization,
            timeout,
        })
    }

    fn request(&self, method: reqwest::Method, url: Url) -> reqwest::RequestBuilder {
        self.http
            .request(method, url)
            .header(reqwest::header::AUTHORIZATION, self.authorization.clone())
            .timeout(self.timeout)
    }

    pub async fn invoice(&self, source: &[u8], mimetype: &str) -> Result<Value, IntegrationError> {
        self.extract("invoice", source, mimetype, None).await
    }

    pub async fn ready(&self) -> Result<(), IntegrationError> {
        let url = self
            .endpoint
            .join("/health/ready")
            .map_err(|_| IntegrationError::ContractDrift)?;
        let response = self
            .request(reqwest::Method::GET, url)
            .with_current_trace_context()
            .send()
            .await
            .map_err(|_| IntegrationError::Unavailable)?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(classify_status(response.status()))
        }
    }

    pub async fn vision_ready(&self) -> Result<(), IntegrationError> {
        let url = self
            .endpoint
            .join("/health/vision-ready")
            .map_err(|_| IntegrationError::ContractDrift)?;
        let response = self
            .request(reqwest::Method::GET, url)
            .with_current_trace_context()
            .send()
            .await
            .map_err(|_| IntegrationError::Unavailable)?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(classify_status(response.status()))
        }
    }

    pub async fn inventory_vision(
        &self,
        assets: &[(String, String, Vec<u8>)],
        ocr_tokens: &Value,
        provider_order: &[String],
    ) -> Result<Value, IntegrationError> {
        let url = self
            .endpoint
            .join("/v1/inventory-label/vision")
            .map_err(|_| IntegrationError::ContractDrift)?;
        let encoded = assets
            .iter()
            .map(|(asset_id, mimetype, source)| {
                json!({
                    "asset_id":asset_id,"mimetype":mimetype,
                    "source_base64":base64::engine::general_purpose::STANDARD.encode(source),
                })
            })
            .collect::<Vec<_>>();
        let response = self
            .request(reqwest::Method::POST, url)
            .json(&json!({
                "assets":encoded,"ocr_tokens":ocr_tokens,"provider_order":provider_order,
            }))
            .with_current_trace_context()
            .send()
            .await
            .map_err(|error| {
                if error.is_timeout() {
                    IntegrationError::UnknownOutcome
                } else {
                    IntegrationError::Unavailable
                }
            })?;
        let status = response.status();
        let body = bounded_body(response, MAX_RESPONSE_BYTES).await?;
        if !status.is_success() {
            return Err(classify_status(status));
        }
        serde_json::from_slice(&body).map_err(|_| IntegrationError::ContractDrift)
    }

    pub async fn inventory_label(
        &self,
        source: &[u8],
        mimetype: &str,
        asset_id: &str,
    ) -> Result<Value, IntegrationError> {
        self.extract("inventory_label", source, mimetype, Some(asset_id))
            .await
    }

    pub async fn product_lookup(
        &self,
        provider: &str,
        gtin14: &str,
    ) -> Result<Value, IntegrationError> {
        let url = self
            .endpoint
            .join("/v1/products/lookup")
            .map_err(|_| IntegrationError::ContractDrift)?;
        let response = self
            .request(reqwest::Method::POST, url)
            .json(&json!({"provider":provider,"gtin14":gtin14}))
            .with_current_trace_context()
            .send()
            .await
            .map_err(|error| {
                if error.is_timeout() {
                    IntegrationError::UnknownOutcome
                } else {
                    IntegrationError::Unavailable
                }
            })?;
        let status = response.status();
        let body = bounded_body(response, MAX_RESPONSE_BYTES).await?;
        if !status.is_success() {
            return Err(classify_status(status));
        }
        serde_json::from_slice(&body).map_err(|_| IntegrationError::ContractDrift)
    }

    async fn extract(
        &self,
        task: &str,
        source: &[u8],
        mimetype: &str,
        asset_id: Option<&str>,
    ) -> Result<Value, IntegrationError> {
        let url = self
            .endpoint
            .join("/v1/extract")
            .map_err(|_| IntegrationError::ContractDrift)?;
        let response = self
            .request(reqwest::Method::POST, url)
            .json(&json!({
                "task": task,
                "mimetype": mimetype,
                "asset_id": asset_id,
                "source_base64": base64::engine::general_purpose::STANDARD.encode(source),
            }))
            .with_current_trace_context()
            .send()
            .await
            .map_err(|error| {
                if error.is_timeout() {
                    IntegrationError::UnknownOutcome
                } else {
                    IntegrationError::Unavailable
                }
            })?;
        let status = response.status();
        let body = bounded_body(response, MAX_RESPONSE_BYTES).await?;
        if !status.is_success() {
            return Err(classify_status(status));
        }
        serde_json::from_slice(&body).map_err(|_| IntegrationError::ContractDrift)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn extraction_transport_is_built_once_and_credentials_are_request_scoped() {
        let first_transport = shared_http().unwrap();
        let second_transport = shared_http().unwrap();
        assert_eq!(
            EXTRACTION_BROKER_HTTP_BUILDS.load(std::sync::atomic::Ordering::SeqCst),
            1
        );

        let first = ExtractionBrokerClient::with_http(
            first_transport.clone(),
            "https://broker.example.test",
            "first-token",
            Duration::from_secs(7),
        )
        .unwrap();
        let second = ExtractionBrokerClient::with_http(
            second_transport,
            "https://broker.example.test",
            "second-token",
            Duration::from_secs(31),
        )
        .unwrap();
        let url = Url::parse("https://broker.example.test/health/ready").unwrap();
        let first_request = first
            .request(reqwest::Method::GET, url.clone())
            .build()
            .unwrap();
        let second_request = second
            .request(reqwest::Method::GET, url.clone())
            .build()
            .unwrap();
        let bare_request = first_transport.get(url).build().unwrap();

        assert_eq!(
            first_request.headers()[reqwest::header::AUTHORIZATION],
            "Bearer first-token"
        );
        assert_eq!(first_request.timeout(), Some(&Duration::from_secs(7)));
        assert_eq!(
            second_request.headers()[reqwest::header::AUTHORIZATION],
            "Bearer second-token"
        );
        assert_eq!(second_request.timeout(), Some(&Duration::from_secs(31)));
        assert!(
            bare_request
                .headers()
                .get(reqwest::header::AUTHORIZATION)
                .is_none()
        );
        assert_eq!(bare_request.timeout(), None);
    }

    #[tokio::test]
    async fn readiness_preserves_authentication_identity_and_status_classification() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/health/ready"))
            .and(header("authorization", "Bearer fixture-token"))
            .and(header("user-agent", "mb-extraction-client"))
            .respond_with(ResponseTemplate::new(401))
            .expect(1)
            .mount(&server)
            .await;

        let error =
            ExtractionBrokerClient::new(&server.uri(), "fixture-token", Duration::from_secs(2))
                .unwrap()
                .ready()
                .await
                .unwrap_err();
        assert_eq!(error, IntegrationError::Unauthorized);
    }
}
