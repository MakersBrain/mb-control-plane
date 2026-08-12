use std::time::Duration;

use base64::Engine;
use serde_json::{Value, json};
use url::Url;

use crate::domain::IntegrationError;

use super::{bounded_body, classify_status};

const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

#[derive(Clone)]
pub struct ExtractionBrokerClient {
    http: reqwest::Client,
    endpoint: Url,
}

impl ExtractionBrokerClient {
    pub fn new(endpoint: &str, token: &str, timeout: Duration) -> anyhow::Result<Self> {
        let endpoint = Url::parse(endpoint.trim_end_matches('/'))?;
        if !matches!(endpoint.scheme(), "http" | "https") || endpoint.host_str().is_none() {
            anyhow::bail!("extraction broker URL must be absolute HTTP(S)");
        }
        if token.trim().is_empty() {
            anyhow::bail!("extraction broker token is empty");
        }
        let mut authorization = reqwest::header::HeaderValue::from_str(&format!("Bearer {token}"))?;
        authorization.set_sensitive(true);
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(reqwest::header::AUTHORIZATION, authorization);
        let http = reqwest::Client::builder()
            .default_headers(headers)
            .timeout(timeout)
            .connect_timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent("makersbrain-extraction-client")
            .build()?;
        Ok(Self { http, endpoint })
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
            .http
            .get(url)
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
            .http
            .get(url)
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
            .http
            .post(url)
            .json(&json!({
                "assets":encoded,"ocr_tokens":ocr_tokens,"provider_order":provider_order,
            }))
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
            .http
            .post(url)
            .json(&json!({"provider":provider,"gtin14":gtin14}))
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
            .http
            .post(url)
            .json(&json!({
                "task": task,
                "mimetype": mimetype,
                "asset_id": asset_id,
                "source_base64": base64::engine::general_purpose::STANDARD.encode(source),
            }))
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
