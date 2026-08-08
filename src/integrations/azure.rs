use std::time::Duration;

use serde::Deserialize;
use serde_json::Value;
use url::Url;

use crate::domain::IntegrationError;

use super::{bounded_body, classify_status};

const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const MAX_POLLS: usize = 120;
const MIN_POLL_INTERVAL: Duration = Duration::from_secs(2);
const MAX_PROVIDER_DELAY: Duration = Duration::from_secs(900);

#[derive(Clone)]
pub struct AzureInvoiceClient {
    http: reqwest::Client,
    endpoint: Url,
    api_version: String,
    poll_interval: Duration,
}

#[derive(Deserialize)]
struct Operation {
    status: String,
    #[serde(rename = "analyzeResult")]
    result: Option<Value>,
}

impl AzureInvoiceClient {
    pub fn new(
        endpoint: &str,
        key: &str,
        api_version: &str,
        timeout: Duration,
        poll_interval: Duration,
    ) -> anyhow::Result<Self> {
        let endpoint = Url::parse(endpoint.trim_end_matches('/'))?;
        if endpoint.scheme() != "https" || endpoint.host_str().is_none() {
            anyhow::bail!("Azure endpoint must be absolute HTTPS");
        }
        if key.trim().is_empty() || api_version.trim().is_empty() {
            anyhow::bail!("Azure key and API version are required");
        }
        let mut key_header = reqwest::header::HeaderValue::from_str(key)?;
        key_header.set_sensitive(true);
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("ocp-apim-subscription-key", key_header);
        let http = reqwest::Client::builder()
            .default_headers(headers)
            .timeout(timeout)
            .connect_timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .user_agent("makersbrain-invoice-worker")
            .build()?;
        Ok(Self {
            http,
            endpoint,
            api_version: api_version.into(),
            poll_interval,
        })
    }

    fn operation_url(&self, value: &str) -> Result<Url, IntegrationError> {
        let url = Url::parse(value).map_err(|_| IntegrationError::ContractDrift)?;
        if url.origin() != self.endpoint.origin() {
            return Err(IntegrationError::ContractDrift);
        }
        Ok(url)
    }

    pub async fn analyze(&self, source: &[u8], mimetype: &str) -> Result<Value, IntegrationError> {
        let mut url = self
            .endpoint
            .join("/documentintelligence/documentModels/prebuilt-invoice:analyze")
            .map_err(|_| IntegrationError::ContractDrift)?;
        url.query_pairs_mut()
            .append_pair("_overload", "analyzeDocument")
            .append_pair("api-version", &self.api_version);
        let response = self
            .http
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, mimetype)
            .body(source.to_vec())
            .send()
            .await
            .map_err(|error| {
                if error.is_timeout() {
                    IntegrationError::UnknownOutcome
                } else {
                    IntegrationError::Unavailable
                }
            })?;
        if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
            return Err(rate_limited(response.headers()));
        }
        if !response.status().is_success() {
            return Err(classify_status(response.status()));
        }
        let mut next_poll =
            retry_after(response.headers()).unwrap_or(self.poll_interval.max(MIN_POLL_INTERVAL));
        let location = response
            .headers()
            .get("operation-location")
            .and_then(|value| value.to_str().ok())
            .ok_or(IntegrationError::ContractDrift)?;
        let operation_url = self.operation_url(location)?;
        let mut throttled_polls = 0_u32;
        for _ in 0..MAX_POLLS {
            tokio::time::sleep(next_poll).await;
            let response = self
                .http
                .get(operation_url.clone())
                .send()
                .await
                .map_err(|_| IntegrationError::Unavailable)?;
            let status = response.status();
            if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
                throttled_polls = throttled_polls.saturating_add(1);
                next_poll = retry_after(response.headers()).unwrap_or_else(|| {
                    Duration::from_secs(
                        2_u64
                            .saturating_mul(2_u64.saturating_pow(throttled_polls.min(4)))
                            .min(34),
                    )
                });
                continue;
            }
            throttled_polls = 0;
            next_poll = retry_after(response.headers())
                .unwrap_or(self.poll_interval.max(MIN_POLL_INTERVAL));
            let body = bounded_body(response, MAX_RESPONSE_BYTES).await?;
            if !status.is_success() {
                return Err(classify_status(status));
            }
            let operation: Operation =
                serde_json::from_slice(&body).map_err(|_| IntegrationError::ContractDrift)?;
            match operation.status.as_str() {
                "notStarted" | "running" => continue,
                "succeeded" => return operation.result.ok_or(IntegrationError::ContractDrift),
                "failed" => return Err(IntegrationError::Rejected),
                _ => return Err(IntegrationError::ContractDrift),
            }
        }
        Err(IntegrationError::Unavailable)
    }
}

fn retry_after(headers: &reqwest::header::HeaderMap) -> Option<Duration> {
    headers
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok())
        .map(Duration::from_secs)
        .map(|duration| duration.min(MAX_PROVIDER_DELAY))
}

fn rate_limited(headers: &reqwest::header::HeaderMap) -> IntegrationError {
    IntegrationError::RateLimited {
        retry_after_seconds: retry_after(headers).map(|duration| duration.as_secs()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn polling_never_sends_the_key_to_another_origin() {
        let client = AzureInvoiceClient::new(
            "https://fixture.cognitiveservices.azure.com",
            "secret",
            "2024-11-30",
            Duration::from_secs(2),
            Duration::ZERO,
        )
        .unwrap();
        assert_eq!(
            client
                .operation_url("https://attacker.invalid/steal")
                .unwrap_err(),
            IntegrationError::ContractDrift
        );
    }

    #[test]
    fn retry_after_seconds_are_bounded() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(reqwest::header::RETRY_AFTER, "17".parse().unwrap());
        assert_eq!(retry_after(&headers), Some(Duration::from_secs(17)));
        headers.insert(reqwest::header::RETRY_AFTER, "99999".parse().unwrap());
        assert_eq!(retry_after(&headers), Some(MAX_PROVIDER_DELAY));
    }
}
