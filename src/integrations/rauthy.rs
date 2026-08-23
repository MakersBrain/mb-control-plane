use super::{bounded_body, classify_status};
use crate::domain::IntegrationError;
use crate::outbound_http::TraceRequestBuilderExt as _;
use serde_json::Value;
use std::sync::OnceLock;
use std::time::Duration;
use url::Url;

static HTTP: OnceLock<Result<reqwest::Client, String>> = OnceLock::new();

fn shared_http() -> anyhow::Result<reqwest::Client> {
    HTTP.get_or_init(|| {
        crate::outbound_http::external_api_builder("mb-membership-worker")
            .build()
            .map_err(|error| error.to_string())
    })
    .as_ref()
    .cloned()
    .map_err(|error| anyhow::anyhow!(error.clone()))
}

#[derive(Clone)]
pub struct RauthyClient {
    http: reqwest::Client,
    base_url: Url,
    authorization: reqwest::header::HeaderValue,
    timeout: Duration,
}

impl RauthyClient {
    pub fn new(base_url: &str, key: &str, timeout: Duration) -> anyhow::Result<Self> {
        // Url::join treats a base without a trailing slash as a file. Keep the
        // slash so `users/{id}` stays below `/auth/v1/`.
        let base_url = Url::parse(&format!("{}/", base_url.trim_end_matches('/')))?;
        if !matches!(base_url.scheme(), "http" | "https") || base_url.host_str().is_none() {
            anyhow::bail!("Rauthy URL must be absolute HTTP(S)")
        }
        let mut value = reqwest::header::HeaderValue::from_str(&format!("API-Key {key}"))?;
        value.set_sensitive(true);
        Ok(Self {
            http: shared_http()?,
            base_url,
            authorization: value,
            timeout,
        })
    }

    fn request(&self, method: reqwest::Method, url: Url) -> reqwest::RequestBuilder {
        self.http
            .request(method, url)
            .header(reqwest::header::AUTHORIZATION, self.authorization.clone())
            .timeout(self.timeout)
    }

    pub async fn observe_user(
        &self,
        subject: &str,
        expected_email: &str,
    ) -> Result<(), IntegrationError> {
        let url = self
            .base_url
            .join(&format!("users/{subject}"))
            .map_err(|_| IntegrationError::ContractDrift)?;
        let response = self
            .request(reqwest::Method::GET, url)
            .with_current_trace_context()
            .send()
            .await
            .map_err(|_| IntegrationError::Unavailable)?;
        let status = response.status();
        let bytes = bounded_body(response, 1024 * 1024).await?;
        if !status.is_success() {
            return Err(classify_status(status));
        }
        let user: Value =
            serde_json::from_slice(&bytes).map_err(|_| IntegrationError::ContractDrift)?;
        if user.get("id").and_then(Value::as_str) != Some(subject)
            || user
                .get("email")
                .and_then(Value::as_str)
                .map(|v| v.to_lowercase())
                != Some(expected_email.to_lowercase())
        {
            return Err(IntegrationError::ContractDrift);
        }
        Ok(())
    }

    pub async fn revoke_sessions(&self, subject: &str) -> Result<(), IntegrationError> {
        let url = self
            .base_url
            .join(&format!("users/{subject}/logout"))
            .map_err(|_| IntegrationError::ContractDrift)?;
        let response = self
            .request(reqwest::Method::POST, url)
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
        if response.status().is_success() || response.status() == reqwest::StatusCode::NOT_FOUND {
            Ok(())
        } else {
            Err(classify_status(response.status()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn user_observation_classifies_provider_failures_without_leaking_the_key() {
        for (status, expected) in [
            (401, IntegrationError::Unauthorized),
            (
                429,
                IntegrationError::RateLimited {
                    retry_after_seconds: None,
                },
            ),
            (503, IntegrationError::Unavailable),
        ] {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/auth/v1/users/subject-1"))
                .and(header("authorization", "API-Key fixture-key"))
                .and(header("user-agent", "mb-membership-worker"))
                .respond_with(ResponseTemplate::new(status))
                .expect(1)
                .mount(&server)
                .await;
            let client = RauthyClient::new(
                &format!("{}/auth/v1", server.uri()),
                "fixture-key",
                Duration::from_secs(2),
            )
            .unwrap();
            assert_eq!(
                client
                    .observe_user("subject-1", "artisan@example.test")
                    .await,
                Err(expected)
            );
        }
    }

    #[tokio::test]
    async fn user_observation_rejects_identity_contract_drift() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/auth/v1/users/subject-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id":"another-subject","email":"artisan@example.test"
            })))
            .expect(1)
            .mount(&server)
            .await;
        let client = RauthyClient::new(
            &format!("{}/auth/v1", server.uri()),
            "fixture-key",
            Duration::from_secs(2),
        )
        .unwrap();
        assert_eq!(
            client
                .observe_user("subject-1", "artisan@example.test")
                .await,
            Err(IntegrationError::ContractDrift)
        );
    }

    #[tokio::test]
    async fn session_revocation_treats_absence_as_idempotent_success() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/auth/v1/users/subject-1/logout"))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&server)
            .await;
        RauthyClient::new(
            &format!("{}/auth/v1", server.uri()),
            "fixture-key",
            Duration::from_secs(2),
        )
        .unwrap()
        .revoke_sessions("subject-1")
        .await
        .unwrap();
    }

    #[test]
    fn pooled_transport_keeps_authorization_and_timeout_request_local() {
        let first = RauthyClient::new(
            "https://identity.example.test/auth/v1",
            "first-fixture-key",
            Duration::from_secs(7),
        )
        .unwrap();
        let second = RauthyClient::new(
            "https://identity.example.test/auth/v1",
            "second-fixture-key",
            Duration::from_secs(11),
        )
        .unwrap();

        let first_request = first
            .request(
                reqwest::Method::GET,
                first.base_url.join("users/one").unwrap(),
            )
            .build()
            .unwrap();
        let second_request = second
            .request(
                reqwest::Method::GET,
                second.base_url.join("users/two").unwrap(),
            )
            .build()
            .unwrap();

        assert_eq!(
            first_request.headers()[reqwest::header::AUTHORIZATION],
            "API-Key first-fixture-key"
        );
        assert_eq!(
            second_request.headers()[reqwest::header::AUTHORIZATION],
            "API-Key second-fixture-key"
        );
        assert!(first_request.headers()[reqwest::header::AUTHORIZATION].is_sensitive());
        assert_eq!(first_request.timeout(), Some(&Duration::from_secs(7)));
        assert_eq!(second_request.timeout(), Some(&Duration::from_secs(11)));
    }
}
