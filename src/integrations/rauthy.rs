use super::{bounded_body, classify_status};
use crate::domain::IntegrationError;
use serde_json::Value;
use std::time::Duration;
use url::Url;

#[derive(Clone)]
pub struct RauthyClient {
    http: reqwest::Client,
    base_url: Url,
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
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(reqwest::header::AUTHORIZATION, value);
        let http = reqwest::Client::builder()
            .default_headers(headers)
            .timeout(timeout)
            .connect_timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .user_agent("makersbrain-membership-worker")
            .build()?;
        Ok(Self { http, base_url })
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
            .http
            .get(url)
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
        let response = self.http.post(url).send().await.map_err(|error| {
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
}
