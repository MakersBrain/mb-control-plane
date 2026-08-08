use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;
use uuid::Uuid;

use crate::domain::IntegrationError;

use super::{bounded_body, classify_status};

const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

#[derive(Clone)]
pub struct OdooClient {
    http: reqwest::Client,
    base_url: Url,
}

#[derive(Debug, Clone, Serialize)]
pub struct MembershipCommand {
    pub operation_key: String,
    pub workshop_id: Uuid,
    pub user_id: Uuid,
    pub subject: String,
    pub email: String,
    pub name: String,
    pub role: String,
    pub epoch: i32,
    pub active: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct EntitlementCommand {
    pub operation_key: String,
    pub workshop_id: Uuid,
    pub version: i64,
    pub plan: String,
    pub status: String,
    pub limits: Value,
    pub expires_at: Option<String>,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct TenantBootstrapCommand {
    pub operation_key: String,
    pub workshop_id: Uuid,
    pub oidc_client_id: String,
    pub oidc_issuer: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct AppliedCommand {
    pub applied: bool,
    #[serde(default)]
    pub stale: bool,
    #[serde(default)]
    pub epoch: Option<i32>,
    #[serde(default)]
    pub version: Option<i64>,
}

impl OdooClient {
    pub fn new(base_url: &str, token: &str, timeout: Duration) -> anyhow::Result<Self> {
        let base_url = Url::parse(base_url.trim_end_matches('/'))?;
        if !matches!(base_url.scheme(), "http" | "https") || base_url.host_str().is_none() {
            anyhow::bail!("Odoo URL must be absolute HTTP(S)");
        }
        if token.trim().is_empty() {
            anyhow::bail!("Odoo bridge token is empty");
        }
        let mut authorization = reqwest::header::HeaderValue::from_str(&format!("Bearer {token}"))?;
        authorization.set_sensitive(true);
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(reqwest::header::AUTHORIZATION, authorization);
        let http = reqwest::Client::builder()
            .default_headers(headers)
            .timeout(timeout)
            .connect_timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .user_agent("makersbrain-control-worker")
            .build()?;
        Ok(Self { http, base_url })
    }

    async fn post<T: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &T,
    ) -> Result<R, IntegrationError> {
        let url = self
            .base_url
            .join(path)
            .map_err(|_| IntegrationError::ContractDrift)?;
        let response = self
            .http
            .post(url)
            .json(body)
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
        let bytes = bounded_body(response, MAX_RESPONSE_BYTES).await?;
        if !status.is_success() {
            return Err(classify_status(status));
        }
        serde_json::from_slice(&bytes).map_err(|_| IntegrationError::ContractDrift)
    }

    pub async fn reconcile_membership(
        &self,
        command: &MembershipCommand,
    ) -> Result<AppliedCommand, IntegrationError> {
        self.post("/mb_control/v1/memberships/reconcile", command)
            .await
    }

    pub async fn bootstrap_tenant(
        &self,
        command: &TenantBootstrapCommand,
    ) -> Result<Value, IntegrationError> {
        self.post("/mb_control/v1/tenant/bootstrap", command).await
    }

    pub async fn apply_entitlement(
        &self,
        command: &EntitlementCommand,
    ) -> Result<AppliedCommand, IntegrationError> {
        self.post("/mb_control/v1/entitlements/apply", command)
            .await
    }

    pub async fn capture_invoice(&self, command: &Value) -> Result<Value, IntegrationError> {
        self.post("/mb_control/v1/invoices/capture", command).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn membership_uses_the_narrow_tenant_endpoint() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/mb_control/v1/memberships/reconcile"))
            .and(header("authorization", "Bearer fixture-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "applied": true, "epoch": 3
            })))
            .expect(1)
            .mount(&server)
            .await;
        let client =
            OdooClient::new(&server.uri(), "fixture-token", Duration::from_secs(2)).unwrap();
        let result = client
            .reconcile_membership(&MembershipCommand {
                operation_key: "member:fixture:3".into(),
                workshop_id: Uuid::new_v4(),
                user_id: Uuid::new_v4(),
                subject: "rauthy-subject".into(),
                email: "artisan@example.test".into(),
                name: "Artisan".into(),
                role: "artisan".into(),
                epoch: 3,
                active: true,
            })
            .await
            .unwrap();
        assert_eq!(result.epoch, Some(3));
    }
}
