use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::domain::IntegrationError;

use super::{bounded_body, classify_status};

const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_ASSET_BYTES: usize = 15 * 1024 * 1024;
const MAX_PRIVACY_EXPORT_BYTES: usize = 96 * 1024 * 1024;

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
    pub bridge_token: String,
    pub public_hostname: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ModuleEnableCommand {
    pub operation_key: String,
    pub workshop_id: Uuid,
    pub module_key: String,
    pub modules: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ModuleRestrictCommand {
    pub operation_key: String,
    pub workshop_id: Uuid,
    pub module_key: String,
    pub modules: Vec<String>,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ErasureReplayCommand {
    pub operation_key: String,
    pub workshop_id: Uuid,
    pub user_id: Uuid,
    pub subject_key: Uuid,
}

#[derive(Debug, Clone, Serialize)]
pub struct PrivacyExportCommand {
    pub workshop_id: Uuid,
    pub user_id: Uuid,
}

#[derive(Clone, Serialize)]
pub struct CarrierSecretMaterial {
    pub access_key: String,
    pub secret_key: String,
    pub webhook_secret: String,
}

#[derive(Clone, Serialize)]
pub struct CarrierSecretBindingCommand {
    pub workshop_id: Uuid,
    pub company_id: i64,
    pub carrier_id: i64,
    pub provider: String,
    pub environment: String,
    pub secret_ref: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credentials: Option<CarrierSecretMaterial>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, ToSchema)]
pub struct CarrierTarget {
    pub company_id: i64,
    pub company_name: String,
    pub carrier_id: i64,
    pub carrier_name: String,
    pub provider: String,
    pub environment: String,
    pub service_code: String,
    pub configured: bool,
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

#[derive(Debug, Clone)]
pub struct InventoryAsset {
    pub content: Vec<u8>,
    pub mimetype: String,
    pub sha256: String,
}

impl OdooClient {
    pub fn new(
        base_url: &str,
        token: &str,
        database_ref: Option<&str>,
        timeout: Duration,
    ) -> anyhow::Result<Self> {
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
        if let Some(database_ref) = database_ref {
            if database_ref.len() != 35
                || !database_ref.starts_with("mb_")
                || !database_ref[3..]
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
            {
                anyhow::bail!("Odoo database reference is not opaque");
            }
            headers.insert(
                "x-odoo-dbfilter",
                reqwest::header::HeaderValue::from_str(&format!(r"^{database_ref}\Z"))?,
            );
        }
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
        self.post_bounded(path, body, MAX_RESPONSE_BYTES).await
    }

    async fn get<R: for<'de> Deserialize<'de>>(&self, path: &str) -> Result<R, IntegrationError> {
        let url = self
            .base_url
            .join(path)
            .map_err(|_| IntegrationError::ContractDrift)?;
        let response = self.http.get(url).send().await.map_err(|error| {
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

    async fn post_bounded<T: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &T,
        maximum: usize,
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
        let bytes = bounded_body(response, maximum).await?;
        if !status.is_success() {
            return Err(classify_status(status));
        }
        serde_json::from_slice(&bytes).map_err(|_| IntegrationError::ContractDrift)
    }

    pub async fn replay_erasure(
        &self,
        command: &ErasureReplayCommand,
    ) -> Result<(), IntegrationError> {
        let _: Value = self
            .post("/mb_control/v1/privacy/erasure-replay", command)
            .await?;
        Ok(())
    }

    pub async fn export_personal_data(
        &self,
        command: &PrivacyExportCommand,
    ) -> Result<Value, IntegrationError> {
        self.post_bounded(
            "/mb_control/v1/privacy/export",
            command,
            MAX_PRIVACY_EXPORT_BYTES,
        )
        .await
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

    pub async fn inventory_asset(
        &self,
        capture_id: Uuid,
        asset_id: Uuid,
    ) -> Result<InventoryAsset, IntegrationError> {
        let url = self
            .base_url
            .join(&format!(
                "/mb_control/v1/inventory-captures/{capture_id}/assets/{asset_id}"
            ))
            .map_err(|_| IntegrationError::ContractDrift)?;
        let response = self.http.get(url).send().await.map_err(|error| {
            if error.is_timeout() {
                IntegrationError::UnknownOutcome
            } else {
                IntegrationError::Unavailable
            }
        })?;
        let status = response.status();
        if !status.is_success() {
            return Err(classify_status(status));
        }
        let mimetype = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .filter(|value| matches!(*value, "image/jpeg" | "image/png"))
            .ok_or(IntegrationError::ContractDrift)?
            .to_owned();
        let sha256 = response
            .headers()
            .get("x-content-sha256")
            .and_then(|value| value.to_str().ok())
            .filter(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .ok_or(IntegrationError::ContractDrift)?
            .to_ascii_lowercase();
        let declared_length = response
            .headers()
            .get(reqwest::header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<usize>().ok())
            .filter(|value| *value <= MAX_ASSET_BYTES)
            .ok_or(IntegrationError::ContractDrift)?;
        let content = bounded_body(response, MAX_ASSET_BYTES).await?.to_vec();
        if content.len() != declared_length {
            return Err(IntegrationError::ContractDrift);
        }
        Ok(InventoryAsset {
            content,
            mimetype,
            sha256,
        })
    }

    pub async fn capture_inventory_result(
        &self,
        command: &Value,
    ) -> Result<Value, IntegrationError> {
        self.post("/mb_control/v1/inventory-captures/results", command)
            .await
    }

    pub async fn enable_modules(
        &self,
        command: &ModuleEnableCommand,
    ) -> Result<Value, IntegrationError> {
        self.post("/mb_control/v1/modules/enable", command).await
    }

    pub async fn restrict_modules(
        &self,
        command: &ModuleRestrictCommand,
    ) -> Result<Value, IntegrationError> {
        self.post("/mb_control/v1/modules/restrict", command).await
    }

    pub async fn carrier_targets(&self) -> Result<Vec<CarrierTarget>, IntegrationError> {
        self.get("/mb_control/v1/carriers").await
    }

    pub async fn bind_carrier_secret(
        &self,
        command: &CarrierSecretBindingCommand,
    ) -> Result<Value, IntegrationError> {
        self.post("/mb_control/v1/carriers/bind-secret", command)
            .await
    }

    pub async fn unbind_carrier_secret(
        &self,
        command: &CarrierSecretBindingCommand,
    ) -> Result<Value, IntegrationError> {
        self.post("/mb_control/v1/carriers/unbind-secret", command)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use wiremock::matchers::{body_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn carrier_rotation_material_is_sent_only_when_explicitly_present() {
        let command = CarrierSecretBindingCommand {
            workshop_id: Uuid::nil(),
            company_id: 1,
            carrier_id: 2,
            provider: "boxtal".into(),
            environment: "test".into(),
            secret_ref: format!("docker/{}/carrier/{}", Uuid::nil(), Uuid::nil()),
            credentials: Some(CarrierSecretMaterial {
                access_key: "access-key".into(),
                secret_key: "secret-key".into(),
                webhook_secret: "webhook-secret".into(),
            }),
        };
        let encoded = serde_json::to_value(&command).unwrap();
        assert_eq!(encoded["credentials"]["webhook_secret"], "webhook-secret");

        let without_material = CarrierSecretBindingCommand {
            credentials: None,
            ..command
        };
        assert!(
            serde_json::to_value(without_material)
                .unwrap()
                .get("credentials")
                .is_none()
        );
    }

    #[tokio::test]
    async fn provisioning_bootstrap_uses_the_idempotent_tenant_endpoint() {
        let server = MockServer::start().await;
        let command = TenantBootstrapCommand {
            operation_key: "tenant-bootstrap:fixture".into(),
            workshop_id: Uuid::new_v4(),
            oidc_client_id: "makersbrain-odoo-fixture".into(),
            oidc_issuer: "https://identity.example.test".into(),
            bridge_token: "a".repeat(64),
            public_hostname: "atelier.example.test".into(),
        };
        Mock::given(method("POST"))
            .and(path("/mb_control/v1/tenant/bootstrap"))
            .and(header("authorization", "Bearer fixture-token"))
            .and(header(
                "x-odoo-dbfilter",
                r"^mb_00000000000000000000000000000001\Z",
            ))
            .and(body_json(&command))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "applied": true
            })))
            .expect(1)
            .mount(&server)
            .await;
        OdooClient::new(
            &server.uri(),
            "fixture-token",
            Some("mb_00000000000000000000000000000001"),
            Duration::from_secs(2),
        )
        .unwrap()
        .bootstrap_tenant(&command)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn membership_uses_the_narrow_tenant_endpoint() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/mb_control/v1/memberships/reconcile"))
            .and(header("authorization", "Bearer fixture-token"))
            .and(header(
                "x-odoo-dbfilter",
                r"^mb_00000000000000000000000000000001\Z",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "applied": true, "epoch": 3
            })))
            .expect(1)
            .mount(&server)
            .await;
        let client = OdooClient::new(
            &server.uri(),
            "fixture-token",
            Some("mb_00000000000000000000000000000001"),
            Duration::from_secs(2),
        )
        .unwrap();
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

    #[tokio::test]
    async fn erasure_replay_uses_the_tenant_bridge_and_stable_identifiers() {
        let server = MockServer::start().await;
        let workshop = Uuid::new_v4();
        let user = Uuid::new_v4();
        let subject_key = Uuid::new_v4();
        let command = ErasureReplayCommand {
            operation_key: "erasure-replay:tombstone".into(),
            workshop_id: workshop,
            user_id: user,
            subject_key,
        };
        Mock::given(method("POST"))
            .and(path("/mb_control/v1/privacy/erasure-replay"))
            .and(header("authorization", "Bearer fixture-token"))
            .and(body_json(&command))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "applied":true,"already_erased":false,"subject_key":subject_key
            })))
            .expect(1)
            .mount(&server)
            .await;
        OdooClient::new(&server.uri(), "fixture-token", None, Duration::from_secs(2))
            .unwrap()
            .replay_erasure(&command)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn restriction_uses_the_narrow_idempotent_tenant_endpoint() {
        let server = MockServer::start().await;
        let command = ModuleRestrictCommand {
            operation_key: "module-restrict:fixture".into(),
            workshop_id: Uuid::new_v4(),
            module_key: "firings".into(),
            modules: vec!["mb_ceramics_firing".into()],
            reason: "entitlement_inactive".into(),
        };
        Mock::given(method("POST"))
            .and(path("/mb_control/v1/modules/restrict"))
            .and(header("authorization", "Bearer fixture-token"))
            .and(body_json(&command))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "applied":true,"adapter":"odoo_write_rules","rule_ids":[42],
                "write_blocked":true,"historical_read_retained":true
            })))
            .expect(1)
            .mount(&server)
            .await;
        let result = OdooClient::new(&server.uri(), "fixture-token", None, Duration::from_secs(2))
            .unwrap()
            .restrict_modules(&command)
            .await
            .unwrap();
        assert_eq!(result["write_blocked"], true);
    }

    #[tokio::test]
    async fn privacy_export_uses_the_authenticated_tenant_endpoint() {
        let server = MockServer::start().await;
        let command = PrivacyExportCommand {
            workshop_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
        };
        Mock::given(method("POST"))
            .and(path("/mb_control/v1/privacy/export"))
            .and(header("authorization", "Bearer fixture-token"))
            .and(body_json(&command))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "format":"makersbrain-odoo-subject-export-v1",
                "found":true,"datasets":{},"attachments":[]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let value = OdooClient::new(&server.uri(), "fixture-token", None, Duration::from_secs(2))
            .unwrap()
            .export_personal_data(&command)
            .await
            .unwrap();
        assert_eq!(value["found"], true);
    }
}
