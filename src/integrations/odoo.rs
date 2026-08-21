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
pub struct WebshopDomainCommand {
    pub operation_key: String,
    pub workshop_id: Uuid,
    pub hostname: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct WebshopStatusCommand {
    pub workshop_id: Uuid,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct WebshopReadiness {
    pub catalog: bool,
    pub online_payment: bool,
    pub fulfilment: bool,
    pub sender: bool,
    pub domain: bool,
    pub returns: bool,
    pub product_count: i64,
    pub payment_count: i64,
    pub fulfilment_count: i64,
    pub launch_ready: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct WebshopOdooIssue {
    pub kind: String,
    pub state: String,
    pub count: i64,
    pub action_path: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct WebshopStatusObservation {
    pub workshop_id: Uuid,
    pub website_id: i64,
    pub readiness: WebshopReadiness,
    pub issues: Vec<WebshopOdooIssue>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, ToSchema)]
pub struct WebshopSmtpStatus {
    pub transport: String,
    pub configured: bool,
    pub host: Option<String>,
    pub port: Option<i64>,
    pub encryption: Option<String>,
    pub username: Option<String>,
    pub from_email: Option<String>,
    pub password_configured: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct WebshopSmtpStatusCommand {
    pub workshop_id: Uuid,
}

#[derive(Clone, Serialize)]
pub struct WebshopSmtpConfigureCommand {
    pub operation_key: String,
    pub workshop_id: Uuid,
    pub host: String,
    pub port: i64,
    pub encryption: String,
    pub username: String,
    pub password: String,
    pub from_email: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct WebshopSmtpResetCommand {
    pub operation_key: String,
    pub workshop_id: Uuid,
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
pub struct CarrierSecretBindingCommand {
    pub workshop_id: Uuid,
    pub company_id: i64,
    pub carrier_id: i64,
    pub provider: String,
    pub environment: String,
    pub secret_ref: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credentials: Option<Value>,
}

/// The bridge's readiness and the tenant identity it believes it serves.
///
/// Typed rather than `Value` on purpose: the cross-repository compatibility
/// lane asserts against these fields, so a provider that stops sending one
/// fails to parse here rather than yielding a `None` that reads as healthy.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct BridgeHealth {
    pub status: String,
    pub database: String,
    #[serde(default)]
    pub workshop_id: Option<String>,
    #[serde(default)]
    pub entitlement_version: Option<i64>,
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
            .user_agent("mb-control-worker")
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

    /// The bridge's own health and tenant view.
    ///
    /// Authenticated like every other bridge call: an unauthenticated liveness
    /// probe answers a different question from the one the control plane needs,
    /// which is whether *this credential* still reaches *this tenant*.
    pub async fn health(&self) -> Result<BridgeHealth, IntegrationError> {
        self.get("/mb_control/v1/health").await
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

    pub async fn project_webshop_domain(
        &self,
        command: &WebshopDomainCommand,
    ) -> Result<Value, IntegrationError> {
        self.post("/mb_control/v1/webshop/domain", command).await
    }

    pub async fn webshop_status(
        &self,
        command: &WebshopStatusCommand,
    ) -> Result<WebshopStatusObservation, IntegrationError> {
        let observation: WebshopStatusObservation =
            self.post("/mb_control/v1/webshop/status", command).await?;
        let valid = observation.workshop_id == command.workshop_id
            && observation.website_id > 0
            && observation.readiness.product_count >= 0
            && observation.readiness.payment_count >= 0
            && observation.readiness.fulfilment_count >= 0
            && observation.issues.iter().all(|issue| {
                matches!(issue.kind.as_str(), "payment" | "shipment" | "return")
                    && issue.state == "action_required"
                    && issue.count > 0
                    && issue.action_path.as_deref().is_none_or(|path| {
                        path.strip_prefix("/odoo/action-").is_some_and(|id| {
                            !id.is_empty() && id.bytes().all(|byte| byte.is_ascii_digit())
                        })
                    })
            });
        if !valid {
            return Err(IntegrationError::ContractDrift);
        }
        Ok(observation)
    }

    pub async fn webshop_smtp_status(
        &self,
        command: &WebshopSmtpStatusCommand,
    ) -> Result<WebshopSmtpStatus, IntegrationError> {
        let status: WebshopSmtpStatus = self
            .post("/mb_control/v1/webshop/smtp/status", command)
            .await?;
        validate_smtp_status(status)
    }

    pub async fn configure_webshop_smtp(
        &self,
        command: &WebshopSmtpConfigureCommand,
    ) -> Result<WebshopSmtpStatus, IntegrationError> {
        let status: WebshopSmtpStatus = self
            .post("/mb_control/v1/webshop/smtp/configure", command)
            .await?;
        validate_smtp_status(status)
    }

    pub async fn reset_webshop_smtp(
        &self,
        command: &WebshopSmtpResetCommand,
    ) -> Result<WebshopSmtpStatus, IntegrationError> {
        let status: WebshopSmtpStatus = self
            .post("/mb_control/v1/webshop/smtp/reset", command)
            .await?;
        validate_smtp_status(status)
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

fn validate_smtp_status(status: WebshopSmtpStatus) -> Result<WebshopSmtpStatus, IntegrationError> {
    let valid = matches!(status.transport.as_str(), "platform" | "smtp")
        && (!status.configured
            || (status.transport == "smtp"
                && status
                    .host
                    .as_deref()
                    .is_some_and(|value| !value.is_empty())
                && status
                    .port
                    .is_some_and(|value| (1..=65535).contains(&value))
                && status
                    .encryption
                    .as_deref()
                    .is_some_and(|value| matches!(value, "starttls" | "ssl"))
                && status.password_configured));
    valid
        .then_some(status)
        .ok_or(IntegrationError::ContractDrift)
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
            credentials: Some(json!({
                "access_key":"access-key",
                "secret_key":"secret-key",
                "webhook_secret":"webhook-secret"
            })),
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
            oidc_client_id: "mb-odoo-fixture".into(),
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
    async fn canonical_webshop_domain_uses_the_narrow_tenant_endpoint() {
        let server = MockServer::start().await;
        let command = WebshopDomainCommand {
            operation_key: "webshop-domain:fixture".into(),
            workshop_id: Uuid::new_v4(),
            hostname: "www.atelier-luna.fr".into(),
        };
        Mock::given(method("POST"))
            .and(path("/mb_control/v1/webshop/domain"))
            .and(header("authorization", "Bearer fixture-token"))
            .and(body_json(&command))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "projected":true,"website_id":1,"hostname":"www.atelier-luna.fr"
            })))
            .expect(1)
            .mount(&server)
            .await;
        OdooClient::new(&server.uri(), "fixture-token", None, Duration::from_secs(2))
            .unwrap()
            .project_webshop_domain(&command)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn webshop_status_is_tenant_scoped_and_contract_checked() {
        let server = MockServer::start().await;
        let workshop = Uuid::new_v4();
        let command = WebshopStatusCommand {
            workshop_id: workshop,
        };
        Mock::given(method("POST"))
            .and(path("/mb_control/v1/webshop/status"))
            .and(header("authorization", "Bearer fixture-token"))
            .and(body_json(&command))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "workshop_id":workshop,
                "website_id":7,
                "readiness":{
                    "catalog":true,"online_payment":true,"fulfilment":true,
                    "sender":true,"domain":true,"returns":true,
                    "product_count":4,"payment_count":1,"fulfilment_count":2,
                    "launch_ready":true
                },
                "issues":[{"kind":"payment","state":"action_required","count":1,
                    "action_path":"/odoo/action-42"}]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let observed =
            OdooClient::new(&server.uri(), "fixture-token", None, Duration::from_secs(2))
                .unwrap()
                .webshop_status(&command)
                .await
                .unwrap();
        assert!(observed.readiness.launch_ready);
        assert_eq!(observed.issues[0].kind, "payment");
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
