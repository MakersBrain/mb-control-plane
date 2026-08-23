use std::sync::OnceLock;
use std::time::Duration;

use reqwest::{StatusCode, Url};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::domain::IntegrationError;
use crate::integrations::{bounded_body, classify_status};
use crate::outbound_http::TraceRequestBuilderExt as _;

const ROOT: &str = "https://api.scaleway.com/transactional-email/v1alpha1/regions/fr-par/domains";
const WEBHOOK_ROOT: &str =
    "https://api.scaleway.com/transactional-email/v1alpha1/regions/fr-par/webhooks";
const MAXIMUM_RESPONSE: usize = 256 * 1024;

static HTTP: OnceLock<Result<reqwest::Client, String>> = OnceLock::new();

fn shared_http() -> Result<reqwest::Client, IntegrationError> {
    HTTP.get_or_init(|| {
        crate::outbound_http::external_api_builder("mb-email-domain-worker")
            .build()
            .map_err(|error| error.to_string())
    })
    .as_ref()
    .cloned()
    .map_err(|_| IntegrationError::Unavailable)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EmailDomainObservation {
    pub id: Uuid,
    pub name: String,
    pub status: String,
    pub records: Value,
    pub verification: Value,
}

#[derive(Clone)]
pub struct ScalewayTemDomainClient {
    http: reqwest::Client,
    token: reqwest::header::HeaderValue,
    project_id: Uuid,
    root: Url,
    timeout: Duration,
}

impl ScalewayTemDomainClient {
    pub fn new(
        token: String,
        project_id: Uuid,
        timeout: Duration,
    ) -> Result<Self, IntegrationError> {
        if !(16..=512).contains(&token.len()) || token.chars().any(char::is_whitespace) {
            return Err(IntegrationError::ContractDrift);
        }
        let mut value = reqwest::header::HeaderValue::from_str(&token)
            .map_err(|_| IntegrationError::ContractDrift)?;
        value.set_sensitive(true);
        Ok(Self {
            http: shared_http()?,
            token: value,
            project_id,
            root: Url::parse(ROOT).expect("static endpoint"),
            timeout,
        })
    }

    fn request(&self, method: reqwest::Method, url: Url) -> reqwest::RequestBuilder {
        self.http
            .request(method, url)
            .header("X-Auth-Token", self.token.clone())
            .timeout(self.timeout)
    }

    fn endpoint(&self, id: Uuid, suffix: Option<&str>) -> Url {
        let mut endpoint = self.root.clone();
        {
            let mut segments = endpoint
                .path_segments_mut()
                .expect("static endpoint is hierarchical");
            segments.push(&id.to_string());
            if let Some(suffix) = suffix {
                segments.push(suffix);
            }
        }
        endpoint
    }

    pub async fn create(&self, name: &str) -> Result<EmailDomainObservation, IntegrationError> {
        let response = self
            .request(reqwest::Method::POST, self.root.clone())
            .json(&json!({
                "project_id": self.project_id, "domain_name": name, "autoconfig": false
            }))
            .with_current_trace_context()
            .send()
            .await
            .map_err(|_| IntegrationError::Unavailable)?;
        parse_domain(response, None).await
    }

    pub async fn observe(&self, id: Uuid) -> Result<EmailDomainObservation, IntegrationError> {
        let response = self
            .request(reqwest::Method::GET, self.endpoint(id, None))
            .with_current_trace_context()
            .send()
            .await
            .map_err(|_| IntegrationError::Unavailable)?;
        let mut domain = parse_domain(response, None).await?;
        let verification = self
            .request(
                reqwest::Method::GET,
                self.endpoint(id, Some("verification")),
            )
            .with_current_trace_context()
            .send()
            .await
            .map_err(|_| IntegrationError::Unavailable)?;
        let status = verification.status();
        let body = bounded_body(verification, MAXIMUM_RESPONSE).await?;
        if status != StatusCode::OK {
            return Err(classify_status(status));
        }
        domain.verification =
            serde_json::from_slice(&body).map_err(|_| IntegrationError::ContractDrift)?;
        Ok(domain)
    }

    pub async fn check(&self, id: Uuid) -> Result<(), IntegrationError> {
        let response = self
            .request(reqwest::Method::POST, self.endpoint(id, Some("check")))
            .json(&json!({}))
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

    pub async fn revoke(&self, id: Uuid) -> Result<(), IntegrationError> {
        let response = self
            .request(reqwest::Method::POST, self.endpoint(id, Some("revoke")))
            .json(&json!({}))
            .with_current_trace_context()
            .send()
            .await
            .map_err(|_| IntegrationError::Unavailable)?;
        if response.status().is_success() || response.status() == StatusCode::NOT_FOUND {
            Ok(())
        } else {
            Err(classify_status(response.status()))
        }
    }

    pub async fn ensure_webhook(
        &self,
        domain_id: Uuid,
        sns_arn: &str,
        name: &str,
    ) -> Result<Uuid, IntegrationError> {
        if sns_arn.len() > 512 || !sns_arn.starts_with("arn:scw:sns:fr-par:") || name.len() > 100 {
            return Err(IntegrationError::ContractDrift);
        }
        let root = Url::parse(WEBHOOK_ROOT).expect("static endpoint");
        let mut list = root.clone();
        let domain = domain_id.to_string();
        list.query_pairs_mut()
            .append_pair("project_id", &self.project_id.to_string())
            .append_pair("domain_id", &domain);
        let response = self
            .request(reqwest::Method::GET, list)
            .with_current_trace_context()
            .send()
            .await
            .map_err(|_| IntegrationError::Unavailable)?;
        let status = response.status();
        let body = bounded_body(response, MAXIMUM_RESPONSE).await?;
        if status != StatusCode::OK {
            return Err(classify_status(status));
        }
        let value: Value =
            serde_json::from_slice(&body).map_err(|_| IntegrationError::ContractDrift)?;
        let matches = value
            .get("webhooks")
            .and_then(Value::as_array)
            .ok_or(IntegrationError::ContractDrift)?
            .iter()
            .filter(|item| {
                item.get("domain_id").and_then(Value::as_str) == Some(domain.as_str())
                    && item.get("name").and_then(Value::as_str) == Some(name)
                    && item.get("sns_arn").and_then(Value::as_str) == Some(sns_arn)
            })
            .collect::<Vec<_>>();
        if matches.len() > 1 {
            return Err(IntegrationError::ContractDrift);
        }
        if let Some(item) = matches.first() {
            return item
                .get("id")
                .and_then(Value::as_str)
                .and_then(|v| Uuid::parse_str(v).ok())
                .ok_or(IntegrationError::ContractDrift);
        }
        let response = self.request(reqwest::Method::POST, root).json(&json!({"domain_id":domain_id,"project_id":self.project_id,"name":name,"event_types":["email_queued","email_dropped","email_deferred","email_delivered","email_spam","email_mailbox_not_found","email_blocklisted"],"sns_arn":sns_arn})).with_current_trace_context().send().await.map_err(|_|IntegrationError::Unavailable)?;
        let status = response.status();
        let body = bounded_body(response, MAXIMUM_RESPONSE).await?;
        if !status.is_success() {
            return Err(classify_status(status));
        }
        serde_json::from_slice::<Value>(&body)
            .ok()
            .and_then(|v| {
                v.get("id")
                    .and_then(Value::as_str)
                    .and_then(|id| Uuid::parse_str(id).ok())
            })
            .ok_or(IntegrationError::ContractDrift)
    }

    pub async fn delete_webhook(&self, id: Uuid) -> Result<(), IntegrationError> {
        let endpoint = Url::parse(&format!("{WEBHOOK_ROOT}/{id}"))
            .map_err(|_| IntegrationError::ContractDrift)?;
        let response = self
            .request(reqwest::Method::DELETE, endpoint)
            .with_current_trace_context()
            .send()
            .await
            .map_err(|_| IntegrationError::Unavailable)?;
        if response.status().is_success() || response.status() == StatusCode::NOT_FOUND {
            Ok(())
        } else {
            Err(classify_status(response.status()))
        }
    }
}

async fn parse_domain(
    response: reqwest::Response,
    verification: Option<Value>,
) -> Result<EmailDomainObservation, IntegrationError> {
    let status = response.status();
    let body = bounded_body(response, MAXIMUM_RESPONSE).await?;
    if !status.is_success() {
        return Err(classify_status(status));
    }
    parse_domain_value(
        &serde_json::from_slice(&body).map_err(|_| IntegrationError::ContractDrift)?,
        verification.unwrap_or_else(|| json!({})),
    )
}

fn parse_domain_value(
    value: &Value,
    verification: Value,
) -> Result<EmailDomainObservation, IntegrationError> {
    let id = value
        .get("id")
        .and_then(Value::as_str)
        .and_then(|v| Uuid::parse_str(v).ok())
        .ok_or(IntegrationError::ContractDrift)?;
    let name = value
        .get("name")
        .or_else(|| value.get("domain_name"))
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty() && v.len() <= 253)
        .ok_or(IntegrationError::ContractDrift)?
        .to_owned();
    let status = value
        .get("status")
        .and_then(Value::as_str)
        .filter(|v| {
            matches!(
                *v,
                "unknown"
                    | "checked"
                    | "unchecked"
                    | "invalid"
                    | "locked"
                    | "revoked"
                    | "pending"
                    | "autoconfiguring"
            )
        })
        .ok_or(IntegrationError::ContractDrift)?
        .to_owned();
    let records = value.get("records").cloned().unwrap_or_else(|| json!({}));
    if !records.is_object() {
        return Err(IntegrationError::ContractDrift);
    }
    Ok(EmailDomainObservation {
        id,
        name,
        status,
        records,
        verification,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_provider_contract() {
        let value = json!({"id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","name":"atelier.fr","status":"pending","records":{"spf":{"name":"atelier.fr","value":"v=spf1"}}});
        let parsed = parse_domain_value(&value, json!({})).unwrap();
        assert_eq!(parsed.name, "atelier.fr");
        assert_eq!(parsed.status, "pending");
    }

    #[test]
    fn domain_member_endpoints_keep_the_domains_collection_segment() {
        let client = ScalewayTemDomainClient::new(
            "a-valid-transactional-email-token".into(),
            Uuid::nil(),
            Duration::from_secs(1),
        )
        .unwrap();
        let id = Uuid::parse_str("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").unwrap();
        assert_eq!(
            client.endpoint(id, None).as_str(),
            "https://api.scaleway.com/transactional-email/v1alpha1/regions/fr-par/domains/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        );
        assert_eq!(
            client.endpoint(id, Some("verification")).as_str(),
            "https://api.scaleway.com/transactional-email/v1alpha1/regions/fr-par/domains/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa/verification"
        );
    }

    #[test]
    fn pooled_transport_keeps_provider_token_and_timeout_request_local() {
        let client = ScalewayTemDomainClient::new(
            "a-valid-transactional-email-token".into(),
            Uuid::nil(),
            Duration::from_secs(23),
        )
        .unwrap();
        let request = client
            .request(reqwest::Method::GET, client.root.clone())
            .build()
            .unwrap();

        assert_eq!(
            request.headers()["x-auth-token"],
            "a-valid-transactional-email-token"
        );
        assert!(request.headers()["x-auth-token"].is_sensitive());
        assert_eq!(request.timeout(), Some(&Duration::from_secs(23)));
    }
}
