use std::time::Duration;

use reqwest::StatusCode;
use serde_json::{Value, json};

use crate::domain::IntegrationError;
use crate::integrations::{bounded_body, classify_status};

const MAXIMUM_RESPONSE: usize = 256 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsValidationRecord {
    pub record_type: String,
    pub name: String,
    pub value: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustomHostnameObservation {
    pub provider_ref: String,
    pub hostname: String,
    pub hostname_status: String,
    pub certificate_status: String,
    pub validation_records: Vec<DnsValidationRecord>,
    pub error_class: Option<String>,
}

#[derive(Clone)]
pub struct CloudflareCustomHostnameClient {
    http: reqwest::Client,
    token: String,
    zone_id: String,
}

impl CloudflareCustomHostnameClient {
    pub fn new(
        token: String,
        zone_id: String,
        timeout: Duration,
    ) -> Result<Self, IntegrationError> {
        let valid = |value: &str, maximum: usize| {
            (16..=maximum).contains(&value.len())
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        };
        if !valid(&token, 512) || !valid(&zone_id, 64) {
            return Err(IntegrationError::ContractDrift);
        }
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|_| IntegrationError::Unavailable)?;
        Ok(Self {
            http,
            token,
            zone_id,
        })
    }

    fn endpoint(&self, provider_ref: Option<&str>) -> String {
        let root = format!(
            "https://api.cloudflare.com/client/v4/zones/{}/custom_hostnames",
            self.zone_id
        );
        provider_ref.map_or(root.clone(), |id| format!("{root}/{id}"))
    }

    pub async fn create(
        &self,
        hostname: &str,
        workshop: uuid::Uuid,
        domain_id: uuid::Uuid,
    ) -> Result<CustomHostnameObservation, IntegrationError> {
        let response = self
            .http
            .post(self.endpoint(None))
            .bearer_auth(&self.token)
            .json(&json!({
                "hostname":hostname,
                "custom_metadata":{"workshop_id":workshop,"domain_id":domain_id},
                "ssl":{
                    "method":"txt","type":"dv","bundle_method":"ubiquitous",
                    "settings":{"min_tls_version":"1.2","http2":"on","tls_1_3":"on"}
                }
            }))
            .send()
            .await
            .map_err(|_| IntegrationError::Unavailable)?;
        parse_response(response).await
    }

    pub async fn find(
        &self,
        hostname: &str,
    ) -> Result<Option<CustomHostnameObservation>, IntegrationError> {
        let mut endpoint =
            url::Url::parse(&self.endpoint(None)).map_err(|_| IntegrationError::ContractDrift)?;
        endpoint.query_pairs_mut().append_pair("hostname", hostname);
        let response = self
            .http
            .get(endpoint)
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|_| IntegrationError::Unavailable)?;
        let status = response.status();
        let body = bounded_body(response, MAXIMUM_RESPONSE).await?;
        if status != StatusCode::OK {
            return Err(classify_status(status));
        }
        let envelope: Value =
            serde_json::from_slice(&body).map_err(|_| IntegrationError::ContractDrift)?;
        if envelope.get("success").and_then(Value::as_bool) != Some(true) {
            return Err(IntegrationError::Rejected);
        }
        let matches = envelope
            .get("result")
            .and_then(Value::as_array)
            .ok_or(IntegrationError::ContractDrift)?;
        if matches.len() > 1 {
            return Err(IntegrationError::ContractDrift);
        }
        matches
            .first()
            .map(|result| parse_envelope(&json!({"success":true,"result":result})))
            .transpose()
    }

    pub async fn observe(
        &self,
        provider_ref: &str,
    ) -> Result<CustomHostnameObservation, IntegrationError> {
        if provider_ref.len() > 128
            || !provider_ref
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(IntegrationError::ContractDrift);
        }
        let response = self
            .http
            .get(self.endpoint(Some(provider_ref)))
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|_| IntegrationError::Unavailable)?;
        parse_response(response).await
    }

    pub async fn delete(&self, provider_ref: &str) -> Result<(), IntegrationError> {
        if provider_ref.len() > 128
            || !provider_ref
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(IntegrationError::ContractDrift);
        }
        let response = self
            .http
            .delete(self.endpoint(Some(provider_ref)))
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|_| IntegrationError::Unavailable)?;
        match response.status() {
            StatusCode::OK | StatusCode::NO_CONTENT | StatusCode::NOT_FOUND => Ok(()),
            status => Err(classify_status(status)),
        }
    }
}

async fn parse_response(
    response: reqwest::Response,
) -> Result<CustomHostnameObservation, IntegrationError> {
    let status = response.status();
    let body = bounded_body(response, MAXIMUM_RESPONSE).await?;
    if !matches!(status, StatusCode::OK | StatusCode::CREATED) {
        return Err(classify_status(status));
    }
    let envelope: Value =
        serde_json::from_slice(&body).map_err(|_| IntegrationError::ContractDrift)?;
    parse_envelope(&envelope)
}

pub(crate) fn parse_envelope(
    envelope: &Value,
) -> Result<CustomHostnameObservation, IntegrationError> {
    if envelope.get("success").and_then(Value::as_bool) != Some(true) {
        return Err(IntegrationError::Rejected);
    }
    let result = envelope
        .get("result")
        .and_then(Value::as_object)
        .ok_or(IntegrationError::ContractDrift)?;
    let required = |key: &str| {
        result
            .get(key)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty() && value.len() <= 253)
            .map(str::to_owned)
            .ok_or(IntegrationError::ContractDrift)
    };
    let provider_ref = required("id")?;
    let hostname = required("hostname")?;
    let hostname_status = required("status")?;
    let ssl = result
        .get("ssl")
        .and_then(Value::as_object)
        .ok_or(IntegrationError::ContractDrift)?;
    let certificate_status = ssl
        .get("status")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 64)
        .ok_or(IntegrationError::ContractDrift)?
        .to_owned();
    let mut validation_records = Vec::new();
    if let Some(ownership) = result
        .get("ownership_verification")
        .and_then(Value::as_object)
        && let (Some(name), Some(value)) = (
            ownership.get("name").and_then(Value::as_str),
            ownership.get("value").and_then(Value::as_str),
        )
    {
        validation_records.push(DnsValidationRecord {
            record_type: "TXT".into(),
            name: name.to_owned(),
            value: value.to_owned(),
        });
    }
    for record in ssl
        .get("validation_records")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let (record_type, name, value) = if let (Some(name), Some(value)) = (
            record.get("cname").and_then(Value::as_str),
            record.get("cname_target").and_then(Value::as_str),
        ) {
            ("CNAME", name, value)
        } else if let (Some(name), Some(value)) = (
            record.get("txt_name").and_then(Value::as_str),
            record.get("txt_value").and_then(Value::as_str),
        ) {
            ("TXT", name, value)
        } else {
            continue;
        };
        if name.len() <= 253 && value.len() <= 1024 {
            validation_records.push(DnsValidationRecord {
                record_type: record_type.into(),
                name: name.into(),
                value: value.into(),
            });
        }
    }
    validation_records.truncate(8);
    let has_errors = result
        .get("verification_errors")
        .and_then(Value::as_array)
        .is_some_and(|errors| !errors.is_empty())
        || ssl
            .get("validation_errors")
            .and_then(Value::as_array)
            .is_some_and(|errors| !errors.is_empty());
    Ok(CustomHostnameObservation {
        provider_ref,
        hostname,
        hostname_status,
        certificate_status,
        validation_records,
        error_class: has_errors.then(|| "edge_validation_failed".into()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cloudflare_observation_retains_only_actionable_bounded_dns_records() {
        let observation = parse_envelope(&json!({
            "success":true,"result":{
                "id":"023e105f4ecef8ad9ca31a8372d0c353","hostname":"www.atelier-luna.fr",
                "status":"pending","ownership_verification":{"name":"_cf-custom-hostname.www.atelier-luna.fr","value":"host-token"},
                "ssl":{"status":"pending_validation","validation_records":[
                    {"txt_name":"_acme-challenge.www.atelier-luna.fr","txt_value":"cert-token"}
                ],"validation_errors":[]},"verification_errors":[]
            }
        }))
        .unwrap();
        assert_eq!(observation.validation_records.len(), 2);
        assert_eq!(observation.validation_records[0].record_type, "TXT");
        assert_eq!(observation.error_class, None);
    }

    #[test]
    fn cloudflare_error_messages_are_never_projected_into_safe_state() {
        let observation = parse_envelope(&json!({
            "success":true,"result":{
                "id":"023e105f4ecef8ad9ca31a8372d0c353","hostname":"www.atelier-luna.fr",
                "status":"pending","verification_errors":["customer private detail"],
                "ssl":{"status":"validation_timed_out","validation_errors":[{"message":"private provider detail"}]}
            }
        }))
        .unwrap();
        assert_eq!(
            observation.error_class.as_deref(),
            Some("edge_validation_failed")
        );
    }
}
