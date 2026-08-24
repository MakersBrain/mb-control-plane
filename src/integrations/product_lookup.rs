use std::time::Duration;

use serde_json::{Value, json};
use url::Url;

use crate::domain::IntegrationError;
use crate::outbound_http::TraceRequestBuilderExt as _;

use super::{bounded_body, classify_status};

const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

#[derive(Clone)]
pub struct UpcItemDbClient {
    http: reqwest::Client,
    endpoint: Url,
}

impl UpcItemDbClient {
    pub fn new(endpoint: &str, key: Option<&str>) -> anyhow::Result<Self> {
        let endpoint = Url::parse(endpoint)?;
        if endpoint.scheme() != "https" || endpoint.host_str().is_none() {
            anyhow::bail!("UPCitemDB endpoint must be absolute HTTPS");
        }
        let mut headers = reqwest::header::HeaderMap::new();
        if let Some(key) = key.filter(|value| !value.trim().is_empty()) {
            let mut value = reqwest::header::HeaderValue::from_str(key)?;
            value.set_sensitive(true);
            headers.insert("user_key", value);
            headers.insert("key_type", "3scale".parse()?);
        }
        Ok(Self {
            http: crate::outbound_http::external_api_builder(
                "Makersbrain inventory product lookup",
            )
            .default_headers(headers)
            .timeout(Duration::from_secs(10))
            .build()?,
            endpoint,
        })
    }

    pub async fn lookup(&self, gtin14: &str) -> Result<Vec<Value>, IntegrationError> {
        let mut url = self.endpoint.clone();
        url.query_pairs_mut().append_pair("upc", gtin14);
        let response = self
            .http
            .get(url)
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
        let payload: Value =
            serde_json::from_slice(&body).map_err(|_| IntegrationError::ContractDrift)?;
        normalize_response(&payload, gtin14)
    }
}

fn short(value: Option<&Value>, maximum: usize) -> String {
    value
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim()
        .chars()
        .take(maximum)
        .collect()
}

fn normalize_response(payload: &Value, gtin14: &str) -> Result<Vec<Value>, IntegrationError> {
    let items = payload
        .get("items")
        .and_then(Value::as_array)
        .ok_or(IntegrationError::ContractDrift)?;
    let mut candidates = Vec::new();
    for item in items.iter().take(5) {
        let ean = short(item.get("ean"), 14);
        let upc = short(item.get("upc"), 14);
        let normalized_identifier = normalize_gtin(&ean)
            .or_else(|| normalize_gtin(&upc))
            .filter(|value| value == gtin14);
        if normalized_identifier.is_none() {
            continue;
        }
        let title = short(item.get("title"), 255);
        if title.is_empty() {
            continue;
        }
        let brand = short(item.get("brand"), 120);
        let model = short(item.get("model"), 120);
        let size = short(item.get("size"), 80);
        let weight = short(item.get("weight"), 80);
        let pack = if !size.is_empty() { size } else { weight };
        candidates.push(json!({
            "provider":"upcitemdb",
            "source":"upcitemdb_exact_gtin",
            "canonical_id":format!("upcitemdb:{gtin14}"),
            "barcode":gtin14,
            "label":title,
            "name":title,
            "brand":brand,
            "manufacturer_sku":model,
            "pack":pack,
            "confidence":0.7,
            "grounded":true,
            "explanation":"Exact checksum-valid identifier match; product metadata requires review."
        }));
    }
    Ok(candidates)
}

fn normalize_gtin(value: &str) -> Option<String> {
    if !matches!(value.len(), 8 | 12 | 13 | 14) || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let mut digits = value.bytes().map(|byte| byte - b'0').collect::<Vec<_>>();
    let check = digits.pop()?;
    let mut weight = 3_u32;
    let sum = digits.iter().rev().fold(0_u32, |total, digit| {
        let next = total + u32::from(*digit) * weight;
        weight = if weight == 3 { 1 } else { 3 };
        next
    });
    if ((10 - sum % 10) % 10) as u8 != check {
        return None;
    }
    Some(format!("{value:0>14}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_keeps_only_review_safe_exact_identifier_fields() {
        let result = normalize_response(
            &json!({"items":[{"ean":"097539118054","title":"Mayco glaze","brand":"Mayco",
                "model":"SW-106","size":"1 pint","description":"must not be retained",
                "images":["https://untrusted.example/image"],"offers":[{"price":1}]}]}),
            "00097539118054",
        )
        .unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0]["manufacturer_sku"], "SW-106");
        assert!(result[0].get("description").is_none());
        assert!(result[0].get("images").is_none());
        assert!(result[0].get("offers").is_none());
    }

    #[test]
    fn mismatched_or_invalid_identifiers_are_not_candidates() {
        assert!(normalize_gtin("097539118054").is_some());
        assert!(normalize_gtin("097539118055").is_none());
        assert!(
            normalize_response(
                &json!({"items":[{"ean":"00000000000000","title":"Wrong"}]}),
                "00097539118054",
            )
            .unwrap()
            .is_empty()
        );
    }
}
