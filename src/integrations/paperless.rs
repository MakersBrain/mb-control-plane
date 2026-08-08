use std::time::Duration;

use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use url::Url;

use crate::domain::IntegrationError;

use super::{bounded_body, classify_status};

const MAX_METADATA_BYTES: usize = 512 * 1024;
pub const MAX_DOCUMENT_BYTES: usize = 20 * 1024 * 1024;

#[derive(Clone)]
pub struct PaperlessClient {
    http: reqwest::Client,
    base_url: Url,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Document {
    pub id: i64,
    pub title: String,
    pub filename: String,
    #[serde(default)]
    pub tags: Vec<i64>,
}

impl PaperlessClient {
    pub fn new(base_url: &str, token: &str, timeout: Duration) -> anyhow::Result<Self> {
        let base_url = Url::parse(base_url.trim_end_matches('/'))?;
        if !matches!(base_url.scheme(), "http" | "https") || base_url.host_str().is_none() {
            anyhow::bail!("Paperless URL must be absolute HTTP(S)");
        }
        if token.trim().is_empty() {
            anyhow::bail!("Paperless token is empty");
        }
        let authorization_value = if let Some(credentials) = token.strip_prefix("basic:") {
            format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode(credentials)
            )
        } else {
            format!("Token {token}")
        };
        let mut authorization = reqwest::header::HeaderValue::from_str(&authorization_value)?;
        authorization.set_sensitive(true);
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(reqwest::header::AUTHORIZATION, authorization);
        let http = reqwest::Client::builder()
            .default_headers(headers)
            .timeout(timeout)
            .connect_timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .user_agent("makersbrain-invoice-worker")
            .build()?;
        Ok(Self { http, base_url })
    }

    async fn get(&self, path: &str, maximum: usize) -> Result<(String, Vec<u8>), IntegrationError> {
        let url = self
            .base_url
            .join(path)
            .map_err(|_| IntegrationError::ContractDrift)?;
        let response = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|_| IntegrationError::Unavailable)?;
        let status = response.status();
        let mimetype = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .unwrap_or("application/octet-stream")
            .to_owned();
        let body = bounded_body(response, maximum).await?;
        if !status.is_success() {
            return Err(classify_status(status));
        }
        Ok((mimetype, body))
    }

    pub async fn document(&self, id: i64) -> Result<Document, IntegrationError> {
        let (_, body) = self
            .get(&format!("/api/documents/{id}/"), MAX_METADATA_BYTES)
            .await?;
        let document: Document =
            serde_json::from_slice(&body).map_err(|_| IntegrationError::ContractDrift)?;
        if document.id != id || document.filename.is_empty() {
            return Err(IntegrationError::ContractDrift);
        }
        Ok(document)
    }

    pub async fn original(&self, id: i64) -> Result<(String, Vec<u8>), IntegrationError> {
        let result = self
            .get(
                &format!("/api/documents/{id}/download/?original=true"),
                MAX_DOCUMENT_BYTES,
            )
            .await?;
        if result.1.is_empty() {
            return Err(IntegrationError::ContractDrift);
        }
        Ok(result)
    }

    async fn json_request<T: Serialize>(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<&T>,
    ) -> Result<Value, IntegrationError> {
        let url = self
            .base_url
            .join(path)
            .map_err(|_| IntegrationError::ContractDrift)?;
        let mut request = self.http.request(method, url);
        if let Some(body) = body {
            request = request.json(body);
        }
        let response = request
            .send()
            .await
            .map_err(|_| IntegrationError::Unavailable)?;
        let status = response.status();
        let bytes = bounded_body(response, MAX_METADATA_BYTES).await?;
        if !status.is_success() {
            return Err(classify_status(status));
        }
        if bytes.is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_slice(&bytes).map_err(|_| IntegrationError::ContractDrift)
    }

    /// Reconciles the narrow user shape Paperless exposes. Group ids are
    /// provisioned once and stored in the operation payload; public role names
    /// never become arbitrary Paperless group names.
    pub async fn reconcile_user(
        &self,
        username: &str,
        email: &str,
        active: bool,
        group_ids: &[i64],
        administrator: bool,
    ) -> Result<(), IntegrationError> {
        let mut lookup = self
            .base_url
            .join("/api/users/")
            .map_err(|_| IntegrationError::ContractDrift)?;
        lookup
            .query_pairs_mut()
            .append_pair("username__iexact", username);
        let response = self
            .http
            .get(lookup)
            .send()
            .await
            .map_err(|_| IntegrationError::Unavailable)?;
        let status = response.status();
        let bytes = bounded_body(response, MAX_METADATA_BYTES).await?;
        if !status.is_success() {
            return Err(classify_status(status));
        }
        let listing: Value =
            serde_json::from_slice(&bytes).map_err(|_| IntegrationError::ContractDrift)?;
        let users = listing
            .get("results")
            .and_then(Value::as_array)
            .or_else(|| listing.as_array())
            .ok_or(IntegrationError::ContractDrift)?;
        if users.len() > 1 {
            return Err(IntegrationError::ContractDrift);
        }
        let body = json!({
            "username": username,
            "email": email,
            "is_active": active,
            "groups": group_ids,
            "is_staff": administrator,
            "is_superuser": administrator,
        });
        if let Some(id) = users
            .first()
            .and_then(|user| user.get("id"))
            .and_then(Value::as_i64)
        {
            self.json_request(
                reqwest::Method::PATCH,
                &format!("/api/users/{id}/"),
                Some(&body),
            )
            .await?;
        } else if active {
            self.json_request(reqwest::Method::POST, "/api/users/", Some(&body))
                .await?;
        }
        Ok(())
    }

    pub async fn ensure_groups(&self, names: &[&str]) -> Result<Vec<i64>, IntegrationError> {
        let listing = self
            .json_request(
                reqwest::Method::GET,
                "/api/groups/?page_size=100",
                None::<&Value>,
            )
            .await?;
        let groups = listing
            .get("results")
            .and_then(Value::as_array)
            .or_else(|| listing.as_array())
            .ok_or(IntegrationError::ContractDrift)?;
        let mut ids = Vec::with_capacity(names.len());
        for name in names {
            let matches = groups
                .iter()
                .filter(|group| group.get("name").and_then(Value::as_str) == Some(*name))
                .collect::<Vec<_>>();
            if matches.len() > 1 {
                return Err(IntegrationError::ContractDrift);
            }
            let id = if let Some(group) = matches.first() {
                group
                    .get("id")
                    .and_then(Value::as_i64)
                    .ok_or(IntegrationError::ContractDrift)?
            } else {
                self.json_request(
                    reqwest::Method::POST,
                    "/api/groups/",
                    Some(&json!({"name":name,"permissions":[]})),
                )
                .await?
                .get("id")
                .and_then(Value::as_i64)
                .ok_or(IntegrationError::ContractDrift)?
            };
            ids.push(id);
        }
        Ok(ids)
    }

    pub async fn mark_capture(
        &self,
        document_id: i64,
        tag_ids: &[i64],
    ) -> Result<(), IntegrationError> {
        self.json_request(
            reqwest::Method::PATCH,
            &format!("/api/documents/{document_id}/"),
            Some(&json!({"tags":tag_ids})),
        )
        .await?;
        Ok(())
    }
}
