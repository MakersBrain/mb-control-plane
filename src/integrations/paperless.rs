use std::time::Duration;

use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use url::Url;
use uuid::Uuid;

use crate::domain::IntegrationError;

use super::{bounded_body, classify_status};

const MAX_METADATA_BYTES: usize = 512 * 1024;
pub const MAX_DOCUMENT_BYTES: usize = 20 * 1024 * 1024;
const MAX_PRIVACY_EXPORT_BYTES: usize = 96 * 1024 * 1024;
const MAX_PRIVACY_DOCUMENTS: usize = 1000;

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

#[derive(Deserialize)]
struct PaperlessDocument {
    id: i64,
    title: String,
    filename: Option<String>,
    original_file_name: Option<String>,
    #[serde(default)]
    tags: Vec<i64>,
}

fn decode_document(body: &[u8], expected_id: i64) -> Result<Document, IntegrationError> {
    let document: PaperlessDocument =
        serde_json::from_slice(body).map_err(|_| IntegrationError::ContractDrift)?;
    let filename = document
        .filename
        .or(document.original_file_name)
        .filter(|value| !value.trim().is_empty())
        .ok_or(IntegrationError::ContractDrift)?;
    if document.id != expected_id {
        return Err(IntegrationError::ContractDrift);
    }
    Ok(Document {
        id: document.id,
        title: document.title,
        filename,
        tags: document.tags,
    })
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
            .user_agent("mb-invoice-worker")
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
        decode_document(&body, id)
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

    pub async fn export_personal_data(
        &self,
        username: &str,
        workshop_id: Uuid,
        user_id: Uuid,
    ) -> Result<Value, IntegrationError> {
        if username.is_empty() || username.len() > 255 {
            return Err(IntegrationError::ContractDrift);
        }
        let mut users_url = self
            .base_url
            .join("/api/users/")
            .map_err(|_| IntegrationError::ContractDrift)?;
        users_url
            .query_pairs_mut()
            .append_pair("username__iexact", username);
        let response = self
            .http
            .get(users_url)
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
        if users.len() > 1
            || (listing.is_object()
                && listing.get("count").and_then(Value::as_u64) != u64::try_from(users.len()).ok())
        {
            return Err(IntegrationError::ContractDrift);
        }
        let Some(account) = users.first().cloned() else {
            return Ok(json!({
                "format":"mb-paperless-subject-export-v1",
                "workshop_id":workshop_id,"user_id":user_id,"found":false,
                "account":null,"documents":[]
            }));
        };
        if account.get("username").and_then(Value::as_str) != Some(username) {
            return Err(IntegrationError::ContractDrift);
        }
        let owner_id = account
            .get("id")
            .and_then(Value::as_i64)
            .filter(|value| *value > 0)
            .ok_or(IntegrationError::ContractDrift)?;
        let mut first_url = self
            .base_url
            .join("/api/documents/")
            .map_err(|_| IntegrationError::ContractDrift)?;
        first_url
            .query_pairs_mut()
            .append_pair("owner__id", &owner_id.to_string())
            .append_pair("ordering", "id")
            .append_pair("page_size", "100")
            .append_pair("full_perms", "true");
        let first = self.privacy_page(first_url).await?;
        let count = first
            .get("count")
            .and_then(Value::as_u64)
            .and_then(|value| usize::try_from(value).ok())
            .ok_or(IntegrationError::ContractDrift)?;
        if count > MAX_PRIVACY_DOCUMENTS {
            return Err(IntegrationError::TooLarge);
        }
        let pages = count.div_ceil(100).max(1);
        let mut metadata = Vec::with_capacity(count);
        for page in 1..=pages {
            let value = if page == 1 {
                first.clone()
            } else {
                let mut url = self
                    .base_url
                    .join("/api/documents/")
                    .map_err(|_| IntegrationError::ContractDrift)?;
                url.query_pairs_mut()
                    .append_pair("owner__id", &owner_id.to_string())
                    .append_pair("ordering", "id")
                    .append_pair("page_size", "100")
                    .append_pair("full_perms", "true")
                    .append_pair("page", &page.to_string());
                self.privacy_page(url).await?
            };
            let rows = value
                .get("results")
                .and_then(Value::as_array)
                .ok_or(IntegrationError::ContractDrift)?;
            metadata.extend(rows.iter().cloned());
        }
        if metadata.len() != count {
            return Err(IntegrationError::ContractDrift);
        }
        let mut documents = Vec::with_capacity(count);
        let mut previous_id = None;
        let mut approximate_size = serde_json::to_vec(&account)
            .map_err(|_| IntegrationError::ContractDrift)?
            .len();
        for document in metadata {
            let id = document
                .get("id")
                .and_then(Value::as_i64)
                .filter(|value| *value > 0)
                .ok_or(IntegrationError::ContractDrift)?;
            if document.get("owner").and_then(Value::as_i64) != Some(owner_id)
                || previous_id.is_some_and(|previous| id <= previous)
            {
                return Err(IntegrationError::ContractDrift);
            }
            previous_id = Some(id);
            let (mimetype, original) = self.original(id).await?;
            approximate_size = approximate_size
                .checked_add(document.to_string().len())
                .and_then(|value| value.checked_add(original.len().div_ceil(3) * 4))
                .ok_or(IntegrationError::TooLarge)?;
            if approximate_size > MAX_PRIVACY_EXPORT_BYTES {
                return Err(IntegrationError::TooLarge);
            }
            documents.push(json!({
                "metadata":document,"original_mimetype":mimetype,
                "original_base64":base64::engine::general_purpose::STANDARD.encode(original)
            }));
        }
        Ok(json!({
            "format":"mb-paperless-subject-export-v1",
            "workshop_id":workshop_id,"user_id":user_id,"found":true,
            "account":account,"documents":documents
        }))
    }

    async fn privacy_page(&self, url: Url) -> Result<Value, IntegrationError> {
        if url.origin() != self.base_url.origin() {
            return Err(IntegrationError::ContractDrift);
        }
        let response = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|_| IntegrationError::Unavailable)?;
        let status = response.status();
        let body = bounded_body(response, 4 * 1024 * 1024).await?;
        if !status.is_success() {
            return Err(classify_status(status));
        }
        serde_json::from_slice(&body).map_err(|_| IntegrationError::ContractDrift)
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

    /// Removes Paperless account identity and document-owner metadata while
    /// preserving documents that may be subject to the controller's statutory
    /// retention duties. The replacement username is a tombstone pseudonym.
    pub async fn replay_erasure(
        &self,
        username: &str,
        subject_key: Uuid,
    ) -> Result<(), IntegrationError> {
        if username.is_empty() || username.len() > 255 {
            return Err(IntegrationError::ContractDrift);
        }
        let erased_username = format!("erased-{subject_key}");
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
        let Some(user_id) = users
            .first()
            .and_then(|user| user.get("id"))
            .and_then(Value::as_i64)
        else {
            return Ok(());
        };

        let mut processed = 0_usize;
        loop {
            let listing = self
                .json_request(
                    reqwest::Method::GET,
                    &format!("/api/documents/?owner__id={user_id}&page_size=100"),
                    None::<&Value>,
                )
                .await?;
            let documents = listing
                .get("results")
                .and_then(Value::as_array)
                .ok_or(IntegrationError::ContractDrift)?;
            if documents.is_empty() {
                break;
            }
            processed = processed.saturating_add(documents.len());
            if processed > 10_000 {
                return Err(IntegrationError::ContractDrift);
            }
            for document in documents {
                let document_id = document
                    .get("id")
                    .and_then(Value::as_i64)
                    .ok_or(IntegrationError::ContractDrift)?;
                self.json_request(
                    reqwest::Method::PATCH,
                    &format!("/api/documents/{document_id}/"),
                    Some(&json!({"owner":null})),
                )
                .await?;
            }
        }
        self.json_request(
            reqwest::Method::PATCH,
            &format!("/api/users/{user_id}/"),
            Some(&json!({
                "username":erased_username,
                "email":"",
                "first_name":"",
                "last_name":"",
                "is_active":false,
                "is_staff":false,
                "is_superuser":false,
                "groups":[]
            })),
        )
        .await?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_json, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn paperless_original_filename_is_used_when_archive_filename_is_null() {
        let document = decode_document(
            br#"{"id":1,"title":"Phone scan","filename":null,"original_file_name":"invoice.jpg","tags":[]}"#,
            1,
        )
        .unwrap();

        assert_eq!(document.filename, "invoice.jpg");
    }

    #[tokio::test]
    async fn erasure_replay_disables_and_anonymizes_the_processor_account() {
        let server = MockServer::start().await;
        let subject_key = Uuid::new_v4();
        Mock::given(method("GET"))
            .and(path("/api/users/"))
            .and(query_param("username__iexact", "rauthy-subject"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "count":1,"results":[{"id":42,"username":"rauthy-subject"}]
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/documents/"))
            .and(query_param("owner__id", "42"))
            .and(query_param("page_size", "100"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "count":0,"next":null,"results":[]
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path("/api/users/42/"))
            .and(body_json(json!({
                "username":format!("erased-{subject_key}"),
                "email":"","first_name":"","last_name":"","is_active":false,
                "is_staff":false,"is_superuser":false,"groups":[]
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id":42})))
            .expect(1)
            .mount(&server)
            .await;
        PaperlessClient::new(&server.uri(), "fixture-token", Duration::from_secs(2))
            .unwrap()
            .replay_erasure("rauthy-subject", subject_key)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn privacy_export_is_owner_scoped_and_includes_original_content() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/users/"))
            .and(query_param("username__iexact", "subject-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "count":1,"results":[{"id":42,"username":"subject-1","email":"user@example.test"}]
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/documents/"))
            .and(query_param("owner__id", "42"))
            .and(query_param("ordering", "id"))
            .and(query_param("page_size", "100"))
            .and(query_param("full_perms", "true"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "count":1,"next":null,"results":[{"id":7,"owner":42,"title":"Personal invoice","content":"OCR body"}]
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/documents/7/download/"))
            .and(query_param("original", "true"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/pdf")
                    .set_body_bytes(b"fixture-pdf"),
            )
            .expect(1)
            .mount(&server)
            .await;
        let workshop = Uuid::new_v4();
        let user = Uuid::new_v4();
        let export = PaperlessClient::new(&server.uri(), "fixture-token", Duration::from_secs(2))
            .unwrap()
            .export_personal_data("subject-1", workshop, user)
            .await
            .unwrap();
        assert_eq!(export["workshop_id"], workshop.to_string());
        assert_eq!(export["documents"][0]["metadata"]["content"], "OCR body");
        assert_eq!(
            export["documents"][0]["original_base64"],
            base64::engine::general_purpose::STANDARD.encode(b"fixture-pdf")
        );
    }
}
