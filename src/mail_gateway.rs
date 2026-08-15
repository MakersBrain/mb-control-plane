use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::routing::{get, post};
use axum::{Json, Router};
use reqwest::header::{HeaderValue, USER_AGENT};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::sensitive_headers::SetSensitiveRequestHeadersLayer;
use tower_http::trace::TraceLayer;
use url::Url;
use uuid::Uuid;

const SCALEWAY_ENDPOINT: &str =
    "https://api.scaleway.com/transactional-email/v1alpha1/regions/fr-par/emails";

#[derive(Clone)]
pub struct MailGatewayState {
    pub listen: SocketAddr,
    environment: String,
    internal_token: String,
    client: reqwest::Client,
    endpoint: Url,
    project_id: Uuid,
    from_email: String,
    from_name: String,
    allowed_recipients: HashSet<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MailRequest {
    delivery_id: Uuid,
    to: String,
    template: String,
    data: Value,
}

#[derive(Serialize)]
struct Address<'a> {
    email: &'a str,
    name: &'a str,
}

#[derive(Serialize)]
struct ProviderHeader<'a> {
    key: &'a str,
    value: String,
}

#[derive(Serialize)]
struct ProviderRequest<'a> {
    from: Address<'a>,
    to: [Address<'a>; 1],
    subject: String,
    text: String,
    html: String,
    project_id: Uuid,
    additional_headers: [ProviderHeader<'a>; 1],
}

#[derive(Deserialize)]
struct ProviderResponse {
    emails: Vec<ProviderEmail>,
}

#[derive(Deserialize)]
struct ProviderEmail {
    id: String,
}

impl MailGatewayState {
    pub fn from_env() -> anyhow::Result<Self> {
        let required = |name| crate::runtime_secret::required(name).map_err(anyhow::Error::msg);
        let listen = required("MAIL_GATEWAY_LISTEN")?.parse()?;
        let environment = required("MAIL_GATEWAY_ENVIRONMENT")?;
        if !matches!(environment.as_str(), "staging" | "production") {
            anyhow::bail!("MAIL_GATEWAY_ENVIRONMENT must be staging or production");
        }
        let endpoint = Url::parse(&required("MAIL_GATEWAY_SCW_ENDPOINT")?)?;
        if endpoint.as_str() != SCALEWAY_ENDPOINT {
            anyhow::bail!("MAIL_GATEWAY_SCW_ENDPOINT must use the Scaleway Paris TEM endpoint");
        }
        let project_id = required("MAIL_GATEWAY_SCW_PROJECT_ID")?.parse()?;
        let from_email = required("MAIL_GATEWAY_FROM_EMAIL")?.to_ascii_lowercase();
        validate_email(&from_email)?;
        let from_domain = from_email
            .rsplit_once('@')
            .map(|(_, domain)| domain)
            .unwrap_or_default();
        let valid_sender = match environment.as_str() {
            "staging" => from_domain == "notify.staging.makersbrain.net",
            "production" => from_domain == "notify.makersbrain.app",
            _ => false,
        };
        if !valid_sender {
            anyhow::bail!("mail sender does not belong to the environment TEM domain");
        }
        let from_name = required("MAIL_GATEWAY_FROM_NAME")?;
        if from_name.len() > 100 || from_name.chars().any(char::is_control) {
            anyhow::bail!("MAIL_GATEWAY_FROM_NAME is invalid");
        }
        let allowed_recipients = load_recipients(Path::new(&required(
            "MAIL_GATEWAY_ALLOWED_RECIPIENTS_FILE",
        )?))?;
        if environment == "staging" && allowed_recipients.is_empty() {
            anyhow::bail!("staging requires at least one explicitly allowed synthetic recipient");
        }
        let mut provider_token = HeaderValue::from_str(&required("MAIL_GATEWAY_SCW_SECRET_KEY")?)?;
        provider_token.set_sensitive(true);
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("X-Auth-Token", provider_token);
        headers.insert(
            USER_AGENT,
            HeaderValue::from_static("makersbrain-mail-gateway/1"),
        );
        let client = reqwest::Client::builder()
            .default_headers(headers)
            .timeout(Duration::from_secs(20))
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Self {
            listen,
            environment,
            internal_token: required("MAIL_GATEWAY_INTERNAL_TOKEN")?,
            client,
            endpoint,
            project_id,
            from_email,
            from_name,
            allowed_recipients,
        })
    }
}

pub fn app(state: MailGatewayState) -> Router {
    Router::new()
        .route(
            "/health/live",
            get(|| async { Json(json!({"status":"live"})) }),
        )
        .route("/v1/mail", post(send))
        .layer(RequestBodyLimitLayer::new(16 * 1024))
        .layer(SetSensitiveRequestHeadersLayer::new([
            header::AUTHORIZATION,
        ]))
        .layer(TraceLayer::new_for_http().make_span_with(
            |request: &axum::http::Request<axum::body::Body>| {
                tracing::info_span!(
                    "mail_gateway_http_request",
                    http_request_method = %request.method(),
                    http_route = %request.uri().path()
                )
            },
        ))
        .with_state(Arc::new(state))
}

async fn send(
    State(state): State<Arc<MailGatewayState>>,
    headers: HeaderMap,
    Json(request): Json<MailRequest>,
) -> Result<StatusCode, StatusCode> {
    if !authorized(&headers, &state.internal_token) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let recipient = request.to.trim();
    validate_email(recipient).map_err(|_| StatusCode::BAD_REQUEST)?;
    if state.environment == "staging"
        && !state
            .allowed_recipients
            .contains(&recipient.to_ascii_lowercase())
    {
        return Err(StatusCode::FORBIDDEN);
    }
    let (subject, text, html) = render(&request.template, &request.data)?;
    let payload = ProviderRequest {
        from: Address {
            email: &state.from_email,
            name: &state.from_name,
        },
        to: [Address {
            email: recipient,
            name: "",
        }],
        subject,
        text,
        html,
        project_id: state.project_id,
        additional_headers: [ProviderHeader {
            key: "X-MakersBrain-Delivery-ID",
            value: request.delivery_id.to_string(),
        }],
    };
    let response = state
        .client
        .post(state.endpoint.clone())
        .json(&payload)
        .send()
        .await
        .map_err(|error| {
            if error.is_timeout() {
                StatusCode::GATEWAY_TIMEOUT
            } else {
                StatusCode::BAD_GATEWAY
            }
        })?;
    if !response.status().is_success() {
        return Err(StatusCode::BAD_GATEWAY);
    }
    if response
        .content_length()
        .is_some_and(|length| length > 64 * 1024)
    {
        return Err(StatusCode::BAD_GATEWAY);
    }
    let body = response
        .bytes()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;
    if body.len() > 64 * 1024 {
        return Err(StatusCode::BAD_GATEWAY);
    }
    let response: ProviderResponse =
        serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_GATEWAY)?;
    if response.emails.is_empty()
        || response
            .emails
            .iter()
            .any(|email| Uuid::parse_str(&email.id).is_err())
    {
        return Err(StatusCode::BAD_GATEWAY);
    }
    Ok(StatusCode::ACCEPTED)
}

fn render(template: &str, data: &Value) -> Result<(String, String, String), StatusCode> {
    if template != "workshop-invitation" {
        return Err(StatusCode::BAD_REQUEST);
    }
    let object = data.as_object().ok_or(StatusCode::BAD_REQUEST)?;
    let accept_url = object
        .get("accept_url")
        .and_then(Value::as_str)
        .ok_or(StatusCode::BAD_REQUEST)?;
    let parsed = Url::parse(accept_url).map_err(|_| StatusCode::BAD_REQUEST)?;
    if parsed.scheme() != "https"
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.port().is_some()
        || parsed.path() != "/invitations/accept"
        || parsed.query().is_some()
        || parsed.host_str().is_none_or(|host| {
            host != "makersbrain.app"
                && !host.ends_with(".makersbrain.app")
                && host != "staging.makersbrain.net"
                && !host.ends_with(".staging.makersbrain.net")
        })
        || parsed
            .fragment()
            .is_none_or(|fragment| !fragment.starts_with("token=") || fragment.len() < 20)
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let role = object
        .get("role")
        .and_then(Value::as_str)
        .filter(|role| matches!(*role, "owner" | "manager" | "artisan" | "accountant"))
        .ok_or(StatusCode::BAD_REQUEST)?;
    let locale = object.get("locale").and_then(Value::as_str).unwrap_or("fr");
    let (subject, intro, action) = match locale {
        "fr" => (
            "Invitation MakersBrain",
            format!("Vous avez été invité à rejoindre un atelier avec le rôle {role}."),
            "Accepter l’invitation",
        ),
        "en" => (
            "MakersBrain invitation",
            format!("You have been invited to join a workshop with the {role} role."),
            "Accept the invitation",
        ),
        _ => return Err(StatusCode::BAD_REQUEST),
    };
    let text = format!("{intro}\n\n{action}: {accept_url}\n");
    let html = format!(
        "<!doctype html><html><body><p>{}</p><p><a href=\"{}\">{}</a></p></body></html>",
        escape_html(&intro),
        escape_html(accept_url),
        escape_html(action),
    );
    Ok((subject.into(), text, html))
}

fn load_recipients(path: &Path) -> anyhow::Result<HashSet<String>> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.len() > 64 * 1024 {
        anyhow::bail!("recipient allowlist must be a bounded regular file");
    }
    let mut recipients = HashSet::new();
    for line in std::fs::read_to_string(path)?.lines() {
        let recipient = line.trim().to_ascii_lowercase();
        if recipient.is_empty() || !recipients.insert(recipient.clone()) {
            anyhow::bail!("recipient allowlist contains an empty or duplicate entry");
        }
        validate_email(&recipient)?;
    }
    Ok(recipients)
}

fn validate_email(value: &str) -> anyhow::Result<()> {
    if value.len() > 254
        || value.chars().any(char::is_control)
        || value.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        anyhow::bail!("email address is invalid");
    }
    let Some((local, domain)) = value.rsplit_once('@') else {
        anyhow::bail!("email address is invalid");
    };
    if local.is_empty()
        || local.len() > 64
        || domain.is_empty()
        || !domain.contains('.')
        || domain.starts_with('.')
        || domain.ends_with('.')
        || local.starts_with('.')
        || local.ends_with('.')
        || local.contains("..")
        || domain.contains("..")
        || domain
            .split('.')
            .any(|label| label.is_empty() || label.starts_with('-') || label.ends_with('-'))
        || !local
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b".!#$%&'*+/=?^_`{|}~-".contains(&byte))
        || !domain
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
    {
        anyhow::bail!("email address is invalid");
    }
    Ok(())
}

fn authorized(headers: &HeaderMap, expected: &str) -> bool {
    let Some(supplied) = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
    else {
        return false;
    };
    let supplied = supplied.as_bytes();
    let expected = expected.as_bytes();
    let mut difference = supplied.len() ^ expected.len();
    for index in 0..supplied.len().max(expected.len()) {
        difference |= usize::from(
            supplied.get(index).copied().unwrap_or_default()
                ^ expected.get(index).copied().unwrap_or_default(),
        );
    }
    difference == 0
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;
    use wiremock::matchers::{body_partial_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn invitation_template_requires_a_scoped_https_capability() {
        let good = json!({
            "accept_url":"https://staging.makersbrain.net/invitations/accept#token=synthetic-capability-value",
            "role":"artisan",
            "locale":"fr"
        });
        let (_, text, html) = render("workshop-invitation", &good).unwrap();
        assert!(text.contains("https://staging.makersbrain.net/"));
        assert!(html.contains("Accepter l’invitation"));
        let bad = json!({"accept_url":"http://example.test/#token=x","role":"owner"});
        assert_eq!(
            render("workshop-invitation", &bad).unwrap_err(),
            StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn email_validation_rejects_header_injection_and_malformed_domains() {
        assert!(validate_email("synthetic@example.test").is_ok());
        for invalid in [
            "person@example.test\r\nBcc:other@example.test",
            "missing-at",
            "a@localhost",
        ] {
            assert!(validate_email(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn bearer_auth_is_exact() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, "Bearer exact-value".parse().unwrap());
        assert!(authorized(&headers, "exact-value"));
        assert!(!authorized(&headers, "exact-valuE"));
    }

    #[tokio::test]
    async fn authenticated_allowlisted_mail_is_submitted_without_exposing_provider_errors() {
        let provider = MockServer::start().await;
        let provider_id = Uuid::new_v4();
        Mock::given(method("POST"))
            .and(path("/emails"))
            .and(header("X-Auth-Token", "provider-secret"))
            .and(body_partial_json(json!({
                "project_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                "to":[{"email":"Synthetic@Example.test","name":""}],
                "subject":"MakersBrain invitation"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "emails":[{"id":provider_id}]
            })))
            .expect(1)
            .mount(&provider)
            .await;
        let mut provider_token = HeaderValue::from_static("provider-secret");
        provider_token.set_sensitive(true);
        let client = reqwest::Client::builder()
            .default_headers(reqwest::header::HeaderMap::from_iter([(
                reqwest::header::HeaderName::from_static("x-auth-token"),
                provider_token,
            )]))
            .build()
            .unwrap();
        let state = MailGatewayState {
            listen: "127.0.0.1:0".parse().unwrap(),
            environment: "staging".into(),
            internal_token: "internal-secret".into(),
            client,
            endpoint: Url::parse(&format!("{}/emails", provider.uri())).unwrap(),
            project_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".parse().unwrap(),
            from_email: "notifications@notify.staging.makersbrain.net".into(),
            from_name: "MakersBrain".into(),
            allowed_recipients: HashSet::from(["synthetic@example.test".into()]),
        };
        let request = Request::builder()
            .method("POST")
            .uri("/v1/mail")
            .header(header::AUTHORIZATION, "Bearer internal-secret")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({
                    "delivery_id":Uuid::new_v4(),
                    "to":"Synthetic@Example.test",
                    "template":"workshop-invitation",
                    "data":{
                        "accept_url":"https://staging.makersbrain.net/invitations/accept#token=synthetic-capability-value",
                        "role":"artisan",
                        "locale":"en"
                    }
                })
                .to_string(),
            ))
            .unwrap();
        let response = app(state).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
    }
}
