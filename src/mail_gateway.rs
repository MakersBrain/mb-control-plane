use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use aws_lc_rs::signature::{
    RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY, RSA_PKCS1_2048_8192_SHA256, RsaParameters,
    UnparsedPublicKey,
};
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, header};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine as _;
use reqwest::header::HeaderValue;
use rustls_pki_types::{CertificateDer, UnixTime};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::sensitive_headers::SetSensitiveRequestHeadersLayer;
use tower_http::trace::TraceLayer;
use url::Url;
use uuid::Uuid;
use webpki::{ALL_VERIFICATION_ALGS, EndEntityCert, KeyUsage, anchor_from_trusted_cert};

use crate::outbound_http::TraceRequestBuilderExt as _;

const SCALEWAY_ENDPOINT: &str =
    "https://api.scaleway.com/transactional-email/v1alpha1/regions/fr-par/emails";
const SNS_SIGNING_HOST: &str = "messaging.s3.fr-par.scw.cloud";
const SNS_CONFIRMATION_HOST: &str = "sns.mnq.fr-par.scaleway.com";
const MAX_SNS_BODY: usize = 320 * 1024;
const MAX_CERTIFICATE_BODY: usize = 64 * 1024;
const MAX_EVENT_JOURNAL: u64 = 64 * 1024 * 1024;

#[derive(Clone)]
pub struct MailGatewayState {
    pub listen: SocketAddr,
    environment: String,
    internal_token: String,
    provider_client: reqwest::Client,
    public_client: reqwest::Client,
    control_event_url: Url,
    control_event_token: String,
    endpoint: Url,
    project_id: Uuid,
    domain_id: Uuid,
    from_email: String,
    from_name: String,
    allowed_recipients: HashSet<String>,
    sns_topic_arn: String,
    sns_root_ca: Vec<u8>,
    sns_intermediate_ca: Vec<u8>,
    signer_certificates: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    event_journal: Arc<Mutex<EventJournal>>,
}

struct EventJournal {
    path: PathBuf,
    seen: HashSet<Uuid>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MailRequest {
    delivery_id: Uuid,
    to: String,
    template: String,
    data: Value,
    #[serde(default)]
    sender_name: Option<String>,
    #[serde(default)]
    reply_to: Option<String>,
    #[serde(default)]
    attachments: Vec<MailAttachment>,
    #[serde(default)]
    sender_email: Option<String>,
    #[serde(default)]
    sender_domain_id: Option<Uuid>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MailAttachment {
    name: String,
    content_type: String,
    content_base64: String,
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
struct ProviderAttachment<'a> {
    name: &'a str,
    #[serde(rename = "type")]
    content_type: &'a str,
    content: &'a str,
}

#[derive(Serialize)]
struct ProviderRequest<'a> {
    from: Address<'a>,
    to: [Address<'a>; 1],
    subject: String,
    text: String,
    html: String,
    project_id: Uuid,
    attachments: Vec<ProviderAttachment<'a>>,
    additional_headers: Vec<ProviderHeader<'a>>,
}

#[derive(Deserialize)]
struct ProviderResponse {
    emails: Vec<ProviderEmail>,
}

#[derive(Deserialize)]
struct ProviderEmail {
    id: String,
}

#[derive(Deserialize)]
struct SnsEnvelope {
    #[serde(rename = "Type")]
    kind: String,
    #[serde(rename = "MessageId")]
    message_id: String,
    #[serde(rename = "TopicArn")]
    topic_arn: String,
    #[serde(rename = "Message")]
    message: String,
    #[serde(rename = "Timestamp")]
    timestamp: String,
    #[serde(rename = "SignatureVersion")]
    signature_version: String,
    #[serde(rename = "Signature")]
    signature: String,
    #[serde(rename = "SigningCertURL")]
    signing_cert_url: String,
    #[serde(rename = "Subject", default)]
    subject: Option<String>,
    #[serde(rename = "Token", default)]
    token: Option<String>,
    #[serde(rename = "SubscribeURL", default)]
    subscribe_url: Option<String>,
}

#[derive(Deserialize)]
struct TemEvent {
    id: Uuid,
    #[serde(rename = "type")]
    event_type: String,
    project_id: Uuid,
    domain_id: Uuid,
    created_at: String,
    email_id: Option<Uuid>,
    #[serde(default)]
    email_headers: Vec<TemHeader>,
}

#[derive(Deserialize)]
struct TemHeader {
    key: String,
    value: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct JournalRecord {
    schema_version: u8,
    event_id: Uuid,
    sns_message_id: Uuid,
    email_id: Uuid,
    delivery_id: Uuid,
    #[serde(default)]
    domain_id: Uuid,
    event_type: String,
    created_at: String,
}

impl MailGatewayState {
    pub fn from_env() -> anyhow::Result<Self> {
        let configured =
            |name| crate::runtime_secret::required_configuration(name).map_err(anyhow::Error::msg);
        let secret = |name| crate::runtime_secret::required(name).map_err(anyhow::Error::msg);
        let listen = configured("MAIL_GATEWAY_LISTEN")?.parse()?;
        let environment = configured("MAIL_GATEWAY_ENVIRONMENT")?;
        if !matches!(environment.as_str(), "staging" | "production") {
            anyhow::bail!("MAIL_GATEWAY_ENVIRONMENT must be staging or production");
        }
        let endpoint = Url::parse(&configured("MAIL_GATEWAY_SCW_ENDPOINT")?)?;
        if endpoint.as_str() != SCALEWAY_ENDPOINT {
            anyhow::bail!("MAIL_GATEWAY_SCW_ENDPOINT must use the Scaleway Paris TEM endpoint");
        }
        let project_id = configured("MAIL_GATEWAY_SCW_PROJECT_ID")?.parse()?;
        let domain_id = configured("MAIL_GATEWAY_SCW_DOMAIN_ID")?.parse()?;
        let from_email = configured("MAIL_GATEWAY_FROM_EMAIL")?.to_ascii_lowercase();
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
        let from_name = configured("MAIL_GATEWAY_FROM_NAME")?;
        if from_name.len() > 100 || from_name.chars().any(char::is_control) {
            anyhow::bail!("MAIL_GATEWAY_FROM_NAME is invalid");
        }
        let allowed_recipients = load_recipients(Path::new(&configured(
            "MAIL_GATEWAY_ALLOWED_RECIPIENTS_FILE",
        )?))?;
        if environment == "staging" && allowed_recipients.is_empty() {
            anyhow::bail!("staging requires at least one explicitly allowed synthetic recipient");
        }
        let mut provider_token = HeaderValue::from_str(&secret("MAIL_GATEWAY_SCW_SECRET_KEY")?)?;
        provider_token.set_sensitive(true);
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("X-Auth-Token", provider_token);
        let provider_client = crate::outbound_http::external_api_builder("mb-mail-gateway/1")
            .default_headers(headers)
            .timeout(Duration::from_secs(20))
            .build()?;
        let public_client = crate::outbound_http::external_api_builder("mb-mail-gateway/1")
            .timeout(Duration::from_secs(10))
            .build()?;
        let control_event_url = Url::parse(&configured("MAIL_GATEWAY_CONTROL_EVENT_URL")?)?;
        if !matches!(control_event_url.scheme(), "http" | "https")
            || control_event_url.path() != "/internal/v1/mail-events"
            || control_event_url.query().is_some()
            || control_event_url.fragment().is_some()
        {
            anyhow::bail!(
                "MAIL_GATEWAY_CONTROL_EVENT_URL must select the exact control event route"
            );
        }
        let sns_topic_arn = configured("MAIL_GATEWAY_SNS_TOPIC_ARN")?;
        validate_topic_arn(&sns_topic_arn)?;
        let (sns_root_ca, sns_intermediate_ca) =
            load_sns_trust_chain(Path::new(&configured("MAIL_GATEWAY_SNS_TRUST_CHAIN_FILE")?))?;
        let event_journal = EventJournal::load(PathBuf::from(configured(
            "MAIL_GATEWAY_EVENT_JOURNAL_FILE",
        )?))?;
        Ok(Self {
            listen,
            environment,
            internal_token: secret("MAIL_GATEWAY_INTERNAL_TOKEN")?,
            provider_client,
            public_client,
            control_event_url,
            control_event_token: secret("MAIL_GATEWAY_CONTROL_EVENT_TOKEN")?,
            endpoint,
            project_id,
            domain_id,
            from_email,
            from_name,
            allowed_recipients,
            sns_topic_arn,
            sns_root_ca,
            sns_intermediate_ca,
            signer_certificates: Arc::new(Mutex::new(HashMap::new())),
            event_journal: Arc::new(Mutex::new(event_journal)),
        })
    }
}

pub fn app(state: MailGatewayState) -> Router {
    Router::new()
        .route(
            "/health/live",
            get(|| async { Json(json!({"status":"live"})) }),
        )
        .merge(
            Router::new()
                .route("/v1/mail", post(send))
                .layer(RequestBodyLimitLayer::new(16 * 1024 * 1024)),
        )
        .merge(
            Router::new()
                .route("/v1/mail/events", post(receive_sns_event))
                .layer(RequestBodyLimitLayer::new(MAX_SNS_BODY)),
        )
        .layer(SetSensitiveRequestHeadersLayer::new([
            header::AUTHORIZATION,
        ]))
        .layer(TraceLayer::new_for_http().make_span_with(
            |request: &axum::http::Request<axum::body::Body>| {
                tracing::info_span!(
                    "mail_gateway_http_request",
                    http_request_method = http_method_label(request.method()),
                    http_route = mail_gateway_route_label(request.uri().path())
                )
            },
        ))
        .with_state(Arc::new(state))
}

fn http_method_label(method: &Method) -> &'static str {
    match *method {
        Method::GET => "GET",
        Method::POST => "POST",
        _ => "other",
    }
}

fn mail_gateway_route_label(path: &str) -> &'static str {
    match path {
        "/health/live" => "/health/live",
        "/v1/mail" => "/v1/mail",
        "/v1/mail/events" => "/v1/mail/events",
        _ => "unmatched",
    }
}

async fn send(
    State(state): State<Arc<MailGatewayState>>,
    headers: HeaderMap,
    Json(request): Json<MailRequest>,
) -> Result<(StatusCode, Json<Value>), StatusCode> {
    if !authorized(&headers, &state.internal_token) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let recipient = request.to.trim();
    validate_email(recipient).map_err(|_| StatusCode::BAD_REQUEST)?;
    let sender_name = request.sender_name.as_deref().unwrap_or(&state.from_name);
    if sender_name.is_empty()
        || sender_name.len() > 100
        || sender_name.chars().any(char::is_control)
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    if let Some(reply_to) = request.reply_to.as_deref() {
        validate_email(reply_to).map_err(|_| StatusCode::BAD_REQUEST)?;
    }
    if request.sender_email.is_some() != request.sender_domain_id.is_some() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let from_email = request.sender_email.as_deref().unwrap_or(&state.from_email);
    validate_email(from_email).map_err(|_| StatusCode::BAD_REQUEST)?;
    if request.sender_domain_id.is_some_and(|id| id.is_nil()) {
        return Err(StatusCode::BAD_REQUEST);
    }
    if request.attachments.len() > 5 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut attachment_bytes = 0usize;
    for attachment in &request.attachments {
        if attachment.name.is_empty()
            || attachment.name.len() > 255
            || attachment.name.contains('/')
            || attachment.name.contains('\\')
            || attachment.name.chars().any(char::is_control)
            || attachment.content_type.is_empty()
            || attachment.content_type.len() > 127
            || attachment
                .content_type
                .chars()
                .any(|character| character.is_control() || character.is_ascii_whitespace())
        {
            return Err(StatusCode::BAD_REQUEST);
        }
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&attachment.content_base64)
            .map_err(|_| StatusCode::BAD_REQUEST)?;
        attachment_bytes = attachment_bytes.saturating_add(decoded.len());
    }
    if attachment_bytes > 8 * 1024 * 1024 {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    if state.environment == "staging"
        && !state
            .allowed_recipients
            .contains(&recipient.to_ascii_lowercase())
    {
        return Err(StatusCode::FORBIDDEN);
    }
    let (subject, text, html) = render(&request.template, &request.data)?;
    let mut additional_headers = vec![ProviderHeader {
        key: "X-MakersBrain-Delivery-ID",
        value: request.delivery_id.to_string(),
    }];
    if let Some(reply_to) = request.reply_to.as_deref() {
        additional_headers.push(ProviderHeader {
            key: "Reply-To",
            value: reply_to.to_owned(),
        });
    }
    let payload = ProviderRequest {
        from: Address {
            email: from_email,
            name: sender_name,
        },
        to: [Address {
            email: recipient,
            name: "",
        }],
        subject,
        text,
        html,
        project_id: state.project_id,
        attachments: request
            .attachments
            .iter()
            .map(|attachment| ProviderAttachment {
                name: &attachment.name,
                content_type: &attachment.content_type,
                content: &attachment.content_base64,
            })
            .collect(),
        additional_headers,
    };
    let response = state
        .provider_client
        .post(state.endpoint.clone())
        .json(&payload)
        .with_current_trace_context()
        .send()
        .await
        .map_err(|error| {
            tracing::warn!(
                provider = "scaleway-tem",
                operation = "send-mail",
                outcome = "transport-failure",
                error_class = crate::error_reporting::safe_error_class(&error),
                "mail provider call failed"
            );
            if error.is_timeout() {
                StatusCode::GATEWAY_TIMEOUT
            } else {
                StatusCode::BAD_GATEWAY
            }
        })?;
    if !response.status().is_success() {
        tracing::warn!(
            provider = "scaleway-tem",
            operation = "send-mail",
            outcome = "provider-rejected",
            http_response_status = response.status().as_u16(),
            "mail provider rejected request"
        );
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
    if response.emails.len() != 1 {
        return Err(StatusCode::BAD_GATEWAY);
    }
    let provider_message_id =
        Uuid::parse_str(&response.emails[0].id).map_err(|_| StatusCode::BAD_GATEWAY)?;
    Ok((
        StatusCode::ACCEPTED,
        Json(
            json!({"provider_message_id":provider_message_id,"provider_domain_id":request.sender_domain_id.unwrap_or(state.domain_id)}),
        ),
    ))
}

async fn receive_sns_event(
    State(state): State<Arc<MailGatewayState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, StatusCode> {
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if content_type
        .split(';')
        .next()
        .is_none_or(|value| value.trim() != "application/json")
    {
        return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }
    let envelope: SnsEnvelope =
        serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    validate_sns_headers(&headers, &envelope, &state.sns_topic_arn)?;
    let message_id = validate_sns_envelope(&envelope, &state.sns_topic_arn)?;
    let certificate_url = validate_signing_certificate_url(&envelope.signing_cert_url)?;
    let certificate = signer_certificate(&state, certificate_url).await?;
    verify_signer_certificate(&state, &certificate)?;
    verify_sns_signature(&envelope, &certificate)?;

    match envelope.kind.as_str() {
        "SubscriptionConfirmation" => {
            let confirmation = envelope
                .subscribe_url
                .as_deref()
                .ok_or(StatusCode::BAD_REQUEST)
                .and_then(validate_confirmation_url)?;
            let response = state
                .public_client
                .get(confirmation)
                // This URL originates in a signed provider callback. Do not
                // disclose the gateway's internal trace context back to it.
                .send()
                .await
                .map_err(|error| {
                    tracing::warn!(
                        provider = "scaleway-sns",
                        operation = "confirm-subscription",
                        outcome = "transport-failure",
                        error_class = crate::error_reporting::safe_error_class(&error),
                        "SNS confirmation call failed"
                    );
                    StatusCode::BAD_GATEWAY
                })?;
            if !response.status().is_success()
                || response
                    .content_length()
                    .is_some_and(|length| length > MAX_CERTIFICATE_BODY as u64)
            {
                tracing::warn!(
                    provider = "scaleway-sns",
                    operation = "confirm-subscription",
                    outcome = "invalid-response",
                    http_response_status = response.status().as_u16(),
                    "SNS confirmation response was invalid"
                );
                return Err(StatusCode::BAD_GATEWAY);
            }
            let body = response
                .bytes()
                .await
                .map_err(|_| StatusCode::BAD_GATEWAY)?;
            if body.len() > MAX_CERTIFICATE_BODY {
                return Err(StatusCode::BAD_GATEWAY);
            }
            Ok(StatusCode::NO_CONTENT)
        }
        "Notification" => {
            let record = parse_tem_event(&envelope.message, message_id, &state)?;
            state
                .event_journal
                .lock()
                .await
                .append(record.clone())
                .await
                .map_err(|error| {
                    let (error_classes, error_chain_truncated) =
                        crate::error_reporting::safe_anyhow_chain(&error);
                    tracing::error!(
                        ?error_classes,
                        error_chain_truncated,
                        operation = "append-delivery-event",
                        outcome = "failure",
                        "mail event journal append failed"
                    );
                    StatusCode::INTERNAL_SERVER_ERROR
                })?;
            publish_delivery_event(&state, &record).await?;
            Ok(StatusCode::NO_CONTENT)
        }
        _ => Err(StatusCode::BAD_REQUEST),
    }
}

async fn publish_delivery_event(
    state: &MailGatewayState,
    record: &JournalRecord,
) -> Result<(), StatusCode> {
    let response = state
        .public_client
        .post(state.control_event_url.clone())
        .bearer_auth(&state.control_event_token)
        .json(record)
        .with_current_trace_context()
        .send()
        .await
        .map_err(|error| {
            tracing::warn!(
                provider = "control-plane",
                operation = "publish-delivery-event",
                outcome = "transport-failure",
                error_class = crate::error_reporting::safe_error_class(&error),
                "delivery event publication failed"
            );
            StatusCode::BAD_GATEWAY
        })?;
    if !matches!(
        response.status(),
        StatusCode::CREATED | StatusCode::NO_CONTENT
    ) {
        tracing::warn!(
            provider = "control-plane",
            operation = "publish-delivery-event",
            outcome = "provider-rejected",
            http_response_status = response.status().as_u16(),
            "delivery event publication was rejected"
        );
        return Err(StatusCode::BAD_GATEWAY);
    }
    Ok(())
}

impl EventJournal {
    fn load(path: PathBuf) -> anyhow::Result<Self> {
        if !path.is_absolute() || path.components().any(|part| part.as_os_str() == "..") {
            anyhow::bail!("MAIL_GATEWAY_EVENT_JOURNAL_FILE must be an absolute path without ..");
        }
        let parent = path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("event journal requires a parent directory"))?;
        let parent_metadata = std::fs::symlink_metadata(parent)?;
        if !parent_metadata.file_type().is_dir() {
            anyhow::bail!("event journal parent must be a directory, not a symlink");
        }
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) if !metadata.file_type().is_file() => {
                anyhow::bail!("event journal must not be a symlink or special file");
            }
            Ok(metadata) if metadata.len() > MAX_EVENT_JOURNAL => {
                anyhow::bail!("event journal exceeded its configured bound");
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let mut options = std::fs::OpenOptions::new();
        options.create(true).append(true).read(true);
        let file = options.open(&path)?;
        let metadata = file.metadata()?;
        if !metadata.file_type().is_file() || metadata.len() > MAX_EVENT_JOURNAL {
            anyhow::bail!("event journal must be a bounded regular file");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }
        let mut seen = HashSet::new();
        let contents = std::fs::read_to_string(&path)?;
        for line in contents.lines() {
            if line.is_empty() {
                anyhow::bail!("event journal contains an empty record");
            }
            let record: JournalRecord = serde_json::from_str(line)?;
            if record.schema_version != 1 || !seen.insert(record.event_id) {
                anyhow::bail!("event journal contains an invalid or duplicate record");
            }
        }
        Ok(Self { path, seen })
    }

    async fn append(&mut self, record: JournalRecord) -> anyhow::Result<()> {
        if self.seen.contains(&record.event_id) {
            return Ok(());
        }
        let metadata = tokio::fs::metadata(&self.path).await?;
        if metadata.len() > MAX_EVENT_JOURNAL {
            anyhow::bail!("event journal exceeded its configured bound");
        }
        let mut encoded = serde_json::to_vec(&record)?;
        encoded.push(b'\n');
        if metadata.len().saturating_add(encoded.len() as u64) > MAX_EVENT_JOURNAL {
            anyhow::bail!("event journal has no remaining capacity");
        }
        let mut file = tokio::fs::OpenOptions::new()
            .append(true)
            .open(&self.path)
            .await?;
        file.write_all(&encoded).await?;
        file.sync_data().await?;
        self.seen.insert(record.event_id);
        Ok(())
    }
}

fn validate_sns_headers(
    headers: &HeaderMap,
    envelope: &SnsEnvelope,
    expected_topic: &str,
) -> Result<(), StatusCode> {
    let message_type = headers
        .get("x-amz-sns-message-type")
        .and_then(|value| value.to_str().ok())
        .ok_or(StatusCode::BAD_REQUEST)?;
    let topic = headers
        .get("x-amz-sns-topic-arn")
        .and_then(|value| value.to_str().ok())
        .ok_or(StatusCode::BAD_REQUEST)?;
    if message_type != envelope.kind || topic != expected_topic || topic != envelope.topic_arn {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(())
}

fn validate_sns_envelope(envelope: &SnsEnvelope, expected_topic: &str) -> Result<Uuid, StatusCode> {
    if !matches!(
        envelope.kind.as_str(),
        "Notification" | "SubscriptionConfirmation"
    ) || !matches!(envelope.signature_version.as_str(), "1" | "2")
        || envelope.topic_arn != expected_topic
        || envelope.message.len() > 256 * 1024
        || envelope
            .subject
            .as_ref()
            .is_some_and(|value| value.len() > 100)
        || OffsetDateTime::parse(&envelope.timestamp, &Rfc3339).is_err()
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let message_id = Uuid::parse_str(&envelope.message_id).map_err(|_| StatusCode::BAD_REQUEST)?;
    match envelope.kind.as_str() {
        "Notification" => {
            if envelope.token.is_some() || envelope.subscribe_url.is_some() {
                return Err(StatusCode::BAD_REQUEST);
            }
        }
        "SubscriptionConfirmation" => {
            if envelope
                .token
                .as_ref()
                .is_none_or(|value| value.is_empty() || value.len() > 4096)
                || envelope.subscribe_url.is_none()
                || envelope.subject.is_some()
            {
                return Err(StatusCode::BAD_REQUEST);
            }
        }
        _ => return Err(StatusCode::BAD_REQUEST),
    }
    Ok(message_id)
}

fn validate_signing_certificate_url(value: &str) -> Result<Url, StatusCode> {
    let url = Url::parse(value).map_err(|_| StatusCode::BAD_REQUEST)?;
    let filename = url
        .path()
        .strip_prefix("/fr-par/sns/sns_certificate_")
        .and_then(|value| value.strip_suffix(".crt"));
    if url.scheme() != "https"
        || url.host_str() != Some(SNS_SIGNING_HOST)
        || url.port().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || filename.is_none_or(|value| {
            value.is_empty()
                || value.len() > 128
                || !value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        })
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(url)
}

fn validate_confirmation_url(value: &str) -> Result<Url, StatusCode> {
    let url = Url::parse(value).map_err(|_| StatusCode::BAD_REQUEST)?;
    if url.scheme() != "https"
        || url.host_str() != Some(SNS_CONFIRMATION_HOST)
        || url.port().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.query().is_none()
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(url)
}

async fn signer_certificate(state: &MailGatewayState, url: Url) -> Result<Vec<u8>, StatusCode> {
    if let Some(certificate) = state
        .signer_certificates
        .lock()
        .await
        .get(url.as_str())
        .cloned()
    {
        return Ok(certificate);
    }
    let response = state
        .public_client
        .get(url.clone())
        // Signing-certificate URLs originate in provider callbacks. Their
        // allowlist and signature checks do not make trace disclosure useful.
        .send()
        .await
        .map_err(|error| {
            tracing::warn!(
                provider = "scaleway-sns",
                operation = "fetch-signing-certificate",
                outcome = "transport-failure",
                error_class = crate::error_reporting::safe_error_class(&error),
                "SNS signing certificate fetch failed"
            );
            StatusCode::BAD_GATEWAY
        })?;
    if !response.status().is_success()
        || response
            .content_length()
            .is_some_and(|length| length > MAX_CERTIFICATE_BODY as u64)
    {
        tracing::warn!(
            provider = "scaleway-sns",
            operation = "fetch-signing-certificate",
            outcome = "invalid-response",
            http_response_status = response.status().as_u16(),
            "SNS signing certificate response was invalid"
        );
        return Err(StatusCode::BAD_GATEWAY);
    }
    let body = response.bytes().await.map_err(|error| {
        tracing::warn!(
            provider = "scaleway-sns",
            operation = "read-signing-certificate",
            outcome = "transport-failure",
            error_class = crate::error_reporting::safe_error_class(&error),
            "SNS signing certificate response read failed"
        );
        StatusCode::BAD_GATEWAY
    })?;
    if body.len() > MAX_CERTIFICATE_BODY {
        return Err(StatusCode::BAD_GATEWAY);
    }
    let blocks = pem::parse_many(&body).map_err(|_| StatusCode::BAD_GATEWAY)?;
    if blocks.len() != 1 || blocks[0].tag() != "CERTIFICATE" {
        return Err(StatusCode::BAD_GATEWAY);
    }
    let certificate = blocks[0].contents().to_vec();
    verify_signer_certificate(state, &certificate)?;
    let mut cache = state.signer_certificates.lock().await;
    if cache.len() >= 4
        && let Some(oldest) = cache.keys().next().cloned()
    {
        cache.remove(&oldest);
    }
    cache.insert(url.into(), certificate.clone());
    Ok(certificate)
}

fn verify_signer_certificate(
    state: &MailGatewayState,
    certificate: &[u8],
) -> Result<(), StatusCode> {
    let end_der = CertificateDer::from(certificate);
    let end = EndEntityCert::try_from(&end_der).map_err(|_| StatusCode::BAD_REQUEST)?;
    let root_der = CertificateDer::from(state.sns_root_ca.as_slice());
    let root = anchor_from_trusted_cert(&root_der).map_err(|_| StatusCode::BAD_REQUEST)?;
    let intermediate = CertificateDer::from(state.sns_intermediate_ca.as_slice());
    end.verify_for_usage(
        ALL_VERIFICATION_ALGS,
        &[root],
        &[intermediate],
        UnixTime::now(),
        KeyUsage::server_auth(),
        None,
        None,
    )
    .map_err(|_| StatusCode::BAD_REQUEST)?;
    Ok(())
}

fn verify_sns_signature(envelope: &SnsEnvelope, certificate: &[u8]) -> Result<(), StatusCode> {
    let signature = base64::engine::general_purpose::STANDARD
        .decode(&envelope.signature)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    if signature.len() > 1024 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let end_der = CertificateDer::from(certificate);
    let end = EndEntityCert::try_from(&end_der).map_err(|_| StatusCode::BAD_REQUEST)?;
    verify_rsa(
        sns_signature_algorithm(&envelope.signature_version)?,
        end.subject_public_key_info().as_ref(),
        canonical_sns_message(envelope)?.as_bytes(),
        &signature,
    )
}

fn sns_signature_algorithm(version: &str) -> Result<&'static RsaParameters, StatusCode> {
    match version {
        // Scaleway currently documents and emits SNS SignatureVersion 1.
        "1" => Ok(&RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY),
        "2" => Ok(&RSA_PKCS1_2048_8192_SHA256),
        _ => Err(StatusCode::BAD_REQUEST),
    }
}

fn verify_rsa(
    algorithm: &'static RsaParameters,
    subject_public_key_info: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), StatusCode> {
    UnparsedPublicKey::new(algorithm, subject_public_key_info)
        .verify(message, signature)
        .map_err(|_| StatusCode::UNAUTHORIZED)
}

fn canonical_sns_message(envelope: &SnsEnvelope) -> Result<String, StatusCode> {
    let mut fields = Vec::new();
    match envelope.kind.as_str() {
        "Notification" => {
            fields.push(("Message", envelope.message.as_str()));
            fields.push(("MessageId", envelope.message_id.as_str()));
            if let Some(subject) = envelope.subject.as_deref() {
                fields.push(("Subject", subject));
            }
            fields.push(("Timestamp", envelope.timestamp.as_str()));
            fields.push(("TopicArn", envelope.topic_arn.as_str()));
            fields.push(("Type", envelope.kind.as_str()));
        }
        "SubscriptionConfirmation" => {
            fields.push(("Message", envelope.message.as_str()));
            fields.push(("MessageId", envelope.message_id.as_str()));
            fields.push((
                "SubscribeURL",
                envelope
                    .subscribe_url
                    .as_deref()
                    .ok_or(StatusCode::BAD_REQUEST)?,
            ));
            fields.push(("Timestamp", envelope.timestamp.as_str()));
            fields.push((
                "Token",
                envelope.token.as_deref().ok_or(StatusCode::BAD_REQUEST)?,
            ));
            fields.push(("TopicArn", envelope.topic_arn.as_str()));
            fields.push(("Type", envelope.kind.as_str()));
        }
        _ => return Err(StatusCode::BAD_REQUEST),
    }
    let mut canonical = String::new();
    for (name, value) in fields {
        canonical.push_str(name);
        canonical.push('\n');
        canonical.push_str(value);
        canonical.push('\n');
    }
    Ok(canonical)
}

fn parse_tem_event(
    message: &str,
    sns_message_id: Uuid,
    state: &MailGatewayState,
) -> Result<JournalRecord, StatusCode> {
    let event: TemEvent = serde_json::from_str(message).map_err(|_| StatusCode::BAD_REQUEST)?;
    if event.project_id != state.project_id
        || !matches!(
            event.event_type.as_str(),
            "email_queued"
                | "email_deferred"
                | "email_delivered"
                | "email_dropped"
                | "email_spam"
                | "email_mailbox_not_found"
                | "email_blocklisted"
        )
        || event.email_headers.len() > 100
        || OffsetDateTime::parse(&event.created_at, &Rfc3339).is_err()
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let email_id = event.email_id.ok_or(StatusCode::BAD_REQUEST)?;
    let mut delivery_id = None;
    for item in event.email_headers {
        if item.key.len() > 256 || item.value.len() > 4096 {
            return Err(StatusCode::BAD_REQUEST);
        }
        if item.key.eq_ignore_ascii_case("X-MakersBrain-Delivery-ID") {
            if delivery_id.is_some() {
                return Err(StatusCode::BAD_REQUEST);
            }
            delivery_id = Some(Uuid::parse_str(&item.value).map_err(|_| StatusCode::BAD_REQUEST)?);
        }
    }
    Ok(JournalRecord {
        schema_version: 1,
        event_id: event.id,
        sns_message_id,
        email_id,
        delivery_id: delivery_id.ok_or(StatusCode::BAD_REQUEST)?,
        domain_id: event.domain_id,
        event_type: event.event_type,
        created_at: event.created_at,
    })
}

fn validate_topic_arn(value: &str) -> anyhow::Result<()> {
    let parts = value.split(':').collect::<Vec<_>>();
    if parts.len() != 6
        || parts[0..4] != ["arn", "scw", "sns", "fr-par"]
        || Uuid::parse_str(parts[4]).is_err()
        || parts[5].is_empty()
        || value.len() > 512
        || value.chars().any(char::is_control)
    {
        anyhow::bail!("MAIL_GATEWAY_SNS_TOPIC_ARN must be an exact Scaleway fr-par topic ARN");
    }
    Ok(())
}

fn load_sns_trust_chain(path: &Path) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_CERTIFICATE_BODY as u64 {
        anyhow::bail!("SNS trust chain must be a bounded regular file");
    }
    let blocks = pem::parse_many(std::fs::read(path)?)?;
    if blocks.len() != 2 || blocks.iter().any(|block| block.tag() != "CERTIFICATE") {
        anyhow::bail!("SNS trust chain must contain the Scaleway root then intermediate CA");
    }
    Ok((blocks[0].contents().to_vec(), blocks[1].contents().to_vec()))
}

fn render(template: &str, data: &Value) -> Result<(String, String, String), StatusCode> {
    if template == "odoo-rendered-v1" {
        let object = data.as_object().ok_or(StatusCode::BAD_REQUEST)?;
        if object.len() != 3
            || !object.contains_key("subject")
            || !object.contains_key("text")
            || !object.contains_key("html")
        {
            return Err(StatusCode::BAD_REQUEST);
        }
        let subject = object
            .get("subject")
            .and_then(Value::as_str)
            .filter(|value| {
                !value.trim().is_empty()
                    && value.len() <= 255
                    && !value.chars().any(char::is_control)
            })
            .ok_or(StatusCode::BAD_REQUEST)?;
        let text = object
            .get("text")
            .and_then(Value::as_str)
            .filter(|value| value.len() <= 256 * 1024 && !value.contains('\0'))
            .ok_or(StatusCode::BAD_REQUEST)?;
        let html = object
            .get("html")
            .and_then(Value::as_str)
            .filter(|value| value.len() <= 512 * 1024 && !value.contains('\0'))
            .ok_or(StatusCode::BAD_REQUEST)?;
        if text.trim().is_empty() && html.trim().is_empty() {
            return Err(StatusCode::BAD_REQUEST);
        }
        return Ok((subject.to_owned(), text.to_owned(), html.to_owned()));
    }
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
    use axum::body::{Body, to_bytes};
    use axum::http::Request;
    use tower::ServiceExt;
    use tracing::field::{Field, Visit};
    use tracing::{Event, Subscriber};
    use tracing_subscriber::Layer;
    use tracing_subscriber::layer::SubscriberExt as _;
    use wiremock::matchers::{body_partial_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[derive(Clone, Default)]
    struct RecordedLogs(Arc<std::sync::Mutex<Vec<String>>>);

    struct LogVisitor<'a>(&'a mut String);

    impl Visit for LogVisitor<'_> {
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            use std::fmt::Write as _;
            let _ = write!(self.0, "{}={value:?};", field.name());
        }
    }

    impl<S: Subscriber> Layer<S> for RecordedLogs {
        fn on_new_span(
            &self,
            attributes: &tracing::span::Attributes<'_>,
            _id: &tracing::span::Id,
            _context: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let mut rendered = format!("span={};", attributes.metadata().name());
            attributes.record(&mut LogVisitor(&mut rendered));
            self.0.lock().unwrap().push(rendered);
        }

        fn on_event(&self, event: &Event<'_>, _context: tracing_subscriber::layer::Context<'_, S>) {
            let mut rendered = String::new();
            event.record(&mut LogVisitor(&mut rendered));
            self.0.lock().unwrap().push(rendered);
        }
    }

    fn test_state(endpoint: Url, provider_client: reqwest::Client) -> MailGatewayState {
        let journal_directory =
            std::env::temp_dir().join(format!("mb-mail-gateway-test-{}", Uuid::new_v4()));
        std::fs::create_dir(&journal_directory).unwrap();
        MailGatewayState {
            listen: "127.0.0.1:0".parse().unwrap(),
            environment: "staging".into(),
            internal_token: "internal-secret".into(),
            provider_client,
            public_client: reqwest::Client::new(),
            control_event_url: Url::parse("http://127.0.0.1/internal/v1/mail-events").unwrap(),
            control_event_token: "control-event-secret".into(),
            endpoint,
            project_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".parse().unwrap(),
            domain_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb".parse().unwrap(),
            from_email: "notifications@notify.staging.makersbrain.net".into(),
            from_name: "MakersBrain".into(),
            allowed_recipients: HashSet::from(["synthetic@example.test".into()]),
            sns_topic_arn: "arn:scw:sns:fr-par:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa:mb-staging-tem"
                .into(),
            sns_root_ca: Vec::new(),
            sns_intermediate_ca: Vec::new(),
            signer_certificates: Arc::new(Mutex::new(HashMap::new())),
            event_journal: Arc::new(Mutex::new(
                EventJournal::load(journal_directory.join("events.jsonl")).unwrap(),
            )),
        }
    }

    fn notification_envelope() -> SnsEnvelope {
        SnsEnvelope {
            kind: "Notification".into(),
            message_id: "cccccccc-cccc-4ccc-8ccc-cccccccccccc".into(),
            topic_arn: "arn:scw:sns:fr-par:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa:mb-staging-tem"
                .into(),
            message: "payload".into(),
            timestamp: "2026-08-15T12:00:00Z".into(),
            signature_version: "1".into(),
            signature: "signature".into(),
            signing_cert_url:
                "https://messaging.s3.fr-par.scw.cloud/fr-par/sns/sns_certificate_123.crt".into(),
            subject: Some("delivery".into()),
            token: None,
            subscribe_url: None,
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn request_tracing_never_records_mail_secrets_or_personal_content() {
        const TOKEN: &str = "mail-bearer-canary-never-log";
        const EMAIL: &str = "private-mail-canary@example.test";
        const PAYLOAD: &str = "mail-payload-and-model-result-canary";
        const SECRET_PATH: &str = "/run/secrets/mail-signing-key-canary";

        let recorded = RecordedLogs::default();
        let subscriber = tracing_subscriber::registry().with(recorded.clone());
        let _subscriber = tracing::subscriber::set_default(subscriber);
        let provider = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/emails"))
            .respond_with(ResponseTemplate::new(502).set_body_json(json!({
                "token": TOKEN,
                "recipient": EMAIL,
                "provider_detail": PAYLOAD,
                "certificate_path": SECRET_PATH
            })))
            .expect(1)
            .mount(&provider)
            .await;
        let mut state = test_state(
            Url::parse(&format!("{}/emails", provider.uri())).unwrap(),
            reqwest::Client::new(),
        );
        state.internal_token = TOKEN.into();
        let router = app(state);
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/v1/mail")
                    .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({
                            "delivery_id": Uuid::new_v4(),
                            "to": "synthetic@example.test",
                            "template": "odoo-rendered-v1",
                            "reply_to": EMAIL,
                            "data": {
                                "subject": "Safe bounded subject",
                                "text": PAYLOAD,
                                "html": format!("<p>{SECRET_PATH}</p>")
                            }
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        let unmatched = router
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(SECRET_PATH)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unmatched.status(), StatusCode::NOT_FOUND);

        let rendered = recorded.0.lock().unwrap().join("\n");
        assert!(rendered.contains("mail_gateway_http_request"));
        assert!(rendered.contains("/v1/mail"));
        assert!(rendered.contains("unmatched"));
        for canary in [TOKEN, EMAIL, PAYLOAD, SECRET_PATH] {
            assert!(
                !rendered.contains(canary),
                "logged private canary: {canary}"
            );
        }
    }

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
    fn odoo_rendered_template_is_exact_and_bounded() {
        let content = json!({
            "subject":"Order confirmed",
            "text":"Your order is confirmed.",
            "html":"<p>Your order is confirmed.</p>"
        });
        assert_eq!(
            render("odoo-rendered-v1", &content).unwrap(),
            (
                "Order confirmed".into(),
                "Your order is confirmed.".into(),
                "<p>Your order is confirmed.</p>".into()
            )
        );
        assert!(
            render(
                "odoo-rendered-v1",
                &json!({
                    "subject":"Order confirmed", "text":"body", "html":"", "extra":"no"
                })
            )
            .is_err()
        );
        assert!(
            render(
                "odoo-rendered-v1",
                &json!({
                    "subject":"Order\r\nBcc: victim@example.test", "text":"body", "html":""
                })
            )
            .is_err()
        );
        assert!(
            render(
                "odoo-rendered-v1",
                &json!({
                    "subject":"Order confirmed", "text":"", "html":""
                })
            )
            .is_err()
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

    #[test]
    fn topic_arn_is_exactly_scoped_to_scaleway_paris() {
        assert!(
            validate_topic_arn(
                "arn:scw:sns:fr-par:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa:mail-events"
            )
            .is_ok()
        );
        for invalid in [
            "arn:aws:sns:fr-par:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa:mail-events",
            "arn:scw:sns:nl-ams:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa:mail-events",
            "arn:scw:sns:fr-par:not-a-uuid:mail-events",
            "arn:scw:sns:fr-par:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa:",
        ] {
            assert!(validate_topic_arn(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn sns_urls_are_pinned_to_expected_https_origins() {
        assert!(
            validate_signing_certificate_url(
                "https://messaging.s3.fr-par.scw.cloud/fr-par/sns/sns_certificate_123.crt"
            )
            .is_ok()
        );
        assert!(
            validate_confirmation_url(
                "https://sns.mnq.fr-par.scaleway.com/?Action=ConfirmSubscription&Token=bound"
            )
            .is_ok()
        );
        for invalid in [
            "http://messaging.s3.fr-par.scw.cloud/fr-par/sns/sns_certificate_123.crt",
            "https://messaging.s3.fr-par.scw.cloud.evil.test/fr-par/sns/sns_certificate_123.crt",
            "https://messaging.s3.fr-par.scw.cloud/fr-par/sns/../sns_certificate_123.crt",
            "https://messaging.s3.fr-par.scw.cloud/fr-par/sns/sns_certificate_123.crt?redirect=x",
        ] {
            assert!(
                validate_signing_certificate_url(invalid).is_err(),
                "{invalid}"
            );
        }
        for invalid in [
            "http://sns.mnq.fr-par.scaleway.com/?Action=ConfirmSubscription",
            "https://sns.mnq.fr-par.scaleway.com.evil.test/?Action=ConfirmSubscription",
            "https://sns.mnq.fr-par.scaleway.com/",
        ] {
            assert!(validate_confirmation_url(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn bundled_scaleway_paris_trust_chain_is_parseable() {
        // A fixture, not the deployed file: the trust chain is mounted by the
        // Quadlet in mb-infra and its path comes from
        // MAIL_GATEWAY_SNS_TRUST_CHAIN_FILE. This asserts the parser handles a
        // real Scaleway chain, which is this repository's concern.
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("test-fixtures/scaleway-sns-fr-par-trust-chain.pem");
        let (root, intermediate) = load_sns_trust_chain(&path).unwrap();
        assert!(anchor_from_trusted_cert(&CertificateDer::from(root)).is_ok());
        assert!(EndEntityCert::try_from(&CertificateDer::from(intermediate)).is_ok());
    }

    #[test]
    fn sns_notification_canonical_form_is_stable() {
        let envelope = notification_envelope();
        assert_eq!(
            canonical_sns_message(&envelope).unwrap(),
            concat!(
                "Message\npayload\n",
                "MessageId\ncccccccc-cccc-4ccc-8ccc-cccccccccccc\n",
                "Subject\ndelivery\n",
                "Timestamp\n2026-08-15T12:00:00Z\n",
                "TopicArn\narn:scw:sns:fr-par:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa:mb-staging-tem\n",
                "Type\nNotification\n"
            )
        );
    }

    #[test]
    fn sns_signature_versions_dispatch_explicitly() {
        use aws_lc_rs::rand::SystemRandom;
        use aws_lc_rs::rsa::KeySize;
        use aws_lc_rs::signature::{KeyPair, RSA_PKCS1_SHA256, RsaKeyPair};

        let key_pair = RsaKeyPair::generate(KeySize::Rsa2048).unwrap();
        let message = canonical_sns_message(&notification_envelope()).unwrap();
        let mut signature = vec![0; key_pair.public_modulus_len()];
        key_pair
            .sign(
                &RSA_PKCS1_SHA256,
                &SystemRandom::new(),
                message.as_bytes(),
                &mut signature,
            )
            .unwrap();
        assert!(
            verify_rsa(
                sns_signature_algorithm("2").unwrap(),
                key_pair.public_key().as_ref(),
                message.as_bytes(),
                &signature,
            )
            .is_ok()
        );
        assert_eq!(
            verify_rsa(
                sns_signature_algorithm("1").unwrap(),
                key_pair.public_key().as_ref(),
                message.as_bytes(),
                &signature,
            )
            .unwrap_err(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            sns_signature_algorithm("3").unwrap_err(),
            StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn sns_rsa_sha1_signature_is_verified_and_tampering_is_rejected() {
        // Fixed test-only RSA material generated for this canonical SNS fixture.
        let subject_public_key_info = base64::engine::general_purpose::STANDARD
            .decode("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAo8toNBGSGoRdr6d0doEc+iIB3pMmRiokiKTCCUiaD5ZxPEnWTnLT48tzCln37ptIEAJT11ATdUJwXg15apng7UMvWvLT2kVZ6bnbUZHDjMimT8VDBlVKYJ5lY3DW2jMMVOaXzOTTTbbnoDmihCbjOBNgrVmmxDV+0LF1mxBVnUy32hxeZSgBSkoyzX2EccyDmfJHWlluQCNqqHxLnBsNBuj+5HPPztQTIOE3eE/KdRkXJU/7lvHJwaOeN07g+ec/Wx7x3PHsHEq/zdqKP7KEpjnlkMliKAoVCLyjis2yMYXOg+v0codf8Is+4vF7P0D3faq9KMgcrDHvHl+SAgbwrQIDAQAB")
            .unwrap();
        let signature = base64::engine::general_purpose::STANDARD
            .decode("KzrjArwgyfnBODbTDf2SGfP2Egr3C6HT9ebKXtycbW+7WbhT8sawifj5cL5KlMcQzxS3yUlUOc0H6zB8PBy1SaaIOp1rMsw2Kw701w0yX48is25i4vRigDb6CBz5yYNOPYkNPQKcE+HpVtKDu7iMkueXVhOMkhddAdC5aqUNCDzaH8DnoFxw4OvuytvwnL77oydheubNVyR2SF7hGQTV8xiAVrwj5yvIHlFnmwsVXLIHskBJImm+CWlVFZdbJYSe+jOec6J0Nhvv4edDSaRjm89zTo8+oZB/9+ck2qzNvm5VCkf5rL0R9ep8LXfnGBIeEVGguJd137lv1MVr48pLtw==")
            .unwrap();
        let canonical = canonical_sns_message(&notification_envelope()).unwrap();
        assert!(
            verify_rsa(
                sns_signature_algorithm("1").unwrap(),
                &subject_public_key_info,
                canonical.as_bytes(),
                &signature,
            )
            .is_ok()
        );
        assert_eq!(
            verify_rsa(
                sns_signature_algorithm("1").unwrap(),
                &subject_public_key_info,
                b"tampered",
                &signature,
            )
            .unwrap_err(),
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn tem_event_is_scoped_and_journaled_once_without_personal_data() {
        let state = test_state(
            Url::parse("http://127.0.0.1/emails").unwrap(),
            reqwest::Client::new(),
        );
        let event_id = Uuid::new_v4();
        let email_id = Uuid::new_v4();
        let delivery_id = Uuid::new_v4();
        let message = json!({
            "id": event_id,
            "type": "email_delivered",
            "project_id": state.project_id,
            "domain_id": state.domain_id,
            "created_at": "2026-08-15T12:00:00Z",
            "email_id": email_id,
            "email_headers": [
                {"key":"X-MakersBrain-Delivery-ID", "value":delivery_id},
                {"key":"To", "value":"private-person@example.test"}
            ]
        })
        .to_string();
        let record = parse_tem_event(&message, Uuid::new_v4(), &state).unwrap();
        let path = state.event_journal.lock().await.path.clone();
        let mut journal = state.event_journal.lock().await;
        journal.append(record).await.unwrap();
        let duplicate = parse_tem_event(&message, Uuid::new_v4(), &state).unwrap();
        journal.append(duplicate).await.unwrap();
        drop(journal);

        let persisted = std::fs::read_to_string(path).unwrap();
        assert_eq!(persisted.lines().count(), 1);
        assert!(persisted.contains(&delivery_id.to_string()));
        assert!(!persisted.contains("private-person"));

        let wrong_domain = message.replace(
            &state.domain_id.to_string(),
            "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
        );
        assert_ne!(
            parse_tem_event(&wrong_domain, Uuid::new_v4(), &state)
                .unwrap()
                .domain_id,
            state.domain_id
        );
    }

    #[tokio::test]
    async fn delivery_event_is_projected_with_a_separate_exact_bearer() {
        let control = MockServer::start().await;
        let event = JournalRecord {
            schema_version: 1,
            event_id: Uuid::new_v4(),
            sns_message_id: Uuid::new_v4(),
            email_id: Uuid::new_v4(),
            delivery_id: Uuid::new_v4(),
            domain_id: Uuid::new_v4(),
            event_type: "email_spam".into(),
            created_at: "2026-08-15T12:00:00Z".into(),
        };
        Mock::given(method("POST"))
            .and(path("/internal/v1/mail-events"))
            .and(header("authorization", "Bearer control-event-secret"))
            .and(body_partial_json(json!({
                "event_id":event.event_id,
                "email_id":event.email_id,
                "delivery_id":event.delivery_id,
                "event_type":"email_spam"
            })))
            .respond_with(ResponseTemplate::new(201))
            .expect(1)
            .mount(&control)
            .await;
        let mut state = test_state(
            Url::parse("http://127.0.0.1/emails").unwrap(),
            reqwest::Client::new(),
        );
        state.control_event_url =
            Url::parse(&format!("{}/internal/v1/mail-events", control.uri())).unwrap();
        publish_delivery_event(&state, &event).await.unwrap();
    }

    #[tokio::test]
    async fn authenticated_allowlisted_mail_is_submitted_without_exposing_provider_errors() {
        let provider = MockServer::start().await;
        let provider_id = Uuid::new_v4();
        let delivery_id = Uuid::new_v4();
        Mock::given(method("POST"))
            .and(path("/emails"))
            .and(header("X-Auth-Token", "provider-secret"))
            .and(body_partial_json(json!({
                "project_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                "from":{"email":"notifications@notify.staging.makersbrain.net","name":"Atelier Luna via MakersBrain"},
                "to":[{"email":"Synthetic@Example.test","name":""}],
                "subject":"Order confirmed",
                "attachments":[{"name":"receipt.pdf","type":"application/pdf","content":"cGRm"}],
                "additional_headers":[
                    {"key":"X-MakersBrain-Delivery-ID","value":delivery_id},
                    {"key":"Reply-To","value":"studio@example.test"}
                ]
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
        let state = test_state(
            Url::parse(&format!("{}/emails", provider.uri())).unwrap(),
            client,
        );
        let request = Request::builder()
            .method("POST")
            .uri("/v1/mail")
            .header(header::AUTHORIZATION, "Bearer internal-secret")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({
                    "delivery_id":delivery_id,
                    "to":"Synthetic@Example.test",
                    "template":"odoo-rendered-v1",
                    "data":{
                        "subject":"Order confirmed",
                        "text":"Your order is confirmed.",
                        "html":"<p>Your order is confirmed.</p>"
                    },
                    "sender_name":"Atelier Luna via MakersBrain",
                    "reply_to":"studio@example.test",
                    "attachments":[{
                        "name":"receipt.pdf",
                        "content_type":"application/pdf",
                        "content_base64":"cGRm"
                    }]
                })
                .to_string(),
            ))
            .unwrap();
        let response = app(state).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap(),
            json!({"provider_message_id":provider_id,"provider_domain_id":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"})
        );
    }
}
