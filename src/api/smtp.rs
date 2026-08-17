use super::*;

use serde::Serialize;
use url::Host;

pub(crate) use crate::integrations::odoo::WebshopSmtpStatus as WebshopSmtpResponse;

#[derive(Deserialize, Serialize, ToSchema)]
pub(crate) struct WebshopSmtpBody {
    host: String,
    port: i64,
    encryption: String,
    username: String,
    password: String,
    from_email: String,
}

async fn require_access(
    state: &AppState,
    headers: &HeaderMap,
    workshop: Uuid,
    manage: bool,
) -> ApiResult<()> {
    let who = principal(state, headers).await?;
    let role = authority(state, who.user_id, workshop).await?.0;
    if manage && !role.can_manage_modules() {
        return Err(ApiError::Forbidden);
    }
    let enabled = sqlx::query_scalar::<_, bool>(
        "select exists(select 1 from control.workshop_modules
          where workshop_id=$1 and module_key='webshop' and state='enabled')",
    )
    .bind(workshop)
    .fetch_one(state.store.pool())
    .await?;
    if !enabled {
        return Err(ApiError::Conflict("The webshop module is not enabled"));
    }
    Ok(())
}

async fn odoo(
    state: &AppState,
    workshop: Uuid,
) -> ApiResult<crate::integrations::odoo::OdooClient> {
    let (url, secret_ref, database_ref) = crate::worker::service(&state.store, workshop, "odoo")
        .await
        .map_err(|_| ApiError::Conflict("Odoo SMTP configuration is unavailable"))?;
    let token = crate::worker::secret(&secret_ref)
        .map_err(|_| ApiError::Conflict("Odoo SMTP configuration is unavailable"))?;
    crate::integrations::odoo::OdooClient::new(
        &url,
        &token,
        database_ref.as_deref(),
        state.config.request_timeout,
    )
    .map_err(ApiError::Internal)
}

fn validate(body: &WebshopSmtpBody) -> ApiResult<(String, String)> {
    let host = body.host.trim().trim_end_matches('.').to_ascii_lowercase();
    if !matches!(Host::parse(&host), Ok(Host::Domain(_)))
        || psl::domain_str(&host).is_none()
        || host.ends_with(".local")
        || host.ends_with(".localhost")
        || host.ends_with(".test")
        || host.ends_with(".invalid")
        || !(1..=65535).contains(&body.port)
        || !matches!(body.encryption.as_str(), "starttls" | "ssl")
        || body.username.is_empty()
        || body.username.len() > 320
        || body.password.is_empty()
        || body.password.len() > 512
        || body
            .username
            .chars()
            .chain(body.password.chars())
            .any(|value| matches!(value, '\r' | '\n' | '\0'))
    {
        return Err(ApiError::Validation("SMTP credential payload is invalid"));
    }
    let from_email = normalize_email(&body.from_email).map_err(ApiError::Validation)?;
    Ok((host, from_email))
}

fn no_store(status: WebshopSmtpResponse) -> ApiResult<(HeaderMap, Json<WebshopSmtpResponse>)> {
    let mut headers = HeaderMap::new();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok((headers, Json(status)))
}

pub(super) async fn get(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(workshop): Path<Uuid>,
) -> ApiResult<(HeaderMap, Json<WebshopSmtpResponse>)> {
    require_access(&state, &headers, workshop, false).await?;
    let status = odoo(&state, workshop)
        .await?
        .webshop_smtp_status(&crate::integrations::odoo::WebshopSmtpStatusCommand {
            workshop_id: workshop,
        })
        .await
        .map_err(|_| ApiError::Conflict("Odoo SMTP configuration is unavailable"))?;
    no_store(status)
}

pub(super) async fn configure(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(workshop): Path<Uuid>,
    Json(body): Json<WebshopSmtpBody>,
) -> ApiResult<(HeaderMap, Json<WebshopSmtpResponse>)> {
    let (host, from_email) = validate(&body)?;
    require_access(&state, &headers, workshop, true).await?;
    let key = idempotency(&headers)?;
    let status = odoo(&state, workshop)
        .await?
        .configure_webshop_smtp(&crate::integrations::odoo::WebshopSmtpConfigureCommand {
            operation_key: format!("webshop-smtp:{key}"),
            workshop_id: workshop,
            host,
            port: body.port,
            encryption: body.encryption,
            username: body.username,
            password: body.password,
            from_email,
        })
        .await
        .map_err(|_| ApiError::Conflict("The SMTP connection test failed"))?;
    no_store(status)
}

pub(super) async fn reset(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(workshop): Path<Uuid>,
) -> ApiResult<(HeaderMap, Json<WebshopSmtpResponse>)> {
    require_access(&state, &headers, workshop, true).await?;
    let key = idempotency(&headers)?;
    let status = odoo(&state, workshop)
        .await?
        .reset_webshop_smtp(&crate::integrations::odoo::WebshopSmtpResetCommand {
            operation_key: format!("webshop-smtp-reset:{key}"),
            workshop_id: workshop,
        })
        .await
        .map_err(|_| ApiError::Conflict("Odoo SMTP configuration is unavailable"))?;
    no_store(status)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_certificate_validated_tls_modes_are_accepted() {
        let mut body = WebshopSmtpBody {
            host: "smtp.example.fr".into(),
            port: 587,
            encryption: "starttls".into(),
            username: "orders@example.fr".into(),
            password: "application-password".into(),
            from_email: "orders@example.fr".into(),
        };
        assert!(validate(&body).is_ok());
        body.encryption = "none".into();
        assert!(validate(&body).is_err());
        body.encryption = "ssl".into();
        body.host = "127.0.0.1".into();
        assert!(validate(&body).is_err());
    }

    #[test]
    fn public_status_can_only_report_password_presence() {
        let status = WebshopSmtpResponse {
            transport: "smtp".into(),
            configured: true,
            host: Some("smtp.example.fr".into()),
            port: Some(465),
            encryption: Some("ssl".into()),
            username: Some("orders@example.fr".into()),
            from_email: Some("orders@example.fr".into()),
            password_configured: true,
        };
        let response = serde_json::to_value(status).unwrap();
        assert_eq!(response["password_configured"], true);
        assert!(response.get("password").is_none());
    }
}
