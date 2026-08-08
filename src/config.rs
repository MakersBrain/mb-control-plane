use std::net::SocketAddr;
use std::time::Duration;

use thiserror::Error;
use url::Url;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("{0} is required")]
    Missing(&'static str),
    #[error("{name} is invalid: {reason}")]
    Invalid { name: &'static str, reason: String },
}

#[derive(Clone)]
pub struct Config {
    pub listen: SocketAddr,
    pub database_url: String,
    pub public_origin: Url,
    pub cors_origin: Url,
    pub oidc_issuer: Url,
    pub oidc_audience: String,
    pub oidc_discovery_url: Url,
    pub tenant_domain: String,
    pub internal_token: String,
    pub allow_self_signup: bool,
    pub request_timeout: Duration,
}

impl Config {
    pub fn database_url() -> Result<String, ConfigError> {
        required("CONTROL_DATABASE_URL")
    }

    pub fn from_env() -> Result<Self, ConfigError> {
        Ok(Self {
            listen: required("CONTROL_LISTEN")?
                .parse()
                .map_err(|error| ConfigError::Invalid {
                    name: "CONTROL_LISTEN",
                    reason: format!("{error}"),
                })?,
            database_url: Self::database_url()?,
            public_origin: trusted_origin("CONTROL_PUBLIC_ORIGIN")?,
            cors_origin: trusted_origin("CONTROL_CORS_ORIGIN")?,
            oidc_issuer: trusted_origin("CONTROL_OIDC_ISSUER")?,
            oidc_audience: required("CONTROL_OIDC_AUDIENCE")?,
            oidc_discovery_url: absolute_url("CONTROL_OIDC_DISCOVERY_URL")?,
            tenant_domain: tenant_domain()?,
            internal_token: required("CONTROL_INTERNAL_TOKEN")?,
            allow_self_signup: std::env::var("CONTROL_ALLOW_SELF_SIGNUP")
                .is_ok_and(|value| value.eq_ignore_ascii_case("true")),
            request_timeout: Duration::from_secs(20),
        })
    }
}

fn tenant_domain() -> Result<String, ConfigError> {
    let value = required("CONTROL_TENANT_DOMAIN")?
        .trim()
        .to_ascii_lowercase();
    if value.len() > 253
        || !value.contains('.') && value != "localhost"
        || value.starts_with('.')
        || value.ends_with('.')
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'.'
        })
    {
        return Err(ConfigError::Invalid {
            name: "CONTROL_TENANT_DOMAIN",
            reason: "must be a lower-case DNS suffix or localhost".into(),
        });
    }
    Ok(value)
}

fn required(name: &'static str) -> Result<String, ConfigError> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or(ConfigError::Missing(name))
}

fn absolute_url(name: &'static str) -> Result<Url, ConfigError> {
    let value = required(name)?;
    let url = Url::parse(&value).map_err(|error| ConfigError::Invalid {
        name,
        reason: error.to_string(),
    })?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err(ConfigError::Invalid {
            name,
            reason: "must be an absolute HTTP(S) URL".into(),
        });
    }
    Ok(url)
}

fn trusted_origin(name: &'static str) -> Result<Url, ConfigError> {
    let url = absolute_url(name)?;
    let loopback_http = url.scheme() == "http"
        && url.host_str().is_some_and(|host| {
            matches!(host, "localhost" | "127.0.0.1" | "::1") || host.ends_with(".localhost")
        });
    if (url.scheme() != "https" && !loopback_http)
        || url.cannot_be_a_base()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(ConfigError::Invalid {
            name,
            reason: "must be a clean HTTPS origin (HTTP is allowed only on loopback)".into(),
        });
    }
    Ok(url)
}
