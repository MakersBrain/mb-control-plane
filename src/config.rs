use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::PathBuf;
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
    tenant_public_port: Option<u16>,
    pub internal_token: String,
    pub metrics_token: String,
    pub mail_event_token: String,
    pub release_publish_token: String,
    pub invitation_verification_keys_file: PathBuf,
    pub invitation_signing_key_id: String,
    pub deployment_driver_url: Url,
    pub deployment_driver_token: String,
    pub allow_self_signup: bool,
    pub operator_emails: HashSet<String>,
    pub request_timeout: Duration,
    pub synthetic_data_only: bool,
}

impl Config {
    pub fn database_url() -> Result<String, ConfigError> {
        required_secret("CONTROL_DATABASE_URL")
    }

    pub fn synthetic_data_only() -> Result<bool, ConfigError> {
        data_mode(&required("CONTROL_DATA_MODE")?)
    }

    pub fn from_env() -> Result<Self, ConfigError> {
        // The metrics credential exists so that Prometheus, which holds it on
        // disk in its own container, cannot call the internal API. Reusing the
        // internal token here would hand it exactly that, silently.
        let internal_token = required_secret("CONTROL_INTERNAL_TOKEN")?;
        let metrics_token = required_secret("CONTROL_METRICS_TOKEN")?;
        distinct_secret(
            "CONTROL_METRICS_TOKEN",
            &metrics_token,
            "CONTROL_INTERNAL_TOKEN",
            &internal_token,
        )?;
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
            tenant_public_port: optional_port("CONTROL_TENANT_PUBLIC_PORT")?,
            internal_token,
            metrics_token,
            mail_event_token: required_secret("CONTROL_MAIL_EVENT_TOKEN")?,
            release_publish_token: required_secret("CONTROL_RELEASE_PUBLISH_TOKEN")?,
            invitation_verification_keys_file: PathBuf::from(required(
                "CONTROL_INVITATION_VERIFICATION_KEYS_FILE",
            )?),
            invitation_signing_key_id: required("CONTROL_INVITATION_SIGNING_KEY_ID")?,
            deployment_driver_url: absolute_url("CONTROL_DEPLOYMENT_DRIVER_URL")?,
            deployment_driver_token: required_secret("CONTROL_DEPLOYMENT_DRIVER_TOKEN")?,
            allow_self_signup: std::env::var("CONTROL_ALLOW_SELF_SIGNUP")
                .is_ok_and(|value| value.eq_ignore_ascii_case("true")),
            operator_emails: std::env::var("CONTROL_OPERATOR_EMAILS")
                .unwrap_or_default()
                .split(',')
                .map(|value| value.trim().to_ascii_lowercase())
                .filter(|value| !value.is_empty())
                .collect(),
            request_timeout: Duration::from_secs(20),
            synthetic_data_only: Self::synthetic_data_only()?,
        })
    }

    pub(crate) fn tenant_origin(&self, hostname: &str) -> String {
        // The edge port is only meaningful for the local `.localhost` gateway.
        // Cloudflare-backed environments expose tenant hosts on standard HTTPS;
        // carrying the Docker gateway port into those links makes them unusable.
        let port = (self.tenant_domain == "localhost")
            .then_some(self.tenant_public_port)
            .flatten();
        tenant_origin(self.public_origin.scheme(), port, hostname)
    }
}

fn distinct_secret(
    name: &'static str,
    value: &str,
    other_name: &str,
    other: &str,
) -> Result<(), ConfigError> {
    if value == other {
        return Err(ConfigError::Invalid {
            name,
            reason: format!("must differ from {other_name}"),
        });
    }
    Ok(())
}

fn optional_port(name: &'static str) -> Result<Option<u16>, ConfigError> {
    let Some(value) = std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
    else {
        return Ok(None);
    };
    value
        .parse()
        .map(Some)
        .map_err(|error| ConfigError::Invalid {
            name,
            reason: format!("must be a TCP port: {error}"),
        })
}

fn tenant_origin(scheme: &str, port: Option<u16>, hostname: &str) -> String {
    match port {
        Some(port) => format!("{scheme}://{hostname}:{port}"),
        None => format!("{scheme}://{hostname}"),
    }
}

fn data_mode(value: &str) -> Result<bool, ConfigError> {
    data_mode_with(value, &|name| std::env::var(name).ok())
}

fn data_mode_with(
    value: &str,
    lookup: &dyn Fn(&'static str) -> Option<String>,
) -> Result<bool, ConfigError> {
    match value {
        "synthetic" => Ok(true),
        "personal" => {
            validate_personal_data_governance(lookup)?;
            Ok(false)
        }
        _ => Err(ConfigError::Invalid {
            name: "CONTROL_DATA_MODE",
            reason: "must be synthetic or personal".into(),
        }),
    }
}

fn validate_personal_data_governance(
    lookup: &dyn Fn(&'static str) -> Option<String>,
) -> Result<(), ConfigError> {
    for name in [
        "CONTROL_PRIVACY_CONTROLLER_REF",
        "CONTROL_PRIVACY_PROCESSING_RECORD_REF",
        "CONTROL_PRIVACY_RETENTION_APPROVAL_REF",
        "CONTROL_PRIVACY_PROCESSOR_REGISTER_REF",
        "CONTROL_PRIVACY_DPIA_APPROVAL_REF",
    ] {
        let value = lookup(name).ok_or(ConfigError::Missing(name))?;
        let value = value.trim();
        let lower = value.to_ascii_lowercase();
        if !(8..=500).contains(&value.len())
            || value.chars().any(char::is_whitespace)
            || lower.contains("pending")
            || lower.contains("replace")
            || lower.contains("example")
            || lower.contains("todo")
        {
            return Err(ConfigError::Invalid {
                name,
                reason: "must be a bounded opaque reference to approved governance evidence".into(),
            });
        }
    }

    let region_name = "CONTROL_PRIVACY_PROCESSING_REGION";
    let region = lookup(region_name).ok_or(ConfigError::Missing(region_name))?;
    if !matches!(
        region.as_str(),
        "paris" | "azure-france-central" | "azure-west-europe"
    ) {
        return Err(ConfigError::Invalid {
            name: region_name,
            reason: "must be paris, azure-france-central, or azure-west-europe".into(),
        });
    }
    Ok(())
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
    crate::runtime_secret::required_configuration(name).map_err(|reason| {
        if reason == format!("{name} is required") {
            ConfigError::Missing(name)
        } else {
            ConfigError::Invalid { name, reason }
        }
    })
}

fn required_secret(name: &'static str) -> Result<String, ConfigError> {
    crate::runtime_secret::required(name).map_err(|reason| {
        if reason == format!("{name} is required") {
            ConfigError::Missing(name)
        } else {
            ConfigError::Invalid { name, reason }
        }
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_metrics_credential_may_not_be_the_internal_token() {
        // Prometheus keeps this one on disk in its own container; if it were the
        // internal token, that container would hold the internal API.
        let error = distinct_secret(
            "CONTROL_METRICS_TOKEN",
            "same-value",
            "CONTROL_INTERNAL_TOKEN",
            "same-value",
        )
        .expect_err("identical tokens must be rejected");
        assert!(matches!(
            error,
            ConfigError::Invalid {
                name: "CONTROL_METRICS_TOKEN",
                ..
            }
        ));
        assert!(
            distinct_secret(
                "CONTROL_METRICS_TOKEN",
                "metrics-value",
                "CONTROL_INTERNAL_TOKEN",
                "internal-value",
            )
            .is_ok()
        );
    }

    #[test]
    fn tenant_origins_use_the_public_scheme_and_optional_edge_port() {
        assert_eq!(
            tenant_origin("https", None, "atelier.dev1.makersbrain.net"),
            "https://atelier.dev1.makersbrain.net"
        );
        assert_eq!(
            tenant_origin("http", Some(8169), "atelier.localhost"),
            "http://atelier.localhost:8169"
        );
    }

    #[test]
    fn data_mode_is_explicit_and_fail_closed() {
        let absent = |_| None;
        assert!(data_mode_with("synthetic", &absent).unwrap());
        assert!(data_mode_with("personal", &absent).is_err());
        assert!(data_mode_with("", &absent).is_err());
        assert!(data_mode_with("production", &absent).is_err());
    }

    #[test]
    fn personal_data_requires_approved_governance_and_an_allowed_eea_region() {
        let approved = |name| {
            Some(
                match name {
                    "CONTROL_PRIVACY_PROCESSING_REGION" => "paris",
                    _ => "evidence://approved/2026-08-14",
                }
                .into(),
            )
        };
        assert!(!data_mode_with("personal", &approved).unwrap());

        let pending = |name| {
            Some(
                match name {
                    "CONTROL_PRIVACY_PROCESSING_REGION" => "paris",
                    "CONTROL_PRIVACY_DPIA_APPROVAL_REF" => "pending-controller-review",
                    _ => "evidence://approved/2026-08-14",
                }
                .into(),
            )
        };
        assert!(data_mode_with("personal", &pending).is_err());

        let non_eea = |name| {
            Some(
                match name {
                    "CONTROL_PRIVACY_PROCESSING_REGION" => "us-east",
                    _ => "evidence://approved/2026-08-14",
                }
                .into(),
            )
        };
        assert!(data_mode_with("personal", &non_eea).is_err());
    }
}
