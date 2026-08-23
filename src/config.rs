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
    /// Fleet/platform/internal database identity. This pool must never carry a
    /// caller-selected tenant context.
    pub database_url: String,
    /// Human workshop database identity. Every use is wrapped in a
    /// transaction-local workshop execution scope before SQL is issued.
    pub tenant_database_url: String,
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
    pub deployment_driver_socket: Option<PathBuf>,
    pub deployment_driver_token: String,
    pub extraction_broker_url: Url,
    pub extraction_broker_token: String,
    pub allow_self_signup: bool,
    pub operator_emails: HashSet<String>,
    pub request_timeout: Duration,
    pub synthetic_data_only: bool,
}

/// Immutable configuration for the one-shot schema migration process.
pub struct MigrationConfig {
    database_url: String,
    synthetic_data_only: bool,
}

impl MigrationConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        Ok(Self {
            database_url: Config::database_url()?,
            synthetic_data_only: Config::synthetic_data_only()?,
        })
    }

    pub fn database_url(&self) -> &str {
        &self.database_url
    }

    pub fn synthetic_data_only(&self) -> bool {
        self.synthetic_data_only
    }
}

impl Config {
    pub fn database_url() -> Result<String, ConfigError> {
        let value = required_secret("CONTROL_DATABASE_URL")?;
        validate_database_url("CONTROL_DATABASE_URL", &value)?;
        Ok(value)
    }

    pub fn tenant_database_url() -> Result<String, ConfigError> {
        let value = required_secret("CONTROL_TENANT_DATABASE_URL")?;
        validate_database_url("CONTROL_TENANT_DATABASE_URL", &value)?;
        Ok(value)
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
        let database_url = Self::database_url()?;
        let tenant_database_url = Self::tenant_database_url()?;
        distinct_database_login(&database_url, &tenant_database_url)?;
        Ok(Self {
            listen: required("CONTROL_LISTEN")?
                .parse()
                .map_err(|error| ConfigError::Invalid {
                    name: "CONTROL_LISTEN",
                    reason: format!("{error}"),
                })?,
            database_url,
            tenant_database_url,
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
            deployment_driver_socket: crate::deployment_driver_transport::configured_socket()
                .map_err(|error| ConfigError::Invalid {
                    name: "CONTROL_DEPLOYMENT_DRIVER_SOCKET",
                    reason: error.to_string(),
                })?,
            deployment_driver_token: required_secret("CONTROL_DEPLOYMENT_DRIVER_TOKEN")?,
            extraction_broker_url: service_url("CONTROL_EXTRACTION_BROKER_URL")?,
            extraction_broker_token: required_secret("CONTROL_EXTRACTION_BROKER_TOKEN")?,
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

pub(crate) fn validate_database_url(name: &'static str, value: &str) -> Result<(), ConfigError> {
    let url = Url::parse(value).map_err(|error| ConfigError::Invalid {
        name,
        reason: format!("must be a PostgreSQL URL: {error}"),
    })?;
    if !matches!(url.scheme(), "postgres" | "postgresql") || url.host_str().is_none() {
        return Err(ConfigError::Invalid {
            name,
            reason: "must use the postgres or postgresql scheme and include a host".into(),
        });
    }
    Ok(())
}

fn distinct_database_login(platform_url: &str, tenant_url: &str) -> Result<(), ConfigError> {
    let platform = Url::parse(platform_url).map_err(|_| ConfigError::Invalid {
        name: "CONTROL_DATABASE_URL",
        reason: "must be validated before database identity comparison".into(),
    })?;
    let tenant = Url::parse(tenant_url).map_err(|_| ConfigError::Invalid {
        name: "CONTROL_TENANT_DATABASE_URL",
        reason: "must be validated before database identity comparison".into(),
    })?;
    if platform.username().is_empty() || tenant.username().is_empty() {
        return Err(ConfigError::Invalid {
            name: "CONTROL_TENANT_DATABASE_URL",
            reason: "both API database URLs must name explicit login roles".into(),
        });
    }
    if platform.username() == tenant.username() {
        return Err(ConfigError::Invalid {
            name: "CONTROL_TENANT_DATABASE_URL",
            reason: "must use a login role distinct from CONTROL_DATABASE_URL".into(),
        });
    }
    Ok(())
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
    parse_tenant_domain(required("CONTROL_TENANT_DOMAIN")?)
}

pub(crate) fn parse_tenant_domain(value: String) -> Result<String, ConfigError> {
    let value = value.trim().to_ascii_lowercase();
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

fn service_url(name: &'static str) -> Result<Url, ConfigError> {
    let value = required(name)?;
    parse_service_url(name, &value)
}

fn parse_service_url(name: &'static str, value: &str) -> Result<Url, ConfigError> {
    let url = Url::parse(value).map_err(|error| ConfigError::Invalid {
        name,
        reason: error.to_string(),
    })?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err(ConfigError::Invalid {
            name,
            reason: "must be an absolute HTTP(S) URL".into(),
        });
    }
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(ConfigError::Invalid {
            name,
            reason: "must not contain credentials, a query, or a fragment".into(),
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
    fn internal_service_urls_are_absolute_and_never_embed_credentials() {
        let name = "CONTROL_EXTRACTION_BROKER_URL";
        assert!(parse_service_url(name, "http://document-extraction:8090").is_ok());
        for invalid in [
            "document-extraction:8090",
            "ftp://document-extraction/archive",
            "https://token@document-extraction",
            "https://document-extraction?token=secret",
            "https://document-extraction/#fragment",
        ] {
            assert!(
                parse_service_url(name, invalid).is_err(),
                "{invalid} must be rejected"
            );
        }
    }

    #[test]
    fn database_urls_are_typed_before_a_process_connects() {
        assert!(
            validate_database_url(
                "CONTROL_DATABASE_URL",
                "postgresql://control@postgres/control"
            )
            .is_ok()
        );
        for invalid in [
            "control-db",
            "https://postgres/control",
            "postgresql:///control",
        ] {
            assert!(
                validate_database_url("CONTROL_DATABASE_URL", invalid).is_err(),
                "{invalid} must be rejected"
            );
        }
        assert!(
            distinct_database_login(
                "postgresql://control_api@postgres/control",
                "postgresql://control_tenant_api@postgres/control",
            )
            .is_ok()
        );
        assert!(
            distinct_database_login(
                "postgresql://control_api@postgres/control",
                "postgresql://control_api@postgres/control",
            )
            .is_err(),
            "tenant and platform pools must not share a login role"
        );
        assert!(
            distinct_database_login(
                "postgresql://postgres@postgres/control",
                "postgresql://control_tenant_api@postgres/control",
            )
            .is_ok(),
            "identity comparison is independent of host and password handling"
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
