use std::path::{Path, PathBuf};
use std::time::Duration;

use url::Url;

use crate::config::ConfigError;
use crate::integrations::cloudflare::CloudflareCustomHostnameClient;
use crate::invitation::InvitationSigner;
use crate::outbound_http::internal_service_builder;

const TENANT_DOMAIN_QUEUES: [&str; 3] = [
    "tenant-provisioning",
    "invoice-capture",
    "tenant-reconciliation",
];
const DEPLOYMENT_DRIVER_QUEUES: [&str; 4] = [
    "tenant-provisioning",
    "tenant-reconciliation",
    "tenant-lifecycle",
    "release-adoption",
];

/// Immutable process configuration shared by the durable worker loop.
///
/// This is intentionally loaded before the database connection is opened. A
/// worker therefore cannot register itself, lease work, and only then discover
/// that its release identity or tenant routing suffix is malformed.
pub struct WorkerConfig {
    database_url: String,
    release_id: String,
    tenant_domain: Option<String>,
    invoice_extraction: Option<InvoiceExtractionConfig>,
    inventory_extraction: Option<InventoryExtractionConfig>,
    email_delivery: Option<EmailDeliveryConfig>,
    deployment_driver: Option<DeploymentDriverConfig>,
    privacy_driver: Option<PrivacyDriverConfig>,
    custom_hostname_provider: Option<CloudflareCustomHostnameClient>,
}

pub struct InvoiceExtractionConfig {
    captured_tag_ids: Option<Vec<i64>>,
    monthly_page_limit: i64,
    azure_min_interval: Duration,
}

pub struct InventoryExtractionConfig {
    azure_monthly_image_limit: i64,
    ai_monthly_image_limit: i64,
    azure_min_interval: Duration,
}

/// Immutable email-delivery settings and process-scoped transport.
///
/// This type deliberately does not implement `Debug`: it owns the mail gateway
/// bearer and the validated location of the private invitation signing ring.
pub struct EmailDeliveryConfig {
    webhook_url: Url,
    authorization: reqwest::header::HeaderValue,
    client: reqwest::Client,
    invitation_accept_url: Url,
    invitation_signing_key_id: String,
    invitation_signing_keys_file: PathBuf,
}

/// Privacy processor transport settings. This type intentionally does not
/// implement `Debug`, so the bearer token cannot be exposed through routine
/// configuration logging.
pub struct PrivacyDriverConfig {
    url: Url,
    authorization: reqwest::header::HeaderValue,
    socket: Option<PathBuf>,
    client: reqwest::Client,
}

/// Queue-owned deployment-driver endpoint and process-scoped transport.
///
/// Authentication remains request-local so a reusable transport never carries
/// a credential in its default header map.
pub struct DeploymentDriverConfig {
    url: Url,
    authorization: reqwest::header::HeaderValue,
    socket: Option<PathBuf>,
    client: reqwest::Client,
}

impl WorkerConfig {
    pub fn from_env(queue: &str) -> Result<Self, ConfigError> {
        Self::from_lookup(
            queue,
            &|name| {
                crate::runtime_secret::configuration(name)
                    .map_err(|reason| ConfigError::Invalid { name, reason })
            },
            &|name| {
                crate::runtime_secret::environment(name)
                    .map_err(|reason| ConfigError::Invalid { name, reason })
            },
        )
    }

    fn from_lookup(
        queue: &str,
        configuration: &dyn Fn(&'static str) -> Result<Option<String>, ConfigError>,
        secret: &dyn Fn(&'static str) -> Result<Option<String>, ConfigError>,
    ) -> Result<Self, ConfigError> {
        let database_url = required(secret, "CONTROL_DATABASE_URL")?;
        crate::config::validate_database_url("CONTROL_DATABASE_URL", &database_url)?;
        let release_id = required(configuration, "CONTROL_RELEASE_ID")?;
        validate_release_id(&release_id)?;
        let tenant_domain = if TENANT_DOMAIN_QUEUES.contains(&queue) {
            Some(crate::config::parse_tenant_domain(required(
                configuration,
                "CONTROL_TENANT_DOMAIN",
            )?)?)
        } else {
            None
        };
        let invoice_extraction = (queue == "invoice-capture")
            .then(|| InvoiceExtractionConfig::load(configuration))
            .transpose()?;
        let inventory_extraction = (queue == "inventory-capture")
            .then(|| InventoryExtractionConfig::load(configuration))
            .transpose()?;
        let email_delivery = (queue == "email-delivery")
            .then(|| EmailDeliveryConfig::load(configuration, secret))
            .transpose()?;
        let deployment_driver = DEPLOYMENT_DRIVER_QUEUES
            .contains(&queue)
            .then(|| DeploymentDriverConfig::load(configuration, secret))
            .transpose()?;
        let privacy_driver = (queue == "privacy-operations")
            .then(|| PrivacyDriverConfig::load(configuration, secret))
            .transpose()?;
        let custom_hostname_provider = (queue == "tenant-reconciliation")
            .then(|| {
                CloudflareCustomHostnameClient::new(
                    required(secret, "CONTROL_CLOUDFLARE_API_TOKEN")?,
                    required(configuration, "CONTROL_CLOUDFLARE_ZONE_ID")?,
                    Duration::from_secs(20),
                )
                .map_err(|_| ConfigError::Invalid {
                    name: "CONTROL_CLOUDFLARE_API_TOKEN",
                    reason: "custom-hostname provider credentials are malformed".into(),
                })
            })
            .transpose()?;
        Ok(Self {
            database_url,
            release_id,
            tenant_domain,
            invoice_extraction,
            inventory_extraction,
            email_delivery,
            deployment_driver,
            privacy_driver,
            custom_hostname_provider,
        })
    }

    pub fn database_url(&self) -> &str {
        &self.database_url
    }

    pub fn release_id(&self) -> &str {
        &self.release_id
    }

    /// The validated routing suffix for worker classes which construct tenant
    /// hostnames. Absence means this worker class never constructs such a name.
    pub fn tenant_domain(&self) -> Option<&str> {
        self.tenant_domain.as_deref()
    }

    pub fn invoice_extraction(&self) -> Option<&InvoiceExtractionConfig> {
        self.invoice_extraction.as_ref()
    }

    pub fn inventory_extraction(&self) -> Option<&InventoryExtractionConfig> {
        self.inventory_extraction.as_ref()
    }

    pub fn email_delivery(&self) -> Option<&EmailDeliveryConfig> {
        self.email_delivery.as_ref()
    }

    pub fn deployment_driver(&self) -> Option<&DeploymentDriverConfig> {
        self.deployment_driver.as_ref()
    }

    pub fn privacy_driver(&self) -> Option<&PrivacyDriverConfig> {
        self.privacy_driver.as_ref()
    }

    pub fn custom_hostname_provider(&self) -> Option<&CloudflareCustomHostnameClient> {
        self.custom_hostname_provider.as_ref()
    }
}

impl EmailDeliveryConfig {
    fn load(
        configuration: &dyn Fn(&'static str) -> Result<Option<String>, ConfigError>,
        secret: &dyn Fn(&'static str) -> Result<Option<String>, ConfigError>,
    ) -> Result<Self, ConfigError> {
        let webhook_url = exact_http_route(
            "CONTROL_MAIL_WEBHOOK_URL",
            &required(configuration, "CONTROL_MAIL_WEBHOOK_URL")?,
            "/v1/mail",
        )?;
        let authorization = sensitive_bearer(
            "CONTROL_MAIL_WEBHOOK_TOKEN",
            required(secret, "CONTROL_MAIL_WEBHOOK_TOKEN")?,
        )?;
        let public_origin = trusted_root_origin(
            "CONTROL_PUBLIC_ORIGIN",
            &required(configuration, "CONTROL_PUBLIC_ORIGIN")?,
        )?;
        let invitation_accept_url =
            public_origin
                .join("invitations/accept")
                .map_err(|error| ConfigError::Invalid {
                    name: "CONTROL_PUBLIC_ORIGIN",
                    reason: format!("cannot construct the invitation acceptance route: {error}"),
                })?;
        let signing_key_id = required(configuration, "CONTROL_INVITATION_SIGNING_KEY_ID")?;
        validate_key_id(&signing_key_id)?;
        let signing_keys_file = PathBuf::from(required(
            configuration,
            "CONTROL_INVITATION_SIGNING_KEYS_FILE",
        )?);
        if !signing_keys_file.is_absolute() {
            return Err(ConfigError::Invalid {
                name: "CONTROL_INVITATION_SIGNING_KEYS_FILE",
                reason: "must be an absolute path".into(),
            });
        }
        // Read and validate the ring before telemetry or database I/O. Delivery
        // reloads this same validated path so an atomic secret-file rotation can
        // add a new current key while retaining keys named by queued outbox rows.
        InvitationSigner::from_json_file(signing_key_id.clone(), &signing_keys_file).map_err(
            |_| ConfigError::Invalid {
                name: "CONTROL_INVITATION_SIGNING_KEYS_FILE",
                reason: "must contain a valid signing key ring including the current key ID".into(),
            },
        )?;
        let client = internal_service_builder("mb-control-worker/email")
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|error| ConfigError::Invalid {
                name: "CONTROL_MAIL_WEBHOOK_URL",
                reason: format!("could not initialize the mail gateway transport: {error}"),
            })?;
        Ok(Self {
            webhook_url,
            authorization,
            client,
            invitation_accept_url,
            invitation_signing_key_id: signing_key_id,
            invitation_signing_keys_file: signing_keys_file,
        })
    }

    pub fn webhook_url(&self) -> &Url {
        &self.webhook_url
    }

    pub fn authorization(&self) -> &reqwest::header::HeaderValue {
        &self.authorization
    }

    pub fn client(&self) -> &reqwest::Client {
        &self.client
    }

    pub fn invitation_accept_url(&self) -> &Url {
        &self.invitation_accept_url
    }

    /// Reloads the key ring from its startup-validated absolute path.
    ///
    /// Key files are deployed by atomic replacement. Reloading at the delivery
    /// boundary preserves online rotation and lets a queued invitation select
    /// its generation-pinned retained key rather than only the current key.
    pub fn load_invitation_signer(
        &self,
    ) -> Result<InvitationSigner, crate::invitation::InvitationTokenError> {
        InvitationSigner::from_json_file(
            self.invitation_signing_key_id.clone(),
            &self.invitation_signing_keys_file,
        )
    }
}

impl InvoiceExtractionConfig {
    fn load(
        lookup: &dyn Fn(&'static str) -> Result<Option<String>, ConfigError>,
    ) -> Result<Self, ConfigError> {
        Ok(Self {
            captured_tag_ids: optional(lookup, "CONTROL_PAPERLESS_CAPTURED_TAG_IDS")?
                .map(parse_captured_tag_ids)
                .transpose()?,
            monthly_page_limit: bounded_i64(
                lookup,
                "CONTROL_AZURE_MONTHLY_PAGE_LIMIT",
                1_000,
                0,
                1_000_000_000,
            )?,
            azure_min_interval: azure_min_interval(lookup)?,
        })
    }

    pub fn captured_tag_ids(&self) -> Option<&[i64]> {
        self.captured_tag_ids.as_deref()
    }

    pub fn monthly_page_limit(&self) -> i64 {
        self.monthly_page_limit
    }

    pub fn azure_min_interval(&self) -> Duration {
        self.azure_min_interval
    }
}

impl InventoryExtractionConfig {
    fn load(
        lookup: &dyn Fn(&'static str) -> Result<Option<String>, ConfigError>,
    ) -> Result<Self, ConfigError> {
        Ok(Self {
            azure_monthly_image_limit: bounded_i64(
                lookup,
                "CONTROL_AZURE_MONTHLY_IMAGE_LIMIT",
                500,
                0,
                1_000_000_000,
            )?,
            ai_monthly_image_limit: bounded_i64(
                lookup,
                "CONTROL_INVENTORY_AI_MONTHLY_IMAGE_LIMIT",
                500,
                0,
                1_000_000_000,
            )?,
            azure_min_interval: azure_min_interval(lookup)?,
        })
    }

    pub fn azure_monthly_image_limit(&self) -> i64 {
        self.azure_monthly_image_limit
    }

    pub fn ai_monthly_image_limit(&self) -> i64 {
        self.ai_monthly_image_limit
    }

    pub fn azure_min_interval(&self) -> Duration {
        self.azure_min_interval
    }
}

impl PrivacyDriverConfig {
    fn load(
        configuration: &dyn Fn(&'static str) -> Result<Option<String>, ConfigError>,
        secret: &dyn Fn(&'static str) -> Result<Option<String>, ConfigError>,
    ) -> Result<Self, ConfigError> {
        let value = required(configuration, "CONTROL_PRIVACY_DRIVER_URL")?;
        let url = absolute_http_url("CONTROL_PRIVACY_DRIVER_URL", &value)?;
        let authorization = sensitive_bearer(
            "CONTROL_PRIVACY_DRIVER_TOKEN",
            required(secret, "CONTROL_PRIVACY_DRIVER_TOKEN")?,
        )?;
        let socket =
            optional(configuration, "CONTROL_DEPLOYMENT_DRIVER_SOCKET")?.map(PathBuf::from);
        if socket.as_ref().is_some_and(|path| !path.is_absolute()) {
            return Err(ConfigError::Invalid {
                name: "CONTROL_DEPLOYMENT_DRIVER_SOCKET",
                reason: "must be an absolute path".into(),
            });
        }
        let client =
            crate::deployment_driver_transport::client(Duration::from_secs(300), socket.as_deref())
                .map_err(|error| ConfigError::Invalid {
                    name: "CONTROL_PRIVACY_DRIVER_URL",
                    reason: format!("could not initialize the privacy driver transport: {error}"),
                })?;
        Ok(Self {
            url,
            authorization,
            socket,
            client,
        })
    }

    pub fn url(&self) -> &Url {
        &self.url
    }

    pub fn authorization(&self) -> &reqwest::header::HeaderValue {
        &self.authorization
    }

    pub fn socket(&self) -> Option<&Path> {
        self.socket.as_deref()
    }

    pub fn client(&self) -> &reqwest::Client {
        &self.client
    }
}

impl DeploymentDriverConfig {
    fn load(
        configuration: &dyn Fn(&'static str) -> Result<Option<String>, ConfigError>,
        secret: &dyn Fn(&'static str) -> Result<Option<String>, ConfigError>,
    ) -> Result<Self, ConfigError> {
        let url = absolute_http_url(
            "CONTROL_DEPLOYMENT_DRIVER_URL",
            &required(configuration, "CONTROL_DEPLOYMENT_DRIVER_URL")?,
        )?;
        let authorization = sensitive_bearer(
            "CONTROL_DEPLOYMENT_DRIVER_TOKEN",
            required(secret, "CONTROL_DEPLOYMENT_DRIVER_TOKEN")?,
        )?;
        let socket =
            optional(configuration, "CONTROL_DEPLOYMENT_DRIVER_SOCKET")?.map(PathBuf::from);
        if socket.as_ref().is_some_and(|path| !path.is_absolute()) {
            return Err(ConfigError::Invalid {
                name: "CONTROL_DEPLOYMENT_DRIVER_SOCKET",
                reason: "must be an absolute path".into(),
            });
        }
        let client =
            crate::deployment_driver_transport::client(Duration::from_secs(900), socket.as_deref())
                .map_err(|error| ConfigError::Invalid {
                    name: "CONTROL_DEPLOYMENT_DRIVER_URL",
                    reason: format!(
                        "could not initialize the deployment driver transport: {error}"
                    ),
                })?;
        Ok(Self {
            url,
            authorization,
            socket,
            client,
        })
    }

    pub fn url(&self) -> &Url {
        &self.url
    }

    pub fn authorization(&self) -> &reqwest::header::HeaderValue {
        &self.authorization
    }

    pub fn socket(&self) -> Option<&Path> {
        self.socket.as_deref()
    }

    pub fn client(&self) -> &reqwest::Client {
        &self.client
    }

    #[cfg(test)]
    pub(crate) fn for_test(url: &str) -> Self {
        let mut authorization = reqwest::header::HeaderValue::from_static("Bearer test-driver");
        authorization.set_sensitive(true);
        Self {
            url: Url::parse(url).expect("test deployment-driver URL"),
            authorization,
            socket: None,
            client: crate::deployment_driver_transport::client(Duration::from_secs(5), None)
                .expect("test deployment-driver client"),
        }
    }
}

fn sensitive_bearer(
    name: &'static str,
    token: String,
) -> Result<reqwest::header::HeaderValue, ConfigError> {
    let mut authorization = reqwest::header::HeaderValue::from_str(&format!("Bearer {token}"))
        .map_err(|_| ConfigError::Invalid {
            name,
            reason: "must be valid as an HTTP bearer credential".into(),
        })?;
    authorization.set_sensitive(true);
    Ok(authorization)
}

fn required(
    lookup: &dyn Fn(&'static str) -> Result<Option<String>, ConfigError>,
    name: &'static str,
) -> Result<String, ConfigError> {
    lookup(name)?
        .filter(|value| !value.trim().is_empty())
        .ok_or(ConfigError::Missing(name))
}

fn optional(
    lookup: &dyn Fn(&'static str) -> Result<Option<String>, ConfigError>,
    name: &'static str,
) -> Result<Option<String>, ConfigError> {
    Ok(lookup(name)?.filter(|value| !value.trim().is_empty()))
}

fn bounded_i64(
    lookup: &dyn Fn(&'static str) -> Result<Option<String>, ConfigError>,
    name: &'static str,
    default: i64,
    minimum: i64,
    maximum: i64,
) -> Result<i64, ConfigError> {
    let Some(value) = optional(lookup, name)? else {
        return Ok(default);
    };
    let parsed = value
        .trim()
        .parse::<i64>()
        .map_err(|error| ConfigError::Invalid {
            name,
            reason: format!("must be an integer: {error}"),
        })?;
    if !(minimum..=maximum).contains(&parsed) {
        return Err(ConfigError::Invalid {
            name,
            reason: format!("must be between {minimum} and {maximum}"),
        });
    }
    Ok(parsed)
}

fn azure_min_interval(
    lookup: &dyn Fn(&'static str) -> Result<Option<String>, ConfigError>,
) -> Result<Duration, ConfigError> {
    let millis = bounded_i64(
        lookup,
        "CONTROL_AZURE_ANALYZE_MIN_INTERVAL_MS",
        1_100,
        100,
        60_000,
    )?;
    Ok(Duration::from_millis(millis as u64))
}

fn parse_captured_tag_ids(value: String) -> Result<Vec<i64>, ConfigError> {
    let mut ids = value
        .split(',')
        .map(str::trim)
        .map(|value| {
            value
                .parse::<i64>()
                .ok()
                .filter(|id| *id > 0)
                .ok_or_else(|| ConfigError::Invalid {
                    name: "CONTROL_PAPERLESS_CAPTURED_TAG_IDS",
                    reason: "must contain comma-separated positive integer tag IDs".into(),
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    if ids.len() > 100 {
        return Err(ConfigError::Invalid {
            name: "CONTROL_PAPERLESS_CAPTURED_TAG_IDS",
            reason: "must contain no more than 100 tag IDs".into(),
        });
    }
    ids.sort_unstable();
    ids.dedup();
    Ok(ids)
}

fn absolute_http_url(name: &'static str, value: &str) -> Result<Url, ConfigError> {
    let url = Url::parse(value).map_err(|error| ConfigError::Invalid {
        name,
        reason: format!("must be an absolute HTTP URL: {error}"),
    })?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err(ConfigError::Invalid {
            name,
            reason: "must be an absolute HTTP or HTTPS URL".into(),
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

fn exact_http_route(
    name: &'static str,
    value: &str,
    expected_path: &str,
) -> Result<Url, ConfigError> {
    let url = absolute_http_url(name, value)?;
    if url.path() != expected_path {
        return Err(ConfigError::Invalid {
            name,
            reason: format!("must select the exact {expected_path} route"),
        });
    }
    Ok(url)
}

fn trusted_root_origin(name: &'static str, value: &str) -> Result<Url, ConfigError> {
    let url = absolute_http_url(name, value)?;
    let loopback_http = url.scheme() == "http"
        && url.host_str().is_some_and(|host| {
            matches!(host, "localhost" | "127.0.0.1" | "::1") || host.ends_with(".localhost")
        });
    if (url.scheme() != "https" && !loopback_http) || url.path() != "/" {
        return Err(ConfigError::Invalid {
            name,
            reason: "must be a root HTTPS origin (HTTP is allowed only on loopback)".into(),
        });
    }
    Ok(url)
}

fn validate_key_id(value: &str) -> Result<(), ConfigError> {
    if !(1..=100).contains(&value.len())
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(ConfigError::Invalid {
            name: "CONTROL_INVITATION_SIGNING_KEY_ID",
            reason: "must be 1-100 ASCII letters, digits, '.', ':', '_' or '-'".into(),
        });
    }
    Ok(())
}

fn validate_release_id(value: &str) -> Result<(), ConfigError> {
    if !(1..=200).contains(&value.len()) || !value.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(ConfigError::Invalid {
            name: "CONTROL_RELEASE_ID",
            reason: "must be 1-200 printable ASCII characters without whitespace".into(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use base64::Engine as _;

    use super::*;

    fn load(queue: &str, values: &[(&'static str, &str)]) -> Result<WorkerConfig, ConfigError> {
        let mut values = values.iter().copied().collect::<HashMap<_, _>>();
        values
            .entry("CONTROL_DATABASE_URL")
            .or_insert("postgresql://worker:secret@db/control");
        if DEPLOYMENT_DRIVER_QUEUES.contains(&queue) {
            values
                .entry("CONTROL_DEPLOYMENT_DRIVER_URL")
                .or_insert("http://deployment-driver:8080");
            values
                .entry("CONTROL_DEPLOYMENT_DRIVER_TOKEN")
                .or_insert("private-driver-token");
        }
        if queue == "tenant-reconciliation" {
            values
                .entry("CONTROL_CLOUDFLARE_API_TOKEN")
                .or_insert("cloudflare-provider-token");
            values
                .entry("CONTROL_CLOUDFLARE_ZONE_ID")
                .or_insert("cloudflare-zone-identity");
        }
        WorkerConfig::from_lookup(
            queue,
            &|name| Ok(values.get(name).map(|value| (*value).to_owned())),
            &|name| Ok(values.get(name).map(|value| (*value).to_owned())),
        )
    }

    #[test]
    fn every_worker_requires_a_bounded_immutable_release_identity() {
        assert!(matches!(
            load("membership-provisioning", &[]),
            Err(ConfigError::Missing("CONTROL_RELEASE_ID"))
        ));
        assert!(
            load(
                "membership-provisioning",
                &[("CONTROL_RELEASE_ID", "release with spaces")]
            )
            .is_err()
        );
        assert!(
            load(
                "membership-provisioning",
                &[("CONTROL_RELEASE_ID", &"x".repeat(201))]
            )
            .is_err()
        );
        assert_eq!(
            load(
                "membership-provisioning",
                &[("CONTROL_RELEASE_ID", "sha256:abc123")]
            )
            .unwrap()
            .release_id(),
            "sha256:abc123"
        );
    }

    #[test]
    fn every_worker_requires_a_valid_postgresql_url() {
        let missing = HashMap::from([("CONTROL_RELEASE_ID", "release-1")]);
        assert!(matches!(
            WorkerConfig::from_lookup(
                "membership-provisioning",
                &|name| Ok(missing.get(name).map(|value| (*value).to_owned())),
                &|name| Ok(missing.get(name).map(|value| (*value).to_owned())),
            ),
            Err(ConfigError::Missing("CONTROL_DATABASE_URL"))
        ));
        assert!(
            load(
                "membership-provisioning",
                &[
                    ("CONTROL_RELEASE_ID", "release-1"),
                    ("CONTROL_DATABASE_URL", "https://db/control"),
                ],
            )
            .is_err()
        );
        let config = load(
            "membership-provisioning",
            &[
                ("CONTROL_RELEASE_ID", "release-1"),
                (
                    "CONTROL_DATABASE_URL",
                    "postgresql://worker:secret@db/control",
                ),
            ],
        )
        .unwrap();
        assert_eq!(
            config.database_url(),
            "postgresql://worker:secret@db/control"
        );
    }

    #[test]
    fn hostname_building_workers_require_a_valid_tenant_domain() {
        for queue in TENANT_DOMAIN_QUEUES {
            assert!(load(queue, &[("CONTROL_RELEASE_ID", "release-1")]).is_err());
            assert!(
                load(
                    queue,
                    &[
                        ("CONTROL_RELEASE_ID", "release-1"),
                        ("CONTROL_TENANT_DOMAIN", "not a domain")
                    ]
                )
                .is_err()
            );
            assert_eq!(
                load(
                    queue,
                    &[
                        ("CONTROL_RELEASE_ID", "release-1"),
                        ("CONTROL_TENANT_DOMAIN", "Example.TEST")
                    ]
                )
                .unwrap()
                .tenant_domain(),
                Some("example.test")
            );
        }
    }

    #[test]
    fn unrelated_workers_do_not_acquire_unused_tenant_configuration() {
        let config = load(
            "membership-provisioning",
            &[
                ("CONTROL_RELEASE_ID", "release-1"),
                ("CONTROL_TENANT_DOMAIN", "invalid value ignored"),
                ("CONTROL_AZURE_MONTHLY_PAGE_LIMIT", "invalid ignored"),
                ("CONTROL_PRIVACY_DRIVER_URL", "invalid ignored"),
            ],
        )
        .unwrap();
        assert_eq!(config.tenant_domain(), None);
        assert!(config.invoice_extraction().is_none());
        assert!(config.inventory_extraction().is_none());
        assert!(config.email_delivery().is_none());
        assert!(config.deployment_driver().is_none());
        assert!(config.privacy_driver().is_none());
        assert!(config.custom_hostname_provider().is_none());
    }

    #[test]
    fn deployment_transport_is_queue_owned_validated_and_reused() {
        let config = load(
            "tenant-reconciliation",
            &[
                ("CONTROL_RELEASE_ID", "release-1"),
                ("CONTROL_TENANT_DOMAIN", "example.test"),
                ("CONTROL_DEPLOYMENT_DRIVER_URL", "http://driver:8080"),
                ("CONTROL_DEPLOYMENT_DRIVER_TOKEN", "private-token"),
                ("CONTROL_DEPLOYMENT_DRIVER_SOCKET", "/run/driver.sock"),
            ],
        )
        .unwrap();
        let driver = config.deployment_driver().unwrap();
        assert_eq!(driver.url().as_str(), "http://driver:8080/");
        assert_eq!(driver.socket(), Some(Path::new("/run/driver.sock")));
        assert!(driver.authorization().is_sensitive());
        assert!(std::ptr::eq(driver.client(), driver.client()));
        let unauthenticated = driver.client().post(driver.url().clone()).build().unwrap();
        assert!(
            !unauthenticated
                .headers()
                .contains_key(reqwest::header::AUTHORIZATION)
        );
        let authenticated = driver
            .client()
            .post(driver.url().clone())
            .header(
                reqwest::header::AUTHORIZATION,
                driver.authorization().clone(),
            )
            .build()
            .unwrap();
        assert!(
            authenticated
                .headers()
                .get(reqwest::header::AUTHORIZATION)
                .unwrap()
                .is_sensitive()
        );

        for (name, value) in [
            ("CONTROL_DEPLOYMENT_DRIVER_URL", "ftp://driver"),
            ("CONTROL_DEPLOYMENT_DRIVER_URL", "http://user:pass@driver"),
            ("CONTROL_DEPLOYMENT_DRIVER_SOCKET", "relative.sock"),
            ("CONTROL_DEPLOYMENT_DRIVER_TOKEN", "token\nheader"),
        ] {
            assert!(
                load(
                    "tenant-reconciliation",
                    &[
                        ("CONTROL_RELEASE_ID", "release-1"),
                        ("CONTROL_TENANT_DOMAIN", "example.test"),
                        (name, value),
                    ],
                )
                .is_err(),
                "{name}={value} must be rejected"
            );
        }
    }

    #[test]
    fn reconciliation_provider_is_validated_before_work_is_leased() {
        let config = load(
            "tenant-reconciliation",
            &[
                ("CONTROL_RELEASE_ID", "release-1"),
                ("CONTROL_TENANT_DOMAIN", "example.test"),
            ],
        )
        .unwrap();
        assert!(config.custom_hostname_provider().is_some());

        for (name, value) in [
            ("CONTROL_CLOUDFLARE_API_TOKEN", "short"),
            ("CONTROL_CLOUDFLARE_ZONE_ID", "contains spaces invalid"),
        ] {
            assert!(
                load(
                    "tenant-reconciliation",
                    &[
                        ("CONTROL_RELEASE_ID", "release-1"),
                        ("CONTROL_TENANT_DOMAIN", "example.test"),
                        (name, value),
                    ],
                )
                .is_err(),
                "{name} must be validated at startup"
            );
        }
    }

    fn signing_key_file() -> PathBuf {
        let private_key = pem::parse(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test-fixtures/invitation-private.pem"
        )))
        .unwrap();
        let encoded = base64::engine::general_purpose::STANDARD.encode(private_key.contents());
        let path = std::env::temp_dir().join(format!(
            "mb-control-worker-invitation-{}.json",
            uuid::Uuid::new_v4()
        ));
        std::fs::write(
            &path,
            serde_json::json!({"keys":{"current-1":encoded}}).to_string(),
        )
        .unwrap();
        path
    }

    fn load_email(
        overrides: &[(&'static str, &str)],
    ) -> Result<(WorkerConfig, PathBuf), ConfigError> {
        let signing_keys_file = signing_key_file();
        let mut values = HashMap::from([
            (
                "CONTROL_DATABASE_URL",
                "postgresql://worker:secret@db/control".to_owned(),
            ),
            ("CONTROL_RELEASE_ID", "release-1".to_owned()),
            (
                "CONTROL_MAIL_WEBHOOK_URL",
                "http://mail-gateway:8080/v1/mail".to_owned(),
            ),
            ("CONTROL_MAIL_WEBHOOK_TOKEN", "private-token".to_owned()),
            (
                "CONTROL_PUBLIC_ORIGIN",
                "https://control.makersbrain.test/".to_owned(),
            ),
            ("CONTROL_INVITATION_SIGNING_KEY_ID", "current-1".to_owned()),
            (
                "CONTROL_INVITATION_SIGNING_KEYS_FILE",
                signing_keys_file.to_string_lossy().into_owned(),
            ),
        ]);
        for (name, value) in overrides {
            values.insert(*name, (*value).to_owned());
        }
        let loaded = WorkerConfig::from_lookup(
            "email-delivery",
            &|name| Ok(values.get(name).cloned()),
            &|name| Ok(values.get(name).cloned()),
        );
        loaded.map(|config| (config, signing_keys_file))
    }

    #[test]
    fn email_delivery_configuration_is_strict_and_initialized_once() {
        let (config, signing_keys_file) = load_email(&[]).unwrap();
        let email = config.email_delivery().unwrap();
        assert_eq!(
            email.webhook_url().as_str(),
            "http://mail-gateway:8080/v1/mail"
        );
        assert!(email.authorization().is_sensitive());
        assert_eq!(
            email.invitation_accept_url().as_str(),
            "https://control.makersbrain.test/invitations/accept"
        );
        assert_eq!(
            email.load_invitation_signer().unwrap().key_id(),
            "current-1"
        );
        assert!(std::ptr::eq(email.client(), email.client()));
        std::fs::remove_file(signing_keys_file).unwrap();
    }

    #[test]
    fn email_delivery_reloads_an_atomically_rotated_retained_key_ring() {
        let (config, signing_keys_file) = load_email(&[]).unwrap();
        let encoded = serde_json::from_slice::<serde_json::Value>(
            &std::fs::read(&signing_keys_file).unwrap(),
        )
        .unwrap()["keys"]["current-1"]
            .as_str()
            .unwrap()
            .to_owned();
        std::fs::write(
            &signing_keys_file,
            serde_json::json!({"keys":{"retained-0":encoded,"current-1":encoded}}).to_string(),
        )
        .unwrap();

        let signer = config
            .email_delivery()
            .unwrap()
            .load_invitation_signer()
            .unwrap();
        let issued = time::OffsetDateTime::now_utc();
        signer
            .sign_with_key_id(
                "retained-0",
                uuid::Uuid::new_v4(),
                1,
                issued,
                issued + time::Duration::hours(1),
            )
            .unwrap();
        std::fs::remove_file(signing_keys_file).unwrap();
    }

    #[test]
    fn email_delivery_rejects_unsafe_routes_origins_and_key_locations() {
        for (name, value) in [
            (
                "CONTROL_MAIL_WEBHOOK_URL",
                "http://mail-gateway:8080/v1/other",
            ),
            (
                "CONTROL_MAIL_WEBHOOK_URL",
                "http://mail-gateway:8080/v1/mail?forward=other",
            ),
            ("CONTROL_PUBLIC_ORIGIN", "http://control.example.test/"),
            (
                "CONTROL_PUBLIC_ORIGIN",
                "https://control.example.test/application/",
            ),
            ("CONTROL_INVITATION_SIGNING_KEY_ID", "bad key id"),
            ("CONTROL_INVITATION_SIGNING_KEYS_FILE", "relative.json"),
            ("CONTROL_MAIL_WEBHOOK_TOKEN", "token\nheader"),
        ] {
            assert!(load_email(&[(name, value)]).is_err(), "{name}={value}");
        }
        assert!(load_email(&[("CONTROL_PUBLIC_ORIGIN", "http://localhost:4175/")]).is_ok());
    }

    #[test]
    fn invoice_extraction_settings_are_strict_and_queue_owned() {
        let config = load(
            "invoice-capture",
            &[
                ("CONTROL_RELEASE_ID", "release-1"),
                ("CONTROL_TENANT_DOMAIN", "example.test"),
                ("CONTROL_PAPERLESS_CAPTURED_TAG_IDS", "7, 3,7"),
                ("CONTROL_AZURE_MONTHLY_PAGE_LIMIT", "2500"),
                ("CONTROL_AZURE_ANALYZE_MIN_INTERVAL_MS", "900"),
            ],
        )
        .unwrap();
        let extraction = config.invoice_extraction().unwrap();
        assert_eq!(extraction.captured_tag_ids(), Some([3, 7].as_slice()));
        assert_eq!(extraction.monthly_page_limit(), 2_500);
        assert_eq!(extraction.azure_min_interval(), Duration::from_millis(900));
        assert!(config.inventory_extraction().is_none());

        for (name, value) in [
            ("CONTROL_PAPERLESS_CAPTURED_TAG_IDS", "3,nope"),
            ("CONTROL_AZURE_MONTHLY_PAGE_LIMIT", "-1"),
            ("CONTROL_AZURE_ANALYZE_MIN_INTERVAL_MS", "99"),
            ("CONTROL_AZURE_ANALYZE_MIN_INTERVAL_MS", "60001"),
        ] {
            assert!(
                load(
                    "invoice-capture",
                    &[
                        ("CONTROL_RELEASE_ID", "release-1"),
                        ("CONTROL_TENANT_DOMAIN", "example.test"),
                        (name, value),
                    ],
                )
                .is_err(),
                "{name}={value} must be rejected"
            );
        }
    }

    #[test]
    fn inventory_extraction_defaults_and_limits_are_queue_owned() {
        let defaults = load("inventory-capture", &[("CONTROL_RELEASE_ID", "release-1")]).unwrap();
        let defaults = defaults.inventory_extraction().unwrap();
        assert_eq!(defaults.azure_monthly_image_limit(), 500);
        assert_eq!(defaults.ai_monthly_image_limit(), 500);
        assert_eq!(defaults.azure_min_interval(), Duration::from_millis(1_100));

        let configured = load(
            "inventory-capture",
            &[
                ("CONTROL_RELEASE_ID", "release-1"),
                ("CONTROL_AZURE_MONTHLY_IMAGE_LIMIT", "750"),
                ("CONTROL_INVENTORY_AI_MONTHLY_IMAGE_LIMIT", "125"),
            ],
        )
        .unwrap();
        assert_eq!(
            configured
                .inventory_extraction()
                .unwrap()
                .azure_monthly_image_limit(),
            750
        );
        assert_eq!(
            configured
                .inventory_extraction()
                .unwrap()
                .ai_monthly_image_limit(),
            125
        );
    }

    #[test]
    fn privacy_transport_is_validated_once_and_keeps_its_secret_private() {
        let config = load(
            "privacy-operations",
            &[
                ("CONTROL_RELEASE_ID", "release-1"),
                ("CONTROL_PRIVACY_DRIVER_URL", "http://driver:8080"),
                ("CONTROL_PRIVACY_DRIVER_TOKEN", "private-token"),
                ("CONTROL_DEPLOYMENT_DRIVER_SOCKET", "/run/driver.sock"),
            ],
        )
        .unwrap();
        let privacy = config.privacy_driver().unwrap();
        assert_eq!(privacy.url().as_str(), "http://driver:8080/");
        assert!(privacy.authorization().is_sensitive());
        assert!(std::ptr::eq(privacy.client(), privacy.client()));
        assert_eq!(privacy.socket(), Some(Path::new("/run/driver.sock")));
        let unauthenticated = privacy
            .client()
            .post(privacy.url().clone())
            .build()
            .unwrap();
        assert!(
            !unauthenticated
                .headers()
                .contains_key(reqwest::header::AUTHORIZATION)
        );

        for (name, value) in [
            ("CONTROL_PRIVACY_DRIVER_URL", "ftp://driver"),
            ("CONTROL_PRIVACY_DRIVER_URL", "http://user:pass@driver"),
            ("CONTROL_DEPLOYMENT_DRIVER_SOCKET", "relative.sock"),
        ] {
            assert!(
                load(
                    "privacy-operations",
                    &[
                        ("CONTROL_RELEASE_ID", "release-1"),
                        ("CONTROL_PRIVACY_DRIVER_URL", "http://driver:8080"),
                        ("CONTROL_PRIVACY_DRIVER_TOKEN", "private-token"),
                        (name, value),
                    ],
                )
                .is_err(),
                "{name}={value} must be rejected"
            );
        }
        assert!(
            load(
                "privacy-operations",
                &[
                    ("CONTROL_RELEASE_ID", "release-1"),
                    ("CONTROL_PRIVACY_DRIVER_URL", "http://driver:8080"),
                ],
            )
            .is_err()
        );
    }

    #[test]
    fn tenant_domain_ownership_matches_the_machine_readable_process_contract() {
        let specification: serde_json::Value =
            serde_json::from_str(include_str!("../deploy/configuration-spec.json")).unwrap();
        let required = specification["required_environment"].as_object().unwrap();
        for (queue, process) in [
            ("tenant-provisioning", "provisioning_worker"),
            ("membership-provisioning", "membership_worker"),
            ("invoice-capture", "invoice_worker"),
            ("inventory-capture", "inventory_worker"),
            ("email-delivery", "email_worker"),
            ("tenant-reconciliation", "reconciliation_worker"),
            ("tenant-lifecycle", "lifecycle_worker"),
            ("release-adoption", "release_worker"),
            ("privacy-operations", "privacy_worker"),
        ] {
            let process_variables = required[process].as_array().unwrap();
            assert!(
                process_variables
                    .iter()
                    .any(|name| name == "CONTROL_RELEASE_ID"),
                "{process} startup contract omits the worker release identity"
            );
            let contract_requires_domain = process_variables
                .iter()
                .any(|name| name == "CONTROL_TENANT_DOMAIN");
            assert_eq!(
                TENANT_DOMAIN_QUEUES.contains(&queue),
                contract_requires_domain,
                "typed worker configuration and {process} startup contract disagree"
            );
        }
    }

    #[test]
    fn per_queue_tuning_ownership_matches_the_runtime_contract() {
        let specification: serde_json::Value =
            serde_json::from_str(include_str!("../deploy/configuration-spec.json")).unwrap();
        let runtime = specification["runtime_environment"].as_object().unwrap();
        for (service, expected) in [
            (
                "worker-invoice",
                &[
                    "CONTROL_PAPERLESS_CAPTURED_TAG_IDS",
                    "CONTROL_AZURE_MONTHLY_PAGE_LIMIT",
                    "CONTROL_AZURE_ANALYZE_MIN_INTERVAL_MS",
                ][..],
            ),
            (
                "worker-inventory",
                &[
                    "CONTROL_AZURE_MONTHLY_IMAGE_LIMIT",
                    "CONTROL_INVENTORY_AI_MONTHLY_IMAGE_LIMIT",
                    "CONTROL_AZURE_ANALYZE_MIN_INTERVAL_MS",
                ][..],
            ),
            (
                "worker-privacy",
                &["CONTROL_PRIVACY_DRIVER_URL", "CONTROL_PRIVACY_DRIVER_TOKEN"][..],
            ),
            (
                "worker-email",
                &[
                    "CONTROL_MAIL_WEBHOOK_URL",
                    "CONTROL_MAIL_WEBHOOK_TOKEN",
                    "CONTROL_PUBLIC_ORIGIN",
                    "CONTROL_INVITATION_SIGNING_KEY_ID",
                    "CONTROL_INVITATION_SIGNING_KEYS_FILE",
                ][..],
            ),
        ] {
            let variables = runtime[service]["variables"].as_array().unwrap();
            for name in expected {
                assert!(
                    variables.iter().any(|entry| entry == *name),
                    "{service} omits {name}"
                );
            }
        }
    }
}
