use std::path::PathBuf;
use std::time::Duration;

use url::Url;

use crate::config::ConfigError;

const DEFAULT_INTERVAL: Duration = Duration::from_secs(3_600);
const MIN_INTERVAL_SECONDS: u64 = 60;
const MAX_INTERVAL_SECONDS: u64 = 86_400;

/// Immutable configuration for the backup and recovery rehearsal scheduler.
///
/// The executable loads this value before telemetry, PostgreSQL, or the
/// deployment-driver client are initialized. Scheduler work therefore never
/// discovers malformed process configuration after it has started.
pub struct BackupSchedulerConfig {
    database_url: String,
    release_id: String,
    enabled: bool,
    interval: Duration,
    driver_url: Url,
    driver_token: String,
    driver_socket: Option<PathBuf>,
}

impl BackupSchedulerConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(
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
        configuration: &dyn Fn(&'static str) -> Result<Option<String>, ConfigError>,
        secret: &dyn Fn(&'static str) -> Result<Option<String>, ConfigError>,
    ) -> Result<Self, ConfigError> {
        let database_url = required(secret, "CONTROL_DATABASE_URL")?;
        crate::config::validate_database_url("CONTROL_DATABASE_URL", &database_url)?;

        let release_id = required(configuration, "CONTROL_RELEASE_ID")?;
        validate_release_id(&release_id)?;

        let enabled = optional(configuration, "CONTROL_BACKUP_SCHEDULER_ENABLED")?
            .map(|value| parse_boolean("CONTROL_BACKUP_SCHEDULER_ENABLED", &value))
            .transpose()?
            .unwrap_or(false);
        let interval = optional(configuration, "CONTROL_BACKUP_INTERVAL_SECONDS")?
            .map(|value| parse_interval(&value))
            .transpose()?
            .unwrap_or(DEFAULT_INTERVAL);

        let driver_url_value = required(configuration, "CONTROL_DEPLOYMENT_DRIVER_URL")?;
        let driver_url = parse_driver_url(&driver_url_value)?;
        let driver_token = required(secret, "CONTROL_DEPLOYMENT_DRIVER_TOKEN")?;
        let driver_socket =
            optional(configuration, "CONTROL_DEPLOYMENT_DRIVER_SOCKET")?.map(PathBuf::from);
        if driver_socket
            .as_ref()
            .is_some_and(|path| !path.is_absolute())
        {
            return Err(ConfigError::Invalid {
                name: "CONTROL_DEPLOYMENT_DRIVER_SOCKET",
                reason: "must be an absolute path".into(),
            });
        }

        Ok(Self {
            database_url,
            release_id,
            enabled,
            interval,
            driver_url,
            driver_token,
            driver_socket,
        })
    }

    pub fn database_url(&self) -> &str {
        &self.database_url
    }

    pub fn release_id(&self) -> &str {
        &self.release_id
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn interval(&self) -> Duration {
        self.interval
    }

    pub fn driver_url(&self) -> &Url {
        &self.driver_url
    }

    pub fn driver_token(&self) -> &str {
        &self.driver_token
    }

    pub fn driver_socket(&self) -> Option<&std::path::Path> {
        self.driver_socket.as_deref()
    }
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

fn validate_release_id(value: &str) -> Result<(), ConfigError> {
    if !(1..=200).contains(&value.len()) || !value.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(ConfigError::Invalid {
            name: "CONTROL_RELEASE_ID",
            reason: "must be 1-200 printable ASCII characters without whitespace".into(),
        });
    }
    Ok(())
}

fn parse_boolean(name: &'static str, value: &str) -> Result<bool, ConfigError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(ConfigError::Invalid {
            name,
            reason: "must be true or false".into(),
        }),
    }
}

fn parse_interval(value: &str) -> Result<Duration, ConfigError> {
    let seconds = value
        .trim()
        .parse::<u64>()
        .map_err(|error| ConfigError::Invalid {
            name: "CONTROL_BACKUP_INTERVAL_SECONDS",
            reason: format!("must be an integer number of seconds: {error}"),
        })?;
    if !(MIN_INTERVAL_SECONDS..=MAX_INTERVAL_SECONDS).contains(&seconds) {
        return Err(ConfigError::Invalid {
            name: "CONTROL_BACKUP_INTERVAL_SECONDS",
            reason: format!(
                "must be between {MIN_INTERVAL_SECONDS} and {MAX_INTERVAL_SECONDS} seconds"
            ),
        });
    }
    Ok(Duration::from_secs(seconds))
}

fn parse_driver_url(value: &str) -> Result<Url, ConfigError> {
    let mut url = Url::parse(value).map_err(|error| ConfigError::Invalid {
        name: "CONTROL_DEPLOYMENT_DRIVER_URL",
        reason: format!("must be an absolute HTTP URL: {error}"),
    })?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err(ConfigError::Invalid {
            name: "CONTROL_DEPLOYMENT_DRIVER_URL",
            reason: "must be an absolute HTTP or HTTPS URL".into(),
        });
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(ConfigError::Invalid {
            name: "CONTROL_DEPLOYMENT_DRIVER_URL",
            reason: "must not contain credentials".into(),
        });
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(ConfigError::Invalid {
            name: "CONTROL_DEPLOYMENT_DRIVER_URL",
            reason: "must not contain a query or fragment".into(),
        });
    }
    // Preserve a supported path prefix while making endpoint concatenation
    // deterministic for values entered with or without a trailing slash.
    let normalized = url.path().trim_end_matches('/').to_owned();
    url.set_path(if normalized.is_empty() {
        "/"
    } else {
        &normalized
    });
    Ok(url)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn load(values: &[(&'static str, &str)]) -> Result<BackupSchedulerConfig, ConfigError> {
        let values = values.iter().copied().collect::<HashMap<_, _>>();
        BackupSchedulerConfig::from_lookup(
            &|name| Ok(values.get(name).map(|value| (*value).to_owned())),
            &|name| Ok(values.get(name).map(|value| (*value).to_owned())),
        )
    }

    fn required_values() -> Vec<(&'static str, &'static str)> {
        vec![
            (
                "CONTROL_DATABASE_URL",
                "postgresql://backup:secret@db/control",
            ),
            ("CONTROL_RELEASE_ID", "sha256:release-1"),
            ("CONTROL_DEPLOYMENT_DRIVER_URL", "http://driver:8080"),
            ("CONTROL_DEPLOYMENT_DRIVER_TOKEN", "driver-secret"),
        ]
    }

    #[test]
    fn defaults_are_disabled_and_hourly() {
        let config = load(&required_values()).unwrap();
        assert!(!config.enabled());
        assert_eq!(config.interval(), Duration::from_secs(3_600));
        assert_eq!(config.driver_url().as_str(), "http://driver:8080/");
        assert_eq!(config.driver_socket(), None);
    }

    #[test]
    fn optional_values_are_strictly_parsed() {
        let mut values = required_values();
        values.extend([
            ("CONTROL_BACKUP_SCHEDULER_ENABLED", "TRUE"),
            ("CONTROL_BACKUP_INTERVAL_SECONDS", "120"),
            ("CONTROL_DEPLOYMENT_DRIVER_SOCKET", "/run/driver.sock"),
        ]);
        let config = load(&values).unwrap();
        assert!(config.enabled());
        assert_eq!(config.interval(), Duration::from_secs(120));
        assert_eq!(
            config.driver_socket(),
            Some(std::path::Path::new("/run/driver.sock"))
        );

        for (name, value) in [
            ("CONTROL_BACKUP_SCHEDULER_ENABLED", "yes"),
            ("CONTROL_BACKUP_INTERVAL_SECONDS", "59"),
            ("CONTROL_BACKUP_INTERVAL_SECONDS", "86401"),
            ("CONTROL_BACKUP_INTERVAL_SECONDS", "not-a-number"),
            ("CONTROL_DEPLOYMENT_DRIVER_SOCKET", "relative.sock"),
        ] {
            let mut invalid = required_values();
            invalid.push((name, value));
            assert!(load(&invalid).is_err(), "{name}={value} must be rejected");
        }
    }

    #[test]
    fn required_urls_and_release_identity_are_validated() {
        for name in [
            "CONTROL_DATABASE_URL",
            "CONTROL_RELEASE_ID",
            "CONTROL_DEPLOYMENT_DRIVER_URL",
            "CONTROL_DEPLOYMENT_DRIVER_TOKEN",
        ] {
            let mut missing = required_values();
            missing.retain(|(existing, _)| *existing != name);
            assert!(
                matches!(load(&missing), Err(ConfigError::Missing(missing_name)) if missing_name == name),
                "missing {name} must be rejected"
            );
        }

        for (name, value) in [
            ("CONTROL_DATABASE_URL", "https://db/control"),
            ("CONTROL_DEPLOYMENT_DRIVER_URL", "ftp://driver/archive"),
            ("CONTROL_DEPLOYMENT_DRIVER_URL", "http://user:pass@driver"),
            ("CONTROL_RELEASE_ID", "release with spaces"),
        ] {
            let mut invalid = required_values();
            invalid.retain(|(existing, _)| *existing != name);
            invalid.push((name, value));
            assert!(load(&invalid).is_err(), "{name}={value} must be rejected");
        }
    }

    #[test]
    fn typed_ownership_matches_the_machine_readable_contract() {
        let specification: serde_json::Value =
            serde_json::from_str(include_str!("../deploy/configuration-spec.json")).unwrap();
        let required = specification["required_environment"]["backup_scheduler"]
            .as_array()
            .unwrap();
        for name in [
            "CONTROL_DATABASE_URL",
            "CONTROL_RELEASE_ID",
            "CONTROL_DEPLOYMENT_DRIVER_URL",
            "CONTROL_DEPLOYMENT_DRIVER_TOKEN",
        ] {
            assert!(required.iter().any(|entry| entry == name), "missing {name}");
        }
        let runtime = specification["runtime_environment"]["backup-scheduler"]["variables"]
            .as_array()
            .unwrap();
        for name in [
            "CONTROL_BACKUP_INTERVAL_SECONDS",
            "CONTROL_BACKUP_SCHEDULER_ENABLED",
        ] {
            assert!(runtime.iter().any(|entry| entry == name), "missing {name}");
        }
    }
}
