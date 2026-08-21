use std::collections::{HashMap, HashSet};

use serde::Deserialize;
use url::Url;

#[derive(Deserialize)]
struct ConfigurationSpecification {
    required_environment: HashMap<String, Vec<String>>,
    secrets: HashSet<String>,
}

fn specification() -> anyhow::Result<ConfigurationSpecification> {
    serde_json::from_str(include_str!("../deploy/configuration-spec.json")).map_err(|error| {
        anyhow::anyhow!("embedded configuration specification is invalid: {error}")
    })
}

fn placeholder(value: &str) -> bool {
    let value = value.trim().to_ascii_lowercase();
    value.starts_with("replace-")
        || matches!(
            value.as_str(),
            "changeme" | "change-me" | "placeholder" | "example-secret" | "pending"
        )
}

fn validate_postgres_tls_url(name: &str, value: &str) -> anyhow::Result<()> {
    let url = Url::parse(value).map_err(|_| anyhow::anyhow!("{name} is not a valid URL"))?;
    if !matches!(url.scheme(), "postgres" | "postgresql") {
        anyhow::bail!("{name} must use PostgreSQL");
    }
    let query: HashMap<_, _> = url.query_pairs().collect();
    if query.get("sslmode").map(|value| value.as_ref()) != Some("verify-full") {
        anyhow::bail!("{name} must use sslmode=verify-full outside development");
    }
    let root = query
        .get("sslrootcert")
        .map(|value| value.as_ref())
        .unwrap_or_default();
    if !root.starts_with("/run/secrets/") || root.contains("..") {
        anyhow::bail!("{name} must use a mounted PostgreSQL CA below /run/secrets");
    }
    Ok(())
}

fn validate_with(process: &str, lookup: impl Fn(&str) -> Option<String>) -> anyhow::Result<()> {
    let specification = specification()?;
    let required = specification
        .required_environment
        .get(process)
        .ok_or_else(|| {
            anyhow::anyhow!("process {process} is absent from configuration-spec.json")
        })?;
    for name in required {
        let value = lookup(name)
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| anyhow::anyhow!("{name} is required for {process}"))?;
        if specification.secrets.contains(name) && placeholder(&value) {
            anyhow::bail!("{name} contains a forbidden placeholder for {process}");
        }
        let deployment_environment = if process == "docker_driver" {
            lookup("DRIVER_ENVIRONMENT")
        } else {
            lookup("CONTROL_DEPLOYMENT_ENVIRONMENT")
        };
        if matches!(
            deployment_environment.as_deref(),
            Some("staging" | "production")
        ) && (name.ends_with("DATABASE_URL") || name == "DRIVER_POSTGRES_ADMIN_URL")
        {
            validate_postgres_tls_url(name, &value)?;
        }
    }
    if process == "privacy_worker" {
        let lookup_key = lookup("CONTROL_PRIVACY_LOOKUP_KEY").unwrap_or_default();
        let export_key = lookup("CONTROL_PRIVACY_EXPORT_KEY").unwrap_or_default();
        if lookup_key.trim() == export_key.trim() {
            anyhow::bail!("privacy lookup and export encryption keys must be distinct");
        }
    }
    Ok(())
}

pub fn validate_process(process: &str) -> anyhow::Result<()> {
    let specification = specification()?;
    validate_with(process, |name| {
        if specification.secrets.contains(name) {
            crate::runtime_secret::environment(name).ok().flatten()
        } else {
            crate::runtime_secret::configuration(name).ok().flatten()
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_api_values() -> HashMap<String, String> {
        specification().unwrap().required_environment["api"]
            .iter()
            .map(|name| (name.clone(), format!("valid-{name}")))
            .collect()
    }

    #[test]
    fn every_release_process_has_a_configuration_owner() {
        let specification = specification().unwrap();
        for process in [
            "migration",
            "api",
            "membership_worker",
            "provisioning_worker",
            "invoice_worker",
            "inventory_worker",
            "email_worker",
            "reconciliation_worker",
            "lifecycle_worker",
            "release_worker",
            "privacy_worker",
            "docker_driver",
            "backup_scheduler",
            "document_extraction_broker",
            "mail_gateway",
        ] {
            assert!(
                specification.required_environment.contains_key(process),
                "missing startup contract for {process}"
            );
        }
    }

    #[test]
    fn required_secret_aliases_are_classified_as_secrets() {
        let specification = specification().unwrap();
        assert!(
            specification
                .secrets
                .contains("CONTROL_DEPLOYMENT_DRIVER_TOKEN")
        );
    }

    #[test]
    fn startup_gate_rejects_missing_and_placeholder_secrets() {
        let mut values = valid_api_values();
        values.remove("CONTROL_DATABASE_URL");
        assert!(validate_with("api", |name| values.get(name).cloned()).is_err());
        values.insert("CONTROL_DATABASE_URL".into(), "postgresql://valid".into());
        values.insert("CONTROL_INTERNAL_TOKEN".into(), "replace-me".into());
        assert!(validate_with("api", |name| values.get(name).cloned()).is_err());
    }

    #[test]
    fn startup_gate_accepts_a_complete_process_environment() {
        let values = valid_api_values();
        validate_with("api", |name| values.get(name).cloned()).unwrap();
    }

    #[test]
    fn privacy_encryption_purposes_cannot_share_a_key() {
        let mut values = specification().unwrap().required_environment["privacy_worker"]
            .iter()
            .map(|name| (name.clone(), format!("valid-{name}")))
            .collect::<HashMap<_, _>>();
        values.insert("CONTROL_PRIVACY_LOOKUP_KEY".into(), "same-key".into());
        values.insert("CONTROL_PRIVACY_EXPORT_KEY".into(), " same-key ".into());
        assert!(validate_with("privacy_worker", |name| values.get(name).cloned()).is_err());
        values.insert("CONTROL_PRIVACY_EXPORT_KEY".into(), "another-key".into());
        validate_with("privacy_worker", |name| values.get(name).cloned()).unwrap();
    }

    #[test]
    fn production_style_database_urls_require_full_certificate_validation() {
        let mut values = valid_api_values();
        values.insert("CONTROL_DEPLOYMENT_ENVIRONMENT".into(), "staging".into());
        values.insert(
            "CONTROL_DATABASE_URL".into(),
            "postgresql://control:secret@db.internal/control".into(),
        );
        assert!(validate_with("api", |name| values.get(name).cloned()).is_err());
        values.insert(
            "CONTROL_DATABASE_URL".into(),
            "postgresql://control:secret@db.internal/control?sslmode=verify-full&sslrootcert=%2Frun%2Fsecrets%2Fpostgres-ca.crt".into(),
        );
        validate_with("api", |name| values.get(name).cloned()).unwrap();
    }

    #[test]
    fn development_database_urls_remain_compatible_without_tls_query_parameters() {
        let mut values = valid_api_values();
        values.insert(
            "CONTROL_DATABASE_URL".into(),
            "postgresql://control:secret@postgres/control".into(),
        );
        validate_with("api", |name| values.get(name).cloned()).unwrap();
    }
}
