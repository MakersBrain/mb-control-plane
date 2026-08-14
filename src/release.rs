use std::collections::{BTreeMap, HashSet};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApplicationReleaseManifest {
    pub schema_version: u32,
    pub release_id: String,
    pub source_commit: String,
    pub odoo_version: String,
    pub image_digest: String,
    pub built_at: String,
    pub addons: BTreeMap<String, String>,
    pub oca: BTreeMap<String, String>,
    pub upgradeable_from: Vec<String>,
    pub database_runtime_compatibility: BTreeMap<String, RuntimeCompatibility>,
    pub bridge_contract: String,
    pub schema_epoch: u64,
    pub change_class: ChangeClass,
    pub required_postconditions: Vec<Postcondition>,
    pub capability_registry_version: u32,
    pub provenance: ReleaseProvenance,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ChangeClass {
    A,
    B,
    C,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeCompatibility {
    None,
    ReadOnly,
    ReadWrite,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Postcondition {
    RegistryLoad,
    InstalledVersions,
    MigrationLedger,
    RequiredColumns,
    XmlidOwnership,
    Health,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReleaseProvenance {
    pub oci_ref: String,
    pub cosign_bundle_ref: String,
    pub slsa_provenance_ref: String,
    pub sbom_ref: String,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ManifestError {
    #[error("unsupported application release schema version")]
    SchemaVersion,
    #[error("release_id must be an immutable Odoo release identifier")]
    ReleaseId,
    #[error("source_commit must be a full hexadecimal commit digest")]
    SourceCommit,
    #[error("image_digest must be a sha256 OCI digest")]
    ImageDigest,
    #[error("provenance.oci_ref must address the exact image digest")]
    OciReference,
    #[error("built_at must be an RFC 3339 timestamp")]
    BuiltAt,
    #[error("schema_epoch must be positive")]
    SchemaEpoch,
    #[error("capability_registry_version must be positive")]
    CapabilityRegistryVersion,
    #[error("release manifest contains a blank required value")]
    BlankValue,
    #[error("release compatibility contains a duplicate or unknown source release")]
    CompatibilitySource,
    #[error("required postconditions must be unique and include registry_load and health")]
    Postconditions,
    #[error("class B requires a retained source runtime declared read-write compatible")]
    ClassBCompatibility,
}

impl ApplicationReleaseManifest {
    pub fn validate(&self) -> Result<(), ManifestError> {
        if self.schema_version != 1 {
            return Err(ManifestError::SchemaVersion);
        }
        if !release_id(&self.release_id) {
            return Err(ManifestError::ReleaseId);
        }
        if !hex_digest(&self.source_commit, 40, 64) {
            return Err(ManifestError::SourceCommit);
        }
        if !sha256_digest(&self.image_digest) {
            return Err(ManifestError::ImageDigest);
        }
        let expected_suffix = format!("@{}", self.image_digest);
        if self.provenance.oci_ref.starts_with("http")
            || !self.provenance.oci_ref.ends_with(&expected_suffix)
            || self.provenance.oci_ref[..self.provenance.oci_ref.len() - expected_suffix.len()]
                .trim()
                .is_empty()
        {
            return Err(ManifestError::OciReference);
        }
        if OffsetDateTime::parse(&self.built_at, &Rfc3339).is_err() {
            return Err(ManifestError::BuiltAt);
        }
        if self.schema_epoch == 0 {
            return Err(ManifestError::SchemaEpoch);
        }
        if self.capability_registry_version == 0 {
            return Err(ManifestError::CapabilityRegistryVersion);
        }
        if self.odoo_version.trim().is_empty()
            || self.bridge_contract.trim().is_empty()
            || self.addons.values().any(|value| value.trim().is_empty())
            || self.oca.values().any(|value| !hex_digest(value, 40, 64))
            || [
                &self.provenance.oci_ref,
                &self.provenance.cosign_bundle_ref,
                &self.provenance.slsa_provenance_ref,
                &self.provenance.sbom_ref,
            ]
            .iter()
            .any(|value| value.trim().is_empty())
        {
            return Err(ManifestError::BlankValue);
        }

        let sources: HashSet<_> = self.upgradeable_from.iter().collect();
        if sources.len() != self.upgradeable_from.len()
            || sources.contains(&self.release_id)
            || self
                .database_runtime_compatibility
                .keys()
                .any(|release| !sources.contains(release))
        {
            return Err(ManifestError::CompatibilitySource);
        }

        let postconditions: HashSet<_> = self.required_postconditions.iter().collect();
        if postconditions.len() != self.required_postconditions.len()
            || !postconditions.contains(&Postcondition::RegistryLoad)
            || !postconditions.contains(&Postcondition::Health)
        {
            return Err(ManifestError::Postconditions);
        }

        if self.change_class == ChangeClass::B
            && !self
                .database_runtime_compatibility
                .values()
                .any(|value| *value == RuntimeCompatibility::ReadWrite)
        {
            return Err(ManifestError::ClassBCompatibility);
        }
        Ok(())
    }
}

fn release_id(value: &str) -> bool {
    let Some((date, commit)) = value
        .strip_prefix("odoo-")
        .and_then(|value| value.rsplit_once('-'))
    else {
        return false;
    };
    let date_parts: Vec<_> = date.split('.').collect();
    date_parts.len() == 3
        && date_parts[0].len() == 4
        && date_parts[1].len() == 2
        && date_parts[2].len() == 2
        && date_parts
            .iter()
            .all(|part| part.bytes().all(|byte| byte.is_ascii_digit()))
        && hex_digest(commit, 7, 64)
}

fn sha256_digest(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|digest| hex_digest(digest, 64, 64))
}

fn hex_digest(value: &str, minimum: usize, maximum: usize) -> bool {
    (minimum..=maximum).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> ApplicationReleaseManifest {
        ApplicationReleaseManifest {
            schema_version: 1,
            release_id: "odoo-2026.08.14-2cbc37c".into(),
            source_commit: "2cbc37c000000000000000000000000000000000".into(),
            odoo_version: "19.0".into(),
            image_digest: format!("sha256:{}", "a".repeat(64)),
            built_at: "2026-08-14T10:00:00Z".into(),
            addons: BTreeMap::from([("mb_ceramics_workflow".into(), "19.0.3.0.0".into())]),
            oca: BTreeMap::from([("auth_oidc".into(), "f".repeat(40))]),
            upgradeable_from: vec!["odoo-2026.07.30-1111111".into()],
            database_runtime_compatibility: BTreeMap::from([(
                "odoo-2026.07.30-1111111".into(),
                RuntimeCompatibility::ReadWrite,
            )]),
            bridge_contract: ">=3.2.0,<4.0.0".into(),
            schema_epoch: 42,
            change_class: ChangeClass::B,
            required_postconditions: vec![Postcondition::RegistryLoad, Postcondition::Health],
            capability_registry_version: 1,
            provenance: ReleaseProvenance {
                oci_ref: format!("registry.example/odoo@sha256:{}", "a".repeat(64)),
                cosign_bundle_ref: "oci://release/cosign".into(),
                slsa_provenance_ref: "oci://release/provenance".into(),
                sbom_ref: "oci://release/sbom".into(),
            },
        }
    }

    #[test]
    fn accepts_directional_class_b_manifest() {
        assert_eq!(manifest().validate(), Ok(()));
    }

    #[test]
    fn rejects_class_b_without_read_write_rollback_compatibility() {
        let mut value = manifest();
        value.database_runtime_compatibility.insert(
            "odoo-2026.07.30-1111111".into(),
            RuntimeCompatibility::ReadOnly,
        );
        assert_eq!(value.validate(), Err(ManifestError::ClassBCompatibility));
    }

    #[test]
    fn rejects_compatibility_for_an_unlisted_source() {
        let mut value = manifest();
        value.database_runtime_compatibility.insert(
            "odoo-2026.06.01-2222222".into(),
            RuntimeCompatibility::ReadWrite,
        );
        assert_eq!(value.validate(), Err(ManifestError::CompatibilitySource));
    }

    #[test]
    fn rejects_an_oci_reference_not_bound_to_the_image_digest() {
        let mut value = manifest();
        value.provenance.oci_ref = format!("registry.example/odoo@sha256:{}", "b".repeat(64));
        assert_eq!(value.validate(), Err(ManifestError::OciReference));
    }
}
