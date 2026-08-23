use std::collections::{BTreeMap, HashSet};

use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

pub const MAX_FLEET_TENANTS: usize = 500;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApplicationReleaseManifest {
    pub schema_version: u32,
    pub release_id: String,
    pub source_commit: String,
    pub built_at: String,
    pub odoo_runtime: OdooRuntimeDescriptor,
    pub extension_bundle: ExtensionBundleDescriptor,
    pub pair_qualifications: Vec<PairQualification>,
    pub addons: BTreeMap<String, String>,
    pub locked_dependencies: Vec<LockedDependency>,
    pub upgradeable_from: Vec<String>,
    pub database_runtime_compatibility: BTreeMap<String, RuntimeCompatibility>,
    pub bridge_contract: String,
    pub bridge_contract_digest: String,
    pub schema_epoch: u64,
    pub change_class: ChangeClass,
    pub required_postconditions: Vec<Postcondition>,
    pub capability_registry_version: u32,
    pub admission_signature: EvidenceObject,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OdooRuntimeDescriptor {
    pub official_source_ref: String,
    pub deployment_ref: String,
    pub subject_digest: String,
    pub subject_kind: SubjectKind,
    pub version: String,
    pub platforms: Vec<OdooRuntimePlatform>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OdooRuntimePlatform {
    pub platform: Platform,
    pub manifest_digest: String,
    pub config_digest: String,
    pub evidence: RuntimeEvidence,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeEvidence {
    pub sbom: EvidenceObject,
    pub vulnerability_report: EvidenceObject,
    pub scanner: String,
    pub advisory_snapshot_at: String,
    pub policy_digest: String,
    pub sbom_kind: SbomKind,
    pub capability_checks_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExtensionBundleDescriptor {
    pub oci_ref: String,
    pub subject_digest: String,
    pub subject_kind: SubjectKind,
    pub platforms: Vec<ExtensionPlatform>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExtensionPlatform {
    pub platform: Platform,
    pub manifest_digest: String,
    pub config_digest: String,
    pub payload_digest: String,
    pub python_implementation: String,
    pub python_abi: String,
    pub python_platform: String,
    pub dependency_inventory_digest: String,
    pub lock_file_digest: String,
    pub qualified_odoo_runtime: QualifiedOdooRuntime,
    pub signature: EvidenceObject,
    pub sbom: EvidenceObject,
    pub vulnerability_report: EvidenceObject,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct QualifiedOdooRuntime {
    pub official_source_ref: String,
    pub deployment_ref: String,
    pub subject_digest: String,
    pub subject_kind: SubjectKind,
    pub platform: Platform,
    pub manifest_digest: String,
    pub config_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PairQualification {
    pub platform: Platform,
    pub odoo_manifest_digest: String,
    pub extension_manifest_digest: String,
    pub payload_digest: String,
    pub qualification_result: QualificationResult,
    pub qualification_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(deny_unknown_fields)]
pub struct Platform {
    pub os: String,
    pub architecture: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variant: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvidenceObject {
    pub reference: String,
    pub subject_digest: String,
    pub sha256_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LockedDependency {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SubjectKind {
    ImageIndex,
    ImageManifest,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SbomKind {
    Observed,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum QualificationResult {
    Passed,
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

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ManifestError {
    #[error("unsupported application release schema version")]
    SchemaVersion,
    #[error("release_id must be an immutable Odoo release identifier")]
    ReleaseId,
    #[error("source_commit must be a full hexadecimal commit digest")]
    SourceCommit,
    #[error("an OCI identity or evidence digest is invalid")]
    Digest,
    #[error("an OCI reference is not bound to its declared subject digest")]
    OciReference,
    #[error("timestamp is not RFC 3339")]
    Timestamp,
    #[error("release contains a blank or unsupported platform value")]
    BlankValue,
    #[error("platform descriptors must be unique and have exact runtime/extension parity")]
    Platforms,
    #[error("extension qualification does not exactly equal the selected Odoo runtime")]
    QualifiedRuntime,
    #[error("pair qualification is absent, duplicated, mismatched, or has an invalid digest")]
    PairQualification,
    #[error("schema and capability registry versions must be positive")]
    Version,
    #[error("release compatibility contains a duplicate or unknown source release")]
    CompatibilitySource,
    #[error("required postconditions must be unique and include registry_load and health")]
    Postconditions,
    #[error("class B requires a retained source runtime declared read-write compatible")]
    ClassBCompatibility,
}

impl ApplicationReleaseManifest {
    /// Canonical bytes covered by the detached admission signature. The
    /// signature locator is the envelope and is deliberately excluded so the
    /// signed payload does not contain a circular reference to its own bundle.
    pub fn admission_payload(&self) -> Result<Vec<u8>, serde_json::Error> {
        let mut value = serde_json::to_value(self)?;
        value
            .as_object_mut()
            .expect("application release serializes as an object")
            .remove("admission_signature");
        serde_jcs::to_vec(&value)
    }

    pub fn validate(&self) -> Result<(), ManifestError> {
        if self.schema_version != 2 {
            return Err(ManifestError::SchemaVersion);
        }
        if !release_id(&self.release_id) {
            return Err(ManifestError::ReleaseId);
        }
        if !hex_digest(&self.source_commit, 40, 64) {
            return Err(ManifestError::SourceCommit);
        }
        if OffsetDateTime::parse(&self.built_at, &Rfc3339).is_err() {
            return Err(ManifestError::Timestamp);
        }
        if self.schema_epoch == 0 || self.capability_registry_version == 0 {
            return Err(ManifestError::Version);
        }
        if self.odoo_runtime.version.trim().is_empty()
            || self.bridge_contract.trim().is_empty()
            || self.addons.values().any(|v| v.trim().is_empty())
            || self
                .locked_dependencies
                .iter()
                .any(|value| value.name.trim().is_empty() || value.version.trim().is_empty())
        {
            return Err(ManifestError::BlankValue);
        }
        if self
            .locked_dependencies
            .iter()
            .map(|value| &value.name)
            .collect::<HashSet<_>>()
            .len()
            != self.locked_dependencies.len()
        {
            return Err(ManifestError::BlankValue);
        }
        for digest in [
            &self.odoo_runtime.subject_digest,
            &self.extension_bundle.subject_digest,
            &self.bridge_contract_digest,
        ] {
            require_digest(digest)?;
        }
        require_oci_ref(
            &self.odoo_runtime.official_source_ref,
            &self.odoo_runtime.subject_digest,
        )?;
        require_oci_ref(
            &self.odoo_runtime.deployment_ref,
            &self.odoo_runtime.subject_digest,
        )?;
        require_oci_ref(
            &self.extension_bundle.oci_ref,
            &self.extension_bundle.subject_digest,
        )?;
        validate_evidence(&self.admission_signature)?;
        if self.odoo_runtime.platforms.is_empty()
            || self.odoo_runtime.platforms.len() != self.extension_bundle.platforms.len()
            || self.odoo_runtime.platforms.len() != self.pair_qualifications.len()
        {
            return Err(ManifestError::Platforms);
        }

        let mut runtime_platforms = HashSet::new();
        for runtime in &self.odoo_runtime.platforms {
            validate_platform(&runtime.platform)?;
            if !runtime_platforms.insert(runtime.platform.clone()) {
                return Err(ManifestError::Platforms);
            }
            require_digest(&runtime.manifest_digest)?;
            require_digest(&runtime.config_digest)?;
            validate_evidence(&runtime.evidence.sbom)?;
            validate_evidence(&runtime.evidence.vulnerability_report)?;
            require_digest(&runtime.evidence.policy_digest)?;
            require_digest(&runtime.evidence.capability_checks_digest)?;
            if runtime.evidence.scanner.trim().is_empty()
                || OffsetDateTime::parse(&runtime.evidence.advisory_snapshot_at, &Rfc3339).is_err()
            {
                return Err(ManifestError::Timestamp);
            }
        }
        let mut extension_platforms = HashSet::new();
        for extension in &self.extension_bundle.platforms {
            validate_platform(&extension.platform)?;
            if !extension_platforms.insert(extension.platform.clone()) {
                return Err(ManifestError::Platforms);
            }
            for digest in [
                &extension.manifest_digest,
                &extension.config_digest,
                &extension.payload_digest,
                &extension.dependency_inventory_digest,
                &extension.lock_file_digest,
            ] {
                require_digest(digest)?;
            }
            for evidence in [
                &extension.signature,
                &extension.sbom,
                &extension.vulnerability_report,
            ] {
                validate_evidence(evidence)?;
            }
            if extension.python_implementation != "cpython"
                || extension.python_abi.trim().is_empty()
                || extension.python_platform.trim().is_empty()
            {
                return Err(ManifestError::BlankValue);
            }
            let runtime = self
                .odoo_runtime
                .platforms
                .iter()
                .find(|r| r.platform == extension.platform)
                .ok_or(ManifestError::Platforms)?;
            let q = &extension.qualified_odoo_runtime;
            if q.official_source_ref != self.odoo_runtime.official_source_ref
                || q.deployment_ref != self.odoo_runtime.deployment_ref
                || q.subject_digest != self.odoo_runtime.subject_digest
                || q.subject_kind != self.odoo_runtime.subject_kind
                || q.platform != runtime.platform
                || q.manifest_digest != runtime.manifest_digest
                || q.config_digest != runtime.config_digest
            {
                return Err(ManifestError::QualifiedRuntime);
            }
            let pair = self
                .pair_qualifications
                .iter()
                .find(|p| p.platform == extension.platform)
                .ok_or(ManifestError::PairQualification)?;
            if pair.odoo_manifest_digest != runtime.manifest_digest
                || pair.extension_manifest_digest != extension.manifest_digest
                || pair.payload_digest != extension.payload_digest
                || pair.qualification_digest
                    != self.expected_pair_qualification_digest(extension, pair)
            {
                return Err(ManifestError::PairQualification);
            }
        }
        if runtime_platforms != extension_platforms
            || self
                .pair_qualifications
                .iter()
                .map(|p| &p.platform)
                .collect::<HashSet<_>>()
                .len()
                != self.pair_qualifications.len()
        {
            return Err(ManifestError::Platforms);
        }
        let sources: HashSet<_> = self.upgradeable_from.iter().collect();
        if sources.len() != self.upgradeable_from.len()
            || sources.contains(&self.release_id)
            || self
                .database_runtime_compatibility
                .keys()
                .any(|r| !sources.contains(r))
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
                .any(|v| *v == RuntimeCompatibility::ReadWrite)
        {
            return Err(ManifestError::ClassBCompatibility);
        }
        Ok(())
    }

    pub fn selected_platform(
        &self,
    ) -> Option<(&OdooRuntimePlatform, &ExtensionPlatform, &PairQualification)> {
        if self.odoo_runtime.platforms.len() != 1 {
            return None;
        }
        let runtime = &self.odoo_runtime.platforms[0];
        Some((
            runtime,
            self.extension_bundle
                .platforms
                .iter()
                .find(|v| v.platform == runtime.platform)?,
            self.pair_qualifications
                .iter()
                .find(|v| v.platform == runtime.platform)?,
        ))
    }

    fn expected_pair_qualification_digest(
        &self,
        extension: &ExtensionPlatform,
        pair: &PairQualification,
    ) -> String {
        let value = json!({"runtime":&extension.qualified_odoo_runtime,
            "extension":{"subject_digest":&self.extension_bundle.subject_digest,"manifest_digest":&extension.manifest_digest,"config_digest":&extension.config_digest},
            "payload_digest":&extension.payload_digest,"bridge_contract_digest":&self.bridge_contract_digest,
            "addon_versions":&self.addons,"qualification_result":pair.qualification_result});
        format!(
            "sha256:{:x}",
            Sha256::digest(
                serde_jcs::to_vec(&value).expect("qualification serialization cannot fail")
            )
        )
    }
}

fn validate_platform(platform: &Platform) -> Result<(), ManifestError> {
    if platform.os != "linux"
        || platform.architecture.trim().is_empty()
        || platform
            .variant
            .as_ref()
            .is_some_and(|v| v.trim().is_empty())
    {
        Err(ManifestError::BlankValue)
    } else {
        Ok(())
    }
}
fn validate_evidence(e: &EvidenceObject) -> Result<(), ManifestError> {
    require_digest(&e.subject_digest)?;
    require_digest(&e.sha256_digest)?;
    require_oci_ref(&e.reference, &e.subject_digest)
}
fn require_digest(v: &str) -> Result<(), ManifestError> {
    sha256_digest(v).then_some(()).ok_or(ManifestError::Digest)
}
fn require_oci_ref(value: &str, digest: &str) -> Result<(), ManifestError> {
    let suffix = format!("@{digest}");
    if value.starts_with("http")
        || !value.ends_with(&suffix)
        || value[..value.len() - suffix.len()].trim().is_empty()
    {
        Err(ManifestError::OciReference)
    } else {
        Ok(())
    }
}
fn release_id(value: &str) -> bool {
    let Some((date, commit)) = value.strip_prefix("odoo-").and_then(|v| v.rsplit_once('-')) else {
        return false;
    };
    let parts: Vec<_> = date.split('.').collect();
    parts.len() == 3
        && parts[0].len() == 4
        && parts[1].len() == 2
        && parts[2].len() == 2
        && parts.iter().all(|p| p.bytes().all(|b| b.is_ascii_digit()))
        && hex_digest(commit, 7, 64)
}
fn sha256_digest(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|d| hex_digest(d, 64, 64))
}
fn hex_digest(value: &str, min: usize, max: usize) -> bool {
    (min..=max).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::Value;

    fn digest(character: char) -> String {
        format!("sha256:{}", character.to_string().repeat(64))
    }

    fn evidence(character: char) -> Value {
        let subject = digest(character);
        json!({"reference":format!("registry.example/evidence@{subject}"),"subject_digest":subject,"sha256_digest":digest('f')})
    }

    pub(crate) fn fixture() -> ApplicationReleaseManifest {
        let platform = json!({"os":"linux","architecture":"amd64"});
        let runtime_subject = digest('1');
        let runtime_manifest = digest('2');
        let runtime_config = digest('3');
        let extension_subject = digest('4');
        let extension_manifest = digest('5');
        let extension_config = digest('6');
        let payload = digest('7');
        let qualified = json!({
            "official_source_ref":format!("docker.io/library/odoo@{runtime_subject}"),
            "deployment_ref":format!("docker.io/library/odoo@{runtime_subject}"),
            "subject_digest":runtime_subject,"subject_kind":"image_index","platform":platform,
            "manifest_digest":runtime_manifest,"config_digest":runtime_config
        });
        let addons = json!({"mb_control_bridge":"19.0.1.0.0"});
        let pair_input = json!({
            "runtime":qualified,
            "extension":{"subject_digest":extension_subject,"manifest_digest":extension_manifest,"config_digest":extension_config},
            "payload_digest":payload,"bridge_contract_digest":digest('8'),
            "addon_versions":addons,"qualification_result":"passed"
        });
        let qualification = format!(
            "sha256:{:x}",
            Sha256::digest(serde_jcs::to_vec(&pair_input).unwrap())
        );
        serde_json::from_value(json!({
            "schema_version":2,"release_id":"odoo-2026.08.21-abcdef0","source_commit":"a".repeat(40),
            "built_at":"2026-08-21T12:00:00Z",
            "odoo_runtime":{"official_source_ref":format!("docker.io/library/odoo@{runtime_subject}"),"deployment_ref":format!("docker.io/library/odoo@{runtime_subject}"),"subject_digest":runtime_subject,"subject_kind":"image_index","version":"19.0","platforms":[{"platform":platform,"manifest_digest":runtime_manifest,"config_digest":runtime_config,"evidence":{"sbom":evidence('9'),"vulnerability_report":evidence('a'),"scanner":"syft/grype pinned","advisory_snapshot_at":"2026-08-21T12:00:00Z","policy_digest":digest('b'),"sbom_kind":"observed","capability_checks_digest":digest('c')}}]},
            "extension_bundle":{"oci_ref":format!("registry.example/extension@{extension_subject}"),"subject_digest":extension_subject,"subject_kind":"image_index","platforms":[{"platform":platform,"manifest_digest":extension_manifest,"config_digest":extension_config,"payload_digest":payload,"python_implementation":"cpython","python_abi":"cp312","python_platform":"linux_x86_64","dependency_inventory_digest":digest('d'),"lock_file_digest":digest('e'),"qualified_odoo_runtime":qualified,"signature":evidence('b'),"sbom":evidence('c'),"vulnerability_report":evidence('d')}]},
            "pair_qualifications":[{"platform":platform,"odoo_manifest_digest":runtime_manifest,"extension_manifest_digest":extension_manifest,"payload_digest":payload,"qualification_result":"passed","qualification_digest":qualification}],
            "addons":addons,"locked_dependencies":[],"upgradeable_from":[],"database_runtime_compatibility":{},
            "bridge_contract":"mb_control/v1","bridge_contract_digest":digest('8'),"schema_epoch":1,"change_class":"A",
            "required_postconditions":["registry_load","health"],"capability_registry_version":1,"admission_signature":evidence('e')
        })).unwrap()
    }

    #[test]
    fn exact_paired_release_validates_and_tampering_fails_closed() {
        let manifest = fixture();
        assert_eq!(manifest.validate(), Ok(()));
        let mut tampered = manifest;
        tampered.extension_bundle.platforms[0].payload_digest = digest('0');
        assert_eq!(tampered.validate(), Err(ManifestError::PairQualification));
    }

    #[test]
    fn admission_payload_excludes_only_its_detached_signature_locator() {
        let mut manifest = fixture();
        let before = manifest.admission_payload().unwrap();
        manifest.admission_signature = serde_json::from_value(evidence('0')).unwrap();
        assert_eq!(before, manifest.admission_payload().unwrap());
        manifest.source_commit = "b".repeat(40);
        assert_ne!(before, manifest.admission_payload().unwrap());
    }
}
