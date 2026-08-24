use std::{
    path::{Path, PathBuf},
    time::Duration,
};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::domain::IntegrationError;
use crate::persistence::{LeasedOperation, Store};
use crate::worker::release_driver_request_with_key;
use crate::worker_config::DeploymentDriverConfig;

#[tracing::instrument(
    name = "release.record_terminal_failure",
    skip_all,
    fields(scope.kind = "fleet")
)]
pub(crate) async fn failed(
    store: &Store,
    operation: &LeasedOperation,
) -> Result<(), IntegrationError> {
    let Some(release_id) = operation.payload.get("release_id").and_then(Value::as_str) else {
        return Err(IntegrationError::ContractDrift);
    };
    if let Err(error) = record_terminal_failure(store, operation, release_id).await {
        tracing::error!(
            operation=%operation.id,
            error_class=crate::error_reporting::safe_error_class(&error),
            "failed to record terminal release failure"
        );
        return Err(error);
    }
    Ok(())
}

async fn record_terminal_failure(
    store: &Store,
    operation: &LeasedOperation,
    release_id: &str,
) -> Result<(), IntegrationError> {
    let mut tx = store
        .begin()
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
    let current_lease = sqlx::query_scalar::<_, Uuid>(
        "select id from control.operations
         where id=$1 and state='in_flight' and leased_by=$2 and attempt=$3
           and lease_expires_at>now()
         for update",
    )
    .bind(operation.id)
    .bind(&operation.leased_by)
    .bind(operation.attempt)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| IntegrationError::Unavailable)?;
    if current_lease.is_none() {
        tx.commit()
            .await
            .map_err(|_| IntegrationError::Unavailable)?;
        return Ok(());
    }
    let release_status = sqlx::query_scalar::<_, String>(
        "select status from control.application_releases where id=$1 for update",
    )
    .bind(release_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| IntegrationError::Unavailable)?;
    let run = sqlx::query_as::<_, (Uuid, String)>(
        "select id,state from control.release_fleet_runs
         where operation_id=$1 and release_id=$2 for update",
    )
    .bind(operation.id)
    .bind(release_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| IntegrationError::Unavailable)?;
    let release_active = release_status.as_deref() == Some("active");
    let run_active = run.as_ref().is_some_and(|(_, state)| state == "active");
    match (release_active, run_active) {
        (true, true) => {
            tx.commit()
                .await
                .map_err(|_| IntegrationError::Unavailable)?;
            return Ok(());
        }
        (true, false) | (false, true) => return Err(IntegrationError::UnknownOutcome),
        (false, false) => {}
    }
    sqlx::query(
        "update control.application_releases set status='failed',version=version+1
         where id=$1 and status in ('candidate','preflighting','canary','prepared')",
    )
    .bind(release_id)
    .execute(&mut *tx)
    .await
    .map_err(|_| IntegrationError::Unavailable)?;
    sqlx::query(
        "update control.release_fleet_runs set state='failed',failure_class='release_operation_failed',updated_at=now()
         where operation_id=$1 and state in ('preflighting','preparing','paused','activating')",
    )
    .bind(operation.id)
    .execute(&mut *tx)
    .await
    .map_err(|_| IntegrationError::Unavailable)?;
    sqlx::query(
        "update control.runtime_release_slots set state='failed',version=version+1
         where release_id=$1 and state='prepared'",
    )
    .bind(release_id)
    .execute(&mut *tx)
    .await
    .map_err(|_| IntegrationError::Unavailable)?;
    tx.commit().await.map_err(|_| IntegrationError::Unavailable)
}

fn activation_evidence_matches_manifest(
    manifest: &crate::release::ApplicationReleaseManifest,
    evidence: &Value,
) -> bool {
    if manifest.validate().is_err()
        || evidence.get("release_id").and_then(Value::as_str) != Some(manifest.release_id.as_str())
        || evidence.get("odoo_subject_digest").and_then(Value::as_str)
            != Some(manifest.odoo_runtime.subject_digest.as_str())
        || evidence
            .get("extension_subject_digest")
            .and_then(Value::as_str)
            != Some(manifest.extension_bundle.subject_digest.as_str())
        || evidence
            .get("bridge_contract_digest")
            .and_then(Value::as_str)
            != Some(manifest.bridge_contract_digest.as_str())
        || evidence.get("installed_addon_versions")
            != serde_json::to_value(&manifest.addons).ok().as_ref()
    {
        return false;
    }
    manifest.odoo_runtime.platforms.iter().any(|runtime| {
        let Some(extension) = manifest
            .extension_bundle
            .platforms
            .iter()
            .find(|candidate| candidate.platform == runtime.platform)
        else {
            return false;
        };
        let Some(pair) = manifest
            .pair_qualifications
            .iter()
            .find(|candidate| candidate.platform == runtime.platform)
        else {
            return false;
        };
        evidence.get("odoo_manifest_digest").and_then(Value::as_str)
            == Some(runtime.manifest_digest.as_str())
            && evidence.get("odoo_config_digest").and_then(Value::as_str)
                == Some(runtime.config_digest.as_str())
            && evidence
                .get("extension_manifest_digest")
                .and_then(Value::as_str)
                == Some(extension.manifest_digest.as_str())
            && evidence
                .get("extension_config_digest")
                .and_then(Value::as_str)
                == Some(extension.config_digest.as_str())
            && evidence.get("payload_digest").and_then(Value::as_str)
                == Some(extension.payload_digest.as_str())
            && evidence
                .get("pair_qualification_digest")
                .and_then(Value::as_str)
                == Some(pair.qualification_digest.as_str())
            && pair.odoo_manifest_digest == runtime.manifest_digest
            && pair.extension_manifest_digest == extension.manifest_digest
            && pair.payload_digest == extension.payload_digest
    })
}

pub(crate) fn validate_configuration() -> anyhow::Result<()> {
    for name in [
        "CONTROL_RELEASE_COSIGN_EXECUTABLE",
        "CONTROL_RELEASE_COSIGN_OIDC_ISSUER",
        "CONTROL_RELEASE_COSIGN_IDENTITY",
        "CONTROL_RELEASE_COSIGN_REPOSITORY",
        "CONTROL_RELEASE_ORAS_EXECUTABLE",
        "CONTROL_DEPLOYMENT_DRIVER_URL",
    ] {
        crate::runtime_secret::configuration(name)
            .map_err(anyhow::Error::msg)?
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| anyhow::anyhow!("{name} is required for release adoption"))?;
    }
    crate::runtime_secret::required("CONTROL_DEPLOYMENT_DRIVER_TOKEN")
        .map_err(anyhow::Error::msg)?;
    Ok(())
}

async fn verify_release_provenance(
    manifest: &crate::release::ApplicationReleaseManifest,
) -> Result<(), IntegrationError> {
    let executable = required_release_setting("CONTROL_RELEASE_COSIGN_EXECUTABLE")?;
    let issuer = required_release_setting("CONTROL_RELEASE_COSIGN_OIDC_ISSUER")?;
    let identity = required_release_setting("CONTROL_RELEASE_COSIGN_IDENTITY")?;
    let repository = required_release_setting("CONTROL_RELEASE_COSIGN_REPOSITORY")?;
    let oras = required_release_setting("CONTROL_RELEASE_ORAS_EXECUTABLE")?;
    run_cosign(
        &executable,
        &[
            "verify",
            "--certificate-oidc-issuer",
            &issuer,
            "--certificate-identity",
            &identity,
            "--certificate-github-workflow-repository",
            &repository,
            "--output=json",
            &manifest.extension_bundle.oci_ref,
        ],
    )
    .await?;

    // Every immutable evidence object is fetched by its subject reference and
    // checked against the content digest admitted by the release. This is
    // intentionally independent of registry transport integrity.
    let mut evidence = vec![&manifest.admission_signature];
    for runtime in &manifest.odoo_runtime.platforms {
        evidence.push(&runtime.evidence.sbom);
        evidence.push(&runtime.evidence.vulnerability_report);
    }
    for extension in &manifest.extension_bundle.platforms {
        evidence.push(&extension.signature);
        evidence.push(&extension.sbom);
        evidence.push(&extension.vulnerability_report);
    }
    let mut admission_bundle = None;
    for item in evidence {
        let bytes = fetch_evidence(&oras, item).await?;
        if std::ptr::eq(item, &manifest.admission_signature) {
            admission_bundle = Some(bytes);
        }
    }

    let verification_root = temporary_verification_root("admission")?;
    let payload_path = verification_root.join("application-release.json");
    let bundle_path = verification_root.join("admission.bundle");
    std::fs::write(
        &payload_path,
        manifest
            .admission_payload()
            .map_err(|_| IntegrationError::ContractDrift)?,
    )
    .map_err(|_| IntegrationError::Unavailable)?;
    std::fs::write(
        &bundle_path,
        admission_bundle.ok_or(IntegrationError::ContractDrift)?,
    )
    .map_err(|_| IntegrationError::Unavailable)?;
    let verification = run_cosign(
        &executable,
        &[
            "verify-blob",
            "--bundle",
            path_text(&bundle_path)?,
            "--certificate-oidc-issuer",
            &issuer,
            "--certificate-identity",
            &identity,
            "--certificate-github-workflow-repository",
            &repository,
            path_text(&payload_path)?,
        ],
    )
    .await;
    let cleanup = std::fs::remove_dir_all(&verification_root);
    verification?;
    cleanup.map_err(|_| IntegrationError::Unavailable)?;
    Ok(())
}

fn path_text(path: &Path) -> Result<&str, IntegrationError> {
    path.to_str().ok_or(IntegrationError::ContractDrift)
}

fn temporary_verification_root(kind: &str) -> Result<PathBuf, IntegrationError> {
    let root = std::env::temp_dir().join(format!("mb-release-{kind}-{}", Uuid::new_v4()));
    std::fs::create_dir(&root).map_err(|_| IntegrationError::Unavailable)?;
    Ok(root)
}

async fn fetch_evidence(
    oras: &str,
    evidence: &crate::release::EvidenceObject,
) -> Result<Vec<u8>, IntegrationError> {
    const MAX_EVIDENCE_BYTES: u64 = 128 * 1024 * 1024;
    let root = temporary_verification_root("evidence")?;
    let output = tokio::time::timeout(
        Duration::from_secs(120),
        tokio::process::Command::new(oras)
            .args(["pull", "--output", path_text(&root)?, &evidence.reference])
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(|_| IntegrationError::Unavailable)?
    .map_err(|_| IntegrationError::Unavailable)?;
    if !output.status.success() {
        let _ = std::fs::remove_dir_all(&root);
        return Err(IntegrationError::Rejected);
    }
    let files = bounded_regular_files(&root, MAX_EVIDENCE_BYTES)?;
    if files.len() != 1 {
        let _ = std::fs::remove_dir_all(&root);
        return Err(IntegrationError::ContractDrift);
    }
    let bytes = std::fs::read(&files[0]).map_err(|_| IntegrationError::Unavailable)?;
    let observed = format!("sha256:{:x}", Sha256::digest(&bytes));
    let cleanup = std::fs::remove_dir_all(&root);
    if observed != evidence.sha256_digest {
        return Err(IntegrationError::Rejected);
    }
    cleanup.map_err(|_| IntegrationError::Unavailable)?;
    Ok(bytes)
}

fn bounded_regular_files(root: &Path, maximum: u64) -> Result<Vec<PathBuf>, IntegrationError> {
    let mut pending = vec![root.to_owned()];
    let mut files = Vec::new();
    let mut total = 0_u64;
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(directory).map_err(|_| IntegrationError::Unavailable)? {
            let entry = entry.map_err(|_| IntegrationError::Unavailable)?;
            let metadata = entry
                .path()
                .symlink_metadata()
                .map_err(|_| IntegrationError::Unavailable)?;
            if metadata.file_type().is_symlink() {
                return Err(IntegrationError::ContractDrift);
            }
            if metadata.is_dir() {
                pending.push(entry.path());
            } else if metadata.is_file() {
                total = total
                    .checked_add(metadata.len())
                    .ok_or(IntegrationError::ContractDrift)?;
                if total > maximum {
                    return Err(IntegrationError::ContractDrift);
                }
                files.push(entry.path());
            } else {
                return Err(IntegrationError::ContractDrift);
            }
        }
    }
    Ok(files)
}

fn required_release_setting(name: &'static str) -> Result<String, IntegrationError> {
    crate::runtime_secret::required_configuration(name).map_err(|_| IntegrationError::ContractDrift)
}

async fn run_cosign(executable: &str, arguments: &[&str]) -> Result<Vec<u8>, IntegrationError> {
    let output = tokio::time::timeout(
        Duration::from_secs(120),
        tokio::process::Command::new(executable)
            .args(arguments)
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(|_| IntegrationError::Unavailable)?
    .map_err(|_| IntegrationError::Unavailable)?;
    if !output.status.success() {
        return Err(IntegrationError::Rejected);
    }
    Ok(output.stdout)
}

pub(crate) async fn adopt(
    store: &Store,
    operation: &LeasedOperation,
    deployment_driver: &DeploymentDriverConfig,
) -> Result<(), IntegrationError> {
    let release_id = operation
        .payload
        .get("release_id")
        .and_then(Value::as_str)
        .ok_or(IntegrationError::ContractDrift)?;
    match operation.payload.get("phase").and_then(Value::as_str) {
        Some("preflight") => {
            release_preflight(store, operation, release_id, deployment_driver).await
        }
        Some("adopt") => release_fleet_adopt(store, operation, release_id, deployment_driver).await,
        _ => Err(IntegrationError::ContractDrift),
    }
}

async fn release_driver_receipt_matches(
    store: &Store,
    operation: &LeasedOperation,
    target_key: &str,
    evidence: &Value,
) -> Result<bool, IntegrationError> {
    let driver_operation_id = evidence
        .get("driver_operation_id")
        .and_then(Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok())
        .ok_or(IntegrationError::ContractDrift)?;
    let driver_fence_token = evidence
        .get("driver_fence_token")
        .and_then(Value::as_i64)
        .filter(|value| *value > 0)
        .ok_or(IntegrationError::ContractDrift)?;
    sqlx::query_scalar(
        "select exists(select 1 from control.deployment_driver_operations
         where id=$1 and action='release' and state='succeeded'
           and control_operation_id=$2 and control_operation_attempt=$3
           and control_operation_lease_owner=$4 and target_key=$5
           and response->'evidence'=$6
           and (response->'evidence'->>'driver_fence_token')::bigint=$7)",
    )
    .bind(driver_operation_id)
    .bind(operation.id)
    .bind(operation.attempt)
    .bind(&operation.leased_by)
    .bind(target_key)
    .bind(evidence)
    .bind(driver_fence_token)
    .fetch_one(store.pool())
    .await
    .map_err(|_| IntegrationError::Unavailable)
}

async fn release_preflight(
    store: &Store,
    operation: &LeasedOperation,
    release_id: &str,
    deployment_driver: &DeploymentDriverConfig,
) -> Result<(), IntegrationError> {
    let (manifest_value, manifest_digest, status) = sqlx::query_as::<_, (Value, String, String)>(
        "select manifest,manifest_digest,status from control.application_releases where id=$1",
    )
    .bind(release_id)
    .fetch_optional(store.pool())
    .await
    .map_err(|_| IntegrationError::Unavailable)?
    .ok_or(IntegrationError::NotFound)?;
    let manifest: crate::release::ApplicationReleaseManifest =
        serde_json::from_value(manifest_value).map_err(|_| IntegrationError::ContractDrift)?;
    manifest
        .validate()
        .map_err(|_| IntegrationError::ContractDrift)?;
    let computed_manifest_digest = format!(
        "sha256:{:x}",
        Sha256::digest(serde_jcs::to_vec(&manifest).map_err(|_| IntegrationError::ContractDrift)?)
    );
    if computed_manifest_digest != manifest_digest {
        return Err(IntegrationError::ContractDrift);
    }
    let active_registry = sqlx::query_scalar::<_, i32>(
        "select version from control.capability_registry_versions where active",
    )
    .fetch_one(store.pool())
    .await
    .map_err(|_| IntegrationError::Unavailable)?;
    if u32::try_from(active_registry).ok() != Some(manifest.capability_registry_version) {
        return Err(IntegrationError::Rejected);
    }
    if manifest.release_id != release_id {
        return Err(IntegrationError::ContractDrift);
    }
    verify_release_provenance(&manifest).await?;
    let sources = sqlx::query_scalar::<_, String>(
        "select distinct release_id from control.tenant_release_adoptions where state='active'",
    )
    .fetch_all(store.pool())
    .await
    .map_err(|_| IntegrationError::Unavailable)?;
    if sources
        .iter()
        .any(|source| !manifest.upgradeable_from.contains(source))
    {
        return Err(IntegrationError::Rejected);
    }
    let tenants = sqlx::query_as::<_, (Uuid, Uuid, String)>(
        "select w.id,d.id,d.database_ref
         from control.workshops w join control.odoo_databases d on d.workshop_id=w.id
         where w.status<>'deleted' and d.kind='primary' and d.deleted_at is null
         order by w.created_at,w.id",
    )
    .fetch_all(store.pool())
    .await
    .map_err(|_| IntegrationError::Unavailable)?;
    let checkpoint = json!({
        "release_id":release_id,
        "manifest_digest":manifest_digest,
        "tenants":tenants.iter().map(|row|json!({"workshop_id":row.0,"database_id":row.1,"database_ref":row.2})).collect::<Vec<_>>(),
        "verified":{"manifest":true,"directional_compatibility":true,"oci_digest_bound":true}
    });
    match store
        .operation_checkpoint(operation.id)
        .await
        .map_err(|_| IntegrationError::Unavailable)?
    {
        Some(existing) if existing == checkpoint => {}
        Some(_) => return Err(IntegrationError::ContractDrift),
        None => store
            .save_operation_checkpoint(operation, &checkpoint)
            .await
            .map_err(|_| IntegrationError::Unavailable)?,
    }
    if tenants.is_empty() {
        let prepared = release_driver_request_with_key(
            operation,
            &format!("release-initial:{release_id}"),
            &json!({
                "phase":"prepare-initial",
                "release_id":release_id,
                "manifest_digest":manifest_digest,
            }),
            deployment_driver,
        )
        .await?;
        let evidence = prepared
            .get("evidence")
            .filter(|value| value.is_object())
            .ok_or(IntegrationError::ContractDrift)?;
        if evidence.get("release_id").and_then(Value::as_str) != Some(release_id)
            || evidence.get("manifest_digest").and_then(Value::as_str)
                != Some(manifest_digest.as_str())
            || evidence.get("provenance_verified").and_then(Value::as_bool) != Some(true)
            || evidence
                .get("runtime_inspection_verified")
                .and_then(Value::as_bool)
                != Some(true)
        {
            return Err(IntegrationError::ContractDrift);
        }
        if !release_driver_receipt_matches(
            store,
            operation,
            &format!("initial/{release_id}"),
            evidence,
        )
        .await?
        {
            return Err(IntegrationError::ContractDrift);
        }
    }
    let mut tx = store
        .begin()
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
    sqlx::query_scalar::<_, Uuid>(
        "select id from control.operations
         where id=$1 and state='in_flight' and leased_by=$2 and attempt=$3
           and lease_expires_at>now()
         for update",
    )
    .bind(operation.id)
    .bind(&operation.leased_by)
    .bind(operation.attempt)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| IntegrationError::Unavailable)?
    .ok_or(IntegrationError::UnknownOutcome)?;
    let mut current = sqlx::query_scalar::<_, String>(
        "select status from control.application_releases where id=$1 for update",
    )
    .bind(release_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| IntegrationError::Unavailable)?
    .ok_or(IntegrationError::NotFound)?;
    if current != status {
        return Err(IntegrationError::UnknownOutcome);
    }
    if current == "preflighting" {
        let changed = sqlx::query(
            "update control.application_releases set status='canary',version=version+1
             where id=$1 and status='preflighting'",
        )
        .bind(release_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| IntegrationError::Unavailable)?
        .rows_affected();
        if changed != 1 {
            return Err(IntegrationError::UnknownOutcome);
        }
        current = "canary".into();
    }
    if current == "canary" {
        let changed = sqlx::query(
            "update control.application_releases set status='prepared',version=version+1
             where id=$1 and status='canary'",
        )
        .bind(release_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| IntegrationError::Unavailable)?
        .rows_affected();
        if changed != 1 {
            return Err(IntegrationError::UnknownOutcome);
        }
        current = "prepared".into();
    }
    if current != "prepared" {
        return Err(IntegrationError::Rejected);
    }
    tx.commit().await.map_err(|_| IntegrationError::Unavailable)
}

async fn release_fleet_adopt(
    store: &Store,
    operation: &LeasedOperation,
    release_id: &str,
    deployment_driver: &DeploymentDriverConfig,
) -> Result<(), IntegrationError> {
    let run = sqlx::query_as::<_, (Uuid, String)>(
        "select id,state from control.release_fleet_runs where operation_id=$1 and release_id=$2",
    )
    .bind(operation.id)
    .bind(release_id)
    .fetch_optional(store.pool())
    .await
    .map_err(|_| IntegrationError::Unavailable)?
    .ok_or(IntegrationError::NotFound)?;
    if run.1 == "active" {
        return Ok(());
    }
    if !matches!(run.1.as_str(), "preparing" | "activating") {
        return Err(IntegrationError::Rejected);
    }
    // Tenant isolation, recovery, upgrade, verification and the final slot
    // switch are delegated through one idempotent private driver contract. The
    // driver returns only evidence and never release credentials.
    let result = release_driver_request_with_key(
        operation,
        &format!("release-fleet:{}", run.0),
        &json!({"phase":"adopt-fleet","fleet_run_id":run.0,"release_id":release_id}),
        deployment_driver,
    )
    .await?;
    let evidence = result
        .get("evidence")
        .filter(|value| value.is_object())
        .cloned()
        .ok_or(IntegrationError::ContractDrift)?;
    let target_slot = evidence
        .get("target_slot")
        .and_then(Value::as_str)
        .filter(|value| matches!(*value, "blue" | "green"))
        .ok_or(IntegrationError::ContractDrift)?;
    let runtime_key = evidence
        .get("runtime_key")
        .and_then(Value::as_str)
        .filter(|value| *value == "shared-odoo")
        .ok_or(IntegrationError::ContractDrift)?;
    let odoo_subject_digest = evidence
        .get("odoo_subject_digest")
        .and_then(Value::as_str)
        .ok_or(IntegrationError::ContractDrift)?;
    let extension_subject_digest = evidence
        .get("extension_subject_digest")
        .and_then(Value::as_str)
        .ok_or(IntegrationError::ContractDrift)?;
    let pair_qualification_digest = evidence
        .get("pair_qualification_digest")
        .and_then(Value::as_str)
        .ok_or(IntegrationError::ContractDrift)?;
    let extension_volume = evidence
        .get("extension_volume")
        .and_then(Value::as_str)
        .ok_or(IntegrationError::ContractDrift)?;
    let driver_operation_id = evidence
        .get("driver_operation_id")
        .and_then(Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok())
        .ok_or(IntegrationError::ContractDrift)?;
    let driver_fence_token = evidence
        .get("driver_fence_token")
        .and_then(Value::as_i64)
        .filter(|value| *value > 0)
        .ok_or(IntegrationError::ContractDrift)?;
    let driver_action_id = evidence
        .get("driver_action_id")
        .and_then(Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok())
        .ok_or(IntegrationError::ContractDrift)?;
    let prepared = evidence
        .get("prepared_tenants")
        .and_then(Value::as_array)
        .ok_or(IntegrationError::ContractDrift)?;
    if prepared.is_empty()
        || evidence
            .get("old_runtime_database_access_revoked")
            .and_then(Value::as_bool)
            != Some(true)
        || evidence
            .get("tenant_recovery_verified")
            .and_then(Value::as_bool)
            != Some(true)
        || evidence
            .get("candidate_smoke_verified")
            .and_then(Value::as_bool)
            != Some(true)
    {
        return Err(IntegrationError::ContractDrift);
    }
    if evidence.get("release_id").and_then(Value::as_str) != Some(release_id) {
        return Err(IntegrationError::ContractDrift);
    }
    let prepared_value = Value::Array(prepared.clone());
    let mut tx = store
        .begin()
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
    sqlx::query_scalar::<_, Uuid>(
        "select id from control.operations
         where id=$1 and state='in_flight' and leased_by=$2 and attempt=$3
           and lease_expires_at>now()
         for update",
    )
    .bind(operation.id)
    .bind(&operation.leased_by)
    .bind(operation.attempt)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| IntegrationError::Unavailable)?
    .ok_or(IntegrationError::UnknownOutcome)?;
    let release_identity = sqlx::query_as::<_, (String, String, String, Value)>(
        "select odoo_subject_digest,extension_subject_digest,status,manifest
         from control.application_releases where id=$1 for update",
    )
    .bind(release_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|_| IntegrationError::Unavailable)?;
    let manifest: crate::release::ApplicationReleaseManifest =
        serde_json::from_value(release_identity.3).map_err(|_| IntegrationError::ContractDrift)?;
    if release_identity.0 != odoo_subject_digest
        || release_identity.1 != extension_subject_digest
        || release_identity.2 != "prepared"
        || !activation_evidence_matches_manifest(&manifest, &evidence)
    {
        return Err(IntegrationError::ContractDrift);
    }
    let locked_run = sqlx::query_as::<_, (String, Value, i64, Option<i64>)>(
        "select state,tenant_snapshot,fleet_generation,driver_fence_token
         from control.release_fleet_runs
         where id=$1 and operation_id=$2 and release_id=$3 for update",
    )
    .bind(run.0)
    .bind(operation.id)
    .bind(release_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| IntegrationError::Unavailable)?
    .ok_or(IntegrationError::NotFound)?;
    if !matches!(locked_run.0.as_str(), "preparing" | "activating")
        || evidence.get("tenant_snapshot") != Some(&locked_run.1)
        || evidence.get("fleet_generation").and_then(Value::as_i64) != Some(locked_run.2)
        || locked_run.3 != Some(driver_fence_token)
    {
        return Err(IntegrationError::Rejected);
    }
    let driver_response_matches = sqlx::query_scalar::<_, bool>(
        "select exists(select 1 from control.deployment_driver_operations
         where id=$1 and action='release' and state='succeeded'
           and control_operation_id=$2 and control_operation_attempt=$3
           and control_operation_lease_owner=$4
           and target_key=$5 and response->'evidence'=$6)",
    )
    .bind(driver_operation_id)
    .bind(operation.id)
    .bind(operation.attempt)
    .bind(&operation.leased_by)
    .bind(format!("fleet/{}", run.0))
    .bind(&evidence)
    .fetch_one(&mut *tx)
    .await
    .map_err(|_| IntegrationError::Unavailable)?;
    if !driver_response_matches {
        return Err(IntegrationError::ContractDrift);
    }
    let expected_prepared = sqlx::query_scalar::<_, Value>(
        "select coalesce(jsonb_agg(jsonb_build_object(
             'adoption_id',a.id,
             'workshop_id',a.workshop_id,
             'database_id',a.database_id,
             'database_ref',d.database_ref,
             'public_hostname',d.public_hostname
         ) order by a.created_at,a.id),'[]'::jsonb)
         from control.tenant_release_adoptions a
         join control.odoo_databases d
           on d.id=a.database_id and d.workshop_id=a.workshop_id
         where a.operation_id=$1 and a.release_id=$2 and a.state='prepared'",
    )
    .bind(operation.id)
    .bind(release_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|_| IntegrationError::Unavailable)?;
    if expected_prepared != prepared_value {
        return Err(IntegrationError::ContractDrift);
    }
    let expected_count = i64::try_from(prepared.len()).map_err(|_| IntegrationError::TooLarge)?;
    let intent = sqlx::query_as::<
        _,
        (
            String,
            String,
            String,
            String,
            String,
            Value,
            String,
            Option<String>,
            bool,
            Option<i64>,
            Uuid,
            Option<i16>,
        ),
    >(
        "select runtime_key,target_slot,odoo_subject_digest,extension_subject_digest,
                pair_qualification_digest,prepared_tenants,gateway_configuration_digest,
                observed_configuration_digest,activated_at is not null,driver_fence_token,
                driver_action_id,gateway_identity_version
         from control.fleet_activation_intents
         where fleet_run_id=$1 and release_id=$2 and abandoned_at is null for update",
    )
    .bind(run.0)
    .bind(release_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| IntegrationError::Unavailable)?
    .ok_or(IntegrationError::ContractDrift)?;
    if intent.0 != runtime_key
        || intent.1 != target_slot
        || intent.2 != odoo_subject_digest
        || intent.3 != extension_subject_digest
        || intent.4 != pair_qualification_digest
        || intent.5 != prepared_value
        || evidence
            .get("gateway_configuration_digest")
            .and_then(Value::as_str)
            != Some(intent.6.as_str())
        || intent.7.as_deref() != Some(intent.6.as_str())
        || !intent.8
        || intent.9 != Some(driver_fence_token)
        || intent.10 != driver_action_id
        || intent.11 != Some(1)
    {
        return Err(IntegrationError::ContractDrift);
    }
    sqlx::query(
        "update control.tenant_release_adoptions old set
             state='superseded',superseded_at=now(),version=version+1
         from control.tenant_release_adoptions candidate
         where candidate.operation_id=$1 and candidate.release_id=$2
           and old.workshop_id=candidate.workshop_id and old.database_id=candidate.database_id
           and old.state='active'",
    )
    .bind(operation.id)
    .bind(release_id)
    .execute(&mut *tx)
    .await
    .map_err(|_| IntegrationError::Unavailable)?;
    let activated = sqlx::query(
        "update control.tenant_release_adoptions set
             state='active',activated_at=now(),version=version+1
         where operation_id=$1 and release_id=$2 and state='prepared'",
    )
    .bind(operation.id)
    .bind(release_id)
    .execute(&mut *tx)
    .await
    .map_err(|_| IntegrationError::Unavailable)?
    .rows_affected();
    if activated != u64::try_from(expected_count).unwrap_or_default() {
        return Err(IntegrationError::UnknownOutcome);
    }
    sqlx::query(
        "update control.runtime_release_slots set state='retained',version=version+1
         where runtime_key=$1 and state='active' and slot<>$2",
    )
    .bind(runtime_key)
    .bind(target_slot)
    .execute(&mut *tx)
    .await
    .map_err(|_| IntegrationError::Unavailable)?;
    sqlx::query(
        "insert into control.runtime_release_slots(
           runtime_key,slot,release_id,state,odoo_subject_digest,odoo_manifest_digest,odoo_config_digest,
           extension_subject_digest,extension_manifest_digest,extension_config_digest,payload_digest,
           extension_volume,pair_qualification_digest,bridge_contract_digest,installed_addon_versions,
           started_at,verified_at,activated_at,evidence
         ) values($1,$2,$3,'active',$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,now(),now(),now(),$15)
         on conflict(runtime_key,slot) do update set
           release_id=excluded.release_id,state='active',odoo_subject_digest=excluded.odoo_subject_digest,
           odoo_manifest_digest=excluded.odoo_manifest_digest,odoo_config_digest=excluded.odoo_config_digest,
           extension_subject_digest=excluded.extension_subject_digest,extension_manifest_digest=excluded.extension_manifest_digest,
           extension_config_digest=excluded.extension_config_digest,payload_digest=excluded.payload_digest,
           extension_volume=excluded.extension_volume,pair_qualification_digest=excluded.pair_qualification_digest,
           bridge_contract_digest=excluded.bridge_contract_digest,installed_addon_versions=excluded.installed_addon_versions,
           started_at=coalesce(control.runtime_release_slots.started_at,now()),
           verified_at=now(),activated_at=now(),evidence=excluded.evidence,
           version=control.runtime_release_slots.version+1",
    )
    .bind(runtime_key)
    .bind(target_slot)
    .bind(release_id)
    .bind(odoo_subject_digest)
    .bind(evidence.get("odoo_manifest_digest").and_then(Value::as_str).ok_or(IntegrationError::ContractDrift)?)
    .bind(evidence.get("odoo_config_digest").and_then(Value::as_str).ok_or(IntegrationError::ContractDrift)?)
    .bind(extension_subject_digest)
    .bind(evidence.get("extension_manifest_digest").and_then(Value::as_str).ok_or(IntegrationError::ContractDrift)?)
    .bind(evidence.get("extension_config_digest").and_then(Value::as_str).ok_or(IntegrationError::ContractDrift)?)
    .bind(evidence.get("payload_digest").and_then(Value::as_str).ok_or(IntegrationError::ContractDrift)?)
    .bind(extension_volume)
    .bind(pair_qualification_digest)
    .bind(evidence.get("bridge_contract_digest").and_then(Value::as_str).ok_or(IntegrationError::ContractDrift)?)
    .bind(evidence.get("installed_addon_versions").cloned().ok_or(IntegrationError::ContractDrift)?)
    .bind(&evidence)
    .execute(&mut *tx)
    .await
    .map_err(|_| IntegrationError::Unavailable)?;
    sqlx::query(
        "update control.application_releases set status='retained',version=version+1
         where status='active' and id<>$1",
    )
    .bind(release_id)
    .execute(&mut *tx)
    .await
    .map_err(|_| IntegrationError::Unavailable)?;
    let run_activated = sqlx::query(
        "update control.release_fleet_runs set state='active',evidence=$2,updated_at=now()
         where id=$1 and operation_id=$3 and release_id=$4
           and state in ('preparing','activating')",
    )
    .bind(run.0)
    .bind(&evidence)
    .bind(operation.id)
    .bind(release_id)
    .execute(&mut *tx)
    .await
    .map_err(|_| IntegrationError::Unavailable)?
    .rows_affected();
    let release_activated = sqlx::query(
        "update control.application_releases set status='active',version=version+1
         where id=$1 and status='prepared'",
    )
    .bind(release_id)
    .execute(&mut *tx)
    .await
    .map_err(|_| IntegrationError::Unavailable)?
    .rows_affected();
    if run_activated != 1 || release_activated != 1 {
        return Err(IntegrationError::UnknownOutcome);
    }
    tx.commit().await.map_err(|_| IntegrationError::Unavailable)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn release_race_fixture(store: &Store) -> (String, LeasedOperation, Uuid) {
        let suffix = Uuid::new_v4().simple().to_string();
        let release = format!("odoo-2026.08.22-{}", &suffix[..12]);
        let odoo_digest = format!("sha256:{:x}", Sha256::digest(format!("odoo-{suffix}")));
        let extension_digest =
            format!("sha256:{:x}", Sha256::digest(format!("extension-{suffix}")));
        sqlx::query(
            "insert into control.application_releases(
               id,source_commit,odoo_version,odoo_subject_digest,extension_subject_digest,
               odoo_runtime,extension_bundle,pair_qualifications,manifest_digest,addon_versions,
               compatibility,bridge_contract,schema_epoch,change_class,required_postconditions,
               manifest,signature_bundle_ref,extension_signature_ref,sbom_ref,published_at,
               publication_idempotency_key,publication_request_digest
             ) values($1,$2,'19.0',$3,$4,'{}','{}','[{}]',$5,'{}','{}',
                      '>=3.2.0,<4.0.0',42,'B','[]','{}','oci://signature',
                      'oci://extension-signature','oci://sbom',now(),$6,$7)",
        )
        .bind(&release)
        .bind("a".repeat(40))
        .bind(odoo_digest)
        .bind(extension_digest)
        .bind(format!(
            "sha256:{:x}",
            Sha256::digest(format!("manifest-{suffix}"))
        ))
        .bind(format!("release-race:{release}"))
        .bind(vec![0_u8; 32])
        .execute(store.pool())
        .await
        .unwrap();
        for status in ["preflighting", "canary", "prepared"] {
            sqlx::query(
                "update control.application_releases
                 set status=$2,version=version+1 where id=$1",
            )
            .bind(&release)
            .bind(status)
            .execute(store.pool())
            .await
            .unwrap();
        }
        let operation_id = Uuid::new_v4();
        let leased_by = format!("release-race-worker-{operation_id}");
        sqlx::query(
            "insert into control.operations(
               id,kind,queue,payload,correlation_id,idempotency_key,state,attempt,
               max_attempts,leased_by,lease_expires_at
             ) values($1,'odoo.release.adopt','release-adoption',$2,$3,$4,
                      'in_flight',1,3,$5,now()+interval '10 minutes')",
        )
        .bind(operation_id)
        .bind(json!({"phase":"adopt","release_id":release}))
        .bind(Uuid::new_v4())
        .bind(format!("release-race-operation:{operation_id}"))
        .bind(&leased_by)
        .execute(store.pool())
        .await
        .unwrap();
        let run = Uuid::new_v4();
        sqlx::query(
            "insert into control.release_fleet_runs(
               id,release_id,operation_id,fleet_generation,state,tenant_snapshot
             ) values($1,$2,$3,1,'preparing','[]')",
        )
        .bind(run)
        .bind(&release)
        .bind(operation_id)
        .execute(store.pool())
        .await
        .unwrap();
        (
            release.clone(),
            LeasedOperation {
                id: operation_id,
                kind: "odoo.release.adopt".into(),
                workshop_id: None,
                target_user_id: None,
                desired_epoch: None,
                payload: json!({"phase":"adopt","release_id":release}),
                attempt: 1,
                max_attempts: 3,
                leased_by,
                reconciling: false,
                trace_parent: None,
                trace_state: None,
            },
            run,
        )
    }

    #[test]
    fn activation_and_failure_paths_share_lock_order_and_terminal_cas() {
        let source = include_str!("release.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        let failure = production
            .split("async fn record_terminal_failure(")
            .nth(1)
            .unwrap()
            .split("pub(crate) fn validate_configuration")
            .next()
            .unwrap();
        let finalization = production
            .split("let mut tx = store\n        .begin()")
            .last()
            .unwrap();
        for path in [failure, finalization] {
            let operation_lock = path.find("from control.operations").unwrap();
            let release_lock = path.find("from control.application_releases").unwrap();
            let run_lock = path.find("from control.release_fleet_runs").unwrap();
            assert!(operation_lock < release_lock && release_lock < run_lock);
            assert!(path.contains("for update"));
        }
        assert!(finalization.contains("run_activated != 1 || release_activated != 1"));
    }

    #[test]
    fn activation_evidence_is_bound_to_the_exact_admitted_manifest() {
        let manifest = crate::release::tests::fixture();
        let runtime = &manifest.odoo_runtime.platforms[0];
        let extension = &manifest.extension_bundle.platforms[0];
        let pair = &manifest.pair_qualifications[0];
        let mut evidence = json!({
            "release_id":manifest.release_id,
            "odoo_subject_digest":manifest.odoo_runtime.subject_digest,
            "extension_subject_digest":manifest.extension_bundle.subject_digest,
            "odoo_manifest_digest":runtime.manifest_digest,
            "odoo_config_digest":runtime.config_digest,
            "extension_manifest_digest":extension.manifest_digest,
            "extension_config_digest":extension.config_digest,
            "payload_digest":extension.payload_digest,
            "pair_qualification_digest":pair.qualification_digest,
            "bridge_contract_digest":manifest.bridge_contract_digest,
            "installed_addon_versions":manifest.addons,
        });
        assert!(activation_evidence_matches_manifest(&manifest, &evidence));

        for key in [
            "release_id",
            "odoo_subject_digest",
            "extension_subject_digest",
            "odoo_manifest_digest",
            "odoo_config_digest",
            "extension_manifest_digest",
            "extension_config_digest",
            "payload_digest",
            "pair_qualification_digest",
            "bridge_contract_digest",
        ] {
            let original = evidence[key].clone();
            evidence[key] = json!("tampered");
            assert!(
                !activation_evidence_matches_manifest(&manifest, &evidence),
                "tampered {key} was accepted"
            );
            evidence[key] = original;
        }
        evidence["installed_addon_versions"] = json!({"mb_control_bridge":"tampered"});
        assert!(!activation_evidence_matches_manifest(&manifest, &evidence));
    }

    #[test]
    fn initial_and_fleet_release_evidence_require_the_exact_driver_receipt() {
        let source = include_str!("release.rs");
        assert!(source.contains("async fn release_driver_receipt_matches("));
        assert!(source.contains("and control_operation_lease_owner=$4 and target_key=$5"));
        assert!(source.contains("&format!(\"initial/{release_id}\")"));
        assert!(source.contains(".bind(format!(\"fleet/{}\", run.0))"));
        assert!(source.contains("and response->'evidence'=$6"));
        let preflight_finalization = source
            .split("async fn release_preflight(")
            .nth(1)
            .unwrap()
            .split("async fn release_fleet_adopt(")
            .next()
            .unwrap()
            .split("let mut tx = store")
            .last()
            .unwrap();
        assert!(preflight_finalization.contains("from control.operations"));
        assert!(preflight_finalization.contains("lease_expires_at>now()"));
        assert!(preflight_finalization.contains("for update"));
        assert!(
            preflight_finalization
                .find("from control.operations")
                .unwrap()
                < preflight_finalization
                    .find("from control.application_releases")
                    .unwrap(),
            "initial release finalization must lock current worker authority before release state"
        );
    }

    #[tokio::test]
    #[ignore = "requires a disposable CONTROL_TEST_DATABASE_URL"]
    async fn terminal_failure_cannot_overwrite_activation_or_accept_split_state() {
        let database_url =
            std::env::var("CONTROL_TEST_DATABASE_URL").expect("CONTROL_TEST_DATABASE_URL");
        let store = Store::connect(&database_url).await.unwrap();
        store.migrate().await.unwrap();
        let (release, operation, run) = release_race_fixture(&store).await;

        let mut activation = store.begin().await.unwrap();
        sqlx::query("select id from control.operations where id=$1 for update")
            .bind(operation.id)
            .execute(&mut *activation)
            .await
            .unwrap();
        sqlx::query("select id from control.application_releases where id=$1 for update")
            .bind(&release)
            .execute(&mut *activation)
            .await
            .unwrap();
        sqlx::query("select id from control.release_fleet_runs where id=$1 for update")
            .bind(run)
            .execute(&mut *activation)
            .await
            .unwrap();
        let failure_store = store.clone();
        let failed_operation = LeasedOperation {
            payload: operation.payload.clone(),
            ..operation
        };
        let failed_release = release.clone();
        let failure = tokio::spawn(async move {
            record_terminal_failure(&failure_store, &failed_operation, &failed_release).await
        });
        sqlx::query(
            "update control.application_releases
             set status='active',version=version+1 where id=$1 and status='prepared'",
        )
        .bind(&release)
        .execute(&mut *activation)
        .await
        .unwrap();
        sqlx::query(
            "update control.release_fleet_runs set state='active'
             where id=$1 and state='preparing'",
        )
        .bind(run)
        .execute(&mut *activation)
        .await
        .unwrap();
        activation.commit().await.unwrap();
        failure.await.unwrap().unwrap();
        let states = sqlx::query_as::<_, (String, String)>(
            "select r.status,f.state from control.application_releases r
             join control.release_fleet_runs f on f.release_id=r.id where r.id=$1",
        )
        .bind(&release)
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(states, ("active".into(), "active".into()));

        let (split_release, split_operation, split_run) = release_race_fixture(&store).await;
        sqlx::query("update control.release_fleet_runs set state='active' where id=$1")
            .bind(split_run)
            .execute(store.pool())
            .await
            .unwrap();
        assert_eq!(
            record_terminal_failure(&store, &split_operation, &split_release)
                .await
                .unwrap_err(),
            IntegrationError::UnknownOutcome
        );
        let split = sqlx::query_as::<_, (String, String)>(
            "select r.status,f.state from control.application_releases r
             join control.release_fleet_runs f on f.release_id=r.id where r.id=$1",
        )
        .bind(&split_release)
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(split, ("prepared".into(), "active".into()));
    }
}
