use std::{
    path::{Path, PathBuf},
    time::Duration,
};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::domain::IntegrationError;
use crate::persistence::{LeasedOperation, Store};
use crate::worker::driver_request_with_key;

pub(crate) async fn failed(store: &Store, operation: &LeasedOperation) {
    let Some(release_id) = operation.payload.get("release_id").and_then(Value::as_str) else {
        return;
    };
    if let Err(error) = sqlx::query(
        "update control.application_releases set status='failed',version=version+1
         where id=$1 and status in ('candidate','preflighting','canary','prepared')",
    )
    .bind(release_id)
    .execute(store.pool())
    .await
    {
        tracing::error!(operation=%operation.id,error=%error,"failed to record terminal release failure");
    }
    if let Err(error) = sqlx::query(
        "update control.release_fleet_runs set state='failed',failure_class='release_operation_failed',updated_at=now()
         where operation_id=$1 and state in ('preflighting','preparing','paused','activating')",
    )
    .bind(operation.id)
    .execute(store.pool())
    .await
    {
        tracing::error!(operation=%operation.id,error=%error,"failed to record terminal fleet failure");
    }
    if let Err(error) = sqlx::query(
        "update control.runtime_release_slots set state='failed',version=version+1
         where release_id=$1 and state='prepared'",
    )
    .bind(release_id)
    .execute(store.pool())
    .await
    {
        tracing::error!(operation=%operation.id,error=%error,"failed to quarantine prepared release runtime");
    }
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
) -> Result<(), IntegrationError> {
    let release_id = operation
        .payload
        .get("release_id")
        .and_then(Value::as_str)
        .ok_or(IntegrationError::ContractDrift)?;
    match operation.payload.get("phase").and_then(Value::as_str) {
        Some("preflight") => release_preflight(store, operation, release_id).await,
        Some("adopt") => release_fleet_adopt(store, operation, release_id).await,
        _ => Err(IntegrationError::ContractDrift),
    }
}

async fn release_preflight(
    store: &Store,
    operation: &LeasedOperation,
    release_id: &str,
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
        let prepared = driver_request_with_key(
            operation.id,
            Uuid::nil(),
            "release",
            &format!("release-initial:{release_id}"),
            &json!({
                "phase":"prepare-initial",
                "release_id":release_id,
                "manifest_digest":manifest_digest,
            }),
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
    }
    let mut current = status;
    if current == "preflighting" {
        let changed = sqlx::query(
            "update control.application_releases set status='canary',version=version+1
             where id=$1 and status='preflighting'",
        )
        .bind(release_id)
        .execute(store.pool())
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
        .execute(store.pool())
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
    Ok(())
}

async fn release_fleet_adopt(
    store: &Store,
    operation: &LeasedOperation,
    release_id: &str,
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
    // Tenant isolation, recovery, upgrade, verification and the final slot
    // switch are delegated through one idempotent private driver contract. The
    // driver returns only evidence and never release credentials.
    let result = driver_request_with_key(
        operation.id,
        Uuid::nil(),
        "release",
        &format!("release-fleet:{}", run.0),
        &json!({"phase":"adopt-fleet","fleet_run_id":run.0,"release_id":release_id}),
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
    let mut tx = store
        .begin()
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
    let release_identity = sqlx::query_as::<_, (String, String)>(
        "select odoo_subject_digest,extension_subject_digest from control.application_releases where id=$1 for update",
    )
    .bind(release_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|_| IntegrationError::Unavailable)?;
    if release_identity.0 != odoo_subject_digest || release_identity.1 != extension_subject_digest {
        return Err(IntegrationError::ContractDrift);
    }
    let expected_count = sqlx::query_scalar::<_, i64>(
        "select count(*) from control.tenant_release_adoptions
         where operation_id=$1 and release_id=$2 and state='prepared'",
    )
    .bind(operation.id)
    .bind(release_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|_| IntegrationError::Unavailable)?;
    if usize::try_from(expected_count).ok() != Some(prepared.len()) {
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
    sqlx::query(
        "update control.release_fleet_runs set state='active',evidence=$2,updated_at=now()
         where id=$1 and state in ('preparing','activating')",
    )
    .bind(run.0)
    .bind(&evidence)
    .execute(&mut *tx)
    .await
    .map_err(|_| IntegrationError::Unavailable)?;
    sqlx::query(
        "update control.application_releases set status='active',version=version+1
         where id=$1 and status='prepared'",
    )
    .bind(release_id)
    .execute(&mut *tx)
    .await
    .map_err(|_| IntegrationError::Unavailable)?;
    tx.commit().await.map_err(|_| IntegrationError::Unavailable)
}
