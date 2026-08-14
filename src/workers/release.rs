use std::time::Duration;

use base64::Engine;
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
}

pub(crate) fn validate_configuration() -> anyhow::Result<()> {
    for name in [
        "CONTROL_RELEASE_COSIGN_EXECUTABLE",
        "CONTROL_RELEASE_COSIGN_KEY_FILE",
        "CONTROL_RELEASE_SLSA_BUILDER_ID",
        "CONTROL_DEPLOYMENT_DRIVER_URL",
        "CONTROL_DEPLOYMENT_DRIVER_TOKEN",
    ] {
        let value = crate::runtime_secret::environment(name)
            .map_err(anyhow::Error::msg)?
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| anyhow::anyhow!("{name} is required for release adoption"))?;
        if name.ends_with("_FILE") && !std::path::Path::new(&value).is_file() {
            anyhow::bail!("{name} does not identify a readable file");
        }
    }
    Ok(())
}

async fn verify_release_provenance(
    manifest: &crate::release::ApplicationReleaseManifest,
    manifest_digest: &str,
) -> Result<(), IntegrationError> {
    let executable = required_release_setting("CONTROL_RELEASE_COSIGN_EXECUTABLE")?;
    let key = required_release_setting("CONTROL_RELEASE_COSIGN_KEY_FILE")?;
    let builder = required_release_setting("CONTROL_RELEASE_SLSA_BUILDER_ID")?;
    if !std::path::Path::new(&key).is_file() {
        return Err(IntegrationError::ContractDrift);
    }
    run_cosign(
        &executable,
        &[
            "verify",
            "--key",
            &key,
            "--output=json",
            &manifest.provenance.oci_ref,
        ],
    )
    .await?;
    let attestation = run_cosign(
        &executable,
        &[
            "verify-attestation",
            "--key",
            &key,
            "--type=slsaprovenance",
            "--output=json",
            &manifest.provenance.oci_ref,
        ],
    )
    .await?;
    let rows: Value =
        serde_json::from_slice(&attestation).map_err(|_| IntegrationError::ContractDrift)?;
    let rows = rows.as_array().ok_or(IntegrationError::ContractDrift)?;
    if !rows.iter().any(|row| {
        row.get("payload")
            .and_then(Value::as_str)
            .and_then(|payload| {
                base64::engine::general_purpose::STANDARD
                    .decode(payload)
                    .ok()
            })
            .and_then(|payload| serde_json::from_slice::<Value>(&payload).ok())
            .is_some_and(|statement| {
                slsa_statement_matches(&statement, manifest, manifest_digest, &builder)
            })
    }) {
        return Err(IntegrationError::ContractDrift);
    }
    Ok(())
}

fn required_release_setting(name: &'static str) -> Result<String, IntegrationError> {
    crate::runtime_secret::required(name).map_err(|_| IntegrationError::ContractDrift)
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

pub(crate) fn slsa_statement_matches(
    statement: &Value,
    manifest: &crate::release::ApplicationReleaseManifest,
    manifest_digest: &str,
    expected_builder: &str,
) -> bool {
    let image_hex = manifest.image_digest.strip_prefix("sha256:").unwrap_or("");
    let manifest_hex = manifest_digest.strip_prefix("sha256:").unwrap_or("");
    let subject_matches = statement
        .get("subject")
        .and_then(Value::as_array)
        .is_some_and(|subjects| {
            [image_hex, manifest_hex].iter().all(|expected| {
                !expected.is_empty()
                    && subjects.iter().any(|subject| {
                        subject.pointer("/digest/sha256").and_then(Value::as_str) == Some(*expected)
                    })
            })
        });
    let builder_matches = statement
        .pointer("/predicate/runDetails/builder/id")
        .or_else(|| statement.pointer("/predicate/builder/id"))
        .and_then(Value::as_str)
        == Some(expected_builder);
    let dependency_matches = statement
        .pointer("/predicate/buildDefinition/resolvedDependencies")
        .or_else(|| statement.pointer("/predicate/materials"))
        .and_then(Value::as_array)
        .is_some_and(|dependencies| {
            dependencies.iter().any(|dependency| {
                dependency
                    .get("digest")
                    .and_then(Value::as_object)
                    .is_some_and(|digests| {
                        digests
                            .values()
                            .any(|digest| digest.as_str() == Some(manifest.source_commit.as_str()))
                    })
            })
        });
    subject_matches && builder_matches && dependency_matches
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
    if manifest.release_id != release_id
        || !manifest
            .provenance
            .oci_ref
            .ends_with(&format!("@{}", manifest.image_digest))
    {
        return Err(IntegrationError::ContractDrift);
    }
    verify_release_provenance(&manifest, &manifest_digest).await?;
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
    let image_digest = evidence
        .get("image_digest")
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
    let release_image = sqlx::query_scalar::<_, String>(
        "select image_digest from control.application_releases where id=$1 for update",
    )
    .bind(release_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|_| IntegrationError::Unavailable)?;
    if release_image != image_digest {
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
           runtime_key,slot,release_id,state,image_digest,started_at,verified_at,activated_at,evidence
         ) values($1,$2,$3,'active',$4,now(),now(),now(),$5)
         on conflict(runtime_key,slot) do update set
           release_id=excluded.release_id,state='active',image_digest=excluded.image_digest,
           started_at=coalesce(control.runtime_release_slots.started_at,now()),
           verified_at=now(),activated_at=now(),evidence=excluded.evidence,
           version=control.runtime_release_slots.version+1",
    )
    .bind(runtime_key)
    .bind(target_slot)
    .bind(release_id)
    .bind(image_digest)
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
