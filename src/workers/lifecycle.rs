use serde_json::{Value, json};
use uuid::Uuid;

use crate::domain::IntegrationError;
use crate::persistence::{LeasedOperation, Store};
use crate::privacy_crypto;
use crate::worker::{driver, driver_request_with_key, payload_uuid};

pub(crate) async fn run(
    store: &Store,
    operation: &LeasedOperation,
) -> Result<(), IntegrationError> {
    let action = operation
        .payload
        .get("action")
        .and_then(Value::as_str)
        .ok_or(IntegrationError::ContractDrift)?;
    sqlx::query(
        "update control.operations set progress_percent=2,progress_phase='preparing',
                progress_message='Preparing workshop recovery operation',progress_updated_at=now()
         where id=$1 and state='in_flight'",
    )
    .bind(operation.id)
    .execute(store.pool())
    .await
    .map_err(|_| IntegrationError::Unavailable)?;
    match action {
        "snapshot" | "backup" | "delete" => {
            let recovery = payload_uuid(&operation.payload, "recovery_point_id")?;
            let database = payload_uuid(&operation.payload, "database_id")?;
            sqlx::query("update control.odoo_databases set state='snapshotting' where id=$1 and state='ready'")
                .bind(database).execute(store.pool()).await.map_err(|_|IntegrationError::Unavailable)?;
            sqlx::query("update control.workshop_recovery_points set state='creating',verification_state='pending' where id=$1 and state in ('queued','failed')")
                .bind(recovery).execute(store.pool()).await.map_err(|_|IntegrationError::Unavailable)?;
            if action == "delete" {
                let workshop = operation
                    .workshop_id
                    .ok_or(IntegrationError::ContractDrift)?;
                sqlx::query("update control.workshop_deletions set state='quarantining',failure_class=null where workshop_id=$1")
                    .bind(workshop).execute(store.pool()).await.map_err(|_|IntegrationError::Unavailable)?;
                sqlx::query("update control.workshops set status='deleting' where id=$1")
                    .bind(workshop)
                    .execute(store.pool())
                    .await
                    .map_err(|_| IntegrationError::Unavailable)?;
            }
        }
        "restore" => {
            let database = payload_uuid(&operation.payload, "database_id")?;
            let safety = payload_uuid(&operation.payload, "safety_recovery_point_id")?;
            sqlx::query("update control.odoo_databases set state='restoring' where id=$1")
                .bind(database)
                .execute(store.pool())
                .await
                .map_err(|_| IntegrationError::Unavailable)?;
            sqlx::query("update control.workshop_recovery_points set state='creating',verification_state='pending' where id=$1 and state in ('queued','failed')")
                .bind(safety).execute(store.pool()).await.map_err(|_|IntegrationError::Unavailable)?;
        }
        "duplicate" => {
            let target = payload_uuid(&operation.payload, "target_database_id")?;
            sqlx::query("update control.odoo_databases set state='duplicating' where id=$1")
                .bind(target)
                .execute(store.pool())
                .await
                .map_err(|_| IntegrationError::Unavailable)?;
        }
        _ => return Err(IntegrationError::ContractDrift),
    }
    let value = driver(store, operation, "lifecycle").await?;
    match action {
        "snapshot" | "backup" | "delete" => {
            let recovery = payload_uuid(&operation.payload, "recovery_point_id")?;
            let result = value
                .get("recovery_point")
                .ok_or(IntegrationError::ContractDrift)?;
            record_recovery_ready(store, recovery, result).await?;
            let database = payload_uuid(&operation.payload, "database_id")?;
            sqlx::query(if action == "delete" { "update control.odoo_databases set state='suspended' where id=$1 and state='snapshotting'" } else { "update control.odoo_databases set state='ready' where id=$1 and state='snapshotting'" })
                .bind(database)
                .execute(store.pool())
                .await
                .map_err(|_| IntegrationError::Unavailable)?;
            if action == "delete" {
                let workshop = operation
                    .workshop_id
                    .ok_or(IntegrationError::ContractDrift)?;
                let mut tx = store
                    .begin()
                    .await
                    .map_err(|_| IntegrationError::Unavailable)?;
                sqlx::query("update control.workshop_deletions set state='retained',quarantined_at=now(),failure_class=null where workshop_id=$1")
                    .bind(workshop).execute(&mut *tx).await.map_err(|_|IntegrationError::Unavailable)?;
                sqlx::query(
                    "update control.workshops set status='deleted',version=version+1 where id=$1",
                )
                .bind(workshop)
                .execute(&mut *tx)
                .await
                .map_err(|_| IntegrationError::Unavailable)?;
                sqlx::query("update control.service_instances set health='suspended',safe_error_class=null,last_observed_at=now() where workshop_id=$1")
                    .bind(workshop).execute(&mut *tx).await.map_err(|_|IntegrationError::Unavailable)?;
                sqlx::query("update control.carrier_secrets set state='deleted',deleted_at=now(),cleanup_pending_ref=null,version=version+1 where workshop_id=$1 and state<>'deleted'")
                    .bind(workshop).execute(&mut *tx).await.map_err(|_|IntegrationError::Unavailable)?;
                tx.commit()
                    .await
                    .map_err(|_| IntegrationError::Unavailable)?;
            }
        }
        "restore" => {
            let database = payload_uuid(&operation.payload, "database_id")?;
            let safety = payload_uuid(&operation.payload, "safety_recovery_point_id")?;
            let result = value
                .get("safety_recovery_point")
                .ok_or(IntegrationError::ContractDrift)?;
            record_recovery_ready(store, safety, result).await?;
            if value.get("restore_status").and_then(Value::as_str) == Some("rolled_back") {
                return Err(IntegrationError::Rejected);
            }
            if operation
                .payload
                .get("erasure_replay_required")
                .and_then(Value::as_bool)
                == Some(true)
            {
                replay_restored_erasures(store, operation).await?;
            }
            let mut tx = store
                .begin()
                .await
                .map_err(|_| IntegrationError::Unavailable)?;
            sqlx::query("update control.odoo_databases set state='ready',last_restored_at=now() where id=$1")
                .bind(database).execute(&mut *tx).await.map_err(|_|IntegrationError::Unavailable)?;
            tx.commit()
                .await
                .map_err(|_| IntegrationError::Unavailable)?;
            if operation
                .payload
                .get("erasure_replay_required")
                .and_then(Value::as_bool)
                == Some(true)
            {
                driver_request_with_key(
                    operation.id,
                    operation
                        .workshop_id
                        .ok_or(IntegrationError::ContractDrift)?,
                    "resume",
                    &format!("restore-resume:{}", operation.id),
                    &json!({
                        "restore_operation_id":operation.id,
                        "database_id":database
                    }),
                )
                .await?;
            }
        }
        "duplicate" => {
            let target = payload_uuid(&operation.payload, "target_database_id")?;
            sqlx::query("update control.odoo_databases set state='ready' where id=$1 and kind='duplicate' and routable=false")
                .bind(target).execute(store.pool()).await.map_err(|_|IntegrationError::Unavailable)?;
        }
        _ => return Err(IntegrationError::ContractDrift),
    }
    Ok(())
}

async fn replay_restored_erasures(
    store: &Store,
    operation: &LeasedOperation,
) -> Result<(), IntegrationError> {
    let workshop = operation
        .workshop_id
        .ok_or(IntegrationError::ContractDrift)?;
    let rows = sqlx::query_as::<
        _,
        (
            Uuid,
            Uuid,
            Vec<String>,
            Vec<String>,
            Uuid,
            String,
            Vec<u8>,
            Vec<u8>,
        ),
    >(
        "select r.id,t.id,r.required_locations,r.completed_locations,t.subject_key,
                l.key_id,l.nonce,l.ciphertext
         from control.erasure_restore_replays r
         join control.erasure_tombstones t on t.id=r.tombstone_id
         join control.erasure_subject_lookups l on l.tombstone_id=t.id
         where r.operation_id=$1 and r.state<>'complete'
         order by t.sequence",
    )
    .bind(operation.id)
    .fetch_all(store.pool())
    .await
    .map_err(|_| IntegrationError::Unavailable)?;
    if rows.is_empty() {
        let complete = sqlx::query_scalar::<_, bool>(
            "select exists(select 1 from control.erasure_restore_replays where operation_id=$1)
             and not exists(select 1 from control.erasure_restore_replays where operation_id=$1 and state<>'complete')",
        )
        .bind(operation.id)
        .fetch_one(store.pool())
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
        return if complete {
            Ok(())
        } else {
            Err(IntegrationError::ContractDrift)
        };
    }
    for (replay_id, tombstone_id, required, completed, subject_key, key_id, nonce, ciphertext) in
        rows
    {
        let result = async {
            if key_id != privacy_crypto::lookup_key_id()? {
                return Err(IntegrationError::Unauthorized);
            }
            let plaintext = privacy_crypto::decrypt(tombstone_id, &nonce, &ciphertext)?;
            let lookup: Value = serde_json::from_slice(&plaintext)
                .map_err(|_| IntegrationError::ContractDrift)?;
            let user_id = lookup
                .get("control_user_id")
                .and_then(Value::as_str)
                .and_then(|value| Uuid::parse_str(value).ok())
                .ok_or(IntegrationError::ContractDrift)?;
            let rauthy_subject = lookup
                .get("rauthy_subject")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty() && value.len() <= 255)
                .ok_or(IntegrationError::ContractDrift)?;
            sqlx::query("update control.erasure_restore_replays set state='applying',started_at=coalesce(started_at,now()),safe_error_class=null where id=$1")
                .bind(replay_id).execute(store.pool()).await.map_err(|_|IntegrationError::Unavailable)?;
            for location in &required {
                if completed.contains(location) {
                    continue;
                }
                match location.as_str() {
                    "odoo" | "paperless" => {
                        driver_request_with_key(
                            operation.id,
                            workshop,
                            "erasure",
                            &format!("erasure-replay:{tombstone_id}:{location}"),
                            &json!({
                                "restore_operation_id":operation.id,
                                "replay_id":replay_id,
                                "tombstone_id":tombstone_id,
                                "location":location,
                                "control_user_id":user_id,
                                "rauthy_subject":rauthy_subject,
                                "subject_key":subject_key
                            }),
                        )
                        .await?;
                    }
                    _ => return Err(IntegrationError::ContractDrift),
                }
                sqlx::query("update control.erasure_restore_replays set completed_locations=array_append(completed_locations,$2) where id=$1 and not ($2=any(completed_locations))")
                    .bind(replay_id).bind(location).execute(store.pool()).await.map_err(|_|IntegrationError::Unavailable)?;
            }
            let changed=sqlx::query("update control.erasure_restore_replays set state='complete',completed_at=now(),safe_error_class=null where id=$1 and completed_locations @> required_locations")
                .bind(replay_id).execute(store.pool()).await.map_err(|_|IntegrationError::Unavailable)?.rows_affected();
            if changed != 1 {
                return Err(IntegrationError::UnknownOutcome);
            }
            Ok(())
        }
        .await;
        if let Err(error) = result {
            let _ = sqlx::query("update control.erasure_restore_replays set state='failed',safe_error_class=$2 where id=$1")
                .bind(replay_id).bind(error.failure_class()).execute(store.pool()).await;
            return Err(error);
        }
    }
    Ok(())
}

async fn record_recovery_ready(
    store: &Store,
    recovery: Uuid,
    result: &Value,
) -> Result<(), IntegrationError> {
    let string = |key| {
        result
            .get(key)
            .and_then(Value::as_str)
            .ok_or(IntegrationError::ContractDrift)
    };
    let storage_ref = string("storage_ref")?;
    let size_bytes = result
        .get("size_bytes")
        .and_then(Value::as_i64)
        .ok_or(IntegrationError::ContractDrift)?;
    let manifest_digest = string("manifest_digest")?;
    let format_version = string("format_version")?;
    let storage_location = string("storage_location")?;
    let source_release = string("source_release")?;
    let paperless_version = result.get("paperless_version").and_then(Value::as_str);
    let encryption_key_id = result.get("encryption_key_id").and_then(Value::as_str);
    let object_prefix = result.get("object_prefix").and_then(Value::as_str);
    let archive_object_key = result.get("archive_object_key").and_then(Value::as_str);
    let archive_size_bytes = result.get("archive_size_bytes").and_then(Value::as_i64);
    let archive_digest = result.get("archive_digest").and_then(Value::as_str);
    let retention_days = result
        .get("retention_days")
        .and_then(Value::as_i64)
        .unwrap_or(35);
    let components = result
        .get("components")
        .and_then(Value::as_array)
        .ok_or(IntegrationError::ContractDrift)?;
    let mut tx = store
        .begin()
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
    sqlx::query("update control.workshop_recovery_points set state='ready',storage_ref=$2,size_bytes=$3,ready_at=now(),verification_state='verified',verified_at=now(),manifest_digest=$4,format_version=$5,storage_location=$6,source_release=$7,paperless_version=$8,encryption_key_id=$9,object_prefix=$10,expires_at=case when kind='backup' then now()+make_interval(days=>$11) else expires_at end,archive_object_key=$12,archive_size_bytes=$13,archive_digest=$14 where id=$1")
        .bind(recovery).bind(storage_ref).bind(size_bytes).bind(manifest_digest).bind(format_version).bind(storage_location).bind(source_release).bind(paperless_version).bind(encryption_key_id).bind(object_prefix).bind(i32::try_from(retention_days).map_err(|_|IntegrationError::ContractDrift)?).bind(archive_object_key).bind(archive_size_bytes).bind(archive_digest).execute(&mut *tx).await.map_err(|_|IntegrationError::Unavailable)?;
    sqlx::query("delete from control.workshop_recovery_components where recovery_point_id=$1")
        .bind(recovery)
        .execute(&mut *tx)
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
    for component in components {
        let name = component
            .get("name")
            .and_then(Value::as_str)
            .ok_or(IntegrationError::ContractDrift)?;
        let path = component
            .get("path")
            .and_then(Value::as_str)
            .ok_or(IntegrationError::ContractDrift)?;
        let bytes = component
            .get("size_bytes")
            .and_then(Value::as_i64)
            .ok_or(IntegrationError::ContractDrift)?;
        let digest = component
            .get("sha256")
            .and_then(Value::as_str)
            .ok_or(IntegrationError::ContractDrift)?;
        let plaintext_digest = component.get("plaintext_sha256").and_then(Value::as_str);
        sqlx::query("insert into control.workshop_recovery_components(recovery_point_id,component,object_key,size_bytes,digest,plaintext_digest,state,verified_at) values($1,$2,$3,$4,$5,$6,'verified',now())")
            .bind(recovery).bind(name).bind(path).bind(bytes).bind(digest).bind(plaintext_digest).execute(&mut *tx).await.map_err(|_|IntegrationError::Unavailable)?;
    }
    tx.commit().await.map_err(|_| IntegrationError::Unavailable)
}

pub(crate) async fn failed(store: &Store, operation: &LeasedOperation) {
    let action = operation.payload.get("action").and_then(Value::as_str);
    if matches!(action, Some("snapshot" | "backup" | "delete"))
        && let Ok(database) = payload_uuid(&operation.payload, "database_id")
        && let Err(error) = sqlx::query(
            "update control.odoo_databases set state='ready' where id=$1 and state='snapshotting'",
        )
        .bind(database)
        .execute(store.pool())
        .await
    {
        tracing::error!(operation=%operation.id,error=%error,"could not release snapshotting database state");
    }
    if action == Some("restore")
        && let Ok(safety) = payload_uuid(&operation.payload, "safety_recovery_point_id")
        && let Err(error) =
            sqlx::query("update control.workshop_recovery_points set state='failed',verification_state='failed' where id=$1 and state='creating'")
                .bind(safety)
                .execute(store.pool())
                .await
    {
        tracing::error!(operation=%operation.id,error=%error,"could not mark restore safety snapshot failed");
    }
    let result = match action {
        Some("snapshot" | "backup" | "delete") => {
            payload_uuid(&operation.payload, "recovery_point_id").map(|id| {
                (
                    "update control.workshop_recovery_points set state='failed',verification_state='failed' where id=$1",
                    id,
                )
            })
        }
        Some("restore") => payload_uuid(&operation.payload, "database_id").map(|id| {
            (
                "update control.odoo_databases set state='failed' where id=$1 and state='restoring'",
                id,
            )
        }),
        Some("duplicate") => payload_uuid(&operation.payload, "target_database_id").map(|id| {
            (
                "update control.odoo_databases set state='failed' where id=$1",
                id,
            )
        }),
        _ => Err(IntegrationError::ContractDrift),
    };
    if let Ok((query, id)) = result
        && let Err(error) = sqlx::query(query).bind(id).execute(store.pool()).await
    {
        tracing::error!(operation=%operation.id,error=%error,"could not mark lifecycle resource failed");
    }
    if action == Some("delete")
        && let Some(workshop) = operation.workshop_id
        && let Err(error) = sqlx::query("with failed as (update control.workshop_deletions set state='failed',failure_class='lifecycle_failed' where workshop_id=$1 returning previous_status) update control.workshops set status=failed.previous_status from failed where id=$1")
            .bind(workshop).execute(store.pool()).await
    {
        tracing::error!(operation=%operation.id,error=%error,"could not release failed workshop deletion");
    }
}
