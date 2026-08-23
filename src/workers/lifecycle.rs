use serde_json::{Value, json};
use uuid::Uuid;

use crate::domain::IntegrationError;
use crate::persistence::{
    LeasedOperation, TenantStore, WorkshopTransaction, lock_current_operation_lease,
};
use crate::privacy_crypto;
use crate::worker::{driver_request_with_key, payload_uuid};
use crate::worker_config::DeploymentDriverConfig;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LifecycleCommand {
    Snapshot {
        database: Uuid,
        recovery: Uuid,
    },
    Backup {
        database: Uuid,
        recovery: Uuid,
    },
    Delete {
        database: Uuid,
        recovery: Uuid,
    },
    Restore {
        database: Uuid,
        source_recovery: Uuid,
        safety_recovery: Uuid,
        replay_erasures: bool,
    },
    Duplicate {
        source_database: Uuid,
        target_database: Uuid,
    },
}

impl LifecycleCommand {
    fn decode(operation: &LeasedOperation) -> Result<Self, IntegrationError> {
        let action = operation
            .payload
            .get("action")
            .and_then(Value::as_str)
            .ok_or(IntegrationError::ContractDrift)?;
        let database = || payload_uuid(&operation.payload, "database_id");
        let recovery = || payload_uuid(&operation.payload, "recovery_point_id");
        Ok(match action {
            "snapshot" => Self::Snapshot {
                database: database()?,
                recovery: recovery()?,
            },
            "backup" => Self::Backup {
                database: database()?,
                recovery: recovery()?,
            },
            "delete" => Self::Delete {
                database: database()?,
                recovery: recovery()?,
            },
            "restore" => Self::Restore {
                database: database()?,
                source_recovery: recovery()?,
                safety_recovery: payload_uuid(&operation.payload, "safety_recovery_point_id")?,
                replay_erasures: match operation.payload.get("erasure_replay_required") {
                    Some(value) => value.as_bool().ok_or(IntegrationError::ContractDrift)?,
                    None => false,
                },
            },
            "duplicate" => Self::Duplicate {
                source_database: database()?,
                target_database: payload_uuid(&operation.payload, "target_database_id")?,
            },
            _ => return Err(IntegrationError::ContractDrift),
        })
    }

    const fn action(self) -> &'static str {
        match self {
            Self::Snapshot { .. } => "snapshot",
            Self::Backup { .. } => "backup",
            Self::Delete { .. } => "delete",
            Self::Restore { .. } => "restore",
            Self::Duplicate { .. } => "duplicate",
        }
    }
}

fn is_sha256_digest(value: Option<&str>) -> bool {
    value.is_some_and(|value| {
        value.len() == 71
            && value.starts_with("sha256:")
            && value[7..]
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MaintenanceEntry {
    Active(Uuid),
    AlreadyRestored,
}

fn confirm_maintenance_entry(
    response: &Value,
    workshop: Uuid,
) -> Result<MaintenanceEntry, IntegrationError> {
    let effect_run_id = response
        .get("effect_run_id")
        .and_then(Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok())
        .ok_or(IntegrationError::UnknownOutcome)?;
    if response.get("outcome").and_then(Value::as_str) == Some("restored") {
        confirm_maintenance_exit(response, workshop, effect_run_id)?;
        return Ok(MaintenanceEntry::AlreadyRestored);
    }
    if response.get("outcome").and_then(Value::as_str) != Some("maintenance") {
        return Err(IntegrationError::UnknownOutcome);
    }
    let fence = response
        .get("route_fence_token")
        .and_then(Value::as_i64)
        .filter(|value| *value > 0)
        .ok_or(IntegrationError::UnknownOutcome)?;
    let evidence = response
        .get("route_evidence")
        .and_then(Value::as_object)
        .ok_or(IntegrationError::UnknownOutcome)?;
    if evidence.len() != 8
        || evidence.get("effect_run_id").and_then(Value::as_str)
            != Some(effect_run_id.to_string().as_str())
        || evidence.get("workshop_id").and_then(Value::as_str)
            != Some(workshop.to_string().as_str())
        || evidence.get("route_fence_token").and_then(Value::as_i64) != Some(fence)
        || evidence.get("mode").and_then(Value::as_str) != Some("maintenance")
        || evidence.get("disposition").and_then(Value::as_str) != Some("present")
        || evidence
            .get("generation")
            .and_then(Value::as_i64)
            .is_none_or(|value| value <= 0)
        || !is_sha256_digest(evidence.get("projection_digest").and_then(Value::as_str))
        || !is_sha256_digest(evidence.get("rendered_digest").and_then(Value::as_str))
    {
        return Err(IntegrationError::UnknownOutcome);
    }
    Ok(MaintenanceEntry::Active(effect_run_id))
}

fn confirm_maintenance_exit(
    response: &Value,
    workshop: Uuid,
    effect_run_id: Uuid,
) -> Result<(), IntegrationError> {
    if response.get("outcome").and_then(Value::as_str) != Some("restored")
        || response.get("effect_run_id").and_then(Value::as_str)
            != Some(effect_run_id.to_string().as_str())
    {
        return Err(IntegrationError::UnknownOutcome);
    }
    let evidence = response
        .get("route_evidence")
        .and_then(Value::as_object)
        .ok_or(IntegrationError::UnknownOutcome)?;
    if evidence.len() != 8
        || evidence.get("effect_run_id").and_then(Value::as_str)
            != Some(effect_run_id.to_string().as_str())
        || evidence.get("workshop_id").and_then(Value::as_str)
            != Some(workshop.to_string().as_str())
        || evidence.get("mode").and_then(Value::as_str) != Some("restored")
        || evidence
            .get("route_fence_token")
            .and_then(Value::as_i64)
            .is_none_or(|value| value <= 0)
        || evidence
            .get("generation")
            .and_then(Value::as_i64)
            .is_none_or(|value| value <= 0)
        || !is_sha256_digest(evidence.get("projection_digest").and_then(Value::as_str))
        || !is_sha256_digest(evidence.get("rendered_digest").and_then(Value::as_str))
        || !matches!(
            evidence.get("disposition").and_then(Value::as_str),
            Some("present" | "absent")
        )
    {
        return Err(IntegrationError::UnknownOutcome);
    }
    Ok(())
}

async fn restore_is_finalized(
    tenant_store: &TenantStore,
    workshop: Uuid,
    operation: &LeasedOperation,
    command: LifecycleCommand,
) -> Result<bool, IntegrationError> {
    let LifecycleCommand::Restore {
        database,
        safety_recovery,
        replay_erasures,
        ..
    } = command
    else {
        return Ok(false);
    };
    let mut tx = tenant_store
        .begin(workshop)
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
    let finalized = sqlx::query_scalar::<_, bool>(
        "select exists(
             select 1 from control.odoo_databases database
              where database.id=$1 and database.workshop_id=$2
                and database.kind='primary' and database.state='ready'
                and database.last_restored_at is not null)
          and exists(
             select 1 from control.workshop_recovery_points recovery
              where recovery.id=$3 and recovery.workshop_id=$2
                and recovery.operation_id=$4 and recovery.state='ready'
                and recovery.verification_state='verified')
          and ($5=false or not exists(
             select 1 from control.erasure_restore_replays replay
              where replay.operation_id=$4 and replay.state<>'complete'))",
    )
    .bind(database)
    .bind(workshop)
    .bind(safety_recovery)
    .bind(operation.id)
    .bind(replay_erasures)
    .fetch_one(&mut *tx)
    .await
    .map_err(|_| IntegrationError::Unavailable)?;
    tx.commit()
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
    Ok(finalized)
}

async fn exit_maintenance(
    operation: &LeasedOperation,
    workshop: Uuid,
    effect_run_id: Uuid,
    deployment_driver: &DeploymentDriverConfig,
) -> Result<(), IntegrationError> {
    let response = driver_request_with_key(
        operation,
        workshop,
        "route-maintenance-exit",
        &format!("restore-maintenance-exit:{}", operation.id),
        &json!({"effect_run_id":effect_run_id}),
        deployment_driver,
    )
    .await?;
    confirm_maintenance_exit(&response, workshop, effect_run_id)
}

async fn validate_resource_ownership(
    tx: &mut WorkshopTransaction<'_>,
    operation: &LeasedOperation,
    command: LifecycleCommand,
) -> Result<(), IntegrationError> {
    let workshop = tx.workshop_id();
    let owned = match command {
        LifecycleCommand::Snapshot { database, recovery }
        | LifecycleCommand::Backup { database, recovery }
        | LifecycleCommand::Delete { database, recovery } => {
            let kind = if matches!(command, LifecycleCommand::Snapshot { .. }) {
                "snapshot"
            } else {
                "backup"
            };
            sqlx::query_scalar::<_, bool>(
                "select exists(
                    select 1 from control.odoo_databases d
                    join control.workshop_recovery_points r
                      on r.database_id=d.id and r.workshop_id=d.workshop_id
                   where d.id=$1 and d.workshop_id=$2 and d.kind='primary'
                     and r.id=$3 and r.operation_id=$4 and r.kind=$5
                     and ($6=false or exists(
                         select 1 from control.workshop_deletions deletion
                          where deletion.workshop_id=$2
                            and deletion.operation_id=$4
                            and deletion.final_recovery_point_id=$3))
                )",
            )
            .bind(database)
            .bind(workshop)
            .bind(recovery)
            .bind(operation.id)
            .bind(kind)
            .bind(matches!(command, LifecycleCommand::Delete { .. }))
            .fetch_one(&mut **tx)
            .await
        }
        LifecycleCommand::Restore {
            database,
            source_recovery: source,
            safety_recovery: safety,
            ..
        } => {
            sqlx::query_scalar::<_, bool>(
                "select exists(
                    select 1 from control.odoo_databases d
                    join control.workshop_recovery_points source
                      on source.database_id=d.id and source.workshop_id=d.workshop_id
                    join control.workshop_recovery_points safety
                      on safety.database_id=d.id and safety.workshop_id=d.workshop_id
                   where d.id=$1 and d.workshop_id=$2 and d.kind='primary'
                     and source.id=$3 and source.state='ready'
                     and source.verification_state='verified'
                     and source.storage_ref is not null
                     and (source.expires_at is null or source.expires_at>now())
                     and safety.id=$4 and safety.operation_id=$5 and safety.kind='backup'
                )",
            )
            .bind(database)
            .bind(workshop)
            .bind(source)
            .bind(safety)
            .bind(operation.id)
            .fetch_one(&mut **tx)
            .await
        }
        LifecycleCommand::Duplicate {
            source_database: source,
            target_database: target,
        } => {
            sqlx::query_scalar::<_, bool>(
                "select exists(
                    select 1 from control.odoo_databases source
                    join control.odoo_databases target
                      on target.source_database_id=source.id
                     and target.workshop_id=source.workshop_id
                   where source.id=$1 and source.workshop_id=$2 and source.kind='primary'
                     and source.deleted_at is null
                     and target.id=$3 and target.kind='duplicate'
                     and target.state='duplicating' and target.routable=false
                     and target.deleted_at is null
                )",
            )
            .bind(source)
            .bind(workshop)
            .bind(target)
            .fetch_one(&mut **tx)
            .await
        }
    }
    .map_err(|_| IntegrationError::Unavailable)?;
    if !owned {
        return Err(IntegrationError::ContractDrift);
    }
    Ok(())
}

#[tracing::instrument(
    name = "lifecycle.execute",
    skip_all,
    fields(operation = %operation.id, lifecycle_action = tracing::field::Empty,
        phase = "admit")
)]
pub(crate) async fn run(
    tenant_store: &TenantStore,
    workshop: Uuid,
    operation: &LeasedOperation,
    deployment_driver: &DeploymentDriverConfig,
) -> Result<(), IntegrationError> {
    let command = LifecycleCommand::decode(operation)?;
    tracing::Span::current().record("lifecycle_action", command.action());
    if let LifecycleCommand::Delete { database, recovery } = command {
        tracing::Span::current().record("phase", "route_tombstone.materialize");
        let mut route_tx = tenant_store
            .begin(workshop)
            .await
            .map_err(|_| IntegrationError::Unavailable)?;
        super::routes::lock_authority(&mut route_tx, operation).await?;
        let source_locked = sqlx::query_scalar::<_, bool>(
            "select true
               from control.workshops workshop
               join control.odoo_databases database
                 on database.workshop_id=workshop.id and database.id=$2
               join control.workshop_recovery_points recovery
                 on recovery.workshop_id=workshop.id and recovery.database_id=database.id
                and recovery.id=$3 and recovery.operation_id=$4 and recovery.kind='backup'
               join control.workshop_deletions deletion
                 on deletion.workshop_id=workshop.id and deletion.operation_id=$4
                and deletion.final_recovery_point_id=recovery.id
              where workshop.id=$1 and workshop.status in ('restricted','deleting')
                and database.kind='primary' and database.deleted_at is null
              for update of workshop,database,recovery,deletion",
        )
        .bind(workshop)
        .bind(database)
        .bind(recovery)
        .bind(operation.id)
        .fetch_optional(&mut *route_tx)
        .await
        .map_err(|_| IntegrationError::Unavailable)?
        .unwrap_or(false);
        if !source_locked {
            return Err(IntegrationError::ContractDrift);
        }
        let tombstone = super::routes::materialize_tombstone(&mut route_tx, operation).await?;
        route_tx
            .commit()
            .await
            .map_err(|_| IntegrationError::Unavailable)?;
        tracing::Span::current().record("phase", "route_tombstone.apply");
        super::routes::apply(
            operation,
            workshop,
            "lifecycle-delete-tombstone",
            &tombstone,
            deployment_driver,
        )
        .await?;
    }
    tracing::Span::current().record("phase", "lifecycle");
    let maintenance = if matches!(command, LifecycleCommand::Restore { .. }) {
        let mut validation = tenant_store
            .begin(workshop)
            .await
            .map_err(|_| IntegrationError::Unavailable)?;
        validate_resource_ownership(&mut validation, operation, command).await?;
        validation
            .commit()
            .await
            .map_err(|_| IntegrationError::Unavailable)?;
        let response = driver_request_with_key(
            operation,
            workshop,
            "route-maintenance-enter",
            &format!("restore-maintenance-enter:{}", operation.id),
            &json!({"reason":"restore"}),
            deployment_driver,
        )
        .await?;
        match confirm_maintenance_entry(&response, workshop)? {
            MaintenanceEntry::Active(effect_run_id) => {
                if restore_is_finalized(tenant_store, workshop, operation, command).await? {
                    exit_maintenance(operation, workshop, effect_run_id, deployment_driver).await?;
                    return Ok(());
                }
                Some(effect_run_id)
            }
            MaintenanceEntry::AlreadyRestored => return Ok(()),
        }
    } else {
        None
    };
    prepare(tenant_store, workshop, operation, command).await?;
    let value = driver_request_with_key(
        operation,
        workshop,
        "lifecycle",
        &operation.id.to_string(),
        &operation.payload,
        deployment_driver,
    )
    .await?;
    finalize(
        tenant_store,
        workshop,
        operation,
        command,
        &value,
        deployment_driver,
    )
    .await?;
    if let Some(effect_run_id) = maintenance {
        exit_maintenance(operation, workshop, effect_run_id, deployment_driver).await?;
    }
    Ok(())
}

async fn prepare(
    tenant_store: &TenantStore,
    workshop: Uuid,
    operation: &LeasedOperation,
    command: LifecycleCommand,
) -> Result<(), IntegrationError> {
    let mut tx = tenant_store
        .begin(workshop)
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
    validate_resource_ownership(&mut tx, operation, command).await?;
    let progress_changed = sqlx::query(
        "update control.operations set progress_percent=2,progress_phase='preparing',
                progress_message='Preparing workshop recovery operation',progress_updated_at=now()
         where id=$1 and workshop_id=$2 and kind='tenant.lifecycle' and state='in_flight'",
    )
    .bind(operation.id)
    .bind(workshop)
    .execute(&mut *tx)
    .await
    .map_err(|_| IntegrationError::Unavailable)?
    .rows_affected();
    if progress_changed != 1 {
        return Err(IntegrationError::ContractDrift);
    }
    match command {
        LifecycleCommand::Snapshot { database, recovery }
        | LifecycleCommand::Backup { database, recovery }
        | LifecycleCommand::Delete { database, recovery } => {
            let database_changed = sqlx::query("update control.odoo_databases set state='snapshotting' where id=$1 and workshop_id=$2 and state in ('ready','snapshotting')")
                .bind(database).bind(workshop).execute(&mut *tx).await.map_err(|_|IntegrationError::Unavailable)?.rows_affected();
            let recovery_changed = sqlx::query("update control.workshop_recovery_points set state='creating',verification_state='pending' where id=$1 and workshop_id=$2 and operation_id=$3 and state in ('queued','failed','creating')")
                .bind(recovery).bind(workshop).bind(operation.id).execute(&mut *tx).await.map_err(|_|IntegrationError::Unavailable)?.rows_affected();
            if database_changed != 1 || recovery_changed != 1 {
                return Err(IntegrationError::ContractDrift);
            }
            if matches!(command, LifecycleCommand::Delete { .. }) {
                let deletion_changed = sqlx::query("update control.workshop_deletions set state='quarantining',failure_class=null where workshop_id=$1 and operation_id=$2 and final_recovery_point_id=$3 and state in ('scheduled','quarantining')")
                    .bind(workshop).bind(operation.id).bind(recovery).execute(&mut *tx).await.map_err(|_|IntegrationError::Unavailable)?.rows_affected();
                let workshop_changed = sqlx::query("update control.workshops set status='deleting' where id=$1 and status in ('restricted','deleting')")
                    .bind(workshop).execute(&mut *tx).await.map_err(|_| IntegrationError::Unavailable)?.rows_affected();
                if deletion_changed != 1 || workshop_changed != 1 {
                    return Err(IntegrationError::ContractDrift);
                }
            }
        }
        LifecycleCommand::Restore {
            database,
            safety_recovery: safety,
            ..
        } => {
            let database_changed = sqlx::query("update control.odoo_databases set state='restoring' where id=$1 and workshop_id=$2 and state in ('ready','restoring')")
                .bind(database).bind(workshop)
                .execute(&mut *tx)
                .await
                .map_err(|_| IntegrationError::Unavailable)?.rows_affected();
            let safety_changed = sqlx::query("update control.workshop_recovery_points set state='creating',verification_state='pending' where id=$1 and workshop_id=$2 and operation_id=$3 and state in ('queued','failed','creating')")
                .bind(safety).bind(workshop).bind(operation.id).execute(&mut *tx).await.map_err(|_|IntegrationError::Unavailable)?.rows_affected();
            if database_changed != 1 || safety_changed != 1 {
                return Err(IntegrationError::ContractDrift);
            }
        }
        LifecycleCommand::Duplicate {
            target_database: target,
            ..
        } => {
            let changed = sqlx::query("update control.odoo_databases set state='duplicating' where id=$1 and workshop_id=$2 and kind='duplicate' and routable=false and state in ('duplicating','failed')")
                .bind(target).bind(workshop)
                .execute(&mut *tx)
                .await
                .map_err(|_| IntegrationError::Unavailable)?.rows_affected();
            if changed != 1 {
                return Err(IntegrationError::ContractDrift);
            }
        }
    }
    tx.commit().await.map_err(|_| IntegrationError::Unavailable)
}

async fn finalize(
    tenant_store: &TenantStore,
    workshop: Uuid,
    operation: &LeasedOperation,
    command: LifecycleCommand,
    value: &Value,
    deployment_driver: &DeploymentDriverConfig,
) -> Result<(), IntegrationError> {
    match command {
        LifecycleCommand::Snapshot { database, recovery }
        | LifecycleCommand::Backup { database, recovery }
        | LifecycleCommand::Delete { database, recovery } => {
            let result = value
                .get("recovery_point")
                .ok_or(IntegrationError::ContractDrift)?;
            record_recovery_ready(tenant_store, workshop, operation.id, recovery, result).await?;
            let mut tx = tenant_store
                .begin(workshop)
                .await
                .map_err(|_| IntegrationError::Unavailable)?;
            let database_changed = sqlx::query(if matches!(command, LifecycleCommand::Delete { .. }) { "update control.odoo_databases set state='suspended' where id=$1 and workshop_id=$2 and state='snapshotting'" } else { "update control.odoo_databases set state='ready' where id=$1 and workshop_id=$2 and state='snapshotting'" })
                .bind(database).bind(workshop)
                .execute(&mut *tx)
                .await
                .map_err(|_| IntegrationError::Unavailable)?.rows_affected();
            if database_changed != 1 {
                return Err(IntegrationError::ContractDrift);
            }
            if matches!(command, LifecycleCommand::Delete { .. }) {
                let deletion_changed = sqlx::query("update control.workshop_deletions set state='retained',quarantined_at=now(),failure_class=null where workshop_id=$1 and operation_id=$2 and final_recovery_point_id=$3 and state='quarantining'")
                    .bind(workshop).bind(operation.id).bind(recovery).execute(&mut *tx).await.map_err(|_|IntegrationError::Unavailable)?.rows_affected();
                let workshop_changed = sqlx::query(
                    "update control.workshops set status='deleted',version=version+1 where id=$1",
                )
                .bind(workshop)
                .execute(&mut *tx)
                .await
                .map_err(|_| IntegrationError::Unavailable)?
                .rows_affected();
                if deletion_changed != 1 || workshop_changed != 1 {
                    return Err(IntegrationError::ContractDrift);
                }
                sqlx::query("update control.service_instances set health='suspended',safe_error_class=null,last_observed_at=now() where workshop_id=$1")
                    .bind(workshop).execute(&mut *tx).await.map_err(|_|IntegrationError::Unavailable)?;
                sqlx::query("update control.carrier_secrets set state='deleted',deleted_at=now(),cleanup_pending_ref=null,version=version+1 where workshop_id=$1 and state<>'deleted'")
                    .bind(workshop).execute(&mut *tx).await.map_err(|_|IntegrationError::Unavailable)?;
            }
            tx.commit()
                .await
                .map_err(|_| IntegrationError::Unavailable)?;
        }
        LifecycleCommand::Restore {
            database,
            source_recovery,
            safety_recovery: safety,
            replay_erasures,
        } => {
            let result = value
                .get("safety_recovery_point")
                .ok_or(IntegrationError::ContractDrift)?;
            record_recovery_ready(tenant_store, workshop, operation.id, safety, result).await?;
            if value.get("restore_status").and_then(Value::as_str) == Some("rolled_back") {
                return Err(IntegrationError::Rejected);
            }
            if replay_erasures {
                replay_restored_erasures(
                    tenant_store,
                    workshop,
                    source_recovery,
                    operation,
                    deployment_driver,
                )
                .await?;
            }
            let mut tx = tenant_store
                .begin(workshop)
                .await
                .map_err(|_| IntegrationError::Unavailable)?;
            let changed = sqlx::query("update control.odoo_databases set state='ready',last_restored_at=now() where id=$1 and workshop_id=$2 and state='restoring'")
                .bind(database).bind(workshop).execute(&mut *tx).await.map_err(|_|IntegrationError::Unavailable)?.rows_affected();
            if changed != 1 {
                return Err(IntegrationError::ContractDrift);
            }
            tx.commit()
                .await
                .map_err(|_| IntegrationError::Unavailable)?;
        }
        LifecycleCommand::Duplicate {
            target_database: target,
            ..
        } => {
            let mut tx = tenant_store
                .begin(workshop)
                .await
                .map_err(|_| IntegrationError::Unavailable)?;
            let changed = sqlx::query("update control.odoo_databases set state='ready' where id=$1 and workshop_id=$2 and kind='duplicate' and routable=false and state='duplicating'")
                .bind(target).bind(workshop).execute(&mut *tx).await.map_err(|_|IntegrationError::Unavailable)?.rows_affected();
            if changed != 1 {
                return Err(IntegrationError::ContractDrift);
            }
            tx.commit()
                .await
                .map_err(|_| IntegrationError::Unavailable)?;
        }
    }
    Ok(())
}

async fn replay_restored_erasures(
    tenant_store: &TenantStore,
    workshop: Uuid,
    source_recovery: Uuid,
    operation: &LeasedOperation,
    deployment_driver: &DeploymentDriverConfig,
) -> Result<(), IntegrationError> {
    let mut load_tx = tenant_store
        .begin(workshop)
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
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
         join control.workshop_recovery_points recovery on recovery.id=r.recovery_point_id
         join control.erasure_subject_lookups l on l.tombstone_id=t.id
         where r.operation_id=$1 and r.recovery_point_id=$2
           and t.workshop_id=$3 and recovery.workshop_id=$3
           and r.state<>'complete'
         order by t.sequence",
    )
    .bind(operation.id)
    .bind(source_recovery)
    .bind(workshop)
    .fetch_all(&mut *load_tx)
    .await
    .map_err(|_| IntegrationError::Unavailable)?;
    if rows.is_empty() {
        let complete = sqlx::query_scalar::<_, bool>(
            "select exists(
                select 1 from control.erasure_restore_replays r
                join control.erasure_tombstones t on t.id=r.tombstone_id
                join control.workshop_recovery_points recovery on recovery.id=r.recovery_point_id
                where r.operation_id=$1 and r.recovery_point_id=$2
                  and t.workshop_id=$3 and recovery.workshop_id=$3)
             and not exists(
                select 1 from control.erasure_restore_replays r
                join control.erasure_tombstones t on t.id=r.tombstone_id
                join control.workshop_recovery_points recovery on recovery.id=r.recovery_point_id
                where r.operation_id=$1 and r.recovery_point_id=$2
                  and t.workshop_id=$3 and recovery.workshop_id=$3 and r.state<>'complete')",
        )
        .bind(operation.id)
        .bind(source_recovery)
        .bind(workshop)
        .fetch_one(&mut *load_tx)
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
        load_tx
            .commit()
            .await
            .map_err(|_| IntegrationError::Unavailable)?;
        return if complete {
            Ok(())
        } else {
            Err(IntegrationError::ContractDrift)
        };
    }
    load_tx
        .commit()
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
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
            let mut applying_tx = tenant_store.begin(workshop).await.map_err(|_| IntegrationError::Unavailable)?;
            let applying_changed = sqlx::query(
                "update control.erasure_restore_replays replay
                    set state='applying',started_at=coalesce(started_at,now()),safe_error_class=null
                  where replay.id=$1 and replay.operation_id=$2 and replay.recovery_point_id=$3
                    and exists(select 1 from control.erasure_tombstones tombstone
                                where tombstone.id=replay.tombstone_id and tombstone.workshop_id=$4)
                    and exists(select 1 from control.workshop_recovery_points recovery
                                where recovery.id=replay.recovery_point_id and recovery.workshop_id=$4)",
            )
            .bind(replay_id).bind(operation.id).bind(source_recovery).bind(workshop)
            .execute(&mut *applying_tx).await.map_err(|_|IntegrationError::Unavailable)?.rows_affected();
            if applying_changed != 1 {
                return Err(IntegrationError::ContractDrift);
            }
            applying_tx.commit().await.map_err(|_| IntegrationError::Unavailable)?;
            for location in &required {
                if completed.contains(location) {
                    continue;
                }
                match location.as_str() {
                    "odoo" | "paperless" => {
                        driver_request_with_key(
                            operation,
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
                            deployment_driver,
                        )
                        .await?;
                    }
                    _ => return Err(IntegrationError::ContractDrift),
                }
                let mut completed_tx = tenant_store.begin(workshop).await.map_err(|_| IntegrationError::Unavailable)?;
                let completed_changed = sqlx::query(
                    "update control.erasure_restore_replays replay
                        set completed_locations=array_append(completed_locations,$2)
                      where replay.id=$1 and replay.operation_id=$3 and replay.recovery_point_id=$4
                        and not ($2=any(replay.completed_locations))
                        and exists(select 1 from control.erasure_tombstones tombstone
                                    where tombstone.id=replay.tombstone_id and tombstone.workshop_id=$5)
                        and exists(select 1 from control.workshop_recovery_points recovery
                                    where recovery.id=replay.recovery_point_id and recovery.workshop_id=$5)",
                )
                .bind(replay_id).bind(location).bind(operation.id).bind(source_recovery).bind(workshop)
                .execute(&mut *completed_tx).await.map_err(|_|IntegrationError::Unavailable)?.rows_affected();
                if completed_changed != 1 {
                    return Err(IntegrationError::UnknownOutcome);
                }
                completed_tx.commit().await.map_err(|_| IntegrationError::Unavailable)?;
            }
            let mut complete_tx = tenant_store.begin(workshop).await.map_err(|_| IntegrationError::Unavailable)?;
            let changed=sqlx::query(
                "update control.erasure_restore_replays replay
                    set state='complete',completed_at=now(),safe_error_class=null
                  where replay.id=$1 and replay.operation_id=$2 and replay.recovery_point_id=$3
                    and replay.completed_locations @> replay.required_locations
                    and exists(select 1 from control.erasure_tombstones tombstone
                                where tombstone.id=replay.tombstone_id and tombstone.workshop_id=$4)
                    and exists(select 1 from control.workshop_recovery_points recovery
                                where recovery.id=replay.recovery_point_id and recovery.workshop_id=$4)",
            )
                .bind(replay_id).bind(operation.id).bind(source_recovery).bind(workshop)
                .execute(&mut *complete_tx).await.map_err(|_|IntegrationError::Unavailable)?.rows_affected();
            if changed != 1 {
                return Err(IntegrationError::UnknownOutcome);
            }
            complete_tx.commit().await.map_err(|_| IntegrationError::Unavailable)?;
            Ok(())
        }
        .await;
        if let Err(error) = result {
            if let Ok(mut failed_tx) = tenant_store.begin(workshop).await {
                let _ = sqlx::query(
                    "update control.erasure_restore_replays replay set state='failed',safe_error_class=$2
                      where replay.id=$1 and replay.operation_id=$3 and replay.recovery_point_id=$4
                        and exists(select 1 from control.erasure_tombstones tombstone
                                    where tombstone.id=replay.tombstone_id and tombstone.workshop_id=$5)
                        and exists(select 1 from control.workshop_recovery_points recovery
                                    where recovery.id=replay.recovery_point_id and recovery.workshop_id=$5)",
                )
                    .bind(replay_id).bind(error.failure_class()).bind(operation.id).bind(source_recovery).bind(workshop)
                    .execute(&mut *failed_tx).await;
                let _ = failed_tx.commit().await;
            }
            return Err(error);
        }
    }
    Ok(())
}

async fn record_recovery_ready(
    tenant_store: &TenantStore,
    workshop: Uuid,
    operation: Uuid,
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
    let mut tx = tenant_store
        .begin(workshop)
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
    let changed=sqlx::query("update control.workshop_recovery_points set state='ready',storage_ref=$4,size_bytes=$5,ready_at=now(),verification_state='verified',verified_at=now(),manifest_digest=$6,format_version=$7,storage_location=$8,source_release=$9,paperless_version=$10,encryption_key_id=$11,object_prefix=$12,expires_at=case when kind='backup' then now()+make_interval(days=>$13) else expires_at end,archive_object_key=$14,archive_size_bytes=$15,archive_digest=$16 where id=$1 and workshop_id=$2 and operation_id=$3 and state='creating'")
        .bind(recovery).bind(workshop).bind(operation).bind(storage_ref).bind(size_bytes).bind(manifest_digest).bind(format_version).bind(storage_location).bind(source_release).bind(paperless_version).bind(encryption_key_id).bind(object_prefix).bind(i32::try_from(retention_days).map_err(|_|IntegrationError::ContractDrift)?).bind(archive_object_key).bind(archive_size_bytes).bind(archive_digest).execute(&mut *tx).await.map_err(|_|IntegrationError::Unavailable)?.rows_affected();
    if changed != 1 {
        return Err(IntegrationError::ContractDrift);
    }
    sqlx::query("delete from control.workshop_recovery_components component where component.recovery_point_id=$1 and exists(select 1 from control.workshop_recovery_points recovery where recovery.id=component.recovery_point_id and recovery.workshop_id=$2 and recovery.operation_id=$3)")
        .bind(recovery).bind(workshop).bind(operation)
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
        sqlx::query("insert into control.workshop_recovery_components(recovery_point_id,workshop_id,component,object_key,size_bytes,digest,plaintext_digest,state,verified_at) values($1,$2,$3,$4,$5,$6,$7,'verified',now())")
            .bind(recovery).bind(workshop).bind(name).bind(path).bind(bytes).bind(digest).bind(plaintext_digest).execute(&mut *tx).await.map_err(|_|IntegrationError::Unavailable)?;
    }
    tx.commit().await.map_err(|_| IntegrationError::Unavailable)
}

async fn mark_primary_resource_failed(
    tx: &mut WorkshopTransaction<'_>,
    operation: &LeasedOperation,
    command: LifecycleCommand,
) -> Result<(), sqlx::Error> {
    let workshop = tx.workshop_id();
    match command {
        LifecycleCommand::Snapshot { recovery, .. }
        | LifecycleCommand::Backup { recovery, .. }
        | LifecycleCommand::Delete { recovery, .. } => {
            sqlx::query("update control.workshop_recovery_points set state='failed',verification_state='failed' where id=$1 and workshop_id=$2 and operation_id=$3")
                .bind(recovery).bind(workshop).bind(operation.id).execute(&mut **tx).await?;
        }
        LifecycleCommand::Restore { database, .. } => {
            sqlx::query("update control.odoo_databases set state='failed' where id=$1 and workshop_id=$2 and state='restoring'")
                .bind(database).bind(workshop).execute(&mut **tx).await?;
        }
        LifecycleCommand::Duplicate {
            target_database: target,
            ..
        } => {
            sqlx::query("update control.odoo_databases set state='failed' where id=$1 and workshop_id=$2 and kind='duplicate' and routable=false")
                .bind(target).bind(workshop).execute(&mut **tx).await?;
        }
    }
    Ok(())
}

#[tracing::instrument(name = "lifecycle.failure_cleanup", skip_all, fields(operation = %operation.id))]
pub(crate) async fn failed(
    tenant_store: &TenantStore,
    workshop: Uuid,
    operation: &LeasedOperation,
) -> Result<(), IntegrationError> {
    let result = async {
        let command = LifecycleCommand::decode(operation)
            .map_err(|_| sqlx::Error::Protocol("invalid lifecycle command".into()))?;
        let mut tx = tenant_store.begin(workshop).await?;
        if !lock_current_operation_lease(&mut tx, operation).await? {
            return Err(sqlx::Error::Protocol(
                "lifecycle failure cleanup lease was lost".into(),
            ));
        }
        match command {
            LifecycleCommand::Snapshot { database, .. }
            | LifecycleCommand::Backup { database, .. }
            | LifecycleCommand::Delete { database, .. } => {
                sqlx::query(
                    "update control.odoo_databases set state='ready'
                      where id=$1 and workshop_id=$2 and state='snapshotting'",
                )
                .bind(database)
                .bind(workshop)
                .execute(&mut *tx)
                .await?;
            }
            LifecycleCommand::Restore {
                safety_recovery,
                ..
            } => {
                sqlx::query("update control.workshop_recovery_points set state='failed',verification_state='failed' where id=$1 and workshop_id=$2 and operation_id=$3 and state='creating'")
                    .bind(safety_recovery).bind(workshop).bind(operation.id)
                    .execute(&mut *tx).await?;
            }
            LifecycleCommand::Duplicate { .. } => {}
        }
        mark_primary_resource_failed(&mut tx, operation, command).await?;
        if matches!(command, LifecycleCommand::Delete { .. }) {
            sqlx::query("with failed as (update control.workshop_deletions set state='failed',failure_class='lifecycle_failed' where workshop_id=$1 and operation_id=$2 returning previous_status) update control.workshops set status=failed.previous_status from failed where id=$1")
                .bind(workshop).bind(operation.id).execute(&mut *tx).await?;
        }
        tx.commit().await
    }
    .await;
    if let Err(error) = result {
        tracing::error!(
            operation=%operation.id,
            error_class=crate::error_reporting::safe_error_class(&error),
            "could not apply lifecycle failure cleanup"
        );
        return Err(IntegrationError::Unavailable);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::Store;
    use wiremock::MockServer;

    #[test]
    fn maintenance_receipts_are_exactly_bound_to_the_effect_and_workshop() {
        let workshop = Uuid::new_v4();
        let effect = Uuid::new_v4();
        let digest = format!("sha256:{}", "a".repeat(64));
        let entry = json!({
            "outcome":"maintenance",
            "effect_run_id":effect,
            "route_fence_token":7,
            "route_evidence":{
                "effect_run_id":effect,
                "workshop_id":workshop,
                "generation":3,
                "projection_digest":digest,
                "disposition":"present",
                "rendered_digest":format!("sha256:{}", "b".repeat(64)),
                "route_fence_token":7,
                "mode":"maintenance",
            }
        });
        assert_eq!(
            confirm_maintenance_entry(&entry, workshop),
            Ok(MaintenanceEntry::Active(effect))
        );
        let mut stale = entry;
        stale["route_evidence"]["workshop_id"] = json!(Uuid::new_v4());
        assert_eq!(
            confirm_maintenance_entry(&stale, workshop),
            Err(IntegrationError::UnknownOutcome)
        );

        let exit = json!({
            "outcome":"restored",
            "effect_run_id":effect,
            "route_evidence":{
                "effect_run_id":effect,
                "workshop_id":workshop,
                "generation":4,
                "projection_digest":format!("sha256:{}", "c".repeat(64)),
                "disposition":"absent",
                "rendered_digest":format!("sha256:{}", "d".repeat(64)),
                "route_fence_token":7,
                "mode":"restored",
            }
        });
        assert_eq!(confirm_maintenance_exit(&exit, workshop, effect), Ok(()));
        assert_eq!(
            confirm_maintenance_entry(&exit, workshop),
            Ok(MaintenanceEntry::AlreadyRestored),
            "a crash after successful exit must replay as terminal success"
        );
    }

    fn leased_operation(id: Uuid, workshop: Uuid, payload: Value) -> LeasedOperation {
        LeasedOperation {
            id,
            kind: "tenant.lifecycle".into(),
            workshop_id: Some(workshop),
            target_user_id: None,
            desired_epoch: None,
            payload,
            attempt: 1,
            max_attempts: 1,
            leased_by: "lifecycle-scope-worker".into(),
            reconciling: false,
            trace_parent: None,
            trace_state: None,
        }
    }

    #[tokio::test]
    #[ignore = "requires a disposable CONTROL_TEST_DATABASE_URL"]
    async fn forged_cross_workshop_resources_do_not_transition_or_cleanup() {
        let url = std::env::var("CONTROL_TEST_DATABASE_URL")
            .expect("CONTROL_TEST_DATABASE_URL for disposable PostgreSQL");
        let store = Store::connect(&url).await.unwrap();
        store.migrate().await.unwrap();
        let first = Uuid::new_v4();
        let second = Uuid::new_v4();
        for (workshop, label) in [(first, "first"), (second, "second")] {
            sqlx::query("insert into control.workshops(id,slug,display_name,time_zone) values($1,$2,$3,'Europe/Paris')")
                .bind(workshop)
                .bind(format!("lifecycle-scope-{}", workshop.simple()))
                .bind(label)
                .execute(store.pool())
                .await
                .unwrap();
        }
        let user = Uuid::new_v4();
        sqlx::query("insert into control.users(id,email) values($1,$2)")
            .bind(user)
            .bind(format!("lifecycle-{}@example.test", user.simple()))
            .execute(store.pool())
            .await
            .unwrap();
        let operation_id = Uuid::new_v4();
        sqlx::query("insert into control.operations(id,kind,queue,workshop_id,payload,correlation_id,idempotency_key) values($1,'tenant.lifecycle','tenant-lifecycle',$2,'{}',$3,$4)")
            .bind(operation_id).bind(first).bind(Uuid::new_v4()).bind(format!("lifecycle-scope:{operation_id}")).execute(store.pool()).await.unwrap();
        let database = Uuid::new_v4();
        sqlx::query("insert into control.odoo_databases(id,workshop_id,kind,database_ref,public_hostname,label,state,routable) values($1,$2,'primary',$3,$4,'Primary','snapshotting',true)")
            .bind(database).bind(second).bind(crate::domain::opaque_database_ref(database)).bind(format!("{}.example.test", database.simple())).execute(store.pool()).await.unwrap();
        let recovery = Uuid::new_v4();
        sqlx::query("insert into control.workshop_recovery_points(id,workshop_id,database_id,operation_id,kind,label,state,requested_by) values($1,$2,$3,$4,'snapshot','Cross tenant recovery','creating',$5)")
            .bind(recovery).bind(second).bind(database).bind(operation_id).bind(user).execute(store.pool()).await.unwrap();
        let operation = leased_operation(
            operation_id,
            first,
            json!({"action":"snapshot","database_id":database,"recovery_point_id":recovery}),
        );
        let tenant_store = store.worker_tenant_scope();
        let driver = MockServer::start().await;
        let driver_config = DeploymentDriverConfig::for_test(&driver.uri());
        assert_eq!(
            run(&tenant_store, first, &operation, &driver_config,).await,
            Err(IntegrationError::ContractDrift)
        );
        assert!(
            driver.received_requests().await.unwrap().is_empty(),
            "forged lifecycle ownership must fail before driver I/O"
        );
        let progress: i16 =
            sqlx::query_scalar("select progress_percent from control.operations where id=$1")
                .bind(operation_id)
                .fetch_one(store.pool())
                .await
                .unwrap();
        assert_eq!(progress, 0, "forged ownership must not change progress");
        let mut tx = tenant_store.begin(first).await.unwrap();
        assert_eq!(
            validate_resource_ownership(
                &mut tx,
                &operation,
                LifecycleCommand::decode(&operation).unwrap(),
            )
            .await,
            Err(IntegrationError::ContractDrift)
        );
        tx.rollback().await.unwrap();

        let owned_database = Uuid::new_v4();
        sqlx::query("insert into control.odoo_databases(id,workshop_id,kind,database_ref,public_hostname,label,state,routable) values($1,$2,'primary',$3,$4,'Owned primary','ready',true)")
            .bind(owned_database).bind(first).bind(crate::domain::opaque_database_ref(owned_database)).bind(format!("{}.example.test", owned_database.simple())).execute(store.pool()).await.unwrap();
        let owned_recovery = Uuid::new_v4();
        sqlx::query("insert into control.workshop_recovery_points(id,workshop_id,database_id,operation_id,kind,label,state,requested_by) values($1,$2,$3,$4,'snapshot','Owned recovery','queued',$5)")
            .bind(owned_recovery).bind(first).bind(owned_database).bind(operation_id).bind(user).execute(store.pool()).await.unwrap();
        let owned = leased_operation(
            operation_id,
            first,
            json!({"action":"snapshot","database_id":owned_database,"recovery_point_id":owned_recovery}),
        );
        let mut tx = tenant_store.begin(first).await.unwrap();
        assert_eq!(
            validate_resource_ownership(
                &mut tx,
                &owned,
                LifecycleCommand::decode(&owned).unwrap(),
            )
            .await,
            Ok(())
        );
        tx.rollback().await.unwrap();

        sqlx::query(
            "update control.workshop_recovery_points set state='ready',ready_at=now() where id=$1",
        )
        .bind(owned_recovery)
        .execute(store.pool())
        .await
        .unwrap();
        sqlx::query("update control.operations set state='in_flight',leased_by='lifecycle-scope-worker',lease_expires_at=now()+interval '1 minute' where id=$1")
            .bind(operation_id)
            .execute(store.pool())
            .await
            .unwrap();
        assert_eq!(
            run(&tenant_store, first, &owned, &driver_config).await,
            Err(IntegrationError::ContractDrift),
            "a failed prepare compare-and-set must abort the whole scoped transaction"
        );
        assert!(driver.received_requests().await.unwrap().is_empty());
        let prepared_state = sqlx::query_as::<_, (String, i16)>(
            "select database.state,operation.progress_percent
               from control.odoo_databases database
               join control.operations operation on operation.id=$2
              where database.id=$1",
        )
        .bind(owned_database)
        .bind(operation_id)
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(
            prepared_state,
            ("ready".into(), 0),
            "database and progress changes must roll back together"
        );

        let source_recovery = Uuid::new_v4();
        sqlx::query("insert into control.workshop_recovery_points(id,workshop_id,database_id,kind,label,state,storage_ref,requested_by,ready_at,verification_state,verified_at) values($1,$2,$3,'backup','Cross tenant source','ready','test-storage',$4,now(),'verified',now())")
            .bind(source_recovery).bind(second).bind(database).bind(user).execute(store.pool()).await.unwrap();
        let restore_operation_id = Uuid::new_v4();
        sqlx::query("insert into control.operations(id,kind,queue,workshop_id,payload,correlation_id,idempotency_key) values($1,'tenant.lifecycle','tenant-lifecycle',$2,'{}',$3,$4)")
            .bind(restore_operation_id).bind(first).bind(Uuid::new_v4()).bind(format!("lifecycle-restore-scope:{restore_operation_id}")).execute(store.pool()).await.unwrap();
        let safety_recovery = Uuid::new_v4();
        sqlx::query("insert into control.workshop_recovery_points(id,workshop_id,database_id,operation_id,kind,label,state,requested_by) values($1,$2,$3,$4,'backup','Cross tenant safety','queued',$5)")
            .bind(safety_recovery).bind(second).bind(database).bind(restore_operation_id).bind(user).execute(store.pool()).await.unwrap();
        let restore = leased_operation(
            restore_operation_id,
            first,
            json!({"action":"restore","database_id":database,"recovery_point_id":source_recovery,"safety_recovery_point_id":safety_recovery}),
        );
        let mut tx = tenant_store.begin(first).await.unwrap();
        assert_eq!(
            validate_resource_ownership(
                &mut tx,
                &restore,
                LifecycleCommand::decode(&restore).unwrap(),
            )
            .await,
            Err(IntegrationError::ContractDrift)
        );
        tx.rollback().await.unwrap();

        let target = Uuid::new_v4();
        let target_ref = crate::domain::opaque_database_ref(target);
        sqlx::query("insert into control.odoo_databases(id,workshop_id,kind,database_ref,label,state,source_database_id,routable) values($1,$2,'duplicate',$3,'Cross tenant duplicate','duplicating',$4,false)")
            .bind(target).bind(second).bind(&target_ref).bind(database).execute(store.pool()).await.unwrap();
        let duplicate = leased_operation(
            operation_id,
            first,
            json!({"action":"duplicate","database_id":database,"target_database_id":target,"routable":false}),
        );
        let mut tx = tenant_store.begin(first).await.unwrap();
        assert_eq!(
            validate_resource_ownership(
                &mut tx,
                &duplicate,
                LifecycleCommand::decode(&duplicate).unwrap(),
            )
            .await,
            Err(IntegrationError::ContractDrift)
        );
        tx.rollback().await.unwrap();

        failed(&tenant_store, first, &operation).await.unwrap();
        let database_state: String =
            sqlx::query_scalar("select state from control.odoo_databases where id=$1")
                .bind(database)
                .fetch_one(store.pool())
                .await
                .unwrap();
        let recovery_state: String =
            sqlx::query_scalar("select state from control.workshop_recovery_points where id=$1")
                .bind(recovery)
                .fetch_one(store.pool())
                .await
                .unwrap();
        assert_eq!(database_state, "snapshotting");
        assert_eq!(recovery_state, "creating");
    }
}
