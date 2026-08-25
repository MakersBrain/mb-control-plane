use std::ops::{Deref, DerefMut};

use serde_json::Value;
use sqlx::postgres::{PgConnection, PgPoolOptions};
use sqlx::{PgPool, Postgres, Transaction};
use thiserror::Error;
use uuid::Uuid;

use crate::domain::{IntegrationError, OperationKind};

pub const EMBEDDED_SCHEMA_RELEASE: &str = "0051_webshop_domain_tenant_rls";

#[derive(Clone)]
pub struct Store {
    pool: PgPool,
}

/// Database access for work that has already been authorized for one workshop.
///
/// Unlike [`Store`], this type deliberately provides no access to its pool.
/// Callers must open a [`WorkshopTransaction`], which installs the workshop
/// identity as transaction-local PostgreSQL state before yielding an executor.
#[derive(Clone)]
pub struct TenantStore {
    pool: PgPool,
}

/// A transaction whose PostgreSQL tenant context is fixed to one workshop.
///
/// Dereferencing yields the transaction's connection so existing SQLx query
/// calls can use `&mut *transaction`. The underlying tenant pool is never
/// exposed, preventing statements from bypassing the transaction-local scope.
pub struct WorkshopTransaction<'a> {
    transaction: Transaction<'a, Postgres>,
    workshop_id: Uuid,
}

const SET_WORKSHOP_CONTEXT_SQL: &str = "select set_config('control.workshop_id',$1,true)";

pub struct NewOperation<'a> {
    pub kind: OperationKind,
    pub workshop_id: Option<Uuid>,
    pub target_user_id: Option<Uuid>,
    pub desired_epoch: Option<i32>,
    pub payload: &'a Value,
    pub requested_by: Option<Uuid>,
    pub correlation_id: Uuid,
    pub idempotency_key: &'a str,
}

#[derive(Debug)]
pub struct LeasedOperation {
    pub id: Uuid,
    pub kind: String,
    pub workshop_id: Option<Uuid>,
    pub target_user_id: Option<Uuid>,
    pub desired_epoch: Option<i32>,
    pub payload: Value,
    pub attempt: i32,
    pub max_attempts: i32,
    pub leased_by: String,
    pub reconciling: bool,
    pub trace_parent: Option<String>,
    pub trace_state: Option<String>,
}

pub enum OperationOutcome {
    Succeeded,
    Retry(IntegrationError),
    Failed(IntegrationError),
    Unknown,
}

#[derive(Debug, PartialEq, Eq)]
pub struct InitialReleaseActivation {
    pub slot: String,
    pub version: i64,
    pub replayed: bool,
}

#[derive(Debug, Error)]
pub enum InitialReleaseActivationError {
    #[error("{0}")]
    Conflict(&'static str),
    #[error(transparent)]
    Database(#[from] sqlx::Error),
}

pub async fn activate_initial_release(
    tx: &mut Transaction<'_, Postgres>,
    release_id: &str,
) -> Result<InitialReleaseActivation, InitialReleaseActivationError> {
    let release = sqlx::query_as::<_, (String, i64, i32, String, String, String)>(
        "select status,version,(manifest->>'capability_registry_version')::integer,
                odoo_subject_digest,extension_subject_digest,manifest_digest
         from control.application_releases where id=$1 for update",
    )
    .bind(release_id)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or(InitialReleaseActivationError::Conflict(
        "initial application release was not found",
    ))?;
    if release.0 == "active" {
        let active_slot = sqlx::query_as::<_, (String, String, String, String, Value)>(
            "select slot,odoo_subject_digest,extension_subject_digest,pair_qualification_digest,evidence from control.runtime_release_slots
             where runtime_key='shared-odoo' and release_id=$1 and state='active'
               and activated_at is not null",
        )
        .bind(release_id)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or(InitialReleaseActivationError::Conflict(
            "active initial release has no active runtime slot",
        ))?;
        validate_initial_slot_evidence(
            release_id,
            &release.3,
            &release.4,
            &release.5,
            &active_slot,
        )?;
        return Ok(InitialReleaseActivation {
            slot: active_slot.0,
            version: release.1,
            replayed: true,
        });
    }
    if release.0 != "prepared" {
        return Err(InitialReleaseActivationError::Conflict(
            "release preflight must be prepared before initial activation",
        ));
    }
    let empty_fleet = sqlx::query_as::<_, (bool, bool, bool, bool)>(
        "select
            not exists(select 1 from control.workshops),
            not exists(select 1 from control.odoo_databases),
            not exists(select 1 from control.tenant_release_adoptions),
            not exists(select 1 from control.application_releases where status='active')",
    )
    .fetch_one(&mut **tx)
    .await?;
    if !empty_fleet.0 || !empty_fleet.1 || !empty_fleet.2 || !empty_fleet.3 {
        return Err(InitialReleaseActivationError::Conflict(
            "initial release activation requires a completely empty fleet",
        ));
    }
    let active_registry = sqlx::query_scalar::<_, i32>(
        "select version from control.capability_registry_versions where active for share",
    )
    .fetch_optional(&mut **tx)
    .await?
    .ok_or(InitialReleaseActivationError::Conflict(
        "there is no active capability registry",
    ))?;
    if active_registry != release.2 {
        return Err(InitialReleaseActivationError::Conflict(
            "release capability registry does not match the active registry",
        ));
    }
    let prepared_slot = sqlx::query_as::<_, (String, String, String, String, Value)>(
        "select slot,odoo_subject_digest,extension_subject_digest,pair_qualification_digest,evidence from control.runtime_release_slots
         where runtime_key='shared-odoo' and release_id=$1 and state='prepared'
           and started_at is not null and verified_at is not null for update",
    )
    .bind(release_id)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or(InitialReleaseActivationError::Conflict(
        "initial release has no verified prepared runtime slot",
    ))?;
    validate_initial_slot_evidence(
        release_id,
        &release.3,
        &release.4,
        &release.5,
        &prepared_slot,
    )?;
    let slot_changed = sqlx::query(
        "update control.runtime_release_slots
         set state='active',activated_at=now(),version=version+1
         where runtime_key='shared-odoo' and slot=$1 and release_id=$2 and state='prepared'",
    )
    .bind(&prepared_slot.0)
    .bind(release_id)
    .execute(&mut **tx)
    .await?
    .rows_affected();
    let release_changed = sqlx::query(
        "update control.application_releases set status='active',version=version+1
         where id=$1 and status='prepared'",
    )
    .bind(release_id)
    .execute(&mut **tx)
    .await?
    .rows_affected();
    if slot_changed != 1 || release_changed != 1 {
        return Err(InitialReleaseActivationError::Conflict(
            "initial release activation lost its compare-and-set",
        ));
    }
    Ok(InitialReleaseActivation {
        slot: prepared_slot.0,
        version: release.1 + 1,
        replayed: false,
    })
}

fn validate_initial_slot_evidence(
    release_id: &str,
    odoo_subject_digest: &str,
    extension_subject_digest: &str,
    manifest_digest: &str,
    slot: &(String, String, String, String, Value),
) -> Result<(), InitialReleaseActivationError> {
    if slot.1 != odoo_subject_digest
        || slot.2 != extension_subject_digest
        || slot.4.get("release_id").and_then(Value::as_str) != Some(release_id)
        || slot.4.get("odoo_subject_digest").and_then(Value::as_str) != Some(odoo_subject_digest)
        || slot
            .4
            .get("extension_subject_digest")
            .and_then(Value::as_str)
            != Some(extension_subject_digest)
        || slot
            .4
            .get("pair_qualification_digest")
            .and_then(Value::as_str)
            != Some(slot.3.as_str())
        || slot.4.get("manifest_digest").and_then(Value::as_str) != Some(manifest_digest)
        || slot.4.get("provenance_verified").and_then(Value::as_bool) != Some(true)
        || slot
            .4
            .get("runtime_inspection_verified")
            .and_then(Value::as_bool)
            != Some(true)
    {
        return Err(InitialReleaseActivationError::Conflict(
            "prepared runtime slot is missing release-integrity evidence",
        ));
    }
    Ok(())
}

impl TenantStore {
    pub async fn connect(database_url: &str) -> anyhow::Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(12)
            .acquire_timeout(std::time::Duration::from_secs(5))
            .connect(database_url)
            .await?;
        Ok(Self { pool })
    }

    pub async fn begin(&self, workshop_id: Uuid) -> Result<WorkshopTransaction<'_>, sqlx::Error> {
        self.begin_with_isolation(workshop_id, false).await
    }

    /// Open a tenant-scoped transaction whose reads remain coherent while a
    /// projection is assembled from more than one query.
    pub async fn begin_repeatable_read(
        &self,
        workshop_id: Uuid,
    ) -> Result<WorkshopTransaction<'_>, sqlx::Error> {
        self.begin_with_isolation(workshop_id, true).await
    }

    async fn begin_with_isolation(
        &self,
        workshop_id: Uuid,
        repeatable_read: bool,
    ) -> Result<WorkshopTransaction<'_>, sqlx::Error> {
        let mut transaction = self.pool.begin().await?;
        if repeatable_read {
            sqlx::query("set transaction isolation level repeatable read")
                .execute(&mut *transaction)
                .await?;
        }
        let installed_context = sqlx::query_scalar::<_, String>(SET_WORKSHOP_CONTEXT_SQL)
            .bind(workshop_id.to_string())
            .fetch_one(&mut *transaction)
            .await?;
        debug_assert_eq!(installed_context, workshop_id.to_string());
        Ok(WorkshopTransaction {
            transaction,
            workshop_id,
        })
    }
}

impl<'a> WorkshopTransaction<'a> {
    pub fn workshop_id(&self) -> Uuid {
        self.workshop_id
    }

    /// Borrow the underlying transaction when calling an existing helper whose
    /// signature still names `Transaction<Postgres>` explicitly.
    pub fn as_transaction(&mut self) -> &mut Transaction<'a, Postgres> {
        &mut self.transaction
    }

    pub async fn commit(self) -> Result<(), sqlx::Error> {
        self.transaction.commit().await
    }

    pub async fn rollback(self) -> Result<(), sqlx::Error> {
        self.transaction.rollback().await
    }
}

impl<'a> AsMut<Transaction<'a, Postgres>> for WorkshopTransaction<'a> {
    fn as_mut(&mut self) -> &mut Transaction<'a, Postgres> {
        &mut self.transaction
    }
}

impl Deref for WorkshopTransaction<'_> {
    type Target = PgConnection;

    fn deref(&self) -> &Self::Target {
        &self.transaction
    }
}

impl DerefMut for WorkshopTransaction<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.transaction
    }
}

impl Store {
    /// Create the transaction-only capability used after a worker has leased a
    /// workshop operation. Both capabilities intentionally share the worker's
    /// queue-specific pool: PostgreSQL RLS still applies to the login, while
    /// the Rust type prevents tenant handlers from issuing unscoped SQL.
    pub fn worker_tenant_scope(&self) -> TenantStore {
        TenantStore {
            pool: self.pool.clone(),
        }
    }

    pub async fn start_worker(
        &self,
        worker_id: &str,
        queue: &str,
        release_id: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query("insert into control.worker_heartbeats(worker_id,queue,release_id) values($1,$2,$3) on conflict(worker_id) do update set queue=excluded.queue,release_id=excluded.release_id,started_at=now(),last_heartbeat_at=now(),active_operation_id=null,shutdown_at=null")
            .bind(worker_id).bind(queue).bind(release_id).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn heartbeat_worker(
        &self,
        worker_id: &str,
        active_operation_id: Option<Uuid>,
    ) -> Result<bool, sqlx::Error> {
        Ok(sqlx::query("update control.worker_heartbeats set last_heartbeat_at=now(),active_operation_id=$2 where worker_id=$1 and shutdown_at is null")
            .bind(worker_id).bind(active_operation_id).execute(&self.pool).await?.rows_affected()==1)
    }

    pub async fn shutdown_worker(&self, worker_id: &str) -> Result<(), sqlx::Error> {
        sqlx::query("update control.worker_heartbeats set last_heartbeat_at=now(),active_operation_id=null,shutdown_at=now() where worker_id=$1 and shutdown_at is null")
            .bind(worker_id).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn connect(database_url: &str) -> anyhow::Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(12)
            .acquire_timeout(std::time::Duration::from_secs(5))
            .connect(database_url)
            .await?;
        Ok(Self { pool })
    }

    pub async fn migrate(&self) -> anyhow::Result<()> {
        // SQLx owns the PostgreSQL advisory lock and migration ledger. Only the
        // one-shot control-migrate binary calls this method in deployed stacks.
        // Qualifying the ledger is essential: the database role and application
        // schema are both named `control`, while PostgreSQL's default search path
        // is "$user", public. An unqualified ledger would move schemas after the
        // first migration creates `control`.
        let mut migrator = sqlx::migrate!("./migrations");
        migrator.dangerous_set_table_name("public._sqlx_migrations");
        migrator.run(&self.pool).await?;
        self.sync_capability_registry().await?;
        Ok(())
    }

    async fn sync_capability_registry(&self) -> anyhow::Result<()> {
        let registry = crate::modules::embedded_registry()?;
        let digest = crate::modules::embedded_registry_digest();
        let mut tx = self.begin().await?;
        let stored = sqlx::query_scalar::<_, String>(
            "insert into control.capability_registry_versions(version,source_digest,active)
             values($1,$2,false) on conflict(version) do update set version=excluded.version
             returning source_digest",
        )
        .bind(i32::try_from(registry.version)?)
        .bind(&digest)
        .fetch_one(&mut *tx)
        .await?;
        if stored != digest {
            anyhow::bail!("capability registry version was reused with different content");
        }
        for entry in &registry.capabilities {
            let adapter = if !entry.odoo_modules.is_empty() {
                "odoo_modules"
            } else if entry.service.as_deref() == Some("paperless") {
                "paperless_service"
            } else {
                "broker_provider"
            };
            let changed = sqlx::query(
                "insert into control.capability_registry_entries(
                    registry_version,capability_key,dependencies,odoo_modules,service,
                    minimum_release,enforcement_adapter
                 ) values($1,$2,$3,$4,$5,$6,$7)
                 on conflict(registry_version,capability_key) do update set
                    capability_key=excluded.capability_key
                 where control.capability_registry_entries.dependencies=excluded.dependencies
                   and control.capability_registry_entries.odoo_modules=excluded.odoo_modules
                   and control.capability_registry_entries.service is not distinct from excluded.service
                   and control.capability_registry_entries.minimum_release=excluded.minimum_release
                   and control.capability_registry_entries.enforcement_adapter=excluded.enforcement_adapter",
            )
            .bind(i32::try_from(registry.version)?)
            .bind(&entry.key)
            .bind(&entry.dependencies)
            .bind(&entry.odoo_modules)
            .bind(&entry.service)
            .bind(&registry.minimum_application_release)
            .bind(adapter)
            .execute(&mut *tx)
            .await?
            .rows_affected();
            if changed != 1 {
                anyhow::bail!("capability registry entry was reused with different content");
            }
        }
        let count = sqlx::query_scalar::<_, i64>(
            "select count(*) from control.capability_registry_entries where registry_version=$1",
        )
        .bind(i32::try_from(registry.version)?)
        .fetch_one(&mut *tx)
        .await?;
        if usize::try_from(count).ok() != Some(registry.capabilities.len()) {
            anyhow::bail!(
                "capability registry database entries do not exactly match the release registry"
            );
        }
        sqlx::query("update control.capability_registry_versions set active=false where active and version<>$1")
            .bind(i32::try_from(registry.version)?)
            .execute(&mut *tx)
            .await?;
        sqlx::query("update control.capability_registry_versions set active=true where version=$1")
            .bind(i32::try_from(registry.version)?)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub async fn ready(&self) -> bool {
        sqlx::query_scalar::<_, i32>("select 1")
            .fetch_one(&self.pool)
            .await
            .is_ok()
    }

    pub async fn begin(&self) -> Result<Transaction<'_, Postgres>, sqlx::Error> {
        self.pool.begin().await
    }

    pub async fn enqueue(
        transaction: &mut PgConnection,
        operation: NewOperation<'_>,
    ) -> Result<Uuid, sqlx::Error> {
        let trace_context = crate::telemetry::current_trace_context();
        sqlx::query_scalar(
            "insert into control.operations (
                id, kind, queue, workshop_id, target_user_id, desired_epoch,
                payload, requested_by, correlation_id, idempotency_key,
                trace_parent,trace_state
             ) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
             on conflict (kind, requested_by, idempotency_key) do update
                set idempotency_key=excluded.idempotency_key
             where control.operations.workshop_id is not distinct from excluded.workshop_id
               and control.operations.target_user_id is not distinct from excluded.target_user_id
               and control.operations.desired_epoch is not distinct from excluded.desired_epoch
               and control.operations.payload=excluded.payload
             returning id",
        )
        .bind(Uuid::new_v4())
        .bind(operation.kind.as_str())
        .bind(operation.kind.queue())
        .bind(operation.workshop_id)
        .bind(operation.target_user_id)
        .bind(operation.desired_epoch)
        .bind(operation.payload)
        .bind(operation.requested_by)
        .bind(operation.correlation_id)
        .bind(operation.idempotency_key)
        .bind(trace_context.trace_parent)
        .bind(trace_context.trace_state)
        .fetch_one(&mut *transaction)
        .await
    }

    pub async fn operation_checkpoint(&self, operation_id: Uuid) -> anyhow::Result<Option<Value>> {
        Ok(
            sqlx::query_scalar("select checkpoint from control.operations where id=$1")
                .bind(operation_id)
                .fetch_optional(&self.pool)
                .await?
                .flatten(),
        )
    }

    pub async fn save_operation_checkpoint(
        &self,
        operation: &LeasedOperation,
        checkpoint: &Value,
    ) -> anyhow::Result<()> {
        let changed = sqlx::query(
            "update control.operations set checkpoint=$4
             where id=$1 and state='in_flight' and leased_by=$2 and attempt=$3
               and lease_expires_at>now() and checkpoint is null",
        )
        .bind(operation.id)
        .bind(&operation.leased_by)
        .bind(operation.attempt)
        .bind(checkpoint)
        .execute(&self.pool)
        .await?
        .rows_affected();
        if changed != 1 {
            anyhow::bail!("operation checkpoint could not be persisted");
        }
        Ok(())
    }

    pub async fn lease(
        &self,
        queue: &str,
        worker: &str,
    ) -> anyhow::Result<Option<LeasedOperation>> {
        let row = sqlx::query_as::<
            _,
            (
                Uuid,
                String,
                Option<Uuid>,
                Option<Uuid>,
                Option<i32>,
                Value,
                i32,
                i32,
                String,
                Option<String>,
                Option<String>,
            ),
        >(
            "update control.operations operation set
                state='in_flight', attempt=operation.attempt+1, leased_by=$2,
                lease_expires_at=now()+interval '60 seconds'
             from (
                select id, state previous_state from control.operations
                where queue=$1 and (
                    (state in ('pending','awaiting_reconciliation') and next_attempt_at<=now())
                    or (state='in_flight' and lease_expires_at<now())
                ) order by next_attempt_at,created_at for update skip locked limit 1
             ) candidate
             where operation.id=candidate.id
             returning operation.id,operation.kind,operation.workshop_id,
                operation.target_user_id,operation.desired_epoch,operation.payload,
                operation.attempt,operation.max_attempts,candidate.previous_state,
                operation.trace_parent,operation.trace_state",
        )
        .bind(queue)
        .bind(worker)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|row| LeasedOperation {
            id: row.0,
            kind: row.1,
            workshop_id: row.2,
            target_user_id: row.3,
            desired_epoch: row.4,
            payload: row.5,
            attempt: row.6,
            max_attempts: row.7,
            leased_by: worker.to_owned(),
            reconciling: matches!(row.8.as_str(), "in_flight" | "awaiting_reconciliation"),
            trace_parent: row.9,
            trace_state: row.10,
        }))
    }

    pub async fn finish(
        &self,
        operation: &LeasedOperation,
        outcome: OperationOutcome,
    ) -> anyhow::Result<()> {
        let (state, failure, delay, finished) = match outcome {
            OperationOutcome::Succeeded => ("succeeded", None, 0_i64, true),
            OperationOutcome::Unknown => (
                "awaiting_reconciliation",
                Some("unknown_outcome"),
                retry_delay(operation.attempt),
                false,
            ),
            OperationOutcome::Retry(error) if operation.attempt < operation.max_attempts => (
                "pending",
                Some(error.failure_class()),
                effective_retry_delay(operation.attempt, error),
                false,
            ),
            OperationOutcome::Retry(error) | OperationOutcome::Failed(error) => {
                ("dead_letter", Some(error.failure_class()), 0, true)
            }
        };
        let changed = sqlx::query(
            "update control.operations set state=$4,failure_class=$5,
                next_attempt_at=now()+make_interval(secs=>$6),
                leased_by=null,lease_expires_at=null,
                progress_percent=case when $4='succeeded' then 100 else progress_percent end,
                progress_phase=case when $4='succeeded' then 'complete' else progress_phase end,
                progress_message=case when $4='succeeded' then 'Complete' else progress_message end,
                progress_updated_at=now(),
                finished_at=case when $7 then now() else null end
             where id=$1 and leased_by=$2 and attempt=$3 and state='in_flight'
               and lease_expires_at>now()",
        )
        .bind(operation.id)
        .bind(&operation.leased_by)
        .bind(operation.attempt)
        .bind(state)
        .bind(failure)
        .bind(delay as f64)
        .bind(finished)
        .execute(&self.pool)
        .await?;
        if changed.rows_affected() != 1 {
            anyhow::bail!("operation lease was lost");
        }
        Ok(())
    }

    pub async fn renew_lease(
        &self,
        operation_id: Uuid,
        worker: &str,
        attempt: i32,
    ) -> anyhow::Result<bool> {
        let changed = sqlx::query(
            "update control.operations set lease_expires_at=now()+interval '60 seconds'
             where id=$1 and leased_by=$2 and attempt=$3 and state='in_flight'
               and lease_expires_at>now()",
        )
        .bind(operation_id)
        .bind(worker)
        .bind(attempt)
        .execute(&self.pool)
        .await?;
        Ok(changed.rows_affected() == 1)
    }
}

/// Lock and authenticate the exact unexpired durable-operation authority
/// before a terminal domain mutation is made in the same transaction.
pub(crate) async fn lock_current_operation_lease(
    transaction: &mut PgConnection,
    operation: &LeasedOperation,
) -> Result<bool, sqlx::Error> {
    Ok(sqlx::query_scalar::<_, Uuid>(
        "select id from control.operations
          where id=$1 and state='in_flight' and leased_by=$2 and attempt=$3
            and lease_expires_at>now()
          for update",
    )
    .bind(operation.id)
    .bind(&operation.leased_by)
    .bind(operation.attempt)
    .fetch_optional(transaction)
    .await?
    .is_some())
}

fn retry_delay(attempt: i32) -> i64 {
    let exponent = u32::try_from(attempt.saturating_sub(1)).unwrap_or(0).min(8);
    i64::from(5_u32.saturating_mul(2_u32.pow(exponent)).min(900))
}

fn effective_retry_delay(attempt: i32, error: IntegrationError) -> i64 {
    retry_delay(attempt).max(
        error
            .retry_after_seconds()
            .and_then(|value| i64::try_from(value).ok())
            .unwrap_or(0)
            .min(3600),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workshop_context_is_transaction_local() {
        assert_eq!(
            SET_WORKSHOP_CONTEXT_SQL,
            "select set_config('control.workshop_id',$1,true)"
        );
    }

    #[test]
    fn workshop_transaction_is_a_sqlx_connection_executor() {
        fn accepts_connection(_: &mut PgConnection) {}
        fn use_scoped_transaction(transaction: &mut WorkshopTransaction<'_>) {
            accepts_connection(&mut *transaction);
        }

        let _type_checked_executor: fn(&mut WorkshopTransaction<'_>) = use_scoped_transaction;
    }

    #[test]
    fn retry_delay_is_bounded() {
        assert_eq!(retry_delay(1), 5);
        assert_eq!(retry_delay(2), 10);
        assert_eq!(retry_delay(100), 900);
    }

    #[test]
    fn provider_retry_after_wins_but_is_bounded() {
        let rate_limited = |seconds| IntegrationError::RateLimited {
            retry_after_seconds: Some(seconds),
        };
        assert_eq!(effective_retry_delay(1, rate_limited(17)), 17);
        assert_eq!(effective_retry_delay(4, rate_limited(3)), 40);
        assert_eq!(effective_retry_delay(1, rate_limited(99_999)), 3600);
    }
}
