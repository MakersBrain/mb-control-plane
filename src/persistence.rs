use serde_json::Value;
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::domain::{IntegrationError, OperationKind};

pub const EMBEDDED_SCHEMA_RELEASE: &str = "0012_inventory_ai_usage";

#[derive(Clone)]
pub struct Store {
    pool: PgPool,
}

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
}

pub enum OperationOutcome {
    Succeeded,
    Retry(IntegrationError),
    Failed(IntegrationError),
    Unknown,
}

impl Store {
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
        transaction: &mut Transaction<'_, Postgres>,
        operation: NewOperation<'_>,
    ) -> Result<Uuid, sqlx::Error> {
        sqlx::query_scalar(
            "insert into control.operations (
                id, kind, queue, workshop_id, target_user_id, desired_epoch,
                payload, requested_by, correlation_id, idempotency_key
             ) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) returning id",
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
        .fetch_one(&mut **transaction)
        .await
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
                operation.attempt,operation.max_attempts,candidate.previous_state",
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
             where id=$1 and leased_by=$2 and attempt=$3 and state='in_flight'",
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
             where id=$1 and leased_by=$2 and attempt=$3 and state='in_flight'",
        )
        .bind(operation_id)
        .bind(worker)
        .bind(attempt)
        .execute(&self.pool)
        .await?;
        Ok(changed.rows_affected() == 1)
    }
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
