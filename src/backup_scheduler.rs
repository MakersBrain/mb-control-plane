use std::time::Duration;

use reqwest::header::{AUTHORIZATION, HeaderValue};
use serde_json::json;
use sqlx::PgPool;
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

use crate::backup_scheduler_config::BackupSchedulerConfig;
use crate::domain::OperationKind;
use crate::persistence::{NewOperation, Store, TenantStore};

#[derive(Clone, Copy, Debug)]
struct BackupCandidate {
    workshop: Uuid,
    database: Uuid,
    owner: Uuid,
}

#[derive(Clone, Copy, Debug)]
struct RehearsalClaim {
    rehearsal: Uuid,
    workshop: Uuid,
    recovery: Uuid,
    lease_token: Uuid,
    attempt: i32,
    max_attempts: i32,
}

/// Feature-owned scheduler service with an explicit fleet/tenant split.
///
/// The raw pool is private and is used only by the three reviewed, bounded fleet
/// discovery queries. Once discovery yields a workshop, every mutation moves
/// through the transaction-only tenant capability. No database transaction
/// spans a driver request.
pub struct BackupScheduler {
    fleet_discovery: PgPool,
    tenant_store: TenantStore,
    driver_client: reqwest::Client,
    driver_url: Url,
    driver_authorization: HeaderValue,
    scheduler_id: Uuid,
}

impl BackupScheduler {
    pub async fn connect(config: &BackupSchedulerConfig) -> anyhow::Result<Self> {
        let store = Store::connect(config.database_url()).await?;
        let fleet_discovery = store.pool().clone();
        let tenant_store = store.worker_tenant_scope();
        let driver_client = crate::deployment_driver_transport::client(
            Duration::from_secs(900),
            config.driver_socket(),
        )?;
        let mut driver_authorization =
            HeaderValue::from_str(&format!("Bearer {}", config.driver_token()))?;
        driver_authorization.set_sensitive(true);
        Ok(Self {
            fleet_discovery,
            tenant_store,
            driver_client,
            driver_url: config.driver_url().clone(),
            driver_authorization,
            scheduler_id: Uuid::new_v4(),
        })
    }

    #[tracing::instrument(name = "backup_scheduler.schedule", skip_all)]
    pub async fn schedule_due_backups(&self) -> anyhow::Result<usize> {
        let due = sqlx::query_as::<_, (Uuid, Uuid, Uuid)>(
            "select workshop_id,database_id,owner_user_id
               from control.discover_due_backup_memberships(100)",
        )
        .fetch_all(&self.fleet_discovery)
        .await?;
        tracing::info!(
            discovered = due.len(),
            "nightly backup candidates discovered"
        );
        let mut scheduled = 0;
        for (workshop, database, owner) in due {
            if self
                .admit_backup(BackupCandidate {
                    workshop,
                    database,
                    owner,
                })
                .await?
            {
                scheduled += 1;
            }
        }
        Ok(scheduled)
    }

    async fn admit_backup(&self, candidate: BackupCandidate) -> anyhow::Result<bool> {
        let BackupCandidate {
            workshop,
            database,
            owner,
        } = candidate;
        let mut tx = self.tenant_store.begin(workshop).await?;
        sqlx::query("select pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(workshop.to_string())
            .execute(&mut *tx)
            .await?;
        let resources_still_owned = sqlx::query_scalar::<_, bool>(
            "select exists(
                select 1 from control.odoo_databases database
                join control.memberships owner
                  on owner.workshop_id=database.workshop_id and owner.user_id=$3
                 and owner.role='owner' and owner.status='active'
               where database.id=$2 and database.workshop_id=$1
                 and database.kind='primary' and database.state='ready'
                 and database.deleted_at is null)",
        )
        .bind(workshop)
        .bind(database)
        .bind(owner)
        .fetch_one(&mut *tx)
        .await?;
        let lifecycle_active = sqlx::query_scalar::<_, bool>(
            "select exists(select 1 from control.operations where workshop_id=$1 and kind='tenant.lifecycle' and state in ('pending','in_flight','awaiting_reconciliation'))",
        )
        .bind(workshop)
        .fetch_one(&mut *tx)
        .await?;
        let backup_recent = sqlx::query_scalar::<_, bool>(
            "select exists(
                select 1 from control.workshop_recovery_points
                where workshop_id=$1 and kind='backup'
                  and created_at > now()-interval '24 hours'
                  and state in ('queued','creating','ready'))",
        )
        .bind(workshop)
        .fetch_one(&mut *tx)
        .await?;
        if !resources_still_owned || lifecycle_active || backup_recent {
            tx.rollback().await?;
            return Ok(false);
        }
        let documents = sqlx::query_scalar::<_, bool>(
            "select exists(select 1 from control.workshop_modules where workshop_id=$1 and module_key='documents' and state='enabled')",
        )
        .bind(workshop)
        .fetch_one(&mut *tx)
        .await?;
        let scope = if documents {
            vec!["odoo", "paperless"]
        } else {
            vec!["odoo"]
        };
        let recovery = Uuid::new_v4();
        let correlation = Uuid::new_v4();
        let date = OffsetDateTime::now_utc().date();
        let attempts = sqlx::query_scalar::<_, i64>(
            "select count(*) from control.workshop_recovery_points where workshop_id=$1 and kind='backup' and created_at::date=$2",
        )
        .bind(workshop)
        .bind(date)
        .fetch_one(&mut *tx)
        .await?;
        let key = if attempts == 0 {
            format!("nightly-backup:{workshop}:{date}")
        } else {
            format!("nightly-backup:{workshop}:{date}:retry-{}", attempts + 1)
        };
        let payload =
            json!({"action":"backup","database_id":database,"recovery_point_id":recovery});
        let operation = Store::enqueue(
            tx.as_transaction(),
            NewOperation {
                kind: OperationKind::TenantLifecycle,
                workshop_id: Some(workshop),
                target_user_id: None,
                desired_epoch: None,
                payload: &payload,
                requested_by: Some(owner),
                correlation_id: correlation,
                idempotency_key: &key,
            },
        )
        .await?;
        let inserted = sqlx::query("insert into control.workshop_recovery_points(id,workshop_id,database_id,operation_id,kind,label,requested_by,component_scope,format_version) values($1,$2,$3,$4,'backup','Nightly workshop backup',$5,$6,'mb-workshop-recovery-v2')")
            .bind(recovery).bind(workshop).bind(database).bind(operation).bind(owner).bind(&scope)
            .execute(&mut *tx).await?.rows_affected();
        if inserted != 1 {
            anyhow::bail!("nightly recovery admission lost its workshop transaction");
        }
        sqlx::query("insert into control.audit_events(id,actor_audit_subject_id,workshop_id,action,target_type,target_id,correlation_id,outcome,detail) values($1,null,$2,'database.backup.schedule','workshop_recovery_point',$3,$4,'accepted',$5)")
            .bind(Uuid::new_v4()).bind(workshop).bind(recovery.to_string()).bind(correlation)
            .bind(json!({"schedule":"nightly","requested_for_owner":owner})).execute(&mut *tx).await?;
        tx.commit().await?;
        tracing::info!(operation=%operation, "nightly workshop backup queued");
        Ok(true)
    }

    #[tracing::instrument(name = "backup_scheduler.rehearsals", skip_all)]
    pub async fn rehearse_due_recoveries(&self) -> anyhow::Result<usize> {
        let mut claims = Vec::new();
        let retries = sqlx::query_as::<_, (Uuid, Uuid, Uuid)>(
            "select h.id,h.workshop_id,h.recovery_point_id
             from control.workshop_recovery_rehearsals h
             join control.workshop_recovery_points r
               on r.id=h.recovery_point_id and r.workshop_id=h.workshop_id
             where ((h.state='failed' and h.next_attempt_at <= now())
                    or (h.state='running' and h.lease_expires_at <= now()))
               and h.attempt < h.max_attempts
               and r.state='ready' and r.verification_state='verified'
               and (r.expires_at is null or r.expires_at > now())
             order by h.finished_at limit 20",
        )
        .fetch_all(&self.fleet_discovery)
        .await?;
        tracing::info!(
            discovered = retries.len(),
            "recovery rehearsal retries discovered"
        );
        for (rehearsal, workshop, recovery) in retries {
            if let Some(claim) = self
                .claim_rehearsal_retry(RehearsalClaim {
                    rehearsal,
                    workshop,
                    recovery,
                    lease_token: Uuid::nil(),
                    attempt: 0,
                    max_attempts: 0,
                })
                .await?
            {
                claims.push(claim);
            }
        }
        let remaining = 20_i64.saturating_sub(i64::try_from(claims.len())?);
        let due = sqlx::query_as::<_, (Uuid, Uuid)>(
            "select distinct on (r.workshop_id) r.workshop_id,r.id
             from control.workshop_recovery_points r
             where r.kind='backup' and r.state='ready'
               and r.verification_state='verified' and r.storage_location='s3'
               and (r.expires_at is null or r.expires_at > now())
               and not exists (
                 select 1 from control.workshop_recovery_rehearsals h
                 where h.workshop_id=r.workshop_id
                   and ((h.state='succeeded' and h.started_at > now()-interval '30 days')
                     or (h.recovery_point_id=r.id and h.started_at > now()-interval '24 hours')))
             order by r.workshop_id,r.ready_at desc nulls last
             limit $1",
        )
        .bind(remaining)
        .fetch_all(&self.fleet_discovery)
        .await?;
        tracing::info!(discovered = due.len(), "new recovery rehearsals discovered");
        for (workshop, recovery) in due {
            if let Some(claim) = self.claim_new_rehearsal(workshop, recovery).await? {
                claims.push(claim);
            }
        }
        let mut completed = 0;
        for claim in claims {
            self.run_rehearsal(claim).await?;
            completed += 1;
        }
        Ok(completed)
    }

    async fn claim_rehearsal_retry(
        &self,
        claim: RehearsalClaim,
    ) -> anyhow::Result<Option<RehearsalClaim>> {
        let mut tx = self.tenant_store.begin(claim.workshop).await?;
        let lease_token = Uuid::new_v4();
        let claimed = sqlx::query_as::<_, (i32, i32)>(
            "update control.workshop_recovery_rehearsals rehearsal
                set state='running',started_at=now(),finished_at=null,safe_error=null,
                    next_attempt_at=null,attempt=attempt+1,lease_owner=$4,
                    lease_token=$5,lease_expires_at=now()+interval '20 minutes'
              where rehearsal.id=$1 and rehearsal.workshop_id=$2
                and rehearsal.recovery_point_id=$3
                and ((rehearsal.state='failed' and rehearsal.next_attempt_at<=now())
                     or (rehearsal.state='running' and rehearsal.lease_expires_at<=now()))
                and rehearsal.attempt < rehearsal.max_attempts
                and exists(select 1 from control.workshop_recovery_points recovery
                            where recovery.id=rehearsal.recovery_point_id
                              and recovery.workshop_id=rehearsal.workshop_id
                              and recovery.state='ready'
                              and recovery.verification_state='verified'
                              and (recovery.expires_at is null or recovery.expires_at>now()))
              returning rehearsal.attempt,rehearsal.max_attempts",
        )
        .bind(claim.rehearsal)
        .bind(claim.workshop)
        .bind(claim.recovery)
        .bind(self.scheduler_id)
        .bind(lease_token)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(claimed.map(|(attempt, max_attempts)| RehearsalClaim {
            lease_token,
            attempt,
            max_attempts,
            ..claim
        }))
    }

    async fn claim_new_rehearsal(
        &self,
        workshop: Uuid,
        recovery: Uuid,
    ) -> anyhow::Result<Option<RehearsalClaim>> {
        let mut tx = self.tenant_store.begin(workshop).await?;
        let rehearsal = Uuid::new_v4();
        let lease_token = Uuid::new_v4();
        let claimed = sqlx::query_as::<_, (i32, i32)>(
            "insert into control.workshop_recovery_rehearsals(
                 id,recovery_point_id,workshop_id,state,attempt,lease_owner,lease_token,lease_expires_at)
             select $1,recovery.id,recovery.workshop_id,'running',1,$4,$5,now()+interval '20 minutes'
               from control.workshop_recovery_points recovery
              where recovery.id=$2 and recovery.workshop_id=$3
                and recovery.kind='backup' and recovery.state='ready'
                and recovery.verification_state='verified' and recovery.storage_location='s3'
                and (recovery.expires_at is null or recovery.expires_at>now())
                and not exists(select 1 from control.workshop_recovery_rehearsals existing
                                where existing.workshop_id=$3 and existing.state='running')
             on conflict do nothing
             returning attempt,max_attempts",
        )
        .bind(rehearsal)
        .bind(recovery)
        .bind(workshop)
        .bind(self.scheduler_id)
        .bind(lease_token)
        .fetch_optional(&mut *tx)
        .await?
        ;
        tx.commit().await?;
        Ok(claimed.map(|(attempt, max_attempts)| RehearsalClaim {
            rehearsal,
            workshop,
            recovery,
            lease_token,
            attempt,
            max_attempts,
        }))
    }

    async fn run_rehearsal(&self, claim: RehearsalClaim) -> anyhow::Result<()> {
        let request = crate::deployment_driver_transport::traced(
            self.driver_client
                .post(
                    self.driver_url
                        .join(&format!("/v1/tenants/{}/rehearse", claim.workshop))?,
                )
                .header(AUTHORIZATION, self.driver_authorization.clone())
                .header("idempotency-key", format!("rehearsal:{}", claim.rehearsal))
                .json(&json!({"recovery_point_id":claim.recovery})),
        )
        .send()
        .await;
        let (state, safe_error, retryable) = match request {
            Ok(response) if response.status().is_success() => ("succeeded", None, false),
            Ok(response) => (
                "failed",
                Some("driver_rejected"),
                response.status().is_server_error()
                    || response.status() == reqwest::StatusCode::REQUEST_TIMEOUT
                    || response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS,
            ),
            Err(_) => ("failed", Some("driver_unavailable"), true),
        };
        let retry_delay_seconds = 60_i64 * (1_i64 << u32::try_from((claim.attempt - 1).min(6))?);
        let retry_at = retryable && claim.attempt < claim.max_attempts;
        let mut tx = self.tenant_store.begin(claim.workshop).await?;
        let changed = sqlx::query(
            "update control.workshop_recovery_rehearsals
                set state=$4,safe_error=$5,finished_at=now(),
                    next_attempt_at=case when $8 then now()+$9*interval '1 second' else null end,
                    lease_owner=null,lease_token=null,lease_expires_at=null
              where id=$1 and workshop_id=$2 and recovery_point_id=$3 and state='running'
                and lease_owner=$6 and lease_token=$7",
        )
        .bind(claim.rehearsal)
        .bind(claim.workshop)
        .bind(claim.recovery)
        .bind(state)
        .bind(safe_error)
        .bind(self.scheduler_id)
        .bind(claim.lease_token)
        .bind(retry_at)
        .bind(retry_delay_seconds)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if changed != 1 {
            anyhow::bail!("recovery rehearsal result lost its scoped claim");
        }
        sqlx::query("insert into control.audit_events(id,actor_audit_subject_id,workshop_id,action,target_type,target_id,correlation_id,outcome,detail) values($1,null,$2,'database.recovery.rehearse','workshop_recovery_point',$3,$4,$5,$6)")
            .bind(Uuid::new_v4()).bind(claim.workshop).bind(claim.recovery.to_string()).bind(claim.rehearsal)
            .bind(if state == "succeeded" { "succeeded" } else { "failed" })
            .bind(json!({"rehearsal_id":claim.rehearsal,"safe_error":safe_error,"attempt":claim.attempt,"retry_scheduled":retry_at})).execute(&mut *tx).await?;
        tx.commit().await?;
        tracing::info!(
            rehearsal_outcome = state,
            "monthly recovery rehearsal completed"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn scheduler_binary_is_thin_and_fleet_access_is_explicit() {
        let binary = include_str!("bin/control-backup-scheduler.rs");
        for forbidden in ["sqlx::", "PgPool", "Store::", "workshop_recovery_"] {
            assert!(
                !binary.contains(forbidden),
                "the scheduler binary regained persistence logic: {forbidden}"
            );
        }
        let implementation = include_str!("backup_scheduler.rs");
        let fleet_fetch = [".fetch_all(", "&self.fleet_discovery)"].concat();
        assert_eq!(
            implementation.matches(&fleet_fetch).count(),
            3,
            "fleet access must remain an explicit reviewed discovery surface"
        );
        assert!(implementation.matches("self.tenant_store.begin(").count() >= 4);
        assert!(implementation.contains("lease_token=$7"));
    }

    fn scheduler(store: &Store, driver_url: Url) -> BackupScheduler {
        BackupScheduler {
            fleet_discovery: store.pool().clone(),
            tenant_store: store.worker_tenant_scope(),
            driver_client: crate::deployment_driver_transport::client(Duration::from_secs(5), None)
                .unwrap(),
            driver_url,
            driver_authorization: HeaderValue::from_static("Bearer scheduler-test-token"),
            scheduler_id: Uuid::new_v4(),
        }
    }

    async fn ready_recovery(store: &Store) -> (Uuid, Uuid) {
        let user = Uuid::new_v4();
        let workshop = Uuid::new_v4();
        let database = Uuid::new_v4();
        let recovery = Uuid::new_v4();
        sqlx::query("insert into control.users(id,email) values($1,$2)")
            .bind(user)
            .bind(format!("{user}@example.test"))
            .execute(store.pool())
            .await
            .unwrap();
        sqlx::query("insert into control.workshops(id,slug,display_name,time_zone) values($1,$2,'Scheduler fixture','Europe/Paris')")
            .bind(workshop)
            .bind(format!("scheduler-{}", workshop.simple()))
            .execute(store.pool()).await.unwrap();
        sqlx::query("insert into control.odoo_databases(id,workshop_id,kind,database_ref,public_hostname,label,state,routable) values($1,$2,'primary',$3,$4,'Primary','ready',true)")
            .bind(database).bind(workshop).bind(format!("mb_{}",database.simple()))
            .bind(format!("{}.example.test",database.simple())).execute(store.pool()).await.unwrap();
        sqlx::query("insert into control.workshop_recovery_points(id,workshop_id,database_id,kind,label,requested_by,state,ready_at,storage_location,verification_state,verified_at) values($1,$2,$3,'backup','Scheduler fixture',$4,'ready',now(),'s3','verified',now())")
            .bind(recovery).bind(workshop).bind(database).bind(user).execute(store.pool()).await.unwrap();
        (workshop, recovery)
    }

    #[tokio::test]
    #[ignore = "requires a disposable CONTROL_TEST_DATABASE_URL"]
    async fn concurrent_schedulers_issue_one_scoped_rehearsal_and_atomic_audit() {
        let database_url =
            std::env::var("CONTROL_TEST_DATABASE_URL").expect("CONTROL_TEST_DATABASE_URL");
        let store = Store::connect(&database_url).await.unwrap();
        store.migrate().await.unwrap();
        let (workshop, recovery) = ready_recovery(&store).await;
        let driver = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(format!("/v1/tenants/{workshop}/rehearse")))
            .and(header("authorization", "Bearer scheduler-test-token"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&driver)
            .await;
        let first = scheduler(&store, Url::parse(&driver.uri()).unwrap());
        let second = scheduler(&store, Url::parse(&driver.uri()).unwrap());

        let (first_result, second_result) = tokio::join!(
            first.rehearse_due_recoveries(),
            second.rehearse_due_recoveries()
        );
        assert_eq!(first_result.unwrap() + second_result.unwrap(), 1);

        let result = sqlx::query_as::<_, (String, i32, bool, bool)>(
            "select state,attempt,lease_token is null,lease_expires_at is null
               from control.workshop_recovery_rehearsals
              where workshop_id=$1 and recovery_point_id=$2",
        )
        .bind(workshop)
        .bind(recovery)
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(result, ("succeeded".into(), 1, true, true));
        let audit_count = sqlx::query_scalar::<_, i64>(
            "select count(*) from control.audit_events
              where workshop_id=$1 and action='database.recovery.rehearse'
                and target_id=$2 and outcome='succeeded'",
        )
        .bind(workshop)
        .bind(recovery.to_string())
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(audit_count, 1);
        assert_eq!(first.rehearse_due_recoveries().await.unwrap(), 0);
    }
}
