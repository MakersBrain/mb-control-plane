use std::time::Duration;

use makersbrain_control_plane::domain::OperationKind;
use makersbrain_control_plane::persistence::{NewOperation, Store};
use serde_json::json;
use time::OffsetDateTime;
use uuid::Uuid;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let store = Store::connect(&makersbrain_control_plane::Config::database_url()?).await?;
    let interval = std::env::var("CONTROL_BACKUP_INTERVAL_SECONDS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value >= 60)
        .unwrap_or(3600);
    let enabled = std::env::var("CONTROL_BACKUP_SCHEDULER_ENABLED")
        .is_ok_and(|value| value.eq_ignore_ascii_case("true"));
    let driver_url = std::env::var("CONTROL_DEPLOYMENT_DRIVER_URL")?;
    let driver_token = std::env::var("CONTROL_DEPLOYMENT_DRIVER_TOKEN")?;
    let client = reqwest::Client::new();
    if !enabled {
        tracing::info!("nightly workshop backup scheduling is disabled");
    }
    loop {
        if enabled && let Err(error) = schedule_due_backups(&store).await {
            tracing::error!(error=%format_args!("{error:#}"), "nightly backup scheduling failed");
        }
        if enabled
            && let Err(error) = rehearse_due_recoveries(
                &store,
                &client,
                driver_url.trim_end_matches('/'),
                &driver_token,
            )
            .await
        {
            tracing::error!(error=%format_args!("{error:#}"), "monthly recovery rehearsal scheduling failed");
        }
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(interval)) => {},
            _ = makersbrain_control_plane::shutdown_signal() => break,
        }
    }
    Ok(())
}

async fn rehearse_due_recoveries(
    store: &Store,
    client: &reqwest::Client,
    driver_url: &str,
    driver_token: &str,
) -> anyhow::Result<()> {
    let retries = sqlx::query_as::<_, (Uuid, Uuid, Uuid)>(
        "select h.id,h.workshop_id,h.recovery_point_id
         from control.workshop_recovery_rehearsals h
         join control.workshop_recovery_points r on r.id=h.recovery_point_id
         where h.state='failed' and h.finished_at < now()-interval '1 minute'
           and h.safe_error in ('driver_rejected','driver_unavailable')
           and r.state='ready' and r.verification_state='verified'
           and (r.expires_at is null or r.expires_at > now())
         order by h.finished_at limit 20",
    )
    .fetch_all(store.pool())
    .await?;
    for (rehearsal, workshop, recovery) in retries {
        sqlx::query("update control.workshop_recovery_rehearsals set state='running',started_at=now(),finished_at=null,safe_error=null where id=$1 and state='failed'")
            .bind(rehearsal).execute(store.pool()).await?;
        run_rehearsal(
            store,
            client,
            driver_url,
            driver_token,
            rehearsal,
            workshop,
            recovery,
        )
        .await?;
    }
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
                 or h.started_at > now()-interval '24 hours')
           )
         order by r.workshop_id,r.ready_at desc nulls last",
    )
    .fetch_all(store.pool())
    .await?;
    for (workshop, recovery) in due {
        let rehearsal = Uuid::new_v4();
        sqlx::query("insert into control.workshop_recovery_rehearsals(id,recovery_point_id,workshop_id,state) values($1,$2,$3,'running')")
            .bind(rehearsal).bind(recovery).bind(workshop).execute(store.pool()).await?;
        run_rehearsal(
            store,
            client,
            driver_url,
            driver_token,
            rehearsal,
            workshop,
            recovery,
        )
        .await?;
    }
    Ok(())
}

async fn run_rehearsal(
    store: &Store,
    client: &reqwest::Client,
    driver_url: &str,
    driver_token: &str,
    rehearsal: Uuid,
    workshop: Uuid,
    recovery: Uuid,
) -> anyhow::Result<()> {
    let request = client
        .post(format!("{driver_url}/v1/tenants/{workshop}/rehearse"))
        .bearer_auth(driver_token)
        .header("idempotency-key", format!("rehearsal:{rehearsal}"))
        .json(&json!({"recovery_point_id":recovery}))
        .send()
        .await;
    let (state, safe_error) = match request {
        Ok(response) if response.status().is_success() => ("succeeded", None),
        Ok(response) => {
            tracing::error!(%workshop,%recovery,status=%response.status(),"recovery rehearsal failed");
            ("failed", Some("driver_rejected"))
        }
        Err(error) => {
            tracing::error!(%workshop,%recovery,error=%error,"recovery rehearsal unavailable");
            ("failed", Some("driver_unavailable"))
        }
    };
    sqlx::query("update control.workshop_recovery_rehearsals set state=$2,safe_error=$3,finished_at=now() where id=$1")
        .bind(rehearsal).bind(state).bind(safe_error).execute(store.pool()).await?;
    sqlx::query("insert into control.audit_events(id,actor_user_id,workshop_id,action,target_type,target_id,correlation_id,outcome,detail) values($1,null,$2,'database.recovery.rehearse','workshop_recovery_point',$3,$4,$5,$6)")
        .bind(Uuid::new_v4()).bind(workshop).bind(recovery.to_string()).bind(rehearsal)
        .bind(if state == "succeeded" { "succeeded" } else { "failed" })
        .bind(json!({"rehearsal_id":rehearsal,"safe_error":safe_error})).execute(store.pool()).await?;
    tracing::info!(%workshop,%recovery,%rehearsal,%state,"monthly recovery rehearsal completed");
    Ok(())
}

async fn schedule_due_backups(store: &Store) -> anyhow::Result<()> {
    let due = sqlx::query_as::<_, (Uuid, Uuid, Uuid)>(
        "select d.workshop_id,d.id,m.user_id
         from control.odoo_databases d
         join lateral (
             select user_id from control.memberships
             where workshop_id=d.workshop_id and role='owner'
             order by user_id limit 1
         ) m on true
         where d.kind='primary' and d.state='ready' and d.deleted_at is null
           and not exists (
             select 1 from control.workshop_recovery_points r
             where r.workshop_id=d.workshop_id and r.kind='backup'
               and r.created_at > now()-interval '24 hours'
               and r.state in ('queued','creating','ready')
           )",
    )
    .fetch_all(store.pool())
    .await?;
    for (workshop, database, owner) in due {
        let mut tx = store.begin().await?;
        sqlx::query("select pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(workshop.to_string())
            .execute(&mut *tx)
            .await?;
        let active = sqlx::query_scalar::<_, bool>(
            "select exists(select 1 from control.operations where workshop_id=$1 and kind='tenant.lifecycle' and state in ('pending','in_flight','awaiting_reconciliation'))",
        )
        .bind(workshop)
        .fetch_one(&mut *tx)
        .await?;
        if active {
            tx.rollback().await?;
            continue;
        }
        let still_due = !sqlx::query_scalar::<_, bool>(
            "select exists(
                select 1 from control.workshop_recovery_points
                where workshop_id=$1 and kind='backup'
                  and created_at > now()-interval '24 hours'
                  and state in ('queued','creating','ready')
            )",
        )
        .bind(workshop)
        .fetch_one(&mut *tx)
        .await?;
        if !still_due {
            tx.rollback().await?;
            continue;
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
            &mut tx,
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
        sqlx::query("insert into control.workshop_recovery_points(id,workshop_id,database_id,operation_id,kind,label,requested_by,component_scope,format_version) values($1,$2,$3,$4,'backup','Nightly workshop backup',$5,$6,'makersbrain-workshop-recovery-v2') on conflict(id) do nothing")
            .bind(recovery).bind(workshop).bind(database).bind(operation).bind(owner).bind(&scope).execute(&mut *tx).await?;
        sqlx::query("insert into control.audit_events(id,actor_user_id,workshop_id,action,target_type,target_id,correlation_id,outcome,detail) values($1,null,$2,'database.backup.schedule','workshop_recovery_point',$3,$4,'accepted',$5)")
            .bind(Uuid::new_v4()).bind(workshop).bind(recovery.to_string()).bind(correlation).bind(json!({"schedule":"nightly","requested_for_owner":owner})).execute(&mut *tx).await?;
        tx.commit().await?;
        tracing::info!(%workshop,%recovery,%operation,"nightly workshop backup queued");
    }
    Ok(())
}
