use mb_control_plane::persistence::Store;
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

async fn store() -> Store {
    let url = std::env::var("CONTROL_TEST_DATABASE_URL").expect("CONTROL_TEST_DATABASE_URL");
    let store = Store::connect(&url).await.expect("connect test PostgreSQL");
    store.migrate().await.expect("migrate test PostgreSQL");
    store
}

#[derive(Clone)]
struct StartupLease {
    run: Uuid,
    instance: Uuid,
    execution: Uuid,
    global_lease: Uuid,
    route_lease: Uuid,
    fence: i64,
    staging_selector: String,
}

async fn insert_absent_route_fleet(pool: &sqlx::PgPool, count: i64) -> Vec<Uuid> {
    let prefix = Uuid::new_v4().simple().to_string();
    let workshops: Vec<Uuid> = sqlx::query_scalar(
        "insert into control.workshops(id,slug,display_name,time_zone)
         select gen_random_uuid(),$1||'-'||ordinality,'Staged startup fixture','Europe/Paris'
           from generate_series(1,$2) ordinality returning id",
    )
    .bind(format!("staged-{prefix}"))
    .bind(count)
    .fetch_all(pool)
    .await
    .unwrap();
    sqlx::query(
        "insert into control.operations(
           id,kind,queue,workshop_id,payload,correlation_id,idempotency_key,
           state,attempt,leased_by,lease_expires_at
         ) select gen_random_uuid(),'webshop-domain.reconcile','tenant-reconciliation',id,
                  '{}',gen_random_uuid(),'staged-startup:'||id::text,
                  'in_flight',1,'staged-startup-fixture',now()+interval '20 minutes'
             from unnest($1::uuid[]) id",
    )
    .bind(&workshops)
    .execute(pool)
    .await
    .unwrap();
    let digest = format!("sha256:{}", "a".repeat(64));
    let projection = json!({
        "database_id": null,
        "database_ref": null,
        "public_hostname": null,
        "paperless_mode": "absent",
        "paperless_hostname": null,
        "custom_hostnames": []
    });
    sqlx::query(
        "insert into control.workshop_route_projections(
           workshop_id,generation,projection_digest,projection,disposition,
           source_operation_id,source_operation_attempt
         ) select workshop.id,1,$2,$3,'absent',operation.id,1
             from unnest($1::uuid[]) workshop(id)
             join control.operations operation
               on operation.workshop_id=workshop.id
              and operation.leased_by='staged-startup-fixture'",
    )
    .bind(&workshops)
    .bind(&digest)
    .bind(&projection)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "update control.workshop_route_projection_state state set
           desired_generation=1,desired_digest=$2,desired_disposition='absent',updated_at=now()
         from unnest($1::uuid[]) id where state.workshop_id=id",
    )
    .bind(&workshops)
    .bind(&digest)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "update control.operations set state='succeeded',leased_by=null,
            lease_expires_at=null,finished_at=now()
          where workshop_id=any($1) and leased_by='staged-startup-fixture'",
    )
    .bind(&workshops)
    .execute(pool)
    .await
    .unwrap();
    workshops
}

async fn admit(pool: &sqlx::PgPool) -> StartupLease {
    let boot = Uuid::new_v4();
    let instance = Uuid::new_v4();
    let execution = Uuid::new_v4();
    let global_lease = Uuid::new_v4();
    let route_lease = Uuid::new_v4();
    let row: (
        String,
        Option<Uuid>,
        Option<i64>,
        Option<i32>,
        Option<String>,
    ) = sqlx::query_as(
        "select outcome,effect_run_id,global_fence_token,reserved_count,staging_selector
           from control.admit_staged_startup_route_publication(
             $1,$2,$3,$4,$5,$6,$7,1200,1::smallint)",
    )
    .bind(boot)
    .bind(format!("staged-startup:{boot}"))
    .bind("b".repeat(64))
    .bind(instance)
    .bind(execution)
    .bind(global_lease)
    .bind(route_lease)
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(row.0, "acquired");
    assert!(row.3.unwrap() > 0);
    StartupLease {
        run: row.1.unwrap(),
        instance,
        execution,
        global_lease,
        route_lease,
        fence: row.2.unwrap(),
        staging_selector: row.4.unwrap(),
    }
}

async fn record_prior_and_begin(pool: &sqlx::PgPool, lease: &StartupLease) {
    let recorded: bool = sqlx::query_scalar(
        "select control.record_staged_startup_route_prior(
            $1,$2,$3,$4,$5,$6,'generations/boot-live',1,2,null,null)",
    )
    .bind(lease.run)
    .bind(lease.instance)
    .bind(lease.execution)
    .bind(lease.global_lease)
    .bind(lease.route_lease)
    .bind(lease.fence)
    .fetch_one(pool)
    .await
    .unwrap();
    assert!(recorded);
    let replayed: bool = sqlx::query_scalar(
        "select control.record_staged_startup_route_prior(
            $1,$2,$3,$4,$5,$6,'generations/other',3,4,null,null)",
    )
    .bind(lease.run)
    .bind(lease.instance)
    .bind(lease.execution)
    .bind(lease.global_lease)
    .bind(lease.route_lease)
    .bind(lease.fence)
    .fetch_one(pool)
    .await
    .unwrap();
    assert!(!replayed, "the prior selector is a one-shot fenced CAS");
    let began: bool = sqlx::query_scalar(
        "select control.begin_staged_startup_route_publication($1,$2,$3,$4,$5,$6)",
    )
    .bind(lease.run)
    .bind(lease.instance)
    .bind(lease.execution)
    .bind(lease.global_lease)
    .bind(lease.route_lease)
    .bind(lease.fence)
    .fetch_one(pool)
    .await
    .unwrap();
    assert!(began);
}

type BatchRow = (Uuid, i64, String, String, String, i64);

async fn read_batch(
    pool: &sqlx::PgPool,
    lease: &StartupLease,
    after: Option<Uuid>,
    limit: i32,
) -> Vec<BatchRow> {
    sqlx::query_as(
        "select workshop_id,generation,projection_digest,disposition,action,route_fence_token
           from control.read_staged_startup_route_batch($1,$2,$3,$4,$5,$6,$7,$8)",
    )
    .bind(lease.run)
    .bind(lease.instance)
    .bind(lease.execution)
    .bind(lease.global_lease)
    .bind(lease.route_lease)
    .bind(lease.fence)
    .bind(after)
    .bind(limit)
    .fetch_all(pool)
    .await
    .unwrap()
}

async fn record_candidate(
    pool: &sqlx::PgPool,
    lease: &StartupLease,
    after: Option<Uuid>,
    row: &BatchRow,
    fence: i64,
    forge_runtime_identity: bool,
) -> bool {
    let rendered = format!("sha256:{}", "c".repeat(64));
    let runtime = json!({
        "effect_run_id": lease.run,
        "workshop_id": row.0,
        "database_id": null,
        "database_ref": null,
        "unresolved_operation": false,
        "outcome": "absent",
        "odoo_runtime": if forge_runtime_identity { json!("forged") } else { json!(null) },
        "paperless_runtime": null,
        "verified_at": "2026-08-22T00:00:00Z"
    });
    let evidence = json!({
        "effect_run_id": lease.run,
        "workshop_id": row.0,
        "generation": row.1,
        "projection_digest": row.2,
        "disposition": row.3,
        "action": row.4,
        "route_fence_token": row.5,
        "rendered_digest": rendered,
        "runtime_evidence": runtime
    });
    sqlx::query_scalar(
        "select control.record_staged_startup_route_candidate(
          $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'absent',$14,$15,$16)",
    )
    .bind(lease.run)
    .bind(lease.instance)
    .bind(lease.execution)
    .bind(lease.global_lease)
    .bind(lease.route_lease)
    .bind(lease.fence)
    .bind(after)
    .bind(row.0)
    .bind(row.1)
    .bind(&row.2)
    .bind(&row.3)
    .bind(&row.4)
    .bind(fence)
    .bind(runtime)
    .bind(rendered)
    .bind(evidence)
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn sealed_digest(pool: &sqlx::PgPool, run: Uuid) -> String {
    let rows: Vec<(Uuid, i64, String, String, String, String)> = sqlx::query_as(
        "select workshop_id,generation,projection_digest,disposition,action,rendered_digest
           from control.workshop_route_startup_runtime_reservations
          where effect_run_id=$1 and candidate_recorded_at is not null
          order by workshop_id",
    )
    .bind(run)
    .fetch_all(pool)
    .await
    .unwrap();
    let mut hasher = Sha256::new();
    hasher.update(b"mb-startup-route-generation-v1\0");
    for (workshop, generation, projection, disposition, action, rendered) in rows {
        hasher.update(workshop.as_bytes());
        hasher.update(generation.to_be_bytes());
        for value in [projection, disposition, action, rendered] {
            hasher.update(u32::try_from(value.len()).unwrap().to_be_bytes());
            hasher.update(value.as_bytes());
        }
    }
    format!("sha256:{:x}", hasher.finalize())
}

#[tokio::test]
#[ignore = "requires a disposable PostgreSQL 17 CONTROL_TEST_DATABASE_URL"]
async fn staged_startup_publication_is_paged_cursor_fenced_and_observed() {
    let store = store().await;
    let workshops = insert_absent_route_fleet(store.pool(), 1001).await;
    let lease = admit(store.pool()).await;
    record_prior_and_begin(store.pool(), &lease).await;

    assert!(
        read_batch(store.pool(), &lease, None, 501).await.is_empty(),
        "the database enforces the 500-row memory boundary"
    );
    let mut after = None;
    let mut page_sizes = Vec::new();
    loop {
        let page = read_batch(store.pool(), &lease, after, 500).await;
        if page.is_empty() {
            break;
        }
        page_sizes.push(page.len());
        for row in &page {
            if after.is_none() {
                assert!(
                    !record_candidate(store.pool(), &lease, after, row, row.5 + 1, false).await,
                    "a stale route fence must be rejected"
                );
                assert!(
                    !record_candidate(store.pool(), &lease, after, row, row.5, true).await,
                    "runtime evidence must bind the frozen exact identity"
                );
            }
            assert!(record_candidate(store.pool(), &lease, after, row, row.5, false).await);
            after = Some(row.0);
        }
    }
    assert_eq!(page_sizes, vec![500, 500, 1]);
    assert_eq!(after, workshops.iter().max().copied());

    let set_digest = sealed_digest(store.pool(), lease.run).await;
    let sealed: bool = sqlx::query_scalar(
        "select control.seal_staged_startup_route_publication(
            $1,$2,$3,$4,$5,$6,1001,$7)",
    )
    .bind(lease.run)
    .bind(lease.instance)
    .bind(lease.execution)
    .bind(lease.global_lease)
    .bind(lease.route_lease)
    .bind(lease.fence)
    .bind(&set_digest)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert!(sealed);
    let started: bool = sqlx::query_scalar(
        "select control.start_staged_startup_route_publication($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(lease.run)
    .bind(lease.instance)
    .bind(lease.execution)
    .bind(lease.global_lease)
    .bind(lease.route_lease)
    .bind(lease.fence)
    .bind(&set_digest)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert!(started);
    let wrong_observation: bool = sqlx::query_scalar(
        "select control.observe_staged_startup_route_publication(
            $1,$2,$3,$4,$5,$6,$7,$1,$8)",
    )
    .bind(lease.run)
    .bind(lease.instance)
    .bind(lease.execution)
    .bind(lease.global_lease)
    .bind(lease.route_lease)
    .bind(lease.fence)
    .bind("generations/not-the-candidate")
    .bind(&set_digest)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert!(!wrong_observation);
    let observed: bool = sqlx::query_scalar(
        "select control.observe_staged_startup_route_publication(
            $1,$2,$3,$4,$5,$6,$7,$1,$8)",
    )
    .bind(lease.run)
    .bind(lease.instance)
    .bind(lease.execution)
    .bind(lease.global_lease)
    .bind(lease.route_lease)
    .bind(lease.fence)
    .bind(&lease.staging_selector)
    .bind(&set_digest)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert!(observed);
    let response = json!({
        "effect_run_id": lease.run,
        "global_fence_token": lease.fence,
        "workshop_count": 1001,
        "projection_set_digest": set_digest,
        "gateway_reload_digest": format!("sha256:{}", "e".repeat(64))
    });
    let finished: bool = sqlx::query_scalar(
        "select control.finish_staged_startup_route_publication(
            $1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(lease.run)
    .bind(lease.instance)
    .bind(lease.execution)
    .bind(lease.global_lease)
    .bind(lease.route_lease)
    .bind(lease.fence)
    .bind(response)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert!(finished);
    let applied: i64 = sqlx::query_scalar(
        "select count(*) from control.workshop_route_projection_state
          where applied_effect_run_id=$1 and applied_generation=1",
    )
    .bind(lease.run)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(applied, 1001);
}

#[tokio::test]
#[ignore = "requires a disposable PostgreSQL 17 CONTROL_TEST_DATABASE_URL"]
async fn seal_rejects_post_admission_workshops_and_expiry_reconciles_prior() {
    let store = store().await;
    insert_absent_route_fleet(store.pool(), 1).await;
    let lease = admit(store.pool()).await;
    record_prior_and_begin(store.pool(), &lease).await;
    let page = read_batch(store.pool(), &lease, None, 500).await;
    assert_eq!(page.len(), 1);
    assert!(record_candidate(store.pool(), &lease, None, &page[0], page[0].5, false).await);

    let late = Uuid::new_v4();
    sqlx::query(
        "insert into control.workshops(id,slug,display_name,time_zone)
         values($1,$2,'Late startup workshop','Europe/Paris')",
    )
    .bind(late)
    .bind(format!("late-{}", late.simple()))
    .execute(store.pool())
    .await
    .unwrap();
    let set_digest = sealed_digest(store.pool(), lease.run).await;
    let sealed: bool = sqlx::query_scalar(
        "select control.seal_staged_startup_route_publication(
            $1,$2,$3,$4,$5,$6,1,$7)",
    )
    .bind(lease.run)
    .bind(lease.instance)
    .bind(lease.execution)
    .bind(lease.global_lease)
    .bind(lease.route_lease)
    .bind(lease.fence)
    .bind(&set_digest)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert!(
        !sealed,
        "the seal must cover the complete current route fleet"
    );

    sqlx::query(
        "update control.workshop_route_effect_runs
            set lease_expires_at=now()-interval '1 second' where id=$1",
    )
    .bind(lease.run)
    .execute(store.pool())
    .await
    .unwrap();
    sqlx::query(
        "update control.deployment_driver_resource_leases
            set lease_expires_at=now()-interval '1 second'
          where resource_key='runtime/shared-odoo'",
    )
    .execute(store.pool())
    .await
    .unwrap();
    sqlx::query(
        "update control.workshop_route_application_leases
            set lease_expires_at=now()-interval '1 second' where effect_run_id=$1",
    )
    .bind(lease.run)
    .execute(store.pool())
    .await
    .unwrap();
    let reconciliation_owner = Uuid::new_v4();
    let reconciliation_token = Uuid::new_v4();
    let claim: (String, Option<Uuid>, Option<String>) = sqlx::query_as(
        "select outcome,effect_run_id,interrupted_phase
           from control.claim_interrupted_startup_route_publication($1,$2,300)",
    )
    .bind(reconciliation_owner)
    .bind(reconciliation_token)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(
        claim,
        ("acquired".into(), Some(lease.run), Some("staging".into()))
    );
    let wrong: bool = sqlx::query_scalar(
        "select control.finish_interrupted_startup_route_publication(
            $1,$2,$3,'prior','generations/wrong',1,2,null,null,null)",
    )
    .bind(lease.run)
    .bind(reconciliation_owner)
    .bind(reconciliation_token)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert!(!wrong);
    let restored: bool = sqlx::query_scalar(
        "select control.finish_interrupted_startup_route_publication(
            $1,$2,$3,'prior','generations/boot-live',1,2,null,null,null)",
    )
    .bind(lease.run)
    .bind(reconciliation_owner)
    .bind(reconciliation_token)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert!(restored);
    let states: (String, String) = sqlx::query_as(
        "select run.state,lease.state from control.workshop_route_effect_runs run
         join control.deployment_driver_resource_leases lease
           on lease.resource_key='runtime/shared-odoo' where run.id=$1",
    )
    .bind(lease.run)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(states, ("cancelled".into(), "idle".into()));
}

#[tokio::test]
#[ignore = "requires a disposable PostgreSQL 17 CONTROL_TEST_DATABASE_URL"]
async fn admitted_but_unstarted_publication_reconciles_without_filesystem_evidence() {
    let store = store().await;
    insert_absent_route_fleet(store.pool(), 1).await;
    let lease = admit(store.pool()).await;
    sqlx::query(
        "update control.workshop_route_effect_runs
            set lease_expires_at=now()-interval '1 second' where id=$1",
    )
    .bind(lease.run)
    .execute(store.pool())
    .await
    .unwrap();
    sqlx::query(
        "update control.deployment_driver_resource_leases
            set lease_expires_at=now()-interval '1 second'
          where resource_key='runtime/shared-odoo'",
    )
    .execute(store.pool())
    .await
    .unwrap();
    sqlx::query(
        "update control.workshop_route_application_leases
            set lease_expires_at=now()-interval '1 second' where effect_run_id=$1",
    )
    .bind(lease.run)
    .execute(store.pool())
    .await
    .unwrap();
    let owner = Uuid::new_v4();
    let token = Uuid::new_v4();
    let claim: (String, Option<Uuid>, Option<String>, Option<String>) = sqlx::query_as(
        "select outcome,effect_run_id,interrupted_phase,prior_selector
           from control.claim_interrupted_startup_route_publication($1,$2,300)",
    )
    .bind(owner)
    .bind(token)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(
        claim,
        (
            "acquired".into(),
            Some(lease.run),
            Some("staging".into()),
            None
        )
    );
    let forged: bool = sqlx::query_scalar(
        "select control.finish_interrupted_startup_route_publication(
            $1,$2,$3,'unstarted','generations/boot-live',1,2,null,null,null)",
    )
    .bind(lease.run)
    .bind(owner)
    .bind(token)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert!(
        !forged,
        "unstarted recovery must reject manufactured observations"
    );
    let resolved: bool = sqlx::query_scalar(
        "select control.finish_interrupted_startup_route_publication(
            $1,$2,$3,'unstarted',null,null,null,null,null,null)",
    )
    .bind(lease.run)
    .bind(owner)
    .bind(token)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert!(resolved);
    let states: (String, String, String) = sqlx::query_as(
        "select run.state,reservation.state,lease.state
           from control.workshop_route_effect_runs run
           join control.workshop_route_effect_reservations reservation
             on reservation.effect_run_id=run.id
           join control.deployment_driver_resource_leases lease
             on lease.resource_key='runtime/shared-odoo'
          where run.id=$1",
    )
    .bind(lease.run)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(
        states,
        ("cancelled".into(), "restored".into(), "idle".into())
    );
}

#[tokio::test]
#[ignore = "requires a disposable PostgreSQL 17 CONTROL_TEST_DATABASE_URL"]
async fn interrupted_loaded_candidate_reconciles_forward_without_replay() {
    let store = store().await;
    insert_absent_route_fleet(store.pool(), 1).await;
    let lease = admit(store.pool()).await;
    record_prior_and_begin(store.pool(), &lease).await;
    let page = read_batch(store.pool(), &lease, None, 500).await;
    assert_eq!(page.len(), 1);
    assert!(record_candidate(store.pool(), &lease, None, &page[0], page[0].5, false).await);
    let digest = sealed_digest(store.pool(), lease.run).await;
    let sealed: bool = sqlx::query_scalar(
        "select control.seal_staged_startup_route_publication(
            $1,$2,$3,$4,$5,$6,1,$7)",
    )
    .bind(lease.run)
    .bind(lease.instance)
    .bind(lease.execution)
    .bind(lease.global_lease)
    .bind(lease.route_lease)
    .bind(lease.fence)
    .bind(&digest)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert!(sealed);
    let started: bool = sqlx::query_scalar(
        "select control.start_staged_startup_route_publication($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(lease.run)
    .bind(lease.instance)
    .bind(lease.execution)
    .bind(lease.global_lease)
    .bind(lease.route_lease)
    .bind(lease.fence)
    .bind(&digest)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert!(started);
    sqlx::query(
        "update control.workshop_route_effect_runs
            set lease_expires_at=now()-interval '1 second' where id=$1",
    )
    .bind(lease.run)
    .execute(store.pool())
    .await
    .unwrap();
    sqlx::query(
        "update control.workshop_route_application_leases
            set lease_expires_at=now()-interval '1 second' where effect_run_id=$1",
    )
    .bind(lease.run)
    .execute(store.pool())
    .await
    .unwrap();
    sqlx::query(
        "update control.deployment_driver_resource_leases
            set lease_expires_at=now()-interval '1 second'
          where resource_key='runtime/shared-odoo'",
    )
    .execute(store.pool())
    .await
    .unwrap();
    let owner = Uuid::new_v4();
    let token = Uuid::new_v4();
    let claim: (
        String,
        Option<Uuid>,
        Option<String>,
        Option<i32>,
        Option<i32>,
    ) = sqlx::query_as(
        "select outcome,effect_run_id,interrupted_phase,sealed_count,sealed_present_count
               from control.claim_interrupted_startup_route_publication($1,$2,300)",
    )
    .bind(owner)
    .bind(token)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(
        claim,
        (
            "acquired".into(),
            Some(lease.run),
            Some("publication_started".into()),
            Some(1),
            Some(0)
        )
    );
    let inconclusive: bool = sqlx::query_scalar(
        "select control.finish_interrupted_startup_route_publication(
            $1,$2,$3,'inconclusive',null,null,null,null,null,null)",
    )
    .bind(lease.run)
    .bind(owner)
    .bind(token)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert!(inconclusive);
    let owner = Uuid::new_v4();
    let token = Uuid::new_v4();
    let reclaimed: String = sqlx::query_scalar(
        "select outcome
           from control.claim_interrupted_startup_route_publication($1,$2,300)",
    )
    .bind(owner)
    .bind(token)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(reclaimed, "acquired");
    let response = json!({
        "effect_run_id": lease.run,
        "global_fence_token": lease.fence,
        "workshop_count": 1,
        "projection_set_digest": digest,
        "gateway_reload_digest": format!("sha256:{}", "f".repeat(64))
    });
    let reconciled: bool = sqlx::query_scalar(
        "select control.finish_interrupted_startup_route_publication(
            $1,$2,$3,'candidate',$4,11,12,$1,$5,$6)",
    )
    .bind(lease.run)
    .bind(owner)
    .bind(token)
    .bind(&lease.staging_selector)
    .bind(&digest)
    .bind(response)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert!(reconciled);
    let states: (String, String, String, bool) = sqlx::query_as(
        "select run.state,reservation.state,lease.state,
                projection_state.applied_effect_run_id=$1
           from control.workshop_route_effect_runs run
           join control.workshop_route_effect_reservations reservation
             on reservation.effect_run_id=run.id
           join control.workshop_route_projection_state projection_state
             on projection_state.workshop_id=reservation.workshop_id
           join control.deployment_driver_resource_leases lease
             on lease.resource_key='runtime/shared-odoo'
          where run.id=$1",
    )
    .bind(lease.run)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(
        states,
        ("succeeded".into(), "succeeded".into(), "idle".into(), true)
    );
}

#[tokio::test]
#[ignore = "requires PostgreSQL 17 and the control_driver_ledger role"]
async fn startup_publication_ledgers_are_function_only() {
    let store = store().await;
    let mut publication = store.pool().begin().await.unwrap();
    sqlx::query("set local role control_driver_ledger")
        .execute(&mut *publication)
        .await
        .unwrap();
    let denied = sqlx::query("delete from control.workshop_route_startup_publications")
        .execute(&mut *publication)
        .await
        .unwrap_err();
    assert_eq!(
        denied
            .as_database_error()
            .and_then(|error| error.code())
            .as_deref(),
        Some("42501")
    );
    publication.rollback().await.unwrap();

    let mut runtime = store.pool().begin().await.unwrap();
    sqlx::query("set local role control_driver_ledger")
        .execute(&mut *runtime)
        .await
        .unwrap();
    let denied = sqlx::query("delete from control.workshop_route_startup_runtime_reservations")
        .execute(&mut *runtime)
        .await
        .unwrap_err();
    assert_eq!(
        denied
            .as_database_error()
            .and_then(|error| error.code())
            .as_deref(),
        Some("42501")
    );
    runtime.rollback().await.unwrap();
}
