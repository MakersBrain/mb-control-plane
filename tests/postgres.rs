use makersbrain_control_plane::domain::OperationKind;
use makersbrain_control_plane::persistence::{NewOperation, Store};
use serde_json::json;
use uuid::Uuid;

async fn store() -> Store {
    let url = std::env::var("CONTROL_TEST_DATABASE_URL").expect("CONTROL_TEST_DATABASE_URL");
    let store = Store::connect(&url).await.expect("connect test PostgreSQL");
    store.migrate().await.expect("migrate test PostgreSQL");
    store
}

#[tokio::test]
#[ignore = "requires a disposable CONTROL_TEST_DATABASE_URL"]
async fn database_enforces_last_owner_and_non_owner_invitations() {
    let store = store().await;
    let user = Uuid::new_v4();
    let workshop = Uuid::new_v4();
    let mut tx = store.begin().await.unwrap();
    sqlx::query("insert into control.users(id,email) values($1,$2)")
        .bind(user)
        .bind(format!("{user}@example.test"))
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("insert into control.workshops(id,slug,display_name,time_zone) values($1,$2,'Fixture','Europe/Paris')")
        .bind(workshop).bind(format!("fixture-{}",workshop.simple())).execute(&mut *tx).await.unwrap();
    sqlx::query("insert into control.memberships(workshop_id,user_id,role) values($1,$2,'owner')")
        .bind(workshop)
        .bind(user)
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();

    let mut tx = store.begin().await.unwrap();
    sqlx::query(
        "update control.memberships set role='artisan' where workshop_id=$1 and user_id=$2",
    )
    .bind(workshop)
    .bind(user)
    .execute(&mut *tx)
    .await
    .unwrap();
    assert!(
        tx.commit().await.is_err(),
        "last owner change must fail at commit"
    );

    let result = sqlx::query("insert into control.invitations(id,workshop_id,email,role,token_hash,invited_by,idempotency_key,expires_at) values($1,$2,'invitee@example.test','owner',$3,$4,'fixture',now()+interval '1 day')")
        .bind(Uuid::new_v4()).bind(workshop).bind(vec![0_u8;32]).bind(user).execute(store.pool()).await;
    assert!(result.is_err(), "owner must never be an invitation role");

    let database = Uuid::new_v4();
    let opaque_ref = format!("mb_{}", database.simple());
    sqlx::query("insert into control.odoo_databases(id,workshop_id,kind,database_ref,public_hostname,label,routable) values($1,$2,'primary',$3,$4,'Primary',true)")
        .bind(database).bind(workshop).bind(&opaque_ref).bind(format!("fixture-{}.dev1.makersbrain.net",workshop.simple())).execute(store.pool()).await.unwrap();
    assert_ne!(
        opaque_ref,
        format!("fixture-{}.dev1.makersbrain.net", workshop.simple()),
        "database identity must not be derived from its public hostname"
    );

    let invalid = sqlx::query("insert into control.odoo_databases(id,workshop_id,kind,database_ref,label,source_database_id,routable) values($1,$2,'duplicate','fixture-host','Invalid',$3,false)")
        .bind(Uuid::new_v4()).bind(workshop).bind(database).execute(store.pool()).await;
    assert!(
        invalid.is_err(),
        "human hostnames must not be accepted as physical database references"
    );

    let recovery_table = sqlx::query_as::<_, (Option<String>, Option<String>)>(
        "select to_regclass('control.workshop_recovery_points')::text,to_regclass('control.odoo_recovery_points')::text",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(
        recovery_table.0.as_deref(),
        Some("control.workshop_recovery_points")
    );
    assert_eq!(recovery_table.1, None, "the Odoo-only table was migrated");
    let rehearsal_table: Option<String> =
        sqlx::query_scalar("select to_regclass('control.workshop_recovery_rehearsals')::text")
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert_eq!(
        rehearsal_table.as_deref(),
        Some("control.workshop_recovery_rehearsals")
    );
    sqlx::query("insert into control.deployment_driver_operations(idempotency_key,workshop_id,action,request_digest) values('rehearsal-migration-check',$1,'rehearse',repeat('0',64))")
        .bind(workshop)
        .execute(store.pool())
        .await
        .expect("the driver ledger must accept rehearsal actions");

    sqlx::query("insert into control.workshop_recovery_points(id,workshop_id,database_id,kind,label,requested_by,component_scope,format_version) values($1,$2,$3,'snapshot','Full workshop',$4,array['odoo','paperless'],'makersbrain-workshop-recovery-v2')")
        .bind(Uuid::new_v4()).bind(workshop).bind(database).bind(user).execute(store.pool()).await.unwrap();
    let invalid_scope = sqlx::query("insert into control.workshop_recovery_points(id,workshop_id,database_id,kind,label,requested_by,component_scope,format_version) values($1,$2,$3,'snapshot','Missing Odoo',$4,array['paperless'],'makersbrain-workshop-recovery-v2')")
        .bind(Uuid::new_v4()).bind(workshop).bind(database).bind(user).execute(store.pool()).await;
    assert!(
        invalid_scope.is_err(),
        "every workshop recovery set must include Odoo"
    );
}

#[tokio::test]
#[ignore = "requires a disposable CONTROL_TEST_DATABASE_URL"]
async fn enqueue_replays_only_an_identical_idempotent_operation() {
    let store = store().await;
    let key = format!("inventory-test:{}", Uuid::new_v4());
    let payload = json!({"capture_id": Uuid::new_v4(), "assets": []});
    let correlation = Uuid::new_v4();

    let mut first_tx = store.begin().await.unwrap();
    let first = Store::enqueue(
        &mut first_tx,
        NewOperation {
            kind: OperationKind::InventoryCaptureExtract,
            workshop_id: None,
            target_user_id: None,
            desired_epoch: None,
            payload: &payload,
            requested_by: None,
            correlation_id: correlation,
            idempotency_key: &key,
        },
    )
    .await
    .unwrap();
    first_tx.commit().await.unwrap();

    let mut replay_tx = store.begin().await.unwrap();
    let replay = Store::enqueue(
        &mut replay_tx,
        NewOperation {
            kind: OperationKind::InventoryCaptureExtract,
            workshop_id: None,
            target_user_id: None,
            desired_epoch: None,
            payload: &payload,
            requested_by: None,
            correlation_id: correlation,
            idempotency_key: &key,
        },
    )
    .await
    .unwrap();
    replay_tx.commit().await.unwrap();
    assert_eq!(first, replay);

    let leased = store
        .lease("inventory-capture", "checkpoint-test-worker")
        .await
        .unwrap()
        .expect("operation should be leaseable");
    assert_eq!(leased.id, first);
    let checkpoint = json!({"callbacks":[{"operation_key":"stable","attempt_id":Uuid::new_v4()}]});
    store
        .save_operation_checkpoint(&leased, &checkpoint)
        .await
        .unwrap();
    assert_eq!(
        store.operation_checkpoint(first).await.unwrap(),
        Some(checkpoint)
    );

    let changed_payload = json!({"capture_id": Uuid::new_v4(), "assets": []});
    let mut conflict_tx = store.begin().await.unwrap();
    assert!(
        Store::enqueue(
            &mut conflict_tx,
            NewOperation {
                kind: OperationKind::InventoryCaptureExtract,
                workshop_id: None,
                target_user_id: None,
                desired_epoch: None,
                payload: &changed_payload,
                requested_by: None,
                correlation_id: correlation,
                idempotency_key: &key,
            }
        )
        .await
        .is_err()
    );
}
