use makersbrain_control_plane::persistence::Store;
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
}
