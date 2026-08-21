use mb_control_plane::command::{
    CommandAdmission, CommandError, CommandResult, NewCommand, admit_command, complete_command,
};
use mb_control_plane::domain::OperationKind;
use mb_control_plane::modules::{CATALOG, REGISTRY_VERSION};
use mb_control_plane::persistence::{NewOperation, Store};
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
async fn carrier_secret_metadata_is_tenant_carrier_and_environment_scoped() {
    let store = store().await;
    let user = Uuid::new_v4();
    let first = Uuid::new_v4();
    let second = Uuid::new_v4();
    sqlx::query("insert into control.users(id,email) values($1,$2)")
        .bind(user)
        .bind(format!("{user}@example.test"))
        .execute(store.pool())
        .await
        .unwrap();
    for workshop in [first, second] {
        sqlx::query("insert into control.workshops(id,slug,display_name,time_zone) values($1,$2,'Carrier fixture','Europe/Paris')")
            .bind(workshop)
            .bind(format!("carrier-{}", workshop.simple()))
            .execute(store.pool()).await.unwrap();
    }
    for workshop in [first, second] {
        let secret = Uuid::new_v4();
        sqlx::query("insert into control.carrier_secrets(id,workshop_id,provider,environment,company_id,carrier_id,secret_ref,created_by) values($1,$2,'boxtal','test',1,7,$3,$4)")
            .bind(secret).bind(workshop)
            .bind(format!("docker/{workshop}/carrier/{secret}"))
            .bind(user).execute(store.pool()).await.unwrap();
    }
    let invalid = sqlx::query("insert into control.carrier_secrets(id,workshop_id,provider,environment,company_id,carrier_id,secret_ref,created_by) values($1,$2,'boxtal','production-copy',1,8,'not/scoped',$3)")
        .bind(Uuid::new_v4()).bind(first).bind(user).execute(store.pool()).await;
    assert!(
        invalid.is_err(),
        "invalid environment/reference must fail closed"
    );
    let stale = Uuid::new_v4();
    sqlx::query("update control.carrier_secrets set cleanup_pending_ref=$2 where workshop_id=$1")
        .bind(first)
        .bind(format!("docker/{first}/carrier/{stale}"))
        .execute(store.pool())
        .await
        .unwrap();
    let premature_delete = sqlx::query(
        "update control.carrier_secrets set state='deleted',deleted_at=now() where workshop_id=$1",
    )
    .bind(first)
    .execute(store.pool())
    .await;
    assert!(
        premature_delete.is_err(),
        "a credential with pending secure cleanup cannot be finalized as deleted"
    );
    let row = sqlx::query_as::<_, (String, i64, i64)>(
        "update control.carrier_secrets set state='deleted',deleted_at=now(),cleanup_pending_ref=null,version=version+1 where workshop_id=$1 returning state,version,carrier_id",
    )
    .bind(first)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(row, ("deleted".into(), 2, 7));
}

#[tokio::test]
#[ignore = "requires a disposable CONTROL_TEST_DATABASE_URL"]
async fn webshop_domain_registry_enforces_global_claim_and_active_evidence() {
    let store = store().await;
    let user = Uuid::new_v4();
    let first = Uuid::new_v4();
    let second = Uuid::new_v4();
    sqlx::query("insert into control.users(id,email) values($1,$2)")
        .bind(user)
        .bind(format!("{user}@example.test"))
        .execute(store.pool())
        .await
        .unwrap();
    for workshop in [first, second] {
        sqlx::query("insert into control.workshops(id,slug,display_name,time_zone) values($1,$2,'Domain fixture','Europe/Paris')")
            .bind(workshop).bind(format!("domain-{}",workshop.simple()))
            .execute(store.pool()).await.unwrap();
    }
    let domain = Uuid::new_v4();
    sqlx::query("insert into control.webshop_domains(id,workshop_id,hostname,verification_name,verification_value,routing_target,created_by) values($1,$2,'www.atelier-luna.fr','_mb-challenge.www.atelier-luna.fr',$3,'shops.makersbrain.com',$4)")
        .bind(domain).bind(first)
        .bind("mb-verification=0123456789abcdefghijklmnopqrstuv")
        .bind(user).execute(store.pool()).await.unwrap();
    let stolen = sqlx::query("insert into control.webshop_domains(id,workshop_id,hostname,verification_name,verification_value,routing_target,created_by) values($1,$2,'www.atelier-luna.fr','_mb-challenge.www.atelier-luna.fr',$3,'shops.makersbrain.com',$4)")
        .bind(Uuid::new_v4()).bind(second)
        .bind("mb-verification=abcdefghijklmnopqrstuvwxyz012345")
        .bind(user).execute(store.pool()).await;
    assert!(
        stolen.is_err(),
        "a hostname cannot be claimed by two tenants"
    );
    let premature = sqlx::query("update control.webshop_domains set state='active' where id=$1")
        .bind(domain)
        .execute(store.pool())
        .await;
    assert!(
        premature.is_err(),
        "an active route requires ownership, DNS, TLS and provider evidence"
    );
    sqlx::query("update control.webshop_domains set state='active',dns_state='verified',certificate_state='active',ownership_verified_at=now(),provider_ref='cloudflare:test' where id=$1")
        .bind(domain).execute(store.pool()).await.unwrap();
    let duplicate_canonical = Uuid::new_v4();
    sqlx::query("update control.webshop_domains set canonical=true where id=$1")
        .bind(domain)
        .execute(store.pool())
        .await
        .unwrap();
    let result = sqlx::query("insert into control.webshop_domains(id,workshop_id,hostname,verification_name,verification_value,routing_target,created_by,canonical) values($1,$2,'shop.atelier-luna.fr','_mb-challenge.shop.atelier-luna.fr',$3,'shops.makersbrain.com',$4,true)")
        .bind(duplicate_canonical).bind(first)
        .bind("mb-verification=ABCDEFGHIJKLMNOPQRSTUVWXYZ012345")
        .bind(user).execute(store.pool()).await;
    assert!(
        result.is_err(),
        "only one connected custom hostname can be canonical"
    );
}

#[tokio::test]
#[ignore = "requires a disposable CONTROL_TEST_DATABASE_URL"]
async fn webshop_transactional_outbox_is_tenant_scoped_and_idempotent() {
    let store = store().await;
    let workshop = Uuid::new_v4();
    sqlx::query("insert into control.workshops(id,slug,display_name,time_zone) values($1,$2,'Mail fixture','Europe/Paris')")
        .bind(workshop)
        .bind(format!("mail-{}", workshop.simple()))
        .execute(store.pool())
        .await
        .unwrap();
    let payload = json!({
        "content":{"subject":"Order confirmed","text":"Confirmed","html":"<p>Confirmed</p>"},
        "sender_name":"Atelier via MakersBrain",
        "reply_to":"studio@example.fr",
        "model":"sale.order",
        "attachments":[]
    });
    let source_key = format!("odoo:42:0:{}", Uuid::new_v4().simple());
    sqlx::query("insert into control.outbox(id,kind,recipient,template,payload,workshop_id,source_key) values($1,'odoo_transactional','customer@example.fr','odoo-rendered-v1',$2,$3,$4)")
        .bind(Uuid::new_v4())
        .bind(&payload)
        .bind(workshop)
        .bind(&source_key)
        .execute(store.pool())
        .await
        .unwrap();
    let duplicate = sqlx::query("insert into control.outbox(id,kind,recipient,template,payload,workshop_id,source_key) values($1,'odoo_transactional','customer@example.fr','odoo-rendered-v1',$2,$3,$4)")
        .bind(Uuid::new_v4())
        .bind(&payload)
        .bind(workshop)
        .bind(&source_key)
        .execute(store.pool())
        .await;
    assert!(
        duplicate.is_err(),
        "one durable row is allowed per Odoo source key"
    );
    let unscoped = sqlx::query("insert into control.outbox(id,kind,recipient,template,payload) values($1,'odoo_transactional','customer@example.fr','odoo-rendered-v1',$2)")
        .bind(Uuid::new_v4())
        .bind(&payload)
        .execute(store.pool())
        .await;
    assert!(
        unscoped.is_err(),
        "transactional mail must belong to one workshop"
    );
    let wrong_template = sqlx::query("insert into control.outbox(id,kind,recipient,template,payload,workshop_id,source_key) values($1,'odoo_transactional','customer@example.fr','workshop-invitation',$2,$3,$4)")
        .bind(Uuid::new_v4())
        .bind(&payload)
        .bind(workshop)
        .bind(format!("odoo:43:0:{}", Uuid::new_v4().simple()))
        .execute(store.pool())
        .await;
    assert!(
        wrong_template.is_err(),
        "rendered Odoo mail cannot select another template"
    );
}

#[tokio::test]
#[ignore = "requires a disposable CONTROL_TEST_DATABASE_URL"]
async fn branded_email_domain_requires_dns_and_delivered_test_evidence() {
    let store = store().await;
    let user = Uuid::new_v4();
    let workshop = Uuid::new_v4();
    sqlx::query("insert into control.users(id,email) values($1,$2)")
        .bind(user)
        .bind(format!("{user}@example.test"))
        .execute(store.pool())
        .await
        .unwrap();
    sqlx::query("insert into control.workshops(id,slug,display_name,time_zone) values($1,$2,'Email domain fixture','Europe/Paris')").bind(workshop).bind(format!("mail-{}",workshop.simple())).execute(store.pool()).await.unwrap();
    let id = Uuid::new_v4();
    sqlx::query("insert into control.webshop_email_domains(id,workshop_id,domain_name,created_by) values($1,$2,'mail.atelier-luna.fr',$3)").bind(id).bind(workshop).bind(user).execute(store.pool()).await.unwrap();
    let premature=sqlx::query("update control.webshop_email_domains set state='active',provider_ref=$2,provider_status='checked' where id=$1").bind(id).bind(Uuid::new_v4()).execute(store.pool()).await;
    assert!(
        premature.is_err(),
        "provider status alone cannot activate branded sending"
    );
    let duplicate=sqlx::query("insert into control.webshop_email_domains(id,workshop_id,domain_name,created_by) values($1,$2,'mail.atelier-luna.fr',$3)").bind(Uuid::new_v4()).bind(workshop).bind(user).execute(store.pool()).await;
    assert!(duplicate.is_err(), "an email domain has one global owner");
}

#[tokio::test]
#[ignore = "requires a disposable CONTROL_TEST_DATABASE_URL"]
async fn webshop_onboarding_persists_progress_and_requires_completion_evidence() {
    let store = store().await;
    let workshop = Uuid::new_v4();
    sqlx::query("insert into control.workshops(id,slug,display_name,time_zone) values($1,$2,'Onboarding fixture','Europe/Paris')")
        .bind(workshop)
        .bind(format!("onboarding-{}", workshop.simple()))
        .execute(store.pool())
        .await
        .unwrap();
    sqlx::query("insert into control.webshop_onboarding(workshop_id,state,observation,odoo_issues,started_at,last_checked_at,version) values($1,'ready',$2,'[]',now(),now(),2)")
        .bind(workshop)
        .bind(json!({"launch_ready":true,"catalog":true}))
        .execute(store.pool())
        .await
        .unwrap();
    let premature =
        sqlx::query("update control.webshop_onboarding set state='completed' where workshop_id=$1")
            .bind(workshop)
            .execute(store.pool())
            .await;
    assert!(
        premature.is_err(),
        "completed state requires a durable completion timestamp"
    );
    sqlx::query("update control.webshop_onboarding set state='completed',completed_at=now(),version=version+1 where workshop_id=$1")
        .bind(workshop)
        .execute(store.pool())
        .await
        .unwrap();
    let persisted = sqlx::query_as::<_, (String, i64, bool)>(
        "select state,version,(observation->>'launch_ready')::boolean from control.webshop_onboarding where workshop_id=$1",
    )
    .bind(workshop)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(persisted, ("completed".into(), 3, true));

    let operation = Uuid::new_v4();
    sqlx::query("insert into control.operations(id,kind,queue,workshop_id,payload,correlation_id,idempotency_key) values($1,'webshop-onboarding.reconcile','tenant-reconciliation',$2,'{}',$3,$4)")
        .bind(operation)
        .bind(workshop)
        .bind(Uuid::new_v4())
        .bind(format!("onboarding:{workshop}"))
        .execute(store.pool())
        .await
        .unwrap();
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

    let recovery_table = sqlx::query_as::<_, (bool, bool)>(
        "select to_regclass('control.workshop_recovery_points') is not null,to_regclass('control.odoo_recovery_points') is not null",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert!(recovery_table.0, "the workshop recovery table must exist");
    assert!(!recovery_table.1, "the Odoo-only table was migrated");
    let rehearsal_table: bool = sqlx::query_scalar(
        "select to_regclass('control.workshop_recovery_rehearsals') is not null",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert!(rehearsal_table, "the recovery rehearsal table must exist");
    sqlx::query("insert into control.deployment_driver_operations(idempotency_key,workshop_id,action,request_digest) values($1,$2,'rehearse',repeat('0',64))")
        .bind(format!("rehearsal-migration-check:{workshop}"))
        .bind(workshop)
        .execute(store.pool())
        .await
        .expect("the driver ledger must accept rehearsal actions");

    sqlx::query("insert into control.workshop_recovery_points(id,workshop_id,database_id,kind,label,requested_by,component_scope,format_version) values($1,$2,$3,'snapshot','Full workshop',$4,array['odoo','paperless'],'mb-workshop-recovery-v2')")
        .bind(Uuid::new_v4()).bind(workshop).bind(database).bind(user).execute(store.pool()).await.unwrap();
    let default_recovery = Uuid::new_v4();
    sqlx::query("insert into control.workshop_recovery_points(id,workshop_id,database_id,kind,label,requested_by) values($1,$2,$3,'snapshot','Current default',$4)")
        .bind(default_recovery).bind(workshop).bind(database).bind(user).execute(store.pool()).await.unwrap();
    let default_format: String = sqlx::query_scalar(
        "select format_version from control.workshop_recovery_points where id=$1",
    )
    .bind(default_recovery)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(default_format, "mb-workshop-recovery-v2");
    let legacy_format = sqlx::query("insert into control.workshop_recovery_points(id,workshop_id,database_id,kind,label,requested_by,format_version) values($1,$2,$3,'snapshot','Obsolete format',$4,'mb-odoo-recovery-v1')")
        .bind(Uuid::new_v4()).bind(workshop).bind(database).bind(user).execute(store.pool()).await;
    assert!(
        legacy_format.is_err(),
        "the obsolete Odoo-only recovery format must fail closed"
    );
    let invalid_scope = sqlx::query("insert into control.workshop_recovery_points(id,workshop_id,database_id,kind,label,requested_by,component_scope,format_version) values($1,$2,$3,'snapshot','Missing Odoo',$4,array['paperless'],'mb-workshop-recovery-v2')")
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

#[tokio::test]
#[ignore = "requires a disposable CONTROL_TEST_DATABASE_URL"]
async fn invitation_outbox_requires_non_secret_generation_metadata() {
    let store = store().await;
    let user = Uuid::new_v4();
    let workshop = Uuid::new_v4();
    let invitation = Uuid::new_v4();
    sqlx::query("insert into control.users(id,email) values($1,$2)")
        .bind(user)
        .bind(format!("{user}@example.test"))
        .execute(store.pool())
        .await
        .unwrap();
    sqlx::query("insert into control.workshops(id,slug,display_name,time_zone) values($1,$2,'Invitation fixture','Europe/Paris')")
        .bind(workshop)
        .bind(format!("invite-{}", workshop.simple()))
        .execute(store.pool())
        .await
        .unwrap();
    sqlx::query("insert into control.memberships(workshop_id,user_id,role) values($1,$2,'owner')")
        .bind(workshop)
        .bind(user)
        .execute(store.pool())
        .await
        .unwrap();
    sqlx::query("insert into control.invitations(id,workshop_id,email,role,invited_by,idempotency_key,expires_at) values($1,$2,'invitee@example.test','artisan',$3,$4,now()+interval '1 day')")
        .bind(invitation)
        .bind(workshop)
        .bind(user)
        .bind(format!("invite:{invitation}"))
        .execute(store.pool())
        .await
        .unwrap();

    let secret_payload = sqlx::query("insert into control.outbox(id,kind,recipient,template,payload,invitation_id,token_generation,capability_issued_at,capability_expires_at,signing_key_id) values($1,'invitation','invitee@example.test','workshop-invitation',$2,$3,1,now(),now()+interval '1 day','test-key')")
        .bind(Uuid::new_v4())
        .bind(json!({"accept_url":"https://example.test/invitations/accept#token=secret"}))
        .bind(invitation)
        .execute(store.pool())
        .await;
    assert!(
        secret_payload.is_err(),
        "capabilities must not enter outbox JSON"
    );

    let outbox = Uuid::new_v4();
    sqlx::query("insert into control.outbox(id,kind,recipient,template,payload,invitation_id,token_generation,capability_issued_at,capability_expires_at,signing_key_id) values($1,'invitation','invitee@example.test','workshop-invitation',$2,$3,1,now(),now()+interval '1 day','test-key')")
        .bind(outbox)
        .bind(json!({"invitation_id":invitation,"locale":"en"}))
        .bind(invitation)
        .execute(store.pool())
        .await
        .unwrap();
    let duplicate = sqlx::query("insert into control.outbox(id,kind,recipient,template,payload,invitation_id,token_generation,capability_issued_at,capability_expires_at,signing_key_id) values($1,'invitation','invitee@example.test','workshop-invitation',$2,$3,1,now(),now()+interval '1 day','test-key')")
        .bind(Uuid::new_v4())
        .bind(json!({"invitation_id":invitation,"locale":"en"}))
        .bind(invitation)
        .execute(store.pool())
        .await;
    assert!(
        duplicate.is_err(),
        "one outbox event is allowed per generation"
    );
}

#[tokio::test]
#[ignore = "requires a disposable CONTROL_TEST_DATABASE_URL"]
async fn commands_replay_stored_results_and_audit_is_append_only() {
    let store = store().await;
    let user = Uuid::new_v4();
    let workshop = Uuid::new_v4();
    sqlx::query("insert into control.users(id,email) values($1,$2)")
        .bind(user)
        .bind(format!("{user}@example.test"))
        .execute(store.pool())
        .await
        .unwrap();
    sqlx::query("insert into control.workshops(id,slug,display_name,time_zone) values($1,$2,'Command fixture','Europe/Paris')")
        .bind(workshop)
        .bind(format!("command-{}", workshop.simple()))
        .execute(store.pool())
        .await
        .unwrap();
    sqlx::query("insert into control.memberships(workshop_id,user_id,role) values($1,$2,'owner')")
        .bind(workshop)
        .bind(user)
        .execute(store.pool())
        .await
        .unwrap();

    let key = format!("command:{workshop}");
    let request = json!({"workshop_id":workshop,"role":"artisan"});
    let response = json!({"id":workshop,"accepted":true});
    let scope = format!("workshop:{workshop}");
    let mut tx = store.begin().await.unwrap();
    let command_id = match admit_command(
        &mut tx,
        NewCommand {
            actor_user_id: user,
            scope: &scope,
            command_kind: "fixture.update",
            idempotency_key: &key,
            semantic_request: &request,
            expected_version: Some(1),
        },
    )
    .await
    .unwrap()
    {
        CommandAdmission::New { command_id } => command_id,
        other => panic!("expected a new command, got {other:?}"),
    };
    complete_command(
        &mut tx,
        command_id,
        CommandResult {
            operation_id: None,
            response_status: 202,
            response_body: Some(&response),
            result_ref: None,
        },
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();

    let mut replay_tx = store.begin().await.unwrap();
    let replay = admit_command(
        &mut replay_tx,
        NewCommand {
            actor_user_id: user,
            scope: &scope,
            command_kind: "fixture.update",
            idempotency_key: &key,
            semantic_request: &request,
            expected_version: Some(1),
        },
    )
    .await
    .unwrap();
    assert!(matches!(
        replay,
        CommandAdmission::Replay {
            response_status: 202,
            response_body: Some(ref body),
            ..
        } if body == &response
    ));
    replay_tx.commit().await.unwrap();

    let mut mismatch_tx = store.begin().await.unwrap();
    let mismatch = admit_command(
        &mut mismatch_tx,
        NewCommand {
            actor_user_id: user,
            scope: &scope,
            command_kind: "fixture.update",
            idempotency_key: &key,
            semantic_request: &json!({"workshop_id":workshop,"role":"owner"}),
            expected_version: Some(1),
        },
    )
    .await;
    assert!(matches!(mismatch, Err(CommandError::PayloadMismatch)));

    let audit = Uuid::new_v4();
    sqlx::query("insert into control.audit_events(id,actor_audit_subject_id,workshop_id,action,correlation_id,outcome) values($1,(select audit_subject_id from control.users where id=$2),$3,'fixture.command',$4,'accepted')")
        .bind(audit)
        .bind(user)
        .bind(workshop)
        .bind(Uuid::new_v4())
        .execute(store.pool())
        .await
        .unwrap();
    assert!(
        sqlx::query("update control.audit_events set outcome='changed' where id=$1")
            .bind(audit)
            .execute(store.pool())
            .await
            .is_err()
    );
    assert!(
        sqlx::query("delete from control.audit_events where id=$1")
            .bind(audit)
            .execute(store.pool())
            .await
            .is_err()
    );

    sqlx::query("insert into control.operations(id,kind,queue,payload,correlation_id,idempotency_key,trace_parent,trace_state) values($1,'privacy.retention','privacy-operations','{}',$2,$3,'00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01','vendor=value')")
        .bind(Uuid::new_v4()).bind(Uuid::new_v4()).bind(format!("trace:{workshop}"))
        .execute(store.pool()).await.unwrap();
    assert!(sqlx::query("insert into control.operations(id,kind,queue,payload,correlation_id,idempotency_key,trace_parent) values($1,'privacy.retention','privacy-operations','{}',$2,$3,'subject@example.test')")
        .bind(Uuid::new_v4()).bind(Uuid::new_v4()).bind(format!("invalid-trace:{workshop}"))
        .execute(store.pool()).await.is_err());
}

#[tokio::test]
#[ignore = "requires a disposable CONTROL_TEST_DATABASE_URL"]
async fn capability_compare_and_set_allows_exactly_one_winner() {
    let store = store().await;
    let registry_count: i64 = sqlx::query_scalar(
        "select count(*) from control.capability_registry_entries where registry_version=$1",
    )
    .bind(i32::try_from(REGISTRY_VERSION).unwrap())
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(
        registry_count,
        i64::try_from(CATALOG.len()).unwrap(),
        "the embedded registry is fully materialized"
    );
    let ceramics_modules: Vec<String> = sqlx::query_scalar(
        "select odoo_modules from control.capability_registry_entries
         where registry_version=$1 and capability_key='ceramics-production'",
    )
    .bind(i32::try_from(REGISTRY_VERSION).unwrap())
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(ceramics_modules, vec!["mb_ceramics_workflow"]);
    let user = Uuid::new_v4();
    let workshop = Uuid::new_v4();
    sqlx::query("insert into control.users(id,email) values($1,$2)")
        .bind(user)
        .bind(format!("{user}@example.test"))
        .execute(store.pool())
        .await
        .unwrap();
    sqlx::query("insert into control.workshops(id,slug,display_name,time_zone) values($1,$2,'ETag fixture','Europe/Paris')")
        .bind(workshop)
        .bind(format!("etag-{}", workshop.simple()))
        .execute(store.pool())
        .await
        .unwrap();
    sqlx::query("insert into control.memberships(workshop_id,user_id,role) values($1,$2,'owner')")
        .bind(workshop)
        .bind(user)
        .execute(store.pool())
        .await
        .unwrap();
    sqlx::query("insert into control.workshop_modules(workshop_id,module_key,state,version,requested_by) values($1,'documents','requested',1,$2)")
        .bind(workshop)
        .bind(user)
        .execute(store.pool())
        .await
        .unwrap();
    let unknown = sqlx::query("insert into control.workshop_modules(workshop_id,module_key,state,version,requested_by) values($1,'future-capability','requested',1,$2)")
        .bind(workshop).bind(user).execute(store.pool()).await;
    assert!(
        unknown.is_err(),
        "desired state must reference a materialized registry entry"
    );

    let update = |state: &'static str| {
        let pool = store.pool().clone();
        async move {
            sqlx::query("update control.workshop_modules set state=$2,version=version+1 where workshop_id=$1 and module_key='documents' and version=1")
                .bind(workshop)
                .bind(state)
                .execute(&pool)
                .await
                .unwrap()
                .rows_affected()
        }
    };
    let (left, right) = tokio::join!(update("requested"), update("installing"));
    assert_eq!(left + right, 1, "one stale writer must lose");
    let version: i64 = sqlx::query_scalar(
        "select version from control.workshop_modules where workshop_id=$1 and module_key='documents'",
    )
    .bind(workshop)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(version, 2);
    let rewrite_pin = sqlx::query(
        "update control.workshop_modules set resolved_implementation=$2,version=version+1
         where workshop_id=$1 and module_key='documents' and version=2",
    )
    .bind(workshop)
    .bind(json!({"service":"paperless"}))
    .execute(store.pool())
    .await;
    assert!(
        rewrite_pin.is_err(),
        "a retry cannot reinterpret the pinned capability implementation"
    );
}

#[tokio::test]
#[ignore = "requires a disposable CONTROL_TEST_DATABASE_URL"]
async fn capability_restriction_requires_downstream_evidence() {
    let store = store().await;
    let user = Uuid::new_v4();
    let workshop = Uuid::new_v4();
    sqlx::query("insert into control.users(id,email) values($1,$2)")
        .bind(user)
        .bind(format!("{user}@example.test"))
        .execute(store.pool())
        .await
        .unwrap();
    sqlx::query("insert into control.workshops(id,slug,display_name,time_zone) values($1,$2,'Restriction fixture','Europe/Paris')")
        .bind(workshop).bind(format!("restrict-{}",workshop.simple())).execute(store.pool()).await.unwrap();
    let enable = Uuid::new_v4();
    sqlx::query("insert into control.operations(id,kind,queue,workshop_id,payload,requested_by,correlation_id,idempotency_key) values($1,'module.enable','tenant-reconciliation',$2,'{}',$3,$4,$5)")
        .bind(enable).bind(workshop).bind(user).bind(Uuid::new_v4()).bind(format!("enable:{workshop}"))
        .execute(store.pool()).await.unwrap();
    sqlx::query("insert into control.workshop_modules(workshop_id,module_key,state,operation_id,requested_by,resolved_implementation) values($1,'firings','requested',$2,$3,$4)")
        .bind(workshop).bind(enable).bind(user).bind(json!({"odoo_modules":["mb_ceramics_firing"],"service":null}))
        .execute(store.pool()).await.unwrap();
    sqlx::query("update control.workshop_modules set state='installing',version=version+1 where workshop_id=$1 and module_key='firings'")
        .bind(workshop).execute(store.pool()).await.unwrap();
    sqlx::query("update control.workshop_modules set state='enabled',enabled_at=now(),version=version+1 where workshop_id=$1 and module_key='firings'")
        .bind(workshop).execute(store.pool()).await.unwrap();

    let direct = sqlx::query("update control.workshop_modules set state='restricted',restriction_reason='entitlement_inactive',restriction_evidence=$2,restricted_at=now(),version=version+1 where workshop_id=$1 and module_key='firings'")
        .bind(workshop).bind(json!({"adapter":"fake"})).execute(store.pool()).await;
    assert!(
        direct.is_err(),
        "enabled cannot become restricted without adapter execution"
    );

    let restrict = Uuid::new_v4();
    sqlx::query("insert into control.operations(id,kind,queue,workshop_id,payload,requested_by,correlation_id,idempotency_key) values($1,'module.restrict','tenant-reconciliation',$2,'{}',$3,$4,$5)")
        .bind(restrict).bind(workshop).bind(user).bind(Uuid::new_v4()).bind(format!("restrict:{workshop}"))
        .execute(store.pool()).await.unwrap();
    sqlx::query("update control.workshop_modules set state='restricting',operation_id=$2,restriction_reason='entitlement_inactive',version=version+1 where workshop_id=$1 and module_key='firings'")
        .bind(workshop).bind(restrict).execute(store.pool()).await.unwrap();
    let no_evidence = sqlx::query("update control.workshop_modules set state='restricted',restricted_at=now(),version=version+1 where workshop_id=$1 and module_key='firings'")
        .bind(workshop).execute(store.pool()).await;
    assert!(
        no_evidence.is_err(),
        "restricted requires nonempty enforcement evidence"
    );
    sqlx::query("update control.workshop_modules set state='restricted',restriction_evidence=$2,restricted_at=now(),version=version+1 where workshop_id=$1 and module_key='firings'")
        .bind(workshop).bind(json!({"adapter":"odoo_write_rules","write_blocked":true,"historical_read_retained":true}))
        .execute(store.pool()).await.unwrap();
}

#[tokio::test]
#[ignore = "requires a disposable CONTROL_TEST_DATABASE_URL"]
async fn release_state_machine_and_fleet_fences_are_database_enforced() {
    let store = store().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let release = format!("odoo-2026.08.14-{}", &suffix[..12]);
    let digest = format!("sha256:{}", "1".repeat(64));
    let manifest_digest = format!("sha256:{}", "2".repeat(64));
    sqlx::query(
        "insert into control.application_releases(
           id,source_commit,odoo_version,image_digest,manifest_digest,addon_versions,
           compatibility,bridge_contract,schema_epoch,change_class,
           required_postconditions,manifest,signature_bundle_ref,provenance_ref,
           sbom_ref,published_at,publication_idempotency_key,publication_request_digest
         ) values($1,$2,'19.0',$3,$4,'{}','{}','>=3.2.0,<4.0.0',42,'B',
                  '[]','{}','oci://signature','oci://provenance','oci://sbom',now(),$5,$6)",
    )
    .bind(&release)
    .bind("a".repeat(40))
    .bind(&digest)
    .bind(&manifest_digest)
    .bind(format!("release-publication:{release}"))
    .bind(vec![0_u8; 32])
    .execute(store.pool())
    .await
    .unwrap();

    let illegal = sqlx::query(
        "update control.application_releases set status='active',version=version+1 where id=$1",
    )
    .bind(&release)
    .execute(store.pool())
    .await;
    assert!(
        illegal.is_err(),
        "candidate cannot skip preflight and preparation"
    );

    for status in ["preflighting", "canary", "prepared", "active", "retained"] {
        sqlx::query(
            "update control.application_releases set status=$2,version=version+1 where id=$1",
        )
        .bind(&release)
        .bind(status)
        .execute(store.pool())
        .await
        .unwrap();
    }
    let version: i64 =
        sqlx::query_scalar("select version from control.application_releases where id=$1")
            .bind(&release)
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert_eq!(version, 6);

    let operation_one = Uuid::new_v4();
    let operation_two = Uuid::new_v4();
    for operation in [operation_one, operation_two] {
        sqlx::query("insert into control.operations(id,kind,queue,payload,correlation_id,idempotency_key) values($1,'odoo.release.adopt','release-adoption','{}',$2,$3)")
            .bind(operation).bind(Uuid::new_v4()).bind(format!("release-test:{operation}")).execute(store.pool()).await.unwrap();
    }
    let fleet_run = Uuid::new_v4();
    sqlx::query("insert into control.release_fleet_runs(id,release_id,operation_id,fleet_generation,state,tenant_snapshot) values($1,$2,$3,1,'preparing','[]')")
        .bind(fleet_run).bind(&release).bind(operation_one).execute(store.pool()).await.unwrap();
    let second = sqlx::query("insert into control.release_fleet_runs(id,release_id,operation_id,fleet_generation,state,tenant_snapshot) values($1,$2,$3,2,'preparing','[]')")
        .bind(Uuid::new_v4()).bind(&release).bind(operation_two).execute(store.pool()).await;
    assert!(
        second.is_err(),
        "only one unfinished fleet release is allowed"
    );

    let intent = Uuid::new_v4();
    let action = Uuid::new_v4();
    let gateway_digest = format!("sha256:{}", "3".repeat(64));
    sqlx::query("insert into control.fleet_activation_intents(id,fleet_run_id,release_id,runtime_key,target_slot,image_digest,prepared_tenants,gateway_configuration_digest,driver_action_id) values($1,$2,$3,'shared-odoo','blue',$4,'[]',$5,$6)")
        .bind(intent).bind(fleet_run).bind(&release).bind(&digest).bind(&gateway_digest).bind(action).execute(store.pool()).await.unwrap();
    sqlx::query("update control.fleet_activation_intents set observed_configuration_digest=$2,activated_at=now() where id=$1")
        .bind(intent).bind(&gateway_digest).execute(store.pool()).await.unwrap();
    let mutate =
        sqlx::query("update control.fleet_activation_intents set target_slot='green' where id=$1")
            .bind(intent)
            .execute(store.pool())
            .await;
    assert!(mutate.is_err(), "activation intent target is immutable");
    let mismatch = sqlx::query(
        "update control.fleet_activation_intents set observed_configuration_digest=$2 where id=$1",
    )
    .bind(intent)
    .bind(format!("sha256:{}", "4".repeat(64)))
    .execute(store.pool())
    .await;
    assert!(mismatch.is_err(), "observed gateway digest cannot diverge");
}

#[tokio::test]
#[ignore = "requires a disposable CONTROL_TEST_DATABASE_URL"]
async fn privacy_rights_transitions_holds_and_production_gate_are_enforced() {
    let store = store().await;
    let user = Uuid::new_v4();
    let workshop = Uuid::new_v4();
    sqlx::query("insert into control.users(id,email) values($1,$2)")
        .bind(user)
        .bind(format!("{user}@example.test"))
        .execute(store.pool())
        .await
        .unwrap();
    sqlx::query("insert into control.workshops(id,slug,display_name,time_zone) values($1,$2,'Privacy fixture','Europe/Paris')")
        .bind(workshop).bind(format!("privacy-{}",workshop.simple())).execute(store.pool()).await.unwrap();
    sqlx::query("insert into control.memberships(workshop_id,user_id,role) values($1,$2,'owner')")
        .bind(workshop)
        .bind(user)
        .execute(store.pool())
        .await
        .unwrap();
    let request = Uuid::new_v4();
    sqlx::query("insert into control.data_subject_requests(id,subject_user_id,request_type,scope) values($1,$2,'restriction',$3)")
        .bind(request).bind(user).bind(json!({"workshop_ids":[workshop]})).execute(store.pool()).await.unwrap();
    let illegal=sqlx::query("update control.data_subject_requests set status='completed',completed_at=now(),version=version+1 where id=$1")
        .bind(request).execute(store.pool()).await;
    assert!(
        illegal.is_err(),
        "rights requests cannot skip controller review"
    );
    sqlx::query("update control.data_subject_requests set status='controller_review',version=version+1 where id=$1")
        .bind(request).execute(store.pool()).await.unwrap();
    sqlx::query("update control.data_subject_requests set status='approved',decision_code='approved_by_controller',approver_user_id=$2,decided_at=now(),version=version+1 where id=$1")
        .bind(request).bind(user).execute(store.pool()).await.unwrap();
    sqlx::query("insert into control.processing_holds(id,data_subject_request_id,subject_user_id,workshop_id) values($1,$2,$3,$4)")
        .bind(Uuid::new_v4()).bind(request).bind(user).bind(workshop).execute(store.pool()).await.unwrap();
    let blocked=sqlx::query("insert into control.operations(id,kind,queue,workshop_id,payload,requested_by,correlation_id,idempotency_key) values($1,'tenant.reconcile','tenant-reconciliation',$2,'{}',$3,$4,$5)")
        .bind(Uuid::new_v4()).bind(workshop).bind(user).bind(Uuid::new_v4()).bind(format!("held:{request}")).execute(store.pool()).await;
    assert!(
        blocked.is_err(),
        "an active restriction must block ordinary processing"
    );
    sqlx::query("insert into control.operations(id,kind,queue,payload,requested_by,correlation_id,idempotency_key) values($1,'privacy.data_subject_request','privacy-operations',$2,$3,$4,$5)")
        .bind(Uuid::new_v4()).bind(json!({"request_id":request})).bind(user).bind(Uuid::new_v4()).bind(format!("privacy:{request}")).execute(store.pool()).await.unwrap();
    let processor_task = Uuid::new_v4();
    sqlx::query("insert into control.data_subject_processor_tasks(id,data_subject_request_id,processor_key,action) values($1,$2,'control','restrict')")
        .bind(processor_task).bind(request).execute(store.pool()).await.unwrap();
    sqlx::query("update control.data_subject_processor_tasks set state='acknowledged',acknowledgement_ref='evidence:test',version=version+1 where id=$1 and version=1")
        .bind(processor_task).execute(store.pool()).await.unwrap();
    let stale_task=sqlx::query("update control.data_subject_processor_tasks set state='not_applicable',version=version+1 where id=$1 and version=1")
        .bind(processor_task).execute(store.pool()).await.unwrap();
    assert_eq!(
        stale_task.rows_affected(),
        0,
        "processor evidence uses compare-and-set versions"
    );
    let rewrite_final=sqlx::query("update control.data_subject_processor_tasks set state='not_applicable',version=version+1 where id=$1 and version=2")
        .bind(processor_task).execute(store.pool()).await;
    assert!(
        rewrite_final.is_err(),
        "final processor evidence cannot be rewritten"
    );
    let subject_key: Uuid =
        sqlx::query_scalar("select audit_subject_id from control.users where id=$1")
            .bind(user)
            .fetch_one(store.pool())
            .await
            .unwrap();
    sqlx::query("insert into control.erasure_tombstones(id,subject_key,subject_user_id,source_request_id,required_locations) values($1,$2,$3,$4,array['control','rauthy'])")
        .bind(Uuid::new_v4()).bind(subject_key).bind(user).bind(request).execute(store.pool()).await.unwrap();
    let workshop_tombstone = Uuid::new_v4();
    sqlx::query("insert into control.erasure_tombstones(id,subject_key,subject_user_id,workshop_id,source_request_id,required_locations) values($1,$2,$3,$4,$5,array['odoo','backups'])")
        .bind(workshop_tombstone).bind(subject_key).bind(user).bind(workshop).bind(request).execute(store.pool()).await.unwrap();
    let duplicate_tombstone=sqlx::query("insert into control.erasure_tombstones(id,subject_key,subject_user_id,workshop_id,source_request_id,required_locations) values($1,$2,$3,$4,$5,array['odoo','backups'])")
        .bind(Uuid::new_v4()).bind(subject_key).bind(user).bind(workshop).bind(request).execute(store.pool()).await;
    assert!(
        duplicate_tombstone.is_err(),
        "erasure tombstones are idempotent per request and workshop scope"
    );
    let invalid_lookup = sqlx::query("insert into control.erasure_subject_lookups(tombstone_id,key_id,nonce,ciphertext) values($1,'test-key',$2,$3)")
        .bind(workshop_tombstone).bind(vec![0_u8;11]).bind(vec![0_u8;32]).execute(store.pool()).await;
    assert!(
        invalid_lookup.is_err(),
        "encrypted lookups require a 96-bit AEAD nonce"
    );
    sqlx::query("insert into control.erasure_subject_lookups(tombstone_id,key_id,nonce,ciphertext) values($1,'test-key',$2,$3)")
        .bind(workshop_tombstone).bind(vec![0_u8;12]).bind(vec![0_u8;32]).execute(store.pool()).await.unwrap();
    let database = Uuid::new_v4();
    sqlx::query("insert into control.odoo_databases(id,workshop_id,kind,database_ref,public_hostname,label,routable) values($1,$2,'primary',$3,$4,'Primary',true)")
        .bind(database).bind(workshop).bind(format!("mb_{}",database.simple())).bind(format!("{}.example.test",workshop.simple())).execute(store.pool()).await.unwrap();
    let recovery = Uuid::new_v4();
    sqlx::query("insert into control.workshop_recovery_points(id,workshop_id,database_id,kind,label,requested_by,component_scope) values($1,$2,$3,'backup','Privacy replay fixture',$4,array['odoo'])")
        .bind(recovery).bind(workshop).bind(database).bind(user).execute(store.pool()).await.unwrap();
    let restore_operation = Uuid::new_v4();
    sqlx::query("insert into control.operations(id,kind,queue,workshop_id,payload,correlation_id,idempotency_key) values($1,'tenant.lifecycle','tenant-lifecycle',$2,'{}',$3,$4)")
        .bind(restore_operation).bind(workshop).bind(Uuid::new_v4()).bind(format!("restore:{recovery}")).execute(store.pool()).await.unwrap();
    let replay = Uuid::new_v4();
    sqlx::query("insert into control.erasure_restore_replays(id,tombstone_id,recovery_point_id,operation_id,required_locations) values($1,$2,$3,$4,array['odoo'])")
        .bind(replay).bind(workshop_tombstone).bind(recovery).bind(restore_operation).execute(store.pool()).await.unwrap();
    let premature_complete=sqlx::query("update control.erasure_restore_replays set state='complete',completed_at=now() where id=$1")
        .bind(replay).execute(store.pool()).await;
    assert!(
        premature_complete.is_err(),
        "restore replay cannot complete without every processor location"
    );
    sqlx::query("update control.erasure_restore_replays set state='complete',completed_locations=array['odoo'],completed_at=now() where id=$1")
        .bind(replay).execute(store.pool()).await.unwrap();
    let privacy_enable=sqlx::query("update control.privacy_platform_state set controller_ref='controller',dpia_approval_ref='dpia',approved_retention_policy_version=1,approved_processing_register_version=1,production_personal_data_allowed=true,version=version+1 where singleton")
        .execute(store.pool()).await;
    assert!(
        privacy_enable.is_err(),
        "production cannot start without approved linked records"
    );
    let incident = Uuid::new_v4();
    sqlx::query("insert into control.privacy_incidents(id,discovered_at,controller_awareness_at,affected_categories,containment_state,risk_level,created_by) values($1,'2026-08-14T08:00:00Z','2026-08-14T10:00:00Z',array['identity'],'investigating','undetermined',$2)")
        .bind(incident).bind(user).execute(store.pool()).await.unwrap();
    let deadline: time::OffsetDateTime = sqlx::query_scalar(
        "select authority_deadline_at from control.privacy_incidents where id=$1",
    )
    .bind(incident)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(
        deadline,
        time::OffsetDateTime::parse(
            "2026-08-17T10:00:00Z",
            &time::format_description::well_known::Rfc3339
        )
        .unwrap()
    );
    sqlx::query("update control.privacy_incidents set containment_state='contained',version=version+1 where id=$1 and version=1")
        .bind(incident).execute(store.pool()).await.unwrap();
    let incident_backwards=sqlx::query("update control.privacy_incidents set containment_state='investigating',version=version+1 where id=$1 and version=2")
        .bind(incident).execute(store.pool()).await;
    assert!(
        incident_backwards.is_err(),
        "incident containment cannot move backwards"
    );
    let legal_hold = Uuid::new_v4();
    sqlx::query("insert into control.legal_holds(id,scope,reason_code,approval_ref,imposed_by,expires_at) values($1,$2,'litigation','approval:test',$3,now()+interval '7 days')")
        .bind(legal_hold).bind(json!({"datasets":["operations"],"workshop_ids":[workshop]})).bind(user).execute(store.pool()).await.unwrap();
    let scoped_applies: bool =
        sqlx::query_scalar("select control.legal_hold_applies('operations',$1,array[$2])")
            .bind(workshop)
            .bind(user)
            .fetch_one(store.pool())
            .await
            .unwrap();
    let unrelated_applies: bool =
        sqlx::query_scalar("select control.legal_hold_applies('operations',$1,array[$2])")
            .bind(Uuid::new_v4())
            .bind(user)
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert!(scoped_applies, "the explicitly scoped record is held");
    assert!(
        !unrelated_applies,
        "a legal hold does not leak beyond its workshop scope"
    );
    sqlx::query("update control.legal_holds set released_at=now(),released_by=$2,release_reason_code='matter_closed',version=version+1 where id=$1 and version=1")
        .bind(legal_hold).bind(user).execute(store.pool()).await.unwrap();
    let reopen_hold=sqlx::query("update control.legal_holds set released_at=null,released_by=null,release_reason_code=null,version=version+1 where id=$1 and version=2")
        .bind(legal_hold).execute(store.pool()).await;
    assert!(
        reopen_hold.is_err(),
        "a released legal hold cannot be reopened"
    );
}

#[tokio::test]
#[ignore = "requires a disposable CONTROL_TEST_DATABASE_URL"]
async fn privacy_exports_are_subject_bound_single_use_and_expire() {
    let store = store().await;
    let subject = Uuid::new_v4();
    let other = Uuid::new_v4();
    for user in [subject, other] {
        sqlx::query("insert into control.users(id,email) values($1,$2)")
            .bind(user)
            .bind(format!("{user}@example.test"))
            .execute(store.pool())
            .await
            .unwrap();
    }
    let request = Uuid::new_v4();
    sqlx::query("insert into control.data_subject_requests(id,subject_user_id,request_type) values($1,$2,'access')")
        .bind(request).bind(subject).execute(store.pool()).await.unwrap();
    let export = Uuid::new_v4();
    sqlx::query("insert into control.data_subject_exports(id,data_subject_request_id,storage_ref,encryption_key_ref,manifest_digest,state,ready_at,expires_at,nonce,ciphertext,plaintext_size,filename) values($1,$2,$3,'test-export-key',$4,'ready',now(),now()+interval '7 days',$5,$6,16,$7)")
        .bind(export).bind(request).bind(format!("postgres:aead:{export}"))
        .bind(format!("sha256:{}", "a".repeat(64))).bind(vec![0_u8;12])
        .bind(vec![1_u8;32]).bind(format!("privacy-export-{export}.json"))
        .execute(store.pool()).await.unwrap();
    let denied = sqlx::query_scalar::<_, Uuid>(
        "select export_id from control.consume_data_subject_export($1,$2)",
    )
    .bind(export)
    .bind(other)
    .fetch_optional(store.pool())
    .await
    .unwrap();
    assert!(denied.is_none(), "another subject cannot redeem the export");
    let consumed = sqlx::query_scalar::<_, Uuid>(
        "select export_id from control.consume_data_subject_export($1,$2)",
    )
    .bind(export)
    .bind(subject)
    .fetch_optional(store.pool())
    .await
    .unwrap();
    assert_eq!(consumed, Some(export));
    let retained_ciphertext: Option<Vec<u8>> =
        sqlx::query_scalar("select ciphertext from control.data_subject_exports where id=$1")
            .bind(export)
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert!(
        retained_ciphertext.is_none(),
        "consumption wipes ciphertext"
    );
    let replay = sqlx::query_scalar::<_, Uuid>(
        "select export_id from control.consume_data_subject_export($1,$2)",
    )
    .bind(export)
    .bind(subject)
    .fetch_optional(store.pool())
    .await
    .unwrap();
    assert!(
        replay.is_none(),
        "a consumed export cannot be redeemed twice"
    );

    let file_request = Uuid::new_v4();
    sqlx::query("insert into control.data_subject_requests(id,subject_user_id,request_type) values($1,$2,'portability')")
        .bind(file_request).bind(subject).execute(store.pool()).await.unwrap();
    let file_export = Uuid::new_v4();
    let file_ref = format!("file:{file_export}.aead");
    sqlx::query("insert into control.data_subject_exports(id,data_subject_request_id,storage_ref,encryption_key_ref,manifest_digest,state,ready_at,expires_at,nonce,ciphertext,plaintext_size,filename) values($1,$2,$3,'test-export-key',$4,'ready',now(),now()+interval '7 days',$5,null,16,$6)")
        .bind(file_export).bind(file_request).bind(&file_ref)
        .bind(format!("sha256:{}", "c".repeat(64))).bind(vec![0_u8;12])
        .bind(format!("privacy-export-{file_export}.json"))
        .execute(store.pool()).await.unwrap();
    let file_payload = sqlx::query_as::<_, (Uuid, String, Option<Vec<u8>>)>(
        "select export_id,storage_ref,ciphertext
         from control.consume_data_subject_export($1,$2)",
    )
    .bind(file_export)
    .bind(subject)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(file_payload, (file_export, file_ref, None));
    let database_body: Option<Vec<u8>> =
        sqlx::query_scalar("select ciphertext from control.data_subject_exports where id=$1")
            .bind(file_export)
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert!(
        database_body.is_none(),
        "external processor bodies never enter control PostgreSQL"
    );

    let expired_request = Uuid::new_v4();
    sqlx::query("insert into control.data_subject_requests(id,subject_user_id,request_type) values($1,$2,'portability')")
        .bind(expired_request).bind(subject).execute(store.pool()).await.unwrap();
    let expired = Uuid::new_v4();
    sqlx::query("insert into control.data_subject_exports(id,data_subject_request_id,storage_ref,encryption_key_ref,manifest_digest,state,ready_at,expires_at,created_at,nonce,ciphertext,plaintext_size,filename) values($1,$2,$3,'test-export-key',$4,'ready',now()-interval '2 days',now()-interval '1 day',now()-interval '3 days',$5,$6,16,$7)")
        .bind(expired).bind(expired_request).bind(format!("postgres:aead:{expired}"))
        .bind(format!("sha256:{}", "b".repeat(64))).bind(vec![0_u8;12])
        .bind(vec![1_u8;32]).bind(format!("privacy-export-{expired}.json"))
        .execute(store.pool()).await.unwrap();
    let unavailable = sqlx::query_scalar::<_, Uuid>(
        "select export_id from control.consume_data_subject_export($1,$2)",
    )
    .bind(expired)
    .bind(subject)
    .fetch_optional(store.pool())
    .await
    .unwrap();
    assert!(unavailable.is_none());
    let state: String =
        sqlx::query_scalar("select state from control.data_subject_exports where id=$1")
            .bind(expired)
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert_eq!(state, "expired");
    let expired_ciphertext: Option<Vec<u8>> =
        sqlx::query_scalar("select ciphertext from control.data_subject_exports where id=$1")
            .bind(expired)
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert!(expired_ciphertext.is_none(), "expiry wipes ciphertext");
}

#[tokio::test]
#[ignore = "requires a disposable CONTROL_TEST_DATABASE_URL"]
async fn platform_authority_is_role_based_and_bootstrap_is_one_way() {
    let store = store().await;
    let user = Uuid::new_v4();
    sqlx::query("insert into control.users(id,email) values($1,$2)")
        .bind(user)
        .bind(format!("{user}@example.test"))
        .execute(store.pool())
        .await
        .unwrap();
    sqlx::query("insert into control.platform_role_assignments(id,user_id,role,granted_by,grant_reason_code) values($1,$2,'technical_admin',$2,'initial_project_owner')")
        .bind(Uuid::new_v4())
        .bind(user)
        .execute(store.pool())
        .await
        .unwrap();
    assert!(
        sqlx::query("insert into control.platform_role_assignments(id,user_id,role,granted_by,grant_reason_code) values($1,$2,'root',$2,'invalid')")
            .bind(Uuid::new_v4())
            .bind(user)
            .execute(store.pool())
            .await
            .is_err(),
        "unknown platform roles must be rejected by PostgreSQL"
    );
    sqlx::query("update control.platform_authority_state set initial_admin_bootstrapped=true,bootstrapped_at=now() where singleton")
        .execute(store.pool())
        .await
        .unwrap();
    assert!(
        sqlx::query("update control.platform_authority_state set initial_admin_bootstrapped=false where singleton")
            .execute(store.pool())
            .await
            .is_err(),
        "bootstrap state cannot be reopened without explicit forward repair"
    );
}

#[tokio::test]
#[ignore = "requires a disposable CONTROL_TEST_DATABASE_URL"]
async fn product_lookup_fill_lease_has_one_owner_and_can_be_recovered() {
    let store = store().await;
    let first = Uuid::new_v4();
    let second = Uuid::new_v4();
    let acquire = |owner: Uuid| {
        sqlx::query_scalar::<_, Uuid>(
            "insert into control.product_lookup_fills(provider,schema_version,gtin14,state,leased_by,lease_expires_at)
             values('upcitemdb',1,'00000000000000','filling',$1,now()+interval '20 seconds')
             on conflict(provider,schema_version,gtin14) do update set
               state='filling',leased_by=excluded.leased_by,lease_expires_at=excluded.lease_expires_at,updated_at=now()
             where control.product_lookup_fills.state<>'filling' or control.product_lookup_fills.lease_expires_at<=now()
             returning leased_by",
        )
        .bind(owner)
        .fetch_optional(store.pool())
    };
    assert_eq!(acquire(first).await.unwrap(), Some(first));
    assert_eq!(acquire(second).await.unwrap(), None);
    sqlx::query("update control.product_lookup_fills set lease_expires_at=now()-interval '1 second' where leased_by=$1")
        .bind(first)
        .execute(store.pool())
        .await
        .unwrap();
    assert_eq!(acquire(second).await.unwrap(), Some(second));
}

#[tokio::test]
#[ignore = "requires a disposable CONTROL_TEST_DATABASE_URL"]
async fn worker_heartbeat_records_activity_and_graceful_shutdown() {
    let store = store().await;
    let worker = format!("privacy-operations-{}", Uuid::new_v4());
    store
        .start_worker(&worker, "privacy-operations", "test-release")
        .await
        .unwrap();
    assert!(store.heartbeat_worker(&worker, None).await.unwrap());
    store.shutdown_worker(&worker).await.unwrap();
    let row = sqlx::query_as::<_, (String, bool)>(
        "select release_id,shutdown_at is not null from control.worker_heartbeats where worker_id=$1",
    )
    .bind(&worker)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(row, ("test-release".to_owned(), true));
    assert!(!store.heartbeat_worker(&worker, None).await.unwrap());
}
