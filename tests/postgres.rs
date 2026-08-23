use mb_control_plane::command::{
    CommandAdmission, CommandError, CommandResult, NewCommand, admit_command, complete_command,
};
use mb_control_plane::domain::OperationKind;
use mb_control_plane::modules::{CATALOG, REGISTRY_VERSION};
use mb_control_plane::persistence::{NewOperation, Store};
use opentelemetry::trace::TracerProvider as _;
use serde_json::{Value, json};
use sqlx::AssertSqlSafe;
use sqlx::postgres::PgPoolOptions;
use tracing::Instrument as _;
use tracing_opentelemetry::OpenTelemetrySpanExt as _;
use tracing_subscriber::layer::SubscriberExt as _;
use uuid::Uuid;

async fn store() -> Store {
    let url = std::env::var("CONTROL_TEST_DATABASE_URL").expect("CONTROL_TEST_DATABASE_URL");
    let store = Store::connect(&url).await.expect("connect test PostgreSQL");
    store.migrate().await.expect("migrate test PostgreSQL");
    store
}

#[derive(Clone)]
struct ReleaseDriverLeaseCall {
    control_operation_id: Uuid,
    control_operation_attempt: i32,
    control_operation_owner: String,
    idempotency_key: String,
    target_key: String,
    fleet_run_id: Option<Uuid>,
    request_digest: String,
    instance_owner: Uuid,
    execution_token: Uuid,
    resource_lease_token: Uuid,
}

type ReleaseDriverAdmissionRow = (
    String,
    Option<Uuid>,
    Option<i64>,
    Option<serde_json::Value>,
    Option<Vec<Uuid>>,
);

async fn insert_leased_release_operation(
    pool: &sqlx::PgPool,
    owner: &str,
) -> ReleaseDriverLeaseCall {
    let control_operation_id = Uuid::new_v4();
    let release_suffix = Uuid::new_v4().simple().to_string();
    let release_id = format!("odoo-2026.08.22-{}", &release_suffix[..12]);
    sqlx::query(
        "insert into control.operations(
           id,kind,queue,payload,correlation_id,idempotency_key,state,attempt,
           leased_by,lease_expires_at
         ) values($1,'odoo.release.adopt','release-adoption',$2,$3,$4,
                  'in_flight',1,$5,now()+interval '20 minutes')",
    )
    .bind(control_operation_id)
    .bind(json!({"phase":"preflight", "release_id":release_id}))
    .bind(Uuid::new_v4())
    .bind(format!("release-driver-control:{control_operation_id}"))
    .bind(owner)
    .execute(pool)
    .await
    .unwrap();
    ReleaseDriverLeaseCall {
        control_operation_id,
        control_operation_attempt: 1,
        control_operation_owner: owner.to_owned(),
        idempotency_key: format!("release-driver-request:{}", Uuid::new_v4()),
        target_key: format!("initial/{release_id}"),
        fleet_run_id: None,
        request_digest: "a".repeat(64),
        instance_owner: Uuid::new_v4(),
        execution_token: Uuid::new_v4(),
        resource_lease_token: Uuid::new_v4(),
    }
}

async fn attach_release_fleet_run(
    pool: &sqlx::PgPool,
    call: &mut ReleaseDriverLeaseCall,
    workshops: &[Uuid],
) -> Vec<Uuid> {
    let suffix = Uuid::new_v4().simple().to_string();
    let release_id = format!("odoo-2026.08.22-{}", &suffix[..12]);
    let fleet_run_id = Uuid::new_v4();
    let unique_hex = format!("{suffix}{suffix}");
    let subject_digest = format!("sha256:{unique_hex}");
    sqlx::query(
        "insert into control.application_releases(
           id,source_commit,odoo_version,odoo_subject_digest,extension_subject_digest,
           odoo_runtime,extension_bundle,pair_qualifications,manifest_digest,addon_versions,
           compatibility,bridge_contract,schema_epoch,change_class,
           required_postconditions,manifest,signature_bundle_ref,extension_signature_ref,
           sbom_ref,published_at,publication_idempotency_key,publication_request_digest
         ) values($1,$2,'19.0',$3,$3,'{}','{}','[{}]',$3,'{}','{}','>=3.2.0,<4.0.0',42,'B',
                  '[]','{}','oci://signature','oci://extension-signature','oci://sbom',now(),$4,$5)",
    )
    .bind(&release_id)
    .bind(&unique_hex)
    .bind(&subject_digest)
    .bind(format!("route-reservation:{release_id}"))
    .bind(vec![4_u8; 32])
    .execute(pool)
    .await
    .unwrap();
    let snapshot = workshops
        .iter()
        .map(|workshop| {
            let database_id = Uuid::new_v4();
            (
                *workshop,
                database_id,
                json!({
                    "workshop_id": workshop,
                    "database_id": database_id,
                    "database_ref": format!("mb_{}", workshop.simple()),
                    "paperless_enabled": false
                }),
            )
        })
        .collect::<Vec<_>>();
    sqlx::query(
        "insert into control.release_fleet_runs(
           id,release_id,operation_id,fleet_generation,state,tenant_snapshot
         ) values($1,$2,$3,1,'preparing',$4)",
    )
    .bind(fleet_run_id)
    .bind(&release_id)
    .bind(call.control_operation_id)
    .bind(json!(
        snapshot.iter().map(|entry| &entry.2).collect::<Vec<_>>()
    ))
    .execute(pool)
    .await
    .unwrap();
    for (workshop, database_id, _) in &snapshot {
        sqlx::query(
            "insert into control.odoo_databases(
               id,workshop_id,kind,database_ref,public_hostname,label,state,routable
             ) values($1,$2,'primary',$3,$4,'Fleet route database','ready',true)",
        )
        .bind(database_id)
        .bind(workshop)
        .bind(format!("mb_{}", workshop.simple()))
        .bind(format!("{}.fleet-release.example.test", workshop.simple()))
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "insert into control.tenant_release_adoptions(
               id,workshop_id,database_id,release_id,registry_version,state,
               operation_id,target_schema_epoch
             ) values($1,$2,$3,$4,1,'pending',$5,42)",
        )
        .bind(Uuid::new_v4())
        .bind(workshop)
        .bind(database_id)
        .bind(&release_id)
        .bind(call.control_operation_id)
        .execute(pool)
        .await
        .unwrap();
    }
    sqlx::query("update control.operations set payload=$2 where id=$1")
        .bind(call.control_operation_id)
        .bind(json!({"phase":"adopt", "release_id":release_id}))
        .execute(pool)
        .await
        .unwrap();
    call.fleet_run_id = Some(fleet_run_id);
    call.target_key = format!("fleet/{fleet_run_id}");
    let mut reserved = workshops.to_vec();
    reserved.sort_unstable();
    reserved
}

async fn admit_release_driver_lease(
    pool: &sqlx::PgPool,
    call: &ReleaseDriverLeaseCall,
) -> ReleaseDriverAdmissionRow {
    sqlx::query_as(
        "select outcome,driver_operation_id,fence_token,stored_response,reserved_workshops
         from control.admit_release_driver_operation($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
    )
    .bind(call.control_operation_id)
    .bind(call.control_operation_attempt)
    .bind(&call.control_operation_owner)
    .bind(&call.idempotency_key)
    .bind(&call.target_key)
    .bind(call.fleet_run_id)
    .bind(&call.request_digest)
    .bind(call.instance_owner)
    .bind(call.execution_token)
    .bind(call.resource_lease_token)
    .bind(300_i32)
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn admit_release_route_snapshot_v2(
    pool: &sqlx::PgPool,
    call: &ReleaseDriverLeaseCall,
) -> ReleaseDriverAdmissionRow {
    sqlx::query_as(
        "select outcome,driver_operation_id,fence_token,stored_response,reserved_workshops
         from control.admit_release_driver_operation(
           $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,300,1::smallint,2::smallint)",
    )
    .bind(call.control_operation_id)
    .bind(call.control_operation_attempt)
    .bind(&call.control_operation_owner)
    .bind(&call.idempotency_key)
    .bind(&call.target_key)
    .bind(call.fleet_run_id)
    .bind(&call.request_digest)
    .bind(call.instance_owner)
    .bind(call.execution_token)
    .bind(call.resource_lease_token)
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn finish_release_driver_lease(
    pool: &sqlx::PgPool,
    call: &ReleaseDriverLeaseCall,
    driver_operation_id: Uuid,
    fence_token: i64,
    response: &serde_json::Value,
) -> bool {
    sqlx::query_scalar(
        "select control.finish_release_driver_operation($1,$2,$3,$4,$5,'succeeded',$6,null)",
    )
    .bind(driver_operation_id)
    .bind(call.instance_owner)
    .bind(call.execution_token)
    .bind(call.resource_lease_token)
    .bind(fence_token)
    .bind(response)
    .fetch_one(pool)
    .await
    .unwrap()
}

#[derive(Clone)]
struct RouteControlOperation {
    id: Uuid,
    attempt: i32,
    owner: String,
    workshop: Uuid,
}

#[derive(Clone)]
struct RouteApplicationCall {
    control: RouteControlOperation,
    idempotency_key: String,
    request_digest: String,
    generation: i64,
    projection_digest: String,
    instance_owner: Uuid,
    execution_token: Uuid,
    resource_lease_token: Uuid,
}

type RouteProjectionRow = (
    String,
    Option<i64>,
    Option<String>,
    Option<serde_json::Value>,
);
type RouteApplicationRow = (String, Option<Uuid>, Option<i64>, Option<serde_json::Value>);
type AppliedRouteRow = (
    Option<i64>,
    Option<String>,
    Option<String>,
    Option<Uuid>,
    Option<i64>,
);
type RecoverySnapshotBatchRow = (
    String,
    Option<Uuid>,
    Option<Uuid>,
    Option<String>,
    Option<bool>,
    Option<i64>,
    Option<String>,
    Option<String>,
    Option<Value>,
    Option<String>,
    Option<i64>,
    Option<i64>,
    Option<String>,
);

async fn insert_route_control_operation(
    pool: &sqlx::PgPool,
    workshop: Uuid,
    owner: &str,
) -> RouteControlOperation {
    let id = Uuid::new_v4();
    sqlx::query(
        "insert into control.operations(
            id,kind,queue,workshop_id,payload,correlation_id,idempotency_key,
            state,attempt,leased_by,lease_expires_at
         ) values($1,'webshop-domain.reconcile','tenant-reconciliation',$2,'{}',$3,$4,
                  'in_flight',1,$5,now()+interval '20 minutes')",
    )
    .bind(id)
    .bind(workshop)
    .bind(Uuid::new_v4())
    .bind(format!("route-control:{id}"))
    .bind(owner)
    .execute(pool)
    .await
    .unwrap();
    RouteControlOperation {
        id,
        attempt: 1,
        owner: owner.to_owned(),
        workshop,
    }
}

struct ProviderDeletionFixture {
    operation: Uuid,
    workshop: Uuid,
    domain: Uuid,
    provider_ref: String,
    hostname: String,
}

async fn insert_provider_deletion_fixture(
    pool: &sqlx::PgPool,
    owner: &str,
) -> ProviderDeletionFixture {
    let user = Uuid::new_v4();
    let workshop = Uuid::new_v4();
    let operation = Uuid::new_v4();
    let domain = Uuid::new_v4();
    let hostname = format!("{}.delete.example.test", domain.simple());
    let provider_ref = domain.simple().to_string();
    sqlx::query("insert into control.users(id,email) values($1,$2)")
        .bind(user)
        .bind(format!("provider-delete-{user}@example.test"))
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("insert into control.workshops(id,slug,display_name,time_zone) values($1,$2,'Provider deletion fixture','Europe/Paris')")
        .bind(workshop)
        .bind(format!("provider-delete-{}", workshop.simple()))
        .execute(pool)
        .await
        .unwrap();
    sqlx::query(
        "insert into control.operations(
           id,kind,queue,workshop_id,payload,correlation_id,idempotency_key,
           state,attempt,leased_by,lease_expires_at
         ) values($1,'webshop-domain.reconcile','tenant-reconciliation',$2,$3,$4,$5,
                  'in_flight',1,$6,now()+interval '20 minutes')",
    )
    .bind(operation)
    .bind(workshop)
    .bind(json!({"domain_id":domain,"reason":"provider_deletion_test"}))
    .bind(Uuid::new_v4())
    .bind(format!("provider-deletion:{domain}"))
    .bind(owner)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "insert into control.webshop_domains(
           id,workshop_id,hostname,verification_name,verification_value,routing_target,
           state,desired_state,ownership_verified_at,provider_ref,operation_id,created_by
         ) values($1,$2,$3,$4,$5,'shops.example.test','disconnecting','disconnected',
                  now(),$6,$7,$8)",
    )
    .bind(domain)
    .bind(workshop)
    .bind(&hostname)
    .bind(format!("_mb-challenge.{hostname}"))
    .bind(format!("mb-verification={}", domain.simple()))
    .bind(&provider_ref)
    .bind(operation)
    .bind(user)
    .execute(pool)
    .await
    .unwrap();
    ProviderDeletionFixture {
        operation,
        workshop,
        domain,
        provider_ref,
        hostname,
    }
}

async fn advance_provider_deletion(
    pool: &sqlx::PgPool,
    fixture: &ProviderDeletionFixture,
    attempt: i32,
    owner: &str,
    action: &str,
) -> Result<(String, i32, i32, bool), sqlx::Error> {
    sqlx::query_as(
        "select deletion_state,observation_count,delete_dispatch_count,dispatch_authorized
           from control.advance_webshop_domain_provider_deletion($1,$2,$3,$4,$5,$6,$7,$8)",
    )
    .bind(fixture.operation)
    .bind(attempt)
    .bind(owner)
    .bind(fixture.workshop)
    .bind(fixture.domain)
    .bind(&fixture.provider_ref)
    .bind(&fixture.hostname)
    .bind(action)
    .fetch_one(pool)
    .await
}

async fn materialize_route_projection(
    pool: &sqlx::PgPool,
    control: &RouteControlOperation,
    projection: &serde_json::Value,
    digest: &str,
) -> RouteProjectionRow {
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("set transaction isolation level repeatable read")
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query_scalar::<_, i64>("select control.lock_workshop_route_projection($1,$2,$3,$4)")
        .bind(control.id)
        .bind(control.attempt)
        .bind(&control.owner)
        .bind(control.workshop)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    let row = sqlx::query_as(
        "select outcome,generation,projection_digest,projection
           from control.materialize_workshop_route_projection($1,$2,$3,$4,$5,$6)",
    )
    .bind(control.id)
    .bind(control.attempt)
    .bind(&control.owner)
    .bind(control.workshop)
    .bind(projection)
    .bind(digest)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    row
}

async fn admit_route_application(
    pool: &sqlx::PgPool,
    call: &RouteApplicationCall,
) -> RouteApplicationRow {
    sqlx::query_as(
        "select outcome,driver_operation_id,fence_token,stored_response
           from control.admit_workshop_route_application(
             $1,$2,$3,$4,'route-project',$5,$6,$7,$8,$9,$10,$11,300)",
    )
    .bind(call.control.id)
    .bind(call.control.attempt)
    .bind(&call.control.owner)
    .bind(call.control.workshop)
    .bind(&call.idempotency_key)
    .bind(&call.request_digest)
    .bind(call.generation)
    .bind(&call.projection_digest)
    .bind(call.instance_owner)
    .bind(call.execution_token)
    .bind(call.resource_lease_token)
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn finish_route_application(
    pool: &sqlx::PgPool,
    call: &RouteApplicationCall,
    driver_operation: Uuid,
    fence: i64,
    result: (&str, Option<&serde_json::Value>, Option<&str>, Option<&str>),
) -> bool {
    sqlx::query_scalar(
        "select control.finish_workshop_route_application(
            $1,$2,$3,$4,$5,$6,$7,$8,$9)",
    )
    .bind(driver_operation)
    .bind(call.instance_owner)
    .bind(call.execution_token)
    .bind(call.resource_lease_token)
    .bind(fence)
    .bind(result.0)
    .bind(result.1)
    .bind(result.2)
    .bind(result.3)
    .fetch_one(pool)
    .await
    .unwrap()
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
async fn webshop_domain_periodic_claim_is_atomic_bounded_and_tenant_bound() {
    let store = store().await;
    let database_url =
        std::env::var("CONTROL_TEST_DATABASE_URL").expect("CONTROL_TEST_DATABASE_URL");
    let first_pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&database_url)
        .await
        .expect("connect first independent claim pool");
    let second_pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&database_url)
        .await
        .expect("connect second independent claim pool");

    for invalid_limit in [0_i32, 501_i32] {
        let error = sqlx::query(
            "select * from control.admit_due_webshop_domain_reconciliations($1,null,null)",
        )
        .bind(invalid_limit)
        .execute(&first_pool)
        .await
        .expect_err("an out-of-contract claim limit must be rejected");
        assert_eq!(
            error.as_database_error().and_then(|error| error.code()),
            Some(std::borrow::Cow::Borrowed("22023")),
        );
    }

    let user = Uuid::new_v4();
    sqlx::query("insert into control.users(id,email) values($1,$2)")
        .bind(user)
        .bind(format!("domain-claim-{user}@example.test"))
        .execute(store.pool())
        .await
        .unwrap();
    let first_workshop = Uuid::new_v4();
    let second_workshop = Uuid::new_v4();
    for workshop in [first_workshop, second_workshop] {
        sqlx::query("insert into control.workshops(id,slug,display_name,time_zone) values($1,$2,'Domain claim fixture','Europe/Paris')")
            .bind(workshop)
            .bind(format!("domain-claim-{}", workshop.simple()))
            .execute(store.pool())
            .await
            .unwrap();
    }

    let first_domain = Uuid::new_v4();
    let second_domain = Uuid::new_v4();
    for (domain, workshop) in [
        (first_domain, first_workshop),
        (second_domain, second_workshop),
    ] {
        let hostname = format!("{}.claim.example.test", domain.simple());
        sqlx::query(
            "insert into control.webshop_domains(
                id,workshop_id,hostname,verification_name,verification_value,
                routing_target,state,ownership_verified_at,created_by
             ) values($1,$2,$3,$4,$5,'shops.makersbrain.com','dns_pending',now(),$6)",
        )
        .bind(domain)
        .bind(workshop)
        .bind(&hostname)
        .bind(format!("_mb-challenge.{hostname}"))
        .bind(format!("mb-verification={}", domain.simple()))
        .bind(user)
        .execute(store.pool())
        .await
        .unwrap();
    }

    let active_operation = Uuid::new_v4();
    let active_domain = Uuid::new_v4();
    sqlx::query(
        "insert into control.operations(
            id,kind,queue,workshop_id,payload,correlation_id,idempotency_key
         ) values($1,'webshop-domain.reconcile','tenant-reconciliation',$2,$3,$4,$5)",
    )
    .bind(active_operation)
    .bind(first_workshop)
    .bind(json!({"domain_id":active_domain,"reason":"already_active"}))
    .bind(Uuid::new_v4())
    .bind(format!("active-domain-claim:{active_domain}"))
    .execute(store.pool())
    .await
    .unwrap();
    let active_hostname = format!("{}.claim.example.test", active_domain.simple());
    sqlx::query(
        "insert into control.webshop_domains(
            id,workshop_id,hostname,verification_name,verification_value,
            routing_target,state,ownership_verified_at,created_by,operation_id
         ) values($1,$2,$3,$4,$5,'shops.makersbrain.com','dns_pending',now(),$6,$7)",
    )
    .bind(active_domain)
    .bind(first_workshop)
    .bind(&active_hostname)
    .bind(format!("_mb-challenge.{active_hostname}"))
    .bind(format!("mb-verification={}", active_domain.simple()))
    .bind(user)
    .bind(active_operation)
    .execute(store.pool())
    .await
    .unwrap();
    let active_version: i64 =
        sqlx::query_scalar("select version from control.webshop_domains where id=$1")
            .bind(active_domain)
            .fetch_one(store.pool())
            .await
            .unwrap();

    let trace_parent = "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01";
    let trace_state = "mb=test";
    let first_claim = sqlx::query_as::<_, (Uuid, Uuid, Uuid)>(
        "select operation_id,workshop_id,domain_id
           from control.admit_due_webshop_domain_reconciliations(1,$1,$2)",
    )
    .bind(trace_parent)
    .bind(trace_state)
    .fetch_all(&first_pool);
    let second_claim = sqlx::query_as::<_, (Uuid, Uuid, Uuid)>(
        "select operation_id,workshop_id,domain_id
           from control.admit_due_webshop_domain_reconciliations(1,$1,$2)",
    )
    .bind(trace_parent)
    .bind(trace_state)
    .fetch_all(&second_pool);
    let (first_claim, second_claim) = tokio::join!(first_claim, second_claim);
    let mut claims = first_claim.unwrap();
    assert_eq!(
        claims.len(),
        1,
        "one call may not exceed its requested limit"
    );
    let second_claim = second_claim.unwrap();
    assert_eq!(
        second_claim.len(),
        1,
        "the independent caller must skip the locked first candidate"
    );
    claims.extend(second_claim);

    claims.sort_by_key(|claim| claim.2);
    let mut claimed_domains = claims.iter().map(|claim| claim.2).collect::<Vec<_>>();
    claimed_domains.sort_unstable();
    let mut expected_domains = vec![first_domain, second_domain];
    expected_domains.sort_unstable();
    assert_eq!(claimed_domains, expected_domains);
    assert_ne!(
        claims[0].0, claims[1].0,
        "each domain needs its own operation"
    );

    for (operation, workshop, domain) in &claims {
        let bound = sqlx::query_as::<_, (Uuid, Uuid, String, String, serde_json::Value)>(
            "select d.operation_id,o.workshop_id,o.trace_parent,o.trace_state,o.payload
               from control.webshop_domains d
               join control.operations o on o.id=d.operation_id
              where d.id=$1 and d.workshop_id=$2",
        )
        .bind(domain)
        .bind(workshop)
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(bound.0, *operation);
        assert_eq!(bound.1, *workshop);
        assert_eq!(bound.2, trace_parent);
        assert_eq!(bound.3, trace_state);
        assert_eq!(
            bound.4,
            json!({
                "domain_id":domain,
                "reason":"periodic_observation",
                "restore_platform_canonical":false
            })
        );
    }

    let orphaned: i64 = sqlx::query_scalar(
        "select count(*)
           from control.operations operation
          where operation.id=any($1)
            and not exists (
                select 1 from control.webshop_domains domain
                 where domain.operation_id=operation.id
            )",
    )
    .bind(claims.iter().map(|claim| claim.0).collect::<Vec<_>>())
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(orphaned, 0, "claiming must not leave an unbound operation");

    let active_after = sqlx::query_as::<_, (Option<Uuid>, i64)>(
        "select operation_id,version from control.webshop_domains where id=$1",
    )
    .bind(active_domain)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(active_after, (Some(active_operation), active_version));

    let cross_tenant_operation = claims
        .iter()
        .find(|claim| claim.1 == first_workshop)
        .expect("the first workshop domain was claimed")
        .0;
    let cross_tenant_domain = claims
        .iter()
        .find(|claim| claim.1 == second_workshop)
        .expect("the second workshop domain was claimed")
        .2;
    let crossed = sqlx::query("update control.webshop_domains set operation_id=$2 where id=$1")
        .bind(cross_tenant_domain)
        .bind(cross_tenant_operation)
        .execute(store.pool())
        .await
        .expect_err("a domain cannot bind another workshop's operation");
    assert_eq!(
        crossed
            .as_database_error()
            .and_then(|error| error.constraint()),
        Some("webshop_domains_operation_workshop_fkey")
    );

    first_pool.close().await;
    second_pool.close().await;
}

#[tokio::test]
#[ignore = "requires a disposable CONTROL_TEST_DATABASE_URL"]
async fn webshop_domain_cursor_advances_across_same_bucket_conflicts_and_wraps() {
    let store = store().await;
    let preexisting = sqlx::query_as::<_, (Uuid, Uuid)>(
        "select domain.id,domain.workshop_id
           from control.webshop_domains domain
          where ((domain.desired_state='active'
                  and domain.state in ('dns_pending','certificate_pending','testing')
                  and domain.ownership_verified_at is not null)
              or (domain.desired_state='disconnected'
                  and domain.state in ('disconnecting','action_required')))
            and not exists (
                select 1 from control.operations operation
                 where operation.id=domain.operation_id
                   and operation.state in ('pending','in_flight','awaiting_reconciliation')
            )",
    )
    .fetch_all(store.pool())
    .await
    .unwrap();
    for (domain, workshop) in preexisting {
        let operation = Uuid::new_v4();
        sqlx::query(
            "insert into control.operations(
                id,kind,queue,workshop_id,payload,correlation_id,idempotency_key
             ) values($1,'webshop-domain.reconcile','tenant-reconciliation',$2,$3,$4,$5)",
        )
        .bind(operation)
        .bind(workshop)
        .bind(json!({"domain_id":domain,"reason":"cursor_test_isolation"}))
        .bind(Uuid::new_v4())
        .bind(format!("cursor-test-isolation:{domain}:{}", Uuid::new_v4()))
        .execute(store.pool())
        .await
        .unwrap();
        sqlx::query(
            "update control.webshop_domains set operation_id=$2 where id=$1 and workshop_id=$3",
        )
        .bind(domain)
        .bind(operation)
        .bind(workshop)
        .execute(store.pool())
        .await
        .unwrap();
    }
    let user = Uuid::new_v4();
    sqlx::query("insert into control.users(id,email) values($1,$2)")
        .bind(user)
        .bind(format!("domain-cursor-{user}@example.test"))
        .execute(store.pool())
        .await
        .unwrap();

    let mut domains = Vec::new();
    for _ in 0..3 {
        let workshop = Uuid::new_v4();
        let domain = Uuid::new_v4();
        sqlx::query(
            "insert into control.workshops(id,slug,display_name,time_zone)
             values($1,$2,'Domain cursor fixture','Europe/Paris')",
        )
        .bind(workshop)
        .bind(format!("domain-cursor-{}", workshop.simple()))
        .execute(store.pool())
        .await
        .unwrap();
        let hostname = format!("{}.cursor.example.test", domain.simple());
        sqlx::query(
            "insert into control.webshop_domains(
                id,workshop_id,hostname,verification_name,verification_value,
                routing_target,state,ownership_verified_at,created_by
             ) values($1,$2,$3,$4,$5,'shops.makersbrain.com','dns_pending',now(),$6)",
        )
        .bind(domain)
        .bind(workshop)
        .bind(&hostname)
        .bind(format!("_mb-challenge.{hostname}"))
        .bind(format!("mb-verification={}", domain.simple()))
        .bind(user)
        .execute(store.pool())
        .await
        .unwrap();
        domains.push(domain);
    }
    domains.sort_unstable();
    sqlx::query(
        "update control.periodic_admission_cursors
         set after_id=null where workflow='webshop-domain'",
    )
    .execute(store.pool())
    .await
    .unwrap();

    let mut operations = Vec::new();
    for expected in &domains {
        let claimed = sqlx::query_as::<_, (Uuid, Uuid)>(
            "select operation_id,domain_id
               from control.admit_due_webshop_domain_reconciliations(1,null,null)",
        )
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(
            claimed.1, *expected,
            "the cursor must advance in UUID order"
        );
        operations.push(claimed.0);
    }
    sqlx::query(
        "update control.operations set state='succeeded',finished_at=now()
         where id=any($1)",
    )
    .bind(&operations)
    .execute(store.pool())
    .await
    .unwrap();
    sqlx::query(
        "update control.periodic_admission_cursors
         set after_id=null where workflow='webshop-domain'",
    )
    .execute(store.pool())
    .await
    .unwrap();

    for expected in domains.iter().chain(domains.first()) {
        let claimed = sqlx::query_as::<_, (Uuid, Uuid, Uuid)>(
            "select operation_id,workshop_id,domain_id
               from control.admit_due_webshop_domain_reconciliations(1,null,null)",
        )
        .fetch_all(store.pool())
        .await
        .unwrap();
        assert!(
            claimed.is_empty(),
            "a terminal operation from the same bucket must not be rebound"
        );
        let cursor: Option<Uuid> = sqlx::query_scalar(
            "select after_id from control.periodic_admission_cursors
             where workflow='webshop-domain'",
        )
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(cursor, Some(*expected));
    }

    sqlx::query(
        "update control.webshop_domains
         set ownership_verified_at=null
         where id=any($1)",
    )
    .bind(&domains)
    .execute(store.pool())
    .await
    .unwrap();
    sqlx::query(
        "update control.periodic_admission_cursors
         set after_id=null where workflow='webshop-domain'",
    )
    .execute(store.pool())
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "requires a disposable CONTROL_TEST_DATABASE_URL"]
async fn provider_deletion_is_attempt_fenced_single_dispatch_and_globally_bounded() {
    let store = store().await;
    let pool = store.pool();
    let owner = "provider-delete-owner";
    let mut fixture = insert_provider_deletion_fixture(pool, owner).await;

    let stale = advance_provider_deletion(pool, &fixture, 1, "stale-owner", "begin")
        .await
        .expect_err("a stale lease owner must not claim provider deletion");
    assert_eq!(
        stale.as_database_error().and_then(|error| error.code()),
        Some(std::borrow::Cow::Borrowed("40001"))
    );

    advance_provider_deletion(pool, &fixture, 1, owner, "begin")
        .await
        .unwrap();
    advance_provider_deletion(pool, &fixture, 1, owner, "observe_present")
        .await
        .unwrap();
    let first = advance_provider_deletion(pool, &fixture, 1, owner, "dispatch_delete");
    let duplicate = advance_provider_deletion(pool, &fixture, 1, owner, "dispatch_delete");
    let (first, duplicate) = tokio::join!(first, duplicate);
    let first = first.unwrap();
    let duplicate = duplicate.unwrap();
    assert!(
        first.3,
        "the atomic dispatch claim must authorize one caller"
    );
    assert!(
        !duplicate.3,
        "the same leased attempt must never dispatch a second DELETE"
    );

    // A newly admitted operation starts at attempt one too. The durable fence
    // compares the operation ID and attempt, not the attempt number alone.
    sqlx::query(
        "update control.operations set state='succeeded',leased_by=null,
                lease_expires_at=null,finished_at=now() where id=$1",
    )
    .bind(fixture.operation)
    .execute(pool)
    .await
    .unwrap();
    let replacement = Uuid::new_v4();
    sqlx::query(
        "insert into control.operations(
           id,kind,queue,workshop_id,payload,correlation_id,idempotency_key,
           state,attempt,leased_by,lease_expires_at
         ) values($1,'webshop-domain.reconcile','tenant-reconciliation',$2,$3,$4,$5,
                  'in_flight',1,'replacement-owner',now()+interval '20 minutes')",
    )
    .bind(replacement)
    .bind(fixture.workshop)
    .bind(json!({"domain_id":fixture.domain,"reason":"replacement_observer"}))
    .bind(Uuid::new_v4())
    .bind(format!("provider-deletion-replacement:{}", fixture.domain))
    .execute(pool)
    .await
    .unwrap();
    sqlx::query("update control.webshop_domains set operation_id=$2 where id=$1")
        .bind(fixture.domain)
        .bind(replacement)
        .execute(pool)
        .await
        .unwrap();
    fixture.operation = replacement;
    advance_provider_deletion(pool, &fixture, 1, "replacement-owner", "begin")
        .await
        .unwrap();
    advance_provider_deletion(pool, &fixture, 1, "replacement-owner", "observe_present")
        .await
        .unwrap();
    let replacement_dispatch =
        advance_provider_deletion(pool, &fixture, 1, "replacement-owner", "dispatch_delete")
            .await
            .unwrap();
    assert!(replacement_dispatch.3);

    // A crash after dispatch is reconciled by a later exact attempt. Budgets
    // remain attached to the domain/provider intent rather than resetting.
    for attempt in 2..=3 {
        sqlx::query(
            "update control.operations set attempt=$2,leased_by=$3,
                    lease_expires_at=now()+interval '20 minutes' where id=$1",
        )
        .bind(fixture.operation)
        .bind(attempt)
        .bind(format!("{owner}-{attempt}"))
        .execute(pool)
        .await
        .unwrap();
        let current_owner = format!("{owner}-{attempt}");
        advance_provider_deletion(pool, &fixture, attempt, &current_owner, "begin")
            .await
            .unwrap();
        advance_provider_deletion(pool, &fixture, attempt, &current_owner, "observe_present")
            .await
            .unwrap();
        let dispatch =
            advance_provider_deletion(pool, &fixture, attempt, &current_owner, "dispatch_delete")
                .await
                .unwrap();
        assert!(dispatch.3);
    }
    sqlx::query(
        "update control.operations set attempt=4,leased_by='provider-delete-owner-4',
                lease_expires_at=now()+interval '20 minutes' where id=$1",
    )
    .bind(fixture.operation)
    .execute(pool)
    .await
    .unwrap();
    let final_observer =
        advance_provider_deletion(pool, &fixture, 4, "provider-delete-owner-4", "begin")
            .await
            .unwrap();
    assert_eq!(final_observer.0, "delete_dispatched");
    advance_provider_deletion(
        pool,
        &fixture,
        4,
        "provider-delete-owner-4",
        "observe_present",
    )
    .await
    .unwrap();
    let exhausted = advance_provider_deletion(
        pool,
        &fixture,
        4,
        "provider-delete-owner-4",
        "dispatch_delete",
    )
    .await
    .unwrap();
    assert_eq!(exhausted.0, "budget_exhausted");
    assert!(!exhausted.3);
    assert_eq!(exhausted.2, 4);

    // If authoritative absence was already observed (including immediately,
    // without any DELETE), the durable transition is exact and terminal.
    let fixture = insert_provider_deletion_fixture(pool, "absence-owner").await;
    advance_provider_deletion(pool, &fixture, 1, "absence-owner", "begin")
        .await
        .unwrap();
    let absent = advance_provider_deletion(pool, &fixture, 1, "absence-owner", "observe_absent")
        .await
        .unwrap();
    assert_eq!(absent.0, "absence_confirmed");
    assert_eq!(absent.2, 0, "absence must not manufacture a DELETE");

    // Exhausting the dispatch budget does not consume the final observation:
    // four ambiguous sends may all have succeeded, so a later 404 must still
    // be able to prove absence and complete the intent.
    let fixture = insert_provider_deletion_fixture(pool, "eventual-absence-1").await;
    for attempt in 1..=4 {
        let current_owner = format!("eventual-absence-{attempt}");
        if attempt > 1 {
            sqlx::query(
                "update control.operations set attempt=$2,leased_by=$3,
                        lease_expires_at=now()+interval '20 minutes' where id=$1",
            )
            .bind(fixture.operation)
            .bind(attempt)
            .bind(&current_owner)
            .execute(pool)
            .await
            .unwrap();
        }
        advance_provider_deletion(pool, &fixture, attempt, &current_owner, "begin")
            .await
            .unwrap();
        advance_provider_deletion(pool, &fixture, attempt, &current_owner, "observe_present")
            .await
            .unwrap();
        let dispatch =
            advance_provider_deletion(pool, &fixture, attempt, &current_owner, "dispatch_delete")
                .await
                .unwrap();
        assert!(dispatch.3);
    }
    sqlx::query(
        "update control.operations set attempt=5,leased_by='eventual-absence-5',
                lease_expires_at=now()+interval '20 minutes' where id=$1",
    )
    .bind(fixture.operation)
    .execute(pool)
    .await
    .unwrap();
    let final_observer =
        advance_provider_deletion(pool, &fixture, 5, "eventual-absence-5", "begin")
            .await
            .unwrap();
    assert_ne!(final_observer.0, "budget_exhausted");
    let eventual_absence =
        advance_provider_deletion(pool, &fixture, 5, "eventual-absence-5", "observe_absent")
            .await
            .unwrap();
    assert_eq!(eventual_absence.0, "absence_confirmed");
    assert_eq!(eventual_absence.2, 4);
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
async fn lifecycle_resource_relationships_reject_mixed_workshop_ownership() {
    let store = store().await;
    let user = Uuid::new_v4();
    sqlx::query("insert into control.users(id,email) values($1,$2)")
        .bind(user)
        .bind(format!("lifecycle-owner-{user}@example.test"))
        .execute(store.pool())
        .await
        .unwrap();
    let first = Uuid::new_v4();
    let second = Uuid::new_v4();
    for workshop in [first, second] {
        sqlx::query("insert into control.workshops(id,slug,display_name,time_zone,status) values($1,$2,'Lifecycle ownership fixture','Europe/Paris','restricted')")
            .bind(workshop)
            .bind(format!("lifecycle-owner-{}", workshop.simple()))
            .execute(store.pool()).await.unwrap();
    }
    let second_service = Uuid::new_v4();
    sqlx::query("insert into control.service_instances(id,workshop_id,service,base_url,secret_ref) values($1,$2,'odoo','http://odoo.internal','docker/test/odoo')")
        .bind(second_service).bind(second).execute(store.pool()).await.unwrap();
    let crossed_service = sqlx::query("insert into control.odoo_databases(id,workshop_id,service_instance_id,kind,database_ref,public_hostname,label,routable) values($1,$2,$3,'primary',$4,$5,'Crossed service',true)")
        .bind(Uuid::new_v4()).bind(first).bind(second_service)
        .bind(format!("mb_{}", Uuid::new_v4().simple()))
        .bind(format!("{}.example.test", Uuid::new_v4().simple()))
        .execute(store.pool()).await;
    assert!(
        crossed_service.is_err(),
        "a database cannot reference another workshop's service"
    );

    let mut databases = Vec::new();
    let mut operations = Vec::new();
    let mut recoveries = Vec::new();
    for workshop in [first, second] {
        let database = Uuid::new_v4();
        sqlx::query("insert into control.odoo_databases(id,workshop_id,kind,database_ref,public_hostname,label,state,routable) values($1,$2,'primary',$3,$4,'Primary','ready',true)")
            .bind(database).bind(workshop).bind(format!("mb_{}",database.simple()))
            .bind(format!("{}.example.test", database.simple())).execute(store.pool()).await.unwrap();
        let operation = Uuid::new_v4();
        sqlx::query("insert into control.operations(id,kind,queue,workshop_id,payload,correlation_id,idempotency_key) values($1,'tenant.lifecycle','tenant-lifecycle',$2,'{}',$3,$4)")
            .bind(operation).bind(workshop).bind(Uuid::new_v4()).bind(format!("lifecycle-owner:{operation}"))
            .execute(store.pool()).await.unwrap();
        let recovery = Uuid::new_v4();
        sqlx::query("insert into control.workshop_recovery_points(id,workshop_id,database_id,operation_id,kind,label,requested_by) values($1,$2,$3,$4,'backup','Scoped recovery',$5)")
            .bind(recovery).bind(workshop).bind(database).bind(operation).bind(user)
            .execute(store.pool()).await.unwrap();
        databases.push(database);
        operations.push(operation);
        recoveries.push(recovery);
    }

    sqlx::query("insert into control.workshop_recovery_components(recovery_point_id,workshop_id,component,object_key,size_bytes,digest,state,verified_at) values($1,$2,'manifest','manifest.json',1,$3,'verified',now())")
        .bind(recoveries[0]).bind(first).bind("0".repeat(64)).execute(store.pool()).await.unwrap();
    let crossed_component = sqlx::query("insert into control.workshop_recovery_components(recovery_point_id,workshop_id,component,object_key,size_bytes,digest,state,verified_at) values($1,$2,'commit-marker','commit',1,$3,'verified',now())")
        .bind(recoveries[0]).bind(second).bind("1".repeat(64)).execute(store.pool()).await;
    assert!(
        crossed_component.is_err(),
        "a recovery component cannot claim another workshop"
    );

    let crossed_rehearsal = sqlx::query("insert into control.workshop_recovery_rehearsals(id,recovery_point_id,workshop_id,state,lease_owner,lease_token,lease_expires_at) values($1,$2,$3,'running',$4,$5,now()+interval '20 minutes')")
        .bind(Uuid::new_v4()).bind(recoveries[0]).bind(second)
        .bind(Uuid::new_v4()).bind(Uuid::new_v4()).execute(store.pool()).await;
    assert!(
        crossed_rehearsal.is_err(),
        "a rehearsal must share its recovery workshop"
    );

    let crossed_recovery = sqlx::query("insert into control.workshop_deletions(workshop_id,previous_status,requested_by,operation_id,final_recovery_point_id,purge_after) values($1,'restricted',$2,$3,$4,now()+interval '35 days')")
        .bind(first).bind(user).bind(operations[0]).bind(recoveries[1]).execute(store.pool()).await;
    assert!(
        crossed_recovery.is_err(),
        "a deletion cannot retain another workshop's recovery point"
    );
    let crossed_operation = sqlx::query("insert into control.workshop_deletions(workshop_id,previous_status,requested_by,operation_id,final_recovery_point_id,purge_after) values($1,'restricted',$2,$3,$4,now()+interval '35 days')")
        .bind(first).bind(user).bind(operations[1]).bind(recoveries[0]).execute(store.pool()).await;
    assert!(
        crossed_operation.is_err(),
        "a deletion cannot use another workshop's operation"
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

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires a disposable CONTROL_TEST_DATABASE_URL"]
async fn enqueue_persists_the_http_trace_context() {
    opentelemetry::global::set_text_map_propagator(
        opentelemetry_sdk::propagation::TraceContextPropagator::new(),
    );
    let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder().build();
    let subscriber = tracing_subscriber::registry()
        .with(tracing_opentelemetry::layer().with_tracer(provider.tracer("postgres-trace-test")));
    let _subscriber = tracing::subscriber::set_default(subscriber);

    let inbound = std::collections::HashMap::from([
        (
            "traceparent".to_owned(),
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01".to_owned(),
        ),
        ("tracestate".to_owned(), "vendor=value".to_owned()),
    ]);
    let remote_parent =
        opentelemetry::global::get_text_map_propagator(|propagator| propagator.extract(&inbound));
    let request_span = tracing::info_span!("http_request_test");
    request_span.set_parent(remote_parent).unwrap();

    let store = store().await;
    let payload = json!({"capture_id": Uuid::new_v4(), "assets": []});
    let key = format!("trace-context-test:{}", Uuid::new_v4());
    let operation_id = async {
        let mut tx = store.begin().await.unwrap();
        let operation_id = Store::enqueue(
            &mut tx,
            NewOperation {
                kind: OperationKind::InventoryCaptureExtract,
                workshop_id: None,
                target_user_id: None,
                desired_epoch: None,
                payload: &payload,
                requested_by: None,
                correlation_id: Uuid::new_v4(),
                idempotency_key: &key,
            },
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        operation_id
    }
    .instrument(request_span)
    .await;

    let (trace_parent, trace_state) = sqlx::query_as::<_, (Option<String>, Option<String>)>(
        "select trace_parent,trace_state from control.operations where id=$1",
    )
    .bind(operation_id)
    .fetch_one(store.pool())
    .await
    .unwrap();
    let trace_parent = trace_parent.expect("the request trace parent must be persisted");
    assert!(
        trace_parent.starts_with("00-4bf92f3577b34da6a3ce929d0e0e4736-"),
        "the persisted operation must remain in the inbound HTTP trace"
    );
    assert_eq!(trace_state.as_deref(), Some("vendor=value"));

    drop(_subscriber);
    provider.shutdown().unwrap();
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
    sqlx::query("update control.operations set next_attempt_at=now()-interval '1 day' where id=$1")
        .bind(first)
        .execute(store.pool())
        .await
        .unwrap();

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

    let secret_payload = sqlx::query("insert into control.outbox(id,kind,recipient,template,payload,invitation_id,token_generation,capability_issued_at,capability_expires_at,signing_key_id,workshop_id) values($1,'invitation','invitee@example.test','workshop-invitation',$2,$3,1,now(),now()+interval '1 day','test-key',$4)")
        .bind(Uuid::new_v4())
        .bind(json!({"accept_url":"https://example.test/invitations/accept#token=secret"}))
        .bind(invitation)
        .bind(workshop)
        .execute(store.pool())
        .await;
    assert!(
        secret_payload.is_err(),
        "capabilities must not enter outbox JSON"
    );

    let outbox = Uuid::new_v4();
    sqlx::query("insert into control.outbox(id,kind,recipient,template,payload,invitation_id,token_generation,capability_issued_at,capability_expires_at,signing_key_id,workshop_id) values($1,'invitation','invitee@example.test','workshop-invitation',$2,$3,1,now(),now()+interval '1 day','test-key',$4)")
        .bind(outbox)
        .bind(json!({"invitation_id":invitation,"locale":"en"}))
        .bind(invitation)
        .bind(workshop)
        .execute(store.pool())
        .await
        .unwrap();
    let other_workshop = Uuid::new_v4();
    sqlx::query("insert into control.workshops(id,slug,display_name,time_zone) values($1,$2,'Other invitation fixture','Europe/Paris')")
        .bind(other_workshop)
        .bind(format!("invite-other-{}", other_workshop.simple()))
        .execute(store.pool())
        .await
        .unwrap();
    let cross_workshop = sqlx::query("insert into control.outbox(id,kind,recipient,template,payload,invitation_id,token_generation,capability_issued_at,capability_expires_at,signing_key_id,workshop_id) values($1,'invitation','invitee@example.test','workshop-invitation',$2,$3,1,now(),now()+interval '1 day','test-key',$4)")
        .bind(Uuid::new_v4())
        .bind(json!({"invitation_id":invitation,"locale":"en"}))
        .bind(invitation)
        .bind(other_workshop)
        .execute(store.pool())
        .await;
    assert!(
        cross_workshop.is_err(),
        "invitation mail cannot cross workshops"
    );
    let wrong_recipient = sqlx::query("insert into control.outbox(id,kind,recipient,template,payload,invitation_id,token_generation,capability_issued_at,capability_expires_at,signing_key_id,workshop_id) values($1,'invitation','attacker@example.test','workshop-invitation',$2,$3,1,now(),now()+interval '1 day','test-key',$4)")
        .bind(Uuid::new_v4())
        .bind(json!({"invitation_id":invitation,"locale":"en"}))
        .bind(invitation)
        .bind(workshop)
        .execute(store.pool())
        .await;
    assert!(
        wrong_recipient.is_err(),
        "invitation mail recipient must be authoritative"
    );
    let missing_workshop = sqlx::query("insert into control.outbox(id,kind,recipient,template,payload,invitation_id,token_generation,capability_issued_at,capability_expires_at,signing_key_id) values($1,'invitation','invitee@example.test','workshop-invitation',$2,$3,1,now(),now()+interval '1 day','test-key')")
        .bind(Uuid::new_v4())
        .bind(json!({"invitation_id":invitation,"locale":"en"}))
        .bind(invitation)
        .execute(store.pool())
        .await;
    assert!(
        missing_workshop.is_err(),
        "every outbox row must name its workshop"
    );
    let unknown_kind = sqlx::query("insert into control.outbox(id,kind,recipient,template,payload,workshop_id) values($1,'private_mail','invitee@example.test','private-template','{}',$2)")
        .bind(Uuid::new_v4())
        .bind(workshop)
        .execute(store.pool())
        .await;
    assert!(
        unknown_kind.is_err(),
        "outbox kind and metadata shape must be closed"
    );
    let duplicate = sqlx::query("insert into control.outbox(id,kind,recipient,template,payload,invitation_id,token_generation,capability_issued_at,capability_expires_at,signing_key_id,workshop_id) values($1,'invitation','invitee@example.test','workshop-invitation',$2,$3,1,now(),now()+interval '1 day','test-key',$4)")
        .bind(Uuid::new_v4())
        .bind(json!({"invitation_id":invitation,"locale":"en"}))
        .bind(invitation)
        .bind(workshop)
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
async fn workshop_route_projection_protocol_is_monotonic_fenced_and_replayable() {
    let store = store().await;
    sqlx::query(
        "update control.deployment_driver_resource_leases
            set state='idle',driver_operation_id=null,lease_owner=null,lease_token=null,
                lease_expires_at=null,heartbeat_at=null,quarantined_at=null,safe_error=null,
                updated_at=now()
          where resource_key='runtime/shared-odoo'",
    )
    .execute(store.pool())
    .await
    .unwrap();

    let workshop = Uuid::new_v4();
    sqlx::query(
        "insert into control.workshops(id,slug,display_name,time_zone)
         values($1,$2,'Route projection fixture','Europe/Paris')",
    )
    .bind(workshop)
    .bind(format!("route-{}", workshop.simple()))
    .execute(store.pool())
    .await
    .unwrap();
    let first_control =
        insert_route_control_operation(store.pool(), workshop, "route-worker-a").await;
    let second_control =
        insert_route_control_operation(store.pool(), workshop, "route-worker-b").await;
    let third_control =
        insert_route_control_operation(store.pool(), workshop, "route-worker-c").await;

    let database_id = Uuid::new_v4();
    let first_projection = json!({
        "database_id": database_id,
        "database_ref": format!("mb_{}", workshop.simple()),
        "public_hostname": format!("{}.routes.example.test", workshop.simple()),
        "paperless_mode": "absent",
        "paperless_hostname": null,
        "custom_hostnames": []
    });
    let first_digest = format!("sha256:{}", "a".repeat(64));
    let created = materialize_route_projection(
        store.pool(),
        &first_control,
        &first_projection,
        &first_digest,
    )
    .await;
    assert_eq!(created.0, "created");
    assert_eq!(created.1, Some(1));
    assert_eq!(created.2.as_deref(), Some(first_digest.as_str()));
    assert_eq!(created.3.as_ref(), Some(&first_projection));

    let reused = materialize_route_projection(
        store.pool(),
        &second_control,
        &first_projection,
        &first_digest,
    )
    .await;
    assert_eq!(reused.0, "reused");
    assert_eq!(reused.1, Some(1));

    let second_projection = json!({
        "database_id": database_id,
        "database_ref": format!("mb_{}", workshop.simple()),
        "public_hostname": format!("{}.routes.example.test", workshop.simple()),
        "paperless_mode": "absent",
        "paperless_hostname": null,
        "custom_hostnames": [{
            "hostname": format!("shop-{}.example.test", workshop.simple()),
            "canonical": true
        }]
    });
    let second_digest = format!("sha256:{}", "b".repeat(64));
    let changed = materialize_route_projection(
        store.pool(),
        &second_control,
        &second_projection,
        &second_digest,
    )
    .await;
    assert_eq!(changed.0, "created");
    assert_eq!(changed.1, Some(2));
    let generations: Vec<(i64, String)> = sqlx::query_as(
        "select generation,projection_digest
           from control.workshop_route_projections
          where workshop_id=$1 order by generation",
    )
    .bind(workshop)
    .fetch_all(store.pool())
    .await
    .unwrap();
    assert_eq!(
        generations,
        vec![(1, first_digest.clone()), (2, second_digest.clone())]
    );

    let application = RouteApplicationCall {
        control: second_control.clone(),
        idempotency_key: format!("route-application:{workshop}:2"),
        request_digest: "c".repeat(64),
        generation: 2,
        projection_digest: second_digest.clone(),
        instance_owner: Uuid::new_v4(),
        execution_token: Uuid::new_v4(),
        resource_lease_token: Uuid::new_v4(),
    };
    let contender = RouteApplicationCall {
        instance_owner: Uuid::new_v4(),
        execution_token: Uuid::new_v4(),
        resource_lease_token: Uuid::new_v4(),
        ..application.clone()
    };
    let database_url = std::env::var("CONTROL_TEST_DATABASE_URL").unwrap();
    let first_pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&database_url)
        .await
        .unwrap();
    let second_pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&database_url)
        .await
        .unwrap();
    let admissions = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        tokio::join!(
            admit_route_application(&first_pool, &application),
            admit_route_application(&second_pool, &contender)
        )
    })
    .await
    .expect("concurrent route admissions must not deadlock");
    let (winner, replay_caller, acquired, busy) = match (&admissions.0.0[..], &admissions.1.0[..]) {
        ("acquired", "busy") => (&application, &contender, &admissions.0, &admissions.1),
        ("busy", "acquired") => (&contender, &application, &admissions.1, &admissions.0),
        outcomes => panic!("expected one acquired and one busy, got {outcomes:?}"),
    };
    let driver_operation = acquired.1.expect("acquired driver operation");
    let fence = acquired.2.expect("acquired fence");
    assert_eq!(busy.1, Some(driver_operation));
    assert_eq!(busy.2, Some(fence));
    let receipt_count: i64 = sqlx::query_scalar(
        "select count(*) from control.deployment_driver_operations
          where workshop_id=$1 and route_generation=2",
    )
    .bind(workshop)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(receipt_count, 1);

    let rendered_digest = format!("sha256:{}", "d".repeat(64));
    let response = json!({
        "route_evidence": {
            "driver_operation_id": driver_operation,
            "workshop_id": workshop,
            "route_generation": 2,
            "projection_digest": second_digest.clone(),
            "disposition": "present",
            "rendered_digest": rendered_digest.clone(),
            "route_fence_token": fence
        }
    });
    let mut wrong_disposition = response.clone();
    wrong_disposition["route_evidence"]["disposition"] = json!("absent");
    let incomplete_response = json!({
        "route_evidence": {
            "driver_operation_id": driver_operation,
            "workshop_id": workshop,
            "route_generation": 2,
            "projection_digest": second_digest.clone(),
            "rendered_digest": rendered_digest.clone()
        }
    });
    assert!(
        !finish_route_application(
            store.pool(),
            winner,
            driver_operation,
            fence,
            (
                "succeeded",
                Some(&wrong_disposition),
                Some(&rendered_digest),
                None,
            ),
        )
        .await
    );
    assert!(
        !finish_route_application(
            store.pool(),
            winner,
            driver_operation,
            fence,
            (
                "succeeded",
                Some(&incomplete_response),
                Some(&rendered_digest),
                None,
            ),
        )
        .await
    );
    assert!(
        !finish_route_application(
            store.pool(),
            winner,
            driver_operation,
            fence + 1,
            ("succeeded", Some(&response), Some(&rendered_digest), None,),
        )
        .await
    );
    let unapplied: Option<i64> = sqlx::query_scalar(
        "select applied_generation from control.workshop_route_projection_state
          where workshop_id=$1",
    )
    .bind(workshop)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(unapplied, None);
    assert!(
        finish_route_application(
            store.pool(),
            winner,
            driver_operation,
            fence,
            ("succeeded", Some(&response), Some(&rendered_digest), None,),
        )
        .await
    );
    let applied: AppliedRouteRow = sqlx::query_as(
        "select applied_generation,applied_digest,applied_rendered_digest,
                    applied_driver_operation_id,applied_fence_token
               from control.workshop_route_projection_state where workshop_id=$1",
    )
    .bind(workshop)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(
        applied,
        (
            Some(2),
            Some(second_digest.clone()),
            Some(rendered_digest.clone()),
            Some(driver_operation),
            Some(fence)
        )
    );

    let replay = admit_route_application(store.pool(), replay_caller).await;
    assert_eq!(replay.0, "replay");
    assert_eq!(replay.1, Some(driver_operation));
    assert_eq!(replay.2, Some(fence));
    assert_eq!(replay.3.as_ref(), Some(&response));

    let superseded_call = RouteApplicationCall {
        control: first_control.clone(),
        idempotency_key: format!("route-application:{workshop}:1"),
        request_digest: "e".repeat(64),
        generation: 1,
        projection_digest: first_digest.clone(),
        instance_owner: Uuid::new_v4(),
        execution_token: Uuid::new_v4(),
        resource_lease_token: Uuid::new_v4(),
    };
    let superseded = admit_route_application(store.pool(), &superseded_call).await;
    assert_eq!(superseded.0, "superseded");
    assert_eq!(superseded.1, None);
    assert_eq!(superseded.3.as_ref().unwrap()["desired_generation"], 2);
    assert_eq!(
        superseded.3.as_ref().unwrap()["route_evidence"],
        response["route_evidence"]
    );

    let third_projection = json!({
        "database_id": database_id,
        "database_ref": format!("mb_{}", workshop.simple()),
        "public_hostname": format!("{}.routes.example.test", workshop.simple()),
        "paperless_mode": "read_only",
        "paperless_hostname": format!("docs-{}.example.test", workshop.simple()),
        "custom_hostnames": [{
            "hostname": format!("shop-{}.example.test", workshop.simple()),
            "canonical": true
        }]
    });
    let third_digest = format!("sha256:{}", "f".repeat(64));
    let third = materialize_route_projection(
        store.pool(),
        &third_control,
        &third_projection,
        &third_digest,
    )
    .await;
    assert_eq!((third.0.as_str(), third.1), ("created", Some(3)));
    let third_application = RouteApplicationCall {
        control: third_control,
        idempotency_key: format!("route-application:{workshop}:3"),
        request_digest: "1".repeat(64),
        generation: 3,
        projection_digest: third_digest.clone(),
        instance_owner: Uuid::new_v4(),
        execution_token: Uuid::new_v4(),
        resource_lease_token: Uuid::new_v4(),
    };
    let third_admission = admit_route_application(store.pool(), &third_application).await;
    assert_eq!(third_admission.0, "acquired");
    let third_driver_operation = third_admission.1.unwrap();
    let third_fence = third_admission.2.unwrap();
    assert!(third_fence > fence);
    assert!(
        !finish_route_application(
            store.pool(),
            winner,
            driver_operation,
            fence,
            ("succeeded", Some(&response), Some(&rendered_digest), None,),
        )
        .await
    );
    assert!(
        finish_route_application(
            store.pool(),
            &third_application,
            third_driver_operation,
            third_fence,
            ("failed", None, None, Some("test_rejected")),
        )
        .await
    );

    let closed_control =
        insert_route_control_operation(store.pool(), workshop, "route-worker-closed").await;
    sqlx::query(
        "update control.operations
            set state='succeeded',leased_by=null,lease_expires_at=null,finished_at=now()
          where id=$1",
    )
    .bind(closed_control.id)
    .execute(store.pool())
    .await
    .unwrap();
    let closed_materialize = sqlx::query_as::<_, RouteProjectionRow>(
        "select outcome,generation,projection_digest,projection
           from control.materialize_workshop_route_projection($1,$2,$3,$4,$5,$6)",
    )
    .bind(closed_control.id)
    .bind(closed_control.attempt)
    .bind(&closed_control.owner)
    .bind(workshop)
    .bind(&third_projection)
    .bind(format!("sha256:{}", "2".repeat(64)))
    .fetch_one(store.pool())
    .await
    .unwrap_err();
    assert_eq!(
        closed_materialize
            .as_database_error()
            .and_then(|error| error.code())
            .as_deref(),
        Some("55000")
    );
    let closed_application = RouteApplicationCall {
        control: closed_control,
        idempotency_key: format!("route-application:{workshop}:closed"),
        request_digest: "3".repeat(64),
        generation: 3,
        projection_digest: third_digest,
        instance_owner: Uuid::new_v4(),
        execution_token: Uuid::new_v4(),
        resource_lease_token: Uuid::new_v4(),
    };
    let closed_admission = admit_route_application(store.pool(), &closed_application).await;
    assert_eq!(closed_admission.0, "upstream_lease_lost");
    assert_eq!(closed_admission.1, None);

    first_pool.close().await;
    second_pool.close().await;
}

#[tokio::test]
#[ignore = "requires a disposable CONTROL_TEST_DATABASE_URL with control_driver_ledger"]
async fn startup_route_heartbeat_is_atomic_and_driver_authority_is_function_only() {
    let store = store().await;
    sqlx::query(
        "update control.deployment_driver_resource_leases
            set state='idle',authority_kind=null,effect_run_id=null,driver_operation_id=null,
                lease_owner=null,lease_token=null,lease_expires_at=null,heartbeat_at=null,
                quarantined_at=null,safe_error=null,updated_at=now()
          where resource_key='runtime/shared-odoo'",
    )
    .execute(store.pool())
    .await
    .unwrap();

    let fixture_prefix = Uuid::new_v4().simple().to_string();
    sqlx::query(
        "insert into control.workshops(id,slug,display_name,time_zone)
         select gen_random_uuid(),$1||'-'||ordinality,'Startup heartbeat fixture','Europe/Paris'
           from generate_series(1,64) ordinality",
    )
    .bind(format!("heartbeat-{fixture_prefix}"))
    .execute(store.pool())
    .await
    .unwrap();

    let boot_id = Uuid::new_v4();
    let instance_owner = Uuid::new_v4();
    let execution_token = Uuid::new_v4();
    let global_lease_token = Uuid::new_v4();
    let route_lease_token = Uuid::new_v4();
    let admission: (String, Option<Uuid>, Option<i64>, Option<i32>) = sqlx::query_as(
        "select outcome,effect_run_id,global_fence_token,reserved_count
           from control.admit_startup_route_rebuild($1,$2,$3,$4,$5,$6,$7,1200)",
    )
    .bind(boot_id)
    .bind(format!("startup-heartbeat:{boot_id}"))
    .bind("a".repeat(64))
    .bind(instance_owner)
    .bind(execution_token)
    .bind(global_lease_token)
    .bind(route_lease_token)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(admission.0, "acquired");
    assert!(admission.3.unwrap() >= 64);
    let effect_run_id = admission.1.unwrap();
    let global_fence = admission.2.unwrap();

    async fn expiry_fingerprint(pool: &sqlx::PgPool, effect_run_id: Uuid) -> String {
        sqlx::query_scalar::<_, String>(
            "select md5(string_agg(source||':'||expiry,',' order by source))
               from (select 'global' source,lease_expires_at::text expiry
                       from control.deployment_driver_resource_leases
                      where resource_key='runtime/shared-odoo'
                     union all
                     select 'run',lease_expires_at::text
                       from control.workshop_route_effect_runs where id=$1
                     union all
                     select 'route/'||lease.workshop_id::text,lease.lease_expires_at::text
                       from control.workshop_route_application_leases lease
                       join control.workshop_route_effect_reservations reservation
                         on reservation.workshop_id=lease.workshop_id
                      where reservation.effect_run_id=$1) leases",
        )
        .bind(effect_run_id)
        .fetch_one(pool)
        .await
        .unwrap()
    }
    let before_wrong = expiry_fingerprint(store.pool(), effect_run_id).await;
    let wrong_renewal: bool =
        sqlx::query_scalar("select control.renew_startup_route_rebuild($1,$2,$3,$4,$5,$6,1200)")
            .bind(effect_run_id)
            .bind(instance_owner)
            .bind(execution_token)
            .bind(Uuid::new_v4())
            .bind(route_lease_token)
            .bind(global_fence)
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert!(!wrong_renewal);
    assert_eq!(
        before_wrong,
        expiry_fingerprint(store.pool(), effect_run_id).await
    );

    let renewed: bool =
        sqlx::query_scalar("select control.renew_startup_route_rebuild($1,$2,$3,$4,$5,$6,1200)")
            .bind(effect_run_id)
            .bind(instance_owner)
            .bind(execution_token)
            .bind(global_lease_token)
            .bind(route_lease_token)
            .bind(global_fence)
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert!(renewed);
    let distinct_expiries: i64 = sqlx::query_scalar(
        "select count(distinct expiry)
           from (select lease_expires_at expiry from control.deployment_driver_resource_leases
                  where resource_key='runtime/shared-odoo'
                 union all select lease_expires_at from control.workshop_route_effect_runs where id=$1
                 union all select lease.lease_expires_at
                   from control.workshop_route_application_leases lease
                   join control.workshop_route_effect_reservations reservation
                     on reservation.workshop_id=lease.workshop_id
                  where reservation.effect_run_id=$1) leases",
    )
    .bind(effect_run_id)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(distinct_expiries, 1);

    let workshop: Uuid = sqlx::query_scalar(
        "select workshop_id from control.workshop_route_effect_reservations
          where effect_run_id=$1 and action='remove-uninitialized' order by workshop_id limit 1",
    )
    .bind(effect_run_id)
    .fetch_one(store.pool())
    .await
    .unwrap();
    let mut driver = store.pool().begin().await.unwrap();
    sqlx::query("set local role control_driver_ledger")
        .execute(&mut *driver)
        .await
        .unwrap();
    let source: (String, Option<String>, Option<Value>) = sqlx::query_as(
        "select outcome,disposition,projection
           from control.read_startup_route_projection_source($1,$2,$3,$4,$5,$6,$7,$8)",
    )
    .bind(effect_run_id)
    .bind(instance_owner)
    .bind(execution_token)
    .bind(global_lease_token)
    .bind(route_lease_token)
    .bind(global_fence)
    .bind(workshop)
    .bind("example.test")
    .fetch_one(&mut *driver)
    .await
    .unwrap();
    assert_eq!(
        (source.0.as_str(), source.1.as_deref()),
        ("read", Some("absent"))
    );
    let projection = source.2.unwrap();
    let fenced_source: String = sqlx::query_scalar(
        "select outcome from control.read_startup_route_projection_source(
             $1,$2,$3,$4,$5,$6,$7,$8)",
    )
    .bind(effect_run_id)
    .bind(instance_owner)
    .bind(execution_token)
    .bind(global_lease_token)
    .bind(Uuid::new_v4())
    .bind(global_fence)
    .bind(workshop)
    .bind("example.test")
    .fetch_one(&mut *driver)
    .await
    .unwrap();
    assert_eq!(fenced_source, "authority_lost");
    driver.rollback().await.unwrap();

    let mut direct = store.pool().begin().await.unwrap();
    sqlx::query("set local role control_driver_ledger")
        .execute(&mut *direct)
        .await
        .unwrap();
    let denied = sqlx::query("select id from control.workshops limit 1")
        .execute(&mut *direct)
        .await
        .unwrap_err();
    assert_eq!(
        denied.as_database_error().and_then(|e| e.code()).as_deref(),
        Some("42501")
    );
    direct.rollback().await.unwrap();

    let projection_digest = format!("sha256:{}", "b".repeat(64));
    let initialized: (String, Option<i64>) = sqlx::query_as(
        "select outcome,generation from control.initialize_startup_route_projection(
             $1,$2,$3,$4,$5,$6,$7,$8,'absent',$9,$10)",
    )
    .bind(effect_run_id)
    .bind(instance_owner)
    .bind(execution_token)
    .bind(global_lease_token)
    .bind(route_lease_token)
    .bind(global_fence)
    .bind(workshop)
    .bind("example.test")
    .bind(&projection)
    .bind(&projection_digest)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(
        (initialized.0.as_str(), initialized.1),
        ("initialized", Some(1))
    );
    let began: bool =
        sqlx::query_scalar("select control.begin_startup_route_rebuild($1,$2,$3,$4,$5,$6)")
            .bind(effect_run_id)
            .bind(instance_owner)
            .bind(execution_token)
            .bind(global_lease_token)
            .bind(route_lease_token)
            .bind(global_fence)
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert!(began);
    let (action, route_fence): (String, i64) = sqlx::query_as(
        "select action,route_fence_token from control.workshop_route_effect_reservations
          where effect_run_id=$1 and workshop_id=$2",
    )
    .bind(effect_run_id)
    .bind(workshop)
    .fetch_one(store.pool())
    .await
    .unwrap();
    let exact: bool = sqlx::query_scalar(
        "select control.assert_startup_route_workshop_fence(
             $1,$2,$3,$4,$5,$6,$7,1,$8,'absent',$9,$10)",
    )
    .bind(effect_run_id)
    .bind(instance_owner)
    .bind(execution_token)
    .bind(global_lease_token)
    .bind(route_lease_token)
    .bind(global_fence)
    .bind(workshop)
    .bind(&projection_digest)
    .bind(&action)
    .bind(route_fence)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert!(exact);

    let before_drift = expiry_fingerprint(store.pool(), effect_run_id).await;
    sqlx::query(
        "update control.workshop_route_application_leases set lease_token=$2
          where workshop_id=(select workshop_id from control.workshop_route_effect_reservations
            where effect_run_id=$1 and workshop_id<>$3 order by workshop_id limit 1)",
    )
    .bind(effect_run_id)
    .bind(Uuid::new_v4())
    .bind(workshop)
    .execute(store.pool())
    .await
    .unwrap();
    let drifted_renewal: bool =
        sqlx::query_scalar("select control.renew_startup_route_rebuild($1,$2,$3,$4,$5,$6,1200)")
            .bind(effect_run_id)
            .bind(instance_owner)
            .bind(execution_token)
            .bind(global_lease_token)
            .bind(route_lease_token)
            .bind(global_fence)
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert!(!drifted_renewal);
    assert_eq!(
        before_drift,
        expiry_fingerprint(store.pool(), effect_run_id).await
    );
}

#[tokio::test]
#[ignore = "requires a disposable CONTROL_TEST_DATABASE_URL"]
async fn release_route_snapshot_v2_freezes_exact_applied_projections_and_pages_them() {
    let store = store().await;
    sqlx::query(
        "update control.deployment_driver_resource_leases
            set state='idle',authority_kind=null,driver_operation_id=null,effect_run_id=null,
                lease_owner=null,lease_token=null,lease_expires_at=null,heartbeat_at=null,
                quarantined_at=null,safe_error=null,updated_at=now()
          where resource_key='runtime/shared-odoo'",
    )
    .execute(store.pool())
    .await
    .unwrap();

    let workshops = [Uuid::new_v4(), Uuid::new_v4()];
    for workshop in workshops {
        sqlx::query(
            "insert into control.workshops(id,slug,display_name,time_zone)
             values($1,$2,'Release snapshot v2 fixture','Europe/Paris')",
        )
        .bind(workshop)
        .bind(format!("release-snapshot-{}", workshop.simple()))
        .execute(store.pool())
        .await
        .unwrap();
    }
    let mut release = insert_leased_release_operation(store.pool(), "release-snapshot-v2").await;
    let reserved = attach_release_fleet_run(store.pool(), &mut release, &workshops).await;
    let fleet_run = release.fleet_run_id.unwrap();
    let snapshot: Value =
        sqlx::query_scalar("select tenant_snapshot from control.release_fleet_runs where id=$1")
            .bind(fleet_run)
            .fetch_one(store.pool())
            .await
            .unwrap();

    let rejected = sqlx::query(
        "select outcome from control.admit_release_driver_operation(
           $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,300,1::smallint,2::smallint)",
    )
    .bind(release.control_operation_id)
    .bind(release.control_operation_attempt)
    .bind(&release.control_operation_owner)
    .bind(&release.idempotency_key)
    .bind(&release.target_key)
    .bind(release.fleet_run_id)
    .bind(&release.request_digest)
    .bind(release.instance_owner)
    .bind(release.execution_token)
    .bind(release.resource_lease_token)
    .execute(store.pool())
    .await
    .expect_err("missing applied projections must reject protocol-v2 admission");
    assert_eq!(
        rejected.as_database_error().unwrap().code().as_deref(),
        Some("55000")
    );
    let rolled_back: (i64, String) = sqlx::query_as(
        "select
           (select count(*) from control.deployment_driver_operations
             where control_operation_id=$1 and action='release'),
           (select state from control.deployment_driver_resource_leases
             where resource_key='runtime/shared-odoo')",
    )
    .bind(release.control_operation_id)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(rolled_back, (0, "idle".into()));

    for (index, item) in snapshot.as_array().unwrap().iter().enumerate() {
        let workshop = Uuid::parse_str(item["workshop_id"].as_str().unwrap()).unwrap();
        let database_id = Uuid::parse_str(item["database_id"].as_str().unwrap()).unwrap();
        let control = insert_route_control_operation(
            store.pool(),
            workshop,
            &format!("release-snapshot-projection-{index}"),
        )
        .await;
        let projection = json!({
            "database_id": database_id,
            "database_ref": item["database_ref"],
            "public_hostname": format!("{}.release-snapshot.example.test", workshop.simple()),
            "paperless_mode": "absent",
            "paperless_hostname": null,
            "custom_hostnames": []
        });
        let projection_digest = format!("sha256:{}", if index == 0 { "9" } else { "a" }.repeat(64));
        let materialized =
            materialize_route_projection(store.pool(), &control, &projection, &projection_digest)
                .await;
        assert_eq!(materialized.0, "created");
        let application = RouteApplicationCall {
            control,
            idempotency_key: format!("release-snapshot-apply:{workshop}"),
            request_digest: if index == 0 { "b" } else { "c" }.repeat(64),
            generation: materialized.1.unwrap(),
            projection_digest: projection_digest.clone(),
            instance_owner: Uuid::new_v4(),
            execution_token: Uuid::new_v4(),
            resource_lease_token: Uuid::new_v4(),
        };
        let admitted = admit_route_application(store.pool(), &application).await;
        assert_eq!(admitted.0, "acquired");
        let driver_operation = admitted.1.unwrap();
        let fence = admitted.2.unwrap();
        let rendered_digest = format!("sha256:{}", if index == 0 { "d" } else { "e" }.repeat(64));
        let response = json!({"route_evidence":{
            "driver_operation_id":driver_operation,"workshop_id":workshop,
            "route_generation":application.generation,
            "projection_digest":projection_digest,"disposition":"present",
            "rendered_digest":rendered_digest,"route_fence_token":fence
        }});
        assert!(
            finish_route_application(
                store.pool(),
                &application,
                driver_operation,
                fence,
                ("succeeded", Some(&response), Some(&rendered_digest), None),
            )
            .await
        );
    }

    let protocol_v1: ReleaseDriverAdmissionRow = sqlx::query_as(
        "select outcome,driver_operation_id,fence_token,stored_response,reserved_workshops
         from control.admit_release_driver_operation(
           $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,300,1::smallint)",
    )
    .bind(release.control_operation_id)
    .bind(release.control_operation_attempt)
    .bind(&release.control_operation_owner)
    .bind(&release.idempotency_key)
    .bind(&release.target_key)
    .bind(release.fleet_run_id)
    .bind(&release.request_digest)
    .bind(release.instance_owner)
    .bind(release.execution_token)
    .bind(release.resource_lease_token)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(protocol_v1.0, "acquired");
    let conflict = admit_release_route_snapshot_v2(store.pool(), &release).await;
    assert_eq!(conflict.0, "protocol_conflict");
    assert_eq!(conflict.1, protocol_v1.1);
    let legacy_driver_operation = protocol_v1.1.unwrap();
    let legacy_fence = protocol_v1.2.unwrap();
    let safely_failed: bool = sqlx::query_scalar(
        "select control.finish_release_driver_operation(
           $1,$2,$3,$4,$5,'failed',null,'test_protocol_cutover')",
    )
    .bind(legacy_driver_operation)
    .bind(release.instance_owner)
    .bind(release.execution_token)
    .bind(release.resource_lease_token)
    .bind(legacy_fence)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert!(safely_failed);
    sqlx::query("delete from control.deployment_driver_operations where id=$1 and state='failed'")
        .bind(legacy_driver_operation)
        .execute(store.pool())
        .await
        .unwrap();

    let admitted = admit_release_route_snapshot_v2(store.pool(), &release).await;
    assert_eq!(admitted.0, "acquired");
    assert_eq!(admitted.4.as_ref(), Some(&reserved));
    let driver_operation = admitted.1.unwrap();
    let global_fence = admitted.2.unwrap();
    let frozen_count: i64 = sqlx::query_scalar(
        "select count(*) from control.fleet_release_route_snapshot_items
          where driver_operation_id=$1",
    )
    .bind(driver_operation)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(frozen_count, 2);

    let first_page = sqlx::query_as::<_, (Uuid, Value, String, i64)>(
        "select workshop_id,canonical_projection,applied_rendered_digest,route_fence_token
         from control.read_fleet_release_route_snapshot_batch($1,$2,$3,$4,$5,null,1)",
    )
    .bind(driver_operation)
    .bind(release.instance_owner)
    .bind(release.execution_token)
    .bind(release.resource_lease_token)
    .bind(global_fence)
    .fetch_all(store.pool())
    .await
    .unwrap();
    assert_eq!(first_page.len(), 1);
    let second_page = sqlx::query_scalar::<_, Uuid>(
        "select workshop_id from control.read_fleet_release_route_snapshot_batch(
           $1,$2,$3,$4,$5,$6,500)",
    )
    .bind(driver_operation)
    .bind(release.instance_owner)
    .bind(release.execution_token)
    .bind(release.resource_lease_token)
    .bind(global_fence)
    .bind(first_page[0].0)
    .fetch_all(store.pool())
    .await
    .unwrap();
    assert_eq!(second_page.len(), 1);
    assert!(second_page[0] > first_page[0].0);
    let oversized: Vec<Uuid> = sqlx::query_scalar(
        "select workshop_id from control.read_fleet_release_route_snapshot_batch(
           $1,$2,$3,$4,$5,null,501)",
    )
    .bind(driver_operation)
    .bind(release.instance_owner)
    .bind(release.execution_token)
    .bind(release.resource_lease_token)
    .bind(global_fence)
    .fetch_all(store.pool())
    .await
    .unwrap();
    assert!(oversized.is_empty());
    let stale: Vec<Uuid> = sqlx::query_scalar(
        "select workshop_id from control.read_fleet_release_route_snapshot_batch(
           $1,$2,$3,$4,$5,null,500)",
    )
    .bind(driver_operation)
    .bind(release.instance_owner)
    .bind(Uuid::new_v4())
    .bind(release.resource_lease_token)
    .bind(global_fence)
    .fetch_all(store.pool())
    .await
    .unwrap();
    assert!(stale.is_empty());
    let immutable = sqlx::query(
        "update control.fleet_release_route_snapshot_items
            set route_fence_token=route_fence_token+1 where driver_operation_id=$1",
    )
    .bind(driver_operation)
    .execute(store.pool())
    .await
    .expect_err("frozen route snapshot must be immutable");
    assert_eq!(
        immutable.as_database_error().unwrap().code().as_deref(),
        Some("55000")
    );

    assert!(
        !finish_release_driver_lease(
            store.pool(),
            &release,
            driver_operation,
            global_fence,
            &json!({"unused":true}),
        )
        .await,
        "migration 0026 must guard the legacy whole-operation finish for protocol 2"
    );
    let replay = admit_release_route_snapshot_v2(store.pool(), &release).await;
    assert_eq!(replay.0, "busy");
    assert_eq!(replay.1, Some(driver_operation));
    let snapshot_count: i64 = sqlx::query_scalar(
        "select count(*) from control.fleet_release_route_snapshots
          where driver_operation_id=$1",
    )
    .bind(driver_operation)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(
        snapshot_count, 1,
        "exact replay must not duplicate snapshots"
    );
}

#[tokio::test]
#[ignore = "requires a disposable PostgreSQL 17 CONTROL_TEST_DATABASE_URL"]
async fn immutable_release_route_publication_is_exact_and_retains_authority() {
    let store = store().await;
    sqlx::query("update control.release_fleet_runs set state='failed',failure_class='audit_fixture_cleanup' where state in ('preflighting','preparing','paused','activating')")
        .execute(store.pool()).await.unwrap();
    sqlx::query("update control.deployment_driver_resource_leases set state='idle',authority_kind=null,driver_operation_id=null,effect_run_id=null,lease_owner=null,lease_token=null,lease_expires_at=null,heartbeat_at=null,quarantined_at=null,safe_error=null,updated_at=now() where resource_key='runtime/shared-odoo'")
        .execute(store.pool()).await.unwrap();

    let user = Uuid::new_v4();
    sqlx::query("insert into control.users(id,email) values($1,$2)")
        .bind(user)
        .bind(format!("immutable-release-{user}@example.test"))
        .execute(store.pool())
        .await
        .unwrap();
    let workshop = Uuid::new_v4();
    sqlx::query("insert into control.workshops(id,slug,display_name,time_zone) values($1,$2,'Immutable release publication','Europe/Paris')")
        .bind(workshop).bind(format!("immutable-release-{}", workshop.simple()))
        .execute(store.pool()).await.unwrap();
    let mut release = insert_leased_release_operation(store.pool(), "immutable-release-v2").await;
    attach_release_fleet_run(store.pool(), &mut release, &[workshop]).await;
    let fleet_run = release.fleet_run_id.unwrap();
    let item: Value =
        sqlx::query_scalar("select tenant_snapshot->0 from control.release_fleet_runs where id=$1")
            .bind(fleet_run)
            .fetch_one(store.pool())
            .await
            .unwrap();
    let database_id = Uuid::parse_str(item["database_id"].as_str().unwrap()).unwrap();
    let control =
        insert_route_control_operation(store.pool(), workshop, "immutable-release-projection")
            .await;
    let projection_digest = format!("sha256:{}", "1".repeat(64));
    let projection = json!({
        "database_id":database_id,"database_ref":item["database_ref"],
        "public_hostname":format!("{}.immutable-release.example.test",workshop.simple()),
        "paperless_mode":"absent","paperless_hostname":null,"custom_hostnames":[]
    });
    let materialized =
        materialize_route_projection(store.pool(), &control, &projection, &projection_digest).await;
    let route = RouteApplicationCall {
        control,
        idempotency_key: format!("immutable-release-apply:{workshop}"),
        request_digest: "2".repeat(64),
        generation: materialized.1.unwrap(),
        projection_digest: projection_digest.clone(),
        instance_owner: Uuid::new_v4(),
        execution_token: Uuid::new_v4(),
        resource_lease_token: Uuid::new_v4(),
    };
    let route_admission = admit_route_application(store.pool(), &route).await;
    let route_driver = route_admission.1.unwrap();
    let applied_fence = route_admission.2.unwrap();
    let applied_rendered = format!("sha256:{}", "3".repeat(64));
    let route_response = json!({"route_evidence":{
        "driver_operation_id":route_driver,"workshop_id":workshop,
        "route_generation":route.generation,"projection_digest":projection_digest,
        "disposition":"present","rendered_digest":applied_rendered,
        "route_fence_token":applied_fence
    }});
    assert!(
        finish_route_application(
            store.pool(),
            &route,
            route_driver,
            applied_fence,
            (
                "succeeded",
                Some(&route_response),
                Some(&applied_rendered),
                None
            )
        )
        .await
    );

    let admission = admit_release_route_snapshot_v2(store.pool(), &release).await;
    assert_eq!(admission.0, "acquired");
    let driver_operation = admission.1.unwrap();
    let global_fence = admission.2.unwrap();
    let route_lease_token = Uuid::new_v4();
    sqlx::query(
        "update control.operations set lease_expires_at=now()-interval '1 second' where id=$1",
    )
    .bind(release.control_operation_id)
    .execute(store.pool())
    .await
    .unwrap();
    let stale_admission: (String, Option<String>) = sqlx::query_as(
        "select outcome,target_slot from control.admit_immutable_release_route_publication($1,$2,$3,$4,$5,$6,300)",
    )
    .bind(driver_operation)
    .bind(release.instance_owner)
    .bind(release.execution_token)
    .bind(release.resource_lease_token)
    .bind(route_lease_token)
    .bind(global_fence)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(stale_admission.0, "authority_lost");
    let absent_publication: i64 = sqlx::query_scalar(
        "select count(*) from control.fleet_release_route_publications where driver_operation_id=$1",
    )
    .bind(driver_operation)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(absent_publication, 0);
    sqlx::query(
        "update control.operations set lease_expires_at=now()+interval '20 minutes' where id=$1",
    )
    .bind(release.control_operation_id)
    .execute(store.pool())
    .await
    .unwrap();
    let publication: (String, String, String, String, Vec<Uuid>) = sqlx::query_as(
        "select outcome,target_slot,maintenance_selector,candidate_selector,reserved_workshops
         from control.admit_immutable_release_route_publication($1,$2,$3,$4,$5,$6,300)",
    )
    .bind(driver_operation)
    .bind(release.instance_owner)
    .bind(release.execution_token)
    .bind(release.resource_lease_token)
    .bind(route_lease_token)
    .bind(global_fence)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(publication.0, "acquired");
    assert_eq!(publication.1, "blue");
    assert_eq!(
        publication.2,
        format!("generations/release-{}-maintenance", fleet_run.simple())
    );
    assert_eq!(
        publication.3,
        format!("generations/release-{}-candidate", fleet_run.simple())
    );
    assert_eq!(publication.4, vec![workshop]);
    let malformed_quarantine = sqlx::query(
        "update control.fleet_release_route_publications set
         phase='quarantined',interrupted_phase='candidate_sealed',
         quarantined_at=now(),safe_error='release_route_publication_outcome_unknown'
         where driver_operation_id=$1",
    )
    .bind(driver_operation)
    .execute(store.pool())
    .await
    .expect_err("quarantine evidence must exactly match its interrupted phase");
    assert_eq!(
        malformed_quarantine
            .as_database_error()
            .unwrap()
            .code()
            .as_deref(),
        Some("23514")
    );
    let replay_conflict: (String,Option<String>) = sqlx::query_as(
        "select outcome,target_slot from control.admit_immutable_release_route_publication($1,$2,$3,$4,$5,$6,300)")
        .bind(driver_operation).bind(release.instance_owner).bind(release.execution_token)
        .bind(release.resource_lease_token).bind(Uuid::new_v4()).bind(global_fence)
        .fetch_one(store.pool()).await.unwrap();
    assert_eq!(replay_conflict.0, "conflict");

    let wrong_identity = json!({
        "effect_run_id":7,
        "sealed_digest":format!("sha256:{}","4".repeat(64))
    });
    let invalid_type: String = sqlx::query_scalar(
        "select control.record_immutable_release_route_prior($1,$2,$3,$4,$5,$6,$7,11,12,$8)",
    )
    .bind(driver_operation)
    .bind(release.instance_owner)
    .bind(release.execution_token)
    .bind(release.resource_lease_token)
    .bind(route_lease_token)
    .bind(global_fence)
    .bind(format!("generations/startup-{}", Uuid::new_v4()))
    .bind(wrong_identity)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(invalid_type, "invalid");
    let null_non_boot: String = sqlx::query_scalar(
        "select control.record_immutable_release_route_prior($1,$2,$3,$4,$5,$6,$7,11,12,null)",
    )
    .bind(driver_operation)
    .bind(release.instance_owner)
    .bind(release.execution_token)
    .bind(release.resource_lease_token)
    .bind(route_lease_token)
    .bind(global_fence)
    .bind(format!("generations/startup-{}", Uuid::new_v4()))
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(null_non_boot, "invalid");
    let effect_run = Uuid::new_v4();
    let mismatched = json!({"effect_run_id":effect_run,
        "sealed_digest":format!("sha256:{}","4".repeat(64))});
    let selector_mismatch: String = sqlx::query_scalar(
        "select control.record_immutable_release_route_prior($1,$2,$3,$4,$5,$6,$7,11,12,$8)",
    )
    .bind(driver_operation)
    .bind(release.instance_owner)
    .bind(release.execution_token)
    .bind(release.resource_lease_token)
    .bind(route_lease_token)
    .bind(global_fence)
    .bind(format!("generations/startup-{}", Uuid::new_v4()))
    .bind(mismatched)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(selector_mismatch, "invalid");
    let prior_identity = json!({"effect_run_id":effect_run,
        "sealed_digest":format!("sha256:{}","4".repeat(64))});
    let prior: String = sqlx::query_scalar(
        "select control.record_immutable_release_route_prior($1,$2,$3,$4,$5,$6,$7,11,12,$8)",
    )
    .bind(driver_operation)
    .bind(release.instance_owner)
    .bind(release.execution_token)
    .bind(release.resource_lease_token)
    .bind(route_lease_token)
    .bind(global_fence)
    .bind(format!("generations/startup-{effect_run}"))
    .bind(prior_identity)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(prior, "recorded");
    sqlx::query(
        "update control.workshop_route_application_leases set lease_token=$2 where workshop_id=$1",
    )
    .bind(workshop)
    .bind(Uuid::new_v4())
    .execute(store.pool())
    .await
    .unwrap();
    let drifted_read: Vec<Uuid> = sqlx::query_scalar(
        "select workshop_id from control.read_immutable_release_route_snapshot_batch($1,$2,$3,$4,$5,$6,null,500)")
        .bind(driver_operation).bind(release.instance_owner).bind(release.execution_token)
        .bind(release.resource_lease_token).bind(route_lease_token).bind(global_fence)
        .fetch_all(store.pool()).await.unwrap();
    assert!(drifted_read.is_empty());
    sqlx::query(
        "update control.workshop_route_application_leases set lease_token=$2 where workshop_id=$1",
    )
    .bind(workshop)
    .bind(route_lease_token)
    .execute(store.pool())
    .await
    .unwrap();
    let mut read_tx = store.pool().begin().await.unwrap();
    let locked_read: Vec<Uuid> = sqlx::query_scalar(
        "select workshop_id from control.read_immutable_release_route_snapshot_batch($1,$2,$3,$4,$5,$6,null,500)",
    )
    .bind(driver_operation)
    .bind(release.instance_owner)
    .bind(release.execution_token)
    .bind(release.resource_lease_token)
    .bind(route_lease_token)
    .bind(global_fence)
    .fetch_all(&mut *read_tx)
    .await
    .unwrap();
    assert_eq!(locked_read, vec![workshop]);
    let mut competitor = store.pool().acquire().await.unwrap();
    sqlx::query("set lock_timeout='100ms'")
        .execute(&mut *competitor)
        .await
        .unwrap();
    let locked_out = sqlx::query(
        "update control.workshop_route_application_leases set lease_token=$2 where workshop_id=$1",
    )
    .bind(workshop)
    .bind(Uuid::new_v4())
    .execute(&mut *competitor)
    .await
    .expect_err("bounded read must retain exact route authority locks until transaction end");
    assert_eq!(
        locked_out.as_database_error().unwrap().code().as_deref(),
        Some("55P03")
    );
    drop(competitor);
    read_tx.rollback().await.unwrap();

    let maintenance_rendered = format!("sha256:{}", "5".repeat(64));
    let recorded: String = sqlx::query_scalar(
        "select control.record_immutable_release_route_candidate($1,$2,$3,$4,$5,$6,'maintenance',$7,$8,$9,$10,$11)")
        .bind(driver_operation).bind(release.instance_owner).bind(release.execution_token)
        .bind(release.resource_lease_token).bind(route_lease_token).bind(global_fence)
        .bind(workshop).bind(route.generation).bind(&route.projection_digest)
        .bind(&applied_rendered).bind(&maintenance_rendered)
        .fetch_one(store.pool()).await.unwrap();
    assert_eq!(recorded, "recorded");
    let maintenance_digest: String =
        sqlx::query_scalar("select control.release_route_overlay_digest($1,'maintenance')")
            .bind(driver_operation)
            .fetch_one(store.pool())
            .await
            .unwrap();
    let sealed: String = sqlx::query_scalar(
        "select control.seal_immutable_release_route_overlay($1,$2,$3,$4,$5,$6,'maintenance',$7,21,22,1,$8)")
        .bind(driver_operation).bind(release.instance_owner).bind(release.execution_token)
        .bind(release.resource_lease_token).bind(route_lease_token).bind(global_fence)
        .bind(&publication.2).bind(&maintenance_digest).fetch_one(store.pool()).await.unwrap();
    assert_eq!(sealed, "sealed");
    let started: String = sqlx::query_scalar(
        "select control.start_immutable_release_route_publication($1,$2,$3,$4,$5,$6,'maintenance')",
    )
    .bind(driver_operation)
    .bind(release.instance_owner)
    .bind(release.execution_token)
    .bind(release.resource_lease_token)
    .bind(route_lease_token)
    .bind(global_fence)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(started, "started");
    let observe_sql = "select control.observe_immutable_release_route_publication(
        $1,$2,$3,$4,$5,$6,$7,1::smallint,$8,$1,$6,$7,$9,'blue',$10,21,22)";
    let observed: String = sqlx::query_scalar(observe_sql)
        .bind(driver_operation)
        .bind(release.instance_owner)
        .bind(release.execution_token)
        .bind(release.resource_lease_token)
        .bind(route_lease_token)
        .bind(global_fence)
        .bind("maintenance")
        .bind(fleet_run)
        .bind(&maintenance_digest)
        .bind(&publication.2)
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(observed, "observed");
    let bad_replay: String = sqlx::query_scalar(observe_sql)
        .bind(driver_operation)
        .bind(release.instance_owner)
        .bind(release.execution_token)
        .bind(release.resource_lease_token)
        .bind(route_lease_token)
        .bind(global_fence)
        .bind("maintenance")
        .bind(fleet_run)
        .bind(format!("sha256:{}", "9".repeat(64)))
        .bind(&publication.2)
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(bad_replay, "observation_mismatch");
    let lost_replay: String = sqlx::query_scalar(
        "select control.begin_immutable_release_external_effects($1,$2,$3,$4,$5,$6)",
    )
    .bind(driver_operation)
    .bind(release.instance_owner)
    .bind(release.execution_token)
    .bind(release.resource_lease_token)
    .bind(Uuid::new_v4())
    .bind(global_fence)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(lost_replay, "authority_lost");
    let begun: String = sqlx::query_scalar(
        "select control.begin_immutable_release_external_effects($1,$2,$3,$4,$5,$6)",
    )
    .bind(driver_operation)
    .bind(release.instance_owner)
    .bind(release.execution_token)
    .bind(release.resource_lease_token)
    .bind(route_lease_token)
    .bind(global_fence)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(begun, "started");
    let before_stale_renewal: String = sqlx::query_scalar(
        "select lease_expires_at::text from control.deployment_driver_operations where id=$1",
    )
    .bind(driver_operation)
    .fetch_one(store.pool())
    .await
    .unwrap();
    sqlx::query(
        "update control.operations set lease_expires_at=now()-interval '1 second' where id=$1",
    )
    .bind(release.control_operation_id)
    .execute(store.pool())
    .await
    .unwrap();
    let stale_renewal: bool = sqlx::query_scalar(
        "select control.renew_immutable_release_route_publication($1,$2,$3,$4,$5,$6,300)",
    )
    .bind(driver_operation)
    .bind(release.instance_owner)
    .bind(release.execution_token)
    .bind(release.resource_lease_token)
    .bind(route_lease_token)
    .bind(global_fence)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert!(!stale_renewal);
    let after_stale_renewal: String = sqlx::query_scalar(
        "select lease_expires_at::text from control.deployment_driver_operations where id=$1",
    )
    .bind(driver_operation)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(before_stale_renewal, after_stale_renewal);
    let stale_transition: String = sqlx::query_scalar(
        "select control.begin_immutable_release_external_effects($1,$2,$3,$4,$5,$6)",
    )
    .bind(driver_operation)
    .bind(release.instance_owner)
    .bind(release.execution_token)
    .bind(release.resource_lease_token)
    .bind(route_lease_token)
    .bind(global_fence)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(stale_transition, "authority_lost");
    sqlx::query(
        "update control.operations set lease_expires_at=now()+interval '20 minutes' where id=$1",
    )
    .bind(release.control_operation_id)
    .execute(store.pool())
    .await
    .unwrap();
    sqlx::query("update control.workshop_route_application_leases set lease_expires_at=now()-interval '1 second' where workshop_id=$1")
        .bind(workshop).execute(store.pool()).await.unwrap();
    let expired_replay: String = sqlx::query_scalar(
        "select control.begin_immutable_release_external_effects($1,$2,$3,$4,$5,$6)",
    )
    .bind(driver_operation)
    .bind(release.instance_owner)
    .bind(release.execution_token)
    .bind(release.resource_lease_token)
    .bind(route_lease_token)
    .bind(global_fence)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(expired_replay, "authority_lost");
    sqlx::query("update control.workshop_route_application_leases set lease_expires_at=now()+interval '5 minutes' where workshop_id=$1")
        .bind(workshop).execute(store.pool()).await.unwrap();

    let candidate_rendered = format!("sha256:{}", "6".repeat(64));
    let candidate_recorded: String = sqlx::query_scalar(
        "select control.record_immutable_release_route_candidate($1,$2,$3,$4,$5,$6,'candidate',$7,$8,$9,$10,$11)")
        .bind(driver_operation).bind(release.instance_owner).bind(release.execution_token)
        .bind(release.resource_lease_token).bind(route_lease_token).bind(global_fence)
        .bind(workshop).bind(route.generation).bind(&route.projection_digest)
        .bind(&applied_rendered).bind(&candidate_rendered)
        .fetch_one(store.pool()).await.unwrap();
    assert_eq!(candidate_recorded, "recorded");
    let owner_fence: i64 = sqlx::query_scalar(
        "select route_fence_token from control.fleet_release_route_publication_owners where driver_operation_id=$1")
        .bind(driver_operation).fetch_one(store.pool()).await.unwrap();
    let bad_binding = sqlx::query(
        "update control.workshop_route_projection_state set applied_driver_operation_id=$2,
         applied_fence_token=$3,applied_rendered_digest=$4 where workshop_id=$1",
    )
    .bind(workshop)
    .bind(driver_operation)
    .bind(owner_fence)
    .bind(format!("sha256:{}", "7".repeat(64)))
    .execute(store.pool())
    .await
    .expect_err("candidate head binding must require the exact immutable rendered digest");
    assert_eq!(
        bad_binding.as_database_error().unwrap().code().as_deref(),
        Some("55000")
    );
    let candidate_digest: String =
        sqlx::query_scalar("select control.release_route_overlay_digest($1,'candidate')")
            .bind(driver_operation)
            .fetch_one(store.pool())
            .await
            .unwrap();
    let candidate_sealed: String = sqlx::query_scalar(
        "select control.seal_immutable_release_route_overlay($1,$2,$3,$4,$5,$6,'candidate',$7,31,32,1,$8)")
        .bind(driver_operation).bind(release.instance_owner).bind(release.execution_token)
        .bind(release.resource_lease_token).bind(route_lease_token).bind(global_fence)
        .bind(&publication.3).bind(&candidate_digest).fetch_one(store.pool()).await.unwrap();
    assert_eq!(candidate_sealed, "sealed");
    let candidate_started: String = sqlx::query_scalar(
        "select control.start_immutable_release_route_publication($1,$2,$3,$4,$5,$6,'candidate')",
    )
    .bind(driver_operation)
    .bind(release.instance_owner)
    .bind(release.execution_token)
    .bind(release.resource_lease_token)
    .bind(route_lease_token)
    .bind(global_fence)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(candidate_started, "started");
    let candidate_observed: String = sqlx::query_scalar(
        "select control.observe_immutable_release_route_publication(
         $1,$2,$3,$4,$5,$6,'candidate',1::smallint,$7,$1,$6,'candidate',$8,'blue',$9,31,32)",
    )
    .bind(driver_operation)
    .bind(release.instance_owner)
    .bind(release.execution_token)
    .bind(release.resource_lease_token)
    .bind(route_lease_token)
    .bind(global_fence)
    .bind(fleet_run)
    .bind(&candidate_digest)
    .bind(&publication.3)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(candidate_observed, "observed");
    let retained: (String,String,i64) = sqlx::query_as(
        "select publication.phase,global_lease.state,
         (select count(*) from control.workshop_route_application_leases route_lease
          where route_lease.release_publication_id=$1 and route_lease.state='held')
         from control.fleet_release_route_publications publication
         join control.deployment_driver_resource_leases global_lease on global_lease.resource_key='runtime/shared-odoo'
         where publication.driver_operation_id=$1")
        .bind(driver_operation).fetch_one(store.pool()).await.unwrap();
    assert_eq!(
        retained,
        ("awaiting_worker_finalize".into(), "held".into(), 1)
    );
    let mut completion_tx = store.pool().begin().await.unwrap();
    let release_identity: (String, String) = sqlx::query_as(
        "select run.release_id,release.odoo_subject_digest
         from control.release_fleet_runs run
         join control.application_releases release on release.id=run.release_id
         where run.id=$1",
    )
    .bind(fleet_run)
    .fetch_one(&mut *completion_tx)
    .await
    .unwrap();
    let runtime_deployment_ref = "registry.example.test/odoo@sha256:test";
    let runtime_manifest = json!({
        "release_id": release_identity.0,
        "odoo_runtime": {
            "deployment_ref": runtime_deployment_ref,
            "subject_digest": release_identity.1,
            "platforms": [{
                "platform": {"os":"linux","architecture":"amd64"},
                "manifest_digest": format!("sha256:{}","8".repeat(64)),
                "config_digest": format!("sha256:{}","9".repeat(64))
            }]
        },
        "extension_bundle": {
            "subject_digest": release_identity.1,
            "platforms": [{
                "platform": {"os":"linux","architecture":"amd64"},
                "manifest_digest": format!("sha256:{}","a".repeat(64)),
                "config_digest": format!("sha256:{}","b".repeat(64)),
                "payload_digest": format!("sha256:{}","c".repeat(64))
            }]
        },
        "pair_qualifications": [{
            "platform": {"os":"linux","architecture":"amd64"},
            "odoo_manifest_digest": format!("sha256:{}","8".repeat(64)),
            "extension_manifest_digest": format!("sha256:{}","a".repeat(64)),
            "payload_digest": format!("sha256:{}","c".repeat(64)),
            "qualification_result":"passed",
            "qualification_digest": release_identity.1
        }],
        "addons": {},
        "bridge_contract_digest": format!("sha256:{}","d".repeat(64))
    });
    sqlx::query(
        "update control.application_releases
         set manifest=$2,
             version=version+1 where id=$1",
    )
    .bind(&release_identity.0)
    .bind(&runtime_manifest)
    .execute(&mut *completion_tx)
    .await
    .unwrap();
    sqlx::query("savepoint before_completion_probe")
        .execute(&mut *completion_tx)
        .await
        .unwrap();
    for adoption_state in [
        "isolating",
        "backing_up",
        "upgrading",
        "verifying",
        "prepared",
    ] {
        sqlx::query(
            "update control.tenant_release_adoptions set state=$3,version=version+1
             where operation_id=$1 and release_id=$2",
        )
        .bind(release.control_operation_id)
        .bind(&release_identity.0)
        .bind(adoption_state)
        .execute(&mut *completion_tx)
        .await
        .unwrap();
    }
    let prepared: Value = sqlx::query_scalar(
        "select coalesce(jsonb_agg(jsonb_build_object(
          'adoption_id',adoption.id,'workshop_id',adoption.workshop_id,
          'database_id',adoption.database_id,'database_ref',database.database_ref,
          'public_hostname',database.public_hostname)
          order by adoption.created_at,adoption.id),'[]'::jsonb)
         from control.tenant_release_adoptions adoption
         join control.odoo_databases database
          on database.id=adoption.database_id and database.workshop_id=adoption.workshop_id
         where adoption.operation_id=$1 and adoption.release_id=$2
          and adoption.state='prepared'",
    )
    .bind(release.control_operation_id)
    .bind(&release_identity.0)
    .fetch_one(&mut *completion_tx)
    .await
    .unwrap();
    let driver_action_id = Uuid::new_v4();
    let activation_intent_id = Uuid::new_v4();
    let gateway_digest = format!("sha256:{}", "7".repeat(64));
    sqlx::query(
        "insert into control.fleet_activation_intents(
          id,fleet_run_id,release_id,runtime_key,target_slot,odoo_subject_digest,
          extension_subject_digest,pair_qualification_digest,prepared_tenants,
          gateway_configuration_digest,driver_action_id,driver_fence_token,
          gateway_identity_version)
         values($1,$2,$3,'shared-odoo','blue',$4,$4,$4,'[]',$5,$6,$7,1)",
    )
    .bind(activation_intent_id)
    .bind(fleet_run)
    .bind(&release_identity.0)
    .bind(&release_identity.1)
    .bind(&gateway_digest)
    .bind(driver_action_id)
    .bind(global_fence)
    .execute(&mut *completion_tx)
    .await
    .unwrap();
    let invalid_evidence = json!({
        "release_id":release_identity.0,"odoo_subject_digest":release_identity.1,
        "extension_subject_digest":release_identity.1,
        "odoo_manifest_digest":format!("sha256:{}","8".repeat(64)),
        "odoo_config_digest":format!("sha256:{}","9".repeat(64)),
        "extension_manifest_digest":format!("sha256:{}","a".repeat(64)),
        "extension_config_digest":format!("sha256:{}","b".repeat(64)),
        "payload_digest":format!("sha256:{}","c".repeat(64)),
        "extension_volume":"mb-control-ext-aaaaaaaaaaaaaaaa-cccccccccccccccc","pair_qualification_digest":release_identity.1,
        "bridge_contract_digest":format!("sha256:{}","d".repeat(64)),
        "installed_addon_versions":{},"runtime_key":"shared-odoo","target_slot":"blue",
        "runtime_container":"mb-control-odoo-blue","runtime_role":format!("mb_runtime_{}",&release_identity.1[7..23]),
        "runtime_deployment_ref":runtime_deployment_ref,"runtime_config_digest":format!("sha256:{}","e".repeat(64)),
        "prepared_tenants":prepared,"fleet_generation":1,
        "tenant_snapshot":sqlx::query_scalar::<_,Value>("select tenant_snapshot from control.release_fleet_runs where id=$1").bind(fleet_run).fetch_one(&mut *completion_tx).await.unwrap(),
        "gateway_configuration_digest":gateway_digest,"driver_action_id":driver_action_id,
        "driver_operation_id":driver_operation,"driver_fence_token":global_fence,
        "old_runtime_database_access_revoked":true,"tenant_recovery_verified":true,
        "candidate_smoke_verified":true,"candidate_restart_policy":"unless-stopped",
        "retained_restart_policy":"no"
    });
    let premature: String = sqlx::query_scalar(
        "select outcome from control.finish_immutable_release_route_publication(
          $1,$2,$3,$4,$5,$6,jsonb_build_object('evidence',$7::jsonb))",
    )
    .bind(driver_operation)
    .bind(release.instance_owner)
    .bind(release.execution_token)
    .bind(release.resource_lease_token)
    .bind(route_lease_token)
    .bind(global_fence)
    .bind(&invalid_evidence)
    .fetch_one(&mut *completion_tx)
    .await
    .unwrap();
    assert_eq!(premature, "state_drift");
    sqlx::query("rollback to savepoint before_completion_probe")
        .execute(&mut *completion_tx)
        .await
        .unwrap();

    // Recreate exact worker-owned preparation and observed activation intent,
    // then prove the driver close does not activate those rows itself.
    for adoption_state in [
        "isolating",
        "backing_up",
        "upgrading",
        "verifying",
        "prepared",
    ] {
        sqlx::query(
            "update control.tenant_release_adoptions set state=$3,version=version+1
             where operation_id=$1 and release_id=$2",
        )
        .bind(release.control_operation_id)
        .bind(&release_identity.0)
        .bind(adoption_state)
        .execute(&mut *completion_tx)
        .await
        .unwrap();
    }
    sqlx::query(
        "insert into control.fleet_activation_intents(
          id,fleet_run_id,release_id,runtime_key,target_slot,odoo_subject_digest,
          extension_subject_digest,pair_qualification_digest,prepared_tenants,
          gateway_configuration_digest,driver_action_id,driver_fence_token,
          gateway_identity_version,observed_configuration_digest,activated_at)
         values($1,$2,$3,'shared-odoo','blue',$4,$4,$4,$5,$6,$7,$8,1,$6,now())",
    )
    .bind(activation_intent_id)
    .bind(fleet_run)
    .bind(&release_identity.0)
    .bind(&release_identity.1)
    .bind(&prepared)
    .bind(&gateway_digest)
    .bind(driver_action_id)
    .bind(global_fence)
    .execute(&mut *completion_tx)
    .await
    .unwrap();
    let exact_response = json!({"evidence":invalid_evidence});
    let finished: (String, Option<Value>) = sqlx::query_as(
        "select outcome,stored_response
         from control.finish_immutable_release_route_publication($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(driver_operation)
    .bind(release.instance_owner)
    .bind(release.execution_token)
    .bind(release.resource_lease_token)
    .bind(route_lease_token)
    .bind(global_fence)
    .bind(&exact_response)
    .fetch_one(&mut *completion_tx)
    .await
    .unwrap();
    assert_eq!(finished, ("finished".into(), Some(exact_response.clone())));
    let closed: (String, String, String, String, String, i64) = sqlx::query_as(
        "select publication.phase,operation.state,global_lease.state,route_lease.state,
          run.state,(select count(*) from control.fleet_release_route_publication_completions
                     where driver_operation_id=$1 and fleet_run_id=$2
                       and candidate_route_set_digest=$3)
         from control.fleet_release_route_publications publication
         join control.deployment_driver_operations operation on operation.id=publication.driver_operation_id
         join control.deployment_driver_resource_leases global_lease on global_lease.resource_key='runtime/shared-odoo'
         join control.workshop_route_application_leases route_lease on route_lease.workshop_id=$4
         join control.release_fleet_runs run on run.id=publication.fleet_run_id
         where publication.driver_operation_id=$1",
    )
    .bind(driver_operation)
    .bind(fleet_run)
    .bind(&candidate_digest)
    .bind(workshop)
    .fetch_one(&mut *completion_tx)
    .await
    .unwrap();
    assert_eq!(
        closed,
        (
            "completed".into(),
            "succeeded".into(),
            "idle".into(),
            "idle".into(),
            "preparing".into(),
            1
        )
    );
    let activated_elsewhere: (i64, i64, i64, bool) = sqlx::query_as(
        "select (select count(*) from control.tenant_release_adoptions where operation_id=$1 and state='active'),
          (select count(*) from control.runtime_release_slots where release_id=$2 and state='active'),
          (select count(*) from control.application_releases where id=$2 and status='active'),
          exists(select 1 from control.workshop_route_projection_state
           where workshop_id=$3 and applied_rendered_digest=$4 and applied_fence_token=$5
            and applied_driver_operation_id=$6)",
    )
    .bind(release.control_operation_id)
    .bind(&release_identity.0)
    .bind(workshop)
    .bind(&candidate_rendered)
    .bind(owner_fence)
    .bind(driver_operation)
    .fetch_one(&mut *completion_tx)
    .await
    .unwrap();
    assert_eq!(activated_elsewhere, (0, 0, 0, true));
    let finish_replay: String = sqlx::query_scalar(
        "select outcome from control.finish_immutable_release_route_publication($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(driver_operation).bind(release.instance_owner).bind(release.execution_token)
    .bind(release.resource_lease_token).bind(route_lease_token).bind(global_fence)
    .bind(&exact_response).fetch_one(&mut *completion_tx).await.unwrap();
    assert_eq!(finish_replay, "replay");
    let finish_conflict: String = sqlx::query_scalar(
        "select outcome from control.finish_immutable_release_route_publication($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(driver_operation).bind(release.instance_owner).bind(release.execution_token)
    .bind(release.resource_lease_token).bind(route_lease_token).bind(global_fence)
    .bind(json!({"evidence":{}})).fetch_one(&mut *completion_tx).await.unwrap();
    assert_eq!(finish_conflict, "conflict");
    let stale_finish: String = sqlx::query_scalar(
        "select outcome from control.finish_immutable_release_route_publication($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(driver_operation)
    .bind(release.instance_owner)
    .bind(release.execution_token)
    .bind(release.resource_lease_token)
    .bind(Uuid::new_v4())
    .bind(global_fence)
    .bind(&exact_response)
    .fetch_one(&mut *completion_tx)
    .await
    .unwrap();
    assert_eq!(stale_finish, "conflict");
    let replay_result: (String, Option<Value>) = sqlx::query_as(
        "select outcome,stored_response from control.read_immutable_release_route_publication_result($1,$2)",
    ).bind(driver_operation).bind(fleet_run).fetch_one(&mut *completion_tx).await.unwrap();
    assert_eq!(
        replay_result,
        ("replay".into(), Some(exact_response.clone()))
    );
    let result_conflict: String = sqlx::query_scalar(
        "select outcome from control.read_immutable_release_route_publication_result($1,$2)",
    )
    .bind(driver_operation)
    .bind(Uuid::new_v4())
    .fetch_one(&mut *completion_tx)
    .await
    .unwrap();
    assert_eq!(result_conflict, "conflict");
    completion_tx.rollback().await.unwrap();

    let pending_result: (String, Option<Value>) = sqlx::query_as(
        "select outcome,stored_response
         from control.read_immutable_release_route_publication_result($1,$2)",
    )
    .bind(driver_operation)
    .bind(fleet_run)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(pending_result, ("pending".into(), None));
    let malformed_finish: (String, Option<Value>) = sqlx::query_as(
        "select outcome,stored_response
         from control.finish_immutable_release_route_publication(
          $1,$2,$3,$4,$5,$6,'{\"evidence\":{}}'::jsonb)",
    )
    .bind(driver_operation)
    .bind(release.instance_owner)
    .bind(release.execution_token)
    .bind(release.resource_lease_token)
    .bind(route_lease_token)
    .bind(global_fence)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(malformed_finish, ("invalid".into(), None));
    assert!(
        !finish_release_driver_lease(
            store.pool(),
            &release,
            driver_operation,
            global_fence,
            &json!({"forbidden":true})
        )
        .await
    );
    let legacy_renewal: bool = sqlx::query_scalar(
        "select control.renew_release_driver_lease($1,$2,$3,$4,$5,$6,$7,$8,300)",
    )
    .bind(driver_operation)
    .bind(release.control_operation_id)
    .bind(release.control_operation_attempt)
    .bind(&release.control_operation_owner)
    .bind(release.instance_owner)
    .bind(release.execution_token)
    .bind(release.resource_lease_token)
    .bind(global_fence)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert!(!legacy_renewal);
    let legacy_reconciliation: String = sqlx::query_scalar(
        "select outcome from control.admit_fleet_release_reconciliation(
         $1,$2,$3,$4,$5,$6,$7,$8,$9,300)",
    )
    .bind(release.control_operation_id)
    .bind(release.control_operation_attempt)
    .bind(&release.control_operation_owner)
    .bind(&release.idempotency_key)
    .bind(&release.target_key)
    .bind(fleet_run)
    .bind(&release.request_digest)
    .bind(Uuid::new_v4())
    .bind(Uuid::new_v4())
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(legacy_reconciliation, "protocol_conflict");
    let private_acl: Vec<bool> = sqlx::query_scalar(
        "select allowed from (values
         (has_function_privilege('public','control.finish_release_driver_operation_pre_route_publication(uuid,uuid,uuid,uuid,bigint,text,jsonb,text)','execute')),
         (has_function_privilege('public','control.renew_release_driver_lease_pre_route_publication(uuid,uuid,integer,text,uuid,uuid,uuid,bigint,integer)','execute')),
         (has_function_privilege('public','control.admit_fleet_release_reconciliation_pre_route_publication(uuid,integer,text,text,text,uuid,text,uuid,uuid,integer)','execute')),
         (has_function_privilege('public','control.finish_fleet_release_reconciliation_pre_route_publication(uuid,uuid,uuid,text,jsonb)','execute'))
         ) acl(allowed)")
        .fetch_all(store.pool()).await.unwrap();
    assert_eq!(private_acl, vec![false, false, false, false]);
    let quarantined: bool = sqlx::query_scalar(
        "select control.quarantine_immutable_release_route_publication($1,$2,$3,$4,$5,$6,'release_route_publication_outcome_unknown')")
        .bind(driver_operation).bind(release.instance_owner).bind(release.execution_token)
        .bind(release.resource_lease_token).bind(route_lease_token).bind(global_fence)
        .fetch_one(store.pool()).await.unwrap();
    assert!(quarantined);
    let false_replay: bool = sqlx::query_scalar(
        "select control.quarantine_immutable_release_route_publication($1,$2,$3,$4,$5,$6,'release_route_publication_outcome_unknown')")
        .bind(driver_operation).bind(release.instance_owner).bind(release.execution_token)
        .bind(release.resource_lease_token).bind(Uuid::new_v4()).bind(global_fence)
        .fetch_one(store.pool()).await.unwrap();
    assert!(!false_replay);
    let exact_replay: bool = sqlx::query_scalar(
        "select control.quarantine_immutable_release_route_publication($1,$2,$3,$4,$5,$6,'release_route_publication_outcome_unknown')")
        .bind(driver_operation).bind(release.instance_owner).bind(release.execution_token)
        .bind(release.resource_lease_token).bind(route_lease_token).bind(global_fence)
        .fetch_one(store.pool()).await.unwrap();
    assert!(exact_replay);

    // The normal completion probe was rolled back. Recreate the exact worker
    // preparation durably so recovery must validate the same 0036 response.
    for adoption_state in [
        "isolating",
        "backing_up",
        "upgrading",
        "verifying",
        "prepared",
    ] {
        sqlx::query(
            "update control.tenant_release_adoptions set state=$3,version=version+1
             where operation_id=$1 and release_id=$2",
        )
        .bind(release.control_operation_id)
        .bind(&release_identity.0)
        .bind(adoption_state)
        .execute(store.pool())
        .await
        .unwrap();
    }
    sqlx::query(
        "insert into control.fleet_activation_intents(
          id,fleet_run_id,release_id,runtime_key,target_slot,odoo_subject_digest,
          extension_subject_digest,pair_qualification_digest,prepared_tenants,
          gateway_configuration_digest,driver_action_id,driver_fence_token,
          gateway_identity_version,observed_configuration_digest,activated_at)
         values($1,$2,$3,'shared-odoo','blue',$4,$4,$4,$5,$6,$7,$8,1,$6,now())",
    )
    .bind(activation_intent_id)
    .bind(fleet_run)
    .bind(&release_identity.0)
    .bind(&release_identity.1)
    .bind(&prepared)
    .bind(&gateway_digest)
    .bind(driver_action_id)
    .bind(global_fence)
    .execute(store.pool())
    .await
    .unwrap();

    sqlx::query(
        "update control.application_releases
         set manifest=$2,
             version=version+1,updated_at=now() where id=$1",
    )
    .bind(&release_identity.0)
    .bind(&runtime_manifest)
    .execute(store.pool())
    .await
    .unwrap();

    let runtime_recovery_point = Uuid::new_v4();
    let mut runtime_recovery_setup = store.pool().begin().await.unwrap();
    sqlx::query(
        "insert into control.workshop_recovery_points(
          id,workshop_id,database_id,operation_id,kind,label,state,requested_by,
          ready_at,verification_state,verified_at)
         values($1,$2,$3,$4,'backup','Release runtime receipt','ready',
          $5,now(),'verified',now())",
    )
    .bind(runtime_recovery_point)
    .bind(workshop)
    .bind(database_id)
    .bind(release.control_operation_id)
    .bind(user)
    .execute(&mut *runtime_recovery_setup)
    .await
    .unwrap();
    sqlx::query("set local session_replication_role=replica")
        .execute(&mut *runtime_recovery_setup)
        .await
        .unwrap();
    sqlx::query(
        "update control.tenant_release_adoptions
         set backup_recovery_id=$3,verified_at=now()
         where operation_id=$1 and release_id=$2 and state='prepared'",
    )
    .bind(release.control_operation_id)
    .bind(&release_identity.0)
    .bind(runtime_recovery_point)
    .execute(&mut *runtime_recovery_setup)
    .await
    .unwrap();
    sqlx::query("set local session_replication_role=origin")
        .execute(&mut *runtime_recovery_setup)
        .await
        .unwrap();
    runtime_recovery_setup.commit().await.unwrap();

    let recovery_worker = format!("release-recovery-{}", Uuid::new_v4().simple());
    let recovery_attempt = release.control_operation_attempt + 1;
    sqlx::query(
        "update control.operations set attempt=$2,leased_by=$3,
          lease_expires_at=now()+interval '10 minutes',state='in_flight'
          where id=$1",
    )
    .bind(release.control_operation_id)
    .bind(recovery_attempt)
    .bind(&recovery_worker)
    .execute(store.pool())
    .await
    .unwrap();
    let null_claim: String = sqlx::query_scalar(
        "select outcome from control.claim_interrupted_immutable_release_route_publication(
          $1,null,null,$2,$3,null)",
    )
    .bind(driver_operation)
    .bind(Uuid::new_v4())
    .bind(Uuid::new_v4())
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(null_claim, "invalid");
    let recovery_owner = Uuid::new_v4();
    let recovery_token = Uuid::new_v4();
    let stale_claim: (String, Option<i64>, Option<String>) = sqlx::query_as(
        "select outcome,claim_fence,claim_mode
         from control.claim_interrupted_immutable_release_route_publication(
          $1,$2,$3,$4,$5,300)",
    )
    .bind(driver_operation)
    .bind(release.control_operation_attempt)
    .bind(&release.control_operation_owner)
    .bind(recovery_owner)
    .bind(recovery_token)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(stale_claim, ("authority_lost".into(), None, None));
    let acquired_claim: (String, Option<i64>, Option<String>) = sqlx::query_as(
        "select outcome,claim_fence,claim_mode
         from control.claim_interrupted_immutable_release_route_publication(
          $1,$2,$3,$4,$5,300)",
    )
    .bind(driver_operation)
    .bind(recovery_attempt)
    .bind(&recovery_worker)
    .bind(recovery_owner)
    .bind(recovery_token)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(
        acquired_claim,
        ("acquired".into(), Some(1), Some("forward_only".into()))
    );
    let runtime_expectation: (String, Option<Value>) = sqlx::query_as(
        "select outcome,expectation
         from control.read_interrupted_immutable_release_runtime_expectation(
          $1,$2,$3,$4,$5,1)",
    )
    .bind(driver_operation)
    .bind(recovery_attempt)
    .bind(&recovery_worker)
    .bind(recovery_owner)
    .bind(recovery_token)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(runtime_expectation.0, "claimed");
    let runtime_expectation = runtime_expectation.1.unwrap();
    assert_eq!(runtime_expectation["protocol_version"], 1);
    assert_eq!(
        runtime_expectation["driver_operation_id"],
        json!(driver_operation)
    );
    assert_eq!(runtime_expectation["fleet_run_id"], json!(fleet_run));
    assert_eq!(runtime_expectation["release_id"], release_identity.0);
    assert_eq!(runtime_expectation["target_slot"], "blue");
    assert_eq!(runtime_expectation["prepared_tenants"], prepared);
    assert_eq!(
        runtime_expectation["gateway_configuration_digest"],
        gateway_digest
    );
    let lost_runtime_expectation: (String, Option<Value>) = sqlx::query_as(
        "select outcome,expectation
         from control.read_interrupted_immutable_release_runtime_expectation(
          $1,$2,$3,$4,$5,1)",
    )
    .bind(driver_operation)
    .bind(recovery_attempt)
    .bind(&recovery_worker)
    .bind(recovery_owner)
    .bind(Uuid::new_v4())
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(lost_runtime_expectation, ("claim_lost".into(), None));
    for (kind, evidence) in [
        (
            "unstarted",
            json!({"observed_loaded_identity": {
                "protocol_version": 1,
                "fleet_run_id": fleet_run,
                "driver_operation_id": driver_operation
            }}),
        ),
        (
            "prior",
            json!({"observed_selector":"generations/boot-live",
                "observed_loaded_identity":null}),
        ),
    ] {
        let unsafe_resolution: String = sqlx::query_scalar(
            "select control.resolve_interrupted_immutable_release_route_publication(
              $1,$2,$3,$4,$5,1,$6,$7,null)",
        )
        .bind(driver_operation)
        .bind(recovery_attempt)
        .bind(&recovery_worker)
        .bind(recovery_owner)
        .bind(recovery_token)
        .bind(kind)
        .bind(evidence)
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(unsafe_resolution, "unsupported_resolution");
    }
    let unsafe_resolution_count: i64 = sqlx::query_scalar(
        "select count(*) from control.fleet_release_route_publication_recovery_resolutions
          where driver_operation_id=$1 and claim_fence=1",
    )
    .bind(driver_operation)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(unsafe_resolution_count, 0);
    let direct_unsafe_resolution = sqlx::query(
        "insert into control.fleet_release_route_publication_recovery_resolutions(
          driver_operation_id,fleet_run_id,claim_fence,control_operation_attempt,
          control_operation_lease_owner,reconciliation_owner,reconciliation_token_digest,
          claim_mode,resolution_kind,observation_evidence,candidate_response)
         values($1,$2,1,$3,$4,$5,control.release_route_recovery_token_digest($6),
          'forward_only','unstarted','{}'::jsonb,null)",
    )
    .bind(driver_operation)
    .bind(fleet_run)
    .bind(recovery_attempt)
    .bind(&recovery_worker)
    .bind(recovery_owner)
    .bind(recovery_token)
    .execute(store.pool())
    .await
    .expect_err("the defense-in-depth constraint must reject an unsafe direct row");
    assert_eq!(
        direct_unsafe_resolution
            .as_database_error()
            .unwrap()
            .code()
            .as_deref(),
        Some("23514")
    );
    let mut historical_resolution_probe = store.pool().begin().await.unwrap();
    sqlx::query(
        "alter table control.fleet_release_route_publication_recovery_resolutions
          drop constraint fleet_release_route_recovery_resolutions_safe_kind_check",
    )
    .execute(&mut *historical_resolution_probe)
    .await
    .unwrap();
    sqlx::query(
        "insert into control.fleet_release_route_publication_recovery_resolutions(
          driver_operation_id,fleet_run_id,claim_fence,control_operation_attempt,
          control_operation_lease_owner,reconciliation_owner,reconciliation_token_digest,
          claim_mode,resolution_kind,observation_evidence,candidate_response)
         values($1,$2,1,$3,$4,$5,control.release_route_recovery_token_digest($6),
          'forward_only','unstarted','{}'::jsonb,null)",
    )
    .bind(driver_operation)
    .bind(fleet_run)
    .bind(recovery_attempt)
    .bind(&recovery_worker)
    .bind(recovery_owner)
    .bind(recovery_token)
    .execute(&mut *historical_resolution_probe)
    .await
    .unwrap();
    let historical_finish: (String, Option<Value>) = sqlx::query_as(
        "select outcome,stored_response
         from control.finish_interrupted_immutable_release_route_publication(
          $1,$2,$3,$4,$5,1,'unstarted',$6)",
    )
    .bind(driver_operation)
    .bind(recovery_attempt)
    .bind(&recovery_worker)
    .bind(recovery_owner)
    .bind(recovery_token)
    .bind(format!("sha256:{}", "a".repeat(64)))
    .fetch_one(&mut *historical_resolution_probe)
    .await
    .unwrap();
    assert_eq!(historical_finish, ("unsupported_resolution".into(), None));
    let historical_terminal_count: i64 = sqlx::query_scalar(
        "select count(*) from control.fleet_release_route_publication_recovery_terminals
          where driver_operation_id=$1",
    )
    .bind(driver_operation)
    .fetch_one(&mut *historical_resolution_probe)
    .await
    .unwrap();
    assert_eq!(historical_terminal_count, 0);
    historical_resolution_probe.rollback().await.unwrap();
    let mut runtime_drift_probe = store.pool().begin().await.unwrap();
    sqlx::query("set local session_replication_role=replica")
        .execute(&mut *runtime_drift_probe)
        .await
        .unwrap();
    sqlx::query(
        "update control.fleet_activation_intents set activated_at=null,
          observed_configuration_digest=null where id=$1",
    )
    .bind(activation_intent_id)
    .execute(&mut *runtime_drift_probe)
    .await
    .unwrap();
    sqlx::query("set local session_replication_role=origin")
        .execute(&mut *runtime_drift_probe)
        .await
        .unwrap();
    let drifted_runtime_expectation: (String, Option<Value>) = sqlx::query_as(
        "select outcome,expectation
         from control.read_interrupted_immutable_release_runtime_expectation(
          $1,$2,$3,$4,$5,1)",
    )
    .bind(driver_operation)
    .bind(recovery_attempt)
    .bind(&recovery_worker)
    .bind(recovery_owner)
    .bind(recovery_token)
    .fetch_one(&mut *runtime_drift_probe)
    .await
    .unwrap();
    assert_eq!(drifted_runtime_expectation, ("state_drift".into(), None));
    runtime_drift_probe.rollback().await.unwrap();
    // This publication was intentionally driven through candidate observation
    // for the later terminal-race assertions. Rewind only the immutable
    // evidence rows inside a rolled-back probe to exercise the reader's exact
    // candidate_staging boundary without weakening the production function.
    let mut snapshot_probe = store.pool().begin().await.unwrap();
    sqlx::query("set local session_replication_role=replica")
        .execute(&mut *snapshot_probe)
        .await
        .unwrap();
    sqlx::query(
        "update control.fleet_release_route_publications set
          interrupted_phase='candidate_staging',candidate_sealed_count=null,
          candidate_route_set_digest=null,candidate_directory_device=null,
          candidate_directory_inode=null,candidate_publication_started_at=null,
          candidate_observed_at=null where driver_operation_id=$1",
    )
    .bind(driver_operation)
    .execute(&mut *snapshot_probe)
    .await
    .unwrap();
    sqlx::query(
        "update control.fleet_release_route_publication_recovery_route_heads set
          applied_rendered_digest=$2,applied_fence_token=$3
          where driver_operation_id=$1 and claim_fence=1",
    )
    .bind(driver_operation)
    .bind(&applied_rendered)
    .bind(applied_fence)
    .execute(&mut *snapshot_probe)
    .await
    .unwrap();
    sqlx::query("set local session_replication_role=origin")
        .execute(&mut *snapshot_probe)
        .await
        .unwrap();
    let snapshot_page: RecoverySnapshotBatchRow = sqlx::query_as(
        "select * from control.read_interrupted_immutable_release_route_snapshot_batch(
          $1,$2,$3,$4,$5,1,null,1)",
    )
    .bind(driver_operation)
    .bind(recovery_attempt)
    .bind(&recovery_worker)
    .bind(recovery_owner)
    .bind(recovery_token)
    .fetch_one(&mut *snapshot_probe)
    .await
    .unwrap();
    assert_eq!(snapshot_page.0, "claimed");
    assert_eq!(snapshot_page.1, Some(workshop));
    assert_eq!(snapshot_page.2, Some(database_id));
    assert_eq!(snapshot_page.3.as_deref(), item["database_ref"].as_str());
    assert_eq!(snapshot_page.4, Some(false));
    assert_eq!(snapshot_page.5, Some(route.generation));
    assert_eq!(snapshot_page.6.as_ref(), Some(&route.projection_digest));
    assert_eq!(snapshot_page.7.as_deref(), Some("present"));
    assert_eq!(snapshot_page.8.as_ref(), Some(&projection));
    assert_eq!(snapshot_page.9.as_ref(), Some(&applied_rendered));
    assert_eq!(snapshot_page.10, Some(applied_fence));
    assert_eq!(snapshot_page.11, Some(applied_fence));
    assert_eq!(snapshot_page.12.as_deref(), Some("blue"));
    let completed_page: (String, Option<Uuid>) = sqlx::query_as(
        "select outcome,workshop_id
         from control.read_interrupted_immutable_release_route_snapshot_batch(
          $1,$2,$3,$4,$5,1,$6,1)",
    )
    .bind(driver_operation)
    .bind(recovery_attempt)
    .bind(&recovery_worker)
    .bind(recovery_owner)
    .bind(recovery_token)
    .bind(workshop)
    .fetch_one(&mut *snapshot_probe)
    .await
    .unwrap();
    assert_eq!(completed_page, ("complete".into(), None));
    let invalid_snapshot_request: String = sqlx::query_scalar(
        "select outcome from control.read_interrupted_immutable_release_route_snapshot_batch(
          $1,$2,$3,$4,$5,1,'00000000-0000-0000-0000-000000000000'::uuid,1)",
    )
    .bind(driver_operation)
    .bind(recovery_attempt)
    .bind(&recovery_worker)
    .bind(recovery_owner)
    .bind(recovery_token)
    .fetch_one(&mut *snapshot_probe)
    .await
    .unwrap();
    assert_eq!(invalid_snapshot_request, "invalid");
    let lost_snapshot_claim: String = sqlx::query_scalar(
        "select outcome from control.read_interrupted_immutable_release_route_snapshot_batch(
          $1,$2,$3,$4,$5,1,null,1)",
    )
    .bind(driver_operation)
    .bind(recovery_attempt)
    .bind(&recovery_worker)
    .bind(recovery_owner)
    .bind(Uuid::new_v4())
    .fetch_one(&mut *snapshot_probe)
    .await
    .unwrap();
    assert_eq!(lost_snapshot_claim, "claim_lost");
    sqlx::query("set local session_replication_role=replica")
        .execute(&mut *snapshot_probe)
        .await
        .unwrap();
    sqlx::query(
        "update control.fleet_release_route_publication_recovery_claims
         set claim_mode='restore_prior' where driver_operation_id=$1 and claim_fence=1",
    )
    .bind(driver_operation)
    .execute(&mut *snapshot_probe)
    .await
    .unwrap();
    sqlx::query("set local session_replication_role=origin")
        .execute(&mut *snapshot_probe)
        .await
        .unwrap();
    let wrong_snapshot_phase: String = sqlx::query_scalar(
        "select outcome from control.read_interrupted_immutable_release_route_snapshot_batch(
          $1,$2,$3,$4,$5,1,null,1)",
    )
    .bind(driver_operation)
    .bind(recovery_attempt)
    .bind(&recovery_worker)
    .bind(recovery_owner)
    .bind(recovery_token)
    .fetch_one(&mut *snapshot_probe)
    .await
    .unwrap();
    assert_eq!(wrong_snapshot_phase, "wrong_phase");
    snapshot_probe.rollback().await.unwrap();
    let frozen_heads: i64 = sqlx::query_scalar(
        "select count(*) from control.fleet_release_route_publication_recovery_route_heads
          where driver_operation_id=$1 and claim_fence=1",
    )
    .bind(driver_operation)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(frozen_heads, 1);
    let replay_claim: String = sqlx::query_scalar(
        "select outcome from control.claim_interrupted_immutable_release_route_publication(
          $1,$2,$3,$4,$5,300)",
    )
    .bind(driver_operation)
    .bind(recovery_attempt)
    .bind(&recovery_worker)
    .bind(recovery_owner)
    .bind(recovery_token)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(replay_claim, "replay");
    sqlx::query(
        "update control.fleet_release_route_publication_recovery_claims
          set claim_expires_at=now()-interval '1 second'
          where driver_operation_id=$1 and claim_fence=1",
    )
    .bind(driver_operation)
    .execute(store.pool())
    .await
    .unwrap();
    let takeover_owner = Uuid::new_v4();
    let takeover_token = Uuid::new_v4();
    let takeover: (String, Option<i64>, Option<String>) = sqlx::query_as(
        "select outcome,claim_fence,claim_mode
         from control.claim_interrupted_immutable_release_route_publication(
          $1,$2,$3,$4,$5,300)",
    )
    .bind(driver_operation)
    .bind(recovery_attempt)
    .bind(&recovery_worker)
    .bind(takeover_owner)
    .bind(takeover_token)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(
        takeover,
        ("acquired".into(), Some(2), Some("forward_only".into()))
    );
    let runtime_observation = json!({
        "protocol_version": 1,
        "odoo_manifest_digest": format!("sha256:{}", "8".repeat(64)),
        "odoo_config_digest": format!("sha256:{}", "9".repeat(64)),
        "extension_manifest_digest": format!("sha256:{}", "a".repeat(64)),
        "extension_config_digest": format!("sha256:{}", "b".repeat(64)),
        "payload_digest": format!("sha256:{}", "c".repeat(64)),
        "extension_volume": "mb-control-ext-aaaaaaaaaaaaaaaa-cccccccccccccccc",
        "runtime_container": "mb-control-odoo-blue",
        "runtime_config_digest": format!("sha256:{}", "e".repeat(64)),
        "external_executor_quiescent": true,
        "candidate_runtime_verified": true,
        "gateway_identity_verified": true,
        "target_database_access_verified": true,
        "old_runtime_retired": true,
        "tenant_recovery_verified": true,
        "candidate_smoke_verified": true,
        "candidate_restart_policy": "unless-stopped",
        "retained_restart_policy": "no",
        "observed_gateway_configuration_digest": gateway_digest,
        "observed_target_slot": "blue"
    });
    let runtime_receipt: (String, Option<String>, Option<Value>) = sqlx::query_as(
        "select outcome,observation_digest,completion_response
         from control.record_interrupted_immutable_release_runtime_observation(
          $1,$2,$3,$4,$5,2,$6)",
    )
    .bind(driver_operation)
    .bind(recovery_attempt)
    .bind(&recovery_worker)
    .bind(takeover_owner)
    .bind(takeover_token)
    .bind(&runtime_observation)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(runtime_receipt.0, "recorded");
    assert_eq!(runtime_receipt.2, Some(exact_response.clone()));
    let observation_digest = runtime_receipt.1.unwrap();
    let replayed_runtime_receipt: (String, Option<String>, Option<Value>) = sqlx::query_as(
        "select outcome,observation_digest,completion_response
         from control.record_interrupted_immutable_release_runtime_observation(
          $1,$2,$3,$4,$5,2,$6)",
    )
    .bind(driver_operation)
    .bind(recovery_attempt)
    .bind(&recovery_worker)
    .bind(takeover_owner)
    .bind(takeover_token)
    .bind(&runtime_observation)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(
        replayed_runtime_receipt,
        (
            "replay".into(),
            Some(observation_digest.clone()),
            Some(exact_response.clone())
        )
    );
    let mut conflicting_runtime_observation = runtime_observation.clone();
    conflicting_runtime_observation["runtime_config_digest"] =
        Value::String(format!("sha256:{}", "f".repeat(64)));
    let conflicting_runtime_receipt: String = sqlx::query_scalar(
        "select outcome
         from control.record_interrupted_immutable_release_runtime_observation(
          $1,$2,$3,$4,$5,2,$6)",
    )
    .bind(driver_operation)
    .bind(recovery_attempt)
    .bind(&recovery_worker)
    .bind(takeover_owner)
    .bind(takeover_token)
    .bind(&conflicting_runtime_observation)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(conflicting_runtime_receipt, "conflict");
    let lost_runtime_receipt: String = sqlx::query_scalar(
        "select outcome
         from control.record_interrupted_immutable_release_runtime_observation(
          $1,$2,$3,$4,$5,2,$6)",
    )
    .bind(driver_operation)
    .bind(recovery_attempt)
    .bind(&recovery_worker)
    .bind(takeover_owner)
    .bind(Uuid::new_v4())
    .bind(&runtime_observation)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(lost_runtime_receipt, "claim_lost");
    let caller_response_rejected: String = sqlx::query_scalar(
        "select control.authorize_interrupted_immutable_release_route_exchange(
          $1,$2,$3,$4,$5,2,'publish_candidate','candidate',$6)",
    )
    .bind(driver_operation)
    .bind(recovery_attempt)
    .bind(&recovery_worker)
    .bind(takeover_owner)
    .bind(takeover_token)
    .bind(&exact_response)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(caller_response_rejected, "runtime_observation_required");
    let candidate_authorized: String = sqlx::query_scalar(
        "select control.authorize_interrupted_immutable_release_route_candidate_from_observation(
          $1,$2,$3,$4,$5,2,$6)",
    )
    .bind(driver_operation)
    .bind(recovery_attempt)
    .bind(&recovery_worker)
    .bind(takeover_owner)
    .bind(takeover_token)
    .bind(&observation_digest)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(candidate_authorized, "authorized");
    let malformed_artifacts = json!({
        "protocol_version": 1,
        "driver_operation_id": driver_operation,
        "fleet_run_id": fleet_run,
        "claim_fence": 2,
        "resolution_kind": "candidate",
        "observed_selector": publication.3,
        "observed_directory_device": 31,
        "observed_directory_inode": 32,
        "observed_loaded_identity": {
            "protocol_version": 1,
            "fleet_run_id": fleet_run,
            "driver_operation_id": driver_operation,
            "original_global_fence_token": global_fence,
            "overlay_kind": "candidate",
            "route_set_digest": candidate_digest,
            "target_slot": "blue"
        },
        "maintenance_artifact": null,
        "candidate_artifact": null
    });
    let artifact_mismatch: String = sqlx::query_scalar(
        "select control.resolve_interrupted_immutable_release_route_publication(
          $1,$2,$3,$4,$5,2,'candidate',$6,null)",
    )
    .bind(driver_operation)
    .bind(recovery_attempt)
    .bind(&recovery_worker)
    .bind(takeover_owner)
    .bind(takeover_token)
    .bind(malformed_artifacts)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(artifact_mismatch, "observation_mismatch");
    let maintenance_identity = json!({
        "protocol_version": 1,
        "fleet_run_id": fleet_run,
        "driver_operation_id": driver_operation,
        "original_global_fence_token": global_fence,
        "overlay_kind": "maintenance",
        "route_set_digest": maintenance_digest,
        "target_slot": "blue"
    });
    let candidate_identity = json!({
        "protocol_version": 1,
        "fleet_run_id": fleet_run,
        "driver_operation_id": driver_operation,
        "original_global_fence_token": global_fence,
        "overlay_kind": "candidate",
        "route_set_digest": candidate_digest,
        "target_slot": "blue"
    });
    let exact_observation = json!({
        "protocol_version": 1,
        "driver_operation_id": driver_operation,
        "fleet_run_id": fleet_run,
        "claim_fence": 2,
        "resolution_kind": "candidate",
        "observed_selector": publication.3,
        "observed_directory_device": 31,
        "observed_directory_inode": 32,
        "observed_loaded_identity": candidate_identity,
        "maintenance_artifact": {
            "selector": publication.2,
            "directory_device": 21,
            "directory_inode": 22,
            "loaded_identity": maintenance_identity,
            "publication_started": true
        },
        "candidate_artifact": {
            "selector": publication.3,
            "directory_device": 31,
            "directory_inode": 32,
            "loaded_identity": candidate_identity,
            "publication_started": true
        }
    });
    let resolved: String = sqlx::query_scalar(
        "select control.resolve_interrupted_immutable_release_route_publication(
          $1,$2,$3,$4,$5,2,'candidate',$6,null)",
    )
    .bind(driver_operation)
    .bind(recovery_attempt)
    .bind(&recovery_worker)
    .bind(takeover_owner)
    .bind(takeover_token)
    .bind(&exact_observation)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(resolved, "recorded");
    let unreviewed_finish: (String, Option<Value>) = sqlx::query_as(
        "select outcome,stored_response
         from control.finish_reviewed_interrupted_immutable_release_route_publication(
          $1,$2,$3,$4,$5,2)",
    )
    .bind(driver_operation)
    .bind(recovery_attempt)
    .bind(&recovery_worker)
    .bind(takeover_owner)
    .bind(takeover_token)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(unreviewed_finish, ("review_required".into(), None));
    let caller_digest_finish: (String, Option<Value>) = sqlx::query_as(
        "select outcome,stored_response
         from control.finish_interrupted_immutable_release_route_publication(
          $1,$2,$3,$4,$5,2,'candidate',$6)",
    )
    .bind(driver_operation)
    .bind(recovery_attempt)
    .bind(&recovery_worker)
    .bind(takeover_owner)
    .bind(takeover_token)
    .bind(format!("sha256:{}", "f".repeat(64)))
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(
        caller_digest_finish,
        ("reviewed_finish_required".into(), None)
    );
    let review: (String, Option<String>) = sqlx::query_as(
        "select outcome,review_digest
         from control.review_interrupted_immutable_release_runtime_observation(
          $1,2,$2,$3,$4,$5,'accept_candidate')",
    )
    .bind(driver_operation)
    .bind(release.control_operation_id)
    .bind(recovery_attempt)
    .bind(&recovery_worker)
    .bind(&observation_digest)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(review.0, "approved");
    assert!(
        review
            .1
            .as_deref()
            .is_some_and(|digest| digest.starts_with("sha256:"))
    );
    let review_replay: (String, Option<String>) = sqlx::query_as(
        "select outcome,review_digest
         from control.review_interrupted_immutable_release_runtime_observation(
          $1,2,$2,$3,$4,$5,'accept_candidate')",
    )
    .bind(driver_operation)
    .bind(release.control_operation_id)
    .bind(recovery_attempt)
    .bind(&recovery_worker)
    .bind(&observation_digest)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(review_replay, ("replay".into(), review.1));

    // Deterministically put the normal 0036 completion wrapper in the narrow
    // race where its unlocked receipt precheck saw no row, recovery has reached
    // the receipt insert while holding the legacy lock set, and the wrapper is
    // waiting in the legacy fallback. The wrapper's post-fallback receipt read
    // must therefore override wrong_phase/authority_lost without disclosing a
    // stored success response to a conflicting caller.
    const RECOVERY_BARRIER_CLASS: i32 = 2_037_003;
    const RECOVERY_BARRIER_OBJECT: i32 = 37;
    sqlx::query(
        "create or replace function control.test_block_release_recovery_receipt()
         returns trigger language plpgsql as $function$
         begin
          if current_setting('mb_control.test_release_recovery_barrier',true)='on' then
           perform pg_advisory_xact_lock(2037003,37);
          end if;
          return new;
         end $function$",
    )
    .execute(store.pool())
    .await
    .unwrap();
    sqlx::query(
        "drop trigger if exists test_block_release_recovery_receipt
         on control.fleet_release_route_publication_completions",
    )
    .execute(store.pool())
    .await
    .unwrap();
    sqlx::query(
        "create trigger test_block_release_recovery_receipt before insert
         on control.fleet_release_route_publication_completions for each row
         execute function control.test_block_release_recovery_receipt()",
    )
    .execute(store.pool())
    .await
    .unwrap();

    let mut barrier = store.pool().acquire().await.unwrap();
    sqlx::query("select pg_advisory_lock($1,$2)")
        .bind(RECOVERY_BARRIER_CLASS)
        .bind(RECOVERY_BARRIER_OBJECT)
        .execute(&mut *barrier)
        .await
        .unwrap();
    let recovery_application = format!("release-recovery-race-{}", Uuid::new_v4().simple());
    let recovery_pool = store.pool().clone();
    let recovery_worker_task = recovery_worker.clone();
    let recovered_task = tokio::spawn(async move {
        let mut transaction = recovery_pool.begin().await.unwrap();
        sqlx::query("select set_config('application_name',$1,true)")
            .bind(&recovery_application)
            .execute(&mut *transaction)
            .await
            .unwrap();
        sqlx::query("select set_config('lock_timeout','10s',true)")
            .execute(&mut *transaction)
            .await
            .unwrap();
        sqlx::query("select set_config('mb_control.test_release_recovery_barrier','on',true)")
            .execute(&mut *transaction)
            .await
            .unwrap();
        let result: (String, Option<Value>) = sqlx::query_as(
            "select outcome,stored_response
             from control.finish_reviewed_interrupted_immutable_release_route_publication(
              $1,$2,$3,$4,$5,2)",
        )
        .bind(driver_operation)
        .bind(recovery_attempt)
        .bind(&recovery_worker_task)
        .bind(takeover_owner)
        .bind(takeover_token)
        .fetch_one(&mut *transaction)
        .await
        .unwrap();
        transaction.commit().await.unwrap();
        result
    });

    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let waiting: bool = sqlx::query_scalar(
                "select exists(select 1 from pg_stat_activity
                 where application_name like 'release-recovery-race-%'
                  and wait_event_type='Lock' and lower(wait_event)='advisory')",
            )
            .fetch_one(&mut *barrier)
            .await
            .unwrap();
            if waiting {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("recovery must reach the advisory receipt barrier");

    let mut racing_conflict_response = exact_response.clone();
    racing_conflict_response["evidence"]["runtime_config_digest"] =
        Value::String(format!("sha256:{}", "f".repeat(64)));
    let normal_application = format!("release-normal-race-{}", Uuid::new_v4().simple());
    let normal_pool = store.pool().clone();
    let normal_response = racing_conflict_response.clone();
    let normal_worker = tokio::spawn(async move {
        let mut connection = normal_pool.acquire().await.unwrap();
        sqlx::query("select set_config('application_name',$1,false)")
            .bind(&normal_application)
            .execute(&mut *connection)
            .await
            .unwrap();
        sqlx::query("set lock_timeout='10s'")
            .execute(&mut *connection)
            .await
            .unwrap();
        sqlx::query_as::<_, (String, Option<Value>)>(
            "select outcome,stored_response
             from control.finish_immutable_release_route_publication($1,$2,$3,$4,$5,$6,$7)",
        )
        .bind(driver_operation)
        .bind(release.instance_owner)
        .bind(release.execution_token)
        .bind(release.resource_lease_token)
        .bind(route_lease_token)
        .bind(global_fence)
        .bind(&normal_response)
        .fetch_one(&mut *connection)
        .await
        .unwrap()
    });
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let waiting: bool = sqlx::query_scalar(
                "select exists(select 1 from pg_stat_activity
                 where application_name like 'release-normal-race-%'
                  and wait_event_type='Lock')",
            )
            .fetch_one(&mut *barrier)
            .await
            .unwrap();
            if waiting {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("normal wrapper must enter the locked legacy fallback");
    sqlx::query("select pg_advisory_unlock($1,$2)")
        .bind(RECOVERY_BARRIER_CLASS)
        .bind(RECOVERY_BARRIER_OBJECT)
        .execute(&mut *barrier)
        .await
        .unwrap();

    let recovered = recovered_task.await.unwrap();
    assert_eq!(
        recovered,
        ("applied_recovered".into(), Some(exact_response.clone()))
    );
    let raced_normal = normal_worker.await.unwrap();
    assert_eq!(raced_normal, ("conflict".into(), None));
    let authoritative_replay: (String, Option<Value>) = sqlx::query_as(
        "select outcome,stored_response
         from control.finish_immutable_release_route_publication($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(driver_operation)
    .bind(release.instance_owner)
    .bind(release.execution_token)
    .bind(release.resource_lease_token)
    .bind(route_lease_token)
    .bind(global_fence)
    .bind(&exact_response)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(
        authoritative_replay,
        ("replay".into(), Some(exact_response.clone()))
    );
    sqlx::query(
        "drop trigger test_block_release_recovery_receipt
         on control.fleet_release_route_publication_completions",
    )
    .execute(store.pool())
    .await
    .unwrap();
    sqlx::query("drop function control.test_block_release_recovery_receipt()")
        .execute(store.pool())
        .await
        .unwrap();
    sqlx::query(
        "update control.fleet_release_route_publication_recovery_claims
          set claim_expires_at=now()-interval '1 second'
          where driver_operation_id=$1 and claim_fence=2",
    )
    .bind(driver_operation)
    .execute(store.pool())
    .await
    .unwrap();
    let terminal_replay: (String, Option<Value>) = sqlx::query_as(
        "select outcome,stored_response
         from control.finish_reviewed_interrupted_immutable_release_route_publication(
          $1,$2,$3,$4,$5,2)",
    )
    .bind(driver_operation)
    .bind(recovery_attempt)
    .bind(&recovery_worker)
    .bind(takeover_owner)
    .bind(takeover_token)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(
        terminal_replay,
        ("replay".into(), Some(exact_response.clone()))
    );
    let stale_terminal: (String, Option<Value>) = sqlx::query_as(
        "select outcome,stored_response
         from control.finish_reviewed_interrupted_immutable_release_route_publication(
          $1,$2,$3,$4,$5,2)",
    )
    .bind(driver_operation)
    .bind(recovery_attempt)
    .bind(&recovery_worker)
    .bind(takeover_owner)
    .bind(Uuid::new_v4())
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(stale_terminal, ("claim_lost".into(), None));

    let vector: (String,String) = sqlx::query_as(
        "with r as (select control.release_route_overlay_record_bytes(
         '00112233-4455-6677-8899-aabbccddeeff',72623859790382856,
         'sha256:'||repeat('a',64),'sha256:'||repeat('b',64),'sha256:'||repeat('c',64)) b)
         select encode(b,'hex'),'sha256:'||encode(public.digest(
          convert_to('mb-release-route-overlay-v1','UTF8')||decode('00','hex')||b,'sha256'),'hex') from r")
        .fetch_one(store.pool()).await.unwrap();
    assert!(
        vector
            .0
            .starts_with("00112233445566778899aabbccddeeff0102030405060708")
    );
    assert_eq!(
        vector.1,
        "sha256:59c2a7266d764878e81696d3fb4ebfe3c030344280b81795e91e0b293b403a7a"
    );
}

#[tokio::test]
#[ignore = "requires a disposable CONTROL_TEST_DATABASE_URL"]
async fn fleet_release_reserves_its_snapshot_and_excludes_route_applications() {
    let store = store().await;
    sqlx::query(
        "update control.deployment_driver_resource_leases
            set state='idle',driver_operation_id=null,lease_owner=null,lease_token=null,
                lease_expires_at=null,heartbeat_at=null,quarantined_at=null,safe_error=null,
                updated_at=now()
          where resource_key='runtime/shared-odoo'",
    )
    .execute(store.pool())
    .await
    .unwrap();

    let first_workshop = Uuid::new_v4();
    let second_workshop = Uuid::new_v4();
    let outside_snapshot = Uuid::new_v4();
    for workshop in [first_workshop, second_workshop, outside_snapshot] {
        sqlx::query(
            "insert into control.workshops(id,slug,display_name,time_zone)
             values($1,$2,'Fleet route reservation fixture','Europe/Paris')",
        )
        .bind(workshop)
        .bind(format!("fleet-route-{}", workshop.simple()))
        .execute(store.pool())
        .await
        .unwrap();
    }

    let mut release = insert_leased_release_operation(store.pool(), "release-route-fence").await;
    let reserved = attach_release_fleet_run(
        store.pool(),
        &mut release,
        &[second_workshop, first_workshop],
    )
    .await;
    assert!(!reserved.contains(&outside_snapshot));

    sqlx::query(
        "update control.workshop_route_application_leases
            set state='uninitialized',initialization_required=true,updated_at=now()
          where workshop_id=$1 and state='idle'",
    )
    .bind(first_workshop)
    .execute(store.pool())
    .await
    .unwrap();
    let uninitialized = admit_release_driver_lease(store.pool(), &release).await;
    assert_eq!(uninitialized.0, "route_uninitialized");
    assert_eq!(uninitialized.1, None);
    assert_eq!(uninitialized.4.as_ref(), Some(&reserved));
    sqlx::query(
        "update control.workshop_route_application_leases
            set state='idle',initialization_required=false,updated_at=now()
          where workshop_id=$1 and state='uninitialized'",
    )
    .bind(first_workshop)
    .execute(store.pool())
    .await
    .unwrap();

    let first_control =
        insert_route_control_operation(store.pool(), first_workshop, "route-after-release").await;
    let second_control =
        insert_route_control_operation(store.pool(), second_workshop, "route-before-release").await;
    let first_projection = json!({
        "database_id": Uuid::new_v4(),
        "database_ref": format!("mb_{}", first_workshop.simple()),
        "public_hostname": format!("{}.fleet-route.example.test", first_workshop.simple()),
        "paperless_mode": "absent",
        "paperless_hostname": null,
        "custom_hostnames": []
    });
    let second_projection = json!({
        "database_id": Uuid::new_v4(),
        "database_ref": format!("mb_{}", second_workshop.simple()),
        "public_hostname": format!("{}.fleet-route.example.test", second_workshop.simple()),
        "paperless_mode": "absent",
        "paperless_hostname": null,
        "custom_hostnames": []
    });
    let first_digest = format!("sha256:{}", "5".repeat(64));
    let second_digest = format!("sha256:{}", "6".repeat(64));
    assert_eq!(
        materialize_route_projection(
            store.pool(),
            &first_control,
            &first_projection,
            &first_digest,
        )
        .await
        .0,
        "created"
    );
    assert_eq!(
        materialize_route_projection(
            store.pool(),
            &second_control,
            &second_projection,
            &second_digest,
        )
        .await
        .0,
        "created"
    );
    let route = RouteApplicationCall {
        control: second_control,
        idempotency_key: format!("route-before-fleet:{second_workshop}"),
        request_digest: "7".repeat(64),
        generation: 1,
        projection_digest: second_digest,
        instance_owner: Uuid::new_v4(),
        execution_token: Uuid::new_v4(),
        resource_lease_token: Uuid::new_v4(),
    };
    let route_admission = admit_route_application(store.pool(), &route).await;
    assert_eq!(route_admission.0, "acquired");
    let route_driver_operation = route_admission.1.unwrap();
    let route_fence = route_admission.2.unwrap();

    let route_busy = admit_release_driver_lease(store.pool(), &release).await;
    assert_eq!(route_busy.0, "route_busy");
    assert_eq!(route_busy.1, Some(route_driver_operation));
    assert_eq!(route_busy.4.as_ref(), Some(&reserved));
    assert_eq!(
        sqlx::query(
            "update control.workshop_route_application_leases
                set lease_expires_at=now()-interval '1 second',updated_at=now()
              where workshop_id=$1 and state='held' and driver_operation_id=$2
                and fence_token=$3",
        )
        .bind(second_workshop)
        .bind(route_driver_operation)
        .bind(route_fence)
        .execute(store.pool())
        .await
        .unwrap()
        .rows_affected(),
        1
    );
    let expired = admit_release_driver_lease(store.pool(), &release).await;
    assert_eq!(expired.0, "route_quarantined");
    assert_eq!(expired.1, Some(route_driver_operation));
    assert_eq!(expired.4.as_ref(), Some(&reserved));
    let quarantined: (String, Option<String>) = sqlx::query_as(
        "select state,safe_error from control.workshop_route_application_leases
          where workshop_id=$1",
    )
    .bind(second_workshop)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(quarantined.0, "quarantined");
    assert_eq!(quarantined.1.as_deref(), Some("runtime_outcome_unknown"));
    sqlx::query(
        "update control.workshop_route_application_leases
            set state='idle',initialization_required=false,driver_operation_id=null,
                generation=null,projection_digest=null,lease_owner=null,lease_token=null,
                lease_expires_at=null,heartbeat_at=null,quarantined_at=null,safe_error=null,
                updated_at=now()
          where workshop_id=$1 and state='quarantined'",
    )
    .bind(second_workshop)
    .execute(store.pool())
    .await
    .unwrap();

    let acquired = admit_release_driver_lease(store.pool(), &release).await;
    assert_eq!(acquired.0, "acquired");
    assert!(acquired.1.is_some());
    assert!(acquired.2.is_some());
    assert_eq!(acquired.4.as_ref(), Some(&reserved));

    let blocked_route = RouteApplicationCall {
        control: first_control,
        idempotency_key: format!("route-after-fleet:{first_workshop}"),
        request_digest: "8".repeat(64),
        generation: 1,
        projection_digest: first_digest,
        instance_owner: Uuid::new_v4(),
        execution_token: Uuid::new_v4(),
        resource_lease_token: Uuid::new_v4(),
    };
    let fleet_busy = admit_route_application(store.pool(), &blocked_route).await;
    assert_eq!(fleet_busy.0, "fleet_busy");
    assert_eq!(fleet_busy.1, acquired.1);
    assert_eq!(fleet_busy.2, acquired.2);

    let release_receipts: i64 = sqlx::query_scalar(
        "select count(*) from control.deployment_driver_operations
          where control_operation_id=$1 and action='release'",
    )
    .bind(release.control_operation_id)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(
        release_receipts, 1,
        "refusals must not strand release receipts"
    );

    // This integration target intentionally reuses one database across tests.
    // Leave neither singleton release authority nor an unfinished fleet run
    // behind for the following replica/quarantine state-machine tests.
    sqlx::query(
        "update control.deployment_driver_resource_leases
            set state='idle',driver_operation_id=null,lease_owner=null,lease_token=null,
                lease_expires_at=null,heartbeat_at=null,quarantined_at=null,safe_error=null,
                updated_at=now()
          where resource_key='runtime/shared-odoo'",
    )
    .execute(store.pool())
    .await
    .unwrap();
    assert_eq!(
        sqlx::query(
            "update control.release_fleet_runs
                set state='failed',failure_class='test_fixture_complete',updated_at=now()
              where operation_id=$1 and state not in ('active','failed')",
        )
        .bind(release.control_operation_id)
        .execute(store.pool())
        .await
        .unwrap()
        .rows_affected(),
        1
    );
}

#[tokio::test]
#[ignore = "requires a disposable CONTROL_TEST_DATABASE_URL"]
async fn release_driver_lease_serializes_replicas_replays_and_quarantines_expiry() {
    // Initial-release admission deliberately requires an empty fleet. Run this
    // state-machine test in its own database so unrelated workshop fixtures in
    // the shared integration database cannot weaken that precondition.
    let shared_url = std::env::var("CONTROL_TEST_DATABASE_URL").unwrap();
    let database = format!("control_release_lease_{}", Uuid::new_v4().simple());
    let mut admin_url = url::Url::parse(&shared_url).unwrap();
    admin_url.set_path("postgres");
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(admin_url.as_str())
        .await
        .unwrap();
    sqlx::query(AssertSqlSafe(format!("create database \"{database}\"")))
        .execute(&admin)
        .await
        .unwrap();
    let mut test_url = url::Url::parse(&shared_url).unwrap();
    test_url.set_path(&database);
    let database_url = test_url.to_string();
    let store = Store::connect(&database_url).await.unwrap();
    store.migrate().await.unwrap();
    let first_pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&database_url)
        .await
        .unwrap();
    let second_pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&database_url)
        .await
        .unwrap();

    let first = insert_leased_release_operation(store.pool(), "release-worker-a").await;
    let second = insert_leased_release_operation(store.pool(), "release-worker-b").await;
    let (first_admission, second_admission) =
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            tokio::join!(
                admit_release_driver_lease(&first_pool, &first),
                admit_release_driver_lease(&second_pool, &second),
            )
        })
        .await
        .expect("concurrent release lease admission must not deadlock");
    let (winner, winner_admission, loser, loser_admission) =
        match (first_admission.0.as_str(), second_admission.0.as_str()) {
            ("acquired", "busy") => (&first, first_admission, &second, second_admission),
            ("busy", "acquired") => (&second, second_admission, &first, first_admission),
            outcomes => panic!("expected one acquired and one busy admission, got {outcomes:?}"),
        };
    let winner_operation = winner_admission
        .1
        .expect("acquisition must identify the driver operation");
    let first_fence = winner_admission
        .2
        .expect("acquisition must return a fence token");
    assert_eq!(winner_admission.4, Some(Vec::<Uuid>::new()));
    assert_eq!(loser_admission.4, Some(Vec::<Uuid>::new()));
    assert_eq!(loser_admission.1, Some(winner_operation));
    assert_eq!(loser_admission.2, Some(first_fence));

    let held = sqlx::query_as::<_, (String, i64, Option<Uuid>, Option<Uuid>, Option<Uuid>)>(
        "select state,fence_token,driver_operation_id,lease_owner,lease_token
         from control.deployment_driver_resource_leases
         where resource_key='runtime/shared-odoo'",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(held.0, "held");
    assert_eq!(held.1, first_fence);
    assert_eq!(held.2, Some(winner_operation));
    assert_eq!(held.3, Some(winner.instance_owner));
    assert_eq!(held.4, Some(winner.resource_lease_token));

    let response = json!({"evidence":{"release_id":"lease-test","observed":true}});
    assert!(
        finish_release_driver_lease(
            store.pool(),
            winner,
            winner_operation,
            first_fence,
            &response,
        )
        .await
    );
    let rebound_owner = format!("release-worker-retry-{}", Uuid::new_v4());
    assert_eq!(
        sqlx::query(
            "update control.operations
             set attempt=2,leased_by=$2,lease_expires_at=now()+interval '20 minutes'
             where id=$1 and state='in_flight' and attempt=1",
        )
        .bind(winner.control_operation_id)
        .bind(&rebound_owner)
        .execute(store.pool())
        .await
        .unwrap()
        .rows_affected(),
        1
    );
    let mut rebound = winner.clone();
    rebound.control_operation_attempt = 2;
    rebound.control_operation_owner = rebound_owner.clone();
    rebound.instance_owner = Uuid::new_v4();
    rebound.execution_token = Uuid::new_v4();
    rebound.resource_lease_token = Uuid::new_v4();
    let replay = admit_release_driver_lease(store.pool(), &rebound).await;
    assert_eq!(replay.0, "replay");
    assert_eq!(replay.1, Some(winner_operation));
    assert_eq!(replay.2, Some(first_fence));
    assert_eq!(replay.3, Some(response));
    assert_eq!(replay.4, Some(Vec::<Uuid>::new()));
    let rebound_binding = sqlx::query_as::<_, (Option<Uuid>, Option<i32>, Option<String>)>(
        "select control_operation_id,control_operation_attempt,control_operation_lease_owner
         from control.deployment_driver_operations where id=$1",
    )
    .bind(winner_operation)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(rebound_binding.0, Some(winner.control_operation_id));
    assert_eq!(rebound_binding.1, Some(2));
    assert_eq!(rebound_binding.2.as_deref(), Some(rebound_owner.as_str()));

    let second_acquisition = admit_release_driver_lease(store.pool(), loser).await;
    assert_eq!(second_acquisition.0, "acquired");
    let second_operation = second_acquisition.1.unwrap();
    let second_fence = second_acquisition.2.unwrap();
    assert!(
        second_fence > first_fence,
        "resource fencing tokens must increase across owners"
    );
    let expiry_before: time::OffsetDateTime = sqlx::query_scalar(
        "select lease_expires_at from control.deployment_driver_resource_leases
         where resource_key='runtime/shared-odoo'",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    let renewed: bool = sqlx::query_scalar(
        "select control.renew_release_driver_lease($1,$2,$3,$4,$5,$6,$7,$8,600)",
    )
    .bind(second_operation)
    .bind(loser.control_operation_id)
    .bind(loser.control_operation_attempt)
    .bind(&loser.control_operation_owner)
    .bind(loser.instance_owner)
    .bind(loser.execution_token)
    .bind(loser.resource_lease_token)
    .bind(second_fence)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert!(renewed);
    let expiry_after: time::OffsetDateTime = sqlx::query_scalar(
        "select lease_expires_at from control.deployment_driver_resource_leases
         where resource_key='runtime/shared-odoo'",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert!(expiry_after > expiry_before);

    assert_eq!(
        sqlx::query(
            "update control.deployment_driver_resource_leases
             set lease_expires_at=now()-interval '1 second',updated_at=now()
             where resource_key='runtime/shared-odoo' and state='held'
               and driver_operation_id=$1 and lease_owner=$2 and lease_token=$3
               and fence_token=$4",
        )
        .bind(second_operation)
        .bind(loser.instance_owner)
        .bind(loser.resource_lease_token)
        .bind(second_fence)
        .execute(store.pool())
        .await
        .unwrap()
        .rows_affected(),
        1
    );
    assert!(
        !finish_release_driver_lease(
            &second_pool,
            loser,
            second_operation,
            second_fence,
            &json!({"expired_owner_must_not_publish":true}),
        )
        .await,
        "lease expiry must fence success before another admission performs quarantine"
    );
    let third = insert_leased_release_operation(store.pool(), "release-worker-c").await;
    let quarantine = admit_release_driver_lease(&first_pool, &third).await;
    assert_eq!(quarantine.0, "quarantined");
    assert_eq!(quarantine.1, Some(second_operation));
    assert_eq!(quarantine.2, Some(second_fence));
    assert!(
        !sqlx::query_scalar::<_, bool>(
            "select control.finish_release_driver_operation($1,$2,$3,$4,$5,
                    'succeeded',$6,null)",
        )
        .bind(second_operation)
        .bind(loser.instance_owner)
        .bind(loser.execution_token)
        .bind(loser.resource_lease_token)
        .bind(second_fence)
        .bind(json!({"stale":true}))
        .fetch_one(&second_pool)
        .await
        .unwrap(),
        "an expired owner must not finalize after quarantine"
    );

    let quarantined = sqlx::query_as::<
        _,
        (
            String,
            i64,
            Option<Uuid>,
            Option<Uuid>,
            bool,
            bool,
            bool,
            Option<String>,
        ),
    >(
        "select state,fence_token,driver_operation_id,lease_owner,
                lease_token is null,lease_expires_at is null,quarantined_at is not null,safe_error
         from control.deployment_driver_resource_leases
         where resource_key='runtime/shared-odoo'",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(quarantined.0, "quarantined");
    assert_eq!(quarantined.1, second_fence);
    assert_eq!(quarantined.2, Some(second_operation));
    assert_eq!(quarantined.3, Some(loser.instance_owner));
    assert!(quarantined.4 && quarantined.5 && quarantined.6);
    assert_eq!(quarantined.7.as_deref(), Some("runtime_outcome_unknown"));
    let operation = sqlx::query_as::<_, (String, Option<String>, bool, bool)>(
        "select state,safe_error,execution_token is null,lease_expires_at is null
         from control.deployment_driver_operations where id=$1",
    )
    .bind(second_operation)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(operation.0, "in_progress");
    assert_eq!(operation.1.as_deref(), Some("runtime_outcome_unknown"));
    assert!(operation.2 && operation.3);
    let third_rows: i64 = sqlx::query_scalar(
        "select count(*) from control.deployment_driver_operations
         where action='release' and idempotency_key=$1",
    )
    .bind(&third.idempotency_key)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(third_rows, 0, "quarantine must not admit new release work");

    // An empty-fleet initial preparation may be cleared only by a fresh,
    // read-only observation of the exact prepared slot. Fleet activation is
    // intentionally excluded from this reconciliation protocol.
    let release_id = loser.target_key.strip_prefix("initial/").unwrap();
    let digest = format!("sha256:{}", "d".repeat(64));
    sqlx::query(
        "insert into control.application_releases(
           id,source_commit,odoo_version,odoo_subject_digest,extension_subject_digest,
           odoo_runtime,extension_bundle,pair_qualifications,manifest_digest,addon_versions,
           compatibility,bridge_contract,schema_epoch,change_class,required_postconditions,
           manifest,signature_bundle_ref,extension_signature_ref,sbom_ref,published_at,
           publication_idempotency_key,publication_request_digest
         ) values($1,$2,'19.0',$3,$3,'{}','{}','[{}]',$3,'{}','{}',
                  '>=3.2.0,<4.0.0',42,'B','[]','{}','oci://signature',
                  'oci://extension-signature','oci://sbom',now(),$4,$5)",
    )
    .bind(release_id)
    .bind("d".repeat(64))
    .bind(&digest)
    .bind(format!("initial-reconciliation:{release_id}"))
    .bind(vec![9_u8; 32])
    .execute(store.pool())
    .await
    .unwrap();
    let prepared_evidence = json!({
        "release_id": release_id,
        "driver_operation_id": second_operation,
        "driver_fence_token": second_fence
    });
    sqlx::query(
        "insert into control.runtime_release_slots(
           runtime_key,slot,release_id,state,odoo_subject_digest,odoo_manifest_digest,
           odoo_config_digest,extension_subject_digest,extension_manifest_digest,
           extension_config_digest,payload_digest,extension_volume,pair_qualification_digest,
           bridge_contract_digest,installed_addon_versions,started_at,verified_at,evidence
         ) values('shared-odoo','blue',$1,'prepared',$2,$2,$2,$2,$2,$2,$2,
                  'mb-ext-dddddddddddddddd-dddddddddddddddd',$2,$2,'{}',now(),now(),$3)",
    )
    .bind(release_id)
    .bind(&digest)
    .bind(&prepared_evidence)
    .execute(store.pool())
    .await
    .unwrap();
    let reconciliation_owner = Uuid::new_v4();
    let reconciliation_token = Uuid::new_v4();
    let mismatched_request: String = sqlx::query_scalar(
        "select outcome from control.admit_initial_release_reconciliation(
            $1,$2,$3,$4,$5,$6,$7,$8,120)",
    )
    .bind(loser.control_operation_id)
    .bind(loser.control_operation_attempt)
    .bind(&loser.control_operation_owner)
    .bind(&loser.idempotency_key)
    .bind(&loser.target_key)
    .bind("b".repeat(64))
    .bind(reconciliation_owner)
    .bind(reconciliation_token)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(mismatched_request, "not_reconcilable");
    let reconciliation = sqlx::query_as::<
        _,
        (
            String,
            Option<Uuid>,
            Option<Uuid>,
            Option<i64>,
            Option<Value>,
        ),
    >(
        "select outcome,reconciliation_id,driver_operation_id,
                original_fence_token,stored_evidence
         from control.admit_initial_release_reconciliation(
            $1,$2,$3,$4,$5,$6,$7,$8,120)",
    )
    .bind(loser.control_operation_id)
    .bind(loser.control_operation_attempt)
    .bind(&loser.control_operation_owner)
    .bind(&loser.idempotency_key)
    .bind(&loser.target_key)
    .bind(&loser.request_digest)
    .bind(reconciliation_owner)
    .bind(reconciliation_token)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(reconciliation.0, "acquired");
    assert_eq!(reconciliation.2, Some(second_operation));
    assert_eq!(reconciliation.3, Some(second_fence));
    assert_eq!(reconciliation.4, Some(prepared_evidence.clone()));
    let reconciliation_id = reconciliation.1.unwrap();
    let competing = sqlx::query_as::<
        _,
        (
            String,
            Option<Uuid>,
            Option<Uuid>,
            Option<i64>,
            Option<Value>,
        ),
    >(
        "select outcome,reconciliation_id,driver_operation_id,
                original_fence_token,stored_evidence
         from control.admit_initial_release_reconciliation(
            $1,$2,$3,$4,$5,$6,$7,$8,120)",
    )
    .bind(loser.control_operation_id)
    .bind(loser.control_operation_attempt)
    .bind(&loser.control_operation_owner)
    .bind(&loser.idempotency_key)
    .bind(&loser.target_key)
    .bind(&loser.request_digest)
    .bind(Uuid::new_v4())
    .bind(Uuid::new_v4())
    .fetch_one(&second_pool)
    .await
    .unwrap();
    assert_eq!(competing.0, "busy");
    assert!(
        !sqlx::query_scalar::<_, bool>(
            "select control.finish_initial_release_reconciliation($1,$2,$3,'succeeded',$4)",
        )
        .bind(reconciliation_id)
        .bind(reconciliation_owner)
        .bind(reconciliation_token)
        .bind(json!({"evidence":prepared_evidence,"observed":true}))
        .fetch_one(store.pool())
        .await
        .unwrap(),
        "a manufactured or incomplete observation receipt must fail closed"
    );
    let reconciliation_response = json!({
        "evidence": prepared_evidence,
        "observed": true,
        "reconciliation": {
            "id": reconciliation_id,
            "kind": "initial_runtime_inspection",
            "runtime_matches_prepared_slot": true
        }
    });
    assert_eq!(
        sqlx::query(
            "update control.operations set lease_expires_at=now()-interval '1 second'
             where id=$1 and state='in_flight'",
        )
        .bind(loser.control_operation_id)
        .execute(store.pool())
        .await
        .unwrap()
        .rows_affected(),
        1
    );
    assert!(
        !sqlx::query_scalar::<_, bool>(
            "select control.finish_initial_release_reconciliation($1,$2,$3,'succeeded',$4)",
        )
        .bind(reconciliation_id)
        .bind(reconciliation_owner)
        .bind(reconciliation_token)
        .bind(&reconciliation_response)
        .fetch_one(store.pool())
        .await
        .unwrap(),
        "reconciliation must re-authenticate the upstream operation lease"
    );
    sqlx::query(
        "update control.operations set lease_expires_at=now()+interval '20 minutes'
         where id=$1 and state='in_flight'",
    )
    .bind(loser.control_operation_id)
    .execute(store.pool())
    .await
    .unwrap();
    let late_workshop = Uuid::new_v4();
    sqlx::query(
        "insert into control.workshops(id,slug,display_name,time_zone)
         values($1,$2,'Late initial reconciliation fleet member','Europe/Paris')",
    )
    .bind(late_workshop)
    .bind(format!("late-initial-{}", late_workshop.simple()))
    .execute(store.pool())
    .await
    .unwrap();
    assert!(
        !sqlx::query_scalar::<_, bool>(
            "select control.finish_initial_release_reconciliation($1,$2,$3,'succeeded',$4)",
        )
        .bind(reconciliation_id)
        .bind(reconciliation_owner)
        .bind(reconciliation_token)
        .bind(&reconciliation_response)
        .fetch_one(store.pool())
        .await
        .unwrap(),
        "a fleet member admitted after observation claim must retain quarantine"
    );
    let still_quarantined: String = sqlx::query_scalar(
        "select state from control.deployment_driver_resource_leases
         where resource_key='runtime/shared-odoo'",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(still_quarantined, "quarantined");
    sqlx::query("delete from control.workshop_route_application_leases where workshop_id=$1")
        .bind(late_workshop)
        .execute(store.pool())
        .await
        .unwrap();
    sqlx::query("delete from control.workshop_route_projection_state where workshop_id=$1")
        .bind(late_workshop)
        .execute(store.pool())
        .await
        .unwrap();
    sqlx::query("delete from control.workshops where id=$1")
        .bind(late_workshop)
        .execute(store.pool())
        .await
        .unwrap();
    assert!(
        sqlx::query_scalar::<_, bool>(
            "select control.finish_initial_release_reconciliation($1,$2,$3,'succeeded',$4)",
        )
        .bind(reconciliation_id)
        .bind(reconciliation_owner)
        .bind(reconciliation_token)
        .bind(&reconciliation_response)
        .fetch_one(store.pool())
        .await
        .unwrap()
    );
    let reconciled_resource: (String, i64, bool, bool) = sqlx::query_as(
        "select state,fence_token,driver_operation_id is null,authority_kind is null
         from control.deployment_driver_resource_leases
         where resource_key='runtime/shared-odoo'",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(
        reconciled_resource,
        ("idle".into(), second_fence, true, true)
    );
    let reconciled_operation: (String, Option<String>, Option<Value>) = sqlx::query_as(
        "select state,safe_error,response from control.deployment_driver_operations where id=$1",
    )
    .bind(second_operation)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(reconciled_operation.0, "succeeded");
    assert_eq!(reconciled_operation.1, None);
    assert_eq!(
        reconciled_operation.2,
        Some(reconciliation_response.clone())
    );
    assert!(
        !sqlx::query_scalar::<_, bool>(
            "select control.finish_release_driver_operation($1,$2,$3,$4,$5,
                    'succeeded',$6,null)",
        )
        .bind(second_operation)
        .bind(loser.instance_owner)
        .bind(loser.execution_token)
        .bind(loser.resource_lease_token)
        .bind(second_fence)
        .bind(json!({"stale_after_reconciliation":true}))
        .fetch_one(&second_pool)
        .await
        .unwrap(),
        "the original executor must remain fenced after reconciliation"
    );
    let reconciled_replay = admit_release_driver_lease(store.pool(), loser).await;
    assert_eq!(reconciled_replay.0, "replay");
    assert_eq!(reconciled_replay.3, Some(reconciliation_response));

    first_pool.close().await;
    second_pool.close().await;
    store.pool().close().await;
    sqlx::query(AssertSqlSafe(format!(
        "drop database \"{database}\" with (force)"
    )))
    .execute(&admin)
    .await
    .unwrap();
    admin.close().await;
}

#[tokio::test]
#[ignore = "requires a disposable CONTROL_TEST_DATABASE_URL"]
async fn release_state_machine_and_fleet_fences_are_database_enforced() {
    let store = store().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let release = format!("odoo-2026.08.14-{}", &suffix[..12]);
    let digest = format!("sha256:{}", "1".repeat(64));
    let extension_digest = format!("sha256:{}", "5".repeat(64));
    let manifest_digest = format!("sha256:{}", "2".repeat(64));
    sqlx::query(
        "insert into control.application_releases(
           id,source_commit,odoo_version,odoo_subject_digest,extension_subject_digest,
           odoo_runtime,extension_bundle,pair_qualifications,manifest_digest,addon_versions,
           compatibility,bridge_contract,schema_epoch,change_class,
           required_postconditions,manifest,signature_bundle_ref,extension_signature_ref,
           sbom_ref,published_at,publication_idempotency_key,publication_request_digest
         ) values($1,$2,'19.0',$3,$4,'{}','{}','[{}]',$5,'{}','{}','>=3.2.0,<4.0.0',42,'B',
                  '[]','{}','oci://signature','oci://extension-signature','oci://sbom',now(),$6,$7)",
    )
    .bind(&release)
    .bind("a".repeat(40))
    .bind(&digest)
    .bind(&extension_digest)
    .bind(&manifest_digest)
    .bind(format!("release-publication:{release}"))
    .bind(vec![0_u8; 32])
    .execute(store.pool())
    .await
    .unwrap();

    let volume = format!("mb-ext-{}-{}", "7".repeat(16), "8".repeat(16));
    let lease = Uuid::new_v4();
    sqlx::query(
        "insert into control.extension_volume_preparations(
           volume_name,release_id,extension_manifest_digest,payload_digest,lease_id,lease_expires_at
         ) values($1,$2,$3,$4,$5,now()+interval '2 hours')",
    )
    .bind(&volume)
    .bind(&release)
    .bind(format!("sha256:{}", "7".repeat(64)))
    .bind(format!("sha256:{}", "8".repeat(64)))
    .bind(lease)
    .execute(store.pool())
    .await
    .unwrap();
    let unsafe_volume = sqlx::query(
        "insert into control.extension_volume_preparations(
           volume_name,release_id,extension_manifest_digest,payload_digest,lease_id,lease_expires_at
         ) values('../escape',$1,$2,$3,$4,now()+interval '2 hours')",
    )
    .bind(&release)
    .bind(format!("sha256:{}", "7".repeat(64)))
    .bind(format!("sha256:{}", "8".repeat(64)))
    .bind(Uuid::new_v4())
    .execute(store.pool())
    .await;
    assert!(
        unsafe_volume.is_err(),
        "unsafe preparation volume names fail closed"
    );

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
    sqlx::query("insert into control.fleet_activation_intents(id,fleet_run_id,release_id,runtime_key,target_slot,odoo_subject_digest,extension_subject_digest,pair_qualification_digest,prepared_tenants,gateway_configuration_digest,driver_action_id) values($1,$2,$3,'shared-odoo','blue',$4,$5,$6,'[]',$7,$8)")
        .bind(intent).bind(fleet_run).bind(&release).bind(&digest).bind(&extension_digest).bind(format!("sha256:{}", "6".repeat(64))).bind(&gateway_digest).bind(action).execute(store.pool()).await.unwrap();
    let legacy_activation = sqlx::query("update control.fleet_activation_intents set observed_configuration_digest=$2,activated_at=now() where id=$1")
        .bind(intent).bind(&gateway_digest).execute(store.pool()).await;
    assert!(
        legacy_activation.is_err(),
        "a legacy intent without a loaded-identity version cannot activate"
    );
    sqlx::query("delete from control.fleet_activation_intents where id=$1")
        .bind(intent)
        .execute(store.pool())
        .await
        .unwrap();
    sqlx::query("insert into control.fleet_activation_intents(id,fleet_run_id,release_id,runtime_key,target_slot,odoo_subject_digest,extension_subject_digest,pair_qualification_digest,prepared_tenants,gateway_configuration_digest,driver_action_id,driver_fence_token,gateway_identity_version) values($1,$2,$3,'shared-odoo','blue',$4,$5,$6,'[]',$7,$8,42,1)")
        .bind(intent).bind(fleet_run).bind(&release).bind(&digest).bind(&extension_digest).bind(format!("sha256:{}", "6".repeat(64))).bind(&gateway_digest).bind(action).execute(store.pool()).await.unwrap();
    let partial_activation = sqlx::query(
        "update control.fleet_activation_intents set observed_configuration_digest=$2 where id=$1",
    )
    .bind(intent)
    .bind(&gateway_digest)
    .execute(store.pool())
    .await;
    assert!(
        partial_activation.is_err(),
        "activation time and exact observation must be recorded together"
    );
    sqlx::query("update control.fleet_activation_intents set observed_configuration_digest=$2,activated_at=now() where id=$1")
        .bind(intent).bind(&gateway_digest).execute(store.pool()).await.unwrap();
    for immutable in [
        "update control.fleet_activation_intents set driver_fence_token=43 where id=$1",
        "update control.fleet_activation_intents set gateway_identity_version=null where id=$1",
    ] {
        assert!(
            sqlx::query(immutable)
                .bind(intent)
                .execute(store.pool())
                .await
                .is_err()
        );
    }
    let abandon_active = sqlx::query("update control.fleet_activation_intents set abandoned_at=now(),abandonment_reason='test' where id=$1")
        .bind(intent).execute(store.pool()).await;
    assert!(
        abandon_active.is_err(),
        "an activated intent cannot be abandoned"
    );
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

    assert_eq!(
        sqlx::query(
            "update control.release_fleet_runs
                set state='failed',failure_class='test_fixture_complete',updated_at=now()
              where id=$1 and state='preparing'",
        )
        .bind(fleet_run)
        .execute(store.pool())
        .await
        .unwrap()
        .rows_affected(),
        1,
        "the shared integration database must not retain a fleet-wide admission fence"
    );
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
    sqlx::query("insert into control.erasure_restore_replays(id,workshop_id,tombstone_id,recovery_point_id,operation_id,required_locations) values($1,$2,$3,$4,$5,array['odoo'])")
        .bind(replay).bind(workshop).bind(workshop_tombstone).bind(recovery).bind(restore_operation).execute(store.pool()).await.unwrap();
    let crossed_replay = sqlx::query("insert into control.erasure_restore_replays(id,workshop_id,tombstone_id,recovery_point_id,operation_id,required_locations) values($1,$2,$3,$4,$5,array['odoo'])")
        .bind(Uuid::new_v4()).bind(Uuid::new_v4()).bind(workshop_tombstone).bind(recovery).bind(restore_operation).execute(store.pool()).await;
    assert!(
        crossed_replay.is_err(),
        "restore replay parents must share one workshop"
    );
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

#[tokio::test]
#[ignore = "requires a disposable CONTROL_TEST_DATABASE_URL"]
async fn email_domain_periodic_claim_is_atomic_fair_and_tenant_bound() {
    let store = store().await;
    let preexisting = sqlx::query_as::<_, (Uuid, Uuid)>(
        "select domain.id,domain.workshop_id
           from control.webshop_email_domains domain
          where ((domain.desired_state='active'
                  and domain.state in ('registering','dns_pending','testing'))
              or (domain.desired_state='disconnected'
                  and domain.state in ('disconnecting','action_required')))
            and not exists (
                select 1 from control.operations operation
                 where operation.id=domain.operation_id
                   and operation.state in ('pending','in_flight','awaiting_reconciliation')
            )",
    )
    .fetch_all(store.pool())
    .await
    .unwrap();
    for (domain, workshop) in preexisting {
        let operation = Uuid::new_v4();
        sqlx::query(
            "insert into control.operations(
                id,kind,queue,workshop_id,payload,correlation_id,idempotency_key
             ) values($1,'webshop-email-domain.reconcile','tenant-reconciliation',$2,$3,$4,$5)",
        )
        .bind(operation)
        .bind(workshop)
        .bind(json!({"email_domain_id":domain,"reason":"email_cursor_test_isolation"}))
        .bind(Uuid::new_v4())
        .bind(format!(
            "email-cursor-isolation:{domain}:{}",
            Uuid::new_v4()
        ))
        .execute(store.pool())
        .await
        .unwrap();
        sqlx::query(
            "update control.webshop_email_domains
                set operation_id=$2 where id=$1 and workshop_id=$3",
        )
        .bind(domain)
        .bind(operation)
        .bind(workshop)
        .execute(store.pool())
        .await
        .unwrap();
    }

    let user = Uuid::new_v4();
    sqlx::query("insert into control.users(id,email) values($1,$2)")
        .bind(user)
        .bind(format!("email-cursor-{user}@example.test"))
        .execute(store.pool())
        .await
        .unwrap();
    let mut fixtures = Vec::new();
    for _ in 0..3 {
        let workshop = Uuid::new_v4();
        let domain = Uuid::new_v4();
        sqlx::query(
            "insert into control.workshops(id,slug,display_name,time_zone)
             values($1,$2,'Email cursor fixture','Europe/Paris')",
        )
        .bind(workshop)
        .bind(format!("email-cursor-{}", workshop.simple()))
        .execute(store.pool())
        .await
        .unwrap();
        sqlx::query(
            "insert into control.webshop_email_domains(
                id,workshop_id,domain_name,state,desired_state,created_by
             ) values($1,$2,$3,'dns_pending','active',$4)",
        )
        .bind(domain)
        .bind(workshop)
        .bind(format!("{}.mail.example.test", domain.simple()))
        .bind(user)
        .execute(store.pool())
        .await
        .unwrap();
        fixtures.push((domain, workshop));
    }
    fixtures.sort_by_key(|fixture| fixture.0);
    sqlx::query(
        "update control.periodic_admission_cursors
            set after_id=null where workflow='webshop-email-domain'",
    )
    .execute(store.pool())
    .await
    .unwrap();

    let trace_parent = "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01";
    let trace_state = "mb=email-claim";
    let first = sqlx::query_as::<_, (Uuid, Uuid, Uuid)>(
        "select operation_id,workshop_id,email_domain_id
           from control.admit_due_webshop_email_domain_reconciliations(1,$1,$2)",
    )
    .bind(trace_parent)
    .bind(trace_state)
    .fetch_all(store.pool());
    let second = sqlx::query_as::<_, (Uuid, Uuid, Uuid)>(
        "select operation_id,workshop_id,email_domain_id
           from control.admit_due_webshop_email_domain_reconciliations(1,$1,$2)",
    )
    .bind(trace_parent)
    .bind(trace_state)
    .fetch_all(store.pool());
    let (first, second) = tokio::join!(first, second);
    let mut claims = first.unwrap();
    claims.extend(second.unwrap());
    claims.extend(
        sqlx::query_as::<_, (Uuid, Uuid, Uuid)>(
            "select operation_id,workshop_id,email_domain_id
               from control.admit_due_webshop_email_domain_reconciliations(1,$1,$2)",
        )
        .bind(trace_parent)
        .bind(trace_state)
        .fetch_all(store.pool())
        .await
        .unwrap(),
    );
    claims.sort_by_key(|claim| claim.2);
    assert_eq!(claims.len(), fixtures.len());
    for ((operation, workshop, domain), (expected_domain, expected_workshop)) in
        claims.iter().zip(&fixtures)
    {
        assert_eq!((*domain, *workshop), (*expected_domain, *expected_workshop));
        let evidence = sqlx::query_as::<
            _,
            (
                Option<Uuid>,
                Uuid,
                Option<String>,
                Option<String>,
                serde_json::Value,
            ),
        >(
            "select email.operation_id,operation.workshop_id,operation.trace_parent,
                    operation.trace_state,operation.payload
               from control.webshop_email_domains email
               join control.operations operation on operation.id=email.operation_id
              where email.id=$1",
        )
        .bind(domain)
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(evidence.0, Some(*operation));
        assert_eq!(evidence.1, *workshop);
        assert_eq!(evidence.2.as_deref(), Some(trace_parent));
        assert_eq!(evidence.3.as_deref(), Some(trace_state));
        assert_eq!(
            evidence.4,
            json!({"email_domain_id":domain,"reason":"periodic_observation"})
        );
    }

    let crossed =
        sqlx::query("update control.webshop_email_domains set operation_id=$2 where id=$1")
            .bind(fixtures[1].0)
            .bind(claims[0].0)
            .execute(store.pool())
            .await
            .expect_err("an email domain cannot bind another workshop's operation");
    assert_eq!(
        crossed
            .as_database_error()
            .and_then(|error| error.constraint()),
        Some("webshop_email_domains_operation_workshop_fkey")
    );

    sqlx::query(
        "update control.operations set state='succeeded',finished_at=now()
         where id=any($1)",
    )
    .bind(claims.iter().map(|claim| claim.0).collect::<Vec<_>>())
    .execute(store.pool())
    .await
    .unwrap();
    sqlx::query(
        "update control.periodic_admission_cursors
            set after_id=null where workflow='webshop-email-domain'",
    )
    .execute(store.pool())
    .await
    .unwrap();
    for expected in fixtures
        .iter()
        .map(|fixture| fixture.0)
        .chain(std::iter::once(fixtures[0].0))
    {
        let rows = sqlx::query(
            "select * from control.admit_due_webshop_email_domain_reconciliations(1,null,null)",
        )
        .fetch_all(store.pool())
        .await
        .unwrap();
        assert!(rows.is_empty());
        let cursor: Option<Uuid> = sqlx::query_scalar(
            "select after_id from control.periodic_admission_cursors
             where workflow='webshop-email-domain'",
        )
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(cursor, Some(expected));
    }
    sqlx::query(
        "update control.webshop_email_domains
            set state='disconnected',desired_state='disconnected',disconnected_at=now()
          where id=any($1)",
    )
    .bind(fixtures.iter().map(|fixture| fixture.0).collect::<Vec<_>>())
    .execute(store.pool())
    .await
    .unwrap();
    sqlx::query(
        "update control.periodic_admission_cursors
            set after_id=null where workflow='webshop-email-domain'",
    )
    .execute(store.pool())
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "requires a disposable CONTROL_TEST_DATABASE_URL"]
async fn tenant_periodic_claim_is_bounded_fair_and_payload_exact() {
    let store = store().await;
    let preexisting = sqlx::query_scalar::<_, Uuid>(
        "select workshop.id
           from control.workshops workshop
           join control.odoo_databases database on database.workshop_id=workshop.id
          where workshop.status in ('trial','active','past_due','restricted','suspended')
            and database.kind='primary' and database.deleted_at is null
            and database.public_hostname is not null
            and not exists(
                select 1 from control.operations operation
                 where operation.workshop_id=workshop.id
                   and operation.state in ('pending','in_flight','awaiting_reconciliation')
                   and operation.kind in ('tenant.provision','tenant.reconcile',
                                          'tenant.lifecycle','odoo.release.adopt'))",
    )
    .fetch_all(store.pool())
    .await
    .unwrap();
    for workshop in preexisting {
        sqlx::query(
            "insert into control.operations(
                id,kind,queue,workshop_id,payload,correlation_id,idempotency_key
             ) values($1,'tenant.reconcile','tenant-reconciliation',$2,'{}',$3,$4)",
        )
        .bind(Uuid::new_v4())
        .bind(workshop)
        .bind(Uuid::new_v4())
        .bind(format!(
            "tenant-cursor-isolation:{workshop}:{}",
            Uuid::new_v4()
        ))
        .execute(store.pool())
        .await
        .unwrap();
    }

    let mut fixtures = Vec::new();
    for _ in 0..3 {
        let workshop = Uuid::new_v4();
        let database = Uuid::new_v4();
        let slug = format!("tenant-cursor-{}", workshop.simple());
        let database_ref = format!("mb_{}", workshop.simple());
        let public_hostname = format!("{slug}.example.test");
        sqlx::query(
            "insert into control.workshops(id,slug,display_name,time_zone,status)
             values($1,$2,'Tenant cursor fixture','Europe/Paris','active')",
        )
        .bind(workshop)
        .bind(&slug)
        .execute(store.pool())
        .await
        .unwrap();
        sqlx::query(
            "insert into control.odoo_databases(
                id,workshop_id,kind,database_ref,public_hostname,label,state,routable
             ) values($1,$2,'primary',$3,$4,'Tenant cursor database','ready',true)",
        )
        .bind(database)
        .bind(workshop)
        .bind(&database_ref)
        .bind(&public_hostname)
        .execute(store.pool())
        .await
        .unwrap();
        fixtures.push((workshop, database, slug, database_ref, public_hostname));
    }
    fixtures.sort_by_key(|fixture| fixture.0);
    sqlx::query(
        "update control.periodic_admission_cursors
            set after_id=null where workflow='tenant-reconcile'",
    )
    .execute(store.pool())
    .await
    .unwrap();

    let trace_parent = "00-fedcba9876543210fedcba9876543210-fedcba9876543210-01";
    let trace_state = "mb=tenant-claim";
    let mut claims = sqlx::query_as::<_, (Uuid, Uuid)>(
        "select operation_id,workshop_id
           from control.admit_due_tenant_reconciliations(2,'tenant.example.test',$1,$2)",
    )
    .bind(trace_parent)
    .bind(trace_state)
    .fetch_all(store.pool())
    .await
    .unwrap();
    assert_eq!(claims.len(), 2, "one call must obey its requested bound");
    claims.extend(
        sqlx::query_as::<_, (Uuid, Uuid)>(
            "select operation_id,workshop_id
               from control.admit_due_tenant_reconciliations(2,'tenant.example.test',$1,$2)",
        )
        .bind(trace_parent)
        .bind(trace_state)
        .fetch_all(store.pool())
        .await
        .unwrap(),
    );
    claims.sort_by_key(|claim| claim.1);
    assert_eq!(claims.len(), fixtures.len());
    for ((operation, workshop), fixture) in claims.iter().zip(&fixtures) {
        assert_eq!(*workshop, fixture.0);
        let row = sqlx::query_as::<_, (Option<String>, Option<String>, serde_json::Value)>(
            "select trace_parent,trace_state,payload
               from control.operations where id=$1 and workshop_id=$2",
        )
        .bind(operation)
        .bind(workshop)
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(row.0.as_deref(), Some(trace_parent));
        assert_eq!(row.1.as_deref(), Some(trace_state));
        assert_eq!(
            row.2,
            json!({
                "database_id":fixture.1,
                "database_ref":fixture.3,
                "public_hostname":fixture.4,
                "paperless_hostname":format!("docs-{}.tenant.example.test",fixture.2),
                "paperless_enabled":false,
                "custom_hostnames":[],
                "reason":"periodic_drift_reconciliation"
            })
        );
    }

    sqlx::query(
        "update control.operations set state='succeeded',finished_at=now()
         where id=any($1)",
    )
    .bind(claims.iter().map(|claim| claim.0).collect::<Vec<_>>())
    .execute(store.pool())
    .await
    .unwrap();
    sqlx::query(
        "update control.periodic_admission_cursors
            set after_id=null where workflow='tenant-reconcile'",
    )
    .execute(store.pool())
    .await
    .unwrap();
    for expected in fixtures
        .iter()
        .map(|fixture| fixture.0)
        .chain(std::iter::once(fixtures[0].0))
    {
        let rows = sqlx::query(
            "select * from control.admit_due_tenant_reconciliations(
                1,'tenant.example.test',null,null)",
        )
        .fetch_all(store.pool())
        .await
        .unwrap();
        assert!(rows.is_empty());
        let cursor: Option<Uuid> = sqlx::query_scalar(
            "select after_id from control.periodic_admission_cursors
             where workflow='tenant-reconcile'",
        )
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(cursor, Some(expected));
    }
    sqlx::query("update control.workshops set status='provisioning' where id=any($1)")
        .bind(fixtures.iter().map(|fixture| fixture.0).collect::<Vec<_>>())
        .execute(store.pool())
        .await
        .unwrap();
    sqlx::query(
        "update control.periodic_admission_cursors
            set after_id=null where workflow='tenant-reconcile'",
    )
    .execute(store.pool())
    .await
    .unwrap();
}
