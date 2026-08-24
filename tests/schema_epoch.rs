use mb_control_plane::{
    modules::CATALOG,
    persistence::{InitialReleaseActivationError, Store, activate_initial_release},
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::AssertSqlSafe;
use sqlx::postgres::{PgConnection, PgPoolOptions};
use uuid::Uuid;

#[derive(Deserialize)]
struct CatalogManifest {
    postgres_major: i32,
    relations: Vec<String>,
    catalog: std::collections::BTreeMap<String, CatalogFingerprint>,
}

#[derive(Deserialize)]
struct CatalogFingerprint {
    count: i64,
    digest: String,
}

type RecoveryPublicationAdmissionRow = (
    String,
    Uuid,
    Uuid,
    Uuid,
    i64,
    i64,
    String,
    i32,
    i64,
    String,
    String,
    Option<Value>,
);

fn database_url(admin_url: &str, database: &str) -> String {
    let mut url = url::Url::parse(admin_url).expect("CONTROL_TEST_ADMIN_URL must be a URL");
    url.set_path(database);
    url.to_string()
}

async fn create_database(admin_url: &str, database: &str) -> sqlx::PgPool {
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(admin_url)
        .await
        .expect("connect test PostgreSQL administrator");
    sqlx::query(AssertSqlSafe(format!("create database \"{database}\"")))
        .execute(&admin)
        .await
        .expect("create disposable schema-epoch database");
    admin
}

async fn drop_database(admin: &sqlx::PgPool, database: &str) {
    sqlx::query(AssertSqlSafe(format!(
        "drop database \"{database}\" with (force)"
    )))
    .execute(admin)
    .await
    .expect("drop disposable schema-epoch database");
}

async fn create_runtime_roles(admin: &sqlx::PgPool) {
    sqlx::query(
        "do $$ begin
           create role control_api; create role control_tenant_api;
           create role control_backup_scheduler;
           create role control_driver_ledger; create role control_email_worker;
           create role control_inventory_worker; create role control_invoice_worker;
           create role control_lifecycle_worker; create role control_membership_worker;
           create role control_provisioning_worker; create role control_reconciliation_worker;
           create role control_release_worker; create role control_privacy_worker;
         end $$",
    )
    .execute(admin)
    .await
    .expect("create runtime roles for complete ACL catalog assertion");
}

async fn drop_runtime_roles(admin: &sqlx::PgPool) {
    sqlx::query(
        "do $$ begin
           drop role control_api,control_tenant_api,control_backup_scheduler,control_driver_ledger,
             control_email_worker,control_inventory_worker,control_invoice_worker,
             control_lifecycle_worker,control_membership_worker,control_provisioning_worker,
             control_reconciliation_worker,control_release_worker,control_privacy_worker;
         end $$",
    )
    .execute(admin)
    .await
    .expect("drop runtime roles after ACL catalog assertion");
}

struct RouteSetTerminalDecisionAuthorization<'a> {
    publication_id: Uuid,
    claim_fence: i64,
    reconciliation_operation_id: Uuid,
    reconciliation_operation_attempt: i32,
    reconciliation_operation_lease_owner: &'a str,
    reconciliation_owner: Uuid,
    reconciliation_token: Uuid,
    resolution_kind: &'a str,
    decision: &'a str,
}

async fn authorize_route_set_terminal_decision(
    connection: &mut PgConnection,
    authorization: RouteSetTerminalDecisionAuthorization<'_>,
) -> String {
    sqlx::query_scalar(
        "with decision as (
           select encode(public.digest(
             convert_to('mb-route-set-terminal-decision-v1','UTF8')
             ||uuid_send($1::uuid)||int8send($2::bigint)
             ||uuid_send($3::uuid)||int4send($4::integer)
             ||int4send(octet_length(convert_to($5::text,'UTF8')))||convert_to($5::text,'UTF8')
             ||uuid_send($6::uuid)
             ||public.digest(convert_to('mb-route-set-reconciliation-token-v1','UTF8')
               ||uuid_send($7::uuid),'sha256')
             ||int4send(octet_length(convert_to($8::text,'UTF8')))||convert_to($8::text,'UTF8')
             ||int4send(octet_length(convert_to($9::text,'UTF8')))||convert_to($9::text,'UTF8')
             ||public.digest(convert_to(resolution.evidence::text,'UTF8'),'sha256'),
             'sha256'),'hex') digest
           from control.workshop_route_set_publication_resolutions resolution
           where resolution.publication_id=$1
             and resolution.reconciliation_claim_fence=$2
         ), authorized as (
           update control.operations operation set payload=operation.payload||jsonb_build_object(
             'route_set_resolution_claim_fence',$2,
             'route_set_resolution_kind',$8,
             'route_set_terminal_decision',$9,
             'route_set_terminal_decision_digest',decision.digest)
           from decision where operation.id=$3 returning decision.digest
         ) select digest from authorized",
    )
    .bind(authorization.publication_id)
    .bind(authorization.claim_fence)
    .bind(authorization.reconciliation_operation_id)
    .bind(authorization.reconciliation_operation_attempt)
    .bind(authorization.reconciliation_operation_lease_owner)
    .bind(authorization.reconciliation_owner)
    .bind(authorization.reconciliation_token)
    .bind(authorization.resolution_kind)
    .bind(authorization.decision)
    .fetch_one(connection)
    .await
    .unwrap()
}

async fn insert_prepared_release(store: &Store, registry_version: i32) -> (String, String, String) {
    let release_id = format!("odoo-2026.08.21-{}", Uuid::new_v4().simple());
    let image_digest = format!("sha256:{}", "a".repeat(64));
    let extension_digest = format!("sha256:{}", "c".repeat(64));
    let manifest_digest = format!("sha256:{}", "b".repeat(64));
    sqlx::query(
        "insert into control.application_releases(
           id,source_commit,odoo_version,odoo_subject_digest,extension_subject_digest,
           odoo_runtime,extension_bundle,pair_qualifications,manifest_digest,addon_versions,
           compatibility,bridge_contract,schema_epoch,change_class,required_postconditions,
           manifest,signature_bundle_ref,extension_signature_ref,sbom_ref,published_at,status,
           publication_idempotency_key,publication_request_digest
         ) values($1,$2,'19.0',$3,$4,'{}','{}','[{}]',$5,'{}','{}','>=3.2.0,<4.0.0',1,'A','[]',
           jsonb_build_object(
             'capability_registry_version',$6,
             'odoo_runtime',jsonb_build_object(
               'deployment_ref','docker.io/odoo@sha256:fixture'
             )
           ),'oci://signature',
           'oci://extension-signature','oci://sbom',now(),'prepared',$7,$8)",
    )
    .bind(&release_id)
    .bind("c".repeat(40))
    .bind(&image_digest)
    .bind(&extension_digest)
    .bind(&manifest_digest)
    .bind(registry_version)
    .bind(format!("publish:{release_id}"))
    .bind(vec![1_u8; 32])
    .execute(store.pool())
    .await
    .unwrap();

    (release_id, image_digest, manifest_digest)
}

async fn insert_runtime_slot(
    store: &Store,
    release_id: &str,
    image_digest: &str,
    manifest_digest: &str,
    state: &str,
    verified: bool,
    evidence_verified: bool,
) {
    let evidence = json!({
        "release_id":release_id,
        "odoo_subject_digest":image_digest,
        "extension_subject_digest":format!("sha256:{}", "c".repeat(64)),
        "pair_qualification_digest":format!("sha256:{}", "f".repeat(64)),
        "manifest_digest":manifest_digest,
        "provenance_verified":evidence_verified,
        "runtime_inspection_verified":evidence_verified,
    });
    sqlx::query(
        "insert into control.runtime_release_slots(
           runtime_key,slot,release_id,state,odoo_subject_digest,odoo_manifest_digest,
           odoo_config_digest,extension_subject_digest,extension_manifest_digest,
           extension_config_digest,payload_digest,extension_volume,pair_qualification_digest,
           bridge_contract_digest,installed_addon_versions,started_at,verified_at,evidence
         ) values('shared-odoo','blue',$1,$2,$3,$4,$5,$6,$7,$8,$9,
           'mb-ext-1111111111111111-2222222222222222',$10,$11,'{}',now(),case when $12 then now() end,$13)",
    )
    .bind(release_id)
    .bind(state)
    .bind(image_digest)
    .bind(format!("sha256:{}", "1".repeat(64)))
    .bind(format!("sha256:{}", "2".repeat(64)))
    .bind(format!("sha256:{}", "c".repeat(64)))
    .bind(format!("sha256:{}", "3".repeat(64)))
    .bind(format!("sha256:{}", "4".repeat(64)))
    .bind(format!("sha256:{}", "5".repeat(64)))
    .bind(format!("sha256:{}", "f".repeat(64)))
    .bind(format!("sha256:{}", "6".repeat(64)))
    .bind(verified)
    .bind(evidence)
    .execute(store.pool())
    .await
    .unwrap();
}

fn assert_activation_conflict(error: InitialReleaseActivationError, expected: &str) {
    assert_eq!(error.to_string(), expected);
}

struct FleetReconciliationFixture {
    operation_id: Uuid,
    operation_owner: String,
    driver_operation_id: Uuid,
    fleet_run_id: Uuid,
    intent_id: Uuid,
    driver_action_id: Uuid,
    original_instance_owner: Uuid,
    idempotency_key: String,
    request_digest: String,
    release_id: String,
    image_digest: String,
    gateway_digest: String,
    prepared_tenants: serde_json::Value,
    tenant_snapshot: serde_json::Value,
}

async fn insert_fleet_reconciliation_fixture(
    store: &Store,
    executor_protocol: Option<i16>,
) -> FleetReconciliationFixture {
    let (release_id, image_digest, _) = insert_prepared_release(store, 1).await;
    let workshop_id = Uuid::new_v4();
    let database_id = Uuid::new_v4();
    let adoption_id = Uuid::new_v4();
    let operation_id = Uuid::new_v4();
    let driver_operation_id = Uuid::new_v4();
    let fleet_run_id = Uuid::new_v4();
    let intent_id = Uuid::new_v4();
    let driver_action_id = Uuid::new_v4();
    let original_instance_owner = Uuid::new_v4();
    let operation_owner = format!("release-fixture-{operation_id}");
    let idempotency_key = format!("release-fleet:{fleet_run_id}");
    let request_digest = "7".repeat(64);
    let database_ref = format!("mb_{}", database_id.simple());
    let public_hostname = format!("{}.example.test", workshop_id.simple());
    let tenant_snapshot = json!([{
        "workshop_id": workshop_id,
        "database_id": database_id,
        "database_ref": database_ref,
        "paperless_enabled": false,
    }]);
    let prepared_tenants = json!([{
        "adoption_id": adoption_id,
        "workshop_id": workshop_id,
        "database_id": database_id,
        "database_ref": database_ref,
        "public_hostname": public_hostname,
    }]);
    sqlx::query(
        "insert into control.workshops(id,slug,display_name,time_zone,status)
         values($1,$2,'Fleet reconciliation fixture','UTC','active')",
    )
    .bind(workshop_id)
    .bind(format!(
        "fixture-{}",
        &workshop_id.simple().to_string()[..12]
    ))
    .execute(store.pool())
    .await
    .unwrap();
    sqlx::query(
        "insert into control.odoo_databases(
           id,workshop_id,kind,database_ref,public_hostname,label,state,routable
         ) values($1,$2,'primary',$3,$4,'Primary','ready',true)",
    )
    .bind(database_id)
    .bind(workshop_id)
    .bind(&database_ref)
    .bind(&public_hostname)
    .execute(store.pool())
    .await
    .unwrap();
    sqlx::query(
        "insert into control.operations(
           id,kind,queue,payload,correlation_id,idempotency_key,state,attempt,
           max_attempts,leased_by,lease_expires_at
         ) values($1,'odoo.release.adopt','release-adoption',$2,$3,$4,
                  'in_flight',1,3,$5,now()+interval '10 minutes')",
    )
    .bind(operation_id)
    .bind(json!({"phase":"adopt","release_id":release_id}))
    .bind(Uuid::new_v4())
    .bind(format!("fleet-reconciliation-operation:{operation_id}"))
    .bind(&operation_owner)
    .execute(store.pool())
    .await
    .unwrap();
    sqlx::query(
        "insert into control.tenant_release_adoptions(
           id,workshop_id,database_id,release_id,registry_version,state,
           operation_id,target_schema_epoch,verified_at
         ) values($1,$2,$3,$4,1,'prepared',$5,1,now())",
    )
    .bind(adoption_id)
    .bind(workshop_id)
    .bind(database_id)
    .bind(&release_id)
    .bind(operation_id)
    .execute(store.pool())
    .await
    .unwrap();
    sqlx::query(
        "insert into control.release_fleet_runs(
           id,release_id,operation_id,fleet_generation,state,tenant_snapshot,
           target_slot,driver_fence_token
         ) values($1,$2,$3,1,'activating',$4,'blue',42)",
    )
    .bind(fleet_run_id)
    .bind(&release_id)
    .bind(operation_id)
    .bind(&tenant_snapshot)
    .execute(store.pool())
    .await
    .unwrap();
    sqlx::query(
        "insert into control.deployment_driver_operations(
           id,idempotency_key,workshop_id,action,request_digest,state,safe_error,
           control_operation_id,control_operation_attempt,
           control_operation_lease_owner,target_key,execution_attempt,
           release_executor_protocol_version
         ) values($1,$2,null,'release',$3,'in_progress','runtime_outcome_unknown',
                  $4,1,$5,$6,1,$7)",
    )
    .bind(driver_operation_id)
    .bind(&idempotency_key)
    .bind(&request_digest)
    .bind(operation_id)
    .bind(&operation_owner)
    .bind(format!("fleet/{fleet_run_id}"))
    .bind(executor_protocol)
    .execute(store.pool())
    .await
    .unwrap();
    sqlx::query(
        "update control.deployment_driver_resource_leases set
           state='quarantined',authority_kind='release',fence_token=42,
           driver_operation_id=$1,effect_run_id=null,lease_owner=$2,
           lease_token=null,lease_expires_at=null,heartbeat_at=now(),
           quarantined_at=now(),safe_error='runtime_outcome_unknown',updated_at=now()
         where resource_key='runtime/shared-odoo'",
    )
    .bind(driver_operation_id)
    .bind(original_instance_owner)
    .execute(store.pool())
    .await
    .unwrap();
    let gateway_digest = format!("sha256:{}", "8".repeat(64));
    sqlx::query(
        "insert into control.fleet_activation_intents(
           id,fleet_run_id,release_id,runtime_key,target_slot,
           odoo_subject_digest,extension_subject_digest,
           pair_qualification_digest,prepared_tenants,
           gateway_configuration_digest,driver_action_id,driver_fence_token,
           gateway_identity_version
         ) values($1,$2,$3,'shared-odoo','blue',$4,$5,$6,$7,$8,$9,42,1)",
    )
    .bind(intent_id)
    .bind(fleet_run_id)
    .bind(&release_id)
    .bind(&image_digest)
    .bind(format!("sha256:{}", "c".repeat(64)))
    .bind(format!("sha256:{}", "f".repeat(64)))
    .bind(&prepared_tenants)
    .bind(&gateway_digest)
    .bind(driver_action_id)
    .execute(store.pool())
    .await
    .unwrap();
    FleetReconciliationFixture {
        operation_id,
        operation_owner,
        driver_operation_id,
        fleet_run_id,
        intent_id,
        driver_action_id,
        original_instance_owner,
        idempotency_key,
        request_digest,
        release_id,
        image_digest,
        gateway_digest,
        prepared_tenants,
        tenant_snapshot,
    }
}

#[tokio::test]
#[ignore = "requires a PostgreSQL 17 CONTROL_TEST_ADMIN_URL with CREATEDB"]
async fn blank_database_migrates_and_second_startup_is_a_no_op() {
    let admin_url = std::env::var("CONTROL_TEST_ADMIN_URL").expect("CONTROL_TEST_ADMIN_URL");
    let database = format!("control_epoch_{}", Uuid::new_v4().simple());
    let admin = create_database(&admin_url, &database).await;
    let store = Store::connect(&database_url(&admin_url, &database))
        .await
        .expect("connect disposable database");

    store.migrate().await.expect("apply fresh baseline");
    let first = sqlx::query_as::<_, (i64, i64, i64)>(
        "select
            (select count(*) from public._sqlx_migrations),
            (select count(*) from control.capability_registry_versions where active),
            (select count(*) from control.capability_registry_entries)",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(first.0, 41);
    assert_eq!(first.1, 1);
    assert_eq!(first.2, i64::try_from(CATALOG.len()).unwrap());

    store.migrate().await.expect("second migration startup");
    let second: i64 = sqlx::query_scalar("select count(*) from public._sqlx_migrations")
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(
        second, 41,
        "the second startup must not append a ledger row"
    );
    store.pool().close().await;
    drop_database(&admin, &database).await;
}

#[test]
fn release_generation_retention_migration_keeps_the_boundary_dormant_and_fenced() {
    let migration = include_str!("../migrations/0038_release_generation_retention.sql");
    for required in [
        "fleet_release_generation_retention_subjects",
        "fleet_release_generation_retention_claims",
        "fleet_release_generation_retention_attempts",
        "generation_retention_protected_selectors",
        "discover_fleet_release_generation_retention_candidates",
        "claim_fleet_release_generation_retention",
        "renew_fleet_release_generation_retention_claim",
        "finish_fleet_release_generation_retention",
        "authority_kind='release-retention'",
        "mode='generation_v1'",
        "claim_token_digest",
        "protected_current",
        "identity_mismatch",
    ] {
        assert!(migration.contains(required), "missing {required}");
    }
    assert!(
        migration.contains("after insert on control.fleet_release_route_publication_completions")
    );
    assert!(
        migration
            .contains("after insert on control.fleet_release_route_publication_recovery_terminals")
    );
    assert!(migration.contains("on conflict(driver_operation_id,overlay_kind) do nothing"));
    assert!(
        migration.contains("p_evidence ?& array['observed_target_device','observed_target_inode'")
    );
    assert!(!migration.contains("grant select"));
    assert!(!migration.contains("grant insert"));
    assert!(!migration.contains("grant update"));
    assert!(!migration.contains("grant delete"));
}

#[test]
fn interrupted_release_snapshot_reader_is_claim_authenticated_and_function_only() {
    let migration =
        include_str!("../migrations/0039_interrupted_release_route_snapshot_reader.sql");
    for required in [
        "create function control.read_interrupted_immutable_release_route_snapshot_batch",
        "security definer set search_path=pg_catalog,control",
        "control.lock_immutable_release_route_recovery_claim",
        "claim_lost",
        "wrong_phase",
        "complete",
        "claimed",
        "v_claim.claim_mode<>'forward_only'",
        "v_publication.phase<>'quarantined'",
        "v_publication.interrupted_phase<>'candidate_staging'",
        "v_publication.external_effects_started_at is null",
        "control.fleet_release_route_snapshots",
        "control.fleet_release_route_snapshot_items",
        "control.fleet_release_route_publication_owners",
        "control.fleet_release_route_publication_recovery_route_heads",
        "p_limit<1 or p_limit>500",
        "00000000-0000-0000-0000-000000000000",
        "order by item.workshop_id limit p_limit",
        "to control_driver_ledger",
    ] {
        assert!(migration.contains(required), "missing {required}");
    }
    assert_eq!(migration.matches("create function ").count(), 1);
    assert!(!migration.contains("create table"));
    assert!(!migration.contains("grant select"));
    assert!(!migration.contains("grant insert"));
    assert!(!migration.contains("grant update"));
    assert!(!migration.contains("grant delete"));
}

#[test]
fn interrupted_release_runtime_expectation_is_dormant_fenced_and_fail_closed() {
    let migration = include_str!("../migrations/0040_interrupted_release_runtime_expectation.sql");
    for required in [
        "create function control.read_interrupted_immutable_release_runtime_expectation",
        "security definer set search_path=pg_catalog,control",
        "control.lock_immutable_release_route_recovery_claim",
        "claim_lost",
        "wrong_phase",
        "state_drift",
        "claimed",
        "v_claim.claim_mode<>'forward_only'",
        "v_publication.phase<>'quarantined'",
        "v_global.state<>'quarantined'",
        "v_intent_count<>1",
        "v_intent.prepared_tenants is distinct from v_prepared",
        "rename to resolve_interrupted_immutable_release_route_publication_unsafe_v1",
        "rename to finish_interrupted_immutable_release_route_publication_unsafe_v1",
        "return 'unsupported_resolution'",
        "resolution_kind<>'unstarted'",
        "not valid",
        "to control_driver_ledger",
    ] {
        assert!(migration.contains(required), "missing {required}");
    }
    assert!(!migration.contains("grant select"));
    assert!(!migration.contains("grant insert"));
    assert!(!migration.contains("grant update"));
    assert!(!migration.contains("grant delete"));
}

#[test]
fn interrupted_release_runtime_receipt_and_review_are_separate_capabilities() {
    let migration =
        include_str!("../migrations/0041_interrupted_release_runtime_receipt_review.sql");
    for required in [
        "fleet_release_route_publication_recovery_runtime_observations",
        "fleet_release_route_publication_recovery_reviews",
        "record_interrupted_immutable_release_runtime_observation",
        "authorize_interrupted_immutable_release_route_candidate_from_observation",
        "runtime_observation_required",
        "resolve_interrupted_immutable_release_route_publication_without_runtime_receipt_v2",
        "review_interrupted_immutable_release_runtime_observation",
        "finish_reviewed_interrupted_immutable_release_route_publication",
        "release_route_recovery_runtime_observation_digest",
        "release_route_recovery_review_digest",
        "resolution_digest",
        "accept_candidate",
        "keep_quarantined",
        "security definer set search_path=pg_catalog,control",
        "to control_driver_ledger",
        "to control_release_worker",
    ] {
        assert!(migration.contains(required), "missing {required}");
    }
    assert!(migration.contains("before update or delete"));
    assert!(migration.contains("valid_immutable_release_route_completion_response"));
    assert!(!migration.contains("grant select"));
    assert!(!migration.contains("grant insert"));
    assert!(!migration.contains("grant update"));
    assert!(!migration.contains("grant delete"));
}

#[test]
fn candidate_forward_recovery_requires_an_exact_receipted_route_proof() {
    let recovery = include_str!("../migrations/0037_release_route_publication_recovery.sql");
    let receipt = include_str!("../migrations/0041_interrupted_release_runtime_receipt_review.sql");

    for required in [
        "(select count(*) from jsonb_object_keys(p_observation_evidence))<>11",
        "'observed_directory_inode','observed_loaded_identity','maintenance_artifact','candidate_artifact'",
        "v_selector<>v_seal.selector",
        "v_device is distinct from v_seal.directory_device",
        "v_inode is distinct from v_seal.directory_inode",
        "not control.valid_release_route_loaded_identity(v_identity)",
        "'overlay_kind','candidate','route_set_digest',v_seal.route_set_digest",
        "recovery_authorization.authorization_kind='publish_candidate' and recovery_authorization.response=p_candidate_response",
        "p_observation_evidence->'maintenance_artifact' is distinct from jsonb_build_object",
        "p_observation_evidence->'candidate_artifact' is distinct from jsonb_build_object",
        "'publication_started',true",
    ] {
        assert!(
            recovery.contains(required),
            "missing route-proof fence: {required}"
        );
    }

    for required in [
        "if p_authorization_kind='publish_candidate' then return 'runtime_observation_required'",
        "'candidate',v_observation.completion_response",
        "if p_candidate_response is not null then return 'runtime_observation_required'",
        "auth.response=observation.completion_response",
        "p_observation_evidence,v_observation.completion_response",
        "resolution.candidate_response=observation.completion_response",
        "review.decision='accept_candidate'",
    ] {
        assert!(
            receipt.contains(required),
            "missing receipt/review fence: {required}"
        );
    }
}

#[tokio::test]
#[ignore = "requires a PostgreSQL 17 CONTROL_TEST_ADMIN_URL with CREATEDB"]
async fn interrupted_release_runtime_receipt_review_acl_is_role_separated() {
    let admin_url = std::env::var("CONTROL_TEST_ADMIN_URL").expect("CONTROL_TEST_ADMIN_URL");
    let database = format!("control_release_review_{}", Uuid::new_v4().simple());
    let admin = create_database(&admin_url, &database).await;
    create_runtime_roles(&admin).await;
    let store = Store::connect(&database_url(&admin_url, &database))
        .await
        .unwrap();
    store.migrate().await.unwrap();

    let invalid_observation: String = sqlx::query_scalar(
        "select outcome from control.record_interrupted_immutable_release_runtime_observation(
          null::uuid,null::integer,null::text,null::uuid,null::uuid,null::bigint,null::jsonb)",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(invalid_observation, "invalid");
    let invalid_review: String = sqlx::query_scalar(
        "select outcome from control.review_interrupted_immutable_release_runtime_observation(
          null::uuid,null::bigint,null::uuid,null::integer,null::text,null::text,null::text)",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(invalid_review, "invalid");
    let acl: (bool, bool, bool, bool, bool, bool, bool, bool, bool, bool) = sqlx::query_as(
        "select
          has_function_privilege('control_driver_ledger',
           'control.record_interrupted_immutable_release_runtime_observation(uuid,integer,text,uuid,uuid,bigint,jsonb)','execute'),
          has_function_privilege('control_driver_ledger',
           'control.review_interrupted_immutable_release_runtime_observation(uuid,bigint,uuid,integer,text,text,text)','execute'),
          has_function_privilege('control_driver_ledger',
           'control.finish_reviewed_interrupted_immutable_release_route_publication(uuid,integer,text,uuid,uuid,bigint)','execute'),
          has_function_privilege('control_release_worker',
           'control.record_interrupted_immutable_release_runtime_observation(uuid,integer,text,uuid,uuid,bigint,jsonb)','execute'),
          has_function_privilege('control_release_worker',
           'control.review_interrupted_immutable_release_runtime_observation(uuid,bigint,uuid,integer,text,text,text)','execute'),
          has_function_privilege('control_release_worker',
           'control.finish_reviewed_interrupted_immutable_release_route_publication(uuid,integer,text,uuid,uuid,bigint)','execute'),
          has_function_privilege('control_driver_ledger',
           'control.release_route_recovery_review_digest(uuid,uuid,bigint,text,text,uuid,integer,text,text)','execute'),
          has_table_privilege('control_driver_ledger',
           'control.fleet_release_route_publication_recovery_runtime_observations','select,insert,update,delete'),
          has_table_privilege('control_release_worker',
           'control.fleet_release_route_publication_recovery_reviews','select,insert,update,delete'),
          has_function_privilege('public',
           'control.review_interrupted_immutable_release_runtime_observation(uuid,bigint,uuid,integer,text,text,text)','execute')",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(
        acl,
        (
            true, false, true, false, true, false, false, false, false, false
        )
    );

    store.pool().close().await;
    drop_database(&admin, &database).await;
    drop_runtime_roles(&admin).await;
}

#[tokio::test]
#[ignore = "requires a PostgreSQL 17 CONTROL_TEST_ADMIN_URL with CREATEDB"]
async fn interrupted_release_runtime_expectation_has_only_the_driver_capability() {
    let admin_url = std::env::var("CONTROL_TEST_ADMIN_URL").expect("CONTROL_TEST_ADMIN_URL");
    let database = format!("control_release_runtime_{}", Uuid::new_v4().simple());
    let admin = create_database(&admin_url, &database).await;
    create_runtime_roles(&admin).await;
    let store = Store::connect(&database_url(&admin_url, &database))
        .await
        .unwrap();
    store.migrate().await.unwrap();

    let invalid: String = sqlx::query_scalar(
        "select outcome from control.read_interrupted_immutable_release_runtime_expectation(
          null::uuid,null::integer,null::text,null::uuid,null::uuid,null::bigint)",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(invalid, "invalid");
    let acl: (bool, bool, bool) = sqlx::query_as(
        "select
          has_function_privilege('control_driver_ledger',
           'control.read_interrupted_immutable_release_runtime_expectation(uuid,integer,text,uuid,uuid,bigint)','execute'),
          has_function_privilege('control_release_worker',
           'control.read_interrupted_immutable_release_runtime_expectation(uuid,integer,text,uuid,uuid,bigint)','execute'),
          has_function_privilege('control_driver_ledger',
           'control.resolve_interrupted_immutable_release_route_publication_unsafe_v1(uuid,integer,text,uuid,uuid,bigint,text,jsonb,jsonb)','execute')",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(acl, (true, false, false));

    store.pool().close().await;
    drop_database(&admin, &database).await;
    drop_runtime_roles(&admin).await;
}

#[tokio::test]
#[ignore = "requires a PostgreSQL 17 CONTROL_TEST_ADMIN_URL with CREATEDB"]
async fn interrupted_release_snapshot_reader_has_only_the_driver_capability() {
    let admin_url = std::env::var("CONTROL_TEST_ADMIN_URL").expect("CONTROL_TEST_ADMIN_URL");
    let database = format!("control_release_snapshot_{}", Uuid::new_v4().simple());
    let admin = create_database(&admin_url, &database).await;
    create_runtime_roles(&admin).await;
    let store = Store::connect(&database_url(&admin_url, &database))
        .await
        .unwrap();
    store.migrate().await.unwrap();

    let invalid: String = sqlx::query_scalar(
        "select outcome from control.read_interrupted_immutable_release_route_snapshot_batch(
          null::uuid,null::integer,null::text,null::uuid,null::uuid,
          null::bigint,null::uuid,null::integer)",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(invalid, "invalid");
    let acl: (bool, bool, bool, bool, bool) = sqlx::query_as(
        "select
          has_function_privilege('control_driver_ledger',
           'control.read_interrupted_immutable_release_route_snapshot_batch(uuid,integer,text,uuid,uuid,bigint,uuid,integer)','execute'),
          has_function_privilege('control_release_worker',
           'control.read_interrupted_immutable_release_route_snapshot_batch(uuid,integer,text,uuid,uuid,bigint,uuid,integer)','execute'),
          has_table_privilege('control_driver_ledger','control.fleet_release_route_snapshots','select'),
          has_table_privilege('control_driver_ledger','control.fleet_release_route_snapshot_items','select'),
          has_table_privilege('control_driver_ledger','control.fleet_release_route_publication_recovery_route_heads','select')",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(acl, (true, false, false, false, false));

    store.pool().close().await;
    drop_database(&admin, &database).await;
    drop_runtime_roles(&admin).await;
}

#[tokio::test]
#[ignore = "requires a PostgreSQL 17 CONTROL_TEST_ADMIN_URL with CREATEDB"]
async fn release_generation_retention_schema_is_null_strict_and_function_only() {
    let admin_url = std::env::var("CONTROL_TEST_ADMIN_URL").expect("CONTROL_TEST_ADMIN_URL");
    let database = format!("control_release_retention_{}", Uuid::new_v4().simple());
    let admin = create_database(&admin_url, &database).await;
    create_runtime_roles(&admin).await;
    let store = Store::connect(&database_url(&admin_url, &database))
        .await
        .unwrap();
    store.migrate().await.unwrap();

    let invalid_claim: String = sqlx::query_scalar(
        "select outcome from control.claim_fleet_release_generation_retention(
          null::uuid,null::text,null::uuid,null::uuid,null::integer)",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(invalid_claim, "invalid");
    let invalid_renew: bool = sqlx::query_scalar(
        "select control.renew_fleet_release_generation_retention_claim(
          null::uuid,null::text,null::uuid,null::uuid,null::bigint,null::integer)",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert!(!invalid_renew);
    let invalid_finish: String = sqlx::query_scalar(
        "select control.finish_fleet_release_generation_retention(
          null::uuid,null::text,null::uuid,null::uuid,null::bigint,null::text,null::jsonb)",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(invalid_finish, "invalid");

    sqlx::query(
        "update control.route_set_publication_protocol_state
         set normal_ready=true,recovery_ready=true,startup_ready=true,release_ready=true,
             mode='generation_v1',activation_epoch=1,activated_at=now(),updated_at=now()
         where singleton",
    )
    .execute(store.pool())
    .await
    .unwrap();
    let operation = Uuid::new_v4();
    let fleet = Uuid::new_v4();
    let selector = format!("generations/release-{}-maintenance", fleet.simple());
    let expected_intent = json!({"protocol_version":1,"fleet_run_id":fleet,
        "driver_operation_id":operation,"original_global_fence_token":41,
        "overlay_kind":"maintenance","target_slot":"blue"});
    let expected_identity = json!({"protocol_version":1,"fleet_run_id":fleet,
        "driver_operation_id":operation,"original_global_fence_token":41,
        "overlay_kind":"maintenance","route_set_digest":format!("sha256:{}", "a".repeat(64)),
        "target_slot":"blue"});
    let candidate_selector = format!("generations/release-{}-candidate", fleet.simple());
    let candidate_identity = json!({"protocol_version":1,"fleet_run_id":fleet,
        "driver_operation_id":operation,"original_global_fence_token":41,
        "overlay_kind":"candidate","route_set_digest":format!("sha256:{}", "d".repeat(64)),
        "target_slot":"blue"});
    let prior_fleet = Uuid::new_v4();
    let prior_operation = Uuid::new_v4();
    let prior_selector = format!("generations/release-{}-candidate", prior_fleet.simple());
    let prior_identity = json!({"protocol_version":1,"fleet_run_id":prior_fleet,
        "driver_operation_id":prior_operation,"original_global_fence_token":17,
        "overlay_kind":"candidate","route_set_digest":format!("sha256:{}", "e".repeat(64)),
        "target_slot":"green"});
    let mut fixture = store.pool().begin().await.unwrap();
    sqlx::query("set local session_replication_role='replica'")
        .execute(&mut *fixture)
        .await
        .unwrap();
    sqlx::query(
        "insert into control.deployment_driver_operations(
          id,idempotency_key,action,request_digest,state,safe_error)
         values($1,$2,'release',repeat('c',64),'failed','retention-test-fixture')",
    )
    .bind(operation)
    .bind(format!("release-retention-test:{operation}"))
    .execute(&mut *fixture)
    .await
    .unwrap();
    sqlx::query(
        "insert into control.release_fleet_runs(
          id,release_id,operation_id,fleet_generation,state,tenant_snapshot,target_slot)
         values($1,$2,$3,1,'failed','[]','blue')",
    )
    .bind(fleet)
    .bind(format!("retention-test-{fleet}"))
    .bind(Uuid::new_v4())
    .execute(&mut *fixture)
    .await
    .unwrap();
    sqlx::query(
        "insert into control.fleet_release_route_publications(
          driver_operation_id,fleet_run_id,protocol_version,original_instance_owner,
          original_execution_token,original_global_lease_token,original_route_lease_token,
          original_global_fence_token,control_operation_id,control_operation_attempt,
          control_operation_lease_owner,target_slot,snapshot_count,phase,
          prior_selector,prior_directory_device,prior_directory_inode,prior_loaded_identity,
          prior_recorded_at,maintenance_selector,maintenance_count,maintenance_sealed_count,
          maintenance_route_set_digest,maintenance_directory_device,maintenance_directory_inode,
          maintenance_publication_started_at,maintenance_observed_at,external_effects_started_at,
          candidate_selector,candidate_count,candidate_sealed_count,candidate_route_set_digest,
          candidate_directory_device,candidate_directory_inode,candidate_publication_started_at,
          candidate_observed_at)
         values($1,$2,1,$3,$4,$5,$6,41,$7,1,'retention-test','blue',1,
          'awaiting_worker_finalize',$8,31,32,$9,now(),$10,1,1,$11,41,42,now(),now(),now(),
          $12,1,1,$13,51,52,now(),now())",
    )
    .bind(operation)
    .bind(fleet)
    .bind(Uuid::new_v4())
    .bind(Uuid::new_v4())
    .bind(Uuid::new_v4())
    .bind(Uuid::new_v4())
    .bind(Uuid::new_v4())
    .bind(&prior_selector)
    .bind(&prior_identity)
    .bind(&selector)
    .bind(format!("sha256:{}", "a".repeat(64)))
    .bind(&candidate_selector)
    .bind(format!("sha256:{}", "d".repeat(64)))
    .execute(&mut *fixture)
    .await
    .unwrap();
    fixture.commit().await.unwrap();
    sqlx::query(
        "insert into control.fleet_release_route_publication_completions(
          driver_operation_id,fleet_run_id,candidate_selector,candidate_directory_device,
          candidate_directory_inode,candidate_route_set_digest,target_slot,
          original_global_fence_token,stored_response,completed_at)
         values($1,$2,$3,51,52,$4,'blue',41,$5,now()-interval '31 days')",
    )
    .bind(operation)
    .bind(fleet)
    .bind(&candidate_selector)
    .bind(format!("sha256:{}", "d".repeat(64)))
    .bind(json!({"evidence":{}}))
    .execute(store.pool())
    .await
    .unwrap();
    let subjects: Vec<(String, String, i64, i64, Value)> = sqlx::query_as(
        "select overlay_kind,selector,directory_device,directory_inode,expected_identity
         from control.fleet_release_generation_retention_subjects
         where driver_operation_id=$1 order by overlay_kind",
    )
    .bind(operation)
    .fetch_all(store.pool())
    .await
    .unwrap();
    assert_eq!(subjects.len(), 2);
    assert_eq!(
        subjects[0],
        (
            "candidate".into(),
            candidate_selector,
            51,
            52,
            candidate_identity
        )
    );
    assert_eq!(
        subjects[1],
        (
            "maintenance".into(),
            selector.clone(),
            41,
            42,
            expected_identity.clone()
        )
    );
    assert!(
        !sqlx::query_scalar::<_, bool>(
            "select control.fleet_release_generation_retention_eligible($1,'candidate')",
        )
        .bind(operation)
        .fetch_one(store.pool())
        .await
        .unwrap()
    );
    let mut mature = store.pool().begin().await.unwrap();
    sqlx::query("set local session_replication_role='replica'")
        .execute(&mut *mature)
        .await
        .unwrap();
    sqlx::query(
        "update control.fleet_release_generation_retention_subjects
         set authoritative_at=now()-interval '31 days',retention_not_before=now()-interval '1 day'
         where driver_operation_id=$1 and overlay_kind='maintenance'",
    )
    .bind(operation)
    .execute(&mut *mature)
    .await
    .unwrap();
    mature.commit().await.unwrap();
    assert!(
        sqlx::query_scalar::<_, bool>(
            "select control.fleet_release_generation_retention_eligible($1,'maintenance')",
        )
        .bind(operation)
        .fetch_one(store.pool())
        .await
        .unwrap()
    );

    let owner = Uuid::new_v4();
    let token = Uuid::new_v4();
    let acquired: (String, i64, Uuid, String, i64, i64, Value, Value, i32) = sqlx::query_as(
        "select * from control.claim_fleet_release_generation_retention(
              $1,'maintenance',$2,$3,300)",
    )
    .bind(operation)
    .bind(owner)
    .bind(token)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(acquired.0, "acquired");
    assert_eq!(
        (&acquired.2, &acquired.3, acquired.4, acquired.5),
        (&fleet, &selector, 41, 42)
    );
    assert_eq!(
        (&acquired.6, &acquired.7, acquired.8),
        (&expected_intent, &expected_identity, 1)
    );
    let replay: String = sqlx::query_scalar(
        "select outcome from control.claim_fleet_release_generation_retention(
          $1,'maintenance',$2,$3,300)",
    )
    .bind(operation)
    .bind(owner)
    .bind(token)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(replay, "replay");
    let busy: String = sqlx::query_scalar(
        "select outcome from control.claim_fleet_release_generation_retention(
          $1,'maintenance',$2,$3,300)",
    )
    .bind(operation)
    .bind(Uuid::new_v4())
    .bind(Uuid::new_v4())
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(busy, "busy");
    sqlx::query(
        "update control.deployment_driver_resource_leases
         set lease_expires_at=now()-interval '1 second'
         where resource_key='runtime/shared-odoo'",
    )
    .execute(store.pool())
    .await
    .unwrap();
    sqlx::query(
        "update control.fleet_release_generation_retention_claims
         set claim_expires_at=now()-interval '1 second'
         where driver_operation_id=$1 and overlay_kind='maintenance'",
    )
    .bind(operation)
    .execute(store.pool())
    .await
    .unwrap();
    let takeover_owner = Uuid::new_v4();
    let takeover_token = Uuid::new_v4();
    let takeover: (String, i64) = sqlx::query_as(
        "select outcome,claim_fence from control.claim_fleet_release_generation_retention(
          $1,'maintenance',$2,$3,300)",
    )
    .bind(operation)
    .bind(takeover_owner)
    .bind(takeover_token)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(takeover, ("acquired".into(), acquired.1 + 1));
    assert!(
        !sqlx::query_scalar::<_, bool>(
            "select control.renew_fleet_release_generation_retention_claim(
              $1,'maintenance',$2,$3,$4,300)",
        )
        .bind(operation)
        .bind(owner)
        .bind(token)
        .bind(acquired.1)
        .fetch_one(store.pool())
        .await
        .unwrap()
    );
    let current_fleet = Uuid::new_v4();
    let current_operation = Uuid::new_v4();
    let current_selector = format!("generations/release-{}-candidate", current_fleet.simple());
    let current_identity = json!({"protocol_version":1,"fleet_run_id":current_fleet,
        "driver_operation_id":current_operation,"original_global_fence_token":73,
        "overlay_kind":"candidate","route_set_digest":format!("sha256:{}", "b".repeat(64)),
        "target_slot":"green"});
    let evidence = json!({"protocol_version":1,"driver_operation_id":operation,
        "overlay_kind":"maintenance","claim_fence":takeover.1,"resolution":"already_absent",
        "selector":selector,"expected_intent":expected_intent,"expected_identity":expected_identity,
        "observed_current_selector":current_selector,"observed_current_identity":current_identity,
        "target_present":false,"observed_target_device":null,"observed_target_inode":null,
        "mismatch_kind":null,"observed_target_identity":null});
    let mut mismatched_evidence = evidence.clone();
    mismatched_evidence["selector"] = json!("generations/foreign");
    let evidence_mismatch: String = sqlx::query_scalar(
        "select control.finish_fleet_release_generation_retention(
          $1,'maintenance',$2,$3,$4,'already_absent',$5)",
    )
    .bind(operation)
    .bind(takeover_owner)
    .bind(takeover_token)
    .bind(takeover.1)
    .bind(mismatched_evidence)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(evidence_mismatch, "evidence_mismatch");
    let finished: String = sqlx::query_scalar(
        "select control.finish_fleet_release_generation_retention(
          $1,'maintenance',$2,$3,$4,'already_absent',$5)",
    )
    .bind(operation)
    .bind(takeover_owner)
    .bind(takeover_token)
    .bind(takeover.1)
    .bind(&evidence)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(finished, "already_absent");
    let terminal_replay: String = sqlx::query_scalar(
        "select control.finish_fleet_release_generation_retention(
          $1,'maintenance',$2,$3,$4,'already_absent',$5)",
    )
    .bind(operation)
    .bind(takeover_owner)
    .bind(takeover_token)
    .bind(takeover.1)
    .bind(&evidence)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(terminal_replay, "replay");
    let conflict: String = sqlx::query_scalar(
        "select control.finish_fleet_release_generation_retention(
          $1,'maintenance',$2,$3,$4,'deleted',$5)",
    )
    .bind(operation)
    .bind(takeover_owner)
    .bind(takeover_token)
    .bind(takeover.1)
    .bind(&evidence)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(conflict, "conflict");
    let immutable = sqlx::query(
        "update control.fleet_release_generation_retention_attempts
         set resolution='deleted' where driver_operation_id=$1",
    )
    .bind(operation)
    .execute(store.pool())
    .await
    .unwrap_err();
    assert_eq!(
        immutable.as_database_error().unwrap().code().as_deref(),
        Some("55000")
    );
    let global: (String, Option<String>, Option<Uuid>) = sqlx::query_as(
        "select state,authority_kind,driver_operation_id
         from control.deployment_driver_resource_leases
         where resource_key='runtime/shared-odoo'",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(global, ("idle".into(), None, None));
    assert!(
        !sqlx::query_scalar::<_, bool>(
            "select control.fleet_release_generation_retention_eligible($1,'maintenance')",
        )
        .bind(operation)
        .fetch_one(store.pool())
        .await
        .unwrap()
    );

    let acl: (bool, bool, bool, bool, bool) = sqlx::query_as(
        "select
          has_function_privilege('control_driver_ledger',
           'control.discover_fleet_release_generation_retention_candidates(uuid,text,integer)','execute'),
          has_function_privilege('control_driver_ledger',
           'control.claim_fleet_release_generation_retention(uuid,text,uuid,uuid,integer)','execute'),
          has_function_privilege('control_driver_ledger',
           'control.finish_fleet_release_generation_retention(uuid,text,uuid,uuid,bigint,text,jsonb)','execute'),
          has_table_privilege('control_driver_ledger',
           'control.fleet_release_generation_retention_subjects','select,insert,update,delete'),
          has_function_privilege('control_release_worker',
           'control.claim_fleet_release_generation_retention(uuid,text,uuid,uuid,integer)','execute')",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(acl, (true, true, true, false, false));

    store.pool().close().await;
    drop_database(&admin, &database).await;
    drop_runtime_roles(&admin).await;
}

#[tokio::test]
#[ignore = "requires a PostgreSQL 17 CONTROL_TEST_ADMIN_URL with CREATEDB"]
async fn route_set_publication_admission_is_dormant_and_function_only() {
    let admin_url = std::env::var("CONTROL_TEST_ADMIN_URL").expect("CONTROL_TEST_ADMIN_URL");
    let database = format!("control_route_set_gate_{}", Uuid::new_v4().simple());
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&admin_url)
        .await
        .unwrap();
    create_runtime_roles(&admin).await;
    sqlx::query(AssertSqlSafe(format!("create database \"{database}\"")))
        .execute(&admin)
        .await
        .unwrap();
    let store = Store::connect(&database_url(&admin_url, &database))
        .await
        .unwrap();
    store.migrate().await.unwrap();
    let gate: (String, bool, bool, bool, bool) = sqlx::query_as(
        "select mode,normal_ready,recovery_ready,startup_ready,release_ready
         from control.route_set_publication_protocol_state where singleton",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(gate, ("flat_v1".into(), false, false, false, false));

    let dormant_maintenance_reader: String = sqlx::query_scalar(
        "select outcome from control.read_route_set_recovery_maintenance_admission(
          gen_random_uuid(),gen_random_uuid(),1,'fixture','reader-key',repeat('a',64))",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(dormant_maintenance_reader, "protocol_inactive");
    let dormant_restore_reader: String = sqlx::query_scalar(
        "select outcome from control.read_route_set_recovery_restore_admission(
          gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),1,'fixture')",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(dormant_restore_reader, "protocol_inactive");
    let absent_recovery_result: String = sqlx::query_scalar(
        "select outcome from control.read_route_set_recovery_publication_result(
          gen_random_uuid(),gen_random_uuid(),gen_random_uuid())",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(absent_recovery_result, "absent");

    let workshop_id = Uuid::new_v4();
    let operation_id = Uuid::new_v4();
    sqlx::query(
        "insert into control.workshops(id,slug,display_name,time_zone)
         values($1,$2,'Route set gate','UTC')",
    )
    .bind(workshop_id)
    .bind(format!("route-set-{}", workshop_id.simple()))
    .execute(store.pool())
    .await
    .unwrap();
    sqlx::query(
        "insert into control.operations(id,kind,queue,workshop_id,payload,correlation_id,
           idempotency_key,state,attempt,leased_by,lease_expires_at)
         values($1,'tenant.reconcile','tenant-reconciliation',$2,'{}',$3,'route-set-gate',
           'in_flight',1,'fixture',now()+interval '10 minutes')",
    )
    .bind(operation_id)
    .bind(workshop_id)
    .bind(Uuid::new_v4())
    .execute(store.pool())
    .await
    .unwrap();
    let outcome: String = sqlx::query_scalar(
        "select outcome from control.admit_route_set_publication(
          $1,1,'fixture',$2,'projection','route-set-gate-driver',repeat('a',64),
          1,'sha256:'||repeat('b',64),$3,$4,$5,$6,300)",
    )
    .bind(operation_id)
    .bind(workshop_id)
    .bind(Uuid::new_v4())
    .bind(Uuid::new_v4())
    .bind(Uuid::new_v4())
    .bind(Uuid::new_v4())
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(outcome, "protocol_inactive");
    let publications: i64 =
        sqlx::query_scalar("select count(*) from control.workshop_route_set_publications")
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert_eq!(publications, 0);

    let acl: (bool, bool, bool, bool, bool, bool) = sqlx::query_as(
        "select
          has_table_privilege('control_driver_ledger','control.workshop_route_set_publications','select'),
          has_function_privilege('control_driver_ledger',
            'control.admit_route_set_publication(uuid,integer,text,uuid,text,text,text,bigint,text,uuid,uuid,uuid,uuid,integer)','execute'),
          has_function_privilege('control_driver_ledger',
            'control.route_set_publication_digest(uuid)','execute'),
          has_function_privilege('control_driver_ledger',
            'control.guard_route_set_fleet_membership()','execute'),
          has_function_privilege('control_driver_ledger',
            'control.record_route_set_publication_prior(uuid,uuid,uuid,uuid,uuid,bigint,bigint,text,bigint,bigint,jsonb)','execute'),
          has_function_privilege('control_driver_ledger',
            'control.valid_route_set_loaded_identity(jsonb)','execute')",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(acl, (false, true, false, false, true, false));
    let closed_acl_violations: i64 = sqlx::query_scalar(
        "select count(*) from unnest(array[
          'control_api','control_tenant_api','control_membership_worker',
          'control_provisioning_worker','control_invoice_worker','control_inventory_worker',
          'control_email_worker','control_reconciliation_worker','control_lifecycle_worker',
          'control_backup_scheduler','control_driver_ledger','control_release_worker',
          'control_privacy_worker']) role_name
         where has_table_privilege(role_name,'control.workshop_route_set_publications','select,insert,update,delete')
            or has_table_privilege(role_name,'control.workshop_route_set_publication_resolutions','select,insert,update,delete')
            or has_function_privilege(role_name,'control.guard_route_set_fleet_membership()','execute')
            or has_function_privilege(role_name,'control.valid_route_set_loaded_identity(jsonb)','execute')
            or has_function_privilege(role_name,'control.validate_route_set_publication_phase_transition()','execute')
            or has_function_privilege(role_name,'control.validate_route_set_recovery_eligibility()','execute')
            or has_function_privilege(role_name,'control.validate_route_set_recovery_terminal_evidence()','execute')
            or has_function_privilege(role_name,'control.reject_route_set_resolution_mutation()','execute')
            or has_function_privilege(role_name,
              'control.lock_interrupted_route_set_publication_claim(uuid,uuid,uuid,bigint)','execute')",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(closed_acl_violations, 0);

    let transition_acl_violations: i64 = sqlx::query_scalar(
        "select count(*)
         from unnest(array[
           'control_api','control_tenant_api','control_membership_worker',
           'control_provisioning_worker','control_invoice_worker','control_inventory_worker',
           'control_email_worker','control_reconciliation_worker','control_lifecycle_worker',
           'control_backup_scheduler','control_driver_ledger','control_release_worker',
           'control_privacy_worker']) role_name
         cross join unnest(array[
           'control.record_route_set_publication_prior(uuid,uuid,uuid,uuid,uuid,bigint,bigint,text,bigint,bigint,jsonb)',
           'control.record_route_set_publication_entry(uuid,uuid,uuid,uuid,uuid,bigint,bigint,uuid,bigint,text,text,text,text)',
           'control.seal_route_set_publication(uuid,uuid,uuid,uuid,uuid,bigint,bigint,text,bigint,bigint,integer,integer,text)',
           'control.start_route_set_publication(uuid,uuid,uuid,uuid,uuid,bigint,bigint)',
           'control.observe_route_set_publication(uuid,uuid,uuid,uuid,uuid,bigint,bigint,text,bigint,bigint,jsonb)',
           'control.quarantine_route_set_publication(uuid,uuid,uuid,uuid,uuid,bigint,bigint,text)',
           'control.finish_route_set_publication(uuid,uuid,uuid,uuid,uuid,bigint,bigint)',
           'control.read_route_set_publication_result(uuid,uuid,text,text)',
           'control.discover_interrupted_route_set_publications(uuid,integer)',
           'control.claim_interrupted_route_set_publication(uuid,uuid,integer,text,uuid,uuid,integer)',
           'control.renew_interrupted_route_set_publication_claim(uuid,uuid,uuid,bigint,integer)',
           'control.read_interrupted_route_set_publication_state(uuid,uuid,uuid,bigint)',
           'control.resolve_interrupted_route_set_publication_observation(uuid,uuid,uuid,bigint,text,text,bigint,bigint,jsonb)',
           'control.finish_route_set_publication_recovery(uuid,bigint,uuid,integer,text,uuid,uuid,text,text,text)'
         ]) function_name
         where has_function_privilege(role_name,function_name,'execute')
           is distinct from (role_name='control_driver_ledger')",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(transition_acl_violations, 0);
    let recovery_public_acl: i64 = sqlx::query_scalar(
        "select count(*) from unnest(array[
          'control.admit_route_set_recovery_maintenance(uuid,integer,text,uuid,text,text,text,uuid,uuid,uuid,uuid,integer)',
          'control.admit_route_set_recovery_restore(uuid,uuid,uuid,integer,text,uuid,uuid,uuid,uuid,integer)',
          'control.read_route_set_recovery_maintenance_admission(uuid,uuid,integer,text,text,text)',
          'control.read_route_set_recovery_restore_admission(uuid,uuid,uuid,integer,text)',
          'control.finish_route_set_recovery_publication(uuid,uuid,uuid,uuid,uuid,bigint,bigint)',
          'control.read_route_set_recovery_publication_result(uuid,uuid,uuid)'
         ]) function_name
         where has_function_privilege('control_driver_ledger',function_name,'execute')
          and not has_function_privilege('control_api',function_name,'execute')
          and not has_function_privilege('public',function_name,'execute')",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(recovery_public_acl, 6);

    let prior_effect_run = Uuid::new_v4();
    let prior_fleet_run = Uuid::new_v4();
    let prior_driver_operation = Uuid::new_v4();
    let prior_publication = Uuid::new_v4();
    let startup_identity = json!({
        "effect_run_id": prior_effect_run,
        "sealed_digest": format!("sha256:{}", "1".repeat(64)),
    });
    let release_identity = json!({
        "protocol_version": 1,
        "fleet_run_id": prior_fleet_run,
        "driver_operation_id": prior_driver_operation,
        "original_global_fence_token": 7,
        "overlay_kind": "maintenance",
        "route_set_digest": format!("sha256:{}", "2".repeat(64)),
        "target_slot": "blue",
    });
    let mut release_candidate_identity = release_identity.clone();
    release_candidate_identity["overlay_kind"] = json!("candidate");
    release_candidate_identity["target_slot"] = json!("green");
    for (kind, suffix) in [
        ("projection", "projection"),
        ("recovery_maintenance", "recovery-maintenance"),
        ("recovery_restore", "recovery-restore"),
    ] {
        let identity = json!({
            "protocol_version": 1,
            "publication_id": prior_publication,
            "publication_kind": kind,
            "global_fence_token": 8,
            "target_workshop_id": workshop_id,
            "target_route_fence_token": 9,
            "route_set_digest": format!("sha256:{}", "3".repeat(64)),
        });
        let selector = format!("generations/route-{}-{suffix}", prior_publication.simple());
        let accepted: bool =
            sqlx::query_scalar("select control.valid_route_set_prior_selector_identity($1,$2)")
                .bind(&selector)
                .bind(&identity)
                .fetch_one(store.pool())
                .await
                .unwrap();
        assert!(accepted, "universal prior identity must accept {kind}");
        let rejected: bool =
            sqlx::query_scalar("select control.valid_route_set_prior_selector_identity($1,$2)")
                .bind(format!("{selector}-mismatch"))
                .bind(identity)
                .fetch_one(store.pool())
                .await
                .unwrap();
        assert!(
            !rejected,
            "universal prior selector must bind {kind} exactly"
        );
    }
    for (selector, identity, expected) in [
        ("generations/boot-live".to_owned(), None, true),
        (
            format!("generations/startup-{prior_effect_run}"),
            Some(startup_identity.clone()),
            true,
        ),
        (
            format!("generations/startup-{}", prior_effect_run.simple()),
            Some(startup_identity),
            false,
        ),
        (
            format!(
                "generations/release-{}-maintenance",
                prior_fleet_run.simple()
            ),
            Some(release_identity.clone()),
            true,
        ),
        (
            format!("generations/release-{}-candidate", prior_fleet_run.simple()),
            Some(release_candidate_identity.clone()),
            true,
        ),
        (
            format!(
                "generations/release-{}-maintenance",
                prior_fleet_run.simple()
            ),
            Some(release_candidate_identity),
            false,
        ),
        (
            format!("generations/release-{prior_fleet_run}-maintenance"),
            Some(release_identity),
            false,
        ),
        (
            "generations/boot-live".to_owned(),
            Some(json!({
                "effect_run_id": prior_effect_run,
                "sealed_digest": format!("sha256:{}", "4".repeat(64)),
            })),
            false,
        ),
    ] {
        let accepted: bool =
            sqlx::query_scalar("select control.valid_route_set_prior_selector_identity($1,$2)")
                .bind(selector)
                .bind(identity)
                .fetch_one(store.pool())
                .await
                .unwrap();
        assert_eq!(accepted, expected);
    }

    let vector_workshop = Uuid::parse_str("00112233-4455-6677-8899-aabbccddeeff").unwrap();
    let fields = [
        "sha256:projection",
        "present",
        "sha256:applied-rendered",
        "sha256:rendered",
    ];
    let sql_record: Vec<u8> =
        sqlx::query_scalar("select control.route_set_publication_record_bytes($1,42,$2,$3,$4,$5)")
            .bind(vector_workshop)
            .bind(fields[0])
            .bind(fields[1])
            .bind(fields[2])
            .bind(fields[3])
            .fetch_one(store.pool())
            .await
            .unwrap();
    let mut rust_record = Vec::new();
    rust_record.extend_from_slice(vector_workshop.as_bytes());
    rust_record.extend_from_slice(&42_i64.to_be_bytes());
    for field in fields {
        rust_record.extend_from_slice(&u32::try_from(field.len()).unwrap().to_be_bytes());
        rust_record.extend_from_slice(field.as_bytes());
    }
    assert_eq!(sql_record, rust_record);
    let sql_digest: String = sqlx::query_scalar(
        "select encode(public.digest(convert_to('mb-route-set-publication-v1','UTF8')
          ||decode('00','hex')||$1,'sha256'),'hex')",
    )
    .bind(&rust_record)
    .fetch_one(store.pool())
    .await
    .unwrap();
    let mut rust_digest_input = b"mb-route-set-publication-v1\0".to_vec();
    rust_digest_input.extend_from_slice(&rust_record);
    assert_eq!(
        sql_digest,
        format!("{:x}", Sha256::digest(rust_digest_input))
    );

    let result_before_admission: (String, Option<Uuid>, Option<Uuid>, Option<Value>) =
        sqlx::query_as(
            "select outcome,publication_id,driver_operation_id,response
             from control.read_route_set_publication_result($1,$2,$3,$4)",
        )
        .bind(operation_id)
        .bind(workshop_id)
        .bind("route-set-generation-two")
        .bind("9".repeat(64))
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(result_before_admission, ("absent".into(), None, None, None));

    // Test-only activation proves the acquired branch without exposing an
    // activation API or changing the production-default dormant gate.
    sqlx::query(
        "update control.route_set_publication_protocol_state
         set normal_ready=true,recovery_ready=true,startup_ready=true,release_ready=true,
             mode='generation_v1',activation_epoch=1,activated_at=now(),updated_at=now()
         where singleton",
    )
    .execute(store.pool())
    .await
    .unwrap();
    let other_workshop = Uuid::new_v4();
    let other_operation = Uuid::new_v4();
    sqlx::query(
        "insert into control.workshops(id,slug,display_name,time_zone)
         values($1,$2,'Other route set','UTC')",
    )
    .bind(other_workshop)
    .bind(format!("route-set-{}", other_workshop.simple()))
    .execute(store.pool())
    .await
    .unwrap();
    sqlx::query(
        "insert into control.operations(id,kind,queue,workshop_id,payload,correlation_id,
           idempotency_key,state,attempt,leased_by,lease_expires_at)
         values($1,'tenant.reconcile','tenant-reconciliation',$2,'{}',$3,'route-set-other',
           'in_flight',1,'fixture',now()+interval '10 minutes')",
    )
    .bind(other_operation)
    .bind(other_workshop)
    .bind(Uuid::new_v4())
    .execute(store.pool())
    .await
    .unwrap();
    let target_applied = format!("sha256:{}", "1".repeat(64));
    let target_desired = format!("sha256:{}", "2".repeat(64));
    let other_applied = format!("sha256:{}", "3".repeat(64));
    let other_desired = format!("sha256:{}", "4".repeat(64));
    for (source_operation, source_workshop, generation, digest, marker, disposition) in [
        (
            operation_id,
            workshop_id,
            1_i64,
            &target_applied,
            "target-old",
            "present",
        ),
        (
            operation_id,
            workshop_id,
            2_i64,
            &target_desired,
            "target-new",
            "absent",
        ),
        (
            other_operation,
            other_workshop,
            1_i64,
            &other_applied,
            "other-old",
            "present",
        ),
        (
            other_operation,
            other_workshop,
            2_i64,
            &other_desired,
            "other-queued",
            "present",
        ),
    ] {
        sqlx::query(
            "insert into control.workshop_route_projections(
               workshop_id,generation,projection_digest,projection,source_operation_id,
               source_operation_attempt,disposition)
             values($1,$2,$3,jsonb_build_object('marker',$4),$5,1,$6)",
        )
        .bind(source_workshop)
        .bind(generation)
        .bind(digest)
        .bind(marker)
        .bind(source_operation)
        .bind(disposition)
        .execute(store.pool())
        .await
        .unwrap();
    }
    let target_previous_driver: Uuid = sqlx::query_scalar(
        "insert into control.deployment_driver_operations(
           idempotency_key,workshop_id,action,request_digest,state,response,target_key,
           route_generation,route_projection_digest,route_fence_token)
         values('route-set-target-old',$1,'route-project',repeat('5',64),'succeeded','{}',
           'route/'||$1::text,1,$2,1) returning id",
    )
    .bind(workshop_id)
    .bind(&target_applied)
    .fetch_one(store.pool())
    .await
    .unwrap();
    let other_previous_driver: Uuid = sqlx::query_scalar(
        "insert into control.deployment_driver_operations(
           idempotency_key,workshop_id,action,request_digest,state,response,target_key,
           route_generation,route_projection_digest,route_fence_token)
         values('route-set-other-old',$1,'route-project',repeat('6',64),'succeeded','{}',
           'route/'||$1::text,1,$2,1) returning id",
    )
    .bind(other_workshop)
    .bind(&other_applied)
    .fetch_one(store.pool())
    .await
    .unwrap();
    sqlx::query(
        "update control.workshop_route_projection_state set
           desired_generation=2,desired_digest=$2,desired_disposition='absent',
           applied_generation=1,applied_digest=$3,applied_disposition='present',
           applied_rendered_digest=$4,applied_driver_operation_id=$5,applied_fence_token=1
         where workshop_id=$1",
    )
    .bind(workshop_id)
    .bind(&target_desired)
    .bind(&target_applied)
    .bind(format!("sha256:{}", "7".repeat(64)))
    .bind(target_previous_driver)
    .execute(store.pool())
    .await
    .unwrap();
    sqlx::query(
        "update control.workshop_route_projection_state set
           desired_generation=2,desired_digest=$2,desired_disposition='present',
           applied_generation=1,applied_digest=$3,applied_disposition='present',
           applied_rendered_digest=$4,applied_driver_operation_id=$5,applied_fence_token=1
         where workshop_id=$1",
    )
    .bind(other_workshop)
    .bind(&other_desired)
    .bind(&other_applied)
    .bind(format!("sha256:{}", "8".repeat(64)))
    .bind(other_previous_driver)
    .execute(store.pool())
    .await
    .unwrap();

    let instance_owner = Uuid::new_v4();
    let execution_token = Uuid::new_v4();
    let global_token = Uuid::new_v4();
    let route_token = Uuid::new_v4();
    let phantom_workshop = Uuid::new_v4();
    let mut membership_transaction = store.pool().begin().await.unwrap();
    sqlx::query(
        "insert into control.workshops(id,slug,display_name,time_zone)
         values($1,$2,'Rolled back route set member','UTC')",
    )
    .bind(phantom_workshop)
    .bind(format!("route-set-{}", phantom_workshop.simple()))
    .execute(&mut *membership_transaction)
    .await
    .unwrap();
    let admission_pool = store.pool().clone();
    let admission_target_digest = target_desired.clone();
    let admission = tokio::spawn(async move {
        sqlx::query_as::<_, (String, Uuid, Uuid, i64, i64, String, i32)>(
            "select outcome,publication_id,driver_operation_id,global_fence_token,
               target_route_fence_token,selector,snapshot_count
             from control.admit_route_set_publication(
              $1,1,'fixture',$2,'projection','route-set-generation-two',repeat('9',64),
              2,$3,$4,$5,$6,$7,300)",
        )
        .bind(operation_id)
        .bind(workshop_id)
        .bind(admission_target_digest)
        .bind(instance_owner)
        .bind(execution_token)
        .bind(global_token)
        .bind(route_token)
        .fetch_one(&admission_pool)
        .await
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert!(
        !admission.is_finished(),
        "admission must wait behind an earlier fleet-membership transaction"
    );
    membership_transaction.rollback().await.unwrap();
    let acquired = admission.await.unwrap().unwrap();
    assert_eq!(acquired.0, "acquired");
    assert_eq!(acquired.6, 2);
    assert!(acquired.3 > 0 && acquired.4 > 1);

    let null_authority_is_rejected: bool = sqlx::query_scalar(
        "with authority as (
           select $1::uuid publication_id,$2::uuid instance_owner,$3::uuid execution_token,
                  $4::uuid global_token,$5::uuid route_token,$6::bigint global_fence,
                  $7::bigint route_fence
         )
         select bool_and(outcome is false)
         from authority cross join lateral (values
           (control.quarantine_route_set_publication(publication_id,null,execution_token,
             global_token,route_token,global_fence,route_fence,
             'route_set_publication_outcome_unknown')),
           (control.quarantine_route_set_publication(publication_id,instance_owner,null,
             global_token,route_token,global_fence,route_fence,
             'route_set_publication_outcome_unknown')),
           (control.quarantine_route_set_publication(publication_id,instance_owner,execution_token,
             null,route_token,global_fence,route_fence,
             'route_set_publication_outcome_unknown')),
           (control.quarantine_route_set_publication(publication_id,instance_owner,execution_token,
             global_token,null,global_fence,route_fence,
             'route_set_publication_outcome_unknown')),
           (control.quarantine_route_set_publication(publication_id,instance_owner,execution_token,
             global_token,route_token,null,route_fence,
             'route_set_publication_outcome_unknown')),
           (control.quarantine_route_set_publication(publication_id,instance_owner,execution_token,
             global_token,route_token,global_fence,null,
             'route_set_publication_outcome_unknown'))
         ) attempts(outcome)",
    )
    .bind(acquired.1)
    .bind(instance_owner)
    .bind(execution_token)
    .bind(global_token)
    .bind(route_token)
    .bind(acquired.3)
    .bind(acquired.4)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert!(null_authority_is_rejected);

    let recovery_operation = Uuid::new_v4();
    sqlx::query(
        "insert into control.operations(id,kind,queue,workshop_id,payload,correlation_id,
           idempotency_key,state,attempt,leased_by,lease_expires_at)
         values($1,'tenant.reconcile','tenant-reconciliation',$2,$3,$4,$5,
           'in_flight',1,'recovery-fixture',now()+interval '10 minutes')",
    )
    .bind(recovery_operation)
    .bind(workshop_id)
    .bind(json!({"route_set_publication_id": acquired.1, "protocol_version": 1}))
    .bind(Uuid::new_v4())
    .bind(format!("route-set-recovery-{}", acquired.1))
    .execute(store.pool())
    .await
    .unwrap();
    let recovery_owner = Uuid::new_v4();
    let recovery_token = Uuid::new_v4();
    let live_claim: String = sqlx::query_scalar(
        "select outcome from control.claim_interrupted_route_set_publication(
          $1,$2,1,'recovery-fixture',$3,$4,300)",
    )
    .bind(acquired.1)
    .bind(recovery_operation)
    .bind(recovery_owner)
    .bind(recovery_token)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(live_claim, "not_expired");

    for expiry_sql in [
        "update control.operations set lease_expires_at=now()-interval '1 second' where id=$1",
        "update control.deployment_driver_operations set lease_expires_at=now()-interval '1 second' where id=$1",
        "update control.deployment_driver_resource_leases set lease_expires_at=now()-interval '1 second' where resource_key='runtime/shared-odoo'",
        "update control.workshop_route_application_leases set lease_expires_at=now()-interval '1 second' where workshop_id=$1",
    ] {
        let mut probe = store.pool().begin().await.unwrap();
        let mut query = sqlx::query(expiry_sql);
        if expiry_sql.contains("control.operations ") {
            query = query.bind(operation_id);
        } else if expiry_sql.contains("deployment_driver_operations") {
            query = query.bind(acquired.2);
        } else if expiry_sql.contains("workshop_route_application_leases") {
            query = query.bind(workshop_id);
        }
        query.execute(&mut *probe).await.unwrap();
        let outcome: String = sqlx::query_scalar(
            "select outcome from control.claim_interrupted_route_set_publication(
              $1,$2,1,'recovery-fixture',$3,$4,300)",
        )
        .bind(acquired.1)
        .bind(recovery_operation)
        .bind(recovery_owner)
        .bind(recovery_token)
        .fetch_one(&mut *probe)
        .await
        .unwrap();
        assert_eq!(outcome, "not_expired", "all four leases must be expired");
        probe.rollback().await.unwrap();
    }

    for drift_sql in [
        "update control.operations set queue='tenant-lifecycle' where id=$1",
        "update control.deployment_driver_operations set control_operation_attempt=control_operation_attempt+1 where id=$1",
        "update control.deployment_driver_resource_leases set fence_token=fence_token+1 where resource_key='runtime/shared-odoo'",
        "update control.workshop_route_application_leases set generation=generation+1 where workshop_id=$1",
    ] {
        let mut probe = store.pool().begin().await.unwrap();
        sqlx::query(
            "with upstream as (
               update control.operations set lease_expires_at=now()-interval '1 second' where id=$1
             ), driver as (
               update control.deployment_driver_operations set lease_expires_at=now()-interval '1 second' where id=$2
             ), global_lease as (
               update control.deployment_driver_resource_leases set lease_expires_at=now()-interval '1 second'
               where resource_key='runtime/shared-odoo'
             )
             update control.workshop_route_application_leases
             set lease_expires_at=now()-interval '1 second' where workshop_id=$3",
        )
        .bind(operation_id)
        .bind(acquired.2)
        .bind(workshop_id)
        .execute(&mut *probe)
        .await
        .unwrap();
        sqlx::query("set local session_replication_role=replica")
            .execute(&mut *probe)
            .await
            .unwrap();
        let mut query = sqlx::query(drift_sql);
        if drift_sql.contains("control.operations ") {
            query = query.bind(operation_id);
        } else if drift_sql.contains("deployment_driver_operations") {
            query = query.bind(acquired.2);
        } else if drift_sql.contains("workshop_route_application_leases") {
            query = query.bind(workshop_id);
        }
        query.execute(&mut *probe).await.unwrap();
        sqlx::query("set local session_replication_role=origin")
            .execute(&mut *probe)
            .await
            .unwrap();
        let outcome: String = sqlx::query_scalar(
            "select outcome from control.claim_interrupted_route_set_publication(
              $1,$2,1,'recovery-fixture',$3,$4,300)",
        )
        .bind(acquired.1)
        .bind(recovery_operation)
        .bind(recovery_owner)
        .bind(recovery_token)
        .fetch_one(&mut *probe)
        .await
        .unwrap();
        assert_eq!(outcome, "authority_inconsistent", "{drift_sql}");
        probe.rollback().await.unwrap();
    }

    sqlx::query(
        "with upstream as (
           update control.operations set lease_expires_at=now()-interval '1 second' where id=$1
         ), driver as (
           update control.deployment_driver_operations set lease_expires_at=now()-interval '1 second' where id=$2
         ), global_lease as (
           update control.deployment_driver_resource_leases set lease_expires_at=now()-interval '1 second'
           where resource_key='runtime/shared-odoo'
         )
         update control.workshop_route_application_leases
         set lease_expires_at=now()-interval '1 second' where workshop_id=$3",
    )
    .bind(operation_id)
    .bind(acquired.2)
    .bind(workshop_id)
    .execute(store.pool())
    .await
    .unwrap();
    let mut winning_claim = store.pool().begin().await.unwrap();
    let winner: String = sqlx::query_scalar(
        "select outcome from control.claim_interrupted_route_set_publication(
          $1,$2,1,'recovery-fixture',$3,$4,300)",
    )
    .bind(acquired.1)
    .bind(recovery_operation)
    .bind(recovery_owner)
    .bind(recovery_token)
    .fetch_one(&mut *winning_claim)
    .await
    .unwrap();
    assert_eq!(winner, "acquired");
    let claimant_pool = store.pool().clone();
    let competing_owner = Uuid::new_v4();
    let competing_token = Uuid::new_v4();
    let competing_claim = tokio::spawn(async move {
        let mut transaction = claimant_pool.begin().await.unwrap();
        sqlx::query(
            "select set_config('lock_timeout','5s',true),
                    set_config('statement_timeout','8s',true)",
        )
        .execute(&mut *transaction)
        .await
        .unwrap();
        let outcome: String = sqlx::query_scalar(
            "select outcome from control.claim_interrupted_route_set_publication(
              $1,$2,1,'recovery-fixture',$3,$4,300)",
        )
        .bind(acquired.1)
        .bind(recovery_operation)
        .bind(competing_owner)
        .bind(competing_token)
        .fetch_one(&mut *transaction)
        .await
        .unwrap();
        transaction.rollback().await.unwrap();
        outcome
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert!(!competing_claim.is_finished());
    winning_claim.rollback().await.unwrap();
    let competing_outcome =
        tokio::time::timeout(std::time::Duration::from_secs(10), competing_claim)
            .await
            .expect("interrupted route-set claimers must not deadlock")
            .unwrap();
    assert_eq!(competing_outcome, "acquired");

    let mut expiry_probe = store.pool().begin().await.unwrap();
    sqlx::query(
        "with upstream as (
           update control.operations set lease_expires_at=now()-interval '1 second' where id=$1
         ), driver as (
           update control.deployment_driver_operations set lease_expires_at=now()-interval '1 second' where id=$2
         ), global_lease as (
           update control.deployment_driver_resource_leases set lease_expires_at=now()-interval '1 second'
           where resource_key='runtime/shared-odoo'
         )
         update control.workshop_route_application_leases
         set lease_expires_at=now()-interval '1 second' where workshop_id=$3",
    )
    .bind(operation_id)
    .bind(acquired.2)
    .bind(workshop_id)
    .execute(&mut *expiry_probe)
    .await
    .unwrap();
    let claimed: (String, Option<i64>, Option<String>) = sqlx::query_as(
        "select outcome,claim_fence,claim_mode
         from control.claim_interrupted_route_set_publication(
          $1,$2,1,'recovery-fixture',$3,$4,300)",
    )
    .bind(acquired.1)
    .bind(recovery_operation)
    .bind(recovery_owner)
    .bind(recovery_token)
    .fetch_one(&mut *expiry_probe)
    .await
    .unwrap();
    assert_eq!(
        claimed,
        ("acquired".into(), Some(1), Some("write_cleanup".into()))
    );
    let discovered: (Uuid, String, bool) = sqlx::query_as(
        "select publication_id,claim_mode,claim_available
         from control.discover_interrupted_route_set_publications(null,100)
         where publication_id=$1",
    )
    .bind(acquired.1)
    .fetch_one(&mut *expiry_probe)
    .await
    .unwrap();
    assert_eq!(discovered, (acquired.1, "write_cleanup".into(), false));
    let interrupted: (String, String, bool) = sqlx::query_as(
        "select phase,interrupted_phase,recovery_eligible_at is not null
         from control.workshop_route_set_publications where publication_id=$1",
    )
    .bind(acquired.1)
    .fetch_one(&mut *expiry_probe)
    .await
    .unwrap();
    assert_eq!(interrupted, ("quarantined".into(), "staging".into(), true));
    let claim_replay: String = sqlx::query_scalar(
        "select outcome from control.claim_interrupted_route_set_publication(
          $1,$2,1,'recovery-fixture',$3,$4,300)",
    )
    .bind(acquired.1)
    .bind(recovery_operation)
    .bind(recovery_owner)
    .bind(recovery_token)
    .fetch_one(&mut *expiry_probe)
    .await
    .unwrap();
    assert_eq!(claim_replay, "replay");
    let claimed_state: (String, Option<Value>) = sqlx::query_as(
        "select outcome,state from control.read_interrupted_route_set_publication_state(
          $1,$2,$3,1)",
    )
    .bind(acquired.1)
    .bind(recovery_owner)
    .bind(recovery_token)
    .fetch_one(&mut *expiry_probe)
    .await
    .unwrap();
    assert_eq!(claimed_state.0, "claimed");
    assert_eq!(
        claimed_state.1.as_ref().unwrap()["claim_mode"],
        "write_cleanup"
    );
    let claimed_state = claimed_state.1.unwrap();
    assert_eq!(claimed_state.as_object().unwrap().len(), 27);
    assert!(claimed_state["recovery_effect_run_id"].is_null());
    assert_eq!(claimed_state["protocol_version"], 1);
    assert_eq!(claimed_state["original_global_fence_token"], acquired.3);
    assert_eq!(claimed_state["target_route_fence_token"], acquired.4);
    assert_eq!(claimed_state["target_generation"], 2);
    assert_eq!(claimed_state["target_projection_digest"], target_desired);
    assert_eq!(claimed_state["target_disposition"], "absent");
    assert!(claimed_state["sealed_count"].is_null());
    assert!(claimed_state["sealed_present_count"].is_null());
    let renewed_claim: String = sqlx::query_scalar(
        "select control.renew_interrupted_route_set_publication_claim($1,$2,$3,1,300)",
    )
    .bind(acquired.1)
    .bind(recovery_owner)
    .bind(recovery_token)
    .fetch_one(&mut *expiry_probe)
    .await
    .unwrap();
    assert_eq!(renewed_claim, "renewed");
    let unstarted: (String, Option<Value>) = sqlx::query_as(
        "select outcome,evidence from control.resolve_interrupted_route_set_publication_observation(
          $1,$2,$3,1,'unstarted',null,null,null,null)",
    )
    .bind(acquired.1)
    .bind(recovery_owner)
    .bind(recovery_token)
    .fetch_one(&mut *expiry_probe)
    .await
    .unwrap();
    assert_eq!(unstarted.0, "recorded");
    assert_eq!(
        unstarted.1.as_ref().unwrap()["resolution_kind"],
        "unstarted"
    );
    let unstarted_replay: String = sqlx::query_scalar(
        "select outcome from control.resolve_interrupted_route_set_publication_observation(
          $1,$2,$3,1,'unstarted',null,null,null,null)",
    )
    .bind(acquired.1)
    .bind(recovery_owner)
    .bind(recovery_token)
    .fetch_one(&mut *expiry_probe)
    .await
    .unwrap();
    assert_eq!(unstarted_replay, "replay");
    let unstarted_decision_digest = authorize_route_set_terminal_decision(
        &mut expiry_probe,
        RouteSetTerminalDecisionAuthorization {
            publication_id: acquired.1,
            claim_fence: 1,
            reconciliation_operation_id: recovery_operation,
            reconciliation_operation_attempt: 1,
            reconciliation_operation_lease_owner: "recovery-fixture",
            reconciliation_owner: recovery_owner,
            reconciliation_token: recovery_token,
            resolution_kind: "unstarted",
            decision: "accept",
        },
    )
    .await;
    sqlx::query("savepoint unstarted_fleet_drift_probe")
        .execute(&mut *expiry_probe)
        .await
        .unwrap();
    sqlx::query("set local session_replication_role=replica")
        .execute(&mut *expiry_probe)
        .await
        .unwrap();
    sqlx::query(
        "update control.workshop_route_projection_state
         set applied_fence_token=applied_fence_token+100 where workshop_id=$1",
    )
    .bind(other_workshop)
    .execute(&mut *expiry_probe)
    .await
    .unwrap();
    sqlx::query("set local session_replication_role=origin")
        .execute(&mut *expiry_probe)
        .await
        .unwrap();
    let unstarted_drift: String = sqlx::query_scalar(
        "select outcome from control.finish_route_set_publication_recovery(
          $1,1,$2,1,'recovery-fixture',$3,$4,'unstarted','accept',$5)",
    )
    .bind(acquired.1)
    .bind(recovery_operation)
    .bind(recovery_owner)
    .bind(recovery_token)
    .bind(&unstarted_decision_digest)
    .fetch_one(&mut *expiry_probe)
    .await
    .unwrap();
    assert_eq!(unstarted_drift, "authority_inconsistent");
    sqlx::query("rollback to savepoint unstarted_fleet_drift_probe")
        .execute(&mut *expiry_probe)
        .await
        .unwrap();
    let unstarted_terminal: (String, Option<Value>) = sqlx::query_as(
        "select outcome,response from control.finish_route_set_publication_recovery(
          $1,1,$2,1,'recovery-fixture',$3,$4,'unstarted','accept',$5)",
    )
    .bind(acquired.1)
    .bind(recovery_operation)
    .bind(recovery_owner)
    .bind(recovery_token)
    .bind(&unstarted_decision_digest)
    .fetch_one(&mut *expiry_probe)
    .await
    .unwrap();
    assert_eq!(unstarted_terminal.0, "completed");
    assert_eq!(
        unstarted_terminal.1.as_ref().unwrap()["outcome"],
        "not_applied"
    );
    let unstarted_result: (String, Option<Value>) = sqlx::query_as(
        "select outcome,response from control.read_route_set_publication_result($1,$2,$3,$4)",
    )
    .bind(operation_id)
    .bind(workshop_id)
    .bind("route-set-generation-two")
    .bind("9".repeat(64))
    .fetch_one(&mut *expiry_probe)
    .await
    .unwrap();
    assert_eq!(unstarted_result.0, "not_applied");
    assert_eq!(
        unstarted_result.1.as_ref().unwrap()["resolution_kind"],
        "unstarted"
    );
    let unstarted_state: (String, String, String, i64) = sqlx::query_as(
        "select driver.state,global_lease.state,route_lease.state,projection.applied_generation
         from control.workshop_route_set_publications publication
         join control.deployment_driver_operations driver on driver.id=publication.driver_operation_id
         join control.deployment_driver_resource_leases global_lease
           on global_lease.resource_key='runtime/shared-odoo'
         join control.workshop_route_application_leases route_lease
           on route_lease.workshop_id=publication.target_workshop_id
         join control.workshop_route_projection_state projection
           on projection.workshop_id=publication.target_workshop_id
         where publication.publication_id=$1",
    )
    .bind(acquired.1)
    .fetch_one(&mut *expiry_probe)
    .await
    .unwrap();
    assert_eq!(
        unstarted_state,
        ("failed".into(), "idle".into(), "idle".into(), 1)
    );
    let resolution_mutation = sqlx::query(
        "update control.workshop_route_set_publication_resolutions
         set evidence='{}' where publication_id=$1 and reconciliation_claim_fence=1",
    )
    .bind(acquired.1)
    .execute(&mut *expiry_probe)
    .await
    .unwrap_err();
    assert_eq!(
        resolution_mutation
            .as_database_error()
            .and_then(|error| error.code())
            .as_deref(),
        Some("55000")
    );
    expiry_probe.rollback().await.unwrap();

    let mut continuation_drift_probe = store.pool().begin().await.unwrap();
    sqlx::query(
        "with upstream as (
           update control.operations set lease_expires_at=now()-interval '1 second' where id=$1
         ), driver as (
           update control.deployment_driver_operations set lease_expires_at=now()-interval '1 second' where id=$2
         ), global_lease as (
           update control.deployment_driver_resource_leases set lease_expires_at=now()-interval '1 second'
           where resource_key='runtime/shared-odoo'
         )
         update control.workshop_route_application_leases
         set lease_expires_at=now()-interval '1 second' where workshop_id=$3",
    )
    .bind(operation_id)
    .bind(acquired.2)
    .bind(workshop_id)
    .execute(&mut *continuation_drift_probe)
    .await
    .unwrap();
    let acquired_for_drift: (String, Option<i64>) = sqlx::query_as(
        "select outcome,claim_fence from control.claim_interrupted_route_set_publication(
          $1,$2,1,'recovery-fixture',$3,$4,300)",
    )
    .bind(acquired.1)
    .bind(recovery_operation)
    .bind(recovery_owner)
    .bind(recovery_token)
    .fetch_one(&mut *continuation_drift_probe)
    .await
    .unwrap();
    assert_eq!(acquired_for_drift, ("acquired".into(), Some(1)));
    sqlx::query("set local session_replication_role=replica")
        .execute(&mut *continuation_drift_probe)
        .await
        .unwrap();
    sqlx::query(
        "update control.deployment_driver_operations
         set route_fence_token=route_fence_token+1 where id=$1",
    )
    .bind(acquired.2)
    .execute(&mut *continuation_drift_probe)
    .await
    .unwrap();
    sqlx::query("set local session_replication_role=origin")
        .execute(&mut *continuation_drift_probe)
        .await
        .unwrap();
    let drifted_read: String = sqlx::query_scalar(
        "select outcome from control.read_interrupted_route_set_publication_state($1,$2,$3,1)",
    )
    .bind(acquired.1)
    .bind(recovery_owner)
    .bind(recovery_token)
    .fetch_one(&mut *continuation_drift_probe)
    .await
    .unwrap();
    assert_eq!(drifted_read, "claim_lost");
    let drifted_renew: String = sqlx::query_scalar(
        "select control.renew_interrupted_route_set_publication_claim($1,$2,$3,1,300)",
    )
    .bind(acquired.1)
    .bind(recovery_owner)
    .bind(recovery_token)
    .fetch_one(&mut *continuation_drift_probe)
    .await
    .unwrap();
    assert_eq!(drifted_renew, "claim_lost");
    let drifted_resolve: String = sqlx::query_scalar(
        "select outcome from control.resolve_interrupted_route_set_publication_observation(
          $1,$2,$3,1,'inconclusive',null,null,null,null)",
    )
    .bind(acquired.1)
    .bind(recovery_owner)
    .bind(recovery_token)
    .fetch_one(&mut *continuation_drift_probe)
    .await
    .unwrap();
    assert_eq!(drifted_resolve, "claim_lost");
    continuation_drift_probe.rollback().await.unwrap();

    let mut takeover_probe = store.pool().begin().await.unwrap();
    sqlx::query(
        "with upstream as (
           update control.operations set lease_expires_at=now()-interval '1 second' where id=$1
         ), driver as (
           update control.deployment_driver_operations set lease_expires_at=now()-interval '1 second' where id=$2
         ), global_lease as (
           update control.deployment_driver_resource_leases set lease_expires_at=now()-interval '1 second'
           where resource_key='runtime/shared-odoo'
         )
         update control.workshop_route_application_leases
         set lease_expires_at=now()-interval '1 second' where workshop_id=$3",
    )
    .bind(operation_id)
    .bind(acquired.2)
    .bind(workshop_id)
    .execute(&mut *takeover_probe)
    .await
    .unwrap();
    let first_claim: (String, Option<i64>) = sqlx::query_as(
        "select outcome,claim_fence from control.claim_interrupted_route_set_publication(
          $1,$2,1,'recovery-fixture',$3,$4,300)",
    )
    .bind(acquired.1)
    .bind(recovery_operation)
    .bind(recovery_owner)
    .bind(recovery_token)
    .fetch_one(&mut *takeover_probe)
    .await
    .unwrap();
    assert_eq!(first_claim, ("acquired".into(), Some(1)));
    sqlx::query(
        "update control.workshop_route_set_publications
         set reconciliation_expires_at=now()-interval '1 second' where publication_id=$1",
    )
    .bind(acquired.1)
    .execute(&mut *takeover_probe)
    .await
    .unwrap();
    let takeover_owner = Uuid::new_v4();
    let takeover_token = Uuid::new_v4();
    let takeover: (String, Option<i64>) = sqlx::query_as(
        "select outcome,claim_fence from control.claim_interrupted_route_set_publication(
          $1,$2,1,'recovery-fixture',$3,$4,300)",
    )
    .bind(acquired.1)
    .bind(recovery_operation)
    .bind(takeover_owner)
    .bind(takeover_token)
    .fetch_one(&mut *takeover_probe)
    .await
    .unwrap();
    assert_eq!(takeover, ("acquired".into(), Some(2)));
    let stale_renew: String = sqlx::query_scalar(
        "select control.renew_interrupted_route_set_publication_claim($1,$2,$3,1,300)",
    )
    .bind(acquired.1)
    .bind(recovery_owner)
    .bind(recovery_token)
    .fetch_one(&mut *takeover_probe)
    .await
    .unwrap();
    assert_eq!(stale_renew, "claim_lost");
    let inconclusive: String = sqlx::query_scalar(
        "select outcome from control.resolve_interrupted_route_set_publication_observation(
          $1,$2,$3,2,'inconclusive',null,null,null,null)",
    )
    .bind(acquired.1)
    .bind(takeover_owner)
    .bind(takeover_token)
    .fetch_one(&mut *takeover_probe)
    .await
    .unwrap();
    assert_eq!(inconclusive, "recorded");
    takeover_probe.rollback().await.unwrap();

    let mut expiry_probe = store.pool().begin().await.unwrap();
    sqlx::query(
        "update control.deployment_driver_resource_leases
         set lease_expires_at=now()-interval '1 second'
         where resource_key='runtime/shared-odoo'",
    )
    .execute(&mut *expiry_probe)
    .await
    .unwrap();
    let pre_start_quarantined: bool = sqlx::query_scalar(
        "select control.quarantine_route_set_publication(
          $1,$2,$3,$4,$5,$6,$7,'route_set_publication_outcome_unknown')",
    )
    .bind(acquired.1)
    .bind(instance_owner)
    .bind(execution_token)
    .bind(global_token)
    .bind(route_token)
    .bind(acquired.3)
    .bind(acquired.4)
    .fetch_one(&mut *expiry_probe)
    .await
    .unwrap();
    assert!(pre_start_quarantined);
    let interrupted: (String, String) = sqlx::query_as(
        "select phase,interrupted_phase from control.workshop_route_set_publications
         where publication_id=$1",
    )
    .bind(acquired.1)
    .fetch_one(&mut *expiry_probe)
    .await
    .unwrap();
    assert_eq!(interrupted, ("quarantined".into(), "staging".into()));
    let legacy_discovery: (String, bool) = sqlx::query_as(
        "select claim_mode,claim_available
         from control.discover_interrupted_route_set_publications(null,100)
         where publication_id=$1",
    )
    .bind(acquired.1)
    .fetch_one(&mut *expiry_probe)
    .await
    .unwrap();
    assert_eq!(legacy_discovery, ("observe_only".into(), true));
    sqlx::query("savepoint unsupported_recovery_kind")
        .execute(&mut *expiry_probe)
        .await
        .unwrap();
    sqlx::query("set local session_replication_role=replica")
        .execute(&mut *expiry_probe)
        .await
        .unwrap();
    sqlx::query(
        "alter table control.workshop_route_set_publications
         drop constraint workshop_route_set_publications_owner_xor_check",
    )
    .execute(&mut *expiry_probe)
    .await
    .unwrap();
    sqlx::query(
        "update control.workshop_route_set_publications
         set publication_kind='recovery_maintenance',
             selector='generations/route-'||replace(publication_id::text,'-','')||
               '-recovery-maintenance'
         where publication_id=$1",
    )
    .bind(acquired.1)
    .execute(&mut *expiry_probe)
    .await
    .unwrap();
    sqlx::query("set local session_replication_role=origin")
        .execute(&mut *expiry_probe)
        .await
        .unwrap();
    let unsupported_discovery_count: i64 = sqlx::query_scalar(
        "select count(*) from control.discover_interrupted_route_set_publications(null,100)
         where publication_id=$1",
    )
    .bind(acquired.1)
    .fetch_one(&mut *expiry_probe)
    .await
    .unwrap();
    assert_eq!(
        unsupported_discovery_count, 1,
        "recovery-kind publications are discoverable in the generalized feed"
    );
    sqlx::query("rollback to savepoint unsupported_recovery_kind")
        .execute(&mut *expiry_probe)
        .await
        .unwrap();
    let legacy_quarantine_claim: (String, Option<String>) = sqlx::query_as(
        "select outcome,claim_mode from control.claim_interrupted_route_set_publication(
          $1,$2,1,'recovery-fixture',$3,$4,300)",
    )
    .bind(acquired.1)
    .bind(recovery_operation)
    .bind(recovery_owner)
    .bind(recovery_token)
    .fetch_one(&mut *expiry_probe)
    .await
    .unwrap();
    assert_eq!(
        legacy_quarantine_claim,
        ("acquired".into(), Some("observe_only".into()))
    );
    let legacy_unstarted: String = sqlx::query_scalar(
        "select outcome from control.resolve_interrupted_route_set_publication_observation(
          $1,$2,$3,1,'unstarted',null,null,null,null)",
    )
    .bind(acquired.1)
    .bind(recovery_owner)
    .bind(recovery_token)
    .fetch_one(&mut *expiry_probe)
    .await
    .unwrap();
    assert_eq!(legacy_unstarted, "recorded");
    let second_legacy_token = Uuid::new_v4();
    let second_legacy_claim: (String, Option<i64>, Option<String>) = sqlx::query_as(
        "select outcome,claim_fence,claim_mode
         from control.claim_interrupted_route_set_publication(
          $1,$2,1,'recovery-fixture',$3,$4,300)",
    )
    .bind(acquired.1)
    .bind(recovery_operation)
    .bind(recovery_owner)
    .bind(second_legacy_token)
    .fetch_one(&mut *expiry_probe)
    .await
    .unwrap();
    assert_eq!(
        second_legacy_claim,
        ("acquired".into(), Some(2), Some("observe_only".into()))
    );
    let quarantined_result: String = sqlx::query_scalar(
        "select outcome from control.read_route_set_publication_result($1,$2,$3,$4)",
    )
    .bind(operation_id)
    .bind(workshop_id)
    .bind("route-set-generation-two")
    .bind("9".repeat(64))
    .fetch_one(&mut *expiry_probe)
    .await
    .unwrap();
    assert_eq!(quarantined_result, "pending");
    expiry_probe.rollback().await.unwrap();

    for drift_sql in [
        "update control.operations set attempt=attempt+1 where id=$1",
        "update control.deployment_driver_operations set route_fence_token=route_fence_token+1 where id=$1",
        "update control.deployment_driver_resource_leases set lease_owner=$1 where resource_key='runtime/shared-odoo'",
        "update control.workshop_route_application_leases set projection_digest='sha256:'||repeat('f',64) where workshop_id=$1",
    ] {
        let mut probe = store.pool().begin().await.unwrap();
        sqlx::query(
            "update control.deployment_driver_resource_leases
             set lease_expires_at=now()-interval '1 second'
             where resource_key='runtime/shared-odoo'",
        )
        .execute(&mut *probe)
        .await
        .unwrap();
        let quarantined: bool = sqlx::query_scalar(
            "select control.quarantine_route_set_publication(
              $1,$2,$3,$4,$5,$6,$7,'route_set_publication_outcome_unknown')",
        )
        .bind(acquired.1)
        .bind(instance_owner)
        .bind(execution_token)
        .bind(global_token)
        .bind(route_token)
        .bind(acquired.3)
        .bind(acquired.4)
        .fetch_one(&mut *probe)
        .await
        .unwrap();
        assert!(quarantined);
        sqlx::query("set local session_replication_role=replica")
            .execute(&mut *probe)
            .await
            .unwrap();
        let mut query = sqlx::query(drift_sql);
        if drift_sql.contains("control.operations ") {
            query = query.bind(operation_id);
        } else if drift_sql.contains("deployment_driver_operations") {
            query = query.bind(acquired.2);
        } else if drift_sql.contains("deployment_driver_resource_leases") {
            query = query.bind(Uuid::new_v4());
        } else {
            query = query.bind(workshop_id);
        }
        query.execute(&mut *probe).await.unwrap();
        sqlx::query("set local session_replication_role=origin")
            .execute(&mut *probe)
            .await
            .unwrap();
        let outcome: String = sqlx::query_scalar(
            "select outcome from control.claim_interrupted_route_set_publication(
              $1,$2,1,'recovery-fixture',$3,$4,300)",
        )
        .bind(acquired.1)
        .bind(recovery_operation)
        .bind(recovery_owner)
        .bind(recovery_token)
        .fetch_one(&mut *probe)
        .await
        .unwrap();
        assert_eq!(outcome, "authority_inconsistent", "{drift_sql}");
        probe.rollback().await.unwrap();
    }

    sqlx::query(
        "with upstream as (
           update control.operations set lease_expires_at=now()+interval '10 minutes' where id=$1
         ), driver as (
           update control.deployment_driver_operations set lease_expires_at=now()+interval '10 minutes' where id=$2
         ), global_lease as (
           update control.deployment_driver_resource_leases set lease_expires_at=now()+interval '10 minutes'
           where resource_key='runtime/shared-odoo'
         )
         update control.workshop_route_application_leases
         set lease_expires_at=now()+interval '10 minutes' where workshop_id=$3",
    )
    .bind(operation_id)
    .bind(acquired.2)
    .bind(workshop_id)
    .execute(store.pool())
    .await
    .unwrap();

    let blocked_workshop = Uuid::new_v4();
    let membership_error = sqlx::query(
        "insert into control.workshops(id,slug,display_name,time_zone)
         values($1,$2,'Blocked route set member','UTC')",
    )
    .bind(blocked_workshop)
    .bind(format!("route-set-{}", blocked_workshop.simple()))
    .execute(store.pool())
    .await
    .unwrap_err();
    let membership_code = membership_error
        .as_database_error()
        .and_then(|error| error.code());
    assert_eq!(membership_code.as_deref(), Some("55000"));
    let workshop_count: i64 = sqlx::query_scalar("select count(*) from control.workshops")
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(workshop_count, 2);

    let snapshot: Vec<(Uuid, i64, String, String, String, bool)> = sqlx::query_as(
        "select workshop_id,generation,projection_digest,disposition,
                applied_rendered_digest,is_target
         from control.read_route_set_publication_snapshot_batch(
           $1,$2,$3,$4,$5,$6,$7,null,500)",
    )
    .bind(acquired.1)
    .bind(instance_owner)
    .bind(execution_token)
    .bind(global_token)
    .bind(route_token)
    .bind(acquired.3)
    .bind(acquired.4)
    .fetch_all(store.pool())
    .await
    .unwrap();
    assert_eq!(snapshot.len(), 2);
    assert!(
        snapshot
            .iter()
            .any(|row| { row.0 == workshop_id && row.1 == 2 && row.2 == target_desired && row.5 })
    );
    assert!(
        snapshot.iter().any(|row| {
            row.0 == other_workshop && row.1 == 1 && row.2 == other_applied && !row.5
        })
    );

    let route_set_prior_effect_run = Uuid::new_v4();
    let route_set_prior_selector = format!("generations/startup-{route_set_prior_effect_run}");
    let route_set_prior_identity = json!({
        "effect_run_id": route_set_prior_effect_run,
        "sealed_digest": format!("sha256:{}", "6".repeat(64)),
    });
    let prior: String = sqlx::query_scalar(
        "select control.record_route_set_publication_prior(
          $1,$2,$3,$4,$5,$6,$7,$8,11,12,$9)",
    )
    .bind(acquired.1)
    .bind(instance_owner)
    .bind(execution_token)
    .bind(global_token)
    .bind(route_token)
    .bind(acquired.3)
    .bind(acquired.4)
    .bind(&route_set_prior_selector)
    .bind(&route_set_prior_identity)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(prior, "recorded");
    let prior_replay: String = sqlx::query_scalar(
        "select control.record_route_set_publication_prior(
          $1,$2,$3,$4,$5,$6,$7,$8,11,12,$9)",
    )
    .bind(acquired.1)
    .bind(instance_owner)
    .bind(execution_token)
    .bind(global_token)
    .bind(route_token)
    .bind(acquired.3)
    .bind(acquired.4)
    .bind(&route_set_prior_selector)
    .bind(&route_set_prior_identity)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(prior_replay, "replay");

    let out_of_order: String = sqlx::query_scalar(
        "select control.record_route_set_publication_entry(
          $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
    )
    .bind(acquired.1)
    .bind(instance_owner)
    .bind(execution_token)
    .bind(global_token)
    .bind(route_token)
    .bind(acquired.3)
    .bind(acquired.4)
    .bind(snapshot[1].0)
    .bind(snapshot[1].1)
    .bind(&snapshot[1].2)
    .bind(&snapshot[1].3)
    .bind(&snapshot[1].4)
    .bind(&snapshot[1].4)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(out_of_order, "out_of_order");
    for row in &snapshot {
        let rendered = if row.3 == "absent" {
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_owned()
        } else if row.5 {
            format!("sha256:{}", "c".repeat(64))
        } else {
            row.4.clone()
        };
        if !row.5 {
            let drift: String = sqlx::query_scalar(
                "select control.record_route_set_publication_entry(
                  $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
            )
            .bind(acquired.1)
            .bind(instance_owner)
            .bind(execution_token)
            .bind(global_token)
            .bind(route_token)
            .bind(acquired.3)
            .bind(acquired.4)
            .bind(row.0)
            .bind(row.1)
            .bind(&row.2)
            .bind(&row.3)
            .bind(&row.4)
            .bind(format!("sha256:{}", "e".repeat(64)))
            .fetch_one(store.pool())
            .await
            .unwrap();
            assert_eq!(drift, "render_invariant_mismatch");
        } else if row.3 == "absent" {
            let noncanonical_empty: String = sqlx::query_scalar(
                "select control.record_route_set_publication_entry(
                  $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
            )
            .bind(acquired.1)
            .bind(instance_owner)
            .bind(execution_token)
            .bind(global_token)
            .bind(route_token)
            .bind(acquired.3)
            .bind(acquired.4)
            .bind(row.0)
            .bind(row.1)
            .bind(&row.2)
            .bind(&row.3)
            .bind(&row.4)
            .bind(format!("sha256:{}", "c".repeat(64)))
            .fetch_one(store.pool())
            .await
            .unwrap();
            assert_eq!(noncanonical_empty, "render_invariant_mismatch");
        }
        let recorded: String = sqlx::query_scalar(
            "select control.record_route_set_publication_entry(
              $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
        )
        .bind(acquired.1)
        .bind(instance_owner)
        .bind(execution_token)
        .bind(global_token)
        .bind(route_token)
        .bind(acquired.3)
        .bind(acquired.4)
        .bind(row.0)
        .bind(row.1)
        .bind(&row.2)
        .bind(&row.3)
        .bind(&row.4)
        .bind(rendered)
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(recorded, "recorded");
        let replayed: String = sqlx::query_scalar(
            "select control.record_route_set_publication_entry(
              $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
        )
        .bind(acquired.1)
        .bind(instance_owner)
        .bind(execution_token)
        .bind(global_token)
        .bind(route_token)
        .bind(acquired.3)
        .bind(acquired.4)
        .bind(row.0)
        .bind(row.1)
        .bind(&row.2)
        .bind(&row.3)
        .bind(&row.4)
        .bind(if row.3 == "absent" {
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_owned()
        } else if row.5 {
            format!("sha256:{}", "c".repeat(64))
        } else {
            row.4.clone()
        })
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(replayed, "replay");
    }
    let digest_rows: Vec<(Uuid, i64, String, String, String, String)> = sqlx::query_as(
        "select workshop_id,generation,projection_digest,disposition,
                applied_rendered_digest,rendered_digest
         from control.workshop_route_set_publication_records
         where publication_id=$1 order by workshop_id",
    )
    .bind(acquired.1)
    .fetch_all(store.pool())
    .await
    .unwrap();
    let mut digest_input = b"mb-route-set-publication-v1\0".to_vec();
    for (workshop, generation, projection, disposition, applied, rendered) in digest_rows {
        digest_input.extend_from_slice(workshop.as_bytes());
        digest_input.extend_from_slice(&generation.to_be_bytes());
        for field in [projection, disposition, applied, rendered] {
            digest_input.extend_from_slice(&u32::try_from(field.len()).unwrap().to_be_bytes());
            digest_input.extend_from_slice(field.as_bytes());
        }
    }
    let database_digest: String =
        sqlx::query_scalar("select control.route_set_publication_digest($1)")
            .bind(acquired.1)
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert_eq!(
        database_digest,
        format!("sha256:{:x}", Sha256::digest(digest_input))
    );

    let illegal_jump = sqlx::query(
        "update control.workshop_route_set_publications
         set phase='observed',updated_at=now() where publication_id=$1",
    )
    .bind(acquired.1)
    .execute(store.pool())
    .await
    .unwrap_err();
    assert_eq!(
        illegal_jump
            .as_database_error()
            .and_then(|error| error.code())
            .as_deref(),
        Some("55000")
    );
    let reused_prior: String = sqlx::query_scalar(
        "select control.seal_route_set_publication(
          $1,$2,$3,$4,$5,$6,$7,$8,11,12,2,1,$9)",
    )
    .bind(acquired.1)
    .bind(instance_owner)
    .bind(execution_token)
    .bind(global_token)
    .bind(route_token)
    .bind(acquired.3)
    .bind(acquired.4)
    .bind(&acquired.5)
    .bind(&database_digest)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(reused_prior, "prior_directory_reused");
    let sealed: String = sqlx::query_scalar(
        "select control.seal_route_set_publication(
          $1,$2,$3,$4,$5,$6,$7,$8,21,22,2,1,$9)",
    )
    .bind(acquired.1)
    .bind(instance_owner)
    .bind(execution_token)
    .bind(global_token)
    .bind(route_token)
    .bind(acquired.3)
    .bind(acquired.4)
    .bind(&acquired.5)
    .bind(&database_digest)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(sealed, "sealed");
    let seal_replay: String = sqlx::query_scalar(
        "select control.seal_route_set_publication(
          $1,$2,$3,$4,$5,$6,$7,$8,21,22,2,1,$9)",
    )
    .bind(acquired.1)
    .bind(instance_owner)
    .bind(execution_token)
    .bind(global_token)
    .bind(route_token)
    .bind(acquired.3)
    .bind(acquired.4)
    .bind(&acquired.5)
    .bind(&database_digest)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(seal_replay, "replay");
    let sealed_mutation = sqlx::query(
        "update control.workshop_route_set_publications
         set route_set_digest='sha256:'||repeat('f',64),updated_at=now()
         where publication_id=$1",
    )
    .bind(acquired.1)
    .execute(store.pool())
    .await
    .unwrap_err();
    assert_eq!(
        sealed_mutation
            .as_database_error()
            .and_then(|error| error.code())
            .as_deref(),
        Some("55000")
    );
    let started: String =
        sqlx::query_scalar("select control.start_route_set_publication($1,$2,$3,$4,$5,$6,$7)")
            .bind(acquired.1)
            .bind(instance_owner)
            .bind(execution_token)
            .bind(global_token)
            .bind(route_token)
            .bind(acquired.3)
            .bind(acquired.4)
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert_eq!(started, "started");
    let start_replay: String =
        sqlx::query_scalar("select control.start_route_set_publication($1,$2,$3,$4,$5,$6,$7)")
            .bind(acquired.1)
            .bind(instance_owner)
            .bind(execution_token)
            .bind(global_token)
            .bind(route_token)
            .bind(acquired.3)
            .bind(acquired.4)
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert_eq!(start_replay, "replay");
    let premature_finish: (String, Option<Value>) = sqlx::query_as(
        "select outcome,response from control.finish_route_set_publication(
          $1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(acquired.1)
    .bind(instance_owner)
    .bind(execution_token)
    .bind(global_token)
    .bind(route_token)
    .bind(acquired.3)
    .bind(acquired.4)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(premature_finish, ("wrong_phase".into(), None));
    let mut post_start_probe = store.pool().begin().await.unwrap();
    let started_quarantine: bool = sqlx::query_scalar(
        "select control.quarantine_route_set_publication(
          $1,$2,$3,$4,$5,$6,$7,'route_set_publication_outcome_unknown')",
    )
    .bind(acquired.1)
    .bind(instance_owner)
    .bind(execution_token)
    .bind(global_token)
    .bind(route_token)
    .bind(acquired.3)
    .bind(acquired.4)
    .fetch_one(&mut *post_start_probe)
    .await
    .unwrap();
    assert!(started_quarantine);
    let started_quarantine_replay: bool = sqlx::query_scalar(
        "select control.quarantine_route_set_publication(
          $1,$2,$3,$4,$5,$6,$7,'route_set_publication_outcome_unknown')",
    )
    .bind(acquired.1)
    .bind(instance_owner)
    .bind(execution_token)
    .bind(global_token)
    .bind(route_token)
    .bind(acquired.3)
    .bind(acquired.4)
    .fetch_one(&mut *post_start_probe)
    .await
    .unwrap();
    assert!(started_quarantine_replay);
    let prior_claim: (String, Option<i64>, Option<String>) = sqlx::query_as(
        "select outcome,claim_fence,claim_mode
         from control.claim_interrupted_route_set_publication(
          $1,$2,1,'recovery-fixture',$3,$4,300)",
    )
    .bind(acquired.1)
    .bind(recovery_operation)
    .bind(recovery_owner)
    .bind(recovery_token)
    .fetch_one(&mut *post_start_probe)
    .await
    .unwrap();
    assert_eq!(
        prior_claim,
        ("acquired".into(), Some(1), Some("observe_only".into()))
    );
    sqlx::query("savepoint inconclusive_terminal_probe")
        .execute(&mut *post_start_probe)
        .await
        .unwrap();
    let inconclusive_observation: String = sqlx::query_scalar(
        "select outcome from control.resolve_interrupted_route_set_publication_observation(
          $1,$2,$3,1,'inconclusive',null,null,null,null)",
    )
    .bind(acquired.1)
    .bind(recovery_owner)
    .bind(recovery_token)
    .fetch_one(&mut *post_start_probe)
    .await
    .unwrap();
    assert_eq!(inconclusive_observation, "recorded");
    let inconclusive_digest = authorize_route_set_terminal_decision(
        &mut post_start_probe,
        RouteSetTerminalDecisionAuthorization {
            publication_id: acquired.1,
            claim_fence: 1,
            reconciliation_operation_id: recovery_operation,
            reconciliation_operation_attempt: 1,
            reconciliation_operation_lease_owner: "recovery-fixture",
            reconciliation_owner: recovery_owner,
            reconciliation_token: recovery_token,
            resolution_kind: "inconclusive",
            decision: "keep_quarantined",
        },
    )
    .await;
    sqlx::query("savepoint inconclusive_fleet_drift_probe")
        .execute(&mut *post_start_probe)
        .await
        .unwrap();
    sqlx::query("set local session_replication_role=replica")
        .execute(&mut *post_start_probe)
        .await
        .unwrap();
    sqlx::query(
        "update control.workshop_route_projection_state
         set applied_fence_token=applied_fence_token+100 where workshop_id=$1",
    )
    .bind(other_workshop)
    .execute(&mut *post_start_probe)
    .await
    .unwrap();
    sqlx::query("set local session_replication_role=origin")
        .execute(&mut *post_start_probe)
        .await
        .unwrap();
    let inconclusive_drift: String = sqlx::query_scalar(
        "select outcome from control.finish_route_set_publication_recovery(
          $1,1,$2,1,'recovery-fixture',$3,$4,'inconclusive','keep_quarantined',$5)",
    )
    .bind(acquired.1)
    .bind(recovery_operation)
    .bind(recovery_owner)
    .bind(recovery_token)
    .bind(&inconclusive_digest)
    .fetch_one(&mut *post_start_probe)
    .await
    .unwrap();
    assert_eq!(inconclusive_drift, "authority_inconsistent");
    sqlx::query("rollback to savepoint inconclusive_fleet_drift_probe")
        .execute(&mut *post_start_probe)
        .await
        .unwrap();
    let blocked: String = sqlx::query_scalar(
        "select outcome from control.finish_route_set_publication_recovery(
          $1,1,$2,1,'recovery-fixture',$3,$4,'inconclusive','keep_quarantined',$5)",
    )
    .bind(acquired.1)
    .bind(recovery_operation)
    .bind(recovery_owner)
    .bind(recovery_token)
    .bind(&inconclusive_digest)
    .fetch_one(&mut *post_start_probe)
    .await
    .unwrap();
    assert_eq!(blocked, "blocked");
    let blocked_state: (String, String, String, bool) = sqlx::query_as(
        "select driver.state,global_lease.state,route_lease.state,
                publication.recovery_terminal_at is null
         from control.workshop_route_set_publications publication
         join control.deployment_driver_operations driver on driver.id=publication.driver_operation_id
         join control.deployment_driver_resource_leases global_lease
           on global_lease.resource_key='runtime/shared-odoo'
         join control.workshop_route_application_leases route_lease
           on route_lease.workshop_id=publication.target_workshop_id
         where publication.publication_id=$1",
    )
    .bind(acquired.1)
    .fetch_one(&mut *post_start_probe)
    .await
    .unwrap();
    assert_eq!(
        blocked_state,
        (
            "in_progress".into(),
            "quarantined".into(),
            "quarantined".into(),
            true
        )
    );
    sqlx::query("rollback to savepoint inconclusive_terminal_probe")
        .execute(&mut *post_start_probe)
        .await
        .unwrap();
    let prior_observation: String = sqlx::query_scalar(
        "select outcome from control.resolve_interrupted_route_set_publication_observation(
          $1,$2,$3,1,'prior',$4,11,12,$5)",
    )
    .bind(acquired.1)
    .bind(recovery_owner)
    .bind(recovery_token)
    .bind(&route_set_prior_selector)
    .bind(&route_set_prior_identity)
    .fetch_one(&mut *post_start_probe)
    .await
    .unwrap();
    assert_eq!(prior_observation, "recorded");
    let prior_digest = authorize_route_set_terminal_decision(
        &mut post_start_probe,
        RouteSetTerminalDecisionAuthorization {
            publication_id: acquired.1,
            claim_fence: 1,
            reconciliation_operation_id: recovery_operation,
            reconciliation_operation_attempt: 1,
            reconciliation_operation_lease_owner: "recovery-fixture",
            reconciliation_owner: recovery_owner,
            reconciliation_token: recovery_token,
            resolution_kind: "prior",
            decision: "accept",
        },
    )
    .await;
    sqlx::query("savepoint boot_live_prior_terminal_probe")
        .execute(&mut *post_start_probe)
        .await
        .unwrap();
    sqlx::query("set local session_replication_role=replica")
        .execute(&mut *post_start_probe)
        .await
        .unwrap();
    sqlx::query(
        "update control.workshop_route_set_publications
         set prior_selector='generations/boot-live',prior_loaded_identity=null
         where publication_id=$1",
    )
    .bind(acquired.1)
    .execute(&mut *post_start_probe)
    .await
    .unwrap();
    sqlx::query(
        "update control.workshop_route_set_publication_resolutions
         set evidence=jsonb_set(jsonb_set(evidence,'{observed_selector}',
               to_jsonb('generations/boot-live'::text)),
               '{observed_loaded_identity}','null'::jsonb)
         where publication_id=$1 and reconciliation_claim_fence=1",
    )
    .bind(acquired.1)
    .execute(&mut *post_start_probe)
    .await
    .unwrap();
    sqlx::query("set local session_replication_role=origin")
        .execute(&mut *post_start_probe)
        .await
        .unwrap();
    let boot_live_digest = authorize_route_set_terminal_decision(
        &mut post_start_probe,
        RouteSetTerminalDecisionAuthorization {
            publication_id: acquired.1,
            claim_fence: 1,
            reconciliation_operation_id: recovery_operation,
            reconciliation_operation_attempt: 1,
            reconciliation_operation_lease_owner: "recovery-fixture",
            reconciliation_owner: recovery_owner,
            reconciliation_token: recovery_token,
            resolution_kind: "prior",
            decision: "accept",
        },
    )
    .await;
    let boot_live_refused: String = sqlx::query_scalar(
        "select outcome from control.finish_route_set_publication_recovery(
          $1,1,$2,1,'recovery-fixture',$3,$4,'prior','accept',$5)",
    )
    .bind(acquired.1)
    .bind(recovery_operation)
    .bind(recovery_owner)
    .bind(recovery_token)
    .bind(&boot_live_digest)
    .fetch_one(&mut *post_start_probe)
    .await
    .unwrap();
    assert_eq!(boot_live_refused, "observation_mismatch");
    sqlx::query("rollback to savepoint boot_live_prior_terminal_probe")
        .execute(&mut *post_start_probe)
        .await
        .unwrap();
    sqlx::query("savepoint prior_fleet_drift_probe")
        .execute(&mut *post_start_probe)
        .await
        .unwrap();
    sqlx::query("set local session_replication_role=replica")
        .execute(&mut *post_start_probe)
        .await
        .unwrap();
    sqlx::query(
        "update control.workshop_route_projection_state
         set applied_fence_token=applied_fence_token+100 where workshop_id=$1",
    )
    .bind(other_workshop)
    .execute(&mut *post_start_probe)
    .await
    .unwrap();
    sqlx::query("set local session_replication_role=origin")
        .execute(&mut *post_start_probe)
        .await
        .unwrap();
    let prior_drift: String = sqlx::query_scalar(
        "select outcome from control.finish_route_set_publication_recovery(
          $1,1,$2,1,'recovery-fixture',$3,$4,'prior','accept',$5)",
    )
    .bind(acquired.1)
    .bind(recovery_operation)
    .bind(recovery_owner)
    .bind(recovery_token)
    .bind(&prior_digest)
    .fetch_one(&mut *post_start_probe)
    .await
    .unwrap();
    assert_eq!(prior_drift, "authority_inconsistent");
    sqlx::query("rollback to savepoint prior_fleet_drift_probe")
        .execute(&mut *post_start_probe)
        .await
        .unwrap();
    let prior_terminal: (String, Option<Value>) = sqlx::query_as(
        "select outcome,response from control.finish_route_set_publication_recovery(
          $1,1,$2,1,'recovery-fixture',$3,$4,'prior','accept',$5)",
    )
    .bind(acquired.1)
    .bind(recovery_operation)
    .bind(recovery_owner)
    .bind(recovery_token)
    .bind(&prior_digest)
    .fetch_one(&mut *post_start_probe)
    .await
    .unwrap();
    assert_eq!(prior_terminal.0, "completed");
    assert_eq!(prior_terminal.1.as_ref().unwrap()["outcome"], "not_applied");
    post_start_probe.rollback().await.unwrap();
    let loaded_identity = json!({
        "protocol_version": 1,
        "publication_id": acquired.1,
        "publication_kind": "projection",
        "global_fence_token": acquired.3,
        "target_workshop_id": workshop_id,
        "target_route_fence_token": acquired.4,
        "route_set_digest": database_digest,
    });
    let mut wrong_identity = loaded_identity.clone();
    wrong_identity["route_set_digest"] = json!(format!("sha256:{}", "d".repeat(64)));
    let mismatch: String = sqlx::query_scalar(
        "select control.observe_route_set_publication(
          $1,$2,$3,$4,$5,$6,$7,$8,21,22,$9)",
    )
    .bind(acquired.1)
    .bind(instance_owner)
    .bind(execution_token)
    .bind(global_token)
    .bind(route_token)
    .bind(acquired.3)
    .bind(acquired.4)
    .bind(&acquired.5)
    .bind(wrong_identity)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(mismatch, "observation_mismatch");
    let observed: String = sqlx::query_scalar(
        "select control.observe_route_set_publication(
          $1,$2,$3,$4,$5,$6,$7,$8,21,22,$9)",
    )
    .bind(acquired.1)
    .bind(instance_owner)
    .bind(execution_token)
    .bind(global_token)
    .bind(route_token)
    .bind(acquired.3)
    .bind(acquired.4)
    .bind(&acquired.5)
    .bind(&loaded_identity)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(observed, "observed");
    let observe_replay: String = sqlx::query_scalar(
        "select control.observe_route_set_publication(
          $1,$2,$3,$4,$5,$6,$7,$8,21,22,$9)",
    )
    .bind(acquired.1)
    .bind(instance_owner)
    .bind(execution_token)
    .bind(global_token)
    .bind(route_token)
    .bind(acquired.3)
    .bind(acquired.4)
    .bind(&acquired.5)
    .bind(&loaded_identity)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(observe_replay, "replay");
    let mut observed_recovery = store.pool().begin().await.unwrap();
    sqlx::query(
        "with upstream as (
           update control.operations set lease_expires_at=now()-interval '1 second' where id=$1
         ), driver as (
           update control.deployment_driver_operations set lease_expires_at=now()-interval '1 second' where id=$2
         ), global_lease as (
           update control.deployment_driver_resource_leases set lease_expires_at=now()-interval '1 second'
           where resource_key='runtime/shared-odoo'
         )
         update control.workshop_route_application_leases
         set lease_expires_at=now()-interval '1 second' where workshop_id=$3",
    )
    .bind(operation_id)
    .bind(acquired.2)
    .bind(workshop_id)
    .execute(&mut *observed_recovery)
    .await
    .unwrap();
    let observed_claim: (String, Option<i64>, Option<String>) = sqlx::query_as(
        "select outcome,claim_fence,claim_mode
         from control.claim_interrupted_route_set_publication(
          $1,$2,1,'recovery-fixture',$3,$4,300)",
    )
    .bind(acquired.1)
    .bind(recovery_operation)
    .bind(recovery_owner)
    .bind(recovery_token)
    .fetch_one(&mut *observed_recovery)
    .await
    .unwrap();
    assert_eq!(
        observed_claim,
        ("acquired".into(), Some(1), Some("observe_only".into()))
    );
    let forbidden_prior: String = sqlx::query_scalar(
        "select outcome from control.resolve_interrupted_route_set_publication_observation(
          $1,$2,$3,1,'prior',$4,11,12,null)",
    )
    .bind(acquired.1)
    .bind(recovery_owner)
    .bind(recovery_token)
    .bind("generations/boot-live")
    .fetch_one(&mut *observed_recovery)
    .await
    .unwrap();
    assert_eq!(forbidden_prior, "evidence_mismatch");
    let candidate_observation: (String, Option<Value>) = sqlx::query_as(
        "select outcome,evidence from control.resolve_interrupted_route_set_publication_observation(
          $1,$2,$3,1,'candidate',$4,21,22,$5)",
    )
    .bind(acquired.1)
    .bind(recovery_owner)
    .bind(recovery_token)
    .bind(&acquired.5)
    .bind(&loaded_identity)
    .fetch_one(&mut *observed_recovery)
    .await
    .unwrap();
    assert_eq!(candidate_observation.0, "recorded");
    let terminal_decision_digest = authorize_route_set_terminal_decision(
        &mut observed_recovery,
        RouteSetTerminalDecisionAuthorization {
            publication_id: acquired.1,
            claim_fence: 1,
            reconciliation_operation_id: recovery_operation,
            reconciliation_operation_attempt: 1,
            reconciliation_operation_lease_owner: "recovery-fixture",
            reconciliation_owner: recovery_owner,
            reconciliation_token: recovery_token,
            resolution_kind: "candidate",
            decision: "accept",
        },
    )
    .await;
    let terminal_snapshot_probe: (i64, i64, bool) = sqlx::query_as(
        "select count(*),count(*) filter(where
           (snapshot.is_target and (state.desired_generation is distinct from snapshot.generation
            or state.desired_digest is distinct from snapshot.projection_digest
            or state.desired_disposition is distinct from snapshot.disposition))
           or state.applied_generation is distinct from snapshot.baseline_applied_generation
           or state.applied_digest is distinct from snapshot.baseline_applied_digest
           or state.applied_disposition is distinct from snapshot.baseline_applied_disposition
           or state.applied_rendered_digest is distinct from snapshot.baseline_applied_rendered_digest
           or state.applied_driver_operation_id is distinct from snapshot.baseline_applied_driver_operation_id
           or state.applied_effect_run_id is distinct from snapshot.baseline_applied_effect_run_id
           or state.applied_fence_token is distinct from snapshot.baseline_applied_fence_token),
           bool_or(snapshot.is_target and snapshot.workshop_id=$2)
         from control.workshop_route_set_publication_snapshot snapshot
         join control.workshop_route_projection_state state on state.workshop_id=snapshot.workshop_id
         where snapshot.publication_id=$1",
    )
    .bind(acquired.1)
    .bind(workshop_id)
    .fetch_one(&mut *observed_recovery)
    .await
    .unwrap();
    assert_eq!(terminal_snapshot_probe, (2, 0, true));
    sqlx::query("savepoint candidate_fleet_drift_probe")
        .execute(&mut *observed_recovery)
        .await
        .unwrap();
    sqlx::query("set local session_replication_role=replica")
        .execute(&mut *observed_recovery)
        .await
        .unwrap();
    sqlx::query(
        "update control.workshop_route_projection_state
         set applied_fence_token=applied_fence_token+100 where workshop_id=$1",
    )
    .bind(other_workshop)
    .execute(&mut *observed_recovery)
    .await
    .unwrap();
    sqlx::query("set local session_replication_role=origin")
        .execute(&mut *observed_recovery)
        .await
        .unwrap();
    let candidate_drift: String = sqlx::query_scalar(
        "select outcome from control.finish_route_set_publication_recovery(
          $1,1,$2,1,'recovery-fixture',$3,$4,'candidate','accept',$5)",
    )
    .bind(acquired.1)
    .bind(recovery_operation)
    .bind(recovery_owner)
    .bind(recovery_token)
    .bind(&terminal_decision_digest)
    .fetch_one(&mut *observed_recovery)
    .await
    .unwrap();
    assert_eq!(candidate_drift, "authority_inconsistent");
    sqlx::query("rollback to savepoint candidate_fleet_drift_probe")
        .execute(&mut *observed_recovery)
        .await
        .unwrap();
    let wrong_token: String = sqlx::query_scalar(
        "select outcome from control.finish_route_set_publication_recovery(
          $1,1,$2,1,'recovery-fixture',$3,$4,'candidate','accept',$5)",
    )
    .bind(acquired.1)
    .bind(recovery_operation)
    .bind(recovery_owner)
    .bind(Uuid::new_v4())
    .bind(&terminal_decision_digest)
    .fetch_one(&mut *observed_recovery)
    .await
    .unwrap();
    assert_eq!(wrong_token, "observation_mismatch");
    let forged_digest: String = sqlx::query_scalar(
        "select outcome from control.finish_route_set_publication_recovery(
          $1,1,$2,1,'recovery-fixture',$3,$4,'candidate','accept',repeat('7',64))",
    )
    .bind(acquired.1)
    .bind(recovery_operation)
    .bind(recovery_owner)
    .bind(recovery_token)
    .fetch_one(&mut *observed_recovery)
    .await
    .unwrap();
    assert_eq!(forged_digest, "observation_mismatch");
    let terminal: (String, Option<Value>) = sqlx::query_as(
        "select outcome,response from control.finish_route_set_publication_recovery(
          $1,1,$2,1,'recovery-fixture',$3,$4,'candidate','accept',$5)",
    )
    .bind(acquired.1)
    .bind(recovery_operation)
    .bind(recovery_owner)
    .bind(recovery_token)
    .bind(&terminal_decision_digest)
    .fetch_one(&mut *observed_recovery)
    .await
    .unwrap();
    assert_eq!(terminal.0, "completed");
    assert_eq!(terminal.1.as_ref().unwrap()["outcome"], "applied_recovered");
    let recovered_result: (String, Option<Value>) = sqlx::query_as(
        "select outcome,response from control.read_route_set_publication_result($1,$2,$3,$4)",
    )
    .bind(operation_id)
    .bind(workshop_id)
    .bind("route-set-generation-two")
    .bind("9".repeat(64))
    .fetch_one(&mut *observed_recovery)
    .await
    .unwrap();
    assert_eq!(recovered_result.0, "completed");
    assert_eq!(
        recovered_result.1.as_ref().unwrap(),
        &terminal.1.as_ref().unwrap()["driver_response"]
    );
    sqlx::query(
        "update control.route_set_publication_protocol_state
         set mode='flat_v1',normal_ready=false,recovery_ready=false,startup_ready=false,
             release_ready=false,activation_epoch=0,activated_at=null,updated_at=now()
         where singleton",
    )
    .execute(&mut *observed_recovery)
    .await
    .unwrap();
    let replay: String = sqlx::query_scalar(
        "select outcome from control.finish_route_set_publication_recovery(
          $1,1,$2,1,'recovery-fixture',$3,$4,'candidate','accept',$5)",
    )
    .bind(acquired.1)
    .bind(recovery_operation)
    .bind(recovery_owner)
    .bind(recovery_token)
    .bind(&terminal_decision_digest)
    .fetch_one(&mut *observed_recovery)
    .await
    .unwrap();
    assert_eq!(replay, "replay");
    let conflict: String = sqlx::query_scalar(
        "select outcome from control.finish_route_set_publication_recovery(
          $1,1,$2,1,'recovery-fixture',$3,$4,'candidate','accept',repeat('7',64))",
    )
    .bind(acquired.1)
    .bind(recovery_operation)
    .bind(recovery_owner)
    .bind(recovery_token)
    .fetch_one(&mut *observed_recovery)
    .await
    .unwrap();
    assert_eq!(conflict, "conflict");
    let recovery_terminal_state: (String, String, String, String, String, i64) = sqlx::query_as(
        "select publication.phase,global_lease.state,route_lease.state,
                publication.recovery_terminal_kind,driver.state,projection.applied_generation
         from control.workshop_route_set_publications publication
         join control.deployment_driver_resource_leases global_lease
           on global_lease.resource_key='runtime/shared-odoo'
         join control.workshop_route_application_leases route_lease
           on route_lease.workshop_id=publication.target_workshop_id
         join control.deployment_driver_operations driver on driver.id=publication.driver_operation_id
         join control.workshop_route_projection_state projection
           on projection.workshop_id=publication.target_workshop_id
         where publication.publication_id=$1",
    )
    .bind(acquired.1)
    .fetch_one(&mut *observed_recovery)
    .await
    .unwrap();
    assert_eq!(
        recovery_terminal_state,
        (
            "quarantined".into(),
            "idle".into(),
            "idle".into(),
            "candidate".into(),
            "succeeded".into(),
            2
        )
    );
    let undiscoverable: i64 = sqlx::query_scalar(
        "select count(*) from control.discover_interrupted_route_set_publications(null,100)
         where publication_id=$1",
    )
    .bind(acquired.1)
    .fetch_one(&mut *observed_recovery)
    .await
    .unwrap();
    assert_eq!(undiscoverable, 0);
    observed_recovery.rollback().await.unwrap();
    let observed_mutation = sqlx::query(
        "update control.workshop_route_set_publications
         set observed_selector='generations/boot-live',updated_at=now()
         where publication_id=$1",
    )
    .bind(acquired.1)
    .execute(store.pool())
    .await
    .unwrap_err();
    assert_eq!(
        observed_mutation
            .as_database_error()
            .and_then(|error| error.code())
            .as_deref(),
        Some("55000")
    );
    let observed_phase: (String, i64) = sqlx::query_as(
        "select publication.phase,state.applied_generation
         from control.workshop_route_set_publications publication
         join control.workshop_route_projection_state state
           on state.workshop_id=publication.target_workshop_id
         where publication.publication_id=$1",
    )
    .bind(acquired.1)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(observed_phase, ("observed".into(), 1));

    let stale_read: Vec<(Uuid,)> = sqlx::query_as(
        "select workshop_id from control.read_route_set_publication_snapshot_batch(
           $1,$2,$3,$4,$5,$6,$7,null,500)",
    )
    .bind(acquired.1)
    .bind(instance_owner)
    .bind(execution_token)
    .bind(Uuid::new_v4())
    .bind(route_token)
    .bind(acquired.3)
    .bind(acquired.4)
    .fetch_all(store.pool())
    .await
    .unwrap();
    assert!(stale_read.is_empty());
    let stale_renew: bool =
        sqlx::query_scalar("select control.renew_route_set_publication($1,$2,$3,$4,$5,$6,$7,300)")
            .bind(acquired.1)
            .bind(instance_owner)
            .bind(execution_token)
            .bind(global_token)
            .bind(route_token)
            .bind(acquired.3)
            .bind(acquired.4 + 1)
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert!(!stale_renew);
    let renewed: bool =
        sqlx::query_scalar("select control.renew_route_set_publication($1,$2,$3,$4,$5,$6,$7,300)")
            .bind(acquired.1)
            .bind(instance_owner)
            .bind(execution_token)
            .bind(global_token)
            .bind(route_token)
            .bind(acquired.3)
            .bind(acquired.4)
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert!(renewed);

    let replay: String = sqlx::query_scalar(
        "select outcome from control.admit_route_set_publication(
          $1,1,'fixture',$2,'projection','route-set-generation-two',repeat('9',64),
          2,$3,$4,$5,$6,$7,300)",
    )
    .bind(operation_id)
    .bind(workshop_id)
    .bind(&target_desired)
    .bind(instance_owner)
    .bind(execution_token)
    .bind(global_token)
    .bind(route_token)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(replay, "replay");
    let fresh_token_replay: String = sqlx::query_scalar(
        "select outcome from control.admit_route_set_publication(
          $1,1,'fixture',$2,'projection','route-set-generation-two',repeat('9',64),
          2,$3,$4,$5,$6,$7,300)",
    )
    .bind(operation_id)
    .bind(workshop_id)
    .bind(&target_desired)
    .bind(instance_owner)
    .bind(Uuid::new_v4())
    .bind(global_token)
    .bind(route_token)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(fresh_token_replay, "conflict");
    let collision: String = sqlx::query_scalar(
        "select outcome from control.admit_route_set_publication(
          $1,1,'fixture',$2,'projection','route-set-generation-two-conflict',repeat('a',64),
          2,$3,$4,$5,$6,$7,300)",
    )
    .bind(operation_id)
    .bind(workshop_id)
    .bind(&target_desired)
    .bind(instance_owner)
    .bind(execution_token)
    .bind(global_token)
    .bind(route_token)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(collision, "conflict");
    let publication_count: i64 =
        sqlx::query_scalar("select count(*) from control.workshop_route_set_publications")
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert_eq!(publication_count, 1);
    let ownership: (Uuid, i64, Uuid, i64) = sqlx::query_as(
        "select global_lease.route_set_publication_id,global_lease.fence_token,
                route_lease.route_set_publication_id,route_lease.fence_token
         from control.deployment_driver_resource_leases global_lease
         join control.workshop_route_application_leases route_lease on route_lease.workshop_id=$1
         where global_lease.resource_key='runtime/shared-odoo'",
    )
    .bind(workshop_id)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(ownership, (acquired.1, acquired.3, acquired.1, acquired.4));

    let pending: (String, Option<Uuid>, Option<Uuid>, Option<Value>) = sqlx::query_as(
        "select outcome,publication_id,driver_operation_id,response
         from control.read_route_set_publication_result($1,$2,$3,$4)",
    )
    .bind(operation_id)
    .bind(workshop_id)
    .bind("route-set-generation-two")
    .bind("9".repeat(64))
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(
        pending,
        ("pending".into(), Some(acquired.1), Some(acquired.2), None)
    );
    let absent_result: String = sqlx::query_scalar(
        "select outcome from control.read_route_set_publication_result($1,$2,$3,$4)",
    )
    .bind(operation_id)
    .bind(workshop_id)
    .bind("route-set-generation-absent")
    .bind("9".repeat(64))
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(absent_result, "absent");

    // Every caller-supplied authority component is immutable publication
    // identity. A stale value conflicts before any final state is changed.
    for stale in 0..6 {
        let row: (String, Option<Value>) = sqlx::query_as(
            "select outcome,response from control.finish_route_set_publication(
              $1,$2,$3,$4,$5,$6,$7)",
        )
        .bind(acquired.1)
        .bind(if stale == 0 {
            Uuid::new_v4()
        } else {
            instance_owner
        })
        .bind(if stale == 1 {
            Uuid::new_v4()
        } else {
            execution_token
        })
        .bind(if stale == 2 {
            Uuid::new_v4()
        } else {
            global_token
        })
        .bind(if stale == 3 {
            Uuid::new_v4()
        } else {
            route_token
        })
        .bind(if stale == 4 {
            acquired.3 + 1
        } else {
            acquired.3
        })
        .bind(if stale == 5 {
            acquired.4 + 1
        } else {
            acquired.4
        })
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(row, ("authority_lost".into(), None));
    }

    // Either half of the full frozen state CAS drifting must abort the whole
    // function, including its earlier driver-success update.
    for drift_desired in [false, true] {
        let mut drift = store.pool().begin().await.unwrap();
        if drift_desired {
            sqlx::query(
                "update control.workshop_route_projection_state
                 set desired_generation=1,desired_digest=$2,desired_disposition='present'
                 where workshop_id=$1",
            )
            .bind(workshop_id)
            .bind(&target_applied)
            .execute(&mut *drift)
            .await
            .unwrap();
        } else {
            sqlx::query(
                "update control.workshop_route_projection_state
                 set applied_rendered_digest='sha256:'||repeat('d',64)
                 where workshop_id=$1",
            )
            .bind(workshop_id)
            .execute(&mut *drift)
            .await
            .unwrap();
        }
        let error =
            sqlx::query("select * from control.finish_route_set_publication($1,$2,$3,$4,$5,$6,$7)")
                .bind(acquired.1)
                .bind(instance_owner)
                .bind(execution_token)
                .bind(global_token)
                .bind(route_token)
                .bind(acquired.3)
                .bind(acquired.4)
                .execute(&mut *drift)
                .await
                .unwrap_err();
        assert_eq!(
            error
                .as_database_error()
                .and_then(|error| error.code())
                .as_deref(),
            Some("40001")
        );
        drift.rollback().await.unwrap();
    }

    let blocked_member = Uuid::new_v4();
    let membership_blocked = sqlx::query(
        "insert into control.workshops(id,slug,display_name,time_zone)
         values($1,$2,'Blocked until finalization','UTC')",
    )
    .bind(blocked_member)
    .bind(format!("route-set-{}", blocked_member.simple()))
    .execute(store.pool())
    .await
    .unwrap_err();
    assert_eq!(
        membership_blocked
            .as_database_error()
            .and_then(|error| error.code())
            .as_deref(),
        Some("55000")
    );

    let target_rendered = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    let expected_response = json!({
        "outcome": "applied",
        "workshop_id": workshop_id,
        "route_evidence": {
            "driver_operation_id": acquired.2,
            "workshop_id": workshop_id,
            "route_generation": 2,
            "projection_digest": target_desired,
            "disposition": "absent",
            "rendered_digest": target_rendered,
            "route_fence_token": acquired.4,
        },
        "route_set_evidence": {
            "protocol_version": 1,
            "publication_id": acquired.1,
            "publication_kind": "projection",
            "selector": acquired.5,
            "route_set_digest": database_digest,
            "snapshot_count": acquired.6,
            "present_count": 1,
            "global_fence_token": acquired.3,
            "directory_device": 21,
            "directory_inode": 22,
        }
    });
    let mut direct_completion = store.pool().begin().await.unwrap();
    let direct_completion_error = sqlx::query(
        "update control.workshop_route_set_publications
         set phase='completed',finished_at=now(),final_response=$2,updated_at=now()
         where publication_id=$1",
    )
    .bind(acquired.1)
    .bind(&expected_response)
    .execute(&mut *direct_completion)
    .await
    .unwrap_err();
    assert_eq!(
        direct_completion_error
            .as_database_error()
            .and_then(|error| error.code())
            .as_deref(),
        Some("55000")
    );
    direct_completion.rollback().await.unwrap();

    let mut winning_finish = store.pool().begin().await.unwrap();
    sqlx::query(
        "select set_config('lock_timeout','5s',true),
                set_config('statement_timeout','8s',true)",
    )
    .execute(&mut *winning_finish)
    .await
    .unwrap();
    let finished: (String, Option<Value>) = sqlx::query_as(
        "select outcome,response from control.finish_route_set_publication(
          $1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(acquired.1)
    .bind(instance_owner)
    .bind(execution_token)
    .bind(global_token)
    .bind(route_token)
    .bind(acquired.3)
    .bind(acquired.4)
    .fetch_one(&mut *winning_finish)
    .await
    .unwrap();
    assert_eq!(
        finished,
        ("completed".into(), Some(expected_response.clone()))
    );

    let finish_pool = store.pool().clone();
    let concurrent_finish = tokio::spawn(async move {
        let mut transaction = finish_pool.begin().await.unwrap();
        sqlx::query(
            "select set_config('lock_timeout','5s',true),
                    set_config('statement_timeout','8s',true)",
        )
        .execute(&mut *transaction)
        .await
        .unwrap();
        let row: (String, Option<Value>) = sqlx::query_as(
            "select outcome,response from control.finish_route_set_publication(
              $1,$2,$3,$4,$5,$6,$7)",
        )
        .bind(acquired.1)
        .bind(instance_owner)
        .bind(execution_token)
        .bind(global_token)
        .bind(route_token)
        .bind(acquired.3)
        .bind(acquired.4)
        .fetch_one(&mut *transaction)
        .await
        .unwrap();
        transaction.commit().await.unwrap();
        row
    });
    let quarantine_pool = store.pool().clone();
    let concurrent_quarantine = tokio::spawn(async move {
        let mut transaction = quarantine_pool.begin().await.unwrap();
        sqlx::query(
            "select set_config('lock_timeout','5s',true),
                    set_config('statement_timeout','8s',true)",
        )
        .execute(&mut *transaction)
        .await
        .unwrap();
        let quarantined: bool = sqlx::query_scalar(
            "select control.quarantine_route_set_publication(
              $1,$2,$3,$4,$5,$6,$7,'route_set_publication_outcome_unknown')",
        )
        .bind(acquired.1)
        .bind(instance_owner)
        .bind(execution_token)
        .bind(global_token)
        .bind(route_token)
        .bind(acquired.3)
        .bind(acquired.4)
        .fetch_one(&mut *transaction)
        .await
        .unwrap();
        transaction.commit().await.unwrap();
        quarantined
    });
    let membership_pool = store.pool().clone();
    let membership_slug = format!("route-set-{}", blocked_member.simple());
    let concurrent_membership = tokio::spawn(async move {
        let mut transaction = membership_pool.begin().await.unwrap();
        sqlx::query(
            "select set_config('lock_timeout','5s',true),
                    set_config('statement_timeout','8s',true)",
        )
        .execute(&mut *transaction)
        .await
        .unwrap();
        let inserted = sqlx::query(
            "insert into control.workshops(id,slug,display_name,time_zone)
             values($1,$2,'Allowed only after terminal commit','UTC')",
        )
        .bind(blocked_member)
        .bind(membership_slug)
        .execute(&mut *transaction)
        .await
        .unwrap()
        .rows_affected();
        sqlx::query("delete from control.workshop_route_projection_state where workshop_id=$1")
            .bind(blocked_member)
            .execute(&mut *transaction)
            .await
            .unwrap();
        sqlx::query("delete from control.workshop_route_application_leases where workshop_id=$1")
            .bind(blocked_member)
            .execute(&mut *transaction)
            .await
            .unwrap();
        let deleted = sqlx::query("delete from control.workshops where id=$1")
            .bind(blocked_member)
            .execute(&mut *transaction)
            .await
            .unwrap()
            .rows_affected();
        transaction.commit().await.unwrap();
        (inserted, deleted)
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert!(!concurrent_finish.is_finished());
    assert!(!concurrent_quarantine.is_finished());
    assert!(!concurrent_membership.is_finished());
    winning_finish.commit().await.unwrap();

    let concurrent_finish_result =
        tokio::time::timeout(std::time::Duration::from_secs(10), concurrent_finish)
            .await
            .expect("concurrent exact finalizer must not deadlock")
            .unwrap();
    assert_eq!(
        concurrent_finish_result,
        ("replay".into(), Some(expected_response.clone()))
    );
    let concurrent_quarantine_result =
        tokio::time::timeout(std::time::Duration::from_secs(10), concurrent_quarantine)
            .await
            .expect("finalization and quarantine must not deadlock")
            .unwrap();
    assert!(!concurrent_quarantine_result);
    let concurrent_membership_result =
        tokio::time::timeout(std::time::Duration::from_secs(10), concurrent_membership)
            .await
            .expect("finalization and fleet membership mutation must not deadlock")
            .unwrap();
    assert_eq!(concurrent_membership_result, (1, 1));

    let post_completion_admission: String = sqlx::query_scalar(
        "select outcome from control.admit_route_set_publication(
          $1,1,'fixture',$2,'projection','route-set-generation-two',repeat('9',64),
          2,$3,$4,$5,$6,$7,300)",
    )
    .bind(operation_id)
    .bind(workshop_id)
    .bind(&target_desired)
    .bind(instance_owner)
    .bind(execution_token)
    .bind(global_token)
    .bind(route_token)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(post_completion_admission, "authority_lost");

    sqlx::query(
        "update control.operations set lease_expires_at=now()-interval '1 second'
         where id=$1",
    )
    .bind(operation_id)
    .execute(store.pool())
    .await
    .unwrap();

    let replayed: (String, Option<Value>) = sqlx::query_as(
        "select outcome,response from control.finish_route_set_publication(
          $1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(acquired.1)
    .bind(instance_owner)
    .bind(execution_token)
    .bind(global_token)
    .bind(route_token)
    .bind(acquired.3)
    .bind(acquired.4)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(replayed, ("replay".into(), Some(expected_response.clone())));
    let completed_conflict: String = sqlx::query_scalar(
        "select outcome from control.finish_route_set_publication(
          $1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(acquired.1)
    .bind(instance_owner)
    .bind(Uuid::new_v4())
    .bind(global_token)
    .bind(route_token)
    .bind(acquired.3)
    .bind(acquired.4)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(completed_conflict, "conflict");

    let result: (String, Option<Uuid>, Option<Uuid>, Option<Value>) = sqlx::query_as(
        "select outcome,publication_id,driver_operation_id,response
         from control.read_route_set_publication_result($1,$2,$3,$4)",
    )
    .bind(operation_id)
    .bind(workshop_id)
    .bind("route-set-generation-two")
    .bind("9".repeat(64))
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(
        result,
        (
            "completed".into(),
            Some(acquired.1),
            Some(acquired.2),
            Some(expected_response.clone())
        )
    );
    let conflict_result: (String, Option<Uuid>, Option<Uuid>, Option<Value>) = sqlx::query_as(
        "select outcome,publication_id,driver_operation_id,response
         from control.read_route_set_publication_result($1,$2,$3,$4)",
    )
    .bind(operation_id)
    .bind(workshop_id)
    .bind("route-set-generation-two")
    .bind("a".repeat(64))
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(conflict_result, ("conflict".into(), None, None, None));

    let final_state: (
        String,
        i64,
        String,
        String,
        Uuid,
        i64,
        String,
        String,
        i64,
        i64,
        String,
    ) = sqlx::query_as(
        "select publication.phase,state.applied_generation,state.applied_digest,
                    state.applied_disposition,state.applied_driver_operation_id,
                    state.applied_fence_token,driver.state,global_lease.state,
                    global_lease.fence_token,route_lease.fence_token,route_lease.state
             from control.workshop_route_set_publications publication
             join control.workshop_route_projection_state state
               on state.workshop_id=publication.target_workshop_id
             join control.deployment_driver_operations driver
               on driver.id=publication.driver_operation_id
             join control.deployment_driver_resource_leases global_lease
               on global_lease.resource_key='runtime/shared-odoo'
             join control.workshop_route_application_leases route_lease
               on route_lease.workshop_id=publication.target_workshop_id
             where publication.publication_id=$1",
    )
    .bind(acquired.1)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(
        final_state,
        (
            "completed".into(),
            2,
            target_desired.clone(),
            "absent".into(),
            acquired.2,
            acquired.4,
            "succeeded".into(),
            "idle".into(),
            acquired.3,
            acquired.4,
            "idle".into(),
        )
    );
    let other_head: (i64, String) = sqlx::query_as(
        "select applied_generation,applied_digest from control.workshop_route_projection_state
         where workshop_id=$1",
    )
    .bind(other_workshop)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(other_head, (1, other_applied));
    let released_authority: (bool, bool, bool, bool) = sqlx::query_as(
        "select global_lease.authority_kind is null,
                global_lease.route_set_publication_id is null,
                route_lease.authority_kind is null,
                route_lease.route_set_publication_id is null
         from control.deployment_driver_resource_leases global_lease
         join control.workshop_route_application_leases route_lease
           on route_lease.workshop_id=$1
         where global_lease.resource_key='runtime/shared-odoo'",
    )
    .bind(workshop_id)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(released_authority, (true, true, true, true));

    // A committed immutable observation admits exactly one terminal writer.
    // Concurrent exact and forged callers serialize behind that writer and
    // then observe replay and conflict respectively.
    let race_operation = Uuid::new_v4();
    let race_target_digest = format!("sha256:{}", "4".repeat(64));
    sqlx::query(
        "insert into control.operations(id,kind,queue,workshop_id,payload,correlation_id,
           idempotency_key,state,attempt,leased_by,lease_expires_at)
         values($1,'tenant.reconcile','tenant-reconciliation',$2,'{}',$3,$4,
           'in_flight',1,'race-upstream',now()+interval '10 minutes')",
    )
    .bind(race_operation)
    .bind(workshop_id)
    .bind(Uuid::new_v4())
    .bind(format!("route-set-race-upstream-{race_operation}"))
    .execute(store.pool())
    .await
    .unwrap();
    sqlx::query(
        "insert into control.workshop_route_projections(
           workshop_id,generation,projection_digest,projection,source_operation_id,
           source_operation_attempt,disposition)
         values($1,3,$2,jsonb_build_object('marker','terminal-race'),$3,1,'present')",
    )
    .bind(workshop_id)
    .bind(&race_target_digest)
    .bind(race_operation)
    .execute(store.pool())
    .await
    .unwrap();
    sqlx::query(
        "update control.workshop_route_projection_state
         set desired_generation=3,desired_digest=$2,desired_disposition='present'
         where workshop_id=$1",
    )
    .bind(workshop_id)
    .bind(&race_target_digest)
    .execute(store.pool())
    .await
    .unwrap();
    let race_instance_owner = Uuid::new_v4();
    let race_execution_token = Uuid::new_v4();
    let race_global_token = Uuid::new_v4();
    let race_route_token = Uuid::new_v4();
    let race_admission: (String, Uuid, Uuid, i64, i64) = sqlx::query_as(
        "select outcome,publication_id,driver_operation_id,global_fence_token,target_route_fence_token
         from control.admit_route_set_publication(
          $1,1,'race-upstream',$2,'projection','route-set-terminal-race',repeat('5',64),
          3,$3,$4,$5,$6,$7,300)",
    )
    .bind(race_operation)
    .bind(workshop_id)
    .bind(&race_target_digest)
    .bind(race_instance_owner)
    .bind(race_execution_token)
    .bind(race_global_token)
    .bind(race_route_token)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(race_admission.0, "acquired");
    let race_reconciliation_operation = Uuid::new_v4();
    sqlx::query(
        "insert into control.operations(id,kind,queue,workshop_id,payload,correlation_id,
           idempotency_key,state,attempt,leased_by,lease_expires_at)
         values($1,'tenant.reconcile','tenant-reconciliation',$2,
           jsonb_build_object('route_set_publication_id',$3::uuid,'protocol_version',1),
           $4,$5,'in_flight',1,'race-recovery',now()+interval '10 minutes')",
    )
    .bind(race_reconciliation_operation)
    .bind(workshop_id)
    .bind(race_admission.1)
    .bind(Uuid::new_v4())
    .bind(format!("route-set-race-recovery-{}", race_admission.1))
    .execute(store.pool())
    .await
    .unwrap();
    sqlx::query(
        "with upstream as (
           update control.operations set lease_expires_at=now()-interval '1 second' where id=$1
         ), driver as (
           update control.deployment_driver_operations set lease_expires_at=now()-interval '1 second'
           where id=$2
         ), global_lease as (
           update control.deployment_driver_resource_leases set lease_expires_at=now()-interval '1 second'
           where resource_key='runtime/shared-odoo'
         ) update control.workshop_route_application_leases
           set lease_expires_at=now()-interval '1 second' where workshop_id=$3",
    )
    .bind(race_operation)
    .bind(race_admission.2)
    .bind(workshop_id)
    .execute(store.pool())
    .await
    .unwrap();
    let race_owner = Uuid::new_v4();
    let race_token = Uuid::new_v4();
    let race_claim: (String, Option<i64>) = sqlx::query_as(
        "select outcome,claim_fence from control.claim_interrupted_route_set_publication(
          $1,$2,1,'race-recovery',$3,$4,300)",
    )
    .bind(race_admission.1)
    .bind(race_reconciliation_operation)
    .bind(race_owner)
    .bind(race_token)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(race_claim, ("acquired".into(), Some(1)));
    let race_resolution: String = sqlx::query_scalar(
        "select outcome from control.resolve_interrupted_route_set_publication_observation(
          $1,$2,$3,1,'unstarted',null,null,null,null)",
    )
    .bind(race_admission.1)
    .bind(race_owner)
    .bind(race_token)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(race_resolution, "recorded");
    let mut race_authorization = store.pool().acquire().await.unwrap();
    let race_digest = authorize_route_set_terminal_decision(
        &mut race_authorization,
        RouteSetTerminalDecisionAuthorization {
            publication_id: race_admission.1,
            claim_fence: 1,
            reconciliation_operation_id: race_reconciliation_operation,
            reconciliation_operation_attempt: 1,
            reconciliation_operation_lease_owner: "race-recovery",
            reconciliation_owner: race_owner,
            reconciliation_token: race_token,
            resolution_kind: "unstarted",
            decision: "accept",
        },
    )
    .await;
    drop(race_authorization);
    let mut race_winner = store.pool().begin().await.unwrap();
    let race_winner_outcome: String = sqlx::query_scalar(
        "select outcome from control.finish_route_set_publication_recovery(
          $1,1,$2,1,'race-recovery',$3,$4,'unstarted','accept',$5)",
    )
    .bind(race_admission.1)
    .bind(race_reconciliation_operation)
    .bind(race_owner)
    .bind(race_token)
    .bind(&race_digest)
    .fetch_one(&mut *race_winner)
    .await
    .unwrap();
    assert_eq!(race_winner_outcome, "completed");
    let exact_pool = store.pool().clone();
    let exact_digest = race_digest.clone();
    let exact_race = tokio::spawn(async move {
        sqlx::query_scalar::<_, String>(
            "select outcome from control.finish_route_set_publication_recovery(
              $1,1,$2,1,'race-recovery',$3,$4,'unstarted','accept',$5)",
        )
        .bind(race_admission.1)
        .bind(race_reconciliation_operation)
        .bind(race_owner)
        .bind(race_token)
        .bind(exact_digest)
        .fetch_one(&exact_pool)
        .await
        .unwrap()
    });
    let conflict_pool = store.pool().clone();
    let conflict_race = tokio::spawn(async move {
        sqlx::query_scalar::<_, String>(
            "select outcome from control.finish_route_set_publication_recovery(
              $1,1,$2,1,'race-recovery',$3,$4,'unstarted','accept',repeat('7',64))",
        )
        .bind(race_admission.1)
        .bind(race_reconciliation_operation)
        .bind(race_owner)
        .bind(race_token)
        .fetch_one(&conflict_pool)
        .await
        .unwrap()
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert!(!exact_race.is_finished());
    assert!(!conflict_race.is_finished());
    race_winner.commit().await.unwrap();
    assert_eq!(exact_race.await.unwrap(), "replay");
    assert_eq!(conflict_race.await.unwrap(), "conflict");

    let terminal_mutation = sqlx::query(
        "update control.workshop_route_set_publications set updated_at=now()
         where publication_id=$1",
    )
    .bind(acquired.1)
    .execute(store.pool())
    .await
    .unwrap_err();
    assert_eq!(
        terminal_mutation
            .as_database_error()
            .and_then(|error| error.code())
            .as_deref(),
        Some("55000")
    );

    store.pool().close().await;
    drop_database(&admin, &database).await;
    drop_runtime_roles(&admin).await;
}

#[tokio::test]
#[ignore = "requires a PostgreSQL 17 CONTROL_TEST_ADMIN_URL with CREATEDB"]
async fn fleet_release_reconciliation_is_function_only_and_protocol_fenced() {
    let admin_url = std::env::var("CONTROL_TEST_ADMIN_URL").expect("CONTROL_TEST_ADMIN_URL");
    let database = format!("control_fleet_reconcile_{}", Uuid::new_v4().simple());
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&admin_url)
        .await
        .unwrap();
    create_runtime_roles(&admin).await;
    sqlx::query(AssertSqlSafe(format!("create database \"{database}\"")))
        .execute(&admin)
        .await
        .unwrap();
    let store = Store::connect(&database_url(&admin_url, &database))
        .await
        .unwrap();
    store.migrate().await.unwrap();

    let driver_acl = sqlx::query_as::<_, (bool, bool, bool, bool, bool, bool)>(
        "select
           has_function_privilege('control_driver_ledger',
             'control.admit_release_driver_operation(uuid,integer,text,text,text,uuid,text,uuid,uuid,uuid,integer,smallint)','EXECUTE'),
           has_function_privilege('control_driver_ledger',
             'control.admit_fleet_release_reconciliation(uuid,integer,text,text,text,uuid,text,uuid,uuid,integer)','EXECUTE'),
           has_function_privilege('control_driver_ledger',
             'control.finish_fleet_release_reconciliation(uuid,uuid,uuid,text,jsonb)','EXECUTE'),
           has_function_privilege('control_driver_ledger',
             'control.admit_release_driver_operation(uuid,integer,text,text,text,uuid,text,uuid,uuid,uuid,integer)','EXECUTE'),
           has_function_privilege('control_driver_ledger',
             'control.admit_release_driver_operation_v2(uuid,integer,text,text,text,uuid,text,uuid,uuid,uuid,integer)','EXECUTE'),
           has_table_privilege('control_driver_ledger',
             'control.fleet_release_reconciliations','INSERT,UPDATE,DELETE')",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(driver_acl, (true, true, true, true, false, false));

    let denied = sqlx::query_as::<_, (bool, bool, bool)>(
        "select
           has_function_privilege(0::oid,
             'control.admit_fleet_release_reconciliation(uuid,integer,text,text,text,uuid,text,uuid,uuid,integer)','EXECUTE'),
           has_function_privilege('control_release_worker',
             'control.admit_fleet_release_reconciliation(uuid,integer,text,text,text,uuid,text,uuid,uuid,integer)','EXECUTE'),
           has_function_privilege('control_api',
             'control.finish_fleet_release_reconciliation(uuid,uuid,uuid,text,jsonb)','EXECUTE')",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(denied, (false, false, false));

    let protocol = sqlx::query_as::<_, (bool, bool, i64)>(
        "select
           (select not attnotnull from pg_attribute
            where attrelid='control.deployment_driver_operations'::regclass
              and attname='release_executor_protocol_version'),
           exists(select 1 from pg_trigger
             where tgrelid='control.deployment_driver_operations'::regclass
               and tgname='deployment_driver_release_executor_protocol_immutable'),
           (select count(*) from pg_constraint
            where conrelid='control.fleet_release_reconciliations'::regclass)",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert!(
        protocol.0,
        "legacy executor protocol evidence must remain NULL"
    );
    assert!(
        protocol.1,
        "executor protocol identity must be trigger-immutable"
    );
    assert!(
        protocol.2 >= 15,
        "reconciliation state is missing database constraints"
    );

    let invalid: String = sqlx::query_scalar(
        "select outcome from control.admit_release_driver_operation(
           gen_random_uuid(),1,'test','test','fleet/'||gen_random_uuid()::text,
           null,repeat('0',64),gen_random_uuid(),gen_random_uuid(),
           gen_random_uuid(),120,0::smallint)",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(invalid, "invalid");

    store.pool().close().await;
    drop_database(&admin, &database).await;
    drop_runtime_roles(&admin).await;
}

#[tokio::test]
#[ignore = "requires a PostgreSQL 17 CONTROL_TEST_ADMIN_URL with CREATEDB"]
async fn release_route_snapshot_v2_is_function_only_and_rolling_compatible() {
    let admin_url = std::env::var("CONTROL_TEST_ADMIN_URL").expect("CONTROL_TEST_ADMIN_URL");
    let database = format!("control_release_snapshot_acl_{}", Uuid::new_v4().simple());
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&admin_url)
        .await
        .unwrap();
    create_runtime_roles(&admin).await;
    sqlx::query(AssertSqlSafe(format!("create database \"{database}\"")))
        .execute(&admin)
        .await
        .unwrap();
    let store = Store::connect(&database_url(&admin_url, &database))
        .await
        .unwrap();
    store.migrate().await.unwrap();

    let acl = sqlx::query_as::<_, (bool, bool, bool, bool, bool, bool)>(
        "select
           has_function_privilege('control_driver_ledger',
             'control.admit_release_driver_operation(uuid,integer,text,text,text,uuid,text,uuid,uuid,uuid,integer,smallint,smallint)','EXECUTE'),
           has_function_privilege('control_driver_ledger',
             'control.read_fleet_release_route_snapshot_batch(uuid,uuid,uuid,uuid,bigint,uuid,integer)','EXECUTE'),
           has_function_privilege('control_driver_ledger',
             'control.admit_release_driver_operation(uuid,integer,text,text,text,uuid,text,uuid,uuid,uuid,integer,smallint)','EXECUTE'),
           has_function_privilege('control_driver_ledger',
             'control.admit_release_driver_operation(uuid,integer,text,text,text,uuid,text,uuid,uuid,uuid,integer)','EXECUTE'),
           has_table_privilege('control_driver_ledger',
             'control.fleet_release_route_snapshots','SELECT,INSERT,UPDATE,DELETE'),
           has_table_privilege('control_driver_ledger',
             'control.fleet_release_route_snapshot_items','SELECT,INSERT,UPDATE,DELETE')",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(acl, (true, true, true, true, false, false));

    let denied: (bool, bool) = sqlx::query_as(
        "select
           has_function_privilege(0::oid,
             'control.admit_release_driver_operation(uuid,integer,text,text,text,uuid,text,uuid,uuid,uuid,integer,smallint,smallint)','EXECUTE'),
           has_function_privilege('control_release_worker',
             'control.read_fleet_release_route_snapshot_batch(uuid,uuid,uuid,uuid,bigint,uuid,integer)','EXECUTE')",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(denied, (false, false));

    let shape: (bool, bool, i64, i64) = sqlx::query_as(
        "select
           exists(select 1 from pg_trigger where tgrelid=
             'control.deployment_driver_operations'::regclass
             and tgname='deployment_driver_release_route_snapshot_protocol_immutable'),
           exists(select 1 from pg_trigger where tgrelid=
             'control.fleet_release_route_snapshot_items'::regclass
             and tgname='fleet_release_route_snapshot_items_immutable'),
           (select count(*) from pg_constraint where conrelid=
             'control.fleet_release_route_snapshots'::regclass),
           (select count(*) from pg_constraint where conrelid=
             'control.fleet_release_route_snapshot_items'::regclass)",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert!(shape.0 && shape.1);
    assert!(shape.2 >= 7 && shape.3 >= 12);

    store.pool().close().await;
    drop_database(&admin, &database).await;
    drop_runtime_roles(&admin).await;
}

#[tokio::test]
#[ignore = "requires a PostgreSQL 17 CONTROL_TEST_ADMIN_URL with CREATEDB"]
async fn fleet_release_reconciliation_refuses_legacy_and_finishes_only_exact_forward_proof() {
    let admin_url = std::env::var("CONTROL_TEST_ADMIN_URL").expect("CONTROL_TEST_ADMIN_URL");
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&admin_url)
        .await
        .unwrap();
    create_runtime_roles(&admin).await;

    let legacy_database = format!("control_fleet_legacy_{}", Uuid::new_v4().simple());
    sqlx::query(AssertSqlSafe(format!(
        "create database \"{legacy_database}\""
    )))
    .execute(&admin)
    .await
    .unwrap();
    let legacy_store = Store::connect(&database_url(&admin_url, &legacy_database))
        .await
        .unwrap();
    legacy_store.migrate().await.unwrap();
    let legacy = insert_fleet_reconciliation_fixture(&legacy_store, None).await;
    let legacy_outcome: String = sqlx::query_scalar(
        "select outcome from control.admit_fleet_release_reconciliation(
           $1,1,$2,$3,$4,$5,$6,$7,$8,120)",
    )
    .bind(legacy.operation_id)
    .bind(&legacy.operation_owner)
    .bind(&legacy.idempotency_key)
    .bind(format!("fleet/{}", legacy.fleet_run_id))
    .bind(legacy.fleet_run_id)
    .bind(&legacy.request_digest)
    .bind(Uuid::new_v4())
    .bind(Uuid::new_v4())
    .fetch_one(legacy_store.pool())
    .await
    .unwrap();
    assert_eq!(legacy_outcome, "not_reconcilable");
    legacy_store.pool().close().await;
    drop_database(&admin, &legacy_database).await;

    let database = format!("control_fleet_forward_{}", Uuid::new_v4().simple());
    sqlx::query(AssertSqlSafe(format!("create database \"{database}\"")))
        .execute(&admin)
        .await
        .unwrap();
    let store = Store::connect(&database_url(&admin_url, &database))
        .await
        .unwrap();
    store.migrate().await.unwrap();
    let fixture = insert_fleet_reconciliation_fixture(&store, Some(1)).await;
    let claim_owner = Uuid::new_v4();
    let claim_token = Uuid::new_v4();
    let claim = sqlx::query_as::<
        _,
        (
            String,
            Option<Uuid>,
            Option<Uuid>,
            Option<i64>,
            Option<serde_json::Value>,
            Option<serde_json::Value>,
        ),
    >(
        "select outcome,reconciliation_id,driver_operation_id,
                original_fence_token,activation_identity,stored_response
         from control.admit_fleet_release_reconciliation(
           $1,1,$2,$3,$4,$5,$6,$7,$8,120)",
    )
    .bind(fixture.operation_id)
    .bind(&fixture.operation_owner)
    .bind(&fixture.idempotency_key)
    .bind(format!("fleet/{}", fixture.fleet_run_id))
    .bind(fixture.fleet_run_id)
    .bind(&fixture.request_digest)
    .bind(claim_owner)
    .bind(claim_token)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(claim.0, "acquired");
    assert_eq!(claim.2, Some(fixture.driver_operation_id));
    assert_eq!(claim.3, Some(42));
    let reconciliation_id = claim.1.unwrap();
    let activation_identity = claim.4.unwrap();
    assert_eq!(
        activation_identity["original_instance_owner"],
        json!(fixture.original_instance_owner)
    );
    assert_eq!(
        activation_identity["original_driver_fence_token"],
        json!(42)
    );
    assert_eq!(
        activation_identity["release_executor_protocol_version"],
        json!(1)
    );

    let null_success = sqlx::query(
        "update control.fleet_release_reconciliations set
           state='succeeded',instance_owner=null,execution_token=null,
           lease_expires_at=null,observed_at=now(),response=null,safe_error=null
         where id=$1",
    )
    .bind(reconciliation_id)
    .execute(store.pool())
    .await;
    assert!(
        null_success.is_err(),
        "a succeeded claim must carry a non-NULL object response"
    );
    let null_inconclusive_error = sqlx::query(
        "update control.fleet_release_reconciliations set
           state='inconclusive',instance_owner=null,execution_token=null,
           lease_expires_at=null,observed_at=now(),response=null,safe_error=null
         where id=$1",
    )
    .bind(reconciliation_id)
    .execute(store.pool())
    .await;
    assert!(
        null_inconclusive_error.is_err(),
        "an inconclusive claim must carry a non-NULL safe error"
    );

    let stale_finished: bool = sqlx::query_scalar(
        "select control.finish_fleet_release_reconciliation($1,$2,$3,'inconclusive',null)",
    )
    .bind(reconciliation_id)
    .bind(claim_owner)
    .bind(Uuid::new_v4())
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert!(!stale_finished, "a stale execution token must not finalize");
    let inconclusive: bool = sqlx::query_scalar(
        "select control.finish_fleet_release_reconciliation($1,$2,$3,'inconclusive',null)",
    )
    .bind(reconciliation_id)
    .bind(claim_owner)
    .bind(claim_token)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert!(inconclusive);
    let quarantined: String = sqlx::query_scalar(
        "select state from control.deployment_driver_resource_leases
         where resource_key='runtime/shared-odoo'",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(quarantined, "quarantined");

    let second_owner = Uuid::new_v4();
    let second_token = Uuid::new_v4();
    let second_outcome: String = sqlx::query_scalar(
        "select outcome from control.admit_fleet_release_reconciliation(
           $1,1,$2,$3,$4,$5,$6,$7,$8,120)",
    )
    .bind(fixture.operation_id)
    .bind(&fixture.operation_owner)
    .bind(&fixture.idempotency_key)
    .bind(format!("fleet/{}", fixture.fleet_run_id))
    .bind(fixture.fleet_run_id)
    .bind(&fixture.request_digest)
    .bind(second_owner)
    .bind(second_token)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(second_outcome, "acquired");
    sqlx::query(
        "update control.fleet_release_reconciliations
         set lease_expires_at=now()-interval '1 second'
         where id=$1",
    )
    .bind(reconciliation_id)
    .execute(store.pool())
    .await
    .unwrap();
    let final_owner = Uuid::new_v4();
    let final_token = Uuid::new_v4();
    let expiry_reclaim: String = sqlx::query_scalar(
        "select outcome from control.admit_fleet_release_reconciliation(
           $1,1,$2,$3,$4,$5,$6,$7,$8,120)",
    )
    .bind(fixture.operation_id)
    .bind(&fixture.operation_owner)
    .bind(&fixture.idempotency_key)
    .bind(format!("fleet/{}", fixture.fleet_run_id))
    .bind(fixture.fleet_run_id)
    .bind(&fixture.request_digest)
    .bind(final_owner)
    .bind(final_token)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(expiry_reclaim, "acquired");
    let expiry_evidence = sqlx::query_as::<_, (i32, bool)>(
        "select claim_expirations,last_claim_expired_at is not null
         from control.fleet_release_reconciliations where id=$1",
    )
    .bind(reconciliation_id)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(expiry_evidence.0, 1);
    assert!(expiry_evidence.1);

    let gateway_identity = json!({
        "protocol_version": 1,
        "fleet_run_id": fixture.fleet_run_id,
        "driver_action_id": fixture.driver_action_id,
        "original_driver_fence_token": 42,
        "gateway_configuration_digest": fixture.gateway_digest,
        "target_slot": "blue",
    });
    let evidence = json!({
        "release_id": fixture.release_id,
        "odoo_subject_digest": fixture.image_digest,
        "extension_subject_digest": format!("sha256:{}", "c".repeat(64)),
        "odoo_manifest_digest": format!("sha256:{}", "1".repeat(64)),
        "odoo_config_digest": format!("sha256:{}", "2".repeat(64)),
        "extension_manifest_digest": format!("sha256:{}", "3".repeat(64)),
        "extension_config_digest": format!("sha256:{}", "4".repeat(64)),
        "payload_digest": format!("sha256:{}", "5".repeat(64)),
        "extension_volume": "mb-control-ext-1111111111111111-2222222222222222",
        "pair_qualification_digest": format!("sha256:{}", "f".repeat(64)),
        "bridge_contract_digest": format!("sha256:{}", "6".repeat(64)),
        "installed_addon_versions": {},
        "runtime_key": "shared-odoo",
        "target_slot": "blue",
        "runtime_container": "mb-odoo-blue",
        "runtime_role": "mb_runtime_aaaaaaaaaaaaaaaa",
        "runtime_deployment_ref": "docker.io/odoo@sha256:fixture",
        "runtime_config_digest": format!("sha256:{}", "9".repeat(64)),
        "prepared_tenants": fixture.prepared_tenants,
        "fleet_generation": 1,
        "tenant_snapshot": fixture.tenant_snapshot,
        "gateway_configuration_digest": fixture.gateway_digest,
        "driver_action_id": fixture.driver_action_id,
        "driver_operation_id": fixture.driver_operation_id,
        "driver_fence_token": 42,
        "old_runtime_database_access_revoked": true,
        "tenant_recovery_verified": true,
        "candidate_smoke_verified": true,
        "candidate_restart_policy": "unless-stopped",
        "retained_restart_policy": "no",
    });
    assert_eq!(evidence.as_object().unwrap().len(), 30);
    let response = json!({
        "evidence": evidence,
        "reconciliation": {
            "id": reconciliation_id,
            "kind": "fleet_activation_forward",
            "protocol_version": 1,
            "external_executor_quiescent": true,
            "candidate_runtime_verified": true,
            "gateway_identity_verified": true,
            "target_database_access_verified": true,
            "old_runtime_retired": true,
            "forward_only": true,
            "original_executor": {
                "instance_owner": fixture.original_instance_owner,
                "protocol_version": 1,
            },
            "gateway_identity": gateway_identity,
        }
    });
    let succeeded: bool = sqlx::query_scalar(
        "select control.finish_fleet_release_reconciliation($1,$2,$3,'succeeded',$4)",
    )
    .bind(reconciliation_id)
    .bind(final_owner)
    .bind(final_token)
    .bind(&response)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert!(succeeded, "the exact closed forward proof must finalize");
    let terminal = sqlx::query_as::<_, (String, String, bool, bool, String, i32)>(
        "select operation.state,resource.state,
                intent.activated_at is not null,
                intent.observed_configuration_digest=intent.gateway_configuration_digest,
                reconciliation.state,reconciliation.claim_expirations
         from control.deployment_driver_operations operation
         join control.deployment_driver_resource_leases resource
           on resource.resource_key='runtime/shared-odoo'
         join control.fleet_activation_intents intent on intent.id=$2
         join control.fleet_release_reconciliations reconciliation
           on reconciliation.driver_operation_id=operation.id
         where operation.id=$1",
    )
    .bind(fixture.driver_operation_id)
    .bind(fixture.intent_id)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(
        terminal,
        (
            "succeeded".into(),
            "idle".into(),
            true,
            true,
            "succeeded".into(),
            1
        )
    );

    store.pool().close().await;
    drop_database(&admin, &database).await;
    drop_runtime_roles(&admin).await;
}

#[tokio::test]
#[ignore = "requires a PostgreSQL 17 CONTROL_TEST_ADMIN_URL with CREATEDB"]
async fn release_lease_upgrade_quarantines_legacy_in_progress_rows_before_validation() {
    let admin_url = std::env::var("CONTROL_TEST_ADMIN_URL").expect("CONTROL_TEST_ADMIN_URL");
    let database = format!("control_release_lease_upgrade_{}", Uuid::new_v4().simple());
    let admin = create_database(&admin_url, &database).await;
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&database_url(&admin_url, &database))
        .await
        .unwrap();
    for migration in [
        include_str!("../migrations/0001_control_plane_base.sql"),
        include_str!("../migrations/0002_backup_scheduler_permissions.sql"),
        include_str!("../migrations/0003_workspace_extension_volume_names.sql"),
        include_str!("../migrations/0004_paperless_runtime_spec.sql"),
        include_str!("../migrations/0005_tenant_api_identity.sql"),
        include_str!("../migrations/0006_outbox_tenant_ownership.sql"),
        include_str!("../migrations/0007_lifecycle_resource_ownership.sql"),
        include_str!("../migrations/0008_scheduler_rehearsal_leases.sql"),
        include_str!("../migrations/0009_driver_idempotency_scope.sql"),
    ] {
        sqlx::raw_sql(migration).execute(&pool).await.unwrap();
    }
    let key = format!("legacy-release:{}", Uuid::new_v4());
    sqlx::query(
        "insert into control.deployment_driver_operations(
           idempotency_key,workshop_id,action,request_digest,state
         ) values($1,null,'release',$2,'in_progress')",
    )
    .bind(&key)
    .bind("a".repeat(64))
    .execute(&pool)
    .await
    .unwrap();
    sqlx::raw_sql(include_str!("../migrations/0010_release_driver_lease.sql"))
        .execute(&pool)
        .await
        .expect("legacy unknown release execution must not block the lease migration");
    let row = sqlx::query_as::<_, (Uuid, String, Option<Uuid>)>(
        "select id,safe_error,execution_token
         from control.deployment_driver_operations where idempotency_key=$1",
    )
    .bind(&key)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_ne!(row.0, Uuid::nil());
    assert_eq!(row.1, "runtime_outcome_unknown");
    assert_eq!(row.2, None);
    let resource = sqlx::query_as::<_, (String, Option<Uuid>, String)>(
        "select state,driver_operation_id,safe_error
         from control.deployment_driver_resource_leases
         where resource_key='runtime/shared-odoo'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(resource.0, "quarantined");
    assert_eq!(resource.1, Some(row.0));
    assert_eq!(resource.2, "runtime_outcome_unknown");

    pool.close().await;
    drop_database(&admin, &database).await;
}

#[tokio::test]
#[ignore = "requires a PostgreSQL 17 CONTROL_TEST_ADMIN_URL with CREATEDB"]
async fn release_lease_upgrade_refuses_unfenced_successful_history() {
    let admin_url = std::env::var("CONTROL_TEST_ADMIN_URL").expect("CONTROL_TEST_ADMIN_URL");
    let database = format!("control_release_lease_refusal_{}", Uuid::new_v4().simple());
    let admin = create_database(&admin_url, &database).await;
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&database_url(&admin_url, &database))
        .await
        .unwrap();
    for migration in [
        include_str!("../migrations/0001_control_plane_base.sql"),
        include_str!("../migrations/0002_backup_scheduler_permissions.sql"),
        include_str!("../migrations/0003_workspace_extension_volume_names.sql"),
        include_str!("../migrations/0004_paperless_runtime_spec.sql"),
        include_str!("../migrations/0005_tenant_api_identity.sql"),
        include_str!("../migrations/0006_outbox_tenant_ownership.sql"),
        include_str!("../migrations/0007_lifecycle_resource_ownership.sql"),
        include_str!("../migrations/0008_scheduler_rehearsal_leases.sql"),
        include_str!("../migrations/0009_driver_idempotency_scope.sql"),
    ] {
        sqlx::raw_sql(migration).execute(&pool).await.unwrap();
    }
    let release_id = format!("odoo-legacy-{}", Uuid::new_v4().simple());
    sqlx::query(
        "insert into control.deployment_driver_operations(
           idempotency_key,workshop_id,action,request_digest,state,response
         ) values($1,null,'release',$2,'succeeded',$3)",
    )
    .bind(format!("release-initial:{release_id}"))
    .bind("b".repeat(64))
    .bind(json!({"evidence":{"release_id":release_id}}))
    .execute(&pool)
    .await
    .unwrap();

    let error = sqlx::raw_sql(include_str!("../migrations/0010_release_driver_lease.sql"))
        .execute(&pool)
        .await
        .expect_err("an unfenced success must require pre-deploy reconciliation");
    assert!(
        error
            .to_string()
            .contains("unfenced successful historical release receipt"),
        "unexpected migration refusal: {error}"
    );

    pool.close().await;
    drop_database(&admin, &database).await;
}

#[tokio::test]
#[ignore = "requires a PostgreSQL 17 CONTROL_TEST_ADMIN_URL with CREATEDB"]
async fn old_epoch_ledger_fails_closed_without_modification() {
    let admin_url = std::env::var("CONTROL_TEST_ADMIN_URL").expect("CONTROL_TEST_ADMIN_URL");
    let database = format!("control_old_epoch_{}", Uuid::new_v4().simple());
    let admin = create_database(&admin_url, &database).await;
    let url = database_url(&admin_url, &database);
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    sqlx::query(
        "create table public._sqlx_migrations(
            version bigint primary key,description text not null,
            installed_on timestamptz not null default now(),success boolean not null,
            checksum bytea not null,execution_time bigint not null
         )",
    )
    .execute(&pool)
    .await
    .unwrap();
    let old_checksum = vec![0_u8; 48];
    sqlx::query(
        "insert into public._sqlx_migrations
         (version,description,success,checksum,execution_time)
         values(1,'control plane',true,$1,1)",
    )
    .bind(&old_checksum)
    .execute(&pool)
    .await
    .unwrap();
    pool.close().await;

    let store = Store::connect(&url).await.unwrap();
    let error = store
        .migrate()
        .await
        .expect_err("old epoch must fail closed");
    assert!(
        error
            .to_string()
            .contains("previously applied but has been modified"),
        "unexpected migration refusal: {error:#}"
    );
    let ledger =
        sqlx::query_as::<_, (i64, Vec<u8>)>("select version,checksum from public._sqlx_migrations")
            .fetch_all(store.pool())
            .await
            .unwrap();
    assert_eq!(ledger, vec![(1, old_checksum)]);
    let schema_created: bool = sqlx::query_scalar(
        "select exists(select 1 from information_schema.schemata where schema_name='control')",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert!(!schema_created, "refusal must happen before baseline DDL");
    store.pool().close().await;
    drop_database(&admin, &database).await;
}

#[tokio::test]
#[ignore = "requires a PostgreSQL 17 CONTROL_TEST_ADMIN_URL with CREATEDB"]
async fn flat_writer_guardrails_are_protocol_first_and_runtime_closed() {
    let admin_url = std::env::var("CONTROL_TEST_ADMIN_URL").expect("CONTROL_TEST_ADMIN_URL");
    let database = format!("control_flat_guard_{}", Uuid::new_v4().simple());
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&admin_url)
        .await
        .unwrap();
    create_runtime_roles(&admin).await;
    sqlx::query(AssertSqlSafe(format!("create database \"{database}\"")))
        .execute(&admin)
        .await
        .unwrap();
    let store = Store::connect(&database_url(&admin_url, &database))
        .await
        .unwrap();
    store.migrate().await.unwrap();
    let dormant_gate: (String, bool, bool, bool, bool, i64, bool) = sqlx::query_as(
        "select mode,normal_ready,recovery_ready,startup_ready,release_ready,
                activation_epoch,activated_at is null
         from control.route_set_publication_protocol_state where singleton",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(
        dormant_gate,
        ("flat_v1".into(), false, false, false, false, 0, true)
    );

    // Invalid vectors are mutation-free and exercise delegation without a
    // large fixture. Their outcomes are the vocabulary consumed by the old
    // driver call sites, and must remain identical in flat_v1.
    let flat_vectors = [
        (
            "select outcome from control.admit_workshop_route_application(null,0,null,null,null,null,null,0,null,null,null,null,0)",
            "select outcome from control.admit_workshop_route_application_flat_v1(null,0,null,null,null,null,null,0,null,null,null,null,0)",
            "upstream_lease_lost",
        ),
        (
            "select outcome from control.admit_workshop_route_maintenance(null,0,null,null,null,null,null,null,null,null,0)",
            "select outcome from control.admit_workshop_route_maintenance_flat_v1(null,0,null,null,null,null,null,null,null,null,0)",
            "invalid",
        ),
        (
            "select outcome from control.admit_startup_route_rebuild(null,null,null,null,null,null,null,0)",
            "select outcome from control.admit_startup_route_rebuild_flat_v1(null,null,null,null,null,null,null,0)",
            "invalid",
        ),
        (
            "select outcome from control.admit_staged_startup_route_publication(null,null,null,null,null,null,null,0,1::smallint)",
            "select outcome from control.admit_startup_route_rebuild_flat_v1(null,null,null,null,null,null,null,0)",
            "invalid",
        ),
        (
            "select outcome from control.claim_interrupted_startup_route_publication(null,null,0)",
            "select outcome from control.claim_interrupted_startup_route_publication_flat_v1(null,null,0)",
            "invalid",
        ),
        (
            "select outcome from control.claim_workshop_route_maintenance_exit(null,null,0,null,null,null,null,0)",
            "select outcome from control.claim_workshop_route_maintenance_exit_flat_v1(null,null,0,null,null,null,null,0)",
            "invalid",
        ),
        (
            "select outcome from control.admit_release_driver_operation(null,0,null,null,null,null,null,null,null,null,0)",
            "select outcome from control.admit_release_driver_operation_flat_v1(null,0,null,null,null,null,null,null,null,null,0)",
            "invalid",
        ),
        (
            "select outcome from control.admit_release_driver_operation(null,0,null,null,null,null,null,null,null,null,0,1::smallint)",
            "select outcome from control.admit_release_driver_operation_flat_v1(null,0,null,null,null,null,null,null,null,null,0,1::smallint)",
            "invalid",
        ),
        (
            "select outcome from control.admit_release_driver_operation(null,0,null,null,null,null,null,null,null,null,0,1::smallint,1::smallint)",
            "select outcome from control.admit_release_driver_operation_flat_v1(null,0,null,null,null,null,null,null,null,null,0,1::smallint,1::smallint)",
            "invalid",
        ),
        (
            "select outcome from control.admit_initial_release_reconciliation(null,0,null,null,null,null,null,null,0)",
            "select outcome from control.admit_initial_release_reconciliation_flat_v1(null,0,null,null,null,null,null,null,0)",
            "invalid",
        ),
        (
            "select outcome from control.admit_fleet_release_reconciliation(null,0,null,null,null,null,null,null,null,0)",
            "select outcome from control.admit_fleet_release_reconciliation_flat_v1(null,0,null,null,null,null,null,null,null,0)",
            "invalid",
        ),
        (
            "select outcome from control.admit_immutable_release_route_publication(null,null,null,null,null,0,0)",
            "select outcome from control.admit_immutable_release_route_publication_flat_v1(null,null,null,null,null,0,0)",
            "invalid",
        ),
    ];
    for (public_sql, internal_sql, expected) in flat_vectors {
        let public: String = sqlx::query_scalar(public_sql)
            .fetch_one(store.pool())
            .await
            .unwrap();
        let internal: String = sqlx::query_scalar(internal_sql)
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(public, internal);
        assert_eq!(public, expected);
    }

    let internal_acl_violations: i64 = sqlx::query_scalar(
        "select count(*) from unnest(array[
           'control_api','control_tenant_api','control_membership_worker',
           'control_provisioning_worker','control_invoice_worker','control_inventory_worker',
           'control_email_worker','control_reconciliation_worker','control_lifecycle_worker',
           'control_backup_scheduler','control_driver_ledger','control_release_worker',
           'control_privacy_worker']) role_name
         cross join (select p.oid from pg_proc p join pg_namespace n on n.oid=p.pronamespace
           where n.nspname='control' and (p.proname like 'admit%\\_flat\\_v1' escape '\\'
             or p.proname like 'claim%\\_flat\\_v1' escape '\\')) guarded
         where has_function_privilege(role_name,guarded.oid,'execute')",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(internal_acl_violations, 0);
    let public_acl_count: i64 = sqlx::query_scalar(
        "select count(*) from pg_proc p join pg_namespace n on n.oid=p.pronamespace
         where n.nspname='control'
           and p.proname in ('admit_workshop_route_application','admit_workshop_route_maintenance',
             'admit_startup_route_rebuild','admit_release_driver_operation',
             'admit_initial_release_reconciliation','admit_fleet_release_reconciliation',
             'admit_immutable_release_route_publication',
             'claim_interrupted_startup_route_publication',
             'claim_workshop_route_maintenance_exit')
           and has_function_privilege('control_driver_ledger',p.oid,'execute')
           and not has_function_privilege('control_api',p.oid,'execute')",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(
        public_acl_count, 11,
        "all public overloads stay driver-only"
    );

    let mut runtime = store.pool().begin().await.unwrap();
    sqlx::query("set local role control_driver_ledger")
        .execute(&mut *runtime)
        .await
        .unwrap();
    let runtime_outcome: String = sqlx::query_scalar(
        "select outcome from control.admit_workshop_route_application(null,0,null,null,null,null,null,0,null,null,null,null,0)",
    ).fetch_one(&mut *runtime).await.unwrap();
    assert_eq!(
        runtime_outcome, "upstream_lease_lost",
        "SECURITY DEFINER wrapper must retain operational access to its private delegate"
    );
    runtime.rollback().await.unwrap();
    let mut forbidden = store.pool().begin().await.unwrap();
    sqlx::query("set local role control_driver_ledger")
        .execute(&mut *forbidden)
        .await
        .unwrap();
    let direct_internal = sqlx::query_scalar::<_, String>(
        "select outcome from control.admit_workshop_route_application_flat_v1(null,0,null,null,null,null,null,0,null,null,null,null,0)",
    ).fetch_one(&mut *forbidden).await.unwrap_err();
    assert_eq!(
        direct_internal
            .as_database_error()
            .and_then(|error| error.code())
            .as_deref(),
        Some("42501")
    );
    forbidden.rollback().await.unwrap();

    let before: (i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64) = sqlx::query_as(
        "select (select count(*) from control.deployment_driver_operations),
          (select count(*) from control.workshop_route_effect_runs),
          (select count(*) from control.workshop_route_startup_publications),
          (select count(*) from control.release_driver_reconciliations),
          (select count(*) from control.fleet_release_reconciliations),
          (select count(*) from control.fleet_release_route_publications),
          (select count(*) from control.fleet_release_route_publication_owners),
          (select count(*) from control.fleet_release_route_snapshots),
          (select count(*) from control.workshop_route_effect_reservations),
          (select count(*) from control.workshop_route_application_leases),
          (select count(*) from control.deployment_driver_resource_leases)",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();

    // Hold the singleton while an old admission begins. It must wait, then see
    // the mode committed by the activation transaction and refuse.
    let mut activation = store.pool().begin().await.unwrap();
    sqlx::query(
        "select mode from control.route_set_publication_protocol_state where singleton for update",
    )
    .execute(&mut *activation)
    .await
    .unwrap();
    let pool = store.pool().clone();
    let mut admission = tokio::spawn(async move {
        sqlx::query_scalar::<_, String>(
            "select outcome from control.admit_workshop_route_application(null,0,null,null,null,null,null,0,null,null,null,null,0)",
        ).fetch_one(&pool).await.unwrap()
    });
    let pool = store.pool().clone();
    let mut startup_recovery =
        tokio::spawn(async move {
            sqlx::query_scalar::<_, String>(
            "select outcome from control.claim_interrupted_startup_route_publication(null,null,0)",
        ).fetch_one(&pool).await.unwrap()
        });
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), &mut admission)
            .await
            .is_err(),
        "legacy admission must serialize behind the protocol row"
    );
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), &mut startup_recovery)
            .await
            .is_err(),
        "legacy recovery claim must serialize behind the protocol row"
    );
    sqlx::query(
        "update control.route_set_publication_protocol_state set
          mode='activating_v1',normal_ready=true,recovery_ready=true,startup_ready=true,
          release_ready=true,activation_epoch=1,updated_at=now() where singleton",
    )
    .execute(&mut *activation)
    .await
    .unwrap();
    activation.commit().await.unwrap();
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(10), admission)
            .await
            .unwrap()
            .unwrap(),
        "fleet_busy"
    );
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(10), startup_recovery)
            .await
            .unwrap()
            .unwrap(),
        "none"
    );

    let refused_vectors = [
        (
            "select outcome from control.admit_workshop_route_application(null,0,null,null,null,null,null,0,null,null,null,null,0)",
            "fleet_busy",
        ),
        (
            "select outcome from control.admit_workshop_route_maintenance(null,0,null,null,null,null,null,null,null,null,0)",
            "fleet_busy",
        ),
        (
            "select outcome from control.admit_startup_route_rebuild(null,null,null,null,null,null,null,0)",
            "busy",
        ),
        (
            "select outcome from control.admit_staged_startup_route_publication(null,null,null,null,null,null,null,0,1::smallint)",
            "busy",
        ),
        (
            "select outcome from control.claim_interrupted_startup_route_publication(null,null,0)",
            "none",
        ),
        (
            "select outcome from control.claim_workshop_route_maintenance_exit(null,null,0,null,null,null,null,0)",
            "fleet_busy",
        ),
        (
            "select outcome from control.admit_release_driver_operation(null,0,null,null,null,null,null,null,null,null,0)",
            "busy",
        ),
        (
            "select outcome from control.admit_release_driver_operation(null,0,null,null,null,null,null,null,null,null,0,1::smallint)",
            "busy",
        ),
        (
            "select outcome from control.admit_release_driver_operation(null,0,null,null,null,null,null,null,null,null,0,1::smallint,1::smallint)",
            "busy",
        ),
        (
            "select outcome from control.admit_initial_release_reconciliation(null,0,null,null,null,null,null,null,0)",
            "busy",
        ),
        (
            "select outcome from control.admit_fleet_release_reconciliation(null,0,null,null,null,null,null,null,null,0)",
            "busy",
        ),
        (
            "select outcome from control.admit_immutable_release_route_publication(null,null,null,null,null,0,0)",
            "protocol_conflict",
        ),
    ];
    for mode in ["activating_v1", "generation_v1"] {
        if mode == "generation_v1" {
            sqlx::query("update control.route_set_publication_protocol_state set mode=$1,activated_at=now(),updated_at=now() where singleton")
                .bind(mode).execute(store.pool()).await.unwrap();
        }
        for (sql, expected) in refused_vectors {
            let outcome: String = sqlx::query_scalar(sql)
                .fetch_one(store.pool())
                .await
                .unwrap();
            assert_eq!(outcome, expected, "wrong refusal in {mode}");
        }
    }
    let after: (i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64) = sqlx::query_as(
        "select (select count(*) from control.deployment_driver_operations),
          (select count(*) from control.workshop_route_effect_runs),
          (select count(*) from control.workshop_route_startup_publications),
          (select count(*) from control.release_driver_reconciliations),
          (select count(*) from control.fleet_release_reconciliations),
          (select count(*) from control.fleet_release_route_publications),
          (select count(*) from control.fleet_release_route_publication_owners),
          (select count(*) from control.fleet_release_route_snapshots),
          (select count(*) from control.workshop_route_effect_reservations),
          (select count(*) from control.workshop_route_application_leases),
          (select count(*) from control.deployment_driver_resource_leases)",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(
        after, before,
        "non-flat refusal must not mutate writer state"
    );

    store.pool().close().await;
    drop_database(&admin, &database).await;
    drop_runtime_roles(&admin).await;
}

#[tokio::test]
#[ignore = "requires a PostgreSQL 17 CONTROL_TEST_ADMIN_URL with CREATEDB"]
async fn recovery_route_set_publication_entry_restore_and_replay_are_exact() {
    let admin_url = std::env::var("CONTROL_TEST_ADMIN_URL").expect("CONTROL_TEST_ADMIN_URL");
    let database = format!("control_recovery_route_set_{}", Uuid::new_v4().simple());
    let admin = create_database(&admin_url, &database).await;
    let store = Store::connect(&database_url(&admin_url, &database))
        .await
        .unwrap();
    store.migrate().await.unwrap();
    sqlx::query(
        "update control.route_set_publication_protocol_state set mode='generation_v1',
         normal_ready=true,recovery_ready=true,startup_ready=true,release_ready=true,
         activation_epoch=1,activated_at=now(),updated_at=now() where singleton",
    )
    .execute(store.pool())
    .await
    .unwrap();
    let workshop = Uuid::new_v4();
    let operation = Uuid::new_v4();
    let projection_digest = format!("sha256:{}", "1".repeat(64));
    let applied_rendered = format!("sha256:{}", "2".repeat(64));
    sqlx::query("insert into control.workshops(id,slug,display_name,time_zone) values($1,$2,'Recovery route set','UTC')")
        .bind(workshop).bind(format!("recovery-route-{}", workshop.simple()))
        .execute(store.pool()).await.unwrap();
    sqlx::query(
        "insert into control.operations(id,kind,queue,workshop_id,payload,correlation_id,
         idempotency_key,state,attempt,leased_by,lease_expires_at)
         values($1,'tenant.lifecycle','tenant-lifecycle',$2,'{}',$3,$4,'in_flight',1,
         'recovery-fixture',now()+interval '10 minutes')",
    )
    .bind(operation)
    .bind(workshop)
    .bind(Uuid::new_v4())
    .bind(format!("recovery-route-operation-{operation}"))
    .execute(store.pool())
    .await
    .unwrap();
    sqlx::query(
        "insert into control.workshop_route_projections(workshop_id,generation,projection_digest,
         projection,source_operation_id,source_operation_attempt,disposition)
         values($1,1,$2,jsonb_build_object('marker','applied'),$3,1,'present')",
    )
    .bind(workshop)
    .bind(&projection_digest)
    .bind(operation)
    .execute(store.pool())
    .await
    .unwrap();
    let prior_driver: Uuid = sqlx::query_scalar(
        "insert into control.deployment_driver_operations(idempotency_key,workshop_id,action,
         request_digest,state,response,target_key,route_generation,route_projection_digest,route_fence_token)
         values($1,$2,'route-project',repeat('3',64),'succeeded','{}','route/'||$2::text,1,$3,1)
         returning id",
    )
    .bind(format!("recovery-prior-{workshop}")).bind(workshop).bind(&projection_digest)
    .fetch_one(store.pool()).await.unwrap();
    sqlx::query(
        "update control.workshop_route_projection_state set desired_generation=1,desired_digest=$2,
         desired_disposition='present',applied_generation=1,applied_digest=$2,
         applied_disposition='present',applied_rendered_digest=$3,
         applied_driver_operation_id=$4,applied_effect_run_id=null,applied_fence_token=1 where workshop_id=$1",
    )
    .bind(workshop).bind(&projection_digest).bind(&applied_rendered).bind(prior_driver)
    .execute(store.pool()).await.unwrap();

    let instance = Uuid::new_v4();
    let execution = Uuid::new_v4();
    let global_token = Uuid::new_v4();
    let route_token = Uuid::new_v4();
    let mut null_desired_probe = store.pool().begin().await.unwrap();
    sqlx::query(
        "update control.workshop_route_projection_state set desired_generation=null,
         desired_digest=null,desired_disposition=null where workshop_id=$1",
    )
    .bind(workshop)
    .execute(&mut *null_desired_probe)
    .await
    .unwrap();
    let null_desired: String = sqlx::query_scalar(
        "select outcome from control.admit_route_set_recovery_maintenance(
         $1,1,'recovery-fixture',$2,'restore','null-desired',repeat('8',64),$3,$4,$5,$6,300)",
    )
    .bind(operation)
    .bind(workshop)
    .bind(instance)
    .bind(execution)
    .bind(global_token)
    .bind(route_token)
    .fetch_one(&mut *null_desired_probe)
    .await
    .unwrap();
    assert_eq!(null_desired, "fleet_not_ready");
    let null_desired_effects: i64 = sqlx::query_scalar(
        "select count(*) from control.workshop_route_effect_runs where idempotency_key='null-desired'",
    )
    .fetch_one(&mut *null_desired_probe).await.unwrap();
    assert_eq!(
        null_desired_effects, 0,
        "refusal must not reserve recovery authority"
    );
    null_desired_probe.rollback().await.unwrap();
    let maintenance: RecoveryPublicationAdmissionRow = sqlx::query_as(
        "select * from control.admit_route_set_recovery_maintenance(
             $1,1,'recovery-fixture',$2,'restore','recovery-entry',repeat('4',64),$3,$4,$5,$6,300)",
    )
    .bind(operation)
    .bind(workshop)
    .bind(instance)
    .bind(execution)
    .bind(global_token)
    .bind(route_token)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(maintenance.0, "acquired");
    assert_eq!(maintenance.3, workshop);
    let fast_busy: String = sqlx::query_scalar(
        "select outcome from control.read_route_set_recovery_maintenance_admission(
         $1,$2,1,'recovery-fixture','recovery-entry',repeat('4',64))",
    )
    .bind(workshop)
    .bind(operation)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(fast_busy, "busy");
    let snapshot: (Uuid, i64, String, String, String) = sqlx::query_as(
        "select workshop_id,generation,projection_digest,disposition,applied_rendered_digest
         from control.read_route_set_publication_snapshot_batch($1,$2,$3,$4,$5,$6,$7,null,500)",
    )
    .bind(maintenance.1)
    .bind(instance)
    .bind(execution)
    .bind(global_token)
    .bind(route_token)
    .bind(maintenance.4)
    .bind(maintenance.5)
    .fetch_one(store.pool())
    .await
    .unwrap();
    let startup_prior_effect = Uuid::new_v4();
    let startup_prior_selector = format!("generations/startup-{startup_prior_effect}");
    let startup_prior_identity = json!({
        "effect_run_id": startup_prior_effect,
        "sealed_digest": format!("sha256:{}", "0".repeat(64)),
    });
    let prior: String = sqlx::query_scalar(
        "select control.record_route_set_publication_prior($1,$2,$3,$4,$5,$6,$7,$8,1,2,$9)",
    )
    .bind(maintenance.1)
    .bind(instance)
    .bind(execution)
    .bind(global_token)
    .bind(route_token)
    .bind(maintenance.4)
    .bind(maintenance.5)
    .bind(&startup_prior_selector)
    .bind(&startup_prior_identity)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(prior, "recorded");
    let maintenance_rendered = format!("sha256:{}", "5".repeat(64));
    let recorded: String = sqlx::query_scalar(
        "select control.record_route_set_publication_entry($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
    )
    .bind(maintenance.1).bind(instance).bind(execution).bind(global_token).bind(route_token)
    .bind(maintenance.4).bind(maintenance.5).bind(snapshot.0).bind(snapshot.1).bind(&snapshot.2)
    .bind(&snapshot.3).bind(&snapshot.4).bind(&maintenance_rendered)
    .fetch_one(store.pool()).await.unwrap();
    assert_eq!(recorded, "recorded");
    let digest: String = sqlx::query_scalar("select control.route_set_publication_digest($1)")
        .bind(maintenance.1)
        .fetch_one(store.pool())
        .await
        .unwrap();
    let sealed: String = sqlx::query_scalar(
        "select control.seal_route_set_publication($1,$2,$3,$4,$5,$6,$7,$8,21,22,1,1,$9)",
    )
    .bind(maintenance.1)
    .bind(instance)
    .bind(execution)
    .bind(global_token)
    .bind(route_token)
    .bind(maintenance.4)
    .bind(maintenance.5)
    .bind(&maintenance.6)
    .bind(&digest)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(sealed, "sealed");
    let started: String =
        sqlx::query_scalar("select control.start_route_set_publication($1,$2,$3,$4,$5,$6,$7)")
            .bind(maintenance.1)
            .bind(instance)
            .bind(execution)
            .bind(global_token)
            .bind(route_token)
            .bind(maintenance.4)
            .bind(maintenance.5)
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert_eq!(started, "started");
    let identity = json!({"protocol_version":1,"publication_id":maintenance.1,
        "publication_kind":"recovery_maintenance","global_fence_token":maintenance.4,
        "target_workshop_id":workshop,"target_route_fence_token":maintenance.5,"route_set_digest":digest});
    let observed: String = sqlx::query_scalar(
        "select control.observe_route_set_publication($1,$2,$3,$4,$5,$6,$7,$8,21,22,$9)",
    )
    .bind(maintenance.1)
    .bind(instance)
    .bind(execution)
    .bind(global_token)
    .bind(route_token)
    .bind(maintenance.4)
    .bind(maintenance.5)
    .bind(&maintenance.6)
    .bind(&identity)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(observed, "observed");
    let next_digest = format!("sha256:{}", "6".repeat(64));
    sqlx::query(
        "insert into control.workshop_route_projections(workshop_id,generation,projection_digest,
         projection,source_operation_id,source_operation_attempt,disposition)
         values($1,2,$2,jsonb_build_object('marker','desired-after-entry'),$3,1,'present')",
    )
    .bind(workshop)
    .bind(&next_digest)
    .bind(operation)
    .execute(store.pool())
    .await
    .unwrap();
    sqlx::query("update control.workshop_route_projection_state set desired_generation=2,desired_digest=$2 where workshop_id=$1")
        .bind(workshop).bind(&next_digest).execute(store.pool()).await.unwrap();
    let finished: (String, Value) = sqlx::query_as(
        "select outcome,response from control.finish_route_set_recovery_publication($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(maintenance.1).bind(instance).bind(execution).bind(global_token).bind(route_token)
    .bind(maintenance.4).bind(maintenance.5).fetch_one(store.pool()).await.unwrap();
    assert_eq!(finished.0, "completed");
    assert_eq!(finished.1["outcome"], "maintenance");
    assert_eq!(finished.1["route_fence_token"], maintenance.5);
    assert_eq!(finished.1["route_evidence"].as_object().unwrap().len(), 8);
    let applied_after_entry: (i64, String, Uuid) = sqlx::query_as(
        "select applied_generation,applied_digest,applied_driver_operation_id
         from control.workshop_route_projection_state where workshop_id=$1",
    )
    .bind(workshop)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(
        applied_after_entry,
        (1, projection_digest.clone(), prior_driver)
    );
    let entry_replay: (String, Option<Value>) = sqlx::query_as(
        "select outcome,stored_response from control.admit_route_set_recovery_maintenance(
         $1,1,'recovery-fixture',$2,'restore','recovery-entry',repeat('4',64),$3,$4,$5,$6,300)",
    )
    .bind(operation)
    .bind(workshop)
    .bind(instance)
    .bind(execution)
    .bind(global_token)
    .bind(route_token)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(entry_replay, ("replay".into(), Some(finished.1.clone())));

    let restore_instance = Uuid::new_v4();
    let restore_execution = Uuid::new_v4();
    let restore_global = Uuid::new_v4();
    let restore_route = Uuid::new_v4();
    let restore: RecoveryPublicationAdmissionRow =
        sqlx::query_as("select * from control.admit_route_set_recovery_restore($1,$2,$3,1,'recovery-fixture',$4,$5,$6,$7,300)")
        .bind(maintenance.2).bind(workshop).bind(operation).bind(restore_instance)
        .bind(restore_execution).bind(restore_global).bind(restore_route)
        .fetch_one(store.pool()).await.unwrap();
    assert_eq!(restore.0, "acquired");
    assert_eq!(
        restore.5, maintenance.5,
        "restore reuses the maintenance route fence"
    );

    let mut terminal_retry = store.pool().begin().await.unwrap();
    sqlx::query(
        "update control.deployment_driver_resource_leases set lease_expires_at=now()-interval '1 second'
         where resource_key='runtime/shared-odoo'",
    )
    .execute(&mut *terminal_retry).await.unwrap();
    let quarantined: bool = sqlx::query_scalar(
        "select control.quarantine_route_set_publication(
         $1,$2,$3,$4,$5,$6,$7,'route_set_publication_outcome_unknown')",
    )
    .bind(restore.1)
    .bind(restore_instance)
    .bind(restore_execution)
    .bind(restore_global)
    .bind(restore_route)
    .bind(restore.4)
    .bind(restore.5)
    .fetch_one(&mut *terminal_retry)
    .await
    .unwrap();
    assert!(quarantined);
    let reconciliation_operation = Uuid::new_v4();
    sqlx::query(
        "insert into control.operations(id,kind,queue,workshop_id,payload,correlation_id,
         idempotency_key,state,attempt,leased_by,lease_expires_at)
         values($1,'tenant.reconcile','tenant-reconciliation',$2,$3,$4,$5,'in_flight',1,
         'terminal-fixture',now()+interval '10 minutes')",
    )
    .bind(reconciliation_operation)
    .bind(workshop)
    .bind(json!({"route_set_publication_id": restore.1, "protocol_version": 1}))
    .bind(Uuid::new_v4())
    .bind(format!("terminal-retry-{}", restore.1))
    .execute(&mut *terminal_retry)
    .await
    .unwrap();
    let reconciliation_owner = Uuid::new_v4();
    let reconciliation_token = Uuid::new_v4();
    let claim: (String, Option<i64>) = sqlx::query_as(
        "select outcome,claim_fence from control.claim_interrupted_route_set_publication(
         $1,$2,1,'terminal-fixture',$3,$4,300)",
    )
    .bind(restore.1)
    .bind(reconciliation_operation)
    .bind(reconciliation_owner)
    .bind(reconciliation_token)
    .fetch_one(&mut *terminal_retry)
    .await
    .unwrap();
    assert_eq!(claim, ("acquired".into(), Some(1)));
    let resolved: String = sqlx::query_scalar(
        "select outcome from control.resolve_interrupted_route_set_publication_observation(
         $1,$2,$3,1,'unstarted',null,null,null,null)",
    )
    .bind(restore.1)
    .bind(reconciliation_owner)
    .bind(reconciliation_token)
    .fetch_one(&mut *terminal_retry)
    .await
    .unwrap();
    assert_eq!(resolved, "recorded");
    let decision_digest = authorize_route_set_terminal_decision(
        &mut terminal_retry,
        RouteSetTerminalDecisionAuthorization {
            publication_id: restore.1,
            claim_fence: 1,
            reconciliation_operation_id: reconciliation_operation,
            reconciliation_operation_attempt: 1,
            reconciliation_operation_lease_owner: "terminal-fixture",
            reconciliation_owner,
            reconciliation_token,
            resolution_kind: "unstarted",
            decision: "accept",
        },
    )
    .await;
    let terminal: (String, Value) = sqlx::query_as(
        "select outcome,response from control.finish_route_set_publication_recovery(
         $1,1,$2,1,'terminal-fixture',$3,$4,'unstarted','accept',$5)",
    )
    .bind(restore.1)
    .bind(reconciliation_operation)
    .bind(reconciliation_owner)
    .bind(reconciliation_token)
    .bind(&decision_digest)
    .fetch_one(&mut *terminal_retry)
    .await
    .unwrap();
    assert_eq!(terminal.0, "completed");
    assert_eq!(terminal.1["outcome"], "not_applied");
    let same_attempt_closed: String = sqlx::query_scalar(
        "select outcome from control.admit_route_set_recovery_restore(
         $1,$2,$3,1,'recovery-fixture',$4,$5,$6,$7,300)",
    )
    .bind(maintenance.2)
    .bind(workshop)
    .bind(operation)
    .bind(Uuid::new_v4())
    .bind(Uuid::new_v4())
    .bind(Uuid::new_v4())
    .bind(Uuid::new_v4())
    .fetch_one(&mut *terminal_retry)
    .await
    .unwrap();
    assert_eq!(same_attempt_closed, "not_applied");
    sqlx::query("update control.operations set attempt=2,lease_expires_at=now()+interval '10 minutes' where id=$1")
        .bind(operation).execute(&mut *terminal_retry).await.unwrap();
    let retried: String = sqlx::query_scalar(
        "select outcome from control.admit_route_set_recovery_restore(
         $1,$2,$3,2,'recovery-fixture',$4,$5,$6,$7,300)",
    )
    .bind(maintenance.2)
    .bind(workshop)
    .bind(operation)
    .bind(Uuid::new_v4())
    .bind(Uuid::new_v4())
    .bind(Uuid::new_v4())
    .bind(Uuid::new_v4())
    .fetch_one(&mut *terminal_retry)
    .await
    .unwrap();
    assert_eq!(retried, "acquired");
    terminal_retry.rollback().await.unwrap();

    let restore_snapshot: (Uuid, i64, String, String, String) = sqlx::query_as(
        "select workshop_id,generation,projection_digest,disposition,applied_rendered_digest
         from control.read_route_set_publication_snapshot_batch($1,$2,$3,$4,$5,$6,$7,null,500)",
    )
    .bind(restore.1)
    .bind(restore_instance)
    .bind(restore_execution)
    .bind(restore_global)
    .bind(restore_route)
    .bind(restore.4)
    .bind(restore.5)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(
        (restore_snapshot.1, restore_snapshot.2.as_str()),
        (2, next_digest.as_str())
    );
    let restore_prior: String = sqlx::query_scalar(
        "select control.record_route_set_publication_prior($1,$2,$3,$4,$5,$6,$7,$8,21,22,$9)",
    )
    .bind(restore.1)
    .bind(restore_instance)
    .bind(restore_execution)
    .bind(restore_global)
    .bind(restore_route)
    .bind(restore.4)
    .bind(restore.5)
    .bind(&maintenance.6)
    .bind(&identity)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(restore_prior, "recorded");
    let restored_rendered = format!("sha256:{}", "7".repeat(64));
    let restore_recorded: String = sqlx::query_scalar(
        "select control.record_route_set_publication_entry($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
    )
    .bind(restore.1).bind(restore_instance).bind(restore_execution).bind(restore_global).bind(restore_route)
    .bind(restore.4).bind(restore.5).bind(restore_snapshot.0).bind(restore_snapshot.1)
    .bind(&restore_snapshot.2).bind(&restore_snapshot.3).bind(&restore_snapshot.4).bind(&restored_rendered)
    .fetch_one(store.pool()).await.unwrap();
    assert_eq!(restore_recorded, "recorded");
    let restore_digest: String =
        sqlx::query_scalar("select control.route_set_publication_digest($1)")
            .bind(restore.1)
            .fetch_one(store.pool())
            .await
            .unwrap();
    let restore_sealed: String = sqlx::query_scalar(
        "select control.seal_route_set_publication($1,$2,$3,$4,$5,$6,$7,$8,31,32,1,1,$9)",
    )
    .bind(restore.1)
    .bind(restore_instance)
    .bind(restore_execution)
    .bind(restore_global)
    .bind(restore_route)
    .bind(restore.4)
    .bind(restore.5)
    .bind(&restore.6)
    .bind(&restore_digest)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(restore_sealed, "sealed");
    let restore_started: String =
        sqlx::query_scalar("select control.start_route_set_publication($1,$2,$3,$4,$5,$6,$7)")
            .bind(restore.1)
            .bind(restore_instance)
            .bind(restore_execution)
            .bind(restore_global)
            .bind(restore_route)
            .bind(restore.4)
            .bind(restore.5)
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert_eq!(restore_started, "started");
    let restore_identity = json!({"protocol_version":1,"publication_id":restore.1,
        "publication_kind":"recovery_restore","global_fence_token":restore.4,
        "target_workshop_id":workshop,"target_route_fence_token":restore.5,
        "route_set_digest":restore_digest});
    let restore_observed: String = sqlx::query_scalar(
        "select control.observe_route_set_publication($1,$2,$3,$4,$5,$6,$7,$8,31,32,$9)",
    )
    .bind(restore.1)
    .bind(restore_instance)
    .bind(restore_execution)
    .bind(restore_global)
    .bind(restore_route)
    .bind(restore.4)
    .bind(restore.5)
    .bind(&restore.6)
    .bind(&restore_identity)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(restore_observed, "observed");
    let restored: (String, Value) = sqlx::query_as(
        "select outcome,response from control.finish_route_set_recovery_publication($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(restore.1).bind(restore_instance).bind(restore_execution).bind(restore_global).bind(restore_route)
    .bind(restore.4).bind(restore.5).fetch_one(store.pool()).await.unwrap();
    assert_eq!(restored.0, "completed");
    assert_eq!(restored.1["outcome"], "restored");
    assert!(restored.1.get("route_fence_token").is_none());
    assert_eq!(restored.1["route_evidence"].as_object().unwrap().len(), 8);
    let restored_head: (i64, String, Option<Uuid>, Option<Uuid>) = sqlx::query_as(
        "select applied_generation,applied_digest,applied_driver_operation_id,applied_effect_run_id
         from control.workshop_route_projection_state where workshop_id=$1",
    )
    .bind(workshop)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(
        restored_head,
        (2, next_digest.clone(), None, Some(maintenance.2))
    );
    sqlx::query(
        "update control.operations set attempt=2,lease_expires_at=now()+interval '10 minutes'
         where id=$1",
    )
    .bind(operation)
    .execute(store.pool())
    .await
    .unwrap();
    let newer_attempt_replay: (String, Option<Value>) = sqlx::query_as(
        "select outcome,stored_response from control.admit_route_set_recovery_restore(
         $1,$2,$3,2,'recovery-fixture',$4,$5,$6,$7,300)",
    )
    .bind(maintenance.2)
    .bind(workshop)
    .bind(operation)
    .bind(Uuid::new_v4())
    .bind(Uuid::new_v4())
    .bind(Uuid::new_v4())
    .bind(Uuid::new_v4())
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(
        newer_attempt_replay,
        ("replay".into(), Some(restored.1.clone()))
    );
    let exact_result: (String, Uuid, Uuid, String, Value) = sqlx::query_as(
        "select * from control.read_route_set_recovery_publication_result($1,$2,$3)",
    )
    .bind(restore.1)
    .bind(maintenance.2)
    .bind(operation)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(exact_result.0, "completed");
    assert_eq!(exact_result.1, restore.1);
    assert_eq!(exact_result.4, restored.1);
    let legacy_operation = Uuid::new_v4();
    let legacy_effect = Uuid::new_v4();
    sqlx::query(
        "insert into control.operations(id,kind,queue,workshop_id,payload,correlation_id,
         idempotency_key,state,attempt,leased_by,lease_expires_at)
         values($1,'tenant.lifecycle','tenant-lifecycle',$2,'{}',$3,$4,'in_flight',1,
         'legacy-fixture',now()+interval '10 minutes')",
    )
    .bind(legacy_operation)
    .bind(workshop)
    .bind(Uuid::new_v4())
    .bind(format!("legacy-effect-operation-{legacy_operation}"))
    .execute(store.pool())
    .await
    .unwrap();
    sqlx::query(
        "insert into control.workshop_route_effect_runs(id,kind,reason,target_key,idempotency_key,
         request_digest,workshop_id,control_operation_id,control_operation_attempt,
         control_operation_lease_owner,state,heartbeat_at,response,safe_error)
         values($1,'recovery-maintenance','restore','maintenance/'||$2::text||'/'||$3::text,
         $4,repeat('9',64),$2,$3,1,'legacy-fixture','maintenance',now(),'{}','recovery_maintenance')",
    )
    .bind(legacy_effect).bind(workshop).bind(legacy_operation)
    .bind(format!("legacy-effect-{legacy_effect}"))
    .execute(store.pool()).await.unwrap();
    let legacy_refused: String = sqlx::query_scalar(
        "select outcome from control.admit_route_set_recovery_restore(
         $1,$2,$3,1,'legacy-fixture',$4,$5,$6,$7,300)",
    )
    .bind(legacy_effect)
    .bind(workshop)
    .bind(legacy_operation)
    .bind(Uuid::new_v4())
    .bind(Uuid::new_v4())
    .bind(Uuid::new_v4())
    .bind(Uuid::new_v4())
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(legacy_refused, "not_maintenance");
    let legacy_publications: i64 = sqlx::query_scalar(
        "select count(*) from control.workshop_route_set_publications where recovery_effect_run_id=$1",
    )
    .bind(legacy_effect).fetch_one(store.pool()).await.unwrap();
    assert_eq!(legacy_publications, 0);

    store.pool().close().await;
    drop_database(&admin, &database).await;
}

#[tokio::test]
#[ignore = "requires a PostgreSQL 17 CONTROL_TEST_ADMIN_URL with CREATEDB"]
async fn startup_route_set_publication_is_exact_replayable_and_terminally_recoverable() {
    let admin_url = std::env::var("CONTROL_TEST_ADMIN_URL").expect("CONTROL_TEST_ADMIN_URL");
    let database = format!("control_startup_route_set_{}", Uuid::new_v4().simple());
    let admin = create_database(&admin_url, &database).await;
    create_runtime_roles(&admin).await;
    let store = Store::connect(&database_url(&admin_url, &database))
        .await
        .unwrap();
    store.migrate().await.unwrap();

    let boot = Uuid::new_v4();
    let inactive: String = sqlx::query_scalar(
        "select outcome from control.read_route_set_startup_admission($1,'startup-zero',repeat('a',64))",
    )
    .bind(boot)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(inactive, "protocol_inactive");
    sqlx::query(
        "update control.route_set_publication_protocol_state
         set normal_ready=true,recovery_ready=true,startup_ready=true,release_ready=true,
             mode='generation_v1',activation_epoch=1,activated_at=now(),updated_at=now()
         where singleton",
    )
    .execute(store.pool())
    .await
    .unwrap();

    let identity_types: (bool, bool, bool) = sqlx::query_as(
        "select
          control.valid_route_set_loaded_identity(jsonb_build_object(
           'protocol_version',1,'publication_id',$1::uuid,'publication_kind','startup',
           'startup_effect_run_id',$2::uuid,'global_fence_token',1,
           'route_set_digest','sha256:'||repeat('a',64))),
          control.valid_route_set_loaded_identity(jsonb_build_object(
           'protocol_version','1','publication_id',$1::uuid,'publication_kind','startup',
           'startup_effect_run_id',$2::uuid,'global_fence_token',1,
           'route_set_digest','sha256:'||repeat('a',64))),
          control.valid_route_set_loaded_identity(jsonb_build_object(
           'protocol_version',1,'publication_id',$1::uuid,'publication_kind','projection',
           'target_workshop_id',$2::uuid,'target_route_fence_token','1',
           'global_fence_token',1,'route_set_digest','sha256:'||repeat('a',64)))",
    )
    .bind(Uuid::new_v4())
    .bind(Uuid::new_v4())
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(identity_types, (true, false, false));

    let instance = Uuid::new_v4();
    let execution = Uuid::new_v4();
    let global = Uuid::new_v4();
    let route = Uuid::new_v4();
    let admission: (String, Uuid, Uuid, i64, i32, String) = sqlx::query_as(
        "select outcome,publication_id,effect_run_id,global_fence_token,snapshot_count,selector
         from control.admit_route_set_startup_publication(
          $1,'startup-zero',repeat('a',64),$2,$3,$4,$5,300,1::smallint)",
    )
    .bind(boot)
    .bind(instance)
    .bind(execution)
    .bind(global)
    .bind(route)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!((admission.0.as_str(), admission.4), ("acquired", 0));
    let scope: (Option<Uuid>, Option<Uuid>, Option<Uuid>) = sqlx::query_as(
        "select target_workshop_id,control_operation_id,driver_operation_id
         from control.workshop_route_set_publications where publication_id=$1",
    )
    .bind(admission.1)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(scope, (None, None, None));
    let prior: String = sqlx::query_scalar(
        "select control.record_route_set_startup_prior(
          $1,$2,$3,$4,$5,$6,'generations/boot-live',1,2,null)",
    )
    .bind(admission.1)
    .bind(instance)
    .bind(execution)
    .bind(global)
    .bind(route)
    .bind(admission.3)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(prior, "recorded");
    let digest: String = sqlx::query_scalar("select control.route_set_publication_digest($1)")
        .bind(admission.1)
        .fetch_one(store.pool())
        .await
        .unwrap();
    let sealed: String = sqlx::query_scalar(
        "select control.seal_route_set_startup_publication(
          $1,$2,$3,$4,$5,$6,0,0,$7,11,12)",
    )
    .bind(admission.1)
    .bind(instance)
    .bind(execution)
    .bind(global)
    .bind(route)
    .bind(admission.3)
    .bind(&digest)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(sealed, "sealed");
    let started: String =
        sqlx::query_scalar("select control.start_route_set_startup_publication($1,$2,$3,$4,$5,$6)")
            .bind(admission.1)
            .bind(instance)
            .bind(execution)
            .bind(global)
            .bind(route)
            .bind(admission.3)
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert_eq!(started, "started");
    let identity = json!({"protocol_version":1,"publication_id":admission.1,
        "publication_kind":"startup","startup_effect_run_id":admission.2,
        "global_fence_token":admission.3,"route_set_digest":digest});
    let observed: String = sqlx::query_scalar(
        "select control.observe_route_set_startup_publication($1,$2,$3,$4,$5,$6,$7,$8)",
    )
    .bind(admission.1)
    .bind(instance)
    .bind(execution)
    .bind(global)
    .bind(route)
    .bind(admission.3)
    .bind(&admission.5)
    .bind(&identity)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(observed, "observed");
    let finished: (String, Value) = sqlx::query_as(
        "select outcome,response from control.finish_route_set_startup_publication($1,$2,$3,$4,$5,$6)",
    )
    .bind(admission.1)
    .bind(instance)
    .bind(execution)
    .bind(global)
    .bind(route)
    .bind(admission.3)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(finished.0, "applied");
    assert_eq!(finished.1.as_object().unwrap().len(), 5);
    assert_eq!(
        finished.1["gateway_reload_digest"],
        finished.1["projection_set_digest"]
    );
    let replay: (String, Option<Value>) = sqlx::query_as(
        "select outcome,stored_response from control.read_route_set_startup_admission(
          $1,'startup-zero',repeat('a',64))",
    )
    .bind(boot)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(replay, ("replay".into(), Some(finished.1)));

    // Pre-publication expiry may terminalize only an exact restored prior.
    let prior_boot = Uuid::new_v4();
    let prior_instance = Uuid::new_v4();
    let prior_execution = Uuid::new_v4();
    let prior_global = Uuid::new_v4();
    let prior_route = Uuid::new_v4();
    let prior_admission: (Uuid, Uuid, i64) = sqlx::query_as(
        "select publication_id,effect_run_id,global_fence_token
         from control.admit_route_set_startup_publication(
          $1,'startup-prior',repeat('b',64),$2,$3,$4,$5,300,1::smallint)",
    )
    .bind(prior_boot)
    .bind(prior_instance)
    .bind(prior_execution)
    .bind(prior_global)
    .bind(prior_route)
    .fetch_one(store.pool())
    .await
    .unwrap();
    let prior_recorded: String = sqlx::query_scalar(
        "select control.record_route_set_startup_prior(
          $1,$2,$3,$4,$5,$6,'generations/boot-live',21,22,null)",
    )
    .bind(prior_admission.0)
    .bind(prior_instance)
    .bind(prior_execution)
    .bind(prior_global)
    .bind(prior_route)
    .bind(prior_admission.2)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(prior_recorded, "recorded");
    sqlx::query(
        "update control.workshop_route_effect_runs set lease_expires_at=now()-interval '1 second'
         where id=$1",
    )
    .bind(prior_admission.1)
    .execute(store.pool())
    .await
    .unwrap();
    sqlx::query(
        "update control.deployment_driver_resource_leases set lease_expires_at=now()-interval '1 second'
         where route_set_publication_id=$1",
    )
    .bind(prior_admission.0)
    .execute(store.pool())
    .await
    .unwrap();
    let recovery_owner = Uuid::new_v4();
    let recovery_token = Uuid::new_v4();
    let claim: (String, i64, String) = sqlx::query_as(
        "select outcome,claim_fence,claim_mode
         from control.claim_interrupted_route_set_startup_publication($1,$2,$3,300)",
    )
    .bind(prior_admission.0)
    .bind(recovery_owner)
    .bind(recovery_token)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(claim, ("acquired".into(), 1, "write_cleanup".into()));
    let false_unstarted: String = sqlx::query_scalar(
        "select control.resolve_interrupted_route_set_startup_publication_observation(
          $1,$2,$3,1,'unstarted',$4)",
    )
    .bind(prior_admission.0)
    .bind(recovery_owner)
    .bind(recovery_token)
    .bind(
        json!({"publication_id":prior_admission.0,"resolution_kind":"unstarted",
        "observed_selector":null,"observed_directory_device":null,
        "observed_directory_inode":null,"observed_loaded_identity":null}),
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(false_unstarted, "observation_mismatch");
    let resolution: String = sqlx::query_scalar(
        "select control.resolve_interrupted_route_set_startup_publication_observation(
          $1,$2,$3,1,'prior',$4)",
    )
    .bind(prior_admission.0)
    .bind(recovery_owner)
    .bind(recovery_token)
    .bind(
        json!({"publication_id":prior_admission.0,"resolution_kind":"prior",
        "observed_selector":"generations/boot-live","observed_directory_device":21,
        "observed_directory_inode":22,"observed_loaded_identity":null}),
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(resolution, "recorded");
    let decision_digest: String = sqlx::query_scalar(
        "select control.route_set_startup_terminal_decision_digest($1,1,$2,'prior','cancel_unstarted')",
    )
    .bind(prior_admission.0)
    .bind(recovery_owner)
    .fetch_one(store.pool())
    .await
    .unwrap();
    let terminal: (String, Value) = sqlx::query_as(
        "select outcome,response from control.finish_route_set_startup_publication_recovery(
          $1,1,$2,$3,'prior','cancel_unstarted',$4)",
    )
    .bind(prior_admission.0)
    .bind(recovery_owner)
    .bind(recovery_token)
    .bind(decision_digest)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(terminal.0, "not_applied");
    assert_eq!(terminal.1["resolution_kind"], "prior");
    let terminal_read: String = sqlx::query_scalar(
        "select outcome from control.read_route_set_startup_publication_result($1,$2,$3)",
    )
    .bind(prior_admission.0)
    .bind(prior_admission.1)
    .bind(prior_boot)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(terminal_read, "not_applied");
    let prior_admission_replay: (String, Option<Value>) = sqlx::query_as(
        "select outcome,stored_response from control.read_route_set_startup_admission(
          $1,'startup-prior',repeat('b',64))",
    )
    .bind(prior_boot)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(
        prior_admission_replay,
        ("not_applied".into(), Some(terminal.1))
    );

    // A crash after publication_started but before selector exchange may still
    // prove the exact prior under observe-only authority and terminalize as
    // not-applied without writing the gateway.
    let post_start_boot = Uuid::new_v4();
    let post_start_instance = Uuid::new_v4();
    let post_start_execution = Uuid::new_v4();
    let post_start_global = Uuid::new_v4();
    let post_start_route = Uuid::new_v4();
    let post_start: (Uuid, Uuid, i64) = sqlx::query_as(
        "select publication_id,effect_run_id,global_fence_token
         from control.admit_route_set_startup_publication(
          $1,'startup-post-start-prior',repeat('f',64),$2,$3,$4,$5,300,1::smallint)",
    )
    .bind(post_start_boot)
    .bind(post_start_instance)
    .bind(post_start_execution)
    .bind(post_start_global)
    .bind(post_start_route)
    .fetch_one(store.pool())
    .await
    .unwrap();
    let post_start_prior: String = sqlx::query_scalar(
        "select control.record_route_set_startup_prior(
          $1,$2,$3,$4,$5,$6,'generations/boot-live',71,72,null)",
    )
    .bind(post_start.0)
    .bind(post_start_instance)
    .bind(post_start_execution)
    .bind(post_start_global)
    .bind(post_start_route)
    .bind(post_start.2)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(post_start_prior, "recorded");
    let post_start_digest: String =
        sqlx::query_scalar("select control.route_set_publication_digest($1)")
            .bind(post_start.0)
            .fetch_one(store.pool())
            .await
            .unwrap();
    let post_start_sealed: String = sqlx::query_scalar(
        "select control.seal_route_set_startup_publication(
          $1,$2,$3,$4,$5,$6,0,0,$7,73,74)",
    )
    .bind(post_start.0)
    .bind(post_start_instance)
    .bind(post_start_execution)
    .bind(post_start_global)
    .bind(post_start_route)
    .bind(post_start.2)
    .bind(post_start_digest)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(post_start_sealed, "sealed");
    let post_start_started: String =
        sqlx::query_scalar("select control.start_route_set_startup_publication($1,$2,$3,$4,$5,$6)")
            .bind(post_start.0)
            .bind(post_start_instance)
            .bind(post_start_execution)
            .bind(post_start_global)
            .bind(post_start_route)
            .bind(post_start.2)
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert_eq!(post_start_started, "started");
    sqlx::query(
        "update control.workshop_route_effect_runs set lease_expires_at=now()-interval '1 second'
         where id=$1",
    )
    .bind(post_start.1)
    .execute(store.pool())
    .await
    .unwrap();
    sqlx::query(
        "update control.deployment_driver_resource_leases set lease_expires_at=now()-interval '1 second'
         where route_set_publication_id=$1",
    )
    .bind(post_start.0)
    .execute(store.pool())
    .await
    .unwrap();
    let post_start_owner = Uuid::new_v4();
    let post_start_token = Uuid::new_v4();
    let post_start_claim: (String, i64, String) = sqlx::query_as(
        "select outcome,claim_fence,claim_mode
         from control.claim_interrupted_route_set_startup_publication($1,$2,$3,300)",
    )
    .bind(post_start.0)
    .bind(post_start_owner)
    .bind(post_start_token)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(
        post_start_claim,
        ("acquired".into(), 1, "observe_only".into())
    );
    let post_start_resolution: String = sqlx::query_scalar(
        "select control.resolve_interrupted_route_set_startup_publication_observation(
          $1,$2,$3,1,'prior',$4)",
    )
    .bind(post_start.0)
    .bind(post_start_owner)
    .bind(post_start_token)
    .bind(
        json!({"publication_id":post_start.0,"resolution_kind":"prior",
        "observed_selector":"generations/boot-live","observed_directory_device":71,
        "observed_directory_inode":72,"observed_loaded_identity":null}),
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(post_start_resolution, "recorded");
    let post_start_decision: String = sqlx::query_scalar(
        "select control.route_set_startup_terminal_decision_digest(
          $1,1,$2,'prior','cancel_unstarted')",
    )
    .bind(post_start.0)
    .bind(post_start_owner)
    .fetch_one(store.pool())
    .await
    .unwrap();
    let post_start_terminal: (String, Value) = sqlx::query_as(
        "select outcome,response from control.finish_route_set_startup_publication_recovery(
          $1,1,$2,$3,'prior','cancel_unstarted',$4)",
    )
    .bind(post_start.0)
    .bind(post_start_owner)
    .bind(post_start_token)
    .bind(post_start_decision)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(post_start_terminal.0, "not_applied");
    let post_start_admission: (String, Option<Value>) = sqlx::query_as(
        "select outcome,stored_response from control.read_route_set_startup_admission(
          $1,'startup-post-start-prior',repeat('f',64))",
    )
    .bind(post_start_boot)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(
        post_start_admission,
        ("not_applied".into(), Some(post_start_terminal.1))
    );

    // A genuinely uninitialized route carries a nullable baseline without a
    // manufactured generation, digest, owner, or fence.
    let workshop = Uuid::new_v4();
    let source_operation = Uuid::new_v4();
    let absent_projection_digest = format!("sha256:{}", "d".repeat(64));
    let empty_rendered = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    sqlx::query(
        "insert into control.workshops(id,slug,display_name,time_zone)
         values($1,$2,'Startup absent route','UTC')",
    )
    .bind(workshop)
    .bind(format!("startup-absent-{}", workshop.simple()))
    .execute(store.pool())
    .await
    .unwrap();
    sqlx::query(
        "insert into control.operations(id,kind,queue,workshop_id,payload,correlation_id,
         idempotency_key,state,attempt,leased_by,lease_expires_at)
         values($1,'tenant.reconcile','tenant-reconciliation',$2,'{}',$3,$4,'in_flight',1,
         'startup-source',now()+interval '10 minutes')",
    )
    .bind(source_operation)
    .bind(workshop)
    .bind(Uuid::new_v4())
    .bind(format!("startup-source-{source_operation}"))
    .execute(store.pool())
    .await
    .unwrap();
    sqlx::query(
        "insert into control.workshop_route_projections(workshop_id,generation,projection_digest,
         projection,source_operation_id,source_operation_attempt,disposition)
         values($1,1,$2,jsonb_build_object('paperless_mode','absent'),$3,1,'absent')",
    )
    .bind(workshop)
    .bind(&absent_projection_digest)
    .bind(source_operation)
    .execute(store.pool())
    .await
    .unwrap();
    sqlx::query(
        "update control.workshop_route_projection_state
         set desired_generation=1,desired_digest=$2,desired_disposition='absent'
         where workshop_id=$1",
    )
    .bind(workshop)
    .bind(&absent_projection_digest)
    .execute(store.pool())
    .await
    .unwrap();
    let row_boot = Uuid::new_v4();
    let row_instance = Uuid::new_v4();
    let row_execution = Uuid::new_v4();
    let row_global = Uuid::new_v4();
    let row_route = Uuid::new_v4();
    let row_admission: (Uuid, Uuid, i64, String) = sqlx::query_as(
        "select publication_id,effect_run_id,global_fence_token,selector
         from control.admit_route_set_startup_publication(
          $1,'startup-one-row',repeat('d',64),$2,$3,$4,$5,300,1::smallint)",
    )
    .bind(row_boot)
    .bind(row_instance)
    .bind(row_execution)
    .bind(row_global)
    .bind(row_route)
    .fetch_one(store.pool())
    .await
    .unwrap();
    let row_prior: String = sqlx::query_scalar(
        "select control.record_route_set_startup_prior(
          $1,$2,$3,$4,$5,$6,'generations/boot-live',51,52,null)",
    )
    .bind(row_admission.0)
    .bind(row_instance)
    .bind(row_execution)
    .bind(row_global)
    .bind(row_route)
    .bind(row_admission.2)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(row_prior, "recorded");
    let row_snapshot: (Uuid, i64, String, String, Option<String>, i64, bool) = sqlx::query_as(
        "select workshop_id,generation,projection_digest,disposition,
         baseline_applied_rendered_digest,route_fence_token,unresolved_operation
         from control.read_route_set_startup_snapshot_batch($1,$2,$3,$4,$5,$6,null,500)",
    )
    .bind(row_admission.0)
    .bind(row_instance)
    .bind(row_execution)
    .bind(row_global)
    .bind(row_route)
    .bind(row_admission.2)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(row_snapshot.4, None);
    let row_runtime = json!({"effect_run_id":row_admission.1,"workshop_id":workshop,
        "database_id":null,"database_ref":null,"unresolved_operation":row_snapshot.6,
        "outcome":"absent","odoo_runtime":null,"paperless_runtime":null,
        "verified_at":"2026-08-23T00:00:00Z"});
    let row_recorded: String = sqlx::query_scalar(
        "select control.record_route_set_startup_entry(
          $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'absent',$13,$14)",
    )
    .bind(row_admission.0)
    .bind(row_instance)
    .bind(row_execution)
    .bind(row_global)
    .bind(row_route)
    .bind(row_admission.2)
    .bind(workshop)
    .bind(row_snapshot.1)
    .bind(&row_snapshot.2)
    .bind(&row_snapshot.3)
    .bind(Option::<String>::None)
    .bind(row_snapshot.5)
    .bind(&row_runtime)
    .bind(empty_rendered)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(row_recorded, "recorded");
    let row_entry_replays: (String, String, String, String) = sqlx::query_as(
        "select
          control.record_route_set_startup_entry(
           $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,null,$11,'absent',$12,$13),
          control.record_route_set_startup_entry(
           $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,null,$11+1,'absent',$12,$13),
          control.record_route_set_startup_entry(
           $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,null,$11,'ready',$12,$13),
          control.record_route_set_startup_entry(
           $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,null,$11,'absent',$12||'{\"tampered\":true}'::jsonb,$13)",
    )
    .bind(row_admission.0)
    .bind(row_instance)
    .bind(row_execution)
    .bind(row_global)
    .bind(row_route)
    .bind(row_admission.2)
    .bind(workshop)
    .bind(row_snapshot.1)
    .bind(&row_snapshot.2)
    .bind(&row_snapshot.3)
    .bind(row_snapshot.5)
    .bind(&row_runtime)
    .bind(empty_rendered)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(
        row_entry_replays,
        (
            "replay".into(),
            "conflict".into(),
            "conflict".into(),
            "conflict".into()
        )
    );
    let row_digest: String = sqlx::query_scalar("select control.route_set_publication_digest($1)")
        .bind(row_admission.0)
        .fetch_one(store.pool())
        .await
        .unwrap();
    let row_sealed: String = sqlx::query_scalar(
        "select control.seal_route_set_startup_publication(
          $1,$2,$3,$4,$5,$6,1,0,$7,61,62)",
    )
    .bind(row_admission.0)
    .bind(row_instance)
    .bind(row_execution)
    .bind(row_global)
    .bind(row_route)
    .bind(row_admission.2)
    .bind(&row_digest)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(row_sealed, "sealed");
    let _: String =
        sqlx::query_scalar("select control.start_route_set_startup_publication($1,$2,$3,$4,$5,$6)")
            .bind(row_admission.0)
            .bind(row_instance)
            .bind(row_execution)
            .bind(row_global)
            .bind(row_route)
            .bind(row_admission.2)
            .fetch_one(store.pool())
            .await
            .unwrap();
    let row_identity = json!({"protocol_version":1,"publication_id":row_admission.0,
        "publication_kind":"startup","startup_effect_run_id":row_admission.1,
        "global_fence_token":row_admission.2,"route_set_digest":row_digest});
    let _: String = sqlx::query_scalar(
        "select control.observe_route_set_startup_publication($1,$2,$3,$4,$5,$6,$7,$8)",
    )
    .bind(row_admission.0)
    .bind(row_instance)
    .bind(row_execution)
    .bind(row_global)
    .bind(row_route)
    .bind(row_admission.2)
    .bind(&row_admission.3)
    .bind(&row_identity)
    .fetch_one(store.pool())
    .await
    .unwrap();
    let row_finished: String = sqlx::query_scalar(
        "select outcome from control.finish_route_set_startup_publication($1,$2,$3,$4,$5,$6)",
    )
    .bind(row_admission.0)
    .bind(row_instance)
    .bind(row_execution)
    .bind(row_global)
    .bind(row_route)
    .bind(row_admission.2)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(row_finished, "applied");
    let applied: (i64, String, String, Uuid, i64, String, bool) = sqlx::query_as(
        "select state.applied_generation,state.applied_digest,state.applied_disposition,
         state.applied_effect_run_id,state.applied_fence_token,lease.state,lease.initialization_required
         from control.workshop_route_projection_state state
         join control.workshop_route_application_leases lease using(workshop_id)
         where state.workshop_id=$1",
    )
    .bind(workshop)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(
        applied,
        (
            1,
            absent_projection_digest.clone(),
            "absent".into(),
            row_admission.1,
            row_snapshot.5,
            "idle".into(),
            false
        )
    );

    // Once publication started, only an exact candidate observation may move
    // the frozen fleet forward; prior/unstarted is no longer admissible.
    let candidate_boot = Uuid::new_v4();
    let candidate_instance = Uuid::new_v4();
    let candidate_execution = Uuid::new_v4();
    let candidate_global = Uuid::new_v4();
    let candidate_route = Uuid::new_v4();
    let candidate: (Uuid, Uuid, i64, String) = sqlx::query_as(
        "select publication_id,effect_run_id,global_fence_token,selector
         from control.admit_route_set_startup_publication(
          $1,'startup-candidate',repeat('c',64),$2,$3,$4,$5,300,1::smallint)",
    )
    .bind(candidate_boot)
    .bind(candidate_instance)
    .bind(candidate_execution)
    .bind(candidate_global)
    .bind(candidate_route)
    .fetch_one(store.pool())
    .await
    .unwrap();
    let candidate_prior: String = sqlx::query_scalar(
        "select control.record_route_set_startup_prior(
          $1,$2,$3,$4,$5,$6,'generations/boot-live',31,32,null)",
    )
    .bind(candidate.0)
    .bind(candidate_instance)
    .bind(candidate_execution)
    .bind(candidate_global)
    .bind(candidate_route)
    .bind(candidate.2)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(candidate_prior, "recorded");
    let candidate_snapshot: (i64, String, String, Option<String>, i64, bool) = sqlx::query_as(
        "select generation,projection_digest,disposition,baseline_applied_rendered_digest,
         route_fence_token,unresolved_operation
         from control.read_route_set_startup_snapshot_batch($1,$2,$3,$4,$5,$6,null,500)",
    )
    .bind(candidate.0)
    .bind(candidate_instance)
    .bind(candidate_execution)
    .bind(candidate_global)
    .bind(candidate_route)
    .bind(candidate.2)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(candidate_snapshot.3.as_deref(), Some(empty_rendered));
    let candidate_runtime = json!({"effect_run_id":candidate.1,"workshop_id":workshop,
        "database_id":null,"database_ref":null,"unresolved_operation":candidate_snapshot.5,
        "outcome":"absent","odoo_runtime":null,"paperless_runtime":null,
        "verified_at":"2026-08-23T00:00:01Z"});
    let candidate_recorded: String = sqlx::query_scalar(
        "select control.record_route_set_startup_entry(
          $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'absent',$13,$14)",
    )
    .bind(candidate.0)
    .bind(candidate_instance)
    .bind(candidate_execution)
    .bind(candidate_global)
    .bind(candidate_route)
    .bind(candidate.2)
    .bind(workshop)
    .bind(candidate_snapshot.0)
    .bind(&candidate_snapshot.1)
    .bind(&candidate_snapshot.2)
    .bind(&candidate_snapshot.3)
    .bind(candidate_snapshot.4)
    .bind(&candidate_runtime)
    .bind(empty_rendered)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(candidate_recorded, "recorded");
    let candidate_digest: String =
        sqlx::query_scalar("select control.route_set_publication_digest($1)")
            .bind(candidate.0)
            .fetch_one(store.pool())
            .await
            .unwrap();
    let candidate_sealed: String = sqlx::query_scalar(
        "select control.seal_route_set_startup_publication(
          $1,$2,$3,$4,$5,$6,1,0,$7,41,42)",
    )
    .bind(candidate.0)
    .bind(candidate_instance)
    .bind(candidate_execution)
    .bind(candidate_global)
    .bind(candidate_route)
    .bind(candidate.2)
    .bind(&candidate_digest)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(candidate_sealed, "sealed");
    let candidate_started: String =
        sqlx::query_scalar("select control.start_route_set_startup_publication($1,$2,$3,$4,$5,$6)")
            .bind(candidate.0)
            .bind(candidate_instance)
            .bind(candidate_execution)
            .bind(candidate_global)
            .bind(candidate_route)
            .bind(candidate.2)
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert_eq!(candidate_started, "started");
    sqlx::query(
        "update control.workshop_route_effect_runs set lease_expires_at=now()-interval '1 second'
         where id=$1",
    )
    .bind(candidate.1)
    .execute(store.pool())
    .await
    .unwrap();
    sqlx::query(
        "update control.deployment_driver_resource_leases set lease_expires_at=now()-interval '1 second'
         where route_set_publication_id=$1",
    )
    .bind(candidate.0)
    .execute(store.pool())
    .await
    .unwrap();
    sqlx::query(
        "update control.workshop_route_application_leases
         set lease_expires_at=now()-interval '1 second' where route_set_publication_id=$1",
    )
    .bind(candidate.0)
    .execute(store.pool())
    .await
    .unwrap();
    let candidate_owner = Uuid::new_v4();
    let candidate_token = Uuid::new_v4();
    let candidate_claim: (String, i64, String) = sqlx::query_as(
        "select outcome,claim_fence,claim_mode
         from control.claim_interrupted_route_set_startup_publication($1,$2,$3,300)",
    )
    .bind(candidate.0)
    .bind(candidate_owner)
    .bind(candidate_token)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(
        candidate_claim,
        ("acquired".into(), 1, "observe_only".into())
    );
    let candidate_identity = json!({"protocol_version":1,"publication_id":candidate.0,
        "publication_kind":"startup","startup_effect_run_id":candidate.1,
        "global_fence_token":candidate.2,"route_set_digest":candidate_digest});
    let candidate_resolution: String = sqlx::query_scalar(
        "select control.resolve_interrupted_route_set_startup_publication_observation(
          $1,$2,$3,1,'candidate',$4)",
    )
    .bind(candidate.0)
    .bind(candidate_owner)
    .bind(candidate_token)
    .bind(
        json!({"publication_id":candidate.0,"resolution_kind":"candidate",
        "observed_selector":candidate.3,"observed_directory_device":41,
        "observed_directory_inode":42,"observed_loaded_identity":candidate_identity}),
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(candidate_resolution, "recorded");
    let candidate_decision_digest: String = sqlx::query_scalar(
        "select control.route_set_startup_terminal_decision_digest(
          $1,1,$2,'candidate','finish_candidate')",
    )
    .bind(candidate.0)
    .bind(candidate_owner)
    .fetch_one(store.pool())
    .await
    .unwrap();
    let candidate_terminal: (String, Value) = sqlx::query_as(
        "select outcome,response from control.finish_route_set_startup_publication_recovery(
          $1,1,$2,$3,'candidate','finish_candidate',$4)",
    )
    .bind(candidate.0)
    .bind(candidate_owner)
    .bind(candidate_token)
    .bind(candidate_decision_digest)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(candidate_terminal.0, "applied_recovered");
    assert_eq!(candidate_terminal.1.as_object().unwrap().len(), 5);
    let candidate_admission_replay: (String, Option<Value>) = sqlx::query_as(
        "select outcome,stored_response from control.read_route_set_startup_admission(
          $1,'startup-candidate',repeat('c',64))",
    )
    .bind(candidate_boot)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(
        candidate_admission_replay,
        ("replay".into(), Some(candidate_terminal.1))
    );

    // Retention remains dormant and independently fenced.  Once three exact
    // candidate observations exist, only the oldest is eligible; the newest
    // two remain protected.  Database authorization is completed before the
    // test supplies the host-side non-current/deletion evidence.
    let mut retention_clock = store.begin().await.unwrap();
    sqlx::query("set local session_replication_role='replica'")
        .execute(&mut *retention_clock)
        .await
        .unwrap();
    sqlx::query(
        "update control.workshop_route_set_publications
         set retention_not_before=now()-interval '1 second'
         where publication_id in ($1,$2,$3,$4)",
    )
    .bind(admission.1)
    .bind(row_admission.0)
    .bind(candidate.0)
    .bind(post_start.0)
    .execute(&mut *retention_clock)
    .await
    .unwrap();
    retention_clock.commit().await.unwrap();
    let newest_two_protected: (bool, bool, bool) = sqlx::query_as(
        "select control.route_set_generation_retention_eligible($1),
         control.route_set_generation_retention_eligible($2),
         control.route_set_generation_retention_eligible($3)",
    )
    .bind(row_admission.0)
    .bind(candidate.0)
    .bind(post_start.0)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(newest_two_protected, (false, false, true));
    let retention_owner = Uuid::new_v4();
    let retention_token = Uuid::new_v4();
    let retention_claim: (
        String,
        i64,
        String,
        String,
        i64,
        i64,
        Value,
        Value,
        i32,
        i32,
    ) = sqlx::query_as(
        "select outcome,claim_fence,publication_kind,selector,directory_device,
         directory_inode,expected_intent,expected_identity,route_count,present_count
         from control.claim_route_set_generation_retention($1,$2,$3,300)",
    )
    .bind(admission.1)
    .bind(retention_owner)
    .bind(retention_token)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(retention_claim.0, "acquired");
    assert_eq!(retention_claim.2, "startup");
    assert_eq!(retention_claim.4, 11);
    assert_eq!(retention_claim.5, 12);
    assert_eq!(retention_claim.6.as_object().unwrap().len(), 5);
    assert_eq!(retention_claim.7.as_object().unwrap().len(), 6);
    assert_eq!((retention_claim.8, retention_claim.9), (0, 0));
    let retention_evidence = json!({
        "protocol_version":1,"publication_id":admission.1,
        "claim_fence":retention_claim.1,"resolution":"deleted",
        "selector":retention_claim.3,"expected_intent":retention_claim.6,
        "expected_identity":retention_claim.7,
        "observed_current_selector":candidate.3,
        "observed_current_identity":candidate_identity,
        "target_present":true,"observed_target_device":11,
        "observed_target_inode":12,"mismatch_kind":null,
        "observed_target_identity":null
    });
    let retained: String = sqlx::query_scalar(
        "select control.finish_route_set_generation_retention(
          $1,$2,$3,$4,'deleted',$5)",
    )
    .bind(admission.1)
    .bind(retention_owner)
    .bind(retention_token)
    .bind(retention_claim.1)
    .bind(&retention_evidence)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(retained, "deleted");
    let retained_replay: String = sqlx::query_scalar(
        "select control.finish_route_set_generation_retention(
          $1,$2,$3,$4,'deleted',$5)",
    )
    .bind(admission.1)
    .bind(retention_owner)
    .bind(retention_token)
    .bind(retention_claim.1)
    .bind(&retention_evidence)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(retained_replay, "replay");
    let retention_terminal_state: (bool, String, Option<Uuid>) = sqlx::query_as(
        "select control.route_set_generation_retention_eligible($1),state,
         route_set_publication_id from control.deployment_driver_resource_leases
         where resource_key='runtime/shared-odoo'",
    )
    .bind(admission.1)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(retention_terminal_state, (false, "idle".into(), None));

    let retry_owner = Uuid::new_v4();
    let retry_token = Uuid::new_v4();
    let retry_claim: (
        String,
        i64,
        String,
        String,
        i64,
        i64,
        Value,
        Value,
        i32,
        i32,
    ) = sqlx::query_as(
        "select outcome,claim_fence,publication_kind,selector,directory_device,
             directory_inode,expected_intent,expected_identity,route_count,present_count
             from control.claim_route_set_generation_retention($1,$2,$3,300)",
    )
    .bind(post_start.0)
    .bind(retry_owner)
    .bind(retry_token)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(retry_claim.0, "acquired");
    let protected_evidence = json!({
        "protocol_version":1,"publication_id":post_start.0,
        "claim_fence":retry_claim.1,"resolution":"protected_current",
        "selector":retry_claim.3,"expected_intent":retry_claim.6,
        "expected_identity":retry_claim.7,
        "observed_current_selector":retry_claim.3,
        "observed_current_identity":retry_claim.7,
        "target_present":true,"observed_target_device":retry_claim.4,
        "observed_target_inode":retry_claim.5,"mismatch_kind":null,
        "observed_target_identity":null
    });
    let protected: String = sqlx::query_scalar(
        "select control.finish_route_set_generation_retention(
          $1,$2,$3,$4,'protected_current',$5)",
    )
    .bind(post_start.0)
    .bind(retry_owner)
    .bind(retry_token)
    .bind(retry_claim.1)
    .bind(&protected_evidence)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(protected, "protected_current");
    assert!(sqlx::query_scalar::<_, bool>(
        "select control.route_set_generation_retention_eligible($1)",
    )
    .bind(post_start.0)
    .fetch_one(store.pool())
    .await
    .unwrap());

    let expired_owner = Uuid::new_v4();
    let expired_token = Uuid::new_v4();
    let expired_claim: (
        String,
        i64,
        String,
        String,
        i64,
        i64,
        Value,
        Value,
        i32,
        i32,
    ) = sqlx::query_as(
        "select outcome,claim_fence,publication_kind,selector,directory_device,
             directory_inode,expected_intent,expected_identity,route_count,present_count
             from control.claim_route_set_generation_retention($1,$2,$3,300)",
    )
    .bind(post_start.0)
    .bind(expired_owner)
    .bind(expired_token)
    .fetch_one(store.pool())
    .await
    .unwrap();
    sqlx::query(
        "update control.deployment_driver_resource_leases
         set lease_expires_at=now()-interval '1 second'
         where authority_kind='route-set-retention' and route_set_publication_id=$1",
    )
    .bind(post_start.0)
    .execute(store.pool())
    .await
    .unwrap();
    sqlx::query(
        "update control.route_set_generation_retention_claims
         set claim_expires_at=now()-interval '1 second' where publication_id=$1",
    )
    .bind(post_start.0)
    .execute(store.pool())
    .await
    .unwrap();
    let expired_renewed: bool = sqlx::query_scalar(
        "select control.renew_route_set_generation_retention_claim($1,$2,$3,$4,300)",
    )
    .bind(post_start.0)
    .bind(expired_owner)
    .bind(expired_token)
    .bind(expired_claim.1)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert!(!expired_renewed);
    let expired_evidence = json!({
        "protocol_version":1,"publication_id":post_start.0,
        "claim_fence":expired_claim.1,"resolution":"protected_current",
        "selector":expired_claim.3,"expected_intent":expired_claim.6,
        "expected_identity":expired_claim.7,
        "observed_current_selector":expired_claim.3,
        "observed_current_identity":expired_claim.7,
        "target_present":true,"observed_target_device":expired_claim.4,
        "observed_target_inode":expired_claim.5,"mismatch_kind":null,
        "observed_target_identity":null
    });
    let expired_finish: String = sqlx::query_scalar(
        "select control.finish_route_set_generation_retention(
          $1,$2,$3,$4,'protected_current',$5)",
    )
    .bind(post_start.0)
    .bind(expired_owner)
    .bind(expired_token)
    .bind(expired_claim.1)
    .bind(&expired_evidence)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(expired_finish, "claim_lost");
    let takeover_owner = Uuid::new_v4();
    let takeover_token = Uuid::new_v4();
    let takeover: (
        String,
        i64,
        String,
        String,
        i64,
        i64,
        Value,
        Value,
        i32,
        i32,
    ) = sqlx::query_as(
        "select outcome,claim_fence,publication_kind,selector,directory_device,
             directory_inode,expected_intent,expected_identity,route_count,present_count
             from control.claim_route_set_generation_retention($1,$2,$3,300)",
    )
    .bind(post_start.0)
    .bind(takeover_owner)
    .bind(takeover_token)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(takeover.0, "acquired");
    assert!(takeover.1 > expired_claim.1);
    let stale_finish: String = sqlx::query_scalar(
        "select control.finish_route_set_generation_retention(
          $1,$2,$3,$4,'protected_current',$5)",
    )
    .bind(post_start.0)
    .bind(expired_owner)
    .bind(expired_token)
    .bind(expired_claim.1)
    .bind(&expired_evidence)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(stale_finish, "claim_lost");
    let directory_mismatch_evidence = json!({
        "protocol_version":1,"publication_id":post_start.0,
        "claim_fence":takeover.1,"resolution":"identity_mismatch",
        "selector":takeover.3,"expected_intent":takeover.6,
        "expected_identity":takeover.7,
        "observed_current_selector":candidate.3,
        "observed_current_identity":candidate_identity,
        "target_present":true,"observed_target_device":takeover.4+1,
        "observed_target_inode":takeover.5,"mismatch_kind":"directory_identity",
        "observed_target_identity":null
    });
    let directory_mismatch: String = sqlx::query_scalar(
        "select control.finish_route_set_generation_retention(
          $1,$2,$3,$4,'identity_mismatch',$5)",
    )
    .bind(post_start.0)
    .bind(takeover_owner)
    .bind(takeover_token)
    .bind(takeover.1)
    .bind(&directory_mismatch_evidence)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(directory_mismatch, "identity_mismatch");

    let content_owner = Uuid::new_v4();
    let content_token = Uuid::new_v4();
    let content_claim: (
        String,
        i64,
        String,
        String,
        i64,
        i64,
        Value,
        Value,
        i32,
        i32,
    ) = sqlx::query_as(
        "select outcome,claim_fence,publication_kind,selector,directory_device,
             directory_inode,expected_intent,expected_identity,route_count,present_count
             from control.claim_route_set_generation_retention($1,$2,$3,300)",
    )
    .bind(post_start.0)
    .bind(content_owner)
    .bind(content_token)
    .fetch_one(store.pool())
    .await
    .unwrap();
    let malformed_content = json!({
        "protocol_version":1,"publication_id":post_start.0,
        "claim_fence":content_claim.1,"resolution":"identity_mismatch",
        "selector":content_claim.3,"expected_intent":content_claim.6,
        "expected_identity":content_claim.7,
        "observed_current_selector":candidate.3,
        "observed_current_identity":identity,
        "target_present":true,"observed_target_device":content_claim.4,
        "observed_target_inode":content_claim.5,"mismatch_kind":"content_identity",
        "observed_target_identity":content_claim.7
    });
    let null_resolution: String = sqlx::query_scalar(
        "select control.finish_route_set_generation_retention(
          $1,$2,$3,$4,$5,$6)",
    )
    .bind(post_start.0)
    .bind(content_owner)
    .bind(content_token)
    .bind(content_claim.1)
    .bind(Option::<String>::None)
    .bind(&malformed_content)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(null_resolution, "invalid");
    let malformed_outcome: String = sqlx::query_scalar(
        "select control.finish_route_set_generation_retention(
          $1,$2,$3,$4,'identity_mismatch',$5)",
    )
    .bind(post_start.0)
    .bind(content_owner)
    .bind(content_token)
    .bind(content_claim.1)
    .bind(&malformed_content)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(malformed_outcome, "evidence_mismatch");
    let mut content_evidence = malformed_content.clone();
    content_evidence["observed_current_identity"] = candidate_identity.clone();
    let content_mismatch: String = sqlx::query_scalar(
        "select control.finish_route_set_generation_retention(
          $1,$2,$3,$4,'identity_mismatch',$5)",
    )
    .bind(post_start.0)
    .bind(content_owner)
    .bind(content_token)
    .bind(content_claim.1)
    .bind(&content_evidence)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(content_mismatch, "identity_mismatch");

    let absent_owner = Uuid::new_v4();
    let absent_token = Uuid::new_v4();
    let absent_claim: (
        String,
        i64,
        String,
        String,
        i64,
        i64,
        Value,
        Value,
        i32,
        i32,
    ) = sqlx::query_as(
        "select outcome,claim_fence,publication_kind,selector,directory_device,
             directory_inode,expected_intent,expected_identity,route_count,present_count
             from control.claim_route_set_generation_retention($1,$2,$3,300)",
    )
    .bind(post_start.0)
    .bind(absent_owner)
    .bind(absent_token)
    .fetch_one(store.pool())
    .await
    .unwrap();
    let absent_evidence = json!({
        "protocol_version":1,"publication_id":post_start.0,
        "claim_fence":absent_claim.1,"resolution":"already_absent",
        "selector":absent_claim.3,"expected_intent":absent_claim.6,
        "expected_identity":absent_claim.7,
        "observed_current_selector":candidate.3,
        "observed_current_identity":candidate_identity,
        "target_present":false,"observed_target_device":null,
        "observed_target_inode":null,"mismatch_kind":null,
        "observed_target_identity":null
    });
    let absent: String = sqlx::query_scalar(
        "select control.finish_route_set_generation_retention(
          $1,$2,$3,$4,'already_absent',$5)",
    )
    .bind(post_start.0)
    .bind(absent_owner)
    .bind(absent_token)
    .bind(absent_claim.1)
    .bind(&absent_evidence)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(absent, "already_absent");
    let effects_before_cap: i64 =
        sqlx::query_scalar("select count(*) from control.workshop_route_effect_runs")
            .fetch_one(store.pool())
            .await
            .unwrap();
    let publications_before_cap: i64 =
        sqlx::query_scalar("select count(*) from control.workshop_route_set_publications")
            .fetch_one(store.pool())
            .await
            .unwrap();
    sqlx::query(
        "insert into control.workshops(id,slug,display_name,time_zone)
         select gen_random_uuid(),'startup-cap-'||n::text,'Startup cap '||n::text,'UTC'
         from generate_series(1,500) n",
    )
    .execute(store.pool())
    .await
    .unwrap();
    let capped: String = sqlx::query_scalar(
        "select outcome from control.admit_route_set_startup_publication(
          gen_random_uuid(),'startup-over-cap',repeat('e',64),gen_random_uuid(),gen_random_uuid(),
          gen_random_uuid(),gen_random_uuid(),300,1::smallint)",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(capped, "fleet_too_large");
    let cap_state: (i64, i64, String, Option<Uuid>) = sqlx::query_as(
        "select (select count(*) from control.workshop_route_effect_runs),
         (select count(*) from control.workshop_route_set_publications),state,route_set_publication_id
         from control.deployment_driver_resource_leases where resource_key='runtime/shared-odoo'",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(
        cap_state,
        (
            effects_before_cap,
            publications_before_cap,
            "idle".into(),
            None
        )
    );

    let startup_acl: (bool, bool, bool, bool, bool) = sqlx::query_as(
        "select
          has_function_privilege('control_driver_ledger',
           'control.admit_route_set_startup_publication(uuid,text,text,uuid,uuid,uuid,uuid,integer,smallint)','execute'),
          has_function_privilege('control_driver_ledger',
           'control.finish_route_set_startup_publication_recovery(uuid,bigint,uuid,uuid,text,text,text)','execute'),
          has_table_privilege('control_driver_ledger',
           'control.workshop_route_set_startup_metadata','select,insert,update,delete'),
          has_function_privilege('control_driver_ledger',
           'control.claim_route_set_generation_retention(uuid,uuid,uuid,integer)','execute'),
          has_table_privilege('control_driver_ledger',
           'control.route_set_generation_retention_attempts','select,insert,update,delete')",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(startup_acl, (true, true, false, true, false));
    let release_completion_acl: (bool, bool, bool) = sqlx::query_as(
        "select
          has_function_privilege('control_driver_ledger',
           'control.finish_immutable_release_route_publication(uuid,uuid,uuid,uuid,uuid,bigint,jsonb)','execute'),
          has_function_privilege('control_driver_ledger',
           'control.read_immutable_release_route_publication_result(uuid,uuid)','execute'),
          has_table_privilege('control_driver_ledger',
           'control.fleet_release_route_publication_completions','select,insert,update,delete')",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(release_completion_acl, (true, true, false));
    let release_recovery_acl: (bool, bool, bool, bool, bool, bool, bool) = sqlx::query_as(
        "select
          has_function_privilege('control_driver_ledger',
           'control.claim_interrupted_immutable_release_route_publication(uuid,integer,text,uuid,uuid,integer)','execute'),
          has_function_privilege('control_driver_ledger',
           'control.finish_interrupted_immutable_release_route_publication(uuid,integer,text,uuid,uuid,bigint,text,text)','execute'),
          has_table_privilege('control_driver_ledger',
           'control.fleet_release_route_publication_recovery_claims','select,insert,update,delete'),
          has_table_privilege('control_driver_ledger',
           'control.fleet_release_route_publication_recovery_candidate_records','select,insert,update,delete'),
          has_table_privilege('control_driver_ledger',
           'control.fleet_release_route_publication_recovery_route_heads','select,insert,update,delete'),
          has_function_privilege('control_driver_ledger',
           'control.finish_immutable_release_route_publication_before_recovery(uuid,uuid,uuid,uuid,uuid,bigint,jsonb)','execute'),
          has_function_privilege('control_release_worker',
           'control.claim_interrupted_immutable_release_route_publication(uuid,integer,text,uuid,uuid,integer)','execute')",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(
        release_recovery_acl,
        (true, true, false, false, false, false, false)
    );
    let startup_acl_violations: i64 = sqlx::query_scalar(
        "select count(*)
         from unnest(array[
          'control_api','control_tenant_api','control_membership_worker',
          'control_provisioning_worker','control_invoice_worker','control_inventory_worker',
          'control_email_worker','control_reconciliation_worker','control_lifecycle_worker',
          'control_backup_scheduler','control_release_worker','control_privacy_worker']) role_name
         cross join unnest(array[
          'control.read_route_set_startup_admission(uuid,text,text)',
          'control.admit_route_set_startup_publication(uuid,text,text,uuid,uuid,uuid,uuid,integer,smallint)',
          'control.finish_route_set_startup_publication(uuid,uuid,uuid,uuid,uuid,bigint)',
          'control.claim_interrupted_route_set_startup_publication(uuid,uuid,uuid,integer)',
          'control.finish_route_set_startup_publication_recovery(uuid,bigint,uuid,uuid,text,text,text)',
          'control.discover_route_set_generation_retention_candidates(uuid,integer)',
          'control.claim_route_set_generation_retention(uuid,uuid,uuid,integer)',
          'control.finish_route_set_generation_retention(uuid,uuid,uuid,bigint,text,jsonb)',
          'control.finish_immutable_release_route_publication(uuid,uuid,uuid,uuid,uuid,bigint,jsonb)',
          'control.read_immutable_release_route_publication_result(uuid,uuid)',
          'control.claim_interrupted_immutable_release_route_publication(uuid,integer,text,uuid,uuid,integer)',
          'control.read_interrupted_immutable_release_runtime_expectation(uuid,integer,text,uuid,uuid,bigint)',
          'control.finish_interrupted_immutable_release_route_publication(uuid,integer,text,uuid,uuid,bigint,text,text)']) signature
         where has_function_privilege(role_name,signature,'execute')",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(startup_acl_violations, 0);

    store.pool().close().await;
    drop_database(&admin, &database).await;
    drop_runtime_roles(&admin).await;
}

#[tokio::test]
#[ignore = "requires a PostgreSQL 17 CONTROL_TEST_ADMIN_URL with CREATEDB"]
async fn fresh_catalog_matches_the_curated_baseline_manifest() {
    let expected: CatalogManifest =
        serde_json::from_str(include_str!("control_plane_catalog.json")).unwrap();
    let admin_url = std::env::var("CONTROL_TEST_ADMIN_URL").expect("CONTROL_TEST_ADMIN_URL");
    let database = format!("control_catalog_{}", Uuid::new_v4().simple());
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&admin_url)
        .await
        .unwrap();
    create_runtime_roles(&admin).await;
    sqlx::query(AssertSqlSafe(format!("create database \"{database}\"")))
        .execute(&admin)
        .await
        .unwrap();
    let store = Store::connect(&database_url(&admin_url, &database))
        .await
        .unwrap();
    store.migrate().await.unwrap();
    let server_major: i32 =
        sqlx::query_scalar("select current_setting('server_version_num')::integer / 10000")
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert_eq!(server_major, expected.postgres_major);
    let relations = sqlx::query_scalar::<_, String>(
        "select c.relname from pg_class c join pg_namespace n on n.oid=c.relnamespace
         where n.nspname='control' and c.relkind in ('r','v') order by c.relname",
    )
    .fetch_all(store.pool())
    .await
    .unwrap();
    assert_eq!(relations, expected.relations);

    let actual = sqlx::query_as::<_, (String, i64, String)>(
        "with
         columns as (
           select jsonb_agg(jsonb_build_object(
             'table',c.relname,'name',a.attname,'type',format_type(a.atttypid,a.atttypmod),
             'nullable',not a.attnotnull,'default',pg_get_expr(d.adbin,d.adrelid)
           ) order by c.relname,a.attnum) value,count(*) count
           from pg_attribute a join pg_class c on c.oid=a.attrelid
           join pg_namespace n on n.oid=c.relnamespace
           left join pg_attrdef d on d.adrelid=a.attrelid and d.adnum=a.attnum
           where n.nspname='control' and c.relkind in ('r','v')
             and a.attnum>0 and not a.attisdropped
         ), constraints as (
           select jsonb_agg(jsonb_build_object(
             'table',c.relname,'name',con.conname,
             'definition',pg_get_constraintdef(con.oid,true)
           ) order by c.relname,con.conname) value,count(*) count
           from pg_constraint con join pg_class c on c.oid=con.conrelid
           join pg_namespace n on n.oid=c.relnamespace where n.nspname='control'
         ), indexes as (
           select jsonb_agg(jsonb_build_object('name',i.relname,'definition',pg_get_indexdef(i.oid))
             order by i.relname) value,count(*) count
           from pg_class i join pg_namespace n on n.oid=i.relnamespace
           where n.nspname='control' and i.relkind='i'
         ), functions as (
           select jsonb_agg(jsonb_build_object(
             'name',p.proname,'arguments',pg_get_function_identity_arguments(p.oid),
             'security_definer',p.prosecdef,'config',p.proconfig
           ) order by p.proname,pg_get_function_identity_arguments(p.oid)) value,count(*) count
           from pg_proc p join pg_namespace n on n.oid=p.pronamespace
           where n.nspname='control'
         ), triggers as (
           select jsonb_agg(jsonb_build_object(
             'table',c.relname,'name',t.tgname,'definition',pg_get_triggerdef(t.oid,true)
           ) order by c.relname,t.tgname) value,count(*) count
           from pg_trigger t join pg_class c on c.oid=t.tgrelid
           join pg_namespace n on n.oid=c.relnamespace
           where n.nspname='control' and not t.tgisinternal
         ), privileges as (
           select 'schema'::text object_type,n.nspname object_name,
             case when acl.grantee=n.nspowner then 'OWNER'
                  when acl.grantee=0 then 'PUBLIC' else role.rolname end grantee,
             acl.privilege_type::text privilege
           from pg_namespace n
           cross join lateral aclexplode(coalesce(n.nspacl,acldefault('n',n.nspowner))) acl
           left join pg_roles role on role.oid=acl.grantee
           where n.nspname='control'
           union all
           select case object.relkind when 'S' then 'sequence' when 'v' then 'view' else 'table' end,
             namespace.nspname||'.'||object.relname,
             case when acl.grantee=object.relowner then 'OWNER'
                  when acl.grantee=0 then 'PUBLIC' else role.rolname end,
             acl.privilege_type::text
           from pg_class object join pg_namespace namespace on namespace.oid=object.relnamespace
           cross join lateral aclexplode(coalesce(object.relacl,acldefault(
             case when object.relkind='S' then 'S'::\"char\" else 'r'::\"char\" end,
             object.relowner))) acl
           left join pg_roles role on role.oid=acl.grantee
           where namespace.nspname='control' and object.relkind in ('r','v','S')
           union all
           select 'function',namespace.nspname||'.'||procedure.proname||'('||
             pg_get_function_identity_arguments(procedure.oid)||')',
             case when acl.grantee=procedure.proowner then 'OWNER'
                  when acl.grantee=0 then 'PUBLIC' else role.rolname end,
             acl.privilege_type::text
           from pg_proc procedure join pg_namespace namespace on namespace.oid=procedure.pronamespace
           cross join lateral aclexplode(coalesce(procedure.proacl,acldefault('f',procedure.proowner))) acl
           left join pg_roles role on role.oid=acl.grantee
           where namespace.nspname='control'
         ), privilege_value as (
           select jsonb_agg(jsonb_build_object(
             'object_type',object_type,'object_name',object_name,
             'grantee',grantee,'privilege',privilege
           ) order by object_type,object_name,grantee,privilege) value,count(*) count
           from privileges
         ), default_privileges as (
           select kinds.name,
             coalesce(jsonb_agg(jsonb_build_object(
               'grantee',case when acl.grantee=owner.oid then 'OWNER'
                              when acl.grantee=0 then 'PUBLIC' else role.rolname end,
               'privilege',acl.privilege_type::text
             ) order by case when acl.grantee=owner.oid then 'OWNER'
                             when acl.grantee=0 then 'PUBLIC' else role.rolname end,
                        acl.privilege_type),'[]'::jsonb) privileges
           from (values('functions','f'::\"char\"),('sequences','S'::\"char\"),
                       ('tables','r'::\"char\")) kinds(name,objtype)
           left join pg_default_acl defaults
             on defaults.defaclrole=(select oid from pg_roles where rolname=current_user)
            and defaults.defaclnamespace=0 and defaults.defaclobjtype=kinds.objtype
           left join lateral aclexplode(coalesce(defaults.defaclacl,
             acldefault(kinds.objtype,(select oid from pg_roles where rolname=current_user)))) acl on true
           left join pg_roles role on role.oid=acl.grantee
           cross join lateral (select oid from pg_roles where rolname=current_user) owner
           group by kinds.name
         ), default_privilege_value as (
           select jsonb_agg(jsonb_build_object(
             'object_type',name,'privileges',privileges
           ) order by name) value,count(*) count from default_privileges
         )
         select 'columns',count,md5(value::text) from columns
         union all select 'constraints',count,md5(value::text) from constraints
         union all select 'indexes',count,md5(value::text) from indexes
         union all select 'functions',count,md5(value::text) from functions
         union all select 'triggers',count,md5(value::text) from triggers
         union all select 'privileges',count,md5(value::text) from privilege_value
         union all select 'default_privileges',count,md5(value::text) from default_privilege_value",
    )
    .fetch_all(store.pool())
    .await
    .unwrap();
    let mut drift = Vec::new();
    for (name, count, digest) in actual {
        let fingerprint = expected.catalog.get(&name).unwrap();
        if count != fingerprint.count || digest != fingerprint.digest {
            drift.push(format!(
                "{name}: count={count}, digest={digest} (expected count={}, digest={})",
                fingerprint.count, fingerprint.digest
            ));
        }
    }
    store.pool().close().await;
    drop_database(&admin, &database).await;
    drop_runtime_roles(&admin).await;
    assert!(drift.is_empty(), "catalog drift:\n{}", drift.join("\n"));
}

#[tokio::test]
#[ignore = "requires a PostgreSQL 17 CONTROL_TEST_ADMIN_URL with CREATEDB"]
async fn empty_fleet_activation_succeeds_replays_and_refuses_invalid_slots() {
    let admin_url = std::env::var("CONTROL_TEST_ADMIN_URL").expect("CONTROL_TEST_ADMIN_URL");
    let database = format!("control_initial_slot_{}", Uuid::new_v4().simple());
    let admin = create_database(&admin_url, &database).await;
    let store = Store::connect(&database_url(&admin_url, &database))
        .await
        .unwrap();
    store.migrate().await.unwrap();
    let (release, image, manifest) = insert_prepared_release(&store, 1).await;

    let mut tx = store.begin().await.unwrap();
    assert_activation_conflict(
        activate_initial_release(&mut tx, &release)
            .await
            .unwrap_err(),
        "initial release has no verified prepared runtime slot",
    );
    tx.rollback().await.unwrap();
    insert_runtime_slot(&store, &release, &image, &manifest, "verifying", true, true).await;
    let mut tx = store.begin().await.unwrap();
    assert_activation_conflict(
        activate_initial_release(&mut tx, &release)
            .await
            .unwrap_err(),
        "initial release has no verified prepared runtime slot",
    );
    tx.rollback().await.unwrap();
    sqlx::query("update control.runtime_release_slots set state='prepared',verified_at=null")
        .execute(store.pool())
        .await
        .unwrap();
    let mut tx = store.begin().await.unwrap();
    assert_activation_conflict(
        activate_initial_release(&mut tx, &release)
            .await
            .unwrap_err(),
        "initial release has no verified prepared runtime slot",
    );
    tx.rollback().await.unwrap();
    sqlx::query("update control.runtime_release_slots set verified_at=now(),evidence=evidence||'{\"runtime_inspection_verified\":false}'::jsonb")
        .execute(store.pool()).await.unwrap();
    let mut tx = store.begin().await.unwrap();
    assert_activation_conflict(
        activate_initial_release(&mut tx, &release)
            .await
            .unwrap_err(),
        "prepared runtime slot is missing release-integrity evidence",
    );
    tx.rollback().await.unwrap();
    sqlx::query("update control.runtime_release_slots set evidence=evidence||'{\"runtime_inspection_verified\":true}'::jsonb")
        .execute(store.pool()).await.unwrap();
    let mut tx = store.begin().await.unwrap();
    let activated = activate_initial_release(&mut tx, &release).await.unwrap();
    assert_eq!(
        (
            activated.slot.as_str(),
            activated.version,
            activated.replayed
        ),
        ("blue", 2, false)
    );
    tx.commit().await.unwrap();
    let mut tx = store.begin().await.unwrap();
    let replay = activate_initial_release(&mut tx, &release).await.unwrap();
    assert_eq!(
        (replay.slot.as_str(), replay.version, replay.replayed),
        ("blue", 2, true)
    );
    tx.commit().await.unwrap();

    store.pool().close().await;
    drop_database(&admin, &database).await;
}

#[tokio::test]
#[ignore = "requires a PostgreSQL 17 CONTROL_TEST_ADMIN_URL with CREATEDB"]
async fn empty_fleet_activation_refuses_nonempty_or_mismatched_state() {
    let admin_url = std::env::var("CONTROL_TEST_ADMIN_URL").expect("CONTROL_TEST_ADMIN_URL");
    let database = format!("control_initial_guard_{}", Uuid::new_v4().simple());
    let admin = create_database(&admin_url, &database).await;
    let store = Store::connect(&database_url(&admin_url, &database))
        .await
        .unwrap();
    store.migrate().await.unwrap();
    let (release, image, manifest) = insert_prepared_release(&store, 1).await;
    insert_runtime_slot(&store, &release, &image, &manifest, "prepared", true, true).await;
    let workshop = Uuid::new_v4();
    sqlx::query("insert into control.workshops(id,slug,display_name,time_zone) values($1,$2,'Guard','Europe/Paris')")
        .bind(workshop).bind(format!("guard-{}",workshop.simple())).execute(store.pool()).await.unwrap();
    let mut tx = store.begin().await.unwrap();
    assert_activation_conflict(
        activate_initial_release(&mut tx, &release)
            .await
            .unwrap_err(),
        "initial release activation requires a completely empty fleet",
    );
    tx.rollback().await.unwrap();
    let database_id = Uuid::new_v4();
    sqlx::query("insert into control.odoo_databases(id,workshop_id,kind,database_ref,public_hostname,label,routable) values($1,$2,'primary',$3,$4,'Primary',true)")
        .bind(database_id).bind(workshop).bind(format!("mb_{}",database_id.simple())).bind(format!("{}.example.test",workshop.simple())).execute(store.pool()).await.unwrap();
    let mut tx = store.begin().await.unwrap();
    assert_activation_conflict(
        activate_initial_release(&mut tx, &release)
            .await
            .unwrap_err(),
        "initial release activation requires a completely empty fleet",
    );
    tx.rollback().await.unwrap();
    sqlx::query("insert into control.tenant_release_adoptions(id,workshop_id,database_id,release_id,registry_version,state,target_schema_epoch) values($1,$2,$3,$4,1,'active',1)")
        .bind(Uuid::new_v4()).bind(workshop).bind(database_id).bind(&release).execute(store.pool()).await.unwrap();
    let mut tx = store.begin().await.unwrap();
    assert_activation_conflict(
        activate_initial_release(&mut tx, &release)
            .await
            .unwrap_err(),
        "initial release activation requires a completely empty fleet",
    );
    tx.rollback().await.unwrap();
    sqlx::query("delete from control.tenant_release_adoptions")
        .execute(store.pool())
        .await
        .unwrap();
    sqlx::query("delete from control.odoo_databases")
        .execute(store.pool())
        .await
        .unwrap();
    sqlx::query("delete from control.workshop_route_application_leases")
        .execute(store.pool())
        .await
        .unwrap();
    sqlx::query("delete from control.workshop_route_projection_state")
        .execute(store.pool())
        .await
        .unwrap();
    sqlx::query("delete from control.workshops")
        .execute(store.pool())
        .await
        .unwrap();
    let active_release = format!("odoo-2026.08.21-{}", Uuid::new_v4().simple());
    sqlx::query("insert into control.application_releases(id,source_commit,odoo_version,odoo_subject_digest,extension_subject_digest,odoo_runtime,extension_bundle,pair_qualifications,manifest_digest,addon_versions,compatibility,bridge_contract,schema_epoch,change_class,required_postconditions,manifest,signature_bundle_ref,extension_signature_ref,sbom_ref,published_at,status,publication_idempotency_key,publication_request_digest) select $1,source_commit,odoo_version,$4,$5,odoo_runtime,extension_bundle,pair_qualifications,$6,addon_versions,compatibility,bridge_contract,schema_epoch,change_class,required_postconditions,manifest,signature_bundle_ref,extension_signature_ref,sbom_ref,published_at,'active',$2,$3 from control.application_releases where id=$7")
        .bind(&active_release).bind(format!("publish:{active_release}")).bind(vec![2_u8;32])
        .bind(format!("sha256:{}","d".repeat(64))).bind(format!("sha256:{}","e".repeat(64))).bind(format!("sha256:{}","7".repeat(64)))
        .bind(&release).execute(store.pool()).await.unwrap();
    let mut tx = store.begin().await.unwrap();
    assert_activation_conflict(
        activate_initial_release(&mut tx, &release)
            .await
            .unwrap_err(),
        "initial release activation requires a completely empty fleet",
    );
    tx.rollback().await.unwrap();
    sqlx::query("delete from control.application_releases where id=$1")
        .bind(&active_release)
        .execute(store.pool())
        .await
        .unwrap();
    sqlx::query("update control.application_releases set manifest=jsonb_set(manifest,'{capability_registry_version}','2'),version=version+1 where id=$1")
        .bind(&release).execute(store.pool()).await.unwrap();
    let mut tx = store.begin().await.unwrap();
    assert_activation_conflict(
        activate_initial_release(&mut tx, &release)
            .await
            .unwrap_err(),
        "release capability registry does not match the active registry",
    );
    tx.rollback().await.unwrap();

    store.pool().close().await;
    drop_database(&admin, &database).await;
}
