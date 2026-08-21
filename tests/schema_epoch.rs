use mb_control_plane::{
    modules::CATALOG,
    persistence::{InitialReleaseActivationError, Store, activate_initial_release},
};
use serde::Deserialize;
use serde_json::json;
use sqlx::AssertSqlSafe;
use sqlx::postgres::PgPoolOptions;
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
           create role control_api; create role control_backup_scheduler;
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
           drop role control_api,control_backup_scheduler,control_driver_ledger,
             control_email_worker,control_inventory_worker,control_invoice_worker,
             control_lifecycle_worker,control_membership_worker,control_provisioning_worker,
             control_reconciliation_worker,control_release_worker,control_privacy_worker;
         end $$",
    )
    .execute(admin)
    .await
    .expect("drop runtime roles after ACL catalog assertion");
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
           jsonb_build_object('capability_registry_version',$6),'oci://signature',
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
    assert_eq!(first.0, 1);
    assert_eq!(first.1, 1);
    assert_eq!(first.2, i64::try_from(CATALOG.len()).unwrap());

    store.migrate().await.expect("second migration startup");
    let second: i64 = sqlx::query_scalar("select count(*) from public._sqlx_migrations")
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(second, 1, "the second startup must not append a ledger row");
    store.pool().close().await;
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
