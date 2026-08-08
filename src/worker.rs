use std::time::Duration;

use base64::Engine;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::domain::IntegrationError;
use crate::integrations::azure::AzureInvoiceClient;
use crate::integrations::odoo::{
    EntitlementCommand, MembershipCommand, OdooClient, TenantBootstrapCommand,
};
use crate::integrations::paperless::PaperlessClient;
use crate::integrations::rauthy::RauthyClient;
use crate::persistence::{LeasedOperation, OperationOutcome, Store};

const QUEUES: [&str; 7] = [
    "identity-operations",
    "tenant-provisioning",
    "membership-provisioning",
    "invoice-capture",
    "email-delivery",
    "tenant-reconciliation",
    "tenant-lifecycle",
];

pub async fn run(store: Store, queue: &str) -> anyhow::Result<()> {
    if !QUEUES.contains(&queue) {
        anyhow::bail!("unknown worker queue {queue}")
    }
    let worker_id = format!("{queue}-{}", Uuid::new_v4());
    tracing::info!(queue,worker=%worker_id,"worker started");
    loop {
        tokio::select! {
            _=tokio::time::sleep(Duration::from_secs(2))=>{
                if let Some(operation)=store.lease(queue,&worker_id).await?{
                    let heartbeat_store = store.clone();
                    let heartbeat_operation_id = operation.id;
                    let heartbeat_worker = operation.leased_by.clone();
                    let heartbeat_attempt = operation.attempt;
                    let heartbeat = tokio::spawn(async move {
                        loop {
                            tokio::time::sleep(Duration::from_secs(20)).await;
                            match heartbeat_store.renew_lease(heartbeat_operation_id, &heartbeat_worker, heartbeat_attempt).await {
                                Ok(true) => {}
                                Ok(false) => break,
                                Err(error) => tracing::warn!(operation=%heartbeat_operation_id,error=%error,"operation lease heartbeat failed"),
                            }
                        }
                    });
                    let result = handle(&store,&operation).await;
                    if operation.kind == "tenant.lifecycle"
                        && result.as_ref().is_err_and(|error| !error.retryable() || operation.attempt >= operation.max_attempts)
                    {
                        lifecycle_failed(&store, &operation).await;
                    }
                    let outcome=match result{
                        Ok(())=>OperationOutcome::Succeeded,
                        Err(IntegrationError::UnknownOutcome)=>OperationOutcome::Unknown,
                        Err(error) if error.retryable()=>OperationOutcome::Retry(error),
                        Err(error)=>OperationOutcome::Failed(error),
                    };
                    heartbeat.abort();
                    store.finish(&operation,outcome).await?;
                }
            }
            _=crate::shutdown_signal()=>break,
        }
    }
    Ok(())
}

async fn handle(store: &Store, operation: &LeasedOperation) -> Result<(), IntegrationError> {
    tracing::info!(operation=%operation.id,kind=%operation.kind,attempt=operation.attempt,reconciling=operation.reconciling,"handling operation");
    match operation.kind.as_str() {
        "membership.reconcile" => membership(store, operation).await,
        "entitlement.apply" => entitlement(store, operation).await,
        "invoice.capture" => invoice(store, operation).await,
        "tenant.provision" => driver(store, operation, "provision").await.map(|_| ()),
        "tenant.reconcile" => driver(store, operation, "reconcile").await.map(|_| ()),
        "tenant.lifecycle" => lifecycle(store, operation).await,
        "email.delivery" => deliver_mail(store, operation).await,
        _ => Err(IntegrationError::ContractDrift),
    }
}

fn env(name: &str) -> Result<String, IntegrationError> {
    std::env::var(name)
        .ok()
        .filter(|v| !v.trim().is_empty())
        .ok_or(IntegrationError::Unauthorized)
}
fn secret(reference: &str) -> Result<String, IntegrationError> {
    if reference.is_empty() || reference.len() > 180 {
        return Err(IntegrationError::ContractDrift);
    }
    let valid_reference = reference.split('/').all(|segment| {
        !segment.is_empty()
            && segment.len() <= 64
            && segment
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    });
    if !valid_reference {
        return Err(IntegrationError::ContractDrift);
    }
    if let Ok(root) = std::env::var("CONTROL_SECRET_ROOT") {
        let root = std::fs::canonicalize(root).map_err(|_| IntegrationError::Unauthorized)?;
        let candidate = root.join(reference);
        let resolved =
            std::fs::canonicalize(&candidate).map_err(|_| IntegrationError::Unauthorized)?;
        if !resolved.starts_with(&root) {
            return Err(IntegrationError::ContractDrift);
        }
        let value = std::fs::read_to_string(resolved)
            .map_err(|_| IntegrationError::Unauthorized)?
            .trim_end_matches(['\r', '\n'])
            .to_owned();
        if value.is_empty() {
            return Err(IntegrationError::Unauthorized);
        }
        return Ok(value);
    }
    let name = format!(
        "CONTROL_SECRET__{}",
        reference
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            })
            .collect::<String>()
    );
    env(&name)
}

async fn service(
    store: &Store,
    workshop: Uuid,
    name: &str,
) -> Result<(String, String, Option<String>), IntegrationError> {
    sqlx::query_as::<_, (String, String, Option<String>)>(
        "select si.base_url,si.secret_ref,od.database_ref
        from control.service_instances si
        left join control.odoo_databases od on od.workshop_id=si.workshop_id
            and od.kind='primary' and od.deleted_at is null and si.service='odoo'
        where si.workshop_id=$1 and si.service=$2",
    )
    .bind(workshop)
    .bind(name)
    .fetch_optional(store.pool())
    .await
    .map_err(|_| IntegrationError::Unavailable)?
    .ok_or(IntegrationError::NotFound)
}

async fn membership(store: &Store, operation: &LeasedOperation) -> Result<(), IntegrationError> {
    let workshop = operation
        .workshop_id
        .ok_or(IntegrationError::ContractDrift)?;
    let user = operation
        .target_user_id
        .ok_or(IntegrationError::ContractDrift)?;
    let epoch = operation
        .desired_epoch
        .ok_or(IntegrationError::ContractDrift)?;
    let row=sqlx::query_as::<_,(String,Option<String>,String,String,String,i32)>("select u.email,u.display_name,i.subject,m.role,m.status,m.authority_epoch from control.users u join control.external_identities i on i.user_id=u.id join control.memberships m on m.user_id=u.id where u.id=$1 and m.workshop_id=$2")
        .bind(user).bind(workshop).fetch_optional(store.pool()).await.map_err(|_|IntegrationError::Unavailable)?.ok_or(IntegrationError::NotFound)?;
    if row.5 != epoch {
        return Ok(());
    }
    let active = row.4 == "active";
    let rauthy = RauthyClient::new(
        &env("CONTROL_RAUTHY_ADMIN_URL")?,
        &env("CONTROL_RAUTHY_ADMIN_KEY")?,
        Duration::from_secs(10),
    )
    .map_err(|_| IntegrationError::ContractDrift)?;
    let rauthy_result = async {
        rauthy.observe_user(&row.2, &row.0).await?;
        if !active {
            rauthy.revoke_sessions(&row.2).await?
        }
        Ok(())
    }
    .await;
    record_target(
        store,
        workshop,
        user,
        "rauthy",
        epoch,
        &rauthy_result,
        if active { "ready" } else { "disabled" },
    )
    .await?;
    let odoo_result = async {
        let (url, reference, database_ref) = service(store, workshop, "odoo").await?;
        let client = OdooClient::new(
            &url,
            &secret(&reference)?,
            database_ref.as_deref(),
            Duration::from_secs(20),
        )
        .map_err(|_| IntegrationError::ContractDrift)?;
        client
            .reconcile_membership(&MembershipCommand {
                operation_key: format!("membership:{workshop}:{user}:{epoch}"),
                workshop_id: workshop,
                user_id: user,
                subject: row.2.clone(),
                email: row.0.clone(),
                name: row.1.clone().unwrap_or_else(|| row.0.clone()),
                role: row.3.clone(),
                epoch,
                active,
            })
            .await?;
        Ok(())
    }
    .await;
    record_target(
        store,
        workshop,
        user,
        "odoo",
        epoch,
        &odoo_result,
        if active { "ready" } else { "disabled" },
    )
    .await?;
    let paperless_result = async {
        let (url, reference, _) = service(store, workshop, "paperless").await?;
        let client = PaperlessClient::new(&url, &secret(&reference)?, Duration::from_secs(20))
            .map_err(|_| IntegrationError::ContractDrift)?;
        let groups = client.ensure_groups(paperless_group_names(&row.3)?).await?;
        client.reconcile_user(&row.2, &row.0, active, &groups).await
    }
    .await;
    record_target(
        store,
        workshop,
        user,
        "paperless",
        epoch,
        &paperless_result,
        if active { "ready" } else { "disabled" },
    )
    .await?;
    for result in [rauthy_result, odoo_result, paperless_result] {
        result?
    }
    Ok(())
}

fn paperless_group_names(role: &str) -> Result<&'static [&'static str], IntegrationError> {
    match role {
        "viewer" => Ok(&["MakersBrain Viewer"]),
        "artisan" => Ok(&["MakersBrain Artisan"]),
        "accountant" => Ok(&["MakersBrain Accountant"]),
        "studio_manager" | "owner" => Ok(&["MakersBrain Studio Manager"]),
        _ => Err(IntegrationError::ContractDrift),
    }
}

async fn record_target(
    store: &Store,
    workshop: Uuid,
    user: Uuid,
    target: &str,
    epoch: i32,
    result: &Result<(), IntegrationError>,
    success: &str,
) -> Result<(), IntegrationError> {
    let (state, error) = match result {
        Ok(()) => (success, None),
        Err(error) => ("degraded", Some(error.failure_class())),
    };
    sqlx::query("update control.membership_targets set applied_epoch=case when $5 is null then $4 else applied_epoch end,state=$6,safe_error_class=$5,observed_at=now() where workshop_id=$1 and user_id=$2 and target=$3 and desired_epoch=$4")
        .bind(workshop).bind(user).bind(target).bind(epoch).bind(error).bind(state).execute(store.pool()).await.map_err(|_|IntegrationError::Unavailable)?;
    Ok(())
}

async fn entitlement(store: &Store, operation: &LeasedOperation) -> Result<(), IntegrationError> {
    let workshop = operation
        .workshop_id
        .ok_or(IntegrationError::ContractDrift)?;
    let row=sqlx::query_as::<_,(i64,String,String,Value,Option<time::OffsetDateTime>,String)>("select version,plan,status,limits,expires_at,signature from control.entitlements where workshop_id=$1").bind(workshop).fetch_optional(store.pool()).await.map_err(|_|IntegrationError::Unavailable)?.ok_or(IntegrationError::NotFound)?;
    let (url, reference, database_ref) = service(store, workshop, "odoo").await?;
    let client = OdooClient::new(
        &url,
        &secret(&reference)?,
        database_ref.as_deref(),
        Duration::from_secs(20),
    )
    .map_err(|_| IntegrationError::ContractDrift)?;
    client
        .apply_entitlement(&EntitlementCommand {
            operation_key: format!("entitlement:{workshop}:{}", row.0),
            workshop_id: workshop,
            version: row.0,
            plan: row.1,
            status: row.2,
            limits: row.3,
            expires_at: row.4.map(|v| v.to_string()),
            signature: row.5,
        })
        .await?;
    Ok(())
}

async fn invoice(store: &Store, operation: &LeasedOperation) -> Result<(), IntegrationError> {
    let workshop = operation
        .workshop_id
        .ok_or(IntegrationError::ContractDrift)?;
    let document_id = operation
        .payload
        .get("document_id")
        .and_then(Value::as_i64)
        .ok_or(IntegrationError::ContractDrift)?;
    let (paperless_url, paperless_ref, _) = service(store, workshop, "paperless").await?;
    let paperless = PaperlessClient::new(
        &paperless_url,
        &secret(&paperless_ref)?,
        Duration::from_secs(30),
    )
    .map_err(|_| IntegrationError::ContractDrift)?;
    let metadata = paperless.document(document_id).await?;
    let (mimetype, source) = paperless.original(document_id).await?;
    let digest = format!("{:x}", Sha256::digest(&source));
    let (provider, invoice, confidence, pages) =
        if let Some(invoice) = crate::invoice::structured(&source) {
            ("structured", invoice, json!({}), 1_i64)
        } else {
            reserve_azure(
                store,
                operation.id,
                workshop,
                estimated_pages(&source, &mimetype),
            )
            .await?;
            throttle_azure_submission(store).await?;
            let azure = AzureInvoiceClient::new(
                &env("CONTROL_AZURE_ENDPOINT")?,
                &env("CONTROL_AZURE_KEY")?,
                &std::env::var("CONTROL_AZURE_API_VERSION").unwrap_or_else(|_| "2024-11-30".into()),
                Duration::from_secs(45),
                Duration::from_millis(
                    std::env::var("CONTROL_AZURE_POLL_INTERVAL_MS")
                        .ok()
                        .and_then(|value| value.parse().ok())
                        .unwrap_or(2_000_u64)
                        .max(2_000),
                ),
            )
            .map_err(|_| IntegrationError::ContractDrift)?;
            let result = azure.analyze(&source, &mimetype).await?;
            let (invoice, confidence, pages) = crate::invoice::normalize_azure(&result)?;
            ("azure", invoice, confidence, pages)
        };
    let requires_review = crate::invoice::requires_review(&invoice, &confidence);
    let (odoo_url, odoo_ref, database_ref) = service(store, workshop, "odoo").await?;
    let odoo = OdooClient::new(
        &odoo_url,
        &secret(&odoo_ref)?,
        database_ref.as_deref(),
        Duration::from_secs(45),
    )
    .map_err(|_| IntegrationError::ContractDrift)?;
    odoo.capture_invoice(&json!({"operation_key":format!("invoice:{workshop}:{document_id}:{digest}"),"workshop_id":workshop,"external_document_id":format!("paperless:{document_id}"),"content_digest":digest,"source_filename":metadata.filename,"source_mimetype":mimetype,"source_base64":base64::engine::general_purpose::STANDARD.encode(&source),"provider":provider,"model":if provider=="azure"{"prebuilt-invoice"}else{"structured"},"page_count":pages,"requires_review":requires_review,"field_confidence":confidence,"invoice":invoice})).await?;
    if let Ok(tags) = std::env::var("CONTROL_PAPERLESS_CAPTURED_TAG_IDS") {
        let mut ids = tags
            .split(',')
            .filter_map(|v| v.trim().parse().ok())
            .collect::<Vec<_>>();
        ids.extend(metadata.tags.iter().copied());
        ids.sort_unstable();
        ids.dedup();
        if !ids.is_empty() {
            paperless.mark_capture(document_id, &ids).await?
        }
    }
    Ok(())
}

fn estimated_pages(source: &[u8], mimetype: &str) -> i64 {
    if mimetype == "application/pdf" {
        source
            .windows(11)
            .filter(|window| *window == b"/Type /Page")
            .count()
            .max(1) as i64
    } else {
        1
    }
}
async fn reserve_azure(
    store: &Store,
    operation: Uuid,
    workshop: Uuid,
    pages: i64,
) -> Result<(), IntegrationError> {
    let limit = std::env::var("CONTROL_AZURE_MONTHLY_PAGE_LIMIT")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(1000);
    let mut transaction = store
        .begin()
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
    let reserved = sqlx::query_scalar::<_, i64>(
        "insert into control.usage_reservations(operation_id,workshop_id,metric,quantity)
         values($1,$2,'azure_invoice_pages',$3)
         on conflict(operation_id) do nothing returning quantity",
    )
    .bind(operation)
    .bind(workshop)
    .bind(pages)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| IntegrationError::Unavailable)?;
    if reserved.is_none() {
        transaction
            .rollback()
            .await
            .map_err(|_| IntegrationError::Unavailable)?;
        return Ok(());
    }
    let quantity=sqlx::query_scalar::<_,i64>("insert into control.usage_counters(workshop_id,period,metric,quantity) select $1,date_trunc('month',current_date)::date,'azure_invoice_pages',$2 where $2<=$3 on conflict(workshop_id,period,metric) do update set quantity=control.usage_counters.quantity+excluded.quantity,updated_at=now() where control.usage_counters.quantity+excluded.quantity<=$3 returning quantity")
        .bind(workshop).bind(pages).bind(limit).fetch_optional(&mut *transaction).await.map_err(|_|IntegrationError::Unavailable)?;
    if quantity.is_none() {
        transaction
            .rollback()
            .await
            .map_err(|_| IntegrationError::Unavailable)?;
        return Err(IntegrationError::Rejected);
    }
    transaction
        .commit()
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
    Ok(())
}

async fn throttle_azure_submission(store: &Store) -> Result<(), IntegrationError> {
    let interval_ms = std::env::var("CONTROL_AZURE_ANALYZE_MIN_INTERVAL_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(1_100)
        .clamp(100, 60_000);
    let interval_seconds = interval_ms as f64 / 1_000.0;
    let delay_seconds = sqlx::query_scalar::<_, f64>(
        "insert into control.provider_rate_limits(provider,next_allowed_at)
         values('azure_document_analyze',now()+make_interval(secs=>$1))
         on conflict(provider) do update set
           next_allowed_at=greatest(control.provider_rate_limits.next_allowed_at,now())+make_interval(secs=>$1),
           updated_at=now()
         returning greatest(0,extract(epoch from
           (next_allowed_at-make_interval(secs=>$1)-now())))::float8",
    )
    .bind(interval_seconds)
    .fetch_one(store.pool())
    .await
    .map_err(|_| IntegrationError::Unavailable)?;
    if delay_seconds > 0.0 {
        tokio::time::sleep(Duration::from_secs_f64(delay_seconds)).await;
    }
    Ok(())
}

async fn driver(
    store: &Store,
    operation: &LeasedOperation,
    action: &str,
) -> Result<Value, IntegrationError> {
    let workshop = operation
        .workshop_id
        .ok_or(IntegrationError::ContractDrift)?;
    let url = env("CONTROL_DEPLOYMENT_DRIVER_URL")?;
    let token = env("CONTROL_DEPLOYMENT_DRIVER_TOKEN")?;
    // First-time Odoo and Paperless initialization can legitimately take several
    // minutes. The operation lease is heartbeated while this request is in flight,
    // and the driver persists idempotent outcomes for ambiguous disconnects.
    let client = http_client(&token, Duration::from_secs(900))?;
    let response = client
        .post(format!(
            "{}/v1/tenants/{workshop}/{action}",
            url.trim_end_matches('/')
        ))
        .header("idempotency-key", operation.id.to_string())
        .json(&operation.payload)
        .send()
        .await
        .map_err(|error| {
            if error.is_timeout() {
                IntegrationError::UnknownOutcome
            } else {
                IntegrationError::Unavailable
            }
        })?;
    let status = response.status();
    let value: Value = response
        .json()
        .await
        .map_err(|_| IntegrationError::ContractDrift)?;
    if !status.is_success() {
        return Err(super_classify(status));
    }
    if action == "provision" {
        for service_name in ["odoo", "paperless"] {
            let service = value
                .get(service_name)
                .ok_or(IntegrationError::ContractDrift)?;
            let base = service
                .get("base_url")
                .and_then(Value::as_str)
                .ok_or(IntegrationError::ContractDrift)?;
            let secret_ref = service
                .get("secret_ref")
                .and_then(Value::as_str)
                .ok_or(IntegrationError::ContractDrift)?;
            sqlx::query("insert into control.service_instances(id,workshop_id,service,base_url,secret_ref,release_id,health,applied_epoch) values($1,$2,$3,$4,$5,$6,'ready',1) on conflict(workshop_id,service) do update set base_url=excluded.base_url,secret_ref=excluded.secret_ref,release_id=excluded.release_id,health='ready',last_observed_at=now()")
        .bind(Uuid::new_v4()).bind(workshop).bind(service_name).bind(base).bind(secret_ref).bind(value.get("release_id").and_then(Value::as_str)).execute(store.pool()).await.map_err(|_|IntegrationError::Unavailable)?;
        }
        let expected_ref = operation
            .payload
            .get("database_ref")
            .and_then(Value::as_str)
            .ok_or(IntegrationError::ContractDrift)?;
        let expected_hostname = operation
            .payload
            .get("public_hostname")
            .and_then(Value::as_str)
            .ok_or(IntegrationError::ContractDrift)?;
        let database = value
            .get("odoo")
            .and_then(|odoo| odoo.get("database"))
            .ok_or(IntegrationError::ContractDrift)?;
        if database.get("database_ref").and_then(Value::as_str) != Some(expected_ref)
            || database.get("public_hostname").and_then(Value::as_str) != Some(expected_hostname)
            || expected_hostname == expected_ref
        {
            return Err(IntegrationError::ContractDrift);
        }
        let service_id = sqlx::query_scalar::<_, Uuid>(
            "select id from control.service_instances where workshop_id=$1 and service='odoo'",
        )
        .bind(workshop)
        .fetch_one(store.pool())
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
        let changed = sqlx::query("update control.odoo_databases set service_instance_id=$2,state='ready' where workshop_id=$1 and kind='primary' and database_ref=$3 and public_hostname=$4")
            .bind(workshop).bind(service_id).bind(expected_ref).bind(expected_hostname).execute(store.pool()).await.map_err(|_|IntegrationError::Unavailable)?;
        if changed.rows_affected() != 1 {
            return Err(IntegrationError::ContractDrift);
        }
        let odoo_config = value
            .get("odoo_oidc")
            .ok_or(IntegrationError::ContractDrift)?;
        let oidc_client_id = odoo_config
            .get("client_id")
            .and_then(Value::as_str)
            .ok_or(IntegrationError::ContractDrift)?;
        let oidc_issuer = odoo_config
            .get("issuer")
            .and_then(Value::as_str)
            .ok_or(IntegrationError::ContractDrift)?;
        let (odoo_url, odoo_ref, database_ref) = service(store, workshop, "odoo").await?;
        let odoo = OdooClient::new(
            &odoo_url,
            &secret(&odoo_ref)?,
            database_ref.as_deref(),
            Duration::from_secs(30),
        )
        .map_err(|_| IntegrationError::ContractDrift)?;
        odoo.bootstrap_tenant(&TenantBootstrapCommand {
            operation_key: format!("tenant-bootstrap:{workshop}"),
            workshop_id: workshop,
            oidc_client_id: oidc_client_id.into(),
            oidc_issuer: oidc_issuer.into(),
        })
        .await?;
        sqlx::query("update control.workshops set status='trial',version=version+1 where id=$1 and status='provisioning'").bind(workshop).execute(store.pool()).await.map_err(|_|IntegrationError::Unavailable)?;
        let owner = sqlx::query_as::<_, (Uuid, i32)>(
            "select user_id,authority_epoch from control.memberships where workshop_id=$1 and role='owner' and status='active'",
        )
        .bind(workshop)
        .fetch_optional(store.pool())
        .await
        .map_err(|_| IntegrationError::Unavailable)?
        .ok_or(IntegrationError::ContractDrift)?;
        let mut tx = store
            .begin()
            .await
            .map_err(|_| IntegrationError::Unavailable)?;
        seed_membership_targets(&mut tx, workshop, owner.0, owner.1).await?;
        let payload = json!({"active":true});
        let key = format!("provision-owner:{workshop}:{}", owner.1);
        Store::enqueue(
            &mut tx,
            crate::persistence::NewOperation {
                kind: crate::domain::OperationKind::MembershipReconcile,
                workshop_id: Some(workshop),
                target_user_id: Some(owner.0),
                desired_epoch: Some(owner.1),
                payload: &payload,
                requested_by: Some(owner.0),
                correlation_id: Uuid::new_v4(),
                idempotency_key: &key,
            },
        )
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
        tx.commit()
            .await
            .map_err(|_| IntegrationError::Unavailable)?;
    }
    Ok(value)
}

async fn lifecycle(store: &Store, operation: &LeasedOperation) -> Result<(), IntegrationError> {
    let action = operation
        .payload
        .get("action")
        .and_then(Value::as_str)
        .ok_or(IntegrationError::ContractDrift)?;
    match action {
        "snapshot" | "backup" => {
            let recovery = payload_uuid(&operation.payload, "recovery_point_id")?;
            sqlx::query("update control.odoo_recovery_points set state='creating' where id=$1 and state in ('queued','failed')")
                .bind(recovery).execute(store.pool()).await.map_err(|_|IntegrationError::Unavailable)?;
        }
        "restore" => {
            let database = payload_uuid(&operation.payload, "database_id")?;
            let safety = payload_uuid(&operation.payload, "safety_recovery_point_id")?;
            sqlx::query("update control.odoo_databases set state='restoring' where id=$1")
                .bind(database)
                .execute(store.pool())
                .await
                .map_err(|_| IntegrationError::Unavailable)?;
            sqlx::query("update control.odoo_recovery_points set state='creating' where id=$1 and state in ('queued','failed')")
                .bind(safety).execute(store.pool()).await.map_err(|_|IntegrationError::Unavailable)?;
        }
        "duplicate" => {
            let target = payload_uuid(&operation.payload, "target_database_id")?;
            sqlx::query("update control.odoo_databases set state='duplicating' where id=$1")
                .bind(target)
                .execute(store.pool())
                .await
                .map_err(|_| IntegrationError::Unavailable)?;
        }
        _ => return Err(IntegrationError::ContractDrift),
    }
    let value = driver(store, operation, "lifecycle").await?;
    match action {
        "snapshot" | "backup" => {
            let recovery = payload_uuid(&operation.payload, "recovery_point_id")?;
            let result = value
                .get("recovery_point")
                .ok_or(IntegrationError::ContractDrift)?;
            let storage_ref = result
                .get("storage_ref")
                .and_then(Value::as_str)
                .ok_or(IntegrationError::ContractDrift)?;
            let size_bytes = result
                .get("size_bytes")
                .and_then(Value::as_i64)
                .ok_or(IntegrationError::ContractDrift)?;
            sqlx::query("update control.odoo_recovery_points set state='ready',storage_ref=$2,size_bytes=$3,ready_at=now() where id=$1")
                .bind(recovery).bind(storage_ref).bind(size_bytes).execute(store.pool()).await.map_err(|_|IntegrationError::Unavailable)?;
        }
        "restore" => {
            let database = payload_uuid(&operation.payload, "database_id")?;
            let safety = payload_uuid(&operation.payload, "safety_recovery_point_id")?;
            let result = value
                .get("safety_recovery_point")
                .ok_or(IntegrationError::ContractDrift)?;
            let storage_ref = result
                .get("storage_ref")
                .and_then(Value::as_str)
                .ok_or(IntegrationError::ContractDrift)?;
            let size_bytes = result
                .get("size_bytes")
                .and_then(Value::as_i64)
                .ok_or(IntegrationError::ContractDrift)?;
            let mut tx = store
                .begin()
                .await
                .map_err(|_| IntegrationError::Unavailable)?;
            sqlx::query("update control.odoo_recovery_points set state='ready',storage_ref=$2,size_bytes=$3,ready_at=now() where id=$1")
                .bind(safety).bind(storage_ref).bind(size_bytes).execute(&mut *tx).await.map_err(|_|IntegrationError::Unavailable)?;
            sqlx::query("update control.odoo_databases set state='ready',last_restored_at=now() where id=$1")
                .bind(database).execute(&mut *tx).await.map_err(|_|IntegrationError::Unavailable)?;
            tx.commit()
                .await
                .map_err(|_| IntegrationError::Unavailable)?;
        }
        "duplicate" => {
            let target = payload_uuid(&operation.payload, "target_database_id")?;
            sqlx::query("update control.odoo_databases set state='ready' where id=$1 and kind='duplicate' and routable=false")
                .bind(target).execute(store.pool()).await.map_err(|_|IntegrationError::Unavailable)?;
        }
        _ => return Err(IntegrationError::ContractDrift),
    }
    Ok(())
}

async fn lifecycle_failed(store: &Store, operation: &LeasedOperation) {
    let action = operation.payload.get("action").and_then(Value::as_str);
    if action == Some("restore")
        && let Ok(safety) = payload_uuid(&operation.payload, "safety_recovery_point_id")
        && let Err(error) =
            sqlx::query("update control.odoo_recovery_points set state='failed' where id=$1")
                .bind(safety)
                .execute(store.pool())
                .await
    {
        tracing::error!(operation=%operation.id,error=%error,"could not mark restore safety snapshot failed");
    }
    let result = match action {
        Some("snapshot" | "backup") => {
            payload_uuid(&operation.payload, "recovery_point_id").map(|id| {
                (
                    "update control.odoo_recovery_points set state='failed' where id=$1",
                    id,
                )
            })
        }
        Some("restore") => payload_uuid(&operation.payload, "database_id").map(|id| {
            (
                "update control.odoo_databases set state='failed' where id=$1",
                id,
            )
        }),
        Some("duplicate") => payload_uuid(&operation.payload, "target_database_id").map(|id| {
            (
                "update control.odoo_databases set state='failed' where id=$1",
                id,
            )
        }),
        _ => Err(IntegrationError::ContractDrift),
    };
    if let Ok((query, id)) = result
        && let Err(error) = sqlx::query(query).bind(id).execute(store.pool()).await
    {
        tracing::error!(operation=%operation.id,error=%error,"could not mark lifecycle resource failed");
    }
}

fn payload_uuid(payload: &Value, key: &str) -> Result<Uuid, IntegrationError> {
    payload
        .get(key)
        .and_then(Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok())
        .ok_or(IntegrationError::ContractDrift)
}

async fn seed_membership_targets(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    workshop: Uuid,
    user: Uuid,
    epoch: i32,
) -> Result<(), IntegrationError> {
    sqlx::query("insert into control.membership_targets(workshop_id,user_id,target,desired_epoch) select $1,$2,target,$3 from unnest(array['rauthy','odoo','paperless']) target on conflict(workshop_id,user_id,target) do update set desired_epoch=excluded.desired_epoch,state='pending',safe_error_class=null")
        .bind(workshop).bind(user).bind(epoch).execute(&mut **tx).await.map_err(|_| IntegrationError::Unavailable)?;
    Ok(())
}

async fn deliver_mail(store: &Store, operation: &LeasedOperation) -> Result<(), IntegrationError> {
    let outbox = operation
        .payload
        .get("outbox_id")
        .and_then(Value::as_str)
        .and_then(|v| Uuid::parse_str(v).ok())
        .ok_or(IntegrationError::ContractDrift)?;
    let row=sqlx::query_as::<_,(String,String,Value)>("update control.outbox set state='sending',attempts=attempts+1 where id=$1 and state in('queued','deferred') returning recipient,template,payload").bind(outbox).fetch_optional(store.pool()).await.map_err(|_|IntegrationError::Unavailable)?.ok_or(IntegrationError::NotFound)?;
    let client = http_client(&env("CONTROL_MAIL_WEBHOOK_TOKEN")?, Duration::from_secs(30))?;
    let response = client
        .post(env("CONTROL_MAIL_WEBHOOK_URL")?)
        .json(&json!({"to":row.0,"template":row.1,"data":row.2}))
        .send()
        .await
        .map_err(|error| {
            if error.is_timeout() {
                IntegrationError::UnknownOutcome
            } else {
                IntegrationError::Unavailable
            }
        })?;
    if !response.status().is_success() {
        sqlx::query("update control.outbox set state='deferred',next_attempt_at=now()+interval '1 minute' where id=$1").bind(outbox).execute(store.pool()).await.ok();
        return Err(super_classify(response.status()));
    }
    sqlx::query("update control.outbox set state='sent',sent_at=now() where id=$1")
        .bind(outbox)
        .execute(store.pool())
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
    Ok(())
}

fn http_client(token: &str, timeout: Duration) -> Result<reqwest::Client, IntegrationError> {
    let mut value = reqwest::header::HeaderValue::from_str(&format!("Bearer {token}"))
        .map_err(|_| IntegrationError::ContractDrift)?;
    value.set_sensitive(true);
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(reqwest::header::AUTHORIZATION, value);
    reqwest::Client::builder()
        .default_headers(headers)
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| IntegrationError::ContractDrift)
}
fn super_classify(status: reqwest::StatusCode) -> IntegrationError {
    match status.as_u16() {
        400 | 409 | 422 => IntegrationError::Rejected,
        401 | 403 => IntegrationError::Unauthorized,
        404 => IntegrationError::NotFound,
        429 => IntegrationError::RateLimited {
            retry_after_seconds: None,
        },
        500..=599 => IntegrationError::Unavailable,
        _ => IntegrationError::ContractDrift,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn secret_names_cannot_escape_environment_namespace() {
        assert_eq!(
            "CONTROL_SECRET__TENANTS_DEMO_ODOO",
            format!(
                "CONTROL_SECRET__{}",
                "tenants/demo/odoo"
                    .chars()
                    .map(|c| if c.is_ascii_alphanumeric() {
                        c.to_ascii_uppercase()
                    } else {
                        '_'
                    })
                    .collect::<String>()
            )
        );
    }
    #[test]
    fn pdf_page_estimate_is_bounded_below() {
        assert_eq!(estimated_pages(b"not a pdf", "application/pdf"), 1);
    }
}
