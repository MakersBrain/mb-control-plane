use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

use crate::domain::IntegrationError;
use crate::outbound_http::TraceRequestBuilderExt as _;
use crate::persistence::{LeasedOperation, Store, TenantStore};
use crate::privacy_crypto;
use crate::worker_config::PrivacyDriverConfig;

type ExportMembership = (
    Uuid,
    String,
    String,
    String,
    OffsetDateTime,
    Option<OffsetDateTime>,
);

const MAX_EXPORT_WORKSHOPS: usize = 50;
const MAX_ERASURE_WORKSHOPS: usize = 500;
const MAX_EXPORT_CLEANUP_BATCH: i64 = 100;
const RETENTION_BATCH_SIZE: i32 = 200;

struct ExportCleanupLease<'a> {
    owner: &'a str,
    token: Uuid,
    fence: i64,
}

type ExportUser = (
    String,
    Option<String>,
    String,
    OffsetDateTime,
    Option<OffsetDateTime>,
);
type ExportIdentity = (String, String, OffsetDateTime, Option<OffsetDateTime>);
type ExportRequestHistory = (Uuid, String, String, OffsetDateTime, Option<OffsetDateTime>);
type ExportProcessorTask = (String, String, String, Option<String>);

struct PrivacyExportSnapshot {
    user: ExportUser,
    identity: Option<ExportIdentity>,
    request_history: Vec<ExportRequestHistory>,
    processor_tasks: Vec<ExportProcessorTask>,
    workshop_ids: Vec<Uuid>,
}

struct DataSubjectExportRequest<'a> {
    operation: &'a LeasedOperation,
    id: Uuid,
    subject_user_id: Uuid,
    request_type: &'a str,
    scope: &'a Value,
}

fn export_timestamp(value: OffsetDateTime) -> Result<String, IntegrationError> {
    value
        .format(&Rfc3339)
        .map_err(|_| IntegrationError::ContractDrift)
}

#[tracing::instrument(name = "worker.privacy.export_cleanup", skip_all)]
pub(crate) async fn cleanup_export_artifacts(
    store: &Store,
    lease_owner: &str,
) -> Result<u64, IntegrationError> {
    let Some((token, fence)) =
        sqlx::query_as::<_, (Uuid, i64)>("select * from control.claim_privacy_export_cleanup($1)")
            .bind(lease_owner)
            .fetch_optional(store.pool())
            .await
            .map_err(|_| IntegrationError::Unavailable)?
    else {
        tracing::debug!("privacy export cleanup lease is held by another replica");
        return Ok(0);
    };
    let lease = ExportCleanupLease {
        owner: lease_owner,
        token,
        fence,
    };
    let cleanup = cleanup_export_artifacts_with_lease(store, &lease).await;
    let release = sqlx::query_scalar::<_, bool>(
        "select control.release_privacy_export_cleanup($1,$2,$3) is true",
    )
    .bind(lease.owner)
    .bind(lease.token)
    .bind(lease.fence)
    .fetch_one(store.pool())
    .await;
    match (cleanup, release) {
        (Err(error), Ok(_)) => Err(error),
        (Err(error), Err(_)) => {
            tracing::warn!("privacy export cleanup failed and its lease could not be released");
            Err(error)
        }
        (Ok(_), Err(_)) => {
            tracing::warn!("privacy export cleanup lease release failed");
            Err(IntegrationError::Unavailable)
        }
        (Ok(deleted), Ok(false)) => {
            tracing::warn!("privacy export cleanup lease was not current at release");
            Ok(deleted)
        }
        (Ok(deleted), Ok(true)) => Ok(deleted),
    }
}

async fn cleanup_export_artifacts_with_lease(
    store: &Store,
    lease: &ExportCleanupLease<'_>,
) -> Result<u64, IntegrationError> {
    renew_export_cleanup_lease(store, lease).await?;
    sqlx::query_scalar::<_, i64>("select control.purge_expired_data_subject_exports()")
        .fetch_one(store.pool())
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
    let artifacts = sqlx::query_as::<_, (Uuid, String)>(
        "select id,storage_ref from control.data_subject_exports
         where state in ('consumed','expired','revoked')
           and storage_ref like 'file:%.aead' order by id limit $1",
    )
    .bind(MAX_EXPORT_CLEANUP_BATCH)
    .fetch_all(store.pool())
    .await
    .map_err(|_| IntegrationError::Unavailable)?;
    let mut deleted = 0_u64;
    for (export_id, storage_ref) in artifacts {
        renew_export_cleanup_lease(store, lease).await?;
        privacy_crypto::delete_export_artifact(export_id, &storage_ref)?;
        let changed = sqlx::query_scalar::<_, bool>(
            "select control.mark_privacy_export_artifact_purged($1,$2,$3,$4,$5) is true",
        )
        .bind(export_id)
        .bind(&storage_ref)
        .bind(lease.owner)
        .bind(lease.token)
        .bind(lease.fence)
        .fetch_one(store.pool())
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
        if !changed {
            return Err(IntegrationError::Unavailable);
        }
        deleted = deleted.saturating_add(1);
    }
    Ok(deleted)
}

async fn renew_export_cleanup_lease(
    store: &Store,
    lease: &ExportCleanupLease<'_>,
) -> Result<(), IntegrationError> {
    let renewed = sqlx::query_scalar::<_, bool>(
        "select control.renew_privacy_export_cleanup($1,$2,$3) is true",
    )
    .bind(lease.owner)
    .bind(lease.token)
    .bind(lease.fence)
    .fetch_one(store.pool())
    .await
    .map_err(|_| IntegrationError::Unavailable)?;
    if !renewed {
        tracing::warn!("privacy export cleanup lease was lost");
        return Err(IntegrationError::Unavailable);
    }
    Ok(())
}

async fn processor_exports(
    request_id: Uuid,
    workshop_ids: &[Uuid],
    driver: &PrivacyDriverConfig,
) -> Result<Vec<Value>, IntegrationError> {
    let mut result = Vec::new();
    let mut remaining = privacy_crypto::MAX_EXPORT_BYTES - 1024 * 1024;
    for workshop_id in workshop_ids {
        let url = driver
            .url()
            .join(&format!("/v1/privacy/{workshop_id}/export"))
            .map_err(|_| IntegrationError::ContractDrift)?;
        if url.origin() != driver.url().origin() {
            return Err(IntegrationError::ContractDrift);
        }
        let response = driver
            .client()
            .post(url)
            .header(
                reqwest::header::AUTHORIZATION,
                driver.authorization().clone(),
            )
            .json(&json!({"request_id":request_id}))
            .with_current_trace_context()
            .send()
            .await
            .map_err(|_| IntegrationError::Unavailable)?;
        let status = response.status();
        let body = crate::integrations::bounded_body(response, remaining).await?;
        if !status.is_success() {
            return Err(crate::integrations::classify_status(status));
        }
        result.push(serde_json::from_slice(&body).map_err(|_| IntegrationError::ContractDrift)?);
        remaining = remaining
            .checked_sub(body.len())
            .ok_or(IntegrationError::TooLarge)?;
    }
    Ok(result)
}

fn requested_workshops(scope: &Value) -> Result<Vec<Uuid>, IntegrationError> {
    let values = scope
        .get("workshop_ids")
        .and_then(Value::as_array)
        .ok_or(IntegrationError::ContractDrift)?;
    if values.len() > MAX_EXPORT_WORKSHOPS {
        return Err(IntegrationError::TooLarge);
    }
    let workshops = values
        .iter()
        .map(|value| {
            value
                .as_str()
                .and_then(|value| Uuid::parse_str(value).ok())
                .ok_or(IntegrationError::ContractDrift)
        })
        .collect::<Result<Vec<_>, _>>()?;
    if workshops
        .iter()
        .copied()
        .collect::<std::collections::HashSet<_>>()
        .len()
        != workshops.len()
    {
        return Err(IntegrationError::ContractDrift);
    }
    Ok(workshops)
}

async fn read_privacy_subject_workshops(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    operation: &LeasedOperation,
    request_id: Uuid,
    limit: usize,
) -> Result<Vec<Uuid>, IntegrationError> {
    sqlx::query_scalar::<_, Uuid>(
        "select workshop_id
           from control.read_privacy_subject_workshops($1,$2,$3,$4,$5)",
    )
    .bind(request_id)
    .bind(operation.id)
    .bind(operation.attempt)
    .bind(&operation.leased_by)
    .bind(i32::try_from(limit).map_err(|_| IntegrationError::TooLarge)?)
    .fetch_all(&mut **tx)
    .await
    .map_err(|_| IntegrationError::Unavailable)
}

async fn privacy_export_snapshot(
    store: &Store,
    operation: &LeasedOperation,
    request_id: Uuid,
    subject_user_id: Uuid,
    scope: &Value,
) -> Result<PrivacyExportSnapshot, IntegrationError> {
    let mut tx = store
        .begin()
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
    let user = sqlx::query_as::<_, ExportUser>(
        "select email,display_name,locale,created_at,disabled_at from control.users where id=$1",
    )
    .bind(subject_user_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|_| IntegrationError::Unavailable)?;
    let identity = sqlx::query_as::<_, ExportIdentity>(
        "select issuer,subject,linked_at,disabled_at from control.external_identities
         where user_id=$1 order by linked_at,id limit 1",
    )
    .bind(subject_user_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| IntegrationError::Unavailable)?;
    let request_history = sqlx::query_as::<_, ExportRequestHistory>(
        "select id,request_type,status,requested_at,completed_at
         from control.data_subject_requests where subject_user_id=$1 order by requested_at,id",
    )
    .bind(subject_user_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(|_| IntegrationError::Unavailable)?;
    let processor_tasks = sqlx::query_as::<_, ExportProcessorTask>(
        "select processor_key,action,state,acknowledgement_ref
         from control.data_subject_processor_tasks where data_subject_request_id=$1
         order by processor_key,action",
    )
    .bind(request_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(|_| IntegrationError::Unavailable)?;
    let mut workshop_ids = requested_workshops(scope)?;
    if workshop_ids.is_empty() {
        workshop_ids = read_privacy_subject_workshops(
            &mut tx,
            operation,
            request_id,
            MAX_EXPORT_WORKSHOPS + 1,
        )
        .await?;
        if workshop_ids.len() > MAX_EXPORT_WORKSHOPS {
            return Err(IntegrationError::TooLarge);
        }
    }
    tx.commit()
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
    Ok(PrivacyExportSnapshot {
        user,
        identity,
        request_history,
        processor_tasks,
        workshop_ids,
    })
}

async fn tenant_export_memberships(
    tenant_store: &TenantStore,
    subject_user_id: Uuid,
    workshop_ids: &[Uuid],
) -> Result<Vec<ExportMembership>, IntegrationError> {
    let mut memberships = Vec::with_capacity(workshop_ids.len());
    for workshop_id in workshop_ids {
        let mut tx = tenant_store
            .begin(*workshop_id)
            .await
            .map_err(|_| IntegrationError::Unavailable)?;
        let membership = sqlx::query_as::<_, ExportMembership>(
            "select m.workshop_id,w.display_name,m.role,m.status,m.created_at,m.revoked_at
             from control.memberships m join control.workshops w on w.id=m.workshop_id
             where m.workshop_id=$1 and m.user_id=$2",
        )
        .bind(workshop_id)
        .bind(subject_user_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| IntegrationError::Unavailable)?
        .ok_or(IntegrationError::NotFound)?;
        tx.commit()
            .await
            .map_err(|_| IntegrationError::Unavailable)?;
        memberships.push(membership);
    }
    Ok(memberships)
}

async fn prepare_data_subject_export(
    store: &Store,
    tenant_store: &TenantStore,
    request: DataSubjectExportRequest<'_>,
    driver: &PrivacyDriverConfig,
) -> Result<(), IntegrationError> {
    if let Some(state) = sqlx::query_scalar::<_, String>(
        "select state from control.data_subject_exports where data_subject_request_id=$1",
    )
    .bind(request.id)
    .fetch_optional(store.pool())
    .await
    .map_err(|_| IntegrationError::Unavailable)?
    {
        return if matches!(state.as_str(), "ready" | "consumed") {
            Ok(())
        } else {
            Err(IntegrationError::Rejected)
        };
    }

    let snapshot = privacy_export_snapshot(
        store,
        request.operation,
        request.id,
        request.subject_user_id,
        request.scope,
    )
    .await?;
    let memberships = tenant_export_memberships(
        tenant_store,
        request.subject_user_id,
        &snapshot.workshop_ids,
    )
    .await?;
    let processor_exports = processor_exports(request.id, &snapshot.workshop_ids, driver).await?;

    let payload = json!({
        "format":"mb-gdpr-export-v1",
        "generated_at":export_timestamp(OffsetDateTime::now_utc())?,
        "request":{"id":request.id,"type":request.request_type,"scope":request.scope},
        "subject":{
            "id":request.subject_user_id,"email":snapshot.user.0,"display_name":snapshot.user.1,"locale":snapshot.user.2,
            "created_at":export_timestamp(snapshot.user.3)?,
            "disabled_at":snapshot.user.4.map(export_timestamp).transpose()?
        },
        "external_identity":snapshot.identity.map(|row| -> Result<Value,IntegrationError> { Ok(json!({
            "issuer":row.0,"subject":row.1,"linked_at":export_timestamp(row.2)?,
            "disabled_at":row.3.map(export_timestamp).transpose()?
        }))}).transpose()?,
        "memberships":memberships.into_iter().map(|row| -> Result<Value,IntegrationError> { Ok(json!({
            "workshop_id":row.0,"workshop_name":row.1,"role":row.2,"status":row.3,
            "created_at":export_timestamp(row.4)?,"revoked_at":row.5.map(export_timestamp).transpose()?
        }))}).collect::<Result<Vec<_>,_>>()?,
        "rights_request_history":snapshot.request_history.into_iter().map(|row| -> Result<Value,IntegrationError> { Ok(json!({
            "id":row.0,"type":row.1,"status":row.2,"requested_at":export_timestamp(row.3)?,
            "completed_at":row.4.map(export_timestamp).transpose()?
        }))}).collect::<Result<Vec<_>,_>>()?,
        "processor_manifest":snapshot.processor_tasks.into_iter().map(|row| json!({
            "processor":row.0,"action":row.1,"state":row.2,"evidence_ref":row.3
        })).collect::<Vec<_>>(),
        "processor_exports":processor_exports
    });
    let plaintext = serde_json::to_vec(&payload).map_err(|_| IntegrationError::ContractDrift)?;
    let export_id = Uuid::new_v4();
    let digest = format!("sha256:{:x}", Sha256::digest(&plaintext));
    let (nonce, ciphertext) = privacy_crypto::encrypt_export(export_id, &plaintext)?;
    let storage_ref = privacy_crypto::store_export_artifact(export_id, &ciphertext)?;
    let inserted = sqlx::query(
        "insert into control.data_subject_exports(
             id,data_subject_request_id,storage_ref,encryption_key_ref,manifest_digest,state,
             ready_at,expires_at,nonce,ciphertext,plaintext_size,filename
         ) values($1,$2,$3,$4,$5,'ready',now(),now()+interval '7 days',$6,null,$7,$8)",
    )
    .bind(export_id)
    .bind(request.id)
    .bind(&storage_ref)
    .bind(privacy_crypto::export_key_id()?)
    .bind(digest)
    .bind(nonce)
    .bind(i64::try_from(plaintext.len()).map_err(|_| IntegrationError::TooLarge)?)
    .bind(format!("privacy-export-{export_id}.json"))
    .execute(store.pool())
    .await;
    if inserted.is_err() {
        let _ = privacy_crypto::delete_export_artifact(export_id, &storage_ref);
        return Err(IntegrationError::Unavailable);
    }
    Ok(())
}

async fn ensure_erasure_tombstone(
    store: &Store,
    request_id: Uuid,
    subject_key: Uuid,
    subject_user_id: Uuid,
    rauthy_subject: &str,
    workshop_id: Option<Uuid>,
    required_locations: &[String],
) -> Result<Uuid, IntegrationError> {
    let mut tx = store
        .begin()
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
    let candidate = Uuid::new_v4();
    let inserted = sqlx::query_scalar::<_, Uuid>(
        "insert into control.erasure_tombstones(
             id,subject_key,subject_user_id,workshop_id,source_request_id,required_locations
         ) values($1,$2,$3,$4,$5,$6)
         on conflict do nothing returning id",
    )
    .bind(candidate)
    .bind(subject_key)
    .bind(subject_user_id)
    .bind(workshop_id)
    .bind(request_id)
    .bind(required_locations)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| IntegrationError::Unavailable)?;
    let tombstone = if let Some(id) = inserted {
        id
    } else {
        sqlx::query_scalar::<_, Uuid>(
            "select id from control.erasure_tombstones
             where source_request_id=$1 and workshop_id is not distinct from $2",
        )
        .bind(request_id)
        .bind(workshop_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| IntegrationError::Unavailable)?
    };
    let lookup_exists = sqlx::query_scalar::<_, bool>(
        "select exists(select 1 from control.erasure_subject_lookups where tombstone_id=$1)",
    )
    .bind(tombstone)
    .fetch_one(&mut *tx)
    .await
    .map_err(|_| IntegrationError::Unavailable)?;
    if !lookup_exists {
        let plaintext = serde_json::to_vec(&json!({
            "control_user_id":subject_user_id,
            "rauthy_subject":rauthy_subject
        }))
        .map_err(|_| IntegrationError::ContractDrift)?;
        let (nonce, ciphertext) = privacy_crypto::encrypt(tombstone, &plaintext)?;
        sqlx::query(
            "insert into control.erasure_subject_lookups(tombstone_id,key_id,nonce,ciphertext)
             values($1,$2,$3,$4)",
        )
        .bind(tombstone)
        .bind(privacy_crypto::lookup_key_id()?)
        .bind(nonce)
        .bind(ciphertext)
        .execute(&mut *tx)
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
    }
    tx.commit()
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
    Ok(tombstone)
}

#[tracing::instrument(
    name = "worker.privacy.retention",
    skip_all,
    fields(operation.id = %operation.id, retention.phase = tracing::field::Empty)
)]
pub(crate) async fn retention(
    store: &Store,
    operation: &LeasedOperation,
) -> Result<(), IntegrationError> {
    let run_id = operation
        .payload
        .get("retention_run_id")
        .and_then(Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok())
        .ok_or(IntegrationError::ContractDrift)?;
    loop {
        let (outcome, phase, considered, affected, held) =
            sqlx::query_as::<_, (String, String, i32, i32, i32)>(
                "select outcome,phase,considered,affected,held
                   from control.run_privacy_retention_batch($1,$2,$3,$4,$5)",
            )
            .bind(run_id)
            .bind(operation.id)
            .bind(operation.attempt)
            .bind(&operation.leased_by)
            .bind(RETENTION_BATCH_SIZE)
            .fetch_one(store.pool())
            .await
            .map_err(|_| IntegrationError::Unavailable)?;
        let phase = match phase.as_str() {
            "invitations" => "invitations",
            "mail-delivery" => "mail_delivery",
            "operations" => "operations",
            "complete" => "complete",
            _ => return Err(IntegrationError::ContractDrift),
        };
        if !(0..=RETENTION_BATCH_SIZE).contains(&considered)
            || affected < 0
            || held < 0
            || affected.saturating_add(held) > considered
        {
            return Err(IntegrationError::ContractDrift);
        }
        tracing::Span::current().record("retention.phase", phase);
        tracing::debug!(
            retention.phase = phase,
            considered,
            affected,
            held,
            "privacy retention batch committed"
        );
        match outcome.as_str() {
            "more" if phase != "complete" => tokio::task::yield_now().await,
            "complete" if phase == "complete" => return Ok(()),
            "blocked" | "failed" if phase == "complete" => {
                return Err(IntegrationError::Rejected);
            }
            _ => return Err(IntegrationError::ContractDrift),
        }
    }
}

#[tracing::instrument(name = "worker.privacy.data_subject_request", skip_all, fields(operation.id = %operation.id))]
pub(crate) async fn data_subject_request(
    store: &Store,
    tenant_store: &TenantStore,
    operation: &LeasedOperation,
    driver: &PrivacyDriverConfig,
) -> Result<(), IntegrationError> {
    let request_id = operation
        .payload
        .get("request_id")
        .and_then(Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok())
        .ok_or(IntegrationError::ContractDrift)?;
    let target_user_id = operation
        .target_user_id
        .ok_or(IntegrationError::ContractDrift)?;
    let request=sqlx::query_as::<_,(String,String,Uuid,i64,Value)>("select request_type,status,subject_user_id,version,scope from control.data_subject_requests where id=$1 and operation_id=$2 and subject_user_id=$3")
        .bind(request_id).bind(operation.id).bind(target_user_id).fetch_optional(store.pool()).await.map_err(|_|IntegrationError::Unavailable)?.ok_or(IntegrationError::NotFound)?;
    if request.1 == "completed" {
        return Ok(());
    }
    if request.1 != "approved" && request.1 != "executing" {
        return Err(IntegrationError::Rejected);
    }
    verify_operation_lease(store, operation).await?;
    cleanup_export_artifacts(store, &operation.leased_by).await?;
    if request.1 == "approved" {
        transition_dsr(store, operation, request_id, "approved", "executing").await?;
    }
    match request.0.as_str() {
        "restriction" => {
            sqlx::query("insert into control.processing_holds(id,data_subject_request_id,subject_user_id) select $1,$2,$3 where not exists(select 1 from control.processing_holds where subject_user_id=$3 and workshop_id is null and active)")
                .bind(Uuid::new_v4()).bind(request_id).bind(request.2).execute(store.pool()).await.map_err(|_|IntegrationError::Unavailable)?;
            sqlx::query("update control.data_subject_processor_tasks set state='acknowledged',acknowledgement_ref='control:processing-hold',version=version+1 where data_subject_request_id=$1 and processor_key='control' and action='restrict' and state in ('pending','sent','failed')")
                .bind(request_id).execute(store.pool()).await.map_err(|_|IntegrationError::Unavailable)?;
        }
        "erasure" => {
            let (audit_subject, rauthy_subject) = sqlx::query_as::<_, (Uuid, String)>(
                "select u.audit_subject_id,i.subject from control.users u
                 join control.external_identities i on i.user_id=u.id
                 where u.id=$1 order by i.linked_at,i.id limit 1",
            )
            .bind(request.2)
            .fetch_one(store.pool())
            .await
            .map_err(|_| IntegrationError::Unavailable)?;
            ensure_erasure_tombstone(
                store,
                request_id,
                audit_subject,
                request.2,
                &rauthy_subject,
                None,
                &["control".to_owned(), "rauthy".to_owned()],
            )
            .await?;
            let mut workshops = request
                .4
                .get("workshop_ids")
                .and_then(Value::as_array)
                .ok_or(IntegrationError::ContractDrift)?
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .and_then(|value| Uuid::parse_str(value).ok())
                        .ok_or(IntegrationError::ContractDrift)
                })
                .collect::<Result<Vec<_>, _>>()?;
            if workshops.is_empty() {
                let mut membership_tx = store
                    .begin()
                    .await
                    .map_err(|_| IntegrationError::Unavailable)?;
                workshops = read_privacy_subject_workshops(
                    &mut membership_tx,
                    operation,
                    request_id,
                    MAX_ERASURE_WORKSHOPS + 1,
                )
                .await?;
                membership_tx
                    .commit()
                    .await
                    .map_err(|_| IntegrationError::Unavailable)?;
                if workshops.len() > MAX_ERASURE_WORKSHOPS {
                    return Err(IntegrationError::TooLarge);
                }
            }
            for workshop in workshops {
                let documents=sqlx::query_scalar::<_,bool>("select exists(select 1 from control.workshop_modules where workshop_id=$1 and module_key='documents' and state='enabled')")
                    .bind(workshop).fetch_one(store.pool()).await.map_err(|_|IntegrationError::Unavailable)?;
                let required = if documents {
                    vec![
                        "odoo".to_owned(),
                        "paperless".to_owned(),
                        "backups".to_owned(),
                    ]
                } else {
                    vec!["odoo".to_owned(), "backups".to_owned()]
                };
                ensure_erasure_tombstone(
                    store,
                    request_id,
                    audit_subject,
                    request.2,
                    &rauthy_subject,
                    Some(workshop),
                    &required,
                )
                .await?;
            }
        }
        "access" | "portability" | "rectification" | "objection" => {}
        _ => return Err(IntegrationError::ContractDrift),
    }
    if matches!(request.0.as_str(), "access" | "portability") {
        prepare_data_subject_export(
            store,
            tenant_store,
            DataSubjectExportRequest {
                operation,
                id: request_id,
                subject_user_id: request.2,
                request_type: &request.0,
                scope: &request.4,
            },
            driver,
        )
        .await?;
    }
    complete_dsr(
        store,
        operation,
        request_id,
        matches!(request.0.as_str(), "access" | "portability"),
    )
    .await
}

async fn transition_dsr(
    store: &Store,
    operation: &LeasedOperation,
    id: Uuid,
    from: &str,
    to: &str,
) -> Result<(), IntegrationError> {
    let mut tx = store
        .begin()
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
    lock_operation_lease(&mut tx, operation).await?;
    let changed=sqlx::query("update control.data_subject_requests set status=$3,version=version+1 where id=$1 and operation_id=$4 and status=$2")
        .bind(id).bind(from).bind(to).bind(operation.id).execute(&mut *tx).await.map_err(|_|IntegrationError::Unavailable)?.rows_affected();
    if changed != 1 {
        return Err(IntegrationError::UnknownOutcome);
    }
    tx.commit().await.map_err(|_| IntegrationError::Unavailable)
}

async fn complete_dsr(
    store: &Store,
    operation: &LeasedOperation,
    request_id: Uuid,
    acknowledge_export: bool,
) -> Result<(), IntegrationError> {
    let mut tx = store
        .begin()
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
    lock_operation_lease(&mut tx, operation).await?;
    if acknowledge_export {
        let evidence_ref = format!("control:subject-export:{request_id}");
        sqlx::query(
            "update control.data_subject_processor_tasks
             set state='acknowledged',acknowledgement_ref=$2,safe_error_class=null,
                 version=version+1
             where data_subject_request_id=$1 and action='export'
               and state in ('pending','sent','failed')",
        )
        .bind(request_id)
        .bind(evidence_ref)
        .execute(&mut *tx)
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
    }
    let outstanding = sqlx::query_scalar::<_, bool>(
        "select exists(select 1 from control.data_subject_processor_tasks
         where data_subject_request_id=$1
           and state not in ('acknowledged','not_applicable'))",
    )
    .bind(request_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|_| IntegrationError::Unavailable)?;
    if outstanding {
        return Err(IntegrationError::Unavailable);
    }
    let changed = sqlx::query(
        "update control.data_subject_requests
         set status='completed',completed_at=now(),version=version+1
         where id=$1 and operation_id=$2 and status='executing'",
    )
    .bind(request_id)
    .bind(operation.id)
    .execute(&mut *tx)
    .await
    .map_err(|_| IntegrationError::Unavailable)?
    .rows_affected();
    if changed != 1 {
        return Err(IntegrationError::UnknownOutcome);
    }
    tx.commit().await.map_err(|_| IntegrationError::Unavailable)
}

async fn lock_operation_lease(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    operation: &LeasedOperation,
) -> Result<(), IntegrationError> {
    sqlx::query_scalar::<_, Uuid>(
        "select id from control.operations
         where id=$1 and state='in_flight' and leased_by=$2 and attempt=$3
           and lease_expires_at>now()
         for update",
    )
    .bind(operation.id)
    .bind(&operation.leased_by)
    .bind(operation.attempt)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| IntegrationError::Unavailable)?
    .ok_or(IntegrationError::UnknownOutcome)?;
    Ok(())
}

async fn verify_operation_lease(
    store: &Store,
    operation: &LeasedOperation,
) -> Result<(), IntegrationError> {
    let mut tx = store
        .begin()
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
    lock_operation_lease(&mut tx, operation).await?;
    tx.commit().await.map_err(|_| IntegrationError::Unavailable)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn export_scope_is_unique_and_bounded() {
        let first = Uuid::new_v4();
        let second = Uuid::new_v4();
        let parsed = requested_workshops(&json!({
            "workshop_ids": [first.to_string(), second.to_string()]
        }))
        .unwrap();
        assert_eq!(parsed, vec![first, second]);
        assert_eq!(
            requested_workshops(&json!({
                "workshop_ids": [first.to_string(), first.to_string()]
            })),
            Err(IntegrationError::ContractDrift)
        );
        let oversized = (0..=MAX_EXPORT_WORKSHOPS)
            .map(|_| Value::String(Uuid::new_v4().to_string()))
            .collect::<Vec<_>>();
        assert_eq!(
            requested_workshops(&json!({"workshop_ids": oversized})),
            Err(IntegrationError::TooLarge)
        );
    }

    #[test]
    fn export_cleanup_is_database_leased_and_fenced() {
        let source = include_str!("privacy.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        let cleanup = production
            .split("pub(crate) async fn cleanup_export_artifacts(")
            .nth(1)
            .unwrap()
            .split("async fn processor_exports(")
            .next()
            .unwrap();
        let claim = cleanup.find("claim_privacy_export_cleanup").unwrap();
        let purge = cleanup.find("purge_expired_data_subject_exports").unwrap();
        let deletion = cleanup.find("delete_export_artifact").unwrap();
        let acknowledgement = cleanup.find("mark_privacy_export_artifact_purged").unwrap();
        let release = cleanup.find("release_privacy_export_cleanup").unwrap();
        assert!(claim < purge && purge < deletion && deletion < acknowledgement);
        assert!(claim < release);
        assert!(cleanup.contains("renew_privacy_export_cleanup"));
        assert!(!cleanup.contains("set storage_ref=concat"));

        let migration = include_str!("../../migrations/0017_privacy_export_cleanup_lease.sql");
        assert!(migration.contains("fence_token = cleanup.fence_token + 1"));
        assert!(migration.contains("cleanup.lease_expires_at > now()"));
        assert!(
            migration.contains("grant execute on function control.claim_privacy_export_cleanup")
        );
        assert!(
            migration
                .contains("grant execute on function control.mark_privacy_export_artifact_purged")
        );
    }

    #[test]
    fn retention_uses_only_the_bounded_fenced_database_capability() {
        let source = include_str!("privacy.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        let retention = production
            .split("pub(crate) async fn retention(")
            .nth(1)
            .unwrap()
            .split("pub(crate) async fn data_subject_request(")
            .next()
            .unwrap();
        assert!(retention.contains("run_privacy_retention_batch"));
        assert!(retention.contains("RETENTION_BATCH_SIZE"));
        for forbidden in [
            "delete from control.outbox",
            "update control.invitations",
            "update control.operations",
            "select count(*) from control.invitations",
            "legal_hold_applies",
        ] {
            assert!(
                !retention.contains(forbidden),
                "retention bypassed its database capability with {forbidden}"
            );
        }

        let migration = include_str!("../../migrations/0020_privacy_retention_batches.sql");
        assert!(migration.contains("p_batch_limit>200"));
        assert!(migration.contains("x.lease_expires_at>clock_timestamp()"));
        assert!(migration.contains("op.lease_expires_at<=clock_timestamp()"));
        assert!(migration.contains("for update"));
        assert!(migration.contains("control.legal_hold_applies("));
        assert!(migration.contains(
            "lock table control.invitations,control.outbox,control.operations in share mode"
        ));
        assert!(migration.contains("cutoff_at=clock_timestamp()"));
        assert!(migration.contains("invitation_high_water"));
        assert!(migration.contains("maintain_retention_sequence"));
        assert!(
            migration
                .contains("revoke all on table control.retention_runs from control_privacy_worker")
        );
    }

    #[tokio::test]
    #[ignore = "requires a disposable CONTROL_TEST_DATABASE_URL"]
    async fn retention_batches_resume_fence_stale_owners_and_preserve_held_rows() {
        let database_url =
            std::env::var("CONTROL_TEST_DATABASE_URL").expect("CONTROL_TEST_DATABASE_URL");
        let store = Store::connect(&database_url).await.unwrap();
        store.migrate().await.unwrap();

        let operator = Uuid::new_v4();
        sqlx::query("insert into control.users(id,email) values($1,$2)")
            .bind(operator)
            .bind(format!("retention-operator-{operator}@example.test"))
            .execute(store.pool())
            .await
            .unwrap();
        let held_workshop = Uuid::new_v4();
        let free_workshop = Uuid::new_v4();
        for (workshop, label) in [(held_workshop, "Held"), (free_workshop, "Free")] {
            sqlx::query(
                "insert into control.workshops(id,slug,display_name,time_zone)
                 values($1,$2,$3,'Europe/Paris')",
            )
            .bind(workshop)
            .bind(format!("retention-{}", workshop.simple()))
            .bind(label)
            .execute(store.pool())
            .await
            .unwrap();
        }
        let policy_version: i32 = sqlx::query_scalar(
            "select coalesce(max(version),0)+1 from control.retention_policy_versions",
        )
        .fetch_one(store.pool())
        .await
        .unwrap();
        sqlx::query(
            "insert into control.retention_policy_versions(
               version,status,policy,policy_digest,approval_ref,approved_by,approved_at
             ) values($1,'approved',$2,$3,'retention-test-approval',$4,now())",
        )
        .bind(policy_version)
        .bind(json!({"datasets":{
            "invitations":{"duration_days":36500},
            "mail-delivery":{"duration_days":36500},
            "operations":{"duration_days":36500}
        }}))
        .bind(format!("sha256:{}", "d".repeat(64)))
        .bind(operator)
        .execute(store.pool())
        .await
        .unwrap();

        let held_invitation = Uuid::new_v4();
        let free_invitation = Uuid::new_v4();
        for (invitation, workshop, local) in [
            (held_invitation, held_workshop, "held"),
            (free_invitation, free_workshop, "free"),
        ] {
            sqlx::query(
                "insert into control.invitations(
                   id,workshop_id,email,role,invited_by,idempotency_key,
                   created_at,expires_at
                 ) values($1,$2,$3,'viewer',$4,$5,
                          now()-interval '40002 days',now()-interval '40001 days')",
            )
            .bind(invitation)
            .bind(workshop)
            .bind(format!("retention-{local}-{invitation}@example.test"))
            .bind(operator)
            .bind(format!("retention-test:{invitation}"))
            .execute(store.pool())
            .await
            .unwrap();
        }
        let held_operation = Uuid::new_v4();
        let free_operation = Uuid::new_v4();
        for (candidate, workshop, marker) in [
            (held_operation, held_workshop, "held-personal-marker"),
            (free_operation, free_workshop, "free-personal-marker"),
        ] {
            sqlx::query(
                "insert into control.operations(
                   id,kind,queue,workshop_id,payload,correlation_id,idempotency_key,
                   state,created_at,finished_at
                 ) values($1,'tenant.reconcile','tenant-reconciliation',$2,$3,$4,$5,
                          'succeeded',now()-interval '40002 days',now()-interval '40001 days')",
            )
            .bind(candidate)
            .bind(workshop)
            .bind(json!({"personal_marker":marker}))
            .bind(Uuid::new_v4())
            .bind(format!("retention-candidate:{candidate}"))
            .execute(store.pool())
            .await
            .unwrap();
        }
        sqlx::query(
            "insert into control.legal_holds(
               id,scope,reason_code,approval_ref,imposed_by,expires_at
             ) values($1,$2,'retention_test','retention-test-hold',$3,now()+interval '1 day')",
        )
        .bind(Uuid::new_v4())
        .bind(json!({
            "datasets":["invitations","operations"],
            "workshop_ids":[held_workshop]
        }))
        .bind(operator)
        .execute(store.pool())
        .await
        .unwrap();

        let run_id = Uuid::new_v4();
        let operation_id = Uuid::new_v4();
        let lease_owner = format!("privacy-retention-test-{operation_id}");
        sqlx::query(
            "insert into control.operations(
               id,kind,queue,payload,correlation_id,idempotency_key,state,attempt,
               leased_by,lease_expires_at
             ) values($1,'privacy.retention','privacy-operations',$2,$3,$4,
                      'in_flight',1,$5,now()+interval '10 minutes')",
        )
        .bind(operation_id)
        .bind(json!({"retention_run_id":run_id}))
        .bind(Uuid::new_v4())
        .bind(format!("retention-run:{run_id}"))
        .bind(&lease_owner)
        .execute(store.pool())
        .await
        .unwrap();
        sqlx::query(
            "insert into control.retention_runs(id,policy_version,operation_id,dry_run)
             values($1,$2,$3,false)",
        )
        .bind(run_id)
        .bind(policy_version)
        .bind(operation_id)
        .execute(store.pool())
        .await
        .unwrap();

        let first = sqlx::query_as::<_, (String, String, i32, i32, i32)>(
            "select * from control.run_privacy_retention_batch($1,$2,1,$3,1)",
        )
        .bind(run_id)
        .bind(operation_id)
        .bind(&lease_owner)
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(first.0, "more");
        assert_eq!(first.2, 1);
        let durable_progress = sqlx::query_as::<_, (String, i64, i64, i64)>(
            "select retention_phase,invitation_cursor,invitation_high_water,invitation_candidates
             from control.retention_runs where id=$1",
        )
        .bind(run_id)
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(durable_progress.0, "invitations");
        assert!(durable_progress.1 > 0);
        assert!(durable_progress.1 <= durable_progress.2);
        assert_eq!(durable_progress.3, 1);

        // This row is deliberately backdated after the run snapshot. Its
        // monotonic identity exceeds the frozen high-water mark, so it must be
        // deferred instead of being skipped behind the cursor.
        let late_invitation = Uuid::new_v4();
        let late_email = format!("retention-late-{late_invitation}@example.test");
        let late_sequence: i64 = sqlx::query_scalar(
            "insert into control.invitations(
               id,workshop_id,email,role,invited_by,idempotency_key,created_at,expires_at
             ) values($1,$2,$3,'viewer',$4,$5,
                      now()-interval '40002 days',now()-interval '40001 days')
             returning retention_sequence",
        )
        .bind(late_invitation)
        .bind(free_workshop)
        .bind(&late_email)
        .bind(operator)
        .bind(format!("retention-test:{late_invitation}"))
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert!(late_sequence > durable_progress.2);

        let stale = sqlx::query("select * from control.run_privacy_retention_batch($1,$2,1,$3,1)")
            .bind(run_id)
            .bind(operation_id)
            .bind("privacy-retention-stale-owner")
            .fetch_one(store.pool())
            .await;
        assert!(stale.is_err());
        let after_stale: i64 = sqlx::query_scalar(
            "select invitation_candidates from control.retention_runs where id=$1",
        )
        .bind(run_id)
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(after_stale, 1);

        for _ in 0..8 {
            let step = sqlx::query_as::<_, (String, String, i32, i32, i32)>(
                "select * from control.run_privacy_retention_batch($1,$2,1,$3,1)",
            )
            .bind(run_id)
            .bind(operation_id)
            .bind(&lease_owner)
            .fetch_one(store.pool())
            .await
            .unwrap();
            if step.0 == "complete" {
                break;
            }
        }
        let (state, evidence) = sqlx::query_as::<_, (String, Value)>(
            "select state,evidence from control.retention_runs where id=$1",
        )
        .bind(run_id)
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(state, "completed");
        assert_eq!(evidence["candidates"]["invitations"], 2);
        assert_eq!(evidence["held"]["invitations"], 1);
        assert_eq!(evidence["anonymized_invitation_count"], 1);
        assert_eq!(evidence["candidates"]["operation_details"], 2);
        assert_eq!(evidence["held"]["operation_details"], 1);
        assert_eq!(evidence["redacted_operation_count"], 1);

        let held_email: String =
            sqlx::query_scalar("select email from control.invitations where id=$1")
                .bind(held_invitation)
                .fetch_one(store.pool())
                .await
                .unwrap();
        assert!(held_email.contains("retention-held"));
        let free_email: String =
            sqlx::query_scalar("select email from control.invitations where id=$1")
                .bind(free_invitation)
                .fetch_one(store.pool())
                .await
                .unwrap();
        assert_eq!(
            free_email,
            format!("retained-invitation-{free_invitation}@invalid")
        );
        let held_payload: Value =
            sqlx::query_scalar("select payload from control.operations where id=$1")
                .bind(held_operation)
                .fetch_one(store.pool())
                .await
                .unwrap();
        assert_eq!(held_payload["personal_marker"], "held-personal-marker");
        let free_payload: Value =
            sqlx::query_scalar("select payload from control.operations where id=$1")
                .bind(free_operation)
                .fetch_one(store.pool())
                .await
                .unwrap();
        assert_eq!(free_payload, json!({"redacted":true}));

        let replay = sqlx::query_as::<_, (String, String, i32, i32, i32)>(
            "select * from control.run_privacy_retention_batch($1,$2,1,$3,1)",
        )
        .bind(run_id)
        .bind(operation_id)
        .bind(&lease_owner)
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(replay.0, "complete");
        let replay_candidates: i64 = sqlx::query_scalar(
            "select invitation_candidates from control.retention_runs where id=$1",
        )
        .bind(run_id)
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(replay_candidates, 2);

        let deferred_email: String =
            sqlx::query_scalar("select email from control.invitations where id=$1")
                .bind(late_invitation)
                .fetch_one(store.pool())
                .await
                .unwrap();
        assert_eq!(deferred_email, late_email);

        // Held candidates are also intentionally behind this run's cursor.
        // Releasing the hold makes them eligible only for a new snapshot/run.
        sqlx::query(
            "update control.legal_holds set released_at=now(),released_by=$1,version=version+1,
             release_reason_code='retention_test_release' where approval_ref='retention-test-hold'",
        )
        .bind(operator)
        .execute(store.pool())
        .await
        .unwrap();
        let second_run = Uuid::new_v4();
        let second_operation = Uuid::new_v4();
        let second_owner = format!("privacy-retention-test-{second_operation}");
        sqlx::query(
            "insert into control.operations(
               id,kind,queue,payload,correlation_id,idempotency_key,state,attempt,leased_by,lease_expires_at
             ) values($1,'privacy.retention','privacy-operations',$2,$3,$4,'in_flight',1,$5,now()+interval '10 minutes')",
        )
        .bind(second_operation)
        .bind(json!({"retention_run_id":second_run}))
        .bind(Uuid::new_v4())
        .bind(format!("retention-run:{second_run}"))
        .bind(&second_owner)
        .execute(store.pool())
        .await
        .unwrap();
        sqlx::query("insert into control.retention_runs(id,policy_version,operation_id,dry_run) values($1,$2,$3,false)")
            .bind(second_run).bind(policy_version).bind(second_operation)
            .execute(store.pool()).await.unwrap();
        for _ in 0..6 {
            let step = sqlx::query_as::<_, (String, String, i32, i32, i32)>(
                "select * from control.run_privacy_retention_batch($1,$2,1,$3,200)",
            )
            .bind(second_run)
            .bind(second_operation)
            .bind(&second_owner)
            .fetch_one(store.pool())
            .await
            .unwrap();
            if step.0 == "complete" {
                break;
            }
        }
        let second_state: String =
            sqlx::query_scalar("select state from control.retention_runs where id=$1")
                .bind(second_run)
                .fetch_one(store.pool())
                .await
                .unwrap();
        assert_eq!(second_state, "completed");
        let (released_email, included_email) = sqlx::query_as::<_, (String, String)>(
            "select (select email from control.invitations where id=$1),
                    (select email from control.invitations where id=$2)",
        )
        .bind(held_invitation)
        .bind(late_invitation)
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(
            released_email,
            format!("retained-invitation-{held_invitation}@invalid")
        );
        assert_eq!(
            included_email,
            format!("retained-invitation-{late_invitation}@invalid")
        );
        let released_payload: Value =
            sqlx::query_scalar("select payload from control.operations where id=$1")
                .bind(held_operation)
                .fetch_one(store.pool())
                .await
                .unwrap();
        assert_eq!(released_payload, json!({"redacted":true}));
    }

    #[tokio::test]
    #[ignore = "requires a disposable CONTROL_TEST_DATABASE_URL"]
    async fn export_cleanup_lease_serializes_replicas_and_fences_takeover() {
        let database_url =
            std::env::var("CONTROL_TEST_DATABASE_URL").expect("CONTROL_TEST_DATABASE_URL");
        let store = Store::connect(&database_url).await.unwrap();
        store.migrate().await.unwrap();
        sqlx::query(
            "update control.privacy_export_cleanup_lease
             set lease_owner=null,lease_token=null,lease_expires_at=null",
        )
        .execute(store.pool())
        .await
        .unwrap();

        let first_owner = format!("privacy-cleanup-first-{}", Uuid::new_v4());
        let second_owner = format!("privacy-cleanup-second-{}", Uuid::new_v4());
        let first = sqlx::query_as::<_, (Uuid, i64)>(
            "select * from control.claim_privacy_export_cleanup($1)",
        )
        .bind(&first_owner)
        .fetch_one(store.pool())
        .await
        .unwrap();
        let excluded = sqlx::query_as::<_, (Uuid, i64)>(
            "select * from control.claim_privacy_export_cleanup($1)",
        )
        .bind(&second_owner)
        .fetch_optional(store.pool())
        .await
        .unwrap();
        assert!(excluded.is_none());

        sqlx::query(
            "update control.privacy_export_cleanup_lease set lease_expires_at=now()-interval '1 second'",
        )
        .execute(store.pool())
        .await
        .unwrap();
        let second = sqlx::query_as::<_, (Uuid, i64)>(
            "select * from control.claim_privacy_export_cleanup($1)",
        )
        .bind(&second_owner)
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(second.1, first.1 + 1);

        let stale_renewal: bool =
            sqlx::query_scalar("select control.renew_privacy_export_cleanup($1,$2,$3) is true")
                .bind(&first_owner)
                .bind(first.0)
                .bind(first.1)
                .fetch_one(store.pool())
                .await
                .unwrap();
        assert!(!stale_renewal);
        let subject = Uuid::new_v4();
        let request = Uuid::new_v4();
        let export = Uuid::new_v4();
        let storage_ref = format!("file:{export}.aead");
        sqlx::query("insert into control.users(id,email) values($1,$2)")
            .bind(subject)
            .bind(format!("privacy-cleanup-{subject}@example.test"))
            .execute(store.pool())
            .await
            .unwrap();
        sqlx::query(
            "insert into control.data_subject_requests(id,subject_user_id,request_type)
             values($1,$2,'access')",
        )
        .bind(request)
        .bind(subject)
        .execute(store.pool())
        .await
        .unwrap();
        sqlx::query(
            "insert into control.data_subject_exports(
               id,data_subject_request_id,storage_ref,encryption_key_ref,
               manifest_digest,state,expires_at
             ) values($1,$2,$3,'test-key',$4,'expired',now()+interval '1 hour')",
        )
        .bind(export)
        .bind(request)
        .bind(&storage_ref)
        .bind(format!("sha256:{}", "a".repeat(64)))
        .execute(store.pool())
        .await
        .unwrap();
        let stale_mark: bool = sqlx::query_scalar(
            "select control.mark_privacy_export_artifact_purged($1,$2,$3,$4,$5) is true",
        )
        .bind(export)
        .bind(&storage_ref)
        .bind(&first_owner)
        .bind(first.0)
        .bind(first.1)
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert!(!stale_mark);
        let current_mark: bool = sqlx::query_scalar(
            "select control.mark_privacy_export_artifact_purged($1,$2,$3,$4,$5) is true",
        )
        .bind(export)
        .bind(&storage_ref)
        .bind(&second_owner)
        .bind(second.0)
        .bind(second.1)
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert!(current_mark);
        let recorded_ref: String =
            sqlx::query_scalar("select storage_ref from control.data_subject_exports where id=$1")
                .bind(export)
                .fetch_one(store.pool())
                .await
                .unwrap();
        assert_eq!(recorded_ref, format!("purged:{storage_ref}"));
        let current_release: bool =
            sqlx::query_scalar("select control.release_privacy_export_cleanup($1,$2,$3) is true")
                .bind(&second_owner)
                .bind(second.0)
                .bind(second.1)
                .fetch_one(store.pool())
                .await
                .unwrap();
        assert!(current_release);
    }

    #[test]
    fn export_effects_follow_fleet_and_tenant_snapshots() {
        let source = include_str!("privacy.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        let prepare = production
            .split("async fn prepare_data_subject_export(")
            .nth(1)
            .unwrap()
            .split("async fn ensure_erasure_tombstone(")
            .next()
            .unwrap();
        let fleet_snapshot = prepare.find("privacy_export_snapshot(").unwrap();
        let tenant_snapshot = prepare.find("tenant_export_memberships(").unwrap();
        let processor_effect = prepare.find("processor_exports(").unwrap();
        assert!(fleet_snapshot < tenant_snapshot && tenant_snapshot < processor_effect);

        let tenant_function = production
            .split("async fn tenant_export_memberships(")
            .nth(1)
            .unwrap()
            .split("async fn prepare_data_subject_export(")
            .next()
            .unwrap();
        assert!(tenant_function.contains("tenant_store"));
        assert!(tenant_function.contains(".begin(*workshop_id)"));
        assert!(tenant_function.contains("m.workshop_id=$1 and m.user_id=$2"));
        assert!(tenant_function.contains("tx.commit()"));

        let handler = production
            .split("pub(crate) async fn data_subject_request(")
            .nth(1)
            .unwrap();
        assert!(handler.contains("operation_id=$2 and subject_user_id=$3"));
        let bound_request = handler
            .find("operation_id=$2 and subject_user_id=$3")
            .unwrap();
        let lease = handler.find("verify_operation_lease(").unwrap();
        let cleanup = handler.find("cleanup_export_artifacts(").unwrap();
        assert!(bound_request < lease && lease < cleanup);
        let export = handler.find("prepare_data_subject_export(").unwrap();
        assert!(handler[export..].contains("set state='acknowledged'"));
    }

    #[tokio::test]
    #[ignore = "requires a disposable CONTROL_TEST_DATABASE_URL"]
    async fn completion_is_fenced_to_the_bound_operation_lease() {
        let database_url =
            std::env::var("CONTROL_TEST_DATABASE_URL").expect("CONTROL_TEST_DATABASE_URL");
        let store = Store::connect(&database_url).await.unwrap();
        store.migrate().await.unwrap();
        let subject = Uuid::new_v4();
        sqlx::query("insert into control.users(id,email) values($1,$2)")
            .bind(subject)
            .bind(format!("privacy-fence-{subject}@example.test"))
            .execute(store.pool())
            .await
            .unwrap();

        let operation = |id: Uuid, leased_by: String| LeasedOperation {
            id,
            kind: "privacy.data_subject_request".into(),
            workshop_id: None,
            target_user_id: Some(subject),
            desired_epoch: None,
            payload: json!({}),
            attempt: 1,
            max_attempts: 3,
            leased_by,
            reconciling: false,
            trace_parent: None,
            trace_state: None,
        };
        let bound_id = Uuid::new_v4();
        let wrong_id = Uuid::new_v4();
        let bound = operation(bound_id, format!("privacy-bound-{bound_id}"));
        let wrong = operation(wrong_id, format!("privacy-wrong-{wrong_id}"));
        for candidate in [&bound, &wrong] {
            sqlx::query(
                "insert into control.operations(
                   id,kind,queue,target_user_id,payload,correlation_id,idempotency_key,
                   state,attempt,max_attempts,leased_by,lease_expires_at
                 ) values($1,'privacy.data_subject_request','privacy-operations',$2,$3,$4,$5,
                          'in_flight',1,3,$6,now()+interval '10 minutes')",
            )
            .bind(candidate.id)
            .bind(subject)
            .bind(json!({"request_id": Uuid::new_v4()}))
            .bind(Uuid::new_v4())
            .bind(format!("privacy-fence-operation:{}", candidate.id))
            .bind(&candidate.leased_by)
            .execute(store.pool())
            .await
            .unwrap();
        }
        let request = Uuid::new_v4();
        sqlx::query(
            "insert into control.data_subject_requests(
               id,subject_user_id,request_type,scope,status,operation_id
             ) values($1,$2,'access','{\"workshop_ids\":[]}'::jsonb,'executing',$3)",
        )
        .bind(request)
        .bind(subject)
        .bind(bound.id)
        .execute(store.pool())
        .await
        .unwrap();
        let task = Uuid::new_v4();
        sqlx::query(
            "insert into control.data_subject_processor_tasks(
               id,data_subject_request_id,processor_key,action
             ) values($1,$2,'control','export')",
        )
        .bind(task)
        .bind(request)
        .execute(store.pool())
        .await
        .unwrap();

        assert_eq!(
            complete_dsr(&store, &wrong, request, true).await,
            Err(IntegrationError::UnknownOutcome)
        );
        let unchanged = sqlx::query_as::<_, (String, String)>(
            "select r.status,t.state from control.data_subject_requests r
             join control.data_subject_processor_tasks t on t.data_subject_request_id=r.id
             where r.id=$1 and t.id=$2",
        )
        .bind(request)
        .bind(task)
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(unchanged, ("executing".into(), "pending".into()));

        complete_dsr(&store, &bound, request, true).await.unwrap();
        let completed = sqlx::query_as::<_, (String, String)>(
            "select r.status,t.state from control.data_subject_requests r
             join control.data_subject_processor_tasks t on t.data_subject_request_id=r.id
             where r.id=$1 and t.id=$2",
        )
        .bind(request)
        .bind(task)
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(completed, ("completed".into(), "acknowledged".into()));
    }
}
