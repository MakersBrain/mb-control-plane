use std::time::Duration;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

use crate::domain::IntegrationError;
use crate::persistence::{LeasedOperation, Store};
use crate::privacy_crypto;

type ExportMembership = (
    Uuid,
    String,
    String,
    String,
    OffsetDateTime,
    Option<OffsetDateTime>,
);

fn export_timestamp(value: OffsetDateTime) -> Result<String, IntegrationError> {
    value
        .format(&Rfc3339)
        .map_err(|_| IntegrationError::ContractDrift)
}

pub(crate) async fn cleanup_export_artifacts(store: &Store) -> Result<u64, IntegrationError> {
    sqlx::query_scalar::<_, i64>("select control.purge_expired_data_subject_exports()")
        .fetch_one(store.pool())
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
    let artifacts = sqlx::query_as::<_, (Uuid, String)>(
        "select id,storage_ref from control.data_subject_exports
         where state in ('consumed','expired','revoked')
           and storage_ref like 'file:%.aead' order by id",
    )
    .fetch_all(store.pool())
    .await
    .map_err(|_| IntegrationError::Unavailable)?;
    let mut deleted = 0_u64;
    for (export_id, storage_ref) in artifacts {
        privacy_crypto::delete_export_artifact(export_id, &storage_ref)?;
        let changed = sqlx::query(
            "update control.data_subject_exports
             set storage_ref=concat('purged:',storage_ref)
             where id=$1 and state in ('consumed','expired','revoked') and storage_ref=$2",
        )
        .bind(export_id)
        .bind(&storage_ref)
        .execute(store.pool())
        .await
        .map_err(|_| IntegrationError::Unavailable)?
        .rows_affected();
        deleted = deleted.saturating_add(changed);
    }
    Ok(deleted)
}

async fn processor_exports(
    request_id: Uuid,
    memberships: &[ExportMembership],
    scope: &Value,
) -> Result<Vec<Value>, IntegrationError> {
    let scoped = scope
        .get("workshop_ids")
        .and_then(Value::as_array)
        .ok_or(IntegrationError::ContractDrift)?;
    let scoped = scoped
        .iter()
        .map(|value| {
            value
                .as_str()
                .and_then(|value| Uuid::parse_str(value).ok())
                .ok_or(IntegrationError::ContractDrift)
        })
        .collect::<Result<std::collections::HashSet<_>, _>>()?;
    let base =
        std::env::var("CONTROL_PRIVACY_DRIVER_URL").map_err(|_| IntegrationError::Unauthorized)?;
    let base =
        url::Url::parse(base.trim_end_matches('/')).map_err(|_| IntegrationError::ContractDrift)?;
    if !matches!(base.scheme(), "http" | "https") || base.host_str().is_none() {
        return Err(IntegrationError::ContractDrift);
    }
    let token = crate::runtime_secret::environment("CONTROL_PRIVACY_DRIVER_TOKEN")
        .map_err(|_| IntegrationError::Unauthorized)?
        .filter(|value| !value.trim().is_empty())
        .ok_or(IntegrationError::Unauthorized)?;
    let mut authorization = reqwest::header::HeaderValue::from_str(&format!("Bearer {token}"))
        .map_err(|_| IntegrationError::ContractDrift)?;
    authorization.set_sensitive(true);
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(reqwest::header::AUTHORIZATION, authorization);
    let client = reqwest::Client::builder()
        .default_headers(headers)
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(300))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("mb-privacy-worker")
        .build()
        .map_err(|_| IntegrationError::ContractDrift)?;
    let mut result = Vec::new();
    let mut remaining = privacy_crypto::MAX_EXPORT_BYTES - 1024 * 1024;
    for membership in memberships {
        if !scoped.is_empty() && !scoped.contains(&membership.0) {
            continue;
        }
        let url = base
            .join(&format!("/v1/privacy/{}/export", membership.0))
            .map_err(|_| IntegrationError::ContractDrift)?;
        if url.origin() != base.origin() {
            return Err(IntegrationError::ContractDrift);
        }
        let response = client
            .post(url)
            .json(&json!({"request_id":request_id}))
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

async fn prepare_data_subject_export(
    store: &Store,
    request_id: Uuid,
    subject_user_id: Uuid,
    request_type: &str,
    scope: &Value,
) -> Result<(), IntegrationError> {
    if let Some(state) = sqlx::query_scalar::<_, String>(
        "select state from control.data_subject_exports where data_subject_request_id=$1",
    )
    .bind(request_id)
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

    let user = sqlx::query_as::<
        _,
        (
            String,
            Option<String>,
            String,
            OffsetDateTime,
            Option<OffsetDateTime>,
        ),
    >(
        "select email,display_name,locale,created_at,disabled_at from control.users where id=$1",
    )
    .bind(subject_user_id)
    .fetch_one(store.pool())
    .await
    .map_err(|_| IntegrationError::Unavailable)?;
    let identity = sqlx::query_as::<_, (String, String, OffsetDateTime, Option<OffsetDateTime>)>(
        "select issuer,subject,linked_at,disabled_at from control.external_identities where user_id=$1",
    )
    .bind(subject_user_id)
    .fetch_optional(store.pool())
    .await
    .map_err(|_| IntegrationError::Unavailable)?;
    let memberships = sqlx::query_as::<_, ExportMembership>(
        "select m.workshop_id,w.display_name,m.role,m.status,m.created_at,m.revoked_at
         from control.memberships m join control.workshops w on w.id=m.workshop_id
         where m.user_id=$1 order by m.workshop_id",
    )
    .bind(subject_user_id)
    .fetch_all(store.pool())
    .await
    .map_err(|_| IntegrationError::Unavailable)?;
    let request_history =
        sqlx::query_as::<_, (Uuid, String, String, OffsetDateTime, Option<OffsetDateTime>)>(
            "select id,request_type,status,requested_at,completed_at
         from control.data_subject_requests where subject_user_id=$1 order by requested_at,id",
        )
        .bind(subject_user_id)
        .fetch_all(store.pool())
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
    let processor_tasks = sqlx::query_as::<_, (String, String, String, Option<String>)>(
        "select processor_key,action,state,acknowledgement_ref
         from control.data_subject_processor_tasks where data_subject_request_id=$1
         order by processor_key,action",
    )
    .bind(request_id)
    .fetch_all(store.pool())
    .await
    .map_err(|_| IntegrationError::Unavailable)?;
    let processor_exports = processor_exports(request_id, &memberships, scope).await?;

    let payload = json!({
        "format":"mb-gdpr-export-v1",
        "generated_at":export_timestamp(OffsetDateTime::now_utc())?,
        "request":{"id":request_id,"type":request_type,"scope":scope},
        "subject":{
            "id":subject_user_id,"email":user.0,"display_name":user.1,"locale":user.2,
            "created_at":export_timestamp(user.3)?,
            "disabled_at":user.4.map(export_timestamp).transpose()?
        },
        "external_identity":identity.map(|row| -> Result<Value,IntegrationError> { Ok(json!({
            "issuer":row.0,"subject":row.1,"linked_at":export_timestamp(row.2)?,
            "disabled_at":row.3.map(export_timestamp).transpose()?
        }))}).transpose()?,
        "memberships":memberships.into_iter().map(|row| -> Result<Value,IntegrationError> { Ok(json!({
            "workshop_id":row.0,"workshop_name":row.1,"role":row.2,"status":row.3,
            "created_at":export_timestamp(row.4)?,"revoked_at":row.5.map(export_timestamp).transpose()?
        }))}).collect::<Result<Vec<_>,_>>()?,
        "rights_request_history":request_history.into_iter().map(|row| -> Result<Value,IntegrationError> { Ok(json!({
            "id":row.0,"type":row.1,"status":row.2,"requested_at":export_timestamp(row.3)?,
            "completed_at":row.4.map(export_timestamp).transpose()?
        }))}).collect::<Result<Vec<_>,_>>()?,
        "processor_manifest":processor_tasks.into_iter().map(|row| json!({
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
    .bind(request_id)
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
    let (policy_version,dry_run,state)=sqlx::query_as::<_,(Option<i32>,bool,String)>(
        "select policy_version,dry_run,state from control.retention_runs where id=$1 and operation_id=$2",
    ).bind(run_id).bind(operation.id).fetch_optional(store.pool()).await
        .map_err(|_|IntegrationError::Unavailable)?.ok_or(IntegrationError::NotFound)?;
    if state == "completed" {
        return Ok(());
    }
    let Some(policy_version) = policy_version else {
        sqlx::query("update control.retention_runs set state='blocked_approval',evidence=jsonb_build_object('reason','retention_policy_approval_required'),completed_at=now() where id=$1")
            .bind(run_id).execute(store.pool()).await.map_err(|_|IntegrationError::Unavailable)?;
        return Err(IntegrationError::Rejected);
    };
    let policy = sqlx::query_as::<_, (String, Value)>(
        "select status,policy from control.retention_policy_versions where version=$1",
    )
    .bind(policy_version)
    .fetch_optional(store.pool())
    .await
    .map_err(|_| IntegrationError::Unavailable)?
    .ok_or(IntegrationError::NotFound)?;
    if !dry_run && policy.0 != "approved" {
        sqlx::query("update control.retention_runs set state='blocked_approval',evidence=jsonb_build_object('reason','retention_policy_not_approved'),completed_at=now() where id=$1")
            .bind(run_id).execute(store.pool()).await.map_err(|_|IntegrationError::Unavailable)?;
        return Err(IntegrationError::Rejected);
    }
    let duration = |dataset: &str| -> Result<i64, IntegrationError> {
        policy
            .1
            .pointer(&format!("/datasets/{dataset}/duration_days"))
            .and_then(Value::as_i64)
            .filter(|days| *days >= 0 && *days <= 36500)
            .ok_or(IntegrationError::ContractDrift)
    };
    let invitation_days = duration("invitations")?;
    let mail_days = duration("mail-delivery")?;
    let operation_days = duration("operations")?;
    let invitations=sqlx::query_scalar::<_,i64>("select count(*) from control.invitations where coalesce(accepted_at,revoked_at,expires_at)<now()-($1::bigint*interval '1 day')")
        .bind(invitation_days).fetch_one(store.pool()).await.map_err(|_|IntegrationError::Unavailable)?;
    let outbox=sqlx::query_scalar::<_,i64>("select count(*) from control.outbox where state in ('sent','dead_letter') and coalesce(sent_at,created_at)<now()-($1::bigint*interval '1 day')")
        .bind(mail_days).fetch_one(store.pool()).await.map_err(|_|IntegrationError::Unavailable)?;
    let operations=sqlx::query_scalar::<_,i64>("select count(*) from control.operations where state in ('succeeded','dead_letter') and coalesce(finished_at,created_at)<now()-($1::bigint*interval '1 day') and kind not like 'privacy.%'")
        .bind(operation_days).fetch_one(store.pool()).await.map_err(|_|IntegrationError::Unavailable)?;
    let deletable_invitations=sqlx::query_scalar::<_,i64>("select count(*) from control.invitations i where coalesce(i.accepted_at,i.revoked_at,i.expires_at)<now()-($1::bigint*interval '1 day') and not control.legal_hold_applies('invitations',i.workshop_id,array[i.invited_by,i.accepted_user_id])")
        .bind(invitation_days).fetch_one(store.pool()).await.map_err(|_|IntegrationError::Unavailable)?;
    let deletable_outbox=sqlx::query_scalar::<_,i64>("select count(*) from control.outbox o left join control.invitations i on i.id=o.invitation_id where o.state in ('sent','dead_letter') and coalesce(o.sent_at,o.created_at)<now()-($1::bigint*interval '1 day') and not control.legal_hold_applies('mail-delivery',i.workshop_id,array[i.invited_by,i.accepted_user_id])")
        .bind(mail_days).fetch_one(store.pool()).await.map_err(|_|IntegrationError::Unavailable)?;
    let redactable_operations=sqlx::query_scalar::<_,i64>("select count(*) from control.operations o where o.state in ('succeeded','dead_letter') and coalesce(o.finished_at,o.created_at)<now()-($1::bigint*interval '1 day') and o.kind not like 'privacy.%' and not control.legal_hold_applies('operations',o.workshop_id,array[o.requested_by,o.target_user_id])")
        .bind(operation_days).fetch_one(store.pool()).await.map_err(|_|IntegrationError::Unavailable)?;
    let held_datasets = [
        (deletable_invitations < invitations).then_some("invitations"),
        (deletable_outbox < outbox).then_some("mail-delivery"),
        (redactable_operations < operations).then_some("operations"),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();
    let deleted_count = if dry_run {
        0
    } else {
        deletable_invitations + deletable_outbox
    };
    let redacted_operation_count = if dry_run { 0 } else { redactable_operations };
    let evidence = json!({
        "policy_version":policy_version,
        "dry_run":dry_run,
        "candidates":{"invitations":invitations,"mail_delivery":outbox,"operation_details":operations},
        "held":{"invitations":invitations-deletable_invitations,"mail_delivery":outbox-deletable_outbox,"operation_details":operations-redactable_operations},
        "held_datasets":held_datasets,
        "deleted_count":deleted_count,
        "redacted_operation_count":redacted_operation_count
    });
    if !dry_run {
        let mut tx = store
            .begin()
            .await
            .map_err(|_| IntegrationError::Unavailable)?;
        sqlx::query("delete from control.outbox o using (select o2.id from control.outbox o2 left join control.invitations i on i.id=o2.invitation_id where o2.state in ('sent','dead_letter') and coalesce(o2.sent_at,o2.created_at)<now()-($1::bigint*interval '1 day') and not control.legal_hold_applies('mail-delivery',i.workshop_id,array[i.invited_by,i.accepted_user_id])) deletable where o.id=deletable.id")
            .bind(mail_days).execute(&mut *tx).await.map_err(|_|IntegrationError::Unavailable)?;
        sqlx::query("update control.invitations i set email=concat('retained-invitation-',i.id,'@invalid'),idempotency_key=concat('retained:',i.id) where coalesce(i.accepted_at,i.revoked_at,i.expires_at)<now()-($1::bigint*interval '1 day') and not control.legal_hold_applies('invitations',i.workshop_id,array[i.invited_by,i.accepted_user_id])")
            .bind(invitation_days).execute(&mut *tx).await.map_err(|_|IntegrationError::Unavailable)?;
        sqlx::query("update control.operations o set payload='{\"redacted\":true}'::jsonb,checkpoint=null where o.state in ('succeeded','dead_letter') and coalesce(o.finished_at,o.created_at)<now()-($1::bigint*interval '1 day') and o.kind not like 'privacy.%' and not control.legal_hold_applies('operations',o.workshop_id,array[o.requested_by,o.target_user_id])")
            .bind(operation_days).execute(&mut *tx).await.map_err(|_|IntegrationError::Unavailable)?;
        tx.commit()
            .await
            .map_err(|_| IntegrationError::Unavailable)?;
    }
    sqlx::query("update control.retention_runs set state='completed',evidence=$2,started_at=coalesce(started_at,now()),completed_at=now() where id=$1")
        .bind(run_id).bind(evidence).execute(store.pool()).await.map_err(|_|IntegrationError::Unavailable)?;
    Ok(())
}

pub(crate) async fn data_subject_request(
    store: &Store,
    operation: &LeasedOperation,
) -> Result<(), IntegrationError> {
    cleanup_export_artifacts(store).await?;
    let request_id = operation
        .payload
        .get("request_id")
        .and_then(Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok())
        .ok_or(IntegrationError::ContractDrift)?;
    let request=sqlx::query_as::<_,(String,String,Uuid,i64,Value)>("select request_type,status,subject_user_id,version,scope from control.data_subject_requests where id=$1")
        .bind(request_id).fetch_optional(store.pool()).await.map_err(|_|IntegrationError::Unavailable)?.ok_or(IntegrationError::NotFound)?;
    if request.1 == "completed" {
        return Ok(());
    }
    if request.1 != "approved" && request.1 != "executing" {
        return Err(IntegrationError::Rejected);
    }
    if request.1 == "approved" {
        transition_dsr(store, request_id, "approved", "executing").await?;
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
                workshops=sqlx::query_scalar::<_,Uuid>("select workshop_id from control.memberships where user_id=$1 order by workshop_id")
                    .bind(request.2).fetch_all(store.pool()).await.map_err(|_|IntegrationError::Unavailable)?;
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
    // Processor tasks remain outstanding until there is actual evidence. This
    // prevents a partial export or erasure from falsely closing a rights request.
    let outstanding=sqlx::query_scalar::<_,bool>("select exists(select 1 from control.data_subject_processor_tasks where data_subject_request_id=$1 and state not in ('acknowledged','not_applicable'))")
        .bind(request_id).fetch_one(store.pool()).await.map_err(|_|IntegrationError::Unavailable)?;
    if outstanding {
        return Err(IntegrationError::Unavailable);
    }
    if matches!(request.0.as_str(), "access" | "portability") {
        prepare_data_subject_export(store, request_id, request.2, &request.0, &request.4).await?;
    }
    transition_dsr(store, request_id, "executing", "completed").await
}

async fn transition_dsr(
    store: &Store,
    id: Uuid,
    from: &str,
    to: &str,
) -> Result<(), IntegrationError> {
    let changed=sqlx::query("update control.data_subject_requests set status=$3,completed_at=case when $3='completed' then now() else completed_at end,version=version+1 where id=$1 and status=$2")
        .bind(id).bind(from).bind(to).execute(store.pool()).await.map_err(|_|IntegrationError::Unavailable)?.rows_affected();
    if changed == 1 {
        Ok(())
    } else {
        Err(IntegrationError::UnknownOutcome)
    }
}
