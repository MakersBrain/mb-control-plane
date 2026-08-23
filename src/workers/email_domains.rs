use std::time::Duration;

use serde_json::{Value, json};
use uuid::Uuid;

use crate::domain::{IntegrationError, OperationKind};
use crate::integrations::scaleway_tem::{EmailDomainObservation, ScalewayTemDomainClient};
use crate::persistence::{LeasedOperation, NewOperation, Store, lock_current_operation_lease};

fn client() -> Result<ScalewayTemDomainClient, IntegrationError> {
    let token = crate::runtime_secret::required("CONTROL_MAIL_SCW_SECRET_KEY")
        .map_err(|_| IntegrationError::ContractDrift)?;
    let project = crate::runtime_secret::required_configuration("CONTROL_MAIL_SCW_PROJECT_ID")
        .map_err(|_| IntegrationError::ContractDrift)?
        .parse()
        .map_err(|_| IntegrationError::ContractDrift)?;
    ScalewayTemDomainClient::new(token, project, Duration::from_secs(20))
}

fn record_status<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value
        .get(key)
        .and_then(Value::as_object)
        .and_then(|v| v.get("status"))
        .and_then(Value::as_str)
}

fn dns_ready(observation: &EmailDomainObservation) -> bool {
    ["spf_record", "dkim_record", "dmarc_record"]
        .iter()
        .all(|key| record_status(&observation.verification, key) == Some("valid"))
}

async fn store_observation(
    store: &Store,
    id: Uuid,
    operation: Uuid,
    observation: &EmailDomainObservation,
) -> Result<(), IntegrationError> {
    let next = if observation.status == "checked" && dns_ready(observation) {
        "testing"
    } else if matches!(
        observation.status.as_str(),
        "invalid" | "locked" | "revoked"
    ) {
        "action_required"
    } else {
        "dns_pending"
    };
    sqlx::query("update control.webshop_email_domains set provider_ref=$3,provider_status=$4,dns_records=$5,verification=$6,state=$7,last_health_checked_at=now(),last_error_class=case when $7='action_required' then 'provider_domain_invalid' else null end,updated_at=now(),version=version+1 where id=$1 and operation_id=$2 and desired_state='active'")
        .bind(id).bind(operation).bind(observation.id).bind(&observation.status).bind(&observation.records).bind(&observation.verification).bind(next)
        .execute(store.pool()).await.map_err(|_|IntegrationError::Unavailable)?;
    Ok(())
}

pub(crate) async fn run(
    store: &Store,
    operation: &LeasedOperation,
) -> Result<(), IntegrationError> {
    let workshop = operation
        .workshop_id
        .ok_or(IntegrationError::ContractDrift)?;
    let id = operation
        .payload
        .get("email_domain_id")
        .and_then(Value::as_str)
        .and_then(|v| Uuid::parse_str(v).ok())
        .ok_or(IntegrationError::ContractDrift)?;
    let row=sqlx::query_as::<_,(String,String,Option<Uuid>,Option<Uuid>,Option<Uuid>,Option<time::OffsetDateTime>,Uuid)>(
        "select domain_name,desired_state,provider_ref,webhook_ref,test_outbox_id,test_delivered_at,created_by from control.webshop_email_domains where id=$1 and workshop_id=$2 and operation_id=$3")
        .bind(id).bind(workshop).bind(operation.id).fetch_optional(store.pool()).await.map_err(|_|IntegrationError::Unavailable)?.ok_or(IntegrationError::NotFound)?;
    let provider = client()?;
    if row.1 == "disconnected" {
        if let Some(webhook_ref) = row.3 {
            provider.delete_webhook(webhook_ref).await?;
        }
        if let Some(provider_ref) = row.2 {
            provider.revoke(provider_ref).await?;
        }
        sqlx::query("update control.webshop_email_domains set state='disconnected',provider_status='revoked',disconnected_at=now(),last_error_class=null,updated_at=now(),version=version+1 where id=$1 and operation_id=$2")
            .bind(id).bind(operation.id).execute(store.pool()).await.map_err(|_|IntegrationError::Unavailable)?;
        return Ok(());
    }
    let observation = match row.2 {
        Some(provider_ref) => {
            provider.check(provider_ref).await?;
            provider.observe(provider_ref).await?
        }
        None => provider.create(&row.0).await?,
    };
    if observation.name != row.0 {
        return Err(IntegrationError::ContractDrift);
    }
    store_observation(store, id, operation.id, &observation).await?;
    if observation.status != "checked" || !dns_ready(&observation) {
        return Ok(());
    }
    let sns_arn = crate::runtime_secret::required_configuration("CONTROL_MAIL_SNS_TOPIC_ARN")
        .map_err(|_| IntegrationError::ContractDrift)?;
    let webhook_ref = provider
        .ensure_webhook(observation.id, &sns_arn, &format!("mb-{id}"))
        .await?;
    sqlx::query(
        "update control.webshop_email_domains set webhook_ref=$2 where id=$1 and operation_id=$3",
    )
    .bind(id)
    .bind(webhook_ref)
    .bind(operation.id)
    .execute(store.pool())
    .await
    .map_err(|_| IntegrationError::Unavailable)?;
    if row.5.is_some() {
        sqlx::query("update control.webshop_email_domains set state='active',last_error_class=null,updated_at=now(),version=version+1 where id=$1 and operation_id=$2 and test_delivered_at is not null")
            .bind(id).bind(operation.id).execute(store.pool()).await.map_err(|_|IntegrationError::Unavailable)?;
        return Ok(());
    }
    if row.4.is_none() {
        let recipient =
            sqlx::query_scalar::<_, String>("select email from control.users where id=$1")
                .bind(row.6)
                .fetch_one(store.pool())
                .await
                .map_err(|_| IntegrationError::Unavailable)?;
        let suppressed=sqlx::query_scalar::<_,bool>("select exists(select 1 from control.email_suppressions where workshop_id=$1 and recipient=$2)").bind(workshop).bind(&recipient).fetch_one(store.pool()).await.map_err(|_|IntegrationError::Unavailable)?;
        if suppressed {
            sqlx::query("update control.webshop_email_domains set state='action_required',last_error_class='test_recipient_suppressed',updated_at=now(),version=version+1 where id=$1 and operation_id=$2").bind(id).bind(operation.id).execute(store.pool()).await.map_err(|_|IntegrationError::Unavailable)?;
            return Ok(());
        }
        let outbox = Uuid::new_v4();
        let mut tx = store
            .begin()
            .await
            .map_err(|_| IntegrationError::Unavailable)?;
        sqlx::query("insert into control.outbox(id,kind,recipient,template,payload,workshop_id,source_key) values($1,'odoo_transactional',$2,'odoo-rendered-v1',$3,$4,$5)")
            .bind(outbox).bind(recipient).bind(json!({"sender_name":"MakersBrain domain test","reply_to":Value::Null,"attachments":[],"content":{"subject":"Your branded sender is ready","text":"This delivery verifies your branded sender domain.","html":"<p>This delivery verifies your branded sender domain.</p>"}}))
            .bind(workshop).bind(format!("email-domain-test:{id}"))
            .execute(&mut *tx).await.map_err(|_|IntegrationError::Unavailable)?;
        let mail_operation = Store::enqueue(
            &mut tx,
            NewOperation {
                kind: OperationKind::EmailDelivery,
                workshop_id: Some(workshop),
                target_user_id: None,
                desired_epoch: None,
                payload: &json!({"outbox_id":outbox}),
                requested_by: None,
                correlation_id: Uuid::new_v4(),
                idempotency_key: &format!("email-domain-test:{id}"),
            },
        )
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
        sqlx::query("update control.webshop_email_domains set test_outbox_id=$2,updated_at=now(),version=version+1 where id=$1 and operation_id=$3")
            .bind(id).bind(outbox).bind(operation.id).execute(&mut *tx).await.map_err(|_|IntegrationError::Unavailable)?;
        tx.commit()
            .await
            .map_err(|_| IntegrationError::Unavailable)?;
        let _ = mail_operation;
    }
    Ok(())
}

pub(crate) async fn failed(
    store: &Store,
    operation: &LeasedOperation,
) -> Result<(), IntegrationError> {
    let Some(workshop) = operation.workshop_id else {
        return Err(IntegrationError::ContractDrift);
    };
    let Some(id) = operation
        .payload
        .get("email_domain_id")
        .and_then(Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok())
    else {
        return Err(IntegrationError::ContractDrift);
    };
    let mut tx = store
        .begin()
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
    if !lock_current_operation_lease(&mut tx, operation)
        .await
        .map_err(|_| IntegrationError::Unavailable)?
    {
        return Err(IntegrationError::UnknownOutcome);
    }
    let changed = sqlx::query(
        "update control.webshop_email_domains
            set state='action_required',last_error_class='reconciliation_failed',
                last_health_checked_at=now(),updated_at=now(),version=version+1
          where id=$1 and workshop_id=$2 and operation_id=$3 and state<>'disconnected'",
    )
    .bind(id)
    .bind(workshop)
    .bind(operation.id)
    .execute(&mut *tx)
    .await
    .map_err(|_| IntegrationError::Unavailable)?
    .rows_affected();
    if changed > 1 {
        return Err(IntegrationError::ContractDrift);
    }
    tx.commit().await.map_err(|_| IntegrationError::Unavailable)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn required_dns_records_gate_activation() {
        let ready = json!({"spf_record":{"status":"valid"},"dkim_record":{"status":"valid"},"dmarc_record":{"status":"valid"}});
        let observation = EmailDomainObservation {
            id: Uuid::nil(),
            name: "a.fr".into(),
            status: "checked".into(),
            records: json!({}),
            verification: ready,
        };
        assert!(dns_ready(&observation));
    }
}
