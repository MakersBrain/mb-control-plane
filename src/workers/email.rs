use serde_json::{Value, json};
use uuid::Uuid;

use crate::domain::IntegrationError;
use crate::outbound_http::TraceRequestBuilderExt as _;
use crate::persistence::{LeasedOperation, TenantStore};
use crate::worker_config::EmailDeliveryConfig;

async fn owned_outbox(
    tenant_store: &TenantStore,
    workshop: Uuid,
    outbox: Uuid,
) -> Result<(String, String), IntegrationError> {
    let mut tx = tenant_store
        .begin(workshop)
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
    let owned = sqlx::query_as::<_, (String, String)>(
        "select o.kind,o.state
           from control.outbox o
           left join control.invitations i on i.id=o.invitation_id
          where o.id=$1 and o.workshop_id=$2
            and (o.kind<>'invitation' or i.workshop_id=$2)",
    )
    .bind(outbox)
    .bind(workshop)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| IntegrationError::Unavailable)?
    .ok_or(IntegrationError::NotFound)?;
    tx.commit()
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
    Ok(owned)
}

pub(crate) async fn deliver(
    tenant_store: &TenantStore,
    workshop: Uuid,
    operation: &LeasedOperation,
    config: &EmailDeliveryConfig,
) -> Result<(), IntegrationError> {
    let outbox = operation
        .payload
        .get("outbox_id")
        .and_then(Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok())
        .ok_or(IntegrationError::ContractDrift)?;
    let owned = owned_outbox(tenant_store, workshop, outbox).await?;
    // A timed-out submission is reconciled by the authenticated provider event,
    // which fills the provider identifiers and advances the outbox to `sent`.
    // Until that evidence arrives, replay remains fenced to avoid duplicates.
    if operation.reconciling {
        return if matches!(owned.1.as_str(), "sent" | "dead_letter") {
            Ok(())
        } else {
            Err(IntegrationError::UnknownOutcome)
        };
    }
    let mut read_tx = tenant_store
        .begin(workshop)
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
    let row = sqlx::query_as::<
        _,
        (
            String,
            String,
            String,
            Value,
            Option<Uuid>,
            Option<i32>,
            Option<time::OffsetDateTime>,
            Option<time::OffsetDateTime>,
            Option<String>,
            Option<String>,
            Option<Uuid>,
            Option<String>,
            Option<String>,
        ),
    >(
        "select o.kind,o.recipient,o.template,o.payload,o.invitation_id,
           o.token_generation,o.capability_issued_at,o.capability_expires_at,o.signing_key_id,
           case when ed.provider_status='checked' then ed.sender_local_part||'@'||ed.domain_name end,
           case when ed.provider_status='checked' then ed.provider_ref end,
           invitation.role,invitation.locale
         from control.outbox o
         left join control.invitations invitation on invitation.id=o.invitation_id
         left join lateral (select d.* from control.webshop_email_domains d
             where d.workshop_id=o.workshop_id and d.desired_state='active'
               and (d.state='active' or d.test_outbox_id=o.id)
             order by (d.test_outbox_id=o.id) desc,d.updated_at desc limit 1) ed on true
         where o.id=$1 and (
             (o.kind='odoo_transactional' and o.workshop_id=$2)
             or (o.kind='invitation' and o.workshop_id=$2 and invitation.workshop_id=$2)
         ) and o.state in('queued','deferred')
           and (o.kind<>'invitation' or exists (
             select 1 from control.invitations i
             where o.invitation_id=i.id and o.token_generation=i.token_generation
               and i.accepted_at is null and i.revoked_at is null and i.expires_at>now()
           ))",
    )
    .bind(outbox)
    .bind(workshop)
    .fetch_optional(&mut *read_tx)
    .await
    .map_err(|_| IntegrationError::Unavailable)?;
    let Some((
        kind,
        recipient,
        template,
        mut data,
        invitation,
        generation,
        issued,
        expires,
        key_id,
        sender_email,
        sender_domain_id,
        invitation_role,
        invitation_locale,
    )) = row
    else {
        sqlx::query("update control.outbox o set state='dead_letter' where o.id=$1 and o.kind='invitation' and o.workshop_id=$2 and o.state in ('queued','deferred') and exists(select 1 from control.invitations i where i.id=o.invitation_id and i.workshop_id=$2)")
            .bind(outbox).bind(workshop).execute(&mut *read_tx).await.map_err(|_| IntegrationError::Unavailable)?;
        read_tx
            .commit()
            .await
            .map_err(|_| IntegrationError::Unavailable)?;
        return Ok(());
    };
    read_tx
        .commit()
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
    let (sender_name, reply_to, attachments) = if kind == "invitation" {
        data = json!({
            "invitation_id": invitation.ok_or(IntegrationError::ContractDrift)?,
            "workshop_id": workshop,
            "role": invitation_role.ok_or(IntegrationError::ContractDrift)?,
            "locale": invitation_locale.ok_or(IntegrationError::ContractDrift)?,
        });
        let mut invitation_origin = config.invitation_accept_url().clone();
        let signer = config
            .load_invitation_signer()
            .map_err(|_| IntegrationError::ContractDrift)?;
        let token = signer
            .sign_with_key_id(
                &key_id.ok_or(IntegrationError::ContractDrift)?,
                invitation.ok_or(IntegrationError::ContractDrift)?,
                generation.ok_or(IntegrationError::ContractDrift)?,
                issued.ok_or(IntegrationError::ContractDrift)?,
                expires.ok_or(IntegrationError::ContractDrift)?,
            )
            .map_err(|_| IntegrationError::ContractDrift)?;
        invitation_origin.set_fragment(Some(&format!("token={token}")));
        data.as_object_mut()
            .ok_or(IntegrationError::ContractDrift)?
            .insert(
                "accept_url".into(),
                Value::String(invitation_origin.to_string()),
            );
        (None, None, json!([]))
    } else if kind == "odoo_transactional" {
        let object = data.as_object().ok_or(IntegrationError::ContractDrift)?;
        let content = object
            .get("content")
            .cloned()
            .ok_or(IntegrationError::ContractDrift)?;
        let sender_name = object
            .get("sender_name")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let reply_to = object
            .get("reply_to")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let attachments = object
            .get("attachments")
            .cloned()
            .ok_or(IntegrationError::ContractDrift)?;
        data = content;
        (sender_name, reply_to, attachments)
    } else {
        return Err(IntegrationError::ContractDrift);
    };
    let mut claim_tx = tenant_store
        .begin(workshop)
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
    let claimed = sqlx::query(
        "update control.outbox o set state='sending',attempts=attempts+1
         where o.id=$1 and o.state in('queued','deferred')
           and o.workshop_id=$2
           and (o.kind<>'invitation' or exists (
                    select 1 from control.invitations owner
                    where owner.id=o.invitation_id and owner.workshop_id=$2))
           and (o.kind<>'invitation' or exists (
             select 1 from control.invitations i
             where o.invitation_id=i.id and o.token_generation=i.token_generation
               and i.accepted_at is null and i.revoked_at is null and i.expires_at>now()
           ))",
    )
    .bind(outbox)
    .bind(workshop)
    .execute(&mut *claim_tx)
    .await
    .map_err(|_| IntegrationError::Unavailable)?
    .rows_affected();
    if claimed != 1 {
        claim_tx
            .commit()
            .await
            .map_err(|_| IntegrationError::Unavailable)?;
        return Ok(());
    }
    claim_tx
        .commit()
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
    let response = match config
        .client()
        .post(config.webhook_url().clone())
        .header(
            reqwest::header::AUTHORIZATION,
            config.authorization().clone(),
        )
        .json(&json!({
            "delivery_id":outbox,"to":recipient,"template":template,"data":data,
            "sender_name":sender_name,"reply_to":reply_to,"attachments":attachments,
            "sender_email":sender_email,"sender_domain_id":sender_domain_id
        }))
        .with_current_trace_context()
        .send()
        .await
    {
        Ok(response) => response,
        Err(error) if error.is_connect() => {
            // DNS, TCP and TLS connection failures happen before the gateway can
            // accept the delivery. Put the row back into the selectable retry set.
            let mut tx = tenant_store
                .begin(workshop)
                .await
                .map_err(|_| IntegrationError::Unavailable)?;
            sqlx::query(
                "update control.outbox o set state='deferred',next_attempt_at=now()+interval '1 minute' where o.id=$1 and o.state='sending' and o.workshop_id=$2 and (o.kind<>'invitation' or exists(select 1 from control.invitations i where i.id=o.invitation_id and i.workshop_id=$2))",
            )
            .bind(outbox).bind(workshop)
            .execute(&mut *tx)
            .await
            .map_err(|_| IntegrationError::Unavailable)?;
            tx.commit()
                .await
                .map_err(|_| IntegrationError::Unavailable)?;
            return Err(IntegrationError::Unavailable);
        }
        Err(_) => return Err(IntegrationError::UnknownOutcome),
    };
    let status = response.status();
    if status == reqwest::StatusCode::GATEWAY_TIMEOUT {
        return Err(IntegrationError::UnknownOutcome);
    }
    if !status.is_success() {
        let error = crate::integrations::classify_status(status);
        let mut tx = tenant_store
            .begin(workshop)
            .await
            .map_err(|_| IntegrationError::Unavailable)?;
        if error.retryable() {
            sqlx::query("update control.outbox o set state='deferred',next_attempt_at=now()+interval '1 minute' where o.id=$1 and o.workshop_id=$2 and (o.kind<>'invitation' or exists(select 1 from control.invitations i where i.id=o.invitation_id and i.workshop_id=$2))")
                .bind(outbox).bind(workshop).execute(&mut *tx).await.ok();
        } else {
            sqlx::query(
                "update control.outbox o set state='dead_letter',next_attempt_at=null where o.id=$1 and o.workshop_id=$2 and (o.kind<>'invitation' or exists(select 1 from control.invitations i where i.id=o.invitation_id and i.workshop_id=$2))",
            )
            .bind(outbox).bind(workshop)
            .execute(&mut *tx)
            .await
            .ok();
        }
        tx.commit().await.ok();
        return Err(error);
    }
    let body = crate::integrations::bounded_body(response, 4096).await?;
    let provider_response =
        serde_json::from_slice::<Value>(&body).map_err(|_| IntegrationError::ContractDrift)?;
    let provider_message_id = provider_response
        .get("provider_message_id")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .and_then(|value| Uuid::parse_str(&value).ok())
        .ok_or(IntegrationError::ContractDrift)?;
    let provider_domain_id = provider_response
        .get("provider_domain_id")
        .and_then(Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok())
        .ok_or(IntegrationError::ContractDrift)?;
    if sender_domain_id.is_some_and(|expected| expected != provider_domain_id) {
        return Err(IntegrationError::ContractDrift);
    }
    let mut tx = tenant_store
        .begin(workshop)
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
    let changed = sqlx::query("update control.outbox o set state='sent',sent_at=now(),delivery_state='submitted',provider_message_id=$2,provider_domain_id=$3 where o.id=$1 and o.state='sending' and o.workshop_id=$4 and (o.kind<>'invitation' or exists(select 1 from control.invitations i where i.id=o.invitation_id and i.workshop_id=$4))")
        .bind(outbox)
        .bind(provider_message_id)
        .bind(provider_domain_id)
        .bind(workshop)
        .execute(&mut *tx)
        .await
        .map_err(|_| IntegrationError::Unavailable)?
        .rows_affected();
    tx.commit()
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
    if changed != 1 {
        return Err(IntegrationError::UnknownOutcome);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::Store;

    #[tokio::test]
    #[ignore = "requires a disposable CONTROL_TEST_DATABASE_URL"]
    async fn cross_workshop_outbox_is_rejected_before_delivery_configuration() {
        let url = std::env::var("CONTROL_TEST_DATABASE_URL")
            .expect("CONTROL_TEST_DATABASE_URL for disposable PostgreSQL");
        let store = Store::connect(&url).await.unwrap();
        store.migrate().await.unwrap();
        let first = Uuid::new_v4();
        let second = Uuid::new_v4();
        for (workshop, label) in [(first, "first"), (second, "second")] {
            sqlx::query("insert into control.workshops(id,slug,display_name,time_zone) values($1,$2,$3,'Europe/Paris')")
                .bind(workshop)
                .bind(format!("email-scope-{}", workshop.simple()))
                .bind(label)
                .execute(store.pool())
                .await
                .unwrap();
        }
        let outbox = Uuid::new_v4();
        sqlx::query("insert into control.outbox(id,kind,recipient,template,payload,workshop_id,source_key) values($1,'odoo_transactional','customer@example.test','odoo-rendered-v1',$2,$3,$4)")
            .bind(outbox)
            .bind(json!({"sender_name":Value::Null,"reply_to":Value::Null,"attachments":[],"content":{"subject":"scope test","text":"scope test","html":"<p>scope test</p>"}}))
            .bind(second)
            .bind(format!("scope-test:{outbox}"))
            .execute(store.pool())
            .await
            .unwrap();

        let tenant_store = store.worker_tenant_scope();
        assert_eq!(
            owned_outbox(&tenant_store, first, outbox).await,
            Err(IntegrationError::NotFound)
        );
        let unchanged = sqlx::query_as::<_, (String, i32)>(
            "select state,attempts from control.outbox where id=$1",
        )
        .bind(outbox)
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(unchanged, ("queued".into(), 0));
        assert_eq!(
            owned_outbox(&tenant_store, second, outbox).await.unwrap(),
            ("odoo_transactional".into(), "queued".into())
        );
    }
}
