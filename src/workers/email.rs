use std::time::Duration;

use serde_json::{Value, json};
use uuid::Uuid;

use crate::domain::IntegrationError;
use crate::invitation::InvitationSigner;
use crate::persistence::{LeasedOperation, Store};

fn secret(name: &str) -> Result<String, IntegrationError> {
    crate::runtime_secret::environment(name)
        .map_err(|_| IntegrationError::Unauthorized)?
        .filter(|value| !value.trim().is_empty())
        .ok_or(IntegrationError::Unauthorized)
}

fn configured(name: &str) -> Result<String, IntegrationError> {
    crate::runtime_secret::required_configuration(name).map_err(|_| IntegrationError::Unauthorized)
}

fn client(token: &str) -> Result<reqwest::Client, IntegrationError> {
    let mut value = reqwest::header::HeaderValue::from_str(&format!("Bearer {token}"))
        .map_err(|_| IntegrationError::ContractDrift)?;
    value.set_sensitive(true);
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(reqwest::header::AUTHORIZATION, value);
    reqwest::Client::builder()
        .default_headers(headers)
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| IntegrationError::ContractDrift)
}

pub(crate) async fn deliver(
    store: &Store,
    operation: &LeasedOperation,
) -> Result<(), IntegrationError> {
    let outbox = operation
        .payload
        .get("outbox_id")
        .and_then(Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok())
        .ok_or(IntegrationError::ContractDrift)?;
    // A timed-out submission is reconciled by the authenticated provider event,
    // which fills the provider identifiers and advances the outbox to `sent`.
    // Until that evidence arrives, replay remains fenced to avoid duplicates.
    if operation.reconciling {
        let state = sqlx::query_scalar::<_, String>("select state from control.outbox where id=$1")
            .bind(outbox)
            .fetch_optional(store.pool())
            .await
            .map_err(|_| IntegrationError::Unavailable)?
            .ok_or(IntegrationError::NotFound)?;
        return if matches!(state.as_str(), "sent" | "dead_letter") {
            Ok(())
        } else {
            Err(IntegrationError::UnknownOutcome)
        };
    }
    // Validate the gateway before claiming the row. Broken secret mounts must
    // not strand durable mail in `sending`.
    let client = client(&secret("CONTROL_MAIL_WEBHOOK_TOKEN")?)?;
    let webhook_url = configured("CONTROL_MAIL_WEBHOOK_URL")?;
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
        ),
    >(
        "select o.kind,o.recipient,o.template,o.payload,o.invitation_id,
           o.token_generation,o.capability_issued_at,o.capability_expires_at,o.signing_key_id,
           case when ed.provider_status='checked' then ed.sender_local_part||'@'||ed.domain_name end,
           case when ed.provider_status='checked' then ed.provider_ref end
         from control.outbox o
         left join lateral (select d.* from control.webshop_email_domains d
             where d.workshop_id=o.workshop_id and d.desired_state='active'
               and (d.state='active' or d.test_outbox_id=o.id)
             order by (d.test_outbox_id=o.id) desc,d.updated_at desc limit 1) ed on true
         where o.id=$1 and o.state in('queued','deferred')
           and (o.kind<>'invitation' or exists (
             select 1 from control.invitations i
             where o.invitation_id=i.id and o.token_generation=i.token_generation
               and i.accepted_at is null and i.revoked_at is null and i.expires_at>now()
           ))",
    )
    .bind(outbox)
    .fetch_optional(store.pool())
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
    )) = row
    else {
        sqlx::query("update control.outbox set state='dead_letter' where id=$1 and kind='invitation' and state in ('queued','deferred')")
            .bind(outbox).execute(store.pool()).await.map_err(|_| IntegrationError::Unavailable)?;
        return Ok(());
    };
    let (sender_name, reply_to, attachments) = if kind == "invitation" {
        let signer = InvitationSigner::from_json_file(
            configured("CONTROL_INVITATION_SIGNING_KEY_ID")?,
            std::path::Path::new(&configured("CONTROL_INVITATION_SIGNING_KEYS_FILE")?),
        )
        .map_err(|_| IntegrationError::ContractDrift)?;
        let mut invitation_origin = url::Url::parse(&configured("CONTROL_PUBLIC_ORIGIN")?)
            .and_then(|origin| origin.join("invitations/accept"))
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
    let claimed = sqlx::query(
        "update control.outbox o set state='sending',attempts=attempts+1
         where o.id=$1 and o.state in('queued','deferred')
           and (o.kind<>'invitation' or exists (
             select 1 from control.invitations i
             where o.invitation_id=i.id and o.token_generation=i.token_generation
               and i.accepted_at is null and i.revoked_at is null and i.expires_at>now()
           ))",
    )
    .bind(outbox)
    .execute(store.pool())
    .await
    .map_err(|_| IntegrationError::Unavailable)?
    .rows_affected();
    if claimed != 1 {
        return Ok(());
    }
    let response = match client
        .post(webhook_url)
        .json(&json!({
            "delivery_id":outbox,"to":recipient,"template":template,"data":data,
            "sender_name":sender_name,"reply_to":reply_to,"attachments":attachments,
            "sender_email":sender_email,"sender_domain_id":sender_domain_id
        }))
        .send()
        .await
    {
        Ok(response) => response,
        Err(error) if error.is_connect() => {
            // DNS, TCP and TLS connection failures happen before the gateway can
            // accept the delivery. Put the row back into the selectable retry set.
            sqlx::query(
                "update control.outbox set state='deferred',next_attempt_at=now()+interval '1 minute' where id=$1 and state='sending'",
            )
            .bind(outbox)
            .execute(store.pool())
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
        if error.retryable() {
            sqlx::query("update control.outbox set state='deferred',next_attempt_at=now()+interval '1 minute' where id=$1")
                .bind(outbox).execute(store.pool()).await.ok();
        } else {
            sqlx::query(
                "update control.outbox set state='dead_letter',next_attempt_at=null where id=$1",
            )
            .bind(outbox)
            .execute(store.pool())
            .await
            .ok();
        }
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
    sqlx::query("update control.outbox set state='sent',sent_at=now(),delivery_state='submitted',provider_message_id=$2,provider_domain_id=$3 where id=$1")
        .bind(outbox)
        .bind(provider_message_id)
        .bind(provider_domain_id)
        .execute(store.pool())
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
    Ok(())
}
