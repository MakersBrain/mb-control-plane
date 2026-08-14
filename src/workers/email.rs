use std::time::Duration;

use serde_json::{Value, json};
use uuid::Uuid;

use crate::domain::IntegrationError;
use crate::invitation::InvitationSigner;
use crate::persistence::{LeasedOperation, Store};

fn required(name: &str) -> Result<String, IntegrationError> {
    crate::runtime_secret::environment(name)
        .map_err(|_| IntegrationError::Unauthorized)?
        .filter(|value| !value.trim().is_empty())
        .ok_or(IntegrationError::Unauthorized)
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
    // Validate local delivery configuration before claiming the row. A broken
    // key mount or webhook setting must not strand mail in `sending`.
    let signer = InvitationSigner::from_json_file(
        required("CONTROL_INVITATION_SIGNING_KEY_ID")?,
        std::path::Path::new(&required("CONTROL_INVITATION_SIGNING_KEYS_FILE")?),
    )
    .map_err(|_| IntegrationError::ContractDrift)?;
    let mut invitation_origin = url::Url::parse(&required("CONTROL_PUBLIC_ORIGIN")?)
        .and_then(|origin| origin.join("invitations/accept"))
        .map_err(|_| IntegrationError::ContractDrift)?;
    let client = client(&required("CONTROL_MAIL_WEBHOOK_TOKEN")?)?;
    let webhook_url = required("CONTROL_MAIL_WEBHOOK_URL")?;
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
        ),
    >(
        "select o.kind,o.recipient,o.template,o.payload,o.invitation_id,
           o.token_generation,o.capability_issued_at,o.capability_expires_at,o.signing_key_id
         from control.outbox o
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
    )) = row
    else {
        sqlx::query("update control.outbox set state='dead_letter' where id=$1 and kind='invitation' and state in ('queued','deferred')")
            .bind(outbox).execute(store.pool()).await.map_err(|_| IntegrationError::Unavailable)?;
        return Ok(());
    };
    if kind == "invitation" {
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
    }
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
    let response = client
        .post(webhook_url)
        .json(&json!({"to":recipient,"template":template,"data":data}))
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
        sqlx::query("update control.outbox set state='deferred',next_attempt_at=now()+interval '1 minute' where id=$1")
            .bind(outbox).execute(store.pool()).await.ok();
        return Err(crate::integrations::classify_status(response.status()));
    }
    sqlx::query("update control.outbox set state='sent',sent_at=now() where id=$1")
        .bind(outbox)
        .execute(store.pool())
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
    Ok(())
}
