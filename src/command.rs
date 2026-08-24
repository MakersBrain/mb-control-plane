use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::postgres::PgConnection;
use thiserror::Error;
use uuid::Uuid;

pub struct NewCommand<'a> {
    pub actor_user_id: Uuid,
    pub scope: &'a str,
    pub command_kind: &'a str,
    pub idempotency_key: &'a str,
    pub semantic_request: &'a Value,
    pub expected_version: Option<i64>,
}

#[derive(Debug, PartialEq)]
pub enum CommandAdmission {
    New {
        command_id: Uuid,
    },
    Replay {
        command_id: Uuid,
        operation_id: Option<Uuid>,
        response_status: u16,
        response_body: Option<Value>,
        result_ref: Option<String>,
    },
    InProgress {
        command_id: Uuid,
        operation_id: Option<Uuid>,
    },
}

#[derive(Debug, Error)]
pub enum CommandError {
    #[error("idempotency key is invalid")]
    InvalidIdempotencyKey,
    #[error("idempotency key was already used for another semantic request")]
    PayloadMismatch,
    #[error(transparent)]
    Database(#[from] sqlx::Error),
}

pub fn request_digest(request: &Value) -> [u8; 32] {
    let canonical = serde_jcs::to_vec(request)
        .expect("serde_json values accepted by the API are valid RFC 8785 inputs");
    Sha256::digest(&canonical).into()
}

pub async fn admit_command(
    tx: &mut PgConnection,
    command: NewCommand<'_>,
) -> Result<CommandAdmission, CommandError> {
    if !valid_idempotency_key(command.idempotency_key) {
        return Err(CommandError::InvalidIdempotencyKey);
    }
    let id = Uuid::new_v4();
    let digest = request_digest(command.semantic_request);
    let inserted = sqlx::query(
        "insert into control.commands(
           id,actor_user_id,scope,command_kind,idempotency_key,request_digest,expected_version
         ) values($1,$2,$3,$4,$5,$6,$7)
         on conflict(actor_user_id,scope,command_kind,idempotency_key) do nothing",
    )
    .bind(id)
    .bind(command.actor_user_id)
    .bind(command.scope)
    .bind(command.command_kind)
    .bind(command.idempotency_key)
    .bind(digest.as_slice())
    .bind(command.expected_version)
    .execute(&mut *tx)
    .await?
    .rows_affected()
        == 1;

    let row = sqlx::query_as::<
        _,
        (
            Uuid,
            Vec<u8>,
            Option<i64>,
            String,
            Option<Uuid>,
            Option<i32>,
            Option<Value>,
            Option<String>,
        ),
    >(
        "select id,request_digest,expected_version,state,operation_id,
           response_status,response_body,result_ref
         from control.commands
         where actor_user_id=$1 and scope=$2 and command_kind=$3 and idempotency_key=$4
         for update",
    )
    .bind(command.actor_user_id)
    .bind(command.scope)
    .bind(command.command_kind)
    .bind(command.idempotency_key)
    .fetch_one(&mut *tx)
    .await?;

    if row.1.as_slice() != digest || row.2 != command.expected_version {
        return Err(CommandError::PayloadMismatch);
    }
    if inserted {
        return Ok(CommandAdmission::New { command_id: row.0 });
    }
    if row.3 == "completed" {
        return Ok(CommandAdmission::Replay {
            command_id: row.0,
            operation_id: row.4,
            response_status: u16::try_from(row.5.unwrap_or(500)).unwrap_or(500),
            response_body: row.6,
            result_ref: row.7,
        });
    }
    Ok(CommandAdmission::InProgress {
        command_id: row.0,
        operation_id: row.4,
    })
}

pub struct CommandResult<'a> {
    pub operation_id: Option<Uuid>,
    pub response_status: u16,
    pub response_body: Option<&'a Value>,
    pub result_ref: Option<&'a str>,
}

pub async fn complete_command(
    tx: &mut PgConnection,
    command_id: Uuid,
    result: CommandResult<'_>,
) -> Result<(), CommandError> {
    let changed = sqlx::query(
        "update control.commands set state='completed',operation_id=$2,response_status=$3,
           response_body=$4,result_ref=$5,completed_at=now()
         where id=$1 and state='admitted'",
    )
    .bind(command_id)
    .bind(result.operation_id)
    .bind(i32::from(result.response_status))
    .bind(result.response_body)
    .bind(result.result_ref)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if changed != 1 {
        return Err(CommandError::Database(sqlx::Error::RowNotFound));
    }
    Ok(())
}

fn valid_idempotency_key(value: &str) -> bool {
    (1..=255).contains(&value.len())
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'-')
        })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn semantic_digest_is_stable_across_object_key_order() {
        let left: Value =
            serde_json::from_str(r#"{"role":"artisan","email":"a@example.test"}"#).unwrap();
        let right: Value =
            serde_json::from_str(r#"{"email":"a@example.test","role":"artisan"}"#).unwrap();
        assert_eq!(request_digest(&left), request_digest(&right));
        assert_ne!(
            request_digest(&left),
            request_digest(&json!({"email":"b@example.test","role":"artisan"}))
        );
    }

    #[test]
    fn idempotency_keys_are_bounded_and_header_safe() {
        assert!(valid_idempotency_key(
            "invite:550e8400-e29b-41d4-a716-446655440000"
        ));
        assert!(!valid_idempotency_key(""));
        assert!(!valid_idempotency_key("contains a space"));
        assert!(!valid_idempotency_key(&"x".repeat(256)));
    }

    #[test]
    fn digest_uses_rfc_8785_number_and_utf16_key_canonicalization() {
        let value: Value = serde_json::from_str(
            r#"{"\r":3.333333333333333e29,"1":333333333.33333329,"€":1e30,"😀":4.50,"ö":2e-3}"#,
        )
        .unwrap();
        let canonical = serde_jcs::to_string(&value).unwrap();
        assert_eq!(
            canonical,
            r#"{"\r":3.333333333333333e+29,"1":333333333.3333333,"ö":0.002,"€":1e+30,"😀":4.5}"#
        );
        let expected: [u8; 32] = Sha256::digest(canonical).into();
        assert_eq!(request_digest(&value), expected);
    }
}
