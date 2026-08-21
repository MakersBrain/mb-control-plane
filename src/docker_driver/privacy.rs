use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::integrations::odoo::{OdooClient, PrivacyExportCommand};
use crate::integrations::paperless::PaperlessClient;

use super::{DriverError, DriverState, payload_uuid};

pub(super) async fn export(
    State(state): State<Arc<DriverState>>,
    Path(workshop): Path<Uuid>,
    headers: HeaderMap,
    Json(payload): Json<Value>,
) -> Result<Json<Value>, DriverError> {
    if headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        != Some(&format!("Bearer {}", state.config.privacy_token))
    {
        return Err(DriverError(StatusCode::UNAUTHORIZED, "unauthorized".into()));
    }
    let request_id = payload_uuid(&payload, "request_id")?;
    let subject = sqlx::query_as::<_, (Uuid, String)>(
        "select r.subject_user_id,i.subject
           from control.data_subject_requests r
           join control.memberships m on m.user_id=r.subject_user_id and m.workshop_id=$2
           join control.external_identities i on i.user_id=r.subject_user_id
          where r.id=$1 and r.status='executing'
            and r.request_type in ('access','portability')
            and (coalesce(jsonb_array_length(r.scope->'workshop_ids'),0)=0
                 or coalesce(r.scope->'workshop_ids','[]'::jsonb) ? $3)
          order by i.linked_at,i.id limit 1",
    )
    .bind(request_id)
    .bind(workshop)
    .bind(workshop.to_string())
    .fetch_optional(&state.ledger)
    .await
    .map_err(DriverError::internal)?
    .ok_or_else(|| {
        DriverError(
            StatusCode::FORBIDDEN,
            "privacy export is not authorized".into(),
        )
    })?;
    let services = sqlx::query_as::<_, (String, String, String, Option<String>)>(
        "select si.service,si.base_url,si.secret_ref,
                case when si.service='odoo' then od.database_ref else null end
           from control.service_instances si
           left join control.odoo_databases od on od.workshop_id=si.workshop_id
             and od.kind='primary' and od.deleted_at is null and si.service='odoo'
          where si.workshop_id=$1 and si.service in ('odoo','paperless')
          order by si.service",
    )
    .bind(workshop)
    .fetch_all(&state.ledger)
    .await
    .map_err(DriverError::internal)?;
    let mut odoo = None;
    let mut paperless = None;
    for (service, base_url, secret_ref, database_ref) in services {
        if secret_ref != format!("docker/{workshop}/{service}") {
            return Err(DriverError::bad(
                "processor secret reference is not tenant-scoped",
            ));
        }
        let token = std::fs::read_to_string(
            state
                .config
                .secret_root
                .join("docker")
                .join(workshop.to_string())
                .join(&service),
        )
        .map_err(DriverError::internal)?;
        let token = token.trim();
        if token.is_empty() {
            return Err(DriverError::internal("processor credential is empty"));
        }
        match service.as_str() {
            "odoo" => {
                let client = OdooClient::new(
                    &base_url,
                    token,
                    database_ref.as_deref(),
                    Duration::from_secs(120),
                )
                .map_err(DriverError::internal)?;
                odoo = Some(
                    client
                        .export_personal_data(&PrivacyExportCommand {
                            workshop_id: workshop,
                            user_id: subject.0,
                        })
                        .await
                        .map_err(DriverError::integration)?,
                );
            }
            "paperless" => {
                let client = PaperlessClient::new(&base_url, token, Duration::from_secs(120))
                    .map_err(DriverError::internal)?;
                paperless = Some(
                    client
                        .export_personal_data(&subject.1, workshop, subject.0)
                        .await
                        .map_err(DriverError::integration)?,
                );
            }
            _ => return Err(DriverError::bad("unsupported processor service")),
        }
    }
    let odoo = odoo.ok_or_else(|| {
        DriverError(
            StatusCode::NOT_FOUND,
            "Odoo processor service not found".into(),
        )
    })?;
    let result = json!({
        "format":"mb-processor-subject-export-v1",
        "request_id":request_id,"workshop_id":workshop,"user_id":subject.0,
        "odoo":odoo,"paperless":paperless
    });
    if serde_json::to_vec(&result)
        .map_err(DriverError::internal)?
        .len()
        > crate::privacy_crypto::MAX_EXPORT_BYTES - 1024 * 1024
    {
        return Err(DriverError(
            StatusCode::PAYLOAD_TOO_LARGE,
            "processor export exceeds the secure export limit".into(),
        ));
    }
    Ok(Json(result))
}
