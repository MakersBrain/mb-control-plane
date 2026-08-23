use std::time::Duration;

use crate::domain::IntegrationError;
use crate::integrations::odoo::{OdooClient, WebshopStatusCommand};
use crate::persistence::{LeasedOperation, Store, lock_current_operation_lease};

pub(crate) async fn run(
    store: &Store,
    operation: &LeasedOperation,
) -> Result<(), IntegrationError> {
    let workshop = operation
        .workshop_id
        .ok_or(IntegrationError::ContractDrift)?;
    let current = sqlx::query_scalar::<_, bool>(
        "select exists(select 1 from control.webshop_onboarding
          where workshop_id=$1 and operation_id=$2 and state in ('in_progress','action_required','ready','completed'))",
    )
    .bind(workshop)
    .bind(operation.id)
    .fetch_one(store.pool())
    .await
    .map_err(|_| IntegrationError::Unavailable)?;
    if !current {
        return Err(IntegrationError::ContractDrift);
    }
    let (url, secret_ref, database_ref) = crate::worker::service(store, workshop, "odoo").await?;
    let observed = OdooClient::new(
        &url,
        &crate::worker::secret(&secret_ref)?,
        database_ref.as_deref(),
        Duration::from_secs(20),
    )
    .map_err(|_| IntegrationError::ContractDrift)?
    .webshop_status(&WebshopStatusCommand {
        workshop_id: workshop,
    })
    .await?;
    let ready = observed.readiness.launch_ready;
    let readiness =
        serde_json::to_value(observed.readiness).map_err(|_| IntegrationError::ContractDrift)?;
    let issues =
        serde_json::to_value(observed.issues).map_err(|_| IntegrationError::ContractDrift)?;
    let changed = sqlx::query(
        "update control.webshop_onboarding
            set observation=$3,odoo_issues=$4,
                state=case when state='completed' and $5 then 'completed'
                           when $5 then 'ready' else 'action_required' end,
                completed_at=case when state='completed' and $5 then completed_at else null end,
                last_error_class=null,last_checked_at=now(),updated_at=now(),version=version+1
          where workshop_id=$1 and operation_id=$2",
    )
    .bind(workshop)
    .bind(operation.id)
    .bind(readiness)
    .bind(issues)
    .bind(ready)
    .execute(store.pool())
    .await
    .map_err(|_| IntegrationError::Unavailable)?
    .rows_affected();
    if changed != 1 {
        return Err(IntegrationError::ContractDrift);
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
        "update control.webshop_onboarding
            set state=case when state='completed' then 'completed' else 'action_required' end,
                last_error_class='readiness_unavailable',
                updated_at=now(),version=version+1
          where workshop_id=$1 and operation_id=$2",
    )
    .bind(workshop)
    .bind(operation.id)
    .execute(&mut *tx)
    .await
    .map_err(|_| IntegrationError::Unavailable)?
    .rows_affected();
    if changed != 1 {
        return Err(IntegrationError::ContractDrift);
    }
    tx.commit().await.map_err(|_| IntegrationError::Unavailable)
}
