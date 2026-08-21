use std::time::Duration;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::domain::IntegrationError;
use crate::integrations::cloudflare::{CloudflareCustomHostnameClient, CustomHostnameObservation};
use crate::integrations::odoo::{OdooClient, WebshopDomainCommand};
use crate::persistence::{LeasedOperation, Store};

fn client() -> Result<CloudflareCustomHostnameClient, IntegrationError> {
    let token = crate::runtime_secret::required("CONTROL_CLOUDFLARE_API_TOKEN")
        .map_err(|_| IntegrationError::ContractDrift)?;
    let zone_id = crate::runtime_secret::required_configuration("CONTROL_CLOUDFLARE_ZONE_ID")
        .map_err(|_| IntegrationError::ContractDrift)?;
    CloudflareCustomHostnameClient::new(token, zone_id, Duration::from_secs(20))
}

fn certificate_state(status: &str) -> &'static str {
    match status {
        "active" | "staging_active" | "backup_issued" => "active",
        "expired" | "pending_expiration" => "expired",
        value if value.ends_with("_timed_out") || matches!(value, "inactive" | "deleted") => {
            "failed"
        }
        "initializing" | "pending_validation" => "pending",
        _ => "provisioning",
    }
}

async fn record_observation(
    store: &Store,
    operation: &LeasedOperation,
    domain_id: Uuid,
    observation: &CustomHostnameObservation,
) -> Result<bool, IntegrationError> {
    let hostname_ready = matches!(
        observation.hostname_status.as_str(),
        "active" | "active_redeploying" | "provisioned" | "test_active" | "test_active_apex"
    );
    let certificate = certificate_state(&observation.certificate_status);
    let ready = hostname_ready && certificate == "active";
    let records = observation
        .validation_records
        .iter()
        .map(|record| json!({"type":record.record_type,"name":record.name,"value":record.value}))
        .collect::<Vec<_>>();
    let next_state = if ready {
        "testing"
    } else if observation.error_class.is_some() || certificate == "failed" {
        "action_required"
    } else if hostname_ready {
        "certificate_pending"
    } else {
        "dns_pending"
    };
    sqlx::query(
        "update control.webshop_domains
            set provider_ref=$3,state=$4,dns_state=case when $5 then 'verified' else 'pending' end,
                certificate_state=$6,edge_verification_records=$7,
                dns_observed_at=case when $5 then now() else dns_observed_at end,
                certificate_observed_at=case when $6='active' then now() else certificate_observed_at end,
                last_health_checked_at=now(),last_error_class=$8,updated_at=now(),version=version+1
          where id=$1 and workshop_id=$2 and operation_id=$9 and desired_state='active'",
    )
    .bind(domain_id)
    .bind(operation.workshop_id.ok_or(IntegrationError::ContractDrift)?)
    .bind(&observation.provider_ref)
    .bind(next_state)
    .bind(hostname_ready)
    .bind(certificate)
    .bind(Value::Array(records))
    .bind(&observation.error_class)
    .bind(operation.id)
    .execute(store.pool())
    .await
    .map_err(|_| IntegrationError::Unavailable)?;
    Ok(ready)
}

pub(crate) async fn run(
    store: &Store,
    operation: &LeasedOperation,
) -> Result<(), IntegrationError> {
    let workshop = operation
        .workshop_id
        .ok_or(IntegrationError::ContractDrift)?;
    let domain_id = operation
        .payload
        .get("domain_id")
        .and_then(Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok())
        .ok_or(IntegrationError::ContractDrift)?;
    let row = sqlx::query_as::<
        _,
        (
            String,
            Option<String>,
            Option<time::OffsetDateTime>,
            String,
            bool,
        ),
    >(
        "select hostname,provider_ref,ownership_verified_at,desired_state,canonical
           from control.webshop_domains where id=$1 and workshop_id=$2 and operation_id=$3",
    )
    .bind(domain_id)
    .bind(workshop)
    .bind(operation.id)
    .fetch_optional(store.pool())
    .await
    .map_err(|_| IntegrationError::Unavailable)?
    .ok_or(IntegrationError::NotFound)?;
    if row.3 == "disconnected" {
        let tenant = sqlx::query_as::<_, (Uuid, String, String, String, bool)>(
            "select d.id,w.slug,d.database_ref,d.public_hostname,
                    exists(select 1 from control.workshop_modules where workshop_id=w.id and module_key='documents' and state='enabled')
               from control.workshops w join control.odoo_databases d on d.workshop_id=w.id
              where w.id=$1 and d.kind='primary' and d.deleted_at is null",
        )
        .bind(workshop)
        .fetch_one(store.pool())
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
        let payload = json!({
            "database_id":tenant.0,"database_ref":tenant.2,"public_hostname":tenant.3,
            "paperless_hostname":format!("docs-{}.{}",tenant.1,crate::worker::configuration("CONTROL_TENANT_DOMAIN")?),
            "paperless_enabled":tenant.4,
            "custom_hostnames":crate::worker::routable_custom_hostnames(store,workshop)
                .await.map_err(|_| IntegrationError::Unavailable)?
        });
        let route_digest = format!(
            "{:x}",
            Sha256::digest(
                serde_json::to_vec(&payload).map_err(|_| IntegrationError::ContractDrift)?
            )
        );
        crate::worker::driver_request_with_key(
            operation.id,
            workshop,
            "reconcile",
            &format!("webshop-domain-disconnect-route:{domain_id}:{route_digest}"),
            &payload,
        )
        .await?;
        if operation
            .payload
            .get("restore_platform_canonical")
            .and_then(Value::as_bool)
            == Some(true)
        {
            let (url, secret_ref, database_ref) =
                crate::worker::service(store, workshop, "odoo").await?;
            OdooClient::new(
                &url,
                &crate::worker::secret(&secret_ref)?,
                database_ref.as_deref(),
                Duration::from_secs(20),
            )
            .map_err(|_| IntegrationError::ContractDrift)?
            .project_webshop_domain(&WebshopDomainCommand {
                operation_key: format!("webshop-domain:{domain_id}:restore-platform"),
                workshop_id: workshop,
                hostname: tenant.3,
            })
            .await?;
        }
        if let Some(reference) = row.1.as_deref() {
            client()?.delete(reference).await?;
        }
        sqlx::query(
            "update control.webshop_domains
                set state='disconnected',disconnected_at=now(),provider_ref=null,
                    certificate_state='pending',edge_verification_records='[]'::jsonb,
                    redirect_target=null,
                    last_error_class=null,last_health_checked_at=now(),updated_at=now(),version=version+1
              where id=$1 and workshop_id=$2 and operation_id=$3 and desired_state='disconnected'",
        )
        .bind(domain_id)
        .bind(workshop)
        .bind(operation.id)
        .execute(store.pool())
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
        return Ok(());
    }
    if row.2.is_none() || row.3 != "active" {
        return Err(IntegrationError::ContractDrift);
    }
    let client = match client() {
        Ok(client) => client,
        Err(error) => {
            sqlx::query("update control.webshop_domains set state='action_required',last_error_class='edge_provider_not_configured',last_health_checked_at=now(),updated_at=now(),version=version+1 where id=$1 and operation_id=$2")
                .bind(domain_id).bind(operation.id).execute(store.pool()).await
                .map_err(|_| IntegrationError::Unavailable)?;
            return Err(error);
        }
    };
    let observation = match row.1 {
        Some(reference) => client.observe(&reference).await,
        None => match client.find(&row.0).await {
            Ok(Some(observation)) => Ok(observation),
            Ok(None) => client.create(&row.0, workshop, domain_id).await,
            Err(error) => Err(error),
        },
    };
    let observation = match observation {
        Ok(observation) if observation.hostname == row.0 => observation,
        Ok(_) => return Err(IntegrationError::ContractDrift),
        Err(error) if !error.retryable() => {
            sqlx::query("update control.webshop_domains set state='action_required',last_error_class=$3,last_health_checked_at=now(),updated_at=now(),version=version+1 where id=$1 and operation_id=$2")
                .bind(domain_id).bind(operation.id).bind(error.failure_class())
                .execute(store.pool()).await.map_err(|_| IntegrationError::Unavailable)?;
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    if !record_observation(store, operation, domain_id, &observation).await? {
        return Ok(());
    }

    let tenant = sqlx::query_as::<_, (Uuid, String, String, String, bool)>(
        "select d.id,w.slug,d.database_ref,d.public_hostname,
                exists(select 1 from control.workshop_modules where workshop_id=w.id and module_key='documents' and state='enabled')
           from control.workshops w join control.odoo_databases d on d.workshop_id=w.id
          where w.id=$1 and d.kind='primary' and d.deleted_at is null",
    )
    .bind(workshop)
    .fetch_one(store.pool())
    .await
    .map_err(|_| IntegrationError::Unavailable)?;
    let payload = json!({
        "database_id":tenant.0,"database_ref":tenant.2,"public_hostname":tenant.3,
        "paperless_hostname":format!("docs-{}.{}",tenant.1,crate::worker::configuration("CONTROL_TENANT_DOMAIN")?),
        "paperless_enabled":tenant.4,
        "custom_hostnames":crate::worker::routable_custom_hostnames(store,workshop)
            .await.map_err(|_| IntegrationError::Unavailable)?
    });
    let route_digest = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&payload).map_err(|_| IntegrationError::ContractDrift)?)
    );
    crate::worker::driver_request_with_key(
        operation.id,
        workshop,
        "reconcile",
        &format!("webshop-domain-route:{domain_id}:{route_digest}"),
        &payload,
    )
    .await?;
    if row.4 {
        let (url, secret_ref, database_ref) =
            crate::worker::service(store, workshop, "odoo").await?;
        OdooClient::new(
            &url,
            &crate::worker::secret(&secret_ref)?,
            database_ref.as_deref(),
            Duration::from_secs(20),
        )
        .map_err(|_| IntegrationError::ContractDrift)?
        .project_webshop_domain(&WebshopDomainCommand {
            operation_key: format!("webshop-domain:{domain_id}:{}", observation.provider_ref),
            workshop_id: workshop,
            hostname: row.0.clone(),
        })
        .await?;
    }
    sqlx::query("update control.webshop_domains set state='active',last_error_class=null,last_health_checked_at=now(),updated_at=now(),version=version+1 where id=$1 and operation_id=$2 and state='testing'")
        .bind(domain_id).bind(operation.id).execute(store.pool()).await
        .map_err(|_| IntegrationError::Unavailable)?;
    Ok(())
}

pub(crate) async fn failed(store: &Store, operation: &LeasedOperation) {
    let Some(workshop) = operation.workshop_id else {
        return;
    };
    let Some(domain_id) = operation
        .payload
        .get("domain_id")
        .and_then(Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok())
    else {
        return;
    };
    if let Err(error) = sqlx::query(
        "update control.webshop_domains
            set state='action_required',last_error_class='reconciliation_failed',
                last_health_checked_at=now(),updated_at=now(),version=version+1
          where id=$1 and workshop_id=$2 and operation_id=$3 and state<>'disconnected'",
    )
    .bind(domain_id)
    .bind(workshop)
    .bind(operation.id)
    .execute(store.pool())
    .await
    {
        tracing::error!(operation=%operation.id,error=%error,"could not mark webshop domain reconciliation failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_certificate_states_are_fail_closed() {
        assert_eq!(certificate_state("active"), "active");
        assert_eq!(certificate_state("pending_issuance"), "provisioning");
        assert_eq!(certificate_state("validation_timed_out"), "failed");
        assert_eq!(certificate_state("expired"), "expired");
    }
}
