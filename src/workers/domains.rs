use std::time::Duration;

use async_trait::async_trait;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tracing::field;
use uuid::Uuid;

use crate::domain::IntegrationError;
use crate::integrations::cloudflare::{
    CloudflareCustomHostnameClient, CustomHostnameDeletionObservation, CustomHostnameObservation,
};
use crate::integrations::odoo::{OdooClient, WebshopDomainCommand};
use crate::persistence::{LeasedOperation, TenantStore, WorkshopTransaction};
use crate::worker_config::DeploymentDriverConfig;

use super::routes::{RouteProjection, ServiceConnection};

#[async_trait]
trait CustomHostnameProvider: Sync {
    async fn create(
        &self,
        hostname: &str,
        workshop: Uuid,
        domain_id: Uuid,
    ) -> Result<CustomHostnameObservation, IntegrationError>;
    async fn find(
        &self,
        hostname: &str,
    ) -> Result<Option<CustomHostnameObservation>, IntegrationError>;
    async fn observe(
        &self,
        provider_ref: &str,
    ) -> Result<CustomHostnameObservation, IntegrationError>;
    async fn observe_deletion(
        &self,
        provider_ref: &str,
    ) -> Result<CustomHostnameDeletionObservation, IntegrationError>;
    async fn delete(&self, provider_ref: &str) -> Result<(), IntegrationError>;
}

#[async_trait]
impl CustomHostnameProvider for CloudflareCustomHostnameClient {
    async fn create(
        &self,
        hostname: &str,
        workshop: Uuid,
        domain_id: Uuid,
    ) -> Result<CustomHostnameObservation, IntegrationError> {
        self.create(hostname, workshop, domain_id).await
    }

    async fn find(
        &self,
        hostname: &str,
    ) -> Result<Option<CustomHostnameObservation>, IntegrationError> {
        self.find(hostname).await
    }

    async fn observe(
        &self,
        provider_ref: &str,
    ) -> Result<CustomHostnameObservation, IntegrationError> {
        self.observe(provider_ref).await
    }

    async fn observe_deletion(
        &self,
        provider_ref: &str,
    ) -> Result<CustomHostnameDeletionObservation, IntegrationError> {
        self.observe_deletion(provider_ref).await
    }

    async fn delete(&self, provider_ref: &str) -> Result<(), IntegrationError> {
        self.delete(provider_ref).await
    }
}

#[derive(Clone, Copy)]
enum DomainAction {
    Activate,
    Disconnect,
}

impl DomainAction {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Activate => "activate",
            Self::Disconnect => "disconnect",
        }
    }
}

struct DomainSnapshot {
    id: Uuid,
    hostname: String,
    provider_ref: Option<String>,
    action: DomainAction,
    route: Option<RouteProjection>,
}

struct ProviderDeletionAdvance {
    state: String,
    dispatch_authorized: bool,
}

async fn advance_provider_deletion(
    tenant_store: &TenantStore,
    workshop: Uuid,
    operation: &LeasedOperation,
    snapshot: &DomainSnapshot,
    provider_ref: &str,
    action: &str,
) -> Result<ProviderDeletionAdvance, IntegrationError> {
    let mut tx = tenant_store
        .begin(workshop)
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
    let row = sqlx::query_as::<_, (String, i32, i32, bool)>(
        "select deletion_state,observation_count,delete_dispatch_count,dispatch_authorized
         from control.advance_webshop_domain_provider_deletion(
             $1,$2,$3,$4,$5,$6,$7,$8
         )",
    )
    .bind(operation.id)
    .bind(operation.attempt)
    .bind(&operation.leased_by)
    .bind(workshop)
    .bind(snapshot.id)
    .bind(provider_ref)
    .bind(&snapshot.hostname)
    .bind(action)
    .fetch_one(&mut *tx)
    .await
    .map_err(|error| {
        if matches!(
            error
                .as_database_error()
                .and_then(|error| error.code())
                .as_deref(),
            Some("40001")
        ) {
            IntegrationError::UnknownOutcome
        } else {
            IntegrationError::Unavailable
        }
    })?;
    tx.commit()
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
    Ok(ProviderDeletionAdvance {
        state: row.0,
        dispatch_authorized: row.3,
    })
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

async fn lock_current_operation(
    tx: &mut WorkshopTransaction<'_>,
    operation: &LeasedOperation,
) -> Result<(), IntegrationError> {
    super::routes::lock_authority(tx, operation).await
}

async fn route_snapshot(
    tx: &mut WorkshopTransaction<'_>,
    operation: &LeasedOperation,
    tenant_domain: &str,
    project_to_odoo: bool,
) -> Result<RouteProjection, IntegrationError> {
    super::routes::materialize(tx, operation, tenant_domain, project_to_odoo).await
}

async fn load_snapshot(
    tenant_store: &TenantStore,
    workshop: Uuid,
    operation: &LeasedOperation,
    domain_id: Uuid,
    tenant_domain: &str,
) -> Result<DomainSnapshot, IntegrationError> {
    let mut tx = tenant_store
        .begin_repeatable_read(workshop)
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
    lock_current_operation(&mut tx, operation).await?;
    // The shared authority helper locks operation -> route head before the
    // domain source row below.
    let row = sqlx::query_as::<_, (String, Option<String>, Option<time::OffsetDateTime>, String)>(
        "select hostname,provider_ref,ownership_verified_at,desired_state
         from control.webshop_domains
         where id=$1 and workshop_id=$2 and operation_id=$3
         for update",
    )
    .bind(domain_id)
    .bind(workshop)
    .bind(operation.id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| IntegrationError::Unavailable)?
    .ok_or(IntegrationError::NotFound)?;
    let action = if row.3 == "disconnected" {
        DomainAction::Disconnect
    } else if row.2.is_some() && row.3 == "active" {
        DomainAction::Activate
    } else {
        return Err(IntegrationError::ContractDrift);
    };
    let route = if matches!(action, DomainAction::Disconnect) {
        Some(
            route_snapshot(
                &mut tx,
                operation,
                tenant_domain,
                operation
                    .payload
                    .get("restore_platform_canonical")
                    .and_then(Value::as_bool)
                    == Some(true),
            )
            .await?,
        )
    } else {
        None
    };
    tx.commit()
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
    Ok(DomainSnapshot {
        id: domain_id,
        hostname: row.0,
        provider_ref: row.1,
        action,
        route,
    })
}

async fn record_observation(
    tenant_store: &TenantStore,
    workshop: Uuid,
    operation: &LeasedOperation,
    snapshot: &DomainSnapshot,
    observation: &CustomHostnameObservation,
    tenant_domain: &str,
) -> Result<Option<RouteProjection>, IntegrationError> {
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
    let mut tx = tenant_store
        .begin_repeatable_read(workshop)
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
    lock_current_operation(&mut tx, operation).await?;
    let canonical = sqlx::query_scalar::<_, bool>(
        "update control.webshop_domains
         set provider_ref=$4,state=$5,
             dns_state=case when $6 then 'verified' else 'pending' end,
             certificate_state=$7,edge_verification_records=$8,
             dns_observed_at=case when $6 then now() else dns_observed_at end,
             certificate_observed_at=case when $7='active' then now() else certificate_observed_at end,
             last_health_checked_at=now(),last_error_class=$9,updated_at=now(),version=version+1
         where id=$1 and workshop_id=$2 and operation_id=$3 and desired_state='active'
         returning canonical",
    )
    .bind(snapshot.id)
    .bind(workshop)
    .bind(operation.id)
    .bind(&observation.provider_ref)
    .bind(next_state)
    .bind(hostname_ready)
    .bind(certificate)
    .bind(Value::Array(records))
    .bind(&observation.error_class)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| IntegrationError::Unavailable)?
    .ok_or(IntegrationError::UnknownOutcome)?;
    let route = if ready {
        Some(route_snapshot(&mut tx, operation, tenant_domain, canonical).await?)
    } else {
        None
    };
    tx.commit()
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
    Ok(route)
}

async fn record_action_required(
    tenant_store: &TenantStore,
    workshop: Uuid,
    operation: &LeasedOperation,
    domain_id: Uuid,
    failure_class: &str,
) -> Result<(), IntegrationError> {
    let mut tx = tenant_store
        .begin(workshop)
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
    lock_current_operation(&mut tx, operation).await?;
    let changed = sqlx::query(
        "update control.webshop_domains
         set state='action_required',last_error_class=$4,last_health_checked_at=now(),
             updated_at=now(),version=version+1
         where id=$1 and workshop_id=$2 and operation_id=$3 and state<>'disconnected'",
    )
    .bind(domain_id)
    .bind(workshop)
    .bind(operation.id)
    .bind(failure_class)
    .execute(&mut *tx)
    .await
    .map_err(|_| IntegrationError::Unavailable)?
    .rows_affected();
    if changed != 1 {
        return Err(IntegrationError::UnknownOutcome);
    }
    tx.commit().await.map_err(|_| IntegrationError::Unavailable)
}

async fn finalize(
    tenant_store: &TenantStore,
    workshop: Uuid,
    operation: &LeasedOperation,
    domain_id: Uuid,
    action: DomainAction,
) -> Result<(), IntegrationError> {
    let mut tx = tenant_store
        .begin(workshop)
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
    lock_current_operation(&mut tx, operation).await?;
    let changed = match action {
        DomainAction::Activate => sqlx::query(
            "update control.webshop_domains
             set state='active',last_error_class=null,last_health_checked_at=now(),
                 updated_at=now(),version=version+1
             where id=$1 and workshop_id=$2 and operation_id=$3 and state='testing'",
        ),
        DomainAction::Disconnect => sqlx::query(
            "update control.webshop_domains
             set state='disconnected',disconnected_at=now(),provider_ref=null,
                 certificate_state='pending',edge_verification_records='[]'::jsonb,
                 redirect_target=null,last_error_class=null,last_health_checked_at=now(),
                 updated_at=now(),version=version+1
             where id=$1 and workshop_id=$2 and operation_id=$3
               and desired_state='disconnected'",
        ),
    }
    .bind(domain_id)
    .bind(workshop)
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

async fn project_odoo(
    workshop: Uuid,
    domain_id: Uuid,
    hostname: String,
    provider_ref: &str,
    service: ServiceConnection,
) -> Result<(), IntegrationError> {
    let projection_digest = format!(
        "{:x}",
        Sha256::digest(format!("{hostname}\0{provider_ref}").as_bytes())
    );
    OdooClient::new(
        &service.0,
        &crate::worker::secret(&service.1)?,
        service.2.as_deref(),
        Duration::from_secs(20),
    )
    .map_err(|_| IntegrationError::ContractDrift)?
    .project_webshop_domain(&WebshopDomainCommand {
        operation_key: format!("webshop-domain:{domain_id}:{projection_digest}"),
        workshop_id: workshop,
        hostname,
    })
    .await
    .map(|_| ())
}

fn confirm_route_application(
    response: &Value,
    workshop: Uuid,
    route: &RouteProjection,
) -> Result<(), IntegrationError> {
    super::routes::confirm_application(response, workshop, route)
}

async fn reconcile<P: CustomHostnameProvider>(
    tenant_store: &TenantStore,
    workshop: Uuid,
    operation: &LeasedOperation,
    tenant_domain: &str,
    deployment_driver: &DeploymentDriverConfig,
    provider: &P,
) -> Result<(), IntegrationError> {
    let domain_id = operation
        .payload
        .get("domain_id")
        .and_then(Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok())
        .ok_or(IntegrationError::ContractDrift)?;
    tracing::Span::current().record("domain_id", field::display(domain_id));
    let snapshot =
        load_snapshot(tenant_store, workshop, operation, domain_id, tenant_domain).await?;
    tracing::Span::current().record("domain_action", snapshot.action.as_str());

    match snapshot.action {
        DomainAction::Disconnect => {
            tracing::Span::current().record("phase", "route");
            let route = snapshot
                .route
                .as_ref()
                .ok_or(IntegrationError::ContractDrift)?;
            tracing::Span::current().record("route_generation", route.generation);
            let route_response = crate::worker::driver_request_with_key(
                operation,
                workshop,
                "route-project",
                &format!(
                    "webshop-domain-disconnect-route:{domain_id}:{}:{}",
                    route.generation, route.projection_digest
                ),
                &route.payload,
                deployment_driver,
            )
            .await?;
            confirm_route_application(&route_response, workshop, route)?;
            if let Some(service) = route.odoo.clone() {
                tracing::Span::current().record("phase", "odoo");
                let platform_hostname = route
                    .payload
                    .get("public_hostname")
                    .and_then(Value::as_str)
                    .ok_or(IntegrationError::ContractDrift)?
                    .to_owned();
                project_odoo(
                    workshop,
                    domain_id,
                    platform_hostname,
                    "restore-platform",
                    service,
                )
                .await?;
            }
            if let Some(reference) = snapshot.provider_ref.as_deref() {
                tracing::Span::current().record("phase", "provider.delete.begin");
                let intent = advance_provider_deletion(
                    tenant_store,
                    workshop,
                    operation,
                    &snapshot,
                    reference,
                    "begin",
                )
                .await?;
                if intent.state == "budget_exhausted" {
                    tracing::Span::current()
                        .record("provider_deletion_outcome", "budget_exhausted");
                    record_action_required(
                        tenant_store,
                        workshop,
                        operation,
                        snapshot.id,
                        "provider_deletion_budget_exhausted",
                    )
                    .await?;
                    return Ok(());
                }
                if intent.state == "absence_confirmed" {
                    tracing::Span::current()
                        .record("provider_deletion_outcome", "absence_replayed");
                } else {
                    tracing::Span::current().record("phase", "provider.delete.observe_before");
                    let before = provider.observe_deletion(reference).await?;
                    match before {
                        CustomHostnameDeletionObservation::Absent => {
                            let recorded = advance_provider_deletion(
                                tenant_store,
                                workshop,
                                operation,
                                &snapshot,
                                reference,
                                "observe_absent",
                            )
                            .await?;
                            if recorded.state != "absence_confirmed" {
                                return Err(IntegrationError::UnknownOutcome);
                            }
                            tracing::Span::current()
                                .record("provider_deletion_outcome", "absence_confirmed");
                        }
                        CustomHostnameDeletionObservation::Present(observation) => {
                            if observation.provider_ref != reference
                                || observation.hostname != snapshot.hostname
                            {
                                return Err(IntegrationError::ContractDrift);
                            }
                            let observed = advance_provider_deletion(
                                tenant_store,
                                workshop,
                                operation,
                                &snapshot,
                                reference,
                                "observe_present",
                            )
                            .await?;
                            if observed.state == "budget_exhausted" {
                                tracing::Span::current()
                                    .record("provider_deletion_outcome", "budget_exhausted");
                                record_action_required(
                                    tenant_store,
                                    workshop,
                                    operation,
                                    snapshot.id,
                                    "provider_deletion_budget_exhausted",
                                )
                                .await?;
                                return Ok(());
                            }
                            let dispatched = advance_provider_deletion(
                                tenant_store,
                                workshop,
                                operation,
                                &snapshot,
                                reference,
                                "dispatch_delete",
                            )
                            .await?;
                            if dispatched.state == "budget_exhausted" {
                                tracing::Span::current()
                                    .record("provider_deletion_outcome", "budget_exhausted");
                                record_action_required(
                                    tenant_store,
                                    workshop,
                                    operation,
                                    snapshot.id,
                                    "provider_deletion_budget_exhausted",
                                )
                                .await?;
                                return Ok(());
                            }
                            if !dispatched.dispatch_authorized {
                                // This exact attempt already dispatched or lost the
                                // atomic claim. A later admitted observation may
                                // continue, but this execution must not send twice.
                                tracing::Span::current()
                                    .record("provider_deletion_outcome", "observation_pending");
                                return Ok(());
                            }
                            tracing::Span::current().record("phase", "provider.delete.dispatch");
                            match provider.delete(reference).await {
                                Ok(()) => {}
                                Err(IntegrationError::UnknownOutcome) => {
                                    // The dispatch claim is durable. Complete this
                                    // bounded observation cycle without claiming
                                    // provider absence; periodic admission will
                                    // create a new fenced observer.
                                    tracing::Span::current()
                                        .record("provider_deletion_outcome", "ambiguous_persisted");
                                    return Ok(());
                                }
                                Err(error) => return Err(error),
                            }
                            tracing::Span::current()
                                .record("phase", "provider.delete.observe_after");
                            match provider.observe_deletion(reference).await? {
                                CustomHostnameDeletionObservation::Absent => {
                                    let recorded = advance_provider_deletion(
                                        tenant_store,
                                        workshop,
                                        operation,
                                        &snapshot,
                                        reference,
                                        "observe_absent",
                                    )
                                    .await?;
                                    if recorded.state != "absence_confirmed" {
                                        return Err(IntegrationError::UnknownOutcome);
                                    }
                                    tracing::Span::current()
                                        .record("provider_deletion_outcome", "absence_confirmed");
                                }
                                CustomHostnameDeletionObservation::Present(observation)
                                    if observation.provider_ref == reference
                                        && observation.hostname == snapshot.hostname =>
                                {
                                    let recorded = advance_provider_deletion(
                                        tenant_store,
                                        workshop,
                                        operation,
                                        &snapshot,
                                        reference,
                                        "observe_present",
                                    )
                                    .await?;
                                    if recorded.state == "budget_exhausted" {
                                        tracing::Span::current().record(
                                            "provider_deletion_outcome",
                                            "budget_exhausted",
                                        );
                                        record_action_required(
                                            tenant_store,
                                            workshop,
                                            operation,
                                            snapshot.id,
                                            "provider_deletion_budget_exhausted",
                                        )
                                        .await?;
                                        return Ok(());
                                    }
                                    tracing::Span::current()
                                        .record("provider_deletion_outcome", "still_present");
                                    return Ok(());
                                }
                                CustomHostnameDeletionObservation::Present(_) => {
                                    return Err(IntegrationError::ContractDrift);
                                }
                            }
                        }
                    }
                }
            }
            tracing::Span::current().record("phase", "finalize");
            finalize(
                tenant_store,
                workshop,
                operation,
                domain_id,
                DomainAction::Disconnect,
            )
            .await
        }
        DomainAction::Activate => {
            tracing::Span::current().record("phase", "provider.observe");
            let observation = match snapshot.provider_ref.as_deref() {
                Some(reference) => provider.observe(reference).await,
                None => match provider.find(&snapshot.hostname).await {
                    Ok(Some(observation)) => Ok(observation),
                    Ok(None) => {
                        provider
                            .create(&snapshot.hostname, workshop, domain_id)
                            .await
                    }
                    Err(error) => Err(error),
                },
            };
            let observation = match observation {
                Ok(observation) if observation.hostname == snapshot.hostname => observation,
                Ok(_) => return Err(IntegrationError::ContractDrift),
                Err(error) if !error.retryable() => {
                    record_action_required(
                        tenant_store,
                        workshop,
                        operation,
                        domain_id,
                        error.failure_class(),
                    )
                    .await?;
                    return Ok(());
                }
                Err(error) => return Err(error),
            };
            let Some(route) = record_observation(
                tenant_store,
                workshop,
                operation,
                &snapshot,
                &observation,
                tenant_domain,
            )
            .await?
            else {
                return Ok(());
            };
            tracing::Span::current().record("phase", "route");
            tracing::Span::current().record("route_generation", route.generation);
            let route_response = crate::worker::driver_request_with_key(
                operation,
                workshop,
                "route-project",
                &format!(
                    "webshop-domain-route:{domain_id}:{}:{}",
                    route.generation, route.projection_digest
                ),
                &route.payload,
                deployment_driver,
            )
            .await?;
            confirm_route_application(&route_response, workshop, &route)?;
            if let Some(service) = route.odoo {
                tracing::Span::current().record("phase", "odoo");
                project_odoo(
                    workshop,
                    domain_id,
                    snapshot.hostname,
                    &observation.provider_ref,
                    service,
                )
                .await?;
            }
            tracing::Span::current().record("phase", "finalize");
            finalize(
                tenant_store,
                workshop,
                operation,
                domain_id,
                DomainAction::Activate,
            )
            .await
        }
    }
}

#[tracing::instrument(
    name = "worker.webshop_domain.reconcile",
    skip_all,
    fields(
        operation_id = %operation.id,
        operation_attempt = operation.attempt,
        workshop_id = %workshop,
        domain_id = field::Empty,
        domain_action = field::Empty,
        phase = "load",
        route_generation = field::Empty,
        provider_deletion_outcome = field::Empty,
        outcome = field::Empty,
        error_class = field::Empty
    )
)]
pub(crate) async fn run(
    tenant_store: &TenantStore,
    workshop: Uuid,
    operation: &LeasedOperation,
    tenant_domain: &str,
    deployment_driver: &DeploymentDriverConfig,
    provider: &CloudflareCustomHostnameClient,
) -> Result<(), IntegrationError> {
    let result = reconcile(
        tenant_store,
        workshop,
        operation,
        tenant_domain,
        deployment_driver,
        provider,
    )
    .await;
    match &result {
        Ok(()) => {
            tracing::Span::current().record("outcome", "succeeded");
        }
        Err(error) => {
            tracing::Span::current().record(
                "outcome",
                if matches!(error, IntegrationError::UnknownOutcome) {
                    "unknown"
                } else if error.retryable() {
                    "retryable"
                } else {
                    "terminal"
                },
            );
            tracing::Span::current().record("error_class", error.failure_class());
        }
    }
    result
}

#[tracing::instrument(
    name = "worker.webshop_domain.fail",
    skip_all,
    fields(
        operation_id = %operation.id,
        operation_attempt = operation.attempt,
        workshop_id = %workshop,
        outcome = field::Empty
    )
)]
pub(crate) async fn failed(
    tenant_store: &TenantStore,
    workshop: Uuid,
    operation: &LeasedOperation,
) -> Result<(), IntegrationError> {
    let Some(domain_id) = operation
        .payload
        .get("domain_id")
        .and_then(Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok())
    else {
        tracing::Span::current().record("outcome", "invalid_contract");
        return Err(IntegrationError::ContractDrift);
    };
    match record_action_required(
        tenant_store,
        workshop,
        operation,
        domain_id,
        "reconciliation_failed",
    )
    .await
    {
        Ok(()) => {
            tracing::Span::current().record("outcome", "recorded");
            Ok(())
        }
        Err(error) => {
            tracing::Span::current().record("outcome", "fenced");
            tracing::error!(
                operation=%operation.id,
                error_class=crate::error_reporting::safe_error_class(&error),
                "could not mark webshop domain reconciliation failed"
            );
            Err(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route_fixture() -> RouteProjection {
        RouteProjection {
            payload: json!({}),
            generation: 3,
            projection_digest:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            disposition: "present",
            odoo: None,
        }
    }

    #[test]
    fn route_application_confirmation_requires_matching_durable_evidence() {
        let workshop = Uuid::new_v4();
        let route = route_fixture();
        let applied = json!({
            "outcome":"applied",
            "route_evidence":{
                "workshop_id":workshop,
                "route_generation":route.generation,
                "projection_digest":route.projection_digest,
                "disposition":"present",
                "rendered_digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "driver_operation_id":Uuid::new_v4(),
                "route_fence_token":2
            }
        });
        assert!(confirm_route_application(&applied, workshop, &route).is_ok());

        let mut mismatched = applied.clone();
        mismatched["route_evidence"]["route_generation"] = json!(route.generation + 1);
        assert_eq!(
            confirm_route_application(&mismatched, workshop, &route),
            Err(IntegrationError::UnknownOutcome)
        );
        let mut superseded = applied;
        superseded["outcome"] = json!("superseded");
        assert_eq!(
            confirm_route_application(&superseded, workshop, &route),
            Err(IntegrationError::Unavailable)
        );
    }

    #[test]
    fn provider_certificate_states_are_fail_closed() {
        assert_eq!(certificate_state("active"), "active");
        assert_eq!(certificate_state("pending_issuance"), "provisioning");
        assert_eq!(certificate_state("validation_timed_out"), "failed");
        assert_eq!(certificate_state("unknown_new_state"), "provisioning");
    }

    #[test]
    fn domain_execution_uses_only_the_transaction_scoped_capability() {
        let source = include_str!("domains.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        assert!(!source.contains("use crate::persistence::{LeasedOperation, Store"));
        assert!(!source.contains(".pool()"));
        assert!(source.contains("tenant_store: &TenantStore"));
        assert!(source.contains("tx: &mut WorkshopTransaction<'_>"));
        let routes = include_str!("routes.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        assert!(routes.contains("lease_expires_at>now()"));
        assert!(routes.contains("attempt=$3 and leased_by=$4"));
        assert!(source.contains("name = \"worker.webshop_domain.reconcile\""));
    }

    async fn leased_domain_operation(
        store: &crate::persistence::Store,
        workshop: Uuid,
        domain_id: Uuid,
        owner: &str,
    ) -> LeasedOperation {
        let id = Uuid::new_v4();
        sqlx::query(
            "insert into control.operations(
               id,kind,queue,workshop_id,payload,correlation_id,idempotency_key,
               state,attempt,leased_by,lease_expires_at
             ) values($1,'webshop-domain.reconcile','tenant-reconciliation',$2,$3,$4,$5,
                      'in_flight',1,$6,now()+interval '10 minutes')",
        )
        .bind(id)
        .bind(workshop)
        .bind(json!({"domain_id":domain_id,"reason":"test"}))
        .bind(Uuid::new_v4())
        .bind(format!("domain-capability:{id}"))
        .bind(owner)
        .execute(store.pool())
        .await
        .unwrap();
        LeasedOperation {
            id,
            kind: "webshop-domain.reconcile".into(),
            workshop_id: Some(workshop),
            target_user_id: None,
            desired_epoch: None,
            payload: json!({"domain_id":domain_id,"reason":"test"}),
            attempt: 1,
            max_attempts: 12,
            leased_by: owner.into(),
            reconciling: false,
            trace_parent: None,
            trace_state: None,
        }
    }

    async fn insert_domain_fixture(
        store: &crate::persistence::Store,
        workshop: Uuid,
        operation: Uuid,
        user: Uuid,
    ) -> Uuid {
        let domain = Uuid::new_v4();
        sqlx::query(
            "insert into control.webshop_domains(
               id,workshop_id,hostname,verification_name,verification_value,routing_target,
               state,desired_state,ownership_verified_at,operation_id,created_by
             ) values($1,$2,$3,$4,$5,'shops.example.test','dns_pending','active',now(),$6,$7)",
        )
        .bind(domain)
        .bind(workshop)
        .bind(format!("{}.example.test", domain.simple()))
        .bind(format!("_mb-challenge.{}.example.test", domain.simple()))
        .bind(format!(
            "mb-verification={}",
            &domain.simple().to_string()[..32]
        ))
        .bind(operation)
        .bind(user)
        .execute(store.pool())
        .await
        .unwrap();
        domain
    }

    #[tokio::test]
    #[ignore = "requires a disposable CONTROL_TEST_DATABASE_URL"]
    async fn tenant_snapshot_and_provider_results_are_fenced_to_the_exact_attempt() {
        let database_url =
            std::env::var("CONTROL_TEST_DATABASE_URL").expect("CONTROL_TEST_DATABASE_URL");
        let store = crate::persistence::Store::connect(&database_url)
            .await
            .unwrap();
        store.migrate().await.unwrap();
        let user = Uuid::new_v4();
        sqlx::query("insert into control.users(id,email) values($1,$2)")
            .bind(user)
            .bind(format!("domain-capability-{user}@example.test"))
            .execute(store.pool())
            .await
            .unwrap();
        let first = Uuid::new_v4();
        let second = Uuid::new_v4();
        for workshop in [first, second] {
            sqlx::query(
                "insert into control.workshops(id,slug,display_name,time_zone)
                 values($1,$2,'Domain capability','Europe/Paris')",
            )
            .bind(workshop)
            .bind(format!("domain-capability-{}", workshop.simple()))
            .execute(store.pool())
            .await
            .unwrap();
        }
        let placeholder = Uuid::new_v4();
        let first_operation = leased_domain_operation(&store, first, placeholder, "domain-a").await;
        let second_operation =
            leased_domain_operation(&store, second, placeholder, "domain-b").await;
        let first_domain = insert_domain_fixture(&store, first, first_operation.id, user).await;
        let second_domain = insert_domain_fixture(&store, second, second_operation.id, user).await;
        let first_operation = LeasedOperation {
            payload: json!({"domain_id":first_domain,"reason":"test"}),
            ..first_operation
        };
        let forged = LeasedOperation {
            id: first_operation.id,
            kind: first_operation.kind.clone(),
            workshop_id: first_operation.workshop_id,
            target_user_id: first_operation.target_user_id,
            desired_epoch: first_operation.desired_epoch,
            payload: json!({"domain_id":second_domain,"reason":"test"}),
            attempt: first_operation.attempt,
            max_attempts: first_operation.max_attempts,
            leased_by: first_operation.leased_by.clone(),
            reconciling: first_operation.reconciling,
            trace_parent: first_operation.trace_parent.clone(),
            trace_state: first_operation.trace_state.clone(),
        };
        let tenant_store = store.worker_tenant_scope();
        let forged_error =
            match load_snapshot(&tenant_store, first, &forged, second_domain, "example.test").await
            {
                Ok(_) => panic!("a cross-workshop domain snapshot was accepted"),
                Err(error) => error,
            };
        assert_eq!(forged_error, IntegrationError::NotFound);

        let snapshot = load_snapshot(
            &tenant_store,
            first,
            &first_operation,
            first_domain,
            "example.test",
        )
        .await
        .unwrap();
        let before = sqlx::query_as::<_, (String, i64, Option<String>)>(
            "select state,version,provider_ref from control.webshop_domains where id=$1",
        )
        .bind(first_domain)
        .fetch_one(store.pool())
        .await
        .unwrap();
        sqlx::query(
            "update control.operations
             set attempt=2,leased_by='domain-new-owner',lease_expires_at=now()+interval '10 minutes'
             where id=$1",
        )
        .bind(first_operation.id)
        .execute(store.pool())
        .await
        .unwrap();
        let observation = CustomHostnameObservation {
            provider_ref: "provider-reference".into(),
            hostname: snapshot.hostname.clone(),
            hostname_status: "active".into(),
            certificate_status: "active".into(),
            validation_records: Vec::new(),
            error_class: None,
        };
        let stale_observation = record_observation(
            &tenant_store,
            first,
            &first_operation,
            &snapshot,
            &observation,
            "example.test",
        )
        .await;
        assert!(matches!(
            stale_observation,
            Err(IntegrationError::UnknownOutcome)
        ));
        assert_eq!(
            record_action_required(
                &tenant_store,
                first,
                &first_operation,
                first_domain,
                "reconciliation_failed",
            )
            .await
            .unwrap_err(),
            IntegrationError::UnknownOutcome
        );
        let after = sqlx::query_as::<_, (String, i64, Option<String>)>(
            "select state,version,provider_ref from control.webshop_domains where id=$1",
        )
        .bind(first_domain)
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(after, before);
    }
}
