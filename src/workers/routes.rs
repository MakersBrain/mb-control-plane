use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::domain::IntegrationError;
use crate::persistence::{LeasedOperation, WorkshopTransaction};
use crate::worker_config::DeploymentDriverConfig;

pub(crate) type ServiceConnection = (String, String, Option<String>);

pub(crate) struct RouteProjection {
    pub(crate) payload: Value,
    pub(crate) generation: i64,
    pub(crate) projection_digest: String,
    pub(crate) disposition: &'static str,
    pub(crate) odoo: Option<ServiceConnection>,
}

pub(crate) async fn lock_current_operation(
    tx: &mut WorkshopTransaction<'_>,
    operation: &LeasedOperation,
) -> Result<(), IntegrationError> {
    let current = sqlx::query_scalar::<_, Uuid>(
        "select id from control.operations
         where id=$1 and workshop_id=$2 and state='in_flight'
           and attempt=$3 and leased_by=$4 and lease_expires_at>now()
         for update",
    )
    .bind(operation.id)
    .bind(tx.workshop_id())
    .bind(operation.attempt)
    .bind(&operation.leased_by)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| IntegrationError::Unavailable)?;
    if current.is_none() {
        return Err(IntegrationError::UnknownOutcome);
    }
    Ok(())
}

pub(crate) async fn lock_authority(
    tx: &mut WorkshopTransaction<'_>,
    operation: &LeasedOperation,
) -> Result<(), IntegrationError> {
    lock_current_operation(tx, operation).await?;
    match sqlx::query_scalar::<_, i64>("select control.lock_workshop_route_projection($1,$2,$3,$4)")
        .bind(operation.id)
        .bind(operation.attempt)
        .bind(&operation.leased_by)
        .bind(tx.workshop_id())
        .fetch_one(&mut **tx)
        .await
    {
        Ok(_) => Ok(()),
        Err(error)
            if error
                .as_database_error()
                .and_then(|error| error.code())
                .as_deref()
                == Some("55000") =>
        {
            Err(IntegrationError::UnknownOutcome)
        }
        Err(_) => Err(IntegrationError::Unavailable),
    }
}

async fn scoped_service(
    tx: &mut WorkshopTransaction<'_>,
    name: &str,
) -> Result<ServiceConnection, IntegrationError> {
    sqlx::query_as::<_, ServiceConnection>(
        "select service.base_url,service.secret_ref,database.database_ref
         from control.service_instances service
         left join control.odoo_databases database
           on database.workshop_id=service.workshop_id
          and database.kind='primary' and database.deleted_at is null
          and service.service='odoo'
         where service.workshop_id=$1 and service.service=$2",
    )
    .bind(tx.workshop_id())
    .bind(name)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| IntegrationError::Unavailable)?
    .ok_or(IntegrationError::NotFound)
}

pub(crate) async fn materialize(
    tx: &mut WorkshopTransaction<'_>,
    operation: &LeasedOperation,
    tenant_domain: &str,
    project_to_odoo: bool,
) -> Result<RouteProjection, IntegrationError> {
    let workshop = tx.workshop_id();
    let tenant = sqlx::query_as::<_, (Uuid, String, String, String, String)>(
        "select database.id,workshop.slug,database.database_ref,database.public_hostname,
                coalesce((select case
                            when module.state in ('installing','enabled') then 'read_write'
                            when module.state in ('restricting','restricted') then 'read_only'
                            else 'absent' end
                          from control.workshop_modules module
                          join control.service_instances paperless
                            on paperless.workshop_id=module.workshop_id
                           and paperless.service='paperless'
                           and paperless.health='ready'
                       where module.workshop_id=workshop.id
                         and module.module_key='documents'),'absent')
         from control.workshops workshop
         join control.odoo_databases database on database.workshop_id=workshop.id
         where workshop.id=$1 and database.kind='primary' and database.deleted_at is null",
    )
    .bind(workshop)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| IntegrationError::Unavailable)?
    .ok_or(IntegrationError::NotFound)?;
    let custom_hostnames = sqlx::query_scalar::<_, Value>(
        "select coalesce(jsonb_agg(jsonb_build_object(
                    'hostname',hostname,'canonical',canonical) order by hostname),'[]'::jsonb)
         from control.webshop_domains
         where workshop_id=$1 and state in ('testing','active') and desired_state='active'",
    )
    .bind(workshop)
    .fetch_one(&mut **tx)
    .await
    .map_err(|_| IntegrationError::Unavailable)?;
    let odoo = if project_to_odoo {
        Some(scoped_service(tx, "odoo").await?)
    } else {
        None
    };
    let paperless_hostname =
        (tenant.4 != "absent").then(|| format!("docs-{}.{}", tenant.1, tenant_domain));
    let projection = json!({
        "database_id":tenant.0,
        "database_ref":tenant.2,
        "public_hostname":tenant.3,
        "paperless_mode":tenant.4,
        "paperless_hostname":paperless_hostname,
        "custom_hostnames":custom_hostnames,
    });
    let digest = format!(
        "sha256:{:x}",
        Sha256::digest(
            serde_jcs::to_vec(&projection).map_err(|_| IntegrationError::ContractDrift)?
        )
    );
    let row = sqlx::query_as::<_, (String, Option<i64>, Option<String>, Option<Value>)>(
        "select outcome,generation,projection_digest,projection
           from control.materialize_workshop_route_projection($1,$2,$3,$4,$5,$6)",
    )
    .bind(operation.id)
    .bind(operation.attempt)
    .bind(&operation.leased_by)
    .bind(workshop)
    .bind(&projection)
    .bind(&digest)
    .fetch_one(&mut **tx)
    .await
    .map_err(|_| IntegrationError::Unavailable)?;
    let (generation, projection_digest, stored_projection) = match row.0.as_str() {
        "created" | "reused" => (
            row.1.ok_or(IntegrationError::ContractDrift)?,
            row.2.ok_or(IntegrationError::ContractDrift)?,
            row.3.ok_or(IntegrationError::ContractDrift)?,
        ),
        "upstream_lease_lost" => return Err(IntegrationError::UnknownOutcome),
        _ => return Err(IntegrationError::ContractDrift),
    };
    if generation <= 0 || projection_digest != digest || stored_projection != projection {
        return Err(IntegrationError::ContractDrift);
    }
    let mut payload = stored_projection;
    let object = payload
        .as_object_mut()
        .ok_or(IntegrationError::ContractDrift)?;
    object.insert("route_generation".into(), json!(generation));
    object.insert(
        "route_projection_digest".into(),
        Value::String(projection_digest.clone()),
    );
    Ok(RouteProjection {
        payload,
        generation,
        projection_digest,
        disposition: "present",
        odoo,
    })
}

pub(crate) async fn materialize_tombstone(
    tx: &mut WorkshopTransaction<'_>,
    operation: &LeasedOperation,
) -> Result<RouteProjection, IntegrationError> {
    let workshop = tx.workshop_id();
    let projection = json!({
        "database_id":null,
        "database_ref":null,
        "public_hostname":null,
        "paperless_mode":"absent",
        "paperless_hostname":null,
        "custom_hostnames":[],
    });
    let digest = format!(
        "sha256:{:x}",
        Sha256::digest(
            serde_jcs::to_vec(&projection).map_err(|_| IntegrationError::ContractDrift)?
        )
    );
    let row = sqlx::query_as::<_, (String, Option<i64>, Option<String>, Option<Value>)>(
        "select outcome,generation,projection_digest,projection
           from control.materialize_workshop_route_tombstone($1,$2,$3,$4,$5,$6)",
    )
    .bind(operation.id)
    .bind(operation.attempt)
    .bind(&operation.leased_by)
    .bind(workshop)
    .bind(&projection)
    .bind(&digest)
    .fetch_one(&mut **tx)
    .await
    .map_err(|_| IntegrationError::Unavailable)?;
    let (generation, projection_digest, stored_projection) = match row.0.as_str() {
        "created" | "reused" => (
            row.1.ok_or(IntegrationError::ContractDrift)?,
            row.2.ok_or(IntegrationError::ContractDrift)?,
            row.3.ok_or(IntegrationError::ContractDrift)?,
        ),
        "upstream_lease_lost" => return Err(IntegrationError::UnknownOutcome),
        "digest_conflict" => return Err(IntegrationError::UnknownOutcome),
        _ => return Err(IntegrationError::ContractDrift),
    };
    if generation <= 0 || projection_digest != digest || stored_projection != projection {
        return Err(IntegrationError::ContractDrift);
    }
    let mut payload = stored_projection;
    let object = payload
        .as_object_mut()
        .ok_or(IntegrationError::ContractDrift)?;
    object.insert("route_generation".into(), json!(generation));
    object.insert(
        "route_projection_digest".into(),
        Value::String(projection_digest.clone()),
    );
    object.insert("route_disposition".into(), Value::String("absent".into()));
    Ok(RouteProjection {
        payload,
        generation,
        projection_digest,
        disposition: "absent",
        odoo: None,
    })
}

pub(crate) fn confirm_application(
    response: &Value,
    workshop: Uuid,
    route: &RouteProjection,
) -> Result<(), IntegrationError> {
    let evidence = response
        .get("route_evidence")
        .and_then(Value::as_object)
        .ok_or(IntegrationError::UnknownOutcome)?;
    match response.get("outcome").and_then(Value::as_str) {
        Some("applied") | Some("replayed") => {}
        Some("superseded") => return Err(IntegrationError::Unavailable),
        _ => return Err(IntegrationError::UnknownOutcome),
    }
    if evidence.get("workshop_id").and_then(Value::as_str) != Some(workshop.to_string().as_str())
        || evidence.get("route_generation").and_then(Value::as_i64) != Some(route.generation)
        || evidence.get("projection_digest").and_then(Value::as_str)
            != Some(route.projection_digest.as_str())
        || evidence.get("disposition").and_then(Value::as_str) != Some(route.disposition)
    {
        return Err(IntegrationError::UnknownOutcome);
    }
    Ok(())
}

pub(crate) async fn apply(
    operation: &LeasedOperation,
    workshop: Uuid,
    key_prefix: &str,
    route: &RouteProjection,
    deployment_driver: &DeploymentDriverConfig,
) -> Result<Value, IntegrationError> {
    let response = crate::worker::driver_request_with_key(
        operation,
        workshop,
        "route-project",
        &format!(
            "{key_prefix}:{}:{}",
            route.generation, route.projection_digest
        ),
        &route.payload,
        deployment_driver,
    )
    .await?;
    confirm_application(&response, workshop, route)?;
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_confirmation_is_bound_to_workshop_generation_and_digest() {
        let workshop = Uuid::new_v4();
        let route = RouteProjection {
            payload: json!({}),
            generation: 4,
            projection_digest: format!("sha256:{}", "a".repeat(64)),
            disposition: "present",
            odoo: None,
        };
        let response = json!({
            "outcome":"applied",
            "route_evidence":{
                "workshop_id":workshop,
                "route_generation":4,
                "projection_digest":route.projection_digest,
                "disposition":"present",
            }
        });
        assert!(confirm_application(&response, workshop, &route).is_ok());
        let mut stale = response.clone();
        stale["route_evidence"]["route_generation"] = json!(3);
        assert!(matches!(
            confirm_application(&stale, workshop, &route),
            Err(IntegrationError::UnknownOutcome)
        ));
        let mut wrong_disposition = response;
        wrong_disposition["route_evidence"]["disposition"] = json!("absent");
        assert!(matches!(
            confirm_application(&wrong_disposition, workshop, &route),
            Err(IntegrationError::UnknownOutcome)
        ));
    }
}
