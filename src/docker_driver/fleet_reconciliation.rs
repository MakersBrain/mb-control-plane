//! Observation-only completion of a protocol-v1 fleet activation.
//!
//! No function in this module starts, stops, creates, deletes, or rewrites an
//! external resource. A mismatch always preserves quarantine.

use std::time::Duration;

use super::*;

async fn finish(
    state: &DriverState,
    reconciliation: &FleetReleaseReconciliation,
    outcome: &str,
    response: Option<&Value>,
) -> Result<(), DriverError> {
    let finished = sqlx::query_scalar::<_, bool>(
        "select control.finish_fleet_release_reconciliation($1,$2,$3,$4,$5)",
    )
    .bind(reconciliation.id)
    .bind(reconciliation.instance_owner)
    .bind(reconciliation.execution_token)
    .bind(outcome)
    .bind(response)
    .fetch_one(&state.ledger)
    .await
    .map_err(DriverError::internal)?;
    if !finished {
        return Err(DriverError::internal(
            "fleet release reconciliation fence was lost",
        ));
    }
    Ok(())
}

async fn observe(
    state: &DriverState,
    payload: &Value,
    reconciliation: &FleetReleaseReconciliation,
) -> Result<Value, DriverError> {
    let fleet_run = payload_uuid(payload, "fleet_run_id")?;
    let release_id = payload
        .get("release_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| DriverError::bad("release_id is required"))?;
    if payload.get("phase").and_then(Value::as_str) != Some("adopt-fleet")
        || fleet_run != reconciliation.gateway_identity.fleet_run_id
        || reconciliation.original_fence_token
            != reconciliation.gateway_identity.original_driver_fence_token
    {
        return Err(DriverError::internal(
            "fleet reconciliation request identity drifted",
        ));
    }
    let run = sqlx::query_as::<_, (Value, i64, Uuid)>(
        "select tenant_snapshot,fleet_generation,operation_id from control.release_fleet_runs
          where id=$1 and release_id=$2 and state in ('preparing','activating')
            and driver_fence_token=$3",
    )
    .bind(fleet_run)
    .bind(release_id)
    .bind(reconciliation.original_fence_token)
    .fetch_optional(&state.ledger)
    .await
    .map_err(DriverError::internal)?
    .ok_or_else(|| DriverError::internal("fleet reconciliation run drifted"))?;
    let release = sqlx::query_as::<_, (Value, String, String)>(
        "select manifest,status,odoo_subject_digest from control.application_releases where id=$1",
    )
    .bind(release_id)
    .fetch_optional(&state.ledger)
    .await
    .map_err(DriverError::internal)?
    .ok_or_else(|| DriverError::internal("fleet reconciliation release is absent"))?;
    if release.1 != "prepared" {
        return Err(DriverError::internal(
            "fleet reconciliation release is not prepared",
        ));
    }
    let manifest: crate::release::ApplicationReleaseManifest =
        serde_json::from_value(release.0).map_err(DriverError::internal)?;
    manifest.validate().map_err(DriverError::internal)?;
    if manifest.release_id != release_id || manifest.odoo_runtime.subject_digest != release.2 {
        return Err(DriverError::internal(
            "fleet reconciliation release identity drifted",
        ));
    }
    let observation = super::release_runtime_observation::observe_release_runtime(
        state,
        super::release_runtime_observation::ReleaseRuntimeObservationRequest {
            fleet_run_id: fleet_run,
            release_id,
            control_operation_id: run.2,
            driver_operation_id: reconciliation.driver_operation_id,
            original_instance_owner: reconciliation.original_instance_owner,
            original_global_fence_token: reconciliation.original_fence_token,
            target_slot: reconciliation.gateway_identity.target_slot,
            manifest: &manifest,
            expected_tenant_snapshot: &run.0,
            gateway_identity: &reconciliation.gateway_identity,
        },
    )
    .await?;
    let evidence = observation.completion_evidence(
        release_id,
        &manifest,
        run.1,
        &reconciliation.gateway_identity,
        reconciliation.driver_operation_id,
        reconciliation.original_fence_token,
    );
    Ok(json!({"evidence":evidence,"reconciliation":{
        "id":reconciliation.id,"kind":"fleet_activation_forward","protocol_version":1,
        "external_executor_quiescent":true,"candidate_runtime_verified":true,
        "gateway_identity_verified":true,"target_database_access_verified":true,
        "old_runtime_retired":true,"forward_only":true,
        "original_executor":{"instance_owner":reconciliation.original_instance_owner,
            "protocol_version":1},
        "gateway_identity":reconciliation.gateway_identity
    }}))
}

#[tracing::instrument(
    name = "deployment_driver.release_reconciliation.observe_fleet",
    skip_all,
    fields(reconciliation.id = %reconciliation.id,
        driver_operation_id = %reconciliation.driver_operation_id,
        reconciliation.outcome = tracing::field::Empty)
)]
pub(super) async fn reconcile_fleet_release(
    state: &DriverState,
    payload: &Value,
    reconciliation: &FleetReleaseReconciliation,
) -> Result<Value, DriverError> {
    match tokio::time::timeout(
        Duration::from_secs(540),
        observe(state, payload, reconciliation),
    )
    .await
    {
        Ok(Ok(response)) => {
            if let Err(error) = finish(state, reconciliation, "succeeded", Some(&response)).await {
                tracing::warn!(
                    error_class = error.safe_class(),
                    "fleet release reconciliation success was not durably confirmed"
                );
                return Err(fleet_reconciliation_inconclusive());
            }
            tracing::Span::current().record("reconciliation.outcome", "succeeded");
            Ok(response)
        }
        Ok(Err(error)) => {
            tracing::warn!(
                error_class = error.safe_class(),
                "fleet release observation was inconclusive"
            );
            if let Err(finish_error) = finish(state, reconciliation, "inconclusive", None).await {
                tracing::warn!(
                    error_class = finish_error.safe_class(),
                    "fleet release reconciliation inconclusive result was not durably confirmed"
                );
            }
            tracing::Span::current().record("reconciliation.outcome", "inconclusive");
            Err(fleet_reconciliation_inconclusive())
        }
        Err(_) => {
            if let Err(error) = finish(state, reconciliation, "inconclusive", None).await {
                tracing::warn!(
                    error_class = error.safe_class(),
                    "fleet release reconciliation timeout was not durably confirmed"
                );
            }
            tracing::Span::current().record("reconciliation.outcome", "timed_out");
            Err(fleet_reconciliation_inconclusive())
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn reconciliation_has_no_runtime_mutation_or_job_dispatch_path() {
        let production = include_str!("fleet_reconciliation.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        for forbidden in [
            "ensure_release_runtime(",
            "ensure_release_runtime_role(",
            "run_docker_job(",
            "run_docker_job_with_secrets(",
            "docker_create_container(",
            "docker_start_container(",
            "docker_stop_container(",
            "docker_delete_container(",
            "set_odoo_boot_selected(",
            "activate_release_routes(",
            "publish_release_gateway_identity(",
        ] {
            assert!(
                !production.contains(forbidden),
                "reconciliation must remain observation-only: {forbidden}"
            );
        }
    }
}
