//! Exact, read-only observation of an interrupted fleet release executor.
//!
//! This module deliberately does not terminate containers, systemd units, or
//! PostgreSQL backends.  A future reconciler may proceed only when every
//! observer returns [`ExecutorState::Quiescent`].  Missing or mismatched
//! identity is ambiguous rather than evidence of absence.

use super::*;

pub(crate) const FLEET_RUN_LABEL: &str = "mb.fleet-run";
pub(crate) const DRIVER_OPERATION_LABEL: &str = "mb.driver-operation";
pub(crate) const DRIVER_FENCE_LABEL: &str = "mb.driver-fence";
pub(crate) const ADOPTION_LABEL: &str = "mb.release-adoption";

pub(crate) fn driver_postgres_application_name(instance_id: Uuid) -> String {
    format!("mb-driver-v1-{instance_id}")
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ReleaseExecutorIdentity {
    pub(crate) fleet_run_id: Uuid,
    pub(crate) driver_operation_id: Uuid,
    pub(crate) original_fence_token: i64,
    pub(crate) adoption_id: Uuid,
}

impl ReleaseExecutorIdentity {
    pub(crate) fn new(
        fleet_run_id: Uuid,
        driver_operation_id: Uuid,
        original_fence_token: i64,
        adoption_id: Uuid,
    ) -> Result<Self, DriverError> {
        if original_fence_token <= 0 {
            return Err(DriverError::internal(
                "release executor fence identity is invalid",
            ));
        }
        Ok(Self {
            fleet_run_id,
            driver_operation_id,
            original_fence_token,
            adoption_id,
        })
    }

    pub(crate) fn labels(&self) -> Value {
        json!({
            FLEET_RUN_LABEL: self.fleet_run_id.to_string(),
            DRIVER_OPERATION_LABEL: self.driver_operation_id.to_string(),
            DRIVER_FENCE_LABEL: self.original_fence_token.to_string(),
            ADOPTION_LABEL: self.adoption_id.to_string(),
        })
    }

    /// PostgreSQL limits `application_name` to 63 bytes.  Hashing the complete
    /// closed identity prevents truncation from merging different attempts.
    pub(crate) fn postgres_application_name(&self) -> String {
        let canonical = format!(
            "v1/{}/{}/{}/{}",
            self.fleet_run_id,
            self.driver_operation_id,
            self.original_fence_token,
            self.adoption_id
        );
        let digest = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(Sha256::digest(canonical.as_bytes()));
        format!("mb-release-v1-{digest}")
    }

    fn matches_labels(&self, inspect: &Value) -> bool {
        let labels = inspect.pointer("/Config/Labels").and_then(Value::as_object);
        labels.is_some_and(|labels| {
            labels.get(FLEET_RUN_LABEL).and_then(Value::as_str)
                == Some(self.fleet_run_id.to_string().as_str())
                && labels.get(DRIVER_OPERATION_LABEL).and_then(Value::as_str)
                    == Some(self.driver_operation_id.to_string().as_str())
                && labels.get(DRIVER_FENCE_LABEL).and_then(Value::as_str)
                    == Some(self.original_fence_token.to_string().as_str())
                && labels.get(ADOPTION_LABEL).and_then(Value::as_str)
                    == Some(self.adoption_id.to_string().as_str())
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExecutorState {
    Active,
    Quiescent,
    Ambiguous,
}

fn combine_executor_states(states: &[ExecutorState]) -> ExecutorState {
    if states.contains(&ExecutorState::Active) {
        ExecutorState::Active
    } else if states.contains(&ExecutorState::Ambiguous) {
        ExecutorState::Ambiguous
    } else {
        ExecutorState::Quiescent
    }
}

/// Interpret an exact runtime inspection. `None` must only be supplied for an
/// authoritative runtime-object-not-found response. That absence is usable by
/// reconciliation only for protocol-v1 receipts: older jobs were not required
/// to carry this identity, so their missing deterministic name proves nothing.
pub(crate) fn observe_runtime_object(
    identity: &ReleaseExecutorIdentity,
    inspect: Option<&Value>,
) -> ExecutorState {
    let Some(inspect) = inspect else {
        return ExecutorState::Quiescent;
    };
    if !identity.matches_labels(inspect) {
        return ExecutorState::Ambiguous;
    }
    match inspect.pointer("/State/Running").and_then(Value::as_bool) {
        Some(true) => ExecutorState::Active,
        Some(false) => ExecutorState::Quiescent,
        None => ExecutorState::Ambiguous,
    }
}

/// Observe the deterministic Docker container or Quadlet transient job without
/// changing it. A runtime race or an active unit without its exact labelled
/// container is an error, so callers retain quarantine.
#[allow(dead_code)] // consumed by the next fleet-reconciliation admission slice
pub(super) async fn observe_runtime_executor(
    state: &DriverState,
    container: &str,
    identity: &ReleaseExecutorIdentity,
) -> Result<ExecutorState, DriverError> {
    validate_name(container)?;
    let inspect = match &state.backend {
        RuntimeBackend::Docker => {
            let response = state
                .runtime
                .client
                .get(
                    state
                        .runtime
                        .endpoint(&format!("/containers/{container}/json")),
                )
                .send()
                .await
                .map_err(DriverError::internal)?;
            match response.status() {
                StatusCode::OK => Some(response.json().await.map_err(DriverError::internal)?),
                StatusCode::NOT_FOUND => None,
                status => {
                    return Err(DriverError::internal(format!(
                        "runtime executor inspection returned {status}"
                    )));
                }
            }
        }
        RuntimeBackend::Quadlet(backend) => backend.inspect_job(container).await?,
    };
    Ok(observe_runtime_object(identity, inspect.as_ref()))
}

/// Prove that PostgreSQL has no backend belonging to this exact executor.
/// Failure to inspect is propagated and must retain quarantine.
#[allow(dead_code)] // consumed by the next fleet-reconciliation admission slice
pub(super) async fn observe_postgres_executor(
    state: &DriverState,
    identity: &ReleaseExecutorIdentity,
) -> Result<ExecutorState, DriverError> {
    let count = sqlx::query_scalar::<_, i64>(
        "select count(*) from pg_catalog.pg_stat_activity where application_name=$1",
    )
    .bind(identity.postgres_application_name())
    .fetch_one(&state.postgres)
    .await
    .map_err(DriverError::internal)?;
    Ok(if count == 0 {
        ExecutorState::Quiescent
    } else {
        ExecutorState::Active
    })
}

/// Observe SQL still executing under the original driver process identity.
/// Idle pooled connections are not an effect executor; active transactions,
/// statements, and idle-in-transaction backends all retain quarantine.
#[allow(dead_code)] // consumed by the next fleet-reconciliation admission slice
pub(super) async fn observe_postgres_driver(
    state: &DriverState,
    original_instance_id: Uuid,
) -> Result<ExecutorState, DriverError> {
    let count = sqlx::query_scalar::<_, i64>(
        "select count(*) from pg_catalog.pg_stat_activity
          where application_name=$1 and backend_type='client backend'
            and state is distinct from 'idle'",
    )
    .bind(driver_postgres_application_name(original_instance_id))
    .fetch_one(&state.postgres)
    .await
    .map_err(DriverError::internal)?;
    Ok(if count == 0 {
        ExecutorState::Quiescent
    } else {
        ExecutorState::Active
    })
}

/// One fail-closed entry point for the future reconciler. Authority may move
/// forward only when the exact runtime job, its database connections, and the
/// original driver's direct SQL executor are all quiescent.
#[allow(dead_code)] // consumed by the next fleet-reconciliation admission slice
pub(super) async fn observe_release_executor_quiescence(
    state: &DriverState,
    container: &str,
    identity: &ReleaseExecutorIdentity,
    original_instance_id: Uuid,
) -> Result<ExecutorState, DriverError> {
    let runtime = observe_runtime_executor(state, container, identity).await?;
    let job_postgres = observe_postgres_executor(state, identity).await?;
    let driver_postgres = observe_postgres_driver(state, original_instance_id).await?;
    Ok(combine_executor_states(&[
        runtime,
        job_postgres,
        driver_postgres,
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> ReleaseExecutorIdentity {
        ReleaseExecutorIdentity {
            fleet_run_id: Uuid::parse_str("11111111-1111-4111-8111-111111111111").unwrap(),
            driver_operation_id: Uuid::parse_str("22222222-2222-4222-8222-222222222222").unwrap(),
            original_fence_token: 41,
            adoption_id: Uuid::parse_str("33333333-3333-4333-8333-333333333333").unwrap(),
        }
    }

    #[test]
    fn exact_running_executor_is_active() {
        let identity = identity();
        let inspect = json!({"Config":{"Labels":identity.labels()},"State":{"Running":true}});
        assert_eq!(
            observe_runtime_object(&identity, Some(&inspect)),
            ExecutorState::Active
        );
    }

    #[test]
    fn exact_terminal_executor_is_quiescent() {
        let identity = identity();
        let inspect = json!({"Config":{"Labels":identity.labels()},"State":{"Running":false}});
        assert_eq!(
            observe_runtime_object(&identity, Some(&inspect)),
            ExecutorState::Quiescent
        );
        assert_eq!(
            observe_runtime_object(&identity, None),
            ExecutorState::Quiescent
        );
    }

    #[test]
    fn incomplete_or_other_attempt_identity_is_ambiguous() {
        let identity = identity();
        let mut labels = identity.labels();
        labels[DRIVER_FENCE_LABEL] = json!("42");
        let drifted = json!({"Config":{"Labels":labels},"State":{"Running":false}});
        let incomplete = json!({"Config":{"Labels":identity.labels()},"State":{}});
        assert_eq!(
            observe_runtime_object(&identity, Some(&drifted)),
            ExecutorState::Ambiguous
        );
        assert_eq!(
            observe_runtime_object(&identity, Some(&incomplete)),
            ExecutorState::Ambiguous
        );
    }

    #[test]
    fn quiescence_requires_every_executor_to_be_quiescent() {
        assert_eq!(
            combine_executor_states(&[
                ExecutorState::Quiescent,
                ExecutorState::Quiescent,
                ExecutorState::Quiescent,
            ]),
            ExecutorState::Quiescent
        );
        assert_eq!(
            combine_executor_states(&[ExecutorState::Quiescent, ExecutorState::Ambiguous]),
            ExecutorState::Ambiguous
        );
        assert_eq!(
            combine_executor_states(&[ExecutorState::Ambiguous, ExecutorState::Active]),
            ExecutorState::Active
        );
    }

    #[test]
    fn postgres_name_is_bounded_and_binds_every_identity_field() {
        let identity = identity();
        let name = identity.postgres_application_name();
        assert_eq!(name.len(), 57);
        let mut changed = identity.clone();
        changed.original_fence_token += 1;
        assert_ne!(name, changed.postgres_application_name());
        changed = identity.clone();
        changed.adoption_id = Uuid::new_v4();
        assert_ne!(name, changed.postgres_application_name());
        changed = identity.clone();
        changed.fleet_run_id = Uuid::new_v4();
        assert_ne!(name, changed.postgres_application_name());
        changed = identity.clone();
        changed.driver_operation_id = Uuid::new_v4();
        assert_ne!(name, changed.postgres_application_name());
    }

    #[test]
    fn driver_postgres_name_is_exact_and_bounded() {
        let instance = Uuid::parse_str("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").unwrap();
        let name = driver_postgres_application_name(instance);
        assert_eq!(name, "mb-driver-v1-aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
        assert!(name.len() <= 63);
    }

    #[test]
    fn release_dispatch_persists_runtime_and_postgres_identity() {
        let release = include_str!("release.rs");
        assert!(release.contains("ReleaseExecutorIdentity::new("));
        assert!(release.contains("\"Labels\": executor.labels()"));
        assert!(release.contains("db_app_name = {executor_application_name}"));
        assert!(release.contains("PGAPPNAME={executor_application_name}"));

        let driver = include_str!("../docker_driver.rs");
        assert!(driver.contains("driver_postgres_application_name("));
        assert!(driver.contains("connect_with(postgres_options)"));
    }
}
