//! Shared, read-only proof of a fleet release runtime.
//!
//! This module is the only constructor of [`VerifiedReleaseRuntimeObservation`].
//! It observes existing runtime, PostgreSQL, tenant, route, and gateway state;
//! it never creates, starts, stops, updates, or deletes an external resource.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::Duration;

use async_trait::async_trait;

use super::executor_quiescence::{ExecutorState, ReleaseExecutorIdentity};
use super::*;

#[derive(Clone, Copy)]
pub(super) struct ReleaseRuntimeObservationRequest<'a> {
    pub fleet_run_id: Uuid,
    pub release_id: &'a str,
    pub control_operation_id: Uuid,
    pub driver_operation_id: Uuid,
    pub original_instance_owner: Uuid,
    pub original_global_fence_token: i64,
    pub target_slot: ReleaseTargetSlot,
    pub manifest: &'a crate::release::ApplicationReleaseManifest,
    pub expected_tenant_snapshot: &'a Value,
    pub gateway_identity: &'a ReleaseGatewayGenerationIdentity,
}

#[derive(Debug, sqlx::FromRow)]
struct ObservedTenant {
    adoption_id: Uuid,
    workshop_id: Uuid,
    database_id: Uuid,
    database_ref: String,
    public_hostname: String,
    component_scope: Vec<String>,
}

/// Secret text deliberately has no `Debug`, `Display`, or serialization
/// implementation. It may cross the blocking boundary but never a log or
/// durable-evidence boundary.
struct SecretText(String);

impl SecretText {
    fn expose(&self) -> &str {
        &self.0
    }
}

/// One immutable snapshot of every filesystem input needed by runtime
/// observation. Loading all inputs in one blocking task keeps Tokio workers
/// free even at the bounded 500-tenant fleet limit.
struct ReleaseRuntimeObservationFiles {
    runtime_password: SecretText,
    tenant_bridge_tokens: HashMap<Uuid, SecretText>,
    route_digest: Option<String>,
}

impl ReleaseRuntimeObservationFiles {
    fn validate_for(&self, workshops: &[Uuid]) -> Result<(), DriverError> {
        let expected = workshops.iter().copied().collect::<HashSet<_>>();
        if expected.len() != workshops.len()
            || expected.len() != self.tenant_bridge_tokens.len()
            || !expected
                .iter()
                .all(|workshop| self.tenant_bridge_tokens.contains_key(workshop))
            || self.runtime_password.expose().is_empty()
            || self
                .tenant_bridge_tokens
                .values()
                .any(|token| token.expose().is_empty())
            || self
                .route_digest
                .as_deref()
                .is_some_and(|value| validate_digest(value).is_err())
        {
            return Err(DriverError::internal(
                "release runtime filesystem observation is incomplete",
            ));
        }
        Ok(())
    }

    fn tenant_bridge_token(&self, workshop: Uuid) -> Result<&str, DriverError> {
        self.tenant_bridge_tokens
            .get(&workshop)
            .map(SecretText::expose)
            .ok_or_else(|| DriverError::internal("tenant bridge credential is absent"))
    }
}

#[async_trait]
trait ReleaseRuntimeObservationFsPort: Send + Sync {
    async fn load(&self, workshops: &[Uuid])
    -> Result<ReleaseRuntimeObservationFiles, DriverError>;
}

async fn load_verified_release_runtime_files<F: ReleaseRuntimeObservationFsPort>(
    filesystem: &F,
    workshops: &[Uuid],
) -> Result<ReleaseRuntimeObservationFiles, DriverError> {
    let files = filesystem.load(workshops).await?;
    files.validate_for(workshops)?;
    Ok(files)
}

struct LiveReleaseRuntimeObservationFs {
    runtime_credential_path: PathBuf,
    tenant_secret_root: PathBuf,
    route_root: PathBuf,
}

#[async_trait]
impl ReleaseRuntimeObservationFsPort for LiveReleaseRuntimeObservationFs {
    async fn load(
        &self,
        workshops: &[Uuid],
    ) -> Result<ReleaseRuntimeObservationFiles, DriverError> {
        let runtime_credential_path = self.runtime_credential_path.clone();
        let tenant_secret_root = self.tenant_secret_root.clone();
        let route_root = self.route_root.clone();
        let workshops = workshops.to_vec();
        tokio::task::spawn_blocking(move || {
            load_release_runtime_observation_files(
                runtime_credential_path,
                tenant_secret_root,
                route_root,
                &workshops,
            )
        })
        .await
        .map_err(DriverError::internal)?
    }
}

fn load_release_runtime_observation_files(
    runtime_credential_path: PathBuf,
    tenant_secret_root: PathBuf,
    route_root: PathBuf,
    workshops: &[Uuid],
) -> Result<ReleaseRuntimeObservationFiles, DriverError> {
    if workshops.len() > 500 {
        return Err(DriverError::internal(
            "release runtime filesystem observation exceeds fleet bound",
        ));
    }
    let expected = workshops.iter().copied().collect::<HashSet<_>>();
    if expected.len() != workshops.len() {
        return Err(DriverError::internal(
            "release runtime filesystem observation has duplicate tenants",
        ));
    }
    let runtime_password = std::fs::read_to_string(runtime_credential_path)
        .map_err(DriverError::internal)?
        .trim_end_matches(['\r', '\n'])
        .to_owned();
    if runtime_password.is_empty() {
        return Err(DriverError::internal("runtime credential is absent"));
    }

    let selected = gateway::selected_route_root(&route_root)?;
    let mut tenant_bridge_tokens = HashMap::with_capacity(workshops.len());
    let mut routes = Vec::with_capacity(workshops.len());
    let mut maintenance_route = false;
    for workshop in workshops {
        let token =
            std::fs::read_to_string(tenant_secret_root.join(workshop.to_string()).join("odoo"))
                .map_err(DriverError::internal)?
                .trim()
                .to_owned();
        if token.is_empty() {
            return Err(DriverError::internal("tenant bridge credential is absent"));
        }
        let route = std::fs::read(selected.join(format!("{workshop}.conf")))
            .map_err(DriverError::internal)?;
        maintenance_route |= route
            .windows("Retry-After".len())
            .any(|value| value == b"Retry-After");
        tenant_bridge_tokens.insert(*workshop, SecretText(token));
        routes.push((*workshop, route));
    }
    let route_digest = (!maintenance_route).then(|| {
        super::release::route_set_digest(
            routes
                .iter()
                .map(|(workshop, route)| (*workshop, route.as_slice())),
        )
    });
    let files = ReleaseRuntimeObservationFiles {
        runtime_password: SecretText(runtime_password),
        tenant_bridge_tokens,
        route_digest,
    };
    files.validate_for(workshops)?;
    Ok(files)
}

/// An observation can only be created after every read-only proof succeeds.
/// Fields are intentionally private so callers cannot manufacture positive
/// booleans and submit them as evidence.
#[derive(Clone, Debug, Serialize)]
pub(super) struct VerifiedReleaseRuntimeObservation {
    protocol_version: u8,
    odoo_manifest_digest: String,
    odoo_config_digest: String,
    extension_manifest_digest: String,
    extension_config_digest: String,
    payload_digest: String,
    extension_volume: String,
    runtime_container: String,
    runtime_config_digest: String,
    external_executor_quiescent: bool,
    candidate_runtime_verified: bool,
    gateway_identity_verified: bool,
    target_database_access_verified: bool,
    old_runtime_retired: bool,
    tenant_recovery_verified: bool,
    candidate_smoke_verified: bool,
    candidate_restart_policy: String,
    retained_restart_policy: String,
    observed_gateway_configuration_digest: String,
    observed_target_slot: ReleaseTargetSlot,
    #[serde(skip)]
    runtime_role: String,
    #[serde(skip)]
    prepared_tenants: Value,
    #[serde(skip)]
    tenant_snapshot: Value,
    #[serde(skip)]
    pair_qualification_digest: String,
}

impl VerifiedReleaseRuntimeObservation {
    pub(super) fn as_database_value(&self) -> Result<Value, DriverError> {
        serde_json::to_value(self).map_err(DriverError::internal)
    }

    pub(super) fn completion_evidence(
        &self,
        release_id: &str,
        manifest: &crate::release::ApplicationReleaseManifest,
        fleet_generation: i64,
        gateway_identity: &ReleaseGatewayGenerationIdentity,
        driver_operation_id: Uuid,
        driver_fence_token: i64,
    ) -> Value {
        json!({
            "release_id":release_id,
            "odoo_subject_digest":manifest.odoo_runtime.subject_digest,
            "extension_subject_digest":manifest.extension_bundle.subject_digest,
            "odoo_manifest_digest":self.odoo_manifest_digest,
            "odoo_config_digest":self.odoo_config_digest,
            "extension_manifest_digest":self.extension_manifest_digest,
            "extension_config_digest":self.extension_config_digest,
            "payload_digest":self.payload_digest,
            "extension_volume":self.extension_volume,
            "pair_qualification_digest":self.pair_qualification_digest,
            "bridge_contract_digest":manifest.bridge_contract_digest,
            "installed_addon_versions":manifest.addons,
            "runtime_key":"shared-odoo",
            "target_slot":self.observed_target_slot,
            "runtime_container":self.runtime_container,
            "runtime_role":self.runtime_role,
            "runtime_deployment_ref":manifest.odoo_runtime.deployment_ref,
            "runtime_config_digest":self.runtime_config_digest,
            "prepared_tenants":self.prepared_tenants,
            "fleet_generation":fleet_generation,
            "tenant_snapshot":self.tenant_snapshot,
            "gateway_configuration_digest":self.observed_gateway_configuration_digest,
            "driver_action_id":gateway_identity.driver_action_id,
            "driver_operation_id":driver_operation_id,
            "driver_fence_token":driver_fence_token,
            "old_runtime_database_access_revoked":self.target_database_access_verified,
            "tenant_recovery_verified":self.tenant_recovery_verified,
            "candidate_smoke_verified":self.candidate_smoke_verified,
            "candidate_restart_policy":self.candidate_restart_policy,
            "retained_restart_policy":self.retained_restart_policy,
        })
    }

    pub(super) fn validate_for_recovery_expectation(
        &self,
        expectation: &super::release_route_recovery_db::ReleaseRecoveryRuntimeExpectation,
    ) -> Result<(), DriverError> {
        let (runtime, extension, pair) =
            super::release::selected_release_platform(&expectation.release_manifest)?;
        if self.protocol_version != 1
            || !self.external_executor_quiescent
            || !self.candidate_runtime_verified
            || !self.gateway_identity_verified
            || !self.target_database_access_verified
            || !self.old_runtime_retired
            || !self.tenant_recovery_verified
            || !self.candidate_smoke_verified
            || self.candidate_restart_policy != "unless-stopped"
            || self.retained_restart_policy != "no"
            || self.observed_target_slot != expectation.target_slot
            || self.observed_gateway_configuration_digest
                != expectation.gateway_configuration_digest
            || self.odoo_manifest_digest != runtime.manifest_digest
            || self.odoo_config_digest != runtime.config_digest
            || self.extension_manifest_digest != extension.manifest_digest
            || self.extension_config_digest != extension.config_digest
            || self.payload_digest != extension.payload_digest
            || self.pair_qualification_digest != pair.qualification_digest
            || self.pair_qualification_digest != expectation.pair_qualification_digest
            || !valid_runtime_container(&self.runtime_container, expectation.target_slot.as_str())
            || !super::release_route_publication_db::valid_extension_volume(
                &self.extension_volume,
                &extension.manifest_digest,
                &extension.payload_digest,
            )
        {
            return Err(DriverError::internal(
                "release recovery runtime observation differs",
            ));
        }
        for value in [
            &self.odoo_manifest_digest,
            &self.odoo_config_digest,
            &self.extension_manifest_digest,
            &self.extension_config_digest,
            &self.payload_digest,
            &self.runtime_config_digest,
            &self.observed_gateway_configuration_digest,
        ] {
            validate_digest(value)?;
        }
        Ok(())
    }
}

#[tracing::instrument(
    name = "deployment_driver.release_runtime.observe",
    skip_all,
    fields(
        driver.operation_id = %request.driver_operation_id,
        observation.outcome = tracing::field::Empty
    )
)]
pub(super) async fn observe_release_runtime(
    state: &DriverState,
    request: ReleaseRuntimeObservationRequest<'_>,
) -> Result<VerifiedReleaseRuntimeObservation, DriverError> {
    validate_request(&request)?;
    let result = observe_release_runtime_inner(state, request).await;
    tracing::Span::current().record(
        "observation.outcome",
        if result.is_ok() {
            "verified"
        } else {
            "inconclusive"
        },
    );
    result
}

/// Build the same verified observation from the database-owned recovery
/// expectation. This is intentionally dormant: the future coordinator owns
/// claim renewal, timeout, receipt persistence, and the later protocol-v2
/// loaded-overlay proof. Failure to observe the rolling gateway identity is
/// inconclusive and must retain quarantine.
#[allow(dead_code)]
pub(super) async fn observe_recovery_release_runtime(
    state: &DriverState,
    expectation: &super::release_route_recovery_db::ReleaseRecoveryRuntimeExpectation,
) -> Result<VerifiedReleaseRuntimeObservation, DriverError> {
    let gateway_identity = ReleaseGatewayGenerationIdentity::new(
        expectation.fleet_run_id,
        expectation.driver_action_id,
        expectation.original_global_fence_token,
        expectation.gateway_configuration_digest.clone(),
        expectation.target_slot.as_str(),
    )?;
    let tenant_snapshot =
        serde_json::to_value(&expectation.tenant_snapshot).map_err(DriverError::internal)?;
    observe_release_runtime(
        state,
        ReleaseRuntimeObservationRequest {
            fleet_run_id: expectation.fleet_run_id,
            release_id: &expectation.release_id,
            control_operation_id: expectation.control_operation_id,
            driver_operation_id: expectation.driver_operation_id,
            original_instance_owner: expectation.original_instance_owner,
            original_global_fence_token: expectation.original_global_fence_token,
            target_slot: expectation.target_slot,
            manifest: &expectation.release_manifest,
            expected_tenant_snapshot: &tenant_snapshot,
            gateway_identity: &gateway_identity,
        },
    )
    .await
}

async fn observe_release_runtime_inner(
    state: &DriverState,
    request: ReleaseRuntimeObservationRequest<'_>,
) -> Result<VerifiedReleaseRuntimeObservation, DriverError> {
    let runtime_role =
        super::release::release_runtime_role(&request.manifest.odoo_runtime.subject_digest);
    let filesystem = LiveReleaseRuntimeObservationFs {
        runtime_credential_path: super::driver_runtime_secret_root(state)
            .join("releases")
            .join(&runtime_role),
        tenant_secret_root: state.config.secret_root.join("docker"),
        route_root: state.config.route_root.clone(),
    };
    observe_release_runtime_with_fs(state, request, runtime_role, &filesystem).await
}

async fn observe_release_runtime_with_fs<F: ReleaseRuntimeObservationFsPort>(
    state: &DriverState,
    request: ReleaseRuntimeObservationRequest<'_>,
    runtime_role: String,
    filesystem: &F,
) -> Result<VerifiedReleaseRuntimeObservation, DriverError> {
    let (runtime_platform, extension_platform, pair) =
        super::release::selected_release_platform(request.manifest)?;
    let target_slot = request.target_slot.as_str();
    let runtime_container = state.config.docker_resource(format!("odoo-{target_slot}"));
    let extension_volume = state.config.docker_resource(format!(
        "ext-{}-{}",
        &extension_platform.manifest_digest[7..23],
        &extension_platform.payload_digest[7..23]
    ));
    let tenants = load_verified_tenants(state, &request).await?;
    let (prepared_tenants, tenant_snapshot) = tenant_evidence(&tenants);
    if &tenant_snapshot != request.expected_tenant_snapshot {
        return Err(DriverError::internal(
            "release runtime tenant snapshot differs",
        ));
    }
    let workshops = tenants
        .iter()
        .map(|tenant| tenant.workshop_id)
        .collect::<Vec<_>>();
    let files = load_verified_release_runtime_files(filesystem, &workshops).await?;
    let runtime_config_digest = super::release::release_runtime_config_digest(
        state,
        &request.manifest.odoo_runtime.deployment_ref,
        &runtime_role,
        files.runtime_password.expose(),
    );

    if super::executor_quiescence::observe_postgres_driver(state, request.original_instance_owner)
        .await?
        != ExecutorState::Quiescent
    {
        return Err(DriverError::internal("original release executor is active"));
    }
    for tenant in &tenants {
        let identity = ReleaseExecutorIdentity::new(
            request.fleet_run_id,
            request.driver_operation_id,
            request.original_global_fence_token,
            tenant.adoption_id,
        )?;
        let job = state.config.docker_resource(format!(
            "release-upgrade-{}",
            &tenant.adoption_id.simple().to_string()[..12]
        ));
        if super::executor_quiescence::observe_runtime_executor(state, &job, &identity).await?
            != ExecutorState::Quiescent
            || super::executor_quiescence::observe_postgres_executor(state, &identity).await?
                != ExecutorState::Quiescent
        {
            return Err(DriverError::internal("release executor is not quiescent"));
        }
    }

    let candidate = inspect_container(state, &runtime_container).await?;
    if !runtime_inspect_matches(
        &candidate,
        &request.manifest.odoo_runtime.deployment_ref,
        &runtime_platform.config_digest,
        &runtime_config_digest,
        &extension_volume,
    ) {
        return Err(DriverError::internal("candidate runtime drifted"));
    }
    observe_candidate_policy(state, &runtime_container, &candidate).await?;

    let old_slot = sqlx::query_scalar::<_, String>(
        "select slot from control.runtime_release_slots
          where runtime_key='shared-odoo' and state='active' and slot<>$1",
    )
    .bind(target_slot)
    .fetch_optional(&state.ledger)
    .await
    .map_err(DriverError::internal)?
    .ok_or_else(|| DriverError::internal("retained runtime is absent"))?;
    let old_container = state.config.docker_resource(format!("odoo-{old_slot}"));
    let retained = inspect_container(state, &old_container).await?;
    if retained.pointer("/State/Running").and_then(Value::as_bool) != Some(false) {
        return Err(DriverError::internal("retained runtime is active"));
    }
    observe_retained_policy(state, &old_container, &retained).await?;

    for tenant in &tenants {
        if !database_access_matches(
            state,
            &tenant.database_ref,
            &runtime_role,
            files.runtime_password.expose(),
        )
        .await?
        {
            return Err(DriverError::internal("database authority drifted"));
        }
        super::release::verify_release_database_identity(
            state,
            &tenant.database_ref,
            tenant.workshop_id,
            request.manifest,
        )
        .await?;
        if !super::release::observe_release_runtime_identity_once(
            state,
            &runtime_container,
            tenant.workshop_id,
            &tenant.database_ref,
            files.tenant_bridge_token(tenant.workshop_id)?,
        )
        .await?
        {
            return Err(DriverError::internal("candidate readiness drifted"));
        }
    }
    if files.route_digest.as_deref()
        != Some(
            request
                .gateway_identity
                .gateway_configuration_digest
                .as_str(),
        )
    {
        return Err(DriverError::internal("gateway routes drifted"));
    }
    gateway::observe_running_release_gateway_generation(state, request.gateway_identity).await?;

    Ok(VerifiedReleaseRuntimeObservation {
        protocol_version: 1,
        odoo_manifest_digest: runtime_platform.manifest_digest.clone(),
        odoo_config_digest: runtime_platform.config_digest.clone(),
        extension_manifest_digest: extension_platform.manifest_digest.clone(),
        extension_config_digest: extension_platform.config_digest.clone(),
        payload_digest: extension_platform.payload_digest.clone(),
        extension_volume,
        runtime_container,
        runtime_config_digest,
        external_executor_quiescent: true,
        candidate_runtime_verified: true,
        gateway_identity_verified: true,
        target_database_access_verified: true,
        old_runtime_retired: true,
        tenant_recovery_verified: true,
        candidate_smoke_verified: true,
        candidate_restart_policy: "unless-stopped".into(),
        retained_restart_policy: "no".into(),
        observed_gateway_configuration_digest: request
            .gateway_identity
            .gateway_configuration_digest
            .clone(),
        observed_target_slot: request.target_slot,
        runtime_role,
        prepared_tenants,
        tenant_snapshot,
        pair_qualification_digest: pair.qualification_digest.clone(),
    })
}

fn validate_request(request: &ReleaseRuntimeObservationRequest<'_>) -> Result<(), DriverError> {
    request.manifest.validate().map_err(DriverError::internal)?;
    if request.fleet_run_id.is_nil()
        || request.release_id.is_empty()
        || request.release_id != request.manifest.release_id
        || request.control_operation_id.is_nil()
        || request.driver_operation_id.is_nil()
        || request.original_instance_owner.is_nil()
        || request.original_global_fence_token <= 0
        || request.gateway_identity.fleet_run_id != request.fleet_run_id
        || request.gateway_identity.original_driver_fence_token
            != request.original_global_fence_token
        || request.gateway_identity.target_slot != request.target_slot
        || !request.expected_tenant_snapshot.is_array()
    {
        return Err(DriverError::internal(
            "release runtime observation request is invalid",
        ));
    }
    Ok(())
}

async fn load_verified_tenants(
    state: &DriverState,
    request: &ReleaseRuntimeObservationRequest<'_>,
) -> Result<Vec<ObservedTenant>, DriverError> {
    let tenants = sqlx::query_as::<_, ObservedTenant>(
        "select adoption.id adoption_id,adoption.workshop_id,adoption.database_id,
                database.database_ref,database.public_hostname,recovery.component_scope
           from control.tenant_release_adoptions adoption
           join control.odoo_databases database on database.id=adoption.database_id
             and database.workshop_id=adoption.workshop_id
           join control.workshop_recovery_points recovery on recovery.id=adoption.backup_recovery_id
             and recovery.workshop_id=adoption.workshop_id
          where adoption.operation_id=$1 and adoption.release_id=$2 and adoption.state='prepared'
            and adoption.verified_at is not null and recovery.state='ready'
            and recovery.verification_state='verified' and recovery.verified_at is not null
            and (recovery.expires_at is null or recovery.expires_at>now())
          order by adoption.created_at,adoption.id limit 501",
    )
    .bind(request.control_operation_id)
    .bind(request.release_id)
    .fetch_all(&state.ledger)
    .await
    .map_err(DriverError::internal)?;
    if tenants.is_empty() || tenants.len() > crate::release::MAX_FLEET_TENANTS {
        return Err(DriverError::internal(
            "release runtime prepared tenant set is incomplete",
        ));
    }
    Ok(tenants)
}

fn tenant_evidence(tenants: &[ObservedTenant]) -> (Value, Value) {
    let prepared = Value::Array(
        tenants
            .iter()
            .map(|tenant| {
                json!({"adoption_id":tenant.adoption_id,"workshop_id":tenant.workshop_id,
                    "database_id":tenant.database_id,"database_ref":tenant.database_ref,
                    "public_hostname":tenant.public_hostname})
            })
            .collect(),
    );
    let mut snapshot = tenants.iter().collect::<Vec<_>>();
    snapshot.sort_by_key(|tenant| (tenant.workshop_id, tenant.database_id));
    let snapshot = Value::Array(
        snapshot
            .into_iter()
            .map(|tenant| {
                json!({"workshop_id":tenant.workshop_id,"database_id":tenant.database_id,
                    "database_ref":tenant.database_ref,
                    "paperless_enabled":tenant.component_scope.iter().any(|value| value=="paperless")})
            })
            .collect(),
    );
    (prepared, snapshot)
}

fn runtime_inspect_matches(
    inspect: &Value,
    image: &str,
    image_config: &str,
    runtime_config: &str,
    volume: &str,
) -> bool {
    inspect.pointer("/State/Running").and_then(Value::as_bool) == Some(true)
        && inspect.pointer("/Config/Image").and_then(Value::as_str) == Some(image)
        && inspect.get("Image").and_then(Value::as_str) == Some(image_config)
        && inspect
            .pointer("/Config/Labels/mb.config-digest")
            .and_then(Value::as_str)
            == Some(runtime_config)
        && inspect
            .get("Mounts")
            .and_then(Value::as_array)
            .is_some_and(|mounts| {
                mounts.iter().any(|mount| {
                    (mount.get("Name").and_then(Value::as_str) == Some(volume)
                        || mount.get("Source").and_then(Value::as_str) == Some(volume))
                        && mount.get("Destination").and_then(Value::as_str)
                            == Some("/opt/mb-extension")
                        && mount.get("RW").and_then(Value::as_bool) == Some(false)
                })
            })
}

async fn inspect_container(state: &DriverState, name: &str) -> Result<Value, DriverError> {
    match &state.backend {
        RuntimeBackend::Docker => docker_inspect_container(state, name).await,
        RuntimeBackend::Quadlet(backend) => backend.inspect_container(name).await,
    }
}

async fn observe_candidate_policy(
    state: &DriverState,
    container: &str,
    inspect: &Value,
) -> Result<(), DriverError> {
    match &state.backend {
        RuntimeBackend::Docker
            if docker_client::observed_restart_policy(inspect) != Some("unless-stopped") =>
        {
            Err(DriverError::internal("candidate restart policy drifted"))
        }
        RuntimeBackend::Quadlet(backend) if !backend.container_boot_selected(container).await? => {
            Err(DriverError::internal("candidate is not boot-selected"))
        }
        _ => Ok(()),
    }
}

async fn observe_retained_policy(
    state: &DriverState,
    container: &str,
    inspect: &Value,
) -> Result<(), DriverError> {
    match &state.backend {
        RuntimeBackend::Docker if docker_client::observed_restart_policy(inspect) != Some("no") => {
            Err(DriverError::internal("retained restart policy drifted"))
        }
        RuntimeBackend::Quadlet(backend) if backend.container_boot_selected(container).await? => {
            Err(DriverError::internal("retained runtime is boot-selected"))
        }
        _ => Ok(()),
    }
}

async fn database_access_matches(
    state: &DriverState,
    database: &str,
    target_role: &str,
    target_password: &str,
) -> Result<bool, DriverError> {
    if !safe_pg_identifier(database) || !safe_pg_identifier(target_role) {
        return Ok(false);
    }
    let acl_matches = sqlx::query_scalar::<_, bool>(
        "select has_database_privilege($1,$2,'CONNECT')
             and not has_database_privilege('odoo',$2,'CONNECT')
             and not exists(
                 select 1 from pg_catalog.pg_database database,
                      lateral aclexplode(coalesce(database.datacl,
                          acldefault('d',database.datdba))) privilege
                  where database.datname=$2 and privilege.grantee=0
                    and privilege.privilege_type='CONNECT')
             and not exists(
                 select 1 from pg_catalog.pg_roles role
                  where role.rolname like 'mb_runtime_%' and role.rolname<>$1
                    and has_database_privilege(role.rolname,$2,'CONNECT'))",
    )
    .bind(target_role)
    .bind(database)
    .fetch_one(&state.postgres)
    .await
    .map_err(DriverError::internal)?;
    if !acl_matches {
        return Ok(false);
    }
    let options = state
        .config
        .postgres_admin_url
        .parse::<PgConnectOptions>()
        .map_err(DriverError::internal)?
        .username(target_role)
        .password(target_password)
        .database(database)
        .application_name("mb-release-runtime-observation-v1");
    let pool = tokio::time::timeout(
        Duration::from_secs(10),
        PgPoolOptions::new()
            .max_connections(1)
            .connect_with(options),
    )
    .await
    .map_err(|_| DriverError::internal("target runtime database connection timed out"))?
    .map_err(DriverError::internal)?;
    let identity = sqlx::query_as::<_, (String, String)>("select current_user,current_database()")
        .fetch_one(&pool)
        .await
        .map_err(DriverError::internal)?;
    pool.close().await;
    Ok(identity.0 == target_role && identity.1 == database)
}

fn valid_runtime_container(value: &str, target_slot: &str) -> bool {
    let suffix = format!("-odoo-{target_slot}");
    let Some(prefix) = value.strip_suffix(&suffix) else {
        return false;
    };
    !prefix.is_empty()
        && value.len() <= 127
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn validate_digest(value: &str) -> Result<(), DriverError> {
    if value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(DriverError::internal(
            "release runtime observation digest is invalid",
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use super::*;

    struct ObservationFixture {
        root: PathBuf,
        runtime_credential: PathBuf,
        tenant_secrets: PathBuf,
        route_root: PathBuf,
    }

    impl ObservationFixture {
        fn new() -> Self {
            let root = std::env::temp_dir()
                .join(format!("mb-release-runtime-observation-{}", Uuid::new_v4()));
            let runtime_credential = root.join("runtime-password");
            let tenant_secrets = root.join("tenant-secrets");
            let route_root = root.join("routes");
            std::fs::create_dir_all(route_root.join("generations/candidate")).unwrap();
            std::fs::create_dir_all(&tenant_secrets).unwrap();
            std::fs::write(&runtime_credential, "runtime-secret\n").unwrap();
            symlink("generations/candidate", route_root.join("current")).unwrap();
            Self {
                root,
                runtime_credential,
                tenant_secrets,
                route_root,
            }
        }

        fn add_tenant(&self, workshop: Uuid, route: &[u8], token: &str) {
            let secrets = self.tenant_secrets.join(workshop.to_string());
            std::fs::create_dir(&secrets).unwrap();
            std::fs::write(secrets.join("odoo"), token).unwrap();
            std::fs::write(
                self.route_root
                    .join("generations/candidate")
                    .join(format!("{workshop}.conf")),
                route,
            )
            .unwrap();
        }
    }

    impl Drop for ObservationFixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    struct ScriptedFs {
        extra_workshop: Option<Uuid>,
        empty_token: bool,
    }

    #[async_trait]
    impl ReleaseRuntimeObservationFsPort for ScriptedFs {
        async fn load(
            &self,
            workshops: &[Uuid],
        ) -> Result<ReleaseRuntimeObservationFiles, DriverError> {
            let mut tenant_bridge_tokens = workshops
                .iter()
                .copied()
                .map(|workshop| {
                    (
                        workshop,
                        SecretText(if self.empty_token {
                            String::new()
                        } else {
                            "tenant-token".into()
                        }),
                    )
                })
                .collect::<HashMap<_, _>>();
            if let Some(extra) = self.extra_workshop {
                tenant_bridge_tokens.insert(extra, SecretText("extra-token".into()));
            }
            Ok(ReleaseRuntimeObservationFiles {
                runtime_password: SecretText("runtime-password".into()),
                tenant_bridge_tokens,
                route_digest: Some(format!("sha256:{}", "a".repeat(64))),
            })
        }
    }

    fn candidate() -> Value {
        json!({"State":{"Running":true},"Image":"sha256:image-config",
            "Config":{"Image":"image","Labels":{"mb.config-digest":"sha256:runtime"}},
            "Mounts":[{"Name":"volume","Destination":"/opt/mb-extension","RW":false}]})
    }

    fn verified() -> VerifiedReleaseRuntimeObservation {
        VerifiedReleaseRuntimeObservation {
            protocol_version: 1,
            odoo_manifest_digest: format!("sha256:{}", "1".repeat(64)),
            odoo_config_digest: format!("sha256:{}", "2".repeat(64)),
            extension_manifest_digest: format!("sha256:{}", "3".repeat(64)),
            extension_config_digest: format!("sha256:{}", "4".repeat(64)),
            payload_digest: format!("sha256:{}", "5".repeat(64)),
            extension_volume: "mb-control-ext-3333333333333333-5555555555555555".into(),
            runtime_container: "mb-control-odoo-blue".into(),
            runtime_config_digest: format!("sha256:{}", "6".repeat(64)),
            external_executor_quiescent: true,
            candidate_runtime_verified: true,
            gateway_identity_verified: true,
            target_database_access_verified: true,
            old_runtime_retired: true,
            tenant_recovery_verified: true,
            candidate_smoke_verified: true,
            candidate_restart_policy: "unless-stopped".into(),
            retained_restart_policy: "no".into(),
            observed_gateway_configuration_digest: format!("sha256:{}", "7".repeat(64)),
            observed_target_slot: ReleaseTargetSlot::Blue,
            runtime_role: "mb_runtime_1111111111111111".into(),
            prepared_tenants: json!([]),
            tenant_snapshot: json!([]),
            pair_qualification_digest: format!("sha256:{}", "8".repeat(64)),
        }
    }

    #[test]
    fn runtime_inspection_is_exact() {
        let inspect = candidate();
        assert!(runtime_inspect_matches(
            &inspect,
            "image",
            "sha256:image-config",
            "sha256:runtime",
            "volume"
        ));
        for pointer in [
            "/State/Running",
            "/Image",
            "/Config/Image",
            "/Config/Labels/mb.config-digest",
            "/Mounts/0/Name",
            "/Mounts/0/Destination",
            "/Mounts/0/RW",
        ] {
            let mut drifted = inspect.clone();
            *drifted.pointer_mut(pointer).unwrap() = Value::Null;
            assert!(
                !runtime_inspect_matches(
                    &drifted,
                    "image",
                    "sha256:image-config",
                    "sha256:runtime",
                    "volume"
                ),
                "accepted drift at {pointer}"
            );
        }
    }

    #[test]
    fn tenant_evidence_preserves_adoption_order_and_sorts_snapshot_identity() {
        let first_workshop = Uuid::parse_str("20000000-0000-4000-8000-000000000002").unwrap();
        let second_workshop = Uuid::parse_str("10000000-0000-4000-8000-000000000001").unwrap();
        let tenants = vec![
            ObservedTenant {
                adoption_id: Uuid::new_v4(),
                workshop_id: first_workshop,
                database_id: Uuid::new_v4(),
                database_ref: "mb_first".into(),
                public_hostname: "first.example.test".into(),
                component_scope: vec!["odoo".into()],
            },
            ObservedTenant {
                adoption_id: Uuid::new_v4(),
                workshop_id: second_workshop,
                database_id: Uuid::new_v4(),
                database_ref: "mb_second".into(),
                public_hostname: "second.example.test".into(),
                component_scope: vec!["odoo".into(), "paperless".into()],
            },
        ];
        let (prepared, snapshot) = tenant_evidence(&tenants);
        assert_eq!(prepared[0]["workshop_id"], json!(first_workshop));
        assert_eq!(prepared[1]["workshop_id"], json!(second_workshop));
        assert_eq!(snapshot[0]["workshop_id"], json!(second_workshop));
        assert_eq!(snapshot[0]["paperless_enabled"], json!(true));
        assert_eq!(snapshot[1]["workshop_id"], json!(first_workshop));
        assert_eq!(snapshot[1]["paperless_enabled"], json!(false));
    }

    #[test]
    fn filesystem_snapshot_loads_exact_tenant_keys_and_route_bytes() {
        let fixture = ObservationFixture::new();
        let first = Uuid::parse_str("10000000-0000-4000-8000-000000000001").unwrap();
        let second = Uuid::parse_str("20000000-0000-4000-8000-000000000002").unwrap();
        fixture.add_tenant(first, b"server { return 204; }\n", "first-token\n");
        fixture.add_tenant(second, b"server { return 204; }\n", "second-token\n");

        let files = load_release_runtime_observation_files(
            fixture.runtime_credential.clone(),
            fixture.tenant_secrets.clone(),
            fixture.route_root.clone(),
            &[first, second],
        )
        .unwrap();

        assert_eq!(files.runtime_password.expose(), "runtime-secret");
        assert_eq!(files.tenant_bridge_token(first).unwrap(), "first-token");
        assert_eq!(files.tenant_bridge_token(second).unwrap(), "second-token");
        assert!(
            files
                .route_digest
                .as_deref()
                .is_some_and(|digest| { digest.starts_with("sha256:") && digest.len() == 71 })
        );
        assert!(files.validate_for(&[first, second]).is_ok());
        assert!(files.validate_for(&[first]).is_err());
    }

    #[test]
    fn filesystem_snapshot_fails_closed_on_duplicates_secrets_and_maintenance() {
        let fixture = ObservationFixture::new();
        let workshop = Uuid::new_v4();
        fixture.add_tenant(
            workshop,
            b"server { add_header Retry-After 60; return 503; }\n",
            "tenant-token",
        );
        assert!(
            load_release_runtime_observation_files(
                fixture.runtime_credential.clone(),
                fixture.tenant_secrets.clone(),
                fixture.route_root.clone(),
                &[workshop, workshop],
            )
            .is_err()
        );
        let files = load_release_runtime_observation_files(
            fixture.runtime_credential.clone(),
            fixture.tenant_secrets.clone(),
            fixture.route_root.clone(),
            &[workshop],
        )
        .unwrap();
        assert_eq!(files.route_digest, None);

        std::fs::write(&fixture.runtime_credential, "").unwrap();
        assert!(
            load_release_runtime_observation_files(
                fixture.runtime_credential.clone(),
                fixture.tenant_secrets.clone(),
                fixture.route_root.clone(),
                &[workshop],
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn filesystem_port_cannot_return_partial_or_cross_tenant_evidence() {
        let workshop = Uuid::new_v4();
        assert!(
            load_verified_release_runtime_files(
                &ScriptedFs {
                    extra_workshop: Some(Uuid::new_v4()),
                    empty_token: false,
                },
                &[workshop],
            )
            .await
            .is_err()
        );
        assert!(
            load_verified_release_runtime_files(
                &ScriptedFs {
                    extra_workshop: None,
                    empty_token: true,
                },
                &[workshop],
            )
            .await
            .is_err()
        );
    }

    #[test]
    fn verified_recovery_payload_is_exact_and_names_are_closed() {
        assert!(valid_runtime_container("mb-control-odoo-blue", "blue"));
        assert!(!valid_runtime_container("mb_control-odoo-blue", "blue"));
        assert!(!valid_runtime_container("-odoo-blue", "blue"));
        let value = verified().as_database_value().unwrap();
        assert_eq!(value.as_object().unwrap().len(), 20);
        assert!(value.get("runtime_role").is_none());
        assert!(value.get("prepared_tenants").is_none());
        assert!(value.get("tenant_snapshot").is_none());
        assert!(value.get("pair_qualification_digest").is_none());
        let source = include_str!("release_runtime_observation.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        for forbidden in [
            "ensure_release_runtime(",
            "run_docker_job(",
            "docker_create_container(",
            "docker_start_container(",
            "docker_stop_container(",
            "docker_delete_container(",
            "docker_ensure_restart_policy(",
            "set_odoo_boot_selected(",
            "activate_release_routes(",
            "publish_release_gateway_identity(",
            "block_on(",
        ] {
            assert!(
                !production.contains(forbidden),
                "runtime observer must remain read-only: {forbidden}"
            );
        }
        let async_observer = production
            .split("async fn observe_release_runtime_with_fs")
            .nth(1)
            .unwrap();
        assert!(!async_observer.contains("std::fs::"));
        assert!(!async_observer.contains("selected_route_root("));
        assert_eq!(production.matches("spawn_blocking(").count(), 1);
        let adapter = include_str!("release_route_recovery_db.rs");
        assert!(!adapter.contains("struct ReleaseRecoveryRuntimeObservation"));
        assert!(adapter.contains("observation: &VerifiedReleaseRuntimeObservation"));
        let span = source
            .split("name = \"deployment_driver.release_runtime.observe\"")
            .nth(1)
            .unwrap()
            .split("pub(super) async fn observe_release_runtime")
            .next()
            .unwrap();
        assert!(span.contains("driver.operation_id"));
        for sensitive in [
            "fleet_run_id",
            "workshop",
            "database",
            "hostname",
            "container",
            "volume",
            "digest",
            "token",
            "fence",
            "target_slot",
        ] {
            assert!(!span.contains(sensitive), "unsafe span field: {sensitive}");
        }
    }
}
