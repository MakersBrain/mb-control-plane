-- Dormant protocol-v2 release route publication finalization.
--
-- The deployment driver owns this transaction only through its durable
-- response.  The release worker remains the sole owner of the subsequent
-- tenant/runtime/release/fleet-run activation transaction.

alter table control.fleet_release_route_publications
  add column completed_at timestamptz,
  drop constraint fleet_release_route_publications_prior_identity_check,
  drop constraint fleet_release_route_publications_prior_selector_identity_check,
  drop constraint fleet_release_route_publications_phase_check,
  drop constraint fleet_release_route_publications_terminal_check,
  drop constraint fleet_release_route_publications_phase_shape_check,
  add constraint fleet_release_route_publications_phase_check check(phase in (
    'maintenance_staging','maintenance_sealed','maintenance_publication_started',
    'maintenance_observed','candidate_staging','candidate_sealed',
    'candidate_publication_started','awaiting_worker_finalize','completed','quarantined')),
  add constraint fleet_release_route_publications_terminal_check check(
    (phase not in ('awaiting_worker_finalize','completed') or
      (candidate_observed_at is not null and candidate_publication_started_at is not null
       and external_effects_started_at is not null))
    and ((phase='completed')=(completed_at is not null))
    and (phase<>'quarantined' or (quarantined_at is not null
      and safe_error='release_route_publication_outcome_unknown'))
    and ((phase='quarantined')=(quarantined_at is not null))
    and ((phase='quarantined')=(safe_error is not null))
    and ((phase='quarantined')=(interrupted_phase is not null))
    and (phase='maintenance_staging'
      or (phase='quarantined' and interrupted_phase='maintenance_staging')
      or prior_recorded_at is not null)),
  add constraint fleet_release_route_publications_phase_shape_check check(
    (phase='maintenance_staging' and maintenance_sealed_count is null
      and maintenance_route_set_digest is null and maintenance_directory_device is null
      and maintenance_directory_inode is null
      and maintenance_publication_started_at is null and maintenance_observed_at is null
      and external_effects_started_at is null and candidate_sealed_count is null
      and candidate_count=0 and candidate_route_set_digest is null
      and candidate_directory_device is null and candidate_directory_inode is null
      and candidate_publication_started_at is null and candidate_observed_at is null)
    or (phase='maintenance_sealed' and maintenance_sealed_count is not null
      and maintenance_route_set_digest is not null and maintenance_directory_device is not null
      and maintenance_directory_inode is not null
      and maintenance_publication_started_at is null and maintenance_observed_at is null
      and external_effects_started_at is null and candidate_count=0
      and candidate_sealed_count is null and candidate_route_set_digest is null
      and candidate_directory_device is null and candidate_directory_inode is null
      and candidate_publication_started_at is null and candidate_observed_at is null)
    or (phase='maintenance_publication_started' and maintenance_sealed_count is not null
      and maintenance_route_set_digest is not null and maintenance_directory_device is not null
      and maintenance_directory_inode is not null
      and maintenance_publication_started_at is not null and maintenance_observed_at is null
      and external_effects_started_at is null and candidate_count=0
      and candidate_sealed_count is null and candidate_route_set_digest is null
      and candidate_directory_device is null and candidate_directory_inode is null
      and candidate_publication_started_at is null and candidate_observed_at is null)
    or (phase='maintenance_observed' and maintenance_observed_at is not null
      and maintenance_publication_started_at is not null and external_effects_started_at is null
      and maintenance_sealed_count is not null and maintenance_route_set_digest is not null
      and maintenance_directory_device is not null and maintenance_directory_inode is not null
      and candidate_count=0
      and candidate_sealed_count is null and candidate_route_set_digest is null
      and candidate_directory_device is null and candidate_directory_inode is null
      and candidate_publication_started_at is null and candidate_observed_at is null)
    or (phase='candidate_staging' and maintenance_observed_at is not null
      and maintenance_sealed_count is not null and maintenance_route_set_digest is not null
      and maintenance_directory_device is not null and maintenance_directory_inode is not null
      and maintenance_publication_started_at is not null
      and external_effects_started_at is not null and candidate_sealed_count is null
      and candidate_route_set_digest is null and candidate_directory_device is null
      and candidate_directory_inode is null and candidate_publication_started_at is null
      and candidate_observed_at is null)
    or (phase='candidate_sealed' and external_effects_started_at is not null
      and maintenance_observed_at is not null and maintenance_sealed_count is not null
      and maintenance_route_set_digest is not null and maintenance_directory_device is not null
      and maintenance_directory_inode is not null and maintenance_publication_started_at is not null
      and candidate_sealed_count is not null and candidate_route_set_digest is not null
      and candidate_directory_device is not null and candidate_directory_inode is not null
      and candidate_publication_started_at is null
      and candidate_observed_at is null)
    or (phase='candidate_publication_started' and candidate_sealed_count is not null
      and candidate_route_set_digest is not null and candidate_directory_device is not null
      and candidate_directory_inode is not null and maintenance_observed_at is not null
      and maintenance_sealed_count is not null and maintenance_route_set_digest is not null
      and maintenance_directory_device is not null and maintenance_directory_inode is not null
      and maintenance_publication_started_at is not null and external_effects_started_at is not null
      and candidate_publication_started_at is not null and candidate_observed_at is null)
    or (phase in ('awaiting_worker_finalize','completed')
      and maintenance_observed_at is not null and maintenance_sealed_count is not null
      and maintenance_route_set_digest is not null and maintenance_directory_device is not null
      and maintenance_directory_inode is not null and maintenance_publication_started_at is not null
      and external_effects_started_at is not null and candidate_sealed_count is not null
      and candidate_route_set_digest is not null and candidate_directory_device is not null
      and candidate_directory_inode is not null and candidate_publication_started_at is not null
      and candidate_observed_at is not null)
    or (phase='quarantined' and (
      (interrupted_phase='maintenance_staging' and maintenance_sealed_count is null
        and maintenance_route_set_digest is null and maintenance_directory_device is null
        and maintenance_directory_inode is null and maintenance_publication_started_at is null
        and maintenance_observed_at is null and external_effects_started_at is null
        and candidate_count=0 and candidate_sealed_count is null
        and candidate_route_set_digest is null and candidate_directory_device is null
        and candidate_directory_inode is null and candidate_publication_started_at is null
        and candidate_observed_at is null)
      or (interrupted_phase='maintenance_sealed' and maintenance_sealed_count is not null
        and maintenance_route_set_digest is not null and maintenance_directory_device is not null
        and maintenance_directory_inode is not null and maintenance_publication_started_at is null
        and maintenance_observed_at is null and external_effects_started_at is null
        and candidate_count=0 and candidate_sealed_count is null
        and candidate_route_set_digest is null and candidate_directory_device is null
        and candidate_directory_inode is null and candidate_publication_started_at is null
        and candidate_observed_at is null)
      or (interrupted_phase='maintenance_publication_started' and maintenance_sealed_count is not null
        and maintenance_route_set_digest is not null and maintenance_directory_device is not null
        and maintenance_directory_inode is not null and maintenance_publication_started_at is not null
        and maintenance_observed_at is null and external_effects_started_at is null
        and candidate_count=0 and candidate_sealed_count is null
        and candidate_route_set_digest is null and candidate_directory_device is null
        and candidate_directory_inode is null and candidate_publication_started_at is null
        and candidate_observed_at is null)
      or (interrupted_phase='maintenance_observed' and maintenance_observed_at is not null
        and maintenance_sealed_count is not null and maintenance_route_set_digest is not null
        and maintenance_directory_device is not null and maintenance_directory_inode is not null
        and maintenance_publication_started_at is not null and external_effects_started_at is null
        and candidate_count=0 and candidate_sealed_count is null
        and candidate_route_set_digest is null and candidate_directory_device is null
        and candidate_directory_inode is null and candidate_publication_started_at is null
        and candidate_observed_at is null)
      or (interrupted_phase='candidate_staging' and maintenance_observed_at is not null
        and maintenance_sealed_count is not null and maintenance_route_set_digest is not null
        and maintenance_directory_device is not null and maintenance_directory_inode is not null
        and maintenance_publication_started_at is not null and external_effects_started_at is not null
        and candidate_sealed_count is null and candidate_route_set_digest is null
        and candidate_directory_device is null and candidate_directory_inode is null
        and candidate_publication_started_at is null and candidate_observed_at is null)
      or (interrupted_phase='candidate_sealed' and maintenance_observed_at is not null
        and maintenance_sealed_count is not null and maintenance_route_set_digest is not null
        and maintenance_directory_device is not null and maintenance_directory_inode is not null
        and maintenance_publication_started_at is not null and external_effects_started_at is not null
        and candidate_sealed_count is not null and candidate_route_set_digest is not null
        and candidate_directory_device is not null and candidate_directory_inode is not null
        and candidate_publication_started_at is null and candidate_observed_at is null)
      or (interrupted_phase='candidate_publication_started' and maintenance_observed_at is not null
        and maintenance_sealed_count is not null and maintenance_route_set_digest is not null
        and maintenance_directory_device is not null and maintenance_directory_inode is not null
        and maintenance_publication_started_at is not null and external_effects_started_at is not null
        and candidate_sealed_count is not null and candidate_route_set_digest is not null
        and candidate_directory_device is not null and candidate_directory_inode is not null
        and candidate_publication_started_at is not null and candidate_observed_at is null)
      or (interrupted_phase='awaiting_worker_finalize' and maintenance_observed_at is not null
        and maintenance_sealed_count is not null and maintenance_route_set_digest is not null
        and maintenance_directory_device is not null and maintenance_directory_inode is not null
        and maintenance_publication_started_at is not null and external_effects_started_at is not null
        and candidate_sealed_count is not null and candidate_route_set_digest is not null
        and candidate_directory_device is not null and candidate_directory_inode is not null
        and candidate_publication_started_at is not null and candidate_observed_at is not null))));

-- Release v2 can start from a generation produced by any universal writer.
-- The shared helper is closed over legacy startup, release, and universal
-- identities; BootLive remains the single selector for which NULL identity is
-- valid.  The existing prior_check still requires positive device/inode.
alter table control.fleet_release_route_publications
  add constraint fleet_release_route_publications_prior_selector_identity_check
  check(prior_recorded_at is null
    or control.valid_route_set_prior_selector_identity(prior_selector,prior_loaded_identity)),
  add constraint fleet_release_route_publications_completion_identity_key
    unique(driver_operation_id,fleet_run_id);

create table control.fleet_release_route_publication_completions (
  driver_operation_id uuid primary key,
  fleet_run_id uuid not null unique,
  candidate_selector text not null,
  candidate_directory_device bigint not null,
  candidate_directory_inode bigint not null,
  candidate_route_set_digest text not null,
  target_slot text not null,
  original_global_fence_token bigint not null,
  stored_response jsonb not null,
  completed_at timestamptz not null default now(),
  constraint fleet_release_route_publication_completions_publication_fkey
    foreign key(driver_operation_id,fleet_run_id)
    references control.fleet_release_route_publications(driver_operation_id,fleet_run_id) on delete restrict,
  constraint fleet_release_route_publication_completions_run_fkey
    foreign key(fleet_run_id) references control.release_fleet_runs(id) on delete restrict,
  constraint fleet_release_route_publication_completions_shape_check check(
    candidate_selector ~ '^generations/release-[0-9a-f]{32}-candidate$'
    and candidate_directory_device>0 and candidate_directory_inode>0
    and candidate_route_set_digest ~ '^sha256:[0-9a-f]{64}$'
    and target_slot in ('blue','green') and original_global_fence_token>0
    and jsonb_typeof(stored_response)='object'
    and pg_column_size(stored_response)<=1048576
    and stored_response ?& array['evidence']
    and stored_response-array['evidence']='{}'::jsonb
    and jsonb_typeof(stored_response->'evidence')='object')
);

create trigger fleet_release_route_publication_completions_immutable
before update or delete on control.fleet_release_route_publication_completions
for each row execute function control.reject_release_route_publication_identity_mutation();

create or replace function control.validate_release_route_publication_update()
returns trigger language plpgsql set search_path=pg_catalog,control as $function$
begin
 if new.driver_operation_id<>old.driver_operation_id or new.fleet_run_id<>old.fleet_run_id
  or new.protocol_version<>old.protocol_version or new.original_instance_owner<>old.original_instance_owner
  or new.original_execution_token<>old.original_execution_token
  or new.original_global_lease_token<>old.original_global_lease_token
  or new.original_route_lease_token<>old.original_route_lease_token
  or new.original_global_fence_token<>old.original_global_fence_token
  or new.control_operation_id<>old.control_operation_id
  or new.control_operation_attempt<>old.control_operation_attempt
  or new.control_operation_lease_owner<>old.control_operation_lease_owner
  or new.target_slot<>old.target_slot or new.snapshot_count<>old.snapshot_count
  or new.maintenance_selector<>old.maintenance_selector or new.candidate_selector<>old.candidate_selector
  or new.created_at<>old.created_at then raise exception 'release route publication identity is immutable' using errcode='55000'; end if;
 if old.prior_recorded_at is not null and (new.prior_recorded_at is distinct from old.prior_recorded_at
  or new.prior_selector is distinct from old.prior_selector or new.prior_directory_device is distinct from old.prior_directory_device
  or new.prior_directory_inode is distinct from old.prior_directory_inode or new.prior_loaded_identity is distinct from old.prior_loaded_identity)
  then raise exception 'release route prior identity is immutable' using errcode='55000'; end if;
 if old.maintenance_sealed_count is not null and (new.maintenance_sealed_count is distinct from old.maintenance_sealed_count
  or new.maintenance_route_set_digest is distinct from old.maintenance_route_set_digest
  or new.maintenance_directory_device is distinct from old.maintenance_directory_device
  or new.maintenance_directory_inode is distinct from old.maintenance_directory_inode)
  then raise exception 'maintenance seal is immutable' using errcode='55000'; end if;
 if old.candidate_sealed_count is not null and (new.candidate_sealed_count is distinct from old.candidate_sealed_count
  or new.candidate_route_set_digest is distinct from old.candidate_route_set_digest
  or new.candidate_directory_device is distinct from old.candidate_directory_device
  or new.candidate_directory_inode is distinct from old.candidate_directory_inode)
  then raise exception 'candidate seal is immutable' using errcode='55000'; end if;
 if old.maintenance_publication_started_at is not null and new.maintenance_publication_started_at is distinct from old.maintenance_publication_started_at
  or old.maintenance_observed_at is not null and new.maintenance_observed_at is distinct from old.maintenance_observed_at
  or old.external_effects_started_at is not null and new.external_effects_started_at is distinct from old.external_effects_started_at
  or old.candidate_publication_started_at is not null and new.candidate_publication_started_at is distinct from old.candidate_publication_started_at
  or old.candidate_observed_at is not null and new.candidate_observed_at is distinct from old.candidate_observed_at
  or old.completed_at is not null and new.completed_at is distinct from old.completed_at
  or old.quarantined_at is not null and new.quarantined_at is distinct from old.quarantined_at then
  raise exception 'release route publication timestamps are immutable' using errcode='55000'; end if;
 if old.interrupted_phase is not null and new.interrupted_phase is distinct from old.interrupted_phase then
  raise exception 'release route interrupted phase is immutable' using errcode='55000'; end if;
 if new.maintenance_count not between old.maintenance_count and old.maintenance_count+1
   or new.candidate_count not between old.candidate_count and old.candidate_count+1 then
  raise exception 'release route record cursor is append-only' using errcode='55000'; end if;
 if not (new.phase=old.phase or (old.phase,new.phase) in (
   ('maintenance_staging','maintenance_sealed'),('maintenance_sealed','maintenance_publication_started'),
   ('maintenance_publication_started','maintenance_observed'),('maintenance_observed','candidate_staging'),
   ('candidate_staging','candidate_sealed'),('candidate_sealed','candidate_publication_started'),
   ('candidate_publication_started','awaiting_worker_finalize'),('awaiting_worker_finalize','completed'),
   ('maintenance_publication_started','quarantined'),('maintenance_staging','quarantined'),
   ('maintenance_sealed','quarantined'),('maintenance_observed','quarantined'),
   ('candidate_staging','quarantined'),('candidate_sealed','quarantined'),
   ('candidate_publication_started','quarantined'),('awaiting_worker_finalize','quarantined')))
 then raise exception 'invalid release route publication transition' using errcode='55000'; end if;
 return new;
end $function$;

create function control.finish_immutable_release_route_publication(
 p_driver_operation_id uuid,p_instance_owner uuid,p_execution_token uuid,
 p_global_lease_token uuid,p_route_lease_token uuid,p_global_fence_token bigint,
 p_response jsonb
) returns table(outcome text,stored_response jsonb)
language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_publication control.fleet_release_route_publications%rowtype;
 v_operation control.deployment_driver_operations%rowtype;
 v_upstream control.operations%rowtype; v_run control.release_fleet_runs%rowtype;
 v_release control.application_releases%rowtype;
 v_intent control.fleet_activation_intents%rowtype; v_evidence jsonb;
 v_expected_prepared jsonb; v_exact integer; v_changed integer;
begin
 select * into v_publication from control.fleet_release_route_publications
  where driver_operation_id=p_driver_operation_id;
 if not found then return query select 'not_found',null::jsonb; return; end if;
 if v_publication.original_instance_owner<>p_instance_owner
  or v_publication.original_execution_token<>p_execution_token
  or v_publication.original_global_lease_token<>p_global_lease_token
  or v_publication.original_route_lease_token<>p_route_lease_token
  or v_publication.original_global_fence_token<>p_global_fence_token then
  return query select 'conflict',null::jsonb; return;
 end if;
 if v_publication.phase='completed' then
  return query select case when completion.stored_response=p_response then 'replay' else 'conflict' end,
   completion.stored_response from control.fleet_release_route_publication_completions completion
   where completion.driver_operation_id=p_driver_operation_id; return;
 end if;
 if jsonb_typeof(p_response) is distinct from 'object'
  or p_response-array['evidence']<>'{}'::jsonb
  or not (p_response ?& array['evidence'])
  or jsonb_typeof(p_response->'evidence') is distinct from 'object'
  or pg_column_size(p_response)>1048576 then
  return query select 'invalid',null::jsonb; return;
 end if;
 v_evidence:=p_response->'evidence';
 if (select count(*) from jsonb_object_keys(v_evidence))<>30
  or not (v_evidence ?& array['release_id','odoo_subject_digest','extension_subject_digest',
   'odoo_manifest_digest','odoo_config_digest','extension_manifest_digest','extension_config_digest',
   'payload_digest','extension_volume','pair_qualification_digest','bridge_contract_digest',
   'installed_addon_versions','runtime_key','target_slot','runtime_container','runtime_role',
   'runtime_deployment_ref','runtime_config_digest','prepared_tenants','fleet_generation',
   'tenant_snapshot','gateway_configuration_digest','driver_action_id','driver_operation_id',
   'driver_fence_token','old_runtime_database_access_revoked','tenant_recovery_verified',
   'candidate_smoke_verified','candidate_restart_policy','retained_restart_policy']) then
  return query select 'invalid',null::jsonb; return;
 end if;
 if exists(select 1 from unnest(array[
   'release_id','odoo_subject_digest','extension_subject_digest','odoo_manifest_digest',
   'odoo_config_digest','extension_manifest_digest','extension_config_digest','payload_digest',
   'extension_volume','pair_qualification_digest','bridge_contract_digest','runtime_key',
   'target_slot','runtime_container','runtime_role','runtime_deployment_ref',
   'runtime_config_digest','gateway_configuration_digest','candidate_restart_policy',
   'retained_restart_policy']) key
   where jsonb_typeof(v_evidence->key) is distinct from 'string')
  or jsonb_typeof(v_evidence->'fleet_generation') is distinct from 'number'
  or jsonb_typeof(v_evidence->'driver_action_id') is distinct from 'string'
  or jsonb_typeof(v_evidence->'driver_operation_id') is distinct from 'string'
  or jsonb_typeof(v_evidence->'driver_fence_token') is distinct from 'number' then
  return query select 'invalid',null::jsonb; return;
 end if;

 -- The existing release acquisition order is upstream, global, route leases,
 -- driver, run/publication.  Every close follows the same order.
 select * into v_upstream from control.operations where id=v_publication.control_operation_id for update;
 perform 1 from control.deployment_driver_resource_leases
  where resource_key='runtime/shared-odoo' for update;
 perform 1 from control.fleet_release_route_publication_owners owner
  join control.workshop_route_application_leases lease using(workshop_id)
  where owner.driver_operation_id=p_driver_operation_id order by owner.workshop_id for update of lease;
 select * into v_operation from control.deployment_driver_operations
  where id=p_driver_operation_id for update;
 select release.* into v_release from control.application_releases release
  join control.release_fleet_runs run on run.release_id=release.id
  where run.id=v_publication.fleet_run_id for update of release;
 select * into v_run from control.release_fleet_runs where id=v_publication.fleet_run_id for update;
 select * into v_publication from control.fleet_release_route_publications
  where driver_operation_id=p_driver_operation_id for update;
 if v_publication.phase='completed' then
  return query select case when completion.stored_response=p_response then 'replay' else 'conflict' end,
   completion.stored_response from control.fleet_release_route_publication_completions completion
   where completion.driver_operation_id=p_driver_operation_id; return;
 end if;
 if v_publication.phase<>'awaiting_worker_finalize' then
  return query select 'wrong_phase',null::jsonb; return;
 end if;
 if v_upstream.id is null or v_upstream.kind<>'odoo.release.adopt' or v_upstream.queue<>'release-adoption'
  or v_upstream.workshop_id is not null or v_upstream.state<>'in_flight'
  or v_upstream.attempt<>v_publication.control_operation_attempt
  or v_upstream.leased_by<>v_publication.control_operation_lease_owner
  or v_upstream.lease_expires_at<=now() or v_upstream.payload->>'phase'<>'adopt'
  or v_operation.state<>'in_progress' or v_operation.safe_error is not null
  or v_operation.execution_token<>p_execution_token or v_operation.lease_expires_at<=now()
  or v_operation.release_executor_protocol_version<>1
  or v_operation.release_route_snapshot_protocol_version<>2
  or v_run.state not in ('preparing','activating')
  or v_run.driver_fence_token<>p_global_fence_token then
  return query select 'authority_lost',null::jsonb; return;
 end if;
 if not exists(select 1 from control.deployment_driver_resource_leases global_lease
  where global_lease.resource_key='runtime/shared-odoo' and global_lease.state='held'
   and global_lease.authority_kind='release' and global_lease.driver_operation_id=p_driver_operation_id
   and global_lease.lease_owner=p_instance_owner and global_lease.lease_token=p_global_lease_token
   and global_lease.fence_token=p_global_fence_token and global_lease.lease_expires_at>now()) then
  return query select 'authority_lost',null::jsonb; return;
 end if;
 select count(*) into v_exact from control.fleet_release_route_publication_owners owner
 join control.fleet_release_route_publication_records record
  on record.driver_operation_id=owner.driver_operation_id and record.workshop_id=owner.workshop_id
  and record.overlay_kind='candidate'
 join control.workshop_route_application_leases lease on lease.workshop_id=owner.workshop_id
 join control.workshop_route_projection_state state on state.workshop_id=owner.workshop_id
 where owner.driver_operation_id=p_driver_operation_id
  and lease.state='held' and lease.authority_kind='release-overlay'
  and lease.release_publication_id=p_driver_operation_id and lease.generation=owner.generation
  and lease.projection_digest=owner.projection_digest and lease.fence_token=owner.route_fence_token
  and lease.lease_owner=p_instance_owner and lease.lease_token=p_route_lease_token and lease.lease_expires_at>now()
  and state.applied_generation=owner.generation and state.applied_digest=owner.projection_digest
  and state.applied_disposition='present' and state.applied_rendered_digest=record.rendered_digest
  and state.applied_driver_operation_id=p_driver_operation_id and state.applied_effect_run_id is null
  and state.applied_fence_token=owner.route_fence_token
  and state.desired_generation=owner.generation and state.desired_digest=owner.projection_digest
  and state.desired_disposition='present';
 if v_exact<>v_publication.snapshot_count then
  return query select 'state_drift',null::jsonb; return;
 end if;
 select * into v_intent from control.fleet_activation_intents
  where fleet_run_id=v_run.id and release_id=v_run.release_id and runtime_key='shared-odoo'
   and target_slot=v_publication.target_slot and driver_fence_token=p_global_fence_token
   and gateway_identity_version=1 and abandoned_at is null for update;
 if not found
  or v_intent.observed_configuration_digest is distinct from v_intent.gateway_configuration_digest
  or v_intent.activated_at is null then
  return query select 'state_drift',null::jsonb; return;
 end if;
 select coalesce(jsonb_agg(jsonb_build_object('adoption_id',adoption.id,
  'workshop_id',adoption.workshop_id,'database_id',adoption.database_id,
  'database_ref',database.database_ref,'public_hostname',database.public_hostname)
  order by adoption.created_at,adoption.id),'[]'::jsonb) into v_expected_prepared
 from control.tenant_release_adoptions adoption join control.odoo_databases database
  on database.id=adoption.database_id and database.workshop_id=adoption.workshop_id
 where adoption.operation_id=v_upstream.id and adoption.release_id=v_run.release_id
  and adoption.state='prepared';
 if v_intent.prepared_tenants is distinct from v_expected_prepared
  or jsonb_array_length(v_expected_prepared)<>jsonb_array_length(v_run.tenant_snapshot)
  or jsonb_array_length(v_expected_prepared) not between 1 and 500
  or v_release.id is null or v_release.id<>v_run.release_id
  or v_release.odoo_subject_digest<>v_intent.odoo_subject_digest
  or v_release.extension_subject_digest<>v_intent.extension_subject_digest
  or v_evidence->>'release_id' is distinct from v_run.release_id
  or v_evidence->>'runtime_key' is distinct from 'shared-odoo'
  or v_evidence->>'target_slot' is distinct from v_publication.target_slot
  or v_evidence->>'odoo_subject_digest' is distinct from v_intent.odoo_subject_digest
  or v_evidence->>'extension_subject_digest' is distinct from v_intent.extension_subject_digest
  or v_evidence->>'pair_qualification_digest' is distinct from v_intent.pair_qualification_digest
  or v_evidence->'prepared_tenants' is distinct from v_expected_prepared
  or v_evidence->'tenant_snapshot' is distinct from v_run.tenant_snapshot
  or v_evidence->'fleet_generation' is distinct from to_jsonb(v_run.fleet_generation)
  or v_evidence->>'gateway_configuration_digest' is distinct from v_intent.gateway_configuration_digest
  or v_evidence->'driver_action_id' is distinct from to_jsonb(v_intent.driver_action_id)
  or v_evidence->'driver_operation_id' is distinct from to_jsonb(p_driver_operation_id)
  or v_evidence->'driver_fence_token' is distinct from to_jsonb(p_global_fence_token)
  or v_evidence->'old_runtime_database_access_revoked' is distinct from 'true'::jsonb
  or v_evidence->'tenant_recovery_verified' is distinct from 'true'::jsonb
  or v_evidence->'candidate_smoke_verified' is distinct from 'true'::jsonb
  or v_evidence->>'candidate_restart_policy' is distinct from 'unless-stopped'
  or v_evidence->>'retained_restart_policy' is distinct from 'no'
  or jsonb_typeof(v_evidence->'installed_addon_versions') is distinct from 'object'
  or jsonb_typeof(v_evidence->'prepared_tenants') is distinct from 'array'
  or jsonb_typeof(v_evidence->'tenant_snapshot') is distinct from 'array'
  or (v_evidence->>'odoo_manifest_digest' ~ '^sha256:[0-9a-f]{64}$') is distinct from true
  or (v_evidence->>'odoo_config_digest' ~ '^sha256:[0-9a-f]{64}$') is distinct from true
  or (v_evidence->>'extension_manifest_digest' ~ '^sha256:[0-9a-f]{64}$') is distinct from true
  or (v_evidence->>'extension_config_digest' ~ '^sha256:[0-9a-f]{64}$') is distinct from true
  or (v_evidence->>'payload_digest' ~ '^sha256:[0-9a-f]{64}$') is distinct from true
  or (v_evidence->>'bridge_contract_digest' ~ '^sha256:[0-9a-f]{64}$') is distinct from true
  or (v_evidence->>'runtime_config_digest' ~ '^sha256:[0-9a-f]{64}$') is distinct from true
  or (v_evidence->>'extension_volume' ~
      ('^mb-(control-|dev[1-4]-)?ext-'||substr(v_evidence->>'extension_manifest_digest',8,16)
       ||'-'||substr(v_evidence->>'payload_digest',8,16)||'$')) is distinct from true
  or (v_evidence->>'runtime_container' ~
      ('^[a-z0-9][a-z0-9-]{0,110}-odoo-'||v_publication.target_slot||'$')) is distinct from true
  or v_evidence->>'runtime_role' is distinct from
      'mb_runtime_'||substr(v_intent.odoo_subject_digest,8,16)
  or v_evidence->>'runtime_deployment_ref' is distinct from
      v_release.manifest->'odoo_runtime'->>'deployment_ref' then
  return query select 'invalid',null::jsonb; return;
 end if;

 insert into control.fleet_release_route_publication_completions(
  driver_operation_id,fleet_run_id,candidate_selector,candidate_directory_device,
  candidate_directory_inode,candidate_route_set_digest,target_slot,
  original_global_fence_token,stored_response)
 values(p_driver_operation_id,v_run.id,v_publication.candidate_selector,
  v_publication.candidate_directory_device,v_publication.candidate_directory_inode,
  v_publication.candidate_route_set_digest,v_publication.target_slot,
  p_global_fence_token,p_response);
 update control.deployment_driver_operations set state='succeeded',response=p_response,
  safe_error=null,execution_token=null,lease_expires_at=null,updated_at=now()
 where id=p_driver_operation_id and state='in_progress' and execution_token=p_execution_token
  and lease_expires_at>now(); get diagnostics v_changed=row_count;
 if v_changed<>1 then raise exception 'release driver completion drifted' using errcode='40001'; end if;
 update control.workshop_route_application_leases lease set state='idle',authority_kind=null,
  release_publication_id=null,generation=null,projection_digest=null,lease_owner=null,
  lease_token=null,lease_expires_at=null,heartbeat_at=null,quarantined_at=null,
  safe_error=null,initialization_required=false,updated_at=now()
 from control.fleet_release_route_publication_owners owner
 where owner.driver_operation_id=p_driver_operation_id and lease.workshop_id=owner.workshop_id
  and lease.state='held' and lease.authority_kind='release-overlay'
  and lease.release_publication_id=p_driver_operation_id and lease.fence_token=owner.route_fence_token
  and lease.lease_owner=p_instance_owner and lease.lease_token=p_route_lease_token;
 get diagnostics v_changed=row_count;
 if v_changed<>v_publication.snapshot_count then raise exception 'release route completion cardinality drifted' using errcode='40001'; end if;
 update control.deployment_driver_resource_leases set state='idle',authority_kind=null,
  driver_operation_id=null,effect_run_id=null,route_set_publication_id=null,
  lease_owner=null,lease_token=null,lease_expires_at=null,heartbeat_at=null,
  quarantined_at=null,safe_error=null,updated_at=now()
 where resource_key='runtime/shared-odoo' and state='held' and authority_kind='release'
  and driver_operation_id=p_driver_operation_id and lease_owner=p_instance_owner
  and lease_token=p_global_lease_token and fence_token=p_global_fence_token;
 get diagnostics v_changed=row_count;
 if v_changed<>1 then raise exception 'release global completion drifted' using errcode='40001'; end if;
 update control.fleet_release_route_publications set phase='completed',completed_at=now(),updated_at=now()
  where driver_operation_id=p_driver_operation_id and phase='awaiting_worker_finalize';
 get diagnostics v_changed=row_count;
 if v_changed<>1 then raise exception 'release publication completion drifted' using errcode='40001'; end if;
 return query select 'finished',p_response;
end $function$;

create function control.read_immutable_release_route_publication_result(
 p_driver_operation_id uuid,p_fleet_run_id uuid
) returns table(outcome text,stored_response jsonb)
language sql stable security definer set search_path=pg_catalog,control as $function$
 select case when publication.driver_operation_id is null then 'not_found'
   when publication.fleet_run_id<>p_fleet_run_id then 'conflict'
   when completion.driver_operation_id is not null then 'replay'
   when publication.phase='quarantined' then 'quarantined' else 'pending' end,
  case when publication.fleet_run_id=p_fleet_run_id then completion.stored_response else null end
 from (values(1)) singleton(value)
 left join control.fleet_release_route_publications publication
  on publication.driver_operation_id=p_driver_operation_id
 left join control.fleet_release_route_publication_completions completion
  on completion.driver_operation_id=publication.driver_operation_id
$function$;

revoke all on table control.fleet_release_route_publication_completions from public;
revoke all on function control.finish_immutable_release_route_publication(uuid,uuid,uuid,uuid,uuid,bigint,jsonb) from public;
revoke all on function control.read_immutable_release_route_publication_result(uuid,uuid) from public;

do $migration$ declare v_role text; begin
 foreach v_role in array array['control_api','control_tenant_api','control_membership_worker',
 'control_provisioning_worker','control_invoice_worker','control_inventory_worker',
 'control_email_worker','control_reconciliation_worker','control_lifecycle_worker',
 'control_backup_scheduler','control_driver_ledger','control_release_worker','control_privacy_worker'] loop
  if exists(select 1 from pg_roles where rolname=v_role) then
   execute format('revoke all on table control.fleet_release_route_publication_completions from %I',v_role);
  end if;
 end loop;
 if exists(select 1 from pg_roles where rolname='control_driver_ledger') then
  grant execute on function control.finish_immutable_release_route_publication(uuid,uuid,uuid,uuid,uuid,bigint,jsonb) to control_driver_ledger;
  grant execute on function control.read_immutable_release_route_publication_result(uuid,uuid) to control_driver_ledger;
 end if;
end $migration$;

comment on table control.fleet_release_route_publication_completions is
'Immutable protocol-v2 release driver receipts after exact candidate observation; release worker activation remains a separate transaction.';
