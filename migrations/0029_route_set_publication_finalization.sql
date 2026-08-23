-- Dormant projection-only atomic finalization and immutable result replay for
-- route-set publications. This migration deliberately supplies no activation,
-- abort, recovery claim, interrupted reconciliation, or recovery-kind
-- finalization API.

alter table control.workshop_route_set_publications
 add column final_response jsonb;

alter table control.workshop_route_set_publications
 drop constraint workshop_route_set_publications_phase_check,
 drop constraint workshop_route_set_publications_terminal_check,
 drop constraint workshop_route_set_publications_phase_evidence_check,
 add constraint workshop_route_set_publications_phase_check check(phase in (
   'staging','sealed','publication_started','observed','completed','quarantined')),
 add constraint workshop_route_set_publications_terminal_check check(
  ((phase='quarantined')=(quarantined_at is not null))
  and ((phase='quarantined')=(interrupted_phase is not null))
  and ((phase='completed')=(finished_at is not null))
  and ((phase='completed')=(final_response is not null))
  and (final_response is null or (jsonb_typeof(final_response)='object'
   and pg_column_size(final_response)<=16384))
  and ((phase='quarantined' and safe_error='route_set_publication_outcome_unknown')
   or (phase<>'quarantined' and safe_error is null))),
 add constraint workshop_route_set_publications_phase_evidence_check check(
  (phase='staging' and sealed_count is null and publication_started_at is null
   and observed_at is null and finished_at is null and final_response is null)
  or (phase='sealed' and prior_recorded_at is not null and sealed_count=snapshot_count
   and publication_started_at is null and observed_at is null and finished_at is null
   and final_response is null)
  or (phase='publication_started' and prior_recorded_at is not null
   and sealed_count=snapshot_count and publication_started_at is not null
   and observed_at is null and finished_at is null and final_response is null)
  or (phase='observed' and prior_recorded_at is not null and sealed_count=snapshot_count
   and publication_started_at is not null and observed_at is not null
   and finished_at is null and final_response is null)
  or (phase='completed' and prior_recorded_at is not null and sealed_count=snapshot_count
   and publication_started_at is not null and observed_at is not null
   and finished_at is not null and final_response is not null)
  or (phase='quarantined' and finished_at is null and final_response is null and (
   (interrupted_phase='staging' and sealed_count is null and publication_started_at is null and observed_at is null)
   or (interrupted_phase='sealed' and prior_recorded_at is not null and sealed_count=snapshot_count
    and publication_started_at is null and observed_at is null)
   or (interrupted_phase='publication_started' and prior_recorded_at is not null
    and sealed_count=snapshot_count and publication_started_at is not null and observed_at is null)
   or (interrupted_phase='observed' and prior_recorded_at is not null
    and sealed_count=snapshot_count and publication_started_at is not null and observed_at is not null))));

create or replace function control.validate_route_set_publication_phase_transition()
returns trigger language plpgsql set search_path=pg_catalog,control as $function$
declare v_target control.workshop_route_set_publication_targets%rowtype;
 v_record control.workshop_route_set_publication_records%rowtype;
 v_expected jsonb; v_expected_response jsonb;
begin
 if old.phase='completed' and new is distinct from old then
  raise exception 'completed route-set publication evidence is immutable' using errcode='55000';
 end if;
 if new.phase is distinct from old.phase and not (
   (old.phase='staging' and new.phase in ('sealed','quarantined'))
   or (old.phase='sealed' and new.phase in ('publication_started','quarantined'))
   or (old.phase='publication_started' and new.phase in ('observed','quarantined'))
   or (old.phase='observed' and new.phase in ('completed','quarantined'))) then
  raise exception 'invalid route-set publication phase transition % -> %',old.phase,new.phase using errcode='55000';
 end if;
 if old.prior_recorded_at is not null and (
   new.prior_selector is distinct from old.prior_selector
   or new.prior_directory_device is distinct from old.prior_directory_device
   or new.prior_directory_inode is distinct from old.prior_directory_inode
   or new.prior_loaded_identity is distinct from old.prior_loaded_identity
   or new.prior_recorded_at is distinct from old.prior_recorded_at) then
  raise exception 'route-set prior evidence is immutable' using errcode='55000';
 end if;
 if old.sealed_count is not null and (
   new.sealed_count is distinct from old.sealed_count
   or new.sealed_present_count is distinct from old.sealed_present_count
   or new.route_set_digest is distinct from old.route_set_digest
   or new.candidate_directory_device is distinct from old.candidate_directory_device
   or new.candidate_directory_inode is distinct from old.candidate_directory_inode) then
  raise exception 'route-set seal evidence is immutable' using errcode='55000';
 end if;
 if old.publication_started_at is not null and
   new.publication_started_at is distinct from old.publication_started_at then
  raise exception 'route-set publication-start evidence is immutable' using errcode='55000';
 end if;
 if old.observed_at is not null and (
   new.observed_selector is distinct from old.observed_selector
   or new.observed_loaded_identity is distinct from old.observed_loaded_identity
   or new.observed_at is distinct from old.observed_at) then
  raise exception 'route-set observation evidence is immutable' using errcode='55000';
 end if;
 if old.finished_at is not null and (
   new.finished_at is distinct from old.finished_at
   or new.final_response is distinct from old.final_response) then
  raise exception 'route-set final evidence is immutable' using errcode='55000';
 end if;
 if old.quarantined_at is not null and (
   new.interrupted_phase is distinct from old.interrupted_phase
   or new.quarantined_at is distinct from old.quarantined_at
   or new.safe_error is distinct from old.safe_error) then
  raise exception 'route-set quarantine evidence is immutable' using errcode='55000';
 end if;
 if new.observed_at is not null then
  select * into strict v_target from control.workshop_route_set_publication_targets
   where publication_id=new.publication_id;
  v_expected:=jsonb_build_object('protocol_version',1,'publication_id',new.publication_id,
   'publication_kind',new.publication_kind,'global_fence_token',new.original_global_fence_token,
   'target_workshop_id',new.target_workshop_id,
   'target_route_fence_token',v_target.target_route_fence_token,
   'route_set_digest',new.route_set_digest);
  if new.observed_selector is distinct from new.selector
   or new.observed_loaded_identity is distinct from v_expected then
   raise exception 'route-set observed identity is not exact' using errcode='55000';
  end if;
 end if;
 if new.phase='completed' then
  select * into strict v_record from control.workshop_route_set_publication_records
   where publication_id=new.publication_id and workshop_id=new.target_workshop_id;
  v_expected_response:=jsonb_build_object('outcome','applied','workshop_id',v_target.workshop_id,
   'route_evidence',jsonb_build_object(
    'driver_operation_id',new.driver_operation_id,'workshop_id',v_target.workshop_id,
    'route_generation',v_target.target_generation,
    'projection_digest',v_target.target_projection_digest,
    'disposition',v_target.target_disposition,'rendered_digest',v_record.rendered_digest,
    'route_fence_token',v_target.target_route_fence_token),
   'route_set_evidence',jsonb_build_object(
    'protocol_version',new.protocol_version,'publication_id',new.publication_id,
    'publication_kind',new.publication_kind,'selector',new.selector,
    'route_set_digest',new.route_set_digest,'snapshot_count',new.snapshot_count,
    'present_count',new.sealed_present_count,
    'global_fence_token',new.original_global_fence_token,
    'directory_device',new.candidate_directory_device,
    'directory_inode',new.candidate_directory_inode));
  if new.publication_kind<>'projection'
   or new.final_response is distinct from v_expected_response
   or not exists(select 1 from control.deployment_driver_operations driver
    where driver.id=new.driver_operation_id and driver.state='succeeded'
     and driver.response is not distinct from v_expected_response
     and driver.execution_token is null and driver.lease_expires_at is null)
   or not exists(select 1 from control.workshop_route_projection_state state
    where state.workshop_id=v_target.workshop_id
     and state.desired_generation=v_target.target_generation
     and state.desired_digest=v_target.target_projection_digest
     and state.desired_disposition=v_target.target_disposition
     and state.applied_generation=v_target.target_generation
     and state.applied_digest=v_target.target_projection_digest
     and state.applied_disposition=v_target.target_disposition
     and state.applied_rendered_digest=v_record.rendered_digest
     and state.applied_driver_operation_id=new.driver_operation_id
     and state.applied_effect_run_id is null
     and state.applied_fence_token=v_target.target_route_fence_token)
   or not exists(select 1 from control.deployment_driver_resource_leases lease
    where lease.resource_key='runtime/shared-odoo' and lease.state='idle'
     and lease.authority_kind is null and lease.route_set_publication_id is null
     and lease.driver_operation_id is null and lease.effect_run_id is null
     and lease.lease_owner is null and lease.lease_token is null
     and lease.lease_expires_at is null and lease.fence_token=new.original_global_fence_token)
   or not exists(select 1 from control.workshop_route_application_leases lease
    where lease.workshop_id=v_target.workshop_id and lease.state='idle'
     and lease.authority_kind is null and lease.route_set_publication_id is null
     and lease.driver_operation_id is null and lease.effect_run_id is null
     and lease.release_publication_id is null and lease.lease_owner is null
     and lease.lease_token is null and lease.lease_expires_at is null
     and lease.fence_token=v_target.target_route_fence_token) then
   raise exception 'route-set final receipt is not exact' using errcode='55000';
  end if;
 end if;
 return new;
end $function$;

create function control.finish_route_set_publication(
 p_publication_id uuid,p_instance_owner uuid,p_execution_token uuid,
 p_global_lease_token uuid,p_route_lease_token uuid,p_global_fence_token bigint,
 p_target_route_fence_token bigint
) returns table(outcome text,response jsonb)
language plpgsql security definer set search_path=pg_catalog,control as $function$
declare
 v_lookup control.workshop_route_set_publications%rowtype;
 v_upstream control.operations%rowtype;
 v_global control.deployment_driver_resource_leases%rowtype;
 v_route control.workshop_route_application_leases%rowtype;
 v_driver control.deployment_driver_operations%rowtype;
 v_publication control.workshop_route_set_publications%rowtype;
 v_target control.workshop_route_set_publication_targets%rowtype;
 v_state control.workshop_route_projection_state%rowtype;
 v_record control.workshop_route_set_publication_records%rowtype;
 v_protocol text; v_count integer; v_present integer; v_digest text;
 v_expected_identity jsonb; v_response jsonb; v_changed integer;
begin
 if p_publication_id is null or p_instance_owner is null or p_execution_token is null
  or p_global_lease_token is null or p_route_lease_token is null
  or p_global_fence_token is null or p_global_fence_token<=0
  or p_target_route_fence_token is null or p_target_route_fence_token<=0 then
  return query select 'invalid',null::jsonb; return;
 end if;
 select * into v_lookup from control.workshop_route_set_publications
  where publication_id=p_publication_id;
 if not found then return query select 'invalid',null::jsonb; return; end if;

 -- Global lock order shared by admission, renewal, quarantine and finalization.
 select * into v_upstream from control.operations where id=v_lookup.control_operation_id for update;
 select mode into strict v_protocol from control.route_set_publication_protocol_state
  where singleton for update;
 select * into v_global from control.deployment_driver_resource_leases
  where resource_key='runtime/shared-odoo' for update;
 select * into v_route from control.workshop_route_application_leases
  where workshop_id=v_lookup.target_workshop_id for update;
 select * into v_driver from control.deployment_driver_operations
  where id=v_lookup.driver_operation_id for update;
 select * into strict v_publication from control.workshop_route_set_publications
  where publication_id=p_publication_id for update;
 select * into strict v_target from control.workshop_route_set_publication_targets
  where publication_id=p_publication_id;
 select * into v_state from control.workshop_route_projection_state
  where workshop_id=v_publication.target_workshop_id for update;
 select * into v_record from control.workshop_route_set_publication_records
  where publication_id=p_publication_id and workshop_id=v_publication.target_workshop_id for update;

 if v_publication.original_instance_owner is distinct from p_instance_owner
  or v_publication.original_execution_token is distinct from p_execution_token
  or v_publication.original_global_lease_token is distinct from p_global_lease_token
  or v_publication.original_route_lease_token is distinct from p_route_lease_token
  or v_publication.original_global_fence_token is distinct from p_global_fence_token
  or v_target.target_route_fence_token is distinct from p_target_route_fence_token then
  return query select case when v_publication.phase='completed' then 'conflict'
   else 'authority_lost' end,null::jsonb; return;
 end if;
 if v_publication.phase='completed' then
  return query select 'replay',v_publication.final_response; return;
 end if;
 if v_publication.publication_kind<>'projection' then
  return query select 'invalid',null::jsonb; return;
 end if;
 if v_publication.phase<>'observed' then
  return query select 'wrong_phase',null::jsonb; return;
 end if;
 if v_protocol<>'generation_v1'
  or v_upstream.state<>'in_flight'
  or v_upstream.attempt<>v_publication.control_operation_attempt
  or v_upstream.workshop_id is distinct from v_publication.target_workshop_id
  or v_upstream.leased_by is distinct from v_publication.control_operation_lease_owner
  or v_upstream.lease_expires_at<=now()
  or not ((v_upstream.kind='tenant.provision' and v_upstream.queue='tenant-provisioning')
   or (v_upstream.kind in ('tenant.reconcile','module.enable','module.restrict','webshop-domain.reconcile')
    and v_upstream.queue='tenant-reconciliation')
   or (v_upstream.kind='tenant.lifecycle' and v_upstream.queue='tenant-lifecycle'))
  or v_driver.state<>'in_progress' or v_driver.safe_error is not null
  or v_driver.action<>'route-project'
  or v_driver.workshop_id is distinct from v_publication.target_workshop_id
  or v_driver.control_operation_id is distinct from v_publication.control_operation_id
  or v_driver.control_operation_attempt is distinct from v_publication.control_operation_attempt
  or v_driver.control_operation_lease_owner is distinct from v_publication.control_operation_lease_owner
  or v_driver.target_key is distinct from 'route/'||v_publication.target_workshop_id::text
  or v_driver.execution_token is distinct from p_execution_token
  or v_driver.lease_expires_at<=now()
  or v_global.state<>'held' or v_global.authority_kind<>'route-set-publication'
  or v_global.route_set_publication_id is distinct from p_publication_id
  or v_global.lease_owner is distinct from p_instance_owner
  or v_global.lease_token is distinct from p_global_lease_token
  or v_global.fence_token is distinct from p_global_fence_token
  or v_global.lease_expires_at<=now()
  or v_route.state<>'held' or v_route.authority_kind<>'route-set-publication'
  or v_route.route_set_publication_id is distinct from p_publication_id
  or v_route.lease_owner is distinct from p_instance_owner
  or v_route.lease_token is distinct from p_route_lease_token
  or v_route.fence_token is distinct from p_target_route_fence_token
  or v_route.lease_expires_at<=now()
  or v_route.generation is distinct from v_target.target_generation
  or v_route.projection_digest is distinct from v_target.target_projection_digest
  or v_driver.route_generation is distinct from v_target.target_generation
  or v_driver.route_projection_digest is distinct from v_target.target_projection_digest
  or v_driver.route_fence_token is distinct from p_target_route_fence_token then
  return query select 'authority_lost',null::jsonb; return;
 end if;

 select count(*),count(*) filter(where disposition='present') into v_count,v_present
  from control.workshop_route_set_publication_records where publication_id=p_publication_id;
 select control.route_set_publication_digest(p_publication_id) into v_digest;
 v_expected_identity:=jsonb_build_object('protocol_version',1,'publication_id',p_publication_id,
  'publication_kind','projection','global_fence_token',p_global_fence_token,
  'target_workshop_id',v_target.workshop_id,
  'target_route_fence_token',p_target_route_fence_token,
  'route_set_digest',v_publication.route_set_digest);
 if v_count<>v_publication.snapshot_count or v_count<>v_publication.sealed_count
  or v_present<>v_publication.sealed_present_count
  or v_digest is distinct from v_publication.route_set_digest
  or v_publication.observed_selector is distinct from v_publication.selector
  or v_publication.observed_loaded_identity is distinct from v_expected_identity
  or v_record.publication_id is null
  or v_record.generation is distinct from v_target.target_generation
  or v_record.projection_digest is distinct from v_target.target_projection_digest
  or v_record.disposition is distinct from v_target.target_disposition
  or v_record.applied_rendered_digest is distinct from v_target.prior_applied_rendered_digest then
  return query select 'authority_lost',null::jsonb; return;
 end if;

 v_response:=jsonb_build_object('outcome','applied','workshop_id',v_target.workshop_id,
  'route_evidence',jsonb_build_object(
   'driver_operation_id',v_driver.id,'workshop_id',v_target.workshop_id,
   'route_generation',v_target.target_generation,
   'projection_digest',v_target.target_projection_digest,
   'disposition',v_target.target_disposition,'rendered_digest',v_record.rendered_digest,
   'route_fence_token',v_target.target_route_fence_token),
  'route_set_evidence',jsonb_build_object(
   'protocol_version',v_publication.protocol_version,'publication_id',v_publication.publication_id,
   'publication_kind',v_publication.publication_kind,'selector',v_publication.selector,
   'route_set_digest',v_publication.route_set_digest,'snapshot_count',v_publication.snapshot_count,
   'present_count',v_publication.sealed_present_count,
   'global_fence_token',v_publication.original_global_fence_token,
   'directory_device',v_publication.candidate_directory_device,
   'directory_inode',v_publication.candidate_directory_inode));

 update control.deployment_driver_operations set state='succeeded',response=v_response,
  safe_error=null,execution_token=null,lease_expires_at=null,updated_at=now()
 where id=v_driver.id and state='in_progress' and execution_token=p_execution_token
  and lease_expires_at>now() and route_generation=v_target.target_generation
  and route_projection_digest=v_target.target_projection_digest
  and route_fence_token=p_target_route_fence_token;
 get diagnostics v_changed=row_count;
 if v_changed<>1 then raise exception 'route-set driver finalization drifted' using errcode='40001'; end if;

 update control.workshop_route_projection_state set
  applied_generation=v_target.target_generation,applied_digest=v_target.target_projection_digest,
  applied_disposition=v_target.target_disposition,
  applied_rendered_digest=v_record.rendered_digest,
  applied_driver_operation_id=v_driver.id,applied_effect_run_id=null,
  applied_fence_token=v_target.target_route_fence_token,updated_at=now()
 where workshop_id=v_target.workshop_id
  and desired_generation=v_target.target_generation
  and desired_digest=v_target.target_projection_digest
  and desired_disposition=v_target.target_disposition
  and applied_generation=v_target.prior_applied_generation
  and applied_digest=v_target.prior_applied_digest
  and applied_disposition=v_target.prior_applied_disposition
  and applied_rendered_digest=v_target.prior_applied_rendered_digest
  and applied_driver_operation_id is not distinct from v_target.prior_applied_driver_operation_id
  and applied_effect_run_id is not distinct from v_target.prior_applied_effect_run_id
  and applied_fence_token=v_target.prior_applied_fence_token;
 get diagnostics v_changed=row_count;
 if v_changed<>1 then raise exception 'route-set target projection CAS drifted' using errcode='40001'; end if;

 update control.workshop_route_application_leases set state='idle',initialization_required=false,
  driver_operation_id=null,generation=null,projection_digest=null,lease_owner=null,lease_token=null,
  lease_expires_at=null,heartbeat_at=null,quarantined_at=null,safe_error=null,updated_at=now()
 where workshop_id=v_target.workshop_id and state='held' and authority_kind='route-set-publication'
  and route_set_publication_id=p_publication_id and lease_owner=p_instance_owner
  and lease_token=p_route_lease_token and fence_token=p_target_route_fence_token;
 get diagnostics v_changed=row_count;
 if v_changed<>1 then raise exception 'route-set target lease release drifted' using errcode='40001'; end if;

 update control.deployment_driver_resource_leases set state='idle',driver_operation_id=null,
  lease_owner=null,lease_token=null,lease_expires_at=null,heartbeat_at=null,
  quarantined_at=null,safe_error=null,updated_at=now()
 where resource_key='runtime/shared-odoo' and state='held'
  and authority_kind='route-set-publication' and route_set_publication_id=p_publication_id
  and lease_owner=p_instance_owner and lease_token=p_global_lease_token
  and fence_token=p_global_fence_token;
 get diagnostics v_changed=row_count;
 if v_changed<>1 then raise exception 'route-set global lease release drifted' using errcode='40001'; end if;

 update control.workshop_route_set_publications set phase='completed',finished_at=now(),
  final_response=v_response,updated_at=now()
 where publication_id=p_publication_id and phase='observed' and finished_at is null
  and final_response is null;
 get diagnostics v_changed=row_count;
 if v_changed<>1 then raise exception 'route-set publication completion drifted' using errcode='40001'; end if;
 return query select 'completed',v_response;
end $function$;

create function control.read_route_set_publication_result(
 p_control_operation_id uuid,p_workshop_id uuid,p_idempotency_key text,p_request_digest text
) returns table(outcome text,publication_id uuid,driver_operation_id uuid,response jsonb)
language plpgsql stable security definer set search_path=pg_catalog,control as $function$
declare v_driver control.deployment_driver_operations%rowtype;
 v_publication control.workshop_route_set_publications%rowtype;
begin
 if p_control_operation_id is null or p_workshop_id is null or p_idempotency_key is null
  or length(p_idempotency_key) not between 1 and 180
  or p_request_digest is null or p_request_digest !~ '^[0-9a-f]{64}$' then
  return query select 'absent',null::uuid,null::uuid,null::jsonb; return;
 end if;
 select * into v_driver from control.deployment_driver_operations driver
  where driver.workshop_id=p_workshop_id and driver.action='route-project'
   and driver.idempotency_key=p_idempotency_key;
 if not found then
  return query select 'absent',null::uuid,null::uuid,null::jsonb; return;
 end if;
 select * into v_publication from control.workshop_route_set_publications publication
  where publication.driver_operation_id=v_driver.id;
 if not found or v_driver.control_operation_id is distinct from p_control_operation_id
  or v_driver.request_digest is distinct from p_request_digest then
  return query select 'conflict',null::uuid,null::uuid,null::jsonb; return;
 end if;
 if v_publication.phase='completed' then
  return query select 'completed',v_publication.publication_id,v_driver.id,v_publication.final_response; return;
 end if;
 return query select 'pending',v_publication.publication_id,v_driver.id,null::jsonb;
end $function$;

revoke all on function control.finish_route_set_publication(uuid,uuid,uuid,uuid,uuid,bigint,bigint) from public;
revoke all on function control.read_route_set_publication_result(uuid,uuid,text,text) from public;

do $migration$ declare v_role text; begin
 foreach v_role in array array['control_api','control_tenant_api','control_membership_worker','control_provisioning_worker',
  'control_invoice_worker','control_inventory_worker','control_email_worker','control_reconciliation_worker',
  'control_lifecycle_worker','control_backup_scheduler','control_driver_ledger','control_release_worker','control_privacy_worker'] loop
  if exists(select 1 from pg_roles where rolname=v_role) then
   execute format('revoke all on function control.finish_route_set_publication(uuid,uuid,uuid,uuid,uuid,bigint,bigint) from %I',v_role);
   execute format('revoke all on function control.read_route_set_publication_result(uuid,uuid,text,text) from %I',v_role);
  end if;
 end loop;
 if exists(select 1 from pg_roles where rolname='control_driver_ledger') then
  grant execute on function control.finish_route_set_publication(uuid,uuid,uuid,uuid,uuid,bigint,bigint) to control_driver_ledger;
  grant execute on function control.read_route_set_publication_result(uuid,uuid,text,text) to control_driver_ledger;
 end if;
end $migration$;

comment on table control.workshop_route_set_publications is
'Dormant immutable full-fleet route-set evidence through projection-only atomic finalization and exact result replay; activation and recovery finalization are absent.';
