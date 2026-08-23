-- Dormant recovery-maintenance and recovery-restore route-set publications.
--
-- A publication has exactly one durable logical owner: projection publications
-- are owned by a deployment-driver operation, while recovery publications are
-- owned by the existing recovery-maintenance effect run.  This migration does
-- not change the protocol mode/readiness singleton and exposes no activation
-- or active-dispatch API.

alter table control.workshop_route_set_publications
  alter column driver_operation_id drop not null,
  drop constraint workshop_route_set_publications_driver_operation_id_key,
  add column recovery_effect_run_id uuid,
  add constraint workshop_route_set_publications_recovery_effect_fkey
    foreign key(recovery_effect_run_id)
    references control.workshop_route_effect_runs(id) on delete restrict,
  add constraint workshop_route_set_publications_owner_xor_check check(
    (publication_kind='projection' and driver_operation_id is not null
      and recovery_effect_run_id is null)
    or (publication_kind in ('recovery_maintenance','recovery_restore')
      and driver_operation_id is null and recovery_effect_run_id is not null));

create unique index workshop_route_set_publications_driver_owner
  on control.workshop_route_set_publications(driver_operation_id)
  where driver_operation_id is not null;
create unique index workshop_route_set_publications_recovery_maintenance_owner
  on control.workshop_route_set_publications(recovery_effect_run_id)
  where recovery_effect_run_id is not null and publication_kind='recovery_maintenance';
create unique index workshop_route_set_publications_recovery_restore_attempt
  on control.workshop_route_set_publications(
   recovery_effect_run_id,control_operation_id,control_operation_attempt)
  where recovery_effect_run_id is not null and publication_kind='recovery_restore';

create or replace function control.normalize_workshop_route_authority()
returns trigger language plpgsql security definer set search_path=pg_catalog,control as $function$
begin
 if old.state='maintenance' and new.state='held'
  and not ((new.authority_kind='recovery-maintenance'
      and new.effect_run_id is not distinct from old.effect_run_id)
   or (new.authority_kind='route-set-publication' and new.effect_run_id is null
      and new.route_set_publication_id is not null
      and new.fence_token is not distinct from old.fence_token
      and exists(select 1 from control.workshop_route_set_publications publication
       join control.workshop_route_set_publication_targets target using(publication_id)
       where publication.publication_id=new.route_set_publication_id
        and publication.publication_kind='recovery_restore'
        and publication.recovery_effect_run_id=old.effect_run_id
        and publication.target_workshop_id=new.workshop_id
        and target.workshop_id=new.workshop_id
        and target.target_route_fence_token=new.fence_token))) then
  raise exception 'stable maintenance authority cannot be stolen' using errcode='55000';
 end if;
 if new.state in ('idle','uninitialized') then
  new.authority_kind:=null; new.effect_run_id:=null; new.release_publication_id:=null;
  new.route_set_publication_id:=null;
 elsif new.driver_operation_id is not null and new.effect_run_id is null
   and new.release_publication_id is null and new.route_set_publication_id is null
   and new.authority_kind is null then
  new.authority_kind:=case when new.generation is null then 'legacy' else 'projection' end;
 end if;
 return new;
end $function$;

create or replace function control.validate_route_set_publication_parent_update()
returns trigger language plpgsql set search_path=pg_catalog,control as $function$
begin
 if tg_op='DELETE' then
  raise exception 'route-set publication parents are retained evidence' using errcode='55000';
 end if;
 if new.publication_id is distinct from old.publication_id
  or new.protocol_version is distinct from old.protocol_version
  or new.publication_kind is distinct from old.publication_kind
  or new.driver_operation_id is distinct from old.driver_operation_id
  or new.recovery_effect_run_id is distinct from old.recovery_effect_run_id
  or new.control_operation_id is distinct from old.control_operation_id
  or new.control_operation_attempt is distinct from old.control_operation_attempt
  or new.control_operation_lease_owner is distinct from old.control_operation_lease_owner
  or new.original_instance_owner is distinct from old.original_instance_owner
  or new.original_execution_token is distinct from old.original_execution_token
  or new.original_global_lease_token is distinct from old.original_global_lease_token
  or new.original_route_lease_token is distinct from old.original_route_lease_token
  or new.original_global_fence_token is distinct from old.original_global_fence_token
  or new.target_workshop_id is distinct from old.target_workshop_id
  or new.selector is distinct from old.selector
  or new.snapshot_count is distinct from old.snapshot_count
  or new.correlation_id is distinct from old.correlation_id
  or new.trace_parent is distinct from old.trace_parent
  or new.trace_state is distinct from old.trace_state
  or new.retention_not_before is distinct from old.retention_not_before
  or new.created_at is distinct from old.created_at then
  raise exception 'immutable route-set publication identity cannot be changed' using errcode='55000';
 end if;
 return new;
end $function$;

create or replace function control.validate_route_set_recovery_terminal_evidence()
returns trigger language plpgsql set search_path=pg_catalog,control as $function$
declare v_keys integer;
begin
 if new.recovery_terminal_at is not null then
  select count(*) into v_keys from jsonb_object_keys(new.recovery_terminal_response);
  if new.publication_kind='projection' then
   if v_keys<>11
    or new.recovery_terminal_response->>'publication_id' is distinct from new.publication_id::text
    or new.recovery_terminal_response->>'driver_operation_id' is distinct from new.driver_operation_id::text
    or new.recovery_terminal_response->>'target_workshop_id' is distinct from new.target_workshop_id::text
    or new.recovery_terminal_response->>'resolution_claim_fence' is distinct from new.recovery_terminal_claim_fence::text
    or new.recovery_terminal_response->>'resolution_kind' is distinct from new.recovery_terminal_kind
    or new.recovery_terminal_response->>'reconciliation_operation_id' is distinct from new.recovery_terminal_operation_id::text
    or new.recovery_terminal_response->>'reconciliation_operation_attempt' is distinct from new.recovery_terminal_operation_attempt::text
    or new.recovery_terminal_response->>'reconciliation_operation_lease_owner' is distinct from new.recovery_terminal_operation_lease_owner
    or new.recovery_terminal_response->>'decision_digest' is distinct from new.recovery_terminal_decision_digest
    or (new.recovery_terminal_kind='candidate' and (
      new.recovery_terminal_response->>'outcome' is distinct from 'applied_recovered'
      or jsonb_typeof(new.recovery_terminal_response->'driver_response') is distinct from 'object'))
    or (new.recovery_terminal_kind in ('prior','unstarted') and (
      new.recovery_terminal_response->>'outcome' is distinct from 'not_applied'
      or new.recovery_terminal_response->'driver_response' is distinct from 'null'::jsonb)) then
    raise exception 'route-set terminal recovery response is not exact' using errcode='55000';
   end if;
  else
   if v_keys<>12 or new.recovery_terminal_response->>'publication_id' is distinct from new.publication_id::text
    or new.recovery_terminal_response->>'effect_run_id' is distinct from new.recovery_effect_run_id::text
    or new.recovery_terminal_response->>'publication_kind' is distinct from new.publication_kind
    or new.recovery_terminal_response->>'target_workshop_id' is distinct from new.target_workshop_id::text
    or new.recovery_terminal_response->>'resolution_claim_fence' is distinct from new.recovery_terminal_claim_fence::text
    or new.recovery_terminal_response->>'resolution_kind' is distinct from new.recovery_terminal_kind
    or new.recovery_terminal_response->>'reconciliation_operation_id' is distinct from new.recovery_terminal_operation_id::text
    or new.recovery_terminal_response->>'reconciliation_operation_attempt' is distinct from new.recovery_terminal_operation_attempt::text
    or new.recovery_terminal_response->>'reconciliation_operation_lease_owner' is distinct from new.recovery_terminal_operation_lease_owner
    or new.recovery_terminal_response->>'decision_digest' is distinct from new.recovery_terminal_decision_digest
    or (new.recovery_terminal_kind='candidate' and (
      new.recovery_terminal_response->>'outcome' not in ('maintenance_recovered','restored_recovered')
      or new.recovery_terminal_response->>'outcome' is null
      or jsonb_typeof(new.recovery_terminal_response->'effect_response') is distinct from 'object'))
    or (new.recovery_terminal_kind in ('prior','unstarted') and (
      new.recovery_terminal_response->>'outcome' is distinct from 'not_applied'
      or new.recovery_terminal_response->'effect_response' is distinct from 'null'::jsonb)) then
    raise exception 'recovery-kind terminal response is not exact' using errcode='55000';
   end if;
  end if;
 end if;
 if old.recovery_terminal_at is not null and (
  new.recovery_terminal_kind is distinct from old.recovery_terminal_kind
  or new.recovery_terminal_claim_fence is distinct from old.recovery_terminal_claim_fence
  or new.recovery_terminal_operation_id is distinct from old.recovery_terminal_operation_id
  or new.recovery_terminal_operation_attempt is distinct from old.recovery_terminal_operation_attempt
  or new.recovery_terminal_operation_lease_owner is distinct from old.recovery_terminal_operation_lease_owner
  or new.recovery_terminal_decision_digest is distinct from old.recovery_terminal_decision_digest
  or new.recovery_terminal_response is distinct from old.recovery_terminal_response
  or new.recovery_terminal_at is distinct from old.recovery_terminal_at) then
  raise exception 'route-set terminal recovery evidence is immutable' using errcode='55000';
 end if;
 return new;
end $function$;

alter function control.finish_route_set_publication_recovery(
 uuid,bigint,uuid,integer,text,uuid,uuid,text,text,text
) rename to finish_route_set_publication_recovery_projection_v1;

create function control.finish_recovery_route_set_publication_recovery(
 p_publication_id uuid,p_resolution_claim_fence bigint,
 p_reconciliation_operation_id uuid,p_reconciliation_operation_attempt integer,
 p_reconciliation_operation_lease_owner text,p_reconciliation_owner uuid,
 p_reconciliation_token uuid,p_resolution_kind text,p_decision text,p_decision_digest text
) returns table(outcome text,response jsonb)
language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_publication control.workshop_route_set_publications%rowtype;
 v_target control.workshop_route_set_publication_targets%rowtype;
 v_effect control.workshop_route_effect_runs%rowtype;
 v_reservation control.workshop_route_effect_reservations%rowtype;
 v_resolution control.workshop_route_set_publication_resolutions%rowtype;
 v_reconciliation control.operations%rowtype; v_state control.workshop_route_projection_state%rowtype;
 v_record control.workshop_route_set_publication_records%rowtype;
 v_entry control.workshop_route_set_publications%rowtype;
 v_token_digest text; v_expected_decision_digest text; v_digest text;
 v_count integer; v_present integer; v_drift integer; v_changed integer;
 v_snapshot_count integer; v_record_drift integer;
 v_expected_identity jsonb; v_route_evidence jsonb; v_effect_response jsonb; v_entry_response jsonb; v_response jsonb;
begin
 if p_publication_id is null or p_resolution_claim_fence is null or p_resolution_claim_fence<=0
  or p_reconciliation_operation_id is null or p_reconciliation_operation_attempt is null
  or p_reconciliation_operation_attempt<=0 or p_reconciliation_operation_lease_owner is null
  or btrim(p_reconciliation_operation_lease_owner)='' or p_reconciliation_owner is null
  or p_reconciliation_token is null or p_resolution_kind not in ('candidate','prior','unstarted','inconclusive')
  or p_decision not in ('accept','keep_quarantined')
  or p_decision_digest is null or p_decision_digest !~ '^[0-9a-f]{64}$'
  or ((p_resolution_kind='inconclusive') is distinct from (p_decision='keep_quarantined')) then
  return query select 'invalid',null::jsonb; return;
 end if;
 select * into v_publication from control.workshop_route_set_publications
  where publication_id=p_publication_id;
 if not found then return query select 'absent',null::jsonb; return; end if;
 select * into v_resolution from control.workshop_route_set_publication_resolutions
  where publication_id=p_publication_id and reconciliation_claim_fence=p_resolution_claim_fence;
 v_token_digest:=encode(public.digest(convert_to('mb-route-set-reconciliation-token-v1','UTF8')
  ||uuid_send(p_reconciliation_token),'sha256'),'hex');
 if found then
  v_expected_decision_digest:=encode(public.digest(convert_to('mb-route-set-terminal-decision-v1','UTF8')
   ||uuid_send(p_publication_id)||int8send(p_resolution_claim_fence)
   ||uuid_send(p_reconciliation_operation_id)||int4send(p_reconciliation_operation_attempt)
   ||int4send(octet_length(convert_to(p_reconciliation_operation_lease_owner,'UTF8')))
   ||convert_to(p_reconciliation_operation_lease_owner,'UTF8')||uuid_send(p_reconciliation_owner)
   ||decode(v_token_digest,'hex')||int4send(octet_length(convert_to(p_resolution_kind,'UTF8')))
   ||convert_to(p_resolution_kind,'UTF8')||int4send(octet_length(convert_to(p_decision,'UTF8')))
   ||convert_to(p_decision,'UTF8')||public.digest(convert_to(v_resolution.evidence::text,'UTF8'),'sha256'),
   'sha256'),'hex');
 end if;
 if v_publication.recovery_terminal_at is not null then
  if v_resolution.reconciliation_owner is not distinct from p_reconciliation_owner
   and v_resolution.reconciliation_token_digest is not distinct from v_token_digest
   and v_publication.recovery_terminal_claim_fence is not distinct from p_resolution_claim_fence
   and v_publication.recovery_terminal_operation_id is not distinct from p_reconciliation_operation_id
   and v_publication.recovery_terminal_operation_attempt is not distinct from p_reconciliation_operation_attempt
   and v_publication.recovery_terminal_operation_lease_owner is not distinct from p_reconciliation_operation_lease_owner
   and v_publication.recovery_terminal_kind is not distinct from p_resolution_kind
   and v_publication.recovery_terminal_decision_digest is not distinct from p_decision_digest
   and p_decision_digest is not distinct from v_expected_decision_digest then
   return query select 'replay',v_publication.recovery_terminal_response; return;
  end if;
  return query select 'conflict',null::jsonb; return;
 end if;
 perform 1 from control.operations where id in
  (v_publication.control_operation_id,p_reconciliation_operation_id) order by id for update;
 select * into v_reconciliation from control.operations where id=p_reconciliation_operation_id;
 perform 1 from control.deployment_driver_resource_leases
  where resource_key='runtime/shared-odoo' for update;
 perform 1 from control.workshop_route_application_leases
  where workshop_id=v_publication.target_workshop_id for update;
 perform 1 from control.workshop_route_effect_runs
  where id=v_publication.recovery_effect_run_id for update;
 select * into strict v_publication from control.workshop_route_set_publications
  where publication_id=p_publication_id for update;
 select * into strict v_target from control.workshop_route_set_publication_targets
  where publication_id=p_publication_id;
 select * into strict v_effect from control.workshop_route_effect_runs
  where id=v_publication.recovery_effect_run_id for update;
 select * into strict v_reservation from control.workshop_route_effect_reservations
  where effect_run_id=v_effect.id and workshop_id=v_target.workshop_id for update;
 select * into strict v_state from control.workshop_route_projection_state
  where workshop_id=v_target.workshop_id for update;
 perform 1 from control.workshop_route_set_publication_records
  where publication_id=p_publication_id order by workshop_id for update;
 select * into v_record from control.workshop_route_set_publication_records
  where publication_id=p_publication_id and workshop_id=v_target.workshop_id;
 select * into v_resolution from control.workshop_route_set_publication_resolutions
  where publication_id=p_publication_id and reconciliation_claim_fence=p_resolution_claim_fence for update;
 if v_publication.publication_kind not in ('recovery_maintenance','recovery_restore')
  or v_publication.phase is distinct from 'quarantined' or v_effect.state is distinct from 'quarantined'
  or v_resolution.publication_id is null or v_resolution.resolution_kind is distinct from p_resolution_kind
  or v_resolution.reconciliation_operation_id is distinct from p_reconciliation_operation_id
  or v_resolution.reconciliation_operation_attempt is distinct from p_reconciliation_operation_attempt
  or v_resolution.reconciliation_operation_lease_owner is distinct from p_reconciliation_operation_lease_owner
  or v_resolution.reconciliation_owner is distinct from p_reconciliation_owner
  or v_resolution.reconciliation_token_digest is distinct from v_token_digest
  or p_decision_digest is distinct from v_expected_decision_digest
  or v_resolution.evidence->>'publication_id' is distinct from p_publication_id::text
  or v_resolution.evidence->>'claim_fence' is distinct from p_resolution_claim_fence::text
  or v_resolution.evidence->>'resolution_kind' is distinct from p_resolution_kind
  or (p_resolution_kind='prior' and (
   v_publication.prior_loaded_identity is null
   or v_publication.prior_selector='generations/boot-live'
   or not control.valid_route_set_prior_selector_identity(
    v_publication.prior_selector,v_publication.prior_loaded_identity)
   or nullif(v_resolution.evidence->'observed_loaded_identity','null'::jsonb)
      is distinct from v_publication.prior_loaded_identity))
  or v_reconciliation.id is null or v_reconciliation.kind is distinct from 'tenant.reconcile'
  or v_reconciliation.workshop_id is distinct from v_publication.target_workshop_id
  or v_reconciliation.queue is distinct from 'tenant-reconciliation'
  or v_reconciliation.state is distinct from 'in_flight'
  or v_reconciliation.attempt is distinct from p_reconciliation_operation_attempt
  or v_reconciliation.leased_by is distinct from p_reconciliation_operation_lease_owner
  or v_reconciliation.lease_expires_at<=now()
  or v_reconciliation.payload->>'route_set_publication_id' is distinct from p_publication_id::text
  or v_reconciliation.payload->>'protocol_version' is distinct from '1'
  or v_reconciliation.payload->>'route_set_resolution_claim_fence' is distinct from p_resolution_claim_fence::text
  or v_reconciliation.payload->>'route_set_resolution_kind' is distinct from p_resolution_kind
  or v_reconciliation.payload->>'route_set_terminal_decision' is distinct from p_decision
  or v_reconciliation.payload->>'route_set_terminal_decision_digest' is distinct from p_decision_digest
  or not exists(select 1 from control.deployment_driver_resource_leases lease
    where lease.resource_key='runtime/shared-odoo' and lease.state='quarantined'
     and lease.route_set_publication_id=p_publication_id and lease.fence_token=v_publication.original_global_fence_token)
  or not exists(select 1 from control.workshop_route_application_leases lease
    where lease.workshop_id=v_target.workshop_id and lease.state='quarantined'
     and lease.route_set_publication_id=p_publication_id and lease.fence_token=v_target.target_route_fence_token) then
  return query select 'authority_inconsistent',null::jsonb; return;
 end if;
 if p_resolution_kind='inconclusive' then
  return query select 'blocked',jsonb_build_object('outcome','quarantined',
   'publication_id',p_publication_id,'resolution_claim_fence',p_resolution_claim_fence,
   'resolution_kind','inconclusive','decision','keep_quarantined'); return;
 end if;
 select count(*) into v_snapshot_count from control.workshop_route_set_publication_snapshot
  where publication_id=p_publication_id;
 select count(*) into v_drift from control.workshop_route_set_publication_snapshot snapshot
 left join control.workshop_route_projection_state state on state.workshop_id=snapshot.workshop_id
 where snapshot.publication_id=p_publication_id and (
  state.workshop_id is null or state.applied_generation is distinct from snapshot.baseline_applied_generation
  or state.applied_digest is distinct from snapshot.baseline_applied_digest
  or state.applied_disposition is distinct from snapshot.baseline_applied_disposition
  or state.applied_rendered_digest is distinct from snapshot.baseline_applied_rendered_digest
  or state.applied_driver_operation_id is distinct from snapshot.baseline_applied_driver_operation_id
  or state.applied_effect_run_id is distinct from snapshot.baseline_applied_effect_run_id
  or state.applied_fence_token is distinct from snapshot.baseline_applied_fence_token
  or (p_resolution_kind='candidate' and v_publication.publication_kind='recovery_restore'
   and snapshot.is_target and (
    state.desired_generation is distinct from snapshot.generation
    or state.desired_digest is distinct from snapshot.projection_digest
    or state.desired_disposition is distinct from snapshot.disposition)));
 select count(*) into v_record_drift
 from control.workshop_route_set_publication_records record
 left join control.workshop_route_set_publication_snapshot snapshot
  on snapshot.publication_id=record.publication_id and snapshot.workshop_id=record.workshop_id
 where record.publication_id=p_publication_id and (
  snapshot.workshop_id is null
  or record.generation is distinct from snapshot.generation
  or record.projection_digest is distinct from snapshot.projection_digest
  or record.disposition is distinct from snapshot.disposition
  or record.applied_rendered_digest is distinct from snapshot.baseline_applied_rendered_digest);
 if v_snapshot_count is distinct from v_publication.snapshot_count or v_drift<>0 or v_record_drift<>0
  or not exists(select 1 from control.workshop_route_set_publication_snapshot snapshot
   where snapshot.publication_id=p_publication_id and snapshot.workshop_id=v_target.workshop_id
    and snapshot.is_target and snapshot.generation=v_target.target_generation
    and snapshot.projection_digest=v_target.target_projection_digest
    and snapshot.disposition=v_target.target_disposition) then
  return query select 'authority_inconsistent',null::jsonb; return;
 end if;
 if p_resolution_kind='candidate' then
  select count(*),count(*) filter(where disposition='present') into v_count,v_present
   from control.workshop_route_set_publication_records where publication_id=p_publication_id;
  select control.route_set_publication_digest(p_publication_id) into v_digest;
  v_expected_identity:=jsonb_build_object('protocol_version',1,'publication_id',p_publication_id,
   'publication_kind',v_publication.publication_kind,
   'global_fence_token',v_publication.original_global_fence_token,
   'target_workshop_id',v_target.workshop_id,
   'target_route_fence_token',v_target.target_route_fence_token,
   'route_set_digest',v_publication.route_set_digest);
  if v_resolution.evidence->>'observed_selector' is distinct from v_publication.selector
   or (v_resolution.evidence->>'observed_directory_device')::bigint
      is distinct from v_publication.candidate_directory_device
   or (v_resolution.evidence->>'observed_directory_inode')::bigint
      is distinct from v_publication.candidate_directory_inode
   or nullif(v_resolution.evidence->'observed_loaded_identity','null'::jsonb)
      is distinct from v_expected_identity
   or v_count<>v_publication.snapshot_count or v_count<>v_publication.sealed_count
   or v_present<>v_publication.sealed_present_count or v_digest is distinct from v_publication.route_set_digest
   or v_record.publication_id is null
   or v_record.generation is distinct from v_target.target_generation
   or v_record.projection_digest is distinct from v_target.target_projection_digest
   or v_record.disposition is distinct from v_target.target_disposition
   or v_record.applied_rendered_digest is distinct from v_target.prior_applied_rendered_digest then
   return query select 'observation_mismatch',null::jsonb; return;
  end if;
  v_route_evidence:=jsonb_build_object('effect_run_id',v_effect.id,'workshop_id',v_target.workshop_id,
   'generation',v_target.target_generation,'projection_digest',v_target.target_projection_digest,
   'disposition',v_target.target_disposition,'rendered_digest',v_record.rendered_digest,
   'route_fence_token',v_target.target_route_fence_token,'mode',
   case v_publication.publication_kind when 'recovery_maintenance' then 'maintenance' else 'restored' end);
  v_effect_response:=jsonb_build_object('outcome',case v_publication.publication_kind
    when 'recovery_maintenance' then 'maintenance' else 'restored' end,
   'effect_run_id',v_effect.id,'route_evidence',v_route_evidence,
   'route_set_evidence',jsonb_build_object('protocol_version',v_publication.protocol_version,
    'publication_id',v_publication.publication_id,'publication_kind',v_publication.publication_kind,
    'selector',v_publication.selector,'route_set_digest',v_publication.route_set_digest,
    'snapshot_count',v_publication.snapshot_count,'present_count',v_publication.sealed_present_count,
    'global_fence_token',v_publication.original_global_fence_token,
    'directory_device',v_publication.candidate_directory_device,'directory_inode',v_publication.candidate_directory_inode));
  if v_publication.publication_kind='recovery_maintenance' then
   v_effect_response:=v_effect_response||jsonb_build_object('route_fence_token',v_target.target_route_fence_token);
   update control.workshop_route_effect_reservations set state='maintenance',
    maintenance_rendered_digest=v_record.rendered_digest,maintenance_evidence=v_route_evidence,updated_at=now()
    where effect_run_id=v_effect.id and state='quarantined';
   get diagnostics v_changed=row_count;
   if v_changed<>1 then raise exception 'recovered maintenance reservation drifted' using errcode='40001'; end if;
   update control.workshop_route_effect_runs set state='maintenance',response=v_effect_response,
    safe_error='recovery_maintenance',finished_at=null,updated_at=now() where id=v_effect.id and state='quarantined';
   get diagnostics v_changed=row_count;
   if v_changed<>1 then raise exception 'recovered maintenance effect drifted' using errcode='40001'; end if;
   update control.workshop_route_application_leases set state='maintenance',
    authority_kind='recovery-maintenance',effect_run_id=v_effect.id,route_set_publication_id=null,
    lease_owner=null,heartbeat_at=now(),quarantined_at=null,safe_error='recovery_maintenance',updated_at=now()
    where workshop_id=v_target.workshop_id and state='quarantined' and route_set_publication_id=p_publication_id;
   get diagnostics v_changed=row_count;
   if v_changed<>1 then raise exception 'recovered maintenance route drifted' using errcode='40001'; end if;
  else
   update control.workshop_route_projection_state set applied_generation=v_target.target_generation,
    applied_digest=v_target.target_projection_digest,applied_disposition=v_target.target_disposition,
    applied_rendered_digest=v_record.rendered_digest,applied_driver_operation_id=null,
    applied_effect_run_id=v_effect.id,applied_fence_token=v_target.target_route_fence_token,updated_at=now()
   where workshop_id=v_target.workshop_id and desired_generation=v_target.target_generation
    and desired_digest=v_target.target_projection_digest and desired_disposition=v_target.target_disposition
    and applied_generation=v_target.prior_applied_generation and applied_digest=v_target.prior_applied_digest
    and applied_disposition=v_target.prior_applied_disposition
    and applied_rendered_digest=v_target.prior_applied_rendered_digest
    and applied_driver_operation_id is not distinct from v_target.prior_applied_driver_operation_id
    and applied_effect_run_id is not distinct from v_target.prior_applied_effect_run_id
    and applied_fence_token=v_target.prior_applied_fence_token;
   get diagnostics v_changed=row_count;
   if v_changed<>1 then raise exception 'recovered restore applied-head CAS drifted' using errcode='40001'; end if;
   update control.workshop_route_effect_reservations set state='restored',
    restored_rendered_digest=v_record.rendered_digest,restored_evidence=v_route_evidence,updated_at=now()
    where effect_run_id=v_effect.id and state='quarantined';
   get diagnostics v_changed=row_count;
   if v_changed<>1 then raise exception 'recovered restore reservation drifted' using errcode='40001'; end if;
   update control.workshop_route_effect_runs set state='succeeded',response=v_effect_response,
    safe_error=null,finished_at=now(),updated_at=now() where id=v_effect.id and state='quarantined';
   get diagnostics v_changed=row_count;
   if v_changed<>1 then raise exception 'recovered restore effect drifted' using errcode='40001'; end if;
   update control.workshop_route_application_leases set state='idle',authority_kind=null,
    effect_run_id=null,route_set_publication_id=null,generation=null,projection_digest=null,
    lease_owner=null,heartbeat_at=null,quarantined_at=null,safe_error=null,updated_at=now()
    where workshop_id=v_target.workshop_id and state='quarantined' and route_set_publication_id=p_publication_id;
   get diagnostics v_changed=row_count;
   if v_changed<>1 then raise exception 'recovered restore route drifted' using errcode='40001'; end if;
  end if;
 else
  v_effect_response:=null;
  if v_publication.publication_kind='recovery_maintenance' then
   update control.workshop_route_effect_reservations set state='reserved',updated_at=now()
    where effect_run_id=v_effect.id and state='quarantined';
   get diagnostics v_changed=row_count;
   if v_changed<>1 then raise exception 'cancelled maintenance reservation drifted' using errcode='40001'; end if;
   update control.workshop_route_effect_runs set state='cancelled',response=null,
    safe_error=null,finished_at=now(),updated_at=now() where id=v_effect.id and state='quarantined';
   get diagnostics v_changed=row_count;
   if v_changed<>1 then raise exception 'cancelled maintenance effect drifted' using errcode='40001'; end if;
   update control.workshop_route_application_leases set state='idle',authority_kind=null,
    effect_run_id=null,route_set_publication_id=null,generation=null,projection_digest=null,
    lease_owner=null,heartbeat_at=null,quarantined_at=null,safe_error=null,updated_at=now()
    where workshop_id=v_target.workshop_id and state='quarantined' and route_set_publication_id=p_publication_id;
   get diagnostics v_changed=row_count;
   if v_changed<>1 then raise exception 'cancelled maintenance route drifted' using errcode='40001'; end if;
  else
   select * into strict v_entry from control.workshop_route_set_publications
    where recovery_effect_run_id=v_effect.id and publication_kind='recovery_maintenance'
     and (phase='completed' or (phase='quarantined' and recovery_terminal_kind='candidate'
      and recovery_terminal_at is not null
      and jsonb_typeof(recovery_terminal_response->'effect_response')='object'));
   v_entry_response:=case when v_entry.phase='completed' then v_entry.final_response
    else v_entry.recovery_terminal_response->'effect_response' end;
   update control.workshop_route_effect_reservations set state='maintenance',
    generation=baseline_generation,projection_digest=baseline_projection_digest,
    disposition=baseline_disposition,action='maintenance',updated_at=now()
    where effect_run_id=v_effect.id and state='quarantined';
   get diagnostics v_changed=row_count;
   if v_changed<>1 then raise exception 'restored maintenance reservation drifted' using errcode='40001'; end if;
   update control.workshop_route_effect_runs set state='maintenance',response=v_entry_response,
    safe_error='recovery_maintenance',finished_at=null,updated_at=now() where id=v_effect.id and state='quarantined';
   get diagnostics v_changed=row_count;
   if v_changed<>1 then raise exception 'restored maintenance effect drifted' using errcode='40001'; end if;
   update control.workshop_route_application_leases set state='maintenance',
    authority_kind='recovery-maintenance',effect_run_id=v_effect.id,route_set_publication_id=null,
    generation=v_target.prior_applied_generation,projection_digest=v_target.prior_applied_digest,
    lease_owner=null,heartbeat_at=now(),quarantined_at=null,safe_error='recovery_maintenance',updated_at=now()
    where workshop_id=v_target.workshop_id and state='quarantined' and route_set_publication_id=p_publication_id;
   get diagnostics v_changed=row_count;
   if v_changed<>1 then raise exception 'restored maintenance route drifted' using errcode='40001'; end if;
  end if;
 end if;
 update control.deployment_driver_resource_leases set state='idle',authority_kind=null,
  route_set_publication_id=null,lease_owner=null,heartbeat_at=null,quarantined_at=null,
  safe_error=null,updated_at=now() where resource_key='runtime/shared-odoo'
  and state='quarantined' and route_set_publication_id=p_publication_id;
 get diagnostics v_changed=row_count;
 if v_changed<>1 then raise exception 'recovery terminal global release drifted' using errcode='40001'; end if;
 v_response:=jsonb_build_object('outcome',case when p_resolution_kind='candidate' then
   case v_publication.publication_kind when 'recovery_maintenance' then 'maintenance_recovered'
    else 'restored_recovered' end else 'not_applied' end,
  'publication_id',p_publication_id,'effect_run_id',v_effect.id,
  'publication_kind',v_publication.publication_kind,'target_workshop_id',v_target.workshop_id,
  'resolution_claim_fence',p_resolution_claim_fence,'resolution_kind',p_resolution_kind,
  'reconciliation_operation_id',p_reconciliation_operation_id,
  'reconciliation_operation_attempt',p_reconciliation_operation_attempt,
  'reconciliation_operation_lease_owner',p_reconciliation_operation_lease_owner,
  'decision_digest',p_decision_digest,'effect_response',v_effect_response);
 update control.workshop_route_set_publications set recovery_terminal_kind=p_resolution_kind,
  recovery_terminal_claim_fence=p_resolution_claim_fence,
  recovery_terminal_operation_id=p_reconciliation_operation_id,
  recovery_terminal_operation_attempt=p_reconciliation_operation_attempt,
  recovery_terminal_operation_lease_owner=p_reconciliation_operation_lease_owner,
  recovery_terminal_decision_digest=p_decision_digest,recovery_terminal_response=v_response,
  recovery_terminal_at=now(),updated_at=now()
 where publication_id=p_publication_id and phase='quarantined' and recovery_terminal_at is null;
 get diagnostics v_changed=row_count;
 if v_changed<>1 then raise exception 'recovery terminal evidence drifted' using errcode='40001'; end if;
 return query select 'completed',v_response;
end $function$;

create function control.finish_route_set_publication_recovery(
 p_publication_id uuid,p_resolution_claim_fence bigint,
 p_reconciliation_operation_id uuid,p_reconciliation_operation_attempt integer,
 p_reconciliation_operation_lease_owner text,p_reconciliation_owner uuid,
 p_reconciliation_token uuid,p_resolution_kind text,p_decision text,p_decision_digest text
) returns table(outcome text,response jsonb)
language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_kind text;
begin
 perform 1 from control.route_set_publication_protocol_state where singleton for update;
 select publication_kind into v_kind from control.workshop_route_set_publications
  where publication_id=p_publication_id;
 if v_kind in ('recovery_maintenance','recovery_restore') then
  return query select * from control.finish_recovery_route_set_publication_recovery(
   p_publication_id,p_resolution_claim_fence,p_reconciliation_operation_id,
   p_reconciliation_operation_attempt,p_reconciliation_operation_lease_owner,
   p_reconciliation_owner,p_reconciliation_token,p_resolution_kind,p_decision,p_decision_digest);
 end if;
 return query select * from control.finish_route_set_publication_recovery_projection_v1(
  p_publication_id,p_resolution_claim_fence,p_reconciliation_operation_id,
  p_reconciliation_operation_attempt,p_reconciliation_operation_lease_owner,
  p_reconciliation_owner,p_reconciliation_token,p_resolution_kind,p_decision,p_decision_digest);
end $function$;

alter function control.lock_interrupted_route_set_publication_claim(
 uuid,uuid,uuid,bigint
) rename to lock_interrupted_route_set_publication_claim_projection_v1;

create function control.lock_interrupted_recovery_route_set_publication_claim(
 p_publication_id uuid,p_reconciliation_owner uuid,p_reconciliation_token uuid,p_claim_fence bigint
) returns boolean language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_publication control.workshop_route_set_publications%rowtype;
 v_target control.workshop_route_set_publication_targets%rowtype;
 v_reconciliation control.operations%rowtype;
begin
 select * into v_publication from control.workshop_route_set_publications
  where publication_id=p_publication_id;
 if not found then return false; end if;
 perform 1 from control.operations where id in
  (v_publication.control_operation_id,v_publication.reconciliation_operation_id) order by id for update;
 perform 1 from control.deployment_driver_resource_leases
  where resource_key='runtime/shared-odoo' for update;
 perform 1 from control.workshop_route_application_leases
  where workshop_id=v_publication.target_workshop_id for update;
 perform 1 from control.workshop_route_effect_runs
  where id=v_publication.recovery_effect_run_id for update;
 select * into strict v_publication from control.workshop_route_set_publications
  where publication_id=p_publication_id for update;
 select * into strict v_target from control.workshop_route_set_publication_targets
  where publication_id=p_publication_id;
 select * into v_reconciliation from control.operations
  where id=v_publication.reconciliation_operation_id;
 return coalesce(v_publication.phase='quarantined'
  and v_publication.publication_kind in ('recovery_maintenance','recovery_restore')
  and v_publication.reconciliation_owner=p_reconciliation_owner
  and v_publication.reconciliation_token=p_reconciliation_token
  and v_publication.reconciliation_claim_fence=p_claim_fence
  and v_publication.reconciliation_expires_at>now()
  and v_reconciliation.state='in_flight' and v_reconciliation.kind='tenant.reconcile'
  and v_reconciliation.queue='tenant-reconciliation'
  and v_reconciliation.workshop_id=v_publication.target_workshop_id
  and v_reconciliation.attempt=v_publication.reconciliation_operation_attempt
  and v_reconciliation.leased_by=v_publication.reconciliation_operation_lease_owner
  and v_reconciliation.lease_expires_at>now()
  and exists(select 1 from control.deployment_driver_resource_leases lease
   where lease.resource_key='runtime/shared-odoo' and lease.state='quarantined'
    and lease.authority_kind='route-set-publication' and lease.route_set_publication_id=p_publication_id
    and lease.fence_token=v_publication.original_global_fence_token
    and lease.lease_token is null and lease.lease_expires_at is null)
  and exists(select 1 from control.workshop_route_application_leases lease
   where lease.workshop_id=v_target.workshop_id and lease.state='quarantined'
    and lease.authority_kind='route-set-publication' and lease.route_set_publication_id=p_publication_id
    and lease.fence_token=v_target.target_route_fence_token
    and lease.lease_token is null and lease.lease_expires_at is null)
  and exists(select 1 from control.workshop_route_effect_runs effect
   where effect.id=v_publication.recovery_effect_run_id and effect.kind='recovery-maintenance'
    and effect.workshop_id=v_target.workshop_id and effect.state='quarantined'
    and effect.safe_error='runtime_outcome_unknown' and effect.execution_token is null
    and effect.route_lease_token is null and effect.lease_expires_at is null),false);
end $function$;

create function control.lock_interrupted_route_set_publication_claim(
 p_publication_id uuid,p_reconciliation_owner uuid,p_reconciliation_token uuid,p_claim_fence bigint
) returns boolean language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_kind text;
begin
 perform 1 from control.route_set_publication_protocol_state
  where singleton and mode='generation_v1' for update;
 if not found then return false; end if;
 select publication_kind into v_kind from control.workshop_route_set_publications
  where publication_id=p_publication_id;
 if v_kind='projection' then
  return control.lock_interrupted_route_set_publication_claim_projection_v1(
   p_publication_id,p_reconciliation_owner,p_reconciliation_token,p_claim_fence);
 end if;
 return control.lock_interrupted_recovery_route_set_publication_claim(
  p_publication_id,p_reconciliation_owner,p_reconciliation_token,p_claim_fence);
end $function$;

alter function control.read_interrupted_route_set_publication_state(
 uuid,uuid,uuid,bigint
) rename to read_interrupted_route_set_publication_state_projection_v1;

create function control.read_interrupted_recovery_route_set_publication_state(
 p_publication_id uuid,p_reconciliation_owner uuid,p_reconciliation_token uuid,p_claim_fence bigint
) returns table(outcome text,state jsonb)
language plpgsql stable security definer set search_path=pg_catalog,control as $function$
declare v_publication control.workshop_route_set_publications%rowtype;
 v_target control.workshop_route_set_publication_targets%rowtype; v_record_count integer;
begin
 select * into v_publication from control.workshop_route_set_publications
 where publication_id=p_publication_id and phase='quarantined'
  and publication_kind in ('recovery_maintenance','recovery_restore')
  and reconciliation_owner=p_reconciliation_owner and reconciliation_token=p_reconciliation_token
  and reconciliation_claim_fence=p_claim_fence and reconciliation_expires_at>now()
  and exists(select 1 from control.route_set_publication_protocol_state protocol
   where protocol.singleton and protocol.mode='generation_v1')
  and exists(select 1 from control.operations operation
   where operation.id=workshop_route_set_publications.reconciliation_operation_id
    and operation.state='in_flight' and operation.kind='tenant.reconcile'
    and operation.queue='tenant-reconciliation' and operation.workshop_id=workshop_route_set_publications.target_workshop_id
    and operation.attempt=workshop_route_set_publications.reconciliation_operation_attempt
    and operation.leased_by=workshop_route_set_publications.reconciliation_operation_lease_owner
    and operation.lease_expires_at>now()
    and operation.payload->>'route_set_publication_id'=p_publication_id::text
    and operation.payload->>'protocol_version'='1')
  and exists(select 1 from control.workshop_route_effect_runs effect
   where effect.id=workshop_route_set_publications.recovery_effect_run_id
    and effect.kind='recovery-maintenance' and effect.state='quarantined'
    and effect.workshop_id=workshop_route_set_publications.target_workshop_id
    and effect.safe_error='runtime_outcome_unknown')
  and exists(select 1 from control.deployment_driver_resource_leases lease
   where lease.resource_key='runtime/shared-odoo' and lease.state='quarantined'
    and lease.route_set_publication_id=p_publication_id)
  and exists(select 1 from control.workshop_route_application_leases lease
   where lease.workshop_id=workshop_route_set_publications.target_workshop_id
    and lease.state='quarantined' and lease.route_set_publication_id=p_publication_id);
 if not found then return query select 'claim_lost',null::jsonb; return; end if;
 select * into strict v_target from control.workshop_route_set_publication_targets
  where publication_id=p_publication_id;
 select count(*) into v_record_count from control.workshop_route_set_publication_records
  where publication_id=p_publication_id;
 return query select 'claimed',jsonb_build_object(
  'protocol_version',v_publication.protocol_version,'publication_id',v_publication.publication_id,
  'publication_kind',v_publication.publication_kind,
  'recovery_effect_run_id',v_publication.recovery_effect_run_id,
  'interrupted_phase',v_publication.interrupted_phase,'claim_mode',v_publication.reconciliation_claim_mode,
  'claim_fence',v_publication.reconciliation_claim_fence,'target_workshop_id',v_target.workshop_id,
  'original_global_fence_token',v_publication.original_global_fence_token,
  'target_route_fence_token',v_target.target_route_fence_token,
  'target_generation',v_target.target_generation,'target_projection_digest',v_target.target_projection_digest,
  'target_disposition',v_target.target_disposition,'selector',v_publication.selector,
  'prior_selector',v_publication.prior_selector,'prior_directory_device',v_publication.prior_directory_device,
  'prior_directory_inode',v_publication.prior_directory_inode,'prior_loaded_identity',v_publication.prior_loaded_identity,
  'candidate_directory_device',v_publication.candidate_directory_device,
  'candidate_directory_inode',v_publication.candidate_directory_inode,'sealed_count',v_publication.sealed_count,
  'sealed_present_count',v_publication.sealed_present_count,'route_set_digest',v_publication.route_set_digest,
  'record_count',v_record_count,'publication_started_at',v_publication.publication_started_at,
  'observed_selector',v_publication.observed_selector,'observed_loaded_identity',v_publication.observed_loaded_identity);
end $function$;

create function control.read_interrupted_route_set_publication_state(
 p_publication_id uuid,p_reconciliation_owner uuid,p_reconciliation_token uuid,p_claim_fence bigint
) returns table(outcome text,state jsonb)
language plpgsql stable security definer set search_path=pg_catalog,control as $function$
declare v_kind text; v_result record;
begin
 select publication_kind into v_kind from control.workshop_route_set_publications
  where publication_id=p_publication_id;
 if v_kind='projection' then
  select * into v_result from control.read_interrupted_route_set_publication_state_projection_v1(
   p_publication_id,p_reconciliation_owner,p_reconciliation_token,p_claim_fence);
  if v_result.outcome='claimed' then
   return query select v_result.outcome,(v_result.state||jsonb_build_object('recovery_effect_run_id',null));
  else return query select v_result.outcome,v_result.state; end if;
  return;
 end if;
 return query select * from control.read_interrupted_recovery_route_set_publication_state(
  p_publication_id,p_reconciliation_owner,p_reconciliation_token,p_claim_fence);
end $function$;

-- Extend the final-evidence trigger without weakening projection receipts.
create or replace function control.validate_route_set_publication_phase_transition()
returns trigger language plpgsql set search_path=pg_catalog,control as $function$
declare v_target control.workshop_route_set_publication_targets%rowtype;
 v_record control.workshop_route_set_publication_records%rowtype;
 v_expected jsonb; v_expected_response jsonb; v_route_evidence jsonb;
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
 if old.publication_started_at is not null and new.publication_started_at is distinct from old.publication_started_at then
  raise exception 'route-set publication-start evidence is immutable' using errcode='55000';
 end if;
 if old.observed_at is not null and (new.observed_selector is distinct from old.observed_selector
  or new.observed_loaded_identity is distinct from old.observed_loaded_identity
  or new.observed_at is distinct from old.observed_at) then
  raise exception 'route-set observation evidence is immutable' using errcode='55000';
 end if;
 if old.finished_at is not null and (new.finished_at is distinct from old.finished_at
  or new.final_response is distinct from old.final_response) then
  raise exception 'route-set final evidence is immutable' using errcode='55000';
 end if;
 if old.quarantined_at is not null and (new.interrupted_phase is distinct from old.interrupted_phase
  or new.quarantined_at is distinct from old.quarantined_at
  or new.safe_error is distinct from old.safe_error) then
  raise exception 'route-set quarantine evidence is immutable' using errcode='55000';
 end if;
 select * into v_target from control.workshop_route_set_publication_targets where publication_id=new.publication_id;
 if new.observed_at is not null then
  v_expected:=jsonb_build_object('protocol_version',1,'publication_id',new.publication_id,
   'publication_kind',new.publication_kind,'global_fence_token',new.original_global_fence_token,
   'target_workshop_id',new.target_workshop_id,'target_route_fence_token',v_target.target_route_fence_token,
   'route_set_digest',new.route_set_digest);
  if new.observed_selector is distinct from new.selector or new.observed_loaded_identity is distinct from v_expected then
   raise exception 'route-set observed identity is not exact' using errcode='55000';
  end if;
 end if;
 if new.phase='completed' then
  select * into strict v_record from control.workshop_route_set_publication_records
   where publication_id=new.publication_id and workshop_id=new.target_workshop_id;
  if new.publication_kind='projection' then
   v_expected_response:=jsonb_build_object('outcome','applied','workshop_id',v_target.workshop_id,
    'route_evidence',jsonb_build_object('driver_operation_id',new.driver_operation_id,
     'workshop_id',v_target.workshop_id,'route_generation',v_target.target_generation,
     'projection_digest',v_target.target_projection_digest,'disposition',v_target.target_disposition,
     'rendered_digest',v_record.rendered_digest,'route_fence_token',v_target.target_route_fence_token),
    'route_set_evidence',jsonb_build_object('protocol_version',new.protocol_version,
     'publication_id',new.publication_id,'publication_kind',new.publication_kind,'selector',new.selector,
     'route_set_digest',new.route_set_digest,'snapshot_count',new.snapshot_count,
     'present_count',new.sealed_present_count,'global_fence_token',new.original_global_fence_token,
     'directory_device',new.candidate_directory_device,'directory_inode',new.candidate_directory_inode));
   if new.final_response is distinct from v_expected_response
    or not exists(select 1 from control.deployment_driver_operations driver where driver.id=new.driver_operation_id
     and driver.state='succeeded' and driver.response is not distinct from v_expected_response
     and driver.execution_token is null and driver.lease_expires_at is null)
    or not exists(select 1 from control.workshop_route_projection_state state where state.workshop_id=v_target.workshop_id
     and state.desired_generation=v_target.target_generation and state.desired_digest=v_target.target_projection_digest
     and state.desired_disposition=v_target.target_disposition and state.applied_generation=v_target.target_generation
     and state.applied_digest=v_target.target_projection_digest and state.applied_disposition=v_target.target_disposition
     and state.applied_rendered_digest=v_record.rendered_digest and state.applied_driver_operation_id=new.driver_operation_id
     and state.applied_effect_run_id is null and state.applied_fence_token=v_target.target_route_fence_token)
    or not exists(select 1 from control.deployment_driver_resource_leases lease
     where lease.resource_key='runtime/shared-odoo' and lease.state='idle' and lease.authority_kind is null
      and lease.route_set_publication_id is null and lease.driver_operation_id is null and lease.effect_run_id is null
      and lease.lease_owner is null and lease.lease_token is null and lease.lease_expires_at is null
      and lease.fence_token=new.original_global_fence_token)
    or not exists(select 1 from control.workshop_route_application_leases lease
     where lease.workshop_id=v_target.workshop_id and lease.state='idle' and lease.authority_kind is null
      and lease.route_set_publication_id is null and lease.driver_operation_id is null and lease.effect_run_id is null
      and lease.release_publication_id is null and lease.lease_owner is null and lease.lease_token is null
      and lease.lease_expires_at is null and lease.fence_token=v_target.target_route_fence_token) then
    raise exception 'route-set final receipt is not exact' using errcode='55000';
   end if;
  else
   v_route_evidence:=jsonb_build_object('effect_run_id',new.recovery_effect_run_id,
    'workshop_id',v_target.workshop_id,'generation',v_target.target_generation,
    'projection_digest',v_target.target_projection_digest,'disposition',v_target.target_disposition,
    'rendered_digest',v_record.rendered_digest,'route_fence_token',v_target.target_route_fence_token,
    'mode',case new.publication_kind when 'recovery_maintenance' then 'maintenance' else 'restored' end);
   v_expected_response:=jsonb_build_object(
    'outcome',case new.publication_kind when 'recovery_maintenance' then 'maintenance' else 'restored' end,
    'effect_run_id',new.recovery_effect_run_id,'route_evidence',v_route_evidence,
    'route_set_evidence',jsonb_build_object('protocol_version',new.protocol_version,
     'publication_id',new.publication_id,'publication_kind',new.publication_kind,'selector',new.selector,
     'route_set_digest',new.route_set_digest,'snapshot_count',new.snapshot_count,
     'present_count',new.sealed_present_count,'global_fence_token',new.original_global_fence_token,
     'directory_device',new.candidate_directory_device,'directory_inode',new.candidate_directory_inode));
   if new.publication_kind='recovery_maintenance' then
    v_expected_response:=v_expected_response||jsonb_build_object(
     'route_fence_token',v_target.target_route_fence_token);
   end if;
   if new.final_response is distinct from v_expected_response
    or not exists(select 1 from control.workshop_route_effect_runs effect
     where effect.id=new.recovery_effect_run_id and effect.response is not distinct from v_expected_response
      and ((new.publication_kind='recovery_maintenance' and effect.state='maintenance'
        and effect.safe_error='recovery_maintenance' and effect.finished_at is null)
       or (new.publication_kind='recovery_restore' and effect.state='succeeded'
        and effect.safe_error is null and effect.finished_at is not null)))
    or not exists(select 1 from control.deployment_driver_resource_leases lease
     where lease.resource_key='runtime/shared-odoo' and lease.state='idle' and lease.authority_kind is null
      and lease.route_set_publication_id is null and lease.fence_token=new.original_global_fence_token)
    or (new.publication_kind='recovery_maintenance' and (
      not exists(select 1 from control.workshop_route_projection_state state
       where state.workshop_id=v_target.workshop_id and state.applied_generation=v_target.prior_applied_generation
        and state.applied_digest=v_target.prior_applied_digest
        and state.applied_disposition=v_target.prior_applied_disposition
        and state.applied_rendered_digest=v_target.prior_applied_rendered_digest
        and state.applied_driver_operation_id is not distinct from v_target.prior_applied_driver_operation_id
        and state.applied_effect_run_id is not distinct from v_target.prior_applied_effect_run_id
        and state.applied_fence_token=v_target.prior_applied_fence_token)
      or not exists(select 1 from control.workshop_route_application_leases lease
       where lease.workshop_id=v_target.workshop_id and lease.state='maintenance'
        and lease.authority_kind='recovery-maintenance' and lease.effect_run_id=new.recovery_effect_run_id
        and lease.route_set_publication_id is null and lease.fence_token=v_target.target_route_fence_token)))
    or (new.publication_kind='recovery_restore' and (
      not exists(select 1 from control.workshop_route_projection_state state
       where state.workshop_id=v_target.workshop_id and state.desired_generation=v_target.target_generation
        and state.desired_digest=v_target.target_projection_digest and state.desired_disposition=v_target.target_disposition
        and state.applied_generation=v_target.target_generation and state.applied_digest=v_target.target_projection_digest
        and state.applied_disposition=v_target.target_disposition and state.applied_rendered_digest=v_record.rendered_digest
        and state.applied_driver_operation_id is null and state.applied_effect_run_id=new.recovery_effect_run_id
        and state.applied_fence_token=v_target.target_route_fence_token)
      or not exists(select 1 from control.workshop_route_application_leases lease
       where lease.workshop_id=v_target.workshop_id and lease.state='idle' and lease.authority_kind is null
        and lease.effect_run_id is null and lease.route_set_publication_id is null
        and lease.fence_token=v_target.target_route_fence_token))) then
    raise exception 'recovery route-set final receipt is not exact' using errcode='55000';
   end if;
  end if;
 end if;
 return new;
end $function$;

create or replace function control.renew_route_set_publication(
 p_publication_id uuid,p_instance_owner uuid,p_execution_token uuid,p_global_lease_token uuid,
 p_route_lease_token uuid,p_global_fence_token bigint,p_target_route_fence_token bigint,p_ttl_seconds integer
) returns boolean language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_expires timestamptz; v_changed integer; v_publication control.workshop_route_set_publications%rowtype;
begin
 if p_ttl_seconds is null or p_ttl_seconds not between 60 and 1200 then return false; end if;
 if not control.lock_route_set_publication_authority(p_publication_id,p_instance_owner,p_execution_token,
  p_global_lease_token,p_route_lease_token,p_global_fence_token,p_target_route_fence_token) then return false; end if;
 select * into strict v_publication from control.workshop_route_set_publications
  where publication_id=p_publication_id;
 v_expires:=now()+make_interval(secs=>p_ttl_seconds);
 if v_publication.driver_operation_id is not null then
  update control.deployment_driver_operations set lease_expires_at=v_expires,updated_at=now()
  where id=v_publication.driver_operation_id and state='in_progress'
   and execution_token=p_execution_token and lease_expires_at>now();
 else
  update control.workshop_route_effect_runs set lease_expires_at=v_expires,heartbeat_at=now(),updated_at=now()
  where id=v_publication.recovery_effect_run_id
   and state=case v_publication.publication_kind when 'recovery_maintenance' then 'reserved' else 'restore_started' end
   and instance_owner=p_instance_owner and execution_token=p_execution_token
   and route_lease_token=p_route_lease_token and lease_expires_at>now();
 end if;
 get diagnostics v_changed=row_count; if v_changed<>1 then return false; end if;
 update control.deployment_driver_resource_leases set lease_expires_at=v_expires,heartbeat_at=now(),updated_at=now()
 where resource_key='runtime/shared-odoo' and state='held' and authority_kind='route-set-publication'
  and route_set_publication_id=p_publication_id and lease_token=p_global_lease_token
  and fence_token=p_global_fence_token;
 get diagnostics v_changed=row_count; if v_changed<>1 then return false; end if;
 update control.workshop_route_application_leases lease set lease_expires_at=v_expires,heartbeat_at=now(),updated_at=now()
 from control.workshop_route_set_publication_targets target where target.publication_id=p_publication_id
  and lease.workshop_id=target.workshop_id and lease.state='held' and lease.authority_kind='route-set-publication'
  and lease.route_set_publication_id=p_publication_id and lease.lease_token=p_route_lease_token
  and lease.fence_token=p_target_route_fence_token;
 get diagnostics v_changed=row_count; return v_changed=1;
end $function$;

alter function control.finish_route_set_publication(
 uuid,uuid,uuid,uuid,uuid,bigint,bigint
) rename to finish_route_set_publication_projection_v1;

create function control.finish_route_set_publication(
 p_publication_id uuid,p_instance_owner uuid,p_execution_token uuid,
 p_global_lease_token uuid,p_route_lease_token uuid,p_global_fence_token bigint,
 p_target_route_fence_token bigint
) returns table(outcome text,response jsonb)
language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_kind text;
begin
 perform 1 from control.route_set_publication_protocol_state where singleton for update;
 select publication_kind into v_kind from control.workshop_route_set_publications
  where publication_id=p_publication_id;
 if v_kind in ('recovery_maintenance','recovery_restore') then
  return query select * from control.finish_route_set_recovery_publication(
   p_publication_id,p_instance_owner,p_execution_token,p_global_lease_token,p_route_lease_token,
   p_global_fence_token,p_target_route_fence_token);
 end if;
 return query select * from control.finish_route_set_publication_projection_v1(
  p_publication_id,p_instance_owner,p_execution_token,p_global_lease_token,p_route_lease_token,
  p_global_fence_token,p_target_route_fence_token);
end $function$;

create function control.finish_route_set_recovery_publication(
 p_publication_id uuid,p_instance_owner uuid,p_execution_token uuid,
 p_global_lease_token uuid,p_route_lease_token uuid,p_global_fence_token bigint,
 p_target_route_fence_token bigint
) returns table(outcome text,response jsonb)
language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_publication control.workshop_route_set_publications%rowtype;
 v_target control.workshop_route_set_publication_targets%rowtype;
 v_effect control.workshop_route_effect_runs%rowtype;
 v_reservation control.workshop_route_effect_reservations%rowtype;
 v_state control.workshop_route_projection_state%rowtype;
 v_record control.workshop_route_set_publication_records%rowtype;
 v_count integer; v_present integer; v_changed integer; v_digest text;
 v_route_evidence jsonb; v_response jsonb; v_expected_identity jsonb;
begin
 if p_publication_id is null or p_instance_owner is null or p_execution_token is null
  or p_global_lease_token is null or p_route_lease_token is null
  or p_global_fence_token is null or p_global_fence_token<=0
  or p_target_route_fence_token is null or p_target_route_fence_token<=0 then
  return query select 'invalid',null::jsonb; return;
 end if;
 if not control.lock_route_set_publication_authority(p_publication_id,p_instance_owner,p_execution_token,
   p_global_lease_token,p_route_lease_token,p_global_fence_token,p_target_route_fence_token) then
  select * into v_publication from control.workshop_route_set_publications where publication_id=p_publication_id;
  if found and v_publication.phase='completed'
   and v_publication.original_instance_owner=p_instance_owner
   and v_publication.original_execution_token=p_execution_token
   and v_publication.original_global_lease_token=p_global_lease_token
   and v_publication.original_route_lease_token=p_route_lease_token
   and v_publication.original_global_fence_token=p_global_fence_token then
   return query select 'replay',v_publication.final_response; return;
  end if;
  return query select 'authority_lost',null::jsonb; return;
 end if;
 select * into strict v_publication from control.workshop_route_set_publications
  where publication_id=p_publication_id for update;
 select * into strict v_target from control.workshop_route_set_publication_targets
  where publication_id=p_publication_id;
 select * into strict v_effect from control.workshop_route_effect_runs
  where id=v_publication.recovery_effect_run_id for update;
 select * into strict v_reservation from control.workshop_route_effect_reservations
  where effect_run_id=v_effect.id and workshop_id=v_target.workshop_id for update;
 select * into strict v_state from control.workshop_route_projection_state
  where workshop_id=v_target.workshop_id for update;
 select * into strict v_record from control.workshop_route_set_publication_records
  where publication_id=p_publication_id and workshop_id=v_target.workshop_id;
 if v_publication.publication_kind not in ('recovery_maintenance','recovery_restore')
  or v_publication.phase<>'observed'
  or v_target.target_route_fence_token<>p_target_route_fence_token then
  return query select 'wrong_phase',null::jsonb; return;
 end if;
 select count(*),count(*) filter(where disposition='present') into v_count,v_present
 from control.workshop_route_set_publication_records where publication_id=p_publication_id;
 select control.route_set_publication_digest(p_publication_id) into v_digest;
 v_expected_identity:=jsonb_build_object('protocol_version',1,'publication_id',p_publication_id,
  'publication_kind',v_publication.publication_kind,'global_fence_token',p_global_fence_token,
  'target_workshop_id',v_target.workshop_id,'target_route_fence_token',p_target_route_fence_token,
  'route_set_digest',v_publication.route_set_digest);
 if v_count<>v_publication.snapshot_count or v_count<>v_publication.sealed_count
  or v_present<>v_publication.sealed_present_count or v_digest is distinct from v_publication.route_set_digest
  or v_publication.observed_selector is distinct from v_publication.selector
  or v_publication.observed_loaded_identity is distinct from v_expected_identity
  or v_record.generation<>v_target.target_generation
  or v_record.projection_digest<>v_target.target_projection_digest
  or v_record.disposition<>v_target.target_disposition
  or v_record.applied_rendered_digest<>v_target.prior_applied_rendered_digest
  or v_reservation.route_fence_token<>p_target_route_fence_token then
  return query select 'authority_lost',null::jsonb; return;
 end if;
 v_route_evidence:=jsonb_build_object('effect_run_id',v_effect.id,
  'workshop_id',v_target.workshop_id,'generation',v_target.target_generation,
  'projection_digest',v_target.target_projection_digest,'disposition',v_target.target_disposition,
  'rendered_digest',v_record.rendered_digest,'route_fence_token',v_target.target_route_fence_token,
  'mode',case v_publication.publication_kind when 'recovery_maintenance' then 'maintenance' else 'restored' end);
 v_response:=jsonb_build_object(
  'outcome',case v_publication.publication_kind when 'recovery_maintenance' then 'maintenance' else 'restored' end,
  'effect_run_id',v_effect.id,'route_evidence',v_route_evidence,
  'route_set_evidence',jsonb_build_object('protocol_version',v_publication.protocol_version,
   'publication_id',v_publication.publication_id,'publication_kind',v_publication.publication_kind,
   'selector',v_publication.selector,'route_set_digest',v_publication.route_set_digest,
   'snapshot_count',v_publication.snapshot_count,'present_count',v_publication.sealed_present_count,
   'global_fence_token',v_publication.original_global_fence_token,
   'directory_device',v_publication.candidate_directory_device,
   'directory_inode',v_publication.candidate_directory_inode));
 if v_publication.publication_kind='recovery_maintenance' then
  v_response:=v_response||jsonb_build_object(
   'route_fence_token',v_target.target_route_fence_token);
 end if;

 if v_publication.publication_kind='recovery_maintenance' then
  -- The maintenance generation is an operational routing state only.  Its
  -- successful publication must not change any logical applied-head field.
  if v_state.applied_generation<>v_target.prior_applied_generation
   or v_state.applied_digest<>v_target.prior_applied_digest
   or v_state.applied_disposition<>v_target.prior_applied_disposition
   or v_state.applied_rendered_digest<>v_target.prior_applied_rendered_digest
   or v_state.applied_driver_operation_id is distinct from v_target.prior_applied_driver_operation_id
   or v_state.applied_effect_run_id is distinct from v_target.prior_applied_effect_run_id
   or v_state.applied_fence_token<>v_target.prior_applied_fence_token then
   return query select 'projection_drift',null::jsonb; return;
  end if;
  update control.workshop_route_effect_reservations set state='maintenance',
   maintenance_rendered_digest=v_record.rendered_digest,
   maintenance_evidence=v_route_evidence,updated_at=now()
  where effect_run_id=v_effect.id and workshop_id=v_target.workshop_id and state='reserved'
   and generation=v_target.target_generation and projection_digest=v_target.target_projection_digest
   and disposition=v_target.target_disposition and route_fence_token=p_target_route_fence_token;
  get diagnostics v_changed=row_count;
  if v_changed<>1 then raise exception 'maintenance reservation finalization drifted' using errcode='40001'; end if;
  update control.workshop_route_application_leases set state='maintenance',
   authority_kind='recovery-maintenance',effect_run_id=v_effect.id,route_set_publication_id=null,
   lease_owner=null,lease_token=null,lease_expires_at=null,safe_error='recovery_maintenance',updated_at=now()
  where workshop_id=v_target.workshop_id and state='held' and authority_kind='route-set-publication'
   and route_set_publication_id=p_publication_id and lease_owner=p_instance_owner
   and lease_token=p_route_lease_token and fence_token=p_target_route_fence_token;
  get diagnostics v_changed=row_count;
  if v_changed<>1 then raise exception 'maintenance route release drifted' using errcode='40001'; end if;
  update control.workshop_route_effect_runs set state='maintenance',response=v_response,
   instance_owner=null,execution_token=null,route_lease_token=null,lease_expires_at=null,
   safe_error='recovery_maintenance',updated_at=now()
  where id=v_effect.id and state='reserved' and instance_owner=p_instance_owner
   and execution_token=p_execution_token and route_lease_token=p_route_lease_token;
 else
  update control.workshop_route_projection_state set applied_generation=v_target.target_generation,
   applied_digest=v_target.target_projection_digest,applied_disposition=v_target.target_disposition,
   applied_rendered_digest=v_record.rendered_digest,applied_driver_operation_id=null,
   applied_effect_run_id=v_effect.id,applied_fence_token=p_target_route_fence_token,updated_at=now()
  where workshop_id=v_target.workshop_id
   and desired_generation=v_target.target_generation and desired_digest=v_target.target_projection_digest
   and desired_disposition=v_target.target_disposition
   and applied_generation=v_target.prior_applied_generation and applied_digest=v_target.prior_applied_digest
   and applied_disposition=v_target.prior_applied_disposition
   and applied_rendered_digest=v_target.prior_applied_rendered_digest
   and applied_driver_operation_id is not distinct from v_target.prior_applied_driver_operation_id
   and applied_effect_run_id is not distinct from v_target.prior_applied_effect_run_id
   and applied_fence_token=v_target.prior_applied_fence_token;
  get diagnostics v_changed=row_count;
  if v_changed<>1 then return query select 'projection_drift',null::jsonb; return; end if;
  update control.workshop_route_effect_reservations set state='restored',
   restored_rendered_digest=v_record.rendered_digest,restored_evidence=v_route_evidence,updated_at=now()
  where effect_run_id=v_effect.id and workshop_id=v_target.workshop_id and state='maintenance'
   and generation=v_target.target_generation and projection_digest=v_target.target_projection_digest
   and disposition=v_target.target_disposition and route_fence_token=p_target_route_fence_token;
  get diagnostics v_changed=row_count;
  if v_changed<>1 then raise exception 'restore reservation finalization drifted' using errcode='40001'; end if;
  update control.workshop_route_application_leases set state='idle',authority_kind=null,
   effect_run_id=null,route_set_publication_id=null,generation=null,projection_digest=null,
   lease_owner=null,lease_token=null,lease_expires_at=null,heartbeat_at=null,
   quarantined_at=null,safe_error=null,updated_at=now()
  where workshop_id=v_target.workshop_id and state='held' and authority_kind='route-set-publication'
   and route_set_publication_id=p_publication_id and lease_owner=p_instance_owner
   and lease_token=p_route_lease_token and fence_token=p_target_route_fence_token;
  get diagnostics v_changed=row_count;
  if v_changed<>1 then raise exception 'restore route release drifted' using errcode='40001'; end if;
  update control.workshop_route_effect_runs set state='succeeded',response=v_response,
   instance_owner=null,execution_token=null,route_lease_token=null,lease_expires_at=null,
   safe_error=null,finished_at=now(),updated_at=now()
  where id=v_effect.id and state='restore_started' and instance_owner=p_instance_owner
   and execution_token=p_execution_token and route_lease_token=p_route_lease_token;
 end if;
 get diagnostics v_changed=row_count;
 if v_changed<>1 then raise exception 'recovery effect finalization drifted' using errcode='40001'; end if;
 update control.deployment_driver_resource_leases set state='idle',authority_kind=null,
  driver_operation_id=null,effect_run_id=null,route_set_publication_id=null,
  lease_owner=null,lease_token=null,lease_expires_at=null,heartbeat_at=null,
  quarantined_at=null,safe_error=null,updated_at=now()
 where resource_key='runtime/shared-odoo' and state='held' and authority_kind='route-set-publication'
  and route_set_publication_id=p_publication_id and lease_owner=p_instance_owner
  and lease_token=p_global_lease_token and fence_token=p_global_fence_token;
 get diagnostics v_changed=row_count;
 if v_changed<>1 then raise exception 'recovery global release drifted' using errcode='40001'; end if;
 update control.workshop_route_set_publications set phase='completed',finished_at=now(),
  final_response=v_response,updated_at=now()
 where publication_id=p_publication_id and phase='observed' and final_response is null;
 get diagnostics v_changed=row_count;
 if v_changed<>1 then raise exception 'recovery publication completion drifted' using errcode='40001'; end if;
 return query select 'completed',v_response;
end $function$;

create function control.read_route_set_recovery_publication_result(
 p_publication_id uuid,p_effect_run_id uuid,p_control_operation_id uuid
) returns table(outcome text,publication_id uuid,effect_run_id uuid,publication_kind text,response jsonb)
language plpgsql stable security definer set search_path=pg_catalog,control as $function$
declare v_effect control.workshop_route_effect_runs%rowtype;
 v_restore control.workshop_route_set_publications%rowtype;
 v_entry control.workshop_route_set_publications%rowtype;
begin
 if p_publication_id is null or p_effect_run_id is null or p_control_operation_id is null then
  return query select 'absent',null::uuid,null::uuid,null::text,null::jsonb; return;
 end if;
 select * into v_effect from control.workshop_route_effect_runs where id=p_effect_run_id;
 if not found then return query select 'absent',null::uuid,null::uuid,null::text,null::jsonb; return; end if;
 if v_effect.control_operation_id is distinct from p_control_operation_id
  or v_effect.kind is distinct from 'recovery-maintenance' then
  return query select 'conflict',null::uuid,p_effect_run_id,null::text,null::jsonb; return;
 end if;
 select * into v_restore from control.workshop_route_set_publications publication
  where publication.publication_id=p_publication_id
   and publication.recovery_effect_run_id=p_effect_run_id
   and publication.control_operation_id=p_control_operation_id
   and publication.publication_kind='recovery_restore';
 if found then
  if v_restore.phase='completed' then
   return query select 'completed',v_restore.publication_id,p_effect_run_id,
    v_restore.publication_kind,v_restore.final_response; return;
  elsif v_restore.recovery_terminal_at is not null then
   return query select case when v_restore.recovery_terminal_kind='candidate'
     then 'completed' else 'not_applied' end,
    v_restore.publication_id,p_effect_run_id,v_restore.publication_kind,
    case when v_restore.recovery_terminal_kind='candidate'
     then v_restore.recovery_terminal_response->'effect_response'
     else v_restore.recovery_terminal_response end; return;
  end if;
  return query select 'pending',v_restore.publication_id,p_effect_run_id,
   v_restore.publication_kind,null::jsonb; return;
 end if;
 select * into v_entry from control.workshop_route_set_publications publication
  where publication.publication_id=p_publication_id
   and publication.recovery_effect_run_id=p_effect_run_id
   and publication.control_operation_id=p_control_operation_id
   and publication.publication_kind='recovery_maintenance';
 if not found then return query select 'absent',null::uuid,p_effect_run_id,null::text,null::jsonb; return; end if;
 if v_entry.phase='completed' then
  return query select 'completed',v_entry.publication_id,p_effect_run_id,
   v_entry.publication_kind,v_entry.final_response; return;
 elsif v_entry.recovery_terminal_at is not null then
  return query select case when v_entry.recovery_terminal_kind='candidate'
    then 'completed' else 'not_applied' end,
   v_entry.publication_id,p_effect_run_id,v_entry.publication_kind,
   case when v_entry.recovery_terminal_kind='candidate'
    then v_entry.recovery_terminal_response->'effect_response'
    else v_entry.recovery_terminal_response end; return;
 end if;
 return query select 'pending',v_entry.publication_id,p_effect_run_id,
  v_entry.publication_kind,null::jsonb;
end $function$;

-- Generic record transitions can now authenticate either exact owner.  The
-- effect branch deliberately verifies the upstream lease and both publication
-- leases independently; an effect-run token alone is never publication
-- authority.
create or replace function control.has_route_set_publication_authority(
 p_publication_id uuid,p_instance_owner uuid,p_execution_token uuid,
 p_global_lease_token uuid,p_route_lease_token uuid,p_global_fence_token bigint,
 p_target_route_fence_token bigint
) returns boolean language sql stable security definer set search_path=pg_catalog,control as $function$
 select exists(select 1
 from control.workshop_route_set_publications publication
 join control.workshop_route_set_publication_targets target using(publication_id)
 join control.operations upstream on upstream.id=publication.control_operation_id
 left join control.deployment_driver_operations driver on driver.id=publication.driver_operation_id
 left join control.workshop_route_effect_runs effect on effect.id=publication.recovery_effect_run_id
 join control.deployment_driver_resource_leases global_lease on global_lease.resource_key='runtime/shared-odoo'
 join control.workshop_route_application_leases route_lease on route_lease.workshop_id=publication.target_workshop_id
 join control.route_set_publication_protocol_state protocol on protocol.singleton
 where publication.publication_id=p_publication_id
  and publication.phase in ('staging','sealed','publication_started','observed')
  and protocol.mode='generation_v1'
  and publication.original_instance_owner=p_instance_owner
  and publication.original_execution_token=p_execution_token
  and publication.original_global_lease_token=p_global_lease_token
  and publication.original_route_lease_token=p_route_lease_token
  and publication.original_global_fence_token=p_global_fence_token
  and upstream.state='in_flight' and upstream.workshop_id=publication.target_workshop_id
  and upstream.attempt=publication.control_operation_attempt
  and upstream.leased_by=publication.control_operation_lease_owner and upstream.lease_expires_at>now()
  and ((publication.publication_kind='projection'
    and ((upstream.kind='tenant.provision' and upstream.queue='tenant-provisioning')
     or (upstream.kind in ('tenant.reconcile','module.enable','module.restrict','webshop-domain.reconcile')
      and upstream.queue='tenant-reconciliation')
     or (upstream.kind='tenant.lifecycle' and upstream.queue='tenant-lifecycle'))
    and driver.state='in_progress' and driver.safe_error is null
    and driver.execution_token=p_execution_token and driver.lease_expires_at>now())
   or (publication.publication_kind in ('recovery_maintenance','recovery_restore')
    and protocol.recovery_ready and upstream.kind='tenant.lifecycle'
    and upstream.queue='tenant-lifecycle'
    and effect.kind='recovery-maintenance' and effect.workshop_id=publication.target_workshop_id
    and effect.control_operation_id=publication.control_operation_id
    and effect.control_operation_attempt=publication.control_operation_attempt
    and effect.control_operation_lease_owner=publication.control_operation_lease_owner
    and effect.state=case publication.publication_kind when 'recovery_maintenance' then 'reserved' else 'restore_started' end
    and effect.instance_owner=p_instance_owner and effect.execution_token=p_execution_token
    and effect.route_lease_token=p_route_lease_token and effect.lease_expires_at>now()))
  and global_lease.state='held' and global_lease.authority_kind='route-set-publication'
  and global_lease.route_set_publication_id=p_publication_id
  and global_lease.lease_owner=p_instance_owner and global_lease.lease_token=p_global_lease_token
  and global_lease.fence_token=p_global_fence_token and global_lease.lease_expires_at>now()
  and route_lease.state='held' and route_lease.authority_kind='route-set-publication'
  and route_lease.route_set_publication_id=p_publication_id
  and route_lease.lease_owner=p_instance_owner and route_lease.lease_token=p_route_lease_token
  and route_lease.fence_token=p_target_route_fence_token and route_lease.lease_expires_at>now()
  and route_lease.generation=target.target_generation
  and route_lease.projection_digest=target.target_projection_digest
  and target.target_route_fence_token=p_target_route_fence_token)
$function$;

create or replace function control.lock_route_set_publication_authority(
 p_publication_id uuid,p_instance_owner uuid,p_execution_token uuid,
 p_global_lease_token uuid,p_route_lease_token uuid,p_global_fence_token bigint,
 p_target_route_fence_token bigint
) returns boolean language plpgsql volatile security definer set search_path=pg_catalog,control as $function$
declare v_control uuid; v_target uuid; v_driver uuid; v_effect uuid;
begin
 select control_operation_id,target_workshop_id,driver_operation_id,recovery_effect_run_id
 into v_control,v_target,v_driver,v_effect from control.workshop_route_set_publications
 where publication_id=p_publication_id;
 if not found then return false; end if;
 perform 1 from control.route_set_publication_protocol_state where singleton for update;
 perform 1 from control.operations where id=v_control for update;
 perform 1 from control.deployment_driver_resource_leases where resource_key='runtime/shared-odoo' for update;
 perform 1 from control.workshop_route_application_leases where workshop_id=v_target for update;
 if v_driver is not null then
  perform 1 from control.deployment_driver_operations where id=v_driver for update;
 else
  perform 1 from control.workshop_route_effect_runs where id=v_effect for update;
  perform 1 from control.workshop_route_effect_reservations
   where effect_run_id=v_effect and workshop_id=v_target for update;
 end if;
 perform 1 from control.workshop_route_set_publications where publication_id=p_publication_id for update;
 return control.has_route_set_publication_authority(p_publication_id,p_instance_owner,p_execution_token,
  p_global_lease_token,p_route_lease_token,p_global_fence_token,p_target_route_fence_token);
end $function$;

create or replace function control.record_route_set_publication_entry(
 p_publication_id uuid,p_instance_owner uuid,p_execution_token uuid,p_global_lease_token uuid,
 p_route_lease_token uuid,p_global_fence_token bigint,p_target_route_fence_token bigint,
 p_workshop_id uuid,p_generation bigint,p_projection_digest text,p_disposition text,
 p_applied_rendered_digest text,p_rendered_digest text
) returns text language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_publication control.workshop_route_set_publications%rowtype;
 v_snapshot control.workshop_route_set_publication_snapshot%rowtype;
 v_existing control.workshop_route_set_publication_records%rowtype; v_expected uuid;
begin
 if p_rendered_digest is null or p_rendered_digest !~ '^sha256:[0-9a-f]{64}$' then return 'invalid'; end if;
 if not control.lock_route_set_publication_authority(p_publication_id,p_instance_owner,p_execution_token,
   p_global_lease_token,p_route_lease_token,p_global_fence_token,p_target_route_fence_token) then return 'authority_lost'; end if;
 select * into v_existing from control.workshop_route_set_publication_records
 where publication_id=p_publication_id and workshop_id=p_workshop_id;
 if found then
  if v_existing.generation=p_generation and v_existing.projection_digest=p_projection_digest
   and v_existing.disposition=p_disposition
   and v_existing.applied_rendered_digest=p_applied_rendered_digest
   and v_existing.rendered_digest=p_rendered_digest then return 'replay'; end if;
  return 'conflict';
 end if;
 select * into v_publication from control.workshop_route_set_publications
 where publication_id=p_publication_id for update;
 if v_publication.phase<>'staging' then return 'wrong_phase'; end if;
 if v_publication.prior_recorded_at is null then return 'prior_absent'; end if;
 select snapshot.workshop_id into v_expected from control.workshop_route_set_publication_snapshot snapshot
 where snapshot.publication_id=p_publication_id and not exists(
  select 1 from control.workshop_route_set_publication_records record
  where record.publication_id=snapshot.publication_id and record.workshop_id=snapshot.workshop_id)
 order by snapshot.workshop_id limit 1;
 if v_expected is distinct from p_workshop_id then return 'out_of_order'; end if;
 select * into v_snapshot from control.workshop_route_set_publication_snapshot snapshot
 where snapshot.publication_id=p_publication_id and snapshot.workshop_id=p_workshop_id
  and snapshot.generation=p_generation and snapshot.projection_digest=p_projection_digest
  and snapshot.disposition=p_disposition
  and snapshot.baseline_applied_rendered_digest=p_applied_rendered_digest;
 if not found then return 'snapshot_drift'; end if;
 if (not v_snapshot.is_target and p_rendered_digest<>v_snapshot.baseline_applied_rendered_digest)
  or (p_disposition='absent'
   and p_rendered_digest<>'sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
  or (v_snapshot.is_target and v_publication.publication_kind='recovery_maintenance'
   and p_disposition<>'present') then return 'render_invariant_mismatch'; end if;
 insert into control.workshop_route_set_publication_records(publication_id,workshop_id,generation,
  projection_digest,disposition,applied_rendered_digest,rendered_digest)
 values(p_publication_id,p_workshop_id,p_generation,p_projection_digest,p_disposition,
  p_applied_rendered_digest,p_rendered_digest);
 return 'recorded';
end $function$;

create function control.admit_route_set_recovery_maintenance(
 p_control_operation_id uuid,p_control_operation_attempt integer,p_control_operation_lease_owner text,
 p_workshop_id uuid,p_reason text,p_idempotency_key text,p_request_digest text,
 p_instance_owner uuid,p_execution_token uuid,p_global_lease_token uuid,p_route_lease_token uuid,
 p_ttl_seconds integer
) returns table(outcome text,publication_id uuid,effect_run_id uuid,target_workshop_id uuid,global_fence_token bigint,
 target_route_fence_token bigint,selector text,snapshot_count integer,target_generation bigint,
 target_projection_digest text,target_disposition text,stored_response jsonb)
language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_protocol control.route_set_publication_protocol_state%rowtype;
 v_upstream control.operations%rowtype; v_global control.deployment_driver_resource_leases%rowtype;
 v_route control.workshop_route_application_leases%rowtype;
 v_state control.workshop_route_projection_state%rowtype; v_effect control.workshop_route_effect_runs%rowtype;
 v_existing control.workshop_route_set_publications%rowtype;
 v_restore control.workshop_route_set_publications%rowtype;
 v_publication_id uuid:=gen_random_uuid(); v_effect_id uuid:=gen_random_uuid();
 v_global_fence bigint; v_route_fence bigint; v_count integer; v_ready integer; v_selected integer;
 v_expires timestamptz; v_exact integer;
begin
 if p_reason is distinct from 'restore' or p_control_operation_id is null
  or p_control_operation_attempt is null or p_control_operation_attempt<=0
  or p_control_operation_lease_owner is null or btrim(p_control_operation_lease_owner)=''
  or p_workshop_id is null or p_idempotency_key is null or length(p_idempotency_key) not between 1 and 180
  or p_request_digest is null or p_request_digest !~ '^[0-9a-f]{64}$'
  or p_instance_owner is null or p_execution_token is null or p_global_lease_token is null
  or p_route_lease_token is null or p_ttl_seconds is null or p_ttl_seconds not between 60 and 1200 then
  return query select 'invalid',null::uuid,null::uuid,null::uuid,null::bigint,null::bigint,null::text,null::integer,
   null::bigint,null::text,null::text,null::jsonb; return;
 end if;
 select * into strict v_protocol from control.route_set_publication_protocol_state where singleton for update;
 if v_protocol.mode<>'generation_v1' or not v_protocol.recovery_ready then
  return query select 'protocol_inactive',null::uuid,null::uuid,null::uuid,null::bigint,null::bigint,null::text,null::integer,
   null::bigint,null::text,null::text,null::jsonb; return;
 end if;
 select * into v_upstream from control.operations where id=p_control_operation_id for update;
 if not found or v_upstream.workshop_id is distinct from p_workshop_id
  or v_upstream.kind is distinct from 'tenant.lifecycle'
  or v_upstream.queue is distinct from 'tenant-lifecycle'
  or v_upstream.state is distinct from 'in_flight'
  or v_upstream.attempt is distinct from p_control_operation_attempt
  or v_upstream.leased_by is distinct from p_control_operation_lease_owner
  or v_upstream.lease_expires_at<=now() then
  return query select 'upstream_lease_lost',null::uuid,null::uuid,null::uuid,null::bigint,null::bigint,null::text,null::integer,
   null::bigint,null::text,null::text,null::jsonb; return;
 end if;
 select * into v_global from control.deployment_driver_resource_leases
  where resource_key='runtime/shared-odoo' for update;
 perform 1 from control.workshop_route_application_leases order by workshop_id for update;
 perform 1 from control.workshop_route_projection_state order by workshop_id for update;
 select * into v_effect from control.workshop_route_effect_runs where kind='recovery-maintenance'
  and (idempotency_key=p_idempotency_key
   or target_key='maintenance/'||p_workshop_id::text||'/'||p_control_operation_id::text)
 order by (idempotency_key=p_idempotency_key) desc limit 1 for update;
 if found then
  select * into v_existing from control.workshop_route_set_publications
   where recovery_effect_run_id=v_effect.id and publication_kind='recovery_maintenance';
  if v_effect.idempotency_key is distinct from p_idempotency_key
   or v_effect.request_digest is distinct from p_request_digest
   or v_effect.control_operation_id is distinct from p_control_operation_id
   or v_effect.workshop_id is distinct from p_workshop_id or not found then
   return query select 'conflict',null::uuid,v_effect.id,null::uuid,null::bigint,null::bigint,
    null::text,null::integer,null::bigint,null::text,null::text,null::jsonb; return;
  end if;
  select * into v_restore from control.workshop_route_set_publications
   where recovery_effect_run_id=v_effect.id and publication_kind='recovery_restore'
    and (phase='completed' or (phase='quarantined' and recovery_terminal_kind='candidate'
     and recovery_terminal_at is not null
     and jsonb_typeof(recovery_terminal_response->'effect_response')='object'));
  if found and v_effect.state='succeeded' then
   return query select 'replay',v_restore.publication_id,v_effect.id,v_effect.workshop_id,
    v_restore.original_global_fence_token,
    (select target.target_route_fence_token from control.workshop_route_set_publication_targets target where target.publication_id=v_restore.publication_id),v_restore.selector,v_restore.snapshot_count,
    (select target.target_generation from control.workshop_route_set_publication_targets target where target.publication_id=v_restore.publication_id),
    (select target.target_projection_digest from control.workshop_route_set_publication_targets target where target.publication_id=v_restore.publication_id),
    (select target.target_disposition from control.workshop_route_set_publication_targets target where target.publication_id=v_restore.publication_id),
    case when v_restore.phase='completed' then v_restore.final_response
      else v_restore.recovery_terminal_response->'effect_response' end; return;
  end if;
  if v_existing.recovery_terminal_at is not null then
   return query select case when v_existing.recovery_terminal_kind='candidate' then 'replay' else 'not_applied' end,
    v_existing.publication_id,v_effect.id,v_effect.workshop_id,
    v_existing.original_global_fence_token,
    (select target.target_route_fence_token from control.workshop_route_set_publication_targets target where target.publication_id=v_existing.publication_id),v_existing.selector,v_existing.snapshot_count,
    (select target.target_generation from control.workshop_route_set_publication_targets target where target.publication_id=v_existing.publication_id),
    (select target.target_projection_digest from control.workshop_route_set_publication_targets target where target.publication_id=v_existing.publication_id),
    (select target.target_disposition from control.workshop_route_set_publication_targets target where target.publication_id=v_existing.publication_id),
    case when v_existing.recovery_terminal_kind='candidate'
      then v_existing.recovery_terminal_response->'effect_response'
      else v_existing.recovery_terminal_response end; return;
  end if;
  if v_existing.phase='completed' then
   return query select 'replay',v_existing.publication_id,v_effect.id,v_effect.workshop_id,
    v_existing.original_global_fence_token,
    (select target.target_route_fence_token from control.workshop_route_set_publication_targets target where target.publication_id=v_existing.publication_id),v_existing.selector,v_existing.snapshot_count,
    (select target.target_generation from control.workshop_route_set_publication_targets target where target.publication_id=v_existing.publication_id),
    (select target.target_projection_digest from control.workshop_route_set_publication_targets target where target.publication_id=v_existing.publication_id),
    (select target.target_disposition from control.workshop_route_set_publication_targets target where target.publication_id=v_existing.publication_id),
    v_existing.final_response; return;
  end if;
  return query select 'busy',v_existing.publication_id,v_effect.id,v_effect.workshop_id,v_existing.original_global_fence_token,
   (select target.target_route_fence_token from control.workshop_route_set_publication_targets target where target.publication_id=v_existing.publication_id),v_existing.selector,v_existing.snapshot_count,
   (select target.target_generation from control.workshop_route_set_publication_targets target where target.publication_id=v_existing.publication_id),
   (select target.target_projection_digest from control.workshop_route_set_publication_targets target where target.publication_id=v_existing.publication_id),
   (select target.target_disposition from control.workshop_route_set_publication_targets target where target.publication_id=v_existing.publication_id),null::jsonb; return;
 end if;
 if v_global.state is distinct from 'idle' then
  return query select case when v_global.state='quarantined' then 'fleet_quarantined' else 'fleet_busy' end,
   v_global.route_set_publication_id,v_global.effect_run_id,null::uuid,v_global.fence_token,null::bigint,null::text,null::integer,
   null::bigint,null::text,null::text,null::jsonb; return;
 end if;
 select * into strict v_route from control.workshop_route_application_leases where workshop_id=p_workshop_id;
 select * into strict v_state from control.workshop_route_projection_state where workshop_id=p_workshop_id;
 select count(*) into v_count from control.workshops;
 select count(*) into v_ready from control.workshops workshop
 join control.workshop_route_application_leases lease on lease.workshop_id=workshop.id
 join control.workshop_route_projection_state state on state.workshop_id=workshop.id
 where lease.state='idle' and state.applied_generation is not null and state.applied_digest is not null
  and state.applied_disposition is not null and state.applied_rendered_digest is not null
  and state.applied_fence_token>0
  and ((state.applied_driver_operation_id is not null)<>(state.applied_effect_run_id is not null));
 select count(*) into v_selected from control.workshop_route_projection_state state
 join control.workshop_route_projections projection on projection.workshop_id=state.workshop_id
  and projection.generation=state.applied_generation and projection.projection_digest=state.applied_digest
  and projection.disposition=state.applied_disposition;
 if v_count not between 1 and 500 or v_ready<>v_count or v_selected<>v_count
  or v_route.state is distinct from 'idle'
  or v_state.applied_disposition is distinct from 'present'
  or v_state.desired_generation is distinct from v_state.applied_generation
  or v_state.desired_digest is distinct from v_state.applied_digest
  or v_state.desired_disposition is distinct from v_state.applied_disposition then
  return query select 'fleet_not_ready',null::uuid,null::uuid,p_workshop_id,null::bigint,v_route.fence_token,null::text,v_count,
   null::bigint,null::text,null::text,null::jsonb; return;
 end if;
 v_expires:=now()+make_interval(secs=>p_ttl_seconds);
 v_global_fence:=v_global.fence_token+1;
 v_route_fence:=greatest(v_route.fence_token,v_state.applied_fence_token)+1;
 insert into control.workshop_route_effect_runs(id,kind,reason,target_key,idempotency_key,request_digest,
  workshop_id,control_operation_id,control_operation_attempt,control_operation_lease_owner,state,
  instance_owner,execution_token,route_lease_token,lease_expires_at,heartbeat_at)
 values(v_effect_id,'recovery-maintenance','restore','maintenance/'||p_workshop_id::text||'/'||p_control_operation_id::text,
  p_idempotency_key,p_request_digest,p_workshop_id,p_control_operation_id,p_control_operation_attempt,
  p_control_operation_lease_owner,'reserved',p_instance_owner,p_execution_token,p_route_lease_token,v_expires,now());
 insert into control.workshop_route_effect_reservations(effect_run_id,workshop_id,generation,
  projection_digest,disposition,baseline_generation,baseline_projection_digest,baseline_disposition,
  route_fence_token,action,prior_lease_state)
 values(v_effect_id,p_workshop_id,v_state.applied_generation,v_state.applied_digest,v_state.applied_disposition,
  v_state.applied_generation,v_state.applied_digest,v_state.applied_disposition,v_route_fence,'maintenance','idle');
 insert into control.workshop_route_set_publications(publication_id,protocol_version,publication_kind,
  driver_operation_id,recovery_effect_run_id,control_operation_id,control_operation_attempt,
  control_operation_lease_owner,original_instance_owner,original_execution_token,
  original_global_lease_token,original_route_lease_token,original_global_fence_token,target_workshop_id,
  selector,snapshot_count,phase,trace_parent,trace_state,correlation_id)
 values(v_publication_id,1,'recovery_maintenance',null,v_effect_id,p_control_operation_id,
  p_control_operation_attempt,p_control_operation_lease_owner,p_instance_owner,p_execution_token,
  p_global_lease_token,p_route_lease_token,v_global_fence,p_workshop_id,
  'generations/route-'||replace(v_publication_id::text,'-','')||'-recovery-maintenance',
  v_count,'staging',v_upstream.trace_parent,v_upstream.trace_state,v_upstream.correlation_id);
 insert into control.workshop_route_set_publication_targets(publication_id,workshop_id,
  prior_applied_generation,prior_applied_digest,prior_applied_disposition,prior_applied_rendered_digest,
  prior_applied_driver_operation_id,prior_applied_effect_run_id,prior_applied_fence_token,
  target_generation,target_projection_digest,target_disposition,target_route_fence_token)
 values(v_publication_id,p_workshop_id,v_state.applied_generation,v_state.applied_digest,
  v_state.applied_disposition,v_state.applied_rendered_digest,v_state.applied_driver_operation_id,
  v_state.applied_effect_run_id,v_state.applied_fence_token,v_state.applied_generation,
  v_state.applied_digest,v_state.applied_disposition,v_route_fence);
 insert into control.workshop_route_set_publication_snapshot(publication_id,workshop_id,generation,
  projection_digest,disposition,canonical_projection,baseline_applied_generation,baseline_applied_digest,
  baseline_applied_disposition,baseline_applied_rendered_digest,baseline_applied_driver_operation_id,
  baseline_applied_effect_run_id,baseline_applied_fence_token,is_target)
 select v_publication_id,state.workshop_id,state.applied_generation,state.applied_digest,
  state.applied_disposition,projection.projection,state.applied_generation,state.applied_digest,
  state.applied_disposition,state.applied_rendered_digest,state.applied_driver_operation_id,
  state.applied_effect_run_id,state.applied_fence_token,state.workshop_id=p_workshop_id
 from control.workshop_route_projection_state state join control.workshop_route_projections projection
  on projection.workshop_id=state.workshop_id and projection.generation=state.applied_generation
  and projection.projection_digest=state.applied_digest and projection.disposition=state.applied_disposition
 order by state.workshop_id;
 get diagnostics v_exact=row_count;
 if v_exact<>v_count then raise exception 'recovery-maintenance snapshot drifted' using errcode='40001'; end if;
 update control.deployment_driver_resource_leases set state='held',authority_kind='route-set-publication',
  driver_operation_id=null,effect_run_id=null,route_set_publication_id=v_publication_id,
  fence_token=v_global_fence,lease_owner=p_instance_owner,lease_token=p_global_lease_token,
  lease_expires_at=v_expires,heartbeat_at=now(),updated_at=now()
 where resource_key='runtime/shared-odoo' and state='idle';
 get diagnostics v_exact=row_count;
 if v_exact<>1 then raise exception 'recovery-maintenance global authority drifted' using errcode='40001'; end if;
 update control.workshop_route_application_leases set state='held',authority_kind='route-set-publication',
  driver_operation_id=null,effect_run_id=null,release_publication_id=null,
  route_set_publication_id=v_publication_id,fence_token=v_route_fence,
  generation=v_state.applied_generation,projection_digest=v_state.applied_digest,
  lease_owner=p_instance_owner,lease_token=p_route_lease_token,lease_expires_at=v_expires,
  heartbeat_at=now(),updated_at=now() where workshop_id=p_workshop_id and state='idle';
 get diagnostics v_exact=row_count;
 if v_exact<>1 then raise exception 'recovery-maintenance route authority drifted' using errcode='40001'; end if;
 return query select 'acquired',v_publication_id,v_effect_id,p_workshop_id,v_global_fence,v_route_fence,
  'generations/route-'||replace(v_publication_id::text,'-','')||'-recovery-maintenance',v_count,
  v_state.applied_generation,v_state.applied_digest,v_state.applied_disposition,null::jsonb;
end $function$;

create function control.admit_route_set_recovery_restore(
 p_effect_run_id uuid,p_workshop_id uuid,p_control_operation_id uuid,p_control_operation_attempt integer,
 p_control_operation_lease_owner text,p_instance_owner uuid,p_execution_token uuid,
 p_global_lease_token uuid,p_route_lease_token uuid,p_ttl_seconds integer
) returns table(outcome text,publication_id uuid,effect_run_id uuid,target_workshop_id uuid,global_fence_token bigint,
 target_route_fence_token bigint,selector text,snapshot_count integer,target_generation bigint,
 target_projection_digest text,target_disposition text,stored_response jsonb)
language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_protocol control.route_set_publication_protocol_state%rowtype;
 v_upstream control.operations%rowtype; v_global control.deployment_driver_resource_leases%rowtype;
 v_route control.workshop_route_application_leases%rowtype;
 v_state control.workshop_route_projection_state%rowtype; v_effect control.workshop_route_effect_runs%rowtype;
 v_reservation control.workshop_route_effect_reservations%rowtype;
 v_existing control.workshop_route_set_publications%rowtype;
 v_success control.workshop_route_set_publications%rowtype;
 v_entry control.workshop_route_set_publications%rowtype;
 v_publication_id uuid:=gen_random_uuid(); v_global_fence bigint; v_count integer;
 v_ready integer; v_selected integer; v_expires timestamptz; v_exact integer;
begin
 if p_effect_run_id is null or p_workshop_id is null or p_control_operation_id is null
  or p_control_operation_attempt is null or p_control_operation_attempt<=0
  or p_control_operation_lease_owner is null or btrim(p_control_operation_lease_owner)=''
  or p_instance_owner is null or p_execution_token is null or p_global_lease_token is null
  or p_route_lease_token is null or p_ttl_seconds is null or p_ttl_seconds not between 60 and 1200 then
  return query select 'invalid',null::uuid,p_effect_run_id,null::uuid,null::bigint,null::bigint,null::text,null::integer,
   null::bigint,null::text,null::text,null::jsonb; return;
 end if;
 select * into strict v_protocol from control.route_set_publication_protocol_state where singleton for update;
 if v_protocol.mode<>'generation_v1' or not v_protocol.recovery_ready then
  return query select 'protocol_inactive',null::uuid,p_effect_run_id,null::uuid,null::bigint,null::bigint,null::text,null::integer,
   null::bigint,null::text,null::text,null::jsonb; return;
 end if;
 select * into v_upstream from control.operations where id=p_control_operation_id for update;
 if not found or v_upstream.workshop_id is distinct from p_workshop_id
  or v_upstream.kind is distinct from 'tenant.lifecycle'
  or v_upstream.queue is distinct from 'tenant-lifecycle'
  or v_upstream.state is distinct from 'in_flight'
  or v_upstream.attempt is distinct from p_control_operation_attempt
  or v_upstream.leased_by is distinct from p_control_operation_lease_owner
  or v_upstream.lease_expires_at<=now() then
  return query select 'upstream_lease_lost',null::uuid,p_effect_run_id,null::uuid,null::bigint,null::bigint,null::text,null::integer,
   null::bigint,null::text,null::text,null::jsonb; return;
 end if;
 select * into v_global from control.deployment_driver_resource_leases
  where resource_key='runtime/shared-odoo' for update;
 perform 1 from control.workshop_route_application_leases order by workshop_id for update;
 perform 1 from control.workshop_route_projection_state order by workshop_id for update;
 select * into v_effect from control.workshop_route_effect_runs where id=p_effect_run_id for update;
 if not found or v_effect.kind is distinct from 'recovery-maintenance'
  or v_effect.control_operation_id is distinct from p_control_operation_id
  or v_effect.workshop_id is distinct from p_workshop_id then
  return query select 'not_maintenance',null::uuid,p_effect_run_id,v_effect.workshop_id,null::bigint,null::bigint,null::text,null::integer,
   null::bigint,null::text,null::text,null::jsonb; return;
 end if;
 select * into v_entry from control.workshop_route_set_publications
  where recovery_effect_run_id=p_effect_run_id and publication_kind='recovery_maintenance'
   and (phase='completed' or (phase='quarantined' and recovery_terminal_kind='candidate'
    and recovery_terminal_at is not null
    and jsonb_typeof(recovery_terminal_response->'effect_response')='object'));
 if not found then
  return query select 'not_maintenance',null::uuid,p_effect_run_id,p_workshop_id,
   null::bigint,null::bigint,null::text,null::integer,null::bigint,null::text,null::text,null::jsonb; return;
 end if;
 select * into v_success from control.workshop_route_set_publications
  where recovery_effect_run_id=p_effect_run_id and publication_kind='recovery_restore'
   and (phase='completed' or (phase='quarantined' and recovery_terminal_kind='candidate'
    and recovery_terminal_at is not null))
  order by created_at desc limit 1;
 if found and v_effect.state='succeeded' then
  return query select 'replay',v_success.publication_id,p_effect_run_id,v_effect.workshop_id,
   v_success.original_global_fence_token,
   (select target.target_route_fence_token from control.workshop_route_set_publication_targets target where target.publication_id=v_success.publication_id),
   v_success.selector,v_success.snapshot_count,
   (select target.target_generation from control.workshop_route_set_publication_targets target where target.publication_id=v_success.publication_id),
   (select target.target_projection_digest from control.workshop_route_set_publication_targets target where target.publication_id=v_success.publication_id),
   (select target.target_disposition from control.workshop_route_set_publication_targets target where target.publication_id=v_success.publication_id),
   case when v_success.phase='completed' then v_success.final_response
    else v_success.recovery_terminal_response->'effect_response' end; return;
 end if;
 select * into v_existing from control.workshop_route_set_publications
  where recovery_effect_run_id=p_effect_run_id and publication_kind='recovery_restore'
   and control_operation_id=p_control_operation_id
   and control_operation_attempt=p_control_operation_attempt;
 if found then
  if v_existing.control_operation_id is distinct from p_control_operation_id then
   return query select 'conflict',v_existing.publication_id,p_effect_run_id,v_effect.workshop_id,
    v_existing.original_global_fence_token,
    (select target.target_route_fence_token from control.workshop_route_set_publication_targets target where target.publication_id=v_existing.publication_id),v_existing.selector,
    v_existing.snapshot_count,null::bigint,null::text,null::text,null::jsonb; return;
  end if;
  if v_existing.recovery_terminal_at is not null then
   return query select case when v_existing.recovery_terminal_kind='candidate' then 'replay' else 'not_applied' end,
    v_existing.publication_id,p_effect_run_id,v_effect.workshop_id,
    v_existing.original_global_fence_token,
    (select target.target_route_fence_token from control.workshop_route_set_publication_targets target where target.publication_id=v_existing.publication_id),
    v_existing.selector,v_existing.snapshot_count,
    (select target.target_generation from control.workshop_route_set_publication_targets target where target.publication_id=v_existing.publication_id),
    (select target.target_projection_digest from control.workshop_route_set_publication_targets target where target.publication_id=v_existing.publication_id),
    (select target.target_disposition from control.workshop_route_set_publication_targets target where target.publication_id=v_existing.publication_id),
    case when v_existing.recovery_terminal_kind='candidate'
      then v_existing.recovery_terminal_response->'effect_response'
      else v_existing.recovery_terminal_response end; return;
  end if;
  if v_existing.phase='completed' then
   return query select 'replay',v_existing.publication_id,p_effect_run_id,v_effect.workshop_id,
    v_existing.original_global_fence_token,
    (select target.target_route_fence_token from control.workshop_route_set_publication_targets target where target.publication_id=v_existing.publication_id),v_existing.selector,
    v_existing.snapshot_count,
    (select target.target_generation from control.workshop_route_set_publication_targets target where target.publication_id=v_existing.publication_id),
    (select target.target_projection_digest from control.workshop_route_set_publication_targets target where target.publication_id=v_existing.publication_id),
    (select target.target_disposition from control.workshop_route_set_publication_targets target where target.publication_id=v_existing.publication_id),
    v_existing.final_response; return;
  end if;
  return query select 'busy',v_existing.publication_id,p_effect_run_id,v_effect.workshop_id,
   v_existing.original_global_fence_token,
   (select target.target_route_fence_token from control.workshop_route_set_publication_targets target where target.publication_id=v_existing.publication_id),v_existing.selector,
   v_existing.snapshot_count,
   (select target.target_generation from control.workshop_route_set_publication_targets target where target.publication_id=v_existing.publication_id),
   (select target.target_projection_digest from control.workshop_route_set_publication_targets target where target.publication_id=v_existing.publication_id),
   (select target.target_disposition from control.workshop_route_set_publication_targets target where target.publication_id=v_existing.publication_id),null::jsonb; return;
 end if;
 if v_effect.state is distinct from 'maintenance' then
  return query select 'not_maintenance',null::uuid,p_effect_run_id,v_effect.workshop_id,null::bigint,null::bigint,null::text,null::integer,
   null::bigint,null::text,null::text,null::jsonb; return;
 end if;
 select * into strict v_reservation from control.workshop_route_effect_reservations reservation
  where reservation.effect_run_id=p_effect_run_id and reservation.workshop_id=v_effect.workshop_id for update;
 select * into strict v_route from control.workshop_route_application_leases route_lease
  where route_lease.workshop_id=v_effect.workshop_id;
 select * into strict v_state from control.workshop_route_projection_state projection_state
  where projection_state.workshop_id=v_effect.workshop_id;
 if v_global.state is distinct from 'idle' then
  return query select case when v_global.state='quarantined' then 'fleet_quarantined' else 'fleet_busy' end,
   v_global.route_set_publication_id,p_effect_run_id,v_effect.workshop_id,v_global.fence_token,v_reservation.route_fence_token,
   null::text,null::integer,null::bigint,null::text,null::text,null::jsonb; return;
 end if;
 if v_route.state<>'maintenance' or v_route.authority_kind<>'recovery-maintenance'
  or v_route.effect_run_id<>p_effect_run_id or v_route.fence_token<>v_reservation.route_fence_token
  or v_route.lease_owner is not null or v_route.lease_token is not null
  or v_route.lease_expires_at is not null or v_route.safe_error<>'recovery_maintenance'
  or v_state.desired_generation is null then
  return query select 'authority_lost',null::uuid,p_effect_run_id,v_effect.workshop_id,null::bigint,v_reservation.route_fence_token,
   null::text,null::integer,null::bigint,null::text,null::text,null::jsonb; return;
 end if;
 select count(*) into v_count from control.workshops;
 select count(*) into v_ready from control.workshops workshop
 join control.workshop_route_application_leases lease on lease.workshop_id=workshop.id
 join control.workshop_route_projection_state state on state.workshop_id=workshop.id
 where (lease.state='idle' or (lease.workshop_id=v_effect.workshop_id and lease.state='maintenance'
    and lease.effect_run_id=p_effect_run_id))
  and state.applied_generation is not null and state.applied_digest is not null
  and state.applied_disposition is not null and state.applied_rendered_digest is not null
  and state.applied_fence_token>0
  and ((state.applied_driver_operation_id is not null)<>(state.applied_effect_run_id is not null));
 select count(*) into v_selected from control.workshop_route_projection_state state
 join control.workshop_route_projections projection on projection.workshop_id=state.workshop_id
  and projection.generation=case when state.workshop_id=v_effect.workshop_id then state.desired_generation else state.applied_generation end
  and projection.projection_digest=case when state.workshop_id=v_effect.workshop_id then state.desired_digest else state.applied_digest end
  and projection.disposition=case when state.workshop_id=v_effect.workshop_id then state.desired_disposition else state.applied_disposition end;
 if v_count not between 1 and 500 or v_ready<>v_count or v_selected<>v_count then
  return query select 'fleet_not_ready',null::uuid,p_effect_run_id,v_effect.workshop_id,null::bigint,v_reservation.route_fence_token,
   null::text,v_count,null::bigint,null::text,null::text,null::jsonb; return;
 end if;
 v_expires:=now()+make_interval(secs=>p_ttl_seconds); v_global_fence:=v_global.fence_token+1;
 insert into control.workshop_route_set_publications(publication_id,protocol_version,publication_kind,
  driver_operation_id,recovery_effect_run_id,control_operation_id,control_operation_attempt,
  control_operation_lease_owner,original_instance_owner,original_execution_token,
  original_global_lease_token,original_route_lease_token,original_global_fence_token,target_workshop_id,
  selector,snapshot_count,phase,trace_parent,trace_state,correlation_id)
 values(v_publication_id,1,'recovery_restore',null,p_effect_run_id,p_control_operation_id,
  p_control_operation_attempt,p_control_operation_lease_owner,p_instance_owner,p_execution_token,
  p_global_lease_token,p_route_lease_token,v_global_fence,v_effect.workshop_id,
  'generations/route-'||replace(v_publication_id::text,'-','')||'-recovery-restore',
  v_count,'staging',v_upstream.trace_parent,v_upstream.trace_state,v_upstream.correlation_id);
 insert into control.workshop_route_set_publication_targets(publication_id,workshop_id,
  prior_applied_generation,prior_applied_digest,prior_applied_disposition,prior_applied_rendered_digest,
  prior_applied_driver_operation_id,prior_applied_effect_run_id,prior_applied_fence_token,
  target_generation,target_projection_digest,target_disposition,target_route_fence_token)
 values(v_publication_id,v_effect.workshop_id,v_state.applied_generation,v_state.applied_digest,
  v_state.applied_disposition,v_state.applied_rendered_digest,v_state.applied_driver_operation_id,
  v_state.applied_effect_run_id,v_state.applied_fence_token,v_state.desired_generation,
  v_state.desired_digest,v_state.desired_disposition,v_reservation.route_fence_token);
 insert into control.workshop_route_set_publication_snapshot(publication_id,workshop_id,generation,
  projection_digest,disposition,canonical_projection,baseline_applied_generation,baseline_applied_digest,
  baseline_applied_disposition,baseline_applied_rendered_digest,baseline_applied_driver_operation_id,
  baseline_applied_effect_run_id,baseline_applied_fence_token,is_target)
 select v_publication_id,state.workshop_id,
  case when state.workshop_id=v_effect.workshop_id then state.desired_generation else state.applied_generation end,
  case when state.workshop_id=v_effect.workshop_id then state.desired_digest else state.applied_digest end,
  case when state.workshop_id=v_effect.workshop_id then state.desired_disposition else state.applied_disposition end,
  projection.projection,state.applied_generation,state.applied_digest,state.applied_disposition,
  state.applied_rendered_digest,state.applied_driver_operation_id,state.applied_effect_run_id,
  state.applied_fence_token,state.workshop_id=v_effect.workshop_id
 from control.workshop_route_projection_state state join control.workshop_route_projections projection
  on projection.workshop_id=state.workshop_id
  and projection.generation=case when state.workshop_id=v_effect.workshop_id then state.desired_generation else state.applied_generation end
  and projection.projection_digest=case when state.workshop_id=v_effect.workshop_id then state.desired_digest else state.applied_digest end
  and projection.disposition=case when state.workshop_id=v_effect.workshop_id then state.desired_disposition else state.applied_disposition end
 order by state.workshop_id;
 get diagnostics v_exact=row_count;
 if v_exact<>v_count then raise exception 'recovery-restore snapshot drifted' using errcode='40001'; end if;
 update control.workshop_route_effect_reservations reservation set generation=v_state.desired_generation,
  projection_digest=v_state.desired_digest,disposition=v_state.desired_disposition,
  action=case when v_state.desired_disposition='absent' then 'remove-absent' else 'render' end,updated_at=now()
 where reservation.effect_run_id=p_effect_run_id and reservation.workshop_id=v_effect.workshop_id
  and reservation.state='maintenance';
 get diagnostics v_exact=row_count;
 if v_exact<>1 then raise exception 'recovery reservation drifted' using errcode='40001'; end if;
 update control.workshop_route_effect_runs effect set state='restore_started',
  control_operation_attempt=p_control_operation_attempt,
  control_operation_lease_owner=p_control_operation_lease_owner,instance_owner=p_instance_owner,
  execution_token=p_execution_token,route_lease_token=p_route_lease_token,
  lease_expires_at=v_expires,heartbeat_at=now(),safe_error=null,updated_at=now()
 where effect.id=p_effect_run_id and effect.state='maintenance';
 get diagnostics v_exact=row_count;
 if v_exact<>1 then raise exception 'recovery effect drifted' using errcode='40001'; end if;
 update control.deployment_driver_resource_leases global_lease set state='held',authority_kind='route-set-publication',
  driver_operation_id=null,effect_run_id=null,route_set_publication_id=v_publication_id,
  fence_token=v_global_fence,lease_owner=p_instance_owner,lease_token=p_global_lease_token,
  lease_expires_at=v_expires,heartbeat_at=now(),updated_at=now()
 where global_lease.resource_key='runtime/shared-odoo' and global_lease.state='idle';
 get diagnostics v_exact=row_count;
 if v_exact<>1 then raise exception 'recovery global authority drifted' using errcode='40001'; end if;
 update control.workshop_route_application_leases route_lease set state='held',authority_kind='route-set-publication',
  effect_run_id=null,route_set_publication_id=v_publication_id,
  generation=v_state.desired_generation,projection_digest=v_state.desired_digest,
  lease_owner=p_instance_owner,lease_token=p_route_lease_token,lease_expires_at=v_expires,
  heartbeat_at=now(),safe_error=null,updated_at=now()
 where route_lease.workshop_id=v_effect.workshop_id and route_lease.state='maintenance'
  and route_lease.authority_kind='recovery-maintenance'
  and route_lease.effect_run_id=p_effect_run_id
  and route_lease.fence_token=v_reservation.route_fence_token;
 get diagnostics v_exact=row_count;
 if v_exact<>1 then raise exception 'recovery route authority drifted' using errcode='40001'; end if;
 return query select 'acquired',v_publication_id,p_effect_run_id,v_effect.workshop_id,v_global_fence,
  v_reservation.route_fence_token,
  'generations/route-'||replace(v_publication_id::text,'-','')||'-recovery-restore',v_count,
 v_state.desired_generation,v_state.desired_digest,v_state.desired_disposition,null::jsonb;
end $function$;

-- Keep the projection implementation intact behind a protocol-first wrapper;
-- recovery publications quarantine their effect owner instead of a driver row.
alter function control.quarantine_route_set_publication(
 uuid,uuid,uuid,uuid,uuid,bigint,bigint,text
) rename to quarantine_route_set_publication_projection_v1;

create function control.quarantine_recovery_route_set_publication(
 p_publication_id uuid,p_instance_owner uuid,p_execution_token uuid,p_global_lease_token uuid,
 p_route_lease_token uuid,p_global_fence_token bigint,p_target_route_fence_token bigint,
 p_safe_error text
) returns boolean language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_publication control.workshop_route_set_publications%rowtype;
 v_target control.workshop_route_set_publication_targets%rowtype;
 v_upstream control.operations%rowtype; v_effect control.workshop_route_effect_runs%rowtype;
 v_global control.deployment_driver_resource_leases%rowtype;
 v_route control.workshop_route_application_leases%rowtype; v_expired boolean; v_changed integer;
begin
 if p_safe_error is distinct from 'route_set_publication_outcome_unknown' then return false; end if;
 select * into v_publication from control.workshop_route_set_publications
  where publication_id=p_publication_id;
 if not found or v_publication.publication_kind not in ('recovery_maintenance','recovery_restore') then return false; end if;
 select * into strict v_target from control.workshop_route_set_publication_targets where publication_id=p_publication_id;
 select * into v_upstream from control.operations where id=v_publication.control_operation_id for update;
 select * into v_global from control.deployment_driver_resource_leases
  where resource_key='runtime/shared-odoo' for update;
 select * into v_route from control.workshop_route_application_leases
  where workshop_id=v_target.workshop_id for update;
 select * into v_effect from control.workshop_route_effect_runs
  where id=v_publication.recovery_effect_run_id for update;
 select * into strict v_publication from control.workshop_route_set_publications
  where publication_id=p_publication_id for update;
 if v_publication.original_instance_owner is distinct from p_instance_owner
  or v_publication.original_execution_token is distinct from p_execution_token
  or v_publication.original_global_lease_token is distinct from p_global_lease_token
  or v_publication.original_route_lease_token is distinct from p_route_lease_token
  or v_publication.original_global_fence_token is distinct from p_global_fence_token
  or v_target.target_route_fence_token is distinct from p_target_route_fence_token then return false; end if;
 if v_publication.phase='quarantined' then
  return coalesce(v_global.state='quarantined' and v_route.state='quarantined'
   and v_effect.state='quarantined' and v_global.route_set_publication_id=p_publication_id
   and v_route.route_set_publication_id=p_publication_id,false);
 end if;
 if v_publication.phase not in ('staging','sealed','publication_started','observed')
  or v_global.state is distinct from 'held'
  or v_global.authority_kind is distinct from 'route-set-publication'
  or v_global.route_set_publication_id is distinct from p_publication_id
  or v_global.lease_owner is distinct from p_instance_owner
  or v_global.lease_token is distinct from p_global_lease_token
  or v_global.fence_token is distinct from p_global_fence_token
  or v_route.state is distinct from 'held'
  or v_route.authority_kind is distinct from 'route-set-publication'
  or v_route.route_set_publication_id is distinct from p_publication_id
  or v_route.lease_owner is distinct from p_instance_owner
  or v_route.lease_token is distinct from p_route_lease_token
  or v_route.fence_token is distinct from p_target_route_fence_token
  or v_effect.instance_owner is distinct from p_instance_owner
  or v_effect.execution_token is distinct from p_execution_token
  or v_effect.route_lease_token is distinct from p_route_lease_token then return false; end if;
 v_expired:=coalesce(v_upstream.lease_expires_at<=now(),true)
  or coalesce(v_effect.lease_expires_at<=now(),true)
  or coalesce(v_global.lease_expires_at<=now(),true)
  or coalesce(v_route.lease_expires_at<=now(),true);
 if v_publication.phase in ('staging','sealed') and not v_expired then return false; end if;
 update control.deployment_driver_resource_leases set state='quarantined',lease_token=null,
  lease_expires_at=null,quarantined_at=now(),safe_error='runtime_outcome_unknown',updated_at=now()
 where resource_key='runtime/shared-odoo' and state='held' and route_set_publication_id=p_publication_id;
 get diagnostics v_changed=row_count; if v_changed<>1 then raise exception 'recovery global quarantine drifted' using errcode='40001'; end if;
 update control.workshop_route_application_leases set state='quarantined',lease_token=null,
  lease_expires_at=null,quarantined_at=now(),safe_error='route_set_publication_outcome_unknown',updated_at=now()
 where workshop_id=v_target.workshop_id and state='held' and route_set_publication_id=p_publication_id;
 get diagnostics v_changed=row_count; if v_changed<>1 then raise exception 'recovery route quarantine drifted' using errcode='40001'; end if;
 update control.workshop_route_effect_reservations set state='quarantined',updated_at=now()
 where effect_run_id=v_effect.id and workshop_id=v_target.workshop_id
  and state=case v_publication.publication_kind when 'recovery_maintenance' then 'reserved' else 'maintenance' end;
 get diagnostics v_changed=row_count; if v_changed<>1 then raise exception 'recovery reservation quarantine drifted' using errcode='40001'; end if;
 update control.workshop_route_effect_runs set state='quarantined',instance_owner=null,
  execution_token=null,route_lease_token=null,lease_expires_at=null,
  safe_error='runtime_outcome_unknown',finished_at=now(),updated_at=now()
 where id=v_effect.id and state=case v_publication.publication_kind
  when 'recovery_maintenance' then 'reserved' else 'restore_started' end;
 get diagnostics v_changed=row_count; if v_changed<>1 then raise exception 'recovery effect quarantine drifted' using errcode='40001'; end if;
 update control.workshop_route_set_publications set interrupted_phase=phase,phase='quarantined',
  quarantined_at=now(),safe_error=p_safe_error,recovery_eligible_at=now(),
  recovery_write_eligible=(publication_started_at is null and phase in ('staging','sealed')),updated_at=now()
 where publication_id=p_publication_id;
 return true;
end $function$;

create function control.quarantine_route_set_publication(
 p_publication_id uuid,p_instance_owner uuid,p_execution_token uuid,p_global_lease_token uuid,
 p_route_lease_token uuid,p_global_fence_token bigint,p_target_route_fence_token bigint,p_safe_error text
) returns boolean language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_kind text;
begin
 perform 1 from control.route_set_publication_protocol_state where singleton for update;
 select publication_kind into v_kind from control.workshop_route_set_publications
  where publication_id=p_publication_id;
 if v_kind='projection' then
  return control.quarantine_route_set_publication_projection_v1(p_publication_id,p_instance_owner,
   p_execution_token,p_global_lease_token,p_route_lease_token,p_global_fence_token,
   p_target_route_fence_token,p_safe_error);
 end if;
 return control.quarantine_recovery_route_set_publication(p_publication_id,p_instance_owner,
  p_execution_token,p_global_lease_token,p_route_lease_token,p_global_fence_token,
  p_target_route_fence_token,p_safe_error);
end $function$;

create function control.read_route_set_recovery_maintenance_admission(
 p_workshop_id uuid,p_control_operation_id uuid,p_control_operation_attempt integer,
 p_control_operation_lease_owner text,p_idempotency_key text,p_request_digest text
) returns table(outcome text,publication_id uuid,effect_run_id uuid,target_workshop_id uuid,
 global_fence_token bigint,target_route_fence_token bigint,selector text,snapshot_count integer,
 target_generation bigint,target_projection_digest text,target_disposition text,stored_response jsonb)
language plpgsql stable security definer set search_path=pg_catalog,control as $function$
declare v_protocol control.route_set_publication_protocol_state%rowtype;
 v_upstream control.operations%rowtype; v_effect control.workshop_route_effect_runs%rowtype;
 v_entry control.workshop_route_set_publications%rowtype;
 v_restore control.workshop_route_set_publications%rowtype; v_publication control.workshop_route_set_publications%rowtype;
begin
 if p_workshop_id is null or p_control_operation_id is null or p_control_operation_attempt is null
  or p_control_operation_attempt<=0 or p_control_operation_lease_owner is null
  or btrim(p_control_operation_lease_owner)='' or p_idempotency_key is null
  or length(p_idempotency_key) not between 1 and 180
  or p_request_digest is null or p_request_digest !~ '^[0-9a-f]{64}$' then
  return query select 'invalid',null::uuid,null::uuid,null::uuid,null::bigint,null::bigint,
   null::text,null::integer,null::bigint,null::text,null::text,null::jsonb; return;
 end if;
 select * into strict v_protocol from control.route_set_publication_protocol_state where singleton;
 if v_protocol.mode is distinct from 'generation_v1' or not v_protocol.recovery_ready then
  return query select 'protocol_inactive',null::uuid,null::uuid,null::uuid,null::bigint,null::bigint,
   null::text,null::integer,null::bigint,null::text,null::text,null::jsonb; return;
 end if;
 select * into v_upstream from control.operations where id=p_control_operation_id;
 if not found or v_upstream.workshop_id is distinct from p_workshop_id
  or v_upstream.kind is distinct from 'tenant.lifecycle'
  or v_upstream.queue is distinct from 'tenant-lifecycle'
  or v_upstream.state is distinct from 'in_flight'
  or v_upstream.attempt is distinct from p_control_operation_attempt
  or v_upstream.leased_by is distinct from p_control_operation_lease_owner
  or v_upstream.lease_expires_at<=now() then
  return query select 'upstream_lease_lost',null::uuid,null::uuid,null::uuid,null::bigint,null::bigint,
   null::text,null::integer,null::bigint,null::text,null::text,null::jsonb; return;
 end if;
 select * into v_effect from control.workshop_route_effect_runs where kind='recovery-maintenance'
  and (idempotency_key=p_idempotency_key
   or target_key='maintenance/'||p_workshop_id::text||'/'||p_control_operation_id::text)
 order by (idempotency_key=p_idempotency_key) desc limit 1;
 if not found then
  return query select 'absent',null::uuid,null::uuid,null::uuid,null::bigint,null::bigint,
   null::text,null::integer,null::bigint,null::text,null::text,null::jsonb; return;
 end if;
 if v_effect.idempotency_key is distinct from p_idempotency_key
  or v_effect.request_digest is distinct from p_request_digest
  or v_effect.control_operation_id is distinct from p_control_operation_id
  or v_effect.workshop_id is distinct from p_workshop_id then
  return query select 'conflict',null::uuid,null::uuid,null::uuid,null::bigint,null::bigint,
   null::text,null::integer,null::bigint,null::text,null::text,null::jsonb; return;
 end if;
 select * into v_restore from control.workshop_route_set_publications
  where recovery_effect_run_id=v_effect.id and publication_kind='recovery_restore'
   and (phase='completed' or (phase='quarantined' and recovery_terminal_kind='candidate'
    and recovery_terminal_at is not null))
  order by created_at desc limit 1;
 if found and v_effect.state='succeeded' then v_publication:=v_restore;
 else
  select * into v_entry from control.workshop_route_set_publications
   where recovery_effect_run_id=v_effect.id and publication_kind='recovery_maintenance';
  if not found then
   return query select 'conflict',null::uuid,null::uuid,null::uuid,null::bigint,null::bigint,
    null::text,null::integer,null::bigint,null::text,null::text,null::jsonb; return;
  end if;
  v_publication:=v_entry;
 end if;
 return query select
  case when v_publication.recovery_terminal_at is not null then
    case when v_publication.recovery_terminal_kind='candidate' then 'replay' else 'not_applied' end
   when v_publication.phase='completed' then 'replay' else 'busy' end,
  v_publication.publication_id,v_effect.id,v_effect.workshop_id,v_publication.original_global_fence_token,
  target.target_route_fence_token,v_publication.selector,v_publication.snapshot_count,
  target.target_generation,target.target_projection_digest,target.target_disposition,
  case when v_publication.recovery_terminal_at is not null then
    case when v_publication.recovery_terminal_kind='candidate'
      then v_publication.recovery_terminal_response->'effect_response'
      else v_publication.recovery_terminal_response end
   when v_publication.phase='completed' then v_publication.final_response else null end
 from control.workshop_route_set_publication_targets target
 where target.publication_id=v_publication.publication_id;
end $function$;

create function control.read_route_set_recovery_restore_admission(
 p_effect_run_id uuid,p_workshop_id uuid,p_control_operation_id uuid,
 p_control_operation_attempt integer,p_control_operation_lease_owner text
) returns table(outcome text,publication_id uuid,effect_run_id uuid,target_workshop_id uuid,
 global_fence_token bigint,target_route_fence_token bigint,selector text,snapshot_count integer,
 target_generation bigint,target_projection_digest text,target_disposition text,stored_response jsonb)
language plpgsql stable security definer set search_path=pg_catalog,control as $function$
declare v_protocol control.route_set_publication_protocol_state%rowtype;
 v_upstream control.operations%rowtype; v_effect control.workshop_route_effect_runs%rowtype;
 v_publication control.workshop_route_set_publications%rowtype;
 v_entry control.workshop_route_set_publications%rowtype;
begin
 if p_effect_run_id is null or p_workshop_id is null or p_control_operation_id is null
  or p_control_operation_attempt is null or p_control_operation_attempt<=0
  or p_control_operation_lease_owner is null or btrim(p_control_operation_lease_owner)='' then
  return query select 'invalid',null::uuid,null::uuid,null::uuid,null::bigint,null::bigint,
   null::text,null::integer,null::bigint,null::text,null::text,null::jsonb; return;
 end if;
 select * into strict v_protocol from control.route_set_publication_protocol_state where singleton;
 if v_protocol.mode is distinct from 'generation_v1' or not v_protocol.recovery_ready then
  return query select 'protocol_inactive',null::uuid,null::uuid,null::uuid,null::bigint,null::bigint,
   null::text,null::integer,null::bigint,null::text,null::text,null::jsonb; return;
 end if;
 select * into v_upstream from control.operations where id=p_control_operation_id;
 if not found or v_upstream.workshop_id is distinct from p_workshop_id
  or v_upstream.kind is distinct from 'tenant.lifecycle'
  or v_upstream.queue is distinct from 'tenant-lifecycle'
  or v_upstream.state is distinct from 'in_flight'
  or v_upstream.attempt is distinct from p_control_operation_attempt
  or v_upstream.leased_by is distinct from p_control_operation_lease_owner
  or v_upstream.lease_expires_at<=now() then
  return query select 'upstream_lease_lost',null::uuid,null::uuid,null::uuid,null::bigint,null::bigint,
   null::text,null::integer,null::bigint,null::text,null::text,null::jsonb; return;
 end if;
 select * into v_effect from control.workshop_route_effect_runs where id=p_effect_run_id;
 if not found or v_effect.kind is distinct from 'recovery-maintenance'
  or v_effect.control_operation_id is distinct from p_control_operation_id
  or v_effect.workshop_id is distinct from p_workshop_id then
  return query select 'conflict',null::uuid,null::uuid,null::uuid,null::bigint,null::bigint,
   null::text,null::integer,null::bigint,null::text,null::text,null::jsonb; return;
 end if;
 select * into v_entry from control.workshop_route_set_publications
  where recovery_effect_run_id=p_effect_run_id and publication_kind='recovery_maintenance'
   and (phase='completed' or (phase='quarantined' and recovery_terminal_kind='candidate'
    and recovery_terminal_at is not null
    and jsonb_typeof(recovery_terminal_response->'effect_response')='object'));
 if not found then
  return query select 'conflict',null::uuid,null::uuid,null::uuid,null::bigint,null::bigint,
   null::text,null::integer,null::bigint,null::text,null::text,null::jsonb; return;
 end if;
 if v_effect.state='succeeded' then
  select * into v_publication from control.workshop_route_set_publications
   where recovery_effect_run_id=p_effect_run_id and publication_kind='recovery_restore'
    and (phase='completed' or (phase='quarantined' and recovery_terminal_kind='candidate'
     and recovery_terminal_at is not null))
   order by created_at desc limit 1;
 else
  select * into v_publication from control.workshop_route_set_publications
   where recovery_effect_run_id=p_effect_run_id and publication_kind='recovery_restore'
    and control_operation_id=p_control_operation_id
    and control_operation_attempt=p_control_operation_attempt
   order by created_at desc limit 1;
 end if;
 if not found then
  return query select 'absent',null::uuid,null::uuid,null::uuid,null::bigint,null::bigint,
   null::text,null::integer,null::bigint,null::text,null::text,null::jsonb; return;
 end if;
 return query select
  case when v_publication.recovery_terminal_at is not null then
    case when v_publication.recovery_terminal_kind='candidate' then 'replay' else 'not_applied' end
   when v_publication.phase='completed' then 'replay' else 'busy' end,
  v_publication.publication_id,v_effect.id,v_effect.workshop_id,v_publication.original_global_fence_token,
  target.target_route_fence_token,v_publication.selector,v_publication.snapshot_count,
  target.target_generation,target.target_projection_digest,target.target_disposition,
  case when v_publication.recovery_terminal_at is not null then
    case when v_publication.recovery_terminal_kind='candidate'
      then v_publication.recovery_terminal_response->'effect_response'
      else v_publication.recovery_terminal_response end
   when v_publication.phase='completed' then v_publication.final_response else null end
 from control.workshop_route_set_publication_targets target
 where target.publication_id=v_publication.publication_id;
end $function$;

create or replace function control.discover_interrupted_route_set_publications(
 p_after_publication_id uuid,p_limit integer
) returns table(publication_id uuid,target_workshop_id uuid,publication_kind text,
 interrupted_phase text,claim_mode text,claim_fence bigint,claim_available boolean,
 selector text,route_set_digest text,updated_at timestamptz)
language plpgsql stable security definer set search_path=pg_catalog,control as $function$
begin
 if p_limit is null or p_limit not between 1 and 100 then return; end if;
 return query select publication.publication_id,publication.target_workshop_id,
  publication.publication_kind,publication.interrupted_phase,
  case when publication.recovery_eligible_at is not null and publication.recovery_write_eligible
   and publication.publication_started_at is null and publication.interrupted_phase in ('staging','sealed')
   then 'write_cleanup' else 'observe_only' end,publication.reconciliation_claim_fence,
  publication.reconciliation_owner is null or publication.reconciliation_expires_at<=now(),
  publication.selector,publication.route_set_digest,publication.updated_at
 from control.workshop_route_set_publications publication
 where publication.phase='quarantined' and publication.recovery_terminal_at is null
  and (p_after_publication_id is null or publication.publication_id>p_after_publication_id)
 order by publication.publication_id limit p_limit;
end $function$;

alter function control.claim_interrupted_route_set_publication(
 uuid,uuid,integer,text,uuid,uuid,integer
) rename to claim_interrupted_route_set_publication_projection_v1;

create function control.claim_interrupted_recovery_route_set_publication(
 p_publication_id uuid,p_reconciliation_operation_id uuid,
 p_reconciliation_operation_attempt integer,p_reconciliation_operation_lease_owner text,
 p_reconciliation_owner uuid,p_reconciliation_token uuid,p_ttl_seconds integer
) returns table(outcome text,claim_fence bigint,claim_mode text)
language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_publication control.workshop_route_set_publications%rowtype;
 v_reconciliation control.operations%rowtype; v_upstream control.operations%rowtype;
 v_global control.deployment_driver_resource_leases%rowtype;
 v_route control.workshop_route_application_leases%rowtype;
 v_effect control.workshop_route_effect_runs%rowtype;
 v_target control.workshop_route_set_publication_targets%rowtype;
 v_all_expired boolean; v_mode text; v_fence bigint; v_changed integer;
begin
 if p_publication_id is null or p_reconciliation_operation_id is null
  or p_reconciliation_operation_attempt is null or p_reconciliation_operation_attempt<=0
  or p_reconciliation_operation_lease_owner is null or btrim(p_reconciliation_operation_lease_owner)=''
  or p_reconciliation_owner is null or p_reconciliation_token is null
  or p_ttl_seconds is null or p_ttl_seconds not between 60 and 1200 then
  return query select 'invalid',null::bigint,null::text; return;
 end if;
 select * into v_publication from control.workshop_route_set_publications
  where publication_id=p_publication_id;
 if not found or v_publication.publication_kind not in ('recovery_maintenance','recovery_restore') then
  return query select 'invalid',null::bigint,null::text; return;
 end if;
 perform 1 from control.operations where id in
  (v_publication.control_operation_id,p_reconciliation_operation_id) order by id for update;
 select * into v_upstream from control.operations where id=v_publication.control_operation_id;
 select * into v_reconciliation from control.operations where id=p_reconciliation_operation_id;
 select * into v_global from control.deployment_driver_resource_leases
  where resource_key='runtime/shared-odoo' for update;
 select * into v_route from control.workshop_route_application_leases
  where workshop_id=v_publication.target_workshop_id for update;
 select * into v_effect from control.workshop_route_effect_runs
  where id=v_publication.recovery_effect_run_id for update;
 select * into strict v_publication from control.workshop_route_set_publications
  where publication_id=p_publication_id for update;
 select * into strict v_target from control.workshop_route_set_publication_targets
  where publication_id=p_publication_id;
 if v_reconciliation.id is null
  or v_reconciliation.workshop_id is distinct from v_publication.target_workshop_id
  or v_reconciliation.kind is distinct from 'tenant.reconcile'
  or v_reconciliation.queue is distinct from 'tenant-reconciliation'
  or v_reconciliation.state is distinct from 'in_flight'
  or v_reconciliation.attempt is distinct from p_reconciliation_operation_attempt
  or v_reconciliation.leased_by is distinct from p_reconciliation_operation_lease_owner
  or v_reconciliation.lease_expires_at<=now()
  or v_reconciliation.payload->>'route_set_publication_id' is distinct from p_publication_id::text
  or v_reconciliation.payload->>'protocol_version' is distinct from '1' then
  return query select 'reconciliation_lease_lost',null::bigint,null::text; return;
 end if;
 if v_publication.reconciliation_owner is not null and v_publication.reconciliation_expires_at>now() then
  if v_publication.reconciliation_operation_id=p_reconciliation_operation_id
   and v_publication.reconciliation_operation_attempt=p_reconciliation_operation_attempt
   and v_publication.reconciliation_operation_lease_owner=p_reconciliation_operation_lease_owner
   and v_publication.reconciliation_owner=p_reconciliation_owner
   and v_publication.reconciliation_token=p_reconciliation_token then
   return query select 'replay',v_publication.reconciliation_claim_fence,
    v_publication.reconciliation_claim_mode; return;
  end if;
  return query select 'busy',v_publication.reconciliation_claim_fence,
   v_publication.reconciliation_claim_mode; return;
 end if;
 if v_publication.phase<>'quarantined' then
  if v_publication.phase not in ('staging','sealed','publication_started','observed')
   or v_global.state is distinct from 'held'
   or v_global.route_set_publication_id is distinct from p_publication_id
   or v_route.state is distinct from 'held'
   or v_route.route_set_publication_id is distinct from p_publication_id
   or v_effect.state is distinct from (case v_publication.publication_kind
      when 'recovery_maintenance' then 'reserved' else 'restore_started' end) then
   return query select 'authority_inconsistent',null::bigint,null::text; return;
  end if;
  v_all_expired:=coalesce(v_upstream.lease_expires_at<=now(),false)
   and coalesce(v_effect.lease_expires_at<=now(),false)
   and coalesce(v_global.lease_expires_at<=now(),false)
   and coalesce(v_route.lease_expires_at<=now(),false);
  if not v_all_expired then return query select 'not_expired',null::bigint,null::text; return; end if;
  update control.deployment_driver_resource_leases set state='quarantined',lease_token=null,
   lease_expires_at=null,quarantined_at=now(),safe_error='runtime_outcome_unknown',updated_at=now()
  where resource_key='runtime/shared-odoo' and state='held' and route_set_publication_id=p_publication_id;
  get diagnostics v_changed=row_count; if v_changed<>1 then raise exception 'recovery claim global drifted' using errcode='40001'; end if;
  update control.workshop_route_application_leases set state='quarantined',lease_token=null,
   lease_expires_at=null,quarantined_at=now(),safe_error='route_set_publication_outcome_unknown',updated_at=now()
  where workshop_id=v_target.workshop_id and state='held' and route_set_publication_id=p_publication_id;
  get diagnostics v_changed=row_count; if v_changed<>1 then raise exception 'recovery claim route drifted' using errcode='40001'; end if;
  update control.workshop_route_effect_reservations set state='quarantined',updated_at=now()
   where effect_run_id=v_effect.id and workshop_id=v_target.workshop_id
    and state=case v_publication.publication_kind when 'recovery_maintenance' then 'reserved' else 'maintenance' end;
  get diagnostics v_changed=row_count;
  if v_changed<>1 then raise exception 'recovery claim reservation drifted' using errcode='40001'; end if;
  update control.workshop_route_effect_runs set state='quarantined',instance_owner=null,
   execution_token=null,route_lease_token=null,lease_expires_at=null,
   safe_error='runtime_outcome_unknown',finished_at=now(),updated_at=now() where id=v_effect.id
    and state=case v_publication.publication_kind when 'recovery_maintenance' then 'reserved' else 'restore_started' end;
  get diagnostics v_changed=row_count;
  if v_changed<>1 then raise exception 'recovery claim effect drifted' using errcode='40001'; end if;
  update control.workshop_route_set_publications set interrupted_phase=phase,phase='quarantined',
   quarantined_at=now(),safe_error='route_set_publication_outcome_unknown',recovery_eligible_at=now(),
   recovery_write_eligible=(publication_started_at is null and phase in ('staging','sealed')),updated_at=now()
   where publication_id=p_publication_id and phase=v_publication.phase;
  get diagnostics v_changed=row_count;
  if v_changed<>1 then raise exception 'recovery claim publication drifted' using errcode='40001'; end if;
  select * into strict v_publication from control.workshop_route_set_publications
   where publication_id=p_publication_id;
 else
  if v_global.state is distinct from 'quarantined'
   or v_global.route_set_publication_id is distinct from p_publication_id
   or v_route.state is distinct from 'quarantined'
   or v_route.route_set_publication_id is distinct from p_publication_id
   or v_effect.state is distinct from 'quarantined' then
   return query select 'authority_inconsistent',null::bigint,null::text; return;
  end if;
 end if;
 v_mode:=case when v_publication.recovery_write_eligible
  and v_publication.publication_started_at is null and v_publication.interrupted_phase in ('staging','sealed')
  then 'write_cleanup' else 'observe_only' end;
 v_fence:=v_publication.reconciliation_claim_fence+1;
 update control.workshop_route_set_publications set
  reconciliation_operation_id=p_reconciliation_operation_id,
  reconciliation_operation_attempt=p_reconciliation_operation_attempt,
  reconciliation_operation_lease_owner=p_reconciliation_operation_lease_owner,
  reconciliation_owner=p_reconciliation_owner,reconciliation_token=p_reconciliation_token,
  reconciliation_expires_at=least(v_reconciliation.lease_expires_at,
   now()+make_interval(secs=>p_ttl_seconds)),reconciliation_claim_fence=v_fence,
  reconciliation_claim_mode=v_mode,updated_at=now() where publication_id=p_publication_id
   and phase='quarantined' and recovery_terminal_at is null
   and (reconciliation_owner is null or reconciliation_expires_at<=now());
 get diagnostics v_changed=row_count;
 if v_changed<>1 then raise exception 'recovery claim ownership drifted' using errcode='40001'; end if;
 return query select 'acquired',v_fence,v_mode;
end $function$;

alter function control.admit_route_set_publication(
 uuid,integer,text,uuid,text,text,text,bigint,text,uuid,uuid,uuid,uuid,integer
) rename to admit_route_set_publication_projection_v1;

create function control.admit_route_set_publication(
 p_control_operation_id uuid,p_control_operation_attempt integer,p_control_operation_lease_owner text,
 p_workshop_id uuid,p_publication_kind text,p_idempotency_key text,p_request_digest text,
 p_generation bigint,p_projection_digest text,p_instance_owner uuid,p_execution_token uuid,
 p_global_lease_token uuid,p_route_lease_token uuid,p_ttl_seconds integer
) returns table(outcome text,publication_id uuid,driver_operation_id uuid,global_fence_token bigint,
 target_route_fence_token bigint,selector text,snapshot_count integer)
language plpgsql security definer set search_path=pg_catalog,control as $function$
begin
 perform 1 from control.route_set_publication_protocol_state where singleton for update;
 return query select * from control.admit_route_set_publication_projection_v1(
  p_control_operation_id,p_control_operation_attempt,p_control_operation_lease_owner,
  p_workshop_id,p_publication_kind,p_idempotency_key,p_request_digest,p_generation,
  p_projection_digest,p_instance_owner,p_execution_token,p_global_lease_token,
  p_route_lease_token,p_ttl_seconds);
end $function$;

create function control.claim_interrupted_route_set_publication(
 p_publication_id uuid,p_reconciliation_operation_id uuid,
 p_reconciliation_operation_attempt integer,p_reconciliation_operation_lease_owner text,
 p_reconciliation_owner uuid,p_reconciliation_token uuid,p_ttl_seconds integer
) returns table(outcome text,claim_fence bigint,claim_mode text)
language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_kind text;
begin
 perform 1 from control.route_set_publication_protocol_state where singleton for update;
 select publication_kind into v_kind from control.workshop_route_set_publications
  where publication_id=p_publication_id;
 if v_kind='projection' then
  return query select * from control.claim_interrupted_route_set_publication_projection_v1(
   p_publication_id,p_reconciliation_operation_id,p_reconciliation_operation_attempt,
   p_reconciliation_operation_lease_owner,p_reconciliation_owner,p_reconciliation_token,p_ttl_seconds);
 end if;
 return query select * from control.claim_interrupted_recovery_route_set_publication(
 p_publication_id,p_reconciliation_operation_id,p_reconciliation_operation_attempt,
  p_reconciliation_operation_lease_owner,p_reconciliation_owner,p_reconciliation_token,p_ttl_seconds);
end $function$;

revoke all on function control.admit_route_set_recovery_maintenance(uuid,integer,text,uuid,text,text,text,uuid,uuid,uuid,uuid,integer) from public;
revoke all on function control.admit_route_set_recovery_restore(uuid,uuid,uuid,integer,text,uuid,uuid,uuid,uuid,integer) from public;
revoke all on function control.admit_route_set_publication(uuid,integer,text,uuid,text,text,text,bigint,text,uuid,uuid,uuid,uuid,integer) from public;
revoke all on function control.admit_route_set_publication_projection_v1(uuid,integer,text,uuid,text,text,text,bigint,text,uuid,uuid,uuid,uuid,integer) from public;
revoke all on function control.finish_route_set_recovery_publication(uuid,uuid,uuid,uuid,uuid,bigint,bigint) from public;
revoke all on function control.finish_route_set_publication(uuid,uuid,uuid,uuid,uuid,bigint,bigint) from public;
revoke all on function control.finish_route_set_publication_projection_v1(uuid,uuid,uuid,uuid,uuid,bigint,bigint) from public;
revoke all on function control.read_route_set_recovery_publication_result(uuid,uuid,uuid) from public;
revoke all on function control.read_route_set_recovery_maintenance_admission(uuid,uuid,integer,text,text,text) from public;
revoke all on function control.read_route_set_recovery_restore_admission(uuid,uuid,uuid,integer,text) from public;
revoke all on function control.quarantine_route_set_publication(uuid,uuid,uuid,uuid,uuid,bigint,bigint,text) from public;
revoke all on function control.claim_interrupted_route_set_publication(uuid,uuid,integer,text,uuid,uuid,integer) from public;
revoke all on function control.lock_interrupted_route_set_publication_claim(uuid,uuid,uuid,bigint) from public;
revoke all on function control.read_interrupted_route_set_publication_state(uuid,uuid,uuid,bigint) from public;
revoke all on function control.finish_route_set_publication_recovery(uuid,bigint,uuid,integer,text,uuid,uuid,text,text,text) from public;
revoke all on function control.quarantine_route_set_publication_projection_v1(uuid,uuid,uuid,uuid,uuid,bigint,bigint,text) from public;
revoke all on function control.quarantine_recovery_route_set_publication(uuid,uuid,uuid,uuid,uuid,bigint,bigint,text) from public;
revoke all on function control.claim_interrupted_route_set_publication_projection_v1(uuid,uuid,integer,text,uuid,uuid,integer) from public;
revoke all on function control.claim_interrupted_recovery_route_set_publication(uuid,uuid,integer,text,uuid,uuid,integer) from public;
revoke all on function control.lock_interrupted_route_set_publication_claim_projection_v1(uuid,uuid,uuid,bigint) from public;
revoke all on function control.lock_interrupted_recovery_route_set_publication_claim(uuid,uuid,uuid,bigint) from public;
revoke all on function control.read_interrupted_route_set_publication_state_projection_v1(uuid,uuid,uuid,bigint) from public;
revoke all on function control.read_interrupted_recovery_route_set_publication_state(uuid,uuid,uuid,bigint) from public;
revoke all on function control.finish_route_set_publication_recovery_projection_v1(uuid,bigint,uuid,integer,text,uuid,uuid,text,text,text) from public;
revoke all on function control.finish_recovery_route_set_publication_recovery(uuid,bigint,uuid,integer,text,uuid,uuid,text,text,text) from public;

do $migration$ declare v_role text; begin
 foreach v_role in array array['control_api','control_tenant_api','control_membership_worker','control_provisioning_worker',
  'control_invoice_worker','control_inventory_worker','control_email_worker','control_reconciliation_worker',
  'control_lifecycle_worker','control_backup_scheduler','control_driver_ledger','control_release_worker','control_privacy_worker'] loop
  if exists(select 1 from pg_roles where rolname=v_role) then
   execute format('revoke all on function control.quarantine_route_set_publication_projection_v1(uuid,uuid,uuid,uuid,uuid,bigint,bigint,text) from %I',v_role);
   execute format('revoke all on function control.quarantine_recovery_route_set_publication(uuid,uuid,uuid,uuid,uuid,bigint,bigint,text) from %I',v_role);
   execute format('revoke all on function control.claim_interrupted_route_set_publication_projection_v1(uuid,uuid,integer,text,uuid,uuid,integer) from %I',v_role);
   execute format('revoke all on function control.claim_interrupted_recovery_route_set_publication(uuid,uuid,integer,text,uuid,uuid,integer) from %I',v_role);
   execute format('revoke all on function control.lock_interrupted_route_set_publication_claim_projection_v1(uuid,uuid,uuid,bigint) from %I',v_role);
   execute format('revoke all on function control.lock_interrupted_recovery_route_set_publication_claim(uuid,uuid,uuid,bigint) from %I',v_role);
   execute format('revoke all on function control.read_interrupted_route_set_publication_state_projection_v1(uuid,uuid,uuid,bigint) from %I',v_role);
   execute format('revoke all on function control.read_interrupted_recovery_route_set_publication_state(uuid,uuid,uuid,bigint) from %I',v_role);
   execute format('revoke all on function control.finish_route_set_publication_recovery_projection_v1(uuid,bigint,uuid,integer,text,uuid,uuid,text,text,text) from %I',v_role);
   execute format('revoke all on function control.finish_recovery_route_set_publication_recovery(uuid,bigint,uuid,integer,text,uuid,uuid,text,text,text) from %I',v_role);
   execute format('revoke all on function control.admit_route_set_publication_projection_v1(uuid,integer,text,uuid,text,text,text,bigint,text,uuid,uuid,uuid,uuid,integer) from %I',v_role);
   execute format('revoke all on function control.finish_route_set_publication_projection_v1(uuid,uuid,uuid,uuid,uuid,bigint,bigint) from %I',v_role);
  end if;
 end loop;
 if exists(select 1 from pg_roles where rolname='control_driver_ledger') then
  grant execute on function control.admit_route_set_recovery_maintenance(uuid,integer,text,uuid,text,text,text,uuid,uuid,uuid,uuid,integer) to control_driver_ledger;
  grant execute on function control.admit_route_set_recovery_restore(uuid,uuid,uuid,integer,text,uuid,uuid,uuid,uuid,integer) to control_driver_ledger;
  grant execute on function control.admit_route_set_publication(uuid,integer,text,uuid,text,text,text,bigint,text,uuid,uuid,uuid,uuid,integer) to control_driver_ledger;
  grant execute on function control.finish_route_set_recovery_publication(uuid,uuid,uuid,uuid,uuid,bigint,bigint) to control_driver_ledger;
  grant execute on function control.finish_route_set_publication(uuid,uuid,uuid,uuid,uuid,bigint,bigint) to control_driver_ledger;
  grant execute on function control.read_route_set_recovery_publication_result(uuid,uuid,uuid) to control_driver_ledger;
  grant execute on function control.read_route_set_recovery_maintenance_admission(uuid,uuid,integer,text,text,text) to control_driver_ledger;
  grant execute on function control.read_route_set_recovery_restore_admission(uuid,uuid,uuid,integer,text) to control_driver_ledger;
  grant execute on function control.quarantine_route_set_publication(uuid,uuid,uuid,uuid,uuid,bigint,bigint,text) to control_driver_ledger;
  grant execute on function control.claim_interrupted_route_set_publication(uuid,uuid,integer,text,uuid,uuid,integer) to control_driver_ledger;
  grant execute on function control.read_interrupted_route_set_publication_state(uuid,uuid,uuid,bigint) to control_driver_ledger;
  grant execute on function control.finish_route_set_publication_recovery(uuid,bigint,uuid,integer,text,uuid,uuid,text,text,text) to control_driver_ledger;
 end if;
end $migration$;

comment on table control.workshop_route_set_publications is
'Immutable full-fleet publications with XOR deployment-driver or recovery-effect ownership; recovery publication remains dormant.';
