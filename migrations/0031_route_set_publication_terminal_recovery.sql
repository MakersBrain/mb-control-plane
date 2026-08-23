-- Dormant reviewed terminalization of exact migration-0030 observations.
-- This migration is function-only: it does not activate generation_v1 and has
-- no application call site.  The publication row deliberately retains its
-- quarantined phase as historical evidence; `recovery_terminal_at` is the
-- immutable terminal marker.  Only the resource/route quarantines are released.

alter table control.workshop_route_set_publications
 add column recovery_terminal_kind text,
 add column recovery_terminal_claim_fence bigint,
 add column recovery_terminal_operation_id uuid,
 add column recovery_terminal_operation_attempt integer,
 add column recovery_terminal_operation_lease_owner text,
 add column recovery_terminal_decision_digest text,
 add column recovery_terminal_response jsonb,
 add column recovery_terminal_at timestamptz,
 add constraint workshop_route_set_publications_recovery_terminal_operation_fkey
  foreign key(recovery_terminal_operation_id) references control.operations(id) on delete restrict,
 add constraint workshop_route_set_publications_recovery_terminal_check check(
  (recovery_terminal_kind is null and recovery_terminal_claim_fence is null
   and recovery_terminal_operation_id is null and recovery_terminal_operation_attempt is null
   and recovery_terminal_operation_lease_owner is null and recovery_terminal_decision_digest is null
   and recovery_terminal_response is null and recovery_terminal_at is null)
  or (recovery_terminal_kind is not null
   and recovery_terminal_claim_fence is not null
   and recovery_terminal_operation_id is not null
   and recovery_terminal_operation_attempt is not null
   and recovery_terminal_operation_lease_owner is not null
   and recovery_terminal_decision_digest is not null
   and recovery_terminal_response is not null and recovery_terminal_at is not null
   and phase='quarantined' and recovery_terminal_kind in ('candidate','prior','unstarted')
   and recovery_terminal_claim_fence>0 and recovery_terminal_operation_attempt>0
   and btrim(recovery_terminal_operation_lease_owner)<>''
   and recovery_terminal_decision_digest ~ '^[0-9a-f]{64}$'
   and jsonb_typeof(recovery_terminal_response)='object'
   and pg_column_size(recovery_terminal_response)<=16384 and recovery_terminal_at is not null));

create function control.validate_route_set_recovery_terminal_evidence()
returns trigger language plpgsql set search_path=pg_catalog,control as $function$
begin
 if new.recovery_terminal_at is not null and (
  new.recovery_terminal_response->>'publication_id' is distinct from new.publication_id::text
  or new.recovery_terminal_response->>'driver_operation_id' is distinct from new.driver_operation_id::text
  or new.recovery_terminal_response->>'target_workshop_id' is distinct from new.target_workshop_id::text
  or new.recovery_terminal_response->>'resolution_claim_fence'
     is distinct from new.recovery_terminal_claim_fence::text
  or new.recovery_terminal_response->>'resolution_kind' is distinct from new.recovery_terminal_kind
  or new.recovery_terminal_response->>'reconciliation_operation_id'
     is distinct from new.recovery_terminal_operation_id::text
  or new.recovery_terminal_response->>'reconciliation_operation_attempt'
     is distinct from new.recovery_terminal_operation_attempt::text
  or new.recovery_terminal_response->>'reconciliation_operation_lease_owner'
     is distinct from new.recovery_terminal_operation_lease_owner
  or new.recovery_terminal_response->>'decision_digest'
     is distinct from new.recovery_terminal_decision_digest
  or (select count(*) from jsonb_object_keys(new.recovery_terminal_response))<>11
  or (new.recovery_terminal_kind='candidate' and (
      new.recovery_terminal_response->>'outcome' is distinct from 'applied_recovered'
      or jsonb_typeof(new.recovery_terminal_response->'driver_response') is distinct from 'object'))
  or (new.recovery_terminal_kind in ('prior','unstarted') and (
      new.recovery_terminal_response->>'outcome' is distinct from 'not_applied'
      or new.recovery_terminal_response->'driver_response' is distinct from 'null'::jsonb))
 ) then
  raise exception 'route-set terminal recovery response is not exact' using errcode='55000';
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

create trigger workshop_route_set_publications_recovery_terminal_immutable
before update on control.workshop_route_set_publications for each row
execute function control.validate_route_set_recovery_terminal_evidence();

-- Resolved publications are no longer discoverable even though their retained
-- publication phase remains quarantined for historical provenance.
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
   and publication.publication_started_at is null
   and publication.interrupted_phase in ('staging','sealed')
   then 'write_cleanup' else 'observe_only' end,
  publication.reconciliation_claim_fence,
  publication.reconciliation_owner is null or publication.reconciliation_expires_at<=now(),
  publication.selector,publication.route_set_digest,publication.updated_at
 from control.workshop_route_set_publications publication
 where publication.phase='quarantined' and publication.publication_kind='projection'
  and publication.recovery_terminal_at is null
  and (p_after_publication_id is null or publication.publication_id>p_after_publication_id)
 order by publication.publication_id limit p_limit;
end $function$;

create function control.finish_route_set_publication_recovery(
 p_publication_id uuid,p_resolution_claim_fence bigint,
 p_reconciliation_operation_id uuid,p_reconciliation_operation_attempt integer,
 p_reconciliation_operation_lease_owner text,p_reconciliation_owner uuid,
 p_reconciliation_token uuid,p_resolution_kind text,
 p_decision text,p_decision_digest text
) returns table(outcome text,response jsonb)
language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_lookup control.workshop_route_set_publications%rowtype;
 v_upstream control.operations%rowtype; v_reconciliation control.operations%rowtype;
 v_global control.deployment_driver_resource_leases%rowtype;
 v_route control.workshop_route_application_leases%rowtype;
 v_driver control.deployment_driver_operations%rowtype;
 v_publication control.workshop_route_set_publications%rowtype;
 v_target control.workshop_route_set_publication_targets%rowtype;
 v_state control.workshop_route_projection_state%rowtype;
 v_record control.workshop_route_set_publication_records%rowtype;
 v_resolution control.workshop_route_set_publication_resolutions%rowtype;
 v_count integer; v_present integer; v_digest text; v_changed integer;
 v_snapshot_count integer; v_drift_count integer; v_record_drift_count integer;
 v_expected_identity jsonb; v_driver_response jsonb; v_response jsonb;
 v_token_digest text; v_expected_decision_digest text; v_protocol_mode text;
begin
 if p_publication_id is null or p_resolution_claim_fence is null or p_resolution_claim_fence<=0
  or p_reconciliation_operation_id is null or p_reconciliation_operation_attempt is null
  or p_reconciliation_operation_attempt<=0 or p_reconciliation_operation_lease_owner is null
  or btrim(p_reconciliation_operation_lease_owner)='' or p_reconciliation_owner is null
  or p_reconciliation_token is null or p_resolution_kind is null
  or p_resolution_kind not in ('candidate','prior','unstarted','inconclusive')
  or p_decision is null or p_decision not in ('accept','keep_quarantined')
  or p_decision_digest is null or p_decision_digest !~ '^[0-9a-f]{64}$'
  or ((p_resolution_kind='inconclusive') is distinct from (p_decision='keep_quarantined')) then
  return query select 'invalid',null::jsonb; return;
 end if;
 select * into v_lookup from control.workshop_route_set_publications
  where publication_id=p_publication_id;
 if not found then return query select 'absent',null::jsonb; return; end if;

 -- A terminal row and its resolution are immutable. Authenticate and replay
 -- that durable receipt without consulting or locking reusable live authority.
 if v_lookup.recovery_terminal_at is not null then
  select * into v_resolution from control.workshop_route_set_publication_resolutions
   where publication_id=p_publication_id and reconciliation_claim_fence=p_resolution_claim_fence;
  v_token_digest:=encode(public.digest(convert_to('mb-route-set-reconciliation-token-v1','UTF8')
   ||uuid_send(p_reconciliation_token),'sha256'),'hex');
  if v_resolution.publication_id is not null then
   v_expected_decision_digest:=encode(public.digest(
    convert_to('mb-route-set-terminal-decision-v1','UTF8')
    ||uuid_send(p_publication_id)||int8send(p_resolution_claim_fence)
    ||uuid_send(p_reconciliation_operation_id)||int4send(p_reconciliation_operation_attempt)
    ||int4send(octet_length(convert_to(p_reconciliation_operation_lease_owner,'UTF8')))
    ||convert_to(p_reconciliation_operation_lease_owner,'UTF8')
    ||uuid_send(p_reconciliation_owner)||decode(v_token_digest,'hex')
    ||int4send(octet_length(convert_to(p_resolution_kind,'UTF8')))||convert_to(p_resolution_kind,'UTF8')
    ||int4send(octet_length(convert_to(p_decision,'UTF8')))||convert_to(p_decision,'UTF8')
    ||public.digest(convert_to(v_resolution.evidence::text,'UTF8'),'sha256'),'sha256'),'hex');
  end if;
  if v_resolution.reconciliation_owner is not distinct from p_reconciliation_owner
   and v_resolution.reconciliation_token_digest is not distinct from v_token_digest
   and p_decision_digest is not distinct from v_expected_decision_digest
   and v_lookup.recovery_terminal_claim_fence is not distinct from p_resolution_claim_fence
   and v_lookup.recovery_terminal_operation_id is not distinct from p_reconciliation_operation_id
   and v_lookup.recovery_terminal_operation_attempt is not distinct from p_reconciliation_operation_attempt
   and v_lookup.recovery_terminal_operation_lease_owner is not distinct from p_reconciliation_operation_lease_owner
   and v_lookup.recovery_terminal_kind is not distinct from p_resolution_kind
   and v_lookup.recovery_terminal_decision_digest is not distinct from p_decision_digest then
   return query select 'replay',v_lookup.recovery_terminal_response; return;
  end if;
  return query select 'conflict',null::jsonb; return;
 end if;

 -- Canonical order: both operations by UUID, protocol, global, target route,
 -- driver, publication, target, every frozen applied head by workshop UUID,
 -- every immutable record by workshop UUID, then the observation.
 perform 1 from control.operations where id in
  (v_lookup.control_operation_id,p_reconciliation_operation_id) order by id for update;
 select * into v_upstream from control.operations where id=v_lookup.control_operation_id;
 select * into v_reconciliation from control.operations where id=p_reconciliation_operation_id;
 select mode into v_protocol_mode from control.route_set_publication_protocol_state
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
 perform 1 from control.workshop_route_projection_state state
  join control.workshop_route_set_publication_snapshot snapshot
   on snapshot.publication_id=p_publication_id and snapshot.workshop_id=state.workshop_id
  order by state.workshop_id for update of state;
 select * into v_state from control.workshop_route_projection_state
  where workshop_id=v_publication.target_workshop_id;
 perform 1 from control.workshop_route_set_publication_records record
  where record.publication_id=p_publication_id order by record.workshop_id for update;
 select * into v_record from control.workshop_route_set_publication_records
  where publication_id=p_publication_id and workshop_id=v_publication.target_workshop_id for update;
 select * into v_resolution from control.workshop_route_set_publication_resolutions
  where publication_id=p_publication_id and reconciliation_claim_fence=p_resolution_claim_fence for update;

 v_token_digest:=encode(public.digest(convert_to('mb-route-set-reconciliation-token-v1','UTF8')
  ||uuid_send(p_reconciliation_token),'sha256'),'hex');
 if v_resolution.publication_id is not null then
  v_expected_decision_digest:=encode(public.digest(
   convert_to('mb-route-set-terminal-decision-v1','UTF8')
   ||uuid_send(p_publication_id)||int8send(p_resolution_claim_fence)
   ||uuid_send(p_reconciliation_operation_id)||int4send(p_reconciliation_operation_attempt)
   ||int4send(octet_length(convert_to(p_reconciliation_operation_lease_owner,'UTF8')))
   ||convert_to(p_reconciliation_operation_lease_owner,'UTF8')
   ||uuid_send(p_reconciliation_owner)||decode(v_token_digest,'hex')
   ||int4send(octet_length(convert_to(p_resolution_kind,'UTF8')))||convert_to(p_resolution_kind,'UTF8')
   ||int4send(octet_length(convert_to(p_decision,'UTF8')))||convert_to(p_decision,'UTF8')
   ||public.digest(convert_to(v_resolution.evidence::text,'UTF8'),'sha256'),'sha256'),'hex');
 end if;

 if v_publication.recovery_terminal_at is not null then
  if v_resolution.reconciliation_owner=p_reconciliation_owner
   and v_resolution.reconciliation_token_digest=v_token_digest
   and p_decision_digest=v_expected_decision_digest
   and v_publication.recovery_terminal_claim_fence=p_resolution_claim_fence
   and v_publication.recovery_terminal_operation_id=p_reconciliation_operation_id
   and v_publication.recovery_terminal_operation_attempt=p_reconciliation_operation_attempt
   and v_publication.recovery_terminal_operation_lease_owner=p_reconciliation_operation_lease_owner
   and v_publication.recovery_terminal_kind=p_resolution_kind
   and v_publication.recovery_terminal_decision_digest=p_decision_digest then
   return query select 'replay',v_publication.recovery_terminal_response; return;
  end if;
  return query select 'conflict',null::jsonb; return;
 end if;
 if v_protocol_mode is distinct from 'generation_v1' then
  return query select 'protocol_inactive',null::jsonb; return;
 end if;
 if v_resolution.publication_id is null
  or v_resolution.resolution_kind is distinct from p_resolution_kind
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
      is distinct from v_publication.prior_loaded_identity)) then
  return query select 'observation_mismatch',null::jsonb; return;
 end if;
 if v_reconciliation.id is null
  or v_reconciliation.workshop_id is distinct from v_publication.target_workshop_id
  or v_reconciliation.kind is distinct from 'tenant.reconcile'
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
  or v_reconciliation.payload->>'route_set_terminal_decision_digest' is distinct from p_decision_digest then
  return query select 'reconciliation_lease_lost',null::jsonb; return;
 end if;
 if v_publication.phase is distinct from 'quarantined'
  or v_publication.publication_kind is distinct from 'projection'
  or v_publication.reconciliation_operation_id is not null
  or v_publication.reconciliation_owner is not null or v_publication.reconciliation_token is not null
  or v_upstream.state is distinct from 'in_flight'
  or v_upstream.attempt is distinct from v_publication.control_operation_attempt
  or v_upstream.leased_by is distinct from v_publication.control_operation_lease_owner
  or v_upstream.workshop_id is distinct from v_publication.target_workshop_id
  or not coalesce((v_upstream.kind='tenant.provision' and v_upstream.queue='tenant-provisioning')
   or (v_upstream.kind in ('tenant.reconcile','module.enable','module.restrict','webshop-domain.reconcile')
    and v_upstream.queue='tenant-reconciliation')
   or (v_upstream.kind='tenant.lifecycle' and v_upstream.queue='tenant-lifecycle'),false)
  or v_target.workshop_id is distinct from v_publication.target_workshop_id
  or v_global.state is distinct from 'quarantined'
  or v_global.authority_kind is distinct from 'route-set-publication'
  or v_global.route_set_publication_id is distinct from p_publication_id
  or v_global.lease_owner is distinct from v_publication.original_instance_owner
  or v_global.lease_token is not null or v_global.lease_expires_at is not null
  or v_global.fence_token is distinct from v_publication.original_global_fence_token
  or v_global.safe_error is distinct from 'runtime_outcome_unknown'
  or v_route.state is distinct from 'quarantined'
  or v_route.authority_kind is distinct from 'route-set-publication'
  or v_route.route_set_publication_id is distinct from p_publication_id
  or v_route.lease_owner is distinct from v_publication.original_instance_owner
  or v_route.lease_token is not null or v_route.lease_expires_at is not null
  or v_route.fence_token is distinct from v_target.target_route_fence_token
  or v_route.generation is distinct from v_target.target_generation
  or v_route.projection_digest is distinct from v_target.target_projection_digest
  or v_route.safe_error is distinct from 'route_set_publication_outcome_unknown'
  or v_driver.state is distinct from 'in_progress'
  or v_driver.safe_error is distinct from 'runtime_outcome_unknown'
  or v_driver.execution_token is not null or v_driver.lease_expires_at is not null
  or v_driver.action is distinct from 'route-project'
  or v_driver.workshop_id is distinct from v_publication.target_workshop_id
  or v_driver.control_operation_id is distinct from v_publication.control_operation_id
  or v_driver.control_operation_attempt is distinct from v_publication.control_operation_attempt
  or v_driver.control_operation_lease_owner is distinct from v_publication.control_operation_lease_owner
  or v_driver.target_key is distinct from 'route/'||v_publication.target_workshop_id::text
  or v_driver.route_generation is distinct from v_target.target_generation
  or v_driver.route_projection_digest is distinct from v_target.target_projection_digest
  or v_driver.route_fence_token is distinct from v_target.target_route_fence_token then
  return query select 'authority_inconsistent',null::jsonb; return;
 end if;

 -- Reprove the complete immutable fleet snapshot before releasing either
 -- quarantine.  The target desired head must still be the frozen generation,
 -- every applied head must still be the exact baseline captured at admission,
 -- and every staged record must still be an exact rendering of its snapshot
 -- member. Candidate terminalization may subsequently advance only the target.
 select count(*) into v_snapshot_count
 from control.workshop_route_set_publication_snapshot snapshot
 where snapshot.publication_id=p_publication_id;
 select count(*) into v_drift_count
 from control.workshop_route_set_publication_snapshot snapshot
 left join control.workshop_route_projection_state state on state.workshop_id=snapshot.workshop_id
 where snapshot.publication_id=p_publication_id and (
  state.workshop_id is null
  or (snapshot.is_target and (state.desired_generation is distinct from snapshot.generation
   or state.desired_digest is distinct from snapshot.projection_digest
   or state.desired_disposition is distinct from snapshot.disposition))
  or state.applied_generation is distinct from snapshot.baseline_applied_generation
  or state.applied_digest is distinct from snapshot.baseline_applied_digest
  or state.applied_disposition is distinct from snapshot.baseline_applied_disposition
  or state.applied_rendered_digest is distinct from snapshot.baseline_applied_rendered_digest
  or state.applied_driver_operation_id is distinct from snapshot.baseline_applied_driver_operation_id
  or state.applied_effect_run_id is distinct from snapshot.baseline_applied_effect_run_id
  or state.applied_fence_token is distinct from snapshot.baseline_applied_fence_token);
 select count(*) into v_record_drift_count
 from control.workshop_route_set_publication_records record
 left join control.workshop_route_set_publication_snapshot snapshot
  on snapshot.publication_id=record.publication_id and snapshot.workshop_id=record.workshop_id
 where record.publication_id=p_publication_id and (
  snapshot.workshop_id is null
  or record.generation is distinct from snapshot.generation
  or record.projection_digest is distinct from snapshot.projection_digest
  or record.disposition is distinct from snapshot.disposition
  or record.applied_rendered_digest is distinct from snapshot.baseline_applied_rendered_digest);
 if v_snapshot_count<>v_publication.snapshot_count or v_drift_count<>0
  or v_record_drift_count<>0
  or not exists(select 1 from control.workshop_route_set_publication_snapshot snapshot
   where snapshot.publication_id=p_publication_id and snapshot.workshop_id=v_target.workshop_id
    and snapshot.is_target and snapshot.generation=v_target.target_generation
    and snapshot.projection_digest=v_target.target_projection_digest
    and snapshot.disposition=v_target.target_disposition)
  or v_state.workshop_id is null then
 return query select 'authority_inconsistent',null::jsonb; return;
 end if;

 select count(*) into v_count from control.workshop_route_set_publication_records
 where publication_id=p_publication_id;
 if v_publication.sealed_count is not null and (
  v_count<>v_publication.sealed_count
  or control.route_set_publication_digest(p_publication_id) is distinct from v_publication.route_set_digest) then
  return query select 'authority_inconsistent',null::jsonb; return;
 end if;

 if p_resolution_kind='inconclusive' then
  return query select 'blocked',jsonb_build_object('outcome','quarantined',
   'publication_id',p_publication_id,'resolution_claim_fence',p_resolution_claim_fence,
   'resolution_kind','inconclusive','decision','keep_quarantined'); return;
 end if;

 if p_resolution_kind='candidate' then
  select count(*),count(*) filter(where disposition='present') into v_count,v_present
   from control.workshop_route_set_publication_records where publication_id=p_publication_id;
  select control.route_set_publication_digest(p_publication_id) into v_digest;
  v_expected_identity:=jsonb_build_object('protocol_version',1,'publication_id',p_publication_id,
   'publication_kind','projection','global_fence_token',v_publication.original_global_fence_token,
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
  v_driver_response:=jsonb_build_object('outcome','applied','workshop_id',v_target.workshop_id,
   'route_evidence',jsonb_build_object('driver_operation_id',v_driver.id,
    'workshop_id',v_target.workshop_id,'route_generation',v_target.target_generation,
    'projection_digest',v_target.target_projection_digest,'disposition',v_target.target_disposition,
    'rendered_digest',v_record.rendered_digest,'route_fence_token',v_target.target_route_fence_token),
   'route_set_evidence',jsonb_build_object('protocol_version',v_publication.protocol_version,
    'publication_id',v_publication.publication_id,'publication_kind',v_publication.publication_kind,
    'selector',v_publication.selector,'route_set_digest',v_publication.route_set_digest,
    'snapshot_count',v_publication.snapshot_count,'present_count',v_publication.sealed_present_count,
    'global_fence_token',v_publication.original_global_fence_token,
    'directory_device',v_publication.candidate_directory_device,
    'directory_inode',v_publication.candidate_directory_inode));
  update control.workshop_route_projection_state set
   applied_generation=v_target.target_generation,applied_digest=v_target.target_projection_digest,
   applied_disposition=v_target.target_disposition,applied_rendered_digest=v_record.rendered_digest,
   applied_driver_operation_id=v_driver.id,applied_effect_run_id=null,
   applied_fence_token=v_target.target_route_fence_token,updated_at=now()
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
  if v_changed<>1 then raise exception 'route-set recovery applied-head CAS drifted' using errcode='40001'; end if;
  update control.deployment_driver_operations set state='succeeded',response=v_driver_response,
   safe_error=null,updated_at=now() where id=v_driver.id and state='in_progress'
   and safe_error='runtime_outcome_unknown' and execution_token is null and lease_expires_at is null;
 else
  update control.deployment_driver_operations set state='failed',response=null,
   safe_error='route_set_publication_not_applied',updated_at=now()
  where id=v_driver.id and state='in_progress' and safe_error='runtime_outcome_unknown'
   and execution_token is null and lease_expires_at is null;
 end if;
 get diagnostics v_changed=row_count;
 if v_changed<>1 then raise exception 'route-set recovery driver terminalization drifted' using errcode='40001'; end if;

 update control.workshop_route_application_leases set state='idle',initialization_required=false,
  authority_kind=null,driver_operation_id=null,effect_run_id=null,release_publication_id=null,
  route_set_publication_id=null,generation=null,projection_digest=null,lease_owner=null,
  heartbeat_at=null,quarantined_at=null,safe_error=null,updated_at=now()
 where workshop_id=v_target.workshop_id and state='quarantined'
  and authority_kind='route-set-publication' and route_set_publication_id=p_publication_id
  and fence_token=v_target.target_route_fence_token;
 get diagnostics v_changed=row_count;
 if v_changed<>1 then raise exception 'route-set recovery target release drifted' using errcode='40001'; end if;
 update control.deployment_driver_resource_leases set state='idle',authority_kind=null,
  driver_operation_id=null,effect_run_id=null,route_set_publication_id=null,lease_owner=null,
  heartbeat_at=null,quarantined_at=null,safe_error=null,updated_at=now()
 where resource_key='runtime/shared-odoo' and state='quarantined'
  and authority_kind='route-set-publication' and route_set_publication_id=p_publication_id
  and fence_token=v_publication.original_global_fence_token;
 get diagnostics v_changed=row_count;
 if v_changed<>1 then raise exception 'route-set recovery global release drifted' using errcode='40001'; end if;

 v_response:=jsonb_build_object('outcome',case when p_resolution_kind='candidate'
   then 'applied_recovered' else 'not_applied' end,'publication_id',p_publication_id,
   'driver_operation_id',v_driver.id,'target_workshop_id',v_target.workshop_id,
   'resolution_claim_fence',p_resolution_claim_fence,'resolution_kind',p_resolution_kind,
   'reconciliation_operation_id',p_reconciliation_operation_id,
   'reconciliation_operation_attempt',p_reconciliation_operation_attempt,
   'reconciliation_operation_lease_owner',p_reconciliation_operation_lease_owner,
   'decision_digest',p_decision_digest,'driver_response',v_driver_response);
 update control.workshop_route_set_publications set
  recovery_terminal_kind=p_resolution_kind,recovery_terminal_claim_fence=p_resolution_claim_fence,
  recovery_terminal_operation_id=p_reconciliation_operation_id,
  recovery_terminal_operation_attempt=p_reconciliation_operation_attempt,
  recovery_terminal_operation_lease_owner=p_reconciliation_operation_lease_owner,
  recovery_terminal_decision_digest=p_decision_digest,recovery_terminal_response=v_response,
  recovery_terminal_at=now(),updated_at=now()
 where publication_id=p_publication_id and phase='quarantined' and recovery_terminal_at is null;
 get diagnostics v_changed=row_count;
 if v_changed<>1 then raise exception 'route-set recovery terminal evidence drifted' using errcode='40001'; end if;
 return query select 'completed',v_response;
end $function$;

create or replace function control.read_route_set_publication_result(
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
 if v_publication.recovery_terminal_at is not null then
  if v_publication.recovery_terminal_kind='candidate' and v_driver.state='succeeded'
   and v_driver.response is not null
   and v_publication.recovery_terminal_response->'driver_response' is not distinct from v_driver.response then
   return query select 'completed',v_publication.publication_id,v_driver.id,v_driver.response; return;
  elsif v_publication.recovery_terminal_kind in ('prior','unstarted') and v_driver.state='failed'
   and v_driver.safe_error='route_set_publication_not_applied' and v_driver.response is null then
   return query select 'not_applied',v_publication.publication_id,v_driver.id,
    jsonb_build_object('outcome','not_applied','publication_id',v_publication.publication_id,
     'driver_operation_id',v_driver.id,'resolution_kind',v_publication.recovery_terminal_kind,
     'safe_error',v_driver.safe_error); return;
  end if;
  return query select 'conflict',null::uuid,null::uuid,null::jsonb; return;
 end if;
 return query select 'pending',v_publication.publication_id,v_driver.id,null::jsonb;
end $function$;

revoke all on function control.validate_route_set_recovery_terminal_evidence() from public;
revoke all on function control.finish_route_set_publication_recovery(uuid,bigint,uuid,integer,text,uuid,uuid,text,text,text) from public;
do $migration$ declare v_role text; begin
 foreach v_role in array array['control_api','control_tenant_api','control_membership_worker','control_provisioning_worker',
  'control_invoice_worker','control_inventory_worker','control_email_worker','control_reconciliation_worker',
  'control_lifecycle_worker','control_backup_scheduler','control_driver_ledger','control_release_worker','control_privacy_worker'] loop
  if exists(select 1 from pg_roles where rolname=v_role) then
   execute format('revoke all on function control.validate_route_set_recovery_terminal_evidence() from %I',v_role);
   execute format('revoke all on function control.finish_route_set_publication_recovery(uuid,bigint,uuid,integer,text,uuid,uuid,text,text,text) from %I',v_role);
  end if;
 end loop;
 if exists(select 1 from pg_roles where rolname='control_driver_ledger') then
  grant execute on function control.finish_route_set_publication_recovery(uuid,bigint,uuid,integer,text,uuid,uuid,text,text,text) to control_driver_ledger;
 end if;
end $migration$;

comment on function control.finish_route_set_publication_recovery(uuid,bigint,uuid,integer,text,uuid,uuid,text,text,text) is
'Dormant reviewed terminalization of one immutable route-set recovery observation; inconclusive evidence remains quarantined and nonterminal.';
comment on function control.read_route_set_publication_result(uuid,uuid,text,text) is
'Exact route-set result replay, including reviewed recovered candidate and explicit prior/unstarted non-applied terminal outcomes.';
