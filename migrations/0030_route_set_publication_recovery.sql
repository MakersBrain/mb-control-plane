-- Dormant interrupted-publication discovery, claim fencing, and immutable
-- observation evidence. PostgreSQL claim fences cannot fence a stale
-- filesystem writer. Consequently, a claim for an operation that ever
-- crossed publication_started is observe-only: it grants no selector write,
-- candidate cleanup, or prior restoration authority. Pre-start claims are
-- write_cleanup-capable only because publication_started_at is durably NULL.
--
-- This migration intentionally performs no activation, target-head mutation,
-- ordinary abort, prior restoration, recovery-kind finalization, or release
-- of quarantined global/route authority. Exact evidence remains fail-closed
-- for a later reviewed terminal-resolution protocol.

alter table control.workshop_route_set_publications
 add column reconciliation_claim_fence bigint not null default 0,
 add column reconciliation_claim_mode text,
 add column recovery_eligible_at timestamptz,
 add column recovery_write_eligible boolean not null default false;

alter table control.workshop_route_set_publications
 drop constraint workshop_route_set_publications_reconciliation_check,
 add constraint workshop_route_set_publications_reconciliation_check check(
  (reconciliation_operation_id is null and reconciliation_operation_attempt is null
   and reconciliation_operation_lease_owner is null and reconciliation_owner is null
   and reconciliation_token is null and reconciliation_expires_at is null
   and reconciliation_claim_mode is null)
  or (phase='quarantined' and reconciliation_operation_id is not null
   and reconciliation_operation_attempt>0 and btrim(reconciliation_operation_lease_owner)<>''
   and reconciliation_owner is not null and reconciliation_token is not null
   and reconciliation_expires_at is not null
   and reconciliation_claim_mode in ('write_cleanup','observe_only'))),
 add constraint workshop_route_set_publications_reconciliation_fence_check
  check(reconciliation_claim_fence>=0),
 add constraint workshop_route_set_publications_recovery_eligible_check
  check((recovery_eligible_at is null or phase='quarantined')
   and (not recovery_write_eligible
    or (recovery_eligible_at is not null and phase='quarantined')));

create function control.validate_route_set_recovery_eligibility()
returns trigger language plpgsql set search_path=pg_catalog,control as $function$
begin
 if old.recovery_eligible_at is not null
  and new.recovery_eligible_at is distinct from old.recovery_eligible_at then
  raise exception 'route-set recovery eligibility evidence is immutable' using errcode='55000';
 end if;
 if new.recovery_write_eligible is distinct from old.recovery_write_eligible
  and not (not old.recovery_write_eligible and new.recovery_write_eligible
   and old.phase in ('staging','sealed') and new.phase='quarantined'
   and old.recovery_eligible_at is null and new.recovery_eligible_at is not null) then
  raise exception 'route-set recovery write capability is immutable' using errcode='55000';
 end if;
 return new;
end $function$;

create trigger workshop_route_set_publications_recovery_eligibility_immutable
before update on control.workshop_route_set_publications for each row
execute function control.validate_route_set_recovery_eligibility();

create table control.workshop_route_set_publication_resolutions (
 publication_id uuid not null,
 reconciliation_claim_fence bigint not null,
 reconciliation_operation_id uuid not null,
 reconciliation_operation_attempt integer not null,
 reconciliation_operation_lease_owner text not null,
 reconciliation_owner uuid not null,
 reconciliation_token_digest text not null,
 claim_mode text not null,
 resolution_kind text not null,
 evidence jsonb not null,
 recorded_at timestamptz not null default now(),
 primary key(publication_id,reconciliation_claim_fence),
 constraint workshop_route_set_publication_resolutions_publication_fkey
  foreign key(publication_id) references control.workshop_route_set_publications(publication_id) on delete restrict,
 constraint workshop_route_set_publication_resolutions_operation_fkey
  foreign key(reconciliation_operation_id) references control.operations(id) on delete restrict,
 constraint workshop_route_set_publication_resolutions_shape_check check(
  reconciliation_claim_fence>0 and reconciliation_token_digest ~ '^[0-9a-f]{64}$'
  and reconciliation_operation_attempt>0 and btrim(reconciliation_operation_lease_owner)<>''
  and claim_mode in ('write_cleanup','observe_only')
  and resolution_kind in ('candidate','prior','unstarted','inconclusive')
  and jsonb_typeof(evidence)='object' and pg_column_size(evidence)<=8192
  and evidence->>'reconciliation_operation_id'=reconciliation_operation_id::text
  and evidence->>'reconciliation_operation_attempt'=reconciliation_operation_attempt::text
  and evidence->>'reconciliation_operation_lease_owner'=reconciliation_operation_lease_owner)
);

create function control.reject_route_set_resolution_mutation()
returns trigger language plpgsql set search_path=pg_catalog,control as $function$
begin
 raise exception 'route-set resolution evidence is immutable' using errcode='55000';
end $function$;

create trigger workshop_route_set_publication_resolutions_immutable
before update or delete on control.workshop_route_set_publication_resolutions
for each row execute function control.reject_route_set_resolution_mutation();

create function control.discover_interrupted_route_set_publications(
 p_after_publication_id uuid,p_limit integer
) returns table(publication_id uuid,target_workshop_id uuid,publication_kind text,
 interrupted_phase text,claim_mode text,claim_fence bigint,claim_available boolean,
 selector text,route_set_digest text,updated_at timestamptz)
language plpgsql stable security definer set search_path=pg_catalog,control as $function$
begin
 if p_limit is null or p_limit not between 1 and 100 then return; end if;
 return query select publication.publication_id,publication.target_workshop_id,
  publication.publication_kind,publication.interrupted_phase,
  case when publication.recovery_eligible_at is not null
   and publication.recovery_write_eligible
   and publication.publication_started_at is null
   and publication.interrupted_phase in ('staging','sealed')
   then 'write_cleanup' else 'observe_only' end,
  publication.reconciliation_claim_fence,
  publication.reconciliation_owner is null or publication.reconciliation_expires_at<=now(),
  publication.selector,publication.route_set_digest,publication.updated_at
 from control.workshop_route_set_publications publication
 where publication.phase='quarantined' and publication.publication_kind='projection'
  and (p_after_publication_id is null or publication.publication_id>p_after_publication_id)
 order by publication.publication_id limit p_limit;
end $function$;

create function control.claim_interrupted_route_set_publication(
 p_publication_id uuid,p_reconciliation_operation_id uuid,
 p_reconciliation_operation_attempt integer,p_reconciliation_operation_lease_owner text,
 p_reconciliation_owner uuid,p_reconciliation_token uuid,p_ttl_seconds integer
) returns table(outcome text,claim_fence bigint,claim_mode text)
language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_lookup control.workshop_route_set_publications%rowtype;
 v_upstream control.operations%rowtype; v_reconciliation control.operations%rowtype;
 v_global control.deployment_driver_resource_leases%rowtype;
 v_route control.workshop_route_application_leases%rowtype;
 v_driver control.deployment_driver_operations%rowtype;
 v_publication control.workshop_route_set_publications%rowtype;
 v_target control.workshop_route_set_publication_targets%rowtype;
 v_expired boolean;
 v_mode text; v_fence bigint; v_changed integer;
begin
 if p_publication_id is null or p_reconciliation_operation_id is null
  or p_reconciliation_operation_attempt is null or p_reconciliation_operation_attempt<=0
  or p_reconciliation_operation_lease_owner is null
  or btrim(p_reconciliation_operation_lease_owner)=''
  or p_reconciliation_owner is null or p_reconciliation_token is null
  or p_ttl_seconds is null or p_ttl_seconds not between 60 and 1200 then
  return query select 'invalid',null::bigint,null::text; return;
 end if;
 select * into v_lookup from control.workshop_route_set_publications
  where publication_id=p_publication_id;
 if not found then return query select 'absent',null::bigint,null::text; return; end if;

 -- Canonical order: original upstream, reconciliation upstream, protocol,
 -- global lease, target route lease, driver, publication, target record.
 perform 1 from control.operations
  where id in (v_lookup.control_operation_id,p_reconciliation_operation_id) order by id for update;
 select * into v_upstream from control.operations where id=v_lookup.control_operation_id;
 select * into v_reconciliation from control.operations where id=p_reconciliation_operation_id;
 perform 1 from control.route_set_publication_protocol_state
  where singleton and mode='generation_v1' for update;
 if not found then return query select 'protocol_inactive',null::bigint,null::text; return; end if;
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

 if v_publication.phase='completed' then
  return query select 'terminal',v_publication.reconciliation_claim_fence,null::text; return;
 end if;
 if v_publication.publication_kind<>'projection'
  or p_reconciliation_operation_id=v_publication.control_operation_id then
  return query select 'invalid',null::bigint,null::text; return;
 end if;
 if v_reconciliation.id is null or v_reconciliation.workshop_id is distinct from v_publication.target_workshop_id
  or v_reconciliation.kind<>'tenant.reconcile' or v_reconciliation.queue<>'tenant-reconciliation'
  or v_reconciliation.state<>'in_flight'
  or v_reconciliation.attempt<>p_reconciliation_operation_attempt
  or v_reconciliation.leased_by is distinct from p_reconciliation_operation_lease_owner
  or v_reconciliation.lease_expires_at<=now() then
  return query select 'reconciliation_lease_lost',null::bigint,null::text; return;
 end if;
 if v_reconciliation.payload->>'route_set_publication_id' is distinct from p_publication_id::text
  or v_reconciliation.payload->>'protocol_version' is distinct from '1' then
  return query select 'reconciliation_lease_lost',null::bigint,null::text; return;
 end if;
 if v_publication.reconciliation_owner is not null
  and v_publication.reconciliation_expires_at>now() then
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
  if v_publication.phase not in ('staging','sealed','publication_started','observed') then
   return query select 'wrong_phase',null::bigint,null::text; return;
  end if;
  if v_upstream.state is distinct from 'in_flight'
   or v_upstream.attempt is distinct from v_publication.control_operation_attempt
   or v_upstream.leased_by is distinct from v_publication.control_operation_lease_owner
   or v_upstream.workshop_id is distinct from v_publication.target_workshop_id
   or not coalesce((v_upstream.kind='tenant.provision' and v_upstream.queue='tenant-provisioning')
    or (v_upstream.kind in ('tenant.reconcile','module.enable','module.restrict','webshop-domain.reconcile')
     and v_upstream.queue='tenant-reconciliation')
    or (v_upstream.kind='tenant.lifecycle' and v_upstream.queue='tenant-lifecycle'),false)
   or v_target.workshop_id is distinct from v_publication.target_workshop_id
   or v_publication.original_instance_owner is distinct from v_global.lease_owner
   or v_publication.original_execution_token is distinct from v_driver.execution_token
   or v_publication.original_global_lease_token is distinct from v_global.lease_token
   or v_publication.original_route_lease_token is distinct from v_route.lease_token
   or v_publication.original_global_fence_token is distinct from v_global.fence_token
   or v_target.target_route_fence_token is distinct from v_route.fence_token
   or v_global.state is distinct from 'held'
   or v_global.authority_kind is distinct from 'route-set-publication'
   or v_global.route_set_publication_id is distinct from p_publication_id
   or v_global.lease_owner is distinct from v_publication.original_instance_owner
   or v_global.fence_token is distinct from v_publication.original_global_fence_token
   or v_global.safe_error is not null
   or v_route.state is distinct from 'held'
   or v_route.authority_kind is distinct from 'route-set-publication'
   or v_route.route_set_publication_id is distinct from p_publication_id
   or v_route.lease_owner is distinct from v_publication.original_instance_owner
   or v_route.generation is distinct from v_target.target_generation
   or v_route.projection_digest is distinct from v_target.target_projection_digest
   or v_route.fence_token is distinct from v_target.target_route_fence_token
   or v_route.safe_error is not null
   or v_driver.state is distinct from 'in_progress' or v_driver.safe_error is not null
   or v_driver.action is distinct from 'route-project'
   or v_driver.workshop_id is distinct from v_publication.target_workshop_id
   or v_driver.control_operation_id is distinct from v_publication.control_operation_id
   or v_driver.control_operation_attempt is distinct from v_publication.control_operation_attempt
   or v_driver.control_operation_lease_owner is distinct from v_publication.control_operation_lease_owner
   or v_driver.target_key is distinct from 'route/'||v_publication.target_workshop_id::text
   or v_driver.route_generation is distinct from v_target.target_generation
   or v_driver.route_projection_digest is distinct from v_target.target_projection_digest
   or v_driver.route_fence_token is distinct from v_target.target_route_fence_token then
   return query select 'authority_inconsistent',null::bigint,null::text; return;
  end if;
  v_expired:=coalesce(v_upstream.lease_expires_at<=now(),false)
   and coalesce(v_driver.lease_expires_at<=now(),false)
   and coalesce(v_global.lease_expires_at<=now(),false)
   and coalesce(v_route.lease_expires_at<=now(),false);
  if not v_expired then return query select 'not_expired',null::bigint,null::text; return; end if;
  update control.deployment_driver_resource_leases set state='quarantined',lease_token=null,
   lease_expires_at=null,quarantined_at=now(),safe_error='runtime_outcome_unknown',updated_at=now()
   where resource_key='runtime/shared-odoo' and state='held'
    and route_set_publication_id=p_publication_id;
  get diagnostics v_changed=row_count;
  if v_changed<>1 then raise exception 'route-set recovery global quarantine drifted' using errcode='40001'; end if;
  update control.workshop_route_application_leases set state='quarantined',lease_token=null,
   lease_expires_at=null,quarantined_at=now(),safe_error='route_set_publication_outcome_unknown',updated_at=now()
   where workshop_id=v_target.workshop_id and state='held'
    and route_set_publication_id=p_publication_id;
  get diagnostics v_changed=row_count;
  if v_changed<>1 then raise exception 'route-set recovery target quarantine drifted' using errcode='40001'; end if;
  update control.deployment_driver_operations set safe_error='runtime_outcome_unknown',
   execution_token=null,lease_expires_at=null,updated_at=now()
   where id=v_publication.driver_operation_id and state='in_progress' and safe_error is null;
  get diagnostics v_changed=row_count;
  if v_changed<>1 then raise exception 'route-set recovery driver quarantine drifted' using errcode='40001'; end if;
  update control.workshop_route_set_publications set interrupted_phase=phase,phase='quarantined',
   quarantined_at=now(),safe_error='route_set_publication_outcome_unknown',
   recovery_eligible_at=now(),
   recovery_write_eligible=(publication_started_at is null and phase in ('staging','sealed')),
   updated_at=now()
   where publication_id=p_publication_id;
  select * into strict v_publication from control.workshop_route_set_publications
   where publication_id=p_publication_id;
 else
  if v_upstream.state is distinct from 'in_flight'
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
   return query select 'authority_inconsistent',null::bigint,null::text; return;
  end if;
  -- A quarantine created by 0028 predates durable all-expired eligibility
  -- evidence. Its cleared exact fences are safe to observe but can never be
  -- upgraded into filesystem write/restore authority.
 end if;

 v_mode:=case when v_publication.recovery_eligible_at is not null
   and v_publication.recovery_write_eligible
   and v_publication.publication_started_at is null
   and v_publication.interrupted_phase in ('staging','sealed')
  then 'write_cleanup' else 'observe_only' end;
 v_fence:=v_publication.reconciliation_claim_fence+1;
 update control.workshop_route_set_publications set
  reconciliation_operation_id=p_reconciliation_operation_id,
  reconciliation_operation_attempt=p_reconciliation_operation_attempt,
  reconciliation_operation_lease_owner=p_reconciliation_operation_lease_owner,
  reconciliation_owner=p_reconciliation_owner,reconciliation_token=p_reconciliation_token,
  reconciliation_expires_at=least(v_reconciliation.lease_expires_at,
   now()+make_interval(secs=>p_ttl_seconds)),
  reconciliation_claim_fence=v_fence,reconciliation_claim_mode=v_mode,
  recovery_eligible_at=coalesce(recovery_eligible_at,now()),updated_at=now()
 where publication_id=p_publication_id;
 return query select 'acquired',v_fence,v_mode;
end $function$;

create function control.lock_interrupted_route_set_publication_claim(
 p_publication_id uuid,p_reconciliation_owner uuid,p_reconciliation_token uuid,p_claim_fence bigint
) returns boolean language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_lookup control.workshop_route_set_publications%rowtype;
 v_publication control.workshop_route_set_publications%rowtype;
 v_target control.workshop_route_set_publication_targets%rowtype;
 v_reconciliation control.operations%rowtype;
begin
 select * into v_lookup from control.workshop_route_set_publications
  where publication_id=p_publication_id;
 if not found or v_lookup.reconciliation_operation_id is null then return false; end if;
 perform 1 from control.operations where id in (
  v_lookup.control_operation_id,v_lookup.reconciliation_operation_id) order by id for update;
 perform 1 from control.route_set_publication_protocol_state
  where singleton and mode='generation_v1' for update;
 if not found then return false; end if;
 perform 1 from control.deployment_driver_resource_leases
  where resource_key='runtime/shared-odoo' for update;
 perform 1 from control.workshop_route_application_leases
  where workshop_id=v_lookup.target_workshop_id for update;
 perform 1 from control.deployment_driver_operations where id=v_lookup.driver_operation_id for update;
 select * into v_publication from control.workshop_route_set_publications
  where publication_id=p_publication_id for update;
 select * into strict v_target from control.workshop_route_set_publication_targets
  where publication_id=p_publication_id;
 select * into v_reconciliation from control.operations
  where id=v_publication.reconciliation_operation_id;
 return coalesce(v_publication.phase='quarantined' and v_publication.publication_kind='projection'
  and v_publication.reconciliation_owner=p_reconciliation_owner
  and v_publication.reconciliation_token=p_reconciliation_token
  and v_publication.reconciliation_claim_fence=p_claim_fence
  and v_publication.reconciliation_expires_at>now()
  and v_reconciliation.state='in_flight'
  and v_reconciliation.workshop_id=v_publication.target_workshop_id
  and v_reconciliation.kind='tenant.reconcile'
  and v_reconciliation.queue='tenant-reconciliation'
  and v_reconciliation.attempt=v_publication.reconciliation_operation_attempt
  and v_reconciliation.leased_by=v_publication.reconciliation_operation_lease_owner
  and v_reconciliation.lease_expires_at>now()
  and v_reconciliation.payload->>'route_set_publication_id'=p_publication_id::text
  and v_reconciliation.payload->>'protocol_version'='1'
  and exists(select 1 from control.operations upstream
   where upstream.id=v_publication.control_operation_id
    and upstream.state='in_flight'
    and upstream.attempt=v_publication.control_operation_attempt
    and upstream.leased_by=v_publication.control_operation_lease_owner
    and upstream.workshop_id=v_publication.target_workshop_id
    and ((upstream.kind='tenant.provision' and upstream.queue='tenant-provisioning')
     or (upstream.kind in ('tenant.reconcile','module.enable','module.restrict','webshop-domain.reconcile')
      and upstream.queue='tenant-reconciliation')
     or (upstream.kind='tenant.lifecycle' and upstream.queue='tenant-lifecycle')))
  and exists(select 1 from control.deployment_driver_resource_leases lease
   where lease.resource_key='runtime/shared-odoo' and lease.state='quarantined'
    and lease.authority_kind='route-set-publication'
    and lease.route_set_publication_id=p_publication_id
    and lease.lease_owner=v_publication.original_instance_owner
    and lease.lease_token is null and lease.lease_expires_at is null
    and lease.fence_token=v_publication.original_global_fence_token
    and lease.safe_error='runtime_outcome_unknown')
  and exists(select 1 from control.workshop_route_application_leases lease
   where v_target.workshop_id=v_publication.target_workshop_id
    and lease.workshop_id=v_target.workshop_id and lease.state='quarantined'
    and lease.authority_kind='route-set-publication'
    and lease.route_set_publication_id=p_publication_id
    and lease.lease_owner=v_publication.original_instance_owner
    and lease.lease_token is null and lease.lease_expires_at is null
    and lease.fence_token=v_target.target_route_fence_token
    and lease.generation=v_target.target_generation
    and lease.projection_digest=v_target.target_projection_digest
    and lease.safe_error='route_set_publication_outcome_unknown')
  and exists(select 1 from control.deployment_driver_operations driver
   where driver.id=v_publication.driver_operation_id and driver.state='in_progress'
    and driver.safe_error='runtime_outcome_unknown' and driver.execution_token is null
    and driver.lease_expires_at is null and driver.action='route-project'
    and driver.workshop_id=v_publication.target_workshop_id
    and driver.control_operation_id=v_publication.control_operation_id
    and driver.control_operation_attempt=v_publication.control_operation_attempt
    and driver.control_operation_lease_owner=v_publication.control_operation_lease_owner
    and driver.target_key='route/'||v_publication.target_workshop_id::text
    and driver.route_generation=v_target.target_generation
    and driver.route_projection_digest=v_target.target_projection_digest
    and driver.route_fence_token=v_target.target_route_fence_token),false);
end $function$;

create function control.renew_interrupted_route_set_publication_claim(
 p_publication_id uuid,p_reconciliation_owner uuid,p_reconciliation_token uuid,
 p_claim_fence bigint,p_ttl_seconds integer
) returns text language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_changed integer; v_operation_expires timestamptz;
begin
 if p_publication_id is null or p_reconciliation_owner is null or p_reconciliation_token is null
  or p_claim_fence is null or p_claim_fence<=0 or p_ttl_seconds is null
  or p_ttl_seconds not between 60 and 1200 then return 'invalid'; end if;
 if not control.lock_interrupted_route_set_publication_claim(p_publication_id,
  p_reconciliation_owner,p_reconciliation_token,p_claim_fence) then return 'claim_lost'; end if;
 select operation.lease_expires_at into strict v_operation_expires
 from control.workshop_route_set_publications publication
 join control.operations operation on operation.id=publication.reconciliation_operation_id
 where publication.publication_id=p_publication_id;
 update control.workshop_route_set_publications set
  reconciliation_expires_at=least(v_operation_expires,
   now()+make_interval(secs=>p_ttl_seconds)),updated_at=now()
 where publication_id=p_publication_id and phase='quarantined'
  and reconciliation_owner=p_reconciliation_owner and reconciliation_token=p_reconciliation_token
  and reconciliation_claim_fence=p_claim_fence and reconciliation_expires_at>now();
 get diagnostics v_changed=row_count;
 return case when v_changed=1 then 'renewed' else 'claim_lost' end;
end $function$;

create function control.read_interrupted_route_set_publication_state(
 p_publication_id uuid,p_reconciliation_owner uuid,p_reconciliation_token uuid,p_claim_fence bigint
) returns table(outcome text,state jsonb)
language plpgsql stable security definer set search_path=pg_catalog,control as $function$
declare v_publication control.workshop_route_set_publications%rowtype;
 v_target control.workshop_route_set_publication_targets%rowtype; v_record_count integer;
begin
  select * into v_publication from control.workshop_route_set_publications
  where publication_id=p_publication_id and phase='quarantined'
   and publication_kind='projection'
   and reconciliation_owner=p_reconciliation_owner and reconciliation_token=p_reconciliation_token
   and reconciliation_claim_fence=p_claim_fence and reconciliation_expires_at>now()
   and exists(select 1 from control.operations operation
    where operation.id=workshop_route_set_publications.reconciliation_operation_id
     and operation.state='in_flight'
     and operation.workshop_id=workshop_route_set_publications.target_workshop_id
     and operation.kind='tenant.reconcile' and operation.queue='tenant-reconciliation'
     and operation.attempt=workshop_route_set_publications.reconciliation_operation_attempt
     and operation.leased_by=workshop_route_set_publications.reconciliation_operation_lease_owner
     and operation.lease_expires_at>now()
     and operation.payload->>'route_set_publication_id'=p_publication_id::text
     and operation.payload->>'protocol_version'='1')
   and exists(select 1 from control.route_set_publication_protocol_state protocol
    where protocol.singleton and protocol.mode='generation_v1')
   and exists(select 1 from control.operations upstream
    where upstream.id=workshop_route_set_publications.control_operation_id
     and upstream.state='in_flight'
     and upstream.attempt=workshop_route_set_publications.control_operation_attempt
     and upstream.leased_by=workshop_route_set_publications.control_operation_lease_owner
     and upstream.workshop_id=workshop_route_set_publications.target_workshop_id
     and ((upstream.kind='tenant.provision' and upstream.queue='tenant-provisioning')
      or (upstream.kind in ('tenant.reconcile','module.enable','module.restrict','webshop-domain.reconcile')
       and upstream.queue='tenant-reconciliation')
      or (upstream.kind='tenant.lifecycle' and upstream.queue='tenant-lifecycle')))
   and exists(select 1 from control.deployment_driver_resource_leases lease
    where lease.resource_key='runtime/shared-odoo' and lease.state='quarantined'
     and lease.authority_kind='route-set-publication'
     and lease.route_set_publication_id=p_publication_id
     and lease.lease_owner=workshop_route_set_publications.original_instance_owner
     and lease.lease_token is null and lease.lease_expires_at is null
     and lease.fence_token=workshop_route_set_publications.original_global_fence_token
     and lease.safe_error='runtime_outcome_unknown')
   and exists(select 1 from control.workshop_route_set_publication_targets target
    join control.workshop_route_application_leases lease on lease.workshop_id=target.workshop_id
    where target.publication_id=p_publication_id
     and target.workshop_id=workshop_route_set_publications.target_workshop_id
     and lease.state='quarantined'
     and lease.authority_kind='route-set-publication'
     and lease.route_set_publication_id=p_publication_id
     and lease.lease_owner=workshop_route_set_publications.original_instance_owner
     and lease.lease_token is null and lease.lease_expires_at is null
     and lease.fence_token=target.target_route_fence_token
     and lease.generation=target.target_generation
     and lease.projection_digest=target.target_projection_digest
     and lease.safe_error='route_set_publication_outcome_unknown')
   and exists(select 1 from control.deployment_driver_operations driver
    where driver.id=workshop_route_set_publications.driver_operation_id
     and driver.state='in_progress' and driver.safe_error='runtime_outcome_unknown'
     and driver.execution_token is null and driver.lease_expires_at is null
     and driver.action='route-project'
     and driver.workshop_id=workshop_route_set_publications.target_workshop_id
     and driver.control_operation_id=workshop_route_set_publications.control_operation_id
     and driver.control_operation_attempt=workshop_route_set_publications.control_operation_attempt
     and driver.control_operation_lease_owner=workshop_route_set_publications.control_operation_lease_owner
     and driver.target_key='route/'||workshop_route_set_publications.target_workshop_id::text
     and exists(select 1 from control.workshop_route_set_publication_targets target
      where target.publication_id=p_publication_id
       and driver.route_generation=target.target_generation
       and driver.route_projection_digest=target.target_projection_digest
       and driver.route_fence_token=target.target_route_fence_token));
 if not found then return query select 'claim_lost',null::jsonb; return; end if;
 select * into strict v_target from control.workshop_route_set_publication_targets
  where publication_id=p_publication_id;
 select count(*) into v_record_count from control.workshop_route_set_publication_records
  where publication_id=p_publication_id;
 return query select 'claimed',jsonb_build_object(
  'protocol_version',v_publication.protocol_version,
  'publication_id',v_publication.publication_id,'publication_kind',v_publication.publication_kind,
  'interrupted_phase',v_publication.interrupted_phase,'claim_mode',v_publication.reconciliation_claim_mode,
  'claim_fence',v_publication.reconciliation_claim_fence,'target_workshop_id',v_target.workshop_id,
  'original_global_fence_token',v_publication.original_global_fence_token,
  'target_route_fence_token',v_target.target_route_fence_token,
  'target_generation',v_target.target_generation,
  'target_projection_digest',v_target.target_projection_digest,
  'target_disposition',v_target.target_disposition,
  'selector',v_publication.selector,'prior_selector',v_publication.prior_selector,
  'prior_directory_device',v_publication.prior_directory_device,
  'prior_directory_inode',v_publication.prior_directory_inode,
  'prior_loaded_identity',v_publication.prior_loaded_identity,
  'candidate_directory_device',v_publication.candidate_directory_device,
  'candidate_directory_inode',v_publication.candidate_directory_inode,
  'sealed_count',v_publication.sealed_count,
  'sealed_present_count',v_publication.sealed_present_count,
  'route_set_digest',v_publication.route_set_digest,'record_count',v_record_count,
  'publication_started_at',v_publication.publication_started_at,
  'observed_selector',v_publication.observed_selector,
  'observed_loaded_identity',v_publication.observed_loaded_identity);
end $function$;

create function control.resolve_interrupted_route_set_publication_observation(
 p_publication_id uuid,p_reconciliation_owner uuid,p_reconciliation_token uuid,p_claim_fence bigint,
 p_resolution_kind text,p_observed_selector text,p_observed_directory_device bigint,
 p_observed_directory_inode bigint,p_observed_loaded_identity jsonb
) returns table(outcome text,evidence jsonb)
language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_publication control.workshop_route_set_publications%rowtype;
 v_target control.workshop_route_set_publication_targets%rowtype;
 v_existing control.workshop_route_set_publication_resolutions%rowtype;
 v_expected_identity jsonb; v_evidence jsonb; v_count integer; v_token_digest text;
begin
 v_token_digest:=encode(public.digest(convert_to('mb-route-set-reconciliation-token-v1','UTF8')
  ||uuid_send(p_reconciliation_token),'sha256'),'hex');
 if p_resolution_kind not in ('candidate','prior','unstarted','inconclusive') then
  return query select 'invalid',null::jsonb; return; end if;
 select * into v_existing from control.workshop_route_set_publication_resolutions
  where publication_id=p_publication_id and reconciliation_claim_fence=p_claim_fence;
 if found then
  if v_existing.reconciliation_owner=p_reconciliation_owner
   and v_existing.reconciliation_token_digest=v_token_digest
   and v_existing.resolution_kind=p_resolution_kind
   and v_existing.evidence->>'observed_selector' is not distinct from p_observed_selector
   and (v_existing.evidence->>'observed_directory_device')::bigint
    is not distinct from p_observed_directory_device
   and (v_existing.evidence->>'observed_directory_inode')::bigint
    is not distinct from p_observed_directory_inode
   and nullif(v_existing.evidence->'observed_loaded_identity','null'::jsonb)
    is not distinct from p_observed_loaded_identity then
   return query select 'replay',v_existing.evidence; return;
  end if;
 return query select 'conflict',null::jsonb; return;
 end if;
 if not control.lock_interrupted_route_set_publication_claim(p_publication_id,
  p_reconciliation_owner,p_reconciliation_token,p_claim_fence) then
  select * into v_existing from control.workshop_route_set_publication_resolutions
   where publication_id=p_publication_id and reconciliation_claim_fence=p_claim_fence;
  if found and v_existing.reconciliation_owner=p_reconciliation_owner
   and v_existing.reconciliation_token_digest=v_token_digest
   and v_existing.resolution_kind=p_resolution_kind
   and v_existing.evidence->>'observed_selector' is not distinct from p_observed_selector
   and (v_existing.evidence->>'observed_directory_device')::bigint is not distinct from p_observed_directory_device
   and (v_existing.evidence->>'observed_directory_inode')::bigint is not distinct from p_observed_directory_inode
   and nullif(v_existing.evidence->'observed_loaded_identity','null'::jsonb) is not distinct from p_observed_loaded_identity then
   return query select 'replay',v_existing.evidence; return;
  end if;
  return query select 'claim_lost',null::jsonb; return;
 end if;
 select * into v_publication from control.workshop_route_set_publications
  where publication_id=p_publication_id and phase='quarantined'
   and reconciliation_owner=p_reconciliation_owner and reconciliation_token=p_reconciliation_token
   and reconciliation_claim_fence=p_claim_fence and reconciliation_expires_at>now() for update;
 if not found then return query select 'claim_lost',null::jsonb; return; end if;
 select * into strict v_target from control.workshop_route_set_publication_targets
  where publication_id=p_publication_id;
 select count(*) into v_count from control.workshop_route_set_publication_records
  where publication_id=p_publication_id;
 v_expected_identity:=jsonb_build_object('protocol_version',1,
  'publication_id',v_publication.publication_id,'publication_kind',v_publication.publication_kind,
  'global_fence_token',v_publication.original_global_fence_token,
  'target_workshop_id',v_target.workshop_id,
  'target_route_fence_token',v_target.target_route_fence_token,
  'route_set_digest',v_publication.route_set_digest);
 if p_resolution_kind='candidate' then
  if v_publication.interrupted_phase not in ('publication_started','observed')
   or v_publication.sealed_count is null or v_count<>v_publication.sealed_count
   or p_observed_selector is distinct from v_publication.selector
   or p_observed_directory_device is distinct from v_publication.candidate_directory_device
   or p_observed_directory_inode is distinct from v_publication.candidate_directory_inode
   or p_observed_loaded_identity is distinct from v_expected_identity then
   return query select 'evidence_mismatch',null::jsonb; return; end if;
 elsif p_resolution_kind='prior' then
  if v_publication.interrupted_phase not in ('staging','sealed','publication_started')
   or v_publication.prior_recorded_at is null
   or p_observed_selector is distinct from v_publication.prior_selector
   or p_observed_directory_device is distinct from v_publication.prior_directory_device
   or p_observed_directory_inode is distinct from v_publication.prior_directory_inode
   or p_observed_loaded_identity is distinct from v_publication.prior_loaded_identity then
   return query select 'evidence_mismatch',null::jsonb; return; end if;
 elsif p_resolution_kind='unstarted' then
  if v_publication.interrupted_phase<>'staging' or v_publication.prior_recorded_at is not null
   or v_publication.publication_started_at is not null or v_count<>0
   or p_observed_selector is not null or p_observed_directory_device is not null
   or p_observed_directory_inode is not null or p_observed_loaded_identity is not null then
   return query select 'evidence_mismatch',null::jsonb; return; end if;
 else
  if p_observed_selector is not null or p_observed_directory_device is not null
   or p_observed_directory_inode is not null or p_observed_loaded_identity is not null then
   return query select 'evidence_mismatch',null::jsonb; return; end if;
 end if;
 v_evidence:=jsonb_build_object('publication_id',v_publication.publication_id,
  'claim_fence',p_claim_fence,'claim_mode',v_publication.reconciliation_claim_mode,
  'reconciliation_operation_id',v_publication.reconciliation_operation_id,
  'reconciliation_operation_attempt',v_publication.reconciliation_operation_attempt,
  'reconciliation_operation_lease_owner',v_publication.reconciliation_operation_lease_owner,
  'resolution_kind',p_resolution_kind,'interrupted_phase',v_publication.interrupted_phase,
  'observed_selector',p_observed_selector,'observed_directory_device',p_observed_directory_device,
  'observed_directory_inode',p_observed_directory_inode,
  'observed_loaded_identity',p_observed_loaded_identity);
 insert into control.workshop_route_set_publication_resolutions(publication_id,
  reconciliation_claim_fence,reconciliation_operation_id,reconciliation_operation_attempt,
  reconciliation_operation_lease_owner,reconciliation_owner,reconciliation_token_digest,
  claim_mode,resolution_kind,evidence) values(p_publication_id,p_claim_fence,
  v_publication.reconciliation_operation_id,v_publication.reconciliation_operation_attempt,
  v_publication.reconciliation_operation_lease_owner,p_reconciliation_owner,v_token_digest,
  v_publication.reconciliation_claim_mode,p_resolution_kind,v_evidence);
 update control.workshop_route_set_publications set reconciliation_operation_id=null,
  reconciliation_operation_attempt=null,reconciliation_operation_lease_owner=null,
  reconciliation_owner=null,reconciliation_token=null,reconciliation_expires_at=null,
  reconciliation_claim_mode=null,updated_at=now() where publication_id=p_publication_id;
 return query select 'recorded',v_evidence;
end $function$;

revoke all on table control.workshop_route_set_publication_resolutions from public;
revoke all on function control.reject_route_set_resolution_mutation() from public;
revoke all on function control.validate_route_set_recovery_eligibility() from public;
revoke all on function control.lock_interrupted_route_set_publication_claim(uuid,uuid,uuid,bigint) from public;
revoke all on function control.discover_interrupted_route_set_publications(uuid,integer) from public;
revoke all on function control.claim_interrupted_route_set_publication(uuid,uuid,integer,text,uuid,uuid,integer) from public;
revoke all on function control.renew_interrupted_route_set_publication_claim(uuid,uuid,uuid,bigint,integer) from public;
revoke all on function control.read_interrupted_route_set_publication_state(uuid,uuid,uuid,bigint) from public;
revoke all on function control.resolve_interrupted_route_set_publication_observation(uuid,uuid,uuid,bigint,text,text,bigint,bigint,jsonb) from public;

do $migration$ declare v_role text; begin
 foreach v_role in array array['control_api','control_tenant_api','control_membership_worker','control_provisioning_worker',
  'control_invoice_worker','control_inventory_worker','control_email_worker','control_reconciliation_worker',
  'control_lifecycle_worker','control_backup_scheduler','control_driver_ledger','control_release_worker','control_privacy_worker'] loop
  if exists(select 1 from pg_roles where rolname=v_role) then
   execute format('revoke all on table control.workshop_route_set_publication_resolutions from %I',v_role);
   execute format('revoke all on function control.reject_route_set_resolution_mutation() from %I',v_role);
   execute format('revoke all on function control.validate_route_set_recovery_eligibility() from %I',v_role);
   execute format('revoke all on function control.lock_interrupted_route_set_publication_claim(uuid,uuid,uuid,bigint) from %I',v_role);
  end if;
 end loop;
 if exists(select 1 from pg_roles where rolname='control_driver_ledger') then
  grant execute on function control.discover_interrupted_route_set_publications(uuid,integer) to control_driver_ledger;
  grant execute on function control.claim_interrupted_route_set_publication(uuid,uuid,integer,text,uuid,uuid,integer) to control_driver_ledger;
  grant execute on function control.renew_interrupted_route_set_publication_claim(uuid,uuid,uuid,bigint,integer) to control_driver_ledger;
  grant execute on function control.read_interrupted_route_set_publication_state(uuid,uuid,uuid,bigint) to control_driver_ledger;
  grant execute on function control.resolve_interrupted_route_set_publication_observation(uuid,uuid,uuid,bigint,text,text,bigint,bigint,jsonb) to control_driver_ledger;
 end if;
end $migration$;

comment on table control.workshop_route_set_publication_resolutions is
'Immutable, non-terminal interrupted route-set observations; evidence never grants filesystem authority or releases quarantined fleet membership.';
