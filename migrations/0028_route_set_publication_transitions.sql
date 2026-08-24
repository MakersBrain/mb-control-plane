-- Dormant evidence transitions for migration 0027 route-set publications.
-- This migration deliberately supplies no activation, applied-head mutation,
-- successful finalization, recovery admission, or interrupted claim API.

create function control.valid_route_set_loaded_identity(p_identity jsonb)
returns boolean language sql immutable parallel safe set search_path=pg_catalog,control as $function$
 select p_identity is null or control.valid_release_route_loaded_identity(p_identity) or (
  jsonb_typeof(p_identity)='object' and pg_column_size(p_identity)<=4096
  and p_identity ?& array['protocol_version','publication_id','publication_kind','global_fence_token',
    'target_workshop_id','target_route_fence_token','route_set_digest']
  and p_identity-array['protocol_version','publication_id','publication_kind','global_fence_token',
    'target_workshop_id','target_route_fence_token','route_set_digest']='{}'::jsonb
  and jsonb_typeof(p_identity->'protocol_version')='number'
  and jsonb_typeof(p_identity->'publication_id')='string'
  and jsonb_typeof(p_identity->'publication_kind')='string'
  and jsonb_typeof(p_identity->'global_fence_token')='number'
  and jsonb_typeof(p_identity->'target_workshop_id')='string'
  and jsonb_typeof(p_identity->'target_route_fence_token')='number'
  and jsonb_typeof(p_identity->'route_set_digest')='string'
  and p_identity->>'protocol_version'='1'
  and p_identity->>'publication_id' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
  and p_identity->>'publication_kind' in ('projection','recovery_maintenance','recovery_restore')
  and p_identity->>'global_fence_token' ~ '^[1-9][0-9]{0,18}$'
  and (length(p_identity->>'global_fence_token')<19
    or p_identity->>'global_fence_token'<='9223372036854775807')
  and p_identity->>'target_workshop_id' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
  and p_identity->>'target_route_fence_token' ~ '^[1-9][0-9]{0,18}$'
  and (length(p_identity->>'target_route_fence_token')<19
    or p_identity->>'target_route_fence_token'<='9223372036854775807')
  and p_identity->>'route_set_digest' ~ '^sha256:[0-9a-f]{64}$')
$function$;

create function control.valid_route_set_prior_selector_identity(p_selector text,p_identity jsonb)
returns boolean language sql immutable parallel safe set search_path=pg_catalog,control as $function$
 select p_selector is not null and p_selector ~ '^generations/[A-Za-z0-9][A-Za-z0-9-]{0,63}$'
  and control.valid_route_set_loaded_identity(p_identity) and (
   (p_selector='generations/boot-live' and p_identity is null)
   or (p_identity is not null and (
    (p_identity ? 'effect_run_id'
     and p_selector='generations/startup-'||(p_identity->>'effect_run_id'))
    or (p_identity ? 'fleet_run_id'
     and p_selector='generations/release-'||replace(p_identity->>'fleet_run_id','-','')
      ||'-'||(p_identity->>'overlay_kind'))
    or (p_identity ? 'publication_id'
     and p_selector='generations/route-'||replace(p_identity->>'publication_id','-','')||'-'||
      case p_identity->>'publication_kind'
       when 'projection' then 'projection'
       when 'recovery_maintenance' then 'recovery-maintenance'
       when 'recovery_restore' then 'recovery-restore' end))))
$function$;

alter table control.workshop_route_set_publications
 drop constraint workshop_route_set_publications_phase_check,
 drop constraint workshop_route_set_publications_prior_check,
 drop constraint workshop_route_set_publications_terminal_check,
 drop constraint workshop_route_set_publications_phase_evidence_check,
 add constraint workshop_route_set_publications_phase_check check(phase in (
   'staging','sealed','publication_started','observed','quarantined')),
 add constraint workshop_route_set_publications_prior_check check(
  (prior_recorded_at is null and prior_selector is null and prior_directory_device is null
   and prior_directory_inode is null and prior_loaded_identity is null)
  or (prior_recorded_at is not null and prior_selector is not null
   and prior_selector ~ '^generations/[A-Za-z0-9][A-Za-z0-9-]{0,63}$'
   and prior_directory_device>0 and prior_directory_inode>0
   and control.valid_route_set_prior_selector_identity(prior_selector,prior_loaded_identity))),
 add constraint workshop_route_set_publications_terminal_check check(
  ((phase='quarantined')=(quarantined_at is not null))
  and ((phase='quarantined')=(interrupted_phase is not null))
  and finished_at is null
  and ((phase='quarantined' and safe_error='route_set_publication_outcome_unknown')
   or (phase<>'quarantined' and
   (safe_error is null and quarantined_at is null and interrupted_phase is null
    and finished_at is null)))),
 add constraint workshop_route_set_publications_phase_evidence_check check(
  (phase='staging' and sealed_count is null and publication_started_at is null
   and observed_at is null and finished_at is null)
  or (phase='sealed' and prior_recorded_at is not null and sealed_count=snapshot_count
   and publication_started_at is null and observed_at is null and finished_at is null)
  or (phase='publication_started' and prior_recorded_at is not null and sealed_count=snapshot_count
   and publication_started_at is not null and observed_at is null and finished_at is null)
  or (phase='observed' and prior_recorded_at is not null and sealed_count=snapshot_count
   and publication_started_at is not null and observed_at is not null and finished_at is null)
  or (phase='quarantined' and finished_at is null and (
   (interrupted_phase='staging' and sealed_count is null and publication_started_at is null and observed_at is null)
   or (interrupted_phase='sealed' and prior_recorded_at is not null and sealed_count=snapshot_count
    and publication_started_at is null and observed_at is null)
   or (interrupted_phase='publication_started' and prior_recorded_at is not null
    and sealed_count=snapshot_count and publication_started_at is not null and observed_at is null)
   or (interrupted_phase='observed' and prior_recorded_at is not null
    and sealed_count=snapshot_count and publication_started_at is not null and observed_at is not null))));

create function control.validate_route_set_publication_phase_transition()
returns trigger language plpgsql set search_path=pg_catalog,control as $function$
declare v_target control.workshop_route_set_publication_targets%rowtype; v_expected jsonb;
begin
 if new.phase is distinct from old.phase and not (
   (old.phase='staging' and new.phase in ('sealed','quarantined'))
   or (old.phase='sealed' and new.phase in ('publication_started','quarantined'))
   or (old.phase='publication_started' and new.phase in ('observed','quarantined'))
   or (old.phase='observed' and new.phase='quarantined')) then
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
 return new;
end $function$;

create trigger workshop_route_set_publications_phase_monotonic
before update on control.workshop_route_set_publications for each row
execute function control.validate_route_set_publication_phase_transition();

create or replace function control.has_route_set_publication_authority(
 p_publication_id uuid,p_instance_owner uuid,p_execution_token uuid,
 p_global_lease_token uuid,p_route_lease_token uuid,p_global_fence_token bigint,
 p_target_route_fence_token bigint
) returns boolean language sql stable security definer set search_path=pg_catalog,control as $function$
 select exists(select 1
 from control.workshop_route_set_publications publication
 join control.workshop_route_set_publication_targets target using(publication_id)
 join control.operations upstream on upstream.id=publication.control_operation_id
 join control.deployment_driver_operations driver on driver.id=publication.driver_operation_id
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
  and upstream.state='in_flight' and upstream.attempt=publication.control_operation_attempt
  and upstream.leased_by=publication.control_operation_lease_owner and upstream.lease_expires_at>now()
  and driver.state='in_progress' and driver.safe_error is null
  and driver.execution_token=p_execution_token and driver.lease_expires_at>now()
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

create function control.record_route_set_publication_prior(
 p_publication_id uuid,p_instance_owner uuid,p_execution_token uuid,p_global_lease_token uuid,
 p_route_lease_token uuid,p_global_fence_token bigint,p_target_route_fence_token bigint,
 p_prior_selector text,p_prior_directory_device bigint,p_prior_directory_inode bigint,
 p_prior_loaded_identity jsonb
) returns text language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_row control.workshop_route_set_publications%rowtype;
begin
 if not control.lock_route_set_publication_authority(p_publication_id,p_instance_owner,p_execution_token,
   p_global_lease_token,p_route_lease_token,p_global_fence_token,p_target_route_fence_token) then return 'authority_lost'; end if;
 select * into v_row from control.workshop_route_set_publications where publication_id=p_publication_id for update;
 if v_row.prior_recorded_at is not null then
  if v_row.prior_selector=p_prior_selector and v_row.prior_directory_device=p_prior_directory_device
   and v_row.prior_directory_inode=p_prior_directory_inode
   and v_row.prior_loaded_identity is not distinct from p_prior_loaded_identity then return 'replay'; end if;
  return 'conflict';
 end if;
 if v_row.phase<>'staging' then return 'wrong_phase'; end if;
 if p_prior_selector is null or p_prior_selector !~ '^generations/[A-Za-z0-9][A-Za-z0-9-]{0,63}$'
  or p_prior_directory_device is null or p_prior_directory_device<=0
  or p_prior_directory_inode is null or p_prior_directory_inode<=0
  or p_prior_selector=v_row.selector
  or not control.valid_route_set_prior_selector_identity(p_prior_selector,p_prior_loaded_identity)
  then return 'invalid'; end if;
 update control.workshop_route_set_publications set prior_selector=p_prior_selector,
  prior_directory_device=p_prior_directory_device,prior_directory_inode=p_prior_directory_inode,
  prior_loaded_identity=p_prior_loaded_identity,prior_recorded_at=now(),updated_at=now()
 where publication_id=p_publication_id;
 return 'recorded';
end $function$;

create function control.record_route_set_publication_entry(
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
  or (v_snapshot.is_target and v_publication.publication_kind='recovery_restore'
   and p_rendered_digest<>v_snapshot.baseline_applied_rendered_digest)
  or (v_snapshot.is_target and v_publication.publication_kind='recovery_maintenance'
   and p_disposition<>'present') then return 'render_invariant_mismatch'; end if;
 insert into control.workshop_route_set_publication_records(publication_id,workshop_id,generation,
  projection_digest,disposition,applied_rendered_digest,rendered_digest)
 values(p_publication_id,p_workshop_id,p_generation,p_projection_digest,p_disposition,
  p_applied_rendered_digest,p_rendered_digest);
 return 'recorded';
end $function$;

create function control.seal_route_set_publication(
 p_publication_id uuid,p_instance_owner uuid,p_execution_token uuid,p_global_lease_token uuid,
 p_route_lease_token uuid,p_global_fence_token bigint,p_target_route_fence_token bigint,
 p_selector text,p_directory_device bigint,p_directory_inode bigint,p_record_count integer,
 p_present_count integer,p_route_set_digest text
) returns text language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_row control.workshop_route_set_publications%rowtype; v_count integer; v_present integer; v_digest text;
begin
 if not control.lock_route_set_publication_authority(p_publication_id,p_instance_owner,p_execution_token,
   p_global_lease_token,p_route_lease_token,p_global_fence_token,p_target_route_fence_token) then return 'authority_lost'; end if;
 select * into v_row from control.workshop_route_set_publications where publication_id=p_publication_id for update;
 if v_row.phase<>'staging' then
  if v_row.sealed_count=p_record_count and v_row.sealed_present_count=p_present_count
   and v_row.route_set_digest=p_route_set_digest and v_row.selector=p_selector
   and v_row.candidate_directory_device=p_directory_device
   and v_row.candidate_directory_inode=p_directory_inode then return 'replay'; end if;
  return 'wrong_phase';
 end if;
 if v_row.prior_recorded_at is null then return 'prior_absent'; end if;
 if p_selector is distinct from v_row.selector or p_directory_device is null or p_directory_device<=0
  or p_directory_inode is null or p_directory_inode<=0
  or p_record_count is distinct from v_row.snapshot_count or p_present_count is null
  or p_present_count not between 0 and p_record_count
  or p_route_set_digest is null or p_route_set_digest !~ '^sha256:[0-9a-f]{64}$' then return 'invalid'; end if;
 if p_directory_device=v_row.prior_directory_device
  and p_directory_inode=v_row.prior_directory_inode then return 'prior_directory_reused'; end if;
 select count(*),count(*) filter(where disposition='present') into v_count,v_present
 from control.workshop_route_set_publication_records where publication_id=p_publication_id;
 select control.route_set_publication_digest(p_publication_id) into v_digest;
 if v_count<>p_record_count then return 'count_mismatch'; end if;
 if v_present<>p_present_count then return 'present_count_mismatch'; end if;
 if v_digest is distinct from p_route_set_digest then return 'digest_mismatch'; end if;
 update control.workshop_route_set_publications set phase='sealed',sealed_count=p_record_count,
  sealed_present_count=p_present_count,route_set_digest=p_route_set_digest,
  candidate_directory_device=p_directory_device,candidate_directory_inode=p_directory_inode,updated_at=now()
 where publication_id=p_publication_id;
 return 'sealed';
end $function$;

create function control.start_route_set_publication(
 p_publication_id uuid,p_instance_owner uuid,p_execution_token uuid,p_global_lease_token uuid,
 p_route_lease_token uuid,p_global_fence_token bigint,p_target_route_fence_token bigint
) returns text language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_phase text;
begin
 if not control.lock_route_set_publication_authority(p_publication_id,p_instance_owner,p_execution_token,
   p_global_lease_token,p_route_lease_token,p_global_fence_token,p_target_route_fence_token) then return 'authority_lost'; end if;
 select phase into v_phase from control.workshop_route_set_publications where publication_id=p_publication_id for update;
 if v_phase in ('publication_started','observed') then return 'replay'; end if;
 if v_phase<>'sealed' then return 'wrong_phase'; end if;
 update control.workshop_route_set_publications set phase='publication_started',
  publication_started_at=now(),updated_at=now() where publication_id=p_publication_id;
 return 'started';
end $function$;

create function control.observe_route_set_publication(
 p_publication_id uuid,p_instance_owner uuid,p_execution_token uuid,p_global_lease_token uuid,
 p_route_lease_token uuid,p_global_fence_token bigint,p_target_route_fence_token bigint,
 p_observed_selector text,p_observed_directory_device bigint,p_observed_directory_inode bigint,
 p_loaded_identity jsonb
) returns text language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_row control.workshop_route_set_publications%rowtype; v_expected jsonb;
begin
 if not control.lock_route_set_publication_authority(p_publication_id,p_instance_owner,p_execution_token,
   p_global_lease_token,p_route_lease_token,p_global_fence_token,p_target_route_fence_token) then return 'authority_lost'; end if;
 select * into v_row from control.workshop_route_set_publications where publication_id=p_publication_id for update;
 v_expected:=jsonb_build_object('protocol_version',1,'publication_id',v_row.publication_id,
  'publication_kind',v_row.publication_kind,'global_fence_token',v_row.original_global_fence_token,
  'target_workshop_id',v_row.target_workshop_id,'target_route_fence_token',p_target_route_fence_token,
  'route_set_digest',v_row.route_set_digest);
 if p_observed_selector is distinct from v_row.selector
  or p_observed_directory_device is distinct from v_row.candidate_directory_device
  or p_observed_directory_inode is distinct from v_row.candidate_directory_inode
  or p_loaded_identity is distinct from v_expected then return 'observation_mismatch'; end if;
 if v_row.phase='observed' then return 'replay'; end if;
 if v_row.phase<>'publication_started' then return 'wrong_phase'; end if;
 update control.workshop_route_set_publications set phase='observed',observed_selector=p_observed_selector,
  observed_loaded_identity=p_loaded_identity,observed_at=now(),updated_at=now()
 where publication_id=p_publication_id;
 return 'observed';
end $function$;

create function control.quarantine_route_set_publication(
 p_publication_id uuid,p_instance_owner uuid,p_execution_token uuid,p_global_lease_token uuid,
 p_route_lease_token uuid,p_global_fence_token bigint,p_target_route_fence_token bigint,
 p_safe_error text
) returns boolean language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_row control.workshop_route_set_publications%rowtype; v_target control.workshop_route_set_publication_targets%rowtype;
 v_upstream control.operations%rowtype; v_global control.deployment_driver_resource_leases%rowtype;
 v_route control.workshop_route_application_leases%rowtype; v_driver control.deployment_driver_operations%rowtype;
 v_expired boolean; v_changed integer; v_control_operation_id uuid;
begin
 if p_publication_id is null or p_instance_owner is null or p_execution_token is null
  or p_global_lease_token is null or p_route_lease_token is null
  or p_global_fence_token is null or p_target_route_fence_token is null
  or p_safe_error is distinct from 'route_set_publication_outcome_unknown' then return false; end if;
 select control_operation_id into v_control_operation_id from control.workshop_route_set_publications
 where publication_id=p_publication_id;
 if not found then return false; end if;
 select * into v_upstream from control.operations where id=v_control_operation_id for update;
 perform 1 from control.route_set_publication_protocol_state where singleton for update;
 select * into v_global from control.deployment_driver_resource_leases where resource_key='runtime/shared-odoo' for update;
 select * into v_target from control.workshop_route_set_publication_targets where publication_id=p_publication_id;
 select * into v_route from control.workshop_route_application_leases where workshop_id=v_target.workshop_id for update;
 select * into v_driver from control.deployment_driver_operations where id=(select driver_operation_id
  from control.workshop_route_set_publications where publication_id=p_publication_id) for update;
 select * into v_row from control.workshop_route_set_publications where publication_id=p_publication_id for update;
 if v_row.original_instance_owner is distinct from p_instance_owner
  or v_row.original_execution_token is distinct from p_execution_token
  or v_row.original_global_lease_token is distinct from p_global_lease_token
  or v_row.original_route_lease_token is distinct from p_route_lease_token
  or v_row.original_global_fence_token is distinct from p_global_fence_token
  or v_target.target_route_fence_token is distinct from p_target_route_fence_token then return false; end if;
 if v_row.phase='quarantined' then
  return coalesce(v_global.state='quarantined' and v_global.authority_kind='route-set-publication'
   and v_global.route_set_publication_id is not distinct from p_publication_id
   and v_global.lease_owner is not distinct from p_instance_owner
   and v_global.fence_token is not distinct from p_global_fence_token and v_global.lease_token is null
   and v_global.lease_expires_at is null and v_global.quarantined_at is not null
   and v_global.safe_error='runtime_outcome_unknown' and v_route.state='quarantined'
   and v_route.authority_kind='route-set-publication'
   and v_route.route_set_publication_id is not distinct from p_publication_id
   and v_route.lease_owner is not distinct from p_instance_owner
   and v_route.fence_token is not distinct from p_target_route_fence_token
   and v_route.lease_token is null and v_route.lease_expires_at is null
   and v_route.quarantined_at is not null and v_route.safe_error='route_set_publication_outcome_unknown'
   and v_route.generation is not distinct from v_target.target_generation
   and v_route.projection_digest is not distinct from v_target.target_projection_digest
   and v_driver.state='in_progress' and v_driver.safe_error='runtime_outcome_unknown'
   and v_driver.execution_token is null and v_driver.lease_expires_at is null,false);
 end if;
 if v_row.phase not in ('staging','sealed','publication_started','observed') then return false; end if;
 if v_global.state is distinct from 'held'
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
  or v_route.generation is distinct from v_target.target_generation
  or v_route.projection_digest is distinct from v_target.target_projection_digest
  or v_driver.state is distinct from 'in_progress'
  or v_driver.execution_token is distinct from p_execution_token then return false; end if;
 v_expired:=coalesce(v_upstream.lease_expires_at<=now(),true)
  or coalesce(v_driver.lease_expires_at<=now(),true)
  or coalesce(v_global.lease_expires_at<=now(),true)
  or coalesce(v_route.lease_expires_at<=now(),true);
 if v_row.phase in ('staging','sealed') and not v_expired then return false; end if;
 update control.deployment_driver_resource_leases set state='quarantined',lease_token=null,
  lease_expires_at=null,quarantined_at=now(),safe_error='runtime_outcome_unknown',updated_at=now()
 where resource_key='runtime/shared-odoo' and route_set_publication_id=p_publication_id;
 get diagnostics v_changed=row_count; if v_changed<>1 then raise exception 'global quarantine drifted' using errcode='40001'; end if;
 update control.workshop_route_application_leases set state='quarantined',lease_token=null,
  lease_expires_at=null,quarantined_at=now(),safe_error='route_set_publication_outcome_unknown',updated_at=now()
 where workshop_id=v_target.workshop_id and route_set_publication_id=p_publication_id;
 get diagnostics v_changed=row_count; if v_changed<>1 then raise exception 'route quarantine drifted' using errcode='40001'; end if;
 update control.deployment_driver_operations set safe_error='runtime_outcome_unknown',execution_token=null,
  lease_expires_at=null,updated_at=now() where id=v_row.driver_operation_id and state='in_progress';
 get diagnostics v_changed=row_count; if v_changed<>1 then raise exception 'driver quarantine drifted' using errcode='40001'; end if;
 update control.workshop_route_set_publications set interrupted_phase=phase,phase='quarantined',
  quarantined_at=now(),safe_error=p_safe_error,updated_at=now()
 where publication_id=p_publication_id;
 return true;
end $function$;

revoke all on function control.valid_route_set_loaded_identity(jsonb) from public;
revoke all on function control.valid_route_set_prior_selector_identity(text,jsonb) from public;
revoke all on function control.validate_route_set_publication_phase_transition() from public;
revoke all on function control.record_route_set_publication_prior(uuid,uuid,uuid,uuid,uuid,bigint,bigint,text,bigint,bigint,jsonb) from public;
revoke all on function control.record_route_set_publication_entry(uuid,uuid,uuid,uuid,uuid,bigint,bigint,uuid,bigint,text,text,text,text) from public;
revoke all on function control.seal_route_set_publication(uuid,uuid,uuid,uuid,uuid,bigint,bigint,text,bigint,bigint,integer,integer,text) from public;
revoke all on function control.start_route_set_publication(uuid,uuid,uuid,uuid,uuid,bigint,bigint) from public;
revoke all on function control.observe_route_set_publication(uuid,uuid,uuid,uuid,uuid,bigint,bigint,text,bigint,bigint,jsonb) from public;
revoke all on function control.quarantine_route_set_publication(uuid,uuid,uuid,uuid,uuid,bigint,bigint,text) from public;

do $migration$ declare v_role text; begin
 foreach v_role in array array['control_api','control_tenant_api','control_membership_worker','control_provisioning_worker',
  'control_invoice_worker','control_inventory_worker','control_email_worker','control_reconciliation_worker',
  'control_lifecycle_worker','control_backup_scheduler','control_driver_ledger','control_release_worker','control_privacy_worker'] loop
  if exists(select 1 from pg_roles where rolname=v_role) then
   execute format('revoke all on function control.valid_route_set_loaded_identity(jsonb) from %I',v_role);
   execute format('revoke all on function control.valid_route_set_prior_selector_identity(text,jsonb) from %I',v_role);
   execute format('revoke all on function control.validate_route_set_publication_phase_transition() from %I',v_role);
  end if;
 end loop;
 if exists(select 1 from pg_roles where rolname='control_driver_ledger') then
  grant execute on function control.record_route_set_publication_prior(uuid,uuid,uuid,uuid,uuid,bigint,bigint,text,bigint,bigint,jsonb) to control_driver_ledger;
  grant execute on function control.record_route_set_publication_entry(uuid,uuid,uuid,uuid,uuid,bigint,bigint,uuid,bigint,text,text,text,text) to control_driver_ledger;
  grant execute on function control.seal_route_set_publication(uuid,uuid,uuid,uuid,uuid,bigint,bigint,text,bigint,bigint,integer,integer,text) to control_driver_ledger;
  grant execute on function control.start_route_set_publication(uuid,uuid,uuid,uuid,uuid,bigint,bigint) to control_driver_ledger;
  grant execute on function control.observe_route_set_publication(uuid,uuid,uuid,uuid,uuid,bigint,bigint,text,bigint,bigint,jsonb) to control_driver_ledger;
  grant execute on function control.quarantine_route_set_publication(uuid,uuid,uuid,uuid,uuid,bigint,bigint,text) to control_driver_ledger;
 end if;
end $migration$;

comment on table control.workshop_route_set_publications is
'Dormant immutable full-fleet publication evidence through exact worker observation; authority remains held and no applied head advances.';
