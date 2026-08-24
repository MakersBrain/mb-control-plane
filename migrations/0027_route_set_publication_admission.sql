-- Dormant admission and immutable snapshot boundary for complete projection-
-- derived route-set generations.  This migration deliberately leaves the
-- singleton in flat_v1 and exposes no activation or selector-transition API.
-- Recovery/startup/release readiness remains false until their flat writers
-- are replaced by later reviewed migrations.

create table control.route_set_publication_protocol_state (
    singleton boolean primary key default true check(singleton),
    mode text not null,
    protocol_version smallint not null,
    normal_ready boolean not null,
    recovery_ready boolean not null,
    startup_ready boolean not null,
    release_ready boolean not null,
    activation_epoch bigint not null default 0,
    activated_at timestamptz,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    constraint route_set_publication_protocol_mode_check
      check(mode in ('flat_v1','activating_v1','generation_v1')),
    constraint route_set_publication_protocol_version_check
      check(protocol_version=1),
    constraint route_set_publication_protocol_activation_check check(
      (mode='flat_v1' and activation_epoch=0 and activated_at is null)
      or (mode='activating_v1' and activation_epoch>0 and activated_at is null
          and normal_ready and recovery_ready and startup_ready and release_ready)
      or (mode='generation_v1' and activation_epoch>0 and activated_at is not null
          and normal_ready and recovery_ready and startup_ready and release_ready))
);

insert into control.route_set_publication_protocol_state(
  mode,protocol_version,normal_ready,recovery_ready,startup_ready,release_ready
) values('flat_v1',1,false,false,false,false);

create table control.workshop_route_set_publications (
    publication_id uuid primary key default gen_random_uuid(),
    protocol_version smallint not null,
    publication_kind text not null,
    driver_operation_id uuid not null unique,
    control_operation_id uuid not null,
    control_operation_attempt integer not null,
    control_operation_lease_owner text not null,
    original_instance_owner uuid not null,
    original_execution_token uuid not null,
    original_global_lease_token uuid not null,
    original_route_lease_token uuid not null,
    original_global_fence_token bigint not null,
    target_workshop_id uuid not null,
    selector text not null unique,
    snapshot_count integer not null,
    phase text not null,
    interrupted_phase text,
    prior_selector text,
    prior_directory_device bigint,
    prior_directory_inode bigint,
    prior_loaded_identity jsonb,
    prior_recorded_at timestamptz,
    sealed_count integer,
    sealed_present_count integer,
    route_set_digest text,
    candidate_directory_device bigint,
    candidate_directory_inode bigint,
    publication_started_at timestamptz,
    observed_selector text,
    observed_loaded_identity jsonb,
    observed_at timestamptz,
    finished_at timestamptz,
    quarantined_at timestamptz,
    safe_error text,
    reconciliation_operation_id uuid,
    reconciliation_operation_attempt integer,
    reconciliation_operation_lease_owner text,
    reconciliation_owner uuid,
    reconciliation_token uuid,
    reconciliation_expires_at timestamptz,
    trace_parent text,
    trace_state text,
    correlation_id uuid not null,
    retention_not_before timestamptz not null default now()+interval '30 days',
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    constraint workshop_route_set_publications_driver_fkey
      foreign key(driver_operation_id) references control.deployment_driver_operations(id) on delete restrict,
    constraint workshop_route_set_publications_control_fkey
      foreign key(control_operation_id) references control.operations(id) on delete restrict,
    constraint workshop_route_set_publications_target_fkey
      foreign key(target_workshop_id) references control.workshops(id) on delete restrict,
    constraint workshop_route_set_publications_reconciliation_fkey
      foreign key(reconciliation_operation_id) references control.operations(id) on delete restrict,
    constraint workshop_route_set_publications_protocol_check check(protocol_version=1),
    constraint workshop_route_set_publications_kind_check
      check(publication_kind in ('projection','recovery_maintenance','recovery_restore')),
    constraint workshop_route_set_publications_selector_check check(
      selector='generations/route-'||replace(publication_id::text,'-','')||'-'||case publication_kind
        when 'projection' then 'projection'
        when 'recovery_maintenance' then 'recovery-maintenance'
        when 'recovery_restore' then 'recovery-restore' end),
    constraint workshop_route_set_publications_count_check check(snapshot_count between 1 and 500),
    constraint workshop_route_set_publications_phase_check check(phase in (
      'staging','sealed','publication_started','observed','completed','quarantined')),
    constraint workshop_route_set_publications_interrupted_check check(
      interrupted_phase is null or interrupted_phase in
        ('staging','sealed','publication_started','observed')),
    constraint workshop_route_set_publications_fence_check check(
      original_global_fence_token>0 and control_operation_attempt>0
      and btrim(control_operation_lease_owner)<>''),
    constraint workshop_route_set_publications_prior_check check(
      (prior_recorded_at is null and prior_selector is null and prior_directory_device is null
       and prior_directory_inode is null and prior_loaded_identity is null)
      or (prior_recorded_at is not null and prior_selector is not null
       and prior_selector ~ '^generations/[A-Za-z0-9][A-Za-z0-9-]{0,63}$'
       and prior_directory_device>0 and prior_directory_inode>0
       and (prior_loaded_identity is null or
         (jsonb_typeof(prior_loaded_identity)='object' and pg_column_size(prior_loaded_identity)<=4096)))),
    constraint workshop_route_set_publications_seal_check check(
      (sealed_count is null and sealed_present_count is null and route_set_digest is null
       and candidate_directory_device is null and candidate_directory_inode is null)
      or (sealed_count=snapshot_count and sealed_present_count between 0 and sealed_count
       and route_set_digest ~ '^sha256:[0-9a-f]{64}$'
       and candidate_directory_device>0 and candidate_directory_inode>0)),
    constraint workshop_route_set_publications_observation_check check(
      (observed_at is null and observed_selector is null and observed_loaded_identity is null)
      or (observed_at is not null and observed_selector=selector
       and jsonb_typeof(observed_loaded_identity)='object'
       and pg_column_size(observed_loaded_identity)<=4096)),
    constraint workshop_route_set_publications_terminal_check check(
      (phase<>'completed' or (observed_at is not null and finished_at is not null))
      and ((phase='quarantined')=(quarantined_at is not null))
      and ((phase='quarantined')=(interrupted_phase is not null))
      and (phase<>'quarantined' or safe_error='route_set_publication_outcome_unknown')
      and (phase='quarantined' or (safe_error is null and quarantined_at is null
        and interrupted_phase is null))),
    constraint workshop_route_set_publications_phase_evidence_check check(
      (phase='staging' and prior_recorded_at is null and sealed_count is null
       and publication_started_at is null and observed_at is null and finished_at is null)
      or (phase='sealed' and prior_recorded_at is not null and sealed_count=snapshot_count
       and publication_started_at is null and observed_at is null and finished_at is null)
      or (phase='publication_started' and prior_recorded_at is not null and sealed_count=snapshot_count
       and publication_started_at is not null and observed_at is null and finished_at is null)
      or (phase='observed' and prior_recorded_at is not null and sealed_count=snapshot_count
       and publication_started_at is not null and observed_at is not null and finished_at is null)
      or (phase='completed' and prior_recorded_at is not null and sealed_count=snapshot_count
       and publication_started_at is not null and observed_at is not null and finished_at is not null)
      or phase='quarantined'),
    constraint workshop_route_set_publications_reconciliation_check check(
      (reconciliation_operation_id is null and reconciliation_operation_attempt is null
       and reconciliation_operation_lease_owner is null and reconciliation_owner is null
       and reconciliation_token is null and reconciliation_expires_at is null)
      or (phase='quarantined' and reconciliation_operation_id is not null
       and reconciliation_operation_attempt>0 and btrim(reconciliation_operation_lease_owner)<>''
       and reconciliation_owner is not null and reconciliation_token is not null
       and reconciliation_expires_at is not null)),
    constraint workshop_route_set_publications_trace_check check(
      (trace_parent is null or trace_parent ~ '^[0-9a-f]{2}-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$')
      and (trace_state is null or octet_length(trace_state)<=512))
);

create table control.workshop_route_set_publication_targets (
    publication_id uuid primary key,
    workshop_id uuid not null,
    prior_applied_generation bigint not null,
    prior_applied_digest text not null,
    prior_applied_disposition text not null,
    prior_applied_rendered_digest text not null,
    prior_applied_driver_operation_id uuid,
    prior_applied_effect_run_id uuid,
    prior_applied_fence_token bigint not null,
    target_generation bigint not null,
    target_projection_digest text not null,
    target_disposition text not null,
    target_route_fence_token bigint not null,
    unique(publication_id,workshop_id,target_generation,target_projection_digest,target_disposition),
    constraint workshop_route_set_publication_targets_publication_fkey
      foreign key(publication_id) references control.workshop_route_set_publications(publication_id) on delete restrict,
    constraint workshop_route_set_publication_targets_projection_fkey
      foreign key(workshop_id,target_generation,target_projection_digest,target_disposition)
      references control.workshop_route_projections(workshop_id,generation,projection_digest,disposition) on delete restrict,
    constraint workshop_route_set_publication_targets_shape_check check(
      prior_applied_generation>0 and prior_applied_digest ~ '^sha256:[0-9a-f]{64}$'
      and prior_applied_disposition in ('present','absent')
      and prior_applied_rendered_digest ~ '^sha256:[0-9a-f]{64}$'
      and ((prior_applied_driver_operation_id is not null)<>(prior_applied_effect_run_id is not null))
      and prior_applied_fence_token>0 and target_generation>0
      and target_projection_digest ~ '^sha256:[0-9a-f]{64}$'
      and target_disposition in ('present','absent')
      and target_route_fence_token>prior_applied_fence_token)
);

create table control.workshop_route_set_publication_snapshot (
    publication_id uuid not null,
    workshop_id uuid not null,
    generation bigint not null,
    projection_digest text not null,
    disposition text not null,
    canonical_projection jsonb not null,
    baseline_applied_generation bigint not null,
    baseline_applied_digest text not null,
    baseline_applied_disposition text not null,
    baseline_applied_rendered_digest text not null,
    baseline_applied_driver_operation_id uuid,
    baseline_applied_effect_run_id uuid,
    baseline_applied_fence_token bigint not null,
    is_target boolean not null,
    primary key(publication_id,workshop_id),
    unique(publication_id,workshop_id,generation,projection_digest,disposition),
    constraint workshop_route_set_publication_snapshot_publication_fkey
      foreign key(publication_id) references control.workshop_route_set_publications(publication_id) on delete restrict,
    constraint workshop_route_set_publication_snapshot_projection_fkey
      foreign key(workshop_id,generation,projection_digest,disposition)
      references control.workshop_route_projections(workshop_id,generation,projection_digest,disposition) on delete restrict,
    constraint workshop_route_set_publication_snapshot_shape_check check(
      generation>0 and projection_digest ~ '^sha256:[0-9a-f]{64}$'
      and disposition in ('present','absent') and jsonb_typeof(canonical_projection)='object'
      and pg_column_size(canonical_projection)<=65536
      and baseline_applied_generation>0
      and baseline_applied_digest ~ '^sha256:[0-9a-f]{64}$'
      and baseline_applied_disposition in ('present','absent')
      and baseline_applied_rendered_digest ~ '^sha256:[0-9a-f]{64}$'
      and ((baseline_applied_driver_operation_id is not null)<>(baseline_applied_effect_run_id is not null))
      and baseline_applied_fence_token>0)
);

create unique index workshop_route_set_publication_one_target
  on control.workshop_route_set_publication_snapshot(publication_id) where is_target;

create table control.workshop_route_set_publication_records (
    publication_id uuid not null,
    workshop_id uuid not null,
    generation bigint not null,
    projection_digest text not null,
    disposition text not null,
    applied_rendered_digest text not null,
    rendered_digest text not null,
    recorded_at timestamptz not null default now(),
    primary key(publication_id,workshop_id),
    constraint workshop_route_set_publication_records_snapshot_fkey
      foreign key(publication_id,workshop_id,generation,projection_digest,disposition)
      references control.workshop_route_set_publication_snapshot(
        publication_id,workshop_id,generation,projection_digest,disposition) on delete restrict,
    constraint workshop_route_set_publication_records_shape_check check(
      generation>0 and projection_digest ~ '^sha256:[0-9a-f]{64}$'
      and disposition in ('present','absent')
      and applied_rendered_digest ~ '^sha256:[0-9a-f]{64}$'
      and rendered_digest ~ '^sha256:[0-9a-f]{64}$')
);

create function control.reject_route_set_publication_identity_mutation()
returns trigger language plpgsql set search_path=pg_catalog,control as $function$
begin
  raise exception 'immutable route-set publication evidence cannot be changed' using errcode='55000';
end $function$;

create function control.validate_route_set_publication_parent_update()
returns trigger language plpgsql set search_path=pg_catalog,control as $function$
begin
 if tg_op='DELETE' then
  raise exception 'route-set publication parents are retained evidence' using errcode='55000';
 end if;
 if new.publication_id<>old.publication_id or new.protocol_version<>old.protocol_version
  or new.publication_kind<>old.publication_kind or new.driver_operation_id<>old.driver_operation_id
  or new.control_operation_id<>old.control_operation_id
  or new.control_operation_attempt<>old.control_operation_attempt
  or new.control_operation_lease_owner<>old.control_operation_lease_owner
  or new.original_instance_owner<>old.original_instance_owner
  or new.original_execution_token<>old.original_execution_token
  or new.original_global_lease_token<>old.original_global_lease_token
  or new.original_route_lease_token<>old.original_route_lease_token
  or new.original_global_fence_token<>old.original_global_fence_token
  or new.target_workshop_id<>old.target_workshop_id or new.selector<>old.selector
  or new.snapshot_count<>old.snapshot_count or new.correlation_id<>old.correlation_id
  or new.trace_parent is distinct from old.trace_parent
  or new.trace_state is distinct from old.trace_state
  or new.retention_not_before<>old.retention_not_before or new.created_at<>old.created_at then
  raise exception 'immutable route-set publication identity cannot be changed' using errcode='55000';
 end if;
 return new;
end $function$;

create trigger workshop_route_set_publications_identity_immutable before update or delete
on control.workshop_route_set_publications for each row
execute function control.validate_route_set_publication_parent_update();

create trigger workshop_route_set_targets_immutable before update or delete
on control.workshop_route_set_publication_targets for each row
execute function control.reject_route_set_publication_identity_mutation();
create trigger workshop_route_set_snapshot_immutable before update or delete
on control.workshop_route_set_publication_snapshot for each row
execute function control.reject_route_set_publication_identity_mutation();
create trigger workshop_route_set_records_immutable before update or delete
on control.workshop_route_set_publication_records for each row
execute function control.reject_route_set_publication_identity_mutation();

create function control.route_set_publication_record_bytes(
 p_workshop_id uuid,p_generation bigint,p_projection_digest text,p_disposition text,
 p_applied_rendered_digest text,p_rendered_digest text
) returns bytea language sql immutable strict parallel safe set search_path=pg_catalog,control as $function$
 select uuid_send(p_workshop_id)||int8send(p_generation)
  ||int4send(octet_length(convert_to(p_projection_digest,'UTF8')))||convert_to(p_projection_digest,'UTF8')
  ||int4send(octet_length(convert_to(p_disposition,'UTF8')))||convert_to(p_disposition,'UTF8')
  ||int4send(octet_length(convert_to(p_applied_rendered_digest,'UTF8')))||convert_to(p_applied_rendered_digest,'UTF8')
  ||int4send(octet_length(convert_to(p_rendered_digest,'UTF8')))||convert_to(p_rendered_digest,'UTF8')
$function$;

create function control.route_set_publication_digest(p_publication_id uuid)
returns text language sql stable security definer set search_path=pg_catalog,control as $function$
 select 'sha256:'||encode(public.digest(
  convert_to('mb-route-set-publication-v1','UTF8')||decode('00','hex')||
  coalesce(decode(string_agg(encode(control.route_set_publication_record_bytes(
    record.workshop_id,record.generation,record.projection_digest,record.disposition,
    record.applied_rendered_digest,record.rendered_digest),'hex'),'' order by record.workshop_id),'hex'),''::bytea),
  'sha256'),'hex')
 from control.workshop_route_set_publication_records record
 where record.publication_id=p_publication_id
$function$;

-- Add exact polymorphic publication ownership without changing any active
-- flat-v1 caller while the singleton remains flat_v1.
alter table control.deployment_driver_resource_leases
  drop constraint deployment_driver_resource_leases_authority_check,
  drop constraint deployment_driver_resource_leases_shape_v2_check,
  add column route_set_publication_id uuid,
  add constraint deployment_driver_resource_leases_route_set_publication_fkey
    foreign key(route_set_publication_id)
    references control.workshop_route_set_publications(publication_id) on delete restrict,
  add constraint deployment_driver_resource_leases_authority_check
    check(authority_kind is null or authority_kind in ('release','startup-rebuild','route-set-publication')),
  add constraint deployment_driver_resource_leases_shape_v3_check check(
    (state='idle' and authority_kind is null and driver_operation_id is null and effect_run_id is null
      and route_set_publication_id is null and lease_owner is null and lease_token is null
      and lease_expires_at is null and heartbeat_at is null and quarantined_at is null and safe_error is null)
    or (state='held' and authority_kind is not null
      and ((authority_kind='release' and driver_operation_id is not null and effect_run_id is null and route_set_publication_id is null)
        or (authority_kind='startup-rebuild' and driver_operation_id is null and effect_run_id is not null and route_set_publication_id is null)
        or (authority_kind='route-set-publication' and driver_operation_id is null and effect_run_id is null and route_set_publication_id is not null))
      and lease_owner is not null and lease_token is not null and lease_expires_at is not null
      and heartbeat_at is not null and quarantined_at is null and safe_error is null and fence_token>0)
    or (state='quarantined' and authority_kind is not null
      and ((authority_kind='release' and driver_operation_id is not null and effect_run_id is null and route_set_publication_id is null)
        or (authority_kind='startup-rebuild' and driver_operation_id is null and effect_run_id is not null and route_set_publication_id is null)
        or (authority_kind='route-set-publication' and driver_operation_id is null and effect_run_id is null and route_set_publication_id is not null))
      and lease_owner is not null and lease_token is null and lease_expires_at is null
      and heartbeat_at is not null and quarantined_at is not null and safe_error='runtime_outcome_unknown'
      and fence_token>0));

alter table control.workshop_route_application_leases
  drop constraint workshop_route_application_leases_authority_check,
  drop constraint workshop_route_application_leases_shape_v3_check,
  add column route_set_publication_id uuid,
  add constraint workshop_route_application_leases_route_set_publication_fkey
    foreign key(route_set_publication_id)
    references control.workshop_route_set_publications(publication_id) on delete restrict,
  add constraint workshop_route_application_leases_authority_check check(authority_kind is null or authority_kind in (
    'projection','startup-rebuild','recovery-maintenance','legacy','release-overlay','route-set-publication')),
  add constraint workshop_route_application_leases_shape_v4_check check(
    (state in ('uninitialized','idle') and authority_kind is null and driver_operation_id is null
      and effect_run_id is null and release_publication_id is null and route_set_publication_id is null
      and generation is null and projection_digest is null and lease_owner is null and lease_token is null
      and lease_expires_at is null and heartbeat_at is null and quarantined_at is null and safe_error is null
      and ((state='uninitialized' and initialization_required) or (state='idle' and not initialization_required)))
    or (state='held' and authority_kind in
      ('projection','startup-rebuild','recovery-maintenance','release-overlay','route-set-publication')
      and ((authority_kind='projection' and driver_operation_id is not null and effect_run_id is null and release_publication_id is null and route_set_publication_id is null)
        or (authority_kind in ('startup-rebuild','recovery-maintenance') and driver_operation_id is null and effect_run_id is not null and release_publication_id is null and route_set_publication_id is null)
        or (authority_kind='release-overlay' and driver_operation_id is null and effect_run_id is null and release_publication_id is not null and route_set_publication_id is null)
        or (authority_kind='route-set-publication' and driver_operation_id is null and effect_run_id is null and release_publication_id is null and route_set_publication_id is not null))
      and lease_owner is not null and lease_token is not null and lease_expires_at is not null
      and heartbeat_at is not null and quarantined_at is null and safe_error is null and fence_token>0
      and ((authority_kind='startup-rebuild' and generation is null and projection_digest is null)
        or (generation>0 and projection_digest ~ '^sha256:[0-9a-f]{64}$')))
    or (state='maintenance' and authority_kind='recovery-maintenance' and driver_operation_id is null
      and effect_run_id is not null and release_publication_id is null and route_set_publication_id is null
      and generation>0 and projection_digest ~ '^sha256:[0-9a-f]{64}$' and lease_owner is null
      and lease_token is null and lease_expires_at is null and heartbeat_at is not null
      and quarantined_at is null and safe_error='recovery_maintenance' and fence_token>0)
    or (state='quarantined' and authority_kind is not null
      and ((authority_kind in ('projection','legacy') and driver_operation_id is not null and effect_run_id is null and release_publication_id is null and route_set_publication_id is null)
        or (authority_kind in ('startup-rebuild','recovery-maintenance') and driver_operation_id is null and effect_run_id is not null and release_publication_id is null and route_set_publication_id is null)
        or (authority_kind='release-overlay' and driver_operation_id is null and effect_run_id is null and release_publication_id is not null and route_set_publication_id is null)
        or (authority_kind='route-set-publication' and driver_operation_id is null and effect_run_id is null and release_publication_id is null and route_set_publication_id is not null))
      and lease_owner is not null and lease_token is null and lease_expires_at is null
      and heartbeat_at is not null and quarantined_at is not null and fence_token>0
      and safe_error in ('runtime_outcome_unknown','legacy_route_outcome_unknown',
        'legacy_maintenance_outcome_unknown','release_route_publication_outcome_unknown',
        'route_set_publication_outcome_unknown')));

create or replace function control.normalize_global_route_authority()
returns trigger language plpgsql security definer set search_path=pg_catalog,control as $function$
begin
 if new.state='idle' then
  new.authority_kind:=null; new.effect_run_id:=null; new.route_set_publication_id:=null;
 elsif new.driver_operation_id is not null and new.effect_run_id is null
   and new.route_set_publication_id is null and new.authority_kind is null then
  new.authority_kind:='release';
 end if;
 return new;
end $function$;

create or replace function control.normalize_workshop_route_authority()
returns trigger language plpgsql security definer set search_path=pg_catalog,control as $function$
begin
 if old.state='maintenance' and new.state='held'
   and (new.authority_kind is distinct from 'recovery-maintenance'
    or new.effect_run_id is distinct from old.effect_run_id) then
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

-- Fleet membership is part of every universal generation. In generation_v1,
-- membership mutation serializes on the same protocol/global rows as admission
-- and is forbidden for the full logical lifetime of held or quarantined
-- publication authority.
create function control.guard_route_set_fleet_membership()
returns trigger language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_mode text; v_global_state text;
begin
 select mode into strict v_mode from control.route_set_publication_protocol_state
 where singleton for update;
 if v_mode<>'generation_v1' then
  if tg_op='DELETE' then return old; end if;
  return new;
 end if;
 select state into strict v_global_state from control.deployment_driver_resource_leases
 where resource_key='runtime/shared-odoo' for update;
 if v_global_state<>'idle' then
  raise exception 'fleet membership is fenced by route-set publication authority'
   using errcode='55000';
 end if;
 if tg_op='DELETE' then return old; end if;
 return new;
end $function$;

create trigger workshops_route_set_membership_guard before insert or delete
on control.workshops for each row execute function control.guard_route_set_fleet_membership();

-- Authority helper used by renewal and bounded reads.  It verifies the exact
-- upstream lease but never extends it.
create function control.has_route_set_publication_authority(
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
 where publication.publication_id=p_publication_id and publication.phase<>'quarantined'
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
  and target.target_route_fence_token=p_target_route_fence_token)
$function$;

create function control.lock_route_set_publication_authority(
 p_publication_id uuid,p_instance_owner uuid,p_execution_token uuid,
 p_global_lease_token uuid,p_route_lease_token uuid,p_global_fence_token bigint,
 p_target_route_fence_token bigint
) returns boolean language plpgsql volatile security definer set search_path=pg_catalog,control as $function$
declare v_control uuid; v_target uuid; v_driver uuid;
begin
 select control_operation_id,target_workshop_id,driver_operation_id
 into v_control,v_target,v_driver from control.workshop_route_set_publications
 where publication_id=p_publication_id;
 if not found then return false; end if;
 perform 1 from control.operations where id=v_control for update;
 perform 1 from control.route_set_publication_protocol_state where singleton for update;
 perform 1 from control.deployment_driver_resource_leases where resource_key='runtime/shared-odoo' for update;
 perform 1 from control.workshop_route_application_leases where workshop_id=v_target for update;
 perform 1 from control.deployment_driver_operations where id=v_driver for update;
 perform 1 from control.workshop_route_set_publications where publication_id=p_publication_id for update;
 return control.has_route_set_publication_authority(p_publication_id,p_instance_owner,p_execution_token,
  p_global_lease_token,p_route_lease_token,p_global_fence_token,p_target_route_fence_token);
end $function$;

create function control.admit_route_set_publication(
 p_control_operation_id uuid,p_control_operation_attempt integer,p_control_operation_lease_owner text,
 p_workshop_id uuid,p_publication_kind text,p_idempotency_key text,p_request_digest text,
 p_generation bigint,p_projection_digest text,p_instance_owner uuid,p_execution_token uuid,
 p_global_lease_token uuid,p_route_lease_token uuid,p_ttl_seconds integer
) returns table(outcome text,publication_id uuid,driver_operation_id uuid,global_fence_token bigint,
 target_route_fence_token bigint,selector text,snapshot_count integer)
language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_upstream control.operations%rowtype; v_global control.deployment_driver_resource_leases%rowtype;
 v_target_lease control.workshop_route_application_leases%rowtype;
 v_target_state control.workshop_route_projection_state%rowtype; v_driver control.deployment_driver_operations%rowtype;
 v_publication control.workshop_route_set_publications%rowtype; v_publication_id uuid:=gen_random_uuid();
 v_target control.workshop_route_set_publication_targets%rowtype;
 v_driver_id uuid; v_global_fence bigint; v_route_fence bigint; v_count integer; v_exact integer;
 v_lease_count integer; v_state_count integer; v_ready_count integer; v_selected_count integer;
 v_expires timestamptz; v_exact_key boolean;
begin
 if p_publication_kind is null or p_publication_kind<>'projection'
  or p_control_operation_attempt is null or p_control_operation_attempt<=0
  or p_control_operation_lease_owner is null or btrim(p_control_operation_lease_owner)=''
  or p_idempotency_key is null or length(p_idempotency_key) not between 1 and 180
  or p_request_digest is null or p_request_digest !~ '^[0-9a-f]{64}$'
  or p_generation is null or p_generation<=0
  or p_projection_digest is null or p_projection_digest !~ '^sha256:[0-9a-f]{64}$'
  or p_instance_owner is null or p_execution_token is null or p_global_lease_token is null
  or p_route_lease_token is null or p_ttl_seconds is null
  or p_ttl_seconds not between 60 and 1200 then
  return query select 'invalid',null::uuid,null::uuid,null::bigint,null::bigint,null::text,null::integer; return;
 end if;
 v_expires:=now()+make_interval(secs=>p_ttl_seconds);
 select * into v_upstream from control.operations operation where operation.id=p_control_operation_id for update;
 if not found or v_upstream.workshop_id is distinct from p_workshop_id
  or v_upstream.state<>'in_flight' or v_upstream.attempt<>p_control_operation_attempt
  or v_upstream.leased_by is distinct from p_control_operation_lease_owner or v_upstream.lease_expires_at<=now()
  or not ((v_upstream.kind='tenant.provision' and v_upstream.queue='tenant-provisioning')
   or (v_upstream.kind in ('tenant.reconcile','module.enable','module.restrict','webshop-domain.reconcile')
       and v_upstream.queue='tenant-reconciliation')
   or (v_upstream.kind='tenant.lifecycle' and v_upstream.queue='tenant-lifecycle')) then
  return query select 'upstream_lease_lost',null::uuid,null::uuid,null::bigint,null::bigint,null::text,null::integer; return;
 end if;
 perform 1 from control.route_set_publication_protocol_state protocol where protocol.singleton for update;
 if not exists(select 1 from control.route_set_publication_protocol_state
   where singleton and mode='generation_v1' and normal_ready and recovery_ready and startup_ready and release_ready) then
  return query select 'protocol_inactive',null::uuid,null::uuid,null::bigint,null::bigint,null::text,null::integer; return;
 end if;
 select * into v_global from control.deployment_driver_resource_leases
 where resource_key='runtime/shared-odoo' for update;
 perform 1 from control.workshop_route_application_leases lease order by lease.workshop_id for update;
 perform 1 from control.workshop_route_projection_state state order by state.workshop_id for update;
 select * into v_driver from control.deployment_driver_operations operation
 where operation.workshop_id=p_workshop_id and operation.action='route-project'
  and operation.idempotency_key=p_idempotency_key for update;
 v_exact_key:=found;
 if not v_exact_key then
  select * into v_driver from control.deployment_driver_operations operation
  where operation.workshop_id=p_workshop_id and operation.route_generation=p_generation
   and operation.route_projection_digest=p_projection_digest
  order by operation.id limit 1 for update;
 end if;
 if found then
  select * into v_publication from control.workshop_route_set_publications publication
   where publication.driver_operation_id=v_driver.id for update;
  if not found then
   return query select 'legacy_receipt',null::uuid,v_driver.id,null::bigint,null::bigint,null::text,null::integer; return;
  end if;
  select * into strict v_target from control.workshop_route_set_publication_targets target
   where target.publication_id=v_publication.publication_id;
  -- Resource and execution tokens are immutable publication identity. A
  -- restarted executor must reconcile/claim in a later protocol; presenting
  -- fresh tokens here is a conflict, never a silent authority transfer.
  if not v_exact_key or v_driver.request_digest<>p_request_digest or v_driver.action<>'route-project'
   or v_driver.route_generation<>p_generation or v_driver.route_projection_digest<>p_projection_digest
   or v_publication.publication_kind<>p_publication_kind
   or v_publication.control_operation_id<>p_control_operation_id
   or v_publication.control_operation_attempt<>p_control_operation_attempt
   or v_publication.control_operation_lease_owner<>p_control_operation_lease_owner
   or v_publication.target_workshop_id<>p_workshop_id
   or v_target.target_generation<>p_generation
   or v_target.target_projection_digest<>p_projection_digest
   or v_publication.original_instance_owner<>p_instance_owner
   or v_publication.original_execution_token<>p_execution_token
   or v_publication.original_global_lease_token<>p_global_lease_token
   or v_publication.original_route_lease_token<>p_route_lease_token then
   return query select 'conflict',v_publication.publication_id,v_driver.id,
    v_publication.original_global_fence_token,null::bigint,v_publication.selector,v_publication.snapshot_count; return;
  end if;
  return query select case when control.has_route_set_publication_authority(v_publication.publication_id,
    p_instance_owner,p_execution_token,p_global_lease_token,p_route_lease_token,
    v_publication.original_global_fence_token,v_target.target_route_fence_token)
    then 'replay' else 'authority_lost' end,v_publication.publication_id,v_driver.id,
    v_publication.original_global_fence_token,v_target.target_route_fence_token,
    v_publication.selector,v_publication.snapshot_count; return;
 end if;
 if v_global.state<>'idle' then
  return query select case when v_global.state='quarantined' then 'fleet_quarantined' else 'fleet_busy' end,
   v_global.route_set_publication_id,v_global.driver_operation_id,v_global.fence_token,null::bigint,null::text,null::integer; return;
 end if;
 select * into v_target_lease from control.workshop_route_application_leases where workshop_id=p_workshop_id;
 select * into v_target_state from control.workshop_route_projection_state where workshop_id=p_workshop_id;
 select count(*) into v_count from control.workshops;
 select count(*) into v_lease_count from control.workshop_route_application_leases;
 select count(*) into v_state_count from control.workshop_route_projection_state;
 select count(*) into v_ready_count
 from control.workshops workshop
 join control.workshop_route_application_leases lease on lease.workshop_id=workshop.id
 join control.workshop_route_projection_state state on state.workshop_id=workshop.id
 where lease.state='idle'
  and state.applied_generation is not null and state.applied_digest is not null
  and state.applied_disposition is not null and state.applied_rendered_digest is not null
  and state.applied_fence_token is not null and state.applied_fence_token>0
  and ((state.applied_driver_operation_id is not null)<>(state.applied_effect_run_id is not null));
 select count(*) into v_selected_count
 from control.workshops workshop
 join control.workshop_route_projection_state state on state.workshop_id=workshop.id
 join control.workshop_route_projections projection on projection.workshop_id=state.workshop_id
  and projection.generation=case when state.workshop_id=p_workshop_id then state.desired_generation else state.applied_generation end
  and projection.projection_digest=case when state.workshop_id=p_workshop_id then state.desired_digest else state.applied_digest end
  and projection.disposition=case when state.workshop_id=p_workshop_id then state.desired_disposition else state.applied_disposition end;
 if v_count not between 1 and 500 or v_lease_count<>v_count or v_state_count<>v_count
  or v_ready_count<>v_count or v_selected_count<>v_count or v_target_lease.state<>'idle'
  or v_target_state.desired_generation<>p_generation or v_target_state.desired_digest<>p_projection_digest
  or v_target_state.applied_generation is null then
  return query select 'fleet_not_ready',null::uuid,null::uuid,null::bigint,null::bigint,null::text,v_count; return;
 end if;
 v_global_fence:=v_global.fence_token+1;
 v_route_fence:=greatest(v_target_lease.fence_token,v_target_state.applied_fence_token)+1;
 insert into control.deployment_driver_operations(idempotency_key,workshop_id,action,request_digest,
  control_operation_id,control_operation_attempt,control_operation_lease_owner,target_key,
  execution_token,lease_expires_at,execution_attempt,route_generation,route_projection_digest,route_fence_token)
 values(p_idempotency_key,p_workshop_id,'route-project',p_request_digest,p_control_operation_id,
  p_control_operation_attempt,p_control_operation_lease_owner,'route/'||p_workshop_id::text,
  p_execution_token,v_expires,1,p_generation,p_projection_digest,v_route_fence) returning id into v_driver_id;
 insert into control.workshop_route_set_publications(publication_id,protocol_version,publication_kind,
  driver_operation_id,control_operation_id,control_operation_attempt,control_operation_lease_owner,
  original_instance_owner,original_execution_token,original_global_lease_token,original_route_lease_token,
  original_global_fence_token,target_workshop_id,selector,snapshot_count,phase,trace_parent,trace_state,correlation_id)
 values(v_publication_id,1,p_publication_kind,v_driver_id,p_control_operation_id,p_control_operation_attempt,
  p_control_operation_lease_owner,p_instance_owner,p_execution_token,p_global_lease_token,p_route_lease_token,
  v_global_fence,p_workshop_id,'generations/route-'||replace(v_publication_id::text,'-','')||'-projection',
  v_count,'staging',v_upstream.trace_parent,v_upstream.trace_state,v_upstream.correlation_id);
 insert into control.workshop_route_set_publication_targets(publication_id,workshop_id,
  prior_applied_generation,prior_applied_digest,prior_applied_disposition,prior_applied_rendered_digest,
  prior_applied_driver_operation_id,prior_applied_effect_run_id,prior_applied_fence_token,
  target_generation,target_projection_digest,target_disposition,target_route_fence_token)
 values(v_publication_id,p_workshop_id,v_target_state.applied_generation,v_target_state.applied_digest,
  v_target_state.applied_disposition,v_target_state.applied_rendered_digest,
  v_target_state.applied_driver_operation_id,v_target_state.applied_effect_run_id,v_target_state.applied_fence_token,
  v_target_state.desired_generation,v_target_state.desired_digest,v_target_state.desired_disposition,v_route_fence);
 insert into control.workshop_route_set_publication_snapshot(publication_id,workshop_id,generation,
  projection_digest,disposition,canonical_projection,baseline_applied_generation,baseline_applied_digest,
  baseline_applied_disposition,baseline_applied_rendered_digest,baseline_applied_driver_operation_id,
  baseline_applied_effect_run_id,baseline_applied_fence_token,is_target)
 select v_publication_id,state.workshop_id,
  case when state.workshop_id=p_workshop_id then state.desired_generation else state.applied_generation end,
  case when state.workshop_id=p_workshop_id then state.desired_digest else state.applied_digest end,
  case when state.workshop_id=p_workshop_id then state.desired_disposition else state.applied_disposition end,
  projection.projection,state.applied_generation,state.applied_digest,state.applied_disposition,
  state.applied_rendered_digest,state.applied_driver_operation_id,state.applied_effect_run_id,
  state.applied_fence_token,state.workshop_id=p_workshop_id
 from control.workshop_route_projection_state state
 join control.workshop_route_projections projection on projection.workshop_id=state.workshop_id
  and projection.generation=case when state.workshop_id=p_workshop_id then state.desired_generation else state.applied_generation end
  and projection.projection_digest=case when state.workshop_id=p_workshop_id then state.desired_digest else state.applied_digest end
  and projection.disposition=case when state.workshop_id=p_workshop_id then state.desired_disposition else state.applied_disposition end
 order by state.workshop_id;
 get diagnostics v_exact=row_count;
 if v_exact<>v_count then raise exception 'route-set snapshot cardinality drifted' using errcode='40001'; end if;
 update control.deployment_driver_resource_leases set state='held',authority_kind='route-set-publication',
  driver_operation_id=null,effect_run_id=null,route_set_publication_id=v_publication_id,
  fence_token=v_global_fence,lease_owner=p_instance_owner,lease_token=p_global_lease_token,
  lease_expires_at=v_expires,heartbeat_at=now(),updated_at=now()
 where resource_key='runtime/shared-odoo' and state='idle';
 if not found then raise exception 'route-set global authority drifted' using errcode='40001'; end if;
 update control.workshop_route_application_leases set state='held',authority_kind='route-set-publication',
  driver_operation_id=null,effect_run_id=null,release_publication_id=null,route_set_publication_id=v_publication_id,
  fence_token=v_route_fence,generation=p_generation,projection_digest=p_projection_digest,
  lease_owner=p_instance_owner,lease_token=p_route_lease_token,lease_expires_at=v_expires,
  heartbeat_at=now(),updated_at=now() where workshop_id=p_workshop_id and state='idle';
 if not found then raise exception 'route-set target authority drifted' using errcode='40001'; end if;
 return query select 'acquired',v_publication_id,v_driver_id,v_global_fence,v_route_fence,
  'generations/route-'||replace(v_publication_id::text,'-','')||'-projection',v_count;
end $function$;

create function control.renew_route_set_publication(
 p_publication_id uuid,p_instance_owner uuid,p_execution_token uuid,p_global_lease_token uuid,
 p_route_lease_token uuid,p_global_fence_token bigint,p_target_route_fence_token bigint,p_ttl_seconds integer
) returns boolean language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_expires timestamptz; v_changed integer;
begin
 if p_ttl_seconds is null or p_ttl_seconds not between 60 and 1200 then return false; end if;
 if not control.lock_route_set_publication_authority(p_publication_id,p_instance_owner,p_execution_token,
  p_global_lease_token,p_route_lease_token,p_global_fence_token,p_target_route_fence_token) then return false; end if;
 v_expires:=now()+make_interval(secs=>p_ttl_seconds);
 update control.deployment_driver_operations driver set lease_expires_at=v_expires,updated_at=now()
 from control.workshop_route_set_publications publication where publication.publication_id=p_publication_id
  and driver.id=publication.driver_operation_id and driver.state='in_progress'
  and driver.execution_token=p_execution_token and driver.lease_expires_at>now();
 get diagnostics v_changed=row_count; if v_changed<>1 then return false; end if;
 update control.deployment_driver_resource_leases set lease_expires_at=v_expires,heartbeat_at=now(),updated_at=now()
 where resource_key='runtime/shared-odoo' and state='held' and authority_kind='route-set-publication'
  and route_set_publication_id=p_publication_id and lease_token=p_global_lease_token
  and fence_token=p_global_fence_token; get diagnostics v_changed=row_count; if v_changed<>1 then return false; end if;
 update control.workshop_route_application_leases lease set lease_expires_at=v_expires,heartbeat_at=now(),updated_at=now()
 from control.workshop_route_set_publication_targets target where target.publication_id=p_publication_id
  and lease.workshop_id=target.workshop_id and lease.state='held' and lease.authority_kind='route-set-publication'
  and lease.route_set_publication_id=p_publication_id and lease.lease_token=p_route_lease_token
  and lease.fence_token=p_target_route_fence_token; get diagnostics v_changed=row_count; return v_changed=1;
end $function$;

create function control.read_route_set_publication_snapshot_batch(
 p_publication_id uuid,p_instance_owner uuid,p_execution_token uuid,p_global_lease_token uuid,
 p_route_lease_token uuid,p_global_fence_token bigint,p_target_route_fence_token bigint,
 p_after_workshop_id uuid,p_limit integer
) returns table(workshop_id uuid,generation bigint,projection_digest text,disposition text,
 canonical_projection jsonb,applied_rendered_digest text,is_target boolean)
language plpgsql security definer set search_path=pg_catalog,control as $function$
begin
 if p_limit is null or p_limit not between 1 and 500 then return; end if;
 if not control.lock_route_set_publication_authority(p_publication_id,p_instance_owner,p_execution_token,
  p_global_lease_token,p_route_lease_token,p_global_fence_token,p_target_route_fence_token) then return; end if;
 return query select snapshot.workshop_id,snapshot.generation,snapshot.projection_digest,snapshot.disposition,
  snapshot.canonical_projection,snapshot.baseline_applied_rendered_digest,snapshot.is_target
 from control.workshop_route_set_publication_snapshot snapshot
 where snapshot.publication_id=p_publication_id
  and (p_after_workshop_id is null or snapshot.workshop_id>p_after_workshop_id)
 order by snapshot.workshop_id limit p_limit;
end $function$;

revoke all on table control.route_set_publication_protocol_state from public;
revoke all on table control.workshop_route_set_publications from public;
revoke all on table control.workshop_route_set_publication_targets from public;
revoke all on table control.workshop_route_set_publication_snapshot from public;
revoke all on table control.workshop_route_set_publication_records from public;
revoke all on function control.reject_route_set_publication_identity_mutation() from public;
revoke all on function control.validate_route_set_publication_parent_update() from public;
revoke all on function control.guard_route_set_fleet_membership() from public;
revoke all on function control.route_set_publication_record_bytes(uuid,bigint,text,text,text,text) from public;
revoke all on function control.route_set_publication_digest(uuid) from public;
revoke all on function control.has_route_set_publication_authority(uuid,uuid,uuid,uuid,uuid,bigint,bigint) from public;
revoke all on function control.lock_route_set_publication_authority(uuid,uuid,uuid,uuid,uuid,bigint,bigint) from public;
revoke all on function control.admit_route_set_publication(uuid,integer,text,uuid,text,text,text,bigint,text,uuid,uuid,uuid,uuid,integer) from public;
revoke all on function control.renew_route_set_publication(uuid,uuid,uuid,uuid,uuid,bigint,bigint,integer) from public;
revoke all on function control.read_route_set_publication_snapshot_batch(uuid,uuid,uuid,uuid,uuid,bigint,bigint,uuid,integer) from public;

do $migration$ declare v_role text; begin
 foreach v_role in array array['control_api','control_tenant_api','control_membership_worker','control_provisioning_worker',
  'control_invoice_worker','control_inventory_worker','control_email_worker','control_reconciliation_worker',
  'control_lifecycle_worker','control_backup_scheduler','control_driver_ledger','control_release_worker','control_privacy_worker'] loop
  if exists(select 1 from pg_roles where rolname=v_role) then
   execute format('revoke all on table control.route_set_publication_protocol_state, control.workshop_route_set_publications, control.workshop_route_set_publication_targets, control.workshop_route_set_publication_snapshot, control.workshop_route_set_publication_records from %I',v_role);
  end if;
 end loop;
 if exists(select 1 from pg_roles where rolname='control_driver_ledger') then
  grant execute on function control.admit_route_set_publication(uuid,integer,text,uuid,text,text,text,bigint,text,uuid,uuid,uuid,uuid,integer) to control_driver_ledger;
  grant execute on function control.renew_route_set_publication(uuid,uuid,uuid,uuid,uuid,bigint,bigint,integer) to control_driver_ledger;
  grant execute on function control.read_route_set_publication_snapshot_batch(uuid,uuid,uuid,uuid,uuid,bigint,bigint,uuid,integer) to control_driver_ledger;
 end if;
end $migration$;

comment on table control.route_set_publication_protocol_state is
'Dormant one-way coordinated gate; flat_v1 remains active until every selected-generation writer is immutable.';
comment on table control.workshop_route_set_publications is
'Dormant immutable full-fleet route-set admission evidence; migration 0027 supplies projection admission only.';
