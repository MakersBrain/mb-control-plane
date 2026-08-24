-- Dormant protocol-v2 route publication authority for fleet releases.
--
-- This migration deliberately stops at awaiting_worker_finalize.  Observing a
-- candidate route generation advances only the route projection heads; it does
-- not release either the global release authority or any per-workshop route
-- fence and it cannot mark the release driver operation successful.

create extension if not exists pgcrypto with schema public;

create table control.fleet_release_route_publications (
    driver_operation_id uuid primary key,
    fleet_run_id uuid not null unique,
    protocol_version smallint not null,
    original_instance_owner uuid not null,
    original_execution_token uuid not null,
    original_global_lease_token uuid not null,
    original_route_lease_token uuid not null,
    original_global_fence_token bigint not null,
    control_operation_id uuid not null,
    control_operation_attempt integer not null,
    control_operation_lease_owner text not null,
    target_slot text not null,
    snapshot_count integer not null,
    phase text not null,
    interrupted_phase text,
    prior_selector text,
    prior_directory_device bigint,
    prior_directory_inode bigint,
    prior_loaded_identity jsonb,
    prior_recorded_at timestamptz,
    maintenance_selector text not null,
    maintenance_count integer not null default 0,
    maintenance_sealed_count integer,
    maintenance_route_set_digest text,
    maintenance_directory_device bigint,
    maintenance_directory_inode bigint,
    maintenance_publication_started_at timestamptz,
    maintenance_observed_at timestamptz,
    external_effects_started_at timestamptz,
    candidate_selector text not null,
    candidate_count integer not null default 0,
    candidate_sealed_count integer,
    candidate_route_set_digest text,
    candidate_directory_device bigint,
    candidate_directory_inode bigint,
    candidate_publication_started_at timestamptz,
    candidate_observed_at timestamptz,
    quarantined_at timestamptz,
    safe_error text,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    constraint fleet_release_route_publications_snapshot_fkey
      foreign key(driver_operation_id,fleet_run_id)
      references control.fleet_release_route_snapshots(driver_operation_id,fleet_run_id)
      on delete restrict,
    constraint fleet_release_route_publications_protocol_check check(protocol_version=1),
    constraint fleet_release_route_publications_control_operation_fkey
      foreign key(control_operation_id) references control.operations(id) on delete restrict,
    constraint fleet_release_route_publications_control_identity_check check(
      control_operation_attempt>0 and btrim(control_operation_lease_owner)<>''),
    constraint fleet_release_route_publications_target_check check(target_slot in ('blue','green')),
    constraint fleet_release_route_publications_count_check check(
      snapshot_count between 1 and 500 and maintenance_count between 0 and snapshot_count
      and candidate_count between 0 and snapshot_count),
    constraint fleet_release_route_publications_selector_check check(
      maintenance_selector='generations/release-'||replace(fleet_run_id::text,'-','')||'-maintenance'
      and candidate_selector='generations/release-'||replace(fleet_run_id::text,'-','')||'-candidate'
      and (prior_selector is null or prior_selector ~ '^generations/[A-Za-z0-9][A-Za-z0-9-]{0,63}$')),
    constraint fleet_release_route_publications_phase_check check(phase in (
      'maintenance_staging','maintenance_sealed','maintenance_publication_started',
      'maintenance_observed','candidate_staging','candidate_sealed',
      'candidate_publication_started','awaiting_worker_finalize','quarantined')),
    constraint fleet_release_route_publications_interrupted_phase_check check(
      interrupted_phase is null or interrupted_phase in ('maintenance_staging','maintenance_sealed',
       'maintenance_publication_started','maintenance_observed','candidate_staging','candidate_sealed',
       'candidate_publication_started','awaiting_worker_finalize')),
    constraint fleet_release_route_publications_prior_check check(
      (prior_recorded_at is null and prior_selector is null and prior_directory_device is null and prior_directory_inode is null and prior_loaded_identity is null)
      or (prior_recorded_at is not null and prior_selector is not null
          and prior_directory_device>0 and prior_directory_inode>0
          and (prior_loaded_identity is null or (jsonb_typeof(prior_loaded_identity)='object'
            and pg_column_size(prior_loaded_identity)<=4096)))),
    constraint fleet_release_route_publications_maintenance_seal_check check(
      (maintenance_sealed_count is null and maintenance_route_set_digest is null
       and maintenance_directory_device is null and maintenance_directory_inode is null)
      or (maintenance_sealed_count=maintenance_count
       and maintenance_sealed_count=snapshot_count
       and maintenance_route_set_digest ~ '^sha256:[0-9a-f]{64}$'
       and maintenance_directory_device>0 and maintenance_directory_inode>0)),
    constraint fleet_release_route_publications_candidate_seal_check check(
      (candidate_sealed_count is null and candidate_route_set_digest is null
       and candidate_directory_device is null and candidate_directory_inode is null)
      or (candidate_sealed_count=candidate_count and candidate_sealed_count=snapshot_count
       and candidate_route_set_digest ~ '^sha256:[0-9a-f]{64}$'
       and candidate_directory_device>0 and candidate_directory_inode>0)),
    constraint fleet_release_route_publications_terminal_check check(
      (phase<>'awaiting_worker_finalize' or (candidate_observed_at is not null
       and candidate_publication_started_at is not null and external_effects_started_at is not null))
      and (phase<>'quarantined' or (quarantined_at is not null
       and safe_error='release_route_publication_outcome_unknown'))
      and ((phase='quarantined')=(quarantined_at is not null))
      and ((phase='quarantined')=(safe_error is not null))
      and ((phase='quarantined')=(interrupted_phase is not null))
      and (phase='maintenance_staging'
        or (phase='quarantined' and interrupted_phase='maintenance_staging')
        or prior_recorded_at is not null))
    ,constraint fleet_release_route_publications_phase_shape_check check(
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
        and candidate_directory_inode is null
        and candidate_publication_started_at is null and candidate_observed_at is null)
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
      or (phase='awaiting_worker_finalize' and maintenance_observed_at is not null
        and maintenance_sealed_count is not null and maintenance_route_set_digest is not null
        and maintenance_directory_device is not null and maintenance_directory_inode is not null
        and maintenance_publication_started_at is not null and external_effects_started_at is not null
        and candidate_sealed_count is not null and candidate_route_set_digest is not null
        and candidate_directory_device is not null and candidate_directory_inode is not null
        and candidate_publication_started_at is not null and candidate_observed_at is not null)
      or (phase='quarantined' and (
        (interrupted_phase='maintenance_staging' and maintenance_sealed_count is null
          and maintenance_route_set_digest is null and maintenance_directory_device is null
          and maintenance_directory_inode is null
          and maintenance_publication_started_at is null and maintenance_observed_at is null
          and external_effects_started_at is null and candidate_count=0
          and candidate_sealed_count is null and candidate_route_set_digest is null
          and candidate_directory_device is null and candidate_directory_inode is null
          and candidate_publication_started_at is null
          and candidate_observed_at is null)
        or (interrupted_phase='maintenance_sealed' and maintenance_sealed_count is not null
          and maintenance_route_set_digest is not null and maintenance_directory_device is not null
          and maintenance_directory_inode is not null
          and maintenance_publication_started_at is null and maintenance_observed_at is null
          and external_effects_started_at is null and candidate_count=0
          and candidate_sealed_count is null and candidate_route_set_digest is null
          and candidate_directory_device is null and candidate_directory_inode is null
          and candidate_publication_started_at is null
          and candidate_observed_at is null)
        or (interrupted_phase='maintenance_publication_started' and maintenance_sealed_count is not null
          and maintenance_route_set_digest is not null and maintenance_directory_device is not null
          and maintenance_directory_inode is not null
          and maintenance_publication_started_at is not null and maintenance_observed_at is null
          and external_effects_started_at is null and candidate_count=0
          and candidate_sealed_count is null and candidate_route_set_digest is null
          and candidate_directory_device is null and candidate_directory_inode is null
          and candidate_publication_started_at is null
          and candidate_observed_at is null)
        or (interrupted_phase='maintenance_observed' and maintenance_observed_at is not null
          and maintenance_sealed_count is not null and maintenance_route_set_digest is not null
          and maintenance_directory_device is not null and maintenance_directory_inode is not null
          and maintenance_publication_started_at is not null
          and external_effects_started_at is null and candidate_count=0
          and candidate_sealed_count is null and candidate_route_set_digest is null
          and candidate_directory_device is null and candidate_directory_inode is null
          and candidate_publication_started_at is null
          and candidate_observed_at is null)
        or (interrupted_phase='candidate_staging' and maintenance_observed_at is not null
          and maintenance_sealed_count is not null and maintenance_route_set_digest is not null
          and maintenance_directory_device is not null and maintenance_directory_inode is not null
          and maintenance_publication_started_at is not null
          and external_effects_started_at is not null and candidate_sealed_count is null
          and candidate_route_set_digest is null and candidate_directory_device is null
          and candidate_directory_inode is null and candidate_publication_started_at is null
          and candidate_observed_at is null)
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
          and candidate_publication_started_at is not null and candidate_observed_at is not null))))
);

create function control.valid_release_route_loaded_identity(p_identity jsonb)
returns boolean language sql immutable parallel safe set search_path=pg_catalog,control as $function$
 select p_identity is null or (
  jsonb_typeof(p_identity)='object' and pg_column_size(p_identity)<=4096 and (
   (p_identity ?& array['effect_run_id','sealed_digest']
    and p_identity-array['effect_run_id','sealed_digest']='{}'::jsonb
    and jsonb_typeof(p_identity->'effect_run_id')='string'
    and jsonb_typeof(p_identity->'sealed_digest')='string'
    and p_identity->>'effect_run_id' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    and p_identity->>'sealed_digest' ~ '^sha256:[0-9a-f]{64}$')
   or
   (p_identity ?& array['protocol_version','fleet_run_id','driver_operation_id','original_global_fence_token','overlay_kind','route_set_digest','target_slot']
    and p_identity-array['protocol_version','fleet_run_id','driver_operation_id','original_global_fence_token','overlay_kind','route_set_digest','target_slot']='{}'::jsonb
    and jsonb_typeof(p_identity->'protocol_version')='number'
    and jsonb_typeof(p_identity->'fleet_run_id')='string'
    and jsonb_typeof(p_identity->'driver_operation_id')='string'
    and jsonb_typeof(p_identity->'original_global_fence_token')='number'
    and jsonb_typeof(p_identity->'overlay_kind')='string'
    and jsonb_typeof(p_identity->'route_set_digest')='string'
    and jsonb_typeof(p_identity->'target_slot')='string'
    and p_identity->>'protocol_version'='1'
    and p_identity->>'fleet_run_id' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    and p_identity->>'driver_operation_id' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    and p_identity->>'original_global_fence_token' ~ '^[1-9][0-9]{0,18}$'
    and (length(p_identity->>'original_global_fence_token')<19
      or p_identity->>'original_global_fence_token'<='9223372036854775807')
    and p_identity->>'overlay_kind' in ('maintenance','candidate')
    and p_identity->>'route_set_digest' ~ '^sha256:[0-9a-f]{64}$'
    and p_identity->>'target_slot' in ('blue','green'))))
$function$;
alter table control.fleet_release_route_publications
 add constraint fleet_release_route_publications_prior_identity_check
 check(control.valid_release_route_loaded_identity(prior_loaded_identity)),
 add constraint fleet_release_route_publications_prior_selector_identity_check check(
  prior_recorded_at is null or
  (prior_selector='generations/boot-live' and prior_loaded_identity is null) or
  (prior_loaded_identity is not null and (
    (prior_loaded_identity ? 'effect_run_id'
      and prior_selector='generations/startup-'||(prior_loaded_identity->>'effect_run_id')) or
    (prior_loaded_identity ? 'fleet_run_id'
      and prior_selector='generations/release-'||replace(prior_loaded_identity->>'fleet_run_id','-','')
        ||'-'||(prior_loaded_identity->>'overlay_kind')))));

create table control.fleet_release_route_publication_owners (
    driver_operation_id uuid not null,
    workshop_id uuid not null,
    generation bigint not null,
    projection_digest text not null,
    applied_rendered_digest text not null,
    applied_fence_token bigint not null,
    snapshot_route_fence_token bigint not null,
    route_fence_token bigint not null,
    primary key(driver_operation_id,workshop_id),
    unique(driver_operation_id,workshop_id,generation,projection_digest,applied_rendered_digest),
    unique(driver_operation_id,workshop_id,generation,projection_digest,route_fence_token),
    constraint fleet_release_route_publication_owners_publication_fkey
      foreign key(driver_operation_id) references control.fleet_release_route_publications(driver_operation_id) on delete restrict,
    constraint fleet_release_route_publication_owners_snapshot_fkey
      foreign key(driver_operation_id,workshop_id,generation,projection_digest,
                  applied_rendered_digest,applied_fence_token,snapshot_route_fence_token)
      references control.fleet_release_route_snapshot_items(
                  driver_operation_id,workshop_id,generation,projection_digest,
                  applied_rendered_digest,applied_fence_token,route_fence_token) on delete restrict,
    constraint fleet_release_route_publication_owners_fence_check check(
      generation>0 and projection_digest ~ '^sha256:[0-9a-f]{64}$'
      and applied_rendered_digest ~ '^sha256:[0-9a-f]{64}$'
      and applied_fence_token>0 and snapshot_route_fence_token>0
      and route_fence_token=snapshot_route_fence_token+1)
);

create table control.fleet_release_route_publication_records (
    driver_operation_id uuid not null,
    overlay_kind text not null,
    workshop_id uuid not null,
    generation bigint not null,
    projection_digest text not null,
    applied_rendered_digest text not null,
    rendered_digest text not null,
    recorded_at timestamptz not null default now(),
    primary key(driver_operation_id,overlay_kind,workshop_id),
    constraint fleet_release_route_publication_records_owner_fkey
      foreign key(driver_operation_id,workshop_id,generation,projection_digest,
                  applied_rendered_digest)
      references control.fleet_release_route_publication_owners(
                  driver_operation_id,workshop_id,generation,projection_digest,
                  applied_rendered_digest),
    constraint fleet_release_route_publication_records_kind_check check(overlay_kind in ('maintenance','candidate')),
    constraint fleet_release_route_publication_records_digest_check check(
      generation>0 and projection_digest ~ '^sha256:[0-9a-f]{64}$'
      and applied_rendered_digest ~ '^sha256:[0-9a-f]{64}$'
      and rendered_digest ~ '^sha256:[0-9a-f]{64}$')
);

create function control.reject_release_route_publication_identity_mutation()
returns trigger language plpgsql set search_path=pg_catalog,control as $function$
begin
  raise exception 'immutable release route publication identity cannot be changed' using errcode='55000';
end $function$;

create function control.validate_release_route_publication_update()
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
   ('candidate_publication_started','awaiting_worker_finalize'),('maintenance_publication_started','quarantined'),
   ('maintenance_staging','quarantined'),('maintenance_sealed','quarantined'),
   ('maintenance_observed','quarantined'),('candidate_staging','quarantined'),('candidate_sealed','quarantined'),
   ('candidate_publication_started','quarantined'),('awaiting_worker_finalize','quarantined')))
 then raise exception 'invalid release route publication transition' using errcode='55000'; end if;
 return new;
end $function$;

create trigger fleet_release_route_publication_owners_immutable
before update or delete on control.fleet_release_route_publication_owners
for each row execute function control.reject_release_route_publication_identity_mutation();
create trigger fleet_release_route_publication_records_immutable
before update or delete on control.fleet_release_route_publication_records
for each row execute function control.reject_release_route_publication_identity_mutation();
create trigger fleet_release_route_publications_validate
before update on control.fleet_release_route_publications
for each row execute function control.validate_release_route_publication_update();
create trigger fleet_release_route_publications_delete_reject
before delete on control.fleet_release_route_publications
for each row execute function control.reject_release_route_publication_identity_mutation();

alter table control.workshop_route_application_leases
  drop constraint workshop_route_application_leases_authority_check,
  drop constraint workshop_route_application_leases_shape_v2_check,
  add column release_publication_id uuid,
  add constraint workshop_route_application_leases_release_publication_fkey
    foreign key(release_publication_id)
    references control.fleet_release_route_publications(driver_operation_id) on delete restrict,
  add constraint workshop_route_application_leases_authority_check
    check(authority_kind is null or authority_kind in (
      'projection','startup-rebuild','recovery-maintenance','legacy','release-overlay')),
  add constraint workshop_route_application_leases_shape_v3_check check(
    (state in ('uninitialized','idle') and authority_kind is null
      and driver_operation_id is null and effect_run_id is null and release_publication_id is null
      and generation is null and projection_digest is null and lease_owner is null
      and lease_token is null and lease_expires_at is null and heartbeat_at is null
      and quarantined_at is null and safe_error is null
      and ((state='uninitialized' and initialization_required) or (state='idle' and not initialization_required)))
    or
    (state='held' and authority_kind in ('projection','startup-rebuild','recovery-maintenance','release-overlay')
      and ((authority_kind='projection' and driver_operation_id is not null and effect_run_id is null and release_publication_id is null)
        or (authority_kind in ('startup-rebuild','recovery-maintenance') and driver_operation_id is null and effect_run_id is not null and release_publication_id is null)
        or (authority_kind='release-overlay' and driver_operation_id is null and effect_run_id is null and release_publication_id is not null))
      and lease_owner is not null and lease_token is not null and lease_expires_at is not null
      and heartbeat_at is not null and quarantined_at is null and safe_error is null and fence_token>0
      and ((authority_kind='startup-rebuild' and generation is null and projection_digest is null)
        or (generation>0 and projection_digest ~ '^sha256:[0-9a-f]{64}$')))
    or
    (state='maintenance' and authority_kind='recovery-maintenance'
      and driver_operation_id is null and effect_run_id is not null and release_publication_id is null
      and generation>0 and projection_digest ~ '^sha256:[0-9a-f]{64}$'
      and lease_owner is null and lease_token is null and lease_expires_at is null
      and heartbeat_at is not null and quarantined_at is null and safe_error='recovery_maintenance' and fence_token>0)
    or
    (state='quarantined' and authority_kind is not null
      and ((authority_kind in ('projection','legacy') and driver_operation_id is not null and effect_run_id is null and release_publication_id is null)
        or (authority_kind in ('startup-rebuild','recovery-maintenance') and driver_operation_id is null and effect_run_id is not null and release_publication_id is null)
        or (authority_kind='release-overlay' and driver_operation_id is null and effect_run_id is null and release_publication_id is not null))
      and lease_owner is not null and lease_token is null and lease_expires_at is null
      and heartbeat_at is not null and quarantined_at is not null and fence_token>0
      and safe_error in ('runtime_outcome_unknown','legacy_route_outcome_unknown',
        'legacy_maintenance_outcome_unknown','release_route_publication_outcome_unknown')));

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
  elsif new.driver_operation_id is not null and new.effect_run_id is null
        and new.release_publication_id is null and new.authority_kind is null then
    new.authority_kind:=case when new.generation is null then 'legacy' else 'projection' end;
  end if;
  return new;
end $function$;

create function control.validate_workshop_route_applied_driver_binding()
returns trigger language plpgsql set search_path=pg_catalog,control as $function$
begin
 if new.applied_driver_operation_id is null then return new; end if;
 if exists(select 1 from control.deployment_driver_operations operation
   where operation.id=new.applied_driver_operation_id and operation.workshop_id=new.workshop_id
    and operation.route_generation=new.applied_generation and operation.route_projection_digest=new.applied_digest
    and operation.route_fence_token=new.applied_fence_token) then return new; end if;
 if new.applied_disposition='present' and new.desired_disposition='present'
   and new.desired_generation=new.applied_generation and new.desired_digest=new.applied_digest
   and exists(select 1 from control.fleet_release_route_publication_owners owner
    join control.fleet_release_route_publications publication using(driver_operation_id)
    join control.fleet_release_route_publication_records record
      on record.driver_operation_id=owner.driver_operation_id and record.workshop_id=owner.workshop_id
     and record.overlay_kind='candidate'
    where owner.driver_operation_id=new.applied_driver_operation_id and owner.workshop_id=new.workshop_id
     and owner.generation=new.applied_generation and owner.projection_digest=new.applied_digest
     and owner.route_fence_token=new.applied_fence_token
     and record.generation=new.applied_generation and record.projection_digest=new.applied_digest
     and record.applied_rendered_digest=owner.applied_rendered_digest
     and record.rendered_digest=new.applied_rendered_digest
     and publication.phase in ('candidate_publication_started','awaiting_worker_finalize')) then return new; end if;
 raise exception 'applied route driver binding is not authorized' using errcode='55000';
end $function$;

create trigger workshop_route_projection_state_applied_driver_binding
before insert or update of applied_generation,applied_digest,applied_disposition,
 applied_rendered_digest,applied_driver_operation_id,applied_fence_token
on control.workshop_route_projection_state for each row
execute function control.validate_workshop_route_applied_driver_binding();

create function control.release_route_overlay_record_bytes(
  p_workshop_id uuid,p_generation bigint,p_projection_digest text,
  p_applied_rendered_digest text,p_rendered_digest text
) returns bytea language sql immutable strict parallel safe
set search_path=pg_catalog,control as $function$
  select uuid_send(p_workshop_id)||int8send(p_generation)
    ||int4send(octet_length(convert_to(p_projection_digest,'UTF8')))||convert_to(p_projection_digest,'UTF8')
    ||int4send(octet_length(convert_to(p_applied_rendered_digest,'UTF8')))||convert_to(p_applied_rendered_digest,'UTF8')
    ||int4send(octet_length(convert_to(p_rendered_digest,'UTF8')))||convert_to(p_rendered_digest,'UTF8')
$function$;

create function control.release_route_overlay_digest(p_driver_operation_id uuid,p_overlay_kind text)
returns text language sql stable security definer set search_path=pg_catalog,control as $function$
  select 'sha256:'||encode(public.digest(
    convert_to('mb-release-route-overlay-v1','UTF8')||decode('00','hex')||
    coalesce(decode(string_agg(encode(control.release_route_overlay_record_bytes(
      record.workshop_id,record.generation,record.projection_digest,
      record.applied_rendered_digest,record.rendered_digest),'hex'),'' order by record.workshop_id),'hex'),''::bytea),
    'sha256'),'hex')
  from control.fleet_release_route_publication_records record
  where record.driver_operation_id=p_driver_operation_id and record.overlay_kind=p_overlay_kind
$function$;

create function control.admit_immutable_release_route_publication(
  p_driver_operation_id uuid,p_instance_owner uuid,p_execution_token uuid,
  p_global_lease_token uuid,p_route_lease_token uuid,p_global_fence_token bigint,
  p_ttl_seconds integer
) returns table(outcome text,target_slot text,maintenance_selector text,candidate_selector text,reserved_workshops uuid[])
language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_global control.deployment_driver_resource_leases%rowtype;
  v_operation control.deployment_driver_operations%rowtype; v_snapshot control.fleet_release_route_snapshots%rowtype;
  v_upstream control.operations%rowtype;
  v_run control.release_fleet_runs%rowtype; v_publication control.fleet_release_route_publications%rowtype;
  v_exact integer; v_expires timestamptz; v_active_slot text; v_target_slot text;
begin
  if p_ttl_seconds<60 or p_ttl_seconds>1200 or p_route_lease_token is null then
    return query select 'invalid',null::text,null::text,null::text,null::uuid[]; return;
  end if;
  select * into v_operation from control.deployment_driver_operations where id=p_driver_operation_id;
  if not found or v_operation.control_operation_id is null then
    return query select 'not_found',null::text,null::text,null::text,null::uuid[]; return;
  end if;
  -- Canonical acquisition order: control operation, global authority, route
  -- leases in UUID order, driver operation, snapshot/run, publication.
  select * into v_upstream from control.operations where id=v_operation.control_operation_id for update;
  select * into v_global from control.deployment_driver_resource_leases
   where resource_key='runtime/shared-odoo' for update;
  perform 1 from control.runtime_release_slots slot where slot.runtime_key='shared-odoo'
   order by slot.slot for update;
  select slot.slot into v_active_slot from control.runtime_release_slots slot
   where slot.runtime_key='shared-odoo' and slot.state='active';
  v_target_slot:=case when v_active_slot='blue' then 'green' else 'blue' end;
  perform 1 from control.fleet_release_route_snapshot_items item
    join control.workshop_route_application_leases lease using(workshop_id)
   where item.driver_operation_id=p_driver_operation_id order by item.workshop_id for update of lease;
  select * into v_operation from control.deployment_driver_operations where id=p_driver_operation_id for update;
  select * into v_snapshot from control.fleet_release_route_snapshots where driver_operation_id=p_driver_operation_id for update;
  if not found then return query select 'not_found',null::text,null::text,null::text,null::uuid[]; return; end if;
  select * into v_run from control.release_fleet_runs where id=v_snapshot.fleet_run_id for update;
  select * into v_publication from control.fleet_release_route_publications where driver_operation_id=p_driver_operation_id for update;
  if found then
    if v_publication.original_instance_owner=p_instance_owner
      and v_publication.original_execution_token=p_execution_token
      and v_publication.original_global_lease_token=p_global_lease_token
      and v_publication.original_route_lease_token=p_route_lease_token
      and v_publication.original_global_fence_token=p_global_fence_token then
      if v_publication.phase='quarantined' then
        return query select 'quarantined',v_publication.target_slot,v_publication.maintenance_selector,
          v_publication.candidate_selector,array(select owner.workshop_id from control.fleet_release_route_publication_owners owner
            where owner.driver_operation_id=p_driver_operation_id order by owner.workshop_id); return;
      elsif control.has_immutable_release_route_authority(p_driver_operation_id,p_instance_owner,p_execution_token,
          p_global_lease_token,p_route_lease_token,p_global_fence_token) then
        return query select 'replay',v_publication.target_slot,v_publication.maintenance_selector,
          v_publication.candidate_selector,array(select owner.workshop_id from control.fleet_release_route_publication_owners owner
            where owner.driver_operation_id=p_driver_operation_id order by owner.workshop_id); return;
      end if;
      return query select 'authority_lost',null::text,null::text,null::text,null::uuid[]; return;
    end if;
    return query select 'conflict',null::text,null::text,null::text,null::uuid[]; return;
  end if;
  if v_global.state<>'held' or v_global.authority_kind<>'release'
    or v_global.driver_operation_id is distinct from p_driver_operation_id
    or v_global.lease_owner is distinct from p_instance_owner
    or v_global.lease_token is distinct from p_global_lease_token
    or v_global.fence_token is distinct from p_global_fence_token or v_global.lease_expires_at<=now()
    or v_operation.action<>'release' or v_operation.state<>'in_progress' or v_operation.safe_error is not null
    or v_operation.execution_token is distinct from p_execution_token or v_operation.lease_expires_at<=now()
    or v_operation.release_executor_protocol_version is distinct from 1
    or v_operation.release_route_snapshot_protocol_version is distinct from 2
    or v_operation.control_operation_id is distinct from v_upstream.id
    or v_operation.control_operation_attempt is distinct from v_upstream.attempt
    or v_operation.control_operation_lease_owner is distinct from v_upstream.leased_by
    or v_upstream.kind<>'odoo.release.adopt' or v_upstream.queue<>'release-adoption'
    or v_upstream.workshop_id is not null or v_upstream.state<>'in_flight'
    or v_upstream.lease_expires_at<=now() or v_upstream.payload->>'phase' is distinct from 'adopt'
    or v_snapshot.protocol_version<>2 or v_snapshot.original_global_fence_token<>p_global_fence_token
    or v_run.state<>'preparing' or (v_run.target_slot is not null and v_run.target_slot<>v_target_slot)
    or (v_run.driver_fence_token is not null and v_run.driver_fence_token<>p_global_fence_token)
    or exists(select 1 from control.fleet_activation_intents intent where intent.fleet_run_id=v_run.id)
  then return query select 'authority_lost',null::text,null::text,null::text,null::uuid[]; return; end if;
  if v_run.target_slot is null or v_run.driver_fence_token is null then
    update control.release_fleet_runs run_update
      set target_slot=coalesce(run_update.target_slot,v_target_slot),
      driver_fence_token=coalesce(run_update.driver_fence_token,p_global_fence_token),updated_at=now()
     where run_update.id=v_run.id and run_update.state='preparing'
      and (run_update.target_slot is null or run_update.target_slot=v_target_slot)
      and (run_update.driver_fence_token is null or run_update.driver_fence_token=p_global_fence_token);
    if not found then raise exception 'release target slot binding drifted' using errcode='40001'; end if;
    v_run.target_slot:=v_target_slot;
    v_run.driver_fence_token:=p_global_fence_token;
  end if;
  select count(*) into v_exact
  from control.fleet_release_route_snapshot_items item
  join control.workshop_route_projection_state state on state.workshop_id=item.workshop_id
  join control.workshop_route_application_leases lease on lease.workshop_id=item.workshop_id
  where item.driver_operation_id=p_driver_operation_id
    and state.applied_generation=item.generation and state.applied_digest=item.projection_digest
    and state.applied_disposition='present' and state.applied_rendered_digest=item.applied_rendered_digest
    and state.applied_fence_token=item.applied_fence_token
    and state.desired_generation=item.generation and state.desired_digest=item.projection_digest
    and state.desired_disposition='present'
    and lease.state='idle' and not lease.initialization_required
    and lease.fence_token=item.route_fence_token;
  if v_exact<>v_snapshot.snapshot_count then
    return query select 'route_drift',null::text,null::text,null::text,null::uuid[]; return;
  end if;
  insert into control.fleet_release_route_publications(
    driver_operation_id,fleet_run_id,protocol_version,original_instance_owner,
    original_execution_token,original_global_lease_token,original_route_lease_token,
    original_global_fence_token,control_operation_id,control_operation_attempt,
    control_operation_lease_owner,target_slot,snapshot_count,phase,maintenance_selector,candidate_selector)
  values(p_driver_operation_id,v_run.id,1,p_instance_owner,p_execution_token,p_global_lease_token,
    p_route_lease_token,p_global_fence_token,v_upstream.id,v_upstream.attempt,v_upstream.leased_by,
    v_run.target_slot,v_snapshot.snapshot_count,'maintenance_staging',
    'generations/release-'||replace(v_run.id::text,'-','')||'-maintenance',
    'generations/release-'||replace(v_run.id::text,'-','')||'-candidate');
  insert into control.fleet_release_route_publication_owners(
    driver_operation_id,workshop_id,generation,projection_digest,applied_rendered_digest,
    applied_fence_token,snapshot_route_fence_token,route_fence_token)
  select p_driver_operation_id,item.workshop_id,item.generation,item.projection_digest,
    item.applied_rendered_digest,item.applied_fence_token,item.route_fence_token,item.route_fence_token+1
  from control.fleet_release_route_snapshot_items item where item.driver_operation_id=p_driver_operation_id
  order by item.workshop_id;
  v_expires:=now()+make_interval(secs=>p_ttl_seconds);
  update control.workshop_route_application_leases lease set state='held',authority_kind='release-overlay',
    release_publication_id=p_driver_operation_id,generation=owner.generation,
    projection_digest=owner.projection_digest,fence_token=owner.route_fence_token,
    lease_owner=p_instance_owner,lease_token=p_route_lease_token,lease_expires_at=v_expires,
    heartbeat_at=now(),updated_at=now()
  from control.fleet_release_route_publication_owners owner
  where owner.driver_operation_id=p_driver_operation_id and owner.workshop_id=lease.workshop_id;
  get diagnostics v_exact=row_count;
  if v_exact<>v_snapshot.snapshot_count then raise exception 'release route reservation cardinality drifted' using errcode='40001'; end if;
  return query select 'acquired',v_run.target_slot,
    'generations/release-'||replace(v_run.id::text,'-','')||'-maintenance',
    'generations/release-'||replace(v_run.id::text,'-','')||'-candidate',
    array(select item.workshop_id from control.fleet_release_route_snapshot_items item
      where item.driver_operation_id=p_driver_operation_id order by item.workshop_id);
end $function$;

create function control.renew_immutable_release_route_publication(
 p_driver_operation_id uuid,p_instance_owner uuid,p_execution_token uuid,
 p_global_lease_token uuid,p_route_lease_token uuid,p_global_fence_token bigint,p_ttl_seconds integer
) returns boolean language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_expected integer; v_exact integer; v_changed integer; v_expires timestamptz;
begin
 if p_ttl_seconds<60 or p_ttl_seconds>1200 then return false; end if;
 if not control.lock_immutable_release_route_authority(p_driver_operation_id,p_instance_owner,p_execution_token,
  p_global_lease_token,p_route_lease_token,p_global_fence_token) then return false; end if;
 select snapshot_count into v_expected from control.fleet_release_route_publications publication
 join control.deployment_driver_operations operation on operation.id=publication.driver_operation_id
 join control.operations upstream on upstream.id=publication.control_operation_id
 join control.deployment_driver_resource_leases global_lease on global_lease.resource_key='runtime/shared-odoo'
 where publication.driver_operation_id=p_driver_operation_id and publication.phase<>'quarantined'
  and publication.original_instance_owner=p_instance_owner and publication.original_execution_token=p_execution_token
  and publication.original_global_lease_token=p_global_lease_token and publication.original_route_lease_token=p_route_lease_token
  and publication.original_global_fence_token=p_global_fence_token
  and upstream.state='in_flight' and upstream.attempt=publication.control_operation_attempt
  and upstream.leased_by=publication.control_operation_lease_owner and upstream.lease_expires_at>now()
  and operation.state='in_progress' and operation.safe_error is null and operation.execution_token=p_execution_token and operation.lease_expires_at>now()
  and global_lease.state='held' and global_lease.authority_kind='release' and global_lease.driver_operation_id=p_driver_operation_id
  and global_lease.lease_owner=p_instance_owner and global_lease.lease_token=p_global_lease_token
  and global_lease.fence_token=p_global_fence_token and global_lease.lease_expires_at>now();
 if not found then return false; end if;
 select count(*) into v_exact from control.fleet_release_route_publication_owners owner
 join control.workshop_route_application_leases lease using(workshop_id)
 where owner.driver_operation_id=p_driver_operation_id and lease.state='held' and lease.authority_kind='release-overlay'
  and lease.release_publication_id=p_driver_operation_id and lease.generation=owner.generation
  and lease.projection_digest=owner.projection_digest and lease.fence_token=owner.route_fence_token
  and lease.lease_owner=p_instance_owner and lease.lease_token=p_route_lease_token and lease.lease_expires_at>now();
 if v_exact<>v_expected then return false; end if;
 v_expires:=now()+make_interval(secs=>p_ttl_seconds);
 update control.deployment_driver_resource_leases set lease_expires_at=v_expires,heartbeat_at=now(),updated_at=now()
  where resource_key='runtime/shared-odoo'; get diagnostics v_changed=row_count;
 if v_changed<>1 then raise exception 'release global renewal drifted' using errcode='40001'; end if;
 update control.deployment_driver_operations set lease_expires_at=v_expires,updated_at=now() where id=p_driver_operation_id;
 get diagnostics v_changed=row_count;
 if v_changed<>1 then raise exception 'release operation renewal drifted' using errcode='40001'; end if;
 update control.workshop_route_application_leases lease set lease_expires_at=v_expires,heartbeat_at=now(),updated_at=now()
  from control.fleet_release_route_publication_owners owner where owner.driver_operation_id=p_driver_operation_id and owner.workshop_id=lease.workshop_id;
 get diagnostics v_changed=row_count; if v_changed<>v_expected then raise exception 'release route renewal drifted' using errcode='40001'; end if;
 return true;
end $function$;

create function control.has_immutable_release_route_authority(
 p_driver_operation_id uuid,p_instance_owner uuid,p_execution_token uuid,
 p_global_lease_token uuid,p_route_lease_token uuid,p_global_fence_token bigint
) returns boolean language sql stable security definer set search_path=pg_catalog,control as $function$
 select exists(select 1 from control.fleet_release_route_publications publication
 join control.deployment_driver_operations operation on operation.id=publication.driver_operation_id
 join control.operations upstream on upstream.id=publication.control_operation_id
 join control.deployment_driver_resource_leases global_lease on global_lease.resource_key='runtime/shared-odoo'
 where publication.driver_operation_id=p_driver_operation_id and publication.phase<>'quarantined'
 and publication.original_instance_owner=p_instance_owner and publication.original_execution_token=p_execution_token
 and publication.original_global_lease_token=p_global_lease_token and publication.original_route_lease_token=p_route_lease_token
 and publication.original_global_fence_token=p_global_fence_token
 and operation.control_operation_id=publication.control_operation_id
 and operation.control_operation_attempt=publication.control_operation_attempt
 and operation.control_operation_lease_owner=publication.control_operation_lease_owner
 and upstream.kind='odoo.release.adopt' and upstream.queue='release-adoption'
 and upstream.workshop_id is null and upstream.state='in_flight'
 and upstream.payload->>'phase'='adopt'
 and upstream.attempt=publication.control_operation_attempt
 and upstream.leased_by=publication.control_operation_lease_owner
 and upstream.lease_expires_at>now()
 and operation.state='in_progress' and operation.safe_error is null and operation.execution_token=p_execution_token and operation.lease_expires_at>now()
 and global_lease.state='held' and global_lease.authority_kind='release' and global_lease.driver_operation_id=p_driver_operation_id
 and global_lease.lease_owner=p_instance_owner and global_lease.lease_token=p_global_lease_token
 and global_lease.fence_token=p_global_fence_token and global_lease.lease_expires_at>now()
 and (select count(*) from control.fleet_release_route_publication_owners owner
  join control.workshop_route_application_leases route_lease using(workshop_id)
  where owner.driver_operation_id=p_driver_operation_id and route_lease.state='held'
  and route_lease.authority_kind='release-overlay' and route_lease.release_publication_id=p_driver_operation_id
  and route_lease.generation=owner.generation and route_lease.projection_digest=owner.projection_digest
  and route_lease.fence_token=owner.route_fence_token and route_lease.lease_owner=p_instance_owner
  and route_lease.lease_token=p_route_lease_token and route_lease.lease_expires_at>now())=publication.snapshot_count)
$function$;

create function control.lock_immutable_release_route_authority(
 p_driver_operation_id uuid,p_instance_owner uuid,p_execution_token uuid,
 p_global_lease_token uuid,p_route_lease_token uuid,p_global_fence_token bigint
) returns boolean language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_control_operation_id uuid;
begin
 select publication.control_operation_id into v_control_operation_id
 from control.fleet_release_route_publications publication
 where publication.driver_operation_id=p_driver_operation_id;
 if not found then return false; end if;
 perform 1 from control.operations upstream where upstream.id=v_control_operation_id for update;
 perform 1 from control.deployment_driver_resource_leases global_lease
  where global_lease.resource_key='runtime/shared-odoo' for update;
 perform 1 from control.fleet_release_route_publication_owners owner
 join control.workshop_route_application_leases route_lease using(workshop_id)
 where owner.driver_operation_id=p_driver_operation_id order by owner.workshop_id for update of route_lease;
 perform 1 from control.deployment_driver_operations operation where operation.id=p_driver_operation_id for update;
 perform 1 from control.fleet_release_route_publications publication
  where publication.driver_operation_id=p_driver_operation_id for update;
 return control.has_immutable_release_route_authority(p_driver_operation_id,p_instance_owner,p_execution_token,
  p_global_lease_token,p_route_lease_token,p_global_fence_token);
end $function$;

create function control.record_immutable_release_route_prior(
 p_driver_operation_id uuid,p_instance_owner uuid,p_execution_token uuid,
 p_global_lease_token uuid,p_route_lease_token uuid,p_global_fence_token bigint,
 p_prior_selector text,p_prior_directory_device bigint,p_prior_directory_inode bigint,p_prior_loaded_identity jsonb
) returns text language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_row control.fleet_release_route_publications%rowtype;
begin
 if not control.lock_immutable_release_route_authority(p_driver_operation_id,p_instance_owner,p_execution_token,
   p_global_lease_token,p_route_lease_token,p_global_fence_token) then return 'authority_lost'; end if;
 select * into v_row from control.fleet_release_route_publications
  where driver_operation_id=p_driver_operation_id for update;
 if v_row.phase<>'maintenance_staging' then return 'wrong_phase'; end if;
 if v_row.prior_recorded_at is not null then
   if v_row.prior_selector=p_prior_selector and v_row.prior_directory_device=p_prior_directory_device and v_row.prior_directory_inode=p_prior_directory_inode
     and v_row.prior_loaded_identity is not distinct from p_prior_loaded_identity then return 'replay'; end if;
   return 'conflict';
 end if;
 if p_prior_selector is null or p_prior_selector !~ '^generations/[A-Za-z0-9][A-Za-z0-9-]{0,63}$'
   or p_prior_directory_device<=0 or p_prior_directory_inode<=0
   or p_prior_selector in (v_row.maintenance_selector,v_row.candidate_selector)
   or not control.valid_release_route_loaded_identity(p_prior_loaded_identity)
   or not ((p_prior_selector='generations/boot-live' and p_prior_loaded_identity is null)
    or (p_prior_loaded_identity is not null and (
      (p_prior_loaded_identity ? 'effect_run_id'
       and p_prior_selector='generations/startup-'||(p_prior_loaded_identity->>'effect_run_id'))
      or (p_prior_loaded_identity ? 'fleet_run_id'
       and p_prior_selector='generations/release-'||replace(p_prior_loaded_identity->>'fleet_run_id','-','')
         ||'-'||(p_prior_loaded_identity->>'overlay_kind'))))) then return 'invalid'; end if;
 update control.fleet_release_route_publications set prior_selector=p_prior_selector,
  prior_directory_device=p_prior_directory_device,prior_directory_inode=p_prior_directory_inode,
  prior_loaded_identity=p_prior_loaded_identity,prior_recorded_at=now(),updated_at=now() where driver_operation_id=p_driver_operation_id;
 return 'recorded';
end $function$;

create function control.read_immutable_release_route_snapshot_batch(
 p_driver_operation_id uuid,p_instance_owner uuid,p_execution_token uuid,
 p_global_lease_token uuid,p_route_lease_token uuid,p_global_fence_token bigint,
 p_after_workshop_id uuid,p_limit integer
) returns table(workshop_id uuid,database_id uuid,database_ref text,paperless_enabled boolean,
 generation bigint,projection_digest text,canonical_projection jsonb,applied_rendered_digest text,
 applied_fence_token bigint,route_fence_token bigint,target_slot text)
language plpgsql security definer set search_path=pg_catalog,control as $function$
begin
 if p_limit<1 or p_limit>500 then return; end if;
 if not control.lock_immutable_release_route_authority(p_driver_operation_id,p_instance_owner,p_execution_token,
  p_global_lease_token,p_route_lease_token,p_global_fence_token) then return; end if;
 return query select item.workshop_id,item.database_id,item.database_ref,item.paperless_enabled,
  item.generation,item.projection_digest,item.canonical_projection,item.applied_rendered_digest,
  item.applied_fence_token,owner.route_fence_token,publication.target_slot
 from control.fleet_release_route_snapshot_items item
 join control.fleet_release_route_publication_owners owner using(driver_operation_id,workshop_id)
 join control.fleet_release_route_publications publication using(driver_operation_id)
 where item.driver_operation_id=p_driver_operation_id and (p_after_workshop_id is null or item.workshop_id>p_after_workshop_id)
 order by item.workshop_id limit p_limit;
end $function$;

create function control.record_immutable_release_route_candidate(
 p_driver_operation_id uuid,p_instance_owner uuid,p_execution_token uuid,
 p_global_lease_token uuid,p_route_lease_token uuid,p_global_fence_token bigint,
 p_overlay_kind text,p_workshop_id uuid,p_generation bigint,p_projection_digest text,
 p_applied_rendered_digest text,p_rendered_digest text
) returns text language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_publication control.fleet_release_route_publications%rowtype; v_existing record; v_expected uuid;
begin
 if p_overlay_kind not in ('maintenance','candidate') or p_rendered_digest !~ '^sha256:[0-9a-f]{64}$' then return 'invalid'; end if;
 if not control.lock_immutable_release_route_authority(p_driver_operation_id,p_instance_owner,p_execution_token,
      p_global_lease_token,p_route_lease_token,p_global_fence_token) then return 'authority_lost'; end if;
 select * into v_publication from control.fleet_release_route_publications where driver_operation_id=p_driver_operation_id for update;
 if not found or (p_overlay_kind='maintenance' and v_publication.phase<>'maintenance_staging')
  or (p_overlay_kind='candidate' and v_publication.phase<>'candidate_staging') then return 'wrong_phase'; end if;
 select * into v_existing from control.fleet_release_route_publication_records where driver_operation_id=p_driver_operation_id
   and overlay_kind=p_overlay_kind and workshop_id=p_workshop_id;
 if found then
  if v_existing.generation=p_generation and v_existing.projection_digest=p_projection_digest
   and v_existing.applied_rendered_digest=p_applied_rendered_digest and v_existing.rendered_digest=p_rendered_digest then return 'replay'; end if;
  return 'conflict';
 end if;
 select owner.workshop_id into v_expected from control.fleet_release_route_publication_owners owner
 where owner.driver_operation_id=p_driver_operation_id and not exists(select 1 from control.fleet_release_route_publication_records record
  where record.driver_operation_id=owner.driver_operation_id and record.overlay_kind=p_overlay_kind and record.workshop_id=owner.workshop_id)
 order by owner.workshop_id limit 1;
 if v_expected is distinct from p_workshop_id then return 'out_of_order'; end if;
 if not exists(select 1 from control.fleet_release_route_publication_owners owner
   where owner.driver_operation_id=p_driver_operation_id and owner.workshop_id=p_workshop_id
   and owner.generation=p_generation and owner.projection_digest=p_projection_digest
   and owner.applied_rendered_digest=p_applied_rendered_digest) then return 'snapshot_drift'; end if;
 insert into control.fleet_release_route_publication_records(driver_operation_id,overlay_kind,workshop_id,
  generation,projection_digest,applied_rendered_digest,rendered_digest)
 values(p_driver_operation_id,p_overlay_kind,p_workshop_id,p_generation,p_projection_digest,p_applied_rendered_digest,p_rendered_digest);
 if p_overlay_kind='maintenance' then update control.fleet_release_route_publications set maintenance_count=maintenance_count+1,updated_at=now()
  where driver_operation_id=p_driver_operation_id;
 else update control.fleet_release_route_publications set candidate_count=candidate_count+1,updated_at=now()
  where driver_operation_id=p_driver_operation_id; end if;
 return 'recorded';
end $function$;

create function control.seal_immutable_release_route_overlay(
 p_driver_operation_id uuid,p_instance_owner uuid,p_execution_token uuid,
 p_global_lease_token uuid,p_route_lease_token uuid,p_global_fence_token bigint,
 p_overlay_kind text,p_selector text,p_directory_device bigint,p_directory_inode bigint,
 p_record_count integer,p_route_set_digest text
) returns text language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_row control.fleet_release_route_publications%rowtype; v_digest text;
begin
 if not control.lock_immutable_release_route_authority(p_driver_operation_id,p_instance_owner,p_execution_token,
   p_global_lease_token,p_route_lease_token,p_global_fence_token) then return 'authority_lost'; end if;
 select * into v_row from control.fleet_release_route_publications where driver_operation_id=p_driver_operation_id for update;
 if not found then return 'not_found'; end if;
 if p_overlay_kind='maintenance' and v_row.phase<>'maintenance_staging' then
  if v_row.maintenance_sealed_count=p_record_count and v_row.maintenance_route_set_digest=p_route_set_digest
    and v_row.maintenance_selector=p_selector and v_row.maintenance_directory_device=p_directory_device
    and v_row.maintenance_directory_inode=p_directory_inode then return 'replay'; end if;
  return 'wrong_phase';
 elsif p_overlay_kind='candidate' and v_row.phase<>'candidate_staging' then
  if v_row.candidate_sealed_count=p_record_count and v_row.candidate_route_set_digest=p_route_set_digest
    and v_row.candidate_selector=p_selector and v_row.candidate_directory_device=p_directory_device
    and v_row.candidate_directory_inode=p_directory_inode then return 'replay'; end if;
  return 'wrong_phase';
 elsif p_overlay_kind not in ('maintenance','candidate') then return 'invalid'; end if;
 if p_directory_device<=0 or p_directory_inode<=0 or p_record_count<>v_row.snapshot_count
   or p_selector<>(case when p_overlay_kind='maintenance' then v_row.maintenance_selector else v_row.candidate_selector end) then return 'invalid'; end if;
 if v_row.prior_recorded_at is null then return 'prior_absent'; end if;
 select control.release_route_overlay_digest(p_driver_operation_id,p_overlay_kind) into v_digest;
 if v_digest is distinct from p_route_set_digest then return 'digest_mismatch'; end if;
 if p_overlay_kind='maintenance' and v_row.maintenance_count<>p_record_count then return 'count_mismatch'; end if;
 if p_overlay_kind='candidate' and v_row.candidate_count<>p_record_count then return 'count_mismatch'; end if;
 if p_overlay_kind='maintenance' then update control.fleet_release_route_publications set
   maintenance_sealed_count=p_record_count,maintenance_route_set_digest=p_route_set_digest,
   maintenance_directory_device=p_directory_device,maintenance_directory_inode=p_directory_inode,
   phase='maintenance_sealed',updated_at=now() where driver_operation_id=p_driver_operation_id;
 else update control.fleet_release_route_publications set candidate_sealed_count=p_record_count,
   candidate_route_set_digest=p_route_set_digest,candidate_directory_device=p_directory_device,
   candidate_directory_inode=p_directory_inode,phase='candidate_sealed',updated_at=now()
   where driver_operation_id=p_driver_operation_id; end if;
 return 'sealed';
end $function$;

create function control.start_immutable_release_route_publication(
 p_driver_operation_id uuid,p_instance_owner uuid,p_execution_token uuid,
 p_global_lease_token uuid,p_route_lease_token uuid,p_global_fence_token bigint,p_overlay_kind text
) returns text language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_phase text;
begin
 if not control.lock_immutable_release_route_authority(p_driver_operation_id,p_instance_owner,p_execution_token,
  p_global_lease_token,p_route_lease_token,p_global_fence_token) then return 'authority_lost'; end if;
 select phase into v_phase from control.fleet_release_route_publications where driver_operation_id=p_driver_operation_id for update;
 if not found then return 'not_found'; end if;
 if (p_overlay_kind='maintenance' and v_phase='maintenance_publication_started')
   or (p_overlay_kind='candidate' and v_phase='candidate_publication_started') then return 'replay'; end if;
 if p_overlay_kind='maintenance' and v_phase='maintenance_sealed' then
  update control.fleet_release_route_publications set phase='maintenance_publication_started',maintenance_publication_started_at=now(),updated_at=now()
   where driver_operation_id=p_driver_operation_id; return 'started';
 elsif p_overlay_kind='candidate' and v_phase='candidate_sealed' then
  update control.fleet_release_route_publications set phase='candidate_publication_started',candidate_publication_started_at=now(),updated_at=now()
   where driver_operation_id=p_driver_operation_id; return 'started';
 end if; return 'wrong_phase';
end $function$;

create function control.observe_immutable_release_route_publication(
 p_driver_operation_id uuid,p_instance_owner uuid,p_execution_token uuid,
 p_global_lease_token uuid,p_route_lease_token uuid,p_global_fence_token bigint,p_overlay_kind text,
 p_protocol_version smallint,p_fleet_run_id uuid,p_identity_driver_operation_id uuid,
 p_identity_original_global_fence_token bigint,p_identity_overlay_kind text,
 p_identity_route_set_digest text,p_identity_target_slot text,p_observed_selector text,
 p_observed_directory_device bigint,p_observed_directory_inode bigint
) returns text language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_row control.fleet_release_route_publications%rowtype; v_changed integer;
begin
 if not control.lock_immutable_release_route_authority(p_driver_operation_id,p_instance_owner,p_execution_token,
  p_global_lease_token,p_route_lease_token,p_global_fence_token) then return 'authority_lost'; end if;
 select * into v_row from control.fleet_release_route_publications where driver_operation_id=p_driver_operation_id for update;
 if not found then return 'not_found'; end if;
 if p_protocol_version<>1 or p_fleet_run_id<>v_row.fleet_run_id or p_identity_driver_operation_id<>p_driver_operation_id
   or p_identity_original_global_fence_token<>v_row.original_global_fence_token or p_identity_overlay_kind<>p_overlay_kind
   or p_identity_target_slot<>v_row.target_slot then return 'identity_mismatch'; end if;
 if p_overlay_kind='maintenance' then
  if p_identity_route_set_digest<>v_row.maintenance_route_set_digest
   or p_observed_selector<>v_row.maintenance_selector or p_observed_directory_device<>v_row.maintenance_directory_device
   or p_observed_directory_inode<>v_row.maintenance_directory_inode then return 'observation_mismatch'; end if;
  if v_row.phase='maintenance_observed' then return 'replay'; end if;
  if v_row.phase<>'maintenance_publication_started' then return 'wrong_phase'; end if;
  update control.fleet_release_route_publications set phase='maintenance_observed',maintenance_observed_at=now(),updated_at=now()
   where driver_operation_id=p_driver_operation_id; return 'observed';
 elsif p_overlay_kind='candidate' then
  if p_identity_route_set_digest<>v_row.candidate_route_set_digest
   or p_observed_selector<>v_row.candidate_selector or p_observed_directory_device<>v_row.candidate_directory_device
   or p_observed_directory_inode<>v_row.candidate_directory_inode then return 'observation_mismatch'; end if;
  if v_row.phase='awaiting_worker_finalize' then return 'replay'; end if;
  if v_row.phase<>'candidate_publication_started' then return 'wrong_phase'; end if;
  -- Candidate observation advances exactly the frozen heads under the newly
  -- acquired per-route fences.  Authority remains held for worker finalization.
  update control.workshop_route_projection_state state set
    applied_rendered_digest=record.rendered_digest,applied_driver_operation_id=p_driver_operation_id,
    applied_effect_run_id=null,applied_fence_token=owner.route_fence_token,updated_at=now()
  from control.fleet_release_route_publication_owners owner
  join control.fleet_release_route_publication_records record
    on record.driver_operation_id=owner.driver_operation_id and record.workshop_id=owner.workshop_id
   and record.overlay_kind='candidate'
  where owner.driver_operation_id=p_driver_operation_id and state.workshop_id=owner.workshop_id
   and state.applied_generation=owner.generation and state.applied_digest=owner.projection_digest
   and state.applied_disposition='present' and state.applied_rendered_digest=owner.applied_rendered_digest
   and state.applied_fence_token=owner.applied_fence_token
   and state.desired_generation=owner.generation and state.desired_digest=owner.projection_digest
   and state.desired_disposition='present';
  get diagnostics v_changed=row_count;
  if v_changed<>v_row.snapshot_count then raise exception 'candidate route head advancement drifted' using errcode='40001'; end if;
  update control.fleet_release_route_publications set phase='awaiting_worker_finalize',candidate_observed_at=now(),updated_at=now()
   where driver_operation_id=p_driver_operation_id; return 'observed';
 end if; return 'invalid';
end $function$;

create function control.begin_immutable_release_external_effects(
 p_driver_operation_id uuid,p_instance_owner uuid,p_execution_token uuid,
 p_global_lease_token uuid,p_route_lease_token uuid,p_global_fence_token bigint
) returns text language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_phase text;
begin
 if not control.lock_immutable_release_route_authority(p_driver_operation_id,p_instance_owner,p_execution_token,
  p_global_lease_token,p_route_lease_token,p_global_fence_token) then return 'authority_lost'; end if;
 select phase into v_phase from control.fleet_release_route_publications where driver_operation_id=p_driver_operation_id for update;
 if v_phase='candidate_staging' then return 'replay'; end if;
 if v_phase is distinct from 'maintenance_observed' then return 'wrong_phase'; end if;
 update control.fleet_release_route_publications set phase='candidate_staging',external_effects_started_at=now(),updated_at=now()
 where driver_operation_id=p_driver_operation_id; return 'started';
end $function$;

create function control.quarantine_immutable_release_route_publication(
 p_driver_operation_id uuid,p_instance_owner uuid,p_execution_token uuid,
 p_global_lease_token uuid,p_route_lease_token uuid,p_global_fence_token bigint,
 p_safe_error text
) returns boolean language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_row control.fleet_release_route_publications%rowtype; v_global control.deployment_driver_resource_leases%rowtype;
 v_operation control.deployment_driver_operations%rowtype; v_control_operation_id uuid;
 v_expected integer; v_exact integer; v_changed integer; v_expired boolean;
begin
 if p_safe_error<>'release_route_publication_outcome_unknown' then return false; end if;
 select publication.control_operation_id into v_control_operation_id
 from control.fleet_release_route_publications publication where publication.driver_operation_id=p_driver_operation_id;
 if not found then return false; end if;
 perform 1 from control.operations upstream where upstream.id=v_control_operation_id for update;
 select * into v_global from control.deployment_driver_resource_leases where resource_key='runtime/shared-odoo' for update;
 perform 1 from control.fleet_release_route_publication_owners owner join control.workshop_route_application_leases lease using(workshop_id)
  where owner.driver_operation_id=p_driver_operation_id order by owner.workshop_id for update of lease;
 select * into v_operation from control.deployment_driver_operations where id=p_driver_operation_id for update;
 select * into v_row from control.fleet_release_route_publications where driver_operation_id=p_driver_operation_id for update;
 if not found then return false; end if;
 if v_row.original_instance_owner<>p_instance_owner or v_row.original_execution_token<>p_execution_token
  or v_row.original_global_lease_token<>p_global_lease_token or v_row.original_route_lease_token<>p_route_lease_token
  or v_row.original_global_fence_token<>p_global_fence_token then return false; end if;
 select count(*) into v_expected from control.fleet_release_route_publication_owners where driver_operation_id=p_driver_operation_id;
 if v_row.phase='quarantined' then
  select count(*) into v_exact from control.fleet_release_route_publication_owners owner
   join control.workshop_route_application_leases lease using(workshop_id)
   where owner.driver_operation_id=p_driver_operation_id and lease.state='quarantined'
    and lease.authority_kind='release-overlay' and lease.release_publication_id=p_driver_operation_id
    and lease.generation=owner.generation and lease.projection_digest=owner.projection_digest
    and lease.fence_token=owner.route_fence_token and lease.lease_owner=p_instance_owner
    and lease.lease_token is null and lease.safe_error='release_route_publication_outcome_unknown';
  return v_exact=v_expected and v_global.state='quarantined' and v_global.authority_kind='release'
   and v_global.driver_operation_id=p_driver_operation_id and v_global.lease_owner=p_instance_owner
   and v_global.fence_token=p_global_fence_token and v_operation.state='in_progress'
   and v_operation.safe_error='runtime_outcome_unknown';
 end if;
 if v_global.state<>'held' or v_global.authority_kind<>'release' or v_global.driver_operation_id<>p_driver_operation_id
  or v_global.lease_owner<>p_instance_owner or v_global.lease_token<>p_global_lease_token or v_global.fence_token<>p_global_fence_token
  or v_operation.state<>'in_progress' or v_operation.execution_token<>p_execution_token then return false; end if;
 select count(*) into v_exact from control.fleet_release_route_publication_owners owner
 join control.workshop_route_application_leases lease using(workshop_id)
 where owner.driver_operation_id=p_driver_operation_id and lease.state='held'
  and lease.authority_kind='release-overlay' and lease.release_publication_id=p_driver_operation_id
  and lease.generation=owner.generation and lease.projection_digest=owner.projection_digest
  and lease.fence_token=owner.route_fence_token and lease.lease_owner=p_instance_owner
  and lease.lease_token=p_route_lease_token;
 if v_exact<>v_expected then return false; end if;
 select v_global.lease_expires_at<=now() or v_operation.lease_expires_at<=now() or exists(
  select 1 from control.fleet_release_route_publication_owners owner join control.workshop_route_application_leases lease using(workshop_id)
  where owner.driver_operation_id=p_driver_operation_id and lease.lease_expires_at<=now()) into v_expired;
 if not v_expired and v_row.phase not in ('maintenance_publication_started','maintenance_observed',
   'candidate_staging','candidate_sealed','candidate_publication_started','awaiting_worker_finalize') then return false; end if;
 update control.deployment_driver_operations set safe_error='runtime_outcome_unknown',execution_token=null,
  lease_expires_at=null,updated_at=now() where id=p_driver_operation_id and state='in_progress'
  and execution_token=p_execution_token; get diagnostics v_changed=row_count;
 if v_changed<>1 then raise exception 'release operation quarantine drifted' using errcode='40001'; end if;
 update control.deployment_driver_resource_leases set state='quarantined',lease_token=null,lease_expires_at=null,
  quarantined_at=now(),safe_error='runtime_outcome_unknown',updated_at=now() where resource_key='runtime/shared-odoo'
  and state='held' and authority_kind='release' and driver_operation_id=p_driver_operation_id
  and lease_owner=p_instance_owner and lease_token=p_global_lease_token and fence_token=p_global_fence_token;
 get diagnostics v_changed=row_count;
 if v_changed<>1 then raise exception 'release global quarantine drifted' using errcode='40001'; end if;
 update control.workshop_route_application_leases lease set state='quarantined',lease_token=null,lease_expires_at=null,
  quarantined_at=now(),safe_error='release_route_publication_outcome_unknown',updated_at=now()
 from control.fleet_release_route_publication_owners owner
 where owner.driver_operation_id=p_driver_operation_id and owner.workshop_id=lease.workshop_id
  and lease.state='held' and lease.authority_kind='release-overlay'
  and lease.release_publication_id=p_driver_operation_id and lease.generation=owner.generation
  and lease.projection_digest=owner.projection_digest and lease.fence_token=owner.route_fence_token
  and lease.lease_owner=p_instance_owner and lease.lease_token=p_route_lease_token;
 get diagnostics v_changed=row_count;
 if v_changed<>v_expected then raise exception 'release route quarantine cardinality drifted' using errcode='40001'; end if;
 update control.fleet_release_route_publications set interrupted_phase=phase,phase='quarantined',quarantined_at=now(),
  safe_error=p_safe_error,updated_at=now() where driver_operation_id=p_driver_operation_id;
 return true;
end $function$;

-- Guard every legacy whole-operation close/reconciliation surface.  Renamed
-- primitives retain their ACL in PostgreSQL, so revoke them from all runtime
-- roles before installing wrappers under the old signatures.
alter function control.finish_release_driver_operation(uuid,uuid,uuid,uuid,bigint,text,jsonb,text)
 rename to finish_release_driver_operation_pre_route_publication;
alter function control.renew_release_driver_lease(uuid,uuid,integer,text,uuid,uuid,uuid,bigint,integer)
 rename to renew_release_driver_lease_pre_route_publication;
alter function control.admit_fleet_release_reconciliation(uuid,integer,text,text,text,uuid,text,uuid,uuid,integer)
 rename to admit_fleet_release_reconciliation_pre_route_publication;
alter function control.finish_fleet_release_reconciliation(uuid,uuid,uuid,text,jsonb)
 rename to finish_fleet_release_reconciliation_pre_route_publication;

create function control.finish_release_driver_operation(
 p_driver_operation_id uuid,p_instance_owner uuid,p_execution_token uuid,p_resource_lease_token uuid,
 p_fence_token bigint,p_outcome text,p_response jsonb,p_safe_error text
) returns boolean language plpgsql security definer set search_path=pg_catalog,control as $function$
begin
 perform 1 from control.deployment_driver_resource_leases where resource_key='runtime/shared-odoo' for update;
 perform 1 from control.deployment_driver_operations where id=p_driver_operation_id for update;
 if exists(select 1 from control.deployment_driver_operations operation where operation.id=p_driver_operation_id
   and operation.release_route_snapshot_protocol_version=2) then return false; end if;
 return control.finish_release_driver_operation_pre_route_publication(p_driver_operation_id,p_instance_owner,
  p_execution_token,p_resource_lease_token,p_fence_token,p_outcome,p_response,p_safe_error);
end $function$;

create function control.renew_release_driver_lease(
 p_driver_operation_id uuid,p_control_operation_id uuid,p_control_operation_attempt integer,
 p_control_operation_lease_owner text,p_instance_owner uuid,p_execution_token uuid,
 p_resource_lease_token uuid,p_fence_token bigint,p_ttl_seconds integer
) returns boolean language plpgsql security definer set search_path=pg_catalog,control as $function$
begin
 perform 1 from control.operations where id=p_control_operation_id for update;
 perform 1 from control.deployment_driver_resource_leases where resource_key='runtime/shared-odoo' for update;
 perform 1 from control.deployment_driver_operations where id=p_driver_operation_id for update;
 if exists(select 1 from control.deployment_driver_operations operation where operation.id=p_driver_operation_id
  and operation.release_route_snapshot_protocol_version=2) then return false; end if;
 return control.renew_release_driver_lease_pre_route_publication(p_driver_operation_id,p_control_operation_id,
  p_control_operation_attempt,p_control_operation_lease_owner,p_instance_owner,p_execution_token,
  p_resource_lease_token,p_fence_token,p_ttl_seconds);
end $function$;

create function control.admit_fleet_release_reconciliation(
 p_control_operation_id uuid,p_control_operation_attempt integer,p_control_operation_lease_owner text,
 p_idempotency_key text,p_target_key text,p_fleet_run_id uuid,p_request_digest text,
 p_instance_owner uuid,p_execution_token uuid,p_ttl_seconds integer
) returns table(outcome text,reconciliation_id uuid,driver_operation_id uuid,original_fence_token bigint,
 activation_identity jsonb,stored_response jsonb)
language plpgsql security definer set search_path=pg_catalog,control as $function$
begin
 perform 1 from control.operations where id=p_control_operation_id for update;
 perform 1 from control.deployment_driver_resource_leases where resource_key='runtime/shared-odoo' for update;
 perform 1 from control.deployment_driver_operations operation
  where operation.id=(select resource.driver_operation_id from control.deployment_driver_resource_leases resource
   where resource.resource_key='runtime/shared-odoo') for update;
 if exists(select 1 from control.deployment_driver_resource_leases resource
  join control.deployment_driver_operations operation on operation.id=resource.driver_operation_id
  where resource.resource_key='runtime/shared-odoo' and operation.release_route_snapshot_protocol_version=2) then
  return query select 'protocol_conflict',null::uuid,operation.id,resource.fence_token,null::jsonb,null::jsonb
   from control.deployment_driver_resource_leases resource join control.deployment_driver_operations operation
   on operation.id=resource.driver_operation_id where resource.resource_key='runtime/shared-odoo'; return;
 end if;
 return query select * from control.admit_fleet_release_reconciliation_pre_route_publication(
  p_control_operation_id,p_control_operation_attempt,p_control_operation_lease_owner,p_idempotency_key,
  p_target_key,p_fleet_run_id,p_request_digest,p_instance_owner,p_execution_token,p_ttl_seconds);
end $function$;

create function control.finish_fleet_release_reconciliation(
 p_reconciliation_id uuid,p_instance_owner uuid,p_execution_token uuid,p_outcome text,p_response jsonb
) returns boolean language plpgsql security definer set search_path=pg_catalog,control as $function$
begin
 perform 1 from control.operations operation where operation.id=(select driver.control_operation_id
  from control.fleet_release_reconciliations reconciliation join control.deployment_driver_operations driver
  on driver.id=reconciliation.driver_operation_id where reconciliation.id=p_reconciliation_id) for update;
 perform 1 from control.deployment_driver_resource_leases where resource_key='runtime/shared-odoo' for update;
 perform 1 from control.deployment_driver_operations operation where operation.id=(select reconciliation.driver_operation_id
  from control.fleet_release_reconciliations reconciliation where reconciliation.id=p_reconciliation_id) for update;
 perform 1 from control.fleet_release_reconciliations where id=p_reconciliation_id for update;
 if exists(select 1 from control.fleet_release_reconciliations reconciliation
  join control.deployment_driver_operations operation on operation.id=reconciliation.driver_operation_id
  where reconciliation.id=p_reconciliation_id and operation.release_route_snapshot_protocol_version=2) then return false; end if;
 return control.finish_fleet_release_reconciliation_pre_route_publication(
  p_reconciliation_id,p_instance_owner,p_execution_token,p_outcome,p_response);
end $function$;

revoke all on table control.fleet_release_route_publications from public;
revoke all on table control.fleet_release_route_publication_owners from public;
revoke all on table control.fleet_release_route_publication_records from public;
revoke all on function control.valid_release_route_loaded_identity(jsonb) from public;
revoke all on function control.reject_release_route_publication_identity_mutation() from public;
revoke all on function control.validate_release_route_publication_update() from public;
revoke all on function control.validate_workshop_route_applied_driver_binding() from public;
revoke all on function control.release_route_overlay_record_bytes(uuid,bigint,text,text,text) from public;
revoke all on function control.release_route_overlay_digest(uuid,text) from public;
revoke all on function control.has_immutable_release_route_authority(uuid,uuid,uuid,uuid,uuid,bigint) from public;
revoke all on function control.lock_immutable_release_route_authority(uuid,uuid,uuid,uuid,uuid,bigint) from public;
revoke all on function control.admit_immutable_release_route_publication(uuid,uuid,uuid,uuid,uuid,bigint,integer) from public;
revoke all on function control.renew_immutable_release_route_publication(uuid,uuid,uuid,uuid,uuid,bigint,integer) from public;
revoke all on function control.record_immutable_release_route_prior(uuid,uuid,uuid,uuid,uuid,bigint,text,bigint,bigint,jsonb) from public;
revoke all on function control.read_immutable_release_route_snapshot_batch(uuid,uuid,uuid,uuid,uuid,bigint,uuid,integer) from public;
revoke all on function control.record_immutable_release_route_candidate(uuid,uuid,uuid,uuid,uuid,bigint,text,uuid,bigint,text,text,text) from public;
revoke all on function control.seal_immutable_release_route_overlay(uuid,uuid,uuid,uuid,uuid,bigint,text,text,bigint,bigint,integer,text) from public;
revoke all on function control.start_immutable_release_route_publication(uuid,uuid,uuid,uuid,uuid,bigint,text) from public;
revoke all on function control.observe_immutable_release_route_publication(uuid,uuid,uuid,uuid,uuid,bigint,text,smallint,uuid,uuid,bigint,text,text,text,text,bigint,bigint) from public;
revoke all on function control.begin_immutable_release_external_effects(uuid,uuid,uuid,uuid,uuid,bigint) from public;
revoke all on function control.quarantine_immutable_release_route_publication(uuid,uuid,uuid,uuid,uuid,bigint,text) from public;
revoke all on function control.finish_release_driver_operation_pre_route_publication(uuid,uuid,uuid,uuid,bigint,text,jsonb,text) from public;
revoke all on function control.renew_release_driver_lease_pre_route_publication(uuid,uuid,integer,text,uuid,uuid,uuid,bigint,integer) from public;
revoke all on function control.admit_fleet_release_reconciliation_pre_route_publication(uuid,integer,text,text,text,uuid,text,uuid,uuid,integer) from public;
revoke all on function control.finish_fleet_release_reconciliation_pre_route_publication(uuid,uuid,uuid,text,jsonb) from public;
revoke all on function control.finish_release_driver_operation(uuid,uuid,uuid,uuid,bigint,text,jsonb,text) from public;
revoke all on function control.renew_release_driver_lease(uuid,uuid,integer,text,uuid,uuid,uuid,bigint,integer) from public;
revoke all on function control.admit_fleet_release_reconciliation(uuid,integer,text,text,text,uuid,text,uuid,uuid,integer) from public;
revoke all on function control.finish_fleet_release_reconciliation(uuid,uuid,uuid,text,jsonb) from public;

do $migration$ declare v_role text; begin
 foreach v_role in array array['control_api','control_tenant_api','control_membership_worker','control_provisioning_worker',
 'control_invoice_worker','control_inventory_worker','control_email_worker','control_reconciliation_worker',
 'control_lifecycle_worker','control_backup_scheduler','control_driver_ledger','control_release_worker','control_privacy_worker'] loop
  if exists(select 1 from pg_roles where rolname=v_role) then
   execute format('revoke all on table control.fleet_release_route_publications, control.fleet_release_route_publication_owners, control.fleet_release_route_publication_records from %I',v_role);
   execute format('revoke all on function control.finish_release_driver_operation_pre_route_publication(uuid,uuid,uuid,uuid,bigint,text,jsonb,text) from %I',v_role);
   execute format('revoke all on function control.renew_release_driver_lease_pre_route_publication(uuid,uuid,integer,text,uuid,uuid,uuid,bigint,integer) from %I',v_role);
   execute format('revoke all on function control.admit_fleet_release_reconciliation_pre_route_publication(uuid,integer,text,text,text,uuid,text,uuid,uuid,integer) from %I',v_role);
   execute format('revoke all on function control.finish_fleet_release_reconciliation_pre_route_publication(uuid,uuid,uuid,text,jsonb) from %I',v_role);
  end if;
 end loop;
 if exists(select 1 from pg_roles where rolname='control_driver_ledger') then
  grant execute on function control.finish_release_driver_operation(uuid,uuid,uuid,uuid,bigint,text,jsonb,text) to control_driver_ledger;
  grant execute on function control.renew_release_driver_lease(uuid,uuid,integer,text,uuid,uuid,uuid,bigint,integer) to control_driver_ledger;
  grant execute on function control.admit_fleet_release_reconciliation(uuid,integer,text,text,text,uuid,text,uuid,uuid,integer) to control_driver_ledger;
  grant execute on function control.finish_fleet_release_reconciliation(uuid,uuid,uuid,text,jsonb) to control_driver_ledger;
  grant execute on function control.admit_immutable_release_route_publication(uuid,uuid,uuid,uuid,uuid,bigint,integer) to control_driver_ledger;
  grant execute on function control.renew_immutable_release_route_publication(uuid,uuid,uuid,uuid,uuid,bigint,integer) to control_driver_ledger;
  grant execute on function control.record_immutable_release_route_prior(uuid,uuid,uuid,uuid,uuid,bigint,text,bigint,bigint,jsonb) to control_driver_ledger;
  grant execute on function control.read_immutable_release_route_snapshot_batch(uuid,uuid,uuid,uuid,uuid,bigint,uuid,integer) to control_driver_ledger;
  grant execute on function control.record_immutable_release_route_candidate(uuid,uuid,uuid,uuid,uuid,bigint,text,uuid,bigint,text,text,text) to control_driver_ledger;
  grant execute on function control.seal_immutable_release_route_overlay(uuid,uuid,uuid,uuid,uuid,bigint,text,text,bigint,bigint,integer,text) to control_driver_ledger;
  grant execute on function control.start_immutable_release_route_publication(uuid,uuid,uuid,uuid,uuid,bigint,text) to control_driver_ledger;
  grant execute on function control.observe_immutable_release_route_publication(uuid,uuid,uuid,uuid,uuid,bigint,text,smallint,uuid,uuid,bigint,text,text,text,text,bigint,bigint) to control_driver_ledger;
  grant execute on function control.begin_immutable_release_external_effects(uuid,uuid,uuid,uuid,uuid,bigint) to control_driver_ledger;
  grant execute on function control.quarantine_immutable_release_route_publication(uuid,uuid,uuid,uuid,uuid,bigint,text) to control_driver_ledger;
 end if;
end $migration$;

comment on table control.fleet_release_route_publications is
'Dormant protocol-v2 immutable maintenance/candidate route publication state; awaiting_worker_finalize retains every authority.';
