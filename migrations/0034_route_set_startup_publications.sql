-- Dormant fleet-scoped startup publications on the universal route-set ledger.
--
-- Startup has no target workshop and no control operation.  Its existing
-- startup-rebuild effect run is the sole logical owner.  This migration does
-- not change protocol mode/readiness and adds no active dispatch or activation
-- API.  The flat-v1 startup tables and functions remain byte-compatible.

alter table control.workshop_route_set_publications
  alter column control_operation_id drop not null,
  alter column control_operation_attempt drop not null,
  alter column control_operation_lease_owner drop not null,
  alter column target_workshop_id drop not null,
  add column startup_effect_run_id uuid,
  add constraint workshop_route_set_publications_startup_effect_fkey
    foreign key(startup_effect_run_id)
    references control.workshop_route_effect_runs(id) on delete restrict,
  drop constraint workshop_route_set_publications_kind_check,
  add constraint workshop_route_set_publications_kind_check check(
    publication_kind in ('projection','recovery_maintenance','recovery_restore','startup')),
  drop constraint workshop_route_set_publications_owner_xor_check,
  add constraint workshop_route_set_publications_owner_xor_check check(
    (publication_kind='projection' and driver_operation_id is not null
      and recovery_effect_run_id is null and startup_effect_run_id is null)
    or (publication_kind in ('recovery_maintenance','recovery_restore')
      and driver_operation_id is null and recovery_effect_run_id is not null
      and startup_effect_run_id is null)
    or (publication_kind='startup' and driver_operation_id is null
      and recovery_effect_run_id is null and startup_effect_run_id is not null)),
  add constraint workshop_route_set_publications_scope_check check(
    (publication_kind<>'startup' and target_workshop_id is not null
      and control_operation_id is not null and control_operation_attempt>0
      and control_operation_lease_owner is not null
      and btrim(control_operation_lease_owner)<>'')
    or (publication_kind='startup' and target_workshop_id is null
      and control_operation_id is null and control_operation_attempt is null
      and control_operation_lease_owner is null)),
  drop constraint workshop_route_set_publications_selector_check,
  add constraint workshop_route_set_publications_selector_check check(
    selector='generations/route-'||replace(publication_id::text,'-','')||'-'||
      case publication_kind
       when 'projection' then 'projection'
       when 'recovery_maintenance' then 'recovery-maintenance'
       when 'recovery_restore' then 'recovery-restore'
       when 'startup' then 'startup' end),
  drop constraint workshop_route_set_publications_count_check,
  add constraint workshop_route_set_publications_count_check check(
    (publication_kind='startup' and snapshot_count between 0 and 500)
    or (publication_kind<>'startup' and snapshot_count between 1 and 500));

create unique index workshop_route_set_publications_startup_owner
  on control.workshop_route_set_publications(startup_effect_run_id)
  where startup_effect_run_id is not null;

-- A startup baseline may be genuinely uninitialized.  Nullable baseline
-- evidence represents that state; no synthetic generation, digest, owner, or
-- fence is manufactured.  Existing non-startup rows retain their exact shape.
alter table control.workshop_route_set_publication_snapshot
  alter column baseline_applied_generation drop not null,
  alter column baseline_applied_digest drop not null,
  alter column baseline_applied_disposition drop not null,
  alter column baseline_applied_rendered_digest drop not null,
  alter column baseline_applied_fence_token drop not null,
  drop constraint workshop_route_set_publication_snapshot_shape_check,
  add constraint workshop_route_set_publication_snapshot_shape_check check(
    generation>0 and projection_digest ~ '^sha256:[0-9a-f]{64}$'
    and disposition in ('present','absent') and jsonb_typeof(canonical_projection)='object'
    and pg_column_size(canonical_projection)<=65536 and (
      (baseline_applied_generation is null and baseline_applied_digest is null
       and baseline_applied_disposition is null and baseline_applied_rendered_digest is null
       and baseline_applied_driver_operation_id is null and baseline_applied_effect_run_id is null
       and baseline_applied_fence_token is null)
      or (baseline_applied_generation>0
       and baseline_applied_digest ~ '^sha256:[0-9a-f]{64}$'
       and baseline_applied_disposition in ('present','absent')
       and baseline_applied_rendered_digest ~ '^sha256:[0-9a-f]{64}$'
       and ((baseline_applied_driver_operation_id is not null)
         <> (baseline_applied_effect_run_id is not null))
       and baseline_applied_fence_token>0)));

alter table control.workshop_route_set_publication_records
  alter column applied_rendered_digest drop not null,
  drop constraint workshop_route_set_publication_records_shape_check,
  add constraint workshop_route_set_publication_records_shape_check check(
    generation>0 and projection_digest ~ '^sha256:[0-9a-f]{64}$'
    and disposition in ('present','absent')
    and (applied_rendered_digest is null
      or applied_rendered_digest ~ '^sha256:[0-9a-f]{64}$')
    and rendered_digest ~ '^sha256:[0-9a-f]{64}$');

create or replace function control.route_set_publication_record_bytes(
 p_workshop_id uuid,p_generation bigint,p_projection_digest text,p_disposition text,
 p_applied_rendered_digest text,p_rendered_digest text
) returns bytea language sql immutable parallel safe set search_path=pg_catalog,control as $function$
 select case when p_workshop_id is null or p_generation is null or p_projection_digest is null
   or p_disposition is null or p_rendered_digest is null then null else
  uuid_send(p_workshop_id)||int8send(p_generation)
  ||int4send(octet_length(convert_to(p_projection_digest,'UTF8')))||convert_to(p_projection_digest,'UTF8')
  ||int4send(octet_length(convert_to(p_disposition,'UTF8')))||convert_to(p_disposition,'UTF8')
  ||case when p_applied_rendered_digest is null then int4send(-1)
    else int4send(octet_length(convert_to(p_applied_rendered_digest,'UTF8')))
      ||convert_to(p_applied_rendered_digest,'UTF8') end
  ||int4send(octet_length(convert_to(p_rendered_digest,'UTF8')))||convert_to(p_rendered_digest,'UTF8') end
$function$;

-- Frozen fleet-wide startup facts.  These are distinct from the generic
-- canonical projection snapshot because runtime verification must be replayed
-- against the exact database, shared Odoo, Paperless, and operation evidence
-- observed at admission.
create table control.workshop_route_set_startup_metadata (
 publication_id uuid primary key,
 boot_id uuid not null,
 active_runtime_slot text,
 active_runtime_release_id text,
 active_runtime_subject_digest text,
 active_runtime_deployment_ref text,
 active_runtime_config_digest text,
 active_runtime_slot_version bigint,
 fleet_release_unresolved boolean not null,
 created_at timestamptz not null default now(),
 constraint workshop_route_set_startup_metadata_publication_fkey
  foreign key(publication_id) references control.workshop_route_set_publications(publication_id) on delete restrict,
 constraint workshop_route_set_startup_metadata_runtime_check check(
  (active_runtime_slot is null and active_runtime_release_id is null
   and active_runtime_subject_digest is null and active_runtime_deployment_ref is null
   and active_runtime_config_digest is null and active_runtime_slot_version is null)
  or (active_runtime_slot in ('blue','green') and active_runtime_release_id is not null
   and active_runtime_subject_digest ~ '^sha256:[0-9a-f]{64}$'
   and active_runtime_deployment_ref is not null and btrim(active_runtime_deployment_ref)<>''
   and active_runtime_config_digest ~ '^sha256:[0-9a-f]{64}$'
   and active_runtime_slot_version>0))
);

create table control.workshop_route_set_startup_runtime_snapshot (
 publication_id uuid not null,
 workshop_id uuid not null,
 database_id uuid,
 database_ref text,
 public_hostname text,
 action text not null,
 paperless_mode text not null,
 paperless_hostname text,
 paperless_service_id uuid,
 paperless_service_health text,
 paperless_service_base_url text,
 paperless_service_desired_epoch integer,
 paperless_service_applied_epoch integer,
 paperless_runtime_spec jsonb,
 unresolved_operation boolean not null,
 route_fence_token bigint not null,
 runtime_outcome text,
 runtime_evidence jsonb,
 recorded_at timestamptz,
 primary key(publication_id,workshop_id),
 constraint workshop_route_set_startup_runtime_publication_fkey
  foreign key(publication_id) references control.workshop_route_set_startup_metadata(publication_id) on delete restrict,
 constraint workshop_route_set_startup_runtime_snapshot_fkey
  foreign key(publication_id,workshop_id)
  references control.workshop_route_set_publication_snapshot(publication_id,workshop_id) on delete restrict,
 constraint workshop_route_set_startup_runtime_database_fkey
  foreign key(database_id) references control.odoo_databases(id) on delete restrict,
 constraint workshop_route_set_startup_runtime_service_fkey
  foreign key(paperless_service_id) references control.service_instances(id) on delete restrict,
 constraint workshop_route_set_startup_runtime_shape_check check(
  action in ('render','remove-absent') and route_fence_token>0
  and paperless_mode in ('absent','read_write','read_only')
  and ((paperless_mode='absent' and paperless_hostname is null
    and paperless_service_id is null and paperless_service_health is null
    and paperless_service_base_url is null and paperless_service_desired_epoch is null
    and paperless_service_applied_epoch is null and paperless_runtime_spec is null)
   or (paperless_mode<>'absent' and paperless_hostname is not null
    and paperless_service_id is not null and paperless_service_health='ready'
    and paperless_service_base_url is not null and btrim(paperless_service_base_url)<>''
    and paperless_service_desired_epoch>0
    and paperless_service_applied_epoch between 0 and paperless_service_desired_epoch
    and jsonb_typeof(paperless_runtime_spec)='object'
    and pg_column_size(paperless_runtime_spec)<=16384))
  and ((action='render' and database_id is not null and database_ref is not null
    and btrim(database_ref)<>'' and public_hostname is not null and btrim(public_hostname)<>'')
   or (action='remove-absent' and database_id is null and database_ref is null
    and public_hostname is null and paperless_mode='absent'))),
 constraint workshop_route_set_startup_runtime_record_check check(
  (recorded_at is null and runtime_outcome is null and runtime_evidence is null)
  or (recorded_at is not null and runtime_outcome in ('ready','absent')
    and jsonb_typeof(runtime_evidence)='object' and pg_column_size(runtime_evidence)<=16384))
);

create function control.reject_route_set_startup_evidence_mutation()
returns trigger language plpgsql set search_path=pg_catalog,control as $function$
begin
 raise exception 'immutable route-set startup evidence cannot be changed' using errcode='55000';
end $function$;

create trigger workshop_route_set_startup_metadata_immutable
 before update or delete on control.workshop_route_set_startup_metadata
 for each row execute function control.reject_route_set_startup_evidence_mutation();

create function control.validate_route_set_startup_runtime_update()
returns trigger language plpgsql set search_path=pg_catalog,control as $function$
begin
 if tg_op='DELETE' or new.publication_id is distinct from old.publication_id
  or new.workshop_id is distinct from old.workshop_id or new.database_id is distinct from old.database_id
  or new.database_ref is distinct from old.database_ref or new.public_hostname is distinct from old.public_hostname
  or new.action is distinct from old.action or new.paperless_mode is distinct from old.paperless_mode
  or new.paperless_hostname is distinct from old.paperless_hostname
  or new.paperless_service_id is distinct from old.paperless_service_id
  or new.paperless_service_health is distinct from old.paperless_service_health
  or new.paperless_service_base_url is distinct from old.paperless_service_base_url
  or new.paperless_service_desired_epoch is distinct from old.paperless_service_desired_epoch
  or new.paperless_service_applied_epoch is distinct from old.paperless_service_applied_epoch
  or new.paperless_runtime_spec is distinct from old.paperless_runtime_spec
  or new.unresolved_operation is distinct from old.unresolved_operation
  or new.route_fence_token is distinct from old.route_fence_token
  or old.recorded_at is not null
  or new.recorded_at is null or new.runtime_outcome is null or new.runtime_evidence is null then
  raise exception 'immutable route-set startup runtime evidence cannot be changed' using errcode='55000';
 end if;
 return new;
end $function$;

create trigger workshop_route_set_startup_runtime_immutable
 before update or delete on control.workshop_route_set_startup_runtime_snapshot
 for each row execute function control.validate_route_set_startup_runtime_update();

revoke all on table control.workshop_route_set_startup_metadata from public;
revoke all on table control.workshop_route_set_startup_runtime_snapshot from public;

create function control.validate_route_set_startup_scope()
returns trigger language plpgsql set search_path=pg_catalog,control as $function$
declare v_publication control.workshop_route_set_publications%rowtype;
 v_snapshot control.workshop_route_set_publication_snapshot%rowtype;
begin
 if tg_table_name='workshop_route_set_publications' then
  if new.publication_kind='startup' and not exists(
   select 1 from control.workshop_route_effect_runs effect
   where effect.id=new.startup_effect_run_id and effect.kind='startup-rebuild'
    and effect.workshop_id is null and effect.control_operation_id is null) then
   raise exception 'startup publication owner is not an exact startup effect' using errcode='55000';
  end if;
  return new;
 end if;
 if tg_table_name='workshop_route_set_startup_metadata' then
  select * into v_publication from control.workshop_route_set_publications
   where publication_id=new.publication_id;
  if not found or v_publication.publication_kind<>'startup'
   or not exists(select 1 from control.workshop_route_effect_runs effect
    where effect.id=v_publication.startup_effect_run_id and effect.kind='startup-rebuild'
     and effect.target_key='startup/'||new.boot_id::text) then
   raise exception 'startup publication boot identity is not exact' using errcode='55000';
  end if;
  return new;
 end if;
 select * into v_publication from control.workshop_route_set_publications
  where publication_id=new.publication_id;
 select * into v_snapshot from control.workshop_route_set_publication_snapshot
  where publication_id=new.publication_id and workshop_id=new.workshop_id;
 if not found or v_publication.publication_kind<>'startup' or v_snapshot.is_target
  or ((v_snapshot.disposition='present')<>(new.action='render'))
  or ((v_snapshot.disposition='absent')<>(new.action='remove-absent'))
  or (new.action='render' and new.paperless_mode is null) then
  raise exception 'startup runtime snapshot scope is not exact' using errcode='55000';
 end if;
 return new;
end $function$;

create trigger workshop_route_set_startup_parent_scope
 before insert or update on control.workshop_route_set_publications
 for each row execute function control.validate_route_set_startup_scope();
create trigger workshop_route_set_startup_metadata_scope
 before insert on control.workshop_route_set_startup_metadata
 for each row execute function control.validate_route_set_startup_scope();
create trigger workshop_route_set_startup_runtime_scope
 before insert on control.workshop_route_set_startup_runtime_snapshot
 for each row execute function control.validate_route_set_startup_scope();

create function control.validate_route_set_snapshot_scope()
returns trigger language plpgsql set search_path=pg_catalog,control as $function$
declare v_kind text;
begin
 select publication_kind into strict v_kind from control.workshop_route_set_publications
  where publication_id=new.publication_id;
 if (v_kind='startup' and (new.is_target
    or not ((new.baseline_applied_generation is null and new.baseline_applied_digest is null
      and new.baseline_applied_disposition is null and new.baseline_applied_rendered_digest is null
      and new.baseline_applied_driver_operation_id is null and new.baseline_applied_effect_run_id is null
      and new.baseline_applied_fence_token is null)
     or (new.baseline_applied_generation is not null and new.baseline_applied_digest is not null
      and new.baseline_applied_disposition is not null and new.baseline_applied_rendered_digest is not null
      and ((new.baseline_applied_driver_operation_id is not null)
       <> (new.baseline_applied_effect_run_id is not null))
      and new.baseline_applied_fence_token is not null))))
  or (v_kind<>'startup' and (new.baseline_applied_generation is null
    or new.baseline_applied_digest is null or new.baseline_applied_disposition is null
    or new.baseline_applied_rendered_digest is null or new.baseline_applied_fence_token is null)) then
  raise exception 'route-set snapshot scope is not exact' using errcode='55000';
 end if;
 return new;
end $function$;

create trigger workshop_route_set_snapshot_scope
 before insert on control.workshop_route_set_publication_snapshot
 for each row execute function control.validate_route_set_snapshot_scope();

create or replace function control.valid_route_set_loaded_identity(p_identity jsonb)
returns boolean language sql immutable parallel safe set search_path=pg_catalog,control as $function$
 select p_identity is null or control.valid_release_route_loaded_identity(p_identity) or (
  jsonb_typeof(p_identity)='object' and pg_column_size(p_identity)<=4096 and (
   (p_identity ?& array['protocol_version','publication_id','publication_kind','global_fence_token',
      'target_workshop_id','target_route_fence_token','route_set_digest']
   and p_identity-array['protocol_version','publication_id','publication_kind','global_fence_token',
      'target_workshop_id','target_route_fence_token','route_set_digest']='{}'::jsonb
    and jsonb_typeof(p_identity->'target_workshop_id')='string'
    and jsonb_typeof(p_identity->'target_route_fence_token')='number'
    and p_identity->>'publication_kind' in ('projection','recovery_maintenance','recovery_restore')
    and p_identity->>'target_workshop_id' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    and p_identity->>'target_route_fence_token' ~ '^[1-9][0-9]{0,18}$'
    and (length(p_identity->>'target_route_fence_token')<19
      or p_identity->>'target_route_fence_token'<='9223372036854775807'))
   or
   (p_identity ?& array['protocol_version','publication_id','publication_kind','startup_effect_run_id',
      'global_fence_token','route_set_digest']
    and p_identity-array['protocol_version','publication_id','publication_kind','startup_effect_run_id',
      'global_fence_token','route_set_digest']='{}'::jsonb
    and jsonb_typeof(p_identity->'startup_effect_run_id')='string'
    and p_identity->>'publication_kind'='startup'
    and p_identity->>'startup_effect_run_id' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'))
  and jsonb_typeof(p_identity->'protocol_version')='number'
  and jsonb_typeof(p_identity->'publication_id')='string'
  and jsonb_typeof(p_identity->'publication_kind')='string'
  and jsonb_typeof(p_identity->'global_fence_token')='number'
  and jsonb_typeof(p_identity->'route_set_digest')='string'
  and p_identity->>'protocol_version'='1'
  and p_identity->>'publication_id' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
  and p_identity->>'global_fence_token' ~ '^[1-9][0-9]{0,18}$'
  and (length(p_identity->>'global_fence_token')<19
    or p_identity->>'global_fence_token'<='9223372036854775807')
  and p_identity->>'route_set_digest' ~ '^sha256:[0-9a-f]{64}$')
$function$;

create or replace function control.valid_route_set_prior_selector_identity(p_selector text,p_identity jsonb)
returns boolean language sql immutable parallel safe set search_path=pg_catalog,control as $function$
 select p_selector is not null and p_selector ~ '^generations/[A-Za-z0-9][A-Za-z0-9-]{0,63}$'
  and control.valid_route_set_loaded_identity(p_identity) and (
   (p_selector='generations/boot-live' and p_identity is null)
   or (p_identity is not null and (
    (p_identity ? 'effect_run_id' and p_selector='generations/startup-'||(p_identity->>'effect_run_id'))
    or (p_identity ? 'fleet_run_id' and p_selector='generations/release-'||replace(p_identity->>'fleet_run_id','-','')
      ||'-'||(p_identity->>'overlay_kind'))
    or (p_identity ? 'publication_id' and p_selector='generations/route-'||replace(p_identity->>'publication_id','-','')||'-'||
      case p_identity->>'publication_kind'
       when 'projection' then 'projection'
       when 'recovery_maintenance' then 'recovery-maintenance'
       when 'recovery_restore' then 'recovery-restore'
       when 'startup' then 'startup' end))))
$function$;

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
  or new.startup_effect_run_id is distinct from old.startup_effect_run_id
  or new.control_operation_id is distinct from old.control_operation_id
  or new.control_operation_attempt is distinct from old.control_operation_attempt
  or new.control_operation_lease_owner is distinct from old.control_operation_lease_owner
  or new.original_instance_owner is distinct from old.original_instance_owner
  or new.original_execution_token is distinct from old.original_execution_token
  or new.original_global_lease_token is distinct from old.original_global_lease_token
  or new.original_route_lease_token is distinct from old.original_route_lease_token
  or new.original_global_fence_token is distinct from old.original_global_fence_token
  or new.target_workshop_id is distinct from old.target_workshop_id
  or new.selector is distinct from old.selector or new.snapshot_count is distinct from old.snapshot_count
  or new.correlation_id is distinct from old.correlation_id
  or new.trace_parent is distinct from old.trace_parent or new.trace_state is distinct from old.trace_state
  or new.retention_not_before is distinct from old.retention_not_before
  or new.created_at is distinct from old.created_at then
  raise exception 'immutable route-set publication identity cannot be changed' using errcode='55000';
 end if;
 return new;
end $function$;

create function control.read_route_set_startup_admission(
 p_boot_id uuid,p_idempotency_key text,p_request_digest text
) returns table(outcome text,publication_id uuid,effect_run_id uuid,global_fence_token bigint,
 snapshot_count integer,selector text,active_runtime_slot text,active_runtime_release_id text,
 active_runtime_subject_digest text,active_runtime_deployment_ref text,
 active_runtime_config_digest text,active_runtime_slot_version bigint,
 fleet_release_unresolved boolean,stored_response jsonb)
language plpgsql stable security definer set search_path=pg_catalog,control as $function$
declare v_effect control.workshop_route_effect_runs%rowtype;
 v_publication control.workshop_route_set_publications%rowtype;
 v_metadata control.workshop_route_set_startup_metadata%rowtype;
 -- The terminal table is created later in this migration. Keep this as a
 -- runtime record so an upgrade beginning at 0034 does not require the
 -- session-level check_function_bodies setting inherited by a fresh install.
 v_terminal record;
 v_protocol control.route_set_publication_protocol_state%rowtype;
begin
 if p_boot_id is null or p_idempotency_key is null or length(p_idempotency_key) not between 1 and 180
  or p_request_digest is null or p_request_digest !~ '^[0-9a-f]{64}$' then
  return query select 'conflict',null::uuid,null::uuid,null::bigint,null::integer,null::text,
   null::text,null::text,null::text,null::text,null::text,null::bigint,null::boolean,null::jsonb; return;
 end if;
 select * into v_effect from control.workshop_route_effect_runs effect
 where effect.kind='startup-rebuild' and (effect.idempotency_key=p_idempotency_key
  or effect.target_key='startup/'||p_boot_id::text)
 order by (effect.idempotency_key=p_idempotency_key) desc limit 1;
 if not found then
  select * into strict v_protocol from control.route_set_publication_protocol_state where singleton;
  return query select case when v_protocol.mode='generation_v1' and v_protocol.startup_ready
    then 'absent' else 'protocol_inactive' end,
   null::uuid,null::uuid,null::bigint,null::integer,null::text,
   null::text,null::text,null::text,null::text,null::text,null::bigint,null::boolean,null::jsonb; return;
 end if;
 select * into v_publication from control.workshop_route_set_publications publication
  where publication.startup_effect_run_id=v_effect.id;
 if v_effect.idempotency_key is distinct from p_idempotency_key
  or v_effect.target_key is distinct from 'startup/'||p_boot_id::text
  or v_effect.request_digest is distinct from p_request_digest or not found then
  return query select 'conflict',v_publication.publication_id,v_effect.id,
   v_effect.global_fence_token,v_publication.snapshot_count,v_publication.selector,
   null::text,null::text,null::text,null::text,null::text,null::bigint,null::boolean,null::jsonb; return;
 end if;
 select * into strict v_metadata from control.workshop_route_set_startup_metadata metadata
  where metadata.publication_id=v_publication.publication_id;
 select * into v_terminal from control.workshop_route_set_startup_recovery_terminals terminal
  where terminal.publication_id=v_publication.publication_id;
 return query select case
   when v_terminal.publication_id is not null and v_terminal.resolution_kind='candidate' then 'replay'
   when v_terminal.publication_id is not null then 'not_applied'
   when v_effect.state='succeeded' and v_publication.phase='completed' then 'replay'
   when v_effect.state='quarantined' or v_publication.phase='quarantined' then 'fleet_quarantined'
   else 'busy' end,
  v_publication.publication_id,v_effect.id,v_publication.original_global_fence_token,
  v_publication.snapshot_count,v_publication.selector,v_metadata.active_runtime_slot,
  v_metadata.active_runtime_release_id,v_metadata.active_runtime_subject_digest,
  v_metadata.active_runtime_deployment_ref,v_metadata.active_runtime_config_digest,
  v_metadata.active_runtime_slot_version,v_metadata.fleet_release_unresolved,
  case when v_terminal.publication_id is not null then v_terminal.response
   when v_publication.phase='completed' then v_publication.final_response end;
end $function$;

create function control.admit_route_set_startup_publication(
 p_boot_id uuid,p_idempotency_key text,p_request_digest text,
 p_instance_owner uuid,p_execution_token uuid,p_global_lease_token uuid,
 p_route_lease_token uuid,p_ttl_seconds integer,p_protocol_version smallint
) returns table(outcome text,publication_id uuid,effect_run_id uuid,global_fence_token bigint,
 snapshot_count integer,selector text,active_runtime_slot text,active_runtime_release_id text,
 active_runtime_subject_digest text,active_runtime_deployment_ref text,
 active_runtime_config_digest text,active_runtime_slot_version bigint,
 fleet_release_unresolved boolean,stored_response jsonb)
language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_protocol control.route_set_publication_protocol_state%rowtype;
 v_existing record; v_admission record; v_active control.runtime_release_slots%rowtype;
 v_active_count integer; v_release_unresolved boolean; v_bad integer; v_count integer;
 v_fleet_count integer; v_lease_count integer; v_state_count integer;
 v_publication_id uuid:=gen_random_uuid(); v_selector text; v_changed integer;
begin
 if p_boot_id is null or p_idempotency_key is null or length(p_idempotency_key) not between 1 and 180
  or p_request_digest is null or p_request_digest !~ '^[0-9a-f]{64}$'
  or p_instance_owner is null or p_execution_token is null or p_global_lease_token is null
  or p_route_lease_token is null or p_ttl_seconds is null or p_ttl_seconds not between 60 and 1200
  or p_protocol_version is distinct from 1 then
  return query select 'invalid',null::uuid,null::uuid,null::bigint,null::integer,null::text,
   null::text,null::text,null::text,null::text,null::text,null::bigint,null::boolean,null::jsonb; return;
 end if;
 select * into strict v_protocol from control.route_set_publication_protocol_state where singleton for update;
 select * into strict v_existing from control.read_route_set_startup_admission(
  p_boot_id,p_idempotency_key,p_request_digest);
 if v_existing.outcome not in ('absent','protocol_inactive') then
  return query select v_existing.outcome,v_existing.publication_id,v_existing.effect_run_id,
   v_existing.global_fence_token,v_existing.snapshot_count,v_existing.selector,
   v_existing.active_runtime_slot,v_existing.active_runtime_release_id,
   v_existing.active_runtime_subject_digest,v_existing.active_runtime_deployment_ref,
   v_existing.active_runtime_config_digest,v_existing.active_runtime_slot_version,
   v_existing.fleet_release_unresolved,v_existing.stored_response; return;
 end if;
 if v_protocol.mode<>'generation_v1' or not v_protocol.startup_ready then
  return query select 'protocol_inactive',null::uuid,null::uuid,null::bigint,null::integer,null::text,
   null::text,null::text,null::text,null::text,null::text,null::bigint,null::boolean,null::jsonb; return;
 end if;
 perform 1 from control.deployment_driver_resource_leases
  where resource_key='runtime/shared-odoo' for update;
 perform 1 from control.workshop_route_application_leases order by workshop_id for update;
 perform 1 from control.workshop_route_projection_state order by workshop_id for update;
 perform 1 from control.runtime_release_slots where runtime_key='shared-odoo' order by slot for share;
 perform 1 from control.release_fleet_runs
  where state in ('preflighting','preparing','paused','activating') order by id for share;
 perform 1 from control.service_instances where service='paperless' order by workshop_id for share;
 select count(*) into v_fleet_count from control.workshops;
 select count(*) into v_lease_count from control.workshop_route_application_leases;
 select count(*) into v_state_count from control.workshop_route_projection_state;
 if v_fleet_count>500 then
  return query select 'fleet_too_large',null::uuid,null::uuid,null::bigint,v_fleet_count,null::text,
   null::text,null::text,null::text,null::text,null::text,null::bigint,null::boolean,null::jsonb; return;
 end if;
 if v_lease_count<>v_fleet_count or v_state_count<>v_fleet_count then
  return query select 'initialization_required',null::uuid,null::uuid,null::bigint,v_fleet_count,null::text,
   null::text,null::text,null::text,null::text,null::text,null::bigint,null::boolean,null::jsonb; return;
 end if;
 select * into strict v_admission from control.admit_startup_route_rebuild_flat_v1(
  p_boot_id,p_idempotency_key,p_request_digest,p_instance_owner,p_execution_token,
  p_global_lease_token,p_route_lease_token,p_ttl_seconds);
 if v_admission.outcome<>'acquired' then
  return query select v_admission.outcome,null::uuid,v_admission.effect_run_id,
   v_admission.global_fence_token,v_admission.reserved_count,null::text,
   null::text,null::text,null::text,null::text,null::text,null::bigint,null::boolean,
   v_admission.stored_response; return;
 end if;
 select count(*) into v_bad
 from control.workshop_route_effect_reservations reservation
 left join control.workshop_route_projections projection
  on projection.workshop_id=reservation.workshop_id
 and projection.generation=reservation.generation
 and projection.projection_digest=reservation.projection_digest
 and projection.disposition=reservation.disposition
 where reservation.effect_run_id=v_admission.effect_run_id and (
  reservation.generation is null or projection.workshop_id is null
  or reservation.action not in ('render','remove-absent')
  or (projection.projection->>'paperless_mode'<>'absent' and not exists(
   select 1 from control.service_instances service
   where service.workshop_id=reservation.workshop_id and service.service='paperless'
    and service.health='ready' and service.runtime_spec is not null
    and jsonb_typeof(service.runtime_spec)='object' and pg_column_size(service.runtime_spec)<=16384
    and (service.runtime_spec->>'config_digest' ~ '^[0-9a-f]{64}$') is true)));
 if v_bad<>0 then
  perform control.finish_startup_route_rebuild_v2(v_admission.effect_run_id,p_instance_owner,
   p_execution_token,p_global_lease_token,p_route_lease_token,v_admission.global_fence_token,
   'cancelled',null,null);
  return query select 'initialization_required',null::uuid,v_admission.effect_run_id,
   v_admission.global_fence_token,v_admission.reserved_count,null::text,
   null::text,null::text,null::text,null::text,null::text,null::bigint,null::boolean,null::jsonb; return;
 end if;
 select count(*) into v_active_count from control.runtime_release_slots
  where runtime_key='shared-odoo' and state='active';
 if v_active_count=1 then
  select * into strict v_active from control.runtime_release_slots
   where runtime_key='shared-odoo' and state='active' for share;
 elsif exists(select 1 from control.workshop_route_effect_reservations reservation
  where reservation.effect_run_id=v_admission.effect_run_id and reservation.disposition='present') then
  perform control.finish_startup_route_rebuild_v2(v_admission.effect_run_id,p_instance_owner,
   p_execution_token,p_global_lease_token,p_route_lease_token,v_admission.global_fence_token,
   'cancelled',null,null);
  return query select 'runtime_ambiguous',null::uuid,v_admission.effect_run_id,
   v_admission.global_fence_token,v_admission.reserved_count,null::text,
   null::text,null::text,null::text,null::text,null::text,null::bigint,null::boolean,null::jsonb; return;
 end if;
 if v_active_count=1 and ((v_active.evidence->>'runtime_deployment_ref') is null
  or btrim(v_active.evidence->>'runtime_deployment_ref')=''
  or (v_active.evidence->>'runtime_config_digest' ~ '^sha256:[0-9a-f]{64}$') is distinct from true) then
  perform control.finish_startup_route_rebuild_v2(v_admission.effect_run_id,p_instance_owner,
   p_execution_token,p_global_lease_token,p_route_lease_token,v_admission.global_fence_token,
   'cancelled',null,null);
  return query select 'runtime_identity_missing',null::uuid,v_admission.effect_run_id,
   v_admission.global_fence_token,v_admission.reserved_count,null::text,
   null::text,null::text,null::text,null::text,null::text,null::bigint,null::boolean,null::jsonb; return;
 end if;
 select exists(select 1 from control.release_fleet_runs
  where state in ('preflighting','preparing','paused','activating')) into v_release_unresolved;
 v_selector:='generations/route-'||replace(v_publication_id::text,'-','')||'-startup';
 insert into control.workshop_route_set_publications(publication_id,protocol_version,publication_kind,
  driver_operation_id,recovery_effect_run_id,startup_effect_run_id,control_operation_id,
  control_operation_attempt,control_operation_lease_owner,original_instance_owner,
  original_execution_token,original_global_lease_token,original_route_lease_token,
  original_global_fence_token,target_workshop_id,selector,snapshot_count,phase,correlation_id)
 values(v_publication_id,1,'startup',null,null,v_admission.effect_run_id,null,null,null,
  p_instance_owner,p_execution_token,p_global_lease_token,p_route_lease_token,
  v_admission.global_fence_token,null,v_selector,v_admission.reserved_count,'staging',p_boot_id);
 insert into control.workshop_route_set_publication_snapshot(publication_id,workshop_id,generation,
  projection_digest,disposition,canonical_projection,baseline_applied_generation,
  baseline_applied_digest,baseline_applied_disposition,baseline_applied_rendered_digest,
  baseline_applied_driver_operation_id,baseline_applied_effect_run_id,baseline_applied_fence_token,is_target)
 select v_publication_id,reservation.workshop_id,reservation.generation,reservation.projection_digest,
  reservation.disposition,projection.projection,state.applied_generation,state.applied_digest,
  state.applied_disposition,state.applied_rendered_digest,state.applied_driver_operation_id,
  state.applied_effect_run_id,state.applied_fence_token,false
 from control.workshop_route_effect_reservations reservation
 join control.workshop_route_projections projection on projection.workshop_id=reservation.workshop_id
  and projection.generation=reservation.generation and projection.projection_digest=reservation.projection_digest
  and projection.disposition=reservation.disposition
 join control.workshop_route_projection_state state on state.workshop_id=reservation.workshop_id
 where reservation.effect_run_id=v_admission.effect_run_id order by reservation.workshop_id;
 get diagnostics v_count=row_count;
 if v_count<>v_admission.reserved_count then
  raise exception 'startup route-set snapshot drifted' using errcode='40001';
 end if;
 insert into control.workshop_route_set_startup_metadata(publication_id,boot_id,
  active_runtime_slot,active_runtime_release_id,active_runtime_subject_digest,
  active_runtime_deployment_ref,active_runtime_config_digest,active_runtime_slot_version,
  fleet_release_unresolved)
 values(v_publication_id,p_boot_id,v_active.slot,v_active.release_id,v_active.odoo_subject_digest,
  v_active.evidence->>'runtime_deployment_ref',v_active.evidence->>'runtime_config_digest',
  v_active.version,v_release_unresolved);
 insert into control.workshop_route_set_startup_runtime_snapshot(publication_id,workshop_id,
  database_id,database_ref,public_hostname,action,paperless_mode,paperless_hostname,
  paperless_service_id,paperless_service_health,paperless_service_base_url,
  paperless_service_desired_epoch,paperless_service_applied_epoch,paperless_runtime_spec,
  unresolved_operation,route_fence_token)
 select v_publication_id,reservation.workshop_id,
  case when reservation.disposition='present' then (projection.projection->>'database_id')::uuid end,
  case when reservation.disposition='present' then projection.projection->>'database_ref' end,
  case when reservation.disposition='present' then projection.projection->>'public_hostname' end,
  reservation.action,projection.projection->>'paperless_mode',
  nullif(projection.projection->>'paperless_hostname',''),
  case when projection.projection->>'paperless_mode'<>'absent' then service.id end,
  case when projection.projection->>'paperless_mode'<>'absent' then service.health end,
  case when projection.projection->>'paperless_mode'<>'absent' then service.base_url end,
  case when projection.projection->>'paperless_mode'<>'absent' then service.desired_epoch end,
  case when projection.projection->>'paperless_mode'<>'absent' then service.applied_epoch end,
  case when projection.projection->>'paperless_mode'<>'absent' then service.runtime_spec end,
  (exists(select 1 from control.operations operation where operation.workshop_id=reservation.workshop_id
    and operation.state in ('pending','in_flight','awaiting_reconciliation')
    and operation.kind in ('tenant.provision','tenant.reconcile','tenant.lifecycle','odoo.release.adopt'))
   or exists(select 1 from control.deployment_driver_operations operation
    where operation.workshop_id=reservation.workshop_id and operation.state='in_progress')),
  reservation.route_fence_token
 from control.workshop_route_effect_reservations reservation
 join control.workshop_route_projections projection on projection.workshop_id=reservation.workshop_id
  and projection.generation=reservation.generation and projection.projection_digest=reservation.projection_digest
  and projection.disposition=reservation.disposition
 left join control.service_instances service on service.workshop_id=reservation.workshop_id
  and service.service='paperless'
 where reservation.effect_run_id=v_admission.effect_run_id order by reservation.workshop_id;
 get diagnostics v_count=row_count;
 if v_count<>v_admission.reserved_count then
  raise exception 'startup runtime snapshot drifted' using errcode='40001';
 end if;
 update control.deployment_driver_resource_leases global_lease set authority_kind='route-set-publication',
  effect_run_id=null,route_set_publication_id=v_publication_id,updated_at=now()
 where global_lease.resource_key='runtime/shared-odoo' and global_lease.state='held'
  and global_lease.authority_kind='startup-rebuild'
  and global_lease.effect_run_id=v_admission.effect_run_id and global_lease.lease_owner=p_instance_owner
  and global_lease.lease_token=p_global_lease_token
  and global_lease.fence_token=v_admission.global_fence_token;
 get diagnostics v_changed=row_count;
 if v_changed<>1 then raise exception 'startup global authority drifted' using errcode='40001'; end if;
 update control.workshop_route_application_leases lease set authority_kind='route-set-publication',
  effect_run_id=null,route_set_publication_id=v_publication_id,updated_at=now()
 from control.workshop_route_effect_reservations reservation
 where reservation.effect_run_id=v_admission.effect_run_id and reservation.workshop_id=lease.workshop_id
  and lease.state='held' and lease.authority_kind='startup-rebuild'
  and lease.effect_run_id=v_admission.effect_run_id and lease.lease_owner=p_instance_owner
  and lease.lease_token=p_route_lease_token and lease.fence_token=reservation.route_fence_token;
 get diagnostics v_changed=row_count;
 if v_changed<>v_admission.reserved_count then
  raise exception 'startup route authority drifted' using errcode='40001';
 end if;
 return query select 'acquired',v_publication_id,v_admission.effect_run_id,
  v_admission.global_fence_token,v_admission.reserved_count,v_selector,v_active.slot,
  v_active.release_id,v_active.odoo_subject_digest,v_active.evidence->>'runtime_deployment_ref',
  v_active.evidence->>'runtime_config_digest',v_active.version,v_release_unresolved,null::jsonb;
end $function$;

create function control.has_route_set_startup_authority(
 p_publication_id uuid,p_instance_owner uuid,p_execution_token uuid,
 p_global_lease_token uuid,p_route_lease_token uuid,p_global_fence_token bigint
) returns boolean language sql stable security definer set search_path=pg_catalog,control as $function$
 select exists(
  select 1 from control.workshop_route_set_publications publication
  join control.workshop_route_effect_runs effect on effect.id=publication.startup_effect_run_id
  join control.deployment_driver_resource_leases global_lease
   on global_lease.resource_key='runtime/shared-odoo'
  where publication.publication_id=p_publication_id and publication.publication_kind='startup'
   and publication.phase in ('staging','sealed','publication_started','observed')
   and publication.original_instance_owner=p_instance_owner
   and publication.original_execution_token=p_execution_token
   and publication.original_global_lease_token=p_global_lease_token
   and publication.original_route_lease_token=p_route_lease_token
   and publication.original_global_fence_token=p_global_fence_token
   and effect.kind='startup-rebuild' and effect.state in ('reserved','effects_started')
   and effect.instance_owner=p_instance_owner and effect.execution_token=p_execution_token
   and effect.global_lease_token=p_global_lease_token and effect.route_lease_token=p_route_lease_token
   and effect.global_fence_token=p_global_fence_token and effect.lease_expires_at>now()
   and global_lease.state='held' and global_lease.authority_kind='route-set-publication'
   and global_lease.route_set_publication_id=p_publication_id
   and global_lease.lease_owner=p_instance_owner and global_lease.lease_token=p_global_lease_token
   and global_lease.fence_token=p_global_fence_token and global_lease.lease_expires_at>now()
   and publication.snapshot_count=(select count(*) from control.workshop_route_set_publication_snapshot
    where publication_id=p_publication_id)
   and publication.snapshot_count=(select count(*)
    from control.workshop_route_set_publication_snapshot snapshot
    join control.workshop_route_set_startup_runtime_snapshot runtime
     on runtime.publication_id=snapshot.publication_id and runtime.workshop_id=snapshot.workshop_id
    join control.workshop_route_application_leases lease on lease.workshop_id=snapshot.workshop_id
    where snapshot.publication_id=p_publication_id and not snapshot.is_target
     and lease.state='held' and lease.authority_kind='route-set-publication'
     and lease.route_set_publication_id=p_publication_id and lease.driver_operation_id is null
     and lease.effect_run_id is null and lease.release_publication_id is null
     and lease.generation=snapshot.generation and lease.projection_digest=snapshot.projection_digest
     and lease.fence_token=runtime.route_fence_token and lease.lease_owner=p_instance_owner
     and lease.lease_token=p_route_lease_token and lease.lease_expires_at>now()))
$function$;

create function control.lock_route_set_startup_authority(
 p_publication_id uuid,p_instance_owner uuid,p_execution_token uuid,
 p_global_lease_token uuid,p_route_lease_token uuid,p_global_fence_token bigint
) returns boolean language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_effect uuid;
begin
 select startup_effect_run_id into v_effect from control.workshop_route_set_publications
  where publication_id=p_publication_id and publication_kind='startup';
 if not found then return false; end if;
 perform 1 from control.route_set_publication_protocol_state where singleton for update;
 perform 1 from control.deployment_driver_resource_leases
  where resource_key='runtime/shared-odoo' for update;
 perform 1 from control.workshop_route_application_leases lease
  where lease.route_set_publication_id=p_publication_id order by lease.workshop_id for update;
 perform 1 from control.workshop_route_effect_runs where id=v_effect for update;
 perform 1 from control.workshop_route_effect_reservations
  where effect_run_id=v_effect order by workshop_id for update;
 perform 1 from control.workshop_route_set_publications where publication_id=p_publication_id for update;
 return control.has_route_set_startup_authority(p_publication_id,p_instance_owner,p_execution_token,
  p_global_lease_token,p_route_lease_token,p_global_fence_token);
end $function$;

create function control.renew_route_set_startup_publication(
 p_publication_id uuid,p_instance_owner uuid,p_execution_token uuid,
 p_global_lease_token uuid,p_route_lease_token uuid,p_global_fence_token bigint,
 p_ttl_seconds integer
) returns boolean language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_effect uuid; v_count integer; v_changed integer;
 v_expires timestamptz;
begin
 if p_ttl_seconds is null or p_ttl_seconds not between 60 and 1200 then return false; end if;
 if not control.lock_route_set_startup_authority(p_publication_id,p_instance_owner,p_execution_token,
  p_global_lease_token,p_route_lease_token,p_global_fence_token) then return false; end if;
 select startup_effect_run_id,snapshot_count into strict v_effect,v_count
  from control.workshop_route_set_publications where publication_id=p_publication_id;
 v_expires:=now()+make_interval(secs=>p_ttl_seconds);
 update control.workshop_route_effect_runs set lease_expires_at=v_expires,heartbeat_at=now(),updated_at=now()
  where id=v_effect and state in ('reserved','effects_started');
 get diagnostics v_changed=row_count; if v_changed<>1 then return false; end if;
 update control.deployment_driver_resource_leases set lease_expires_at=v_expires,
  heartbeat_at=now(),updated_at=now() where resource_key='runtime/shared-odoo'
  and route_set_publication_id=p_publication_id and state='held';
 get diagnostics v_changed=row_count; if v_changed<>1 then raise exception 'startup global renewal drifted' using errcode='40001'; end if;
 update control.workshop_route_application_leases set lease_expires_at=v_expires,
  heartbeat_at=now(),updated_at=now() where route_set_publication_id=p_publication_id and state='held';
 get diagnostics v_changed=row_count; if v_changed<>v_count then raise exception 'startup route renewal drifted' using errcode='40001'; end if;
 return true;
end $function$;

create function control.record_route_set_startup_prior(
 p_publication_id uuid,p_instance_owner uuid,p_execution_token uuid,
 p_global_lease_token uuid,p_route_lease_token uuid,p_global_fence_token bigint,
 p_prior_selector text,p_prior_directory_device bigint,p_prior_directory_inode bigint,
 p_prior_loaded_identity jsonb
) returns text language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_publication control.workshop_route_set_publications%rowtype; v_changed integer;
begin
 if not control.lock_route_set_startup_authority(p_publication_id,p_instance_owner,p_execution_token,
  p_global_lease_token,p_route_lease_token,p_global_fence_token) then return 'authority_lost'; end if;
 select * into strict v_publication from control.workshop_route_set_publications
  where publication_id=p_publication_id;
 if v_publication.prior_recorded_at is not null then
  return case when v_publication.prior_selector=p_prior_selector
   and v_publication.prior_directory_device=p_prior_directory_device
   and v_publication.prior_directory_inode=p_prior_directory_inode
   and v_publication.prior_loaded_identity is not distinct from p_prior_loaded_identity
   then 'replay' else 'conflict' end;
 end if;
 if v_publication.phase<>'staging' or p_prior_directory_device is null or p_prior_directory_device<=0
  or p_prior_directory_inode is null or p_prior_directory_inode<=0
  or not control.valid_route_set_prior_selector_identity(p_prior_selector,p_prior_loaded_identity)
  or (p_prior_loaded_identity is null and p_prior_selector<>'generations/boot-live') then return 'invalid'; end if;
 update control.workshop_route_set_publications set prior_selector=p_prior_selector,
  prior_directory_device=p_prior_directory_device,prior_directory_inode=p_prior_directory_inode,
  prior_loaded_identity=p_prior_loaded_identity,prior_recorded_at=now(),updated_at=now()
  where publication_id=p_publication_id and prior_recorded_at is null;
 get diagnostics v_changed=row_count; if v_changed<>1 then return 'conflict'; end if;
 update control.workshop_route_effect_runs set state='effects_started',updated_at=now()
  where id=v_publication.startup_effect_run_id and state='reserved';
 get diagnostics v_changed=row_count;
 if v_changed<>1 then raise exception 'startup effect begin drifted' using errcode='40001'; end if;
 return 'recorded';
end $function$;

create function control.read_route_set_startup_snapshot_batch(
 p_publication_id uuid,p_instance_owner uuid,p_execution_token uuid,
 p_global_lease_token uuid,p_route_lease_token uuid,p_global_fence_token bigint,
 p_after_workshop uuid,p_limit integer
) returns table(workshop_id uuid,generation bigint,projection_digest text,disposition text,
 canonical_projection jsonb,baseline_applied_generation bigint,baseline_applied_digest text,
 baseline_applied_disposition text,baseline_applied_rendered_digest text,
 baseline_applied_driver_operation_id uuid,baseline_applied_effect_run_id uuid,
 baseline_applied_fence_token bigint,route_fence_token bigint,database_id uuid,
 database_ref text,public_hostname text,action text,paperless_mode text,
 paperless_hostname text,paperless_service_id uuid,paperless_service_health text,
 paperless_service_base_url text,paperless_service_desired_epoch integer,
 paperless_service_applied_epoch integer,paperless_runtime_spec jsonb,
 unresolved_operation boolean)
language sql stable security definer set search_path=pg_catalog,control as $function$
 select snapshot.workshop_id,snapshot.generation,snapshot.projection_digest,snapshot.disposition,
  snapshot.canonical_projection,snapshot.baseline_applied_generation,snapshot.baseline_applied_digest,
  snapshot.baseline_applied_disposition,snapshot.baseline_applied_rendered_digest,
  snapshot.baseline_applied_driver_operation_id,snapshot.baseline_applied_effect_run_id,
  snapshot.baseline_applied_fence_token,runtime.route_fence_token,runtime.database_id,
  runtime.database_ref,runtime.public_hostname,runtime.action,runtime.paperless_mode,
  runtime.paperless_hostname,runtime.paperless_service_id,runtime.paperless_service_health,
  runtime.paperless_service_base_url,runtime.paperless_service_desired_epoch,
  runtime.paperless_service_applied_epoch,runtime.paperless_runtime_spec,runtime.unresolved_operation
 from control.workshop_route_set_publication_snapshot snapshot
 join control.workshop_route_set_startup_runtime_snapshot runtime
  on runtime.publication_id=snapshot.publication_id and runtime.workshop_id=snapshot.workshop_id
 join control.workshop_route_set_publications publication
  on publication.publication_id=snapshot.publication_id
 where snapshot.publication_id=p_publication_id and publication.phase='staging'
  and publication.prior_recorded_at is not null and runtime.recorded_at is null
  and control.has_route_set_startup_authority(p_publication_id,p_instance_owner,p_execution_token,
   p_global_lease_token,p_route_lease_token,p_global_fence_token)
  and (p_after_workshop is null or snapshot.workshop_id>p_after_workshop)
  and p_limit between 1 and 500 order by snapshot.workshop_id limit p_limit
$function$;

create function control.record_route_set_startup_entry(
 p_publication_id uuid,p_instance_owner uuid,p_execution_token uuid,
 p_global_lease_token uuid,p_route_lease_token uuid,p_global_fence_token bigint,
 p_workshop_id uuid,p_generation bigint,p_projection_digest text,p_disposition text,
 p_baseline_applied_rendered_digest text,p_route_fence_token bigint,
 p_runtime_outcome text,p_runtime_evidence jsonb,p_rendered_digest text
) returns text language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_publication control.workshop_route_set_publications%rowtype;
 v_snapshot control.workshop_route_set_publication_snapshot%rowtype;
 v_runtime control.workshop_route_set_startup_runtime_snapshot%rowtype;
 v_metadata control.workshop_route_set_startup_metadata%rowtype;
 v_existing control.workshop_route_set_publication_records%rowtype;
 v_expected uuid; v_keys integer; v_changed integer; v_effect_evidence jsonb;
begin
 if p_rendered_digest is null or p_rendered_digest !~ '^sha256:[0-9a-f]{64}$'
  or jsonb_typeof(p_runtime_evidence) is distinct from 'object'
  or pg_column_size(p_runtime_evidence)>16384 then return 'invalid'; end if;
 if not control.lock_route_set_startup_authority(p_publication_id,p_instance_owner,p_execution_token,
  p_global_lease_token,p_route_lease_token,p_global_fence_token) then return 'authority_lost'; end if;
 select * into v_existing from control.workshop_route_set_publication_records
  where publication_id=p_publication_id and workshop_id=p_workshop_id;
 if found then
  select * into v_runtime from control.workshop_route_set_startup_runtime_snapshot
   where publication_id=p_publication_id and workshop_id=p_workshop_id;
  return case when v_existing.generation=p_generation
   and v_existing.projection_digest=p_projection_digest and v_existing.disposition=p_disposition
   and v_existing.applied_rendered_digest is not distinct from p_baseline_applied_rendered_digest
   and v_existing.rendered_digest=p_rendered_digest and found
   and v_runtime.route_fence_token=p_route_fence_token and v_runtime.recorded_at is not null
   and v_runtime.runtime_outcome=p_runtime_outcome
   and v_runtime.runtime_evidence=p_runtime_evidence then 'replay' else 'conflict' end;
 end if;
 select * into strict v_publication from control.workshop_route_set_publications
  where publication_id=p_publication_id;
 if v_publication.phase<>'staging' or v_publication.prior_recorded_at is null then return 'wrong_phase'; end if;
 select snapshot.workshop_id into v_expected from control.workshop_route_set_publication_snapshot snapshot
 where snapshot.publication_id=p_publication_id and not exists(
  select 1 from control.workshop_route_set_publication_records record
  where record.publication_id=snapshot.publication_id and record.workshop_id=snapshot.workshop_id)
 order by snapshot.workshop_id limit 1;
 if v_expected is distinct from p_workshop_id then return 'out_of_order'; end if;
 select * into v_snapshot from control.workshop_route_set_publication_snapshot
 where publication_id=p_publication_id and workshop_id=p_workshop_id
  and generation=p_generation and projection_digest=p_projection_digest and disposition=p_disposition
  and baseline_applied_rendered_digest is not distinct from p_baseline_applied_rendered_digest;
 if not found then return 'snapshot_drift'; end if;
 select * into strict v_runtime from control.workshop_route_set_startup_runtime_snapshot
  where publication_id=p_publication_id and workshop_id=p_workshop_id and route_fence_token=p_route_fence_token
  and recorded_at is null for update;
 select * into strict v_metadata from control.workshop_route_set_startup_metadata
  where publication_id=p_publication_id;
 if (p_disposition='absent' and p_rendered_digest<>
   'sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855') then
  return 'render_invariant_mismatch';
 end if;
 select count(*) into v_keys from jsonb_object_keys(p_runtime_evidence);
 if v_keys<>9
  or p_runtime_evidence->'effect_run_id' is distinct from to_jsonb(v_publication.startup_effect_run_id)
  or p_runtime_evidence->'workshop_id' is distinct from to_jsonb(p_workshop_id)
  or p_runtime_evidence->'database_id' is distinct from coalesce(to_jsonb(v_runtime.database_id),'null'::jsonb)
  or p_runtime_evidence->'database_ref' is distinct from coalesce(to_jsonb(v_runtime.database_ref),'null'::jsonb)
  or p_runtime_evidence->'unresolved_operation' is distinct from to_jsonb(v_runtime.unresolved_operation)
  or p_runtime_evidence->>'outcome' is distinct from p_runtime_outcome
  or not (p_runtime_evidence ?& array['odoo_runtime','paperless_runtime','verified_at'])
  or jsonb_typeof(p_runtime_evidence->'verified_at') is distinct from 'string'
  or (v_snapshot.disposition='present' and (p_runtime_outcome<>'ready'
   or p_runtime_evidence->'odoo_runtime' is distinct from jsonb_build_object(
    'slot',v_metadata.active_runtime_slot,'release_id',v_metadata.active_runtime_release_id,
    'subject_digest',v_metadata.active_runtime_subject_digest,
    'deployment_ref',v_metadata.active_runtime_deployment_ref,
    'config_digest',v_metadata.active_runtime_config_digest,
    'slot_version',v_metadata.active_runtime_slot_version)
   or p_runtime_evidence->'paperless_runtime' is distinct from
    case when v_runtime.paperless_mode='absent' then 'null'::jsonb else jsonb_build_object(
     'service_id',v_runtime.paperless_service_id,
     'config_digest',v_runtime.paperless_runtime_spec->>'config_digest') end))
  or (v_snapshot.disposition='absent' and (p_runtime_outcome<>'absent'
   or p_runtime_evidence->'odoo_runtime'<>'null'::jsonb
   or p_runtime_evidence->'paperless_runtime'<>'null'::jsonb)) then return 'runtime_mismatch'; end if;
 insert into control.workshop_route_set_publication_records(publication_id,workshop_id,
  generation,projection_digest,disposition,applied_rendered_digest,rendered_digest)
 values(p_publication_id,p_workshop_id,p_generation,p_projection_digest,p_disposition,
  p_baseline_applied_rendered_digest,p_rendered_digest);
 update control.workshop_route_set_startup_runtime_snapshot set runtime_outcome=p_runtime_outcome,
  runtime_evidence=p_runtime_evidence,recorded_at=now()
  where publication_id=p_publication_id and workshop_id=p_workshop_id and recorded_at is null;
 get diagnostics v_changed=row_count;
 if v_changed<>1 then raise exception 'startup runtime evidence drifted' using errcode='40001'; end if;
 v_effect_evidence:=jsonb_build_object('effect_run_id',v_publication.startup_effect_run_id,
  'workshop_id',p_workshop_id,'generation',p_generation,'projection_digest',p_projection_digest,
  'disposition',p_disposition,'rendered_digest',p_rendered_digest,'route_fence_token',p_route_fence_token);
 update control.workshop_route_effect_reservations set state='candidate',rendered_digest=p_rendered_digest,
  evidence=v_effect_evidence,updated_at=now() where effect_run_id=v_publication.startup_effect_run_id
  and workshop_id=p_workshop_id and state='reserved' and route_fence_token=p_route_fence_token;
 get diagnostics v_changed=row_count;
 if v_changed<>1 then raise exception 'startup effect candidate drifted' using errcode='40001'; end if;
 return 'recorded';
end $function$;

create function control.seal_route_set_startup_publication(
 p_publication_id uuid,p_instance_owner uuid,p_execution_token uuid,
 p_global_lease_token uuid,p_route_lease_token uuid,p_global_fence_token bigint,
 p_candidate_count integer,p_present_count integer,p_route_set_digest text,
 p_candidate_directory_device bigint,p_candidate_directory_inode bigint
) returns text language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_publication control.workshop_route_set_publications%rowtype;
 v_records integer; v_present integer; v_computed text; v_changed integer;
 v_active_count integer; v_metadata control.workshop_route_set_startup_metadata%rowtype;
 v_release_unresolved boolean;
begin
 if p_candidate_count is null or p_candidate_count not between 0 and 500
  or p_present_count is null or p_present_count not between 0 and p_candidate_count
  or p_route_set_digest is null or p_route_set_digest !~ '^sha256:[0-9a-f]{64}$'
  or p_candidate_directory_device is null or p_candidate_directory_device<=0
  or p_candidate_directory_inode is null or p_candidate_directory_inode<=0 then return 'invalid'; end if;
 if not control.lock_route_set_startup_authority(p_publication_id,p_instance_owner,p_execution_token,
  p_global_lease_token,p_route_lease_token,p_global_fence_token) then return 'authority_lost'; end if;
 select * into strict v_publication from control.workshop_route_set_publications
  where publication_id=p_publication_id;
 if v_publication.phase='sealed' then
  return case when v_publication.sealed_count=p_candidate_count
   and v_publication.sealed_present_count=p_present_count
   and v_publication.route_set_digest=p_route_set_digest
   and v_publication.candidate_directory_device=p_candidate_directory_device
   and v_publication.candidate_directory_inode=p_candidate_directory_inode then 'replay' else 'conflict' end;
 end if;
 if v_publication.phase<>'staging' or v_publication.prior_recorded_at is null then return 'wrong_phase'; end if;
 select count(*),count(*) filter(where disposition='present'),control.route_set_publication_digest(p_publication_id)
  into v_records,v_present,v_computed from control.workshop_route_set_publication_records
  where publication_id=p_publication_id;
 if v_records<>p_candidate_count or v_records<>v_publication.snapshot_count
  or v_present<>p_present_count or v_computed is distinct from p_route_set_digest
  or exists(select 1 from control.workshop_route_set_startup_runtime_snapshot
   where publication_id=p_publication_id and recorded_at is null)
  or exists(select 1 from control.workshop_route_set_publication_snapshot snapshot
   join control.workshop_route_projection_state state using(workshop_id)
   where snapshot.publication_id=p_publication_id and (
    state.desired_generation is distinct from snapshot.generation
    or state.desired_digest is distinct from snapshot.projection_digest
    or state.desired_disposition is distinct from snapshot.disposition
    or state.applied_generation is distinct from snapshot.baseline_applied_generation
    or state.applied_digest is distinct from snapshot.baseline_applied_digest
    or state.applied_disposition is distinct from snapshot.baseline_applied_disposition
    or state.applied_rendered_digest is distinct from snapshot.baseline_applied_rendered_digest
    or state.applied_driver_operation_id is distinct from snapshot.baseline_applied_driver_operation_id
    or state.applied_effect_run_id is distinct from snapshot.baseline_applied_effect_run_id
    or state.applied_fence_token is distinct from snapshot.baseline_applied_fence_token)) then
  return 'snapshot_drift';
 end if;
 select * into strict v_metadata from control.workshop_route_set_startup_metadata
  where publication_id=p_publication_id;
 select count(*) into v_active_count from control.runtime_release_slots
  where runtime_key='shared-odoo' and state='active';
 select exists(select 1 from control.release_fleet_runs
  where state in ('preflighting','preparing','paused','activating')) into v_release_unresolved;
 if v_metadata.fleet_release_unresolved is distinct from v_release_unresolved
  or ((v_metadata.active_runtime_slot is null and v_active_count<>0)
   or (v_metadata.active_runtime_slot is not null and (v_active_count<>1 or not exists(
    select 1 from control.runtime_release_slots runtime where runtime.runtime_key='shared-odoo'
     and runtime.state='active' and runtime.slot=v_metadata.active_runtime_slot
     and runtime.release_id=v_metadata.active_runtime_release_id
     and runtime.odoo_subject_digest=v_metadata.active_runtime_subject_digest
     and runtime.evidence->>'runtime_deployment_ref'=v_metadata.active_runtime_deployment_ref
     and runtime.evidence->>'runtime_config_digest'=v_metadata.active_runtime_config_digest
     and runtime.version=v_metadata.active_runtime_slot_version)))) then return 'runtime_drift'; end if;
 update control.workshop_route_set_publications set phase='sealed',sealed_count=p_candidate_count,
  sealed_present_count=p_present_count,route_set_digest=p_route_set_digest,
  candidate_directory_device=p_candidate_directory_device,
  candidate_directory_inode=p_candidate_directory_inode,updated_at=now()
 where publication_id=p_publication_id and phase='staging';
 get diagnostics v_changed=row_count;
 return case when v_changed=1 then 'sealed' else 'conflict' end;
end $function$;

create function control.start_route_set_startup_publication(
 p_publication_id uuid,p_instance_owner uuid,p_execution_token uuid,
 p_global_lease_token uuid,p_route_lease_token uuid,p_global_fence_token bigint
) returns text language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_phase text; v_changed integer;
begin
 if not control.lock_route_set_startup_authority(p_publication_id,p_instance_owner,p_execution_token,
  p_global_lease_token,p_route_lease_token,p_global_fence_token) then return 'authority_lost'; end if;
 select phase into strict v_phase from control.workshop_route_set_publications
  where publication_id=p_publication_id;
 if v_phase='publication_started' then return 'replay'; end if;
 if v_phase<>'sealed' then return 'wrong_phase'; end if;
 update control.workshop_route_set_publications set phase='publication_started',
  publication_started_at=now(),updated_at=now()
  where publication_id=p_publication_id and phase='sealed';
 get diagnostics v_changed=row_count;
 return case when v_changed=1 then 'started' else 'conflict' end;
end $function$;

drop trigger workshop_route_set_publications_phase_monotonic
 on control.workshop_route_set_publications;
create trigger workshop_route_set_publications_phase_monotonic_pre_startup
 before update on control.workshop_route_set_publications for each row
 when (new.publication_kind<>'startup')
 execute function control.validate_route_set_publication_phase_transition();

create function control.validate_route_set_startup_phase_transition()
returns trigger language plpgsql set search_path=pg_catalog,control as $function$
declare v_expected_identity jsonb; v_expected_response jsonb;
 v_exact integer; v_records integer;
begin
 if old.phase='completed' and new is distinct from old then
  raise exception 'completed startup publication evidence is immutable' using errcode='55000';
 end if;
 if new.phase is distinct from old.phase and not (
  (old.phase='staging' and new.phase in ('sealed','quarantined'))
  or (old.phase='sealed' and new.phase in ('publication_started','quarantined'))
  or (old.phase='publication_started' and new.phase in ('observed','quarantined'))
  or (old.phase='observed' and new.phase in ('completed','quarantined'))) then
  raise exception 'invalid startup publication phase transition % -> %',old.phase,new.phase using errcode='55000';
 end if;
 if old.prior_recorded_at is not null and (new.prior_selector is distinct from old.prior_selector
  or new.prior_directory_device is distinct from old.prior_directory_device
  or new.prior_directory_inode is distinct from old.prior_directory_inode
  or new.prior_loaded_identity is distinct from old.prior_loaded_identity
  or new.prior_recorded_at is distinct from old.prior_recorded_at) then
  raise exception 'startup prior evidence is immutable' using errcode='55000';
 end if;
 if old.sealed_count is not null and (new.sealed_count is distinct from old.sealed_count
  or new.sealed_present_count is distinct from old.sealed_present_count
  or new.route_set_digest is distinct from old.route_set_digest
  or new.candidate_directory_device is distinct from old.candidate_directory_device
  or new.candidate_directory_inode is distinct from old.candidate_directory_inode) then
  raise exception 'startup seal evidence is immutable' using errcode='55000';
 end if;
 if old.publication_started_at is not null
  and new.publication_started_at is distinct from old.publication_started_at then
  raise exception 'startup publication-start evidence is immutable' using errcode='55000';
 end if;
 if old.observed_at is not null and (new.observed_selector is distinct from old.observed_selector
  or new.observed_loaded_identity is distinct from old.observed_loaded_identity
  or new.observed_at is distinct from old.observed_at) then
  raise exception 'startup observation evidence is immutable' using errcode='55000';
 end if;
 if old.finished_at is not null and (new.finished_at is distinct from old.finished_at
  or new.final_response is distinct from old.final_response) then
  raise exception 'startup final evidence is immutable' using errcode='55000';
 end if;
 if old.quarantined_at is not null and (new.interrupted_phase is distinct from old.interrupted_phase
  or new.quarantined_at is distinct from old.quarantined_at
  or new.safe_error is distinct from old.safe_error) then
  raise exception 'startup quarantine evidence is immutable' using errcode='55000';
 end if;
 if new.observed_at is not null then
  v_expected_identity:=jsonb_build_object('protocol_version',1,'publication_id',new.publication_id,
   'publication_kind','startup','startup_effect_run_id',new.startup_effect_run_id,
   'global_fence_token',new.original_global_fence_token,'route_set_digest',new.route_set_digest);
  if new.observed_selector is distinct from new.selector
   or new.observed_loaded_identity is distinct from v_expected_identity then
   raise exception 'startup observed identity is not exact' using errcode='55000';
  end if;
 end if;
 if new.phase='completed' then
  v_expected_response:=jsonb_build_object('effect_run_id',new.startup_effect_run_id,
   'global_fence_token',new.original_global_fence_token,'workshop_count',new.snapshot_count,
   'projection_set_digest',new.route_set_digest,'gateway_reload_digest',new.route_set_digest);
  select count(*) into v_records from control.workshop_route_set_publication_records
   where publication_id=new.publication_id;
  select count(*) into v_exact from control.workshop_route_set_publication_snapshot snapshot
  join control.workshop_route_set_publication_records record
   on record.publication_id=snapshot.publication_id and record.workshop_id=snapshot.workshop_id
  join control.workshop_route_set_startup_runtime_snapshot runtime
   on runtime.publication_id=snapshot.publication_id and runtime.workshop_id=snapshot.workshop_id
  join control.workshop_route_projection_state state on state.workshop_id=snapshot.workshop_id
  join control.workshop_route_application_leases lease on lease.workshop_id=snapshot.workshop_id
  where snapshot.publication_id=new.publication_id and state.desired_generation=snapshot.generation
   and state.desired_digest=snapshot.projection_digest and state.desired_disposition=snapshot.disposition
   and state.applied_generation=snapshot.generation and state.applied_digest=snapshot.projection_digest
   and state.applied_disposition=snapshot.disposition
   and state.applied_rendered_digest=record.rendered_digest
   and state.applied_driver_operation_id is null
   and state.applied_effect_run_id=new.startup_effect_run_id
   and state.applied_fence_token=runtime.route_fence_token
   and lease.state='idle' and lease.authority_kind is null
   and lease.driver_operation_id is null and lease.effect_run_id is null
   and lease.release_publication_id is null and lease.route_set_publication_id is null
   and lease.lease_owner is null and lease.lease_token is null and lease.lease_expires_at is null
   and lease.fence_token=runtime.route_fence_token;
  if new.final_response is distinct from v_expected_response or v_records<>new.snapshot_count
   or v_exact<>new.snapshot_count
   or not exists(select 1 from control.workshop_route_effect_runs effect
    where effect.id=new.startup_effect_run_id and effect.kind='startup-rebuild'
     and effect.state='succeeded' and effect.response is not distinct from v_expected_response
     and effect.instance_owner is null and effect.execution_token is null
     and effect.global_lease_token is null and effect.route_lease_token is null
     and effect.lease_expires_at is null and effect.safe_error is null and effect.finished_at is not null)
   or not exists(select 1 from control.deployment_driver_resource_leases lease
    where lease.resource_key='runtime/shared-odoo' and lease.state='idle'
     and lease.authority_kind is null and lease.driver_operation_id is null
     and lease.effect_run_id is null and lease.route_set_publication_id is null
     and lease.lease_owner is null and lease.lease_token is null and lease.lease_expires_at is null
     and lease.fence_token=new.original_global_fence_token) then
   raise exception 'startup final receipt is not exact' using errcode='55000';
  end if;
 end if;
 return new;
end $function$;

create trigger workshop_route_set_publications_phase_monotonic_startup
 before update on control.workshop_route_set_publications for each row
 when (new.publication_kind='startup')
 execute function control.validate_route_set_startup_phase_transition();

create function control.observe_route_set_startup_publication(
 p_publication_id uuid,p_instance_owner uuid,p_execution_token uuid,
 p_global_lease_token uuid,p_route_lease_token uuid,p_global_fence_token bigint,
 p_observed_selector text,p_observed_loaded_identity jsonb
) returns text language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_publication control.workshop_route_set_publications%rowtype;
 v_expected jsonb; v_changed integer;
begin
 if not control.lock_route_set_startup_authority(p_publication_id,p_instance_owner,p_execution_token,
  p_global_lease_token,p_route_lease_token,p_global_fence_token) then return 'authority_lost'; end if;
 select * into strict v_publication from control.workshop_route_set_publications
  where publication_id=p_publication_id;
 v_expected:=jsonb_build_object('protocol_version',1,'publication_id',p_publication_id,
  'publication_kind','startup','startup_effect_run_id',v_publication.startup_effect_run_id,
  'global_fence_token',p_global_fence_token,'route_set_digest',v_publication.route_set_digest);
 if v_publication.phase='observed' then
  return case when v_publication.observed_selector=p_observed_selector
   and v_publication.observed_loaded_identity=p_observed_loaded_identity then 'replay' else 'conflict' end;
 end if;
 if v_publication.phase<>'publication_started' then return 'wrong_phase'; end if;
 if p_observed_selector is distinct from v_publication.selector
  or p_observed_loaded_identity is distinct from v_expected then return 'observation_mismatch'; end if;
 update control.workshop_route_set_publications set phase='observed',
  observed_selector=p_observed_selector,observed_loaded_identity=p_observed_loaded_identity,
  observed_at=now(),updated_at=now() where publication_id=p_publication_id
  and phase='publication_started';
 get diagnostics v_changed=row_count;
 return case when v_changed=1 then 'observed' else 'conflict' end;
end $function$;

create function control.finish_route_set_startup_publication(
 p_publication_id uuid,p_instance_owner uuid,p_execution_token uuid,
 p_global_lease_token uuid,p_route_lease_token uuid,p_global_fence_token bigint
) returns table(outcome text,response jsonb)
language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_publication control.workshop_route_set_publications%rowtype;
 v_response jsonb; v_changed integer;
begin
 select * into v_publication from control.workshop_route_set_publications
  where publication_id=p_publication_id;
 if not found or v_publication.publication_kind<>'startup' then
  return query select 'not_found',null::jsonb; return;
 end if;
 if v_publication.phase='completed' then
  return query select 'replay',v_publication.final_response; return;
 end if;
 if not control.lock_route_set_startup_authority(p_publication_id,p_instance_owner,p_execution_token,
  p_global_lease_token,p_route_lease_token,p_global_fence_token) then
  return query select 'authority_lost',null::jsonb; return;
 end if;
 select * into strict v_publication from control.workshop_route_set_publications
  where publication_id=p_publication_id;
 if v_publication.phase<>'observed' then return query select 'wrong_phase',null::jsonb; return; end if;
 if (select count(*) from control.workshop_route_set_publication_records
   where publication_id=p_publication_id)<>v_publication.snapshot_count
  or exists(select 1 from control.workshop_route_set_publication_snapshot snapshot
   join control.workshop_route_projection_state state using(workshop_id)
   where snapshot.publication_id=p_publication_id and (
    state.desired_generation is distinct from snapshot.generation
    or state.desired_digest is distinct from snapshot.projection_digest
    or state.desired_disposition is distinct from snapshot.disposition
    or state.applied_generation is distinct from snapshot.baseline_applied_generation
    or state.applied_digest is distinct from snapshot.baseline_applied_digest
    or state.applied_disposition is distinct from snapshot.baseline_applied_disposition
    or state.applied_rendered_digest is distinct from snapshot.baseline_applied_rendered_digest
    or state.applied_driver_operation_id is distinct from snapshot.baseline_applied_driver_operation_id
    or state.applied_effect_run_id is distinct from snapshot.baseline_applied_effect_run_id
    or state.applied_fence_token is distinct from snapshot.baseline_applied_fence_token)) then
  return query select 'snapshot_drift',null::jsonb; return;
 end if;
 v_response:=jsonb_build_object('effect_run_id',v_publication.startup_effect_run_id,
  'global_fence_token',v_publication.original_global_fence_token,
  'workshop_count',v_publication.snapshot_count,
  'projection_set_digest',v_publication.route_set_digest,
  'gateway_reload_digest',v_publication.route_set_digest);
 update control.workshop_route_projection_state state set applied_generation=snapshot.generation,
  applied_digest=snapshot.projection_digest,applied_disposition=snapshot.disposition,
  applied_rendered_digest=record.rendered_digest,applied_driver_operation_id=null,
  applied_effect_run_id=v_publication.startup_effect_run_id,
  applied_fence_token=runtime.route_fence_token,updated_at=now()
 from control.workshop_route_set_publication_snapshot snapshot
 join control.workshop_route_set_publication_records record
  on record.publication_id=snapshot.publication_id and record.workshop_id=snapshot.workshop_id
 join control.workshop_route_set_startup_runtime_snapshot runtime
  on runtime.publication_id=snapshot.publication_id and runtime.workshop_id=snapshot.workshop_id
 where snapshot.publication_id=p_publication_id and state.workshop_id=snapshot.workshop_id
  and state.desired_generation=snapshot.generation and state.desired_digest=snapshot.projection_digest
  and state.desired_disposition=snapshot.disposition
  and state.applied_generation is not distinct from snapshot.baseline_applied_generation
  and state.applied_digest is not distinct from snapshot.baseline_applied_digest
  and state.applied_disposition is not distinct from snapshot.baseline_applied_disposition
  and state.applied_rendered_digest is not distinct from snapshot.baseline_applied_rendered_digest
  and state.applied_driver_operation_id is not distinct from snapshot.baseline_applied_driver_operation_id
  and state.applied_effect_run_id is not distinct from snapshot.baseline_applied_effect_run_id
  and state.applied_fence_token is not distinct from snapshot.baseline_applied_fence_token;
 get diagnostics v_changed=row_count;
 if v_changed<>v_publication.snapshot_count then
  raise exception 'startup applied-head finalization drifted' using errcode='40001';
 end if;
 update control.workshop_route_effect_reservations reservation set state='succeeded',updated_at=now()
 from control.workshop_route_set_publication_snapshot snapshot
 where snapshot.publication_id=p_publication_id
  and reservation.effect_run_id=v_publication.startup_effect_run_id
  and reservation.workshop_id=snapshot.workshop_id and reservation.state='candidate';
 get diagnostics v_changed=row_count;
 if v_changed<>v_publication.snapshot_count then raise exception 'startup reservation finalization drifted' using errcode='40001'; end if;
 update control.workshop_route_effect_runs set state='succeeded',instance_owner=null,
  execution_token=null,global_lease_token=null,route_lease_token=null,lease_expires_at=null,
  response=v_response,safe_error=null,finished_at=now(),updated_at=now()
 where id=v_publication.startup_effect_run_id and state='effects_started'
  and instance_owner=p_instance_owner and execution_token=p_execution_token
  and global_lease_token=p_global_lease_token and route_lease_token=p_route_lease_token
  and global_fence_token=p_global_fence_token;
 get diagnostics v_changed=row_count;
 if v_changed<>1 then raise exception 'startup effect finalization drifted' using errcode='40001'; end if;
 update control.workshop_route_application_leases set state='idle',authority_kind=null,
  driver_operation_id=null,effect_run_id=null,release_publication_id=null,route_set_publication_id=null,
  generation=null,projection_digest=null,lease_owner=null,lease_token=null,lease_expires_at=null,
  heartbeat_at=null,quarantined_at=null,safe_error=null,initialization_required=false,updated_at=now()
 where route_set_publication_id=p_publication_id and state='held';
 get diagnostics v_changed=row_count;
 if v_changed<>v_publication.snapshot_count then raise exception 'startup route release drifted' using errcode='40001'; end if;
 update control.deployment_driver_resource_leases set state='idle',authority_kind=null,
  driver_operation_id=null,effect_run_id=null,route_set_publication_id=null,lease_owner=null,
  lease_token=null,lease_expires_at=null,heartbeat_at=null,quarantined_at=null,safe_error=null,
  updated_at=now() where resource_key='runtime/shared-odoo' and state='held'
  and route_set_publication_id=p_publication_id and fence_token=p_global_fence_token;
 get diagnostics v_changed=row_count;
 if v_changed<>1 then raise exception 'startup global release drifted' using errcode='40001'; end if;
 update control.workshop_route_set_publications set phase='completed',finished_at=now(),
  final_response=v_response,updated_at=now() where publication_id=p_publication_id and phase='observed';
 get diagnostics v_changed=row_count;
 if v_changed<>1 then raise exception 'startup publication finalization drifted' using errcode='40001'; end if;
 return query select 'applied',v_response;
end $function$;

create function control.read_route_set_startup_publication_result(
 p_publication_id uuid,p_effect_run_id uuid,p_boot_id uuid
) returns table(outcome text,publication_id uuid,effect_run_id uuid,response jsonb)
language sql stable security definer set search_path=pg_catalog,control as $function$
 select case when publication.phase='completed' and effect.state='succeeded' then 'replay'
   when publication.phase='quarantined' or effect.state='quarantined' then 'fleet_quarantined'
   else 'busy' end,
  publication.publication_id,effect.id,
  case when publication.phase='completed' then publication.final_response end
 from control.workshop_route_set_publications publication
 join control.workshop_route_effect_runs effect on effect.id=publication.startup_effect_run_id
 join control.workshop_route_set_startup_metadata metadata using(publication_id)
 where publication.publication_id=p_publication_id and publication.publication_kind='startup'
  and effect.id=p_effect_run_id and effect.kind='startup-rebuild'
  and metadata.boot_id=p_boot_id and effect.target_key='startup/'||p_boot_id::text
$function$;

create function control.quarantine_route_set_startup_publication(
 p_publication_id uuid,p_instance_owner uuid,p_execution_token uuid,
 p_global_lease_token uuid,p_route_lease_token uuid,p_global_fence_token bigint,
 p_safe_error text
) returns boolean language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_publication control.workshop_route_set_publications%rowtype;
 v_effect control.workshop_route_effect_runs%rowtype;
 v_global control.deployment_driver_resource_leases%rowtype;
 v_expected integer; v_exact integer; v_changed integer; v_expired boolean;
begin
 if p_safe_error is distinct from 'route_set_publication_outcome_unknown' then return false; end if;
 perform 1 from control.route_set_publication_protocol_state where singleton for update;
 select * into v_publication from control.workshop_route_set_publications
  where publication_id=p_publication_id and publication_kind='startup';
 if not found then return false; end if;
 select * into v_global from control.deployment_driver_resource_leases
  where resource_key='runtime/shared-odoo' for update;
 perform 1 from control.workshop_route_application_leases
  where route_set_publication_id=p_publication_id order by workshop_id for update;
 select * into v_effect from control.workshop_route_effect_runs
  where id=v_publication.startup_effect_run_id for update;
 perform 1 from control.workshop_route_effect_reservations
  where effect_run_id=v_effect.id order by workshop_id for update;
 select * into strict v_publication from control.workshop_route_set_publications
  where publication_id=p_publication_id for update;
 if v_publication.original_instance_owner is distinct from p_instance_owner
  or v_publication.original_execution_token is distinct from p_execution_token
  or v_publication.original_global_lease_token is distinct from p_global_lease_token
  or v_publication.original_route_lease_token is distinct from p_route_lease_token
  or v_publication.original_global_fence_token is distinct from p_global_fence_token then return false; end if;
 if v_publication.phase='quarantined' then
  select count(*) into v_exact from control.workshop_route_application_leases
   where route_set_publication_id=p_publication_id and state='quarantined'
    and lease_owner=p_instance_owner and lease_token is null and lease_expires_at is null
    and safe_error='route_set_publication_outcome_unknown';
  return v_global.state='quarantined' and v_global.route_set_publication_id=p_publication_id
   and v_effect.state='quarantined' and v_exact=v_publication.snapshot_count;
 end if;
 if v_publication.phase not in ('staging','sealed','publication_started','observed')
  or v_global.state<>'held' or v_global.authority_kind<>'route-set-publication'
  or v_global.route_set_publication_id<>p_publication_id
  or v_global.lease_owner<>p_instance_owner or v_global.lease_token<>p_global_lease_token
  or v_global.fence_token<>p_global_fence_token
  or v_effect.state not in ('reserved','effects_started')
  or v_effect.instance_owner<>p_instance_owner or v_effect.execution_token<>p_execution_token
  or v_effect.global_lease_token<>p_global_lease_token or v_effect.route_lease_token<>p_route_lease_token then
  return false;
 end if;
 select count(*) into v_expected from control.workshop_route_set_publication_snapshot
  where publication_id=p_publication_id;
 select count(*) into v_exact from control.workshop_route_set_publication_snapshot snapshot
 join control.workshop_route_set_startup_runtime_snapshot runtime
  on runtime.publication_id=snapshot.publication_id and runtime.workshop_id=snapshot.workshop_id
 join control.workshop_route_application_leases lease on lease.workshop_id=snapshot.workshop_id
 where snapshot.publication_id=p_publication_id and lease.state='held'
  and lease.authority_kind='route-set-publication' and lease.route_set_publication_id=p_publication_id
  and lease.lease_owner=p_instance_owner and lease.lease_token=p_route_lease_token
  and lease.fence_token=runtime.route_fence_token;
 if v_expected<>v_publication.snapshot_count or v_exact<>v_expected then return false; end if;
 v_expired:=v_effect.lease_expires_at<=now() or v_global.lease_expires_at<=now()
  or exists(select 1 from control.workshop_route_application_leases
   where route_set_publication_id=p_publication_id and lease_expires_at<=now());
 if v_publication.phase in ('staging','sealed') and not v_expired then return false; end if;
 update control.deployment_driver_resource_leases set state='quarantined',lease_token=null,
  lease_expires_at=null,quarantined_at=now(),safe_error='runtime_outcome_unknown',updated_at=now()
 where resource_key='runtime/shared-odoo' and state='held' and route_set_publication_id=p_publication_id;
 get diagnostics v_changed=row_count;
 if v_changed<>1 then raise exception 'startup global quarantine drifted' using errcode='40001'; end if;
 update control.workshop_route_application_leases set state='quarantined',lease_token=null,
  lease_expires_at=null,quarantined_at=now(),safe_error='route_set_publication_outcome_unknown',updated_at=now()
 where state='held' and route_set_publication_id=p_publication_id;
 get diagnostics v_changed=row_count;
 if v_changed<>v_expected then raise exception 'startup route quarantine drifted' using errcode='40001'; end if;
 update control.workshop_route_effect_reservations set state='quarantined',updated_at=now()
 where effect_run_id=v_effect.id and state in ('reserved','candidate');
 get diagnostics v_changed=row_count;
 if v_changed<>v_expected then raise exception 'startup reservation quarantine drifted' using errcode='40001'; end if;
 update control.workshop_route_effect_runs set state='quarantined',instance_owner=null,
  execution_token=null,global_lease_token=null,route_lease_token=null,lease_expires_at=null,
  safe_error='runtime_outcome_unknown',finished_at=now(),updated_at=now()
 where id=v_effect.id and state in ('reserved','effects_started');
 get diagnostics v_changed=row_count;
 if v_changed<>1 then raise exception 'startup effect quarantine drifted' using errcode='40001'; end if;
 update control.workshop_route_set_publications set interrupted_phase=phase,phase='quarantined',
  quarantined_at=now(),safe_error=p_safe_error,recovery_eligible_at=now(),
  recovery_write_eligible=(publication_started_at is null and phase in ('staging','sealed')),
  updated_at=now() where publication_id=p_publication_id and phase=v_publication.phase;
 get diagnostics v_changed=row_count;
 if v_changed<>1 then raise exception 'startup publication quarantine drifted' using errcode='40001'; end if;
 return true;
end $function$;

create function control.discover_interrupted_route_set_startup_publications(
 p_after_publication_id uuid,p_limit integer
) returns table(publication_id uuid,effect_run_id uuid,interrupted_phase text,
 claim_mode text,selector text,route_set_digest text,snapshot_count integer,updated_at timestamptz)
language sql stable security definer set search_path=pg_catalog,control as $function$
 select publication.publication_id,publication.startup_effect_run_id,publication.interrupted_phase,
  case when publication.recovery_write_eligible and publication.publication_started_at is null
   and publication.interrupted_phase in ('staging','sealed') then 'write_cleanup' else 'observe_only' end,
  publication.selector,publication.route_set_digest,publication.snapshot_count,publication.updated_at
 from control.workshop_route_set_publications publication
 where publication.publication_kind='startup' and publication.phase='quarantined'
  and publication.recovery_terminal_at is null
  and (p_after_publication_id is null or publication.publication_id>p_after_publication_id)
  and p_limit between 1 and 100 order by publication.publication_id limit p_limit
$function$;

create table control.workshop_route_set_startup_recovery_claims (
 publication_id uuid primary key,
 claim_fence bigint not null default 0 check(claim_fence>=0),
 claim_mode text,
 reconciliation_owner uuid,
 reconciliation_token uuid,
 reconciliation_expires_at timestamptz,
 updated_at timestamptz not null default now(),
 constraint workshop_route_set_startup_recovery_claim_publication_fkey
  foreign key(publication_id) references control.workshop_route_set_publications(publication_id) on delete restrict,
 constraint workshop_route_set_startup_recovery_claim_shape check(
  (claim_mode is null and reconciliation_owner is null and reconciliation_token is null
   and reconciliation_expires_at is null)
  or (claim_fence>0 and claim_mode in ('write_cleanup','observe_only')
   and reconciliation_owner is not null and reconciliation_token is not null
   and reconciliation_expires_at is not null))
);

create table control.workshop_route_set_startup_recovery_resolutions (
 publication_id uuid not null,
 claim_fence bigint not null,
 reconciliation_owner uuid not null,
 reconciliation_token_digest text not null,
 claim_mode text not null,
 resolution_kind text not null,
 evidence jsonb not null,
 recorded_at timestamptz not null default now(),
 primary key(publication_id,claim_fence),
 constraint workshop_route_set_startup_resolution_publication_fkey
  foreign key(publication_id) references control.workshop_route_set_publications(publication_id) on delete restrict,
 constraint workshop_route_set_startup_resolution_shape check(
  claim_fence>0 and reconciliation_token_digest ~ '^[0-9a-f]{64}$'
  and claim_mode in ('write_cleanup','observe_only')
  and resolution_kind in ('candidate','prior','unstarted','inconclusive')
  and jsonb_typeof(evidence)='object' and pg_column_size(evidence)<=8192)
);

create table control.workshop_route_set_startup_recovery_terminals (
 publication_id uuid primary key,
 claim_fence bigint not null check(claim_fence>0),
 reconciliation_owner uuid not null,
 resolution_kind text not null check(resolution_kind in ('candidate','prior','unstarted')),
 decision_digest text not null check(decision_digest ~ '^[0-9a-f]{64}$'),
 response jsonb not null check(jsonb_typeof(response)='object' and pg_column_size(response)<=16384),
 terminal_at timestamptz not null default now(),
 constraint workshop_route_set_startup_terminal_publication_fkey
  foreign key(publication_id) references control.workshop_route_set_publications(publication_id) on delete restrict,
 constraint workshop_route_set_startup_terminal_resolution_fkey
  foreign key(publication_id,claim_fence)
  references control.workshop_route_set_startup_recovery_resolutions(publication_id,claim_fence) on delete restrict
);

create trigger workshop_route_set_startup_resolutions_immutable
 before update or delete on control.workshop_route_set_startup_recovery_resolutions
 for each row execute function control.reject_route_set_startup_evidence_mutation();
create trigger workshop_route_set_startup_terminals_immutable
 before update or delete on control.workshop_route_set_startup_recovery_terminals
 for each row execute function control.reject_route_set_startup_evidence_mutation();

revoke all on table control.workshop_route_set_startup_recovery_claims from public;
revoke all on table control.workshop_route_set_startup_recovery_resolutions from public;
revoke all on table control.workshop_route_set_startup_recovery_terminals from public;

create or replace function control.discover_interrupted_route_set_startup_publications(
 p_after_publication_id uuid,p_limit integer
) returns table(publication_id uuid,effect_run_id uuid,interrupted_phase text,
 claim_mode text,selector text,route_set_digest text,snapshot_count integer,updated_at timestamptz)
language sql stable security definer set search_path=pg_catalog,control as $function$
 select publication.publication_id,publication.startup_effect_run_id,publication.interrupted_phase,
  case when publication.recovery_write_eligible and publication.publication_started_at is null
   and publication.interrupted_phase in ('staging','sealed') then 'write_cleanup' else 'observe_only' end,
  publication.selector,publication.route_set_digest,publication.snapshot_count,publication.updated_at
 from control.workshop_route_set_publications publication
 left join control.workshop_route_set_startup_recovery_terminals terminal using(publication_id)
 where publication.publication_kind='startup' and publication.phase='quarantined'
  and terminal.publication_id is null
  and (p_after_publication_id is null or publication.publication_id>p_after_publication_id)
  and p_limit between 1 and 100 order by publication.publication_id limit p_limit
$function$;

create function control.claim_interrupted_route_set_startup_publication(
 p_publication_id uuid,p_reconciliation_owner uuid,p_reconciliation_token uuid,p_ttl_seconds integer
) returns table(outcome text,claim_fence bigint,claim_mode text)
language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_publication control.workshop_route_set_publications%rowtype;
 v_effect control.workshop_route_effect_runs%rowtype;
 v_global control.deployment_driver_resource_leases%rowtype;
 v_claim control.workshop_route_set_startup_recovery_claims%rowtype;
 v_mode text; v_fence bigint; v_changed integer; v_exact integer;
begin
 if p_publication_id is null or p_reconciliation_owner is null or p_reconciliation_token is null
  or p_ttl_seconds is null or p_ttl_seconds not between 60 and 1200 then
  return query select 'invalid',null::bigint,null::text; return;
 end if;
 perform 1 from control.route_set_publication_protocol_state where singleton for update;
 select * into v_publication from control.workshop_route_set_publications
  where publication_id=p_publication_id and publication_kind='startup';
 if not found then return query select 'not_found',null::bigint,null::text; return; end if;
 select * into v_global from control.deployment_driver_resource_leases
  where resource_key='runtime/shared-odoo' for update;
 perform 1 from control.workshop_route_application_leases
  where route_set_publication_id=p_publication_id order by workshop_id for update;
 select * into v_effect from control.workshop_route_effect_runs
  where id=v_publication.startup_effect_run_id for update;
 perform 1 from control.workshop_route_effect_reservations
  where effect_run_id=v_effect.id order by workshop_id for update;
 select * into strict v_publication from control.workshop_route_set_publications
  where publication_id=p_publication_id for update;
 if exists(select 1 from control.workshop_route_set_startup_recovery_terminals
  where publication_id=p_publication_id) then
  return query select 'terminal',null::bigint,null::text; return;
 end if;
 if v_publication.phase<>'quarantined' then
  if v_publication.phase not in ('staging','sealed','publication_started','observed')
   or v_effect.state not in ('reserved','effects_started') or v_global.state<>'held'
   or v_global.route_set_publication_id<>p_publication_id
   or v_effect.lease_expires_at>now() or v_global.lease_expires_at>now()
   or exists(select 1 from control.workshop_route_application_leases
    where route_set_publication_id=p_publication_id and lease_expires_at>now()) then
   return query select 'not_expired',null::bigint,null::text; return;
  end if;
  if not control.quarantine_route_set_startup_publication(p_publication_id,
   v_publication.original_instance_owner,v_publication.original_execution_token,
   v_publication.original_global_lease_token,v_publication.original_route_lease_token,
   v_publication.original_global_fence_token,'route_set_publication_outcome_unknown') then
   return query select 'authority_inconsistent',null::bigint,null::text; return;
  end if;
  select * into strict v_publication from control.workshop_route_set_publications
   where publication_id=p_publication_id;
 else
  select count(*) into v_exact from control.workshop_route_application_leases
   where route_set_publication_id=p_publication_id and state='quarantined';
  if v_global.state<>'quarantined' or v_global.route_set_publication_id<>p_publication_id
   or v_effect.state<>'quarantined' or v_exact<>v_publication.snapshot_count then
   return query select 'authority_inconsistent',null::bigint,null::text; return;
  end if;
 end if;
 insert into control.workshop_route_set_startup_recovery_claims(publication_id)
 values(p_publication_id) on conflict(publication_id) do nothing;
 select * into strict v_claim from control.workshop_route_set_startup_recovery_claims
  where publication_id=p_publication_id for update;
 if v_claim.reconciliation_owner is not null and v_claim.reconciliation_expires_at>now() then
  if v_claim.reconciliation_owner=p_reconciliation_owner
   and v_claim.reconciliation_token=p_reconciliation_token then
   return query select 'replay',v_claim.claim_fence,v_claim.claim_mode;
  else return query select 'busy',v_claim.claim_fence,v_claim.claim_mode; end if;
  return;
 end if;
 v_mode:=case when v_publication.recovery_write_eligible
  and v_publication.publication_started_at is null
  and v_publication.interrupted_phase in ('staging','sealed') then 'write_cleanup' else 'observe_only' end;
 v_fence:=v_claim.claim_fence+1;
 update control.workshop_route_set_startup_recovery_claims set claim_fence=v_fence,
  claim_mode=v_mode,reconciliation_owner=p_reconciliation_owner,
  reconciliation_token=p_reconciliation_token,
  reconciliation_expires_at=now()+make_interval(secs=>p_ttl_seconds),updated_at=now()
  where publication_id=p_publication_id
   and (reconciliation_owner is null or reconciliation_expires_at<=now());
 get diagnostics v_changed=row_count;
 if v_changed<>1 then raise exception 'startup recovery claim drifted' using errcode='40001'; end if;
 return query select 'acquired',v_fence,v_mode;
end $function$;

create function control.read_interrupted_route_set_startup_publication_state(
 p_publication_id uuid,p_reconciliation_owner uuid,p_reconciliation_token uuid,p_claim_fence bigint
) returns table(outcome text,state jsonb)
language plpgsql stable security definer set search_path=pg_catalog,control as $function$
declare v_publication control.workshop_route_set_publications%rowtype;
 v_claim control.workshop_route_set_startup_recovery_claims%rowtype;
begin
 select * into v_claim from control.workshop_route_set_startup_recovery_claims
  where publication_id=p_publication_id and claim_fence=p_claim_fence
   and reconciliation_owner=p_reconciliation_owner and reconciliation_token=p_reconciliation_token
   and reconciliation_expires_at>now();
 if not found then return query select 'claim_lost',null::jsonb; return; end if;
 select * into v_publication from control.workshop_route_set_publications
  where publication_id=p_publication_id and publication_kind='startup' and phase='quarantined';
 if not found then return query select 'not_found',null::jsonb; return; end if;
 return query select 'claimed',jsonb_build_object(
  'protocol_version',v_publication.protocol_version,'publication_id',v_publication.publication_id,
  'publication_kind','startup','startup_effect_run_id',v_publication.startup_effect_run_id,
  'interrupted_phase',v_publication.interrupted_phase,'claim_mode',v_claim.claim_mode,
  'claim_fence',v_claim.claim_fence,'selector',v_publication.selector,
  'snapshot_count',v_publication.snapshot_count,'route_set_digest',v_publication.route_set_digest,
  'prior_selector',v_publication.prior_selector,
  'prior_directory_device',v_publication.prior_directory_device,
  'prior_directory_inode',v_publication.prior_directory_inode,
  'prior_loaded_identity',v_publication.prior_loaded_identity,
  'candidate_directory_device',v_publication.candidate_directory_device,
  'candidate_directory_inode',v_publication.candidate_directory_inode,
  'observed_selector',v_publication.observed_selector,
  'observed_loaded_identity',v_publication.observed_loaded_identity);
end $function$;

create function control.resolve_interrupted_route_set_startup_publication_observation(
 p_publication_id uuid,p_reconciliation_owner uuid,p_reconciliation_token uuid,
 p_claim_fence bigint,p_resolution_kind text,p_evidence jsonb
) returns text language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_publication control.workshop_route_set_publications%rowtype;
 v_claim control.workshop_route_set_startup_recovery_claims%rowtype;
 v_expected_identity jsonb; v_keys integer;
begin
 if p_resolution_kind not in ('candidate','prior','unstarted','inconclusive')
  or jsonb_typeof(p_evidence) is distinct from 'object' or pg_column_size(p_evidence)>8192 then
  return 'invalid'; end if;
 perform 1 from control.route_set_publication_protocol_state where singleton for update;
 select * into v_claim from control.workshop_route_set_startup_recovery_claims
  where publication_id=p_publication_id and claim_fence=p_claim_fence
   and reconciliation_owner=p_reconciliation_owner and reconciliation_token=p_reconciliation_token
   and reconciliation_expires_at>now() for update;
 if not found then return 'claim_lost'; end if;
 select * into v_publication from control.workshop_route_set_publications
  where publication_id=p_publication_id and publication_kind='startup' and phase='quarantined' for update;
 if not found then return 'not_found'; end if;
 if exists(select 1 from control.workshop_route_set_startup_recovery_resolutions
  where publication_id=p_publication_id and claim_fence=p_claim_fence) then
  return case when exists(select 1 from control.workshop_route_set_startup_recovery_resolutions
   where publication_id=p_publication_id and claim_fence=p_claim_fence
    and reconciliation_owner=p_reconciliation_owner and resolution_kind=p_resolution_kind
    and evidence=p_evidence) then 'replay' else 'conflict' end;
 end if;
 select count(*) into v_keys from jsonb_object_keys(p_evidence);
 if v_keys<>6 or p_evidence->>'publication_id' is distinct from p_publication_id::text
  or p_evidence->>'resolution_kind' is distinct from p_resolution_kind
  or not (p_evidence ?& array['observed_selector','observed_directory_device',
   'observed_directory_inode','observed_loaded_identity']) then return 'invalid'; end if;
 v_expected_identity:=jsonb_build_object('protocol_version',1,'publication_id',p_publication_id,
  'publication_kind','startup','startup_effect_run_id',v_publication.startup_effect_run_id,
  'global_fence_token',v_publication.original_global_fence_token,
  'route_set_digest',v_publication.route_set_digest);
 if p_resolution_kind='candidate' and (
   v_claim.claim_mode<>'observe_only'
   or v_publication.interrupted_phase not in ('publication_started','observed')
   or jsonb_typeof(p_evidence->'observed_selector') is distinct from 'string'
   or jsonb_typeof(p_evidence->'observed_directory_device') is distinct from 'number'
   or jsonb_typeof(p_evidence->'observed_directory_inode') is distinct from 'number'
   or jsonb_typeof(p_evidence->'observed_loaded_identity') is distinct from 'object'
   or (p_evidence->>'observed_directory_device') !~ '^[1-9][0-9]{0,18}$'
   or (p_evidence->>'observed_directory_inode') !~ '^[1-9][0-9]{0,18}$'
   or p_evidence->>'observed_selector' is distinct from v_publication.selector
   or p_evidence->>'observed_directory_device' is distinct from v_publication.candidate_directory_device::text
   or p_evidence->>'observed_directory_inode' is distinct from v_publication.candidate_directory_inode::text
   or p_evidence->'observed_loaded_identity' is distinct from v_expected_identity) then
  return 'observation_mismatch';
 elsif p_resolution_kind='prior' and (
   not ((v_claim.claim_mode='write_cleanup' and v_publication.interrupted_phase in ('staging','sealed'))
    or (v_claim.claim_mode='observe_only' and v_publication.interrupted_phase='publication_started'))
   or v_publication.prior_recorded_at is null
   or jsonb_typeof(p_evidence->'observed_selector') is distinct from 'string'
   or jsonb_typeof(p_evidence->'observed_directory_device') is distinct from 'number'
   or jsonb_typeof(p_evidence->'observed_directory_inode') is distinct from 'number'
   or jsonb_typeof(p_evidence->'observed_loaded_identity') not in ('object','null')
   or (p_evidence->>'observed_directory_device') !~ '^[1-9][0-9]{0,18}$'
   or (p_evidence->>'observed_directory_inode') !~ '^[1-9][0-9]{0,18}$'
   or p_evidence->>'observed_selector' is distinct from v_publication.prior_selector
   or p_evidence->>'observed_directory_device' is distinct from v_publication.prior_directory_device::text
   or p_evidence->>'observed_directory_inode' is distinct from v_publication.prior_directory_inode::text
   or p_evidence->'observed_loaded_identity' is distinct from coalesce(v_publication.prior_loaded_identity,'null'::jsonb)) then
  return 'observation_mismatch';
 elsif p_resolution_kind='unstarted' and (
   v_claim.claim_mode<>'write_cleanup' or v_publication.interrupted_phase<>'staging'
   or v_publication.prior_recorded_at is not null or v_publication.sealed_count is not null
   or v_publication.publication_started_at is not null or v_publication.observed_at is not null
   or exists(select 1 from control.workshop_route_set_publication_records
      where publication_id=p_publication_id)
   or p_evidence->'observed_selector' is distinct from 'null'::jsonb
   or p_evidence->'observed_directory_device' is distinct from 'null'::jsonb
   or p_evidence->'observed_directory_inode' is distinct from 'null'::jsonb
   or p_evidence->'observed_loaded_identity' is distinct from 'null'::jsonb) then
  return 'observation_mismatch';
 elsif p_resolution_kind='inconclusive' and (
   p_evidence->'observed_selector' is null or p_evidence->'observed_directory_device' is null
   or p_evidence->'observed_directory_inode' is null or p_evidence->'observed_loaded_identity' is null) then
  return 'invalid';
 end if;
 insert into control.workshop_route_set_startup_recovery_resolutions(publication_id,claim_fence,
  reconciliation_owner,reconciliation_token_digest,claim_mode,resolution_kind,evidence)
 values(p_publication_id,p_claim_fence,p_reconciliation_owner,
  encode(public.digest(uuid_send(p_reconciliation_token),'sha256'),'hex'),
  v_claim.claim_mode,p_resolution_kind,p_evidence);
 return 'recorded';
end $function$;

create function control.route_set_startup_terminal_decision_digest(
 p_publication_id uuid,p_claim_fence bigint,p_reconciliation_owner uuid,
 p_resolution_kind text,p_decision text
) returns text language sql immutable strict parallel safe set search_path=pg_catalog,control as $function$
 select encode(public.digest(convert_to('mb-route-set-startup-terminal-v1','UTF8')||decode('00','hex')
  ||uuid_send(p_publication_id)||int8send(p_claim_fence)||uuid_send(p_reconciliation_owner)
  ||int4send(octet_length(convert_to(p_resolution_kind,'UTF8')))||convert_to(p_resolution_kind,'UTF8')
  ||int4send(octet_length(convert_to(p_decision,'UTF8')))||convert_to(p_decision,'UTF8'),'sha256'),'hex')
$function$;

create function control.finish_route_set_startup_publication_recovery(
 p_publication_id uuid,p_claim_fence bigint,p_reconciliation_owner uuid,
 p_reconciliation_token uuid,p_resolution_kind text,p_decision text,p_decision_digest text
) returns table(outcome text,response jsonb)
language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_publication control.workshop_route_set_publications%rowtype;
 v_claim control.workshop_route_set_startup_recovery_claims%rowtype;
 v_resolution control.workshop_route_set_startup_recovery_resolutions%rowtype;
 v_effect control.workshop_route_effect_runs%rowtype; v_response jsonb;
 v_changed integer; v_exact integer;
begin
 if p_resolution_kind not in ('candidate','prior','unstarted')
  or p_decision is distinct from (case when p_resolution_kind='candidate'
    then 'finish_candidate' else 'cancel_unstarted' end)
  or p_decision_digest is distinct from control.route_set_startup_terminal_decision_digest(
   p_publication_id,p_claim_fence,p_reconciliation_owner,p_resolution_kind,p_decision) then
  return query select 'invalid',null::jsonb; return;
 end if;
 perform 1 from control.route_set_publication_protocol_state where singleton for update;
 select * into v_publication from control.workshop_route_set_publications
  where publication_id=p_publication_id and publication_kind='startup';
 if not found then return query select 'not_found',null::jsonb; return; end if;
 perform 1 from control.deployment_driver_resource_leases
  where resource_key='runtime/shared-odoo' for update;
 perform 1 from control.workshop_route_application_leases
  where route_set_publication_id=p_publication_id order by workshop_id for update;
 select * into v_effect from control.workshop_route_effect_runs
  where id=v_publication.startup_effect_run_id for update;
 perform 1 from control.workshop_route_effect_reservations
  where effect_run_id=v_effect.id order by workshop_id for update;
 select * into strict v_publication from control.workshop_route_set_publications
  where publication_id=p_publication_id for update;
 select * into v_claim from control.workshop_route_set_startup_recovery_claims
  where publication_id=p_publication_id and claim_fence=p_claim_fence
   and reconciliation_owner=p_reconciliation_owner and reconciliation_token=p_reconciliation_token
   and reconciliation_expires_at>now() for update;
 if not found then return query select 'claim_lost',null::jsonb; return; end if;
 select * into v_resolution from control.workshop_route_set_startup_recovery_resolutions
  where publication_id=p_publication_id and claim_fence=p_claim_fence
   and reconciliation_owner=p_reconciliation_owner and resolution_kind=p_resolution_kind;
 if not found then return query select 'observation_absent',null::jsonb; return; end if;
 select terminal.response into v_response
 from control.workshop_route_set_startup_recovery_terminals terminal
 where terminal.publication_id=p_publication_id;
 if found then return query select 'replay',v_response; return; end if;
 if v_publication.phase<>'quarantined' or v_effect.state<>'quarantined'
  or exists(select 1 from control.workshop_route_application_leases
   where route_set_publication_id=p_publication_id and state<>'quarantined')
  or not exists(select 1 from control.deployment_driver_resource_leases
   where resource_key='runtime/shared-odoo' and state='quarantined'
    and route_set_publication_id=p_publication_id) then
  return query select 'authority_inconsistent',null::jsonb; return;
 end if;
 if p_resolution_kind='candidate' then
  if v_publication.interrupted_phase not in ('publication_started','observed')
   or v_resolution.claim_mode<>'observe_only'
   or (select count(*) from control.workshop_route_set_publication_records
      where publication_id=p_publication_id)<>v_publication.snapshot_count
   or exists(select 1 from control.workshop_route_set_publication_snapshot snapshot
    join control.workshop_route_projection_state state using(workshop_id)
    where snapshot.publication_id=p_publication_id and (
     state.desired_generation is distinct from snapshot.generation
     or state.desired_digest is distinct from snapshot.projection_digest
     or state.desired_disposition is distinct from snapshot.disposition
     or state.applied_generation is distinct from snapshot.baseline_applied_generation
     or state.applied_digest is distinct from snapshot.baseline_applied_digest
     or state.applied_disposition is distinct from snapshot.baseline_applied_disposition
     or state.applied_rendered_digest is distinct from snapshot.baseline_applied_rendered_digest
     or state.applied_driver_operation_id is distinct from snapshot.baseline_applied_driver_operation_id
     or state.applied_effect_run_id is distinct from snapshot.baseline_applied_effect_run_id
     or state.applied_fence_token is distinct from snapshot.baseline_applied_fence_token)) then
   return query select 'snapshot_drift',null::jsonb; return;
  end if;
  v_response:=jsonb_build_object('effect_run_id',v_publication.startup_effect_run_id,
   'global_fence_token',v_publication.original_global_fence_token,
   'workshop_count',v_publication.snapshot_count,
   'projection_set_digest',v_publication.route_set_digest,
   'gateway_reload_digest',v_publication.route_set_digest);
  update control.workshop_route_projection_state state set applied_generation=snapshot.generation,
   applied_digest=snapshot.projection_digest,applied_disposition=snapshot.disposition,
   applied_rendered_digest=record.rendered_digest,applied_driver_operation_id=null,
   applied_effect_run_id=v_publication.startup_effect_run_id,
   applied_fence_token=runtime.route_fence_token,updated_at=now()
  from control.workshop_route_set_publication_snapshot snapshot
  join control.workshop_route_set_publication_records record
   on record.publication_id=snapshot.publication_id and record.workshop_id=snapshot.workshop_id
  join control.workshop_route_set_startup_runtime_snapshot runtime
   on runtime.publication_id=snapshot.publication_id and runtime.workshop_id=snapshot.workshop_id
  where snapshot.publication_id=p_publication_id and state.workshop_id=snapshot.workshop_id
   and state.desired_generation=snapshot.generation and state.desired_digest=snapshot.projection_digest
   and state.desired_disposition=snapshot.disposition
   and state.applied_generation is not distinct from snapshot.baseline_applied_generation
   and state.applied_digest is not distinct from snapshot.baseline_applied_digest
   and state.applied_disposition is not distinct from snapshot.baseline_applied_disposition
   and state.applied_rendered_digest is not distinct from snapshot.baseline_applied_rendered_digest
   and state.applied_driver_operation_id is not distinct from snapshot.baseline_applied_driver_operation_id
   and state.applied_effect_run_id is not distinct from snapshot.baseline_applied_effect_run_id
   and state.applied_fence_token is not distinct from snapshot.baseline_applied_fence_token;
  get diagnostics v_changed=row_count;
  if v_changed<>v_publication.snapshot_count then raise exception 'startup recovery applied-head drifted' using errcode='40001'; end if;
  update control.workshop_route_effect_runs set state='succeeded',safe_error=null,response=v_response,
   updated_at=now() where id=v_effect.id and state='quarantined';
 else
  if not ((v_resolution.claim_mode='write_cleanup'
     and v_publication.interrupted_phase in ('staging','sealed'))
    or (p_resolution_kind='prior' and v_resolution.claim_mode='observe_only'
     and v_publication.interrupted_phase='publication_started')) then
   return query select 'observation_mismatch',null::jsonb; return;
  end if;
  v_response:=jsonb_build_object('outcome','not_applied','publication_id',p_publication_id,
   'effect_run_id',v_publication.startup_effect_run_id,'resolution_kind',p_resolution_kind,
   'decision_digest',p_decision_digest);
  update control.workshop_route_effect_runs set state='cancelled',safe_error=null,response=null,
   updated_at=now() where id=v_effect.id and state='quarantined';
 end if;
 get diagnostics v_changed=row_count;
 if v_changed<>1 then raise exception 'startup recovery effect terminal drifted' using errcode='40001'; end if;
 if p_resolution_kind='candidate' then
  update control.workshop_route_effect_reservations set state='succeeded',updated_at=now()
   where effect_run_id=v_effect.id and state='quarantined';
  get diagnostics v_changed=row_count;
  if v_changed<>v_publication.snapshot_count then
   raise exception 'startup recovery candidate reservations drifted' using errcode='40001';
  end if;
  update control.workshop_route_application_leases set state='idle',authority_kind=null,
   driver_operation_id=null,effect_run_id=null,release_publication_id=null,route_set_publication_id=null,
   generation=null,projection_digest=null,lease_owner=null,lease_token=null,lease_expires_at=null,
   heartbeat_at=null,quarantined_at=null,safe_error=null,initialization_required=false,updated_at=now()
  where route_set_publication_id=p_publication_id and state='quarantined';
  get diagnostics v_changed=row_count;
  if v_changed<>v_publication.snapshot_count then
   raise exception 'startup recovery candidate routes drifted' using errcode='40001';
  end if;
 else
  update control.workshop_route_effect_reservations set state='restored',updated_at=now()
   where effect_run_id=v_effect.id and state='quarantined';
  get diagnostics v_changed=row_count;
  if v_changed<>v_publication.snapshot_count then
   raise exception 'startup recovery restored reservations drifted' using errcode='40001';
  end if;
  update control.workshop_route_application_leases lease set state=reservation.prior_lease_state,
   authority_kind=null,driver_operation_id=null,effect_run_id=null,release_publication_id=null,
   route_set_publication_id=null,generation=null,projection_digest=null,lease_owner=null,
   lease_token=null,lease_expires_at=null,heartbeat_at=null,quarantined_at=null,safe_error=null,
   initialization_required=(reservation.prior_lease_state='uninitialized'),updated_at=now()
  from control.workshop_route_effect_reservations reservation
  where reservation.effect_run_id=v_effect.id and reservation.workshop_id=lease.workshop_id
   and lease.route_set_publication_id=p_publication_id and lease.state='quarantined';
  get diagnostics v_changed=row_count;
  if v_changed<>v_publication.snapshot_count then
   raise exception 'startup recovery prior routes drifted' using errcode='40001';
  end if;
 end if;
 update control.deployment_driver_resource_leases set state='idle',authority_kind=null,
  driver_operation_id=null,effect_run_id=null,route_set_publication_id=null,lease_owner=null,
  lease_token=null,lease_expires_at=null,heartbeat_at=null,quarantined_at=null,safe_error=null,
  updated_at=now() where resource_key='runtime/shared-odoo' and state='quarantined'
  and route_set_publication_id=p_publication_id;
 get diagnostics v_changed=row_count;
 if v_changed<>1 then raise exception 'startup recovery global release drifted' using errcode='40001'; end if;
 insert into control.workshop_route_set_startup_recovery_terminals(publication_id,claim_fence,
  reconciliation_owner,resolution_kind,decision_digest,response)
 values(p_publication_id,p_claim_fence,p_reconciliation_owner,p_resolution_kind,p_decision_digest,v_response);
 return query select case when p_resolution_kind='candidate' then 'applied_recovered' else 'not_applied' end,v_response;
end $function$;

create or replace function control.read_route_set_startup_publication_result(
 p_publication_id uuid,p_effect_run_id uuid,p_boot_id uuid
) returns table(outcome text,publication_id uuid,effect_run_id uuid,response jsonb)
language sql stable security definer set search_path=pg_catalog,control as $function$
 select case when terminal.publication_id is not null then
    case when terminal.resolution_kind='candidate' then 'applied_recovered' else 'not_applied' end
   when publication.phase='completed' and effect.state='succeeded' then 'replay'
   when publication.phase='quarantined' or effect.state='quarantined' then 'fleet_quarantined'
   else 'busy' end,
  publication.publication_id,effect.id,
  case when terminal.publication_id is not null then terminal.response
   when publication.phase='completed' then publication.final_response end
 from control.workshop_route_set_publications publication
 join control.workshop_route_effect_runs effect on effect.id=publication.startup_effect_run_id
 join control.workshop_route_set_startup_metadata metadata using(publication_id)
 left join control.workshop_route_set_startup_recovery_terminals terminal using(publication_id)
 where publication.publication_id=p_publication_id and publication.publication_kind='startup'
  and effect.id=p_effect_run_id and effect.kind='startup-rebuild'
  and metadata.boot_id=p_boot_id and effect.target_key='startup/'||p_boot_id::text
$function$;

-- `boot-live` deliberately has no loaded identity and is accepted only by the
-- fleet startup transition above.  Targeted projection/recovery publishers
-- must clone an identity-bearing generation.
alter function control.record_route_set_publication_prior(
 uuid,uuid,uuid,uuid,uuid,bigint,bigint,text,bigint,bigint,jsonb
) rename to record_route_set_publication_prior_identity_v1;

create function control.record_route_set_publication_prior(
 p_publication_id uuid,p_instance_owner uuid,p_execution_token uuid,p_global_lease_token uuid,
 p_route_lease_token uuid,p_global_fence_token bigint,p_target_route_fence_token bigint,
 p_prior_selector text,p_prior_directory_device bigint,p_prior_directory_inode bigint,
 p_prior_loaded_identity jsonb
) returns text language plpgsql security definer set search_path=pg_catalog,control as $function$
begin
 if p_prior_selector='generations/boot-live' or p_prior_loaded_identity is null then
  return 'invalid';
 end if;
 return control.record_route_set_publication_prior_identity_v1(p_publication_id,p_instance_owner,
  p_execution_token,p_global_lease_token,p_route_lease_token,p_global_fence_token,
  p_target_route_fence_token,p_prior_selector,p_prior_directory_device,p_prior_directory_inode,
  p_prior_loaded_identity);
end $function$;



revoke all on function control.read_route_set_startup_admission(uuid,text,text) from public;
revoke all on function control.admit_route_set_startup_publication(uuid,text,text,uuid,uuid,uuid,uuid,integer,smallint) from public;
revoke all on function control.has_route_set_startup_authority(uuid,uuid,uuid,uuid,uuid,bigint) from public;
revoke all on function control.lock_route_set_startup_authority(uuid,uuid,uuid,uuid,uuid,bigint) from public;
revoke all on function control.renew_route_set_startup_publication(uuid,uuid,uuid,uuid,uuid,bigint,integer) from public;
revoke all on function control.record_route_set_startup_prior(uuid,uuid,uuid,uuid,uuid,bigint,text,bigint,bigint,jsonb) from public;
revoke all on function control.read_route_set_startup_snapshot_batch(uuid,uuid,uuid,uuid,uuid,bigint,uuid,integer) from public;
revoke all on function control.record_route_set_startup_entry(uuid,uuid,uuid,uuid,uuid,bigint,uuid,bigint,text,text,text,bigint,text,jsonb,text) from public;
revoke all on function control.seal_route_set_startup_publication(uuid,uuid,uuid,uuid,uuid,bigint,integer,integer,text,bigint,bigint) from public;
revoke all on function control.start_route_set_startup_publication(uuid,uuid,uuid,uuid,uuid,bigint) from public;
revoke all on function control.observe_route_set_startup_publication(uuid,uuid,uuid,uuid,uuid,bigint,text,jsonb) from public;
revoke all on function control.finish_route_set_startup_publication(uuid,uuid,uuid,uuid,uuid,bigint) from public;
revoke all on function control.read_route_set_startup_publication_result(uuid,uuid,uuid) from public;
revoke all on function control.quarantine_route_set_startup_publication(uuid,uuid,uuid,uuid,uuid,bigint,text) from public;
revoke all on function control.discover_interrupted_route_set_startup_publications(uuid,integer) from public;
revoke all on function control.claim_interrupted_route_set_startup_publication(uuid,uuid,uuid,integer) from public;
revoke all on function control.read_interrupted_route_set_startup_publication_state(uuid,uuid,uuid,bigint) from public;
revoke all on function control.resolve_interrupted_route_set_startup_publication_observation(uuid,uuid,uuid,bigint,text,jsonb) from public;
revoke all on function control.route_set_startup_terminal_decision_digest(uuid,bigint,uuid,text,text) from public;
revoke all on function control.finish_route_set_startup_publication_recovery(uuid,bigint,uuid,uuid,text,text,text) from public;
revoke all on function control.record_route_set_publication_prior(uuid,uuid,uuid,uuid,uuid,bigint,bigint,text,bigint,bigint,jsonb) from public;
revoke all on function control.record_route_set_publication_prior_identity_v1(uuid,uuid,uuid,uuid,uuid,bigint,bigint,text,bigint,bigint,jsonb) from public;
revoke all on function control.validate_route_set_startup_phase_transition() from public;
revoke all on function control.validate_route_set_startup_scope() from public;
revoke all on function control.validate_route_set_snapshot_scope() from public;
revoke all on function control.validate_route_set_startup_runtime_update() from public;
revoke all on function control.reject_route_set_startup_evidence_mutation() from public;

do $migration$ declare v_role text; begin
 foreach v_role in array array['control_api','control_tenant_api','control_membership_worker',
  'control_provisioning_worker','control_invoice_worker','control_inventory_worker',
  'control_email_worker','control_reconciliation_worker','control_lifecycle_worker',
  'control_backup_scheduler','control_driver_ledger','control_release_worker','control_privacy_worker'] loop
  if exists(select 1 from pg_roles where rolname=v_role) then
   execute format('revoke all on table control.workshop_route_set_startup_metadata from %I',v_role);
   execute format('revoke all on table control.workshop_route_set_startup_runtime_snapshot from %I',v_role);
   execute format('revoke all on table control.workshop_route_set_startup_recovery_claims from %I',v_role);
   execute format('revoke all on table control.workshop_route_set_startup_recovery_resolutions from %I',v_role);
   execute format('revoke all on table control.workshop_route_set_startup_recovery_terminals from %I',v_role);
   execute format('revoke all on function control.has_route_set_startup_authority(uuid,uuid,uuid,uuid,uuid,bigint) from %I',v_role);
   execute format('revoke all on function control.lock_route_set_startup_authority(uuid,uuid,uuid,uuid,uuid,bigint) from %I',v_role);
   execute format('revoke all on function control.record_route_set_publication_prior_identity_v1(uuid,uuid,uuid,uuid,uuid,bigint,bigint,text,bigint,bigint,jsonb) from %I',v_role);
  end if;
 end loop;
 if exists(select 1 from pg_roles where rolname='control_driver_ledger') then
  grant execute on function control.read_route_set_startup_admission(uuid,text,text),
   control.admit_route_set_startup_publication(uuid,text,text,uuid,uuid,uuid,uuid,integer,smallint),
   control.renew_route_set_startup_publication(uuid,uuid,uuid,uuid,uuid,bigint,integer),
   control.record_route_set_startup_prior(uuid,uuid,uuid,uuid,uuid,bigint,text,bigint,bigint,jsonb),
   control.read_route_set_startup_snapshot_batch(uuid,uuid,uuid,uuid,uuid,bigint,uuid,integer),
   control.record_route_set_startup_entry(uuid,uuid,uuid,uuid,uuid,bigint,uuid,bigint,text,text,text,bigint,text,jsonb,text),
   control.seal_route_set_startup_publication(uuid,uuid,uuid,uuid,uuid,bigint,integer,integer,text,bigint,bigint),
   control.start_route_set_startup_publication(uuid,uuid,uuid,uuid,uuid,bigint),
   control.observe_route_set_startup_publication(uuid,uuid,uuid,uuid,uuid,bigint,text,jsonb),
   control.finish_route_set_startup_publication(uuid,uuid,uuid,uuid,uuid,bigint),
   control.read_route_set_startup_publication_result(uuid,uuid,uuid),
   control.quarantine_route_set_startup_publication(uuid,uuid,uuid,uuid,uuid,bigint,text),
   control.discover_interrupted_route_set_startup_publications(uuid,integer),
   control.claim_interrupted_route_set_startup_publication(uuid,uuid,uuid,integer),
   control.read_interrupted_route_set_startup_publication_state(uuid,uuid,uuid,bigint),
   control.resolve_interrupted_route_set_startup_publication_observation(uuid,uuid,uuid,bigint,text,jsonb),
   control.route_set_startup_terminal_decision_digest(uuid,bigint,uuid,text,text),
   control.finish_route_set_startup_publication_recovery(uuid,bigint,uuid,uuid,text,text,text)
   ,control.record_route_set_publication_prior(uuid,uuid,uuid,uuid,uuid,bigint,bigint,text,bigint,bigint,jsonb)
  to control_driver_ledger;
 end if;
end $migration$;

comment on table control.workshop_route_set_startup_metadata is
'Dormant immutable fleet startup identity and frozen shared-runtime evidence; no readiness or callsite is activated.';
comment on function control.admit_route_set_startup_publication(uuid,text,text,uuid,uuid,uuid,uuid,integer,smallint) is
'Dormant protocol-v1 fleet startup admission; refuses over 500 workshops without mutation and creates no synthetic target identity.';
comment on function control.finish_route_set_startup_publication(uuid,uuid,uuid,uuid,uuid,bigint) is
'Atomically advances every frozen startup applied head only after exact loaded-generation observation.';
