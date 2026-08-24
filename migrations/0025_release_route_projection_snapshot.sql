-- Freeze the immutable logical route inputs for a future projection-derived
-- release overlay.  This is deliberately an admission/read-only foundation:
-- protocol-v2 does not yet change per-workshop lease state or authorize host
-- effects, so old protocol-v1 binaries remain behavior-compatible.

alter table control.deployment_driver_operations
    add column release_route_snapshot_protocol_version smallint,
    add constraint deployment_driver_operations_release_route_snapshot_protocol_check
        check(release_route_snapshot_protocol_version is null
              or release_route_snapshot_protocol_version=2);

create or replace function control.validate_release_route_snapshot_protocol_update()
returns trigger language plpgsql
set search_path=pg_catalog, control
as $function$
begin
    if old.release_route_snapshot_protocol_version is not null
       and new.release_route_snapshot_protocol_version is distinct from
            old.release_route_snapshot_protocol_version then
        raise exception 'release route snapshot protocol identity is immutable'
            using errcode='55000';
    end if;
    if old.release_route_snapshot_protocol_version is null
       and new.release_route_snapshot_protocol_version is not null
       and not (old.action='release' and old.state='in_progress'
           and old.safe_error is null and old.execution_attempt=1
           and old.execution_token is not null and old.lease_expires_at>now()
           and old.release_executor_protocol_version=1
           and exists(select 1 from control.deployment_driver_resource_leases lease
               where lease.resource_key='runtime/shared-odoo'
                 and lease.state='held' and lease.authority_kind='release'
                 and lease.driver_operation_id=old.id
                 and lease.lease_expires_at>now())) then
        raise exception 'release route snapshot protocol must be bound at fresh admission'
            using errcode='55000';
    end if;
    return new;
end
$function$;

create trigger deployment_driver_release_route_snapshot_protocol_immutable
before update of release_route_snapshot_protocol_version
on control.deployment_driver_operations
for each row execute function control.validate_release_route_snapshot_protocol_update();

create table control.fleet_release_route_snapshots (
    driver_operation_id uuid primary key,
    fleet_run_id uuid not null unique,
    protocol_version smallint not null,
    original_global_fence_token bigint not null,
    snapshot_count integer not null,
    created_at timestamptz not null default now(),
    constraint fleet_release_route_snapshots_operation_fkey
        foreign key(driver_operation_id)
        references control.deployment_driver_operations(id) on delete restrict,
    constraint fleet_release_route_snapshots_run_fkey
        foreign key(fleet_run_id)
        references control.release_fleet_runs(id) on delete restrict,
    constraint fleet_release_route_snapshots_identity_key
        unique(driver_operation_id,fleet_run_id),
    constraint fleet_release_route_snapshots_protocol_check
        check(protocol_version=2),
    constraint fleet_release_route_snapshots_fence_check
        check(original_global_fence_token>0),
    constraint fleet_release_route_snapshots_count_check
        check(snapshot_count between 1 and 500)
);

create table control.fleet_release_route_snapshot_items (
    driver_operation_id uuid not null,
    fleet_run_id uuid not null,
    workshop_id uuid not null,
    database_id uuid not null,
    database_ref text not null,
    paperless_enabled boolean not null,
    generation bigint not null,
    projection_digest text not null,
    disposition text not null,
    canonical_projection jsonb not null,
    applied_rendered_digest text not null,
    applied_fence_token bigint not null,
    route_fence_token bigint not null,
    created_at timestamptz not null default now(),
    primary key(driver_operation_id,workshop_id),
    unique(fleet_run_id,workshop_id),
    unique(driver_operation_id,workshop_id,route_fence_token),
    unique(driver_operation_id,workshop_id,generation,projection_digest,
        applied_rendered_digest),
    unique(driver_operation_id,workshop_id,generation,projection_digest,
        applied_rendered_digest,applied_fence_token,route_fence_token),
    constraint fleet_release_route_snapshot_items_snapshot_fkey
        foreign key(driver_operation_id,fleet_run_id)
        references control.fleet_release_route_snapshots(
            driver_operation_id,fleet_run_id
        ) on delete restrict,
    constraint fleet_release_route_snapshot_items_projection_fkey
        foreign key(workshop_id,generation,projection_digest,disposition)
        references control.workshop_route_projections(
            workshop_id,generation,projection_digest,disposition
        ) on delete restrict,
    constraint fleet_release_route_snapshot_items_generation_check
        check(generation>0),
    constraint fleet_release_route_snapshot_items_projection_digest_check
        check(projection_digest ~ '^sha256:[0-9a-f]{64}$'),
    constraint fleet_release_route_snapshot_items_disposition_check
        check(disposition='present'),
    constraint fleet_release_route_snapshot_items_projection_check
        check(jsonb_typeof(canonical_projection)='object'
              and pg_column_size(canonical_projection)<=1048576),
    constraint fleet_release_route_snapshot_items_rendered_digest_check
        check(applied_rendered_digest ~ '^sha256:[0-9a-f]{64}$'),
    constraint fleet_release_route_snapshot_items_applied_fence_check
        check(applied_fence_token>0),
    constraint fleet_release_route_snapshot_items_route_fence_check
        check(route_fence_token>0),
    constraint fleet_release_route_snapshot_items_database_ref_check
        check(database_ref ~ '^mb_[0-9a-f]{32}$')
);

create or replace function control.reject_fleet_release_route_snapshot_mutation()
returns trigger language plpgsql
set search_path=pg_catalog, control
as $function$
begin
    raise exception 'fleet release route snapshot is immutable' using errcode='55000';
end
$function$;

create trigger fleet_release_route_snapshots_immutable
before update or delete on control.fleet_release_route_snapshots
for each row execute function control.reject_fleet_release_route_snapshot_mutation();
create trigger fleet_release_route_snapshot_items_immutable
before update or delete on control.fleet_release_route_snapshot_items
for each row execute function control.reject_fleet_release_route_snapshot_mutation();

-- Keep the protocol-v1 API intact and add a distinct protocol-v2 overload.
create or replace function control.admit_release_driver_operation(
    p_control_operation_id uuid,p_control_operation_attempt integer,
    p_control_operation_lease_owner text,p_idempotency_key text,p_target_key text,
    p_fleet_run_id uuid,p_request_digest text,p_instance_owner uuid,
    p_execution_token uuid,p_resource_lease_token uuid,p_ttl_seconds integer,
    p_release_executor_protocol_version smallint,
    p_release_route_snapshot_protocol_version smallint
) returns table(outcome text,driver_operation_id uuid,fence_token bigint,
    stored_response jsonb,reserved_workshops uuid[])
language plpgsql security definer
set search_path=pg_catalog, control
as $function$
declare v_row record; v_count integer; v_changed bigint;
begin
    if p_release_executor_protocol_version is distinct from 1
       or p_release_route_snapshot_protocol_version is distinct from 2
       or p_fleet_run_id is null then
        return query select 'invalid'::text,null::uuid,null::bigint,
            null::jsonb,null::uuid[];
        return;
    end if;

    select * into strict v_row from control.admit_release_driver_operation(
        p_control_operation_id,p_control_operation_attempt,
        p_control_operation_lease_owner,p_idempotency_key,p_target_key,
        p_fleet_run_id,p_request_digest,p_instance_owner,p_execution_token,
        p_resource_lease_token,p_ttl_seconds,
        p_release_executor_protocol_version
    );

    if v_row.outcome<>'acquired' then
        if v_row.driver_operation_id is not null and exists(
            select 1 from control.deployment_driver_operations operation
            where operation.id=v_row.driver_operation_id
              and operation.release_route_snapshot_protocol_version is distinct from 2
        ) then
            return query select 'protocol_conflict'::text,v_row.driver_operation_id,
                v_row.fence_token,null::jsonb,v_row.reserved_workshops;
            return;
        end if;
        return query select v_row.outcome,v_row.driver_operation_id,v_row.fence_token,
            v_row.stored_response,v_row.reserved_workshops;
        return;
    end if;

    -- The v1 primitive has already locked control operation, global resource,
    -- fleet run, route rows in UUID order, and the new driver operation.  Freeze
    -- only an exact, currently applied immutable projection for every fleet row.
    if cardinality(v_row.reserved_workshops) not between 1 and 500
       or exists(
            select 1
            from jsonb_array_elements((select tenant_snapshot
                    from control.release_fleet_runs where id=p_fleet_run_id)) item
            left join control.workshop_route_projection_state state
              on state.workshop_id=(item->>'workshop_id')::uuid
            left join control.workshop_route_application_leases lease
              on lease.workshop_id=state.workshop_id
            left join control.workshop_route_projections projection
              on projection.workshop_id=state.workshop_id
             and projection.generation=state.applied_generation
             and projection.projection_digest=state.applied_digest
             and projection.disposition=state.applied_disposition
            where state.workshop_id is null or lease.workshop_id is null
               or lease.state<>'idle' or lease.initialization_required
               or state.desired_generation is distinct from state.applied_generation
               or state.desired_digest is distinct from state.applied_digest
               or state.desired_disposition is distinct from state.applied_disposition
               or state.applied_generation is null
               or state.applied_disposition is distinct from 'present'
               or state.applied_rendered_digest is null
               or state.applied_fence_token is null
               or projection.workshop_id is null
               or projection.projection is null
               or jsonb_typeof(projection.projection)<>'object'
               or (select count(*) from jsonb_object_keys(projection.projection))<>6
               or not (projection.projection ?& array[
                    'database_id','database_ref','public_hostname','paperless_mode',
                    'paperless_hostname','custom_hostnames'])
               or projection.projection->>'database_id' is distinct from item->>'database_id'
               or projection.projection->>'database_ref' is distinct from item->>'database_ref'
               or ((projection.projection->>'paperless_mode')<>'absent') is distinct from
                    ((item->>'paperless_enabled')::boolean)
               or jsonb_typeof(projection.projection->'custom_hostnames')<>'array'
               or exists(
                    select 1 from (
                        select value->>'hostname' hostname,
                               lag(value->>'hostname') over(order by ordinality) prior,
                               value,ordinality
                        from jsonb_array_elements(projection.projection->'custom_hostnames')
                             with ordinality
                    ) custom
                    where jsonb_typeof(custom.value)<>'object'
                       or (select count(*) from jsonb_object_keys(custom.value))<>2
                       or not (custom.value ?& array['hostname','canonical'])
                       or jsonb_typeof(custom.value->'hostname')<>'string'
                       or jsonb_typeof(custom.value->'canonical')<>'boolean'
                       or custom.prior>=custom.hostname
               )
       ) then
        raise exception 'release route snapshot is incomplete, drifted, or noncanonical'
            using errcode='55000';
    end if;

    update control.deployment_driver_operations operation
    set release_route_snapshot_protocol_version=2,updated_at=now()
    where operation.id=v_row.driver_operation_id
      and operation.state='in_progress' and operation.safe_error is null
      and operation.release_executor_protocol_version=1
      and operation.release_route_snapshot_protocol_version is null;
    get diagnostics v_changed=row_count;
    if v_changed<>1 then
        raise exception 'release route snapshot protocol binding was lost'
            using errcode='40001';
    end if;

    insert into control.fleet_release_route_snapshots(
        driver_operation_id,fleet_run_id,protocol_version,
        original_global_fence_token,snapshot_count
    ) values(v_row.driver_operation_id,p_fleet_run_id,2,v_row.fence_token,
        cardinality(v_row.reserved_workshops));

    insert into control.fleet_release_route_snapshot_items(
        driver_operation_id,fleet_run_id,workshop_id,database_id,database_ref,
        paperless_enabled,generation,projection_digest,disposition,
        canonical_projection,applied_rendered_digest,applied_fence_token,
        route_fence_token
    )
    select v_row.driver_operation_id,p_fleet_run_id,
        (item->>'workshop_id')::uuid,(item->>'database_id')::uuid,
        item->>'database_ref',(item->>'paperless_enabled')::boolean,
        state.applied_generation,state.applied_digest,state.applied_disposition,
        projection.projection,state.applied_rendered_digest,state.applied_fence_token,
        lease.fence_token
    from jsonb_array_elements((select tenant_snapshot
            from control.release_fleet_runs where id=p_fleet_run_id)) item
    join control.workshop_route_projection_state state
      on state.workshop_id=(item->>'workshop_id')::uuid
    join control.workshop_route_application_leases lease
      on lease.workshop_id=state.workshop_id
    join control.workshop_route_projections projection
      on projection.workshop_id=state.workshop_id
     and projection.generation=state.applied_generation
     and projection.projection_digest=state.applied_digest
     and projection.disposition=state.applied_disposition
    order by state.workshop_id;
    get diagnostics v_count=row_count;
    if v_count<>cardinality(v_row.reserved_workshops) then
        raise exception 'release route snapshot cardinality drifted' using errcode='40001';
    end if;
    return query select v_row.outcome,v_row.driver_operation_id,v_row.fence_token,
        v_row.stored_response,v_row.reserved_workshops;
end
$function$;

create or replace function control.read_fleet_release_route_snapshot_batch(
    p_driver_operation_id uuid,p_instance_owner uuid,p_execution_token uuid,
    p_resource_lease_token uuid,p_global_fence_token bigint,
    p_after_workshop_id uuid,p_limit integer
) returns table(
    workshop_id uuid,database_id uuid,database_ref text,paperless_enabled boolean,
    generation bigint,projection_digest text,disposition text,
    canonical_projection jsonb,applied_rendered_digest text,applied_fence_token bigint,
    route_fence_token bigint
)
language plpgsql security definer
set search_path=pg_catalog, control
as $function$
begin
    if p_limit is null or p_limit<1 or p_limit>500 then return; end if;
    perform 1
    from control.deployment_driver_operations operation
    join control.deployment_driver_resource_leases lease
      on lease.resource_key='runtime/shared-odoo'
     and lease.driver_operation_id=operation.id
    join control.fleet_release_route_snapshots snapshot
      on snapshot.driver_operation_id=operation.id
    where operation.id=p_driver_operation_id
      and operation.action='release' and operation.state='in_progress'
      and operation.safe_error is null
      and operation.release_executor_protocol_version=1
      and operation.release_route_snapshot_protocol_version=2
      and operation.execution_token=p_execution_token
      and operation.lease_expires_at>now()
      and lease.state='held' and lease.authority_kind='release'
      and lease.lease_owner=p_instance_owner
      and lease.lease_token=p_resource_lease_token
      and lease.fence_token=p_global_fence_token
      and lease.lease_expires_at>now()
      and snapshot.protocol_version=2
      and snapshot.original_global_fence_token=p_global_fence_token;
    if not found then return; end if;
    return query
    select item.workshop_id,item.database_id,item.database_ref,item.paperless_enabled,
        item.generation,item.projection_digest,item.disposition,
        item.canonical_projection,item.applied_rendered_digest,item.applied_fence_token,
        item.route_fence_token
    from control.fleet_release_route_snapshot_items item
    where item.driver_operation_id=p_driver_operation_id
      and (p_after_workshop_id is null or item.workshop_id>p_after_workshop_id)
    order by item.workshop_id limit p_limit;
end
$function$;

revoke all on table control.fleet_release_route_snapshots from public;
revoke all on table control.fleet_release_route_snapshot_items from public;
revoke all on function control.validate_release_route_snapshot_protocol_update() from public;
revoke all on function control.reject_fleet_release_route_snapshot_mutation() from public;
revoke all on function control.admit_release_driver_operation(
    uuid,integer,text,text,text,uuid,text,uuid,uuid,uuid,integer,smallint,smallint
) from public;
revoke all on function control.read_fleet_release_route_snapshot_batch(
    uuid,uuid,uuid,uuid,bigint,uuid,integer
) from public;

do $migration$
begin
    if exists(select 1 from pg_roles where rolname='control_driver_ledger') then
        revoke insert,update,delete on control.fleet_release_route_snapshots,
            control.fleet_release_route_snapshot_items from control_driver_ledger;
        grant execute on function control.admit_release_driver_operation(
            uuid,integer,text,text,text,uuid,text,uuid,uuid,uuid,integer,smallint,smallint
        ) to control_driver_ledger;
        grant execute on function control.read_fleet_release_route_snapshot_batch(
            uuid,uuid,uuid,uuid,bigint,uuid,integer
        ) to control_driver_ledger;
    end if;
end
$migration$;

comment on table control.fleet_release_route_snapshots is
'Protocol-v2 immutable admission identity for a future projection-derived fleet release overlay; this migration does not authorize route host effects.';
comment on table control.fleet_release_route_snapshot_items is
'Exact applied immutable route projections frozen at protocol-v2 release admission; direct runtime-role mutation is denied.';
comment on column control.deployment_driver_operations.release_route_snapshot_protocol_version is
'Version 2 declares the immutable route-snapshot admission contract; NULL preserves protocol-v1 rolling compatibility.';
