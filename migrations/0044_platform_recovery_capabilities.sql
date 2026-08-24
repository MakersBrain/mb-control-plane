-- The platform API needs fleet-wide recovery status reads, but its two recovery
-- writes have closed command shapes. Move those writes behind validated,
-- transaction-participating capabilities before recovery-point RLS is enabled.

create function control.insert_platform_deletion_recovery_point(
    p_recovery_id uuid,
    p_workshop_id uuid,
    p_database_id uuid,
    p_operation_id uuid
) returns uuid
language plpgsql
security definer
set search_path = pg_catalog, control
as $function$
declare
    v_requested_by uuid;
    v_documents_enabled boolean;
begin
    select operation.requested_by
      into v_requested_by
      from control.operations operation
     where operation.id = p_operation_id
       and operation.kind = 'tenant.lifecycle'
       and operation.queue = 'tenant-lifecycle'
       and operation.workshop_id = p_workshop_id
       and operation.requested_by is not null
       and operation.state = 'pending'
       and operation.payload->>'action' = 'delete'
       and operation.payload->>'database_id' = p_database_id::text
       and operation.payload->>'recovery_point_id' = p_recovery_id::text
       and (select count(*) from jsonb_object_keys(operation.payload)) = 3
     for update;
    if not found then
        raise exception using
            errcode = '23514',
            message = 'platform deletion recovery capability rejected';
    end if;

    if not exists (
        select 1
          from control.odoo_databases database
         where database.id = p_database_id
           and database.workshop_id = p_workshop_id
           and database.kind = 'primary'
           and database.deleted_at is null
    ) then
        raise exception using
            errcode = '23514',
            message = 'platform deletion recovery database rejected';
    end if;

    select exists (
        select 1
          from control.workshop_modules module
         where module.workshop_id = p_workshop_id
           and module.module_key = 'documents'
           and module.state = 'enabled'
    ) into v_documents_enabled;

    insert into control.workshop_recovery_points(
        id, workshop_id, database_id, operation_id, kind, label,
        requested_by, component_scope, format_version
    ) values (
        p_recovery_id, p_workshop_id, p_database_id, p_operation_id,
        'backup', 'Final pre-deletion backup', v_requested_by,
        case when v_documents_enabled
             then array['odoo','paperless']::text[]
             else array['odoo']::text[]
        end,
        'mb-workshop-recovery-v2'
    );
    return p_recovery_id;
end
$function$;

create function control.insert_platform_release_recovery_point(
    p_recovery_id uuid,
    p_fleet_run_id uuid,
    p_workshop_id uuid,
    p_database_id uuid,
    p_operation_id uuid,
    p_release_id text
) returns table(recovery_id uuid, source_release_id text)
language plpgsql
security definer
set search_path = pg_catalog, control
as $function$
declare
    v_requested_by uuid;
    v_snapshot jsonb;
    v_tenant jsonb;
    v_source_release text;
    v_database_ref text;
    v_matching_tenants integer;
    v_documents_enabled boolean;
begin
    select operation.requested_by
      into v_requested_by
      from control.operations operation
     where operation.id = p_operation_id
       and operation.kind = 'odoo.release.adopt'
       and operation.queue = 'release-adoption'
       and operation.workshop_id is null
       and operation.requested_by is not null
       and operation.state = 'pending'
       and operation.payload->>'phase' = 'adopt'
       and operation.payload->>'release_id' = p_release_id
       and operation.payload->>'confirmation' = p_release_id
       and (select count(*) from jsonb_object_keys(operation.payload)) = 3
     for update;
    if not found then
        raise exception using
            errcode = '23514',
            message = 'platform release recovery operation rejected';
    end if;

    select fleet.tenant_snapshot
      into v_snapshot
      from control.release_fleet_runs fleet
     where fleet.id = p_fleet_run_id
       and fleet.release_id = p_release_id
       and fleet.operation_id = p_operation_id
       and fleet.state = 'preparing'
     for update;
    if not found or not exists (
        select 1
          from control.application_releases release
         where release.id = p_release_id
           and release.status = 'prepared'
    ) then
        raise exception using
            errcode = '23514',
            message = 'platform release recovery fleet rejected';
    end if;

    select count(*)::integer
      into v_matching_tenants
      from jsonb_array_elements(v_snapshot) tenant
     where tenant->>'workshop_id' = p_workshop_id::text
       and tenant->>'database_id' = p_database_id::text;
    if v_matching_tenants <> 1 then
        raise exception using
            errcode = '23514',
            message = 'platform release recovery tenant rejected';
    end if;

    select tenant
      into v_tenant
      from jsonb_array_elements(v_snapshot) tenant
     where tenant->>'workshop_id' = p_workshop_id::text
       and tenant->>'database_id' = p_database_id::text;
    if jsonb_typeof(v_tenant) is distinct from 'object'
       or (select count(*) from jsonb_object_keys(v_tenant)) <> 4
       or jsonb_typeof(v_tenant->'paperless_enabled') is distinct from 'boolean' then
        raise exception using
            errcode = '23514',
            message = 'platform release recovery snapshot rejected';
    end if;
    v_documents_enabled := (v_tenant->>'paperless_enabled')::boolean;

    select database.database_ref
      into v_database_ref
      from control.odoo_databases database
     where database.id = p_database_id
       and database.workshop_id = p_workshop_id
       and database.kind = 'primary'
       and database.deleted_at is null;
    if not found or v_tenant->>'database_ref' is distinct from v_database_ref then
        raise exception using
            errcode = '23514',
            message = 'platform release recovery database rejected';
    end if;

    select adoption.release_id
      into v_source_release
      from control.tenant_release_adoptions adoption
     where adoption.workshop_id = p_workshop_id
       and adoption.database_id = p_database_id
       and adoption.state = 'active';

    insert into control.workshop_recovery_points(
        id, workshop_id, database_id, operation_id, kind, label,
        requested_by, component_scope, format_version, source_release
    ) values (
        p_recovery_id, p_workshop_id, p_database_id, p_operation_id,
        'backup', 'Pre-release recovery for ' || p_release_id, v_requested_by,
        case when v_documents_enabled
             then array['odoo','paperless']::text[]
             else array['odoo']::text[]
        end,
        'mb-workshop-recovery-v2', v_source_release
    );

    return query select p_recovery_id, v_source_release;
end
$function$;

revoke all on function control.insert_platform_deletion_recovery_point(
    uuid, uuid, uuid, uuid
) from public;
revoke all on function control.insert_platform_release_recovery_point(
    uuid, uuid, uuid, uuid, uuid, text
) from public;

do $migration$
begin
    if exists (select 1 from pg_roles where rolname = 'control_api') then
        revoke insert, update, delete
            on table control.workshop_recovery_points
            from control_api;
        grant select on table control.workshop_recovery_points to control_api;
        grant execute on function control.insert_platform_deletion_recovery_point(
            uuid, uuid, uuid, uuid
        ) to control_api;
        grant execute on function control.insert_platform_release_recovery_point(
            uuid, uuid, uuid, uuid, uuid, text
        ) to control_api;
    end if;
end
$migration$;

comment on function control.insert_platform_deletion_recovery_point(
    uuid, uuid, uuid, uuid
) is 'Insert one final deletion backup only for an exact pending tenant-lifecycle delete operation.';
comment on function control.insert_platform_release_recovery_point(
    uuid, uuid, uuid, uuid, uuid, text
) is 'Insert one pre-release backup only for an exact prepared fleet run tenant snapshot.';
