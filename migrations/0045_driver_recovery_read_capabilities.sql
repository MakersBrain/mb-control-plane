-- Fleet release execution needs two bounded, fleet-wide recovery-point reads.
-- Keep tenant recovery reads scoped to their existing workflow, but move these
-- cross-tenant reads behind exact live driver authorities before enabling RLS.

create function control.read_release_driver_tenants(
    p_fleet_run_id uuid,
    p_release_id text,
    p_driver_operation_id uuid,
    p_control_operation_id uuid,
    p_control_operation_attempt integer,
    p_control_operation_lease_owner text,
    p_instance_owner uuid,
    p_execution_token uuid,
    p_resource_lease_token uuid,
    p_fence_token bigint
) returns table(
    id uuid,
    workshop_id uuid,
    database_id uuid,
    database_ref text,
    public_hostname text,
    backup_recovery_id uuid,
    component_scope text[]
)
language plpgsql
security definer
set search_path = pg_catalog, control
as $function$
begin
    if not exists (
        select 1
          from control.operations operation
          join control.deployment_driver_operations driver
            on driver.id = p_driver_operation_id
           and driver.control_operation_id = operation.id
          join control.deployment_driver_resource_leases resource
            on resource.resource_key = 'runtime/shared-odoo'
           and resource.driver_operation_id = driver.id
          join control.release_fleet_runs fleet
            on fleet.id = p_fleet_run_id
           and fleet.operation_id = operation.id
         where operation.id = p_control_operation_id
           and operation.kind = 'odoo.release.adopt'
           and operation.queue = 'release-adoption'
           and operation.workshop_id is null
           and operation.state = 'in_flight'
           and operation.attempt = p_control_operation_attempt
           and operation.leased_by = p_control_operation_lease_owner
           and operation.lease_expires_at > now()
           and operation.payload->>'phase' = 'adopt'
           and operation.payload->>'release_id' = p_release_id
           and driver.action = 'release'
           and driver.state = 'in_progress'
           and driver.safe_error is null
           and driver.control_operation_attempt = p_control_operation_attempt
           and driver.control_operation_lease_owner = p_control_operation_lease_owner
           and driver.target_key = 'fleet/' || p_fleet_run_id::text
           and driver.execution_token = p_execution_token
           and driver.lease_expires_at > now()
           and resource.state = 'held'
           and resource.authority_kind = 'release'
           and resource.lease_owner = p_instance_owner
           and resource.lease_token = p_resource_lease_token
           and resource.fence_token = p_fence_token
           and resource.lease_expires_at > now()
           and fleet.release_id = p_release_id
           and fleet.state in ('preparing', 'activating')
           and fleet.driver_fence_token = p_fence_token
    ) then
        raise exception using
            errcode = '42501',
            message = 'release driver tenant read capability rejected';
    end if;

    return query
    select adoption.id, adoption.workshop_id, adoption.database_id,
           database.database_ref, database.public_hostname,
           adoption.backup_recovery_id, recovery.component_scope
      from control.tenant_release_adoptions adoption
      join control.release_fleet_runs fleet
        on fleet.operation_id = adoption.operation_id
      join control.odoo_databases database
        on database.id = adoption.database_id
       and database.workshop_id = adoption.workshop_id
      join control.workshop_recovery_points recovery
        on recovery.id = adoption.backup_recovery_id
       and recovery.workshop_id = adoption.workshop_id
     where fleet.id = p_fleet_run_id
       and adoption.release_id = p_release_id
     order by adoption.created_at, adoption.id
     limit 501;
end
$function$;

create function control.read_release_reconciliation_tenants(
    p_reconciliation_id uuid,
    p_instance_owner uuid,
    p_execution_token uuid,
    p_fleet_run_id uuid,
    p_release_id text,
    p_control_operation_id uuid,
    p_driver_operation_id uuid,
    p_original_instance_owner uuid,
    p_original_fence_token bigint
) returns table(
    adoption_id uuid,
    workshop_id uuid,
    database_id uuid,
    database_ref text,
    public_hostname text,
    component_scope text[]
)
language plpgsql
security definer
set search_path = pg_catalog, control
as $function$
begin
    if not exists (
        select 1
          from control.fleet_release_reconciliations reconciliation
          join control.operations operation
            on operation.id = p_control_operation_id
          join control.deployment_driver_operations driver
            on driver.id = reconciliation.driver_operation_id
          join control.deployment_driver_resource_leases resource
            on resource.resource_key = 'runtime/shared-odoo'
           and resource.driver_operation_id = driver.id
          join control.release_fleet_runs fleet
            on fleet.id = reconciliation.fleet_run_id
         where reconciliation.id = p_reconciliation_id
           and reconciliation.state = 'observing'
           and reconciliation.instance_owner = p_instance_owner
           and reconciliation.execution_token = p_execution_token
           and reconciliation.lease_expires_at > now()
           and reconciliation.fleet_run_id = p_fleet_run_id
           and reconciliation.driver_operation_id = p_driver_operation_id
           and reconciliation.original_instance_owner = p_original_instance_owner
           and reconciliation.original_fence_token = p_original_fence_token
           and reconciliation.control_operation_attempt = operation.attempt
           and reconciliation.control_operation_lease_owner = operation.leased_by
           and operation.kind = 'odoo.release.adopt'
           and operation.queue = 'release-adoption'
           and operation.workshop_id is null
           and operation.state = 'in_flight'
           and operation.lease_expires_at > now()
           and operation.payload->>'phase' = 'adopt'
           and operation.payload->>'release_id' = p_release_id
           and driver.control_operation_id = operation.id
           and driver.action = 'release'
           and driver.state = 'in_progress'
           and driver.safe_error = 'runtime_outcome_unknown'
           and driver.release_executor_protocol_version = 1
           and driver.target_key = 'fleet/' || p_fleet_run_id::text
           and resource.state = 'quarantined'
           and resource.authority_kind = 'release'
           and resource.lease_owner = p_original_instance_owner
           and resource.fence_token = p_original_fence_token
           and fleet.operation_id = operation.id
           and fleet.release_id = p_release_id
           and fleet.state in ('preparing', 'activating')
           and fleet.driver_fence_token = p_original_fence_token
    ) then
        raise exception using
            errcode = '42501',
            message = 'release reconciliation tenant read capability rejected';
    end if;

    return query
    select adoption.id, adoption.workshop_id, adoption.database_id,
           database.database_ref, database.public_hostname,
           recovery.component_scope
      from control.tenant_release_adoptions adoption
      join control.odoo_databases database
        on database.id = adoption.database_id
       and database.workshop_id = adoption.workshop_id
      join control.workshop_recovery_points recovery
        on recovery.id = adoption.backup_recovery_id
       and recovery.workshop_id = adoption.workshop_id
     where adoption.operation_id = p_control_operation_id
       and adoption.release_id = p_release_id
       and adoption.state = 'prepared'
       and adoption.verified_at is not null
       and recovery.state = 'ready'
       and recovery.verification_state = 'verified'
       and recovery.verified_at is not null
       and (recovery.expires_at is null or recovery.expires_at > now())
     order by adoption.created_at, adoption.id
     limit 501;
end
$function$;

revoke all on function control.read_release_driver_tenants(
    uuid, text, uuid, uuid, integer, text, uuid, uuid, uuid, bigint
) from public;
revoke all on function control.read_release_reconciliation_tenants(
    uuid, uuid, uuid, uuid, text, uuid, uuid, uuid, bigint
) from public;

do $migration$
begin
    if exists (select 1 from pg_roles where rolname = 'control_driver_ledger') then
        grant execute on function control.read_release_driver_tenants(
            uuid, text, uuid, uuid, integer, text, uuid, uuid, uuid, bigint
        ) to control_driver_ledger;
        grant execute on function control.read_release_reconciliation_tenants(
            uuid, uuid, uuid, uuid, text, uuid, uuid, uuid, bigint
        ) to control_driver_ledger;
    end if;
end
$migration$;

comment on function control.read_release_driver_tenants(
    uuid, text, uuid, uuid, integer, text, uuid, uuid, uuid, bigint
) is 'Read the bounded fleet tenant recovery projection for one exact live release driver lease.';
comment on function control.read_release_reconciliation_tenants(
    uuid, uuid, uuid, uuid, text, uuid, uuid, uuid, bigint
) is 'Read the bounded verified fleet tenant recovery projection for one exact live fleet reconciliation claim.';
