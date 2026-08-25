-- Replace the deployment driver's last direct projection read with one exact
-- lookup capability, then keep immutable history and applied-state parents
-- function-only beneath forced RLS.

create function control.read_workshop_route_projection_disposition(
    p_workshop_id uuid,
    p_generation bigint,
    p_projection_digest text
) returns table(disposition text)
language sql stable security definer
set search_path = pg_catalog, control
as $function$
    select projection.disposition
      from control.workshop_route_projections projection
     where projection.workshop_id = p_workshop_id
       and projection.generation = p_generation
       and projection.projection_digest = p_projection_digest
$function$;

revoke all on function control.read_workshop_route_projection_disposition(uuid,bigint,text)
    from public;

alter table control.workshop_route_projections enable row level security;
alter table control.workshop_route_projections force row level security;
alter table control.workshop_route_projection_state enable row level security;
alter table control.workshop_route_projection_state force row level security;

do $migration$
declare
    v_role text;
begin
    if exists (select 1 from pg_roles where rolname = 'control') then
        create policy workshop_route_projections_migration_owner
            on control.workshop_route_projections
            as permissive for all to control using (true) with check (true);
        create policy workshop_route_projection_state_migration_owner
            on control.workshop_route_projection_state
            as permissive for all to control using (true) with check (true);
    end if;

    foreach v_role in array array[
        'control_api','control_tenant_api','control_membership_worker',
        'control_provisioning_worker','control_invoice_worker',
        'control_inventory_worker','control_email_worker',
        'control_reconciliation_worker','control_lifecycle_worker',
        'control_backup_scheduler','control_driver_ledger',
        'control_release_worker','control_privacy_worker'
    ] loop
        if exists (select 1 from pg_roles where rolname = v_role) then
            execute format(
                'revoke all on table control.workshop_route_projections, control.workshop_route_projection_state from %I',
                v_role
            );
        end if;
    end loop;

    if exists (select 1 from pg_roles where rolname = 'control_driver_ledger') then
        grant execute on function control.read_workshop_route_projection_disposition(
            uuid,bigint,text
        ) to control_driver_ledger;
    end if;
end
$migration$;

comment on function control.read_workshop_route_projection_disposition(uuid,bigint,text) is
'Exact function-only deployment-driver lookup for one immutable workshop projection identity.';
comment on table control.workshop_route_projections is
'Append-only workshop route history protected by forced RLS; runtime materialization and reads are function-only.';
comment on table control.workshop_route_projection_state is
'Workshop desired/applied route heads protected by forced RLS; all runtime transitions are function-only.';
