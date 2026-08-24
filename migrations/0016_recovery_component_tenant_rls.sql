-- Recovery components disclose the exact object layout and integrity digests of
-- a workshop backup.  Their only runtime consumers are the already-scoped
-- lifecycle and driver-ledger workflows, so make the database enforce the
-- workshop capability those workflows install on every short transaction.

alter table control.workshop_recovery_components enable row level security;
alter table control.workshop_recovery_components force row level security;

do $migration$
begin
    -- The one-shot migration owner remains able to inspect and repair catalog
    -- state.  Runtime logins are non-owners and NOBYPASSRLS.
    if exists (select 1 from pg_roles where rolname = 'control') then
        create policy workshop_recovery_components_migration_owner
        on control.workshop_recovery_components
        as permissive
        for all
        to control
        using (true)
        with check (true);
    end if;

    if exists (select 1 from pg_roles where rolname = 'control_lifecycle_worker') then
        create policy workshop_recovery_components_lifecycle_tenant
        on control.workshop_recovery_components
        as permissive
        for all
        to control_lifecycle_worker
        using (
            workshop_id = control.current_workshop_id()
            and exists (
                select 1
                  from control.workshop_recovery_points recovery
                 where recovery.id = workshop_recovery_components.recovery_point_id
                   and recovery.workshop_id = control.current_workshop_id()
            )
        )
        with check (
            workshop_id = control.current_workshop_id()
            and exists (
                select 1
                  from control.workshop_recovery_points recovery
                 where recovery.id = workshop_recovery_components.recovery_point_id
                   and recovery.workshop_id = control.current_workshop_id()
            )
        );

        grant execute on function control.current_workshop_id()
            to control_lifecycle_worker;
    end if;

    if exists (select 1 from pg_roles where rolname = 'control_driver_ledger') then
        create policy workshop_recovery_components_driver_tenant
        on control.workshop_recovery_components
        as permissive
        for all
        to control_driver_ledger
        using (
            workshop_id = control.current_workshop_id()
            and exists (
                select 1
                  from control.workshop_recovery_points recovery
                 where recovery.id = workshop_recovery_components.recovery_point_id
                   and recovery.workshop_id = control.current_workshop_id()
            )
        )
        with check (
            workshop_id = control.current_workshop_id()
            and exists (
                select 1
                  from control.workshop_recovery_points recovery
                 where recovery.id = workshop_recovery_components.recovery_point_id
                   and recovery.workshop_id = control.current_workshop_id()
            )
        );

        grant execute on function control.current_workshop_id()
            to control_driver_ledger;
    end if;

    -- The platform API has no component-table call path.  Its inherited base
    -- grant was an unbounded residual surface and is deliberately removed.
    if exists (select 1 from pg_roles where rolname = 'control_api') then
        revoke all on table control.workshop_recovery_components from control_api;
    end if;
end
$migration$;

comment on table control.workshop_recovery_components is
'Workshop backup object manifest protected by forced tenant RLS; runtime access requires the exact transaction-local workshop capability and matching recovery parent.';
