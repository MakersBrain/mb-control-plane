-- Recovery points are discovered fleet-wide by platform status and the backup
-- scheduler, but every direct runtime mutation belongs to one workshop.  The
-- release driver's two fleet projections are already mediated by exact live
-- SECURITY DEFINER capabilities, so direct driver access can now fail closed
-- on the transaction-local workshop identity.

alter table control.workshop_recovery_points enable row level security;
alter table control.workshop_recovery_points force row level security;

do $migration$
begin
    if exists (select 1 from pg_roles where rolname = 'control') then
        create policy workshop_recovery_points_migration_owner
        on control.workshop_recovery_points
        as permissive
        for all
        to control
        using (true)
        with check (true);
    end if;

    if exists (select 1 from pg_roles where rolname = 'control_api') then
        create policy workshop_recovery_points_platform_read
        on control.workshop_recovery_points
        as permissive
        for select
        to control_api
        using (true);
    end if;

    if exists (select 1 from pg_roles where rolname = 'control_tenant_api') then
        create policy workshop_recovery_points_tenant_api_read
        on control.workshop_recovery_points
        as permissive
        for select
        to control_tenant_api
        using (workshop_id = control.current_workshop_id());

        create policy workshop_recovery_points_tenant_api_insert
        on control.workshop_recovery_points
        as permissive
        for insert
        to control_tenant_api
        with check (workshop_id = control.current_workshop_id());

        grant execute on function control.current_workshop_id()
            to control_tenant_api;
    end if;

    if exists (select 1 from pg_roles where rolname = 'control_lifecycle_worker') then
        revoke insert, delete
            on table control.workshop_recovery_points
            from control_lifecycle_worker;

        create policy workshop_recovery_points_lifecycle_read
        on control.workshop_recovery_points
        as permissive
        for select
        to control_lifecycle_worker
        using (workshop_id = control.current_workshop_id());

        create policy workshop_recovery_points_lifecycle_update
        on control.workshop_recovery_points
        as permissive
        for update
        to control_lifecycle_worker
        using (workshop_id = control.current_workshop_id())
        with check (workshop_id = control.current_workshop_id());

        grant execute on function control.current_workshop_id()
            to control_lifecycle_worker;
    end if;

    if exists (select 1 from pg_roles where rolname = 'control_backup_scheduler') then
        create policy workshop_recovery_points_scheduler_discovery
        on control.workshop_recovery_points
        as permissive
        for select
        to control_backup_scheduler
        using (true);

        create policy workshop_recovery_points_scheduler_insert
        on control.workshop_recovery_points
        as permissive
        for insert
        to control_backup_scheduler
        with check (workshop_id = control.current_workshop_id());

        grant execute on function control.current_workshop_id()
            to control_backup_scheduler;
    end if;

    if exists (select 1 from pg_roles where rolname = 'control_driver_ledger') then
        create policy workshop_recovery_points_driver_read
        on control.workshop_recovery_points
        as permissive
        for select
        to control_driver_ledger
        using (workshop_id = control.current_workshop_id());

        create policy workshop_recovery_points_driver_update
        on control.workshop_recovery_points
        as permissive
        for update
        to control_driver_ledger
        using (workshop_id = control.current_workshop_id())
        with check (workshop_id = control.current_workshop_id());

        grant execute on function control.current_workshop_id()
            to control_driver_ledger;
    end if;
end
$migration$;

comment on table control.workshop_recovery_points is
'Workshop-owned recovery-point ledger protected by forced tenant RLS; platform and scheduler discovery remain explicitly fleet-readable, bounded capabilities mediate fleet writes and driver release reads, and direct mutations require transaction-local workshop context.';
