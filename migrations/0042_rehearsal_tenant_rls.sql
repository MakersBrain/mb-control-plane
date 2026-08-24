-- Recovery rehearsals are discovered fleet-wide but mutated only after the
-- scheduler has selected one workshop and installed transaction-local tenant
-- context. Preserve bounded fleet reads while making every runtime write obey
-- that workshop capability and the recovery-point ownership relationship.

alter table control.workshop_recovery_rehearsals enable row level security;
alter table control.workshop_recovery_rehearsals force row level security;

do $migration$
begin
    if exists (select 1 from pg_roles where rolname = 'control') then
        create policy workshop_recovery_rehearsals_migration_owner
        on control.workshop_recovery_rehearsals
        as permissive
        for all
        to control
        using (true)
        with check (true);
    end if;

    if exists (select 1 from pg_roles where rolname = 'control_api') then
        revoke insert, update, delete
            on table control.workshop_recovery_rehearsals
            from control_api;
        grant select on table control.workshop_recovery_rehearsals to control_api;

        create policy workshop_recovery_rehearsals_platform_read
        on control.workshop_recovery_rehearsals
        as permissive
        for select
        to control_api
        using (true);
    end if;

    if exists (select 1 from pg_roles where rolname = 'control_backup_scheduler') then
        grant select, insert on table control.workshop_recovery_rehearsals
            to control_backup_scheduler;
        grant update (
            state,
            started_at,
            finished_at,
            safe_error,
            attempt,
            next_attempt_at,
            lease_owner,
            lease_token,
            lease_expires_at
        ) on table control.workshop_recovery_rehearsals
            to control_backup_scheduler;

        create policy workshop_recovery_rehearsals_scheduler_discovery
        on control.workshop_recovery_rehearsals
        as permissive
        for select
        to control_backup_scheduler
        using (true);

        create policy workshop_recovery_rehearsals_scheduler_insert
        on control.workshop_recovery_rehearsals
        as permissive
        for insert
        to control_backup_scheduler
        with check (
            workshop_id = control.current_workshop_id()
            and exists (
                select 1
                  from control.workshop_recovery_points recovery
                 where recovery.id = workshop_recovery_rehearsals.recovery_point_id
                   and recovery.workshop_id = control.current_workshop_id()
            )
        );

        create policy workshop_recovery_rehearsals_scheduler_update
        on control.workshop_recovery_rehearsals
        as permissive
        for update
        to control_backup_scheduler
        using (
            workshop_id = control.current_workshop_id()
            and exists (
                select 1
                  from control.workshop_recovery_points recovery
                 where recovery.id = workshop_recovery_rehearsals.recovery_point_id
                   and recovery.workshop_id = control.current_workshop_id()
            )
        )
        with check (
            workshop_id = control.current_workshop_id()
            and exists (
                select 1
                  from control.workshop_recovery_points recovery
                 where recovery.id = workshop_recovery_rehearsals.recovery_point_id
                   and recovery.workshop_id = control.current_workshop_id()
            )
        );

        grant execute on function control.current_workshop_id()
            to control_backup_scheduler;
    end if;
end
$migration$;

comment on table control.workshop_recovery_rehearsals is
'Fleet-readable recovery rehearsal ledger with forced tenant RLS on scheduler writes; runtime mutation requires exact transaction-local workshop context and matching recovery parent.';
