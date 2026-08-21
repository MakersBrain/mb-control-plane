-- The scheduler reads the owner and module scope before enqueuing a backup,
-- and records both scheduled backups and recovery rehearsal outcomes.
-- Runtime roles are deployment-owned and deliberately absent from bare schema
-- databases used by tests and offline tooling.
do $migration$
begin
    if exists (select 1 from pg_roles where rolname = 'control_backup_scheduler') then
        grant select on table control.memberships to control_backup_scheduler;
        grant select on table control.workshop_modules to control_backup_scheduler;
        grant insert on table control.audit_events to control_backup_scheduler;
        grant update on table control.workshop_recovery_rehearsals to control_backup_scheduler;
        grant update (idempotency_key) on table control.operations to control_backup_scheduler;
    end if;
end
$migration$;
