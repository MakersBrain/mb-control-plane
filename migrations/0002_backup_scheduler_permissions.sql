-- The scheduler reads the owner and module scope before enqueuing a backup,
-- and records both scheduled backups and recovery rehearsal outcomes.
grant select on table control.memberships to control_backup_scheduler;
grant select on table control.workshop_modules to control_backup_scheduler;
grant insert on table control.audit_events to control_backup_scheduler;
grant update on table control.workshop_recovery_rehearsals to control_backup_scheduler;
grant update (idempotency_key) on table control.operations to control_backup_scheduler;
