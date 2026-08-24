-- Recovery rehearsals are short fleet discoveries followed by workshop-scoped
-- claims. Persist the claim identity and retry budget so a crashed scheduler can
-- be recovered without overlapping driver calls or retrying forever.

alter table control.workshop_recovery_rehearsals
    add column attempt integer not null default 1,
    add column max_attempts integer not null default 6,
    add column next_attempt_at timestamp with time zone,
    add column lease_owner uuid,
    add column lease_token uuid,
    add column lease_expires_at timestamp with time zone;

update control.workshop_recovery_rehearsals
   set lease_owner = gen_random_uuid(),
       lease_token = gen_random_uuid(),
       lease_expires_at = now()
 where state = 'running';

update control.workshop_recovery_rehearsals
   set next_attempt_at = coalesce(finished_at, now()) + interval '1 minute'
 where state = 'failed'
   and safe_error in ('driver_rejected', 'driver_unavailable');

alter table control.workshop_recovery_rehearsals
    add constraint workshop_recovery_rehearsals_attempt_check
        check (attempt >= 1 and max_attempts between 1 and 20 and attempt <= max_attempts),
    add constraint workshop_recovery_rehearsals_lease_check
        check (
            (state = 'running'
             and finished_at is null
             and next_attempt_at is null
             and lease_owner is not null
             and lease_token is not null
             and lease_expires_at is not null)
            or
            (state <> 'running'
             and finished_at is not null
             and lease_owner is null
             and lease_token is null
             and lease_expires_at is null)
        );

create unique index workshop_recovery_rehearsals_one_running_per_workshop
    on control.workshop_recovery_rehearsals (workshop_id)
    where state = 'running';

create index workshop_recovery_rehearsals_retry_claims
    on control.workshop_recovery_rehearsals (next_attempt_at)
    where state = 'failed' and next_attempt_at is not null;

do $migration$
begin
    if exists (select 1 from pg_roles where rolname = 'control_backup_scheduler') then
        revoke update on table control.workshop_recovery_rehearsals from control_backup_scheduler;
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
        ) on table control.workshop_recovery_rehearsals to control_backup_scheduler;
    end if;
end
$migration$;

comment on column control.workshop_recovery_rehearsals.lease_token is
'Opaque fencing token required to finalize the currently leased rehearsal attempt.';

comment on column control.workshop_recovery_rehearsals.next_attempt_at is
'Retry admission time; NULL means the result is terminal even when state is failed.';
