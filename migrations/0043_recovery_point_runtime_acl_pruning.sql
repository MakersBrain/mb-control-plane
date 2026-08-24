-- Recovery-point access for release and privacy work is mediated by narrower
-- capabilities. Remove the stale direct table grants before designing forced
-- RLS for the remaining mixed platform, scheduler, lifecycle, and driver paths.

do $migration$
begin
    if exists (select 1 from pg_roles where rolname = 'control_release_worker') then
        revoke select, insert, update
            on table control.workshop_recovery_points
            from control_release_worker;
    end if;

    if exists (select 1 from pg_roles where rolname = 'control_privacy_worker') then
        revoke select
            on table control.workshop_recovery_points
            from control_privacy_worker;
    end if;
end
$migration$;

comment on table control.workshop_recovery_points is
'Workshop-owned recovery-point ledger; release review uses its bounded SECURITY DEFINER capability, privacy has no direct path, and remaining runtime access awaits command-specific tenant isolation.';
