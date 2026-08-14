do $$
begin
    if exists(select 1 from pg_roles where rolname='control_reconciliation_worker') then
        grant select on control.release_fleet_runs to control_reconciliation_worker;
    end if;
end $$;

comment on table control.release_fleet_runs is
'Fleet-wide release fence observed by periodic reconciliation before admitting tenant drift work.';
