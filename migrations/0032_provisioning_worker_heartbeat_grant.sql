do $$
begin
    if exists (
        select 1 from pg_roles where rolname = 'control_provisioning_worker'
    ) then
        grant select, insert, update on control.worker_heartbeats
            to control_provisioning_worker;
    end if;
end
$$;
