create table control.worker_heartbeats (
    worker_id text primary key check(length(worker_id) between 1 and 200),
    queue text not null check(length(queue) between 1 and 100),
    release_id text not null check(length(release_id) between 1 and 200),
    started_at timestamptz not null default now(),
    last_heartbeat_at timestamptz not null default now(),
    active_operation_id uuid references control.operations(id) on delete set null,
    shutdown_at timestamptz,
    check(shutdown_at is null or shutdown_at>=started_at)
);
create index worker_heartbeats_freshness on control.worker_heartbeats(queue,last_heartbeat_at desc)
where shutdown_at is null;

do $$
declare role_name text;
begin
    foreach role_name in array array[
        'control_provision_worker','control_membership_worker','control_invoice_worker',
        'control_inventory_worker','control_email_worker','control_reconciliation_worker',
        'control_lifecycle_worker','control_release_worker','control_privacy_worker'
    ] loop
        if exists(select 1 from pg_roles where rolname=role_name) then
            execute format('grant select,insert,update on control.worker_heartbeats to %I',role_name);
        end if;
    end loop;
    if exists(select 1 from pg_roles where rolname='control_api') then
        grant select on control.worker_heartbeats to control_api;
    end if;
end $$;
