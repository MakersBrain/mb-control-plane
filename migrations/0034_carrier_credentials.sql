create table control.carrier_secrets (
    id uuid primary key,
    workshop_id uuid not null references control.workshops(id) on delete restrict,
    provider text not null check (provider ~ '^[a-z][a-z0-9_]{0,31}$'),
    environment text not null check (environment in ('test','production')),
    company_id bigint not null check (company_id > 0),
    carrier_id bigint not null check (carrier_id > 0),
    secret_ref text not null unique check (secret_ref ~ '^docker/[0-9a-f-]{36}/carrier/[0-9a-f-]{36}$'),
    version bigint not null default 1 check (version > 0),
    state text not null default 'active' check (state in ('active','suspended','deleted')),
    created_by uuid not null references control.users(id) on delete restrict,
    created_at timestamptz not null default now(),
    rotated_at timestamptz,
    deleted_at timestamptz,
    cleanup_pending_ref text check (
        cleanup_pending_ref is null or
        cleanup_pending_ref ~ '^docker/[0-9a-f-]{36}/carrier/[0-9a-f-]{36}$'
    ),
    unique (workshop_id, provider, environment, company_id, carrier_id),
    check ((state = 'deleted') = (deleted_at is not null)),
    check (state <> 'deleted' or cleanup_pending_ref is null)
);

create index carrier_secrets_workshop on control.carrier_secrets(workshop_id, state, provider);

alter table control.deployment_driver_operations
    drop constraint deployment_driver_operations_action_check,
    add constraint deployment_driver_operations_action_check check (
        action in ('provision','reconcile','lifecycle','rehearse','release',
                   'erasure','resume','restrict','carrier-secret','carrier-secret-delete')
    );

do $$
begin
    if exists(select 1 from pg_roles where rolname='control_api') then
        grant select, insert, update on control.carrier_secrets to control_api;
    end if;
    if exists(select 1 from pg_roles where rolname='control_reconciliation_worker') then
        grant select, update on control.carrier_secrets to control_reconciliation_worker;
    end if;
    if exists(select 1 from pg_roles where rolname='control_provisioning_worker') then
        grant select, update on control.carrier_secrets to control_provisioning_worker;
    end if;
    if exists(select 1 from pg_roles where rolname='control_lifecycle_worker') then
        grant select, update on control.carrier_secrets to control_lifecycle_worker;
    end if;
end $$;
