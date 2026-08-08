create table control.deployment_driver_operations (
    idempotency_key text primary key check (btrim(idempotency_key) <> ''),
    workshop_id uuid not null references control.workshops(id) on delete restrict,
    action text not null check (action in ('provision', 'reconcile', 'lifecycle')),
    request_digest text not null check (request_digest ~ '^[0-9a-f]{64}$'),
    state text not null default 'in_progress' check (state in ('in_progress', 'succeeded', 'failed')),
    response jsonb,
    safe_error text,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    check ((state = 'succeeded') = (response is not null))
);

create index deployment_driver_operations_workshop
on control.deployment_driver_operations (workshop_id, created_at desc);

comment on table control.deployment_driver_operations is
'Persistent idempotency ledger for the private Docker/Podman deployment-driver boundary.';
