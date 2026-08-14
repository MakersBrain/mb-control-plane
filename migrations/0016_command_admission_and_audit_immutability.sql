create table control.commands (
    id uuid primary key,
    actor_user_id uuid not null references control.users(id) on delete restrict,
    scope text not null check (btrim(scope) <> '' and length(scope) <= 200),
    command_kind text not null check (btrim(command_kind) <> '' and length(command_kind) <= 100),
    idempotency_key text not null check (
        length(idempotency_key) between 1 and 255
        and idempotency_key ~ '^[A-Za-z0-9._:/-]+$'
    ),
    request_digest bytea not null check (octet_length(request_digest) = 32),
    expected_version bigint check (expected_version is null or expected_version > 0),
    state text not null default 'admitted' check (state in ('admitted','completed')),
    operation_id uuid references control.operations(id) on delete restrict,
    response_status integer check (response_status between 100 and 599),
    response_body jsonb,
    result_ref text,
    created_at timestamptz not null default now(),
    completed_at timestamptz,
    unique (actor_user_id, scope, command_kind, idempotency_key),
    check ((state = 'completed') = (completed_at is not null)),
    check (state <> 'completed' or response_status is not null),
    check (response_body is null or result_ref is null)
);

create index commands_created on control.commands (created_at desc, id desc);

alter table control.invitations
    drop constraint invitations_invited_by_idempotency_key_key;

create function control.reject_audit_mutation() returns trigger
language plpgsql
set search_path = pg_catalog, control
as $$
begin
    raise exception 'audit events are append-only' using errcode = '42501';
end
$$;

revoke all on function control.reject_audit_mutation() from public;

create trigger audit_events_append_only
before update or delete on control.audit_events
for each row execute function control.reject_audit_mutation();

alter table control.memberships
    add column version bigint not null default 1 check (version > 0);

alter table control.workshop_modules
    add column version bigint not null default 1 check (version > 0);
