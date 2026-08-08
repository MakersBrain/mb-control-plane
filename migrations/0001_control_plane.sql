create schema if not exists control;

create table control.users (
    id uuid primary key,
    email text not null unique check (email = lower(btrim(email)) and email <> ''),
    display_name text,
    locale text not null default 'en' check (locale in ('en', 'fr')),
    authority_epoch integer not null default 1 check (authority_epoch > 0),
    created_at timestamptz not null default now(),
    disabled_at timestamptz
);

create table control.external_identities (
    id uuid primary key,
    user_id uuid not null references control.users(id) on delete restrict,
    issuer text not null,
    subject text not null,
    email_at_link text,
    linked_at timestamptz not null default now(),
    disabled_at timestamptz,
    unique (issuer, subject),
    unique (user_id)
);

create table control.workshops (
    id uuid primary key,
    slug text not null unique check (slug ~ '^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$'),
    display_name text not null check (btrim(display_name) <> ''),
    legal_name text,
    country_code text check (country_code ~ '^[A-Z]{2}$'),
    time_zone text not null,
    plan text not null default 'trial',
    status text not null default 'provisioning' check (status in (
        'provisioning', 'trial', 'active', 'past_due', 'restricted',
        'suspended', 'deleting', 'deleted'
    )),
    version bigint not null default 1 check (version > 0),
    created_at timestamptz not null default now()
);

create table control.memberships (
    workshop_id uuid not null references control.workshops(id) on delete restrict,
    user_id uuid not null references control.users(id) on delete restrict,
    role text not null check (role in ('viewer', 'artisan', 'accountant', 'studio_manager', 'owner')),
    status text not null default 'active' check (status in ('active', 'revoked')),
    authority_epoch integer not null default 1 check (authority_epoch > 0),
    created_at timestamptz not null default now(),
    revoked_at timestamptz,
    primary key (workshop_id, user_id),
    check ((status = 'revoked') = (revoked_at is not null))
);

create function control.assert_last_owner() returns trigger language plpgsql as $$
declare target uuid := coalesce(old.workshop_id, new.workshop_id);
begin
    if not exists (
        select 1 from control.memberships
        where workshop_id = target and role = 'owner' and status = 'active'
    ) then
        raise exception 'workshop would have no active owner' using errcode = '23514';
    end if;
    return null;
end $$;

create constraint trigger memberships_keep_owner
after insert or update or delete on control.memberships
deferrable initially deferred for each row execute function control.assert_last_owner();

create table control.invitations (
    id uuid primary key,
    workshop_id uuid not null references control.workshops(id) on delete cascade,
    email text not null check (email = lower(btrim(email)) and email <> ''),
    role text not null check (role in ('viewer', 'artisan', 'accountant', 'studio_manager')),
    token_hash bytea not null unique check (octet_length(token_hash) = 32),
    locale text not null default 'en' check (locale in ('en', 'fr')),
    invited_by uuid not null references control.users(id) on delete restrict,
    idempotency_key text not null check (idempotency_key <> ''),
    created_at timestamptz not null default now(),
    expires_at timestamptz not null,
    sent_count integer not null default 1 check (sent_count > 0),
    last_sent_at timestamptz not null default now(),
    accepted_at timestamptz,
    accepted_user_id uuid references control.users(id) on delete restrict,
    revoked_at timestamptz,
    check (expires_at > created_at),
    check (accepted_at is null or accepted_user_id is not null),
    check (accepted_at is null or revoked_at is null),
    unique (invited_by, idempotency_key)
);

create unique index invitations_one_pending
on control.invitations (workshop_id, email)
where accepted_at is null and revoked_at is null;

create table control.service_instances (
    id uuid primary key,
    workshop_id uuid not null references control.workshops(id) on delete restrict,
    service text not null check (service in ('odoo', 'paperless')),
    base_url text not null,
    secret_ref text not null,
    release_id text,
    desired_epoch integer not null default 1 check (desired_epoch > 0),
    applied_epoch integer not null default 0 check (applied_epoch between 0 and desired_epoch),
    health text not null default 'provisioning' check (health in ('provisioning', 'ready', 'degraded', 'suspended', 'failed')),
    last_observed_at timestamptz,
    safe_error_class text,
    unique (workshop_id, service)
);

create table control.membership_targets (
    workshop_id uuid not null,
    user_id uuid not null,
    target text not null check (target in ('rauthy', 'odoo', 'paperless')),
    desired_epoch integer not null check (desired_epoch > 0),
    applied_epoch integer not null default 0 check (applied_epoch between 0 and desired_epoch),
    state text not null default 'pending' check (state in ('pending', 'ready', 'degraded', 'disabled')),
    safe_error_class text,
    observed_at timestamptz,
    primary key (workshop_id, user_id, target),
    foreign key (workshop_id, user_id) references control.memberships(workshop_id, user_id) on delete cascade
);

create table control.ownership_transfers (
    id uuid primary key,
    workshop_id uuid not null references control.workshops(id) on delete cascade,
    from_user_id uuid not null references control.users(id) on delete restrict,
    to_user_id uuid not null references control.users(id) on delete restrict,
    idempotency_key text not null check (idempotency_key <> ''),
    created_at timestamptz not null default now(),
    expires_at timestamptz not null,
    accepted_at timestamptz,
    revoked_at timestamptz,
    check (from_user_id <> to_user_id),
    check (expires_at > created_at),
    check (accepted_at is null or revoked_at is null),
    unique (from_user_id, idempotency_key)
);

create table control.operations (
    id uuid primary key,
    kind text not null check (kind in (
        'tenant.provision', 'membership.reconcile', 'entitlement.apply',
        'invoice.capture', 'tenant.reconcile', 'tenant.lifecycle', 'email.delivery'
    )),
    queue text not null,
    workshop_id uuid references control.workshops(id) on delete restrict,
    target_user_id uuid references control.users(id) on delete restrict,
    desired_epoch integer check (desired_epoch is null or desired_epoch > 0),
    payload jsonb not null check (jsonb_typeof(payload) = 'object'),
    requested_by uuid references control.users(id) on delete restrict,
    correlation_id uuid not null,
    idempotency_key text not null check (idempotency_key <> ''),
    state text not null default 'pending' check (state in ('pending', 'in_flight', 'awaiting_reconciliation', 'succeeded', 'dead_letter')),
    attempt integer not null default 0 check (attempt >= 0),
    max_attempts integer not null default 12 check (max_attempts between 1 and 100),
    next_attempt_at timestamptz not null default now(),
    leased_by text,
    lease_expires_at timestamptz,
    failure_class text,
    created_at timestamptz not null default now(),
    finished_at timestamptz,
    unique nulls not distinct (kind, requested_by, idempotency_key),
    check ((state = 'in_flight') = (leased_by is not null)),
    check ((state = 'in_flight') = (lease_expires_at is not null))
);

create index operations_due on control.operations (queue, next_attempt_at, created_at)
where state in ('pending', 'in_flight', 'awaiting_reconciliation');

create table control.entitlements (
    workshop_id uuid primary key references control.workshops(id) on delete restrict,
    version bigint not null check (version > 0),
    plan text not null,
    status text not null,
    limits jsonb not null default '{}',
    expires_at timestamptz,
    signature text not null,
    updated_at timestamptz not null default now()
);

create table control.usage_counters (
    workshop_id uuid not null references control.workshops(id) on delete restrict,
    period date not null,
    metric text not null check (metric in ('azure_invoice_pages')),
    quantity bigint not null default 0 check (quantity >= 0),
    updated_at timestamptz not null default now(),
    primary key (workshop_id, period, metric),
    check (date_trunc('month', period)::date = period)
);

create table control.outbox (
    id uuid primary key,
    kind text not null,
    recipient text not null,
    template text not null,
    payload jsonb not null,
    state text not null default 'queued' check (state in ('queued', 'sending', 'sent', 'deferred', 'dead_letter')),
    attempts integer not null default 0,
    next_attempt_at timestamptz not null default now(),
    created_at timestamptz not null default now(),
    sent_at timestamptz
);

create table control.audit_events (
    id uuid primary key,
    actor_user_id uuid references control.users(id) on delete restrict,
    workshop_id uuid references control.workshops(id) on delete restrict,
    action text not null,
    target_type text,
    target_id text,
    correlation_id uuid not null,
    outcome text not null,
    detail jsonb not null default '{}',
    created_at timestamptz not null default now()
);

create index audit_events_created on control.audit_events (created_at desc, id desc);
