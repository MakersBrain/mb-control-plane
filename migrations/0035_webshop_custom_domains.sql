create table control.webshop_domains (
    id uuid primary key,
    workshop_id uuid not null references control.workshops(id) on delete restrict,
    hostname text not null unique,
    verification_name text not null,
    verification_value text not null unique,
    routing_target text not null,
    state text not null default 'ownership_pending' check (state in (
        'ownership_pending', 'dns_pending', 'certificate_pending', 'testing',
        'active', 'action_required', 'suspended', 'disconnecting', 'disconnected'
    )),
    desired_state text not null default 'active' check (desired_state in ('active','disconnected')),
    dns_state text not null default 'pending' check (dns_state in ('pending','verified','failed')),
    certificate_state text not null default 'pending' check (certificate_state in (
        'pending','provisioning','active','failed','expired'
    )),
    ownership_verified_at timestamptz,
    dns_observed_at timestamptz,
    certificate_observed_at timestamptz,
    last_health_checked_at timestamptz,
    last_error_class text,
    canonical boolean not null default false,
    redirect_target text,
    provider_ref text,
    edge_verification_records jsonb not null default '[]' check (jsonb_typeof(edge_verification_records)='array'),
    operation_id uuid references control.operations(id) on delete restrict,
    created_by uuid not null references control.users(id) on delete restrict,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    disconnected_at timestamptz,
    version bigint not null default 1 check (version > 0),
    check (hostname = lower(hostname)),
    check (hostname ~ '^[a-z0-9][a-z0-9.-]*[a-z0-9]$'),
    check (hostname !~ '\.\.'),
    check (verification_name = '_makersbrain-challenge.' || hostname),
    check (verification_value ~ '^makersbrain-verification=[A-Za-z0-9]{32}$'),
    check (routing_target ~ '^[a-z0-9][a-z0-9.-]*[a-z0-9]$'),
    check (redirect_target is null or redirect_target <> hostname),
    check ((state = 'disconnected') = (disconnected_at is not null)),
    check (state <> 'active' or (
        ownership_verified_at is not null and dns_state = 'verified'
        and certificate_state = 'active' and provider_ref is not null
    ))
);

create index webshop_domains_workshop
    on control.webshop_domains(workshop_id, state, created_at);

create unique index webshop_domains_one_canonical
    on control.webshop_domains(workshop_id)
    where canonical and state <> 'disconnected';

comment on table control.webshop_domains is
'Desired and observed lifecycle for artisan-owned webshop hostnames. External DNS, certificate and edge resources remain control-plane owned.';
comment on column control.webshop_domains.provider_ref is
'Opaque custom-hostname identifier returned by the selected edge provider.';

alter table control.operations drop constraint operations_kind_check;
alter table control.operations add constraint operations_kind_check check (kind in (
    'tenant.provision', 'membership.reconcile', 'entitlement.apply',
    'invoice.capture', 'inventory.capture.extract', 'tenant.reconcile',
    'tenant.lifecycle', 'email.delivery', 'module.enable', 'module.restrict',
    'odoo.release.adopt', 'privacy.retention', 'privacy.data_subject_request',
    'webshop-domain.reconcile'
));

do $$
begin
    if exists(select 1 from pg_roles where rolname='control_api') then
        grant select, insert, update on control.webshop_domains to control_api;
    end if;
    if exists(select 1 from pg_roles where rolname='control_reconciliation_worker') then
        grant select, update on control.webshop_domains to control_reconciliation_worker;
    end if;
    if exists(select 1 from pg_roles where rolname='control_lifecycle_worker') then
        grant select, update on control.webshop_domains to control_lifecycle_worker;
    end if;
end $$;
