create table control.webshop_email_domains (
    id uuid primary key,
    workshop_id uuid not null references control.workshops(id) on delete cascade,
    domain_name text not null unique,
    sender_local_part text not null default 'bonjour',
    state text not null default 'registering'
        check (state in ('registering','dns_pending','testing','active','action_required','disconnecting','disconnected')),
    desired_state text not null default 'active'
        check (desired_state in ('active','disconnected')),
    provider_ref uuid,
    webhook_ref uuid,
    provider_status text,
    dns_records jsonb not null default '{}'::jsonb check (jsonb_typeof(dns_records)='object'),
    verification jsonb not null default '{}'::jsonb check (jsonb_typeof(verification)='object'),
    test_outbox_id uuid references control.outbox(id),
    test_delivered_at timestamptz,
    operation_id uuid references control.operations(id),
    last_error_class text,
    last_health_checked_at timestamptz,
    created_by uuid not null references control.users(id),
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    disconnected_at timestamptz,
    version bigint not null default 1,
    check (domain_name=lower(domain_name) and length(domain_name) between 4 and 253),
    check (sender_local_part ~ '^[a-z0-9][a-z0-9._+-]{0,63}$'),
    check (state <> 'active' or (provider_ref is not null and provider_status='checked' and test_delivered_at is not null))
);

create index webshop_email_domains_reconcile
    on control.webshop_email_domains(state, desired_state, updated_at);
create unique index webshop_email_domains_one_active
    on control.webshop_email_domains(workshop_id) where state='active' and desired_state='active';

alter table control.outbox add column provider_domain_id uuid;

alter table control.operations drop constraint operations_kind_check;
alter table control.operations add constraint operations_kind_check check (kind in (
    'tenant.provision','membership.reconcile','entitlement.apply','invoice.capture',
    'inventory.capture.extract','tenant.reconcile','tenant.lifecycle','email.delivery',
    'module.enable','module.restrict','odoo.release.adopt','privacy.retention',
    'privacy.data_subject_request','webshop-domain.reconcile','webshop-email-domain.reconcile'
));

do $$ begin
    if exists(select 1 from pg_roles where rolname='control_api') then
        grant select,insert,update on control.webshop_email_domains to control_api;
    end if;
    if exists(select 1 from pg_roles where rolname='control_reconciliation_worker') then
        grant select,update on control.webshop_email_domains to control_reconciliation_worker;
        grant select,insert on control.outbox to control_reconciliation_worker;
        grant select on control.email_suppressions to control_reconciliation_worker;
    end if;
    if exists(select 1 from pg_roles where rolname='control_email_worker') then
        grant select on control.webshop_email_domains to control_email_worker;
    end if;
end $$;
