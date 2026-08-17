create table control.webshop_onboarding (
    workshop_id uuid primary key references control.workshops(id) on delete cascade,
    state text not null default 'not_started'
        check (state in ('not_started','in_progress','ready','completed','action_required')),
    observation jsonb not null default '{}'::jsonb
        check (jsonb_typeof(observation)='object'),
    odoo_issues jsonb not null default '[]'::jsonb
        check (jsonb_typeof(odoo_issues)='array'),
    operation_id uuid references control.operations(id) on delete restrict,
    last_error_class text,
    started_at timestamptz,
    last_checked_at timestamptz,
    completed_at timestamptz,
    updated_at timestamptz not null default now(),
    version bigint not null default 1 check (version > 0),
    check ((state='completed')=(completed_at is not null))
);

alter table control.operations drop constraint operations_kind_check;
alter table control.operations add constraint operations_kind_check check (kind in (
    'tenant.provision','membership.reconcile','entitlement.apply','invoice.capture',
    'inventory.capture.extract','tenant.reconcile','tenant.lifecycle','email.delivery',
    'module.enable','module.restrict','odoo.release.adopt','privacy.retention',
    'privacy.data_subject_request','webshop-domain.reconcile','webshop-email-domain.reconcile',
    'webshop-onboarding.reconcile'
));

do $$ begin
    if exists(select 1 from pg_roles where rolname='control_api') then
        grant select,insert,update on control.webshop_onboarding to control_api;
    end if;
    if exists(select 1 from pg_roles where rolname='control_reconciliation_worker') then
        grant select,insert,update on control.webshop_onboarding to control_reconciliation_worker;
    end if;
end $$;
