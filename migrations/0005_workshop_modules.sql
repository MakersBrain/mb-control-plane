alter table control.operations drop constraint operations_kind_check;
alter table control.operations add constraint operations_kind_check check (kind in (
    'tenant.provision', 'membership.reconcile', 'entitlement.apply',
    'invoice.capture', 'tenant.reconcile', 'tenant.lifecycle', 'email.delivery',
    'module.enable'
));

create table control.workshop_modules (
    workshop_id uuid not null references control.workshops(id) on delete restrict,
    module_key text not null check (module_key in (
        'catalogue', 'firings', 'kiln-connectivity', 'labels', 'depot', 'sumup'
    )),
    state text not null check (state in ('requested', 'enabled')),
    operation_id uuid references control.operations(id) on delete restrict,
    requested_by uuid not null references control.users(id) on delete restrict,
    requested_at timestamptz not null default now(),
    enabled_at timestamptz,
    primary key (workshop_id, module_key),
    check ((state = 'enabled') = (enabled_at is not null))
);

comment on table control.workshop_modules is
'Desired and applied state for the curated MakersBrain Odoo feature catalogue.';
