alter table control.workshop_modules
    drop constraint workshop_modules_module_key_check;

alter table control.workshop_modules
    add constraint workshop_modules_module_key_check check (module_key in (
        'catalogue', 'firings', 'kiln-connectivity', 'labels', 'depot', 'sumup',
        'documents', 'invoice-capture', 'azure-invoice-extraction'
    ));

comment on table control.workshop_modules is
'Desired and applied state for curated Odoo modules and optional workshop services.';

-- Preserve the behavior of workshops provisioned before document services
-- became opt-in. New workshops start without these rows.
insert into control.workshop_modules (
    workshop_id, module_key, state, requested_by, enabled_at
)
select service.workshop_id, module.module_key, 'enabled', owner.user_id, now()
from control.service_instances service
cross join (values
    ('documents'), ('invoice-capture'), ('azure-invoice-extraction')
) module(module_key)
join lateral (
    select membership.user_id
    from control.memberships membership
    where membership.workshop_id=service.workshop_id and membership.role='owner'
    order by membership.user_id
    limit 1
) owner on true
where service.service='paperless'
on conflict (workshop_id,module_key) do nothing;
