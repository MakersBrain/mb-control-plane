alter table control.workshop_modules
    drop constraint workshop_modules_module_key_check,
    add constraint workshop_modules_module_key_check check (module_key in (
        'ceramics-production', 'catalogue', 'firings', 'kiln-connectivity',
        'labels', 'depot', 'sumup', 'documents', 'invoice-capture',
        'azure-invoice-extraction', 'inventory-capture',
        'azure-label-extraction', 'inventory-ai-fallback'
    ));

alter table control.workshop_modules
    drop constraint workshop_modules_state_check,
    add constraint workshop_modules_state_check check (
        state in ('requested', 'enabled', 'restricted')
    );

create table control.capability_registry_versions (
    version integer primary key check (version > 0),
    source_digest text not null check (source_digest ~ '^sha256:[0-9a-f]{64}$'),
    activated_at timestamptz not null default now(),
    active boolean not null default false
);

create unique index capability_registry_one_active
    on control.capability_registry_versions (active) where active;

insert into control.capability_registry_versions(version,source_digest,active)
values(1,'sha256:528d089a90c5f869566eef1451bc4dea5aa1271190501d47996b06a36d091f01',true);

comment on table control.capability_registry_versions is
    'Activation evidence for the typed capability registry embedded in the control release';

do $$
begin
    if exists (select 1 from pg_roles where rolname = 'control_api') then
        grant select on control.capability_registry_versions to control_api;
    end if;
    if exists (select 1 from pg_roles where rolname = 'control_reconciliation_worker') then
        grant update on control.workshop_modules to control_reconciliation_worker;
    end if;
end
$$;
