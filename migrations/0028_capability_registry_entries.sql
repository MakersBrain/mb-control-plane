alter table control.workshop_modules
    drop constraint workshop_modules_module_key_check,
    drop constraint workshop_modules_state_check,
    drop constraint if exists workshop_modules_check,
    add constraint workshop_modules_module_key_format check (
        module_key ~ '^[a-z0-9][a-z0-9-]{1,63}$'
    ),
    add constraint workshop_modules_state_check check (
        state in ('requested','installing','enabled','failed','restricted')
    ),
    add constraint workshop_modules_enabled_at_check check (
        state<>'enabled' or enabled_at is not null
    );

create table control.capability_registry_entries (
    registry_version integer not null references control.capability_registry_versions(version) on delete restrict,
    capability_key text not null check(capability_key ~ '^[a-z0-9][a-z0-9-]{1,63}$'),
    dependencies text[] not null default '{}',
    odoo_modules text[] not null default '{}',
    service text,
    minimum_release text not null check(btrim(minimum_release)<>''),
    enforcement_adapter text not null check(enforcement_adapter in (
        'odoo_modules','paperless_service','broker_provider'
    )),
    primary key(registry_version,capability_key),
    check(not capability_key=any(dependencies)),
    check(array_position(dependencies,null) is null),
    check(array_position(odoo_modules,null) is null),
    check((enforcement_adapter='odoo_modules')=(cardinality(odoo_modules)>0)),
    check((enforcement_adapter='paperless_service')=(service='paperless'))
);

alter table control.tenant_release_adoptions
    add constraint tenant_release_adoptions_registry_version_fk
    foreign key(registry_version) references control.capability_registry_versions(version)
    on delete restrict;

insert into control.capability_registry_entries(
    registry_version,capability_key,dependencies,odoo_modules,service,minimum_release,enforcement_adapter
) values
    (1,'ceramics-production',array['firings'],array['mb_ceramics_workflow'],null,'0.1.0','odoo_modules'),
    (1,'catalogue','{}',array['mb_catalogue_sync'],null,'0.1.0','odoo_modules'),
    (1,'firings','{}',array['mb_ceramics_firing'],null,'0.1.0','odoo_modules'),
    (1,'kiln-connectivity',array['firings'],array['mb_kiln_bridge'],null,'0.1.0','odoo_modules'),
    (1,'labels','{}',array['mb_label','mb_label_pos'],null,'0.1.0','odoo_modules'),
    (1,'depot','{}',array['mb_depot'],null,'0.1.0','odoo_modules'),
    (1,'sumup','{}',array['mb_payment_sumup','mb_account_payment_sumup','mb_pos_sumup'],null,'0.1.0','odoo_modules'),
    (1,'inventory-capture','{}',array['mb_inventory_capture'],null,'0.1.0','odoo_modules'),
    (1,'azure-label-extraction',array['inventory-capture'],'{}',null,'0.1.0','broker_provider'),
    (1,'inventory-ai-fallback',array['inventory-capture'],'{}',null,'0.1.0','broker_provider'),
    (1,'documents','{}','{}','paperless','0.1.0','paperless_service'),
    (1,'invoice-capture',array['documents'],array['mb_invoice_capture'],null,'0.1.0','odoo_modules'),
    (1,'azure-invoice-extraction',array['invoice-capture'],'{}',null,'0.1.0','broker_provider');

alter table control.workshop_modules
    add column registry_version integer not null default 1,
    add column application_release_id text references control.application_releases(id) on delete restrict,
    add column entitlement_version bigint check(entitlement_version is null or entitlement_version>0),
    add column resolved_implementation jsonb not null default '{}' check(jsonb_typeof(resolved_implementation)='object'),
    add constraint workshop_modules_registry_entry_fk
        foreign key(registry_version,module_key)
        references control.capability_registry_entries(registry_version,capability_key)
        on delete restrict;

update control.workshop_modules wm
   set registry_version=a.registry_version,
       application_release_id=a.release_id,
       entitlement_version=e.version,
       resolved_implementation=jsonb_build_object(
           'odoo_modules',to_jsonb(c.odoo_modules),'service',to_jsonb(c.service)
       )
  from control.tenant_release_adoptions a
  join control.capability_registry_entries c
    on c.registry_version=a.registry_version
  left join control.entitlements e on e.workshop_id=a.workshop_id
 where a.workshop_id=wm.workshop_id and a.state='active'
   and c.capability_key=wm.module_key;

create function control.validate_workshop_module_update() returns trigger
language plpgsql set search_path=pg_catalog,control as $$
begin
    if new.workshop_id<>old.workshop_id or new.module_key<>old.module_key then
        raise exception 'capability activation identity is immutable' using errcode='55000';
    end if;
    if new.version<>old.version+1 then
        raise exception 'capability activation version must increment exactly once' using errcode='40001';
    end if;
    if not (
        (old.state='requested' and new.state in ('requested','installing','failed','restricted')) or
        (old.state='installing' and new.state in ('installing','enabled','failed','restricted')) or
        (old.state='enabled' and new.state in ('enabled','restricted')) or
        (old.state in ('failed','restricted') and new.state='requested')
    ) then
        raise exception 'invalid capability activation transition % -> %',old.state,new.state using errcode='23514';
    end if;
    if new.operation_id is not distinct from old.operation_id then
        if new.registry_version<>old.registry_version
           or new.application_release_id is distinct from old.application_release_id
           or new.entitlement_version is distinct from old.entitlement_version
           or new.resolved_implementation<>old.resolved_implementation then
            raise exception 'pinned capability activation contract is immutable' using errcode='55000';
        end if;
    elsif new.state<>'requested' or new.operation_id is null then
        raise exception 'only a new requested activation may replace its pinned contract' using errcode='55000';
    end if;
    return new;
end $$;

create trigger workshop_module_update before update on control.workshop_modules
for each row execute function control.validate_workshop_module_update();

revoke all on function control.validate_workshop_module_update() from public;

do $$
begin
    if exists(select 1 from pg_roles where rolname='control_api') then
        grant select on control.capability_registry_entries to control_api;
    end if;
    if exists(select 1 from pg_roles where rolname='control_provisioning_worker') then
        grant select on control.capability_registry_entries to control_provisioning_worker;
    end if;
    if exists(select 1 from pg_roles where rolname='control_reconciliation_worker') then
        grant select on control.capability_registry_entries to control_reconciliation_worker;
    end if;
end $$;
