-- Split human workshop transactions from the mixed platform/internal API
-- identity. RLS is intentionally introduced on one directly tenant-owned
-- table first; later candidates require their worker workflows to be split.

create function control.current_workshop_id() returns uuid
language plpgsql stable
set search_path to 'pg_catalog', 'control'
as $$
declare
    configured text;
begin
    configured := nullif(current_setting('control.workshop_id', true), '');
    if configured is null then
        return null;
    end if;
    begin
        return configured::uuid;
    exception
        when invalid_text_representation then return null;
    end;
end
$$;

comment on function control.current_workshop_id() is
'Fail-closed transaction-local workshop context for tenant RLS policies; never authenticates a principal.';
revoke all on function control.current_workshop_id() from public;

alter table control.ownership_transfers enable row level security;
alter table control.ownership_transfers force row level security;

do $migration$
begin
    if exists (select 1 from pg_roles where rolname = 'control') then
        create policy ownership_transfers_migration_owner
        on control.ownership_transfers
        as permissive
        for all
        to control
        using (true)
        with check (true);
    end if;

    if exists (select 1 from pg_roles where rolname = 'control_api') then
        create policy ownership_transfers_platform_api
        on control.ownership_transfers
        as permissive
        for all
        to control_api
        using (true)
        with check (true);
    end if;

    if exists (select 1 from pg_roles where rolname = 'control_tenant_api') then
        create policy ownership_transfers_tenant_api
        on control.ownership_transfers
        as permissive
        for all
        to control_tenant_api
        using (workshop_id = control.current_workshop_id())
        with check (workshop_id = control.current_workshop_id());

        grant usage on schema control to control_tenant_api;
        grant execute on function control.current_workshop_id() to control_tenant_api;
        revoke all on all sequences in schema control from control_tenant_api;

        grant insert on table control.audit_events to control_tenant_api;
        grant select on table control.application_releases to control_tenant_api;
        grant select on table control.capability_registry_entries to control_tenant_api;
        grant select on table control.capability_registry_versions to control_tenant_api;
        grant select, insert, update on table control.carrier_secrets to control_tenant_api;
        grant select, insert, update on table control.commands to control_tenant_api;
        grant select on table control.entitlements to control_tenant_api;
        grant insert on table control.erasure_restore_replays to control_tenant_api;
        grant select on table control.erasure_tombstones to control_tenant_api;
        grant select, insert, update on table control.invitations to control_tenant_api;
        grant select, insert, update on table control.membership_targets to control_tenant_api;
        grant select, update on table control.memberships to control_tenant_api;
        grant select, insert, update on table control.odoo_databases to control_tenant_api;
        grant select, insert on table control.operations to control_tenant_api;
        grant select, insert on table control.outbox to control_tenant_api;
        grant select, insert, update on table control.ownership_transfers to control_tenant_api;
        grant select on table control.service_instances to control_tenant_api;
        grant select on table control.tenant_release_adoptions to control_tenant_api;
        grant select on table control.users to control_tenant_api;
        grant select, insert, update on table control.webshop_domains to control_tenant_api;
        grant select, insert, update on table control.webshop_email_domains to control_tenant_api;
        grant select, insert, update on table control.webshop_onboarding to control_tenant_api;
        grant select, insert, update on table control.workshop_modules to control_tenant_api;
        grant select, insert on table control.workshop_recovery_points to control_tenant_api;
        grant select, update on table control.workshops to control_tenant_api;
    end if;
end
$migration$;
