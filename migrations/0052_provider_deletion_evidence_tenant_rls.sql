-- Keep provider-deletion evidence function-only and deny direct runtime access
-- beneath every owner capability that reads or advances it.

alter table control.webshop_domain_provider_deletion_attempts enable row level security;
alter table control.webshop_domain_provider_deletion_attempts force row level security;

do $migration$
begin
    if exists (select 1 from pg_roles where rolname = 'control') then
        create policy webshop_domain_provider_deletion_attempts_migration_owner
            on control.webshop_domain_provider_deletion_attempts
            as permissive for all to control using (true) with check (true);
    end if;

    if exists (select 1 from pg_roles where rolname = 'control_api') then
        revoke all on table control.webshop_domain_provider_deletion_attempts from control_api;
    end if;
    if exists (select 1 from pg_roles where rolname = 'control_tenant_api') then
        revoke all on table control.webshop_domain_provider_deletion_attempts from control_tenant_api;
    end if;
    if exists (select 1 from pg_roles where rolname = 'control_membership_worker') then
        revoke all on table control.webshop_domain_provider_deletion_attempts from control_membership_worker;
    end if;
    if exists (select 1 from pg_roles where rolname = 'control_provisioning_worker') then
        revoke all on table control.webshop_domain_provider_deletion_attempts from control_provisioning_worker;
    end if;
    if exists (select 1 from pg_roles where rolname = 'control_invoice_worker') then
        revoke all on table control.webshop_domain_provider_deletion_attempts from control_invoice_worker;
    end if;
    if exists (select 1 from pg_roles where rolname = 'control_inventory_worker') then
        revoke all on table control.webshop_domain_provider_deletion_attempts from control_inventory_worker;
    end if;
    if exists (select 1 from pg_roles where rolname = 'control_email_worker') then
        revoke all on table control.webshop_domain_provider_deletion_attempts from control_email_worker;
    end if;
    if exists (select 1 from pg_roles where rolname = 'control_reconciliation_worker') then
        revoke all on table control.webshop_domain_provider_deletion_attempts from control_reconciliation_worker;
    end if;
    if exists (select 1 from pg_roles where rolname = 'control_lifecycle_worker') then
        revoke all on table control.webshop_domain_provider_deletion_attempts from control_lifecycle_worker;
    end if;
    if exists (select 1 from pg_roles where rolname = 'control_backup_scheduler') then
        revoke all on table control.webshop_domain_provider_deletion_attempts from control_backup_scheduler;
    end if;
    if exists (select 1 from pg_roles where rolname = 'control_driver_ledger') then
        revoke all on table control.webshop_domain_provider_deletion_attempts from control_driver_ledger;
    end if;
    if exists (select 1 from pg_roles where rolname = 'control_release_worker') then
        revoke all on table control.webshop_domain_provider_deletion_attempts from control_release_worker;
    end if;
    if exists (select 1 from pg_roles where rolname = 'control_privacy_worker') then
        revoke all on table control.webshop_domain_provider_deletion_attempts from control_privacy_worker;
    end if;
end
$migration$;

comment on table control.webshop_domain_provider_deletion_attempts is
'Workshop-owned durable provider-deletion evidence protected by forced tenant RLS; all runtime reads and mutations remain behind exact fixed-path capabilities.';
