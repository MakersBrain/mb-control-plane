-- Login roles are infrastructure-owned and created before migrations. This
-- migration owns only object privileges, so disposable schema tests can run
-- without CREATEROLE while real deployments receive the grants below.
revoke create on schema control from public;
revoke all on all tables in schema control from public;
revoke all on all sequences in schema control from public;
revoke all on all functions in schema control from public;

do $$
declare
    role_name text;
begin
    foreach role_name in array array[
        'control_api', 'control_membership_worker',
        'control_provisioning_worker', 'control_invoice_worker',
        'control_inventory_worker', 'control_email_worker',
        'control_reconciliation_worker', 'control_lifecycle_worker',
        'control_backup_scheduler', 'control_driver_ledger'
    ] loop
        if exists (select 1 from pg_roles where rolname = role_name) then
            execute format('grant usage on schema control to %I', role_name);
        end if;
    end loop;
end
$$;

do $$
begin
    if exists (select 1 from pg_roles where rolname = 'control_api') then
        grant select, insert, update, delete on
            control.users, control.external_identities, control.workshops,
            control.memberships, control.membership_targets,
            control.invitations, control.ownership_transfers,
            control.entitlements, control.workshop_modules,
            control.usage_counters, control.usage_reservations,
            control.outbox, control.operations, control.odoo_databases,
            control.workshop_recovery_points,
            control.workshop_recovery_components,
            control.workshop_recovery_rehearsals,
            control.workshop_deletions, control.product_lookup_cache,
            control.provider_rate_limits, control.service_instances,
            control.commands
        to control_api;
        grant select, insert on control.audit_events to control_api;
    end if;

    if exists (select 1 from pg_roles where rolname = 'control_membership_worker') then
        grant select on control.users, control.external_identities,
            control.workshops, control.memberships, control.workshop_modules,
            control.service_instances to control_membership_worker;
        grant select, insert, update on control.membership_targets,
            control.operations to control_membership_worker;
    end if;

    if exists (select 1 from pg_roles where rolname = 'control_provisioning_worker') then
        grant select on control.workshops, control.memberships,
            control.odoo_databases to control_provisioning_worker;
        grant select, insert, update on control.service_instances,
            control.membership_targets, control.operations
        to control_provisioning_worker;
    end if;

    if exists (select 1 from pg_roles where rolname = 'control_invoice_worker') then
        grant select on control.workshops, control.memberships,
            control.membership_targets, control.workshop_modules,
            control.service_instances, control.entitlements
        to control_invoice_worker;
        grant select, insert, update, delete on control.usage_reservations,
            control.usage_counters, control.provider_rate_limits,
            control.operations to control_invoice_worker;
    end if;

    if exists (select 1 from pg_roles where rolname = 'control_inventory_worker') then
        grant select on control.workshops, control.memberships,
            control.membership_targets, control.workshop_modules,
            control.service_instances, control.entitlements
        to control_inventory_worker;
        grant select, insert, update, delete on control.usage_reservations,
            control.usage_counters, control.provider_rate_limits,
            control.product_lookup_cache, control.operations
        to control_inventory_worker;
    end if;

    if exists (select 1 from pg_roles where rolname = 'control_email_worker') then
        grant select on control.invitations to control_email_worker;
        grant select, update on control.outbox, control.operations
        to control_email_worker;
    end if;

    if exists (select 1 from pg_roles where rolname = 'control_reconciliation_worker') then
        grant select on control.users, control.external_identities,
            control.workshops, control.memberships,
            control.workshop_modules, control.entitlements,
            control.odoo_databases to control_reconciliation_worker;
        grant select, insert, update on control.membership_targets,
            control.service_instances, control.operations
        to control_reconciliation_worker;
    end if;

    if exists (select 1 from pg_roles where rolname = 'control_lifecycle_worker') then
        grant select on control.workshops, control.odoo_databases,
            control.workshop_recovery_components to control_lifecycle_worker;
        grant select, insert, update, delete on control.operations,
            control.workshop_recovery_points,
            control.workshop_recovery_components,
            control.workshop_recovery_rehearsals,
            control.workshop_deletions to control_lifecycle_worker;
        grant update on control.workshops, control.odoo_databases
        to control_lifecycle_worker;
    end if;

    if exists (select 1 from pg_roles where rolname = 'control_backup_scheduler') then
        grant select on control.workshops, control.odoo_databases,
            control.workshop_recovery_points,
            control.workshop_recovery_rehearsals to control_backup_scheduler;
        grant select, insert on control.operations,
            control.workshop_recovery_points,
            control.workshop_recovery_rehearsals to control_backup_scheduler;
    end if;

    if exists (select 1 from pg_roles where rolname = 'control_driver_ledger') then
        grant select, insert, update on control.deployment_driver_operations
        to control_driver_ledger;
        grant select, update on control.odoo_databases,
            control.operations, control.workshop_recovery_points
        to control_driver_ledger;
        grant select, insert, delete on control.workshop_recovery_components
        to control_driver_ledger;
    end if;
end
$$;

-- Future objects are private until an explicit migration assigns them. This is
-- deliberately stricter than granting a catch-all runtime default privilege.
alter default privileges revoke all on tables from public;
alter default privileges revoke all on sequences from public;
alter default privileges revoke execute on functions from public;
