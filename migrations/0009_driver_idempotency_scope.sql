-- Driver requests are idempotent within their actual authority scope. Tenant
-- actions are isolated by workshop and action; fleet release remains one
-- deliberate global namespace represented by a NULL workshop.

alter table control.deployment_driver_operations
    drop constraint deployment_driver_operations_pkey,
    add constraint deployment_driver_operations_scope_check
        check ((action = 'release') = (workshop_id is null)),
    add constraint deployment_driver_operations_scope_key
        unique nulls not distinct (workshop_id, action, idempotency_key);

do $migration$
begin
    if exists (select 1 from pg_roles where rolname = 'control_driver_ledger') then
        revoke insert, update on table control.deployment_driver_operations
            from control_driver_ledger;
        grant insert (idempotency_key, workshop_id, action, request_digest)
            on table control.deployment_driver_operations to control_driver_ledger;
        grant update (state, response, safe_error, updated_at)
            on table control.deployment_driver_operations to control_driver_ledger;
    end if;
end
$migration$;

comment on constraint deployment_driver_operations_scope_key
    on control.deployment_driver_operations is
'Idempotency namespace: one global release scope and independent workshop/action scopes.';
