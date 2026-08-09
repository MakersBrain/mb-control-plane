alter table control.deployment_driver_operations
    drop constraint deployment_driver_operations_action_check;

alter table control.deployment_driver_operations
    add constraint deployment_driver_operations_action_check
    check (action in ('provision', 'reconcile', 'lifecycle', 'rehearse'));
