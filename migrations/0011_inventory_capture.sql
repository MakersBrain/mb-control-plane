alter table control.operations drop constraint operations_kind_check;
alter table control.operations add constraint operations_kind_check check (kind in (
    'tenant.provision', 'membership.reconcile', 'entitlement.apply',
    'invoice.capture', 'inventory.capture.extract', 'tenant.reconcile',
    'tenant.lifecycle', 'email.delivery', 'module.enable'
));

alter table control.workshop_modules drop constraint workshop_modules_module_key_check;
alter table control.workshop_modules add constraint workshop_modules_module_key_check check (module_key in (
    'catalogue', 'firings', 'kiln-connectivity', 'labels', 'depot', 'sumup',
    'documents', 'invoice-capture', 'azure-invoice-extraction',
    'inventory-capture', 'azure-label-extraction', 'inventory-ai-fallback'
));

alter table control.usage_counters drop constraint usage_counters_metric_check;
alter table control.usage_counters add constraint usage_counters_metric_check check (
    metric in ('azure_invoice_pages', 'azure_inventory_images')
);

alter table control.usage_reservations drop constraint usage_reservations_metric_check;
alter table control.usage_reservations add constraint usage_reservations_metric_check check (
    metric in ('azure_invoice_pages', 'azure_inventory_images')
);
