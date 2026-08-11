alter table control.usage_reservations drop constraint usage_reservations_pkey;
alter table control.usage_reservations add primary key (operation_id, metric);

alter table control.usage_counters drop constraint usage_counters_metric_check;
alter table control.usage_counters add constraint usage_counters_metric_check check (
    metric in ('azure_invoice_pages', 'azure_inventory_images', 'inventory_ai_images')
);

alter table control.usage_reservations drop constraint usage_reservations_metric_check;
alter table control.usage_reservations add constraint usage_reservations_metric_check check (
    metric in ('azure_invoice_pages', 'azure_inventory_images', 'inventory_ai_images')
);
