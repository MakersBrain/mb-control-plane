alter table control.outbox
    add column workshop_id uuid references control.workshops(id) on delete restrict,
    add column source_key text,
    add column provider_message_id uuid unique,
    add column delivery_state text not null default 'pending' check (delivery_state in (
        'pending','submitted','delivered','deferred','bounced','complained','suppressed'
    )),
    add column last_event_at timestamptz,
    add constraint outbox_source_scope check (
        (kind = 'odoo_transactional' and workshop_id is not null and source_key is not null
         and length(source_key) between 1 and 255
         and source_key ~ '^[A-Za-z0-9._:/-]+$'
         and template = 'odoo-rendered-v1')
        or
        (kind <> 'odoo_transactional' and source_key is null)
    );

create unique index outbox_workshop_source_unique
    on control.outbox(workshop_id,source_key)
    where source_key is not null;

create index outbox_workshop_delivery_state
    on control.outbox(workshop_id,delivery_state,created_at desc)
    where workshop_id is not null;

comment on column control.outbox.source_key is
'Stable tenant-supplied Odoo mail identity. It contains no recipient or message content.';
comment on column control.outbox.provider_message_id is
'Opaque Scaleway TEM email UUID used to correlate authenticated delivery events.';
