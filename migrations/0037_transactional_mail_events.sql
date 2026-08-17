create table control.email_delivery_events (
    event_id uuid primary key,
    outbox_id uuid not null references control.outbox(id) on delete cascade,
    provider_message_id uuid not null,
    sns_message_id uuid not null,
    event_type text not null check (event_type in (
        'email_queued','email_deferred','email_delivered','email_dropped',
        'email_spam','email_mailbox_not_found','email_blocklisted'
    )),
    occurred_at timestamptz not null,
    received_at timestamptz not null default now()
);

create index email_delivery_events_outbox_occurred
    on control.email_delivery_events(outbox_id,occurred_at desc);

create table control.email_suppressions (
    workshop_id uuid not null references control.workshops(id) on delete cascade,
    recipient text not null,
    reason text not null check (reason in ('dropped','spam','mailbox_not_found','blocklisted')),
    source_event_id uuid not null references control.email_delivery_events(event_id) on delete restrict,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    primary key (workshop_id,recipient)
);

comment on table control.email_suppressions is
'Tenant-scoped do-not-send registry derived only from authenticated provider delivery events.';

do $$
begin
    if exists (select 1 from pg_roles where rolname = 'control_api') then
        grant select,insert on control.email_delivery_events to control_api;
        grant select,insert,update on control.email_suppressions to control_api;
    end if;
end
$$;
