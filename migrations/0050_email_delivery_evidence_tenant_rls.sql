-- Bind provider delivery evidence to the same workshop as its protected
-- outbox parent, and require transaction-local workshop context for direct
-- suppression and branded-domain workflows.

alter table control.email_delivery_events
    add column workshop_id uuid;

update control.email_delivery_events event
   set workshop_id = outbox.workshop_id
  from control.outbox outbox
 where outbox.id = event.outbox_id;

alter table control.email_delivery_events
    alter column workshop_id set not null,
    drop constraint email_delivery_events_outbox_id_fkey,
    add constraint email_delivery_events_event_tenant_key
        unique (event_id, workshop_id),
    add constraint email_delivery_events_outbox_tenant_fkey
        foreign key (outbox_id, workshop_id)
        references control.outbox(id, workshop_id)
        on delete cascade;

alter table control.email_suppressions
    drop constraint email_suppressions_source_event_id_fkey,
    add constraint email_suppressions_source_event_tenant_fkey
        foreign key (source_event_id, workshop_id)
        references control.email_delivery_events(event_id, workshop_id)
        on delete restrict;

create or replace function control.record_transactional_outbox_delivery_event(
    p_event_id uuid,
    p_outbox_id uuid,
    p_provider_message_id uuid,
    p_sns_message_id uuid,
    p_provider_domain_id uuid,
    p_event_type text,
    p_occurred_at timestamptz
) returns text
language plpgsql
security definer
set search_path = pg_catalog, control
as $function$
declare
    v_outbox control.outbox%rowtype;
    v_existing control.email_delivery_events%rowtype;
    v_inserted uuid;
    v_delivery_state text;
    v_suppression_reason text;
begin
    v_delivery_state := case p_event_type
        when 'email_queued' then 'submitted'
        when 'email_deferred' then 'deferred'
        when 'email_delivered' then 'delivered'
        when 'email_dropped' then 'bounced'
        when 'email_mailbox_not_found' then 'bounced'
        when 'email_spam' then 'complained'
        when 'email_blocklisted' then 'suppressed'
        else null
    end;
    v_suppression_reason := case p_event_type
        when 'email_dropped' then 'dropped'
        when 'email_spam' then 'spam'
        when 'email_mailbox_not_found' then 'mailbox_not_found'
        when 'email_blocklisted' then 'blocklisted'
        else null
    end;
    if v_delivery_state is null then
        raise exception using
            errcode = '22023',
            message = 'mail delivery event type is invalid';
    end if;

    select outbox.* into v_outbox
      from control.outbox outbox
     where outbox.id = p_outbox_id
       and outbox.kind = 'odoo_transactional'
       and (outbox.provider_message_id is null
            or outbox.provider_message_id = p_provider_message_id)
       and (outbox.provider_domain_id is null
            or outbox.provider_domain_id = p_provider_domain_id)
     for update;
    if not found then
        return 'ignored';
    end if;

    insert into control.email_delivery_events(
        event_id,
        outbox_id,
        workshop_id,
        provider_message_id,
        sns_message_id,
        event_type,
        occurred_at
    ) values (
        p_event_id,
        p_outbox_id,
        v_outbox.workshop_id,
        p_provider_message_id,
        p_sns_message_id,
        p_event_type,
        p_occurred_at
    )
    on conflict(event_id) do nothing
    returning event_id into v_inserted;

    if v_inserted is null then
        select event.* into v_existing
          from control.email_delivery_events event
         where event.event_id = p_event_id;
        if v_existing.outbox_id is distinct from p_outbox_id
           or v_existing.workshop_id is distinct from v_outbox.workshop_id
           or v_existing.provider_message_id is distinct from p_provider_message_id
           or v_existing.sns_message_id is distinct from p_sns_message_id
           or v_existing.event_type is distinct from p_event_type
           or v_existing.occurred_at is distinct from p_occurred_at then
            return 'conflict';
        end if;
        return 'replayed';
    end if;

    update control.outbox outbox
       set delivery_state = v_delivery_state,
           last_event_at = p_occurred_at,
           provider_message_id = coalesce(outbox.provider_message_id, p_provider_message_id),
           provider_domain_id = coalesce(outbox.provider_domain_id, p_provider_domain_id),
           state = case when outbox.state = 'sending' then 'sent' else outbox.state end,
           sent_at = case
               when outbox.state = 'sending' then coalesce(outbox.sent_at, now())
               else outbox.sent_at
           end
     where outbox.id = p_outbox_id
       and (outbox.last_event_at is null or outbox.last_event_at <= p_occurred_at);

    if p_event_type = 'email_delivered' then
        update control.webshop_email_domains domain
           set test_delivered_at = coalesce(domain.test_delivered_at, p_occurred_at),
               updated_at = now(),
               version = domain.version + 1
         where domain.test_outbox_id = p_outbox_id
           and domain.workshop_id = v_outbox.workshop_id
           and domain.desired_state = 'active';
    end if;

    if v_suppression_reason is not null then
        insert into control.email_suppressions(
            workshop_id,
            recipient,
            reason,
            source_event_id
        ) values (
            v_outbox.workshop_id,
            v_outbox.recipient,
            v_suppression_reason,
            p_event_id
        )
        on conflict(workshop_id, recipient) do update set
            reason = excluded.reason,
            source_event_id = excluded.source_event_id,
            updated_at = now();
    end if;

    return 'created';
end
$function$;

revoke all on function control.record_transactional_outbox_delivery_event(
    uuid, uuid, uuid, uuid, uuid, text, timestamptz
) from public;

alter table control.email_delivery_events enable row level security;
alter table control.email_delivery_events force row level security;
alter table control.email_suppressions enable row level security;
alter table control.email_suppressions force row level security;
alter table control.webshop_email_domains enable row level security;
alter table control.webshop_email_domains force row level security;

do $migration$
begin
    if exists (select 1 from pg_roles where rolname = 'control') then
        create policy email_delivery_events_migration_owner
            on control.email_delivery_events
            as permissive for all to control using (true) with check (true);
        create policy email_suppressions_migration_owner
            on control.email_suppressions
            as permissive for all to control using (true) with check (true);
        create policy webshop_email_domains_migration_owner
            on control.webshop_email_domains
            as permissive for all to control using (true) with check (true);
    end if;

    if exists (select 1 from pg_roles where rolname = 'control_api') then
        revoke select, insert on table control.email_delivery_events from control_api;
        revoke select, insert, update on table control.email_suppressions from control_api;
        revoke select, insert, update on table control.webshop_email_domains from control_api;
    end if;

    if exists (select 1 from pg_roles where rolname = 'control_tenant_api') then
        grant select on table control.email_suppressions to control_tenant_api;
        create policy email_suppressions_tenant_api_read
            on control.email_suppressions
            as permissive for select to control_tenant_api
            using (workshop_id = control.current_workshop_id());
        create policy webshop_email_domains_tenant_api_read
            on control.webshop_email_domains
            as permissive for select to control_tenant_api
            using (workshop_id = control.current_workshop_id());
        create policy webshop_email_domains_tenant_api_insert
            on control.webshop_email_domains
            as permissive for insert to control_tenant_api
            with check (workshop_id = control.current_workshop_id());
        create policy webshop_email_domains_tenant_api_update
            on control.webshop_email_domains
            as permissive for update to control_tenant_api
            using (workshop_id = control.current_workshop_id())
            with check (workshop_id = control.current_workshop_id());
    end if;

    if exists (select 1 from pg_roles where rolname = 'control_reconciliation_worker') then
        create policy email_suppressions_reconciliation_read
            on control.email_suppressions
            as permissive for select to control_reconciliation_worker
            using (workshop_id = control.current_workshop_id());
        create policy webshop_email_domains_reconciliation_read
            on control.webshop_email_domains
            as permissive for select to control_reconciliation_worker
            using (workshop_id = control.current_workshop_id());
        create policy webshop_email_domains_reconciliation_update
            on control.webshop_email_domains
            as permissive for update to control_reconciliation_worker
            using (workshop_id = control.current_workshop_id())
            with check (workshop_id = control.current_workshop_id());
    end if;

    if exists (select 1 from pg_roles where rolname = 'control_email_worker') then
        create policy webshop_email_domains_email_worker_read
            on control.webshop_email_domains
            as permissive for select to control_email_worker
            using (workshop_id = control.current_workshop_id());
    end if;
end
$migration$;

comment on table control.email_delivery_events is
'Provider delivery evidence bound to its workshop-owned outbox parent; runtime access is function-only.';

comment on table control.email_suppressions is
'Workshop-owned recipient suppression evidence protected by forced tenant RLS; provider writes are function-only.';

comment on table control.webshop_email_domains is
'Workshop-owned branded sender-domain state protected by forced tenant RLS; fleet admission and provider evidence are function-only.';
