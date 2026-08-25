-- Every outbox row has a non-null workshop owner. Keep platform reporting
-- read-only, require transaction-local workshop context for producers and the
-- email worker, and mediate authenticated provider events through one exact,
-- replay-safe database capability.

create function control.record_transactional_outbox_delivery_event(
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
        provider_message_id,
        sns_message_id,
        event_type,
        occurred_at
    ) values (
        p_event_id,
        p_outbox_id,
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

alter table control.outbox enable row level security;
alter table control.outbox force row level security;

do $migration$
begin
    if exists (select 1 from pg_roles where rolname = 'control') then
        create policy outbox_migration_owner on control.outbox
        as permissive for all to control using (true) with check (true);
    end if;

    if exists (select 1 from pg_roles where rolname = 'control_api') then
        revoke insert, update, delete on table control.outbox from control_api;
        create policy outbox_platform_read on control.outbox
        as permissive for select to control_api using (true);
        grant execute on function control.record_transactional_outbox_delivery_event(
            uuid, uuid, uuid, uuid, uuid, text, timestamptz
        ) to control_api;
    end if;

    if exists (select 1 from pg_roles where rolname = 'control_tenant_api') then
        create policy outbox_tenant_api_read on control.outbox
        as permissive for select to control_tenant_api
        using (workshop_id = control.current_workshop_id());
        create policy outbox_tenant_api_insert on control.outbox
        as permissive for insert to control_tenant_api
        with check (workshop_id = control.current_workshop_id());
        grant execute on function control.current_workshop_id() to control_tenant_api;
    end if;

    if exists (select 1 from pg_roles where rolname = 'control_email_worker') then
        create policy outbox_email_worker_read on control.outbox
        as permissive for select to control_email_worker
        using (workshop_id = control.current_workshop_id());
        create policy outbox_email_worker_update on control.outbox
        as permissive for update to control_email_worker
        using (workshop_id = control.current_workshop_id())
        with check (workshop_id = control.current_workshop_id());
        grant execute on function control.current_workshop_id() to control_email_worker;
    end if;

    if exists (select 1 from pg_roles where rolname = 'control_reconciliation_worker') then
        revoke select on table control.outbox from control_reconciliation_worker;
        create policy outbox_reconciliation_worker_insert on control.outbox
        as permissive for insert to control_reconciliation_worker
        with check (workshop_id = control.current_workshop_id());
        grant execute on function control.current_workshop_id() to control_reconciliation_worker;
    end if;

    if exists (select 1 from pg_roles where rolname = 'control_privacy_worker') then
        revoke select, update, delete on table control.outbox from control_privacy_worker;
    end if;
end
$migration$;

comment on table control.outbox is
'Workshop-owned durable email outbox protected by forced tenant RLS; platform reporting is read-only, producers and delivery workers require transaction-local workshop context, provider events use one exact replay-safe capability, and privacy retention is function-only.';
