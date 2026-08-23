-- Make periodic webshop-domain admission a bounded fleet capability while
-- preserving workshop ownership for every post-lease execution mutation.

alter table control.webshop_domains
    drop constraint webshop_domains_operation_id_fkey,
    add constraint webshop_domains_operation_workshop_fkey
        foreign key (operation_id, workshop_id)
        references control.operations(id, workshop_id)
        on delete restrict;

create or replace function control.admit_due_webshop_domain_reconciliations(
    p_limit integer,
    p_trace_parent text,
    p_trace_state text
) returns table(operation_id uuid, workshop_id uuid, domain_id uuid)
language plpgsql security definer
set search_path = pg_catalog, control
as $function$
declare
    v_domain record;
    v_operation_id uuid;
    v_inserted_id uuid;
    v_bucket bigint;
    v_changed bigint;
begin
    if p_limit < 1 or p_limit > 500 then
        raise exception 'webshop domain admission limit must be between 1 and 500'
            using errcode='22023';
    end if;
    if p_trace_parent is not null
       and p_trace_parent !~ '^[0-9a-f]{2}-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$' then
        raise exception 'invalid trace parent' using errcode='22023';
    end if;
    if p_trace_state is not null
       and (length(p_trace_state) < 1 or length(p_trace_state) > 512
            or p_trace_state ~ '[\r\n]') then
        raise exception 'invalid trace state' using errcode='22023';
    end if;
    v_bucket := floor(extract(epoch from clock_timestamp()) / 300)::bigint;

    for v_domain in
        select domain.id,domain.workshop_id,domain.version,
               domain.desired_state='disconnected'
                   and domain.redirect_target is not null as restore_platform_canonical
        from control.webshop_domains domain
        where ((domain.desired_state='active'
                and domain.state in ('dns_pending','certificate_pending','testing')
                and domain.ownership_verified_at is not null)
            or (domain.desired_state='disconnected'
                and domain.state in ('disconnecting','action_required')))
          and not exists (
              select 1 from control.operations operation
              where operation.id=domain.operation_id
                and operation.state in ('pending','in_flight','awaiting_reconciliation')
          )
        order by domain.id
        for update skip locked
        limit p_limit
    loop
        v_operation_id := gen_random_uuid();
        v_inserted_id := null;
        insert into control.operations(
            id,kind,queue,workshop_id,payload,correlation_id,idempotency_key,
            trace_parent,trace_state
        ) values (
            v_operation_id,'webshop-domain.reconcile','tenant-reconciliation',
            v_domain.workshop_id,
            jsonb_build_object(
                'domain_id',v_domain.id,
                'reason','periodic_observation',
                'restore_platform_canonical',v_domain.restore_platform_canonical
            ),
            gen_random_uuid(),
            format('periodic-domain:%s:%s',v_domain.id,v_bucket),
            p_trace_parent,p_trace_state
        ) on conflict (kind,requested_by,idempotency_key) do nothing
        returning id into v_inserted_id;

        -- A terminal operation from this same admission window is not rebound.
        -- The next five-minute window gets a new key and can observe again.
        if v_inserted_id is null then
            continue;
        end if;

        update control.webshop_domains domain
        set operation_id=v_inserted_id,updated_at=now(),version=version+1
        where domain.id=v_domain.id and domain.workshop_id=v_domain.workshop_id
          and domain.version=v_domain.version
          and ((domain.desired_state='active'
                and domain.state in ('dns_pending','certificate_pending','testing')
                and domain.ownership_verified_at is not null)
            or (domain.desired_state='disconnected'
                and domain.state in ('disconnecting','action_required')))
          and not exists (
              select 1 from control.operations operation
              where operation.id=domain.operation_id
                and operation.state in ('pending','in_flight','awaiting_reconciliation')
          );
        get diagnostics v_changed = row_count;
        if v_changed <> 1 then
            raise exception 'webshop domain claim lost its compare-and-set'
                using errcode='40001';
        end if;
        operation_id := v_inserted_id;
        workshop_id := v_domain.workshop_id;
        domain_id := v_domain.id;
        return next;
    end loop;
end
$function$;

revoke all on function control.admit_due_webshop_domain_reconciliations(integer,text,text)
    from public;

do $migration$
begin
    if exists(select 1 from pg_roles where rolname='control_reconciliation_worker') then
        grant execute on function
            control.admit_due_webshop_domain_reconciliations(integer,text,text)
            to control_reconciliation_worker;
    end if;
end
$migration$;

comment on function control.admit_due_webshop_domain_reconciliations(integer,text,text) is
'Atomically admits bounded periodic domain work; returns explicit workshop ownership.';
