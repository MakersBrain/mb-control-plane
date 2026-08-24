-- Admit periodic webshop-email-domain work as one bounded, transactional
-- capability.  Selection, durable operation creation, and tenant binding are
-- indivisible so concurrent worker replicas cannot enqueue orphaned or
-- cross-workshop work.

alter table control.webshop_email_domains
    drop constraint webshop_email_domains_operation_id_fkey,
    add constraint webshop_email_domains_operation_workshop_fkey
        foreign key (operation_id, workshop_id)
        references control.operations(id, workshop_id)
        on delete restrict;

create table control.periodic_admission_cursors (
    workflow text primary key,
    after_id uuid,
    updated_at timestamptz not null default now(),
    constraint periodic_admission_cursors_workflow_check check (
        workflow in ('tenant-reconcile','webshop-domain','webshop-email-domain')
    )
);

insert into control.periodic_admission_cursors(workflow) values
    ('tenant-reconcile'),('webshop-domain'),('webshop-email-domain');

revoke all on table control.periodic_admission_cursors from public;

comment on table control.periodic_admission_cursors is
'Function-private durable cursors prevent bounded periodic admission from starving later UUIDs.';

create or replace function control.admit_due_webshop_email_domain_reconciliations(
    p_limit integer,
    p_trace_parent text,
    p_trace_state text
) returns table(operation_id uuid, workshop_id uuid, email_domain_id uuid)
language plpgsql security definer
set search_path = pg_catalog, control
as $function$
declare
    v_domain record;
    v_operation_id uuid;
    v_inserted_id uuid;
    v_bucket bigint;
    v_changed bigint;
    v_after_id uuid;
begin
    if p_limit < 1 or p_limit > 500 then
        raise exception 'webshop email domain admission limit must be between 1 and 500'
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

    select cursor.after_id into v_after_id
      from control.periodic_admission_cursors cursor
     where cursor.workflow='webshop-email-domain'
     for update;
    if not found then
        raise exception 'webshop email domain admission cursor is missing'
            using errcode='55000';
    end if;

    for v_domain in
        select domain.id,domain.workshop_id,domain.version
          from control.webshop_email_domains domain
         where ((domain.desired_state='active'
                 and domain.state in ('registering','dns_pending','testing'))
             or (domain.desired_state='disconnected'
                 and domain.state in ('disconnecting','action_required')))
           and not exists (
               select 1 from control.operations operation
                where operation.id=domain.operation_id
                  and operation.state in ('pending','in_flight','awaiting_reconciliation')
           )
         order by (v_after_id is not null and domain.id <= v_after_id),domain.id
         for update skip locked
         limit p_limit
    loop
        v_after_id := v_domain.id;
        v_operation_id := gen_random_uuid();
        v_inserted_id := null;
        insert into control.operations(
            id,kind,queue,workshop_id,payload,correlation_id,idempotency_key,
            trace_parent,trace_state
        ) values (
            v_operation_id,'webshop-email-domain.reconcile','tenant-reconciliation',
            v_domain.workshop_id,
            jsonb_build_object(
                'email_domain_id',v_domain.id,
                'reason','periodic_observation'
            ),
            gen_random_uuid(),
            format('periodic-email-domain:%s:%s',v_domain.id,v_bucket),
            p_trace_parent,p_trace_state
        ) on conflict (kind,requested_by,idempotency_key) do nothing
        returning id into v_inserted_id;

        -- A terminal operation from this admission window remains terminal.
        -- A later window may observe and admit the domain again.
        if v_inserted_id is null then
            continue;
        end if;

        update control.webshop_email_domains domain
           set operation_id=v_inserted_id,updated_at=now(),version=version+1
         where domain.id=v_domain.id
           and domain.workshop_id=v_domain.workshop_id
           and domain.version=v_domain.version
           and ((domain.desired_state='active'
                 and domain.state in ('registering','dns_pending','testing'))
             or (domain.desired_state='disconnected'
                 and domain.state in ('disconnecting','action_required')))
           and not exists (
               select 1 from control.operations operation
                where operation.id=domain.operation_id
                  and operation.state in ('pending','in_flight','awaiting_reconciliation')
           );
        get diagnostics v_changed = row_count;
        if v_changed <> 1 then
            raise exception 'webshop email domain claim lost its compare-and-set'
                using errcode='40001';
        end if;

        operation_id := v_inserted_id;
        workshop_id := v_domain.workshop_id;
        email_domain_id := v_domain.id;
        return next;
    end loop;

    update control.periodic_admission_cursors
       set after_id=v_after_id,updated_at=clock_timestamp()
     where workflow='webshop-email-domain';
end
$function$;

-- Migration 0011 used immutable UUID ordering.  When more than one page was
-- due, repeated calls in the same five-minute idempotency window could keep
-- reconsidering the first terminal page and starve later UUIDs.  Preserve its
-- contract while advancing a durable cyclic cursor on every considered row.
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
    v_after_id uuid;
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

    select cursor.after_id into v_after_id
      from control.periodic_admission_cursors cursor
     where cursor.workflow='webshop-domain'
     for update;
    if not found then
        raise exception 'webshop domain admission cursor is missing'
            using errcode='55000';
    end if;

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
           and not (domain.desired_state='disconnected'
               and domain.provider_ref is not null
               and exists (
                   select 1
                     from control.webshop_domain_provider_deletion_attempts attempt
                    where attempt.domain_id=domain.id
                      and attempt.workshop_id=domain.workshop_id
                      and attempt.provider_ref=domain.provider_ref
                      and attempt.state='budget_exhausted'
               ))
         order by (v_after_id is not null and domain.id <= v_after_id),domain.id
         for update skip locked
         limit p_limit
    loop
        v_after_id := v_domain.id;
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

        if v_inserted_id is null then
            continue;
        end if;

        update control.webshop_domains domain
           set operation_id=v_inserted_id,updated_at=now(),version=version+1
         where domain.id=v_domain.id
           and domain.workshop_id=v_domain.workshop_id
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
           )
           and not (domain.desired_state='disconnected'
               and domain.provider_ref is not null
               and exists (
                   select 1
                     from control.webshop_domain_provider_deletion_attempts attempt
                    where attempt.domain_id=domain.id
                      and attempt.workshop_id=domain.workshop_id
                      and attempt.provider_ref=domain.provider_ref
                      and attempt.state='budget_exhausted'
               ));
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

    update control.periodic_admission_cursors
       set after_id=v_after_id,updated_at=clock_timestamp()
     where workflow='webshop-domain';
end
$function$;

create or replace function control.admit_due_tenant_reconciliations(
    p_limit integer,
    p_tenant_domain text,
    p_trace_parent text,
    p_trace_state text
) returns table(operation_id uuid, workshop_id uuid)
language plpgsql security definer
set search_path = pg_catalog, control
as $function$
declare
    v_tenant record;
    v_inserted_id uuid;
    v_bucket bigint;
    v_after_id uuid;
begin
    if p_limit < 1 or p_limit > 500 then
        raise exception 'tenant reconciliation admission limit must be between 1 and 500'
            using errcode='22023';
    end if;
    if p_tenant_domain is null or length(p_tenant_domain) < 1
       or length(p_tenant_domain) > 253 or p_tenant_domain <> lower(p_tenant_domain)
       or p_tenant_domain !~ '^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$' then
        raise exception 'invalid tenant domain' using errcode='22023';
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
    v_bucket := floor(extract(epoch from clock_timestamp()) / 21600)::bigint;

    select cursor.after_id into v_after_id
      from control.periodic_admission_cursors cursor
     where cursor.workflow='tenant-reconcile'
     for update;
    if not found then
        raise exception 'tenant reconciliation admission cursor is missing'
            using errcode='55000';
    end if;

    for v_tenant in
        select workshop.id as workshop_id,database.id as database_id,
               workshop.slug,database.database_ref,database.public_hostname,
               exists(select 1 from control.workshop_modules module
                       where module.workshop_id=workshop.id
                         and module.module_key='documents' and module.state='enabled')
                   as paperless_enabled,
               coalesce((select jsonb_agg(jsonb_build_object(
                           'hostname',domain.hostname,'canonical',domain.canonical)
                           order by domain.hostname)
                           from control.webshop_domains domain
                          where domain.workshop_id=workshop.id
                            and domain.state in ('testing','active')
                            and domain.desired_state='active'),'[]'::jsonb)
                   as custom_hostnames
          from control.workshops workshop
          join control.odoo_databases database on database.workshop_id=workshop.id
         where workshop.status in ('trial','active','past_due','restricted','suspended')
           and database.kind='primary' and database.deleted_at is null
           and database.public_hostname is not null
           and not exists(
               select 1 from control.release_fleet_runs fleet
                where fleet.state in ('preflighting','preparing','paused','activating')
           )
           and not exists(
               select 1 from control.operations operation
                where operation.workshop_id=workshop.id
                  and operation.state in ('pending','in_flight','awaiting_reconciliation')
                  and operation.kind in ('tenant.provision','tenant.reconcile',
                                         'tenant.lifecycle','odoo.release.adopt')
           )
         order by (v_after_id is not null and workshop.id <= v_after_id),workshop.id
         for update of workshop skip locked
         limit p_limit
    loop
        v_after_id := v_tenant.workshop_id;
        v_inserted_id := null;
        insert into control.operations(
            id,kind,queue,workshop_id,payload,correlation_id,idempotency_key,
            trace_parent,trace_state
        ) values (
            gen_random_uuid(),'tenant.reconcile','tenant-reconciliation',
            v_tenant.workshop_id,
            jsonb_build_object(
                'database_id',v_tenant.database_id,
                'database_ref',v_tenant.database_ref,
                'public_hostname',v_tenant.public_hostname,
                'paperless_hostname',format('docs-%s.%s',v_tenant.slug,p_tenant_domain),
                'paperless_enabled',v_tenant.paperless_enabled,
                'custom_hostnames',v_tenant.custom_hostnames,
                'reason','periodic_drift_reconciliation'
            ),
            gen_random_uuid(),
            format('periodic-reconcile:%s:%s',v_tenant.workshop_id,v_bucket),
            p_trace_parent,p_trace_state
        ) on conflict (kind,requested_by,idempotency_key) do nothing
        returning id into v_inserted_id;

        if v_inserted_id is null then
            continue;
        end if;
        operation_id := v_inserted_id;
        workshop_id := v_tenant.workshop_id;
        return next;
    end loop;

    update control.periodic_admission_cursors
       set after_id=v_after_id,updated_at=clock_timestamp()
     where workflow='tenant-reconcile';
end
$function$;

revoke all on function
    control.admit_due_webshop_email_domain_reconciliations(integer,text,text)
    from public;

revoke all on function control.admit_due_webshop_domain_reconciliations(integer,text,text)
    from public;

revoke all on function control.admit_due_tenant_reconciliations(integer,text,text,text)
    from public;

do $migration$
begin
    if exists(select 1 from pg_roles where rolname='control_reconciliation_worker') then
        grant execute on function
            control.admit_due_webshop_email_domain_reconciliations(integer,text,text)
            to control_reconciliation_worker;
        grant execute on function
            control.admit_due_webshop_domain_reconciliations(integer,text,text)
            to control_reconciliation_worker;
        grant execute on function
            control.admit_due_tenant_reconciliations(integer,text,text,text)
            to control_reconciliation_worker;
    end if;
end
$migration$;

comment on function
    control.admit_due_webshop_email_domain_reconciliations(integer,text,text) is
'Atomically admits bounded periodic email-domain work; returns explicit workshop ownership.';

comment on function control.admit_due_webshop_domain_reconciliations(integer,text,text) is
'Atomically admits bounded periodic custom-hostname work using a durable fair cursor.';

comment on function control.admit_due_tenant_reconciliations(integer,text,text,text) is
'Atomically admits bounded periodic tenant work using a durable fair cursor.';
