-- Give every workshop route one immutable desired-state history and one
-- database-backed physical application authority. Generations are allocated
-- while source rows are locked, never from driver request arrival order.

create table control.workshop_route_projections (
    workshop_id uuid not null,
    generation bigint not null,
    projection_digest text not null,
    projection jsonb not null,
    source_operation_id uuid not null,
    source_operation_attempt integer not null,
    created_at timestamptz not null default now(),
    primary key (workshop_id, generation),
    unique (workshop_id, generation, projection_digest),
    constraint workshop_route_projections_workshop_fkey
        foreign key (workshop_id) references control.workshops(id) on delete restrict,
    constraint workshop_route_projections_source_operation_fkey
        foreign key (source_operation_id, workshop_id)
        references control.operations(id, workshop_id) on delete restrict,
    constraint workshop_route_projections_generation_check check (generation > 0),
    constraint workshop_route_projections_digest_check
        check (projection_digest ~ '^sha256:[0-9a-f]{64}$'),
    constraint workshop_route_projections_projection_check
        check (jsonb_typeof(projection) = 'object'),
    constraint workshop_route_projections_attempt_check
        check (source_operation_attempt > 0)
);

create table control.workshop_route_projection_state (
    workshop_id uuid primary key,
    desired_generation bigint,
    desired_digest text,
    applied_generation bigint,
    applied_digest text,
    applied_rendered_digest text,
    applied_driver_operation_id uuid,
    applied_fence_token bigint,
    updated_at timestamptz not null default now(),
    constraint workshop_route_projection_state_workshop_fkey
        foreign key (workshop_id) references control.workshops(id) on delete restrict,
    constraint workshop_route_projection_state_desired_shape check (
        (desired_generation is null and desired_digest is null)
        or (desired_generation > 0 and desired_digest ~ '^sha256:[0-9a-f]{64}$')
    ),
    constraint workshop_route_projection_state_applied_shape check (
        (applied_generation is null and applied_digest is null
            and applied_rendered_digest is null
            and applied_driver_operation_id is null and applied_fence_token is null)
        or
        (applied_generation > 0 and applied_digest ~ '^sha256:[0-9a-f]{64}$'
            and applied_rendered_digest ~ '^sha256:[0-9a-f]{64}$'
            and applied_driver_operation_id is not null and applied_fence_token > 0)
    ),
    constraint workshop_route_projection_state_order_check
        check (applied_generation is null or desired_generation is null
               or applied_generation <= desired_generation),
    constraint workshop_route_projection_state_desired_fkey
        foreign key (workshop_id, desired_generation, desired_digest)
        references control.workshop_route_projections(
            workshop_id, generation, projection_digest
        ) on delete restrict,
    constraint workshop_route_projection_state_applied_fkey
        foreign key (workshop_id, applied_generation, applied_digest)
        references control.workshop_route_projections(
            workshop_id, generation, projection_digest
        ) on delete restrict,
    constraint workshop_route_projection_state_driver_operation_fkey
        foreign key (applied_driver_operation_id)
        references control.deployment_driver_operations(id) on delete restrict
);

create table control.workshop_route_application_leases (
    workshop_id uuid primary key,
    state text not null,
    initialization_required boolean not null,
    fence_token bigint not null default 0,
    driver_operation_id uuid,
    generation bigint,
    projection_digest text,
    lease_owner uuid,
    lease_token uuid,
    lease_expires_at timestamptz,
    heartbeat_at timestamptz,
    quarantined_at timestamptz,
    safe_error text,
    updated_at timestamptz not null default now(),
    constraint workshop_route_application_leases_workshop_fkey
        foreign key (workshop_id) references control.workshops(id) on delete restrict,
    constraint workshop_route_application_leases_driver_operation_fkey
        foreign key (driver_operation_id)
        references control.deployment_driver_operations(id) on delete restrict,
    constraint workshop_route_application_leases_projection_fkey
        foreign key (workshop_id, generation, projection_digest)
        references control.workshop_route_projections(
            workshop_id, generation, projection_digest
        ) on delete restrict,
    constraint workshop_route_application_leases_state_check
        check (state in ('uninitialized','idle','held','quarantined')),
    constraint workshop_route_application_leases_fence_check check (fence_token >= 0),
    constraint workshop_route_application_leases_shape_check check (
        (state in ('uninitialized','idle')
            and driver_operation_id is null and generation is null
            and projection_digest is null and lease_owner is null
            and lease_token is null and lease_expires_at is null
            and heartbeat_at is null and quarantined_at is null and safe_error is null
            and ((state='uninitialized' and initialization_required)
                 or (state='idle' and not initialization_required)))
        or
        (state='held' and driver_operation_id is not null and generation > 0
            and projection_digest ~ '^sha256:[0-9a-f]{64}$' and lease_owner is not null
            and lease_token is not null and lease_expires_at is not null
            and heartbeat_at is not null and quarantined_at is null
            and safe_error is null and fence_token > 0)
        or
        (state='quarantined' and driver_operation_id is not null
            and lease_owner is not null and lease_token is null
            and lease_expires_at is null and heartbeat_at is not null
            and quarantined_at is not null and safe_error in (
                'runtime_outcome_unknown','legacy_route_outcome_unknown'
            ) and fence_token > 0
            and ((safe_error='runtime_outcome_unknown' and generation > 0
                  and projection_digest ~ '^sha256:[0-9a-f]{64}$')
                 or (safe_error='legacy_route_outcome_unknown'
                     and generation is null and projection_digest is null)))
    )
);

-- Existing physical routes cannot be inferred from PostgreSQL. They remain
-- fail closed until a materialized projection succeeds through the fenced
-- application path. A trigger gives only workshops created after this
-- migration a known empty/idle starting state.
insert into control.workshop_route_projection_state(workshop_id)
select id from control.workshops;

insert into control.workshop_route_application_leases(
    workshop_id,state,initialization_required
)
select id,'uninitialized',true from control.workshops;

create or replace function control.seed_workshop_route_projection_state()
returns trigger
language plpgsql security definer
set search_path = pg_catalog, control
as $function$
begin
    insert into control.workshop_route_projection_state(workshop_id)
    values(new.id) on conflict(workshop_id) do nothing;
    insert into control.workshop_route_application_leases(
        workshop_id,state,initialization_required
    ) values(new.id,'idle',false) on conflict(workshop_id) do nothing;
    return null;
end
$function$;

create trigger workshop_route_projection_seed
after insert on control.workshops
for each row execute function control.seed_workshop_route_projection_state();

create or replace function control.reject_workshop_route_projection_mutation()
returns trigger
language plpgsql
set search_path = pg_catalog, control
as $function$
begin
    raise exception 'workshop route projection history is immutable'
        using errcode='55000';
end
$function$;

create trigger workshop_route_projection_immutable
before update or delete on control.workshop_route_projections
for each row execute function control.reject_workshop_route_projection_mutation();

alter table control.deployment_driver_operations
    drop constraint deployment_driver_operations_action_check,
    add constraint deployment_driver_operations_action_check check (
        action in ('provision','reconcile','lifecycle','rehearse','release',
                   'erasure','resume','restrict','carrier-secret',
                   'carrier-secret-delete','route-project')
    ),
    add column route_generation bigint,
    add column route_projection_digest text,
    add column route_fence_token bigint,
    add constraint deployment_driver_operations_route_projection_shape check (
        (route_generation is null and route_projection_digest is null
            and route_fence_token is null)
        or
        (workshop_id is not null and route_generation > 0
            and route_projection_digest ~ '^sha256:[0-9a-f]{64}$'
            and route_fence_token > 0
            and target_key = 'route/' || workshop_id::text)
    ),
    add constraint deployment_driver_operations_route_projection_fkey
        foreign key (workshop_id, route_generation, route_projection_digest)
        references control.workshop_route_projections(
            workshop_id, generation, projection_digest
        ) on delete restrict,
    add constraint deployment_driver_operations_route_active_binding check (
        route_generation is null or state <> 'in_progress' or safe_error is not null or (
            control_operation_id is not null
            and control_operation_attempt is not null and control_operation_attempt > 0
            and control_operation_lease_owner is not null
            and btrim(control_operation_lease_owner) <> ''
            and execution_token is not null and lease_expires_at is not null
            and execution_attempt > 0
        )
    ),
    add constraint deployment_driver_operations_route_binding_key unique (
        id,workshop_id,route_generation,route_projection_digest,route_fence_token
    );

alter table control.workshop_route_application_leases
    add constraint workshop_route_application_leases_driver_binding_fkey
        foreign key (
            driver_operation_id,workshop_id,generation,projection_digest,fence_token
        ) references control.deployment_driver_operations(
            id,workshop_id,route_generation,route_projection_digest,route_fence_token
        ) on delete restrict;

alter table control.workshop_route_projection_state
    add constraint workshop_route_projection_state_driver_binding_fkey
        foreign key (
            applied_driver_operation_id,workshop_id,applied_generation,
            applied_digest,applied_fence_token
        ) references control.deployment_driver_operations(
            id,workshop_id,route_generation,route_projection_digest,route_fence_token
        ) on delete restrict;

create unique index deployment_driver_route_projection_target
    on control.deployment_driver_operations(
        workshop_id,route_generation,route_projection_digest
    ) where route_generation is not null;

-- More than one legacy route writer for one workshop cannot be represented by
-- one resource lease and therefore requires reconciliation before migration.
do $migration$
begin
    if exists (
        select 1
        from control.deployment_driver_operations operation
        where operation.workshop_id is not null
          and operation.action in ('provision','reconcile','lifecycle','resume','restrict')
          and operation.state='in_progress'
        group by operation.workshop_id
        having count(*) > 1
    ) then
        raise exception 'multiple legacy route outcomes for one workshop require reconciliation before migration';
    end if;

    update control.deployment_driver_operations operation
    set safe_error='runtime_outcome_unknown',execution_token=null,
        lease_expires_at=null,updated_at=now()
    where operation.workshop_id is not null
      and operation.action in ('provision','reconcile','lifecycle','resume','restrict')
      and operation.state='in_progress';

    update control.workshop_route_application_leases lease
    set state='quarantined',initialization_required=true,fence_token=1,
        driver_operation_id=operation.id,
        lease_owner='00000000-0000-0000-0000-000000000000'::uuid,
        heartbeat_at=now(),quarantined_at=now(),
        safe_error='legacy_route_outcome_unknown',updated_at=now()
    from control.deployment_driver_operations operation
    where operation.workshop_id=lease.workshop_id
      and operation.action in ('provision','reconcile','lifecycle','resume','restrict')
      and operation.state='in_progress';
end
$migration$;

create or replace function control.lock_workshop_route_projection(
    p_control_operation_id uuid,
    p_control_operation_attempt integer,
    p_control_operation_lease_owner text,
    p_workshop_id uuid
) returns bigint
language plpgsql security definer
set search_path = pg_catalog, control
as $function$
declare v_generation bigint;
begin
    perform 1 from control.operations operation
    where operation.id=p_control_operation_id
      and operation.workshop_id=p_workshop_id
      and (
          (operation.kind='tenant.provision' and operation.queue='tenant-provisioning')
          or (operation.kind in (
                'tenant.reconcile','module.enable','module.restrict',
                'webshop-domain.reconcile'
              ) and operation.queue='tenant-reconciliation')
          or (operation.kind='tenant.lifecycle' and operation.queue='tenant-lifecycle')
      )
      and operation.state='in_flight'
      and operation.attempt=p_control_operation_attempt
      and operation.leased_by=p_control_operation_lease_owner
      and operation.lease_expires_at>now()
    for update;
    if not found then
        raise exception 'upstream operation lease was lost' using errcode='55000';
    end if;

    insert into control.workshop_route_projection_state(workshop_id)
    values(p_workshop_id) on conflict(workshop_id) do nothing;
    select desired_generation into v_generation
    from control.workshop_route_projection_state
    where workshop_id=p_workshop_id
    for update;
    return coalesce(v_generation,0);
end
$function$;

create or replace function control.materialize_workshop_route_projection(
    p_control_operation_id uuid,
    p_control_operation_attempt integer,
    p_control_operation_lease_owner text,
    p_workshop_id uuid,
    p_projection jsonb,
    p_projection_digest text
) returns table(
    outcome text,
    generation bigint,
    projection_digest text,
    projection jsonb
)
language plpgsql security definer
set search_path = pg_catalog, control
as $function$
declare
    v_state control.workshop_route_projection_state%rowtype;
    v_custom jsonb;
    v_previous_hostname text;
    v_canonical_count integer := 0;
    v_key_count integer;
    v_generation bigint;
    v_canonical jsonb;
begin
    perform 1 from control.operations operation
    where operation.id=p_control_operation_id
      and operation.workshop_id=p_workshop_id
      and (
          (operation.kind='tenant.provision' and operation.queue='tenant-provisioning')
          or (operation.kind in (
                'tenant.reconcile','module.enable','module.restrict',
                'webshop-domain.reconcile'
              ) and operation.queue='tenant-reconciliation')
          or (operation.kind='tenant.lifecycle' and operation.queue='tenant-lifecycle')
      )
      and operation.state='in_flight'
      and operation.attempt=p_control_operation_attempt
      and operation.leased_by=p_control_operation_lease_owner
      and operation.lease_expires_at>now()
    for update;
    if not found then
        return query select 'upstream_lease_lost'::text,null::bigint,null::text,null::jsonb;
        return;
    end if;

    if p_projection_digest is null
       or p_projection_digest !~ '^sha256:[0-9a-f]{64}$'
       or p_projection is null or jsonb_typeof(p_projection) <> 'object' then
        return query select 'invalid'::text,null::bigint,null::text,null::jsonb;
        return;
    end if;
    select count(*) into v_key_count from jsonb_object_keys(p_projection);
    if v_key_count <> 6
       or not (p_projection ?& array[
           'database_id','database_ref','public_hostname','paperless_mode',
           'paperless_hostname','custom_hostnames'
       ])
       or jsonb_typeof(p_projection->'database_id') <> 'string'
       or jsonb_typeof(p_projection->'database_ref') <> 'string'
       or jsonb_typeof(p_projection->'public_hostname') <> 'string'
       or jsonb_typeof(p_projection->'paperless_mode') <> 'string'
       or jsonb_typeof(p_projection->'custom_hostnames') <> 'array'
       or (p_projection->>'database_id') !~
           '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
       or (p_projection->>'database_ref') !~ '^mb_[0-9a-f]{32}$'
       or (p_projection->>'public_hostname') !~
           '^[a-z0-9][a-z0-9.-]{1,251}[a-z0-9]$'
       or (p_projection->>'public_hostname') ~ '\.\.'
       or (p_projection->>'paperless_mode') not in ('absent','read_write','read_only')
       or jsonb_array_length(p_projection->'custom_hostnames') > 64
       or ((p_projection->>'paperless_mode')='absent'
           and jsonb_typeof(p_projection->'paperless_hostname') <> 'null')
       or ((p_projection->>'paperless_mode')<>'absent' and (
           jsonb_typeof(p_projection->'paperless_hostname') <> 'string'
           or (p_projection->>'paperless_hostname') !~
               '^[a-z0-9][a-z0-9.-]{1,251}[a-z0-9]$'
           or (p_projection->>'paperless_hostname') ~ '\.\.'
       )) then
        return query select 'invalid'::text,null::bigint,null::text,null::jsonb;
        return;
    end if;

    for v_custom in select value from jsonb_array_elements(p_projection->'custom_hostnames')
    loop
        if jsonb_typeof(v_custom) <> 'object' then
            return query select 'invalid'::text,null::bigint,null::text,null::jsonb;
            return;
        end if;
        select count(*) into v_key_count from jsonb_object_keys(v_custom);
        if v_key_count <> 2
           or not (v_custom ?& array['hostname','canonical'])
           or jsonb_typeof(v_custom->'hostname') <> 'string'
           or jsonb_typeof(v_custom->'canonical') <> 'boolean'
           or (v_custom->>'hostname') !~ '^[a-z0-9][a-z0-9.-]{1,251}[a-z0-9]$'
           or (v_custom->>'hostname') ~ '\.\.'
           or (v_previous_hostname is not null
               and (v_custom->>'hostname') <= v_previous_hostname) then
            return query select 'invalid'::text,null::bigint,null::text,null::jsonb;
            return;
        end if;
        if (v_custom->>'canonical')::boolean then
            v_canonical_count := v_canonical_count + 1;
            if v_canonical_count > 1 then
                return query select 'invalid'::text,null::bigint,null::text,null::jsonb;
                return;
            end if;
        end if;
        v_previous_hostname := v_custom->>'hostname';
    end loop;

    v_canonical := jsonb_build_object(
        'database_id',p_projection->'database_id',
        'database_ref',p_projection->'database_ref',
        'public_hostname',p_projection->'public_hostname',
        'paperless_mode',p_projection->'paperless_mode',
        'paperless_hostname',p_projection->'paperless_hostname',
        'custom_hostnames',p_projection->'custom_hostnames'
    );

    insert into control.workshop_route_projection_state(workshop_id)
    values(p_workshop_id) on conflict(workshop_id) do nothing;
    select * into strict v_state
    from control.workshop_route_projection_state state
    where state.workshop_id=p_workshop_id
    for update;
    if v_state.desired_digest=p_projection_digest
       and exists(
           select 1 from control.workshop_route_projections stored
           where stored.workshop_id=p_workshop_id
             and stored.generation=v_state.desired_generation
             and stored.projection_digest=p_projection_digest
             and stored.projection=v_canonical
       ) then
        return query select 'reused'::text,v_state.desired_generation,
            p_projection_digest,v_canonical;
        return;
    end if;
    if v_state.desired_digest=p_projection_digest then
        return query select 'invalid'::text,null::bigint,null::text,null::jsonb;
        return;
    end if;

    v_generation := coalesce(v_state.desired_generation,0)+1;
    insert into control.workshop_route_projections(
        workshop_id,generation,projection_digest,projection,
        source_operation_id,source_operation_attempt
    ) values (
        p_workshop_id,v_generation,p_projection_digest,v_canonical,
        p_control_operation_id,p_control_operation_attempt
    );
    update control.workshop_route_projection_state state
    set desired_generation=v_generation,desired_digest=p_projection_digest,updated_at=now()
    where state.workshop_id=p_workshop_id;
    return query select 'created'::text,v_generation,p_projection_digest,v_canonical;
end
$function$;

create or replace function control.admit_workshop_route_application(
    p_control_operation_id uuid,
    p_control_operation_attempt integer,
    p_control_operation_lease_owner text,
    p_workshop_id uuid,
    p_action text,
    p_idempotency_key text,
    p_request_digest text,
    p_generation bigint,
    p_projection_digest text,
    p_instance_owner uuid,
    p_execution_token uuid,
    p_route_lease_token uuid,
    p_ttl_seconds integer
) returns table(
    outcome text,
    driver_operation_id uuid,
    fence_token bigint,
    stored_response jsonb
)
language plpgsql security definer
set search_path = pg_catalog, control
as $function$
declare
    v_global control.deployment_driver_resource_leases%rowtype;
    v_state control.workshop_route_projection_state%rowtype;
    v_lease control.workshop_route_application_leases%rowtype;
    v_operation control.deployment_driver_operations%rowtype;
    v_operation_id uuid;
    v_fence bigint;
    v_exact_key boolean;
begin
    if p_action is distinct from 'route-project'
       or p_ttl_seconds < 60 or p_ttl_seconds > 1200
       or p_control_operation_attempt <= 0
       or p_control_operation_lease_owner is null
       or btrim(p_control_operation_lease_owner)=''
       or p_idempotency_key is null
       or length(p_idempotency_key) < 1 or length(p_idempotency_key) > 180
       or p_request_digest is null
       or p_request_digest !~ '^[0-9a-f]{64}$'
       or p_projection_digest is null
       or p_projection_digest !~ '^sha256:[0-9a-f]{64}$'
       or p_generation <= 0 then
        return query select 'invalid'::text,null::uuid,null::bigint,null::jsonb;
        return;
    end if;
    perform 1 from control.operations operation
    where operation.id=p_control_operation_id
      and operation.workshop_id=p_workshop_id
      and (
          (operation.kind='tenant.provision' and operation.queue='tenant-provisioning')
          or (operation.kind in (
                'tenant.reconcile','module.enable','module.restrict',
                'webshop-domain.reconcile'
              ) and operation.queue='tenant-reconciliation')
          or (operation.kind='tenant.lifecycle' and operation.queue='tenant-lifecycle')
      )
      and operation.state='in_flight'
      and operation.attempt=p_control_operation_attempt
      and operation.leased_by=p_control_operation_lease_owner
      and operation.lease_expires_at>now()
    for update;
    if not found then
        return query select 'upstream_lease_lost'::text,null::uuid,null::bigint,null::jsonb;
        return;
    end if;

    select * into strict v_global
    from control.deployment_driver_resource_leases resource
    where resource.resource_key='runtime/shared-odoo' for update;
    if v_global.state='held' then
        return query select 'fleet_busy'::text,v_global.driver_operation_id,
            v_global.fence_token,null::jsonb;
        return;
    elsif v_global.state='quarantined' then
        return query select 'fleet_quarantined'::text,v_global.driver_operation_id,
            v_global.fence_token,null::jsonb;
        return;
    end if;

    select * into strict v_state
    from control.workshop_route_projection_state state
    where state.workshop_id=p_workshop_id for update;
    select * into strict v_lease
    from control.workshop_route_application_leases lease
    where lease.workshop_id=p_workshop_id for update;

    if v_lease.state='held' and v_lease.lease_expires_at<=now() then
        update control.deployment_driver_operations operation
        set safe_error='runtime_outcome_unknown',execution_token=null,
            lease_expires_at=null,updated_at=now()
        where operation.id=v_lease.driver_operation_id
          and operation.state='in_progress';
        update control.workshop_route_application_leases lease
        set state='quarantined',lease_token=null,lease_expires_at=null,
            quarantined_at=now(),safe_error='runtime_outcome_unknown',updated_at=now()
        where lease.workshop_id=p_workshop_id;
        return query select 'quarantined'::text,v_lease.driver_operation_id,
            v_lease.fence_token,null::jsonb;
        return;
    end if;
    if v_lease.state='quarantined' then
        return query select 'quarantined'::text,v_lease.driver_operation_id,
            v_lease.fence_token,null::jsonb;
        return;
    end if;

    select operation.* into v_operation
    from control.deployment_driver_operations operation
    where operation.workshop_id=p_workshop_id
      and (
          (operation.action=p_action and operation.idempotency_key=p_idempotency_key)
          or (operation.route_generation=p_generation
              and operation.route_projection_digest=p_projection_digest)
      )
    order by (operation.action=p_action
              and operation.idempotency_key=p_idempotency_key) desc
    limit 1
    for update;
    if found then
        v_exact_key := v_operation.action=p_action
            and v_operation.idempotency_key=p_idempotency_key;
        if v_operation.request_digest<>p_request_digest
           or (v_operation.route_generation is not null and (
               v_operation.route_generation<>p_generation
               or v_operation.route_projection_digest<>p_projection_digest
           ))
           or (v_exact_key
               and v_operation.control_operation_id is distinct from p_control_operation_id) then
            return query select 'digest_conflict'::text,v_operation.id,
                v_lease.fence_token,null::jsonb;
        elsif v_operation.route_generation is null then
            return query select 'legacy_receipt'::text,v_operation.id,
                v_lease.fence_token,null::jsonb;
        elsif v_operation.state='succeeded' then
            if v_exact_key then
                update control.deployment_driver_operations operation
                set control_operation_attempt=p_control_operation_attempt,
                    control_operation_lease_owner=p_control_operation_lease_owner,
                    updated_at=now()
                where operation.id=v_operation.id and operation.state='succeeded';
            end if;
            return query select 'replay'::text,v_operation.id,
                v_operation.route_fence_token,v_operation.response;
        elsif v_operation.state='failed' then
            return query select 'failed'::text,v_operation.id,
                v_operation.route_fence_token,null::jsonb;
        elsif v_operation.safe_error='runtime_outcome_unknown' then
            return query select 'quarantined'::text,v_operation.id,
                v_operation.route_fence_token,null::jsonb;
        else
            return query select 'busy'::text,v_operation.id,
                v_operation.route_fence_token,null::jsonb;
        end if;
        return;
    end if;

    if v_state.desired_generation is null then
        return query select 'uninitialized'::text,null::uuid,v_lease.fence_token,null::jsonb;
        return;
    elsif p_generation<v_state.desired_generation then
        return query select 'superseded'::text,null::uuid,v_lease.fence_token,
            jsonb_strip_nulls(jsonb_build_object(
                'superseded',true,
                'desired_generation',v_state.desired_generation,
                'desired_digest',v_state.desired_digest,
                'route_evidence',case when v_state.applied_generation is null then null
                    else jsonb_build_object(
                        'driver_operation_id',v_state.applied_driver_operation_id,
                        'workshop_id',p_workshop_id,
                        'route_generation',v_state.applied_generation,
                        'projection_digest',v_state.applied_digest,
                        'rendered_digest',v_state.applied_rendered_digest,
                        'route_fence_token',v_state.applied_fence_token
                    ) end
            ));
        return;
    elsif p_generation<>v_state.desired_generation
       or p_projection_digest<>v_state.desired_digest then
        return query select 'unreserved'::text,null::uuid,v_lease.fence_token,null::jsonb;
        return;
    end if;
    if v_lease.state='held' then
        return query select 'busy'::text,v_lease.driver_operation_id,
            v_lease.fence_token,null::jsonb;
        return;
    end if;

    v_fence := v_lease.fence_token+1;
    insert into control.deployment_driver_operations(
        idempotency_key,workshop_id,action,request_digest,
        control_operation_id,control_operation_attempt,control_operation_lease_owner,
        target_key,execution_token,lease_expires_at,execution_attempt,
        route_generation,route_projection_digest,route_fence_token
    ) values (
        p_idempotency_key,p_workshop_id,p_action,p_request_digest,
        p_control_operation_id,p_control_operation_attempt,p_control_operation_lease_owner,
        'route/'||p_workshop_id::text,p_execution_token,
        now()+make_interval(secs=>p_ttl_seconds),1,
        p_generation,p_projection_digest,v_fence
    ) returning id into v_operation_id;
    update control.workshop_route_application_leases lease
    set state='held',fence_token=v_fence,driver_operation_id=v_operation_id,
        generation=p_generation,projection_digest=p_projection_digest,
        lease_owner=p_instance_owner,lease_token=p_route_lease_token,
        lease_expires_at=now()+make_interval(secs=>p_ttl_seconds),heartbeat_at=now(),
        quarantined_at=null,safe_error=null,updated_at=now()
    where lease.workshop_id=p_workshop_id;
    return query select 'acquired'::text,v_operation_id,v_fence,null::jsonb;
end
$function$;

create or replace function control.renew_workshop_route_application(
    p_driver_operation_id uuid,
    p_control_operation_id uuid,
    p_control_operation_attempt integer,
    p_control_operation_lease_owner text,
    p_instance_owner uuid,
    p_execution_token uuid,
    p_route_lease_token uuid,
    p_fence_token bigint,
    p_ttl_seconds integer
) returns boolean
language plpgsql security definer
set search_path = pg_catalog, control
as $function$
declare
    v_workshop uuid;
    v_changed bigint;
begin
    if p_ttl_seconds<60 or p_ttl_seconds>1200 then return false; end if;
    select operation.workshop_id into v_workshop
    from control.operations operation
    where operation.id=p_control_operation_id and operation.state='in_flight'
      and operation.attempt=p_control_operation_attempt
      and operation.leased_by=p_control_operation_lease_owner
      and operation.lease_expires_at>now()
      and (
          (operation.kind='tenant.provision' and operation.queue='tenant-provisioning')
          or (operation.kind in (
                  'tenant.reconcile','module.enable','module.restrict',
                  'webshop-domain.reconcile'
              ) and operation.queue='tenant-reconciliation')
          or (operation.kind='tenant.lifecycle' and operation.queue='tenant-lifecycle')
      )
    for update;
    if not found or v_workshop is null then return false; end if;

    perform 1 from control.deployment_driver_resource_leases resource
    where resource.resource_key='runtime/shared-odoo' and resource.state='idle'
    for update;
    if not found then return false; end if;

    update control.workshop_route_application_leases lease
    set lease_expires_at=now()+make_interval(secs=>p_ttl_seconds),
        heartbeat_at=now(),updated_at=now()
    where lease.workshop_id=v_workshop and lease.state='held'
      and lease.driver_operation_id=p_driver_operation_id
      and lease.lease_owner=p_instance_owner
      and lease.lease_token=p_route_lease_token
      and lease.fence_token=p_fence_token and lease.lease_expires_at>now();
    get diagnostics v_changed=row_count;
    if v_changed<>1 then return false; end if;

    update control.deployment_driver_operations operation
    set lease_expires_at=now()+make_interval(secs=>p_ttl_seconds),updated_at=now()
    where operation.id=p_driver_operation_id and operation.workshop_id=v_workshop
      and operation.state='in_progress'
      and operation.control_operation_id=p_control_operation_id
      and operation.control_operation_attempt=p_control_operation_attempt
      and operation.control_operation_lease_owner=p_control_operation_lease_owner
      and operation.execution_token=p_execution_token
      and operation.route_fence_token=p_fence_token
      and operation.lease_expires_at>now();
    get diagnostics v_changed=row_count;
    if v_changed<>1 then
        raise exception 'workshop route driver operation lease was lost'
            using errcode='40001';
    end if;
    return true;
end
$function$;

create or replace function control.finish_workshop_route_application(
    p_driver_operation_id uuid,
    p_instance_owner uuid,
    p_execution_token uuid,
    p_route_lease_token uuid,
    p_fence_token bigint,
    p_outcome text,
    p_response jsonb,
    p_rendered_digest text,
    p_safe_error text
) returns boolean
language plpgsql security definer
set search_path = pg_catalog, control
as $function$
declare
    v_lease control.workshop_route_application_leases%rowtype;
    v_changed bigint;
    v_evidence_key_count integer;
begin
    if p_outcome not in ('succeeded','failed','unknown') then return false; end if;
    select * into v_lease
    from control.workshop_route_application_leases lease
    where lease.driver_operation_id=p_driver_operation_id
    for update;
    if not found or v_lease.state<>'held'
       or v_lease.lease_owner<>p_instance_owner
       or v_lease.lease_token<>p_route_lease_token
       or v_lease.fence_token<>p_fence_token
       or (p_outcome<>'unknown' and v_lease.lease_expires_at<=now()) then
        return false;
    end if;
    if p_outcome='succeeded' then
        if p_safe_error is not null
           or p_response is null or jsonb_typeof(p_response)<>'object'
           or jsonb_typeof(p_response->'route_evidence')<>'object' then
            return false;
        end if;
        select count(*) into v_evidence_key_count
        from jsonb_object_keys(p_response->'route_evidence');
        if v_evidence_key_count<>6
           or p_rendered_digest is null
           or p_rendered_digest !~ '^sha256:[0-9a-f]{64}$'
           or (p_response->'route_evidence'->>'driver_operation_id')
                is distinct from p_driver_operation_id::text
           or (p_response->'route_evidence'->>'workshop_id')
                is distinct from v_lease.workshop_id::text
           or (p_response->'route_evidence'->>'route_generation')
                is distinct from v_lease.generation::text
           or (p_response->'route_evidence'->>'projection_digest')
                is distinct from v_lease.projection_digest
           or (p_response->'route_evidence'->>'rendered_digest')
                is distinct from p_rendered_digest
           or (p_response->'route_evidence'->>'route_fence_token')
                is distinct from p_fence_token::text then
            return false;
        end if;
    end if;
    if p_outcome='failed' then
        if p_response is not null or p_rendered_digest is not null
           or p_safe_error is null or btrim(p_safe_error)='' then
            return false;
        end if;
    elsif p_outcome='unknown' then
        if p_response is not null or p_rendered_digest is not null
           or p_safe_error is not null then
            return false;
        end if;
    end if;

    update control.deployment_driver_operations operation
    set state=case when p_outcome='unknown' then 'in_progress' else p_outcome end,
        response=case when p_outcome='succeeded' then p_response else null end,
        safe_error=case when p_outcome='unknown' then 'runtime_outcome_unknown'
                        else p_safe_error end,
        execution_token=null,lease_expires_at=null,updated_at=now()
    where operation.id=p_driver_operation_id and operation.state='in_progress'
      and operation.execution_token=p_execution_token
      and operation.route_generation=v_lease.generation
      and operation.route_projection_digest=v_lease.projection_digest
      and operation.route_fence_token=p_fence_token
      and (p_outcome='unknown' or operation.lease_expires_at>now());
    get diagnostics v_changed=row_count;
    if v_changed<>1 then return false; end if;

    if p_outcome='succeeded' then
        update control.workshop_route_projection_state state
        set applied_generation=v_lease.generation,
            applied_digest=v_lease.projection_digest,
            applied_rendered_digest=p_rendered_digest,
            applied_driver_operation_id=p_driver_operation_id,
            applied_fence_token=p_fence_token,updated_at=now()
        where state.workshop_id=v_lease.workshop_id;
        update control.workshop_route_application_leases lease
        set state='idle',initialization_required=false,driver_operation_id=null,
            generation=null,projection_digest=null,lease_owner=null,lease_token=null,
            lease_expires_at=null,heartbeat_at=null,quarantined_at=null,
            safe_error=null,updated_at=now()
        where lease.workshop_id=v_lease.workshop_id;
    elsif p_outcome='failed' then
        update control.workshop_route_application_leases lease
        set state=case when initialization_required then 'uninitialized' else 'idle' end,
            driver_operation_id=null,generation=null,projection_digest=null,
            lease_owner=null,lease_token=null,lease_expires_at=null,
            heartbeat_at=null,quarantined_at=null,safe_error=null,updated_at=now()
        where lease.workshop_id=v_lease.workshop_id;
    else
        update control.workshop_route_application_leases lease
        set state='quarantined',lease_token=null,lease_expires_at=null,
            quarantined_at=now(),safe_error='runtime_outcome_unknown',updated_at=now()
        where lease.workshop_id=v_lease.workshop_id;
    end if;
    get diagnostics v_changed=row_count;
    if v_changed<>1 then
        raise exception 'workshop route resource lease was lost' using errcode='40001';
    end if;
    return true;
end
$function$;

-- Replace the release admission surface with one that reserves the frozen
-- fleet against per-workshop route applications. The fleet membership is
-- derived from the authoritative run snapshot; callers cannot supply it.
drop function control.admit_release_driver_operation(
    uuid,integer,text,text,text,text,uuid,uuid,uuid,integer
);

create or replace function control.admit_release_driver_operation(
    p_control_operation_id uuid,
    p_control_operation_attempt integer,
    p_control_operation_lease_owner text,
    p_idempotency_key text,
    p_target_key text,
    p_fleet_run_id uuid,
    p_request_digest text,
    p_instance_owner uuid,
    p_execution_token uuid,
    p_resource_lease_token uuid,
    p_ttl_seconds integer
) returns table(
    outcome text,
    driver_operation_id uuid,
    fence_token bigint,
    stored_response jsonb,
    reserved_workshops uuid[]
)
language plpgsql security definer
set search_path = pg_catalog, control
as $function$
declare
    v_control_operation control.operations%rowtype;
    v_resource control.deployment_driver_resource_leases%rowtype;
    v_fleet_run control.release_fleet_runs%rowtype;
    v_operation control.deployment_driver_operations%rowtype;
    v_route control.workshop_route_application_leases%rowtype;
    v_operation_id uuid;
    v_fence bigint;
    v_snapshot_count integer;
    v_adoption_count integer;
    v_route_count integer;
    v_reserved uuid[] := array[]::uuid[];
begin
    if p_ttl_seconds < 60 or p_ttl_seconds > 1200
       or p_control_operation_attempt <= 0
       or p_control_operation_lease_owner is null
       or btrim(p_control_operation_lease_owner) = ''
       or p_idempotency_key is null
       or btrim(p_idempotency_key) = '' or length(p_idempotency_key) > 180
       or p_request_digest is null
       or p_request_digest !~ '^[0-9a-f]{64}$'
       or p_instance_owner is null or p_execution_token is null
       or p_resource_lease_token is null
       or (
           p_fleet_run_id is null
           and (p_target_key is null
                or p_target_key !~ '^initial/[A-Za-z0-9._:-]{1,200}$')
       )
       or (
           p_fleet_run_id is not null
           and p_target_key is distinct from 'fleet/' || p_fleet_run_id::text
       ) then
        return query select 'invalid'::text,null::uuid,null::bigint,null::jsonb,
            null::uuid[];
        return;
    end if;

    select operation.* into v_control_operation
    from control.operations operation
    where operation.id=p_control_operation_id
      and operation.kind='odoo.release.adopt'
      and operation.queue='release-adoption'
      and operation.workshop_id is null
      and operation.state='in_flight'
      and operation.attempt=p_control_operation_attempt
      and operation.leased_by=p_control_operation_lease_owner
      and operation.lease_expires_at>now()
    for update;
    if not found then
        return query select 'upstream_lease_lost'::text,null::uuid,null::bigint,
            null::jsonb,null::uuid[];
        return;
    end if;

    select * into strict v_resource
    from control.deployment_driver_resource_leases resource
    where resource.resource_key='runtime/shared-odoo'
    for update;

    if p_fleet_run_id is null then
        if v_control_operation.payload->>'phase' is distinct from 'preflight'
           or v_control_operation.payload->>'release_id' is null
           or p_target_key is distinct from
                'initial/' || (v_control_operation.payload->>'release_id') then
            return query select 'invalid'::text,null::uuid,v_resource.fence_token,
                null::jsonb,null::uuid[];
            return;
        end if;
    else
        select run.* into v_fleet_run
        from control.release_fleet_runs run
        where run.id=p_fleet_run_id
          and run.operation_id=p_control_operation_id
        for share;
        if not found
           or v_control_operation.payload->>'phase' is distinct from 'adopt'
           or v_control_operation.payload->>'release_id'
                is distinct from v_fleet_run.release_id
           or v_fleet_run.state not in ('preparing','activating')
           or jsonb_typeof(v_fleet_run.tenant_snapshot)<>'array'
           or jsonb_array_length(v_fleet_run.tenant_snapshot)<1
           or jsonb_array_length(v_fleet_run.tenant_snapshot)>500 then
            return query select 'invalid_fleet'::text,null::uuid,
                v_resource.fence_token,null::jsonb,null::uuid[];
            return;
        end if;

        select count(*) into v_snapshot_count
        from jsonb_array_elements(v_fleet_run.tenant_snapshot) snapshot(item)
        where jsonb_typeof(snapshot.item)='object'
          and case when jsonb_typeof(snapshot.item)='object'
              then (select count(*) from jsonb_object_keys(snapshot.item))=4
              else false end
          and snapshot.item ?& array[
              'workshop_id','database_id','database_ref','paperless_enabled'
          ]
          and jsonb_typeof(snapshot.item->'workshop_id')='string'
          and jsonb_typeof(snapshot.item->'database_id')='string'
          and jsonb_typeof(snapshot.item->'database_ref')='string'
          and jsonb_typeof(snapshot.item->'paperless_enabled')='boolean'
          and (snapshot.item->>'workshop_id') ~
              '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
          and (snapshot.item->>'database_id') ~
              '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
          and (snapshot.item->>'database_ref') ~ '^mb_[0-9a-f]{32}$';
        if v_snapshot_count<>jsonb_array_length(v_fleet_run.tenant_snapshot) then
            return query select 'invalid_fleet'::text,null::uuid,
                v_resource.fence_token,null::jsonb,null::uuid[];
            return;
        end if;

        select count(*),count(distinct (snapshot.item->>'workshop_id')::uuid)
        into v_snapshot_count,v_adoption_count
        from jsonb_array_elements(v_fleet_run.tenant_snapshot) snapshot(item);
        if v_snapshot_count<>v_adoption_count then
            return query select 'invalid_fleet'::text,null::uuid,
                v_resource.fence_token,null::jsonb,null::uuid[];
            return;
        end if;

        select count(*) into v_adoption_count
        from control.tenant_release_adoptions adoption
        where adoption.operation_id=p_control_operation_id
          and adoption.release_id=v_fleet_run.release_id;
        if v_adoption_count<>v_snapshot_count
           or exists (
               select 1
               from jsonb_array_elements(v_fleet_run.tenant_snapshot) snapshot(item)
               where not exists (
                   select 1 from control.tenant_release_adoptions adoption
                   where adoption.operation_id=p_control_operation_id
                     and adoption.release_id=v_fleet_run.release_id
                     and adoption.workshop_id=(snapshot.item->>'workshop_id')::uuid
                     and adoption.database_id=(snapshot.item->>'database_id')::uuid
               )
           )
           or exists (
               select 1
               from control.tenant_release_adoptions adoption
               where adoption.operation_id=p_control_operation_id
                 and adoption.release_id=v_fleet_run.release_id
                 and not exists (
                     select 1
                     from jsonb_array_elements(v_fleet_run.tenant_snapshot) snapshot(item)
                     where (snapshot.item->>'workshop_id')::uuid=adoption.workshop_id
                       and (snapshot.item->>'database_id')::uuid=adoption.database_id
                 )
           ) then
            return query select 'invalid_fleet'::text,null::uuid,
                v_resource.fence_token,null::jsonb,null::uuid[];
            return;
        end if;

        select array_agg((snapshot.item->>'workshop_id')::uuid
                         order by (snapshot.item->>'workshop_id')::uuid)
        into v_reserved
        from jsonb_array_elements(v_fleet_run.tenant_snapshot) snapshot(item);
    end if;

    -- This union is deliberate: snapshot rows freeze the intended fleet, and
    -- every current non-idle row catches work admitted immediately before the
    -- global lock. UUID order is the common route-row lock order.
    perform 1
    from control.workshop_route_application_leases route
    where route.workshop_id=any(v_reserved) or route.state<>'idle'
    order by route.workshop_id
    for update;

    if v_resource.state='held' and v_resource.lease_expires_at<=now() then
        update control.deployment_driver_operations operation
        set safe_error='runtime_outcome_unknown',execution_token=null,
            lease_expires_at=null,updated_at=now()
        where operation.id=v_resource.driver_operation_id
          and operation.state='in_progress';
        update control.deployment_driver_resource_leases resource
        set state='quarantined',lease_token=null,lease_expires_at=null,
            quarantined_at=now(),safe_error='runtime_outcome_unknown',updated_at=now()
        where resource.resource_key='runtime/shared-odoo';
        return query select 'quarantined'::text,v_resource.driver_operation_id,
            v_resource.fence_token,null::jsonb,v_reserved;
        return;
    elsif v_resource.state='quarantined' then
        return query select 'quarantined'::text,v_resource.driver_operation_id,
            v_resource.fence_token,null::jsonb,v_reserved;
        return;
    end if;

    select operation.* into v_operation
    from control.deployment_driver_operations operation
    where operation.workshop_id is null and operation.action='release'
      and (operation.idempotency_key=p_idempotency_key
           or operation.target_key=p_target_key)
    order by (operation.idempotency_key=p_idempotency_key) desc
    limit 1 for update;
    if found then
        if v_operation.request_digest<>p_request_digest
           or v_operation.target_key is distinct from p_target_key
           or v_operation.control_operation_id is distinct from
                p_control_operation_id then
            return query select 'digest_conflict'::text,v_operation.id,
                v_resource.fence_token,null::jsonb,v_reserved;
        elsif v_operation.state='succeeded' then
            update control.deployment_driver_operations operation
            set control_operation_attempt=p_control_operation_attempt,
                control_operation_lease_owner=p_control_operation_lease_owner,
                updated_at=now()
            where operation.id=v_operation.id and operation.state='succeeded';
            return query select 'replay'::text,v_operation.id,
                v_resource.fence_token,v_operation.response,v_reserved;
        elsif v_operation.state='failed' then
            return query select 'failed'::text,v_operation.id,
                v_resource.fence_token,null::jsonb,v_reserved;
        elsif v_operation.safe_error='runtime_outcome_unknown' then
            return query select 'quarantined'::text,v_operation.id,
                v_resource.fence_token,null::jsonb,v_reserved;
        else
            return query select 'busy'::text,v_operation.id,
                v_resource.fence_token,null::jsonb,v_reserved;
        end if;
        return;
    end if;
    if v_resource.state='held' then
        return query select 'busy'::text,v_resource.driver_operation_id,
            v_resource.fence_token,null::jsonb,v_reserved;
        return;
    end if;

    -- Expired route ownership has an unknowable host outcome and is never
    -- stolen. Quarantine every such row before refusing the release.
    update control.deployment_driver_operations operation
    set safe_error='runtime_outcome_unknown',execution_token=null,
        lease_expires_at=null,updated_at=now()
    where operation.id in (
        select route.driver_operation_id
        from control.workshop_route_application_leases route
        where route.state='held' and route.lease_expires_at<=now()
    ) and operation.state='in_progress';
    update control.workshop_route_application_leases route
    set state='quarantined',lease_token=null,lease_expires_at=null,
        quarantined_at=now(),safe_error='runtime_outcome_unknown',updated_at=now()
    where route.state='held' and route.lease_expires_at<=now();

    select route.* into v_route
    from control.workshop_route_application_leases route
    where route.state<>'idle'
    order by route.workshop_id
    limit 1;
    if found then
        return query select case v_route.state
                when 'held' then 'route_busy'
                when 'quarantined' then 'route_quarantined'
                else 'route_uninitialized' end,
            v_route.driver_operation_id,v_resource.fence_token,null::jsonb,v_reserved;
        return;
    end if;

    if p_fleet_run_id is null then
        select count(*) into v_route_count
        from control.workshop_route_application_leases;
        if v_route_count<>0 then
            return query select 'fleet_not_empty'::text,null::uuid,
                v_resource.fence_token,null::jsonb,array[]::uuid[];
            return;
        end if;
    else
        select count(*) into v_route_count
        from control.workshop_route_application_leases route
        where route.workshop_id=any(v_reserved);
        if v_route_count<>cardinality(v_reserved) then
            return query select 'route_uninitialized'::text,null::uuid,
                v_resource.fence_token,null::jsonb,v_reserved;
            return;
        end if;
    end if;

    insert into control.deployment_driver_operations(
        idempotency_key,workshop_id,action,request_digest,control_operation_id,
        control_operation_attempt,control_operation_lease_owner,target_key,
        execution_token,lease_expires_at,execution_attempt
    ) values (
        p_idempotency_key,null,'release',p_request_digest,p_control_operation_id,
        p_control_operation_attempt,p_control_operation_lease_owner,p_target_key,
        p_execution_token,now()+make_interval(secs=>p_ttl_seconds),1
    ) returning id into v_operation_id;
    v_fence:=v_resource.fence_token+1;
    update control.deployment_driver_resource_leases resource
    set state='held',fence_token=v_fence,driver_operation_id=v_operation_id,
        lease_owner=p_instance_owner,lease_token=p_resource_lease_token,
        lease_expires_at=now()+make_interval(secs=>p_ttl_seconds),
        heartbeat_at=now(),quarantined_at=null,safe_error=null,updated_at=now()
    where resource.resource_key='runtime/shared-odoo';
    return query select 'acquired'::text,v_operation_id,v_fence,null::jsonb,
        v_reserved;
end
$function$;

revoke all on function control.lock_workshop_route_projection(uuid,integer,text,uuid)
    from public;
revoke all on function control.seed_workshop_route_projection_state() from public;
revoke all on function control.reject_workshop_route_projection_mutation() from public;
revoke all on function control.materialize_workshop_route_projection(uuid,integer,text,uuid,jsonb,text)
    from public;
revoke all on function control.admit_workshop_route_application(uuid,integer,text,uuid,text,text,text,bigint,text,uuid,uuid,uuid,integer)
    from public;
revoke all on function control.renew_workshop_route_application(uuid,uuid,integer,text,uuid,uuid,uuid,bigint,integer)
    from public;
revoke all on function control.finish_workshop_route_application(uuid,uuid,uuid,uuid,bigint,text,jsonb,text,text)
    from public;
revoke all on function control.admit_release_driver_operation(uuid,integer,text,text,text,uuid,text,uuid,uuid,uuid,integer)
    from public;

do $migration$
declare v_role text;
begin
    foreach v_role in array array[
        'control_reconciliation_worker','control_provisioning_worker',
        'control_lifecycle_worker'
    ] loop
        if exists(select 1 from pg_roles where rolname=v_role) then
            execute format(
                'grant execute on function control.lock_workshop_route_projection(uuid,integer,text,uuid) to %I',
                v_role
            );
            execute format(
                'grant execute on function control.materialize_workshop_route_projection(uuid,integer,text,uuid,jsonb,text) to %I',
                v_role
            );
        end if;
    end loop;
    if exists(select 1 from pg_roles where rolname='control_driver_ledger') then
        revoke insert,update,delete on control.workshop_route_projections,
            control.workshop_route_projection_state,
            control.workshop_route_application_leases from control_driver_ledger;
        grant select on control.workshop_route_projections,
            control.workshop_route_projection_state,
            control.workshop_route_application_leases to control_driver_ledger;
        grant execute on function control.admit_workshop_route_application(uuid,integer,text,uuid,text,text,text,bigint,text,uuid,uuid,uuid,integer)
            to control_driver_ledger;
        grant execute on function control.renew_workshop_route_application(uuid,uuid,integer,text,uuid,uuid,uuid,bigint,integer)
            to control_driver_ledger;
        grant execute on function control.finish_workshop_route_application(uuid,uuid,uuid,uuid,bigint,text,jsonb,text,text)
            to control_driver_ledger;
        grant execute on function control.admit_release_driver_operation(uuid,integer,text,text,text,uuid,text,uuid,uuid,uuid,integer)
            to control_driver_ledger;
    end if;
end
$migration$;

comment on table control.workshop_route_projections is
'Append-only logical route projections; generation order is source-transaction order.';
comment on table control.workshop_route_projection_state is
'Current desired and last authoritatively applied workshop route generations.';
comment on table control.workshop_route_application_leases is
'Cross-replica workshop route executor lease; expiry and unknown host effects quarantine.';
