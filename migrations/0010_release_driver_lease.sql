-- Serialize shared-runtime release effects across driver replicas. Expiry is
-- deliberately quarantined rather than stolen: Docker, filesystem and
-- PostgreSQL effects cannot themselves reject a stale fencing token.

alter table control.deployment_driver_operations
    add column id uuid default gen_random_uuid() not null,
    add column control_operation_id uuid,
    add column control_operation_attempt integer,
    add column control_operation_lease_owner text,
    add column target_key text,
    add column execution_token uuid,
    add column lease_expires_at timestamptz,
    add column execution_attempt integer default 0 not null,
    add constraint deployment_driver_operations_id_key unique (id),
    add constraint deployment_driver_operations_control_operation_id_fkey
        foreign key (control_operation_id) references control.operations(id) on delete restrict,
    add constraint deployment_driver_operations_execution_attempt_check
        check (execution_attempt >= 0),
    add constraint deployment_driver_operations_execution_lease_check
        check ((execution_token is null) = (lease_expires_at is null));

-- Old unbound in-progress release calls cannot be proved safe after this
-- migration. Preserve their evidence but force reconciliation instead of
-- manufacturing an authority binding.
update control.deployment_driver_operations
set safe_error = 'runtime_outcome_unknown', updated_at = now()
where action = 'release' and state = 'in_progress' and safe_error is null;

-- Normal release keys have always carried the logical target. Recover that
-- identity before adding the target uniqueness fence. An unrecognizable
-- successful receipt must be reconciled before deployment: allowing it through
-- would permit the same external target to execute again under a new key.
update control.deployment_driver_operations
set target_key = case
        when idempotency_key ~ '^release-initial:[A-Za-z0-9._:-]{1,200}$'
            then 'initial/' || regexp_replace(idempotency_key, '^release-initial:', '')
        when idempotency_key ~ '^release-fleet:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
            then 'fleet/' || regexp_replace(idempotency_key, '^release-fleet:', '')
        else null
    end,
    updated_at = now()
where action = 'release' and target_key is null;

do $migration$
begin
    if exists (
        select 1 from control.deployment_driver_operations
        where action='release' and state='succeeded'
          and (control_operation_id is null
               or response->'evidence'->>'driver_operation_id' is null
               or response->'evidence'->>'driver_fence_token' is null)
    ) then
        raise exception 'unfenced successful historical release receipt requires reconciliation before migration';
    end if;
    if (
        select count(*) from control.deployment_driver_operations
        where action='release' and state='in_progress'
          and safe_error='runtime_outcome_unknown'
    ) > 1 then
        raise exception 'multiple historical release outcomes require reconciliation before migration';
    end if;
end
$migration$;

alter table control.deployment_driver_operations
    add constraint deployment_driver_operations_release_binding_check
    check (action <> 'release' or state <> 'in_progress' or safe_error is not null or (
        control_operation_id is not null
        and control_operation_attempt is not null and control_operation_attempt > 0
        and control_operation_lease_owner is not null
        and btrim(control_operation_lease_owner) <> ''
        and target_key is not null and target_key ~ '^(initial|fleet)/[A-Za-z0-9._:-]{1,200}$'
        and execution_token is not null and lease_expires_at is not null
        and execution_attempt > 0
    ));

create unique index deployment_driver_release_target
    on control.deployment_driver_operations(target_key)
    where action = 'release' and target_key is not null;

create table control.deployment_driver_resource_leases (
    resource_key text primary key,
    state text not null default 'idle',
    fence_token bigint not null default 0,
    driver_operation_id uuid,
    lease_owner uuid,
    lease_token uuid,
    lease_expires_at timestamptz,
    heartbeat_at timestamptz,
    quarantined_at timestamptz,
    safe_error text,
    updated_at timestamptz not null default now(),
    constraint deployment_driver_resource_leases_resource_key_check
        check (resource_key = 'runtime/shared-odoo'),
    constraint deployment_driver_resource_leases_state_check
        check (state in ('idle','held','quarantined')),
    constraint deployment_driver_resource_leases_fence_check check (fence_token >= 0),
    constraint deployment_driver_resource_leases_operation_fkey
        foreign key (driver_operation_id)
        references control.deployment_driver_operations(id) on delete restrict,
    constraint deployment_driver_resource_leases_shape_check check (
        (state = 'idle' and driver_operation_id is null and lease_owner is null
            and lease_token is null and lease_expires_at is null
            and heartbeat_at is null and quarantined_at is null and safe_error is null)
        or
        (state = 'held' and driver_operation_id is not null and lease_owner is not null
            and lease_token is not null and lease_expires_at is not null
            and heartbeat_at is not null and quarantined_at is null and safe_error is null
            and fence_token > 0)
        or
        (state = 'quarantined' and driver_operation_id is not null and lease_owner is not null
            and lease_token is null and lease_expires_at is null
            and heartbeat_at is not null and quarantined_at is not null
            and safe_error = 'runtime_outcome_unknown' and fence_token > 0)
    )
);

insert into control.deployment_driver_resource_leases(
    resource_key,state,fence_token,driver_operation_id,lease_owner,
    heartbeat_at,quarantined_at,safe_error
)
select 'runtime/shared-odoo','quarantined',1,operation.id,
       '00000000-0000-0000-0000-000000000000'::uuid,now(),now(),
       'runtime_outcome_unknown'
from control.deployment_driver_operations operation
where operation.action='release' and operation.state='in_progress'
  and operation.safe_error='runtime_outcome_unknown'
union all
select 'runtime/shared-odoo','idle',0,null,null,null,null,null
where not exists (
    select 1 from control.deployment_driver_operations operation
    where operation.action='release' and operation.state='in_progress'
      and operation.safe_error='runtime_outcome_unknown'
);

alter table control.release_fleet_runs
    add column driver_fence_token bigint,
    add constraint release_fleet_runs_driver_fence_check
        check (driver_fence_token is null or driver_fence_token > 0);

alter table control.fleet_activation_intents
    add column driver_fence_token bigint,
    add column abandoned_at timestamptz,
    add column abandonment_reason text,
    add constraint fleet_activation_intents_driver_fence_check
        check (driver_fence_token is null or driver_fence_token > 0),
    add constraint fleet_activation_intents_abandonment_check
        check ((abandoned_at is null) = (abandonment_reason is null));

create or replace function control.admit_release_driver_operation(
    p_control_operation_id uuid,
    p_control_operation_attempt integer,
    p_control_operation_lease_owner text,
    p_idempotency_key text,
    p_target_key text,
    p_request_digest text,
    p_instance_owner uuid,
    p_execution_token uuid,
    p_resource_lease_token uuid,
    p_ttl_seconds integer
) returns table(outcome text, driver_operation_id uuid, fence_token bigint, stored_response jsonb)
language plpgsql security definer
set search_path = pg_catalog, control
as $function$
declare
    v_resource control.deployment_driver_resource_leases%rowtype;
    v_operation control.deployment_driver_operations%rowtype;
    v_operation_id uuid;
    v_fence bigint;
begin
    if p_ttl_seconds < 60 or p_ttl_seconds > 1200
       or p_control_operation_attempt <= 0
       or btrim(p_control_operation_lease_owner) = ''
       or p_target_key !~ '^(initial|fleet)/[A-Za-z0-9._:-]{1,200}$'
       or p_request_digest !~ '^[0-9a-f]{64}$' then
        return query select 'invalid'::text, null::uuid, null::bigint, null::jsonb;
        return;
    end if;
    perform 1 from control.operations operation
        where operation.id = p_control_operation_id
          and operation.kind = 'odoo.release.adopt'
          and operation.queue = 'release-adoption'
          and operation.workshop_id is null
          and operation.state = 'in_flight'
          and operation.attempt = p_control_operation_attempt
          and operation.leased_by = p_control_operation_lease_owner
          and operation.lease_expires_at > now()
        for update;
    if not found then
        return query select 'upstream_lease_lost'::text, null::uuid, null::bigint, null::jsonb;
        return;
    end if;

    select * into strict v_resource
    from control.deployment_driver_resource_leases resource
    where resource.resource_key = 'runtime/shared-odoo'
    for update;

    if v_resource.state = 'held' and v_resource.lease_expires_at <= now() then
        update control.deployment_driver_operations operation
        set safe_error = 'runtime_outcome_unknown', execution_token = null,
            lease_expires_at = null, updated_at = now()
        where operation.id = v_resource.driver_operation_id
          and operation.state = 'in_progress';
        update control.deployment_driver_resource_leases resource
        set state = 'quarantined', lease_token = null, lease_expires_at = null,
            quarantined_at = now(), safe_error = 'runtime_outcome_unknown', updated_at = now()
        where resource.resource_key = 'runtime/shared-odoo';
        return query select 'quarantined'::text, v_resource.driver_operation_id,
            v_resource.fence_token, null::jsonb;
        return;
    end if;
    if v_resource.state = 'quarantined' then
        return query select 'quarantined'::text, v_resource.driver_operation_id,
            v_resource.fence_token, null::jsonb;
        return;
    end if;

    select operation.* into v_operation
    from control.deployment_driver_operations operation
    where operation.workshop_id is null and operation.action = 'release'
      and (operation.idempotency_key = p_idempotency_key
           or operation.target_key = p_target_key)
    order by (operation.idempotency_key = p_idempotency_key) desc
    limit 1 for update;
    if found then
        if v_operation.request_digest <> p_request_digest
           or v_operation.target_key is distinct from p_target_key then
            return query select 'digest_conflict'::text, v_operation.id,
                v_resource.fence_token, null::jsonb;
        elsif v_operation.control_operation_id <> p_control_operation_id then
            return query select 'digest_conflict'::text, v_operation.id,
                v_resource.fence_token, null::jsonb;
        elsif v_operation.state = 'succeeded' then
            update control.deployment_driver_operations operation
            set control_operation_attempt=p_control_operation_attempt,
                control_operation_lease_owner=p_control_operation_lease_owner,
                updated_at=now()
            where operation.id=v_operation.id and operation.state='succeeded';
            return query select 'replay'::text, v_operation.id,
                v_resource.fence_token, v_operation.response;
        elsif v_operation.state = 'failed' then
            return query select 'failed'::text, v_operation.id,
                v_resource.fence_token, null::jsonb;
        elsif v_operation.safe_error = 'runtime_outcome_unknown' then
            return query select 'quarantined'::text, v_operation.id,
                v_resource.fence_token, null::jsonb;
        else
            return query select 'busy'::text, v_operation.id,
                v_resource.fence_token, null::jsonb;
        end if;
        return;
    end if;
    if v_resource.state = 'held' then
        return query select 'busy'::text, v_resource.driver_operation_id,
            v_resource.fence_token, null::jsonb;
        return;
    end if;

    insert into control.deployment_driver_operations(
        idempotency_key,workshop_id,action,request_digest,control_operation_id,
        control_operation_attempt,control_operation_lease_owner,target_key,
        execution_token,lease_expires_at,execution_attempt
    ) values (
        p_idempotency_key,null,'release',p_request_digest,p_control_operation_id,
        p_control_operation_attempt,p_control_operation_lease_owner,p_target_key,
        p_execution_token,now()+make_interval(secs => p_ttl_seconds),1
    ) returning id into v_operation_id;
    v_fence := v_resource.fence_token + 1;
    update control.deployment_driver_resource_leases resource
    set state = 'held', fence_token = v_fence, driver_operation_id = v_operation_id,
        lease_owner = p_instance_owner, lease_token = p_resource_lease_token,
        lease_expires_at = now()+make_interval(secs => p_ttl_seconds),
        heartbeat_at = now(), quarantined_at = null, safe_error = null, updated_at = now()
    where resource.resource_key = 'runtime/shared-odoo';
    return query select 'acquired'::text, v_operation_id, v_fence, null::jsonb;
end
$function$;

create or replace function control.renew_release_driver_lease(
    p_driver_operation_id uuid,
    p_control_operation_id uuid,
    p_control_operation_attempt integer,
    p_control_operation_lease_owner text,
    p_instance_owner uuid,
    p_execution_token uuid,
    p_resource_lease_token uuid,
    p_fence_token bigint,
    p_ttl_seconds integer
) returns boolean
language plpgsql security definer
set search_path = pg_catalog, control
as $function$
declare v_changed bigint;
begin
    if p_ttl_seconds < 60 or p_ttl_seconds > 1200 then return false; end if;
    perform 1 from control.operations operation
        where operation.id=p_control_operation_id and operation.state='in_flight'
          and operation.attempt=p_control_operation_attempt
          and operation.leased_by=p_control_operation_lease_owner
          and operation.lease_expires_at>now()
        for update;
    if not found then return false; end if;
    update control.deployment_driver_resource_leases resource
    set lease_expires_at=now()+make_interval(secs => p_ttl_seconds),
        heartbeat_at=now(),updated_at=now()
    where resource.resource_key='runtime/shared-odoo' and resource.state='held'
      and resource.driver_operation_id=p_driver_operation_id
      and resource.lease_owner=p_instance_owner
      and resource.lease_token=p_resource_lease_token
      and resource.fence_token=p_fence_token and resource.lease_expires_at>now();
    get diagnostics v_changed = row_count;
    if v_changed <> 1 then return false; end if;
    update control.deployment_driver_operations operation
    set lease_expires_at=now()+make_interval(secs => p_ttl_seconds),updated_at=now()
    where operation.id=p_driver_operation_id and operation.state='in_progress'
      and operation.control_operation_id=p_control_operation_id
      and operation.control_operation_attempt=p_control_operation_attempt
      and operation.control_operation_lease_owner=p_control_operation_lease_owner
      and operation.execution_token=p_execution_token and operation.lease_expires_at>now();
    get diagnostics v_changed = row_count;
    if v_changed <> 1 then raise exception 'release driver operation lease was lost' using errcode='40001'; end if;
    return true;
end
$function$;

create or replace function control.finish_release_driver_operation(
    p_driver_operation_id uuid,
    p_instance_owner uuid,
    p_execution_token uuid,
    p_resource_lease_token uuid,
    p_fence_token bigint,
    p_outcome text,
    p_response jsonb,
    p_safe_error text
) returns boolean
language plpgsql security definer
set search_path = pg_catalog, control
as $function$
declare
    v_changed bigint;
    v_resource control.deployment_driver_resource_leases%rowtype;
begin
    if p_outcome not in ('succeeded','failed','unknown') then return false; end if;
    select * into strict v_resource
    from control.deployment_driver_resource_leases resource
    where resource.resource_key='runtime/shared-odoo' for update;
    if v_resource.state <> 'held'
       or v_resource.driver_operation_id <> p_driver_operation_id
       or v_resource.lease_owner <> p_instance_owner
       or v_resource.lease_token <> p_resource_lease_token
       or v_resource.fence_token <> p_fence_token
       or (p_outcome <> 'unknown' and v_resource.lease_expires_at <= now()) then
        return false;
    end if;
    update control.deployment_driver_operations operation
    set state=case when p_outcome='unknown' then 'in_progress' else p_outcome end,
        response=case when p_outcome='succeeded' then p_response else null end,
        safe_error=case when p_outcome='unknown' then 'runtime_outcome_unknown' else p_safe_error end,
        execution_token=null,lease_expires_at=null,updated_at=now()
    where operation.id=p_driver_operation_id and operation.state='in_progress'
      and operation.execution_token=p_execution_token
      and (p_outcome='unknown' or operation.lease_expires_at>now());
    get diagnostics v_changed = row_count;
    if v_changed <> 1 then return false; end if;
    if p_outcome='unknown' then
        update control.deployment_driver_resource_leases resource
        set state='quarantined',lease_token=null,lease_expires_at=null,
            quarantined_at=now(),safe_error='runtime_outcome_unknown',updated_at=now()
        where resource.resource_key='runtime/shared-odoo' and resource.state='held'
          and resource.driver_operation_id=p_driver_operation_id
          and resource.lease_owner=p_instance_owner
          and resource.lease_token=p_resource_lease_token
          and resource.fence_token=p_fence_token;
    else
        update control.deployment_driver_resource_leases resource
        set state='idle',driver_operation_id=null,lease_owner=null,lease_token=null,
            lease_expires_at=null,heartbeat_at=null,quarantined_at=null,
            safe_error=null,updated_at=now()
        where resource.resource_key='runtime/shared-odoo' and resource.state='held'
          and resource.driver_operation_id=p_driver_operation_id
          and resource.lease_owner=p_instance_owner
          and resource.lease_token=p_resource_lease_token
          and resource.fence_token=p_fence_token;
    end if;
    get diagnostics v_changed = row_count;
    if v_changed <> 1 then raise exception 'release driver resource lease was lost' using errcode='40001'; end if;
    return true;
end
$function$;

revoke all on function control.admit_release_driver_operation(uuid,integer,text,text,text,text,uuid,uuid,uuid,integer) from public;
revoke all on function control.renew_release_driver_lease(uuid,uuid,integer,text,uuid,uuid,uuid,bigint,integer) from public;
revoke all on function control.finish_release_driver_operation(uuid,uuid,uuid,uuid,bigint,text,jsonb,text) from public;

do $migration$
begin
    if exists (select 1 from pg_roles where rolname='control_driver_ledger') then
        revoke insert,update,delete on control.deployment_driver_resource_leases from control_driver_ledger;
        grant select on control.deployment_driver_resource_leases to control_driver_ledger;
        grant execute on function control.admit_release_driver_operation(uuid,integer,text,text,text,text,uuid,uuid,uuid,integer) to control_driver_ledger;
        grant execute on function control.renew_release_driver_lease(uuid,uuid,integer,text,uuid,uuid,uuid,bigint,integer) to control_driver_ledger;
        grant execute on function control.finish_release_driver_operation(uuid,uuid,uuid,uuid,bigint,text,jsonb,text) to control_driver_ledger;
    end if;
    if exists (select 1 from pg_roles where rolname='control_release_worker') then
        grant select on control.deployment_driver_resource_leases to control_release_worker;
        grant select on control.deployment_driver_operations to control_release_worker;
    end if;
end
$migration$;

comment on table control.deployment_driver_resource_leases is
'Cross-replica lease and monotonic fence for shared runtime effects; expiry quarantines.';
