-- Reconcile an outcome-unknown initial release without replaying host effects.
-- This deliberately excludes fleet activation: route publication, tenant
-- database grants and old-runtime shutdown do not enforce the PostgreSQL fence
-- and therefore need a separate cross-fence compensation protocol.

create table control.release_driver_reconciliations (
    id uuid primary key default gen_random_uuid(),
    driver_operation_id uuid not null unique,
    target_key text not null,
    original_fence_token bigint not null,
    state text not null,
    observation_attempt integer not null default 1,
    control_operation_attempt integer not null,
    control_operation_lease_owner text not null,
    instance_owner uuid,
    execution_token uuid,
    lease_expires_at timestamptz,
    observed_at timestamptz,
    response jsonb,
    safe_error text,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    constraint release_driver_reconciliations_operation_fkey
        foreign key(driver_operation_id)
        references control.deployment_driver_operations(id) on delete restrict,
    constraint release_driver_reconciliations_target_check
        check(target_key ~ '^initial/[A-Za-z0-9._:-]{1,200}$'),
    constraint release_driver_reconciliations_fence_check
        check(original_fence_token > 0),
    constraint release_driver_reconciliations_attempt_check
        check(observation_attempt > 0 and control_operation_attempt > 0),
    constraint release_driver_reconciliations_state_check
        check(state in ('observing','inconclusive','succeeded')),
    constraint release_driver_reconciliations_shape_check check(
        (state='observing' and instance_owner is not null
            and execution_token is not null and lease_expires_at is not null
            and observed_at is null and response is null and safe_error is null)
        or
        (state='inconclusive' and instance_owner is null
            and execution_token is null and lease_expires_at is null
            and observed_at is not null and response is null
            and safe_error='initial_runtime_observation_inconclusive')
        or
        (state='succeeded' and instance_owner is null
            and execution_token is null and lease_expires_at is null
            and observed_at is not null and jsonb_typeof(response)='object'
            and safe_error is null)
    )
);

create or replace function control.admit_initial_release_reconciliation(
    p_control_operation_id uuid,
    p_control_operation_attempt integer,
    p_control_operation_lease_owner text,
    p_idempotency_key text,
    p_target_key text,
    p_request_digest text,
    p_instance_owner uuid,
    p_execution_token uuid,
    p_ttl_seconds integer
) returns table(
    outcome text,
    reconciliation_id uuid,
    driver_operation_id uuid,
    original_fence_token bigint,
    stored_evidence jsonb
)
language plpgsql security definer
set search_path=pg_catalog, control
as $function$
declare
    v_resource control.deployment_driver_resource_leases%rowtype;
    v_operation control.deployment_driver_operations%rowtype;
    v_reconciliation control.release_driver_reconciliations%rowtype;
    v_release_id text;
    v_evidence jsonb;
begin
    if p_control_operation_attempt<=0
       or p_control_operation_lease_owner is null
       or btrim(p_control_operation_lease_owner)=''
       or p_idempotency_key is null or btrim(p_idempotency_key)=''
       or length(p_idempotency_key)>180
       or p_target_key is null
       or p_target_key !~ '^initial/[A-Za-z0-9._:-]{1,200}$'
       or p_request_digest is null or p_request_digest !~ '^[0-9a-f]{64}$'
       or p_instance_owner is null or p_execution_token is null
       or p_ttl_seconds<60 or p_ttl_seconds>600 then
        return query select 'invalid',null::uuid,null::uuid,null::bigint,null::jsonb;
        return;
    end if;

    perform 1 from control.operations operation
    where operation.id=p_control_operation_id
      and operation.kind='odoo.release.adopt'
      and operation.queue='release-adoption'
      and operation.workshop_id is null
      and operation.state='in_flight'
      and operation.attempt=p_control_operation_attempt
      and operation.leased_by=p_control_operation_lease_owner
      and operation.lease_expires_at>now()
      and operation.payload->>'phase'='preflight'
      and p_target_key='initial/'||(operation.payload->>'release_id')
    for update;
    if not found then
        return query select 'upstream_lease_lost',null::uuid,null::uuid,
            null::bigint,null::jsonb;
        return;
    end if;

    select * into strict v_resource
    from control.deployment_driver_resource_leases
    where resource_key='runtime/shared-odoo' for update;
    if v_resource.state<>'quarantined'
       or v_resource.authority_kind<>'release'
       or v_resource.driver_operation_id is null then
        return query select 'not_quarantined',null::uuid,
            v_resource.driver_operation_id,v_resource.fence_token,null::jsonb;
        return;
    end if;

    select * into strict v_operation
    from control.deployment_driver_operations
    where id=v_resource.driver_operation_id for update;
    if v_operation.action<>'release'
       or v_operation.state<>'in_progress'
       or v_operation.safe_error<>'runtime_outcome_unknown'
       or v_operation.control_operation_id<>p_control_operation_id
       or v_operation.idempotency_key<>p_idempotency_key
       or v_operation.target_key<>p_target_key
       or v_operation.request_digest<>p_request_digest
       or v_resource.fence_token<=0 then
        return query select 'not_reconcilable',null::uuid,v_operation.id,
            v_resource.fence_token,null::jsonb;
        return;
    end if;

    -- Reconciliation is safe only while this is still the bootstrap release.
    -- A later workshop or database changes the effect into a fleet-scoped
    -- decision and must retain quarantine.
    if exists(select 1 from control.workshops)
       or exists(select 1 from control.odoo_databases)
       or exists(select 1 from control.tenant_release_adoptions)
       or exists(select 1 from control.application_releases where status='active')
       or exists(select 1 from control.workshop_route_application_leases) then
        return query select 'fleet_not_empty',null::uuid,v_operation.id,
            v_resource.fence_token,null::jsonb;
        return;
    end if;

    v_release_id:=substr(p_target_key,length('initial/')+1);
    select slot.evidence into v_evidence
    from control.runtime_release_slots slot
    where slot.runtime_key='shared-odoo' and slot.release_id=v_release_id
      and slot.state='prepared'
      and jsonb_typeof(slot.evidence)='object'
      and slot.evidence->>'release_id'=v_release_id
      and slot.evidence->>'driver_operation_id'=v_operation.id::text
      and slot.evidence->>'driver_fence_token'=v_resource.fence_token::text
    order by slot.verified_at desc nulls last,slot.slot
    limit 1 for update;
    if not found then
        return query select 'evidence_absent',null::uuid,v_operation.id,
            v_resource.fence_token,null::jsonb;
        return;
    end if;

    select * into v_reconciliation
    from control.release_driver_reconciliations reconciliation
    where reconciliation.driver_operation_id=v_operation.id for update;
    if found then
        if v_reconciliation.target_key<>p_target_key
           or v_reconciliation.original_fence_token<>v_resource.fence_token then
            return query select 'conflict',v_reconciliation.id,v_operation.id,
                v_resource.fence_token,null::jsonb;
            return;
        elsif v_reconciliation.state='observing'
              and v_reconciliation.lease_expires_at>now() then
            return query select 'busy',v_reconciliation.id,v_operation.id,
                v_resource.fence_token,null::jsonb;
            return;
        elsif v_reconciliation.state='succeeded' then
            return query select 'replay',v_reconciliation.id,v_operation.id,
                v_resource.fence_token,v_evidence;
            return;
        end if;
        update control.release_driver_reconciliations set
            state='observing',observation_attempt=observation_attempt+1,
            control_operation_attempt=p_control_operation_attempt,
            control_operation_lease_owner=p_control_operation_lease_owner,
            instance_owner=p_instance_owner,execution_token=p_execution_token,
            lease_expires_at=now()+make_interval(secs=>p_ttl_seconds),
            observed_at=null,response=null,safe_error=null,updated_at=now()
        where id=v_reconciliation.id;
        return query select 'acquired',v_reconciliation.id,v_operation.id,
            v_resource.fence_token,v_evidence;
        return;
    end if;

    insert into control.release_driver_reconciliations(
        driver_operation_id,target_key,original_fence_token,state,
        control_operation_attempt,control_operation_lease_owner,
        instance_owner,execution_token,lease_expires_at
    ) values(
        v_operation.id,p_target_key,v_resource.fence_token,'observing',
        p_control_operation_attempt,p_control_operation_lease_owner,
        p_instance_owner,p_execution_token,
        now()+make_interval(secs=>p_ttl_seconds)
    ) returning id into v_reconciliation.id;
    return query select 'acquired',v_reconciliation.id,v_operation.id,
        v_resource.fence_token,v_evidence;
end
$function$;

create or replace function control.finish_initial_release_reconciliation(
    p_reconciliation_id uuid,
    p_instance_owner uuid,
    p_execution_token uuid,
    p_outcome text,
    p_response jsonb
) returns boolean
language plpgsql security definer
set search_path=pg_catalog, control
as $function$
declare
    v_reconciliation control.release_driver_reconciliations%rowtype;
    v_resource control.deployment_driver_resource_leases%rowtype;
    v_operation control.deployment_driver_operations%rowtype;
    v_slot_evidence jsonb;
    v_changed bigint;
begin
    if p_outcome not in ('succeeded','inconclusive') then return false; end if;
    -- Discover identities without locking, then acquire the canonical durable
    -- order: upstream operation before shared release authority and receipts.
    select * into v_reconciliation
    from control.release_driver_reconciliations
    where id=p_reconciliation_id and state='observing'
      and instance_owner=p_instance_owner and execution_token=p_execution_token
      and lease_expires_at>now();
    if not found then return false; end if;
    select * into v_operation
    from control.deployment_driver_operations
    where id=v_reconciliation.driver_operation_id;
    if not found or v_operation.control_operation_id is null then return false; end if;
    perform 1 from control.operations operation
    where operation.id=v_operation.control_operation_id
      and operation.kind='odoo.release.adopt'
      and operation.queue='release-adoption'
      and operation.workshop_id is null
      and operation.state='in_flight'
      and operation.attempt=v_reconciliation.control_operation_attempt
      and operation.leased_by=v_reconciliation.control_operation_lease_owner
      and operation.lease_expires_at>now()
    for update;
    if not found then return false; end if;

    if p_outcome='succeeded' then
        -- Keep the fleet-empty predicate stable through commit. SHARE blocks
        -- concurrent inserts/updates/deletes without granting this function a
        -- mutation path into any of these authorities.
        lock table control.workshops,control.odoo_databases,
            control.tenant_release_adoptions,
            control.workshop_route_application_leases,
            control.application_releases in share mode;
    end if;
    select * into v_resource
    from control.deployment_driver_resource_leases
    where resource_key='runtime/shared-odoo' for update;
    if not found then return false; end if;
    select * into v_operation
    from control.deployment_driver_operations
    where id=v_reconciliation.driver_operation_id for update;
    if not found then return false; end if;
    select * into v_reconciliation
    from control.release_driver_reconciliations
    where id=p_reconciliation_id and state='observing'
      and instance_owner=p_instance_owner and execution_token=p_execution_token
      and lease_expires_at>now() for update;
    if not found then return false; end if;
    if v_resource.state<>'quarantined'
       or v_resource.authority_kind<>'release'
       or v_resource.driver_operation_id<>v_operation.id
       or v_resource.fence_token<>v_reconciliation.original_fence_token
       or v_operation.state<>'in_progress'
       or v_operation.safe_error<>'runtime_outcome_unknown' then
        return false;
    end if;
    if p_outcome='inconclusive' then
        if p_response is not null then return false; end if;
        update control.release_driver_reconciliations set state='inconclusive',
            instance_owner=null,execution_token=null,lease_expires_at=null,
            observed_at=now(),safe_error='initial_runtime_observation_inconclusive',
            updated_at=now() where id=p_reconciliation_id;
        return found;
    end if;

    if exists(select 1 from control.workshops)
       or exists(select 1 from control.odoo_databases)
       or exists(select 1 from control.tenant_release_adoptions)
       or exists(select 1 from control.application_releases where status='active')
       or exists(select 1 from control.workshop_route_application_leases) then
        return false;
    end if;

    select slot.evidence into v_slot_evidence
    from control.runtime_release_slots slot
    where slot.runtime_key='shared-odoo'
      and slot.release_id=substr(v_reconciliation.target_key,length('initial/')+1)
      and slot.state='prepared'
      and slot.evidence->>'driver_operation_id'=v_operation.id::text
      and slot.evidence->>'driver_fence_token'=v_resource.fence_token::text
    order by slot.verified_at desc nulls last,slot.slot limit 1 for update;
    if not found or jsonb_typeof(p_response)<>'object'
       or (select count(*) from jsonb_object_keys(p_response))<>3
       or p_response->'evidence' is distinct from v_slot_evidence
       or p_response->'observed' is distinct from 'true'::jsonb
       or p_response->'reconciliation' is distinct from jsonb_build_object(
            'id',p_reconciliation_id,
            'kind','initial_runtime_inspection',
            'runtime_matches_prepared_slot',true
       ) then
        return false;
    end if;

    update control.deployment_driver_operations set state='succeeded',
        control_operation_attempt=v_reconciliation.control_operation_attempt,
        control_operation_lease_owner=v_reconciliation.control_operation_lease_owner,
        response=p_response,safe_error=null,execution_token=null,
        lease_expires_at=null,updated_at=now()
    where id=v_operation.id and state='in_progress'
      and safe_error='runtime_outcome_unknown';
    get diagnostics v_changed=row_count; if v_changed<>1 then return false; end if;
    update control.release_driver_reconciliations set state='succeeded',
        instance_owner=null,execution_token=null,lease_expires_at=null,
        observed_at=now(),response=p_response,safe_error=null,updated_at=now()
    where id=p_reconciliation_id;
    update control.deployment_driver_resource_leases set state='idle',
        authority_kind=null,driver_operation_id=null,effect_run_id=null,
        lease_owner=null,lease_token=null,lease_expires_at=null,heartbeat_at=null,
        quarantined_at=null,safe_error=null,updated_at=now()
    where resource_key='runtime/shared-odoo' and state='quarantined'
      and authority_kind='release' and driver_operation_id=v_operation.id
      and fence_token=v_reconciliation.original_fence_token;
    get diagnostics v_changed=row_count;
    if v_changed<>1 then
        raise exception 'release reconciliation resource fence was lost'
            using errcode='40001';
    end if;
    return true;
end
$function$;

revoke all on table control.release_driver_reconciliations from public;
revoke all on function control.admit_initial_release_reconciliation(
    uuid,integer,text,text,text,text,uuid,uuid,integer) from public;
revoke all on function control.finish_initial_release_reconciliation(
    uuid,uuid,uuid,text,jsonb) from public;

do $migration$
begin
    if exists(select 1 from pg_roles where rolname='control_driver_ledger') then
        grant execute on function control.admit_initial_release_reconciliation(
            uuid,integer,text,text,text,text,uuid,uuid,integer) to control_driver_ledger;
        grant execute on function control.finish_initial_release_reconciliation(
            uuid,uuid,uuid,text,jsonb) to control_driver_ledger;
    end if;
end
$migration$;

comment on table control.release_driver_reconciliations is
'Read-only host observation claims for outcome-unknown empty-fleet initial releases; fleet cutovers remain quarantined.';
