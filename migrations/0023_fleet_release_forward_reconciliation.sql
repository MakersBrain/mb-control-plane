-- Recover an outcome-unknown fleet cutover without replaying or rolling back
-- the original release.  Only binaries which declared executor observation
-- protocol v1 before admission can create automatically reconcilable work.

alter table control.deployment_driver_operations
    add column release_executor_protocol_version smallint,
    add constraint deployment_driver_operations_release_executor_protocol_check
        check(release_executor_protocol_version is null
              or release_executor_protocol_version=1);

create or replace function control.validate_release_executor_protocol_update()
returns trigger
language plpgsql
set search_path=pg_catalog, control
as $function$
begin
    if old.release_executor_protocol_version is not null
       and new.release_executor_protocol_version is distinct from
            old.release_executor_protocol_version then
        raise exception 'release executor protocol identity is immutable'
            using errcode='55000';
    end if;
    if old.release_executor_protocol_version is null
       and new.release_executor_protocol_version is not null
       and not (
           old.action='release' and old.state='in_progress'
           and old.safe_error is null and old.execution_attempt=1
           and old.execution_token is not null and old.lease_expires_at>now()
           and exists(
               select 1 from control.deployment_driver_resource_leases lease
               where lease.resource_key='runtime/shared-odoo'
                 and lease.state='held' and lease.authority_kind='release'
                 and lease.driver_operation_id=old.id
                 and lease.lease_expires_at>now()
           )
       ) then
        raise exception 'release executor protocol must be bound at fresh admission'
            using errcode='55000';
    end if;
    return new;
end
$function$;

create trigger deployment_driver_release_executor_protocol_immutable
before update of release_executor_protocol_version
on control.deployment_driver_operations
for each row execute function control.validate_release_executor_protocol_update();

-- Retain the previous implementation only as a private transition primitive.
-- Its ACL follows the rename, so revoke it explicitly before publishing the
-- protocol-aware entry point.
alter function control.admit_release_driver_operation(
    uuid,integer,text,text,text,uuid,text,uuid,uuid,uuid,integer
) rename to admit_release_driver_operation_v2;

revoke all on function control.admit_release_driver_operation_v2(
    uuid,integer,text,text,text,uuid,text,uuid,uuid,uuid,integer
) from public;

do $migration$
declare v_role text;
begin
    foreach v_role in array array[
        'control_api','control_tenant_api','control_membership_worker',
        'control_provisioning_worker','control_invoice_worker',
        'control_inventory_worker','control_email_worker',
        'control_reconciliation_worker','control_lifecycle_worker',
        'control_backup_scheduler','control_driver_ledger',
        'control_release_worker','control_privacy_worker'
    ] loop
        if exists(select 1 from pg_roles where rolname=v_role) then
            execute format(
                'revoke all on function control.admit_release_driver_operation_v2(uuid,integer,text,text,text,uuid,text,uuid,uuid,uuid,integer) from %I',
                v_role
            );
        end if;
    end loop;
end
$migration$;

create or replace function control.admit_release_driver_operation(
    p_control_operation_id uuid,p_control_operation_attempt integer,
    p_control_operation_lease_owner text,p_idempotency_key text,p_target_key text,
    p_fleet_run_id uuid,p_request_digest text,p_instance_owner uuid,
    p_execution_token uuid,p_resource_lease_token uuid,p_ttl_seconds integer,
    p_release_executor_protocol_version smallint
) returns table(outcome text,driver_operation_id uuid,fence_token bigint,
    stored_response jsonb,reserved_workshops uuid[])
language plpgsql security definer
set search_path=pg_catalog, control
as $function$
declare v_row record; v_changed bigint;
begin
    if p_release_executor_protocol_version is distinct from 1 then
        return query select 'invalid'::text,null::uuid,null::bigint,
            null::jsonb,null::uuid[];
        return;
    end if;
    select * into strict v_row from control.admit_release_driver_operation_v2(
        p_control_operation_id,p_control_operation_attempt,
        p_control_operation_lease_owner,p_idempotency_key,p_target_key,
        p_fleet_run_id,p_request_digest,p_instance_owner,p_execution_token,
        p_resource_lease_token,p_ttl_seconds
    );
    if v_row.outcome='acquired' then
        update control.deployment_driver_operations operation
        set release_executor_protocol_version=p_release_executor_protocol_version,
            updated_at=now()
        where operation.id=v_row.driver_operation_id
          and operation.action='release' and operation.state='in_progress'
          and operation.safe_error is null
          and operation.release_executor_protocol_version is null;
        get diagnostics v_changed=row_count;
        if v_changed<>1 then
            raise exception 'release executor protocol binding was lost'
                using errcode='40001';
        end if;
    end if;
    return query select v_row.outcome,v_row.driver_operation_id,
        v_row.fence_token,v_row.stored_response,v_row.reserved_workshops;
end
$function$;

-- Rolling deployments retain the old public signature.  It deliberately does
-- not assign protocol evidence: work first admitted by an older binary can run
-- normally, but an ambiguous outcome remains legacy and non-reconcilable.
create or replace function control.admit_release_driver_operation(
    p_control_operation_id uuid,p_control_operation_attempt integer,
    p_control_operation_lease_owner text,p_idempotency_key text,p_target_key text,
    p_fleet_run_id uuid,p_request_digest text,p_instance_owner uuid,
    p_execution_token uuid,p_resource_lease_token uuid,p_ttl_seconds integer
) returns table(outcome text,driver_operation_id uuid,fence_token bigint,
    stored_response jsonb,reserved_workshops uuid[])
language plpgsql security definer
set search_path=pg_catalog, control
as $function$
begin
    return query select * from control.admit_release_driver_operation_v2(
        p_control_operation_id,p_control_operation_attempt,
        p_control_operation_lease_owner,p_idempotency_key,p_target_key,
        p_fleet_run_id,p_request_digest,p_instance_owner,p_execution_token,
        p_resource_lease_token,p_ttl_seconds
    );
end
$function$;

create table control.fleet_release_reconciliations (
    id uuid primary key default gen_random_uuid(),
    driver_operation_id uuid not null unique,
    fleet_run_id uuid not null unique,
    activation_intent_id uuid not null unique,
    target_key text not null,
    original_fence_token bigint not null,
    original_instance_owner uuid not null,
    original_driver_action_id uuid not null,
    release_executor_protocol_version smallint not null,
    gateway_identity_version smallint not null,
    gateway_configuration_digest text not null,
    target_slot text not null,
    state text not null,
    observation_attempt integer not null default 1,
    claim_expirations integer not null default 0,
    last_claim_expired_at timestamptz,
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
    constraint fleet_release_reconciliations_operation_fkey
        foreign key(driver_operation_id)
        references control.deployment_driver_operations(id) on delete restrict,
    constraint fleet_release_reconciliations_run_fkey
        foreign key(fleet_run_id)
        references control.release_fleet_runs(id) on delete restrict,
    constraint fleet_release_reconciliations_intent_fkey
        foreign key(activation_intent_id)
        references control.fleet_activation_intents(id) on delete restrict,
    constraint fleet_release_reconciliations_target_check
        check(target_key='fleet/'||fleet_run_id::text),
    constraint fleet_release_reconciliations_fence_check
        check(original_fence_token>0),
    constraint fleet_release_reconciliations_protocol_check
        check(release_executor_protocol_version=1 and gateway_identity_version=1),
    constraint fleet_release_reconciliations_gateway_digest_check
        check(gateway_configuration_digest ~ '^sha256:[0-9a-f]{64}$'),
    constraint fleet_release_reconciliations_target_slot_check
        check(target_slot in ('blue','green')),
    constraint fleet_release_reconciliations_attempt_check
        check(observation_attempt>0 and claim_expirations>=0
              and control_operation_attempt>0),
    constraint fleet_release_reconciliations_expiry_check
        check((claim_expirations=0)=(last_claim_expired_at is null)),
    constraint fleet_release_reconciliations_state_check
        check(state in ('observing','inconclusive','succeeded')),
    constraint fleet_release_reconciliations_shape_check check(
        (state='observing' and instance_owner is not null
            and execution_token is not null and lease_expires_at is not null
            and observed_at is null and response is null and safe_error is null)
        or
        (state='inconclusive' and instance_owner is null
            and execution_token is null and lease_expires_at is null
            and observed_at is not null and response is null and safe_error is not null
            and safe_error in ('fleet_forward_observation_inconclusive',
                               'fleet_reconciliation_claim_expired'))
        or
        (state='succeeded' and instance_owner is null
            and execution_token is null and lease_expires_at is null
            and observed_at is not null and response is not null
            and jsonb_typeof(response)='object'
            and pg_column_size(response)<=1048576 and safe_error is null)
    )
);

create or replace function control.validate_fleet_release_reconciliation_update()
returns trigger
language plpgsql
set search_path=pg_catalog, control
as $function$
begin
    if new.id<>old.id
       or new.driver_operation_id<>old.driver_operation_id
       or new.fleet_run_id<>old.fleet_run_id
       or new.activation_intent_id<>old.activation_intent_id
       or new.target_key<>old.target_key
       or new.original_fence_token<>old.original_fence_token
       or new.original_instance_owner<>old.original_instance_owner
       or new.original_driver_action_id<>old.original_driver_action_id
       or new.release_executor_protocol_version<>
            old.release_executor_protocol_version
       or new.gateway_identity_version<>old.gateway_identity_version
       or new.gateway_configuration_digest<>old.gateway_configuration_digest
       or new.target_slot<>old.target_slot
       or new.created_at<>old.created_at then
        raise exception 'fleet reconciliation original identity is immutable'
            using errcode='55000';
    end if;
    if old.state='succeeded' and new is distinct from old then
        raise exception 'succeeded fleet reconciliation is immutable'
            using errcode='55000';
    end if;
    return new;
end
$function$;

create trigger fleet_release_reconciliations_identity_immutable
before update on control.fleet_release_reconciliations
for each row execute function control.validate_fleet_release_reconciliation_update();

create or replace function control.admit_fleet_release_reconciliation(
    p_control_operation_id uuid,
    p_control_operation_attempt integer,
    p_control_operation_lease_owner text,
    p_idempotency_key text,
    p_target_key text,
    p_fleet_run_id uuid,
    p_request_digest text,
    p_instance_owner uuid,
    p_execution_token uuid,
    p_ttl_seconds integer
) returns table(
    outcome text,
    reconciliation_id uuid,
    driver_operation_id uuid,
    original_fence_token bigint,
    activation_identity jsonb,
    stored_response jsonb
)
language plpgsql security definer
set search_path=pg_catalog, control
as $function$
declare
    v_resource control.deployment_driver_resource_leases%rowtype;
    v_operation control.deployment_driver_operations%rowtype;
    v_run control.release_fleet_runs%rowtype;
    v_intent control.fleet_activation_intents%rowtype;
    v_reconciliation control.fleet_release_reconciliations%rowtype;
    v_identity jsonb;
    v_activation_identity jsonb;
begin
    if p_control_operation_attempt<=0
       or p_control_operation_lease_owner is null
       or btrim(p_control_operation_lease_owner)=''
       or p_idempotency_key is null or btrim(p_idempotency_key)=''
       or length(p_idempotency_key)>180
       or p_fleet_run_id is null
       or p_target_key is distinct from 'fleet/'||p_fleet_run_id::text
       or p_request_digest is null or p_request_digest !~ '^[0-9a-f]{64}$'
       or p_instance_owner is null or p_execution_token is null
       or p_ttl_seconds<60 or p_ttl_seconds>600 then
        return query select 'invalid',null::uuid,null::uuid,null::bigint,
            null::jsonb,null::jsonb;
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
      and operation.payload->>'phase'='adopt'
    for update;
    if not found then
        return query select 'upstream_lease_lost',null::uuid,null::uuid,
            null::bigint,null::jsonb,null::jsonb;
        return;
    end if;

    select * into strict v_resource
    from control.deployment_driver_resource_leases
    where resource_key='runtime/shared-odoo' for update;
    if v_resource.state<>'quarantined'
       or v_resource.authority_kind<>'release'
       or v_resource.driver_operation_id is null then
        return query select 'not_quarantined',null::uuid,
            v_resource.driver_operation_id,v_resource.fence_token,
            null::jsonb,null::jsonb;
        return;
    end if;

    select * into strict v_operation
    from control.deployment_driver_operations
    where id=v_resource.driver_operation_id for update;
    if v_operation.action<>'release'
       or v_operation.state<>'in_progress'
       or v_operation.safe_error is distinct from 'runtime_outcome_unknown'
       or v_operation.release_executor_protocol_version is distinct from 1
       or v_operation.control_operation_id is distinct from p_control_operation_id
       or v_operation.idempotency_key<>p_idempotency_key
       or v_operation.target_key is distinct from p_target_key
       or v_operation.request_digest<>p_request_digest
       or v_resource.fence_token<=0 then
        return query select 'not_reconcilable',null::uuid,v_operation.id,
            v_resource.fence_token,null::jsonb,null::jsonb;
        return;
    end if;

    select * into v_run from control.release_fleet_runs
    where id=p_fleet_run_id and operation_id=p_control_operation_id
      and release_id=(select payload->>'release_id' from control.operations
                      where id=p_control_operation_id)
      and state in ('preparing','activating')
      and driver_fence_token=v_resource.fence_token
      and jsonb_typeof(tenant_snapshot)='array'
      and jsonb_array_length(tenant_snapshot) between 1 and 500
    for update;
    if not found then
        return query select 'fleet_state_mismatch',null::uuid,v_operation.id,
            v_resource.fence_token,null::jsonb,null::jsonb;
        return;
    end if;

    select * into v_intent from control.fleet_activation_intents
    where fleet_run_id=v_run.id and release_id=v_run.release_id
      and runtime_key='shared-odoo'
      and driver_fence_token=v_resource.fence_token
      and gateway_identity_version=1 and abandoned_at is null
    for update;
    if not found then
        return query select 'activation_identity_absent',null::uuid,v_operation.id,
            v_resource.fence_token,null::jsonb,null::jsonb;
        return;
    end if;

    v_identity:=jsonb_build_object(
        'protocol_version',v_intent.gateway_identity_version,
        'fleet_run_id',v_intent.fleet_run_id,
        'driver_action_id',v_intent.driver_action_id,
        'original_driver_fence_token',v_intent.driver_fence_token,
        'gateway_configuration_digest',v_intent.gateway_configuration_digest,
        'target_slot',v_intent.target_slot
    );
    v_activation_identity:=v_identity||jsonb_build_object(
        'original_instance_owner',v_resource.lease_owner,
        'release_executor_protocol_version',
            v_operation.release_executor_protocol_version
    );

    select * into v_reconciliation
    from control.fleet_release_reconciliations reconciliation
    where reconciliation.driver_operation_id=v_operation.id for update;
    if found then
        if v_reconciliation.fleet_run_id<>v_run.id
           or v_reconciliation.activation_intent_id<>v_intent.id
           or v_reconciliation.target_key<>p_target_key
           or v_reconciliation.original_fence_token<>v_resource.fence_token
           or v_reconciliation.original_instance_owner<>v_resource.lease_owner
           or v_reconciliation.original_driver_action_id<>v_intent.driver_action_id
           or v_reconciliation.release_executor_protocol_version<>1
           or v_reconciliation.gateway_identity_version<>1
           or v_reconciliation.gateway_configuration_digest<>
                v_intent.gateway_configuration_digest
           or v_reconciliation.target_slot<>v_intent.target_slot then
            return query select 'conflict',v_reconciliation.id,v_operation.id,
                v_resource.fence_token,null::jsonb,null::jsonb;
            return;
        elsif v_reconciliation.state='observing'
              and v_reconciliation.lease_expires_at>now() then
            return query select 'busy',v_reconciliation.id,v_operation.id,
                v_resource.fence_token,v_activation_identity,null::jsonb;
            return;
        elsif v_reconciliation.state='succeeded' then
            return query select 'replay',v_reconciliation.id,v_operation.id,
                v_resource.fence_token,v_activation_identity,
                v_reconciliation.response;
            return;
        end if;
        update control.fleet_release_reconciliations set
            state='observing',observation_attempt=observation_attempt+1,
            claim_expirations=claim_expirations+
                case when state='observing' then 1 else 0 end,
            last_claim_expired_at=case when state='observing' then now()
                else last_claim_expired_at end,
            control_operation_attempt=p_control_operation_attempt,
            control_operation_lease_owner=p_control_operation_lease_owner,
            instance_owner=p_instance_owner,execution_token=p_execution_token,
            lease_expires_at=now()+make_interval(secs=>p_ttl_seconds),
            observed_at=null,response=null,safe_error=null,updated_at=now()
        where id=v_reconciliation.id;
        return query select 'acquired',v_reconciliation.id,v_operation.id,
            v_resource.fence_token,v_activation_identity,null::jsonb;
        return;
    end if;

    insert into control.fleet_release_reconciliations(
        driver_operation_id,fleet_run_id,activation_intent_id,target_key,
        original_fence_token,original_instance_owner,original_driver_action_id,
        release_executor_protocol_version,gateway_identity_version,
        gateway_configuration_digest,target_slot,state,
        control_operation_attempt,control_operation_lease_owner,
        instance_owner,execution_token,lease_expires_at
    ) values(
        v_operation.id,v_run.id,v_intent.id,p_target_key,
        v_resource.fence_token,v_resource.lease_owner,v_intent.driver_action_id,1,1,
        v_intent.gateway_configuration_digest,v_intent.target_slot,'observing',
        p_control_operation_attempt,p_control_operation_lease_owner,
        p_instance_owner,p_execution_token,
        now()+make_interval(secs=>p_ttl_seconds)
    ) returning id into v_reconciliation.id;
    return query select 'acquired',v_reconciliation.id,v_operation.id,
        v_resource.fence_token,v_activation_identity,null::jsonb;
end
$function$;

create or replace function control.finish_fleet_release_reconciliation(
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
    v_reconciliation control.fleet_release_reconciliations%rowtype;
    v_resource control.deployment_driver_resource_leases%rowtype;
    v_operation control.deployment_driver_operations%rowtype;
    v_release control.application_releases%rowtype;
    v_run control.release_fleet_runs%rowtype;
    v_intent control.fleet_activation_intents%rowtype;
    v_evidence jsonb;
    v_proof jsonb;
    v_identity jsonb;
    v_expected_prepared jsonb;
    v_changed bigint;
begin
    if p_outcome not in ('succeeded','inconclusive') then return false; end if;
    select * into v_reconciliation
    from control.fleet_release_reconciliations
    where id=p_reconciliation_id and state='observing'
      and instance_owner=p_instance_owner and execution_token=p_execution_token
      and lease_expires_at>now();
    if not found then return false; end if;
    select * into v_operation from control.deployment_driver_operations
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
      and operation.payload->>'phase'='adopt'
    for update;
    if not found then return false; end if;

    select * into v_resource from control.deployment_driver_resource_leases
    where resource_key='runtime/shared-odoo' for update;
    select * into v_operation from control.deployment_driver_operations
    where id=v_reconciliation.driver_operation_id for update;
    select * into v_reconciliation
    from control.fleet_release_reconciliations
    where id=p_reconciliation_id and state='observing'
      and instance_owner=p_instance_owner and execution_token=p_execution_token
      and lease_expires_at>now() for update;
    if not found
       or v_resource.state<>'quarantined'
       or v_resource.authority_kind is distinct from 'release'
       or v_resource.driver_operation_id is distinct from v_operation.id
       or v_resource.fence_token<>v_reconciliation.original_fence_token
       or v_operation.state<>'in_progress'
       or v_operation.safe_error is distinct from 'runtime_outcome_unknown'
       or v_operation.release_executor_protocol_version is distinct from 1 then
        return false;
    end if;

    if p_outcome='inconclusive' then
        if p_response is not null then return false; end if;
        update control.fleet_release_reconciliations set state='inconclusive',
            instance_owner=null,execution_token=null,lease_expires_at=null,
            observed_at=now(),safe_error='fleet_forward_observation_inconclusive',
            updated_at=now() where id=p_reconciliation_id;
        return found;
    end if;

    select release.* into v_release from control.application_releases release
    where release.id=(select run.release_id from control.release_fleet_runs run
                      where run.id=v_reconciliation.fleet_run_id)
      and release.status='prepared'
    for update;
    if not found then return false; end if;
    select * into v_run from control.release_fleet_runs
    where id=v_reconciliation.fleet_run_id
      and operation_id=v_operation.control_operation_id
      and state in ('preparing','activating')
      and driver_fence_token=v_reconciliation.original_fence_token
      and jsonb_typeof(tenant_snapshot)='array'
      and jsonb_array_length(tenant_snapshot) between 1 and 500
    for update;
    if not found then return false; end if;
    select * into v_intent from control.fleet_activation_intents
    where id=v_reconciliation.activation_intent_id
      and fleet_run_id=v_run.id and release_id=v_run.release_id
      and runtime_key='shared-odoo'
      and driver_action_id=v_reconciliation.original_driver_action_id
      and driver_fence_token=v_reconciliation.original_fence_token
      and gateway_identity_version=v_reconciliation.gateway_identity_version
      and gateway_configuration_digest=
            v_reconciliation.gateway_configuration_digest
      and target_slot=v_reconciliation.target_slot
      and abandoned_at is null
    for update;
    if not found then return false; end if;
    if v_release.id<>v_run.release_id
       or v_release.odoo_subject_digest<>v_intent.odoo_subject_digest
       or v_release.extension_subject_digest<>v_intent.extension_subject_digest then
        return false;
    end if;
    v_identity:=jsonb_build_object(
        'protocol_version',v_intent.gateway_identity_version,
        'fleet_run_id',v_intent.fleet_run_id,
        'driver_action_id',v_intent.driver_action_id,
        'original_driver_fence_token',v_intent.driver_fence_token,
        'gateway_configuration_digest',v_intent.gateway_configuration_digest,
        'target_slot',v_intent.target_slot
    );
    if jsonb_typeof(p_response) is distinct from 'object'
       or (select count(*) from jsonb_object_keys(p_response))<>2
       or not (p_response ?& array['evidence','reconciliation'])
       or jsonb_typeof(p_response->'evidence') is distinct from 'object'
       or jsonb_typeof(p_response->'reconciliation') is distinct from 'object'
       or pg_column_size(p_response)>1048576 then
        return false;
    end if;
    v_evidence:=p_response->'evidence';
    v_proof:=p_response->'reconciliation';
    if (select count(*) from jsonb_object_keys(v_proof))<>11
       or v_proof->'id' is distinct from to_jsonb(p_reconciliation_id)
       or v_proof->'kind' is distinct from '"fleet_activation_forward"'::jsonb
       or v_proof->'protocol_version' is distinct from '1'::jsonb
       or v_proof->'external_executor_quiescent' is distinct from 'true'::jsonb
       or v_proof->'candidate_runtime_verified' is distinct from 'true'::jsonb
       or v_proof->'gateway_identity_verified' is distinct from 'true'::jsonb
       or v_proof->'target_database_access_verified' is distinct from 'true'::jsonb
       or v_proof->'old_runtime_retired' is distinct from 'true'::jsonb
       or v_proof->'forward_only' is distinct from 'true'::jsonb
       or v_proof->'original_executor' is distinct from jsonb_build_object(
            'instance_owner',v_reconciliation.original_instance_owner,
            'protocol_version',v_reconciliation.release_executor_protocol_version
       )
       or v_proof->'gateway_identity' is distinct from v_identity then
        return false;
    end if;

    select coalesce(jsonb_agg(jsonb_build_object(
        'adoption_id',adoption.id,
        'workshop_id',adoption.workshop_id,
        'database_id',adoption.database_id,
        'database_ref',database.database_ref,
        'public_hostname',database.public_hostname
    ) order by adoption.created_at,adoption.id),'[]'::jsonb)
    into v_expected_prepared
    from control.tenant_release_adoptions adoption
    join control.odoo_databases database
      on database.id=adoption.database_id
     and database.workshop_id=adoption.workshop_id
    where adoption.operation_id=v_operation.control_operation_id
      and adoption.release_id=v_run.release_id and adoption.state='prepared';
    if v_expected_prepared<>v_intent.prepared_tenants
       or jsonb_array_length(v_expected_prepared)<>jsonb_array_length(v_run.tenant_snapshot)
       or (select count(*) from jsonb_object_keys(v_evidence))<>30
       or not (v_evidence ?& array[
            'release_id','odoo_subject_digest','extension_subject_digest',
            'odoo_manifest_digest','odoo_config_digest',
            'extension_manifest_digest','extension_config_digest','payload_digest',
            'extension_volume','pair_qualification_digest',
            'bridge_contract_digest','installed_addon_versions','runtime_key',
            'target_slot','runtime_container','runtime_role',
            'runtime_deployment_ref','runtime_config_digest','prepared_tenants',
            'fleet_generation','tenant_snapshot','gateway_configuration_digest',
            'driver_action_id','driver_operation_id','driver_fence_token',
            'old_runtime_database_access_revoked','tenant_recovery_verified',
            'candidate_smoke_verified','candidate_restart_policy',
            'retained_restart_policy'
       ])
       or v_evidence->>'release_id' is distinct from v_run.release_id
       or v_evidence->>'runtime_key' is distinct from 'shared-odoo'
       or v_evidence->>'target_slot' is distinct from v_intent.target_slot
       or v_evidence->>'odoo_subject_digest' is distinct from v_intent.odoo_subject_digest
       or v_evidence->>'extension_subject_digest' is distinct from v_intent.extension_subject_digest
       or v_evidence->>'pair_qualification_digest' is distinct from v_intent.pair_qualification_digest
       or v_evidence->'prepared_tenants' is distinct from v_expected_prepared
       or v_evidence->'tenant_snapshot' is distinct from v_run.tenant_snapshot
       or v_evidence->>'fleet_generation' is distinct from v_run.fleet_generation::text
       or v_evidence->>'gateway_configuration_digest' is distinct from
            v_intent.gateway_configuration_digest
       or v_evidence->>'driver_action_id' is distinct from v_intent.driver_action_id::text
       or v_evidence->>'driver_operation_id' is distinct from v_operation.id::text
       or v_evidence->>'driver_fence_token' is distinct from
            v_reconciliation.original_fence_token::text
       or v_evidence->'old_runtime_database_access_revoked' is distinct from 'true'::jsonb
       or v_evidence->'tenant_recovery_verified' is distinct from 'true'::jsonb
       or v_evidence->'candidate_smoke_verified' is distinct from 'true'::jsonb
       or v_evidence->>'candidate_restart_policy' is distinct from 'unless-stopped'
       or v_evidence->>'retained_restart_policy' is distinct from 'no'
       or (v_evidence->>'odoo_manifest_digest' ~ '^sha256:[0-9a-f]{64}$')
            is distinct from true
       or (v_evidence->>'odoo_config_digest' ~ '^sha256:[0-9a-f]{64}$')
            is distinct from true
       or (v_evidence->>'extension_manifest_digest' ~ '^sha256:[0-9a-f]{64}$')
            is distinct from true
       or (v_evidence->>'extension_config_digest' ~ '^sha256:[0-9a-f]{64}$')
            is distinct from true
       or (v_evidence->>'payload_digest' ~ '^sha256:[0-9a-f]{64}$')
            is distinct from true
       or (v_evidence->>'bridge_contract_digest' ~ '^sha256:[0-9a-f]{64}$')
            is distinct from true
       or (v_evidence->>'runtime_config_digest' ~ '^sha256:[0-9a-f]{64}$')
            is distinct from true
       or (v_evidence->>'extension_volume' ~
            '^mb-(control-|dev[1-4]-)?ext-[a-f0-9]{16}-[a-f0-9]{16}$')
            is distinct from true
       or (v_evidence->>'runtime_container' ~
            ('^[a-z0-9][a-z0-9-]{0,110}-odoo-'||v_intent.target_slot||'$'))
            is distinct from true
       or v_evidence->>'runtime_role' is distinct from
            'mb_runtime_'||substr(v_intent.odoo_subject_digest,8,16)
       or v_evidence->>'runtime_deployment_ref' is distinct from
            v_release.manifest->'odoo_runtime'->>'deployment_ref'
       or jsonb_typeof(v_evidence->'installed_addon_versions') is distinct from 'object' then
        return false;
    end if;

    -- The only direction exposed here is forward: acknowledge the exact loaded
    -- generation (if needed), preserve all immutable intent fields, then turn
    -- the original quarantined receipt into success.  No function in this
    -- migration can restore an old route, grant an old runtime access, abandon
    -- the intent, or mark the original operation failed.
    if v_intent.activated_at is null then
        update control.fleet_activation_intents set
            observed_configuration_digest=gateway_configuration_digest,
            activated_at=now()
        where id=v_intent.id and activated_at is null
          and observed_configuration_digest is null and abandoned_at is null
          and gateway_identity_version=1;
        get diagnostics v_changed=row_count;
        if v_changed<>1 then return false; end if;
    elsif v_intent.observed_configuration_digest is distinct from
            v_intent.gateway_configuration_digest then
        return false;
    end if;

    update control.deployment_driver_operations set state='succeeded',
        control_operation_attempt=v_reconciliation.control_operation_attempt,
        control_operation_lease_owner=v_reconciliation.control_operation_lease_owner,
        response=p_response,safe_error=null,execution_token=null,
        lease_expires_at=null,updated_at=now()
    where id=v_operation.id and state='in_progress'
      and safe_error='runtime_outcome_unknown'
      and release_executor_protocol_version=1;
    get diagnostics v_changed=row_count;
    if v_changed<>1 then return false; end if;
    update control.fleet_release_reconciliations set state='succeeded',
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
        raise exception 'fleet reconciliation resource fence was lost'
            using errcode='40001';
    end if;
    return true;
end
$function$;

revoke all on table control.fleet_release_reconciliations from public;
revoke all on function control.validate_release_executor_protocol_update() from public;
revoke all on function control.validate_fleet_release_reconciliation_update() from public;
revoke all on function control.admit_release_driver_operation(
    uuid,integer,text,text,text,uuid,text,uuid,uuid,uuid,integer,smallint
) from public;
revoke all on function control.admit_release_driver_operation(
    uuid,integer,text,text,text,uuid,text,uuid,uuid,uuid,integer
) from public;
revoke all on function control.admit_fleet_release_reconciliation(
    uuid,integer,text,text,text,uuid,text,uuid,uuid,integer
) from public;
revoke all on function control.finish_fleet_release_reconciliation(
    uuid,uuid,uuid,text,jsonb
) from public;

do $migration$
begin
    if exists(select 1 from pg_roles where rolname='control_driver_ledger') then
        revoke insert,update,delete on control.fleet_release_reconciliations
            from control_driver_ledger;
        grant execute on function control.admit_release_driver_operation(
            uuid,integer,text,text,text,uuid,text,uuid,uuid,uuid,integer,smallint
        ) to control_driver_ledger;
        grant execute on function control.admit_release_driver_operation(
            uuid,integer,text,text,text,uuid,text,uuid,uuid,uuid,integer
        ) to control_driver_ledger;
        grant execute on function control.admit_fleet_release_reconciliation(
            uuid,integer,text,text,text,uuid,text,uuid,uuid,integer
        ) to control_driver_ledger;
        grant execute on function control.finish_fleet_release_reconciliation(
            uuid,uuid,uuid,text,jsonb
        ) to control_driver_ledger;
    end if;
end
$migration$;

comment on column control.deployment_driver_operations.release_executor_protocol_version is
'Executor-observation contract declared by the admitting binary before release host effects; NULL is legacy and cannot be reconciled automatically.';
comment on table control.fleet_release_reconciliations is
'Expiring, function-only claims for exact forward completion of protocol-v1 outcome-unknown fleet cutovers; no rollback or blind replay transition exists.';
