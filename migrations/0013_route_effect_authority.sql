-- Give startup rebuilds and recovery maintenance first-class ownership of the
-- same global and per-workshop route authorities used by releases and normal
-- projection applications. Host effects cannot reject a stale fence, so every
-- expired or ambiguous effect remains fail closed.

create table control.workshop_route_effect_runs (
    id uuid primary key default gen_random_uuid(),
    kind text not null,
    reason text not null,
    target_key text not null,
    idempotency_key text not null,
    request_digest text not null,
    workshop_id uuid,
    control_operation_id uuid,
    control_operation_attempt integer,
    control_operation_lease_owner text,
    state text not null,
    instance_owner uuid,
    execution_token uuid,
    global_lease_token uuid,
    route_lease_token uuid,
    lease_expires_at timestamptz,
    heartbeat_at timestamptz,
    global_fence_token bigint,
    response jsonb,
    safe_error text,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    finished_at timestamptz,
    unique(kind,target_key),
    unique(kind,idempotency_key),
    constraint workshop_route_effect_runs_kind_check
        check(kind in ('startup-rebuild','recovery-maintenance')),
    constraint workshop_route_effect_runs_reason_check check(
        (kind='startup-rebuild' and reason='startup-rebuild')
        or (kind='recovery-maintenance' and reason='restore')
    ),
    constraint workshop_route_effect_runs_state_check check(state in (
        'reserved','effects_started','maintenance','restore_started',
        'succeeded','cancelled','quarantined'
    )),
    constraint workshop_route_effect_runs_request_digest_check
        check(request_digest ~ '^[0-9a-f]{64}$'),
    constraint workshop_route_effect_runs_target_check check(
        (kind='startup-rebuild' and workshop_id is null
            and target_key ~ '^startup/[0-9a-f-]{36}$'
            and control_operation_id is null
            and control_operation_attempt is null
            and control_operation_lease_owner is null)
        or
        (kind='recovery-maintenance' and workshop_id is not null
            and target_key='maintenance/'||workshop_id::text||'/'||control_operation_id::text
            and control_operation_id is not null
            and control_operation_attempt>0
            and control_operation_lease_owner is not null
            and btrim(control_operation_lease_owner)<>'')
    ),
    constraint workshop_route_effect_runs_live_shape check(
        (state in ('reserved','effects_started','restore_started')
            and instance_owner is not null and execution_token is not null
            and route_lease_token is not null and lease_expires_at is not null
            and heartbeat_at is not null and safe_error is null
            and finished_at is null
            and ((kind='startup-rebuild' and global_lease_token is not null
                  and global_fence_token>0)
                 or (kind='recovery-maintenance' and global_lease_token is null
                     and global_fence_token is null)))
        or
        (state='maintenance' and kind='recovery-maintenance'
            and instance_owner is null and execution_token is null
            and global_lease_token is null and route_lease_token is null
            and lease_expires_at is null and heartbeat_at is not null
            and global_fence_token is null and safe_error='recovery_maintenance'
            and finished_at is null)
        or
        (state in ('succeeded','cancelled','quarantined')
            and instance_owner is null and execution_token is null
            and global_lease_token is null and route_lease_token is null
            and lease_expires_at is null and finished_at is not null
            and ((state='quarantined' and safe_error is not null)
                 or (state<>'quarantined' and safe_error is null)))
    ),
    constraint workshop_route_effect_runs_response_check
        check(response is null or jsonb_typeof(response)='object'),
    constraint workshop_route_effect_runs_workshop_fkey
        foreign key(workshop_id) references control.workshops(id) on delete restrict,
    constraint workshop_route_effect_runs_operation_fkey
        foreign key(control_operation_id) references control.operations(id) on delete restrict
);

alter table control.workshop_route_projections
    add column disposition text not null default 'present',
    add column source_effect_run_id uuid,
    alter column source_operation_id drop not null,
    alter column source_operation_attempt drop not null,
    add constraint workshop_route_projections_disposition_check
        check(disposition in ('present','absent')),
    add constraint workshop_route_projections_source_effect_fkey
        foreign key(source_effect_run_id)
        references control.workshop_route_effect_runs(id) on delete restrict,
    add constraint workshop_route_projections_source_identity_check check(
        (source_operation_id is not null and source_operation_attempt>0
            and source_effect_run_id is null)
        or
        (source_operation_id is null and source_operation_attempt is null
            and source_effect_run_id is not null)
    ),
    add constraint workshop_route_projections_v2_key unique(
        workshop_id,generation,projection_digest,disposition
    );

alter table control.workshop_route_projection_state
    drop constraint workshop_route_projection_state_desired_shape,
    drop constraint workshop_route_projection_state_applied_shape,
    drop constraint workshop_route_projection_state_driver_binding_fkey,
    add column desired_disposition text,
    add column applied_disposition text,
    add column applied_effect_run_id uuid,
    add constraint workshop_route_projection_state_effect_fkey
        foreign key(applied_effect_run_id)
        references control.workshop_route_effect_runs(id) on delete restrict;

update control.workshop_route_projection_state
set desired_disposition='present'
where desired_generation is not null;
update control.workshop_route_projection_state
set applied_disposition='present'
where applied_generation is not null;

alter table control.workshop_route_projection_state
    add constraint workshop_route_projection_state_desired_shape check(
        (desired_generation is null and desired_digest is null
            and desired_disposition is null)
        or
        (desired_generation>0 and desired_digest ~ '^sha256:[0-9a-f]{64}$'
            and desired_disposition in ('present','absent'))
    ),
    add constraint workshop_route_projection_state_applied_shape check(
        (applied_generation is null and applied_digest is null
            and applied_disposition is null and applied_rendered_digest is null
            and applied_driver_operation_id is null
            and applied_effect_run_id is null and applied_fence_token is null)
        or
        (applied_generation>0 and applied_digest ~ '^sha256:[0-9a-f]{64}$'
            and applied_disposition in ('present','absent')
            and applied_rendered_digest ~ '^sha256:[0-9a-f]{64}$'
            and ((applied_driver_operation_id is not null)
                 <> (applied_effect_run_id is not null))
            and applied_fence_token>0)
    ),
    add constraint workshop_route_projection_state_desired_v2_fkey
        foreign key(workshop_id,desired_generation,desired_digest,desired_disposition)
        references control.workshop_route_projections(
            workshop_id,generation,projection_digest,disposition
        ) on delete restrict,
    add constraint workshop_route_projection_state_applied_v2_fkey
        foreign key(workshop_id,applied_generation,applied_digest,applied_disposition)
        references control.workshop_route_projections(
            workshop_id,generation,projection_digest,disposition
        ) on delete restrict;

create table control.workshop_route_effect_reservations (
    effect_run_id uuid not null,
    workshop_id uuid not null,
    generation bigint,
    projection_digest text,
    disposition text,
    baseline_generation bigint,
    baseline_projection_digest text,
    baseline_disposition text,
    route_fence_token bigint not null,
    action text not null,
    prior_lease_state text not null,
    state text not null default 'reserved',
    rendered_digest text,
    evidence jsonb,
    maintenance_rendered_digest text,
    maintenance_evidence jsonb,
    restored_rendered_digest text,
    restored_evidence jsonb,
    updated_at timestamptz not null default now(),
    primary key(effect_run_id,workshop_id),
    unique(effect_run_id,workshop_id,generation,projection_digest,route_fence_token),
    constraint workshop_route_effect_reservations_run_fkey
        foreign key(effect_run_id)
        references control.workshop_route_effect_runs(id) on delete restrict,
    constraint workshop_route_effect_reservations_projection_fkey
        foreign key(workshop_id,generation,projection_digest,disposition)
        references control.workshop_route_projections(
            workshop_id,generation,projection_digest,disposition
        ) on delete restrict,
    constraint workshop_route_effect_reservations_baseline_fkey
        foreign key(workshop_id,baseline_generation,baseline_projection_digest,
            baseline_disposition)
        references control.workshop_route_projections(
            workshop_id,generation,projection_digest,disposition
        ) on delete restrict,
    constraint workshop_route_effect_reservations_action_check
        check(action in ('render','remove-absent','remove-uninitialized','maintenance')),
    constraint workshop_route_effect_reservations_prior_check
        check(prior_lease_state in ('idle','uninitialized')),
    constraint workshop_route_effect_reservations_state_check
        check(state in ('reserved','candidate','maintenance','restored','succeeded','quarantined')),
    constraint workshop_route_effect_reservations_projection_shape check(
        (action='remove-uninitialized' and generation is null
            and projection_digest is null and disposition is null)
        or
        (action<>'remove-uninitialized' and generation>0
            and projection_digest ~ '^sha256:[0-9a-f]{64}$'
            and disposition in ('present','absent'))
    ),
    constraint workshop_route_effect_reservations_baseline_shape check(
        (baseline_generation is null
            and baseline_projection_digest is null and baseline_disposition is null)
        or
        (baseline_generation>0
            and baseline_projection_digest ~ '^sha256:[0-9a-f]{64}$'
            and baseline_disposition='present')
    ),
    constraint workshop_route_effect_reservations_rendered_check
        check(rendered_digest is null
              or rendered_digest ~ '^sha256:[0-9a-f]{64}$'),
    constraint workshop_route_effect_reservations_maintenance_digest_check
        check(maintenance_rendered_digest is null
              or maintenance_rendered_digest ~ '^sha256:[0-9a-f]{64}$'),
    constraint workshop_route_effect_reservations_restored_digest_check
        check(restored_rendered_digest is null
              or restored_rendered_digest ~ '^sha256:[0-9a-f]{64}$'),
    constraint workshop_route_effect_reservations_fence_check
        check(route_fence_token>0),
    constraint workshop_route_effect_reservations_evidence_check
        check((evidence is null or jsonb_typeof(evidence)='object')
          and (maintenance_evidence is null
               or jsonb_typeof(maintenance_evidence)='object')
          and (restored_evidence is null
               or jsonb_typeof(restored_evidence)='object'))
);

alter table control.workshop_route_projection_state
    add constraint workshop_route_projection_state_effect_binding_fkey
        foreign key(
            applied_effect_run_id,workshop_id,applied_generation,
            applied_digest,applied_fence_token
        ) references control.workshop_route_effect_reservations(
            effect_run_id,workshop_id,generation,projection_digest,route_fence_token
        ) on delete restrict;

alter table control.deployment_driver_resource_leases
    drop constraint deployment_driver_resource_leases_shape_check,
    add column authority_kind text,
    add column effect_run_id uuid,
    add constraint deployment_driver_resource_leases_effect_fkey
        foreign key(effect_run_id)
        references control.workshop_route_effect_runs(id) on delete restrict;

update control.deployment_driver_resource_leases
set authority_kind='release'
where driver_operation_id is not null;

alter table control.deployment_driver_resource_leases
    add constraint deployment_driver_resource_leases_authority_check
        check(authority_kind is null or authority_kind in ('release','startup-rebuild')),
    add constraint deployment_driver_resource_leases_shape_v2_check check(
        (state='idle' and authority_kind is null and driver_operation_id is null
            and effect_run_id is null and lease_owner is null and lease_token is null
            and lease_expires_at is null and heartbeat_at is null
            and quarantined_at is null and safe_error is null)
        or
        (state='held' and authority_kind is not null
            and ((authority_kind='release' and driver_operation_id is not null
                  and effect_run_id is null)
                 or (authority_kind='startup-rebuild' and driver_operation_id is null
                     and effect_run_id is not null))
            and lease_owner is not null and lease_token is not null
            and lease_expires_at is not null and heartbeat_at is not null
            and quarantined_at is null and safe_error is null and fence_token>0)
        or
        (state='quarantined' and authority_kind is not null
            and ((authority_kind='release' and driver_operation_id is not null
                  and effect_run_id is null)
                 or (authority_kind='startup-rebuild' and driver_operation_id is null
                     and effect_run_id is not null))
            and lease_owner is not null and lease_token is null
            and lease_expires_at is null and heartbeat_at is not null
            and quarantined_at is not null and safe_error='runtime_outcome_unknown'
            and fence_token>0)
    );

alter table control.workshop_route_application_leases
    drop constraint workshop_route_application_leases_shape_check,
    add column authority_kind text,
    add column effect_run_id uuid,
    add constraint workshop_route_application_leases_effect_fkey
        foreign key(effect_run_id)
        references control.workshop_route_effect_runs(id) on delete restrict;

update control.workshop_route_application_leases
set authority_kind=case
    when driver_operation_id is null then null
    when generation is null then 'legacy'
    else 'projection' end;

alter table control.workshop_route_application_leases
    drop constraint workshop_route_application_leases_state_check,
    add constraint workshop_route_application_leases_state_check
        check(state in ('uninitialized','idle','held','maintenance','quarantined')),
    add constraint workshop_route_application_leases_authority_check
        check(authority_kind is null or authority_kind in (
            'projection','startup-rebuild','recovery-maintenance','legacy'
        )),
    add constraint workshop_route_application_leases_shape_v2_check check(
        (state in ('uninitialized','idle') and authority_kind is null
            and driver_operation_id is null and effect_run_id is null
            and generation is null and projection_digest is null
            and lease_owner is null and lease_token is null
            and lease_expires_at is null and heartbeat_at is null
            and quarantined_at is null and safe_error is null
            and ((state='uninitialized' and initialization_required)
                 or (state='idle' and not initialization_required)))
        or
        (state='held' and authority_kind in (
                'projection','startup-rebuild','recovery-maintenance'
            ) and ((authority_kind='projection' and driver_operation_id is not null
                    and effect_run_id is null)
                   or (authority_kind<>'projection' and driver_operation_id is null
                       and effect_run_id is not null))
            and lease_owner is not null and lease_token is not null
            and lease_expires_at is not null and heartbeat_at is not null
            and quarantined_at is null and safe_error is null and fence_token>0
            and ((authority_kind='startup-rebuild' and generation is null
                    and projection_digest is null)
                 or (generation>0
                    and projection_digest ~ '^sha256:[0-9a-f]{64}$')))
        or
        (state='maintenance' and authority_kind='recovery-maintenance'
            and driver_operation_id is null and effect_run_id is not null
            and generation>0 and projection_digest ~ '^sha256:[0-9a-f]{64}$'
            and lease_owner is null and lease_token is null
            and lease_expires_at is null and heartbeat_at is not null
            and quarantined_at is null and safe_error='recovery_maintenance'
            and fence_token>0)
        or
        (state='quarantined' and authority_kind is not null
            and ((authority_kind in ('projection','legacy')
                    and driver_operation_id is not null and effect_run_id is null)
                 or (authority_kind in ('startup-rebuild','recovery-maintenance')
                    and driver_operation_id is null and effect_run_id is not null))
            and lease_owner is not null and lease_token is null
            and lease_expires_at is null and heartbeat_at is not null
            and quarantined_at is not null and safe_error in (
                'runtime_outcome_unknown','legacy_route_outcome_unknown',
                'legacy_maintenance_outcome_unknown'
            ) and fence_token>0)
    );

-- Preserve the 0010/0012 function contracts while their Rust callers migrate
-- to explicit polymorphic ownership. These triggers only normalize ownership;
-- they never manufacture a fence or relax a state transition.
create or replace function control.normalize_global_route_authority()
returns trigger language plpgsql security definer
set search_path=pg_catalog, control
as $function$
begin
    if new.state='idle' then
        new.authority_kind:=null;
        new.effect_run_id:=null;
    elsif new.driver_operation_id is not null and new.effect_run_id is null
          and new.authority_kind is null then
        new.authority_kind:='release';
    end if;
    return new;
end
$function$;
create trigger deployment_driver_resource_authority_normalize
before insert or update on control.deployment_driver_resource_leases
for each row execute function control.normalize_global_route_authority();

create or replace function control.normalize_workshop_route_authority()
returns trigger language plpgsql security definer
set search_path=pg_catalog, control
as $function$
begin
    if old.state='maintenance' and new.state='held'
       and (new.authority_kind is distinct from 'recovery-maintenance'
            or new.effect_run_id is distinct from old.effect_run_id) then
        raise exception 'stable maintenance authority cannot be stolen'
            using errcode='55000';
    end if;
    if new.state in ('idle','uninitialized') then
        new.authority_kind:=null;
        new.effect_run_id:=null;
    elsif new.driver_operation_id is not null and new.effect_run_id is null
          and new.authority_kind is null then
        new.authority_kind:=case when new.generation is null
            then 'legacy' else 'projection' end;
    end if;
    return new;
end
$function$;
create trigger workshop_route_authority_normalize
before insert or update on control.workshop_route_application_leases
for each row execute function control.normalize_workshop_route_authority();

create or replace function control.normalize_workshop_route_projection_state()
returns trigger language plpgsql security definer
set search_path=pg_catalog, control
as $function$
begin
    if new.desired_generation is null then
        new.desired_disposition:=null;
    elsif new.desired_disposition is null
          or new.desired_generation is distinct from old.desired_generation
          or new.desired_digest is distinct from old.desired_digest then
        select disposition into strict new.desired_disposition
        from control.workshop_route_projections
        where workshop_id=new.workshop_id and generation=new.desired_generation
          and projection_digest=new.desired_digest;
    end if;
    if new.applied_generation is null then
        new.applied_disposition:=null;
        new.applied_effect_run_id:=null;
    elsif new.applied_disposition is null
          or new.applied_generation is distinct from old.applied_generation
          or new.applied_digest is distinct from old.applied_digest then
        select disposition into strict new.applied_disposition
        from control.workshop_route_projections
        where workshop_id=new.workshop_id and generation=new.applied_generation
          and projection_digest=new.applied_digest;
    end if;
    if new.applied_driver_operation_id is not null then
        new.applied_effect_run_id:=null;
    end if;
    return new;
end
$function$;
create trigger workshop_route_projection_state_normalize
before insert or update on control.workshop_route_projection_state
for each row execute function control.normalize_workshop_route_projection_state();

create or replace function control.lock_workshop_route_projection(
    p_control_operation_id uuid,p_control_operation_attempt integer,
    p_control_operation_lease_owner text,p_workshop_id uuid
) returns bigint
language plpgsql security definer set search_path=pg_catalog, control
as $function$
declare v_generation bigint; v_global_state text; v_route_state text;
begin
    perform 1 from control.operations operation
    where operation.id=p_control_operation_id
      and operation.workshop_id=p_workshop_id
      and ((operation.kind='tenant.provision' and operation.queue='tenant-provisioning')
        or (operation.kind in ('tenant.reconcile','module.enable','module.restrict',
              'webshop-domain.reconcile') and operation.queue='tenant-reconciliation')
        or (operation.kind='tenant.lifecycle' and operation.queue='tenant-lifecycle'))
      and operation.state='in_flight' and operation.attempt=p_control_operation_attempt
      and operation.leased_by=p_control_operation_lease_owner
      and operation.lease_expires_at>now() for update;
    if not found then raise exception 'route source operation lease is not current'
        using errcode='55000'; end if;
    select state into strict v_global_state
    from control.deployment_driver_resource_leases
    where resource_key='runtime/shared-odoo' for update;
    if v_global_state<>'idle' then
        raise exception 'global route authority is not idle' using errcode='55000';
    end if;
    select state into strict v_route_state
    from control.workshop_route_application_leases
    where workshop_id=p_workshop_id for update;
    if v_route_state not in ('idle','uninitialized','maintenance') then
        raise exception 'workshop route authority is not source-mutable'
            using errcode='55000';
    end if;
    select desired_generation into v_generation
    from control.workshop_route_projection_state
    where workshop_id=p_workshop_id for update;
    return coalesce(v_generation,0);
end
$function$;

alter function control.materialize_workshop_route_projection(
    uuid,integer,text,uuid,jsonb,text
) rename to materialize_workshop_route_projection_v1;

create or replace function control.materialize_workshop_route_projection(
    p_control_operation_id uuid,p_control_operation_attempt integer,
    p_control_operation_lease_owner text,p_workshop_id uuid,
    p_projection jsonb,p_projection_digest text
) returns table(outcome text,generation bigint,projection_digest text,projection jsonb)
language plpgsql security definer set search_path=pg_catalog, control
as $function$
begin
    perform control.lock_workshop_route_projection(
        p_control_operation_id,p_control_operation_attempt,
        p_control_operation_lease_owner,p_workshop_id
    );
    return query select materialized.outcome,materialized.generation,
        materialized.projection_digest,materialized.projection
    from control.materialize_workshop_route_projection_v1(
        p_control_operation_id,p_control_operation_attempt,
        p_control_operation_lease_owner,p_workshop_id,p_projection,p_projection_digest
    ) materialized;
end
$function$;

-- Keep the public 0012 signatures stable while teaching their admissions the
-- new durable maintenance state. The renamed implementations retain all old
-- replay and evidence behavior.
alter function control.admit_workshop_route_application(
    uuid,integer,text,uuid,text,text,text,bigint,text,uuid,uuid,uuid,integer
) rename to admit_workshop_route_application_v1;

create or replace function control.admit_workshop_route_application(
    p_control_operation_id uuid,p_control_operation_attempt integer,
    p_control_operation_lease_owner text,p_workshop_id uuid,p_action text,
    p_idempotency_key text,p_request_digest text,p_generation bigint,
    p_projection_digest text,p_instance_owner uuid,p_execution_token uuid,
    p_route_lease_token uuid,p_ttl_seconds integer
) returns table(outcome text,driver_operation_id uuid,fence_token bigint,stored_response jsonb)
language plpgsql security definer set search_path=pg_catalog, control
as $function$
declare v_lease control.workshop_route_application_leases%rowtype;
    v_row record; v_disposition text;
begin
    perform 1 from control.operations operation
    where operation.id=p_control_operation_id
      and operation.workshop_id=p_workshop_id
      and ((operation.kind='tenant.provision' and operation.queue='tenant-provisioning')
        or (operation.kind in ('tenant.reconcile','module.enable','module.restrict',
              'webshop-domain.reconcile') and operation.queue='tenant-reconciliation')
        or (operation.kind='tenant.lifecycle' and operation.queue='tenant-lifecycle'))
      and operation.state='in_flight' and operation.attempt=p_control_operation_attempt
      and operation.leased_by=p_control_operation_lease_owner
      and operation.lease_expires_at>now() for update;
    if not found then return query select 'upstream_lease_lost',null::uuid,
        null::bigint,null::jsonb; return; end if;
    perform 1 from control.deployment_driver_resource_leases
    where resource_key='runtime/shared-odoo' for update;
    select * into strict v_lease from control.workshop_route_application_leases
    where workshop_id=p_workshop_id for update;
    if v_lease.state='maintenance' then
        return query select 'busy',v_lease.effect_run_id,v_lease.fence_token,null::jsonb;
        return;
    end if;
    select * into strict v_row
    from control.admit_workshop_route_application_v1(
        p_control_operation_id,p_control_operation_attempt,
        p_control_operation_lease_owner,p_workshop_id,p_action,p_idempotency_key,
        p_request_digest,p_generation,p_projection_digest,p_instance_owner,
        p_execution_token,p_route_lease_token,p_ttl_seconds
    );
    if jsonb_typeof(v_row.stored_response->'route_evidence')='object'
       and not (v_row.stored_response->'route_evidence' ? 'disposition') then
        select projection.disposition into v_disposition
        from control.workshop_route_projections projection
        where projection.workshop_id=p_workshop_id
          and projection.generation::text=
              v_row.stored_response->'route_evidence'->>'route_generation'
          and projection.projection_digest=
              v_row.stored_response->'route_evidence'->>'projection_digest';
        if found then
            v_row.stored_response:=jsonb_set(
                v_row.stored_response,'{route_evidence,disposition}',
                to_jsonb(v_disposition),true
            );
        end if;
    end if;
    return query select v_row.outcome,v_row.driver_operation_id,
        v_row.fence_token,v_row.stored_response;
end
$function$;

alter function control.admit_release_driver_operation(
    uuid,integer,text,text,text,uuid,text,uuid,uuid,uuid,integer
) rename to admit_release_driver_operation_v1;

create or replace function control.admit_release_driver_operation(
    p_control_operation_id uuid,p_control_operation_attempt integer,
    p_control_operation_lease_owner text,p_idempotency_key text,p_target_key text,
    p_fleet_run_id uuid,p_request_digest text,p_instance_owner uuid,
    p_execution_token uuid,p_resource_lease_token uuid,p_ttl_seconds integer
) returns table(outcome text,driver_operation_id uuid,fence_token bigint,
    stored_response jsonb,reserved_workshops uuid[])
language plpgsql security definer set search_path=pg_catalog, control
as $function$
declare v_row record;
begin
    select * into strict v_row from control.admit_release_driver_operation_v1(
        p_control_operation_id,p_control_operation_attempt,
        p_control_operation_lease_owner,p_idempotency_key,p_target_key,p_fleet_run_id,
        p_request_digest,p_instance_owner,p_execution_token,p_resource_lease_token,
        p_ttl_seconds
    );
    if v_row.outcome='route_uninitialized' and exists(
        select 1 from control.workshop_route_application_leases
        where state='maintenance'
    ) then
        v_row.outcome:='route_busy';
    end if;
    return query select v_row.outcome,v_row.driver_operation_id,v_row.fence_token,
        v_row.stored_response,v_row.reserved_workshops;
end
$function$;

-- Bind every normal route receipt to the immutable projection disposition.
-- The 0012 implementation remains the state-transition primitive; this
-- wrapper verifies the additional evidence field and delegates the original
-- six-field receipt only after that exact check succeeds. A six-field receipt
-- remains valid only for a pre-0013 in-flight `present` projection; old code
-- cannot request or acknowledge an `absent` projection.
alter function control.finish_workshop_route_application(
    uuid,uuid,uuid,uuid,bigint,text,jsonb,text,text
) rename to finish_workshop_route_application_v1;

create or replace function control.finish_workshop_route_application(
    p_driver_operation_id uuid,p_instance_owner uuid,p_execution_token uuid,
    p_route_lease_token uuid,p_fence_token bigint,p_outcome text,
    p_response jsonb,p_rendered_digest text,p_safe_error text
) returns boolean
language plpgsql security definer set search_path=pg_catalog, control
as $function$
declare v_disposition text; v_evidence_keys integer; v_legacy_response jsonb;
    v_finished boolean; v_changed bigint;
begin
    if p_outcome='succeeded' then
        if jsonb_typeof(p_response) is distinct from 'object'
           or jsonb_typeof(p_response->'route_evidence') is distinct from 'object' then
            return false;
        end if;
        select projection.disposition into v_disposition
        from control.workshop_route_application_leases lease
        join control.workshop_route_projections projection
          on projection.workshop_id=lease.workshop_id
         and projection.generation=lease.generation
         and projection.projection_digest=lease.projection_digest
        where lease.driver_operation_id=p_driver_operation_id
          and lease.state='held' for update of lease;
        if not found then return false; end if;
        select count(*) into v_evidence_keys
        from jsonb_object_keys(p_response->'route_evidence');
        if not (
            (v_evidence_keys=7 and
             p_response->'route_evidence'->>'disposition' is not distinct from v_disposition)
            or (v_evidence_keys=6 and v_disposition='present')
        ) then
            return false;
        end if;
        v_legacy_response:=case when v_evidence_keys=7 then jsonb_set(
                p_response,'{route_evidence}',
                (p_response->'route_evidence')-'disposition'
            ) else p_response end;
    else
        v_legacy_response:=p_response;
    end if;
    v_finished:=control.finish_workshop_route_application_v1(
        p_driver_operation_id,p_instance_owner,p_execution_token,
        p_route_lease_token,p_fence_token,p_outcome,v_legacy_response,
        p_rendered_digest,p_safe_error
    );
    if v_finished and p_outcome='succeeded' and v_evidence_keys=7 then
        update control.deployment_driver_operations
        set response=p_response,updated_at=now()
        where id=p_driver_operation_id and state='succeeded';
        get diagnostics v_changed=row_count;
        if v_changed<>1 then
            raise exception 'route disposition receipt persistence was lost'
                using errcode='40001';
        end if;
    end if;
    return v_finished;
end
$function$;

-- Existing ambiguous lifecycle route effects that started after 0012 cannot be
-- adopted from PostgreSQL. Quarantine an otherwise idle workshop; more than
-- one such writer is a migration-time reconciliation error.
do $migration$
begin
    if exists(
        select 1 from control.deployment_driver_operations operation
        join control.workshop_route_application_leases lease
          on lease.workshop_id=operation.workshop_id and lease.state='idle'
        where operation.action in ('lifecycle','resume')
          and operation.state='in_progress'
        group by operation.workshop_id having count(*)>1
    ) then
        raise exception 'multiple legacy maintenance effects require reconciliation';
    end if;
    update control.deployment_driver_operations operation
    set safe_error='runtime_outcome_unknown',updated_at=now()
    where operation.action in ('lifecycle','resume') and operation.state='in_progress'
      and exists(select 1 from control.workshop_route_application_leases lease
                 where lease.workshop_id=operation.workshop_id and lease.state='idle');
    update control.workshop_route_application_leases lease
    set state='quarantined',authority_kind='legacy',fence_token=fence_token+1,
        driver_operation_id=operation.id,lease_owner=
            '00000000-0000-0000-0000-000000000000'::uuid,
        heartbeat_at=now(),quarantined_at=now(),
        safe_error='legacy_maintenance_outcome_unknown',updated_at=now()
    from control.deployment_driver_operations operation
    where operation.workshop_id=lease.workshop_id
      and operation.action in ('lifecycle','resume')
      and operation.state='in_progress' and lease.state='idle';
end
$migration$;

create or replace function control.admit_startup_route_rebuild(
    p_boot_id uuid,
    p_idempotency_key text,
    p_request_digest text,
    p_instance_owner uuid,
    p_execution_token uuid,
    p_global_lease_token uuid,
    p_route_lease_token uuid,
    p_ttl_seconds integer
) returns table(
    outcome text,effect_run_id uuid,global_fence_token bigint,
    reserved_count integer,stored_response jsonb
)
language plpgsql security definer
set search_path=pg_catalog, control
as $function$
declare
    v_global control.deployment_driver_resource_leases%rowtype;
    v_run control.workshop_route_effect_runs%rowtype;
    v_route control.workshop_route_application_leases%rowtype;
    v_run_id uuid;
    v_fence bigint;
    v_count integer;
begin
    if p_boot_id is null or p_idempotency_key is null
       or btrim(p_idempotency_key)='' or length(p_idempotency_key)>180
       or p_request_digest !~ '^[0-9a-f]{64}$'
       or p_instance_owner is null or p_execution_token is null
       or p_global_lease_token is null or p_route_lease_token is null
       or p_ttl_seconds<60 or p_ttl_seconds>1200 then
        return query select 'invalid',null::uuid,null::bigint,null::integer,null::jsonb;
        return;
    end if;
    select * into strict v_global from control.deployment_driver_resource_leases
    where resource_key='runtime/shared-odoo' for update;
    perform 1 from control.workshop_route_application_leases
    order by workshop_id for update;

    if v_global.state='held' and v_global.lease_expires_at<=now() then
        if v_global.authority_kind='release' then
            update control.deployment_driver_operations set
                safe_error='runtime_outcome_unknown',execution_token=null,
                lease_expires_at=null,updated_at=now()
            where id=v_global.driver_operation_id and state='in_progress';
        else
            update control.workshop_route_effect_runs set state='quarantined',
                instance_owner=null,execution_token=null,global_lease_token=null,
                route_lease_token=null,lease_expires_at=null,
                safe_error='runtime_outcome_unknown',finished_at=now(),updated_at=now()
            where id=v_global.effect_run_id;
        end if;
        update control.deployment_driver_resource_leases set state='quarantined',
            lease_token=null,lease_expires_at=null,quarantined_at=now(),
            safe_error='runtime_outcome_unknown',updated_at=now()
        where resource_key='runtime/shared-odoo';
        return query select 'quarantined',coalesce(v_global.effect_run_id,
            v_global.driver_operation_id),v_global.fence_token,null::integer,null::jsonb;
        return;
    end if;
    if v_global.state='quarantined' then
        return query select 'quarantined',coalesce(v_global.effect_run_id,
            v_global.driver_operation_id),v_global.fence_token,null::integer,null::jsonb;
        return;
    end if;

    select * into v_run from control.workshop_route_effect_runs
    where kind='startup-rebuild' and (
        idempotency_key=p_idempotency_key or target_key='startup/'||p_boot_id::text
    ) order by (idempotency_key=p_idempotency_key) desc limit 1 for update;
    if found then
        select count(*) into v_count from control.workshop_route_effect_reservations
        where effect_run_id=v_run.id;
        if v_run.request_digest<>p_request_digest
           or v_run.target_key<>'startup/'||p_boot_id::text then
            return query select 'digest_conflict',v_run.id,v_run.global_fence_token,
                v_count,null::jsonb;
        elsif v_run.state='succeeded' then
            return query select 'replay',v_run.id,v_run.global_fence_token,
                v_count,v_run.response;
        elsif v_run.state='quarantined' then
            return query select 'quarantined',v_run.id,v_run.global_fence_token,
                v_count,null::jsonb;
        else
            return query select 'busy',v_run.id,v_run.global_fence_token,
                v_count,null::jsonb;
        end if;
        return;
    end if;
    if v_global.state='held' then
        return query select 'busy',coalesce(v_global.effect_run_id,
            v_global.driver_operation_id),v_global.fence_token,null::integer,null::jsonb;
        return;
    end if;

    -- Expiry is unknown even if the last observed database phase was early.
    select * into v_route from control.workshop_route_application_leases
    where state='held' and lease_expires_at<=now()
    order by workshop_id limit 1;
    if found then
        if v_route.authority_kind='projection' then
            update control.deployment_driver_operations set
                safe_error='runtime_outcome_unknown',execution_token=null,
                lease_expires_at=null,updated_at=now()
            where id=v_route.driver_operation_id and state='in_progress';
        else
            update control.workshop_route_effect_runs set state='quarantined',
                instance_owner=null,execution_token=null,global_lease_token=null,
                route_lease_token=null,lease_expires_at=null,
                safe_error='runtime_outcome_unknown',finished_at=now(),updated_at=now()
            where id=v_route.effect_run_id;
        end if;
        update control.workshop_route_application_leases set state='quarantined',
            lease_token=null,lease_expires_at=null,quarantined_at=now(),
            safe_error='runtime_outcome_unknown',updated_at=now()
        where workshop_id=v_route.workshop_id;
        return query select 'route_quarantined',coalesce(v_route.effect_run_id,
            v_route.driver_operation_id),v_global.fence_token,null::integer,null::jsonb;
        return;
    end if;
    select * into v_route from control.workshop_route_application_leases
    where state not in ('idle','uninitialized') order by workshop_id limit 1;
    if found then
        return query select case when v_route.state='quarantined'
            then 'route_quarantined' else 'route_busy' end,
            coalesce(v_route.effect_run_id,v_route.driver_operation_id),
            v_global.fence_token,null::integer,null::jsonb;
        return;
    end if;

    v_fence:=v_global.fence_token+1;
    insert into control.workshop_route_effect_runs(
        kind,reason,target_key,idempotency_key,request_digest,state,instance_owner,
        execution_token,global_lease_token,route_lease_token,lease_expires_at,
        heartbeat_at,global_fence_token
    ) values (
        'startup-rebuild','startup-rebuild','startup/'||p_boot_id::text,p_idempotency_key,
        p_request_digest,'reserved',p_instance_owner,p_execution_token,
        p_global_lease_token,p_route_lease_token,
        now()+make_interval(secs=>p_ttl_seconds),now(),v_fence
    ) returning id into v_run_id;

    insert into control.workshop_route_effect_reservations(
        effect_run_id,workshop_id,generation,projection_digest,disposition,
        route_fence_token,action,prior_lease_state
    )
    select v_run_id,lease.workshop_id,state.desired_generation,state.desired_digest,
        state.desired_disposition,lease.fence_token+1,
        case when state.desired_generation is null then 'remove-uninitialized'
             when state.desired_disposition='absent' then 'remove-absent'
             else 'render' end,
        lease.state
    from control.workshop_route_application_leases lease
    join control.workshop_route_projection_state state
      on state.workshop_id=lease.workshop_id
    order by lease.workshop_id;
    get diagnostics v_count=row_count;

    update control.workshop_route_application_leases lease
    set state='held',authority_kind='startup-rebuild',effect_run_id=v_run_id,
        driver_operation_id=null,generation=reservation.generation,
        projection_digest=reservation.projection_digest,
        fence_token=reservation.route_fence_token,lease_owner=p_instance_owner,
        lease_token=p_route_lease_token,
        lease_expires_at=now()+make_interval(secs=>p_ttl_seconds),
        heartbeat_at=now(),updated_at=now()
    from control.workshop_route_effect_reservations reservation
    where reservation.effect_run_id=v_run_id
      and reservation.workshop_id=lease.workshop_id;
    update control.deployment_driver_resource_leases set state='held',
        authority_kind='startup-rebuild',effect_run_id=v_run_id,
        driver_operation_id=null,fence_token=v_fence,lease_owner=p_instance_owner,
        lease_token=p_global_lease_token,
        lease_expires_at=now()+make_interval(secs=>p_ttl_seconds),
        heartbeat_at=now(),updated_at=now()
    where resource_key='runtime/shared-odoo';
    return query select 'acquired',v_run_id,v_fence,v_count,null::jsonb;
end
$function$;

create or replace function control.read_startup_route_rebuild_batch(
    p_effect_run_id uuid,p_instance_owner uuid,p_execution_token uuid,
    p_global_lease_token uuid,p_global_fence_token bigint,
    p_after_workshop uuid,p_limit integer
) returns table(
    workshop_id uuid,generation bigint,projection_digest text,
    disposition text,action text,route_fence_token bigint,projection jsonb
)
language sql security definer
set search_path=pg_catalog, control
as $function$
    select reservation.workshop_id,reservation.generation,
        reservation.projection_digest,reservation.disposition,
        reservation.action,reservation.route_fence_token,projection.projection
    from control.workshop_route_effect_runs run
    join control.workshop_route_effect_reservations reservation
      on reservation.effect_run_id=run.id
    left join control.workshop_route_projections projection
      on projection.workshop_id=reservation.workshop_id
     and projection.generation=reservation.generation
     and projection.projection_digest=reservation.projection_digest
    where run.id=p_effect_run_id and run.kind='startup-rebuild'
      and run.state in ('reserved','effects_started')
      and run.instance_owner=p_instance_owner
      and run.execution_token=p_execution_token
      and run.global_lease_token=p_global_lease_token
      and run.global_fence_token=p_global_fence_token
      and run.lease_expires_at>now()
      and (p_after_workshop is null or reservation.workshop_id>p_after_workshop)
      and p_limit between 1 and 500
    order by reservation.workshop_id limit p_limit
$function$;

-- Initialize only an uninitialized reservation, and only from an exact SQL
-- reconstruction of authoritative source rows. The digest is caller-computed
-- JCS SHA-256; PostgreSQL deliberately never hashes jsonb::text.
create or replace function control.initialize_startup_route_projection(
    p_effect_run_id uuid,p_instance_owner uuid,p_execution_token uuid,
    p_global_lease_token uuid,p_route_lease_token uuid,
    p_global_fence_token bigint,p_workshop_id uuid,
    p_tenant_domain text,p_disposition text,p_projection jsonb,p_projection_digest text
) returns table(outcome text,generation bigint)
language plpgsql security definer
set search_path=pg_catalog, control
as $function$
declare
    v_run control.workshop_route_effect_runs%rowtype;
    v_state control.workshop_route_projection_state%rowtype;
    v_reservation control.workshop_route_effect_reservations%rowtype;
    v_source jsonb;
    v_database_count integer;
    v_generation bigint;
begin
    if p_disposition not in ('present','absent')
       or p_tenant_domain is null
       or p_tenant_domain !~ '^[a-z0-9][a-z0-9.-]{1,251}[a-z0-9]$'
       or p_tenant_domain ~ '\.\.'
       or p_projection_digest !~ '^sha256:[0-9a-f]{64}$'
       or jsonb_typeof(p_projection)<>'object' then
        return query select 'invalid',null::bigint; return;
    end if;
    select * into v_run from control.workshop_route_effect_runs
    where id=p_effect_run_id and kind='startup-rebuild' and state='reserved'
      and instance_owner=p_instance_owner and execution_token=p_execution_token
      and global_lease_token=p_global_lease_token
      and route_lease_token=p_route_lease_token
      and global_fence_token=p_global_fence_token and lease_expires_at>now()
    for update;
    if not found then return query select 'authority_lost',null::bigint; return; end if;
    select * into strict v_reservation from control.workshop_route_effect_reservations
    where effect_run_id=p_effect_run_id and workshop_id=p_workshop_id for update;
    if v_reservation.action<>'remove-uninitialized' then
        return query select 'already_initialized',v_reservation.generation; return;
    end if;
    select * into strict v_state from control.workshop_route_projection_state
    where workshop_id=p_workshop_id for update;
    if v_state.desired_generation is not null then
        return query select 'source_changed',null::bigint; return;
    end if;

    select count(*) into v_database_count
    from control.workshops workshop
    join control.odoo_databases database on database.workshop_id=workshop.id
    where workshop.id=p_workshop_id
      and database.kind='primary'
      and database.deleted_at is null
      and database.public_hostname is not null;
    if v_database_count=1 then
        select jsonb_build_object(
            'database_id',to_jsonb(database.id::text),
            'database_ref',to_jsonb(database.database_ref),
            'public_hostname',to_jsonb(database.public_hostname),
            'paperless_mode',to_jsonb(coalesce(paperless.mode,'absent')),
            'paperless_hostname',case when coalesce(paperless.mode,'absent')='absent'
                then 'null'::jsonb
                else to_jsonb('docs-'||workshop.slug||'.'||p_tenant_domain) end,
            'custom_hostnames',coalesce((select jsonb_agg(jsonb_build_object(
                    'hostname',domain.hostname,'canonical',domain.canonical)
                    order by domain.hostname)
                from control.webshop_domains domain
                where domain.workshop_id=workshop.id
                  and domain.state in ('testing','active')
                  and domain.desired_state='active'),'[]'::jsonb)
        ) into v_source
        from control.workshops workshop
        join control.odoo_databases database on database.workshop_id=workshop.id
        left join lateral (
            select case
                when module.state in ('installing','enabled') then 'read_write'
                when module.state in ('restricting','restricted') then 'read_only'
                else 'absent' end as mode
            from control.workshop_modules module
            join control.service_instances service
              on service.workshop_id=module.workshop_id
             and service.service='paperless' and service.health='ready'
            where module.workshop_id=workshop.id and module.module_key='documents'
            order by module.module_key limit 1
        ) paperless on true
        where workshop.id=p_workshop_id
          and database.kind='primary'
          and database.deleted_at is null
          and database.public_hostname is not null;
        if p_disposition<>'present' or p_projection is distinct from v_source then
            return query select 'source_mismatch',null::bigint; return;
        end if;
    elsif v_database_count=0 then
        v_source:=jsonb_build_object(
            'database_id',null,'database_ref',null,'public_hostname',null,
            'paperless_mode','absent','paperless_hostname',null,
            'custom_hostnames','[]'::jsonb
        );
        if p_disposition<>'absent' or p_projection is distinct from v_source then
            return query select 'source_mismatch',null::bigint; return;
        end if;
    else
        return query select 'source_ambiguous',null::bigint; return;
    end if;

    v_generation:=1;
    insert into control.workshop_route_projections(
        workshop_id,generation,projection_digest,projection,disposition,
        source_operation_id,source_operation_attempt,source_effect_run_id
    ) values(p_workshop_id,v_generation,p_projection_digest,p_projection,
        p_disposition,null,null,p_effect_run_id);
    update control.workshop_route_projection_state set
        desired_generation=v_generation,desired_digest=p_projection_digest,
        desired_disposition=p_disposition,updated_at=now()
    where workshop_id=p_workshop_id;
    update control.workshop_route_effect_reservations set
        generation=v_generation,projection_digest=p_projection_digest,
        disposition=p_disposition,
        action=case when p_disposition='present' then 'render' else 'remove-absent' end,
        updated_at=now()
    where effect_run_id=p_effect_run_id and workshop_id=p_workshop_id;
    update control.workshop_route_application_leases set
        generation=v_generation,projection_digest=p_projection_digest,updated_at=now()
    where workshop_id=p_workshop_id and effect_run_id=p_effect_run_id
      and authority_kind='startup-rebuild' and lease_token=p_route_lease_token;
    return query select 'initialized',v_generation;
end
$function$;

create or replace function control.materialize_workshop_route_tombstone(
    p_control_operation_id uuid,p_control_operation_attempt integer,
    p_control_operation_lease_owner text,p_workshop_id uuid,
    p_projection jsonb,p_projection_digest text
) returns table(outcome text,generation bigint,projection_digest text,projection jsonb)
language plpgsql security definer set search_path=pg_catalog, control
as $function$
declare v_state control.workshop_route_projection_state%rowtype;
    v_generation bigint;
    v_tombstone jsonb:=jsonb_build_object(
        'database_id',null,'database_ref',null,'public_hostname',null,
        'paperless_mode','absent','paperless_hostname',null,
        'custom_hostnames','[]'::jsonb
    );
begin
    perform control.lock_workshop_route_projection(
        p_control_operation_id,p_control_operation_attempt,
        p_control_operation_lease_owner,p_workshop_id
    );
    perform 1 from control.operations
    where id=p_control_operation_id and kind='tenant.lifecycle'
      and queue='tenant-lifecycle';
    if not found then return query select 'invalid',null::bigint,
        null::text,null::jsonb; return; end if;
    if p_projection_digest !~ '^sha256:[0-9a-f]{64}$'
       or p_projection is distinct from v_tombstone then
        return query select 'invalid',null::bigint,null::text,null::jsonb; return;
    end if;
    select * into strict v_state from control.workshop_route_projection_state
    where workshop_id=p_workshop_id for update;
    if v_state.desired_disposition='absent' then
        if v_state.desired_digest=p_projection_digest then
            return query select 'reused',v_state.desired_generation,
                p_projection_digest,v_tombstone; return;
        end if;
        return query select 'digest_conflict',null::bigint,null::text,null::jsonb; return;
    end if;
    v_generation:=coalesce(v_state.desired_generation,0)+1;
    insert into control.workshop_route_projections(
        workshop_id,generation,projection_digest,projection,disposition,
        source_operation_id,source_operation_attempt
    ) values(p_workshop_id,v_generation,p_projection_digest,v_tombstone,'absent',
        p_control_operation_id,p_control_operation_attempt);
    update control.workshop_route_projection_state set
        desired_generation=v_generation,desired_digest=p_projection_digest,
        desired_disposition='absent',updated_at=now()
    where workshop_id=p_workshop_id;
    return query select 'created',v_generation,p_projection_digest,v_tombstone;
end
$function$;

create or replace function control.begin_startup_route_rebuild(
    p_effect_run_id uuid,p_instance_owner uuid,p_execution_token uuid,
    p_global_lease_token uuid,p_route_lease_token uuid,p_global_fence_token bigint
) returns boolean
language plpgsql security definer set search_path=pg_catalog, control
as $function$
declare v_changed bigint;
begin
    update control.workshop_route_effect_runs set state='effects_started',updated_at=now()
    where id=p_effect_run_id and kind='startup-rebuild'
      and state in ('reserved','effects_started')
      and instance_owner=p_instance_owner and execution_token=p_execution_token
      and global_lease_token=p_global_lease_token
      and route_lease_token=p_route_lease_token
      and global_fence_token=p_global_fence_token and lease_expires_at>now();
    get diagnostics v_changed=row_count; return v_changed=1;
end
$function$;

create or replace function control.renew_startup_route_rebuild(
    p_effect_run_id uuid,p_instance_owner uuid,p_execution_token uuid,
    p_global_lease_token uuid,p_route_lease_token uuid,
    p_global_fence_token bigint,p_ttl_seconds integer
) returns boolean
language plpgsql security definer set search_path=pg_catalog, control
as $function$
declare v_count bigint; v_expected bigint;
begin
    if p_ttl_seconds<60 or p_ttl_seconds>1200 then return false; end if;
    perform 1 from control.deployment_driver_resource_leases
    where resource_key='runtime/shared-odoo' for update;
    perform 1 from control.workshop_route_application_leases
    where effect_run_id=p_effect_run_id order by workshop_id for update;
    update control.workshop_route_effect_runs set
        lease_expires_at=now()+make_interval(secs=>p_ttl_seconds),
        heartbeat_at=now(),updated_at=now()
    where id=p_effect_run_id and kind='startup-rebuild'
      and state in ('reserved','effects_started')
      and instance_owner=p_instance_owner and execution_token=p_execution_token
      and global_lease_token=p_global_lease_token
      and route_lease_token=p_route_lease_token
      and global_fence_token=p_global_fence_token and lease_expires_at>now();
    get diagnostics v_count=row_count; if v_count<>1 then return false; end if;
    update control.deployment_driver_resource_leases set
        lease_expires_at=now()+make_interval(secs=>p_ttl_seconds),
        heartbeat_at=now(),updated_at=now()
    where resource_key='runtime/shared-odoo' and state='held'
      and authority_kind='startup-rebuild' and effect_run_id=p_effect_run_id
      and lease_owner=p_instance_owner and lease_token=p_global_lease_token
      and fence_token=p_global_fence_token and lease_expires_at>now();
    get diagnostics v_count=row_count; if v_count<>1 then return false; end if;
    select count(*) into v_expected from control.workshop_route_effect_reservations
    where effect_run_id=p_effect_run_id;
    update control.workshop_route_application_leases set
        lease_expires_at=now()+make_interval(secs=>p_ttl_seconds),
        heartbeat_at=now(),updated_at=now()
    where authority_kind='startup-rebuild' and effect_run_id=p_effect_run_id
      and state='held' and lease_owner=p_instance_owner
      and lease_token=p_route_lease_token and lease_expires_at>now();
    get diagnostics v_count=row_count;
    if v_count<>v_expected then raise exception 'startup route reservation lost'
        using errcode='40001'; end if;
    return true;
end
$function$;

create or replace function control.record_startup_route_candidate(
    p_effect_run_id uuid,p_instance_owner uuid,p_execution_token uuid,
    p_route_lease_token uuid,p_workshop_id uuid,p_route_fence_token bigint,
    p_rendered_digest text,p_evidence jsonb
) returns boolean
language plpgsql security definer set search_path=pg_catalog, control
as $function$
declare v_res control.workshop_route_effect_reservations%rowtype; v_keys integer;
begin
    if p_rendered_digest !~ '^sha256:[0-9a-f]{64}$'
       or jsonb_typeof(p_evidence)<>'object' then return false; end if;
    select reservation.* into v_res
    from control.workshop_route_effect_runs run
    join control.workshop_route_effect_reservations reservation
      on reservation.effect_run_id=run.id
    where run.id=p_effect_run_id and run.state='effects_started'
      and run.instance_owner=p_instance_owner and run.execution_token=p_execution_token
      and run.route_lease_token=p_route_lease_token and run.lease_expires_at>now()
      and reservation.workshop_id=p_workshop_id
      and reservation.route_fence_token=p_route_fence_token for update;
    if not found then return false; end if;
    select count(*) into v_keys from jsonb_object_keys(p_evidence);
    if v_keys<>7
       or p_evidence->>'effect_run_id' is distinct from p_effect_run_id::text
       or p_evidence->>'workshop_id' is distinct from p_workshop_id::text
       or p_evidence->>'generation' is distinct from v_res.generation::text
       or p_evidence->>'projection_digest' is distinct from v_res.projection_digest
       or p_evidence->>'disposition' is distinct from v_res.disposition
       or p_evidence->>'rendered_digest' is distinct from p_rendered_digest
       or p_evidence->>'route_fence_token' is distinct from p_route_fence_token::text
       then return false; end if;
    update control.workshop_route_effect_reservations set state='candidate',
        rendered_digest=p_rendered_digest,evidence=p_evidence,updated_at=now()
    where effect_run_id=p_effect_run_id and workshop_id=p_workshop_id
      and state in ('reserved','candidate');
    return found;
end
$function$;

create or replace function control.finish_startup_route_rebuild(
    p_effect_run_id uuid,p_instance_owner uuid,p_execution_token uuid,
    p_global_lease_token uuid,p_route_lease_token uuid,
    p_global_fence_token bigint,p_outcome text,p_response jsonb,p_safe_error text
) returns boolean
language plpgsql security definer set search_path=pg_catalog, control
as $function$
declare v_run control.workshop_route_effect_runs%rowtype; v_count bigint;
    v_response_keys integer;
begin
    if p_outcome not in ('succeeded','cancelled','unknown') then return false; end if;
    select * into v_run from control.workshop_route_effect_runs
    where id=p_effect_run_id and kind='startup-rebuild'
      and state in ('reserved','effects_started')
      and instance_owner=p_instance_owner and execution_token=p_execution_token
      and global_lease_token=p_global_lease_token
      and route_lease_token=p_route_lease_token
      and global_fence_token=p_global_fence_token for update;
    if not found then return false; end if;
    perform 1 from control.deployment_driver_resource_leases
    where resource_key='runtime/shared-odoo' for update;
    perform 1 from control.workshop_route_application_leases
    where effect_run_id=p_effect_run_id order by workshop_id for update;
    if p_outcome='succeeded' then
        if v_run.state<>'effects_started' or v_run.lease_expires_at<=now()
           or p_safe_error is not null or jsonb_typeof(p_response)<>'object'
           or exists(select 1 from control.workshop_route_effect_reservations
                     where effect_run_id=p_effect_run_id and state<>'candidate') then
            return false;
        end if;
        select count(*) into v_response_keys from jsonb_object_keys(p_response);
        select count(*) into v_count from control.workshop_route_effect_reservations
        where effect_run_id=p_effect_run_id;
        if v_response_keys<>5
           or p_response->>'effect_run_id' is distinct from p_effect_run_id::text
           or p_response->>'global_fence_token'
                is distinct from p_global_fence_token::text
           or p_response->>'workshop_count' is distinct from v_count::text
           or p_response->>'projection_set_digest' is null
           or p_response->>'projection_set_digest' !~ '^sha256:[0-9a-f]{64}$'
           or p_response->>'gateway_reload_digest' is null
           or p_response->>'gateway_reload_digest' !~ '^sha256:[0-9a-f]{64}$'
           then return false; end if;
        update control.workshop_route_projection_state state set
            applied_generation=reservation.generation,
            applied_digest=reservation.projection_digest,
            applied_disposition=reservation.disposition,
            applied_rendered_digest=reservation.rendered_digest,
            applied_driver_operation_id=null,
            applied_effect_run_id=p_effect_run_id,
            applied_fence_token=reservation.route_fence_token,updated_at=now()
        from control.workshop_route_effect_reservations reservation
        where reservation.effect_run_id=p_effect_run_id
          and reservation.workshop_id=state.workshop_id
          and reservation.generation is not null;
        update control.workshop_route_effect_reservations set
            state='succeeded',updated_at=now()
        where effect_run_id=p_effect_run_id;
        update control.workshop_route_application_leases lease set
            state=case when reservation.generation is null
                then 'uninitialized' else 'idle' end,
            initialization_required=(reservation.generation is null),
            authority_kind=null,effect_run_id=null,driver_operation_id=null,
            generation=null,projection_digest=null,lease_owner=null,lease_token=null,
            lease_expires_at=null,heartbeat_at=null,quarantined_at=null,
            safe_error=null,updated_at=now()
        from control.workshop_route_effect_reservations reservation
        where reservation.effect_run_id=p_effect_run_id
          and reservation.workshop_id=lease.workshop_id;
        update control.workshop_route_effect_runs set state='succeeded',
            response=p_response,instance_owner=null,execution_token=null,
            global_lease_token=null,route_lease_token=null,lease_expires_at=null,
            finished_at=now(),updated_at=now() where id=p_effect_run_id;
        update control.deployment_driver_resource_leases set state='idle',
            authority_kind=null,effect_run_id=null,driver_operation_id=null,
            lease_owner=null,lease_token=null,lease_expires_at=null,
            heartbeat_at=null,quarantined_at=null,safe_error=null,updated_at=now()
        where resource_key='runtime/shared-odoo' and effect_run_id=p_effect_run_id;
    elsif p_outcome='cancelled' then
        if v_run.state<>'reserved'
           or exists(select 1 from control.workshop_route_effect_reservations
                     where effect_run_id=p_effect_run_id and state<>'reserved') then
            return false;
        end if;
        update control.workshop_route_application_leases lease set
            state=reservation.prior_lease_state,authority_kind=null,
            effect_run_id=null,driver_operation_id=null,generation=null,
            projection_digest=null,lease_owner=null,lease_token=null,
            lease_expires_at=null,heartbeat_at=null,updated_at=now()
        from control.workshop_route_effect_reservations reservation
        where reservation.effect_run_id=p_effect_run_id
          and reservation.workshop_id=lease.workshop_id;
        update control.workshop_route_effect_runs set state='cancelled',
            instance_owner=null,execution_token=null,global_lease_token=null,
            route_lease_token=null,lease_expires_at=null,finished_at=now(),updated_at=now()
        where id=p_effect_run_id;
        update control.deployment_driver_resource_leases set state='idle',
            authority_kind=null,effect_run_id=null,driver_operation_id=null,
            lease_owner=null,lease_token=null,lease_expires_at=null,
            heartbeat_at=null,updated_at=now()
        where resource_key='runtime/shared-odoo' and effect_run_id=p_effect_run_id;
    else
        if p_safe_error is not null or p_response is not null then return false; end if;
        update control.workshop_route_effect_reservations set state='quarantined',updated_at=now()
        where effect_run_id=p_effect_run_id;
        update control.workshop_route_application_leases set state='quarantined',
            lease_token=null,lease_expires_at=null,quarantined_at=now(),
            safe_error='runtime_outcome_unknown',updated_at=now()
        where effect_run_id=p_effect_run_id;
        update control.workshop_route_effect_runs set state='quarantined',
            instance_owner=null,execution_token=null,global_lease_token=null,
            route_lease_token=null,lease_expires_at=null,
            safe_error='runtime_outcome_unknown',finished_at=now(),updated_at=now()
        where id=p_effect_run_id;
        update control.deployment_driver_resource_leases set state='quarantined',
            lease_token=null,lease_expires_at=null,quarantined_at=now(),
            safe_error='runtime_outcome_unknown',updated_at=now()
        where resource_key='runtime/shared-odoo' and effect_run_id=p_effect_run_id;
    end if;
    get diagnostics v_count=row_count; return v_count=1;
end
$function$;

create or replace function control.admit_workshop_route_maintenance(
    p_control_operation_id uuid,p_control_operation_attempt integer,
    p_control_operation_lease_owner text,p_workshop_id uuid,
    p_reason text,p_idempotency_key text,p_request_digest text,p_instance_owner uuid,
    p_execution_token uuid,p_route_lease_token uuid,p_ttl_seconds integer
) returns table(outcome text,effect_run_id uuid,route_fence_token bigint,
    projection jsonb,stored_response jsonb)
language plpgsql security definer set search_path=pg_catalog, control
as $function$
declare v_global control.deployment_driver_resource_leases%rowtype;
    v_route control.workshop_route_application_leases%rowtype;
    v_state control.workshop_route_projection_state%rowtype;
    v_run control.workshop_route_effect_runs%rowtype;
    v_run_id uuid; v_fence bigint; v_projection jsonb;
begin
    if p_reason is distinct from 'restore'
       or p_control_operation_attempt<=0 or p_control_operation_lease_owner is null
       or btrim(p_control_operation_lease_owner)='' or p_idempotency_key is null
       or btrim(p_idempotency_key)='' or length(p_idempotency_key)>180
       or p_request_digest !~ '^[0-9a-f]{64}$'
       or p_instance_owner is null or p_execution_token is null
       or p_route_lease_token is null or p_ttl_seconds<60 or p_ttl_seconds>1200 then
        return query select 'invalid',null::uuid,null::bigint,null::jsonb,null::jsonb;
        return;
    end if;
    perform 1 from control.operations operation
    where operation.id=p_control_operation_id and operation.workshop_id=p_workshop_id
      and operation.kind='tenant.lifecycle' and operation.queue='tenant-lifecycle'
      and operation.state='in_flight'
      and operation.attempt=p_control_operation_attempt
      and operation.leased_by=p_control_operation_lease_owner
      and operation.lease_expires_at>now() for update;
    if not found then return query select 'upstream_lease_lost',null::uuid,
        null::bigint,null::jsonb,null::jsonb; return; end if;
    select * into strict v_global from control.deployment_driver_resource_leases
    where resource_key='runtime/shared-odoo' for update;
    if v_global.state<>'idle' then return query select
        case when v_global.state='quarantined' then 'fleet_quarantined' else 'fleet_busy' end,
        coalesce(v_global.effect_run_id,v_global.driver_operation_id),v_global.fence_token,
        null::jsonb,null::jsonb; return; end if;
    select * into strict v_route from control.workshop_route_application_leases
    where workshop_id=p_workshop_id for update;
    select * into strict v_state from control.workshop_route_projection_state
    where workshop_id=p_workshop_id for update;

    select * into v_run from control.workshop_route_effect_runs
    where kind='recovery-maintenance' and (
        idempotency_key=p_idempotency_key or target_key=
            'maintenance/'||p_workshop_id::text||'/'||p_control_operation_id::text
    ) order by (idempotency_key=p_idempotency_key) desc limit 1 for update;
    if found then
        if v_run.request_digest<>p_request_digest
           or v_run.control_operation_id<>p_control_operation_id then
            return query select 'digest_conflict',v_run.id,null::bigint,null::jsonb,null::jsonb;
        elsif v_run.state='succeeded' then
            return query select 'replay',v_run.id,
                (select reservation.route_fence_token
                 from control.workshop_route_effect_reservations reservation
                 where reservation.effect_run_id=v_run.id
                   and reservation.workshop_id=p_workshop_id),
                null::jsonb,v_run.response;
        elsif v_run.state='maintenance' then
            return query select 'maintenance',v_run.id,v_route.fence_token,null::jsonb,null::jsonb;
        elsif v_run.state='quarantined' then
            return query select 'quarantined',v_run.id,v_route.fence_token,null::jsonb,null::jsonb;
        else return query select 'busy',v_run.id,v_route.fence_token,null::jsonb,null::jsonb;
        end if; return;
    end if;
    if v_route.state<>'idle' then return query select
        case when v_route.state='uninitialized' then 'uninitialized'
             when v_route.state='quarantined' then 'quarantined' else 'busy' end,
        coalesce(v_route.effect_run_id,v_route.driver_operation_id),v_route.fence_token,
        null::jsonb,null::jsonb; return; end if;
    if v_state.applied_generation is null or v_state.applied_disposition<>'present'
       or v_state.desired_generation<>v_state.applied_generation
       or v_state.desired_digest<>v_state.applied_digest
       or v_state.desired_disposition<>v_state.applied_disposition then
        return query select 'projection_pending',null::uuid,v_route.fence_token,
            null::jsonb,null::jsonb; return;
    end if;
    select stored.projection into strict v_projection
    from control.workshop_route_projections stored
    where stored.workshop_id=p_workshop_id
      and stored.generation=v_state.applied_generation
      and stored.projection_digest=v_state.applied_digest;
    v_fence:=v_route.fence_token+1;
    insert into control.workshop_route_effect_runs(
        kind,reason,target_key,idempotency_key,request_digest,workshop_id,
        control_operation_id,control_operation_attempt,control_operation_lease_owner,
        state,instance_owner,execution_token,route_lease_token,lease_expires_at,heartbeat_at
    ) values('recovery-maintenance','restore',
        'maintenance/'||p_workshop_id::text||'/'||p_control_operation_id::text,
        p_idempotency_key,p_request_digest,p_workshop_id,p_control_operation_id,
        p_control_operation_attempt,p_control_operation_lease_owner,'reserved',
        p_instance_owner,p_execution_token,p_route_lease_token,
        now()+make_interval(secs=>p_ttl_seconds),now()) returning id into v_run_id;
    insert into control.workshop_route_effect_reservations(
        effect_run_id,workshop_id,generation,projection_digest,disposition,
        baseline_generation,baseline_projection_digest,baseline_disposition,
        route_fence_token,action,prior_lease_state
    ) values(v_run_id,p_workshop_id,v_state.applied_generation,v_state.applied_digest,
        v_state.applied_disposition,v_state.applied_generation,v_state.applied_digest,
        v_state.applied_disposition,v_fence,'maintenance','idle');
    update control.workshop_route_application_leases set state='held',
        authority_kind='recovery-maintenance',effect_run_id=v_run_id,
        driver_operation_id=null,generation=v_state.applied_generation,
        projection_digest=v_state.applied_digest,fence_token=v_fence,
        lease_owner=p_instance_owner,lease_token=p_route_lease_token,
        lease_expires_at=now()+make_interval(secs=>p_ttl_seconds),
        heartbeat_at=now(),updated_at=now() where workshop_id=p_workshop_id;
    return query select 'acquired',v_run_id,v_fence,v_projection,null::jsonb;
end
$function$;

create or replace function control.begin_workshop_route_maintenance(
    p_effect_run_id uuid,p_instance_owner uuid,p_execution_token uuid,
    p_route_lease_token uuid,p_route_fence_token bigint
) returns boolean language plpgsql security definer set search_path=pg_catalog, control
as $function$ declare v_changed bigint; begin
    update control.workshop_route_effect_runs run set state='effects_started',updated_at=now()
    from control.workshop_route_effect_reservations reservation
    where run.id=p_effect_run_id and run.kind='recovery-maintenance'
      and run.state='reserved' and run.instance_owner=p_instance_owner
      and run.execution_token=p_execution_token
      and run.route_lease_token=p_route_lease_token and run.lease_expires_at>now()
      and reservation.effect_run_id=run.id
      and reservation.route_fence_token=p_route_fence_token;
    get diagnostics v_changed=row_count; return v_changed=1;
end $function$;

create or replace function control.renew_workshop_route_effect(
    p_effect_run_id uuid,p_control_operation_id uuid,
    p_control_operation_attempt integer,p_control_operation_lease_owner text,
    p_instance_owner uuid,p_execution_token uuid,p_route_lease_token uuid,
    p_route_fence_token bigint,p_ttl_seconds integer
) returns boolean language plpgsql security definer set search_path=pg_catalog, control
as $function$ declare v_workshop uuid; v_changed bigint; begin
    if p_ttl_seconds<60 or p_ttl_seconds>1200 then return false; end if;
    select workshop_id into v_workshop from control.operations
    where id=p_control_operation_id and kind='tenant.lifecycle'
      and queue='tenant-lifecycle' and state='in_flight'
      and attempt=p_control_operation_attempt and leased_by=p_control_operation_lease_owner
      and lease_expires_at>now() for update;
    if not found then return false; end if;
    perform 1 from control.deployment_driver_resource_leases
    where resource_key='runtime/shared-odoo' and state='idle' for update;
    if not found then return false; end if;
    update control.workshop_route_application_leases set
        lease_expires_at=now()+make_interval(secs=>p_ttl_seconds),
        heartbeat_at=now(),updated_at=now()
    where workshop_id=v_workshop and state='held'
      and authority_kind='recovery-maintenance' and effect_run_id=p_effect_run_id
      and lease_owner=p_instance_owner and lease_token=p_route_lease_token
      and fence_token=p_route_fence_token and lease_expires_at>now();
    get diagnostics v_changed=row_count; if v_changed<>1 then return false; end if;
    update control.workshop_route_effect_runs set
        lease_expires_at=now()+make_interval(secs=>p_ttl_seconds),
        heartbeat_at=now(),updated_at=now()
    where id=p_effect_run_id and control_operation_id=p_control_operation_id
      and control_operation_attempt=p_control_operation_attempt
      and control_operation_lease_owner=p_control_operation_lease_owner
      and state in ('reserved','effects_started','restore_started')
      and instance_owner=p_instance_owner and execution_token=p_execution_token
      and route_lease_token=p_route_lease_token and lease_expires_at>now();
    get diagnostics v_changed=row_count;
    if v_changed<>1 then raise exception 'recovery route effect lease lost'
        using errcode='40001'; end if; return true;
end $function$;

create or replace function control.finish_workshop_route_maintenance_entry(
    p_effect_run_id uuid,p_instance_owner uuid,p_execution_token uuid,
    p_route_lease_token uuid,p_route_fence_token bigint,p_outcome text,
    p_rendered_digest text,p_evidence jsonb
) returns boolean language plpgsql security definer set search_path=pg_catalog, control
as $function$ declare v_run control.workshop_route_effect_runs%rowtype;
    v_res control.workshop_route_effect_reservations%rowtype; v_keys integer;
begin
    if p_outcome not in ('maintenance','cancelled','unknown') then return false; end if;
    select * into v_run from control.workshop_route_effect_runs
    where id=p_effect_run_id and kind='recovery-maintenance'
      and state in ('reserved','effects_started') and instance_owner=p_instance_owner
      and execution_token=p_execution_token and route_lease_token=p_route_lease_token for update;
    if not found then return false; end if;
    select * into strict v_res from control.workshop_route_effect_reservations
    where effect_run_id=p_effect_run_id for update;
    if p_outcome='maintenance' then
        if v_run.state<>'effects_started' or v_run.lease_expires_at<=now()
           or p_rendered_digest !~ '^sha256:[0-9a-f]{64}$'
           or jsonb_typeof(p_evidence)<>'object' then return false; end if;
        select count(*) into v_keys from jsonb_object_keys(p_evidence);
        if v_keys<>8
           or p_evidence->>'effect_run_id' is distinct from p_effect_run_id::text
           or p_evidence->>'workshop_id' is distinct from v_run.workshop_id::text
           or p_evidence->>'generation' is distinct from v_res.generation::text
           or p_evidence->>'projection_digest' is distinct from v_res.projection_digest
           or p_evidence->>'disposition' is distinct from v_res.disposition
           or p_evidence->>'rendered_digest' is distinct from p_rendered_digest
           or p_evidence->>'route_fence_token' is distinct from p_route_fence_token::text
           or p_evidence->>'mode' is distinct from 'maintenance' then return false; end if;
        update control.workshop_route_effect_reservations set state='maintenance',
            maintenance_rendered_digest=p_rendered_digest,
            maintenance_evidence=p_evidence,updated_at=now()
        where effect_run_id=p_effect_run_id;
        update control.workshop_route_application_leases set state='maintenance',
            lease_owner=null,lease_token=null,lease_expires_at=null,
            safe_error='recovery_maintenance',updated_at=now()
        where workshop_id=v_run.workshop_id and effect_run_id=p_effect_run_id
          and fence_token=p_route_fence_token;
        update control.workshop_route_effect_runs set state='maintenance',
            instance_owner=null,execution_token=null,route_lease_token=null,
            lease_expires_at=null,safe_error='recovery_maintenance',updated_at=now()
        where id=p_effect_run_id;
    elsif p_outcome='cancelled' then
        if v_run.state<>'reserved' or p_rendered_digest is not null
           or p_evidence is not null then return false; end if;
        update control.workshop_route_application_leases set state='idle',
            authority_kind=null,effect_run_id=null,generation=null,
            projection_digest=null,lease_owner=null,lease_token=null,
            lease_expires_at=null,heartbeat_at=null,updated_at=now()
        where workshop_id=v_run.workshop_id and effect_run_id=p_effect_run_id;
        update control.workshop_route_effect_runs set state='cancelled',
            instance_owner=null,execution_token=null,route_lease_token=null,
            lease_expires_at=null,finished_at=now(),updated_at=now()
        where id=p_effect_run_id;
    else
        if p_rendered_digest is not null or p_evidence is not null then
            return false;
        end if;
        update control.workshop_route_effect_reservations set state='quarantined',updated_at=now()
        where effect_run_id=p_effect_run_id;
        update control.workshop_route_application_leases set state='quarantined',
            lease_token=null,lease_expires_at=null,quarantined_at=now(),
            safe_error='runtime_outcome_unknown',updated_at=now()
        where workshop_id=v_run.workshop_id and effect_run_id=p_effect_run_id;
        update control.workshop_route_effect_runs set state='quarantined',
            instance_owner=null,execution_token=null,route_lease_token=null,
            lease_expires_at=null,safe_error='runtime_outcome_unknown',
            finished_at=now(),updated_at=now() where id=p_effect_run_id;
    end if; return true;
end $function$;

create or replace function control.claim_workshop_route_maintenance_exit(
    p_effect_run_id uuid,p_control_operation_id uuid,
    p_control_operation_attempt integer,p_control_operation_lease_owner text,
    p_instance_owner uuid,p_execution_token uuid,p_route_lease_token uuid,
    p_ttl_seconds integer
) returns table(outcome text,route_fence_token bigint,disposition text,projection jsonb)
language plpgsql security definer set search_path=pg_catalog, control
as $function$ declare v_run control.workshop_route_effect_runs%rowtype;
    v_res control.workshop_route_effect_reservations%rowtype;
    v_state control.workshop_route_projection_state%rowtype; v_projection jsonb;
begin
    if p_effect_run_id is null or p_control_operation_id is null
       or p_control_operation_attempt<=0
       or p_control_operation_lease_owner is null
       or btrim(p_control_operation_lease_owner)=''
       or p_instance_owner is null or p_execution_token is null
       or p_route_lease_token is null
       or p_ttl_seconds<60 or p_ttl_seconds>1200 then
        return query select 'invalid',null::bigint,null::text,null::jsonb; return;
    end if;
    perform 1 from control.operations where id=p_control_operation_id
      and kind='tenant.lifecycle' and queue='tenant-lifecycle' and state='in_flight'
      and attempt=p_control_operation_attempt and leased_by=p_control_operation_lease_owner
      and lease_expires_at>now() for update;
    if not found then return query select 'upstream_lease_lost',null::bigint,null::text,null::jsonb; return; end if;
    perform 1 from control.deployment_driver_resource_leases
    where resource_key='runtime/shared-odoo' and state='idle' for update;
    if not found then return query select 'fleet_busy',null::bigint,null::text,null::jsonb; return; end if;
    select * into v_run from control.workshop_route_effect_runs
    where id=p_effect_run_id and kind='recovery-maintenance' and state='maintenance'
      and control_operation_id=p_control_operation_id for update;
    if not found then return query select 'not_maintenance',null::bigint,null::text,null::jsonb; return; end if;
    select * into strict v_res from control.workshop_route_effect_reservations
    where effect_run_id=p_effect_run_id for update;
    perform 1 from control.workshop_route_application_leases
    where workshop_id=v_run.workshop_id and state='maintenance'
      and effect_run_id=p_effect_run_id and fence_token=v_res.route_fence_token for update;
    if not found then return query select 'authority_lost',null::bigint,null::text,null::jsonb; return; end if;
    select * into strict v_state from control.workshop_route_projection_state
    where workshop_id=v_run.workshop_id for update;
    if v_state.desired_generation is null then
        return query select 'projection_missing',null::bigint,null::text,null::jsonb; return;
    end if;
    select stored.projection into strict v_projection
    from control.workshop_route_projections stored
    where stored.workshop_id=v_run.workshop_id
      and stored.generation=v_state.desired_generation
      and stored.projection_digest=v_state.desired_digest
      and stored.disposition=v_state.desired_disposition;
    update control.workshop_route_effect_reservations set
        generation=v_state.desired_generation,
        projection_digest=v_state.desired_digest,
        disposition=v_state.desired_disposition,
        action=case when v_state.desired_disposition='absent'
            then 'remove-absent' else 'render' end,updated_at=now()
    where effect_run_id=p_effect_run_id and workshop_id=v_run.workshop_id;
    update control.workshop_route_effect_runs set state='restore_started',
        control_operation_attempt=p_control_operation_attempt,
        control_operation_lease_owner=p_control_operation_lease_owner,
        instance_owner=p_instance_owner,execution_token=p_execution_token,
        route_lease_token=p_route_lease_token,
        lease_expires_at=now()+make_interval(secs=>p_ttl_seconds),
        heartbeat_at=now(),safe_error=null,updated_at=now()
    where id=p_effect_run_id;
    update control.workshop_route_application_leases set state='held',
        generation=v_state.desired_generation,projection_digest=v_state.desired_digest,
        lease_owner=p_instance_owner,lease_token=p_route_lease_token,
        lease_expires_at=now()+make_interval(secs=>p_ttl_seconds),
        safe_error=null,updated_at=now() where workshop_id=v_run.workshop_id;
    return query select 'acquired',v_res.route_fence_token,
        v_state.desired_disposition,v_projection;
end $function$;

create or replace function control.finish_workshop_route_maintenance_exit(
    p_effect_run_id uuid,p_instance_owner uuid,p_execution_token uuid,
    p_route_lease_token uuid,p_route_fence_token bigint,p_outcome text,
    p_rendered_digest text,p_evidence jsonb,p_safe_error text
) returns boolean language plpgsql security definer set search_path=pg_catalog, control
as $function$ declare v_run control.workshop_route_effect_runs%rowtype;
    v_res control.workshop_route_effect_reservations%rowtype; v_keys integer;
begin
    if p_outcome not in ('succeeded','unknown') then return false; end if;
    select * into v_run from control.workshop_route_effect_runs
    where id=p_effect_run_id and kind='recovery-maintenance' and state='restore_started'
      and instance_owner=p_instance_owner and execution_token=p_execution_token
      and route_lease_token=p_route_lease_token for update;
    if not found then return false; end if;
    select * into strict v_res from control.workshop_route_effect_reservations
    where effect_run_id=p_effect_run_id for update;
    if p_outcome='succeeded' then
        if v_run.lease_expires_at<=now() or p_safe_error is not null
           or p_rendered_digest !~ '^sha256:[0-9a-f]{64}$'
           or jsonb_typeof(p_evidence)<>'object' then return false; end if;
        select count(*) into v_keys from jsonb_object_keys(p_evidence);
        if v_keys<>8
           or p_evidence->>'effect_run_id' is distinct from p_effect_run_id::text
           or p_evidence->>'workshop_id' is distinct from v_run.workshop_id::text
           or p_evidence->>'generation' is distinct from v_res.generation::text
           or p_evidence->>'projection_digest' is distinct from v_res.projection_digest
           or p_evidence->>'disposition' is distinct from v_res.disposition
           or p_evidence->>'rendered_digest' is distinct from p_rendered_digest
           or p_evidence->>'route_fence_token' is distinct from p_route_fence_token::text
           or p_evidence->>'mode' is distinct from 'restored' then return false; end if;
        update control.workshop_route_effect_reservations set state='restored',
            restored_rendered_digest=p_rendered_digest,
            restored_evidence=p_evidence,updated_at=now()
        where effect_run_id=p_effect_run_id;
        update control.workshop_route_projection_state set
            applied_generation=v_res.generation,
            applied_digest=v_res.projection_digest,
            applied_disposition=v_res.disposition,
            applied_rendered_digest=p_rendered_digest,
            applied_driver_operation_id=null,applied_effect_run_id=p_effect_run_id,
            applied_fence_token=p_route_fence_token,updated_at=now()
        where workshop_id=v_run.workshop_id
          and desired_generation=v_res.generation
          and desired_digest=v_res.projection_digest
          and desired_disposition=v_res.disposition;
        if not found then return false; end if;
        update control.workshop_route_application_leases set state='idle',
            authority_kind=null,effect_run_id=null,generation=null,
            projection_digest=null,lease_owner=null,lease_token=null,
            lease_expires_at=null,heartbeat_at=null,safe_error=null,updated_at=now()
        where workshop_id=v_run.workshop_id and effect_run_id=p_effect_run_id;
        update control.workshop_route_effect_runs set state='succeeded',
            response=jsonb_build_object('route_evidence',p_evidence),
            instance_owner=null,execution_token=null,route_lease_token=null,
            lease_expires_at=null,finished_at=now(),updated_at=now()
        where id=p_effect_run_id;
    else
        if p_rendered_digest is not null or p_evidence is not null
           or p_safe_error is not null then return false; end if;
        update control.workshop_route_effect_reservations set state='quarantined',updated_at=now()
        where effect_run_id=p_effect_run_id;
        update control.workshop_route_application_leases set state='quarantined',
            lease_token=null,lease_expires_at=null,quarantined_at=now(),
            safe_error='runtime_outcome_unknown',updated_at=now()
        where workshop_id=v_run.workshop_id and effect_run_id=p_effect_run_id;
        update control.workshop_route_effect_runs set state='quarantined',
            instance_owner=null,execution_token=null,route_lease_token=null,
            lease_expires_at=null,safe_error='runtime_outcome_unknown',
            finished_at=now(),updated_at=now() where id=p_effect_run_id;
    end if; return true;
end $function$;

revoke all on table control.workshop_route_effect_runs from public;
revoke all on table control.workshop_route_effect_reservations from public;
revoke all on function control.normalize_global_route_authority() from public;
revoke all on function control.normalize_workshop_route_authority() from public;
revoke all on function control.normalize_workshop_route_projection_state() from public;
revoke all on function control.materialize_workshop_route_projection_v1(uuid,integer,text,uuid,jsonb,text) from public;
revoke all on function control.admit_workshop_route_application_v1(uuid,integer,text,uuid,text,text,text,bigint,text,uuid,uuid,uuid,integer) from public;
revoke all on function control.admit_release_driver_operation_v1(uuid,integer,text,text,text,uuid,text,uuid,uuid,uuid,integer) from public;
revoke all on function control.materialize_workshop_route_projection(uuid,integer,text,uuid,jsonb,text) from public;
revoke all on function control.admit_workshop_route_application(uuid,integer,text,uuid,text,text,text,bigint,text,uuid,uuid,uuid,integer) from public;
revoke all on function control.admit_release_driver_operation(uuid,integer,text,text,text,uuid,text,uuid,uuid,uuid,integer) from public;
revoke all on function control.finish_workshop_route_application(uuid,uuid,uuid,uuid,bigint,text,jsonb,text,text) from public;
revoke all on function control.finish_workshop_route_application_v1(uuid,uuid,uuid,uuid,bigint,text,jsonb,text,text) from public;
revoke all on function control.admit_startup_route_rebuild(uuid,text,text,uuid,uuid,uuid,uuid,integer) from public;
revoke all on function control.read_startup_route_rebuild_batch(uuid,uuid,uuid,uuid,bigint,uuid,integer) from public;
revoke all on function control.initialize_startup_route_projection(uuid,uuid,uuid,uuid,uuid,bigint,uuid,text,text,jsonb,text) from public;
revoke all on function control.materialize_workshop_route_tombstone(uuid,integer,text,uuid,jsonb,text) from public;
revoke all on function control.begin_startup_route_rebuild(uuid,uuid,uuid,uuid,uuid,bigint) from public;
revoke all on function control.renew_startup_route_rebuild(uuid,uuid,uuid,uuid,uuid,bigint,integer) from public;
revoke all on function control.record_startup_route_candidate(uuid,uuid,uuid,uuid,uuid,bigint,text,jsonb) from public;
revoke all on function control.finish_startup_route_rebuild(uuid,uuid,uuid,uuid,uuid,bigint,text,jsonb,text) from public;
revoke all on function control.admit_workshop_route_maintenance(uuid,integer,text,uuid,text,text,text,uuid,uuid,uuid,integer) from public;
revoke all on function control.begin_workshop_route_maintenance(uuid,uuid,uuid,uuid,bigint) from public;
revoke all on function control.renew_workshop_route_effect(uuid,uuid,integer,text,uuid,uuid,uuid,bigint,integer) from public;
revoke all on function control.finish_workshop_route_maintenance_entry(uuid,uuid,uuid,uuid,bigint,text,text,jsonb) from public;
revoke all on function control.claim_workshop_route_maintenance_exit(uuid,uuid,integer,text,uuid,uuid,uuid,integer) from public;
revoke all on function control.finish_workshop_route_maintenance_exit(uuid,uuid,uuid,uuid,bigint,text,text,jsonb,text) from public;

do $migration$
begin
    if exists(select 1 from pg_roles where rolname='control_driver_ledger') then
        revoke execute on function control.finish_workshop_route_application_v1(
            uuid,uuid,uuid,uuid,bigint,text,jsonb,text,text
        ) from control_driver_ledger;
        revoke execute on function
            control.admit_workshop_route_application_v1(uuid,integer,text,uuid,text,text,text,bigint,text,uuid,uuid,uuid,integer),
            control.admit_release_driver_operation_v1(uuid,integer,text,text,text,uuid,text,uuid,uuid,uuid,integer)
        from control_driver_ledger;
        revoke insert,update,delete on control.workshop_route_effect_runs,
            control.workshop_route_effect_reservations from control_driver_ledger;
        grant select on control.workshop_route_effect_runs,
            control.workshop_route_effect_reservations to control_driver_ledger;
        grant execute on function control.admit_startup_route_rebuild(uuid,text,text,uuid,uuid,uuid,uuid,integer),
            control.admit_workshop_route_application(uuid,integer,text,uuid,text,text,text,bigint,text,uuid,uuid,uuid,integer),
            control.admit_release_driver_operation(uuid,integer,text,text,text,uuid,text,uuid,uuid,uuid,integer),
            control.finish_workshop_route_application(uuid,uuid,uuid,uuid,bigint,text,jsonb,text,text),
            control.read_startup_route_rebuild_batch(uuid,uuid,uuid,uuid,bigint,uuid,integer),
            control.initialize_startup_route_projection(uuid,uuid,uuid,uuid,uuid,bigint,uuid,text,text,jsonb,text),
            control.begin_startup_route_rebuild(uuid,uuid,uuid,uuid,uuid,bigint),
            control.renew_startup_route_rebuild(uuid,uuid,uuid,uuid,uuid,bigint,integer),
            control.record_startup_route_candidate(uuid,uuid,uuid,uuid,uuid,bigint,text,jsonb),
            control.finish_startup_route_rebuild(uuid,uuid,uuid,uuid,uuid,bigint,text,jsonb,text),
            control.admit_workshop_route_maintenance(uuid,integer,text,uuid,text,text,text,uuid,uuid,uuid,integer),
            control.begin_workshop_route_maintenance(uuid,uuid,uuid,uuid,bigint),
            control.renew_workshop_route_effect(uuid,uuid,integer,text,uuid,uuid,uuid,bigint,integer),
            control.finish_workshop_route_maintenance_entry(uuid,uuid,uuid,uuid,bigint,text,text,jsonb),
            control.claim_workshop_route_maintenance_exit(uuid,uuid,integer,text,uuid,uuid,uuid,integer),
            control.finish_workshop_route_maintenance_exit(uuid,uuid,uuid,uuid,bigint,text,text,jsonb,text)
        to control_driver_ledger;
    end if;
end
$migration$;

do $migration$
declare v_role text;
begin
    foreach v_role in array array[
        'control_reconciliation_worker','control_provisioning_worker',
        'control_lifecycle_worker'
    ] loop
        if exists(select 1 from pg_roles where rolname=v_role) then
            execute format(
                'revoke execute on function control.materialize_workshop_route_projection_v1(uuid,integer,text,uuid,jsonb,text) from %I',
                v_role
            );
            execute format(
                'grant execute on function control.materialize_workshop_route_projection(uuid,integer,text,uuid,jsonb,text) to %I',
                v_role
            );
        end if;
    end loop;
    if exists(select 1 from pg_roles where rolname='control_lifecycle_worker') then
        grant execute on function control.materialize_workshop_route_tombstone(
            uuid,integer,text,uuid,jsonb,text
        ) to control_lifecycle_worker;
    end if;
end
$migration$;

comment on table control.workshop_route_effect_runs is
'Durable startup and recovery route effect authority; expiry never permits stealing.';
comment on table control.workshop_route_effect_reservations is
'Frozen per-workshop membership and exact evidence for a route effect run.';
