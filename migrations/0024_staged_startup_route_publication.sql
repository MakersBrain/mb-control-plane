-- Publish the startup route projection as one staged, bounded-memory,
-- observable generation.  The 0013/0019 entry points remain available during
-- the rolling Rust cutover; this migration only adds protocol-v1 entry points.

create table control.workshop_route_startup_publications (
    effect_run_id uuid primary key,
    protocol_version smallint not null,
    original_instance_owner uuid not null,
    original_execution_token uuid not null,
    original_global_lease_token uuid not null,
    original_route_lease_token uuid not null,
    original_global_fence_token bigint not null,
    staging_selector text not null,
    prior_selector text,
    prior_directory_device bigint,
    prior_directory_inode bigint,
    prior_gateway_effect_run_id uuid,
    prior_gateway_set_digest text,
    prior_recorded_at timestamptz,
    active_runtime_slot text,
    active_runtime_release_id text,
    active_runtime_subject_digest text,
    active_runtime_deployment_ref text,
    active_runtime_config_digest text,
    active_runtime_slot_version bigint,
    fleet_release_unresolved boolean not null,
    phase text not null default 'staging',
    interrupted_phase text,
    last_completed_workshop uuid,
    candidate_count integer not null default 0,
    sealed_count integer,
    sealed_present_count integer,
    projection_set_digest text,
    publication_started_at timestamptz,
    observed_selector text,
    observed_effect_run_id uuid,
    observed_projection_set_digest text,
    observed_at timestamptz,
    finalized_at timestamptz,
    reconciliation_owner uuid,
    reconciliation_token uuid,
    reconciliation_expires_at timestamptz,
    safe_error text,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    constraint workshop_route_startup_publications_run_fkey
        foreign key(effect_run_id)
        references control.workshop_route_effect_runs(id) on delete restrict,
    constraint workshop_route_startup_publications_protocol_check
        check(protocol_version=1),
    constraint workshop_route_startup_publications_fence_check
        check(original_global_fence_token>0),
    constraint workshop_route_startup_publications_selector_check check(
        staging_selector='generations/startup-'||effect_run_id::text
        and (prior_selector is null
             or (prior_selector ~ '^generations/[A-Za-z0-9][A-Za-z0-9-]{0,63}$'
                 and staging_selector<>prior_selector))
    ),
    constraint workshop_route_startup_publications_prior_identity_check check(
        (prior_recorded_at is null and prior_selector is null
            and prior_directory_device is null and prior_directory_inode is null
            and prior_gateway_effect_run_id is null and prior_gateway_set_digest is null)
        or (prior_recorded_at is not null and prior_selector is not null
            and prior_directory_device>0 and prior_directory_inode>0
            and ((prior_gateway_effect_run_id is null and prior_gateway_set_digest is null)
              or (prior_gateway_effect_run_id is not null
                  and prior_gateway_set_digest ~ '^sha256:[0-9a-f]{64}$')))
    ),
    constraint workshop_route_startup_publications_runtime_check check(
        (active_runtime_slot is null and active_runtime_release_id is null
            and active_runtime_subject_digest is null
            and active_runtime_deployment_ref is null
            and active_runtime_config_digest is null
            and active_runtime_slot_version is null)
        or (active_runtime_slot in ('blue','green')
            and active_runtime_release_id is not null
            and active_runtime_subject_digest ~ '^sha256:[0-9a-f]{64}$'
            and active_runtime_deployment_ref is not null
            and btrim(active_runtime_deployment_ref)<>''
            and active_runtime_config_digest ~ '^sha256:[0-9a-f]{64}$'
            and active_runtime_slot_version>0)
    ),
    constraint workshop_route_startup_publications_phase_check
        check(phase in ('staging','sealed','publication_started','observed','quarantined')),
    constraint workshop_route_startup_publications_interrupted_phase_check
        check(interrupted_phase is null or interrupted_phase in
            ('staging','sealed','publication_started','observed')),
    constraint workshop_route_startup_publications_count_check check(
        candidate_count>=0
        and ((sealed_count is null and sealed_present_count is null)
             or (sealed_count>=0 and sealed_present_count between 0 and sealed_count))
    ),
    constraint workshop_route_startup_publications_seal_check check(
        (phase='staging' and sealed_count is null and sealed_present_count is null
            and projection_set_digest is null
            and publication_started_at is null and observed_selector is null
            and observed_effect_run_id is null
            and observed_projection_set_digest is null and observed_at is null)
        or
        (phase in ('sealed','publication_started') and sealed_count is not null
            and sealed_present_count is not null
            and candidate_count=sealed_count
            and projection_set_digest ~ '^sha256:[0-9a-f]{64}$'
            and observed_selector is null and observed_effect_run_id is null
            and observed_projection_set_digest is null and observed_at is null
            and ((phase='sealed' and publication_started_at is null)
                 or (phase='publication_started' and publication_started_at is not null)))
        or
        (phase='observed' and sealed_count is not null
            and sealed_present_count is not null
            and candidate_count=sealed_count
            and projection_set_digest ~ '^sha256:[0-9a-f]{64}$'
            and publication_started_at is not null
            and observed_selector=staging_selector
            and observed_effect_run_id=effect_run_id
            and observed_projection_set_digest=projection_set_digest
            and observed_at is not null)
        or
        (phase='quarantined' and interrupted_phase is not null
            and safe_error='startup_publication_outcome_unknown')
    ),
    constraint workshop_route_startup_publications_reconciliation_check check(
        (reconciliation_owner is null and reconciliation_token is null
            and reconciliation_expires_at is null)
        or (phase='quarantined' and reconciliation_owner is not null
            and reconciliation_token is not null
            and reconciliation_expires_at is not null)
    )
);

create table control.workshop_route_startup_runtime_reservations (
    effect_run_id uuid not null,
    workshop_id uuid not null,
    database_id uuid,
    database_ref text,
    public_hostname text,
    generation bigint not null,
    projection_digest text not null,
    disposition text not null,
    action text not null,
    paperless_mode text not null,
    paperless_hostname text,
    paperless_service_id uuid,
    paperless_service_health text,
    paperless_service_base_url text,
    paperless_service_desired_epoch integer,
    paperless_service_applied_epoch integer,
    paperless_runtime_spec jsonb,
    unresolved_operation boolean not null,
    route_fence_token bigint not null,
    runtime_outcome text,
    runtime_evidence jsonb,
    rendered_digest text,
    candidate_evidence jsonb,
    candidate_recorded_at timestamptz,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    primary key(effect_run_id,workshop_id),
    constraint workshop_route_startup_runtime_publication_fkey
        foreign key(effect_run_id)
        references control.workshop_route_startup_publications(effect_run_id)
        on delete restrict,
    constraint workshop_route_startup_runtime_route_reservation_fkey
        foreign key(effect_run_id,workshop_id,generation,projection_digest,route_fence_token)
        references control.workshop_route_effect_reservations(
            effect_run_id,workshop_id,generation,projection_digest,route_fence_token
        ) on delete restrict,
    constraint workshop_route_startup_runtime_database_fkey
        foreign key(database_id) references control.odoo_databases(id) on delete restrict,
    constraint workshop_route_startup_runtime_service_fkey
        foreign key(paperless_service_id)
        references control.service_instances(id) on delete restrict,
    constraint workshop_route_startup_runtime_projection_fkey
        foreign key(workshop_id,generation,projection_digest,disposition)
        references control.workshop_route_projections(
            workshop_id,generation,projection_digest,disposition
        ) on delete restrict,
    constraint workshop_route_startup_runtime_identity_check check(
        generation>0 and projection_digest ~ '^sha256:[0-9a-f]{64}$'
        and disposition in ('present','absent')
        and action in ('render','remove-absent')
        and route_fence_token>0
        and paperless_mode in ('absent','read_write','read_only')
        and ((paperless_mode='absent' and paperless_hostname is null)
             or (paperless_mode<>'absent' and paperless_hostname is not null))
        and ((paperless_mode='absent' and paperless_service_id is null
              and paperless_service_health is null
              and paperless_service_base_url is null
              and paperless_service_desired_epoch is null
              and paperless_service_applied_epoch is null
              and paperless_runtime_spec is null)
             or (paperless_mode<>'absent' and paperless_service_id is not null
              and paperless_service_health='ready'
              and paperless_service_base_url is not null
              and btrim(paperless_service_base_url)<>''
              and paperless_service_desired_epoch>0
              and paperless_service_applied_epoch between 0
                  and paperless_service_desired_epoch
              and jsonb_typeof(paperless_runtime_spec)='object'
              and pg_column_size(paperless_runtime_spec)<=16384))
        and ((disposition='present' and database_id is not null
              and database_ref is not null and btrim(database_ref)<>''
              and public_hostname is not null and btrim(public_hostname)<>''
              and action='render')
             or (disposition='absent' and database_id is null
              and database_ref is null and public_hostname is null
              and paperless_mode='absent' and paperless_hostname is null
              and action='remove-absent'))
    ),
    constraint workshop_route_startup_runtime_candidate_check check(
        (runtime_outcome is null and runtime_evidence is null
            and rendered_digest is null and candidate_evidence is null
            and candidate_recorded_at is null)
        or (runtime_outcome in ('ready','absent')
            and jsonb_typeof(runtime_evidence)='object'
            and rendered_digest ~ '^sha256:[0-9a-f]{64}$'
            and jsonb_typeof(candidate_evidence)='object'
            and candidate_recorded_at is not null
            and ((disposition='present' and runtime_outcome='ready')
                 or (disposition='absent' and runtime_outcome='absent')))
    )
);

-- Reject direct mutation even when a future broad grant accidentally reaches
-- these ledgers.  SECURITY DEFINER transition functions run as their owner and
-- are the sole runtime mutation interface.
revoke all on table control.workshop_route_startup_publications from public;
revoke all on table control.workshop_route_startup_runtime_reservations from public;

create function control.admit_staged_startup_route_publication(
    p_boot_id uuid,p_idempotency_key text,p_request_digest text,
    p_instance_owner uuid,p_execution_token uuid,p_global_lease_token uuid,
    p_route_lease_token uuid,p_ttl_seconds integer,p_protocol_version smallint
) returns table(
    outcome text,effect_run_id uuid,global_fence_token bigint,
    reserved_count integer,staging_selector text,prior_selector text,
    active_runtime_slot text,active_runtime_release_id text,
    active_runtime_subject_digest text,active_runtime_deployment_ref text,
    active_runtime_config_digest text,active_runtime_slot_version bigint,
    fleet_release_unresolved boolean,stored_response jsonb
)
language plpgsql security definer
set search_path=pg_catalog, control
as $function$
declare v_admission record; v_count bigint; v_bad bigint; v_staging text;
    v_active control.runtime_release_slots%rowtype; v_active_count bigint;
    v_release_unresolved boolean;
begin
    if p_protocol_version is distinct from 1
    then
        return query select 'invalid'::text,null::uuid,null::bigint,null::integer,
            null::text,null::text,null::text,null::text,null::text,null::text,
            null::text,null::bigint,null::boolean,null::jsonb; return;
    end if;
    select * into strict v_admission from control.admit_startup_route_rebuild(
        p_boot_id,p_idempotency_key,p_request_digest,p_instance_owner,
        p_execution_token,p_global_lease_token,p_route_lease_token,p_ttl_seconds
    );
    if v_admission.outcome<>'acquired' then
        return query select v_admission.outcome,v_admission.effect_run_id,
            v_admission.global_fence_token,v_admission.reserved_count,
            publication.staging_selector,publication.prior_selector,
            publication.active_runtime_slot,publication.active_runtime_release_id,
            publication.active_runtime_subject_digest,
            publication.active_runtime_deployment_ref,
            publication.active_runtime_config_digest,
            publication.active_runtime_slot_version,
            publication.fleet_release_unresolved,v_admission.stored_response
        from (select 1) singleton
        left join control.workshop_route_startup_publications publication
          on publication.effect_run_id=v_admission.effect_run_id;
        return;
    end if;
    v_staging:='generations/startup-'||v_admission.effect_run_id::text;
    select count(*) into v_bad
      from control.workshop_route_effect_reservations reservation
      left join control.workshop_route_projections projection
        on projection.workshop_id=reservation.workshop_id
       and projection.generation=reservation.generation
       and projection.projection_digest=reservation.projection_digest
       and projection.disposition=reservation.disposition
     where reservation.effect_run_id=v_admission.effect_run_id
       and (reservation.generation is null or projection.workshop_id is null
            or reservation.action not in ('render','remove-absent')
            or (projection.projection->>'paperless_mode'<>'absent' and not exists(
                select 1 from control.service_instances service
                 where service.workshop_id=reservation.workshop_id
                   and service.service='paperless' and service.health='ready'
                   and service.runtime_spec is not null
                   and jsonb_typeof(service.runtime_spec)='object'
                   and pg_column_size(service.runtime_spec)<=16384
                   and (service.runtime_spec->>'config_digest'
                        ~ '^[0-9a-f]{64}$') is true
            )));
    if v_bad<>0 then
        perform control.finish_startup_route_rebuild_v2(
            v_admission.effect_run_id,p_instance_owner,p_execution_token,
            p_global_lease_token,p_route_lease_token,
            v_admission.global_fence_token,'cancelled',null,null
        );
        return query select 'initialization_required',v_admission.effect_run_id,
            v_admission.global_fence_token,v_admission.reserved_count,
            null::text,null::text,null::text,null::text,null::text,null::text,
            null::text,null::bigint,null::boolean,null::jsonb; return;
    end if;
    select count(*) into v_active_count from control.runtime_release_slots
     where runtime_key='shared-odoo' and state='active';
    if v_active_count=1 then
        select * into strict v_active from control.runtime_release_slots
         where runtime_key='shared-odoo' and state='active' for share;
    elsif exists(
        select 1 from control.workshop_route_effect_reservations reservation
         where reservation.effect_run_id=v_admission.effect_run_id
           and reservation.disposition='present'
    ) then
        perform control.finish_startup_route_rebuild_v2(
            v_admission.effect_run_id,p_instance_owner,p_execution_token,
            p_global_lease_token,p_route_lease_token,
            v_admission.global_fence_token,'cancelled',null,null
        );
        return query select 'runtime_ambiguous',v_admission.effect_run_id,
            v_admission.global_fence_token,v_admission.reserved_count,
            null::text,null::text,null::text,null::text,null::text,null::text,
            null::text,null::bigint,null::boolean,null::jsonb; return;
    end if;
    if v_active_count=1 and (
        (v_active.evidence->>'runtime_deployment_ref') is null
        or btrim(v_active.evidence->>'runtime_deployment_ref')=''
        or (v_active.evidence->>'runtime_config_digest'
            ~ '^sha256:[0-9a-f]{64}$') is distinct from true
    ) then
        perform control.finish_startup_route_rebuild_v2(
            v_admission.effect_run_id,p_instance_owner,p_execution_token,
            p_global_lease_token,p_route_lease_token,
            v_admission.global_fence_token,'cancelled',null,null
        );
        return query select 'runtime_identity_missing',v_admission.effect_run_id,
            v_admission.global_fence_token,v_admission.reserved_count,
            null::text,null::text,null::text,null::text,null::text,null::text,
            null::text,null::bigint,null::boolean,null::jsonb; return;
    end if;
    select exists(select 1 from control.release_fleet_runs
        where state in ('preflighting','preparing','paused','activating'))
      into v_release_unresolved;
    insert into control.workshop_route_startup_publications(
        effect_run_id,protocol_version,original_instance_owner,
        original_execution_token,original_global_lease_token,
        original_route_lease_token,original_global_fence_token,
        staging_selector,active_runtime_slot,active_runtime_release_id,
        active_runtime_subject_digest,active_runtime_deployment_ref,
        active_runtime_config_digest,active_runtime_slot_version,
        fleet_release_unresolved
    ) values(v_admission.effect_run_id,1,p_instance_owner,p_execution_token,
        p_global_lease_token,p_route_lease_token,v_admission.global_fence_token,
        v_staging,v_active.slot,v_active.release_id,v_active.odoo_subject_digest,
        v_active.evidence->>'runtime_deployment_ref',
        v_active.evidence->>'runtime_config_digest',v_active.version,
        v_release_unresolved);
    insert into control.workshop_route_startup_runtime_reservations(
        effect_run_id,workshop_id,database_id,database_ref,public_hostname,
        generation,projection_digest,disposition,action,paperless_mode,
        paperless_hostname,paperless_service_id,paperless_service_health,
        paperless_service_base_url,paperless_service_desired_epoch,
        paperless_service_applied_epoch,paperless_runtime_spec,
        unresolved_operation,route_fence_token
    )
    select reservation.effect_run_id,reservation.workshop_id,
        case when reservation.disposition='present'
             then (projection.projection->>'database_id')::uuid end,
        case when reservation.disposition='present'
             then projection.projection->>'database_ref' end,
        case when reservation.disposition='present'
             then projection.projection->>'public_hostname' end,
        reservation.generation,reservation.projection_digest,
        reservation.disposition,reservation.action,
        projection.projection->>'paperless_mode',
        nullif(projection.projection->>'paperless_hostname',''),
        case when projection.projection->>'paperless_mode'<>'absent'
             then service.id end,
        case when projection.projection->>'paperless_mode'<>'absent'
             then service.health end,
        case when projection.projection->>'paperless_mode'<>'absent'
             then service.base_url end,
        case when projection.projection->>'paperless_mode'<>'absent'
             then service.desired_epoch end,
        case when projection.projection->>'paperless_mode'<>'absent'
             then service.applied_epoch end,
        case when projection.projection->>'paperless_mode'<>'absent'
             then service.runtime_spec end,
        (exists(select 1 from control.operations operation
                 where operation.workshop_id=reservation.workshop_id
                   and operation.state in ('pending','in_flight','awaiting_reconciliation')
                   and operation.kind in ('tenant.provision','tenant.reconcile',
                       'tenant.lifecycle','odoo.release.adopt'))
         or exists(select 1 from control.deployment_driver_operations driver_operation
                 where driver_operation.workshop_id=reservation.workshop_id
                   and driver_operation.state='in_progress')),
        reservation.route_fence_token
    from control.workshop_route_effect_reservations reservation
    join control.workshop_route_projections projection
      on projection.workshop_id=reservation.workshop_id
     and projection.generation=reservation.generation
     and projection.projection_digest=reservation.projection_digest
     and projection.disposition=reservation.disposition
    left join control.service_instances service
      on service.workshop_id=reservation.workshop_id
     and service.service='paperless'
    where reservation.effect_run_id=v_admission.effect_run_id
    order by reservation.workshop_id;
    get diagnostics v_count=row_count;
    if v_count<>v_admission.reserved_count then
        raise exception 'startup runtime snapshot drifted during admission'
            using errcode='40001';
    end if;
    return query select 'acquired',v_admission.effect_run_id,
        v_admission.global_fence_token,v_admission.reserved_count,
        v_staging,null::text,v_active.slot,v_active.release_id,
        v_active.odoo_subject_digest,v_active.evidence->>'runtime_deployment_ref',
        v_active.evidence->>'runtime_config_digest',v_active.version,
        v_release_unresolved,null::jsonb;
end
$function$;

create function control.record_staged_startup_route_prior(
    p_effect_run_id uuid,p_instance_owner uuid,p_execution_token uuid,
    p_global_lease_token uuid,p_route_lease_token uuid,p_global_fence_token bigint,
    p_observed_selector text,p_observed_directory_device bigint,
    p_observed_directory_inode bigint,p_observed_effect_run_id uuid,
    p_observed_projection_set_digest text
) returns boolean
language plpgsql security definer set search_path=pg_catalog, control
as $function$
declare v_changed bigint;
begin
    if p_observed_selector is null
       or p_observed_selector !~ '^generations/[A-Za-z0-9][A-Za-z0-9-]{0,63}$'
       or p_observed_directory_device<=0 or p_observed_directory_inode<=0
       or ((p_observed_effect_run_id is null)
            <> (p_observed_projection_set_digest is null))
       or (p_observed_projection_set_digest is not null
           and p_observed_projection_set_digest !~ '^sha256:[0-9a-f]{64}$')
       then return false; end if;
    perform 1
      from control.workshop_route_effect_runs run
      join control.deployment_driver_resource_leases global_lease
        on global_lease.resource_key='runtime/shared-odoo'
     where run.id=p_effect_run_id and run.kind='startup-rebuild'
       and run.state='reserved' and run.instance_owner=p_instance_owner
       and run.execution_token=p_execution_token
       and run.global_lease_token=p_global_lease_token
       and run.route_lease_token=p_route_lease_token
       and run.global_fence_token=p_global_fence_token
       and run.lease_expires_at>now()
       and global_lease.state='held'
       and global_lease.authority_kind='startup-rebuild'
       and global_lease.effect_run_id=p_effect_run_id
       and global_lease.lease_owner=p_instance_owner
       and global_lease.lease_token=p_global_lease_token
       and global_lease.fence_token=p_global_fence_token
       and global_lease.lease_expires_at>now()
     for update of run,global_lease;
    if not found then return false; end if;
    update control.workshop_route_startup_publications set
        prior_selector=p_observed_selector,
        prior_directory_device=p_observed_directory_device,
        prior_directory_inode=p_observed_directory_inode,
        prior_gateway_effect_run_id=p_observed_effect_run_id,
        prior_gateway_set_digest=p_observed_projection_set_digest,
        prior_recorded_at=now(),updated_at=now()
     where effect_run_id=p_effect_run_id and phase='staging'
       and prior_recorded_at is null
       and staging_selector<>p_observed_selector
       and original_instance_owner=p_instance_owner
       and original_execution_token=p_execution_token
       and original_global_lease_token=p_global_lease_token
       and original_route_lease_token=p_route_lease_token
       and original_global_fence_token=p_global_fence_token;
    get diagnostics v_changed=row_count; return v_changed=1;
end
$function$;

create function control.begin_staged_startup_route_publication(
    p_effect_run_id uuid,p_instance_owner uuid,p_execution_token uuid,
    p_global_lease_token uuid,p_route_lease_token uuid,p_global_fence_token bigint
) returns boolean
language plpgsql security definer set search_path=pg_catalog, control
as $function$
begin
    perform 1 from control.workshop_route_startup_publications publication
     where publication.effect_run_id=p_effect_run_id
       and publication.phase='staging'
       and publication.prior_recorded_at is not null
       and publication.original_instance_owner=p_instance_owner
       and publication.original_execution_token=p_execution_token
       and publication.original_global_lease_token=p_global_lease_token
       and publication.original_route_lease_token=p_route_lease_token
       and publication.original_global_fence_token=p_global_fence_token
     for update;
    if not found then return false; end if;
    return control.begin_startup_route_rebuild(
        p_effect_run_id,p_instance_owner,p_execution_token,p_global_lease_token,
        p_route_lease_token,p_global_fence_token
    );
end
$function$;

create function control.read_staged_startup_route_batch(
    p_effect_run_id uuid,p_instance_owner uuid,p_execution_token uuid,
    p_global_lease_token uuid,p_route_lease_token uuid,p_global_fence_token bigint,
    p_after_workshop uuid,p_limit integer
) returns table(
    workshop_id uuid,database_id uuid,database_ref text,public_hostname text,
    generation bigint,projection_digest text,disposition text,action text,
    paperless_mode text,paperless_hostname text,paperless_service_id uuid,
    paperless_service_health text,paperless_service_base_url text,
    paperless_service_desired_epoch integer,paperless_service_applied_epoch integer,
    paperless_runtime_spec jsonb,unresolved_operation boolean,
    route_fence_token bigint,projection jsonb
)
language sql stable security definer set search_path=pg_catalog, control
as $function$
    select runtime.workshop_id,runtime.database_id,runtime.database_ref,
        runtime.public_hostname,runtime.generation,runtime.projection_digest,
        runtime.disposition,runtime.action,runtime.paperless_mode,
        runtime.paperless_hostname,runtime.paperless_service_id,
        runtime.paperless_service_health,runtime.paperless_service_base_url,
        runtime.paperless_service_desired_epoch,runtime.paperless_service_applied_epoch,
        runtime.paperless_runtime_spec,runtime.unresolved_operation,
        runtime.route_fence_token,projection.projection
    from control.workshop_route_startup_publications publication
    join control.workshop_route_effect_runs run on run.id=publication.effect_run_id
    join control.deployment_driver_resource_leases global_lease
      on global_lease.resource_key='runtime/shared-odoo'
    join control.workshop_route_startup_runtime_reservations runtime
      on runtime.effect_run_id=publication.effect_run_id
    join control.workshop_route_application_leases route_lease
      on route_lease.workshop_id=runtime.workshop_id
    join control.workshop_route_projections projection
      on projection.workshop_id=runtime.workshop_id
     and projection.generation=runtime.generation
     and projection.projection_digest=runtime.projection_digest
     and projection.disposition=runtime.disposition
    where publication.effect_run_id=p_effect_run_id
      and publication.phase='staging'
      and publication.prior_recorded_at is not null
      and publication.last_completed_workshop is not distinct from p_after_workshop
      and run.kind='startup-rebuild' and run.state='effects_started'
      and run.instance_owner=p_instance_owner
      and run.execution_token=p_execution_token
      and run.global_lease_token=p_global_lease_token
      and run.route_lease_token=p_route_lease_token
      and run.global_fence_token=p_global_fence_token
      and run.lease_expires_at>now()
      and global_lease.state='held' and global_lease.authority_kind='startup-rebuild'
      and global_lease.effect_run_id=p_effect_run_id
      and global_lease.lease_owner=p_instance_owner
      and global_lease.lease_token=p_global_lease_token
      and global_lease.fence_token=p_global_fence_token
      and global_lease.lease_expires_at>now()
      and route_lease.state='held' and route_lease.authority_kind='startup-rebuild'
      and route_lease.effect_run_id=p_effect_run_id
      and route_lease.lease_owner=p_instance_owner
      and route_lease.lease_token=p_route_lease_token
      and route_lease.fence_token=runtime.route_fence_token
      and route_lease.generation=runtime.generation
      and route_lease.projection_digest=runtime.projection_digest
      and route_lease.lease_expires_at>now()
      and runtime.candidate_recorded_at is null
      and (p_after_workshop is null or runtime.workshop_id>p_after_workshop)
      and p_limit between 1 and 500
    order by runtime.workshop_id limit p_limit
$function$;

create function control.record_staged_startup_route_candidate(
    p_effect_run_id uuid,p_instance_owner uuid,p_execution_token uuid,
    p_global_lease_token uuid,p_route_lease_token uuid,p_global_fence_token bigint,
    p_expected_after_workshop uuid,p_workshop_id uuid,p_generation bigint,
    p_projection_digest text,p_disposition text,p_action text,
    p_route_fence_token bigint,p_runtime_outcome text,p_runtime_evidence jsonb,
    p_rendered_digest text,p_candidate_evidence jsonb
) returns boolean
language plpgsql security definer set search_path=pg_catalog, control
as $function$
declare v_publication control.workshop_route_startup_publications%rowtype;
    v_runtime control.workshop_route_startup_runtime_reservations%rowtype;
    v_next uuid; v_keys integer; v_changed bigint; v_legacy_evidence jsonb;
begin
    if p_rendered_digest !~ '^sha256:[0-9a-f]{64}$'
       or jsonb_typeof(p_runtime_evidence) is distinct from 'object'
       or jsonb_typeof(p_candidate_evidence) is distinct from 'object'
       or pg_column_size(p_runtime_evidence)>16384
       or pg_column_size(p_candidate_evidence)>16384 then return false; end if;
    select * into v_publication
      from control.workshop_route_startup_publications
     where effect_run_id=p_effect_run_id and phase='staging'
       and original_instance_owner=p_instance_owner
       and original_execution_token=p_execution_token
       and original_global_lease_token=p_global_lease_token
       and original_route_lease_token=p_route_lease_token
       and original_global_fence_token=p_global_fence_token
       and last_completed_workshop is not distinct from p_expected_after_workshop
     for update;
    if not found then return false; end if;
    if not control.assert_startup_route_workshop_fence(
        p_effect_run_id,p_instance_owner,p_execution_token,p_global_lease_token,
        p_route_lease_token,p_global_fence_token,p_workshop_id,p_generation,
        p_projection_digest,p_disposition,p_action,p_route_fence_token
    ) then return false; end if;
    select workshop_id into v_next
      from control.workshop_route_startup_runtime_reservations
     where effect_run_id=p_effect_run_id and candidate_recorded_at is null
       and (p_expected_after_workshop is null
            or workshop_id>p_expected_after_workshop)
     order by workshop_id limit 1;
    if v_next is distinct from p_workshop_id then return false; end if;
    select * into v_runtime
      from control.workshop_route_startup_runtime_reservations
     where effect_run_id=p_effect_run_id and workshop_id=p_workshop_id
       and generation=p_generation and projection_digest=p_projection_digest
       and disposition=p_disposition and action=p_action
       and route_fence_token=p_route_fence_token
       and candidate_recorded_at is null
     for update;
    if not found then return false; end if;
    select count(*) into v_keys from jsonb_object_keys(p_runtime_evidence);
    if v_keys<>9
       or p_runtime_evidence->'effect_run_id' is distinct from to_jsonb(p_effect_run_id)
       or p_runtime_evidence->'workshop_id' is distinct from to_jsonb(p_workshop_id)
       or p_runtime_evidence->'database_id' is distinct from
            coalesce(to_jsonb(v_runtime.database_id),'null'::jsonb)
       or p_runtime_evidence->'database_ref' is distinct from
            coalesce(to_jsonb(v_runtime.database_ref),'null'::jsonb)
       or p_runtime_evidence->'unresolved_operation' is distinct from
            to_jsonb(v_runtime.unresolved_operation)
       or p_runtime_evidence->>'outcome' is distinct from p_runtime_outcome
       or not (p_runtime_evidence ?& array[
            'odoo_runtime','paperless_runtime','verified_at'])
       or jsonb_typeof(p_runtime_evidence->'verified_at') is distinct from 'string'
       or ((v_runtime.disposition='present' and (
                p_runtime_outcome<>'ready'
                or p_runtime_evidence->'odoo_runtime' is distinct from
                    jsonb_build_object(
                        'slot',v_publication.active_runtime_slot,
                        'release_id',v_publication.active_runtime_release_id,
                        'subject_digest',v_publication.active_runtime_subject_digest,
                        'deployment_ref',v_publication.active_runtime_deployment_ref,
                        'config_digest',v_publication.active_runtime_config_digest,
                        'slot_version',v_publication.active_runtime_slot_version)
                or p_runtime_evidence->'paperless_runtime' is distinct from
                    case when v_runtime.paperless_mode='absent' then 'null'::jsonb
                    else jsonb_build_object(
                        'service_id',v_runtime.paperless_service_id,
                        'config_digest',v_runtime.paperless_runtime_spec->>'config_digest') end))
           or (v_runtime.disposition='absent' and (
                p_runtime_outcome<>'absent'
                or p_runtime_evidence->'odoo_runtime'<>'null'::jsonb
                or p_runtime_evidence->'paperless_runtime'<>'null'::jsonb))) then
        return false;
    end if;
    select count(*) into v_keys from jsonb_object_keys(p_candidate_evidence);
    if v_keys<>9
       or p_candidate_evidence->'effect_run_id' is distinct from to_jsonb(p_effect_run_id)
       or p_candidate_evidence->'workshop_id' is distinct from to_jsonb(p_workshop_id)
       or p_candidate_evidence->>'generation' is distinct from p_generation::text
       or p_candidate_evidence->>'projection_digest' is distinct from p_projection_digest
       or p_candidate_evidence->>'disposition' is distinct from p_disposition
       or p_candidate_evidence->>'action' is distinct from p_action
       or p_candidate_evidence->>'route_fence_token' is distinct from p_route_fence_token::text
       or p_candidate_evidence->>'rendered_digest' is distinct from p_rendered_digest
       or p_candidate_evidence->'runtime_evidence' is distinct from p_runtime_evidence then
        return false;
    end if;
    v_legacy_evidence:=jsonb_build_object(
        'effect_run_id',p_effect_run_id,'workshop_id',p_workshop_id,
        'generation',p_generation,'projection_digest',p_projection_digest,
        'disposition',p_disposition,'rendered_digest',p_rendered_digest,
        'route_fence_token',p_route_fence_token
    );
    update control.workshop_route_startup_runtime_reservations set
        runtime_outcome=p_runtime_outcome,runtime_evidence=p_runtime_evidence,
        rendered_digest=p_rendered_digest,candidate_evidence=p_candidate_evidence,
        candidate_recorded_at=now(),updated_at=now()
    where effect_run_id=p_effect_run_id and workshop_id=p_workshop_id
      and candidate_recorded_at is null;
    get diagnostics v_changed=row_count; if v_changed<>1 then return false; end if;
    update control.workshop_route_effect_reservations set state='candidate',
        rendered_digest=p_rendered_digest,evidence=v_legacy_evidence,updated_at=now()
    where effect_run_id=p_effect_run_id and workshop_id=p_workshop_id
      and state='reserved';
    get diagnostics v_changed=row_count;
    if v_changed<>1 then raise exception 'startup candidate ledger drifted'
        using errcode='40001'; end if;
    update control.workshop_route_startup_publications set
        last_completed_workshop=p_workshop_id,candidate_count=candidate_count+1,
        updated_at=now() where effect_run_id=p_effect_run_id;
    return true;
end
$function$;

create function control.seal_staged_startup_route_publication(
    p_effect_run_id uuid,p_instance_owner uuid,p_execution_token uuid,
    p_global_lease_token uuid,p_route_lease_token uuid,p_global_fence_token bigint,
    p_candidate_count integer,p_projection_set_digest text
) returns boolean
language plpgsql security definer set search_path=pg_catalog, control
as $function$
declare v_publication control.workshop_route_startup_publications%rowtype;
    v_frozen bigint; v_current bigint; v_changed bigint; v_last uuid;
    v_active_count bigint; v_release_unresolved boolean;
    v_computed_set_digest text; v_present bigint;
begin
    if p_candidate_count<0
       or p_projection_set_digest !~ '^sha256:[0-9a-f]{64}$' then return false; end if;
    perform 1 from control.deployment_driver_resource_leases
     where resource_key='runtime/shared-odoo' for update;
    perform 1 from control.workshop_route_application_leases
     order by workshop_id for update;
    perform 1 from control.runtime_release_slots
     where runtime_key='shared-odoo' order by slot for share;
    perform 1 from control.release_fleet_runs
     where state in ('preflighting','preparing','paused','activating')
     order by id for share;
    perform 1 from control.service_instances
     where service='paperless' order by workshop_id for share;
    select * into v_publication from control.workshop_route_startup_publications
     where effect_run_id=p_effect_run_id and phase='staging'
       and original_instance_owner=p_instance_owner
       and original_execution_token=p_execution_token
       and original_global_lease_token=p_global_lease_token
       and original_route_lease_token=p_route_lease_token
       and original_global_fence_token=p_global_fence_token for update;
    if not found or not control.assert_startup_route_global_fence(
        p_effect_run_id,p_instance_owner,p_execution_token,p_global_lease_token,
        p_global_fence_token) then return false; end if;
    select count(*) into v_frozen
      from control.workshop_route_startup_runtime_reservations
     where effect_run_id=p_effect_run_id and candidate_recorded_at is not null;
    select workshop_id into v_last
      from control.workshop_route_startup_runtime_reservations
     where effect_run_id=p_effect_run_id and candidate_recorded_at is not null
     order by workshop_id desc limit 1;
    select count(*) into v_present
      from control.workshop_route_startup_runtime_reservations runtime
     where runtime.effect_run_id=p_effect_run_id
       and runtime.candidate_recorded_at is not null
       and runtime.disposition='present';
    select 'sha256:'||encode(sha256(
        convert_to('mb-startup-route-generation-v1','UTF8')||decode('00','hex')||
        coalesce(string_agg(
            uuid_send(runtime.workshop_id)||int8send(runtime.generation)||
            int4send(octet_length(runtime.projection_digest))||
                convert_to(runtime.projection_digest,'UTF8')||
            int4send(octet_length(runtime.disposition))||
                convert_to(runtime.disposition,'UTF8')||
            int4send(octet_length(runtime.action))||
                convert_to(runtime.action,'UTF8')||
            int4send(octet_length(runtime.rendered_digest))||
                convert_to(runtime.rendered_digest,'UTF8')
            ,''::bytea order by runtime.workshop_id),''::bytea)
        ),'hex')
      into v_computed_set_digest
      from control.workshop_route_startup_runtime_reservations runtime
     where runtime.effect_run_id=p_effect_run_id
       and runtime.candidate_recorded_at is not null;
    select count(*) into v_current
      from control.workshop_route_application_leases;
    select count(*) into v_active_count from control.runtime_release_slots
     where runtime_key='shared-odoo' and state='active';
    select exists(select 1 from control.release_fleet_runs
        where state in ('preflighting','preparing','paused','activating'))
      into v_release_unresolved;
    if v_frozen<>p_candidate_count
       or v_computed_set_digest is distinct from p_projection_set_digest
       or v_publication.candidate_count<>p_candidate_count
       or v_current<>p_candidate_count
       or v_publication.last_completed_workshop is distinct from v_last
       or v_publication.fleet_release_unresolved is distinct from v_release_unresolved
       or ((v_publication.active_runtime_slot is null and v_active_count<>0)
           or (v_publication.active_runtime_slot is not null and (
                v_active_count<>1 or not exists(
                    select 1 from control.runtime_release_slots runtime
                     where runtime.runtime_key='shared-odoo'
                       and runtime.state='active'
                       and runtime.slot=v_publication.active_runtime_slot
                       and runtime.release_id=v_publication.active_runtime_release_id
                       and runtime.odoo_subject_digest=
                            v_publication.active_runtime_subject_digest
                       and runtime.evidence->>'runtime_deployment_ref'=
                            v_publication.active_runtime_deployment_ref
                       and runtime.evidence->>'runtime_config_digest'=
                            v_publication.active_runtime_config_digest
                       and runtime.version=v_publication.active_runtime_slot_version
                ))))
       or exists(
          select 1 from control.workshop_route_startup_runtime_reservations runtime
           where runtime.effect_run_id=p_effect_run_id
             and runtime.paperless_mode<>'absent'
             and not exists(
                select 1 from control.service_instances service
                 where service.id=runtime.paperless_service_id
                   and service.workshop_id=runtime.workshop_id
                   and service.service='paperless'
                   and service.health=runtime.paperless_service_health
                   and service.base_url=runtime.paperless_service_base_url
                   and service.desired_epoch=runtime.paperless_service_desired_epoch
                   and service.applied_epoch=runtime.paperless_service_applied_epoch
                   and service.runtime_spec=runtime.paperless_runtime_spec
             )
       )
       or exists(
          select 1 from control.workshop_route_application_leases lease
          full join control.workshop_route_startup_runtime_reservations runtime
            on runtime.effect_run_id=p_effect_run_id
           and runtime.workshop_id=lease.workshop_id
          left join control.workshop_route_projection_state projection_state
            on projection_state.workshop_id=runtime.workshop_id
          where lease.workshop_id is null or runtime.workshop_id is null
             or lease.state<>'held' or lease.authority_kind<>'startup-rebuild'
             or lease.effect_run_id is distinct from p_effect_run_id
             or lease.lease_owner is distinct from p_instance_owner
             or lease.lease_token is distinct from p_route_lease_token
             or lease.fence_token is distinct from runtime.route_fence_token
             or lease.generation is distinct from runtime.generation
             or lease.projection_digest is distinct from runtime.projection_digest
             or lease.lease_expires_at<=now()
             or projection_state.desired_generation is distinct from runtime.generation
             or projection_state.desired_digest is distinct from runtime.projection_digest
             or projection_state.desired_disposition is distinct from runtime.disposition
             or runtime.candidate_recorded_at is null
       ) then return false; end if;
    update control.workshop_route_startup_publications set phase='sealed',
        sealed_count=p_candidate_count,
        sealed_present_count=v_present::integer,
        projection_set_digest=p_projection_set_digest,
        updated_at=now() where effect_run_id=p_effect_run_id and phase='staging';
    get diagnostics v_changed=row_count; return v_changed=1;
end
$function$;

create function control.start_staged_startup_route_publication(
    p_effect_run_id uuid,p_instance_owner uuid,p_execution_token uuid,
    p_global_lease_token uuid,p_route_lease_token uuid,p_global_fence_token bigint,
    p_projection_set_digest text
) returns boolean
language plpgsql security definer set search_path=pg_catalog, control
as $function$
declare v_changed bigint;
begin
    if not control.assert_startup_route_global_fence(
        p_effect_run_id,p_instance_owner,p_execution_token,p_global_lease_token,
        p_global_fence_token) then return false; end if;
    update control.workshop_route_startup_publications set
        phase='publication_started',publication_started_at=now(),updated_at=now()
    where effect_run_id=p_effect_run_id and phase='sealed'
      and original_instance_owner=p_instance_owner
      and original_execution_token=p_execution_token
      and original_global_lease_token=p_global_lease_token
      and original_route_lease_token=p_route_lease_token
      and original_global_fence_token=p_global_fence_token
      and projection_set_digest=p_projection_set_digest;
    get diagnostics v_changed=row_count; return v_changed=1;
end
$function$;

create function control.observe_staged_startup_route_publication(
    p_effect_run_id uuid,p_instance_owner uuid,p_execution_token uuid,
    p_global_lease_token uuid,p_route_lease_token uuid,p_global_fence_token bigint,
    p_observed_selector text,p_observed_effect_run_id uuid,
    p_observed_projection_set_digest text
) returns boolean
language plpgsql security definer set search_path=pg_catalog, control
as $function$
declare v_changed bigint;
begin
    if not control.assert_startup_route_global_fence(
        p_effect_run_id,p_instance_owner,p_execution_token,p_global_lease_token,
        p_global_fence_token) then return false; end if;
    update control.workshop_route_startup_publications set phase='observed',
        observed_selector=p_observed_selector,
        observed_effect_run_id=p_observed_effect_run_id,
        observed_projection_set_digest=p_observed_projection_set_digest,
        observed_at=now(),updated_at=now()
    where effect_run_id=p_effect_run_id and phase='publication_started'
      and original_instance_owner=p_instance_owner
      and original_execution_token=p_execution_token
      and original_global_lease_token=p_global_lease_token
      and original_route_lease_token=p_route_lease_token
      and original_global_fence_token=p_global_fence_token
      and staging_selector=p_observed_selector
      and effect_run_id=p_observed_effect_run_id
      and projection_set_digest=p_observed_projection_set_digest;
    get diagnostics v_changed=row_count; return v_changed=1;
end
$function$;

create function control.finish_staged_startup_route_publication(
    p_effect_run_id uuid,p_instance_owner uuid,p_execution_token uuid,
    p_global_lease_token uuid,p_route_lease_token uuid,p_global_fence_token bigint,
    p_response jsonb
) returns boolean
language plpgsql security definer set search_path=pg_catalog, control
as $function$
declare v_publication control.workshop_route_startup_publications%rowtype;
    v_keys bigint; v_finished boolean;
begin
    select * into v_publication from control.workshop_route_startup_publications
     where effect_run_id=p_effect_run_id and phase='observed'
       and original_instance_owner=p_instance_owner
       and original_execution_token=p_execution_token
       and original_global_lease_token=p_global_lease_token
       and original_route_lease_token=p_route_lease_token
       and original_global_fence_token=p_global_fence_token for update;
    if not found or jsonb_typeof(p_response) is distinct from 'object' then return false; end if;
    select count(*) into v_keys from jsonb_object_keys(p_response);
    if v_keys<>5
       or p_response->>'effect_run_id' is distinct from p_effect_run_id::text
       or p_response->>'global_fence_token' is distinct from p_global_fence_token::text
       or p_response->>'workshop_count' is distinct from v_publication.sealed_count::text
       or p_response->>'projection_set_digest' is distinct from
            v_publication.projection_set_digest
       or (p_response->>'gateway_reload_digest' ~ '^sha256:[0-9a-f]{64}$')
            is distinct from true then return false; end if;
    v_finished:=control.finish_startup_route_rebuild_v2(
        p_effect_run_id,p_instance_owner,p_execution_token,p_global_lease_token,
        p_route_lease_token,p_global_fence_token,'succeeded',p_response,null
    );
    if not v_finished then return false; end if;
    update control.workshop_route_startup_publications set finalized_at=now(),updated_at=now()
     where effect_run_id=p_effect_run_id;
    return true;
end
$function$;

create function control.abort_staged_startup_route_publication(
    p_effect_run_id uuid,p_instance_owner uuid,p_execution_token uuid,
    p_global_lease_token uuid,p_route_lease_token uuid,p_global_fence_token bigint,
    p_observed_selector text,p_observed_directory_device bigint,
    p_observed_directory_inode bigint,p_observed_effect_run_id uuid,
    p_observed_projection_set_digest text
) returns boolean
language plpgsql security definer set search_path=pg_catalog, control
as $function$
declare v_publication control.workshop_route_startup_publications%rowtype;
    v_expected bigint; v_exact bigint; v_changed bigint;
begin
    perform 1 from control.deployment_driver_resource_leases global_lease
     where global_lease.resource_key='runtime/shared-odoo'
       and global_lease.state='held'
       and global_lease.authority_kind='startup-rebuild'
       and global_lease.effect_run_id=p_effect_run_id
       and global_lease.lease_owner=p_instance_owner
       and global_lease.lease_token=p_global_lease_token
       and global_lease.fence_token=p_global_fence_token
     for update;
    if not found then return false; end if;
    perform 1 from control.workshop_route_application_leases route_lease
     where route_lease.effect_run_id=p_effect_run_id
     order by route_lease.workshop_id for update;
    perform 1 from control.workshop_route_effect_runs run
     where run.id=p_effect_run_id and run.kind='startup-rebuild'
       and run.state in ('reserved','effects_started')
       and run.instance_owner=p_instance_owner
       and run.execution_token=p_execution_token
       and run.global_lease_token=p_global_lease_token
       and run.route_lease_token=p_route_lease_token
       and run.global_fence_token=p_global_fence_token
     for update;
    if not found then return false; end if;
    select * into v_publication from control.workshop_route_startup_publications
     where effect_run_id=p_effect_run_id and phase in ('staging','sealed')
       and finalized_at is null and prior_recorded_at is not null
       and original_instance_owner=p_instance_owner
       and original_execution_token=p_execution_token
       and original_global_lease_token=p_global_lease_token
       and original_route_lease_token=p_route_lease_token
       and original_global_fence_token=p_global_fence_token for update;
    if not found or v_publication.prior_selector<>p_observed_selector
       or v_publication.prior_directory_device<>p_observed_directory_device
       or v_publication.prior_directory_inode<>p_observed_directory_inode
       or v_publication.prior_gateway_effect_run_id is distinct from p_observed_effect_run_id
       or v_publication.prior_gateway_set_digest is distinct from
            p_observed_projection_set_digest then return false; end if;
    select count(*) into v_expected
      from control.workshop_route_effect_reservations reservation
     where reservation.effect_run_id=p_effect_run_id;
    select count(*) into v_exact
      from control.workshop_route_effect_reservations reservation
      join control.workshop_route_application_leases route_lease
        on route_lease.workshop_id=reservation.workshop_id
       and route_lease.state='held'
       and route_lease.authority_kind='startup-rebuild'
       and route_lease.effect_run_id=p_effect_run_id
       and route_lease.lease_owner=p_instance_owner
       and route_lease.lease_token=p_route_lease_token
       and route_lease.fence_token=reservation.route_fence_token
       and route_lease.generation is not distinct from reservation.generation
       and route_lease.projection_digest is not distinct from
            reservation.projection_digest
     where reservation.effect_run_id=p_effect_run_id;
    if v_exact<>v_expected then return false; end if;
    -- Candidate rows may exist, so the legacy cancellation primitive is too
    -- narrow.  This transition is safe only because exact observation proves
    -- that publication never selected the candidate.
    update control.workshop_route_application_leases lease set
        state=reservation.prior_lease_state,authority_kind=null,effect_run_id=null,
        driver_operation_id=null,generation=null,projection_digest=null,
        lease_owner=null,lease_token=null,lease_expires_at=null,heartbeat_at=null,
        updated_at=now()
    from control.workshop_route_effect_reservations reservation
    where reservation.effect_run_id=p_effect_run_id
      and reservation.workshop_id=lease.workshop_id
      and lease.state='held' and lease.effect_run_id=p_effect_run_id;
    update control.workshop_route_effect_runs set state='cancelled',
        instance_owner=null,execution_token=null,global_lease_token=null,
        route_lease_token=null,lease_expires_at=null,finished_at=now(),updated_at=now()
     where id=p_effect_run_id and state in ('reserved','effects_started');
    get diagnostics v_changed=row_count;
    if v_changed<>1 then raise exception 'startup abort run fence was lost'
        using errcode='40001'; end if;
    update control.workshop_route_effect_reservations set state='restored',updated_at=now()
     where effect_run_id=p_effect_run_id and state in ('reserved','candidate');
    update control.deployment_driver_resource_leases set state='idle',
        authority_kind=null,effect_run_id=null,driver_operation_id=null,
        lease_owner=null,lease_token=null,lease_expires_at=null,heartbeat_at=null,
        updated_at=now()
     where resource_key='runtime/shared-odoo' and state='held'
       and effect_run_id=p_effect_run_id and fence_token=p_global_fence_token;
    get diagnostics v_changed=row_count;
    if v_changed<>1 then raise exception 'startup abort global fence was lost'
        using errcode='40001'; end if;
    update control.workshop_route_startup_publications set finalized_at=now(),updated_at=now()
     where effect_run_id=p_effect_run_id;
    return true;
end
$function$;

create function control.claim_interrupted_startup_route_publication(
    p_reconciliation_owner uuid,p_reconciliation_token uuid,p_ttl_seconds integer
) returns table(
    outcome text,effect_run_id uuid,interrupted_phase text,
    original_instance_owner uuid,original_global_fence_token bigint,
    prior_selector text,prior_directory_device bigint,prior_directory_inode bigint,
    staging_selector text,prior_gateway_effect_run_id uuid,
    prior_gateway_set_digest text,sealed_count integer,sealed_present_count integer,
    projection_set_digest text
)
language plpgsql security definer set search_path=pg_catalog, control
as $function$
declare v_publication control.workshop_route_startup_publications%rowtype;
    v_run control.workshop_route_effect_runs%rowtype;
begin
    if p_reconciliation_owner is null or p_reconciliation_token is null
       or p_ttl_seconds<60 or p_ttl_seconds>1200 then
        return query select 'invalid'::text,null::uuid,null::text,null::uuid,
            null::bigint,null::text,null::bigint,null::bigint,null::text,null::uuid,null::text,
            null::integer,null::integer,null::text; return;
    end if;
    perform 1 from control.deployment_driver_resource_leases
     where resource_key='runtime/shared-odoo' for update;
    select publication.* into v_publication
      from control.workshop_route_startup_publications publication
      join control.workshop_route_effect_runs run on run.id=publication.effect_run_id
     where publication.finalized_at is null
       and ((publication.phase='quarantined'
              and (publication.reconciliation_expires_at is null
                   or publication.reconciliation_expires_at<=now()))
            or (publication.phase in ('staging','sealed','publication_started','observed')
              and run.state in ('reserved','effects_started')
              and run.lease_expires_at<=now()))
     order by publication.created_at,publication.effect_run_id limit 1
     for update of publication;
    if not found then
        return query select 'none'::text,null::uuid,null::text,null::uuid,
            null::bigint,null::text,null::bigint,null::bigint,null::text,null::uuid,null::text,
            null::integer,null::integer,null::text; return;
    end if;
    select run.* into strict v_run from control.workshop_route_effect_runs run
     where run.id=v_publication.effect_run_id for update;
    perform 1 from control.workshop_route_application_leases route_lease
     where route_lease.effect_run_id=v_publication.effect_run_id
     order by route_lease.workshop_id for update;
    if v_publication.phase<>'quarantined' then
        update control.workshop_route_startup_publications publication set
            interrupted_phase=publication.phase,phase='quarantined',
            safe_error='startup_publication_outcome_unknown',updated_at=now()
         where publication.effect_run_id=v_publication.effect_run_id;
        update control.workshop_route_effect_reservations reservation
           set state='quarantined',updated_at=now()
         where reservation.effect_run_id=v_publication.effect_run_id;
        update control.workshop_route_application_leases route_lease set state='quarantined',
            lease_token=null,lease_expires_at=null,quarantined_at=now(),
            safe_error='runtime_outcome_unknown',updated_at=now()
         where route_lease.effect_run_id=v_publication.effect_run_id
           and route_lease.state='held';
        update control.workshop_route_effect_runs run set state='quarantined',
            instance_owner=null,execution_token=null,global_lease_token=null,
            route_lease_token=null,lease_expires_at=null,
            safe_error='runtime_outcome_unknown',finished_at=now(),updated_at=now()
         where run.id=v_publication.effect_run_id;
        update control.deployment_driver_resource_leases global_lease set state='quarantined',
            lease_token=null,lease_expires_at=null,quarantined_at=now(),
            safe_error='runtime_outcome_unknown',updated_at=now()
         where global_lease.resource_key='runtime/shared-odoo'
           and global_lease.effect_run_id=v_publication.effect_run_id;
    end if;
    update control.workshop_route_startup_publications publication set
        reconciliation_owner=p_reconciliation_owner,
        reconciliation_token=p_reconciliation_token,
        reconciliation_expires_at=now()+make_interval(secs=>p_ttl_seconds),
        updated_at=now() where publication.effect_run_id=v_publication.effect_run_id
    returning * into v_publication;
    return query select 'acquired',v_publication.effect_run_id,
        v_publication.interrupted_phase,v_publication.original_instance_owner,
        v_publication.original_global_fence_token,v_publication.prior_selector,
        v_publication.prior_directory_device,v_publication.prior_directory_inode,
        v_publication.staging_selector,v_publication.prior_gateway_effect_run_id,
        v_publication.prior_gateway_set_digest,v_publication.sealed_count,
        v_publication.sealed_present_count,v_publication.projection_set_digest;
end
$function$;

create function control.finish_interrupted_startup_route_publication(
    p_effect_run_id uuid,p_reconciliation_owner uuid,p_reconciliation_token uuid,
    p_outcome text,p_observed_selector text,p_observed_directory_device bigint,
    p_observed_directory_inode bigint,p_observed_effect_run_id uuid,
    p_observed_projection_set_digest text,p_response jsonb
) returns boolean
language plpgsql security definer set search_path=pg_catalog, control
as $function$
declare v_publication control.workshop_route_startup_publications%rowtype;
    v_keys bigint; v_changed bigint;
begin
    if p_outcome not in ('candidate','prior','unstarted','inconclusive') then
        return false;
    end if;
    perform 1 from control.deployment_driver_resource_leases
     where resource_key='runtime/shared-odoo' for update;
    select * into v_publication from control.workshop_route_startup_publications
     where effect_run_id=p_effect_run_id and phase='quarantined'
       and reconciliation_owner=p_reconciliation_owner
       and reconciliation_token=p_reconciliation_token
       and reconciliation_expires_at>now() for update;
    if not found then return false; end if;
    perform 1 from control.workshop_route_application_leases
     where effect_run_id=p_effect_run_id order by workshop_id for update;
    if p_outcome='inconclusive' then
        if p_observed_selector is not null
           or p_observed_directory_device is not null
           or p_observed_directory_inode is not null
           or p_observed_effect_run_id is not null
           or p_observed_projection_set_digest is not null
           or p_response is not null then return false; end if;
        update control.workshop_route_startup_publications set
            reconciliation_owner=null,reconciliation_token=null,
            reconciliation_expires_at=null,updated_at=now()
         where effect_run_id=p_effect_run_id;
        return true;
    end if;
    if p_outcome='candidate' then
        if v_publication.interrupted_phase not in ('publication_started','observed')
           or v_publication.sealed_count is null
           or p_observed_selector is distinct from v_publication.staging_selector
           or p_observed_directory_device<=0
           or p_observed_directory_inode<=0
           or p_observed_effect_run_id is distinct from p_effect_run_id
           or p_observed_projection_set_digest is distinct from
                v_publication.projection_set_digest
           or jsonb_typeof(p_response) is distinct from 'object' then return false; end if;
        select count(*) into v_keys from jsonb_object_keys(p_response);
        if v_keys<>5
           or p_response->>'effect_run_id' is distinct from p_effect_run_id::text
           or p_response->>'global_fence_token' is distinct from
                v_publication.original_global_fence_token::text
           or p_response->>'workshop_count' is distinct from
                v_publication.sealed_count::text
           or p_response->>'projection_set_digest' is distinct from
                v_publication.projection_set_digest
           or (p_response->>'gateway_reload_digest' ~ '^sha256:[0-9a-f]{64}$')
                is distinct from true
           or exists(
              select 1 from control.workshop_route_startup_runtime_reservations runtime
              join control.workshop_route_projection_state projection_state
                on projection_state.workshop_id=runtime.workshop_id
             where runtime.effect_run_id=p_effect_run_id
               and (runtime.candidate_recorded_at is null
                    or projection_state.desired_generation is distinct from runtime.generation
                    or projection_state.desired_digest is distinct from runtime.projection_digest
                    or projection_state.desired_disposition is distinct from runtime.disposition)
           ) then return false; end if;
        update control.workshop_route_projection_state projection_state set
            applied_generation=runtime.generation,
            applied_digest=runtime.projection_digest,
            applied_disposition=runtime.disposition,
            applied_rendered_digest=runtime.rendered_digest,
            applied_driver_operation_id=null,applied_effect_run_id=p_effect_run_id,
            applied_fence_token=runtime.route_fence_token,updated_at=now()
        from control.workshop_route_startup_runtime_reservations runtime
        where runtime.effect_run_id=p_effect_run_id
          and runtime.workshop_id=projection_state.workshop_id;
        update control.workshop_route_effect_reservations set state='succeeded',updated_at=now()
         where effect_run_id=p_effect_run_id;
        update control.workshop_route_effect_runs set state='succeeded',response=p_response,
            safe_error=null,finished_at=coalesce(finished_at,now()),updated_at=now()
         where id=p_effect_run_id and state='quarantined';
    elsif p_outcome='prior' then
        if v_publication.interrupted_phase not in
                ('staging','sealed','publication_started') then return false; end if;
        if p_observed_selector is distinct from v_publication.prior_selector
           or p_observed_directory_device is distinct from
                v_publication.prior_directory_device
           or p_observed_directory_inode is distinct from
                v_publication.prior_directory_inode
           or p_observed_effect_run_id is distinct from
                v_publication.prior_gateway_effect_run_id
           or p_observed_projection_set_digest is distinct from
                v_publication.prior_gateway_set_digest
           or p_response is not null then return false; end if;
        update control.workshop_route_effect_runs set state='cancelled',response=null,
            safe_error=null,finished_at=coalesce(finished_at,now()),updated_at=now()
         where id=p_effect_run_id and state='quarantined';
        update control.workshop_route_effect_reservations set state='restored',updated_at=now()
         where effect_run_id=p_effect_run_id and state='quarantined';
    else
        if v_publication.interrupted_phase<>'staging'
           or v_publication.prior_recorded_at is not null
           or v_publication.prior_selector is not null
           or v_publication.prior_directory_device is not null
           or v_publication.prior_directory_inode is not null
           or v_publication.prior_gateway_effect_run_id is not null
           or v_publication.prior_gateway_set_digest is not null
           or v_publication.candidate_count<>0
           or v_publication.last_completed_workshop is not null
           or v_publication.sealed_count is not null
           or v_publication.sealed_present_count is not null
           or v_publication.projection_set_digest is not null
           or v_publication.publication_started_at is not null
           or p_observed_selector is not null
           or p_observed_directory_device is not null
           or p_observed_directory_inode is not null
           or p_observed_effect_run_id is not null
           or p_observed_projection_set_digest is not null
           or p_response is not null then return false; end if;
        update control.workshop_route_effect_runs set state='cancelled',response=null,
            safe_error=null,finished_at=coalesce(finished_at,now()),updated_at=now()
         where id=p_effect_run_id and state='quarantined';
        update control.workshop_route_effect_reservations set state='restored',updated_at=now()
         where effect_run_id=p_effect_run_id and state='quarantined';
    end if;
    update control.workshop_route_application_leases lease set
        state=case when p_outcome='candidate' then 'idle'
                   else reservation.prior_lease_state end,
        initialization_required=case when p_outcome='candidate' then false
                   else reservation.prior_lease_state='uninitialized' end,
        authority_kind=null,effect_run_id=null,driver_operation_id=null,
        generation=null,projection_digest=null,lease_owner=null,lease_token=null,
        lease_expires_at=null,heartbeat_at=null,quarantined_at=null,
        safe_error=null,updated_at=now()
    from control.workshop_route_effect_reservations reservation
    where reservation.effect_run_id=p_effect_run_id
      and reservation.workshop_id=lease.workshop_id
      and lease.state='quarantined' and lease.fence_token=reservation.route_fence_token;
    update control.deployment_driver_resource_leases set state='idle',
        authority_kind=null,effect_run_id=null,driver_operation_id=null,
        lease_owner=null,lease_token=null,lease_expires_at=null,heartbeat_at=null,
        quarantined_at=null,safe_error=null,updated_at=now()
     where resource_key='runtime/shared-odoo' and state='quarantined'
       and authority_kind='startup-rebuild' and effect_run_id=p_effect_run_id
       and fence_token=v_publication.original_global_fence_token;
    get diagnostics v_changed=row_count;
    if v_changed<>1 then raise exception 'startup publication reconciliation fence was lost'
        using errcode='40001'; end if;
    update control.workshop_route_startup_publications set
        phase=case when p_outcome='candidate' then 'observed' else interrupted_phase end,
        observed_selector=case when p_outcome='candidate' then p_observed_selector end,
        observed_effect_run_id=case when p_outcome='candidate' then p_effect_run_id end,
        observed_projection_set_digest=case when p_outcome='candidate'
            then projection_set_digest end,
        observed_at=case when p_outcome='candidate' then now() end,
        finalized_at=now(),safe_error=null,reconciliation_owner=null,
        reconciliation_token=null,reconciliation_expires_at=null,updated_at=now()
     where effect_run_id=p_effect_run_id;
    return true;
end
$function$;

revoke all on function control.admit_staged_startup_route_publication(
    uuid,text,text,uuid,uuid,uuid,uuid,integer,smallint
) from public;
revoke all on function control.record_staged_startup_route_prior(
    uuid,uuid,uuid,uuid,uuid,bigint,text,bigint,bigint,uuid,text
) from public;
revoke all on function control.begin_staged_startup_route_publication(
    uuid,uuid,uuid,uuid,uuid,bigint
) from public;
revoke all on function control.read_staged_startup_route_batch(
    uuid,uuid,uuid,uuid,uuid,bigint,uuid,integer
) from public;
revoke all on function control.record_staged_startup_route_candidate(
    uuid,uuid,uuid,uuid,uuid,bigint,uuid,uuid,bigint,text,text,text,bigint,text,jsonb,text,jsonb
) from public;
revoke all on function control.seal_staged_startup_route_publication(
    uuid,uuid,uuid,uuid,uuid,bigint,integer,text
) from public;
revoke all on function control.start_staged_startup_route_publication(
    uuid,uuid,uuid,uuid,uuid,bigint,text
) from public;
revoke all on function control.observe_staged_startup_route_publication(
    uuid,uuid,uuid,uuid,uuid,bigint,text,uuid,text
) from public;
revoke all on function control.finish_staged_startup_route_publication(
    uuid,uuid,uuid,uuid,uuid,bigint,jsonb
) from public;
revoke all on function control.abort_staged_startup_route_publication(
    uuid,uuid,uuid,uuid,uuid,bigint,text,bigint,bigint,uuid,text
) from public;
revoke all on function control.claim_interrupted_startup_route_publication(
    uuid,uuid,integer
) from public;
revoke all on function control.finish_interrupted_startup_route_publication(
    uuid,uuid,uuid,text,text,bigint,bigint,uuid,text,jsonb
) from public;

do $migration$
begin
    if exists(select 1 from pg_roles where rolname='control_driver_ledger') then
        revoke insert,update,delete on
            control.workshop_route_startup_publications,
            control.workshop_route_startup_runtime_reservations
            from control_driver_ledger;
        grant select on control.workshop_route_startup_publications,
            control.workshop_route_startup_runtime_reservations
            to control_driver_ledger;
        grant execute on function control.admit_staged_startup_route_publication(
            uuid,text,text,uuid,uuid,uuid,uuid,integer,smallint
        ), control.record_staged_startup_route_prior(
            uuid,uuid,uuid,uuid,uuid,bigint,text,bigint,bigint,uuid,text
        ), control.begin_staged_startup_route_publication(
            uuid,uuid,uuid,uuid,uuid,bigint
        ), control.read_staged_startup_route_batch(
            uuid,uuid,uuid,uuid,uuid,bigint,uuid,integer
        ), control.record_staged_startup_route_candidate(
            uuid,uuid,uuid,uuid,uuid,bigint,uuid,uuid,bigint,text,text,text,bigint,text,jsonb,text,jsonb
        ), control.seal_staged_startup_route_publication(
            uuid,uuid,uuid,uuid,uuid,bigint,integer,text
        ), control.start_staged_startup_route_publication(
            uuid,uuid,uuid,uuid,uuid,bigint,text
        ), control.observe_staged_startup_route_publication(
            uuid,uuid,uuid,uuid,uuid,bigint,text,uuid,text
        ), control.finish_staged_startup_route_publication(
            uuid,uuid,uuid,uuid,uuid,bigint,jsonb
        ), control.abort_staged_startup_route_publication(
            uuid,uuid,uuid,uuid,uuid,bigint,text,bigint,bigint,uuid,text
        ), control.claim_interrupted_startup_route_publication(
            uuid,uuid,integer
        ), control.finish_interrupted_startup_route_publication(
            uuid,uuid,uuid,text,text,bigint,bigint,uuid,text,jsonb
        ) to control_driver_ledger;
    end if;
end
$migration$;

comment on table control.workshop_route_startup_runtime_reservations is
    'Function-only immutable startup runtime snapshot plus one bounded candidate receipt per workshop.';
comment on table control.workshop_route_startup_publications is
    'Function-only staged startup selector, cursor, seal, loaded-generation observation, and reconciliation ledger.';
comment on function control.read_staged_startup_route_batch(
    uuid,uuid,uuid,uuid,uuid,bigint,uuid,integer
) is 'Exact-authority 1..500-row keyset reader; returns only unfinished rows after the durable cursor.';
comment on function control.seal_staged_startup_route_publication(
    uuid,uuid,uuid,uuid,uuid,bigint,integer,text
) is 'Seals only a complete ordered candidate set whose IDs exactly equal the complete current route-lease fleet.';
