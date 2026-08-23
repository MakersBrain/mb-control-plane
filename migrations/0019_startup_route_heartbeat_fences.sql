-- Replace per-route whole-fleet renewal with one atomic periodic heartbeat and
-- constant-cost exact assertions around filesystem and gateway effects. Host
-- effects still cannot consume a PostgreSQL fence, so a failed post-effect
-- assertion remains an unknown outcome and is quarantined by startup cleanup.

create or replace function control.renew_startup_route_rebuild(
    p_effect_run_id uuid,p_instance_owner uuid,p_execution_token uuid,
    p_global_lease_token uuid,p_route_lease_token uuid,
    p_global_fence_token bigint,p_ttl_seconds integer
) returns boolean
language plpgsql security definer
set search_path=pg_catalog, control
as $function$
declare
    v_global control.deployment_driver_resource_leases%rowtype;
    v_run control.workshop_route_effect_runs%rowtype;
    v_expected bigint;
    v_exact bigint;
    v_changed bigint;
    v_expires_at timestamptz;
begin
    if p_ttl_seconds<60 or p_ttl_seconds>1200 then return false; end if;

    -- Preserve the global -> workshop route -> effect-run lock order used by
    -- startup admission. No expiry changes occur until the entire frozen set
    -- has been authenticated.
    select * into v_global
      from control.deployment_driver_resource_leases
     where resource_key='runtime/shared-odoo'
     for update;
    if not found
       or v_global.state<>'held'
       or v_global.authority_kind<>'startup-rebuild'
       or v_global.effect_run_id is distinct from p_effect_run_id
       or v_global.lease_owner is distinct from p_instance_owner
       or v_global.lease_token is distinct from p_global_lease_token
       or v_global.fence_token is distinct from p_global_fence_token
       or v_global.lease_expires_at<=now() then
        return false;
    end if;

    perform 1
      from control.workshop_route_effect_reservations reservation
      join control.workshop_route_application_leases lease
        on lease.workshop_id=reservation.workshop_id
     where reservation.effect_run_id=p_effect_run_id
     order by reservation.workshop_id
     for update of lease;

    select * into v_run
      from control.workshop_route_effect_runs
     where id=p_effect_run_id
     for update;
    if not found
       or v_run.kind<>'startup-rebuild'
       or v_run.state not in ('reserved','effects_started')
       or v_run.instance_owner is distinct from p_instance_owner
       or v_run.execution_token is distinct from p_execution_token
       or v_run.global_lease_token is distinct from p_global_lease_token
       or v_run.route_lease_token is distinct from p_route_lease_token
       or v_run.global_fence_token is distinct from p_global_fence_token
       or v_run.lease_expires_at<=now() then
        return false;
    end if;

    select count(*) into v_expected
      from control.workshop_route_effect_reservations
     where effect_run_id=p_effect_run_id;
    select count(*) into v_exact
      from control.workshop_route_effect_reservations reservation
      join control.workshop_route_application_leases lease
        on lease.workshop_id=reservation.workshop_id
       and lease.state='held'
       and lease.authority_kind='startup-rebuild'
       and lease.effect_run_id=p_effect_run_id
       and lease.driver_operation_id is null
       and lease.generation is not distinct from reservation.generation
       and lease.projection_digest is not distinct from reservation.projection_digest
       and lease.fence_token=reservation.route_fence_token
       and lease.lease_owner=p_instance_owner
       and lease.lease_token=p_route_lease_token
       and lease.lease_expires_at>now()
     where reservation.effect_run_id=p_effect_run_id;
    if v_exact<>v_expected then return false; end if;

    v_expires_at:=now()+make_interval(secs=>p_ttl_seconds);
    update control.workshop_route_effect_runs
       set lease_expires_at=v_expires_at,heartbeat_at=now(),updated_at=now()
     where id=p_effect_run_id;
    get diagnostics v_changed=row_count;
    if v_changed<>1 then raise exception 'startup effect run renewal drifted'
        using errcode='40001'; end if;

    update control.deployment_driver_resource_leases
       set lease_expires_at=v_expires_at,heartbeat_at=now(),updated_at=now()
     where resource_key='runtime/shared-odoo';
    get diagnostics v_changed=row_count;
    if v_changed<>1 then raise exception 'startup global renewal drifted'
        using errcode='40001'; end if;

    update control.workshop_route_application_leases lease
       set lease_expires_at=v_expires_at,heartbeat_at=now(),updated_at=now()
      from control.workshop_route_effect_reservations reservation
     where reservation.effect_run_id=p_effect_run_id
       and reservation.workshop_id=lease.workshop_id;
    get diagnostics v_changed=row_count;
    if v_changed<>v_expected then raise exception 'startup route renewal drifted'
        using errcode='40001'; end if;
    return true;
end
$function$;

create function control.read_startup_route_projection_source(
    p_effect_run_id uuid,p_instance_owner uuid,p_execution_token uuid,
    p_global_lease_token uuid,p_route_lease_token uuid,p_global_fence_token bigint,
    p_workshop_id uuid,p_tenant_domain text
) returns table(outcome text,disposition text,projection jsonb)
language plpgsql stable security definer
set search_path=pg_catalog, control
as $function$
declare v_source jsonb; v_database_count integer;
begin
    if p_tenant_domain is null
       or p_tenant_domain !~ '^[a-z0-9][a-z0-9.-]{1,251}[a-z0-9]$'
       or p_tenant_domain ~ '\.\.' then
        return query select 'invalid',null::text,null::jsonb; return;
    end if;
    if not exists(
        select 1
          from control.workshop_route_effect_runs run
          join control.deployment_driver_resource_leases global_lease
            on global_lease.resource_key='runtime/shared-odoo'
          join control.workshop_route_effect_reservations reservation
            on reservation.effect_run_id=run.id and reservation.workshop_id=p_workshop_id
          join control.workshop_route_application_leases route_lease
            on route_lease.workshop_id=reservation.workshop_id
         where run.id=p_effect_run_id and run.kind='startup-rebuild' and run.state='reserved'
           and run.instance_owner=p_instance_owner and run.execution_token=p_execution_token
           and run.global_lease_token=p_global_lease_token
           and run.route_lease_token=p_route_lease_token
           and run.global_fence_token=p_global_fence_token and run.lease_expires_at>now()
           and global_lease.state='held' and global_lease.authority_kind='startup-rebuild'
           and global_lease.effect_run_id=p_effect_run_id
           and global_lease.lease_owner=p_instance_owner
           and global_lease.lease_token=p_global_lease_token
           and global_lease.fence_token=p_global_fence_token
           and global_lease.lease_expires_at>now()
           and reservation.action='remove-uninitialized'
           and reservation.generation is null and reservation.projection_digest is null
           and reservation.disposition is null
           and route_lease.state='held' and route_lease.authority_kind='startup-rebuild'
           and route_lease.effect_run_id=p_effect_run_id
           and route_lease.driver_operation_id is null
           and route_lease.generation is null and route_lease.projection_digest is null
           and route_lease.fence_token=reservation.route_fence_token
           and route_lease.lease_owner=p_instance_owner
           and route_lease.lease_token=p_route_lease_token
           and route_lease.lease_expires_at>now()
    ) then
        return query select 'authority_lost',null::text,null::jsonb; return;
    end if;
    select count(*) into v_database_count
      from control.workshops workshop
      join control.odoo_databases database on database.workshop_id=workshop.id
     where workshop.id=p_workshop_id and database.kind='primary'
       and database.deleted_at is null and database.public_hostname is not null;
    if v_database_count=0 then
        return query select 'read','absent',jsonb_build_object(
            'database_id',null,'database_ref',null,'public_hostname',null,
            'paperless_mode','absent','paperless_hostname',null,
            'custom_hostnames','[]'::jsonb
        );
    elsif v_database_count<>1 then
        return query select 'source_ambiguous',null::text,null::jsonb; return;
    end if;
    select jsonb_build_object(
        'database_id',to_jsonb(database.id::text),
        'database_ref',to_jsonb(database.database_ref),
        'public_hostname',to_jsonb(database.public_hostname),
        'paperless_mode',to_jsonb(coalesce(paperless.mode,'absent')),
        'paperless_hostname',case when coalesce(paperless.mode,'absent')='absent'
            then 'null'::jsonb else to_jsonb('docs-'||workshop.slug||'.'||p_tenant_domain) end,
        'custom_hostnames',coalesce((select jsonb_agg(jsonb_build_object(
            'hostname',domain.hostname,'canonical',domain.canonical) order by domain.hostname)
          from control.webshop_domains domain where domain.workshop_id=workshop.id
            and domain.state in ('testing','active') and domain.desired_state='active'),'[]'::jsonb)
    ) into v_source
      from control.workshops workshop
      join control.odoo_databases database on database.workshop_id=workshop.id
      left join lateral (select case
          when module.state in ('installing','enabled') then 'read_write'
          when module.state in ('restricting','restricted') then 'read_only'
          else 'absent' end as mode
        from control.workshop_modules module
        join control.service_instances service on service.workshop_id=module.workshop_id
         and service.service='paperless' and service.health='ready'
       where module.workshop_id=workshop.id and module.module_key='documents'
       order by module.module_key limit 1) paperless on true
     where workshop.id=p_workshop_id and database.kind='primary'
       and database.deleted_at is null and database.public_hostname is not null;
    return query select 'read','present',v_source;
end
$function$;

create function control.assert_startup_route_global_fence(
    p_effect_run_id uuid,p_instance_owner uuid,p_execution_token uuid,
    p_global_lease_token uuid,p_global_fence_token bigint
) returns boolean
language sql stable security definer
set search_path=pg_catalog, control
as $function$
    select exists(
        select 1
          from control.workshop_route_effect_runs run
          join control.deployment_driver_resource_leases global_lease
            on global_lease.resource_key='runtime/shared-odoo'
         where run.id=p_effect_run_id and run.kind='startup-rebuild'
           and run.state='effects_started'
           and run.instance_owner=p_instance_owner
           and run.execution_token=p_execution_token
           and run.global_lease_token=p_global_lease_token
           and run.global_fence_token=p_global_fence_token
           and run.lease_expires_at>now()
           and global_lease.state='held'
           and global_lease.authority_kind='startup-rebuild'
           and global_lease.effect_run_id=p_effect_run_id
           and global_lease.lease_owner=p_instance_owner
           and global_lease.lease_token=p_global_lease_token
           and global_lease.fence_token=p_global_fence_token
           and global_lease.lease_expires_at>now()
    )
$function$;

create function control.assert_startup_route_workshop_fence(
    p_effect_run_id uuid,p_instance_owner uuid,p_execution_token uuid,
    p_global_lease_token uuid,p_route_lease_token uuid,
    p_global_fence_token bigint,p_workshop_id uuid,p_generation bigint,
    p_projection_digest text,p_disposition text,p_action text,
    p_route_fence_token bigint
) returns boolean
language sql stable security definer
set search_path=pg_catalog, control
as $function$
    select exists(
        select 1
          from control.workshop_route_effect_runs run
          join control.deployment_driver_resource_leases global_lease
            on global_lease.resource_key='runtime/shared-odoo'
          join control.workshop_route_effect_reservations reservation
            on reservation.effect_run_id=run.id
           and reservation.workshop_id=p_workshop_id
          join control.workshop_route_application_leases route_lease
            on route_lease.workshop_id=reservation.workshop_id
         where run.id=p_effect_run_id and run.kind='startup-rebuild'
           and run.state='effects_started'
           and run.instance_owner=p_instance_owner
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
           and reservation.generation is not distinct from p_generation
           and reservation.projection_digest is not distinct from p_projection_digest
           and reservation.disposition is not distinct from p_disposition
           and reservation.action=p_action
           and reservation.route_fence_token=p_route_fence_token
           and route_lease.state='held'
           and route_lease.authority_kind='startup-rebuild'
           and route_lease.effect_run_id=p_effect_run_id
           and route_lease.driver_operation_id is null
           and route_lease.generation is not distinct from p_generation
           and route_lease.projection_digest is not distinct from p_projection_digest
           and route_lease.fence_token=p_route_fence_token
           and route_lease.lease_owner=p_instance_owner
           and route_lease.lease_token=p_route_lease_token
           and route_lease.lease_expires_at>now()
    )
$function$;

create function control.record_startup_route_candidate_v2(
    p_effect_run_id uuid,p_instance_owner uuid,p_execution_token uuid,
    p_global_lease_token uuid,p_route_lease_token uuid,
    p_global_fence_token bigint,p_workshop_id uuid,p_generation bigint,
    p_projection_digest text,p_disposition text,p_action text,
    p_route_fence_token bigint,p_rendered_digest text,p_evidence jsonb
) returns boolean
language plpgsql security definer
set search_path=pg_catalog, control
as $function$
declare
    v_res control.workshop_route_effect_reservations%rowtype;
    v_keys integer;
begin
    if p_generation<=0
       or p_projection_digest !~ '^sha256:[0-9a-f]{64}$'
       or p_disposition not in ('present','absent')
       or p_action not in ('render','remove-absent')
       or p_route_fence_token<=0
       or p_rendered_digest !~ '^sha256:[0-9a-f]{64}$'
       or jsonb_typeof(p_evidence)<>'object' then return false; end if;

    perform 1 from control.deployment_driver_resource_leases
     where resource_key='runtime/shared-odoo' and state='held'
       and authority_kind='startup-rebuild' and effect_run_id=p_effect_run_id
       and lease_owner=p_instance_owner and lease_token=p_global_lease_token
       and fence_token=p_global_fence_token and lease_expires_at>now()
     for update;
    if not found then return false; end if;
    perform 1 from control.workshop_route_application_leases
     where workshop_id=p_workshop_id and state='held'
       and authority_kind='startup-rebuild' and effect_run_id=p_effect_run_id
       and driver_operation_id is null
       and generation=p_generation and projection_digest=p_projection_digest
       and fence_token=p_route_fence_token and lease_owner=p_instance_owner
       and lease_token=p_route_lease_token and lease_expires_at>now()
     for update;
    if not found then return false; end if;
    perform 1 from control.workshop_route_effect_runs
     where id=p_effect_run_id and kind='startup-rebuild' and state='effects_started'
       and instance_owner=p_instance_owner and execution_token=p_execution_token
       and global_lease_token=p_global_lease_token
       and route_lease_token=p_route_lease_token
       and global_fence_token=p_global_fence_token and lease_expires_at>now()
     for update;
    if not found then return false; end if;
    select * into v_res from control.workshop_route_effect_reservations
     where effect_run_id=p_effect_run_id and workshop_id=p_workshop_id
       and generation=p_generation and projection_digest=p_projection_digest
       and disposition=p_disposition and action=p_action
       and route_fence_token=p_route_fence_token
     for update;
    if not found then return false; end if;

    select count(*) into v_keys from jsonb_object_keys(p_evidence);
    if v_keys<>7
       or p_evidence->>'effect_run_id' is distinct from p_effect_run_id::text
       or p_evidence->>'workshop_id' is distinct from p_workshop_id::text
       or p_evidence->>'generation' is distinct from p_generation::text
       or p_evidence->>'projection_digest' is distinct from p_projection_digest
       or p_evidence->>'disposition' is distinct from p_disposition
       or p_evidence->>'rendered_digest' is distinct from p_rendered_digest
       or p_evidence->>'route_fence_token' is distinct from p_route_fence_token::text
       then return false; end if;
    update control.workshop_route_effect_reservations
       set state='candidate',rendered_digest=p_rendered_digest,
           evidence=p_evidence,updated_at=now()
     where effect_run_id=p_effect_run_id and workshop_id=p_workshop_id
       and state in ('reserved','candidate');
    return found;
end
$function$;

create function control.finish_startup_route_rebuild_v2(
    p_effect_run_id uuid,p_instance_owner uuid,p_execution_token uuid,
    p_global_lease_token uuid,p_route_lease_token uuid,
    p_global_fence_token bigint,p_outcome text,p_response jsonb,p_safe_error text
) returns boolean
language plpgsql security definer
set search_path=pg_catalog, control
as $function$
declare v_expected bigint; v_exact bigint;
begin
    if p_outcome='succeeded' then
        perform 1 from control.deployment_driver_resource_leases
         where resource_key='runtime/shared-odoo' and state='held'
           and authority_kind='startup-rebuild' and effect_run_id=p_effect_run_id
           and lease_owner=p_instance_owner and lease_token=p_global_lease_token
           and fence_token=p_global_fence_token and lease_expires_at>now()
         for update;
        if not found then return false; end if;
        perform 1
          from control.workshop_route_effect_reservations reservation
          join control.workshop_route_application_leases lease
            on lease.workshop_id=reservation.workshop_id
         where reservation.effect_run_id=p_effect_run_id
         order by reservation.workshop_id
         for update of lease;
        select count(*) into v_expected
          from control.workshop_route_effect_reservations
         where effect_run_id=p_effect_run_id;
        select count(*) into v_exact
          from control.workshop_route_effect_reservations reservation
          join control.workshop_route_application_leases lease
            on lease.workshop_id=reservation.workshop_id
           and lease.state='held' and lease.authority_kind='startup-rebuild'
           and lease.effect_run_id=p_effect_run_id
           and lease.driver_operation_id is null
           and lease.generation is not distinct from reservation.generation
           and lease.projection_digest is not distinct from reservation.projection_digest
           and lease.fence_token=reservation.route_fence_token
           and lease.lease_owner=p_instance_owner
           and lease.lease_token=p_route_lease_token
           and lease.lease_expires_at>now()
         where reservation.effect_run_id=p_effect_run_id;
        if v_exact<>v_expected then return false; end if;
    end if;
    return control.finish_startup_route_rebuild(
        p_effect_run_id,p_instance_owner,p_execution_token,
        p_global_lease_token,p_route_lease_token,p_global_fence_token,
        p_outcome,p_response,p_safe_error
    );
end
$function$;

revoke all on function control.assert_startup_route_global_fence(
    uuid,uuid,uuid,uuid,bigint
) from public;
revoke all on function control.read_startup_route_projection_source(
    uuid,uuid,uuid,uuid,uuid,bigint,uuid,text
) from public;
revoke all on function control.assert_startup_route_workshop_fence(
    uuid,uuid,uuid,uuid,uuid,bigint,uuid,bigint,text,text,text,bigint
) from public;
revoke all on function control.record_startup_route_candidate_v2(
    uuid,uuid,uuid,uuid,uuid,bigint,uuid,bigint,text,text,text,bigint,text,jsonb
) from public;
revoke all on function control.finish_startup_route_rebuild_v2(
    uuid,uuid,uuid,uuid,uuid,bigint,text,jsonb,text
) from public;

do $migration$
begin
    if exists(select 1 from pg_roles where rolname='control_driver_ledger') then
        revoke execute on function control.record_startup_route_candidate(
            uuid,uuid,uuid,uuid,uuid,bigint,text,jsonb
        ) from control_driver_ledger;
        revoke execute on function control.finish_startup_route_rebuild(
            uuid,uuid,uuid,uuid,uuid,bigint,text,jsonb,text
        ) from control_driver_ledger;
        grant execute on function control.assert_startup_route_global_fence(
            uuid,uuid,uuid,uuid,bigint
        ), control.assert_startup_route_workshop_fence(
            uuid,uuid,uuid,uuid,uuid,bigint,uuid,bigint,text,text,text,bigint
        ), control.record_startup_route_candidate_v2(
            uuid,uuid,uuid,uuid,uuid,bigint,uuid,bigint,text,text,text,bigint,text,jsonb
        ), control.finish_startup_route_rebuild_v2(
            uuid,uuid,uuid,uuid,uuid,bigint,text,jsonb,text
        ), control.read_startup_route_projection_source(
            uuid,uuid,uuid,uuid,uuid,bigint,uuid,text
        ) to control_driver_ledger;
    end if;
end
$migration$;

comment on function control.renew_startup_route_rebuild(
    uuid,uuid,uuid,uuid,uuid,bigint,integer
) is 'Atomic O(fleet) startup lease heartbeat; validates the complete frozen set before changing any expiry.';
comment on function control.assert_startup_route_global_fence(
    uuid,uuid,uuid,uuid,bigint
) is 'Constant-cost exact startup global authority assertion; never renews a lease.';
comment on function control.assert_startup_route_workshop_fence(
    uuid,uuid,uuid,uuid,uuid,bigint,uuid,bigint,text,text,text,bigint
) is 'Constant-cost exact startup workshop and global authority assertion; never renews a lease.';
comment on function control.read_startup_route_projection_source(
    uuid,uuid,uuid,uuid,uuid,bigint,uuid,text
)
is 'Least-privilege startup projection source read; initialization independently revalidates the exact source.';
