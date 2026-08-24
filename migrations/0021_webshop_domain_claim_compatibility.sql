-- Keep hostname admission stable while the application moves away from a
-- cross-workshop ON CONFLICT update.  A later migration may replace the global
-- hostname constraint with live-row uniqueness and redefine this capability to
-- insert a fresh row without changing its application contract.

create function control.claim_webshop_domain(
    p_domain_id uuid,
    p_workshop_id uuid,
    p_hostname text,
    p_verification_name text,
    p_verification_value text,
    p_routing_target text,
    p_created_by uuid
) returns table(outcome text, domain_id uuid, domain_version bigint)
language plpgsql security definer
set search_path = pg_catalog, control
as $function$
declare
    v_existing control.webshop_domains%rowtype;
begin
    if control.current_workshop_id() is distinct from p_workshop_id then
        raise exception 'webshop domain claim requires the current workshop capability'
            using errcode = '42501';
    end if;
    if not exists (
        select 1
          from control.memberships membership
         where membership.workshop_id = p_workshop_id
           and membership.user_id = p_created_by
           and membership.status = 'active'
           and membership.role in ('owner', 'studio_manager')
    ) then
        raise exception 'webshop domain claim requires an active manager'
            using errcode = '42501';
    end if;

    select domain.* into v_existing
      from control.webshop_domains domain
     where domain.hostname = p_hostname
     for update;

    if not found then
        begin
            insert into control.webshop_domains(
                id, workshop_id, hostname, verification_name,
                verification_value, routing_target, created_by
            ) values (
                p_domain_id, p_workshop_id, p_hostname, p_verification_name,
                p_verification_value, p_routing_target, p_created_by
            ) returning id, version into domain_id, domain_version;
        exception
            when unique_violation then
                return query select 'conflict', null::uuid, null::bigint;
                return;
        end;
        return query select 'created', domain_id, domain_version;
        return;
    end if;

    if v_existing.state <> 'disconnected'
       or exists (
           select 1
             from control.webshop_domain_provider_deletion_attempts attempt
            where attempt.domain_id = v_existing.id
              and attempt.workshop_id = v_existing.workshop_id
       ) then
        return query select 'conflict', null::uuid, null::bigint;
        return;
    end if;

    update control.webshop_domains domain
       set workshop_id = p_workshop_id,
           verification_name = p_verification_name,
           verification_value = p_verification_value,
           routing_target = p_routing_target,
           state = 'ownership_pending', desired_state = 'active',
           dns_state = 'pending', certificate_state = 'pending',
           ownership_verified_at = null, dns_observed_at = null,
           certificate_observed_at = null, last_health_checked_at = null,
           last_error_class = null, canonical = false, redirect_target = null,
           provider_ref = null, edge_verification_records = '[]'::jsonb,
           operation_id = null, created_by = p_created_by, created_at = now(),
           updated_at = now(), disconnected_at = null,
           version = domain.version + 1
     where domain.id = v_existing.id
       and domain.workshop_id = v_existing.workshop_id
       and domain.state = 'disconnected'
     returning domain.id, domain.version into domain_id, domain_version;
    if not found then
        raise exception 'webshop domain claim lost its locked row'
            using errcode = '40001';
    end if;
    return query select 'reclaimed', domain_id, domain_version;
end
$function$;

revoke all on function control.claim_webshop_domain(uuid,uuid,text,text,text,text,uuid)
    from public;

do $migration$
begin
    if exists(select 1 from pg_roles where rolname = 'control_tenant_api') then
        grant execute on function
            control.claim_webshop_domain(uuid,uuid,text,text,text,text,uuid)
            to control_tenant_api;
    end if;
end
$migration$;

comment on function control.claim_webshop_domain(uuid,uuid,text,text,text,text,uuid) is
'Workshop-scoped hostname claim compatibility capability; active claims conflict and disconnected claims are reused only while the global hostname constraint remains deployed.';
