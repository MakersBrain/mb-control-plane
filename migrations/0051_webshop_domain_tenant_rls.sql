-- Release disconnected hostnames without ever transferring ownership of an
-- existing row, then protect every direct runtime read and mutation with the
-- transaction-local workshop capability.

alter table control.webshop_domains
    drop constraint webshop_domains_hostname_key;

create unique index webshop_domains_live_hostname_unique
    on control.webshop_domains(hostname)
    where state <> 'disconnected';

create or replace function control.claim_webshop_domain(
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
end
$function$;

revoke all on function control.claim_webshop_domain(uuid,uuid,text,text,text,text,uuid)
    from public;

alter table control.webshop_domains enable row level security;
alter table control.webshop_domains force row level security;

do $migration$
begin
    if exists (select 1 from pg_roles where rolname = 'control') then
        create policy webshop_domains_migration_owner on control.webshop_domains
            as permissive for all to control using (true) with check (true);
    end if;

    if exists (select 1 from pg_roles where rolname = 'control_api') then
        revoke select, insert, update on table control.webshop_domains from control_api;
    end if;

    if exists (select 1 from pg_roles where rolname = 'control_tenant_api') then
        revoke insert on table control.webshop_domains from control_tenant_api;
        create policy webshop_domains_tenant_api_read on control.webshop_domains
            as permissive for select to control_tenant_api
            using (workshop_id = control.current_workshop_id());
        create policy webshop_domains_tenant_api_update on control.webshop_domains
            as permissive for update to control_tenant_api
            using (workshop_id = control.current_workshop_id())
            with check (workshop_id = control.current_workshop_id());
    end if;

    if exists (select 1 from pg_roles where rolname = 'control_reconciliation_worker') then
        create policy webshop_domains_reconciliation_read on control.webshop_domains
            as permissive for select to control_reconciliation_worker
            using (workshop_id = control.current_workshop_id());
        create policy webshop_domains_reconciliation_update on control.webshop_domains
            as permissive for update to control_reconciliation_worker
            using (workshop_id = control.current_workshop_id())
            with check (workshop_id = control.current_workshop_id());
    end if;

    if exists (select 1 from pg_roles where rolname = 'control_lifecycle_worker') then
        create policy webshop_domains_lifecycle_read on control.webshop_domains
            as permissive for select to control_lifecycle_worker
            using (workshop_id = control.current_workshop_id());
        create policy webshop_domains_lifecycle_update on control.webshop_domains
            as permissive for update to control_lifecycle_worker
            using (workshop_id = control.current_workshop_id())
            with check (workshop_id = control.current_workshop_id());
    end if;
end
$migration$;

comment on table control.webshop_domains is
'Workshop-owned custom-hostname state protected by forced tenant RLS; live hostname claims and fleet admission use bounded fixed-path capabilities.';

comment on function control.claim_webshop_domain(uuid,uuid,text,text,text,text,uuid) is
'Workshop-scoped live-hostname claim capability; disconnected history remains immutable and a new owner receives a fresh row.';
