-- Memberships authorize human access and expose tenant affiliation. Keep only
-- explicit platform reporting fleet-readable; mediate bootstrap writes and
-- fleet worker discovery through bounded capabilities, while ordinary runtime
-- access requires transaction-local workshop context.

create function control.insert_initial_workshop_owner(
    p_command_id uuid,
    p_workshop_id uuid,
    p_user_id uuid
) returns integer
language plpgsql
security definer
set search_path = pg_catalog, control
as $function$
declare
    v_epoch integer;
begin
    if not exists (
        select 1
          from control.commands command
          join control.workshops workshop on workshop.id = p_workshop_id
         where command.id = p_command_id
           and command.actor_user_id = p_user_id
           and command.scope = 'platform:workshops'
           and command.command_kind = 'workshop.create'
           and command.state = 'admitted'
           and workshop.status = 'provisioning'
           and not exists (
               select 1 from control.memberships existing
                where existing.workshop_id = workshop.id
           )
    ) then
        raise exception using
            errcode = '42501',
            message = 'initial workshop owner capability rejected';
    end if;

    insert into control.memberships(workshop_id, user_id, role)
    values (p_workshop_id, p_user_id, 'owner')
    returning authority_epoch into v_epoch;
    return v_epoch;
end
$function$;

create function control.accept_invitation_membership(
    p_invitation_id uuid,
    p_token_generation integer,
    p_user_id uuid,
    p_command_id uuid
) returns table(workshop_id uuid, authority_epoch integer)
language plpgsql
security definer
set search_path = pg_catalog, control
as $function$
declare
    v_invitation control.invitations%rowtype;
    v_epoch integer;
begin
    select invitation.* into v_invitation
      from control.invitations invitation
     where invitation.id = p_invitation_id
       and invitation.token_generation = p_token_generation
     for update;
    if not found
       or v_invitation.accepted_at is not null
       or v_invitation.revoked_at is not null
       or v_invitation.expires_at <= now()
       or not exists (
           select 1 from control.users user_row
            where user_row.id = p_user_id
              and user_row.email = v_invitation.email
       )
       or not exists (
           select 1 from control.commands command
            where command.id = p_command_id
              and command.actor_user_id = p_user_id
              and command.scope = 'workshop:' || v_invitation.workshop_id::text
              and command.command_kind = 'invitation.accept'
              and command.state = 'admitted'
       ) then
        raise exception using
            errcode = '42501',
            message = 'invitation membership capability rejected';
    end if;

    insert into control.memberships(workshop_id, user_id, role)
    values (v_invitation.workshop_id, p_user_id, v_invitation.role)
    on conflict on constraint memberships_pkey do update set
        role = excluded.role,
        status = 'active',
        revoked_at = null,
        authority_epoch = control.memberships.authority_epoch + 1
    returning control.memberships.authority_epoch into v_epoch;

    update control.invitations invitation
       set accepted_at = now(), accepted_user_id = p_user_id
     where invitation.id = v_invitation.id
       and invitation.workshop_id = v_invitation.workshop_id
       and invitation.accepted_at is null
       and invitation.revoked_at is null;
    if not found then
        raise exception using
            errcode = '40001',
            message = 'invitation acceptance target was lost';
    end if;

    return query select v_invitation.workshop_id, v_epoch;
end
$function$;

create function control.discover_due_backup_memberships(
    p_limit integer
) returns table(workshop_id uuid, database_id uuid, owner_user_id uuid)
language plpgsql
security definer
set search_path = pg_catalog, control
as $function$
begin
    if p_limit < 1 or p_limit > 100 then
        raise exception using
            errcode = '22023',
            message = 'backup membership discovery limit is invalid';
    end if;
    return query
    select database.workshop_id, database.id, owner_membership.user_id
      from control.odoo_databases database
      join lateral (
          select membership.user_id
            from control.memberships membership
           where membership.workshop_id = database.workshop_id
             and membership.role = 'owner'
             and membership.status = 'active'
           order by membership.user_id
           limit 1
      ) owner_membership on true
     where database.kind = 'primary'
       and database.state = 'ready'
       and database.deleted_at is null
       and not exists (
           select 1 from control.workshop_recovery_points recovery
            where recovery.workshop_id = database.workshop_id
              and recovery.kind = 'backup'
              and recovery.created_at > now() - interval '24 hours'
              and recovery.state in ('queued', 'creating', 'ready')
       )
     order by database.workshop_id, database.id
     limit p_limit;
end
$function$;

create function control.read_privacy_subject_workshops(
    p_request_id uuid,
    p_operation_id uuid,
    p_operation_attempt integer,
    p_lease_owner text,
    p_limit integer
) returns table(workshop_id uuid)
language plpgsql
security definer
set search_path = pg_catalog, control
as $function$
begin
    if p_limit < 1 or p_limit > 501
       or not exists (
           select 1
             from control.operations operation
             join control.data_subject_requests request
               on request.id = p_request_id
              and request.operation_id = operation.id
              and request.subject_user_id = operation.target_user_id
            where operation.id = p_operation_id
              and operation.kind = 'privacy.data_subject_request'
              and operation.queue = 'privacy-operations'
              and operation.workshop_id is null
              and operation.state = 'in_flight'
              and operation.attempt = p_operation_attempt
              and operation.leased_by = p_lease_owner
              and operation.lease_expires_at > now()
              and operation.payload->>'request_id' = p_request_id::text
              and request.status in ('approved', 'executing')
              and coalesce(jsonb_array_length(request.scope->'workshop_ids'), 0) = 0
       ) then
        raise exception using
            errcode = '42501',
            message = 'privacy subject workshop capability rejected';
    end if;

    return query
    select membership.workshop_id
      from control.memberships membership
      join control.data_subject_requests request
        on request.id = p_request_id
       and request.subject_user_id = membership.user_id
     order by membership.workshop_id
     limit p_limit;
end
$function$;

revoke all on function control.insert_initial_workshop_owner(uuid, uuid, uuid) from public;
revoke all on function control.accept_invitation_membership(uuid, integer, uuid, uuid) from public;
revoke all on function control.discover_due_backup_memberships(integer) from public;
revoke all on function control.read_privacy_subject_workshops(uuid, uuid, integer, text, integer) from public;

alter table control.memberships enable row level security;
alter table control.memberships force row level security;

do $migration$
begin
    if exists (select 1 from pg_roles where rolname = 'control') then
        create policy memberships_migration_owner on control.memberships
        as permissive for all to control using (true) with check (true);
    end if;

    if exists (select 1 from pg_roles where rolname = 'control_api') then
        revoke insert, update, delete on table control.memberships from control_api;
        create policy memberships_platform_read on control.memberships
        as permissive for select to control_api using (true);
        grant execute on function control.insert_initial_workshop_owner(uuid, uuid, uuid)
            to control_api;
        grant execute on function control.accept_invitation_membership(uuid, integer, uuid, uuid)
            to control_api;
    end if;

    if exists (select 1 from pg_roles where rolname = 'control_tenant_api') then
        create policy memberships_tenant_api_read on control.memberships
        as permissive for select to control_tenant_api
        using (workshop_id = control.current_workshop_id());
        create policy memberships_tenant_api_update on control.memberships
        as permissive for update to control_tenant_api
        using (workshop_id = control.current_workshop_id())
        with check (workshop_id = control.current_workshop_id());
        grant execute on function control.current_workshop_id() to control_tenant_api;
    end if;

    if exists (select 1 from pg_roles where rolname = 'control_membership_worker') then
        create policy memberships_membership_worker_read on control.memberships
        as permissive for select to control_membership_worker
        using (workshop_id = control.current_workshop_id());
        grant execute on function control.current_workshop_id() to control_membership_worker;
    end if;

    if exists (select 1 from pg_roles where rolname = 'control_provisioning_worker') then
        create policy memberships_provisioning_worker_read on control.memberships
        as permissive for select to control_provisioning_worker
        using (workshop_id = control.current_workshop_id());
        grant execute on function control.current_workshop_id() to control_provisioning_worker;
    end if;

    if exists (select 1 from pg_roles where rolname = 'control_reconciliation_worker') then
        create policy memberships_reconciliation_worker_read on control.memberships
        as permissive for select to control_reconciliation_worker
        using (workshop_id = control.current_workshop_id());
        grant execute on function control.current_workshop_id() to control_reconciliation_worker;
    end if;

    if exists (select 1 from pg_roles where rolname = 'control_backup_scheduler') then
        create policy memberships_backup_scheduler_read on control.memberships
        as permissive for select to control_backup_scheduler
        using (workshop_id = control.current_workshop_id());
        grant execute on function control.current_workshop_id() to control_backup_scheduler;
        grant execute on function control.discover_due_backup_memberships(integer)
            to control_backup_scheduler;
    end if;

    if exists (select 1 from pg_roles where rolname = 'control_privacy_worker') then
        create policy memberships_privacy_worker_read on control.memberships
        as permissive for select to control_privacy_worker
        using (workshop_id = control.current_workshop_id());
        grant execute on function control.current_workshop_id() to control_privacy_worker;
        grant execute on function control.read_privacy_subject_workshops(uuid, uuid, integer, text, integer)
            to control_privacy_worker;
    end if;

    if exists (select 1 from pg_roles where rolname = 'control_driver_ledger') then
        create policy memberships_driver_read on control.memberships
        as permissive for select to control_driver_ledger
        using (workshop_id = control.current_workshop_id());
        grant execute on function control.current_workshop_id() to control_driver_ledger;
    end if;

    if exists (select 1 from pg_roles where rolname = 'control_invoice_worker') then
        revoke select on table control.memberships from control_invoice_worker;
    end if;
    if exists (select 1 from pg_roles where rolname = 'control_inventory_worker') then
        revoke select on table control.memberships from control_inventory_worker;
    end if;
end
$migration$;

comment on table control.memberships is
'Workshop membership authority protected by forced tenant RLS; platform reporting is read-only, bootstrap writes and fleet discovery use bounded capabilities, and direct worker or driver reads require transaction-local workshop context.';
