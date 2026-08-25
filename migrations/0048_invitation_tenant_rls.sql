-- Invitations contain bearer-bootstrap material and tenant membership intent.
-- Tenant and email paths use transaction-local workshop context; the only
-- fleet entry points are exact-row capabilities for verified tokens and
-- authenticated membership managers.

create function control.lock_live_invitation(
    p_invitation_id uuid,
    p_token_generation integer
) returns table(
    invitation_id uuid,
    workshop_id uuid,
    email text,
    role text,
    locale text,
    expires_at timestamptz,
    workshop_display_name text
)
language plpgsql
security definer
set search_path = pg_catalog, control
as $function$
begin
    return query
    select invitation.id,
           invitation.workshop_id,
           invitation.email,
           invitation.role,
           invitation.locale,
           invitation.expires_at,
           workshop.display_name
      from control.invitations invitation
      join control.workshops workshop on workshop.id = invitation.workshop_id
     where invitation.id = p_invitation_id
       and invitation.token_generation = p_token_generation
       and invitation.accepted_at is null
       and invitation.revoked_at is null
       and invitation.expires_at > now()
     for update of invitation;
end
$function$;

create function control.read_managed_invitation(
    p_invitation_id uuid,
    p_user_id uuid
) returns table(
    invitation_id uuid,
    workshop_id uuid,
    email text,
    role text,
    locale text,
    expires_at timestamptz
)
language sql
stable
security definer
set search_path = pg_catalog, control
as $function$
    select invitation.id,
           invitation.workshop_id,
           invitation.email,
           invitation.role,
           invitation.locale,
           invitation.expires_at
      from control.invitations invitation
      join control.memberships membership
        on membership.workshop_id = invitation.workshop_id
       and membership.user_id = p_user_id
       and membership.status = 'active'
       and membership.role in ('owner', 'studio_manager')
     where invitation.id = p_invitation_id
       and invitation.accepted_at is null
       and invitation.revoked_at is null;
$function$;

revoke all on function control.lock_live_invitation(uuid, integer) from public;
revoke all on function control.read_managed_invitation(uuid, uuid) from public;

alter table control.invitations enable row level security;
alter table control.invitations force row level security;

do $migration$
begin
    if exists (select 1 from pg_roles where rolname = 'control') then
        create policy invitations_migration_owner on control.invitations
        as permissive for all to control using (true) with check (true);
    end if;

    if exists (select 1 from pg_roles where rolname = 'control_api') then
        revoke select, insert, update, delete on table control.invitations from control_api;
        grant execute on function control.lock_live_invitation(uuid, integer)
            to control_api;
        grant execute on function control.read_managed_invitation(uuid, uuid)
            to control_api;
    end if;

    if exists (select 1 from pg_roles where rolname = 'control_tenant_api') then
        create policy invitations_tenant_api_read on control.invitations
        as permissive for select to control_tenant_api
        using (workshop_id = control.current_workshop_id());
        create policy invitations_tenant_api_insert on control.invitations
        as permissive for insert to control_tenant_api
        with check (workshop_id = control.current_workshop_id());
        create policy invitations_tenant_api_update on control.invitations
        as permissive for update to control_tenant_api
        using (workshop_id = control.current_workshop_id())
        with check (workshop_id = control.current_workshop_id());
        grant execute on function control.current_workshop_id() to control_tenant_api;
    end if;

    if exists (select 1 from pg_roles where rolname = 'control_email_worker') then
        create policy invitations_email_worker_read on control.invitations
        as permissive for select to control_email_worker
        using (workshop_id = control.current_workshop_id());
        grant execute on function control.current_workshop_id() to control_email_worker;
    end if;

    if exists (select 1 from pg_roles where rolname = 'control_privacy_worker') then
        revoke select, update, delete on table control.invitations from control_privacy_worker;
    end if;
end
$migration$;

comment on table control.invitations is
'Invitation capability state protected by forced tenant RLS; bearer bootstrap and authenticated manager discovery use exact-row functions, tenant mutations require transaction-local workshop context, and privacy retention is function-only.';
