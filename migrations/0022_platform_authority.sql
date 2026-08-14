create table control.platform_authority_state (
    singleton boolean primary key default true check(singleton),
    initial_admin_bootstrapped boolean not null default false,
    bootstrapped_at timestamptz,
    check(initial_admin_bootstrapped=(bootstrapped_at is not null))
);
insert into control.platform_authority_state(singleton) values(true);

create table control.platform_role_assignments (
    id uuid primary key,
    user_id uuid not null references control.users(id) on delete restrict,
    role text not null check(role in (
        'technical_admin','release_operator','privacy_reviewer',
        'security_responder','auditor'
    )),
    granted_by uuid references control.users(id) on delete restrict,
    grant_reason_code text not null check(btrim(grant_reason_code)<>''),
    granted_at timestamptz not null default now(),
    revoked_at timestamptz,
    revoked_by uuid references control.users(id) on delete restrict,
    revoke_reason_code text,
    version bigint not null default 1 check(version>0),
    updated_at timestamptz not null default now(),
    check((revoked_at is null)=(revoked_by is null and revoke_reason_code is null))
);
create index platform_role_assignments_active_user
on control.platform_role_assignments(user_id,role) where revoked_at is null;
create unique index platform_role_assignments_one_active_role
on control.platform_role_assignments(user_id,role) where revoked_at is null;

create function control.validate_platform_role_update() returns trigger
language plpgsql set search_path=pg_catalog,control as $$
begin
    if new.id<>old.id or new.user_id<>old.user_id or new.role<>old.role
       or new.granted_by is distinct from old.granted_by
       or new.grant_reason_code<>old.grant_reason_code or new.granted_at<>old.granted_at
    then raise exception 'platform role grant identity is immutable' using errcode='55000'; end if;
    if old.revoked_at is not null then
        raise exception 'revoked platform role grants are immutable' using errcode='55000';
    end if;
    if new.version<>old.version+1 then
        raise exception 'platform role version must increment exactly once' using errcode='40001';
    end if;
    new.updated_at=now(); return new;
end $$;
create trigger platform_role_assignment_update before update on control.platform_role_assignments
for each row execute function control.validate_platform_role_update();

create function control.require_technical_admin() returns trigger
language plpgsql set search_path=pg_catalog,control as $$
begin
    if not exists(select 1 from platform_role_assignments where role='technical_admin' and revoked_at is null)
    then raise exception 'at least one technical administrator is required' using errcode='23514'; end if;
    return null;
end $$;
create constraint trigger platform_requires_technical_admin
after insert or update on control.platform_role_assignments
deferrable initially deferred for each row execute function control.require_technical_admin();

revoke all on function control.validate_platform_role_update() from public;
revoke all on function control.require_technical_admin() from public;

do $$
begin
    if exists(select 1 from pg_roles where rolname='control_api') then
        grant select,update on control.platform_authority_state to control_api;
        grant select,insert,update on control.platform_role_assignments to control_api;
    end if;
end $$;
