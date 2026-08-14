-- Protected processor lookup and fail-closed evidence for erasure replay after restore.
alter table control.deployment_driver_operations
    drop constraint deployment_driver_operations_action_check,
    add constraint deployment_driver_operations_action_check check (
        action in ('provision','reconcile','lifecycle','rehearse','release','erasure','resume')
    );

create table control.erasure_subject_lookups (
    tombstone_id uuid primary key references control.erasure_tombstones(id) on delete cascade,
    key_id text not null check(key_id ~ '^[A-Za-z0-9_.-]{1,100}$'),
    nonce bytea not null check(octet_length(nonce)=12),
    ciphertext bytea not null check(octet_length(ciphertext) between 17 and 4112),
    created_at timestamptz not null default now()
);

create table control.erasure_restore_replays (
    id uuid primary key,
    tombstone_id uuid not null references control.erasure_tombstones(id) on delete restrict,
    recovery_point_id uuid not null references control.workshop_recovery_points(id) on delete restrict,
    operation_id uuid not null references control.operations(id) on delete restrict,
    required_locations text[] not null check(cardinality(required_locations)>0),
    completed_locations text[] not null default '{}',
    state text not null default 'pending' check(state in ('pending','applying','complete','failed')),
    safe_error_class text check(safe_error_class is null or safe_error_class ~ '^[a-z][a-z0-9_]{0,99}$'),
    started_at timestamptz,
    completed_at timestamptz,
    created_at timestamptz not null default now(),
    unique(tombstone_id,recovery_point_id),
    check(completed_locations <@ required_locations),
    check(state<>'complete' or (completed_locations @> required_locations and completed_at is not null))
);

comment on table control.erasure_subject_lookups is
    'AEAD-protected processor lookup; key material is mounted only into privacy and lifecycle workers.';
comment on table control.erasure_restore_replays is
    'Evidence that every restored processor location was erased before public routing resumed.';

create function control.erasure_lookup_available(target uuid) returns boolean
language sql stable security definer set search_path=pg_catalog,control as $$
    select exists(select 1 from erasure_subject_lookups where tombstone_id=target)
$$;
revoke all on function control.erasure_lookup_available(uuid) from public;

do $$
begin
    if exists(select 1 from pg_roles where rolname='control_privacy_worker') then
        grant select,insert on control.erasure_subject_lookups to control_privacy_worker;
    end if;
    if exists(select 1 from pg_roles where rolname='control_lifecycle_worker') then
        grant select on control.erasure_tombstones,control.erasure_subject_lookups to control_lifecycle_worker;
        grant select,insert,update on control.erasure_restore_replays to control_lifecycle_worker;
    end if;
    if exists(select 1 from pg_roles where rolname='control_api') then
        grant select,insert on control.erasure_restore_replays to control_api;
        grant execute on function control.erasure_lookup_available(uuid) to control_api;
    end if;
    if exists(select 1 from pg_roles where rolname='control_driver_ledger') then
        grant select on control.operations,control.erasure_tombstones,
            control.erasure_restore_replays,control.service_instances
        to control_driver_ledger;
    end if;
end $$;
