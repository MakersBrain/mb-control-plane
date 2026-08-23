-- Privacy export artifacts live on a filesystem shared by every privacy-worker
-- replica.  Serialize cleanup through PostgreSQL and fence the database
-- acknowledgement so an expired executor cannot publish work after takeover.

create table control.privacy_export_cleanup_lease (
    singleton boolean primary key default true check (singleton),
    lease_owner text,
    lease_token uuid,
    lease_expires_at timestamp with time zone,
    fence_token bigint not null default 0 check (fence_token >= 0),
    updated_at timestamp with time zone not null default now(),
    constraint privacy_export_cleanup_lease_identity_check check (
        (lease_owner is null and lease_token is null and lease_expires_at is null)
        or
        (lease_owner is not null and btrim(lease_owner) <> ''
         and lease_token is not null and lease_expires_at is not null)
    )
);

insert into control.privacy_export_cleanup_lease(singleton) values (true);

revoke all on table control.privacy_export_cleanup_lease from public;

create function control.claim_privacy_export_cleanup(p_lease_owner text)
returns table(lease_token uuid, fence_token bigint)
language plpgsql
security definer
set search_path = pg_catalog, control
as $function$
begin
    if p_lease_owner is null or btrim(p_lease_owner) = '' or length(p_lease_owner) > 255 then
        raise exception 'invalid privacy export cleanup lease owner' using errcode = '22023';
    end if;

    return query
    update control.privacy_export_cleanup_lease cleanup
       set lease_owner = p_lease_owner,
           lease_token = gen_random_uuid(),
           lease_expires_at = now() + interval '2 minutes',
           fence_token = cleanup.fence_token + 1,
           updated_at = now()
     where cleanup.singleton
       and (cleanup.lease_expires_at is null or cleanup.lease_expires_at <= now())
    returning cleanup.lease_token, cleanup.fence_token;
end
$function$;

create function control.renew_privacy_export_cleanup(
    p_lease_owner text,
    p_lease_token uuid,
    p_fence_token bigint
)
returns boolean
language sql
security definer
set search_path = pg_catalog, control
as $function$
    update control.privacy_export_cleanup_lease cleanup
       set lease_expires_at = now() + interval '2 minutes',
           updated_at = now()
     where cleanup.singleton
       and cleanup.lease_owner = p_lease_owner
       and cleanup.lease_token = p_lease_token
       and cleanup.fence_token = p_fence_token
       and cleanup.lease_expires_at > now()
    returning true
$function$;

create function control.mark_privacy_export_artifact_purged(
    p_export_id uuid,
    p_storage_ref text,
    p_lease_owner text,
    p_lease_token uuid,
    p_fence_token bigint
)
returns boolean
language sql
security definer
set search_path = pg_catalog, control
as $function$
    update control.data_subject_exports export
       set storage_ref = concat('purged:', export.storage_ref)
     where export.id = p_export_id
       and export.state in ('consumed', 'expired', 'revoked')
       and export.storage_ref = p_storage_ref
       and p_storage_ref like 'file:%.aead'
       and exists (
           select 1
             from control.privacy_export_cleanup_lease cleanup
            where cleanup.singleton
              and cleanup.lease_owner = p_lease_owner
              and cleanup.lease_token = p_lease_token
              and cleanup.fence_token = p_fence_token
              and cleanup.lease_expires_at > now()
       )
    returning true
$function$;

create function control.release_privacy_export_cleanup(
    p_lease_owner text,
    p_lease_token uuid,
    p_fence_token bigint
)
returns boolean
language sql
security definer
set search_path = pg_catalog, control
as $function$
    update control.privacy_export_cleanup_lease cleanup
       set lease_owner = null,
           lease_token = null,
           lease_expires_at = null,
           updated_at = now()
     where cleanup.singleton
       and cleanup.lease_owner = p_lease_owner
       and cleanup.lease_token = p_lease_token
       and cleanup.fence_token = p_fence_token
       and cleanup.lease_expires_at > now()
    returning true
$function$;

revoke all on function control.claim_privacy_export_cleanup(text) from public;
revoke all on function control.renew_privacy_export_cleanup(text, uuid, bigint) from public;
revoke all on function control.mark_privacy_export_artifact_purged(uuid, text, text, uuid, bigint) from public;
revoke all on function control.release_privacy_export_cleanup(text, uuid, bigint) from public;

do $migration$
begin
    if exists (select 1 from pg_roles where rolname = 'control_privacy_worker') then
        grant execute on function control.claim_privacy_export_cleanup(text)
            to control_privacy_worker;
        grant execute on function control.renew_privacy_export_cleanup(text, uuid, bigint)
            to control_privacy_worker;
        grant execute on function control.mark_privacy_export_artifact_purged(uuid, text, text, uuid, bigint)
            to control_privacy_worker;
        grant execute on function control.release_privacy_export_cleanup(text, uuid, bigint)
            to control_privacy_worker;
    end if;
end
$migration$;

comment on table control.privacy_export_cleanup_lease is
'Singleton cross-replica lease for destructive privacy export artifact cleanup.';

comment on column control.privacy_export_cleanup_lease.fence_token is
'Monotonic generation required by renewal, acknowledgement, and release.';

comment on function control.mark_privacy_export_artifact_purged(uuid, text, text, uuid, bigint) is
'Acknowledges an idempotent file deletion only while the exact cleanup lease remains current.';
