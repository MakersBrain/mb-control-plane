alter table control.data_subject_exports
    add column nonce bytea,
    add column ciphertext bytea,
    add column plaintext_size bigint,
    add column content_type text not null default 'application/json',
    add column filename text;

alter table control.data_subject_exports
    add constraint data_subject_exports_nonce_check
        check(nonce is null or octet_length(nonce)=12),
    add constraint data_subject_exports_ciphertext_check
        check(ciphertext is null or octet_length(ciphertext) between 17 and 8388624),
    add constraint data_subject_exports_plaintext_size_check
        check(plaintext_size is null or plaintext_size between 1 and 8388608),
    add constraint data_subject_exports_content_type_check
        check(content_type='application/json'),
    add constraint data_subject_exports_filename_check
        check(filename is null or filename ~ '^privacy-export-[0-9a-f-]{36}\.json$'),
    add constraint data_subject_exports_ready_payload_check
        check(state<>'ready' or
              (nonce is not null and ciphertext is not null and plaintext_size is not null
               and filename is not null and ready_at is not null));

create view control.data_subject_export_status as
select e.id,e.data_subject_request_id,e.manifest_digest,
       case when e.state='ready' and e.expires_at<=now() then 'expired' else e.state end as state,
       e.ready_at,e.expires_at,
       e.consumed_at,e.created_at,e.content_type,e.filename,e.plaintext_size
from control.data_subject_exports e;

create function control.consume_data_subject_export(p_export_id uuid,p_subject_user_id uuid)
returns table(
    export_id uuid,encryption_key_ref text,nonce bytea,ciphertext bytea,
    manifest_digest text,content_type text,filename text,plaintext_size bigint
)
language plpgsql security definer
set search_path=pg_catalog,control
as $$
declare selected record;
begin
    select e.id as export_id,e.encryption_key_ref,e.nonce,e.ciphertext,e.manifest_digest,
           e.content_type,e.filename,e.plaintext_size,e.expires_at
      into selected
      from control.data_subject_exports e
      join control.data_subject_requests r on r.id=e.data_subject_request_id
     where e.id=p_export_id and r.subject_user_id=p_subject_user_id and e.state='ready'
       for update of e;
    if not found then return; end if;
    if selected.expires_at<=now() then
        update control.data_subject_exports e
           set state='expired',nonce=null,ciphertext=null
         where e.id=p_export_id;
        return;
    end if;
    update control.data_subject_exports e
       set state='consumed',consumed_at=now(),nonce=null,ciphertext=null
     where e.id=p_export_id;
    return query select selected.export_id,selected.encryption_key_ref,selected.nonce,
        selected.ciphertext,selected.manifest_digest,selected.content_type,selected.filename,
        selected.plaintext_size;
end $$;

create function control.purge_expired_data_subject_exports() returns bigint
language plpgsql security definer
set search_path=pg_catalog,control
as $$
declare affected bigint;
begin
    update control.data_subject_exports
       set state='expired',nonce=null,ciphertext=null
     where state='ready' and expires_at<=now();
    get diagnostics affected=row_count;
    return affected;
end $$;

revoke all on control.data_subject_export_status from public;
revoke all on function control.consume_data_subject_export(uuid,uuid) from public;
revoke all on function control.purge_expired_data_subject_exports() from public;

do $$
begin
    if exists(select 1 from pg_roles where rolname='control_api') then
        revoke all on control.data_subject_exports from control_api;
        grant select on control.data_subject_export_status to control_api;
        grant execute on function control.consume_data_subject_export(uuid,uuid) to control_api;
        grant execute on function control.purge_expired_data_subject_exports() to control_api;
    end if;
    if exists(select 1 from pg_roles where rolname='control_privacy_worker') then
        grant execute on function control.purge_expired_data_subject_exports() to control_privacy_worker;
    end if;
end $$;
