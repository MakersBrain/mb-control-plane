-- Large processor exports must not place document or invoice bodies in the
-- control database. Existing PostgreSQL-backed exports remain redeemable;
-- newly prepared exports use an encrypted artifact on the dedicated volume.
alter table control.data_subject_exports
    drop constraint data_subject_exports_ciphertext_check,
    drop constraint data_subject_exports_plaintext_size_check,
    drop constraint data_subject_exports_ready_payload_check,
    add constraint data_subject_exports_ciphertext_check
        check(ciphertext is null or octet_length(ciphertext) between 17 and 134217744),
    add constraint data_subject_exports_plaintext_size_check
        check(plaintext_size is null or plaintext_size between 1 and 134217728),
    add constraint data_subject_exports_ready_payload_check
        check(state<>'ready' or (
            nonce is not null and plaintext_size is not null and filename is not null
            and ready_at is not null and (
                (storage_ref like 'postgres:aead:%' and ciphertext is not null) or
                (storage_ref like 'file:%.aead' and ciphertext is null)
            )
        ));

create index data_subject_exports_terminal_file_artifacts
    on control.data_subject_exports(id)
    where state in ('consumed','expired','revoked') and storage_ref like 'file:%.aead';

drop function control.consume_data_subject_export(uuid,uuid);
create function control.consume_data_subject_export(p_export_id uuid,p_subject_user_id uuid)
returns table(
    export_id uuid,encryption_key_ref text,storage_ref text,nonce bytea,ciphertext bytea,
    manifest_digest text,content_type text,filename text,plaintext_size bigint
)
language plpgsql security definer
set search_path=pg_catalog,control
as $$
declare selected record;
begin
    select e.id as export_id,e.encryption_key_ref,e.storage_ref,e.nonce,e.ciphertext,
           e.manifest_digest,e.content_type,e.filename,e.plaintext_size,e.expires_at
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
    return query select selected.export_id,selected.encryption_key_ref,
        selected.storage_ref,selected.nonce,selected.ciphertext,selected.manifest_digest,
        selected.content_type,selected.filename,selected.plaintext_size;
end $$;

revoke all on function control.consume_data_subject_export(uuid,uuid) from public;

do $$
begin
    if exists(select 1 from pg_roles where rolname='control_api') then
        grant execute on function control.consume_data_subject_export(uuid,uuid) to control_api;
    end if;
    if exists(select 1 from pg_roles where rolname='control_driver_ledger') then
        grant select on control.data_subject_requests,control.memberships,
            control.external_identities,control.service_instances,
            control.odoo_databases to control_driver_ledger;
    end if;
end $$;
