create table control.product_lookup_fills (
    provider text not null,
    schema_version integer not null check(schema_version>0),
    gtin14 text not null check(gtin14 ~ '^[0-9]{14}$'),
    state text not null check(state in ('filling','idle','failed')),
    leased_by uuid,
    lease_expires_at timestamptz,
    last_error_class text,
    updated_at timestamptz not null default now(),
    primary key(provider,schema_version,gtin14),
    check((state='filling')=(leased_by is not null and lease_expires_at is not null)),
    check(last_error_class is null or (length(last_error_class) between 1 and 100))
);
create index product_lookup_fills_expired on control.product_lookup_fills(lease_expires_at)
where state='filling';

do $$
begin
    if exists(select 1 from pg_roles where rolname='control_api') then
        grant select,insert,update on control.product_lookup_fills to control_api;
    end if;
end $$;
