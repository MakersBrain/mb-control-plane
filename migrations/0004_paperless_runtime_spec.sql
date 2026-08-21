-- Narrow, non-secret desired state used to reconstruct a missing Paperless
-- Quadlet after host replacement. This is not a generic runtime catalogue.
alter table control.service_instances
  add column runtime_spec jsonb;

alter table control.service_instances
  add constraint service_instances_runtime_spec_check check (
    runtime_spec is null or (
      service = 'paperless'
      and jsonb_typeof(runtime_spec) = 'object'
      and runtime_spec ?& array[
        'version','image','config_digest','container_name','database_ref',
        'database_role','redis_identity','public_hostname','volumes'
      ]
      and runtime_spec - array[
        'version','image','config_digest','container_name','database_ref',
        'database_role','redis_identity','public_hostname','volumes'
      ] = '{}'::jsonb
      and runtime_spec->>'version' = '1'
      and runtime_spec->>'config_digest' ~ '^[a-f0-9]{64}$'
      and jsonb_typeof(runtime_spec->'volumes') = 'array'
    )
  );

do $$ begin
  if exists(select 1 from pg_roles where rolname='control_driver_ledger') then
    execute 'GRANT UPDATE(runtime_spec) ON TABLE control.service_instances TO control_driver_ledger';
  end if;
end $$;
