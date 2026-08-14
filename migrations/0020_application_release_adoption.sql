alter table control.operations drop constraint operations_kind_check;
alter table control.operations add constraint operations_kind_check check (kind in (
    'tenant.provision', 'membership.reconcile', 'entitlement.apply',
    'invoice.capture', 'inventory.capture.extract', 'tenant.reconcile',
    'tenant.lifecycle', 'email.delivery', 'module.enable', 'odoo.release.adopt'
));

alter table control.deployment_driver_operations
    drop constraint deployment_driver_operations_action_check,
    alter column workshop_id drop not null,
    add constraint deployment_driver_operations_action_check check (
        action in ('provision','reconcile','lifecycle','rehearse','release')
    );

-- A fleet operation owns one independently verified recovery set per tenant.
-- Earlier lifecycle operations still produce one row, while this replaces the
-- obsolete global one-recovery-row-per-operation constraint.
alter table control.workshop_recovery_points
    drop constraint if exists odoo_recovery_points_operation_id_key;
alter table control.workshop_recovery_points
    drop constraint if exists workshop_recovery_points_operation_id_key;
create unique index workshop_recovery_operation_database
    on control.workshop_recovery_points(operation_id,database_id)
    where operation_id is not null;

create table control.application_releases (
    id text primary key check (id ~ '^odoo-[0-9]{4}\.[0-9]{2}\.[0-9]{2}-[a-f0-9]{7,64}$'),
    source_commit text not null check (source_commit ~ '^[a-f0-9]{40,64}$'),
    odoo_version text not null check (odoo_version ~ '^19\.[0-9]+$'),
    image_digest text not null unique check (image_digest ~ '^sha256:[a-f0-9]{64}$'),
    manifest_digest text not null unique check (manifest_digest ~ '^sha256:[a-f0-9]{64}$'),
    addon_versions jsonb not null check (jsonb_typeof(addon_versions)='object'),
    compatibility jsonb not null check (jsonb_typeof(compatibility)='object'),
    bridge_contract text not null,
    schema_epoch bigint not null check (schema_epoch > 0),
    change_class text not null check (change_class in ('A','B','C')),
    required_postconditions jsonb not null check (jsonb_typeof(required_postconditions)='array'),
    manifest jsonb not null check (jsonb_typeof(manifest)='object'),
    signature_bundle_ref text not null,
    provenance_ref text not null,
    sbom_ref text not null,
    published_at timestamptz not null,
    status text not null default 'candidate' check (status in (
        'candidate','preflighting','canary','prepared','active','retained','failed'
    )),
    version bigint not null default 1 check (version > 0),
    publication_idempotency_key text not null unique check (btrim(publication_idempotency_key)<>''),
    publication_request_digest bytea not null check (octet_length(publication_request_digest)=32),
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);
create unique index application_release_one_active
on control.application_releases((status)) where status='active';

create table control.tenant_release_adoptions (
    id uuid primary key,
    workshop_id uuid not null references control.workshops(id) on delete restrict,
    database_id uuid not null references control.odoo_databases(id) on delete restrict,
    release_id text not null references control.application_releases(id) on delete restrict,
    source_release_id text references control.application_releases(id) on delete restrict,
    registry_version integer not null check (registry_version > 0),
    state text not null default 'pending' check (state in (
        'pending','isolating','backing_up','upgrading','verifying','prepared',
        'active','superseded','failed','restoring','rolled_back'
    )),
    operation_id uuid references control.operations(id) on delete restrict,
    backup_recovery_id uuid references control.workshop_recovery_points(id) on delete restrict,
    source_schema_epoch bigint check (source_schema_epoch is null or source_schema_epoch > 0),
    target_schema_epoch bigint not null check (target_schema_epoch > 0),
    started_at timestamptz,
    verified_at timestamptz,
    activated_at timestamptz,
    superseded_at timestamptz,
    failure_class text,
    evidence jsonb not null default '{}' check (jsonb_typeof(evidence)='object'),
    version bigint not null default 1 check (version > 0),
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    unique (workshop_id,database_id,release_id),
    check (source_release_id is null or source_release_id<>release_id)
);

create unique index tenant_release_one_unfinished
on control.tenant_release_adoptions(workshop_id,database_id)
where state in ('pending','isolating','backing_up','upgrading','verifying','prepared','failed','restoring');

create unique index tenant_release_one_active
on control.tenant_release_adoptions(workshop_id,database_id)
where state='active';

create table control.runtime_release_slots (
    runtime_key text not null check (btrim(runtime_key)<>''),
    slot text not null check (slot in ('blue','green')),
    release_id text not null references control.application_releases(id) on delete restrict,
    state text not null check (state in ('inactive','starting','verifying','prepared','active','retained','failed')),
    image_digest text not null check (image_digest ~ '^sha256:[a-f0-9]{64}$'),
    started_at timestamptz,
    verified_at timestamptz,
    activated_at timestamptz,
    evidence jsonb not null default '{}' check (jsonb_typeof(evidence)='object'),
    version bigint not null default 1 check (version > 0),
    primary key(runtime_key,slot)
);

create unique index runtime_release_one_active
on control.runtime_release_slots(runtime_key) where state='active';

create table control.release_fleet_runs (
    id uuid primary key,
    release_id text not null references control.application_releases(id) on delete restrict,
    operation_id uuid not null unique references control.operations(id) on delete restrict,
    fleet_generation bigint not null check (fleet_generation > 0),
    state text not null check (state in ('preflighting','preparing','paused','activating','active','failed')),
    tenant_snapshot jsonb not null check (jsonb_typeof(tenant_snapshot)='array'),
    canary_workshop_id uuid references control.workshops(id) on delete restrict,
    target_slot text check (target_slot in ('blue','green')),
    failure_class text,
    evidence jsonb not null default '{}' check (jsonb_typeof(evidence)='object'),
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

create unique index release_fleet_one_unfinished
on control.release_fleet_runs((true))
where state in ('preflighting','preparing','paused','activating');

create table control.fleet_activation_intents (
    id uuid primary key,
    fleet_run_id uuid not null unique references control.release_fleet_runs(id) on delete restrict,
    release_id text not null references control.application_releases(id) on delete restrict,
    runtime_key text not null,
    target_slot text not null check (target_slot in ('blue','green')),
    image_digest text not null check (image_digest ~ '^sha256:[a-f0-9]{64}$'),
    prepared_tenants jsonb not null check (jsonb_typeof(prepared_tenants)='array'),
    gateway_configuration_digest text not null check (gateway_configuration_digest ~ '^sha256:[a-f0-9]{64}$'),
    driver_action_id uuid not null unique,
    observed_configuration_digest text,
    created_at timestamptz not null default now(),
    activated_at timestamptz
);

create function control.validate_fleet_activation_intent_update() returns trigger
language plpgsql set search_path=pg_catalog,control as $$
begin
    if new.id<>old.id or new.fleet_run_id<>old.fleet_run_id
       or new.release_id<>old.release_id or new.runtime_key<>old.runtime_key
       or new.target_slot<>old.target_slot or new.image_digest<>old.image_digest
       or new.prepared_tenants<>old.prepared_tenants
       or new.gateway_configuration_digest<>old.gateway_configuration_digest
       or new.driver_action_id<>old.driver_action_id or new.created_at<>old.created_at
    then raise exception 'fleet activation intent is immutable' using errcode='55000'; end if;
    if new.observed_configuration_digest is not null
       and new.observed_configuration_digest<>new.gateway_configuration_digest
    then raise exception 'observed gateway digest does not match activation intent' using errcode='23514'; end if;
    if old.observed_configuration_digest is not null
       and new.observed_configuration_digest is distinct from old.observed_configuration_digest
    then raise exception 'observed gateway digest is immutable once recorded' using errcode='55000'; end if;
    if old.activated_at is not null and new.activated_at is distinct from old.activated_at
    then raise exception 'activation timestamp is immutable once recorded' using errcode='55000'; end if;
    return new;
end $$;

create trigger fleet_activation_intent_update
before update on control.fleet_activation_intents
for each row execute function control.validate_fleet_activation_intent_update();

create function control.validate_application_release_transition() returns trigger
language plpgsql set search_path=pg_catalog,control as $$
begin
    if new.status<>old.status and not (
        (old.status='candidate' and new.status in ('preflighting','failed')) or
        (old.status='preflighting' and new.status in ('canary','failed')) or
        (old.status='canary' and new.status in ('prepared','failed')) or
        (old.status='prepared' and new.status in ('active','failed')) or
        (old.status='active' and new.status='retained')
    ) then raise exception 'invalid application release transition % -> %',old.status,new.status using errcode='23514';
    end if;
    if new.version<>old.version+1 then raise exception 'release version must increment exactly once' using errcode='40001'; end if;
    new.updated_at=now();
    return new;
end $$;

create trigger application_release_transition
before update on control.application_releases
for each row execute function control.validate_application_release_transition();

create function control.validate_tenant_release_transition() returns trigger
language plpgsql set search_path=pg_catalog,control as $$
begin
    if new.state<>old.state and not (
        (old.state='pending' and new.state in ('isolating','failed')) or
        (old.state='isolating' and new.state in ('backing_up','failed')) or
        (old.state='backing_up' and new.state in ('upgrading','failed')) or
        (old.state='upgrading' and new.state in ('verifying','failed')) or
        (old.state='verifying' and new.state in ('prepared','failed')) or
        (old.state='prepared' and new.state in ('active','restoring')) or
        (old.state='active' and new.state='superseded') or
        (old.state='failed' and new.state='restoring') or
        (old.state='restoring' and new.state in ('rolled_back','failed'))
    ) then raise exception 'invalid tenant release transition % -> %',old.state,new.state using errcode='23514';
    end if;
    if new.version<>old.version+1 then raise exception 'adoption version must increment exactly once' using errcode='40001'; end if;
    new.updated_at=now();
    return new;
end $$;

create trigger tenant_release_transition
before update on control.tenant_release_adoptions
for each row execute function control.validate_tenant_release_transition();

revoke all on function control.validate_application_release_transition() from public;
revoke all on function control.validate_tenant_release_transition() from public;
revoke all on function control.validate_fleet_activation_intent_update() from public;

do $$
begin
    if exists(select 1 from pg_roles where rolname='control_api') then
        grant select,insert,update on control.application_releases,
            control.tenant_release_adoptions,control.release_fleet_runs,
            control.fleet_activation_intents to control_api;
        grant select on control.runtime_release_slots to control_api;
    end if;
    if exists(select 1 from pg_roles where rolname='control_release_worker') then
        grant usage on schema control to control_release_worker;
        grant select,update on control.application_releases,
            control.tenant_release_adoptions,control.runtime_release_slots,
            control.release_fleet_runs,control.fleet_activation_intents,
            control.workshops,control.odoo_databases,control.workshop_modules,
            control.service_instances,control.workshop_recovery_points
            ,control.capability_registry_versions
        to control_release_worker;
        grant select,insert,update on control.operations,
            control.workshop_recovery_points to control_release_worker;
        grant insert on control.runtime_release_slots,
            control.tenant_release_adoptions,control.fleet_activation_intents
        to control_release_worker;
    end if;
    if exists(select 1 from pg_roles where rolname='control_driver_ledger') then
        grant select,insert,update on control.application_releases,
            control.tenant_release_adoptions,control.runtime_release_slots,
            control.release_fleet_runs,control.fleet_activation_intents
        to control_driver_ledger;
    end if;
end $$;
