alter table control.odoo_recovery_points
    rename to workshop_recovery_points;

alter table control.odoo_databases
    add column connection_limit_before_lifecycle integer
        check (connection_limit_before_lifecycle is null or connection_limit_before_lifecycle >= -1);

alter index control.odoo_recovery_points_workshop
    rename to workshop_recovery_points_workshop;

alter table control.workshop_recovery_points
    add column component_scope text[] not null default array['odoo']::text[],
    add column format_version text not null default 'makersbrain-odoo-recovery-v1',
    add column storage_location text not null default 'local',
    add column object_prefix text,
    add column manifest_digest text,
    add column encryption_key_id text,
    add column source_release text,
    add column paperless_version text,
    add column verification_state text not null default 'pending',
    add column verified_at timestamptz;

alter table control.workshop_recovery_points
    add constraint workshop_recovery_points_component_scope_check check (
        cardinality(component_scope) > 0
        and component_scope @> array['odoo']::text[]
        and component_scope <@ array['odoo', 'paperless']::text[]
    ),
    add constraint workshop_recovery_points_format_version_check check (
        btrim(format_version) <> ''
    ),
    add constraint workshop_recovery_points_storage_location_check check (
        storage_location in ('local', 's3')
    ),
    add constraint workshop_recovery_points_manifest_digest_check check (
        manifest_digest is null or manifest_digest ~ '^[0-9a-f]{64}$'
    ),
    add constraint workshop_recovery_points_verification_state_check check (
        verification_state in ('pending', 'verified', 'failed')
    ),
    add constraint workshop_recovery_points_verified_check check (
        verification_state <> 'verified' or verified_at is not null
    );

update control.workshop_recovery_points
set verification_state = 'verified',
    verified_at = coalesce(ready_at, created_at)
where state = 'ready';

create table control.workshop_recovery_components (
    recovery_point_id uuid not null
        references control.workshop_recovery_points(id) on delete cascade,
    component text not null check (component in (
        'odoo-database', 'odoo-filestore', 'paperless-database',
        'paperless-data', 'paperless-media', 'paperless-consume',
        'manifest', 'commit-marker'
    )),
    object_key text not null check (btrim(object_key) <> ''),
    size_bytes bigint not null check (size_bytes >= 0),
    digest text not null check (digest ~ '^[0-9a-f]{64}$'),
    plaintext_digest text check (
        plaintext_digest is null or plaintext_digest ~ '^[0-9a-f]{64}$'
    ),
    state text not null default 'verified' check (state in (
        'uploading', 'verified', 'failed'
    )),
    verified_at timestamptz,
    primary key (recovery_point_id, component),
    check (state <> 'verified' or verified_at is not null)
);

create table control.workshop_recovery_rehearsals (
    id uuid primary key,
    recovery_point_id uuid not null
        references control.workshop_recovery_points(id) on delete cascade,
    workshop_id uuid not null references control.workshops(id) on delete cascade,
    state text not null check (state in ('running', 'succeeded', 'failed')),
    started_at timestamptz not null default now(),
    finished_at timestamptz,
    safe_error text,
    check (state = 'running' or finished_at is not null)
);

create index workshop_recovery_rehearsals_due
    on control.workshop_recovery_rehearsals(workshop_id, started_at desc);

comment on table control.workshop_recovery_points is
'Versioned, verified recovery sets for Odoo and active stateful workshop services.';
comment on column control.workshop_recovery_points.component_scope is
'Immutable component scope captured when creation starts; always contains Odoo and conditionally Paperless.';
comment on column control.workshop_recovery_points.storage_ref is
'Server-owned opaque local or S3 reference. It must never be accepted from an API or operation payload.';
comment on table control.workshop_recovery_components is
'Integrity metadata for every object committed as part of a workshop recovery set.';
comment on table control.workshop_recovery_rehearsals is
'Monthly isolated download, decryption, integrity and temporary database restore checks.';
