create table control.odoo_databases (
    id uuid primary key,
    workshop_id uuid not null references control.workshops(id) on delete restrict,
    service_instance_id uuid references control.service_instances(id) on delete restrict,
    kind text not null check (kind in ('primary', 'duplicate')),
    database_ref text not null unique check (database_ref ~ '^mb_[0-9a-f]{32}$'),
    public_hostname text unique,
    label text not null check (btrim(label) <> ''),
    state text not null default 'provisioning' check (state in (
        'provisioning', 'ready', 'snapshotting', 'restoring', 'duplicating',
        'suspended', 'failed', 'deleted'
    )),
    source_database_id uuid,
    routable boolean not null default false,
    created_at timestamptz not null default now(),
    last_restored_at timestamptz,
    deleted_at timestamptz,
    check (public_hostname is null or public_hostname = lower(public_hostname)),
    check (public_hostname is null or public_hostname ~ '^[a-z0-9][a-z0-9.-]*[a-z0-9]$'),
    check (public_hostname is null or public_hostname <> database_ref),
    check ((kind = 'primary') = (routable and public_hostname is not null)),
    check ((kind = 'duplicate') = (source_database_id is not null)),
    unique (id, workshop_id),
    foreign key (source_database_id, workshop_id)
        references control.odoo_databases(id, workshop_id) on delete restrict
);

create unique index odoo_databases_one_primary
on control.odoo_databases (workshop_id)
where kind = 'primary' and deleted_at is null;

create table control.odoo_recovery_points (
    id uuid primary key,
    workshop_id uuid not null references control.workshops(id) on delete restrict,
    database_id uuid not null,
    operation_id uuid unique references control.operations(id) on delete restrict,
    kind text not null check (kind in ('snapshot', 'backup')),
    label text not null check (btrim(label) <> ''),
    state text not null default 'queued' check (state in (
        'queued', 'creating', 'ready', 'failed', 'expired', 'deleted'
    )),
    storage_ref text,
    size_bytes bigint check (size_bytes is null or size_bytes >= 0),
    requested_by uuid not null references control.users(id) on delete restrict,
    created_at timestamptz not null default now(),
    ready_at timestamptz,
    expires_at timestamptz,
    check (state <> 'ready' or ready_at is not null),
    check (expires_at is null or expires_at > created_at),
    foreign key (database_id, workshop_id)
        references control.odoo_databases(id, workshop_id) on delete restrict
);

create index odoo_recovery_points_workshop
on control.odoo_recovery_points (workshop_id, created_at desc);

comment on column control.odoo_databases.database_ref is
'Opaque physical database identifier. It must never be derived from a workshop slug or hostname.';
comment on column control.odoo_databases.public_hostname is
'User-facing routing name. The deployment gateway maps it to the opaque database identifier.';
