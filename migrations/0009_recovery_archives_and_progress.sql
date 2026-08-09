alter table control.operations
    add column progress_percent smallint not null default 0
        check (progress_percent between 0 and 100),
    add column progress_phase text,
    add column progress_message text,
    add column progress_updated_at timestamptz;

alter table control.workshop_recovery_points
    add column archive_object_key text,
    add column archive_size_bytes bigint check (archive_size_bytes >= 0),
    add column archive_digest text check (
        archive_digest is null or archive_digest ~ '^[0-9a-f]{64}$'
    );

alter table control.workshop_recovery_components
    drop constraint workshop_recovery_components_component_check;

alter table control.workshop_recovery_components
    add constraint workshop_recovery_components_component_check check (component in (
        'odoo-database', 'odoo-filestore', 'paperless-database',
        'paperless-data', 'paperless-media', 'paperless-consume',
        'manifest', 'commit-marker', 'portable-archive'
    ));

comment on column control.operations.progress_percent is
'Durable phase-based progress for browser updates; it is not a byte-accurate transfer meter.';
comment on column control.workshop_recovery_points.archive_object_key is
'Server-owned S3 key for the single-file encrypted portable archive; never accepted from clients.';
