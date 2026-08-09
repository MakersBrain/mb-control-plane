create table control.workshop_deletions (
    workshop_id uuid primary key references control.workshops(id) on delete restrict,
    state text not null default 'scheduled' check (state in (
        'scheduled', 'quarantining', 'retained', 'failed'
    )),
    previous_status text not null check (previous_status in (
        'provisioning', 'trial', 'active', 'past_due', 'restricted', 'suspended'
    )),
    requested_by uuid not null references control.users(id) on delete restrict,
    operation_id uuid not null unique references control.operations(id) on delete restrict,
    final_recovery_point_id uuid not null unique references control.workshop_recovery_points(id) on delete restrict,
    requested_at timestamptz not null default now(),
    quarantined_at timestamptz,
    purge_after timestamptz not null,
    failure_class text,
    check (purge_after > requested_at),
    check ((state = 'retained') = (quarantined_at is not null))
);

comment on table control.workshop_deletions is
'Operator-requested workshop removal. A workshop is hidden only after its final encrypted backup is verified and its runtime is quarantined; retained records are eligible for a separately controlled physical purge after purge_after.';
