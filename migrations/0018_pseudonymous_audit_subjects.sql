alter table control.users
    add column audit_subject_id uuid not null default gen_random_uuid(),
    add constraint users_audit_subject_unique unique (audit_subject_id);

alter table control.audit_events
    add column actor_audit_subject_id uuid;

alter table control.audit_events disable trigger audit_events_append_only;

update control.audit_events a
set actor_audit_subject_id = u.audit_subject_id
from control.users u
where u.id = a.actor_user_id;

create index audit_events_actor_subject
    on control.audit_events (actor_audit_subject_id, created_at desc);

alter table control.audit_events
    drop column actor_user_id;

alter table control.audit_events enable trigger audit_events_append_only;

comment on column control.users.audit_subject_id is
    'Random pseudonymous identifier used in immutable security/audit evidence';
comment on column control.audit_events.actor_audit_subject_id is
    'Pseudonymous actor; resolve to a user only through authorized subject-rights/security workflows';
