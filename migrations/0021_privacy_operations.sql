alter table control.operations drop constraint operations_kind_check;
alter table control.operations add constraint operations_kind_check check (kind in (
    'tenant.provision', 'membership.reconcile', 'entitlement.apply',
    'invoice.capture', 'inventory.capture.extract', 'tenant.reconcile',
    'tenant.lifecycle', 'email.delivery', 'module.enable', 'odoo.release.adopt',
    'privacy.retention', 'privacy.data_subject_request'
));

create table control.privacy_platform_state (
    singleton boolean primary key default true check(singleton),
    controller_ref text,
    dpo_ref text,
    production_personal_data_allowed boolean not null default false,
    approved_retention_policy_version integer,
    approved_processing_register_version integer,
    dpia_approval_ref text,
    version bigint not null default 1 check(version>0),
    updated_at timestamptz not null default now(),
    check(not production_personal_data_allowed or (
        controller_ref is not null and btrim(controller_ref)<>''
        and approved_retention_policy_version is not null
        and approved_processing_register_version is not null
        and dpia_approval_ref is not null and btrim(dpia_approval_ref)<>''
    ))
);
insert into control.privacy_platform_state(singleton) values(true);

create table control.retention_policy_versions (
    version integer primary key check(version>0),
    status text not null check(status in ('draft','approval_required','approved','retired')),
    policy jsonb not null check(jsonb_typeof(policy)='object'),
    policy_digest text not null unique check(policy_digest ~ '^sha256:[0-9a-f]{64}$'),
    controller_ref text,
    approval_ref text,
    approved_by uuid references control.users(id) on delete restrict,
    approved_at timestamptz,
    effective_at timestamptz,
    created_at timestamptz not null default now(),
    check((status='approved')=(approval_ref is not null and approved_by is not null and approved_at is not null)),
    check(status<>'approved' or not jsonb_path_exists(policy,'$.datasets.* ? (@.duration_days == null)'))
);

create table control.processing_register_versions (
    version integer primary key check(version>0),
    status text not null check(status in ('draft','approval_required','approved','retired')),
    activities jsonb not null check(jsonb_typeof(activities)='array'),
    register_digest text not null unique check(register_digest ~ '^sha256:[0-9a-f]{64}$'),
    controller_ref text,
    approval_ref text,
    approved_by uuid references control.users(id) on delete restrict,
    approved_at timestamptz,
    created_at timestamptz not null default now(),
    check((status='approved')=(approval_ref is not null and approved_by is not null and approved_at is not null))
);

create table control.processor_approvals (
    id uuid primary key,
    processing_register_version integer not null references control.processing_register_versions(version) on delete restrict,
    provider_key text not null check(provider_key ~ '^[a-z0-9][a-z0-9_-]{1,63}$'),
    purpose_key text not null check(purpose_key ~ '^[a-z0-9][a-z0-9_-]{1,63}$'),
    region text not null check(btrim(region)<>''),
    eea boolean not null,
    article_28_terms_ref text not null check(btrim(article_28_terms_ref)<>''),
    transfer_assessment_ref text,
    status text not null check(status in ('pending','approved','suspended','revoked')),
    valid_from timestamptz,
    valid_until timestamptz,
    created_at timestamptz not null default now(),
    unique(processing_register_version,provider_key,purpose_key),
    check(eea or transfer_assessment_ref is not null),
    check(status<>'approved' or valid_from is not null),
    check(valid_until is null or valid_from is null or valid_until>valid_from)
);

create table control.data_subject_requests (
    id uuid primary key,
    subject_user_id uuid not null references control.users(id) on delete restrict,
    request_type text not null check(request_type in ('access','rectification','erasure','restriction','portability','objection')),
    scope jsonb not null default '{}' check(jsonb_typeof(scope)='object'),
    status text not null default 'received' check(status in (
        'received','identity_verification','controller_review','approved','executing',
        'completed','refused','cancelled'
    )),
    identity_verification_state text not null default 'verified_session' check(identity_verification_state in ('pending','verified_session','verified_out_of_band','failed')),
    controller_required boolean not null default true,
    requested_at timestamptz not null default now(),
    due_at timestamptz not null default now()+interval '1 month',
    extended_due_at timestamptz,
    extension_notification_ref text,
    decision_code text,
    approver_user_id uuid references control.users(id) on delete restrict,
    decided_at timestamptz,
    operation_id uuid references control.operations(id) on delete restrict,
    completed_at timestamptz,
    version bigint not null default 1 check(version>0),
    updated_at timestamptz not null default now(),
    check(extended_due_at is null or (extended_due_at>due_at and extension_notification_ref is not null)),
    check(status not in ('approved','refused') or (decision_code is not null and approver_user_id is not null and decided_at is not null)),
    check(status<>'completed' or completed_at is not null)
);
create index data_subject_requests_due on control.data_subject_requests(coalesce(extended_due_at,due_at))
where status not in ('completed','refused','cancelled');

create table control.processing_holds (
    id uuid primary key,
    data_subject_request_id uuid not null references control.data_subject_requests(id) on delete restrict,
    subject_user_id uuid not null references control.users(id) on delete restrict,
    workshop_id uuid references control.workshops(id) on delete restrict,
    exception_scope text[] not null default array['storage']::text[] check(exception_scope <@ array['storage','legal_claims','security']::text[]),
    active boolean not null default true,
    imposed_at timestamptz not null default now(),
    released_at timestamptz,
    released_by uuid references control.users(id) on delete restrict,
    release_reason_code text,
    check(active=(released_at is null and released_by is null and release_reason_code is null))
);
create unique index processing_hold_active_subject_scope on control.processing_holds(subject_user_id,coalesce(workshop_id,'00000000-0000-0000-0000-000000000000'::uuid)) where active;

create table control.data_subject_processor_tasks (
    id uuid primary key,
    data_subject_request_id uuid not null references control.data_subject_requests(id) on delete restrict,
    processor_key text not null,
    action text not null check(action in ('search','export','rectify','erase','restrict','unrestrict','object')),
    state text not null default 'pending' check(state in ('pending','sent','acknowledged','failed','not_applicable')),
    acknowledgement_ref text,
    safe_error_class text,
    version bigint not null default 1 check(version>0),
    updated_at timestamptz not null default now(),
    unique(data_subject_request_id,processor_key,action),
    check(state<>'acknowledged' or acknowledgement_ref is not null)
);

create function control.validate_processor_task_update() returns trigger
language plpgsql set search_path=pg_catalog,control as $$
begin
    if new.id<>old.id or new.data_subject_request_id<>old.data_subject_request_id
       or new.processor_key<>old.processor_key or new.action<>old.action
    then raise exception 'processor task identity is immutable' using errcode='55000'; end if;
    if not (
        (old.state='pending' and new.state in ('sent','acknowledged','failed','not_applicable')) or
        (old.state='sent' and new.state in ('sent','acknowledged','failed','not_applicable')) or
        (old.state='failed' and new.state in ('sent','acknowledged','not_applicable'))
    ) then raise exception 'invalid processor task transition % -> %',old.state,new.state using errcode='23514'; end if;
    if new.version<>old.version+1 then raise exception 'processor task version must increment exactly once' using errcode='40001'; end if;
    new.updated_at=now(); return new;
end $$;
create trigger processor_task_update before update on control.data_subject_processor_tasks
for each row execute function control.validate_processor_task_update();

create table control.data_subject_exports (
    id uuid primary key,
    data_subject_request_id uuid not null unique references control.data_subject_requests(id) on delete restrict,
    storage_ref text not null check(btrim(storage_ref)<>''),
    encryption_key_ref text not null check(btrim(encryption_key_ref)<>''),
    manifest_digest text not null check(manifest_digest ~ '^sha256:[0-9a-f]{64}$'),
    state text not null check(state in ('preparing','ready','consumed','expired','revoked')),
    ready_at timestamptz,
    expires_at timestamptz not null,
    consumed_at timestamptz,
    created_at timestamptz not null default now(),
    check(expires_at>created_at),
    check(state<>'ready' or ready_at is not null),
    check(state<>'consumed' or consumed_at is not null)
);

create table control.erasure_tombstones (
    id uuid primary key,
    subject_key uuid not null,
    subject_user_id uuid references control.users(id) on delete set null,
    workshop_id uuid references control.workshops(id) on delete restrict,
    source_request_id uuid not null references control.data_subject_requests(id) on delete restrict,
    sequence bigint generated always as identity unique,
    applies_before timestamptz not null default now(),
    required_locations text[] not null,
    completed_locations text[] not null default '{}',
    state text not null default 'pending' check(state in ('pending','applying','complete','held')),
    created_at timestamptz not null default now(),
    completed_at timestamptz,
    check(completed_locations <@ required_locations),
    check(state<>'complete' or (completed_locations @> required_locations and completed_at is not null))
);
create unique index erasure_tombstone_request_scope on control.erasure_tombstones(
    source_request_id,coalesce(workshop_id,'00000000-0000-0000-0000-000000000000'::uuid)
);

create table control.retention_runs (
    id uuid primary key,
    policy_version integer references control.retention_policy_versions(version) on delete restrict,
    operation_id uuid not null unique references control.operations(id) on delete restrict,
    dry_run boolean not null,
    state text not null default 'queued' check(state in ('queued','running','completed','failed','blocked_approval')),
    evidence jsonb not null default '{}' check(jsonb_typeof(evidence)='object'),
    started_at timestamptz,
    completed_at timestamptz,
    created_at timestamptz not null default now(),
    check(not dry_run or state not in ('completed') or coalesce((evidence->>'deleted_count')::bigint,0)=0)
);

create table control.privacy_incidents (
    id uuid primary key,
    discovered_at timestamptz not null,
    controller_awareness_at timestamptz,
    authority_deadline_at timestamptz,
    affected_categories text[] not null check(cardinality(affected_categories)>0),
    affected_workshop_ids uuid[] not null default '{}',
    estimated_subject_count bigint check(estimated_subject_count is null or estimated_subject_count>=0),
    containment_state text not null check(containment_state in ('investigating','contained','eradicated','monitoring','closed')),
    risk_level text check(risk_level in ('undetermined','low','medium','high')),
    notification_required boolean,
    decision_ref text,
    authority_notification_ref text,
    subject_notification_ref text,
    version bigint not null default 1,
    created_by uuid not null references control.users(id) on delete restrict,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    check(notification_required is null or decision_ref is not null),
    check(notification_required is distinct from true or controller_awareness_at is not null)
);

create table control.legal_holds (
    id uuid primary key,
    scope jsonb not null check(jsonb_typeof(scope)='object'),
    reason_code text not null check(btrim(reason_code)<>''),
    approval_ref text not null check(btrim(approval_ref)<>''),
    imposed_by uuid not null references control.users(id) on delete restrict,
    imposed_at timestamptz not null default now(),
    expires_at timestamptz not null,
    released_at timestamptz,
    released_by uuid references control.users(id) on delete restrict,
    release_reason_code text,
    version bigint not null default 1 check(version>0),
    check(expires_at>imposed_at),
    check(scope ? 'datasets' and jsonb_typeof(scope->'datasets')='array' and jsonb_array_length(scope->'datasets')>0),
    check(not scope ? 'workshop_ids' or jsonb_typeof(scope->'workshop_ids')='array'),
    check(not scope ? 'subject_user_ids' or jsonb_typeof(scope->'subject_user_ids')='array'),
    check((released_at is null and released_by is null and release_reason_code is null)
       or (released_at is not null and released_by is not null and release_reason_code is not null))
);

create function control.set_privacy_incident_deadline() returns trigger
language plpgsql set search_path=pg_catalog,control as $$
begin
    new.authority_deadline_at=case when new.controller_awareness_at is null then null else new.controller_awareness_at+interval '72 hours' end;
    return new;
end $$;
create trigger privacy_incident_deadline before insert or update of controller_awareness_at
on control.privacy_incidents for each row execute function control.set_privacy_incident_deadline();

create function control.validate_privacy_incident_update() returns trigger
language plpgsql set search_path=pg_catalog,control as $$
begin
    if new.id<>old.id or new.discovered_at<>old.discovered_at or new.created_by<>old.created_by
       or new.created_at<>old.created_at
    then raise exception 'privacy incident identity is immutable' using errcode='55000'; end if;
    if (case new.containment_state when 'investigating' then 1 when 'contained' then 2
           when 'eradicated' then 3 when 'monitoring' then 4 when 'closed' then 5 end
       < (case old.containment_state when 'investigating' then 1 when 'contained' then 2
           when 'eradicated' then 3 when 'monitoring' then 4 when 'closed' then 5 end)
       )
    then raise exception 'privacy incident containment cannot move backwards' using errcode='23514'; end if;
    if new.version<>old.version+1
    then raise exception 'privacy incident version must increment exactly once' using errcode='40001'; end if;
    new.updated_at=now(); return new;
end $$;
create trigger privacy_incident_update before update on control.privacy_incidents
for each row execute function control.validate_privacy_incident_update();

create function control.validate_legal_hold_update() returns trigger
language plpgsql set search_path=pg_catalog,control as $$
begin
    if new.id<>old.id or new.scope<>old.scope or new.reason_code<>old.reason_code
       or new.approval_ref<>old.approval_ref or new.imposed_by<>old.imposed_by
       or new.imposed_at<>old.imposed_at or new.expires_at<>old.expires_at
    then raise exception 'legal hold scope and authority are immutable' using errcode='55000'; end if;
    if old.released_at is not null
    then raise exception 'a released legal hold cannot be changed' using errcode='23514'; end if;
    if new.version<>old.version+1
    then raise exception 'legal hold version must increment exactly once' using errcode='40001'; end if;
    return new;
end $$;
create trigger legal_hold_update before update on control.legal_holds
for each row execute function control.validate_legal_hold_update();

create function control.legal_hold_applies(p_dataset_key text, p_workshop_id uuid, p_subject_ids uuid[])
returns boolean language sql stable set search_path=pg_catalog,control as $$
    select exists(
        select 1 from legal_holds h
        where h.released_at is null and h.expires_at>now()
          and ((h.scope->'datasets') ? p_dataset_key or (h.scope->'datasets') ? '*')
          and (
              coalesce(jsonb_array_length(h.scope->'workshop_ids'),0)=0
              or h.scope @> jsonb_build_object('workshop_ids',jsonb_build_array(p_workshop_id))
          )
          and (
              coalesce(jsonb_array_length(h.scope->'subject_user_ids'),0)=0
              or exists(
                  select 1 from unnest(coalesce(p_subject_ids,'{}'::uuid[])) as subject(subject_id)
                  where h.scope @> jsonb_build_object('subject_user_ids',jsonb_build_array(subject.subject_id))
              )
          )
    )
$$;

alter table control.privacy_platform_state
    add constraint privacy_platform_retention_version_fk foreign key(approved_retention_policy_version)
        references control.retention_policy_versions(version) on delete restrict,
    add constraint privacy_platform_register_version_fk foreign key(approved_processing_register_version)
        references control.processing_register_versions(version) on delete restrict;

create function control.validate_privacy_platform_state() returns trigger
language plpgsql set search_path=pg_catalog,control as $$
begin
    if new.version<>old.version+1 then raise exception 'privacy state version must increment exactly once' using errcode='40001'; end if;
    if new.production_personal_data_allowed and not (
        exists(select 1 from retention_policy_versions where version=new.approved_retention_policy_version and status='approved')
        and exists(select 1 from processing_register_versions where version=new.approved_processing_register_version and status='approved')
        and not exists(select 1 from processor_approvals where processing_register_version=new.approved_processing_register_version and status<>'approved')
    ) then raise exception 'privacy production approvals are incomplete' using errcode='23514'; end if;
    new.updated_at=now(); return new;
end $$;
create trigger privacy_platform_state_update before update on control.privacy_platform_state
for each row execute function control.validate_privacy_platform_state();

create function control.validate_data_subject_request_transition() returns trigger
language plpgsql set search_path=pg_catalog,control as $$
begin
    if new.subject_user_id<>old.subject_user_id or new.request_type<>old.request_type or new.scope<>old.scope or new.requested_at<>old.requested_at or new.due_at<>old.due_at
    then raise exception 'data-subject request identity and scope are immutable' using errcode='55000'; end if;
    if new.status<>old.status and not (
        (old.status='received' and new.status in ('identity_verification','controller_review','cancelled')) or
        (old.status='identity_verification' and new.status in ('controller_review','refused','cancelled')) or
        (old.status='controller_review' and new.status in ('approved','refused','cancelled')) or
        (old.status='approved' and new.status='executing') or
        (old.status='executing' and new.status in ('completed','refused'))
    ) then raise exception 'invalid data-subject request transition % -> %',old.status,new.status using errcode='23514'; end if;
    if new.version<>old.version+1 then raise exception 'data-subject request version must increment exactly once' using errcode='40001'; end if;
    new.updated_at=now(); return new;
end $$;
create trigger data_subject_request_transition before update on control.data_subject_requests
for each row execute function control.validate_data_subject_request_transition();

create function control.enforce_subject_processing_hold() returns trigger
language plpgsql set search_path=pg_catalog,control as $$
begin
    if coalesce(new.target_user_id,new.requested_by) is not null and new.kind not in ('privacy.retention','privacy.data_subject_request')
       and exists(select 1 from processing_holds h where h.subject_user_id=coalesce(new.target_user_id,new.requested_by) and h.active and (h.workshop_id is null or h.workshop_id is not distinct from new.workshop_id))
    then raise exception 'processing is restricted for this data subject' using errcode='42501'; end if;
    return new;
end $$;
create trigger operations_subject_processing_hold before insert on control.operations
for each row execute function control.enforce_subject_processing_hold();

revoke all on function control.validate_privacy_platform_state() from public;
revoke all on function control.validate_data_subject_request_transition() from public;
revoke all on function control.enforce_subject_processing_hold() from public;
revoke all on function control.set_privacy_incident_deadline() from public;
revoke all on function control.validate_processor_task_update() from public;
revoke all on function control.validate_privacy_incident_update() from public;
revoke all on function control.validate_legal_hold_update() from public;
revoke all on function control.legal_hold_applies(text,uuid,uuid[]) from public;

do $$
begin
    if exists(select 1 from pg_roles where rolname='control_api') then
        grant select,insert,update on control.data_subject_requests,
            control.processing_holds,control.data_subject_processor_tasks,
            control.data_subject_exports,control.erasure_tombstones,
            control.privacy_incidents,control.legal_holds to control_api;
        grant select on control.privacy_platform_state,control.retention_policy_versions,
            control.processing_register_versions,control.processor_approvals,
            control.retention_runs to control_api;
    end if;
    if exists(select 1 from pg_roles where rolname='control_privacy_worker') then
        grant usage on schema control to control_privacy_worker;
        grant select on control.users,control.external_identities,control.memberships,
            control.invitations,control.outbox,control.audit_events,control.workshops,
            control.workshop_recovery_points,control.privacy_platform_state,
            control.retention_policy_versions,control.processing_register_versions,
            control.processor_approvals,control.legal_holds to control_privacy_worker;
        grant select,insert,update on control.operations,control.data_subject_requests,
            control.processing_holds,control.data_subject_processor_tasks,
            control.data_subject_exports,control.erasure_tombstones,control.retention_runs
        to control_privacy_worker;
        grant update,delete on control.invitations,control.outbox to control_privacy_worker;
        grant update on control.users,control.external_identities to control_privacy_worker;
        grant execute on function control.legal_hold_applies(text,uuid,uuid[]) to control_privacy_worker;
    end if;
end $$;
