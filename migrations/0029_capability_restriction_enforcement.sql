alter table control.operations drop constraint operations_kind_check;
alter table control.operations add constraint operations_kind_check check (kind in (
    'tenant.provision', 'membership.reconcile', 'entitlement.apply',
    'invoice.capture', 'inventory.capture.extract', 'tenant.reconcile',
    'tenant.lifecycle', 'email.delivery', 'module.enable', 'module.restrict',
    'odoo.release.adopt', 'privacy.retention', 'privacy.data_subject_request'
));

alter table control.deployment_driver_operations
    drop constraint deployment_driver_operations_action_check,
    add constraint deployment_driver_operations_action_check check (
        action in ('provision','reconcile','lifecycle','rehearse','release',
                   'erasure','resume','restrict')
    );

drop trigger workshop_module_update on control.workshop_modules;

alter table control.workshop_modules
    drop constraint workshop_modules_state_check,
    add column restriction_reason text,
    add column restriction_evidence jsonb,
    add column restricted_at timestamptz,
    add constraint workshop_modules_state_check check (
        state in ('requested','installing','enabled','failed','restricting','restricted')
    ),
    add constraint workshop_modules_restriction_reason_check check (
        restriction_reason is null or restriction_reason ~ '^[a-z][a-z0-9_]{0,63}$'
    ),
    add constraint workshop_modules_restriction_evidence_check check (
        restriction_evidence is null or jsonb_typeof(restriction_evidence)='object'
    );

-- A legacy `restricted` value did not prove enforcement. Preserve fail-closed
-- semantics and enqueue an evidence-producing adapter operation.
insert into control.operations(
    id,kind,queue,workshop_id,payload,requested_by,correlation_id,idempotency_key
)
select gen_random_uuid(),'module.restrict','tenant-reconciliation',wm.workshop_id,
       jsonb_build_object(
           'module_key',wm.module_key,'reason','legacy_unverified',
           'registry_version',wm.registry_version,
           'application_release_id',wm.application_release_id,
           'entitlement_version',wm.entitlement_version,
           'resolved_implementation',wm.resolved_implementation
       ),wm.requested_by,gen_random_uuid(),
       'migration:0029:module-restrict:'||wm.workshop_id::text||':'||wm.module_key
  from control.workshop_modules wm where wm.state='restricted';

update control.workshop_modules wm
   set state='restricting',operation_id=o.id,restriction_reason='legacy_unverified',
       version=wm.version+1
  from control.operations o
 where wm.state='restricted' and o.kind='module.restrict'
   and o.idempotency_key='migration:0029:module-restrict:'||wm.workshop_id::text||':'||wm.module_key;

alter table control.workshop_modules
    add constraint workshop_modules_restricted_evidence_check check (
        state<>'restricted' or (
            restriction_reason is not null and restriction_evidence is not null
            and restriction_evidence<>'{}'::jsonb and restricted_at is not null
        )
    );

create or replace function control.validate_workshop_module_update() returns trigger
language plpgsql set search_path=pg_catalog,control as $$
begin
    if new.workshop_id<>old.workshop_id or new.module_key<>old.module_key then
        raise exception 'capability activation identity is immutable' using errcode='55000';
    end if;
    if new.version<>old.version+1 then
        raise exception 'capability activation version must increment exactly once' using errcode='40001';
    end if;
    if not (
        (old.state='requested' and new.state in ('requested','installing','failed')) or
        (old.state='installing' and new.state in ('installing','enabled','failed')) or
        (old.state='enabled' and new.state in ('enabled','restricting')) or
        (old.state='restricting' and new.state in ('restricting','restricted','failed','requested')) or
        (old.state in ('failed','restricted') and new.state='requested')
    ) then
        raise exception 'invalid capability activation transition % -> %',old.state,new.state using errcode='23514';
    end if;
    if new.operation_id is not distinct from old.operation_id then
        if new.registry_version<>old.registry_version
           or new.application_release_id is distinct from old.application_release_id
           or new.entitlement_version is distinct from old.entitlement_version
           or new.resolved_implementation<>old.resolved_implementation then
            raise exception 'pinned capability activation contract is immutable' using errcode='55000';
        end if;
    elsif not (
        (new.state='requested' and new.operation_id is not null) or
        (old.state='enabled' and new.state='restricting' and new.operation_id is not null
         and new.registry_version=old.registry_version
         and new.application_release_id is not distinct from old.application_release_id
         and new.entitlement_version is not distinct from old.entitlement_version
         and new.resolved_implementation=old.resolved_implementation)
    ) then
        raise exception 'operation replacement is not permitted for this transition' using errcode='55000';
    end if;
    if new.state='requested' then
        new.restriction_reason=null;
        new.restriction_evidence=null;
        new.restricted_at=null;
    end if;
    return new;
end $$;

create trigger workshop_module_update before update on control.workshop_modules
for each row execute function control.validate_workshop_module_update();

do $$
begin
    if exists(select 1 from pg_roles where rolname='control_reconciliation_worker') then
        grant select on control.tenant_release_adoptions to control_reconciliation_worker;
    end if;
end $$;

comment on column control.workshop_modules.restriction_evidence is
'Privacy-safe proof returned by the downstream enforcement adapter; required before restricted.';
