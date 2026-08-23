-- Make lifecycle resource ownership relationally explicit before any further
-- row-level-security rollout. Fleet-scoped release operations remain linked by
-- their existing single-column operation foreign keys because one operation
-- intentionally coordinates several workshops.

alter table control.service_instances
    add constraint service_instances_id_workshop_id_key unique (id, workshop_id);

alter table control.workshop_recovery_points
    add constraint workshop_recovery_points_id_workshop_id_key unique (id, workshop_id);

alter table control.operations
    add constraint operations_id_workshop_id_key unique (id, workshop_id);

alter table control.erasure_tombstones
    add constraint erasure_tombstones_id_workshop_id_key unique (id, workshop_id);

alter table control.workshop_recovery_components
    add column workshop_id uuid;

update control.workshop_recovery_components component
   set workshop_id = recovery.workshop_id
  from control.workshop_recovery_points recovery
 where recovery.id = component.recovery_point_id;

alter table control.workshop_recovery_components
    alter column workshop_id set not null;

alter table control.erasure_restore_replays
    add column workshop_id uuid;

update control.erasure_restore_replays replay
   set workshop_id = recovery.workshop_id
  from control.workshop_recovery_points recovery,
       control.erasure_tombstones tombstone,
       control.operations operation
 where recovery.id = replay.recovery_point_id
   and tombstone.id = replay.tombstone_id
   and operation.id = replay.operation_id
   and tombstone.workshop_id = recovery.workshop_id
   and operation.workshop_id = recovery.workshop_id;

-- Any legacy replay whose three parents disagree remains NULL and makes the
-- migration fail closed here instead of silently blessing mixed ownership.
alter table control.erasure_restore_replays
    alter column workshop_id set not null;

alter table control.odoo_databases
    drop constraint odoo_databases_service_instance_id_fkey,
    add constraint odoo_databases_service_instance_workshop_fkey
        foreign key (service_instance_id, workshop_id)
        references control.service_instances(id, workshop_id)
        on delete restrict;

alter table control.workshop_recovery_components
    drop constraint workshop_recovery_components_recovery_point_id_fkey,
    add constraint workshop_recovery_components_recovery_workshop_fkey
        foreign key (recovery_point_id, workshop_id)
        references control.workshop_recovery_points(id, workshop_id)
        on delete cascade;

alter table control.workshop_recovery_rehearsals
    drop constraint workshop_recovery_rehearsals_recovery_point_id_fkey,
    add constraint workshop_recovery_rehearsals_recovery_workshop_fkey
        foreign key (recovery_point_id, workshop_id)
        references control.workshop_recovery_points(id, workshop_id)
        on delete cascade;

alter table control.workshop_deletions
    drop constraint workshop_deletions_final_recovery_point_id_fkey,
    drop constraint workshop_deletions_operation_id_fkey,
    add constraint workshop_deletions_final_recovery_workshop_fkey
        foreign key (final_recovery_point_id, workshop_id)
        references control.workshop_recovery_points(id, workshop_id)
        on delete restrict,
    add constraint workshop_deletions_operation_workshop_fkey
        foreign key (operation_id, workshop_id)
        references control.operations(id, workshop_id)
        on delete restrict;

alter table control.erasure_restore_replays
    drop constraint erasure_restore_replays_operation_id_fkey,
    drop constraint erasure_restore_replays_recovery_point_id_fkey,
    drop constraint erasure_restore_replays_tombstone_id_fkey,
    add constraint erasure_restore_replays_operation_workshop_fkey
        foreign key (operation_id, workshop_id)
        references control.operations(id, workshop_id)
        on delete restrict,
    add constraint erasure_restore_replays_recovery_workshop_fkey
        foreign key (recovery_point_id, workshop_id)
        references control.workshop_recovery_points(id, workshop_id)
        on delete restrict,
    add constraint erasure_restore_replays_tombstone_workshop_fkey
        foreign key (tombstone_id, workshop_id)
        references control.erasure_tombstones(id, workshop_id)
        on delete restrict;

alter table control.tenant_release_adoptions
    drop constraint tenant_release_adoptions_backup_recovery_id_fkey,
    drop constraint tenant_release_adoptions_database_id_fkey,
    add constraint tenant_release_adoptions_backup_recovery_workshop_fkey
        foreign key (backup_recovery_id, workshop_id)
        references control.workshop_recovery_points(id, workshop_id)
        on delete restrict,
    add constraint tenant_release_adoptions_database_workshop_fkey
        foreign key (database_id, workshop_id)
        references control.odoo_databases(id, workshop_id)
        on delete restrict;

do $$
begin
    if exists(select 1 from pg_roles where rolname = 'control_lifecycle_worker') then
        grant select, update on table control.service_instances to control_lifecycle_worker;
        revoke all on table control.workshop_recovery_rehearsals from control_lifecycle_worker;
    end if;
end
$$;

comment on column control.workshop_recovery_components.workshop_id is
'Denormalized tenant key constrained to the owning recovery point for scoped worker execution and future RLS.';

comment on column control.erasure_restore_replays.workshop_id is
'Tenant key shared by the replay operation, source recovery point, and erasure tombstone.';
