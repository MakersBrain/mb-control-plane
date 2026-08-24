-- Dormant cutover guardrails for every legacy selected-generation admission.
-- This migration does not change the protocol mode or readiness flags.  It
-- only makes flat-v1 admission serialize behind the protocol singleton so a
-- later activation transaction can exclude old binaries without a Rust-side
-- check-then-act race.

alter function control.admit_workshop_route_application(
 uuid,integer,text,uuid,text,text,text,bigint,text,uuid,uuid,uuid,integer
) rename to admit_workshop_route_application_flat_v1;

create function control.admit_workshop_route_application(
 p_control_operation_id uuid,p_control_operation_attempt integer,
 p_control_operation_lease_owner text,p_workshop_id uuid,p_action text,
 p_idempotency_key text,p_request_digest text,p_generation bigint,
 p_projection_digest text,p_instance_owner uuid,p_execution_token uuid,
 p_route_lease_token uuid,p_ttl_seconds integer
) returns table(outcome text,driver_operation_id uuid,fence_token bigint,stored_response jsonb)
language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_mode text;
begin
 select mode into strict v_mode from control.route_set_publication_protocol_state
 where singleton for update;
 if v_mode<>'flat_v1' then
  return query select 'fleet_busy'::text,null::uuid,null::bigint,null::jsonb;
  return;
 end if;
 return query select * from control.admit_workshop_route_application_flat_v1(
  p_control_operation_id,p_control_operation_attempt,p_control_operation_lease_owner,
  p_workshop_id,p_action,p_idempotency_key,p_request_digest,p_generation,
  p_projection_digest,p_instance_owner,p_execution_token,p_route_lease_token,p_ttl_seconds);
end $function$;

alter function control.admit_workshop_route_maintenance(
 uuid,integer,text,uuid,text,text,text,uuid,uuid,uuid,integer
) rename to admit_workshop_route_maintenance_flat_v1;

create function control.admit_workshop_route_maintenance(
 p_control_operation_id uuid,p_control_operation_attempt integer,
 p_control_operation_lease_owner text,p_workshop_id uuid,p_reason text,
 p_idempotency_key text,p_request_digest text,p_instance_owner uuid,
 p_execution_token uuid,p_route_lease_token uuid,p_ttl_seconds integer
) returns table(outcome text,effect_run_id uuid,route_fence_token bigint,
 projection jsonb,stored_response jsonb)
language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_mode text;
begin
 select mode into strict v_mode from control.route_set_publication_protocol_state
 where singleton for update;
 if v_mode<>'flat_v1' then
  return query select 'fleet_busy'::text,null::uuid,null::bigint,null::jsonb,null::jsonb;
  return;
 end if;
 return query select * from control.admit_workshop_route_maintenance_flat_v1(
  p_control_operation_id,p_control_operation_attempt,p_control_operation_lease_owner,
  p_workshop_id,p_reason,p_idempotency_key,p_request_digest,p_instance_owner,
  p_execution_token,p_route_lease_token,p_ttl_seconds);
end $function$;

alter function control.admit_startup_route_rebuild(
 uuid,text,text,uuid,uuid,uuid,uuid,integer
) rename to admit_startup_route_rebuild_flat_v1;

create function control.admit_startup_route_rebuild(
 p_boot_id uuid,p_idempotency_key text,p_request_digest text,p_instance_owner uuid,
 p_execution_token uuid,p_global_lease_token uuid,p_route_lease_token uuid,
 p_ttl_seconds integer
) returns table(outcome text,effect_run_id uuid,global_fence_token bigint,
 reserved_count integer,stored_response jsonb)
language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_mode text;
begin
 select mode into strict v_mode from control.route_set_publication_protocol_state
 where singleton for update;
 if v_mode<>'flat_v1' then
  return query select 'busy'::text,null::uuid,null::bigint,null::integer,null::jsonb;
  return;
 end if;
 return query select * from control.admit_startup_route_rebuild_flat_v1(
  p_boot_id,p_idempotency_key,p_request_digest,p_instance_owner,p_execution_token,
  p_global_lease_token,p_route_lease_token,p_ttl_seconds);
end $function$;

-- Startup recovery can independently claim an expired staged publication and
-- then observe or restore the selected generation.  It does not pass through
-- startup admission, so it needs its own protocol-first boundary.
alter function control.claim_interrupted_startup_route_publication(
 uuid,uuid,integer
) rename to claim_interrupted_startup_route_publication_flat_v1;

create function control.claim_interrupted_startup_route_publication(
 p_reconciliation_owner uuid,p_reconciliation_token uuid,p_ttl_seconds integer
) returns table(outcome text,effect_run_id uuid,interrupted_phase text,
 original_instance_owner uuid,original_global_fence_token bigint,
 prior_selector text,prior_directory_device bigint,prior_directory_inode bigint,
 staging_selector text,prior_gateway_effect_run_id uuid,
 prior_gateway_set_digest text,sealed_count integer,sealed_present_count integer,
 projection_set_digest text)
language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_mode text;
begin
 select mode into strict v_mode from control.route_set_publication_protocol_state
 where singleton for update;
 if v_mode<>'flat_v1' then
  return query select 'none'::text,null::uuid,null::text,null::uuid,null::bigint,
   null::text,null::bigint,null::bigint,null::text,null::uuid,null::text,
   null::integer,null::integer,null::text;
  return;
 end if;
 return query select * from control.claim_interrupted_startup_route_publication_flat_v1(
  p_reconciliation_owner,p_reconciliation_token,p_ttl_seconds);
end $function$;

-- Recovery-maintenance exit is another direct claim that re-arms a workshop
-- route lease and authorizes restoration effects without re-entering the
-- maintenance admission function.
alter function control.claim_workshop_route_maintenance_exit(
 uuid,uuid,integer,text,uuid,uuid,uuid,integer
) rename to claim_workshop_route_maintenance_exit_flat_v1;

create function control.claim_workshop_route_maintenance_exit(
 p_effect_run_id uuid,p_control_operation_id uuid,
 p_control_operation_attempt integer,p_control_operation_lease_owner text,
 p_instance_owner uuid,p_execution_token uuid,p_route_lease_token uuid,
 p_ttl_seconds integer
) returns table(outcome text,route_fence_token bigint,disposition text,projection jsonb)
language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_mode text;
begin
 select mode into strict v_mode from control.route_set_publication_protocol_state
 where singleton for update;
 if v_mode<>'flat_v1' then
  return query select 'fleet_busy'::text,null::bigint,null::text,null::jsonb;
  return;
 end if;
 return query select * from control.claim_workshop_route_maintenance_exit_flat_v1(
  p_effect_run_id,p_control_operation_id,p_control_operation_attempt,
  p_control_operation_lease_owner,p_instance_owner,p_execution_token,
  p_route_lease_token,p_ttl_seconds);
end $function$;

-- Guard every rolling-compatible release overload.  The 13-argument dormant
-- snapshot overload delegates through the guarded 12-argument overload, but it
-- is wrapped independently so no public admission surface can bypass the first
-- protocol-row lock.
alter function control.admit_release_driver_operation(
 uuid,integer,text,text,text,uuid,text,uuid,uuid,uuid,integer
) rename to admit_release_driver_operation_flat_v1;
alter function control.admit_release_driver_operation(
 uuid,integer,text,text,text,uuid,text,uuid,uuid,uuid,integer,smallint
) rename to admit_release_driver_operation_flat_v1;
alter function control.admit_release_driver_operation(
 uuid,integer,text,text,text,uuid,text,uuid,uuid,uuid,integer,smallint,smallint
) rename to admit_release_driver_operation_flat_v1;

create function control.admit_release_driver_operation(
 p_control_operation_id uuid,p_control_operation_attempt integer,
 p_control_operation_lease_owner text,p_idempotency_key text,p_target_key text,
 p_fleet_run_id uuid,p_request_digest text,p_instance_owner uuid,
 p_execution_token uuid,p_resource_lease_token uuid,p_ttl_seconds integer
) returns table(outcome text,driver_operation_id uuid,fence_token bigint,
 stored_response jsonb,reserved_workshops uuid[])
language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_mode text;
begin
 select mode into strict v_mode from control.route_set_publication_protocol_state
 where singleton for update;
 if v_mode<>'flat_v1' then
  return query select 'busy'::text,null::uuid,null::bigint,null::jsonb,null::uuid[];
  return;
 end if;
 return query select * from control.admit_release_driver_operation_flat_v1(
  p_control_operation_id,p_control_operation_attempt,p_control_operation_lease_owner,
  p_idempotency_key,p_target_key,p_fleet_run_id,p_request_digest,p_instance_owner,
  p_execution_token,p_resource_lease_token,p_ttl_seconds);
end $function$;

create function control.admit_release_driver_operation(
 p_control_operation_id uuid,p_control_operation_attempt integer,
 p_control_operation_lease_owner text,p_idempotency_key text,p_target_key text,
 p_fleet_run_id uuid,p_request_digest text,p_instance_owner uuid,
 p_execution_token uuid,p_resource_lease_token uuid,p_ttl_seconds integer,
 p_release_executor_protocol_version smallint
) returns table(outcome text,driver_operation_id uuid,fence_token bigint,
 stored_response jsonb,reserved_workshops uuid[])
language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_mode text;
begin
 select mode into strict v_mode from control.route_set_publication_protocol_state
 where singleton for update;
 if v_mode<>'flat_v1' then
  return query select 'busy'::text,null::uuid,null::bigint,null::jsonb,null::uuid[];
  return;
 end if;
 return query select * from control.admit_release_driver_operation_flat_v1(
  p_control_operation_id,p_control_operation_attempt,p_control_operation_lease_owner,
  p_idempotency_key,p_target_key,p_fleet_run_id,p_request_digest,p_instance_owner,
  p_execution_token,p_resource_lease_token,p_ttl_seconds,
  p_release_executor_protocol_version);
end $function$;

create function control.admit_release_driver_operation(
 p_control_operation_id uuid,p_control_operation_attempt integer,
 p_control_operation_lease_owner text,p_idempotency_key text,p_target_key text,
 p_fleet_run_id uuid,p_request_digest text,p_instance_owner uuid,
 p_execution_token uuid,p_resource_lease_token uuid,p_ttl_seconds integer,
 p_release_executor_protocol_version smallint,
 p_release_route_snapshot_protocol_version smallint
) returns table(outcome text,driver_operation_id uuid,fence_token bigint,
 stored_response jsonb,reserved_workshops uuid[])
language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_mode text;
begin
 select mode into strict v_mode from control.route_set_publication_protocol_state
 where singleton for update;
 if v_mode<>'flat_v1' then
  return query select 'busy'::text,null::uuid,null::bigint,null::jsonb,null::uuid[];
  return;
 end if;
 return query select * from control.admit_release_driver_operation_flat_v1(
  p_control_operation_id,p_control_operation_attempt,p_control_operation_lease_owner,
  p_idempotency_key,p_target_key,p_fleet_run_id,p_request_digest,p_instance_owner,
  p_execution_token,p_resource_lease_token,p_ttl_seconds,
  p_release_executor_protocol_version,p_release_route_snapshot_protocol_version);
end $function$;

-- Reconciliation admissions can resume a quarantined legacy release and then
-- authorize host observation/effects without passing through release admission.
-- They therefore need the same protocol-first exclusion as initial admission.
alter function control.admit_initial_release_reconciliation(
 uuid,integer,text,text,text,text,uuid,uuid,integer
) rename to admit_initial_release_reconciliation_flat_v1;

create function control.admit_initial_release_reconciliation(
 p_control_operation_id uuid,p_control_operation_attempt integer,
 p_control_operation_lease_owner text,p_idempotency_key text,p_target_key text,
 p_request_digest text,p_instance_owner uuid,p_execution_token uuid,p_ttl_seconds integer
) returns table(outcome text,reconciliation_id uuid,driver_operation_id uuid,
 original_fence_token bigint,stored_evidence jsonb)
language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_mode text;
begin
 select mode into strict v_mode from control.route_set_publication_protocol_state
 where singleton for update;
 if v_mode<>'flat_v1' then
  return query select 'busy'::text,null::uuid,null::uuid,null::bigint,null::jsonb;
  return;
 end if;
 return query select * from control.admit_initial_release_reconciliation_flat_v1(
  p_control_operation_id,p_control_operation_attempt,p_control_operation_lease_owner,
  p_idempotency_key,p_target_key,p_request_digest,p_instance_owner,p_execution_token,
  p_ttl_seconds);
end $function$;

alter function control.admit_fleet_release_reconciliation(
 uuid,integer,text,text,text,uuid,text,uuid,uuid,integer
) rename to admit_fleet_release_reconciliation_flat_v1;

create function control.admit_fleet_release_reconciliation(
 p_control_operation_id uuid,p_control_operation_attempt integer,
 p_control_operation_lease_owner text,p_idempotency_key text,p_target_key text,
 p_fleet_run_id uuid,p_request_digest text,p_instance_owner uuid,
 p_execution_token uuid,p_ttl_seconds integer
) returns table(outcome text,reconciliation_id uuid,driver_operation_id uuid,
 original_fence_token bigint,activation_identity jsonb,stored_response jsonb)
language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_mode text;
begin
 select mode into strict v_mode from control.route_set_publication_protocol_state
 where singleton for update;
 if v_mode<>'flat_v1' then
  return query select 'busy'::text,null::uuid,null::uuid,null::bigint,null::jsonb,null::jsonb;
  return;
 end if;
 return query select * from control.admit_fleet_release_reconciliation_flat_v1(
  p_control_operation_id,p_control_operation_attempt,p_control_operation_lease_owner,
  p_idempotency_key,p_target_key,p_fleet_run_id,p_request_digest,p_instance_owner,
  p_execution_token,p_ttl_seconds);
end $function$;

-- The immutable release-overlay admission is dormant but executable by the
-- driver ledger. Guard it directly so future code cannot use the old release
-- authority as a post-activation selector-publication bypass.
alter function control.admit_immutable_release_route_publication(
 uuid,uuid,uuid,uuid,uuid,bigint,integer
) rename to admit_immutable_release_route_publication_flat_v1;

create function control.admit_immutable_release_route_publication(
 p_driver_operation_id uuid,p_instance_owner uuid,p_execution_token uuid,
 p_global_lease_token uuid,p_route_lease_token uuid,p_global_fence_token bigint,
 p_ttl_seconds integer
) returns table(outcome text,target_slot text,maintenance_selector text,
 candidate_selector text,reserved_workshops uuid[])
language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_mode text;
begin
 select mode into strict v_mode from control.route_set_publication_protocol_state
 where singleton for update;
 if v_mode<>'flat_v1' then
  return query select 'protocol_conflict'::text,null::text,null::text,null::text,null::uuid[];
  return;
 end if;
 return query select * from control.admit_immutable_release_route_publication_flat_v1(
  p_driver_operation_id,p_instance_owner,p_execution_token,p_global_lease_token,
  p_route_lease_token,p_global_fence_token,p_ttl_seconds);
end $function$;

revoke all on function control.admit_workshop_route_application_flat_v1(
 uuid,integer,text,uuid,text,text,text,bigint,text,uuid,uuid,uuid,integer) from public;
revoke all on function control.admit_workshop_route_maintenance_flat_v1(
 uuid,integer,text,uuid,text,text,text,uuid,uuid,uuid,integer) from public;
revoke all on function control.admit_startup_route_rebuild_flat_v1(
 uuid,text,text,uuid,uuid,uuid,uuid,integer) from public;
revoke all on function control.claim_interrupted_startup_route_publication_flat_v1(
 uuid,uuid,integer) from public;
revoke all on function control.claim_workshop_route_maintenance_exit_flat_v1(
 uuid,uuid,integer,text,uuid,uuid,uuid,integer) from public;
revoke all on function control.admit_release_driver_operation_flat_v1(
 uuid,integer,text,text,text,uuid,text,uuid,uuid,uuid,integer) from public;
revoke all on function control.admit_release_driver_operation_flat_v1(
 uuid,integer,text,text,text,uuid,text,uuid,uuid,uuid,integer,smallint) from public;
revoke all on function control.admit_release_driver_operation_flat_v1(
 uuid,integer,text,text,text,uuid,text,uuid,uuid,uuid,integer,smallint,smallint) from public;
revoke all on function control.admit_initial_release_reconciliation_flat_v1(
 uuid,integer,text,text,text,text,uuid,uuid,integer) from public;
revoke all on function control.admit_fleet_release_reconciliation_flat_v1(
 uuid,integer,text,text,text,uuid,text,uuid,uuid,integer) from public;
revoke all on function control.admit_immutable_release_route_publication_flat_v1(
 uuid,uuid,uuid,uuid,uuid,bigint,integer) from public;

revoke all on function control.admit_workshop_route_application(
 uuid,integer,text,uuid,text,text,text,bigint,text,uuid,uuid,uuid,integer) from public;
revoke all on function control.admit_workshop_route_maintenance(
 uuid,integer,text,uuid,text,text,text,uuid,uuid,uuid,integer) from public;
revoke all on function control.admit_startup_route_rebuild(
 uuid,text,text,uuid,uuid,uuid,uuid,integer) from public;
revoke all on function control.claim_interrupted_startup_route_publication(
 uuid,uuid,integer) from public;
revoke all on function control.claim_workshop_route_maintenance_exit(
 uuid,uuid,integer,text,uuid,uuid,uuid,integer) from public;
revoke all on function control.admit_release_driver_operation(
 uuid,integer,text,text,text,uuid,text,uuid,uuid,uuid,integer) from public;
revoke all on function control.admit_release_driver_operation(
 uuid,integer,text,text,text,uuid,text,uuid,uuid,uuid,integer,smallint) from public;
revoke all on function control.admit_release_driver_operation(
 uuid,integer,text,text,text,uuid,text,uuid,uuid,uuid,integer,smallint,smallint) from public;
revoke all on function control.admit_initial_release_reconciliation(
 uuid,integer,text,text,text,text,uuid,uuid,integer) from public;
revoke all on function control.admit_fleet_release_reconciliation(
 uuid,integer,text,text,text,uuid,text,uuid,uuid,integer) from public;
revoke all on function control.admit_immutable_release_route_publication(
 uuid,uuid,uuid,uuid,uuid,bigint,integer) from public;

do $migration$
declare v_role text;
begin
 for v_role in select unnest(array[
  'control_api','control_tenant_api','control_driver_ledger','control_backup_scheduler',
  'control_email_worker','control_inventory_worker','control_invoice_worker',
  'control_lifecycle_worker','control_membership_worker','control_privacy_worker',
  'control_provisioning_worker','control_reconciliation_worker','control_release_worker',
  -- Retain revocation for historical/development roles too: renamed functions
  -- preserve any explicit ACL attached to the old public identity.
  'control_worker','control_worker_tenant','control_driver_tenant','control_mail_gateway',
  'control_extraction_broker','control_migration'
 ]) loop
  if exists(select 1 from pg_roles where rolname=v_role) then
   execute format('revoke all on function control.admit_workshop_route_application_flat_v1(uuid,integer,text,uuid,text,text,text,bigint,text,uuid,uuid,uuid,integer) from %I',v_role);
   execute format('revoke all on function control.admit_workshop_route_maintenance_flat_v1(uuid,integer,text,uuid,text,text,text,uuid,uuid,uuid,integer) from %I',v_role);
   execute format('revoke all on function control.admit_startup_route_rebuild_flat_v1(uuid,text,text,uuid,uuid,uuid,uuid,integer) from %I',v_role);
   execute format('revoke all on function control.claim_interrupted_startup_route_publication_flat_v1(uuid,uuid,integer) from %I',v_role);
   execute format('revoke all on function control.claim_workshop_route_maintenance_exit_flat_v1(uuid,uuid,integer,text,uuid,uuid,uuid,integer) from %I',v_role);
   execute format('revoke all on function control.admit_release_driver_operation_flat_v1(uuid,integer,text,text,text,uuid,text,uuid,uuid,uuid,integer) from %I',v_role);
   execute format('revoke all on function control.admit_release_driver_operation_flat_v1(uuid,integer,text,text,text,uuid,text,uuid,uuid,uuid,integer,smallint) from %I',v_role);
   execute format('revoke all on function control.admit_release_driver_operation_flat_v1(uuid,integer,text,text,text,uuid,text,uuid,uuid,uuid,integer,smallint,smallint) from %I',v_role);
   execute format('revoke all on function control.admit_initial_release_reconciliation_flat_v1(uuid,integer,text,text,text,text,uuid,uuid,integer) from %I',v_role);
   execute format('revoke all on function control.admit_fleet_release_reconciliation_flat_v1(uuid,integer,text,text,text,uuid,text,uuid,uuid,integer) from %I',v_role);
   execute format('revoke all on function control.admit_immutable_release_route_publication_flat_v1(uuid,uuid,uuid,uuid,uuid,bigint,integer) from %I',v_role);
  end if;
 end loop;
 if exists(select 1 from pg_roles where rolname='control_driver_ledger') then
  grant execute on function control.admit_workshop_route_application(
   uuid,integer,text,uuid,text,text,text,bigint,text,uuid,uuid,uuid,integer),
   control.admit_workshop_route_maintenance(
   uuid,integer,text,uuid,text,text,text,uuid,uuid,uuid,integer),
   control.admit_startup_route_rebuild(uuid,text,text,uuid,uuid,uuid,uuid,integer),
   control.claim_interrupted_startup_route_publication(uuid,uuid,integer),
   control.claim_workshop_route_maintenance_exit(
   uuid,uuid,integer,text,uuid,uuid,uuid,integer),
   control.admit_release_driver_operation(
   uuid,integer,text,text,text,uuid,text,uuid,uuid,uuid,integer),
   control.admit_release_driver_operation(
   uuid,integer,text,text,text,uuid,text,uuid,uuid,uuid,integer,smallint),
   control.admit_release_driver_operation(
   uuid,integer,text,text,text,uuid,text,uuid,uuid,uuid,integer,smallint,smallint),
   control.admit_initial_release_reconciliation(
   uuid,integer,text,text,text,text,uuid,uuid,integer),
   control.admit_fleet_release_reconciliation(
   uuid,integer,text,text,text,uuid,text,uuid,uuid,integer),
   control.admit_immutable_release_route_publication(
   uuid,uuid,uuid,uuid,uuid,bigint,integer)
  to control_driver_ledger;
 end if;
end $migration$;

comment on function control.admit_workshop_route_application(
 uuid,integer,text,uuid,text,text,text,bigint,text,uuid,uuid,uuid,integer) is
'Flat-v1 compatibility admission serialized behind the dormant route-set protocol singleton; refuses without mutation outside flat_v1.';
comment on function control.admit_workshop_route_maintenance(
 uuid,integer,text,uuid,text,text,text,uuid,uuid,uuid,integer) is
'Flat-v1 recovery-maintenance admission serialized behind the dormant route-set protocol singleton; refuses without mutation outside flat_v1.';
comment on function control.admit_startup_route_rebuild(
 uuid,text,text,uuid,uuid,uuid,uuid,integer) is
'Flat-v1 startup admission serialized behind the dormant route-set protocol singleton; refuses without mutation outside flat_v1.';
comment on function control.admit_release_driver_operation(
 uuid,integer,text,text,text,uuid,text,uuid,uuid,uuid,integer,smallint) is
'Active flat-v1 release admission serialized behind the dormant route-set protocol singleton; refuses without mutation outside flat_v1.';
