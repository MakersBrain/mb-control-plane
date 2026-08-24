-- Dormant, claim-authenticated expected inputs for independently observing an
-- interrupted protocol-v2 release runtime. This migration does not inspect or
-- mutate the runtime, publish routes, or enable a recovery scheduler.

create function control.read_interrupted_immutable_release_runtime_expectation(
 p_driver_operation_id uuid,p_control_operation_attempt integer,
 p_control_operation_lease_owner text,p_reconciliation_owner uuid,
 p_reconciliation_token uuid,p_claim_fence bigint
) returns table(outcome text,expectation jsonb)
language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_publication control.fleet_release_route_publications%rowtype;
 v_claim control.fleet_release_route_publication_recovery_claims%rowtype;
 v_driver control.deployment_driver_operations%rowtype;
 v_global control.deployment_driver_resource_leases%rowtype;
 v_run control.release_fleet_runs%rowtype;
 v_release control.application_releases%rowtype;
 v_intent control.fleet_activation_intents%rowtype;
 v_prepared jsonb; v_intent_count integer;
begin
 if p_driver_operation_id is null or p_control_operation_attempt is null
  or p_control_operation_attempt<=0 or p_control_operation_lease_owner is null
  or btrim(p_control_operation_lease_owner)='' or p_reconciliation_owner is null
  or p_reconciliation_token is null or p_claim_fence is null or p_claim_fence<=0 then
  return query select 'invalid'::text,null::jsonb; return;
 end if;
 if not control.lock_immutable_release_route_recovery_claim(
  p_driver_operation_id,p_control_operation_attempt,p_control_operation_lease_owner,
  p_reconciliation_owner,p_reconciliation_token,p_claim_fence) then
  return query select 'claim_lost'::text,null::jsonb; return;
 end if;
 select * into v_publication from control.fleet_release_route_publications
  where driver_operation_id=p_driver_operation_id;
 select * into v_claim from control.fleet_release_route_publication_recovery_claims
  where driver_operation_id=p_driver_operation_id and claim_fence=p_claim_fence
   and fleet_run_id=v_publication.fleet_run_id;
 if v_publication.driver_operation_id is null or v_claim.driver_operation_id is null
  or v_claim.claim_mode<>'forward_only' or v_publication.phase<>'quarantined'
  or v_publication.interrupted_phase not in ('candidate_staging','candidate_sealed',
    'candidate_publication_started','awaiting_worker_finalize')
  or v_publication.external_effects_started_at is null then
  return query select 'wrong_phase'::text,null::jsonb; return;
 end if;
 select * into v_driver from control.deployment_driver_operations
  where id=p_driver_operation_id;
 select * into v_global from control.deployment_driver_resource_leases
  where resource_key='runtime/shared-odoo';
 select * into v_run from control.release_fleet_runs
  where id=v_publication.fleet_run_id;
 select * into v_release from control.application_releases
  where id=v_run.release_id;
 select count(*)::integer into v_intent_count from control.fleet_activation_intents intent
  where intent.fleet_run_id=v_run.id and intent.release_id=v_run.release_id
   and intent.runtime_key='shared-odoo' and intent.target_slot=v_publication.target_slot
   and intent.driver_fence_token=v_publication.original_global_fence_token
   and intent.gateway_identity_version=1 and intent.abandoned_at is null;
 if v_intent_count=1 then
  select * into v_intent from control.fleet_activation_intents intent
   where intent.fleet_run_id=v_run.id and intent.release_id=v_run.release_id
    and intent.runtime_key='shared-odoo' and intent.target_slot=v_publication.target_slot
    and intent.driver_fence_token=v_publication.original_global_fence_token
    and intent.gateway_identity_version=1 and intent.abandoned_at is null;
 end if;
 select coalesce(jsonb_agg(jsonb_build_object(
   'adoption_id',adoption.id,'workshop_id',adoption.workshop_id,
   'database_id',adoption.database_id,'database_ref',database.database_ref,
   'public_hostname',database.public_hostname)
   order by adoption.created_at,adoption.id),'[]'::jsonb) into v_prepared
 from control.tenant_release_adoptions adoption
 join control.odoo_databases database on database.id=adoption.database_id
  and database.workshop_id=adoption.workshop_id
 where adoption.operation_id=v_publication.control_operation_id
  and adoption.release_id=v_run.release_id and adoption.state='prepared';
 if exists(select 1 from control.fleet_release_route_publication_recovery_terminals
    where driver_operation_id=p_driver_operation_id)
  or exists(select 1 from control.fleet_release_route_publication_recovery_resolutions
    where driver_operation_id=p_driver_operation_id and claim_fence=p_claim_fence) then
  return query select 'wrong_phase'::text,null::jsonb; return;
 end if;
 if v_driver.id is null or v_driver.control_operation_id<>v_publication.control_operation_id
  or v_driver.state<>'in_progress' or v_driver.safe_error is distinct from 'runtime_outcome_unknown'
  or v_driver.release_executor_protocol_version is distinct from 1
  or v_global.resource_key is null or v_global.state<>'quarantined'
  or v_global.authority_kind is distinct from 'release'
  or v_global.driver_operation_id is distinct from p_driver_operation_id
  or v_global.lease_owner is distinct from v_publication.original_instance_owner
  or v_global.fence_token is distinct from v_publication.original_global_fence_token
  or v_run.id is null or v_run.operation_id<>v_publication.control_operation_id
  or v_run.state not in ('preparing','activating')
  or v_run.target_slot is distinct from v_publication.target_slot
  or v_run.driver_fence_token is distinct from v_publication.original_global_fence_token
  or jsonb_typeof(v_run.tenant_snapshot) is distinct from 'array'
  or jsonb_array_length(v_run.tenant_snapshot) not between 1 and 500
  or v_release.id is null
  or jsonb_typeof(v_release.manifest) is distinct from 'object'
  or v_intent_count<>1 or v_intent.odoo_subject_digest<>v_release.odoo_subject_digest
  or v_intent.extension_subject_digest<>v_release.extension_subject_digest
  or v_intent.observed_configuration_digest is distinct from v_intent.gateway_configuration_digest
  or v_intent.activated_at is null or v_intent.prepared_tenants is distinct from v_prepared
  or jsonb_array_length(v_prepared)<>jsonb_array_length(v_run.tenant_snapshot) then
  return query select 'state_drift'::text,null::jsonb; return;
 end if;
 return query select 'claimed'::text,jsonb_build_object(
  'protocol_version',1,'driver_operation_id',p_driver_operation_id,
  'fleet_run_id',v_run.id,'release_id',v_run.release_id,
  'control_operation_id',v_publication.control_operation_id,
  'original_instance_owner',v_publication.original_instance_owner,
  'original_global_fence_token',v_publication.original_global_fence_token,
  'target_slot',v_publication.target_slot,'release_manifest',v_release.manifest,
  'release_manifest_digest',v_release.manifest_digest,
  'release_executor_protocol_version',v_driver.release_executor_protocol_version,
  'odoo_subject_digest',v_intent.odoo_subject_digest,
  'extension_subject_digest',v_intent.extension_subject_digest,
  'pair_qualification_digest',v_intent.pair_qualification_digest,
  'prepared_tenants',v_prepared,'fleet_generation',v_run.fleet_generation,
  'tenant_snapshot',v_run.tenant_snapshot,
  'gateway_configuration_digest',v_intent.gateway_configuration_digest,
  'driver_action_id',v_intent.driver_action_id);
end $function$;

-- Preserve the audited 0037 implementation behind a private compatibility
-- name and put a narrow policy gate in front of its original signature.
alter function control.resolve_interrupted_immutable_release_route_publication(
 uuid,integer,text,uuid,uuid,bigint,text,jsonb,jsonb)
 rename to resolve_interrupted_immutable_release_route_publication_unsafe_v1;

create function control.resolve_interrupted_immutable_release_route_publication(
 p_driver_operation_id uuid,p_control_operation_attempt integer,p_control_operation_lease_owner text,
 p_reconciliation_owner uuid,p_reconciliation_token uuid,p_claim_fence bigint,
 p_resolution_kind text,p_observation_evidence jsonb,p_candidate_response jsonb
) returns text language plpgsql security definer set search_path=pg_catalog,control as $function$
begin
 if not control.lock_immutable_release_route_recovery_claim(
  p_driver_operation_id,p_control_operation_attempt,p_control_operation_lease_owner,
  p_reconciliation_owner,p_reconciliation_token,p_claim_fence) then return 'claim_lost'; end if;
 if p_resolution_kind='unstarted'
  or (p_resolution_kind='prior' and
    jsonb_typeof(p_observation_evidence->'observed_loaded_identity') is distinct from 'object') then
  return 'unsupported_resolution';
 end if;
 return control.resolve_interrupted_immutable_release_route_publication_unsafe_v1(
  p_driver_operation_id,p_control_operation_attempt,p_control_operation_lease_owner,
  p_reconciliation_owner,p_reconciliation_token,p_claim_fence,p_resolution_kind,
  p_observation_evidence,p_candidate_response);
end $function$;

-- NOT VALID permits an upgrade over historical 0037 evidence, while still
-- checking every new row, including writes that bypass the public wrapper.
alter table control.fleet_release_route_publication_recovery_resolutions
 add constraint fleet_release_route_recovery_resolutions_safe_kind_check check(
  resolution_kind<>'unstarted' and
  (resolution_kind<>'prior' or
   coalesce(jsonb_typeof(observation_evidence->'observed_loaded_identity')='object',false))) not valid;

alter function control.finish_interrupted_immutable_release_route_publication(
 uuid,integer,text,uuid,uuid,bigint,text,text)
 rename to finish_interrupted_immutable_release_route_publication_unsafe_v1;

create function control.finish_interrupted_immutable_release_route_publication(
 p_driver_operation_id uuid,p_control_operation_attempt integer,p_control_operation_lease_owner text,
 p_reconciliation_owner uuid,p_reconciliation_token uuid,p_claim_fence bigint,
 p_resolution_kind text,p_decision_digest text
) returns table(outcome text,stored_response jsonb)
language plpgsql security definer set search_path=pg_catalog,control as $function$
begin
 if control.lock_immutable_release_route_recovery_claim(
  p_driver_operation_id,p_control_operation_attempt,p_control_operation_lease_owner,
  p_reconciliation_owner,p_reconciliation_token,p_claim_fence)
  and exists(select 1 from control.fleet_release_route_publication_recovery_resolutions resolution
   where resolution.driver_operation_id=p_driver_operation_id
    and resolution.claim_fence=p_claim_fence
    and (resolution.resolution_kind='unstarted' or
      (resolution.resolution_kind='prior' and
       jsonb_typeof(resolution.observation_evidence->'observed_loaded_identity')
        is distinct from 'object'))) then
  return query select 'unsupported_resolution'::text,null::jsonb; return;
 end if;
 return query select * from control.finish_interrupted_immutable_release_route_publication_unsafe_v1(
  p_driver_operation_id,p_control_operation_attempt,p_control_operation_lease_owner,
  p_reconciliation_owner,p_reconciliation_token,p_claim_fence,p_resolution_kind,p_decision_digest);
end $function$;

revoke all on function control.read_interrupted_immutable_release_runtime_expectation(
 uuid,integer,text,uuid,uuid,bigint) from public;
revoke all on function control.resolve_interrupted_immutable_release_route_publication_unsafe_v1(
 uuid,integer,text,uuid,uuid,bigint,text,jsonb,jsonb) from public;
revoke all on function control.finish_interrupted_immutable_release_route_publication_unsafe_v1(
 uuid,integer,text,uuid,uuid,bigint,text,text) from public;
revoke all on function control.resolve_interrupted_immutable_release_route_publication(
 uuid,integer,text,uuid,uuid,bigint,text,jsonb,jsonb) from public;
revoke all on function control.finish_interrupted_immutable_release_route_publication(
 uuid,integer,text,uuid,uuid,bigint,text,text) from public;

do $migration$ declare v_role text; begin
 foreach v_role in array array['control_api','control_tenant_api','control_membership_worker',
  'control_provisioning_worker','control_invoice_worker','control_inventory_worker',
  'control_email_worker','control_reconciliation_worker','control_lifecycle_worker',
  'control_backup_scheduler','control_driver_ledger','control_release_worker','control_privacy_worker'] loop
  if exists(select 1 from pg_roles where rolname=v_role) then
   execute format('revoke all on function control.read_interrupted_immutable_release_runtime_expectation(uuid,integer,text,uuid,uuid,bigint) from %I',v_role);
   execute format('revoke all on function control.resolve_interrupted_immutable_release_route_publication_unsafe_v1(uuid,integer,text,uuid,uuid,bigint,text,jsonb,jsonb) from %I',v_role);
   execute format('revoke all on function control.finish_interrupted_immutable_release_route_publication_unsafe_v1(uuid,integer,text,uuid,uuid,bigint,text,text) from %I',v_role);
   execute format('revoke all on function control.resolve_interrupted_immutable_release_route_publication(uuid,integer,text,uuid,uuid,bigint,text,jsonb,jsonb) from %I',v_role);
   execute format('revoke all on function control.finish_interrupted_immutable_release_route_publication(uuid,integer,text,uuid,uuid,bigint,text,text) from %I',v_role);
  end if;
 end loop;
 if exists(select 1 from pg_roles where rolname='control_driver_ledger') then
  grant execute on function control.read_interrupted_immutable_release_runtime_expectation(
   uuid,integer,text,uuid,uuid,bigint) to control_driver_ledger;
  grant execute on function control.resolve_interrupted_immutable_release_route_publication(
   uuid,integer,text,uuid,uuid,bigint,text,jsonb,jsonb) to control_driver_ledger;
  grant execute on function control.finish_interrupted_immutable_release_route_publication(
   uuid,integer,text,uuid,uuid,bigint,text,text) to control_driver_ledger;
 end if;
end $migration$;

comment on function control.read_interrupted_immutable_release_runtime_expectation(
 uuid,integer,text,uuid,uuid,bigint) is
'Dormant claim-authenticated source of database-known expected inputs for independent interrupted release runtime observation.';
