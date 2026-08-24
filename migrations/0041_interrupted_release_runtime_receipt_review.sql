-- Dormant runtime observation receipts and independently privileged review for
-- protocol-v2 release-route recovery. No scheduler or external effect is
-- enabled here. PostgreSQL, not the observer, builds completion responses.

create table control.fleet_release_route_publication_recovery_runtime_observations (
 driver_operation_id uuid not null,
 fleet_run_id uuid not null,
 claim_fence bigint not null,
 control_operation_attempt integer not null,
 control_operation_lease_owner text not null,
 reconciliation_owner uuid not null,
 reconciliation_token_digest text not null,
 runtime_observation jsonb not null,
 completion_response jsonb not null,
 observation_digest text not null,
 recorded_at timestamptz not null default now(),
 primary key(driver_operation_id,claim_fence),
 unique(driver_operation_id,claim_fence,observation_digest),
 constraint fleet_release_route_recovery_runtime_observations_publication_fkey
  foreign key(driver_operation_id,fleet_run_id)
  references control.fleet_release_route_publications(driver_operation_id,fleet_run_id)
  on delete restrict,
 constraint fleet_release_route_recovery_runtime_observations_claim_fkey
  foreign key(driver_operation_id,fleet_run_id,claim_fence)
  references control.fleet_release_route_publication_recovery_claims(
   driver_operation_id,fleet_run_id,claim_fence) on delete restrict,
 constraint fleet_release_route_recovery_runtime_observations_shape_check check(
  claim_fence>0 and control_operation_attempt>0
  and btrim(control_operation_lease_owner)<>''
  and reconciliation_token_digest ~ '^sha256:[0-9a-f]{64}$'
  and jsonb_typeof(runtime_observation)='object'
  and pg_column_size(runtime_observation)<=16384
  and jsonb_typeof(completion_response)='object'
  and pg_column_size(completion_response)<=1048576
  and observation_digest ~ '^sha256:[0-9a-f]{64}$')
);

create table control.fleet_release_route_publication_recovery_reviews (
 driver_operation_id uuid not null,
 fleet_run_id uuid not null,
 claim_fence bigint not null,
 observation_digest text not null,
 resolution_digest text not null,
 review_control_operation_id uuid not null,
 review_attempt integer not null,
 review_lease_owner text not null,
 decision text not null,
 review_digest text not null,
 reviewed_at timestamptz not null default now(),
 primary key(driver_operation_id,claim_fence),
 unique(driver_operation_id,claim_fence,review_digest),
 constraint fleet_release_route_recovery_reviews_observation_fkey
  foreign key(driver_operation_id,claim_fence,observation_digest)
  references control.fleet_release_route_publication_recovery_runtime_observations(
   driver_operation_id,claim_fence,observation_digest) on delete restrict,
 constraint fleet_release_route_recovery_reviews_resolution_fkey
  foreign key(driver_operation_id,claim_fence)
  references control.fleet_release_route_publication_recovery_resolutions(
   driver_operation_id,claim_fence) on delete restrict,
 constraint fleet_release_route_recovery_reviews_shape_check check(
  claim_fence>0 and review_attempt>0 and btrim(review_lease_owner)<>''
  and observation_digest ~ '^sha256:[0-9a-f]{64}$'
  and resolution_digest ~ '^sha256:[0-9a-f]{64}$'
  and decision in ('accept_candidate','keep_quarantined')
  and review_digest ~ '^sha256:[0-9a-f]{64}$')
);

create trigger fleet_release_route_recovery_runtime_observations_immutable
before update or delete on control.fleet_release_route_publication_recovery_runtime_observations
for each row execute function control.reject_release_route_recovery_evidence_mutation();

create trigger fleet_release_route_recovery_reviews_immutable
before update or delete on control.fleet_release_route_publication_recovery_reviews
for each row execute function control.reject_release_route_recovery_evidence_mutation();

create function control.release_route_recovery_runtime_observation_digest(
 p_driver_operation_id uuid,p_fleet_run_id uuid,p_claim_fence bigint,
 p_runtime_observation jsonb,p_completion_response jsonb
) returns text language sql immutable set search_path=pg_catalog,public as $function$
 select 'sha256:'||encode(public.digest(convert_to(
  'mb-release-route-runtime-observation-v1:'||p_driver_operation_id::text||':'||
  p_fleet_run_id::text||':'||p_claim_fence::text||':'||
  coalesce(p_runtime_observation::text,'null')||':'||
  coalesce(p_completion_response::text,'null'),'UTF8'),'sha256'),'hex')
$function$;

create function control.release_route_recovery_review_digest(
 p_driver_operation_id uuid,p_fleet_run_id uuid,p_claim_fence bigint,
 p_observation_digest text,p_resolution_digest text,p_review_control_operation_id uuid,
 p_review_attempt integer,p_review_lease_owner text,p_decision text
) returns text language sql immutable set search_path=pg_catalog,public as $function$
 select 'sha256:'||encode(public.digest(convert_to(
  'mb-release-route-recovery-review-v1:'||p_driver_operation_id::text||':'||
  p_fleet_run_id::text||':'||p_claim_fence::text||':'||p_observation_digest||':'||
  p_resolution_digest||':'||p_review_control_operation_id::text||':'||
  p_review_attempt::text||':'||p_review_lease_owner||':'||p_decision,
  'UTF8'),'sha256'),'hex')
$function$;

create function control.lock_immutable_release_route_recovery_review(
 p_driver_operation_id uuid,p_claim_fence bigint,p_control_operation_id uuid,
 p_review_attempt integer,p_review_lease_owner text
) returns boolean language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_control_operation_id uuid; v_fleet_run_id uuid; v_release_id text;
begin
 select control_operation_id,fleet_run_id into v_control_operation_id,v_fleet_run_id
  from control.fleet_release_route_publications where driver_operation_id=p_driver_operation_id;
 if not found or v_control_operation_id<>p_control_operation_id then return false; end if;
 perform 1 from control.operations where id=p_control_operation_id for update;
 perform 1 from control.route_set_publication_protocol_state where singleton for update;
 perform 1 from control.deployment_driver_resource_leases
  where resource_key='runtime/shared-odoo' for update;
 perform 1 from control.fleet_release_route_publication_owners owner
  join control.workshop_route_application_leases lease using(workshop_id)
  where owner.driver_operation_id=p_driver_operation_id
  order by owner.workshop_id for update of lease;
 perform 1 from control.deployment_driver_operations where id=p_driver_operation_id for update;
 select release_id into v_release_id from control.release_fleet_runs where id=v_fleet_run_id;
 perform 1 from control.application_releases where id=v_release_id for update;
 perform 1 from control.release_fleet_runs where id=v_fleet_run_id for update;
 perform 1 from control.fleet_activation_intents where fleet_run_id=v_fleet_run_id for update;
 perform 1 from control.tenant_release_adoptions adoption
  where adoption.operation_id=p_control_operation_id and adoption.release_id=v_release_id
  order by adoption.created_at,adoption.id for update;
 perform 1 from control.fleet_release_route_publications
  where driver_operation_id=p_driver_operation_id for update;
 perform 1 from control.fleet_release_route_publication_recovery_claims
  where driver_operation_id=p_driver_operation_id and claim_fence=p_claim_fence for update;
 perform 1 from control.fleet_release_route_publication_recovery_runtime_observations
  where driver_operation_id=p_driver_operation_id and claim_fence=p_claim_fence for update;
 perform 1 from control.fleet_release_route_publication_recovery_resolutions
  where driver_operation_id=p_driver_operation_id and claim_fence=p_claim_fence for update;
 perform 1 from control.fleet_release_route_publication_recovery_reviews
  where driver_operation_id=p_driver_operation_id and claim_fence=p_claim_fence for update;
 return exists(select 1 from control.operations operation
   where operation.id=p_control_operation_id and operation.kind='odoo.release.adopt'
    and operation.queue='release-adoption' and operation.workshop_id is null
    and operation.payload->>'phase'='adopt' and operation.state='in_flight'
    and operation.attempt=p_review_attempt and operation.leased_by=p_review_lease_owner
    and operation.lease_expires_at>now())
  and exists(select 1 from control.fleet_release_route_publication_recovery_claims claim
   where claim.driver_operation_id=p_driver_operation_id and claim.claim_fence=p_claim_fence
    and claim.control_operation_attempt=p_review_attempt
    and claim.control_operation_lease_owner=p_review_lease_owner
    and claim.claim_expires_at>now());
end $function$;

create function control.record_interrupted_immutable_release_runtime_observation(
 p_driver_operation_id uuid,p_control_operation_attempt integer,
 p_control_operation_lease_owner text,p_reconciliation_owner uuid,
 p_reconciliation_token uuid,p_claim_fence bigint,p_runtime_observation jsonb
) returns table(outcome text,observation_digest text,completion_response jsonb)
language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_expectation_outcome text; v_expectation jsonb;
 v_existing control.fleet_release_route_publication_recovery_runtime_observations%rowtype;
 v_response jsonb; v_digest text; v_verified_count integer;
begin
 if jsonb_typeof(p_runtime_observation) is distinct from 'object'
  or pg_column_size(p_runtime_observation)>16384
  or (select count(*) from jsonb_object_keys(p_runtime_observation))<>20
  or not (p_runtime_observation ?& array[
   'protocol_version','odoo_manifest_digest','odoo_config_digest',
   'extension_manifest_digest','extension_config_digest','payload_digest',
   'extension_volume','runtime_container','runtime_config_digest',
   'external_executor_quiescent','candidate_runtime_verified','gateway_identity_verified',
   'target_database_access_verified','old_runtime_retired','tenant_recovery_verified',
   'candidate_smoke_verified','candidate_restart_policy','retained_restart_policy',
   'observed_gateway_configuration_digest','observed_target_slot'])
  or p_runtime_observation->'protocol_version'<>'1'::jsonb
  or exists(select 1 from unnest(array['odoo_manifest_digest','odoo_config_digest',
    'extension_manifest_digest','extension_config_digest','payload_digest',
    'runtime_config_digest','observed_gateway_configuration_digest']) key
    where jsonb_typeof(p_runtime_observation->key) is distinct from 'string'
     or ((p_runtime_observation->>key) ~ '^sha256:[0-9a-f]{64}$') is distinct from true)
  or exists(select 1 from unnest(array['external_executor_quiescent',
    'candidate_runtime_verified','gateway_identity_verified','target_database_access_verified',
    'old_runtime_retired','tenant_recovery_verified','candidate_smoke_verified']) key
    where p_runtime_observation->key is distinct from 'true'::jsonb)
  or p_runtime_observation->>'candidate_restart_policy'<>'unless-stopped'
  or p_runtime_observation->>'retained_restart_policy'<>'no'
  or jsonb_typeof(p_runtime_observation->'extension_volume') is distinct from 'string'
  or jsonb_typeof(p_runtime_observation->'runtime_container') is distinct from 'string'
  or jsonb_typeof(p_runtime_observation->'observed_target_slot') is distinct from 'string' then
  return query select 'invalid'::text,null::text,null::jsonb; return;
 end if;
 select expected.outcome,expected.expectation into v_expectation_outcome,v_expectation
  from control.read_interrupted_immutable_release_runtime_expectation(
   p_driver_operation_id,p_control_operation_attempt,p_control_operation_lease_owner,
   p_reconciliation_owner,p_reconciliation_token,p_claim_fence) expected;
 if v_expectation_outcome<>'claimed' then
  return query select v_expectation_outcome,null::text,null::jsonb; return;
 end if;
 select * into v_existing
  from control.fleet_release_route_publication_recovery_runtime_observations
  where driver_operation_id=p_driver_operation_id and claim_fence=p_claim_fence;
 if found then
  if v_existing.runtime_observation=p_runtime_observation then
   return query select 'replay',v_existing.observation_digest,v_existing.completion_response;
  else return query select 'conflict',null::text,null::jsonb; end if;
  return;
 end if;
 if p_runtime_observation->>'observed_target_slot'<>v_expectation->>'target_slot'
  or p_runtime_observation->>'observed_gateway_configuration_digest'<>
    v_expectation->>'gateway_configuration_digest'
  or ((p_runtime_observation->>'runtime_container') ~
    ('^[a-z0-9][a-z0-9-]{0,110}-odoo-'||(v_expectation->>'target_slot')||'$'))
      is distinct from true
  or ((p_runtime_observation->>'extension_volume') ~
    ('^mb-(control-|dev[1-4]-)?ext-'||
     substr(p_runtime_observation->>'extension_manifest_digest',8,16)||'-'||
     substr(p_runtime_observation->>'payload_digest',8,16)||'$')) is distinct from true
  or v_expectation->'release_manifest'->>'release_id'<>v_expectation->>'release_id'
  or v_expectation->'release_manifest'->'odoo_runtime'->>'subject_digest'<>
    v_expectation->>'odoo_subject_digest'
  or v_expectation->'release_manifest'->'extension_bundle'->>'subject_digest'<>
    v_expectation->>'extension_subject_digest'
  or jsonb_typeof(v_expectation->'release_manifest'->'addons') is distinct from 'object'
  or ((v_expectation->'release_manifest'->>'bridge_contract_digest') ~
    '^sha256:[0-9a-f]{64}$') is distinct from true
  or not exists(
   select 1
   from jsonb_array_elements(v_expectation->'release_manifest'->'odoo_runtime'->'platforms') runtime
   join jsonb_array_elements(v_expectation->'release_manifest'->'extension_bundle'->'platforms') extension
    on extension->'platform'=runtime->'platform'
   join jsonb_array_elements(v_expectation->'release_manifest'->'pair_qualifications') pair
    on pair->'platform'=runtime->'platform'
   where runtime->>'manifest_digest'=p_runtime_observation->>'odoo_manifest_digest'
    and runtime->>'config_digest'=p_runtime_observation->>'odoo_config_digest'
    and extension->>'manifest_digest'=p_runtime_observation->>'extension_manifest_digest'
    and extension->>'config_digest'=p_runtime_observation->>'extension_config_digest'
    and extension->>'payload_digest'=p_runtime_observation->>'payload_digest'
    and pair->>'odoo_manifest_digest'=runtime->>'manifest_digest'
    and pair->>'extension_manifest_digest'=extension->>'manifest_digest'
    and pair->>'payload_digest'=extension->>'payload_digest'
    and pair->>'qualification_digest'=v_expectation->>'pair_qualification_digest'
    and pair->>'qualification_result'='passed') then
  return query select 'state_drift',null::text,null::jsonb; return;
 end if;
 select count(*)::integer into v_verified_count
 from control.tenant_release_adoptions adoption
 join control.workshop_recovery_points recovery on recovery.id=adoption.backup_recovery_id
  and recovery.workshop_id=adoption.workshop_id
 where adoption.operation_id=(v_expectation->>'control_operation_id')::uuid
  and adoption.release_id=v_expectation->>'release_id' and adoption.state='prepared'
  and adoption.verified_at is not null and recovery.state='ready'
  and recovery.verification_state='verified' and recovery.verified_at is not null
  and (recovery.expires_at is null or recovery.expires_at>now());
 if v_verified_count<>jsonb_array_length(v_expectation->'prepared_tenants') then
  return query select 'state_drift',null::text,null::jsonb; return;
 end if;
 v_response:=jsonb_build_object('evidence',jsonb_build_object(
  'release_id',v_expectation->>'release_id',
  'odoo_subject_digest',v_expectation->>'odoo_subject_digest',
  'extension_subject_digest',v_expectation->>'extension_subject_digest',
  'odoo_manifest_digest',p_runtime_observation->>'odoo_manifest_digest',
  'odoo_config_digest',p_runtime_observation->>'odoo_config_digest',
  'extension_manifest_digest',p_runtime_observation->>'extension_manifest_digest',
  'extension_config_digest',p_runtime_observation->>'extension_config_digest',
  'payload_digest',p_runtime_observation->>'payload_digest',
  'extension_volume',p_runtime_observation->>'extension_volume',
  'pair_qualification_digest',v_expectation->>'pair_qualification_digest',
  'bridge_contract_digest',v_expectation->'release_manifest'->>'bridge_contract_digest',
  'installed_addon_versions',v_expectation->'release_manifest'->'addons',
  'runtime_key','shared-odoo','target_slot',v_expectation->>'target_slot',
  'runtime_container',p_runtime_observation->>'runtime_container',
  'runtime_role','mb_runtime_'||substr(v_expectation->>'odoo_subject_digest',8,16),
  'runtime_deployment_ref',v_expectation->'release_manifest'->'odoo_runtime'->>'deployment_ref',
  'runtime_config_digest',p_runtime_observation->>'runtime_config_digest',
  'prepared_tenants',v_expectation->'prepared_tenants',
  'fleet_generation',v_expectation->'fleet_generation',
  'tenant_snapshot',v_expectation->'tenant_snapshot',
  'gateway_configuration_digest',v_expectation->>'gateway_configuration_digest',
  'driver_action_id',v_expectation->'driver_action_id',
  'driver_operation_id',v_expectation->'driver_operation_id',
  'driver_fence_token',v_expectation->'original_global_fence_token',
  'old_runtime_database_access_revoked',true,'tenant_recovery_verified',true,
  'candidate_smoke_verified',true,'candidate_restart_policy','unless-stopped',
  'retained_restart_policy','no'));
 if not control.valid_immutable_release_route_completion_response(
   p_driver_operation_id,v_response) then
  return query select 'state_drift',null::text,null::jsonb; return;
 end if;
 v_digest:=control.release_route_recovery_runtime_observation_digest(
  p_driver_operation_id,(v_expectation->>'fleet_run_id')::uuid,p_claim_fence,
  p_runtime_observation,v_response);
 insert into control.fleet_release_route_publication_recovery_runtime_observations(
  driver_operation_id,fleet_run_id,claim_fence,control_operation_attempt,
  control_operation_lease_owner,reconciliation_owner,reconciliation_token_digest,
  runtime_observation,completion_response,observation_digest)
 values(p_driver_operation_id,(v_expectation->>'fleet_run_id')::uuid,p_claim_fence,
  p_control_operation_attempt,p_control_operation_lease_owner,p_reconciliation_owner,
  control.release_route_recovery_token_digest(p_reconciliation_token),
 p_runtime_observation,v_response,v_digest);
 return query select 'recorded',v_digest,v_response;
end $function$;

-- Candidate exchange authorization may no longer accept a response supplied by
-- its caller. Preserve the old implementation only as a private primitive.
alter function control.authorize_interrupted_immutable_release_route_exchange(
 uuid,integer,text,uuid,uuid,bigint,text,text,jsonb)
 rename to authorize_interrupted_immutable_release_route_exchange_unreceipted_v1;

create function control.authorize_interrupted_immutable_release_route_exchange(
 p_driver_operation_id uuid,p_control_operation_attempt integer,p_control_operation_lease_owner text,
 p_reconciliation_owner uuid,p_reconciliation_token uuid,p_claim_fence bigint,
 p_authorization_kind text,p_overlay_kind text,p_response jsonb
) returns text language plpgsql security definer set search_path=pg_catalog,control as $function$
begin
 if p_authorization_kind='publish_candidate' then return 'runtime_observation_required'; end if;
 return control.authorize_interrupted_immutable_release_route_exchange_unreceipted_v1(
  p_driver_operation_id,p_control_operation_attempt,p_control_operation_lease_owner,
  p_reconciliation_owner,p_reconciliation_token,p_claim_fence,p_authorization_kind,
  p_overlay_kind,p_response);
end $function$;

create function control.authorize_interrupted_immutable_release_route_candidate_from_observation(
 p_driver_operation_id uuid,p_control_operation_attempt integer,p_control_operation_lease_owner text,
 p_reconciliation_owner uuid,p_reconciliation_token uuid,p_claim_fence bigint,
 p_observation_digest text
) returns text language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_observation control.fleet_release_route_publication_recovery_runtime_observations%rowtype;
begin
 if not control.lock_immutable_release_route_recovery_claim(
  p_driver_operation_id,p_control_operation_attempt,p_control_operation_lease_owner,
  p_reconciliation_owner,p_reconciliation_token,p_claim_fence) then return 'claim_lost'; end if;
 select * into v_observation
  from control.fleet_release_route_publication_recovery_runtime_observations
  where driver_operation_id=p_driver_operation_id and claim_fence=p_claim_fence
   and observation_digest=p_observation_digest
   and reconciliation_owner=p_reconciliation_owner
   and reconciliation_token_digest=control.release_route_recovery_token_digest(p_reconciliation_token);
 if not found then return 'observation_absent'; end if;
 return control.authorize_interrupted_immutable_release_route_exchange_unreceipted_v1(
  p_driver_operation_id,p_control_operation_attempt,p_control_operation_lease_owner,
  p_reconciliation_owner,p_reconciliation_token,p_claim_fence,'publish_candidate',
  'candidate',v_observation.completion_response);
end $function$;

alter function control.resolve_interrupted_immutable_release_route_publication(
 uuid,integer,text,uuid,uuid,bigint,text,jsonb,jsonb)
 rename to resolve_interrupted_immutable_release_route_publication_without_runtime_receipt_v2;

create function control.resolve_interrupted_immutable_release_route_publication(
 p_driver_operation_id uuid,p_control_operation_attempt integer,p_control_operation_lease_owner text,
 p_reconciliation_owner uuid,p_reconciliation_token uuid,p_claim_fence bigint,
 p_resolution_kind text,p_observation_evidence jsonb,p_candidate_response jsonb
) returns text language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_observation control.fleet_release_route_publication_recovery_runtime_observations%rowtype;
begin
 if p_resolution_kind<>'candidate' then
  return control.resolve_interrupted_immutable_release_route_publication_without_runtime_receipt_v2(
   p_driver_operation_id,p_control_operation_attempt,p_control_operation_lease_owner,
   p_reconciliation_owner,p_reconciliation_token,p_claim_fence,p_resolution_kind,
   p_observation_evidence,p_candidate_response);
 end if;
 if p_candidate_response is not null then return 'runtime_observation_required'; end if;
 if not control.lock_immutable_release_route_recovery_claim(
  p_driver_operation_id,p_control_operation_attempt,p_control_operation_lease_owner,
  p_reconciliation_owner,p_reconciliation_token,p_claim_fence) then return 'claim_lost'; end if;
 select * into v_observation
  from control.fleet_release_route_publication_recovery_runtime_observations observation
  where observation.driver_operation_id=p_driver_operation_id
   and observation.claim_fence=p_claim_fence
   and observation.reconciliation_owner=p_reconciliation_owner
   and observation.reconciliation_token_digest=
    control.release_route_recovery_token_digest(p_reconciliation_token)
   and exists(select 1 from control.fleet_release_route_publication_recovery_authorizations auth
    where auth.driver_operation_id=p_driver_operation_id
     and auth.claim_fence=p_claim_fence
     and auth.authorization_kind='publish_candidate'
     and auth.response=observation.completion_response);
 if not found then return 'runtime_observation_required'; end if;
 return control.resolve_interrupted_immutable_release_route_publication_without_runtime_receipt_v2(
  p_driver_operation_id,p_control_operation_attempt,p_control_operation_lease_owner,
  p_reconciliation_owner,p_reconciliation_token,p_claim_fence,p_resolution_kind,
  p_observation_evidence,v_observation.completion_response);
end $function$;

create function control.review_interrupted_immutable_release_runtime_observation(
 p_driver_operation_id uuid,p_claim_fence bigint,p_control_operation_id uuid,
 p_review_attempt integer,p_review_lease_owner text,p_observation_digest text,p_decision text
) returns table(outcome text,review_digest text)
language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_publication control.fleet_release_route_publications%rowtype;
 v_observation control.fleet_release_route_publication_recovery_runtime_observations%rowtype;
 v_resolution control.fleet_release_route_publication_recovery_resolutions%rowtype;
 v_existing control.fleet_release_route_publication_recovery_reviews%rowtype;
 v_resolution_digest text; v_review_digest text;
begin
 if p_driver_operation_id is null or p_claim_fence is null or p_claim_fence<=0
  or p_control_operation_id is null or p_review_attempt is null or p_review_attempt<=0
  or p_review_lease_owner is null or btrim(p_review_lease_owner)=''
  or p_observation_digest is null or p_observation_digest !~ '^sha256:[0-9a-f]{64}$'
  or p_decision not in ('accept_candidate','keep_quarantined') then
  return query select 'invalid'::text,null::text; return;
 end if;
 if not control.lock_immutable_release_route_recovery_review(
  p_driver_operation_id,p_claim_fence,p_control_operation_id,p_review_attempt,
  p_review_lease_owner) then return query select 'lease_lost'::text,null::text; return; end if;
 select * into v_publication from control.fleet_release_route_publications
  where driver_operation_id=p_driver_operation_id;
 select * into v_observation
  from control.fleet_release_route_publication_recovery_runtime_observations
  where driver_operation_id=p_driver_operation_id and claim_fence=p_claim_fence
   and observation_digest=p_observation_digest;
 if not found then return query select 'observation_absent'::text,null::text; return; end if;
 select * into v_resolution from control.fleet_release_route_publication_recovery_resolutions
  where driver_operation_id=p_driver_operation_id and claim_fence=p_claim_fence
   and resolution_kind='candidate';
 if not found then return query select 'resolution_absent'::text,null::text; return; end if;
 if v_publication.phase<>'quarantined'
  or v_resolution.candidate_response is distinct from v_observation.completion_response
  or not control.valid_immutable_release_route_completion_response(
    p_driver_operation_id,v_observation.completion_response) then
  return query select 'state_drift'::text,null::text; return;
 end if;
 v_resolution_digest:=control.release_route_recovery_decision_digest(
  p_driver_operation_id,v_publication.fleet_run_id,p_claim_fence,'candidate',
  v_resolution.observation_evidence,v_resolution.candidate_response);
 v_review_digest:=control.release_route_recovery_review_digest(
  p_driver_operation_id,v_publication.fleet_run_id,p_claim_fence,p_observation_digest,
  v_resolution_digest,p_control_operation_id,p_review_attempt,p_review_lease_owner,p_decision);
 select * into v_existing from control.fleet_release_route_publication_recovery_reviews
  where driver_operation_id=p_driver_operation_id and claim_fence=p_claim_fence;
 if found then
  if v_existing.review_digest=v_review_digest then
   return query select 'replay',v_existing.review_digest;
  else return query select 'conflict'::text,null::text; end if;
  return;
 end if;
 insert into control.fleet_release_route_publication_recovery_reviews(
  driver_operation_id,fleet_run_id,claim_fence,observation_digest,resolution_digest,
  review_control_operation_id,review_attempt,review_lease_owner,decision,review_digest)
 values(p_driver_operation_id,v_publication.fleet_run_id,p_claim_fence,p_observation_digest,
  v_resolution_digest,p_control_operation_id,p_review_attempt,p_review_lease_owner,
  p_decision,v_review_digest);
 return query select case when p_decision='accept_candidate' then 'approved' else 'kept_quarantined' end,
  v_review_digest;
end $function$;

alter function control.finish_interrupted_immutable_release_route_publication(
 uuid,integer,text,uuid,uuid,bigint,text,text)
 rename to finish_interrupted_immutable_release_route_publication_without_independent_review_v2;

create function control.finish_interrupted_immutable_release_route_publication(
 p_driver_operation_id uuid,p_control_operation_attempt integer,p_control_operation_lease_owner text,
 p_reconciliation_owner uuid,p_reconciliation_token uuid,p_claim_fence bigint,
 p_resolution_kind text,p_decision_digest text
) returns table(outcome text,stored_response jsonb)
language plpgsql security definer set search_path=pg_catalog,control as $function$
begin
 if p_resolution_kind='candidate' then
  return query select 'reviewed_finish_required'::text,null::jsonb; return;
 end if;
 return query select * from
  control.finish_interrupted_immutable_release_route_publication_without_independent_review_v2(
   p_driver_operation_id,p_control_operation_attempt,p_control_operation_lease_owner,
   p_reconciliation_owner,p_reconciliation_token,p_claim_fence,p_resolution_kind,p_decision_digest);
end $function$;

create function control.finish_reviewed_interrupted_immutable_release_route_publication(
 p_driver_operation_id uuid,p_control_operation_attempt integer,p_control_operation_lease_owner text,
 p_reconciliation_owner uuid,p_reconciliation_token uuid,p_claim_fence bigint
) returns table(outcome text,stored_response jsonb)
language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_review control.fleet_release_route_publication_recovery_reviews%rowtype;
begin
 select review.* into v_review
 from control.fleet_release_route_publication_recovery_reviews review
 join control.fleet_release_route_publication_recovery_runtime_observations observation
  using(driver_operation_id,claim_fence,observation_digest)
 join control.fleet_release_route_publication_recovery_resolutions resolution
  using(driver_operation_id,claim_fence)
 where review.driver_operation_id=p_driver_operation_id and review.claim_fence=p_claim_fence
  and review.decision='accept_candidate' and resolution.resolution_kind='candidate'
  and resolution.candidate_response=observation.completion_response
  and review.resolution_digest=control.release_route_recovery_decision_digest(
   resolution.driver_operation_id,resolution.fleet_run_id,resolution.claim_fence,
   resolution.resolution_kind,resolution.observation_evidence,resolution.candidate_response);
 if not found then return query select 'review_required'::text,null::jsonb; return; end if;
 return query select * from
  control.finish_interrupted_immutable_release_route_publication_without_independent_review_v2(
   p_driver_operation_id,p_control_operation_attempt,p_control_operation_lease_owner,
   p_reconciliation_owner,p_reconciliation_token,p_claim_fence,'candidate',
   v_review.resolution_digest);
end $function$;

revoke all on table control.fleet_release_route_publication_recovery_runtime_observations,
 control.fleet_release_route_publication_recovery_reviews from public;
revoke all on function control.release_route_recovery_runtime_observation_digest(uuid,uuid,bigint,jsonb,jsonb) from public;
revoke all on function control.release_route_recovery_review_digest(uuid,uuid,bigint,text,text,uuid,integer,text,text) from public;
revoke all on function control.lock_immutable_release_route_recovery_review(uuid,bigint,uuid,integer,text) from public;
revoke all on function control.record_interrupted_immutable_release_runtime_observation(uuid,integer,text,uuid,uuid,bigint,jsonb) from public;
revoke all on function control.authorize_interrupted_immutable_release_route_exchange_unreceipted_v1(uuid,integer,text,uuid,uuid,bigint,text,text,jsonb) from public;
revoke all on function control.authorize_interrupted_immutable_release_route_candidate_from_observation(uuid,integer,text,uuid,uuid,bigint,text) from public;
revoke all on function control.resolve_interrupted_immutable_release_route_publication_without_runtime_receipt_v2(uuid,integer,text,uuid,uuid,bigint,text,jsonb,jsonb) from public;
revoke all on function control.review_interrupted_immutable_release_runtime_observation(uuid,bigint,uuid,integer,text,text,text) from public;
revoke all on function control.finish_interrupted_immutable_release_route_publication_without_independent_review_v2(uuid,integer,text,uuid,uuid,bigint,text,text) from public;
revoke all on function control.finish_reviewed_interrupted_immutable_release_route_publication(uuid,integer,text,uuid,uuid,bigint) from public;
revoke all on function control.authorize_interrupted_immutable_release_route_exchange(uuid,integer,text,uuid,uuid,bigint,text,text,jsonb) from public;
revoke all on function control.resolve_interrupted_immutable_release_route_publication(uuid,integer,text,uuid,uuid,bigint,text,jsonb,jsonb) from public;
revoke all on function control.finish_interrupted_immutable_release_route_publication(uuid,integer,text,uuid,uuid,bigint,text,text) from public;

do $migration$ declare v_role text; begin
 foreach v_role in array array['control_api','control_tenant_api','control_membership_worker',
  'control_provisioning_worker','control_invoice_worker','control_inventory_worker',
  'control_email_worker','control_reconciliation_worker','control_lifecycle_worker',
  'control_backup_scheduler','control_driver_ledger','control_release_worker','control_privacy_worker'] loop
  if exists(select 1 from pg_roles where rolname=v_role) then
   execute format('revoke all on table control.fleet_release_route_publication_recovery_runtime_observations, control.fleet_release_route_publication_recovery_reviews from %I',v_role);
   execute format('revoke all on function control.release_route_recovery_runtime_observation_digest(uuid,uuid,bigint,jsonb,jsonb), control.release_route_recovery_review_digest(uuid,uuid,bigint,text,text,uuid,integer,text,text), control.lock_immutable_release_route_recovery_review(uuid,bigint,uuid,integer,text), control.record_interrupted_immutable_release_runtime_observation(uuid,integer,text,uuid,uuid,bigint,jsonb), control.authorize_interrupted_immutable_release_route_exchange_unreceipted_v1(uuid,integer,text,uuid,uuid,bigint,text,text,jsonb), control.authorize_interrupted_immutable_release_route_candidate_from_observation(uuid,integer,text,uuid,uuid,bigint,text), control.resolve_interrupted_immutable_release_route_publication_without_runtime_receipt_v2(uuid,integer,text,uuid,uuid,bigint,text,jsonb,jsonb), control.review_interrupted_immutable_release_runtime_observation(uuid,bigint,uuid,integer,text,text,text), control.finish_interrupted_immutable_release_route_publication_without_independent_review_v2(uuid,integer,text,uuid,uuid,bigint,text,text), control.finish_reviewed_interrupted_immutable_release_route_publication(uuid,integer,text,uuid,uuid,bigint), control.authorize_interrupted_immutable_release_route_exchange(uuid,integer,text,uuid,uuid,bigint,text,text,jsonb), control.resolve_interrupted_immutable_release_route_publication(uuid,integer,text,uuid,uuid,bigint,text,jsonb,jsonb), control.finish_interrupted_immutable_release_route_publication(uuid,integer,text,uuid,uuid,bigint,text,text) from %I',v_role);
  end if;
 end loop;
 if exists(select 1 from pg_roles where rolname='control_driver_ledger') then
  grant execute on function control.record_interrupted_immutable_release_runtime_observation(uuid,integer,text,uuid,uuid,bigint,jsonb) to control_driver_ledger;
  grant execute on function control.authorize_interrupted_immutable_release_route_candidate_from_observation(uuid,integer,text,uuid,uuid,bigint,text) to control_driver_ledger;
  grant execute on function control.finish_reviewed_interrupted_immutable_release_route_publication(uuid,integer,text,uuid,uuid,bigint) to control_driver_ledger;
  grant execute on function control.authorize_interrupted_immutable_release_route_exchange(uuid,integer,text,uuid,uuid,bigint,text,text,jsonb) to control_driver_ledger;
  grant execute on function control.resolve_interrupted_immutable_release_route_publication(uuid,integer,text,uuid,uuid,bigint,text,jsonb,jsonb) to control_driver_ledger;
  grant execute on function control.finish_interrupted_immutable_release_route_publication(uuid,integer,text,uuid,uuid,bigint,text,text) to control_driver_ledger;
 end if;
 if exists(select 1 from pg_roles where rolname='control_release_worker') then
  grant execute on function control.review_interrupted_immutable_release_runtime_observation(uuid,bigint,uuid,integer,text,text,text) to control_release_worker;
 end if;
end $migration$;

comment on table control.fleet_release_route_publication_recovery_runtime_observations is
'Immutable claim-authenticated live-fact receipt whose canonical completion response is built by PostgreSQL.';
comment on table control.fleet_release_route_publication_recovery_reviews is
'Immutable release-worker review binding the runtime observation and post-exchange route resolution before terminalization.';
