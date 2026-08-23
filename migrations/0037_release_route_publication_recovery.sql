-- Dormant, specialized recovery for interrupted protocol-v2 fleet releases.
--
-- Recovery is authenticated by a *new* live release-adoption attempt.  It does
-- not reuse either the legacy release reconciliation ledger or the universal
-- one-target publication recovery protocol.  No caller is enabled by this
-- migration.

create table control.fleet_release_route_publication_recovery_claims (
  driver_operation_id uuid not null,
  fleet_run_id uuid not null,
  claim_fence bigint not null default 0,
  claim_mode text,
  control_operation_attempt integer,
  control_operation_lease_owner text,
  reconciliation_owner uuid,
  reconciliation_token uuid,
  claim_expires_at timestamptz,
  updated_at timestamptz not null default now(),
  primary key(driver_operation_id,claim_fence),
  unique(driver_operation_id,fleet_run_id,claim_fence),
  constraint fleet_release_route_recovery_claims_publication_fkey
    foreign key(driver_operation_id,fleet_run_id)
    references control.fleet_release_route_publications(driver_operation_id,fleet_run_id)
    on delete restrict,
  constraint fleet_release_route_recovery_claims_fence_check check(claim_fence>=0),
  constraint fleet_release_route_recovery_claims_shape_check check(
    (claim_mode is null and control_operation_attempt is null
      and control_operation_lease_owner is null and reconciliation_owner is null
      and reconciliation_token is null and claim_expires_at is null)
    or (claim_mode is not null and claim_mode in ('write_cleanup','restore_prior','forward_only')
      and claim_fence>0 and control_operation_attempt is not null and control_operation_attempt>0
      and control_operation_lease_owner is not null and btrim(control_operation_lease_owner)<>''
      and reconciliation_owner is not null and reconciliation_token is not null
      and claim_expires_at is not null))
);

create table control.fleet_release_route_publication_recovery_route_heads (
  driver_operation_id uuid not null,
  claim_fence bigint not null,
  workshop_id uuid not null,
  applied_generation bigint not null,
  applied_digest text not null,
  applied_disposition text not null,
  applied_rendered_digest text not null,
  applied_driver_operation_id uuid,
  applied_effect_run_id uuid,
  applied_fence_token bigint not null,
  desired_generation bigint not null,
  desired_digest text not null,
  desired_disposition text not null,
  recorded_at timestamptz not null default now(),
  primary key(driver_operation_id,claim_fence,workshop_id),
  constraint fleet_release_route_recovery_route_heads_claim_fkey
    foreign key(driver_operation_id,claim_fence) references
      control.fleet_release_route_publication_recovery_claims(driver_operation_id,claim_fence)
      on delete restrict,
  constraint fleet_release_route_recovery_route_heads_shape_check check(
    applied_generation>0 and desired_generation=applied_generation
    and applied_digest ~ '^sha256:[0-9a-f]{64}$' and desired_digest=applied_digest
    and applied_disposition='present' and desired_disposition='present'
    and applied_rendered_digest ~ '^sha256:[0-9a-f]{64}$'
    and applied_fence_token>0
    and ((applied_driver_operation_id is null)<>(applied_effect_run_id is null)))
);

create table control.fleet_release_route_publication_recovery_authorizations (
  driver_operation_id uuid not null,
  claim_fence bigint not null,
  authorization_kind text not null,
  overlay_kind text,
  response jsonb,
  authorized_at timestamptz not null default now(),
  primary key(driver_operation_id,claim_fence,authorization_kind),
  constraint fleet_release_route_recovery_authorizations_claim_fkey
    foreign key(driver_operation_id,claim_fence) references
      control.fleet_release_route_publication_recovery_claims(driver_operation_id,claim_fence)
      on delete restrict,
  constraint fleet_release_route_recovery_authorizations_shape_check check(
    authorization_kind in ('dispose_overlay','restore_prior','publish_candidate')
    and ((authorization_kind='restore_prior' and overlay_kind is null and response is null)
      or (authorization_kind='dispose_overlay' and overlay_kind in ('maintenance','candidate')
        and response is null)
      or (authorization_kind='publish_candidate' and overlay_kind='candidate'
        and response is not null and jsonb_typeof(response)='object'
        and pg_column_size(response)<=1048576)))
);

create table control.fleet_release_route_publication_recovery_candidate_records (
  driver_operation_id uuid not null,
  claim_fence bigint not null,
  workshop_id uuid not null,
  generation bigint not null,
  projection_digest text not null,
  applied_rendered_digest text not null,
  rendered_digest text not null,
  recorded_at timestamptz not null default now(),
  primary key(driver_operation_id,claim_fence,workshop_id),
  constraint fleet_release_route_recovery_candidate_records_claim_fkey
    foreign key(driver_operation_id,claim_fence) references
      control.fleet_release_route_publication_recovery_claims(driver_operation_id,claim_fence)
      on delete restrict,
  constraint fleet_release_route_recovery_candidate_records_owner_fkey
    foreign key(driver_operation_id,workshop_id,generation,projection_digest,applied_rendered_digest)
    references control.fleet_release_route_publication_owners(
      driver_operation_id,workshop_id,generation,projection_digest,applied_rendered_digest)
      on delete restrict,
  constraint fleet_release_route_recovery_candidate_records_digest_check check(
    generation>0 and projection_digest ~ '^sha256:[0-9a-f]{64}$'
    and applied_rendered_digest ~ '^sha256:[0-9a-f]{64}$'
    and rendered_digest ~ '^sha256:[0-9a-f]{64}$')
);

create table control.fleet_release_route_publication_recovery_candidate_seals (
  driver_operation_id uuid not null,
  claim_fence bigint not null,
  selector text not null,
  directory_device bigint not null,
  directory_inode bigint not null,
  record_count integer not null,
  route_set_digest text not null,
  sealed_at timestamptz not null default now(),
  primary key(driver_operation_id,claim_fence),
  constraint fleet_release_route_recovery_candidate_seals_claim_fkey
    foreign key(driver_operation_id,claim_fence) references
      control.fleet_release_route_publication_recovery_claims(driver_operation_id,claim_fence)
      on delete restrict,
  constraint fleet_release_route_recovery_candidate_seals_shape_check check(
    selector ~ '^generations/release-[0-9a-f]{32}-candidate$'
    and directory_device>0 and directory_inode>0 and record_count between 1 and 500
    and route_set_digest ~ '^sha256:[0-9a-f]{64}$')
);

create table control.fleet_release_route_publication_recovery_resolutions (
  driver_operation_id uuid not null,
  fleet_run_id uuid not null,
  claim_fence bigint not null,
  control_operation_attempt integer not null,
  control_operation_lease_owner text not null,
  reconciliation_owner uuid not null,
  reconciliation_token_digest text not null,
  claim_mode text not null,
  resolution_kind text not null,
  observation_evidence jsonb not null,
  candidate_response jsonb,
  recorded_at timestamptz not null default now(),
  primary key(driver_operation_id,claim_fence),
  unique(driver_operation_id,claim_fence,reconciliation_owner,resolution_kind),
  constraint fleet_release_route_recovery_resolutions_publication_fkey
    foreign key(driver_operation_id,fleet_run_id)
    references control.fleet_release_route_publications(driver_operation_id,fleet_run_id)
    on delete restrict,
  constraint fleet_release_route_recovery_resolutions_claim_fkey
    foreign key(driver_operation_id,claim_fence)
    references control.fleet_release_route_publication_recovery_claims(driver_operation_id,claim_fence)
    on delete restrict,
  constraint fleet_release_route_recovery_resolutions_shape_check check(
    claim_fence>0 and control_operation_attempt>0
    and btrim(control_operation_lease_owner)<>''
    and reconciliation_token_digest ~ '^sha256:[0-9a-f]{64}$'
    and claim_mode in ('write_cleanup','restore_prior','forward_only')
    and resolution_kind in ('candidate','prior','unstarted','inconclusive')
    and jsonb_typeof(observation_evidence)='object'
    and pg_column_size(observation_evidence)<=16384
    and ((resolution_kind='candidate' and candidate_response is not null
      and jsonb_typeof(candidate_response)='object'
      and pg_column_size(candidate_response)<=1048576)
      or (resolution_kind<>'candidate' and candidate_response is null)))
);

create table control.fleet_release_route_publication_recovery_terminals (
  driver_operation_id uuid primary key,
  fleet_run_id uuid not null unique,
  claim_fence bigint not null,
  control_operation_attempt integer not null,
  control_operation_lease_owner text not null,
  reconciliation_owner uuid not null,
  resolution_kind text not null,
  outcome text not null,
  decision_digest text not null,
  response jsonb not null,
  terminal_at timestamptz not null default now(),
  constraint fleet_release_route_recovery_terminals_resolution_fkey
    foreign key(driver_operation_id,claim_fence,reconciliation_owner,resolution_kind)
    references control.fleet_release_route_publication_recovery_resolutions(
      driver_operation_id,claim_fence,reconciliation_owner,resolution_kind) on delete restrict,
  constraint fleet_release_route_recovery_terminals_publication_fkey
    foreign key(driver_operation_id,fleet_run_id)
    references control.fleet_release_route_publications(driver_operation_id,fleet_run_id)
    on delete restrict,
  constraint fleet_release_route_recovery_terminals_shape_check check(
    claim_fence>0 and control_operation_attempt>0
    and btrim(control_operation_lease_owner)<>''
    and resolution_kind in ('candidate','prior','unstarted')
    and outcome in ('applied_recovered','not_applied')
    and ((resolution_kind='candidate')=(outcome='applied_recovered'))
    and decision_digest ~ '^sha256:[0-9a-f]{64}$'
    and jsonb_typeof(response)='object' and pg_column_size(response)<=1048576)
);

create function control.reject_release_route_recovery_evidence_mutation()
returns trigger language plpgsql set search_path=pg_catalog,control as $function$
begin
 raise exception 'release route recovery evidence is immutable' using errcode='55000';
end $function$;

/* ACL is installed after every function definition.
-- Function-only runtime surface.
revoke all on table control.fleet_release_route_publication_recovery_claims,
 control.fleet_release_route_publication_recovery_authorizations,
 control.fleet_release_route_publication_recovery_candidate_records,
 control.fleet_release_route_publication_recovery_candidate_seals,
 control.fleet_release_route_publication_recovery_route_heads,
 control.fleet_release_route_publication_recovery_resolutions,
 control.fleet_release_route_publication_recovery_terminals from public;
revoke all on function control.release_route_recovery_token_digest(uuid) from public;
revoke all on function control.release_route_recovery_decision_digest(uuid,uuid,bigint,text,jsonb,jsonb) from public;
revoke all on function control.valid_release_route_recovery_worker(uuid,integer,text) from public;
revoke all on function control.valid_immutable_release_route_completion_response(uuid,jsonb) from public;
revoke all on function control.lock_immutable_release_route_recovery_claim(uuid,integer,text,uuid,uuid,bigint) from public;
revoke all on function control.finish_immutable_release_route_publication_before_recovery(uuid,uuid,uuid,uuid,uuid,bigint,jsonb) from public;
revoke all on function control.discover_interrupted_immutable_release_route_publications(uuid,integer) from public;
revoke all on function control.claim_interrupted_immutable_release_route_publication(uuid,integer,text,uuid,uuid,integer) from public;
revoke all on function control.renew_interrupted_immutable_release_route_publication_claim(uuid,integer,text,uuid,uuid,bigint,integer) from public;
revoke all on function control.read_interrupted_immutable_release_route_publication_state(uuid,integer,text,uuid,uuid,bigint) from public;
revoke all on function control.record_interrupted_immutable_release_route_candidate_entry(uuid,integer,text,uuid,uuid,bigint,uuid,bigint,text,text,text) from public;
revoke all on function control.seal_interrupted_immutable_release_route_candidate(uuid,integer,text,uuid,uuid,bigint,text,bigint,bigint,integer,text) from public;
revoke all on function control.authorize_interrupted_immutable_release_route_exchange(uuid,integer,text,uuid,uuid,bigint,text,text,jsonb) from public;
revoke all on function control.resolve_interrupted_immutable_release_route_publication(uuid,integer,text,uuid,uuid,bigint,text,jsonb,jsonb) from public;
revoke all on function control.finish_interrupted_immutable_release_route_publication(uuid,integer,text,uuid,uuid,bigint,text,text) from public;
revoke all on function control.finish_immutable_release_route_publication(uuid,uuid,uuid,uuid,uuid,bigint,jsonb) from public;
revoke all on function control.read_immutable_release_route_publication_result(uuid,uuid) from public;

do $migration$ declare v_role text; begin
 foreach v_role in array array['control_api','control_tenant_api','control_membership_worker',
 'control_provisioning_worker','control_invoice_worker','control_inventory_worker',
 'control_email_worker','control_reconciliation_worker','control_lifecycle_worker',
 'control_backup_scheduler','control_driver_ledger','control_release_worker','control_privacy_worker'] loop
  if exists(select 1 from pg_roles where rolname=v_role) then
   execute format('revoke all on table control.fleet_release_route_publication_recovery_claims, control.fleet_release_route_publication_recovery_authorizations, control.fleet_release_route_publication_recovery_candidate_records, control.fleet_release_route_publication_recovery_candidate_seals, control.fleet_release_route_publication_recovery_route_heads, control.fleet_release_route_publication_recovery_resolutions, control.fleet_release_route_publication_recovery_terminals from %I',v_role);
   execute format('revoke all on function control.finish_immutable_release_route_publication_before_recovery(uuid,uuid,uuid,uuid,uuid,bigint,jsonb) from %I',v_role);
  end if;
 end loop;
 if exists(select 1 from pg_roles where rolname='control_driver_ledger') then
  grant execute on function control.discover_interrupted_immutable_release_route_publications(uuid,integer) to control_driver_ledger;
  grant execute on function control.claim_interrupted_immutable_release_route_publication(uuid,integer,text,uuid,uuid,integer) to control_driver_ledger;
  grant execute on function control.renew_interrupted_immutable_release_route_publication_claim(uuid,integer,text,uuid,uuid,bigint,integer) to control_driver_ledger;
  grant execute on function control.read_interrupted_immutable_release_route_publication_state(uuid,integer,text,uuid,uuid,bigint) to control_driver_ledger;
  grant execute on function control.record_interrupted_immutable_release_route_candidate_entry(uuid,integer,text,uuid,uuid,bigint,uuid,bigint,text,text,text) to control_driver_ledger;
  grant execute on function control.seal_interrupted_immutable_release_route_candidate(uuid,integer,text,uuid,uuid,bigint,text,bigint,bigint,integer,text) to control_driver_ledger;
  grant execute on function control.authorize_interrupted_immutable_release_route_exchange(uuid,integer,text,uuid,uuid,bigint,text,text,jsonb) to control_driver_ledger;
  grant execute on function control.resolve_interrupted_immutable_release_route_publication(uuid,integer,text,uuid,uuid,bigint,text,jsonb,jsonb) to control_driver_ledger;
  grant execute on function control.finish_interrupted_immutable_release_route_publication(uuid,integer,text,uuid,uuid,bigint,text,text) to control_driver_ledger;
  grant execute on function control.finish_immutable_release_route_publication(uuid,uuid,uuid,uuid,uuid,bigint,jsonb) to control_driver_ledger;
  grant execute on function control.read_immutable_release_route_publication_result(uuid,uuid) to control_driver_ledger;
 end if;
end $migration$;

comment on table control.fleet_release_route_publication_recovery_claims is
'Dormant fenced recovery claims authenticated by the current retrying release worker; expiry is capped by its operation lease.';
comment on table control.fleet_release_route_publication_recovery_resolutions is
'Immutable exact filesystem observations for specialized protocol-v2 release route recovery.';
comment on table control.fleet_release_route_publication_recovery_terminals is
'Immutable terminal not-applied or forward-recovered release route decisions; the quarantined parent remains forensic evidence.';
*/

-- A recovered candidate deliberately leaves the immutable parent quarantined.
-- Preserve the 0036 call surface while making its durable completion receipt
-- authoritative for replay regardless of parent phase.
alter function control.finish_immutable_release_route_publication(
 uuid,uuid,uuid,uuid,uuid,bigint,jsonb)
 rename to finish_immutable_release_route_publication_before_recovery;

create function control.finish_immutable_release_route_publication(
 p_driver_operation_id uuid,p_instance_owner uuid,p_execution_token uuid,
 p_global_lease_token uuid,p_route_lease_token uuid,p_global_fence_token bigint,
 p_response jsonb
) returns table(outcome text,stored_response jsonb)
language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_publication control.fleet_release_route_publications%rowtype; v_completion jsonb;
 v_outcome text; v_stored_response jsonb;
begin
 select * into v_publication from control.fleet_release_route_publications
  where driver_operation_id=p_driver_operation_id;
 if not found then return query select 'not_found',null::jsonb; return; end if;
 if v_publication.original_instance_owner is distinct from p_instance_owner
  or v_publication.original_execution_token is distinct from p_execution_token
  or v_publication.original_global_lease_token is distinct from p_global_lease_token
  or v_publication.original_route_lease_token is distinct from p_route_lease_token
  or v_publication.original_global_fence_token is distinct from p_global_fence_token then
  return query select 'conflict',null::jsonb; return;
 end if;
 select completion.stored_response into v_completion
  from control.fleet_release_route_publication_completions completion
  where completion.driver_operation_id=p_driver_operation_id;
 if found then return query select case when v_completion=p_response then 'replay' else 'conflict' end,
  case when v_completion=p_response then v_completion else null::jsonb end; return; end if;
 select result.outcome,result.stored_response into v_outcome,v_stored_response
 from control.finish_immutable_release_route_publication_before_recovery(
  p_driver_operation_id,p_instance_owner,p_execution_token,p_global_lease_token,
  p_route_lease_token,p_global_fence_token,p_response) result;
 if v_outcome='finished' then return query select v_outcome,v_stored_response; return; end if;
 select completion.stored_response into v_completion
  from control.fleet_release_route_publication_completions completion
  where completion.driver_operation_id=p_driver_operation_id;
 if found then return query select case when v_completion=p_response then 'replay' else 'conflict' end,
  case when v_completion=p_response then v_completion else null::jsonb end; return; end if;
 return query select v_outcome,v_stored_response;
end $function$;

create or replace function control.read_immutable_release_route_publication_result(
 p_driver_operation_id uuid,p_fleet_run_id uuid
) returns table(outcome text,stored_response jsonb)
language sql stable security definer set search_path=pg_catalog,control as $function$
 select case when publication.driver_operation_id is null then 'not_found'
   when publication.fleet_run_id<>p_fleet_run_id then 'conflict'
   when completion.driver_operation_id is not null then 'replay'
   when terminal.driver_operation_id is not null then terminal.outcome
   when publication.phase='quarantined' then 'quarantined' else 'pending' end,
  case when publication.fleet_run_id=p_fleet_run_id
    then coalesce(completion.stored_response,terminal.response) else null end
 from (values(1)) singleton(value)
 left join control.fleet_release_route_publications publication
  on publication.driver_operation_id=p_driver_operation_id
 left join control.fleet_release_route_publication_completions completion
  on completion.driver_operation_id=publication.driver_operation_id
 left join control.fleet_release_route_publication_recovery_terminals terminal
  on terminal.driver_operation_id=publication.driver_operation_id
$function$;

create trigger fleet_release_route_recovery_authorizations_immutable
before update or delete on control.fleet_release_route_publication_recovery_authorizations
for each row execute function control.reject_release_route_recovery_evidence_mutation();
create trigger fleet_release_route_recovery_route_heads_immutable
before update or delete on control.fleet_release_route_publication_recovery_route_heads
for each row execute function control.reject_release_route_recovery_evidence_mutation();
create trigger fleet_release_route_recovery_candidate_records_immutable
before update or delete on control.fleet_release_route_publication_recovery_candidate_records
for each row execute function control.reject_release_route_recovery_evidence_mutation();
create trigger fleet_release_route_recovery_candidate_seals_immutable
before update or delete on control.fleet_release_route_publication_recovery_candidate_seals
for each row execute function control.reject_release_route_recovery_evidence_mutation();
create trigger fleet_release_route_recovery_resolutions_immutable
before update or delete on control.fleet_release_route_publication_recovery_resolutions
for each row execute function control.reject_release_route_recovery_evidence_mutation();
create trigger fleet_release_route_recovery_terminals_immutable
before update or delete on control.fleet_release_route_publication_recovery_terminals
for each row execute function control.reject_release_route_recovery_evidence_mutation();

create function control.release_route_recovery_token_digest(p_token uuid)
returns text language sql immutable strict set search_path=pg_catalog,public as $function$
 select 'sha256:'||encode(public.digest(
   convert_to('mb-release-route-recovery-token-v1:'||p_token::text,'UTF8'),'sha256'),'hex')
$function$;

create function control.release_route_recovery_decision_digest(
 p_driver_operation_id uuid,p_fleet_run_id uuid,p_claim_fence bigint,
 p_resolution_kind text,p_observation_evidence jsonb,p_candidate_response jsonb
) returns text language sql immutable set search_path=pg_catalog,public as $function$
 select 'sha256:'||encode(public.digest(convert_to(
  'mb-release-route-recovery-terminal-v1:'||p_driver_operation_id::text||':'||
  p_fleet_run_id::text||':'||p_claim_fence::text||':'||p_resolution_kind||':'||
  coalesce(p_observation_evidence::text,'null')||':'||coalesce(p_candidate_response::text,'null'),
  'UTF8'),'sha256'),'hex')
$function$;

create function control.valid_release_route_recovery_worker(
 p_driver_operation_id uuid,p_control_operation_attempt integer,
 p_control_operation_lease_owner text
) returns boolean language sql stable security definer set search_path=pg_catalog,control as $function$
 select exists(
  select 1 from control.fleet_release_route_publications publication
  join control.operations operation on operation.id=publication.control_operation_id
  where publication.driver_operation_id=p_driver_operation_id
   and p_control_operation_attempt>publication.control_operation_attempt
   and operation.kind='odoo.release.adopt' and operation.queue='release-adoption'
   and operation.workshop_id is null and operation.payload->>'phase'='adopt'
   and operation.state='in_flight' and operation.attempt=p_control_operation_attempt
   and operation.leased_by=p_control_operation_lease_owner
   and operation.lease_expires_at>now())
$function$;

create function control.discover_interrupted_immutable_release_route_publications(
 p_after_driver_operation_id uuid,p_limit integer
) returns table(driver_operation_id uuid,fleet_run_id uuid,interrupted_phase text,
 claim_mode text,claim_fence bigint,claim_available boolean,
 maintenance_selector text,candidate_selector text,updated_at timestamptz)
language sql stable security definer set search_path=pg_catalog,control as $function$
 select publication.driver_operation_id,publication.fleet_run_id,publication.interrupted_phase,
  case when publication.external_effects_started_at is not null then 'forward_only'
   when publication.interrupted_phase in ('maintenance_publication_started','maintenance_observed') then 'restore_prior'
   else 'write_cleanup' end,
  coalesce(claim.claim_fence,0),coalesce(claim.claim_expires_at<=now(),true),
  publication.maintenance_selector,publication.candidate_selector,publication.updated_at
 from control.fleet_release_route_publications publication
 left join lateral (select candidate.* from control.fleet_release_route_publication_recovery_claims candidate
   where candidate.driver_operation_id=publication.driver_operation_id
   order by candidate.claim_fence desc limit 1) claim on true
 left join control.fleet_release_route_publication_recovery_terminals terminal
  on terminal.driver_operation_id=publication.driver_operation_id
 where publication.phase='quarantined' and terminal.driver_operation_id is null
  and (p_after_driver_operation_id is null or publication.driver_operation_id>p_after_driver_operation_id)
  and p_limit between 1 and 100
 order by publication.driver_operation_id limit least(greatest(p_limit,0),100)
$function$;

create function control.claim_interrupted_immutable_release_route_publication(
 p_driver_operation_id uuid,p_control_operation_attempt integer,
 p_control_operation_lease_owner text,p_reconciliation_owner uuid,
 p_reconciliation_token uuid,p_ttl_seconds integer
) returns table(outcome text,claim_fence bigint,claim_mode text)
language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_publication control.fleet_release_route_publications%rowtype;
 v_claim control.fleet_release_route_publication_recovery_claims%rowtype;
 v_upstream control.operations%rowtype; v_global control.deployment_driver_resource_leases%rowtype;
 v_driver control.deployment_driver_operations%rowtype;
 v_expected integer; v_exact integer; v_mode text; v_expiry timestamptz; v_claim_found boolean;
begin
 if p_control_operation_attempt is null or p_control_operation_attempt<=0
  or p_control_operation_lease_owner is null or btrim(p_control_operation_lease_owner)=''
  or p_reconciliation_owner is null or p_reconciliation_token is null
  or p_ttl_seconds is null or p_ttl_seconds not between 60 and 1200 then
  return query select 'invalid',null::bigint,null::text; return;
 end if;
 select * into v_publication from control.fleet_release_route_publications
  where driver_operation_id=p_driver_operation_id;
 if not found then return query select 'not_found',null::bigint,null::text; return; end if;
 -- Canonical order: current upstream operation, protocol singleton, global, routes by UUID,
 -- driver, run/publication, then recovery ledger.
 select * into v_upstream from control.operations where id=v_publication.control_operation_id for update;
 perform 1 from control.route_set_publication_protocol_state where singleton for update;
 if not exists(select 1 from control.route_set_publication_protocol_state
   where singleton and protocol_version=1) then
  return query select 'protocol_incompatible',null::bigint,null::text; return;
 end if;
 select * into v_global from control.deployment_driver_resource_leases
  where resource_key='runtime/shared-odoo' for update;
 perform 1 from control.fleet_release_route_publication_owners owner
  join control.workshop_route_application_leases lease using(workshop_id)
  where owner.driver_operation_id=p_driver_operation_id order by owner.workshop_id for update of lease;
 select * into v_driver from control.deployment_driver_operations where id=p_driver_operation_id for update;
 perform 1 from control.release_fleet_runs where id=v_publication.fleet_run_id for update;
 select * into v_publication from control.fleet_release_route_publications
  where driver_operation_id=p_driver_operation_id for update;
 select * into v_claim from control.fleet_release_route_publication_recovery_claims
  where driver_operation_id=p_driver_operation_id order by claim_fence desc limit 1 for update;
 v_claim_found:=found;
 if exists(select 1 from control.fleet_release_route_publication_recovery_terminals
   where driver_operation_id=p_driver_operation_id) then
  return query select 'terminal',coalesce(v_claim.claim_fence,0),v_claim.claim_mode; return;
 end if;
 if v_upstream.id is null or v_upstream.kind<>'odoo.release.adopt'
  or v_upstream.queue<>'release-adoption' or v_upstream.workshop_id is not null
  or v_upstream.payload->>'phase'<>'adopt' or v_upstream.state<>'in_flight'
  or v_upstream.attempt<>p_control_operation_attempt
  or v_upstream.leased_by<>p_control_operation_lease_owner
  or v_upstream.lease_expires_at<=now()
  or p_control_operation_attempt<=v_publication.control_operation_attempt then
  return query select 'authority_lost',null::bigint,null::text; return;
 end if;
 if v_claim_found and v_claim.claim_expires_at>now() then
  if v_claim.control_operation_attempt=p_control_operation_attempt
   and v_claim.control_operation_lease_owner=p_control_operation_lease_owner
   and v_claim.reconciliation_owner=p_reconciliation_owner
   and v_claim.reconciliation_token=p_reconciliation_token then
   return query select 'replay',v_claim.claim_fence,v_claim.claim_mode; return;
  end if;
  return query select 'busy',v_claim.claim_fence,v_claim.claim_mode; return;
 end if;
 select count(*) into v_expected from control.fleet_release_route_publication_owners
  where driver_operation_id=p_driver_operation_id;
 if v_publication.phase<>'quarantined' then
  -- A recovery claimant never steals a partially-live authority set.
  select count(*) into v_exact from control.fleet_release_route_publication_owners owner
   join control.workshop_route_application_leases lease using(workshop_id)
   where owner.driver_operation_id=p_driver_operation_id and lease.state='held'
    and lease.authority_kind='release-overlay' and lease.release_publication_id=p_driver_operation_id
    and lease.fence_token=owner.route_fence_token and lease.lease_expires_at<=now();
  if v_exact<>v_expected or v_global.state<>'held' or v_global.authority_kind<>'release'
   or v_global.driver_operation_id<>p_driver_operation_id
   or v_global.lease_owner<>v_publication.original_instance_owner
   or v_global.lease_token<>v_publication.original_global_lease_token
   or v_global.fence_token<>v_publication.original_global_fence_token
   or v_global.lease_expires_at>now()
   or v_driver.state<>'in_progress' or v_driver.execution_token<>v_publication.original_execution_token
   or v_driver.lease_expires_at is null or v_driver.lease_expires_at>now() then
   return query select 'not_expired',null::bigint,null::text; return;
  end if;
  if exists(select 1 from control.fleet_release_route_publication_owners owner
    join control.workshop_route_application_leases lease using(workshop_id)
    where owner.driver_operation_id=p_driver_operation_id and
     (lease.lease_owner is distinct from v_publication.original_instance_owner
      or lease.lease_token is distinct from v_publication.original_route_lease_token
      or lease.generation is distinct from owner.generation
      or lease.projection_digest is distinct from owner.projection_digest
      or lease.fence_token is distinct from owner.route_fence_token)) then
   return query select 'authority_inconsistent',null::bigint,null::text; return;
  end if;
  if not control.quarantine_immutable_release_route_publication(p_driver_operation_id,
    v_publication.original_instance_owner,v_publication.original_execution_token,
    v_publication.original_global_lease_token,v_publication.original_route_lease_token,
    v_publication.original_global_fence_token,'release_route_publication_outcome_unknown') then
   return query select 'authority_inconsistent',null::bigint,null::text; return;
  end if;
  select * into v_publication from control.fleet_release_route_publications
   where driver_operation_id=p_driver_operation_id;
  select * into v_global from control.deployment_driver_resource_leases
   where resource_key='runtime/shared-odoo';
  select * into v_driver from control.deployment_driver_operations where id=p_driver_operation_id;
 end if;
 select count(*) into v_exact from control.fleet_release_route_publication_owners owner
  join control.workshop_route_application_leases lease using(workshop_id)
  where owner.driver_operation_id=p_driver_operation_id and lease.state='quarantined'
   and lease.authority_kind='release-overlay' and lease.release_publication_id=p_driver_operation_id
   and lease.generation=owner.generation and lease.projection_digest=owner.projection_digest
   and lease.fence_token=owner.route_fence_token
   and lease.lease_owner=v_publication.original_instance_owner
   and lease.lease_token is null and lease.lease_expires_at is null
   and lease.quarantined_at is not null
   and lease.safe_error='release_route_publication_outcome_unknown';
 if v_exact<>v_expected or v_global.state<>'quarantined' or v_global.authority_kind<>'release'
  or v_global.driver_operation_id<>p_driver_operation_id
  or v_global.lease_owner<>v_publication.original_instance_owner
  or v_global.fence_token<>v_publication.original_global_fence_token
  or v_global.lease_token is not null or v_global.lease_expires_at is not null
  or v_global.quarantined_at is null
  or v_global.safe_error<>'runtime_outcome_unknown'
  or v_driver.state<>'in_progress' or v_driver.safe_error<>'runtime_outcome_unknown'
  or v_driver.execution_token is not null or v_driver.lease_expires_at is not null then
  return query select 'authority_inconsistent',null::bigint,null::text; return;
 end if;
 v_mode:=case when v_publication.external_effects_started_at is not null then 'forward_only'
  when v_publication.interrupted_phase in ('maintenance_publication_started','maintenance_observed') then 'restore_prior'
  else 'write_cleanup' end;
 v_expiry:=least(now()+make_interval(secs=>p_ttl_seconds),v_upstream.lease_expires_at);
 insert into control.fleet_release_route_publication_recovery_claims(
  driver_operation_id,fleet_run_id,claim_fence,claim_mode,control_operation_attempt,
  control_operation_lease_owner,reconciliation_owner,reconciliation_token,claim_expires_at)
 values(p_driver_operation_id,v_publication.fleet_run_id,coalesce(v_claim.claim_fence,0)+1,
  v_mode,p_control_operation_attempt,p_control_operation_lease_owner,p_reconciliation_owner,
  p_reconciliation_token,v_expiry)
 returning * into v_claim;
 insert into control.fleet_release_route_publication_recovery_route_heads(
  driver_operation_id,claim_fence,workshop_id,applied_generation,applied_digest,
  applied_disposition,applied_rendered_digest,applied_driver_operation_id,
  applied_effect_run_id,applied_fence_token,desired_generation,desired_digest,desired_disposition)
 select p_driver_operation_id,v_claim.claim_fence,state.workshop_id,state.applied_generation,
  state.applied_digest,state.applied_disposition,state.applied_rendered_digest,
  state.applied_driver_operation_id,state.applied_effect_run_id,state.applied_fence_token,
  state.desired_generation,state.desired_digest,state.desired_disposition
 from control.fleet_release_route_publication_owners owner
 join control.workshop_route_projection_state state using(workshop_id)
 where owner.driver_operation_id=p_driver_operation_id
  and state.applied_generation=owner.generation and state.applied_digest=owner.projection_digest
  and state.applied_disposition='present'
  and state.desired_generation=owner.generation and state.desired_digest=owner.projection_digest
  and state.desired_disposition='present'
  and ((v_publication.interrupted_phase<>'awaiting_worker_finalize'
        and state.applied_rendered_digest=owner.applied_rendered_digest
        and state.applied_fence_token=owner.applied_fence_token)
    or (v_publication.interrupted_phase='awaiting_worker_finalize'
        and state.applied_driver_operation_id=p_driver_operation_id
        and state.applied_effect_run_id is null
        and state.applied_fence_token=owner.route_fence_token
        and exists(select 1 from control.fleet_release_route_publication_records record
          where record.driver_operation_id=p_driver_operation_id and record.overlay_kind='candidate'
           and record.workshop_id=owner.workshop_id
           and record.rendered_digest=state.applied_rendered_digest)));
 get diagnostics v_exact=row_count;
 if v_exact<>v_publication.snapshot_count then
  raise exception 'release recovery route-head snapshot drifted' using errcode='40001';
 end if;
 return query select 'acquired',v_claim.claim_fence,v_claim.claim_mode;
end $function$;

create function control.renew_interrupted_immutable_release_route_publication_claim(
 p_driver_operation_id uuid,p_control_operation_attempt integer,
 p_control_operation_lease_owner text,p_reconciliation_owner uuid,
 p_reconciliation_token uuid,p_claim_fence bigint,p_ttl_seconds integer
) returns boolean language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_control_operation_id uuid; v_upstream control.operations%rowtype; v_changed integer;
begin
 if p_ttl_seconds not between 60 and 1200 then return false; end if;
 select control_operation_id into v_control_operation_id from control.fleet_release_route_publications
  where driver_operation_id=p_driver_operation_id;
 if not found then return false; end if;
 select * into v_upstream from control.operations where id=v_control_operation_id for update;
 perform 1 from control.route_set_publication_protocol_state where singleton for update;
 if not control.valid_release_route_recovery_worker(p_driver_operation_id,
   p_control_operation_attempt,p_control_operation_lease_owner) then return false; end if;
 update control.fleet_release_route_publication_recovery_claims set
  claim_expires_at=least(now()+make_interval(secs=>p_ttl_seconds),v_upstream.lease_expires_at),updated_at=now()
 where driver_operation_id=p_driver_operation_id and claim_fence=p_claim_fence
  and control_operation_attempt=p_control_operation_attempt
  and control_operation_lease_owner=p_control_operation_lease_owner
  and reconciliation_owner=p_reconciliation_owner and reconciliation_token=p_reconciliation_token
  and claim_expires_at>now();
 get diagnostics v_changed=row_count; return v_changed=1;
end $function$;

create function control.read_interrupted_immutable_release_route_publication_state(
 p_driver_operation_id uuid,p_control_operation_attempt integer,
 p_control_operation_lease_owner text,p_reconciliation_owner uuid,
 p_reconciliation_token uuid,p_claim_fence bigint
) returns table(outcome text,state jsonb)
language sql stable security definer set search_path=pg_catalog,control as $function$
 select case when publication.driver_operation_id is null then 'not_found'
  when terminal.driver_operation_id is not null then 'terminal'
  when claim.driver_operation_id is null or claim.claim_fence is distinct from p_claim_fence
   or claim.control_operation_attempt is distinct from p_control_operation_attempt
   or claim.control_operation_lease_owner is distinct from p_control_operation_lease_owner
   or claim.reconciliation_owner is distinct from p_reconciliation_owner
   or claim.reconciliation_token is distinct from p_reconciliation_token or claim.claim_expires_at<=now()
   or not control.valid_release_route_recovery_worker(p_driver_operation_id,
       p_control_operation_attempt,p_control_operation_lease_owner) then 'claim_lost' else 'claimed' end,
  case when publication.driver_operation_id is null then null else jsonb_build_object(
   'driver_operation_id',publication.driver_operation_id,'fleet_run_id',publication.fleet_run_id,
   'claim_fence',claim.claim_fence,'claim_mode',claim.claim_mode,
   'interrupted_phase',publication.interrupted_phase,'target_slot',publication.target_slot,
   'original_global_fence_token',publication.original_global_fence_token,
   'snapshot_count',publication.snapshot_count,'prior_selector',publication.prior_selector,
   'prior_directory_device',publication.prior_directory_device,
   'prior_directory_inode',publication.prior_directory_inode,
   'prior_loaded_identity',publication.prior_loaded_identity,
   'maintenance_selector',publication.maintenance_selector,
   'maintenance_route_set_digest',publication.maintenance_route_set_digest,
   'maintenance_directory_device',publication.maintenance_directory_device,
   'maintenance_directory_inode',publication.maintenance_directory_inode,
   'candidate_selector',publication.candidate_selector,
   'candidate_route_set_digest',publication.candidate_route_set_digest,
   'candidate_directory_device',publication.candidate_directory_device,
   'candidate_directory_inode',publication.candidate_directory_inode,
   'external_effects_started_at',publication.external_effects_started_at) end
 from (values(1)) singleton(value)
 left join control.fleet_release_route_publications publication
  on publication.driver_operation_id=p_driver_operation_id
 left join control.fleet_release_route_publication_recovery_claims claim
  on claim.driver_operation_id=publication.driver_operation_id and claim.claim_fence=p_claim_fence
 left join control.fleet_release_route_publication_recovery_terminals terminal
  on terminal.driver_operation_id=publication.driver_operation_id
$function$;

-- Shared by the original 0036 finalizer and recovery before candidate
-- publication is authorized.  It is intentionally read-only: callers still
-- recheck every mutable row under the canonical close locks.
create function control.valid_immutable_release_route_completion_response(
 p_driver_operation_id uuid,p_response jsonb
) returns boolean language plpgsql stable security definer set search_path=pg_catalog,control as $function$
declare v_publication control.fleet_release_route_publications%rowtype;
 v_run control.release_fleet_runs%rowtype; v_release control.application_releases%rowtype;
 v_intent control.fleet_activation_intents%rowtype; v_evidence jsonb; v_expected_prepared jsonb;
begin
 if jsonb_typeof(p_response) is distinct from 'object' or p_response-array['evidence']<>'{}'::jsonb
  or not (p_response ?& array['evidence']) or jsonb_typeof(p_response->'evidence') is distinct from 'object'
  or pg_column_size(p_response)>1048576 then return false; end if;
 v_evidence:=p_response->'evidence';
 if (select count(*) from jsonb_object_keys(v_evidence))<>30
  or not (v_evidence ?& array['release_id','odoo_subject_digest','extension_subject_digest',
   'odoo_manifest_digest','odoo_config_digest','extension_manifest_digest','extension_config_digest',
   'payload_digest','extension_volume','pair_qualification_digest','bridge_contract_digest',
   'installed_addon_versions','runtime_key','target_slot','runtime_container','runtime_role',
   'runtime_deployment_ref','runtime_config_digest','prepared_tenants','fleet_generation',
   'tenant_snapshot','gateway_configuration_digest','driver_action_id','driver_operation_id',
   'driver_fence_token','old_runtime_database_access_revoked','tenant_recovery_verified',
   'candidate_smoke_verified','candidate_restart_policy','retained_restart_policy']) then return false; end if;
 if exists(select 1 from unnest(array['release_id','odoo_subject_digest','extension_subject_digest',
   'odoo_manifest_digest','odoo_config_digest','extension_manifest_digest','extension_config_digest',
   'payload_digest','extension_volume','pair_qualification_digest','bridge_contract_digest','runtime_key',
   'target_slot','runtime_container','runtime_role','runtime_deployment_ref','runtime_config_digest',
   'gateway_configuration_digest','candidate_restart_policy','retained_restart_policy']) key
   where jsonb_typeof(v_evidence->key) is distinct from 'string')
  or jsonb_typeof(v_evidence->'fleet_generation') is distinct from 'number'
  or jsonb_typeof(v_evidence->'driver_action_id') is distinct from 'string'
  or jsonb_typeof(v_evidence->'driver_operation_id') is distinct from 'string'
  or jsonb_typeof(v_evidence->'driver_fence_token') is distinct from 'number'
  or jsonb_typeof(v_evidence->'installed_addon_versions') is distinct from 'object'
  or jsonb_typeof(v_evidence->'prepared_tenants') is distinct from 'array'
  or jsonb_typeof(v_evidence->'tenant_snapshot') is distinct from 'array' then return false; end if;
 select * into v_publication from control.fleet_release_route_publications
  where driver_operation_id=p_driver_operation_id;
 if not found then return false; end if;
 select * into v_run from control.release_fleet_runs where id=v_publication.fleet_run_id;
 select * into v_release from control.application_releases where id=v_run.release_id;
 select * into v_intent from control.fleet_activation_intents where fleet_run_id=v_run.id
  and release_id=v_run.release_id and runtime_key='shared-odoo' and target_slot=v_publication.target_slot
  and driver_fence_token=v_publication.original_global_fence_token
  and gateway_identity_version=1 and abandoned_at is null;
 if not found or v_intent.observed_configuration_digest is distinct from v_intent.gateway_configuration_digest
  or v_intent.activated_at is null then return false; end if;
 select coalesce(jsonb_agg(jsonb_build_object('adoption_id',adoption.id,
   'workshop_id',adoption.workshop_id,'database_id',adoption.database_id,
   'database_ref',database.database_ref,'public_hostname',database.public_hostname)
   order by adoption.created_at,adoption.id),'[]'::jsonb) into v_expected_prepared
 from control.tenant_release_adoptions adoption join control.odoo_databases database
  on database.id=adoption.database_id and database.workshop_id=adoption.workshop_id
 where adoption.operation_id=v_publication.control_operation_id and adoption.release_id=v_run.release_id
  and adoption.state='prepared';
 return coalesce((v_intent.prepared_tenants is not distinct from v_expected_prepared
  and jsonb_array_length(v_expected_prepared)=jsonb_array_length(v_run.tenant_snapshot)
  and jsonb_array_length(v_expected_prepared) between 1 and 500
  and v_release.id=v_run.release_id
  and v_release.odoo_subject_digest=v_intent.odoo_subject_digest
  and v_release.extension_subject_digest=v_intent.extension_subject_digest
  and v_evidence->>'release_id'=v_run.release_id
  and v_evidence->>'runtime_key'='shared-odoo'
  and v_evidence->>'target_slot'=v_publication.target_slot
  and v_evidence->>'odoo_subject_digest'=v_intent.odoo_subject_digest
  and v_evidence->>'extension_subject_digest'=v_intent.extension_subject_digest
  and v_evidence->>'pair_qualification_digest'=v_intent.pair_qualification_digest
  and v_evidence->'prepared_tenants'=v_expected_prepared
  and v_evidence->'tenant_snapshot'=v_run.tenant_snapshot
  and v_evidence->'fleet_generation'=to_jsonb(v_run.fleet_generation)
  and v_evidence->>'gateway_configuration_digest'=v_intent.gateway_configuration_digest
  and v_evidence->'driver_action_id'=to_jsonb(v_intent.driver_action_id)
  and v_evidence->'driver_operation_id'=to_jsonb(p_driver_operation_id)
  and v_evidence->'driver_fence_token'=to_jsonb(v_publication.original_global_fence_token)
  and v_evidence->'old_runtime_database_access_revoked'='true'::jsonb
  and v_evidence->'tenant_recovery_verified'='true'::jsonb
  and v_evidence->'candidate_smoke_verified'='true'::jsonb
  and v_evidence->>'candidate_restart_policy'='unless-stopped'
  and v_evidence->>'retained_restart_policy'='no'
  and (v_evidence->>'odoo_manifest_digest' ~ '^sha256:[0-9a-f]{64}$')
  and (v_evidence->>'odoo_config_digest' ~ '^sha256:[0-9a-f]{64}$')
  and (v_evidence->>'extension_manifest_digest' ~ '^sha256:[0-9a-f]{64}$')
  and (v_evidence->>'extension_config_digest' ~ '^sha256:[0-9a-f]{64}$')
  and (v_evidence->>'payload_digest' ~ '^sha256:[0-9a-f]{64}$')
  and (v_evidence->>'bridge_contract_digest' ~ '^sha256:[0-9a-f]{64}$')
  and (v_evidence->>'runtime_config_digest' ~ '^sha256:[0-9a-f]{64}$')
  and (v_evidence->>'extension_volume' ~ ('^mb-(control-|dev[1-4]-)?ext-'||
    substr(v_evidence->>'extension_manifest_digest',8,16)||'-'||
    substr(v_evidence->>'payload_digest',8,16)||'$'))
  and (v_evidence->>'runtime_container' ~
    ('^[a-z0-9][a-z0-9-]{0,110}-odoo-'||v_publication.target_slot||'$'))
  and v_evidence->>'runtime_role'='mb_runtime_'||substr(v_intent.odoo_subject_digest,8,16)
  and v_evidence->>'runtime_deployment_ref'=v_release.manifest->'odoo_runtime'->>'deployment_ref'),false);
end $function$;

create function control.lock_immutable_release_route_recovery_claim(
 p_driver_operation_id uuid,p_control_operation_attempt integer,
 p_control_operation_lease_owner text,p_reconciliation_owner uuid,
 p_reconciliation_token uuid,p_claim_fence bigint
) returns boolean language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_control_operation_id uuid; v_fleet_run_id uuid; v_release_id text;
begin
 select control_operation_id,fleet_run_id into v_control_operation_id,v_fleet_run_id
  from control.fleet_release_route_publications
  where driver_operation_id=p_driver_operation_id;
 if not found then return false; end if;
 perform 1 from control.operations where id=v_control_operation_id for update;
 perform 1 from control.route_set_publication_protocol_state where singleton for update;
 perform 1 from control.deployment_driver_resource_leases where resource_key='runtime/shared-odoo' for update;
 perform 1 from control.fleet_release_route_publication_owners owner
  join control.workshop_route_application_leases lease using(workshop_id)
  where owner.driver_operation_id=p_driver_operation_id order by owner.workshop_id for update of lease;
 perform 1 from control.deployment_driver_operations where id=p_driver_operation_id for update;
 select run.release_id into v_release_id from control.release_fleet_runs run where run.id=v_fleet_run_id;
 perform 1 from control.application_releases where id=v_release_id for update;
 perform 1 from control.release_fleet_runs where id=v_fleet_run_id for update;
 perform 1 from control.fleet_activation_intents where fleet_run_id=v_fleet_run_id for update;
 perform 1 from control.tenant_release_adoptions adoption
  where adoption.operation_id=v_control_operation_id and adoption.release_id=v_release_id
  order by adoption.created_at,adoption.id for update;
 perform 1 from control.fleet_release_route_publications where driver_operation_id=p_driver_operation_id for update;
 perform 1 from control.fleet_release_route_publication_recovery_claims
  where driver_operation_id=p_driver_operation_id and claim_fence=p_claim_fence for update;
 return control.valid_release_route_recovery_worker(p_driver_operation_id,
   p_control_operation_attempt,p_control_operation_lease_owner)
  and exists(select 1 from control.fleet_release_route_publication_recovery_claims claim
   where claim.driver_operation_id=p_driver_operation_id and claim.claim_fence=p_claim_fence
    and claim.control_operation_attempt=p_control_operation_attempt
    and claim.control_operation_lease_owner=p_control_operation_lease_owner
    and claim.reconciliation_owner=p_reconciliation_owner
    and claim.reconciliation_token=p_reconciliation_token and claim.claim_expires_at>now());
end $function$;

create function control.record_interrupted_immutable_release_route_candidate_entry(
 p_driver_operation_id uuid,p_control_operation_attempt integer,p_control_operation_lease_owner text,
 p_reconciliation_owner uuid,p_reconciliation_token uuid,p_claim_fence bigint,
 p_workshop_id uuid,p_generation bigint,p_projection_digest text,
 p_applied_rendered_digest text,p_rendered_digest text
) returns text language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_publication control.fleet_release_route_publications%rowtype; v_existing record; v_expected uuid;
begin
 if not control.lock_immutable_release_route_recovery_claim(p_driver_operation_id,p_control_operation_attempt,
  p_control_operation_lease_owner,p_reconciliation_owner,p_reconciliation_token,p_claim_fence) then return 'claim_lost'; end if;
 select * into v_publication from control.fleet_release_route_publications where driver_operation_id=p_driver_operation_id;
 if v_publication.phase<>'quarantined' or v_publication.interrupted_phase<>'candidate_staging'
  or v_publication.external_effects_started_at is null then return 'wrong_phase'; end if;
 select generation,projection_digest,applied_rendered_digest,rendered_digest into v_existing
  from control.fleet_release_route_publication_recovery_candidate_records
  where driver_operation_id=p_driver_operation_id and claim_fence=p_claim_fence
   and workshop_id=p_workshop_id;
 if found then return case when v_existing.generation=p_generation and v_existing.projection_digest=p_projection_digest
  and v_existing.applied_rendered_digest=p_applied_rendered_digest and v_existing.rendered_digest=p_rendered_digest
  then 'replay' else 'conflict' end; end if;
 select owner.workshop_id into v_expected from control.fleet_release_route_publication_owners owner
  where owner.driver_operation_id=p_driver_operation_id and not exists(select 1
   from control.fleet_release_route_publication_recovery_candidate_records record
   where record.driver_operation_id=owner.driver_operation_id and record.claim_fence=p_claim_fence
    and record.workshop_id=owner.workshop_id)
  order by owner.workshop_id limit 1;
 if v_expected is distinct from p_workshop_id then return 'out_of_order'; end if;
 if not exists(select 1 from control.fleet_release_route_publication_owners owner
   where owner.driver_operation_id=p_driver_operation_id and owner.workshop_id=p_workshop_id
    and owner.generation=p_generation and owner.projection_digest=p_projection_digest
    and owner.applied_rendered_digest=p_applied_rendered_digest) then return 'snapshot_drift'; end if;
 insert into control.fleet_release_route_publication_recovery_candidate_records(
  driver_operation_id,claim_fence,workshop_id,generation,projection_digest,
  applied_rendered_digest,rendered_digest)
 values(p_driver_operation_id,p_claim_fence,p_workshop_id,p_generation,p_projection_digest,
  p_applied_rendered_digest,p_rendered_digest);
 return 'recorded';
end $function$;

create function control.seal_interrupted_immutable_release_route_candidate(
 p_driver_operation_id uuid,p_control_operation_attempt integer,p_control_operation_lease_owner text,
 p_reconciliation_owner uuid,p_reconciliation_token uuid,p_claim_fence bigint,
 p_selector text,p_directory_device bigint,p_directory_inode bigint,
 p_record_count integer,p_route_set_digest text
) returns text language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_publication control.fleet_release_route_publications%rowtype; v_digest text; v_existing record; v_count integer;
begin
 if not control.lock_immutable_release_route_recovery_claim(p_driver_operation_id,p_control_operation_attempt,
  p_control_operation_lease_owner,p_reconciliation_owner,p_reconciliation_token,p_claim_fence) then return 'claim_lost'; end if;
 select * into v_publication from control.fleet_release_route_publications where driver_operation_id=p_driver_operation_id;
 if v_publication.phase<>'quarantined' or v_publication.interrupted_phase<>'candidate_staging'
  or v_publication.external_effects_started_at is null then return 'wrong_phase'; end if;
 select selector,directory_device,directory_inode,record_count,route_set_digest into v_existing
  from control.fleet_release_route_publication_recovery_candidate_seals
  where driver_operation_id=p_driver_operation_id and claim_fence=p_claim_fence;
 if found then return case when v_existing.record_count=p_record_count and v_existing.selector=p_selector
  and v_existing.directory_device=p_directory_device and v_existing.directory_inode=p_directory_inode
  and v_existing.route_set_digest=p_route_set_digest then 'replay' else 'conflict' end; end if;
 if p_selector<>v_publication.candidate_selector or p_directory_device<=0 or p_directory_inode<=0
  or p_record_count<>v_publication.snapshot_count then return 'invalid'; end if;
 select count(*),'sha256:'||encode(public.digest(
   convert_to('mb-release-route-overlay-v1','UTF8')||decode('00','hex')||
   coalesce(decode(string_agg(encode(control.release_route_overlay_record_bytes(
    record.workshop_id,record.generation,record.projection_digest,
    record.applied_rendered_digest,record.rendered_digest),'hex'),'' order by record.workshop_id),'hex'),''::bytea),
   'sha256'),'hex') into v_count,v_digest
 from control.fleet_release_route_publication_recovery_candidate_records record
 where record.driver_operation_id=p_driver_operation_id and record.claim_fence=p_claim_fence;
 if v_count<>p_record_count then return 'count_mismatch'; end if;
 if v_digest is distinct from p_route_set_digest then return 'digest_mismatch'; end if;
 insert into control.fleet_release_route_publication_recovery_candidate_seals(
  driver_operation_id,claim_fence,selector,directory_device,directory_inode,record_count,route_set_digest)
 values(p_driver_operation_id,p_claim_fence,p_selector,p_directory_device,p_directory_inode,
  p_record_count,p_route_set_digest); return 'sealed';
end $function$;

create function control.authorize_interrupted_immutable_release_route_exchange(
 p_driver_operation_id uuid,p_control_operation_attempt integer,p_control_operation_lease_owner text,
 p_reconciliation_owner uuid,p_reconciliation_token uuid,p_claim_fence bigint,
 p_authorization_kind text,p_overlay_kind text,p_response jsonb
) returns text language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_publication control.fleet_release_route_publications%rowtype; v_claim_mode text; v_existing record;
begin
 if not control.lock_immutable_release_route_recovery_claim(p_driver_operation_id,p_control_operation_attempt,
  p_control_operation_lease_owner,p_reconciliation_owner,p_reconciliation_token,p_claim_fence) then return 'claim_lost'; end if;
 select * into v_publication from control.fleet_release_route_publications where driver_operation_id=p_driver_operation_id;
 select claim_mode into v_claim_mode from control.fleet_release_route_publication_recovery_claims
  where driver_operation_id=p_driver_operation_id and claim_fence=p_claim_fence;
 select authorization_kind,overlay_kind,response into v_existing from control.fleet_release_route_publication_recovery_authorizations
  where driver_operation_id=p_driver_operation_id and claim_fence=p_claim_fence
   and authorization_kind=p_authorization_kind;
 if found then return case when v_existing.overlay_kind is not distinct from p_overlay_kind
  and v_existing.response is not distinct from p_response then 'replay' else 'conflict' end; end if;
 if p_authorization_kind='dispose_overlay' then
  if v_claim_mode<>'write_cleanup' or p_response is not null
   or p_overlay_kind<>'maintenance'
   or v_publication.interrupted_phase not in ('maintenance_staging','maintenance_sealed')
   then return 'invalid'; end if;
  insert into control.fleet_release_route_publication_recovery_authorizations(
   driver_operation_id,claim_fence,authorization_kind,overlay_kind)
  values(p_driver_operation_id,p_claim_fence,'dispose_overlay',p_overlay_kind);
  return 'authorized';
 elsif p_authorization_kind='restore_prior' then
  if v_claim_mode<>'restore_prior' or v_publication.external_effects_started_at is not null
   or v_publication.prior_recorded_at is null or p_overlay_kind is not null
   or p_response is not null then return 'invalid'; end if;
  insert into control.fleet_release_route_publication_recovery_authorizations(
   driver_operation_id,claim_fence,authorization_kind) values(p_driver_operation_id,p_claim_fence,'restore_prior');
  return 'authorized';
 elsif p_authorization_kind='publish_candidate' then
  if v_claim_mode<>'forward_only' or p_overlay_kind is distinct from 'candidate'
   or v_publication.external_effects_started_at is null
   or v_publication.interrupted_phase not in ('candidate_staging','candidate_sealed','candidate_publication_started','awaiting_worker_finalize')
   or (v_publication.interrupted_phase='candidate_staging' and not exists(select 1
      from control.fleet_release_route_publication_recovery_candidate_seals seal
      where seal.driver_operation_id=p_driver_operation_id and seal.claim_fence=p_claim_fence
       and seal.record_count=v_publication.snapshot_count))
   or (v_publication.interrupted_phase<>'candidate_staging'
      and v_publication.candidate_sealed_count<>v_publication.snapshot_count)
   or not control.valid_immutable_release_route_completion_response(p_driver_operation_id,p_response) then return 'invalid'; end if;
  insert into control.fleet_release_route_publication_recovery_authorizations(
   driver_operation_id,claim_fence,authorization_kind,overlay_kind,response)
  values(p_driver_operation_id,p_claim_fence,'publish_candidate','candidate',p_response);
  return 'authorized';
 end if;
 return 'invalid';
end $function$;

create function control.resolve_interrupted_immutable_release_route_publication(
 p_driver_operation_id uuid,p_control_operation_attempt integer,p_control_operation_lease_owner text,
 p_reconciliation_owner uuid,p_reconciliation_token uuid,p_claim_fence bigint,
 p_resolution_kind text,p_observation_evidence jsonb,p_candidate_response jsonb
) returns text language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_publication control.fleet_release_route_publications%rowtype;
 v_claim control.fleet_release_route_publication_recovery_claims%rowtype;
 v_existing control.fleet_release_route_publication_recovery_resolutions%rowtype;
 v_seal control.fleet_release_route_publication_recovery_candidate_seals%rowtype;
 v_selector text; v_device bigint; v_inode bigint; v_identity jsonb; v_exact integer;
begin
 if p_resolution_kind is null or p_resolution_kind not in ('candidate','prior','unstarted','inconclusive')
  or jsonb_typeof(p_observation_evidence) is distinct from 'object'
  or pg_column_size(p_observation_evidence)>16384
  or (select count(*) from jsonb_object_keys(p_observation_evidence))<>11
  or not (p_observation_evidence ?& array['protocol_version','driver_operation_id','fleet_run_id',
   'claim_fence','resolution_kind','observed_selector','observed_directory_device',
   'observed_directory_inode','observed_loaded_identity','maintenance_artifact','candidate_artifact'])
  or jsonb_typeof(p_observation_evidence->'protocol_version') is distinct from 'number'
  or jsonb_typeof(p_observation_evidence->'driver_operation_id') is distinct from 'string'
  or jsonb_typeof(p_observation_evidence->'fleet_run_id') is distinct from 'string'
  or jsonb_typeof(p_observation_evidence->'claim_fence') is distinct from 'number'
  or jsonb_typeof(p_observation_evidence->'resolution_kind') is distinct from 'string'
  or jsonb_typeof(p_observation_evidence->'observed_selector') not in ('string','null')
  or jsonb_typeof(p_observation_evidence->'observed_directory_device') not in ('number','null')
  or jsonb_typeof(p_observation_evidence->'observed_directory_inode') not in ('number','null')
  or jsonb_typeof(p_observation_evidence->'observed_loaded_identity') not in ('object','null')
  or jsonb_typeof(p_observation_evidence->'maintenance_artifact') not in ('object','null')
  or jsonb_typeof(p_observation_evidence->'candidate_artifact') not in ('object','null')
  or p_observation_evidence->'protocol_version'<>'1'::jsonb
  or p_observation_evidence->'driver_operation_id'<>to_jsonb(p_driver_operation_id)
  or p_observation_evidence->'claim_fence'<>to_jsonb(p_claim_fence)
  or p_observation_evidence->>'resolution_kind'<>p_resolution_kind then return 'invalid'; end if;
 if not control.lock_immutable_release_route_recovery_claim(p_driver_operation_id,p_control_operation_attempt,
  p_control_operation_lease_owner,p_reconciliation_owner,p_reconciliation_token,p_claim_fence) then return 'claim_lost'; end if;
 select * into v_publication from control.fleet_release_route_publications where driver_operation_id=p_driver_operation_id;
 select * into v_claim from control.fleet_release_route_publication_recovery_claims
  where driver_operation_id=p_driver_operation_id and claim_fence=p_claim_fence;
 if p_observation_evidence->'fleet_run_id'<>to_jsonb(v_publication.fleet_run_id) then return 'invalid'; end if;
 select * into v_existing from control.fleet_release_route_publication_recovery_resolutions
  where driver_operation_id=p_driver_operation_id and claim_fence=p_claim_fence;
 if found then return case when v_existing.resolution_kind=p_resolution_kind
  and v_existing.observation_evidence=p_observation_evidence
  and v_existing.candidate_response is not distinct from p_candidate_response
  then 'replay' else 'conflict' end; end if;
 v_selector:=p_observation_evidence->>'observed_selector';
 v_device:=(p_observation_evidence->>'observed_directory_device')::bigint;
 v_inode:=(p_observation_evidence->>'observed_directory_inode')::bigint;
 v_identity:=p_observation_evidence->'observed_loaded_identity';
 if v_identity='null'::jsonb then v_identity:=null; end if;
 if p_resolution_kind='candidate' then
  if v_publication.interrupted_phase='candidate_staging' then
   select * into v_seal from control.fleet_release_route_publication_recovery_candidate_seals
    where driver_operation_id=p_driver_operation_id and claim_fence=p_claim_fence;
   if not found then return 'observation_mismatch'; end if;
  else
   v_seal.selector:=v_publication.candidate_selector;
   v_seal.directory_device:=v_publication.candidate_directory_device;
   v_seal.directory_inode:=v_publication.candidate_directory_inode;
   v_seal.route_set_digest:=v_publication.candidate_route_set_digest;
   v_seal.record_count:=v_publication.candidate_sealed_count;
  end if;
  if v_claim.claim_mode<>'forward_only' or v_publication.external_effects_started_at is null
   or v_publication.interrupted_phase not in ('candidate_staging','candidate_sealed','candidate_publication_started','awaiting_worker_finalize')
   or v_seal.record_count<>v_publication.snapshot_count
   or v_selector<>v_seal.selector
   or v_device is distinct from v_seal.directory_device
   or v_inode is distinct from v_seal.directory_inode
   or not control.valid_release_route_loaded_identity(v_identity)
   or v_identity<>jsonb_build_object('protocol_version',1,'fleet_run_id',v_publication.fleet_run_id,
     'driver_operation_id',p_driver_operation_id,
     'original_global_fence_token',v_publication.original_global_fence_token,
     'overlay_kind','candidate','route_set_digest',v_seal.route_set_digest,
     'target_slot',v_publication.target_slot)
   or not exists(select 1 from control.fleet_release_route_publication_recovery_authorizations recovery_authorization
     where recovery_authorization.driver_operation_id=p_driver_operation_id and recovery_authorization.claim_fence=p_claim_fence
      and recovery_authorization.authorization_kind='publish_candidate' and recovery_authorization.response=p_candidate_response)
   or not control.valid_immutable_release_route_completion_response(p_driver_operation_id,p_candidate_response)
   then return 'observation_mismatch'; end if;
  if p_observation_evidence->'maintenance_artifact' is distinct from jsonb_build_object(
    'selector',v_publication.maintenance_selector,
    'directory_device',v_publication.maintenance_directory_device,
    'directory_inode',v_publication.maintenance_directory_inode,
    'loaded_identity',jsonb_build_object('protocol_version',1,'fleet_run_id',v_publication.fleet_run_id,
      'driver_operation_id',p_driver_operation_id,
      'original_global_fence_token',v_publication.original_global_fence_token,
      'overlay_kind','maintenance','route_set_digest',v_publication.maintenance_route_set_digest,
      'target_slot',v_publication.target_slot),'publication_started',true)
   or p_observation_evidence->'candidate_artifact' is distinct from jsonb_build_object(
    'selector',v_seal.selector,'directory_device',v_seal.directory_device,
    'directory_inode',v_seal.directory_inode,'loaded_identity',v_identity,
    'publication_started',true) then return 'observation_mismatch'; end if;
 elsif p_resolution_kind='prior' then
  if v_claim.claim_mode not in ('write_cleanup','restore_prior')
   or v_publication.external_effects_started_at is not null or v_publication.prior_recorded_at is null
   or v_selector is distinct from v_publication.prior_selector
   or v_device is distinct from v_publication.prior_directory_device
   or v_inode is distinct from v_publication.prior_directory_inode
   or v_identity is distinct from v_publication.prior_loaded_identity
   or not control.valid_route_set_prior_selector_identity(v_selector,v_identity)
   or (v_claim.claim_mode='restore_prior' and not exists(select 1
     from control.fleet_release_route_publication_recovery_authorizations recovery_authorization
     where recovery_authorization.driver_operation_id=p_driver_operation_id and recovery_authorization.claim_fence=p_claim_fence
      and recovery_authorization.authorization_kind='restore_prior')) then return 'observation_mismatch'; end if;
 elsif p_resolution_kind='unstarted' then
  if v_claim.claim_mode<>'write_cleanup' or v_publication.interrupted_phase<>'maintenance_staging'
   or v_publication.prior_recorded_at is not null or v_publication.maintenance_count<>0
   or v_publication.maintenance_sealed_count is not null
   or v_publication.maintenance_publication_started_at is not null
   or v_publication.external_effects_started_at is not null or v_publication.candidate_count<>0
   or v_publication.candidate_sealed_count is not null or v_publication.candidate_publication_started_at is not null
   or v_selector in (v_publication.maintenance_selector,v_publication.candidate_selector)
   or v_device is null or v_device<=0 or v_inode is null or v_inode<=0
   or not control.valid_route_set_prior_selector_identity(v_selector,v_identity) then return 'observation_mismatch'; end if;
 elsif p_candidate_response is not null then return 'invalid'; end if;
 if p_resolution_kind in ('prior','unstarted') then
  if v_claim.claim_mode='write_cleanup' and
    (p_observation_evidence->'maintenance_artifact'<>'null'::jsonb
      or p_observation_evidence->'candidate_artifact'<>'null'::jsonb
      or not exists(select 1 from control.fleet_release_route_publication_recovery_authorizations recovery_authorization
       where recovery_authorization.driver_operation_id=p_driver_operation_id
        and recovery_authorization.claim_fence=p_claim_fence
        and recovery_authorization.authorization_kind='dispose_overlay'
        and recovery_authorization.overlay_kind='maintenance')) then return 'observation_mismatch';
  elsif v_claim.claim_mode='restore_prior' and
    (p_observation_evidence->'candidate_artifact'<>'null'::jsonb
      or p_observation_evidence->'maintenance_artifact' is distinct from jsonb_build_object(
       'selector',v_publication.maintenance_selector,
       'directory_device',v_publication.maintenance_directory_device,
       'directory_inode',v_publication.maintenance_directory_inode,
       'loaded_identity',jsonb_build_object('protocol_version',1,'fleet_run_id',v_publication.fleet_run_id,
        'driver_operation_id',p_driver_operation_id,
        'original_global_fence_token',v_publication.original_global_fence_token,
        'overlay_kind','maintenance','route_set_digest',v_publication.maintenance_route_set_digest,
        'target_slot',v_publication.target_slot),'publication_started',true)) then return 'observation_mismatch';
  end if;
 end if;
 -- Pre-external decisions are valid only while every frozen head is unchanged.
 if p_resolution_kind in ('prior','unstarted') then
  select count(*) into v_exact from control.fleet_release_route_publication_owners owner
   join control.fleet_release_route_publication_recovery_route_heads head
    on head.driver_operation_id=owner.driver_operation_id and head.workshop_id=owner.workshop_id
     and head.claim_fence=p_claim_fence
   join control.workshop_route_projection_state state using(workshop_id)
   where owner.driver_operation_id=p_driver_operation_id
    and head.applied_rendered_digest=owner.applied_rendered_digest
    and head.applied_fence_token=owner.applied_fence_token
    and state.applied_generation=head.applied_generation and state.applied_digest=head.applied_digest
    and state.applied_disposition=head.applied_disposition
    and state.applied_rendered_digest=head.applied_rendered_digest
    and state.applied_driver_operation_id is not distinct from head.applied_driver_operation_id
    and state.applied_effect_run_id is not distinct from head.applied_effect_run_id
    and state.applied_fence_token=head.applied_fence_token
    and state.desired_generation=head.desired_generation and state.desired_digest=head.desired_digest
    and state.desired_disposition=head.desired_disposition;
  if v_exact<>v_publication.snapshot_count then return 'snapshot_drift'; end if;
 end if;
 insert into control.fleet_release_route_publication_recovery_resolutions(
  driver_operation_id,fleet_run_id,claim_fence,control_operation_attempt,
  control_operation_lease_owner,reconciliation_owner,reconciliation_token_digest,
  claim_mode,resolution_kind,observation_evidence,candidate_response)
 values(p_driver_operation_id,v_publication.fleet_run_id,p_claim_fence,p_control_operation_attempt,
  p_control_operation_lease_owner,p_reconciliation_owner,
  control.release_route_recovery_token_digest(p_reconciliation_token),v_claim.claim_mode,
  p_resolution_kind,p_observation_evidence,p_candidate_response);
 return 'recorded';
exception when invalid_text_representation or numeric_value_out_of_range then return 'invalid';
end $function$;

create function control.finish_interrupted_immutable_release_route_publication(
 p_driver_operation_id uuid,p_control_operation_attempt integer,p_control_operation_lease_owner text,
 p_reconciliation_owner uuid,p_reconciliation_token uuid,p_claim_fence bigint,
 p_resolution_kind text,p_decision_digest text
) returns table(outcome text,stored_response jsonb)
language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_publication control.fleet_release_route_publications%rowtype;
 v_resolution control.fleet_release_route_publication_recovery_resolutions%rowtype;
 v_terminal control.fleet_release_route_publication_recovery_terminals%rowtype;
 v_seal control.fleet_release_route_publication_recovery_candidate_seals%rowtype;
 v_response jsonb; v_expected_digest text; v_exact integer; v_changed integer;
begin
 select terminal.* into v_terminal
 from control.fleet_release_route_publication_recovery_terminals terminal
 join control.fleet_release_route_publication_recovery_resolutions resolution
  on resolution.driver_operation_id=terminal.driver_operation_id
   and resolution.claim_fence=terminal.claim_fence
 where terminal.driver_operation_id=p_driver_operation_id
  and terminal.claim_fence=p_claim_fence
  and terminal.control_operation_attempt=p_control_operation_attempt
  and terminal.control_operation_lease_owner=p_control_operation_lease_owner
  and terminal.reconciliation_owner=p_reconciliation_owner
  and resolution.reconciliation_token_digest=
    control.release_route_recovery_token_digest(p_reconciliation_token);
 if found then
  if v_terminal.resolution_kind=p_resolution_kind
   and v_terminal.decision_digest=p_decision_digest then
   return query select 'replay',v_terminal.response; return;
  end if;
  return query select 'conflict',null::jsonb; return;
 end if;
 if not control.lock_immutable_release_route_recovery_claim(p_driver_operation_id,p_control_operation_attempt,
  p_control_operation_lease_owner,p_reconciliation_owner,p_reconciliation_token,p_claim_fence) then
  return query select 'claim_lost',null::jsonb; return; end if;
 select * into v_publication from control.fleet_release_route_publications where driver_operation_id=p_driver_operation_id;
 select * into v_resolution from control.fleet_release_route_publication_recovery_resolutions
  where driver_operation_id=p_driver_operation_id and claim_fence=p_claim_fence;
 if not found or v_resolution.resolution_kind<>p_resolution_kind
  or v_resolution.control_operation_attempt<>p_control_operation_attempt
  or v_resolution.control_operation_lease_owner<>p_control_operation_lease_owner
  or v_resolution.reconciliation_owner<>p_reconciliation_owner
  or v_resolution.reconciliation_token_digest<>control.release_route_recovery_token_digest(p_reconciliation_token)
  then return query select 'resolution_absent',null::jsonb; return; end if;
 if p_resolution_kind='inconclusive' then return query select 'blocked',null::jsonb; return; end if;
 v_expected_digest:=control.release_route_recovery_decision_digest(p_driver_operation_id,
  v_publication.fleet_run_id,p_claim_fence,p_resolution_kind,
  v_resolution.observation_evidence,v_resolution.candidate_response);
 if p_decision_digest is distinct from v_expected_digest then
  return query select 'decision_mismatch',null::jsonb; return; end if;
 if p_resolution_kind='candidate' then
  if not control.valid_immutable_release_route_completion_response(p_driver_operation_id,
    v_resolution.candidate_response) then return query select 'state_drift',null::jsonb; return; end if;
  select count(*) into v_exact
  from control.fleet_release_route_publication_recovery_route_heads head
  join control.workshop_route_projection_state state using(workshop_id)
  where head.driver_operation_id=p_driver_operation_id and head.claim_fence=p_claim_fence
   and state.applied_generation=head.applied_generation and state.applied_digest=head.applied_digest
   and state.applied_disposition=head.applied_disposition
   and state.applied_rendered_digest=head.applied_rendered_digest
   and state.applied_driver_operation_id is not distinct from head.applied_driver_operation_id
   and state.applied_effect_run_id is not distinct from head.applied_effect_run_id
   and state.applied_fence_token=head.applied_fence_token
   and state.desired_generation=head.desired_generation and state.desired_digest=head.desired_digest
   and state.desired_disposition=head.desired_disposition;
  if v_exact<>v_publication.snapshot_count then
   return query select 'state_drift',null::jsonb; return;
  end if;
  select count(*) into v_exact
  from control.fleet_release_route_publication_recovery_route_heads head
  join control.fleet_release_route_publication_owners owner using(driver_operation_id,workshop_id)
  join lateral (select legacy.rendered_digest from control.fleet_release_route_publication_records legacy
     where v_publication.interrupted_phase<>'candidate_staging'
      and legacy.driver_operation_id=owner.driver_operation_id and legacy.workshop_id=owner.workshop_id
      and legacy.overlay_kind='candidate'
    union all select recovery.rendered_digest
     from control.fleet_release_route_publication_recovery_candidate_records recovery
     where v_publication.interrupted_phase='candidate_staging'
      and recovery.driver_operation_id=owner.driver_operation_id
      and recovery.claim_fence=p_claim_fence and recovery.workshop_id=owner.workshop_id) record on true
  where head.driver_operation_id=p_driver_operation_id and head.claim_fence=p_claim_fence
   and head.applied_rendered_digest=record.rendered_digest
   and head.applied_driver_operation_id=p_driver_operation_id
   and head.applied_effect_run_id is null and head.applied_fence_token=owner.route_fence_token;
  if v_exact=0 then
   update control.workshop_route_projection_state state set
    applied_rendered_digest=record.rendered_digest,applied_driver_operation_id=p_driver_operation_id,
    applied_effect_run_id=null,applied_fence_token=owner.route_fence_token,updated_at=now()
   from control.fleet_release_route_publication_owners owner
   join control.fleet_release_route_publication_recovery_route_heads head
    on head.driver_operation_id=owner.driver_operation_id and head.workshop_id=owner.workshop_id
     and head.claim_fence=p_claim_fence
   join lateral (select legacy.rendered_digest from control.fleet_release_route_publication_records legacy
      where v_publication.interrupted_phase<>'candidate_staging'
       and legacy.driver_operation_id=owner.driver_operation_id and legacy.workshop_id=owner.workshop_id
       and legacy.overlay_kind='candidate'
     union all select recovery.rendered_digest
      from control.fleet_release_route_publication_recovery_candidate_records recovery
      where v_publication.interrupted_phase='candidate_staging'
       and recovery.driver_operation_id=owner.driver_operation_id
       and recovery.claim_fence=p_claim_fence and recovery.workshop_id=owner.workshop_id) record on true
   where owner.driver_operation_id=p_driver_operation_id and state.workshop_id=owner.workshop_id
    and state.applied_generation=head.applied_generation and state.applied_digest=head.applied_digest
    and state.applied_disposition=head.applied_disposition
    and state.applied_rendered_digest=head.applied_rendered_digest
    and state.applied_driver_operation_id is not distinct from head.applied_driver_operation_id
    and state.applied_effect_run_id is not distinct from head.applied_effect_run_id
    and state.applied_fence_token=head.applied_fence_token
    and state.desired_generation=head.desired_generation and state.desired_digest=head.desired_digest
    and state.desired_disposition=head.desired_disposition;
   get diagnostics v_changed=row_count;
   if v_changed<>v_publication.snapshot_count then raise exception 'recovery candidate head drifted' using errcode='40001'; end if;
  elsif v_exact<>v_publication.snapshot_count then
   return query select 'state_drift',null::jsonb; return;
  end if;
  v_response:=v_resolution.candidate_response;
  if v_publication.interrupted_phase='candidate_staging' then
   select * into v_seal from control.fleet_release_route_publication_recovery_candidate_seals
    where driver_operation_id=p_driver_operation_id and claim_fence=p_claim_fence;
   if not found then return query select 'state_drift',null::jsonb; return; end if;
  else
   v_seal.selector:=v_publication.candidate_selector;
   v_seal.directory_device:=v_publication.candidate_directory_device;
   v_seal.directory_inode:=v_publication.candidate_directory_inode;
   v_seal.route_set_digest:=v_publication.candidate_route_set_digest;
  end if;
  insert into control.fleet_release_route_publication_completions(
   driver_operation_id,fleet_run_id,candidate_selector,candidate_directory_device,
   candidate_directory_inode,candidate_route_set_digest,target_slot,
   original_global_fence_token,stored_response)
  values(p_driver_operation_id,v_publication.fleet_run_id,v_seal.selector,
   v_seal.directory_device,v_seal.directory_inode,
   v_seal.route_set_digest,v_publication.target_slot,
   v_publication.original_global_fence_token,v_response);
  update control.deployment_driver_operations set state='succeeded',response=v_response,
   safe_error=null,execution_token=null,lease_expires_at=null,updated_at=now()
   where id=p_driver_operation_id and state='in_progress' and safe_error='runtime_outcome_unknown';
  get diagnostics v_changed=row_count;
  if v_changed<>1 then raise exception 'recovery driver completion drifted' using errcode='40001'; end if;
 else
  if v_publication.external_effects_started_at is not null
   or (p_resolution_kind='unstarted' and (v_publication.interrupted_phase<>'maintenance_staging'
     or v_publication.prior_recorded_at is not null))
   or (p_resolution_kind='prior' and v_publication.prior_recorded_at is null) then
   return query select 'state_drift',null::jsonb; return;
  end if;
  select count(*) into v_exact from control.fleet_release_route_publication_owners owner
   join control.fleet_release_route_publication_recovery_route_heads head
    on head.driver_operation_id=owner.driver_operation_id and head.workshop_id=owner.workshop_id
     and head.claim_fence=p_claim_fence
   join control.workshop_route_projection_state state using(workshop_id)
   where owner.driver_operation_id=p_driver_operation_id
    and head.applied_rendered_digest=owner.applied_rendered_digest
    and head.applied_fence_token=owner.applied_fence_token
    and state.applied_generation=head.applied_generation and state.applied_digest=head.applied_digest
    and state.applied_disposition=head.applied_disposition
    and state.applied_rendered_digest=head.applied_rendered_digest
    and state.applied_driver_operation_id is not distinct from head.applied_driver_operation_id
    and state.applied_effect_run_id is not distinct from head.applied_effect_run_id
    and state.applied_fence_token=head.applied_fence_token
    and state.desired_generation=head.desired_generation and state.desired_digest=head.desired_digest
    and state.desired_disposition=head.desired_disposition;
  if v_exact<>v_publication.snapshot_count then return query select 'snapshot_drift',null::jsonb; return; end if;
  v_response:=jsonb_build_object('outcome','not_applied','driver_operation_id',p_driver_operation_id,
   'fleet_run_id',v_publication.fleet_run_id,'resolution_kind',p_resolution_kind,
   'decision_digest',p_decision_digest);
  update control.deployment_driver_operations set state='failed',response=null,
   safe_error='release_route_publication_not_applied',execution_token=null,lease_expires_at=null,updated_at=now()
   where id=p_driver_operation_id and state='in_progress' and safe_error='runtime_outcome_unknown';
  get diagnostics v_changed=row_count;
  if v_changed<>1 then raise exception 'recovery driver cancellation drifted' using errcode='40001'; end if;
 end if;
 update control.workshop_route_application_leases lease set state='idle',authority_kind=null,
  release_publication_id=null,generation=null,projection_digest=null,lease_owner=null,
  lease_token=null,lease_expires_at=null,heartbeat_at=null,quarantined_at=null,safe_error=null,
  initialization_required=false,updated_at=now()
 from control.fleet_release_route_publication_owners owner
 where owner.driver_operation_id=p_driver_operation_id and lease.workshop_id=owner.workshop_id
  and lease.state='quarantined' and lease.authority_kind='release-overlay'
  and lease.release_publication_id=p_driver_operation_id
  and lease.generation=owner.generation and lease.projection_digest=owner.projection_digest
  and lease.fence_token=owner.route_fence_token
  and lease.lease_owner=v_publication.original_instance_owner and lease.lease_token is null
  and lease.lease_expires_at is null and lease.quarantined_at is not null
  and lease.safe_error='release_route_publication_outcome_unknown';
 get diagnostics v_changed=row_count;
 if v_changed<>v_publication.snapshot_count then raise exception 'recovery route release drifted' using errcode='40001'; end if;
 update control.deployment_driver_resource_leases set state='idle',authority_kind=null,
  driver_operation_id=null,effect_run_id=null,route_set_publication_id=null,
  lease_owner=null,lease_token=null,lease_expires_at=null,heartbeat_at=null,
  quarantined_at=null,safe_error=null,updated_at=now()
 where resource_key='runtime/shared-odoo' and state='quarantined' and authority_kind='release'
  and driver_operation_id=p_driver_operation_id
  and lease_owner=v_publication.original_instance_owner and lease_token is null
  and lease_expires_at is null and quarantined_at is not null
  and safe_error='runtime_outcome_unknown'
  and fence_token=v_publication.original_global_fence_token;
 get diagnostics v_changed=row_count;
 if v_changed<>1 then raise exception 'recovery global release drifted' using errcode='40001'; end if;
 insert into control.fleet_release_route_publication_recovery_terminals(
  driver_operation_id,fleet_run_id,claim_fence,control_operation_attempt,
  control_operation_lease_owner,reconciliation_owner,resolution_kind,outcome,
  decision_digest,response)
 values(p_driver_operation_id,v_publication.fleet_run_id,p_claim_fence,p_control_operation_attempt,
  p_control_operation_lease_owner,p_reconciliation_owner,p_resolution_kind,
  case when p_resolution_kind='candidate' then 'applied_recovered' else 'not_applied' end,
 p_decision_digest,v_response);
 return query select case when p_resolution_kind='candidate' then 'applied_recovered' else 'not_applied' end,v_response;
end $function$;

-- Function-only runtime surface.
revoke all on table control.fleet_release_route_publication_recovery_claims,
 control.fleet_release_route_publication_recovery_authorizations,
 control.fleet_release_route_publication_recovery_candidate_records,
 control.fleet_release_route_publication_recovery_candidate_seals,
 control.fleet_release_route_publication_recovery_route_heads,
 control.fleet_release_route_publication_recovery_resolutions,
 control.fleet_release_route_publication_recovery_terminals from public;
revoke all on function control.release_route_recovery_token_digest(uuid) from public;
revoke all on function control.release_route_recovery_decision_digest(uuid,uuid,bigint,text,jsonb,jsonb) from public;
revoke all on function control.valid_release_route_recovery_worker(uuid,integer,text) from public;
revoke all on function control.valid_immutable_release_route_completion_response(uuid,jsonb) from public;
revoke all on function control.lock_immutable_release_route_recovery_claim(uuid,integer,text,uuid,uuid,bigint) from public;
revoke all on function control.finish_immutable_release_route_publication_before_recovery(uuid,uuid,uuid,uuid,uuid,bigint,jsonb) from public;
revoke all on function control.discover_interrupted_immutable_release_route_publications(uuid,integer) from public;
revoke all on function control.claim_interrupted_immutable_release_route_publication(uuid,integer,text,uuid,uuid,integer) from public;
revoke all on function control.renew_interrupted_immutable_release_route_publication_claim(uuid,integer,text,uuid,uuid,bigint,integer) from public;
revoke all on function control.read_interrupted_immutable_release_route_publication_state(uuid,integer,text,uuid,uuid,bigint) from public;
revoke all on function control.record_interrupted_immutable_release_route_candidate_entry(uuid,integer,text,uuid,uuid,bigint,uuid,bigint,text,text,text) from public;
revoke all on function control.seal_interrupted_immutable_release_route_candidate(uuid,integer,text,uuid,uuid,bigint,text,bigint,bigint,integer,text) from public;
revoke all on function control.authorize_interrupted_immutable_release_route_exchange(uuid,integer,text,uuid,uuid,bigint,text,text,jsonb) from public;
revoke all on function control.resolve_interrupted_immutable_release_route_publication(uuid,integer,text,uuid,uuid,bigint,text,jsonb,jsonb) from public;
revoke all on function control.finish_interrupted_immutable_release_route_publication(uuid,integer,text,uuid,uuid,bigint,text,text) from public;
revoke all on function control.finish_immutable_release_route_publication(uuid,uuid,uuid,uuid,uuid,bigint,jsonb) from public;
revoke all on function control.read_immutable_release_route_publication_result(uuid,uuid) from public;

do $migration$ declare v_role text; begin
 foreach v_role in array array['control_api','control_tenant_api','control_membership_worker',
 'control_provisioning_worker','control_invoice_worker','control_inventory_worker',
 'control_email_worker','control_reconciliation_worker','control_lifecycle_worker',
 'control_backup_scheduler','control_driver_ledger','control_release_worker','control_privacy_worker'] loop
  if exists(select 1 from pg_roles where rolname=v_role) then
   execute format('revoke all on table control.fleet_release_route_publication_recovery_claims, control.fleet_release_route_publication_recovery_authorizations, control.fleet_release_route_publication_recovery_candidate_records, control.fleet_release_route_publication_recovery_candidate_seals, control.fleet_release_route_publication_recovery_route_heads, control.fleet_release_route_publication_recovery_resolutions, control.fleet_release_route_publication_recovery_terminals from %I',v_role);
   execute format('revoke all on function control.finish_immutable_release_route_publication_before_recovery(uuid,uuid,uuid,uuid,uuid,bigint,jsonb) from %I',v_role);
  end if;
 end loop;
 if exists(select 1 from pg_roles where rolname='control_driver_ledger') then
  grant execute on function control.discover_interrupted_immutable_release_route_publications(uuid,integer) to control_driver_ledger;
  grant execute on function control.claim_interrupted_immutable_release_route_publication(uuid,integer,text,uuid,uuid,integer) to control_driver_ledger;
  grant execute on function control.renew_interrupted_immutable_release_route_publication_claim(uuid,integer,text,uuid,uuid,bigint,integer) to control_driver_ledger;
  grant execute on function control.read_interrupted_immutable_release_route_publication_state(uuid,integer,text,uuid,uuid,bigint) to control_driver_ledger;
  grant execute on function control.record_interrupted_immutable_release_route_candidate_entry(uuid,integer,text,uuid,uuid,bigint,uuid,bigint,text,text,text) to control_driver_ledger;
  grant execute on function control.seal_interrupted_immutable_release_route_candidate(uuid,integer,text,uuid,uuid,bigint,text,bigint,bigint,integer,text) to control_driver_ledger;
  grant execute on function control.authorize_interrupted_immutable_release_route_exchange(uuid,integer,text,uuid,uuid,bigint,text,text,jsonb) to control_driver_ledger;
  grant execute on function control.resolve_interrupted_immutable_release_route_publication(uuid,integer,text,uuid,uuid,bigint,text,jsonb,jsonb) to control_driver_ledger;
  grant execute on function control.finish_interrupted_immutable_release_route_publication(uuid,integer,text,uuid,uuid,bigint,text,text) to control_driver_ledger;
  grant execute on function control.finish_immutable_release_route_publication(uuid,uuid,uuid,uuid,uuid,bigint,jsonb) to control_driver_ledger;
  grant execute on function control.read_immutable_release_route_publication_result(uuid,uuid) to control_driver_ledger;
 end if;
end $migration$;

comment on table control.fleet_release_route_publication_recovery_claims is
'Dormant fenced recovery claims authenticated by the current retrying release worker; expiry is capped by its operation lease.';
comment on table control.fleet_release_route_publication_recovery_resolutions is
'Immutable exact filesystem observations for specialized protocol-v2 release route recovery.';
comment on table control.fleet_release_route_publication_recovery_terminals is
'Immutable terminal not-applied or forward-recovered release route decisions; the quarantined parent remains forensic evidence.';
