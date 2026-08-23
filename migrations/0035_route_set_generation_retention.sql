-- Dormant retention authority for immutable generations produced by the
-- universal route-set publication ledger.  This migration does not authorize
-- deletion by itself: the driver must additionally hold the shared host guard
-- and prove immediately before descriptor-relative removal that `current` is
-- not the claimed selector.  Legacy startup and release generation artifacts
-- remain outside this retention scope.

alter table control.deployment_driver_resource_leases
 drop constraint deployment_driver_resource_leases_authority_check,
 drop constraint deployment_driver_resource_leases_shape_v3_check,
 add constraint deployment_driver_resource_leases_authority_check check(
  authority_kind is null or authority_kind in
   ('release','startup-rebuild','route-set-publication','route-set-retention')),
 add constraint deployment_driver_resource_leases_shape_v4_check check(
  (state='idle' and authority_kind is null and driver_operation_id is null
   and effect_run_id is null and route_set_publication_id is null
   and lease_owner is null and lease_token is null and lease_expires_at is null
   and heartbeat_at is null and quarantined_at is null and safe_error is null)
  or (state='held' and authority_kind is not null
   and ((authority_kind='release' and driver_operation_id is not null
      and effect_run_id is null and route_set_publication_id is null)
    or (authority_kind='startup-rebuild' and driver_operation_id is null
      and effect_run_id is not null and route_set_publication_id is null)
    or (authority_kind in ('route-set-publication','route-set-retention')
      and driver_operation_id is null and effect_run_id is null
      and route_set_publication_id is not null))
   and lease_owner is not null and lease_token is not null
   and lease_expires_at is not null and heartbeat_at is not null
   and quarantined_at is null and safe_error is null and fence_token>0)
  or (state='quarantined' and authority_kind is not null
   and ((authority_kind='release' and driver_operation_id is not null
      and effect_run_id is null and route_set_publication_id is null)
    or (authority_kind='startup-rebuild' and driver_operation_id is null
      and effect_run_id is not null and route_set_publication_id is null)
    or (authority_kind='route-set-publication' and driver_operation_id is null
      and effect_run_id is null and route_set_publication_id is not null))
   and lease_owner is not null and lease_token is null and lease_expires_at is null
   and heartbeat_at is not null and quarantined_at is not null
   and safe_error='runtime_outcome_unknown' and fence_token>0));

create table control.route_set_generation_retention_claims (
 publication_id uuid primary key,
 claim_fence bigint not null check(claim_fence>0),
 instance_owner uuid not null,
 claim_token uuid not null,
 claim_expires_at timestamptz not null,
 created_at timestamptz not null default now(),
 updated_at timestamptz not null default now(),
 constraint route_set_generation_retention_claim_publication_fkey
  foreign key(publication_id) references
   control.workshop_route_set_publications(publication_id) on delete restrict
);

create table control.route_set_generation_retention_attempts (
 publication_id uuid not null,
 claim_fence bigint not null check(claim_fence>0),
 instance_owner uuid not null,
 claim_token_digest text not null check(claim_token_digest ~ '^[0-9a-f]{64}$'),
 resolution text not null check(resolution in
  ('deleted','already_absent','protected_current','identity_mismatch')),
 evidence jsonb not null check(jsonb_typeof(evidence)='object' and pg_column_size(evidence)<=16384),
 finished_at timestamptz not null default now(),
 primary key(publication_id,claim_fence),
 constraint route_set_generation_retention_attempt_publication_fkey
  foreign key(publication_id) references
   control.workshop_route_set_publications(publication_id) on delete restrict
);

create function control.reject_route_set_generation_retention_attempt_mutation()
returns trigger language plpgsql set search_path=pg_catalog,control as $function$
begin
 raise exception 'route-set generation retention terminal evidence is immutable'
  using errcode='55000';
end $function$;

create trigger route_set_generation_retention_attempts_immutable
 before update or delete on control.route_set_generation_retention_attempts
 for each row execute function control.reject_route_set_generation_retention_attempt_mutation();

create function control.route_set_generation_retention_expected_identity(p_publication_id uuid)
returns jsonb language sql stable security definer set search_path=pg_catalog,control as $function$
 select case when publication.publication_kind='startup' then
  jsonb_build_object('protocol_version',publication.protocol_version,
   'publication_id',publication.publication_id,'publication_kind','startup',
   'startup_effect_run_id',publication.startup_effect_run_id,
   'global_fence_token',publication.original_global_fence_token,
   'route_set_digest',publication.route_set_digest)
 else jsonb_build_object('protocol_version',publication.protocol_version,
   'publication_id',publication.publication_id,
   'publication_kind',publication.publication_kind,
   'global_fence_token',publication.original_global_fence_token,
   'target_workshop_id',publication.target_workshop_id,
   'target_route_fence_token',target.target_route_fence_token,
   'route_set_digest',publication.route_set_digest) end
 from control.workshop_route_set_publications publication
 left join control.workshop_route_set_publication_targets target using(publication_id)
 where publication.publication_id=p_publication_id
$function$;

create function control.route_set_generation_retention_expected_intent(p_publication_id uuid)
returns jsonb language sql stable security definer set search_path=pg_catalog,control as $function$
 select case when publication.publication_kind='startup' then
  jsonb_build_object('protocol_version',publication.protocol_version,
   'publication_id',publication.publication_id,'publication_kind','startup',
   'startup_effect_run_id',publication.startup_effect_run_id,
   'global_fence_token',publication.original_global_fence_token)
 else jsonb_build_object('protocol_version',publication.protocol_version,
   'publication_id',publication.publication_id,
   'publication_kind',publication.publication_kind,
   'global_fence_token',publication.original_global_fence_token,
   'target_workshop_id',publication.target_workshop_id,
   'target_route_fence_token',target.target_route_fence_token) end
 from control.workshop_route_set_publications publication
 left join control.workshop_route_set_publication_targets target using(publication_id)
 where publication.publication_id=p_publication_id
$function$;

create function control.route_set_generation_retention_eligible(p_publication_id uuid)
returns boolean language sql stable security definer set search_path=pg_catalog,control as $function$
 with applied_raw as (
  select publication.publication_id,publication.observed_at authoritative_at
   from control.workshop_route_set_publications publication
   where publication.phase='completed'
  union all
  select publication.publication_id,resolution.recorded_at
   from control.workshop_route_set_publications publication
   join control.workshop_route_set_publication_resolutions resolution
    on resolution.publication_id=publication.publication_id
    and resolution.reconciliation_claim_fence=publication.recovery_terminal_claim_fence
    and resolution.reconciliation_operation_id=publication.recovery_terminal_operation_id
    and resolution.reconciliation_operation_attempt=publication.recovery_terminal_operation_attempt
    and resolution.reconciliation_operation_lease_owner=publication.recovery_terminal_operation_lease_owner
    and resolution.resolution_kind=publication.recovery_terminal_kind
   where publication.recovery_terminal_kind='candidate'
  union all
  select terminal.publication_id,resolution.recorded_at
   from control.workshop_route_set_startup_recovery_terminals terminal
   join control.workshop_route_set_startup_recovery_resolutions resolution
    on resolution.publication_id=terminal.publication_id
    and resolution.claim_fence=terminal.claim_fence
    and resolution.reconciliation_owner=terminal.reconciliation_owner
    and resolution.resolution_kind=terminal.resolution_kind
   where terminal.resolution_kind='candidate'
 ), applied as (
  select publication_id,max(authoritative_at) authoritative_at
   from applied_raw group by publication_id
 ), terminal_publications as (
  select publication_id from control.workshop_route_set_publications where phase='completed'
  union
  select publication.publication_id
   from control.workshop_route_set_publications publication
   join control.workshop_route_set_publication_resolutions resolution
    on resolution.publication_id=publication.publication_id
    and resolution.reconciliation_claim_fence=publication.recovery_terminal_claim_fence
    and resolution.reconciliation_operation_id=publication.recovery_terminal_operation_id
    and resolution.reconciliation_operation_attempt=publication.recovery_terminal_operation_attempt
    and resolution.reconciliation_operation_lease_owner=publication.recovery_terminal_operation_lease_owner
    and resolution.resolution_kind=publication.recovery_terminal_kind
   where publication.recovery_terminal_at is not null
  union
  select terminal.publication_id
   from control.workshop_route_set_startup_recovery_terminals terminal
   join control.workshop_route_set_startup_recovery_resolutions resolution
    on resolution.publication_id=terminal.publication_id
    and resolution.claim_fence=terminal.claim_fence
    and resolution.reconciliation_owner=terminal.reconciliation_owner
    and resolution.resolution_kind=terminal.resolution_kind
 ), protected_applied as (
  select applied.publication_id from applied
   order by applied.authoritative_at desc,applied.publication_id desc limit 2
 )
 select exists(
  select 1 from control.workshop_route_set_publications publication
  where publication.publication_id=p_publication_id
   and publication.retention_not_before<=now()
   and publication.selector<>'generations/boot-live'
   and publication.sealed_count=publication.snapshot_count
   and publication.route_set_digest is not null
   and publication.candidate_directory_device is not null
   and publication.candidate_directory_inode is not null
   and exists(select 1 from terminal_publications terminal
    where terminal.publication_id=publication.publication_id)
   and not exists(select 1 from protected_applied protected
    where protected.publication_id=publication.publication_id)
   and not exists(select 1 from control.route_set_generation_retention_attempts attempt
    where attempt.publication_id=publication.publication_id
     and attempt.resolution in ('deleted','already_absent'))
   and not exists(
    select 1 from control.workshop_route_set_publications unresolved
    where unresolved.publication_id<>publication.publication_id
     and (unresolved.selector=publication.selector or unresolved.prior_selector=publication.selector)
     and not exists(select 1 from terminal_publications terminal
       where terminal.publication_id=unresolved.publication_id))
   and not exists(
    select 1 from control.fleet_release_route_publications release
    where publication.selector in
     (release.prior_selector,release.maintenance_selector,release.candidate_selector))
   and not exists(
    select 1 from control.workshop_route_startup_publications startup
    where startup.finalized_at is null
     and publication.selector in (startup.prior_selector,startup.staging_selector)))
$function$;

create function control.discover_route_set_generation_retention_candidates(
 p_after_publication_id uuid,p_limit integer
) returns table(publication_id uuid,publication_kind text,selector text,
 retention_not_before timestamptz)
language plpgsql stable security definer set search_path=pg_catalog,control as $function$
begin
 if p_limit is null or p_limit not between 1 and 100 then return; end if;
 if not exists(select 1 from control.route_set_publication_protocol_state
   where singleton and mode='generation_v1') then return; end if;
 return query select publication.publication_id,publication.publication_kind,
  publication.selector,publication.retention_not_before
 from control.workshop_route_set_publications publication
 where (p_after_publication_id is null or publication.publication_id>p_after_publication_id)
  and control.route_set_generation_retention_eligible(publication.publication_id)
 order by publication.publication_id limit p_limit;
end $function$;

create function control.claim_route_set_generation_retention(
 p_publication_id uuid,p_instance_owner uuid,p_claim_token uuid,p_ttl_seconds integer
) returns table(outcome text,claim_fence bigint,publication_kind text,selector text,
 directory_device bigint,directory_inode bigint,expected_intent jsonb,expected_identity jsonb,
 route_count integer,present_count integer)
language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_protocol text; v_global control.deployment_driver_resource_leases%rowtype;
 v_publication control.workshop_route_set_publications%rowtype;
 v_claim control.route_set_generation_retention_claims%rowtype;
 v_fence bigint; v_expiry timestamptz;
begin
 if p_publication_id is null or p_instance_owner is null or p_claim_token is null
  or p_ttl_seconds is null or p_ttl_seconds not between 30 and 3600 then
  return query select 'invalid',null::bigint,null::text,null::text,null::bigint,null::bigint,
   null::jsonb,null::jsonb,null::integer,null::integer; return;
 end if;
 select mode into strict v_protocol from control.route_set_publication_protocol_state
  where singleton for update;
 select * into strict v_global from control.deployment_driver_resource_leases
  where resource_key='runtime/shared-odoo' for update;
 select * into v_publication from control.workshop_route_set_publications
  where publication_id=p_publication_id for update;
 if not found then
  return query select 'not_found',null::bigint,null::text,null::text,null::bigint,null::bigint,
   null::jsonb,null::jsonb,null::integer,null::integer; return;
 end if;
 if v_protocol<>'generation_v1' or not control.route_set_generation_retention_eligible(p_publication_id) then
  return query select 'ineligible',null::bigint,v_publication.publication_kind,v_publication.selector,
   v_publication.candidate_directory_device,v_publication.candidate_directory_inode,
   control.route_set_generation_retention_expected_intent(p_publication_id),
   control.route_set_generation_retention_expected_identity(p_publication_id),
   v_publication.sealed_count,v_publication.sealed_present_count; return;
 end if;
 v_expiry:=now()+make_interval(secs=>p_ttl_seconds);
 select * into v_claim from control.route_set_generation_retention_claims
  where publication_id=p_publication_id for update;
 if v_global.state='held' and v_global.authority_kind='route-set-retention'
  and v_global.route_set_publication_id=p_publication_id
  and v_global.lease_owner=p_instance_owner and v_global.lease_token=p_claim_token
  and v_global.lease_expires_at>now()
  and found and v_claim.claim_fence=v_global.fence_token
  and v_claim.instance_owner=p_instance_owner and v_claim.claim_token=p_claim_token
  and v_claim.claim_expires_at>now() then
  update control.deployment_driver_resource_leases set lease_expires_at=v_expiry,
   heartbeat_at=now(),updated_at=now() where resource_key='runtime/shared-odoo';
  update control.route_set_generation_retention_claims set claim_expires_at=v_expiry,
   updated_at=now() where publication_id=p_publication_id;
  return query select 'replay',v_global.fence_token,v_publication.publication_kind,
   v_publication.selector,v_publication.candidate_directory_device,
   v_publication.candidate_directory_inode,
   control.route_set_generation_retention_expected_intent(p_publication_id),
   control.route_set_generation_retention_expected_identity(p_publication_id),
   v_publication.sealed_count,v_publication.sealed_present_count; return;
 end if;
 if v_global.state='held' and v_global.authority_kind='route-set-retention'
  and v_global.route_set_publication_id=p_publication_id and found
  and v_global.lease_expires_at<=now() and v_claim.claim_expires_at<=now() then
  v_fence:=v_global.fence_token+1;
  update control.deployment_driver_resource_leases set lease_owner=p_instance_owner,
   lease_token=p_claim_token,lease_expires_at=v_expiry,heartbeat_at=now(),
   fence_token=v_fence,updated_at=now() where resource_key='runtime/shared-odoo';
  update control.route_set_generation_retention_claims set claim_fence=v_fence,
   instance_owner=p_instance_owner,claim_token=p_claim_token,claim_expires_at=v_expiry,
   updated_at=now() where publication_id=p_publication_id;
  return query select 'acquired',v_fence,v_publication.publication_kind,v_publication.selector,
   v_publication.candidate_directory_device,v_publication.candidate_directory_inode,
   control.route_set_generation_retention_expected_intent(p_publication_id),
   control.route_set_generation_retention_expected_identity(p_publication_id),
   v_publication.sealed_count,v_publication.sealed_present_count; return;
 end if;
 if v_global.state<>'idle' then
  return query select 'busy',null::bigint,v_publication.publication_kind,v_publication.selector,
   v_publication.candidate_directory_device,v_publication.candidate_directory_inode,
   null::jsonb,null::jsonb,v_publication.sealed_count,v_publication.sealed_present_count; return;
 end if;
 v_fence:=v_global.fence_token+1;
 update control.deployment_driver_resource_leases set state='held',
  authority_kind='route-set-retention',driver_operation_id=null,effect_run_id=null,
  route_set_publication_id=p_publication_id,lease_owner=p_instance_owner,
  lease_token=p_claim_token,lease_expires_at=v_expiry,heartbeat_at=now(),
  quarantined_at=null,safe_error=null,fence_token=v_fence,updated_at=now()
 where resource_key='runtime/shared-odoo' and state='idle';
 insert into control.route_set_generation_retention_claims(publication_id,claim_fence,
  instance_owner,claim_token,claim_expires_at)
 values(p_publication_id,v_fence,p_instance_owner,p_claim_token,v_expiry)
 on conflict(publication_id) do update set claim_fence=excluded.claim_fence,
  instance_owner=excluded.instance_owner,claim_token=excluded.claim_token,
  claim_expires_at=excluded.claim_expires_at,updated_at=now();
 return query select 'acquired',v_fence,v_publication.publication_kind,v_publication.selector,
  v_publication.candidate_directory_device,v_publication.candidate_directory_inode,
  control.route_set_generation_retention_expected_intent(p_publication_id),
  control.route_set_generation_retention_expected_identity(p_publication_id),
  v_publication.sealed_count,v_publication.sealed_present_count;
end $function$;

create function control.renew_route_set_generation_retention_claim(
 p_publication_id uuid,p_instance_owner uuid,p_claim_token uuid,p_claim_fence bigint,
 p_ttl_seconds integer
) returns boolean language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_expiry timestamptz; v_global_count integer; v_claim_count integer;
begin
 if p_ttl_seconds is null or p_ttl_seconds not between 30 and 3600 then return false; end if;
 perform 1 from control.route_set_publication_protocol_state where singleton for update;
 perform 1 from control.deployment_driver_resource_leases
  where resource_key='runtime/shared-odoo' for update;
 if not exists(select 1 from control.deployment_driver_resource_leases global_lease
   join control.route_set_generation_retention_claims claim
    on claim.publication_id=global_lease.route_set_publication_id
   where global_lease.resource_key='runtime/shared-odoo' and global_lease.state='held'
    and global_lease.authority_kind='route-set-retention'
    and global_lease.route_set_publication_id=p_publication_id
    and global_lease.lease_owner=p_instance_owner and global_lease.lease_token=p_claim_token
    and global_lease.fence_token=p_claim_fence and claim.claim_fence=p_claim_fence
    and claim.instance_owner=p_instance_owner and claim.claim_token=p_claim_token
    and global_lease.lease_expires_at>now() and claim.claim_expires_at>now()) then
  return false;
 end if;
 v_expiry:=now()+make_interval(secs=>p_ttl_seconds);
 update control.deployment_driver_resource_leases set lease_expires_at=v_expiry,
  heartbeat_at=now(),updated_at=now()
 where resource_key='runtime/shared-odoo' and state='held'
  and authority_kind='route-set-retention' and route_set_publication_id=p_publication_id
  and lease_owner=p_instance_owner and lease_token=p_claim_token and fence_token=p_claim_fence;
 get diagnostics v_global_count=row_count;
 update control.route_set_generation_retention_claims set claim_expires_at=v_expiry,updated_at=now()
 where publication_id=p_publication_id and claim_fence=p_claim_fence
  and instance_owner=p_instance_owner and claim_token=p_claim_token;
 get diagnostics v_claim_count=row_count;
 if v_global_count<>1 or v_claim_count<>1 then raise exception
  'route-set generation retention renewal authority drifted' using errcode='40001'; end if;
 return true;
end $function$;

create function control.finish_route_set_generation_retention(
 p_publication_id uuid,p_instance_owner uuid,p_claim_token uuid,p_claim_fence bigint,
 p_resolution text,p_evidence jsonb
) returns text language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_global control.deployment_driver_resource_leases%rowtype;
 v_publication control.workshop_route_set_publications%rowtype;
 v_attempt control.route_set_generation_retention_attempts%rowtype;
 v_expected_intent jsonb; v_expected_identity jsonb; v_keys integer; v_changed integer;
begin
 if p_resolution is null
  or p_resolution not in ('deleted','already_absent','protected_current','identity_mismatch')
  or jsonb_typeof(p_evidence) is distinct from 'object' or pg_column_size(p_evidence)>16384 then
  return 'invalid'; end if;
 perform 1 from control.route_set_publication_protocol_state where singleton for update;
 select * into v_attempt from control.route_set_generation_retention_attempts
  where publication_id=p_publication_id and claim_fence=p_claim_fence;
 if found then
  return case when v_attempt.instance_owner=p_instance_owner
    and v_attempt.claim_token_digest=encode(public.digest(uuid_send(p_claim_token),'sha256'),'hex')
    and v_attempt.resolution=p_resolution and v_attempt.evidence=p_evidence
   then 'replay' else 'conflict' end;
 end if;
 select * into strict v_global from control.deployment_driver_resource_leases
  where resource_key='runtime/shared-odoo' for update;
 select * into v_publication from control.workshop_route_set_publications
  where publication_id=p_publication_id for update;
 if not found then return 'not_found'; end if;
 if v_global.state<>'held' or v_global.authority_kind<>'route-set-retention'
  or v_global.route_set_publication_id<>p_publication_id
  or v_global.lease_owner<>p_instance_owner or v_global.lease_token<>p_claim_token
  or v_global.fence_token<>p_claim_fence or v_global.lease_expires_at<=now()
  or not exists(select 1 from control.route_set_generation_retention_claims claim
   where claim.publication_id=p_publication_id and claim.claim_fence=p_claim_fence
    and claim.instance_owner=p_instance_owner and claim.claim_token=p_claim_token
    and claim.claim_expires_at>now()) then
  return 'claim_lost'; end if;
 v_expected_intent:=control.route_set_generation_retention_expected_intent(p_publication_id);
 v_expected_identity:=control.route_set_generation_retention_expected_identity(p_publication_id);
 select count(*) into v_keys from jsonb_object_keys(p_evidence);
 if v_keys<>14
  or p_evidence->'protocol_version' is distinct from '1'::jsonb
  or p_evidence->'publication_id' is distinct from to_jsonb(p_publication_id)
  or p_evidence->'claim_fence' is distinct from to_jsonb(p_claim_fence)
  or p_evidence->'resolution' is distinct from to_jsonb(p_resolution)
  or p_evidence->'selector' is distinct from to_jsonb(v_publication.selector)
  or p_evidence->'expected_intent' is distinct from v_expected_intent
  or p_evidence->'expected_identity' is distinct from v_expected_identity
  or jsonb_typeof(p_evidence->'observed_current_selector') is distinct from 'string'
  or (p_evidence->>'observed_current_selector') !~ '^generations/[A-Za-z0-9][A-Za-z0-9-]{0,63}$'
  or not control.valid_route_set_prior_selector_identity(
    p_evidence->>'observed_current_selector',p_evidence->'observed_current_identity')
  or jsonb_typeof(p_evidence->'target_present') is distinct from 'boolean'
  or not (p_evidence ?& array['observed_target_device','observed_target_inode',
    'mismatch_kind','observed_target_identity']) then
  return 'evidence_mismatch'; end if;
 if (p_resolution in ('deleted','already_absent','identity_mismatch')
    and p_evidence->>'observed_current_selector'=v_publication.selector)
  or (p_resolution='protected_current' and (
    p_evidence->>'observed_current_selector' is distinct from v_publication.selector
    or p_evidence->'observed_current_identity' is distinct from v_expected_identity
    or p_evidence->'target_present' is distinct from 'true'::jsonb
    or p_evidence->'observed_target_device' is distinct from
      to_jsonb(v_publication.candidate_directory_device)
    or p_evidence->'observed_target_inode' is distinct from
      to_jsonb(v_publication.candidate_directory_inode)))
  or (p_resolution='deleted' and (
    p_evidence->'target_present' is distinct from 'true'::jsonb
    or p_evidence->'observed_target_device' is distinct from to_jsonb(v_publication.candidate_directory_device)
    or p_evidence->'observed_target_inode' is distinct from to_jsonb(v_publication.candidate_directory_inode)))
  or (p_resolution='already_absent' and (
    p_evidence->'target_present' is distinct from 'false'::jsonb
    or p_evidence->'observed_target_device' is distinct from 'null'::jsonb
    or p_evidence->'observed_target_inode' is distinct from 'null'::jsonb))
  or (p_resolution<>'identity_mismatch' and (
    p_evidence->'mismatch_kind' is distinct from 'null'::jsonb
    or p_evidence->'observed_target_identity' is distinct from 'null'::jsonb))
  or (p_resolution='identity_mismatch' and (
    p_evidence->'target_present' is distinct from 'true'::jsonb
    or jsonb_typeof(p_evidence->'observed_target_device') is distinct from 'number'
    or jsonb_typeof(p_evidence->'observed_target_inode') is distinct from 'number'
    or (p_evidence->>'observed_target_device') !~ '^[1-9][0-9]{0,18}$'
    or (p_evidence->>'observed_target_inode') !~ '^[1-9][0-9]{0,18}$'
    or p_evidence->>'mismatch_kind' not in ('directory_identity','content_identity')
    or (p_evidence->>'mismatch_kind'='directory_identity' and (
      p_evidence->'observed_target_identity' is distinct from 'null'::jsonb
      or (p_evidence->'observed_target_device'=to_jsonb(v_publication.candidate_directory_device)
       and p_evidence->'observed_target_inode'=to_jsonb(v_publication.candidate_directory_inode))))
    or (p_evidence->>'mismatch_kind'='content_identity' and (
      jsonb_typeof(p_evidence->'observed_target_identity') is distinct from 'object'
      or not control.valid_route_set_prior_selector_identity(
       v_publication.selector,p_evidence->'observed_target_identity')
      or p_evidence->'observed_target_device' is distinct from
       to_jsonb(v_publication.candidate_directory_device)
      or p_evidence->'observed_target_inode' is distinct from
       to_jsonb(v_publication.candidate_directory_inode))))) then
  return 'evidence_mismatch'; end if;
 insert into control.route_set_generation_retention_attempts(publication_id,claim_fence,
  instance_owner,claim_token_digest,resolution,evidence)
 values(p_publication_id,p_claim_fence,p_instance_owner,
  encode(public.digest(uuid_send(p_claim_token),'sha256'),'hex'),p_resolution,p_evidence);
 delete from control.route_set_generation_retention_claims
  where publication_id=p_publication_id and claim_fence=p_claim_fence;
 get diagnostics v_changed=row_count;
 if v_changed<>1 then raise exception 'route-set retention claim drifted' using errcode='40001'; end if;
 update control.deployment_driver_resource_leases set state='idle',authority_kind=null,
  driver_operation_id=null,effect_run_id=null,route_set_publication_id=null,
  lease_owner=null,lease_token=null,lease_expires_at=null,heartbeat_at=null,
  quarantined_at=null,safe_error=null,updated_at=now()
 where resource_key='runtime/shared-odoo' and state='held'
  and authority_kind='route-set-retention' and route_set_publication_id=p_publication_id
  and lease_owner=p_instance_owner and lease_token=p_claim_token and fence_token=p_claim_fence;
 get diagnostics v_changed=row_count;
 if v_changed<>1 then raise exception 'route-set retention global release drifted' using errcode='40001'; end if;
 return p_resolution;
end $function$;

revoke all on table control.route_set_generation_retention_claims from public;
revoke all on table control.route_set_generation_retention_attempts from public;
revoke all on function control.reject_route_set_generation_retention_attempt_mutation() from public;
revoke all on function control.route_set_generation_retention_expected_identity(uuid) from public;
revoke all on function control.route_set_generation_retention_expected_intent(uuid) from public;
revoke all on function control.route_set_generation_retention_eligible(uuid) from public;
revoke all on function control.discover_route_set_generation_retention_candidates(uuid,integer) from public;
revoke all on function control.claim_route_set_generation_retention(uuid,uuid,uuid,integer) from public;
revoke all on function control.renew_route_set_generation_retention_claim(uuid,uuid,uuid,bigint,integer) from public;
revoke all on function control.finish_route_set_generation_retention(uuid,uuid,uuid,bigint,text,jsonb) from public;

do $migration$ declare v_role text; begin
 foreach v_role in array array['control_api','control_tenant_api','control_membership_worker',
  'control_provisioning_worker','control_invoice_worker','control_inventory_worker',
  'control_email_worker','control_reconciliation_worker','control_lifecycle_worker',
  'control_backup_scheduler','control_driver_ledger','control_release_worker','control_privacy_worker'] loop
  if exists(select 1 from pg_roles where rolname=v_role) then
   execute format('revoke all on table control.route_set_generation_retention_claims from %I',v_role);
   execute format('revoke all on table control.route_set_generation_retention_attempts from %I',v_role);
   execute format('revoke all on function control.route_set_generation_retention_expected_identity(uuid) from %I',v_role);
   execute format('revoke all on function control.route_set_generation_retention_expected_intent(uuid) from %I',v_role);
   execute format('revoke all on function control.route_set_generation_retention_eligible(uuid) from %I',v_role);
  end if;
 end loop;
 if exists(select 1 from pg_roles where rolname='control_driver_ledger') then
  grant execute on function
   control.discover_route_set_generation_retention_candidates(uuid,integer),
   control.claim_route_set_generation_retention(uuid,uuid,uuid,integer),
   control.renew_route_set_generation_retention_claim(uuid,uuid,uuid,bigint,integer),
   control.finish_route_set_generation_retention(uuid,uuid,uuid,bigint,text,jsonb)
  to control_driver_ledger;
 end if;
end $migration$;

comment on table control.route_set_generation_retention_attempts is
'Immutable dormant evidence for universal route-set generation retention; database authority is insufficient without the shared host guard and a fresh non-current selector proof.';
