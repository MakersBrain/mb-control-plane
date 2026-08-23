-- Dormant retention authority for immutable release-overlay generations.
-- Database authorization is necessary but insufficient: the driver must also
-- hold the shared host guard and prove `current` is not the target immediately
-- before descriptor-relative deletion. No production caller is enabled here.

alter table control.deployment_driver_resource_leases
 drop constraint deployment_driver_resource_leases_authority_check,
 drop constraint deployment_driver_resource_leases_shape_v4_check,
 add constraint deployment_driver_resource_leases_authority_check check(
  authority_kind is null or authority_kind in
   ('release','startup-rebuild','route-set-publication','route-set-retention','release-retention')),
 add constraint deployment_driver_resource_leases_shape_v5_check check(
  (state='idle' and authority_kind is null and driver_operation_id is null
   and effect_run_id is null and route_set_publication_id is null
   and lease_owner is null and lease_token is null and lease_expires_at is null
   and heartbeat_at is null and quarantined_at is null and safe_error is null)
  or (state='held' and authority_kind is not null
   and ((authority_kind in ('release','release-retention') and driver_operation_id is not null
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

create table control.fleet_release_generation_retention_subjects (
 driver_operation_id uuid not null,
 fleet_run_id uuid not null,
 overlay_kind text not null check(overlay_kind in ('maintenance','candidate')),
 selector text not null,
 directory_device bigint not null check(directory_device>0),
 directory_inode bigint not null check(directory_inode>0),
 route_count integer not null check(route_count between 1 and 500),
 expected_intent jsonb not null,
 expected_identity jsonb not null,
 source_kind text not null check(source_kind in ('completion','recovery_prior')),
 applied_candidate boolean not null,
 authoritative_at timestamptz not null,
 retention_not_before timestamptz not null,
 created_at timestamptz not null default now(),
 primary key(driver_operation_id,overlay_kind),
 unique(driver_operation_id,fleet_run_id,overlay_kind),
 unique(selector),
 constraint fleet_release_generation_retention_subject_publication_fkey
  foreign key(driver_operation_id,fleet_run_id) references
   control.fleet_release_route_publications(driver_operation_id,fleet_run_id) on delete restrict,
 constraint fleet_release_generation_retention_subject_shape_check check(
  selector='generations/release-'||replace(fleet_run_id::text,'-','')||'-'||overlay_kind
  and jsonb_typeof(expected_intent)='object' and pg_column_size(expected_intent)<=4096
  and jsonb_typeof(expected_identity)='object' and pg_column_size(expected_identity)<=4096
  and (applied_candidate=(overlay_kind='candidate'))
  and retention_not_before=authoritative_at+interval '30 days'
  and expected_intent=jsonb_build_object('protocol_version',1,'fleet_run_id',fleet_run_id,
    'driver_operation_id',driver_operation_id,
    'original_global_fence_token',(expected_identity->>'original_global_fence_token')::bigint,
    'overlay_kind',overlay_kind,'target_slot',expected_identity->>'target_slot')
  and expected_identity->'protocol_version'='1'::jsonb
  and expected_identity->'fleet_run_id'=to_jsonb(fleet_run_id)
  and expected_identity->'driver_operation_id'=to_jsonb(driver_operation_id)
  and expected_identity->>'overlay_kind'=overlay_kind
  and expected_identity->>'route_set_digest' ~ '^sha256:[0-9a-f]{64}$'
  and expected_identity->>'target_slot' in ('blue','green')
  and (expected_identity->>'original_global_fence_token') ~ '^[1-9][0-9]{0,18}$'
  and expected_intent ?& array['protocol_version','fleet_run_id','driver_operation_id',
    'original_global_fence_token','overlay_kind','target_slot']
  and expected_intent-array['protocol_version','fleet_run_id','driver_operation_id',
    'original_global_fence_token','overlay_kind','target_slot']='{}'::jsonb
  and expected_identity ?& array['protocol_version','fleet_run_id','driver_operation_id',
    'original_global_fence_token','overlay_kind','route_set_digest','target_slot']
  and expected_identity-array['protocol_version','fleet_run_id','driver_operation_id',
    'original_global_fence_token','overlay_kind','route_set_digest','target_slot']='{}'::jsonb)
);

create table control.fleet_release_generation_retention_claims (
 driver_operation_id uuid not null,
 overlay_kind text not null,
 claim_fence bigint not null check(claim_fence>0),
 instance_owner uuid not null,
 claim_token uuid not null,
 claim_expires_at timestamptz not null,
 created_at timestamptz not null default now(),
 updated_at timestamptz not null default now(),
 primary key(driver_operation_id,overlay_kind),
 constraint fleet_release_generation_retention_claim_subject_fkey
  foreign key(driver_operation_id,overlay_kind) references
   control.fleet_release_generation_retention_subjects(driver_operation_id,overlay_kind) on delete restrict
);

create table control.fleet_release_generation_retention_attempts (
 driver_operation_id uuid not null,
 overlay_kind text not null,
 claim_fence bigint not null check(claim_fence>0),
 instance_owner uuid not null,
 claim_token_digest text not null check(claim_token_digest ~ '^[0-9a-f]{64}$'),
 resolution text not null check(resolution in
  ('deleted','already_absent','protected_current','identity_mismatch')),
 evidence jsonb not null check(jsonb_typeof(evidence)='object' and pg_column_size(evidence)<=16384),
 finished_at timestamptz not null default now(),
 primary key(driver_operation_id,overlay_kind,claim_fence),
 constraint fleet_release_generation_retention_attempt_subject_fkey
  foreign key(driver_operation_id,overlay_kind) references
   control.fleet_release_generation_retention_subjects(driver_operation_id,overlay_kind) on delete restrict
);

create function control.reject_fleet_release_generation_retention_mutation()
returns trigger language plpgsql set search_path=pg_catalog,control as $function$
begin
 raise exception 'release generation retention evidence is immutable' using errcode='55000';
end $function$;

create trigger fleet_release_generation_retention_subjects_immutable
 before update or delete on control.fleet_release_generation_retention_subjects
 for each row execute function control.reject_fleet_release_generation_retention_mutation();
create trigger fleet_release_generation_retention_attempts_immutable
 before update or delete on control.fleet_release_generation_retention_attempts
 for each row execute function control.reject_fleet_release_generation_retention_mutation();

create function control.materialize_fleet_release_generation_retention_subjects()
returns trigger language plpgsql set search_path=pg_catalog,control as $function$
declare p control.fleet_release_route_publications%rowtype; authoritative timestamptz;
begin
 if tg_table_name='fleet_release_route_publication_completions' then
  select * into strict p from control.fleet_release_route_publications
   where driver_operation_id=new.driver_operation_id;
  authoritative:=new.completed_at;
  insert into control.fleet_release_generation_retention_subjects(
   driver_operation_id,fleet_run_id,overlay_kind,selector,directory_device,directory_inode,
   route_count,expected_intent,expected_identity,source_kind,applied_candidate,
   authoritative_at,retention_not_before)
  values
   (p.driver_operation_id,p.fleet_run_id,'maintenance',p.maintenance_selector,
    p.maintenance_directory_device,p.maintenance_directory_inode,p.snapshot_count,
    jsonb_build_object('protocol_version',1,'fleet_run_id',p.fleet_run_id,
     'driver_operation_id',p.driver_operation_id,'original_global_fence_token',p.original_global_fence_token,
     'overlay_kind','maintenance','target_slot',p.target_slot),
    jsonb_build_object('protocol_version',1,'fleet_run_id',p.fleet_run_id,
     'driver_operation_id',p.driver_operation_id,'original_global_fence_token',p.original_global_fence_token,
     'overlay_kind','maintenance','route_set_digest',p.maintenance_route_set_digest,'target_slot',p.target_slot),
    'completion',false,authoritative,authoritative+interval '30 days'),
   (p.driver_operation_id,p.fleet_run_id,'candidate',new.candidate_selector,
    new.candidate_directory_device,new.candidate_directory_inode,p.snapshot_count,
    jsonb_build_object('protocol_version',1,'fleet_run_id',p.fleet_run_id,
     'driver_operation_id',p.driver_operation_id,'original_global_fence_token',new.original_global_fence_token,
     'overlay_kind','candidate','target_slot',new.target_slot),
    jsonb_build_object('protocol_version',1,'fleet_run_id',p.fleet_run_id,
     'driver_operation_id',p.driver_operation_id,'original_global_fence_token',new.original_global_fence_token,
     'overlay_kind','candidate','route_set_digest',new.candidate_route_set_digest,'target_slot',new.target_slot),
    'completion',true,authoritative,authoritative+interval '30 days')
  on conflict(driver_operation_id,overlay_kind) do nothing;
 elsif tg_table_name='fleet_release_route_publication_recovery_terminals'
  and new.resolution_kind='prior' then
  select * into strict p from control.fleet_release_route_publications
   where driver_operation_id=new.driver_operation_id;
  if exists(select 1 from control.fleet_release_route_publication_recovery_resolutions r
    where r.driver_operation_id=new.driver_operation_id and r.claim_fence=new.claim_fence
     and r.resolution_kind='prior' and r.claim_mode='restore_prior') then
   insert into control.fleet_release_generation_retention_subjects(
    driver_operation_id,fleet_run_id,overlay_kind,selector,directory_device,directory_inode,
    route_count,expected_intent,expected_identity,source_kind,applied_candidate,
    authoritative_at,retention_not_before)
   values(p.driver_operation_id,p.fleet_run_id,'maintenance',p.maintenance_selector,
    p.maintenance_directory_device,p.maintenance_directory_inode,p.snapshot_count,
    jsonb_build_object('protocol_version',1,'fleet_run_id',p.fleet_run_id,
     'driver_operation_id',p.driver_operation_id,'original_global_fence_token',p.original_global_fence_token,
     'overlay_kind','maintenance','target_slot',p.target_slot),
    jsonb_build_object('protocol_version',1,'fleet_run_id',p.fleet_run_id,
     'driver_operation_id',p.driver_operation_id,'original_global_fence_token',p.original_global_fence_token,
     'overlay_kind','maintenance','route_set_digest',p.maintenance_route_set_digest,'target_slot',p.target_slot),
    'recovery_prior',false,new.terminal_at,new.terminal_at+interval '30 days')
   on conflict(driver_operation_id,overlay_kind) do nothing;
  end if;
 end if;
 return new;
end $function$;

create trigger fleet_release_generation_retention_completion_materialize
 after insert on control.fleet_release_route_publication_completions
 for each row execute function control.materialize_fleet_release_generation_retention_subjects();
create trigger fleet_release_generation_retention_terminal_materialize
 after insert on control.fleet_release_route_publication_recovery_terminals
 for each row execute function control.materialize_fleet_release_generation_retention_subjects();

-- Backfill exact subjects already made terminal by migrations 0036/0037.
insert into control.fleet_release_generation_retention_subjects(
 driver_operation_id,fleet_run_id,overlay_kind,selector,directory_device,directory_inode,
 route_count,expected_intent,expected_identity,source_kind,applied_candidate,
 authoritative_at,retention_not_before)
select p.driver_operation_id,p.fleet_run_id,k.overlay_kind,
 case when k.overlay_kind='maintenance' then p.maintenance_selector else c.candidate_selector end,
 case when k.overlay_kind='maintenance' then p.maintenance_directory_device else c.candidate_directory_device end,
 case when k.overlay_kind='maintenance' then p.maintenance_directory_inode else c.candidate_directory_inode end,
 p.snapshot_count,
 jsonb_build_object('protocol_version',1,'fleet_run_id',p.fleet_run_id,
  'driver_operation_id',p.driver_operation_id,'original_global_fence_token',c.original_global_fence_token,
  'overlay_kind',k.overlay_kind,'target_slot',c.target_slot),
 jsonb_build_object('protocol_version',1,'fleet_run_id',p.fleet_run_id,
  'driver_operation_id',p.driver_operation_id,'original_global_fence_token',c.original_global_fence_token,
  'overlay_kind',k.overlay_kind,'route_set_digest',case when k.overlay_kind='maintenance'
    then p.maintenance_route_set_digest else c.candidate_route_set_digest end,'target_slot',c.target_slot),
 'completion',k.overlay_kind='candidate',c.completed_at,c.completed_at+interval '30 days'
from control.fleet_release_route_publication_completions c
join control.fleet_release_route_publications p
 on p.driver_operation_id=c.driver_operation_id and p.fleet_run_id=c.fleet_run_id
cross join (values('maintenance'),('candidate')) k(overlay_kind)
on conflict(driver_operation_id,overlay_kind) do nothing;

insert into control.fleet_release_generation_retention_subjects(
 driver_operation_id,fleet_run_id,overlay_kind,selector,directory_device,directory_inode,
 route_count,expected_intent,expected_identity,source_kind,applied_candidate,
 authoritative_at,retention_not_before)
select p.driver_operation_id,p.fleet_run_id,'maintenance',p.maintenance_selector,
 p.maintenance_directory_device,p.maintenance_directory_inode,p.snapshot_count,
 jsonb_build_object('protocol_version',1,'fleet_run_id',p.fleet_run_id,
  'driver_operation_id',p.driver_operation_id,'original_global_fence_token',p.original_global_fence_token,
  'overlay_kind','maintenance','target_slot',p.target_slot),
 jsonb_build_object('protocol_version',1,'fleet_run_id',p.fleet_run_id,
  'driver_operation_id',p.driver_operation_id,'original_global_fence_token',p.original_global_fence_token,
  'overlay_kind','maintenance','route_set_digest',p.maintenance_route_set_digest,'target_slot',p.target_slot),
 'recovery_prior',false,t.terminal_at,t.terminal_at+interval '30 days'
from control.fleet_release_route_publication_recovery_terminals t
join control.fleet_release_route_publication_recovery_resolutions r
 on r.driver_operation_id=t.driver_operation_id and r.claim_fence=t.claim_fence
 and r.resolution_kind=t.resolution_kind
join control.fleet_release_route_publications p
 on p.driver_operation_id=t.driver_operation_id and p.fleet_run_id=t.fleet_run_id
where t.resolution_kind='prior' and r.claim_mode='restore_prior'
on conflict(driver_operation_id,overlay_kind) do nothing;

create function control.generation_retention_protected_selectors()
returns table(selector text) language sql stable security definer set search_path=pg_catalog,control as $function$
 with universal_applied_raw as (
  select p.selector,p.observed_at authoritative_at,p.publication_id::text identity
   from control.workshop_route_set_publications p where p.phase='completed'
  union all
  select p.selector,r.recorded_at,p.publication_id::text
   from control.workshop_route_set_publications p
   join control.workshop_route_set_publication_resolutions r
    on r.publication_id=p.publication_id and r.reconciliation_claim_fence=p.recovery_terminal_claim_fence
     and r.reconciliation_operation_id=p.recovery_terminal_operation_id
     and r.reconciliation_operation_attempt=p.recovery_terminal_operation_attempt
     and r.reconciliation_operation_lease_owner=p.recovery_terminal_operation_lease_owner
     and r.resolution_kind=p.recovery_terminal_kind
   where p.recovery_terminal_kind='candidate'
  union all
  select p.selector,r.recorded_at,p.publication_id::text
   from control.workshop_route_set_startup_recovery_terminals t
   join control.workshop_route_set_startup_recovery_resolutions r
    on r.publication_id=t.publication_id and r.claim_fence=t.claim_fence
     and r.reconciliation_owner=t.reconciliation_owner and r.resolution_kind=t.resolution_kind
   join control.workshop_route_set_publications p on p.publication_id=t.publication_id
   where t.resolution_kind='candidate'
 ), applied as (
  select selector,max(authoritative_at) authoritative_at,max(identity) identity
   from universal_applied_raw group by selector
  union all
  select s.selector,s.authoritative_at,s.driver_operation_id::text
   from control.fleet_release_generation_retention_subjects s where s.applied_candidate
 )
 select applied.selector from applied
 order by authoritative_at desc,identity desc,selector desc limit 2
$function$;

create function control.fleet_release_route_publication_is_terminal(p_driver_operation_id uuid)
returns boolean language sql stable security definer set search_path=pg_catalog,control as $function$
 select exists(select 1 from control.fleet_release_route_publication_completions c
   where c.driver_operation_id=p_driver_operation_id)
  or exists(select 1 from control.fleet_release_route_publication_recovery_terminals t
   where t.driver_operation_id=p_driver_operation_id)
$function$;

create function control.route_set_generation_publication_is_terminal(p_publication_id uuid)
returns boolean language sql stable security definer set search_path=pg_catalog,control as $function$
 select exists(select 1 from control.workshop_route_set_publications p
   where p.publication_id=p_publication_id and p.phase='completed')
  or exists(select 1 from control.workshop_route_set_publications p
   join control.workshop_route_set_publication_resolutions r
    on r.publication_id=p.publication_id
     and r.reconciliation_claim_fence=p.recovery_terminal_claim_fence
     and r.reconciliation_operation_id=p.recovery_terminal_operation_id
     and r.reconciliation_operation_attempt=p.recovery_terminal_operation_attempt
     and r.reconciliation_operation_lease_owner=p.recovery_terminal_operation_lease_owner
     and r.resolution_kind=p.recovery_terminal_kind
   where p.publication_id=p_publication_id and p.recovery_terminal_at is not null)
  or exists(select 1 from control.workshop_route_set_startup_recovery_terminals t
   join control.workshop_route_set_startup_recovery_resolutions r
    on r.publication_id=t.publication_id and r.claim_fence=t.claim_fence
     and r.reconciliation_owner=t.reconciliation_owner and r.resolution_kind=t.resolution_kind
   where t.publication_id=p_publication_id)
$function$;

create function control.valid_fleet_release_retention_identity(p_identity jsonb)
returns boolean language sql immutable security definer set search_path=pg_catalog,control as $function$
 select jsonb_typeof(p_identity)='object'
  and p_identity ?& array['protocol_version','fleet_run_id','driver_operation_id',
   'original_global_fence_token','overlay_kind','route_set_digest','target_slot']
  and p_identity-array['protocol_version','fleet_run_id','driver_operation_id',
   'original_global_fence_token','overlay_kind','route_set_digest','target_slot']='{}'::jsonb
  and p_identity->'protocol_version'='1'::jsonb
  and p_identity->>'fleet_run_id' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
  and p_identity->>'driver_operation_id' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
  and p_identity->>'original_global_fence_token' ~ '^[1-9][0-9]{0,18}$'
  and p_identity->>'overlay_kind' in ('maintenance','candidate')
  and p_identity->>'route_set_digest' ~ '^sha256:[0-9a-f]{64}$'
  and p_identity->>'target_slot' in ('blue','green')
$function$;

create or replace function control.route_set_generation_retention_eligible(p_publication_id uuid)
returns boolean language sql stable security definer set search_path=pg_catalog,control as $function$
 select exists(select 1 from control.workshop_route_set_publications p
  where p.publication_id=p_publication_id and p.retention_not_before<=now()
   and p.selector<>'generations/boot-live' and p.sealed_count=p.snapshot_count
   and p.route_set_digest is not null and p.candidate_directory_device is not null
   and p.candidate_directory_inode is not null
   and control.route_set_generation_publication_is_terminal(p.publication_id)
   and not exists(select 1 from control.generation_retention_protected_selectors() x
    where x.selector=p.selector)
   and not exists(select 1 from control.route_set_generation_retention_attempts a
    where a.publication_id=p.publication_id and a.resolution in ('deleted','already_absent'))
   and not exists(select 1 from control.workshop_route_set_publications u
    where u.publication_id<>p.publication_id and p.selector in (u.selector,u.prior_selector)
     and not control.route_set_generation_publication_is_terminal(u.publication_id))
   and not exists(select 1 from control.fleet_release_route_publications r
    where p.selector in (r.prior_selector,r.maintenance_selector,r.candidate_selector)
     and not control.fleet_release_route_publication_is_terminal(r.driver_operation_id))
   and not exists(select 1 from control.workshop_route_startup_publications s
    where s.finalized_at is null and p.selector in (s.prior_selector,s.staging_selector)))
$function$;

create function control.fleet_release_generation_retention_eligible(
 p_driver_operation_id uuid,p_overlay_kind text
) returns boolean language sql stable security definer set search_path=pg_catalog,control as $function$
 select exists(select 1 from control.fleet_release_generation_retention_subjects s
  where s.driver_operation_id=p_driver_operation_id and s.overlay_kind=p_overlay_kind
   and s.retention_not_before<=now()
   and not exists(select 1 from control.generation_retention_protected_selectors() x
    where x.selector=s.selector)
   and not exists(select 1 from control.fleet_release_generation_retention_attempts a
    where a.driver_operation_id=s.driver_operation_id and a.overlay_kind=s.overlay_kind
     and a.resolution in ('deleted','already_absent'))
   and not exists(select 1 from control.workshop_route_set_publications u
    where s.selector in (u.selector,u.prior_selector)
     and not control.route_set_generation_publication_is_terminal(u.publication_id))
   and not exists(select 1 from control.fleet_release_route_publications r
    where r.driver_operation_id<>s.driver_operation_id
     and s.selector in (r.prior_selector,r.maintenance_selector,r.candidate_selector)
     and not control.fleet_release_route_publication_is_terminal(r.driver_operation_id))
   and not exists(select 1 from control.workshop_route_startup_publications p
    where p.finalized_at is null and s.selector in (p.prior_selector,p.staging_selector)))
$function$;

create function control.discover_fleet_release_generation_retention_candidates(
 p_after_driver_operation_id uuid,p_after_overlay_kind text,p_limit integer
) returns table(driver_operation_id uuid,overlay_kind text,selector text,retention_not_before timestamptz)
language plpgsql stable security definer set search_path=pg_catalog,control as $function$
begin
 if p_limit is null or p_limit not between 1 and 100
  or (p_after_driver_operation_id is null)<>(p_after_overlay_kind is null)
  or (p_after_overlay_kind is not null and p_after_overlay_kind not in ('maintenance','candidate')) then return; end if;
 if not exists(select 1 from control.route_set_publication_protocol_state
   where singleton and mode='generation_v1') then return; end if;
 return query select s.driver_operation_id,s.overlay_kind,s.selector,s.retention_not_before
 from control.fleet_release_generation_retention_subjects s
 where (p_after_driver_operation_id is null or
   (s.driver_operation_id,case s.overlay_kind when 'candidate' then 0 else 1 end)>
   (p_after_driver_operation_id,case p_after_overlay_kind when 'candidate' then 0 else 1 end))
  and control.fleet_release_generation_retention_eligible(s.driver_operation_id,s.overlay_kind)
 order by s.driver_operation_id,case s.overlay_kind when 'candidate' then 0 else 1 end limit p_limit;
end $function$;

create function control.claim_fleet_release_generation_retention(
 p_driver_operation_id uuid,p_overlay_kind text,p_instance_owner uuid,p_claim_token uuid,p_ttl_seconds integer
) returns table(outcome text,claim_fence bigint,fleet_run_id uuid,selector text,directory_device bigint,
 directory_inode bigint,expected_intent jsonb,expected_identity jsonb,route_count integer)
language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_mode text; v_global control.deployment_driver_resource_leases%rowtype;
 v_subject control.fleet_release_generation_retention_subjects%rowtype;
 v_claim control.fleet_release_generation_retention_claims%rowtype; v_fence bigint; v_expiry timestamptz;
begin
 if p_driver_operation_id is null or p_overlay_kind is null or p_overlay_kind not in ('maintenance','candidate')
  or p_instance_owner is null or p_claim_token is null or p_ttl_seconds is null
  or p_ttl_seconds not between 30 and 3600 then
  return query select 'invalid',null::bigint,null::uuid,null::text,null::bigint,null::bigint,
   null::jsonb,null::jsonb,null::integer; return; end if;
 select mode into strict v_mode from control.route_set_publication_protocol_state where singleton for update;
 select * into strict v_global from control.deployment_driver_resource_leases
  where resource_key='runtime/shared-odoo' for update;
 select * into v_subject from control.fleet_release_generation_retention_subjects
  where driver_operation_id=p_driver_operation_id and overlay_kind=p_overlay_kind for update;
 if not found then return query select 'not_found',null::bigint,null::uuid,null::text,null::bigint,
  null::bigint,null::jsonb,null::jsonb,null::integer; return; end if;
 if v_mode<>'generation_v1' or not control.fleet_release_generation_retention_eligible(
   p_driver_operation_id,p_overlay_kind) then
  return query select 'ineligible',null::bigint,v_subject.fleet_run_id,v_subject.selector,
   v_subject.directory_device,v_subject.directory_inode,v_subject.expected_intent,
   v_subject.expected_identity,v_subject.route_count; return; end if;
 v_expiry:=now()+make_interval(secs=>p_ttl_seconds);
 select * into v_claim from control.fleet_release_generation_retention_claims
  where driver_operation_id=p_driver_operation_id and overlay_kind=p_overlay_kind for update;
 if v_global.state='held' and v_global.authority_kind='release-retention'
  and v_global.driver_operation_id=p_driver_operation_id
  and v_global.lease_owner=p_instance_owner and v_global.lease_token=p_claim_token
  and v_global.lease_expires_at>now() and found and v_claim.claim_fence=v_global.fence_token
  and v_claim.instance_owner=p_instance_owner and v_claim.claim_token=p_claim_token
  and v_claim.claim_expires_at>now() then
  update control.deployment_driver_resource_leases set lease_expires_at=v_expiry,
   heartbeat_at=now(),updated_at=now() where resource_key='runtime/shared-odoo';
  update control.fleet_release_generation_retention_claims set claim_expires_at=v_expiry,
   updated_at=now() where driver_operation_id=p_driver_operation_id and overlay_kind=p_overlay_kind;
  return query select 'replay',v_global.fence_token,v_subject.fleet_run_id,v_subject.selector,
   v_subject.directory_device,v_subject.directory_inode,v_subject.expected_intent,
   v_subject.expected_identity,v_subject.route_count; return;
 end if;
 if v_global.state='held' and v_global.authority_kind='release-retention'
  and v_global.driver_operation_id=p_driver_operation_id and found
  and v_global.lease_expires_at<=now() and v_claim.claim_expires_at<=now() then
  v_fence:=v_global.fence_token+1;
  update control.deployment_driver_resource_leases set lease_owner=p_instance_owner,
   lease_token=p_claim_token,lease_expires_at=v_expiry,heartbeat_at=now(),fence_token=v_fence,
   updated_at=now() where resource_key='runtime/shared-odoo';
  update control.fleet_release_generation_retention_claims set claim_fence=v_fence,
   instance_owner=p_instance_owner,claim_token=p_claim_token,claim_expires_at=v_expiry,updated_at=now()
   where driver_operation_id=p_driver_operation_id and overlay_kind=p_overlay_kind;
  return query select 'acquired',v_fence,v_subject.fleet_run_id,v_subject.selector,
   v_subject.directory_device,v_subject.directory_inode,v_subject.expected_intent,
   v_subject.expected_identity,v_subject.route_count; return;
 end if;
 if v_global.state<>'idle' then return query select 'busy',null::bigint,v_subject.fleet_run_id,
  v_subject.selector,v_subject.directory_device,v_subject.directory_inode,null::jsonb,null::jsonb,
  v_subject.route_count; return; end if;
 v_fence:=v_global.fence_token+1;
 update control.deployment_driver_resource_leases set state='held',authority_kind='release-retention',
  driver_operation_id=p_driver_operation_id,effect_run_id=null,route_set_publication_id=null,
  lease_owner=p_instance_owner,lease_token=p_claim_token,lease_expires_at=v_expiry,
  heartbeat_at=now(),quarantined_at=null,safe_error=null,fence_token=v_fence,updated_at=now()
 where resource_key='runtime/shared-odoo' and state='idle';
 insert into control.fleet_release_generation_retention_claims(driver_operation_id,overlay_kind,
  claim_fence,instance_owner,claim_token,claim_expires_at)
 values(p_driver_operation_id,p_overlay_kind,v_fence,p_instance_owner,p_claim_token,v_expiry)
 on conflict(driver_operation_id,overlay_kind) do update set claim_fence=excluded.claim_fence,
  instance_owner=excluded.instance_owner,claim_token=excluded.claim_token,
  claim_expires_at=excluded.claim_expires_at,updated_at=now();
 return query select 'acquired',v_fence,v_subject.fleet_run_id,v_subject.selector,
  v_subject.directory_device,v_subject.directory_inode,v_subject.expected_intent,
  v_subject.expected_identity,v_subject.route_count;
end $function$;

create function control.renew_fleet_release_generation_retention_claim(
 p_driver_operation_id uuid,p_overlay_kind text,p_instance_owner uuid,p_claim_token uuid,
 p_claim_fence bigint,p_ttl_seconds integer
) returns boolean language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_expiry timestamptz; v_global_count integer; v_claim_count integer;
begin
 if p_driver_operation_id is null or p_overlay_kind is null
  or p_overlay_kind not in ('maintenance','candidate') or p_instance_owner is null
  or p_claim_token is null or p_claim_fence is null or p_claim_fence<=0
  or p_ttl_seconds is null or p_ttl_seconds not between 30 and 3600 then return false; end if;
 perform 1 from control.route_set_publication_protocol_state where singleton for update;
 perform 1 from control.deployment_driver_resource_leases
  where resource_key='runtime/shared-odoo' for update;
 if not exists(select 1 from control.deployment_driver_resource_leases g
  join control.fleet_release_generation_retention_claims c
   on c.driver_operation_id=g.driver_operation_id
  where g.resource_key='runtime/shared-odoo' and g.state='held'
   and g.authority_kind='release-retention' and g.driver_operation_id=p_driver_operation_id
   and c.overlay_kind=p_overlay_kind and g.lease_owner=p_instance_owner
   and g.lease_token=p_claim_token and g.fence_token=p_claim_fence
   and c.claim_fence=p_claim_fence and c.instance_owner=p_instance_owner
   and c.claim_token=p_claim_token and g.lease_expires_at>now() and c.claim_expires_at>now())
  then return false; end if;
 v_expiry:=now()+make_interval(secs=>p_ttl_seconds);
 update control.deployment_driver_resource_leases set lease_expires_at=v_expiry,
  heartbeat_at=now(),updated_at=now() where resource_key='runtime/shared-odoo'
  and state='held' and authority_kind='release-retention'
  and driver_operation_id=p_driver_operation_id and lease_owner=p_instance_owner
  and lease_token=p_claim_token and fence_token=p_claim_fence;
 get diagnostics v_global_count=row_count;
 update control.fleet_release_generation_retention_claims set claim_expires_at=v_expiry,
  updated_at=now() where driver_operation_id=p_driver_operation_id and overlay_kind=p_overlay_kind
  and claim_fence=p_claim_fence and instance_owner=p_instance_owner and claim_token=p_claim_token;
 get diagnostics v_claim_count=row_count;
 if v_global_count<>1 or v_claim_count<>1 then raise exception
  'release generation retention renewal authority drifted' using errcode='40001'; end if;
 return true;
end $function$;

create function control.finish_fleet_release_generation_retention(
 p_driver_operation_id uuid,p_overlay_kind text,p_instance_owner uuid,p_claim_token uuid,
 p_claim_fence bigint,p_resolution text,p_evidence jsonb
) returns text language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_global control.deployment_driver_resource_leases%rowtype;
 v_subject control.fleet_release_generation_retention_subjects%rowtype;
 v_attempt control.fleet_release_generation_retention_attempts%rowtype;
 v_keys integer; v_changed integer;
begin
 if p_driver_operation_id is null or p_overlay_kind is null
  or p_overlay_kind not in ('maintenance','candidate') or p_instance_owner is null
  or p_claim_token is null or p_claim_fence is null or p_claim_fence<=0
  or p_resolution is null or p_resolution not in
   ('deleted','already_absent','protected_current','identity_mismatch')
  or jsonb_typeof(p_evidence) is distinct from 'object' or pg_column_size(p_evidence)>16384
  then return 'invalid'; end if;
 perform 1 from control.route_set_publication_protocol_state where singleton for update;
 select * into v_attempt from control.fleet_release_generation_retention_attempts
  where driver_operation_id=p_driver_operation_id and overlay_kind=p_overlay_kind
   and claim_fence=p_claim_fence;
 if found then return case when v_attempt.instance_owner=p_instance_owner
   and v_attempt.claim_token_digest=encode(public.digest(uuid_send(p_claim_token),'sha256'),'hex')
   and v_attempt.resolution=p_resolution and v_attempt.evidence=p_evidence
  then 'replay' else 'conflict' end; end if;
 select * into strict v_global from control.deployment_driver_resource_leases
  where resource_key='runtime/shared-odoo' for update;
 select * into v_subject from control.fleet_release_generation_retention_subjects
  where driver_operation_id=p_driver_operation_id and overlay_kind=p_overlay_kind for update;
 if not found then return 'not_found'; end if;
 if v_global.state<>'held' or v_global.authority_kind<>'release-retention'
  or v_global.driver_operation_id<>p_driver_operation_id
  or v_global.lease_owner<>p_instance_owner or v_global.lease_token<>p_claim_token
  or v_global.fence_token<>p_claim_fence or v_global.lease_expires_at<=now()
  or not exists(select 1 from control.fleet_release_generation_retention_claims c
   where c.driver_operation_id=p_driver_operation_id and c.overlay_kind=p_overlay_kind
    and c.claim_fence=p_claim_fence and c.instance_owner=p_instance_owner
    and c.claim_token=p_claim_token and c.claim_expires_at>now()) then return 'claim_lost'; end if;
 select count(*) into v_keys from jsonb_object_keys(p_evidence);
 if v_keys<>15 or p_evidence->'protocol_version' is distinct from '1'::jsonb
  or p_evidence->'driver_operation_id' is distinct from to_jsonb(p_driver_operation_id)
  or p_evidence->'overlay_kind' is distinct from to_jsonb(p_overlay_kind)
  or p_evidence->'claim_fence' is distinct from to_jsonb(p_claim_fence)
  or p_evidence->'resolution' is distinct from to_jsonb(p_resolution)
  or p_evidence->'selector' is distinct from to_jsonb(v_subject.selector)
  or p_evidence->'expected_intent' is distinct from v_subject.expected_intent
  or p_evidence->'expected_identity' is distinct from v_subject.expected_identity
  or jsonb_typeof(p_evidence->'observed_current_selector') is distinct from 'string'
  or (p_evidence->>'observed_current_selector') !~ '^generations/[A-Za-z0-9][A-Za-z0-9-]{0,63}$'
  or not control.valid_route_set_prior_selector_identity(
    p_evidence->>'observed_current_selector',p_evidence->'observed_current_identity')
  or jsonb_typeof(p_evidence->'target_present') is distinct from 'boolean'
  or not (p_evidence ?& array['observed_target_device','observed_target_inode',
    'mismatch_kind','observed_target_identity']) then return 'evidence_mismatch'; end if;
 if (p_resolution in ('deleted','already_absent','identity_mismatch')
    and p_evidence->>'observed_current_selector'=v_subject.selector)
  or (p_resolution='protected_current' and (
    p_evidence->>'observed_current_selector' is distinct from v_subject.selector
    or p_evidence->'observed_current_identity' is distinct from v_subject.expected_identity
    or p_evidence->'target_present' is distinct from 'true'::jsonb
    or p_evidence->'observed_target_device' is distinct from to_jsonb(v_subject.directory_device)
    or p_evidence->'observed_target_inode' is distinct from to_jsonb(v_subject.directory_inode)))
  or (p_resolution='deleted' and (p_evidence->'target_present' is distinct from 'true'::jsonb
    or p_evidence->'observed_target_device' is distinct from to_jsonb(v_subject.directory_device)
    or p_evidence->'observed_target_inode' is distinct from to_jsonb(v_subject.directory_inode)))
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
    or p_evidence->>'mismatch_kind' not in
      ('directory_identity','content_identity','content_integrity')
    or (p_evidence->>'mismatch_kind'='directory_identity' and (
      p_evidence->'observed_target_identity' is distinct from 'null'::jsonb
      or (p_evidence->'observed_target_device'=to_jsonb(v_subject.directory_device)
       and p_evidence->'observed_target_inode'=to_jsonb(v_subject.directory_inode))))
    or (p_evidence->>'mismatch_kind'='content_identity' and (
      p_evidence->'observed_target_device' is distinct from to_jsonb(v_subject.directory_device)
      or p_evidence->'observed_target_inode' is distinct from to_jsonb(v_subject.directory_inode)
      or not control.valid_fleet_release_retention_identity(
       p_evidence->'observed_target_identity')
      or p_evidence->'observed_target_identity'=v_subject.expected_identity))
    or (p_evidence->>'mismatch_kind'='content_integrity' and (
      p_evidence->'observed_target_device' is distinct from to_jsonb(v_subject.directory_device)
      or p_evidence->'observed_target_inode' is distinct from to_jsonb(v_subject.directory_inode)
      or p_evidence->'observed_target_identity' is distinct from v_subject.expected_identity)))) then
  return 'evidence_mismatch'; end if;
 insert into control.fleet_release_generation_retention_attempts(driver_operation_id,
  overlay_kind,claim_fence,instance_owner,claim_token_digest,resolution,evidence)
 values(p_driver_operation_id,p_overlay_kind,p_claim_fence,p_instance_owner,
  encode(public.digest(uuid_send(p_claim_token),'sha256'),'hex'),p_resolution,p_evidence);
 delete from control.fleet_release_generation_retention_claims
  where driver_operation_id=p_driver_operation_id and overlay_kind=p_overlay_kind
   and claim_fence=p_claim_fence;
 get diagnostics v_changed=row_count;
 if v_changed<>1 then raise exception 'release retention claim drifted' using errcode='40001'; end if;
 update control.deployment_driver_resource_leases set state='idle',authority_kind=null,
  driver_operation_id=null,effect_run_id=null,route_set_publication_id=null,
  lease_owner=null,lease_token=null,lease_expires_at=null,heartbeat_at=null,
  quarantined_at=null,safe_error=null,updated_at=now()
 where resource_key='runtime/shared-odoo' and state='held'
  and authority_kind='release-retention' and driver_operation_id=p_driver_operation_id
  and lease_owner=p_instance_owner and lease_token=p_claim_token and fence_token=p_claim_fence;
 get diagnostics v_changed=row_count;
 if v_changed<>1 then raise exception 'release retention global release drifted' using errcode='40001'; end if;
 return p_resolution;
end $function$;

revoke all on table control.fleet_release_generation_retention_subjects,
 control.fleet_release_generation_retention_claims,
 control.fleet_release_generation_retention_attempts from public;
revoke all on function control.reject_fleet_release_generation_retention_mutation() from public;
revoke all on function control.materialize_fleet_release_generation_retention_subjects() from public;
revoke all on function control.generation_retention_protected_selectors() from public;
revoke all on function control.fleet_release_route_publication_is_terminal(uuid) from public;
revoke all on function control.route_set_generation_publication_is_terminal(uuid) from public;
revoke all on function control.valid_fleet_release_retention_identity(jsonb) from public;
revoke all on function control.route_set_generation_retention_eligible(uuid) from public;
revoke all on function control.fleet_release_generation_retention_eligible(uuid,text) from public;
revoke all on function control.discover_fleet_release_generation_retention_candidates(uuid,text,integer) from public;
revoke all on function control.claim_fleet_release_generation_retention(uuid,text,uuid,uuid,integer) from public;
revoke all on function control.renew_fleet_release_generation_retention_claim(uuid,text,uuid,uuid,bigint,integer) from public;
revoke all on function control.finish_fleet_release_generation_retention(uuid,text,uuid,uuid,bigint,text,jsonb) from public;

do $migration$ declare v_role text; begin
 foreach v_role in array array['control_api','control_tenant_api','control_membership_worker',
  'control_provisioning_worker','control_invoice_worker','control_inventory_worker',
  'control_email_worker','control_reconciliation_worker','control_lifecycle_worker',
  'control_backup_scheduler','control_driver_ledger','control_release_worker','control_privacy_worker'] loop
  if exists(select 1 from pg_roles where rolname=v_role) then
   execute format('revoke all on table control.fleet_release_generation_retention_subjects, control.fleet_release_generation_retention_claims, control.fleet_release_generation_retention_attempts from %I',v_role);
   execute format('revoke all on function control.generation_retention_protected_selectors() from %I',v_role);
   execute format('revoke all on function control.fleet_release_route_publication_is_terminal(uuid) from %I',v_role);
   execute format('revoke all on function control.route_set_generation_publication_is_terminal(uuid) from %I',v_role);
   execute format('revoke all on function control.valid_fleet_release_retention_identity(jsonb) from %I',v_role);
   execute format('revoke all on function control.route_set_generation_retention_eligible(uuid) from %I',v_role);
   execute format('revoke all on function control.fleet_release_generation_retention_eligible(uuid,text) from %I',v_role);
  end if;
 end loop;
 if exists(select 1 from pg_roles where rolname='control_driver_ledger') then
  grant execute on function
   control.discover_fleet_release_generation_retention_candidates(uuid,text,integer),
   control.claim_fleet_release_generation_retention(uuid,text,uuid,uuid,integer),
   control.renew_fleet_release_generation_retention_claim(uuid,text,uuid,uuid,bigint,integer),
   control.finish_fleet_release_generation_retention(uuid,text,uuid,uuid,bigint,text,jsonb)
  to control_driver_ledger;
 end if;
end $migration$;

comment on table control.fleet_release_generation_retention_attempts is
'Immutable dormant evidence for exact release-overlay generation retention; database authority is insufficient without the shared host guard and a fresh non-current selector proof.';
