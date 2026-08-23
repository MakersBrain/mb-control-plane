-- Dormant, claim-authenticated access to the immutable protocol-v2 route
-- snapshot needed to rebuild a forward-only candidate_staging overlay.
-- This migration adds no writer, scheduler, or activation path.

create function control.read_interrupted_immutable_release_route_snapshot_batch(
 p_driver_operation_id uuid,p_control_operation_attempt integer,
 p_control_operation_lease_owner text,p_reconciliation_owner uuid,
 p_reconciliation_token uuid,p_claim_fence bigint,
 p_after_workshop_id uuid,p_limit integer
) returns table(outcome text,workshop_id uuid,database_id uuid,database_ref text,
 paperless_enabled boolean,generation bigint,projection_digest text,disposition text,
 canonical_projection jsonb,applied_rendered_digest text,applied_fence_token bigint,
 route_fence_token bigint,target_slot text)
language plpgsql security definer set search_path=pg_catalog,control as $function$
declare v_publication control.fleet_release_route_publications%rowtype;
 v_claim control.fleet_release_route_publication_recovery_claims%rowtype;
 v_snapshot_count integer; v_exact_count integer;
begin
 if p_driver_operation_id is null or p_control_operation_attempt is null
  or p_control_operation_attempt<=0 or p_control_operation_lease_owner is null
  or btrim(p_control_operation_lease_owner)='' or p_reconciliation_owner is null
  or p_reconciliation_token is null or p_claim_fence is null or p_claim_fence<=0
  or p_limit is null or p_limit<1 or p_limit>500
  or p_after_workshop_id='00000000-0000-0000-0000-000000000000'::uuid then
  return query select 'invalid'::text,null::uuid,null::uuid,null::text,null::boolean,
   null::bigint,null::text,null::text,null::jsonb,null::text,null::bigint,
   null::bigint,null::text;
  return;
 end if;
 if not control.lock_immutable_release_route_recovery_claim(
  p_driver_operation_id,p_control_operation_attempt,p_control_operation_lease_owner,
  p_reconciliation_owner,p_reconciliation_token,p_claim_fence) then
  return query select 'claim_lost'::text,null::uuid,null::uuid,null::text,null::boolean,
   null::bigint,null::text,null::text,null::jsonb,null::text,null::bigint,
   null::bigint,null::text;
  return;
 end if;
 select * into v_publication from control.fleet_release_route_publications
  where driver_operation_id=p_driver_operation_id;
 select * into v_claim from control.fleet_release_route_publication_recovery_claims
  where driver_operation_id=p_driver_operation_id and claim_fence=p_claim_fence
   and fleet_run_id=v_publication.fleet_run_id;
 if v_publication.driver_operation_id is null or v_claim.driver_operation_id is null
  or v_claim.claim_mode<>'forward_only'
  or v_publication.phase<>'quarantined'
  or v_publication.interrupted_phase<>'candidate_staging'
  or v_publication.external_effects_started_at is null then
  return query select 'wrong_phase'::text,null::uuid,null::uuid,null::text,null::boolean,
   null::bigint,null::text,null::text,null::jsonb,null::text,null::bigint,
   null::bigint,null::text;
  return;
 end if;
 select snapshot.snapshot_count,count(item.workshop_id)::integer
 into v_snapshot_count,v_exact_count
 from control.fleet_release_route_snapshots snapshot
 left join control.fleet_release_route_snapshot_items item
  on item.driver_operation_id=snapshot.driver_operation_id
  and item.fleet_run_id=snapshot.fleet_run_id
 left join control.fleet_release_route_publication_owners owner
  on owner.driver_operation_id=item.driver_operation_id
  and owner.workshop_id=item.workshop_id
  and owner.generation=item.generation
  and owner.projection_digest=item.projection_digest
  and owner.applied_rendered_digest=item.applied_rendered_digest
  and owner.applied_fence_token=item.applied_fence_token
  and owner.snapshot_route_fence_token=item.route_fence_token
 left join control.fleet_release_route_publication_recovery_route_heads head
  on head.driver_operation_id=owner.driver_operation_id
  and head.claim_fence=p_claim_fence and head.workshop_id=owner.workshop_id
  and head.applied_generation=item.generation
  and head.applied_digest=item.projection_digest
  and head.applied_disposition=item.disposition
  and head.applied_rendered_digest=item.applied_rendered_digest
  and head.applied_fence_token=item.applied_fence_token
  and head.desired_generation=item.generation
  and head.desired_digest=item.projection_digest
  and head.desired_disposition=item.disposition
 where snapshot.driver_operation_id=p_driver_operation_id
  and snapshot.fleet_run_id=v_publication.fleet_run_id
  and snapshot.protocol_version=2
  and snapshot.original_global_fence_token=v_publication.original_global_fence_token
  and owner.workshop_id is not null and head.workshop_id is not null
 group by snapshot.snapshot_count;
 if not found or v_exact_count<>v_snapshot_count
  or v_snapshot_count<>v_publication.snapshot_count then
  return query select 'wrong_phase'::text,null::uuid,null::uuid,null::text,null::boolean,
   null::bigint,null::text,null::text,null::jsonb,null::text,null::bigint,
   null::bigint,null::text;
  return;
 end if;
 if not exists(select 1 from control.fleet_release_route_snapshot_items item
   where item.driver_operation_id=p_driver_operation_id
    and (p_after_workshop_id is null or item.workshop_id>p_after_workshop_id)) then
  return query select 'complete'::text,null::uuid,null::uuid,null::text,null::boolean,
   null::bigint,null::text,null::text,null::jsonb,null::text,null::bigint,
   null::bigint,null::text;
  return;
 end if;
 return query select 'claimed'::text,item.workshop_id,item.database_id,item.database_ref,
  item.paperless_enabled,item.generation,item.projection_digest,item.disposition,
  item.canonical_projection,item.applied_rendered_digest,item.applied_fence_token,
  item.route_fence_token,v_publication.target_slot
 from control.fleet_release_route_snapshot_items item
 join control.fleet_release_route_publication_owners owner
  on owner.driver_operation_id=item.driver_operation_id
  and owner.workshop_id=item.workshop_id
  and owner.generation=item.generation
  and owner.projection_digest=item.projection_digest
  and owner.applied_rendered_digest=item.applied_rendered_digest
  and owner.applied_fence_token=item.applied_fence_token
  and owner.snapshot_route_fence_token=item.route_fence_token
 join control.fleet_release_route_publication_recovery_route_heads head
  on head.driver_operation_id=owner.driver_operation_id
  and head.claim_fence=p_claim_fence and head.workshop_id=owner.workshop_id
  and head.applied_generation=item.generation
  and head.applied_digest=item.projection_digest
  and head.applied_disposition=item.disposition
  and head.applied_rendered_digest=item.applied_rendered_digest
  and head.applied_fence_token=item.applied_fence_token
  and head.desired_generation=item.generation
  and head.desired_digest=item.projection_digest
  and head.desired_disposition=item.disposition
 where item.driver_operation_id=p_driver_operation_id
  and item.fleet_run_id=v_publication.fleet_run_id
  and (p_after_workshop_id is null or item.workshop_id>p_after_workshop_id)
 order by item.workshop_id limit p_limit;
end $function$;

revoke all on function control.read_interrupted_immutable_release_route_snapshot_batch(
 uuid,integer,text,uuid,uuid,bigint,uuid,integer) from public;

do $migration$ declare v_role text; begin
 foreach v_role in array array['control_api','control_tenant_api','control_membership_worker',
  'control_provisioning_worker','control_invoice_worker','control_inventory_worker',
  'control_email_worker','control_reconciliation_worker','control_lifecycle_worker',
  'control_backup_scheduler','control_driver_ledger','control_release_worker','control_privacy_worker'] loop
  if exists(select 1 from pg_roles where rolname=v_role) then
   execute format('revoke all on function control.read_interrupted_immutable_release_route_snapshot_batch(uuid,integer,text,uuid,uuid,bigint,uuid,integer) from %I',v_role);
  end if;
 end loop;
 if exists(select 1 from pg_roles where rolname='control_driver_ledger') then
  grant execute on function control.read_interrupted_immutable_release_route_snapshot_batch(
   uuid,integer,text,uuid,uuid,bigint,uuid,integer) to control_driver_ledger;
 end if;
end $migration$;

comment on function control.read_interrupted_immutable_release_route_snapshot_batch(
 uuid,integer,text,uuid,uuid,bigint,uuid,integer) is
'Dormant claim-authenticated, keyset-paged immutable snapshot reader used only to rebuild an interrupted forward-only candidate staging overlay.';
