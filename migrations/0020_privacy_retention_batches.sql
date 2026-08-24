-- Fenced, resumable and snapshot-bounded privacy retention.
create sequence control.invitations_retention_sequence;
create sequence control.outbox_retention_sequence;
create sequence control.operations_retention_sequence;
alter table control.invitations add column retention_sequence bigint;
alter table control.outbox add column retention_sequence bigint;
alter table control.operations add column retention_sequence bigint;
update control.invitations set retention_sequence=nextval('control.invitations_retention_sequence');
update control.outbox set retention_sequence=nextval('control.outbox_retention_sequence');
update control.operations set retention_sequence=nextval('control.operations_retention_sequence');
alter table control.invitations alter column retention_sequence set not null, add unique(retention_sequence);
alter table control.outbox alter column retention_sequence set not null, add unique(retention_sequence);
alter table control.operations alter column retention_sequence set not null, add unique(retention_sequence);
alter sequence control.invitations_retention_sequence owned by control.invitations.retention_sequence;
alter sequence control.outbox_retention_sequence owned by control.outbox.retention_sequence;
alter sequence control.operations_retention_sequence owned by control.operations.retention_sequence;

-- Always assign after INSERT has acquired RowExclusive; explicit values cannot
-- forge a position behind a frozen high-water mark. Cursor keys are immutable.
create function control.maintain_retention_sequence() returns trigger language plpgsql
security definer set search_path=pg_catalog,control as $$
begin
 if tg_op='INSERT' then new.retention_sequence:=nextval(tg_argv[0]::regclass); return new; end if;
 if new.retention_sequence is distinct from old.retention_sequence then
  raise exception 'retention sequence is immutable' using errcode='23514';
 end if; return new;
end$$;
revoke all on function control.maintain_retention_sequence() from public;
create trigger invitations_retention_sequence_insert before insert on control.invitations for each row execute function control.maintain_retention_sequence('control.invitations_retention_sequence');
create trigger invitations_retention_sequence_update before update of retention_sequence on control.invitations for each row execute function control.maintain_retention_sequence();
create trigger outbox_retention_sequence_insert before insert on control.outbox for each row execute function control.maintain_retention_sequence('control.outbox_retention_sequence');
create trigger outbox_retention_sequence_update before update of retention_sequence on control.outbox for each row execute function control.maintain_retention_sequence();
create trigger operations_retention_sequence_insert before insert on control.operations for each row execute function control.maintain_retention_sequence('control.operations_retention_sequence');
create trigger operations_retention_sequence_update before update of retention_sequence on control.operations for each row execute function control.maintain_retention_sequence();

alter table control.retention_runs
 add column retention_phase text not null default 'invitations', add column cutoff_at timestamptz,
 add column invitation_high_water bigint, add column invitation_cursor bigint not null default 0,
 add column mail_high_water bigint, add column mail_cursor bigint not null default 0,
 add column operation_high_water bigint, add column operation_cursor bigint not null default 0,
 add column invitation_candidates bigint not null default 0, add column invitation_held bigint not null default 0,
 add column invitation_anonymized bigint not null default 0, add column mail_candidates bigint not null default 0,
 add column mail_held bigint not null default 0, add column mail_deleted bigint not null default 0,
 add column operation_candidates bigint not null default 0, add column operation_held bigint not null default 0,
 add column operation_redacted bigint not null default 0;
update control.retention_runs set state='failed',retention_phase='complete',
 evidence=evidence||jsonb_build_object('reason','legacy_unfenced_retention'),completed_at=coalesce(completed_at,now())
 where state='running';
update control.retention_runs set retention_phase='complete' where state in('completed','failed','blocked_approval');
alter table control.retention_runs
 add check(retention_phase in('invitations','mail-delivery','operations','complete')),
 add check((state='queued' and retention_phase<>'complete') or state='running' or
           (state in('completed','failed','blocked_approval') and retention_phase='complete')),
 add check((cutoff_at is null and invitation_high_water is null and mail_high_water is null and operation_high_water is null
            and invitation_cursor=0 and mail_cursor=0 and operation_cursor=0) or
           (cutoff_at is not null and invitation_high_water>=0 and mail_high_water>=0 and operation_high_water>=0
            and invitation_cursor between 0 and invitation_high_water and mail_cursor between 0 and mail_high_water
            and operation_cursor between 0 and operation_high_water)),
 add check(invitation_candidates>=0 and invitation_held between 0 and invitation_candidates
       and invitation_anonymized between 0 and invitation_candidates-invitation_held
       and mail_candidates>=0 and mail_held between 0 and mail_candidates
       and mail_deleted between 0 and mail_candidates-mail_held
       and operation_candidates>=0 and operation_held between 0 and operation_candidates
       and operation_redacted between 0 and operation_candidates-operation_held);

create function control.run_privacy_retention_batch(p_run_id uuid,p_operation_id uuid,p_operation_attempt integer,p_lease_owner text,p_batch_limit integer)
returns table(outcome text,phase text,considered integer,affected integer,held integer)
language plpgsql security definer set search_path=pg_catalog,control as $$
declare
 op control.operations%rowtype; r control.retention_runs%rowtype; ps text; pol jsonb;
 days_i integer; days_m integer; days_o integer; c record; n integer:=0; changed integer:=0; held_n integer:=0;
 rows_n bigint; last_seq bigint; is_held boolean; next_phase text; held_sets text[];
begin
 if p_run_id is null or p_operation_id is null or p_operation_attempt<1 or p_lease_owner is null
    or btrim(p_lease_owner)='' or length(p_lease_owner)>255 or p_batch_limit<1 or p_batch_limit>200 then
  raise exception 'invalid privacy retention batch identity' using errcode='22023'; end if;

 -- Lock the run before the initial table barrier, avoiding inversion with operation heartbeats.
 select x.* into r from control.retention_runs x where x.id=p_run_id and x.operation_id=p_operation_id for update;
 if not found then raise exception 'privacy retention run is not bound to the operation' using errcode='23503'; end if;
 if r.state in('queued','running') and r.policy_version is not null then
  select x.status,x.policy into ps,pol from control.retention_policy_versions x where x.version=r.policy_version for share;
  if not found then raise exception 'privacy retention policy is absent' using errcode='23503'; end if;
  if coalesce(pol#>>'{datasets,invitations,duration_days}','')!~'^[0-9]{1,5}$'
     or coalesce(pol#>>'{datasets,mail-delivery,duration_days}','')!~'^[0-9]{1,5}$'
     or coalesce(pol#>>'{datasets,operations,duration_days}','')!~'^[0-9]{1,5}$' then
   raise exception 'privacy retention policy durations are invalid' using errcode='23514'; end if;
  days_i:=(pol#>>'{datasets,invitations,duration_days}')::integer;
  days_m:=(pol#>>'{datasets,mail-delivery,duration_days}')::integer;
  days_o:=(pol#>>'{datasets,operations,duration_days}')::integer;
  if days_i>36500 or days_m>36500 or days_o>36500 then raise exception 'privacy retention policy duration exceeds bound' using errcode='23514'; end if;
 end if;
 -- SHARE waits out pre-existing writers and blocks later inserts until all three marks are frozen.
 if r.state in('queued','running') and r.policy_version is not null and (r.dry_run or ps='approved') and r.cutoff_at is null then
  lock table control.invitations,control.outbox,control.operations in share mode;
 end if;
 select x.* into op from control.operations x where x.id=p_operation_id and x.kind='privacy.retention'
  and x.queue='privacy-operations' and x.state='in_flight' and x.attempt=p_operation_attempt
  and x.leased_by=p_lease_owner and x.lease_expires_at>clock_timestamp()
  and x.payload->>'retention_run_id'=p_run_id::text for update;
 if not found then raise exception 'privacy retention operation lease is not current' using errcode='40001'; end if;
 if r.state='completed' then return query select 'complete','complete',0,0,0; return;
 elsif r.state='blocked_approval' then return query select 'blocked','complete',0,0,0; return;
 elsif r.state='failed' then return query select 'failed','complete',0,0,0; return;
 elsif r.state not in('queued','running') then raise exception 'privacy retention run state is invalid' using errcode='23514'; end if;
 if r.policy_version is null then
  update control.retention_runs set state='blocked_approval',retention_phase='complete',completed_at=now(),
   evidence=jsonb_build_object('reason','retention_policy_approval_required') where id=p_run_id;
  return query select 'blocked','complete',0,0,0; return;
 end if;
 if not r.dry_run and ps<>'approved' then
  update control.retention_runs set state='blocked_approval',retention_phase='complete',completed_at=now(),
   evidence=jsonb_build_object('reason','retention_policy_not_approved') where id=p_run_id;
  return query select 'blocked','complete',0,0,0; return;
 end if;
 if r.cutoff_at is null then
  update control.retention_runs x set state='running',started_at=coalesce(x.started_at,now()),cutoff_at=clock_timestamp(),
   invitation_high_water=coalesce((select max(retention_sequence) from control.invitations),0),
   mail_high_water=coalesce((select max(retention_sequence) from control.outbox),0),
   operation_high_water=coalesce((select max(retention_sequence) from control.operations),0)
   where x.id=p_run_id returning x.* into r;
 else update control.retention_runs x set state='running',started_at=coalesce(x.started_at,now()) where x.id=p_run_id returning x.* into r;
 end if;

 if r.retention_phase='invitations' then
  for c in select x.id,x.workshop_id,x.invited_by,x.accepted_user_id,x.retention_sequence from control.invitations x
   where x.retention_sequence>r.invitation_cursor and x.retention_sequence<=r.invitation_high_water
    and coalesce(x.accepted_at,x.revoked_at,x.expires_at)<r.cutoff_at-(days_i::bigint*interval '1 day')
   order by x.retention_sequence limit p_batch_limit for update loop
   n:=n+1; last_seq:=c.retention_sequence; is_held:=control.legal_hold_applies('invitations',c.workshop_id,array[c.invited_by,c.accepted_user_id]::uuid[]);
   if is_held then held_n:=held_n+1; elsif not r.dry_run then
    update control.invitations set email=concat('retained-invitation-',id,'@invalid'),idempotency_key=concat('retained:',id) where id=c.id;
    get diagnostics rows_n=row_count; if rows_n<>1 then raise exception 'privacy invitation target lost' using errcode='40001'; end if; changed:=changed+1;
   end if;
  end loop;
  next_phase:=case when n<p_batch_limit then 'mail-delivery' else 'invitations' end;
  update control.retention_runs x set retention_phase=next_phase,invitation_cursor=coalesce(last_seq,x.invitation_cursor),
   invitation_candidates=x.invitation_candidates+n,invitation_held=x.invitation_held+held_n,
   invitation_anonymized=x.invitation_anonymized+changed where x.id=p_run_id returning x.* into r;
 elsif r.retention_phase='mail-delivery' then
  for c in select x.id,x.workshop_id,i.invited_by,i.accepted_user_id,x.retention_sequence from control.outbox x
   left join control.invitations i on i.id=x.invitation_id where x.retention_sequence>r.mail_cursor and x.retention_sequence<=r.mail_high_water
    and x.state in('sent','dead_letter') and coalesce(x.sent_at,x.created_at)<r.cutoff_at-(days_m::bigint*interval '1 day')
   order by x.retention_sequence limit p_batch_limit for update of x loop
   n:=n+1; last_seq:=c.retention_sequence; is_held:=control.legal_hold_applies('mail-delivery',c.workshop_id,array[c.invited_by,c.accepted_user_id]::uuid[]);
   if is_held then held_n:=held_n+1; elsif not r.dry_run then delete from control.outbox where id=c.id;
    get diagnostics rows_n=row_count; if rows_n<>1 then raise exception 'privacy outbox target lost' using errcode='40001'; end if; changed:=changed+1; end if;
  end loop;
  next_phase:=case when n<p_batch_limit then 'operations' else 'mail-delivery' end;
  update control.retention_runs x set retention_phase=next_phase,mail_cursor=coalesce(last_seq,x.mail_cursor),
   mail_candidates=x.mail_candidates+n,mail_held=x.mail_held+held_n,mail_deleted=x.mail_deleted+changed where x.id=p_run_id returning x.* into r;
 elsif r.retention_phase='operations' then
  for c in select x.id,x.workshop_id,x.requested_by,x.target_user_id,x.retention_sequence from control.operations x
   where x.retention_sequence>r.operation_cursor and x.retention_sequence<=r.operation_high_water and x.state in('succeeded','dead_letter')
    and x.kind not like 'privacy.%' and coalesce(x.finished_at,x.created_at)<r.cutoff_at-(days_o::bigint*interval '1 day')
   order by x.retention_sequence limit p_batch_limit for update loop
   n:=n+1; last_seq:=c.retention_sequence; is_held:=control.legal_hold_applies('operations',c.workshop_id,array[c.requested_by,c.target_user_id]::uuid[]);
   if is_held then held_n:=held_n+1; elsif not r.dry_run then update control.operations set payload='{"redacted":true}',checkpoint=null where id=c.id;
    get diagnostics rows_n=row_count; if rows_n<>1 then raise exception 'privacy operation target lost' using errcode='40001'; end if; changed:=changed+1; end if;
  end loop;
  next_phase:=case when n<p_batch_limit then 'complete' else 'operations' end;
  update control.retention_runs x set retention_phase=next_phase,operation_cursor=coalesce(last_seq,x.operation_cursor),
   operation_candidates=x.operation_candidates+n,operation_held=x.operation_held+held_n,
   operation_redacted=x.operation_redacted+changed where x.id=p_run_id returning x.* into r;
 else raise exception 'privacy retention phase is invalid' using errcode='23514'; end if;
 if op.lease_expires_at<=clock_timestamp() then raise exception 'privacy retention lease expired during batch' using errcode='40001'; end if;
 if r.retention_phase='complete' then
  held_sets:=array_remove(array[case when r.invitation_held>0 then 'invitations' end,case when r.mail_held>0 then 'mail-delivery' end,case when r.operation_held>0 then 'operations' end]::text[],null);
  update control.retention_runs x set state='completed',completed_at=now(),evidence=jsonb_build_object(
   'policy_version',x.policy_version,'dry_run',x.dry_run,'cutoff_at',x.cutoff_at,
   'candidates',jsonb_build_object('invitations',x.invitation_candidates,'mail_delivery',x.mail_candidates,'operation_details',x.operation_candidates),
   'held',jsonb_build_object('invitations',x.invitation_held,'mail_delivery',x.mail_held,'operation_details',x.operation_held),
   'held_datasets',to_jsonb(held_sets),'anonymized_invitation_count',x.invitation_anonymized,
   'deleted_count',x.mail_deleted,'redacted_operation_count',x.operation_redacted,'batch_limit',p_batch_limit) where x.id=p_run_id;
  return query select 'complete','complete',n,changed,held_n;
 end if;
 return query select 'more',r.retention_phase,n,changed,held_n;
end$$;
revoke all on function control.run_privacy_retention_batch(uuid,uuid,integer,text,integer) from public;
do $$begin
 if exists(select 1 from pg_roles where rolname='control_privacy_worker') then
  revoke all on table control.retention_runs from control_privacy_worker;
  grant execute on function control.run_privacy_retention_batch(uuid,uuid,integer,text,integer) to control_privacy_worker;
 end if;
 if exists(select 1 from pg_roles where rolname='control_api') then grant select,insert on control.retention_runs to control_api; end if;
end$$;
comment on function control.run_privacy_retention_batch(uuid,uuid,integer,text,integer) is
'Processes at most 200 snapshot-bounded retention candidates with exact operation fencing and transactional legal holds. Rows beyond frozen high-water marks and held rows are deferred to a future run.';
