-- Make ambiguous custom-hostname deletion a bounded, observable protocol.
-- Provider absence is evidence; a transport error from DELETE never is.

alter table control.webshop_domains
    add constraint webshop_domains_id_workshop_id_key unique (id, workshop_id);

create table control.webshop_domain_provider_deletion_attempts (
    domain_id uuid not null,
    provider_ref text not null,
    workshop_id uuid not null,
    hostname text not null,
    operation_id uuid not null,
    operation_attempt integer not null,
    state text not null default 'observation_required',
    observation_count integer not null default 0,
    delete_dispatch_count integer not null default 0,
    last_observation text,
    last_observation_operation_id uuid,
    last_observation_attempt integer,
    last_dispatch_operation_id uuid,
    last_dispatch_attempt integer,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    primary key (domain_id, provider_ref),
    foreign key (operation_id, workshop_id)
        references control.operations(id, workshop_id) on delete restrict,
    foreign key (domain_id, workshop_id)
        references control.webshop_domains(id, workshop_id) on delete restrict,
    foreign key (last_observation_operation_id, workshop_id)
        references control.operations(id, workshop_id) on delete restrict,
    foreign key (last_dispatch_operation_id, workshop_id)
        references control.operations(id, workshop_id) on delete restrict,
    check (operation_attempt > 0),
    check (provider_ref ~ '^[A-Za-z0-9-]+$' and length(provider_ref) <= 128),
    check (hostname = lower(hostname) and length(hostname) <= 253),
    check (state in ('observation_required','observed_present','delete_dispatched',
                     'absence_confirmed','budget_exhausted')),
    check (observation_count between 0 and 8),
    check (delete_dispatch_count between 0 and 4),
    check (last_observation is null or last_observation in ('present','absent')),
    check ((state = 'absence_confirmed') = (last_observation = 'absent')),
    check (state <> 'delete_dispatched' or last_dispatch_attempt is not null),
    check ((last_observation_operation_id is null) = (last_observation_attempt is null)),
    check ((last_dispatch_operation_id is null) = (last_dispatch_attempt is null)),
    check (last_observation_attempt is null or last_observation_attempt > 0),
    check (last_dispatch_attempt is null or last_dispatch_attempt > 0)
);

create index webshop_domain_provider_deletion_operation
    on control.webshop_domain_provider_deletion_attempts(operation_id, operation_attempt);

create or replace function control.advance_webshop_domain_provider_deletion(
    p_operation_id uuid,
    p_operation_attempt integer,
    p_lease_owner text,
    p_workshop_id uuid,
    p_domain_id uuid,
    p_provider_ref text,
    p_hostname text,
    p_action text
) returns table(deletion_state text, observation_count integer,
                delete_dispatch_count integer, dispatch_authorized boolean)
language plpgsql security definer
set search_path = pg_catalog, control
as $function$
declare
    v_attempt control.webshop_domain_provider_deletion_attempts%rowtype;
    v_dispatch_authorized boolean := false;
begin
    if p_action not in ('begin','observe_present','observe_absent','dispatch_delete') then
        raise exception 'invalid provider deletion action' using errcode='22023';
    end if;
    if p_operation_attempt < 1 or p_lease_owner is null or btrim(p_lease_owner) = '' then
        raise exception 'invalid provider deletion lease tuple' using errcode='22023';
    end if;
    if p_provider_ref is null or p_provider_ref = '' or length(p_provider_ref) > 128
       or p_hostname is null or p_hostname <> lower(p_hostname)
       or length(p_hostname) > 253 then
        raise exception 'invalid provider deletion identity' using errcode='22023';
    end if;

    -- Global operation row precedes the workshop-owned domain and intent row.
    perform 1 from control.operations operation
    where operation.id=p_operation_id and operation.workshop_id=p_workshop_id
      and operation.kind='webshop-domain.reconcile' and operation.state='in_flight'
      and operation.attempt=p_operation_attempt and operation.leased_by=p_lease_owner
      and operation.lease_expires_at>now()
    for update;
    if not found then
        raise exception 'provider deletion operation lease is not current'
            using errcode='40001';
    end if;

    perform 1 from control.webshop_domains domain
    where domain.id=p_domain_id and domain.workshop_id=p_workshop_id
      and domain.operation_id=p_operation_id and domain.desired_state='disconnected'
      and domain.state in ('disconnecting','action_required')
      and domain.provider_ref=p_provider_ref and domain.hostname=p_hostname
    for update;
    if not found then
        raise exception 'provider deletion domain authority is not current'
            using errcode='40001';
    end if;

    insert into control.webshop_domain_provider_deletion_attempts(
        domain_id,provider_ref,workshop_id,hostname,operation_id,operation_attempt
    ) values (p_domain_id,p_provider_ref,p_workshop_id,p_hostname,
              p_operation_id,p_operation_attempt)
    on conflict (domain_id,provider_ref) do update
      set operation_id=excluded.operation_id,operation_attempt=excluded.operation_attempt,
          updated_at=now()
      where webshop_domain_provider_deletion_attempts.workshop_id=excluded.workshop_id
        and webshop_domain_provider_deletion_attempts.hostname=excluded.hostname;

    select * into strict v_attempt
    from control.webshop_domain_provider_deletion_attempts attempt
    where attempt.domain_id=p_domain_id and attempt.provider_ref=p_provider_ref
    for update;
    if v_attempt.workshop_id<>p_workshop_id or v_attempt.hostname<>p_hostname
       or v_attempt.operation_id<>p_operation_id
       or v_attempt.operation_attempt<>p_operation_attempt then
        raise exception 'provider deletion intent identity mismatch' using errcode='22023';
    end if;

    if p_action = 'begin' and v_attempt.state <> 'absence_confirmed'
       and v_attempt.observation_count >= 8 then
        update control.webshop_domain_provider_deletion_attempts attempt
        set state='budget_exhausted',updated_at=now()
        where attempt.domain_id=p_domain_id and attempt.provider_ref=p_provider_ref;
    end if;

    if p_action in ('observe_present','observe_absent') then
        if v_attempt.state = 'absence_confirmed' then
            null;
        elsif p_action = 'observe_absent' then
            update control.webshop_domain_provider_deletion_attempts attempt
            set state='absence_confirmed',
                observation_count=least(attempt.observation_count+1,8),
                last_observation='absent',last_observation_operation_id=p_operation_id,
                last_observation_attempt=p_operation_attempt,
                updated_at=now()
            where attempt.domain_id=p_domain_id and attempt.provider_ref=p_provider_ref;
        elsif v_attempt.state = 'budget_exhausted' or v_attempt.observation_count >= 8 then
            update control.webshop_domain_provider_deletion_attempts attempt
            set state='budget_exhausted',updated_at=now()
            where attempt.domain_id=p_domain_id and attempt.provider_ref=p_provider_ref;
        else
            update control.webshop_domain_provider_deletion_attempts attempt
            set state=case when attempt.last_dispatch_operation_id=p_operation_id
                                      and attempt.last_dispatch_attempt=p_operation_attempt
                           then 'delete_dispatched' else 'observed_present' end,
                observation_count=attempt.observation_count+1,
                last_observation='present',last_observation_operation_id=p_operation_id,
                last_observation_attempt=p_operation_attempt,
                updated_at=now()
            where attempt.domain_id=p_domain_id and attempt.provider_ref=p_provider_ref;
        end if;
    elsif p_action = 'dispatch_delete' then
        if v_attempt.delete_dispatch_count >= 4 then
            update control.webshop_domain_provider_deletion_attempts attempt
            set state='budget_exhausted',updated_at=now()
            where attempt.domain_id=p_domain_id and attempt.provider_ref=p_provider_ref;
        elsif v_attempt.state='observed_present'
          and v_attempt.last_observation='present'
          and v_attempt.last_observation_operation_id=p_operation_id
          and v_attempt.last_observation_attempt=p_operation_attempt
          and (v_attempt.last_dispatch_operation_id is distinct from p_operation_id
               or v_attempt.last_dispatch_attempt is distinct from p_operation_attempt) then
            update control.webshop_domain_provider_deletion_attempts attempt
            set state='delete_dispatched',
                delete_dispatch_count=attempt.delete_dispatch_count+1,
                last_dispatch_operation_id=p_operation_id,
                last_dispatch_attempt=p_operation_attempt,updated_at=now()
            where attempt.domain_id=p_domain_id and attempt.provider_ref=p_provider_ref;
            v_dispatch_authorized := true;
        end if;
    end if;

    return query
    select attempt.state,attempt.observation_count,attempt.delete_dispatch_count,
           v_dispatch_authorized
    from control.webshop_domain_provider_deletion_attempts attempt
    where attempt.domain_id=p_domain_id and attempt.provider_ref=p_provider_ref;
end
$function$;

revoke all on table control.webshop_domain_provider_deletion_attempts from public;
revoke all on function control.advance_webshop_domain_provider_deletion(
    uuid,integer,text,uuid,uuid,text,text,text) from public;

do $migration$
begin
    if exists(select 1 from pg_roles where rolname='control_reconciliation_worker') then
        grant execute on function control.advance_webshop_domain_provider_deletion(
            uuid,integer,text,uuid,uuid,text,text,text) to control_reconciliation_worker;
    end if;
end
$migration$;

comment on table control.webshop_domain_provider_deletion_attempts is
'Finite evidence ledger shared by every operation and lease retry for one provider deletion intent.';
comment on function control.advance_webshop_domain_provider_deletion(
    uuid,integer,text,uuid,uuid,text,text,text) is
'Authenticates the current lease and atomically advances a bounded provider-deletion intent.';
