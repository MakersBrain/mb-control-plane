-- Bind fleet activation to an exact identity observed from the running Nginx
-- workers. Historical intents remain nullable: an old filesystem digest is not
-- proof that a particular configuration was ever loaded and served.

alter table control.fleet_activation_intents
    add column gateway_identity_version smallint,
    add constraint fleet_activation_intents_gateway_identity_version_check
        check(gateway_identity_version is null or gateway_identity_version=1),
    add constraint fleet_activation_intents_activation_evidence_check
        check((activated_at is null)=(observed_configuration_digest is null)) not valid,
    add constraint fleet_activation_intents_abandonment_activation_check
        check(abandoned_at is null or activated_at is null) not valid;

create or replace function control.validate_fleet_activation_intent_update()
returns trigger
language plpgsql
set search_path=pg_catalog, control
as $function$
begin
    if new.id<>old.id or new.fleet_run_id<>old.fleet_run_id
       or new.release_id<>old.release_id or new.runtime_key<>old.runtime_key
       or new.target_slot<>old.target_slot
       or new.odoo_subject_digest<>old.odoo_subject_digest
       or new.extension_subject_digest<>old.extension_subject_digest
       or new.pair_qualification_digest<>old.pair_qualification_digest
       or new.prepared_tenants<>old.prepared_tenants
       or new.gateway_configuration_digest<>old.gateway_configuration_digest
       or new.driver_action_id<>old.driver_action_id
       or new.driver_fence_token is distinct from old.driver_fence_token
       or new.gateway_identity_version is distinct from old.gateway_identity_version
       or new.created_at<>old.created_at then
        raise exception 'fleet activation intent is immutable' using errcode='55000';
    end if;
    if (new.abandoned_at is null)<>(new.abandonment_reason is null) then
        raise exception 'fleet activation abandonment evidence must be paired'
            using errcode='23514';
    end if;
    if new.abandoned_at is not null and new.activated_at is not null then
        raise exception 'fleet activation and abandonment are mutually exclusive'
            using errcode='23514';
    end if;
    if (new.activated_at is null)<>(new.observed_configuration_digest is null) then
        raise exception 'fleet activation requires an exact observed gateway digest'
            using errcode='23514';
    end if;
    if new.observed_configuration_digest is not null
       and new.observed_configuration_digest<>new.gateway_configuration_digest then
        raise exception 'observed gateway digest does not match activation intent'
            using errcode='23514';
    end if;
    if (old.observed_configuration_digest is null
       and new.observed_configuration_digest is not null)
       and new.gateway_identity_version is distinct from 1 then
        raise exception 'legacy fleet activation intent requires reconciliation'
            using errcode='55000';
    end if;
    if old.observed_configuration_digest is not null
       and new.observed_configuration_digest is distinct from old.observed_configuration_digest then
        raise exception 'observed gateway digest is immutable once recorded'
            using errcode='55000';
    end if;
    if old.activated_at is not null and new.activated_at is distinct from old.activated_at then
        raise exception 'activation timestamp is immutable once recorded'
            using errcode='55000';
    end if;
    if old.abandoned_at is not null
       and (new.abandoned_at is distinct from old.abandoned_at
            or new.abandonment_reason is distinct from old.abandonment_reason) then
        raise exception 'fleet activation abandonment is irreversible'
            using errcode='55000';
    end if;
    return new;
end
$function$;

comment on column control.fleet_activation_intents.gateway_identity_version is
'Loaded-gateway identity protocol version; NULL is legacy evidence and cannot be activated automatically.';
