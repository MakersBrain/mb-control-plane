-- Fresh PostgreSQL 17 baseline for the disposable control-plane schema epoch.
-- Runtime roles are infrastructure-owned; conditional grants preserve least privilege
-- while allowing schema-only tests without CREATEROLE.

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

CREATE SCHEMA control;

CREATE FUNCTION control.assert_last_owner() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
declare target uuid := coalesce(old.workshop_id, new.workshop_id);
begin
    if not exists (
        select 1 from control.memberships
        where workshop_id = target and role = 'owner' and status = 'active'
    ) then
        raise exception 'workshop would have no active owner' using errcode = '23514';
    end if;
    return null;
end $$;

CREATE FUNCTION control.consume_data_subject_export(p_export_id uuid, p_subject_user_id uuid) RETURNS TABLE(export_id uuid, encryption_key_ref text, storage_ref text, nonce bytea, ciphertext bytea, manifest_digest text, content_type text, filename text, plaintext_size bigint)
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'control'
    AS $$
declare selected record;
begin
    select e.id as export_id,e.encryption_key_ref,e.storage_ref,e.nonce,e.ciphertext,
           e.manifest_digest,e.content_type,e.filename,e.plaintext_size,e.expires_at
      into selected
      from control.data_subject_exports e
      join control.data_subject_requests r on r.id=e.data_subject_request_id
     where e.id=p_export_id and r.subject_user_id=p_subject_user_id and e.state='ready'
       for update of e;
    if not found then return; end if;
    if selected.expires_at<=now() then
        update control.data_subject_exports e
           set state='expired',nonce=null,ciphertext=null
         where e.id=p_export_id;
        return;
    end if;
    update control.data_subject_exports e
       set state='consumed',consumed_at=now(),nonce=null,ciphertext=null
     where e.id=p_export_id;
    return query select selected.export_id,selected.encryption_key_ref,
        selected.storage_ref,selected.nonce,selected.ciphertext,selected.manifest_digest,
        selected.content_type,selected.filename,selected.plaintext_size;
end $$;

CREATE FUNCTION control.enforce_subject_processing_hold() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'control'
    AS $$
begin
    if coalesce(new.target_user_id,new.requested_by) is not null and new.kind not in ('privacy.retention','privacy.data_subject_request')
       and exists(select 1 from processing_holds h where h.subject_user_id=coalesce(new.target_user_id,new.requested_by) and h.active and (h.workshop_id is null or h.workshop_id is not distinct from new.workshop_id))
    then raise exception 'processing is restricted for this data subject' using errcode='42501'; end if;
    return new;
end $$;

CREATE FUNCTION control.erasure_lookup_available(target uuid) RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'control'
    AS $$
    select exists(select 1 from erasure_subject_lookups where tombstone_id=target)
$$;

CREATE FUNCTION control.legal_hold_applies(p_dataset_key text, p_workshop_id uuid, p_subject_ids uuid[]) RETURNS boolean
    LANGUAGE sql STABLE
    SET search_path TO 'pg_catalog', 'control'
    AS $$
    select exists(
        select 1 from legal_holds h
        where h.released_at is null and h.expires_at>now()
          and ((h.scope->'datasets') ? p_dataset_key or (h.scope->'datasets') ? '*')
          and (
              coalesce(jsonb_array_length(h.scope->'workshop_ids'),0)=0
              or h.scope @> jsonb_build_object('workshop_ids',jsonb_build_array(p_workshop_id))
          )
          and (
              coalesce(jsonb_array_length(h.scope->'subject_user_ids'),0)=0
              or exists(
                  select 1 from unnest(coalesce(p_subject_ids,'{}'::uuid[])) as subject(subject_id)
                  where h.scope @> jsonb_build_object('subject_user_ids',jsonb_build_array(subject.subject_id))
              )
          )
    )
$$;

CREATE FUNCTION control.purge_expired_data_subject_exports() RETURNS bigint
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'control'
    AS $$
declare affected bigint;
begin
    update control.data_subject_exports
       set state='expired',nonce=null,ciphertext=null
     where state='ready' and expires_at<=now();
    get diagnostics affected=row_count;
    return affected;
end $$;

CREATE FUNCTION control.reject_audit_mutation() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'control'
    AS $$
begin
    raise exception 'audit events are append-only' using errcode = '42501';
end
$$;

CREATE FUNCTION control.require_technical_admin() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'control'
    AS $$
begin
    if not exists(select 1 from platform_role_assignments where role='technical_admin' and revoked_at is null)
    then raise exception 'at least one technical administrator is required' using errcode='23514'; end if;
    return null;
end $$;

CREATE FUNCTION control.set_privacy_incident_deadline() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'control'
    AS $$
begin
    new.authority_deadline_at=case when new.controller_awareness_at is null then null else new.controller_awareness_at+interval '72 hours' end;
    return new;
end $$;

CREATE FUNCTION control.validate_application_release_transition() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'control'
    AS $$
begin
    if new.status<>old.status and not (
        (old.status='candidate' and new.status in ('preflighting','failed')) or
        (old.status='preflighting' and new.status in ('canary','failed')) or
        (old.status='canary' and new.status in ('prepared','failed')) or
        (old.status='prepared' and new.status in ('active','failed')) or
        (old.status='active' and new.status='retained')
    ) then raise exception 'invalid application release transition % -> %',old.status,new.status using errcode='23514';
    end if;
    if new.version<>old.version+1 then raise exception 'release version must increment exactly once' using errcode='40001'; end if;
    new.updated_at=now();
    return new;
end $$;

CREATE FUNCTION control.validate_data_subject_request_transition() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'control'
    AS $$
begin
    if new.subject_user_id<>old.subject_user_id or new.request_type<>old.request_type or new.scope<>old.scope or new.requested_at<>old.requested_at or new.due_at<>old.due_at
    then raise exception 'data-subject request identity and scope are immutable' using errcode='55000'; end if;
    if new.status<>old.status and not (
        (old.status='received' and new.status in ('identity_verification','controller_review','cancelled')) or
        (old.status='identity_verification' and new.status in ('controller_review','refused','cancelled')) or
        (old.status='controller_review' and new.status in ('approved','refused','cancelled')) or
        (old.status='approved' and new.status='executing') or
        (old.status='executing' and new.status in ('completed','refused'))
    ) then raise exception 'invalid data-subject request transition % -> %',old.status,new.status using errcode='23514'; end if;
    if new.version<>old.version+1 then raise exception 'data-subject request version must increment exactly once' using errcode='40001'; end if;
    new.updated_at=now(); return new;
end $$;

CREATE FUNCTION control.validate_fleet_activation_intent_update() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'control'
    AS $$
begin
    if new.id<>old.id or new.fleet_run_id<>old.fleet_run_id
       or new.release_id<>old.release_id or new.runtime_key<>old.runtime_key
       or new.target_slot<>old.target_slot or new.image_digest<>old.image_digest
       or new.prepared_tenants<>old.prepared_tenants
       or new.gateway_configuration_digest<>old.gateway_configuration_digest
       or new.driver_action_id<>old.driver_action_id or new.created_at<>old.created_at
    then raise exception 'fleet activation intent is immutable' using errcode='55000'; end if;
    if new.observed_configuration_digest is not null
       and new.observed_configuration_digest<>new.gateway_configuration_digest
    then raise exception 'observed gateway digest does not match activation intent' using errcode='23514'; end if;
    if old.observed_configuration_digest is not null
       and new.observed_configuration_digest is distinct from old.observed_configuration_digest
    then raise exception 'observed gateway digest is immutable once recorded' using errcode='55000'; end if;
    if old.activated_at is not null and new.activated_at is distinct from old.activated_at
    then raise exception 'activation timestamp is immutable once recorded' using errcode='55000'; end if;
    return new;
end $$;

CREATE FUNCTION control.validate_legal_hold_update() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'control'
    AS $$
begin
    if new.id<>old.id or new.scope<>old.scope or new.reason_code<>old.reason_code
       or new.approval_ref<>old.approval_ref or new.imposed_by<>old.imposed_by
       or new.imposed_at<>old.imposed_at or new.expires_at<>old.expires_at
    then raise exception 'legal hold scope and authority are immutable' using errcode='55000'; end if;
    if old.released_at is not null
    then raise exception 'a released legal hold cannot be changed' using errcode='23514'; end if;
    if new.version<>old.version+1
    then raise exception 'legal hold version must increment exactly once' using errcode='40001'; end if;
    return new;
end $$;

CREATE FUNCTION control.validate_platform_role_update() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'control'
    AS $$
begin
    if new.id<>old.id or new.user_id<>old.user_id or new.role<>old.role
       or new.granted_by is distinct from old.granted_by
       or new.grant_reason_code<>old.grant_reason_code or new.granted_at<>old.granted_at
    then raise exception 'platform role grant identity is immutable' using errcode='55000'; end if;
    if old.revoked_at is not null then
        raise exception 'revoked platform role grants are immutable' using errcode='55000';
    end if;
    if new.version<>old.version+1 then
        raise exception 'platform role version must increment exactly once' using errcode='40001';
    end if;
    new.updated_at=now(); return new;
end $$;

CREATE FUNCTION control.validate_privacy_incident_update() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'control'
    AS $$
begin
    if new.id<>old.id or new.discovered_at<>old.discovered_at or new.created_by<>old.created_by
       or new.created_at<>old.created_at
    then raise exception 'privacy incident identity is immutable' using errcode='55000'; end if;
    if (case new.containment_state when 'investigating' then 1 when 'contained' then 2
           when 'eradicated' then 3 when 'monitoring' then 4 when 'closed' then 5 end
       < (case old.containment_state when 'investigating' then 1 when 'contained' then 2
           when 'eradicated' then 3 when 'monitoring' then 4 when 'closed' then 5 end)
       )
    then raise exception 'privacy incident containment cannot move backwards' using errcode='23514'; end if;
    if new.version<>old.version+1
    then raise exception 'privacy incident version must increment exactly once' using errcode='40001'; end if;
    new.updated_at=now(); return new;
end $$;

CREATE FUNCTION control.validate_privacy_platform_state() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'control'
    AS $$
begin
    if new.version<>old.version+1 then raise exception 'privacy state version must increment exactly once' using errcode='40001'; end if;
    if new.production_personal_data_allowed and not (
        exists(select 1 from retention_policy_versions where version=new.approved_retention_policy_version and status='approved')
        and exists(select 1 from processing_register_versions where version=new.approved_processing_register_version and status='approved')
        and not exists(select 1 from processor_approvals where processing_register_version=new.approved_processing_register_version and status<>'approved')
    ) then raise exception 'privacy production approvals are incomplete' using errcode='23514'; end if;
    new.updated_at=now(); return new;
end $$;

CREATE FUNCTION control.validate_processor_task_update() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'control'
    AS $$
begin
    if new.id<>old.id or new.data_subject_request_id<>old.data_subject_request_id
       or new.processor_key<>old.processor_key or new.action<>old.action
    then raise exception 'processor task identity is immutable' using errcode='55000'; end if;
    if not (
        (old.state='pending' and new.state in ('sent','acknowledged','failed','not_applicable')) or
        (old.state='sent' and new.state in ('sent','acknowledged','failed','not_applicable')) or
        (old.state='failed' and new.state in ('sent','acknowledged','not_applicable'))
    ) then raise exception 'invalid processor task transition % -> %',old.state,new.state using errcode='23514'; end if;
    if new.version<>old.version+1 then raise exception 'processor task version must increment exactly once' using errcode='40001'; end if;
    new.updated_at=now(); return new;
end $$;

CREATE FUNCTION control.validate_tenant_release_transition() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'control'
    AS $$
begin
    if new.state<>old.state and not (
        (old.state='pending' and new.state in ('isolating','failed')) or
        (old.state='isolating' and new.state in ('backing_up','failed')) or
        (old.state='backing_up' and new.state in ('upgrading','failed')) or
        (old.state='upgrading' and new.state in ('verifying','failed')) or
        (old.state='verifying' and new.state in ('prepared','failed')) or
        (old.state='prepared' and new.state in ('active','restoring')) or
        (old.state='active' and new.state='superseded') or
        (old.state='failed' and new.state='restoring') or
        (old.state='restoring' and new.state in ('rolled_back','failed'))
    ) then raise exception 'invalid tenant release transition % -> %',old.state,new.state using errcode='23514';
    end if;
    if new.version<>old.version+1 then raise exception 'adoption version must increment exactly once' using errcode='40001'; end if;
    new.updated_at=now();
    return new;
end $$;

CREATE FUNCTION control.validate_workshop_module_update() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'control'
    AS $$
begin
    if new.workshop_id<>old.workshop_id or new.module_key<>old.module_key then
        raise exception 'capability activation identity is immutable' using errcode='55000';
    end if;
    if new.version<>old.version+1 then
        raise exception 'capability activation version must increment exactly once' using errcode='40001';
    end if;
    if not (
        (old.state='requested' and new.state in ('requested','installing','failed')) or
        (old.state='installing' and new.state in ('installing','enabled','failed')) or
        (old.state='enabled' and new.state in ('enabled','restricting')) or
        (old.state='restricting' and new.state in ('restricting','restricted','failed','requested')) or
        (old.state in ('failed','restricted') and new.state='requested')
    ) then
        raise exception 'invalid capability activation transition % -> %',old.state,new.state using errcode='23514';
    end if;
    if new.operation_id is not distinct from old.operation_id then
        if new.registry_version<>old.registry_version
           or new.application_release_id is distinct from old.application_release_id
           or new.entitlement_version is distinct from old.entitlement_version
           or new.resolved_implementation<>old.resolved_implementation then
            raise exception 'pinned capability activation contract is immutable' using errcode='55000';
        end if;
    elsif not (
        (new.state='requested' and new.operation_id is not null) or
        (old.state='enabled' and new.state='restricting' and new.operation_id is not null
         and new.registry_version=old.registry_version
         and new.application_release_id is not distinct from old.application_release_id
         and new.entitlement_version is not distinct from old.entitlement_version
         and new.resolved_implementation=old.resolved_implementation)
    ) then
        raise exception 'operation replacement is not permitted for this transition' using errcode='55000';
    end if;
    if new.state='requested' then
        new.restriction_reason=null;
        new.restriction_evidence=null;
        new.restricted_at=null;
    end if;
    return new;
end $$;

SET default_tablespace = '';

SET default_table_access_method = heap;

CREATE TABLE control.application_releases (
    id text NOT NULL,
    source_commit text NOT NULL,
    odoo_version text NOT NULL,
    image_digest text NOT NULL,
    manifest_digest text NOT NULL,
    addon_versions jsonb NOT NULL,
    compatibility jsonb NOT NULL,
    bridge_contract text NOT NULL,
    schema_epoch bigint NOT NULL,
    change_class text NOT NULL,
    required_postconditions jsonb NOT NULL,
    manifest jsonb NOT NULL,
    signature_bundle_ref text NOT NULL,
    provenance_ref text NOT NULL,
    sbom_ref text NOT NULL,
    published_at timestamp with time zone NOT NULL,
    status text DEFAULT 'candidate'::text NOT NULL,
    version bigint DEFAULT 1 NOT NULL,
    publication_idempotency_key text NOT NULL,
    publication_request_digest bytea NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT application_releases_addon_versions_check CHECK ((jsonb_typeof(addon_versions) = 'object'::text)),
    CONSTRAINT application_releases_change_class_check CHECK ((change_class = ANY (ARRAY['A'::text, 'B'::text, 'C'::text]))),
    CONSTRAINT application_releases_compatibility_check CHECK ((jsonb_typeof(compatibility) = 'object'::text)),
    CONSTRAINT application_releases_id_check CHECK ((id ~ '^odoo-[0-9]{4}\.[0-9]{2}\.[0-9]{2}-[a-f0-9]{7,64}$'::text)),
    CONSTRAINT application_releases_image_digest_check CHECK ((image_digest ~ '^sha256:[a-f0-9]{64}$'::text)),
    CONSTRAINT application_releases_manifest_check CHECK ((jsonb_typeof(manifest) = 'object'::text)),
    CONSTRAINT application_releases_manifest_digest_check CHECK ((manifest_digest ~ '^sha256:[a-f0-9]{64}$'::text)),
    CONSTRAINT application_releases_odoo_version_check CHECK ((odoo_version ~ '^19\.[0-9]+$'::text)),
    CONSTRAINT application_releases_publication_idempotency_key_check CHECK ((btrim(publication_idempotency_key) <> ''::text)),
    CONSTRAINT application_releases_publication_request_digest_check CHECK ((octet_length(publication_request_digest) = 32)),
    CONSTRAINT application_releases_required_postconditions_check CHECK ((jsonb_typeof(required_postconditions) = 'array'::text)),
    CONSTRAINT application_releases_schema_epoch_check CHECK ((schema_epoch > 0)),
    CONSTRAINT application_releases_source_commit_check CHECK ((source_commit ~ '^[a-f0-9]{40,64}$'::text)),
    CONSTRAINT application_releases_status_check CHECK ((status = ANY (ARRAY['candidate'::text, 'preflighting'::text, 'canary'::text, 'prepared'::text, 'active'::text, 'retained'::text, 'failed'::text]))),
    CONSTRAINT application_releases_version_check CHECK ((version > 0))
);

CREATE TABLE control.audit_events (
    id uuid NOT NULL,
    workshop_id uuid,
    action text NOT NULL,
    target_type text,
    target_id text,
    correlation_id uuid NOT NULL,
    outcome text NOT NULL,
    detail jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    actor_audit_subject_id uuid
);

CREATE TABLE control.capability_registry_entries (
    registry_version integer NOT NULL,
    capability_key text NOT NULL,
    dependencies text[] DEFAULT '{}'::text[] NOT NULL,
    odoo_modules text[] DEFAULT '{}'::text[] NOT NULL,
    service text,
    minimum_release text NOT NULL,
    enforcement_adapter text NOT NULL,
    CONSTRAINT capability_registry_entries_capability_key_check CHECK ((capability_key ~ '^[a-z0-9][a-z0-9-]{1,63}$'::text)),
    CONSTRAINT capability_registry_entries_check CHECK ((NOT (capability_key = ANY (dependencies)))),
    CONSTRAINT capability_registry_entries_check1 CHECK (((enforcement_adapter = 'odoo_modules'::text) = (cardinality(odoo_modules) > 0))),
    CONSTRAINT capability_registry_entries_check2 CHECK (((enforcement_adapter = 'paperless_service'::text) = (service = 'paperless'::text))),
    CONSTRAINT capability_registry_entries_dependencies_check CHECK ((array_position(dependencies, NULL::text) IS NULL)),
    CONSTRAINT capability_registry_entries_enforcement_adapter_check CHECK ((enforcement_adapter = ANY (ARRAY['odoo_modules'::text, 'paperless_service'::text, 'broker_provider'::text]))),
    CONSTRAINT capability_registry_entries_minimum_release_check CHECK ((btrim(minimum_release) <> ''::text)),
    CONSTRAINT capability_registry_entries_odoo_modules_check CHECK ((array_position(odoo_modules, NULL::text) IS NULL))
);

CREATE TABLE control.capability_registry_versions (
    version integer NOT NULL,
    source_digest text NOT NULL,
    activated_at timestamp with time zone DEFAULT now() NOT NULL,
    active boolean DEFAULT false NOT NULL,
    CONSTRAINT capability_registry_versions_source_digest_check CHECK ((source_digest ~ '^sha256:[0-9a-f]{64}$'::text)),
    CONSTRAINT capability_registry_versions_version_check CHECK ((version > 0))
);

CREATE TABLE control.carrier_secrets (
    id uuid NOT NULL,
    workshop_id uuid NOT NULL,
    provider text NOT NULL,
    environment text NOT NULL,
    company_id bigint NOT NULL,
    carrier_id bigint NOT NULL,
    secret_ref text NOT NULL,
    version bigint DEFAULT 1 NOT NULL,
    state text DEFAULT 'active'::text NOT NULL,
    created_by uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    rotated_at timestamp with time zone,
    deleted_at timestamp with time zone,
    cleanup_pending_ref text,
    CONSTRAINT carrier_secrets_carrier_id_check CHECK ((carrier_id > 0)),
    CONSTRAINT carrier_secrets_check CHECK (((state = 'deleted'::text) = (deleted_at IS NOT NULL))),
    CONSTRAINT carrier_secrets_check1 CHECK (((state <> 'deleted'::text) OR (cleanup_pending_ref IS NULL))),
    CONSTRAINT carrier_secrets_cleanup_pending_ref_check CHECK (((cleanup_pending_ref IS NULL) OR (cleanup_pending_ref ~ '^docker/[0-9a-f-]{36}/carrier/[0-9a-f-]{36}$'::text))),
    CONSTRAINT carrier_secrets_company_id_check CHECK ((company_id > 0)),
    CONSTRAINT carrier_secrets_environment_check CHECK ((environment = ANY (ARRAY['test'::text, 'production'::text]))),
    CONSTRAINT carrier_secrets_provider_check CHECK ((provider ~ '^[a-z][a-z0-9_]{0,31}$'::text)),
    CONSTRAINT carrier_secrets_secret_ref_check CHECK ((secret_ref ~ '^docker/[0-9a-f-]{36}/carrier/[0-9a-f-]{36}$'::text)),
    CONSTRAINT carrier_secrets_state_check CHECK ((state = ANY (ARRAY['active'::text, 'suspended'::text, 'deleted'::text]))),
    CONSTRAINT carrier_secrets_version_check CHECK ((version > 0))
);

CREATE TABLE control.commands (
    id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    scope text NOT NULL,
    command_kind text NOT NULL,
    idempotency_key text NOT NULL,
    request_digest bytea NOT NULL,
    expected_version bigint,
    state text DEFAULT 'admitted'::text NOT NULL,
    operation_id uuid,
    response_status integer,
    response_body jsonb,
    result_ref text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    completed_at timestamp with time zone,
    CONSTRAINT commands_check CHECK (((state = 'completed'::text) = (completed_at IS NOT NULL))),
    CONSTRAINT commands_check1 CHECK (((state <> 'completed'::text) OR (response_status IS NOT NULL))),
    CONSTRAINT commands_check2 CHECK (((response_body IS NULL) OR (result_ref IS NULL))),
    CONSTRAINT commands_command_kind_check CHECK (((btrim(command_kind) <> ''::text) AND (length(command_kind) <= 100))),
    CONSTRAINT commands_expected_version_check CHECK (((expected_version IS NULL) OR (expected_version > 0))),
    CONSTRAINT commands_idempotency_key_check CHECK ((((length(idempotency_key) >= 1) AND (length(idempotency_key) <= 255)) AND (idempotency_key ~ '^[A-Za-z0-9._:/-]+$'::text))),
    CONSTRAINT commands_request_digest_check CHECK ((octet_length(request_digest) = 32)),
    CONSTRAINT commands_response_status_check CHECK (((response_status >= 100) AND (response_status <= 599))),
    CONSTRAINT commands_scope_check CHECK (((btrim(scope) <> ''::text) AND (length(scope) <= 200))),
    CONSTRAINT commands_state_check CHECK ((state = ANY (ARRAY['admitted'::text, 'completed'::text])))
);

CREATE TABLE control.data_subject_exports (
    id uuid NOT NULL,
    data_subject_request_id uuid NOT NULL,
    storage_ref text NOT NULL,
    encryption_key_ref text NOT NULL,
    manifest_digest text NOT NULL,
    state text NOT NULL,
    ready_at timestamp with time zone,
    expires_at timestamp with time zone NOT NULL,
    consumed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    nonce bytea,
    ciphertext bytea,
    plaintext_size bigint,
    content_type text DEFAULT 'application/json'::text NOT NULL,
    filename text,
    CONSTRAINT data_subject_exports_check CHECK ((expires_at > created_at)),
    CONSTRAINT data_subject_exports_check1 CHECK (((state <> 'ready'::text) OR (ready_at IS NOT NULL))),
    CONSTRAINT data_subject_exports_check2 CHECK (((state <> 'consumed'::text) OR (consumed_at IS NOT NULL))),
    CONSTRAINT data_subject_exports_ciphertext_check CHECK (((ciphertext IS NULL) OR ((octet_length(ciphertext) >= 17) AND (octet_length(ciphertext) <= 134217744)))),
    CONSTRAINT data_subject_exports_content_type_check CHECK ((content_type = 'application/json'::text)),
    CONSTRAINT data_subject_exports_encryption_key_ref_check CHECK ((btrim(encryption_key_ref) <> ''::text)),
    CONSTRAINT data_subject_exports_filename_check CHECK (((filename IS NULL) OR (filename ~ '^privacy-export-[0-9a-f-]{36}\.json$'::text))),
    CONSTRAINT data_subject_exports_manifest_digest_check CHECK ((manifest_digest ~ '^sha256:[0-9a-f]{64}$'::text)),
    CONSTRAINT data_subject_exports_nonce_check CHECK (((nonce IS NULL) OR (octet_length(nonce) = 12))),
    CONSTRAINT data_subject_exports_plaintext_size_check CHECK (((plaintext_size IS NULL) OR ((plaintext_size >= 1) AND (plaintext_size <= 134217728)))),
    CONSTRAINT data_subject_exports_ready_payload_check CHECK (((state <> 'ready'::text) OR ((nonce IS NOT NULL) AND (plaintext_size IS NOT NULL) AND (filename IS NOT NULL) AND (ready_at IS NOT NULL) AND (((storage_ref ~~ 'postgres:aead:%'::text) AND (ciphertext IS NOT NULL)) OR ((storage_ref ~~ 'file:%.aead'::text) AND (ciphertext IS NULL)))))),
    CONSTRAINT data_subject_exports_state_check CHECK ((state = ANY (ARRAY['preparing'::text, 'ready'::text, 'consumed'::text, 'expired'::text, 'revoked'::text]))),
    CONSTRAINT data_subject_exports_storage_ref_check CHECK ((btrim(storage_ref) <> ''::text))
);

CREATE VIEW control.data_subject_export_status AS
 SELECT id,
    data_subject_request_id,
    manifest_digest,
        CASE
            WHEN ((state = 'ready'::text) AND (expires_at <= now())) THEN 'expired'::text
            ELSE state
        END AS state,
    ready_at,
    expires_at,
    consumed_at,
    created_at,
    content_type,
    filename,
    plaintext_size
   FROM control.data_subject_exports e;

CREATE TABLE control.data_subject_processor_tasks (
    id uuid NOT NULL,
    data_subject_request_id uuid NOT NULL,
    processor_key text NOT NULL,
    action text NOT NULL,
    state text DEFAULT 'pending'::text NOT NULL,
    acknowledgement_ref text,
    safe_error_class text,
    version bigint DEFAULT 1 NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT data_subject_processor_tasks_action_check CHECK ((action = ANY (ARRAY['search'::text, 'export'::text, 'rectify'::text, 'erase'::text, 'restrict'::text, 'unrestrict'::text, 'object'::text]))),
    CONSTRAINT data_subject_processor_tasks_check CHECK (((state <> 'acknowledged'::text) OR (acknowledgement_ref IS NOT NULL))),
    CONSTRAINT data_subject_processor_tasks_state_check CHECK ((state = ANY (ARRAY['pending'::text, 'sent'::text, 'acknowledged'::text, 'failed'::text, 'not_applicable'::text]))),
    CONSTRAINT data_subject_processor_tasks_version_check CHECK ((version > 0))
);

CREATE TABLE control.data_subject_requests (
    id uuid NOT NULL,
    subject_user_id uuid NOT NULL,
    request_type text NOT NULL,
    scope jsonb DEFAULT '{}'::jsonb NOT NULL,
    status text DEFAULT 'received'::text NOT NULL,
    identity_verification_state text DEFAULT 'verified_session'::text NOT NULL,
    controller_required boolean DEFAULT true NOT NULL,
    requested_at timestamp with time zone DEFAULT now() NOT NULL,
    due_at timestamp with time zone DEFAULT (now() + '1 mon'::interval) NOT NULL,
    extended_due_at timestamp with time zone,
    extension_notification_ref text,
    decision_code text,
    approver_user_id uuid,
    decided_at timestamp with time zone,
    operation_id uuid,
    completed_at timestamp with time zone,
    version bigint DEFAULT 1 NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT data_subject_requests_check CHECK (((extended_due_at IS NULL) OR ((extended_due_at > due_at) AND (extension_notification_ref IS NOT NULL)))),
    CONSTRAINT data_subject_requests_check1 CHECK (((status <> ALL (ARRAY['approved'::text, 'refused'::text])) OR ((decision_code IS NOT NULL) AND (approver_user_id IS NOT NULL) AND (decided_at IS NOT NULL)))),
    CONSTRAINT data_subject_requests_check2 CHECK (((status <> 'completed'::text) OR (completed_at IS NOT NULL))),
    CONSTRAINT data_subject_requests_identity_verification_state_check CHECK ((identity_verification_state = ANY (ARRAY['pending'::text, 'verified_session'::text, 'verified_out_of_band'::text, 'failed'::text]))),
    CONSTRAINT data_subject_requests_request_type_check CHECK ((request_type = ANY (ARRAY['access'::text, 'rectification'::text, 'erasure'::text, 'restriction'::text, 'portability'::text, 'objection'::text]))),
    CONSTRAINT data_subject_requests_scope_check CHECK ((jsonb_typeof(scope) = 'object'::text)),
    CONSTRAINT data_subject_requests_status_check CHECK ((status = ANY (ARRAY['received'::text, 'identity_verification'::text, 'controller_review'::text, 'approved'::text, 'executing'::text, 'completed'::text, 'refused'::text, 'cancelled'::text]))),
    CONSTRAINT data_subject_requests_version_check CHECK ((version > 0))
);

CREATE TABLE control.deployment_driver_operations (
    idempotency_key text NOT NULL,
    workshop_id uuid,
    action text NOT NULL,
    request_digest text NOT NULL,
    state text DEFAULT 'in_progress'::text NOT NULL,
    response jsonb,
    safe_error text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT deployment_driver_operations_action_check CHECK ((action = ANY (ARRAY['provision'::text, 'reconcile'::text, 'lifecycle'::text, 'rehearse'::text, 'release'::text, 'erasure'::text, 'resume'::text, 'restrict'::text, 'carrier-secret'::text, 'carrier-secret-delete'::text]))),
    CONSTRAINT deployment_driver_operations_check CHECK (((state = 'succeeded'::text) = (response IS NOT NULL))),
    CONSTRAINT deployment_driver_operations_idempotency_key_check CHECK ((btrim(idempotency_key) <> ''::text)),
    CONSTRAINT deployment_driver_operations_request_digest_check CHECK ((request_digest ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT deployment_driver_operations_state_check CHECK ((state = ANY (ARRAY['in_progress'::text, 'succeeded'::text, 'failed'::text])))
);

CREATE TABLE control.email_delivery_events (
    event_id uuid NOT NULL,
    outbox_id uuid NOT NULL,
    provider_message_id uuid NOT NULL,
    sns_message_id uuid NOT NULL,
    event_type text NOT NULL,
    occurred_at timestamp with time zone NOT NULL,
    received_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT email_delivery_events_event_type_check CHECK ((event_type = ANY (ARRAY['email_queued'::text, 'email_deferred'::text, 'email_delivered'::text, 'email_dropped'::text, 'email_spam'::text, 'email_mailbox_not_found'::text, 'email_blocklisted'::text])))
);

CREATE TABLE control.email_suppressions (
    workshop_id uuid NOT NULL,
    recipient text NOT NULL,
    reason text NOT NULL,
    source_event_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT email_suppressions_reason_check CHECK ((reason = ANY (ARRAY['dropped'::text, 'spam'::text, 'mailbox_not_found'::text, 'blocklisted'::text])))
);

CREATE TABLE control.entitlements (
    workshop_id uuid NOT NULL,
    version bigint NOT NULL,
    plan text NOT NULL,
    status text NOT NULL,
    limits jsonb DEFAULT '{}'::jsonb NOT NULL,
    expires_at timestamp with time zone,
    signature text NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT entitlements_version_check CHECK ((version > 0))
);

CREATE TABLE control.erasure_restore_replays (
    id uuid NOT NULL,
    tombstone_id uuid NOT NULL,
    recovery_point_id uuid NOT NULL,
    operation_id uuid NOT NULL,
    required_locations text[] NOT NULL,
    completed_locations text[] DEFAULT '{}'::text[] NOT NULL,
    state text DEFAULT 'pending'::text NOT NULL,
    safe_error_class text,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT erasure_restore_replays_check CHECK ((completed_locations <@ required_locations)),
    CONSTRAINT erasure_restore_replays_check1 CHECK (((state <> 'complete'::text) OR ((completed_locations @> required_locations) AND (completed_at IS NOT NULL)))),
    CONSTRAINT erasure_restore_replays_required_locations_check CHECK ((cardinality(required_locations) > 0)),
    CONSTRAINT erasure_restore_replays_safe_error_class_check CHECK (((safe_error_class IS NULL) OR (safe_error_class ~ '^[a-z][a-z0-9_]{0,99}$'::text))),
    CONSTRAINT erasure_restore_replays_state_check CHECK ((state = ANY (ARRAY['pending'::text, 'applying'::text, 'complete'::text, 'failed'::text])))
);

CREATE TABLE control.erasure_subject_lookups (
    tombstone_id uuid NOT NULL,
    key_id text NOT NULL,
    nonce bytea NOT NULL,
    ciphertext bytea NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT erasure_subject_lookups_ciphertext_check CHECK (((octet_length(ciphertext) >= 17) AND (octet_length(ciphertext) <= 4112))),
    CONSTRAINT erasure_subject_lookups_key_id_check CHECK ((key_id ~ '^[A-Za-z0-9_.-]{1,100}$'::text)),
    CONSTRAINT erasure_subject_lookups_nonce_check CHECK ((octet_length(nonce) = 12))
);

CREATE TABLE control.erasure_tombstones (
    id uuid NOT NULL,
    subject_key uuid NOT NULL,
    subject_user_id uuid,
    workshop_id uuid,
    source_request_id uuid NOT NULL,
    sequence bigint NOT NULL,
    applies_before timestamp with time zone DEFAULT now() NOT NULL,
    required_locations text[] NOT NULL,
    completed_locations text[] DEFAULT '{}'::text[] NOT NULL,
    state text DEFAULT 'pending'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    completed_at timestamp with time zone,
    CONSTRAINT erasure_tombstones_check CHECK ((completed_locations <@ required_locations)),
    CONSTRAINT erasure_tombstones_check1 CHECK (((state <> 'complete'::text) OR ((completed_locations @> required_locations) AND (completed_at IS NOT NULL)))),
    CONSTRAINT erasure_tombstones_state_check CHECK ((state = ANY (ARRAY['pending'::text, 'applying'::text, 'complete'::text, 'held'::text])))
);

ALTER TABLE control.erasure_tombstones ALTER COLUMN sequence ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME control.erasure_tombstones_sequence_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);

CREATE TABLE control.external_identities (
    id uuid NOT NULL,
    user_id uuid NOT NULL,
    issuer text NOT NULL,
    subject text NOT NULL,
    email_at_link text,
    linked_at timestamp with time zone DEFAULT now() NOT NULL,
    disabled_at timestamp with time zone
);

CREATE TABLE control.fleet_activation_intents (
    id uuid NOT NULL,
    fleet_run_id uuid NOT NULL,
    release_id text NOT NULL,
    runtime_key text NOT NULL,
    target_slot text NOT NULL,
    image_digest text NOT NULL,
    prepared_tenants jsonb NOT NULL,
    gateway_configuration_digest text NOT NULL,
    driver_action_id uuid NOT NULL,
    observed_configuration_digest text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    activated_at timestamp with time zone,
    CONSTRAINT fleet_activation_intents_gateway_configuration_digest_check CHECK ((gateway_configuration_digest ~ '^sha256:[a-f0-9]{64}$'::text)),
    CONSTRAINT fleet_activation_intents_image_digest_check CHECK ((image_digest ~ '^sha256:[a-f0-9]{64}$'::text)),
    CONSTRAINT fleet_activation_intents_prepared_tenants_check CHECK ((jsonb_typeof(prepared_tenants) = 'array'::text)),
    CONSTRAINT fleet_activation_intents_target_slot_check CHECK ((target_slot = ANY (ARRAY['blue'::text, 'green'::text])))
);

CREATE TABLE control.invitations (
    id uuid NOT NULL,
    workshop_id uuid NOT NULL,
    email text NOT NULL,
    role text NOT NULL,
    token_hash bytea,
    locale text DEFAULT 'en'::text NOT NULL,
    invited_by uuid NOT NULL,
    idempotency_key text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    sent_count integer DEFAULT 1 NOT NULL,
    last_sent_at timestamp with time zone DEFAULT now() NOT NULL,
    accepted_at timestamp with time zone,
    accepted_user_id uuid,
    revoked_at timestamp with time zone,
    token_generation integer DEFAULT 1 NOT NULL,
    CONSTRAINT invitations_check CHECK ((expires_at > created_at)),
    CONSTRAINT invitations_check1 CHECK (((accepted_at IS NULL) OR (accepted_user_id IS NOT NULL))),
    CONSTRAINT invitations_check2 CHECK (((accepted_at IS NULL) OR (revoked_at IS NULL))),
    CONSTRAINT invitations_email_check CHECK (((email = lower(btrim(email))) AND (email <> ''::text))),
    CONSTRAINT invitations_idempotency_key_check CHECK ((idempotency_key <> ''::text)),
    CONSTRAINT invitations_locale_check CHECK ((locale = ANY (ARRAY['en'::text, 'fr'::text]))),
    CONSTRAINT invitations_role_check CHECK ((role = ANY (ARRAY['viewer'::text, 'artisan'::text, 'accountant'::text, 'studio_manager'::text]))),
    CONSTRAINT invitations_sent_count_check CHECK ((sent_count > 0)),
    CONSTRAINT invitations_token_generation_check CHECK ((token_generation > 0)),
    CONSTRAINT invitations_token_hash_check CHECK ((octet_length(token_hash) = 32))
);

CREATE TABLE control.legal_holds (
    id uuid NOT NULL,
    scope jsonb NOT NULL,
    reason_code text NOT NULL,
    approval_ref text NOT NULL,
    imposed_by uuid NOT NULL,
    imposed_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    released_at timestamp with time zone,
    released_by uuid,
    release_reason_code text,
    version bigint DEFAULT 1 NOT NULL,
    CONSTRAINT legal_holds_approval_ref_check CHECK ((btrim(approval_ref) <> ''::text)),
    CONSTRAINT legal_holds_check CHECK ((expires_at > imposed_at)),
    CONSTRAINT legal_holds_check1 CHECK ((((released_at IS NULL) AND (released_by IS NULL) AND (release_reason_code IS NULL)) OR ((released_at IS NOT NULL) AND (released_by IS NOT NULL) AND (release_reason_code IS NOT NULL)))),
    CONSTRAINT legal_holds_reason_code_check CHECK ((btrim(reason_code) <> ''::text)),
    CONSTRAINT legal_holds_scope_check CHECK ((jsonb_typeof(scope) = 'object'::text)),
    CONSTRAINT legal_holds_scope_check1 CHECK (((scope ? 'datasets'::text) AND (jsonb_typeof((scope -> 'datasets'::text)) = 'array'::text) AND (jsonb_array_length((scope -> 'datasets'::text)) > 0))),
    CONSTRAINT legal_holds_scope_check2 CHECK (((NOT (scope ? 'workshop_ids'::text)) OR (jsonb_typeof((scope -> 'workshop_ids'::text)) = 'array'::text))),
    CONSTRAINT legal_holds_scope_check3 CHECK (((NOT (scope ? 'subject_user_ids'::text)) OR (jsonb_typeof((scope -> 'subject_user_ids'::text)) = 'array'::text))),
    CONSTRAINT legal_holds_version_check CHECK ((version > 0))
);

CREATE TABLE control.membership_targets (
    workshop_id uuid NOT NULL,
    user_id uuid NOT NULL,
    target text NOT NULL,
    desired_epoch integer NOT NULL,
    applied_epoch integer DEFAULT 0 NOT NULL,
    state text DEFAULT 'pending'::text NOT NULL,
    safe_error_class text,
    observed_at timestamp with time zone,
    CONSTRAINT membership_targets_check CHECK (((applied_epoch >= 0) AND (applied_epoch <= desired_epoch))),
    CONSTRAINT membership_targets_desired_epoch_check CHECK ((desired_epoch > 0)),
    CONSTRAINT membership_targets_state_check CHECK ((state = ANY (ARRAY['pending'::text, 'ready'::text, 'degraded'::text, 'disabled'::text]))),
    CONSTRAINT membership_targets_target_check CHECK ((target = ANY (ARRAY['rauthy'::text, 'odoo'::text, 'paperless'::text])))
);

CREATE TABLE control.memberships (
    workshop_id uuid NOT NULL,
    user_id uuid NOT NULL,
    role text NOT NULL,
    status text DEFAULT 'active'::text NOT NULL,
    authority_epoch integer DEFAULT 1 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    revoked_at timestamp with time zone,
    version bigint DEFAULT 1 NOT NULL,
    CONSTRAINT memberships_authority_epoch_check CHECK ((authority_epoch > 0)),
    CONSTRAINT memberships_check CHECK (((status = 'revoked'::text) = (revoked_at IS NOT NULL))),
    CONSTRAINT memberships_role_check CHECK ((role = ANY (ARRAY['viewer'::text, 'artisan'::text, 'accountant'::text, 'studio_manager'::text, 'owner'::text]))),
    CONSTRAINT memberships_status_check CHECK ((status = ANY (ARRAY['active'::text, 'revoked'::text]))),
    CONSTRAINT memberships_version_check CHECK ((version > 0))
);

CREATE TABLE control.odoo_databases (
    id uuid NOT NULL,
    workshop_id uuid NOT NULL,
    service_instance_id uuid,
    kind text NOT NULL,
    database_ref text NOT NULL,
    public_hostname text,
    label text NOT NULL,
    state text DEFAULT 'provisioning'::text NOT NULL,
    source_database_id uuid,
    routable boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    last_restored_at timestamp with time zone,
    deleted_at timestamp with time zone,
    connection_limit_before_lifecycle integer,
    CONSTRAINT odoo_databases_check CHECK (((public_hostname IS NULL) OR (public_hostname <> database_ref))),
    CONSTRAINT odoo_databases_check1 CHECK (((kind = 'primary'::text) = (routable AND (public_hostname IS NOT NULL)))),
    CONSTRAINT odoo_databases_check2 CHECK (((kind = 'duplicate'::text) = (source_database_id IS NOT NULL))),
    CONSTRAINT odoo_databases_connection_limit_before_lifecycle_check CHECK (((connection_limit_before_lifecycle IS NULL) OR (connection_limit_before_lifecycle >= '-1'::integer))),
    CONSTRAINT odoo_databases_database_ref_check CHECK ((database_ref ~ '^mb_[0-9a-f]{32}$'::text)),
    CONSTRAINT odoo_databases_kind_check CHECK ((kind = ANY (ARRAY['primary'::text, 'duplicate'::text]))),
    CONSTRAINT odoo_databases_label_check CHECK ((btrim(label) <> ''::text)),
    CONSTRAINT odoo_databases_public_hostname_check CHECK (((public_hostname IS NULL) OR (public_hostname = lower(public_hostname)))),
    CONSTRAINT odoo_databases_public_hostname_check1 CHECK (((public_hostname IS NULL) OR (public_hostname ~ '^[a-z0-9][a-z0-9.-]*[a-z0-9]$'::text))),
    CONSTRAINT odoo_databases_state_check CHECK ((state = ANY (ARRAY['provisioning'::text, 'ready'::text, 'snapshotting'::text, 'restoring'::text, 'duplicating'::text, 'suspended'::text, 'failed'::text, 'deleted'::text])))
);

CREATE TABLE control.operations (
    id uuid NOT NULL,
    kind text NOT NULL,
    queue text NOT NULL,
    workshop_id uuid,
    target_user_id uuid,
    desired_epoch integer,
    payload jsonb NOT NULL,
    requested_by uuid,
    correlation_id uuid NOT NULL,
    idempotency_key text NOT NULL,
    state text DEFAULT 'pending'::text NOT NULL,
    attempt integer DEFAULT 0 NOT NULL,
    max_attempts integer DEFAULT 12 NOT NULL,
    next_attempt_at timestamp with time zone DEFAULT now() NOT NULL,
    leased_by text,
    lease_expires_at timestamp with time zone,
    failure_class text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    finished_at timestamp with time zone,
    progress_percent smallint DEFAULT 0 NOT NULL,
    progress_phase text,
    progress_message text,
    progress_updated_at timestamp with time zone,
    checkpoint jsonb,
    trace_parent text,
    trace_state text,
    CONSTRAINT operation_trace_parent_format CHECK (((trace_parent IS NULL) OR (trace_parent ~ '^[0-9a-f]{2}-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$'::text))),
    CONSTRAINT operation_trace_state_bounded CHECK (((trace_state IS NULL) OR (((length(trace_state) >= 1) AND (length(trace_state) <= 512)) AND (trace_state !~ '[\r\n]'::text)))),
    CONSTRAINT operations_attempt_check CHECK ((attempt >= 0)),
    CONSTRAINT operations_check CHECK (((state = 'in_flight'::text) = (leased_by IS NOT NULL))),
    CONSTRAINT operations_check1 CHECK (((state = 'in_flight'::text) = (lease_expires_at IS NOT NULL))),
    CONSTRAINT operations_checkpoint_check CHECK (((checkpoint IS NULL) OR (jsonb_typeof(checkpoint) = 'object'::text))),
    CONSTRAINT operations_desired_epoch_check CHECK (((desired_epoch IS NULL) OR (desired_epoch > 0))),
    CONSTRAINT operations_idempotency_key_check CHECK ((idempotency_key <> ''::text)),
    CONSTRAINT operations_kind_check CHECK ((kind = ANY (ARRAY['tenant.provision'::text, 'membership.reconcile'::text, 'entitlement.apply'::text, 'invoice.capture'::text, 'inventory.capture.extract'::text, 'tenant.reconcile'::text, 'tenant.lifecycle'::text, 'email.delivery'::text, 'module.enable'::text, 'module.restrict'::text, 'odoo.release.adopt'::text, 'privacy.retention'::text, 'privacy.data_subject_request'::text, 'webshop-domain.reconcile'::text, 'webshop-email-domain.reconcile'::text, 'webshop-onboarding.reconcile'::text]))),
    CONSTRAINT operations_max_attempts_check CHECK (((max_attempts >= 1) AND (max_attempts <= 100))),
    CONSTRAINT operations_payload_check CHECK ((jsonb_typeof(payload) = 'object'::text)),
    CONSTRAINT operations_progress_percent_check CHECK (((progress_percent >= 0) AND (progress_percent <= 100))),
    CONSTRAINT operations_state_check CHECK ((state = ANY (ARRAY['pending'::text, 'in_flight'::text, 'awaiting_reconciliation'::text, 'succeeded'::text, 'dead_letter'::text])))
);

CREATE TABLE control.outbox (
    id uuid NOT NULL,
    kind text NOT NULL,
    recipient text NOT NULL,
    template text NOT NULL,
    payload jsonb NOT NULL,
    state text DEFAULT 'queued'::text NOT NULL,
    attempts integer DEFAULT 0 NOT NULL,
    next_attempt_at timestamp with time zone DEFAULT now() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    sent_at timestamp with time zone,
    invitation_id uuid,
    token_generation integer,
    capability_issued_at timestamp with time zone,
    capability_expires_at timestamp with time zone,
    signing_key_id text,
    workshop_id uuid,
    source_key text,
    provider_message_id uuid,
    delivery_state text DEFAULT 'pending'::text NOT NULL,
    last_event_at timestamp with time zone,
    provider_domain_id uuid,
    CONSTRAINT outbox_delivery_state_check CHECK ((delivery_state = ANY (ARRAY['pending'::text, 'submitted'::text, 'delivered'::text, 'deferred'::text, 'bounced'::text, 'complained'::text, 'suppressed'::text]))),
    CONSTRAINT outbox_invitation_capability_metadata CHECK (((kind <> 'invitation'::text) OR ((invitation_id IS NOT NULL) AND (token_generation IS NOT NULL) AND (token_generation > 0) AND (capability_issued_at IS NOT NULL) AND (capability_expires_at > capability_issued_at) AND (signing_key_id IS NOT NULL) AND (btrim(signing_key_id) <> ''::text) AND (NOT (payload ? 'accept_url'::text)) AND (NOT (payload ? 'token'::text))))),
    CONSTRAINT outbox_source_scope CHECK ((((kind = 'odoo_transactional'::text) AND (workshop_id IS NOT NULL) AND (source_key IS NOT NULL) AND ((length(source_key) >= 1) AND (length(source_key) <= 255)) AND (source_key ~ '^[A-Za-z0-9._:/-]+$'::text) AND (template = 'odoo-rendered-v1'::text)) OR ((kind <> 'odoo_transactional'::text) AND (source_key IS NULL)))),
    CONSTRAINT outbox_state_check CHECK ((state = ANY (ARRAY['queued'::text, 'sending'::text, 'sent'::text, 'deferred'::text, 'dead_letter'::text])))
);

CREATE TABLE control.ownership_transfers (
    id uuid NOT NULL,
    workshop_id uuid NOT NULL,
    from_user_id uuid NOT NULL,
    to_user_id uuid NOT NULL,
    idempotency_key text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    accepted_at timestamp with time zone,
    revoked_at timestamp with time zone,
    CONSTRAINT ownership_transfers_check CHECK ((from_user_id <> to_user_id)),
    CONSTRAINT ownership_transfers_check1 CHECK ((expires_at > created_at)),
    CONSTRAINT ownership_transfers_check2 CHECK (((accepted_at IS NULL) OR (revoked_at IS NULL))),
    CONSTRAINT ownership_transfers_idempotency_key_check CHECK ((idempotency_key <> ''::text))
);

CREATE TABLE control.platform_authority_state (
    singleton boolean DEFAULT true NOT NULL,
    initial_admin_bootstrapped boolean DEFAULT false NOT NULL,
    bootstrapped_at timestamp with time zone,
    CONSTRAINT platform_authority_state_check CHECK ((initial_admin_bootstrapped = (bootstrapped_at IS NOT NULL))),
    CONSTRAINT platform_authority_state_singleton_check CHECK (singleton)
);

CREATE TABLE control.platform_role_assignments (
    id uuid NOT NULL,
    user_id uuid NOT NULL,
    role text NOT NULL,
    granted_by uuid,
    grant_reason_code text NOT NULL,
    granted_at timestamp with time zone DEFAULT now() NOT NULL,
    revoked_at timestamp with time zone,
    revoked_by uuid,
    revoke_reason_code text,
    version bigint DEFAULT 1 NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT platform_role_assignments_check CHECK (((revoked_at IS NULL) = ((revoked_by IS NULL) AND (revoke_reason_code IS NULL)))),
    CONSTRAINT platform_role_assignments_grant_reason_code_check CHECK ((btrim(grant_reason_code) <> ''::text)),
    CONSTRAINT platform_role_assignments_role_check CHECK ((role = ANY (ARRAY['technical_admin'::text, 'release_operator'::text, 'privacy_reviewer'::text, 'security_responder'::text, 'auditor'::text]))),
    CONSTRAINT platform_role_assignments_version_check CHECK ((version > 0))
);

CREATE TABLE control.privacy_incidents (
    id uuid NOT NULL,
    discovered_at timestamp with time zone NOT NULL,
    controller_awareness_at timestamp with time zone,
    authority_deadline_at timestamp with time zone,
    affected_categories text[] NOT NULL,
    affected_workshop_ids uuid[] DEFAULT '{}'::uuid[] NOT NULL,
    estimated_subject_count bigint,
    containment_state text NOT NULL,
    risk_level text,
    notification_required boolean,
    decision_ref text,
    authority_notification_ref text,
    subject_notification_ref text,
    version bigint DEFAULT 1 NOT NULL,
    created_by uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT privacy_incidents_affected_categories_check CHECK ((cardinality(affected_categories) > 0)),
    CONSTRAINT privacy_incidents_check CHECK (((notification_required IS NULL) OR (decision_ref IS NOT NULL))),
    CONSTRAINT privacy_incidents_check1 CHECK (((notification_required IS DISTINCT FROM true) OR (controller_awareness_at IS NOT NULL))),
    CONSTRAINT privacy_incidents_containment_state_check CHECK ((containment_state = ANY (ARRAY['investigating'::text, 'contained'::text, 'eradicated'::text, 'monitoring'::text, 'closed'::text]))),
    CONSTRAINT privacy_incidents_estimated_subject_count_check CHECK (((estimated_subject_count IS NULL) OR (estimated_subject_count >= 0))),
    CONSTRAINT privacy_incidents_risk_level_check CHECK ((risk_level = ANY (ARRAY['undetermined'::text, 'low'::text, 'medium'::text, 'high'::text])))
);

CREATE TABLE control.privacy_platform_state (
    singleton boolean DEFAULT true NOT NULL,
    controller_ref text,
    dpo_ref text,
    production_personal_data_allowed boolean DEFAULT false NOT NULL,
    approved_retention_policy_version integer,
    approved_processing_register_version integer,
    dpia_approval_ref text,
    version bigint DEFAULT 1 NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT privacy_platform_state_check CHECK (((NOT production_personal_data_allowed) OR ((controller_ref IS NOT NULL) AND (btrim(controller_ref) <> ''::text) AND (approved_retention_policy_version IS NOT NULL) AND (approved_processing_register_version IS NOT NULL) AND (dpia_approval_ref IS NOT NULL) AND (btrim(dpia_approval_ref) <> ''::text)))),
    CONSTRAINT privacy_platform_state_singleton_check CHECK (singleton),
    CONSTRAINT privacy_platform_state_version_check CHECK ((version > 0))
);

CREATE TABLE control.processing_holds (
    id uuid NOT NULL,
    data_subject_request_id uuid NOT NULL,
    subject_user_id uuid NOT NULL,
    workshop_id uuid,
    exception_scope text[] DEFAULT ARRAY['storage'::text] NOT NULL,
    active boolean DEFAULT true NOT NULL,
    imposed_at timestamp with time zone DEFAULT now() NOT NULL,
    released_at timestamp with time zone,
    released_by uuid,
    release_reason_code text,
    CONSTRAINT processing_holds_check CHECK ((active = ((released_at IS NULL) AND (released_by IS NULL) AND (release_reason_code IS NULL)))),
    CONSTRAINT processing_holds_exception_scope_check CHECK ((exception_scope <@ ARRAY['storage'::text, 'legal_claims'::text, 'security'::text]))
);

CREATE TABLE control.processing_register_versions (
    version integer NOT NULL,
    status text NOT NULL,
    activities jsonb NOT NULL,
    register_digest text NOT NULL,
    controller_ref text,
    approval_ref text,
    approved_by uuid,
    approved_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT processing_register_versions_activities_check CHECK ((jsonb_typeof(activities) = 'array'::text)),
    CONSTRAINT processing_register_versions_check CHECK (((status = 'approved'::text) = ((approval_ref IS NOT NULL) AND (approved_by IS NOT NULL) AND (approved_at IS NOT NULL)))),
    CONSTRAINT processing_register_versions_register_digest_check CHECK ((register_digest ~ '^sha256:[0-9a-f]{64}$'::text)),
    CONSTRAINT processing_register_versions_status_check CHECK ((status = ANY (ARRAY['draft'::text, 'approval_required'::text, 'approved'::text, 'retired'::text]))),
    CONSTRAINT processing_register_versions_version_check CHECK ((version > 0))
);

CREATE TABLE control.processor_approvals (
    id uuid NOT NULL,
    processing_register_version integer NOT NULL,
    provider_key text NOT NULL,
    purpose_key text NOT NULL,
    region text NOT NULL,
    eea boolean NOT NULL,
    article_28_terms_ref text NOT NULL,
    transfer_assessment_ref text,
    status text NOT NULL,
    valid_from timestamp with time zone,
    valid_until timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT processor_approvals_article_28_terms_ref_check CHECK ((btrim(article_28_terms_ref) <> ''::text)),
    CONSTRAINT processor_approvals_check CHECK ((eea OR (transfer_assessment_ref IS NOT NULL))),
    CONSTRAINT processor_approvals_check1 CHECK (((status <> 'approved'::text) OR (valid_from IS NOT NULL))),
    CONSTRAINT processor_approvals_check2 CHECK (((valid_until IS NULL) OR (valid_from IS NULL) OR (valid_until > valid_from))),
    CONSTRAINT processor_approvals_provider_key_check CHECK ((provider_key ~ '^[a-z0-9][a-z0-9_-]{1,63}$'::text)),
    CONSTRAINT processor_approvals_purpose_key_check CHECK ((purpose_key ~ '^[a-z0-9][a-z0-9_-]{1,63}$'::text)),
    CONSTRAINT processor_approvals_region_check CHECK ((btrim(region) <> ''::text)),
    CONSTRAINT processor_approvals_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'approved'::text, 'suspended'::text, 'revoked'::text])))
);

CREATE TABLE control.product_lookup_cache (
    provider text NOT NULL,
    schema_version integer NOT NULL,
    gtin14 text NOT NULL,
    outcome text NOT NULL,
    candidates jsonb NOT NULL,
    retrieved_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    CONSTRAINT product_lookup_cache_candidates_check CHECK ((jsonb_typeof(candidates) = 'array'::text)),
    CONSTRAINT product_lookup_cache_check CHECK ((((outcome = 'positive'::text) AND (jsonb_array_length(candidates) > 0)) OR ((outcome = 'negative'::text) AND (jsonb_array_length(candidates) = 0)))),
    CONSTRAINT product_lookup_cache_gtin14_check CHECK ((gtin14 ~ '^[0-9]{14}$'::text)),
    CONSTRAINT product_lookup_cache_outcome_check CHECK ((outcome = ANY (ARRAY['positive'::text, 'negative'::text]))),
    CONSTRAINT product_lookup_cache_schema_version_check CHECK ((schema_version > 0))
);

CREATE TABLE control.product_lookup_fills (
    provider text NOT NULL,
    schema_version integer NOT NULL,
    gtin14 text NOT NULL,
    state text NOT NULL,
    leased_by uuid,
    lease_expires_at timestamp with time zone,
    last_error_class text,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT product_lookup_fills_check CHECK (((state = 'filling'::text) = ((leased_by IS NOT NULL) AND (lease_expires_at IS NOT NULL)))),
    CONSTRAINT product_lookup_fills_gtin14_check CHECK ((gtin14 ~ '^[0-9]{14}$'::text)),
    CONSTRAINT product_lookup_fills_last_error_class_check CHECK (((last_error_class IS NULL) OR ((length(last_error_class) >= 1) AND (length(last_error_class) <= 100)))),
    CONSTRAINT product_lookup_fills_schema_version_check CHECK ((schema_version > 0)),
    CONSTRAINT product_lookup_fills_state_check CHECK ((state = ANY (ARRAY['filling'::text, 'idle'::text, 'failed'::text])))
);

CREATE TABLE control.provider_rate_limits (
    provider text NOT NULL,
    next_allowed_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE control.release_fleet_runs (
    id uuid NOT NULL,
    release_id text NOT NULL,
    operation_id uuid NOT NULL,
    fleet_generation bigint NOT NULL,
    state text NOT NULL,
    tenant_snapshot jsonb NOT NULL,
    canary_workshop_id uuid,
    target_slot text,
    failure_class text,
    evidence jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT release_fleet_runs_evidence_check CHECK ((jsonb_typeof(evidence) = 'object'::text)),
    CONSTRAINT release_fleet_runs_fleet_generation_check CHECK ((fleet_generation > 0)),
    CONSTRAINT release_fleet_runs_state_check CHECK ((state = ANY (ARRAY['preflighting'::text, 'preparing'::text, 'paused'::text, 'activating'::text, 'active'::text, 'failed'::text]))),
    CONSTRAINT release_fleet_runs_target_slot_check CHECK ((target_slot = ANY (ARRAY['blue'::text, 'green'::text]))),
    CONSTRAINT release_fleet_runs_tenant_snapshot_check CHECK ((jsonb_typeof(tenant_snapshot) = 'array'::text))
);

CREATE TABLE control.retention_policy_versions (
    version integer NOT NULL,
    status text NOT NULL,
    policy jsonb NOT NULL,
    policy_digest text NOT NULL,
    controller_ref text,
    approval_ref text,
    approved_by uuid,
    approved_at timestamp with time zone,
    effective_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT retention_policy_versions_check CHECK (((status = 'approved'::text) = ((approval_ref IS NOT NULL) AND (approved_by IS NOT NULL) AND (approved_at IS NOT NULL)))),
    CONSTRAINT retention_policy_versions_check1 CHECK (((status <> 'approved'::text) OR (NOT jsonb_path_exists(policy, '$."datasets".*?(@."duration_days" == null)'::jsonpath)))),
    CONSTRAINT retention_policy_versions_policy_check CHECK ((jsonb_typeof(policy) = 'object'::text)),
    CONSTRAINT retention_policy_versions_policy_digest_check CHECK ((policy_digest ~ '^sha256:[0-9a-f]{64}$'::text)),
    CONSTRAINT retention_policy_versions_status_check CHECK ((status = ANY (ARRAY['draft'::text, 'approval_required'::text, 'approved'::text, 'retired'::text]))),
    CONSTRAINT retention_policy_versions_version_check CHECK ((version > 0))
);

CREATE TABLE control.retention_runs (
    id uuid NOT NULL,
    policy_version integer,
    operation_id uuid NOT NULL,
    dry_run boolean NOT NULL,
    state text DEFAULT 'queued'::text NOT NULL,
    evidence jsonb DEFAULT '{}'::jsonb NOT NULL,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT retention_runs_check CHECK (((NOT dry_run) OR (state <> 'completed'::text) OR (COALESCE(((evidence ->> 'deleted_count'::text))::bigint, (0)::bigint) = 0))),
    CONSTRAINT retention_runs_evidence_check CHECK ((jsonb_typeof(evidence) = 'object'::text)),
    CONSTRAINT retention_runs_state_check CHECK ((state = ANY (ARRAY['queued'::text, 'running'::text, 'completed'::text, 'failed'::text, 'blocked_approval'::text])))
);

CREATE TABLE control.runtime_release_slots (
    runtime_key text NOT NULL,
    slot text NOT NULL,
    release_id text NOT NULL,
    state text NOT NULL,
    image_digest text NOT NULL,
    started_at timestamp with time zone,
    verified_at timestamp with time zone,
    activated_at timestamp with time zone,
    evidence jsonb DEFAULT '{}'::jsonb NOT NULL,
    version bigint DEFAULT 1 NOT NULL,
    CONSTRAINT runtime_release_slots_evidence_check CHECK ((jsonb_typeof(evidence) = 'object'::text)),
    CONSTRAINT runtime_release_slots_image_digest_check CHECK ((image_digest ~ '^sha256:[a-f0-9]{64}$'::text)),
    CONSTRAINT runtime_release_slots_runtime_key_check CHECK ((btrim(runtime_key) <> ''::text)),
    CONSTRAINT runtime_release_slots_slot_check CHECK ((slot = ANY (ARRAY['blue'::text, 'green'::text]))),
    CONSTRAINT runtime_release_slots_state_check CHECK ((state = ANY (ARRAY['inactive'::text, 'starting'::text, 'verifying'::text, 'prepared'::text, 'active'::text, 'retained'::text, 'failed'::text]))),
    CONSTRAINT runtime_release_slots_version_check CHECK ((version > 0))
);

CREATE TABLE control.service_instances (
    id uuid NOT NULL,
    workshop_id uuid NOT NULL,
    service text NOT NULL,
    base_url text NOT NULL,
    secret_ref text NOT NULL,
    release_id text,
    desired_epoch integer DEFAULT 1 NOT NULL,
    applied_epoch integer DEFAULT 0 NOT NULL,
    health text DEFAULT 'provisioning'::text NOT NULL,
    last_observed_at timestamp with time zone,
    safe_error_class text,
    CONSTRAINT service_instances_check CHECK (((applied_epoch >= 0) AND (applied_epoch <= desired_epoch))),
    CONSTRAINT service_instances_desired_epoch_check CHECK ((desired_epoch > 0)),
    CONSTRAINT service_instances_health_check CHECK ((health = ANY (ARRAY['provisioning'::text, 'ready'::text, 'degraded'::text, 'suspended'::text, 'failed'::text]))),
    CONSTRAINT service_instances_service_check CHECK ((service = ANY (ARRAY['odoo'::text, 'paperless'::text])))
);

CREATE TABLE control.tenant_release_adoptions (
    id uuid NOT NULL,
    workshop_id uuid NOT NULL,
    database_id uuid NOT NULL,
    release_id text NOT NULL,
    source_release_id text,
    registry_version integer NOT NULL,
    state text DEFAULT 'pending'::text NOT NULL,
    operation_id uuid,
    backup_recovery_id uuid,
    source_schema_epoch bigint,
    target_schema_epoch bigint NOT NULL,
    started_at timestamp with time zone,
    verified_at timestamp with time zone,
    activated_at timestamp with time zone,
    superseded_at timestamp with time zone,
    failure_class text,
    evidence jsonb DEFAULT '{}'::jsonb NOT NULL,
    version bigint DEFAULT 1 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT tenant_release_adoptions_check CHECK (((source_release_id IS NULL) OR (source_release_id <> release_id))),
    CONSTRAINT tenant_release_adoptions_evidence_check CHECK ((jsonb_typeof(evidence) = 'object'::text)),
    CONSTRAINT tenant_release_adoptions_registry_version_check CHECK ((registry_version > 0)),
    CONSTRAINT tenant_release_adoptions_source_schema_epoch_check CHECK (((source_schema_epoch IS NULL) OR (source_schema_epoch > 0))),
    CONSTRAINT tenant_release_adoptions_state_check CHECK ((state = ANY (ARRAY['pending'::text, 'isolating'::text, 'backing_up'::text, 'upgrading'::text, 'verifying'::text, 'prepared'::text, 'active'::text, 'superseded'::text, 'failed'::text, 'restoring'::text, 'rolled_back'::text]))),
    CONSTRAINT tenant_release_adoptions_target_schema_epoch_check CHECK ((target_schema_epoch > 0)),
    CONSTRAINT tenant_release_adoptions_version_check CHECK ((version > 0))
);

CREATE TABLE control.usage_counters (
    workshop_id uuid NOT NULL,
    period date NOT NULL,
    metric text NOT NULL,
    quantity bigint DEFAULT 0 NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT usage_counters_metric_check CHECK ((metric = ANY (ARRAY['azure_invoice_pages'::text, 'azure_inventory_images'::text, 'inventory_ai_images'::text]))),
    CONSTRAINT usage_counters_period_check CHECK (((date_trunc('month'::text, (period)::timestamp with time zone))::date = period)),
    CONSTRAINT usage_counters_quantity_check CHECK ((quantity >= 0))
);

CREATE TABLE control.usage_reservations (
    operation_id uuid NOT NULL,
    workshop_id uuid NOT NULL,
    metric text NOT NULL,
    quantity bigint NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT usage_reservations_metric_check CHECK ((metric = ANY (ARRAY['azure_invoice_pages'::text, 'azure_inventory_images'::text, 'inventory_ai_images'::text]))),
    CONSTRAINT usage_reservations_quantity_check CHECK ((quantity > 0))
);

CREATE TABLE control.users (
    id uuid NOT NULL,
    email text NOT NULL,
    display_name text,
    locale text DEFAULT 'en'::text NOT NULL,
    authority_epoch integer DEFAULT 1 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    disabled_at timestamp with time zone,
    audit_subject_id uuid DEFAULT gen_random_uuid() NOT NULL,
    CONSTRAINT users_authority_epoch_check CHECK ((authority_epoch > 0)),
    CONSTRAINT users_email_check CHECK (((email = lower(btrim(email))) AND (email <> ''::text))),
    CONSTRAINT users_locale_check CHECK ((locale = ANY (ARRAY['en'::text, 'fr'::text])))
);

CREATE TABLE control.webshop_domains (
    id uuid NOT NULL,
    workshop_id uuid NOT NULL,
    hostname text NOT NULL,
    verification_name text NOT NULL,
    verification_value text NOT NULL,
    routing_target text NOT NULL,
    state text DEFAULT 'ownership_pending'::text NOT NULL,
    desired_state text DEFAULT 'active'::text NOT NULL,
    dns_state text DEFAULT 'pending'::text NOT NULL,
    certificate_state text DEFAULT 'pending'::text NOT NULL,
    ownership_verified_at timestamp with time zone,
    dns_observed_at timestamp with time zone,
    certificate_observed_at timestamp with time zone,
    last_health_checked_at timestamp with time zone,
    last_error_class text,
    canonical boolean DEFAULT false NOT NULL,
    redirect_target text,
    provider_ref text,
    edge_verification_records jsonb DEFAULT '[]'::jsonb NOT NULL,
    operation_id uuid,
    created_by uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    disconnected_at timestamp with time zone,
    version bigint DEFAULT 1 NOT NULL,
    CONSTRAINT webshop_domains_certificate_state_check CHECK ((certificate_state = ANY (ARRAY['pending'::text, 'provisioning'::text, 'active'::text, 'failed'::text, 'expired'::text]))),
    CONSTRAINT webshop_domains_check CHECK ((verification_name = ('_mb-challenge.'::text || hostname))),
    CONSTRAINT webshop_domains_check1 CHECK (((redirect_target IS NULL) OR (redirect_target <> hostname))),
    CONSTRAINT webshop_domains_check2 CHECK (((state = 'disconnected'::text) = (disconnected_at IS NOT NULL))),
    CONSTRAINT webshop_domains_check3 CHECK (((state <> 'active'::text) OR ((ownership_verified_at IS NOT NULL) AND (dns_state = 'verified'::text) AND (certificate_state = 'active'::text) AND (provider_ref IS NOT NULL)))),
    CONSTRAINT webshop_domains_desired_state_check CHECK ((desired_state = ANY (ARRAY['active'::text, 'disconnected'::text]))),
    CONSTRAINT webshop_domains_dns_state_check CHECK ((dns_state = ANY (ARRAY['pending'::text, 'verified'::text, 'failed'::text]))),
    CONSTRAINT webshop_domains_edge_verification_records_check CHECK ((jsonb_typeof(edge_verification_records) = 'array'::text)),
    CONSTRAINT webshop_domains_hostname_check CHECK ((hostname = lower(hostname))),
    CONSTRAINT webshop_domains_hostname_check1 CHECK ((hostname ~ '^[a-z0-9][a-z0-9.-]*[a-z0-9]$'::text)),
    CONSTRAINT webshop_domains_hostname_check2 CHECK ((hostname !~ '\.\.'::text)),
    CONSTRAINT webshop_domains_routing_target_check CHECK ((routing_target ~ '^[a-z0-9][a-z0-9.-]*[a-z0-9]$'::text)),
    CONSTRAINT webshop_domains_state_check CHECK ((state = ANY (ARRAY['ownership_pending'::text, 'dns_pending'::text, 'certificate_pending'::text, 'testing'::text, 'active'::text, 'action_required'::text, 'suspended'::text, 'disconnecting'::text, 'disconnected'::text]))),
    CONSTRAINT webshop_domains_verification_value_check CHECK ((verification_value ~ '^mb-verification=[A-Za-z0-9]{32}$'::text)),
    CONSTRAINT webshop_domains_version_check CHECK ((version > 0))
);

CREATE TABLE control.webshop_email_domains (
    id uuid NOT NULL,
    workshop_id uuid NOT NULL,
    domain_name text NOT NULL,
    sender_local_part text DEFAULT 'bonjour'::text NOT NULL,
    state text DEFAULT 'registering'::text NOT NULL,
    desired_state text DEFAULT 'active'::text NOT NULL,
    provider_ref uuid,
    webhook_ref uuid,
    provider_status text,
    dns_records jsonb DEFAULT '{}'::jsonb NOT NULL,
    verification jsonb DEFAULT '{}'::jsonb NOT NULL,
    test_outbox_id uuid,
    test_delivered_at timestamp with time zone,
    operation_id uuid,
    last_error_class text,
    last_health_checked_at timestamp with time zone,
    created_by uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    disconnected_at timestamp with time zone,
    version bigint DEFAULT 1 NOT NULL,
    CONSTRAINT webshop_email_domains_check CHECK (((state <> 'active'::text) OR ((provider_ref IS NOT NULL) AND (provider_status = 'checked'::text) AND (test_delivered_at IS NOT NULL)))),
    CONSTRAINT webshop_email_domains_desired_state_check CHECK ((desired_state = ANY (ARRAY['active'::text, 'disconnected'::text]))),
    CONSTRAINT webshop_email_domains_dns_records_check CHECK ((jsonb_typeof(dns_records) = 'object'::text)),
    CONSTRAINT webshop_email_domains_domain_name_check CHECK (((domain_name = lower(domain_name)) AND ((length(domain_name) >= 4) AND (length(domain_name) <= 253)))),
    CONSTRAINT webshop_email_domains_sender_local_part_check CHECK ((sender_local_part ~ '^[a-z0-9][a-z0-9._+-]{0,63}$'::text)),
    CONSTRAINT webshop_email_domains_state_check CHECK ((state = ANY (ARRAY['registering'::text, 'dns_pending'::text, 'testing'::text, 'active'::text, 'action_required'::text, 'disconnecting'::text, 'disconnected'::text]))),
    CONSTRAINT webshop_email_domains_verification_check CHECK ((jsonb_typeof(verification) = 'object'::text))
);

CREATE TABLE control.webshop_onboarding (
    workshop_id uuid NOT NULL,
    state text DEFAULT 'not_started'::text NOT NULL,
    observation jsonb DEFAULT '{}'::jsonb NOT NULL,
    odoo_issues jsonb DEFAULT '[]'::jsonb NOT NULL,
    operation_id uuid,
    last_error_class text,
    started_at timestamp with time zone,
    last_checked_at timestamp with time zone,
    completed_at timestamp with time zone,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    version bigint DEFAULT 1 NOT NULL,
    CONSTRAINT webshop_onboarding_check CHECK (((state = 'completed'::text) = (completed_at IS NOT NULL))),
    CONSTRAINT webshop_onboarding_observation_check CHECK ((jsonb_typeof(observation) = 'object'::text)),
    CONSTRAINT webshop_onboarding_odoo_issues_check CHECK ((jsonb_typeof(odoo_issues) = 'array'::text)),
    CONSTRAINT webshop_onboarding_state_check CHECK ((state = ANY (ARRAY['not_started'::text, 'in_progress'::text, 'ready'::text, 'completed'::text, 'action_required'::text]))),
    CONSTRAINT webshop_onboarding_version_check CHECK ((version > 0))
);

CREATE TABLE control.worker_heartbeats (
    worker_id text NOT NULL,
    queue text NOT NULL,
    release_id text NOT NULL,
    started_at timestamp with time zone DEFAULT now() NOT NULL,
    last_heartbeat_at timestamp with time zone DEFAULT now() NOT NULL,
    active_operation_id uuid,
    shutdown_at timestamp with time zone,
    CONSTRAINT worker_heartbeats_check CHECK (((shutdown_at IS NULL) OR (shutdown_at >= started_at))),
    CONSTRAINT worker_heartbeats_queue_check CHECK (((length(queue) >= 1) AND (length(queue) <= 100))),
    CONSTRAINT worker_heartbeats_release_id_check CHECK (((length(release_id) >= 1) AND (length(release_id) <= 200))),
    CONSTRAINT worker_heartbeats_worker_id_check CHECK (((length(worker_id) >= 1) AND (length(worker_id) <= 200)))
);

CREATE TABLE control.workshop_deletions (
    workshop_id uuid NOT NULL,
    state text DEFAULT 'scheduled'::text NOT NULL,
    previous_status text NOT NULL,
    requested_by uuid NOT NULL,
    operation_id uuid NOT NULL,
    final_recovery_point_id uuid NOT NULL,
    requested_at timestamp with time zone DEFAULT now() NOT NULL,
    quarantined_at timestamp with time zone,
    purge_after timestamp with time zone NOT NULL,
    failure_class text,
    CONSTRAINT workshop_deletions_check CHECK ((purge_after > requested_at)),
    CONSTRAINT workshop_deletions_check1 CHECK (((state = 'retained'::text) = (quarantined_at IS NOT NULL))),
    CONSTRAINT workshop_deletions_previous_status_check CHECK ((previous_status = ANY (ARRAY['provisioning'::text, 'trial'::text, 'active'::text, 'past_due'::text, 'restricted'::text, 'suspended'::text]))),
    CONSTRAINT workshop_deletions_state_check CHECK ((state = ANY (ARRAY['scheduled'::text, 'quarantining'::text, 'retained'::text, 'failed'::text])))
);

CREATE TABLE control.workshop_modules (
    workshop_id uuid NOT NULL,
    module_key text NOT NULL,
    state text NOT NULL,
    operation_id uuid,
    requested_by uuid NOT NULL,
    requested_at timestamp with time zone DEFAULT now() NOT NULL,
    enabled_at timestamp with time zone,
    version bigint DEFAULT 1 NOT NULL,
    registry_version integer DEFAULT 1 NOT NULL,
    application_release_id text,
    entitlement_version bigint,
    resolved_implementation jsonb DEFAULT '{}'::jsonb NOT NULL,
    restriction_reason text,
    restriction_evidence jsonb,
    restricted_at timestamp with time zone,
    CONSTRAINT workshop_modules_enabled_at_check CHECK (((state <> 'enabled'::text) OR (enabled_at IS NOT NULL))),
    CONSTRAINT workshop_modules_entitlement_version_check CHECK (((entitlement_version IS NULL) OR (entitlement_version > 0))),
    CONSTRAINT workshop_modules_module_key_format CHECK ((module_key ~ '^[a-z0-9][a-z0-9-]{1,63}$'::text)),
    CONSTRAINT workshop_modules_resolved_implementation_check CHECK ((jsonb_typeof(resolved_implementation) = 'object'::text)),
    CONSTRAINT workshop_modules_restricted_evidence_check CHECK (((state <> 'restricted'::text) OR ((restriction_reason IS NOT NULL) AND (restriction_evidence IS NOT NULL) AND (restriction_evidence <> '{}'::jsonb) AND (restricted_at IS NOT NULL)))),
    CONSTRAINT workshop_modules_restriction_evidence_check CHECK (((restriction_evidence IS NULL) OR (jsonb_typeof(restriction_evidence) = 'object'::text))),
    CONSTRAINT workshop_modules_restriction_reason_check CHECK (((restriction_reason IS NULL) OR (restriction_reason ~ '^[a-z][a-z0-9_]{0,63}$'::text))),
    CONSTRAINT workshop_modules_state_check CHECK ((state = ANY (ARRAY['requested'::text, 'installing'::text, 'enabled'::text, 'failed'::text, 'restricting'::text, 'restricted'::text]))),
    CONSTRAINT workshop_modules_version_check CHECK ((version > 0))
);

CREATE TABLE control.workshop_recovery_components (
    recovery_point_id uuid NOT NULL,
    component text NOT NULL,
    object_key text NOT NULL,
    size_bytes bigint NOT NULL,
    digest text NOT NULL,
    plaintext_digest text,
    state text DEFAULT 'verified'::text NOT NULL,
    verified_at timestamp with time zone,
    CONSTRAINT workshop_recovery_components_check CHECK (((state <> 'verified'::text) OR (verified_at IS NOT NULL))),
    CONSTRAINT workshop_recovery_components_component_check CHECK ((component = ANY (ARRAY['odoo-database'::text, 'odoo-filestore'::text, 'paperless-database'::text, 'paperless-data'::text, 'paperless-media'::text, 'paperless-consume'::text, 'manifest'::text, 'commit-marker'::text, 'portable-archive'::text]))),
    CONSTRAINT workshop_recovery_components_digest_check CHECK ((digest ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT workshop_recovery_components_object_key_check CHECK ((btrim(object_key) <> ''::text)),
    CONSTRAINT workshop_recovery_components_plaintext_digest_check CHECK (((plaintext_digest IS NULL) OR (plaintext_digest ~ '^[0-9a-f]{64}$'::text))),
    CONSTRAINT workshop_recovery_components_size_bytes_check CHECK ((size_bytes >= 0)),
    CONSTRAINT workshop_recovery_components_state_check CHECK ((state = ANY (ARRAY['uploading'::text, 'verified'::text, 'failed'::text])))
);

CREATE TABLE control.workshop_recovery_points (
    id uuid NOT NULL,
    workshop_id uuid NOT NULL,
    database_id uuid NOT NULL,
    operation_id uuid,
    kind text NOT NULL,
    label text NOT NULL,
    state text DEFAULT 'queued'::text NOT NULL,
    storage_ref text,
    size_bytes bigint,
    requested_by uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    ready_at timestamp with time zone,
    expires_at timestamp with time zone,
    component_scope text[] DEFAULT ARRAY['odoo'::text] NOT NULL,
    format_version text DEFAULT 'mb-workshop-recovery-v2'::text NOT NULL,
    storage_location text DEFAULT 'local'::text NOT NULL,
    object_prefix text,
    manifest_digest text,
    encryption_key_id text,
    source_release text,
    paperless_version text,
    verification_state text DEFAULT 'pending'::text NOT NULL,
    verified_at timestamp with time zone,
    archive_object_key text,
    archive_size_bytes bigint,
    archive_digest text,
    CONSTRAINT odoo_recovery_points_check CHECK (((state <> 'ready'::text) OR (ready_at IS NOT NULL))),
    CONSTRAINT odoo_recovery_points_check1 CHECK (((expires_at IS NULL) OR (expires_at > created_at))),
    CONSTRAINT odoo_recovery_points_kind_check CHECK ((kind = ANY (ARRAY['snapshot'::text, 'backup'::text]))),
    CONSTRAINT odoo_recovery_points_label_check CHECK ((btrim(label) <> ''::text)),
    CONSTRAINT odoo_recovery_points_size_bytes_check CHECK (((size_bytes IS NULL) OR (size_bytes >= 0))),
    CONSTRAINT odoo_recovery_points_state_check CHECK ((state = ANY (ARRAY['queued'::text, 'creating'::text, 'ready'::text, 'failed'::text, 'expired'::text, 'deleted'::text]))),
    CONSTRAINT workshop_recovery_points_archive_digest_check CHECK (((archive_digest IS NULL) OR (archive_digest ~ '^[0-9a-f]{64}$'::text))),
    CONSTRAINT workshop_recovery_points_archive_size_bytes_check CHECK ((archive_size_bytes >= 0)),
    CONSTRAINT workshop_recovery_points_component_scope_check CHECK (((cardinality(component_scope) > 0) AND (component_scope @> ARRAY['odoo'::text]) AND (component_scope <@ ARRAY['odoo'::text, 'paperless'::text]))),
    CONSTRAINT workshop_recovery_points_format_version_check CHECK ((format_version = 'mb-workshop-recovery-v2'::text)),
    CONSTRAINT workshop_recovery_points_manifest_digest_check CHECK (((manifest_digest IS NULL) OR (manifest_digest ~ '^[0-9a-f]{64}$'::text))),
    CONSTRAINT workshop_recovery_points_storage_location_check CHECK ((storage_location = ANY (ARRAY['local'::text, 's3'::text]))),
    CONSTRAINT workshop_recovery_points_verification_state_check CHECK ((verification_state = ANY (ARRAY['pending'::text, 'verified'::text, 'failed'::text]))),
    CONSTRAINT workshop_recovery_points_verified_check CHECK (((verification_state <> 'verified'::text) OR (verified_at IS NOT NULL)))
);

CREATE TABLE control.workshop_recovery_rehearsals (
    id uuid NOT NULL,
    recovery_point_id uuid NOT NULL,
    workshop_id uuid NOT NULL,
    state text NOT NULL,
    started_at timestamp with time zone DEFAULT now() NOT NULL,
    finished_at timestamp with time zone,
    safe_error text,
    CONSTRAINT workshop_recovery_rehearsals_check CHECK (((state = 'running'::text) OR (finished_at IS NOT NULL))),
    CONSTRAINT workshop_recovery_rehearsals_state_check CHECK ((state = ANY (ARRAY['running'::text, 'succeeded'::text, 'failed'::text])))
);

CREATE TABLE control.workshops (
    id uuid NOT NULL,
    slug text NOT NULL,
    display_name text NOT NULL,
    legal_name text,
    country_code text,
    time_zone text NOT NULL,
    plan text DEFAULT 'trial'::text NOT NULL,
    status text DEFAULT 'provisioning'::text NOT NULL,
    version bigint DEFAULT 1 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT workshops_country_code_check CHECK ((country_code ~ '^[A-Z]{2}$'::text)),
    CONSTRAINT workshops_display_name_check CHECK ((btrim(display_name) <> ''::text)),
    CONSTRAINT workshops_slug_check CHECK ((slug ~ '^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$'::text)),
    CONSTRAINT workshops_status_check CHECK ((status = ANY (ARRAY['provisioning'::text, 'trial'::text, 'active'::text, 'past_due'::text, 'restricted'::text, 'suspended'::text, 'deleting'::text, 'deleted'::text]))),
    CONSTRAINT workshops_version_check CHECK ((version > 0))
);

ALTER TABLE ONLY control.application_releases
    ADD CONSTRAINT application_releases_image_digest_key UNIQUE (image_digest);

ALTER TABLE ONLY control.application_releases
    ADD CONSTRAINT application_releases_manifest_digest_key UNIQUE (manifest_digest);

ALTER TABLE ONLY control.application_releases
    ADD CONSTRAINT application_releases_pkey PRIMARY KEY (id);

ALTER TABLE ONLY control.application_releases
    ADD CONSTRAINT application_releases_publication_idempotency_key_key UNIQUE (publication_idempotency_key);

ALTER TABLE ONLY control.audit_events
    ADD CONSTRAINT audit_events_pkey PRIMARY KEY (id);

ALTER TABLE ONLY control.capability_registry_entries
    ADD CONSTRAINT capability_registry_entries_pkey PRIMARY KEY (registry_version, capability_key);

ALTER TABLE ONLY control.capability_registry_versions
    ADD CONSTRAINT capability_registry_versions_pkey PRIMARY KEY (version);

ALTER TABLE ONLY control.carrier_secrets
    ADD CONSTRAINT carrier_secrets_pkey PRIMARY KEY (id);

ALTER TABLE ONLY control.carrier_secrets
    ADD CONSTRAINT carrier_secrets_secret_ref_key UNIQUE (secret_ref);

ALTER TABLE ONLY control.carrier_secrets
    ADD CONSTRAINT carrier_secrets_workshop_id_provider_environment_company_id_key UNIQUE (workshop_id, provider, environment, company_id, carrier_id);

ALTER TABLE ONLY control.commands
    ADD CONSTRAINT commands_actor_user_id_scope_command_kind_idempotency_key_key UNIQUE (actor_user_id, scope, command_kind, idempotency_key);

ALTER TABLE ONLY control.commands
    ADD CONSTRAINT commands_pkey PRIMARY KEY (id);

ALTER TABLE ONLY control.data_subject_exports
    ADD CONSTRAINT data_subject_exports_data_subject_request_id_key UNIQUE (data_subject_request_id);

ALTER TABLE ONLY control.data_subject_exports
    ADD CONSTRAINT data_subject_exports_pkey PRIMARY KEY (id);

ALTER TABLE ONLY control.data_subject_processor_tasks
    ADD CONSTRAINT data_subject_processor_tasks_data_subject_request_id_proces_key UNIQUE (data_subject_request_id, processor_key, action);

ALTER TABLE ONLY control.data_subject_processor_tasks
    ADD CONSTRAINT data_subject_processor_tasks_pkey PRIMARY KEY (id);

ALTER TABLE ONLY control.data_subject_requests
    ADD CONSTRAINT data_subject_requests_pkey PRIMARY KEY (id);

ALTER TABLE ONLY control.deployment_driver_operations
    ADD CONSTRAINT deployment_driver_operations_pkey PRIMARY KEY (idempotency_key);

ALTER TABLE ONLY control.email_delivery_events
    ADD CONSTRAINT email_delivery_events_pkey PRIMARY KEY (event_id);

ALTER TABLE ONLY control.email_suppressions
    ADD CONSTRAINT email_suppressions_pkey PRIMARY KEY (workshop_id, recipient);

ALTER TABLE ONLY control.entitlements
    ADD CONSTRAINT entitlements_pkey PRIMARY KEY (workshop_id);

ALTER TABLE ONLY control.erasure_restore_replays
    ADD CONSTRAINT erasure_restore_replays_pkey PRIMARY KEY (id);

ALTER TABLE ONLY control.erasure_restore_replays
    ADD CONSTRAINT erasure_restore_replays_tombstone_id_recovery_point_id_key UNIQUE (tombstone_id, recovery_point_id);

ALTER TABLE ONLY control.erasure_subject_lookups
    ADD CONSTRAINT erasure_subject_lookups_pkey PRIMARY KEY (tombstone_id);

ALTER TABLE ONLY control.erasure_tombstones
    ADD CONSTRAINT erasure_tombstones_pkey PRIMARY KEY (id);

ALTER TABLE ONLY control.erasure_tombstones
    ADD CONSTRAINT erasure_tombstones_sequence_key UNIQUE (sequence);

ALTER TABLE ONLY control.external_identities
    ADD CONSTRAINT external_identities_issuer_subject_key UNIQUE (issuer, subject);

ALTER TABLE ONLY control.external_identities
    ADD CONSTRAINT external_identities_pkey PRIMARY KEY (id);

ALTER TABLE ONLY control.external_identities
    ADD CONSTRAINT external_identities_user_id_key UNIQUE (user_id);

ALTER TABLE ONLY control.fleet_activation_intents
    ADD CONSTRAINT fleet_activation_intents_driver_action_id_key UNIQUE (driver_action_id);

ALTER TABLE ONLY control.fleet_activation_intents
    ADD CONSTRAINT fleet_activation_intents_fleet_run_id_key UNIQUE (fleet_run_id);

ALTER TABLE ONLY control.fleet_activation_intents
    ADD CONSTRAINT fleet_activation_intents_pkey PRIMARY KEY (id);

ALTER TABLE ONLY control.invitations
    ADD CONSTRAINT invitations_pkey PRIMARY KEY (id);

ALTER TABLE ONLY control.invitations
    ADD CONSTRAINT invitations_token_hash_key UNIQUE (token_hash);

ALTER TABLE ONLY control.legal_holds
    ADD CONSTRAINT legal_holds_pkey PRIMARY KEY (id);

ALTER TABLE ONLY control.membership_targets
    ADD CONSTRAINT membership_targets_pkey PRIMARY KEY (workshop_id, user_id, target);

ALTER TABLE ONLY control.memberships
    ADD CONSTRAINT memberships_pkey PRIMARY KEY (workshop_id, user_id);

ALTER TABLE ONLY control.odoo_databases
    ADD CONSTRAINT odoo_databases_database_ref_key UNIQUE (database_ref);

ALTER TABLE ONLY control.odoo_databases
    ADD CONSTRAINT odoo_databases_id_workshop_id_key UNIQUE (id, workshop_id);

ALTER TABLE ONLY control.odoo_databases
    ADD CONSTRAINT odoo_databases_pkey PRIMARY KEY (id);

ALTER TABLE ONLY control.odoo_databases
    ADD CONSTRAINT odoo_databases_public_hostname_key UNIQUE (public_hostname);

ALTER TABLE ONLY control.workshop_recovery_points
    ADD CONSTRAINT odoo_recovery_points_pkey PRIMARY KEY (id);

ALTER TABLE ONLY control.operations
    ADD CONSTRAINT operations_kind_requested_by_idempotency_key_key UNIQUE NULLS NOT DISTINCT (kind, requested_by, idempotency_key);

ALTER TABLE ONLY control.operations
    ADD CONSTRAINT operations_pkey PRIMARY KEY (id);

ALTER TABLE ONLY control.outbox
    ADD CONSTRAINT outbox_invitation_generation_unique UNIQUE (invitation_id, token_generation);

ALTER TABLE ONLY control.outbox
    ADD CONSTRAINT outbox_pkey PRIMARY KEY (id);

ALTER TABLE ONLY control.outbox
    ADD CONSTRAINT outbox_provider_message_id_key UNIQUE (provider_message_id);

ALTER TABLE ONLY control.ownership_transfers
    ADD CONSTRAINT ownership_transfers_from_user_id_idempotency_key_key UNIQUE (from_user_id, idempotency_key);

ALTER TABLE ONLY control.ownership_transfers
    ADD CONSTRAINT ownership_transfers_pkey PRIMARY KEY (id);

ALTER TABLE ONLY control.platform_authority_state
    ADD CONSTRAINT platform_authority_state_pkey PRIMARY KEY (singleton);

ALTER TABLE ONLY control.platform_role_assignments
    ADD CONSTRAINT platform_role_assignments_pkey PRIMARY KEY (id);

ALTER TABLE ONLY control.privacy_incidents
    ADD CONSTRAINT privacy_incidents_pkey PRIMARY KEY (id);

ALTER TABLE ONLY control.privacy_platform_state
    ADD CONSTRAINT privacy_platform_state_pkey PRIMARY KEY (singleton);

ALTER TABLE ONLY control.processing_holds
    ADD CONSTRAINT processing_holds_pkey PRIMARY KEY (id);

ALTER TABLE ONLY control.processing_register_versions
    ADD CONSTRAINT processing_register_versions_pkey PRIMARY KEY (version);

ALTER TABLE ONLY control.processing_register_versions
    ADD CONSTRAINT processing_register_versions_register_digest_key UNIQUE (register_digest);

ALTER TABLE ONLY control.processor_approvals
    ADD CONSTRAINT processor_approvals_pkey PRIMARY KEY (id);

ALTER TABLE ONLY control.processor_approvals
    ADD CONSTRAINT processor_approvals_processing_register_version_provider_ke_key UNIQUE (processing_register_version, provider_key, purpose_key);

ALTER TABLE ONLY control.product_lookup_cache
    ADD CONSTRAINT product_lookup_cache_pkey PRIMARY KEY (provider, schema_version, gtin14);

ALTER TABLE ONLY control.product_lookup_fills
    ADD CONSTRAINT product_lookup_fills_pkey PRIMARY KEY (provider, schema_version, gtin14);

ALTER TABLE ONLY control.provider_rate_limits
    ADD CONSTRAINT provider_rate_limits_pkey PRIMARY KEY (provider);

ALTER TABLE ONLY control.release_fleet_runs
    ADD CONSTRAINT release_fleet_runs_operation_id_key UNIQUE (operation_id);

ALTER TABLE ONLY control.release_fleet_runs
    ADD CONSTRAINT release_fleet_runs_pkey PRIMARY KEY (id);

ALTER TABLE ONLY control.retention_policy_versions
    ADD CONSTRAINT retention_policy_versions_pkey PRIMARY KEY (version);

ALTER TABLE ONLY control.retention_policy_versions
    ADD CONSTRAINT retention_policy_versions_policy_digest_key UNIQUE (policy_digest);

ALTER TABLE ONLY control.retention_runs
    ADD CONSTRAINT retention_runs_operation_id_key UNIQUE (operation_id);

ALTER TABLE ONLY control.retention_runs
    ADD CONSTRAINT retention_runs_pkey PRIMARY KEY (id);

ALTER TABLE ONLY control.runtime_release_slots
    ADD CONSTRAINT runtime_release_slots_pkey PRIMARY KEY (runtime_key, slot);

ALTER TABLE ONLY control.service_instances
    ADD CONSTRAINT service_instances_pkey PRIMARY KEY (id);

ALTER TABLE ONLY control.service_instances
    ADD CONSTRAINT service_instances_workshop_id_service_key UNIQUE (workshop_id, service);

ALTER TABLE ONLY control.tenant_release_adoptions
    ADD CONSTRAINT tenant_release_adoptions_pkey PRIMARY KEY (id);

ALTER TABLE ONLY control.tenant_release_adoptions
    ADD CONSTRAINT tenant_release_adoptions_workshop_id_database_id_release_id_key UNIQUE (workshop_id, database_id, release_id);

ALTER TABLE ONLY control.usage_counters
    ADD CONSTRAINT usage_counters_pkey PRIMARY KEY (workshop_id, period, metric);

ALTER TABLE ONLY control.usage_reservations
    ADD CONSTRAINT usage_reservations_pkey PRIMARY KEY (operation_id, metric);

ALTER TABLE ONLY control.users
    ADD CONSTRAINT users_audit_subject_unique UNIQUE (audit_subject_id);

ALTER TABLE ONLY control.users
    ADD CONSTRAINT users_email_key UNIQUE (email);

ALTER TABLE ONLY control.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);

ALTER TABLE ONLY control.webshop_domains
    ADD CONSTRAINT webshop_domains_hostname_key UNIQUE (hostname);

ALTER TABLE ONLY control.webshop_domains
    ADD CONSTRAINT webshop_domains_pkey PRIMARY KEY (id);

ALTER TABLE ONLY control.webshop_domains
    ADD CONSTRAINT webshop_domains_verification_value_key UNIQUE (verification_value);

ALTER TABLE ONLY control.webshop_email_domains
    ADD CONSTRAINT webshop_email_domains_domain_name_key UNIQUE (domain_name);

ALTER TABLE ONLY control.webshop_email_domains
    ADD CONSTRAINT webshop_email_domains_pkey PRIMARY KEY (id);

ALTER TABLE ONLY control.webshop_onboarding
    ADD CONSTRAINT webshop_onboarding_pkey PRIMARY KEY (workshop_id);

ALTER TABLE ONLY control.worker_heartbeats
    ADD CONSTRAINT worker_heartbeats_pkey PRIMARY KEY (worker_id);

ALTER TABLE ONLY control.workshop_deletions
    ADD CONSTRAINT workshop_deletions_final_recovery_point_id_key UNIQUE (final_recovery_point_id);

ALTER TABLE ONLY control.workshop_deletions
    ADD CONSTRAINT workshop_deletions_operation_id_key UNIQUE (operation_id);

ALTER TABLE ONLY control.workshop_deletions
    ADD CONSTRAINT workshop_deletions_pkey PRIMARY KEY (workshop_id);

ALTER TABLE ONLY control.workshop_modules
    ADD CONSTRAINT workshop_modules_pkey PRIMARY KEY (workshop_id, module_key);

ALTER TABLE ONLY control.workshop_recovery_components
    ADD CONSTRAINT workshop_recovery_components_pkey PRIMARY KEY (recovery_point_id, component);

ALTER TABLE ONLY control.workshop_recovery_rehearsals
    ADD CONSTRAINT workshop_recovery_rehearsals_pkey PRIMARY KEY (id);

ALTER TABLE ONLY control.workshops
    ADD CONSTRAINT workshops_pkey PRIMARY KEY (id);

ALTER TABLE ONLY control.workshops
    ADD CONSTRAINT workshops_slug_key UNIQUE (slug);

CREATE UNIQUE INDEX application_release_one_active ON control.application_releases USING btree (status) WHERE (status = 'active'::text);

CREATE INDEX audit_events_actor_subject ON control.audit_events USING btree (actor_audit_subject_id, created_at DESC);

CREATE INDEX audit_events_created ON control.audit_events USING btree (created_at DESC, id DESC);

CREATE UNIQUE INDEX capability_registry_one_active ON control.capability_registry_versions USING btree (active) WHERE active;

CREATE INDEX carrier_secrets_workshop ON control.carrier_secrets USING btree (workshop_id, state, provider);

CREATE INDEX commands_created ON control.commands USING btree (created_at DESC, id DESC);

CREATE INDEX data_subject_exports_terminal_file_artifacts ON control.data_subject_exports USING btree (id) WHERE ((state = ANY (ARRAY['consumed'::text, 'expired'::text, 'revoked'::text])) AND (storage_ref ~~ 'file:%.aead'::text));

CREATE INDEX data_subject_requests_due ON control.data_subject_requests USING btree (COALESCE(extended_due_at, due_at)) WHERE (status <> ALL (ARRAY['completed'::text, 'refused'::text, 'cancelled'::text]));

CREATE INDEX deployment_driver_operations_workshop ON control.deployment_driver_operations USING btree (workshop_id, created_at DESC);

CREATE INDEX email_delivery_events_outbox_occurred ON control.email_delivery_events USING btree (outbox_id, occurred_at DESC);

CREATE UNIQUE INDEX erasure_tombstone_request_scope ON control.erasure_tombstones USING btree (source_request_id, COALESCE(workshop_id, '00000000-0000-0000-0000-000000000000'::uuid));

CREATE UNIQUE INDEX invitations_one_pending ON control.invitations USING btree (workshop_id, email) WHERE ((accepted_at IS NULL) AND (revoked_at IS NULL));

CREATE UNIQUE INDEX odoo_databases_one_primary ON control.odoo_databases USING btree (workshop_id) WHERE ((kind = 'primary'::text) AND (deleted_at IS NULL));

CREATE INDEX operations_due ON control.operations USING btree (queue, next_attempt_at, created_at) WHERE (state = ANY (ARRAY['pending'::text, 'in_flight'::text, 'awaiting_reconciliation'::text]));

CREATE INDEX outbox_workshop_delivery_state ON control.outbox USING btree (workshop_id, delivery_state, created_at DESC) WHERE (workshop_id IS NOT NULL);

CREATE UNIQUE INDEX outbox_workshop_source_unique ON control.outbox USING btree (workshop_id, source_key) WHERE (source_key IS NOT NULL);

CREATE INDEX platform_role_assignments_active_user ON control.platform_role_assignments USING btree (user_id, role) WHERE (revoked_at IS NULL);

CREATE UNIQUE INDEX platform_role_assignments_one_active_role ON control.platform_role_assignments USING btree (user_id, role) WHERE (revoked_at IS NULL);

CREATE UNIQUE INDEX processing_hold_active_subject_scope ON control.processing_holds USING btree (subject_user_id, COALESCE(workshop_id, '00000000-0000-0000-0000-000000000000'::uuid)) WHERE active;

CREATE INDEX product_lookup_cache_expiry_idx ON control.product_lookup_cache USING btree (expires_at);

CREATE INDEX product_lookup_fills_expired ON control.product_lookup_fills USING btree (lease_expires_at) WHERE (state = 'filling'::text);

CREATE UNIQUE INDEX release_fleet_one_unfinished ON control.release_fleet_runs USING btree ((true)) WHERE (state = ANY (ARRAY['preflighting'::text, 'preparing'::text, 'paused'::text, 'activating'::text]));

CREATE UNIQUE INDEX runtime_release_one_active ON control.runtime_release_slots USING btree (runtime_key) WHERE (state = 'active'::text);

CREATE UNIQUE INDEX tenant_release_one_active ON control.tenant_release_adoptions USING btree (workshop_id, database_id) WHERE (state = 'active'::text);

CREATE UNIQUE INDEX tenant_release_one_unfinished ON control.tenant_release_adoptions USING btree (workshop_id, database_id) WHERE (state = ANY (ARRAY['pending'::text, 'isolating'::text, 'backing_up'::text, 'upgrading'::text, 'verifying'::text, 'prepared'::text, 'failed'::text, 'restoring'::text]));

CREATE UNIQUE INDEX webshop_domains_one_canonical ON control.webshop_domains USING btree (workshop_id) WHERE (canonical AND (state <> 'disconnected'::text));

CREATE INDEX webshop_domains_workshop ON control.webshop_domains USING btree (workshop_id, state, created_at);

CREATE UNIQUE INDEX webshop_email_domains_one_active ON control.webshop_email_domains USING btree (workshop_id) WHERE ((state = 'active'::text) AND (desired_state = 'active'::text));

CREATE INDEX webshop_email_domains_reconcile ON control.webshop_email_domains USING btree (state, desired_state, updated_at);

CREATE INDEX worker_heartbeats_freshness ON control.worker_heartbeats USING btree (queue, last_heartbeat_at DESC) WHERE (shutdown_at IS NULL);

CREATE UNIQUE INDEX workshop_recovery_operation_database ON control.workshop_recovery_points USING btree (operation_id, database_id) WHERE (operation_id IS NOT NULL);

CREATE INDEX workshop_recovery_points_workshop ON control.workshop_recovery_points USING btree (workshop_id, created_at DESC);

CREATE INDEX workshop_recovery_rehearsals_due ON control.workshop_recovery_rehearsals USING btree (workshop_id, started_at DESC);

CREATE TRIGGER application_release_transition BEFORE UPDATE ON control.application_releases FOR EACH ROW EXECUTE FUNCTION control.validate_application_release_transition();

CREATE TRIGGER audit_events_append_only BEFORE DELETE OR UPDATE ON control.audit_events FOR EACH ROW EXECUTE FUNCTION control.reject_audit_mutation();

CREATE TRIGGER data_subject_request_transition BEFORE UPDATE ON control.data_subject_requests FOR EACH ROW EXECUTE FUNCTION control.validate_data_subject_request_transition();

CREATE TRIGGER fleet_activation_intent_update BEFORE UPDATE ON control.fleet_activation_intents FOR EACH ROW EXECUTE FUNCTION control.validate_fleet_activation_intent_update();

CREATE TRIGGER legal_hold_update BEFORE UPDATE ON control.legal_holds FOR EACH ROW EXECUTE FUNCTION control.validate_legal_hold_update();

CREATE CONSTRAINT TRIGGER memberships_keep_owner AFTER INSERT OR DELETE OR UPDATE ON control.memberships DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION control.assert_last_owner();

CREATE TRIGGER operations_subject_processing_hold BEFORE INSERT ON control.operations FOR EACH ROW EXECUTE FUNCTION control.enforce_subject_processing_hold();

CREATE CONSTRAINT TRIGGER platform_requires_technical_admin AFTER INSERT OR UPDATE ON control.platform_role_assignments DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION control.require_technical_admin();

CREATE TRIGGER platform_role_assignment_update BEFORE UPDATE ON control.platform_role_assignments FOR EACH ROW EXECUTE FUNCTION control.validate_platform_role_update();

CREATE TRIGGER privacy_incident_deadline BEFORE INSERT OR UPDATE OF controller_awareness_at ON control.privacy_incidents FOR EACH ROW EXECUTE FUNCTION control.set_privacy_incident_deadline();

CREATE TRIGGER privacy_incident_update BEFORE UPDATE ON control.privacy_incidents FOR EACH ROW EXECUTE FUNCTION control.validate_privacy_incident_update();

CREATE TRIGGER privacy_platform_state_update BEFORE UPDATE ON control.privacy_platform_state FOR EACH ROW EXECUTE FUNCTION control.validate_privacy_platform_state();

CREATE TRIGGER processor_task_update BEFORE UPDATE ON control.data_subject_processor_tasks FOR EACH ROW EXECUTE FUNCTION control.validate_processor_task_update();

CREATE TRIGGER tenant_release_transition BEFORE UPDATE ON control.tenant_release_adoptions FOR EACH ROW EXECUTE FUNCTION control.validate_tenant_release_transition();

CREATE TRIGGER workshop_module_update BEFORE UPDATE ON control.workshop_modules FOR EACH ROW EXECUTE FUNCTION control.validate_workshop_module_update();

ALTER TABLE ONLY control.audit_events
    ADD CONSTRAINT audit_events_workshop_id_fkey FOREIGN KEY (workshop_id) REFERENCES control.workshops(id) ON DELETE RESTRICT;

ALTER TABLE ONLY control.capability_registry_entries
    ADD CONSTRAINT capability_registry_entries_registry_version_fkey FOREIGN KEY (registry_version) REFERENCES control.capability_registry_versions(version) ON DELETE RESTRICT;

ALTER TABLE ONLY control.carrier_secrets
    ADD CONSTRAINT carrier_secrets_created_by_fkey FOREIGN KEY (created_by) REFERENCES control.users(id) ON DELETE RESTRICT;

ALTER TABLE ONLY control.carrier_secrets
    ADD CONSTRAINT carrier_secrets_workshop_id_fkey FOREIGN KEY (workshop_id) REFERENCES control.workshops(id) ON DELETE RESTRICT;

ALTER TABLE ONLY control.commands
    ADD CONSTRAINT commands_actor_user_id_fkey FOREIGN KEY (actor_user_id) REFERENCES control.users(id) ON DELETE RESTRICT;

ALTER TABLE ONLY control.commands
    ADD CONSTRAINT commands_operation_id_fkey FOREIGN KEY (operation_id) REFERENCES control.operations(id) ON DELETE RESTRICT;

ALTER TABLE ONLY control.data_subject_exports
    ADD CONSTRAINT data_subject_exports_data_subject_request_id_fkey FOREIGN KEY (data_subject_request_id) REFERENCES control.data_subject_requests(id) ON DELETE RESTRICT;

ALTER TABLE ONLY control.data_subject_processor_tasks
    ADD CONSTRAINT data_subject_processor_tasks_data_subject_request_id_fkey FOREIGN KEY (data_subject_request_id) REFERENCES control.data_subject_requests(id) ON DELETE RESTRICT;

ALTER TABLE ONLY control.data_subject_requests
    ADD CONSTRAINT data_subject_requests_approver_user_id_fkey FOREIGN KEY (approver_user_id) REFERENCES control.users(id) ON DELETE RESTRICT;

ALTER TABLE ONLY control.data_subject_requests
    ADD CONSTRAINT data_subject_requests_operation_id_fkey FOREIGN KEY (operation_id) REFERENCES control.operations(id) ON DELETE RESTRICT;

ALTER TABLE ONLY control.data_subject_requests
    ADD CONSTRAINT data_subject_requests_subject_user_id_fkey FOREIGN KEY (subject_user_id) REFERENCES control.users(id) ON DELETE RESTRICT;

ALTER TABLE ONLY control.deployment_driver_operations
    ADD CONSTRAINT deployment_driver_operations_workshop_id_fkey FOREIGN KEY (workshop_id) REFERENCES control.workshops(id) ON DELETE RESTRICT;

ALTER TABLE ONLY control.email_delivery_events
    ADD CONSTRAINT email_delivery_events_outbox_id_fkey FOREIGN KEY (outbox_id) REFERENCES control.outbox(id) ON DELETE CASCADE;

ALTER TABLE ONLY control.email_suppressions
    ADD CONSTRAINT email_suppressions_source_event_id_fkey FOREIGN KEY (source_event_id) REFERENCES control.email_delivery_events(event_id) ON DELETE RESTRICT;

ALTER TABLE ONLY control.email_suppressions
    ADD CONSTRAINT email_suppressions_workshop_id_fkey FOREIGN KEY (workshop_id) REFERENCES control.workshops(id) ON DELETE CASCADE;

ALTER TABLE ONLY control.entitlements
    ADD CONSTRAINT entitlements_workshop_id_fkey FOREIGN KEY (workshop_id) REFERENCES control.workshops(id) ON DELETE RESTRICT;

ALTER TABLE ONLY control.erasure_restore_replays
    ADD CONSTRAINT erasure_restore_replays_operation_id_fkey FOREIGN KEY (operation_id) REFERENCES control.operations(id) ON DELETE RESTRICT;

ALTER TABLE ONLY control.erasure_restore_replays
    ADD CONSTRAINT erasure_restore_replays_recovery_point_id_fkey FOREIGN KEY (recovery_point_id) REFERENCES control.workshop_recovery_points(id) ON DELETE RESTRICT;

ALTER TABLE ONLY control.erasure_restore_replays
    ADD CONSTRAINT erasure_restore_replays_tombstone_id_fkey FOREIGN KEY (tombstone_id) REFERENCES control.erasure_tombstones(id) ON DELETE RESTRICT;

ALTER TABLE ONLY control.erasure_subject_lookups
    ADD CONSTRAINT erasure_subject_lookups_tombstone_id_fkey FOREIGN KEY (tombstone_id) REFERENCES control.erasure_tombstones(id) ON DELETE CASCADE;

ALTER TABLE ONLY control.erasure_tombstones
    ADD CONSTRAINT erasure_tombstones_source_request_id_fkey FOREIGN KEY (source_request_id) REFERENCES control.data_subject_requests(id) ON DELETE RESTRICT;

ALTER TABLE ONLY control.erasure_tombstones
    ADD CONSTRAINT erasure_tombstones_subject_user_id_fkey FOREIGN KEY (subject_user_id) REFERENCES control.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY control.erasure_tombstones
    ADD CONSTRAINT erasure_tombstones_workshop_id_fkey FOREIGN KEY (workshop_id) REFERENCES control.workshops(id) ON DELETE RESTRICT;

ALTER TABLE ONLY control.external_identities
    ADD CONSTRAINT external_identities_user_id_fkey FOREIGN KEY (user_id) REFERENCES control.users(id) ON DELETE RESTRICT;

ALTER TABLE ONLY control.fleet_activation_intents
    ADD CONSTRAINT fleet_activation_intents_fleet_run_id_fkey FOREIGN KEY (fleet_run_id) REFERENCES control.release_fleet_runs(id) ON DELETE RESTRICT;

ALTER TABLE ONLY control.fleet_activation_intents
    ADD CONSTRAINT fleet_activation_intents_release_id_fkey FOREIGN KEY (release_id) REFERENCES control.application_releases(id) ON DELETE RESTRICT;

ALTER TABLE ONLY control.invitations
    ADD CONSTRAINT invitations_accepted_user_id_fkey FOREIGN KEY (accepted_user_id) REFERENCES control.users(id) ON DELETE RESTRICT;

ALTER TABLE ONLY control.invitations
    ADD CONSTRAINT invitations_invited_by_fkey FOREIGN KEY (invited_by) REFERENCES control.users(id) ON DELETE RESTRICT;

ALTER TABLE ONLY control.invitations
    ADD CONSTRAINT invitations_workshop_id_fkey FOREIGN KEY (workshop_id) REFERENCES control.workshops(id) ON DELETE CASCADE;

ALTER TABLE ONLY control.legal_holds
    ADD CONSTRAINT legal_holds_imposed_by_fkey FOREIGN KEY (imposed_by) REFERENCES control.users(id) ON DELETE RESTRICT;

ALTER TABLE ONLY control.legal_holds
    ADD CONSTRAINT legal_holds_released_by_fkey FOREIGN KEY (released_by) REFERENCES control.users(id) ON DELETE RESTRICT;

ALTER TABLE ONLY control.membership_targets
    ADD CONSTRAINT membership_targets_workshop_id_user_id_fkey FOREIGN KEY (workshop_id, user_id) REFERENCES control.memberships(workshop_id, user_id) ON DELETE CASCADE;

ALTER TABLE ONLY control.memberships
    ADD CONSTRAINT memberships_user_id_fkey FOREIGN KEY (user_id) REFERENCES control.users(id) ON DELETE RESTRICT;

ALTER TABLE ONLY control.memberships
    ADD CONSTRAINT memberships_workshop_id_fkey FOREIGN KEY (workshop_id) REFERENCES control.workshops(id) ON DELETE RESTRICT;

ALTER TABLE ONLY control.odoo_databases
    ADD CONSTRAINT odoo_databases_service_instance_id_fkey FOREIGN KEY (service_instance_id) REFERENCES control.service_instances(id) ON DELETE RESTRICT;

ALTER TABLE ONLY control.odoo_databases
    ADD CONSTRAINT odoo_databases_source_database_id_workshop_id_fkey FOREIGN KEY (source_database_id, workshop_id) REFERENCES control.odoo_databases(id, workshop_id) ON DELETE RESTRICT;

ALTER TABLE ONLY control.odoo_databases
    ADD CONSTRAINT odoo_databases_workshop_id_fkey FOREIGN KEY (workshop_id) REFERENCES control.workshops(id) ON DELETE RESTRICT;

ALTER TABLE ONLY control.workshop_recovery_points
    ADD CONSTRAINT odoo_recovery_points_database_id_workshop_id_fkey FOREIGN KEY (database_id, workshop_id) REFERENCES control.odoo_databases(id, workshop_id) ON DELETE RESTRICT;

ALTER TABLE ONLY control.workshop_recovery_points
    ADD CONSTRAINT odoo_recovery_points_operation_id_fkey FOREIGN KEY (operation_id) REFERENCES control.operations(id) ON DELETE RESTRICT;

ALTER TABLE ONLY control.workshop_recovery_points
    ADD CONSTRAINT odoo_recovery_points_requested_by_fkey FOREIGN KEY (requested_by) REFERENCES control.users(id) ON DELETE RESTRICT;

ALTER TABLE ONLY control.workshop_recovery_points
    ADD CONSTRAINT odoo_recovery_points_workshop_id_fkey FOREIGN KEY (workshop_id) REFERENCES control.workshops(id) ON DELETE RESTRICT;

ALTER TABLE ONLY control.operations
    ADD CONSTRAINT operations_requested_by_fkey FOREIGN KEY (requested_by) REFERENCES control.users(id) ON DELETE RESTRICT;

ALTER TABLE ONLY control.operations
    ADD CONSTRAINT operations_target_user_id_fkey FOREIGN KEY (target_user_id) REFERENCES control.users(id) ON DELETE RESTRICT;

ALTER TABLE ONLY control.operations
    ADD CONSTRAINT operations_workshop_id_fkey FOREIGN KEY (workshop_id) REFERENCES control.workshops(id) ON DELETE RESTRICT;

ALTER TABLE ONLY control.outbox
    ADD CONSTRAINT outbox_invitation_id_fkey FOREIGN KEY (invitation_id) REFERENCES control.invitations(id) ON DELETE CASCADE;

ALTER TABLE ONLY control.outbox
    ADD CONSTRAINT outbox_workshop_id_fkey FOREIGN KEY (workshop_id) REFERENCES control.workshops(id) ON DELETE RESTRICT;

ALTER TABLE ONLY control.ownership_transfers
    ADD CONSTRAINT ownership_transfers_from_user_id_fkey FOREIGN KEY (from_user_id) REFERENCES control.users(id) ON DELETE RESTRICT;

ALTER TABLE ONLY control.ownership_transfers
    ADD CONSTRAINT ownership_transfers_to_user_id_fkey FOREIGN KEY (to_user_id) REFERENCES control.users(id) ON DELETE RESTRICT;

ALTER TABLE ONLY control.ownership_transfers
    ADD CONSTRAINT ownership_transfers_workshop_id_fkey FOREIGN KEY (workshop_id) REFERENCES control.workshops(id) ON DELETE CASCADE;

ALTER TABLE ONLY control.platform_role_assignments
    ADD CONSTRAINT platform_role_assignments_granted_by_fkey FOREIGN KEY (granted_by) REFERENCES control.users(id) ON DELETE RESTRICT;

ALTER TABLE ONLY control.platform_role_assignments
    ADD CONSTRAINT platform_role_assignments_revoked_by_fkey FOREIGN KEY (revoked_by) REFERENCES control.users(id) ON DELETE RESTRICT;

ALTER TABLE ONLY control.platform_role_assignments
    ADD CONSTRAINT platform_role_assignments_user_id_fkey FOREIGN KEY (user_id) REFERENCES control.users(id) ON DELETE RESTRICT;

ALTER TABLE ONLY control.privacy_incidents
    ADD CONSTRAINT privacy_incidents_created_by_fkey FOREIGN KEY (created_by) REFERENCES control.users(id) ON DELETE RESTRICT;

ALTER TABLE ONLY control.privacy_platform_state
    ADD CONSTRAINT privacy_platform_register_version_fk FOREIGN KEY (approved_processing_register_version) REFERENCES control.processing_register_versions(version) ON DELETE RESTRICT;

ALTER TABLE ONLY control.privacy_platform_state
    ADD CONSTRAINT privacy_platform_retention_version_fk FOREIGN KEY (approved_retention_policy_version) REFERENCES control.retention_policy_versions(version) ON DELETE RESTRICT;

ALTER TABLE ONLY control.processing_holds
    ADD CONSTRAINT processing_holds_data_subject_request_id_fkey FOREIGN KEY (data_subject_request_id) REFERENCES control.data_subject_requests(id) ON DELETE RESTRICT;

ALTER TABLE ONLY control.processing_holds
    ADD CONSTRAINT processing_holds_released_by_fkey FOREIGN KEY (released_by) REFERENCES control.users(id) ON DELETE RESTRICT;

ALTER TABLE ONLY control.processing_holds
    ADD CONSTRAINT processing_holds_subject_user_id_fkey FOREIGN KEY (subject_user_id) REFERENCES control.users(id) ON DELETE RESTRICT;

ALTER TABLE ONLY control.processing_holds
    ADD CONSTRAINT processing_holds_workshop_id_fkey FOREIGN KEY (workshop_id) REFERENCES control.workshops(id) ON DELETE RESTRICT;

ALTER TABLE ONLY control.processing_register_versions
    ADD CONSTRAINT processing_register_versions_approved_by_fkey FOREIGN KEY (approved_by) REFERENCES control.users(id) ON DELETE RESTRICT;

ALTER TABLE ONLY control.processor_approvals
    ADD CONSTRAINT processor_approvals_processing_register_version_fkey FOREIGN KEY (processing_register_version) REFERENCES control.processing_register_versions(version) ON DELETE RESTRICT;

ALTER TABLE ONLY control.release_fleet_runs
    ADD CONSTRAINT release_fleet_runs_canary_workshop_id_fkey FOREIGN KEY (canary_workshop_id) REFERENCES control.workshops(id) ON DELETE RESTRICT;

ALTER TABLE ONLY control.release_fleet_runs
    ADD CONSTRAINT release_fleet_runs_operation_id_fkey FOREIGN KEY (operation_id) REFERENCES control.operations(id) ON DELETE RESTRICT;

ALTER TABLE ONLY control.release_fleet_runs
    ADD CONSTRAINT release_fleet_runs_release_id_fkey FOREIGN KEY (release_id) REFERENCES control.application_releases(id) ON DELETE RESTRICT;

ALTER TABLE ONLY control.retention_policy_versions
    ADD CONSTRAINT retention_policy_versions_approved_by_fkey FOREIGN KEY (approved_by) REFERENCES control.users(id) ON DELETE RESTRICT;

ALTER TABLE ONLY control.retention_runs
    ADD CONSTRAINT retention_runs_operation_id_fkey FOREIGN KEY (operation_id) REFERENCES control.operations(id) ON DELETE RESTRICT;

ALTER TABLE ONLY control.retention_runs
    ADD CONSTRAINT retention_runs_policy_version_fkey FOREIGN KEY (policy_version) REFERENCES control.retention_policy_versions(version) ON DELETE RESTRICT;

ALTER TABLE ONLY control.runtime_release_slots
    ADD CONSTRAINT runtime_release_slots_release_id_fkey FOREIGN KEY (release_id) REFERENCES control.application_releases(id) ON DELETE RESTRICT;

ALTER TABLE ONLY control.service_instances
    ADD CONSTRAINT service_instances_workshop_id_fkey FOREIGN KEY (workshop_id) REFERENCES control.workshops(id) ON DELETE RESTRICT;

ALTER TABLE ONLY control.tenant_release_adoptions
    ADD CONSTRAINT tenant_release_adoptions_backup_recovery_id_fkey FOREIGN KEY (backup_recovery_id) REFERENCES control.workshop_recovery_points(id) ON DELETE RESTRICT;

ALTER TABLE ONLY control.tenant_release_adoptions
    ADD CONSTRAINT tenant_release_adoptions_database_id_fkey FOREIGN KEY (database_id) REFERENCES control.odoo_databases(id) ON DELETE RESTRICT;

ALTER TABLE ONLY control.tenant_release_adoptions
    ADD CONSTRAINT tenant_release_adoptions_operation_id_fkey FOREIGN KEY (operation_id) REFERENCES control.operations(id) ON DELETE RESTRICT;

ALTER TABLE ONLY control.tenant_release_adoptions
    ADD CONSTRAINT tenant_release_adoptions_registry_version_fk FOREIGN KEY (registry_version) REFERENCES control.capability_registry_versions(version) ON DELETE RESTRICT;

ALTER TABLE ONLY control.tenant_release_adoptions
    ADD CONSTRAINT tenant_release_adoptions_release_id_fkey FOREIGN KEY (release_id) REFERENCES control.application_releases(id) ON DELETE RESTRICT;

ALTER TABLE ONLY control.tenant_release_adoptions
    ADD CONSTRAINT tenant_release_adoptions_source_release_id_fkey FOREIGN KEY (source_release_id) REFERENCES control.application_releases(id) ON DELETE RESTRICT;

ALTER TABLE ONLY control.tenant_release_adoptions
    ADD CONSTRAINT tenant_release_adoptions_workshop_id_fkey FOREIGN KEY (workshop_id) REFERENCES control.workshops(id) ON DELETE RESTRICT;

ALTER TABLE ONLY control.usage_counters
    ADD CONSTRAINT usage_counters_workshop_id_fkey FOREIGN KEY (workshop_id) REFERENCES control.workshops(id) ON DELETE RESTRICT;

ALTER TABLE ONLY control.usage_reservations
    ADD CONSTRAINT usage_reservations_operation_id_fkey FOREIGN KEY (operation_id) REFERENCES control.operations(id) ON DELETE RESTRICT;

ALTER TABLE ONLY control.usage_reservations
    ADD CONSTRAINT usage_reservations_workshop_id_fkey FOREIGN KEY (workshop_id) REFERENCES control.workshops(id) ON DELETE RESTRICT;

ALTER TABLE ONLY control.webshop_domains
    ADD CONSTRAINT webshop_domains_created_by_fkey FOREIGN KEY (created_by) REFERENCES control.users(id) ON DELETE RESTRICT;

ALTER TABLE ONLY control.webshop_domains
    ADD CONSTRAINT webshop_domains_operation_id_fkey FOREIGN KEY (operation_id) REFERENCES control.operations(id) ON DELETE RESTRICT;

ALTER TABLE ONLY control.webshop_domains
    ADD CONSTRAINT webshop_domains_workshop_id_fkey FOREIGN KEY (workshop_id) REFERENCES control.workshops(id) ON DELETE RESTRICT;

ALTER TABLE ONLY control.webshop_email_domains
    ADD CONSTRAINT webshop_email_domains_created_by_fkey FOREIGN KEY (created_by) REFERENCES control.users(id);

ALTER TABLE ONLY control.webshop_email_domains
    ADD CONSTRAINT webshop_email_domains_operation_id_fkey FOREIGN KEY (operation_id) REFERENCES control.operations(id);

ALTER TABLE ONLY control.webshop_email_domains
    ADD CONSTRAINT webshop_email_domains_test_outbox_id_fkey FOREIGN KEY (test_outbox_id) REFERENCES control.outbox(id);

ALTER TABLE ONLY control.webshop_email_domains
    ADD CONSTRAINT webshop_email_domains_workshop_id_fkey FOREIGN KEY (workshop_id) REFERENCES control.workshops(id) ON DELETE CASCADE;

ALTER TABLE ONLY control.webshop_onboarding
    ADD CONSTRAINT webshop_onboarding_operation_id_fkey FOREIGN KEY (operation_id) REFERENCES control.operations(id) ON DELETE RESTRICT;

ALTER TABLE ONLY control.webshop_onboarding
    ADD CONSTRAINT webshop_onboarding_workshop_id_fkey FOREIGN KEY (workshop_id) REFERENCES control.workshops(id) ON DELETE CASCADE;

ALTER TABLE ONLY control.worker_heartbeats
    ADD CONSTRAINT worker_heartbeats_active_operation_id_fkey FOREIGN KEY (active_operation_id) REFERENCES control.operations(id) ON DELETE SET NULL;

ALTER TABLE ONLY control.workshop_deletions
    ADD CONSTRAINT workshop_deletions_final_recovery_point_id_fkey FOREIGN KEY (final_recovery_point_id) REFERENCES control.workshop_recovery_points(id) ON DELETE RESTRICT;

ALTER TABLE ONLY control.workshop_deletions
    ADD CONSTRAINT workshop_deletions_operation_id_fkey FOREIGN KEY (operation_id) REFERENCES control.operations(id) ON DELETE RESTRICT;

ALTER TABLE ONLY control.workshop_deletions
    ADD CONSTRAINT workshop_deletions_requested_by_fkey FOREIGN KEY (requested_by) REFERENCES control.users(id) ON DELETE RESTRICT;

ALTER TABLE ONLY control.workshop_deletions
    ADD CONSTRAINT workshop_deletions_workshop_id_fkey FOREIGN KEY (workshop_id) REFERENCES control.workshops(id) ON DELETE RESTRICT;

ALTER TABLE ONLY control.workshop_modules
    ADD CONSTRAINT workshop_modules_application_release_id_fkey FOREIGN KEY (application_release_id) REFERENCES control.application_releases(id) ON DELETE RESTRICT;

ALTER TABLE ONLY control.workshop_modules
    ADD CONSTRAINT workshop_modules_operation_id_fkey FOREIGN KEY (operation_id) REFERENCES control.operations(id) ON DELETE RESTRICT;

ALTER TABLE ONLY control.workshop_modules
    ADD CONSTRAINT workshop_modules_registry_entry_fk FOREIGN KEY (registry_version, module_key) REFERENCES control.capability_registry_entries(registry_version, capability_key) ON DELETE RESTRICT;

ALTER TABLE ONLY control.workshop_modules
    ADD CONSTRAINT workshop_modules_requested_by_fkey FOREIGN KEY (requested_by) REFERENCES control.users(id) ON DELETE RESTRICT;

ALTER TABLE ONLY control.workshop_modules
    ADD CONSTRAINT workshop_modules_workshop_id_fkey FOREIGN KEY (workshop_id) REFERENCES control.workshops(id) ON DELETE RESTRICT;

ALTER TABLE ONLY control.workshop_recovery_components
    ADD CONSTRAINT workshop_recovery_components_recovery_point_id_fkey FOREIGN KEY (recovery_point_id) REFERENCES control.workshop_recovery_points(id) ON DELETE CASCADE;

ALTER TABLE ONLY control.workshop_recovery_rehearsals
    ADD CONSTRAINT workshop_recovery_rehearsals_recovery_point_id_fkey FOREIGN KEY (recovery_point_id) REFERENCES control.workshop_recovery_points(id) ON DELETE CASCADE;

ALTER TABLE ONLY control.workshop_recovery_rehearsals
    ADD CONSTRAINT workshop_recovery_rehearsals_workshop_id_fkey FOREIGN KEY (workshop_id) REFERENCES control.workshops(id) ON DELETE CASCADE;

insert into control.platform_authority_state(singleton) values(true);
insert into control.privacy_platform_state(singleton) values(true);
comment on schema control is
'Authoritative control-plane state; runtime roles receive only explicitly granted access.';
comment on table control.audit_events is
'Append-only security and business audit ledger; mutation is rejected by trigger.';
comment on table control.commands is
'Idempotent command admission ledger binding a request digest to one durable result.';
comment on table control.capability_registry_versions is
'Immutable capability registry identities; exactly one version is active after registry synchronization.';
comment on table control.capability_registry_entries is
'Release-pinned capability implementations. Entries are populated from the embedded registry after migration.';
comment on table control.application_releases is
'Published, integrity-verified application releases governed by the release transition trigger.';
comment on table control.tenant_release_adoptions is
'Per-database immutable release adoption history; at most one adoption is active per tenant database.';
comment on table control.runtime_release_slots is
'Verified shared runtime slots; activation remains bound to the declared release image digest.';
comment on table control.fleet_activation_intents is
'Immutable intent and observed digest evidence for an atomic fleet runtime switch.';
comment on table control.platform_authority_state is
'Singleton authority epoch used to invalidate stale platform-role authorization.';
comment on table control.privacy_platform_state is
'Singleton privacy gate; production personal data requires approved policy and processor evidence.';
comment on function control.consume_data_subject_export(uuid,uuid) is
'Security-definer single-use export retrieval scoped to the requesting data subject.';
comment on function control.enforce_subject_processing_hold() is
'Security-definer fail-closed processing restriction enforced at operation admission.';
comment on function control.erasure_lookup_available(uuid) is
'Security-definer existence check that does not disclose encrypted erasure lookup material.';
comment on function control.purge_expired_data_subject_exports() is
'Security-definer purge of expired export ciphertext and nonces.';
create function control.initial_release_preparable(p_release_id text,p_registry_version integer)
returns boolean language sql stable security definer
set search_path=pg_catalog,control as $$
    select exists(
        select 1 from control.application_releases release
        where release.id=p_release_id
          and (release.manifest->>'capability_registry_version')::integer=p_registry_version
    )
      and exists(
        select 1 from control.capability_registry_versions registry
        where registry.version=p_registry_version and registry.active
    )
      and not exists(select 1 from control.workshops)
      and not exists(select 1 from control.odoo_databases)
      and not exists(select 1 from control.tenant_release_adoptions)
      and not exists(select 1 from control.application_releases where status='active')
$$;
comment on function control.initial_release_preparable(text,integer) is
'Security-definer least-privilege gate proving that initial activation is still limited to an empty fleet and active registry.';
REVOKE ALL ON FUNCTION control.assert_last_owner() FROM PUBLIC;

REVOKE ALL ON FUNCTION control.consume_data_subject_export(p_export_id uuid, p_subject_user_id uuid) FROM PUBLIC;

REVOKE ALL ON FUNCTION control.enforce_subject_processing_hold() FROM PUBLIC;

REVOKE ALL ON FUNCTION control.erasure_lookup_available(target uuid) FROM PUBLIC;

REVOKE ALL ON FUNCTION control.legal_hold_applies(p_dataset_key text, p_workshop_id uuid, p_subject_ids uuid[]) FROM PUBLIC;

REVOKE ALL ON FUNCTION control.purge_expired_data_subject_exports() FROM PUBLIC;

REVOKE ALL ON FUNCTION control.initial_release_preparable(text,integer) FROM PUBLIC;

REVOKE ALL ON FUNCTION control.reject_audit_mutation() FROM PUBLIC;

REVOKE ALL ON FUNCTION control.require_technical_admin() FROM PUBLIC;

REVOKE ALL ON FUNCTION control.set_privacy_incident_deadline() FROM PUBLIC;

REVOKE ALL ON FUNCTION control.validate_application_release_transition() FROM PUBLIC;

REVOKE ALL ON FUNCTION control.validate_data_subject_request_transition() FROM PUBLIC;

REVOKE ALL ON FUNCTION control.validate_fleet_activation_intent_update() FROM PUBLIC;

REVOKE ALL ON FUNCTION control.validate_legal_hold_update() FROM PUBLIC;

REVOKE ALL ON FUNCTION control.validate_platform_role_update() FROM PUBLIC;

REVOKE ALL ON FUNCTION control.validate_privacy_incident_update() FROM PUBLIC;

REVOKE ALL ON FUNCTION control.validate_privacy_platform_state() FROM PUBLIC;

REVOKE ALL ON FUNCTION control.validate_processor_task_update() FROM PUBLIC;

REVOKE ALL ON FUNCTION control.validate_tenant_release_transition() FROM PUBLIC;

REVOKE ALL ON FUNCTION control.validate_workshop_module_update() FROM PUBLIC;

ALTER DEFAULT PRIVILEGES REVOKE ALL ON FUNCTIONS FROM PUBLIC;

do $$ begin if exists(select 1 from pg_roles where rolname='control_api') then execute 'GRANT USAGE ON SCHEMA control TO control_api;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_membership_worker') then execute 'GRANT USAGE ON SCHEMA control TO control_membership_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_provisioning_worker') then execute 'GRANT USAGE ON SCHEMA control TO control_provisioning_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_invoice_worker') then execute 'GRANT USAGE ON SCHEMA control TO control_invoice_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_inventory_worker') then execute 'GRANT USAGE ON SCHEMA control TO control_inventory_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_email_worker') then execute 'GRANT USAGE ON SCHEMA control TO control_email_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_reconciliation_worker') then execute 'GRANT USAGE ON SCHEMA control TO control_reconciliation_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_lifecycle_worker') then execute 'GRANT USAGE ON SCHEMA control TO control_lifecycle_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_backup_scheduler') then execute 'GRANT USAGE ON SCHEMA control TO control_backup_scheduler;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_driver_ledger') then execute 'GRANT USAGE ON SCHEMA control TO control_driver_ledger;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_release_worker') then execute 'GRANT USAGE ON SCHEMA control TO control_release_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_privacy_worker') then execute 'GRANT USAGE ON SCHEMA control TO control_privacy_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_api') then execute 'GRANT ALL ON FUNCTION control.consume_data_subject_export(p_export_id uuid, p_subject_user_id uuid) TO control_api;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_api') then execute 'GRANT ALL ON FUNCTION control.erasure_lookup_available(target uuid) TO control_api;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_privacy_worker') then execute 'GRANT ALL ON FUNCTION control.legal_hold_applies(p_dataset_key text, p_workshop_id uuid, p_subject_ids uuid[]) TO control_privacy_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_api') then execute 'GRANT ALL ON FUNCTION control.purge_expired_data_subject_exports() TO control_api;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_privacy_worker') then execute 'GRANT ALL ON FUNCTION control.purge_expired_data_subject_exports() TO control_privacy_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_driver_ledger') then execute 'GRANT EXECUTE ON FUNCTION control.initial_release_preparable(text,integer) TO control_driver_ledger;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_api') then execute 'GRANT SELECT,INSERT,UPDATE ON TABLE control.application_releases TO control_api;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_release_worker') then execute 'GRANT SELECT,UPDATE ON TABLE control.application_releases TO control_release_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_driver_ledger') then execute 'GRANT SELECT,INSERT,UPDATE ON TABLE control.application_releases TO control_driver_ledger;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_api') then execute 'GRANT SELECT,INSERT ON TABLE control.audit_events TO control_api;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_privacy_worker') then execute 'GRANT SELECT ON TABLE control.audit_events TO control_privacy_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_api') then execute 'GRANT SELECT ON TABLE control.capability_registry_entries TO control_api;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_provisioning_worker') then execute 'GRANT SELECT ON TABLE control.capability_registry_entries TO control_provisioning_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_reconciliation_worker') then execute 'GRANT SELECT ON TABLE control.capability_registry_entries TO control_reconciliation_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_api') then execute 'GRANT SELECT ON TABLE control.capability_registry_versions TO control_api;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_release_worker') then execute 'GRANT SELECT,UPDATE ON TABLE control.capability_registry_versions TO control_release_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_api') then execute 'GRANT SELECT,INSERT,UPDATE ON TABLE control.carrier_secrets TO control_api;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_reconciliation_worker') then execute 'GRANT SELECT,UPDATE ON TABLE control.carrier_secrets TO control_reconciliation_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_provisioning_worker') then execute 'GRANT SELECT,UPDATE ON TABLE control.carrier_secrets TO control_provisioning_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_lifecycle_worker') then execute 'GRANT SELECT,UPDATE ON TABLE control.carrier_secrets TO control_lifecycle_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_api') then execute 'GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE control.commands TO control_api;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_privacy_worker') then execute 'GRANT SELECT,INSERT,UPDATE ON TABLE control.data_subject_exports TO control_privacy_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_api') then execute 'GRANT SELECT ON TABLE control.data_subject_export_status TO control_api;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_api') then execute 'GRANT SELECT,INSERT,UPDATE ON TABLE control.data_subject_processor_tasks TO control_api;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_privacy_worker') then execute 'GRANT SELECT,INSERT,UPDATE ON TABLE control.data_subject_processor_tasks TO control_privacy_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_api') then execute 'GRANT SELECT,INSERT,UPDATE ON TABLE control.data_subject_requests TO control_api;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_privacy_worker') then execute 'GRANT SELECT,INSERT,UPDATE ON TABLE control.data_subject_requests TO control_privacy_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_driver_ledger') then execute 'GRANT SELECT ON TABLE control.data_subject_requests TO control_driver_ledger;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_driver_ledger') then execute 'GRANT SELECT,INSERT,UPDATE ON TABLE control.deployment_driver_operations TO control_driver_ledger;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_api') then execute 'GRANT SELECT,INSERT ON TABLE control.email_delivery_events TO control_api;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_api') then execute 'GRANT SELECT,INSERT,UPDATE ON TABLE control.email_suppressions TO control_api;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_reconciliation_worker') then execute 'GRANT SELECT ON TABLE control.email_suppressions TO control_reconciliation_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_api') then execute 'GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE control.entitlements TO control_api;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_invoice_worker') then execute 'GRANT SELECT ON TABLE control.entitlements TO control_invoice_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_inventory_worker') then execute 'GRANT SELECT ON TABLE control.entitlements TO control_inventory_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_reconciliation_worker') then execute 'GRANT SELECT ON TABLE control.entitlements TO control_reconciliation_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_lifecycle_worker') then execute 'GRANT SELECT,INSERT,UPDATE ON TABLE control.erasure_restore_replays TO control_lifecycle_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_api') then execute 'GRANT SELECT,INSERT ON TABLE control.erasure_restore_replays TO control_api;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_driver_ledger') then execute 'GRANT SELECT ON TABLE control.erasure_restore_replays TO control_driver_ledger;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_privacy_worker') then execute 'GRANT SELECT,INSERT ON TABLE control.erasure_subject_lookups TO control_privacy_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_lifecycle_worker') then execute 'GRANT SELECT ON TABLE control.erasure_subject_lookups TO control_lifecycle_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_api') then execute 'GRANT SELECT,INSERT,UPDATE ON TABLE control.erasure_tombstones TO control_api;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_privacy_worker') then execute 'GRANT SELECT,INSERT,UPDATE ON TABLE control.erasure_tombstones TO control_privacy_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_lifecycle_worker') then execute 'GRANT SELECT ON TABLE control.erasure_tombstones TO control_lifecycle_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_driver_ledger') then execute 'GRANT SELECT ON TABLE control.erasure_tombstones TO control_driver_ledger;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_api') then execute 'GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE control.external_identities TO control_api;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_membership_worker') then execute 'GRANT SELECT ON TABLE control.external_identities TO control_membership_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_reconciliation_worker') then execute 'GRANT SELECT ON TABLE control.external_identities TO control_reconciliation_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_privacy_worker') then execute 'GRANT SELECT,UPDATE ON TABLE control.external_identities TO control_privacy_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_driver_ledger') then execute 'GRANT SELECT ON TABLE control.external_identities TO control_driver_ledger;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_api') then execute 'GRANT SELECT,INSERT,UPDATE ON TABLE control.fleet_activation_intents TO control_api;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_release_worker') then execute 'GRANT SELECT,INSERT,UPDATE ON TABLE control.fleet_activation_intents TO control_release_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_driver_ledger') then execute 'GRANT SELECT,INSERT,UPDATE ON TABLE control.fleet_activation_intents TO control_driver_ledger;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_api') then execute 'GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE control.invitations TO control_api;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_email_worker') then execute 'GRANT SELECT ON TABLE control.invitations TO control_email_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_privacy_worker') then execute 'GRANT SELECT,DELETE,UPDATE ON TABLE control.invitations TO control_privacy_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_api') then execute 'GRANT SELECT,INSERT,UPDATE ON TABLE control.legal_holds TO control_api;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_privacy_worker') then execute 'GRANT SELECT ON TABLE control.legal_holds TO control_privacy_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_api') then execute 'GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE control.membership_targets TO control_api;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_membership_worker') then execute 'GRANT SELECT,INSERT,UPDATE ON TABLE control.membership_targets TO control_membership_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_provisioning_worker') then execute 'GRANT SELECT,INSERT,UPDATE ON TABLE control.membership_targets TO control_provisioning_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_invoice_worker') then execute 'GRANT SELECT ON TABLE control.membership_targets TO control_invoice_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_inventory_worker') then execute 'GRANT SELECT ON TABLE control.membership_targets TO control_inventory_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_reconciliation_worker') then execute 'GRANT SELECT,INSERT,UPDATE ON TABLE control.membership_targets TO control_reconciliation_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_api') then execute 'GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE control.memberships TO control_api;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_membership_worker') then execute 'GRANT SELECT ON TABLE control.memberships TO control_membership_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_provisioning_worker') then execute 'GRANT SELECT ON TABLE control.memberships TO control_provisioning_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_invoice_worker') then execute 'GRANT SELECT ON TABLE control.memberships TO control_invoice_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_inventory_worker') then execute 'GRANT SELECT ON TABLE control.memberships TO control_inventory_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_reconciliation_worker') then execute 'GRANT SELECT ON TABLE control.memberships TO control_reconciliation_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_privacy_worker') then execute 'GRANT SELECT ON TABLE control.memberships TO control_privacy_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_driver_ledger') then execute 'GRANT SELECT ON TABLE control.memberships TO control_driver_ledger;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_api') then execute 'GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE control.odoo_databases TO control_api;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_provisioning_worker') then execute 'GRANT SELECT ON TABLE control.odoo_databases TO control_provisioning_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_reconciliation_worker') then execute 'GRANT SELECT ON TABLE control.odoo_databases TO control_reconciliation_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_lifecycle_worker') then execute 'GRANT SELECT,UPDATE ON TABLE control.odoo_databases TO control_lifecycle_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_backup_scheduler') then execute 'GRANT SELECT ON TABLE control.odoo_databases TO control_backup_scheduler;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_driver_ledger') then execute 'GRANT SELECT,UPDATE ON TABLE control.odoo_databases TO control_driver_ledger;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_release_worker') then execute 'GRANT SELECT,UPDATE ON TABLE control.odoo_databases TO control_release_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_api') then execute 'GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE control.operations TO control_api;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_membership_worker') then execute 'GRANT SELECT,INSERT,UPDATE ON TABLE control.operations TO control_membership_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_provisioning_worker') then execute 'GRANT SELECT,INSERT,UPDATE ON TABLE control.operations TO control_provisioning_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_invoice_worker') then execute 'GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE control.operations TO control_invoice_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_inventory_worker') then execute 'GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE control.operations TO control_inventory_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_email_worker') then execute 'GRANT SELECT,UPDATE ON TABLE control.operations TO control_email_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_reconciliation_worker') then execute 'GRANT SELECT,INSERT,UPDATE ON TABLE control.operations TO control_reconciliation_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_lifecycle_worker') then execute 'GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE control.operations TO control_lifecycle_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_backup_scheduler') then execute 'GRANT SELECT,INSERT ON TABLE control.operations TO control_backup_scheduler;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_driver_ledger') then execute 'GRANT SELECT,UPDATE ON TABLE control.operations TO control_driver_ledger;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_release_worker') then execute 'GRANT SELECT,INSERT,UPDATE ON TABLE control.operations TO control_release_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_privacy_worker') then execute 'GRANT SELECT,INSERT,UPDATE ON TABLE control.operations TO control_privacy_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_api') then execute 'GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE control.outbox TO control_api;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_email_worker') then execute 'GRANT SELECT,UPDATE ON TABLE control.outbox TO control_email_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_privacy_worker') then execute 'GRANT SELECT,DELETE,UPDATE ON TABLE control.outbox TO control_privacy_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_reconciliation_worker') then execute 'GRANT SELECT,INSERT ON TABLE control.outbox TO control_reconciliation_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_api') then execute 'GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE control.ownership_transfers TO control_api;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_api') then execute 'GRANT SELECT,UPDATE ON TABLE control.platform_authority_state TO control_api;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_api') then execute 'GRANT SELECT,INSERT,UPDATE ON TABLE control.platform_role_assignments TO control_api;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_api') then execute 'GRANT SELECT,INSERT,UPDATE ON TABLE control.privacy_incidents TO control_api;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_api') then execute 'GRANT SELECT ON TABLE control.privacy_platform_state TO control_api;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_privacy_worker') then execute 'GRANT SELECT ON TABLE control.privacy_platform_state TO control_privacy_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_api') then execute 'GRANT SELECT,INSERT,UPDATE ON TABLE control.processing_holds TO control_api;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_privacy_worker') then execute 'GRANT SELECT,INSERT,UPDATE ON TABLE control.processing_holds TO control_privacy_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_api') then execute 'GRANT SELECT ON TABLE control.processing_register_versions TO control_api;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_privacy_worker') then execute 'GRANT SELECT ON TABLE control.processing_register_versions TO control_privacy_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_api') then execute 'GRANT SELECT ON TABLE control.processor_approvals TO control_api;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_privacy_worker') then execute 'GRANT SELECT ON TABLE control.processor_approvals TO control_privacy_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_api') then execute 'GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE control.product_lookup_cache TO control_api;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_inventory_worker') then execute 'GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE control.product_lookup_cache TO control_inventory_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_api') then execute 'GRANT SELECT,INSERT,UPDATE ON TABLE control.product_lookup_fills TO control_api;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_api') then execute 'GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE control.provider_rate_limits TO control_api;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_invoice_worker') then execute 'GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE control.provider_rate_limits TO control_invoice_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_inventory_worker') then execute 'GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE control.provider_rate_limits TO control_inventory_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_api') then execute 'GRANT SELECT,INSERT,UPDATE ON TABLE control.release_fleet_runs TO control_api;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_release_worker') then execute 'GRANT SELECT,UPDATE ON TABLE control.release_fleet_runs TO control_release_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_driver_ledger') then execute 'GRANT SELECT,INSERT,UPDATE ON TABLE control.release_fleet_runs TO control_driver_ledger;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_reconciliation_worker') then execute 'GRANT SELECT ON TABLE control.release_fleet_runs TO control_reconciliation_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_api') then execute 'GRANT SELECT ON TABLE control.retention_policy_versions TO control_api;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_privacy_worker') then execute 'GRANT SELECT ON TABLE control.retention_policy_versions TO control_privacy_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_api') then execute 'GRANT SELECT ON TABLE control.retention_runs TO control_api;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_privacy_worker') then execute 'GRANT SELECT,INSERT,UPDATE ON TABLE control.retention_runs TO control_privacy_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_api') then execute 'GRANT SELECT ON TABLE control.runtime_release_slots TO control_api;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_release_worker') then execute 'GRANT SELECT,INSERT,UPDATE ON TABLE control.runtime_release_slots TO control_release_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_driver_ledger') then execute 'GRANT SELECT,INSERT,UPDATE ON TABLE control.runtime_release_slots TO control_driver_ledger;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_api') then execute 'GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE control.service_instances TO control_api;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_membership_worker') then execute 'GRANT SELECT ON TABLE control.service_instances TO control_membership_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_provisioning_worker') then execute 'GRANT SELECT,INSERT,UPDATE ON TABLE control.service_instances TO control_provisioning_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_invoice_worker') then execute 'GRANT SELECT ON TABLE control.service_instances TO control_invoice_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_inventory_worker') then execute 'GRANT SELECT ON TABLE control.service_instances TO control_inventory_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_reconciliation_worker') then execute 'GRANT SELECT,INSERT,UPDATE ON TABLE control.service_instances TO control_reconciliation_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_release_worker') then execute 'GRANT SELECT,UPDATE ON TABLE control.service_instances TO control_release_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_driver_ledger') then execute 'GRANT SELECT ON TABLE control.service_instances TO control_driver_ledger;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_api') then execute 'GRANT SELECT,INSERT,UPDATE ON TABLE control.tenant_release_adoptions TO control_api;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_release_worker') then execute 'GRANT SELECT,INSERT,UPDATE ON TABLE control.tenant_release_adoptions TO control_release_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_driver_ledger') then execute 'GRANT SELECT,INSERT,UPDATE ON TABLE control.tenant_release_adoptions TO control_driver_ledger;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_reconciliation_worker') then execute 'GRANT SELECT ON TABLE control.tenant_release_adoptions TO control_reconciliation_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_api') then execute 'GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE control.usage_counters TO control_api;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_invoice_worker') then execute 'GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE control.usage_counters TO control_invoice_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_inventory_worker') then execute 'GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE control.usage_counters TO control_inventory_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_api') then execute 'GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE control.usage_reservations TO control_api;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_invoice_worker') then execute 'GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE control.usage_reservations TO control_invoice_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_inventory_worker') then execute 'GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE control.usage_reservations TO control_inventory_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_api') then execute 'GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE control.users TO control_api;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_membership_worker') then execute 'GRANT SELECT ON TABLE control.users TO control_membership_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_reconciliation_worker') then execute 'GRANT SELECT ON TABLE control.users TO control_reconciliation_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_privacy_worker') then execute 'GRANT SELECT,UPDATE ON TABLE control.users TO control_privacy_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_api') then execute 'GRANT SELECT,INSERT,UPDATE ON TABLE control.webshop_domains TO control_api;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_reconciliation_worker') then execute 'GRANT SELECT,UPDATE ON TABLE control.webshop_domains TO control_reconciliation_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_lifecycle_worker') then execute 'GRANT SELECT,UPDATE ON TABLE control.webshop_domains TO control_lifecycle_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_api') then execute 'GRANT SELECT,INSERT,UPDATE ON TABLE control.webshop_email_domains TO control_api;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_reconciliation_worker') then execute 'GRANT SELECT,UPDATE ON TABLE control.webshop_email_domains TO control_reconciliation_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_email_worker') then execute 'GRANT SELECT ON TABLE control.webshop_email_domains TO control_email_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_api') then execute 'GRANT SELECT,INSERT,UPDATE ON TABLE control.webshop_onboarding TO control_api;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_reconciliation_worker') then execute 'GRANT SELECT,INSERT,UPDATE ON TABLE control.webshop_onboarding TO control_reconciliation_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_membership_worker') then execute 'GRANT SELECT,INSERT,UPDATE ON TABLE control.worker_heartbeats TO control_membership_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_invoice_worker') then execute 'GRANT SELECT,INSERT,UPDATE ON TABLE control.worker_heartbeats TO control_invoice_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_inventory_worker') then execute 'GRANT SELECT,INSERT,UPDATE ON TABLE control.worker_heartbeats TO control_inventory_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_email_worker') then execute 'GRANT SELECT,INSERT,UPDATE ON TABLE control.worker_heartbeats TO control_email_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_reconciliation_worker') then execute 'GRANT SELECT,INSERT,UPDATE ON TABLE control.worker_heartbeats TO control_reconciliation_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_lifecycle_worker') then execute 'GRANT SELECT,INSERT,UPDATE ON TABLE control.worker_heartbeats TO control_lifecycle_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_release_worker') then execute 'GRANT SELECT,INSERT,UPDATE ON TABLE control.worker_heartbeats TO control_release_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_privacy_worker') then execute 'GRANT SELECT,INSERT,UPDATE ON TABLE control.worker_heartbeats TO control_privacy_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_api') then execute 'GRANT SELECT ON TABLE control.worker_heartbeats TO control_api;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_provisioning_worker') then execute 'GRANT SELECT,INSERT,UPDATE ON TABLE control.worker_heartbeats TO control_provisioning_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_api') then execute 'GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE control.workshop_deletions TO control_api;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_lifecycle_worker') then execute 'GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE control.workshop_deletions TO control_lifecycle_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_api') then execute 'GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE control.workshop_modules TO control_api;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_membership_worker') then execute 'GRANT SELECT ON TABLE control.workshop_modules TO control_membership_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_invoice_worker') then execute 'GRANT SELECT ON TABLE control.workshop_modules TO control_invoice_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_inventory_worker') then execute 'GRANT SELECT ON TABLE control.workshop_modules TO control_inventory_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_reconciliation_worker') then execute 'GRANT SELECT,UPDATE ON TABLE control.workshop_modules TO control_reconciliation_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_release_worker') then execute 'GRANT SELECT,UPDATE ON TABLE control.workshop_modules TO control_release_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_api') then execute 'GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE control.workshop_recovery_components TO control_api;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_lifecycle_worker') then execute 'GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE control.workshop_recovery_components TO control_lifecycle_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_driver_ledger') then execute 'GRANT SELECT,INSERT,DELETE ON TABLE control.workshop_recovery_components TO control_driver_ledger;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_api') then execute 'GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE control.workshop_recovery_points TO control_api;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_lifecycle_worker') then execute 'GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE control.workshop_recovery_points TO control_lifecycle_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_backup_scheduler') then execute 'GRANT SELECT,INSERT ON TABLE control.workshop_recovery_points TO control_backup_scheduler;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_driver_ledger') then execute 'GRANT SELECT,UPDATE ON TABLE control.workshop_recovery_points TO control_driver_ledger;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_release_worker') then execute 'GRANT SELECT,INSERT,UPDATE ON TABLE control.workshop_recovery_points TO control_release_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_privacy_worker') then execute 'GRANT SELECT ON TABLE control.workshop_recovery_points TO control_privacy_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_api') then execute 'GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE control.workshop_recovery_rehearsals TO control_api;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_lifecycle_worker') then execute 'GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE control.workshop_recovery_rehearsals TO control_lifecycle_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_backup_scheduler') then execute 'GRANT SELECT,INSERT ON TABLE control.workshop_recovery_rehearsals TO control_backup_scheduler;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_api') then execute 'GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE control.workshops TO control_api;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_membership_worker') then execute 'GRANT SELECT ON TABLE control.workshops TO control_membership_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_provisioning_worker') then execute 'GRANT SELECT ON TABLE control.workshops TO control_provisioning_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_invoice_worker') then execute 'GRANT SELECT ON TABLE control.workshops TO control_invoice_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_inventory_worker') then execute 'GRANT SELECT ON TABLE control.workshops TO control_inventory_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_reconciliation_worker') then execute 'GRANT SELECT ON TABLE control.workshops TO control_reconciliation_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_lifecycle_worker') then execute 'GRANT SELECT,UPDATE ON TABLE control.workshops TO control_lifecycle_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_backup_scheduler') then execute 'GRANT SELECT ON TABLE control.workshops TO control_backup_scheduler;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_release_worker') then execute 'GRANT SELECT,UPDATE ON TABLE control.workshops TO control_release_worker;'; end if; end $$;
do $$ begin if exists(select 1 from pg_roles where rolname='control_privacy_worker') then execute 'GRANT SELECT ON TABLE control.workshops TO control_privacy_worker;'; end if; end $$;
