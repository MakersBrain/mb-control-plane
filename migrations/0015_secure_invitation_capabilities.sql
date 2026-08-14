alter table control.invitations
    add column token_generation integer not null default 1 check (token_generation > 0),
    alter column token_hash drop not null;

-- Every capability created by the previous implementation appeared in an
-- outbox URL. Invalidate it and redact historical rows during adoption rather
-- than carrying an unknown plaintext capability into the new trust model.
update control.invitations
set revoked_at = coalesce(revoked_at, now()), token_hash = null
where accepted_at is null;

update control.invitations set token_hash = null where token_hash is not null;

update control.outbox
set kind = 'invitation-legacy-redacted',
    payload = payload - 'accept_url',
    state = case when state in ('queued', 'sending', 'deferred') then 'dead_letter' else state end
where kind = 'invitation';

alter table control.outbox
    add column invitation_id uuid references control.invitations(id) on delete cascade,
    add column token_generation integer,
    add column capability_issued_at timestamptz,
    add column capability_expires_at timestamptz,
    add column signing_key_id text,
    add constraint outbox_invitation_capability_metadata check (
        kind <> 'invitation' or (
            invitation_id is not null
            and token_generation is not null and token_generation > 0
            and capability_issued_at is not null
            and capability_expires_at > capability_issued_at
            and signing_key_id is not null and btrim(signing_key_id) <> ''
            and not (payload ? 'accept_url')
            and not (payload ? 'token')
        )
    ),
    add constraint outbox_invitation_generation_unique unique (invitation_id, token_generation);
