-- Bind every durable mail record to one workshop before the email worker can
-- claim it. Invitation ownership and recipient identity are derived from the
-- authoritative invitation row, not duplicated JSON payload fields.
update control.outbox o
   set workshop_id=i.workshop_id,
       recipient=i.email
  from control.invitations i
 where o.kind='invitation' and o.invitation_id=i.id;

alter table control.outbox
  alter column workshop_id set not null;

alter table control.invitations
  add constraint invitations_id_workshop_email_key
  unique(id,workshop_id,email);

alter table control.outbox
  add constraint outbox_id_workshop_key unique(id,workshop_id),
  add constraint outbox_invitation_tenant_recipient_fkey
    foreign key(invitation_id,workshop_id,recipient)
    references control.invitations(id,workshop_id,email)
    on delete cascade,
  add constraint outbox_kind_shape_check check (
    (
      kind='invitation'
      and template='workshop-invitation'
      and invitation_id is not null
      and token_generation is not null
      and capability_issued_at is not null
      and capability_expires_at is not null
      and signing_key_id is not null
      and source_key is null
    ) or (
      kind='odoo_transactional'
      and template='odoo-rendered-v1'
      and invitation_id is null
      and token_generation is null
      and capability_issued_at is null
      and capability_expires_at is null
      and signing_key_id is null
      and source_key is not null
    )
  );

alter table control.webshop_email_domains
  add constraint webshop_email_domains_test_outbox_tenant_fkey
  foreign key(test_outbox_id,workshop_id)
  references control.outbox(id,workshop_id);
