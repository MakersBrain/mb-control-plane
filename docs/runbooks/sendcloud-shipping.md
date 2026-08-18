# Sendcloud shipping operations

## Scope and ownership

Each workshop owns its Sendcloud account, credentials, contracts, carrier
charges, and provider support relationship. MakersBrain stores the public and
private API keys in the tenant-scoped external secret store; Odoo receives only
an opaque reference. Never paste keys into Odoo fields, tickets, logs, fixtures,
or source control.

The implementation is original LGPL-3 MakersBrain code. No Odoo Enterprise,
Onestein, or OCA connector source was copied. The official Odoo connector and
the LGPL OCA 18.0 connector were used only as workflow and architecture prior
art; the deployed addon uses Sendcloud API v3 and does not depend on parcel
creation v2.

## Connect a workshop

1. Enable `Sendcloud shipping` for the workshop and create a Sendcloud delivery
   method in Odoo.
2. Open the control-plane **Shipping credentials** page, select that exact Odoo
   carrier and environment, and enter the workshop's public/private API keys.
   Enter a separate Webhook Signature Key only when Sendcloud supplied one.
3. Run the read-only qualification command below. Copy a returned sender ID into
   the carrier's **Sendcloud sender address ID** field. Configure an exact v3
   outbound option code and, before returns are enabled, a distinct return
   option code.
4. Complete parcel dimensions, structured partner addresses, label format,
   carrier/contract filters, and service-point behavior in Odoo. Test carriers
   accept only the `sendcloud:letter` option; test mode does not make other
   labels charge-free.
5. Use **Show webhook URL** in Odoo and configure that HTTPS URL in Sendcloud.
   Send a signed Test API Webhook. Readiness becomes healthy only after the
   signature is verified.
6. Use **Test connection**. A successful result means authentication, the
   selected sender and the configured option are usable; it does not attest
   billing acceptance or a paid carrier journey.

## Safe read-only qualification

`sendcloud.env` is ignored by Git. It must contain only:

```text
SENDCLOUD_PUBLIC_KEY=...
SENDCLOUD_PRIVATE_KEY=...
```

Optional service-point qualification accepts
`SENDCLOUD_QUALIFICATION_COUNTRY`, `SENDCLOUD_QUALIFICATION_POSTAL_CODE`, and
`SENDCLOUD_QUALIFICATION_CITY`. Run:

```bash
python3 tools/sendcloud_qualification.py --env-file /absolute/path/sendcloud.env
```

The tool contacts only fixed Sendcloud v3 endpoints, refuses redirects, bounds
responses, performs zero mutations, and prints only sanitized counts/IDs. It
never prints response bodies, credentials, headers, or addresses.

## Charged qualification gate

Do not advertise production readiness from the read-only check. A real tracked
label, carrier cancellation, and customer-to-workshop return each require a
separate merchant-approved run through Odoo. Record the exact allowlisted option,
maximum object count of one, approver, expected charge, shipment reference, and
result before running it. Never substitute another option after a rejection.

The safe smoke option `sendcloud:letter` still is not a full sandbox: it does
not qualify real carrier tracking, cancellation, or returns and may have a
processing cost. Returns are blocked entirely on test carriers.

## Restrict, rotate, delete, restore

- Restriction blocks new outbound labels and returns while preserving
  cancellation, document recovery, tracking, reconciliation, and signed webhook
  processing for existing objects.
- Rotation writes a new external secret atomically and updates the opaque Odoo
  reference only after the control plane accepts it. Repeat connection and
  signed-webhook tests.
- Deletion is explicit and stops all authenticated cleanup. Historical shipment
  journals and attachments remain readable.
- Restore neutralisation clears carrier secret references and readiness. Supply
  fresh credentials and repeat onboarding; never reuse a restored binding.

## Incident handling

On an ambiguous outbound timeout, do not press **Send to Shipper** repeatedly.
The journal reconciles by `external_reference_id` before any safe replay. A
return timeout is never automatically replayed: compare the local reference
with Sendcloud portal/API evidence and resolve it explicitly. Document failures
after a successful purchase remain `awaiting_document` and are recovered by the
read-only cron. Tracking webhooks are primary; **Refresh tracking** and the
bounded reconciliation cron repair missed or out-of-order events.
