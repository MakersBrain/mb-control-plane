# Webshop paid-release qualification

This runbook is the staging evidence contract for the webshop, custom-domain
and transactional-email product. It must run against the exact immutable image
map named by the release record. Local mocks, unit tests and a developer Odoo
database do not satisfy these checks.

Use two synthetic workshops with distinct databases, platform hostnames,
tenant bridge credentials and custom domains. Use only protected synthetic
customers and provider test accounts. Never put a hostname, address, provider
identifier, credential, order reference or customer data in an evidence
summary.

## Preconditions

- The staging release is deployed from digest-pinned images and its release
  verification has passed.
- Public DNS and TLS are available for both platform hostnames.
- The staging recipient is present in the mail gateway's exact allowlist.
- Cloudflare for SaaS, Scaleway TEM/DNS, SumUp and Boxtal staging or approved
  low-value production accounts are configured through scoped secret files.
- Provider dashboards and retained diagnostic logs are accessible to the
  operator conducting the test, but are not copied into the privacy-safe
  qualification artifact.
- Browser tests use a clean profile and do not bypass the public edge.

## `webshop_cloudflare_dns_tls`

Pass only when all of the following are observed through the public edge:

1. Connect a previously unclaimed synthetic custom hostname through the
   merchant UI and publish the displayed ownership record.
2. Reconciliation observes ownership, creates or adopts exactly one provider
   custom hostname, and reaches active certificate and routing state.
3. HTTPS serves the correct workshop and certificate. The platform hostname
   redirects to the selected canonical custom hostname.
4. A hostname assigned to workshop A cannot be claimed by workshop B.
5. Temporarily remove or invalidate the required DNS evidence. The dashboard
   exposes a bounded recovery action and does not route an unverified hostname.
6. Restore DNS and prove reconciliation recovers without duplicate provider
   resources or manual database edits.

The separate `two_tenant_isolation` check must also run
`tools/test_topology_odoo_isolation.py` against these two deployed workshops.

## `webshop_scaleway_mail`

Pass only when the exact deployed mail boundary proves both sender modes:

1. Send an approved order message with the platform sender. Confirm delivered
   state and that the artisan reply-to is preserved.
2. Register a synthetic sender domain, publish the displayed SPF, DKIM and
   DMARC records, and prove the domain cannot activate before all DNS states
   and the exact-domain delivered test are observed.
3. Send an approved message from the active branded sender and confirm its
   delivered event is bound to the correct outbox message and provider domain.
4. Exercise authenticated deferred, bounce and complaint events. Confirm the
   durable dashboard states and recipient suppression behavior.
5. Replay an event and prove it is deduplicated. Submit an invalid topic,
   signature or domain binding and prove it is rejected before state mutation.
6. Disconnect the branded domain and prove subsequent mail falls back to the
   fixed platform sender without deleting historical events.

`mail_delivery` remains mandatory for the platform's non-webshop mail paths;
this webshop-specific check cannot be substituted for it.

## `webshop_sumup_payment`

Use the provider's supported staging facility or one approved low-value order.
Pass only when:

1. A published product is checked out through the public shop and SumUp reports
   the authoritative successful checkout state.
2. Odoo contains one paid sale order, the expected stock reservation/movement
   and invoice workflow, with no duplicate transaction or fulfilment.
3. Replaying the provider notification and sending forged success fields do
   not create or settle another payment; settlement is based on provider
   read-back.
4. A failed/cancelled checkout remains unpaid and retryable without reserving
   stock indefinitely.
5. A payment deliberately completed after hold expiry creates exactly one
   merchant-visible exception. Exercise one fulfil recovery or refund recovery
   to its terminal state and replay it to prove idempotency.

## `webshop_boxtal_shipping`

Use a synthetic deliverable address and the configured staging/approved carrier
offer. Pass only when:

1. Checkout returns the expected home-delivery or pickup offer and a pickup
   selection is revalidated before payment and purchase.
2. Merchant fulfilment purchases exactly one shipment and obtains a valid PDF
   label without exposing provider credentials or unsafe document URLs.
3. An authenticated tracking event is deduplicated and updates the customer and
   merchant-visible state.
4. Exercise a delivery exception and prove the dashboard exposes its recovery
   action.
5. Exercise an ambiguous purchase response. Prove the operation is reconciled
   or left explicitly unknown and is never blindly replayed for a provider
   operation without idempotency evidence.
6. Deactivate/reactivate the webshop and prove provider webhook subscriptions
   are removed/recreated without deleting shipment history.

## `webshop_browser_accessibility`

Run through the public TLS endpoints at desktop and mobile viewport sizes. Pass
only when:

1. A merchant can pause, resume and complete onboarding, and every failing
   readiness item links to a usable recovery action.
2. Browse collection and product pages, add to cart, select delivery, pay, view
   the portal order, request a return and observe the merchant return queue.
3. Repeat the public storefront journey for both synthetic workshops and prove
   that host, content, session, cart and portal access never cross tenants.
4. Exercise all three craft palettes with representative content after an
   in-place module upgrade at desktop and mobile widths.
5. Automated accessibility reports no failed WCAG audit in the agreed
   Lighthouse suite, and keyboard-only navigation can reach storefront,
   checkout, onboarding and recovery controls with a visible focus indicator.
6. Merchant deactivation closes the public shop immediately; reactivation
   restores it with retained configuration and external assets.

## Load evidence

The existing mandatory `load_test` check must include the webshop workload. Run
against the production-like multiworker topology, not the single-process local
Odoo server. Record the agreed concurrency, duration and latency/error targets
in the protected test report before execution. The privacy-safe summary may
state only whether those predeclared targets passed. At minimum include public
catalog reads, cart mutations, checkout hold contention for a last item,
control-plane dashboard reads and provider-webhook ingestion. Confirm bounded
queues, no negative stock, no duplicate fulfilment and no cross-tenant result.

## Observability evidence

The mandatory `observability_delivery` check proves that the candidate emits
privacy-safe application and database telemetry and that backup status reaches
the staging monitoring system. Trigger one synthetic application alert, one
database alert and one backup alert through the normal metrics and rule path.
For each, verify notification routing, operator acknowledgement, recovery and
resolution without disabling the rule or inserting an alert directly into the
notification service.

The protected report records the rule names, test window, delivery timestamps
and acknowledgement/resolution outcomes. Before passing the check, inspect the
associated metrics, structured logs, traces and notification payloads for the
forbidden labels declared in `deploy/release-contract.json`. The privacy-safe
evidence summary states only that all three alert lifecycles and the label review
passed for the candidate release.

Before the drill, confirm `prometheus.service` and `alertmanager.service` are
the digest-pinned units in the candidate image map and that neither publishes a
host port. Exercise the application rule by stopping the API process, then
restore it. Exercise the database rule by fencing or stopping the staging DB
while leaving the API process running, then restore connectivity. Exercise the
backup rule by stopping the staging backup scheduler only after a verified
synthetic recovery point exists and allowing the normal 26-hour freshness
threshold to expire. Budget that interval in the qualification window; never
shorten or edit a live rule, alter recovery timestamps, or inject an
Alertmanager event. Restart the scheduler, require a new verified backup, and
capture Prometheus rule state plus the receiver's
trigger/acknowledgement/resolution timestamps in protected evidence.

## Evidence and promotion

For each successful named check, write the five-field JSON evidence file
required by `deploy/podman/qualification.py`: `check`, `status`, `started_at`,
`completed_at` and a privacy-safe `summary`. A check is `passed` only after all
of its conditions above pass for the exact release. Do not convert a skip,
provider outage, unavailable credential or manual expectation into a pass.

Create and validate the qualification record as described in
`deploy/podman/README.md`. Production promotion remains fail-closed until the
complete evidence set is signed and published as an immutable OCI artifact
bound to the exact release and image map.
