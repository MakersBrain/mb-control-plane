# Control-plane DPIA record

Status: threshold assessment and controller approval pending
Last updated: 2026-08-14

## Decision

The project requires a DPIA as an internal production gate even if the future
controller's formal Article 35 threshold assessment concludes it is not legally
mandatory. Production personal-data processing is currently prohibited.

## Processing in scope

The assessment covers central identity and workshop authority, invitations,
operator actions, multi-tenant routing, Odoo and Paperless provisioning,
document/inventory extraction, entitlement and usage records, telemetry,
encrypted recovery sets and data-subject request orchestration.

## Initial high-impact failure modes

- cross-tenant routing, secret resolution or restore;
- public API or email compromise minting invitation capabilities;
- a shared runtime accessing a tenant during an incompatible schema upgrade;
- excessive privileges exposing every tenant/provider capability;
- document, identity or token content entering logs and operation payloads;
- a rights export disclosing another subject's data, crossing tenant scope or
  remaining retrievable after consumption/expiry;
- erasure being reversed by restoration of an older backup;
- automated extraction results being treated as final accounting decisions;
- processing or support access occurring outside the approved EEA boundary.

## Required controls before approval

The P0/P1/P2 gates in `CONTROL-PLANE-IMPROVEMENT-PLAN.md`, the field inventory,
approved retention policy, two-workshop isolation suite, secret canaries,
human review of extraction and rights-export scope, processor register,
transfer assessment, breach rehearsal and data-subject workflow evidence are
mandatory inputs. Rights exports require controller review and processor
acknowledgements before generation, exact tenant/owner filters, authenticated
encryption, integrity verification, single-use download and automatic expiry.

## Approval

Controller: pending
DPO consultation: pending/not yet determined
Residual-risk decision: pending
Review trigger: new provider, personal-data category, profiling/automation,
international transfer, material architecture change or security incident
