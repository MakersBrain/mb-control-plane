# ADR 0003: Per-workshop Paperless processes and Redis ACLs

Status: accepted

Paperless is deployed per workshop with its own database, volumes, credentials
and process set. Redis infrastructure may be shared, but each workshop receives
a distinct ACL user restricted to its key and channel prefixes.

This preserves workshop isolation while avoiding a Redis process per tenant.
Provisioning and recovery must prove both the PostgreSQL and Redis boundaries.
A dedicated Redis instance is required if upstream behavior cannot remain
within enforceable ACL prefixes.

The process receives only a read-only Docker volume subpath for its workshop's
`paperless-runtime` directory in the driver-only volume; API and worker mounts
cannot read it. Database, Redis, Django, OIDC, local-admin and
webhook credentials are supplied through Paperless `_FILE` settings and never
through Docker `Env` or `Cmd`. The post-consume webhook uses the workshop-bound
bridge credential, not the control plane's global internal token. CI rejects a
return to metadata secrets. The Docker Engine subpath contract must also pass
`make topology-secret-check` before deployment; that live canary proves both
cross-subpath isolation and read-only enforcement.

The workshop-scoped Paperless API credential used by control-plane integrations
lives in a separate read-only client volume mounted only by the membership and
invoice workers. It is not stored with either tenant Odoo credentials or the
Paperless infrastructure secrets. The container configuration digest includes
the driver-only source volume and a boundary version so a mount-layout change
recreates an obsolete container before its old runtime path is discarded.
