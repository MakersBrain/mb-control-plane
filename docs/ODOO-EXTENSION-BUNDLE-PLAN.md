# Odoo extension-bundle delivery plan

Status: proposed for review
Date: 2026-08-21
Scope: `mb-control-plane`, `mb-odoo-addons`, and `mb-infra`

## 1. Objective

Run the exact digest-pinned official `odoo:19` image without deriving or
modifying it for ordinary MakersBrain addon releases. Deliver MakersBrain
addons and any future addon-only Python dependencies as a separately signed,
immutable extension bundle.

An addon-only release must not rebuild the Odoo image. An Odoo base-image
change remains a distinct application-release change and must pass the full
database and bridge qualification gates.

This software has not been deployed to production. Update the current curated
control-plane baseline and release contracts directly; do not add data
migrations or compatibility adapters for the monolithic image format.

## 2. Current facts

- `mb-odoo-addons/addons` contains 41 versioned MakersBrain addons and is about
  9 MB.
- Odoo already loads external code through `/mnt/mb-addons` and
  `/mnt/oca-addons`.
- `mb-odoo-addons/tools/release_metadata.py` already records the Odoo base
  digest, every MakersBrain addon version, the current OCA `auth_oidc` commit,
  and the bridge-contract digest.
- The exact pinned official Odoo 19 image contains Python 3.12, `pip`, `qrcode`,
  and `reportlab`. It does not contain `python-jose`.
- OCA `auth_oidc` is the only current reason for `python-jose`. Its additional
  behavior is authorization-code/PKCE handling and local ID-token validation;
  Odoo's built-in `auth_oauth` does not provide the required code-flow fields.
- The official Odoo entrypoint supports `PASSWORD_FILE`, but when `db_password`
  is absent from `ODOO_RC` it expands that secret into `--db_password` process
  arguments. Its file reader also lacks the control plane's strict regular-file,
  size, and single-line checks. `PASSWORD_FILE` alone is therefore insufficient
  for the required secret boundary.

## 3. Selected artifact model

Each application release declares two independently verified OCI inputs and
one qualified pairing between them:

1. `odoo_runtime`: the complete exact official Odoo OCI descriptor;
2. `extension_bundle`: a signed OCI image containing only immutable payloads:
   - `/payload/addons`: MakersBrain addons;
   - `/payload/python`: optional prebuilt addon-only Python packages;
   - `/payload/manifest.json`: versions, hashes, Python ABI, platform, bridge
     contract, source commit, and dependency inventory.

The extension image is a transport image, not the Odoo runtime. Do not execute
an entrypoint supplied by that image during materialization. A fixed,
version-pinned driver helper copies `/payload` from the image into an empty
target volume and writes a digest-bound completion marker last. Bound the
uncompressed byte count, file count, individual file size, and elapsed time
before and during extraction.

Do not use the word `digest` without naming the OCI object it identifies. For
each OCI input, record:

- the digest-pinned source reference and its subject digest;
- whether that subject is an OCI image index or an image manifest;
- the selected `os`, architecture, and variant;
- the selected platform-manifest digest; and
- the image-configuration digest reported by the selected manifest.

The digest in an index-pinned reference, the selected platform-manifest digest,
and Docker or Podman's local image/configuration ID are different identities.
Evidence must record and compare the correct identity at each step. A
multi-platform release contains one platform descriptor and qualification
record per supported platform; it never treats an index digest as the identity
of a running platform image.

The driver materializes one volume per extension platform-manifest digest and
payload tree digest and mounts it read-only in Odoo at
`/opt/mb-extension`. Odoo starts with:

```text
--addons-path=/opt/mb-extension/addons,/usr/lib/python3/dist-packages/odoo/addons
PYTHONPATH=/opt/mb-extension/python
```

Never change an existing extension volume in place. A new platform-manifest or
payload tree digest always gets a new volume. Retain prior volumes while their
releases remain rollback candidates.

The extension manifest contains a `qualified_odoo_runtime` descriptor with the
complete Odoo subject, platform-manifest, configuration, and platform
identities used by CI. Publication and preflight must require exact equality
between that descriptor and the selected `odoo_runtime` descriptor. Matching
only Python ABI, Odoo version, or platform is insufficient. Activation binds a
pair-qualification digest computed from the canonical runtime descriptor,
extension descriptor, payload digest, bridge contract, addon versions, and
qualification result.

## 4. Python dependency injection

Build addon-only dependencies into `/payload/python` during CI with the exact
Odoo platform-manifest and configuration digests that will consume them. Use a
fully pinned, hash-checked lock file and an offline wheelhouse. The resulting
directory is ordinary Python `site-packages` content made visible through
`PYTHONPATH`; the Odoo filesystem and system Python installation remain
unchanged.

The initial dependency payload is empty. Remove OCA `auth_oidc` and do not ship
`python-jose`. `qrcode` and `reportlab` remain provided by the official image,
but CI must prove they are importable from every allowed Odoo platform
descriptor.

Add a dependency-policy gate that:

- extracts every addon's `external_dependencies` declaration;
- maintains an explicit import-to-distribution mapping where names differ;
- proves each dependency is supplied by either the exact Odoo image or the
  locked extension payload;
- rejects undeclared imports and dependencies without hashes;
- rejects a Python ABI or target-platform mismatch;
- rejects native packages that require an unavailable system library.

The gate must also reject unowned top-level modules, namespace collisions with
Odoo or the standard/runtime package set, `sitecustomize`, `usercustomize`,
executable `.pth` files, unexpected console scripts, and files not represented
in the dependency inventory. Test imports and native dynamic-library loading
inside the exact selected Odoo platform image; wheel tags alone are not proof
of runtime compatibility.

Pure Python packages and compatible manylinux wheels may use this mechanism.
An addon requiring a new system package, daemon, device, or incompatible native
library must trigger an explicit Odoo-runtime decision; it cannot silently add
software during container startup.

Do not run `pip`, `apt`, or a package resolver in the deployed Odoo container.
Do not download dependencies during release preparation. Runtime preparation
must consume only previously admitted, digest-addressed artifacts and the
evidence already bound by the signed release manifest.

## 5. Artifact verification and SBOM policy

Odoo 19 is distributed as a Docker Official Image. That program provides a
curated build and public source trail, but it does not currently provide the
same stable signed-SBOM and SLSA-provenance contract that Docker documents for
Docker Hardened Images. Docker is also retiring Docker Content Trust for
Official Images. Docker Scout may generate an SBOM by inspecting an image when
no upstream SBOM attestation exists; that generated document is an observation,
not proof from the Odoo or Docker build system.

Use a deliberately small verification model suitable for the current team. The
signed application-release manifest is the single admission statement for the
tested runtime/extension pair; do not create a second signing service, custom
attestation protocol, transparency-log dependency, or internal image mirror.

### 5.1 Official Odoo runtime admission

For each allowed platform, CI must:

1. resolve `docker.io/library/odoo` by digest with no tag fallback and record the
   subject, selected platform-manifest, and configuration digests;
2. generate an SPDX JSON SBOM from that selected image with one pinned scanner
   and record the scanner name and version;
3. generate a vulnerability report, record the scanner/advisory snapshot time,
   and apply the repository's versioned severity policy; and
4. run the runtime capability checks, including Python ABI, required imports,
   official-entrypoint behavior, and read-only-root startup.

Store the SBOM and vulnerability report as immutable CI release artifacts and
put their SHA-256 digests in the signed application-release manifest. The
signature on that manifest records MakersBrain's decision to admit the exact
official image bytes and the generated evidence. It is not upstream Odoo
provenance, and the generated SBOM must be labelled `observed` rather than
`upstream_attested`.

If the selected official image later publishes a verifiable upstream signature,
SBOM, or provenance attestation under an approved policy, verify and record it
as optional additional evidence. Do not block releases on evidence the official
distribution channel does not guarantee.

### 5.2 MakersBrain extension verification

Sign the extension image with the existing release key. Generate one SPDX JSON
SBOM and one vulnerability report in the same CI release, store them as
immutable release artifacts, and bind their digests plus the source commit,
lock-file digest, payload tree digest, and exact qualified Odoo descriptors into
the signed application-release manifest. BuildKit provenance may be retained
when the existing builder emits it, but it is not a separate deployment gate.

Publication and preflight verify the extension signature, the signed release
manifest, every referenced evidence digest, and exact runtime/extension pair
equality. This provides one understandable trust root and one auditable release
decision without pretending MakersBrain signed the upstream Odoo build.

Relevant upstream contracts are the Docker documentation for
[Official Images](https://docs.docker.com/docker-hub/repos/manage/trusted-content/official-images/),
[Docker Scout SBOM behavior](https://docs.docker.com/scout/how-tos/view-create-sboms/),
and the [`odoo/docker` source repository](https://github.com/odoo/docker).

## 6. OIDC without `python-jose`

Do not fall back to Odoo's implicit OAuth flow. Preserve authorization code,
PKCE S256, state, nonce, RS256, exact issuer, and per-tenant audience checks.

Replace OCA `auth_oidc` with a narrow MakersBrain code-flow addon that extends
the built-in `auth_oauth` integration. It must:

1. generate a fresh PKCE verifier and nonce for each login and retain them only
   in the server-side Odoo session;
2. send an authorization-code request to the exact configured Rauthy issuer;
3. validate the callback state and redeem the single-use code over a bounded,
   certificate-validated request;
4. submit the returned ID token, access token, and expected nonce to a
   tenant-authenticated internal control API whose workshop identity comes from
   its path and credential, not request-body assertions;
5. accept identity claims only after that API validates signature, issuer,
   audience, expiry, nonce, and, when present, the access-token hash;
6. pass the returned stable subject through the existing no-user-creation Odoo
   linking path;
7. keep tokens out of logs, durable database fields, redirects, and errors.

Add an internal control-plane endpoint dedicated to this verification at a
workshop-scoped path. Reuse the Rust OIDC discovery/JWKS cache. Derive the
expected audience with the same versioned deterministic rule the driver already
uses to create the workshop client: `mb-odoo-{workshop_uuid_simple}`.
The request must not select its own audience. The caller must use the existing
tenant-scoped Odoo-to-control credential, and that credential must authenticate
the workshop in the path before token parsing begins. Provisioning and repair
must continue to reconcile that exact client in Rauthy. Responses expose only
the allowlisted stable subject and fields required for an existing-user login.

OIDC Core permits `at_hash` to be absent from an ID token returned by the token
endpoint in Authorization Code Flow. Validate it in constant time whenever it
is present and reject a mismatch, but do not reject a standards-conforming
token solely because that optional claim is absent. The server-to-server token
exchange, TLS validation, exact issuer/audience checks, PKCE, and nonce remain
mandatory.

Treat the Odoo session login attempt as single-use: store a generated attempt
identifier, state, nonce, verifier, creation time, and return target in the
server-side session; atomically consume the attempt before code redemption;
and expire it after a short fixed lifetime. Rauthy's single-use authorization
code plus the consumed session attempt is the replay boundary; do not add a
second durable token-replay database. Never persist the token, access token,
nonce, verifier, or returned claims. A lost response therefore fails closed
and requires a fresh login rather than replaying the callback.

This keeps JOSE and trust-policy code in the control plane rather than
reimplementing cryptography in an Odoo addon. If the control API is unavailable
or any required claim is absent or mismatched, login fails closed. Add a short
threat model covering callback CSRF, code interception, token substitution, key
rotation, replay, cross-tenant audience confusion, and control-API outage.

## 7. Native secret-file consumption

Materialize a complete, per-runtime Odoo configuration as a protected secret
file, mount it read-only, and set `ODOO_RC` to that path. It must contain
`db_host`, `db_port`, `db_user`, and `db_password`. The official entrypoint and
`wait-for-psql.py` then read those values from the configuration and do not add
the password to process arguments.

The driver/bootstrap path that materializes this configuration must enforce a
regular non-link file, bounded single-line source values, safe configuration
escaping, owner-only access, atomic creation, and no overwrite of a populated
runtime slot. The generated configuration is a secret artifact and must never
enter the extension bundle, image layer, release metadata, logs, or audit
payloads.

Do not treat `PASSWORD_FILE` alone as the production solution. It may be used
only in an isolated developer fixture whose process-argument exposure is
explicitly accepted and tested.

Update `mb_control_bridge` to accept
`MB_CONTROL_BRIDGE_TOKEN_FILE=/run/secrets/odoo_bridge_token`. It must apply the
same regular-file, size, line-ending, and non-empty checks as the control plane,
and must reject simultaneous file and plaintext settings. After every caller
uses the file setting and every database-init/update/shell job consumes the
protected `ODOO_RC`, remove `deploy/odoo-secret-entrypoint.sh` and
`deploy/Odoo.Dockerfile` from the control plane.

Other tenant credentials remain in their existing read-only, tenant-scoped
secret roots. They are not part of the extension bundle.

## 8. `mb-odoo-addons` changes

1. Replace the monolithic runtime Dockerfile with an extension-bundle build.
2. Pin the bundle transport base by digest and publish the bundle for every
   supported platform.
3. Remove OCA `auth_oidc` and add the dependency-free MakersBrain code-flow
   adapter and its control-plane validation client.
4. Add the dependency inventory and an empty-by-default, hashed Python lock and
   offline wheel build for future pure-Python dependencies.
5. Extend release metadata with:
   - extension index/subject, platform-manifest, and configuration digests;
   - payload tree digest;
   - the complete Odoo runtime descriptor used for qualification;
   - Python implementation, ABI, and platform;
   - locked dependency names and versions;
   - addon versions;
   - bridge-contract digest; and
   - evidence-object and pair-qualification digests.
6. Sign the extension image and publish its SBOM, vulnerability report, release
   metadata, bridge contract, and any provenance already emitted by the builder.
7. Run the complete addon suite using the exact official Odoo image plus the
   materialized extension volume, not a derived Odoo image.

## 9. Control-plane contract and database changes

Replace the single application-release image identity with independently
validated runtime and extension identities plus an explicit qualification for
each supported pair. The release manifest must contain the equivalent of:

```json
{
  "odoo_runtime": {
    "official_source_ref": "docker.io/library/odoo@sha256:<subject>",
    "deployment_ref": "docker.io/library/odoo@sha256:<subject>",
    "subject_digest": "sha256:<subject>",
    "subject_kind": "image_index",
    "version": "19.0",
    "platforms": [{
      "platform": {"os": "linux", "architecture": "amd64"},
      "manifest_digest": "sha256:<runtime-manifest>",
      "config_digest": "sha256:<runtime-config>",
      "evidence": {
        "sbom_ref": "registry.example/evidence/odoo-sbom@sha256:...",
        "sbom_digest": "sha256:...",
        "vulnerability_report_ref": "registry.example/evidence/odoo-vulns@sha256:...",
        "vulnerability_report_digest": "sha256:...",
        "scanner": "<name-and-version>",
        "policy_digest": "sha256:...",
        "sbom_kind": "observed"
      }
    }]
  },
  "extension_bundle": {
    "oci_ref": "registry.example/mb-odoo-extension@sha256:<subject>",
    "subject_digest": "sha256:<subject>",
    "subject_kind": "image_index",
    "platforms": [{
      "platform": {"os": "linux", "architecture": "amd64"},
      "manifest_digest": "sha256:<extension-manifest>",
      "config_digest": "sha256:<extension-config>",
      "payload_digest": "sha256:<payload>",
      "python_implementation": "cpython",
      "python_abi": "cp312",
      "qualified_odoo_runtime": {
        "subject_digest": "sha256:<subject>",
        "manifest_digest": "sha256:<runtime-manifest>",
        "config_digest": "sha256:<runtime-config>"
      },
      "signature_bundle_ref": "registry.example/evidence/extension-signature@sha256:...",
      "sbom_ref": "registry.example/evidence/extension-sbom@sha256:...",
      "vulnerability_report_ref": "registry.example/evidence/extension-vulns@sha256:..."
    }]
  },
  "pair_qualifications": [{
    "platform": {"os": "linux", "architecture": "amd64"},
    "odoo_manifest_digest": "sha256:<runtime-manifest>",
    "extension_manifest_digest": "sha256:<extension-manifest>",
    "payload_digest": "sha256:<payload>",
    "qualification_digest": "sha256:..."
  }]
}
```

Every evidence reference in the real schema has a digest and subject binding;
the abbreviated extension references above do not imply mutable tags.

Update the curated base schema, Rust manifest types, OpenAPI, generated browser
client, release contract, and catalog assertions together. Runtime-slot
evidence must bind both OCI subjects, both selected platform manifests and
configuration digests, the materialized payload digest, volume identity,
pair-qualification digest, bridge-contract digest, and installed addon versions.

Apply the differentiated verification policies in section 5: an observed SBOM
and signed release admission for the official runtime; an image signature and
SBOM for the MakersBrain extension. Publication, preflight, activation,
rollback, and audit records must never identify a release by only one subject
or omit the selected platform and pair qualification.

Add the tenant-authenticated internal ID-token validation endpoint and bind its
expected audience to the workshop's registered Rauthy client. Extend the Rust
verifier and tests to cover nonce validation; present, absent, and mismatched
`at_hash`; key rotation; consumed callback replay; wrong audiences; wrong
workshops; and malformed token inputs.

## 10. Driver preparation and activation

For a release preflight, the deployment driver must:

1. select exactly one declared platform descriptor for the deployment host;
2. verify the official Odoo reference is digest pinned and allowed, then verify
   the signed release manifest, observed SBOM and vulnerability evidence
   digests, policy result, and selected OCI identities;
3. verify the extension signature, SBOM and vulnerability evidence digests,
   selected OCI identities, and payload metadata;
4. require the extension's `qualified_odoo_runtime` to exactly equal the
   selected runtime descriptor and verify the pair-qualification digest bound
   by the signed release manifest;
5. pull both selected artifacts by digest and prove the resolved platform
   manifests and configuration digests equal the contract;
6. create a new platform-manifest-and-payload-derived target volume with a
   bounded name and acquire a preparation lease for it;
7. use the fixed trusted copy helper, not bundle-supplied executable behavior,
   with no network, no secrets, a read-only root filesystem, dropped
   capabilities, bounded extraction resources, and only the empty target
   volume writable;
8. validate the completion marker, payload tree digest, ownership, modes,
   allowed top-level paths, addon manifests, complete dependency file inventory,
   imports, native-library closure, and absence of links or path escapes;
9. start the exact official Odoo image with the extension volume read-only,
   native secret-file settings, and the declared `PYTHONPATH`/addon paths;
   keep its root filesystem read-only while providing only the required Odoo
   data volume and bounded temporary-filesystem mounts as writable storage;
10. run the existing module-update, registry, schema, XMLID, bridge, health, and
   tenant-isolation postconditions;
11. record the prepared slot and all normalized identity evidence without
    modifying the active slot; and
12. activate only through the existing atomic release-activation path.

Replay with the same release and evidence is a no-op. Any digest, platform,
marker, import, or installed-version mismatch fails closed and leaves the
active slot unchanged.

Garbage collection must use the existing lifecycle lock. It may delete a volume
only after one transactional check proves that no active runtime slot, retained
rollback release, preparation, or engine container/mount references it. A
failed deletion remains auditable and retryable.

## 11. `mb-infra` changes

- Compose a platform release from the complete official Odoo descriptor,
  extension-bundle descriptor, pair-qualification digest, control-plane digest,
  and infrastructure digest.
- Verify both Odoo artifacts before submitting the application-release
  manifest.
- Stop producing or consuming the former monolithic `mb-odoo` runtime image.
- Expose neither addon nor dependency volumes as operator-editable mounts.
- Include both subject, platform-manifest, and configuration identities plus
  the pair qualification in promotion, rollback, and qualification evidence.

## 12. Acceptance gates

- The running Odoo container is configured with the declared digest-pinned
  official source or byte-preserving deployment reference; its selected
  manifest and inspected configuration/image ID equal their distinct declared
  values. No derived Odoo image exists in the release.
- The signed application-release manifest binds an observed SPDX SBOM and scan
  result for the official runtime. The extension has a valid MakersBrain image
  signature and SPDX SBOM. Evidence never mislabels the observed runtime SBOM
  or release decision as upstream Odoo provenance.
- The official image filesystem remains unchanged and its root filesystem is
  read-only.
- All 41 MakersBrain addons load from the read-only extension volume, with no
  OCA `auth_oidc` or `python-jose` present.
- `qrcode` and `reportlab` import successfully from the exact official image;
  adding an undeclared dependency or tampering with a future dependency payload
  fails preflight.
- Rauthy authorization-code/PKCE login passes with centralized ID-token
  verification; implicit flow, wrong nonce, wrong audience, token substitution,
  replay, and cross-workshop validation all fail closed.
- No deployed job executes a package manager or has dependency-download
  network access.
- Database and bridge secrets are consumed from files and never appear in
  container metadata, process arguments, or addon volumes.
- Addon-only changes publish and activate a new extension digest without
  rebuilding or changing the Odoo runtime digest.
- Odoo-runtime and extension artifacts can be admitted independently, but every
  activatable platform pair has its own signed qualification and exact
  descriptor equality proof.
- Empty-fleet activation, two-workshop isolation, bridge compatibility,
  recovery, rollback, and old-slot garbage-collection tests pass.
- A failed extension preparation leaves the prior slot and volume usable. A
  failed module update restores the verified pre-update recovery set and proves
  the prior runtime can reconnect before maintenance mode is removed.
- Docker and Podman implementations produce equivalent evidence.

## 13. Delivery sequence

1. **Identity contract**: add the control-plane ID-token verifier endpoint and
   the dependency-free Odoo code-flow adapter; prove the complete Rauthy login
   and remove `auth_oidc`/`python-jose`.
2. **Addon contracts**: add native bridge-token file support, dependency
   inventory, empty lock file, extension builder, metadata, signing, and tests
   in `mb-odoo-addons`.
3. **Control contracts**: update the fresh schema baseline, release manifest,
   OpenAPI, generated client, verification, and runtime-slot evidence in
   `mb-control-plane`.
4. **Driver lifecycle**: implement extension materialization, official-image
   startup, preflight, rollback retention, and garbage collection.
5. **Infrastructure composition**: consume and promote the paired artifacts in
   `mb-infra`.
6. **Cleanup**: delete the derived Odoo Dockerfiles, custom secret entrypoint,
   monolithic-image metadata, and obsolete CI paths only after the paired
   release passes full-topology qualification.

Do not combine the artifact-contract change with a live environment reset.
Because no production data exists, qualify on a newly created disposable
topology and recreate it on failure rather than introducing compatibility or
data-migration code.

## 14. Alternatives considered

- **Install dependencies at container startup:** rejected because it mutates
  runtime state, requires a resolver or network, slows startup, and cannot be
  bound reliably to release evidence.
- **Create a virtual environment during deployment:** workable but unnecessary;
  Odoo's executable still uses the system interpreter and the environment adds
  activation and shebang coupling. A prebuilt read-only target directory plus
  `PYTHONPATH` is smaller and explicit.
- **Mount raw Git checkouts:** retained for local development only; branches and
  working trees are not immutable deployment inputs.
- **Upload ZIP modules through Odoo:** rejected for controlled deployments
  because it creates per-database code drift and bypasses release signing,
  preflight, and rollback evidence.
- **Use built-in implicit `auth_oauth`:** rejected because it would remove the
  current authorization-code/PKCE guarantees and expose bearer tokens to the
  browser callback.
- **Implement JOSE in the addon:** rejected because identity-token cryptography,
  issuer policy, and JWKS rotation already belong to the Rust control plane.
- **Inject OS packages through a volume:** unsupported. Addons needing new OS
  libraries require an explicit runtime-image decision.
