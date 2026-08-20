#!/usr/bin/env python3
"""Read each image's provenance from the release record that carries it.

There is no map here. The composed platform release, which mb-infra produces,
records for every image which repository signed it and whether it is signed at
all -- observed at composition from which component record the image arrived in,
not from a list anybody maintains.

Deployment reads that. Keeping a second copy here would be a copy of a fact the
record already carries, and one that could drift into trusting the wrong
repository, or into believing an unsigned upstream image had been verified.

Upstream images are pinned by digest and signed by nobody. The digest is the
integrity guarantee; a signature of ours on a copy would only prove we had
copied it. They are recorded `signed: false` and are pulled without a signature
check, which is stated rather than silently skipped.
"""

from __future__ import annotations

COSIGN_OIDC_ISSUER = "https://token.actions.githubusercontent.com"
RELEASE_WORKFLOW = ".github/workflows/release.yml@refs/heads/main"


class UndeclaredImage(ValueError):
    """An image arrived with no provenance in the release record."""


def provenance_of(record: dict, name: str) -> dict:
    """The record's provenance entry for one image.

    Failing closed is the point: an image the record says nothing about is
    precisely the one that must not reach a host.
    """
    entry = (record.get("provenance") or {}).get(name)
    if not isinstance(entry, dict) or "signed" not in entry:
        raise UndeclaredImage(
            f"the release record carries no provenance for image {name!r}; "
            "it will not be pulled."
        )
    return entry


def identity_for(record: dict, name: str) -> tuple[str, str] | None:
    """(certificate identity, repository), or None when nobody signed it."""
    entry = provenance_of(record, name)
    if not entry["signed"]:
        return None
    repository = entry["signed_by"]
    return f"https://github.com/{repository}/{RELEASE_WORKFLOW}", repository


def undeclared(record: dict, names) -> list[str]:
    """Names the record carries no provenance for, so one error lists them all."""
    declared = set((record.get("provenance") or {}).keys())
    return sorted(set(names) - declared)
