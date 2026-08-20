#!/usr/bin/env python3
"""Which repository is allowed to have signed each platform image.

Before the repository split one GitHub Actions workflow built and signed every
image, so one keyless identity verified all of them. That is no longer true:
`mb-odoo-addons` signs the Odoo runtime image, `mb-control-plane` signs the
control plane's own images, and `mb-infra` mirrors and signs the
operational-support images it pins.

Keeping the single old identity would mean one of two bad outcomes -- trusting
`MakersBrain/odoo` for images it does not build, or refusing images that are
legitimately signed. This maps each image to the one repository entitled to
vouch for it.

Failing closed is the point. `identity_for` raises on an image nobody has
declared, because an image whose provenance no one has stated is precisely the
one that must not reach production unverified.
"""

from __future__ import annotations

COSIGN_OIDC_ISSUER = "https://token.actions.githubusercontent.com"

# Every publishing repository signs from the same workflow path on main. The
# branch is part of the identity on purpose: a signature produced from a feature
# branch is not a release.
RELEASE_WORKFLOW = ".github/workflows/release.yml@refs/heads/main"

ODOO = "MakersBrain/mb-odoo-addons"
CONTROL_PLANE = "MakersBrain/mb-control-plane"
INFRA = "MakersBrain/mb-infra"

IMAGE_PROVENANCE: dict[str, str] = {
    # Everything loaded into the Odoo process, built from the addons repository.
    "odoo": ODOO,
    # The control plane's own first-party images.
    "control": CONTROL_PLANE,
    "web": CONTROL_PLANE,
    "paperless": CONTROL_PLANE,
    "backup": CONTROL_PLANE,
    "postgres": CONTROL_PLANE,
    # Operational support. Infrastructure builds, mirrors or pins these, so
    # infrastructure is what signs them.
    "alertmanager": INFRA,
    "alpine": INFRA,
    "cloudflared": INFRA,
    "nginx": INFRA,
    "prometheus": INFRA,
    "rauthy": INFRA,
    "redis": INFRA,
    "vmagent": INFRA,
}


class UndeclaredImage(ValueError):
    """An image arrived with no declared signing repository."""


def repository_for(name: str) -> str:
    try:
        return IMAGE_PROVENANCE[name]
    except KeyError:
        raise UndeclaredImage(
            f"no signing repository is declared for image {name!r}. "
            "Add it to deploy/podman/provenance.py naming the repository whose "
            "release workflow signs it; it will not be pulled until then."
        ) from None


def identity_for(name: str) -> tuple[str, str]:
    """Return (certificate identity, certificate repository) for one image."""
    repository = repository_for(name)
    return f"https://github.com/{repository}/{RELEASE_WORKFLOW}", repository


def undeclared(names) -> list[str]:
    """Names with no declared provenance, so one error can list them all."""
    return sorted(set(names) - set(IMAGE_PROVENANCE))
