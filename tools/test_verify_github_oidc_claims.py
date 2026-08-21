#!/usr/bin/env python3

from __future__ import annotations

import base64
import json
import subprocess
from pathlib import Path


SCRIPT = Path(__file__).with_name("verify_github_oidc_claims.py")


def encoded(value: dict[str, object]) -> str:
    return base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")


def token(payload: dict[str, object]) -> str:
    return f"{encoded({'alg': 'RS256'})}.{encoded(payload)}.signature"


def invoke(payload: dict[str, object]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "python3",
            str(SCRIPT),
            "--repository",
            "MakersBrain/odoo",
            "--repository-id",
            "1332519958",
            "--repository-owner-id",
            "311501550",
            "--environment",
            "release",
            "--audience",
            "mb-release",
        ],
        input=token(payload),
        text=True,
        capture_output=True,
        check=False,
    )


def main() -> int:
    claims = {
        "sub": "repo:MakersBrain@311501550/odoo@1332519958:environment:release",
        "aud": "mb-release",
        "repository": "MakersBrain/odoo",
        "repository_id": "1332519958",
        "repository_owner_id": "311501550",
        "environment": "release",
    }
    accepted = invoke(claims)
    if accepted.returncode != 0:
        raise AssertionError(accepted.stderr)
    summary = json.loads(accepted.stdout)
    if summary["sub"] != claims["sub"] or "signature" in accepted.stdout:
        raise AssertionError("safe claim summary is incomplete or exposes the JWT")

    for name, value in (
        ("sub", "repo:MakersBrain/odoo:ref:refs/heads/main"),
        ("aud", "wrong-audience"),
        ("repository", "Other/odoo"),
        ("repository_id", "999"),
        ("repository_owner_id", "999"),
        ("environment", "production"),
    ):
        rejected = invoke({**claims, name: value})
        if rejected.returncode == 0 or name not in rejected.stderr:
            raise AssertionError(f"mismatched {name} was not rejected")
        if "signature" in rejected.stderr:
            raise AssertionError("rejection exposed the JWT")

    malformed = subprocess.run(
        [
            "python3",
            str(SCRIPT),
            "--repository",
            "MakersBrain/odoo",
            "--repository-id",
            "1332519958",
            "--repository-owner-id",
            "311501550",
            "--environment",
            "release",
            "--audience",
            "mb-release",
        ],
        input="not-a-jwt",
        text=True,
        capture_output=True,
        check=False,
    )
    if malformed.returncode == 0:
        raise AssertionError("malformed JWT was accepted")
    print("GitHub OIDC claim preflight fails closed without exposing the token")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
