#!/usr/bin/env python3
"""Fail closed on the non-secret identity claims of a GitHub OIDC token."""

from __future__ import annotations

import argparse
import base64
import json
import sys


def decode_payload(token: str) -> dict[str, object]:
    parts = token.strip().split(".")
    if len(parts) != 3 or not all(parts):
        raise ValueError("OIDC token is not a three-part JWT")
    padding = "=" * (-len(parts[1]) % 4)
    try:
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + padding))
    except (ValueError, json.JSONDecodeError) as error:
        raise ValueError("OIDC token payload is not valid base64url JSON") from error
    if not isinstance(payload, dict):
        raise ValueError("OIDC token payload is not an object")
    return payload


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", required=True)
    parser.add_argument("--environment", required=True)
    parser.add_argument("--audience", required=True)
    args = parser.parse_args()

    try:
        payload = decode_payload(sys.stdin.read())
    except ValueError as error:
        raise SystemExit(str(error)) from error

    expected_subject = f"repo:{args.repository}:environment:{args.environment}"
    audiences = payload.get("aud")
    if isinstance(audiences, str):
        audiences = [audiences]
    checks = {
        "sub": (payload.get("sub"), expected_subject),
        "repository": (payload.get("repository"), args.repository),
        "environment": (payload.get("environment"), args.environment),
    }
    failures = [
        f"{name}={actual!r}, expected {expected!r}"
        for name, (actual, expected) in checks.items()
        if actual != expected
    ]
    if not isinstance(audiences, list) or args.audience not in audiences:
        failures.append(f"aud={audiences!r}, expected to contain {args.audience!r}")
    if failures:
        raise SystemExit("GitHub OIDC claim contract failed: " + "; ".join(failures))

    print(
        json.dumps(
            {
                "sub": payload["sub"],
                "aud": audiences,
                "repository": payload["repository"],
                "environment": payload["environment"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
