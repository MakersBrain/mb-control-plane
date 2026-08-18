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
    parser.add_argument("--repository-id", required=True)
    parser.add_argument("--repository-owner-id", required=True)
    parser.add_argument("--environment", required=True)
    parser.add_argument("--audience", required=True)
    args = parser.parse_args()

    try:
        payload = decode_payload(sys.stdin.read())
    except ValueError as error:
        raise SystemExit(str(error)) from error

    try:
        owner, repository_name = args.repository.split("/", 1)
    except ValueError as error:
        raise SystemExit("repository must be OWNER/NAME") from error
    for name, value in (
        ("repository-id", args.repository_id),
        ("repository-owner-id", args.repository_owner_id),
    ):
        if not value.isdecimal() or int(value) <= 0:
            raise SystemExit(f"{name} must be a positive decimal ID")
    expected_subject = (
        f"repo:{owner}@{args.repository_owner_id}/"
        f"{repository_name}@{args.repository_id}:environment:{args.environment}"
    )
    audiences = payload.get("aud")
    if isinstance(audiences, str):
        audiences = [audiences]
    checks = {
        "sub": (payload.get("sub"), expected_subject),
        "repository": (payload.get("repository"), args.repository),
        "repository_id": (payload.get("repository_id"), args.repository_id),
        "repository_owner_id": (
            payload.get("repository_owner_id"),
            args.repository_owner_id,
        ),
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
                "repository_id": payload["repository_id"],
                "repository_owner_id": payload["repository_owner_id"],
                "environment": payload["environment"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
