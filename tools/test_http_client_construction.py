#!/usr/bin/env python3
"""Keep production Reqwest transport construction behind the reviewed policy."""

from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DIRECT_CONSTRUCTION = re.compile(
    r"(?:reqwest::Client::(?:new|builder)|reqwest::ClientBuilder::new)\s*\("
)

# This module owns connect timeout, redirects, user agent, and proxy policy.
POLICY_BOUNDARY = "src/outbound_http.rs"


def line_number(source: str, offset: int) -> int:
    return source.count("\n", 0, offset) + 1


def test_module_offset(source: str) -> int | None:
    marker = re.search(r"#\s*\[cfg\(test\)\]\s*\n\s*mod\s+tests\s*\{", source)
    return marker.start() if marker else None


def violations(relative: str, source: str) -> list[str]:
    if relative == POLICY_BOUNDARY:
        return []
    tests_start = test_module_offset(source)
    failures: list[str] = []
    for match in DIRECT_CONSTRUCTION.finditer(source):
        if tests_start is not None and match.start() >= tests_start:
            continue
        failures.append(
            f"{relative}:{line_number(source, match.start())}: "
            "constructs a Reqwest transport outside outbound_http; use a reviewed "
            "external/internal profile and give the client an explicit process owner"
        )
    return failures


def main() -> int:
    unsafe = "fn handle() { let _ = reqwest::Client::new(); }"
    if not violations("src/api/example.rs", unsafe):
        raise AssertionError("HTTP construction detector accepted request-path construction")
    if violations(POLICY_BOUNDARY, unsafe):
        raise AssertionError("HTTP construction detector rejected the policy boundary")

    failures: list[str] = []
    for path in sorted((ROOT / "src").rglob("*.rs")):
        relative = path.relative_to(ROOT).as_posix()
        failures.extend(violations(relative, path.read_text(encoding="utf-8")))
    if failures:
        print("unapproved production Reqwest transport construction:")
        print("\n".join(f"- {failure}" for failure in failures))
        return 1
    print("production Reqwest transports use the reviewed outbound HTTP policy")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
