#!/usr/bin/env python3
"""Keep direct environment reads inside reviewed configuration boundaries."""

from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DIRECT_READ = re.compile(r"(?:std::)?env::(?:var|var_os)\s*\(\s*([^\)]+)\)")
STATIC_NAME = re.compile(r'^"([A-Z][A-Z0-9_]*)"$')

# These modules are themselves configuration/runtime convention boundaries.
BOUNDARY_FILES = {
    "src/config.rs",
    "src/runtime_secret.rs",
    "src/telemetry.rs",
}

# These reads belong to narrowly documented process conventions or existing
# typed configuration constructors in otherwise large modules.
ALLOWED_STATIC_READS = {
    ("src/docker_driver.rs", "DRIVER_PUBLIC_PORT"),
    ("src/docker_driver.rs", "DRIVER_PAPERLESS_IMAGE"),
    ("src/bin/control-container-driver.rs", "LISTEN_PID"),
    ("src/bin/control-container-driver.rs", "LISTEN_FDS"),
}


def line_number(source: str, offset: int) -> int:
    return source.count("\n", 0, offset) + 1


def test_module_offset(source: str) -> int | None:
    marker = re.search(r"#\s*\[cfg\(test\)\]\s*\n\s*mod\s+tests\s*\{", source)
    return marker.start() if marker else None


def violations(relative: str, source: str) -> list[str]:
    if relative in BOUNDARY_FILES:
        return []
    tests_start = test_module_offset(source)
    failures: list[str] = []
    for match in DIRECT_READ.finditer(source):
        if tests_start is not None and match.start() >= tests_start:
            continue
        argument = match.group(1).strip()
        static = STATIC_NAME.fullmatch(argument)
        if static and (relative, static.group(1)) in ALLOWED_STATIC_READS:
            continue
        rendered = static.group(1) if static else argument
        failures.append(
            f"{relative}:{line_number(source, match.start())}: "
            f"direct environment read for {rendered}; use a typed loader or runtime_secret"
        )
    return failures


def main() -> int:
    unsafe = 'fn handle() { let _ = std::env::var("LATE_CONFIGURATION"); }'
    if not violations("src/api/example.rs", unsafe):
        raise AssertionError("environment-access detector accepted an application-path read")
    if violations("src/config.rs", unsafe):
        raise AssertionError("environment-access detector rejected a configuration boundary")

    failures: list[str] = []
    for path in sorted((ROOT / "src").rglob("*.rs")):
        relative = path.relative_to(ROOT).as_posix()
        failures.extend(violations(relative, path.read_text(encoding="utf-8")))
    if failures:
        print("unapproved direct environment reads:")
        print("\n".join(f"- {failure}" for failure in failures))
        return 1
    print("direct environment reads stay inside reviewed configuration boundaries")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
