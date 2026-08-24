#!/usr/bin/env python3
"""Reject common structured-log patterns that can expose sensitive values."""

from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TRACING_EVENT = re.compile(
    r"tracing::(?:trace|debug|info|warn|error|event|trace_span|debug_span|info_span|warn_span|error_span|span)!\s*\((.*?)\);",
    re.DOTALL,
)
RAW_ERROR = re.compile(
    r"(?:\berror\s*=\s*[%?]|[%?]\s*error\b|format_args!\s*\(\s*\"\{error)"
)
SENSITIVE_FIELD = re.compile(
    r"\b(?:authorization|body|content|email|headers|hostname|payload|secret|subject|token)\s*="
)
WHOLE_OBJECT_DEBUG = re.compile(r"\?\s*(?:config|headers|payload|request|response)\b")
FALLBACK_OUTPUT = re.compile(r"e?println!\s*\((.*?)\);", re.DOTALL)
RAW_FALLBACK_ERROR = re.compile(r"\{error(?=[:}])")
RAW_RESULT_MAIN = re.compile(
    r"(?:async\s+)?fn\s+main\s*\(\s*\)\s*->\s*(?:anyhow::)?Result\b"
)


def line_number(source: str, offset: int) -> int:
    return source.count("\n", 0, offset) + 1


def test_module_offset(source: str) -> int | None:
    marker = re.search(r"#\s*\[cfg\(test\)\]\s*\n\s*mod\s+tests\s*\{", source)
    return marker.start() if marker else None


def violations(relative: str, source: str) -> list[str]:
    tests_start = test_module_offset(source)
    failures: list[str] = []
    if relative.startswith("src/bin/"):
        for raw_main in RAW_RESULT_MAIN.finditer(source):
            failures.append(
                f"{relative}:{line_number(source, raw_main.start())}: "
                "raw Result-returning main; map startup/runtime failures to bounded classes"
            )
    for event in TRACING_EVENT.finditer(source):
        if tests_start is not None and event.start() >= tests_start:
            continue
        body = event.group(1)
        reasons = []
        if RAW_ERROR.search(body):
            reasons.append("raw error formatting")
        if SENSITIVE_FIELD.search(body):
            reasons.append("sensitive field name")
        if WHOLE_OBJECT_DEBUG.search(body):
            reasons.append("whole-object debug formatting")
        if reasons:
            failures.append(
                f"{relative}:{line_number(source, event.start())}: "
                f"{', '.join(reasons)}; log stable classes and opaque IDs only"
            )
    for output in FALLBACK_OUTPUT.finditer(source):
        if tests_start is not None and output.start() >= tests_start:
            continue
        if RAW_FALLBACK_ERROR.search(output.group(1)):
            failures.append(
                f"{relative}:{line_number(source, output.start())}: "
                "raw error in console fallback; emit a stable startup/shutdown class only"
            )
    return failures


def main() -> int:
    unsafe = 'fn run() { tracing::error!(error = %error, payload = ?body, "failed"); }'
    if len(violations("src/example.rs", unsafe)) != 1:
        raise AssertionError("log-safety detector accepted a sensitive event")
    safe = (
        'fn run() { tracing::error!(operation = %id, '
        'error_class = "database", "failed"); }'
    )
    if violations("src/example.rs", safe):
        raise AssertionError("log-safety detector rejected stable safe fields")
    fallback = 'fn main() { eprintln!("startup failed: {error:#}"); }'
    if len(violations("src/bin/example.rs", fallback)) != 1:
        raise AssertionError("log-safety detector accepted raw fallback error output")
    raw_main = "async fn main() -> anyhow::Result<()> { Ok(()) }"
    if len(violations("src/bin/example.rs", raw_main)) != 1:
        raise AssertionError("log-safety detector accepted a raw Result-returning main")

    failures: list[str] = []
    for path in sorted((ROOT / "src").rglob("*.rs")):
        relative = path.relative_to(ROOT).as_posix()
        failures.extend(violations(relative, path.read_text(encoding="utf-8")))
    if failures:
        print("unsafe structured logging patterns:")
        print("\n".join(f"- {failure}" for failure in failures))
        return 1
    print("structured logs avoid raw errors and sensitive value fields")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
