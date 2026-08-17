#!/usr/bin/env python3
"""Build an exact materialization manifest from a rendered runtime bundle."""

from __future__ import annotations

import argparse
import json
import os
import tempfile
from pathlib import Path

import materialize


def staged_files(root: Path, relative: Path) -> list[Path]:
    candidate = root / relative
    if candidate.is_symlink():
        materialize.fail(f"staged path contains a symlink: {relative}")
    if candidate.is_file():
        materialize.regular_source(root, relative)
        return [relative]
    if not candidate.is_dir():
        materialize.fail(f"rendered runtime path is absent from staging: {relative}")
    files: list[Path] = []
    for path in sorted(candidate.rglob("*")):
        child = path.relative_to(root)
        if path.is_symlink():
            materialize.fail(f"staged path contains a symlink: {child}")
        if path.is_file():
            materialize.regular_source(root, child)
            files.append(child)
    if not files:
        materialize.fail(f"rendered secret mount is empty in staging: {relative}")
    return files


def build(source: Path, rendered: Path, generation: str) -> dict[str, object]:
    if not materialize.GENERATION.fullmatch(generation):
        materialize.fail("generation is invalid")
    environment_files, secret_mounts = materialize.rendered_contract(rendered)
    entries: dict[Path, str] = {}
    for relative in sorted(environment_files):
        materialize.regular_source(source, relative)
        entries[relative] = "environment"
    for mount in sorted(secret_mounts):
        for relative in staged_files(source, mount):
            existing = entries.get(relative)
            if existing and existing != "secret":
                materialize.fail(f"runtime path has conflicting file types: {relative}")
            entries[relative] = "secret"

    staged: set[Path] = set()
    for path in sorted(source.rglob("*")):
        relative = path.relative_to(source)
        if path.is_symlink():
            materialize.fail(f"staged path contains a symlink: {relative}")
        if path.is_file():
            materialize.regular_source(source, relative)
            staged.add(relative)
    extras = staged - entries.keys()
    if extras:
        materialize.fail(
            "staging contains files outside rendered runtime mounts: "
            + ", ".join(str(path) for path in sorted(extras))
        )
    return {
        "schema_version": 1,
        "generation": generation,
        "entries": [
            {"source": str(path), "target": str(path), "type": entries[path]}
            for path in sorted(entries)
        ],
    }


def write_atomic(output: Path, document: dict[str, object]) -> None:
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary_raw = tempfile.mkstemp(
        prefix=f".{output.name}.", dir=output.parent
    )
    temporary = Path(temporary_raw)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(document, handle, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        temporary.chmod(0o600)
        os.replace(temporary, output)
        materialize.fsync_directory(output.parent)
    except Exception:
        if temporary.exists():
            temporary.unlink()
        raise


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a value-free manifest for a staged runtime configuration"
    )
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--rendered", required=True, type=Path)
    parser.add_argument("--generation", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    source = args.source.resolve(strict=True)
    if not source.is_dir() or args.source.is_symlink():
        materialize.fail("source must be a real directory")
    document = build(source, args.rendered, args.generation)
    write_atomic(args.output, document)
    print(f"wrote manifest for {args.generation}: {len(document['entries'])} files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
