#!/usr/bin/env python3
"""Materialize a scoped runtime configuration tree as an immutable generation."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import tempfile
from pathlib import Path, PurePosixPath


GENERATION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
ENVIRONMENT_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
MODES = {"environment": 0o400, "secret": 0o600, "public": 0o644}
MAX_FILE_SIZE = 1024 * 1024


def fail(message: str) -> None:
    raise ValueError(message)


def relative_path(raw: object, field: str) -> Path:
    if not isinstance(raw, str) or not raw:
        fail(f"{field} must be a non-empty relative path")
    candidate = PurePosixPath(raw)
    if candidate.is_absolute() or ".." in candidate.parts or "." in candidate.parts:
        fail(f"{field} must be a normalized relative path")
    if any(not part or part in {".", ".."} for part in candidate.parts):
        fail(f"{field} must be a normalized relative path")
    return Path(*candidate.parts)


def regular_source(root: Path, relative: Path) -> Path:
    path = root / relative
    try:
        path.relative_to(root)
    except ValueError:
        fail(f"source escapes its root: {relative}")
    cursor = root
    for component in relative.parts:
        cursor = cursor / component
        if cursor.is_symlink():
            fail(f"source path contains a symlink: {relative}")
    if not path.is_file():
        fail(f"source must be a regular, non-symlink file: {relative}")
    if path.stat().st_size > MAX_FILE_SIZE:
        fail(f"source exceeds {MAX_FILE_SIZE} bytes: {relative}")
    return path


def validate_environment(data: bytes, relative: Path) -> None:
    if b"\0" in data or b"\r" in data:
        fail(f"environment file contains a forbidden byte: {relative}")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        fail(f"environment file is not UTF-8: {relative}")
    for number, line in enumerate(text.splitlines(), 1):
        if not line or line.startswith("#"):
            continue
        key, separator, _value = line.partition("=")
        if not separator or not ENVIRONMENT_KEY.fullmatch(key):
            fail(f"invalid environment assignment at {relative}:{number}")


def load_manifest(path: Path) -> tuple[str, list[dict[str, object]]]:
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict) or document.get("schema_version") != 1:
        fail("manifest schema_version must be 1")
    generation = document.get("generation")
    if not isinstance(generation, str) or not GENERATION.fullmatch(generation):
        fail("manifest generation is invalid")
    entries = document.get("entries")
    if not isinstance(entries, list) or not entries:
        fail("manifest entries must be a non-empty array")
    return generation, entries


def validate_entries(source_root: Path, entries: list[dict[str, object]]) -> list[tuple[Path, Path, str, bytes]]:
    validated: list[tuple[Path, Path, str, bytes]] = []
    targets: set[Path] = set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict) or set(entry) != {"source", "target", "type"}:
            fail(f"entry {index} must contain only source, target and type")
        source_relative = relative_path(entry["source"], f"entry {index} source")
        target_relative = relative_path(entry["target"], f"entry {index} target")
        kind = entry["type"]
        if kind not in MODES:
            fail(f"entry {index} type must be environment, secret or public")
        if target_relative in targets:
            fail(f"duplicate target: {target_relative}")
        targets.add(target_relative)
        source = regular_source(source_root, source_relative)
        data = source.read_bytes()
        if not data:
            fail(f"source is empty: {source_relative}")
        if kind == "environment":
            validate_environment(data, source_relative)
        validated.append((source, target_relative, str(kind), data))
    return validated


def rendered_contract(rendered: Path) -> tuple[set[Path], set[Path]]:
    if not rendered.is_dir() or rendered.is_symlink():
        fail("rendered bundle must be a real directory")
    environment_files: set[Path] = set()
    secret_mounts: set[Path] = set()
    for unit in sorted(rendered.glob("*.container")):
        instance = ""
        match = re.fullmatch(r"control-workers@([a-z-]+)\.container", unit.name)
        if match:
            instance = match.group(1)
        for line in unit.read_text(encoding="utf-8").splitlines():
            if line.startswith("EnvironmentFile="):
                raw = line.removeprefix("EnvironmentFile=").replace("%i", instance)
                try:
                    environment_files.add(Path(raw).relative_to("/etc/makersbrain"))
                except ValueError:
                    continue
            if line.startswith("Volume="):
                raw = line.removeprefix("Volume=").replace("%i", instance)
                source = Path(raw.partition(":")[0])
                try:
                    relative = source.relative_to("/etc/makersbrain")
                except ValueError:
                    continue
                # Every file or directory mounted from the immutable runtime
                # generation must be covered by the manifest. Rauthy's
                # bootstrap directory intentionally lives outside `secrets/`
                # because it mixes public client metadata with API-key
                # material, but the whole directory remains mode 0700/0600.
                secret_mounts.add(relative)
    if not environment_files:
        fail("rendered bundle declares no /etc/makersbrain environment files")
    if not secret_mounts:
        fail("rendered bundle declares no /etc/makersbrain secret mounts")
    return environment_files, secret_mounts


def validate_rendered_coverage(
    rendered: Path, entries: list[tuple[Path, Path, str, bytes]]
) -> None:
    environment_files, secret_mounts = rendered_contract(rendered)
    targets = {target: kind for _source, target, kind, _data in entries}
    missing_environment = environment_files - targets.keys()
    if missing_environment:
        fail(
            "manifest omits rendered environment files: "
            + ", ".join(str(path) for path in sorted(missing_environment))
        )
    wrong_environment = sorted(
        path for path in environment_files if targets[path] != "environment"
    )
    if wrong_environment:
        fail(
            "rendered environment files have the wrong type: "
            + ", ".join(str(path) for path in wrong_environment)
        )

    mounted_targets: set[Path] = set()
    empty_mounts: list[Path] = []
    for mount in secret_mounts:
        covered = {
            target
            for target, kind in targets.items()
            if kind == "secret" and (target == mount or mount in target.parents)
        }
        if not covered:
            empty_mounts.append(mount)
        mounted_targets.update(covered)
    if empty_mounts:
        fail(
            "manifest leaves rendered secret mounts empty: "
            + ", ".join(str(path) for path in sorted(empty_mounts))
        )

    permitted = environment_files | mounted_targets
    extras = set(targets) - permitted
    if extras:
        fail(
            "manifest contains files outside rendered runtime mounts: "
            + ", ".join(str(path) for path in sorted(extras))
        )


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def install_generation(
    generation_root: Path,
    current_link: Path,
    generation: str,
    entries: list[tuple[Path, Path, str, bytes]],
    uid: int,
    gid: int,
) -> Path:
    generation_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if generation_root.is_symlink() or not generation_root.is_dir():
        fail("generation root must be a real directory")
    os.chmod(generation_root, 0o700)
    os.chown(generation_root, uid, gid)

    destination = generation_root / generation
    if destination.exists() or destination.is_symlink():
        fail(f"generation already exists: {generation}")
    # Refuse before installing anything, not at the cutover. The first run on a
    # host still carrying the old layout finds a real directory where the
    # generation symlink belongs; discovering that after the generation is in
    # place leaves it installed but unreferenced, with no way back but by hand.
    if current_link.exists() and not current_link.is_symlink():
        fail(
            f"{current_link} is a {'directory' if current_link.is_dir() else 'file'}, "
            "not a generation symlink: move the old layout aside before materializing"
        )
    temporary = Path(tempfile.mkdtemp(prefix=f".{generation}.", dir=generation_root))
    os.chmod(temporary, 0o700)
    os.chown(temporary, uid, gid)
    try:
        for _source, relative, kind, data in entries:
            target = temporary / relative
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            for parent in (target.parent, *target.parent.parents):
                if parent == generation_root.parent:
                    break
                if parent == generation_root:
                    break
                os.chmod(parent, 0o700)
                os.chown(parent, uid, gid)
            descriptor = os.open(
                target,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                MODES[kind],
            )
            try:
                written = 0
                while written < len(data):
                    written += os.write(descriptor, data[written:])
                os.fchmod(descriptor, MODES[kind])
                os.fchown(descriptor, uid, gid)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        for directory, _subdirectories, _files in os.walk(temporary, topdown=False):
            fsync_directory(Path(directory))
        os.rename(temporary, destination)
        fsync_directory(generation_root)

        current_link.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        link_temporary = current_link.with_name(f".{current_link.name}.{os.getpid()}.tmp")
        if link_temporary.exists() or link_temporary.is_symlink():
            link_temporary.unlink()
        os.symlink(destination, link_temporary)
        os.replace(link_temporary, current_link)
        fsync_directory(current_link.parent)
        return destination
    except Exception:
        if temporary.exists():
            shutil.rmtree(temporary)
        # The staging tree is gone by cutover time, so clean up the half-written
        # link too rather than leaving a stray .tmp symlink behind.
        link_temporary = current_link.with_name(f".{current_link.name}.{os.getpid()}.tmp")
        if link_temporary.is_symlink() or link_temporary.exists():
            link_temporary.unlink()
        raise


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Install a staged secret/configuration tree without exposing values on the command line"
    )
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--rendered", required=True, type=Path)
    parser.add_argument("--generation-root", required=True, type=Path)
    parser.add_argument("--current-link", required=True, type=Path)
    parser.add_argument("--uid", type=int, default=os.getuid())
    parser.add_argument("--gid", type=int, default=os.getgid())
    parser.add_argument("--check", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.uid < 0 or args.gid < 0:
        fail("uid and gid must be non-negative numeric identifiers")
    source = args.source.resolve(strict=True)
    if not source.is_dir() or args.source.is_symlink():
        fail("source must be a real directory")
    generation, raw_entries = load_manifest(args.manifest)
    entries = validate_entries(source, raw_entries)
    validate_rendered_coverage(args.rendered, entries)
    if args.check:
        print(f"validated generation {generation}: {len(entries)} files")
        return 0
    destination = install_generation(
        args.generation_root,
        args.current_link,
        generation,
        entries,
        args.uid,
        args.gid,
    )
    print(f"activated generation {destination.name}: {len(entries)} files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
