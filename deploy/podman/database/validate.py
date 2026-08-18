#!/usr/bin/env python3
"""Validate a rendered MakersBrain PostgreSQL host bundle."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path


IMAGE = re.compile(r"^Image=\S+@sha256:[a-f0-9]{64}$", re.MULTILINE)


def validate(root: Path) -> None:
    expected = {
        "postgres.container", "pg_hba.conf", "init-databases.sh", "rendered-values.json",
        "postgres-recovery-init.service", "postgres-backup.service", "postgres-backup.timer",
        "postgres-full-backup.service", "postgres-full-backup.timer", "restore.py",
        "write-fence.py",
    }
    missing = expected - {path.name for path in root.iterdir()}
    if missing:
        raise ValueError(f"database bundle is incomplete: {', '.join(sorted(missing))}")
    unit = (root / "postgres.container").read_text(encoding="utf-8")
    hba = (root / "pg_hba.conf").read_text(encoding="utf-8")
    values = json.loads((root / "rendered-values.json").read_text(encoding="utf-8"))
    if not IMAGE.search(unit):
        raise ValueError("PostgreSQL image is not digest-pinned")
    if "docker.sock" in unit or "podman.sock" in unit or "tcp://" in unit:
        raise ValueError("database unit contains a forbidden runtime socket")
    if (
        "DropCapability=all" not in unit
        or "User=70:70" not in unit
        or "UserNS=keep-id:uid=70,gid=70" not in unit
        or "AddCapability=" in unit
    ):
        raise ValueError("database unit must run rootless as PostgreSQL with no capabilities")
    if "ssl=on" not in unit or "postgres_tls_private_key" not in unit:
        raise ValueError("database TLS is not fail-closed")
    if (
        "Secret=postgres_superuser_password,target=postgres_superuser_password,"
        "uid=70,gid=70,mode=0400"
    ) not in unit:
        raise ValueError("PostgreSQL bootstrap secret is not scoped to the runtime user")
    if (
        "archive_mode=on" not in unit
        or "archive-push" not in unit
        or "pgbackrest_config" not in unit
    ):
        raise ValueError("continuous encrypted WAL recovery is not configured")
    recovery = (root / "postgres-recovery-init.service").read_text(encoding="utf-8")
    if (
        "stanza-create" not in recovery
        or "pgbackrest --stanza=makersbrain check" not in recovery
        or recovery.count("exec --user 70:70") != 2
        or "JobRunningTimeoutSec=180" not in recovery
    ):
        raise ValueError("PostgreSQL recovery repository is not initialized and checked")
    incremental = (root / "postgres-backup.service").read_text()
    if "--type=incr backup" not in incremental or "exec --user 70:70" not in incremental:
        raise ValueError("incremental PostgreSQL backup is missing")
    full = (root / "postgres-full-backup.service").read_text()
    if "--type=full backup" not in full or "exec --user 70:70" not in full:
        raise ValueError("full PostgreSQL backup is missing")
    restore = (root / "restore.py").read_text(encoding="utf-8")
    if "isolated_restore" not in restore or "--pg1-path=/restore" not in restore:
        raise ValueError("isolated PostgreSQL restore drill is missing")
    fence = (root / "write-fence.py").read_text(encoding="utf-8")
    if "default_transaction_read_only" not in fence or "pg_terminate_backend" not in fence:
        raise ValueError("database write fence is missing or does not terminate old sessions")
    if f"hostssl all all {values['app_subnet_cidr']} scram-sha-256" not in hba:
        raise ValueError("pg_hba does not restrict clients to the application subnet")
    if not hba.startswith("local all postgres peer\nlocal all all scram-sha-256\n"):
        raise ValueError("local PostgreSQL administration must use exact-user peer auth")
    if "hostnossl all all 0.0.0.0/0 reject" not in hba:
        raise ValueError("unencrypted PostgreSQL clients are not rejected")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: validate.py RENDERED_DATABASE_BUNDLE")
    validate(Path(sys.argv[1]))
    print("rendered rootless PostgreSQL bundle is valid")
