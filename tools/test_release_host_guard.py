#!/usr/bin/env python3
"""Keep shared-Odoo host authority ahead of durable release admission."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DRIVER = (ROOT / "src/docker_driver.rs").read_text(encoding="utf-8")
GUARD = (ROOT / "src/docker_driver/host_guard.rs").read_text(encoding="utf-8")

required_guard_markers = {
    "libc::O_NOFOLLOW": "the lock file must reject symlink traversal at open",
    "libc::O_CLOEXEC": "the host authority descriptor must not leak into child effects",
    "metadata.nlink() != 1": "hard-linked authority files must be rejected",
    "metadata.uid() != effective_uid()": "the authority owner must be validated",
    "file.try_lock()": "acquisition must be nonblocking and cancellation-safe",
    "tokio::time::sleep(LOCK_RETRY_INTERVAL)": "contention must yield without a blocking task",
    "opened.dev() != named.dev() || opened.ino() != named.ino()": (
        "the open descriptor must still name the validated file"
    ),
}
for marker, message in required_guard_markers.items():
    if marker not in GUARD:
        raise SystemExit(message)

tenant = DRIVER.split("async fn tenant(", 1)[1].split("fn carrier_secret_path(", 1)[0]
guard = tenant.find("SharedOdooHostGuard::acquire")
admission = tenant.find("admit_release_driver_operation(")
finish = tenant.rfind("finish_release_driver_operation(")
if min(guard, admission, finish) < 0 or not guard < admission < finish:
    raise SystemExit(
        "the shared-Odoo host guard must precede release admission and remain scoped through receipt finish"
    )
if "let _shared_odoo_host_guard" not in tenant:
    raise SystemExit("the release handler must retain the RAII guard for its full lexical scope")

print("shared-Odoo release effects use pre-admission cross-process host authority")
