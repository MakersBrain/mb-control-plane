#!/usr/bin/env python3
"""Black-box two-workshop Odoo routing and credential isolation gate."""

from __future__ import annotations

import argparse
import json
import os
import stat
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HEALTH_PATH = "/mb_control/v1/health"


@dataclass(frozen=True)
class Tenant:
    host: str
    workshop: str
    database: str
    token: str


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, url):
        return None


def health(origin: str, tenant: Tenant, forged_database: str) -> tuple[int, dict]:
    request = urllib.request.Request(
        f"{origin.rstrip('/')}{HEALTH_PATH}",
        headers={
            "Authorization": f"Bearer {tenant.token}",
            "Host": tenant.host,
            "X-Odoo-Dbfilter": forged_database,
        },
    )
    try:
        with urllib.request.build_opener(NoRedirect).open(request, timeout=10) as response:
            body = response.read(64 * 1024)
            return response.status, json.loads(body)
    except urllib.error.HTTPError as error:
        error.read(64 * 1024)
        return error.code, {}


def assert_isolated(origin: str, first: Tenant, second: Tenant) -> None:
    for current, other in [(first, second), (second, first)]:
        status, body = health(origin, current, other.database)
        if status != 200:
            raise AssertionError(f"correct credential for {current.host} returned {status}")
        if body.get("status") != "ready":
            raise AssertionError(f"{current.host} is not ready")
        if body.get("database") != current.database:
            raise AssertionError(f"forged database header escaped host mapping for {current.host}")
        if body.get("workshop_id") != current.workshop:
            raise AssertionError(f"host mapping selected another workshop for {current.host}")

        wrong_credential = Tenant(
            host=current.host,
            workshop=current.workshop,
            database=current.database,
            token=other.token,
        )
        wrong_status, _ = health(origin, wrong_credential, current.database)
        if wrong_status not in {401, 403}:
            raise AssertionError(
                f"credential from another workshop was not rejected for {current.host}"
            )

    unknown = Tenant(
        host="unregistered.invalid",
        workshop=first.workshop,
        database=first.database,
        token=first.token,
    )
    unknown_status, _ = health(origin, unknown, second.database)
    if unknown_status not in {404, 421}:
        raise AssertionError("an unregistered host reached a tenant route")


def token_file(variable: str) -> str:
    value = os.environ.get(variable, "")
    path = Path(value)
    if not path.is_absolute() or not path.is_file() or path.is_symlink():
        raise SystemExit(f"{variable} must name an absolute regular secret file")
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o037:
        raise SystemExit(f"{variable} must not be accessible to group/other")
    token = path.read_text(encoding="utf-8").strip()
    if not 48 <= len(token) <= 128 or not token.isalnum():
        raise SystemExit(f"{variable} contains an invalid tenant credential")
    return token


def configured_tenants() -> tuple[str, Tenant, Tenant]:
    required = [
        "CONTROL_TOPOLOGY_GATEWAY_ORIGIN",
        "CONTROL_TOPOLOGY_A_HOST",
        "CONTROL_TOPOLOGY_A_WORKSHOP",
        "CONTROL_TOPOLOGY_A_DATABASE",
        "CONTROL_TOPOLOGY_B_HOST",
        "CONTROL_TOPOLOGY_B_WORKSHOP",
        "CONTROL_TOPOLOGY_B_DATABASE",
    ]
    missing = [name for name in required if not os.environ.get(name)]
    if missing:
        raise SystemExit(f"missing topology variables: {', '.join(missing)}")
    origin = os.environ["CONTROL_TOPOLOGY_GATEWAY_ORIGIN"]
    first = Tenant(
        os.environ["CONTROL_TOPOLOGY_A_HOST"],
        os.environ["CONTROL_TOPOLOGY_A_WORKSHOP"],
        os.environ["CONTROL_TOPOLOGY_A_DATABASE"],
        token_file("CONTROL_TOPOLOGY_A_TOKEN_FILE"),
    )
    second = Tenant(
        os.environ["CONTROL_TOPOLOGY_B_HOST"],
        os.environ["CONTROL_TOPOLOGY_B_WORKSHOP"],
        os.environ["CONTROL_TOPOLOGY_B_DATABASE"],
        token_file("CONTROL_TOPOLOGY_B_TOKEN_FILE"),
    )
    if (
        first.host == second.host
        or first.workshop == second.workshop
        or first.database == second.database
    ):
        raise SystemExit("topology fixtures must use distinct hosts, workshops and databases")
    if first.token == second.token:
        raise SystemExit("topology fixtures share one tenant credential")
    return origin, first, second


def self_test() -> None:
    first = Tenant("one.example.test", "workshop-one", "mb_one", "A" * 64)
    second = Tenant("two.example.test", "workshop-two", "mb_two", "B" * 64)
    tenants = {first.host: first, second.host: second}

    class Fixture(BaseHTTPRequestHandler):
        def do_GET(self):
            tenant = tenants.get(self.headers.get("Host", ""))
            supplied = self.headers.get("Authorization", "").removeprefix("Bearer ")
            if self.path != HEALTH_PATH or tenant is None:
                self.send_error(404)
                return
            if supplied != tenant.token:
                self.send_error(401)
                return
            body = json.dumps(
                {"status": "ready", "database": tenant.database, "workshop_id": tenant.workshop}
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        assert_isolated(f"http://127.0.0.1:{server.server_port}", first, second)
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    arguments = parser.parse_args()
    if arguments.self_test:
        self_test()
        print("Odoo topology isolation harness passed its self-test")
        return
    assert_isolated(*configured_tenants())
    print("two-workshop Odoo host, database and credential isolation passed")


if __name__ == "__main__":
    main()
