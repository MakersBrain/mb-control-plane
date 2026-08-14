#!/usr/bin/env python3
import json
import os
import urllib.request


def secret(name):
    direct = os.environ.get(name)
    path = os.environ.get(name + "_FILE")
    if bool(direct) == bool(path):
        raise SystemExit(f"exactly one of {name} and {name}_FILE is required")
    if direct:
        return direct
    with open(path, "r", encoding="utf-8") as handle:
        value = handle.read(65537)
    if len(value) > 65536 or "\n" in value.rstrip("\n") or "\r" in value.rstrip("\r\n"):
        raise SystemExit(f"{name}_FILE is not a bounded one-line secret")
    value = value.rstrip("\r\n")
    if not value:
        raise SystemExit(f"{name}_FILE is empty")
    return value


document_id = os.environ.get("DOCUMENT_ID")
if not document_id:
    raise SystemExit("DOCUMENT_ID is missing")
workshop = os.environ["MAKERSBRAIN_WORKSHOP_ID"]
url = os.environ["MAKERSBRAIN_CONTROL_URL"].rstrip("/") + f"/internal/v1/paperless/{workshop}/events"
request = urllib.request.Request(url, data=json.dumps({"document_id": int(document_id)}).encode(), method="POST", headers={"Authorization": "Bearer " + secret("PAPERLESS_WEBHOOK_SECRET"), "Content-Type": "application/json"})
with urllib.request.urlopen(request, timeout=10) as response:
    if response.status != 202:
        raise SystemExit(f"control plane returned {response.status}")
