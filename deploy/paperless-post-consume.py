#!/usr/bin/env python3
import json
import os
import urllib.request


document_id = os.environ.get("DOCUMENT_ID")
if not document_id:
    raise SystemExit("DOCUMENT_ID is missing")
workshop = os.environ["MAKERSBRAIN_WORKSHOP_ID"]
url = os.environ["MAKERSBRAIN_CONTROL_URL"].rstrip("/") + f"/internal/v1/paperless/{workshop}/events"
request = urllib.request.Request(url, data=json.dumps({"document_id": int(document_id)}).encode(), method="POST", headers={"Authorization": "Bearer " + os.environ["PAPERLESS_WEBHOOK_SECRET"], "Content-Type": "application/json"})
with urllib.request.urlopen(request, timeout=10) as response:
    if response.status != 202:
        raise SystemExit(f"control plane returned {response.status}")
