#!/usr/bin/env python3
"""Prove recognizable secret canaries never enter rendered Compose output."""

from __future__ import annotations

import json
import re
import subprocess
import tempfile
from pathlib import Path


CONTROL = Path(__file__).resolve().parents[1]
DEPLOY = CONTROL / "deploy"
CANARY_PREFIX = "MB_SECRET_CANARY_DO_NOT_RENDER_"


def canary_environment() -> str:
    specification = json.loads((DEPLOY / "configuration-spec.json").read_text())
    secrets = set(specification["secrets"])
    output: list[str] = []
    for line in (DEPLOY / ".env.example").read_text().splitlines():
        match = re.match(r"^([A-Z][A-Z0-9_]*)=", line)
        if match and match.group(1) in secrets:
            line = f"{match.group(1)}={CANARY_PREFIX}{match.group(1)}"
        elif match and match.group(1) == "PUBLIC_DOMAIN":
            line = "PUBLIC_DOMAIN=dev1.makersbrain.net"
        output.append(line)
    return "\n".join(output) + "\n"


def render(environment: Path, include_tunnel: bool) -> str:
    command = [
        "docker",
        "compose",
        "--env-file",
        str(environment),
        "-f",
        str(DEPLOY / "compose.yml"),
    ]
    if include_tunnel:
        command.extend(["-f", str(DEPLOY / "compose.cloudflare.yml")])
    command.append("config")
    result = subprocess.run(
        command,
        cwd=CONTROL,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout


def main() -> int:
    with tempfile.NamedTemporaryFile("w", prefix="mb-canary-", suffix=".env") as env:
        env.write(canary_environment())
        env.flush()
        for include_tunnel in (False, True):
            rendered = render(Path(env.name), include_tunnel)
            if CANARY_PREFIX in rendered:
                mode = "tunnel" if include_tunnel else "base"
                raise SystemExit(f"secret canary leaked into rendered {mode} Compose output")
    print("rendered Compose models contain no recognizable secret canaries")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
