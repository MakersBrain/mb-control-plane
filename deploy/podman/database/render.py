#!/usr/bin/env python3
"""Render the isolated rootless PostgreSQL host bundle."""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import shutil
from pathlib import Path


HERE = Path(__file__).resolve().parent
IMAGE = re.compile(r"^[^\s]+@sha256:[a-f0-9]{64}$")
RFC1918 = tuple(
    ipaddress.ip_network(cidr) for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)


def load_values(path: Path) -> dict:
    values = json.loads(path.read_text(encoding="utf-8"))
    if values.get("environment") not in {"staging", "production"}:
        raise ValueError("environment must be staging or production")
    image = values.get("postgres_image", "")
    if not IMAGE.fullmatch(image):
        raise ValueError("postgres_image is not pinned by digest")
    bind_ip = ipaddress.ip_address(values.get("private_bind_ip", ""))
    if bind_ip.version != 4 or not any(bind_ip in network for network in RFC1918):
        raise ValueError("private_bind_ip must be a private non-loopback IPv4 address")
    client_network = ipaddress.ip_network(values.get("app_subnet_cidr", ""), strict=True)
    if client_network.version != 4 or not any(
        client_network.subnet_of(network) for network in RFC1918
    ):
        raise ValueError("app_subnet_cidr must be a private IPv4 network")
    data = Path(values.get("data_directory", ""))
    if data != Path("/var/lib/makersbrain/postgresql/data"):
        raise ValueError("data_directory must use the protected database volume")
    return values


def render(values_path: Path, output: Path) -> None:
    values = load_values(values_path)
    if output.exists() and any(output.iterdir()):
        raise ValueError("output directory must be absent or empty")
    output.mkdir(parents=True, exist_ok=True)
    tokens = {
        "POSTGRES_IMAGE": values["postgres_image"],
        "PRIVATE_BIND_IP": values["private_bind_ip"],
        "APP_SUBNET_CIDR": values["app_subnet_cidr"],
        "DATA_DIRECTORY": values["data_directory"],
    }
    for source_root in (HERE / "quadlets", HERE / "assets", HERE / "systemd"):
        for source in sorted(path for path in source_root.rglob("*") if path.is_file()):
            target = output / source.relative_to(source_root)
            content = source.read_text(encoding="utf-8")
            for key, value in tokens.items():
                content = content.replace(f"@@{key}@@", value)
            if "@@" in content:
                raise ValueError(f"unresolved template value in {source.name}")
            target.write_text(content, encoding="utf-8")
            target.chmod(0o644)
    shutil.copy2(HERE.parent.parent / "init-databases.sh", output / "init-databases.sh")
    (output / "init-databases.sh").chmod(0o555)
    shutil.copy2(HERE / "restore.py", output / "restore.py")
    (output / "restore.py").chmod(0o555)
    shutil.copy2(HERE / "write-fence.py", output / "write-fence.py")
    (output / "write-fence.py").chmod(0o555)
    shutil.copy2(values_path, output / "rendered-values.json")
    (output / "rendered-values.json").chmod(0o600)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--values", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    render(args.values, args.output)


if __name__ == "__main__":
    main()
