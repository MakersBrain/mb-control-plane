# ADR 0005: Docker is a development-only deployment driver

Status: accepted

The local Docker driver is privileged and mounts the Docker daemon socket. It
is restricted to loopback development networks and is not an acceptable
production boundary.

Production uses an authenticated Podman/systemd service owned by the
infrastructure repository. It implements the same idempotent, fenced driver
contract using narrowly scoped host identities. Promotion is blocked until the
production driver passes topology, secret-isolation and recovery tests without
a Docker socket.
