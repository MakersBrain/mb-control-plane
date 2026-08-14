.PHONY: check test build topology-secret-check topology-odoo-isolation-check configure configure-tunnel compose-config compose-tunnel-config up up-tunnel down down-tunnel
export CARGO_TARGET_DIR ?= /tmp/makersbrain-control-target

check:
	cargo fmt --check
	python3 tools/validate_contract.py
	python3 tools/test_compose_secret_canary.py
	python3 tools/test_local_secret_bootstrap.py
	python3 tools/test_dynamic_secret_boundary.py
	python3 -m unittest discover -s deploy/podman/tests -v
	sh -ec 'output=$$(mktemp -d); python3 deploy/podman/render.py --values deploy/podman/values.example.json --output "$$output"; python3 deploy/podman/validate.py "$$output"'
	sh -ec 'output=$$(mktemp -d); python3 deploy/podman/database/render.py --values deploy/podman/database/values.example.json --output "$$output"; python3 deploy/podman/database/validate.py "$$output"'
	python3 tools/test_privacy_deployment_gate.py
	python3 tools/test_topology_odoo_isolation.py --self-test
	cargo clippy --locked --all-targets -- -D warnings
	npm --prefix web run check

test:
	cargo test --locked

topology-secret-check:
	./tools/test_docker_secret_subpath.sh

topology-odoo-isolation-check:
	python3 tools/test_topology_odoo_isolation.py

build:
	cargo build --locked --release
	npm --prefix web run build

compose-config:
	docker compose --env-file deploy/.env.example -f deploy/compose.yml config --quiet

compose-tunnel-config:
	PUBLIC_DOMAIN=dev1.makersbrain.net docker compose --env-file deploy/.env.example -f deploy/compose.yml -f deploy/compose.cloudflare.yml config --quiet

configure:
	./deploy/generate-local-config.sh

configure-tunnel: configure
	./deploy/install-tunnel-token.sh

up: configure
	docker compose --env-file deploy/.env -f deploy/compose.yml up -d --build

up-tunnel: configure-tunnel
	docker compose --env-file deploy/.env -f deploy/compose.yml -f deploy/compose.cloudflare.yml up -d --build

down:
	docker compose --env-file deploy/.env -f deploy/compose.yml down

down-tunnel:
	docker compose --env-file deploy/.env -f deploy/compose.yml -f deploy/compose.cloudflare.yml down
