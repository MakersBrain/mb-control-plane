.PHONY: check test build topology-secret-check topology-odoo-isolation-check configure configure-tunnel compose-config compose-tunnel-config up up-tunnel down down-tunnel workspace-config up-workspace down-workspace workspace-status purge-workspace workspace-recovery-prepare workspace-recovery-test
export CARGO_TARGET_DIR ?= /tmp/mb-control-target

check:
	cargo fmt --check
	python3 tools/validate_contract.py
	python3 tools/test_compose_secret_canary.py
	python3 tools/test_local_secret_bootstrap.py
	python3 tools/test_dynamic_secret_boundary.py
	python3 tools/test_privacy_deployment_gate.py
	python3 tools/test_topology_odoo_isolation.py --self-test
	python3 tools/test_workspace_configuration.py
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

workspace-config:
	@test -n "$(WORKSPACE)" || { echo 'WORKSPACE is required' >&2; exit 2; }
	./deploy/configure-workspace.sh --workspace "$(WORKSPACE)" --secret-root "$$XDG_RUNTIME_DIR/makersbrain/$(WORKSPACE)/current"

up-workspace: workspace-config
	docker compose --project-name "mb-$(WORKSPACE)" --env-file deploy/.env -f deploy/compose.yml -f deploy/compose.cloudflare.yml -f deploy/compose.workspace.yml up -d --build

down-workspace:
	@test -n "$(WORKSPACE)" || { echo 'WORKSPACE is required' >&2; exit 2; }
	@test -f deploy/.env || { echo 'deploy/.env is missing; run workspace-config' >&2; exit 1; }
	docker compose --project-name "mb-$(WORKSPACE)" --env-file deploy/.env -f deploy/compose.yml -f deploy/compose.cloudflare.yml -f deploy/compose.workspace.yml down

workspace-status:
	@test -n "$(WORKSPACE)" || { echo 'WORKSPACE is required' >&2; exit 2; }
	@test -f deploy/.env || { echo 'deploy/.env is missing; run workspace-config' >&2; exit 1; }
	docker compose --project-name "mb-$(WORKSPACE)" --env-file deploy/.env -f deploy/compose.yml -f deploy/compose.cloudflare.yml -f deploy/compose.workspace.yml ps

purge-workspace:
	@test -n "$(WORKSPACE)" || { echo 'WORKSPACE is required' >&2; exit 2; }
	@test "$(CONFIRM_WORKSPACE)" = "$(WORKSPACE)" || { echo 'CONFIRM_WORKSPACE must exactly match WORKSPACE' >&2; exit 2; }
	./deploy/purge-workspace.sh --workspace "$(WORKSPACE)" --confirm-workspace "$(CONFIRM_WORKSPACE)"

workspace-recovery-prepare:
	@test -n "$(WORKSPACE)" || { echo 'WORKSPACE is required' >&2; exit 2; }
	./tools/workspace_recovery_acceptance.py prepare --workspace "$(WORKSPACE)"

workspace-recovery-test:
	@test -n "$(WORKSPACE)" || { echo 'WORKSPACE is required' >&2; exit 2; }
	./tools/workspace_recovery_acceptance.py seed --workspace "$(WORKSPACE)"
	./tools/workspace_recovery_acceptance.py backup --workspace "$(WORKSPACE)" --new
	./tools/workspace_recovery_acceptance.py rehearse --workspace "$(WORKSPACE)"
	./tools/workspace_recovery_acceptance.py mutate --workspace "$(WORKSPACE)"
	./tools/workspace_recovery_acceptance.py restore --workspace "$(WORKSPACE)"
	./tools/workspace_recovery_acceptance.py verify --workspace "$(WORKSPACE)"
