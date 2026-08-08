.PHONY: check test build configure configure-tunnel compose-config compose-tunnel-config up up-tunnel down down-tunnel
export CARGO_TARGET_DIR ?= /tmp/makersbrain-control-target

check:
	cargo fmt --check
	cargo clippy --locked --all-targets -- -D warnings
	npm --prefix web run check

test:
	cargo test --locked

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
