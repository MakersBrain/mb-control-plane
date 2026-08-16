# syntax=docker/dockerfile:1.7

FROM ghcr.io/sigstore/cosign/cosign:v2.5.0@sha256:e82eb6d42ccb6bc048d8d9e5e598e4d5178e1af6c00e54e02c9b0569c5f3ec11 AS cosign

FROM rust:1.96-bookworm@sha256:a339861ae23e9abb272cea45dfafde21760d2ce6577a70f8a926153677902663 AS builder
WORKDIR /source
COPY Cargo.toml Cargo.lock ./
RUN --mount=type=cache,id=control-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=control-cargo-git,target=/usr/local/cargo/git,sharing=locked \
    cargo fetch --locked
COPY migrations ./migrations
COPY deploy/capability-registry-v1.json deploy/capability-registry-v2.json deploy/configuration-spec.json ./deploy/
COPY src ./src
RUN --mount=type=cache,id=control-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=control-cargo-git,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=control-cargo-target,target=/source/target,sharing=locked \
    cargo build --locked --release --bins && \
    mkdir -p /out && \
    cp target/release/control-api \
       target/release/control-migrate \
       target/release/control-worker \
       target/release/control-fixture \
       target/release/control-docker-driver \
       target/release/control-container-driver \
       target/release/control-backup-scheduler \
       target/release/document-extraction-broker \
       target/release/control-mail-gateway /out/

FROM debian:bookworm-slim@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241
RUN --mount=type=cache,id=control-apt-lists,target=/var/lib/apt/lists,sharing=locked \
    --mount=type=cache,id=control-apt-cache,target=/var/cache/apt,sharing=locked \
    rm -f /etc/apt/apt.conf.d/docker-clean && \
    apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates curl
RUN useradd --system --uid 10001 --home /nonexistent control
COPY --from=builder /out/control-api /usr/local/bin/control-api
COPY --from=builder /out/control-migrate /usr/local/bin/control-migrate
COPY --from=builder /out/control-worker /usr/local/bin/control-worker
COPY --from=builder /out/control-fixture /usr/local/bin/control-fixture
COPY --from=builder /out/control-docker-driver /usr/local/bin/control-docker-driver
COPY --from=builder /out/control-container-driver /usr/local/bin/control-container-driver
COPY --from=builder /out/control-backup-scheduler /usr/local/bin/control-backup-scheduler
COPY --from=builder /out/document-extraction-broker /usr/local/bin/document-extraction-broker
COPY --from=builder /out/control-mail-gateway /usr/local/bin/control-mail-gateway
COPY --from=cosign /ko-app/cosign /usr/local/bin/cosign
USER 10001:10001
EXPOSE 8080
CMD ["/usr/local/bin/control-api"]
