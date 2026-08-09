# syntax=docker/dockerfile:1.7

FROM rust:1.96-bookworm AS builder
WORKDIR /source
COPY Cargo.toml Cargo.lock ./
RUN --mount=type=cache,id=control-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=control-cargo-git,target=/usr/local/cargo/git,sharing=locked \
    cargo fetch --locked
COPY migrations ./migrations
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
       target/release/control-backup-scheduler /out/

FROM debian:bookworm-slim
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
COPY --from=builder /out/control-backup-scheduler /usr/local/bin/control-backup-scheduler
USER 10001:10001
EXPOSE 8080
CMD ["/usr/local/bin/control-api"]
