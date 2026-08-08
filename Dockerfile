FROM rust:1.96-bookworm AS builder
WORKDIR /source
COPY Cargo.toml Cargo.lock ./
COPY migrations ./migrations
COPY src ./src
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/source/target \
    cargo build --locked --release --bins && \
    mkdir -p /out && \
    cp target/release/control-api \
       target/release/control-migrate \
       target/release/control-worker \
       target/release/control-fixture \
       target/release/control-docker-driver /out/

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && rm -rf /var/lib/apt/lists/*
RUN useradd --system --uid 10001 --home /nonexistent control
COPY --from=builder /out/control-api /usr/local/bin/control-api
COPY --from=builder /out/control-migrate /usr/local/bin/control-migrate
COPY --from=builder /out/control-worker /usr/local/bin/control-worker
COPY --from=builder /out/control-fixture /usr/local/bin/control-fixture
COPY --from=builder /out/control-docker-driver /usr/local/bin/control-docker-driver
USER 10001:10001
EXPOSE 8080
CMD ["/usr/local/bin/control-api"]
