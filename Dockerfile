FROM rust:1.96-bookworm AS builder
WORKDIR /source
COPY Cargo.toml Cargo.lock ./
COPY migrations ./migrations
COPY src ./src
RUN cargo build --locked --release --bins

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && rm -rf /var/lib/apt/lists/*
RUN useradd --system --uid 10001 --home /nonexistent control
COPY --from=builder /source/target/release/control-api /usr/local/bin/control-api
COPY --from=builder /source/target/release/control-migrate /usr/local/bin/control-migrate
COPY --from=builder /source/target/release/control-worker /usr/local/bin/control-worker
COPY --from=builder /source/target/release/control-fixture /usr/local/bin/control-fixture
USER 10001:10001
EXPOSE 8080
CMD ["/usr/local/bin/control-api"]
