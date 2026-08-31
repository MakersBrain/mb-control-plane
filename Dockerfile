# syntax=docker/dockerfile:1.10

FROM ghcr.io/sigstore/cosign/cosign:v3.0.6@sha256:de9c65609e6bde17e6b48de485ee788407c9502fa08b8f4459f595b21f56cd00 AS cosign
FROM ghcr.io/oras-project/oras:v1.3.0@sha256:6ce045ce069a89934d6666b8b49f9c4c0145201bd6de6dbe2aee267814c55468 AS oras

FROM rust:1.98-bookworm@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922 AS builder
WORKDIR /source
ARG TARGETARCH
ARG SCCACHE_VERSION=0.17.0
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && case "$TARGETARCH" in \
         amd64) target=x86_64-unknown-linux-musl; sha256=67c4a96dd237c1f518f6b36083f270f9976d516f1e57fce891755ea782e50006 ;; \
         arm64) target=aarch64-unknown-linux-musl; sha256=821a86343191aa1cbab74bd42f9e93c9a63bf85e4742945f40d3ae84193c1c77 ;; \
         *) echo "unsupported TARGETARCH: $TARGETARCH" >&2; exit 1 ;; \
       esac \
    && archive="sccache-v${SCCACHE_VERSION}-${target}.tar.gz" \
    && curl -fsSLo "/tmp/$archive" \
       "https://github.com/mozilla/sccache/releases/download/v${SCCACHE_VERSION}/$archive" \
    && echo "$sha256  /tmp/$archive" | sha256sum -c - \
    && tar -xzf "/tmp/$archive" --strip-components=1 -C /usr/local/bin \
       "sccache-v${SCCACHE_VERSION}-${target}/sccache" \
    && rm -f "/tmp/$archive" \
    && rm -rf /var/lib/apt/lists/*
ARG RUSTC_WRAPPER
ARG SCCACHE_BUCKET
ARG SCCACHE_ENDPOINT
ARG SCCACHE_REGION=auto
ARG SCCACHE_PREFIX=rust-v1
COPY Cargo.toml Cargo.lock build.rs ./
RUN --mount=type=cache,id=control-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=control-cargo-git,target=/usr/local/cargo/git,sharing=locked \
    cargo fetch --locked
COPY migrations ./migrations
COPY deploy/capability-registry.json deploy/configuration-spec.json ./deploy/
COPY src ./src
RUN --mount=type=secret,id=aws_access_key_id,env=AWS_ACCESS_KEY_ID \
    --mount=type=secret,id=aws_secret_access_key,env=AWS_SECRET_ACCESS_KEY \
    --mount=type=cache,id=control-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=control-cargo-git,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=control-cargo-target,target=/source/target,sharing=locked \
    export RUSTC_WRAPPER SCCACHE_BUCKET SCCACHE_ENDPOINT SCCACHE_REGION \
           SCCACHE_S3_USE_SSL=true SCCACHE_S3_KEY_PREFIX="$SCCACHE_PREFIX" \
           SCCACHE_BASEDIRS=/source:/usr/local/cargo/registry \
    && cargo build --locked --release --bins && \
    mkdir -p /out && \
    cp target/release/control-api \
       target/release/control-migrate \
       target/release/control-worker \
       target/release/control-fixture \
       target/release/control-docker-driver \
       target/release/control-container-driver \
       target/release/control-backup-scheduler \
       target/release/document-extraction-broker \
       target/release/control-extension-helper \
       target/release/control-mail-gateway /out/

FROM scratch AS driver-artifact
COPY --from=builder /out/control-container-driver /control-container-driver

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
COPY --from=builder /out/control-extension-helper /usr/local/bin/control-extension-helper
COPY --from=cosign /ko-app/cosign /usr/local/bin/cosign
COPY --from=oras /bin/oras /usr/local/bin/oras
USER 10001:10001
EXPOSE 8080
CMD ["/usr/local/bin/control-api"]
