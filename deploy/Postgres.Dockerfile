# syntax=docker/dockerfile:1.7

FROM postgres:17-alpine@sha256:742f40ea20b9ff2ff31db5458d127452988a2164df9e17441e191f3b72252193

RUN --mount=type=cache,id=control-postgres-apk,target=/var/cache/apk,sharing=locked \
    apk add --no-cache pgbackrest
