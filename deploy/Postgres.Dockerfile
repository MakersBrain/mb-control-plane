# syntax=docker/dockerfile:1.7

FROM golang:1.25.7-alpine@sha256:f6751d823c26342f9506c03797d2527668d095b0a15f1862cddb4d927a7a4ced AS gosu
WORKDIR /source
ADD --checksum=sha256:33d7537d588ea49458b9509bcf4554bdf5ceacc66da71e5caa1058ea3b689c3b \
    https://github.com/tianon/gosu/archive/6456aaa0f3c854d199d0f037f068eb97515b7513.tar.gz /tmp/gosu.tar.gz
RUN tar -xzf /tmp/gosu.tar.gz --strip-components=1 -C /source && \
    CGO_ENABLED=0 go build -buildvcs=false -trimpath -ldflags '-d -w' -o /gosu .

FROM postgres:17-alpine@sha256:742f40ea20b9ff2ff31db5458d127452988a2164df9e17441e191f3b72252193

COPY --from=gosu /gosu /usr/local/bin/gosu
RUN --mount=type=cache,id=control-postgres-apk,target=/var/cache/apk,sharing=locked \
    apk add --no-cache pgbackrest
