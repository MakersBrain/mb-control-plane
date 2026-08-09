# syntax=docker/dockerfile:1.7

FROM alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce

RUN --mount=type=cache,id=control-backup-apk,target=/var/cache/apk,sharing=locked \
    apk add --no-cache age aws-cli postgresql17-client tar zstd

RUN adduser -S -u 10001 backup

USER 10001:10001
ENTRYPOINT []
CMD ["sh"]
