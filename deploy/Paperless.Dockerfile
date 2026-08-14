# syntax=docker/dockerfile:1.7

FROM ghcr.io/paperless-ngx/paperless-ngx:2.20.15@sha256:6c86cad803970ea782683a8e80e7403444c5bf3cf70de63b4d3c8e87500db92f

COPY --chown=paperless:paperless paperless-post-consume.py /usr/src/paperless/post-consume.py
