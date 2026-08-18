# syntax=docker/dockerfile:1.7

FROM ghcr.io/paperless-ngx/paperless-ngx:3.0.5@sha256:65a4cabf0169ea7fbd90ab7bb28ba3f8b5909613635acda1a03ad606f34b456b

COPY --chown=paperless:paperless paperless-post-consume.py /usr/src/paperless/post-consume.py
