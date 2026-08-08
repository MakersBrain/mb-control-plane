FROM ghcr.io/paperless-ngx/paperless-ngx:2.20.15

COPY --chown=paperless:paperless paperless-post-consume.py /usr/src/paperless/post-consume.py
