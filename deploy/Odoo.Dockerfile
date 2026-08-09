# syntax=docker/dockerfile:1.7

FROM alpine/git:2.49.1 AS oca
RUN git clone --filter=blob:none --no-checkout --sparse https://github.com/OCA/server-auth.git /server-auth \
 && git -C /server-auth sparse-checkout set auth_oidc \
 && git -C /server-auth checkout f51fe1b36965b78ac935e80c6b95d7115440a1b4

FROM odoo:19
USER root
RUN --mount=type=cache,id=odoo-apt-lists,target=/var/lib/apt/lists,sharing=locked \
    --mount=type=cache,id=odoo-apt-cache,target=/var/cache/apt,sharing=locked \
    rm -f /etc/apt/apt.conf.d/docker-clean && \
    apt-get update && \
    apt-get install -y --no-install-recommends python3-jose
COPY --chown=odoo:odoo addons /mnt/makersbrain-addons
COPY --chown=odoo:odoo --from=oca /server-auth/auth_oidc /mnt/oca-addons/auth_oidc
USER odoo
