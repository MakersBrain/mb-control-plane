FROM alpine/git:2.49.1 AS oca
RUN git clone --filter=blob:none --no-checkout --sparse https://github.com/OCA/server-auth.git /server-auth \
 && git -C /server-auth sparse-checkout set auth_oidc \
 && git -C /server-auth checkout f51fe1b36965b78ac935e80c6b95d7115440a1b4

FROM odoo:19
USER root
COPY addons /mnt/makersbrain-addons
COPY --from=oca /server-auth/auth_oidc /mnt/oca-addons/auth_oidc
RUN apt-get update && apt-get install -y --no-install-recommends python3-jose \
 && rm -rf /var/lib/apt/lists/* \
 && chown -R odoo:odoo /mnt/makersbrain-addons /mnt/oca-addons
USER odoo
