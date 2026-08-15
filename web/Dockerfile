# syntax=docker/dockerfile:1.7

FROM node:22-bookworm-slim@sha256:d649c27dae7ba0137b3cef5dd75baa422c08dc3d9e3fc0c23dfb172dc3cc6436 AS builder
WORKDIR /source
# .npmrc carries the registry mapping for @makersbrain/brand and no credential.
# The credential arrives as a BuildKit secret mounted only for the length of this
# RUN, so it is never written to a layer and never appears in the pushed image.
COPY package.json package-lock.json .npmrc ./
RUN --mount=type=cache,id=control-web-npm,target=/root/.npm,sharing=locked \
    --mount=type=secret,id=npmrc,target=/root/.npmrc \
    npm ci --no-audit --no-fund
COPY . .
ARG VITE_CONTROL_API_URL=""
ARG VITE_OIDC_ISSUER
ARG VITE_OIDC_CLIENT_ID=makersbrain-members
ARG VITE_OIDC_REDIRECT_URI
ARG VITE_ACCOUNT_URL
RUN npm run build && node scripts/externalize-bootstrap.mjs

FROM nginx:1.28-alpine@sha256:a8b39bd9cf0f83869a2162827a0caf6137ddf759d50a171451b335cecc87d236
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=builder /source/build /usr/share/nginx/html
EXPOSE 8080
