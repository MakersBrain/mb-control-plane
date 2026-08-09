# syntax=docker/dockerfile:1.7

FROM node:22-bookworm-slim AS builder
WORKDIR /source
COPY package.json package-lock.json ./
RUN --mount=type=cache,id=control-web-npm,target=/root/.npm,sharing=locked \
    npm ci --no-audit --no-fund
COPY . .
ARG VITE_CONTROL_API_URL=""
ARG VITE_OIDC_ISSUER
ARG VITE_OIDC_CLIENT_ID=makersbrain-members
ARG VITE_OIDC_REDIRECT_URI
RUN npm run build && node scripts/externalize-bootstrap.mjs

FROM nginx:1.28-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=builder /source/build /usr/share/nginx/html
EXPOSE 8080
