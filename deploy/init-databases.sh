#!/bin/sh
set -eu
psql --set=ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  --set=control_password="$CONTROL_POSTGRES_PASSWORD" \
  --set=rauthy_password="$RAUTHY_POSTGRES_PASSWORD" \
  --set=paperless_password="$PAPERLESS_POSTGRES_PASSWORD" \
  --set=odoo_password="$ODOO_POSTGRES_PASSWORD" <<'SQL'
create role control login password :'control_password';
create role rauthy login password :'rauthy_password';
create role paperless login password :'paperless_password';
create role odoo login createdb password :'odoo_password';
create database makersbrain_control owner control;
create database rauthy owner rauthy;
create database paperless owner paperless;
revoke all on database makersbrain_control from public;
revoke all on database rauthy from public;
revoke all on database paperless from public;
SQL
