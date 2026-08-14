# ADR 0002: Explicit tenant release adoption

Status: accepted

An immutable signed application-release manifest identifies the Odoo image by
digest, source commit, addon versions, required control-schema range and
rollback class. Every tenant records desired, prepared, applied and verified
release state independently.

Upgrade work runs as durable, fenced, one-tenant operations. A prepared runtime
slot cannot receive routed traffic until every tenant assigned to that slot is
verified. A failed tenant remains isolated and cannot cause fleet activation.
Class C releases recover forward or from a verified tenant recovery point; they
are never represented as ordinary image rollback.
