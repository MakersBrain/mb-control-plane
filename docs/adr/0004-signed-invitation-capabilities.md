# ADR 0004: Asymmetrically signed invitation capabilities

Status: accepted

Invitation links use compact Ed25519 JWS capabilities containing only the
invitation identifier, generation and bounded time claims. PostgreSQL stores no
capability. Generation-pinned outbox events are signed in email-worker memory;
the API receives overlapping public verification keys but no private key.

Links carry the token in a URL fragment. The acceptance page removes it before
network activity and submits it only in POST bodies with no-store and
no-referrer policies. Rotation retains old signing keys only while queued events
reference them and old public keys until all issued capabilities have expired.
