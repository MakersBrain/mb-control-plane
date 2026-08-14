# Failed release adoption

1. Keep the fleet activation fence in place and inspect the release matrix.
   Do not activate the candidate while any routed tenant is incompatible.
2. Identify the failed tenant phase and its tenant-specific verified recovery
   point. Never reuse the canary recovery point for another tenant.
3. For class A, a retained runtime switch is sufficient only when no database
   mutation occurred. For class B, require the manifest's exact directional
   read/write compatibility and two-image verification. Class C requires
   forward repair or verified restore.
4. If the gateway action outcome is unknown, observe the active configuration
   digest before issuing the same stable action ID again.
5. Re-enable route, cron, and long-poll processing only after the database and
   selected runtime are proven compatible.
6. Retain the manifest, signature/provenance result, recovery evidence,
   activation digest, operator decision, and safe failure class.

Do not use shell SQL to force an adoption state or perform image-only rollback
for a class C release.
