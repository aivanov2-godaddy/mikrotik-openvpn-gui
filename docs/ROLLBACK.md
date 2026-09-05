# Rollback runbook

Read this runbook before the first GHCR promotion. A rollback is successful only when the previous UI, RouterOS integration, data, and public access path are all healthy.

## Roll back when

- the new container restarts, fails health checks, or cannot verify RouterOS TLS;
- administrator login, CSRF protection, user/session reads, profile generation, or downloads regress;
- unexpected RouterOS changes occur;
- CPU, memory, storage, or request latency exceeds the approved threshold;
- the proxy, redirect, Cloudflare Access, or origin restriction behaves differently;
- audit or database errors appear.

## Fast application rollback

1. Stop new write activity and announce the maintenance state through the private operator channel.
2. Point the reverse proxy back to the previous container's private address, or stop the new container and start the retained old container.
3. Verify private `/healthz`, then public TLS/Access/login and read-only RouterOS views.
4. Confirm that no canary or failed container remains publicly reachable.
5. Preserve logs and record the failed image digest without copying secrets into GitHub.

The old container record, root directory, image reference, network settings, mounts, and environment list must remain intact until this step is no longer needed.

## Database decision

Do not restore a database merely because the application image was rolled back.

- If the new release made no incompatible data change, keep the current production `/data` volume and use the old image against it after validation.
- If the new release changed schema or corrupted metadata, stop every container that references the volume and restore the matching pre-deployment checkpoint as a complete directory.
- Never let old and new containers write the same SQLite file concurrently.
- RouterOS remains the source of truth; reconcile any RouterOS action completed during the failed window before restoring dashboard metadata.

After a restore, verify file ownership/permissions and check that the audit log reflects the last expected event.

## Registry failure

If GHCR is unavailable, use the already extracted previous container rather than changing to an unverified image. If the previous image has been removed, repull its recorded immutable digest after restoring the appropriate registry configuration and package-read credential.

## Completion criteria

- previous known-good image and data are active;
- private and public health paths pass;
- RouterOS login and read-only data work;
- no unintended listener or proxy target remains;
- incident evidence is retained privately;
- the failed release is blocked from promotion until its cause and a regression test are documented.
