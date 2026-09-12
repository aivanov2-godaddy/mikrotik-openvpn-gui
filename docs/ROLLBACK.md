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

For the normal immutable deployment path, the fastest safe option is the
reviewed router-local helper `scripts/routeros/rollback-last-good.rsc.example`.
It reads only the last-known-good full SHA from the private update journal,
restores that image, and waits for readiness. It does not restore or overwrite
the SQLite volume. Use it after confirming the journal entry and keep the
manual steps below as the recovery fallback.

1. Stop new write activity and announce the maintenance state through the private operator channel.
2. Start the retained blue container against its separate, frozen data directory and require its private `/readyz` before changing traffic.
3. Point the HTTPS reverse proxy and HTTP redirect NAT target back to blue, preserving every other field and rule position.
4. Verify private `/readyz`, then public TLS/Access/login and read-only RouterOS views.
5. Set blue `start-on-boot=yes`, set green `start-on-boot=no`, and stop green only after traffic is confirmed on blue.
6. Confirm that no canary or failed container remains publicly reachable.
7. Preserve logs and record the failed image digest without copying secrets into GitHub.

The old container record, root directory, image reference, network settings, mounts, and environment list must remain intact until this step is no longer needed.

## Database decision

Do not restore a database merely because the application image was rolled back.

- A fast rollback uses blue's frozen, separate data directory. It is deterministic but does not include dashboard-only metadata written during the green window.
- If the green release changed RouterOS state, reconcile those RouterOS-side actions explicitly; RouterOS remains the source of truth.
- Restore the immutable pre-deployment checkpoint only when blue's frozen directory is unavailable or damaged, and only while every container that could reference it is stopped.
- Never let old and new containers write the same SQLite file concurrently.

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
