# RouterOS rollback runbook

This runbook covers the current single-router layout: an isolated canary and
one production container named **vpn-dashboard-production**. The canary is the
acceptance environment; normal production promotions occur only through the
reviewed release controller after the required acceptance gates pass. The
operator-reviewed emergency rollback below is a separate recovery path. There
is no blue/green production pair.

A production image rollback interrupts dashboard access while RouterOS stops,
updates, and starts its production container. The helper does not alter
OpenVPN configuration or client tunnels, and it does not restore or delete
the SQLite volume. Starting an older application image may still write
application events or schema changes to that volume; an image rollback does
not reverse those writes or migrations.

## Roll back when

- the candidate repeatedly fails readiness or loses its exact revision;
- login, CSRF protection, role enforcement, session reads, profile generation,
  or downloads regress;
- telemetry privacy, freshness, event ordering, reconnect, or fallback checks
  fail;
- unexpected RouterOS changes occur;
- resource use, request latency, audit, or database behavior crosses an
  approved threshold;
- the proxy, redirect, access policy, or public TLS path behaves differently.

Stop further promotion activity and keep the current configured image reference
and incident evidence private. Do not execute an installed RouterOS updater as
an improvised rollback path.

## Operator-reviewed last-good rollback

The manual helper is a production-changing emergency path, not a one-click
operation or scheduled task. Journals written before the
`previous-good-image` field was added cannot drive this helper. It intentionally
refuses to infer a target from a mutable tag, opaque RouterOS `image-id`, or a
registry lookup that does not prove what is running. The helper becomes usable
only after a reviewed promotion has written both immutable journal entries.
Until then, do not use this helper or seed its journal by guessing. Use it only
after reviewing the private journal,
confirming the fixed production target, planning the dashboard interruption,
and confirming that the required encrypted data backup is available. RouterOS
configuration and OpenVPN data remain the source of truth.

1. Verify there is exactly one **vpn-dashboard-production** container and that
   the private journal has both the current `last-good-image` and intended
   `previous-good-image` as full ARM64 references with SHA-256 digests. Confirm
   the live configured production image matches `last-good-image`. The helper
   refuses missing, equal, mismatched, or malformed targets. Do not substitute
   a tag or guess an image.
2. Review the helper's package prefix and readiness address against the
   production container's assigned VETH. The helper derives that VETH's
   configured IPv4 address and refuses a readiness URL that does not match its
   exact `http://<VETH-IPv4>:8080/readyz` value; it also validates the address
   as RFC1918. Keep those values private; never commit router addresses or
   local journal contents.
3. Save the helper as the single RouterOS system script named
   **vpn-gui-manual-rollback** and review it with the planned maintenance
   window. The helper requires exactly one script object with that name and
   rejects execution from another script or terminal context. In the RouterOS
   terminal, set the global
   `vpnGuiRollbackAuthorization` to the exact text
   `ROLLBACK <current-image> TO <previous-image>`, copying both complete
   digest-pinned references from the reviewed journal. Run the named script
   manually immediately. It checks for overlapping jobs, compares the exact
   image pair, and clears the authorization marker immediately before the
   first container write. Never schedule the helper or run it concurrently
   with another release operation.
4. The helper stops only the fixed production container, sets
   `previous-good-image` in RouterOS's registry-relative form, updates and
   starts it, then checks the configured `remote-image` read-back and `/readyz`
   source revision against that previous image. It records the restored image
   as current and removes the previous rollback target from the journal after
   readiness succeeds. It does not change mounts, environment lists, **/config**,
   VPN objects, firewall, proxy, or certificates.
5. RouterOS command errors can leave production stopped or partially changed;
   the helper reports the failed lifecycle step but cannot guarantee atomic
   recovery. If a lifecycle command, image read-back, journal write, or
   readiness check fails, treat the result as operator-action-required. Inspect
   the actual container and journal before using the reviewed recovery
   procedure. Do not rerun blindly. A successful app start may write to **/data**
   as described above; the helper does not restore or delete application data.
6. Verify production lifecycle health, **/healthz**, **/readyz**, the public
   access path, login, and read-only RouterOS views. Confirm the response
   revision matches the journal's full source commit. The next successful
   reviewed promotion will create a new previous rollback target.

The helper proves the configured immutable image reference and an application
readiness response for the expected source revision. Those checks do not prove
the running OCI manifest digest or RouterOS's healthcheck state. Do not treat a
configured reference, opaque **image-id**, or app revision as running-digest
proof. Record a deployment as accepted only after the separate candidate-bound
digest, canary, and production health gates pass.

## Data and RouterOS decisions

- Do not restore SQLite just because the application image was rolled back.
- Keep **/data** single-writer. Never attach canary and production to one
  database file or let two application versions write it concurrently.
- Reconcile any RouterOS-side action explicitly; RouterOS remains authoritative.
- Restore a pre-deployment data checkpoint only when the existing data is
  damaged or unavailable and every container that could reference it is
  stopped. Follow the separate tested backup/restore procedure.
- Preserve the old image reference, mounts, environment lists, VETH interfaces,
  proxy rules, firewall, and configuration until recovery is verified.

## Registry failure

If GHCR is unavailable, do not switch to **latest**, **edge**, or another
mutable tag. Use only an already available image whose exact digest and source
revision are verified. If the journal or immutable image cannot be verified,
stop and preserve the current state for operator recovery.

## Completion criteria

- production reports the intended configured immutable image reference and
  expected readiness source revision;
- RouterOS lifecycle health and private and public health paths pass;
- login, read-only RouterOS views, and required telemetry behavior work;
- no unintended listener, proxy target, extra container, or writer remains;
- incident evidence is retained privately and the failed image is blocked from
  promotion until its cause and regression coverage are documented.
