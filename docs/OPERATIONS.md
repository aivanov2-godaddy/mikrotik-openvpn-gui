# Operations runbook

## Daily checks

- Container status is running without restart churn.
- `/healthz` reports process liveness, `/readyz` reports cached SQLite readiness and the deployed revision, and the public path follows the configured HTTPS access flow.
- `/api/observability` (authenticated) reports the local deployment ledger,
  health timeline, and rollback visibility without exposing router credentials
  or VPN material. The same object is included in `/api/status` for the live
  dashboard refresh.
- RouterOS REST certificate validation succeeds; `ROUTEROS_INSECURE_TLS` remains `false`.
- SQLite storage, RouterOS container storage, CPU, and memory stay below local alert thresholds.
- Dashboard users, connected sessions, and interface counters agree with WinBox for a sample identity.
- Audit events contain no passwords, tokens, private keys, profile bodies, or raw authorization headers.

## Optional integrations

Set both `WEBHOOK_URL` and `WEBHOOK_SIGNING_SECRET` in the router-local
environment to enable audit-event delivery. The URL must be HTTPS and the
secret must be at least 32 characters; leaving either value unset disables the
integration. Each JSON event is signed with
`X-VPN-Dashboard-Signature: sha256=<hex>` using HMAC-SHA256 over the exact
string `<timestamp>.<request body>`, where the timestamp is supplied in
`X-VPN-Dashboard-Timestamp`. Receivers should reject stale timestamps, verify
the signature before processing, and deduplicate by
`X-VPN-Dashboard-Event-ID`. Delivery is asynchronous, persisted in the local
SQLite outbox, retried with exponential backoff, and protected by a circuit
breaker, so a slow or unavailable receiver cannot block VPN administration.

The published container image includes the optional Redis client; Redis itself
remains a separate service and is enabled only when `REDIS_STREAM_URL` is set.
The Redis Streams sink currently forwards sanitized audit/outbox events (not
the dashboard's live RouterOS telemetry). Delivery is at-least-once and bounded
by `REDIS_STREAM_MAXLEN`; consumers must deduplicate by `event_id`. Keep Redis
on a private network, enable authentication, and persist its data directory.
The authenticated Prometheus `/metrics` endpoint reports aggregate outbox
backlog/age, retries, last successful delivery, and Redis publish outcomes. A
Redis availability value of `-1` means no publish has yet tested the connection;
the metrics endpoint never probes Redis or emits stream keys, event IDs, or
payloads.
Malformed outbox payloads and events that exhaust ten durable delivery attempts
are retained as dead-letter rows and excluded from automatic retries. The
`vpn_dashboard_integration_outbox_dead_lettered` metric reports only their
aggregate count. Investigate through the protected local database backup and
support process; do not export raw outbox contents. Normal metadata retention
prunes dead-letter rows alongside old audit records.
The same endpoint exports aggregate `vpn_dashboard_sqlite_file_bytes` for the
database/WAL/SHM and `vpn_dashboard_sqlite_volume_free_bytes` for the containing
filesystem (`-1` means the measurement was unavailable); it never exposes the
database path or its records. Alert on sustained WAL growth or low free space
before backup and writes are affected.
CI also exercises Redis restart recovery and the ambiguous case where a stream
append succeeds but its SQLite acknowledgement is lost. The integration job
uses an isolated disposable Redis container; it never connects to a project or
production Redis instance. Treat stream delivery as at-least-once, not exactly
once, and use `event_id` for consumer-side deduplication. A Redis-local effect
can atomically record the dedupe key and apply the effect in one transaction or
Lua script; for effects in another database/service, commit the idempotency key
with that system's effect (or use its native idempotency support). The
integration test demonstrates this contract with a disposable Redis counter;
it is not an application consumer or proof of downstream production behavior.
Use `/healthz` for
liveness and `/readyz` for readiness; these endpoints never expose
configuration or credentials.

## Safe update cadence

### RouterOS API error guidance

The user list, status, and service-health endpoints return stable `code` values
with concise `error` and `next_step` fields when RouterOS requests fail. These
responses do not echo RouterOS response bodies, private host names, or raw
transport exception text. Current codes are `routeros.authentication_failed`,
`routeros.permission_denied`, `routeros.endpoint_unavailable`,
`routeros.request_failed`, and `routeros.unavailable`. Permission guidance asks
operators to inspect effective permissions; it does not recommend granting
broad policies.

1. Review dependency alerts and every available repository security signal.
2. Merge through a pull request with the required pre-commit, secret, test, and ARM64 checks.
3. Select and validate an immutable full-commit `sha-` tag using the local procedure in [DEPLOYMENT.md](DEPLOYMENT.md), or let the tested router-local controller validate the approved public release manifest.
4. Confirm the selected image, RouterOS container status, dashboard `/readyz` revision, and the public login path.
5. Retain the previous image and data checkpoint until the observation window ends.

Never follow `edge`, `latest`, a branch, or another mutable reference; never modify the container's mounts and environment during a routine update. Use the canary-first procedure in [DEPLOYMENT.md](DEPLOYMENT.md) for schema, data, or RouterOS-policy migrations before promoting them. The complete router-local promotion and rollback protocol is documented in [ROUTER_LOCAL_AUTOMATION.md](ROUTER_LOCAL_AUTOMATION.md).

## Redacted diagnostic bundle

An authenticated user with `health.read` may download
`GET /api/reports/diagnostics.zip` when troubleshooting. The endpoint uses the
latest stored health observation and current in-memory telemetry health; it
does not make RouterOS requests or change router/dashboard configuration. The
ZIP contains one fixed-schema `diagnostics.json` file and is capped at 32 KiB.
It includes only release version/revision, aggregate health check IDs/states,
and allowlisted telemetry freshness/reconnect counters. It excludes
usernames, email addresses, IP addresses, hostnames, event payloads, logs,
RouterOS records, credentials, tokens, certificates, keys, and VPN profiles.
The export is audited as `report.diagnostics.export`; audit actor data stays in
the local audit system and is not copied into the bundle. This is distinct
from the compliance report, which intentionally contains operator and
connection-history fields and should be handled as sensitive data.

## Database backup

The dashboard's **Download backup** control creates a self-verifying metadata-only ZIP. Its manifest contains the SHA-256 checksum for `metadata.json`; it never includes RouterOS configuration, credentials, private keys, issued profiles, or active sessions. Keep it in an operator-controlled location.

After selecting **Verify backup**, the setup planner can generate a **review-only
restore plan**. The plan displays the verified SHA-256, metadata size, user
count, and the exact maintenance sequence. It never writes the archive to
`/data`, changes RouterOS, or stores the uploaded bytes. Treat it as a runbook
for an approved maintenance window: make a fresh encrypted RouterOS backup,
checkpoint the current `/data`, perform the reviewed restore manually, then
verify `/readyz`, user counts, and Change History before retiring the checkpoint.

### Router-local pre-deploy backups

For an automated deployment safety net, copy
[`backup-before-update.rsc.example`](../scripts/routeros/backup-before-update.rsc.example)
to the router's private script store, replace its placeholder with a strong
password kept only on the router, and run it before canary promotion. The
helper rotates three fixed slots on external storage. Each slot contains an
encrypted RouterOS binary backup and a `hide-sensitive=yes` configuration
export. It rotates only files with its own prefix and advances the slot
pointer only after both backup commands complete.

This is a RouterOS configuration backup, not a dashboard-data restore. The
dashboard metadata ZIP and a consistent private `/data` checkpoint remain
separate operations. Never commit the configured script or password to the
public repository. Periodically copy a slot to encrypted off-router storage
and test it in an isolated canary.

## Administrator roles and destructive actions

The dashboard reads the signed-in account's RouterOS group and maps it to one
of five explicit dashboard roles. It never keeps a second password or role
database. Unknown groups fail closed to read-only; older RouterOS versions that
cannot expose `/user` retain the existing owner compatibility behavior so a
known deployment does not unexpectedly lose access.

| Dashboard role | Intended responsibility | Typical capabilities |
| --- | --- | --- |
| **Owner** | Full control, including security and destructive actions | All dashboard capabilities |
| **Security operator** | Certificates, devices, sessions, and security settings | Device/profile security, session termination, health and audit reads |
| **Administrator** | Users, policies, profiles, and routine operations | User/profile/policy management, backups, alerts, session controls |
| **Auditor** | Compliance and investigation | Read-only dashboard, reports, and Change History exports |
| **Read-only** | Situational awareness | Dashboard status and read-only VPN data |

The built-in RouterOS groups map as follows: `full`/`owner` → Owner,
`write`/`operator`/`policy` → Administrator, `security`/`security-operator` →
Security operator, `audit`/`auditor` → Auditor, and `read`/`readonly` →
Read-only. Capability checks run in the API as well as the UI, so hiding a
button is never the security boundary.

## Bulk operations and saved views

On **VPN Users**, filter the visible result first, select the intended users,
choose **Suspend**, **Revoke profiles**, or **Add tag**, and select **Preview**.
The server re-reads RouterOS user IDs before producing the preview, so a stale
browser selection cannot silently target a different account. Suspend and
revoke require a RouterOS checkpoint and an exact confirmation phrase. Revoke
only targets dashboard-managed, currently active device certificates; it never
changes the configured CA or server certificate. A retry reports already
completed work as skipped rather than repeating it.

## Policy template review and apply

Preview selected users before applying a policy template. The server returns a
session-bound review receipt covering the template controls, selected RouterOS
user IDs, each user's current RouterOS profile, and current dashboard policy
controls. Apply re-reads those values and rejects a missing or stale receipt
before creating a RouterOS checkpoint. Review again if the template, selection,
or current policy state has changed.
Changing the template or selected users in the page also clears the displayed
review and disables Apply. The receipt does not replace the explicit Apply
action, capability checks, or checkpoint, and it contains no credentials.

The result lists each selected username with an outcome such as applied,
skipped, partial, or failed. Partial failures are safe to retry after the
underlying RouterOS problem is corrected. Change History records the action,
selected count, outcome counts, and tag value when applicable; it intentionally
does not record the selected usernames, passwords, profiles, certificates, or
tokens.

Use **Save current view** to store only the query, status, and tag filters in
the router-local SQLite metadata store. Saved views can be loaded, updated, or
deleted by an operator with user-management capability. They are presentation
metadata, not RouterOS configuration, and they are never included in the
public image, repository, backup manifests, or profile archives.

Every denied capability creates a `role.denied` Change History event with the
actor, required capability, role, and route. It does not include cookies,
passwords, private keys, or profile contents.

For an irreversible action, the dialog displays the exact RouterOS username that will be affected. The operator must type it exactly; the server validates that confirmation again before it creates the RouterOS checkpoint or changes anything. Suspending access is reversible. Removing access and terminating a live tunnel are not undoable by the dashboard.

SQLite backups must be consistent:

1. Run `python scripts/backup_sqlite.py --database /data/dashboard.sqlite --destination /secure/dashboard.sqlite` from an approved maintenance environment.
2. Verify the reported integrity check and retain the destination with mode `0600`.
3. Export the checkpoint to encrypted off-router storage.
4. Start or leave the container running and verify `/readyz` immediately.
5. Test restoration periodically into an isolated canary, never over production.

The helper uses SQLite's online Backup API and is safe while the writer is
running. Do not copy only `dashboard.sqlite` with a file-copy command while WAL
is active; the sidecar state must be captured consistently by SQLite.
The backup destination must be a separate path: the helper refuses to target
the live database, its `-wal` file, or its `-shm` file. It writes a temporary
file beside the destination, validates it, then atomically replaces the
destination. If validation or replacement fails, the previous destination is
left intact and the temporary file is removed.

The repository's backup test suite performs an isolated restore rehearsal and
fault-injects a failed atomic replacement to verify the previous backup is
preserved. Run the focused recovery tests with:

```powershell
python -m unittest tests.test_sqlite_recovery -v
```

The security test also performs an isolated restore rehearsal:
it copies the generated backup into a temporary database, opens it with the
current store, runs the readiness probe, and verifies restored audit/outbox
records. Run it before a release with:

```powershell
python -m unittest tests.test_security.SecurityTests.test_sqlite_wal_checkpoint_and_backup_are_consistent
```

For release acceptance, collect the redacted canary and production observations
in the format shown by
[`release-acceptance-evidence.example.json`](release-acceptance-evidence.example.json)
and validate them with:

```powershell
python scripts/release_acceptance.py --input release-evidence.json --output release-report.json
```

The v2 validator requires the same full immutable image tag and OCI digest in
canary and production; a 30-minute window with at least 30 health samples and
no gap over 120 seconds in each environment; zero health, stale-sample, event
loss/duplication/order, or Redis delivery failures; and p95/freshness targets
within limits. It also requires router CPU/memory/storage peaks, Redis status,
REST fallback, reconnect and snapshot recovery, a SQLite restore rehearsal,
and an isolated canary rollback drill. Production must remain untouched when
canary fails. Resource gates are CPU <=80%, memory <=90%, and storage <=90%.
It emits only release identity, observation window, aggregate measurements,
and pass/fail evidence. The JSON input is still an operator-collected
attestation, not an automatic RouterOS probe; keep it free of credentials,
VPN-user data, addresses, and raw logs. The example JSON contains illustrative
values only and is not production evidence.

Apply retention appropriate to the sensitivity of email ownership, address, usage, and audit metadata. Destroy expired backups securely.

## Credential and certificate rotation

- A public GHCR package requires no pull token. If an organization intentionally uses a private fork, rotate its package-read token before expiry and after any suspected exposure.
- Keep a private-fork token scoped to `read:packages`; validate the new token with a canary pull before revoking the old token.
- Rotate the RouterOS REST server certificate with an overlap window: install the new public CA/config mount, canary the connection, then retire the old trust material.
- Revoke device certificates through RouterOS and the dashboard; do not rely on deleting a downloaded profile.
- For OpenVPN client-certificate revocation, use the staged [certificate revocation migration](CERTIFICATE_REVOCATION.md). Do not enable CRL enforcement until the configured OpenVPN CA has a verifiable, current CRL.
- Review Cloudflare and RouterOS administrator membership regularly.

## Capacity

Track:

- root-directory and temporary image extraction space;
- `/data` growth and backup size;
- container memory/restarts;
- RouterOS CPU under concurrent profile generation and session polling;
- active OpenVPN sessions versus configured account/device limits.

MikroTik recommends external storage for containers. Do not start a pull unless there is room for the compressed layers, extraction, current image, canary, and rollback image.

## Incident containment

If administration access is suspected compromised:

1. Restrict or disable public dashboard access at the edge while preserving OpenVPN service.
2. Revoke the suspected Cloudflare/GitHub/RouterOS credential.
3. Stop profile issuance and destructive dashboard actions.
4. Preserve sanitized logs, image digest, RouterOS configuration snapshot, and audit database through approved private storage.
5. Review RouterOS users, PPP secrets, certificates, active sessions, firewall, proxy, and scheduler state directly in WinBox.
6. Rotate affected client credentials/certificates and restore only from a known-good image and checkpoint.

Never paste raw incident artifacts into an issue. Use a private security advisory.

## Disaster recovery inventory

Keep, outside the router and this repository:

- last known-good image digest and commit SHA;
- RouterOS configuration backup/export protected according to local policy;
- encrypted dashboard `/data` checkpoint;
- public RouterOS REST CA certificate and its rotation record;
- documented bridge/VETH/proxy/firewall topology;
- registry-token recovery and revocation procedure.
