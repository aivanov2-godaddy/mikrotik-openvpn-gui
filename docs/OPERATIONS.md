# Operations runbook

## Daily checks

- Container status is running without restart churn.
- `/healthz` reports process liveness, `/readyz` reports cached SQLite readiness and the deployed revision, and the public path follows the configured HTTPS access flow.
- `/api/observability` (authenticated) reports the local deployment ledger,
  health timeline, and rollback visibility without exposing router credentials
  or VPN material. The same object is included in `/api/status` for the live
  dashboard refresh.
- RouterOS REST certificate validation succeeds; `ROUTEROS_INSECURE_TLS` is `false` (startup rejects `true`).
- SQLite storage, RouterOS container storage, CPU, and memory stay below local alert thresholds.
- Dashboard users, connected sessions, and interface counters agree with WinBox for a sample identity.
- Audit events contain no passwords, tokens, private keys, profile bodies, or raw authorization headers.

### Live dashboard troubleshooting

If the Connections view reports **Connection data delayed**, first check the
Cloudflare Access session and the dashboard's RouterOS sign-in. A cached page
can remain visible after either session expires, while authenticated status
requests stop. Reauthenticate and confirm the live indicator returns before restarting
containers or treating the symptom as a telemetry outage. If the
view remains delayed with both sessions current, continue with the authenticated
health and telemetry diagnostics; do not copy tokens or raw event payloads into
logs or reports.

## Optional integrations

Set both `WEBHOOK_URL` and `WEBHOOK_SIGNING_SECRET` in the router-local
environment to enable audit-event delivery. The URL must be HTTPS and must not
contain a query string; do not put credentials or tokens in the URL. Configure
any receiver-side authorization through the receiver's secure configuration.
The signing secret must be at least 32 characters; leaving either value unset
disables the integration. Each JSON event is signed with
`X-VPN-Dashboard-Signature: sha256=<hex>` using HMAC-SHA256 over the exact
string `<timestamp>.<request body>`, where the timestamp is supplied in
`X-VPN-Dashboard-Timestamp`. Receivers should reject stale timestamps, verify
the signature before processing, and deduplicate by
`X-VPN-Dashboard-Event-ID`. Delivery is asynchronous, persisted in the local
SQLite outbox, retried with exponential backoff, and protected by a circuit
breaker, so a slow or unavailable receiver cannot block VPN administration.

The published container image includes the optional Redis client; Redis itself
remains a separate service and is enabled only when `REDIS_STREAM_URL` is set.
After completing the migration in [REDIS_ROTATION.md](REDIS_ROTATION.md), the
publisher URL must use the dedicated `vpn-dashboard` ACL identity, restricted
to its stream key and publish commands; do not use the shared `default` user.
The Redis Streams sink currently forwards minimized audit/outbox events (not
the dashboard's live RouterOS telemetry). Remote webhook and Redis payloads use
schema v2: `schema_version`, `event`, a UUIDv4 `event_id`, and, when valid, the
coarse action category, approved status value, and creation timestamp. Actor names, targets,
source addresses, free-form details, credentials, and live VPN telemetry stay
out of remote payloads; the full audit record remains in the protected local
SQLite store. This intentionally narrows the previously described outbound
payload; consumers must not depend on the omitted identity/detail fields.
Delivery is at-least-once and bounded by `REDIS_STREAM_MAXLEN`; consumers must
deduplicate by `event_id`. Keep Redis on a private network, enable
authentication, and persist its data directory. Use `rediss://` when Redis
traffic crosses a network boundary that is not already protected by an
isolated trusted transport. For `rediss://`, the dashboard requires certificate
and hostname verification. Select the Redis database in the URL path (such as
`/0`); query parameters are rejected because redis-py otherwise lets URL
options override the publisher's bounded timeouts and TLS settings.
Before rolling back to an application version that predates schema v2,
temporarily disable outbound integrations by unsetting `WEBHOOK_URL`,
`WEBHOOK_SIGNING_SECRET`, and `REDIS_STREAM_URL`; older versions can forward the
broader legacy event shape from the durable outbox. Preserve the local SQLite
outbox, restore a version with the v2 allowlist, then re-enable integrations
after confirming downstream consumers accept the minimized schema.
The authenticated Prometheus `/metrics` endpoint reports aggregate outbox
backlog/age, retries, last successful delivery, and Redis publish outcomes. A
Redis availability value of `-1` means no publish has yet tested the connection;
the metrics endpoint never probes Redis or emits stream keys, event IDs, or
payloads.
For overlap rotation of the RouterOS Redis ACL and the canary/production
publisher URLs, follow the [Redis credential rotation runbook](REDIS_ROTATION.md).
Malformed outbox payloads and events that exhaust ten durable delivery attempts
are retained as dead-letter rows and excluded from automatic retries. The
`vpn_dashboard_integration_outbox_dead_lettered` metric reports only their
aggregate count. Investigate through the protected local database backup and
support process; do not export raw outbox contents. Normal metadata retention
prunes dead-letter rows alongside old audit records.
The outbox retries events only until SQLite records delivery. If Redis later
loses stream data that was already acknowledged, the dashboard does not
automatically reconstruct those entries from SQLite; use Redis persistence and
tested backups when downstream stream retention is required. The local audit
record remains the application-side source of truth only until normal metadata
retention removes it. CI verifies recovery for events that are still pending,
including loss of Redis stream state before the SQLite delivery acknowledgement.
The same endpoint exports aggregate `vpn_dashboard_sqlite_file_bytes` for the
database/WAL/SHM and `vpn_dashboard_sqlite_volume_free_bytes` for the containing
filesystem (`-1` means the measurement was unavailable); it never exposes the
database path or its records. Alert on sustained WAL growth or low free space
before backup and writes are affected.
CI also exercises Redis restart recovery, loss of stream state while the
outbox row is pending, multi-batch backlog drain, and the ambiguous case where
a stream append succeeds but its SQLite acknowledgement is lost. The integration job
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
`routeros.request_failed`, `routeros.tls_untrusted`, `routeros.timeout`,
`routeros.invalid_response`, and `routeros.unavailable`. TLS guidance directs
operators to check the configured certificate/CA without disabling validation;
permission guidance asks operators to inspect effective permissions and does
not recommend granting broad policies. Unknown failure kinds retain the generic
`routeros.unavailable` response.

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

For the route-by-route preview/apply/read-back/recovery inventory and the
boundary between RouterOS mutations and dashboard-only writes, see
[MUTATION_SAFETY.md](MUTATION_SAFETY.md).

The dashboard reads the signed-in account's RouterOS group and maps it to one
of five explicit dashboard roles. It never keeps a second password or role
database. Unknown or empty groups map to read-only. If RouterOS cannot provide
the account/role lookup—including an unsupported `/user` endpoint returning
404—the dashboard grants no role and rejects sign-in. Older RouterOS versions
do not receive an owner-access compatibility fallback when role lookup is
unavailable.

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

Single-device certificate revocation first reads the current RouterOS
certificate, then requires exact device-name confirmation and a reason-bound,
session-bound review receipt. It revokes only that managed client certificate;
it does not disconnect a tunnel already using it. If new-profile creation
cannot save its local device record, the dashboard attempts to revoke the exact
new certificate and verifies the RouterOS state before reporting recovery as
verified. If recovery is reported `unknown`, do not retry profile creation yet:
review **Device Profiles** and the RouterOS certificate inventory in WinBox,
identify only the newly generated client certificate for that attempt, verify
whether it is revoked, and reconcile the dashboard record before retrying. Do
not remove or modify the CA or server certificate as cleanup.

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

Before suspending a user, the dashboard reads the current account and active
session inventory and displays the number of that user's tunnels that will be
disconnected. The apply request carries a session-bound review receipt; if the
account state or matching session IDs changed since preview, the request is
rejected before checkpointing or changing RouterOS. This is a point-in-time
review, not a guarantee that a new tunnel cannot appear between the check and
the RouterOS account update; the account is disabled first and the handler then
terminates and verifies remaining sessions.

Device-profile issuance also requires a two-step review. Its short-lived,
session-bound receipt can be atomically consumed once. The receipt binds the
VPN user, device label, effective policy and DNS mode, delivery type, optional
legacy-certificate migration target, and the current certificate inventory.
Changing any of those facts or replaying a completed receipt requires a fresh
review. The private-key passphrase is intentionally excluded from the preview
and receipt; it is used only when generating the new private key. For a legacy
migration, the old profile stays active until separately revoked after the
replacement has been imported and tested.

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

### Release acceptance evidence

Copy the schema shown by
[`release-acceptance-evidence.example.json`](release-acceptance-evidence.example.json)
to a private local file and fill only the RouterOS/operator-exercise evidence.
Do not enter deployment health, image-digest, or telemetry claims by hand; the
read-only collector owns those fields. SQLite restore flags are also not
operator input: supply local consistent backup paths to the collector, which
performs and records the restore rehearsal. Keep all evidence files, reports,
and backups outside the repository in a private operator-controlled directory.
Supply credentials and tokens only through process-scoped environment
variables; never write them to files, reports, or command arguments.

For candidate source commit
`beba66c0f36231511ec1b9cc664f2be39a128750`, the successful main-branch CI run
ID is `39984997001`. It contains the unexpired
`redis-recovery-beba66c0f36231511ec1b9cc664f2be39a128750` artifact from the
`redis-integration` job. The collector downloads that exact artifact with the
authenticated GitHub CLI and verifies the successful main push, candidate
SHA, workflow, and artifact attestation. This run ID is valid only for that
candidate and the report freshness window; select a new successful main-push
run with the matching artifact when the candidate changes or the evidence is
more than seven days old. Keep CI logs and Redis payloads out of the release
report.

The Python collector starts its own `gh` child processes. If those processes
cannot read the interactive GitHub CLI credential store, the collection
examples below populate `GH_TOKEN` from the authenticated CLI only when it is
not already set. The `finally` blocks remove a value introduced by the runbook
without deleting a pre-existing value. Do not print or persist the token.

Capture the isolated canary rollback report with
`scripts/collect_rollback_acceptance.py`. The collector records authenticated
RouterOS Binary API and REST read-backs plus independent `/readyz` checks; the
operator performs the ordered rollback stages on canary only. The collector
does not issue RouterOS commands or modify production. It writes a redacted,
candidate-bound report to the private evidence directory. Do not hand-author
its timestamps or checkpoint values; see
[`ROUTEROS_ACCEPTANCE.md`](ROUTEROS_ACCEPTANCE.md#redis-recovery-ci-and-canary-rollback-evidence)
for the capture procedure and limits.

Prepare `private-certificate-lifecycle.json` as a separate redacted,
operator-attested report from the controlled canary lifecycle exercise. Use
[`certificate-lifecycle-acceptance.example.json`](certificate-lifecycle-acceptance.example.json)
only as the synthetic schema shape, never as evidence. Record the actual
ordered read-backs for replacement testing, failed-renewal rollback, RouterOS
revocation, fresh/loaded CRL, existing-session outcome, fresh-connection
rejection, and dashboard status distinction. Its immutable candidate image,
OCI digest, and timestamps must match the release collection. The validator
checks this operator attestation and emits an allow-listed projection; it does
not independently observe the certificate actions. Do not include certificate
subjects or serials, usernames, addresses, profile bytes, private keys,
credentials, screenshots with identifying content, or raw logs.

Run the RouterOS read-only sampler and app collector concurrently so their
30-minute windows align, then pass the joined app-collector output—not the
example or uncollected input—to the evaluator. A passing release report now
requires the joined RouterOS evidence. Set the following non-secret values in
the PowerShell session from the protected operator run sheet. The evidence
directory must already exist outside the checkout. Using environment variables
avoids angle-bracket placeholders, which PowerShell can parse as redirection.
Complete the non-secret preflight checks before setting either health-token
environment variable; then provide each short-lived token only immediately
before its collection block, whose `finally` clears it on success or failure.
The rollback capture prompts for passwords if the documented read-only
credential variables are not set; never put token or password values in
arguments or evidence files.

```powershell
$requiredVariables = @(
  'VPN_ACCEPTANCE_EVIDENCE_DIR',
  'VPN_ACCEPTANCE_CANARY_ORIGIN',
  'VPN_ACCEPTANCE_PRODUCTION_ORIGIN',
  'VPN_ACCEPTANCE_CANDIDATE_IMAGE',
  'VPN_ACCEPTANCE_CANDIDATE_DIGEST',
  'VPN_ACCEPTANCE_PREVIOUS_CANARY_IMAGE',
  'VPN_ACCEPTANCE_PRODUCTION_IMAGE'
)
foreach ($name in $requiredVariables) {
  if ([string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($name))) {
    throw "Set $name in this PowerShell session before continuing."
  }
}
$repoRoot = [IO.Path]::GetFullPath((git rev-parse --show-toplevel).Trim())
$evidenceDir = [IO.Path]::GetFullPath($env:VPN_ACCEPTANCE_EVIDENCE_DIR)
$pathComparison = [StringComparison]::OrdinalIgnoreCase
$repoPrefix = $repoRoot.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
if ($evidenceDir.Equals($repoRoot, $pathComparison) -or $evidenceDir.StartsWith($repoPrefix, $pathComparison)) {
  throw 'VPN_ACCEPTANCE_EVIDENCE_DIR must be outside the repository.'
}
if (-not (Test-Path -LiteralPath $evidenceDir -PathType Container)) {
  throw 'Create the private evidence directory before continuing.'
}
$cursorPath = $evidenceDir
while ($cursorPath) {
  $directory = Get-Item -LiteralPath $cursorPath -Force -ErrorAction Stop
  if (($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'VPN_ACCEPTANCE_EVIDENCE_DIR and its parent path must not contain junctions or symbolic links.'
  }
  $parentPath = Split-Path -Parent $cursorPath
  if ([string]::IsNullOrWhiteSpace($parentPath) -or $parentPath -eq $cursorPath) { break }
  $cursorPath = $parentPath
}
$canaryOrigin = $env:VPN_ACCEPTANCE_CANARY_ORIGIN
$productionOrigin = $env:VPN_ACCEPTANCE_PRODUCTION_ORIGIN

$locationPushed = $false
try {
  Push-Location -LiteralPath $evidenceDir
  $locationPushed = $true
  python (Join-Path $repoRoot 'scripts/collect_rollback_acceptance.py') `
    --output private-rollback-rehearsal.json `
    --candidate-image $env:VPN_ACCEPTANCE_CANDIDATE_IMAGE `
    --candidate-digest $env:VPN_ACCEPTANCE_CANDIDATE_DIGEST `
    --previous-canary-image $env:VPN_ACCEPTANCE_PREVIOUS_CANARY_IMAGE `
    --production-image $env:VPN_ACCEPTANCE_PRODUCTION_IMAGE `
    --canary-url $canaryOrigin `
    --production-url $productionOrigin
  if ($LASTEXITCODE -ne 0) {
    throw 'Rollback report capture failed; stop before release collection.'
  }

  $ghTokenAddedByRunbook = $false
  if ([string]::IsNullOrWhiteSpace($env:GH_TOKEN)) {
    $ghToken = (gh auth token).Trim()
    if ([string]::IsNullOrWhiteSpace($ghToken)) {
      throw 'GitHub CLI did not return an authenticated token.'
    }
    $env:GH_TOKEN = $ghToken
    $ghTokenAddedByRunbook = $true
    Remove-Variable ghToken
  }

  python (Join-Path $repoRoot 'scripts/collect_release_acceptance.py') `
    --input private-evidence.json `
    --output private-collected-evidence-prepromotion.json `
    --routeros-report private-routeros-window.json `
    --redis-recovery-run-id 39984997001 `
    --rollback-report private-rollback-rehearsal.json `
    --certificate-lifecycle-report private-certificate-lifecycle.json `
    --stream-observer-report private-stream-observation.json `
    --telemetry-acceptance-input private-telemetry-acceptance.ndjson `
    --canary-url $canaryOrigin `
    --production-url $productionOrigin `
    --canary-sqlite-backup private-canary-backup.sqlite3 `
    --canary-metrics-url $canaryOrigin `
    --canary-api-token-env VPN_ACCEPTANCE_CANARY_TOKEN `
    --duration-seconds 1800 --interval-seconds 60 `
    --phase canary-prepromotion
  if ($LASTEXITCODE -ne 0) {
    throw 'Pre-promotion collection failed; do not evaluate or promote this candidate.'
  }
} finally {
  if ($locationPushed) { Pop-Location }
  Remove-Item Env:VPN_ACCEPTANCE_CANARY_TOKEN, Env:VPN_ACCEPTANCE_PRODUCTION_TOKEN -ErrorAction SilentlyContinue
  if ($ghTokenAddedByRunbook) {
    Remove-Item Env:GH_TOKEN -ErrorAction SilentlyContinue
    $ghTokenAddedByRunbook = $false
  }
}
```

The pre-promotion collection keeps production on its recorded prior image; it
may make read-only health/readiness and RouterOS state probes against
production, but it must not modify production. Evaluate this pre-promotion file
now, before any promotion, and use it for the read-only promotion gate:

```powershell
python (Join-Path $repoRoot 'scripts/release_acceptance.py') `
  --input (Join-Path $evidenceDir 'private-collected-evidence-prepromotion.json') `
  --output (Join-Path $evidenceDir 'private-acceptance-report-prepromotion.json')
if ($LASTEXITCODE -ne 0) {
  throw 'Pre-promotion acceptance failed; do not promote this candidate.'
}

python -m scripts.promote_routeros_release `
  --input (Join-Path $evidenceDir 'private-collected-evidence-prepromotion.json') `
  --canary-ready-url $env:VPN_ACCEPTANCE_CANARY_READY_URL `
  --production-ready-url $env:VPN_ACCEPTANCE_PRODUCTION_READY_URL `
  --check-only
if ($LASTEXITCODE -ne 0) {
  throw 'Read-only promotion check failed; production must remain on its prior image.'
}
```

Only a successful pre-promotion evaluation and `--check-only` result can make
the candidate eligible for a separate, explicitly authorized production
promotion. Never use post-promotion evidence as the promotion input. After an
authorized promotion is observed, collect the independent post-promotion
acceptance record below. Refresh the candidate-bound Redis run ID and
certificate report if either is outside its accepted evidence window. Use
distinct short-lived `health.read` tokens; pass only their environment-variable
names, never their values.

Before the post-promotion collection, repeat the evidence-directory containment
and reparse-point check from the earlier setup block. This detects a path that
was replaced by a junction or symbolic link during the promotion interval.

```powershell
$evidenceDir = [IO.Path]::GetFullPath($env:VPN_ACCEPTANCE_EVIDENCE_DIR)
$repoPrefix = $repoRoot.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
if ($evidenceDir.Equals($repoRoot, $pathComparison) -or $evidenceDir.StartsWith($repoPrefix, $pathComparison)) {
  throw 'VPN_ACCEPTANCE_EVIDENCE_DIR must be outside the repository.'
}
if (-not (Test-Path -LiteralPath $evidenceDir -PathType Container)) {
  throw 'The private evidence directory is no longer available.'
}
$cursorPath = $evidenceDir
while ($cursorPath) {
  $directory = Get-Item -LiteralPath $cursorPath -Force -ErrorAction Stop
  if (($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'VPN_ACCEPTANCE_EVIDENCE_DIR and its parent path must not contain junctions or symbolic links.'
  }
  $parentPath = Split-Path -Parent $cursorPath
  if ([string]::IsNullOrWhiteSpace($parentPath) -or $parentPath -eq $cursorPath) { break }
  $cursorPath = $parentPath
}

$locationPushed = $false
try {
  Push-Location -LiteralPath $evidenceDir
  $locationPushed = $true
  $ghTokenAddedByRunbook = $false
  if ([string]::IsNullOrWhiteSpace($env:GH_TOKEN)) {
    $ghToken = (gh auth token).Trim()
    if ([string]::IsNullOrWhiteSpace($ghToken)) {
      throw 'GitHub CLI did not return an authenticated token.'
    }
    $env:GH_TOKEN = $ghToken
    $ghTokenAddedByRunbook = $true
    Remove-Variable ghToken
  }

  python (Join-Path $repoRoot 'scripts/collect_release_acceptance.py') `
    --input private-evidence.json `
    --output private-collected-evidence-postpromotion.json `
    --routeros-report private-routeros-window.json `
    --redis-recovery-run-id 39984997001 `
    --rollback-report private-rollback-rehearsal.json `
    --certificate-lifecycle-report private-certificate-lifecycle.json `
    --stream-observer-report private-stream-observation.json `
    --telemetry-acceptance-input private-telemetry-acceptance.ndjson `
    --canary-url $canaryOrigin `
    --production-url $productionOrigin `
    --canary-sqlite-backup private-canary-backup.sqlite3 `
    --production-sqlite-backup private-production-backup.sqlite3 `
    --canary-metrics-url $canaryOrigin `
    --production-metrics-url $productionOrigin `
    --canary-api-token-env VPN_ACCEPTANCE_CANARY_TOKEN `
    --production-api-token-env VPN_ACCEPTANCE_PRODUCTION_TOKEN `
    --duration-seconds 1800 --interval-seconds 60 `
    --phase postpromotion
  if ($LASTEXITCODE -ne 0) {
    throw 'Post-promotion collection failed; do not evaluate this candidate.'
  }
} finally {
  if ($locationPushed) { Pop-Location }
  Remove-Item Env:VPN_ACCEPTANCE_CANARY_TOKEN, Env:VPN_ACCEPTANCE_PRODUCTION_TOKEN -ErrorAction SilentlyContinue
  if ($ghTokenAddedByRunbook) {
    Remove-Item Env:GH_TOKEN -ErrorAction SilentlyContinue
    $ghTokenAddedByRunbook = $false
  }
}
```

The post-promotion output is for production acceptance only; it cannot
authorize promotion. Each collection block clears the short-lived health API
tokens and any `GH_TOKEN` introduced by the runbook in its `finally` block.
This preserves a pre-existing `GH_TOKEN` and clears temporary credentials on
success or failure.

Evaluate the post-promotion collected output separately:

```powershell
python (Join-Path $repoRoot 'scripts/release_acceptance.py') `
  --input (Join-Path $evidenceDir 'private-collected-evidence-postpromotion.json') `
  --output (Join-Path $evidenceDir 'private-acceptance-report-postpromotion.json')
if ($LASTEXITCODE -ne 0) {
  throw 'Post-promotion acceptance failed; production release acceptance remains incomplete.'
}
```

See [`ROUTEROS_ACCEPTANCE.md`](ROUTEROS_ACCEPTANCE.md#collect-a-bounded-app-health-window)
for secure token handling and the full procedure.

The v2 validator requires the same full immutable image tag and OCI digest in
canary and production; a 30-minute window with at least 30 health samples and
no gap over 120 seconds in each environment; zero health, stale-sample, event
loss/duplication/order, or Redis delivery failures; and p95/freshness targets
within limits. It also requires router CPU/memory/storage peaks, Redis status,
REST fallback, reconnect and snapshot recovery, a SQLite restore rehearsal,
and an isolated canary rollback drill. Production must remain unmodified when
canary fails. The pre-promotion collectors may read production readiness,
health, and RouterOS state, but may not write to it. Resource gates are CPU
<=80%, memory <=90%, and storage <=90%.
It emits only release identity, observation window, aggregate measurements,
and pass/fail evidence. RouterOS resource samples and client-exercise results
remain operator-supplied evidence; the app collector does not probe RouterOS
or control VPN clients. A passing report is evidence, not a deployment action:
the collector never promotes or rolls back. The reviewed RouterOS updater stages
candidates on canary only; it cannot update production after the readiness-only
soak. After the full collector and evaluator pass, the local
`scripts/promote_routeros_release.py` controller re-evaluates the fresh evidence,
checks the router's current canary and production images, confirms the stage
record, and rechecks both private
`/readyz` endpoints. The `--check-only` command shown above must use the
pre-promotion collection file; it re-evaluates the evidence and live image
read-backs immediately before any separately authorized promotion.

Production promotion is a separate write operation and is not performed by
the collectors, evaluator, or the `--check-only` gate. Run it only when the
current release policy and operator authority explicitly permit that exact
candidate. RouterOS REST credentials are read only from `ROUTEROS_REST_URL`,
`ROUTEROS_DEPLOY_USERNAME`, and `ROUTEROS_DEPLOY_PASSWORD`; never put them in
arguments or evidence files. The controller verifies production readiness,
updates the local last-good journal, and restores the previous immutable image
if startup, readiness, or journal persistence fails. It does not upload the
acceptance report or alter mounts, environment lists, `/data`, certificates,
VPN users, firewall, or RouterOS OpenVPN policy. A scheduler stage is not
promotion; production acceptance still requires a fresh `postpromotion`
collection. Keep origins out of the report and keep credentials, VPN-user data,
addresses, and raw logs out of both input and output. The example JSON contains
illustrative values only and is not production evidence.

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
