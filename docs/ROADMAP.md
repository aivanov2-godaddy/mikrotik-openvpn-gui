# Public roadmap

The project is developed public-first: generic features are designed, tested,
and released here before an operator optionally evaluates them in a private
canary. This source repository never receives router credentials, live user
data, deployment runners, or production network details.

## Current release status — 2026-10-05

Formal release **v2.7.0** is published from commit
`2e01f111e1445c79b1753477a41efbaec27a1a2d`. Release workflow
[37212204043](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/37212204043)
and container workflow
[37212204038](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/37212204038)
completed successfully. ARM64 image tag/digest:
`sha-2e01f111e1445c79b1753477a41efbaec27a1a2d-arm64` /
`sha256:cf7f60ba462db7c70333892cd39ef5a88b4d496c0cfb6068ec2f184b7946178a`.
AMD64 image tag/digest:
`sha-2e01f111e1445c79b1753477a41efbaec27a1a2d-amd64` /
`sha256:c5549656a5706786579052e274c0018f405ea2c7530956a3761143ca200e8b1f`.
Both image builds passed runtime smoke tests and detached provenance/SBOM
verification; the `routeros-stable` manifest now points to this commit. On
2026-10-04, RouterOS WebFig read-back confirmed the v2.7.0 ARM64 immutable tag
on both canary and production containers, each with the RouterOS healthy
(`H`) marker. This verifies image deployment and container health only; it is
not formal VPN/telemetry acceptance and does not replace the outstanding
operator acceptance evidence tracked below.

### Earlier RouterOS-confirmed runtime image — PR #478 — 2026-10-05

The latest numbered release remains **v2.7.0**; subsequent changes are
main-branch patches. PR [#478](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/478)
merged as `d5f8f4418d6ec972aa51ea4634b56c7fd89093f4`; publication workflow
[37294618814](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/37294618814)
passed. RouterOS WebFig read-back on 2026-10-05 then showed both canary and
production configured with
`sha-d5f8f4418d6ec972aa51ea4634b56c7fd89093f4-arm64`, both healthy (`H`), and
the Redis container running (`R`). The published ARM64 registry digest is
`sha256:1ec08a3a0c5d4741a701270ba30249aba62e215649170aa3a6b69c150fc41209`;
the AMD64 digest is
`sha256:fad6a49eb253f52c5407369700833c7733f26972f49ae37fa012dd43e0a6f787`.
RouterOS reports the configured tag, not an independent registry digest
read-back. The current browser tab was at the dashboard sign-in page, so this
read-back confirms image identity and container health only—not authenticated
post-deployment UI, live-event behavior, or the sustained acceptance window.
No new numbered release was created.

### Latest RouterOS-confirmed mainline image — PR #484 — 2026-10-05

After that RouterOS read-back, PRs #481–#484 merged. The runtime change covered
by this read-back was PR [#484](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/484),
commit `93627bca38312ad1845249c6df1c0fcecf12122e`. Publication workflow
[37302952543](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/37302952543)
passed source and browser verification, both architecture builds, runtime
smoke tests, and detached provenance/SBOM attestations. ARM64 tag/digest:
`sha-93627bca38312ad1845249c6df1c0fcecf12122e-arm64` /
`sha256:01872672a9093ac999272c0be0cf97bf27c2139af1cde90f41b501ac4995ba73`.
AMD64 tag/digest:
`sha-93627bca38312ad1845249c6df1c0fcecf12122e-amd64` /
`sha256:6c6c2babc30e499f35b62877cc8e2450ea17cb0aad9e32b3f296cfd5199fce78`.
The `routeros-stable` manifest was refreshed to this candidate as part of the
same workflow; it does not update routers automatically.
This mainline image is not a numbered release. RouterOS WebFig read-back on
2026-10-05 after publication showed canary and production configured with the
ARM64 immutable tag above, both healthy (`H`), with Redis running (`R`).
RouterOS reports the configured tag, not an independently verified registry
digest. This confirms deployment configuration and container health, but not
sustained canary acceptance. The active dashboard browser tab was at sign-in
during inspection, so authenticated post-deployment streaming and UI behavior
remain unverified. The latest numbered release remains v2.7.0.

PR #474's earlier published-but-unverified image was
`sha-aa48c90a6a5fbba5763a96390f10210efe34131c-arm64` /
`sha256:870324122035e4ca0414bc6ecf0102698f33e10ece81e1645fbed29bb6dc167d`;
at that time, it was superseded in the registry by candidate `c9bbdfd` above;
that historical publication did not make it a RouterOS-confirmed deployment.

### Latest published mainline artifact — PR #494 — 2026-10-05

PR [#494](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/494)
merged as `03d08a2e6a08554c68cf74930049ac29ac0b3219`; publication workflow
[37328242084](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/37328242084)
passed CI, ARM64/AMD64 image builds, exact-digest provenance/SBOM verification,
and runtime smoke. ARM64 tag/digest:
`ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-03d08a2e6a08554c68cf74930049ac29ac0b3219-arm64` /
`sha256:5d5645d7613f74081bb01e390d6201ba6230968de72248119b39c9a4274ecad4`.
This is publication/CI evidence only; no RouterOS read-back confirms this image
on either canary or production. The latest timestamped RouterOS tag/health
read-back remains PR #484 above. The 30-minute telemetry/Redis soak and
rollback acceptance remain pending.

### Previously published mainline artifact — PR #492 — 2026-10-05

PR [#492](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/492)
merged as `a4f2cce829c8453a7b982307677d2d3173b94a90`; publication workflow
[37317035616](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/37317035616)
passed source checks, unit/mock integration tests, rendered browser/accessibility
tests, ARM64/AMD64 builds, exact-digest provenance/SBOM verification, and
runtime smoke tests. Its ARM64 image is
`sha-a4f2cce829c8453a7b982307677d2d3173b94a90-arm64` /
`sha256:682a6dc61aeb47cc0e0979ab03d3c4f30d8497f8f0fbb44282bef84267f7f373`.
The commit updates only the repository's RouterOS updater example, docs, and
tests; its 30-sample readiness soak has not been installed or exercised on the
router. This is a newer publication, **not** a verified deployment. The latest
timestamped RouterOS tag/health read-back remains PR #484 above, and #199's
telemetry/Redis soak and rollback acceptance remain open. The latest numbered
release remains v2.7.0.

### Post-v2.7.0 runtime patch — PR #443

PR [#443](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/443)
removes the certificate-revocation status check and its warning from the
dashboard's Service Health and protection-summary UI. Certificate inventory,
reviewed per-device revocation actions, and RouterOS enforcement were not
changed. The merged source is commit `9045057e155b97408e9364bf759e329d60f81b69`;
container workflow [37223686260](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/37223686260)
passed release-source verification, the rendered browser/accessibility suite,
ARM64/AMD64 publication, runtime smoke, and exact-digest provenance/SBOM
verification. The ARM64 image is
`sha-9045057e155b97408e9364bf759e329d60f81b69-arm64` /
`sha256:aa632131c3f5ae5efb0a5bc24246223cd5e7fa26b21ba4810c226e6228d229ad`.
After the stable manifest update, RouterOS WebFig showed that immutable tag on
both canary and production, each with healthy (`H`) status. The dashboard
container restart invalidated the prior browser session; the subsequent page
was at sign-in, so authenticated post-restart rendering was not verified.
This is point-in-time rollout evidence, not the sustained acceptance tracked
in issues #198/#199 or independent on-router digest comparison.

### Post-v2.7.0 runtime patch — PR #448

PR [#448](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/448)
adds reviewed retirement for an unmanaged legacy certificate after its
replacement import and connection test are operator-confirmed. The change
preserves the `device.manage` gate, one-time state-bound review, and RouterOS
read-back; it does not prove session termination or reconnect rejection. Main
commit `72c4c255b92b9c5ffb9af509fea5b6306da65657` was published by container
workflow [37230021532](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/37230021532).
Both architectures passed source verification, rendered browser/accessibility
tests, image smoke tests, and exact-digest provenance/SBOM verification. ARM64
tag/digest:
`sha-72c4c255b92b9c5ffb9af509fea5b6306da65657-arm64` /
`sha256:55f2735691f53950d65ed681fa8d47f6861972544e002e40349ac849e4dda185`.
AMD64 tag/digest:
`sha-72c4c255b92b9c5ffb9af509fea5b6306da65657-amd64` /
`sha256:bbb9aaf2e0d943397d7968a7a4c452408c2ba37e9990dd936495c3721fc87198`.
The `routeros-stable` manifest now names this commit. That is publication, not
proof of RouterOS rollout. A read-only WebFig observation at 2026-10-04 23:41
Europe/Sofia subsequently showed this exact immutable ARM64 tag configured on
both canary and production, each with healthy (`H`) status; Redis showed
running (`R`). The container table's point-in-time CPU/memory values were also
observed, but are not a sustained baseline and are not reproduced in this
public roadmap. RouterOS reports the configured tag, not the registry digest.
The public dashboard was at its RouterOS-authenticated sign-in page, so no
authenticated application, live telemetry, or lifecycle test was performed.
Formal version v2.7.0 remains the latest numbered release. This read-back does
not complete the live lifecycle or telemetry acceptance gates.

## v1.1 — Installation Wizard ✅

An offline, review-only installer that validates non-secret answers and renders
a RouterOS `.rsc` plan. It keeps Container package installation, device-mode
physical confirmation, TLS, storage checks, firewall/DNS work, and applying
commands explicitly manual.

## v1.2 — Policy templates and groups ✅

Protected `standard`, `contractor`, and `administrator` templates, plus custom
templates. Selected users receive a preview before an explicit, checkpointed
apply; later direct edits are retained as visible per-user overrides.

## v1.3 — Health and actionable alerts (implemented)

The dashboard now brings RouterOS REST reachability, dashboard storage,
OpenVPN service, profile-issuance prerequisites, client-certificate inventory,
and router capacity into one read-only view. It no longer displays a
certificate-revocation/CRL status check. Reviewed per-device revocation
workflows remain available; removing the status display did not change
RouterOS enforcement or configuration. Each displayed health result explains
its impact and a safe next step; it never changes RouterOS automatically.
Per-user quota and schedule alerts remain visible in the normal dashboard
alert list.

## v1.4 — Reports and audit (implemented)

The audit page now supports readable date-range exports in redacted CSV and
JSON formats, in-page filtering, and bounded automatic retention. Exported
records contain action metadata only; passwords, private keys, profiles, and
RouterOS secrets are excluded.

## v1.5 — Backup and restore safety (implemented)

The setup planner can download a local metadata-only archive and verify an
existing archive's structure, format, and SHA-256 checksum entirely in memory.
Compatibility results are recorded in Change History; restore remains an
explicit review-only operation and is never applied automatically. Backups
remain local to the operator.

## v1.6 — Administrator guardrails (implemented)

Clear capability matrix, explicit destructive-action confirmations, and richer
audit rationale without a second administrator-password database.

## v1.7 — Opt-in integrations (implemented)

The dashboard supports provider-neutral HTTPS webhooks for sanitized audit
events, signed with HMAC-SHA256 and delivered asynchronously through a bounded
queue. `/healthz` and `/readyz` provide lightweight monitoring probes. Both
integrations are disabled unless explicitly configured; provider-specific
services remain optional adapters rather than hard dependencies.

## v1.9 — Review-first OpenVPN foundations (implemented)

The installer retains its short path for routers that already run OpenVPN. An
opt-in advanced planner is being added for a supported router with no existing
OpenVPN server: it validates that boundary and creates a copyable, non-secret
plan for the CA, server certificate, address pool, PPP profile, OpenVPN server,
and a disabled firewall rule. The plan includes a RouterOS checkpoint command
and requires the operator to review firewall placement, NAT, and enabling the
server in a maintenance window. It never changes RouterOS automatically. The
release also includes a full first-install playbook and a redacted real-router
canary acceptance procedure, so a maintainer can verify the public image before
it is promoted by their router-local deployment controller.

## v2.0 — Device posture checks (phase 1) ✅

The Device Profiles view evaluates each managed profile against the RouterOS
certificate inventory already read by the dashboard. A profile is marked
**Approved** only when its certificate is present, non-revoked, and issued by
the configured current CA; missing, revoked, or legacy-CA identities are
marked **Needs review** with an explanatory reason. This is deliberately
read-only: it does not rotate the CA, alter certificates, or change RouterOS.
Explicit device revocation remains the separate, confirmed action.

## v2.0 — Production observability (implemented)

Service Health now includes a local deployment history, a compact health
timeline, and rollback visibility for immutable releases. The authenticated
`/api/observability` endpoint and the normal live-status payload expose the same
metadata to the UI. Observations stay on the router-hosted database, are
retention-pruned, and never include CA material, credentials, profiles, or
RouterOS configuration.

## v2.1 — Mobile administrator workflows (implemented)

The same dashboard is optimized for phones and tablets. Responsive navigation,
touch-sized controls, safe-area spacing, viewport-safe dialogs, stacked action
groups, readable health cards, and bounded horizontal tables keep
administrative workflows usable in portrait and landscape without adding a
native app or changing the OpenVPN client experience. These are
presentation-only changes: APIs, RouterOS state, certificates, CA material,
and the router-hosted data boundary remain unchanged.

The follow-up polish pass adds an adaptive navigation treatment, stronger
mobile hierarchy, rounded card grouping, thumb-sized primary actions, clearer
live-session facts and graph containers, and keyboard-safe dialog surfaces.
Active navigation scrolls into view when a dashboard card opens another view;
all existing keyboard and screen-reader semantics remain intact.

Appearance preferences are available from the top bar on every dashboard view:
Standard preserves the slate WinBox baseline, Dark is tuned for low-light use,
Light provides a high-contrast daylight surface, and System follows the device
preference. The choice is browser-local and presentation-only.

## v2.2 — Administrator roles and authentication audit (implemented)

RouterOS groups map to Owner, Security operator, Administrator, Auditor, and
Read-only roles. A shared capability matrix is enforced by every API mutation
and mirrored by the UI, while the router remains the identity source and no
second dashboard-password database is introduced. Change History records
successful and failed sign-ins, role assignment, denied capabilities, and
dashboard-session revocation with safe metadata only. This release does not
modify CA material, certificates, issued profiles, RouterOS configuration, or
router-hosted VPN data.

Every roadmap item gets a focused issue, pull request, passing CI, and squash
merge. This milestone shipped in PR #137. See the live GitHub
[roadmap issue](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/4).

## v2.3 — Enterprise operations foundations (implemented)

This release starts the next enterprise-grade layer while preserving the
review-first and router-data boundaries:

- **Administrator session center:** safe session inventory with source,
  authentication method, idle/absolute expiry, and explicit revocation. The
  current session cannot revoke itself.
- **Break-glass recovery planning:** owner/security-operator users can produce
  a time-limited, reason-bound RouterOS recovery checklist. It is a plan only;
  it creates no credentials and changes no RouterOS state.
- **Signed release verification:** immutable GHCR SHA tags are checked against
  the reported revision before promotion. Mutable tags are rejected and the
  CA/data preservation gate is shown in the result.
- **Real-time telemetry:** an authenticated Server-Sent Events stream supplies
  connection snapshots, with the existing five-second polling path retained as
  a resilient fallback.
- **Profile diagnostics:** uploaded profiles are parsed in memory for endpoint,
  protocol, certificate blocks, and modern TLS safeguards; profile contents and
  private keys are never persisted or echoed.
- **Segmentation planning:** LAN/internet/full-tunnel zones and CIDRs can be
  reviewed as a deterministic plan before any future RouterOS implementation.
- **Metrics and compliance:** `/metrics` exposes secret-free Prometheus
  counters; a bounded compliance ZIP contains redacted summary, audit, and
  connection data.
- **Scoped API tokens:** short-lived, read-only bearer tokens can be issued,
  listed, and revoked by security-capable operators. Only a one-time plaintext
  token is shown; storage retains a hash and metadata only.
- **Accessible mobile/PWA foundation:** touch-safe controls, reduced-motion
  support, consistent labels, and an installable web-app manifest improve
  phone workflows without changing the OpenVPN client experience.

All controls are capability-gated and audited. No item in this foundation
release rotates or deletes CA material, certificates, profiles, RouterOS
configuration, or router-resident VPN data. This milestone shipped in PR #138;
the feature remains release-tagged separately from the published v2.0.0 image
until the next release checklist is completed.

## v2.4 - Bulk operations and saved views (implemented)

VPN Users now supports selecting up to 100 users from the current filtered
result, reviewing a server-generated preview, and applying suspend, revoke, or
dashboard-only tag actions after an exact confirmation phrase. Suspend and
revoke operations create the same router-local checkpoint used by their
single-user equivalents; retries are idempotent, and the response reports
skipped, applied, partial, and failed users individually. Change History stores
only aggregate counts and safe action metadata, never a user list, password,
certificate, profile, or RouterOS secret.

Operators can save, load, update, and delete named views containing only the
query, status, and tag filters. Saved views are stored in the router-local
SQLite metadata database and are deliberately excluded from the public image
and repository. The feature is UI/API capability-gated and does not alter the
CA, certificate issuance, profile format, or existing `/data` mount.

## v2.5 — Binary live telemetry (deployed)

The dashboard now uses a read-only RouterOS Binary API-SSL
transport with a Socket.IO browser gateway. The first slice validates the
protocol framing and documents the migration and full-revert procedure. The
second slice adds a disabled-by-default, in-memory broker that normalizes
records, reconciles snapshots, emits versioned session transitions, and
redacts every event through an explicit allow-list. The third slice adds a
transport-neutral gateway contract that authorizes the existing RouterOS
session capability, bounds replay, and recovers stale cursors with a snapshot.
The fourth slice adds a disabled-by-default supervisor that owns only the
read-only active-session listen stream, reconnects with bounded backoff, and
publishes redacted health metrics. The fifth slice adds a compatible optional
Socket.IO adapter and capability discovery; the sixth adds a frontend
selection hook with SSE fallback and a consecutive-sample canary comparator.
The public runtime uses the authenticated Socket.IO path with SSE and REST
fallback. RouterOS REST remains the mutation path; OpenVPN CA material,
certificates, profiles, users, RouterOS configuration, and router-local data
remain outside the feature boundary. The deployed router image is healthy and
has passed the immutable-image rollout checks. The first controlled acceptance
window verified container health, REST fallback during an API-SSL interruption,
and automatic Binary API recovery. A connected-client window then verified
live connect/disconnect rendering, snapshot recovery, changing traffic
samples, and two simultaneous dashboard clients. The latest immutable image
also corrects live-rate spikes by using the full five-second sample cadence.
The controlled acceptance report records passing event-age, counter-reset,
parity, event-order, reconnect, security, and fallback evidence. The acceptance
evaluator requires explicit evidence attestations rather than allowing an
incomplete window to pass. The native ASGI/Uvicorn WebSocket runtime is
implemented behind
``SOCKETIO_ENGINE=asgi``; the dependency-free polling bridge remains the
immediate rollback mode.

## v2.6 — Durable integration delivery (implemented)

SQLite WAL mode, busy timeouts, bounded autocheckpoints, and online atomic
database backups protect router-local state. Sanitized audit events are written
to a transactionally consistent SQLite outbox and delivered at least once with
timestamped HMAC signatures, event IDs, retries, backoff, and circuit breaking.
Redis Streams is an explicit optional build/runtime path for multi-consumer
fan-out; it is not required by the single-container deployment. No GetStream
SDK or provider-specific credentials are included in the public image; a future
GetStream adapter must remain behind the same redaction, idempotency, and local
REST/SSE fallback boundary.

## Next release — Integration and rollout confidence

- Expose authenticated, payload-free metrics for Redis publishes, retries,
  SQLite outbox backlog and age, and last successful delivery.
- Test transient Redis loss/recovery, duplicate event-ID behavior, and an
  isolated SQLite backup restore rehearsal.
- Validate redacted release evidence for canary then production, requiring the
  same immutable image and digest, health/readiness, telemetry freshness and
  latency targets, Redis publish verification, REST fallback, and reconnect/
  snapshot recovery. The v2 evidence gate additionally requires a 30-minute
  sampled window, zero recorded delivery/health/event-integrity failures,
  resource peaks, and a canary rollback drill before production protection is
  considered verified.
- Keep the validator read-only: it reports evidence and never promotes an
  image or changes RouterOS policy, users, certificates, or data.

## Product quality program — professional single-router operator experience

The next roadmap is tracked as [epic #205](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/205). The product goal is a polished, evidence-backed MikroTik OpenVPN control plane: less explanation on routine screens, clearer task actions, dependable live status, safer lifecycle operations, and verifiable release/security claims. **Multi-tenancy is explicitly out of scope.**

### Phase 1 — UX foundation

- [#188](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/188) Refocus Dashboard as an operator command center.
- [#189](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/189) Group navigation by operator tasks and improve mobile labels.
- [#190](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/190) Make Users and Connections lists scannable and action-oriented.
- [#191](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/191) Improve live status and graph controls without pausing telemetry.
- [#192](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/192) Establish design-system and accessibility regression gates.

### Phase 2 — Operator workflows

- [#193](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/193) Add a read-only Connection Doctor and RouterOS-aware capability checks.
- [#194](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/194) Build safe device and certificate lifecycle workflows.
- [#195](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/195) Add a correlated operations timeline and actionable notifications.
- [#204](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/204) Produce redacted support bundles and actionable error guidance.

### Phase 3 — Reliability proof

- [#196](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/196) Exercise Redis outbox delivery against real Redis failures.
- [#197](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/197) Fault-inject SQLite writes, WAL, backup, and restore.
- [#198](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/198) Add telemetry SLOs and stream recovery observability.

### Phase 4 — Release and security assurance

- [#199](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/199) Automate read-only acceptance evidence and canary soak gates.
- [#200](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/200) Create a verifiable security assurance and live-session review.
- [#201](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/201) Add read-only RouterOS least-privilege and exposure diagnostics.
- [#202](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/202) Standardize preview, apply, verify, and recovery for mutations.
- [#203](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/203) Publish verifiable SBOM/provenance and a tested RouterOS compatibility policy.

### Execution status — 2026-10-05

This table retains the delivery evidence for roadmap issues #188–#204, including
issues already closed for their repository implementation. Issues #192, #194,
#199, and #200 remain open as standalone issues; the epic #205 tracks
cross-cutting acceptance still requiring human, physical-router, or external
review evidence.
The entries below are not claims that every listed issue remains open or that
point-in-time/device-independent checks complete live acceptance:

**Redis ACL migration runbook (2026-10-05):** PR [#488](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/488)
merged as `974a929d26128acf2e496f18112789892d6eec07`. It documents moving the
publisher from the shared Redis `default` identity to a dedicated,
least-privilege `vpn-dashboard` identity, including canary-first switching,
verification, rollback, and subsequent password rotation. This is an
operator procedure only: the PR did not change RouterOS ACL files, container
environment lists, credentials, Redis state, or either dashboard container.
Do not treat the merged runbook as proof that the device-side migration has
been performed.

**Certificate lifecycle status:** #194 was reopened on 2026-10-04 because the
tracking issue for PR #255 explicitly said it did not close #194, although the
parent had been closed. The repository has a basic migration path that issues a
replacement profile without retiring the legacy certificate. PR #429 clarifies
that ZIP/QR profile actions issue a new certificate and that lost-profile
recovery uses a replacement identity because private keys are not retained for
same-identity re-download. The complete guided staging/import/test/retire
experience and live RouterOS CRL, active-session, reconnect, and rollback
acceptance remain incomplete.

PR [#490](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/490)
closes a managed-device bypass in this workflow: once a replacement is staged
for a managed certificate, retirement now requires the import and operator
test attestations, then re-reads the source and replacement certificates before
review/apply and verifies that the active replacement belongs to the same VPN
user under the configured CA. RouterOS's user-wide active-session observation
still cannot attribute that session to a specific certificate. The PR passed
repository CI but did not exercise or change router/client state; deployment,
CRL enforcement, reconnect rejection, and rollback remain outstanding.

**Production acceptance update (2026-10-04, 15:02 Europe/Sofia):** the
operator-authenticated Owner session loaded the protected production Dashboard
and Connections views; both showed the live Socket.IO transport. This verifies
ordinary authenticated browser/proxy access only and supersedes the table's
earlier pending item for that basic check under #199/#200. There were no active
VPN clients, so this did not validate a live session-event timeline correlation
for #195, session expiry/revocation for #200, or the sleep/wake soak for #199.
No operator-initiated RouterOS configuration, VPN-user, or active-session
mutation was performed. The remaining device and independent-review gates
below still apply.

**Production live-update observation (2026-10-05, approximately 00:11
Europe/Sofia):** the already-authenticated Owner Dashboard reported the live
Socket.IO transport. After the operator reported connecting a VPN client, the
same open dashboard showed one connected user and updated aggregate traffic
without a page reload. Router health readings also continued to update. This is
one observed live connection-state change, not a timed latency measurement or
proof of event ordering/loss behavior; no client identity or address is recorded.
The same observation exposed a stale lower status-strip session count; the
repository fix and regression are included in the current change, but have not
yet been deployed. No RouterOS configuration, account, certificate, or session
mutation was performed by the agent.

**Production image update (2026-10-04, 16:54 Europe/Sofia):** after PR #432
merged, CI run [37205578218](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/37205578218)
published ARM64 image tag
`sha-cbc0e6e29771e425793b5bcff31e51a1e6f65779-arm64` with registry digest
`sha256:e2341066e70ef0ff83fa994d8a8381c4fad279cd62ddde096b923003207ff57e`;
the build, image smoke test, and provenance/SBOM verification passed. The
authenticated RouterOS Container view subsequently showed both canary and
production on that exact immutable tag, with both containers healthy. RouterOS
logs showed `/readyz` returning HTTP 200 for canary and production after the
update (latest production probe at 16:54:05). The router reports configured
tags rather than registry digests, so the digest-to-tag association comes from
the successful CI publication record, not an on-router digest read-back. An
earlier canary attempt was rolled back safely; the later retry proceeded and
production was promoted. This is point-in-time deployment verification, not
formal sustained telemetry, resource, session-lifecycle, or rollback-drill
acceptance. An authenticated browser check was outstanding immediately after
that restart; the later live-update observation is recorded above.

| Issue | Merged evidence | Still required |
| --- | --- | --- |
| [#192](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/192) | CI checks focus visibility, reduced motion, forced colors, and responsive CSS (#220); rendered Chromium screenshot baselines cover Dashboard, VPN Users, and Connections at desktop/tablet/mobile sizes; visually reviewed desktop-state snapshots additionally cover a dashboard warning, a filtered no-results users list, the add-user dialog, and the connection termination prompt; the test gate forbids re-baselining serious contrast regressions; forced-colors rendering verifies keyboard focus, navigation, and primary action visibility at all three viewports; browser checks verify keyboard-only activation/current-view indication across the primary views plus 720 CSS-pixel zoom-equivalent reflow without page-level horizontal overflow; PR #348 adds light-theme axe checks and fixes 127 serious contrast findings plus Add-user dialog keyboard/focus/validation/Escape coverage; PR #384 expands axe scans to ten operator views at desktop/tablet/mobile and fixes low-contrast secondary text and inaccessible scroll regions in Device Profiles, Service Health, Policy Templates, and Change History; PR #389 verifies reduced-motion animation/transition suppression and non-smooth scrolling in the rendered Add VPN user dialog at all three viewports; PR #478 adds axe scans for the no-results, add-user-dialog, and termination-review desktop states and fixes low-contrast add-user helper text. A five-task usability protocol with success/error criteria and before/after measurement guidance is documented in [ACCESSIBILITY.md](ACCESSIBILITY.md). | Run and record the human task study; assistive-technology review; manual actual-200%-browser-zoom inspection. Automated checks are not an accessibility-conformance claim. |
| [#194](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/194) | Expiry-aware certificate inventory and carefully scoped posture language (#231); managed per-device revocation uses RouterOS `issued-revoke` and exact revoked-timestamp read-back (#254); profile ZIP/QR actions now explicitly issue a new identity, and lost-profile recovery deliberately uses a replacement because private keys are not retained for same-identity re-download (#429); Device Profiles now shows the replacement certificate name and next import/test step while keeping the old certificate active until separately revoked; unmanaged legacy migrations now expose the same reviewed, state-bound retirement flow only after operator-confirmed replacement testing and current-CA certificate checks; the optional CA-wide CRL migration runbook is explicitly separate from this per-device scope, and the dashboard no longer presents aggregate CRL status. | Complete and accept the guided replacement/import/test/retire lifecycle; prove CRL enforcement, active-session handling, fresh reconnect rejection, and a controlled canary failure/rollback on the router. No repository evidence claims these live outcomes. |
| [#195](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/195) | Change History is explicitly a bounded dashboard audit view, not a complete RouterOS event timeline (#230); actionable alerts deduplicate by action/target and cap new records while retaining every durable audit record (#274); dashboard audit, health, and deployment observations are joined into a searchable/filterable bounded timeline with age, source, coverage warning, and `audit.read`-gated redacted JSON export; audit timeline IDs now use stable local audit-row IDs; bounded status-only Redis outbox delivery events are included for `audit.read` viewers (#315); session snapshot history now joins through non-causal account/time and nearby health/deployment context, with inferred/absence-observed timestamp labels and a dual `audit.read` + `sessions.read` JSON export gate (#321); rendered browser coverage verifies event-type, text, and local-calendar date-range filtering, and the selected end date uses DST-safe calendar-day arithmetic; PR #372 adds recurrence count, last-seen updates, and severity escalation for active alert groups, without claiming cross-source incident correlation; PR #392 adds accessible navigation between related timeline events, retains links and keyboard focus through live refresh, reveals filtered targets, and checks redaction/contrast at desktop/tablet/mobile; PR #413 filters events before relationship correlation so date-filtered exports never refer to omitted events. | Validate inferred correlation against real RouterOS/session-history timelines and retain the explicit completeness/gap caveat; complete durable RouterOS event history remains intentionally unclaimed. |
| [#196](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/196) | Completed for the repository scope: disposable-Redis outage/restart, ambiguous-delivery and idempotent-consumer tests (#224, #233); malformed-event classification, bounded retries and dead-letter metrics (#237); 45-event outage backlog draining (#238); pending-row recovery and explicit acknowledged-data-loss durability boundary (#240). Operations docs define at-least-once delivery, event-ID deduplication, Redis persistence requirements, and Redis-optional behavior. CI uses an isolated Redis instance and secret-free aggregate metrics are tested. |
| [#197](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/197) | Isolated backup/restore and interrupted-write/disk-full tests; bounded lock-timeout recovery and WAL checkpoint behavior (#228, #234); backup restore rehearsal opens a consistent point-in-time copy without touching the live source; backup-target failure preserves the prior backup and source database while cleaning temporary files (#257); concurrent multi-writer stress with repeated backup/checkpoint and restore integrity checks (#286). | Sustained deployment storage/lock soak, retention/restore operations, and a canary restore rehearsal. |
| [#198](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/198) | Process-observation freshness metrics and acceptance collection (#227, #232); slow outbound-client isolation test (#235); sequence-gap event-loss detection and integer validation in acceptance evidence (#283); idempotent Socket.IO reconnect handling (#288); CPU, memory, and storage observations are individually required (#300); browser regression verifies Socket.IO-to-SSE fallback and live snapshot at desktop/tablet/mobile (#318); acceptance evidence distinguishes duplicate sequence values from lower out-of-order arrivals and treats process-local counter resets as explicit epochs; bounded aggregate P95 gateway enqueue-to-authorized-poll delay is exposed for runtime diagnostics and Prometheus; PR #346 forces a current snapshot when a replay cursor is ahead of the restarted process's sequence; PR #373 detects interior replay gaps, recovers with a redacted snapshot, and orders out-of-order batches; deterministic supervisor regressions cover stream interruption/reconnect and snapshot synchronization failures with partial-snapshot suppression and bounded exponential retry. PR #385 preserved bounded exponential backoff until a full snapshot succeeds; PR #387 adds future-timestamp clock-skew visibility. The sustained evidence evaluator requires container health in every sample and one verification record covering all required checks; incomplete metrics/attestations fail closed. PR #466 adds aggregate gateway-delivery metrics and reset-aware acceptance reporting. This follow-up exposes fixed-cardinality supervisor state, reconnect/failure counters, and snapshot timestamps to Prometheus and the soak report; it is instrumentation only and requires publication/deployment before live data can be collected. On 2026-10-05, authenticated production observation confirmed Socket.IO live updates without page reload, but exposed a stale lower status-strip count. PR #455 fixes that count and adds SSE/Socket.IO browser regressions across desktop/tablet/mobile; it is merged and published, but the RouterOS updater stopped the candidate canary after about five seconds and restored the previous image. Both canary and production were subsequently observed healthy on the previous tag; no promotion occurred. The rejection cause is not yet known, so this is not deployed or accepted. | Device-backed end-to-end latency/freshness percentiles, actual RouterOS/API restart and snapshot recovery, complete event-integrity evidence, production proxy/browser sleep-wake soak, and rollback drill; diagnose the candidate readiness/startup rejection and deploy PR #455 through the existing canary gate before claiming the footer fix live; point-in-time deployment health and a single untimed session transition are not formal acceptance, and RouterOS does not expose a registry digest for independent on-device comparison. |
| [#199](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/199) | Read-only health/readiness/metrics evidence collector (#226, #232); PR #445 requires complete aggregate Redis/outbox and telemetry-observation metrics throughout both environments' acceptance windows, fails closed on missing/gapped metrics, and clears caller-supplied Redis success claims; PR #478 also fails closed on unknown latency/freshness/outbox metrics, pending outbox work, or observed dead letters; formal release v2.6.4 was published by run [37199225501](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/37199225501), with ARM64 digest `sha256:89b0b0d5a7f6b5d417d134fcaa04e442fbe88c4dfc11b49a8192bf152a404bd4` and AMD64 digest `sha256:0c39c558a3c293e59b836bb4601a41060d298048627804bc2559b65b1e0c5c95`; both builds, rendered-browser checks, runtime smoke, and exact-digest provenance/SBOM verification passed. The updater promoted the immutable ARM64 tag to production after canary health/stability checks, then recorded production healthy. A later authenticated production observation confirmed live Socket.IO updates without page reload. PR #455's subsequent candidate publication passed CI and ARM64 smoke, but RouterOS stopped the candidate canary after about five seconds and restored the previous image; production remained healthy on the prior tag. PR #492 adds a 30-sample one-minute /readyz guard to the repository updater example, but that example is not installed on the router. The latest timestamped 2026-10-05 WebFig read-back remains PR #484's immutable ARM64 tag healthy on both canary and production, with Redis running. PR #492 was published as `sha-a4f2cce829c8453a7b982307677d2d3173b94a90-arm64` / `sha256:682a6dc61aeb47cc0e0979ab03d3c4f30d8497f8f0fbb44282bef84267f7f373` and had no on-router read-back; it has since been superseded as the latest publication by PR #494, commit `03d08a2e6a08554c68cf74930049ac29ac0b3219`, ARM64 tag `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-03d08a2e6a08554c68cf74930049ac29ac0b3219-arm64`, digest `sha256:5d5645d7613f74081bb01e390d6201ba6230968de72248119b39c9a4274ecad4`; #494 is CI-verified/published but not read back on RouterOS. These are publication/container-health observations only: no full 30-minute sampled canary/production window, latency/freshness percentiles, Redis delivery and reconnect/snapshot/event-integrity evidence, or rollback drill has been completed. | Complete a full 30-minute sampled canary/production window with latency/freshness percentiles, Redis delivery and reconnect/snapshot/event-integrity evidence; controlled rollback drill; no router-side registry-manifest digest endpoint is available. |
| [#200](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/200) | Stream-session revalidation tests and scoped ASVS evidence map (#218, #229); SSE revalidates its authenticated RouterOS session and effective `sessions.read` capability before each telemetry write without extending idle lifetime; both ASGI and polling Socket.IO paths stop delivery when authorization changes mid-batch; PR #345 binds each polling SID to its initiating dashboard session and rejects cross-session reuse; API tokens require `sessions.read` for connection/usage exports and both `audit.read` plus `sessions.read` for compliance export; anonymous/missing-CSRF route matrices, sensitive `read_only` capability denials, same-origin guard (#287), ASGI foreign-Origin handshake tests, and literal/regex dispatch completeness check (#291); policy-template and saved-view GETs enforce `policies.read` / `sessions.read`; PR #347 inventories and tests the intentionally RouterOS-session-only, sanitized `/api/telemetry` status route; PR #351 adds SSE idle/absolute expiry and polling-expiry delivery-stop regressions; PR #353 corrects and pins the ASVS v5 authorization and WebSocket Origin references; PR #355 adds `health.read` inventory and token-allow/deny coverage for `/metrics` and redacted diagnostics; PR #374 enforces `health.read` on `/api/observability` and clarifies that route-dispatch/anonymous-CSRF coverage is not exhaustive role-by-role review; PR #377 gates server-rendered Change History rows and navigation on `audit.read` after independent review found a dashboard-only disclosure; PR #395 revalidates RouterOS account enabled state and group-derived role at 15-second intervals across authenticated requests and live transports, immediately applies downgrades, avoids silent privilege elevation, revokes missing/disabled accounts, and fails closed to read-only on lookup errors; saved-view creation/deletion now explicitly requires `sessions.read`; PR #414 expires idle polling clients and closes their gateway subscriptions on the next bridge request; PR #416 exercises every non-empty combination of the four API-token scopes across the scoped route matrix; PR #424 revalidates the RouterOS session and `sessions.read` authorization after a blocking live-session fetch and before persistence or SSE delivery, with a revocation-during-fetch regression; PR #450 re-read route authorization, token-scope, metrics/export, SSE, Socket.IO, and ASGI live-delivery paths at commit `9fb89ec`, added the current review record to [SECURITY_ASSURANCE.md](SECURITY_ASSURANCE.md), and passed all hosted CI including Python 3.13/3.14, rendered browser/accessibility, same-origin, Redis, dependency, secret, pre-commit, and ARM64 smoke checks. The 172 focused local security/app/ASGI tests also passed. The authenticated production Owner dashboard was rechecked on 2026-10-05 and showed live Socket.IO; this verifies normal authenticated proxy access for that session only. | Live-router role-change/expiry/revocation observation; exhaustive authorization review and full independent external security review remain required. |
| [#201](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/201) | Repository implementation complete: redacted read-only account/group/service diagnostics (#222); unknown or incomplete RouterOS group policy tokens produce an explicit unknown posture (#246); IPv4/IPv6 allowlist and catch-all coverage (#273); current `available-from` and legacy `address` service-property probes; PR #331 compares the active REST management source against configured account/service allowlists, reports ambiguous or unsupported responses as unknown, and redacts the source. Privacy, read-only behavior, RouterOS property-version differences, and official documentation are covered in tests/docs. | Physical firewall/input-chain and upstream network enforcement remain unknown until separately checked during RouterOS operational acceptance (#199); the diagnostic deliberately does not claim to prove them. |
| [#202](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/202) | Policy-template apply revalidates a session-bound preview receipt and current RouterOS state (#223); session termination reads back RouterOS state and reports verified, failed, or unknown outcomes; policy-template application now performs per-user RouterOS profile read-back and preserves local metadata only after verification (#250); user deletion verifies managed certificate revocation before account deletion and verifies account absence before clearing local metadata, reconciling lost responses and reporting unknown/partial outcomes (#261); single-user suspend/restore verifies the RouterOS `disabled` state before clearing local enforcement, reconciles lost PATCH responses, and distinguishes mismatch from unavailable read-back (#264); single-user edits verify RouterOS state before committing metadata, reconcile response loss and keep passwords unverifiable/partial (#265, #272); generated PPP rate-limit profile state is now bound into account-provision, edit, and policy-template review receipts, with exact `rate-limit` read-back after create/update; bulk suspend/revoke use read-back and preserve partial progress; device revocation and profile issuance require reviewed state and reconcile failures (#279, #282, #292, #293); account creation and duplication now preview copied/effective settings, exclude secrets from review display, and reject stale intent before mutation (#294); all review-first edit, policy apply, suspension, device revoke, profile issue, and account provision flows now use server-side atomic single-use receipts, with replay rejected and changed password values bound by a process-keyed commitment (#295); bulk suspend/revoke/tag bind receipts to selected users and relevant account/session/certificate/tag state, reject stale previews, and prevent replay (#298); account deletion now reviews the exact managed-certificate scope and consumes a one-time session-bound receipt before revocation/deletion, rejecting changed certificate inventories (#301); deletion review also binds dashboard-local metadata and clears account-scoped tags, policy assignment, controls, and email only after confirmed absence (#302); individual session termination now binds the exact live session identity to a single-use review receipt and rejects changed sessions before disconnecting (#303); access restoration also requires a one-time receipt bound to the disabled account state (#304); account-provisioning failure verifies account/certificate cleanup and compares generated PPP profile state against the reviewed snapshot, retaining shared-profile residue and reporting `partial`/`unknown` explicitly instead of falsely claiming complete recovery; failed profile issuance now reads back the uniquely named partial certificate after cleanup and reports unresolved RouterOS residue instead of silently ignoring a rejected DELETE; relative expiry selections now remain stable across review/apply second boundaries (#305); ambiguous individual session-termination DELETE responses are now reconciled by exact-session read-back even when the request response is lost (#317); the route-by-route mutation and local-write boundary is documented in [MUTATION_SAFETY.md](MUTATION_SAFETY.md). | Live-router acceptance across the supported release/model matrix and independent review of ambiguous/competing-operator scenarios; compensating recovery may remain partial/unknown because RouterOS has no cross-resource transaction. |
| [#203](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/203) | Immutable image tags, SPDX SBOM and provenance generation (#221); publication verifies each detached attestation against the exact image digest, expected signer workflow, and source commit (#249); installation docs distinguish CI smoke from hardware evidence, identify ARM64 deployment context, evaluation-only AMD64, unsupported ARM32, unverified RouterOS releases/models, and no universal resource minimums; workflow #332 splits Linux full verification from Windows browser regression, with both required before publishing; runtime revision `04d7d0b1cb653865d3bbe8c516c92b28ee0cb315` was published with ARM64 digest `sha256:d2b07cd6fcf4403a2d26212a2ce48a6c29846638d2a251c38be64e8b29faf6a3` and AMD64 digest `sha256:172e9b5803305d53dc2a74435231681309e7e5862e518da61a58c45395b448cf`; exact-digest provenance/SBOM verification, runtime smoke, and stable manifest update passed (run #37129113703). This is registry evidence, not a deployment claim. | RouterOS compatibility for this revision and other hardware/releases, independent on-router digest comparison, and measured per-device CPU/memory/storage baselines. |
| [#204](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/204) | Completed: authenticated, bounded, allowlisted diagnostic bundle with no RouterOS calls (#225); static, redacted RouterOS error guidance (#247); keyboard-accessible preview-before-download disclosure with explicit contents/exclusions and unchanged authenticated download (#256). Tests verify privacy exclusions, bounded export, no RouterOS dependency, and rendered desktop/tablet/mobile download behavior. |

**#199 release-acceptance follow-up (PR #495):** Adds separate
`canary-prepromotion` and `postpromotion` phases, phase-scoped GHCR digest
verification, a hard deadline for registry requests, and truthful handling of
the previous production image as a health/revision baseline only. This
read-only repository tooling does not collect RouterOS-only measurements,
perform a canary deployment/rollback, or complete the device-backed soak;
issue #199 remains open for those acceptance results.

**Security review finding closed in-repository (2026-10-05):** PR #474 fixed a
fail-open role-mapping edge case: if RouterOS returned a matching account
record without a `group`, login previously defaulted that account to Owner.
Missing, null, or blank group now maps to read-only, with regression coverage.
This does not close #200: live privilege-change/expiry/revocation acceptance
and a full independent external security review remain open.

**#200 follow-up audit (2026-10-05):** a separate read-only review found the
repository has tests for SSE/Socket.IO authorization stop, same-origin and
foreign-origin behavior, token scopes, idle/absolute expiry, and RouterOS role
revalidation. It found no new bypass, but the route inventory explicitly is
not an exhaustive independent handler-by-handler review. Production behavior
through the proxy for logout, revocation, expiry, role downgrade, and account
disable has not been observed. PR [#497](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/497)
adds same-origin login checks before RouterOS authentication, path/IP-free
application access logs, an explicit `users.read` guard, and accurate
disclosures/tests for sensitive authorized exports. It does not change the
production image or claim assurance about reverse-proxy/host logs, physical
RouterOS permissions, or production export handling. Issue #200 remains open
for the complete authorization review and controlled live-session security
acceptance. See [SECURITY_ASSURANCE.md](SECURITY_ASSURANCE.md) and
[ROUTE_AUTHORIZATION.md](ROUTE_AUTHORIZATION.md).

**Certificate lifecycle hardening:** the staged migration's connection-test
attestation now also requires a read-only observation that RouterOS currently
shows an active session for the matching VPN user. This is user-level evidence,
not proof of which client certificate the connection used; historic migration
records without this observation must be re-confirmed before revocation. The
existing import/test/retire workflow and exact RouterOS revocation read-back
remain in place. Live client/CRL/reconnect acceptance is still outstanding.

**Current deployment correction (2026-10-05; supersedes the earlier #198/#199
table snapshot below):** PR #455's first canary attempt
rolled back after about five seconds; the exact rejection cause is unknown.
The scheduled immutable updater later recovered and promoted the candidate.
After PR #457's successful publication, RouterOS also promoted
`sha-0f41d723b9431fd73b0fa97f113c4f764d2f7034-arm64` through canary to
production. Registry digest:
`sha256:2ed6842ab0493f772f3fdfd7cf3d08ce5f1bc8db31939e6d97aac29623684a4c`.
Read-only WebFig showed both containers healthy on that tag, container logs
showed `/readyz` HTTP 200 after production start, and the authenticated
Dashboard reported live updates with matching zero counts in its main card and
footer. This does not demonstrate a nonzero session transition or satisfy the
long-window telemetry/Redis acceptance gates. PR #457's bounded, secret-free
readiness diagnostics are in the repository updater example but have not been
installed into the separate router-local script. See
[the acceptance report](LIVE_TELEMETRY_ACCEPTANCE_REPORT.md) for detailed
publication, digest, and health evidence.

The repository updater template is now being strengthened to require 30
successful `/readyz` samples at one-minute intervals before automatic
promotion. This is only a repeated readiness guard; it does not replace the
full telemetry/Redis/resource acceptance evidence above, and no router-local
updater script was changed as part of this repository work.

**Follow-up live-stream check (2026-10-05, approximately 02:03–02:04
Europe/Sofia):** after the operator reconnected to the management VPN, two
authenticated production Dashboard observations about 75 seconds apart, with
no page reload, both showed `Live · SOCKETIO` and `Operational` service health.
Router uptime advanced and the CPU sample changed. Both connected-user counts
remained zero, so this is live health-update evidence only—not proof of
session-event delivery or nonzero count synchronization. Resource samples were
below documented cutoffs; exact values remain private. The 30-minute soak,
latency/freshness percentiles, Redis delivery, RouterOS API restart/snapshot
recovery, event-integrity verification, and rollback drill remain open. At
02:23:57, 30 minutes had elapsed since production start and the dashboard still
reported live/operational with both session counts at zero. This was an elapsed
time checkpoint with spot checks, not a continuous sampled soak; #199 remains
open.

**Read-only management-VPN follow-up (2026-10-05, about 02:50–02:51
Europe/Sofia):** the authenticated Dashboard remained `Live · SOCKETIO` and
`Operational`; uptime and CPU changed between views without a page reload, and
the connected-session count remained zero. RouterOS logs showed successful
`/readyz` responses for canary and production, and a successful scheduled Redis
RDB save. This supplements point-in-time health/persistence evidence only; it
does not measure a VPN-client event, Redis stream delivery/recovery, API
restart/snapshot recovery, or formal soak. No router configuration or container
was changed. See the [acceptance report](LIVE_TELEMETRY_ACCEPTANCE_REPORT.md).

**Latest browser/API access gate (2026-10-05, about 03:17–03:19 Europe/Sofia):**
the already-rendered production Dashboard showed `Connection data delayed`,
and its console repeatedly recorded `TypeError: Failed to fetch` from the
`/api/status` poll. A separate direct navigation to that endpoint was
redirected to Cloudflare Access login. The response status/body was not
captured, so the exact failure layer is unproven; this is consistent with an
expired or unavailable Access session, not evidence of a RouterOS or Redis
failure. RouterOS local `/readyz` checks still returned HTTP 200, which does
not establish authenticated status or live-event delivery. The existing page
was not reloaded, no login code was submitted, and RouterOS/containers were
not changed. The older PR #455 “not deployed” note in the issue table is
superseded by the later successful scheduled rollout and PR #457 image
read-back above; this new Access-gated observation supersedes the earlier
02:50–02:51 “Live · SOCKETIO” observation as the latest browser state. Do not
resume or pass live acceptance until authenticated API access is restored.
See the [acceptance report](LIVE_TELEMETRY_ACCEPTANCE_REPORT.md).

**Authenticated access follow-up (2026-10-05, about 03:37–03:39
Europe/Sofia):** the already-open production Dashboard was observed twice
about 75 seconds apart without a manual refresh. It reported `Live · SOCKETIO`
or `Live · updated now` and `Operational`; Router uptime advanced and the CPU
sample changed. The connected-session count remained zero. This supersedes
the earlier Access-gated page as the latest browser observation and confirms
live health updates for that authenticated browser session. No login code was
entered and no router/container state was changed. It does not provide a
nonzero VPN session, event latency, traffic freshness, Redis delivery,
reconnect/recovery, or a sustained acceptance window; #198/#199 remain open.
See the [acceptance report](LIVE_TELEMETRY_ACCEPTANCE_REPORT.md).

**Fresh authenticated deployment check (2026-10-05, about 05:08
Europe/Sofia):** the prior dashboard tab had expired at Cloudflare Access and
was showing stale status/release data. After re-authenticating and loading a
fresh page, the Dashboard reported `Live · updated now` and `Operational`; the
dashboard's baked running revision matched the RouterOS container's immutable
ARM64 tag `sha-dd4a1fa34b6ff33092e4e2afc9ce334c8931a8b0-arm64`, and the locally
recorded previous release matched `73e6dd44c53f96504f6a505c0e9667976ef0a7db`.
Both canary and production were healthy on that tag. No VPN client was
connected. This resolves the apparent revision mismatch as stale browser state;
it remains a point-in-time check and does not satisfy the sustained telemetry,
live-session, reconnect, or rollback acceptance window. No RouterOS/VPN
configuration or data was changed.

**Acceptance evidence integrity:** merged PR #461 requires reconnect,
comparison, security, and verification attestations to carry timestamps within
the same strictly increasing sample window; missing timestamps,
stale/out-of-window attestations, or an unverifiable sample interval fail
closed. The current follow-up also validates `counter_reset` and
`counter_reset_recovered` as booleans whenever supplied, including false-like
values. These evaluator safeguards prevent malformed or stale evidence from
passing; they do not create or substitute for the still-pending router-side
measurements and recovery drills.

Merged PR [#473](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/473)
(commit `82ede5bdaa2c632eaa674af2075e2dbfecdfea60`) makes the final release
acceptance validator honor the live collector's `passed` result and failed
gates; malformed collection status is rejected. Python 3.13/3.14,
pre-commit, browser/accessibility, Redis, security, secret-scan, and ARM64
runtime-smoke checks passed. This is tooling and acceptance-integrity work, not
a runtime image change and not completion of the open #199 canary/production
evidence requirements.

**Acceptance collector gateway-stage metrics:** the collector now requires and
reports the existing aggregate gateway client/buffer gauges, published and
replayed event counts, snapshot-recovery and rejected-client counters, delivery
queue observations, and latest/P95 enqueue-to-authorized-poll delay. It
calculates counter deltas/reset flags and distinguishes unknown (`-1`) queue
age from fresh observations. This adds delivery-stage evidence to #199 while
explicitly not labeling it end-to-end RouterOS-to-browser latency. No runtime
or RouterOS change is included; the live acceptance gates remain open.
See [production observability](OBSERVABILITY.md).

**Latest timestamped RouterOS read-back (2026-10-05):** WebFig showed PR #484's
immutable ARM64 tag `sha-93627bca38312ad1845249c6df1c0fcecf12122e-arm64` on
both canary and production, each healthy (`H`), with Redis running (`R`). Its
registry digest is `sha256:01872672a9093ac999272c0be0cf97bf27c2139af1cde90f41b501ac4995ba73`;
RouterOS reports the tag, not an independent digest. A separate 2026-10-05
System > Resources sample recorded CPU, memory, and storage below the current
cutoffs; exact values remain in the operator-local private record. These are
point-in-time observations, not a sustained baseline. PR #494 is the latest
published image but has no timestamped on-router read-back; PR #492 also has no
such read-back, and its updater example has not been installed. An undated
screenshot shows `Live · SOCKETIO`
and zero sessions but has no readable immutable image tag; it is not used as
post-publication or formal acceptance evidence. None of these observations
satisfies #198/#199 acceptance or a rollback drill.

Historical v2.6.4 registry publication and RouterOS rollout (2026-10-04):
formal release **v2.6.4**, commit `9671f27db9e5bad61323378fcdab51fca3d39a8b`,
is published by run
[37199225501](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/37199225501).
Both architecture builds, rendered-browser validation, runtime smoke tests,
exact-digest provenance/SBOM verification, and stable-manifest publication
passed. ARM64 tag/digest:
`sha-9671f27db9e5bad61323378fcdab51fca3d39a8b-arm64` /
`sha256:89b0b0d5a7f6b5d417d134fcaa04e442fbe88c4dfc11b49a8192bf152a404bd4`.
AMD64 tag/digest: `sha-9671f27db9e5bad61323378fcdab51fca3d39a8b-amd64` /
`sha256:0c39c558a3c293e59b836bb4601a41060d298048627804bc2559b65b1e0c5c95`.
The RouterOS updater started canary at 14:46:26, observed it healthy during
the configured stability window, promoted production at 14:48:50, and logged
promotion complete at 14:49:01 Europe/Sofia. Subsequent readiness probes
returned HTTP 200; Redis remained running. This confirms configured tags and
point-in-time health, not an on-router registry digest comparison or formal
sustained acceptance. No resource baseline was measured. Event latency/freshness
percentiles, API-restart recovery, event integrity, and rollback results remain
open. See
[LIVE_TELEMETRY_ACCEPTANCE_REPORT.md](LIVE_TELEMETRY_ACCEPTANCE_REPORT.md)
for the current acceptance limits.

The subsequent profile-issuance clarification in PR #429 was published by
workflow run [37203288349](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/37203288349).
Its ARM64 image tag is
`sha-b435b0419832d26b15221b36434aae30766a4d65-arm64`, with registry manifest
digest
`sha256:df747beb85827e338cfdbf69f6a2749b36a2fd74ef7e40d41991944dad9675e1`.
RouterOS logs show canary readiness (`/readyz` HTTP 200), production promotion
at 15:58:54, production readiness (`/readyz` HTTP 200), and updater completion
at 15:59:05 Europe/Sofia on 2026-10-04; subsequent production readiness also
returned HTTP 200. The restart invalidated the browser login, so no authenticated
post-restart UI check is claimed. This rollout record does not include a
resource baseline, live certificate/CRL acceptance, or formal sustained
telemetry acceptance.

PR #434 subsequently completed the repository-side staged migration guidance
and was merged as `bd9be4e25831e53c84b89fe2e332d27bf9c985c7`. Its ARM64 image
was published by run
[37209541229](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/37209541229)
with tag
`sha-bd9be4e25831e53c84b89fe2e332d27bf9c985c7-arm64` and registry digest
`sha256:99e2f3cb9a0cd2542b677ccc15c286ae564f415c19453aabbdd7b30cdf5acdc8`.
Read-only RouterOS WebFig read-back showed that tag on the canary and production
containers with healthy status. This is rollout evidence, not a fresh `/readyz`
assertion or end-to-end certificate acceptance. Import and connection-test
steps are operator attestations; RouterOS inventory cannot establish which
certificate an existing VPN session used. The formal application version at
that image was v2.6.4. The subsequent v2.7.0 release records the merged profile
recovery and staged migration improvements; its publication and sanitized
RouterOS tag/health read-back are documented at the top of this roadmap and in
`LIVE_TELEMETRY_ACCEPTANCE_REPORT.md`.

An earlier `routeros-stable` manifest was refreshed by publication run
[37085223385](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/37085223385)
for runtime commit `01055d4efdc041c2443f41e08235896bf6f4f754`. Its ARM64 image
digest is `sha256:9d9dbc94712c09a7bf40106a6a92145f36b37344255da3730c6630fb5317284f`
and AMD64 digest is
`sha256:c767d441492c17189d2d7fd478a66f1b81882f7ee194222adffc2e75b5f1aa54`.
Both architecture jobs passed exact-digest provenance/SBOM verification and
runtime smoke tests. On 2026-10-03, RouterOS read-back showed both canary and
production using the immutable ARM64 tag for `01055d4`, with both containers
healthy; the router updater also logged production already on the approved
image. This verifies the deployed revision tag, not the local image's content
digest. The full 30-minute acceptance window and rollback rehearsal remain
pending, and public readiness remains gated behind Cloudflare Access.

Unauthenticated edge check for #200 (2026-10-04): direct HTTPS GET requests to
the public root, event, observability, operations-timeline, and metrics routes
each returned HTTP 302 before redirects were followed; the browser showed
Cloudflare Access. This is a point-in-time edge-gate observation only, not
proof of backend anonymous-route denial, authenticated role enforcement,
cross-origin behavior, or live-session revocation. The authenticated dashboard
check and live RouterOS authorization-expiry/revocation exercise remain open.

Additional repository work merged on 2026-10-03: PR #328 added exact account
and session read-back, persisted pending intent, secret-safe partial/unknown
automation outcomes, recovery tests, and keyboard/reflow browser checks for
#192 and #202. Its main-branch browser run exposed a 30px page-level horizontal
scroll leak at narrow widths from the intentionally scrollable mobile
navigation. PR #329 fixed this by clipping only root-level horizontal
overflow, preserving the navigation's own scrolling, and added a browser
assertion for both behaviors. PR #329 merged after the rendered-browser suite
passed on desktop, tablet, and mobile. No router deployment was performed.

The #328 commit image was auto-published by run
[37123588437](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/37123588437),
despite that run's browser job failing (the fix is in #329). The publish jobs
passed image smoke and exact-digest provenance/SBOM verification: ARM64
`sha256:6100629c3409941643c950e8d4fe2216cc4174440fa7ba9061a88b326020c472`,
AMD64 `sha256:ee10346ae3464a2deaca355ecb76a022f002a69c3c1a8f424f758c4b02ef0235`.
This image has not been verified on RouterOS and must not be described as
deployed. PR #330 adds the complete rendered-browser suite to the release
workflow's own verification gate so image publication cannot advance the
stable manifest when the browser suite is red. That process hardening remains
in review until the PR and its CI finish.

Each issue is delivered as a focused PR with CI and acceptance evidence. Dependency order may pull security or reliability work forward when required to make a feature safe. Core live telemetry, REST/SSE fallback, RouterOS as source of truth, redaction, and review-first destructive actions remain product invariants.

**Current release acceptance update (2026-10-05):** PR #495 merged the
read-only acceptance collector's explicit canary-prepromotion and
postpromotion phases, candidate-only prepromotion registry verification, and
bounded registry lookup. It is acceptance tooling, not a runtime image change.
Read-only WebFig now confirms PR #494's immutable ARM64 tag on both canary and
production with healthy container states; the registry digest is recorded in
the acceptance report, but RouterOS does not independently expose or verify
that digest. An older rendered dashboard tab showed `Connection data delayed`
and an Access challenge; a fresh Dashboard tab then loaded authenticated from
the existing browser session and showed `Live · SOCKETIO` with changing health
samples over 75 seconds and no manual refresh. The Connections view also
reported the Socket.IO transport live and its five-second graph cadence. This
verifies live health updates and transport indication in that session only,
not VPN-session events or traffic freshness under load. See [the current
acceptance report](LIVE_TELEMETRY_ACCEPTANCE_REPORT.md).

Issue #199 remains open: no nonzero VPN-client transition or continuous
30-minute telemetry/Redis sample series has been collected in this window;
event latency/freshness, reconnect and full-snapshot recovery, event
integrity, and a canary rollback/restore drill are still unproven. Do not
promote a candidate or mark acceptance complete on container health alone.
