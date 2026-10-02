# Public roadmap

The project is developed public-first: generic features are designed, tested,
and released here before an operator optionally evaluates them in a private
canary. This source repository never receives router credentials, live user
data, deployment runners, or production network details.

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
OpenVPN service, profile-issuance prerequisites, certificate state, and router
capacity into one read-only view. Each result explains its impact and a safe
next step; it never changes RouterOS automatically. Per-user quota and schedule
alerts remain visible in the normal dashboard alert list.

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

### Execution status — 2026-10-03

The issues below remain open until their full acceptance criteria are met; these
are verified partial milestones, not issue completions:

| Issue | Merged evidence | Still required |
| --- | --- | --- |
| [#192](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/192) | CI checks focus visibility, reduced motion, forced colors, and responsive CSS (#220). | Rendered browser/accessibility regression and human task validation. |
| [#194](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/194) | Expiry-aware certificate inventory and carefully scoped posture language (#231). | Staged renewal/re-download and hardware proof of CRL enforcement, active-session handling, and rejection after reconnect. |
| [#195](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/195) | Change History is explicitly a bounded dashboard audit view, not a complete RouterOS event timeline (#230). | Privacy-safe source/freshness correlation and incident identity with notification dedup that never suppresses durable audit. |
| [#196](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/196) | Disposable-Redis outage/restart, ambiguous-delivery and idempotent-consumer tests (#224, #233); malformed-event classification, bounded retries and dead-letter metrics (#237); 45-event outage backlog draining (#238); pending-row recovery after Redis stream-state loss (#240). The durability boundary is explicit: acknowledged stream entries are not rebuilt from SQLite after Redis data loss because downstream effects may already have occurred; Redis persistence/backups are required. | Add real-Redis fault coverage for acknowledged-data loss; verify downstream production consumer idempotency and complete canary/production outage/recovery soak evidence. |
| [#197](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/197) | Isolated backup/restore and interrupted-write/disk-full tests; bounded lock-timeout recovery and WAL checkpoint behavior (#228, #234). | Sustained storage/lock stress, retention/restore operations, and a canary restore rehearsal. |
| [#198](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/198) | Process-observation freshness metrics and acceptance collection (#227, #232); slow outbound-client isolation test (#235). | Device-backed latency/freshness percentiles, reconnect/snapshot and event-integrity tests, and proxy/browser recovery soak. |
| [#199](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/199) | Read-only health/readiness/metrics evidence collector (#226, #232); 2026-10-03 canary soak and production repull both reported the a9deb20 image revision healthy, with `/readyz` checks passing. The GHCR ARM64 digest is recorded in `LIVE_TELEMETRY_ACCEPTANCE_REPORT.md`; zero active PPP/OpenVPN sessions were observed before the production repull. | Full 30-minute sampled canary/production window with latency/freshness percentiles, Redis delivery, reconnect/snapshot and event-integrity evidence; router-side manifest-digest verification and canary rollback drill. |
| [#200](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/200) | Stream-session revalidation tests and scoped ASVS evidence map (#218, #229). | Full route authorization review, independent assessment, deployed proxy/browser checks, and live-router session lifecycle evidence. |
| [#201](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/201) | Redacted read-only account/group/service diagnostics (#222). | Effective source/network-boundary verification and tested least-privilege mapping; firewall enforcement remains unknown until independently checked. |
| [#202](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/202) | Policy-template apply revalidates a session-bound preview receipt and current RouterOS state (#223); session termination reads back RouterOS state and reports verified, failed, or unknown outcomes. | Apply/verify/recovery consistency across user, device, certificate, policy, and bulk mutations; review and recovery guidance for partial outcomes. |
| [#203](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/203) | Immutable image tags, SBOM/provenance verification, and compatibility documentation (#221). | RouterOS hardware compatibility and resource baselines. |
| [#204](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/204) | Authenticated, bounded, allowlisted diagnostic bundle with no RouterOS calls (#225). | Broader rendered UX review and remaining actionable error guidance. |

The current `routeros-stable` manifest targets runtime commit
`a9deb20a50363712fa8c65f933163f2ffd5678ce`; its ARM64 image digest is
`sha256:99f85730776a95c486bd3b212bb4a590a854961a64a5cf8448cccf2254f392bc`.
On 2026-10-03, RouterOS showed this exact image revision and healthy
`/readyz` checks on both canary and production after a 60-second canary soak
and production repull. The GHCR manifest digest is verified by the publication
workflow, but the inspected RouterOS UI does not expose that registry digest
for independent on-device comparison. This is partial deployment evidence,
not completion of #199's long-window acceptance criteria; public readiness
remains gated behind Cloudflare Access.

Each issue is delivered as a focused PR with CI and acceptance evidence. Dependency order may pull security or reliability work forward when required to make a feature safe. Core live telemetry, REST/SSE fallback, RouterOS as source of truth, redaction, and review-first destructive actions remain product invariants.
