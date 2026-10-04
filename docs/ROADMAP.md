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
| [#192](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/192) | CI checks focus visibility, reduced motion, forced colors, and responsive CSS (#220); rendered Chromium screenshot baselines cover Dashboard, VPN Users, and Connections at desktop/tablet/mobile sizes; the test gate forbids re-baselining serious contrast regressions; forced-colors rendering verifies keyboard focus, navigation, and primary action visibility at all three viewports; browser checks verify keyboard-only activation/current-view indication across the primary views plus 720 CSS-pixel zoom-equivalent reflow without page-level horizontal overflow; PR #348 adds light-theme axe checks and fixes 127 serious contrast findings plus Add-user dialog keyboard/focus/validation/Escape coverage; PR #384 expands axe scans to ten operator views at desktop/tablet/mobile and fixes low-contrast secondary text and inaccessible scroll regions in Device Profiles, Service Health, Policy Templates, and Change History; PR #389 verifies reduced-motion animation/transition suppression and non-smooth scrolling in the rendered Add VPN user dialog at all three viewports. A five-task usability protocol with success/error criteria and before/after measurement guidance is documented in [ACCESSIBILITY.md](ACCESSIBILITY.md). | Run and record the human task study; assistive-technology review; manual actual-200%-browser-zoom inspection. Automated checks are not an accessibility-conformance claim. |
| [#194](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/194) | Expiry-aware certificate inventory and carefully scoped posture language (#231); managed per-device revocation now uses RouterOS `issued-revoke`, confirms the exact certificate's revoked timestamp by read-back before changing local state, and reports mismatch/unknown safely (#254). | Staged renewal/re-download and hardware proof of CRL enforcement, active-session handling, and rejection after reconnect; #254 does not claim these live outcomes. |
| [#195](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/195) | Change History is explicitly a bounded dashboard audit view, not a complete RouterOS event timeline (#230); actionable alerts deduplicate by action/target and cap new records while retaining every durable audit record (#274); dashboard audit, health, and deployment observations are joined into a searchable/filterable bounded timeline with age, source, coverage warning, and `audit.read`-gated redacted JSON export; audit timeline IDs now use stable local audit-row IDs; bounded status-only Redis outbox delivery events are included for `audit.read` viewers (#315); session snapshot history now joins through non-causal account/time and nearby health/deployment context, with inferred/absence-observed timestamp labels and a dual `audit.read` + `sessions.read` JSON export gate (#321); rendered browser coverage verifies event-type, text, and local-calendar date-range filtering, and the selected end date uses DST-safe calendar-day arithmetic; PR #372 adds recurrence count, last-seen updates, and severity escalation for active alert groups, without claiming cross-source incident correlation; PR #392 adds accessible navigation between related timeline events, retains links and keyboard focus through live refresh, reveals filtered targets, and checks redaction/contrast at desktop/tablet/mobile. | Validate the correlation behavior against real RouterOS/session-history timelines and retain the explicit completeness/gap caveat; complete durable RouterOS event history remains intentionally unclaimed. |
| [#196](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/196) | Completed for the repository scope: disposable-Redis outage/restart, ambiguous-delivery and idempotent-consumer tests (#224, #233); malformed-event classification, bounded retries and dead-letter metrics (#237); 45-event outage backlog draining (#238); pending-row recovery and explicit acknowledged-data-loss durability boundary (#240). Operations docs define at-least-once delivery, event-ID deduplication, Redis persistence requirements, and Redis-optional behavior. CI uses an isolated Redis instance and secret-free aggregate metrics are tested. |
| [#197](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/197) | Isolated backup/restore and interrupted-write/disk-full tests; bounded lock-timeout recovery and WAL checkpoint behavior (#228, #234); backup restore rehearsal opens a consistent point-in-time copy without touching the live source; backup-target failure preserves the prior backup and source database while cleaning temporary files (#257); concurrent multi-writer stress with repeated backup/checkpoint and restore integrity checks (#286). | Sustained deployment storage/lock soak, retention/restore operations, and a canary restore rehearsal. |
| [#198](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/198) | Process-observation freshness metrics and acceptance collection (#227, #232); slow outbound-client isolation test (#235); sequence-gap event-loss detection and integer validation in acceptance evidence (#283); idempotent Socket.IO reconnect handling (#288); CPU, memory, and storage observations are individually required (#300); browser regression verifies Socket.IO-to-SSE fallback and live snapshot at desktop/tablet/mobile (#318); acceptance evidence distinguishes duplicate sequence values from lower out-of-order arrivals and treats process-local counter resets as explicit epochs; bounded aggregate P95 gateway enqueue-to-authorized-poll delay is exposed for runtime diagnostics and Prometheus; PR #346 forces a current snapshot when a replay cursor is ahead of the restarted process's sequence; PR #373 detects interior replay gaps, recovers with a redacted snapshot, and orders out-of-order batches; deterministic supervisor regressions cover stream interruption/reconnect and snapshot synchronization failures with partial-snapshot suppression and bounded exponential retry. PR #385 preserved bounded exponential backoff until a full snapshot succeeds; PR #387 adds future-timestamp clock-skew visibility. On 2026-10-04, RouterOS read-back confirmed canary and production configured with `297d960` and both healthy. | Device-backed end-to-end latency/freshness percentiles, actual RouterOS/API restart and snapshot recovery, complete event-integrity evidence, production proxy/browser sleep-wake soak, and rollback drill; the point-in-time deployment/health read-back is not the formal acceptance window. |
| [#199](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/199) | Read-only health/readiness/metrics evidence collector (#226, #232); 2026-10-04 RouterOS read-back confirmed canary and production configured with immutable tag `sha-297d9607a070dfe71a2b8c15075ef739127eb8ce-arm64`, both healthy, and Redis running. Publication run [37166529360](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/37166529360) passed ARM64/AMD64 build, runtime smoke, and exact-digest provenance/SBOM verification; published ARM64 digest `sha256:ddcf57b91b9daa31c962c9e63fbbff2db5adea3ce4f18c349396a04f4d2699fd`, AMD64 digest `sha256:2a50bcfd6bbdbfca68b6af1c95df196d5fde7495d3ab3e52183b5703cf9802a9`. No post-promotion resource sample was recorded. | Full 30-minute sampled canary/production window with latency/freshness percentiles, Redis delivery and reconnect/snapshot/event-integrity evidence; authenticated browser verification after the restart; controlled rollback drill; router-side registry-manifest digest comparison. |
| [#200](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/200) | Stream-session revalidation tests and scoped ASVS evidence map (#218, #229); SSE revalidates its authenticated RouterOS session and effective `sessions.read` capability before each telemetry write without extending idle lifetime; both ASGI and polling Socket.IO paths stop delivery when authorization changes mid-batch; PR #345 binds each polling SID to its initiating dashboard session and rejects cross-session reuse; API tokens require `sessions.read` for connection/usage exports and both `audit.read` plus `sessions.read` for compliance export; anonymous/missing-CSRF route matrices, sensitive `read_only` capability denials, same-origin guard (#287), ASGI foreign-Origin handshake tests, and literal/regex dispatch completeness check (#291); policy-template and saved-view GETs enforce `policies.read` / `sessions.read`; PR #347 inventories and tests the intentionally RouterOS-session-only, sanitized `/api/telemetry` status route; PR #351 adds SSE idle/absolute expiry and polling-expiry delivery-stop regressions; PR #353 corrects and pins the ASVS v5 authorization and WebSocket Origin references; PR #355 adds `health.read` inventory and token-allow/deny coverage for `/metrics` and redacted diagnostics; PR #374 enforces `health.read` on `/api/observability` and clarifies that route-dispatch/anonymous-CSRF coverage is not exhaustive role-by-route review; PR #377 gates server-rendered Change History rows and navigation on `audit.read` after independent review found a dashboard-only disclosure. | Deployed signed-in proxy/browser checks and live-router session lifecycle evidence. |
| [#201](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/201) | Repository implementation complete: redacted read-only account/group/service diagnostics (#222); unknown or incomplete RouterOS group policy tokens produce an explicit unknown posture (#246); IPv4/IPv6 allowlist and catch-all coverage (#273); current `available-from` and legacy `address` service-property probes; PR #331 compares the active REST management source against configured account/service allowlists, reports ambiguous or unsupported responses as unknown, and redacts the source. Privacy, read-only behavior, RouterOS property-version differences, and official documentation are covered in tests/docs. | Physical firewall/input-chain and upstream network enforcement remain unknown until separately checked during RouterOS operational acceptance (#199); the diagnostic deliberately does not claim to prove them. |
| [#202](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/202) | Policy-template apply revalidates a session-bound preview receipt and current RouterOS state (#223); session termination reads back RouterOS state and reports verified, failed, or unknown outcomes; policy-template application now performs per-user RouterOS profile read-back and preserves local metadata only after verification (#250); user deletion verifies managed certificate revocation before account deletion and verifies account absence before clearing local metadata, reconciling lost responses and reporting unknown/partial outcomes (#261); single-user suspend/restore verifies the RouterOS `disabled` state before clearing local enforcement, reconciles lost PATCH responses, and distinguishes mismatch from unavailable read-back (#264); single-user edits verify RouterOS state before committing metadata, reconcile response loss and keep passwords unverifiable/partial (#265, #272); generated PPP rate-limit profile state is now bound into account-provision, edit, and policy-template review receipts, with exact `rate-limit` read-back after create/update; bulk suspend/revoke use read-back and preserve partial progress; device revocation and profile issuance require reviewed state and reconcile failures (#279, #282, #292, #293); account creation and duplication now preview copied/effective settings, exclude secrets from review display, and reject stale intent before mutation (#294); all review-first edit, policy apply, suspension, device revoke, profile issue, and account provision flows now use server-side atomic single-use receipts, with replay rejected and changed password values bound by a process-keyed commitment (#295); bulk suspend/revoke/tag bind receipts to selected users and relevant account/session/certificate/tag state, reject stale previews, and prevent replay (#298); account deletion now reviews the exact managed-certificate scope and consumes a one-time session-bound receipt before revocation/deletion, rejecting changed certificate inventories (#301); deletion review also binds dashboard-local metadata and clears account-scoped tags, policy assignment, controls, and email only after confirmed absence (#302); individual session termination now binds the exact live session identity to a single-use review receipt and rejects changed sessions before disconnecting (#303); access restoration also requires a one-time receipt bound to the disabled account state (#304); account-provisioning failure verifies account/certificate cleanup and compares generated PPP profile state against the reviewed snapshot, retaining shared-profile residue and reporting `partial`/`unknown` explicitly instead of falsely claiming complete recovery; failed profile issuance now reads back the uniquely named partial certificate after cleanup and reports unresolved RouterOS residue instead of silently ignoring a rejected DELETE; relative expiry selections now remain stable across review/apply second boundaries (#305); ambiguous individual session-termination DELETE responses are now reconciled by exact-session read-back even when the request response is lost (#317); the route-by-route mutation and local-write boundary is documented in [MUTATION_SAFETY.md](MUTATION_SAFETY.md). | Live-router acceptance across the supported release/model matrix and independent review of ambiguous/competing-operator scenarios; compensating recovery may remain partial/unknown because RouterOS has no cross-resource transaction. |
| [#203](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/203) | Immutable image tags, SPDX SBOM and provenance generation (#221); publication verifies each detached attestation against the exact image digest, expected signer workflow, and source commit (#249); installation docs distinguish CI smoke from hardware evidence, identify ARM64 deployment context, evaluation-only AMD64, unsupported ARM32, unverified RouterOS releases/models, and no universal resource minimums; workflow #332 splits Linux full verification from Windows browser regression, with both required before publishing; runtime revision `04d7d0b1cb653865d3bbe8c516c92b28ee0cb315` was published with ARM64 digest `sha256:d2b07cd6fcf4403a2d26212a2ce48a6c29846638d2a251c38be64e8b29faf6a3` and AMD64 digest `sha256:172e9b5803305d53dc2a74435231681309e7e5862e518da61a58c45395b448cf`; exact-digest provenance/SBOM verification, runtime smoke, and stable manifest update passed (run #37129113703). This is registry evidence, not a deployment claim. | RouterOS compatibility for this revision and other hardware/releases, independent on-router digest comparison, and measured per-device CPU/memory/storage baselines. |
| [#204](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/204) | Completed: authenticated, bounded, allowlisted diagnostic bundle with no RouterOS calls (#225); static, redacted RouterOS error guidance (#247); keyboard-accessible preview-before-download disclosure with explicit contents/exclusions and unchanged authenticated download (#256). Tests verify privacy exclusions, bounded export, no RouterOS dependency, and rendered desktop/tablet/mobile download behavior. |

Latest stable registry publication (2026-10-04): the public `routeros-stable`
manifest points to commit `015ee9278adb1f438fdae9e6a82397f4cfcbaca6`, published
by [run 37171199073](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/37171199073).
ARM64 digest: `sha256:b53d519b3d427d3dbd4c789c882e82cc7ead2406c27af906ed69a3409f45c2b6`.
AMD64 digest: `sha256:dcd9f10de3786c894feadd3100f09ad6c83575ba0075c9c1ae26423951ce6ec9`.
Both architectures, runtime smoke tests, and exact-digest provenance/SBOM
verification passed. The last RouterOS read-back confirmed canary and production
on the previous `297d960` immutable ARM64 tag and healthy, with Redis running;
deployment and health for `015ee92` are not yet verified. Registry publication
is not deployment or acceptance evidence, and does not establish sustained
SLOs or an independent digest comparison on the router. See
[LIVE_TELEMETRY_ACCEPTANCE_REPORT.md](LIVE_TELEMETRY_ACCEPTANCE_REPORT.md)
for the current acceptance limits.

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
