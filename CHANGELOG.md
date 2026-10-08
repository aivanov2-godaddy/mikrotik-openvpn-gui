# Changelog

All notable operator-visible changes are recorded here. The project follows the
principles of [Keep a Changelog](https://keepachangelog.com/) and uses
semantic-version style release tags.

## Unreleased

### Added

- Offer staged same-CA renewal for expiring or expired dashboard-managed device
  certificates; retain the old certificate until the replacement is imported,
  tested, and separately retired through the existing review and read-back flow.

### Changed

- Reject the reserved `.invalid` hostname for `PUBLIC_ORIGIN` in runtime config
  and RouterOS installation/canary plans, preventing a placeholder endpoint
  from being accepted as a deployable dashboard origin.
- Remove the certificate-specific reconnect-report action: RouterOS can confirm
  certificate revocation and user-level sessions, but cannot prove which
  certificate a session used. Historical reports remain explicitly unverified.
- Require at least 30 candidate readiness samples, at least 60 seconds apart,
  before the RouterOS release updater automatically promotes a canary image.
  Any failed sample rolls the canary back without changing production.
- Clarify that readiness-only sampling does not replace the full telemetry,
  Redis, resource, reconnect, event-integrity, and rollback acceptance report.

### Fixed

- Keep the live-telemetry indicator governed by recent stream snapshots instead
  of letting a failed five-second full-status poll overwrite a fresh SSE or
  Socket.IO update. The delayed state remains visible when no recent stream
  snapshot is available.

### Tests

- Guard the updater's minimum 30-minute sampled readiness gate and rollback
  ordering before production promotion.
- Verify repeated status-poll failures do not turn a recently updated Socket.IO
  connection indicator into a delayed state.

## 2.7.0 - 2026-10-04

### Added

- Guided, per-device certificate migration: issue a replacement profile, record
  operator-attested import and connection-test steps, and keep the old
  certificate active until its separately reviewed revocation.
- Device Profiles identifies the exact replacement certificate and clarifies
  that RouterOS inventory cannot prove which certificate a live client session
  used. Lost-profile recovery issues a new identity rather than re-downloading
  a private key that the dashboard does not retain.

### Tests

- Verify migration-step ordering, current-CA and active-certificate read-back,
  audit attribution, stale/re-issued migration handling, and that progress
  records do not claim RouterOS verified client import or session identity.

## 2.6.4 - 2026-10-04

### Fixed

- Revalidate the authenticated RouterOS session and `sessions.read`
  authorization after the blocking RouterOS session fetch and before saving
  observations or emitting telemetry, preventing data delivery after mid-fetch
  revocation.

### Tests

- Add a regression that revokes a session during the RouterOS fetch and verifies
  no SSE frame is emitted and no fetched observation is persisted.

## 2.6.3 - 2026-10-04

### Fixed

- Reject legacy Socket.IO polling requests whose `Origin` is not allowed,
  matching the WebSocket origin policy.
- Show an explicit no-results state when VPN Users search or filters match no
  accounts.

### Tests

- Cover dashboard warning, VPN Users empty state, add-user dialog, and
  Connections termination prompt in rendered-browser regression tests.

## 2.6.2 - 2026-10-04

### Fixed

- Apply timeline export date filters before related-event correlation so
  exported references never point to events omitted by the selected range.
- Expire idle Socket.IO polling clients and release their gateway subscriptions
  so abandoned sessions cannot retain live-client capacity indefinitely.

## 2.6.1 - 2026-10-04

### Fixed

- Return an explicit forbidden response when scoped API tokens request the
  RouterOS-session-only telemetry status endpoint.

## 2.6.0 - 2026-10-04

### Added

- Rate-limit actionable alerts to ten per action per minute while preserving
  independent durable audit writes and keeping alert targets out of metrics.
- Session-bound policy-template review receipts that reject apply requests when
  the selected users, template controls, current RouterOS profiles, or current
  policy state differ from the preview.
- Secret-free Redis and SQLite outbox delivery metrics on the authenticated
  Prometheus endpoint, plus retry/recovery and duplicate-event-ID tests.
- Isolated SQLite backup restore rehearsal coverage and a read-only,
  redacted canary-to-production release acceptance evidence validator.
- Read-only RouterOS account, policy-category, and management-service exposure
  diagnostics with derived-only output and explicit unknown firewall status.
- Add-user and duplicate-account previews now require a reason, bind it to the
  single-use review receipt, and include it in successful and recovery audits.
- Policy-template application now requires an operator rationale, binds it to
  the single-use preview receipt, and records it in apply audits.
- Repeated active alerts now update bounded incident recurrence metadata and
  retain severity escalation without suppressing durable audit/outbox events.
- Enforce `health.read` on service-health and setup-preflight routes; keep
  RouterOS user/status data endpoints unavailable to API-token principals.
- Enforce `health.read` on deployment/health observability while adding audit
  and session-history details only for tokens or roles with those capabilities.
- Require timestamped, sufficiently sampled 30-minute telemetry evidence before
  the acceptance evaluator can report sustained latency/freshness SLOs as pass.
- Recover live clients from missing in-window event sequences with a redacted
  snapshot, and replay out-of-order batches in monotonic order.
- Gate server-rendered Change History data and navigation on `audit.read`,
  matching the existing API/export authorization boundary for read-only users.

## 2.5.0 - 2026-10-01

### Added

- Bulk VPN-user operations with filtered multi-select, review previews, exact
  confirmations, idempotent suspend/revoke/tag actions, partial-failure
  reporting, and redacted aggregate audit events.
- Router-local saved views for reusable query, status, and tag filters. View
  definitions contain no credentials, profile contents, certificate material,
  or RouterOS configuration.
- Administrator roles (Owner, Security operator, Administrator, Auditor, and
  Read-only) with capability enforcement in the UI and API, plus redacted
  authentication and authorization audit events.
- Enterprise administrator session center with idle/absolute expiry metadata,
  explicit revocation, and safe session-ID handling.
- Review-only break-glass recovery planning, immutable release verification,
  profile diagnostics, and network segmentation plans; none changes RouterOS.
- Authenticated Server-Sent Events for live connection snapshots with polling
  fallback, plus secret-free Prometheus metrics and a redacted compliance ZIP.
- Short-lived, scoped read-only API tokens stored as one-way hashes and shown
  in plaintext only once to a security-capable administrator.
- Mobile/PWA accessibility foundation with reduced-motion support and an
  installable web-app manifest.
- A disabled-by-default RouterOS Binary API protocol foundation with framing,
  sentence parsing, listen-record handling, and focused tests for the planned
  live-telemetry transport.
- A disabled-by-default in-memory telemetry broker that normalizes Binary API
  records, reconciles snapshots, emits versioned session transitions, and
  enforces an allow-list so credentials and profile material cannot reach a
  future Socket.IO delivery layer.
- A disabled-by-default, dependency-free telemetry gateway contract that
  checks the existing RouterOS session capability, publishes versioned redacted
  frames, and recovers stale cursors with bounded snapshots without retaining
  dashboard credentials or session objects.
- A public live-telemetry migration plan and a full-revert runbook that keep
  the existing REST/SSE fallback, OpenVPN CA, certificates, profiles, and
  router-local data unchanged.

### Fixed

- Certificate-alert integration tests now derive their warning-window fixture
  from the current time so CI remains deterministic.

### Maintenance

- Updated the container build dependencies for QEMU, Buildx, and Build Push;
  all checks passed before merge.
- Removed unavailable Dependabot label names so future update pull requests do
  not carry broken label warnings.

## 2.0.0 - 2026-09-16

### Added

- Read-only device posture checks that compare every managed profile with the
  live RouterOS certificate inventory. Profiles are approved only when their
  certificate is present, non-revoked, and issued by the configured current
  CA; missing, revoked, and legacy-CA identities include an actionable reason.
  No CA, certificate, credential, profile, or RouterOS configuration is
  changed by these checks.

## 1.11.0 - 2026-09-16

### Added

- Mobile administrator ergonomics with responsive navigation, touch-sized
  controls, viewport-safe dialogs, and readable narrow-screen health, session,
  device, policy, audit, and observability views.
- Mobile UX polish with adaptive navigation treatment, thumb-sized action
  controls, calm card grouping, readable session facts, and keyboard-safe
  dialog presentation at phone widths.
- Appearance preferences with Standard, Dark, Light, and System modes. The
  selection is stored only in the browser, follows the device preference in
  System mode, and does not alter RouterOS, certificates, or dashboard data.
- A router-local certificate migration center that discovers legacy client
  profiles, issues tracked replacements, and keeps revocation explicitly
  operator-controlled after the replacement has been tested.
- Central `VERSION` metadata and a protected-tag release-notes workflow with a
  dry-run preview. Release tags are checked against the repository version and
  notes record the immutable source commit without changing router deployment.
- Local production observability with immutable deployment history, a compact
  service-health timeline, authenticated observability API data, and explicit
  rollback visibility. The metadata stays in the router-hosted `/data` store
  and does not touch the OpenVPN CA, certificates, users, or profiles.

### Changed

- Unified the dashboard visual hierarchy with contextual navigation icons,
  mobile-friendly icon tooltips, and a consistent readable type scale for
  user cards, health checks, planner panels, policy templates, and audit data.
- Public distribution references now use the canonical
  `mikrotik-openvpn-gui` repository and GHCR package name. The next published
  immutable image and stable release manifest are therefore generated under
  that package path.

### Security

- Router-local automatic updates now permit a strictly validated private HTTP
  `/readyz` probe when TLS terminates at a separate local proxy. Public release
  manifests remain HTTPS-only and certificate-validated; readiness must report
  the immutable candidate revision before promotion.

## 1.9.0 - 2026-09-10

### Added

- Review-first OpenVPN foundation planning for supported routers that do not
  yet have an OpenVPN server, including a copyable non-secret configuration
  plan and an explicit firewall review boundary.
- Administrator capability guidance and destructive-action guardrails that
  keep audit history useful without storing another administrator-password
  database.
- An illustrated, first-install RouterOS playbook for HTTPS/domain and
  direct-IP deployments, plus a redacted real-router canary acceptance guide.

## 1.8.0 - 2026-09-09

### Added

- Per-device certificate revocation with exact confirmation, RouterOS
  checkpoint, and Change History recording.
- Certificate inventory warnings for expired certificates and certificates
  expiring within 30 days, with guided replacement-profile instructions.
- Simple public-repository-to-RouterOS canary-to-production architecture
  documentation and diagram.

## 1.0.0 - 2026-09-07

### Added

- Public, self-hosted RouterOS OpenVPN dashboard source release.
- WinBox-inspired user, device-profile, session, traffic, and audit views.
- RouterOS-backed VPN user lifecycle actions and per-device certificate/profile
  issuance with ZIP and short-lived QR onboarding.
- Access presets for concurrent devices, expiry, schedule, speed, DNS, and
  quota controls.
- Architecture-specific ARM64 and AMD64 container publishing with immutable
  commit-addressed image tags.
- Local pre-commit, secret-pattern, history-scan, Python test, and RouterOS
  image-build verification.

### Security

- Apache-2.0 public-source release with no production credentials, router
  runners, private operations history, or automatic router-deployment workflow.
- Explicit HTTPS/TLS validation and local, immutable-image deployment guidance.
