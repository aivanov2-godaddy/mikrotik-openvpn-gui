# Changelog

All notable operator-visible changes are recorded here. The project follows the
principles of [Keep a Changelog](https://keepachangelog.com/) and uses
semantic-version style release tags.

## Unreleased

### Added

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
