# Changelog

All notable operator-visible changes are recorded here. The project follows the
principles of [Keep a Changelog](https://keepachangelog.com/) and uses
semantic-version style release tags.

## Unreleased

### Added

- Central `VERSION` metadata and a protected-tag release-notes workflow with a
  dry-run preview. Release tags are checked against the repository version and
  notes record the immutable source commit without changing router deployment.

### Changed

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
