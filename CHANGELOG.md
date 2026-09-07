# Changelog

All notable operator-visible changes are recorded here. The project follows the
principles of [Keep a Changelog](https://keepachangelog.com/) and uses
semantic-version style release tags.

## Unreleased

No unreleased changes.

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
