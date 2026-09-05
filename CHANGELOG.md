# Changelog

Significant operator-visible changes are recorded here. This project follows the structure of Keep a Changelog but does not claim semantic-version compatibility until a versioned release is created.

## Unreleased

### Added

- Private-repository governance, security reporting guidance, and contribution policy.
- GitHub Actions checks for compilation, tests, secret patterns, and an ARM64 container build.
- Private GHCR publishing with immutable full-commit tags and a RouterOS-compatible single-platform manifest.
- RouterOS canary deployment, rollback, and operations runbooks.
- Offline immutable-image canary plan rendering with strict input validation.
- A database-aware `/readyz` gate with baked release identity and ARM64 runtime smoke tests.

### Changed

- The production image now owns `/app`; only `/data` and the configuration-only `/config` path are host-mounted.
- Container metadata now records source, revision, version, and proprietary license information.
- RouterOS-managed `/etc/hostname`, `/etc/hosts`, and `/etc/resolv.conf` files are removed from the image so RouterOS 7.24 can create them at container start.
- The legacy host-mounted source updater now exits without contacting RouterOS.
- Blue/green promotion now requires separate frozen blue, immutable checkpoint, and green working data directories for deterministic rollback.
