# Changelog

Significant operator-visible changes are recorded here. This project follows the structure of Keep a Changelog but does not claim semantic-version compatibility until a versioned release is created.

## Unreleased

### Added

- Private-repository governance, security reporting guidance, and contribution policy.
- GitHub Actions checks for compilation, tests, secret patterns, and an ARM64 container build.
- Private GHCR publishing with immutable full-commit tags and a RouterOS-compatible single-platform manifest.
- RouterOS canary deployment, rollback, and operations runbooks.

### Changed

- The production image now owns `/app`; only `/data` and the configuration-only `/config` path are host-mounted.
- Container metadata now records source, revision, version, and proprietary license information.
