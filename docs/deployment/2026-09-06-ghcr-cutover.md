# Production deployment: immutable GHCR release

**Date:** 2026-09-06  
**Router:** `core.Wanted.sx` (RB5009UPr+S+, RouterOS 7.24.2 stable)  
**Release:** `68aeb62ff32744598afb21edd4aa5b3f0a553728`  
**Image:** `aivanov2-godaddy/mikrotik-openvpn-gui:sha-68aeb62ff32744598afb21edd4aa5b3f0a553728`  
**Published GHCR digest:** `sha256:0cfe84e24bb45149f74d0efbab96f4f3881b80951ef6d995496a60fdd84d0b8b`

## Outcome

The live RouterOS dashboard now runs the immutable ARM64 image built and
published by GitHub Actions. The production container is configured to start
on boot and uses the verified production data mount. The former host-mounted
container is stopped and preserved as a rollback copy; it was not deleted.

Future releases can be prepared as a stopped RouterOS canary, verified through
`/readyz`, and promoted with the guarded blue/green procedure. Traffic is only
switched after the candidate is healthy and a public browser check succeeds.

## Verification performed

- GitHub Actions build and private GHCR publish completed for the release.
- RouterOS canary readiness returned the expected release revision.
- Router-local production readiness returned `status=ready` and the expected
  revision after cutover.
- `https://vpn.wanted.sx` loaded through Cloudflare Access, accepted the
  email verification step, and authenticated to RouterOS.
- The dashboard displayed `core.Wanted.sx` and RouterOS 7.24.2 status.
- `http://vpn.wanted.sx` returned the expected 301 redirect to HTTPS.
- The rollback scheduler was removed only after the public verification.

## Recovery and data handling

- The pre-change RouterOS system backup and the consistent SQLite checkpoint
  are stored outside this repository under the operator backup directory
  `router-backups/pre-ghcr-20260905T042902Z/`.
- The checkpoint is encrypted at rest and its local integrity metadata is
  recorded in the guarded promotion journal. Plaintext checkpoint data was
  removed after verification.
- The previous dashboard container remains stopped with a rollback comment and
  its original data mount. Use the guarded rollback workflow only after
  checking the current journal and traffic state.
- RouterOS built-in storage is the accepted capacity exception for this
  deployment; external storage remains recommended for larger databases or
  longer retention.

## Security boundary

No credentials, Cloudflare tokens, private keys, exported VPN profiles,
databases, plaintext checkpoints, or RouterOS backup files are committed here.
The RouterOS manifest digest is not independently observable from RouterOS;
the immutable full-commit tag and the GHCR workflow digest above are retained
as the release evidence.

