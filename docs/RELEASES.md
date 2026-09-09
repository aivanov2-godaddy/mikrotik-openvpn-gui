# Releases

## Versioning

The public project starts at **v1.0.0**. Releases use semantic-version style
tags: `vMAJOR.MINOR.PATCH`.

- **PATCH**: compatible bug fixes and documentation corrections.
- **MINOR**: backwards-compatible features and operator improvements.
- **MAJOR**: a compatibility break, required migration, or RouterOS support
  boundary change.

Operator-visible changes are summarized in [CHANGELOG.md](../CHANGELOG.md).

## Published images

The public `Publish container` workflow verifies a `main` change, then publishes
single-platform images to GHCR using the repository's current owner and name.
It produces:

- `sha-<40-character-commit>-arm64` for RouterOS ARM64;
- `sha-<40-character-commit>-amd64` for CHR/x86 evaluation;
- `edge-arm64` and `edge-amd64` for inspection only;
- release tags, with architecture suffixes, when a `v*` tag is pushed.

The unsuffixed ARM64 `sha-<commit>` tag remains a convenience alias. Operators
should still use the suffixed tag so the intended architecture is unambiguous.
An image digest is stronger than any tag; record it with production changes.

RouterOS labels some 32-bit hardware `arm`. This project does not publish an
`arm` image because ARM32/ARMv5 compatibility has not been verified. Validate
the exact RouterOS release and hardware before using any new architecture.

## Public-source boundary

This repository contains public source, public image publishing, and a generic
release manifest only. It does not include a router address, production
credentials, cloud credentials, configuration export, self-hosted runner, or a
remote router-deployment workflow. A fork inherits no route to another
operator's network.

Use the explicit local procedure in [DEPLOYMENT.md](DEPLOYMENT.md) for a
router update. The supported automated option is an operator-installed,
router-local scheduler that validates the public manifest and promotes a
pinned SHA image through canary. It keeps all router state and credentials
local; see [ROUTER_LOCAL_AUTOMATION.md](ROUTER_LOCAL_AUTOMATION.md). Never add
secrets, a router endpoint, or a remote deployment runner to this public source
repository.

## Maintainer release checklist

1. Create an issue describing the release scope and migration impact.
2. Open a focused pull request with tests, docs, and `CHANGELOG.md` updates.
3. Require CI, including pre-commit, secret-pattern checks, unit tests, and
   the ARM64 image build, to pass.
4. Merge the reviewed pull request to `main`.
5. Verify the architecture-specific image tags and their digests in GHCR.
6. Perform a canary validation outside this repository before any production
   router update.
7. Tag `vMAJOR.MINOR.PATCH` only after the release notes are complete.

## Fresh public history

The v1.0.0 public release is intentionally published with a clean source
history. It does not import historical private operations commits. Before any
publication or archive hand-off, run:

```powershell
python scripts/check-secrets.py
python scripts/check_history.py --repo .
```

Use `--marker` locally for any private hostname or identifier you need to
exclude. The scanner never prints the supplied marker value.
