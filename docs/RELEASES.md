# Release and image contract

This document describes how a repository release becomes an image a RouterOS
operator may choose to install. Publishing an image and deploying it to a
router are separate actions.

## Image-publishing trigger

Pushes publish images only when a runtime input changes: the application
modules, static assets, `Containerfile`, or `LICENSE`. Deployment policy,
workflow, documentation, and test changes are verified by CI but do not publish
an image. Use **Publish container** with `workflow_dispatch` when a reviewed
workflow-only change must be exercised deliberately.

## Supported image platforms

| Image suffix | OCI platform | RouterOS position |
| --- | --- | --- |
| `arm64` | `linux/arm64` | Supported and validated on an ARM64 RouterOS container host. |
| `amd64` | `linux/amd64` | Published for x86/CHR evaluation; require a canary on the exact RouterOS version. |
| `arm` | — | Not published. RouterOS `arm` naming does not establish a compatible ARM32 ABI for this image. |

RouterOS operators must select the matching, single-platform tag. Do not rely
on a multi-architecture manifest or a mutable tag for RouterOS pulls.

## Image references

For commit `0123...abcd`, the publisher emits these references under the
repository's GHCR package:

- `sha-<full-commit>-arm64` and `sha-<full-commit>-amd64` are
  commit-addressed architecture-specific tags.
- `sha-<full-commit>` is the ARM64 compatibility alias for the validated
  RouterOS target.
- `edge-arm64`, `edge-amd64`, and the ARM64 `edge` alias are mutable inspection
  tags. They are never deployment targets.
- A signed-off release tag such as `v1.0.0-arm64` is a convenience reference,
  not a replacement for recording its immutable digest.

GHCR tags are mutable registry references unless the package policy prevents
retagging. Record both the full commit SHA and the published digest before a
canary or production update; use the digest for the operator's immutable audit
record. RouterOS compatibility takes
precedence over OCI metadata: deployable images intentionally avoid attached
SBOM/provenance indexes until the installed RouterOS version has passed an
isolated pull test.

## Fork-safe deployment boundary

Every repository and fork publishes its own images and controls its own Actions
secrets, environments, runners, and RouterOS configuration. No upstream
router address, credential, token, or deployment secret belongs in this source
tree, a release asset, an example, or a fork variable.

The `Deploy production to RouterOS` workflow is manual by default. It requires
the selected full commit SHA, the literal confirmation `DEPLOY`, a protected
environment, and a repository-scoped private runner. A repository owner can
enable same-repository default-branch automation only by setting
`ENABLE_ROUTEROS_AUTODEPLOY=true` after a successful canary and rollback
exercise. Leave that variable unset for manual-only operation.

> **Public-source boundary:** do not attach a RouterOS-reachable self-hosted
> runner to a public repository. Before changing repository visibility, move
> the deployment workflow and its runner to a private, owner-controlled relay
> repository (or an equivalently isolated deployment service). Repository
> workflow guards are an important control, but they do not turn a shared
> self-hosted runner into a safe public-execution environment.

## v1.0.0 release checklist

Before creating a public release:

1. Complete the public-source privacy, licensing, history-scan, and support
   gate. Do not change repository or package visibility before it passes.
   From a private local clone, run
   `python scripts/check_history.py --repo . --marker '<private instance marker>'`
   once for each private hostname, account label, or other deployment identity.
   The scanner checks every commit reachable from local refs and prints only
   rule labels, commit prefixes, and paths—not the marker or matched value.
2. Run the full local and GitHub CI validation suite, including the secret
   scanner and both published image smoke tests.
3. Validate the ARM64 image with the documented isolated RouterOS canary,
   including `/readyz`, RouterOS TLS, login, read-only views, one reversible
   action, and rollback.
4. Publish a release branch or tag from the approved commit as `v1.0.0`.
5. Confirm the architecture-specific images, commit SHA, and digests in the
   published workflow summary.
6. Create GitHub release notes from `CHANGELOG.md`, listing supported
   platforms, minimum RouterOS policy, installation documentation, migration
   notes, and known limitations. Do not attach router exports, profile
   archives, database files, screenshots with live values, or credentials.
7. Keep production deployment manual unless the documented opt-in condition
   has already been met. Record the chosen immutable reference and rollback
   checkpoint in a private operator record.

## Release notes template

Use this short format for every public release:

```markdown
## Compatibility
- RouterOS container host: ARM64 supported; AMD64/CHR evaluation only.
- Dashboard image: `<repository>:vX.Y.Z-arm64`.

## Highlights
- Operator-visible improvements and fixed defects.

## Upgrade
1. Read the installation and rollback runbooks.
2. Canary the immutable ARM64 commit/digest.
3. Promote manually through the protected deployment workflow.

## Security
- No deployment secrets, router exports, profiles, or customer data are
  included in this release.
```

For router preparation, installation, validation, and rollback details, use
[INSTALLATION.md](INSTALLATION.md), [DEPLOYMENT.md](DEPLOYMENT.md), and
[ROLLBACK.md](ROLLBACK.md).
