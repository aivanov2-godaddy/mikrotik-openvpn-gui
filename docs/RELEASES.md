# Releases

## Versioning

The public project starts at **v1.0.0**. Releases use semantic-version style
tags: `vMAJOR.MINOR.PATCH`.

- **PATCH**: compatible bug fixes and documentation corrections.
- **MINOR**: backwards-compatible features and operator improvements.
- **MAJOR**: a compatibility break, required migration, or RouterOS support
  boundary change.

Operator-visible changes are summarized in [CHANGELOG.md](../CHANGELOG.md).

The current published feature release is **v2.6.0**. It includes the v2.1
mobile administrator workflows, v2.2 administrator roles and authentication
audit, v2.3 enterprise operations foundations, v2.4 bulk operations and saved
views, and v2.5 Binary API live telemetry with the Socket.IO gateway and
fallback paths. v2.6 adds Redis/outbox reliability and recovery coverage,
security and operations controls, accessibility and timeline improvements, and
redacted acceptance tooling. The release also includes the subsequent
live-stream stability, typography, security, and runtime dependency updates.
Earlier v2.5 images were deployed and verified on RouterOS; v2.6 deployment is
tracked separately below and is not yet claimed as accepted. The first
controlled acceptance window verified container health, REST fallback during a
temporary API-SSL interruption, automatic Binary API recovery, authentication
denial, and the deployed resource snapshot. A connected-client window also
verified live connect/disconnect rendering, snapshot recovery, changing
traffic samples, and two simultaneous dashboard clients. Exact event-age,
counter-reset, and Binary/REST parity evidence remains an operational
follow-up. The
previous published feature release was **v2.0.0**, which added read-only device
posture checks while preserving the router-local data and immutable-image
deployment model.

## Published images

### Latest stable registry publication

Runtime commit `b60e977a5e4dada47fbaec18b7a15a2646e6865d` (release **v2.6.0**)
is the current `routeros-stable` manifest target. Container publication run
[#37181655530](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/37181655530)
and release-notes run
[#37181655568](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/37181655568)
passed. Both architecture builds, published-runtime smoke tests, stable-manifest
publication, and exact-digest provenance/SBOM verification passed. The immutable
tags and registry digests are:

| Platform | Immutable image tag | Published digest |
| --- | --- | --- |
| RouterOS ARM64 | `sha-b60e977a5e4dada47fbaec18b7a15a2646e6865d-arm64` | `sha256:7fd9276428933c4f1ce529354f8bb95d79cef16d4d416f0011a3f825fe661a81` |
| CHR/x86 AMD64 (evaluation) | `sha-b60e977a5e4dada47fbaec18b7a15a2646e6865d-amd64` | `sha256:2ed94f2551bbbca626ff1d27ef4b28752170f42af9f7003d3affac1a33c1614a` |

The RouterOS updater is expected to process this manifest on its scheduled
check. The latest read-only WebFig check after publication still showed the
previous `bcb7633` ARM64 tag on canary and production, with both containers
healthy and Redis running. The v2.6.0 RouterOS rollout is therefore pending
read-back. Even after deployment, a point-in-time tag/health check is not the
formal sustained acceptance window; event latency/freshness percentiles,
restart/recovery, counter-reset/event-integrity, and rollback drills remain
outstanding.

### Latest recorded RouterOS tag read-back (historical)

Runtime revision `a2d0ce29943964c2a5c9a12d5a53650b3bbe16b3` includes the
previous published runtime plus Engine.IO polling SID-to-session binding (PR
[#345](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/345)),
telemetry process-epoch snapshot recovery (PR
[#346](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/346)),
read-only telemetry endpoint authorization documentation and contract coverage
(PR [#347](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/347)),
and light-theme contrast plus accessible Add-user dialog improvements (PR
[#348](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/348)).
Publish workflow [37135796169](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/37135796169)
completed both architecture builds, published-runtime smoke tests, stable
manifest publication, and exact-digest provenance/SBOM attestation verification
on 2026-10-03.

| Platform | Immutable image tag | Published digest |
| --- | --- | --- |
| RouterOS ARM64 | `sha-a2d0ce29943964c2a5c9a12d5a53650b3bbe16b3-arm64` | `sha256:3d6ec58d333634a571107fc6b941b6ba86c2e279db51c4c627f792cdbbb17e38` |
| CHR/x86 AMD64 (evaluation) | `sha-a2d0ce29943964c2a5c9a12d5a53650b3bbe16b3-amd64` | `sha256:800de775757f38b4a7a7c13501d664a1f9afa20a3276f766797d1de5343ce5c3` |

The public `routeros-stable` manifest was fetched and points to commit
`a2d0ce29943964c2a5c9a12d5a53650b3bbe16b3`. On 2026-10-03, authenticated
RouterOS read-back showed both the canary and production containers using the
ARM64 immutable tag above; both were marked healthy. RouterOS reports the
configured image tag, not the local registry content digest, so digest
identity on the router is not independently verified. This point-in-time
read-back is not a sustained latency/freshness, resource, event-integrity, or
rollback acceptance result. v2.6.0 is the latest published versioned release;
its publication does not itself mean it has been deployed or accepted on the
router.

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

### Build provenance and SBOM

For each published architecture, the workflow first pushes and smoke-tests the
single-platform runtime image with Buildx SBOM and provenance generation
disabled. It then scans that exact pushed digest with Syft, creates a signed
GitHub artifact attestation for SLSA build provenance, and creates a separate
signed SBOM predicate attestation whose subject is the same image digest. The
attestations are stored by GitHub, not embedded in the image or pushed as OCI
referrers; this keeps the runtime manifest/index that RouterOS pulls unchanged.
The SPDX JSON is also uploaded as a workflow artifact named
`sbom-<architecture>-<commit>` for convenience. Its retention follows the
repository's Actions artifact-retention policy; the signed SBOM predicate is
retrievable and verifiable through the attestation API independently of that
downloadable copy.

The signatures use GitHub Actions OIDC and short-lived Sigstore certificates.
This establishes the attestation signer and binds each statement to the image
digest; it is not a claim that the build is reproducible, that the workflow is
an independently hardened trusted builder, or that the SBOM is complete for
runtime-downloaded components. Verify the workflow identity and expected source
commit rather than relying on a tag or an attestation's descriptive fields.

Install a current GitHub CLI with `gh attestation` support and authenticate to
GHCR if required to resolve the image. Set the exact immutable digest from the
`Build and publish` workflow summary, not a mutable tag:

```sh
REPOSITORY=OWNER/REPOSITORY
COMMIT=<40-character-source-commit>
DIGEST=sha256:<published-image-digest>
IMAGE="ghcr.io/${REPOSITORY}@${DIGEST}"
SIGNER_WORKFLOW="${REPOSITORY}/.github/workflows/container.yml"

# Verify SLSA provenance signature, signer workflow, and source commit.
gh attestation verify "oci://${IMAGE}" \
  --repo "${REPOSITORY}" \
  --signer-workflow "${SIGNER_WORKFLOW}" \
  --source-digest "${COMMIT}"

# Verify the separately signed SPDX SBOM predicate for the same image digest.
gh attestation verify "oci://${IMAGE}" \
  --repo "${REPOSITORY}" \
  --signer-workflow "${SIGNER_WORKFLOW}" \
  --source-digest "${COMMIT}" \
  --predicate-type https://spdx.dev/Document/v2.3

# Optional: extract the verified SBOM predicate as JSON for inspection.
gh attestation verify "oci://${IMAGE}" \
  --repo "${REPOSITORY}" \
  --signer-workflow "${SIGNER_WORKFLOW}" \
  --source-digest "${COMMIT}" \
  --predicate-type https://spdx.dev/Document/v2.3 \
  --format json \
  --jq '.[].verificationResult.statement.predicate' > sbom.spdx.json
```

Repeat for `amd64` when validating the CHR/x86 image. The attestation API is
GitHub-hosted; verification requires GitHub's attestation service and is not an
offline trust-root procedure. The workflow artifact copy is convenient for
inspection but is not a substitute for successful signature, signer, source,
predicate-type, and image-digest verification. Never verify a mutable `edge`
tag as release evidence.

### Compatibility and validation matrix

| Target | Published artifact | What CI proves | RouterOS/device certification |
| --- | --- | --- | --- |
| ARM64 | `sha-<commit>-arm64` | Native architecture image is built, pulled by digest, and `/readyz` is smoke-tested | Validate on the exact RouterOS release and hardware before production use; CI emulation is not hardware certification |
| AMD64 / CHR | `sha-<commit>-amd64` | Native architecture image is built, pulled by digest, and `/readyz` is smoke-tested | CHR/x86 target; validate the target hypervisor and RouterOS release before production use |
| ARM32 / ARMv5 | Not published | No CI build or runtime claim | Unsupported / unverified |

The application targets RouterOS 7 REST APIs and uses the RouterOS container
feature for hosting; API behavior, container capability, architecture support,
storage, and resource headroom vary by RouterOS version and device. Public CI
does not certify every RouterOS release or hardware model. Treat untested
combinations as unverified, and record hardware-specific acceptance privately
without publishing router identity, address, user data, or configuration.

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
6. Verify the image's GitHub provenance attestation and download its matching
   architecture-specific SPDX SBOM artifact.
7. Perform a canary validation outside this repository before any production
   router update.
8. Tag `vMAJOR.MINOR.PATCH` only after the release notes are complete.

The repository's next release version is kept in [`VERSION`](../VERSION). Run
`python scripts/validate_release.py --tag v2.6.0` before creating a tag. The
`Release notes` workflow previews GitHub-generated notes without changing a
release when run manually with `dry_run=true`; a pushed, matching `v*` tag is
the only event that publishes a release. Notes contain commit and pull-request
metadata only—never router state or credentials.

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
