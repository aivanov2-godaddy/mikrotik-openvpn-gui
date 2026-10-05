# Releases

## Versioning

The public project starts at **v1.0.0**. Releases use semantic-version style
tags: `vMAJOR.MINOR.PATCH`.

- **PATCH**: compatible bug fixes and documentation corrections.
- **MINOR**: backwards-compatible features and operator improvements.
- **MAJOR**: a compatibility break, required migration, or RouterOS support
  boundary change.

Operator-visible changes are summarized in [CHANGELOG.md](../CHANGELOG.md).

The latest formal versioned release is **v2.7.0**. It includes the v2.1
mobile administrator workflows, v2.2 administrator roles and authentication
audit, v2.3 enterprise operations foundations, v2.4 bulk operations and saved
views, and v2.5 Binary API live telemetry with the Socket.IO gateway and
fallback paths. v2.6 adds Redis/outbox reliability and recovery coverage,
security and operations controls, accessibility and timeline improvements, and
redacted acceptance tooling. Release v2.7.0 adds guided per-device certificate
migration: operators can issue and test a replacement identity before retiring
the old one, and recovery creates a new identity rather than re-downloading a
private key the dashboard does not retain. Patch v2.6.1 gives scoped API tokens
a deliberate 403 response when they request the RouterOS-session-only telemetry status.
Patch v2.6.2 fixes timeline date filtering before bounded event correlation,
expires abandoned Socket.IO polling sessions, and completes exhaustive
route/token scope-subset coverage. Patch v2.6.3 adds origin validation for
legacy Socket.IO polling requests and an explicit VPN Users no-results state,
with rendered-browser regression coverage. Patch v2.6.4 closes an SSE
revocation-during-RouterOS-fetch race by revalidating the session and
`sessions.read` authorization after the blocking fetch and before observation
persistence or telemetry delivery. Neither image publication nor a
point-in-time tag read-back is
the formal sustained acceptance. The first
controlled acceptance window verified container health, REST fallback during a
temporary API-SSL interruption, automatic Binary API recovery, authentication
denial, and the deployed resource snapshot. A connected-client window also
verified live connect/disconnect rendering, snapshot recovery, changing
traffic samples, and two simultaneous dashboard clients. Exact event-age,
counter-reset, and Binary/REST parity evidence remains an operational
follow-up. Release **v2.0.0** originally introduced read-only device posture
checks while preserving the router-local data and immutable-image deployment
model.

At the maintainer's request, the superseded GitHub Release entries v2.6.3 and
v2.6.4 were removed on 2026-10-05; their Git tags remain available for
historical/rollback reference. v2.7.0 remains the latest numbered release.

## Published images

### Latest published mainline candidate — PR #504 — 2026-10-06

PR [#504](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/504)
merged to main as
`a62724c94261b00866fa3d55416a7b540305d40b`. Publication workflow
[#37384368900](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/37384368900)
passed source and rendered-browser checks, ARM64/AMD64 publication,
exact-digest provenance/SBOM verification, and published-runtime smoke tests.
Independent SLSA verification matched both published image digests to this
commit and the repository's `Publish container` workflow. The
`routeros-stable` manifest asset was read back and names this commit and both
immutable tags.

| Platform | Immutable image tag | Published digest |
| --- | --- | --- |
| RouterOS ARM64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-a62724c94261b00866fa3d55416a7b540305d40b-arm64` | `sha256:2b1d249c4219302305ce54e73b856dc22f5b884ff786b083ea18de2868e454af` |
| CHR/x86 AMD64 (evaluation) | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-a62724c94261b00866fa3d55416a7b540305d40b-amd64` | `sha256:81a7e06a1904b36ccd2ba6208a46f93006ac0ab059e7eeb91a220e94c77594fe` |

No RouterOS read-back was performed for PR #504. The latest recorded router
state remains canary PR #501 and production PR #497; those configured tags do
not establish that PR #504 is installed. The telemetry/Redis acceptance and
candidate-specific rollback rehearsal remain pending. Production has not been
promoted to this candidate. No new numbered release was created; v2.7.0
remains the latest formal version.

### Previously published mainline candidate — PR #501 — 2026-10-06

PR [#501](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/501)
merged to main as
`0ab71339f8884e3b8e185d55bfbcdc69cd088c22`. Publication workflow
[#37376243641](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/37376243641)
passed source and rendered-browser checks, ARM64/AMD64 publication, exact-digest
provenance/SBOM verification, and published-runtime smoke tests. The ARM64 SLSA
provenance was independently verified against the published digest and mainline
commit. The `routeros-stable` manifest asset was fetched and confirmed to name
this commit and both immutable tags.

| Platform | Immutable image tag | Published digest |
| --- | --- | --- |
| RouterOS ARM64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-0ab71339f8884e3b8e185d55bfbcdc69cd088c22-arm64` | `sha256:f2b4368e194eb6996018efc2c3729f866e1da79046312e60cd9511b92dcf41fa` |
| CHR/x86 AMD64 (evaluation) | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-0ab71339f8884e3b8e185d55bfbcdc69cd088c22-amd64` | `sha256:dab88909d624e04c9d76acb5a05cbe27a2e9b4ce2d2fab33f94837a0d3b96414` |

Read-only RouterOS WebFig read-back listed the canary on the PR #501 ARM64 tag
with the `H` status marker, while production remained on the PR #497 immutable
tag; Redis was running. This is configured-tag/status evidence only: RouterOS
does not expose the digest of the locally cached image. The production dashboard
showed `Live · SOCKETIO`, Operational service health, and zero connected VPN
users in one point-in-time observation. The 30-minute telemetry/Redis acceptance
and current-candidate rollback rehearsal remain pending. Production has not been
promoted to this candidate. No new numbered release was created; v2.7.0 remains
the latest formal version.

### Previously published mainline image — PR #497 — 2026-10-05

PR [#497](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/497)
merged to main as
`3eda7a15acb6fdb0f9749dfe0c2fd9efeeae714f`. Publication workflow
[#37351647768](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/37351647768)
passed release-source and rendered-browser checks, ARM64/AMD64 publication,
exact-digest provenance/SBOM verification, published-runtime smoke, and stable
manifest publication. The RouterOS ARM64 image is:

| Platform | Immutable image tag | Published digest |
| --- | --- | --- |
| RouterOS ARM64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-3eda7a15acb6fdb0f9749dfe0c2fd9efeeae714f-arm64` | `sha256:089e9c48c3e388cd08be3a44ddd9f525a0b50ea9e15983d6a8fa78e442fecc6c` |

Read-only RouterOS read-back showed canary and production configured with this
tag and healthy (`H`). The canary rollback-and-forward-recovery rehearsal
returned the expected `/readyz` revisions; production was not restarted for
that drill. The authenticated application later showed live status and
`Operational` service health. This is point-in-time evidence, not the formal
30-minute telemetry/Redis acceptance. The router exposes the configured tag,
not an independent registry digest. No new numbered release was created;
v2.7.0 remains current.

### Previously published mainline image — PR #494 — 2026-10-05

PR [#494](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/494)
merged to main as
`03d08a2e6a08554c68cf74930049ac29ac0b3219`. Publication workflow
[#37328242084](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/37328242084)
passed CI, image publication, provenance/SBOM verification, and runtime smoke
checks. The immutable ARM64 image is:

| Platform | Immutable image tag | Published digest |
| --- | --- | --- |
| RouterOS ARM64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-03d08a2e6a08554c68cf74930049ac29ac0b3219-arm64` | `sha256:5d5645d7613f74081bb01e390d6201ba6230968de72248119b39c9a4274ecad4` |

This was a published, CI-verified mainline image, not a new numbered release.
It has since been superseded by PR #504 above. Its publication history is
retained here; the full telemetry/Redis acceptance remains pending.

### Earlier post-release mainline image publication — PR #484 — 2026-10-05

Main-branch runtime commit
`93627bca38312ad1845249c6df1c0fcecf12122e` was published by workflow
[#37302952543](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/37302952543).
The build, runtime smoke test, detached provenance, and SBOM attestations
passed for both architectures:

| Platform | Immutable image tag | Published digest |
| --- | --- | --- |
| RouterOS ARM64 | `sha-93627bca38312ad1845249c6df1c0fcecf12122e-arm64` | `sha256:01872672a9093ac999272c0be0cf97bf27c2139af1cde90f41b501ac4995ba73` |
| CHR/x86 AMD64 (evaluation) | `sha-93627bca38312ad1845249c6df1c0fcecf12122e-amd64` | `sha256:6c6c2babc30e499f35b62877cc8e2450ea17cb0aad9e32b3f296cfd5199fce78` |

This is a published mainline image, not a new numbered release. At that time it
was the latest image with a timestamped RouterOS read-back: on 2026-10-05 WebFig
showed both canary and production configured with the ARM64 immutable tag above
and healthy (`H`), with Redis running (`R`). RouterOS reports the configured
tag, not an independently verified registry digest. This confirms deployment
configuration and container health, not sustained acceptance. The dashboard
tab was at sign-in during that particular inspection; a later authenticated
observation is recorded above. The PR #497 read-back subsequently superseded
this observation, and the 2026-10-06 PR #501 canary candidate is recorded in the
latest section. The `routeros-stable` manifest was refreshed by the PR #484
publication workflow and later advanced to PR #501; a manifest update does not
itself update any router.

### Latest numbered release and earlier RouterOS-observed runtime patch — PR #478

The latest formal release is **v2.7.0**, commit
`2e01f111e1445c79b1753477a41efbaec27a1a2d`. Subsequent main-branch runtime
patches are published as immutable commit tags without creating a numbered
release. PR [#478](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/478)
was an earlier RouterOS-observed runtime patch, merged as `d5f8f4418d6ec972aa51ea4634b56c7fd89093f4`;
publication workflow
[#37294618814](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/37294618814)
passed. The published immutable tags/digests for this on-router revision were:

| Platform | Immutable image tag | Published digest |
| --- | --- | --- |
| RouterOS ARM64 | `sha-d5f8f4418d6ec972aa51ea4634b56c7fd89093f4-arm64` | `sha256:1ec08a3a0c5d4741a701270ba30249aba62e215649170aa3a6b69c150fc41209` |
| CHR/x86 AMD64 (evaluation) | `sha-d5f8f4418d6ec972aa51ea4634b56c7fd89093f4-amd64` | `sha256:fad6a49eb253f52c5407369700833c7733f26972f49ae37fa012dd43e0a6f787` |

RouterOS WebFig read-back after the publication above showed canary and
production configured with its ARM64 immutable tag, both healthy (`H`), and
Redis running (`R`). RouterOS reports the configured tag, not an independent
registry digest. This is point-in-time deployment and container-health
evidence—not the formal sustained acceptance window. Latency/freshness
percentiles, API restart/recovery, counter-reset and
event-integrity checks, Redis delivery soak, and rollback drills remain
outstanding.

### Earlier RouterOS tag read-back (historical)

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
rollback acceptance result. The latest numbered release remains v2.7.0; this
historical image read-back does not itself mean that release has been deployed
or accepted on the router.

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

The repository's next release version is kept in [`VERSION`](../VERSION) (currently
`2.7.0`). Run `python scripts/validate_release.py --tag v2.7.0` before creating
that tag. The
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
