# Releases

## Versioning

The public project starts at **v1.0.0**. Releases use semantic-version style
tags: `vMAJOR.MINOR.PATCH`.

- **PATCH**: compatible bug fixes and documentation corrections.
- **MINOR**: backwards-compatible features and operator improvements.
- **MAJOR**: a compatibility break, required migration, or RouterOS support
  boundary change.

Operator-visible changes are summarized in [CHANGELOG.md](../CHANGELOG.md).

This public release record documents repository commits, published artifacts,
CI provenance, and redacted deployment-gate status. Router identity, detailed
RouterOS state, live measurements, and operator/session details remain in
private operational records.

The latest formal versioned release remains **v2.7.0**. The next planned
version, v2.8.0, has not been tagged or published. PR #829
(`9fd85aaff7f4ed43888209d2b77663207a11a897`) is the latest published image
source. It improves SQLite-backed integration-outbox recovery after transient
storage failures and strengthens release-acceptance and sanitized updater
checks. PR #830 is documentation-only and adds an offline comparator risk flag;
it did not change the runtime image. The immutable candidate is not a numbered
release or evidence of RouterOS deployment.

For PR #829, main CI run
[#40171739354](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/40171739354)
and publisher run
[#40171739273](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/40171739273)
passed. SLSA provenance for the ARM64 and AMD64 images was verified against
this source commit, `refs/heads/main`, and the `Publish container` workflow.
Exact tags and digests are recorded below.

The PR #829 images have not been read back from RouterOS as the configured
canary image, and candidate-specific rollback, live telemetry acceptance, and
the independent security review remain incomplete. The installed updater and
its scheduler bindings are not fully reconciled and were not run. Production's
candidate digest and application health have not been revalidated. Keep
production promotion and v2.8.0 gated until candidate-specific acceptance
passes.

## Latest published mainline image — PR #829 — 2026-10-25

PR [#829](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/829)
merged as `9fd85aaff7f4ed43888209d2b77663207a11a897`. Main CI run
[#40171739354](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/40171739354)
and publisher run
[#40171739273](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/40171739273)
passed. The SLSA provenance attestations for both architecture-specific images
were verified against the exact source commit and main-branch `Publish
container` workflow.

| Platform | Immutable image tag | Registry digest |
| --- | --- | --- |
| RouterOS ARM64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-9fd85aaff7f4ed43888209d2b77663207a11a897-arm64` | `sha256:29c594c7349af2b226afc38ea92cdf4d73d69ce4610a552726bc59297ca68da1` |
| AMD64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-9fd85aaff7f4ed43888209d2b77663207a11a897-amd64` | `sha256:aad12eb8d90e295c6968bddc81696836d2247e2d12d800cbf3dcffd1e870e60d` |

These are immutable published artifacts, not a numbered release or a
deployment. RouterOS candidate staging, rollback rehearsal, the required live
acceptance window, and production promotion are not claimed.

The latest read-only WinBox observation on 2026-10-25 showed the canary
container healthy, with architecture `arm64` and OCI revision
`79816625e493f9581e7389b95760403ac6c9a327` (PR #806). That view did not read
back the complete configured image tag or registry digest. The WinBox Stats
view showed 0.7% CPU, 60.9 MiB memory, and 0 B swap; it is not a soak or
sustained-resource measurement. This later observation supersedes an earlier inventory that
reported the canary stopped, but does not verify or accept PR #829.

## Previous published mainline image — PR #824 — 2026-10-25

PR [#824](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/824)
merged as `060c1a247e9ba97651ff8093049161de34e57a12`. Main CI run
[#40157395035](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/40157395035),
publisher run
[#40157395026](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/40157395026),
and main-branch CodeQL run
[#40157394958](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/40157394958)
passed. The publisher verified detached provenance and SPDX SBOM attestations
against the exact source commit, smoke-tested both architecture images, and
read back the stable immutable manifest.

| Platform | Immutable image tag | Registry digest |
| --- | --- | --- |
| RouterOS ARM64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-060c1a247e9ba97651ff8093049161de34e57a12-arm64` | `sha256:f26a64afad79ec43ffe247d81cdf7488b84b52811af022e6d3bcce8d5d6ab2aa` |
| AMD64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-060c1a247e9ba97651ff8093049161de34e57a12-amd64` | `sha256:0a598defd090b8de7372f0ef9f6738f5ef76fe1dc3722bf4c9cb55bb36bc8319` |

PR #824 disabled Uvicorn's default access logger in the production ASGI
launcher so URL-bearing request paths are not emitted by that logger. This is
a code-level safeguard, not evidence about historical or external proxy logs.
The later WinBox read-back showed the canary healthy with embedded PR #806
revision `79816625e493f9581e7389b95760403ac6c9a327`; it did not read the full
configured tag or digest. The earlier stopped-state inventory was superseded by
that later observation. This does not claim PR #824 was staged or accepted.

## Previous published mainline image — PR #817 — 2026-10-25

PR [#817](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/817)
merged as `40ae1d86bbc8037172e38f1b018e71576925f201`. Main CI run
[#40143943796](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/40143943796),
publisher run
[#40143943784](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/40143943784),
and main-branch CodeQL run
[#40143943935](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/40143943935)
passed. The publisher verified detached provenance and SPDX SBOM attestations
against the exact source commit and smoke-tested both architecture images. It
published the stable immutable manifest; unlike earlier runs, this workflow
did not include a manifest read-back step.

| Platform | Immutable image tag | Registry digest |
| --- | --- | --- |
| RouterOS ARM64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-40ae1d86bbc8037172e38f1b018e71576925f201-arm64` | `sha256:cd96ffd32fb223abe7776c4ac2a6701cbea0c36fa5699619ead5915549cd0b3c` |
| AMD64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-40ae1d86bbc8037172e38f1b018e71576925f201-amd64` | `sha256:d47a711056d7bc7a59b5fddfb68a3584eb0246d047fe6f9e7e1d9b44eba11253` |

The images are immutable published artifacts, not a numbered release or a
deployment. The read-only inventory accompanying this PR #817 checkpoint
reported the canary stopped. A subsequent WinBox read-back on 2026-10-25 showed
the canary healthy with embedded PR #806 revision
`79816625e493f9581e7389b95760403ac6c9a327`; it did not verify the PR #817
image tag or digest. No PR #817 staging, production promotion, or candidate
acceptance is claimed. The release and security-acceptance gates remain open.

## Previous published mainline image — PR #815 — 2026-10-25

PR [#815](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/815)
merged as `42ce550652f8134f3f0e3ed4ca37c3a3df413624`. Main CI run
[#40138240586](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/40138240586)
and publisher run
[#40138240583](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/40138240583)
passed. The required CodeQL check passed on the PR; the current main-branch
alert inventory is 0 open / 7 closed. The publisher verified detached
provenance and SPDX SBOM attestations against the exact source commit, smoke-
tested both architectures, and read back the generic `routeros-stable`
manifest matching this commit.

| Platform | Immutable image tag | Registry digest |
| --- | --- | --- |
| RouterOS ARM64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-42ce550652f8134f3f0e3ed4ca37c3a3df413624-arm64` | `sha256:d51572f37e09623cdc3e2990038f1a8ed39abc2de3dfd9beb50251c03168f4df` |
| AMD64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-42ce550652f8134f3f0e3ed4ca37c3a3df413624-amd64` | `sha256:1331b647c516ebab3e3ef2c69b00456c440f9fc69e9a5dd335431a7db35faef6` |

The images are immutable published artifacts, not a numbered release or a
deployment. No RouterOS staging, production promotion, or fresh router
read-back is claimed; the last recorded canary checkpoint remains PR #806.
The installed updater mismatch and candidate-specific live acceptance remain
open.

## Previous published mainline image — PR #811 — 2026-10-24

PR [#811](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/811)
merged as `0f031789939f48e37c42bf258987fb23a9069192`. Main CI run
[#40117101238](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/40117101238),
CodeQL run
[#40117101744](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/40117101744),
and publisher run
[#40117101217](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/40117101217)
passed. The publisher verified detached provenance and SPDX SBOM attestations
against the exact source commit, smoke-tested both images, and read back the
stable immutable manifest.

| Platform | Immutable image tag | Registry digest |
| --- | --- | --- |
| RouterOS ARM64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-0f031789939f48e37c42bf258987fb23a9069192-arm64` | `sha256:37d64d3c4cbb7df686108cdffc77a1e642a4e7ac6b07bc5563f294b2a96d75c8` |
| AMD64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-0f031789939f48e37c42bf258987fb23a9069192-amd64` | `sha256:faeaa1dcc3f3f98034e77a0e5a885848904702557227bd24ce50d2aad4fe68ee` |

This is an immutable published image, not a numbered release or a deployment.
The PR #810 mobile SSE-fallback regression was resolved in #811, and main CI
passed. No RouterOS staging, production promotion, or fresh router read-back
is claimed; the last recorded canary checkpoint remains PR #806. The installed
updater mismatch and candidate-specific live acceptance remain open.
PR #778 adds
redacted diagnostics for CSRF Origin/Referer rejections and binds Engine.IO
SIDs to the active dashboard session before sending the handshake. PR #776
ensures logout revokes the session before the audit write, so audit-storage
failure cannot preserve an authenticated session. It retains PR #772's fail-closed process core-dump
limit, PR #767's content-hashed static assets, and PR #761's active-session Engine.IO
authorization, PR #759's live interface-counter projection,
PR #758's duplicate CSRF-header rejection, PR #755's session-bound telemetry
authorization and revocation cleanup, PR #751's hardening of session expiry
and SQLite WAL startup under contention, PR #745's preservation of VPN
sessions when RouterOS has not yet supplied a complete interface-counter
sample, PR #740's automatic-poll session-expiry hardening and safe credential
representation, and PR #741's redaction of RouterOS upstream error details.
Earlier merged work includes the read-only device-posture guard that requires
both the stored RouterOS certificate ID and normalized fingerprint to match.
PR #728's pinned Python base-image registry change is also part of this
mainline history. The broader candidate highlights are stricter live-data field
allowlists and session revalidation, serialized telemetry/session invalidation,
safer staged certificate renewal, improved telemetry recovery, and
evidence-gated RouterOS canary promotion. CI publication is not RouterOS
acceptance; do not tag or publish v2.8.0 until candidate-specific canary
acceptance passes. Earlier releases
introduced the v2.1 mobile administrator workflows,
v2.2 administrator roles and authentication audit, v2.3 enterprise operations
foundations, v2.4 bulk operations and saved views, and v2.5 Binary API live
telemetry with the Socket.IO gateway and fallback paths. v2.6 adds Redis/outbox
reliability and recovery coverage, security and operations controls,
accessibility and timeline improvements, and redacted acceptance tooling.
Release v2.7.0 adds guided per-device certificate
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
follow-up. These were historical windows for earlier deployments and do not
establish acceptance for the current candidate. Release **v2.0.0**
originally introduced read-only device posture checks while preserving the
router-local data and immutable-image deployment model.

PR #730's device-posture identity safeguard remains included in the latest
published candidate below. Publication does not establish RouterOS deployment
or acceptance.

At the maintainer's request, the superseded GitHub Release entries v2.6.3 and
v2.6.4 were removed on 2026-10-05; their Git tags remain available for
historical/rollback reference. Keep v2.7.0 as the only numbered GitHub Release
until v2.8.0 is accepted, published, and verified; then remove the superseded
GitHub Release entry while retaining its Git tag for rollback history.

## Published images

### Previously published mainline image — PR #806 — 2026-10-24

PR [#806](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/806)
merged as `79816625e493f9581e7389b95760403ac6c9a327`. Main CI run
[#40038241253](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/40038241253)
and CodeQL run
[#40038238944](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/40038238944)
and publisher run
[#40039075586](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/40039075586)
passed, including ARM64 image build, Redis recovery integration,
rendered-browser/accessibility regression, secret-pattern checks, and
dependency audit. The immutable ARM64 image was read back from GHCR and staged
on the canary.

| Platform | Immutable image tag | Registry digest |
| --- | --- | --- |
| RouterOS ARM64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-79816625e493f9581e7389b95760403ac6c9a327-arm64` | `sha256:dd646c8b25a5b4e24653d2268719b89513da85c7164e68e499b5ebd4cf292dce` |

This is an immutable published mainline image, not a numbered release;
v2.7.0 remains the latest formal release. Canary staging and healthy
revision/readiness read-back are recorded in `LIVE_TELEMETRY_ACCEPTANCE_REPORT.md`
and `ROUTEROS_ACCEPTANCE.md`. Sparse point samples do not constitute the
required 30-minute soak. Candidate-specific rollback and full live acceptance
remain incomplete; production was not changed.

### Previously published mainline image — PR #803 — 2026-10-24

PR [#803](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/803)
merged as `e12d1708e81959f02c182659dc5bb35a82229fef`. Main CI run
[#40022645523](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/40022645523),
CodeQL run
[#40022645787](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/40022645787),
and publisher run
[#40022645478](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/40022645478)
passed. Both architecture images were built and smoke-tested; provenance and
SPDX SBOM attestations were verified, and the stable manifest was published
and read back. Its artifact digests and earlier canary readiness/rollback
observations are historical and are not acceptance evidence for PR #806.

| Platform | Immutable image tag | Registry digest |
| --- | --- | --- |
| RouterOS ARM64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-e12d1708e81959f02c182659dc5bb35a82229fef-arm64` | `sha256:d0fe3c7c19cd49db9499e645e4d31467cc264d8575b74da59d4beffc9967250c` |
| AMD64 / CHR | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-e12d1708e81959f02c182659dc5bb35a82229fef-amd64` | `sha256:d36b00322a4bcc9ba0cca21af2ef0a5b18a4b6f351f989d423df5dcf1fe86f63` |

### Previously published mainline image — PR #798 — 2026-10-23

PR [#798](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/798)
merged as `041a9d2ac7581dac18911c236cbbb3aee4280273`. It requires one
same-origin `Referer` before allocating Engine.IO state for an originless
Socket.IO polling GET, preserves that browser evidence with
`Referrer-Policy: same-origin`, and covers the fallback in server and rendered
browser tests. Main CI run
[#40000779522](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/40000779522)
and publisher run
[#40000779533](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/40000779533)
passed. Both architecture images were built and smoke-tested; provenance and
SBOM attestations were verified against the source and image digests, and the
stable manifest was published and read back.

| Platform | Immutable image tag | Registry digest |
| --- | --- | --- |
| RouterOS ARM64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-041a9d2ac7581dac18911c236cbbb3aee4280273-arm64` | `sha256:b41ad2cde73efe9f465d583430e4801b75335b18c92b9a364ec21149c69ab601` |
| AMD64 / CHR | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-041a9d2ac7581dac18911c236cbbb3aee4280273-amd64` | `sha256:bf2c211397f30940cb72ab199f2d575b42372341491a934b1260bdd9a12fba6c` |

This is an immutable published mainline image, not a numbered release;
v2.7.0 remains the latest formal release. Publication did not stage or run the
updater on RouterOS. Current PR #806 canary staging and sparse healthy
readiness samples are recorded above; a candidate-specific rollback rehearsal,
30-minute soak, and live acceptance remain pending. Do not tag or publish
v2.8.0 until current candidate-specific acceptance gates pass.

### Previously published mainline image — PR #797 — 2026-10-23

PR [#797](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/797)
merged as `6ca0ebbfab7781c2113555db491b60f5072c4630`. Its CI run
[#39997529192](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/39997529192)
and publisher run
[#39997529273](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/39997529273)
passed. Both architecture images were built and smoke-tested; provenance and
SBOM attestations were verified against the source and image digests, and the
stable manifest was published and read back. PR #797 improves rollback
verification in the checked-in RouterOS updater example; it does not install
or execute that updater on RouterOS.

| Platform | Immutable image tag | Registry digest |
| --- | --- | --- |
| RouterOS ARM64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-6ca0ebbfab7781c2113555db491b60f5072c4630-arm64` | `sha256:de7df62309d9340e49958117a3b04d0c21991c708384abd27343435fc8704380` |
| AMD64 / CHR | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-6ca0ebbfab7781c2113555db491b60f5072c4630-amd64` | `sha256:759b8aaa1cd2cd7e37f2b148669caf6cafc1361ff3ca0d2451b30b9349d1090a` |

These are immutable published mainline images, not a numbered release;
v2.7.0 remains the latest formal release. Publication did not stage or run the
updater on RouterOS and is not candidate-specific acceptance or production
promotion. Later PR #803 staging and rollback evidence is historical; current
PR #806 staging and its pending acceptance gates are recorded above.

### Previously published mainline image — PR #794 — 2026-10-23

PR [#794](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/794)
merged as `beba66c0f36231511ec1b9cc664f2be39a128750`. It rejects missing,
duplicate, or foreign-Origin WebSocket handshakes before Engine.IO allocation,
retains the session-bound HTTP polling GET compatibility path, and uses
non-authenticating revocation references instead of exposing dashboard session
cookie bearers in the admin inventory. Main CI run
[#39984997001](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/39984997001)
and publisher run
[#39984997106](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/39984997106)
passed. The publisher built and smoke-tested ARM64/AMD64 images, recorded
immutable digests, generated detached SPDX SBOMs, verified provenance/SBOM
attestations against the source and exact image digests, and published/read
back the stable manifest. The public `routeros-stable` manifest names this
source commit and both immutable architecture tags.

| Platform | Immutable image tag | Registry digest |
| --- | --- | --- |
| RouterOS ARM64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-beba66c0f36231511ec1b9cc664f2be39a128750-arm64` | `sha256:1dad53e8e89acab230ae69703cec319a64ce472ca1336c491d7aa13e022f96f5` |
| AMD64 / CHR | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-beba66c0f36231511ec1b9cc664f2be39a128750-amd64` | `sha256:dd576d101fe0a16070c27eece09757f5f765c1536703feaa786f43d28f74e26e` |

These are immutable published mainline images, not a numbered release; v2.7.0
remains the latest formal release. Publication did not stage or run the updater
on RouterOS and is not candidate-specific acceptance or production promotion.
PR #803 canary staging and rollback evidence is historical. Current PR #806
staging and pending full live acceptance are recorded above.

### Previously published mainline image — PR #793 — 2026-10-23

PR [#793](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/793)
merged as `fbcbe96ff9fc56ffa5b0f750b8e72d59fbeeb164`. It bounds Engine.IO
polling client state (default 128), makes established ASGI authorization waits
finite and fail-closed, and extends release-acceptance runbook coverage. Main CI
run [#39941787724](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/39941787724)
and publisher run
[#39941787902](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/39941787902)
passed. The publisher built and smoke-tested both architectures, recorded
immutable digests, generated and attested detached SPDX SBOMs, verified
provenance/SBOM attestations against the source and exact image digests, and
published/read back the stable manifest.

| Platform | Immutable image tag | Registry digest |
| --- | --- | --- |
| RouterOS ARM64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-fbcbe96ff9fc56ffa5b0f750b8e72d59fbeeb164-arm64` | `sha256:b3d347184b016851d6e0b43135ee2831ebb2ba7e3dc5f4bca2270e8fa4c5bc10` |
| AMD64 / CHR | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-fbcbe96ff9fc56ffa5b0f750b8e72d59fbeeb164-amd64` | `sha256:53fa088b3b7eafa110fd95db823f554d524070a9367ab2816879182ebacbc708` |

These are immutable published mainline images, not a numbered release; v2.7.0
remains the latest formal release. No RouterOS staging for PR #793 was
recorded at the time; later PR #803 staging and rollback evidence is historical,
and the current PR #806 state is documented above. Neither publication record
replaces the pending live acceptance gates.

### Previously published mainline image — PR #791 — 2026-10-23

PR [#791](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/791)
merged as `0002ce431fd8be0a66801725fbfb371f01ce7567`. It adds precise,
redacted step diagnostics to `scripts/routeros/immutable-release-updater.rsc.example`
and a regression contract. The example script is not copied into the container
image. Main CI run
[#39925624459](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/39925624459)
and publisher run
[#39925624510](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/39925624510)
passed; the published image was smoke-tested and its provenance/SBOM
attestations verified.

| Platform | Immutable image tag | Registry digest |
| --- | --- | --- |
| RouterOS ARM64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-0002ce431fd8be0a66801725fbfb371f01ce7567-arm64` | `sha256:a61103b00e34ce5172ca084e6744dba2326fc351e5cca362c9fb7951430e581e` |

This publication did not stage or run the example updater on RouterOS and is
not candidate-specific acceptance or production promotion. PR #793 and then
PR #794 superseded it at the time; PR #811 was the latest published mainline
image when this historical entry was written. PR #815 and later PR #817 have
since superseded it. It is not a numbered release.

### Previously published mainline image — PR #778 — 2026-10-23

PR [#778](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/778)
merged as `10721ebc7a0a4db2fb8ef82a80783376140e4205`. It adds redacted
CSRF Origin/Referer rejection diagnostics and binds Engine.IO transport SIDs
to the active dashboard session before the handshake packet is sent. Main CI
run
[#39882283490](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/39882283490)
and publisher run
[#39882283500](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/39882283500)
passed. The publisher smoke-tested the ARM64 image, and the provenance and
SPDX SBOM attestations verified against the container workflow and exact main
source commit.

| Platform | Immutable image tag | Registry digest |
| --- | --- | --- |
| RouterOS ARM64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-10721ebc7a0a4db2fb8ef82a80783376140e4205-arm64` | `sha256:f518688d46cb7b1c089ad63d2310263076e7f067b4ada597a651dd4e349ba832` |

No RouterOS staging for this image is recorded. It was superseded by PR #794
at the time of that earlier record; PR #811 was then the latest published
image, later superseded by PR #815 and PR #817. PR #776 below is a historical
candidate-bound record; the current PR #806
canary evidence is above. No #778 hardware acceptance is claimed. Production
was not changed. This is an immutable published mainline image, not a numbered
release; v2.7.0 remains the latest formal release. Do not tag or publish
v2.8.0 until the current candidate-specific acceptance gates pass.

### Historical candidate-bound canary record — PR #776 — 2026-10-23

PR [#776](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/776)
merged as `c4b4b76793b2454e81362867d8654962627de6fa`. The logout path now
revokes the server-side session before persisting the audit event, and tests
cover the audit-write failure path. Main CI run
[#39867875857](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/39867875857)
and publisher run
[#39867875877](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/39867875877)
passed. The published ARM64 and AMD64 image attestations verify against the
`container.yml` workflow, repository, and exact `main` source commit.

| Platform | Immutable image tag | Registry digest |
| --- | --- | --- |
| RouterOS ARM64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-c4b4b76793b2454e81362867d8654962627de6fa-arm64` | `sha256:8b5dfa0d2c4fae542e0c560576a91432812823ebe55ecc6bcad7bbfa7c0e922e` |
| AMD64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-c4b4b76793b2454e81362867d8654962627de6fa-amd64` | `sha256:fad2b337196e5fe09d2040acb3353e4acc5fe2d894bc49866a0470369c75d4f9` |

The stable release manifest asset was published and read back; its SHA-256 is
`d00f32bb8c77f89232350cadccd15bb181fac6df03de965ce10cff452705833e`.
On 2026-10-23, the RouterOS canary updater was invoked for the ARM64 tag. The
latest recorded read-back confirmed that immutable tag and healthy startup;
the updater was no longer active and no completed 30-minute sample record was
verified. The readiness gate is not passed. A later dashboard observation
showed a connected-user change without manual refresh; exact latency was not
timed. A canary sign-out attempt was rejected by the origin check and did not
revoke the session; its request header shape remains unknown. The persisted
pending-candidate record did not match the later canary image, so it does not
bind a passing soak to that image. Production remained on its prior image. CI,
image publication, and provenance verification do not constitute RouterOS
acceptance. The formal version remains v2.7.0; do not create v2.8.0 until
candidate-specific acceptance passes.

### Previously published mainline candidate — PR #772 — 2026-10-19

PR [#772](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/772)
merged as `624bfbf032396b3b2b21cab1a659985b6d580f79`. It applies a fail-closed
process core-dump limit before application and server startup. Main CI run
[#39242524458](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/39242524458)
and publisher run
[#39242524446](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/39242524446)
passed. The publisher built and smoke-tested ARM64/AMD64 images, verified
detached provenance and SPDX SBOM attestations, and read back the stable
manifest. These results do not establish RouterOS host core-dump collector
policy or canary/production acceptance.

| Platform | Immutable image tag | Published digest |
| --- | --- | --- |
| RouterOS ARM64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-624bfbf032396b3b2b21cab1a659985b6d580f79-arm64` | `sha256:b341f063e405283ea1647670073665375aa3213300afd3b2b4076e7039377fbd` |
| CHR/x86 AMD64 (evaluation) | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-624bfbf032396b3b2b21cab1a659985b6d580f79-amd64` | `sha256:2cf79dfecf4231f8b33c9e675d64982adc392197ab428dbccde803d2e7bd1721` |

On 2026-10-19, the PR #772 ARM64 tag was staged on the isolated canary.
RouterOS read-back reported the configured immutable tag and a healthy
container at that point in time; the post-start check found zero active VPN
sessions. This is startup evidence, not a canary acceptance result: the
30-minute soak, live-session freshness/reconnect, failure recovery, deployed
security checks, and rollback remain unverified. At that read-back, production
remained on its prior image. The formal version remains v2.7.0; do not tag or
publish v2.8.0 until the candidate-specific acceptance gates pass. See
[the candidate report](LIVE_TELEMETRY_ACCEPTANCE_REPORT.md).

### Previously published mainline candidate — PR #767 — 2026-10-19

PR [#767](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/767)
merged as `19f7ca90915871d5cfa9e68f356f62dadc90ddf8`. It replaces the fixed
static-asset cache version with content-hashed asset URLs, allowing clients to
fetch the current bundle after an update. Publisher run
[#39194800313](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/39194800313)
passed source/security checks, compilation and the full test suite, rendered
browser/accessibility checks, ARM64 and AMD64 publication/runtime smoke,
detached provenance and SPDX SBOM attestation verification, and stable-manifest
publication/read-back. Provenance was verified against the exact source and
artifact.

| Platform | Immutable image tag | Published digest |
| --- | --- | --- |
| RouterOS ARM64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-19f7ca90915871d5cfa9e68f356f62dadc90ddf8-arm64` | `sha256:dd78656ff241eb090cba52c3825a5421b902983a139b9f91403f82f2109586d5` |

This candidate was observed on the isolated canary on 2026-10-19, with the
dashboard and Connections page loading and zero active sessions/devices at the
check. This point-in-time status is not a 30-minute readiness window,
live-session acceptance, or rollback rehearsal. PR #772 supersedes it as the
then-latest published candidate at the time of that checkpoint.

### Previously published mainline candidate — PR #761 — 2026-10-18

PR [#761](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/761)
merged as `e8af615c42145b9b6a1ea44bee9b217ffc5dc4be`. It rejects anonymous,
unknown, expired, and revoked dashboard sessions before Engine.IO allocates an
HTTP or WebSocket transport; the early check is fail-closed and nonblocking,
does not refresh the idle deadline, and leaves role/capability checks intact.
Publisher run
[#39168925504](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/39168925504)
passed source/security checks, compilation and the full test suite, rendered
browser/accessibility checks, ARM64 and AMD64 publication/runtime smoke,
detached provenance and SPDX SBOM attestation verification, and stable-manifest
publication/read-back. The stable manifest asset's digest is
`sha256:5dec3e1c0433cef382ff9b687dd10581e48f9192e61133fb30721d5fc08dbce2`.

| Platform | Immutable image tag | Published digest |
| --- | --- | --- |
| RouterOS ARM64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-e8af615c42145b9b6a1ea44bee9b217ffc5dc4be-arm64` | `sha256:0d58f3b2c24281d82064b9d95da9d31bb56073c0daa0f116bd7c3e2d8b90d32b` |
| CHR/x86 AMD64 (evaluation) | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-e8af615c42145b9b6a1ea44bee9b217ffc5dc4be-amd64` | `sha256:e949bfa43ed1f0ac989cc3a32da95da26a19e5b028fe14761fbca061c4cc305c` |

These artifacts are published, not evidence of deployment acceptance for the
current candidate. PR #772 supersedes this image on mainline. The formal version
remains v2.7.0, and v2.8.0 must not be tagged or published until the current
candidate-specific canary gates pass.

### Previously published mainline candidate — PR #759 — 2026-10-18

PR [#759](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/759)
merged as `f426e2f6cc8d048ce954790ca6f110a3c5226796`. It fixes the live
interface-counter projection so nested broker samples, cumulative totals, and
measured rates reach the redacted telemetry frame. Publisher run
[#39163698221](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/39163698221)
passed source/security checks, compilation and tests, rendered
browser/accessibility checks, ARM64 and AMD64 publication and runtime smoke,
detached provenance and SPDX SBOM attestation verification, and stable-manifest
publication/read-back. Provenance and SBOM attestations were independently
verified against each exact image digest and source commit. The downloaded
`routeros-stable` manifest matches this commit and both immutable architecture
tags; its SHA-256 is
`2f1e065cfb403b5cf9d7425b4e523d43b71636347b218f97aabaa69a315f5ff5`.

| Platform | Immutable image tag | Published digest |
| --- | --- | --- |
| RouterOS ARM64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-f426e2f6cc8d048ce954790ca6f110a3c5226796-arm64` | `sha256:c4ef9388763215123bf77abe6253dc84f12d66bbc28f8eb21b88574f38d6ad33` |
| CHR/x86 AMD64 (evaluation) | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-f426e2f6cc8d048ce954790ca6f110a3c5226796-amd64` | `sha256:bfcd2cd35fe3530f68ae427b0f8ac3fe0fc90ec8fec4b9e2b0161f9aa089a6b9` |

These artifacts are published, not deployed to RouterOS. PR #772 supersedes
them on mainline. Live-session acceptance remains unverified; the formal
version remains v2.7.0, and v2.8.0 must not be tagged or published until the
candidate-specific canary gates pass.

### Previously published mainline candidate — PR #758

PR [#758](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/758)
merged as `2a6380330b0d181035429c3d862d2936823a860f` and rejects duplicate
CSRF token headers. Publisher run
[#39161334265](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/39161334265)
passed for both architectures and published the stable manifest. These
immutable images remain an earlier rollback candidate; PR #759 supersedes them
on mainline. They are published, not evidence of RouterOS deployment or live
acceptance.

| Platform | Immutable image tag | Published digest |
| --- | --- | --- |
| RouterOS ARM64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-2a6380330b0d181035429c3d862d2936823a860f-arm64` | `sha256:17661812aaaa62ab48928dfc53ebff07ecebdc49b3ed8fbf9854ec6bf36de16` |
| CHR/x86 AMD64 (evaluation) | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-2a6380330b0d181035429c3d862d2936823a860f-amd64` | `sha256:1a87286a2511c99f3a4cd9bc09fa2d174871dedfd32320f69fc87839b957241e` |

### Previously published mainline candidate — PR #755 — 2026-10-15

PR [#755](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/755)
merged as `f16fe17cc2251939bcdfc10eeb26e8c0be85e9c1`. It binds the live
telemetry supervisor to an opaque active-session reference, stops and closes
the stream after session expiry or revocation, serializes event dispatch
against invalidation, and protects Binary API close races. Publisher run
[#38819845718](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/38819845718)
completed successfully for this exact merge commit. Both architectures passed
published-runtime smoke tests and exact-image provenance/SBOM attestation
verification. The stable manifest asset was read back successfully; its digest
is `sha256:33c84af3388d97d6f09e79a6b3247298462610ed41d19bd8caffb2e9b5d61cf1`.

| Platform | Immutable image tag | Published digest |
| --- | --- | --- |
| RouterOS ARM64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-f16fe17cc2251939bcdfc10eeb26e8c0be85e9c1-arm64` | `sha256:1ad03a1f383c6e25ce29548413c8b98f3938a202590934210d16ff628efb893e` |
| CHR/x86 AMD64 (evaluation) | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-f16fe17cc2251939bcdfc10eeb26e8c0be85e9c1-amd64` | `sha256:4437eec31d67c781641bb9eea2cdb2c823a35eace245be8e6cf03e5368ef8c18` |

These artifacts are published, not deployed to RouterOS. No live-session
acceptance or RouterOS compatibility result is inferred from CI publication.
Candidate-specific canary acceptance and rollback rehearsal remain pending;
the formal version remains v2.7.0.

### Previously published mainline candidate — PR #751 — 2026-10-15

PR [#751](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/751)
was merged as `e2e64c68167ccb2f7ff06e5e815e47b1981483e9`. Publisher run
[#38750050793](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/38750050793)
passed source/security checks, compilation and tests, rendered
browser/accessibility checks, ARM64 and AMD64 publication and runtime smoke,
detached provenance and SPDX SBOM attestation verification, and stable-manifest
publication/read-back. The image digests were independently resolved from the
public registry after the run.

| Platform | Immutable image tag | Published digest |
| --- | --- | --- |
| RouterOS ARM64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-e2e64c68167ccb2f7ff06e5e815e47b1981483e9-arm64` | `sha256:177c80d75d5d95681342c0015502b3ac3dd6a7deb1e15b579c1b6704fe2b0001` |
| CHR/x86 AMD64 (evaluation) | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-e2e64c68167ccb2f7ff06e5e815e47b1981483e9-amd64` | `sha256:4b3ac3e76009c18c29053454b104109dcca32c90ef237f525b049293a866a5f2` |

The stable `routeros-release.json` manifest was read back and points to this
source commit and these immutable architecture tags. Publication does not
establish RouterOS deployment or candidate-specific acceptance. Do not tag or
publish v2.8.0 until those acceptance gates pass.

### Previously published mainline candidate — PR #745 — 2026-10-15

PR [#745](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/745)
merged as `ad3cd3df72ea8a6dbb08e3a7b5ac0e97d19a5ed6`. It preserves an active
VPN session when an initial RouterOS observation lacks complete interface
counters; history starts at zero and later complete samples populate the real
totals. Publisher run
[#38720533595](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/38720533595)
passed source/security checks, compilation and tests, rendered
browser/accessibility checks, ARM64 and AMD64 publication and runtime smoke,
detached provenance and SPDX SBOM attestation verification, and stable-manifest
publication/read-back. Provenance was verified for the exact published image
digests and source commit.

| Platform | Immutable image tag | Published digest |
| --- | --- | --- |
| RouterOS ARM64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-ad3cd3df72ea8a6dbb08e3a7b5ac0e97d19a5ed6-arm64` | `sha256:4b3a0fbf6ad3943ce05bbd256f3d2930e2fa89808ccded46779066a484b6b66e` |
| CHR/x86 AMD64 (evaluation) | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-ad3cd3df72ea8a6dbb08e3a7b5ac0e97d19a5ed6-amd64` | `sha256:95a447476d82c4663fb4ba7cf7aef44da2ff7f4c4999ba988f58a30c51a81f5a` |

The stable `routeros-release.json` manifest was read back and points to this
source commit and these immutable architecture tags. CI publication and smoke
tests do not prove RouterOS hardware compatibility, deployment, or live
acceptance. No new numbered release was created; v2.7.0 remains the latest
formal version.

### Previously published mainline candidate — PR #741 — 2026-10-15

PR [#741](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/741)
merged as `ec7b47e49ae74cfb50fc49142ed9f02be99fa0d9`. It prevents RouterOS
HTTP error bodies and transport-specific exception strings from reaching
authenticated API error responses while retaining safe HTTP status and typed
timeout/TLS classification. Publisher run
[#38706097408](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/38706097408)
passed source/security checks, compilation and tests, rendered
browser/accessibility checks, ARM64 and AMD64 publication and runtime smoke,
detached provenance and SPDX SBOM attestation verification, and stable-manifest
publication/read-back. Provenance was verified for the exact published image
digests and source commit.

| Platform | Immutable image tag | Published digest |
| --- | --- | --- |
| RouterOS ARM64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-ec7b47e49ae74cfb50fc49142ed9f02be99fa0d9-arm64` | `sha256:f65908e4b993a32c22da0d6c865738df8579f46c6b4e928a8caf16628527e99f` |
| CHR/x86 AMD64 (evaluation) | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-ec7b47e49ae74cfb50fc49142ed9f02be99fa0d9-amd64` | `sha256:1071c74f4efb146b57096ab61b01a9875f42969ed67e119caa8d82139316943e` |

At the time, the stable manifest read-back matched this source revision and its
immutable architecture tags. These artifacts are published and CI-smoke-tested; they do
not prove RouterOS hardware compatibility, deployment, or live acceptance. No
new numbered release was created; v2.7.0 remains the latest formal version.

### Previously published mainline candidate — PR #740 — 2026-10-15

PR [#740](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/740)
merged as `5fb793d67f519b14d41fb8a5ac0665480294967d`. Automatic requests to
`/api/status` and `/api/certificate-settings` no longer touch the administrator
session, preventing background polling from extending an idle session. RouterOS
passwords are excluded from credential representations. Publisher run
[#38704009698](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/38704009698)
passed source/security checks, compilation and tests, rendered
browser/accessibility checks, ARM64 and AMD64 publication and runtime smoke,
detached provenance and SPDX SBOM attestation verification, and stable-manifest
publication/read-back.

| Platform | Immutable image tag | Published digest |
| --- | --- | --- |
| RouterOS ARM64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-5fb793d67f519b14d41fb8a5ac0665480294967d-arm64` | `sha256:9cc5e54a9460fe8dd64b9c8ce02dea5b95bd67984fbc3fe2d22c052064aace01` |
| CHR/x86 AMD64 (evaluation) | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-5fb793d67f519b14d41fb8a5ac0665480294967d-amd64` | `sha256:fef4e71496804b27304a422bb64843be0a0d6a1822d4fe8051f7ecf892179c49` |

These artifacts are published and CI-smoke-tested, but do not prove RouterOS
deployment or live acceptance. No numbered release was created; v2.7.0 remains
the latest formal version.

### Previously published mainline candidate — PR #730 — 2026-10-15

PR [#730](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/730)
merged as `16c2590f815f31a1c72e78adf00d3cfce4a13162`. It hardens the
read-only device-posture inventory match: both the stored RouterOS certificate
ID and normalized fingerprint must match the current certificate. Publisher
run
[#38679376787](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/38679376787)
passed source/security checks, compilation and tests, rendered
browser/accessibility checks, ARM64 and AMD64 publication and runtime smoke,
detached provenance and SPDX SBOM attestation verification, and stable-manifest
publication/read-back. Provenance was verified for the exact published image
digests and source commit.

| Platform | Immutable image tag | Published digest |
| --- | --- | --- |
| RouterOS ARM64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-16c2590f815f31a1c72e78adf00d3cfce4a13162-arm64` | `sha256:533141633290eae4a5b052d12be2a9759865950bfc976ab1c1b9431f9d52af71` |
| CHR/x86 AMD64 (evaluation) | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-16c2590f815f31a1c72e78adf00d3cfce4a13162-amd64` | `sha256:470206cd75049b0f7d0d1a6cc73028c30dfdb2c80afb259e2382626f680a3d9d` |

The stable manifest read-back matched this source revision and its immutable
architecture tags. These artifacts are published and CI-smoke-tested; they do
not prove RouterOS hardware compatibility, deployment, or live acceptance. No
new numbered release was created; v2.7.0 remains the latest formal version.

### Previously published mainline candidate — PR #728 — 2026-10-15

PR [#728](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/728)
merged as `54701d59afcb959a1b18faa160e0a692c615b88d`. It changes the pinned
Python base image reference from the public ECR mirror to Docker Hub's official
`library/python` image while retaining the identical pinned manifest digest.
This addresses ECR's registry-side data-limit response; it is a build-source
change, not an application feature change. Publisher run
[#38675016514](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/38675016514)
passed release-source checks, rendered browser/accessibility checks, ARM64 and
AMD64 builds, published-runtime smoke tests, detached provenance and SPDX SBOM
attestation verification, and stable-manifest publication/read-back. The image
provenance was also independently verified for both digests against this exact
repository, `main` ref, source commit, and workflow signer.

| Platform | Immutable image tag | Published digest |
| --- | --- | --- |
| RouterOS ARM64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-54701d59afcb959a1b18faa160e0a692c615b88d-arm64` | `sha256:3c037909df18fc8a36ba8cc9ad8b0d1b17b650f249e6de24967fe51e1f4dd2cc` |
| CHR/x86 AMD64 (evaluation) | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-54701d59afcb959a1b18faa160e0a692c615b88d-amd64` | `sha256:fee62e4687458473a14fd95b666819da4653f4d0435c4c9204ecb9b083898f1c` |

The stable manifest asset was read back and matched this source commit. These
artifacts are published and CI-smoke-tested; they are not RouterOS hardware
certification or live acceptance evidence. No new numbered release was created;
v2.7.0 remains the latest formal version.

### Previously published mainline candidate — PR #720 — 2026-10-14

PR [#720](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/720)
merged as `6dd53022523766a5371628dfe158286072494bf4`. It serializes authorized
Socket.IO telemetry delivery with concurrent session invalidation so logout,
revocation, expiry, purge, bulk logout, or rotation cannot race a queued live
send. Publisher run
[#38620869138](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/38620869138)
completed successfully: source/release checks, rendered browser and
accessibility checks, ARM64 and AMD64 image publication, provenance and SPDX
SBOM attestation verification, published-runtime smoke tests, and stable
manifest publication all passed.

| Platform | Immutable image tag | Published digest |
| --- | --- | --- |
| RouterOS ARM64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-6dd53022523766a5371628dfe158286072494bf4-arm64` | `sha256:8379e885c3f52585c3badbb8069c483edd60e4eb526756701d1a90ab409de31d` |
| CHR/x86 AMD64 (evaluation) | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-6dd53022523766a5371628dfe158286072494bf4-amd64` | `sha256:2339d4d8e3e003eab8f6c99d9aad6cf5a748ac161716e23f179ea513bb351271` |

The stable manifest was published. These artifacts are published and
CI-smoke-tested, but candidate-specific RouterOS acceptance and deployment
remain unverified; no canary or production promotion is claimed. No new
numbered release was created; v2.7.0 remains the latest formal version.

### Previously published mainline candidate — PR #716 — 2026-10-14

PR [#716](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/716)
merged as `8661e69b545782f1b63ec3badb2600b8645d986f`. It serializes Socket.IO
telemetry delivery with fresh RouterOS-role revalidation, keeping blocking role
refreshes off the ASGI event loop and preventing authorization refresh races
with queued telemetry. Publisher run
[#38595948468](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/38595948468)
completed successfully with source/security checks, compilation, tests,
ARM64/AMD64 builds, provenance/SBOM attestation verification, stable-manifest
read-back, and published-runtime smoke tests.

| Platform | Immutable image tag | Published digest |
| --- | --- | --- |
| RouterOS ARM64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-8661e69b545782f1b63ec3badb2600b8645d986f-arm64` | `sha256:05844f828e9cde5ae3cc31f1afaa51e067a4519f41d0ed20086e57475d5d3a2f` |
| CHR/x86 AMD64 (evaluation) | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-8661e69b545782f1b63ec3badb2600b8645d986f-amd64` | `sha256:2b29049b1ac6b630c3eeb2bd3542dd1612a6c24d63d88c0caf3f04c950430658` |

The stable manifest was published and read back with these immutable tags.
Candidate-specific RouterOS acceptance remains incomplete; publication and CI
smoke tests do not prove deployment or live compatibility. No canary or
production promotion is claimed. No new numbered release was created; v2.7.0
remains the latest formal version.

### Previously published mainline candidate — PR #714 — 2026-10-14

PR [#714](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/714)
merged as `4e9b7a803f45224a6906ad5feb92c0baf600437a`. It bounds ASGI request
bodies at the application's 64 KiB limit, rejects oversized requests before
unbounded buffering, and adds real-server connection-close regression tests.
Publisher run
[#38582850210](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/38582850210)
passed source/pre-commit and secret checks, compilation, unit/mock and rendered
browser tests, ARM64/AMD64 builds, provenance/SBOM attestation verification,
stable-manifest read-back, and published-runtime smoke tests.

| Platform | Immutable image tag | Published digest |
| --- | --- | --- |
| RouterOS ARM64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-4e9b7a803f45224a6906ad5feb92c0baf600437a-arm64` | `sha256:87c7f80138ae9ca1c88cedcc04748848680582aa324ab9abe8da36f96c0a7fa8` |
| CHR/x86 AMD64 (evaluation) | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-4e9b7a803f45224a6906ad5feb92c0baf600437a-amd64` | `sha256:ad230039470a519d58bba0cc6236d9023c2976060c3c6f51d481dd0df4247940` |

The stable manifest was published and read back with these immutable tags.
Candidate-specific RouterOS acceptance remains incomplete; publication and CI
smoke tests do not prove deployment or live compatibility. No canary or
production promotion is claimed. No new numbered release was created; v2.7.0
remains the latest formal version.

### Previously published mainline candidate — PR #709 — 2026-10-14

PR [#709](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/709)
merged as `27708980031be0bf114794610187437ebe26ad02`. It closes #199 with a
bounded, read-only SQLite restore rehearsal: temporary restore paths receive
owner-only permissions, integrity/schema/row-count parity is checked, output is
limited to safe evidence, and the production backup is not inspected during
canary pre-promotion. Publisher run
[#38555014198](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/38555014198)
passed source/pre-commit and secret checks, compilation, unit/mock and rendered
browser tests, ARM64/AMD64 image builds, provenance/SBOM attestation
verification, stable-manifest read-back, and published-runtime smoke tests.

| Platform | Immutable image tag | Published digest |
| --- | --- | --- |
| RouterOS ARM64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-27708980031be0bf114794610187437ebe26ad02-arm64` | `sha256:0a385f99aa4bf371d76eab10a76f83ffb7f7bfc2b63934cab93fd4ee375d8cc9` |
| CHR/x86 AMD64 (evaluation) | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-27708980031be0bf114794610187437ebe26ad02-amd64` | `sha256:36cda5ba3d8adf2655c876789f66cac0f5345fccbddb0e7b96f2e844f6856a1e` |

The stable manifest was published and read back with these immutable tags.
Candidate-matched RouterOS acceptance remains incomplete; publication and CI
smoke tests do not prove deployment or live compatibility. No production
promotion is claimed. No new numbered release was created; v2.7.0 remains the
latest formal version.

### Previously published mainline candidate — PR #705 — 2026-10-14

PR [#705](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/705)
merged as `5f19eb14710ac79b60f7447ebb6c2cb72ae20e16`. It hardens cleanup of
temporary RouterOS profile-export artifacts and preserves artifacts when
ownership cannot be established. Publisher run
[#38529872403](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/38529872403)
passed source and rendered-browser verification, ARM64/AMD64 builds, provenance
and SPDX SBOM attestation verification, stable-manifest read-back, and
published-runtime smoke tests.

| Platform | Immutable image tag | Published digest |
| --- | --- | --- |
| RouterOS ARM64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-5f19eb14710ac79b60f7447ebb6c2cb72ae20e16-arm64` | `sha256:2300bd04f33cc0091749b9afc4140638aa48b2b8a93afdfa9e07d9a4423761cb` |
| CHR/x86 AMD64 (evaluation) | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-5f19eb14710ac79b60f7447ebb6c2cb72ae20e16-amd64` | `sha256:ab783cbab9f41269c6c2453050764257156bffd8518acdfdc7777ccdfccafb7a` |

The stable manifest was published and read back with these immutable tags. The
controlled 30-minute canary acceptance window is not complete; event
latency/freshness, recovery, event integrity, Redis delivery, resource soak,
restore, and rollback evidence remain outstanding. No production promotion is
claimed. No new numbered release was created; v2.7.0 remains the latest formal
version.

### Previously published mainline candidate — PR #702 — 2026-10-14

PR [#702](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/702)
merged as `7c91a0f3425ca729cb6ffe12004c2a6e787ac97d`. It adds a read-only
RouterOS CRL configuration observation to Device Profiles; it does not claim
CRL freshness or end-to-end revocation enforcement. Publisher run
[#38519276211](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/38519276211)
passed source verification (including 651 unit/mock tests), 229 rendered
browser checks, ARM64/AMD64 builds, provenance and SPDX SBOM attestation
verification, stable-manifest read-back, and published-runtime smoke tests.

| Platform | Immutable image tag | Published digest |
| --- | --- | --- |
| RouterOS ARM64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-7c91a0f3425ca729cb6ffe12004c2a6e787ac97d-arm64` | `sha256:4682a2eed339aec7e4d77173f017be8510f4ad06227dfd4e92846a2345e11595` |
| CHR/x86 AMD64 (evaluation) | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-7c91a0f3425ca729cb6ffe12004c2a6e787ac97d-amd64` | `sha256:23fd167259d2dab2acdd7dee6e14b6741811fc438591cee3571ccb0ba18d6082` |

The stable manifest was published and read back by the workflow with these
immutable architecture tags. The controlled 30-minute canary acceptance window
is not complete; event latency/freshness, recovery, event integrity, Redis
delivery, resource soak, restore, and rollback evidence remain outstanding.
No production promotion is claimed. No new numbered release was created;
v2.7.0 remains the latest formal version.

### Previously published mainline candidate — PR #692 — 2026-10-13

PR [#692](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/692)
merged as `8f68314bb54cc008edc02bf26e00cdaaa48284f3`. It revalidates the
RouterOS source session around privileged telemetry reads and publication and
adds bounded role revalidation. The
[publisher run](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/38468254627)
passed source verification, rendered-browser checks, ARM64 and AMD64 builds,
stable-manifest publication, image/SBOM attestations, and published-runtime
smoke tests.

| Platform | Immutable image tag | Published digest |
| --- | --- | --- |
| RouterOS ARM64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-8f68314bb54cc008edc02bf26e00cdaaa48284f3-arm64` | `sha256:14dcd6185d131c86196a439d15712c1e4b6b68caa0c34f8f5a6f0e5cde4313f5` |
| CHR/x86 AMD64 (evaluation) | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-8f68314bb54cc008edc02bf26e00cdaaa48284f3-amd64` | `sha256:e3db760e90b2828ef9acc741a380bf82acbe2b8bb345ea0d9f4b5367a7b1b5fa` |

The stable manifest was read back and verified against this commit and both
immutable architecture tags. The controlled 30-minute acceptance window is not
complete; event
latency/freshness, recovery, event integrity, Redis delivery, resource soak,
restore, and rollback evidence remain outstanding. No production promotion is
claimed. No new numbered release was created; v2.7.0 remains the latest formal
version.

### Previously published mainline candidate — PR #685 — 2026-10-13

PR [#685](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/685)
merged as `bc03f3b456a488fc464061fe5944278c0207a94f`. It fixes the RouterOS
disconnect read-back settling window so a just-terminated session is not
mistaken for a failed termination. Its publisher run
[#38449932684](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/38449932684)
published AMD64 and ARM64 images, verified image and SPDX SBOM attestations, and
passed published-runtime smoke tests. PR #709 was the then-current mainline
candidate at the time of this record; later candidates superseded it.

| Platform | Immutable image tag | Published digest |
| --- | --- | --- |
| RouterOS ARM64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-bc03f3b456a488fc464061fe5944278c0207a94f-arm64` | `sha256:b83dd23bab8124b493b676bdaf31c2e45ae8e89d8151822854c63cc348597824` |
| CHR/x86 AMD64 (evaluation) | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-bc03f3b456a488fc464061fe5944278c0207a94f-amd64` | `sha256:cf142629b4242d80d07d3c4582603d95954da571cfd8cbf0d04f0bcec06fd242` |

### Previously published mainline candidate — PR #674 — 2026-10-13

PR [#674](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/674)
merged as `3d65b43ec4b796eb83f52929c56c9efabb980b4d`. It defers session idle-
time refresh until a request has passed its authorization, CSRF, and capability
checks; rejected CSRF requests therefore cannot extend the idle session. The
post-merge [publisher run](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/38404891404)
passed source, full unit/mock integration, rendered browser/accessibility,
secret, dependency, and image-runtime checks. It published AMD64 and ARM64
images, generated and verified image and SPDX SBOM attestations, and passed
published-runtime smoke tests. The public `routeros-stable` manifest was read
back and names this commit and both immutable tags.

| Platform | Immutable image tag | Published digest |
| --- | --- | --- |
| RouterOS ARM64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-3d65b43ec4b796eb83f52929c56c9efabb980b4d-arm64` | `sha256:c2318a464f1a57d86ae27b9103aa5addbcae3bfe43aca3d60fdba7728c9f4fbb` |
| CHR/x86 AMD64 (evaluation) | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-3d65b43ec4b796eb83f52929c56c9efabb980b4d-amd64` | `sha256:7bd258595485a682ecc3892d32caaf29c9eecae377ec19b4f2071f702117f909` |

This artifact record does not assert RouterOS deployment or production
promotion of PR #674. Candidate-specific live acceptance, reconnect/recovery,
Redis delivery, event integrity, resource soak, restore, and rollback remained
incomplete. No new numbered release was created; v2.7.0 remains the latest
formal version.

### Previously published mainline candidate — PR #649 — 2026-10-13

PR [#649](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/649)
merged as
`2b76399f4fdc2cb1db7740b8e9887480cb083fee`. It narrows `/api/status`
connection-history and alert records to explicit safe-field allowlists and
adds exact-field and sensitive-sentinel regression coverage. The
[publisher run](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/38339271291)
passed source and browser/accessibility checks and published/attested both
architectures. The first AMD64 attempt hit an upstream Amazon ECR rate limit;
the failed job was rerun successfully. Both published-runtime smoke tests
passed, and the stable immutable manifest job succeeded.

| Platform | Immutable image tag | Published digest |
| --- | --- | --- |
| RouterOS ARM64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-2b76399f4fdc2cb1db7740b8e9887480cb083fee-arm64` | `sha256:c0e67ad2eb37f2adcec8d777ef5cae24fb3c96250b0fe0eb52dbc5b0e9c21b0f` |
| CHR/x86 AMD64 (evaluation) | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-2b76399f4fdc2cb1db7740b8e9887480cb083fee-amd64` | `sha256:f1cb27f25e9b6c6d5370317cb6c1b0c33d97ee7092e250ffbc2f25316d30e0ec` |

This artifact record does not assert RouterOS deployment or production
promotion of PR #649. The 30-minute live acceptance, Redis delivery,
reconnect/snapshot, event integrity, resource, restore, and rollback checks
remain open. No numbered GitHub release was created; v2.7.0 remains the latest
formal version.

### Previously published mainline candidate — PR #589 — 2026-10-10

PR [#589](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/589)
merged to main as
`148355fc0f40d9e7d17faa0baf8e4bd1d6dc73c0`. Publisher run
[#37997459148](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/37997459148)
passed source and rendered-browser checks, ARM64/AMD64 publication,
exact-digest provenance and SPDX SBOM attestation generation and verification,
and published-runtime smoke tests.

| Platform | Immutable image tag | Published digest |
| --- | --- | --- |
| RouterOS ARM64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-148355fc0f40d9e7d17faa0baf8e4bd1d6dc73c0-arm64` | `sha256:ab4e79a4c8e24a195423832da480f3e39d4767dd3b583f48335a43df32477aeb` |
| CHR/x86 AMD64 (evaluation) | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-148355fc0f40d9e7d17faa0baf8e4bd1d6dc73c0-amd64` | `sha256:d810d620bec734942712ff1fea6a94c63a9996579b3a9dfe389169c3658dc2c8` |

The exact image digests above were each verified against the repository's
`container.yml` signer workflow, source commit, and both provenance and SPDX
predicates. This artifact record omits deployment-specific router observations
and does not claim acceptance. Production promotion, sustained live acceptance,
and candidate-specific rollback remain pending. No new numbered release was
created; v2.7.0 remains the latest formal version.

### Historical published mainline candidate — PR #504 — 2026-10-06

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

This artifact record omits deployment-specific router observations and does
not claim acceptance. The 30-minute telemetry/Redis acceptance and
candidate-specific rollback rehearsal remain pending. No new numbered release
was created; v2.7.0 remains the latest formal version.

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

This artifact record omits deployment-specific router observations and does
not claim acceptance. The 30-minute telemetry/Redis acceptance and
candidate-specific rollback rehearsal remain pending. No new numbered release
was created; v2.7.0 remains the latest formal version.

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

This artifact record omits deployment-specific router observations and does
not claim acceptance. The formal 30-minute telemetry/Redis acceptance remains
separate from publication and CI verification. No new numbered release was
created; v2.7.0 remains current.

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

This is a published mainline image, not a new numbered release. This public
artifact history omits deployment-specific router observations and does not
claim that a manifest update changes a router. Sustained acceptance is a
separate, private operational procedure.

### Latest numbered release and earlier published runtime patch — PR #478

The latest formal release is **v2.7.0**, commit
`2e01f111e1445c79b1753477a41efbaec27a1a2d`. Subsequent main-branch runtime
patches are published as immutable commit tags without creating a numbered
release. PR [#478](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/478)
was an earlier published runtime patch, merged as `d5f8f4418d6ec972aa51ea4634b56c7fd89093f4`;
publication workflow
[#37294618814](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/37294618814)
passed. The published immutable tags/digests for this revision were:

| Platform | Immutable image tag | Published digest |
| --- | --- | --- |
| RouterOS ARM64 | `sha-d5f8f4418d6ec972aa51ea4634b56c7fd89093f4-arm64` | `sha256:1ec08a3a0c5d4741a701270ba30249aba62e215649170aa3a6b69c150fc41209` |
| CHR/x86 AMD64 (evaluation) | `sha-d5f8f4418d6ec972aa51ea4634b56c7fd89093f4-amd64` | `sha256:fad6a49eb253f52c5407369700833c7733f26972f49ae37fa012dd43e0a6f787` |

Deployment-specific router observations are omitted from this public artifact
history. Latency/freshness percentiles, API restart/recovery, counter-reset and
event-integrity checks, Redis delivery soak, and rollback drills remain
separate acceptance requirements.

### Earlier published candidate (historical)

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
`a2d0ce29943964c2a5c9a12d5a53650b3bbe16b3`. Deployment-specific router
observations are omitted from this public artifact history. Publication and
manifest state are not a substitute for a candidate-matched acceptance result;
the latest numbered release remains v2.7.0.

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

The repository's planned next release version is kept in [`VERSION`](../VERSION)
(currently `2.8.0`). Run `python scripts/validate_release.py --tag v2.8.0` before
creating that tag, and only after candidate-specific canary acceptance passes.
The
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
