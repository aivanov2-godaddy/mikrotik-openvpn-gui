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
CI provenance, and redacted deployment-gate status. It may include coarse,
candidate-bound point samples and aggregate outcomes. Router identity, detailed
RouterOS configuration, raw time-series telemetry, and session-level details
remain in private operational records.

The latest formal versioned release remains **v2.7.0**. The next planned version, v2.8.0, has not been tagged or published. PR #971 (`ec760fcfd4ed1cffa5e6ba067d997865fd27e03e`) is the latest published mainline image source; publication does not change the formal version. Post-merge CodeQL #43446742646, main CI #43446742822, and publisher run #43446742850 passed. The publisher's stable manifest and immutable architecture digests are recorded below. PR #971 has not been staged on RouterOS.

PR #966 merged documentation-only at `1d765cf7bf64aaffaf30b3937dc43790c3c09b6b`
before PR #971; its required
checks, post-merge main CI #43412162052, and CodeQL #43412161625 passed. It did
not publish a new image.

The latest RouterOS evidence is a TLS-verified Binary API container snapshot at 14:28:43 UTC on 2026-11-13, before PR #971 publication. It found the canary unhealthy and production running with a tag-only configured reference; runtime manifest identity was reconciled for both, but compared only with PR #965. Direct canary GETs at 14:37:16 UTC returned HTTP 200 and readiness `ready` for the old PR #894 revision. A TLS-verified REST healthcheck read at 14:37:49 UTC classified the default canary check as `segmentation_fault`. These pre-publication observations do not identify the failing process or root cause, establish a healthy rollback baseline, verify PR #971's running digest, or accept the candidate. No post-publication RouterOS readback or production deployment is verified.

Previous RouterOS checkpoint — 2026-11-13 11:03–11:29 UTC: the TLS-verified API snapshot found the canary unhealthy on its old PR #894 configured image and production running with a tag-only reference; neither running registry digest was verified. Direct canary GETs at 11:10:21 UTC returned HTTP 200 and readiness `ready` for the old PR #894 revision. A TLS-verified REST healthcheck comparison at 11:11:50 UTC classified the canary as `segmentation_fault`; production's healthcheck status was `good` with a healthy field true. A bounded filtered log read found no matching fault records. The PR #965 `--check-only` preflight blocked at `baseline / canary_unhealthy` with `router_writes_may_have_started=false`. A read-only WinBox list at 11:28:59 UTC showed the canary unhealthy and production healthy but did not expose image references or running digests.

PR #893
(`c35ca40baf0132b38d60585b0252ab0ef35223b4`) updated the Python 3.15 Alpine
base-image digest. PR #891
(`58a680423a4d616eb926a47c486847c8a4c062fe`) rejects ambiguous Engine.IO
handshake parameters and requires an explicit supported transport for new
handshakes while preserving bound-SID compatibility. PR #889
(`61dae736ea8247dd77eb0a61cf2ca3007aced542`) retains the
Engine.IO admission quota through connection teardown and releases it on
disconnect, including failure paths. PR #885
(`f31bf9e0f6bac65dc6dea7fc00af99743c3e61fb`) preserves accurate
administrator-session revocation audit outcomes and reports queued cleanup retries
as pending. PR #879 (`c0e9ac980da5694a2be9560dcbad0f9234cb9009`) rejects cleartext
RouterOS REST endpoints except for the explicit test-only loopback opt-in.
PR #875
(`bd27e608f074f357461e41fa906b87e84553a363`) bounds the container readiness probe with Alpine BusyBox-compatible timeout syntax. PR #873
(`e7163beebda530f16619094e9e498f3da873f980`) preserves SQLite outbox insertion order when events share a timestamp, including across bounded delivery batches. PR #871
(`eb29581c8430ec862a8b47ee62268a74fec14518`) fixed the published ARM64 runtime-smoke setup in CI. PR #868
(`388baa247b2a12658c66f02d2d40826fe4759553`) bounds RouterOS REST response handling. PR #862
(`445c1d5ca0f28174629be8e8cd94f04de132f0fc`) hardened RouterOS and Redis transport policy. PR #860
(`d3be28625e9d3beb48e2bdf94855ac2b5f7111b1`) hardens CSV and profile diagnostics. PR #849
(`f4708f519a6810ceb7d253c37c199032800ea625`) added the most recent application-level authentication classification, distinguishing RouterOS HTTP 401 credential rejection from HTTP 403 permission denial. Publication is not a numbered release or evidence of RouterOS deployment.

For PR #871, main CI run
[#40602936825](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/40602936825)
and publisher run
[#40602936692](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/40602936692)
passed. The publisher built, scanned, attested, and smoke-tested both
architecture images and published/read back the stable
[`routeros-release.json`](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/releases/download/routeros-stable/routeros-release.json)
manifest. The manifest asset SHA-256 is
`sha256:02e2ec88e9591d0d7686edfeb4c5c0afbf3f4e28807dcdb9521b2035bbb2c84d`.
Code scanning returned zero open alerts on 2026-10-30. Exact immutable tags
and digests are recorded below.

## Latest published mainline image — PR #971 — 2026-11-13

PR [#971](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/971)
merged as `ec760fcfd4ed1cffa5e6ba067d997865fd27e03e`. Post-merge main CI run
[#43446742822](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/43446742822),
CodeQL run
[#43446742646](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/43446742646),
and container publisher run
[#43446742850](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/43446742850)
passed. The publisher built and scanned both architecture images, published
them by immutable digest, verified SLSA provenance and SPDX SBOM attestations,
smoke-tested both published runtimes, and published/read back the stable
manifest. The downloaded `routeros-release.json` asset SHA-256 is
`sha256:344b7778eb32b9d4c89cecaaa5a0cb532b4c13dec7a426fa0f12bb432fc0c976`.

| Platform | Immutable image tag | Registry digest |
| --- | --- | --- |
| RouterOS ARM64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-ec760fcfd4ed1cffa5e6ba067d997865fd27e03e-arm64` | `sha256:a9aa9ab634151ce4c4c3b30ee8ef4bac3c41504ea936cc540a5e8cd1df24112d` |
| AMD64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-ec760fcfd4ed1cffa5e6ba067d997865fd27e03e-amd64` | `sha256:d348019c1290e1baa23d35dcad254e290e285fd729241f67a9aa0d4d7ec81992` |

PR #971 fixes the narrow read allowlist used for runtime image identity
reconciliation; it is not a numbered release or RouterOS deployment. The
latest RouterOS read predates publication and found the canary unhealthy.
PR #971 has not been staged, no post-publication running digest is verified,
and no production deployment is claimed. Issue #927 remains open pending
canary fault diagnosis and candidate-bound RouterOS acceptance.

## Previous published mainline image — PR #965 — 2026-11-13

PR [#965](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/965) merged as 13cae96d27ad42920ca4685116cd475eaa457408. Post-merge main CI run [#43403760502](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/43403760502), main push analysis run [#43403760080](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/43403760080), and container publisher run [#43403760356](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/43403760356) passed. The publisher built and scanned both architecture images, published them by immutable digest, verified provenance and SPDX SBOM attestations, smoke-tested both published runtimes, and published/read back the stable manifest. The downloaded routeros-release.json asset SHA-256 is sha256:052e6fc22da92d8ca6ac6403fef5f18e76ba093964f90e3ee1e8ea5a8fdfb271.

| Platform | Immutable image tag | Registry digest |
| --- | --- | --- |
| RouterOS ARM64 | ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-13cae96d27ad42920ca4685116cd475eaa457408-arm64 | sha256:a83094cf709db13248e372b62dd2cdecf14d41ce2b20a88fda7e533a0ccf6f0c |
| AMD64 | ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-13cae96d27ad42920ca4685116cd475eaa457408-amd64 | sha256:026da66f73c838847343f65338d5941b02c9143d1bce16efe542ec99954865a1 |

PR #965 added privacy-safe diagnostics; it was not a numbered release or RouterOS deployment. It was not staged. At the latest RouterOS readback available while PR #965 was the current published image, the old PR #894 canary was unhealthy, production remained tag-only, and neither running registry digest was verified. The separate REST healthcheck read classified the default canary check as `segmentation_fault`. Issue #927 remains open pending canary fault diagnosis and candidate-bound RouterOS acceptance. No production deployment was claimed.

## Previous published mainline image — PR #935 — 2026-11-12

PR [#935](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/935)
merged as `3f8fc22ec3166b3074fb54f54c79d6dede256ed4`. Post-merge main CI run
[#43174815746](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/43174815746),
main push analysis run
[#43174814930](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/43174814930),
and container publisher run
[#43174815700](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/43174815700)
passed. The publisher completed both architecture builds and scans, verified
the release source and rendered browser behavior, and published/read back the
stable manifest. The downloaded `routeros-release.json` asset SHA-256 is
`sha256:6fb18fbbada53bceffad7418881c26a05e9481f2e2263eb954924fdcd5d195ae`.

| Platform | Immutable image tag | Registry digest |
| --- | --- | --- |
| RouterOS ARM64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-3f8fc22ec3166b3074fb54f54c79d6dede256ed4-arm64` | `sha256:fd8aa26111eefae378caf95c88909264550f8c9faf3f44dc2cca18d2fd7531bd` |
| AMD64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-3f8fc22ec3166b3074fb54f54c79d6dede256ed4-amd64` | `sha256:4aec06e36796a1c6ea019fa8559d1ba11e4a2373615f68490e4f8a1fff6122b1` |

Publication is not a numbered release or RouterOS deployment. PR #935 has not
been staged. The current canary remains pinned to the earlier PR #894 image and
RouterOS reports it unhealthy; production is healthy but still tag-only. Neither
running registry digest is verified. The new candidate's canary health, live
telemetry, recovery, privacy, and rollback acceptance remain pending. No
production deployment is claimed.

## Previous published mainline image — PR #926 — 2026-11-12

PR [#926](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/926)
merged as `301e725c8e3d28761fb408920f08947ee3f43075`. Post-merge main CI run
[#43126239562](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/43126239562),
CodeQL run
[#43126239938](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/43126239938),
and container publisher run
[#43126239602](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/43126239602)
passed. The publisher built and scanned ARM64 and AMD64 images, passed
published-runtime smoke tests, verified detached provenance and SPDX SBOM
attestations against the exact image digests, and published/read back the stable
manifest. The downloaded `routeros-release.json` asset SHA-256 is
`sha256:d286b4decf5cf102ea32a7bcf8592ff7cd199ef8929c09117ab581899d6ff10e`.

| Platform | Immutable image tag | Registry digest |
| --- | --- | --- |
| RouterOS ARM64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-301e725c8e3d28761fb408920f08947ee3f43075-arm64` | `sha256:969cff69318e9abc73a047c4a09afeca1268b8d73a3eec6d13a755529404e150` |
| AMD64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-301e725c8e3d28761fb408920f08947ee3f43075-amd64` | `sha256:3f1085d607ed87a4c129b88360ec9d874bf3c466f7372d09ad28e3f5f03a3ca1` |

Publication is not a numbered release or RouterOS deployment. At this
checkpoint PR #926 remained unstaged; the current canary and #935 candidate
state are recorded above. PR #926's exec-form healthcheck change has not been
validated on the RouterOS device. Issue #927 remains open, and #785, #200, and
production promotion remain gated.

## Previous published mainline image — PR #915 — 2026-11-11

PR [#915](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/915)
merged as `5db3a0d4a220348c2f49934db4a3263776390c6c`. Post-merge main CI run
[#43102229933](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/43102229933),
push/CodeQL workflow
[#43102229923](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/43102229923),
and container publisher run
[#43102229931](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/43102229931)
passed. The publisher built and scanned ARM64 and AMD64 images, generated and
verified provenance and SPDX SBOM attestations for each exact image digest,
passed published-runtime smoke tests, and read back the stable manifest. The
downloaded `routeros-release.json` asset SHA-256 is
`sha256:cf6fdcd90162a337257dc582ddc1fb68fd4bd6ac8e7a0354e04ec2a53afead05`.

| Platform | Immutable image tag | Registry digest |
| --- | --- | --- |
| RouterOS ARM64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-5db3a0d4a220348c2f49934db4a3263776390c6c-arm64` | `sha256:8b5fed8dda70ea1db628c4d261873458086ff4b8a381c33b2f9ebaf16abda407` |
| AMD64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-5db3a0d4a220348c2f49934db4a3263776390c6c-amd64` | `sha256:5805292d6f2f72a5c91ad2128c2b6e902bca4ccd033931875e3f4199e9961a76` |

Publication is not a numbered release or RouterOS deployment. PR #926 now
supersedes PR #915 as the latest published image. The current canary still
runs PR #894 and RouterOS reports it unhealthy; neither its running digest nor
the production running digest is verified. Issue #785 inventory reconciliation
and issue #200 candidate-bound acceptance remain open; production promotion
remains gated.

## Previous published mainline image — PR #909 — 2026-11-11

PR [#909](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/909)
merged as `344cd03a41d18eb3b98076d5dbed8be60ef60a02`. Post-merge CI run
[#42998004640](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/42998004640)
and container publisher run
[#42998004602](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/42998004602)
passed. The publisher built, scanned, attested, and smoke-tested ARM64 and
AMD64 images. Publisher verification passed for SLSA provenance and SPDX SBOM
attestations against both image digests. The stable manifest was published and
read back; its downloaded `routeros-release.json` asset has SHA-256
`sha256:1339e2288beef6aaab65f4bf868c01a3b610476a9ad615a8c7346c18f76d313e`.

| Platform | Immutable image tag | Registry digest |
| --- | --- | --- |
| RouterOS ARM64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-344cd03a41d18eb3b98076d5dbed8be60ef60a02-arm64` | `sha256:e97f72f3605cf4e4ef61f2df5b776c6b8c5bbe7421c1e4c32036e2293097bde7` |
| AMD64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-344cd03a41d18eb3b98076d5dbed8be60ef60a02-amd64` | `sha256:8352182d2687b8dd0f291be8ad0c8f2a46b5133bb9b73e859ad7583aa3bfa66a` |

Publication is not a numbered release or RouterOS deployment. PR #909 has not
been staged on RouterOS. The latest documented canary read-back remains PR #894;
its later unhealthy observation, canary-only restart, and missing post-restart
revision/soak evidence are recorded below. Production promotion remains gated.

## Previous published mainline image — PR #907 — 2026-11-11

PR [#907](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/907)
merged as `a03767c3e06791d591b2460bbd9a54209c8692c4`. Post-merge CI run
[#42955904009](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/42955904009)
and container publisher run
[#42955904268](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/42955904268)
passed. The publisher built, scanned, attested, and smoke-tested ARM64 and
AMD64 images. Its verification steps passed for SLSA provenance and SPDX SBOM
attestations for both image digests; separate local `gh attestation verify`
checks also passed for provenance. The stable manifest was published and read
back. Its downloaded `routeros-release.json` asset has SHA-256
`sha256:45f61f3cd9e48c6c0842dcad4806804fe811896f0416fcca9d410d79834c0082`.

| Platform | Immutable image tag | Registry digest |
| --- | --- | --- |
| RouterOS ARM64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-a03767c3e06791d591b2460bbd9a54209c8692c4-arm64` | `sha256:47176714b950de5d7889c78b1ce77e85b06315ebe8e6a1ab801172ccbc68ec6b` |
| AMD64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-a03767c3e06791d591b2460bbd9a54209c8692c4-amd64` | `sha256:82efb9b4f43466edc7da1e0e109040a78075e19c289ee8d3fc8d613dc1cd389c` |

Publication is not a numbered release or RouterOS deployment. PR #907 is
superseded as the latest published image by PR #909. The latest documented
canary read-back remains PR #894;
its later unhealthy observation, canary-only restart, and missing post-restart
revision/soak evidence are recorded below. Production was not changed.

## Previous published mainline image — PR #901 — 2026-11-11

PR [#901](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/901)
merged as `0fe43250131e3a5e598bd736278531bc4d71417f`. Post-merge CI run
[#42935464660](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/42935464660),
CodeQL run
[#42935464346](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/42935464346),
Dependency Graph run
[#42935470872](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/42935470872),
and publisher run
[#42935464716](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/42935464716)
passed. The publisher built, scanned, and smoke-tested ARM64 and AMD64 images,
then published the stable manifest. Independent `gh attestation verify` checks
passed for SLSA provenance and SPDX SBOM predicates for both exact image
digests, signed by `.github/workflows/container.yml` from this source commit.
The downloaded `routeros-release.json` asset has SHA-256
`sha256:55aae2f27b0469b807c27064a339a04bbb7c938c1198f51e033440aa9f2f67f4`.

| Platform | Immutable image tag | Registry digest |
| --- | --- | --- |
| RouterOS ARM64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-0fe43250131e3a5e598bd736278531bc4d71417f-arm64` | `sha256:fc7af0eb880bddca771bb7e73647c14f050bd674b4c0b450592ffedb2658ca4a` |
| AMD64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-0fe43250131e3a5e598bd736278531bc4d71417f-amd64` | `sha256:ac36036b13842a7bb2ac5611705403e1165c84ac2a07115af8a192f9ccf7ba6f` |

Publication is not a numbered release or RouterOS deployment. PR #901 has not
been staged on RouterOS. The latest documented canary read-back remains PR #894;
its later unhealthy observation, canary-only restart, and missing post-restart
revision/soak evidence are recorded below. Production was not changed.

## Previous published mainline image — PR #897 — 2026-11-04

PR [#897](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/897)
merged as `3d2471813c04c759ad6990726a31200b08d11b8c`. Post-merge CI run
[#41925772788](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/41925772788),
CodeQL run
[#41925772702](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/41925772702),
and publisher run
[#41925772734](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/41925772734)
passed. The publisher built, scanned, attested, and smoke-tested ARM64 and
AMD64 images and read back the stable manifest. Independent `gh attestation
verify` checks passed for the SLSA provenance and SPDX SBOM predicates against
both exact architecture digests, the expected workflow, and this source commit.
The downloaded `routeros-release.json` asset has SHA-256
`sha256:1b922a6f860118414e48a70c709252f7fd09ccf1d503c9250e6b387c254be564`.

| Platform | Immutable image tag | Registry digest |
| --- | --- | --- |
| RouterOS ARM64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-3d2471813c04c759ad6990726a31200b08d11b8c-arm64` | `sha256:4ddc87d662c3c48cf0632adecd379c4df9c35514939831b45b1bb093a188b4e4` |
| AMD64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-3d2471813c04c759ad6990726a31200b08d11b8c-amd64` | `sha256:1d6b77de4ed594b8eb8cabe8853f40d755807a36634aa5fb01611f29c364eb75` |

Publication is not a numbered release or RouterOS deployment. PR #897 has not
been staged on RouterOS. The latest documented canary read-back remains PR #894;
its later unhealthy observation, canary-only restart, and missing post-restart
revision/soak evidence are recorded below. Production was not changed.

## Previous published mainline image — PR #896 — 2026-11-04

PR [#896](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/896)
merged as `19edcd5f5a0f3db5f67f8f226d3588955cd8335e`. Post-merge CI run
[#41919295504](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/41919295504),
CodeQL run
[#41919293445](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/41919293445),
and publisher run
[#41919295251](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/41919295251)
passed. The publisher built, scanned, attested, and smoke-tested ARM64 and
AMD64 images and read back the stable manifest. Independent `gh attestation
verify` checks passed for the SLSA provenance and SPDX SBOM predicates against
both exact architecture digests, the expected workflow, and this source commit.
The downloaded `routeros-release.json` asset has SHA-256
`sha256:d0ae22d7553f653291fabb7681f184a990e8f5384c07a4597b0b3d4c8b37127f`.

| Platform | Immutable image tag | Registry digest |
| --- | --- | --- |
| RouterOS ARM64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-19edcd5f5a0f3db5f67f8f226d3588955cd8335e-arm64` | `sha256:f5046fe05e6a9f5e95510568df2431cc8cea00d1e3436b0080dd7b7ce023b3d4` |
| AMD64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-19edcd5f5a0f3db5f67f8f226d3588955cd8335e-amd64` | `sha256:012e61e5eca70fcabec08d0afef976a355402e567b89ecb563d2fa2a79c78dc4` |

Publication is not a numbered release or RouterOS deployment. No canary
read-back, live acceptance, or production promotion is claimed for PR #896;
production remains unchanged.

## Previous published mainline image — PR #894 — 2026-11-04

PR [#894](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/894)
merged as `84a3148de713abe49be0c7be8f21caa652b68dd9`. Post-merge CI run
[#41739821631](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/41739821631),
CodeQL run
[#41739821442](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/41739821442),
and publisher run
[#41739821658](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/41739821658)
passed. The publisher built, scanned, attested, and smoke-tested ARM64 and
AMD64 images, verified provenance and SPDX SBOM attestations against their
exact digests, and read back the stable manifest. The downloaded
`routeros-release.json` asset has SHA-256
`sha256:341de73e4f27f33fde6b691b6e26036aa9a9b6e7b4fabdb2abfd60a01697b29b`.

| Platform | Immutable image tag | Registry digest |
| --- | --- | --- |
| RouterOS ARM64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-84a3148de713abe49be0c7be8f21caa652b68dd9-arm64` | `sha256:3b5f3304ded4bd0cf09855575f27a8fffa225efe4ef940a0d7e2f25734d6c581` |
| AMD64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-84a3148de713abe49be0c7be8f21caa652b68dd9-amd64` | `sha256:876abb845191359ce7a45b7f996e620d9a123efb6afb221f62fb0f19fc447709` |

The immutable ARM64 reference was configured on the isolated canary, and the
initial RouterOS readiness response returned revision
`84a3148de713abe49be0c7be8f21caa652b68dd9`; the bounded readiness probe and
container health both reported healthy. An authenticated foreground dashboard
received the disposable session's disconnect and later automatic reconnect
without a page reload, including a fresh SSE fallback and snapshot. This is
qualitative live-delivery evidence, not a measured latency, RouterOS API
recovery, or 30-minute acceptance result. A later same-day in-container probe
found `/healthz` and `/readyz` timing out and RouterOS marked the canary
unhealthy. After an authorized canary-only restart, the healthy marker
returned; no authenticated post-restart revision read-back or sustained
recovery window was captured. Production was not changed. No
numbered release was created; v2.7.0 remains the latest formal release.

## Previous published mainline image — PR #893 — 2026-11-03

PR [#893](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/893)
merged as `c35ca40baf0132b38d60585b0252ab0ef35223b4`. Post-merge CI run
[#41734491317](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/41734491317),
CodeQL run
[#41734491203](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/41734491203),
and publisher run
[#41734491479](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/41734491479)
passed. The publisher built, scanned, attested, and smoke-tested ARM64 and
AMD64 images, verified provenance and SPDX SBOM attestations against their
exact digests, and read back the stable manifest. The downloaded
`routeros-release.json` asset has SHA-256
`sha256:b555ad7f9cda65f86c3ee2694ee192e076582af12f297303952c01a97ae17459`.

| Platform | Immutable image tag | Registry digest |
| --- | --- | --- |
| RouterOS ARM64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-c35ca40baf0132b38d60585b0252ab0ef35223b4-arm64` | `sha256:ff75ac4878b03a329dad93247151469095ef786aea1349cca629c2a9245801d8` |
| AMD64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-c35ca40baf0132b38d60585b0252ab0ef35223b4-amd64` | `sha256:24ed53e62ab73b475b0d1ab291b008c1892bd92ddfed962b2d3ae1ffa4f75238` |

Publication is not a numbered release or RouterOS deployment. The last
documented canary read-back is PR #862 and the last documented production image
is PR #788; no RouterOS read-back confirms PR #893 staging or acceptance.

## Previous published mainline image — PR #891 — 2026-10-30

PR [#891](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/891)
merged as `58a680423a4d616eb926a47c486847c8a4c062fe`. Post-merge CI run
[#41026129799](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/41026129799),
CodeQL run
[#41026129207](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/41026129207),
and publisher run
[#41026129573](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/41026129573)
passed. The publisher built, scanned, and smoke-tested ARM64 and AMD64 images,
verified provenance and SPDX SBOM attestations against each exact digest, and
published/read back the stable manifest. The downloaded `routeros-release.json`
asset has SHA-256
`sha256:b84c99e539924bc08188a29b5e628a7c7ef5d62c53266596c5d09e6fc6cb2b77`.

| Platform | Immutable image tag | Registry digest |
| --- | --- | --- |
| RouterOS ARM64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-58a680423a4d616eb926a47c486847c8a4c062fe-arm64` | `sha256:dc5afa62f0410459ac2d48a5c53b7532d2f0a2104d46a9392874e7373fd2d0eb` |
| AMD64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-58a680423a4d616eb926a47c486847c8a4c062fe-amd64` | `sha256:0376f9bb3ede0b018150a34107b19b53115fb0fe3ed1d80a6f71f8891b26bd23` |

Publication is not a numbered release or a RouterOS deployment. A read-only
WinBox listing on 2026-10-30 confirmed the canary still used PR #862's ARM64
immutable tag and digest `sha256:7c47d4a3ec3de83b2218cd3ce417017c92befeb45e967c355e9da9beb3a5b6ac`
with a healthy marker; production still showed the PR #788 ARM64 tag. Neither
device was read back against PR #891 after publication. No PR #891 staging,
candidate acceptance, or production promotion is claimed.

## Previous published mainline image — PR #889 — 2026-10-30

PR [#889](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/889)
merged as `61dae736ea8247dd77eb0a61cf2ca3007aced542`. Main CI run
[#40989048531](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/40989048531),
push-on-main run
[#40989048380](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/40989048380),
and publisher run
[#40989048490](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/40989048490)
passed. The publisher built, scanned, and smoke-tested ARM64 and AMD64 images,
verified provenance and SPDX SBOM attestations against each exact digest, and
read back the stable manifest. Its downloaded `routeros-release.json` asset
has SHA-256 `sha256:ba41854d947498939436586e07765418af80559bf1ed5274cd46c56564295b70`.

| Platform | Immutable image tag | Registry digest |
| --- | --- | --- |
| RouterOS ARM64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-61dae736ea8247dd77eb0a61cf2ca3007aced542-arm64` | `sha256:bc77c427d1aceebb5374bdbf49582b306c90c616503cdb3cb0f08c094ff5e9c8` |
| AMD64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-61dae736ea8247dd77eb0a61cf2ca3007aced542-amd64` | `sha256:3fe143bc183c76a28fac43cc64fe95c1d85867080b17e09f4e9dcbec295c3131` |

Publication is not a numbered release or a RouterOS deployment. The last
historically authenticated canary readiness read recorded here reported
revision `445c1d5ca0f28174629be8e8cd94f04de132f0fc` (PR #862), not PR #889.
On 2026-10-30 an
unauthenticated `/readyz` request returned the Cloudflare Access sign-in page
(HTTP 200), not readiness JSON; the canary browser tab also showed sign-in.
Same-day read-only PPP Active Connections records conflict: one was empty and
another recorded one test tunnel. Neither was correlated with authenticated
dashboard telemetry, so the current session count and canary image revision
were not verified for this publication. Production's last
recorded image remains PR #788 and was not re-read. Neither device has a
read-back confirming PR #889 staging or acceptance.

## Previous published mainline image — PR #885 — 2026-10-29

PR [#885](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/885)
merged as `f31bf9e0f6bac65dc6dea7fc00af99743c3e61fb`. Main CI run
[#40957610185](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/40957610185),
CodeQL run
[#40957609406](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/40957609406),
and publisher run
[#40957610189](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/40957610189)
passed. The publisher built and scanned both architectures, verified provenance
and SPDX SBOM attestations for each exact digest, smoke-tested both runtimes, and
read back the stable release manifest. Independent `gh attestation verify`
checks also passed for both architecture digests and both predicate types.

| Platform | Immutable image tag | Registry digest |
| --- | --- | --- |
| RouterOS ARM64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-f31bf9e0f6bac65dc6dea7fc00af99743c3e61fb-arm64` | `sha256:0b3bebc396e1e2c20e61cbc0103a32d64a6bb9bf329284ea98a0c52687f2122e` |
| AMD64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-f31bf9e0f6bac65dc6dea7fc00af99743c3e61fb-amd64` | `sha256:9074e637e745d51c85f8e9c60a75b528cd206d3508627d9107c723699cf28a4b` |

The stable `routeros-release.json` manifest binds commit
`f31bf9e0f6bac65dc6dea7fc00af99743c3e61fb` to these two immutable digests;
its downloaded asset SHA-256 is
`sha256:aee2573edb8edcb1b8446b012aef408f4d2c1a3727b6dfc4c9dd66cc0fefe390`.

Publication is not a numbered release or a RouterOS deployment. A fresh
Cloudflare Access-authenticated canary readiness read returned revision
`445c1d5ca0f28174629be8e8cd94f04de132f0fc` (PR #862), not PR #885. The
read-only PPP Active Connections view showed zero entries at observation time.
The latest recorded production read-back remains the PR #788 tag; production was
not re-read after this publication. No PR #885 device staging, live acceptance,
or production promotion is claimed.

## Previous published mainline image — PR #879 — 2026-10-29

PR [#879](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/879)
merged as `c0e9ac980da5694a2be9560dcbad0f9234cb9009`. Main CI run
[#40930360829](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/40930360829),
CodeQL run
[#40930361050](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/40930361050),
and publisher run
[#40930361153](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/40930361153)
passed. The publisher built and scanned both architecture images, verified
their provenance and SPDX SBOM attestations, smoke-tested both published
runtimes, and read back the stable manifest.

| Platform | Immutable image tag | Registry digest |
| --- | --- | --- |
| RouterOS ARM64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-c0e9ac980da5694a2be9560dcbad0f9234cb9009-arm64` | `sha256:3f92563ef0ae0c5d55a09fe81eaa950afe6a6d1d028fbebd5a4d36e229688832` |
| AMD64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-c0e9ac980da5694a2be9560dcbad0f9234cb9009-amd64` | `sha256:8e47c68dcdc1bfab6643a15e7e31139e8018960b8879539ec16a452f8e8764d1` |

Publication is not a numbered release or RouterOS deployment. The latest
recorded RouterOS image read-back predates PR #879 publication; no device
read-back confirms that this image is staged or accepted, and production
promotion is unverified.

## Previous published mainline image — PR #875 — 2026-10-29

PR [#875](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/875)
merged as `bd27e608f074f357461e41fa906b87e84553a363`. Main CI run
[#40788153323](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/40788153323),
CodeQL run
[#40788153605](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/40788153605),
and publisher run
[#40788153407](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/40788153407)
passed. The publisher built and scanned both architecture images, verified
provenance and SPDX SBOM attestations against the exact digests, smoke-tested
both published runtimes, and read back the stable manifest. The
[`routeros-release.json`](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/releases/download/routeros-stable/routeros-release.json)
asset SHA-256 is
`sha256:2016b42dac5f13ee3ac1e2ba7c07ecd4ffdd57bb1dae7aca56438249fe7a5f10`.

| Platform | Immutable image tag | Registry digest |
| --- | --- | --- |
| RouterOS ARM64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-bd27e608f074f357461e41fa906b87e84553a363-arm64` | `sha256:a8a42789e3fc72d8402f882b63cfa8280c64cb9cf84e71f8cc6b8c0266fcbfc4` |
| AMD64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-bd27e608f074f357461e41fa906b87e84553a363-amd64` | `sha256:728d22cc3543709ec29e5a0a5f93d1dd1273d654034c76eeda942273bbf0ee9c` |

This is a published image, not a numbered release or RouterOS deployment.
The last recorded RouterOS checkpoint predates PR #879 publication; it does not establish whether PR #875 or PR #879 is currently staged.

## Previous published mainline image — PR #873 — 2026-10-28

PR [#873](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/873)
merged as `e7163beebda530f16619094e9e498f3da873f980`. Main CI run
[#40770342669](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/40770342669)
and publisher run
[#40770342526](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/40770342526)
passed. The publisher built and scanned both architecture images, verified
provenance and SPDX SBOM attestations against their exact digests, smoke-tested
both published runtimes, and read back the stable manifest. The
[`routeros-release.json`](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/releases/download/routeros-stable/routeros-release.json)
asset SHA-256 is
`sha256:a71bf8b99c6819e55162c969cdd9f5687d06110ef1ad5ef6aa59b5831ded7fd7`.

| Platform | Immutable image tag | Registry digest |
| --- | --- | --- |
| RouterOS ARM64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-e7163beebda530f16619094e9e498f3da873f980-arm64` | `sha256:3187f302311d960042894df0e7c5262327f1c26e3d985444d0d7d9f257663a67` |
| AMD64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-e7163beebda530f16619094e9e498f3da873f980-amd64` | `sha256:50ad64d8f0b6f684b1025ce22d2a2ba2df9e1cc3b6531df382ef326d59193f7d` |

This is a published image, not a numbered release or RouterOS deployment.

## Previous published mainline image — PR #871 — 2026-10-28

PR [#871](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/871)
merged as `eb29581c8430ec862a8b47ee62268a74fec14518`. Main CI run
[#40602936825](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/40602936825)
and publisher run
[#40602936692](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/40602936692)
passed. The publisher built and scanned both architecture images, verified
provenance and SPDX SBOM attestations against their exact digests, smoke-tested
the published runtimes, and read back the stable manifest. The manifest SHA-256
is `sha256:02e2ec88e9591d0d7686edfeb4c5c0afbf3f4e28807dcdb9521b2035bbb2c84d`.

| Platform | Immutable image tag | Registry digest |
| --- | --- | --- |
| RouterOS ARM64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-eb29581c8430ec862a8b47ee62268a74fec14518-arm64` | `sha256:e6288dcc70eed59d29bfb697ffd5809de604463d718689e0fa9ca9d5bc615d17` |
| AMD64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-eb29581c8430ec862a8b47ee62268a74fec14518-amd64` | `sha256:d737a8ae1c727ee7e1fb0b1da0c5ccdbeb17f035e1a611bd3242e6ee46c1976f` |

This is a published image, not a numbered release or RouterOS deployment.

## Previous published mainline image — PR #868 — 2026-10-27

PR [#868](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/868)
merged as `388baa247b2a12658c66f02d2d40826fe4759553`. Main CI run
[#40588404193](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/40588404193),
push-on-main run
[#40588403979](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/40588403979),
and publisher run
[#40588404460](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/40588404460)
passed. The stable manifest was published and read back; both architecture
images passed runtime smoke tests, and provenance and SPDX SBOM attestations
were verified against the exact digests. Its manifest asset SHA-256 is
`sha256:02a13a8a237c92e324f6960245907a16aa7627ecb0249d2af592e08afabdeac6`.

| Platform | Immutable image tag | Registry digest |
| --- | --- | --- |
| RouterOS ARM64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-388baa247b2a12658c66f02d2d40826fe4759553-arm64` | `sha256:fc9146deef164b6c537149e9ab81d73eda7f174e9b986010bd1bd0426a5e6740` |
| AMD64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-388baa247b2a12658c66f02d2d40826fe4759553-amd64` | `sha256:d155e1edf32dde2472afa6cf2ff10512c471dc5bbaef6596c0887c64f568c868` |

This is a published image, not a numbered release or RouterOS deployment.
The 2026-10-28 read-only WinBox view showed the canary's configured image
digest prefix matching the PR #862 ARM64 digest below and container status
`HEALTHY`. A single Stats sample showed 0.7% CPU, 38.8 MiB memory, 0 B swap,
69.7 MiB app size, and 0.0 MiB data size. This supersedes the earlier issue
notes that PR #862 had not been read back. The exact readiness revision and a
sustained soak remain unverified. PR #868 has not been staged or accepted on
RouterOS. Keep production promotion and v2.8.0 gated on the open acceptance
criteria.

## Previous published mainline image — PR #862 — 2026-10-27

PR [#862](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/862)
merged as `445c1d5ca0f28174629be8e8cd94f04de132f0fc`. Main CI run
[#40511812292](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/40511812292),
push-on-main run
[#40511812762](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/40511812762),
and publisher run
[#40511812393](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/40511812393)
passed. The stable manifest was published and read back; both architecture
images passed runtime smoke tests, and their provenance and SPDX SBOM
attestations were verified against the exact digests. The stable manifest
asset SHA-256 is
`sha256:21210234eb81c96ee0dc2194e1a3166c46c46526ad70cb769dd11c66c4ac41b0`.

| Platform | Immutable image tag | Registry digest |
| --- | --- | --- |
| RouterOS ARM64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-445c1d5ca0f28174629be8e8cd94f04de132f0fc-arm64` | `sha256:7c47d4a3ec3de83b2218cd3ce417017c92befeb45e967c355e9da9beb3a5b6ac` |
| AMD64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-445c1d5ca0f28174629be8e8cd94f04de132f0fc-amd64` | `sha256:a6e59e2c7c67b89f77c8a6ef126e5e2541ff820f40f2e62ed10731c2cc9cf095` |

PR #862 is a published artifact, not a numbered release. The 2026-10-28
read-only WinBox observation showed the canary's configured image digest
prefix matching the ARM64 digest above and container status `HEALTHY`; one
Stats sample is recorded in the latest-image entry. This supersedes the older
#785/#200 comments that said PR #862 had not been read back. The exact
readiness revision, sustained health/resource impact, live-event behavior, and
acceptance window remain unverified. Keep production promotion and v2.8.0
gated on the open acceptance criteria.

## PR #860 publication checks — 2026-10-27

PR [#860](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/860)
merged as `d3be28625e9d3beb48e2bdf94855ac2b5f7111b1`. Main CI run
[#40498616546](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/40498616546),
CodeQL run
[#40498616642](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/40498616642),
and publisher run
[#40498616545](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/40498616545)
passed. The publisher built and smoke-tested both architecture images,
verified provenance and SPDX SBOM attestations against the exact image
digests, and published/read back the stable `routeros-release.json` manifest.
The manifest asset SHA-256 is
`sha256:b25c8a3fca3722a12a67b2c01cd2433aeffe9130d5c1d09dee3365492bffce46`.
Exact immutable tags and digests are recorded below.

## Previous published mainline image — PR #860 — 2026-10-27

PR [#860](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/860)
merged as `d3be28625e9d3beb48e2bdf94855ac2b5f7111b1`. Main CI run
[#40498616546](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/40498616546),
CodeQL run
[#40498616642](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/40498616642),
and publisher run
[#40498616545](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/40498616545)
passed. The stable manifest was published and read back; both architecture
images passed runtime smoke tests, and their provenance and SPDX SBOM
attestations were verified against the exact digests. The stable manifest
asset SHA-256 is
`sha256:b25c8a3fca3722a12a67b2c01cd2433aeffe9130d5c1d09dee3365492bffce46`.

| Platform | Immutable image tag | Registry digest |
| --- | --- | --- |
| RouterOS ARM64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-d3be28625e9d3beb48e2bdf94855ac2b5f7111b1-arm64` | `sha256:0c8c7c5764bd92f2dcb250474c84a07902d83972bcbe68c98bf45878d079f252` |
| AMD64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-d3be28625e9d3beb48e2bdf94855ac2b5f7111b1-amd64` | `sha256:59e304b3337d3f99bbc404a6d0866461cd13dcaca2439fe577881e0a1f2ca59b` |

PR #860's immutable artifacts are published but have not been read back as the
configured canary or production image. The last documented candidate-bound
RouterOS read-back is the older PR #806 revision; it does not establish PR #860
staging, rollback, live telemetry acceptance, or an independent security
review. The updater and scheduler bindings are not fully reconciled and the
updater was not run. Keep production promotion and v2.8.0 gated until
candidate-specific acceptance passes.

## Previous published mainline image — PR #859 — 2026-10-27

PR [#859](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/859)
merged as `17cc88d5bf7e59752f569fb7ec253c9706e0a6ea`. Main CI run
[#40422360203](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/40422360203),
CodeQL run
[#40422359603](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/40422359603),
and publisher run
[#40422360096](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/40422360096)
passed. Both architecture images passed runtime smoke tests, and their
provenance and SPDX SBOM attestations were verified against the exact digests.
The stable manifest asset SHA-256 was
`sha256:a7bf9db0a77a48ee03435b69ee7ad907031d731c4a718fbecad9b01d659d7850`.

| Platform | Immutable image tag | Registry digest |
| --- | --- | --- |
| RouterOS ARM64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-17cc88d5bf7e59752f569fb7ec253c9706e0a6ea-arm64` | `sha256:877ec4893c075958ee639d003e375e06d323a67396bbe05514efee98234eab76` |
| AMD64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-17cc88d5bf7e59752f569fb7ec253c9706e0a6ea-amd64` | `sha256:7236887299c7eb2f3c53768c5d8710ff4238a5ee8f354f90c6afc8048fcd8b7c` |

## Previous published mainline image — PR #849 — 2026-10-25

PR [#849](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/849)
merged as `f4708f519a6810ceb7d253c37c199032800ea625`. Main CI rerun
[#40239111663](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/40239111663),
CodeQL run
[#40239111237](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/40239111237),
and publisher run
[#40239111661](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/40239111661)
passed. The stable manifest was published and read back; both architecture
images passed runtime smoke tests and their provenance and SPDX SBOM
attestations were verified against the exact digests.
The stable manifest asset SHA-256 at that publication checkpoint was
`sha256:563139236aab98d524c7a829d07a975a827445d2fa023109660e96f25c7143f1`.

| Platform | Immutable image tag | Registry digest |
| --- | --- | --- |
| RouterOS ARM64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-f4708f519a6810ceb7d253c37c199032800ea625-arm64` | `sha256:c12743fa7c1eb4cbeaede2eac4c09ad7fe1bb75b47fc234af0703056e47f56ef` |
| AMD64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-f4708f519a6810ceb7d253c37c199032800ea625-amd64` | `sha256:ee4a5c35b3143e409d098b028fb90bb9f647306c68c30eeb02c498bdf30b05ac` |

These are immutable published artifacts, not a numbered release or a
deployment. The last candidate-bound RouterOS read-back remains PR #806;
candidate-specific rollback, live acceptance, and production promotion are not
claimed.

## Previous published mainline image — PR #846 — 2026-10-25

PR [#846](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/846)
merged as `e7ff31b222df2229186c6c745b0917084599e4b3`. Main CI run
[#40226555414](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/40226555414),
CodeQL run
[#40226031831](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/40226031831),
and publisher run
[#40226555415](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/40226555415)
passed. The stable manifest was published; both architecture images passed
runtime smoke tests and their provenance and SPDX SBOM attestations were
verified against the exact digests. The stable manifest asset SHA-256 at that
publication checkpoint was
`sha256:6ba391ce4a78dbdf4e54dbd8891493b3a5004fcb5e3493b15577599e541b0ab2`.

| Platform | Immutable image tag | Registry digest |
| --- | --- | --- |
| RouterOS ARM64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-e7ff31b222df2229186c6c745b0917084599e4b3-arm64` | `sha256:003cd252a1df946b23531cb89bcb137c525949c7797b82b022ac2c2078a91dac` |
| AMD64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-e7ff31b222df2229186c6c745b0917084599e4b3-amd64` | `sha256:fe525c7a91b572682dce6a7ea73533408013d790a0640775ff3e7f636479f437` |

These are immutable published artifacts, not a numbered release or a
deployment. The last candidate-bound RouterOS read-back remains PR #806;
candidate-specific rollback, live acceptance, and production promotion are not
claimed.

## Previous published mainline image — PR #842 — 2026-10-25

PR [#842](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/842)
merged as `b68bc0cc9245991526efbfcd970e89d07000462a`. Main CI run
[#40213251817](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/40213251817),
CodeQL run
[#40213251555](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/40213251555),
and publisher run
[#40213251904](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/40213251904)
passed. The stable manifest asset was read back and binds both architecture
images to the exact source commit. Provenance and SPDX SBOM attestations were
verified, and both images passed runtime smoke tests. The manifest SHA-256 was
`sha256:84a9053683a31922a1f21eb88efe62e72bdb48a301af14085f797508041a30a7`.

| Platform | Immutable image tag | Registry digest |
| --- | --- | --- |
| RouterOS ARM64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-b68bc0cc9245991526efbfcd970e89d07000462a-arm64` | `sha256:f19586c12bf0047f3e5950f7bff365dd1024662c50e42e9bf70ab5c152bdef30` |
| AMD64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-b68bc0cc9245991526efbfcd970e89d07000462a-amd64` | `sha256:20eb9e83c8c0a43bb4e56c613c82d3dba062c97268f788b15abb2e20679e0b4a` |

These are immutable published artifacts, not a numbered release or a
deployment. Candidate-specific rollback, live acceptance, and production
promotion are not claimed.

## Previous published mainline image — PR #839 — 2026-10-25

PR [#839](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/839)
merged as `273e9ed1c3618e605c3af106a59b76dfb8686769`. Main CI run
[#40204581927](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/40204581927),
CodeQL run
[#40204581975](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/40204581975),
and publisher run
[#40204581900](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/40204581900)
passed. The stable manifest asset was read back and binds both architecture
images to the exact source commit. Provenance and SPDX SBOM attestations were
verified, and both images passed runtime smoke tests.

| Platform | Immutable image tag | Registry digest |
| --- | --- | --- |
| RouterOS ARM64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-273e9ed1c3618e605c3af106a59b76dfb8686769-arm64` | `sha256:53a667d8c8db22d217c38c3ff80a9a32650b1615e69e8d738104652c8fd6b326` |
| AMD64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-273e9ed1c3618e605c3af106a59b76dfb8686769-amd64` | `sha256:1009ca54c47258e00950e93de8a8bead79525e6f88b1ddf6b602862919cbef6b` |

These are immutable published artifacts, not a numbered release or a
deployment. Candidate-specific rollback, live acceptance, and production
promotion are not claimed.

## Previous published mainline image — PR #838 — 2026-10-25

PR [#838](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/838)
merged as `b4b9f966693ad09343889379fb8ff33286a2e2e8`. Main CI run
[#40202982541](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/40202982541),
CodeQL run
[#40202982491](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/40202982491),
and publisher run
[#40202982561](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/40202982561)
passed. The stable manifest asset was read back and binds both architecture
images to the exact source commit. Provenance and SPDX SBOM attestations were
verified, and both images passed runtime smoke tests.

| Platform | Immutable image tag | Registry digest |
| --- | --- | --- |
| RouterOS ARM64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-b4b9f966693ad09343889379fb8ff33286a2e2e8-arm64` | `sha256:d620b82cc9a1d9af66f8506d9cc8bdf237901a387f102bac76ff3cfec22638db` |
| AMD64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-b4b9f966693ad09343889379fb8ff33286a2e2e8-amd64` | `sha256:29dcba4c4de657ba6789fc87031bcd0c5fa7f5a30f24256796abcf4dcd6c1912` |

These are immutable published artifacts, not a numbered release or a
deployment. Candidate-specific rollback, live acceptance, and production
promotion are not claimed.

## Previous published mainline image — PR #836 — 2026-10-25

PR [#836](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/836)
merged as `c88bc730a8e75bcd89ab73dcf85d87df37db7884`. Main CI run
[#40197252415](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/40197252415)
and publisher run
[#40197252453](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/40197252453)
passed. The published stable manifest was read back and its SHA-256 is
`sha256:d63fd6e68f07aeb8f97ea154e16f7eb9a096e6ca6158981985c41a73ee6e1679`.
It binds both architecture images to the exact source commit.

| Platform | Immutable image tag | Registry digest |
| --- | --- | --- |
| RouterOS ARM64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-c88bc730a8e75bcd89ab73dcf85d87df37db7884-arm64` | `sha256:295040612e1541dfe92e396461b243fe8c73a5223e11ae9de6af9914ee234867` |
| AMD64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-c88bc730a8e75bcd89ab73dcf85d87df37db7884-amd64` | `sha256:2f71c739d2a3ea919fb9829cb44d3ddd1e777aabd5b2beb483c97d9b4d59ea14` |

These are immutable published artifacts, not a numbered release or a
deployment. The latest available RouterOS read-back remains the older PR #806
revision; neither the complete PR #836 tag nor its digest has been confirmed on
the device. Candidate-specific rollback, live acceptance, and production
promotion are not claimed.

## Previous published mainline image — PR #829 — 2026-10-25

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
updater on RouterOS. At the time this historical entry was written, PR #806
staging and sparse healthy readiness samples were the recorded canary state.
That checkpoint was later superseded by the PR #894 checkpoint at the top of
this file. Candidate-specific rollback, soak, and live acceptance remain
pending. Do not tag or publish
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
PR #803 canary staging and rollback evidence is historical. PR #806 staging
and pending live acceptance were later recorded as the then-current state;
that checkpoint was subsequently superseded by PR #894 at the top of this
file.

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
recorded at the time; later PR #803 staging, rollback evidence, and PR #806
staging were subsequent historical records. The current documented checkpoint
is PR #894 at the top of this file. Neither publication record replaces the
pending live acceptance gates.

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
candidate-bound record. PR #806 canary evidence was recorded later and is now
superseded by the PR #894 checkpoint at the top of this file. No #778 hardware
acceptance is claimed. Production
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
router update. The operator-installed RouterOS scheduler validates the public
manifest and stages a pinned SHA image on canary only. A separate local
promotion controller requires fresh passing acceptance evidence and exact live
image matches before it changes production. This keeps router state and
credentials local; see [ROUTER_LOCAL_AUTOMATION.md](ROUTER_LOCAL_AUTOMATION.md).
Never add secrets, a router endpoint, or a remote deployment runner to this
public source repository.

## Maintainer release checklist

1. Create an issue describing the release scope and migration impact.
2. Open a focused pull request with tests, docs, and `CHANGELOG.md` updates.
3. Require CI, including pre-commit, secret-pattern checks, unit tests, the
   ARM64 image build, and high/critical OS and library vulnerability scans, to
   pass.
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
The publisher also requires a version tag to match `VERSION` and point to a
commit reachable from the default branch. Each architecture image is built,
scanned, and published in separate jobs. The scanner has read-only permissions
and scans the immutable image archive downloaded from the build job. After that
job succeeds, the publisher independently downloads the same archive, verifies
its checksum, and then uses its registry-write permission to publish it.
Published-image attestations and runtime smoke checks use the resulting digest.

GitHub runs a tag-triggered workflow from the tagged commit. Therefore, this
branch-controlled gate cannot retroactively protect old tag commits containing
an earlier publisher workflow. Do not create or move a release tag to an old
commit. A repository-level release-tag creation rule and a default-branch
controlled tag-creation path remain required to close that bootstrap gap.

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
