# Live telemetry acceptance status

Status: **PR #873 (`e7163beebda530f16619094e9e498f3da873f980`) is the latest
published image source, with immutable ARM64 and AMD64 images. Main CI run
40770342669 and publisher run 40770342526 passed; both images were scanned,
smoke-tested, and verified with provenance and SPDX SBOM attestations. The
stable manifest was published and read back. Exact tags and digests are in
[`RELEASES.md`](RELEASES.md).

An earlier 2026-10-28 read-only WinBox observation showed the canary container
`HEALTHY` and its configured GHCR digest prefix matched PR #862's published
ARM64 digest. A single Stats view showed 0.7% CPU, 38.8 MiB memory, 0 B swap,
69.7 MiB app size, and 0.0 MiB data size. A later point check found the
signed-in dashboard's live stream stale/reconnecting with zero connected
devices; RouterOS Active Connections showed no active sessions. No router
changes were made. The full configured image reference, exact
readiness revision, and sustained resource impact remain unverified. PR #873
has not been staged. Production promotion and the 30-minute acceptance window
remain unverified.**

## RouterOS candidate status — PR #862 and PR #873

PR #862 is a published artifact with immutable digests recorded in
[`RELEASES.md`](RELEASES.md). An earlier WinBox readback showed a configured
image digest prefix matching its published ARM64 digest and a `HEALTHY`
container. The Stats view provided one CPU/memory/swap/app-size/data-size
sample. The earlier draft's exact `/readyz` revision claim remains unverified;
the old issue notes saying PR #862 had not been read back are superseded by
this earlier observation. PR #873 is the latest published image and has not been
staged on RouterOS. The latest confirmed candidate-image read-back is PR #862,
limited to the image digest prefix and point-in-time container status/resource
sample described above. The later stale-stream/no-session check shows that
live telemetry acceptance remains incomplete; neither point check establishes
acceptance of PR #873.

The following candidate-bound gates remain open: a 30-minute resource and
freshness soak; connect/disconnect event latency; API interruption and
reconnect/snapshot recovery; counter reset and duplicate/loss/order checks;
Redis outage/restart delivery recovery; SQLite restore and interrupted-write
checks; authenticated authorization/privacy checks; and canary rollback
rehearsal. The earlier qualitative live-UI check was on PR #806 and does not
provide evidence for this candidate. The installed RouterOS updater remains
unreconciled and was not run.

## Live UI spot check — 2026-10-27

On the existing PR #806 canary image, an authenticated Connections page showed
the Socket.IO live indicator and changing five-second traffic-rate samples.
After the disposable test session was terminated, the same page showed zero
active devices and the ended session in history without a page reload. This is
qualitative evidence of live UI delivery only; no event-latency clock offset was
established, and it is not a 30-minute soak, reconnect/snapshot-recovery result,
or acceptance of PR #873. A reconnect/snapshot check and the controlled soak
remain outstanding. No production image change is claimed.

## Last recorded canary checkpoint — PR #806

PR [#806](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/806)
merged as `79816625e493f9581e7389b95760403ac6c9a327`. CI, CodeQL, ARM64 image
build, Redis recovery integration, rendered-browser/accessibility regression,
secret-pattern checks, and dependency audit passed. The immutable ARM64
registry digest is
`sha256:dd646c8b25a5b4e24653d2268719b89513da85c7164e68e499b5ebd4cf292dce`.
RouterOS read-back confirmed the exact candidate revision and healthy
readiness on canary. Sparse point samples are not a 30-minute soak and do not
prove sustained resource impact. No candidate-specific rollback drill has
been completed for #806. No production image promotion is recorded. The browser
view available at that checkpoint (2026-10-25) was the application sign-in form,
so it did not verify authenticated live-event acceptance, event-age/freshness,
reconnect/snapshot recovery, or session authorization.

## Public artifact evidence

Previously published PR [#798](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/798)
merged as `041a9d2ac7581dac18911c236cbbb3aee4280273`. Main CI run
[#40000779522](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/40000779522)
and publisher run
[#40000779533](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/40000779533)
completed successfully. ARM64/AMD64 image smoke tests passed, and provenance
and SPDX SBOM attestations verified against the exact source commit and image
digests; stable-manifest publication and read-back succeeded. PR #798 requires
same-origin Referer evidence before allocating Engine.IO state for an
originless polling GET and includes a rendered-browser regression. Publication
did not stage or deploy the image on RouterOS.

| Platform | Immutable tag | Registry digest |
| --- | --- | --- |
| RouterOS ARM64 — previous published image; superseded by PR #806 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-041a9d2ac7581dac18911c236cbbb3aee4280273-arm64` | `sha256:b41ad2cde73efe9f465d583430e4801b75335b18c92b9a364ec21149c69ab601` |
| AMD64 / CHR — previous published image; superseded by PR #806 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-041a9d2ac7581dac18911c236cbbb3aee4280273-amd64` | `sha256:bf2c211397f30940cb72ab199f2d575b42372341491a934b1260bdd9a12fba6c` |

PR #798 is not a numbered release; v2.7.0 remains the latest formal version.
Image publication did not deploy to RouterOS or establish live acceptance.

### Historical candidate-bound canary artifact — PR #776

PR [#776](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/776)
(`c4b4b76793b2454e81362867d8654962627de6fa`) is a historical candidate-bound
canary record. Main CI run
[#39867875857](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/39867875857)
and publisher run
[#39867875877](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/39867875877)
completed successfully. The publisher built and smoke-tested ARM64/AMD64
images, verified their provenance and SPDX SBOM attestations, and read back
the stable manifest. The #776 change revokes the server-side session before
the logout audit write. This repository/artifact evidence does not prove
RouterOS hardware acceptance.

| Platform | Immutable tag | Registry digest |
| --- | --- | --- |
| RouterOS ARM64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-c4b4b76793b2454e81362867d8654962627de6fa-arm64` | `sha256:8b5dfa0d2c4fae542e0c560576a91432812823ebe55ecc6bcad7bbfa7c0e922e` |
| AMD64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-c4b4b76793b2454e81362867d8654962627de6fa-amd64` | `sha256:fad2b337196e5fe09d2040acb3353e4acc5fe2d894bc49866a0470369c75d4f9` |

On 2026-10-23, the manual RouterOS updater was invoked for the #776 ARM64
immutable tag. The latest recorded read-back confirmed that tag and RouterOS
marked the container healthy after start. The updater was no longer active
and no completed 30-minute sample record was verified, so readiness is **not
passed**. The persisted pending-candidate record did not match the later
canary image and does not bind a passing soak to #776. During a later
authenticated dashboard observation, the connected-user count changed in the
already-open page without a manual refresh; the exact event latency and
traffic-sample age were not timed. A canary sign-out attempt returned an
origin-rejection error and did not revoke the session. The canary `PUBLIC_ORIGIN`
setting matched the expected origin, but the rejected request's origin/header
shape was not captured; do not weaken origin or CSRF checks while
investigating. The registry digests above are bound to their tags by the
verified publisher workflow; RouterOS reports the configured tag, not a
local OCI digest. No post-publication RouterOS staging or candidate-specific
live acceptance for PR #793 is recorded. The latest recorded read-only RouterOS
inventory at approximately 14:33 UTC on 2026-10-23 showed canary and production
configured with immutable ARM64 tag
`ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-8c3a46df3a7e0e8b0dac9e5ed7a979aa06e855f7-arm64`
(source commit PR #788), not the then-latest published PR #793 tag. This was a
configured-tag read-back before PR #798 was published; no local OCI digest or
candidate readiness was verified. A later read-only PPP Active Connections check showed one active
session at approximately 14:50 UTC and none at approximately 15:02 UTC. The
dashboard was signed out during that observation, so no latency, freshness,
reconnect, or dashboard correlation is claimed. No RouterOS or container
changes were made during these checks.

Public deployment detail here is limited to the redacted canary-stage status
above. This file contains no router identity, hostnames, addresses, resource
readings, logs, or VPN session identities/details. Detailed deployment and
acceptance evidence belongs in operator-controlled storage. The table below is
a gate checklist, not a report of private measurements.

## Candidate acceptance gates

The following table is the historical acceptance record for candidate PR #776;
it is not the current canary image state. PR #806 is staged on the canary with
healthy revision read-back recorded above, but its 30-minute soak, rollback,
and full live acceptance remain incomplete.

| Gate | Required result | Public status |
| --- | --- | --- |
| Candidate identity and readiness | Canary reports the exact immutable candidate and remains healthy for the agreed window. | Exact #776 ARM64 tag and healthy startup read back; updater is no longer active and no completed 30-minute evidence was verified |
| Session event latency | Connect/disconnect visible in the open dashboard within 1 second. | A connected-user change appeared without manual refresh; exact latency and disconnect timing not measured |
| Traffic freshness | Samples are no older than 2 seconds; no manual refresh is needed. | Not measured for #776 |
| Reconnect and snapshot recovery | RouterOS API interruption recovers automatically; a full snapshot follows reconnect. | Not measured for #776 |
| Event and counter integrity | Counter resets do not create incorrect rates; detect missing, duplicated, or out-of-order events. | Not measured for #776 |
| Binary API and REST parity | Compare equivalent read-only snapshots and document any expected differences. | Not measured for #776 |
| Redis/outbox | Exercise unavailable/restarting Redis, retries, duplicate delivery, queue drain, and recovery. | Repository tests exist; candidate-specific live evidence not collected |
| Resource impact | Record bounded CPU, memory, storage, and container-health observations over the soak. | Not measured for #776 |
| Persistence and rollback | Rehearse SQLite restore and rollback in isolated canary; preserve production state. | Not verified for #776 |
| Security and privacy | Unauthenticated clients receive no telemetry; logout revokes the session; logs and reports contain no secrets or unnecessary private data. | Canary sign-out was rejected by the origin check and did not revoke the session; request header shape not captured; deployed investigation remains open |

The 30-minute canary window must use one immutable candidate and a connected
disposable test client. Missing, stale, contradictory, or out-of-window
evidence fails closed. A point-in-time browser observation, image publication,
or readiness-only soak does not pass these gates. Production must not be
promoted until the pre-promotion acceptance report passes and rollback has been
rehearsed; post-promotion acceptance is a separate required phase.

The historical 2026-10-15 readiness-only probe completed 30 consecutive
passing samples at 60-second intervals, each reporting revision
`6dd53022523766a5371628dfe158286072494bf4`. This confirms repeated readiness
and revision reporting only; it does not establish live-event freshness,
session reconnect or snapshot recovery, resource impact, Redis/SQLite recovery,
rollback, or deployed security acceptance.

A separate 2026-10-15 check of the previous PR #745 candidate found stale
session presentation after an operator-initiated test-session disconnect:
RouterOS reported zero matching
active sessions, while the already-open canary dashboard continued to show its
last-known connected snapshot and delayed status. This is a failed freshness
observation, not a measured latency value; the cause, automatic client
reconnect, and snapshot recovery remain unverified.

## Collection

Use the read-only collectors and private RouterOS prerequisites documented in
[`ROUTEROS_ACCEPTANCE.md`](ROUTEROS_ACCEPTANCE.md). Do not put credentials,
cookies, private origins, router exports, client profiles, IP addresses, raw
logs, or session-level/unredacted deployment measurements in GitHub issues,
pull requests, public artifacts, or this file.

The release evaluator also requires an operator-attested, redacted certificate
lifecycle record bound to the canary image tag and digest. Its schema and
collection CLI input are documented in `ROUTEROS_ACCEPTANCE.md`; this repository
gate does not independently prove live RouterOS actions or change the
candidate-specific acceptance status above.
