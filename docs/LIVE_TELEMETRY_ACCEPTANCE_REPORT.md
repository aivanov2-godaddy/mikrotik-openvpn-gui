# Live telemetry acceptance status

Status: **PR #891 (`58a680423a4d616eb926a47c486847c8a4c062fe`) is the latest
published image source, with immutable ARM64 and AMD64 images. Main CI,
CodeQL, image scans, runtime smoke tests, provenance and SPDX SBOM checks
passed; the stable manifest was read back. Exact tags and digests are in
[`RELEASES.md`](RELEASES.md). No post-publication RouterOS read-back confirms
PR #891 staging or acceptance.**

## Historical read-only RouterOS checkpoint — 2026-10-29

WinBox showed the canary's configured digest prefix matching the published
PR #862 ARM64 digest and production's configured immutable tag prefix matching
PR #788. The dashboard container rows displayed `H` markers and Redis displayed
`R`; these are point-in-time UI readings, not a resource soak. PPP Active
Connections showed zero entries. Public `/readyz` requests returned HTTP 200
Cloudflare Access sign-in HTML rather than readiness JSON, and direct private
container readiness probes from the workstation timed out. A fresh
Cloudflare Access-authenticated readiness read returned revision
`445c1d5ca0f28174629be8e8cd94f04de132f0fc` (PR #862), not PR #885. No
live-session acceptance, PR #885 staging, or production promotion is verified;
RouterOS configuration was not changed.
A follow-up WinBox read after the owner reported reconnecting still showed zero
PPP Active Connections, so the reported client session is not corroborated by
RouterOS or authenticated canary telemetry.
WinBox System > Resources also showed a router-wide point sample: 6% CPU,
646.7 MiB free memory of 1024 MiB, 760.5 MiB free disk of 1024 MiB, and 0.0%
bad blocks. These figures do not attribute usage to the dashboard container or
establish sustained impact.

## Current read-only RouterOS checkpoint — 2026-10-30

A fresh WinBox listing showed canary still configured with PR #862's ARM64
immutable tag and matching digest
`sha256:7c47d4a3ec3de83b2218cd3ce417017c92befeb45e967c355e9da9beb3a5b6ac`,
with a healthy marker. Production still showed the PR #788 ARM64 tag. PPP
Active Connections showed one active test tunnel. The canary dashboard sign-in
request remained pending, so no authenticated dashboard event or traffic
sample was correlated with the router session. No PR #891 staging or live
acceptance is established by these point observations.

An earlier 2026-10-28 Stats view showed 0.7% CPU, 38.8 MiB memory, 0 B swap,
69.7 MiB app size, and 0.0 MiB data size. A signed-in dashboard check then
showed a stale/reconnecting live stream and zero connected devices. Those
historical point checks do not establish sustained resource impact. The
30-minute acceptance window and production promotion remain unverified.

## RouterOS candidate status — PR #862 and PR #891

PR #862 is a published artifact with immutable digests recorded in
[`RELEASES.md`](RELEASES.md). An earlier WinBox readback showed a configured
image digest prefix matching the published PR #862 ARM64 digest and a
`HEALTHY` container. The Stats view provided one CPU/memory/swap/app-size/data-
size sample. The fresh authenticated readiness result in the checkpoint above
returned PR #862 revision `445c1d5ca0f28174629be8e8cd94f04de132f0fc`,
confirming that the canary was not running PR #885 at that observation. PR #891
is now the latest published image; no post-publication RouterOS read-back
confirms it is staged. A later read-only WinBox listing on 2026-10-30
reconfirmed PR #862's exact ARM64 tag and digest with a healthy marker; the
production row still showed the PR #788 ARM64 tag. RouterOS showed one active
test tunnel, but the canary sign-in request remained pending, so that session
was not correlated with authenticated dashboard telemetry. These point reads
do not establish live acceptance or acceptance of PR #891.

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
