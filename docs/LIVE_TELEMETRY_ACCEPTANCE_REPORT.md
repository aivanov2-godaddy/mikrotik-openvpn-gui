# Live telemetry acceptance report

Status: **TELEMETRY BASELINE ACCEPTED — CURRENT RUNTIME SOAK PENDING**

This report records the operator's 2026-10-02 acceptance of the Binary API
telemetry baseline, plus later deployment observations. The operator's detailed
acceptance evidence remains private; raw RouterOS data, addresses, account
names, credentials, certificates, tokens, and private identifiers are not
copied into this repository. The later runtime image listed below is a newer
build. Its full 30-minute Redis/telemetry acceptance window remains pending;
the isolated canary rollback-and-recovery drill passed for the earlier PR #497
image. That drill has not yet been repeated for the newer PR #501 candidate
below, and neither drill substitutes for sustained acceptance.

## Latest read-only browser check — 2026-10-05

The already-open production Dashboard still rendered its previous page, but
showed `Connection data delayed`; its displayed status generation time remained
19:31 (the page's displayed time basis was not established). Browser-console
observations from 19:40:04 through 19:42:29 UTC showed the status-poll path
failing every five seconds with `TypeError: Failed to fetch`.
A separate read-only request for `/metrics` was redirected to the Cloudflare
Access sign-in page, so no application metrics body was received. This is
consistent with an edge-authentication/session problem, but does not establish
whether Cloudflare, the app session, or an upstream request caused the failed
polls. It is evidence about the status-poll path, not proof that Socket.IO or
the RouterOS telemetry process itself was down.

At the same check, RouterOS WebFig still showed the production container on the
recorded PR #497 immutable tag, with container state `HEALTHY` and healthcheck
`good`. A separate read-only System > Resources view returned one host resource
sample; exact CPU, memory, storage, and bad-block values are not copied here.

**Follow-up, separate authenticated dashboard tab (about 20:42 UTC):** a new
read-only tab opened using the browser's existing authenticated session showed
the Socket.IO live indicator and Operational service health. Across two
observations about 20 seconds apart, the rendered health data changed without
a page refresh (the CPU reading varied and router uptime advanced). The
dashboard showed no connected VPN users, so this did not exercise a
connect/disconnect event; no active traffic sample was available. The older
stale tab and its failed status polls were left untouched. This confirms that
one authenticated dashboard session received automatically updated health
data at that time, but does not measure sample-age bounds, session-event
latency, Redis delivery, or recovery behavior. The footer's displayed status
time was not used as a freshness measurement. No sign-in code, router
configuration change, or container operation was performed. The formal #199
soak remains pending; neither the older stale tab nor this short live check
alone establishes overall service availability or acceptance.

## Latest published mainline candidate — PR #501 — 2026-10-06

PR [#501](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/501)
merged as `0ab71339f8884e3b8e185d55bfbcdc69cd088c22`. Publication workflow
[#37376243641](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/37376243641)
passed source and rendered-browser validation, ARM64/AMD64 builds, runtime
smokes, and exact-digest provenance/SBOM verification. Independent SLSA
verification matched each published digest to this commit and the repository's
`Publish container` workflow. The stable manifest asset was also read back and
matched this commit and both immutable architecture tags.

| Platform | Immutable image tag | Registry digest |
| --- | --- | --- |
| RouterOS ARM64 | `sha-0ab71339f8884e3b8e185d55bfbcdc69cd088c22-arm64` | `sha256:f2b4368e194eb6996018efc2c3729f866e1da79046312e60cd9511b92dcf41fa` |
| CHR/x86 AMD64 (evaluation) | `sha-0ab71339f8884e3b8e185d55bfbcdc69cd088c22-amd64` | `sha256:dab88909d624e04c9d76acb5a05cbe27a2e9b4ce2d2fab33f94837a0d3b96414` |

Read-only RouterOS WebFig read-back listed the canary with the PR #501 ARM64
tag and the `H` status marker. Production remained on the earlier PR #497
immutable tag, also with `H`; Redis was running. RouterOS exposes its configured
tag, not the bytes or registry digest cached locally. The PR #501 image digest
was verified against GHCR, but the router's cached image digest was not.
No router/container configuration was changed during this check.

The authenticated production dashboard showed `Live · SOCKETIO`, Operational
service health, and zero connected VPN users. This was a point-in-time
observation, not a sample-age measurement or a session/traffic exercise. No
canary `/readyz` probe or current-candidate rollback drill was recorded in this
check. The 30-minute telemetry/Redis acceptance, controlled VPN-client event
test, recovery, counter-reset, parity, ordering, restore, and live security
checks therefore remain open. Production has not been promoted to PR #501; no
new numbered release was created, and v2.7.0 remains the latest formal release.

## Previously published mainline image — PR #497 — 2026-10-05

PR [#497](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/497)
merged as `3eda7a15acb6fdb0f9749dfe0c2fd9efeeae714f`. Publication workflow
[#37351647768](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/37351647768)
passed source and rendered-browser checks, both architecture builds, exact-digest
provenance/SBOM verification, runtime smoke, and stable-manifest publication.
The RouterOS ARM64 image is
`sha-3eda7a15acb6fdb0f9749dfe0c2fd9efeeae714f-arm64` /
`sha256:089e9c48c3e388cd08be3a44ddd9f525a0b50ea9e15983d6a8fa78e442fecc6c`.
The numbered release remains v2.7.0.

Read-only RouterOS read-back showed both canary and production configured with
this immutable tag and healthy (`H`). Canary `/readyz` returned the candidate
revision. A canary-only rollback to the previous immutable image and subsequent
forward recovery both returned the expected ready revision; production was not
restarted during that rehearsal. The router reports a configured tag, not an
independent registry digest. The authenticated production UI later showed live
status and `Operational` Service Health (six healthy checks, none needing
review or unavailable). The active VPN-session count was zero, so no session
event latency or under-load traffic freshness was measured. Unauthenticated
public requests to `/readyz` and `/metrics` were redirected to Cloudflare
Access; this is edge-gate evidence only.

These are point-in-time deployment/readiness observations, not the full #199
acceptance window. No continuous 30-minute metrics series, Redis delivery or
outbox evidence, session transition, API-interruption recovery, counter-reset
or parity test, SQLite restore drill, or live session authorization-expiry
exercise was run. Exact router resource values and deployment-specific records
remain outside this public repository.

## Previously published mainline image — PR #494 — 2026-10-05

PR [#494](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/494)
merged to main as `03d08a2e6a08554c68cf74930049ac29ac0b3219`. Publication
workflow [37328242084](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/37328242084)
and hosted CI passed, including source checks, unit/mock integration and
rendered browser/accessibility tests, ARM64/AMD64 image builds, exact-digest
provenance/SBOM verification, and runtime smoke. The immutable ARM64 image is
`ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-03d08a2e6a08554c68cf74930049ac29ac0b3219-arm64`
with registry digest
`sha256:5d5645d7613f74081bb01e390d6201ba6230968de72248119b39c9a4274ecad4`.

This was published and CI-verified, but has since been superseded by PR #497
above. Its publication record is retained here for history. The full
30-minute telemetry/Redis acceptance remains pending.

## Previously published mainline image — PR #492 — 2026-10-05

PR [#492](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/492)
merged to main as `a4f2cce829c8453a7b982307677d2d3173b94a90`. Publication
workflow [37317035616](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/37317035616)
passed source/pre-commit and secret-pattern checks, unit/mock integration
tests, rendered browser/accessibility tests, ARM64/AMD64 builds, exact-digest
provenance/SBOM verification, and published-runtime smoke tests. Its immutable
ARM64 image is
`sha-a4f2cce829c8453a7b982307677d2d3173b94a90-arm64` /
`sha256:682a6dc61aeb47cc0e0979ab03d3c4f30d8497f8f0fbb44282bef84267f7f373`.

PR #492 changes the repository's RouterOS updater example and its tests/docs;
it requires 30 successful, exact-revision `/readyz` samples at one-minute
intervals before promotion. The example has **not** been installed or
exercised on RouterOS. This publication does not prove that the new gate is
active on the router or that this image is deployed there. The latest
timestamped RouterOS image read-back remains PR #484 below. No RouterOS
configuration, container, VPN data, certificate, or policy was changed for
PR #492; the 30-minute telemetry/Redis acceptance and rollback gates remain
open.

## Earlier browser/API access gate — 2026-10-05, about 03:17–03:19 Europe/Sofia

**Superseded as the latest browser-state observation by the authenticated
follow-up below.**

The already-open production Dashboard showed `Connection data delayed` while
its browser console repeatedly reported `TypeError: Failed to fetch` from the
five-second `/api/status` poll. A separate direct navigation to `/api/status`
was redirected to the Cloudflare Access login page before reaching the app.
No HTTP response status or application error body was captured, so the exact
failure layer is not proven; the evidence is consistent with an expired or
unavailable Cloudflare Access session in that browser context and does not
establish a RouterOS API or Redis fault. The already-rendered page must not be
counted as a successful authenticated telemetry observation.

RouterOS WebFig logs around the same interval showed local `/readyz` HTTP 200
probes for canary and production. Readiness probes do not verify authenticated
`/api/status`, live-stream delivery, or end-to-end telemetry freshness. No
login code was submitted, the original dashboard tab was not reloaded, and no
RouterOS configuration or container was changed. At this observation, live
acceptance was gated until Cloudflare Access authentication and an authenticated
endpoint response were restored. This was not a passing acceptance sample.

## Authenticated dashboard access restored — 2026-10-05, about 03:37–03:39 Europe/Sofia

Using the already-open authenticated production Dashboard, two read-only
observations about 75 seconds apart showed `Live · SOCKETIO` / `Live · updated
now` and `Operational` service health. Router uptime advanced and the CPU
sample changed between observations. The connected-session count remained
zero in both observations. The page was not manually refreshed, no credentials
or login code were entered, and no RouterOS configuration or container was
changed. This confirms that the authenticated dashboard and its live health
updates were working again for this browser session; it does not establish
session-event delivery, traffic freshness, Redis delivery, end-to-end latency,
or sustained acceptance. No VPN client was active, so the event/reconnect
acceptance gates remain open. Exact resource and network values are omitted.

## Earlier RouterOS-confirmed image — PR #478 — 2026-10-05

PR [#478](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/478)
merged as `d5f8f4418d6ec972aa51ea4634b56c7fd89093f4`. Publication workflow
[37294618814](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/37294618814)
passed source verification, rendered browser/accessibility checks, both
architecture builds, detached provenance/SBOM verification, and runtime smoke
tests. The immutable ARM64 tag/digest is
`sha-d5f8f4418d6ec972aa51ea4634b56c7fd89093f4-arm64` /
`sha256:1ec08a3a0c5d4741a701270ba30249aba62e215649170aa3a6b69c150fc41209`;
the AMD64 digest is
`sha256:fad6a49eb253f52c5407369700833c7733f26972f49ae37fa012dd43e0a6f787`.
PR #478 tightens fail-closed acceptance evidence and adds rendered axe checks
for desktop no-results and review-dialog states, including a low-contrast fix.

Read-only RouterOS WebFig read-back on 2026-10-05 showed both canary and
production configured with that ARM64 immutable tag and marked healthy (`H`);
the Redis container was running (`R`). RouterOS reports the configured image
tag, not an independent local registry digest. The current dashboard browser
tab was at sign-in, so authenticated post-deployment rendering and live
telemetry behavior were not checked. This is deployment/container-health
evidence only. The 30-minute sampled telemetry/Redis soak, latency/freshness
percentiles, reconnect/snapshot recovery, event-integrity checks, and rollback
drill remain pending. No numbered release or RouterOS policy/data change was
made for PR #478.

## Latest RouterOS-confirmed image — PR #484 — 2026-10-05

The next application-runtime patch, PR
[#484](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/484),
was published by workflow
[37302952543](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/37302952543).
Its ARM64 tag/digest are
`sha-93627bca38312ad1845249c6df1c0fcecf12122e-arm64` /
`sha256:01872672a9093ac999272c0be0cf97bf27c2139af1cde90f41b501ac4995ba73`.
Read-only WebFig read-back after publication showed this tag on both canary
and production, each healthy (`H`), with Redis running (`R`). RouterOS reports
the configured image tag, not an independent registry digest. This is
point-in-time deployment/health evidence only; it does not prove a sustained
telemetry soak or rollback.

At the time of this read-back, PR #492 was a newer published artifact, but no
timestamped RouterOS read-back confirmed it on-device. It has since been
superseded as the latest published artifact by PR #494 above. PR #492's updater
example remains repository-only and has not been installed on the router.

## PR #455 and subsequent RouterOS rollout — 2026-10-05

PR [#455](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/455)
was merged as `2fd42b651dfc01ef4dbdf03679e937627858ebbb`. Publication workflow
[37237241486](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/37237241486)
completed successfully, including the rendered-browser checks and ARM64 runtime
smoke. The `routeros-stable` manifest now names the immutable ARM64 candidate
tag `sha-2fd42b651dfc01ef4dbdf03679e937627858ebbb-arm64`.

The first observed RouterOS attempt started that candidate as canary, then
stopped it about five seconds later. The container log recorded termination
followed by exit with signal 9, and the updater re-pulled the prior canary
image. The available log did not establish whether the rejection was caused by
readiness timeout, revision mismatch, or another startup condition. No manual
promotion or router policy, CA, VPN-user data, or database change was made.

A later read-only observation showed both canary and production healthy on
`sha-2fd42b651dfc01ef4dbdf03679e937627858ebbb-arm64`. The registry's immutable
ARM64 manifest digest for that tag is
`sha256:18c8ebf15dce8ee2d936fe97457d8172cc2c685ee040019374bae9fa741629d8`.
RouterOS WebFig exposes the configured tag and health marker, not a local
content digest. Container logs subsequently recorded repeated `/readyz` HTTP
200 responses for both services. The initial rollback's exact cause remains
unknown; the later success followed the existing scheduled canary path.

### Latest stable image promotion and authenticated Dashboard check

After PR [#457](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/457)
merged, publication workflow
[#37240953988](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/37240953988)
passed source/unit checks, rendered-browser verification, ARM64 and AMD64
builds, exact-digest SBOM/provenance verification, and published runtime smoke.
The stable manifest names commit
`0f41d723b9431fd73b0fa97f113c4f764d2f7034`, with ARM64 tag
`sha-0f41d723b9431fd73b0fa97f113c4f764d2f7034-arm64`; the registry manifest
digest is `sha256:2ed6842ab0493f772f3fdfd7cf3d08ce5f1bc8db31939e6d97aac29623684a4c`.

Read-only RouterOS logs recorded the candidate canary starting at 01:52:40
Europe/Sofia, returning `/readyz` HTTP 200, and production promotion beginning
at 01:53:54. Production started on the same immutable tag at 01:53:57 and
returned `/readyz` HTTP 200 at 01:54:07. WebFig subsequently showed canary and
production healthy (`H`) on that tag. The authenticated Dashboard remained
available after restart, reported `Live · updated now`, and showed zero
connected users in both its main card and lower status strip. This verifies
the deployed live-count display is consistent at zero; no nonzero session
transition was available to verify on this image. RouterOS reports the
configured immutable tag and health, not an independent local content digest.

PR #457 improves readiness failure logging in the repository's updater
example. The router-local script itself was not replaced by this image update;
it remains a separate manual/router-local artifact. This deployment is a
point-in-time rollout and authenticated UI check, not the outstanding 30-minute
telemetry/Redis soak, RouterOS API-restart recovery, event-integrity exercise,
or controlled rollback rehearsal.

### Follow-up live-stream observation after management-VPN reconnect — 2026-10-05

At approximately 02:03–02:04 Europe/Sofia, the authenticated production
Dashboard was inspected twice about 75 seconds apart without reloading. It
continued to report `Live · SOCKETIO`; RouterOS uptime advanced and its CPU
sample changed between observations, while service health remained
`Operational`. The connected-user card and lower status strip both stayed at
zero, and the resource samples remained below the documented acceptance
cutoffs. This confirms the page continued receiving live health updates, not a
VPN-client connect/disconnect event: no OpenVPN session was active. It does not
provide latency percentiles, a nonzero session transition, traffic-sample
freshness, Redis delivery evidence, sleep/wake recovery, API restart/snapshot
recovery, event-integrity proof, or a 30-minute soak. Exact router resource
values remain in the operator-local private record.

### 30-minute elapsed deployment checkpoint — 2026-10-05 02:23:57 Europe/Sofia

This checkpoint is 30 minutes after production started the immutable image at
01:53:57. The authenticated Dashboard still reported `Live · SOCKETIO` and
`Operational` service health; its main connected-user card and lower status
strip both showed zero. Intermediate read-only Dashboard observations showed
advancing RouterOS uptime and changing CPU samples. This is an elapsed-time
deployment observation with spot checks, not a continuously collected or
per-sample acceptance window. No complete Redis/outbox and telemetry metric
series, latency/freshness percentiles, VPN-client event transition,
RouterOS-API restart/snapshot recovery, event-integrity verification, or
rollback drill was collected. The formal #199 acceptance gate therefore
remains open. Exact router-resource samples remain in the operator-local
private record.

### Read-only management-VPN follow-up — 2026-10-05, about 02:50–02:51 Europe/Sofia

The authenticated production Dashboard continued to report `Live · SOCKETIO`
and `Operational`; RouterOS uptime advanced and its CPU sample changed between
views without a page reload. The connected-user count remained zero. RouterOS
container logs around this check recorded successful `/readyz` HTTP 200 probes
for both canary and production, and Redis completed its scheduled RDB save.
These are point-in-time health and persistence observations only: no VPN-client
event, Redis Stream delivery/replay, RouterOS API interruption/recovery, or
rollback was exercised, and no continuous metric series was collected. No
RouterOS configuration or container was changed. Exact resource values and
private network identifiers are intentionally omitted.

## Latest release publication and RouterOS read-back — 2026-10-04

### Formal v2.7.0 release and its RouterOS image read-back

Formal release **v2.7.0** points to commit
`2e01f111e1445c79b1753477a41efbaec27a1a2d`. Release-notes workflow
[#37212204043](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/37212204043)
and container publication workflow
[#37212204038](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/37212204038)
passed. Both architecture builds passed runtime smoke and exact-digest
provenance/SBOM verification; the stable manifest points to this commit.

| Platform | Immutable image tag | Published digest |
| --- | --- | --- |
| RouterOS ARM64 | `sha-2e01f111e1445c79b1753477a41efbaec27a1a2d-arm64` | `sha256:cf7f60ba462db7c70333892cd39ef5a88b4d496c0cfb6068ec2f184b7946178a` |
| AMD64 (evaluation only) | `sha-2e01f111e1445c79b1753477a41efbaec27a1a2d-amd64` | `sha256:c5549656a5706786579052e274c0018f405ea2c7530956a3761143ca200e8b1f` |

Sanitized RouterOS WebFig read-back on 2026-10-04 confirmed the v2.7.0 ARM64
immutable tag on both canary and production, each with the RouterOS healthy
(`H`) marker. This proves configured-tag deployment and container health only;
it is not a `/readyz` observation, independent registry-digest comparison,
application/browser check after this release, or formal VPN/telemetry
acceptance. No resource sample or sustained soak was collected in this
read-back. The release is based on the PR #434 application code; v2.7.0
primarily records the staged migration/profile-recovery release state. The
newer PR #448 image read-back is recorded separately below.

### Latest post-PR #448 RouterOS read-back — 2026-10-04 23:41 Europe/Sofia

Read-only WebFig inspection showed both the canary and production dashboard
containers configured with the immutable ARM64 tag
`sha-72c4c255b92b9c5ffb9af509fea5b6306da65657-arm64`; each displayed healthy
(`H`) status. The separately configured Redis container displayed running
(`R`). The published ARM64 digest for this tag is
`sha256:55f2735691f53950d65ed681fa8d47f6861972544e002e40349ac849e4dda185`
from the verified publication record above; RouterOS exposes the tag, not an
independent registry digest, so this is not an on-device digest verification.

The container table showed point-in-time CPU and memory readings for both
dashboard instances and Redis. A separate read-only System > Resources view at
approximately 23:56 showed RouterOS CPU, memory, and storage below the current
acceptance cutoffs. Exact readings are retained in an operator-local private
record and are not reproduced here. These are point-in-time observations, not
peaks, a pre-deployment comparison, or a sustained baseline. The production site rendered its RouterOS
dashboard sign-in page; no dashboard credentials were entered, so authenticated
application state, telemetry freshness, and post-release UI behavior remain
unverified. No router configuration or running container was changed during
this inspection. This observation does not satisfy the sustained soak,
reconnect/recovery, event-integrity, or rollback gates.

### Read-only RouterOS resource and container snapshot — 2026-10-04 16:39 UTC

A later WebFig inspection read the System Resources page and container table;
no RouterOS values were changed. Both dashboard containers still showed the
v2.7.0 immutable ARM64 tag and healthy (`H`) marker, and the Redis container
showed running (`R`). Resource values were sampled, but deployment-specific
CPU, memory, and storage measurements are retained only in private acceptance
evidence and are intentionally omitted from this public repository. The few
readings are point-in-time observations, not peak measurements, a sustained
resource baseline, or the formal acceptance soak. The configured tag remains
the only image identity visible in RouterOS; this does not independently
verify the registry digest. The container inventory included environment
configuration, which can contain secrets; no environment values are
reproduced here.

### Post-release security fix deployment (main build)

PR [#424](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/424)
merged as `1690eb89e8d17c272ca128cb7752f89eec856841`. It closes the SSE
revocation-during-fetch race by revalidating authorization after the blocking
RouterOS session query and before persistence or delivery. The full unit suite,
pre-commit, hosted security/browser/accessibility checks, and ARM64/AMD64 build,
provenance, and runtime smoke gates passed. Container run
[#37197892650](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/37197892650)
published the stable main image:

| Platform | Immutable image tag | Published digest |
| --- | --- | --- |
| RouterOS ARM64 | `sha-1690eb89e8d17c272ca128cb7752f89eec856841-arm64` | `sha256:ba11813eeb1b621574e1822ec3a657f2f79f49a6318415883089d09fc14e9966` |
| CHR/x86 AMD64 (evaluation) | `sha-1690eb89e8d17c272ca128cb7752f89eec856841-amd64` | `sha256:4d0145dd432737b39ff926c1fc66408e4cc122373dcc925dcc1aacb80e3856c3` |

The RouterOS updater began the canary test at 14:21:26 Europe/Sofia. It
recovered from transient fetch timeouts, reported canary healthy with HTTP 200
readiness at 14:22:43, and promoted production at 14:23:50 after its configured
stability window. Production startup completed and readiness returned HTTP 200;
the updater logged promotion complete at 14:24:01. Redis remained running.
This is point-in-time configured-tag and health evidence, not a resource
baseline, authenticated browser review, digest read-back, or formal sustained
acceptance. RouterOS policy, CA, certificates, VPN user data, credentials, and
persistent application data were not changed.

### Historical formal v2.6.4 release and RouterOS rollout

Formal release **v2.6.4** points to commit
`9671f27db9e5bad61323378fcdab51fca3d39a8b`. Container publication run
[#37199225501](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/37199225501)
passed both architecture builds, rendered-browser validation, published-runtime
health smokes, and exact-digest provenance/SBOM verification, and updated the
`routeros-stable` manifest. It includes the SSE revocation-during-fetch fix
from PR [#424](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/424).

| Check | Result |
| --- | --- |
| RouterOS ARM64 image | `sha-9671f27db9e5bad61323378fcdab51fca3d39a8b-arm64`, `sha256:89b0b0d5a7f6b5d417d134fcaa04e442fbe88c4dfc11b49a8192bf152a404bd4` |
| AMD64 image (evaluation only) | `sha-9671f27db9e5bad61323378fcdab51fca3d39a8b-amd64`, `sha256:0c39c558a3c293e59b836bb4601a41060d298048627804bc2559b65b1e0c5c95` |
| RouterOS rollout (2026-10-04 14:46–14:49 Europe/Sofia) | Canary healthy after update and configured stability validation; production promoted and healthy; Redis running |
| Resource baseline | Not collected during this read-back |
| Digest comparison on router | Not available; RouterOS exposes configured image tag, not registry content digest |
| Formal sustained acceptance | Pending; this is point-in-time deployment/health evidence only |

The user-authorized updater performed the canary test and production promotion
through its existing scheduled flow. No RouterOS policy, CA, certificates, VPN user data,
credentials, or persistent application data were changed. Do not infer latency
percentiles, event integrity, restart recovery, or rollback acceptance from this
observation.

This is point-in-time rollout evidence, not the formal sustained acceptance
window or an independent on-router registry digest comparison.

### Authenticated production browser check — 2026-10-04

After the v2.6.4 rollout, the operator-authenticated browser loaded the protected
production Dashboard as the Owner role and then opened Connections. The views
reported the live Socket.IO transport and loaded without a manual refresh. This
confirms the normal authenticated application/reverse-proxy path for this session;
it is not a test of unauthenticated API denial, role changes, session expiry or
revocation, or a sustained live-event latency window. No VPN clients were
connected during the observation, so no new session event could be correlated
with RouterOS history. No operator-initiated RouterOS configuration, VPN-user,
or active-session mutation was performed.

### Historical v2.6.1 publication and read-back

Release **v2.6.1**, commit `0aa90ab1deb9bffd44a1c78797f3b599dd9208b2`, was
published after PR #406. Release-notes run
[37184131881](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/37184131881)
and container run
[37184131858](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/37184131858)
passed. The stable manifest points to this commit; both architectures, runtime
smoke tests, and exact-digest provenance/SBOM checks passed. The scheduled
updater passed canary readiness/stability and promoted production.

| Check | Result |
| --- | --- |
| RouterOS ARM64 image | `sha-0aa90ab1deb9bffd44a1c78797f3b599dd9208b2-arm64`, `sha256:979c8a4e34858e1188b3314f12b28ab5e0d09571ea0722f42c05532f0f9cc92b` |
| AMD64 image (evaluation only) | `sha256:db71b92af8d259ff995a9ab55345038ad4b78ceaa93289d5f06e3c5731f2d2f9` |
| Stable manifest | Updated to v2.6.1 ARM64/AMD64 immutable tags |
| Canary and production at latest WebFig check (2026-10-04 08:17 UTC) | Both configured with `sha-0aa90ab1deb9bffd44a1c78797f3b599dd9208b2-arm64` and healthy; Redis was running |
| Point-in-time RouterOS resource snapshot | Collected; deployment-specific values are retained in private acceptance evidence. Not a sustained baseline. |
| Router digest comparison | Not available from the RouterOS configured-tag read-back |
| v2.6.1 deployment | Confirmed on canary and production by immutable tag and healthy status; point-in-time only |
| Formal acceptance | Pending; no sustained acceptance or rollback result is claimed |

No RouterOS policy, CA, certificates, VPN user data, credentials, or persistent
application data were changed by release publication or its automatic rollout.
The read-back verifies the configured immutable tag and health, but does not
independently compare the registry digest on the router or complete the formal
acceptance window.

## Deployment identity and status snapshot — 2026-10-05 (before PR #501)

The following point-in-time rows preserve the status known before PR #501 was
published. For the current published candidate, canary tag read-back, and
production state, see the 2026-10-06 section near the top of this report.

| Field | Value |
| --- | --- |
| Repository | aivanov2-godaddy/mikrotik-openvpn-gui |
| Accepted telemetry commit | ffbf7f6 (`ffbf7f618df2fd23ce4bcee033680cd1ef882a8c`) |
| Acceptance canary image tag | `sha-ffbf7f618df2fd23ce4bcee033680cd1ef882a8c-arm64` |
| Acceptance canary image digest | `sha256:59358cde350cefdbb7c918045199a9a7b84d01578a58fae6e115f7444d127c08` |
| Acceptance production image tag | `sha-ffbf7f618df2fd23ce4bcee033680cd1ef882a8c-arm64` |
| Acceptance production image digest | `sha256:59358cde350cefdbb7c918045199a9a7b84d01578a58fae6e115f7444d127c08` |
| Last authenticated production application observation | On 2026-10-05 at approximately 05:08 Europe/Sofia, the freshly loaded authenticated Owner Dashboard showed `Live · updated now` and `Operational`; its baked revision matched the configured immutable ARM64 image tag. No VPN client was connected. This is a point-in-time health/live-state observation, not a session-event latency, traffic-freshness, or sustained acceptance measurement. No session identity or address is included. |
| Latest RouterOS container read-back at that time | The 2026-10-05 WebFig read-back showed canary and production configured with PR #484's `sha-93627bca38312ad1845249c6df1c0fcecf12122e-arm64` tag, both healthy (`H`), with Redis running (`R`). This is point-in-time tag/health evidence; RouterOS does not report an independent registry digest. |
| Latest published mainline image at that time | PR #494 main commit `03d08a2e6a08554c68cf74930049ac29ac0b3219`, publication run [37328242084](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/37328242084); ARM64 tag `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-03d08a2e6a08554c68cf74930049ac29ac0b3219-arm64`, digest `sha256:5d5645d7613f74081bb01e390d6201ba6230968de72248119b39c9a4274ecad4`. Published and CI-verified; not verified on RouterOS. |
| RouterOS System Resources observation at that time | On 2026-10-05 at approximately 05:08 Europe/Sofia, router CPU, memory, and storage were below the then-current cutoffs; exact values remain in private local evidence. This is one point-in-time sample, not a sustained resource baseline. |
| Latest numbered release | v2.7.0, commit `2e01f111e1445c79b1753477a41efbaec27a1a2d`, publication run [37212204038](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/37212204038); exact-digest provenance/SBOM and runtime smoke passed |
| Latest main runtime patch at that time | PR #494, commit `03d08a2e6a08554c68cf74930049ac29ac0b3219`, was the latest application-runtime change before PR #501. |
| Formal v2.7.0 ARM64 / AMD64 digests | `sha256:cf7f60ba462db7c70333892cd39ef5a88b4d496c0cfb6068ec2f184b7946178a` / `sha256:c5549656a5706786579052e274c0018f405ea2c7530956a3761143ca200e8b1f` |
| Previous main runtime patch | PR #490, commit `8d189f82dca62ee112729c7fdfb2a96a35588ce5`, preceding PR #494 in the application-runtime history. |
| RouterOS read-back after latest image publication | No RouterOS read-back of PR #494 is recorded. The latest timestamped on-router tag/health observation remains PR #484 on both canary and production. This does not establish PR #492's updater example is installed or complete telemetry acceptance. |
| Dashboard state at PR #484 RouterOS read-back | The Dashboard browser tab showed its sign-in page during that read-back. An undated screenshot shows an authenticated dashboard with `Live · SOCKETIO`, but it has no legible immutable image tag/digest and cannot establish sustained event/freshness evidence. |
| Acceptance window | Earlier 2026-10-02 post-publication verification of the accepted telemetry image, health, ASGI transport, and Binary API configuration; separate brief authenticated live-update observation on 2026-10-05, not a formal acceptance window |
| RouterOS version | 7.24.4 stable during baseline acceptance; 7.24.5 stable in the authenticated production dashboard observation on 2026-10-04 |

The accepted Binary API baseline was promoted to production on 2026-10-01.
Later authenticated RouterOS read-back, recorded on 2026-10-03, showed canary
and production configured with the immutable `a2d0ce2` ARM64 tag and both
containers healthy on RouterOS 7.24.5 stable. The registry digest above comes
from the signed publication workflow; RouterOS reports its configured tag, not
the image content digest. These are point-in-time records, not the later
runtime's sustained acceptance. The public endpoint remains behind Cloudflare
Access.

## Previous deployed release read-back — 2026-10-04 (v2.5-era image)

PR #397 merged as `7eacb9fdbd42ca1e3e9b67005d2f2eea4a5a262a`. Publication run
[37175496014](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/37175496014)
passed source and rendered-browser verification, ARM64/AMD64 image publication,
runtime smoke tests, and exact-digest SBOM/provenance verification. A subsequent
read-only RouterOS WebFig inspection showed both canary and production
configured with the immutable ARM64 tag and healthy; Redis remained running.
This supersedes the older deployment observations below, but it is still only a
point-in-time tag/health check, not formal acceptance.

| Check | Result |
| --- | --- |
| ARM64 tag / registry digest | `sha-7eacb9fdbd42ca1e3e9b67005d2f2eea4a5a262a-arm64` / `sha256:0614da1d2eb1c029312c13ecb951adea6ff09ff387149472ca712a070de2d4f3` |
| AMD64 registry digest | `sha256:9ffde399b83fe07f0417a3d53f41a8df62af6e3bce6fc5973c88382cf2e8e53e` (not deployed on this ARM64 router) |
| Canary / production configured tag | Both read back as `sha-7eacb9fdbd42ca1e3e9b67005d2f2eea4a5a262a-arm64` |
| Container health / resources | Both healthy; point-in-time resource values are retained in private acceptance evidence; Redis was running (not a sustained resource baseline) |
| Router resources | No complete post-promotion CPU/memory/storage baseline or peak sample recorded |
| Application access | Browser remained at the Cloudflare Access email-code sign-in form; authenticated post-restart UI and event freshness checks await operator sign-in |
| Registry digest on device | Not independently compared: RouterOS read-back exposes the configured immutable tag, not the registry content digest |
| Formal runtime soak / rollback | Not completed for this release; no API interruption, counter-reset, Redis failure, or rollback test was performed |

No authenticated readiness/metrics collection was completed after this
restart. The RouterOS container health flag reflects its
configured local health check; it is not a substitute for the formal
30-minute telemetry/Redis acceptance window. No RouterOS configuration,
policy, CA, certificates, VPN user data, or persistent data was changed in
this observation.

## Newer published candidate — deployment verification pending — 2026-10-04

PR #395 merged as `d28ac1ce3264a988ba27fada4a5bec30ae1d6ce0`. At the time, publication run
[37173593889](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/37173593889)
passed release-source verification, the rendered browser/accessibility suite,
ARM64 and AMD64 builds, runtime smoke tests, and exact-digest provenance/SBOM
verification. The immutable ARM64 image tag is
`sha-d28ac1ce3264a988ba27fada4a5bec30ae1d6ce0-arm64` with digest
`sha256:f120d689f04e588bee8dd6dfa921cef176825a3315f52c3c9e2a17f1827bad1e`;
the AMD64 digest is
`sha256:427d6a88e8784e7fa63518e0880ac5cbcd5ed284b770897d7eb1c1df7e548e9e`.

| Check | Result |
| --- | --- |
| Publication and image verification | Passed for both architectures, including runtime smoke and exact-digest attestations |
| Canary / production configured image | Not read back for this candidate; the last confirmed tag remains the `297d960` ARM64 image recorded above |
| Authenticated public dashboard | Still at the Cloudflare Access email-code sign-in form during this check; no authenticated dashboard or live-event freshness observation was made |
| Router resources, container health, and Redis | No post-publication router observation recorded |
| Formal soak, role-change/expiry, API interruption, counter-reset, and rollback drill | Pending; publication and CI do not complete runtime acceptance |

This is registry evidence, not router deployment evidence. No router policy,
CA, certificates, VPN user data, or persistent data was changed by publication.

PR #392 merged as `015ee9278adb1f438fdae9e6a82397f4cfcbaca6`. Publication run
[37171199073](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/37171199073)
passed release-source verification, the complete rendered browser/accessibility
suite, ARM64 and AMD64 builds, runtime smoke tests, and exact-digest
provenance/SBOM verification. The immutable ARM64 image is
`sha-015ee9278adb1f438fdae9e6a82397f4cfcbaca6-arm64` with digest
`sha256:b53d519b3d427d3dbd4c789c882e82cc7ead2406c27af906ed69a3409f45c2b6`;
the AMD64 digest is
`sha256:dcd9f10de3786c894feadd3100f09ad6c83575ba0075c9c1ae26423951ce6ec9`.

| Check | Result |
| --- | --- |
| Publication and image verification | Passed for both architectures, including runtime smoke and exact-digest attestations |
| Canary / production configured image | Not yet read back for this candidate; the last confirmed tag remains the `297d960` ARM64 image recorded above |
| Container health, Redis, and router resources | No post-publication router observation recorded |
| Authenticated dashboard event freshness / reconnect | Pending operator sign-in and live-device observation |
| Formal soak, API interruption, counter-reset, and rollback drill | Pending; this publication does not complete the runtime acceptance window |

The router-local deployment controller is expected to consume the approved
immutable release, but no deployment is claimed until read-back confirms it.
No router policy, CA, certificates, VPN user data, or persistent data was
changed by this publication.

## Previously published candidate and canary observation — 2026-10-04

At that point, the public `routeros-stable` manifest pointed to commit
`34a880970ecc6ce622c257e3307c9b7cc2885b96`. Publication run
[37149717625](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/37149717625)
passed source and rendered-browser verification, ARM64 and AMD64 builds,
runtime smoke tests, and exact-digest provenance/SBOM verification. The
published tags are `sha-34a880970ecc6ce622c257e3307c9b7cc2885b96-arm64` and
`sha-34a880970ecc6ce622c257e3307c9b7cc2885b96-amd64`; the registry digests
are recorded above. The workflow summary now reports platform and architecture
without shell command substitution.

This is registry evidence, not router deployment evidence. The most recent
read-only canary readiness response observed during this session reported
revision `68fbaaae5ec50b42992f3678c8042e48f987bc8c`, before the `10930df`
publication. Subsequent private readiness probes timed out; current canary and
production revisions/health therefore remain unverified. No claim is made that
the latest stable image is running on either router container. The fresh
runtime soak, live telemetry measurements, and rollback rehearsal remain
pending.

## Historical deployment read-back — 2026-10-03

Runtime revision `a2d0ce29943964c2a5c9a12d5a53650b3bbe16b3` includes the
session-binding, process-epoch snapshot recovery, telemetry authorization, and
accessibility changes recorded in [RELEASES.md](RELEASES.md). Publication run
[37135796169](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/37135796169)
passed both architecture builds, runtime smoke, stable-manifest publication,
and exact-digest provenance/SBOM verification. Authenticated RouterOS read-back
reported both containers on the immutable ARM64 tag and healthy; the router
does not report the registry manifest digest.

| Check | Result |
| --- | --- |
| Candidate image | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-a2d0ce29943964c2a5c9a12d5a53650b3bbe16b3-arm64` |
| Published ARM64 manifest digest | `sha256:3d6ec58d333634a571107fc6b941b6ba86c2e279db51c4c627f792cdbbb17e38` |
| Canary revision / health | `a2d0ce29943964c2a5c9a12d5a53650b3bbe16b3`; authenticated RouterOS read-back healthy; later private `/healthz` and `/readyz` probe returned `ok` and `ready` at this revision |
| Production revision / health | `a2d0ce29943964c2a5c9a12d5a53650b3bbe16b3`; authenticated RouterOS read-back healthy; the production private endpoint was not reachable from the later workstation probe |
| Container resource observations | Point-in-time values are retained in private acceptance evidence; not a baseline or peak. |
| Digest identity on RouterOS | Not verified; RouterOS read-back exposed the configured tag, while digest is from registry publication evidence. |

This is a deployment/readiness check, not a replacement for the formal
30-minute Redis/telemetry acceptance window. A later unauthenticated public
health probe redirected to Cloudflare Access, so current production health was
not independently rechecked from that workstation. Router-side registry-digest
attestation, long-window latency/freshness percentiles, Redis delivery evidence,
and recovery/failure-injection gates remain outstanding for the current runtime.

## Published candidate and canary read-back — 2026-10-04

The latest stable manifest now points to merge commit
`1a6bf3e35a1b785e1d7797cf9dfd50ab8ea2fe5e`. Publication run
[37156506629](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/37156506629)
passed source/unit and rendered-browser verification, ARM64/AMD64 builds,
runtime smoke, and exact-digest SBOM/provenance verification.

| Check | Result |
| --- | --- |
| Candidate ARM64 tag / digest | `sha-1a6bf3e35a1b785e1d7797cf9dfd50ab8ea2fe5e-arm64` / `sha256:31a9fbb5403da9871556ca55044d265f23d726b24d073455673f12c005ce0b66` |
| Candidate AMD64 tag / digest | `sha-1a6bf3e35a1b785e1d7797cf9dfd50ab8ea2fe5e-amd64` / `sha256:53605fa053e968ed6643197dd87b9c19529b1feda2239df63005b0d0ba00f435` |
| Canary `/readyz` | HTTP 200, ready, but still reports previous revision `ce01f712d1b90e41e55ddd0fb1470302ec15563d`; candidate not yet observed running. |
| Unauthenticated canary `/api/telemetry` | HTTP 401 on the previously observed canary revision; this does not validate the new candidate's runtime authorization. |
| Production direct readiness probes | Timed out from this workstation; no production revision or health claim. |
| RouterOS updater observation | Existing updater log reported a run skipped because another run held its lock; no manual update command or RouterOS configuration change was issued. |

This is publication plus partial read-only canary evidence, not acceptance. The
new candidate has not been confirmed on the canary, the updater lock state has
not been independently resolved, and no current production read-back is
available. Do not promote or claim acceptance based solely on this table.

### Subsequent canary read-back

After the updater's overlapping run cleared, a later read-only canary check
returned HTTP 200 from `/readyz` with revision
`1a6bf3e35a1b785e1d7797cf9dfd50ab8ea2fe5e`, matching the published candidate.
Unauthenticated requests to `/api/telemetry`, `/metrics`, and
`/api/observability` each returned HTTP 401. This verifies candidate readiness
and anonymous denial only. It does not verify authenticated telemetry freshness,
the Redis delivery path, RouterOS reconnect/snapshot recovery, a 30-minute soak,
or production deployment. No RouterOS policy or secrets were changed.

## Earlier published candidate — 2026-10-04

The main-branch publication for merge commit
`6ae554ed226107e8639f345ff02bd0ae4269c5fc` completed in run
[37159106219](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/37159106219).
ARM64 and AMD64 builds, detached SBOM/provenance verification, and published
runtime smoke tests passed.

| Check | Result |
| --- | --- |
| ARM64 tag / digest | `sha-6ae554ed226107e8639f345ff02bd0ae4269c5fc-arm64` / `sha256:1f01b92a7da0d11d0013e2fa208ad8e843ae699580b2f4ca1a319ec22238e8cd` |
| AMD64 tag / digest | `sha-6ae554ed226107e8639f345ff02bd0ae4269c5fc-amd64` / `sha256:6c03325292a51acb08265feb15ca4a5e3d253522e8b6237aa7e1443717b11a5a` |
| Canary revision / health after publication | Not verified in this observation; latest separate canary readiness observation remains `1a6bf3e`. |
| Production revision / health after publication | An authenticated production dashboard subsequently reported this full revision running and the RouterOS connection healthy; see the next section. |
| 30-minute telemetry/Redis soak and rollback drill | Not performed for this candidate. |

At publication time, this was registry evidence only. A later authenticated
production dashboard observation is recorded below. Canary soak and formal
acceptance remain pending.

### Authenticated production dashboard observation — 2026-10-04

The signed-in dashboard at `vpn.wanted.sx` loaded successfully through
Cloudflare Access. Its Service Health panel reported the router connection
healthy on RouterOS 7.24.5, six checks healthy and one needing review
(certificate-revocation behavior), and its deployment history marked release
`edge-arm64` / revision
`6ae554ed226107e8639f345ff02bd0ae4269c5fc` as running. The page also exposed
the live Connections view and identified its delivery transport as Socket.IO.

This is a point-in-time authenticated application observation, not a RouterOS
container CLI read-back: the dashboard did not expose a registry manifest
digest, so the exact running digest is not established by this observation.
It does not establish canary status, sustained telemetry freshness/latency,
Redis delivery/recovery, API-restart recovery, event integrity, or a rollback
drill. No RouterOS settings, VPN data, certificates, or secrets were changed.

## Earlier deployed correction

PR [#179](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/179)
fixed false multi-gigabit live-traffic spikes by calculating browser rates only
on the documented five-second sample cadence. The change preserves the live
Socket.IO stream and does not add a manual refresh path. CI passed all 12
required checks before the immutable image was published and promoted.

## Acceptance gates

The following results apply to the accepted Binary API telemetry baseline and
the private operator window dated 2026-10-01/02; they are not evidence that
later `a2d0ce2`, `6ae554e`, or `7eacb9f` images completed their own release
soaks.

| Gate | Target | Result | Evidence reference |
| --- | --- | --- | --- |
| Router CPU | No unacceptable increase; record peak and baseline | PASS; measurements are retained in private acceptance evidence | private-acceptance-record |
| Router memory | No unacceptable increase; record peak and baseline | PASS; measurements are retained in private acceptance evidence | private-acceptance-record |
| Router storage | Below the configured limit | PASS; measurement is retained in private acceptance evidence | private-acceptance-record |
| Container health | Healthy for the full observation window | PASS; canary and production healthy across the sampled five-second window with one active client | acceptance-window-2026-10-01 |
| Session event latency | p95 at or below 1 second | PASS; confirmed in the private operator acceptance record | private-acceptance-record |
| Traffic freshness | No sample older than 2 seconds | PASS; confirmed in the private operator acceptance record | private-acceptance-record |
| Live UI delivery | Connect/disconnect visible without refresh | PASS for one observed disconnect/reconnect cycle; both ended and connected rows appeared without refresh | acceptance-window-2026-10-01-live-client |
| API interruption | Automatic reconnect observed | PASS; API-SSL restored and Binary API login returned after ~4s | acceptance-window-2026-10-01-api-fallback |
| Snapshot recovery | Full snapshot restored after reconnect | PASS; active connection, uptime, traffic, and history snapshot restored after reconnect | acceptance-window-2026-10-01-live-client |
| Counter reset | Rates remain correct after reset | PASS; confirmed in the private operator acceptance record | private-acceptance-record |
| Binary/REST parity | Binary snapshot matches REST snapshot | PASS; confirmed in the private operator acceptance record | private-acceptance-record |
| Event integrity | No lost, duplicated, or out-of-order events | PASS; confirmed in the private operator acceptance record | private-acceptance-record |
| REST fallback | Available throughout the test | PASS; `/api/status` returned 200 while API-SSL was disabled | acceptance-window-2026-10-01-api-fallback |
| Authentication | Unauthenticated telemetry denied | PASS; unauthenticated telemetry requests returned 401 | acceptance-window-2026-10-01-auth |
| Secret scan | Payloads/logs contain no secrets or private data | PASS; confirmed by the private acceptance scan and public redaction checks | private-acceptance-record |

## Runtime and rollback

- Effective public transport: Socket.IO over ASGI/Uvicorn when API-SSL is available
- Fallback transport verified: REST status polling remained live during API-SSL interruption
- Multi-client smoke check: PASS; two authenticated dashboard clients simultaneously
  remained live and showed the same active-session snapshot
- WebSocket-specific health metrics: exposed through the authenticated `/metrics`
  endpoint for active connections, accepted/rejected connections, disconnects,
  and redacted events emitted
- Rollback image: `sha-8336e297...-arm64` (previous production image; digest retained in private deployment record)
- Rollback procedure exercised: **No**; no image rollback was needed
- RouterOS configuration changed: **No persistent change**; API-SSL was toggled off/on only for this controlled test
- OpenVPN CA or certificates changed: **No**
- VPN users, profiles, or router-local data changed: **No**

## Final decision

Baseline result: **PASS — the operator accepted the controlled production
window, immutable telemetry image, reconnect/snapshot behavior, live traffic
freshness, counter handling, Binary/REST parity, event integrity, and privacy
gates.**

Historical deployment result as of 2026-10-05: **PR #497 WAS PUBLISHED,
ROUTEROS-OBSERVED, AND HEALTHY; FORMAL ACCEPTANCE PENDING —** the canary and production containers
were read back on the immutable ARM64 tag
`sha-3eda7a15acb6fdb0f9749dfe0c2fd9efeeae714f-arm64`, whose published
registry digest is
`sha256:089e9c48c3e388cd08be3a44ddd9f525a0b50ea9e15983d6a8fa78e442fecc6c`.
RouterOS reports the configured tag, not an independent digest. The canary
rollback-and-forward-recovery drill returned the expected `/readyz` revisions;
the production container was not restarted for that drill. The authenticated
dashboard showed live status and Operational service health, but no VPN client
was connected and no event or traffic-freshness metric was available. PR #492's
30-sample updater example is not installed on the router. These point-in-time
observations are not a sustained baseline. The 30-minute Redis/telemetry
window, latency/freshness percentiles, API-reconnect and event-integrity
evidence, SQLite restore, and live session expiry/revocation exercise remain
pending.**

The deployed image contains PR #478's fail-closed acceptance collector and
dialog accessibility checks. PR #479 updates the repository's release and
acceptance records only; it does not change the runtime image.

The acceptance evaluator remains available for future regression windows. New
evidence must remain outside the repository and should be redacted before any
future aggregate result is published:

    python scripts/telemetry_acceptance.py --input private-acceptance.ndjson --max-latency-p95-ms 1000 --max-event-age-seconds 2 --max-router-cpu-percent 80 --max-router-memory-percent 90 --max-router-storage-percent 90

Keep private-acceptance.ndjson outside the repository. The procedure for
collecting it is in LIVE_TELEMETRY_CANARY.md, and the immediate rollback path
is in LIVE_TELEMETRY_ROLLBACK.md.

## Historical RouterOS and browser read-back — PR #497 — 2026-10-05

Read-only RouterOS WebFig inspection showed both canary and production
configured with PR #497's immutable ARM64 tag
`sha-3eda7a15acb6fdb0f9749dfe0c2fd9efeeae714f-arm64`; both dashboard
containers were marked healthy (`H`). Canary `/readyz` returned HTTP 200 and
the expected revision. A canary-only rollback to the previous immutable image
and forward recovery to PR #497 both returned the expected ready revisions.
Production was not restarted or rolled back. RouterOS exposes the configured
tag and health state, not an independent registry digest; the matching digest
is from the verified publication record. Exact router/container resource
samples remain operator-local.

In the authenticated browser, the Dashboard showed `Live · updated now` and
zero connected VPN clients; the Service Health page showed `Operational`, six
healthy checks, and zero needing review or unavailable. These observations
confirm a currently live authenticated UI and read-only health result, not a
VPN connect/disconnect event, end-to-end event latency, under-load traffic
freshness, Redis delivery, or a sustained soak. Unauthenticated public
requests to `/readyz` and `/metrics` were redirected to Cloudflare Access;
this establishes the edge gate only. No live client event or production
service interruption was induced. No CA, certificate, VPN user, or RouterOS
policy was changed. The canary image was rolled back and restored to the
candidate; the production container was not restarted.
Formal #199 acceptance and #200 live authorization/security checks remain
open.
