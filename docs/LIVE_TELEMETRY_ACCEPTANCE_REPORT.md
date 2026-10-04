# Live telemetry acceptance report

Status: **TELEMETRY BASELINE ACCEPTED — CURRENT RUNTIME SOAK PENDING**

This report records the operator's 2026-10-02 acceptance of the Binary API
telemetry baseline, plus later deployment observations. The operator's detailed
acceptance evidence remains private; raw RouterOS data, addresses, account
names, credentials, certificates, tokens, and private identifiers are not
copied into this repository. The later runtime image listed below is a newer
build; its full 30-minute Redis/telemetry acceptance window and rollback drill
have not been recorded as complete.

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
dashboard instances and Redis. Those readings are retained as operational
observations, not reproduced here, and are not RouterOS-wide resource samples,
peaks, or a sustained baseline. The production site rendered its RouterOS
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

## Deployment identity

| Field | Value |
| --- | --- |
| Repository | aivanov2-godaddy/mikrotik-openvpn-gui |
| Accepted telemetry commit | ffbf7f6 (`ffbf7f618df2fd23ce4bcee033680cd1ef882a8c`) |
| Acceptance canary image tag | `sha-ffbf7f618df2fd23ce4bcee033680cd1ef882a8c-arm64` |
| Acceptance canary image digest | `sha256:59358cde350cefdbb7c918045199a9a7b84d01578a58fae6e115f7444d127c08` |
| Acceptance production image tag | `sha-ffbf7f618df2fd23ce4bcee033680cd1ef882a8c-arm64` |
| Acceptance production image digest | `sha256:59358cde350cefdbb7c918045199a9a7b84d01578a58fae6e115f7444d127c08` |
| Last authenticated production application observation | At 2026-10-04 15:02 Europe/Sofia, before v2.7.0 deployment, an authenticated Owner browser session loaded the protected Dashboard and Connections views; both displayed the live Socket.IO transport. Read-only UI verification; no live VPN session was active for session-event correlation. The current browser is at the RouterOS-authenticated dashboard sign-in page; no post-PR #448 authenticated rendering or new live-session event was verified. |
| Latest RouterOS container read-back | On 2026-10-04 23:41 Europe/Sofia, WebFig showed PR #448's immutable ARM64 tag `sha-72c4c255b92b9c5ffb9af509fea5b6306da65657-arm64` on canary and production, both healthy (`H`), with Redis running (`R`). Point-in-time container CPU/memory readings were observed; they are not a sustained baseline. No `/readyz` or authenticated app check was made. |
| Latest numbered release | v2.7.0, commit `2e01f111e1445c79b1753477a41efbaec27a1a2d`, publication run [37212204038](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/37212204038); exact-digest provenance/SBOM and runtime smoke passed |
| Latest published runtime image | PR #448 main commit `72c4c255b92b9c5ffb9af509fea5b6306da65657`, publication run [37230021532](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/37230021532); ARM64 digest `sha256:55f2735691f53950d65ed681fa8d47f6861972544e002e40349ac849e4dda185`; AMD64 digest `sha256:bbb9aaf2e0d943397d7968a7a4c452408c2ba37e9990dd936495c3721fc87198` |
| Formal v2.7.0 ARM64 / AMD64 digests | `sha256:cf7f60ba462db7c70333892cd39ef5a88b4d496c0cfb6068ec2f184b7946178a` / `sha256:c5549656a5706786579052e274c0018f405ea2c7530956a3761143ca200e8b1f` |
| Latest main runtime patch | PR #448, commit `72c4c255b92b9c5ffb9af509fea5b6306da65657`, container workflow [37230021532](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/37230021532); this is a main-branch image patch, not a new semantic release. |
| Previous main runtime patch | PR #443, commit `9045057e155b97408e9364bf759e329d60f81b69`, container workflow [37223686260](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/37223686260); it removed only the dashboard CRL/revocation status display and its status-only RouterOS read. |
| RouterOS read-back after PR #448 | WebFig showed the exact immutable ARM64 tag `sha-72c4c255b92b9c5ffb9af509fea5b6306da65657-arm64` configured and healthy (`H`) on canary and production; Redis was running (`R`). This configured-tag read-back does not independently verify the registry digest. |
| Acceptance window | 2026-10-02 post-publication verification of the accepted telemetry image, health, ASGI transport, and Binary API configuration |
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

## Latest recorded deployment read-back — 2026-10-03

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

Current runtime result: **PR #448 IMAGE TAG DEPLOYED / CONTAINER HEALTH
OBSERVED; FORMAL ACCEPTANCE PENDING —** on 2026-10-04 23:41 Europe/Sofia,
WebFig showed PR #448's immutable ARM64 tag on canary and production, each
healthy (`H`), and Redis running (`R`). Point-in-time per-container CPU/memory
readings were visible; they are not a RouterOS-wide resource sample or a
sustained baseline. RouterOS exposes the configured tag rather than an
independent registry digest. The dashboard browser was at its RouterOS-auth
sign-in page; there was no authenticated application check. The 30-minute
Redis/telemetry window, measured freshness/latency, reconnect/failure tests,
session expiry/revocation exercise, and rollback drill remain pending.**

The acceptance evaluator remains available for future regression windows. New
evidence must remain outside the repository and should be redacted before any
future aggregate result is published:

    python scripts/telemetry_acceptance.py --input private-acceptance.ndjson --max-latency-p95-ms 1000 --max-event-age-seconds 2 --max-router-cpu-percent 80 --max-router-memory-percent 90 --max-router-storage-percent 90

Keep private-acceptance.ndjson outside the repository. The procedure for
collecting it is in LIVE_TELEMETRY_CANARY.md, and the immediate rollback path
is in LIVE_TELEMETRY_ROLLBACK.md.
