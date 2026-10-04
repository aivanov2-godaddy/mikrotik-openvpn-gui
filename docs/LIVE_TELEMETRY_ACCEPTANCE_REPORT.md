# Live telemetry acceptance report

Status: **TELEMETRY BASELINE ACCEPTED — CURRENT RUNTIME SOAK PENDING**

This report records the operator's 2026-10-02 acceptance of the Binary API
telemetry baseline, plus later deployment observations. The operator's detailed
acceptance evidence remains private; raw RouterOS data, addresses, account
names, credentials, certificates, tokens, and private identifiers are not
copied into this repository. The later runtime image listed below is a newer
build; its full 30-minute Redis/telemetry acceptance window and rollback drill
have not been recorded as complete.

## Deployment identity

| Field | Value |
| --- | --- |
| Repository | aivanov2-godaddy/mikrotik-openvpn-gui |
| Accepted telemetry commit | ffbf7f6 (`ffbf7f618df2fd23ce4bcee033680cd1ef882a8c`) |
| Acceptance canary image tag | `sha-ffbf7f618df2fd23ce4bcee033680cd1ef882a8c-arm64` |
| Acceptance canary image digest | `sha256:59358cde350cefdbb7c918045199a9a7b84d01578a58fae6e115f7444d127c08` |
| Acceptance production image tag | `sha-ffbf7f618df2fd23ce4bcee033680cd1ef882a8c-arm64` |
| Acceptance production image digest | `sha256:59358cde350cefdbb7c918045199a9a7b84d01578a58fae6e115f7444d127c08` |
| Latest authenticated production observation | After the 2026-10-04 rollout, RouterOS read-back confirmed `297d9607a070dfe71a2b8c15075ef739127eb8ce` configured on both containers and healthy; authenticated browser verification is pending operator sign-in after the restart |
| Latest verified canary observation | RouterOS read-back on 2026-10-04 confirmed the canary on `297d9607a070dfe71a2b8c15075ef739127eb8ce` and healthy at that point in time |
| Latest published candidate | `015ee9278adb1f438fdae9e6a82397f4cfcbaca6` (publication run [37171199073](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/37171199073)); RouterOS deployment read-back for this candidate is pending |
| Latest published ARM64 / AMD64 digests | `sha256:b53d519b3d427d3dbd4c789c882e82cc7ead2406c27af906ed69a3409f45c2b6` / `sha256:dcd9f10de3786c894feadd3100f09ad6c83575ba0075c9c1ae26423951ce6ec9` |
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

## Latest deployed release read-back — 2026-10-04

PR #387 merged as `297d9607a070dfe71a2b8c15075ef739127eb8ce`. Publication run
[37166529360](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/37166529360)
passed source and rendered-browser verification, ARM64/AMD64 image publication,
runtime smoke tests, and exact-digest SBOM/provenance verification. RouterOS
read-only console inspection confirmed both canary and production configured
with the immutable ARM64 tag and showed both containers healthy; Redis remained
running. This supersedes earlier statements below that the current deployed
revision or canary state was unknown.

| Check | Result |
| --- | --- |
| ARM64 tag / registry digest | `sha-297d9607a070dfe71a2b8c15075ef739127eb8ce-arm64` / `sha256:ddcf57b91b9daa31c962c9e63fbbff2db5adea3ce4f18c349396a04f4d2699fd` |
| AMD64 registry digest | `sha256:2a50bcfd6bbdbfca68b6af1c95df196d5fde7495d3ab3e52183b5703cf9802a9` (not deployed on this ARM64 router) |
| Canary / production configured tag | Both read back as `sha-297d9607a070dfe71a2b8c15075ef739127eb8ce-arm64` |
| Container health / resources | Both healthy; point-in-time reads approximately 33 MiB RAM and under 1% container CPU each; Redis running (resource values are from the preceding sample, not remeasured after promotion) |
| Router resources | No new post-promotion sample recorded; earlier point-in-time sample is not a sustained baseline or peak |
| Application access | Browser session returned to Cloudflare Access sign-in after the container restart; authenticated post-restart UI and event freshness checks await operator sign-in |
| Registry digest on device | Not independently compared: RouterOS read-back exposes the configured immutable tag, not the registry content digest |
| Formal runtime soak / rollback | Not completed for this release; no API interruption, counter-reset, Redis failure, or rollback test was performed |

No authenticated readiness/metrics collection was completed after this
restart. The RouterOS container health flag reflects its
configured local health check; it is not a substitute for the formal
30-minute telemetry/Redis acceptance window. No RouterOS configuration,
policy, CA, certificates, VPN user data, or persistent data was changed in
this observation.

## Newer published candidate — deployment verification pending — 2026-10-04

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
| Container resource observations | Production approximately 33.2 MiB / 0.6% CPU; canary approximately 33.3 MiB / 0.6% CPU. Point-in-time only, not baseline or peak. |
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

## Latest published candidate — 2026-10-04

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

## Latest deployed correction

PR [#179](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/179)
fixed false multi-gigabit live-traffic spikes by calculating browser rates only
on the documented five-second sample cadence. The change preserves the live
Socket.IO stream and does not add a manual refresh path. CI passed all 12
required checks before the immutable image was published and promoted.

## Acceptance gates

The following results apply to the accepted Binary API telemetry baseline and
the private operator window dated 2026-10-01/02; they are not evidence that
later `a2d0ce2` or `6ae554e` images completed their own release soaks.

| Gate | Target | Result | Evidence reference |
| --- | --- | --- | --- |
| Router CPU | No unacceptable increase; record peak and baseline | OBSERVED 2–3% dashboard snapshots | acceptance-window-2026-10-01 |
| Router memory | No unacceptable increase; record peak and baseline | OBSERVED 27–28% dashboard snapshots | acceptance-window-2026-10-01 |
| Router storage | Below the configured limit | OBSERVED 13% dashboard snapshot | acceptance-window-2026-10-01 |
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

Current runtime result: **DEPLOYMENT VERIFIED; FORMAL ACCEPTANCE PENDING —
RouterOS read-back on 2026-10-04 showed canary and production configured with
`297d960` and healthy, with Redis running. The published ARM64 registry digest
is known, but no digest comparison was performed on the router. Post-restart
authenticated browser verification is pending operator sign-in. The 30-minute
Redis/telemetry window, measured freshness/latency, reconnect/failure tests,
and rollback drill remain pending.**

The acceptance evaluator remains available for future regression windows. New
evidence must remain outside the repository and should be redacted before any
future aggregate result is published:

    python scripts/telemetry_acceptance.py --input private-acceptance.ndjson --max-latency-p95-ms 1000 --max-event-age-seconds 2 --max-router-cpu-percent 80 --max-router-memory-percent 90 --max-router-storage-percent 90

Keep private-acceptance.ndjson outside the repository. The procedure for
collecting it is in LIVE_TELEMETRY_CANARY.md, and the immediate rollback path
is in LIVE_TELEMETRY_ROLLBACK.md.
