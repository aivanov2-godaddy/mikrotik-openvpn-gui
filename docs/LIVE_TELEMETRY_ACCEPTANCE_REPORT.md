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
| Latest recorded deployed runtime commit | a2d0ce2 (`a2d0ce29943964c2a5c9a12d5a53650b3bbe16b3`) |
| Latest recorded deployed ARM64 tag | `sha-a2d0ce29943964c2a5c9a12d5a53650b3bbe16b3-arm64` |
| Published ARM64 manifest digest | `sha256:3d6ec58d333634a571107fc6b941b6ba86c2e279db51c4c627f792cdbbb17e38` |
| Latest stable registry publication | `34a880970ecc6ce622c257e3307c9b7cc2885b96` (run [37149717625](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/37149717625)) |
| Latest published ARM64 / AMD64 digests | `sha256:8c2346ea7971b5e26a47af34cb07bc27a39516e15c9860dd2f9bee76f1e0f184` / `sha256:aad9d850feba0b72c7db4660858cef6e747b8855f200d1d75957e3db3f9394fd` |
| Acceptance window | 2026-10-02 post-publication verification of the accepted telemetry image, health, ASGI transport, and Binary API configuration |
| RouterOS at acceptance / current | RouterOS 7.24.4 stable during acceptance; 7.24.5 stable currently / arm64 |

The accepted Binary API baseline was promoted to production on 2026-10-01.
Later authenticated RouterOS read-back, recorded on 2026-10-03, showed canary
and production configured with the immutable `a2d0ce2` ARM64 tag and both
containers healthy on RouterOS 7.24.5 stable. The registry digest above comes
from the signed publication workflow; RouterOS reports its configured tag, not
the image content digest. These are point-in-time records, not the later
runtime's sustained acceptance. The public endpoint remains behind Cloudflare
Access.

## Latest stable registry publication — 2026-10-03

The public `routeros-stable` manifest now points to commit
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

## Latest deployed correction

PR [#179](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/179)
fixed false multi-gigabit live-traffic spikes by calculating browser rates only
on the documented five-second sample cadence. The change preserves the live
Socket.IO stream and does not add a manual refresh path. CI passed all 12
required checks before the immutable image was published and promoted.

## Acceptance gates

The following results apply to the accepted Binary API telemetry baseline and
the private operator window dated 2026-10-01/02; they are not evidence that the
newer `a2d0ce2` runtime completed its own release soak.

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

Current runtime result: **PENDING — the newer `a2d0ce2` deployment still needs
its 30-minute Redis/telemetry acceptance window and rollback drill.**

The acceptance evaluator remains available for future regression windows. New
evidence must remain outside the repository and should be redacted before any
future aggregate result is published:

    python scripts/telemetry_acceptance.py --input private-acceptance.ndjson --max-latency-p95-ms 1000 --max-event-age-seconds 2 --max-router-cpu-percent 80 --max-router-memory-percent 90 --max-router-storage-percent 90

Keep private-acceptance.ndjson outside the repository. The procedure for
collecting it is in LIVE_TELEMETRY_CANARY.md, and the immediate rollback path
is in LIVE_TELEMETRY_ROLLBACK.md.
