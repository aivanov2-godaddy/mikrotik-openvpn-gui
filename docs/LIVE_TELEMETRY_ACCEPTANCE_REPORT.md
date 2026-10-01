# Live telemetry acceptance report

Status: **FORMAL ACCEPTANCE COMPLETE — OPERATOR ACCEPTED**

This report is the public, redacted acceptance record for the deployed Binary
API telemetry image. The operator's detailed acceptance evidence remains
private; raw RouterOS data, addresses, account names, credentials,
certificates, tokens, and private identifiers are not copied into this
repository. The operator accepted the controlled window and the immutable
production rollout on 2026-10-02.

## Deployment identity

| Field | Value |
| --- | --- |
| Repository | aivanov2-godaddy/mikrotik-openvpn-gui |
| Production commit | 559694d (`559694dd8ba2ab65a35b0b59614c5bd76555beda`) |
| Canary image tag | `sha-559694dd8ba2ab65a35b0b59614c5bd76555beda-arm64` |
| Canary image digest | `sha256:b1b04e2d24533605542fbe43baaa6a272e8054dc434e3db6da0250d112cf01f0` |
| Production image tag | `sha-559694dd8ba2ab65a35b0b59614c5bd76555beda-arm64` |
| Production image digest | `sha256:b1b04e2d24533605542fbe43baaa6a272e8054dc434e3db6da0250d112cf01f0` |
| Observation window | 2026-10-02 00:36:01–00:38:26 Europe/Sofia (watchdog canary validation and production promotion) |
| RouterOS version/architecture | RouterOS 7.24.4 stable / arm64 |

The immutable watchdog promoted the canary-validated image to production at
2026-10-01 23:58:47 Europe/Sofia. Both RouterOS containers were subsequently
verified healthy with the same tag, `LIVE_TRANSPORT=binary`, and
`SOCKETIO_ENGINE=asgi`. The public endpoint remained behind Cloudflare Access;
an unauthenticated `/readyz` request correctly returned the Access redirect.

## Latest deployed correction

PR [#179](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/179)
fixed false multi-gigabit live-traffic spikes by calculating browser rates only
on the documented five-second sample cadence. The change preserves the live
Socket.IO stream and does not add a manual refresh path. CI passed all 12
required checks before the immutable image was published and promoted.

## Acceptance gates

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

Overall result: **PASS — the operator accepted the controlled production
window, immutable image rollout, reconnect/snapshot behavior, live traffic
freshness, counter handling, Binary/REST parity, event integrity, and privacy
gates.**

The acceptance evaluator remains available for future regression windows. New
evidence must remain outside the repository and should be redacted before any
future aggregate result is published:

    python scripts/telemetry_acceptance.py --input private-acceptance.ndjson --max-latency-p95-ms 1000 --max-event-age-seconds 2 --max-router-cpu-percent 80 --max-router-memory-percent 90 --max-router-storage-percent 90

Keep private-acceptance.ndjson outside the repository. The procedure for
collecting it is in LIVE_TELEMETRY_CANARY.md, and the immediate rollback path
is in LIVE_TELEMETRY_ROLLBACK.md.
