# Live telemetry acceptance report

Status: **PARTIAL ACCEPTANCE — DISCONNECT AND PRECISION EVIDENCE PENDING**

This report is the controlled acceptance record for the deployed Binary API
telemetry image. It must be completed privately by the operator and committed
only after all raw RouterOS data, addresses, account names, credentials,
certificates, tokens, and private identifiers have been removed. The report
contains aggregate measurements and pass/fail results only.

## Deployment identity

| Field | Value |
| --- | --- |
| Repository | aivanov2-godaddy/mikrotik-openvpn-gui |
| Production commit | ac8b5a8c |
| Canary image tag | `sha-ac8b5a8c222c92c7d7b76d9ec453205c76c469e7-arm64` |
| Canary image digest | `sha256:9e2cfe38c7cf403c5dfaa08118ea9b47281265f4a397e1f26d8f75cfc3792e1e` |
| Production image tag | `sha-ac8b5a8c222c92c7d7b76d9ec453205c76c469e7-arm64` |
| Production image digest | `sha256:9e2cfe38c7cf403c5dfaa08118ea9b47281265f4a397e1f26d8f75cfc3792e1e` |
| Observation window | 2026-10-01 02:02:35–02:02:50 UTC (15-second controlled test; derived from RouterOS local time) |
| RouterOS version/architecture | RouterOS 7.24.4 stable / arm64 |

## Acceptance gates

| Gate | Target | Result | Evidence reference |
| --- | --- | --- | --- |
| Router CPU | No unacceptable increase; record peak and baseline | OBSERVED 2–3% dashboard snapshots | acceptance-window-2026-10-01 |
| Router memory | No unacceptable increase; record peak and baseline | OBSERVED 27–28% dashboard snapshots | acceptance-window-2026-10-01 |
| Router storage | Below the configured limit | OBSERVED 13% dashboard snapshot | acceptance-window-2026-10-01 |
| Container health | Healthy for the full observation window | PASS; canary and production healthy across the sampled five-second window with one active client | acceptance-window-2026-10-01 |
| Session event latency | p95 at or below 1 second | PENDING; the UI exposes no event timestamp for a precise p95 calculation | acceptance-window-2026-10-01-live-client |
| Traffic freshness | No sample older than 2 seconds | PARTIAL; ten consecutive live samples updated without refresh, but exact sample age is not exposed by the UI | acceptance-window-2026-10-01-live-client |
| Live UI delivery | Connect/disconnect visible without refresh | PASS for one observed disconnect/reconnect cycle; both ended and connected rows appeared without refresh | acceptance-window-2026-10-01-live-client |
| API interruption | Automatic reconnect observed | PASS; API-SSL restored and Binary API login returned after ~4s | acceptance-window-2026-10-01-api-fallback |
| Snapshot recovery | Full snapshot restored after reconnect | PASS; active connection, uptime, traffic, and history snapshot restored after reconnect | acceptance-window-2026-10-01-live-client |
| Counter reset | Rates remain correct after reset | PENDING | <private evidence id> |
| Binary/REST parity | Binary snapshot matches REST snapshot | PENDING | <private evidence id> |
| Event integrity | No lost, duplicated, or out-of-order events | PENDING | <private evidence id> |
| REST fallback | Available throughout the test | PASS; `/api/status` returned 200 while API-SSL was disabled | acceptance-window-2026-10-01-api-fallback |
| Authentication | Unauthenticated telemetry denied | PASS; unauthenticated telemetry requests returned 401 | acceptance-window-2026-10-01-auth |
| Secret scan | Payloads/logs contain no secrets or private data | PASS for observed redacted logs and contract checks; full window scan pending | acceptance-window-2026-10-01-security |

## Runtime and rollback

- Effective public transport: Socket.IO over ASGI/Uvicorn when API-SSL is available
- Fallback transport verified: REST status polling remained live during API-SSL interruption
- Rollback image: `sha-8336e297...-arm64` (previous production image; digest retained in private deployment record)
- Rollback procedure exercised: **No**; no image rollback was needed
- RouterOS configuration changed: **No persistent change**; API-SSL was toggled off/on only for this controlled test
- OpenVPN CA or certificates changed: **No**
- VPN users, profiles, or router-local data changed: **No**

## Final decision

Overall result: **PENDING — precise event/traffic metrics, counter-reset, Binary/REST parity, and event-order evidence remain**

The report may be marked **PASS** only when every gate above has a redacted
evidence reference and the aggregate output from the acceptance evaluator exits
with code 0:

    python scripts/telemetry_acceptance.py --input private-acceptance.ndjson --max-latency-p95-ms 1000 --max-event-age-seconds 2 --max-router-cpu-percent 80 --max-router-memory-percent 90 --max-router-storage-percent 90

Keep private-acceptance.ndjson outside the repository. The procedure for
collecting it is in LIVE_TELEMETRY_CANARY.md, and the immediate rollback path
is in LIVE_TELEMETRY_ROLLBACK.md.
