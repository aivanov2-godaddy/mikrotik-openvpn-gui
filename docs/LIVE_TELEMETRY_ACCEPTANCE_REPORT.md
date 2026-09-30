# Live telemetry acceptance report

Status: **PENDING OPERATOR EVIDENCE**

This report is the controlled acceptance record for the deployed Binary API
telemetry image. It must be completed privately by the operator and committed
only after all raw RouterOS data, addresses, account names, credentials,
certificates, tokens, and private identifiers have been removed. The report
contains aggregate measurements and pass/fail results only.

## Deployment identity

| Field | Value |
| --- | --- |
| Repository | aivanov2-godaddy/mikrotik-openvpn-gui |
| Production commit | ba82c4e |
| Canary image tag | <immutable sha tag> |
| Canary image digest | <sha256 digest> |
| Production image tag | <immutable sha tag> |
| Production image digest | <sha256 digest> |
| Observation window | <UTC start> — <UTC end> |
| RouterOS version/architecture | <version and architecture> |

## Acceptance gates

| Gate | Target | Result | Evidence reference |
| --- | --- | --- | --- |
| Router CPU | No unacceptable increase; record peak and baseline | PENDING | <private evidence id> |
| Router memory | No unacceptable increase; record peak and baseline | PENDING | <private evidence id> |
| Router storage | Below the configured limit | PENDING | <private evidence id> |
| Container health | Healthy for the full observation window | PENDING | <private evidence id> |
| Session event latency | p95 at or below 1 second | PENDING | <private evidence id> |
| Traffic freshness | No sample older than 2 seconds | PENDING | <private evidence id> |
| Live UI delivery | Connect/disconnect visible without refresh | PENDING | <private evidence id> |
| API interruption | Automatic reconnect observed | PENDING | <private evidence id> |
| Snapshot recovery | Full snapshot restored after reconnect | PENDING | <private evidence id> |
| Counter reset | Rates remain correct after reset | PENDING | <private evidence id> |
| Binary/REST parity | Binary snapshot matches REST snapshot | PENDING | <private evidence id> |
| Event integrity | No lost, duplicated, or out-of-order events | PENDING | <private evidence id> |
| REST fallback | Available throughout the test | PENDING | <private evidence id> |
| Authentication | Unauthenticated telemetry denied | PENDING | <private evidence id> |
| Secret scan | Payloads/logs contain no secrets or private data | PENDING | <private evidence id> |

## Runtime and rollback

- Effective public transport: <socketio/websocket or fallback>
- Fallback transport verified: <SSE/REST result>
- Rollback image: <previous immutable sha tag and digest>
- Rollback procedure exercised: <yes/no; reference>
- RouterOS configuration changed: **No**
- OpenVPN CA or certificates changed: **No**
- VPN users, profiles, or router-local data changed: **No**

## Final decision

Overall result: **PENDING**

The report may be marked **PASS** only when every gate above has a redacted
evidence reference and the aggregate output from the acceptance evaluator exits
with code 0:

    python scripts/telemetry_acceptance.py --input private-acceptance.ndjson --max-latency-p95-ms 1000 --max-event-age-seconds 2 --max-router-cpu-percent 80 --max-router-memory-percent 90 --max-router-storage-percent 90

Keep private-acceptance.ndjson outside the repository. The procedure for
collecting it is in LIVE_TELEMETRY_CANARY.md, and the immediate rollback path
is in LIVE_TELEMETRY_ROLLBACK.md.
