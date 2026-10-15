# Live telemetry acceptance status

Status: **PR #720 artifact published; candidate-specific live acceptance is
incomplete; production promotion remains gated.**

## Public artifact evidence

PR [#720](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/720)
(`6dd53022523766a5371628dfe158286072494bf4`) is the latest published runtime
candidate. Publisher run
[#38620869138](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/38620869138)
completed successfully with source/security checks, compilation, tests,
ARM64/AMD64 builds, provenance and SPDX SBOM attestation verification,
stable-manifest read-back, and published-runtime smoke tests.

| Platform | Immutable tag | Registry digest |
| --- | --- | --- |
| RouterOS ARM64 | `sha-6dd53022523766a5371628dfe158286072494bf4-arm64` | `sha256:8379e885c3f52585c3badbb8069c483edd60e4eb526756701d1a90ab409de31d` |
| CHR/x86 AMD64 (evaluation) | `sha-6dd53022523766a5371628dfe158286072494bf4-amd64` | `sha256:2339d4d8e3e003eab8f6c99d9aad6cf5a748ac161716e23f179ea513bb351271` |

These are public build and registry facts only. This file contains no RouterOS
deployment assignments, hostnames, addresses, resource readings, logs, or VPN
session observations. Deployment-specific acceptance evidence belongs in
operator-controlled storage. The status below is a gate checklist, not a report
of private measurements.

## Candidate acceptance gates

| Gate | Required result | Public status |
| --- | --- | --- |
| Candidate identity and readiness | Canary reports the exact immutable candidate and remains healthy for the agreed window. | Partial: a readiness-only probe passed 30 one-minute samples for revision `6dd53022523766a5371628dfe158286072494bf4`; record the running digest and full acceptance evidence privately |
| Session event latency | Connect/disconnect visible in the open dashboard within 1 second. | Failed in this observation: RouterOS reported zero active test sessions after disconnect, while the open canary page still showed a stale connected snapshot and delayed status; exact event latency and reconnect remain unmeasured |
| Traffic freshness | Samples are no older than 2 seconds; no manual refresh is needed. | Not yet measured for the candidate |
| Reconnect and snapshot recovery | RouterOS API interruption recovers automatically; a full snapshot follows reconnect. | Not yet measured for the candidate |
| Event and counter integrity | Counter resets do not create incorrect rates; detect missing, duplicated, or out-of-order events. | Not yet measured for the candidate |
| Binary API and REST parity | Compare equivalent read-only snapshots and document any expected differences. | Not yet measured for the candidate |
| Redis/outbox | Exercise unavailable/restarting Redis, retries, duplicate delivery, queue drain, and recovery. | Repository tests exist; candidate-specific live evidence incomplete |
| Resource impact | Record bounded CPU, memory, storage, and container-health observations over the soak. | Not yet measured for the candidate |
| Persistence and rollback | Rehearse SQLite restore and rollback in isolated canary; preserve production state. | Not yet verified for the candidate |
| Security and privacy | Unauthenticated clients receive no telemetry; logs and reports contain no secrets or unnecessary private data. | Repository controls are tested; deployed review remains open |

The 30-minute canary window must use one immutable candidate and a connected
disposable test client. Missing, stale, contradictory, or out-of-window
evidence fails closed. A point-in-time browser observation, image publication,
or readiness-only soak does not pass these gates. Production must not be
promoted until the pre-promotion acceptance report passes and rollback has been
rehearsed; post-promotion acceptance is a separate required phase.

The 2026-10-15 readiness-only probe completed 30 consecutive passing samples
at 60-second intervals, each reporting revision
`6dd53022523766a5371628dfe158286072494bf4`. This confirms repeated readiness
and revision reporting only; it does not establish live-event freshness,
session reconnect or snapshot recovery, resource impact, Redis/SQLite recovery,
rollback, or deployed security acceptance.

A separate 2026-10-15 canary check found stale session presentation after an
operator-initiated test-session disconnect: RouterOS reported zero matching
active sessions, while the already-open canary dashboard continued to show its
last-known connected snapshot and delayed status. This is a failed freshness
observation, not a measured latency value; the cause, automatic client
reconnect, and snapshot recovery remain unverified.

## Collection

Use the read-only collectors and private RouterOS prerequisites documented in
[`ROUTEROS_ACCEPTANCE.md`](ROUTEROS_ACCEPTANCE.md). Do not put credentials,
cookies, private origins, router exports, client profiles, IP addresses, raw
logs, or deployment measurements in GitHub issues, pull requests, public
artifacts, or this file.
