# Live telemetry acceptance status

Status: **PR #702 artifact published; candidate-specific live acceptance is
incomplete; production promotion remains gated.**

## Public artifact evidence

PR [#702](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/702)
(`7c91a0f3425ca729cb6ffe12004c2a6e787ac97d`) is the latest published runtime
candidate. Publisher run
[#38519276211](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/38519276211)
completed successfully with source and rendered-browser verification,
ARM64/AMD64 builds, provenance and SPDX SBOM attestations, stable-manifest
publication, and published-runtime smoke tests.

| Platform | Immutable tag | Registry digest |
| --- | --- | --- |
| RouterOS ARM64 | `sha-7c91a0f3425ca729cb6ffe12004c2a6e787ac97d-arm64` | `sha256:4682a2eed339aec7e4d77173f017be8510f4ad06227dfd4e92846a2345e11595` |
| CHR/x86 AMD64 (evaluation) | `sha-7c91a0f3425ca729cb6ffe12004c2a6e787ac97d-amd64` | `sha256:23fd167259d2dab2acdd7dee6e14b6741811fc438591cee3571ccb0ba18d6082` |

These are public build and registry facts only. This file contains no RouterOS
deployment assignments, hostnames, addresses, resource readings, logs, or VPN
session observations. Deployment-specific acceptance evidence belongs in
operator-controlled storage. The status below is a gate checklist, not a report
of private measurements.

## Candidate acceptance gates

| Gate | Required result | Public status |
| --- | --- | --- |
| Candidate identity and readiness | Canary reports the exact immutable candidate and remains healthy for the agreed window. | Incomplete; verify privately |
| Session event latency | Connect/disconnect visible in the open dashboard within 1 second. | Not yet measured for the candidate |
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

## Collection

Use the read-only collectors and private RouterOS prerequisites documented in
[`ROUTEROS_ACCEPTANCE.md`](ROUTEROS_ACCEPTANCE.md). Do not put credentials,
cookies, private origins, router exports, client profiles, IP addresses, raw
logs, or deployment measurements in GitHub issues, pull requests, public
artifacts, or this file.
