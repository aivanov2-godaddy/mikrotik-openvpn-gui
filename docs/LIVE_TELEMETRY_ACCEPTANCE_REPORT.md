# Live telemetry acceptance status

Status: **PR #761 artifact published; candidate-specific live acceptance is
incomplete; production promotion remains gated.**

## Public artifact evidence

PR [#761](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/761)
(`e8af615c42145b9b6a1ea44bee9b217ffc5dc4be`) is the latest published runtime
candidate. In addition to the session-bound live-telemetry controls, it rejects
Engine.IO transport setup unless the dashboard session is active, before
allocating transport state and without refreshing the idle deadline. Publisher
run
[#39168925504](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/39168925504)
completed source/security checks, rendered browser/accessibility checks,
ARM64/AMD64 image publication and runtime smoke, detached provenance and SPDX
SBOM attestation verification, and stable-manifest read-back.

| Platform | Immutable tag | Registry digest |
| --- | --- | --- |
| RouterOS ARM64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-e8af615c42145b9b6a1ea44bee9b217ffc5dc4be-arm64` | `sha256:0d58f3b2c24281d82064b9d95da9d31bb56073c0daa0f116bd7c3e2d8b90d32b` |
| CHR/x86 AMD64 (evaluation) | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-e8af615c42145b9b6a1ea44bee9b217ffc5dc4be-amd64` | `sha256:e949bfa43ed1f0ac989cc3a32da95da26a19e5b028fe14761fbca061c4cc305c` |

On 2026-10-19, RouterOS read-back confirmed the exact PR #761 ARM64 immutable
tag on the isolated canary and reported the container healthy after start. The
production container was left on its prior image. This is point-in-time
deployment/startup evidence only: the 30-minute acceptance window, authenticated
dashboard readiness, live-session delivery, and candidate-specific recovery
checks have not passed. RouterOS read-back confirms the configured tag, not a
local OCI digest; the registry digest above is bound to the tag by the verified
publisher workflow. The readiness-only probe recorded below belongs to an
earlier candidate and does not transfer to this image.

Public deployment detail here is limited to the redacted canary-stage status
above. This file contains no router identity, hostnames, addresses, resource
readings, logs, or VPN session observations. Detailed deployment and acceptance
evidence belongs in operator-controlled storage. The table below is a gate
checklist, not a report of private measurements.

## Candidate acceptance gates

| Gate | Required result | Public status |
| --- | --- | --- |
| Candidate identity and readiness | Canary reports the exact immutable candidate and remains healthy for the agreed window. | Partial: exact ARM64 tag read-back and healthy status were observed after start on 2026-10-19; the 30-minute window and authenticated application readiness remain unverified |
| Session event latency | Connect/disconnect visible in the open dashboard within 1 second. | Not measured for `e8af615c`; no authenticated, candidate-matched live-session observation is recorded, so event latency and reconnect remain unmeasured |
| Traffic freshness | Samples are no older than 2 seconds; no manual refresh is needed. | Not yet measured for `e8af615c` |
| Reconnect and snapshot recovery | RouterOS API interruption recovers automatically; a full snapshot follows reconnect. | Not yet measured for `e8af615c` |
| Event and counter integrity | Counter resets do not create incorrect rates; detect missing, duplicated, or out-of-order events. | Not yet measured for `e8af615c` |
| Binary API and REST parity | Compare equivalent read-only snapshots and document any expected differences. | Not yet measured for `e8af615c` |
| Redis/outbox | Exercise unavailable/restarting Redis, retries, duplicate delivery, queue drain, and recovery. | Repository tests exist; candidate-specific live evidence incomplete |
| Resource impact | Record bounded CPU, memory, storage, and container-health observations over the soak. | Not yet measured for `e8af615c` |
| Persistence and rollback | Rehearse SQLite restore and rollback in isolated canary; preserve production state. | Not yet verified for `e8af615c` |
| Security and privacy | Unauthenticated clients receive no telemetry; logs and reports contain no secrets or unnecessary private data. | Repository controls are tested; deployed review remains open |

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
logs, or deployment measurements in GitHub issues, pull requests, public
artifacts, or this file.

The release evaluator also requires an operator-attested, redacted certificate
lifecycle record bound to the canary image tag and digest. Its schema and
collection CLI input are documented in `ROUTEROS_ACCEPTANCE.md`; this repository
gate does not independently prove live RouterOS actions or change the
candidate-specific acceptance status above.
