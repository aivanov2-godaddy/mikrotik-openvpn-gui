# Live telemetry acceptance status

Status: **PR #755 artifact published; candidate-specific live acceptance is
incomplete; production promotion remains gated.**

## Public artifact evidence

PR [#755](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/755)
(`f16fe17cc2251939bcdfc10eeb26e8c0be85e9c1`) is the latest published runtime
candidate. It stops live telemetry after its source dashboard session expires
or is revoked. Publisher run
[#38819845718](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/38819845718)
completed successfully with source/security checks, rendered browser and
accessibility checks, ARM64/AMD64 builds, runtime smoke, detached provenance
and SPDX SBOM attestation verification, and stable-manifest read-back.

| Platform | Immutable tag | Registry digest |
| --- | --- | --- |
| RouterOS ARM64 | `sha-f16fe17cc2251939bcdfc10eeb26e8c0be85e9c1-arm64` | `sha256:1ad03a1f383c6e25ce29548413c8b98f3938a202590934210d16ff628efb893e` |
| CHR/x86 AMD64 (evaluation) | `sha-f16fe17cc2251939bcdfc10eeb26e8c0be85e9c1-amd64` | `sha256:4437eec31d67c781641bb9eea2cdb2c823a35eace245be8e6cf03e5368ef8c18` |

These artifacts have **not** been verified as deployed to the RouterOS canary
or production container. The readiness-only probe recorded below belongs to
the earlier `6dd53022523766a5371628dfe158286072494bf4` candidate and does not
transfer to this image.

These are public build and registry facts only. This file contains no RouterOS
deployment assignments, hostnames, addresses, resource readings, logs, or VPN
session observations. Deployment-specific acceptance evidence belongs in
operator-controlled storage. The status below is a gate checklist, not a report
of private measurements.

## Candidate acceptance gates

| Gate | Required result | Public status |
| --- | --- | --- |
| Candidate identity and readiness | Canary reports the exact immutable candidate and remains healthy for the agreed window. | Not verified for `f16fe17c`; no candidate-matched canary deployment or readiness window is recorded |
| Session event latency | Connect/disconnect visible in the open dashboard within 1 second. | Not measured for `f16fe17c`; no authenticated, candidate-matched live-session observation is recorded, so event latency and reconnect remain unmeasured |
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
