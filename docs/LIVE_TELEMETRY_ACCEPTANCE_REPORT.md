# Live telemetry acceptance status

Status: **PR #733 artifact published; candidate-specific live acceptance is
incomplete; production promotion remains gated.**

## Public artifact evidence

PR [#733](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/733)
(`c2758655bec686ad377853b2e600ccb86be3100b`) is the latest published runtime
candidate. Publisher run
[#38686520022](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/38686520022)
completed successfully with source/security checks, compilation, tests,
ARM64/AMD64 builds, detached provenance and SPDX SBOM attestation verification,
stable-manifest read-back, and published-runtime smoke tests. PR #734 was
test-only and did not change the published runtime source.

| Platform | Immutable tag | Registry digest |
| --- | --- | --- |
| RouterOS ARM64 | `sha-c2758655bec686ad377853b2e600ccb86be3100b-arm64` | `sha256:c1db79a633b0679558cef6fec7c8239bde92103a061b29b09f8ac7931f681fc6` |
| CHR/x86 AMD64 (evaluation) | `sha-c2758655bec686ad377853b2e600ccb86be3100b-amd64` | `sha256:04ae2ff3c9606d13d0247834e4e90b4198ceedf60ed5a0ddacc86a4d7c3a7fa1` |

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
| Candidate identity and readiness | Canary reports the exact immutable candidate and remains healthy for the agreed window. | Not verified for `c2758655`; no candidate-matched canary deployment or readiness window is recorded |
| Session event latency | Connect/disconnect visible in the open dashboard within 1 second. | Not measured for `c2758655`; no active test session was available during the latest read-only acceptance check, so event latency and reconnect remain unmeasured |
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

The release evaluator also requires an operator-attested, redacted certificate
lifecycle record bound to the canary image tag and digest. Its schema and
collection CLI input are documented in `ROUTEROS_ACCEPTANCE.md`; this repository
gate does not independently prove live RouterOS actions or change the
candidate-specific acceptance status above.
