# Live telemetry acceptance status

Status: **PR #776 is published and attested. On 2026-10-23 the canary read back
the exact immutable tag and RouterOS reported it healthy after start; the
30-minute readiness soak is in progress.
Candidate-specific live acceptance is incomplete; production promotion remains
gated.**

## Public artifact evidence

PR [#776](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/776)
(`c4b4b76793b2454e81362867d8654962627de6fa`) is the latest published runtime
candidate. Main CI run
[#39867875857](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/39867875857)
and publisher run
[#39867875877](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/39867875877)
completed successfully. The publisher built and smoke-tested ARM64/AMD64
images, verified their provenance and SPDX SBOM attestations, and read back
the stable manifest. The #776 change revokes the server-side session before
the logout audit write. This repository/artifact evidence does not prove
RouterOS hardware acceptance.

| Platform | Immutable tag | Registry digest |
| --- | --- | --- |
| RouterOS ARM64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-c4b4b76793b2454e81362867d8654962627de6fa-arm64` | `sha256:8b5dfa0d2c4fae542e0c560576a91432812823ebe55ecc6bcad7bbfa7c0e922e` |
| AMD64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-c4b4b76793b2454e81362867d8654962627de6fa-amd64` | `sha256:fad2b337196e5fe09d2040acb3353e4acc5fe2d894bc49866a0470369c75d4f9` |

On 2026-10-23, the manual RouterOS updater was invoked for the #776 ARM64
immutable tag. Read-back confirmed that exact tag and RouterOS marked the
container healthy after start. The 30-minute readiness soak is still in
progress. The authenticated canary dashboard loaded and showed zero active VPN
sessions at that observation, so live session-event and traffic-freshness
measurements could not be taken. The registry digests above are bound to their
tags by the verified publisher workflow; RouterOS reports the configured tag,
not a local OCI digest. Production remains on its prior image and has not been
changed. No live acceptance or production promotion is claimed.

Public deployment detail here is limited to the redacted canary-stage status
above. This file contains no router identity, hostnames, addresses, resource
readings, logs, or VPN session identities/details. Detailed deployment and
acceptance evidence belongs in operator-controlled storage. The table below is
a gate checklist, not a report of private measurements.

## Candidate acceptance gates

| Gate | Required result | Public status |
| --- | --- | --- |
| Candidate identity and readiness | Canary reports the exact immutable candidate and remains healthy for the agreed window. | Exact #776 ARM64 tag read back and RouterOS reported healthy after start; 30-minute soak in progress |
| Session event latency | Connect/disconnect visible in the open dashboard within 1 second. | Not measured for #776 |
| Traffic freshness | Samples are no older than 2 seconds; no manual refresh is needed. | Not measured for #776 |
| Reconnect and snapshot recovery | RouterOS API interruption recovers automatically; a full snapshot follows reconnect. | Not measured for #776 |
| Event and counter integrity | Counter resets do not create incorrect rates; detect missing, duplicated, or out-of-order events. | Not measured for #776 |
| Binary API and REST parity | Compare equivalent read-only snapshots and document any expected differences. | Not measured for #776 |
| Redis/outbox | Exercise unavailable/restarting Redis, retries, duplicate delivery, queue drain, and recovery. | Repository tests exist; candidate-specific live evidence not collected |
| Resource impact | Record bounded CPU, memory, storage, and container-health observations over the soak. | Not measured for #776 |
| Persistence and rollback | Rehearse SQLite restore and rollback in isolated canary; preserve production state. | Not verified for #776 |
| Security and privacy | Unauthenticated clients receive no telemetry; logs and reports contain no secrets or unnecessary private data. | Repository controls are tested; candidate-specific deployed review remains open |

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
