# Live telemetry acceptance status

Status: **PR #772 artifact staged on the isolated canary and reported healthy;
candidate-specific live acceptance is incomplete; production promotion remains
gated.**

## Public artifact evidence

PR [#772](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/772)
(`624bfbf032396b3b2b21cab1a659985b6d580f79`) is the latest published runtime
candidate. It applies a fail-closed process core-dump limit before application
and server startup. Main CI run
[#39242524458](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/39242524458)
and publisher run
[#39242524446](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/39242524446)
completed successfully. The publisher verified detached provenance and SPDX
SBOM attestations, built and smoke-tested ARM64/AMD64 images, and read back the
stable manifest. This is repository and artifact evidence; it does not prove
the RouterOS host's core-dump collector policy or hardware acceptance.

| Platform | Immutable tag | Registry digest |
| --- | --- | --- |
| RouterOS ARM64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-624bfbf032396b3b2b21cab1a659985b6d580f79-arm64` | `sha256:b341f063e405283ea1647670073665375aa3213300afd3b2b4076e7039377fbd` |
| AMD64 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-624bfbf032396b3b2b21cab1a659985b6d580f79-amd64` | `sha256:2cf79dfecf4231f8b33c9e675d64982adc392197ab428dbccde803d2e7bd1721` |

On 2026-10-19, the isolated canary was stopped, pointed at the #772 ARM64
immutable tag, updated, and restarted. RouterOS read-back reports the expected
`remote-image` and `tag`, ARM64 architecture, `H - HEALTHY`, and a good
container health check. This is a point-in-time candidate readiness result,
not a sustained soak or complete live acceptance. RouterOS read-back confirms
the configured tag, not a local OCI digest; registry digests above are bound to
their tags by the verified publisher workflow. The post-start RouterOS check
found zero active VPN sessions, so session-event latency and traffic freshness
could not be measured. Production remained healthy on its prior image; no
production deployment was performed for PR #772 and promotion remains gated.
The canary stop/update/start did not change RouterOS VPN policy or touch the
production or Redis containers.

Public deployment detail here is limited to the redacted canary-stage status
above. This file contains no router identity, hostnames, addresses, resource
readings, logs, or VPN session identities/details. Detailed deployment and
acceptance evidence belongs in operator-controlled storage. The table below is
a gate checklist, not a report of private measurements.

## Candidate acceptance gates

| Gate | Required result | Public status |
| --- | --- | --- |
| Candidate identity and readiness | Canary reports the exact immutable candidate and remains healthy for the agreed window. | #772 ARM64 tag read back and canary reported healthy at a point in time; sustained window incomplete |
| Session event latency | Connect/disconnect visible in the open dashboard within 1 second. | Not measured for #772; post-start RouterOS check showed zero active sessions |
| Traffic freshness | Samples are no older than 2 seconds; no manual refresh is needed. | Not measured for #772; no active test client was present after the update |
| Reconnect and snapshot recovery | RouterOS API interruption recovers automatically; a full snapshot follows reconnect. | Not measured for #772 |
| Event and counter integrity | Counter resets do not create incorrect rates; detect missing, duplicated, or out-of-order events. | Not measured for #772 |
| Binary API and REST parity | Compare equivalent read-only snapshots and document any expected differences. | Not measured for #772 |
| Redis/outbox | Exercise unavailable/restarting Redis, retries, duplicate delivery, queue drain, and recovery. | Repository tests exist; candidate-specific live evidence not collected |
| Resource impact | Record bounded CPU, memory, storage, and container-health observations over the soak. | Not measured for #772 |
| Persistence and rollback | Rehearse SQLite restore and rollback in isolated canary; preserve production state. | Not verified for #772 |
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
