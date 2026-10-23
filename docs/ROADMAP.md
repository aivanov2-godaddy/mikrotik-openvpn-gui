# Public roadmap

The goal is a polished, reliable, and secure self-hosted OpenVPN management GUI
for MikroTik RouterOS. The product is single-project/single-router; **multi-
tenant architecture is explicitly out of scope**.

This public roadmap tracks merged product work and a redacted summary of
remaining acceptance gates. It contains no router addresses or names,
user/session data, private origins, credentials, or raw operational logs.
Detailed operational records remain operator-controlled.

## Current project snapshot

Formal release **v2.7.0** remains the latest numbered release. PR #778 is the
latest published runtime, but it has not been staged on RouterOS. PR #776
(`c4b4b76793b2454e81362867d8654962627de6fa`) is the latest recorded canary
candidate and ensures logout revokes the session before the audit write, so an
audit failure cannot leave the session active. Main CI and image publication
passed for both; immutable digests and provenance are recorded in
[`RELEASES.md`](RELEASES.md). On 2026-10-23, the manual canary updater was
invoked for #776. The latest recorded RouterOS read-back confirmed its exact
tag and healthy startup, but the updater is no longer active and no completed
30-minute sample record was verified. The readiness gate is not passed. A later
dashboard observation showed a connected-user change without a manual refresh,
but exact latency was not timed. A canary sign-out was rejected by the origin
check and did not revoke the session; investigation remains open without
relaxing CSRF protection. Production remained on its prior immutable image in
the latest recorded checkpoint. No candidate-specific canary acceptance or
production promotion is claimed here.

The next formal release remains gated on candidate-specific canary acceptance
and the security review below. Do not create or publish v2.8.0 until the gates
pass.

## Issue status

| Status | Issues | Scope |
| --- | --- | --- |
| Complete | [#188](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/188), [#189](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/189), [#190](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/190), [#191](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/191), [#192](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/192) | Dashboard command center, task-grouped/mobile navigation, scannable Users/Connections, live controls, accessibility and visual regression |
| Complete | [#193](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/193), [#195](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/195), [#204](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/204) | Read-only diagnostics, correlated timeline, safe support bundles |
| Complete | [#196](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/196), [#197](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/197), [#198](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/198) | Redis recovery, SQLite/WAL fault coverage, telemetry SLO and recovery observability |
| Complete | [#201](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/201), [#202](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/202), [#203](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/203) | RouterOS least-privilege diagnostics, mutation safety, SBOM/provenance and compatibility policy |
| Closed in GitHub — implementation; device/certificate acceptance remains | [#194](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/194) | PR #676 adds explicit active-session termination before deleting a VPN user, with mocked ordering/failure tests. PR #702 adds a collapsed, read-only CRL configuration observation to Device Profiles without restoring the removed overview alert. PR #705 hardens cleanup of temporary RouterOS profile-export artifacts. PR #707 gates retirement on testing the replacement identity; PR #718 adds fail-closed checkpoint-failure coverage; PR #722 rejects stale, malformed, missing-expiry, and wrong-CA CRL snapshots. PR #730 requires both the stored RouterOS certificate ID and normalized fingerprint to match for a read-only inventory match. PR #737 adds a candidate-bound, operator-attested certificate-lifecycle evidence gate; its merge does not itself prove a successful live lifecycle test. The GitHub issue is closed, but candidate/device-backed CRL freshness, staged renewal and retirement, fresh-connect rejection, active-session behavior, read-back, and canary rollback evidence remain release gates tracked by #205. Profile recovery issues a new identity rather than re-downloading a retained private key. |
| Complete — acceptance tooling; live gates remain | [#199](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/199) | Closed by PR #709. The bounded read-only collector and SQLite restore verifier are implemented. Candidate-matched live soak, deployment, and rollback evidence remain release gates tracked by #205 (device/certificate acceptance) and #200 (security assurance); closing this implementation issue does not claim device acceptance. |
| Open — security assurance | [#200](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/200) | PR #778 is merged and published as the latest mainline runtime; its ARM64 digest is recorded in RELEASES.md, but it has not been staged on RouterOS. The latest recorded canary is PR #776 and reported healthy startup; the persisted pending-candidate record did not match that image, so the candidate-matched 30-minute readiness gate is not passed. A connected-user change appeared without manual refresh, but event latency and traffic freshness were not measured. Canary sign-out was rejected by the origin check; keep CSRF/origin protections fail-closed. Production remains on its prior image in the latest recorded checkpoint. Still required: stage and assess the current candidate; collect candidate-bound readiness/resource data; measure telemetry latency/freshness; verify API reconnect/snapshot recovery, event/counter integrity, Binary API/REST parity, deployed Redis/SQLite recovery, and rollback; complete physical RouterOS permission/credential-memory/log review, the owner risk decision, and independent scoped ASVS review. See SECURITY_ASSURANCE.md and LIVE_TELEMETRY_ACCEPTANCE_REPORT.md. |
| Open — tracking epic | [#205](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/205) | Close only after remaining device/certificate acceptance (tracked here despite #194's GitHub closure), #200 security review, and candidate-specific live acceptance gates pass; include the #199 collector/restore evidence in the candidate report. |

PR #776 merged to main on 2026-10-23 and adds a regression-tested logout
ordering fix: revoke the session before writing the audit event. PR #778
followed with redacted origin-rejection diagnostics and Engine.IO handshake
SID binding; its published image is not staged on RouterOS. Neither merge
closes the remaining deployed-security and device-acceptance gates in #200
and #205.

The latest published runtime is PR #778's immutable ARM64 image; it has not
been staged. The latest recorded canary is PR #776. Its read-back reported
the exact tag and healthy startup, but the updater is no longer active and no
completed 30-minute sample record was verified. Live telemetry, recovery,
deployed-security, and rollback gates remain open; canary logout was rejected
by the origin check and needs diagnosis. Production remains unchanged in the
latest recorded checkpoint. See the
[candidate report](LIVE_TELEMETRY_ACCEPTANCE_REPORT.md).

PR #730's identity guard, PR #740's session-polling hardening, PR #741's
RouterOS error redaction, PR #745's preservation of sessions when initial
interface counters are incomplete, PR #751's session-expiry/WAL-startup
hardening, PR #754's duplicate-Origin rejection, and PR #755's session-bound
live telemetry revocation are included in the latest published candidate.
PR #737 adds a candidate-bound acceptance evidence gate. These merges and their
publication do not prove the pending device-backed live acceptance criteria.

## Acceptance principles

- RouterOS remains the source of truth; live dashboard updates must not require
  a page refresh or silently pause streaming.
- Canary evidence must match one immutable candidate and an explicit
  observation window. Missing or stale measurements fail closed.
- Promotion is gated on measured session-event latency, traffic freshness,
  reconnect and snapshot recovery, event/counter integrity, Redis delivery,
  resource impact, persistence/restore, rollback, and security checks.
- Production is not changed as part of public CI. High-impact router changes
  require an explicit, reviewed maintenance procedure.
- Credentials, private keys, client profiles, router exports, hostnames,
  addresses, user/session data, deployment assignments, and live measurements
  stay out of public issues, pull requests, and repository documents.
- No multi-tenancy work is planned.

For implementation details, see the linked issues and
[`SECURITY_ASSURANCE.md`](SECURITY_ASSURANCE.md). For the current public artifact
record and redacted procedure, see [`RELEASES.md`](RELEASES.md) and
[`ROUTEROS_ACCEPTANCE.md`](ROUTEROS_ACCEPTANCE.md). The acceptance report
contains artifact evidence and redacted current gate status:
[`LIVE_TELEMETRY_ACCEPTANCE_REPORT.md`](LIVE_TELEMETRY_ACCEPTANCE_REPORT.md).
