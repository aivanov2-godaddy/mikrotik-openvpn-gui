# Public roadmap

The goal is a polished, reliable, and secure self-hosted OpenVPN management GUI
for MikroTik RouterOS. The product is single-project/single-router; **multi-
tenant architecture is explicitly out of scope**.

This public roadmap tracks merged product work and a redacted summary of
remaining acceptance gates. It contains no router addresses or names,
user/session data, private origins, credentials, or raw operational logs.
Detailed operational records remain operator-controlled.

## Current project snapshot

Formal release **v2.7.0** remains the latest numbered release. PR #794
(`beba66c0f36231511ec1b9cc664f2be39a128750`) is the latest merged mainline
commit. PR #793 (`fbcbe96ff9fc56ffa5b0f750b8e72d59fbeeb164`) remains the latest
published image; its main CI and ARM64/AMD64 image publication, smoke tests, provenance and
SBOM verification, and stable-manifest publication passed; immutable tags and
digests are recorded in [`RELEASES.md`](RELEASES.md). PR #793 bounds Engine.IO
polling client state and ASGI authorization waits and updates release-acceptance
runbook coverage. Publication did not stage or deploy the image on RouterOS.

The latest candidate-bound canary record remains PR #776; no passing
candidate-bound 30-minute observation is recorded. A read-only RouterOS
inventory at approximately 14:33 UTC on 2026-10-23 showed canary and production
configured with the same immutable ARM64 tag for source commit
`8c3a46df3a7e0e8b0dac9e5ed7a979aa06e855f7` (PR #788), not the latest published
PR #793 tag. This was configured-tag read-back only; no local OCI digest or
candidate readiness was verified. A separate read-only RouterOS PPP Active
Connections check at approximately 14:50 UTC showed one active VPN session; a
later refresh at approximately 15:02 UTC showed none. The canary browser was
at its application sign-in page during that observation, so no dashboard event
latency, freshness, or reconnect evidence is established. These are dated
historical observations, not the current connection state. No router or
container changes were made during those snapshots.

Earlier qualitative observations of live changes without refresh are not
measured latency or freshness acceptance. Two bounded, read-only source reviews
against PR #791's commit found no confirmed authorization bypass in their
reviewed paths. PR #794 is now merged as
`beba66c0f36231511ec1b9cc664f2be39a128750`; it rejects missing, duplicate, or
foreign-Origin WebSocket handshakes before Engine.IO allocation, retains
missing-Origin compatibility only for session-bound HTTP polling GET, and adds
regression coverage for reconnect and the natural 15-second role-cache
deadline. It also replaces admin-session cookie identifiers in the session
inventory with non-authenticating revocation references. These are source/code
changes only: PR #794 has not yet been published or staged on RouterOS. The
assurance matrix remains PARTIAL pending deployed proxy verification and
complete control review. Candidate-specific live acceptance, physical-host
credential-memory/log review, and the named owner risk decision remain open.
No production promotion is claimed here.

Open issue [#785](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/785)
tracks updater reconciliation and safe canary-only staging. PR #791 adds
diagnostics to the checked-in example, but the installed updater's source and
production-promotion behavior remain unreconciled; do not rerun it until that
discrepancy is resolved.

The next formal release remains gated on candidate-specific canary acceptance
and the security review below. Do not create or publish v2.8.0 until the gates
pass.

## Issue status

| Status | Issues | Scope |
| --- | --- | --- |
| Closed in GitHub — core implementation; follow-up UX checks remain | [#188](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/188), [#189](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/189), [#190](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/190), [#191](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/191), [#192](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/192) | Follow-ups identified by source audit: role-specific dashboard-action visibility and legacy-hash navigation regression tests; clarify whether Connections needs bulk selection; expose sample age/reconnecting state; finish documented human task study and assistive-technology review. Freeze/Resume and graph range controls were conditional or not explicit in the issue criteria. |
| Closed in GitHub — core implementation; follow-up polish identified | [#193](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/193), [#195](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/195), [#204](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/204) | Connection Doctor and safe support bundles are implemented. Follow-ups: include certificate/profile context and destination links in Doctor results; expose Integration as a timeline type filter. Timeline remains explicitly bounded and incomplete. |
| Complete | [#196](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/196), [#197](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/197), [#198](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/198) | Redis recovery, SQLite/WAL fault coverage, telemetry SLO and recovery observability |
| Complete | [#201](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/201), [#202](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/202), [#203](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/203) | RouterOS least-privilege diagnostics, mutation safety, SBOM/provenance and compatibility policy |
| Closed in GitHub — implementation; device/certificate acceptance remains | [#194](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/194) | PR #676 adds explicit active-session termination before deleting a VPN user, with mocked ordering/failure tests. PR #702 adds a collapsed, read-only CRL configuration observation to Device Profiles without restoring the removed overview alert. PR #705 hardens cleanup of temporary RouterOS profile-export artifacts. PR #707 gates retirement on testing the replacement identity; PR #718 adds fail-closed checkpoint-failure coverage; PR #722 rejects stale, malformed, missing-expiry, and wrong-CA CRL snapshots. PR #730 requires both the stored RouterOS certificate ID and normalized fingerprint to match for a read-only inventory match. PR #737 adds a candidate-bound, operator-attested certificate-lifecycle evidence gate; its merge does not itself prove a successful live lifecycle test. The GitHub issue is closed, but candidate/device-backed CRL freshness, staged renewal and retirement, fresh-connect rejection, active-session behavior, read-back, and canary rollback evidence remain release gates tracked by #205. Profile recovery issues a new identity rather than re-downloading a retained private key. |
| Complete — acceptance tooling; live gates remain | [#199](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/199) | Closed by PR #709. The bounded read-only collector and SQLite restore verifier are implemented. Candidate-matched live soak, deployment, and rollback evidence remain release gates tracked by #205 (device/certificate acceptance) and #200 (security assurance); closing this implementation issue does not claim device acceptance. |
| Open — security assurance | [#200](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/200) | PR #793 is the latest published image; its ARM64/AMD64 digests are recorded in RELEASES.md, but it has not been staged on RouterOS. PR #794 is merged to source but has not been published or staged. It adds fail-closed WebSocket Origin checks, keeps session-bound HTTP polling GET compatibility, uses non-authenticating admin-session revocation references, and tests initial/reconnect boundaries plus the natural role-cache deadline. V4.4.2 remains PARTIAL pending deployed proxy verification and full control review. The 15-second application role cache is not a verified RouterOS-side revocation bound. Still required: complete independent scoped ASVS assessment; candidate-matched authenticated live-session, revocation/reconnect, freshness and soak evidence; candidate-bound readiness/resource data; event/counter integrity, Binary API/REST parity, deployed Redis/SQLite recovery and rollback; physical RouterOS permission and credential-memory/log/dump review; and the named owner risk decision. See SECURITY_ASSURANCE.md and LIVE_TELEMETRY_ACCEPTANCE_REPORT.md. |
| Open — tracking epic | [#205](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/205) | Close only after remaining device/certificate acceptance (tracked here despite #194's GitHub closure), #200 security review, and candidate-specific live acceptance gates pass; include the #199 collector/restore evidence in the candidate report. |

PR #776 added a regression-tested logout ordering fix: revoke the session
before writing the audit event. PR #778 added redacted origin-rejection
diagnostics and Engine.IO handshake SID binding. PR #791 added precise
step-level failure markers to the example RouterOS updater; PR #793 is the
latest published and attested mainline image. Neither publication staged an
image or updater on RouterOS. These merges do not close the remaining
deployed-security and device-acceptance gates in #200 and #205.
PR #794 then tightened WebSocket Origin and admin-session revocation-reference
handling. These source changes have not yet been published or deployed. No
publication staged an image or updater on RouterOS. These merges do not close
the remaining deployed-security and device-acceptance gates in #200 and #205.

The ASVS matrix classifies V8.3.2 as a known product gap. The application role
cache is 15 seconds, but the current [MikroTik REST API manual](https://manual.mikrotik.com/docs/developer-guides/rest-api/)
also says group-policy edits take effect when the REST API login is renewed,
up to 10 minutes later. That REST behavior is not verified on deployed
RouterOS 7.24.5, so 15 seconds must not be presented as the full device-backed
revocation bound. The natural-deadline regression proves only the bounded
application cache behavior; it is not an immediate-revocation mitigation. No
immediate RouterOS change notification or alert-and-revert control is present.
Canary acceptance must separately measure a user-group reassignment and, in a
disposable test setup, a group-policy edit without changing the production
administrator's group or policy.

The latest candidate-bound canary read-back remains PR #776, and it did not
establish a candidate-bound 30-minute acceptance window. The later #788
configured-tag inventory above is not a candidate-bound acceptance result.
No newer candidate-to-router digest mapping or formal production promotion is
claimed. Live telemetry, recovery, deployed-security, and rollback gates remain open. See the
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
