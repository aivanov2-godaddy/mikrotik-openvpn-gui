# Public roadmap

The goal is a polished, reliable, and secure self-hosted OpenVPN management GUI
for MikroTik RouterOS. The product is single-project/single-router; **multi-
tenant architecture is explicitly out of scope**.

This public roadmap tracks merged product work and a redacted summary of
remaining acceptance gates. It contains no router addresses or names,
user/session data, private origins, credentials, or raw operational logs.
Detailed operational records remain operator-controlled.

## Current project snapshot

Formal release **v2.7.0** remains the latest numbered release. PR #846
(`e7ff31b222df2229186c6c745b0917084599e4b3`) is the latest published runtime
image source. Main CI run 40226555414, CodeQL run 40226031831, and publisher
run 40226555415 passed. The stable manifest and digest-bound provenance/SBOM
were verified for both architecture images. Exact tags and digests are in
[`RELEASES.md`](RELEASES.md). This is a
published candidate, not a numbered release or a RouterOS acceptance claim.
PR #830 is documentation-only and adds an offline comparison risk flag; it
changes no running application or RouterOS state.

An earlier authenticated dashboard observation showed the VPN service online
with `Live · Socket.IO`; it did not identify a candidate image or measure
candidate-bound latency/freshness. The latest read-only WinBox observation on
2026-10-25 showed the canary healthy, architecture `arm64`, and OCI revision
`79816625e493f9581e7389b95760403ac6c9a327` (PR #806). The full configured tag
and digest were not read back. The WinBox Stats view showed 0.7% CPU, 60.9 MiB
memory, and 0 B swap; this is not a soak. It supersedes an earlier inventory that reported
the canary stopped, but does not verify or accept the newer PR #846 image. A
partial read-only updater inventory found an unresolved numeric script
reference on a disabled scheduler; neither that target nor the complete
installed script source has been reconciled. No updater was run, and no router
configuration or production state was changed. Keep staging and promotion
gated on source/binding reconciliation, reviewed canary-only staging, deployed
security review, and candidate-bound live acceptance.

The last digest-bound canary read-back, on 2026-10-24, was PR #806—not the
newer published PR #846 image. That read-back confirmed the exact PR #806 ARM64
tag and healthy readiness. Sparse read-only samples over approximately nine
minutes showed 0.6–0.8% CPU and 38.6 MiB memory. A later WinBox observation on
2026-10-25 again showed the canary healthy with embedded revision
`79816625e493f9581e7389b95760403ac6c9a327`, but did not read the full
configured tag or digest. Its Stats view showed 0.7% CPU, 60.9 MiB memory, and
0 B swap. This supersedes the earlier stopped-state inventory but is not the
required 30-minute soak or sustained-resource result. The canary dashboard was
at its application sign-in form in the available browser view. Authenticated
event latency, traffic freshness, reconnect, snapshot recovery, session
authorization, and a candidate-specific rollback rehearsal remain unverified.
Production was not changed. These are point-in-time health observations, not
full acceptance or production promotion.

Earlier qualitative observations of live changes without refresh are not
measured latency or freshness acceptance. Two bounded, read-only source reviews
against PR #791's commit found no confirmed authorization bypass in their
reviewed paths. PR #798 and the later PR #803 candidate include the same-origin
polling protections; PR #803's publisher and artifact verification passed.
Manual canary staging is recorded above, but it does not establish live-event
latency or freshness.
The assurance matrix remains PARTIAL pending deployed proxy verification and
complete control review. Candidate-specific live acceptance, physical-host
credential-memory/log review, and the named owner risk decision remain open.
No production promotion is claimed here.

Open issue [#785](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/785)
tracks updater reconciliation and safe canary-only staging. PR #791 adds
step-level diagnostics and PR #797 verifies rollback in the checked-in
example. The installed updater still differs from reviewed source and was not
run. PR #806 was manually staged on canary and its exact embedded revision and
healthy readiness were read back. No #806 rollback rehearsal or 30-minute soak
has passed. The original updater error source remains unknown; authenticated
live acceptance remains open.

The next formal release remains gated on candidate-specific canary acceptance
and the security review below. Do not create or publish v2.8.0 until the gates
pass.

## Issue status

| Status | Issues | Scope |
| --- | --- | --- |
| Closed in GitHub — core implementation; follow-up UX checks remain | [#188](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/188), [#189](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/189), [#190](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/190), [#191](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/191), [#192](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/192) | Follow-ups identified by source audit: role-specific dashboard-action visibility and legacy-hash navigation regression tests; clarify whether Connections needs bulk selection; expose sample age/reconnecting state; finish documented human task study and assistive-technology review. Freeze/Resume and graph range controls were conditional or not explicit in the issue criteria. |
| Closed in GitHub — core implementation; follow-up polish identified | [#193](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/193), [#195](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/195), [#204](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/204) | Connection Doctor and safe support bundles are implemented. Follow-ups: include certificate/profile context and destination links in Doctor results; expose Integration as a timeline type filter. Timeline remains explicitly bounded and incomplete. |
| Closed in GitHub — runtime cadence fix merged; live SLO evidence remains | [#198](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/198) | PR #838 makes the runtime honor a one-second start-to-start interface-sample cadence and retains a five-second delay for API-error retries, with regression coverage. This fixes the implementation gap; the measured canary freshness/latency window remains open under #200. Redis recovery and SQLite/WAL fault coverage remain implemented. |
| Complete | [#201](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/201), [#202](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/202), [#203](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/203) | RouterOS least-privilege diagnostics, mutation safety, SBOM/provenance and compatibility policy |
| Closed in GitHub — implementation; device/certificate acceptance remains | [#194](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/194) | PR #676 adds explicit active-session termination before deleting a VPN user, with mocked ordering/failure tests. PR #702 adds a collapsed, read-only CRL configuration observation to Device Profiles without restoring the removed overview alert. PR #705 hardens cleanup of temporary RouterOS profile-export artifacts. PR #707 gates retirement on testing the replacement identity; PR #718 adds fail-closed checkpoint-failure coverage; PR #722 rejects stale, malformed, missing-expiry, and wrong-CA CRL snapshots. PR #730 requires both the stored RouterOS certificate ID and normalized fingerprint to match for a read-only inventory match. PR #737 adds a candidate-bound, operator-attested certificate-lifecycle evidence gate; its merge does not itself prove a successful live lifecycle test. The GitHub issue is closed, but candidate/device-backed CRL freshness, staged renewal and retirement, fresh-connect rejection, active-session behavior, read-back, and canary rollback evidence remain release gates tracked by #205. Profile recovery issues a new identity rather than re-downloading a retained private key. |
| Complete — acceptance tooling; live gates remain | [#199](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/199) | Closed by PR #709. The bounded read-only collector and SQLite restore verifier are implemented. Candidate-matched live soak, deployment, and rollback evidence remain release gates tracked by #205 (device/certificate acceptance) and #200 (security assurance); closing this implementation issue does not claim device acceptance. |
| Open — security assurance | [#200](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/200) | The latest recorded read-only WinBox observation showed healthy canary readiness and embedded PR #806 revision; its full image tag/digest was not read back. Sparse samples over approximately nine minutes showed 0.6–0.8% CPU and 38.6 MiB memory; a later Stats view showed 0.7% CPU and 60.9 MiB memory. Neither is a 30-minute soak. PR #846 is now published, but no candidate-bound RouterOS read-back or acceptance is established. GitHub CodeQL showed 0 open and 7 fixed alerts on 2026-10-25. PR #838 fixes the source cadence gap tracked by #198, PR #839 rejects query strings in webhook URLs, PR #842 fixes the telemetry replay cursor/epoch race, and PR #846 hardens session/audit failure handling; none is measured canary acceptance. Still required: independent scoped ASVS assessment; authenticated live-session, revocation/reconnect, freshness and soak evidence; candidate-bound resource data; event/counter integrity, Binary API/REST parity, deployed Redis/SQLite recovery; physical RouterOS permission and credential-memory/log/dump review; candidate-specific rollback rehearsal; and the named owner risk decision. Live streams use a one-second application role cache; ordinary requests retain 15 seconds. Neither interval is a verified RouterOS-side revocation bound. See SECURITY_ASSURANCE.md and LIVE_TELEMETRY_ACCEPTANCE_REPORT.md. |
| Open — updater reconciliation / safe staging | [#785](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/785) | PR #806's exact tag/digest was read back on 2026-10-24. A later WinBox observation showed the canary healthy with the embedded PR #806 revision, but the full configured tag/digest was not read back; the latest Stats view showed 0.7% CPU and 60.9 MiB memory. PR #846 is published but has no verified canary read-back. PR #830 adds a comparator flag for a missing rollback-restore verifier, but does not reconcile installed scripts or scheduler bindings. A read-only lookup resolved the disabled updater scheduler's previously opaque numeric target to an updater entry; installed source has not been fully reconciled against reviewed source. No updater was run; its original failure source remains unknown. Authenticated live acceptance remains open. |
| Open — tracking epic | [#205](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/205) | Close only after remaining device/certificate acceptance (tracked here despite #194's GitHub closure), #200 security review, and candidate-specific live acceptance gates pass; include the #199 collector/restore evidence in the candidate report. |

PR #776 added a regression-tested logout ordering fix: revoke the session
before writing the audit event. PR #778 added redacted origin-rejection
diagnostics and Engine.IO handshake SID binding. PR #791 and #797 improve the
checked-in example RouterOS updater; neither installs nor executes it. PR #794
added WebSocket Origin and admin-session revocation-reference hardening. PR
#798 adds evidence-gated originless polling and browser coverage; PR #846 is
the latest published runtime source. Its main CI, CodeQL, and publisher passed, but no
candidate-specific acceptance is recorded and it does not satisfy the live
acceptance gates. PR #830 improves offline updater comparison only.
The last recorded canary stage is PR #806. Manual canary staging and point-sample
readiness evidence do not close the deployed-security and device-acceptance
gates in #200 and #205.

The ASVS matrix classifies V8.3.2 as a known product gap. Active live streams
now use a one-second application role-cache interval; ordinary authenticated
requests retain the 15-second interval. The current [MikroTik REST API manual](https://manual.mikrotik.com/docs/developer-guides/rest-api/)
also says group-policy edits take effect when the REST API login is renewed,
up to 10 minutes later. That REST behavior is not verified on deployed
RouterOS 7.24.5, so neither application interval is the full device-backed
revocation bound. The natural-deadline regression proves only the bounded
application cache behavior; it is not an immediate-revocation mitigation. The
one-second value is a freshness threshold, not a polling timer; SSE checks on
its two-second loop, plus RouterOS REST latency. A process-wide semaphore caps
live role refreshes at four concurrent checks and denies stale live requests
when saturated. No immediate RouterOS change notification or alert-and-revert control is present.
Canary acceptance must separately measure a user-group reassignment and, in a
disposable test setup, a group-policy edit without changing the production
administrator's group or policy.

The last digest-bound canary read-back is PR #806; a later WinBox view showed
the canary healthy with the PR #806 embedded revision but did not confirm the
configured tag or digest. Only point samples are available, and neither the
30-minute soak nor a rollback rehearsal has passed for this candidate. No live
telemetry/security acceptance is claimed. No production promotion is recorded. See the
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
