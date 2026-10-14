# Public roadmap

The goal is a polished, reliable, and secure self-hosted OpenVPN management GUI
for MikroTik RouterOS. The product is single-project/single-router; **multi-
tenant architecture is explicitly out of scope**.

This public roadmap tracks merged product work and remaining acceptance gates.
It contains no router deployment assignments, live measurements, user/session
data, private origins, or raw operational logs. Those belong in
operator-controlled records.

## Current project snapshot

Formal release **v2.7.0** remains the latest numbered release. PR
[#692](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/692)
(`8f68314bb54cc008edc02bf26e00cdaaa48284f3`) is the latest published runtime
candidate. Its publisher run
[#38468254627](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/38468254627)
passed; immutable image and provenance metadata are recorded in
[`RELEASES.md`](RELEASES.md). Publication does not prove RouterOS deployment or
acceptance. No production promotion is claimed here.

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
| Open — device/certificate acceptance | [#194](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/194) | PR #676 adds explicit active-session termination before deleting a VPN user, with mocked ordering/failure tests. Candidate/device-backed staged renewal and retirement, CRL/fresh-connect rejection, active-session, read-back, and canary rollback evidence are still outstanding. |
| Open — acceptance evidence | [#199](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/199) | The read-only collector now selects legacy RouterOS `status` or RouterOS 7.20+ lifecycle flags using the reported version, shared with the deployment normalizer. Run the candidate-matched canary acceptance window and rollback/restore checks; live measurements and deployment-specific evidence remain private and incomplete. |
| Open — security assurance | [#200](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/200) | Current main includes the fail-closed RouterOS role-lookup change from #692 and the redacted acceptance-tool safeguards in #698. The #698 merge validation passed the full local suite (640 tests, 1 skipped) and hosted checks. Current focused review passed 272 application/session/ASGI/polling tests plus 20 telemetry-runtime/supervisor tests; it verifies the documented 15-second role-cache bound. Repository evidence is not live acceptance. Still required: deployed proxy/session checks, physical-router revocation-latency validation, exhaustive resource-state/field-level review, and independent requirement-by-requirement assurance. |
| Open — tracking epic | [#205](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/205) | Close after #194, #199, and #200 meet their acceptance criteria. |

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
contains gates only, not deployment results:
[`LIVE_TELEMETRY_ACCEPTANCE_REPORT.md`](LIVE_TELEMETRY_ACCEPTANCE_REPORT.md).
