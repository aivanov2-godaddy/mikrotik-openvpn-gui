# Public roadmap

The goal is a polished, reliable, and secure self-hosted OpenVPN management GUI
for MikroTik RouterOS. The product is single-project/single-router; **multi-
tenant architecture is explicitly out of scope**.

This public roadmap tracks merged product work and a redacted summary of
remaining acceptance gates. It contains no router addresses or names,
user/session data, private origins, credentials, or raw operational logs.
Detailed operational records remain operator-controlled.

## Current project snapshot

Formal release **v2.7.0** remains the latest numbered release. PR
[#751](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/751)
(`e2e64c68167ccb2f7ff06e5e815e47b1981483e9`) is the latest published runtime
candidate. Publisher run
[#38750050793](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/38750050793)
completed successfully, including source/security checks, compilation, tests,
rendered browser/accessibility checks, ARM64/AMD64 image builds and smoke tests,
detached provenance and SPDX SBOM attestation verification, and stable-manifest
read-back. Immutable image digests and provenance metadata are recorded in
[`RELEASES.md`](RELEASES.md). Candidate-specific RouterOS deployment and
acceptance remain pending; prior deployment observations for PR #745 do not
establish acceptance for PR #751. The connected test client has not yet been
verified against the PR #751 canary image. No canary acceptance or production
promotion is claimed here.

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
| Open — security assurance | [#200](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/200) | Current main includes trusted-proxy chain hardening in #704, redacted acceptance-tool safeguards in #698, refreshed assurance mapping in #712, nested observability projection in #713, bounded ASGI request bodies in #714, serialized Socket.IO telemetry with fresh RouterOS-role revalidation in #716, and serialized live telemetry/session invalidation in #720. PR #721 records #720's published artifact evidence; #723 adds synthetic coverage for observability-token scopes, query variants, and payload redaction. PR #722 adds CRL snapshot negative tests for #194; PR #728 fixes the pinned base-image source; PR #730 adds the certificate identity guard. PR #740 prevents automatic polling from extending idle sessions and hides RouterOS passwords from credential representations. PR #741 redacts RouterOS HTTP error bodies and transport exception details. PR #745 preserves active sessions when the first interface-counter observation is incomplete; PR #751 hardens session expiry and SQLite WAL startup under contention. Publisher run [#38750050793](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/38750050793) for the latest candidate passed source/security checks, compilation, tests, rendered browser/accessibility checks, ARM64/AMD64 publication and runtime smoke, detached provenance/SBOM verification, and stable-manifest read-back; immutable digests are recorded in RELEASES.md. Repository evidence is not live acceptance. SECURITY_ASSURANCE.md documents the RouterOS credential-in-process-memory trade-off and explicitly leaves the risk decision unresolved. Still required: deployed Cloudflare/proxy TLS and session checks, live stream logout/revocation/expiry and reconnect verification, physical-router permission and credential-memory review, and an independent external ASVS/security review. |
| Open — tracking epic | [#205](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/205) | Close only after remaining device/certificate acceptance (tracked here despite #194's GitHub closure), #200 security review, and candidate-specific live acceptance gates pass; include the #199 collector/restore evidence in the candidate report. |

PR #730's identity guard, PR #740's session-polling hardening, PR #741's
RouterOS error redaction, PR #745's preservation of sessions when initial
interface counters are incomplete, and PR #751's session-expiry/WAL-startup
hardening are included in the latest published candidate. PR #737 adds a
candidate-bound acceptance evidence gate. These
merges and their publication do not prove the pending device-backed live
acceptance criteria.

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
