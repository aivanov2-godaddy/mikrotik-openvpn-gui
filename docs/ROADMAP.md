# Public roadmap

The goal is a polished, reliable, and secure self-hosted OpenVPN management GUI
for MikroTik RouterOS. The product is single-project/single-router; **multi-
tenant architecture is explicitly out of scope**.

This public roadmap tracks merged product work and a redacted summary of
remaining acceptance gates. It contains no router addresses or names,
user/session data, private origins, credentials, or raw operational logs.
Detailed operational records remain operator-controlled.

## Current project snapshot

**Verified checkpoint — 2026-11-12 17:24 UTC.** Documentation PR #948 merged to `main` at `ff6775227ff7b7471efb6b56c9e50561d000da00` at 16:52:24 UTC. Its required PR checks, post-merge CI run #43263376608, and CodeQL run #43263377503 passed. PR #948 changed documentation only; no publisher run exists for its merge SHA. The latest published image remains PR #935, source `3f8fc22ec3166b3074fb54f54c79d6dede256ed4`, publisher run #43174815700.

TLS-verified, read-only RouterOS API observations between 17:19 and 17:24 UTC found the canary unhealthy and configured to the pinned PR #894 image, not PR #935. The direct private canary `/healthz` and `/readyz` requests returned HTTP 200, with readiness `ready` at the PR #894 revision. A separate healthcheck read classified the RouterOS status as failed/segmentation-fault; no per-container command override was present, and the default command matched the reviewed legacy timeout/wget readiness-check shape. The failing executable and cause remain unknown.

The same bounded container snapshot found production running with a tag-only configured reference. A separate RouterOS healthcheck read returned `good`, with no per-container command override; neither running OCI manifest digest is verified. Direct private production `/healthz` and `/readyz` probes from the collection host returned no HTTP status. That transport result does not establish that the production container is unhealthy.

The latest count-only active OpenVPN query remains the 15:25 UTC observation of zero; no newer count was collected. No session rows or identifiers were requested or retained, so current client-dependent #200 checks remain unverified.

An offline #785 source recheck compared the retained private source export with the later 13:50 UTC inventory. All five source fingerprints and all three scheduler classifications matched. None of the five scripts exactly matched the reviewed template, and all five were missing the canary restore-verification check. The comparator found zero added credential, private-key, destructive-operation, or fetch/download token markers relative to that template; this token comparison is not semantic approval or an updater safety review. The installed updater remains disabled.

The unhealthy canary is not a verified healthy rollback baseline, so PR #935 remains unstaged; its source includes PR #926's exec-form healthcheck fix, which has not been validated on RouterOS. Formal release v2.7.0 remains the latest numbered release. Issues #927, #785, #200, and epic #205 remain open. Within the original #188–#204 roadmap, #188–#199 and #201–#204 are closed; #200 remains open. No RouterOS setting, account, password, container, scheduler, updater, or production state changed; no staging, restart, rollback, or deployment occurred. Multi-tenancy remains excluded.

### Previous checkpoint — PR #938 (2026-11-12 about 11:18 UTC)

PR #938 merged to
`main` as `6290c4d026d9a139bd5af7b660092e5bb08a073b`. It adds a fail-closed
promotion gate requiring a current, candidate-bound independent security
assessment and a separate owner accepted-risk decision. PR checks, including
Python 3.13/3.14, browser/accessibility regression, pre-commit, CodeQL, and the
ARM64 build, passed. Post-merge CI run #43207941928 and main CodeQL run
#43207942515 also passed. No publisher run was triggered for this tooling
change; PR #935 remains the latest published image source. The code gate is
not the assessment or owner decision; issue #200 remains open.

Fresh TLS-verified read-only RouterOS point checks on 2026-11-12 at about
11:16–11:17 UTC found the canary unhealthy with its PR #894 image configured
by digest; the production container was running with a tag-only configured
reference. Neither running image digest was verified. The RouterOS healthcheck
still classified as a segmentation fault, with the default check present and
matching the reviewed shape and no custom command override. Separate direct
canary `/healthz` and `/readyz` probes returned HTTP 200 and `ready` for the
PR #894 revision. These isolated checks do not satisfy candidate acceptance or
authorize staging. No router write, restart, rollback, updater execution, or
production change occurred. The latest published image source remains PR #935;
PR #938 did not publish a new image.

Formal release **v2.7.0** remains the latest numbered release. PR #935
(`3f8fc22ec3166b3074fb54f54c79d6dede256ed4`) is the latest published mainline
image source. Post-merge main CI run #43174815746, main push analysis run
#43174814930, and container publisher run #43174815700 passed. The publisher
built and scanned both architecture images and published/read back the stable
manifest. Exact immutable tags, digests, and manifest checksum are in
[RELEASES.md](RELEASES.md). PR #935 has not been staged on RouterOS. Its
timestamp validation hardening improves the supplied-sample comparator; it
does not prove live RouterOS/API/browser or reconnect behavior.

A read-only WinBox container-table view at about 09:04 UTC on 2026-11-12 showed the canary unhealthy and production healthy. A TLS-verified read-only REST classification at 09:07:57 UTC categorized the canary healthcheck as failed/segmentation-fault; the custom command was absent, the default legacy shell/timeout/wget readiness check was present, lifecycle fields in that narrow result were absent, and restart count was 0. The exact failing executable and root cause remain unknown.

A separate REST configuration snapshot at 08:44 UTC identified the canary as configured for PR #894's older pinned ARM64 digest and production as tag-only. A narrow image-identity read around 09:17 UTC confirmed only that the canary reference remained digest-pinned and production remained tag-only. Both image-id properties were opaque 64-hex hashes unequal to the known PR #894 and PR #935 OCI manifest digests. The current MikroTik CLI reference lists image-id as a read-only string but does not define it as an OCI manifest digest. Neither running registry digest is verified. The earlier 08:22 UTC bounded /healthz and /readyz probes returned HTTP 200/ready for PR #894; they were separate point samples. PR #935 is still unstaged. Issues #927, #785, and #200 remain open, and no canary candidate acceptance or production deployment is claimed.

PR #932 merged at `8aba6f69c8e982af3d28d8dd9ab2055313ae284c`; post-merge main
CI run #43158080040 and CodeQL run #43158079958 passed. This documentation-only
merge published no image. At that checkpoint, PR #926 was the latest published image and had
not been staged. A later read-only WebFig point check on 2026-11-12 showed the
canary unhealthy and production healthy; production's latest verified running
digest remains unknown. Issue #927 tracks candidate device validation and
resolving the healthcheck fault. Issue #785 remains open for updater safety and
live canary-only staging/rollback. The staging CLI now emits redacted structured
diagnostics, but device acceptance remains open and the installed updater stays
disabled. Issue #200 candidate acceptance remains open. No router write,
production change, new numbered release, or production deployment is claimed.

PR #933 merged at `31f4976d98526d8629797ceb3bf3ecebb672d45d` after its required
CI and CodeQL checks passed. It adds versioned, allowlisted failure diagnostics
to the #785 canary staging CLI; it does not change RouterOS state or publish an
image. Post-merge CodeQL run #43163704180 and main CI run
#43163704164 both passed for the merge SHA. All main CI jobs passed, including
Python 3.13/3.14, pre-commit,
security scans, Redis integration/evidence attestation, Socket.IO same-origin,
rendered browser/accessibility regression, and ARM64 image build.
No container publisher run appeared for this merge. A TLS-verified read-only
REST point read at 05:54 UTC could not classify either container's lifecycle;
it confirmed only that the canary's configured reference is digest-pinned,
production's is tag-only, and neither running digest is verified. A separate
read-only WebFig point check at 05:56 UTC showed the canary unhealthy and
production healthy. WinBox was reachable, but its accessibility tree exposed
no container status. These point checks do not meet canary or
production acceptance. A TLS-verified read-only healthcheck classification at
06:06 UTC again reported the segmentation-fault category, with no container
override present and the image default matching the reviewed healthcheck shape.
The raw status and command were omitted; the exact failing executable and root
cause remain unknown.

A subsequent read-only healthcheck-status read at 06:14 UTC again showed the
canary unhealthy. RouterOS reported that the timeout healthcheck process could
not fork because a resource was temporarily unavailable, followed by a
segmentation-fault marker. This identifies the immediate fork failure but does
not establish its underlying cause or identify the faulting process.


On 2026-11-04, RouterOS was read back with the exact immutable PR #894 ARM64
candidate configured. Initial authenticated readiness returned revision
`84a3148de713abe49be0c7be8f21caa652b68dd9`, and the bounded readiness probe
and container health were healthy. A later same-day probe found the canary
unhealthy and bounded in-container `/healthz` and `/readyz` requests timed out.
The cause was not established. After an authorized restart of canary only,
RouterOS's healthy marker returned; post-restart revision read-back and
sustained health remain unverified. Production was not changed. An authenticated
foreground Connections page showed a live Socket.IO stream; after the
disposable test session was terminated, the page showed zero connected devices
and an ended history row without a reload, with a fresh SSE fallback. The client
later reconnected automatically and appeared on the same page with a fresh SSE
snapshot, also without a reload. This is qualitative disconnect/reconnect
evidence only; event and reconnect latency were not measured against the
one-second target, and a RouterOS API interruption was not simulated. The test
client reconnected at that observation. Background tabs intentionally pause the live
transport and reconnect when foregrounded; the stale indicator seen in a
background tab was followed by a fresh foreground stream.

Candidate-specific acceptance remains open: the measured 30-minute freshness
and resource window; connect/reconnect latency; RouterOS API interruption and
snapshot recovery; counter reset and event ordering/loss/duplication; Binary
API/REST parity; Redis outage and recovery; SQLite restore and interrupted-write
checks; authorization/privacy checks; and canary rollback rehearsal.
Issue #785 remains open for updater safety, staging-failure diagnostics, and the
reviewed canary-only staging/rollback path. PR #902 merged as efd634d and fixed
Windows 8.3 path aliases in local inventory/comparison tools; PR #906 merged as b0dfe22 and made offline scheduler resolution conservative. PR #904 clarified
historical canary evidence. These offline tooling changes did not change device
state, and neither provides device-side inventory. On 2026-11-11, the checked-in collector completed a TLS-verified,
read-only Binary API collection under the verified existing
`read,api,rest-api` group with one existing group member. The report was
classified `inventory_collected_review_required`.
The earlier 13:02 UTC report predates this policy change. The returned inventory
contains five scripts and three scheduler entries; the
redacted collector reported two direct bindings and one internal script-ID
candidate, with no opaque or ambiguous targets. A separate private read-only
export at 22:45 UTC matched all five source hashes and all three scheduler
classifications to that report. Two enabled script-run events resolve by unique
name to the first returned source. The disabled event uses
`/system/script/run` with the exact internal ID of the fourth source. MikroTik
documents `run` by ID or name ([RouterOS Scripting
reference](https://help.mikrotik.com/docs/spaces/ROS/pages/47579229/Scripting));
the configured target is therefore resolved within the exported set. The
scheduler remains disabled and was not executed. The authorized API print
replies do not prove exhaustive RouterOS visibility, and the member's
source-address restriction remains unverified. No account was created and no
password was changed.

None of the five installed sources exactly matches the reviewed repository
template. The offline comparator flags the canary restore verifier/call site as
missing in each. The fourth source contains container stop/set/update/start
operations and production references; static inspection does not establish
safe execution or rollback. Keep the dedicated updater disabled. No RouterOS
script, scheduler, configuration, container, account, VPN policy, or production
setting changed during collection. Continue #785 through staging-failure
diagnostics and rollback only when its safety gates permit. Production
promotion remains gated on candidate-bound acceptance.

### Earlier RouterOS point check — 2026-11-12 07:38–07:40 UTC

A read-only WinBox observation at 07:38 UTC showed the canary unhealthy and
production healthy. A separate TLS-verified REST configuration read-back at
07:39 UTC found the canary still pinned to the older PR #894 image, not PR #935,
and production configured by a tag without a digest. Neither running registry
digest was verified. The canary healthcheck continued to report process/fork
resource exhaustion followed by a segmentation-fault marker; the failing
process and root cause remain unknown. No RouterOS write, staging, rollback, or
production change was made. The canary is not a healthy rollback baseline, so
the staging preflight blocks before writes. PR #935 remains unstaged; candidate
acceptance and production promotion remain gated.

### Historical deployment checkpoints

Earlier checks for PR #862 and prior candidates are historical and do not
describe the current canary image. The 2026-10-30 checkpoint is retained below
for its audit trail.

Code Scanning returned zero open alerts on 2026-10-30; that does not replace
the independent security review. PR #849 distinguishes RouterOS HTTP 401
credential rejection from HTTP 403 permission denial without counting
permission or availability failures toward the bad-password lockout budget.
PR #830 is documentation-only and adds an offline comparison risk flag; it
changes no running application or RouterOS state.

Earlier authenticated dashboard and Connections observations used the prior
PR #806 image. They showed the live indicator and a disconnect reflected
without a page reload, but did not measure candidate-bound event latency or
freshness. The 2026-10-28 WinBox read-back for PR #862 confirms a matching
published ARM64 digest prefix, `HEALTHY` container status, and one resource
sample; it does not establish the exact readiness revision or sustained
resource impact. No candidate-specific dashboard session-event result is
asserted. The installed
updater and scheduler bindings remain unreconciled, and the updater was not run.
Keep automated updater use and production promotion gated on source/binding
reconciliation, deployed security review, and candidate-bound live acceptance.

The prior exact digest-bound canary read-back, on 2026-10-24, was PR #806. That
read-back confirmed the exact PR #806
ARM64 tag and healthy readiness. Sparse read-only samples over approximately
nine minutes showed 0.6–0.8% CPU and 38.6 MiB memory. A later WinBox
observation on 2026-10-25 showed the canary healthy with embedded revision
`79816625e493f9581e7389b95760403ac6c9a327`, but did not read the full
configured tag or digest. Its Stats view showed 0.7% CPU, 60.9 MiB memory, and
0 B swap. This supersedes the earlier stopped-state inventory but is not the
required 30-minute soak or sustained-resource result. The canary dashboard was
at its application sign-in form in the 2026-10-25 browser view. Authenticated
event latency, traffic freshness, reconnect, snapshot recovery, session
authorization, and a candidate-specific rollback rehearsal remain unverified.
On 2026-10-27, an authenticated Connections-page
spot check on that existing canary showed changing traffic samples and a
disposable test-session disconnect appearing as zero active devices and an
ended history row without a page reload. This is qualitative stream evidence,
not measured latency/freshness, reconnect/snapshot recovery, a 30-minute soak,
or acceptance of PR #862. No production image change is claimed; these are not
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
example. PR #851 adds a TLS-verified, print-only local inventory collector for
RouterOS scripts and scheduler bindings. Its successful 2026-11-11 run returned
five scripts and three scheduler entries, classified two direct bindings and
one internal-ID candidate, and reported no opaque or ambiguous targets in the
returned data. The redacted collector comparison reported no exact match to
the checked-in reviewed templates; it does not review the installed source
code. Each of the five assessments flags missing canary rollback/restore
verification. An earlier, separately supplied WinBox view recorded the
inventory identity's `read,api` group and source-address restriction. A later
screenshot showed existing terminal scrollback with additional group
privileges, but the GUI denied terminal interaction and no fresh RouterOS
read-back was obtained. Current role and source restrictions remain
unverified, and least-privilege is not validated.
The report remains review-required and does not prove exhaustive record
visibility. The private report/fingerprints remain operator-controlled. No
RouterOS script, scheduler, or configuration changed during collection.
Private source review and binding reconciliation remain outstanding; the
collector has not resolved the mismatch. The installed updater was not run.
Historical record: PR #806 was manually staged on canary and its exact embedded
revision and healthy readiness were read back at that time. That record does
not describe the current canary; see the Current project snapshot above for the
later PR #894 read-back and restart, after which revision and sustained health
remain unverified. No PR #806 rollback rehearsal or 30-minute soak is recorded.
The original updater error source remains unknown; authenticated live
acceptance remains open.

The next formal release remains gated on candidate-specific canary acceptance
and the security review below. Do not create or publish v2.8.0 until the gates
pass.

## Issue status

| Status | Issues | Scope |
| --- | --- | --- |
| Closed in GitHub — core implementation; follow-up UX validation remains | [#188](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/188), [#189](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/189), [#191](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/191), [#192](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/192) | Role-aware Dashboard quick-action visibility has a template regression test; original deep-link fragments have browser regression coverage. Sample-age and reconnect state are implemented and covered by PR #832. Remaining: complete the documented human task study and assistive-technology review. Freeze/Resume and graph range controls were conditional or not explicit in the issue criteria. |
| Closed in GitHub — implementation; follow-up UX validation remains | [#190](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/190) | PR #907 merged on 2026-11-11. Managers can select active connections; each queued disconnect reuses the live single-session impact review, reason, typed confirmation, and one-use token. Live updates preserve selection/focus/scroll and remove ended sessions. No batch-disconnect endpoint was added. Human task-study and assistive-technology follow-up remain separate UX validation work. |
| Closed in GitHub — core implementation; follow-up polish identified | [#193](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/193), [#195](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/195), [#204](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/204) | Connection Doctor and safe support bundles are implemented. Integration event type and delivery outcomes (delivered, pending, dead-lettered) are filterable and covered by a rendered regression. Doctor results now link only to allowlisted dashboard destinations; certificate/profile context remains a follow-up. Timeline remains explicitly bounded and incomplete. |
| Closed in GitHub — runtime cadence fix merged; live SLO evidence remains | [#198](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/198) | PR #838 makes the runtime honor a one-second start-to-start interface-sample cadence and retains a five-second delay for API-error retries, with regression coverage. This fixes the implementation gap; the measured canary freshness/latency window remains open under #200. Redis recovery and SQLite/WAL fault coverage remain implemented. |
| Complete | [#201](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/201), [#202](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/202), [#203](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/203) | RouterOS least-privilege diagnostics, mutation safety, SBOM/provenance and compatibility policy |
| Closed in GitHub — implementation; device/certificate acceptance remains | [#194](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/194) | PR #676 adds explicit active-session termination before deleting a VPN user, with mocked ordering/failure tests. PR #702 adds a collapsed, read-only CRL configuration observation to Device Profiles without restoring the removed overview alert. PR #705 hardens cleanup of temporary RouterOS profile-export artifacts. PR #707 gates retirement on testing the replacement identity; PR #718 adds fail-closed checkpoint-failure coverage; PR #722 rejects stale, malformed, missing-expiry, and wrong-CA CRL snapshots. PR #730 requires both the stored RouterOS certificate ID and normalized fingerprint to match for a read-only inventory match. PR #737 adds a candidate-bound, operator-attested certificate-lifecycle evidence gate; its merge does not itself prove a successful live lifecycle test. The GitHub issue is closed, but candidate/device-backed CRL freshness, staged renewal and retirement, fresh-connect rejection, active-session behavior, read-back, and canary rollback evidence remain release gates tracked by #205. Profile recovery issues a new identity rather than re-downloading a retained private key. |
| Complete — acceptance tooling; live gates remain | [#199](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/199) | Closed by PR #709. The bounded read-only collector and SQLite restore verifier are implemented. Candidate-matched live soak, deployment, and rollback evidence remain release gates tracked by #205 (device/certificate acceptance) and #200 (security assurance); closing this implementation issue does not claim device acceptance. |
| Open — canary healthcheck | [#927](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/927) | PR #926's exec-form healthcheck is present in current main and in published candidate PR #935, but has not been validated on RouterOS. At 17:19–17:21 UTC the canary remained configured to PR #894 and RouterOS classified its default healthcheck as failed/segmentation-fault, while separate direct `/healthz` and `/readyz` requests returned 200/ready for PR #894. No custom command override was present. The normal stage controller refuses an unhealthy baseline; the candidate remains unstaged pending a verified healthy rollback baseline and device acceptance. |
| Open — security assurance | [#200](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/200) | PR #938 adds a fail-closed gate for a current independent, candidate-bound scoped ASVS review and separate owner accepted-risk evidence; neither is supplied. The latest count-only active OpenVPN query is the 15:25 UTC observation of zero; no newer count was collected. Candidate-bound telemetry, recovery, privacy, live-session, security review, owner decision, and rollback evidence remain open. Production healthcheck was `good` at 17:23 UTC, but its configured reference is tag-only and its running digest is unverified. Direct private production health/readiness probes from the collection host obtained no HTTP status. No production deployment is claimed. |
| Open — updater safety / staging and rollback | [#785](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/785) | A local offline recheck found all five retained private source fingerprints and all three scheduler classifications match the later 13:50 UTC inventory. No source exactly matches the reviewed template; all five still lack its canary restore-verification check. The zero added token-marker deltas are not semantic safety approval. Keep the installed updater disabled. The 17:19 UTC readback still found the canary unhealthy, so the reviewed stage and rollback path remains unused. No staging, restart, rollback, updater execution, or production change occurred. |
| Open — tracking epic | [#205](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/205) | Keep open until device/certificate acceptance, #785 updater reconciliation and reviewed canary rollback, #927 healthcheck remediation, and #200 candidate-bound acceptance, independent scoped ASVS review, and owner decision pass. PR #948 merged at `ff6775227ff7b7471efb6b56c9e50561d000da00`; its required PR checks, post-merge CI #43263376608, and CodeQL #43263377503 passed. The 17:19–17:24 UTC API readbacks found the canary on PR #894 and unhealthy; production's RouterOS healthcheck was good but its configured reference is tag-only and its running digest is unverified. PR #935 remains unstaged; multi-tenancy remains excluded. No production deployment is claimed. |

PR #776 added a regression-tested logout ordering fix: revoke the session
before writing the audit event. PR #778 added redacted origin-rejection
diagnostics and Engine.IO handshake SID binding. PR #791 and #797 improve the
checked-in example RouterOS updater; neither installs nor executes it. PR #794
added WebSocket Origin and admin-session revocation-reference hardening.
PR #798 adds evidence-gated originless polling and browser coverage. PR #889
merged Engine.IO quota-retention hardening, and PR #891 rejects ambiguous
handshake query parameters and prevents new polling handshakes from bypassing
the quota reservation. PR #891's post-merge CI, CodeQL, and image publication
passed. PR #893 was published with passing CI, CodeQL, image publication, and
attestations; PR #935 now supersedes it as the latest published image. Immutable
tags and digests are in RELEASES.md. The current #894 canary read-back and its limits are recorded in
the current snapshot above; publication does not satisfy the live acceptance
gates. PR #830
improves offline updater comparison only. PR #851 adds local read-only
inventory tooling for #785. The 2026-10-30 WinBox view did not establish the
`*8` internal-ID target or prove inventory exhaustiveness.
A separate read-only source-fingerprint follow-up recorded on #785 found no
match to three reviewed examples. On 2026-11-11, the existing redacted inventory
was compared locally and in memory with historical `.rsc` and updater-named
files reachable from refs in this checkout at main commit
`778642bc9ff7c8fb728225eaadd75d3f8d76a495`; no exact matches were found.
This bounded search does not include detached Git objects, other local clones,
untracked operator copies, or RouterOS source not returned by the collector.
Because the report omits raw source, installed behavior and scheduler binding
remain unresolved; it also does not prove caller authorization or RouterOS-side
visibility. No RouterOS mutation occurred.
The 2026-10-30 read-back below is historical: it covered PR #862 only and
returned revision `445c1d5ca0f28174629be8e8cd94f04de132f0fc`. It predates the
PR #894 canary checkpoint recorded at the top of this roadmap. The 30-minute
live-acceptance and rollback gates in #200 and #205 remain open.

PR #866 merged on 2026-10-27 as `25e67872beeb328661a71e3d97d655b6fe44844b`.
It serializes reviewed VPN-user mutations across dashboard instances,
revalidates `users.manage` after lock acquisition, and checks both
`users.manage` and `session.manage` from one fresh role snapshot for password
changes. Hosted
CI passed, including Python 3.13/3.14, browser/accessibility, CodeQL, Redis
recovery, and ARM64 build/smoke. This is repository evidence only: PR #866 did
not publish or deploy a new image or change RouterOS. It does not satisfy the
candidate-bound acceptance gates in #200.

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

Historical note: PR #806 was the latest digest-bound canary read-back at that
time. A later WinBox view confirmed its embedded revision and healthy marker,
but did not confirm the configured tag or digest. The latest documented canary
checkpoint is PR #894, described in the project snapshot above; its post-restart
revision and sustained health remain unverified. Neither record establishes a
passed 30-minute soak or rollback rehearsal. No live telemetry/security
acceptance or production promotion is claimed. See the
[candidate report](LIVE_TELEMETRY_ACCEPTANCE_REPORT.md).

PR #730's identity guard, PR #740's session-polling hardening, PR #741's
RouterOS error redaction, PR #745's preservation of sessions when initial
interface counters are incomplete, PR #751's session-expiry/WAL-startup
hardening, PR #754's duplicate-Origin rejection, and PR #755's session-bound
live telemetry revocation are included in the latest published candidate.
PR #737 adds a candidate-bound acceptance evidence gate. These merges and their
publication do not prove the pending device-backed live acceptance criteria.

## Issue #200 — fresh RouterOS role checks

The current source candidate replaces REST-backed role reads at login,
reauthentication, and live-session revalidation with a fresh, verified TLS
Binary API connection. The connection authenticates the same RouterOS account,
then reads only that account's enabled state/group and that group's policy
using exact-name filters and path-specific read-only allowlists. The client
requests only the account's enabled state/group and the group's policy, then
projects the response to those approved properties before role evaluation.
RouterOS may return additional properties despite `.proplist`; this does not
claim the wire response contains only the requested properties. The fresh
Binary API role check requires `api` and `read` permissions, API-SSL reachability,
and a trusted API-SSL certificate. Normal dashboard sign-in also verifies
credentials through RouterOS REST, so the account additionally needs the
`rest-api` permission. A process-wide semaphore limits concurrent checks to
four. The connection is closed after the lookup.

This is a source mitigation candidate. It does not establish how a deployed
RouterOS version applies account disablement, group reassignment, or policy
changes to new Binary API logins, nor does it establish acceptable TLS/login
churn under concurrent streams. Keep V8.3.2 and issue #200 open until a
disposable RouterOS test measures those transitions, live-stream revocation,
and API-SSL service behavior. No RouterOS account or configuration change is
part of this source work.

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
  addresses, user/session data, deployment assignments, and raw time-series
  telemetry stay out of public issues, pull requests, and repository documents.
  Public records may include redacted candidate-bound point samples and
  aggregate outcomes needed to describe acceptance.
- No multi-tenancy work is planned.

For implementation details, see the linked issues and
[`SECURITY_ASSURANCE.md`](SECURITY_ASSURANCE.md). For the current public artifact
record and redacted procedure, see [`RELEASES.md`](RELEASES.md) and
[`ROUTEROS_ACCEPTANCE.md`](ROUTEROS_ACCEPTANCE.md). The acceptance report
contains artifact evidence and redacted current gate status:
[`LIVE_TELEMETRY_ACCEPTANCE_REPORT.md`](LIVE_TELEMETRY_ACCEPTANCE_REPORT.md).
