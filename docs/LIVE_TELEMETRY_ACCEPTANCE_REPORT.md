# Live telemetry acceptance status

Status: PR #971 (`ec760fcfd4ed1cffa5e6ba067d997865fd27e03e`) is the latest published image source. Its immutable RouterOS ARM64 digest is `sha256:a9aa9ab634151ce4c4c3b30ee8ef4bac3c41504ea936cc540a5e8cd1df24112d`; its AMD64 digest is `sha256:d348019c1290e1baa23d35dcad254e290e285fd729241f67a9aa0d4d7ec81992`. Publisher run #43446742850 succeeded, and the stable manifest asset SHA-256 is `sha256:344b7778eb32b9d4c89cecaaa5a0cb532b4c13dec7a426fa0f12bb432fc0c976`. Provenance and SPDX SBOM attestations were independently verified. This publication is not RouterOS deployment evidence. A post-publication TLS-verified REST healthcheck read at 15:45:38 UTC found the canary still configured to old PR #894 and unhealthy, with failed, `resource_unavailable`, `segmentation_fault`, and timeout categories; production remained running with a tag-only configured reference and health category `good`. That query did not verify running digests. Earlier direct canary `/healthz` and `/readyz` probes returned HTTP 200 and ready at the old PR #894 revision, before publication. PR #971 remains unstaged. Production deployment is not claimed.

## Latest published candidate and RouterOS read-back — 2026-11-13 14:28–15:45 UTC

PR #971 merged at 14:51:24 UTC as
`ec760fcfd4ed1cffa5e6ba067d997865fd27e03e`. Required PR checks, post-merge
CodeQL #43446742646 and main CI #43446742822 passed. Publisher run
#43446742850 built and scanned both architectures, published immutable images,
verified their provenance and SPDX SBOM attestations, smoke-tested both
published runtimes, and published/read back the stable manifest. The RouterOS
ARM64 digest is
`sha256:a9aa9ab634151ce4c4c3b30ee8ef4bac3c41504ea936cc540a5e8cd1df24112d`;
the AMD64 digest is
`sha256:d348019c1290e1baa23d35dcad254e290e285fd729241f67a9aa0d4d7ec81992`.

At 15:45:38 UTC, a fresh TLS-verified read-only REST healthcheck/configuration
read found the canary still configured at old PR #894 revision
`84a3148de713abe49be0c7be8f21caa652b68dd9`, digest-pinned but unhealthy, with
health categories failed, `resource_unavailable`, `segmentation_fault`, and
timeout. Production remained at old revision
`8c3a46df3a7e0e8b0dac9e5ed7a979aa06e855f7` with a tag-only configured
reference, lifecycle `running`, and health category `good`. The REST query did
not verify either running OCI digest. The last runtime manifest identity
reconciliation remains the 14:28:43 UTC Binary API point read, before PR #971
publication, which compared the configured references against PR #965 only.
Direct canary GETs at 14:37:16 UTC returned HTTP 200 for `/healthz` and
`/readyz`, with readiness `ready` at old PR #894; those probes also predate
publication. The exact failing process and root cause remain unknown. No
candidate staging, restart, rollback, or production change is verified.

## Previous RouterOS read-back — 2026-11-13 11:03–11:29 UTC

At 11:03:50 UTC, the TLS-verified Binary API container read found the canary lifecycle unhealthy on the old PR #894 configured image. Its configured reference is pinned but does not match PR #965; the running registry digest remains unverified. Production was running with a tag-only reference, also with no verified running digest. Direct private canary GETs at 11:10:21 UTC returned HTTP 200 for `/healthz` and `/readyz`, with readiness `ready` at the old PR #894 revision. A TLS-verified REST healthcheck comparison at 11:11:50 UTC classified the canary as `segmentation_fault` with no per-container command, the reviewed legacy default shape, and restart count 0. It classified production as `good` with its healthy field true, no override, and a default command unlike the legacy shape. A bounded filtered RouterOS log read returned no matching fault records. The PR #965 `--check-only` preflight blocked at `baseline / canary_unhealthy` with `router_writes_may_have_started=false`; it made no RouterOS writes. These observations do not identify the failing executable or root cause, verify either running registry digest, establish a healthy rollback baseline, or accept the candidate.

No RouterOS state changed, PR #965 was not staged, and no production deployment occurred.

At 11:28:59 UTC, a fresh read-only WinBox container-list view showed the
canary unhealthy and production healthy. It did not expose configured image
references or revisions, and it does not verify either running digest. No
RouterOS write was issued during this inspection; the fault and acceptance gates
remain unresolved.

## Previous RouterOS point check — 2026-11-13 09:13 UTC; publication checkpoint — 09:56 UTC

GitHub reports issues #188–#199 and #201–#204 closed; #200, #927, and epic #205 remain open. Issue #785 closed when PR #962 merged; installed updater reconciliation and healthy canary rollback acceptance remain follow-up gates under #205. PR #965 added redacted healthcheck-status diagnostics while preserving unhealthy lifecycle classification. GitHub closed #927 on merge due to an unintended closure keyword in the PR description; the wording was corrected and #927 was reopened because its canary acceptance criteria remain unmet. No RouterOS state changed.

The latest successful Binary API lifecycle read at 09:13 UTC found the canary unhealthy on its old PR #894 digest-pinned reference and production running with a tag-only configured reference. Neither running registry digest was verified. A 09:03 UTC TLS-verified REST configuration read showed the same configured references but omitted lifecycle fields. The initial 08:55 UTC Binary API refresh failed because the in-progress query requested healthcheck-status while its local path allowlist did not include that property; PR #965 adds it only for /container/print, and the subsequent 09:13 UTC read succeeded. A fresh TLS-verified REST healthcheck classification at 09:00 UTC still reported failed / segmentation_fault, with no per-container command, the reviewed legacy default command shape, and restart count 0. Separate direct private /healthz and /readyz probes at 09:00 returned HTTP 200 and readiness ready at the old PR #894 revision. These observations do not clear the healthcheck failure, establish a healthy rollback baseline, or identify the faulting executable/root cause.

The latest count-only active OpenVPN query at 09:03 UTC returned zero and retained no session details. No current disposable-client connection is claimed; client-dependent checks remain deferred. The 05:46 UTC bounded updater inventory and semantic source review still show five installed scripts with no reviewed canary restore-verification call; the updater remains disabled and unexecuted. The 04:14 UTC PR #935 check-only preflight blocked at baseline / canary_unhealthy before writes. The newer PR #965 immutable image is published but has not been staged. No RouterOS account, password, container, scheduler, updater, or production state changed; no stage, restart, rollback, updater execution, or production deployment occurred.

## Previous repository and RouterOS point check — 2026-11-13 03:57–04:14 UTC

A fresh GitHub read confirms issues #188–#199 and #201–#204 are closed; #200, #927, #785, and epic #205 remain open. PR #960 is merged, and its post-merge CI and CodeQL both passed. The latest container-publisher run remains PR #935's successful publication; no publisher run followed #960.

Fresh TLS-verified, read-only checks found the canary still configured for old PR #894 with a digest-pinned reference; Binary API reported it unhealthy. Production is running with a tag-only configured reference. Neither running registry digest was verified. The count-only active OpenVPN query returned zero and requested no session identifiers or addresses; disposable-client identity remains unknown.

REST healthcheck classification at 03:57:38 UTC reported failed/segmentation_fault. No per-container override was present; the default command matched the previously reviewed legacy readiness-check shape. The exact failing executable and root cause remain unknown. Direct private GETs at 03:58:02 UTC returned HTTP 200 for `/healthz` and `/readyz`; readiness was ready at old PR #894. These point probes do not override RouterOS's unhealthy state or establish a sustained interval. No raw healthcheck command/output, private address, or image ID was retained.

A refreshed read-only updater inventory and private source comparison returned five scripts and three schedulers: two enabled direct name bindings, one disabled script-ID candidate, zero opaque targets, no exact reviewed-template match, and no reviewed canary restore-verification call in any source. The bounded marker comparison is not semantic safety approval. No updater was run.

A fresh PR #935 `--check-only` preflight at 04:14 UTC returned `preflight_blocked / baseline / canary_unhealthy` with `router_writes_may_have_started=false` and did not stage the candidate. The fresh 03:59 UTC snapshot still shows the unhealthy canary; it is not a verified healthy rollback baseline. No RouterOS write, staging, restart, rollback, production deployment, or other RouterOS change occurred. Client-dependent #200 checks remain unverified.

## Previous RouterOS point check — 2026-11-13 03:03–03:22 UTC

## Earlier RouterOS observations — 2026-11-12 17:19–18:02 UTC

A TLS-verified, read-only Binary API snapshot at 17:19:59 UTC found the canary lifecycle `unhealthy`, with a pinned configured reference matching PR #894 rather than PR #935. Production was `running` with a tag-only configured reference. Neither running OCI manifest digest was verified.

Bounded direct private canary GETs at 17:21:03 UTC returned HTTP 200 for `/healthz` and `/readyz`; readiness was `ready` at the PR #894 revision. A separate TLS-verified REST classification at 17:21:52 UTC reported the RouterOS healthcheck category as `segmentation_fault` with a `failed` status prefix. No custom per-container healthcheck command was present; the default command matched the reviewed timeout/wget readiness-check shape. These point samples do not identify the failing executable or cause, and do not establish a sustained healthy interval.

Follow-up TLS-verified REST classification at 17:48:38 UTC still reported a `failed`/`segmentation_fault` healthcheck with the default command present, no per-container command override, and the reviewed timeout/wget readiness-check shape. Separate direct private canary GETs at 17:48:54 UTC returned HTTP 200 for `/healthz` and `/readyz`, with readiness still `ready` at PR #894. The app probes do not override RouterOS's failed healthcheck or establish a sustained healthy interval.

A bounded TLS-verified RouterOS log query at about 17:54 UTC found no records matching its healthcheck, segmentation-fault, timeout, wget, unhealthy, memory-pressure, fork, or process-exit filters. No raw log lines were printed or retained. This limited negative query does not show that the fault is absent or identify its cause.

A separate REST classification at 17:23:29 UTC returned `good` for the production healthcheck, with no custom command override. Direct private production `/healthz` and `/readyz` probes from the collection host at 17:24:31 UTC received no HTTP status. This transport result is not evidence that RouterOS marked production unhealthy; deployed production HTTP readiness remains unverified from that probe.

Follow-up TLS-verified REST classification at 18:02:11 UTC again returned `good` for the production healthcheck, with no per-container override; its default command did not match the reviewed healthcheck shape. Separate direct private production `/healthz` and `/readyz` probes at 18:02:48 UTC again received no HTTP status from the collection host. This does not establish that RouterOS marked production unhealthy. Deployed production HTTP readiness and its running OCI digest remain unverified.

PR #935 has not been staged on RouterOS.

The count-only active OpenVPN query at 17:47:24 UTC returned zero. It queried only the `service` field and saved no session details. No session identifiers or addresses were requested or retained; current client-dependent #200 checks remain unverified and are deferred until the disposable client is connected.

The unhealthy canary is not a verified healthy rollback baseline, so PR #935 remains unstaged. The stage controller's healthy-baseline guard remains in force. No RouterOS setting, account, password, container, scheduler, updater, or production state changed; no staging, restart, rollback, or production deployment occurred. Issues #927, #785, #200, and epic #205 remain open.

## Current RouterOS and updater point checks — 2026-11-12 15:25–15:35 UTC

At about 15:25 UTC, read-only WinBox healthcheck-status for the canary remained failed with a resource-unavailable/fork marker followed by a segmentation-fault marker. The exact failing process and root cause remain unknown. A current exact-reference comparison found the configured canary image matches PR #894's immutable ARM64 reference and does not match PR #935's published candidate. The running OCI manifest digest is not verified. No direct `/healthz` or `/readyz` probe was repeated in this check.

The count-only active OpenVPN query returned zero around 15:25 UTC. No session rows, identifiers, or addresses were requested or retained; client-dependent acceptance remains deferred.

At 15:33 UTC, RouterOS returned `good` for the production healthcheck-status field. A read-only comparison found its configured reference was not digest-pinned; the running OCI manifest digest remains unverified. This health marker is not production image-identity or deployment acceptance.

A local offline recheck of #785's retained private updater source export against the later 13:50 UTC inventory found all five source fingerprints and all three scheduler classifications matched. None of the five scripts exactly matched the reviewed template; all five were missing its canary restore-verification check. The comparator found zero added credential, private-key, destructive-operation, or fetch/download token markers relative to the template. This is a bounded token comparison, not semantic approval or an updater safety review. The installed updater remains disabled.

PR #935 remains unstaged because the canary is not a verified healthy rollback baseline. Issues #785, #927, #200, and epic #205 remain open. No RouterOS setting, account, password, container, scheduler, updater, or production state changed; no staging, restart, rollback, or deployment occurred. Multi-tenancy remains excluded.
## Previous RouterOS point check — 2026-11-12 12:48–12:52 UTC

A TLS-verified read-only Binary API snapshot completed at 12:48:37 UTC. The canary remained configured with the pinned PR #894 image and RouterOS reported it unhealthy. Production remained running with a tag-only configured image reference. Neither running registry digest is verified.

At 12:49:50 UTC, separate direct private HTTP GETs returned 200 for `/healthz` and `/readyz`, with readiness ready at the PR #894 revision. At 12:50:23 UTC, a separate TLS-verified REST classification reported failed/segmentation_fault. The image-default healthcheck was present and matched the reviewed legacy shape; no custom per-container override was present. These point samples do not establish a continuous healthy interval or identify the failing executable.

A read-only aggregate OpenVPN session count at 12:52 UTC was zero. No session identifiers or addresses were requested or retained; client-dependent acceptance remains deferred. PR #935 is the latest published image source and has not been staged on RouterOS. The reviewed stage path remains blocked while the canary is unhealthy. No RouterOS write, restart, rollback, or production change occurred.
## Previous RouterOS point check — 2026-11-12 12:12–12:16 UTC

At approximately 12:12 UTC, a TLS-verified read-only `/rest/log/print` query removed the `container` topic filter and searched all returned topics for healthcheck, segmentation-fault, timeout, wget, unhealthy, memory/fork-pressure, and process-crash terms. It returned zero matching rows. No raw log lines were printed or retained. This bounded query does not establish that no related records exist outside the current log buffer or filter terms, and it does not identify the crashing executable.

A bounded TLS-verified Binary API read at 12:15:25 UTC found the canary configured with PR #894's pinned ARM64 digest `sha256:3b5f3304ded4bd0cf09855575f27a8fffa225efe4ef940a0d7e2f25734d6c581` and revision `84a3148de713abe49be0c7be8f21caa652b68dd9`; RouterOS reported `unhealthy`. Production remained `running` with a tag-only reference. Neither running OCI digest is verified.

At 12:15:42 UTC, a separate TLS-verified REST classification reported the canary healthcheck `failed` with a segmentation-fault marker. No per-container command override was configured; the default healthcheck matched the previously reviewed PR #894 shape. At 12:15:58 UTC, separate direct private GETs returned HTTP 200 for `/healthz` and `/readyz`; readiness was `ready` at the PR #894 revision. The direct app response does not override RouterOS's unhealthy state, and these point samples are not a continuous acceptance window.

A bounded read-only aggregate OpenVPN session count at 12:16:17 UTC was zero. No session rows or identifiers were requested or retained; client-dependent acceptance remains deferred. No RouterOS setting, account, password, container, scheduler, or updater state changed. No staging, restart, rollback, or production action occurred. PR #935 remains unstaged; the healthy rollback baseline, candidate-bound health and telemetry window, recovery, privacy, security review, owner decision, and rollback gates remain open.

## Latest RouterOS point check — 2026-11-12 09:04–09:17 UTC

A read-only WinBox container-table view at about 09:04 UTC showed the canary marked unhealthy and production marked healthy.

At 09:07:57 UTC, a TLS-verified read-only REST classification categorized the canary healthcheck as failed with a segmentation-fault marker. The custom command was absent and the default healthcheck matched the previously reviewed legacy shell/timeout/wget readiness-check shape. RouterOS lifecycle fields were absent from that narrow response; the helper reported restart count 0. This does not identify the failing executable or root cause.

A narrow TLS-verified image-identity read around 09:17 UTC found the canary reference digest-pinned and production tag-only. The RouterOS image-id for each was an opaque 64-hex value unequal to the known PR #894 and PR #935 OCI manifest digests. MikroTik's current CLI reference lists image-id as a read-only string but does not define it as the OCI manifest digest. Neither running registry digest is verified.

A prior 08:44 UTC configuration read identified the canary as PR #894 and production as tag-only. Separate bounded direct private GETs at about 08:22 UTC returned HTTP 200 for /healthz and /readyz with readiness ready at PR #894 revision 84a3148de713abe49be0c7be8f21caa652b68dd9; these earlier point probes are not a current healthcheck result or a soak. Current VPN-client connectivity is not asserted because the visible browser terminal scrollback has no reliable command timestamp. No RouterOS write, candidate stage, rollback, restart, or production change occurred. PR #935 remains unstaged; #927, #785, and #200 acceptance remain open.

## Previous RouterOS point check — 2026-11-12 approximately 04:45 UTC

The authenticated WinBox view was inspected read-only. The canary remained
configured for PR #894's immutable ARM64 digest
`sha256:3b5f3304ded4bd0cf09855575f27a8fffa225efe4ef940a0d7e2f25734d6c581`
and was marked `unhealthy`. RouterOS's default healthcheck showed process/fork
exhaustion followed by a segmentation-fault marker. This classifies the
healthcheck failure; the faulting executable and root cause remain unknown.
At 03:31 UTC, the separate bounded private HTTP probe returned 200 for
`/healthz` and `/readyz` and reported `ready` at revision
`84a3148de713abe49be0c7be8f21caa652b68dd9`. The probe and UI state are
different point samples and do not establish a continuous healthy interval.

Production was marked `healthy`, but its configured reference remained a
revision tag without a digest; the running registry digest was not verified.
No RouterOS write, canary staging, rollback, or production change was made.
PR #930's merged staging preflight requires a healthy canary and blocks before
any write when that baseline is unhealthy. It has local mock coverage, not a
device staging result. PR #926 remains unstaged and no candidate-specific
30-minute, telemetry, recovery, privacy, or rollback acceptance is claimed.

## Previous canary read-back — after PR #926 publication — 2026-11-12 00:44 UTC

At 00:44:48 UTC, a TLS-verified read-only Binary API snapshot found the canary
still configured with PR #894's pinned ARM64 digest
`sha256:3b5f3304ded4bd0cf09855575f27a8fffa225efe4ef940a0d7e2f25734d6c581`;
RouterOS reported lifecycle `unhealthy`. Production was `running` with its
prior tag-only configured image. The API report does not verify either running
registry digest.

At 00:46:01 UTC, bounded direct private HTTP GETs returned 200 for `/healthz`
and `/readyz`. The readiness response was `ready` at revision
`84a3148de713abe49be0c7be8f21caa652b68dd9`, matching PR #894. At 00:46:31 UTC,
a separate read-only RouterOS REST classification found the image-default
healthcheck status failed with a segmentation-fault marker; no configured
healthcheck override was present. The observed default command matched PR
#894's reviewed shell-form healthcheck shape. These are separate point samples,
not a continuous health result. The exact crashing executable and root cause
remain unknown.

At that earlier checkpoint, PR #926's immutable ARM64 digest remained
unstaged. It changes the image probe to exec form; RouterOS behavior must be
rechecked after a reviewed canary stage. Issue #927 tracks that check. The
installed updater remains disabled under #785. No canary mutation, rollback,
30-minute acceptance window, or production deployment was claimed.

## Historical canary checkpoint — PR #894 — 2026-11-04

At the initial 2026-11-04 read-back, the canary was configured with the
immutable PR #894 ARM64 reference
`ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-84a3148de713abe49be0c7be8f21caa652b68dd9-arm64@sha256:3b5f3304ded4bd0cf09855575f27a8fffa225efe4ef940a0d7e2f25734d6c581`.
RouterOS reported healthy, the bounded readiness probe succeeded, and the
authenticated readiness response returned revision
`84a3148de713abe49be0c7be8f21caa652b68dd9`.

A later same-day check found the canary unhealthy. Bounded in-container HTTP
requests to both `/healthz` and `/readyz` timed out; these probes did not
establish a root cause. After an authorized restart of canary only, RouterOS
reported a healthy marker again. No authenticated readiness response was
captured after that restart, so the running revision and sustained recovery
remain unverified. Production was not changed.

In the authenticated foreground Connections page, the disposable test session
was visible on Socket.IO. After termination through the review flow, the page
showed zero active devices and the ended history row without a reload; the live
indicator showed a fresh SSE fallback. The disposable client later reconnected
automatically and appeared as active on the same page with a fresh SSE update,
also without a reload. This confirms qualitative disconnect delivery, client
reconnect, snapshot repopulation, and one fallback path. It does not establish
the required 1,000 ms latency because no synchronized event timestamps were
captured, and it does not simulate a RouterOS API interruption. The stale
indicator observed earlier belonged to a background tab; the app pauses its
live transport while hidden and reopened a fresh stream when a foreground tab
was used.

No measured 30-minute resource/freshness window has been completed. Pending
candidate-bound checks include reconnect after RouterOS API interruption,
snapshot recovery, traffic age, counter reset and event-integrity behavior,
Binary API/REST parity, Redis and SQLite failure recovery, authorization and
privacy review, and canary rollback. The installed RouterOS updater remains
disabled and unreconciled under issue #785; it was not run. Production remains
unchanged.

## Historical read-only RouterOS checkpoint — 2026-10-29

WinBox showed the canary's configured digest prefix matching the published
PR #862 ARM64 digest and production's configured immutable tag prefix matching
PR #788. The dashboard container rows displayed `H` markers and Redis displayed
`R`; these are point-in-time UI readings, not a resource soak. PPP Active
Connections showed zero entries. Public `/readyz` requests returned HTTP 200
Cloudflare Access sign-in HTML rather than readiness JSON, and direct private
container readiness probes from the workstation timed out. A fresh
Cloudflare Access-authenticated readiness read returned revision
`445c1d5ca0f28174629be8e8cd94f04de132f0fc` (PR #862), not PR #885. No
live-session acceptance, PR #885 staging, or production promotion is verified;
RouterOS configuration was not changed.
A follow-up WinBox read after the owner reported reconnecting still showed zero
PPP Active Connections, so the reported client session is not corroborated by
RouterOS or authenticated canary telemetry.
WinBox System > Resources also showed a router-wide point sample: 6% CPU,
646.7 MiB free memory of 1024 MiB, 760.5 MiB free disk of 1024 MiB, and 0.0%
bad blocks. These figures do not attribute usage to the dashboard container or
establish sustained impact.

## Historical read-only RouterOS checkpoint — 2026-10-30

A fresh WinBox listing showed canary still configured with PR #862's ARM64
immutable tag and matching digest
`sha256:7c47d4a3ec3de83b2218cd3ce417017c92befeb45e967c355e9da9beb3a5b6ac`,
with a healthy marker. Production still showed the PR #788 ARM64 tag. PPP
Active Connections showed one active test tunnel. The canary dashboard sign-in
request remained pending, so no authenticated dashboard event or traffic
sample was correlated with the router session. No PR #893 staging or live
acceptance is established by these point observations.

An earlier 2026-10-28 Stats view showed 0.7% CPU, 38.8 MiB memory, 0 B swap,
69.7 MiB app size, and 0.0 MiB data size. A signed-in dashboard check then
showed a stale/reconnecting live stream and zero connected devices. Those
historical point checks do not establish sustained resource impact. The
30-minute acceptance window and production promotion remain unverified.

## Historical RouterOS candidate status — PR #862 and PR #893 — 2026-10-30

PR #862 is a published artifact with immutable digests recorded in
[`RELEASES.md`](RELEASES.md). An earlier WinBox readback showed a configured
image digest prefix matching the published PR #862 ARM64 digest and a
`HEALTHY` container. The Stats view provided one CPU/memory/swap/app-size/data-
size sample. The fresh authenticated readiness result in the checkpoint above
returned PR #862 revision `445c1d5ca0f28174629be8e8cd94f04de132f0fc`,
confirming that the canary was not running PR #885 at that observation. At that
time, PR #893 was the latest published image and no post-publication RouterOS
read-back was available. A later read-only WinBox listing on 2026-10-30
reconfirmed PR #862's exact ARM64 tag and digest with a healthy marker; the
production row still showed the PR #788 ARM64 tag. RouterOS showed one active
test tunnel, but the canary sign-in request remained pending, so that session
was not correlated with authenticated dashboard telemetry. These point reads
do not establish live acceptance or acceptance of PR #893.

The following candidate-bound gates remain open: a 30-minute resource and
freshness soak; connect/disconnect event latency; API interruption and
reconnect/snapshot recovery; counter reset and duplicate/loss/order checks;
Redis outage/restart delivery recovery; SQLite restore and interrupted-write
checks; authenticated authorization/privacy checks; and canary rollback
rehearsal. The earlier qualitative live-UI check was on PR #806 and does not
provide evidence for this candidate. The installed RouterOS updater remains
unreconciled and was not run.

## Live UI spot check — 2026-10-27

This was a historical observation on PR #806 and does not describe the current
canary. See the current checkpoint at the top of this report.

On the existing PR #806 canary image, an authenticated Connections page showed
the Socket.IO live indicator and changing five-second traffic-rate samples.
After the disposable test session was terminated, the same page showed zero
active devices and the ended session in history without a page reload. This is
qualitative evidence of live UI delivery only; no event-latency clock offset was
established, and it is not a 30-minute soak, reconnect/snapshot-recovery result,
or acceptance of PR #873. A reconnect/snapshot check and the controlled soak
remain outstanding. No production image change is claimed.

## Historical canary checkpoint — PR #806 — 2026-10-24

This checkpoint is historical; the latest post-publication RouterOS point
read-back is recorded near the top of this report.

PR [#806](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/806)
merged as `79816625e493f9581e7389b95760403ac6c9a327`. CI, CodeQL, ARM64 image
build, Redis recovery integration, rendered-browser/accessibility regression,
secret-pattern checks, and dependency audit passed. The immutable ARM64
registry digest is
`sha256:dd646c8b25a5b4e24653d2268719b89513da85c7164e68e499b5ebd4cf292dce`.
RouterOS read-back confirmed the exact candidate revision and healthy
readiness on canary. Sparse point samples are not a 30-minute soak and do not
prove sustained resource impact. No candidate-specific rollback drill has
been completed for #806. No production image promotion is recorded. The browser
view available at that checkpoint (2026-10-25) was the application sign-in form,
so it did not verify authenticated live-event acceptance, event-age/freshness,
reconnect/snapshot recovery, or session authorization.

## Public artifact evidence

Previously published PR [#798](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/798)
merged as `041a9d2ac7581dac18911c236cbbb3aee4280273`. Main CI run
[#40000779522](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/40000779522)
and publisher run
[#40000779533](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/40000779533)
completed successfully. ARM64/AMD64 image smoke tests passed, and provenance
and SPDX SBOM attestations verified against the exact source commit and image
digests; stable-manifest publication and read-back succeeded. PR #798 requires
same-origin Referer evidence before allocating Engine.IO state for an
originless polling GET and includes a rendered-browser regression. Publication
did not stage or deploy the image on RouterOS.

| Platform | Immutable tag | Registry digest |
| --- | --- | --- |
| RouterOS ARM64 — previous published image; superseded by PR #806 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-041a9d2ac7581dac18911c236cbbb3aee4280273-arm64` | `sha256:b41ad2cde73efe9f465d583430e4801b75335b18c92b9a364ec21149c69ab601` |
| AMD64 / CHR — previous published image; superseded by PR #806 | `ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-041a9d2ac7581dac18911c236cbbb3aee4280273-amd64` | `sha256:bf2c211397f30940cb72ab199f2d575b42372341491a934b1260bdd9a12fba6c` |

PR #798 is not a numbered release; v2.7.0 remains the latest formal version.
Image publication did not deploy to RouterOS or establish live acceptance.

### Historical candidate-bound canary artifact — PR #776

PR [#776](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/776)
(`c4b4b76793b2454e81362867d8654962627de6fa`) is a historical candidate-bound
canary record. Main CI run
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
immutable tag. The latest recorded read-back confirmed that tag and RouterOS
marked the container healthy after start. The updater was no longer active
and no completed 30-minute sample record was verified, so readiness is **not
passed**. The persisted pending-candidate record did not match the later
canary image and does not bind a passing soak to #776. During a later
authenticated dashboard observation, the connected-user count changed in the
already-open page without a manual refresh; the exact event latency and
traffic-sample age were not timed. A canary sign-out attempt returned an
origin-rejection error and did not revoke the session. The canary `PUBLIC_ORIGIN`
setting matched the expected origin, but the rejected request's origin/header
shape was not captured; do not weaken origin or CSRF checks while
investigating. The registry digests above are bound to their tags by the
verified publisher workflow; RouterOS reports the configured tag, not a
local OCI digest. No post-publication RouterOS staging or candidate-specific
live acceptance for PR #793 is recorded. The latest recorded read-only RouterOS
inventory at approximately 14:33 UTC on 2026-10-23 showed canary and production
configured with immutable ARM64 tag
`ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-8c3a46df3a7e0e8b0dac9e5ed7a979aa06e855f7-arm64`
(source commit PR #788), not the then-latest published PR #793 tag. This was a
configured-tag read-back before PR #798 was published; no local OCI digest or
candidate readiness was verified. A later read-only PPP Active Connections check showed one active
session at approximately 14:50 UTC and none at approximately 15:02 UTC. The
dashboard was signed out during that observation, so no latency, freshness,
reconnect, or dashboard correlation is claimed. No RouterOS or container
changes were made during these checks.

Public deployment detail here is limited to the redacted canary-stage status
above. This file contains no router identity, hostnames, addresses, resource
readings, logs, or VPN session identities/details. Detailed deployment and
acceptance evidence belongs in operator-controlled storage. The table below is
a gate checklist, not a report of private measurements.

## Candidate acceptance gates

The following table is the historical acceptance record for candidate PR #776;
it does not describe the current canary. At the time that record was updated,
PR #806 was the staged canary with a healthy revision read-back. That checkpoint
was later superseded by the PR #894 checkpoint at the top of this report. The
PR #806 30-minute soak, rollback, and full live acceptance remained incomplete.

| Gate | Required result | Public status |
| --- | --- | --- |
| Candidate identity and readiness | Canary reports the exact immutable candidate and remains healthy for the agreed window. | Exact #776 ARM64 tag and healthy startup read back; updater is no longer active and no completed 30-minute evidence was verified |
| Session event latency | Connect/disconnect visible in the open dashboard within 1 second. | A connected-user change appeared without manual refresh; exact latency and disconnect timing not measured |
| Traffic freshness | Samples are no older than 2 seconds; no manual refresh is needed. | Not measured for #776 |
| Reconnect and snapshot recovery | RouterOS API interruption recovers automatically; a full snapshot follows reconnect. | Not measured for #776 |
| Event and counter integrity | Counter resets do not create incorrect rates; detect missing, duplicated, or out-of-order events. | Not measured for #776 |
| Binary API and REST parity | Compare equivalent read-only snapshots and document any expected differences. | Not measured for #776 |
| Redis/outbox | Exercise unavailable/restarting Redis, retries, duplicate delivery, backlog drain, and recovery. Verify persistence and `REDIS_STREAM_MAXLEN` capacity cover the maximum expected consumer lag, and test an acknowledged entry trimmed before consumption. | Repository tests cover outage/restart, retry, duplicates, backlog drain, and the explicit no-replay behavior after an acknowledged entry is lost or trimmed (`tests/test_redis_integration.py::RedisOutboxRecoveryTests.test_acknowledged_event_is_not_reconstructed_after_redis_data_loss`; `tests/test_redis_integration.py::RedisOutboxRecoveryTests.test_acknowledged_event_is_not_reconstructed_after_stream_trim`). Candidate-specific Redis persistence/retention and consumer-lag evidence were not collected. The application publishes minimized audit/outbox events; it has no Redis stream consumer, so downstream receipt remains external evidence. |
| Resource impact | Record bounded CPU, memory, storage, and container-health observations over the soak. | Not measured for #776 |
| Persistence and rollback | Rehearse SQLite restore and rollback in isolated canary; preserve production state. | Not verified for #776 |
| Security and privacy | Unauthenticated clients receive no telemetry; logout revokes the session; logs and reports contain no secrets or unnecessary private data. | Canary sign-out was rejected by the origin check and did not revoke the session; request header shape not captured; deployed investigation remains open |

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
logs, or session-level/unredacted deployment measurements in GitHub issues,
pull requests, public artifacts, or this file.

The release evaluator also requires an operator-attested, redacted certificate
lifecycle record bound to the canary image tag and digest. Its schema and
collection CLI input are documented in `ROUTEROS_ACCEPTANCE.md`; this repository
gate does not independently prove live RouterOS actions or change the
candidate-specific acceptance status above.
