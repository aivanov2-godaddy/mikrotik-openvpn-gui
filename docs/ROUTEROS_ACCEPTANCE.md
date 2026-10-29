# RouterOS canary acceptance test

Use this procedure after public CI has passed, before promoting a new immutable
image from canary to production, and again after promotion. It is a repeatable,
redacted hardware-in-the-loop check; it complements the repository's automated
tests.

The procedure is deliberately read-only except for the disposable canary
container and a disposable VPN profile. Do not paste router exports, passwords,
private keys, certificates, profile archives, public IP addresses, or real
domain names into an issue, pull request, or test result.

## Scope and prerequisites

Compatibility claims are evidence-scoped. CI image build/runtime smoke does not
prove RouterOS compatibility. PR #885 (`f31bf9e0f6bac65dc6dea7fc00af99743c3e61fb`)
is the latest published image. Its CI, CodeQL, image scans, runtime smoke tests,
provenance and SPDX SBOM checks passed; the stable manifest was read back. See
[`RELEASES.md`](RELEASES.md) for immutable tags and digests. No RouterOS read-back confirms PR #885 staging or acceptance.

## Current read-only checkpoint — 2026-10-30

WinBox read-back showed the canary still configured for PR #862's published
ARM64 image and reporting `HEALTHY`; production still showed the older immutable
image associated with PR #788. Neither container was changed. RouterOS PPP
Active Connections showed one active test tunnel at the time of the read, but
the canary dashboard browser was at its sign-in page. The session could not be
correlated with authenticated dashboard telemetry, so event delivery, latency,
freshness, reconnect, and snapshot recovery remain unverified for the current
candidate. This is not a soak or acceptance result.

The read-only WinBox review also found five known updater-related script entries
and three scheduler entries. The project updater scheduler was disabled with
zero runs and an unresolved event binding. No updater or script was executed;
no router account, policy, certificate, VPN profile, or container was changed.
Keep the updater disabled until installed source and scheduler bindings are
reconciled and reviewed staging and rollback steps are available. No PR #885
staging or production promotion is claimed.

## Historical checkpoint — 2026-10-29

WinBox showed the canary container's configured digest prefix matching PR #862's
published ARM64 digest, while production still displayed the immutable tag
prefix for PR #788. The list showed the canary and production rows with `H`
markers and Redis with `R`; this is a point-in-time UI observation, not a
resource soak. The PPP Active Connections table was empty. Public `/readyz`
requests returned HTTP 200 Cloudflare Access sign-in HTML in both environments,
not application readiness JSON; direct private-container readiness probes from
the workstation timed out. A fresh Cloudflare Access-authenticated readiness
read returned revision `445c1d5ca0f28174629be8e8cd94f04de132f0fc` (PR #862), not
PR #885. PR #885 staging remains unverified, and no live-session acceptance or
production promotion is claimed. RouterOS configuration was not changed.
A follow-up WinBox read after the owner reported reconnecting still showed zero
PPP Active Connections; the reported client session is not yet corroborated by
RouterOS or authenticated canary telemetry.
The WinBox System > Resources view showed a router-wide point sample of 6% CPU,
646.7 MiB free memory of 1024 MiB, 760.5 MiB free disk of 1024 MiB, and 0.0%
bad blocks. This is not dashboard-container attribution or a sustained soak.

The preserved 2026-10-28 operator-transcribed updater manifests were rechecked
offline on 2026-10-29. The project-updater subset lists three non-exact copies;
all three lack the reviewed canary restore verifier. The larger five-script,
three-scheduler manifest is explicitly non-exhaustive. It records two enabled
scheduler entries invoking a separate `autoupdate` script and one disabled
project-updater scheduler with zero runs whose `/system/script/run *8` target
remains unresolved. The comparator's credential, private-key, destructive-
operation, and fetch-marker heuristics reported no added markers; this is not
a safety approval. The original invalid-request cause was not recovered from
the retained audit bundle and remains unknown. No script or scheduler was run
or changed; keep the project updater disabled.

## Candidate status — PR #862 and PR #885 — partial read-back

PR #862 was published and has immutable architecture tags and digests recorded
in [`RELEASES.md`](RELEASES.md). An earlier WinBox readback showed a configured
image digest prefix matching its published ARM64 digest and container status
`HEALTHY`, with one point-in-time Stats sample. This supersedes the older #785
and #200 comments that said it had not been read back. A fresh authenticated
readiness response returned PR #862 revision
`445c1d5ca0f28174629be8e8cd94f04de132f0fc`, confirming the canary was not
running PR #885 at that observation. PR #885 is the latest published image; no
RouterOS read-back confirms it is staged. Sustained health/resource impact and
the soak remain unverified.

Candidate-specific session-event, traffic-freshness, latency, reconnect,
snapshot-recovery, and authorization evidence remain unavailable for PR #885.
RouterOS later showed one active test tunnel, but it was not correlated with an
authenticated dashboard; the canary browser remained at its sign-in page.
A 30-minute candidate-bound soak, Redis failure/recovery checks,
SQLite backup/restore rehearsal, counter-reset and event-integrity checks, and a
candidate-specific rollback rehearsal remain outstanding. Production
promotion is not claimed. The installed RouterOS updater and scheduler bindings
remain unreconciled and the updater was not run; do not use it until its source
and promotion behavior are reconciled.

## Previous deployment checkpoint — PR #745 — 2026-10-15

The isolated canary was updated to PR #745's exact ARM64 tag,
`ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-ad3cd3df72ea8a6dbb08e3a7b5ac0e97d19a5ed6-arm64`.
RouterOS read-back confirmed that tag and reported `healthy=true`. Its
published registry digest was
`sha256:4b3a0fbf6ad3943ce05bbd256f3d2930e2fa89808ccded46779066a484b6b66e`;
RouterOS reports the configured tag, not a local OCI digest. The previous
canary tag was
`ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-6dd53022523766a5371628dfe158286072494bf4-arm64`;
it is the rollback target for this canary only. The production container and
its data were not changed. The published digest is bound to the tag by the
verified publisher workflow.

One immediate post-start resource sample showed 0% CPU and 40,116,224 bytes
(about 38.3 MiB) of canary memory. This is a single snapshot, not a resource
soak or capacity result. An unauthenticated request to the canary edge returned
HTTP 302 with TLS verification successful, consistent with the configured
access gate; this does not verify an authenticated dashboard session or
application readiness. The active VPN session count was zero at the RouterOS
check. Consequently, session-event latency, traffic freshness, connect and
disconnect delivery, reconnect/snapshot recovery, and Redis delivery under
live traffic were not measured. SQLite restore and canary rollback were not
rehearsed in this checkpoint.

**Result: deployment/startup check passed for the historical PR #745 candidate;
acceptance remains incomplete. Do not carry that result forward to later
candidates, including PR #761 and PR #767, or promote a candidate to production
on the strength of this checkpoint.** The
controlled, candidate-matched acceptance window below must still collect its
required samples and recovery evidence. Keep exact router
addresses, credentials, session details, and raw logs in private
operator-controlled records.

## Previous candidate status — PR #761

The PR #761 candidate is a prior published image. It was not deployed to
RouterOS and has no hardware-acceptance result; later published candidates
#767, #772, and #776 superseded it before PR #778 became the latest published
runtime. At that checkpoint, PR #776 was the latest candidate-bound canary
record.

## Previous candidate status — PR #767

The PR #767 image is published. On 2026-10-19, RouterOS read-back confirmed the
exact ARM64 immutable tag
`ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-19f7ca90915871d5cfa9e68f356f62dadc90ddf8-arm64`
and reported the canary healthy after start. The published ARM64 digest is
`sha256:dd78656ff241eb090cba52c3825a5421b902983a139b9f91403f82f2109586d5`.
The authenticated dashboard and Connections page loaded and displayed the
Socket.IO live indicator. RouterOS and the rendered Connections page both
showed zero active sessions/devices and an empty active-device list.
Production remained on its prior image. The previous canary tag,
`ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-e8af615c42145b9b6a1ea44bee9b217ffc5dc4be-arm64`,
is the identified rollback target; rollback has not been rehearsed.

This is point-in-time deployment and application-readiness evidence only. The
30-minute window, live connect/disconnect and traffic measurements, reconnect
and snapshot recovery, event/counter integrity, resource soak, Redis/SQLite
recovery, and rollback remain unverified. Do not promote until the complete
pre-promotion report passes and rollback is rehearsed. No resource minimum or
cross-model/version certification is inferred. See the
[current release record](RELEASES.md#published-images) and
[acceptance report](LIVE_TELEMETRY_ACCEPTANCE_REPORT.md).

## Previously published runtime — PR #794 (post-publication staging unverified)

PR #794 merged as `beba66c0f36231511ec1b9cc664f2be39a128750`. Its immutable
RouterOS ARM64 image is
`ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-beba66c0f36231511ec1b9cc664f2be39a128750-arm64`
with digest
`sha256:1dad53e8e89acab230ae69703cec319a64ce472ca1336c491d7aa13e022f96f5`.
The AMD64 tag and digest are in `RELEASES.md`. Main CI run #39984997001 and
publisher run #39984997106 passed, including both architecture runtime smoke
tests and provenance/SBOM attestation verification. PR #794 enforces a
same-origin WebSocket handshake and removes session-cookie bearer identifiers
from the admin-session inventory. No post-publication staging is recorded for
this image on RouterOS. Do not treat publication as hardware compatibility or
acceptance evidence.

## Previously published runtime — PR #793 (RouterOS staging unverified)

PR #793 merged as `fbcbe96ff9fc56ffa5b0f750b8e72d59fbeeb164`. Its immutable
RouterOS ARM64 image is
`ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-fbcbe96ff9fc56ffa5b0f750b8e72d59fbeeb164-arm64`
with digest
`sha256:b3d347184b016851d6e0b43135ee2831ebb2ba7e3dc5f4bca2270e8fa4c5bc10`.
The AMD64 tag and digest are in `RELEASES.md`. Main CI run #39941787724 and
publisher run #39941787902 passed, including both architecture runtime smoke
tests and provenance/SBOM attestation verification. PR #793 bounds Engine.IO
polling clients and ASGI authorization waits and updates release-acceptance
runbook coverage. No RouterOS staging for this image is recorded. Do not treat
publication as hardware
compatibility or acceptance evidence.

## Historical candidate-bound canary record — PR #776 (healthy startup; acceptance pending)

PR #776 merged as
`c4b4b76793b2454e81362867d8654962627de6fa`. Its immutable ARM64 image is
`ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-c4b4b76793b2454e81362867d8654962627de6fa-arm64`
with registry digest
`sha256:8b5dfa0d2c4fae542e0c560576a91432812823ebe55ecc6bcad7bbfa7c0e922e`.
The AMD64 image digest is
`sha256:fad2b337196e5fe09d2040acb3353e4acc5fe2d894bc49866a0470369c75d4f9`.
Main CI run #39867875857 and publisher run #39867875877 passed. Provenance
attestations verify against the repository's container workflow and exact
source commit. The manual canary-only updater was invoked on 2026-10-23;
the latest recorded read-back confirmed the exact tag and healthy startup. The updater is no longer
active and no completed 30-minute sample record was verified; readiness is not
passed. A connected-user change appeared in the open dashboard without manual
refresh, but exact latency was not timed. A canary sign-out attempt was
rejected by the origin check and did not revoke the session; investigate this
without weakening origin or CSRF protections. Production was not changed.

The current acceptance window must still capture session latency and traffic
freshness, reconnect/snapshot recovery, event and counter integrity, Binary API
versus REST parity, Redis delivery/recovery, resource impact, SQLite restore,
rollback, and deployed security/privacy checks. Do not promote or create v2.8.0
until the candidate-matched acceptance report passes and rollback is rehearsed.

## Previous candidate status — PR #772 (2026-10-19)

PR #772 merged as
`624bfbf032396b3b2b21cab1a659985b6d580f79`. Its ARM64 immutable image is
`ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-624bfbf032396b3b2b21cab1a659985b6d580f79-arm64`
with registry digest
`sha256:b341f063e405283ea1647670073665375aa3213300afd3b2b4076e7039377fbd`.
The AMD64 image digest is
`sha256:2cf79dfecf4231f8b33c9e675d64982adc392197ab428dbccde803d2e7bd1721`.
Main CI and the publisher completed successfully; detached provenance and SPDX
SBOM attestations, published-runtime smoke, and stable-manifest read-back
passed. The merged change sets the app process core-dump limit to zero before
startup; it does not configure or verify the RouterOS host's dump collector.

On 2026-10-19, RouterOS read-back reported the PR #772 immutable tag and a
healthy container on the isolated canary. The post-start check found zero
active VPN sessions. This is point-in-time startup evidence only; no production
deployment was performed for this candidate. Its
30-minute canary soak, live-session events and freshness, reconnect/snapshot
recovery, event integrity, resource impact, Redis/SQLite recovery, deployed
security checks, and rollback rehearsal are all **not verified**.

This is historical evidence only. PR #793 was the latest published runtime
when this checkpoint was written; PR #794 superseded it at that time, followed
by later publications including PR #798 and PR #817. PR #776 was the latest
recorded canary candidate at that historical checkpoint; PR #806 is the last
candidate-bound read-back documented above. A subsequent WinBox read-back
showed PR #806's embedded revision healthy, but did not read the full configured
tag or digest. Use the exact candidate and its recorded acceptance status
above for any new acceptance run. Do not treat image
publication or startup health as the required 30-minute acceptance window. Do
not promote until the complete candidate-specific report passes and rollback
has been rehearsed.
The PR #497 rollback/readiness results described in the [historical release
record](RELEASES.md#previously-published-mainline-image-pr-497-2026-10-05)
remain historical and do not prove current-candidate canary readiness or rollback.
See the [installation compatibility
matrix](INSTALLATION.md#compatibility-and-support-matrix) and [historical release record](RELEASES.md#previously-published-mainline-image-pr-497-2026-10-05).

- Use one immutable candidate for the canary, such as
  `ghcr.io/<owner>/mikrotik-openvpn-gui:sha-<40-character-commit>-arm64@sha256:<64-hex-digest>`.
  Record the exact pinned reference and digest. Verify the target RouterOS
  version accepts and reads back this form before staging. For a pre-promotion run, also record
  production's separate prior image, tag, digest, and revision; each
  `/readyz` result must match its environment's recorded image. After promotion,
  both environments should identify the candidate.
- Use RouterOS 7 with the Container package enabled. ARM64 hardware uses the
  `-arm64` image; CHR/x86 evaluation uses `-amd64`. ARM32 is unsupported.
- Use a canary router, CHR, or an isolated maintenance window. Take an
  encrypted RouterOS backup first.
- Keep `/data` (SQLite state) and `/config` (trust material) on dedicated
  router storage mounts. Reuse neither a production mount nor a root filesystem
  path for the canary.
- Use a disposable dashboard account and VPN profile. Keep management access on
  HTTPS and keep the router REST service private.

## Record the environment

Redact names, addresses, serials, and mount paths before attaching results.
Record only the facts needed to reproduce a compatibility result:

```routeros
/system/resource/print
/system/package/print where name~"container"
/container/print
```

Do not use or copy `/container/print detail` or container environment-list
output into an acceptance record: detailed RouterOS output may expose Redis
URLs/passwords or other secrets. Capture only the selected non-secret fields
needed for the test, and keep raw terminal output private. Apply the same rule
to WinBox/WebFig: the Containers table's environment column and its
accessibility representation may contain complete values even when the UI
visually clips them. Do not capture, copy, export, or paste that view or its
accessibility tree into chat, tickets, logs, or repository artifacts. Use the
allowlisted acceptance collector or record only non-secret status fields.

Include RouterOS version, architecture, candidate tag/digest, and whether the
test is physical ARM64 or CHR/x86.

## Acceptance checklist

| Check | Pass condition | Evidence to record |
| --- | --- | --- |
| Image and state | Container reaches `running` using the exact pinned candidate. | Tag, digest, and redacted container state. |
| Readiness | Private `/readyz` reports `ready` and the expected immutable revision. | Status and revision only. |
| Router reachability | Dashboard service-health view can read RouterOS through the configured private path. | Pass/review/fail only. |
| Dashboard exposure | HTTPS or direct-IP access matches the chosen installation path; REST is not public. | Chosen path and pass/fail. |
| OpenVPN inventory | Existing service and certificate inventory load without mutation. | Counts only. |
| Disposable profile | Create, download, and validate one disposable profile; then remove or suspend it. | Action outcomes, never the profile. |
| Persistence | Restart the canary container; dashboard state remains on its mounted `/data`. | Restart and pass/fail. |
| Rollback | Previous immutable candidate can be selected and started. | Previous revision and pass/fail. |

For a private VETH path, probe only from an approved management host or the
router-local controller. An example is:

```text
http://<private-container-address>:8080/readyz
```

Do not expose that probe to the public internet. A production controller should
validate the revision before it promotes the candidate.

## Rollback rehearsal

Keep the previous immutable image reference before updating the canary. If the
candidate does not pass, stop it and restore that exact prior reference:

```routeros
/container/stop [find where name="<canary-container>"]
/container/set [find where name="<canary-container>"] remote-image="<owner>/mikrotik-openvpn-gui:sha-<previous-commit>-arm64@sha256:<previous-64-hex-digest>"
/container/update [find where name="<canary-container>"]
/container/start [find where name="<canary-container>"]
```

Replace the examples locally. Do not commit real values. Confirm the restored
container becomes ready before ending the maintenance window.

## Redacted result template

```text
Candidate revision: sha-<40-character-commit>
Image digest: sha256:<digest>
RouterOS: <major.minor.patch> / <architecture>
Environment: physical ARM64 | CHR/x86
Readiness: pass | review | fail
Dashboard-to-RouterOS read: pass | review | fail
Disposable profile lifecycle: pass | review | fail
Persistence after restart: pass | review | fail
Rollback rehearsal: pass | review | fail
Notes: <no credentials, addresses, hosts, profiles, or exports>
```

## Collect a bounded app-health window

Keep the canary's private readiness path distinct from its browser/metrics
origin. RouterOS or an approved management host can probe the canary's private
`/healthz` and `/readyz` addresses without public DNS, NAT, or a reverse proxy.
That path is sufficient for an isolated image-start/readiness soak, but it does
not prove authenticated UI behavior, live telemetry delivery, or metrics.

For those app-level checks, provide a dedicated HTTPS origin routed only to the
isolated canary through the approved reverse proxy and access-control layer.
It must not share a route that resolves to production, and the canary's
`PUBLIC_ORIGIN` must match that dedicated origin before browser checks begin.
Never expose the container port directly. If the dedicated route is not ready,
continue private readiness checks where possible and mark the authenticated
acceptance window incomplete; do not send canary probes to production.

`scripts/collect_release_acceptance.py` requires a completed redacted report
from `scripts/collect_routeros_acceptance.py` via `--routeros-report` for any
passing release-acceptance phase. Run both samplers concurrently; omitting,
failing, or window-mismatching RouterOS evidence prevents a passing result.
The app collector samples `GET /healthz` and
`GET /readyz` on both private app origins. Post-promotion collection also
samples authenticated aggregate `GET /metrics` in both environments. During
`canary-prepromotion`, it samples metrics only from canary; production is checked
for health, readiness, and its separately recorded prior revision, without
requiring that older image to expose the candidate's metrics schema. Prefer
separate API tokens scoped only to `health.read`: `--canary-api-token-env` and
`--production-api-token-env` load each token from a named environment variable
and send it only as a bearer credential to that environment's `/metrics`
endpoint. The readiness probes `/healthz` and `/readyz` never receive
credentials. Token-bearing metrics probes require HTTPS, and each metrics URL
must match its environment's readiness origin exactly. The canary-prepromotion
phase does not load or require a production token. Use distinct, short-lived
tokens and revoke them after the acceptance window. The older `--cookie-env`
option remains available for compatibility, but a single session cookie is
broader and may be sent to both enabled metrics origins. Credentials and probe
origins are never written to the report. It checks each readiness revision
against its own immutable image tag, records the observation window and sample
gaps, and requires complete Redis/outbox health and process-observation metrics
wherever metrics are part of that phase. Missing or incomplete required metrics
fail closed and clear any caller-supplied Redis success claim.
Process-observation ages for session events and traffic samples are not
end-to-end RouterOS-to-browser latency.

The collector also fails the release gate when any known session-event
process-observation age exceeds 2 seconds; unknown ages fail separately. This
2-second freshness bound applies to the process observation-age signal only
and does not replace the separate 1-second session-change delivery target.
Reconnect acceptance requires a positive, reset-free supervisor reconnect
counter delta during the collection window plus an observed last-connected
timestamp in that window. Full RouterOS snapshot recovery additionally
requires the supervisor's last-full-snapshot timestamp to be observed in the
same window at or after that reconnect. The dashboard gateway's client
snapshot-recovery counter is retained as corroborating evidence, but cannot by
itself establish RouterOS full-snapshot recovery. Caller-provided booleans do
not override missing, zero, reset, out-of-window, or incorrectly ordered
measurements.

The RouterOS acceptance window must observe at least one active VPN session
(`active_vpn_sessions_max >= 1`). A zero-only session window fails; the client
may be disconnected during controlled reconnect testing, so the minimum count
is informational and need not remain positive for the entire soak.

Use `--phase canary-prepromotion` for a candidate soak before promotion. The
evidence records the candidate image/revision for canary and production's
separately recorded prior image/revision. The collector checks each deployment
against its own recorded revision throughout the window and requires
production to remain on a different prior immutable image from the canary
candidate. The default `--phase postpromotion` is for verification after
promotion and requires canary and production to report the same candidate
image/revision. In `canary-prepromotion`, only the candidate canary tag/digest
is checked against GHCR; the prior production digest and metrics endpoint are
not required. In `postpromotion`, both canary and production tag/digest pairs
are checked; any required candidate registry digest that is unavailable or
mismatched fails closed. This verifies registry artifact identity, not the
bytes cached on the router. The report declares the registry-check scope, and
the final evaluator reports
`promotion_eligible` for a passing pre-promotion candidate gate and
`production_accepted` only for a passing post-promotion collection. A
pre-promotion report does not assert production acceptance. After promotion,
run the collector again with `--phase postpromotion`, both environments on the
candidate, and both metrics origins supplied; only that passing report marks
production accepted. The prior-production baseline contributes only health,
readiness, revision, and sample-coverage evidence; its older transport,
resource measurements, and data-plane exercise claims are omitted from the
pre-promotion acceptance report and must be verified against the candidate
after promotion.

The collector uses read-only HTTP GET/HEAD probes against the private app and
GHCR and never changes RouterOS/container configuration, promotes an image, or
performs rollback. The local SQLite rehearsal writes only a temporary restore
copy and removes it; the source database/backup remains read-only. A passing
collection is not a promotion action and does not execute or prove the required
rollback rehearsal; that remains a separate controlled RouterOS procedure.

### Redis recovery CI and canary rollback evidence

The passing collector requires `--redis-recovery-run-id` and
`--rollback-report`. The Redis report is produced by the `redis-integration`
CI job and uploaded as `redis-recovery-<full-source-sha>`. The collector uses
the authenticated GitHub CLI to verify the run metadata, download the exact
artifact from a successful `main` push for the candidate revision, and verify
its cryptographically signed GitHub artifact attestation against the CI
workflow and exact source commit. A separate, main-push-only attestation job
receives the OIDC and attestation permissions; the integration-test job stays
limited to read-only repository contents. A
pull-request merge-ref SHA is not the eventual main commit. The report shape is
illustrated in [`redis-recovery-evidence.example.json`](redis-recovery-evidence.example.json).
The example is synthetic and must not be submitted as real test evidence. It is
source-integration evidence for Redis outage, restart, backlog replay, and
duplicate handling; it explicitly sets `runtime_image_digest_verified: false`
and does not prove that Redis behavior was exercised inside the deployed image.
Reports older than seven days, for a different commit, with missing/skipped
scenarios, or with extra fields fail closed. Keep CI logs and Redis payloads out
of the release report.

The rollback report must be captured by
`scripts/collect_rollback_acceptance.py`; do not hand-author the checkpoint
booleans or timestamps. It reads both dashboard containers through authenticated
RouterOS Binary API and REST, independently checks both `/readyz` origins, and
fails unless those observations agree. Probes are restricted to the exact HTTPS
hosts `vpn-dev.wanted.sx` for canary and `vpn.wanted.sx` for production; IP
literals, plaintext HTTP, nonstandard ports, and arbitrary hosts are rejected.
It prompts for six ordered
canary-only stages; it does not issue RouterOS commands or modify production.
Use the redacted shape in
[`rollback-rehearsal-evidence.example.json`](rollback-rehearsal-evidence.example.json)
only to understand the schema, never as real evidence. The source observations
must show production unchanged, the canary candidate healthy and ready, rollback
to the exact previous image, and candidate restoration before its soak. The
RouterOS-configured image tag is read back; the collector does not claim that
the router's cached image digest was verified. The report is explicitly
`operator-attested-unsigned`: its schema and values are validated, but the saved
file is editable and is not cryptographic proof that the historical API reads
occurred. It cannot by itself establish cryptographically verified acceptance.
Keep it private and never include router addresses, credentials, user data, or
raw logs.

Run the rollback capture before the candidate soak, with read-only RouterOS
API/REST credentials supplied via the documented environment variables (or
entered at hidden prompts). Readiness URLs must use the exact configured
environment hostname over HTTPS.

```powershell
python scripts/collect_rollback_acceptance.py `
  --output private-rollback-rehearsal.json `
  --candidate-image ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-<candidate-sha>-arm64@sha256:<candidate-digest> `
  --candidate-digest sha256:<candidate-registry-digest> `
  --previous-canary-image ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-<previous-sha>-arm64@sha256:<previous-digest> `
  --production-image ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-<production-sha>-arm64@sha256:<production-digest> `
  --canary-url https://vpn-dev.wanted.sx `
  --production-url https://vpn.wanted.sx
```

The example uses placeholders; replace them locally. The capture remains
read-only and asks the operator to perform each canary transition between
checkpoints. Never promote production as part of this drill.

### Certificate lifecycle acceptance evidence

Any collection marked `passed: true` must include a
`certificate_lifecycle_acceptance` object. Use
[`certificate-lifecycle-acceptance.example.json`](certificate-lifecycle-acceptance.example.json)
as the separate redacted report supplied with
`--certificate-lifecycle-report`. The collector attaches only its validated,
allow-listed projection to the release evidence. Missing or invalid evidence
fails closed and prevents `promotion_eligible` and `production_accepted`.

This canary-only record must match the exact immutable image tag and OCI digest
in the canary deployment record. Its timezone-aware timestamps must be ordered
from replacement testing, failed-renewal rollback read-back, RouterOS
revocation read-back, fresh/loaded CRL read-back, existing-session read-back,
fresh-connection rejection, and dashboard-state distinction verification.
Evidence may be at most 24 hours before the collection start and no later than
five seconds after its end. The existing session outcome must explicitly be
`terminated` or `remained_active`; the gate does not assume revocation
terminates an already-established tunnel. A fresh connection must be verified
rejected after the revocation/CRL checks.

The record is an operator attestation validated for schema, ordering, freshness,
and candidate identity—not a cryptographic signature or independent proof that
the RouterOS actions occurred. The output marks it with
`evidence_provenance: operator_attested` and `independently_observed: false`.
Perform the controlled test on canary, including
replacement before retirement and a failed-renewal rollback path. Do not put
certificate subjects or serials, usernames, addresses, profile bytes, private
keys, credentials, screenshots with identifying content, or raw logs in the
report. The two privacy fields must remain `false`; unknown fields are rejected
so private data cannot be silently copied into the acceptance output. CA-wide
rotation remains out of scope.

The sampled release gate fails if any session-event, traffic-freshness, or
gateway-delivery latency sample is unknown, even if other samples in the window
are valid. At the end of each environment's observation window, the Redis
outbox must be drained and its dead-letter count must be zero; missing or
unknown outbox metrics, any non-zero pending count observed during the window
(even if it later drains), or any dead-lettered event observed in the window
fail acceptance. This prevents a single fresh final sample or successful
publish from masking a transient backlog, delivery gap, or stuck queue.
For session-event and traffic freshness, the collector compares each age gauge
with its paired source timestamp and the scrape time; missing, contradictory,
or stale source timestamps fail the same window. Redis must be configured and
reported available in every metrics sample, not merely in the final scrape;
the last successful publish must also remain no older than 120 seconds at each
sample.

The final release evaluator requires the collector's timestamped result; a
deployment-only evidence file cannot pass. Its collection window must cover at
least 30 minutes, match both deployment observation windows, and end no more
than 15 minutes before evaluation. Timestamps more than five minutes in the
future fail closed to tolerate only small clock skew. The standalone telemetry
evaluator applies the same 15-minute freshness and five-minute future-skew
limits to its latest sample. Rerun the read-only collector when evidence is
stale; do not edit timestamps by hand.

## Browser and stream evidence for the release gate

A passing candidate window also requires the redacted report from
`scripts/telemetry_stream_observer.py` and the structured result of
`scripts/telemetry_acceptance.py`, captured concurrently with the app and
RouterOS collectors over the same 30-minute canary window. The Socket.IO
observer only accepts an explicitly named canary/development HTTPS origin; it
does not record event payloads, identities, addresses, or credentials.

The telemetry-acceptance evaluator emits a
`vpn-dashboard-telemetry-acceptance-v3` aggregate with its sample window,
browser-visible connect/disconnect and traffic-update counts, transition
latency p95 and maximum, maximum traffic-sample age, sequence/gap/duplicate/order counts,
and reconnect-test outcome. The release collector takes only those allowlisted
aggregates; it does not copy raw NDJSON records or extra caller fields into the
final evidence. A passing window requires visible connect and disconnect
transitions without refresh, visible changing traffic updates, every measured
session transition at most 1,000 ms (with p95 retained as a summary), session-event
and traffic-sample ages at most 2 seconds,
at least 30 sequence observations, zero sequence gaps/duplicates/out-of-order
events, and a successful API-interruption plus snapshot-recovery test. The Socket.IO
observer independently requires a reconnect, a snapshot after that reconnect,
a connected stream at the end, and clean sequence continuity. Either report
missing, failed, stale, shorter than 30 minutes, or outside the app-collector
window by more than five seconds fails closed. Report end times must also be
no more than 15 minutes old when evaluated. The final release evaluator
revalidates the reports and matching window rather than trusting the
collector's `passed` flag alone. The release-collection CLI invokes that
central evaluator after joining RouterOS, stream-observer, and browser evidence;
its exit status therefore includes rollback and production-protection gates,
not only collection and telemetry sub-gates.

Run these captures concurrently from separate trusted local terminals. Keep
the NDJSON input and observer output private; never place raw event frames,
identities, addresses, or secrets in either file:

```powershell
# Set VPN_CANDIDATE_SHA to the exact full lowercase commit SHA for this image.
# Terminal 1: authenticated, redacted Socket.IO observation of the canary.
python scripts/telemetry_stream_observer.py `
  --canary-origin https://<approved-canary-origin> `
  --expected-revision $env:VPN_CANDIDATE_SHA `
  --cookie-env VPN_CANARY_COOKIE `
  --duration-seconds 1800 `
  --output private-stream-observation.json

# Terminal 2 / trusted browser harness: capture redacted
# sample/session/traffic/reconnect records during the same window into
# private-telemetry-acceptance.ndjson. Include one timestamped
# deployment_identity record with the fixed canary origin and candidate SHA;
# the release collector verifies it against repeated direct /readyz
# observations covering this same window. A one-shot standalone readiness
# check cannot establish soak identity.

# Terminal 3: app plus RouterOS collection, started within five seconds of the
# other captures. The observer report is read after the soak ends.
python scripts/collect_release_acceptance.py `
  --input private-evidence.json `
  --output private-collected-evidence.json `
  --routeros-report private-routeros-window.json `
  --stream-observer-report private-stream-observation.json `
  --telemetry-acceptance-input private-telemetry-acceptance.ndjson `
  --canary-url https://<private-canary-origin> `
  --production-url https://<private-production-origin> `
  --canary-sqlite-backup private-canary-backup.sqlite3 `
  --canary-metrics-url https://<approved-canary-origin> `
  --canary-api-token-env VPN_ACCEPTANCE_CANARY_TOKEN `
  --duration-seconds 1800 --interval-seconds 60 `
  --phase canary-prepromotion
```

The telemetry acceptance NDJSON is operator/harness input, not output from the
evaluator. Use real UTC epoch timestamps and the strict record schema in
`docs/LIVE_TELEMETRY_CANARY.md`; do not infer browser rendering from an idle
stream or the Socket.IO observer. If any input is missing or invalid, rerun
the full window instead of editing timestamps or pass flags.

Start from the [evidence schema example](release-acceptance-evidence.example.json)
and fill its RouterOS-only and remaining exercise results locally. Keep that
file private. For SQLite restore, pass a private local backup file with
`--canary-sqlite-backup`; post-promotion runs also require
`--production-sqlite-backup`. Use a consistent SQLite backup made with the
application's SQLite Backup API (or an equivalent WAL-aware backup), not a
copy of only the main database file while WAL writes are active. The collector
opens each source read-only, restores it with SQLite's Backup API into a
temporary local copy, checks integrity, schema, and per-table row counts, and
removes the temporary copy. It enforces a 30-second deadline across SQLite
queries and backup work. On Windows it sets and verifies a protected ACL for
the current user on both the temporary directory and database file; on POSIX
it verifies owner-only directory/file modes. Failure to secure either path
fails closed. In pre-promotion mode it does not open or inspect a production
backup. Backup paths, filenames, database values, and schema text
are never included in the report. The input's `sqlite_restore_verified` and
timestamp fields are ignored and overwritten by this rehearsal. A missing,
oversized, unreadable, corrupt, or non-application backup fails that
environment's restore gate; it cannot pass using an optimistic input boolean.
The report exposes only whether row counts matched, never the counts themselves.
The v3 restore report binds each result to the immutable candidate image tag,
source revision, and registry digest. CI also exercises a WAL-backed source,
preflight low-space rejection, and interrupted-copy cleanup. These tests do
not simulate every real filesystem failure mode; an unexpected mid-copy disk
error is reported as restore failure, not as proof that the source was intact.

The collector also overwrites app health, readiness, timestamps, sample
counts, sample gaps, and Redis publish evidence. Unknown input fields are
dropped from output. Metrics output is restricted to aggregate health, Redis,
and outbox numbers; response bodies, labels, URLs, tokens, and cookies are
never written to the report. Create a separate one-hour API token for each
environment with only the `health.read` capability, and enter the canary token
at a secure PowerShell prompt for the pre-promotion run. The collector does
not create or revoke tokens:

The operator-measured session-event latency maximum and p95 must include measurement start/end
timestamps no more than 15 minutes before the collector window begins (or
during that window). The restore rehearsal is performed and timestamped by the
collector. Canary rollback and production-protection checks remain operator
exercises and must be timestamped within the preceding 24 hours (or during the
window). Missing, future-dated, or older exercise claims fail acceptance; do
not copy results from an earlier release. Local evidence files are not
cryptographic attestations and can be edited after collection. Release reports
therefore include an `evidence_authenticity` projection: Redis source evidence
is marked `github-attestation-claim-verified-during-collection-not-reverified-offline`,
meaning the collector verified the source artifact at collection time but the
local evaluator does not reverify that signature; rollback read-backs are
operator-attested and unsigned, and the final local report is unsigned. A `passed` value means
recorded acceptance gates passed under those stated evidence assumptions; it is
not a cryptographic signature over the overall report.

```powershell
$secureCanaryToken = Read-Host 'Canary health.read API token' -AsSecureString
try {
  $env:VPN_ACCEPTANCE_CANARY_TOKEN = [Net.NetworkCredential]::new('', $secureCanaryToken).Password
python scripts/collect_release_acceptance.py `
  --input private-evidence.json `
  --output private-collected-evidence.json `
  --routeros-report private-routeros-window.json `
  --redis-recovery-run-id 123456789 `
  --rollback-report private-rollback-rehearsal.json `
  --stream-observer-report private-stream-observation.json `
  --telemetry-acceptance-input private-telemetry-acceptance.ndjson `
  --canary-url https://<approved-canary-origin> `
  --production-url https://<approved-production-origin> `
  --canary-sqlite-backup private-canary-backup.sqlite3 `
  --canary-metrics-url https://<approved-canary-origin> `
  --canary-api-token-env VPN_ACCEPTANCE_CANARY_TOKEN `
  --duration-seconds 1800 --interval-seconds 60 `
  --phase canary-prepromotion
python scripts/release_acceptance.py --input private-collected-evidence.json `
  --output private-acceptance-report.json
} finally {
  Remove-Item Env:VPN_ACCEPTANCE_CANARY_TOKEN -ErrorAction SilentlyContinue
  $secureCanaryToken.Dispose()
}
```

After promotion, repeat with separately provisioned canary and production
`health.read` tokens, supplying both token-environment flags, both metrics
origins, and both `--canary-sqlite-backup` and
`--production-sqlite-backup` paths. Clear both environment variables and
dispose both secure strings in the `finally` block. In `canary-prepromotion`, a production token is neither
read nor required. If the compatibility `--cookie-env` option is used instead,
the cookie is sent only to enabled `/metrics` probes and only over HTTPS; avoid
reusing a broad dashboard session when scoped API tokens are available. Each
metrics origin must exactly match that environment's health/readiness origin
(scheme, hostname, and effective port). The acceptance
window is at least 30 minutes, with at least 30 health samples
per environment and no sample gap over 120 seconds. Duration is capped at 24
hours, sampling at 10,000 observations, and app-probe socket timeout at 30
seconds; redirects are not followed. Each GHCR digest lookup runs in a child
process with a hard wall-clock cap of the configured timeout plus a 0.5-second
cleanup margin, so a server trickling response headers cannot hold the
collector indefinitely. The collector checks the candidate tag/digest in a
pre-promotion run and both tag/digest pairs post-promotion against GHCR's
current OCI manifest; required unavailable or mismatched registry digests fail
closed. This is not an independent read-back of RouterOS's cached
image bytes: the current RouterOS container status exposes the configured tag,
not its local OCI digest. The report therefore explicitly records
`router_runtime_digest_verified: false`. Keep the output local or redact it
before sharing.
The app-level collector cannot independently prove router CPU/memory/storage,
VPN event latency/freshness, event loss/ordering, API interruption/recovery,
snapshot recovery, rollback, unauthenticated access, or secret-free logs. It
does rehearse SQLite restoration when the required local backup path(s) are
provided. REST/Binary snapshot parity is measured by the separate
RouterOS sampler below. Other listed checks remain real-router/operator
measurements and must be recorded in the input evidence; a successful HTTP
probe is not a substitute.

For repeatable RouterOS resource and container measurements, use the separate
local-only `scripts/collect_routeros_acceptance.py` sampler from a trusted
workstation that can reach both the router's TLS Binary API and private HTTPS
REST service. Every sample reads the same narrowly allowlisted resource,
container, and active-session fields over both transports; it fails acceptance
if either read fails or the normalized snapshots disagree. CPU readings allow
at most a 10 percentage-point difference to account for sequential sampling;
memory and storage percentages allow at most 1 point; active-session counts,
container state, and immutable revisions must match exactly. The REST reader
uses only HTTPS GET requests to `/rest/system/resource`, `/rest/container`,
and `/rest/ppp/active`, with `.proplist` restrictions, normal certificate
validation, no redirects, a 10-second timeout, and a 1 MiB response limit.
Never enable insecure TLS or expose either API to the Internet. Use a dedicated
read-only RouterOS account with only the `read`, `api`, and `rest-api` policies;
do not grant `write`, `policy`, or `sensitive`.

The sampler reads the RouterOS version from the allowlisted system-resource
response and selects the matching container lifecycle fields: `status` on
RouterOS 7.19 and earlier, and the `running`, `stopped`, `starting`, `stopping`,
and `healthy` flags on RouterOS 7.20 and later. Binary API and HTTPS REST use
the same version rule and shared lifecycle normalizer as the deployment tool.
Missing or malformed versions, unknown lifecycle values, contradictory state
flags, or unhealthy signals fail closed; a transition flag is never treated as
stopped. The collector never retries a failed property query with a broader
record dump.

The sampler accepts Binary API and REST credentials only from process
environment variables, with separate masked password prompts as fallback. Set
the REST URL as a credential-free HTTPS origin (no `/rest` suffix is required).
The output contains CPU, memory, and storage peaks, aggregate active-session
counts, named canary and production health, recognized immutable source
revisions, and REST-parity sample counts. It omits host, username, session
identities/addresses, IDs, container paths, environment lists, mounts, full
image strings, raw replies, and individual mismatching values. Keep the report
private and join its values with the corresponding deployment records locally.
REST/Binary parity is a snapshot consistency check, not an end-to-end event
latency or reconnect test; it does not replace the app-level collector or
controlled API interruption and rollback exercises.

Example PowerShell setup (enter the password only at the hidden prompt):

```powershell
$env:ROUTEROS_ACCEPTANCE_HOST = '<router DNS name covered by its API TLS certificate>'
$env:ROUTEROS_ACCEPTANCE_USERNAME = '<dedicated read-only API user>'
$env:ROUTEROS_ACCEPTANCE_REST_URL = 'https://<router DNS name covered by its HTTPS certificate>'
$env:ROUTEROS_ACCEPTANCE_REST_USERNAME = '<dedicated read-only REST user>'
python scripts/collect_routeros_acceptance.py `
  --output private-routeros-window.json `
  --canary-revision <full-canary-commit-sha> `
  --production-revision <full-production-commit-sha> `
  --duration-seconds 1800 --interval-seconds 60
Remove-Item Env:ROUTEROS_ACCEPTANCE_HOST, Env:ROUTEROS_ACCEPTANCE_USERNAME, `
  Env:ROUTEROS_ACCEPTANCE_REST_URL, Env:ROUTEROS_ACCEPTANCE_REST_USERNAME -ErrorAction SilentlyContinue
```

For private CAs, set `ROUTEROS_ACCEPTANCE_CA_FILE` and
`ROUTEROS_ACCEPTANCE_REST_CA_FILE` to their respective trusted PEM files for
the process. The collector fails closed on TLS errors, absent containers,
malformed capacity readings, missing/changed immutable revisions, sample
failures, incomplete windows, or gaps over two minutes. The source revision is
reported only when the container image matches this repository's immutable
ARM64 tag format, and each observation is checked against the expected
canary/production revision supplied on the command line; the router's locally
cached image digest remains unverified. It also fails if peak CPU exceeds 80%,
memory exceeds 90%, or storage exceeds 90%.

Each completed report is atomically replaced. If setup or collection fails, the
requested output is replaced with a sanitized `collected: false`,
`passed: false` failure report and the command exits nonzero. This prevents a
prior successful report at the same path from being mistaken for the latest
run.

To join RouterOS CPU/memory/storage and container observations to the app-level
soak automatically, run the RouterOS sampler concurrently with the app
collector, then pass its completed private report using the required
`--routeros-report`:

```powershell
python scripts/collect_release_acceptance.py `
  --input private-release-evidence.json `
  --output private-release-collection.json `
  --routeros-report private-routeros-window.json `
  --redis-recovery-run-id 123456789 `
  --rollback-report private-rollback-rehearsal.json `
  --stream-observer-report private-stream-observation.json `
  --telemetry-acceptance-input private-telemetry-acceptance.ndjson `
  --canary-url https://<private-canary-origin> `
  --production-url https://<private-production-origin> `
  --canary-sqlite-backup private-canary-backup.sqlite3 `
  --canary-metrics-url https://<private-canary-origin> `
  --phase canary-prepromotion
```

The join fails closed unless both reports cover the same 30-minute window
(within one minute), all RouterOS samples succeeded, both named containers
stayed healthy, and their observed immutable source revisions match the app
collector's revision tags. The release evaluator rechecks that joined metadata
and that the resource peaks match the deployment records. The RouterOS report
is read locally and its raw contents are not copied to console output; keep
both input and output files private. This join adds resource/container
evidence only—it does not infer event latency, reconnect, event integrity, or
any other operator-only acceptance result.

### Evidence-gated RouterOS promotion

The installed RouterOS scheduler must use the reviewed stage-only updater from
[`ROUTER_LOCAL_AUTOMATION.md`](ROUTER_LOCAL_AUTOMATION.md); an older updater
that promotes after readiness alone bypasses the full acceptance gate. The
stage-only updater writes a small pending record only after its canary
readiness soak and never changes production. The promotion controller requires
that record to match the collected candidate and the exact production baseline.

Set `ROUTEROS_REST_URL`, `ROUTEROS_DEPLOY_USERNAME`, and
`ROUTEROS_DEPLOY_PASSWORD` in the local process environment, plus
`ROUTEROS_REST_CA_PEM` if the router REST certificate uses a private CA. If the
app readiness endpoints use HTTPS with a private CA, set
`VPN_ACCEPTANCE_READY_CA_PEM` separately. Do not put any credential, readiness
URL, router address, or collected evidence in a public issue or repository.
The controller accepts HTTPS or direct private RFC1918 IPv4 HTTP on port 8080
for exact `/readyz` endpoints; it refuses redirects and does not use the public
Cloudflare Access page as readiness evidence.

First run the zero-write gate check from the same trusted local workstation
that can reach the router and private VETH endpoints:

```powershell
python -m scripts.promote_routeros_release `
  --input private-collected-evidence.json `
  --canary-ready-url http://<private-canary-ip>:8080/readyz `
  --production-ready-url http://<private-production-ip>:8080/readyz `
  --check-only
```

The command re-evaluates the fresh `canary-prepromotion` evidence at the time
of invocation, checks the exact project ARM64 candidate tag, confirms both live
RouterOS image tags and readiness revisions still match the report, and
compares the stage-only pending record. To promote after the read-only check
passes, run the same command without `--check-only`. The controller changes
only the named production container's immutable image/lifecycle, verifies the
candidate `/readyz`, records it as last good, and restores the prior image if
startup, readiness, or journal persistence fails. A failed candidate is
quarantined for the scheduler. It never uploads the report or changes mounts,
environment lists, `/data`, certificates, users, firewall, or OpenVPN policy.
After promotion, run the full `postpromotion` collector and evaluator; the
pre-promotion report does not assert production acceptance.

If a check fails, production must remain on its recorded prior immutable image.
Investigate and collect a new window; do not loosen or edit the report to make
the gate pass.
