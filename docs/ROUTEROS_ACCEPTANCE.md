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
prove RouterOS compatibility. The current mainline candidate is PR #674, commit
`3d65b43ec4b796eb83f52929c56c9efabb980b4d`, with ARM64 registry digest
`sha256:c2318a464f1a57d86ae27b9103aa5addbcae3bfe43aca3d60fdba7728c9f4fbb`
and AMD64 registry digest
`sha256:7bd258595485a682ecc3892d32caaf29c9eecae377ec19b4f2071f702117f909`.
Both architectures passed published-runtime smoke tests and image/SBOM
attestation verification. A 2026-10-13 15:47 EEST RouterOS read-back showed
the canary still running the prior healthy image with zero active PPP sessions;
production was not re-read after this publication. Candidate-specific RouterOS
deployment and acceptance have not been recorded. Do not treat older deployment
observations below as evidence for this candidate.
The previous PR #504, commit
`a62724c94261b00866fa3d55416a7b540305d40b`, published the ARM64 image
`ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-a62724c94261b00866fa3d55416a7b540305d40b-arm64`,
registry digest
`sha256:2b1d249c4219302305ce54e73b856dc22f5b884ff786b083ea18de2868e454af`.
The 2026-10-06 read-only RouterOS read-back showed this configured tag on both
canary and production, each healthy (`H`), with Redis running (`R`). The
authenticated production dashboard showed `Live · SOCKETIO` and Operational
health; its CPU health value and router uptime changed across two observations
without a page reload. There were no connected VPN users. RouterOS reports its
configured tag, not the cached registry digest.

That is historical point-in-time deployment and live-health evidence, not
completion of the controlled latency/freshness, session-event, event-integrity,
recovery, resource-soak, Redis-delivery, restore, or rollback acceptance below.
The PR
No assertion is made here that the current PR #674 candidate is configured on
canary or production. First read back the exact configured immutable tag and
health on the canary, then run the pre-promotion collector for that candidate.
Do not promote until the report passes and rollback has been rehearsed. No
resource minimum or cross-model/version certification is inferred. See the
[current release record](RELEASES.md#latest-published-mainline-candidate-pr-674-2026-10-13).
The PR #497 rollback/readiness results described in the [historical release
record](RELEASES.md#previously-published-mainline-image-pr-497-2026-10-05)
remain historical and do not prove PR #504's canary readiness or rollback.
See the [installation compatibility
matrix](INSTALLATION.md#compatibility-and-support-matrix) and [historical release record](RELEASES.md#previously-published-mainline-image-pr-497-2026-10-05).

- Use one immutable candidate for the canary, such as
  `ghcr.io/<owner>/mikrotik-openvpn-gui:sha-<40-character-commit>-arm64`.
  Record its exact tag and digest. For a pre-promotion run, also record
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
needed for the test, and keep raw terminal output private.

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
/container/stop [find where name="vpn-dashboard-canary"]
/container/set [find where name="vpn-dashboard-canary"] remote-image="ghcr.io/<owner>/mikrotik-openvpn-gui:sha-<previous-commit>-arm64"
/container/update [find where name="vpn-dashboard-canary"]
/container/start [find where name="vpn-dashboard-canary"]
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

The collector is read-only: it issues HTTP GET/HEAD probes to the private app
and GHCR and never changes RouterOS/container configuration, promotes an image,
or performs rollback. A passing collection is not a promotion action and does
not execute or prove the required rollback rehearsal; that remains a separate
controlled RouterOS procedure.

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
`vpn-dashboard-telemetry-acceptance-v1` aggregate with its sample window,
browser-visible connect/disconnect and traffic-update counts, transition
latency p95, maximum traffic-sample age, sequence/gap/duplicate/order counts,
and reconnect-test outcome. The release collector takes only those allowlisted
aggregates; it does not copy raw NDJSON records or extra caller fields into the
final evidence. A passing window requires visible connect and disconnect
transitions without refresh, visible changing traffic updates, session-event
p95 at most 1,000 ms, session-event and traffic-sample ages at most 2 seconds,
at least 30 sequence observations, zero sequence gaps/duplicates/out-of-order
events, and a successful API-interruption plus snapshot-recovery test. The Socket.IO
observer independently requires a reconnect, a snapshot after that reconnect,
a connected stream at the end, and clean sequence continuity. Either report
missing, failed, stale, shorter than 30 minutes, or outside the app-collector
window by more than five seconds fails closed. Report end times must also be
no more than 15 minutes old when evaluated. The final release evaluator
revalidates the reports and matching window rather than trusting the
collector's `passed` flag alone.

Run these captures concurrently from separate trusted local terminals. Keep
the NDJSON input and observer output private; never place raw event frames,
identities, addresses, or secrets in either file:

```powershell
# Terminal 1: authenticated, redacted Socket.IO observation of the canary.
python scripts/telemetry_stream_observer.py `
  --canary-origin https://<approved-canary-origin> `
  --cookie-env VPN_CANARY_COOKIE `
  --duration-seconds 1800 `
  --output private-stream-observation.json

# Terminal 2 / trusted browser harness: capture redacted
# sample/session/traffic/reconnect records during the same window into
# private-telemetry-acceptance.ndjson. Run telemetry_acceptance.py against it
# after collection if you want the standalone diagnostic summary.

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
and fill its RouterOS-only and exercise results locally. Keep that file private.
The collector overwrites app health, readiness, timestamps, sample counts,
sample gaps, and Redis publish evidence. Unknown input fields are dropped from
output. Metrics output is restricted to aggregate health, Redis, and outbox
numbers; response bodies, labels, URLs, tokens, and cookies are never written
to the report. Create a separate one-hour API token for each environment with
only the `health.read` capability, and enter the canary token at a secure
PowerShell prompt for the pre-promotion run. The collector does not create or
revoke tokens:

The operator-measured session-event p95 must include measurement start/end
timestamps no more than 15 minutes before the collector window begins (or
during that window). SQLite restore, canary rollback, and production-protection
checks must be timestamped within the preceding 24 hours (or during the
window). Missing, future-dated, or older manual exercise claims fail
acceptance; do not copy results from an earlier release. The evaluator still
labels these operator-entered checks as manual evidence; a timestamp is not a
cryptographic attestation of the action.

```powershell
$secureCanaryToken = Read-Host 'Canary health.read API token' -AsSecureString
try {
  $env:VPN_ACCEPTANCE_CANARY_TOKEN = [Net.NetworkCredential]::new('', $secureCanaryToken).Password
python scripts/collect_release_acceptance.py `
  --input private-evidence.json `
  --output private-collected-evidence.json `
  --routeros-report private-routeros-window.json `
  --stream-observer-report private-stream-observation.json `
  --telemetry-acceptance-input private-telemetry-acceptance.ndjson `
  --canary-url https://<approved-canary-origin> `
  --production-url https://<approved-production-origin> `
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
`health.read` tokens, supplying both token-environment flags and both metrics
origins. Clear both environment variables and dispose both secure strings in
the `finally` block. In `canary-prepromotion`, a production token is neither
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
snapshot recovery, SQLite restore, rollback, unauthenticated access, or
secret-free logs. REST/Binary snapshot parity is measured by the separate
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
  --stream-observer-report private-stream-observation.json `
  --telemetry-acceptance-input private-telemetry-acceptance.ndjson `
  --canary-url https://<private-canary-origin> `
  --production-url https://<private-production-origin> `
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
