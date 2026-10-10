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
prove RouterOS compatibility. PR #504, commit
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

This is point-in-time deployment and live-health evidence, not completion of
the controlled latency/freshness, session-event, event-integrity, recovery,
resource-soak, Redis-delivery, restore, or rollback acceptance below. The PR
#504 image is already configured on production, so its remaining collector run
uses `--phase postpromotion` with both environments on the same candidate; a
canary-prepromotion run applies to a later candidate while production remains
on its prior image. No resource minimum or cross-model/version certification is
inferred. See the [current release
record](RELEASES.md#latest-published-mainline-candidate-pr-504-2026-10-06).
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

`scripts/collect_release_acceptance.py` samples `GET /healthz` and
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

The final release evaluator requires the collector's timestamped result; a
deployment-only evidence file cannot pass. Its collection window must cover at
least 30 minutes, match both deployment observation windows, and end no more
than 15 minutes before evaluation. Timestamps more than five minutes in the
future fail closed to tolerate only small clock skew. The standalone telemetry
evaluator applies the same 15-minute freshness and five-minute future-skew
limits to its latest sample. Rerun the read-only collector when evidence is
stale; do not edit timestamps by hand.

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

```powershell
$secureCanaryToken = Read-Host 'Canary health.read API token' -AsSecureString
try {
  $env:VPN_ACCEPTANCE_CANARY_TOKEN = [Net.NetworkCredential]::new('', $secureCanaryToken).Password
python scripts/collect_release_acceptance.py `
  --input private-evidence.json `
  --output private-collected-evidence.json `
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
The collector cannot independently prove router CPU/memory/storage, VPN event
latency/freshness, event loss/ordering, API interruption/recovery, snapshot
recovery, REST/Binary parity, SQLite restore, rollback, unauthenticated access,
or secret-free logs. Those remain real-router/operator measurements and must be
recorded in the input evidence; a successful HTTP probe is not a substitute.

For repeatable RouterOS resource and container measurements, use the separate
local-only `scripts/collect_routeros_acceptance.py` sampler from a trusted
workstation that can reach the router's TLS Binary API. It accepts credentials
only from process environment variables (with a masked password prompt as the
fallback), uses normal TLS certificate validation, and issues only these
allowlisted read commands with narrow `.proplist` fields:
`/system/resource/print`, `/container/print`, and `/ppp/active/print`. Use a
dedicated RouterOS account with only the `read` and `api` policies. Never enable
insecure TLS or expose the API port to the Internet. The output contains CPU,
memory, and storage peaks, aggregate active-session counts, named canary and
production health, and recognized immutable source revisions; it omits host,
username, session identities/addresses, IDs, container paths, environment
lists, mounts, full image strings, and raw RouterOS replies. Keep the report
private and join its values with the corresponding deployment records locally.
It is not an end-to-end event-latency or reconnect test, and its sample does
not replace the app-level collector or the required controlled API interruption
and rollback exercises.

Example PowerShell setup (enter the password only at the hidden prompt):

```powershell
$env:ROUTEROS_ACCEPTANCE_HOST = '<router DNS name covered by its API TLS certificate>'
$env:ROUTEROS_ACCEPTANCE_USERNAME = '<dedicated read-only API user>'
python scripts/collect_routeros_acceptance.py `
  --output private-routeros-window.json `
  --canary-revision <full-canary-commit-sha> `
  --production-revision <full-production-commit-sha> `
  --duration-seconds 1800 --interval-seconds 60
Remove-Item Env:ROUTEROS_ACCEPTANCE_HOST, Env:ROUTEROS_ACCEPTANCE_USERNAME -ErrorAction SilentlyContinue
```

For a private CA, set `ROUTEROS_ACCEPTANCE_CA_FILE` to its trusted PEM file for
the process. The collector fails closed on TLS errors, absent containers,
malformed capacity readings, missing/changed immutable revisions, sample
failures, incomplete windows, or gaps over two minutes. The source revision is
reported only when the container image matches this repository's immutable
ARM64 tag format, and each observation is checked against the expected
canary/production revision supplied on the command line; the router's locally
cached image digest remains unverified. It also fails if peak CPU exceeds 80%,
memory exceeds 90%, or storage exceeds 90%.

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
