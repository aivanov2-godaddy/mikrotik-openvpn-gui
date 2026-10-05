# RouterOS canary acceptance test

Use this procedure after public CI has passed and before an operator promotes a
new immutable image from canary to production. It is a repeatable, redacted
hardware-in-the-loop check; it complements the repository's automated tests.

The procedure is deliberately read-only except for the disposable canary
container and a disposable VPN profile. Do not paste router exports, passwords,
private keys, certificates, profile archives, public IP addresses, or real
domain names into an issue, pull request, or test result.

## Scope and prerequisites

Compatibility claims are evidence-scoped. CI image build/runtime smoke does not
prove RouterOS compatibility. PR #497, commit
`3eda7a15acb6fdb0f9749dfe0c2fd9efeeae714f`, published the immutable ARM64 tag
`ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-3eda7a15acb6fdb0f9749dfe0c2fd9efeeae714f-arm64`,
registry digest
`sha256:089e9c48c3e388cd08be3a44ddd9f525a0b50ea9e15983d6a8fa78e442fecc6c`.
Read-only RouterOS read-back confirmed that tag and healthy state on canary and
production. Canary `/readyz` returned the expected revision; a canary-only
rollback to the previous immutable image and forward recovery both returned
the expected ready revisions. Production was not restarted for the drill.
RouterOS reports the configured tag, not the registry digest. These are
point-in-time deployment observations, not completion of the controlled
latency/freshness, event-integrity, recovery, resource-soak, Redis-delivery, or
production rollback acceptance below. No resource minimum or cross-model/version
certification is inferred. These PR #497 observations are historical: the
2026-10-06 read-back lists PR #501 on canary while production remains on PR #497.
See the [current release record](RELEASES.md#latest-published-mainline-candidate-pr-501-2026-10-06).
The PR #501 candidate still requires its own readiness and rollback checks plus
the formal physical RouterOS acceptance below.
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

`scripts/collect_release_acceptance.py` samples `GET /healthz` and
`GET /readyz` on both private app origins. Post-promotion collection also
samples authenticated aggregate `GET /metrics` in both environments. During
`canary-prepromotion`, it samples metrics only from canary; production is checked
for health, readiness, and its separately recorded prior revision, without
requiring that older image to expose the candidate's metrics schema. If
`--cookie-env` is supplied, the short-lived cookie is sent only to the private
app probes that are enabled for that phase. Cookie-bearing probes require
HTTPS; the cookie and probe origins are never written to the report. It checks
each readiness revision against its own immutable image tag, records the
observation window and sample gaps, and requires complete Redis/outbox health
and process-observation metrics wherever metrics are part of that phase. Missing
or incomplete required metrics fail closed and clear any caller-supplied Redis
success claim. Process-observation ages for session events and traffic samples
are not end-to-end RouterOS-to-browser latency.

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
unknown outbox metrics, pending events, or any dead-lettered event observed in
the window fail acceptance. This prevents a single fresh sample or successful
publish from masking gaps or a stuck delivery queue.

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
sample gaps, and Redis publish evidence. Unknown input
fields are dropped from output. Metrics output is restricted to aggregate
health, Redis, and outbox numbers; response bodies, labels, URLs, and cookies
are never written to the report. Use a short-lived, least-privileged dashboard
session through an environment variable. Avoid
putting the cookie literal in a command line or shell history; enter it at a
secure prompt in the same PowerShell session:

```powershell
$secureCookie = Read-Host 'Short-lived session Cookie header value' -AsSecureString
try {
  $env:VPN_ACCEPTANCE_COOKIE = [Net.NetworkCredential]::new('', $secureCookie).Password
python scripts/collect_release_acceptance.py `
  --input private-evidence.json `
  --output private-collected-evidence.json `
  --canary-url https://<approved-canary-origin> `
  --production-url https://<approved-production-origin> `
  --canary-metrics-url https://<approved-canary-origin> `
  --cookie-env VPN_ACCEPTANCE_COOKIE `
  --duration-seconds 1800 --interval-seconds 60 `
  --phase canary-prepromotion
python scripts/release_acceptance.py --input private-collected-evidence.json `
  --output private-acceptance-report.json
} finally {
  Remove-Item Env:VPN_ACCEPTANCE_COOKIE -ErrorAction SilentlyContinue
  $secureCookie.Dispose()
}
```

Cookies are sent only to HTTPS origins. Each metrics origin must exactly match
that environment's health/readiness origin (scheme, hostname, and effective
port). The acceptance
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

Promote only a fully passing candidate through the operator-installed
[router-local automation](ROUTER_LOCAL_AUTOMATION.md). If a check needs review,
leave production on its current immutable image and investigate in the local
router environment.
