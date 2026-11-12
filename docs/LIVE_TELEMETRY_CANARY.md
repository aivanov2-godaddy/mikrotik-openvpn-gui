# Live telemetry canary procedure

This procedure describes a local comparison tool for caller-supplied redacted
samples. The comparator itself does not query RouterOS, collect live snapshots,
measure resources or event latency, run reconnect/reconciliation tests, change
transports, or authorize a release. It is intentionally separate from the
production watchdog.

## What the comparator checks

- The supplied redacted session identifier sets match under the configured
  missing/extra limits.
- Every sample has a finite `binary_timestamp` that is present, not future
  dated, and no older than the configured maximum age.
- The configured number of consecutive supplied samples passes those checks.

`ready_to_promote` from this comparator means only that its input file meets
these local comparison rules. It is not a release or promotion decision and
does not prove that the samples came from RouterOS or that the browser received
live updates. Use the candidate-bound collectors and acceptance gates in
`docs/ROUTEROS_ACCEPTANCE.md` for deployed evidence.

## Capture and compare privately

The operator harness should write newline-delimited JSON to a private file or
pipe. Each record must contain only redacted session records and a Unix
`binary_timestamp` captured with the Binary API snapshot. This schema example
uses a placeholder; substitute the real capture-time integer before use:

```text
{"legacy":[{"id":"opaque-1"}],"binary":[{"id":"opaque-1"}],"binary_timestamp":<capture-time-unix-seconds>}
```

Do not commit this file, paste it into an issue, or send it to a public service.
Run the comparator locally:

```text
python telemetry_canary.py --input private-samples.ndjson \
  --max-age 10 --required-consecutive 3
```

The command prints only counts, age, reason, and local comparison readiness.
Missing or future timestamps fail closed and do not contribute to the
consecutive healthy count. Exit code `0` means the supplied consecutive samples
pass this comparator's rules; exit code `1` means the local comparison is not
ready; exit code `2` means the input was invalid.

After the session comparison, run the resource-impact gate against a separate
redacted NDJSON file. The file may contain only numeric measurements and the
transport name:

```json
{"transport":"binary","latency_ms":180,"event_age_seconds":0.7,"router_cpu_percent":22,"router_memory_percent":34,"router_storage_percent":12,"container_healthy":true,"reconnects":0,"event_lost":false}
```

```text
python scripts/telemetry_baseline.py --input private-baseline.ndjson \
  --max-latency-p95-ms 1000 --max-event-age-seconds 2 \
  --max-router-cpu-percent 80 --max-router-memory-percent 90 --max-router-storage-percent 90
```

Exit code `0` means every configured gate passed, `1` means evidence failed a
gate, and `2` means the input was invalid. The output contains aggregates and
gate names only; it never echoes source samples.

The evaluator enforces an allowlist of fields for each record type. Unknown
fields—including credentials, addresses, raw RouterOS records, and identifiers—
are rejected with a generic validation error before they can enter evaluation.
All numeric limits must be finite and non-negative; `NaN` and infinities are
invalid inputs, not ways to disable an acceptance threshold.

For the complete acceptance report, combine resource samples with reconnect,
ordering, counter-reset, and security checks. Values such as
`visible_without_refresh`, `api_interruption_tested`, and
`binary_matches_rest` are assertions supplied by the harness; the JSON
validator does not independently observe those events. Keep the original
candidate-bound collection and its limits in view when evaluating the report:

The example assumes periodic sample records span the full 30-minute interval
from `1728000000` through `1728001800`; intermediate sample lines are omitted.
Every attestation timestamp below falls inside that same interval.
The origin field is a placeholder for the locally approved value; keep the
actual origin out of evidence files and public reports.

```json
{"type":"deployment_identity","origin":"<approved-canary-origin>","candidate_revision":"<full-candidate-sha>","observed_revision":"<full-candidate-sha>","observed_at":1728000900}
{"type":"sample","observed_at":1728000000,"transport":"binary","latency_ms":180,"event_age_seconds":0.7,"router_cpu_percent":22,"router_memory_percent":34,"router_storage_percent":12,"event_epoch":0,"event_sequence":101,"event_lost":false,"event_duplicated":false,"out_of_order":false}
{"type":"session_transition","observed_at":1728000300,"connected":true,"visible_without_refresh":true,"latency_ms":180}
{"type":"session_transition","observed_at":1728000600,"connected":false,"visible_without_refresh":true,"latency_ms":220}
{"type":"traffic_update","observed_at":1728000900,"rx_bytes":1000,"tx_bytes":400,"visible_without_refresh":true,"event_age_seconds":0.7}
{"type":"traffic_update","observed_at":1728000960,"rx_bytes":1250,"tx_bytes":460,"visible_without_refresh":true,"event_age_seconds":0.8}
{"type":"reconnect","observed_at":1728000600,"recovery_seconds":4.2,"snapshot_recovered":true,"api_interruption_tested":true,"rest_fallback_available":true}
{"type":"comparison","observed_at":1728000900,"binary_matches_rest":true}
{"type":"security","observed_at":1728001200,"unauthenticated_denied":true,"secret_bearing_payload":false,"secret_free_logs":true}
{"type":"verification","observed_at":1728001740,"event_latency_measured":true,"traffic_freshness_measured":true,"counter_reset_tested":true,"event_integrity_tested":true,"binary_rest_parity_tested":true,"secret_scan_complete":true}
```

```text
python scripts/telemetry_acceptance.py --input private-acceptance.ndjson --candidate-revision <full-candidate-sha> --max-session-event-latency-ms 1000
```

The release collector independently samples the configured, allowlisted
canary `/readyz` origin over certificate-verified HTTPS without following redirects throughout the full
soak. Every readiness sample must match the candidate revision, and the
timestamped NDJSON identity plus the complete telemetry sample window must fit
inside that same observed interval. A one-shot identity check cannot establish
the identity of an earlier 30-minute telemetry window; therefore the standalone
CLI's single check is diagnostic only and cannot pass the release identity gate.
This is origin/revision binding, not a cryptographic signature over browser
events.

Every sample requires `observed_at`, a non-negative Unix timestamp in seconds.
Session-transition, reconnect, comparison, security, and verification records also require
`observed_at`. Each such attestation must fall within the inclusive interval
between the first and last valid sample timestamps; missing, stale, or future
attestations fail closed. This prevents an old reconnect or security check from
being reused to pass a new soak window.
The evaluator requires a timestamped 30-minute observation window, at least
30 samples, a boolean container-health observation on every sample, no gap
between adjacent samples over 120 seconds, and at least 30
measurements each for event latency, traffic freshness, router CPU, memory,
and storage. It also requires at least 30 sequenced events so event-integrity
checks are based on more than a single observation. These minimums match the
release acceptance collector's 30-minute soak and 30-health-sample floor.
Missing container-health coverage fails with
`container_health_sample_coverage`.

The command emits only aggregate metrics and failed gate names. It also
requires timestamped, ordered session-transition records showing the test
client connected and later disconnected, with both changes visible without a
page refresh. Every transition must carry its own measured `latency_ms`, which
must meet the configured latency target; unrelated periodic latency samples do
not stand in for transition latency. It also requires at least two timestamped
traffic-update records with numeric receive/transmit byte counters that differ
between observations; each update must be visible without a refresh and carry
its own `event_age_seconds` within the configured freshness target. Self-reported
booleans or unrelated sample ages cannot substitute for measured linked values.
The evaluator also requires at least one
reconnect test, one security test, and one explicit
verification record that itself covers every precision, reset, ordering, parity, and
secret-scan gate. Each passing window must also contain at least one CPU,
memory, and storage measurement; missing values fail independently with
`router_cpu_measurement_missing`, `router_memory_measurement_missing`, or
`router_storage_measurement_missing`. A window without those observations or
attestations cannot report pass. Flags split across multiple partial
verification records do not combine; an incomplete record set fails with
`verification_record_incomplete`.

The live release collector independently gates each sampled telemetry window:
traffic-counter sample age must remain at or below 2 seconds, the bounded
gateway enqueue-to-authorized-client-poll p95 must remain at or below 1 second,
and the Binary API supervisor must remain enabled and healthy. The collector
also requires the aggregate `vpn_dashboard_integration_outbox_storage_failures_total`
counter to start at zero and fail the window if it increases or resets. It checks
`vpn_dashboard_process_start_time_seconds` on every scrape and fails if the
process restarted after the observation window began; this catches a restart
that could otherwise reset the storage-failure counter between samples. Run
intentional fault injection outside the final 30-minute soak. Missing traffic
freshness, gateway-delay, or outbox-storage observations fail closed. The gateway p95 is a
server-side delivery stage only; it is not a measurement of RouterOS-to-browser
session-change latency or browser rendering. A real session transition and its
end-to-end latency still require a controlled operator acceptance test and
timestamped evidence; idle periods cannot be interpreted as zero latency.
When the collected v1 report is passed to `release_acceptance.py`, its
`collection.passed` flag and empty `collection.failed_gates` are also required;
optimistic deployment-record fields cannot override a failed live probe window.
The final release evaluator also rejects a missing collector record, a window
shorter than 30 minutes, mismatched deployment/collector timestamps, windows
ending more than 15 minutes before evaluation, and timestamps more than five
minutes in the future. The standalone telemetry evaluator applies the same
freshness and future-skew bounds to its latest sample. Collect fresh evidence
instead of changing recorded timestamps.

For the release gate, `collect_release_acceptance.py` invokes the telemetry
evaluator with the readiness samples it directly collected over the same soak.
The standalone one-shot command cannot supply that trusted interval. The release
gate emits a redacted
`vpn-dashboard-telemetry-acceptance-v3` aggregate: measured session-transition
p95 and maximum latency plus no-refresh visibility counts, traffic-update visibility and maximum
sample age, sequence/gap/duplicate/order counts, and API reconnect/snapshot
results with the sample window. `collect_release_acceptance.py` combines that
with the independent `telemetry_stream_observer.py` report. Both must cover
the same 30-minute canary collector window (within five seconds), be recent,
and pass their own strict field allowlists. The Socket.IO observer must see a
reconnect followed by a snapshot and retain no payloads; browser evidence must
show connected and disconnected states plus changing visible traffic. Missing
or malformed evidence is a release failure, not an optional enhancement.

`event_sequence` is checked within an `event_epoch` (a non-negative integer
identifying one telemetry-process sequence lifetime); omitted epochs default
to `0`. A stream must start in epoch `0`; every epoch change must increment by
exactly one and be covered by a timestamped API-interruption/reconnect record
that confirms snapshot recovery between adjacent sequenced samples. Arbitrary
epoch changes cannot be used to hide sequence gaps. Within an epoch, a repeated
sequence is counted as a duplicate; a previously unseen value lower than the
highest observed sequence is counted as out of order; a forward jump is event
loss. These classifications describe the submitted evidence only and do not
prove the capture itself is complete.

## Acceptance window

1. Start the candidate in a separate canary container with the same read-only
   credentials and trust material. Keep `/data` and `/config` separate from
   production.
2. Confirm `/readyz`, authenticated REST status, and the existing `/api/events`
   stream remain healthy.
3. Collect at least three healthy comparisons, then exercise a temporary API
   disconnect and verify bounded reconnect/backoff plus a reconciliation
   snapshot.
4. Record CPU, memory, storage, container health, sample age, reconnect count,
   event ordering, Binary/REST parity, fallback availability, and secret-scan
   results for the observation window. No certificate, profile, user, firewall,
   or VPN action is part of this test.
5. Promote only the same immutable SHA image after the evidence is reviewed.
   If any check fails, leave production unchanged and follow
   `docs/LIVE_TELEMETRY_ROLLBACK.md`.

## Explicit non-goals

The canary never enables a mutable image tag, changes RouterOS configuration,
rotates the OpenVPN CA, creates or revokes certificates, modifies profiles,
or copies SQLite/router-local data into the public repository.
