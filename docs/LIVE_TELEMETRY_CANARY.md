# Live telemetry canary procedure

This procedure validates the Binary API telemetry path without changing
RouterOS policy or VPN data. It is intentionally separate from the production
watchdog and uses only immutable images.

## What the canary proves

- Binary API-SSL and the redacted broker see the same session set as the
  existing REST snapshot.
- The Binary API snapshot is fresh and remains healthy for consecutive samples.
- Reconnect and reconciliation tests pass without RouterOS mutations.
- Router CPU, memory, event latency, and reconnect behavior stay within the
  acceptance targets in `docs/LIVE_TELEMETRY_PLAN.md`.

## Capture and compare privately

The operator harness should write newline-delimited JSON to a private file or
pipe. It must contain only redacted session records, for example:

```json
{"legacy":[{"id":"opaque-1"}],"binary":[{"id":"opaque-1"}],"binary_timestamp":1720000000}
```

Do not commit this file, paste it into an issue, or send it to a public service.
Run the comparator locally:

```text
python telemetry_canary.py --input private-samples.ndjson \
  --max-age 10 --required-consecutive 3
```

The command prints only counts, age, reason, and promotion readiness. Exit code
`0` means the required consecutive healthy samples were observed. Exit code `1`
means the canary is not ready; exit code `2` means the input was invalid.

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

For the complete acceptance report, combine resource samples with reconnect,
ordering, counter-reset, and security checks:

The example assumes periodic sample records span the full 30-minute interval
from `1728000000` through `1728001800`; intermediate sample lines are omitted.
Every attestation timestamp below falls inside that same interval.

```json
{"type":"sample","observed_at":1728000000,"transport":"binary","latency_ms":180,"event_age_seconds":0.7,"router_cpu_percent":22,"router_memory_percent":34,"router_storage_percent":12,"event_epoch":0,"event_sequence":101,"event_lost":false,"event_duplicated":false,"out_of_order":false}
{"type":"reconnect","observed_at":1728000600,"recovery_seconds":4.2,"snapshot_recovered":true,"api_interruption_tested":true,"rest_fallback_available":true}
{"type":"comparison","observed_at":1728000900,"binary_matches_rest":true}
{"type":"security","observed_at":1728001200,"unauthenticated_denied":true,"secret_bearing_payload":false,"secret_free_logs":true}
{"type":"verification","observed_at":1728001740,"event_latency_measured":true,"traffic_freshness_measured":true,"counter_reset_tested":true,"event_integrity_tested":true,"binary_rest_parity_tested":true,"secret_scan_complete":true}
```

```text
python scripts/telemetry_acceptance.py --input private-acceptance.ndjson
```

Every sample requires `observed_at`, a non-negative Unix timestamp in seconds.
Reconnect, comparison, security, and verification records also require
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
requires at least one reconnect test, one security test, and one explicit
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
and the Binary API supervisor must remain enabled and healthy. Missing traffic
freshness or gateway-delay observations fail closed. The gateway p95 is a
server-side delivery stage only; it is not a measurement of RouterOS-to-browser
session-change latency or browser rendering. A real session transition and its
end-to-end latency still require a controlled operator acceptance test and
timestamped evidence; idle periods cannot be interpreted as zero latency.
When the collected v1 report is passed to `release_acceptance.py`, its
`collection.passed` flag and empty `collection.failed_gates` are also required;
optimistic deployment-record fields cannot override a failed live probe window.

`event_sequence` is checked within an `event_epoch` (a non-negative integer
identifying one telemetry-process sequence lifetime); omitted epochs default
to `0`. Use a new epoch when the broker process restarts and its process-local
sequence counter resets. Within an epoch, a repeated sequence is counted as a
duplicate; a previously unseen value lower than the highest observed sequence
is counted as out of order; a forward jump is event loss. Epoch changes are
reported as boundaries, not as resets or gaps. These classifications describe
the submitted evidence only and do not prove the capture itself is complete.

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
