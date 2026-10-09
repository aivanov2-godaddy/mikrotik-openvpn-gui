"""Evaluate a redacted live-telemetry acceptance window.

The input is newline-delimited JSON captured by an operator harness.  It is
deliberately limited to measurements and boolean test results; RouterOS
records, credentials, addresses, and identifiers must never be included.

Accepted record types are ``sample``, ``session_transition``, ``reconnect``,
``comparison``, ``security``, and ``verification``.  A
sample may contain the fields understood by :mod:`scripts.telemetry_baseline`
plus ``event_sequence``, ``event_lost``, ``event_duplicated``,
``out_of_order``, ``counter_reset``, and ``counter_reset_recovered``.
A verification record explicitly attests that the operator collected latency,
freshness, counter-reset, event-integrity, parity, and complete secret-scan
evidence during the same window.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
import time
from pathlib import Path
from typing import Any, Iterable, TextIO

try:
    from telemetry_baseline import summarize
except ModuleNotFoundError:  # Imported as ``scripts.telemetry_acceptance`` in tests.
    from scripts.telemetry_baseline import summarize

MIN_OBSERVATION_SECONDS = 1800
MIN_SAMPLES = 30
MAX_SAMPLE_GAP_SECONDS = 120
MAX_OBSERVATION_AGE_SECONDS = 900
MAX_FUTURE_SKEW_SECONDS = 300


def _source(path: str) -> TextIO:
    if path == "-":
        return sys.stdin
    return Path(path).open("r", encoding="utf-8")


def _boolean(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{name} must be boolean")
    return value


def _number(value: Any, name: str) -> float:
    if isinstance(value, bool):
        raise ValueError(f"{name} must be numeric")
    try:
        result = float(value)
    except (TypeError, ValueError) as error:
        raise ValueError(f"{name} must be numeric") from error
    if not math.isfinite(result) or result < 0:
        raise ValueError(f"{name} must be finite and non-negative")
    return result


def evaluate(
    lines: Iterable[str], *, limits: dict[str, float], now: float | None = None
) -> tuple[int, dict[str, Any]]:
    samples: list[str] = []
    session_transitions: list[dict[str, Any]] = []
    reconnects: list[dict[str, Any]] = []
    comparisons: list[dict[str, Any]] = []
    security: list[dict[str, Any]] = []
    sequence_epochs: dict[int, dict[str, Any]] = {}
    failures: list[str] = []
    counter_resets = 0
    counter_reset_failures = 0
    duplicate_events = 0
    out_of_order_events = 0
    sequence_evidence = 0
    counter_reset_evidence = 0
    sample_timestamps: list[float] = []
    attestation_timestamps: list[tuple[str, float]] = []
    verification_records: list[dict[str, bool]] = []
    required_verifications = (
        "event_latency_measured",
        "traffic_freshness_measured",
        "counter_reset_tested",
        "event_integrity_tested",
        "binary_rest_parity_tested",
        "secret_scan_complete",
    )
    verification = {name: False for name in required_verifications}

    for line in lines:
        if not line.strip():
            continue
        record = json.loads(line)
        if not isinstance(record, dict):
            raise ValueError("each record must be a JSON object")
        record_type = record.get("type", "sample")
        if isinstance(record_type, str) and record_type in {
            "session_transition", "reconnect", "comparison", "security", "verification"
        }:
            if "observed_at" not in record:
                failures.append(f"{record_type}_timestamp_missing")
            else:
                attestation_timestamps.append((record_type, _number(record["observed_at"], "observed_at")))
        if record_type == "sample":
            samples.append(json.dumps(record, separators=(",", ":")))
            if "observed_at" not in record:
                failures.append("sample_timestamp_missing")
            else:
                sample_timestamps.append(_number(record["observed_at"], "observed_at"))
            if "event_sequence" in record:
                raw_sequence = record["event_sequence"]
                if isinstance(raw_sequence, bool) or not isinstance(raw_sequence, int) or raw_sequence < 0:
                    raise ValueError("event_sequence must be a non-negative integer")
                raw_epoch = record.get("event_epoch", 0)
                if isinstance(raw_epoch, bool) or not isinstance(raw_epoch, int) or raw_epoch < 0:
                    raise ValueError("event_epoch must be a non-negative integer")
                sequence = raw_sequence
                epoch = sequence_epochs.setdefault(raw_epoch, {"last": None, "seen": set()})
                last_sequence = epoch["last"]
                if last_sequence is not None and sequence > last_sequence + 1:
                    failures.append("event_loss")
                inferred_duplicate = sequence in epoch["seen"]
                inferred_out_of_order = last_sequence is not None and sequence < last_sequence
                epoch["seen"].add(sequence)
                if last_sequence is None or sequence > last_sequence:
                    epoch["last"] = sequence
                sequence_evidence += 1
            else:
                inferred_duplicate = False
                inferred_out_of_order = False
            duplicate_flag = False
            out_of_order_flag = False
            for name in ("event_lost", "event_duplicated", "out_of_order"):
                if name in record and _boolean(record[name], name):
                    if name == "event_lost":
                        failures.append("event_loss")
                    elif name == "event_duplicated":
                        duplicate_flag = True
                    else:
                        out_of_order_flag = True
            duplicate_events += int(duplicate_flag or inferred_duplicate)
            out_of_order_events += int(out_of_order_flag or inferred_out_of_order)
            counter_reset = (
                _boolean(record["counter_reset"], "counter_reset")
                if "counter_reset" in record
                else False
            )
            counter_reset_recovered = (
                _boolean(record["counter_reset_recovered"], "counter_reset_recovered")
                if "counter_reset_recovered" in record
                else False
            )
            if counter_reset:
                counter_resets += 1
                if not counter_reset_recovered:
                    counter_reset_failures += 1
                else:
                    counter_reset_evidence += 1
        elif record_type == "session_transition":
            session_transitions.append(record)
            for field, gate in (
                ("test_client_connected", "test_client_session_missing"),
                ("connect_visible_without_refresh", "connect_event_visibility"),
                ("disconnect_visible_without_refresh", "disconnect_event_visibility"),
                ("traffic_changed_without_refresh", "traffic_update_visibility"),
            ):
                if field not in record:
                    failures.append(f"{gate}_evidence_missing")
                elif not _boolean(record[field], field):
                    failures.append(gate)
        elif record_type == "reconnect":
            reconnects.append(record)
            interrupted = _boolean(record.get("api_interruption_tested"), "api_interruption_tested")
            if not interrupted:
                failures.append("api_interruption_test")
            recovered = _boolean(record.get("snapshot_recovered"), "snapshot_recovered")
            recovery_seconds = _number(record.get("recovery_seconds"), "recovery_seconds")
            if not recovered:
                failures.append("snapshot_recovery")
            if recovery_seconds > limits["recovery_seconds"]:
                failures.append("recovery_time")
            fallback = _boolean(record.get("rest_fallback_available"), "rest_fallback_available")
            if not fallback:
                failures.append("rest_fallback")
        elif record_type == "comparison":
            comparisons.append(record)
            if not _boolean(record.get("binary_matches_rest"), "binary_matches_rest"):
                failures.append("binary_rest_mismatch")
        elif record_type == "security":
            security.append(record)
            if not _boolean(record.get("unauthenticated_denied"), "unauthenticated_denied"):
                failures.append("unauthenticated_access")
            if _boolean(record.get("secret_bearing_payload"), "secret_bearing_payload"):
                failures.append("secret_exposure")
            if not _boolean(record.get("secret_free_logs"), "secret_free_logs"):
                failures.append("secret_exposure")
        elif record_type == "verification":
            current: dict[str, bool] = {}
            for name in required_verifications:
                if name in record:
                    current[name] = _boolean(record[name], name)
                    verification[name] = verification[name] or current[name]
            verification_records.append(current)
        else:
            raise ValueError(
                "type must be sample, session_transition, reconnect, comparison, security, or verification"
            )

    if not samples:
        raise ValueError("at least one sample record is required")
    if not session_transitions:
        failures.append("session_transition_test_missing")
    if not reconnects:
        failures.append("reconnect_test_missing")
    if not security:
        failures.append("security_test_missing")
    if not comparisons:
        failures.append("binary_rest_comparison_missing")
    if duplicate_events:
        failures.append("duplicate_events")
    if out_of_order_events:
        failures.append("out_of_order_events")
    if counter_reset_failures:
        failures.append("counter_reset_recovery")
    complete_verification_record = any(
        all(record.get(name) is True for name in required_verifications)
        for record in verification_records
    )
    if not verification_records:
        failures.append("verification_evidence_missing")
    elif not complete_verification_record:
        # Partial records cannot be combined to imply that one full-window
        # verification attestation covered every required check.
        failures.append("verification_record_incomplete")
        for name in required_verifications:
            failures.append(f"{name}_missing")
        verification = {name: False for name in required_verifications}
    decoded_samples = [json.loads(sample) for sample in samples]
    timestamp_deltas = [
        later - earlier for earlier, later in zip(sample_timestamps, sample_timestamps[1:])
    ]
    observation_window = (
        sample_timestamps[-1] - sample_timestamps[0]
        if len(sample_timestamps) >= 2 and all(delta >= 0 for delta in timestamp_deltas)
        else 0.0
    )
    valid_sample_window = (
        len(sample_timestamps) == len(samples)
        and len(sample_timestamps) >= 2
        and all(delta > 0 for delta in timestamp_deltas)
    )
    if valid_sample_window:
        window_start, window_end = sample_timestamps[0], sample_timestamps[-1]
        for record_type, timestamp in attestation_timestamps:
            if timestamp < window_start or timestamp > window_end:
                failures.append(f"{record_type}_outside_observation_window")
    elif attestation_timestamps:
        failures.append("attestation_window_unverifiable")
    if len(samples) < MIN_SAMPLES:
        failures.append("sample_count")
    if len(sample_timestamps) != len(samples):
        failures.append("sample_timestamp_coverage")
    if sample_timestamps:
        current_epoch = time.time() if now is None else _number(now, "now")
        observation_age = current_epoch - sample_timestamps[-1]
        if observation_age > MAX_OBSERVATION_AGE_SECONDS:
            failures.append("observation_window_stale")
        if observation_age < -MAX_FUTURE_SKEW_SECONDS:
            failures.append("observation_window_future_dated")
    if any(delta <= 0 for delta in timestamp_deltas):
        failures.append("sample_timestamps_not_increasing")
    if observation_window < MIN_OBSERVATION_SECONDS:
        failures.append("observation_window_too_short")
    max_sample_gap = max(timestamp_deltas, default=0.0)
    if max_sample_gap > MAX_SAMPLE_GAP_SECONDS:
        failures.append("sample_gap_too_large")
    if sequence_evidence < MIN_SAMPLES:
        failures.append("event_sequence_coverage")
    for field, gate in (
        ("latency_ms", "latency_sample_coverage"),
        ("event_age_seconds", "event_age_sample_coverage"),
        ("router_cpu_percent", "router_cpu_sample_coverage"),
        ("router_memory_percent", "router_memory_sample_coverage"),
        ("router_storage_percent", "router_storage_sample_coverage"),
    ):
        if sum(field in sample for sample in decoded_samples) < MIN_SAMPLES:
            failures.append(gate)
    for field, gate in (
        ("router_cpu_percent", "router_cpu_measurement_missing"),
        ("router_memory_percent", "router_memory_measurement_missing"),
        ("router_storage_percent", "router_storage_measurement_missing"),
    ):
        if not any(field in sample for sample in decoded_samples):
            failures.append(gate)
    if verification["event_latency_measured"] and not any("latency_ms" in sample for sample in decoded_samples):
        failures.append("latency_evidence_missing")
    if verification["traffic_freshness_measured"] and not any("event_age_seconds" in sample for sample in decoded_samples):
        failures.append("event_age_evidence_missing")
    if verification["event_integrity_tested"] and not sequence_evidence:
        failures.append("event_sequence_evidence_missing")
    if verification["counter_reset_tested"] and not counter_reset_evidence:
        failures.append("counter_reset_evidence_missing")

    baseline_code, baseline = summarize(samples, limits={
        "latency_p95_ms": limits["latency_p95_ms"],
        "event_age_seconds": limits["event_age_seconds"],
        "router_cpu_percent": limits["router_cpu_percent"],
        "router_memory_percent": limits["router_memory_percent"],
        "router_storage_percent": limits["router_storage_percent"],
        "reconnects": limits["max_reconnects"],
    })
    failures.extend(item for item in baseline["failed_gates"] if item not in failures)
    result = {
        "healthy": not failures and baseline_code == 0,
        "failed_gates": sorted(set(failures)),
        "baseline": baseline,
        "session_transition_tests": len(session_transitions),
        "reconnect_tests": len(reconnects),
        "comparison_tests": len(comparisons),
        "security_tests": len(security),
        "counter_resets": counter_resets,
        "duplicate_events": duplicate_events,
        "out_of_order_events": out_of_order_events,
        "sample_count": len(samples),
        "observation_window_seconds": observation_window,
        "max_sample_gap_seconds": max_sample_gap,
        "verification": verification,
    }
    return (0 if result["healthy"] else 1), result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", default="-", help="redacted NDJSON file, or - for stdin")
    parser.add_argument("--max-latency-p95-ms", type=float, default=1000.0)
    parser.add_argument("--max-event-age-seconds", type=float, default=2.0)
    parser.add_argument("--max-router-cpu-percent", type=float, default=80.0)
    parser.add_argument("--max-router-memory-percent", type=float, default=90.0)
    parser.add_argument("--max-router-storage-percent", type=float, default=90.0)
    parser.add_argument("--max-reconnects", type=float, default=0.0)
    parser.add_argument("--max-recovery-seconds", type=float, default=10.0)
    args = parser.parse_args()
    source: TextIO | None = None
    try:
        limits = {
            "latency_p95_ms": args.max_latency_p95_ms,
            "event_age_seconds": args.max_event_age_seconds,
            "router_cpu_percent": args.max_router_cpu_percent,
        "router_memory_percent": args.max_router_memory_percent,
        "router_storage_percent": args.max_router_storage_percent,
            "max_reconnects": args.max_reconnects,
            "recovery_seconds": args.max_recovery_seconds,
        }
        if any(value < 0 for value in limits.values()):
            raise ValueError("limits must be non-negative")
        source = _source(args.input)
        code, result = evaluate(source, limits=limits)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(json.dumps({"healthy": False, "failed_gates": ["invalid_input"], "error": str(error)[:120]}))
        return 2
    finally:
        if source is not None and source is not sys.stdin:
            source.close()
    print(json.dumps(result, sort_keys=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
