"""Evaluate a redacted live-telemetry acceptance window.

The input is newline-delimited JSON captured by an operator harness.  It is
deliberately limited to measurements and boolean test results; RouterOS
records, credentials, addresses, and identifiers must never be included.

Accepted record types are ``sample``, ``reconnect``, and ``security``.  A
sample may contain the fields understood by :mod:`scripts.telemetry_baseline`
plus ``event_sequence``, ``event_lost``, ``event_duplicated``,
``out_of_order``, ``counter_reset``, and ``counter_reset_recovered``.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path
from typing import Any, Iterable, TextIO

try:
    from telemetry_baseline import summarize
except ModuleNotFoundError:  # Imported as ``scripts.telemetry_acceptance`` in tests.
    from scripts.telemetry_baseline import summarize


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


def evaluate(lines: Iterable[str], *, limits: dict[str, float]) -> tuple[int, dict[str, Any]]:
    samples: list[str] = []
    reconnects: list[dict[str, Any]] = []
    security: list[dict[str, Any]] = []
    sequences: list[int] = []
    failures: list[str] = []
    counter_resets = 0
    counter_reset_failures = 0
    duplicate_events = 0
    out_of_order_events = 0

    for line in lines:
        if not line.strip():
            continue
        record = json.loads(line)
        if not isinstance(record, dict):
            raise ValueError("each record must be a JSON object")
        record_type = record.get("type", "sample")
        if record_type == "sample":
            samples.append(json.dumps(record, separators=(",", ":")))
            if "event_sequence" in record:
                sequence = int(_number(record["event_sequence"], "event_sequence"))
                sequences.append(sequence)
            for name in ("event_lost", "event_duplicated", "out_of_order"):
                if name in record and _boolean(record[name], name):
                    if name == "event_lost":
                        failures.append("event_loss")
                    elif name == "event_duplicated":
                        duplicate_events += 1
                    else:
                        out_of_order_events += 1
            if record.get("counter_reset"):
                if not _boolean(record["counter_reset"], "counter_reset"):
                    raise ValueError("counter_reset must be boolean")
                counter_resets += 1
                recovered = record.get("counter_reset_recovered", False)
                _boolean(recovered, "counter_reset_recovered")
                if not recovered:
                    counter_reset_failures += 1
        elif record_type == "reconnect":
            reconnects.append(record)
            recovered = _boolean(record.get("snapshot_recovered"), "snapshot_recovered")
            recovery_seconds = _number(record.get("recovery_seconds"), "recovery_seconds")
            if not recovered:
                failures.append("snapshot_recovery")
            if recovery_seconds > limits["recovery_seconds"]:
                failures.append("recovery_time")
        elif record_type == "security":
            security.append(record)
            if not _boolean(record.get("unauthenticated_denied"), "unauthenticated_denied"):
                failures.append("unauthenticated_access")
            if _boolean(record.get("secret_bearing_payload"), "secret_bearing_payload"):
                failures.append("secret_exposure")
        else:
            raise ValueError("type must be sample, reconnect, or security")

    if not samples:
        raise ValueError("at least one sample record is required")
    if not reconnects:
        failures.append("reconnect_test_missing")
    if not security:
        failures.append("security_test_missing")
    if duplicate_events:
        failures.append("duplicate_events")
    if out_of_order_events or any(right <= left for left, right in zip(sequences, sequences[1:])):
        failures.append("out_of_order_events")
    if counter_reset_failures:
        failures.append("counter_reset_recovery")

    baseline_code, baseline = summarize(samples, limits={
        "latency_p95_ms": limits["latency_p95_ms"],
        "event_age_seconds": limits["event_age_seconds"],
        "router_cpu_percent": limits["router_cpu_percent"],
        "router_memory_percent": limits["router_memory_percent"],
        "reconnects": limits["max_reconnects"],
    })
    failures.extend(item for item in baseline["failed_gates"] if item not in failures)
    result = {
        "healthy": not failures and baseline_code == 0,
        "failed_gates": sorted(set(failures)),
        "baseline": baseline,
        "reconnect_tests": len(reconnects),
        "security_tests": len(security),
        "counter_resets": counter_resets,
        "duplicate_events": duplicate_events,
        "out_of_order_events": out_of_order_events,
    }
    return (0 if result["healthy"] else 1), result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", default="-", help="redacted NDJSON file, or - for stdin")
    parser.add_argument("--max-latency-p95-ms", type=float, default=1000.0)
    parser.add_argument("--max-event-age-seconds", type=float, default=2.0)
    parser.add_argument("--max-router-cpu-percent", type=float, default=80.0)
    parser.add_argument("--max-router-memory-percent", type=float, default=90.0)
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
