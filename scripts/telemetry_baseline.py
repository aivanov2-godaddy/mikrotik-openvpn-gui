"""Summarize redacted live-telemetry measurements before a canary promotion.

The input is newline-delimited JSON from an operator harness.  Each line may
contain ``latency_ms``, ``event_age_seconds``, ``router_cpu_percent``,
``router_memory_percent``, ``router_storage_percent``, ``container_healthy``,
``reconnects``, ``event_lost`` and ``transport``.
The command emits aggregate metrics and pass/fail gates only; it never echoes
RouterOS records, addresses, credentials, or session identifiers.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path
from typing import Any, Iterable, TextIO


def _source(path: str) -> TextIO:
    if path == "-":
        return sys.stdin
    return Path(path).open("r", encoding="utf-8")


def _number(sample: dict[str, Any], name: str, *, required: bool = False) -> float | None:
    value = sample.get(name)
    if value is None and not required:
        return None
    if isinstance(value, bool):
        raise ValueError(f"{name} must be numeric")
    try:
        number = float(value)
    except (TypeError, ValueError) as error:
        raise ValueError(f"{name} must be numeric") from error
    if not math.isfinite(number) or number < 0:
        raise ValueError(f"{name} must be finite and non-negative")
    return number


def _percentile(values: list[float], percentile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, math.ceil(percentile * len(ordered)) - 1))
    return ordered[index]


def summarize(lines: Iterable[str], *, limits: dict[str, float]) -> tuple[int, dict[str, Any]]:
    latency: list[float] = []
    age: list[float] = []
    cpu: list[float] = []
    memory: list[float] = []
    storage: list[float] = []
    reconnects = 0
    event_loss = 0
    container_health_failures = 0
    samples = 0
    transports: dict[str, int] = {}
    for line in lines:
        if not line.strip():
            continue
        sample = json.loads(line)
        if not isinstance(sample, dict):
            raise ValueError("each sample must be a JSON object")
        for name, target in (
            ("latency_ms", latency),
            ("event_age_seconds", age),
            ("router_cpu_percent", cpu),
            ("router_memory_percent", memory),
            ("router_storage_percent", storage),
        ):
            value = _number(sample, name)
            if value is not None:
                target.append(value)
        if "container_healthy" in sample:
            if not isinstance(sample["container_healthy"], bool):
                raise ValueError("container_healthy must be boolean")
            if not sample["container_healthy"]:
                container_health_failures += 1
        reconnects += int(_number(sample, "reconnects") or 0)
        event_loss += int(bool(sample.get("event_lost", False)))
        transport = sample.get("transport")
        if transport is not None:
            if not isinstance(transport, str) or transport not in {"rest", "binary", "socketio", "sse"}:
                raise ValueError("transport must be one of rest, binary, socketio, sse")
            transports[transport] = transports.get(transport, 0) + 1
        samples += 1
    if not samples:
        raise ValueError("at least one baseline sample is required")

    metrics = {
        "samples": samples,
        "transport_counts": transports,
        "latency_p50_ms": _percentile(latency, 0.50),
        "latency_p95_ms": _percentile(latency, 0.95),
        "max_event_age_seconds": max(age) if age else None,
        "max_router_cpu_percent": max(cpu) if cpu else None,
        "max_router_memory_percent": max(memory) if memory else None,
        "max_router_storage_percent": max(storage) if storage else None,
        "container_health_failures": container_health_failures,
        "reconnects": reconnects,
        "event_loss_count": event_loss,
    }
    failures: list[str] = []
    if metrics["latency_p95_ms"] is not None and metrics["latency_p95_ms"] > limits["latency_p95_ms"]:
        failures.append("latency_p95")
    if metrics["max_event_age_seconds"] is not None and metrics["max_event_age_seconds"] > limits["event_age_seconds"]:
        failures.append("event_age")
    if metrics["max_router_cpu_percent"] is not None and metrics["max_router_cpu_percent"] > limits["router_cpu_percent"]:
        failures.append("router_cpu")
    if metrics["max_router_memory_percent"] is not None and metrics["max_router_memory_percent"] > limits["router_memory_percent"]:
        failures.append("router_memory")
    if metrics["max_router_storage_percent"] is not None and metrics["max_router_storage_percent"] > limits["router_storage_percent"]:
        failures.append("router_storage")
    if container_health_failures:
        failures.append("container_health")
    if reconnects > limits["reconnects"]:
        failures.append("reconnects")
    if event_loss:
        failures.append("event_loss")
    result = {"healthy": not failures, "failed_gates": failures, **metrics}
    return (0 if not failures else 1), result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", default="-", help="NDJSON sample file, or - for stdin")
    parser.add_argument("--max-latency-p95-ms", type=float, default=1000.0)
    parser.add_argument("--max-event-age-seconds", type=float, default=2.0)
    parser.add_argument("--max-router-cpu-percent", type=float, default=80.0)
    parser.add_argument("--max-router-memory-percent", type=float, default=90.0)
    parser.add_argument("--max-router-storage-percent", type=float, default=90.0)
    parser.add_argument("--max-reconnects", type=float, default=0.0)
    args = parser.parse_args()
    source: TextIO | None = None
    try:
        limits = {
            "latency_p95_ms": args.max_latency_p95_ms,
            "event_age_seconds": args.max_event_age_seconds,
            "router_cpu_percent": args.max_router_cpu_percent,
        "router_memory_percent": args.max_router_memory_percent,
        "router_storage_percent": args.max_router_storage_percent,
            "reconnects": args.max_reconnects,
        }
        if any(value < 0 for value in limits.values()):
            raise ValueError("limits must be non-negative")
        source = _source(args.input)
        code, result = summarize(source, limits=limits)
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
