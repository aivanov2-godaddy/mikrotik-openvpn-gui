"""Validate redacted canary/production evidence and print a release report.

Input is an operator-collected JSON evidence file. It must contain no
credentials, user data, router addresses, or raw logs. This validator does not
connect to or mutate RouterOS; it checks that the recorded rollout evidence is
complete, consistent, and within the project's live-data targets.
"""

from __future__ import annotations

import argparse
from datetime import datetime
import json
import math
import re
import sys
from pathlib import Path
from typing import Any


IMAGE = re.compile(
    r"^(?:ghcr\.io/)?[a-z0-9](?:[a-z0-9._-]{0,98})/[a-z0-9](?:[a-z0-9._-]{0,98}):"
    r"sha-(?P<revision>[0-9a-f]{40})(?:-(?:arm64|amd64))?$"
)
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
ENVIRONMENTS = ("canary", "production")
MIN_SOAK_SECONDS = 1800
MIN_HEALTH_SAMPLES = 30


def _boolean(record: dict[str, Any], field: str) -> bool:
    value = record.get(field)
    if not isinstance(value, bool):
        raise ValueError(f"{field} must be boolean")
    return value


def _number(record: dict[str, Any], field: str) -> float:
    value = record.get(field)
    if isinstance(value, bool):
        raise ValueError(f"{field} must be numeric")
    try:
        parsed = float(value)
    except (TypeError, ValueError) as error:
        raise ValueError(f"{field} must be numeric") from error
    if not math.isfinite(parsed) or parsed < 0:
        raise ValueError(f"{field} must be finite and non-negative")
    return parsed


def _timestamp(record: dict[str, Any], field: str) -> datetime:
    value = record.get(field)
    if not isinstance(value, str):
        raise ValueError(f"{field} must be an ISO-8601 timestamp with timezone")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"{field} must be an ISO-8601 timestamp with timezone") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field} must include a timezone")
    return parsed


def _count(record: dict[str, Any], field: str) -> int:
    value = _number(record, field)
    if not value.is_integer():
        raise ValueError(f"{field} must be a whole-number count")
    return int(value)


def evaluate(document: Any) -> tuple[int, dict[str, Any]]:
    if not isinstance(document, dict) or document.get("format") != "vpn-dashboard-release-evidence-v2":
        raise ValueError("format must be vpn-dashboard-release-evidence-v2")
    deployments = document.get("deployments")
    if not isinstance(deployments, list) or len(deployments) != 2:
        raise ValueError("deployments must contain canary followed by production")

    failures: list[str] = []
    collection = document.get("collection")
    if collection is not None:
        if not isinstance(collection, dict) or collection.get("format") != "vpn-dashboard-release-collection-v1":
            raise ValueError("collection must use vpn-dashboard-release-collection-v1")
        collection_passed = collection.get("passed")
        collection_failures = collection.get("failed_gates")
        if not isinstance(collection_passed, bool):
            raise ValueError("collection passed must be boolean")
        if not isinstance(collection_failures, list) or any(
            not isinstance(gate, str) for gate in collection_failures
        ):
            raise ValueError("collection failed_gates must be a list of strings")
        # Collector failures cannot be overridden by optimistic fields in the
        # deployment records. Do not copy caller-controlled gate names to the
        # public report.
        if not collection_passed or collection_failures:
            failures.append("live_collection_failed")
    safe_records: list[dict[str, Any]] = []
    for record, expected_environment in zip(deployments, ENVIRONMENTS):
        if not isinstance(record, dict):
            raise ValueError("each deployment must be an object")
        if record.get("environment") != expected_environment:
            raise ValueError("deployments must be ordered canary, then production")
        image = str(record.get("image", ""))
        image_match = IMAGE.fullmatch(image)
        if not image_match:
            raise ValueError(f"{expected_environment} image must use a full immutable sha-commit tag")
        digest = str(record.get("digest", ""))
        if not DIGEST.fullmatch(digest):
            raise ValueError(f"{expected_environment} digest must be a sha256 OCI digest")
        transport = record.get("transport")
        if not isinstance(transport, str) or transport not in {"asgi-websocket", "sse-fallback"}:
            raise ValueError(f"{expected_environment} transport must identify the observed runtime")

        healthy = _boolean(record, "container_healthy")
        ready = _boolean(record, "app_ready")
        fallback = _boolean(record, "rest_fallback")
        redis_configured = _boolean(record, "redis_configured")
        redis_available = _boolean(record, "redis_publish_verified")
        reconnect = _boolean(record, "reconnect_recovered")
        snapshot = _boolean(record, "snapshot_recovered")
        backup_restore = _boolean(record, "sqlite_restore_verified")
        rollback = _boolean(record, "rollback_drill_passed")
        production_protected = _boolean(record, "production_untouched_on_canary_failure")
        latency = _number(record, "session_event_p95_ms")
        sample_age = _number(record, "traffic_sample_age_seconds")
        started = _timestamp(record, "observation_started_at")
        ended = _timestamp(record, "observation_ended_at")
        soak_seconds = (ended - started).total_seconds()
        health_samples = _count(record, "health_sample_count")
        max_sample_gap = _number(record, "max_sample_gap_seconds")
        failure_counts = {
            name: _count(record, name)
            for name in (
                "health_failures", "stale_sample_count", "lost_event_count",
                "duplicate_event_count", "out_of_order_event_count",
                "redis_delivery_failure_count",
            )
        }
        resource_peaks = {
            name: _number(record, name)
            for name in (
                "router_cpu_peak_percent", "router_memory_peak_percent",
                "router_storage_peak_percent",
            )
        }

        if not healthy:
            failures.append(f"{expected_environment}_container_unhealthy")
        if not ready:
            failures.append(f"{expected_environment}_app_not_ready")
        if not fallback:
            failures.append(f"{expected_environment}_rest_fallback_unavailable")
        if not redis_configured or not redis_available:
            failures.append(f"{expected_environment}_redis_publish_unverified")
        if not reconnect or not snapshot:
            failures.append(f"{expected_environment}_reconnect_recovery_failed")
        if not backup_restore:
            failures.append(f"{expected_environment}_sqlite_restore_unverified")
        if latency > 1000:
            failures.append(f"{expected_environment}_session_event_latency_exceeded")
        if sample_age > 2:
            failures.append(f"{expected_environment}_traffic_sample_stale")
        if soak_seconds < MIN_SOAK_SECONDS:
            failures.append(f"{expected_environment}_soak_window_too_short")
        if health_samples < MIN_HEALTH_SAMPLES:
            failures.append(f"{expected_environment}_health_samples_insufficient")
        if max_sample_gap > 120:
            failures.append(f"{expected_environment}_health_sample_gap_exceeded")
        if soak_seconds <= 0:
            failures.append(f"{expected_environment}_observation_window_invalid")
        if any(value > 0 for value in failure_counts.values()):
            failures.append(f"{expected_environment}_soak_failures_observed")
        for resource, limit in zip(resource_peaks, (80, 90, 90)):
            if resource_peaks[resource] > limit:
                failures.append(f"{expected_environment}_{resource}_exceeded")
        if expected_environment == "canary" and not rollback:
            failures.append("canary_rollback_drill_failed")
        if expected_environment == "canary" and not production_protected:
            failures.append("production_protection_unverified")

        safe_records.append({
            "environment": expected_environment,
            "image": image,
            "revision": image_match.group("revision"),
            "digest": digest,
            "container_healthy": healthy,
            "app_ready": ready,
            "transport": transport,
            "rest_fallback": fallback,
            "redis_configured": redis_configured,
            "redis_publish_verified": redis_available,
            "reconnect_recovered": reconnect,
            "snapshot_recovered": snapshot,
            "sqlite_restore_verified": backup_restore,
            "session_event_p95_ms": latency,
            "traffic_sample_age_seconds": sample_age,
            "observation_started_at": started.isoformat(),
            "observation_ended_at": ended.isoformat(),
            "observation_window_seconds": soak_seconds,
            "health_sample_count": health_samples,
            "max_sample_gap_seconds": max_sample_gap,
            **failure_counts,
            **resource_peaks,
            "rollback_drill_passed": rollback,
            "production_untouched_on_canary_failure": production_protected,
        })

    if safe_records[0]["image"] != safe_records[1]["image"]:
        failures.append("canary_production_image_mismatch")
    if safe_records[0]["digest"] != safe_records[1]["digest"]:
        failures.append("canary_production_digest_mismatch")
    report = {
        "format": "vpn-dashboard-release-acceptance-report-v2",
        "passed": not failures,
        "failed_gates": sorted(set(failures)),
        "deployments": safe_records,
    }
    return (0 if report["passed"] else 1), report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, help="redacted JSON evidence file")
    parser.add_argument("--output", help="optional report path; stdout if omitted")
    args = parser.parse_args()
    try:
        document = json.loads(Path(args.input).read_text(encoding="utf-8"))
        code, report = evaluate(document)
    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(json.dumps({"passed": False, "failed_gates": ["invalid_input"], "error": str(error)[:160]}))
        return 2
    rendered = json.dumps(report, sort_keys=True, indent=2) + "\n"
    if args.output:
        Path(args.output).write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
