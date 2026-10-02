"""Validate redacted canary/production evidence and print a release report.

Input is an operator-collected JSON evidence file. It must contain no
credentials, user data, router addresses, or raw logs. This validator does not
connect to or mutate RouterOS; it checks that the recorded rollout evidence is
complete, consistent, and within the project's live-data targets.
"""

from __future__ import annotations

import argparse
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


def evaluate(document: Any) -> tuple[int, dict[str, Any]]:
    if not isinstance(document, dict) or document.get("format") != "vpn-dashboard-release-evidence-v1":
        raise ValueError("format must be vpn-dashboard-release-evidence-v1")
    deployments = document.get("deployments")
    if not isinstance(deployments, list) or len(deployments) != 2:
        raise ValueError("deployments must contain canary followed by production")

    failures: list[str] = []
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
        latency = _number(record, "session_event_p95_ms")
        sample_age = _number(record, "traffic_sample_age_seconds")

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
        })

    if safe_records[0]["image"] != safe_records[1]["image"]:
        failures.append("canary_production_image_mismatch")
    if safe_records[0]["digest"] != safe_records[1]["digest"]:
        failures.append("canary_production_digest_mismatch")
    report = {
        "format": "vpn-dashboard-release-acceptance-report-v1",
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
