"""Validate redacted before/candidate/after read-backs for canary rollback."""

from __future__ import annotations

from datetime import datetime, timezone
import re
from typing import Any

MAX_ROLLBACK_EVIDENCE_AGE_SECONDS = 24 * 60 * 60

REPORT_FORMAT = "vpn-dashboard-rollback-rehearsal-v1"
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
IMAGE = re.compile(
    r"^(?:ghcr\.io/)?[a-z0-9]+(?:[._-][a-z0-9]+)*/[a-z0-9]+(?:[._-][a-z0-9]+)*:sha-(?P<revision>[0-9a-f]{40})-arm64$"
)
READBACKS = (
    "production_before",
    "canary_before",
    "canary_candidate",
    "canary_after_rollback",
    "production_after",
    "canary_candidate_restored",
)
REPORT_FIELDS = frozenset({"format", "candidate_image", "candidate_digest", *READBACKS})
READBACK_FIELDS = frozenset({"environment", "observed_at", "image", "healthy", "ready"})
NORMALIZED_READBACK_FIELDS = READBACK_FIELDS | {"revision"}


def _timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return parsed.astimezone(timezone.utc)


def validate_rollback_report(
    report: Any,
    *,
    candidate_image: str,
    candidate_digest: str,
    production_image: str,
    collection_started_at: str,
    collection_ended_at: str,
) -> tuple[dict[str, Any] | None, list[str]]:
    """Verify ordered, healthy RouterOS/readiness read-backs without trusting booleans."""
    if not isinstance(report, dict) or set(report) != REPORT_FIELDS:
        return None, ["rollback_readback_schema_invalid"]
    candidate_match = IMAGE.fullmatch(candidate_image) if isinstance(candidate_image, str) else None
    production_match = IMAGE.fullmatch(production_image) if isinstance(production_image, str) else None
    if (
        report.get("format") != REPORT_FORMAT
        or candidate_match is None
        or production_match is None
        or report.get("candidate_image") != candidate_image
        or report.get("candidate_digest") != candidate_digest
        or not isinstance(candidate_digest, str)
        or DIGEST.fullmatch(candidate_digest) is None
    ):
        return None, ["rollback_candidate_identity_mismatch"]

    window_start = _timestamp(collection_started_at)
    window_end = _timestamp(collection_ended_at)
    if window_start is None or window_end is None or window_end <= window_start:
        return None, ["rollback_window_invalid"]

    safe_readbacks: dict[str, dict[str, Any]] = {}
    parsed_times: list[datetime] = []
    failures: list[str] = []
    earliest_allowed = window_start.timestamp() - MAX_ROLLBACK_EVIDENCE_AGE_SECONDS
    latest_allowed = window_start.timestamp()
    for name in READBACKS:
        item = report.get(name)
        if not isinstance(item, dict) or set(item) not in (READBACK_FIELDS, NORMALIZED_READBACK_FIELDS):
            failures.append("rollback_readback_schema_invalid")
            continue
        expected_environment = "production" if name.startswith("production_") else "canary"
        timestamp = _timestamp(item.get("observed_at"))
        image = item.get("image")
        image_match = IMAGE.fullmatch(image) if isinstance(image, str) else None
        if (
            item.get("environment") != expected_environment
            or timestamp is None
            or image_match is None
            or not isinstance(item.get("healthy"), bool)
            or not isinstance(item.get("ready"), bool)
        ):
            failures.append("rollback_readback_invalid")
            continue
        revision = image_match.group("revision")
        if "revision" in item and item["revision"] != revision:
            failures.append("rollback_readback_revision_mismatch")
        if timestamp.timestamp() < earliest_allowed or timestamp.timestamp() > latest_allowed:
            failures.append("rollback_readback_outside_window")
        if item["healthy"] is not True or item["ready"] is not True:
            failures.append("rollback_readback_unhealthy")
        safe_readbacks[name] = {
            "environment": expected_environment,
            "observed_at": timestamp.isoformat(),
            "image": image,
            "revision": revision,
            "healthy": item["healthy"],
            "ready": item["ready"],
        }
        parsed_times.append(timestamp)

    if failures:
        return None, sorted(set(failures))
    if not all(left < right for left, right in zip(parsed_times, parsed_times[1:])):
        failures.append("rollback_readback_order_invalid")
    if safe_readbacks["canary_candidate"]["image"] != candidate_image:
        failures.append("rollback_candidate_readback_mismatch")
    if safe_readbacks["canary_candidate_restored"]["image"] != candidate_image:
        failures.append("rollback_candidate_restore_readback_mismatch")
    rollback_target = safe_readbacks["canary_before"]["image"]
    if rollback_target == candidate_image or safe_readbacks["canary_after_rollback"]["image"] != rollback_target:
        failures.append("rollback_target_readback_mismatch")
    if (
        safe_readbacks["production_before"]["image"] != production_image
        or safe_readbacks["production_after"]["image"] != production_image
    ):
        failures.append("production_image_changed_during_canary_rollback")

    if failures:
        return None, sorted(set(failures))
    return {
        "format": REPORT_FORMAT,
        "candidate_image": candidate_image,
        "candidate_digest": candidate_digest,
        **safe_readbacks,
    }, []


def summarize_rollback_report(report: dict[str, Any]) -> dict[str, Any]:
    """Project validated read-backs into a concise public acceptance summary."""
    candidate_match = IMAGE.fullmatch(report["candidate_image"])
    rollback_target = report["canary_before"]["image"]
    rollback_match = IMAGE.fullmatch(rollback_target)
    return {
        "format": REPORT_FORMAT,
        "candidate_image": report["candidate_image"],
        "candidate_revision": candidate_match.group("revision"),
        "candidate_registry_digest": report["candidate_digest"],
        "router_runtime_digest_verified": False,
        "rollback_target_image": rollback_target,
        "rollback_target_revision": rollback_match.group("revision"),
        "production_unchanged": report["production_before"]["image"] == report["production_after"]["image"],
        "candidate_restored_before_soak": report["canary_candidate_restored"]["image"] == report["candidate_image"],
        "candidate_restored_at": report["canary_candidate_restored"]["observed_at"],
        "readbacks": {name: report[name] for name in READBACKS},
    }
