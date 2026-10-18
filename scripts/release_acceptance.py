"""Validate redacted canary/production evidence and print a release report.

Input is an operator-collected JSON evidence file. It must contain no
credentials, user data, router addresses, or raw logs. This validator does not
connect to or mutate RouterOS; it checks that the recorded rollout evidence is
complete, consistent, and within the project's live-data targets.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import math
import re
import sys
from pathlib import Path
from typing import Any

try:
    from certificate_lifecycle_acceptance import validate_certificate_lifecycle_acceptance
    from stream_acceptance import validate_stream_acceptance
    from sqlite_restore_verifier import validate_restore_verification
except ModuleNotFoundError:
    from scripts.certificate_lifecycle_acceptance import validate_certificate_lifecycle_acceptance
    from scripts.stream_acceptance import validate_stream_acceptance
    from scripts.sqlite_restore_verifier import validate_restore_verification


IMAGE = re.compile(
    r"^(?:ghcr\.io/)?[a-z0-9](?:[a-z0-9._-]{0,98})/[a-z0-9](?:[a-z0-9._-]{0,98}):"
    r"sha-(?P<revision>[0-9a-f]{40})(?:-(?:arm64|amd64))?$"
)
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
ENVIRONMENTS = ("canary", "production")
MIN_SOAK_SECONDS = 1800
MIN_HEALTH_SAMPLES = 30
MAX_COLLECTION_AGE_SECONDS = 900
MAX_FUTURE_SKEW_SECONDS = 300
MAX_SESSION_EVENT_AGE_SECONDS = 2.0
MAX_EVIDENCE_CLOCK_SKEW_SECONDS = 5
MAX_SESSION_EVENT_LATENCY_EVIDENCE_AGE_SECONDS = 900
MAX_RESTORE_ROLLBACK_EVIDENCE_AGE_SECONDS = 86400


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


def _optional_timestamp(record: dict[str, Any], field: str, *, optional: bool) -> datetime | None:
    if optional and record.get(field) is None:
        return None
    return _timestamp(record, field)


def _count(record: dict[str, Any], field: str) -> int:
    value = _number(record, field)
    if not value.is_integer():
        raise ValueError(f"{field} must be a whole-number count")
    return int(value)


def _optional_boolean(record: dict[str, Any], field: str, *, optional: bool) -> bool | None:
    if optional and record.get(field) is None:
        return None
    return _boolean(record, field)


def _optional_number(record: dict[str, Any], field: str, *, optional: bool) -> float | None:
    if optional and record.get(field) is None:
        return None
    return _number(record, field)


def _optional_count(record: dict[str, Any], field: str, *, optional: bool) -> int | None:
    if optional and record.get(field) is None:
        return None
    return _count(record, field)


def evaluate(
    document: Any,
    *,
    now: datetime | None = None,
    phase: str | None = None,
) -> tuple[int, dict[str, Any]]:
    if not isinstance(document, dict) or document.get("format") != "vpn-dashboard-release-evidence-v2":
        raise ValueError("format must be vpn-dashboard-release-evidence-v2")
    deployments = document.get("deployments")
    if not isinstance(deployments, list) or len(deployments) != 2:
        raise ValueError("deployments must contain canary followed by production")

    failures: list[str] = []
    collection = document.get("collection")
    collection_started: datetime | None = None
    collection_ended: datetime | None = None
    collection_phase: str | None = None
    registry_verification: Any = None
    registry_digests_verified = False
    validated_stream_acceptance: dict[str, Any] | None = None
    collection_passed = False
    if phase is not None and phase not in {"canary-prepromotion", "postpromotion"}:
        raise ValueError("phase must be canary-prepromotion or postpromotion")
    if collection is None:
        failures.append("live_collection_missing")
        collection_phase = phase
    else:
        if not isinstance(collection, dict) or collection.get("format") != "vpn-dashboard-release-collection-v1":
            raise ValueError("collection must use vpn-dashboard-release-collection-v1")
        collection_phase = collection.get("phase")
        if collection_phase not in {"canary-prepromotion", "postpromotion"}:
            raise ValueError("collection phase must be canary-prepromotion or postpromotion")
        if phase is not None and phase != collection_phase:
            raise ValueError("requested phase must match collection phase")
        registry_verification = collection.get("registry_digest_verification")
        expected_registry_count = 1 if collection_phase == "canary-prepromotion" else len(ENVIRONMENTS)
        if not isinstance(registry_verification, list) or len(registry_verification) != expected_registry_count:
            raise ValueError("collection registry digest verification does not match its phase")
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
        collection_started = _timestamp(collection, "started_at")
        collection_ended = _timestamp(collection, "ended_at")
        collection_duration = (collection_ended - collection_started).total_seconds()
        if collection_duration < MIN_SOAK_SECONDS:
            failures.append("live_collection_window_too_short")
        if collection_duration <= 0:
            failures.append("live_collection_window_invalid")
        current_time = now or datetime.now(timezone.utc)
        if current_time.tzinfo is None or current_time.utcoffset() is None:
            raise ValueError("now must include a timezone")
        age_seconds = (current_time - collection_ended).total_seconds()
        if age_seconds > MAX_COLLECTION_AGE_SECONDS:
            failures.append("live_collection_stale")
        if age_seconds < -MAX_FUTURE_SKEW_SECONDS:
            failures.append("live_collection_future_dated")
        stream_acceptance = collection.get("stream_acceptance")
        if collection_passed and (
            not isinstance(stream_acceptance, dict) or stream_acceptance.get("format") != (
                "vpn-dashboard-stream-acceptance-v1"
            )
        ):
            failures.append("stream_acceptance_missing_or_invalid")
        elif collection_passed:
            if set(stream_acceptance) != {"format", "stream_observation", "browser_telemetry"}:
                failures.append("stream_acceptance_schema_invalid")
            try:
                validated_stream_acceptance, stream_failures = validate_stream_acceptance(
                    stream_acceptance.get("stream_observation"),
                    stream_acceptance.get("browser_telemetry"),
                    collection_started_at=collection.get("started_at"),
                    collection_ended_at=collection.get("ended_at"),
                    now=current_time,
                )
            except ValueError:
                stream_failures = ["stream_acceptance_window_invalid"]
            failures.extend(stream_failures)
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
        prior_production_baseline = (
            collection_phase == "canary-prepromotion" and expected_environment == "production"
        )
        raw_digest = record.get("digest")
        digest = raw_digest if isinstance(raw_digest, str) and DIGEST.fullmatch(raw_digest) else None
        if digest is None and not prior_production_baseline:
            raise ValueError(f"{expected_environment} digest must be a sha256 OCI digest")
        transport = record.get("transport")
        allowed_transports = (
            {"rest", "binary", "socketio", "sse", "asgi-websocket", "sse-fallback"}
            if prior_production_baseline
            else {"asgi-websocket", "sse-fallback"}
        )
        if prior_production_baseline and transport is None:
            pass
        elif not isinstance(transport, str) or transport not in allowed_transports:
            raise ValueError(f"{expected_environment} transport must identify the observed runtime")

        healthy = _boolean(record, "container_healthy")
        ready = _boolean(record, "app_ready")
        fallback = _optional_boolean(record, "rest_fallback", optional=prior_production_baseline)
        redis_configured = _optional_boolean(record, "redis_configured", optional=prior_production_baseline)
        redis_available = _optional_boolean(record, "redis_publish_verified", optional=prior_production_baseline)
        reconnect = _optional_boolean(record, "reconnect_recovered", optional=prior_production_baseline)
        snapshot = _optional_boolean(record, "snapshot_recovered", optional=prior_production_baseline)
        reconnect_counter_delta = _optional_count(
            record, "reconnect_recovery_counter_delta", optional=True
        )
        reconnect_counter_reset = _optional_boolean(
            record, "reconnect_recovery_counter_reset", optional=True
        )
        reconnect_observed_at = _optional_number(
            record, "reconnect_observed_at", optional=True
        )
        full_snapshot_recovered_at = _optional_number(
            record, "full_snapshot_recovered_at", optional=True
        )
        backup_restore = _optional_boolean(record, "sqlite_restore_verified", optional=prior_production_baseline)
        rollback = _optional_boolean(record, "rollback_drill_passed", optional=prior_production_baseline)
        production_protected = _optional_boolean(
            record, "production_untouched_on_canary_failure", optional=prior_production_baseline
        )
        latency = _optional_number(record, "session_event_p95_ms", optional=True)
        latency_started = _optional_timestamp(
            record, "session_event_latency_started_at", optional=prior_production_baseline
        )
        latency_ended = _optional_timestamp(
            record, "session_event_latency_ended_at", optional=prior_production_baseline
        )
        restore_verified_at = _optional_timestamp(
            record,
            "sqlite_restore_verified_at",
            optional=prior_production_baseline or backup_restore is not True,
        )
        rollback_drill_at = _optional_timestamp(
            record, "rollback_drill_at", optional=prior_production_baseline or expected_environment != "canary"
        )
        production_protection_at = _optional_timestamp(
            record, "production_protection_observed_at", optional=prior_production_baseline or expected_environment != "canary"
        )
        session_event_age = _optional_number(
            record, "session_event_max_age_seconds", optional=True
        )
        sample_age = _optional_number(record, "traffic_sample_age_seconds", optional=prior_production_baseline)
        started = _timestamp(record, "observation_started_at")
        ended = _timestamp(record, "observation_ended_at")
        soak_seconds = (ended - started).total_seconds()
        health_samples = _count(record, "health_sample_count")
        max_sample_gap = _number(record, "max_sample_gap_seconds")
        failure_counts = {
            name: _optional_count(record, name, optional=prior_production_baseline and name != "health_failures")
            for name in (
                "health_failures", "stale_sample_count", "lost_event_count",
                "duplicate_event_count", "out_of_order_event_count",
                "redis_delivery_failure_count",
            )
        }
        resource_peaks = {
            name: _optional_number(record, name, optional=prior_production_baseline)
            for name in (
                "router_cpu_peak_percent", "router_memory_peak_percent",
                "router_storage_peak_percent",
            )
        }
        observation_start_epoch = started.timestamp()
        observation_end_epoch = ended.timestamp()
        latency_evidence_start = observation_start_epoch - MAX_SESSION_EVENT_LATENCY_EVIDENCE_AGE_SECONDS
        rehearsal_evidence_start = observation_start_epoch - MAX_RESTORE_ROLLBACK_EVIDENCE_AGE_SECONDS
        reconnect_timestamp_in_window = (
            reconnect_observed_at is not None
            and observation_start_epoch <= reconnect_observed_at <= observation_end_epoch + MAX_EVIDENCE_CLOCK_SKEW_SECONDS
        )
        full_snapshot_after_reconnect = (
            full_snapshot_recovered_at is not None
            and reconnect_observed_at is not None
            and observation_start_epoch <= full_snapshot_recovered_at <= observation_end_epoch + MAX_EVIDENCE_CLOCK_SKEW_SECONDS
            and full_snapshot_recovered_at >= reconnect_observed_at
        )
        latency_window_valid = (
            latency_started is not None
            and latency_ended is not None
            and latency_evidence_start <= latency_started.timestamp() <= observation_end_epoch + MAX_EVIDENCE_CLOCK_SKEW_SECONDS
            and latency_evidence_start <= latency_ended.timestamp() <= observation_end_epoch + MAX_EVIDENCE_CLOCK_SKEW_SECONDS
            and latency_ended > latency_started
        )
        restore_timestamp_in_window = (
            restore_verified_at is not None
            and rehearsal_evidence_start <= restore_verified_at.timestamp() <= observation_end_epoch + MAX_EVIDENCE_CLOCK_SKEW_SECONDS
        )
        rollback_timestamp_in_window = (
            rollback_drill_at is not None
            and rehearsal_evidence_start <= rollback_drill_at.timestamp() <= observation_end_epoch + MAX_EVIDENCE_CLOCK_SKEW_SECONDS
        )
        protection_timestamp_in_window = (
            production_protection_at is not None
            and rehearsal_evidence_start <= production_protection_at.timestamp() <= observation_end_epoch + MAX_EVIDENCE_CLOCK_SKEW_SECONDS
        )

        if not healthy:
            failures.append(f"{expected_environment}_container_unhealthy")
        if not ready:
            failures.append(f"{expected_environment}_app_not_ready")
        if not prior_production_baseline and not fallback:
            failures.append(f"{expected_environment}_rest_fallback_unavailable")
        if not prior_production_baseline and (not redis_configured or not redis_available):
            failures.append(f"{expected_environment}_redis_publish_unverified")
        if not prior_production_baseline and (
            not reconnect
            or not snapshot
            or reconnect_counter_delta is None
            or reconnect_counter_delta < 1
            or reconnect_counter_reset is not False
            or not reconnect_timestamp_in_window
            or not full_snapshot_after_reconnect
        ):
            failures.append(f"{expected_environment}_reconnect_recovery_failed")
        if not prior_production_baseline and not backup_restore:
            failures.append(f"{expected_environment}_sqlite_restore_unverified")
        if not prior_production_baseline and not restore_timestamp_in_window:
            failures.append(f"{expected_environment}_sqlite_restore_evidence_stale_or_outside_window")
        if not prior_production_baseline and latency is None:
            failures.append(f"{expected_environment}_session_event_latency_unobserved")
        elif not prior_production_baseline and latency is not None and latency > 1000:
            failures.append(f"{expected_environment}_session_event_latency_exceeded")
        if not prior_production_baseline and not latency_window_valid:
            failures.append(f"{expected_environment}_session_event_latency_evidence_stale_or_outside_window")
        if not prior_production_baseline and (
            session_event_age is None or session_event_age > MAX_SESSION_EVENT_AGE_SECONDS
        ):
            failures.append(f"{expected_environment}_session_event_stale")
        if not prior_production_baseline and sample_age is not None and sample_age > 2:
            failures.append(f"{expected_environment}_traffic_sample_stale")
        if soak_seconds < MIN_SOAK_SECONDS:
            failures.append(f"{expected_environment}_soak_window_too_short")
        if health_samples < MIN_HEALTH_SAMPLES:
            failures.append(f"{expected_environment}_health_samples_insufficient")
        if max_sample_gap > 120:
            failures.append(f"{expected_environment}_health_sample_gap_exceeded")
        if soak_seconds <= 0:
            failures.append(f"{expected_environment}_observation_window_invalid")
        relevant_failures = (
            (failure_counts["health_failures"],)
            if prior_production_baseline
            else tuple(failure_counts.values())
        )
        if any(value is not None and value > 0 for value in relevant_failures):
            failures.append(f"{expected_environment}_soak_failures_observed")
        if not prior_production_baseline:
            for resource, limit in zip(resource_peaks, (80, 90, 90)):
                if resource_peaks[resource] is not None and resource_peaks[resource] > limit:
                    failures.append(f"{expected_environment}_{resource}_exceeded")
        if expected_environment == "canary" and not rollback:
            failures.append("canary_rollback_drill_failed")
        if expected_environment == "canary" and not rollback_timestamp_in_window:
            failures.append("canary_rollback_evidence_stale_or_outside_window")
        if expected_environment == "canary" and not production_protected:
            failures.append("production_protection_unverified")
        if expected_environment == "canary" and not protection_timestamp_in_window:
            failures.append("production_protection_evidence_stale_or_outside_window")

        safe_records.append({
            "environment": expected_environment,
            "image": image,
            "revision": image_match.group("revision"),
            "digest": digest,
            "container_healthy": healthy,
            "app_ready": ready,
            "transport": None if prior_production_baseline else transport,
            "runtime_metrics_scope": "not-collected-prior-production-image" if prior_production_baseline else "collected",
            "rest_fallback": None if prior_production_baseline else fallback,
            "redis_configured": None if prior_production_baseline else redis_configured,
            "redis_publish_verified": None if prior_production_baseline else redis_available,
            "reconnect_recovered": None if prior_production_baseline else reconnect,
            "snapshot_recovered": None if prior_production_baseline else snapshot,
            "reconnect_recovery_counter_delta": None if prior_production_baseline else reconnect_counter_delta,
            "reconnect_recovery_counter_reset": None if prior_production_baseline else reconnect_counter_reset,
            "reconnect_observed_at": None if prior_production_baseline else reconnect_observed_at,
            "full_snapshot_recovered_at": None if prior_production_baseline else full_snapshot_recovered_at,
            "sqlite_restore_verified": None if prior_production_baseline else backup_restore,
            "sqlite_restore_verified_at": (
                None if prior_production_baseline or restore_verified_at is None
                else restore_verified_at.isoformat()
            ),
            "session_event_p95_ms": None if prior_production_baseline else latency,
            "session_event_latency_started_at": (
                None if prior_production_baseline or latency_started is None else latency_started.isoformat()
            ),
            "session_event_latency_ended_at": (
                None if prior_production_baseline or latency_ended is None else latency_ended.isoformat()
            ),
            "session_event_max_age_seconds": None if prior_production_baseline else session_event_age,
            "traffic_sample_age_seconds": None if prior_production_baseline else sample_age,
            "observation_started_at": started.isoformat(),
            "observation_ended_at": ended.isoformat(),
            "observation_window_seconds": soak_seconds,
            "health_sample_count": health_samples,
            "max_sample_gap_seconds": max_sample_gap,
            **{
                name: None if prior_production_baseline and name != "health_failures" else value
                for name, value in failure_counts.items()
            },
            **{
                name: None if prior_production_baseline else value
                for name, value in resource_peaks.items()
            },
            "rollback_drill_passed": None if prior_production_baseline else rollback,
            "rollback_drill_at": (
                None if prior_production_baseline or rollback_drill_at is None else rollback_drill_at.isoformat()
            ),
            "production_untouched_on_canary_failure": None if prior_production_baseline else production_protected,
            "production_protection_observed_at": (
                None if prior_production_baseline or production_protection_at is None
                else production_protection_at.isoformat()
            ),
        })

        if collection_started is not None and collection_ended is not None:
            if abs((started - collection_started).total_seconds()) > 1 or abs(
                (ended - collection_ended).total_seconds()
            ) > 1:
                failures.append(f"{expected_environment}_collection_window_mismatch")

    sqlite_restore_verification: dict[str, Any] | None = None
    if isinstance(collection, dict):
        raw_restore_verification = collection.get("sqlite_restore_verification")
        if raw_restore_verification is None:
            if collection_passed:
                failures.append("sqlite_restore_verification_missing")
        else:
            try:
                sqlite_restore_verification, stale_restore_environments = validate_restore_verification(
                    raw_restore_verification,
                    phase=collection_phase or "postpromotion",
                    deployments=safe_records,
                    now=current_time,
                )
                for check in sqlite_restore_verification["checks"]:
                    environment = check["environment"]
                    if not check["verified"]:
                        failures.append(f"{environment}_sqlite_restore_unverified")
                    if environment in stale_restore_environments:
                        failures.append(f"{environment}_sqlite_restore_evidence_stale_or_outside_window")
            except ValueError:
                failures.append("sqlite_restore_verification_invalid")

    registry_environments = (
        ("canary",) if collection_phase == "canary-prepromotion" else ENVIRONMENTS
    )
    if collection is not None:
        registry_digests_verified = True
        if not isinstance(registry_verification, list) or len(registry_verification) != len(registry_environments):
            raise ValueError("collection registry digest verification does not match its phase")
        for verification, expected_environment in zip(registry_verification, registry_environments):
            deployment = safe_records[ENVIRONMENTS.index(expected_environment)]
            if not isinstance(verification, dict):
                raise ValueError("registry digest verification entries must be objects")
            verified = (
                verification.get("environment") == expected_environment
                and verification.get("image") == deployment["image"]
                and verification.get("expected_digest") == deployment["digest"]
                and verification.get("observed_digest") == deployment["digest"]
                and verification.get("verified") is True
            )
            if not verified:
                failures.append(f"{expected_environment}_registry_digest_unverified")
                registry_digests_verified = False

    if collection_phase == "postpromotion":
        if safe_records[0]["image"] != safe_records[1]["image"]:
            failures.append("canary_production_image_mismatch")
        if safe_records[0]["digest"] != safe_records[1]["digest"]:
            failures.append("canary_production_digest_mismatch")
    elif collection_phase == "canary-prepromotion":
        if (
            safe_records[0]["image"] == safe_records[1]["image"]
            or (
                safe_records[0]["digest"] is not None
                and safe_records[1]["digest"] is not None
                and safe_records[0]["digest"] == safe_records[1]["digest"]
            )
        ):
            failures.append("prepromotion_production_not_on_prior_image")
    certificate_lifecycle_acceptance: dict[str, Any] | None = None
    if collection_passed and isinstance(collection, dict):
        raw_certificate_lifecycle = collection.get("certificate_lifecycle_acceptance")
        if raw_certificate_lifecycle is None:
            failures.append("certificate_lifecycle_acceptance_missing")
        else:
            try:
                certificate_lifecycle_acceptance = validate_certificate_lifecycle_acceptance(
                    raw_certificate_lifecycle,
                    candidate_image=safe_records[0]["image"],
                    candidate_digest=safe_records[0]["digest"],
                    collection_started_at=collection["started_at"],
                    collection_ended_at=collection["ended_at"],
                    allow_normalized_output=True,
                )
            except (KeyError, ValueError):
                failures.append("certificate_lifecycle_acceptance_invalid")
    routeros_resource_evidence: dict[str, Any] | None = None
    raw_routeros_evidence = collection.get("routeros_resource_evidence") if isinstance(collection, dict) else None
    if raw_routeros_evidence is None:
        if isinstance(collection, dict) and collection.get("passed") is True:
            failures.append("routeros_resource_evidence_missing")
    else:
        resource_names = (
            "router_cpu_peak_percent",
            "router_memory_peak_percent",
            "router_storage_peak_percent",
        )
        if not isinstance(raw_routeros_evidence, dict):
            failures.append("routeros_resource_evidence_invalid")
        else:
            try:
                routeros_started = _timestamp(raw_routeros_evidence, "observation_started_at")
                routeros_ended = _timestamp(raw_routeros_evidence, "observation_ended_at")
                sample_count = _count(raw_routeros_evidence, "sample_count")
                rest_parity_successful = _count(raw_routeros_evidence, "rest_parity_successful_sample_count")
                rest_parity_failed = _count(raw_routeros_evidence, "rest_parity_failed_sample_count")
                active_sessions_min = _count(raw_routeros_evidence, "active_vpn_sessions_min")
                active_sessions_max = _count(raw_routeros_evidence, "active_vpn_sessions_max")
                max_gap = _number(raw_routeros_evidence, "max_sample_gap_seconds")
                resource_values = raw_routeros_evidence.get("resource_peaks")
                if (
                    raw_routeros_evidence.get("format") != "vpn-dashboard-routeros-acceptance-v3"
                    or raw_routeros_evidence.get("container_revisions_matched") is not True
                    or rest_parity_successful != sample_count
                    or rest_parity_failed != 0
                    or active_sessions_max < active_sessions_min
                    or sample_count < MIN_HEALTH_SAMPLES
                    or max_gap > 120
                    or (routeros_ended - routeros_started).total_seconds() < MIN_SOAK_SECONDS
                    or collection_started is None
                    or collection_ended is None
                    or abs((routeros_started - collection_started).total_seconds()) > 60
                    or abs((routeros_ended - collection_ended).total_seconds()) > 60
                    or not isinstance(resource_values, dict)
                    or set(resource_values) != set(resource_names)
                ):
                    raise ValueError("invalid RouterOS resource evidence")
                resource_numbers = {
                    name: _number(resource_values, name)
                    for name in resource_names
                }
                for index, deployment in enumerate(safe_records):
                    if collection_phase == "canary-prepromotion" and index == 1:
                        continue
                    for name, expected_value in resource_numbers.items():
                        if deployment[name] != expected_value:
                            raise ValueError("RouterOS resource values do not match deployment evidence")
                if active_sessions_max < 1:
                    failures.append("vpn_test_session_not_observed")
                routeros_resource_evidence = {
                    "format": "vpn-dashboard-routeros-acceptance-v3",
                    "observation_started_at": routeros_started.isoformat(),
                    "observation_ended_at": routeros_ended.isoformat(),
                    "sample_count": sample_count,
                    "rest_parity_successful_sample_count": rest_parity_successful,
                    "rest_parity_failed_sample_count": rest_parity_failed,
                    "active_vpn_sessions_min": active_sessions_min,
                    "active_vpn_sessions_max": active_sessions_max,
                    "max_sample_gap_seconds": max_gap,
                    "resource_peaks": resource_numbers,
                    "container_revisions_matched": True,
                }
            except ValueError:
                failures.append("routeros_resource_evidence_invalid")
    report = {
        "format": "vpn-dashboard-release-acceptance-report-v2",
        "phase": collection_phase,
        "passed": not failures,
        "promotion_eligible": collection_phase == "canary-prepromotion" and not failures,
        "production_accepted": collection_phase == "postpromotion" and not failures,
        "registry_tag_digests_verified": registry_digests_verified,
        "registry_digest_verification_scope": (
            "candidate-canary-only" if collection_phase == "canary-prepromotion" else "canary-and-production"
        ),
        "router_runtime_digest_verified": False,
        "routeros_resource_evidence": routeros_resource_evidence,
        "certificate_lifecycle_acceptance": certificate_lifecycle_acceptance,
        "stream_acceptance": validated_stream_acceptance,
        "sqlite_restore_verification": sqlite_restore_verification,
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
    except (OSError, json.JSONDecodeError, ValueError):
        print(json.dumps({
            "passed": False,
            "failed_gates": ["invalid_input"],
            "error": "acceptance input is invalid or unreadable; details redacted",
        }))
        return 2
    rendered = json.dumps(report, sort_keys=True, indent=2) + "\n"
    if args.output:
        Path(args.output).write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
