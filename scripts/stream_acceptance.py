"""Validate and redact live browser plus Socket.IO canary evidence."""

from __future__ import annotations

from datetime import datetime, timezone
import math
import re
from typing import Any


MAX_WINDOW_SKEW_SECONDS = 5
MAX_REPORT_AGE_SECONDS = 900
MAX_BROWSER_EVENT_LATENCY_MS = 1000
MAX_BROWSER_TRAFFIC_AGE_SECONDS = 2
CANARY_ORIGIN = "https://vpn-dev.wanted.sx"
REVISION_PATTERN = re.compile(r"^[0-9a-f]{40}$")
VERIFICATION_FIELDS = frozenset({
    "event_latency_measured", "traffic_freshness_measured", "counter_reset_tested",
    "event_integrity_tested", "binary_rest_parity_tested", "secret_scan_complete",
})

OBSERVER_FIELDS = frozenset({
    "format", "started_at", "ended_at", "duration_seconds", "origin_role", "origin",
    "candidate_revision", "observed_revision",
    "transport", "connections", "disconnects", "reconnects",
    "stream_connected_at_end", "event_count", "event_counts", "snapshot_count",
    "reconnect_snapshot_count", "sequence_gaps", "duplicate_sequences",
    "out_of_order_sequences", "rejected_frames", "raw_frames_written",
    "identities_or_addresses_written", "credentials_written", "latency_measured",
    "latency_note", "failed_gates", "observed_stream_healthy",
})

BROWSER_FIELDS = frozenset({
    "format", "healthy", "failed_gates", "observation_started_at", "origin",
    "candidate_revision", "observed_revision", "identity_verified",
    "observation_ended_at", "session_transition_count",
    "session_transition_visible_count", "connected_transition_observed",
    "disconnected_transition_observed", "ordered_connect_disconnect_observed",
    "session_event_latency_p95_ms",
    "session_event_age_max_seconds",
    "traffic_update_count", "traffic_update_visible_count",
    "traffic_sample_age_max_seconds", "event_sequence_observation_count",
    "event_sequence_gap_count", "duplicate_event_count",
    "out_of_order_event_count", "reconnect_test_count", "reconnect_success_count",
    "security_tests", "verification",
})


def browser_acceptance_projection(result: Any) -> dict[str, Any] | None:
    """Keep only the stable aggregate contract emitted by telemetry_acceptance."""
    if not isinstance(result, dict):
        return None
    projected = {name: result.get(name) for name in BROWSER_FIELDS}
    verification = result.get("verification")
    projected["verification"] = (
        {name: verification.get(name) for name in VERIFICATION_FIELDS}
        if isinstance(verification, dict)
        else None
    )
    return projected


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


def _finite_number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    parsed = float(value)
    return parsed if math.isfinite(parsed) else None


def _count(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def _window_valid(
    started: datetime | None,
    ended: datetime | None,
    collection_started: datetime,
    collection_ended: datetime,
    *,
    minimum_seconds: float,
) -> bool:
    if started is None or ended is None:
        return False
    duration = (ended - started).total_seconds()
    return (
        duration >= minimum_seconds
        and started <= ended
        and abs(started.timestamp() - collection_started.timestamp()) <= MAX_WINDOW_SKEW_SECONDS
        and abs(ended.timestamp() - collection_ended.timestamp()) <= MAX_WINDOW_SKEW_SECONDS
    )


def validate_stream_acceptance(
    observer: Any,
    browser: Any,
    *,
    collection_started_at: str,
    collection_ended_at: str,
    now: datetime,
    expected_candidate_revision: str | None = None,
    minimum_window_seconds: float = 1800,
) -> tuple[dict[str, Any], list[str]]:
    """Return a safe aggregate projection and stable, non-sensitive gate names."""
    start = _timestamp(collection_started_at)
    end = _timestamp(collection_ended_at)
    if start is None or end is None or end <= start:
        raise ValueError("release collection window is invalid")
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("evaluation time must include a timezone")

    failed: list[str] = []
    safe: dict[str, Any] = {"format": "vpn-dashboard-stream-acceptance-v2"}

    if not isinstance(observer, dict):
        failed.append("stream_observation_missing")
    else:
        if set(observer) != OBSERVER_FIELDS:
            failed.append("stream_observation_schema_invalid")
        obs_start = _timestamp(observer.get("started_at"))
        obs_end = _timestamp(observer.get("ended_at"))
        duration = _finite_number(observer.get("duration_seconds"))
        stale = (
            obs_end is None
            or (now.astimezone(timezone.utc) - obs_end).total_seconds() > MAX_REPORT_AGE_SECONDS
            or (now.astimezone(timezone.utc) - obs_end).total_seconds() < -300
        )
        if stale:
            failed.append("stream_observation_stale")
        if not _window_valid(
            obs_start, obs_end, start, end,
            minimum_seconds=minimum_window_seconds,
        ) or duration is None or obs_start is None or obs_end is None or abs(
            duration - (obs_end - obs_start).total_seconds()
        ) > MAX_WINDOW_SKEW_SECONDS:
            failed.append("stream_observation_window_invalid")
        counts = {
            name: _count(observer.get(name))
            for name in (
                "connections", "disconnects", "reconnects", "event_count",
                "snapshot_count", "reconnect_snapshot_count", "sequence_gaps",
                "duplicate_sequences", "out_of_order_sequences", "rejected_frames",
            )
        }
        raw_event_counts = observer.get("event_counts")
        event_counts: dict[str, int] = {}
        if isinstance(raw_event_counts, dict):
            allowed_event_names = {
                "telemetry.snapshot", "vpn.session.connected", "vpn.session.updated",
                "vpn.session.disconnected", "vpn.interface.counters", "telemetry.counter_reset",
                "router.capacity.updated", "router.health.updated", "telemetry.reconciled",
                "telemetry.health",
            }
            if all(name in allowed_event_names and _count(value) is not None for name, value in raw_event_counts.items()):
                event_counts = dict(raw_event_counts)
        if any(value is None for value in counts.values()):
            failed.append("stream_observation_counts_invalid")
        if observer.get("format") != "vpn-dashboard-telemetry-stream-observation-v1" or (
            observer.get("origin_role") != "canary"
            or observer.get("transport") != "socketio-websocket"
        ):
            failed.append("stream_observation_identity_invalid")
        if (
            expected_candidate_revision is None
            or not isinstance(expected_candidate_revision, str)
            or not REVISION_PATTERN.fullmatch(expected_candidate_revision)
        ):
            failed.append("stream_candidate_revision_unavailable")
        if (
            observer.get("origin") != CANARY_ORIGIN
            or observer.get("candidate_revision") != expected_candidate_revision
            or observer.get("observed_revision") != expected_candidate_revision
        ):
            failed.append("stream_candidate_identity_mismatch")
        if observer.get("observed_stream_healthy") is not True or observer.get("failed_gates") != []:
            failed.append("stream_observation_failed")
        if observer.get("stream_connected_at_end") is not True:
            failed.append("stream_not_connected_at_window_end")
        if counts["event_count"] == 0:
            failed.append("stream_events_missing")
        if counts["connections"] is None or counts["connections"] < 2 or (
            counts["disconnects"] is None or counts["disconnects"] < 1
        ) or counts["reconnects"] is None or counts["reconnects"] < 1 or (
            counts["reconnects"] != counts["connections"] - 1
            or counts["disconnects"] < counts["reconnects"]
            or counts["snapshot_count"] != event_counts.get("telemetry.snapshot", 0)
        ) or (
            counts["reconnect_snapshot_count"] is None or counts["reconnect_snapshot_count"] < 1
            or counts["reconnect_snapshot_count"] > counts["snapshot_count"]
        ):
            failed.append("stream_reconnect_snapshot_missing")
        if any(counts[name] != 0 for name in (
            "sequence_gaps", "duplicate_sequences", "out_of_order_sequences", "rejected_frames"
        ) if counts[name] is not None):
            failed.append("stream_sequence_integrity_failed")
        if observer.get("raw_frames_written") is not False or (
            observer.get("identities_or_addresses_written") is not False
            or observer.get("credentials_written") is not False
        ):
            failed.append("stream_redaction_contract_failed")
        if observer.get("latency_measured") is not False:
            failed.append("stream_observer_contract_invalid")
        if sum(event_counts.values()) != counts["event_count"]:
            failed.append("stream_observation_counts_invalid")
        safe["stream_observation"] = {
            "format": "vpn-dashboard-telemetry-stream-observation-v1",
            "started_at": observer.get("started_at") if obs_start else None,
            "ended_at": observer.get("ended_at") if obs_end else None,
            "duration_seconds": duration,
            "origin_role": "canary",
            "origin": observer.get("origin") if observer.get("origin") == CANARY_ORIGIN else None,
            "candidate_revision": observer.get("candidate_revision")
            if isinstance(observer.get("candidate_revision"), str)
            and REVISION_PATTERN.fullmatch(observer["candidate_revision"]) else None,
            "observed_revision": observer.get("observed_revision")
            if isinstance(observer.get("observed_revision"), str)
            and REVISION_PATTERN.fullmatch(observer["observed_revision"]) else None,
            "transport": "socketio-websocket",
            "event_counts": event_counts,
            **counts,
            "stream_connected_at_end": observer.get("stream_connected_at_end") is True,
            "raw_frames_written": False,
            "identities_or_addresses_written": False,
            "credentials_written": False,
            "latency_measured": False,
            "latency_note": "not measured; client/server clock offset is not established",
            "failed_gates": [],
            "observed_stream_healthy": observer.get("observed_stream_healthy") is True
            and observer.get("failed_gates") == [],
        }

    if not isinstance(browser, dict):
        failed.append("browser_telemetry_evidence_missing")
    else:
        if set(browser) != BROWSER_FIELDS:
            failed.append("browser_telemetry_schema_invalid")
        browser_start = _timestamp(browser.get("observation_started_at"))
        browser_end = _timestamp(browser.get("observation_ended_at"))
        if not _window_valid(
            browser_start, browser_end, start, end,
            minimum_seconds=minimum_window_seconds,
        ):
            failed.append("browser_telemetry_window_invalid")
        if browser_end is None or (
            now.astimezone(timezone.utc) - browser_end
        ).total_seconds() > MAX_REPORT_AGE_SECONDS:
            failed.append("browser_telemetry_stale")
        if browser.get("format") != "vpn-dashboard-telemetry-acceptance-v2":
            failed.append("browser_telemetry_format_invalid")
        if (
            browser.get("origin") != CANARY_ORIGIN
            or browser.get("candidate_revision") != expected_candidate_revision
            or browser.get("observed_revision") != expected_candidate_revision
            or browser.get("identity_verified") is not True
        ):
            failed.append("browser_candidate_identity_mismatch")
        if browser.get("healthy") is not True or browser.get("failed_gates") != []:
            failed.append("browser_telemetry_failed")
        security_tests = _count(browser.get("security_tests"))
        verification = browser.get("verification")
        if (
            security_tests is None or security_tests < 1
            or not isinstance(verification, dict)
            or set(verification) != VERIFICATION_FIELDS
            or any(not isinstance(verification.get(name), bool) for name in VERIFICATION_FIELDS)
            or not all(verification.get(name) is True for name in VERIFICATION_FIELDS)
        ):
            failed.append("browser_security_verification_incomplete")

        numbers = {
            name: _count(browser.get(name))
            for name in (
                "session_transition_count", "session_transition_visible_count",
                "traffic_update_count", "traffic_update_visible_count",
                "event_sequence_observation_count", "event_sequence_gap_count",
                "duplicate_event_count", "out_of_order_event_count",
                "reconnect_test_count", "reconnect_success_count",
            )
        }
        latency = _finite_number(browser.get("session_event_latency_p95_ms"))
        session_age = _finite_number(browser.get("session_event_age_max_seconds"))
        traffic_age = _finite_number(browser.get("traffic_sample_age_max_seconds"))
        if any(value is None for value in numbers.values()):
            failed.append("browser_telemetry_counts_invalid")
        if latency is None:
            failed.append("browser_event_latency_missing")
        elif latency < 0:
            failed.append("browser_event_latency_invalid")
        elif latency > MAX_BROWSER_EVENT_LATENCY_MS:
            failed.append("browser_event_latency_exceeded")
        if session_age is None:
            failed.append("browser_session_freshness_missing")
        elif session_age < 0:
            failed.append("browser_session_event_future_dated")
        elif session_age > MAX_BROWSER_TRAFFIC_AGE_SECONDS:
            failed.append("browser_session_event_stale")
        if traffic_age is None:
            failed.append("browser_traffic_freshness_missing")
        elif traffic_age < 0:
            failed.append("browser_traffic_sample_future_dated")
        elif traffic_age > MAX_BROWSER_TRAFFIC_AGE_SECONDS:
            failed.append("browser_traffic_sample_stale")
        if numbers["session_transition_count"] is None or numbers["session_transition_count"] < 2 or (
            numbers["session_transition_visible_count"] != numbers["session_transition_count"]
            or browser.get("connected_transition_observed") is not True
            or browser.get("disconnected_transition_observed") is not True
            or browser.get("ordered_connect_disconnect_observed") is not True
        ):
            failed.append("browser_session_visibility_incomplete")
        if numbers["traffic_update_count"] is None or numbers["traffic_update_count"] < 2 or (
            numbers["traffic_update_visible_count"] != numbers["traffic_update_count"]
        ):
            failed.append("browser_traffic_visibility_incomplete")
        if numbers["event_sequence_observation_count"] is None or numbers["event_sequence_observation_count"] < 30:
            failed.append("browser_event_sequence_evidence_missing")
        if any(numbers[name] != 0 for name in (
            "event_sequence_gap_count", "duplicate_event_count", "out_of_order_event_count"
        ) if numbers[name] is not None):
            failed.append("browser_event_integrity_failed")
        if numbers["reconnect_test_count"] is None or numbers["reconnect_test_count"] < 1 or (
            numbers["reconnect_success_count"] != numbers["reconnect_test_count"]
        ):
            failed.append("browser_reconnect_evidence_failed")
        safe["browser_telemetry"] = {
            "format": "vpn-dashboard-telemetry-acceptance-v2",
            "origin": browser.get("origin") if browser.get("origin") == CANARY_ORIGIN else None,
            "candidate_revision": browser.get("candidate_revision")
            if isinstance(browser.get("candidate_revision"), str)
            and REVISION_PATTERN.fullmatch(browser["candidate_revision"]) else None,
            "observed_revision": browser.get("observed_revision")
            if isinstance(browser.get("observed_revision"), str)
            and REVISION_PATTERN.fullmatch(browser["observed_revision"]) else None,
            "identity_verified": browser.get("identity_verified") is True,
            "failed_gates": [],
            "observation_started_at": browser.get("observation_started_at") if browser_start else None,
            "observation_ended_at": browser.get("observation_ended_at") if browser_end else None,
            **numbers,
            "session_event_latency_p95_ms": latency,
            "session_event_age_max_seconds": session_age,
            "traffic_sample_age_max_seconds": traffic_age,
            "connected_transition_observed": browser.get("connected_transition_observed") is True,
            "disconnected_transition_observed": browser.get("disconnected_transition_observed") is True,
            "ordered_connect_disconnect_observed": browser.get("ordered_connect_disconnect_observed") is True,
            "healthy": browser.get("healthy") is True and browser.get("failed_gates") == [],
            "security_tests": security_tests,
            "verification": (
                {name: verification.get(name) for name in VERIFICATION_FIELDS}
                if isinstance(verification, dict) else None
            ),
        }

    return safe, sorted(set(failed))
