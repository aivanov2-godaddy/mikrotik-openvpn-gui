"""Collect bounded, redacted release evidence from private app probes.

RouterOS-specific measurements remain operator-supplied in the evidence file.
The canary-prepromotion phase verifies the candidate while production stays on
its recorded prior revision. The postpromotion phase requires both environments
on the same candidate. Network probes are read-only; SQLite restore checks use
only private local sources and a temporary copy. The candidate digest (and,
after promotion, the production digest) is checked against GHCR before the soak.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

try:
    from certificate_lifecycle_acceptance import validate_certificate_lifecycle_acceptance
    from release_acceptance import DIGEST, ENVIRONMENTS, IMAGE, evaluate as validate_evidence
    from stream_acceptance import CANARY_ORIGIN, browser_acceptance_projection, validate_stream_acceptance
    from sqlite_restore_verifier import RESTORE_REPORT_FORMAT, verify_sqlite_restore
    import redis_recovery_acceptance as redis_recovery_acceptance_module
    from redis_recovery_acceptance import (
        download_verified_ci_report,
        validate_ci_provenance,
        validate_report as validate_redis_recovery_report,
    )
    from rollback_acceptance import summarize_rollback_report, validate_rollback_report
except ModuleNotFoundError:
    from scripts.certificate_lifecycle_acceptance import validate_certificate_lifecycle_acceptance
    from scripts.release_acceptance import DIGEST, ENVIRONMENTS, IMAGE, evaluate as validate_evidence
    from scripts.stream_acceptance import CANARY_ORIGIN, browser_acceptance_projection, validate_stream_acceptance
    from scripts.sqlite_restore_verifier import RESTORE_REPORT_FORMAT, verify_sqlite_restore
    import scripts.redis_recovery_acceptance as redis_recovery_acceptance_module
    from scripts.redis_recovery_acceptance import (
        download_verified_ci_report,
        validate_ci_provenance,
        validate_report as validate_redis_recovery_report,
    )
    from scripts.rollback_acceptance import summarize_rollback_report, validate_rollback_report


MAX_REDIS_RECOVERY_REPORT_BYTES = redis_recovery_acceptance_module.MAX_CI_ARTIFACT_BYTES
MAX_RESPONSE_BYTES = 1_000_000
MAX_REGISTRY_RESPONSE_BYTES = 65_536
MAX_DURATION_SECONDS = 86_400
MAX_SAMPLES = 10_000
MAX_STREAM_OBSERVER_REPORT_BYTES = 65_536
MAX_TELEMETRY_ACCEPTANCE_BYTES = 5_000_000
MAX_CERTIFICATE_LIFECYCLE_REPORT_BYTES = 16_384
MAX_ROLLBACK_REPORT_BYTES = 32_768
MIN_SOAK_SECONDS = 1800
MIN_HEALTH_SAMPLES = 30
MAX_SAMPLE_GAP_SECONDS = 120
MAX_TRAFFIC_SAMPLE_AGE_SECONDS = 2.0
MAX_SESSION_EVENT_AGE_SECONDS = 2.0
MAX_REDIS_PUBLISH_AGE_SECONDS = 120.0
MAX_GATEWAY_DELIVERY_P95_SECONDS = 1.0
MAX_OUTBOX_PENDING_AT_WINDOW_END = 0
MAX_OUTBOX_DEAD_LETTERED = 0
MAX_CLOCK_DRIFT_SECONDS = 5.0
METRIC_NAMES = {
    "vpn_dashboard_health",
    "vpn_dashboard_process_start_time_seconds",
    "vpn_dashboard_redis_configured",
    "vpn_dashboard_redis_last_observed_available",
    "vpn_dashboard_redis_publish_total",
    "vpn_dashboard_redis_last_publish_success_timestamp_seconds",
    "vpn_dashboard_integration_outbox_pending",
    "vpn_dashboard_integration_outbox_dead_lettered",
    "vpn_dashboard_integration_outbox_oldest_age_seconds",
    "vpn_dashboard_integration_outbox_storage_failures_total",
    "vpn_dashboard_telemetry_session_event_age_seconds",
    "vpn_dashboard_telemetry_session_event_timestamp_seconds",
    "vpn_dashboard_telemetry_session_events_total",
    "vpn_dashboard_telemetry_traffic_sample_age_seconds",
    "vpn_dashboard_telemetry_traffic_sample_timestamp_seconds",
    "vpn_dashboard_telemetry_traffic_samples_total",
    "vpn_dashboard_telemetry_gateway_clients",
    "vpn_dashboard_telemetry_gateway_buffered_events",
    "vpn_dashboard_telemetry_gateway_events_total",
    "vpn_dashboard_telemetry_gateway_rejected_clients_total",
    "vpn_dashboard_telemetry_gateway_delivery_queue_age_seconds",
    "vpn_dashboard_telemetry_gateway_delivery_queue_age_p95_seconds",
    "vpn_dashboard_telemetry_gateway_delivery_observations",
    "vpn_dashboard_telemetry_supervisor_enabled",
    "vpn_dashboard_telemetry_supervisor_status",
    "vpn_dashboard_telemetry_supervisor_attempts_total",
    "vpn_dashboard_telemetry_supervisor_reconnects_total",
    "vpn_dashboard_telemetry_supervisor_failures_total",
    "vpn_dashboard_telemetry_supervisor_events_total",
    "vpn_dashboard_telemetry_supervisor_last_connected_timestamp_seconds",
    "vpn_dashboard_telemetry_supervisor_last_event_timestamp_seconds",
    "vpn_dashboard_telemetry_supervisor_last_snapshot_timestamp_seconds",
    "vpn_dashboard_telemetry_supervisor_backoff_seconds",
}


def apply_stream_acceptance(
    summary: dict[str, Any], observer_report: Any, browser_report: Any,
    *, now: datetime | None = None, minimum_window_seconds: float = 1800,
) -> tuple[int, dict[str, Any]]:
    """Attach a strict redacted stream/browser report to collected evidence."""
    collection = summary.get("evidence", {}).get("collection", {})
    deployments = summary.get("evidence", {}).get("deployments", [])
    candidate_revision = None
    if isinstance(deployments, list) and deployments and isinstance(deployments[0], dict):
        candidate_revision = deployments[0].get("revision")
        if not isinstance(candidate_revision, str):
            image_match = IMAGE.fullmatch(str(deployments[0].get("image", "")))
            candidate_revision = image_match.group("revision") if image_match else None
    safe, stream_failures = validate_stream_acceptance(
        observer_report,
        browser_report,
        collection_started_at=collection.get("started_at"),
        collection_ended_at=collection.get("ended_at"),
        now=now or _utc_now(),
        expected_candidate_revision=candidate_revision,
        minimum_window_seconds=minimum_window_seconds,
    )
    failures = set(collection.get("failed_gates", []))
    failures.discard("stream_observation_missing")
    failures.discard("browser_telemetry_evidence_missing")
    failures.update(stream_failures)
    collection["stream_acceptance"] = safe
    browser = safe.get("browser_telemetry", {})
    if summary.get("evidence", {}).get("deployments"):
        canary_record = summary["evidence"]["deployments"][0]
        canary_record["session_event_p95_ms"] = browser.get("session_event_latency_p95_ms")
        canary_record["session_event_latency_started_at"] = browser.get("observation_started_at")
        canary_record["session_event_latency_ended_at"] = browser.get("observation_ended_at")
        canary_record["session_event_max_age_seconds"] = browser.get("session_event_age_max_seconds")
        canary_record["traffic_sample_age_seconds"] = browser.get("traffic_sample_age_max_seconds")
    collection["failed_gates"] = sorted(failures)
    collection["passed"] = not failures
    summary["failed_gates"] = sorted(failures)
    summary["passed"] = not failures
    summary["stream_acceptance"] = {
        "healthy": not stream_failures,
        "failed_gates": stream_failures,
    }
    return (0 if not failures else 1), summary


def finalize_release_acceptance(
    summary: dict[str, Any],
    *,
    phase: str,
    now: datetime | None = None,
) -> tuple[int, dict[str, Any]]:
    """Apply the central release evaluator as the final promotion gate.

    Collection and stream/browser checks are intentionally separate stages;
    neither stage alone is sufficient to mark a release accepted.
    """
    evidence = summary.get("evidence")
    if not isinstance(evidence, dict):
        raise ValueError("release evidence is missing")
    acceptance_code, acceptance = validate_evidence(
        evidence, phase=phase, now=now or _utc_now()
    )
    acceptance_failures = acceptance.get("failed_gates", [])
    if not isinstance(acceptance_failures, list):
        raise ValueError("release acceptance result is invalid")
    failed_gates = set(summary.get("failed_gates", []))
    failed_gates.update(gate for gate in acceptance_failures if isinstance(gate, str))
    passed = summary.get("passed") is True and acceptance_code == 0 and not failed_gates
    summary["passed"] = passed
    summary["failed_gates"] = sorted(failed_gates)
    summary["release_acceptance"] = {
        "passed": acceptance.get("passed") is True and acceptance_code == 0,
        "promotion_eligible": acceptance.get("promotion_eligible") is True and acceptance_code == 0,
        "production_accepted": acceptance.get("production_accepted") is True and acceptance_code == 0,
        "failed_gates": sorted(gate for gate in acceptance_failures if isinstance(gate, str)),
    }
    return (0 if passed else 1), summary
REQUIRED_ACCEPTANCE_METRICS = {
    "vpn_dashboard_process_start_time_seconds",
    "vpn_dashboard_redis_configured",
    "vpn_dashboard_redis_last_observed_available",
    "vpn_dashboard_redis_publish_total_success",
    "vpn_dashboard_redis_publish_total_failure",
    "vpn_dashboard_redis_last_publish_success_timestamp_seconds",
    "vpn_dashboard_integration_outbox_pending",
    "vpn_dashboard_integration_outbox_dead_lettered",
    "vpn_dashboard_integration_outbox_oldest_age_seconds",
    "vpn_dashboard_integration_outbox_storage_failures_total",
    "vpn_dashboard_telemetry_session_event_age_seconds",
    "vpn_dashboard_telemetry_session_event_timestamp_seconds",
    "vpn_dashboard_telemetry_traffic_sample_age_seconds",
    "vpn_dashboard_telemetry_traffic_sample_timestamp_seconds",
    "vpn_dashboard_telemetry_gateway_clients",
    "vpn_dashboard_telemetry_gateway_buffered_events",
    "vpn_dashboard_telemetry_gateway_events_total_published",
    "vpn_dashboard_telemetry_gateway_events_total_replayed",
    "vpn_dashboard_telemetry_gateway_rejected_clients_total",
    "vpn_dashboard_telemetry_gateway_delivery_queue_age_seconds",
    "vpn_dashboard_telemetry_gateway_delivery_queue_age_p95_seconds",
    "vpn_dashboard_telemetry_gateway_delivery_observations",
    "vpn_dashboard_telemetry_supervisor_enabled",
    "vpn_dashboard_telemetry_supervisor_status_disabled",
    "vpn_dashboard_telemetry_supervisor_status_connecting",
    "vpn_dashboard_telemetry_supervisor_status_healthy",
    "vpn_dashboard_telemetry_supervisor_status_degraded",
    "vpn_dashboard_telemetry_supervisor_status_stopped",
    "vpn_dashboard_telemetry_supervisor_status_unknown",
    "vpn_dashboard_telemetry_supervisor_attempts_total",
    "vpn_dashboard_telemetry_supervisor_reconnects_total",
    "vpn_dashboard_telemetry_supervisor_failures_total",
    "vpn_dashboard_telemetry_supervisor_events_total",
    "vpn_dashboard_telemetry_supervisor_last_connected_timestamp_seconds",
    "vpn_dashboard_telemetry_supervisor_last_event_timestamp_seconds",
    "vpn_dashboard_telemetry_supervisor_last_snapshot_timestamp_seconds",
    "vpn_dashboard_telemetry_supervisor_backoff_seconds",
}
METRIC_LINE = re.compile(
    r'^(?P<name>[a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{(?P<labels>[^}]*)\})?\s+'
    r'(?P<value>[-+]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][-+]?\d+)?|NaN|[+-]?Inf)(?:\s+\d+)?$'
)
REVISION_IN_IMAGE = re.compile(
    r":sha-(?P<revision>[0-9a-f]{40})-(?:arm64|amd64)(?:@sha256:[0-9a-f]{64})?$"
)
ROUTEROS_RESOURCE_FIELDS = {
    "router_cpu_peak_percent": ("router_cpu_peak_percent", 80),
    "router_memory_peak_percent": ("router_memory_peak_percent", 90),
    "router_storage_peak_percent": ("router_storage_peak_percent", 90),
}


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request: Request, fp: Any, code: int, msg: str, headers: Any, new_url: str) -> None:
        return None


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _write_json_atomically(path: Path, document: dict[str, Any]) -> None:
    """Replace an evidence report atomically so partial/stale JSON is never left behind."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temporary_path = Path(temporary.name)
            temporary.write(json.dumps(document, sort_keys=True, indent=2) + "\n")
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_path, path)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def _read_certificate_lifecycle_report(path: str | Path) -> Any:
    """Load a tightly bounded operator report without retaining oversized input."""
    return _read_bounded_json_report(
        path, MAX_CERTIFICATE_LIFECYCLE_REPORT_BYTES, "certificate lifecycle report"
    )


def _read_bounded_json_report(path: str | Path, max_bytes: int, label: str) -> Any:
    """Read JSON through a bounded binary handle to avoid stat/read races."""
    with Path(path).open("rb") as source:
        content = source.read(max_bytes + 1)
    if len(content) > max_bytes:
        raise ValueError(f"{label} exceeds its size limit")
    return json.loads(content)


def _evidence_timestamp(value: Any, name: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a timezone-aware ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"{name} must be a timezone-aware ISO-8601 timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{name} must be a timezone-aware ISO-8601 timestamp")
    return parsed


def attach_routeros_resource_evidence(evidence: dict[str, Any], routeros: Any) -> None:
    """Join a redacted RouterOS sample window to matching app-soak evidence."""
    if not isinstance(routeros, dict) or routeros.get("format") != "vpn-dashboard-routeros-acceptance-v3":
        raise ValueError("RouterOS evidence format is invalid")
    if routeros.get("passed") is not True or routeros.get("failed_gates") != []:
        raise ValueError("RouterOS evidence did not pass its acceptance gates")
    if routeros.get("credentials_or_raw_router_data_written") is not False:
        raise ValueError("RouterOS evidence privacy attestation is missing")

    sample_count = routeros.get("sample_count")
    successful_count = routeros.get("successful_sample_count")
    failed_count = routeros.get("failed_sample_count")
    rest_successful_count = routeros.get("rest_parity_successful_sample_count")
    rest_failed_count = routeros.get("rest_parity_failed_sample_count")
    active_sessions_min = routeros.get("active_vpn_sessions_min")
    active_sessions_max = routeros.get("active_vpn_sessions_max")
    if (
        isinstance(sample_count, bool) or not isinstance(sample_count, int) or sample_count < 30
        or isinstance(successful_count, bool) or successful_count != sample_count
        or isinstance(failed_count, bool) or failed_count != 0
        or isinstance(rest_successful_count, bool) or rest_successful_count != sample_count
        or isinstance(rest_failed_count, bool) or rest_failed_count != 0
        or isinstance(active_sessions_min, bool) or not isinstance(active_sessions_min, int) or active_sessions_min < 0
        or isinstance(active_sessions_max, bool) or not isinstance(active_sessions_max, int)
        or active_sessions_max < active_sessions_min
        or routeros.get("read_only_rest_paths") != ["/rest/system/resource", "/rest/container", "/rest/ppp/active"]
    ):
        raise ValueError("RouterOS evidence sample coverage is incomplete")
    max_gap = routeros.get("max_sample_gap_seconds")
    duration = routeros.get("duration_seconds")
    if (
        isinstance(max_gap, bool) or not isinstance(max_gap, (int, float))
        or not math.isfinite(max_gap) or max_gap < 0 or max_gap > 120
        or isinstance(duration, bool) or not isinstance(duration, (int, float))
        or not math.isfinite(duration) or duration < MIN_SOAK_SECONDS
    ):
        raise ValueError("RouterOS evidence window is incomplete")
    router_started = _evidence_timestamp(routeros.get("observation_started_at"), "RouterOS start")
    router_ended = _evidence_timestamp(routeros.get("observation_ended_at"), "RouterOS end")
    if (router_ended - router_started).total_seconds() < MIN_SOAK_SECONDS:
        raise ValueError("RouterOS evidence observation window is too short")

    collection = evidence.get("collection")
    deployments = evidence.get("deployments")
    if not isinstance(collection, dict) or not isinstance(deployments, list) or len(deployments) != 2:
        raise ValueError("app evidence is missing its collection window or deployments")
    app_started = _evidence_timestamp(collection.get("started_at"), "app start")
    app_ended = _evidence_timestamp(collection.get("ended_at"), "app end")
    if (
        abs((router_started - app_started).total_seconds()) > 60
        or abs((router_ended - app_ended).total_seconds()) > 60
    ):
        raise ValueError("RouterOS and app evidence windows do not align")

    containers = routeros.get("containers")
    if not isinstance(containers, dict) or set(containers) != set(ENVIRONMENTS):
        raise ValueError("RouterOS evidence is missing named container observations")
    resources: dict[str, float] = {}
    for output_field, (source_field, threshold) in ROUTEROS_RESOURCE_FIELDS.items():
        value = routeros.get(source_field)
        if (
            isinstance(value, bool) or not isinstance(value, (int, float))
            or not math.isfinite(value) or value < 0 or value > threshold
        ):
            raise ValueError("RouterOS resource evidence is invalid or exceeds its threshold")
        resources[output_field] = float(value)

    for environment, record in zip(ENVIRONMENTS, deployments):
        if not isinstance(record, dict) or record.get("environment") != environment:
            raise ValueError("app deployments must be ordered canary then production")
        image_match = IMAGE.fullmatch(str(record.get("image", "")))
        if image_match is None:
            raise ValueError("app deployment image must use a full immutable revision tag")
        observed = containers[environment]
        expected_revision = image_match.group("revision")
        if (
            not isinstance(observed, dict)
            or observed.get("healthy_for_all_successful_samples") is not True
            or observed.get("observed_source_revisions") != [expected_revision]
        ):
            raise ValueError("RouterOS container health or revision does not match app evidence")
        record.update(resources)

    collection["routeros_resource_evidence"] = {
        "format": "vpn-dashboard-routeros-acceptance-v3",
        "observation_started_at": router_started.isoformat(),
        "observation_ended_at": router_ended.isoformat(),
        "sample_count": sample_count,
        "rest_parity_successful_sample_count": rest_successful_count,
        "rest_parity_failed_sample_count": rest_failed_count,
        "active_vpn_sessions_min": active_sessions_min,
        "active_vpn_sessions_max": active_sessions_max,
        "max_sample_gap_seconds": float(max_gap),
        "resource_peaks": resources,
        "container_revisions_matched": True,
    }


def _probe_url(base_url: str, path: str) -> str:
    parsed = urlsplit(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("probe URL must be an absolute HTTP(S) origin")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("probe URL must not contain credentials, query, or fragment")
    if parsed.path not in {"", "/"}:
        raise ValueError("probe URL must be an origin without a path")
    return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


def _origin(base_url: str) -> tuple[str, str, int]:
    parsed = urlsplit(_probe_url(base_url, "/"))
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").rstrip(".").lower()
    port = parsed.port or (443 if scheme == "https" else 80)
    return scheme, host, port


def _get(
    url: str,
    *,
    cookie: str | None = None,
    api_token: str | None = None,
    timeout: float,
) -> tuple[int, bytes]:
    headers = {"Accept": "application/json, text/plain; version=0.0.4"}
    if cookie and api_token:
        raise ValueError("use either a session cookie or an API token, not both")
    if cookie:
        headers["Cookie"] = cookie
    if api_token:
        headers["Authorization"] = f"Bearer {api_token}"
    request = Request(url, headers=headers, method="GET")
    opener = build_opener(_NoRedirect())
    try:
        with opener.open(request, timeout=timeout) as response:
            payload = response.read(MAX_RESPONSE_BYTES + 1)
            status = response.status
    except HTTPError as error:
        # Do not retain or print response bodies, headers, or exception text.
        status = error.code
        error.close()
        return status, b""
    except (URLError, TimeoutError, OSError):
        return 0, b""
    if len(payload) > MAX_RESPONSE_BYTES:
        return 0, b""
    return status, payload


def _registry_digest(image: str, *, timeout: float) -> str | None:
    """Return a GHCR digest, enforcing a total deadline with a worker process."""
    if not IMAGE.fullmatch(image) or not math.isfinite(timeout) or timeout <= 0:
        return None
    try:
        result = subprocess.run(
            [sys.executable, str(Path(__file__).resolve()), "--internal-ghcr-digest", image, str(timeout)],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=timeout + 0.5,
            text=True,
            encoding="utf-8",
        )
    except (OSError, subprocess.SubprocessError, TimeoutError):
        return None
    digest = result.stdout.strip() if result.returncode == 0 else ""
    return digest if DIGEST.fullmatch(digest) else None


def _registry_digest_request(image: str, *, timeout: float) -> str | None:
    """Fetch the GHCR manifest digest; the parent enforces the wall deadline.

    Only GHCR is queried, redirects are disabled, response sizes are bounded,
    and the short-lived anonymous pull token is never returned or logged.
    """
    if not IMAGE.fullmatch(image):
        return None
    reference = image.removeprefix("ghcr.io/")
    repository, image_reference = reference.split(":", 1)
    tag, separator, pinned_digest = image_reference.partition("@")
    registry_reference = pinned_digest if separator else tag
    if repository.count("/") != 1:
        return None
    token_path = "/token?" + urlencode({"scope": f"repository:{repository}:pull"})
    try:
        token_payload = _ghcr_request(
            "GET", token_path, timeout=timeout, max_body_bytes=MAX_REGISTRY_RESPONSE_BYTES,
            headers={"Accept": "application/json"},
        )
        if token_payload is None:
            return None
        token_document = json.loads(token_payload)
        if not isinstance(token_document, dict):
            return None
        token = token_document.get("token") or token_document.get("access_token")
        if (
            not isinstance(token, str)
            or not token
            or len(token) > 16_384
            or "\r" in token
            or "\n" in token
        ):
            return None
        digest = _ghcr_request(
            "HEAD", f"/v2/{repository}/manifests/{registry_reference}", timeout=timeout,
            max_body_bytes=0,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": ", ".join((
                    "application/vnd.oci.image.index.v1+json",
                    "application/vnd.oci.image.manifest.v1+json",
                    "application/vnd.docker.distribution.manifest.list.v2+json",
                    "application/vnd.docker.distribution.manifest.v2+json",
                )),
            },
            digest_header=True,
        )
    except (HTTPError, URLError, OSError, TimeoutError, ValueError, TypeError):
        return None
    return digest if isinstance(digest, str) and DIGEST.fullmatch(digest) else None


def _ghcr_request(
    method: str,
    path: str,
    *,
    timeout: float,
    max_body_bytes: int,
    headers: dict[str, str],
    digest_header: bool = False,
) -> bytes | str | None:
    """Make one GHCR-only HTTPS request with redirects disabled and bounded reads."""
    deadline = time.monotonic() + timeout
    request = Request(
        f"https://ghcr.io{path}",
        headers={**headers, "Accept-Encoding": "identity"},
        method=method,
    )
    opener = build_opener(_NoRedirect())
    try:
        with opener.open(request, timeout=timeout) as response:
            if response.status != 200 or time.monotonic() >= deadline:
                return None
            if digest_header:
                return response.headers.get("Docker-Content-Digest")
            payload = bytearray()
            response_socket = getattr(getattr(getattr(response, "fp", None), "raw", None), "_sock", None)
            while len(payload) <= max_body_bytes:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
                if response_socket is not None and response_socket.fileno() >= 0:
                    response_socket.settimeout(remaining)
                chunk = response.read1(min(8192, max_body_bytes + 1 - len(payload)))
                if not chunk:
                    break
                payload.extend(chunk)
            if len(payload) > max_body_bytes:
                return None
            return bytes(payload)
    except HTTPError as error:
        error.close()
        return None
    except (URLError, OSError, TimeoutError, ValueError):
        return None


def _parse_metrics(payload: bytes) -> dict[str, float]:
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        return {}
    result: dict[str, float] = {}
    for line in text.splitlines():
        match = METRIC_LINE.fullmatch(line.strip())
        if not match or match.group("name") not in METRIC_NAMES:
            continue
        try:
            value = float(match.group("value"))
        except ValueError:
            continue
        if math.isfinite(value):
            name = match.group("name")
            labels = match.group("labels") or ""
            if name == "vpn_dashboard_redis_publish_total":
                outcome = re.fullmatch(r'outcome="(success|failure)"', labels)
                if outcome:
                    result[f"{name}_{outcome.group(1)}"] = value
            elif name == "vpn_dashboard_telemetry_gateway_events_total":
                outcome = re.fullmatch(r'outcome="(published|replayed|snapshot_recovery)"', labels)
                if outcome:
                    result[f"{name}_{outcome.group(1)}"] = value
            elif name == "vpn_dashboard_telemetry_supervisor_status":
                state = re.fullmatch(r'state="(disabled|connecting|healthy|degraded|stopped|unknown)"', labels)
                if state:
                    result[f"{name}_{state.group(1)}"] = value
            elif not labels:
                result[name] = value
    return result


def _json_status(payload: bytes) -> dict[str, Any]:
    try:
        value = json.loads(payload)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _metric_window(samples: list[dict[str, Any]], start_epoch: float, end_epoch: float) -> dict[str, Any]:
    metric_samples = [sample for sample in samples if sample.get("metrics")]
    if not metric_samples:
        return {"available": False}
    last = metric_samples[-1]["metrics"]
    successes_in_window = any(
        sample["metrics"].get("vpn_dashboard_redis_last_publish_success_timestamp_seconds", 0) > start_epoch
        and sample["metrics"].get("vpn_dashboard_redis_last_publish_success_timestamp_seconds", 0) <= end_epoch
        for sample in metric_samples
    )
    def observation_age(metric_name: str, timestamp_name: str) -> dict[str, Any]:
        values: list[float] = []
        timestamps: list[float] = []
        observed: list[float] = []
        unknown_samples = 0
        inconsistent_samples = 0
        for sample in metric_samples:
            metrics = sample["metrics"]
            age = metrics.get(metric_name)
            timestamp = metrics.get(timestamp_name)
            if age is None or timestamp is None or age < 0 or timestamp <= 0:
                unknown_samples += 1
                continue
            scrape_at = sample["at"].timestamp()
            timestamp_age = scrape_at - timestamp
            if timestamp_age < -MAX_CLOCK_DRIFT_SECONDS:
                unknown_samples += 1
                inconsistent_samples += 1
                continue
            effective_age = max(age, timestamp_age, 0.0)
            values.append(age)
            timestamps.append(timestamp)
            observed.append(effective_age)
            if abs(age - timestamp_age) > MAX_CLOCK_DRIFT_SECONDS:
                inconsistent_samples += 1
        return {
            "last_seconds": values[-1] if values else None,
            "max_seconds": max(observed) if observed else None,
            "observed_samples": len(observed),
            "unknown_samples": unknown_samples,
            "inconsistent_samples": inconsistent_samples,
            "last_observed_timestamp_seconds": timestamps[-1] if timestamps else None,
        }

    def binary_window(metric_name: str) -> dict[str, Any]:
        values = [sample["metrics"].get(metric_name) for sample in metric_samples]
        known = [value for value in values if value in (0, 1)]
        return {
            "last": values[-1] if values else None,
            "observed_samples": len(known),
            "unknown_samples": len(values) - len(known),
            "unavailable_samples": sum(value == 0 for value in known),
            "all_enabled": len(known) == len(metric_samples) and all(value == 1 for value in known),
        }

    def counter_window(metric_name: str) -> dict[str, Any]:
        values = [sample["metrics"][metric_name] for sample in metric_samples if metric_name in sample["metrics"]]
        if not values:
            return {"delta": 0, "counter_reset": False, "invalid_samples": 0}
        valid_values = [
            int(value)
            for value in values
            if math.isfinite(value) and value >= 0 and float(value).is_integer()
        ]
        invalid_samples = len(values) - len(valid_values)
        if not valid_values:
            return {"delta": 0, "counter_reset": False, "invalid_samples": invalid_samples}
        previous = valid_values[0]
        delta = 0
        reset = False
        for current in valid_values[1:]:
            if current < previous:
                # A reset starts a new counter epoch; include the post-reset
                # observations instead of allowing them to cancel prior work.
                delta += current
                reset = True
            else:
                delta += current - previous
            previous = current
        return {
            "delta": delta,
            "counter_reset": reset,
            "invalid_samples": invalid_samples,
        }

    process_start_values = [
        sample["metrics"]["vpn_dashboard_process_start_time_seconds"]
        for sample in metric_samples
        if "vpn_dashboard_process_start_time_seconds" in sample["metrics"]
    ]
    valid_process_start_values = [
        value for value in process_start_values if math.isfinite(value) and value > 0
    ]
    process_start_invalid_samples = len(process_start_values) - len(valid_process_start_values)
    process_start_time_changed = len(set(valid_process_start_values)) > 1
    process_started_during_window = bool(
        valid_process_start_values
        and valid_process_start_values[0] > start_epoch + MAX_CLOCK_DRIFT_SECONDS
    )
    process_start_window_start_ambiguous = bool(
        valid_process_start_values
        and start_epoch - MAX_CLOCK_DRIFT_SECONDS
        <= valid_process_start_values[0]
        <= start_epoch + MAX_CLOCK_DRIFT_SECONDS
    )
    process_start_unknown_samples = len(metric_samples) - len(process_start_values)

    counter_metric_names = (
        "vpn_dashboard_redis_publish_total_failure",
        "vpn_dashboard_integration_outbox_storage_failures_total",
        "vpn_dashboard_telemetry_gateway_events_total_published",
        "vpn_dashboard_telemetry_gateway_events_total_replayed",
        "vpn_dashboard_telemetry_gateway_events_total_snapshot_recovery",
        "vpn_dashboard_telemetry_gateway_rejected_clients_total",
        "vpn_dashboard_telemetry_supervisor_attempts_total",
        "vpn_dashboard_telemetry_supervisor_reconnects_total",
        "vpn_dashboard_telemetry_supervisor_failures_total",
        "vpn_dashboard_telemetry_supervisor_events_total",
    )
    counter_windows = {name: counter_window(name) for name in counter_metric_names}
    counter_metric_invalid_samples = sum(
        window["invalid_samples"] for window in counter_windows.values()
    )

    def gauge_window(metric_name: str) -> dict[str, Any]:
        values = [sample["metrics"][metric_name] for sample in metric_samples if metric_name in sample["metrics"]]
        observed = [value for value in values if value >= 0]
        return {
            "last": values[-1] if values else None,
            "max": max(observed) if observed else None,
            "observed_samples": len(observed),
            "unknown_samples": sum(value < 0 for value in values),
        }

    def timestamp_window(metric_name: str) -> dict[str, Any]:
        values = [sample["metrics"][metric_name] for sample in metric_samples if metric_name in sample["metrics"]]
        observed = [value for value in values if value > 0]
        return {
            "first": observed[0] if observed else None,
            "last": observed[-1] if observed else None,
            "observed_samples": len(observed),
            "unknown_samples": len(values) - len(observed),
        }

    session_event_age = observation_age(
        "vpn_dashboard_telemetry_session_event_age_seconds",
        "vpn_dashboard_telemetry_session_event_timestamp_seconds",
    )
    traffic_sample_age = observation_age(
        "vpn_dashboard_telemetry_traffic_sample_age_seconds",
        "vpn_dashboard_telemetry_traffic_sample_timestamp_seconds",
    )
    gateway_delivery_age = gauge_window(
        "vpn_dashboard_telemetry_gateway_delivery_queue_age_p95_seconds"
    )
    outbox_pending = gauge_window("vpn_dashboard_integration_outbox_pending")
    outbox_dead_lettered = gauge_window("vpn_dashboard_integration_outbox_dead_lettered")
    outbox_oldest_age = gauge_window("vpn_dashboard_integration_outbox_oldest_age_seconds")
    outbox_storage_failure_window = counter_windows[
        "vpn_dashboard_integration_outbox_storage_failures_total"
    ]
    outbox_storage_failure_values = [
        sample["metrics"]["vpn_dashboard_integration_outbox_storage_failures_total"]
        for sample in metric_samples
        if "vpn_dashboard_integration_outbox_storage_failures_total" in sample["metrics"]
    ]

    redis_failure_window = counter_windows["vpn_dashboard_redis_publish_total_failure"]
    failure_delta = redis_failure_window["delta"]
    failure_counter_reset = redis_failure_window["counter_reset"]
    redis_configured_window = binary_window("vpn_dashboard_redis_configured")
    redis_availability_window = binary_window("vpn_dashboard_redis_last_observed_available")
    redis_publish_ages: list[float] = []
    redis_publish_age_unknown_samples = 0
    for sample in metric_samples:
        published_at = sample["metrics"].get("vpn_dashboard_redis_last_publish_success_timestamp_seconds")
        if published_at is None or published_at <= 0:
            redis_publish_age_unknown_samples += 1
            continue
        publish_age = sample["at"].timestamp() - published_at
        if publish_age < -MAX_CLOCK_DRIFT_SECONDS:
            redis_publish_age_unknown_samples += 1
            continue
        redis_publish_ages.append(max(0.0, publish_age))
    redis_publish_age_max = max(redis_publish_ages) if redis_publish_ages else None
    redis_publish_age_stale_samples = sum(age > MAX_REDIS_PUBLISH_AGE_SECONDS for age in redis_publish_ages)

    return {
        "available": True,
        "redis_configured": last.get("vpn_dashboard_redis_configured"),
        "redis_configured_window": redis_configured_window,
        "redis_last_observed_available": last.get("vpn_dashboard_redis_last_observed_available"),
        "redis_availability_window": redis_availability_window,
        "redis_publish_success_observed_in_window": successes_in_window,
        "redis_publish_age_max_seconds": redis_publish_age_max,
        "redis_publish_age_unknown_samples": redis_publish_age_unknown_samples,
        "redis_publish_age_stale_samples": redis_publish_age_stale_samples,
        "redis_publish_failure_delta": failure_delta,
        "redis_publish_failure_counter_reset": failure_counter_reset,
        "outbox_pending_last": last.get("vpn_dashboard_integration_outbox_pending"),
        "outbox_pending_max": outbox_pending["max"],
        "outbox_dead_lettered_last": last.get("vpn_dashboard_integration_outbox_dead_lettered"),
        "outbox_oldest_age_seconds_last": last.get("vpn_dashboard_integration_outbox_oldest_age_seconds"),
        "outbox_pending_unknown_samples": outbox_pending["unknown_samples"],
        "outbox_dead_lettered_max": outbox_dead_lettered["max"],
        "outbox_dead_lettered_unknown_samples": outbox_dead_lettered["unknown_samples"],
        "outbox_oldest_age_max_seconds": outbox_oldest_age["max"],
        "outbox_oldest_age_unknown_samples": outbox_oldest_age["unknown_samples"],
        "outbox_storage_failure_delta": outbox_storage_failure_window["delta"],
        "outbox_storage_failure_counter_reset": outbox_storage_failure_window["counter_reset"],
        "counter_metric_invalid_samples": counter_metric_invalid_samples,
        "outbox_storage_failure_initial": (
            outbox_storage_failure_values[0] if outbox_storage_failure_values else None
        ),
        "process_start_time_changed": process_start_time_changed,
        "process_started_during_window": process_started_during_window,
        "process_start_window_start_ambiguous": process_start_window_start_ambiguous,
        "process_start_invalid_samples": process_start_invalid_samples,
        "process_start_unknown_samples": process_start_unknown_samples,
        "telemetry_gateway": {
            "authorized_clients_last": last.get("vpn_dashboard_telemetry_gateway_clients"),
            "buffered_events_last": last.get("vpn_dashboard_telemetry_gateway_buffered_events"),
            "published_events": counter_windows["vpn_dashboard_telemetry_gateway_events_total_published"],
            "replayed_events": counter_windows["vpn_dashboard_telemetry_gateway_events_total_replayed"],
            "snapshot_recoveries": counter_windows[
                "vpn_dashboard_telemetry_gateway_events_total_snapshot_recovery"
            ],
            "rejected_clients": counter_windows["vpn_dashboard_telemetry_gateway_rejected_clients_total"],
            "delivery_observations_last": last.get("vpn_dashboard_telemetry_gateway_delivery_observations"),
            "delivery_queue_age_seconds": gauge_window(
                "vpn_dashboard_telemetry_gateway_delivery_queue_age_seconds"
            ),
            "delivery_queue_age_p95_seconds": gauge_window(
                "vpn_dashboard_telemetry_gateway_delivery_queue_age_p95_seconds"
            ),
            "meaning": (
                "Gateway enqueue-to-authorized-client-poll delay; excludes RouterOS observation and browser rendering."
            ),
        },
        "telemetry_process_observation_age": {
            "session_event": session_event_age,
            "traffic_sample": traffic_sample_age,
            "meaning": "Age since this process observed telemetry; not RouterOS-to-browser delivery latency.",
        },
        "telemetry_supervisor": {
            "enabled_last": last.get("vpn_dashboard_telemetry_supervisor_enabled"),
            "status_last": next(
                (
                    state
                    for state in ("healthy", "connecting", "degraded", "stopped", "disabled", "unknown")
                    if last.get(f"vpn_dashboard_telemetry_supervisor_status_{state}") == 1
                ),
                "unknown",
            ),
            "attempts": counter_windows["vpn_dashboard_telemetry_supervisor_attempts_total"],
            "reconnects": counter_windows["vpn_dashboard_telemetry_supervisor_reconnects_total"],
            "failures": counter_windows["vpn_dashboard_telemetry_supervisor_failures_total"],
            "events": counter_windows["vpn_dashboard_telemetry_supervisor_events_total"],
            "last_connected_timestamp_seconds": last.get(
                "vpn_dashboard_telemetry_supervisor_last_connected_timestamp_seconds"
            ),
            "connected_timestamp_window": timestamp_window(
                "vpn_dashboard_telemetry_supervisor_last_connected_timestamp_seconds"
            ),
            "last_event_timestamp_seconds": last.get(
                "vpn_dashboard_telemetry_supervisor_last_event_timestamp_seconds"
            ),
            "last_snapshot_timestamp_seconds": last.get(
                "vpn_dashboard_telemetry_supervisor_last_snapshot_timestamp_seconds"
            ),
            "snapshot_timestamp_window": timestamp_window(
                "vpn_dashboard_telemetry_supervisor_last_snapshot_timestamp_seconds"
            ),
            "backoff_seconds_last": last.get("vpn_dashboard_telemetry_supervisor_backoff_seconds"),
            "meaning": "Aggregate process-local RouterOS Binary API supervisor state; counters may reset on process restart.",
        },
        "telemetry_slo": {
            "session_event_unknown_samples": session_event_age["unknown_samples"],
            "session_event_timestamp_inconsistent_samples": session_event_age["inconsistent_samples"],
            "session_event_max_age_seconds": session_event_age["max_seconds"],
            "traffic_sample_max_age_seconds": traffic_sample_age["max_seconds"],
            "traffic_sample_unknown_samples": traffic_sample_age["unknown_samples"],
            "traffic_timestamp_inconsistent_samples": traffic_sample_age["inconsistent_samples"],
            "gateway_delivery_p95_max_seconds": gateway_delivery_age["max"],
            "gateway_delivery_p95_unknown_samples": gateway_delivery_age["unknown_samples"],
            "gateway_delivery_observations_last": last.get(
                "vpn_dashboard_telemetry_gateway_delivery_observations"
            ),
            "supervisor_non_healthy_samples": sum(
                sample["metrics"].get("vpn_dashboard_telemetry_supervisor_status_healthy") != 1
                or sample["metrics"].get("vpn_dashboard_telemetry_supervisor_enabled") != 1
                for sample in metric_samples
            ),
            "meaning": (
                "Traffic freshness and server gateway enqueue-to-client-poll delay only; "
                "does not measure RouterOS-to-browser session-change latency or rendering."
            ),
        },
    }


def collect(
    evidence: Any,
    *,
    readyz_urls: dict[str, str],
    sqlite_backup_paths: dict[str, str | os.PathLike[str]] | None = None,
    metrics_urls: dict[str, str] | None = None,
    cookie: str | None = None,
    metrics_tokens: dict[str, str] | None = None,
    duration_seconds: float = 1800,
    interval_seconds: float = 60,
    timeout_seconds: float = 5,
    phase: str = "postpromotion",
    redis_recovery_report: Any = None,
    redis_recovery_provenance: Any = None,
    rollback_report: Any = None,
    probe: Callable[..., tuple[int, bytes]] = _get,
    registry_probe: Callable[..., str | None] = _registry_digest,
    clock: Callable[[], datetime] = _utc_now,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
    minimum_soak_seconds: float = MIN_SOAK_SECONDS,
    minimum_health_samples: int = MIN_HEALTH_SAMPLES,
) -> tuple[int, dict[str, Any]]:
    if not isinstance(evidence, dict) or evidence.get("format") != "vpn-dashboard-release-evidence-v2":
        raise ValueError("evidence must use vpn-dashboard-release-evidence-v2")
    if phase not in {"canary-prepromotion", "postpromotion"}:
        raise ValueError("phase must be canary-prepromotion or postpromotion")
    if sqlite_backup_paths is None:
        sqlite_backup_paths = {}
    if not isinstance(sqlite_backup_paths, dict) or set(sqlite_backup_paths).difference(ENVIRONMENTS):
        raise ValueError("SQLite backup paths must be keyed by canary or production")
    # The shared validator enforces every field's type, enum, bounds, and
    # timestamp format, then returns a strict allowlisted projection. The
    # operator's SQLite restore claim is deliberately discarded before this
    # validation; it is replaced only with the local restore rehearsal result.
    validation_input = dict(evidence)
    raw_deployments = evidence.get("deployments")
    if isinstance(raw_deployments, list):
        validation_deployments = []
        for index, deployment in enumerate(raw_deployments):
            if not isinstance(deployment, dict):
                validation_deployments.append(deployment)
                continue
            sanitized = dict(deployment)
            sanitized.pop("sqlite_restore_verified", None)
            sanitized.pop("sqlite_restore_verified_at", None)
            if not (phase == "canary-prepromotion" and index == 1):
                sanitized["sqlite_restore_verified"] = False
            validation_deployments.append(sanitized)
        validation_input["deployments"] = validation_deployments
    _, validated_evidence = validate_evidence(validation_input, phase=phase)
    records = validated_evidence["deployments"]
    restore_environments = ("canary",) if phase == "canary-prepromotion" else ENVIRONMENTS
    restore_checks: list[dict[str, Any]] = []
    restore_failure_gates: list[str] = []
    for environment in restore_environments:
        verification = verify_sqlite_restore(sqlite_backup_paths.get(environment))
        checked_at = clock()
        verified = verification.get("verified") is True
        checked_at_text = checked_at.isoformat()
        record = records[ENVIRONMENTS.index(environment)]
        # Bind the private backup restore rehearsal to the exact immutable
        # application candidate that was sampled above. The backup path and
        # database contents are never copied into the report.
        record["sqlite_restore_verified"] = verified
        record["sqlite_restore_verified_at"] = checked_at_text if verified else None
        restore_checks.append({
            "environment": environment,
            "candidate_image": record["image"],
            "candidate_revision": record["revision"],
            "candidate_digest": record["digest"],
            "checked_at": checked_at_text,
            "verified": verified,
            "source_opened_read_only": verification.get("source_opened_read_only") is True,
            "restored_integrity": verification.get("restored_integrity") is True,
            "required_schema_present": verification.get("required_schema_present") is True,
            "restored_data_counts_match": verification.get("restored_data_counts_match") is True,
            "temporary_copy_removed": verification.get("temporary_copy_removed") is True,
            "failure_code": verification.get("failure_code"),
        })
        if not verified:
            restore_failure_gates.append(f"{environment}_sqlite_restore_unverified")
    sqlite_restore_verification = {
        "format": RESTORE_REPORT_FORMAT,
        "checks": restore_checks,
    }
    if not math.isfinite(duration_seconds) or duration_seconds <= 0 or duration_seconds > MAX_DURATION_SECONDS:
        raise ValueError("duration must be greater than zero and no more than 86400 seconds")
    if duration_seconds < minimum_soak_seconds:
        raise ValueError("duration is shorter than the required acceptance soak window")
    if not math.isfinite(interval_seconds) or interval_seconds <= 0:
        raise ValueError("interval must be greater than zero")
    if not math.isfinite(timeout_seconds) or timeout_seconds <= 0 or timeout_seconds > 30:
        raise ValueError("timeout must be greater than zero and no more than 30 seconds")
    expected_samples = math.ceil(duration_seconds / interval_seconds) + 1
    if expected_samples > MAX_SAMPLES:
        raise ValueError("sampling schedule exceeds the 10000-sample safety limit")
    if set(readyz_urls) != set(ENVIRONMENTS):
        raise ValueError("readyz URLs must be supplied for canary and production")
    metrics_urls = metrics_urls or {}
    if not set(metrics_urls).issubset(ENVIRONMENTS):
        raise ValueError("metrics URL environment must be canary or production")
    metrics_tokens = metrics_tokens or {}
    if not set(metrics_tokens).issubset(ENVIRONMENTS):
        raise ValueError("metrics token environment must be canary or production")
    if phase == "canary-prepromotion":
        metrics_urls = {name: url for name, url in metrics_urls.items() if name == "canary"}
        metrics_tokens = {name: token for name, token in metrics_tokens.items() if name == "canary"}
    if cookie and metrics_tokens:
        raise ValueError("use either per-environment API tokens or a session cookie, not both")
    if set(metrics_tokens).difference(metrics_urls):
        raise ValueError("each metrics API token requires a matching metrics URL")
    for environment, token in metrics_tokens.items():
        if not re.fullmatch(r"vpt_[A-Za-z0-9_-]{32,128}", token):
            raise ValueError(f"{environment} metrics API token has an invalid format")
    for environment, metrics_url in metrics_urls.items():
        if _origin(metrics_url) != _origin(readyz_urls[environment]):
            raise ValueError(f"{environment} metrics URL origin must exactly match its readiness probe origin")
    if (cookie or metrics_tokens) and any(
        urlsplit(url).scheme != "https"
        for url in metrics_urls.values()
    ):
        raise ValueError("authenticated metrics probes require HTTPS")

    safe_records: dict[str, dict[str, Any]] = {}
    for record, environment in zip(records, ENVIRONMENTS):
        if not isinstance(record, dict) or record.get("environment") != environment:
            raise ValueError("evidence deployments must be ordered canary, then production")
        image = str(record.get("image", ""))
        raw_digest = record.get("digest")
        digest = raw_digest if isinstance(raw_digest, str) and DIGEST.fullmatch(raw_digest) else None
        match = IMAGE.fullmatch(image)
        if not match or digest is None:
            raise ValueError(f"{environment} evidence needs an architecture-specific image reference and resolved digest")
        embedded_digest = match.group("reference_digest")
        if embedded_digest is not None and embedded_digest != digest:
            raise ValueError(f"{environment} image reference and supplied digest do not match")
        if environment == "canary" and embedded_digest is None:
            raise ValueError("canary candidate must use a digest-pinned image reference")
        if phase == "postpromotion" and embedded_digest is None:
            raise ValueError(f"{environment} image must be digest pinned after promotion")
        revision = match.group("revision")
        if not REVISION_IN_IMAGE.search(image) or not re.fullmatch(r"[0-9a-f]{40}", revision):
            raise ValueError(f"{environment} image must bind to a full lowercase source commit")
        safe_records[environment] = {**record, "digest": digest}

    if phase == "postpromotion" and safe_records["canary"]["image"] != safe_records["production"]["image"]:
        raise ValueError("canary and production must use the same image")
    if phase == "canary-prepromotion" and (
        safe_records["canary"]["image"] == safe_records["production"]["image"]
        or (
            safe_records["production"]["digest"] is not None
            and safe_records["canary"]["digest"] == safe_records["production"]["digest"]
        )
    ):
        raise ValueError("pre-promotion canary evidence requires production to remain on its prior immutable image")
    expected_revisions = {
        environment: REVISION_IN_IMAGE.search(safe_records[environment]["image"]).group("revision")  # type: ignore[union-attr]
        for environment in ENVIRONMENTS
    }
    registry_verification: list[dict[str, Any]] = []
    failed_gates: list[str] = list(restore_failure_gates)
    registry_environments = ENVIRONMENTS
    for environment in registry_environments:
        image = safe_records[environment]["image"]
        expected_digest = safe_records[environment]["digest"]
        try:
            observed_digest = registry_probe(image, timeout=timeout_seconds)
        except Exception:  # Treat registry client failures as unavailable evidence.
            observed_digest = None
        observed_digest_valid = isinstance(observed_digest, str) and DIGEST.fullmatch(observed_digest) is not None
        registry_verification.append({
            "environment": environment,
            "image": image,
            "expected_digest": expected_digest,
            "observed_digest": observed_digest if observed_digest_valid else None,
            "verified": observed_digest_valid and observed_digest == expected_digest,
        })
        if not observed_digest_valid:
            failed_gates.append(f"{environment}_registry_digest_unavailable")
        elif observed_digest != expected_digest:
            failed_gates.append(f"{environment}_registry_digest_mismatch")
    deployment_samples: dict[str, list[dict[str, Any]]] = {name: [] for name in ENVIRONMENTS}
    browser_origin_samples: list[dict[str, Any]] = []
    begun = clock()
    began_epoch = begun.timestamp()
    began_monotonic = monotonic()
    deadline = began_monotonic + duration_seconds
    while True:
        observed = clock()
        observed_monotonic = monotonic()
        for environment in ENVIRONMENTS:
            base = readyz_urls[environment]
            health_code, _ = probe(_probe_url(base, "/healthz"), timeout=timeout_seconds)
            ready_code, ready_body = probe(_probe_url(base, "/readyz"), timeout=timeout_seconds)
            ready_payload = _json_status(ready_body) if ready_code == 200 else {}
            revision = ready_payload.get("revision") if isinstance(ready_payload.get("revision"), str) else ""
            metrics: dict[str, float] = {}
            metrics_valid = False
            if environment in metrics_urls and (phase == "postpromotion" or environment == "canary"):
                metrics_code, metrics_body = probe(
                    _probe_url(metrics_urls[environment], "/metrics"),
                    cookie=cookie,
                    api_token=metrics_tokens.get(environment),
                    timeout=timeout_seconds,
                )
                if metrics_code == 200:
                    metrics = _parse_metrics(metrics_body)
                    metrics_valid = REQUIRED_ACCEPTANCE_METRICS.issubset(metrics)
                if not metrics_valid:
                    metrics = {}
            metric_health = metrics.get("vpn_dashboard_health")
            revision_matches = (
                ready_code == 200
                and ready_payload.get("status") == "ready"
                and revision == expected_revisions[environment]
            )
            ready = revision_matches
            deployment_samples[environment].append({
                "at": observed,
                "monotonic": observed_monotonic,
                "ready": ready,
                "revision_matches": revision_matches,
                "healthy": health_code == 200 and ready and metric_health in (None, 1),
                "metrics_valid": metrics_valid,
                "metrics": metrics,
            })
        browser_origin_code, browser_origin_body = probe(
            _probe_url(CANARY_ORIGIN, "/readyz"), timeout=timeout_seconds
        )
        browser_origin_payload = _json_status(browser_origin_body) if browser_origin_code == 200 else {}
        browser_origin_revision = browser_origin_payload.get("revision")
        browser_origin_samples.append({
            "observed_at": observed.isoformat(),
            "ready": browser_origin_payload.get("status") == "ready",
            "revision": browser_origin_revision if isinstance(browser_origin_revision, str) else None,
            "matches_candidate": (
                browser_origin_payload.get("status") == "ready"
                and browser_origin_revision == expected_revisions["canary"]
            ),
        })
        remaining = deadline - monotonic()
        if remaining <= 0:
            break
        sleep(min(interval_seconds, remaining))

    ended = clock()
    ended_monotonic = monotonic()
    certificate_lifecycle_acceptance = None
    raw_certificate_lifecycle = evidence.get("certificate_lifecycle_acceptance")
    if raw_certificate_lifecycle is None:
        failed_gates.append("certificate_lifecycle_acceptance_missing")
    else:
        try:
            certificate_lifecycle_acceptance = validate_certificate_lifecycle_acceptance(
                raw_certificate_lifecycle,
                candidate_image=safe_records["canary"]["image"],
                candidate_digest=safe_records["canary"]["digest"],
                collection_started_at=begun.isoformat(),
                collection_ended_at=ended.isoformat(),
            )
        except (KeyError, ValueError):
            failed_gates.append("certificate_lifecycle_acceptance_invalid")
    wall_duration = (ended - begun).total_seconds()
    monotonic_duration = max(0.0, ended_monotonic - began_monotonic)
    if wall_duration < 0 or abs(wall_duration - monotonic_duration) > MAX_CLOCK_DRIFT_SECONDS:
        failed_gates.append("collection_clock_anomaly")
    summary: dict[str, Any] = {"format": "vpn-dashboard-release-collection-v2", "deployments": []}
    browser_origin_matches = [sample["matches_candidate"] for sample in browser_origin_samples]
    verified_deployment_identity = None
    if browser_origin_matches and all(browser_origin_matches):
        verified_deployment_identity = {
            "origin": CANARY_ORIGIN,
            "candidate_revision": expected_revisions["canary"],
            "observed_revision": expected_revisions["canary"],
            "observation_started_at": datetime.fromisoformat(
                browser_origin_samples[0]["observed_at"]
            ).timestamp(),
            "observation_ended_at": datetime.fromisoformat(
                browser_origin_samples[-1]["observed_at"]
            ).timestamp(),
            "ready_sample_count": len(browser_origin_samples),
            "matching_sample_count": sum(browser_origin_matches),
            "all_samples_ready_for_candidate": True,
        }
    browser_origin_observation = {
        "origin": CANARY_ORIGIN,
        "candidate_revision": expected_revisions["canary"],
        "observed_revision": (
            browser_origin_samples[-1]["revision"] if browser_origin_samples else None
        ),
        "observation_started_at": browser_origin_samples[0]["observed_at"] if browser_origin_samples else None,
        "observation_ended_at": browser_origin_samples[-1]["observed_at"] if browser_origin_samples else None,
        "ready_sample_count": len(browser_origin_samples),
        "matching_sample_count": sum(browser_origin_matches),
        "all_samples_ready_for_candidate": bool(browser_origin_matches) and all(browser_origin_matches),
    }
    for environment in ENVIRONMENTS:
        samples = deployment_samples[environment]
        sample_times = [sample["at"].timestamp() for sample in samples]
        sample_monotonic_times = [sample["monotonic"] for sample in samples]
        wall_gaps = [right - left for left, right in zip(sample_times, sample_times[1:])]
        gaps = [right - left for left, right in zip(sample_monotonic_times, sample_monotonic_times[1:])]
        if any(
            wall_gap <= 0 or abs(wall_gap - monotonic_gap) > MAX_CLOCK_DRIFT_SECONDS
            for wall_gap, monotonic_gap in zip(wall_gaps, gaps)
        ):
            failed_gates.append(f"{environment}_sample_clock_anomaly")
        health_failures = sum(not sample["healthy"] for sample in samples)
        metrics_samples = [sample for sample in samples if sample["metrics_valid"]]
        metrics_sample_times = [sample["at"].timestamp() for sample in metrics_samples]
        metrics_monotonic_times = [sample["monotonic"] for sample in metrics_samples]
        metrics_wall_gaps = [right - left for left, right in zip(metrics_sample_times, metrics_sample_times[1:])]
        metrics_gaps = [right - left for left, right in zip(metrics_monotonic_times, metrics_monotonic_times[1:])]
        if any(
            wall_gap <= 0 or abs(wall_gap - monotonic_gap) > MAX_CLOCK_DRIFT_SECONDS
            for wall_gap, monotonic_gap in zip(metrics_wall_gaps, metrics_gaps)
        ):
            failed_gates.append(f"{environment}_metrics_clock_anomaly")
        metrics_failures = len(samples) - len(metrics_samples)
        max_metrics_gap = max(metrics_gaps, default=0)
        observed_window_seconds = monotonic_duration
        max_gap = max(gaps, default=0)
        if health_failures:
            failed_gates.append(f"{environment}_health_or_revision_failure")
        if observed_window_seconds < minimum_soak_seconds:
            failed_gates.append(f"{environment}_soak_window_too_short")
        if len(samples) < minimum_health_samples:
            failed_gates.append(f"{environment}_health_samples_insufficient")
        if max_gap > MAX_SAMPLE_GAP_SECONDS:
            failed_gates.append(f"{environment}_sample_gap_exceeded")
        metrics_required = phase == "postpromotion" or environment == "canary"
        if metrics_required and len(metrics_samples) < minimum_health_samples:
            failed_gates.append(f"{environment}_metrics_samples_insufficient")
        if metrics_required and (metrics_failures or max_metrics_gap > MAX_SAMPLE_GAP_SECONDS):
            failed_gates.append(f"{environment}_metrics_observation_gap")
        metrics_window_complete = (
            len(metrics_samples) >= minimum_health_samples
            and metrics_failures == 0
            and max_metrics_gap <= MAX_SAMPLE_GAP_SECONDS
        )
        record = safe_records[environment]
        record.update({
            "container_healthy": health_failures == 0,
            "app_ready": all(sample["ready"] for sample in samples),
            "observation_started_at": begun.isoformat(),
            "observation_ended_at": ended.isoformat(),
            "health_sample_count": len(samples),
            "max_sample_gap_seconds": max(gaps, default=0),
            "health_failures": int(record.get("health_failures", 0)) + health_failures,
        })
        metric_summary = _metric_window(metrics_samples, began_epoch, ended.timestamp())
        if metrics_required:
            reconnects = metric_summary.get("telemetry_supervisor", {}).get("reconnects", {})
            supervisor = metric_summary.get("telemetry_supervisor", {})
            reconnect_delta = reconnects.get("delta") if metrics_window_complete else None
            reconnect_reset = reconnects.get("counter_reset") if metrics_window_complete else None
            connected_window = supervisor.get("connected_timestamp_window", {})
            snapshot_window = supervisor.get("snapshot_timestamp_window", {})
            reconnect_at = connected_window.get("last") if metrics_window_complete else None
            snapshot_at = snapshot_window.get("last") if metrics_window_complete else None
            same_window_reconnect = (
                reconnect_at is not None
                and connected_window.get("first") is not None
                and connected_window.get("unknown_samples") == 0
                and connected_window.get("observed_samples") == len(metrics_samples)
                and reconnect_at > connected_window["first"]
                and begun.timestamp() <= reconnect_at <= ended.timestamp() + MAX_CLOCK_DRIFT_SECONDS
            )
            same_window_full_snapshot = (
                snapshot_at is not None
                and snapshot_window.get("first") is not None
                and snapshot_window.get("unknown_samples") == 0
                and snapshot_window.get("observed_samples") == len(metrics_samples)
                and snapshot_at > snapshot_window["first"]
                and begun.timestamp() <= snapshot_at <= ended.timestamp() + MAX_CLOCK_DRIFT_SECONDS
                and same_window_reconnect
                and snapshot_at >= reconnect_at
            )
            record["reconnect_recovery_counter_delta"] = reconnect_delta
            record["reconnect_recovery_counter_reset"] = reconnect_reset
            record["reconnect_observed_at"] = reconnect_at
            record["full_snapshot_recovered_at"] = snapshot_at
            record["reconnect_recovered"] = (
                record.get("reconnect_recovered") is True
                and reconnect_delta is not None
                and reconnect_delta > 0
                and reconnect_reset is False
                and same_window_reconnect
            )
            record["snapshot_recovered"] = (
                record.get("snapshot_recovered") is True
                and same_window_full_snapshot
            )
            if not record["reconnect_recovered"]:
                failed_gates.append(f"{environment}_reconnect_recovery_not_observed")
            if not record["snapshot_recovered"]:
                failed_gates.append(f"{environment}_snapshot_recovery_not_observed")
        # Never carry an operator-supplied Redis success claim through a
        # window that did not independently observe complete aggregate metrics.
        record["redis_configured"] = False
        record["redis_publish_verified"] = False
        if metric_summary["available"] and (metrics_required or metrics_window_complete):
            telemetry_slo = metric_summary["telemetry_slo"]
            session_event_age = telemetry_slo["session_event_max_age_seconds"]
            record["session_event_max_age_seconds"] = session_event_age
            traffic_age = telemetry_slo["traffic_sample_max_age_seconds"]
            if telemetry_slo["session_event_unknown_samples"]:
                failed_gates.append(f"{environment}_session_event_freshness_incomplete")
            if telemetry_slo["session_event_timestamp_inconsistent_samples"]:
                failed_gates.append(f"{environment}_session_event_timestamp_inconsistent")
            if session_event_age is None:
                failed_gates.append(f"{environment}_session_event_freshness_unobserved")
            elif session_event_age > MAX_SESSION_EVENT_AGE_SECONDS:
                failed_gates.append(f"{environment}_session_event_stale")
            if telemetry_slo["traffic_sample_unknown_samples"]:
                failed_gates.append(f"{environment}_traffic_freshness_incomplete")
            if telemetry_slo["traffic_timestamp_inconsistent_samples"]:
                failed_gates.append(f"{environment}_traffic_timestamp_inconsistent")
            if traffic_age is None:
                failed_gates.append(f"{environment}_traffic_freshness_unobserved")
            elif traffic_age > MAX_TRAFFIC_SAMPLE_AGE_SECONDS:
                failed_gates.append(f"{environment}_traffic_sample_stale")
            gateway_p95 = telemetry_slo["gateway_delivery_p95_max_seconds"]
            gateway_observations = telemetry_slo["gateway_delivery_observations_last"]
            if gateway_p95 is None or gateway_p95 < 0 or not gateway_observations or gateway_observations < 1:
                failed_gates.append(f"{environment}_gateway_delivery_latency_unobserved")
            elif gateway_p95 > MAX_GATEWAY_DELIVERY_P95_SECONDS:
                failed_gates.append(f"{environment}_gateway_delivery_latency_exceeded")
            if telemetry_slo["gateway_delivery_p95_unknown_samples"]:
                failed_gates.append(f"{environment}_gateway_delivery_latency_incomplete")
            if telemetry_slo["supervisor_non_healthy_samples"]:
                failed_gates.append(f"{environment}_telemetry_supervisor_not_healthy")
            if metric_summary["outbox_dead_lettered_unknown_samples"]:
                failed_gates.append(f"{environment}_outbox_dead_letter_count_unobserved")
            elif metric_summary["outbox_dead_lettered_max"] is None:
                failed_gates.append(f"{environment}_outbox_dead_letter_count_unobserved")
            elif metric_summary["outbox_dead_lettered_max"] > MAX_OUTBOX_DEAD_LETTERED:
                failed_gates.append(f"{environment}_outbox_dead_letters_present")
            if metric_summary["outbox_pending_unknown_samples"]:
                failed_gates.append(f"{environment}_outbox_pending_count_unobserved")
            elif metric_summary["outbox_pending_max"] is None:
                failed_gates.append(f"{environment}_outbox_pending_count_unobserved")
            elif metric_summary["outbox_pending_max"] > MAX_OUTBOX_PENDING_AT_WINDOW_END:
                failed_gates.append(f"{environment}_outbox_pending_during_window")
            if metric_summary["outbox_oldest_age_unknown_samples"] or metric_summary["outbox_oldest_age_max_seconds"] is None:
                failed_gates.append(f"{environment}_outbox_age_unobserved")
            if metric_summary["outbox_storage_failure_counter_reset"]:
                failed_gates.append(f"{environment}_outbox_storage_failure_counter_reset")
            if metric_summary["outbox_storage_failure_initial"] is None:
                failed_gates.append(f"{environment}_outbox_storage_failure_counter_unobserved")
            elif metric_summary["outbox_storage_failure_initial"] > 0:
                failed_gates.append(f"{environment}_outbox_storage_failure_present_at_window_start")
            if metric_summary["outbox_storage_failure_delta"] > 0:
                failed_gates.append(f"{environment}_outbox_storage_failures_during_window")
            if metric_summary["counter_metric_invalid_samples"]:
                failed_gates.append(f"{environment}_counter_metric_invalid_samples")
            if metric_summary["process_start_unknown_samples"]:
                failed_gates.append(f"{environment}_process_start_time_unobserved")
            if metric_summary["process_start_invalid_samples"]:
                failed_gates.append(f"{environment}_process_start_time_invalid")
            if (
                metric_summary["process_start_time_changed"]
                or metric_summary["process_started_during_window"]
            ):
                failed_gates.append(f"{environment}_process_restarted_during_window")
            if metric_summary["process_start_window_start_ambiguous"]:
                failed_gates.append(f"{environment}_process_start_time_ambiguous_at_window_start")
            # A passing Redis publish requires configuration, observed availability,
            # and a successful publish in this observation window.
            record["redis_configured"] = metrics_window_complete and metric_summary["redis_configured_window"]["all_enabled"]
            record["redis_publish_verified"] = metrics_window_complete and (
                record["redis_configured"]
                and metric_summary["redis_availability_window"]["all_enabled"]
                and metric_summary["redis_publish_success_observed_in_window"]
                and metric_summary["redis_publish_age_unknown_samples"] == 0
                and metric_summary["redis_publish_age_stale_samples"] == 0
                and metric_summary["redis_publish_failure_delta"] == 0
                and not metric_summary["redis_publish_failure_counter_reset"]
            )
            if metric_summary["redis_configured_window"]["unknown_samples"]:
                failed_gates.append(f"{environment}_redis_configuration_unobserved")
            elif metric_summary["redis_configured_window"]["unavailable_samples"]:
                failed_gates.append(f"{environment}_redis_configuration_changed_during_window")
            if metric_summary["redis_availability_window"]["unknown_samples"]:
                failed_gates.append(f"{environment}_redis_availability_unobserved")
            if metric_summary["redis_availability_window"]["unavailable_samples"]:
                failed_gates.append(f"{environment}_redis_unavailable_during_window")
            if metric_summary["redis_publish_age_unknown_samples"]:
                failed_gates.append(f"{environment}_redis_publish_age_unobserved")
            if metric_summary["redis_publish_age_stale_samples"]:
                failed_gates.append(f"{environment}_redis_publish_stale_during_window")
            record["redis_delivery_failure_count"] = (
                int(record.get("redis_delivery_failure_count", 0)) + metric_summary["redis_publish_failure_delta"]
            )
        summary["deployments"].append({
            "environment": environment,
            "sample_count": len(samples),
            "metrics_sample_count": len(metrics_samples),
            "metrics_observation_failures": metrics_failures,
            "max_metrics_sample_gap_seconds": round(max_metrics_gap, 3),
            "healthy_sample_count": len(samples) - health_failures,
            "unhealthy_sample_count": health_failures,
            "max_sample_gap_seconds": round(max(gaps, default=0), 3),
            "observed_revision_matches_image": all(
                sample["revision_matches"] for sample in samples
            ),
            "metrics": metric_summary,
        })
    candidate_record = records[0]
    redis_recovery_verification: dict[str, Any] | None = None
    if redis_recovery_report is None:
        failed_gates.append("redis_recovery_ci_evidence_missing")
    else:
        redis_provenance, provenance_failures = validate_ci_provenance(
            redis_recovery_provenance,
            expected_revision=candidate_record["revision"],
        )
        failed_gates.extend(provenance_failures)
        redis_recovery_verification, redis_recovery_failures = validate_redis_recovery_report(
            redis_recovery_report,
            expected_revision=candidate_record["revision"],
            now=ended,
        )
        failed_gates.extend(redis_recovery_failures)
        if redis_recovery_verification is not None and redis_provenance is not None:
            redis_recovery_verification["ci_provenance"] = redis_provenance

    rollback_rehearsal: dict[str, Any] | None = None
    if rollback_report is None:
        failed_gates.append("rollback_readback_evidence_missing")
    else:
        rollback_rehearsal, rollback_failures = validate_rollback_report(
            rollback_report,
            candidate_image=candidate_record["image"],
            candidate_digest=candidate_record["digest"],
            production_image=records[1]["image"],
            collection_started_at=begun.isoformat(),
            collection_ended_at=ended.isoformat(),
        )
        failed_gates.extend(rollback_failures)

    rollback_summary = summarize_rollback_report(rollback_rehearsal) if rollback_rehearsal else None
    canary_readbacks = rollback_summary["readbacks"] if rollback_summary else {}
    candidate_record["rollback_drill_passed"] = rollback_rehearsal is not None
    candidate_record["rollback_drill_at"] = (
        canary_readbacks.get("canary_after_rollback", {}).get("observed_at")
        if rollback_rehearsal else None
    )
    candidate_record["production_untouched_on_canary_failure"] = (
        rollback_summary.get("production_unchanged") is True
        if rollback_summary else False
    )
    candidate_record["production_protection_observed_at"] = (
        canary_readbacks.get("production_after", {}).get("observed_at")
        if rollback_rehearsal else None
    )
    safe_records["canary"].update({
        "rollback_drill_passed": candidate_record["rollback_drill_passed"],
        "rollback_drill_at": candidate_record["rollback_drill_at"],
        "production_untouched_on_canary_failure": candidate_record[
            "production_untouched_on_canary_failure"
        ],
        "production_protection_observed_at": candidate_record[
            "production_protection_observed_at"
        ],
    })
    enriched_evidence = {
        "format": evidence["format"],
        "deployments": [safe_records[name] for name in ENVIRONMENTS],
        "collection": {
            "format": summary["format"],
            "phase": phase,
            "passed": not failed_gates,
            "failed_gates": sorted(set(failed_gates)),
            "started_at": begun.isoformat(),
            "ended_at": ended.isoformat(),
            "duration_seconds": max(0.0, wall_duration),
            "interval_seconds": interval_seconds,
            "read_only_app_probe_paths": ["/healthz", "/readyz", "/metrics"],
            "registry_request_methods": ["GET token", "HEAD image manifest"],
            "image_digest_source": "GHCR Docker-Content-Digest response; candidate references are digest pinned",
            "registry_digest_verification_scope": (
                "canary-and-production"
            ),
            "router_runtime_digest_verified": False,
            "browser_origin_readiness": browser_origin_observation,
            "stream_acceptance": None,
            "certificate_lifecycle_acceptance": certificate_lifecycle_acceptance,
            "registry_digest_verification": registry_verification,
            "sqlite_restore_verification": sqlite_restore_verification,
            "redis_recovery_verification": redis_recovery_verification,
            "rollback_rehearsal": rollback_rehearsal,
        },
    }
    summary["passed"] = not failed_gates
    summary["failed_gates"] = sorted(set(failed_gates))
    summary["failed_gates"] = sorted(set(summary["failed_gates"]) | {
        "stream_observation_missing", "browser_telemetry_evidence_missing",
    })
    summary["passed"] = False
    summary["evidence"] = enriched_evidence
    summary["evidence"]["collection"]["passed"] = False
    summary["evidence"]["collection"]["failed_gates"] = summary["failed_gates"]
    summary["_verified_deployment_identity"] = verified_deployment_identity
    return (0 if summary["passed"] else 1), summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, help="private, redacted v2 evidence JSON with RouterOS-only fields")
    parser.add_argument("--output", required=True, help="output path for collected evidence JSON")
    parser.add_argument(
        "--routeros-report",
        required=True,
        help="completed redacted report from collect_routeros_acceptance.py; must cover the same soak",
    )
    parser.add_argument(
        "--redis-recovery-run-id",
        help="successful main-branch CI run id; its exact candidate-bound artifact is downloaded and verified with gh",
    )
    parser.add_argument(
        "--rollback-report",
        help="redacted ordered RouterOS/readiness read-backs for the isolated canary rollback drill",
    )
    parser.add_argument(
        "--stream-observer-report", required=True,
        help="redacted telemetry_stream_observer.py report for this same canary soak",
    )
    parser.add_argument(
        "--telemetry-acceptance-input", required=True,
        help="redacted telemetry_acceptance NDJSON captured concurrently over this same soak",
    )
    parser.add_argument(
        "--certificate-lifecycle-report",
        help="redacted, candidate-bound certificate lifecycle acceptance JSON",
    )
    parser.add_argument("--canary-url", required=True, help="private app origin, without path")
    parser.add_argument("--production-url", required=True, help="private app origin, without path")
    parser.add_argument(
        "--canary-sqlite-backup",
        help="local private canary SQLite backup to restore into a temporary copy; never written to the report",
    )
    parser.add_argument(
        "--production-sqlite-backup",
        help="local private production SQLite backup (required for postpromotion; never read prepromotion)",
    )
    parser.add_argument("--canary-metrics-url", required=True, help="canary app origin for authenticated /metrics")
    parser.add_argument("--production-metrics-url", help="production app origin for authenticated /metrics (required for postpromotion acceptance)")
    parser.add_argument("--cookie-env", help="legacy environment variable containing a short-lived session Cookie header value")
    parser.add_argument("--canary-api-token-env", help="environment variable containing a canary health.read API token")
    parser.add_argument("--production-api-token-env", help="environment variable containing a production health.read API token")
    parser.add_argument("--duration-seconds", type=float, default=1800)
    parser.add_argument("--interval-seconds", type=float, default=60)
    parser.add_argument("--timeout-seconds", type=float, default=5)
    parser.add_argument(
        "--phase",
        choices=("canary-prepromotion", "postpromotion"),
        default="postpromotion",
        help="soak the candidate before promotion, or verify both environments after promotion",
    )
    args = parser.parse_args()
    try:
        evidence = json.loads(Path(args.input).read_text(encoding="utf-8"))
        if not isinstance(evidence, dict):
            raise ValueError("release evidence must be a JSON object")
        if args.certificate_lifecycle_report:
            evidence["certificate_lifecycle_acceptance"] = _read_certificate_lifecycle_report(
                args.certificate_lifecycle_report
            )
        redis_recovery_report = None
        redis_recovery_provenance = None
        if args.redis_recovery_run_id:
            deployments = evidence.get("deployments")
            candidate = deployments[0] if isinstance(deployments, list) and deployments else None
            image_match = IMAGE.fullmatch(candidate.get("image", "")) if isinstance(candidate, dict) else None
            if image_match is None:
                raise ValueError("candidate image must contain a full immutable revision before CI verification")
            redis_recovery_report, redis_recovery_provenance = download_verified_ci_report(
                args.redis_recovery_run_id,
                expected_revision=image_match.group("revision"),
            )
        rollback_report = None
        if args.rollback_report:
            rollback_report = _read_bounded_json_report(
                args.rollback_report,
                MAX_ROLLBACK_REPORT_BYTES,
                "rollback read-back report",
            )
        cookie = os.environ.get(args.cookie_env) if args.cookie_env else None
        if args.cookie_env and not cookie:
            raise ValueError("the requested cookie environment variable is unset or empty")
        if cookie and ("\r" in cookie or "\n" in cookie or len(cookie) > 8192):
            raise ValueError("the session cookie value contains invalid characters or exceeds the size limit")
        metrics_tokens: dict[str, str] = {}
        token_environment_names = {"canary": args.canary_api_token_env}
        if args.phase != "canary-prepromotion":
            token_environment_names["production"] = args.production_api_token_env
        for environment, variable_name in token_environment_names.items():
            if not variable_name:
                continue
            token = os.environ.get(variable_name)
            if not token:
                raise ValueError(f"the requested {environment} API-token environment variable is unset or empty")
            metrics_tokens[environment] = token
        metrics_urls = {
            name: value for name, value in (
                ("canary", args.canary_metrics_url), ("production", args.production_metrics_url)
            ) if value
        }
        if args.phase == "canary-prepromotion":
            metrics_urls.pop("production", None)
        sqlite_backup_paths = {}
        if args.canary_sqlite_backup:
            sqlite_backup_paths["canary"] = args.canary_sqlite_backup
        if args.phase == "postpromotion" and args.production_sqlite_backup:
            sqlite_backup_paths["production"] = args.production_sqlite_backup
        code, summary = collect(
            evidence,
            readyz_urls={"canary": args.canary_url, "production": args.production_url},
            sqlite_backup_paths=sqlite_backup_paths,
            metrics_urls=metrics_urls,
            cookie=cookie,
            metrics_tokens=metrics_tokens,
            duration_seconds=args.duration_seconds,
            interval_seconds=args.interval_seconds,
            timeout_seconds=args.timeout_seconds,
            phase=args.phase,
            redis_recovery_report=redis_recovery_report,
            redis_recovery_provenance=redis_recovery_provenance,
            rollback_report=rollback_report,
        )
        verified_deployment_identity = summary.pop("_verified_deployment_identity", None)
        routeros_report = json.loads(Path(args.routeros_report).read_text(encoding="utf-8"))
        attach_routeros_resource_evidence(summary["evidence"], routeros_report)
        observer_path = Path(args.stream_observer_report)
        browser_path = Path(args.telemetry_acceptance_input)
        if observer_path.stat().st_size > MAX_STREAM_OBSERVER_REPORT_BYTES:
            raise ValueError("stream observer report exceeds its aggregate size limit")
        if browser_path.stat().st_size > MAX_TELEMETRY_ACCEPTANCE_BYTES:
            raise ValueError("telemetry acceptance input exceeds its bounded size limit")
        observer_report = json.loads(observer_path.read_text(encoding="utf-8"))
        try:
            from telemetry_acceptance import evaluate as evaluate_telemetry_acceptance
        except ModuleNotFoundError:
            from scripts.telemetry_acceptance import evaluate as evaluate_telemetry_acceptance

        browser_lines = browser_path.read_text(encoding="utf-8").splitlines()
        collection_end = datetime.fromisoformat(
            summary["evidence"]["collection"]["ended_at"].replace("Z", "+00:00")
        )
        _, browser_report = evaluate_telemetry_acceptance(
            browser_lines,
            limits={
                "latency_p95_ms": 1000,
                "event_age_seconds": 2,
                "router_cpu_percent": 80,
                "router_memory_percent": 90,
                "router_storage_percent": 90,
                "max_reconnects": 0,
                "recovery_seconds": 10,
            },
            now=collection_end.timestamp(),
            verified_deployment_identity=verified_deployment_identity,
        )
        code, summary = apply_stream_acceptance(
            summary,
            observer_report,
            browser_acceptance_projection(browser_report),
            now=_utc_now(),
        )
        code, summary = finalize_release_acceptance(
            summary, phase=args.phase, now=_utc_now()
        )
        _write_json_atomically(Path(args.output), summary["evidence"])
        public_summary = {key: value for key, value in summary.items() if key != "evidence"}
        print(json.dumps(public_summary, sort_keys=True, indent=2))
    except (OSError, json.JSONDecodeError, ValueError) as error:
        # Do not emit input, URL, response, credentials, or exception details.
        failure_report = {
            "format": "vpn-dashboard-release-collection-failure-v1",
            "collected": False,
            "collected_at": _utc_now().isoformat(),
            "passed": False,
            "failed_gates": ["collection_failed"],
            "error": type(error).__name__,
        }
        output_replaced = False
        try:
            _write_json_atomically(Path(args.output), failure_report)
            output_replaced = True
        except OSError:
            pass
        print(json.dumps({"collected": False, "output_replaced": output_replaced, "error": type(error).__name__}))
        return 2
    return code


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--internal-ghcr-digest":
        try:
            worker_digest = _registry_digest_request(sys.argv[2], timeout=float(sys.argv[3]))
        except (ValueError, OverflowError):
            worker_digest = None
        if worker_digest:
            sys.stdout.write(worker_digest + "\n")
            raise SystemExit(0)
        raise SystemExit(1)
    raise SystemExit(main())
