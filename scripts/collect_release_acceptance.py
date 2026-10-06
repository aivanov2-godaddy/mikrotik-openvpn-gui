"""Collect bounded, redacted release evidence from private app probes.

RouterOS-specific measurements remain operator-supplied in the evidence file.
The canary-prepromotion phase verifies the candidate while production stays on
its recorded prior revision. The postpromotion phase requires both environments
on the same candidate. Probes are read-only; the candidate digest (and, after
promotion, the production digest) is checked against GHCR before the soak.
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
import time
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

try:
    from release_acceptance import DIGEST, ENVIRONMENTS, IMAGE, evaluate as validate_evidence
except ModuleNotFoundError:
    from scripts.release_acceptance import DIGEST, ENVIRONMENTS, IMAGE, evaluate as validate_evidence


MAX_RESPONSE_BYTES = 1_000_000
MAX_REGISTRY_RESPONSE_BYTES = 65_536
MAX_DURATION_SECONDS = 86_400
MAX_SAMPLES = 10_000
MIN_SOAK_SECONDS = 1800
MIN_HEALTH_SAMPLES = 30
MAX_SAMPLE_GAP_SECONDS = 120
MAX_TRAFFIC_SAMPLE_AGE_SECONDS = 2.0
MAX_GATEWAY_DELIVERY_P95_SECONDS = 1.0
MAX_OUTBOX_PENDING_AT_WINDOW_END = 0
MAX_OUTBOX_DEAD_LETTERED = 0
MAX_CLOCK_DRIFT_SECONDS = 5.0
METRIC_NAMES = {
    "vpn_dashboard_health",
    "vpn_dashboard_redis_configured",
    "vpn_dashboard_redis_last_observed_available",
    "vpn_dashboard_redis_publish_total",
    "vpn_dashboard_redis_last_publish_success_timestamp_seconds",
    "vpn_dashboard_integration_outbox_pending",
    "vpn_dashboard_integration_outbox_dead_lettered",
    "vpn_dashboard_integration_outbox_oldest_age_seconds",
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
REQUIRED_ACCEPTANCE_METRICS = {
    "vpn_dashboard_redis_configured",
    "vpn_dashboard_redis_last_observed_available",
    "vpn_dashboard_redis_publish_total_success",
    "vpn_dashboard_redis_publish_total_failure",
    "vpn_dashboard_redis_last_publish_success_timestamp_seconds",
    "vpn_dashboard_integration_outbox_pending",
    "vpn_dashboard_integration_outbox_dead_lettered",
    "vpn_dashboard_integration_outbox_oldest_age_seconds",
    "vpn_dashboard_telemetry_session_event_age_seconds",
    "vpn_dashboard_telemetry_session_event_timestamp_seconds",
    "vpn_dashboard_telemetry_traffic_sample_age_seconds",
    "vpn_dashboard_telemetry_traffic_sample_timestamp_seconds",
    "vpn_dashboard_telemetry_gateway_clients",
    "vpn_dashboard_telemetry_gateway_buffered_events",
    "vpn_dashboard_telemetry_gateway_events_total_published",
    "vpn_dashboard_telemetry_gateway_events_total_replayed",
    "vpn_dashboard_telemetry_gateway_events_total_snapshot_recovery",
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
REVISION_IN_IMAGE = re.compile(r":sha-(?P<revision>[0-9a-f]{40})(?:-(?:arm64|amd64))?$")


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request: Request, fp: Any, code: int, msg: str, headers: Any, new_url: str) -> None:
        return None


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


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
    repository, tag = reference.rsplit(":", 1)
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
            "HEAD", f"/v2/{repository}/manifests/{tag}", timeout=timeout,
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
    metric_samples = [sample["metrics"] for sample in samples if sample.get("metrics")]
    if not metric_samples:
        return {"available": False}
    last = metric_samples[-1]
    successes_in_window = any(
        sample.get("vpn_dashboard_redis_last_publish_success_timestamp_seconds", 0) > start_epoch
        and sample.get("vpn_dashboard_redis_last_publish_success_timestamp_seconds", 0) <= end_epoch
        for sample in metric_samples
    )
    def observation_age(metric_name: str, timestamp_name: str) -> dict[str, Any]:
        values = [sample[metric_name] for sample in metric_samples if metric_name in sample]
        observed = [value for value in values if value >= 0]
        timestamps = [sample[timestamp_name] for sample in metric_samples if sample.get(timestamp_name, -1) >= 0]
        return {
            "last_seconds": values[-1] if values else None,
            "max_seconds": max(observed) if observed else None,
            "observed_samples": len(observed),
            "unknown_samples": sum(value < 0 for value in values),
            "last_observed_timestamp_seconds": timestamps[-1] if timestamps else None,
        }

    def counter_window(metric_name: str) -> dict[str, Any]:
        values = [sample[metric_name] for sample in metric_samples if metric_name in sample]
        if not values:
            return {"delta": 0, "counter_reset": False}
        previous = max(0, int(values[0]))
        delta = 0
        reset = False
        for raw_value in values[1:]:
            current = max(0, int(raw_value))
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
        }

    def gauge_window(metric_name: str) -> dict[str, Any]:
        values = [sample[metric_name] for sample in metric_samples if metric_name in sample]
        observed = [value for value in values if value >= 0]
        return {
            "last": values[-1] if values else None,
            "max": max(observed) if observed else None,
            "observed_samples": len(observed),
            "unknown_samples": sum(value < 0 for value in values),
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

    redis_failure_window = counter_window("vpn_dashboard_redis_publish_total_failure")
    failure_delta = redis_failure_window["delta"]
    failure_counter_reset = redis_failure_window["counter_reset"]

    return {
        "available": True,
        "redis_configured": last.get("vpn_dashboard_redis_configured"),
        "redis_last_observed_available": last.get("vpn_dashboard_redis_last_observed_available"),
        "redis_publish_success_observed_in_window": successes_in_window,
        "redis_publish_failure_delta": failure_delta,
        "redis_publish_failure_counter_reset": failure_counter_reset,
        "outbox_pending_last": last.get("vpn_dashboard_integration_outbox_pending"),
        "outbox_dead_lettered_last": last.get("vpn_dashboard_integration_outbox_dead_lettered"),
        "outbox_oldest_age_seconds_last": last.get("vpn_dashboard_integration_outbox_oldest_age_seconds"),
        "outbox_pending_unknown_samples": outbox_pending["unknown_samples"],
        "outbox_dead_lettered_max": outbox_dead_lettered["max"],
        "outbox_dead_lettered_unknown_samples": outbox_dead_lettered["unknown_samples"],
        "outbox_oldest_age_max_seconds": outbox_oldest_age["max"],
        "outbox_oldest_age_unknown_samples": outbox_oldest_age["unknown_samples"],
        "telemetry_gateway": {
            "authorized_clients_last": last.get("vpn_dashboard_telemetry_gateway_clients"),
            "buffered_events_last": last.get("vpn_dashboard_telemetry_gateway_buffered_events"),
            "published_events": counter_window("vpn_dashboard_telemetry_gateway_events_total_published"),
            "replayed_events": counter_window("vpn_dashboard_telemetry_gateway_events_total_replayed"),
            "snapshot_recoveries": counter_window(
                "vpn_dashboard_telemetry_gateway_events_total_snapshot_recovery"
            ),
            "rejected_clients": counter_window("vpn_dashboard_telemetry_gateway_rejected_clients_total"),
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
            "attempts": counter_window("vpn_dashboard_telemetry_supervisor_attempts_total"),
            "reconnects": counter_window("vpn_dashboard_telemetry_supervisor_reconnects_total"),
            "failures": counter_window("vpn_dashboard_telemetry_supervisor_failures_total"),
            "events": counter_window("vpn_dashboard_telemetry_supervisor_events_total"),
            "last_connected_timestamp_seconds": last.get(
                "vpn_dashboard_telemetry_supervisor_last_connected_timestamp_seconds"
            ),
            "last_event_timestamp_seconds": last.get(
                "vpn_dashboard_telemetry_supervisor_last_event_timestamp_seconds"
            ),
            "last_snapshot_timestamp_seconds": last.get(
                "vpn_dashboard_telemetry_supervisor_last_snapshot_timestamp_seconds"
            ),
            "backoff_seconds_last": last.get("vpn_dashboard_telemetry_supervisor_backoff_seconds"),
            "meaning": "Aggregate process-local RouterOS Binary API supervisor state; counters may reset on process restart.",
        },
        "telemetry_slo": {
            "session_event_unknown_samples": session_event_age["unknown_samples"],
            "traffic_sample_max_age_seconds": traffic_sample_age["max_seconds"],
            "traffic_sample_unknown_samples": traffic_sample_age["unknown_samples"],
            "gateway_delivery_p95_max_seconds": gateway_delivery_age["max"],
            "gateway_delivery_p95_unknown_samples": gateway_delivery_age["unknown_samples"],
            "gateway_delivery_observations_last": last.get(
                "vpn_dashboard_telemetry_gateway_delivery_observations"
            ),
            "supervisor_non_healthy_samples": sum(
                sample.get("vpn_dashboard_telemetry_supervisor_status_healthy") != 1
                or sample.get("vpn_dashboard_telemetry_supervisor_enabled") != 1
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
    metrics_urls: dict[str, str] | None = None,
    cookie: str | None = None,
    metrics_tokens: dict[str, str] | None = None,
    duration_seconds: float = 1800,
    interval_seconds: float = 60,
    timeout_seconds: float = 5,
    phase: str = "postpromotion",
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
    # The shared validator enforces every field's type, enum, bounds, and
    # timestamp format, then returns a strict allowlisted projection. Use that
    # projection as the only source of caller-supplied values in output.
    _, validated_evidence = validate_evidence(evidence, phase=phase)
    records = validated_evidence["deployments"]
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
        prior_production_baseline = phase == "canary-prepromotion" and environment == "production"
        if not IMAGE.fullmatch(image) or (digest is None and not prior_production_baseline):
            raise ValueError(f"{environment} evidence needs an immutable image tag and digest")
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
    failed_gates: list[str] = []
    registry_environments = ("canary",) if phase == "canary-prepromotion" else ENVIRONMENTS
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
        remaining = deadline - monotonic()
        if remaining <= 0:
            break
        sleep(min(interval_seconds, remaining))

    ended = clock()
    ended_monotonic = monotonic()
    wall_duration = (ended - begun).total_seconds()
    monotonic_duration = max(0.0, ended_monotonic - began_monotonic)
    if wall_duration < 0 or abs(wall_duration - monotonic_duration) > MAX_CLOCK_DRIFT_SECONDS:
        failed_gates.append("collection_clock_anomaly")
    summary: dict[str, Any] = {"format": "vpn-dashboard-release-collection-v1", "deployments": []}
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
        # Never carry an operator-supplied Redis success claim through a
        # window that did not independently observe complete aggregate metrics.
        record["redis_configured"] = False
        record["redis_publish_verified"] = False
        if metric_summary["available"] and (metrics_required or metrics_window_complete):
            telemetry_slo = metric_summary["telemetry_slo"]
            traffic_age = telemetry_slo["traffic_sample_max_age_seconds"]
            if telemetry_slo["session_event_unknown_samples"]:
                failed_gates.append(f"{environment}_session_event_freshness_incomplete")
            if telemetry_slo["traffic_sample_unknown_samples"]:
                failed_gates.append(f"{environment}_traffic_freshness_incomplete")
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
            elif metric_summary["outbox_pending_last"] is None or metric_summary["outbox_pending_last"] < 0:
                failed_gates.append(f"{environment}_outbox_pending_count_unobserved")
            elif metric_summary["outbox_pending_last"] > MAX_OUTBOX_PENDING_AT_WINDOW_END:
                failed_gates.append(f"{environment}_outbox_not_drained")
            if metric_summary["outbox_oldest_age_unknown_samples"] or metric_summary["outbox_oldest_age_max_seconds"] is None:
                failed_gates.append(f"{environment}_outbox_age_unobserved")
            # A passing Redis publish requires configuration, observed availability,
            # and a successful publish in this observation window.
            record["redis_configured"] = metrics_window_complete and metric_summary["redis_configured"] == 1
            record["redis_publish_verified"] = metrics_window_complete and (
                record["redis_configured"]
                and metric_summary["redis_last_observed_available"] == 1
                and metric_summary["redis_publish_success_observed_in_window"]
                and metric_summary["redis_publish_failure_delta"] == 0
                and not metric_summary["redis_publish_failure_counter_reset"]
            )
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
            "image_digest_source": "GHCR Docker-Content-Digest response",
            "registry_digest_verification_scope": (
                "candidate-canary-only" if phase == "canary-prepromotion" else "canary-and-production"
            ),
            "router_runtime_digest_verified": False,
            "registry_digest_verification": registry_verification,
        },
    }
    summary["passed"] = not failed_gates
    summary["failed_gates"] = sorted(set(failed_gates))
    summary["evidence"] = enriched_evidence
    return (0 if summary["passed"] else 1), summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, help="private, redacted v2 evidence JSON with RouterOS-only fields")
    parser.add_argument("--output", required=True, help="output path for collected evidence JSON")
    parser.add_argument("--canary-url", required=True, help="private app origin, without path")
    parser.add_argument("--production-url", required=True, help="private app origin, without path")
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
        code, summary = collect(
            evidence,
            readyz_urls={"canary": args.canary_url, "production": args.production_url},
            metrics_urls=metrics_urls,
            cookie=cookie,
            metrics_tokens=metrics_tokens,
            duration_seconds=args.duration_seconds,
            interval_seconds=args.interval_seconds,
            timeout_seconds=args.timeout_seconds,
            phase=args.phase,
        )
        Path(args.output).write_text(json.dumps(summary["evidence"], sort_keys=True, indent=2) + "\n", encoding="utf-8")
        public_summary = {key: value for key, value in summary.items() if key != "evidence"}
        print(json.dumps(public_summary, sort_keys=True, indent=2))
    except (OSError, json.JSONDecodeError, ValueError) as error:
        # Do not emit input, URL, response, credentials, or exception details.
        print(json.dumps({"collected": False, "error": type(error).__name__}))
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
