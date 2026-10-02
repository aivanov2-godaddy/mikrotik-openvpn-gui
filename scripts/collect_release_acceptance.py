"""Collect bounded, redacted release evidence from private app probes.

RouterOS-specific measurements remain operator-supplied in the evidence file.
This collector only performs HTTP GET requests to /healthz, /readyz and (when
configured) the authenticated, read-only /metrics endpoint.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import re
import time
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

try:
    from release_acceptance import DIGEST, ENVIRONMENTS, IMAGE, evaluate as validate_evidence
except ModuleNotFoundError:
    from scripts.release_acceptance import DIGEST, ENVIRONMENTS, IMAGE, evaluate as validate_evidence


MAX_RESPONSE_BYTES = 1_000_000
MAX_DURATION_SECONDS = 86_400
MAX_SAMPLES = 10_000
MIN_SOAK_SECONDS = 1800
MIN_HEALTH_SAMPLES = 30
MAX_SAMPLE_GAP_SECONDS = 120
METRIC_NAMES = {
    "vpn_dashboard_health",
    "vpn_dashboard_redis_configured",
    "vpn_dashboard_redis_last_observed_available",
    "vpn_dashboard_redis_publish_total",
    "vpn_dashboard_redis_last_publish_success_timestamp_seconds",
    "vpn_dashboard_integration_outbox_pending",
    "vpn_dashboard_integration_outbox_oldest_age_seconds",
    "vpn_dashboard_telemetry_session_event_age_seconds",
    "vpn_dashboard_telemetry_session_event_timestamp_seconds",
    "vpn_dashboard_telemetry_session_events_total",
    "vpn_dashboard_telemetry_traffic_sample_age_seconds",
    "vpn_dashboard_telemetry_traffic_sample_timestamp_seconds",
    "vpn_dashboard_telemetry_traffic_samples_total",
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


def _get(url: str, *, cookie: str | None, timeout: float) -> tuple[int, bytes]:
    headers = {"Accept": "application/json, text/plain; version=0.0.4"}
    if cookie:
        headers["Cookie"] = cookie
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
                outcome = re.search(r'outcome="(success|failure)"', labels)
                if outcome:
                    result[f"{name}_{outcome.group(1)}"] = value
            elif name == "vpn_dashboard_health":
                result[name] = value
            else:
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
    first, last = metric_samples[0], metric_samples[-1]
    successes_in_window = any(
        sample.get("vpn_dashboard_redis_last_publish_success_timestamp_seconds", 0) > start_epoch
        and sample.get("vpn_dashboard_redis_last_publish_success_timestamp_seconds", 0) <= end_epoch
        for sample in metric_samples
    )
    failure_delta = max(
        0,
        int(last.get("vpn_dashboard_redis_publish_total_failure", 0)
            - first.get("vpn_dashboard_redis_publish_total_failure", 0)),
    )
    failure_counter_reset = (
        last.get("vpn_dashboard_redis_publish_total_failure", 0)
        < first.get("vpn_dashboard_redis_publish_total_failure", 0)
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

    return {
        "available": True,
        "redis_configured": last.get("vpn_dashboard_redis_configured"),
        "redis_last_observed_available": last.get("vpn_dashboard_redis_last_observed_available"),
        "redis_publish_success_observed_in_window": successes_in_window,
        "redis_publish_failure_delta": failure_delta,
        "redis_publish_failure_counter_reset": failure_counter_reset,
        "outbox_pending_last": last.get("vpn_dashboard_integration_outbox_pending"),
        "outbox_oldest_age_seconds_last": last.get("vpn_dashboard_integration_outbox_oldest_age_seconds"),
        "telemetry_process_observation_age": {
            "session_event": observation_age(
                "vpn_dashboard_telemetry_session_event_age_seconds",
                "vpn_dashboard_telemetry_session_event_timestamp_seconds",
            ),
            "traffic_sample": observation_age(
                "vpn_dashboard_telemetry_traffic_sample_age_seconds",
                "vpn_dashboard_telemetry_traffic_sample_timestamp_seconds",
            ),
            "meaning": "Age since this process observed telemetry; not RouterOS-to-browser delivery latency.",
        },
    }


def collect(
    evidence: Any,
    *,
    readyz_urls: dict[str, str],
    metrics_urls: dict[str, str] | None = None,
    cookie: str | None = None,
    duration_seconds: float = 1800,
    interval_seconds: float = 60,
    timeout_seconds: float = 5,
    probe: Callable[..., tuple[int, bytes]] = _get,
    clock: Callable[[], datetime] = _utc_now,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
    minimum_soak_seconds: float = MIN_SOAK_SECONDS,
    minimum_health_samples: int = MIN_HEALTH_SAMPLES,
) -> tuple[int, dict[str, Any]]:
    if not isinstance(evidence, dict) or evidence.get("format") != "vpn-dashboard-release-evidence-v2":
        raise ValueError("evidence must use vpn-dashboard-release-evidence-v2")
    # The shared validator enforces every field's type, enum, bounds, and
    # timestamp format, then returns a strict allowlisted projection. Use that
    # projection as the only source of caller-supplied values in output.
    _, validated_evidence = validate_evidence(evidence)
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
    for environment, metrics_url in metrics_urls.items():
        if _origin(metrics_url) != _origin(readyz_urls[environment]):
            raise ValueError(f"{environment} metrics URL origin must exactly match its readiness probe origin")
    if cookie and any(urlsplit(url).scheme != "https" for url in metrics_urls.values()):
        raise ValueError("authenticated metrics probes require HTTPS")

    safe_records: dict[str, dict[str, Any]] = {}
    for record, environment in zip(records, ENVIRONMENTS):
        if not isinstance(record, dict) or record.get("environment") != environment:
            raise ValueError("evidence deployments must be ordered canary, then production")
        image = str(record.get("image", ""))
        digest = str(record.get("digest", ""))
        if not IMAGE.fullmatch(image) or not DIGEST.fullmatch(digest):
            raise ValueError(f"{environment} evidence needs an immutable image tag and digest")
        if environment in safe_records and safe_records[environment]["image"] != image:
            raise ValueError("canary and production must use the same image")
        safe_records[environment] = dict(record)

    if safe_records["canary"]["image"] != safe_records["production"]["image"]:
        raise ValueError("canary and production must use the same image")
    expected_revision = REVISION_IN_IMAGE.search(safe_records["canary"]["image"]).group("revision")  # type: ignore[union-attr]
    deployment_samples: dict[str, list[dict[str, Any]]] = {name: [] for name in ENVIRONMENTS}
    begun = clock()
    began_epoch = begun.timestamp()
    deadline = monotonic() + duration_seconds
    while True:
        observed = clock()
        for environment in ENVIRONMENTS:
            base = readyz_urls[environment]
            health_code, _ = probe(_probe_url(base, "/healthz"), cookie=None, timeout=timeout_seconds)
            ready_code, ready_body = probe(_probe_url(base, "/readyz"), cookie=None, timeout=timeout_seconds)
            ready_payload = _json_status(ready_body) if ready_code == 200 else {}
            revision = ready_payload.get("revision") if isinstance(ready_payload.get("revision"), str) else ""
            metrics: dict[str, float] = {}
            if environment in metrics_urls:
                metrics_code, metrics_body = probe(
                    _probe_url(metrics_urls[environment], "/metrics"), cookie=cookie, timeout=timeout_seconds
                )
                if metrics_code == 200:
                    metrics = _parse_metrics(metrics_body)
            metric_health = metrics.get("vpn_dashboard_health")
            revision_matches = (
                ready_code == 200
                and ready_payload.get("status") == "ready"
                and revision == expected_revision
            )
            ready = revision_matches
            deployment_samples[environment].append({
                "at": observed,
                "ready": ready,
                "revision_matches": revision_matches,
                "healthy": health_code == 200 and ready and metric_health in (None, 1),
                "metrics": metrics,
            })
        now = clock()
        if now.timestamp() - began_epoch >= duration_seconds or monotonic() >= deadline:
            break
        sleep(min(interval_seconds, max(0.0, duration_seconds - (now.timestamp() - began_epoch))))

    ended = clock()
    failed_gates: list[str] = []
    summary: dict[str, Any] = {"format": "vpn-dashboard-release-collection-v1", "deployments": []}
    for environment in ENVIRONMENTS:
        samples = deployment_samples[environment]
        sample_times = [sample["at"].timestamp() for sample in samples]
        gaps = [right - left for left, right in zip(sample_times, sample_times[1:])]
        health_failures = sum(not sample["healthy"] for sample in samples)
        observed_window_seconds = max(0.0, (ended - begun).total_seconds())
        max_gap = max(gaps, default=0)
        if health_failures:
            failed_gates.append(f"{environment}_health_or_revision_failure")
        if observed_window_seconds < minimum_soak_seconds:
            failed_gates.append(f"{environment}_soak_window_too_short")
        if len(samples) < minimum_health_samples:
            failed_gates.append(f"{environment}_health_samples_insufficient")
        if max_gap > MAX_SAMPLE_GAP_SECONDS:
            failed_gates.append(f"{environment}_sample_gap_exceeded")
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
        metric_summary = _metric_window(samples, began_epoch, ended.timestamp())
        if metric_summary["available"]:
            # A passing Redis publish requires configuration, observed availability,
            # and a successful publish in this observation window.
            record["redis_configured"] = metric_summary["redis_configured"] == 1
            record["redis_publish_verified"] = (
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
            "passed": not failed_gates,
            "failed_gates": sorted(set(failed_gates)),
            "started_at": begun.isoformat(),
            "ended_at": ended.isoformat(),
            "duration_seconds": max(0.0, (ended - begun).total_seconds()),
            "interval_seconds": interval_seconds,
            "read_only_get_probes": ["/healthz", "/readyz", "/metrics (optional)"],
            "image_digest_source": "operator-supplied; registry digest is not fetched by this tool",
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
    parser.add_argument("--canary-metrics-url", help="optional app origin for authenticated /metrics")
    parser.add_argument("--production-metrics-url", help="optional app origin for authenticated /metrics")
    parser.add_argument("--cookie-env", help="environment variable containing a short-lived session Cookie header value")
    parser.add_argument("--duration-seconds", type=float, default=1800)
    parser.add_argument("--interval-seconds", type=float, default=60)
    parser.add_argument("--timeout-seconds", type=float, default=5)
    args = parser.parse_args()
    try:
        evidence = json.loads(Path(args.input).read_text(encoding="utf-8"))
        cookie = os.environ.get(args.cookie_env) if args.cookie_env else None
        if args.cookie_env and not cookie:
            raise ValueError("the requested cookie environment variable is unset or empty")
        if cookie and ("\r" in cookie or "\n" in cookie or len(cookie) > 8192):
            raise ValueError("the session cookie value contains invalid characters or exceeds the size limit")
        metrics_urls = {
            name: value for name, value in (
                ("canary", args.canary_metrics_url), ("production", args.production_metrics_url)
            ) if value
        }
        code, summary = collect(
            evidence,
            readyz_urls={"canary": args.canary_url, "production": args.production_url},
            metrics_urls=metrics_urls,
            cookie=cookie,
            duration_seconds=args.duration_seconds,
            interval_seconds=args.interval_seconds,
            timeout_seconds=args.timeout_seconds,
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
    raise SystemExit(main())
