from __future__ import annotations

from datetime import datetime, timedelta, timezone
from contextlib import redirect_stdout
from io import StringIO
import json
import sys
import unittest
from unittest.mock import Mock, patch

from scripts.collect_release_acceptance import collect


REVISION = "a" * 40
IMAGE = f"ghcr.io/example/vpn:sha-{REVISION}-arm64"


def evidence() -> dict[str, object]:
    return {
        "format": "vpn-dashboard-release-evidence-v2",
        "deployments": [
            {
                "environment": environment,
                "image": IMAGE,
                "digest": "sha256:" + "b" * 64,
                "container_healthy": True,
                "app_ready": True,
                "transport": "asgi-websocket",
                "rest_fallback": True,
                "redis_configured": True,
                "redis_publish_verified": False,
                "reconnect_recovered": True,
                "snapshot_recovered": True,
                "sqlite_restore_verified": True,
                "rollback_drill_passed": environment == "canary",
                "production_untouched_on_canary_failure": True,
                "session_event_p95_ms": 400,
                "traffic_sample_age_seconds": 1,
                "observation_started_at": "2026-10-01T00:00:00Z",
                "observation_ended_at": "2026-10-01T00:30:00Z",
                "health_sample_count": 30,
                "max_sample_gap_seconds": 60,
                "health_failures": 0,
                "stale_sample_count": 0,
                "lost_event_count": 0,
                "duplicate_event_count": 0,
                "out_of_order_event_count": 0,
                "redis_delivery_failure_count": 0,
                "router_cpu_peak_percent": 20,
                "router_memory_peak_percent": 25,
                "router_storage_peak_percent": 30,
                "operator_secret": "must-not-appear-in-output",
            }
            for environment in ("canary", "production")
        ],
    }


class FakeTime:
    def __init__(self) -> None:
        self.current = datetime(2026, 10, 2, tzinfo=timezone.utc)
        self.elapsed = 0.0
        self.wall_clock_adjustment_seconds = 0.0
        self.jumped = False

    def clock(self) -> datetime:
        return self.current

    def sleep(self, seconds: float) -> None:
        self.elapsed += seconds
        jump = self.wall_clock_adjustment_seconds if not self.jumped else 0
        self.current += timedelta(seconds=seconds + jump)
        self.jumped = self.jumped or jump > 0

    def monotonic(self) -> float:
        return self.elapsed


class ReleaseCollectionTests(unittest.TestCase):
    def test_production_metrics_origin_is_optional_for_pre_promotion_cli(self) -> None:
        from scripts import collect_release_acceptance as collector

        output = StringIO()
        with patch.object(sys, "argv", ["collect_release_acceptance.py", "--help"]):
            with redirect_stdout(output), self.assertRaises(SystemExit) as raised:
                collector.main()

        self.assertEqual(raised.exception.code, 0)
        self.assertIn("[--production-metrics-url PRODUCTION_METRICS_URL]", output.getvalue())
        self.assertIn("--canary-api-token-env", output.getvalue())
        self.assertIn("--production-api-token-env", output.getvalue())

    def test_http_probe_sends_api_token_as_bearer_without_cookie(self) -> None:
        from scripts import collect_release_acceptance as collector

        token = "vpt_" + "c" * 48

        class Response:
            status = 200

            def __enter__(self) -> Response:
                return self

            def __exit__(self, *_: object) -> None:
                return None

            @staticmethod
            def read(_limit: int) -> bytes:
                return b"ok"

        opener = Mock()
        opener.open.return_value = Response()
        with patch.object(collector, "build_opener", return_value=opener):
            self.assertEqual(
                collector._get("https://canary.example/metrics", api_token=token, timeout=1),
                (200, b"ok"),
            )

        request = opener.open.call_args.args[0]
        self.assertEqual(request.get_header("Authorization"), f"Bearer {token}")
        self.assertIsNone(request.get_header("Cookie"))
        with self.assertRaisesRegex(ValueError, "either a session cookie or an API token"):
            collector._get(
                "https://canary.example/metrics",
                cookie="session=secret-cookie",
                api_token=token,
                timeout=1,
            )

    def test_registry_digest_uses_bounded_ghcr_token_and_manifest_head(self) -> None:
        from scripts import collect_release_acceptance as collector

        digest = "sha256:" + "b" * 64

        class FakeSocket:
            def __init__(self) -> None:
                self.timeouts: list[float] = []

            def settimeout(self, timeout: float) -> None:
                self.timeouts.append(timeout)

            def fileno(self) -> int:
                return 1

        class Response:
            def __init__(self, payload: bytes, *, status: int = 200, digest_header: str = "") -> None:
                self.payload = payload
                self.status = status
                self.headers = {"Docker-Content-Digest": digest_header} if digest_header else {}
                self.socket = FakeSocket()
                self.fp = type("FilePointer", (), {
                    "raw": type("RawSocket", (), {"_sock": self.socket})(),
                })()

            def __enter__(self) -> "Response":
                return self

            def __exit__(self, *args: object) -> None:
                del args

            def read1(self, limit: int) -> bytes:
                chunk = self.payload[:limit]
                self.payload = self.payload[len(chunk):]
                return chunk

            def close(self) -> None:
                return None

        token_response = Response(b'{"token":"short-lived-test-token"}')
        manifest_response = Response(b"", digest_header=digest)

        class Opener:
            def __init__(self) -> None:
                self.requests: list[object] = []

            def open(self, request: object, *, timeout: float) -> Response:
                self.requests.append(request)
                self.asserted_timeout = timeout
                return token_response if len(self.requests) == 1 else manifest_response

        opener = Opener()
        build_opener = Mock(return_value=opener)
        with patch.object(collector, "build_opener", build_opener):
            observed = collector._registry_digest_request(IMAGE, timeout=3)

        self.assertEqual(observed, digest)
        token_request, manifest_request = opener.requests
        self.assertEqual(token_request.get_method(), "GET")
        self.assertTrue(token_request.full_url.startswith("https://ghcr.io/token?scope=repository%3Aexample%2Fvpn%3Apull"))
        self.assertEqual(manifest_request.get_method(), "HEAD")
        self.assertEqual(manifest_request.full_url, f"https://ghcr.io/v2/example/vpn/manifests/sha-{REVISION}-arm64")
        self.assertEqual(manifest_request.get_header("Authorization"), "Bearer short-lived-test-token")
        self.assertTrue(any(isinstance(handler, collector._NoRedirect) for handler in build_opener.call_args.args))
        self.assertTrue(token_response.socket.timeouts)
        self.assertTrue(all(0 < timeout <= 3 for timeout in token_response.socket.timeouts))

    def test_registry_digest_parent_enforces_total_deadline(self) -> None:
        from scripts import collect_release_acceptance as collector

        timeout_error = collector.subprocess.TimeoutExpired("ghcr worker", 3.5)
        with patch.object(collector.subprocess, "run", side_effect=timeout_error) as run:
            self.assertIsNone(collector._registry_digest(IMAGE, timeout=3))

        self.assertEqual(run.call_args.kwargs["timeout"], 3.5)

    def test_registry_digest_does_not_follow_redirects(self) -> None:
        from scripts import collect_release_acceptance as collector

        class RedirectResponse:
            status = 302
            headers: dict[str, str] = {}

            def __enter__(self) -> "RedirectResponse":
                return self

            def __exit__(self, *args: object) -> None:
                del args

        class Opener:
            requests: list[object] = []

            def open(self, request: object, *, timeout: float) -> RedirectResponse:
                del timeout
                self.requests.append(request)
                return RedirectResponse()

        opener = Opener()
        build_opener = Mock(return_value=opener)
        with patch.object(collector, "build_opener", build_opener):
            self.assertIsNone(collector._registry_digest_request(IMAGE, timeout=3))
        self.assertEqual(len(opener.requests), 1)
        self.assertTrue(any(isinstance(handler, collector._NoRedirect) for handler in build_opener.call_args.args))

    def test_registry_response_body_stops_at_total_read_deadline(self) -> None:
        from scripts import collect_release_acceptance as collector

        class FakeSocket:
            def __init__(self) -> None:
                self.timeouts: list[float] = []

            def fileno(self) -> int:
                return 1

            def settimeout(self, timeout: float) -> None:
                self.timeouts.append(timeout)

        class Response:
            status = 200
            headers: dict[str, str] = {}

            def __init__(self) -> None:
                self.socket = FakeSocket()
                self.read_calls = 0
                self.fp = type("FilePointer", (), {
                    "raw": type("RawSocket", (), {"_sock": self.socket})(),
                })()

            def __enter__(self) -> "Response":
                return self

            def __exit__(self, *args: object) -> None:
                del args

            def read1(self, limit: int) -> bytes:
                del limit
                self.read_calls += 1
                return b"x"

        response = Response()

        class Opener:
            def open(self, request: object, *, timeout: float) -> Response:
                del request, timeout
                return response

        with (
            patch.object(collector, "build_opener", return_value=Opener()),
            patch.object(collector.time, "monotonic", side_effect=[0.0, 0.0, 0.5, 2.0]),
        ):
            result = collector._ghcr_request(
                "GET", "/token", timeout=1, max_body_bytes=32, headers={"Accept": "application/json"}
            )

        self.assertIsNone(result)
        self.assertEqual(response.read_calls, 1)
        self.assertEqual(response.socket.timeouts, [0.5])

    def test_metric_parser_ignores_unexpected_and_high_cardinality_labels(self) -> None:
        from scripts.collect_release_acceptance import _parse_metrics

        parsed = _parse_metrics(
            b'vpn_dashboard_telemetry_gateway_clients{user="private-user"} 99\n'
            b'vpn_dashboard_telemetry_gateway_events_total{outcome="published",event_id="private-id"} 99\n'
            b'vpn_dashboard_telemetry_gateway_events_total{outcome="published"} 4\n'
            b'vpn_dashboard_redis_publish_total{outcome="success",token="private-token"} 99\n'
            b'vpn_dashboard_redis_publish_total{outcome="success"} 7\n'
            b'vpn_dashboard_telemetry_supervisor_status{state="healthy",router="private-host"} 99\n'
            b'vpn_dashboard_telemetry_supervisor_status{state="healthy"} 1\n'
        )
        self.assertNotIn("vpn_dashboard_telemetry_gateway_clients", parsed)
        self.assertEqual(parsed["vpn_dashboard_telemetry_gateway_events_total_published"], 4)
        self.assertEqual(parsed["vpn_dashboard_redis_publish_total_success"], 7)
        self.assertEqual(parsed["vpn_dashboard_telemetry_supervisor_status_healthy"], 1)

    def run_collection(
        self,
        *,
        ready: bool = True,
        include_metrics: bool = True,
        include_production_metrics: bool = True,
        preclaim_redis: bool = False,
        traffic_sample_age: float = 0.75,
        gateway_delivery_p95: float = 0.5,
        gateway_delivery_observations: int = 8,
        supervisor_status: str = "healthy",
        supervisor_enabled: int = 1,
        outbox_pending: int = 0,
        outbox_pending_sequence: list[int] | None = None,
        outbox_dead_lettered: int = 0,
        outbox_oldest_age: float = 0,
        unknown_metric_sample: int | None = None,
        wall_clock_adjustment_seconds: float = 0,
        phase: str = "postpromotion",
        production_revision: str | None = None,
        production_observed_revision: str | None = None,
        registry_digests: dict[str, str | None] | None = None,
        clear_prior_production_runtime_evidence: bool = False,
        omit_prior_production_digest: bool = False,
        cookie: str | None = "session=secret-cookie",
        metrics_tokens: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, object], list[tuple[str, str | None, str | None]]]:
        time = FakeTime()
        time.wall_clock_adjustment_seconds = wall_clock_adjustment_seconds
        seen: list[tuple[str, str | None, str | None]] = []
        metrics_observations = 0
        metrics_observations_by_environment = {"canary": 0, "production": 0}
        source = evidence()
        if production_revision is not None:
            production = source["deployments"][1]
            production["image"] = f"ghcr.io/example/vpn:sha-{production_revision}-arm64"
            production["digest"] = "sha256:" + "c" * 64
        if phase == "canary-prepromotion":
            production = source["deployments"][1]
            production["transport"] = "socketio"
            if omit_prior_production_digest:
                production["digest"] = None
            if clear_prior_production_runtime_evidence:
                for field in (
                    "transport", "rest_fallback", "redis_configured", "redis_publish_verified",
                    "reconnect_recovered", "snapshot_recovered", "sqlite_restore_verified",
                    "session_event_p95_ms", "traffic_sample_age_seconds", "stale_sample_count",
                    "lost_event_count", "duplicate_event_count", "out_of_order_event_count",
                    "redis_delivery_failure_count", "router_cpu_peak_percent",
                    "router_memory_peak_percent", "router_storage_peak_percent",
                    "rollback_drill_passed", "production_untouched_on_canary_failure",
                ):
                    production.pop(field, None)
        resolved_registry_digests = registry_digests or {
            source["deployments"][0]["image"]: source["deployments"][0]["digest"],
            source["deployments"][1]["image"]: source["deployments"][1]["digest"],
        }
        if preclaim_redis:
            for deployment in source["deployments"]:
                deployment["redis_publish_verified"] = True

        def probe(
            url: str,
            *,
            timeout: float,
            cookie: str | None = None,
            api_token: str | None = None,
        ) -> tuple[int, bytes]:
            del timeout
            seen.append((url, cookie, api_token))
            if url.endswith("/healthz"):
                return (200 if ready else 503), b'{"status":"ok"}'
            if url.endswith("/readyz"):
                expected_revision = (
                    production_revision
                    if "private.example" in url and production_revision is not None
                    else REVISION
                )
                if "private.example" in url and production_observed_revision is not None:
                    expected_revision = production_observed_revision
                payload = {"status": "ready", "revision": expected_revision if ready else "f" * 40}
                return 200, json.dumps(payload).encode()
            nonlocal metrics_observations
            metrics_observations += 1
            environment = "production" if "private.example" in url else "canary"
            metrics_observations_by_environment[environment] += 1
            sample_is_unknown = metrics_observations == unknown_metric_sample
            pending_value = outbox_pending
            if outbox_pending_sequence:
                pending_index = min(
                    metrics_observations_by_environment[environment] - 1,
                    len(outbox_pending_sequence) - 1,
                )
                pending_value = outbox_pending_sequence[pending_index]
            now = time.clock().timestamp()
            payload = (
                "vpn_dashboard_redis_configured 1\n"
                "vpn_dashboard_redis_last_observed_available 1\n"
                "vpn_dashboard_redis_publish_total{outcome=\"success\"} 7\n"
                "vpn_dashboard_redis_publish_total{outcome=\"failure\"} 0\n"
                f"vpn_dashboard_redis_last_publish_success_timestamp_seconds {now}\n"
                f"vpn_dashboard_integration_outbox_pending {-1 if sample_is_unknown else pending_value}\n"
                f"vpn_dashboard_integration_outbox_dead_lettered {-1 if sample_is_unknown else outbox_dead_lettered}\n"
                f"vpn_dashboard_integration_outbox_oldest_age_seconds {-1 if sample_is_unknown else outbox_oldest_age}\n"
                f"vpn_dashboard_telemetry_session_event_age_seconds {-1 if sample_is_unknown else 0.25}\n"
                f"vpn_dashboard_telemetry_session_event_timestamp_seconds {-1 if sample_is_unknown else now - 0.25}\n"
                "vpn_dashboard_telemetry_session_events_total 4\n"
                f"vpn_dashboard_telemetry_traffic_sample_age_seconds {-1 if sample_is_unknown else traffic_sample_age}\n"
                f"vpn_dashboard_telemetry_traffic_sample_timestamp_seconds {-1 if sample_is_unknown else now - traffic_sample_age}\n"
                "vpn_dashboard_telemetry_traffic_samples_total 12\n"
                "vpn_dashboard_telemetry_gateway_clients 1\n"
                "vpn_dashboard_telemetry_gateway_buffered_events 2\n"
                "vpn_dashboard_telemetry_gateway_events_total{outcome=\"published\"} 15\n"
                "vpn_dashboard_telemetry_gateway_events_total{outcome=\"replayed\"} 3\n"
                "vpn_dashboard_telemetry_gateway_events_total{outcome=\"snapshot_recovery\"} 1\n"
                "vpn_dashboard_telemetry_gateway_rejected_clients_total 0\n"
                "vpn_dashboard_telemetry_gateway_delivery_queue_age_seconds 0.2\n"
                f"vpn_dashboard_telemetry_gateway_delivery_queue_age_p95_seconds {-1 if sample_is_unknown else gateway_delivery_p95}\n"
                f"vpn_dashboard_telemetry_gateway_delivery_observations {gateway_delivery_observations}\n"
                f"vpn_dashboard_telemetry_supervisor_enabled {supervisor_enabled}\n"
                f"vpn_dashboard_telemetry_supervisor_status{{state=\"healthy\"}} {int(supervisor_status == 'healthy')}\n"
                f"vpn_dashboard_telemetry_supervisor_status{{state=\"disabled\"}} {int(supervisor_status == 'disabled')}\n"
                f"vpn_dashboard_telemetry_supervisor_status{{state=\"connecting\"}} {int(supervisor_status == 'connecting')}\n"
                f"vpn_dashboard_telemetry_supervisor_status{{state=\"degraded\"}} {int(supervisor_status == 'degraded')}\n"
                f"vpn_dashboard_telemetry_supervisor_status{{state=\"stopped\"}} {int(supervisor_status == 'stopped')}\n"
                f"vpn_dashboard_telemetry_supervisor_status{{state=\"unknown\"}} {int(supervisor_status == 'unknown')}\n"
                "vpn_dashboard_telemetry_supervisor_attempts_total 3\n"
                "vpn_dashboard_telemetry_supervisor_reconnects_total 2\n"
                "vpn_dashboard_telemetry_supervisor_failures_total 1\n"
                "vpn_dashboard_telemetry_supervisor_events_total 20\n"
                f"vpn_dashboard_telemetry_supervisor_last_connected_timestamp_seconds {now - 1}\n"
                f"vpn_dashboard_telemetry_supervisor_last_event_timestamp_seconds {now - 0.25}\n"
                f"vpn_dashboard_telemetry_supervisor_last_snapshot_timestamp_seconds {now - 2}\n"
                "vpn_dashboard_telemetry_supervisor_backoff_seconds 1\n"
                "vpn_dashboard_info{revision=\"private-label\"} 1\n"
            )
            return 200, payload.encode()

        code, report = collect(
            source,
            readyz_urls={"canary": "https://192.168.1.2", "production": "https://private.example"},
            metrics_urls=(
                {
                    **{"canary": "https://192.168.1.2"},
                    **({"production": "https://private.example"} if include_production_metrics else {}),
                }
                if include_metrics else None
            ),
            cookie=cookie,
            metrics_tokens=metrics_tokens,
            duration_seconds=1,
            interval_seconds=0.5,
            probe=probe,
            registry_probe=lambda image, *, timeout: resolved_registry_digests.get(image),
            clock=time.clock,
            sleep=time.sleep,
            monotonic=time.monotonic,
            minimum_soak_seconds=1,
            minimum_health_samples=2,
            phase=phase,
        )
        return code, report, seen

    def test_collects_health_window_and_authenticated_aggregate_metrics(self) -> None:
        code, report, seen = self.run_collection()
        self.assertEqual(code, 0)
        collected = report["evidence"]
        self.assertEqual(collected["collection"]["format"], "vpn-dashboard-release-collection-v1")
        self.assertEqual(collected["collection"]["phase"], "postpromotion")
        self.assertEqual(
            [entry["verified"] for entry in collected["collection"]["registry_digest_verification"]],
            [True, True],
        )
        self.assertEqual(len(collected["deployments"]), 2)
        self.assertGreaterEqual(collected["deployments"][0]["health_sample_count"], 2)
        self.assertEqual(report["deployments"][0]["metrics_sample_count"], 3)
        self.assertTrue(collected["deployments"][0]["redis_publish_verified"])
        self.assertEqual(report["deployments"][0]["metrics"]["outbox_pending_last"], 0)
        self.assertEqual(report["deployments"][0]["metrics"]["outbox_pending_max"], 0)
        self.assertEqual(report["deployments"][0]["metrics"]["outbox_dead_lettered_last"], 0)
        telemetry = report["deployments"][0]["metrics"]["telemetry_process_observation_age"]
        self.assertEqual(telemetry["session_event"]["max_seconds"], 0.25)
        self.assertEqual(telemetry["traffic_sample"]["max_seconds"], 0.75)
        self.assertIn("not RouterOS-to-browser delivery latency", telemetry["meaning"])
        gateway = report["deployments"][0]["metrics"]["telemetry_gateway"]
        self.assertEqual(gateway["authorized_clients_last"], 1)
        self.assertEqual(gateway["snapshot_recoveries"]["delta"], 0)
        self.assertEqual(gateway["delivery_queue_age_p95_seconds"]["max"], 0.5)
        self.assertIn("excludes RouterOS observation and browser rendering", gateway["meaning"])
        telemetry_slo = report["deployments"][0]["metrics"]["telemetry_slo"]
        self.assertEqual(telemetry_slo["traffic_sample_max_age_seconds"], 0.75)
        self.assertEqual(telemetry_slo["gateway_delivery_p95_max_seconds"], 0.5)
        self.assertEqual(telemetry_slo["supervisor_non_healthy_samples"], 0)
        self.assertIn("does not measure RouterOS-to-browser session-change latency", telemetry_slo["meaning"])
        supervisor = report["deployments"][0]["metrics"]["telemetry_supervisor"]
        self.assertEqual(supervisor["status_last"], "healthy")
        self.assertEqual(supervisor["reconnects"]["delta"], 0)
        self.assertEqual(supervisor["failures"]["delta"], 0)
        self.assertGreater(supervisor["last_snapshot_timestamp_seconds"], 0)
        self.assertTrue(all(
            cookie == ("session=secret-cookie" if url.endswith("/metrics") else None)
            for url, cookie, _ in seen
        ))
        self.assertTrue(all(api_token is None for _, _, api_token in seen))
        serialized = json.dumps(report)
        self.assertNotIn("must-not-appear-in-output", serialized)
        self.assertNotIn("private-label", serialized)
        self.assertNotIn("session=secret-cookie", serialized)
        self.assertNotIn("192.168.1.2", serialized)

    def test_per_environment_api_tokens_are_sent_only_to_their_metrics_origin(self) -> None:
        code, report, seen = self.run_collection(
            cookie=None,
            metrics_tokens={
                "canary": "vpt_" + "c" * 48,
                "production": "vpt_" + "p" * 48,
            },
        )

        self.assertEqual(code, 0)
        self.assertTrue(all(cookie is None for _, cookie, _ in seen))
        self.assertTrue(all(
            api_token == (
                "vpt_" + "c" * 48 if "192.168.1.2" in url and url.endswith("/metrics")
                else "vpt_" + "p" * 48 if "private.example" in url and url.endswith("/metrics")
                else None
            )
            for url, _, api_token in seen
        ))
        serialized = json.dumps(report)
        self.assertNotIn("vpt_" + "c" * 48, serialized)
        self.assertNotIn("vpt_" + "p" * 48, serialized)

    def test_pre_promotion_does_not_use_or_require_production_metrics_token(self) -> None:
        code, report, seen = self.run_collection(
            phase="canary-prepromotion",
            production_revision="c" * 40,
            cookie=None,
            metrics_tokens={"canary": "vpt_" + "c" * 48, "production": "vpt_" + "p" * 48},
        )

        self.assertEqual(code, 0)
        self.assertTrue(report["passed"])
        self.assertTrue(all(
            api_token == ("vpt_" + "c" * 48 if url.endswith("/metrics") and "192.168.1.2" in url else None)
            for url, _, api_token in seen
        ))
        self.assertNotIn("vpt_" + "p" * 48, json.dumps(report))

    def test_measured_telemetry_slo_violations_fail_closed(self) -> None:
        code, report, _ = self.run_collection(
            traffic_sample_age=2.1,
            gateway_delivery_p95=1.1,
            supervisor_status="degraded",
        )
        self.assertEqual(code, 1)
        self.assertIn("canary_traffic_sample_stale", report["failed_gates"])
        self.assertIn("production_traffic_sample_stale", report["failed_gates"])
        self.assertIn("canary_gateway_delivery_latency_exceeded", report["failed_gates"])
        self.assertIn("production_gateway_delivery_latency_exceeded", report["failed_gates"])
        self.assertIn("canary_telemetry_supervisor_not_healthy", report["failed_gates"])
        self.assertIn("production_telemetry_supervisor_not_healthy", report["failed_gates"])

    def test_unobserved_telemetry_slo_fails_closed(self) -> None:
        code, report, _ = self.run_collection(
            traffic_sample_age=-1,
            gateway_delivery_p95=-1,
            gateway_delivery_observations=0,
        )
        self.assertEqual(code, 1)
        self.assertIn("canary_traffic_freshness_unobserved", report["failed_gates"])
        self.assertIn("production_traffic_freshness_unobserved", report["failed_gates"])
        self.assertIn("canary_gateway_delivery_latency_unobserved", report["failed_gates"])
        self.assertIn("production_gateway_delivery_latency_unobserved", report["failed_gates"])

        from scripts.collect_release_acceptance import _metric_window

        summary = _metric_window([{"metrics": {
            "vpn_dashboard_telemetry_traffic_sample_age_seconds": -1,
            "vpn_dashboard_telemetry_traffic_sample_timestamp_seconds": -1,
            "vpn_dashboard_telemetry_gateway_delivery_queue_age_p95_seconds": -1,
            "vpn_dashboard_telemetry_gateway_delivery_observations": 0,
            "vpn_dashboard_telemetry_supervisor_enabled": 0,
            "vpn_dashboard_telemetry_supervisor_status_healthy": 0,
        }}], 0, 1)

        telemetry_slo = summary["telemetry_slo"]
        self.assertIsNone(telemetry_slo["traffic_sample_max_age_seconds"])
        self.assertIsNone(telemetry_slo["gateway_delivery_p95_max_seconds"])
        self.assertEqual(telemetry_slo["supervisor_non_healthy_samples"], 1)

    def test_mixed_unknown_slo_sample_fails_even_when_other_samples_are_fresh(self) -> None:
        code, report, _ = self.run_collection(unknown_metric_sample=2)
        self.assertEqual(code, 1)
        self.assertIn("production_session_event_freshness_incomplete", report["failed_gates"])
        self.assertIn("production_traffic_freshness_incomplete", report["failed_gates"])
        self.assertIn("production_gateway_delivery_latency_incomplete", report["failed_gates"])
        production = next(item for item in report["deployments"] if item["environment"] == "production")
        self.assertGreater(production["metrics"]["telemetry_process_observation_age"]["traffic_sample"]["max_seconds"], 0)
        self.assertGreater(production["metrics"]["telemetry_process_observation_age"]["traffic_sample"]["unknown_samples"], 0)

    def test_pending_or_dead_lettered_outbox_fails_acceptance(self) -> None:
        code, report, _ = self.run_collection(
            outbox_pending=2,
            outbox_dead_lettered=1,
            outbox_oldest_age=45,
        )
        self.assertEqual(code, 1)
        for environment in ("canary", "production"):
            self.assertIn(f"{environment}_outbox_pending_during_window", report["failed_gates"])
            self.assertIn(f"{environment}_outbox_dead_letters_present", report["failed_gates"])

    def test_transient_outbox_backlog_fails_even_if_drained_by_window_end(self) -> None:
        code, report, _ = self.run_collection(outbox_pending_sequence=[0, 2, 0])
        self.assertEqual(code, 1)
        for environment in ("canary", "production"):
            self.assertIn(f"{environment}_outbox_pending_during_window", report["failed_gates"])
        for deployment in report["deployments"]:
            self.assertEqual(deployment["metrics"]["outbox_pending_last"], 0)
            self.assertEqual(deployment["metrics"]["outbox_pending_max"], 2)

    def test_unknown_outbox_sample_fails_even_when_final_sample_is_known(self) -> None:
        code, report, _ = self.run_collection(unknown_metric_sample=2)
        self.assertEqual(code, 1)
        self.assertIn("production_outbox_pending_count_unobserved", report["failed_gates"])
        self.assertIn("production_outbox_dead_letter_count_unobserved", report["failed_gates"])
        self.assertIn("production_outbox_age_unobserved", report["failed_gates"])

    def test_missing_metrics_fail_closed_and_clear_supplied_redis_claims(self) -> None:
        code, report, _ = self.run_collection(include_metrics=False, preclaim_redis=True)
        self.assertEqual(code, 1)
        self.assertIn("canary_metrics_samples_insufficient", report["failed_gates"])
        self.assertIn("production_metrics_samples_insufficient", report["failed_gates"])
        for deployment in report["evidence"]["deployments"]:
            self.assertFalse(deployment["redis_configured"])
            self.assertFalse(deployment["redis_publish_verified"])
        for deployment in report["deployments"]:
            self.assertEqual(deployment["metrics_sample_count"], 0)

    def test_unknown_telemetry_age_is_not_reported_as_fresh(self) -> None:
        from scripts.collect_release_acceptance import _metric_window

        metrics = {
            "vpn_dashboard_health": 1,
            "vpn_dashboard_telemetry_session_event_age_seconds": -1,
            "vpn_dashboard_telemetry_session_event_timestamp_seconds": -1,
            "vpn_dashboard_telemetry_traffic_sample_age_seconds": -1,
            "vpn_dashboard_telemetry_traffic_sample_timestamp_seconds": -1,
        }
        summary = _metric_window([{"metrics": metrics}], 0, 1)
        telemetry = summary["telemetry_process_observation_age"]
        self.assertIsNone(telemetry["session_event"]["max_seconds"])
        self.assertEqual(telemetry["session_event"]["unknown_samples"], 1)
        self.assertIsNone(telemetry["traffic_sample"]["max_seconds"])
        self.assertEqual(telemetry["traffic_sample"]["unknown_samples"], 1)

    def test_gateway_metrics_report_counter_deltas_and_unknown_queue_age(self) -> None:
        from scripts.collect_release_acceptance import _metric_window

        first = {
            "vpn_dashboard_telemetry_gateway_events_total_published": 10,
            "vpn_dashboard_telemetry_gateway_events_total_replayed": 3,
            "vpn_dashboard_telemetry_gateway_events_total_snapshot_recovery": 1,
            "vpn_dashboard_telemetry_gateway_rejected_clients_total": 2,
            "vpn_dashboard_telemetry_gateway_delivery_queue_age_seconds": -1,
            "vpn_dashboard_telemetry_gateway_delivery_queue_age_p95_seconds": -1,
            "vpn_dashboard_telemetry_gateway_delivery_observations": 0,
        }
        last = {
            "vpn_dashboard_telemetry_gateway_events_total_published": 14,
            "vpn_dashboard_telemetry_gateway_events_total_replayed": 5,
            "vpn_dashboard_telemetry_gateway_events_total_snapshot_recovery": 2,
            "vpn_dashboard_telemetry_gateway_rejected_clients_total": 2,
            "vpn_dashboard_telemetry_gateway_delivery_queue_age_seconds": 0.25,
            "vpn_dashboard_telemetry_gateway_delivery_queue_age_p95_seconds": 0.75,
            "vpn_dashboard_telemetry_gateway_delivery_observations": 4,
        }

        summary = _metric_window([{"metrics": first}, {"metrics": last}], 0, 1)
        gateway = summary["telemetry_gateway"]
        self.assertEqual(gateway["published_events"], {"delta": 4, "counter_reset": False})
        self.assertEqual(gateway["replayed_events"]["delta"], 2)
        self.assertEqual(gateway["snapshot_recoveries"]["delta"], 1)
        self.assertEqual(gateway["rejected_clients"]["delta"], 0)
        self.assertEqual(gateway["delivery_observations_last"], 4)
        self.assertEqual(gateway["delivery_queue_age_p95_seconds"]["max"], 0.75)
        self.assertEqual(gateway["delivery_queue_age_p95_seconds"]["unknown_samples"], 1)

    def test_gateway_counter_reset_is_reported_not_wrapped_as_large_delta(self) -> None:
        from scripts.collect_release_acceptance import _metric_window

        first = {"vpn_dashboard_telemetry_gateway_events_total_published": 100}
        last = {"vpn_dashboard_telemetry_gateway_events_total_published": 3}
        summary = _metric_window([{"metrics": first}, {"metrics": last}], 0, 1)
        self.assertEqual(
            summary["telemetry_gateway"]["published_events"],
            {"delta": 3, "counter_reset": True},
        )

    def test_mid_window_counter_reset_preserves_post_reset_delta(self) -> None:
        from scripts.collect_release_acceptance import _metric_window

        samples = [
            {"metrics": {
                "vpn_dashboard_telemetry_gateway_events_total_published": 10,
                "vpn_dashboard_redis_publish_total_failure": 5,
            }},
            {"metrics": {
                "vpn_dashboard_telemetry_gateway_events_total_published": 2,
                "vpn_dashboard_redis_publish_total_failure": 1,
            }},
            {"metrics": {
                "vpn_dashboard_telemetry_gateway_events_total_published": 8,
                "vpn_dashboard_redis_publish_total_failure": 4,
            }},
        ]
        summary = _metric_window(samples, 0, 1)
        self.assertEqual(
            summary["telemetry_gateway"]["published_events"],
            {"delta": 8, "counter_reset": True},
        )
        self.assertEqual(summary["redis_publish_failure_delta"], 4)
        self.assertTrue(summary["redis_publish_failure_counter_reset"])

    def test_readiness_or_revision_mismatch_fails_closed(self) -> None:
        code, report, _ = self.run_collection(ready=False)
        self.assertEqual(code, 1)
        deployment = report["evidence"]["deployments"][0]
        self.assertFalse(deployment["container_healthy"])
        self.assertFalse(deployment["app_ready"])
        self.assertGreater(deployment["health_failures"], 0)

    def test_pre_promotion_soak_accepts_candidate_with_old_healthy_production(self) -> None:
        code, report, _ = self.run_collection(
            phase="canary-prepromotion",
            production_revision="c" * 40,
        )

        self.assertEqual(code, 0)
        self.assertTrue(report["passed"])
        self.assertEqual(report["evidence"]["collection"]["phase"], "canary-prepromotion")
        production = report["evidence"]["deployments"][1]
        self.assertEqual(production["image"], f"ghcr.io/example/vpn:sha-{'c' * 40}-arm64")
        self.assertTrue(production["app_ready"])

    def test_pre_promotion_candidate_does_not_require_old_production_metrics(self) -> None:
        for include_production_metrics in (False, True):
            with self.subTest(include_production_metrics=include_production_metrics):
                code, report, seen = self.run_collection(
                    phase="canary-prepromotion",
                    production_revision="c" * 40,
                    include_production_metrics=include_production_metrics,
                    clear_prior_production_runtime_evidence=True,
                    omit_prior_production_digest=True,
                )

                self.assertEqual(code, 0)
                self.assertEqual(report["evidence"]["deployments"][1]["redis_publish_verified"], False)
                self.assertIsNone(report["evidence"]["deployments"][1]["digest"])
                self.assertEqual(report["deployments"][1]["metrics_sample_count"], 0)
                self.assertFalse(any(url == "https://private.example/metrics" for url, _, _ in seen))
                self.assertEqual(
                    report["evidence"]["collection"]["registry_digest_verification_scope"],
                    "candidate-canary-only",
                )
                self.assertEqual(
                    [item["environment"] for item in report["evidence"]["collection"]["registry_digest_verification"]],
                    ["canary"],
                )
                from scripts.release_acceptance import evaluate

                collected_evidence = report["evidence"]
                started = "2026-10-02T10:25:00+00:00"
                ended = "2026-10-02T10:55:00+00:00"
                collected_evidence["collection"].update({
                    "started_at": started,
                    "ended_at": ended,
                    "duration_seconds": 1800,
                })
                for deployment in collected_evidence["deployments"]:
                    deployment.update({
                        "observation_started_at": started,
                        "observation_ended_at": ended,
                        "health_sample_count": 30,
                        "max_sample_gap_seconds": 60,
                    })
                accepted, final_report = evaluate(
                    collected_evidence,
                    now=datetime(2026, 10, 2, 11, tzinfo=timezone.utc),
                )
                self.assertEqual(accepted, 0, final_report["failed_gates"])
                self.assertFalse(final_report["production_accepted"])
                self.assertIsNone(final_report["deployments"][1]["digest"])
                self.assertIsNone(final_report["deployments"][1]["transport"])

    def test_pre_promotion_soak_fails_if_production_revision_changes(self) -> None:
        code, report, _ = self.run_collection(
            phase="canary-prepromotion",
            production_revision="c" * 40,
            production_observed_revision="d" * 40,
        )

        self.assertEqual(code, 1)
        self.assertIn("production_health_or_revision_failure", report["failed_gates"])

    def test_registry_digest_mismatch_or_unavailability_fails_closed(self) -> None:
        mismatch, mismatch_report, _ = self.run_collection(
            registry_digests={IMAGE: "sha256:" + "c" * 64},
        )
        self.assertEqual(mismatch, 1)
        self.assertIn("canary_registry_digest_mismatch", mismatch_report["failed_gates"])
        self.assertIn("production_registry_digest_mismatch", mismatch_report["failed_gates"])

        unavailable, unavailable_report, _ = self.run_collection(
            registry_digests={IMAGE: None},
        )
        self.assertEqual(unavailable, 1)
        self.assertIn("canary_registry_digest_unavailable", unavailable_report["failed_gates"])

    def test_wall_clock_jump_cannot_shorten_or_falsely_pass_soak(self) -> None:
        for adjustment in (10, -10):
            with self.subTest(adjustment=adjustment):
                code, report, _ = self.run_collection(wall_clock_adjustment_seconds=adjustment)
                self.assertEqual(code, 1)
                self.assertIn("collection_clock_anomaly", report["failed_gates"])
                self.assertIn("canary_sample_clock_anomaly", report["failed_gates"])
                self.assertGreaterEqual(report["evidence"]["collection"]["duration_seconds"], 0)

    def test_rejects_publicly_embedded_credentials_in_probe_url(self) -> None:
        source = evidence()
        with self.assertRaisesRegex(ValueError, "credentials"):
            collect(
                source,
                readyz_urls={"canary": "https://user:pass@example.test", "production": "https://example.test"},
                duration_seconds=1,
                minimum_soak_seconds=1,
            )

    def test_rejects_invalid_duration_before_probing(self) -> None:
        with self.assertRaisesRegex(ValueError, "duration"):
            collect(
                evidence(),
                readyz_urls={"canary": "http://192.168.1.2", "production": "http://192.168.1.3"},
                duration_seconds=86_401,
            )

    def test_rejects_soak_shorter_than_acceptance_minimum(self) -> None:
        with self.assertRaisesRegex(ValueError, "shorter than the required"):
            collect(
                evidence(),
                readyz_urls={"canary": "http://192.168.1.2", "production": "http://192.168.1.3"},
                duration_seconds=1799,
            )

    def test_authenticated_metrics_cannot_send_credentials_over_http(self) -> None:
        with self.assertRaisesRegex(ValueError, "require HTTPS"):
            collect(
                evidence(),
                readyz_urls={"canary": "http://192.168.1.2", "production": "https://private.example"},
                metrics_urls={"canary": "http://192.168.1.2"},
                metrics_tokens={"canary": "vpt_" + "c" * 48},
                duration_seconds=1,
                minimum_soak_seconds=1,
            )

    def test_rejects_cross_host_metrics_origin_before_sending_token(self) -> None:
        with self.assertRaisesRegex(ValueError, "origin must exactly match"):
            collect(
                evidence(),
                readyz_urls={"canary": "https://canary.example", "production": "https://production.example"},
                metrics_urls={"canary": "https://attacker.example"},
                metrics_tokens={"canary": "vpt_" + "c" * 48},
                duration_seconds=1,
                minimum_soak_seconds=1,
            )

    def test_rejects_arbitrary_enum_and_typed_evidence_values(self) -> None:
        invalid_enum = evidence()
        invalid_enum["deployments"][0]["transport"] = "secret-string-that-is-not-an-enum"
        with self.assertRaisesRegex(ValueError, "transport"):
            collect(
                invalid_enum,
                readyz_urls={"canary": "https://canary.example", "production": "https://production.example"},
                duration_seconds=1,
                minimum_soak_seconds=1,
            )

        invalid_type = evidence()
        invalid_type["deployments"][0]["session_event_p95_ms"] = "sensitive-string"
        with self.assertRaisesRegex(ValueError, "session_event_p95_ms"):
            collect(
                invalid_type,
                readyz_urls={"canary": "https://canary.example", "production": "https://production.example"},
                duration_seconds=1,
                minimum_soak_seconds=1,
            )


if __name__ == "__main__":
    unittest.main()
