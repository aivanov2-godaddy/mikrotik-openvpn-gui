from __future__ import annotations

from datetime import datetime, timedelta, timezone
from contextlib import redirect_stdout
from io import StringIO
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

from scripts.collect_release_acceptance import (
    _read_certificate_lifecycle_report,
    apply_stream_acceptance,
    collect,
    finalize_release_acceptance,
)
from scripts.sqlite_restore_verifier import verify_sqlite_restore
from scripts.stream_acceptance import CANARY_ORIGIN, VERIFICATION_FIELDS
from scripts.redis_recovery_acceptance import (
    REPORT_FORMAT as REDIS_RECOVERY_FORMAT,
    REQUIRED_TEST_NAMES,
    report_projection_sha256,
    validate_report as validate_redis_report,
)
from scripts.rollback_acceptance import REPORT_FORMAT as ROLLBACK_REPORT_FORMAT
from store import MetadataStore


REVISION = "a" * 40
DIGEST = "sha256:" + "b" * 64
PRIOR_DIGEST = "sha256:" + "c" * 64
TAG_IMAGE = f"ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-{REVISION}-arm64"
IMAGE = f"{TAG_IMAGE}@{DIGEST}"


def image_ref(revision: str, digest: str = DIGEST) -> str:
    return f"ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-{revision}-arm64@{digest}"


def redis_recovery_report(revision: str = REVISION) -> dict[str, object]:
    return {
        "format": REDIS_RECOVERY_FORMAT,
        "source_revision": revision,
        "started_at": "2026-10-01T23:50:00Z",
        "ended_at": "2026-10-01T23:51:00Z",
        "test_results": {name: "passed" for name in REQUIRED_TEST_NAMES},
        "scope": "source-integration-tests",
        "runtime_image_digest_verified": False,
    }


def redis_ci_provenance(revision: str = REVISION) -> dict[str, object]:
    report = redis_recovery_report(revision)
    safe, failures = validate_redis_report(
        report,
        expected_revision=revision,
        now=datetime(2026, 10, 2, 10, tzinfo=timezone.utc),
    )
    if failures or safe is None:
        raise AssertionError("test Redis recovery fixture is invalid")
    return {
        "repository": "aivanov2-godaddy/mikrotik-openvpn-gui",
        "workflow_path": ".github/workflows/ci.yml",
        "event": "push",
        "branch": "main",
        "status": "completed",
        "conclusion": "success",
        "head_sha": revision,
        "run_id": "123456789",
        "artifact_id": "987654321",
        "artifact_name": f"redis-recovery-{revision}",
        "attestation_verified_during_collection": True,
        "report_sha256": report_projection_sha256(safe),
    }


def rollback_report_for(
    candidate_image: str,
    candidate_digest: str,
    production_image: str,
    started_at: datetime,
) -> dict[str, object]:
    start = started_at.astimezone(timezone.utc)
    prior_image = image_ref("c" * 40, PRIOR_DIGEST)

    def readback(environment: str, image: str, offset_seconds: int) -> dict[str, object]:
        observed = (start + timedelta(seconds=offset_seconds)).isoformat()
        canary_revision = image.split(":sha-", 1)[1].split("-arm64", 1)[0] if environment == "canary" else prior_image.split(":sha-", 1)[1].split("-arm64", 1)[0]
        production_revision = production_image.split(":sha-", 1)[1].split("-arm64", 1)[0]
        source = {
            "collector": "authenticated-routeros-api-rest-readyz-v1",
            "captured_at": observed,
            "api_authenticated": True,
            "rest_authenticated": True,
            "rest_parity_verified": True,
            "canary_revision": canary_revision,
            "production_revision": production_revision,
            "canary_ready_revision": canary_revision,
            "production_ready_revision": production_revision,
            "canary_healthy": True,
            "production_healthy": True,
            "canary_ready": True,
            "production_ready": True,
        }
        return {
            "environment": environment,
            "observed_at": observed,
            "image": image,
            "healthy": True,
            "ready": True,
            "source": source,
        }

    return {
        "format": ROLLBACK_REPORT_FORMAT,
        "candidate_image": candidate_image,
        "candidate_digest": candidate_digest,
        "production_before": readback("production", production_image, -600),
        "canary_before": readback("canary", prior_image, -590),
        "canary_candidate": readback("canary", candidate_image, -580),
        "canary_after_rollback": readback("canary", prior_image, -570),
        "production_after": readback("production", production_image, -560),
        "canary_candidate_restored": readback("canary", candidate_image, -550),
    }


def certificate_lifecycle_evidence() -> dict[str, object]:
    return {
        "format": "vpn-dashboard-certificate-lifecycle-acceptance-v1",
        "environment": "canary",
        "candidate_image": IMAGE,
        "candidate_digest": "sha256:" + "b" * 64,
        "replacement_tested_before_retirement": True,
        "replacement_tested_at": "2026-10-01T23:40:00Z",
        "failed_renewal_rollback_read_back_verified": True,
        "failed_renewal_rollback_read_back_at": "2026-10-01T23:41:00Z",
        "routeros_revocation_read_back_verified": True,
        "routeros_revocation_read_back_at": "2026-10-01T23:42:00Z",
        "crl_fresh_and_loaded_verified": True,
        "crl_fresh_loaded_at": "2026-10-01T23:43:00Z",
        "existing_session_read_back_verified": True,
        "existing_session_outcome": "terminated",
        "existing_session_read_back_at": "2026-10-01T23:44:00Z",
        "fresh_connection_rejection_verified": True,
        "fresh_connection_rejection_at": "2026-10-01T23:45:00Z",
        "dashboard_status_distinctions_verified": True,
        "dashboard_status_distinctions_verified_at": "2026-10-01T23:46:00Z",
        "private_material_or_profile_contents_in_evidence": False,
        "raw_logs_in_evidence": False,
    }


def evidence() -> dict[str, object]:
    return {
        "format": "vpn-dashboard-release-evidence-v2",
        "certificate_lifecycle_acceptance": certificate_lifecycle_evidence(),
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
                "reconnect_recovery_counter_delta": 1,
                "reconnect_recovery_counter_reset": False,
                "snapshot_recovery_counter_delta": 1,
                "snapshot_recovery_counter_reset": False,
                "reconnect_observed_at": 1790935500,
                "full_snapshot_recovered_at": 1790935800,
                "sqlite_restore_verified": True,
                "sqlite_restore_verified_at": "2026-10-02T10:24:00Z",
                "rollback_drill_passed": environment == "canary",
                "rollback_drill_at": "2026-10-02T10:26:00Z",
                "production_untouched_on_canary_failure": True,
                "production_protection_observed_at": "2026-10-02T10:27:00Z",
                "session_event_p95_ms": 400,
                "session_event_latency_started_at": "2026-10-02T10:10:00Z",
                "session_event_latency_ended_at": "2026-10-02T10:20:00Z",
                "session_event_max_age_seconds": 0.5,
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
    def test_final_gate_catches_failed_rollback_even_when_collection_passed(self) -> None:
        code, summary, _seen = self.run_collection()
        self.assertEqual(code, 0)
        self.assertTrue(summary["passed"])
        summary["evidence"]["collection"]["rollback_rehearsal"][
            "canary_after_rollback"
        ]["healthy"] = False
        collection_end = datetime.fromisoformat(
            summary["evidence"]["collection"]["ended_at"].replace("Z", "+00:00")
        )

        code, summary = finalize_release_acceptance(
            summary, phase="postpromotion", now=collection_end + timedelta(seconds=1)
        )

        self.assertEqual(code, 1)
        self.assertFalse(summary["passed"])
        self.assertIn("canary_rollback_drill_failed", summary["failed_gates"])
        self.assertFalse(summary["release_acceptance"]["passed"])

    def test_routeros_resource_evidence_joins_only_matching_healthy_revisions(self) -> None:
        from scripts.collect_release_acceptance import attach_routeros_resource_evidence

        revision = "a" * 40
        app_evidence = {
            "collection": {
                "started_at": "2026-10-01T00:00:00Z",
                "ended_at": "2026-10-01T00:30:00Z",
            },
            "deployments": [
                {"environment": environment, "image": image_ref(revision)}
                for environment in ("canary", "production")
            ],
        }
        routeros_report = {
            "format": "vpn-dashboard-routeros-acceptance-v3",
            "passed": True,
            "failed_gates": [],
            "credentials_or_raw_router_data_written": False,
            "observation_started_at": "2026-10-01T00:00:10Z",
            "observation_ended_at": "2026-10-01T00:30:10Z",
            "duration_seconds": 1800,
            "sample_count": 31,
            "successful_sample_count": 31,
            "failed_sample_count": 0,
            "rest_parity_successful_sample_count": 31,
            "rest_parity_failed_sample_count": 0,
            "active_vpn_sessions_min": 0,
            "active_vpn_sessions_max": 1,
            "read_only_rest_paths": ["/rest/system/resource", "/rest/container", "/rest/ppp/active"],
            "max_sample_gap_seconds": 60,
            "router_cpu_peak_percent": 24,
            "router_memory_peak_percent": 35,
            "router_storage_peak_percent": 18,
            "containers": {
                environment: {
                    "healthy_for_all_successful_samples": True,
                    "observed_source_revisions": [revision],
                }
                for environment in ("canary", "production")
            },
        }

        attach_routeros_resource_evidence(app_evidence, routeros_report)

        self.assertEqual(app_evidence["deployments"][0]["router_cpu_peak_percent"], 24.0)
        self.assertEqual(app_evidence["deployments"][1]["router_memory_peak_percent"], 35.0)
        self.assertTrue(app_evidence["collection"]["routeros_resource_evidence"]["container_revisions_matched"])

    def test_routeros_resource_evidence_rejects_window_or_revision_mismatch(self) -> None:
        from copy import deepcopy
        from scripts.collect_release_acceptance import attach_routeros_resource_evidence

        revision = "a" * 40
        app_evidence = {
            "collection": {
                "started_at": "2026-10-01T00:00:00Z",
                "ended_at": "2026-10-01T00:30:00Z",
            },
            "deployments": [
                {"environment": environment, "image": image_ref(revision)}
                for environment in ("canary", "production")
            ],
        }
        routeros_report = {
            "format": "vpn-dashboard-routeros-acceptance-v3",
            "passed": True,
            "failed_gates": [],
            "credentials_or_raw_router_data_written": False,
            "observation_started_at": "2026-10-01T00:00:00Z",
            "observation_ended_at": "2026-10-01T00:30:00Z",
            "duration_seconds": 1800,
            "sample_count": 30,
            "successful_sample_count": 30,
            "failed_sample_count": 0,
            "rest_parity_successful_sample_count": 30,
            "rest_parity_failed_sample_count": 0,
            "active_vpn_sessions_min": 0,
            "active_vpn_sessions_max": 1,
            "read_only_rest_paths": ["/rest/system/resource", "/rest/container", "/rest/ppp/active"],
            "max_sample_gap_seconds": 60,
            "router_cpu_peak_percent": 24,
            "router_memory_peak_percent": 35,
            "router_storage_peak_percent": 18,
            "containers": {
                environment: {
                    "healthy_for_all_successful_samples": True,
                    "observed_source_revisions": [revision],
                }
                for environment in ("canary", "production")
            },
        }
        mismatch = deepcopy(routeros_report)
        mismatch["containers"]["canary"]["observed_source_revisions"] = ["c" * 40]
        parity_gap = deepcopy(routeros_report)
        parity_gap["rest_parity_successful_sample_count"] -= 1
        parity_failure = deepcopy(routeros_report)
        parity_failure["rest_parity_failed_sample_count"] = 1

        for report in (
            mismatch,
            {**routeros_report, "observation_started_at": "2026-10-01T00:02:00Z"},
            parity_gap,
            parity_failure,
            {key: value for key, value in routeros_report.items() if key != "read_only_rest_paths"},
        ):
            with self.subTest(report=report["observation_started_at"]):
                with self.assertRaises(ValueError):
                    attach_routeros_resource_evidence(deepcopy(app_evidence), report)

    def test_collection_failure_atomically_replaces_a_stale_passing_report(self) -> None:
        from scripts import collect_release_acceptance as collector

        with tempfile.TemporaryDirectory() as directory:
            input_path = Path(directory) / "input.json"
            output_path = Path(directory) / "report.json"
            input_path.write_text(json.dumps(evidence()), encoding="utf-8")
            output_path.write_text('{"passed": true, "old": "stale"}\n', encoding="utf-8")
            output = StringIO()
            arguments = [
                "collect_release_acceptance.py",
                "--input", str(input_path),
                "--output", str(output_path),
                "--routeros-report", str(Path(directory) / "routeros.json"),
                "--stream-observer-report", str(Path(directory) / "stream.json"),
                "--telemetry-acceptance-input", str(Path(directory) / "browser.ndjson"),
                "--canary-url", "https://canary.example",
                "--production-url", "https://production.example",
                "--canary-metrics-url", "https://canary.example",
                "--phase", "canary-prepromotion",
            ]
            with (
                patch.object(sys, "argv", arguments),
                patch.object(collector, "collect", side_effect=ValueError("private-router.invalid password-secret")),
                redirect_stdout(output),
            ):
                self.assertEqual(collector.main(), 2)

            report = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(report["format"], "vpn-dashboard-release-collection-failure-v1")
            self.assertFalse(report["collected"])
            self.assertFalse(report["passed"])
            self.assertEqual(report["failed_gates"], ["collection_failed"])
            self.assertEqual(report["error"], "ValueError")
            self.assertNotIn("stale", output_path.read_text(encoding="utf-8"))
            self.assertNotIn("private-router", output_path.read_text(encoding="utf-8"))
            self.assertNotIn("password-secret", output.getvalue())

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
        self.assertIn("--stream-observer-report", output.getvalue())
        self.assertIn("--telemetry-acceptance-input", output.getvalue())
        self.assertIn("--canary-sqlite-backup", output.getvalue())
        self.assertIn("--production-sqlite-backup", output.getvalue())

    def test_routeros_soak_report_is_required_before_app_collection_starts(self) -> None:
        from scripts import collect_release_acceptance as collector

        arguments = [
            "collect_release_acceptance.py",
            "--input", "private-evidence.json",
            "--output", "private-collected-evidence.json",
            "--canary-url", "https://canary.example",
            "--production-url", "https://production.example",
            "--canary-metrics-url", "https://canary.example",
            "--phase", "canary-prepromotion",
        ]
        with patch.object(sys, "argv", arguments), patch.object(collector, "collect") as collect:
            with self.assertRaises(SystemExit) as raised:
                collector.main()

        self.assertEqual(raised.exception.code, 2)
        collect.assert_not_called()

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
            observed = collector._registry_digest_request(TAG_IMAGE, timeout=3)

        self.assertEqual(observed, digest)
        token_request, manifest_request = opener.requests
        self.assertEqual(token_request.get_method(), "GET")
        self.assertTrue(token_request.full_url.startswith(
            "https://ghcr.io/token?scope=repository%3Aaivanov2-godaddy%2Fmikrotik-openvpn-gui%3Apull"
        ))
        self.assertEqual(manifest_request.get_method(), "HEAD")
        self.assertEqual(
            manifest_request.full_url,
            f"https://ghcr.io/v2/aivanov2-godaddy/mikrotik-openvpn-gui/manifests/sha-{REVISION}-arm64",
        )
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
            b'vpn_dashboard_integration_outbox_storage_failures_total{event_id="private-id"} 99\n'
            b'vpn_dashboard_integration_outbox_storage_failures_total 3\n'
            b'vpn_dashboard_process_start_time_seconds 1790928000.5\n'
            b'vpn_dashboard_telemetry_supervisor_status{state="healthy",router="private-host"} 99\n'
            b'vpn_dashboard_telemetry_supervisor_status{state="healthy"} 1\n'
        )
        self.assertNotIn("vpn_dashboard_telemetry_gateway_clients", parsed)
        self.assertEqual(parsed["vpn_dashboard_telemetry_gateway_events_total_published"], 4)
        self.assertEqual(parsed["vpn_dashboard_redis_publish_total_success"], 7)
        self.assertEqual(parsed["vpn_dashboard_integration_outbox_storage_failures_total"], 3)
        self.assertEqual(parsed["vpn_dashboard_process_start_time_seconds"], 1790928000.5)
        self.assertEqual(parsed["vpn_dashboard_telemetry_supervisor_status_healthy"], 1)

    def run_collection(
        self,
        *,
        ready: bool = True,
        include_metrics: bool = True,
        include_production_metrics: bool = True,
        preclaim_redis: bool = False,
        traffic_sample_age: float = 0.75,
        session_event_age: float = 0.25,
        gateway_delivery_p95: float = 0.5,
        gateway_delivery_observations: int = 8,
        redis_availability_sequence: list[int] | None = None,
        redis_publish_age_seconds: float = 0,
        inconsistent_session_timestamp: bool = False,
        inconsistent_traffic_timestamp: bool = False,
        supervisor_status: str = "healthy",
        supervisor_enabled: int = 1,
        reconnect_counter_delta: int = 1,
        snapshot_recovery_counter_delta: int = 1,
        advance_recovery_timestamps: bool = True,
        outbox_pending: int = 0,
        outbox_pending_sequence: list[int] | None = None,
        outbox_dead_lettered: int = 0,
        outbox_oldest_age: float = 0,
        outbox_storage_failure_initial: int = 0,
        outbox_storage_failure_delta: int = 0,
        outbox_storage_failure_counter_reset: bool = False,
        process_start_time_override: float | None = None,
        process_restart_observed: bool = False,
        unknown_metric_sample: int | None = None,
        wall_clock_adjustment_seconds: float = 0,
        phase: str = "postpromotion",
        browser_origin_revision: str | None = None,
        production_revision: str | None = None,
        production_observed_revision: str | None = None,
        registry_digests: dict[str, str | None] | None = None,
        clear_prior_production_runtime_evidence: bool = False,
        omit_prior_production_digest: bool = False,
        include_certificate_lifecycle_report: bool = True,
        certificate_lifecycle_report: dict[str, object] | None = None,
        omit_redis_recovery_report: bool = False,
        redis_source_revision: str | None = None,
        omit_rollback_report: bool = False,
        missing_sqlite_backups: tuple[str, ...] = (),
        corrupt_sqlite_backups: tuple[str, ...] = (),
        extra_sqlite_backup_paths: dict[str, str | Path] | None = None,
        cookie: str | None = "session=secret-cookie",
        metrics_tokens: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, object], list[tuple[str, str | None, str | None]]]:
        time = FakeTime()
        time.wall_clock_adjustment_seconds = wall_clock_adjustment_seconds
        seen: list[tuple[str, str | None, str | None]] = []
        metrics_observations = 0
        metrics_observations_by_environment = {"canary": 0, "production": 0}
        recovery_timestamp_bases: dict[str, float] = {}
        process_start_time_bases: dict[str, float] = {}
        source = evidence()
        if not include_certificate_lifecycle_report:
            source.pop("certificate_lifecycle_acceptance", None)
        if certificate_lifecycle_report is not None:
            source["certificate_lifecycle_acceptance"] = certificate_lifecycle_report
        if production_revision is not None:
            production = source["deployments"][1]
            production["image"] = image_ref(production_revision, PRIOR_DIGEST)
            production["digest"] = PRIOR_DIGEST
        if phase == "canary-prepromotion":
            production = source["deployments"][1]
            production["transport"] = "socketio"
            if omit_prior_production_digest:
                production["digest"] = None
            if clear_prior_production_runtime_evidence:
                for field in (
                    "transport", "rest_fallback", "redis_configured", "redis_publish_verified",
                    "reconnect_recovered", "snapshot_recovered", "sqlite_restore_verified",
                    "sqlite_restore_verified_at", "rollback_drill_at", "production_protection_observed_at",
                    "session_event_latency_started_at", "session_event_latency_ended_at",
                    "session_event_p95_ms", "session_event_max_ms", "traffic_sample_age_seconds", "stale_sample_count",
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
                if "vpn-dev.wanted.sx" in url and browser_origin_revision is not None:
                    expected_revision = browser_origin_revision
                else:
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
            recovery_timestamp_bases.setdefault(environment, now)
            recovery_time_base = recovery_timestamp_bases[environment]
            process_start_time_bases.setdefault(environment, now - 3600)
            process_start_time = (
                now - 1
                if process_restart_observed and metrics_observations_by_environment[environment] > 1
                else process_start_time_bases[environment]
            )
            if process_start_time_override is not None:
                process_start_time = process_start_time_override
            recovery_observed = metrics_observations_by_environment[environment] > 1
            availability_index = min(metrics_observations_by_environment[environment] - 1,
                                     len(redis_availability_sequence or [1]) - 1)
            redis_available = (redis_availability_sequence or [1])[availability_index]
            event_timestamp_age = 10 if inconsistent_session_timestamp else session_event_age
            traffic_timestamp_age = 10 if inconsistent_traffic_timestamp else traffic_sample_age
            outbox_storage_failures = (
                outbox_storage_failure_initial + 5
                if outbox_storage_failure_counter_reset and not recovery_observed
                else outbox_storage_failure_initial + outbox_storage_failure_delta
                if recovery_observed
                else outbox_storage_failure_initial
            )
            reconnect_timestamp = recovery_time_base - 0.25 + (
                reconnect_counter_delta if recovery_observed and advance_recovery_timestamps else 0
            )
            full_snapshot_timestamp = recovery_time_base - 0.5 + (
                1.4
                if recovery_observed and advance_recovery_timestamps else 0
            )
            payload = (
                "vpn_dashboard_redis_configured 1\n"
                f"vpn_dashboard_redis_last_observed_available {redis_available}\n"
                "vpn_dashboard_redis_publish_total{outcome=\"success\"} 7\n"
                "vpn_dashboard_redis_publish_total{outcome=\"failure\"} 0\n"
                f"vpn_dashboard_redis_last_publish_success_timestamp_seconds {now - redis_publish_age_seconds}\n"
                f"vpn_dashboard_integration_outbox_pending {-1 if sample_is_unknown else pending_value}\n"
                f"vpn_dashboard_integration_outbox_dead_lettered {-1 if sample_is_unknown else outbox_dead_lettered}\n"
                f"vpn_dashboard_integration_outbox_oldest_age_seconds {-1 if sample_is_unknown else outbox_oldest_age}\n"
                f"vpn_dashboard_integration_outbox_storage_failures_total {outbox_storage_failures}\n"
                f"vpn_dashboard_process_start_time_seconds {process_start_time}\n"
                f"vpn_dashboard_telemetry_session_event_age_seconds {-1 if sample_is_unknown else session_event_age}\n"
                f"vpn_dashboard_telemetry_session_event_timestamp_seconds {-1 if sample_is_unknown else now - event_timestamp_age}\n"
                "vpn_dashboard_telemetry_session_events_total 4\n"
                f"vpn_dashboard_telemetry_traffic_sample_age_seconds {-1 if sample_is_unknown else traffic_sample_age}\n"
                f"vpn_dashboard_telemetry_traffic_sample_timestamp_seconds {-1 if sample_is_unknown else now - traffic_timestamp_age}\n"
                "vpn_dashboard_telemetry_traffic_samples_total 12\n"
                "vpn_dashboard_telemetry_gateway_clients 1\n"
                "vpn_dashboard_telemetry_gateway_buffered_events 2\n"
                "vpn_dashboard_telemetry_gateway_events_total{outcome=\"published\"} 15\n"
                "vpn_dashboard_telemetry_gateway_events_total{outcome=\"replayed\"} 3\n"
                "vpn_dashboard_telemetry_gateway_events_total{outcome=\"snapshot_recovery\"} "
                f"{1 + (snapshot_recovery_counter_delta if metrics_observations_by_environment[environment] > 1 else 0)}\n"
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
                "vpn_dashboard_telemetry_supervisor_reconnects_total "
                f"{2 + (reconnect_counter_delta if metrics_observations_by_environment[environment] > 1 else 0)}\n"
                "vpn_dashboard_telemetry_supervisor_failures_total 1\n"
                "vpn_dashboard_telemetry_supervisor_events_total 20\n"
                "vpn_dashboard_telemetry_supervisor_last_connected_timestamp_seconds "
                f"{reconnect_timestamp}\n"
                f"vpn_dashboard_telemetry_supervisor_last_event_timestamp_seconds {now - 0.25}\n"
                "vpn_dashboard_telemetry_supervisor_last_snapshot_timestamp_seconds "
                f"{full_snapshot_timestamp}\n"
                "vpn_dashboard_telemetry_supervisor_backoff_seconds 1\n"
                "vpn_dashboard_info{revision=\"private-label\"} 1\n"
            )
            return 200, payload.encode()

        backup_directory = tempfile.TemporaryDirectory(prefix="release-acceptance-backups-")
        try:
            backup_paths: dict[str, str | Path] = {}
            restore_environments = ("canary",) if phase == "canary-prepromotion" else ("canary", "production")
            for environment in restore_environments:
                if environment in missing_sqlite_backups:
                    continue
                store = MetadataStore(str(Path(backup_directory.name) / f"{environment}-live.sqlite3"))
                backup_path = Path(backup_directory.name) / f"{environment}-backup.sqlite3"
                store.backup_database(str(backup_path))
                if environment in corrupt_sqlite_backups:
                    backup_path.write_bytes(b"not a sqlite database")
                backup_paths[environment] = backup_path
            backup_paths.update(extra_sqlite_backup_paths or {})
            candidate_deployment = source["deployments"][0]
            production_deployment = source["deployments"][1]
            redis_report = None if omit_redis_recovery_report else redis_recovery_report(
                redis_source_revision or REVISION
            )
            rollback_readbacks = None if omit_rollback_report else rollback_report_for(
                candidate_deployment["image"],
                candidate_deployment["digest"],
                production_deployment["image"],
                time.current,
            )
            code, report = collect(
                source,
                readyz_urls={"canary": "https://192.168.1.2", "production": "https://private.example"},
                sqlite_backup_paths=backup_paths,
                metrics_urls=(
                    {
                        **{"canary": "https://192.168.1.2"},
                        **({"production": "https://private.example"} if include_production_metrics else {}),
                    }
                    if include_metrics else None
                ),
                cookie=cookie,
                metrics_tokens=metrics_tokens,
                duration_seconds=1800,
                interval_seconds=60,
                probe=probe,
                registry_probe=lambda image, *, timeout: resolved_registry_digests.get(image),
                clock=time.clock,
                sleep=time.sleep,
                monotonic=time.monotonic,
                minimum_soak_seconds=1,
                minimum_health_samples=2,
                phase=phase,
                redis_recovery_report=redis_report,
                redis_recovery_provenance=redis_ci_provenance(redis_source_revision or REVISION),
                rollback_report=rollback_readbacks,
            )
        finally:
            backup_directory.cleanup()
        started = report["evidence"]["collection"]["started_at"]
        ended = report["evidence"]["collection"]["ended_at"]
        observer = {
            "format": "vpn-dashboard-telemetry-stream-observation-v1",
            "started_at": started, "ended_at": ended, "duration_seconds": 1800,
            "origin_role": "canary", "origin": CANARY_ORIGIN,
            "candidate_revision": REVISION, "observed_revision": REVISION,
            "transport": "socketio-websocket",
            "connections": 2, "disconnects": 1, "reconnects": 1,
            "stream_connected_at_end": True, "event_count": 3,
            "event_counts": {"telemetry.snapshot": 2, "vpn.session.updated": 1},
            "snapshot_count": 2, "reconnect_snapshot_count": 1,
            "sequence_gaps": 0, "duplicate_sequences": 0,
            "out_of_order_sequences": 0, "rejected_frames": 0,
            "raw_frames_written": False, "identities_or_addresses_written": False,
            "credentials_written": False, "latency_measured": False,
            "latency_note": "not measured; client/server clock offset is not established",
            "failed_gates": [], "observed_stream_healthy": True,
        }
        verified_identity = report.pop("_verified_deployment_identity", None)
        browser = {
            "format": "vpn-dashboard-telemetry-acceptance-v3", "healthy": True,
            "origin": CANARY_ORIGIN,
            "candidate_revision": REVISION, "observed_revision": REVISION,
            "identity_verified": verified_identity is not None,
            "failed_gates": [], "observation_started_at": started,
            "observation_ended_at": ended, "session_transition_count": 2,
            "session_transition_visible_count": 2, "connected_transition_observed": True,
            "disconnected_transition_observed": True,
            "ordered_connect_disconnect_observed": True,
            "session_event_latency_p95_ms": 400,
            "session_event_latency_max_ms": 550,
            "session_event_age_max_seconds": 0.5,
            "traffic_update_count": 2, "traffic_update_visible_count": 2,
            "traffic_sample_age_max_seconds": 1.0, "event_sequence_observation_count": 30,
            "event_sequence_gap_count": 0, "duplicate_event_count": 0,
            "out_of_order_event_count": 0, "reconnect_test_count": 1,
            "reconnect_success_count": 1,
            "security_tests": 1,
            "verification": {name: True for name in VERIFICATION_FIELDS},
        }
        code, report = apply_stream_acceptance(
            report, observer, browser, now=time.current, minimum_window_seconds=1800,
        )
        return code, report, seen

    def test_collects_health_window_and_authenticated_aggregate_metrics(self) -> None:
        code, report, seen = self.run_collection()
        self.assertEqual(code, 0)
        self.assertEqual(
            report["evidence"]["collection"]["certificate_lifecycle_acceptance"]["format"],
            "vpn-dashboard-certificate-lifecycle-acceptance-v1",
        )
        collected = report["evidence"]
        self.assertEqual(collected["collection"]["format"], "vpn-dashboard-release-collection-v2")
        self.assertEqual(collected["collection"]["phase"], "postpromotion")
        self.assertEqual(collected["collection"]["browser_origin_readiness"]["ready_sample_count"], 31)
        self.assertTrue(collected["collection"]["browser_origin_readiness"]["all_samples_ready_for_candidate"])
        self.assertEqual(
            [entry["verified"] for entry in collected["collection"]["registry_digest_verification"]],
            [True, True],
        )
        self.assertEqual(len(collected["deployments"]), 2)
        self.assertGreaterEqual(collected["deployments"][0]["health_sample_count"], 2)
        self.assertEqual(report["deployments"][0]["metrics_sample_count"], 31)
        self.assertEqual(collected["deployments"][0]["session_event_max_ms"], 550)
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
        self.assertEqual(gateway["snapshot_recoveries"]["delta"], 1)
        self.assertEqual(gateway["delivery_queue_age_p95_seconds"]["max"], 0.5)
        self.assertIn("excludes RouterOS observation and browser rendering", gateway["meaning"])
        telemetry_slo = report["deployments"][0]["metrics"]["telemetry_slo"]
        self.assertEqual(telemetry_slo["traffic_sample_max_age_seconds"], 0.75)
        self.assertEqual(telemetry_slo["gateway_delivery_p95_max_seconds"], 0.5)
        self.assertEqual(telemetry_slo["supervisor_non_healthy_samples"], 0)
        self.assertIn("does not measure RouterOS-to-browser session-change latency", telemetry_slo["meaning"])
        restore_checks = collected["collection"]["sqlite_restore_verification"]["checks"]
        self.assertEqual([check["environment"] for check in restore_checks], ["canary", "production"])
        self.assertTrue(all(check["verified"] for check in restore_checks))
        self.assertTrue(all(check["source_opened_read_only"] for check in restore_checks))
        self.assertTrue(all(check["restored_integrity"] for check in restore_checks))
        self.assertTrue(all(check["restored_data_counts_match"] for check in restore_checks))
        self.assertTrue(all(check["temporary_copy_removed"] for check in restore_checks))
        self.assertTrue(all(check["candidate_image"] == IMAGE for check in restore_checks))
        self.assertTrue(all(check["candidate_revision"] == REVISION for check in restore_checks))
        self.assertTrue(all(check["candidate_digest"] == "sha256:" + "b" * 64 for check in restore_checks))
        collection = collected["collection"]
        self.assertEqual(collection["redis_recovery_verification"]["source_revision"], REVISION)
        self.assertEqual(collection["redis_recovery_verification"]["scope"], "source-integration-tests")
        self.assertFalse(collection["redis_recovery_verification"]["runtime_image_digest_verified"])
        self.assertEqual(collection["rollback_rehearsal"]["candidate_image"], IMAGE)
        self.assertEqual(
            report["evidence"]["deployments"][0]["rollback_drill_at"],
            collection["rollback_rehearsal"]["canary_after_rollback"]["observed_at"],
        )
        supervisor = report["deployments"][0]["metrics"]["telemetry_supervisor"]
        self.assertEqual(supervisor["status_last"], "healthy")
        self.assertEqual(supervisor["reconnects"]["delta"], 1)
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

    def test_browser_origin_candidate_mismatch_blocks_identity_binding(self) -> None:
        code, report, _seen = self.run_collection(browser_origin_revision="f" * 40)

        self.assertEqual(code, 1)
        self.assertFalse(report["evidence"]["collection"]["browser_origin_readiness"]["all_samples_ready_for_candidate"])
        self.assertIn("browser_candidate_identity_mismatch", report["stream_acceptance"]["failed_gates"])

    def test_missing_local_backups_override_optimistic_input_and_fail_closed(self) -> None:
        code, report, _ = self.run_collection(missing_sqlite_backups=("canary", "production"))

        self.assertEqual(code, 1)
        self.assertIn("canary_sqlite_restore_unverified", report["failed_gates"])
        self.assertIn("production_sqlite_restore_unverified", report["failed_gates"])
        self.assertFalse(report["evidence"]["deployments"][0]["sqlite_restore_verified"])
        self.assertFalse(report["evidence"]["deployments"][1]["sqlite_restore_verified"])
        checks = report["evidence"]["collection"]["sqlite_restore_verification"]["checks"]
        self.assertEqual([check["failure_code"] for check in checks], ["backup_missing", "backup_missing"])
        self.assertNotIn("release-acceptance-backups-", json.dumps(report))

    def test_missing_redis_or_rollback_evidence_cannot_be_overridden_by_input_booleans(self) -> None:
        _, redis_report, _ = self.run_collection(omit_redis_recovery_report=True)
        self.assertIn("redis_recovery_ci_evidence_missing", redis_report["failed_gates"])

        _, rollback_report, _ = self.run_collection(omit_rollback_report=True)
        self.assertIn("rollback_readback_evidence_missing", rollback_report["failed_gates"])
        canary = rollback_report["evidence"]["deployments"][0]
        self.assertFalse(canary["rollback_drill_passed"])
        self.assertFalse(canary["production_untouched_on_canary_failure"])

    def test_redis_ci_report_must_match_candidate_revision(self) -> None:
        _, report, _ = self.run_collection(redis_source_revision="c" * 40)

        self.assertIn("redis_recovery_ci_candidate_mismatch", report["failed_gates"])

    def test_corrupt_canary_backup_fails_only_its_restore_gate(self) -> None:
        code, report, _ = self.run_collection(corrupt_sqlite_backups=("canary",))

        self.assertEqual(code, 1)
        self.assertIn("canary_sqlite_restore_unverified", report["failed_gates"])
        self.assertNotIn("production_sqlite_restore_unverified", report["failed_gates"])
        checks = report["evidence"]["collection"]["sqlite_restore_verification"]["checks"]
        self.assertEqual([check["failure_code"] for check in checks], ["invalid_sqlite", None])

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
        with patch(
            "scripts.collect_release_acceptance.verify_sqlite_restore",
            wraps=verify_sqlite_restore,
        ) as restore_spy:
            code, report, seen = self.run_collection(
                phase="canary-prepromotion",
                production_revision="c" * 40,
                extra_sqlite_backup_paths={"production": "unused-private-production-backup.sqlite3"},
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
        checks = report["evidence"]["collection"]["sqlite_restore_verification"]["checks"]
        self.assertEqual([check["environment"] for check in checks], ["canary"])
        restore_spy.assert_called_once()
        self.assertIn("canary-backup", str(restore_spy.call_args.args[0]))
        self.assertIsNone(report["evidence"]["deployments"][1]["sqlite_restore_verified"])
        self.assertNotIn("unused-private-production-backup", json.dumps(report))

    def test_certificate_lifecycle_report_is_required_and_unknown_fields_are_not_copied(self) -> None:
        code, report, _ = self.run_collection(include_certificate_lifecycle_report=False)
        self.assertNotEqual(code, 0)
        self.assertIn(
            "certificate_lifecycle_acceptance_missing",
            report["evidence"]["collection"]["failed_gates"],
        )
        self.assertIsNone(report["evidence"]["collection"]["certificate_lifecycle_acceptance"])

        unsafe_report = certificate_lifecycle_evidence()
        unsafe_report["certificate_serial"] = "must-not-appear"
        code, report, _ = self.run_collection(certificate_lifecycle_report=unsafe_report)
        self.assertNotEqual(code, 0)
        self.assertIn(
            "certificate_lifecycle_acceptance_invalid",
            report["evidence"]["collection"]["failed_gates"],
        )
        self.assertNotIn("must-not-appear", json.dumps(report["evidence"]))

        spoofed_provenance = certificate_lifecycle_evidence()
        spoofed_provenance.update({
            "evidence_provenance": "operator_attested",
            "independently_observed": False,
        })
        code, report, _ = self.run_collection(certificate_lifecycle_report=spoofed_provenance)
        self.assertNotEqual(code, 0)
        self.assertIn(
            "certificate_lifecycle_acceptance_invalid",
            report["evidence"]["collection"]["failed_gates"],
        )

        malformed_outcome = certificate_lifecycle_evidence()
        malformed_outcome["existing_session_outcome"] = ["terminated"]
        code, report, _ = self.run_collection(certificate_lifecycle_report=malformed_outcome)
        self.assertNotEqual(code, 0)
        self.assertIn(
            "certificate_lifecycle_acceptance_invalid",
            report["evidence"]["collection"]["failed_gates"],
        )

    def test_certificate_lifecycle_cli_report_loader_is_bounded_and_json_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            report_path = Path(temporary_directory) / "certificate-report.json"
            expected = certificate_lifecycle_evidence()
            report_path.write_text(json.dumps(expected), encoding="utf-8")
            self.assertEqual(_read_certificate_lifecycle_report(report_path), expected)

            report_path.write_text(" " * (16_384 + 1), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "size limit"):
                _read_certificate_lifecycle_report(report_path)

    def test_new_acceptance_report_loaders_are_byte_bounded(self) -> None:
        from scripts.collect_release_acceptance import (
            MAX_REDIS_RECOVERY_REPORT_BYTES,
            MAX_ROLLBACK_REPORT_BYTES,
            _read_bounded_json_report,
        )

        with tempfile.TemporaryDirectory() as temporary_directory:
            report_path = Path(temporary_directory) / "bounded-report.json"
            report_path.write_text('{"safe":true}', encoding="utf-8")
            self.assertEqual(_read_bounded_json_report(report_path, 32, "test report"), {"safe": True})

            for limit, label in (
                (MAX_REDIS_RECOVERY_REPORT_BYTES, "Redis recovery report"),
                (MAX_ROLLBACK_REPORT_BYTES, "rollback read-back report"),
            ):
                report_path.write_bytes(b" " * (limit + 1))
                with self.subTest(label=label), self.assertRaisesRegex(ValueError, "size limit"):
                    _read_bounded_json_report(report_path, limit, label)

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

    def test_stale_session_event_age_fails_closed(self) -> None:
        code, report, _ = self.run_collection(session_event_age=2.01)
        self.assertEqual(code, 1)
        self.assertIn("canary_session_event_stale", report["failed_gates"])
        self.assertIn("production_session_event_stale", report["failed_gates"])

    def test_source_timestamps_cannot_contradict_fresh_age_gauges(self) -> None:
        code, report, _ = self.run_collection(
            session_event_age=0.25,
            traffic_sample_age=0.75,
            inconsistent_session_timestamp=True,
            inconsistent_traffic_timestamp=True,
        )
        self.assertEqual(code, 1)
        for environment in ("canary", "production"):
            self.assertIn(f"{environment}_session_event_timestamp_inconsistent", report["failed_gates"])
            self.assertIn(f"{environment}_session_event_stale", report["failed_gates"])
            self.assertIn(f"{environment}_traffic_timestamp_inconsistent", report["failed_gates"])
            self.assertIn(f"{environment}_traffic_sample_stale", report["failed_gates"])

    def test_redis_transient_unavailability_fails_even_when_final_sample_is_healthy(self) -> None:
        code, report, _ = self.run_collection(redis_availability_sequence=[1, 0, 1])
        self.assertEqual(code, 1)
        for environment in ("canary", "production"):
            self.assertIn(f"{environment}_redis_unavailable_during_window", report["failed_gates"])
            deployment = next(item for item in report["deployments"] if item["environment"] == environment)
            availability = deployment["metrics"]["redis_availability_window"]
            self.assertEqual(availability["last"], 1)
            self.assertEqual(availability["unavailable_samples"], 1)

    def test_stale_redis_publish_timestamp_fails_even_when_availability_is_true(self) -> None:
        code, report, _ = self.run_collection(redis_publish_age_seconds=121)
        self.assertEqual(code, 1)
        for environment in ("canary", "production"):
            self.assertIn(f"{environment}_redis_publish_stale_during_window", report["failed_gates"])

    def test_reconnect_and_full_snapshot_timestamps_must_advance_in_window(self) -> None:
        code, report, _ = self.run_collection(
            reconnect_counter_delta=0,
            snapshot_recovery_counter_delta=0,
        )
        self.assertEqual(code, 1)
        self.assertIn("canary_reconnect_recovery_not_observed", report["failed_gates"])
        self.assertIn("canary_snapshot_recovery_not_observed", report["failed_gates"])
        canary = report["evidence"]["deployments"][0]
        self.assertFalse(canary["reconnect_recovered"])
        self.assertFalse(canary["snapshot_recovered"])

        code, report, _ = self.run_collection(advance_recovery_timestamps=False)
        self.assertEqual(code, 1)
        self.assertIn("canary_reconnect_recovery_not_observed", report["failed_gates"])
        self.assertIn("canary_snapshot_recovery_not_observed", report["failed_gates"])

    def test_reconnect_requires_counter_delta_but_full_snapshot_uses_supervisor_timestamp(self) -> None:
        code, report, _ = self.run_collection(reconnect_counter_delta=0)
        self.assertEqual(code, 1)
        self.assertIn("canary_reconnect_recovery_not_observed", report["failed_gates"])
        canary = report["evidence"]["deployments"][0]
        self.assertFalse(canary["reconnect_recovered"])
        self.assertEqual(canary["reconnect_recovery_counter_delta"], 0)

        # Gateway snapshot_recovery counts stale client-cursor replay, not the
        # RouterOS supervisor's full snapshot after API reconnect. A zero delta
        # there must not invalidate a directly observed supervisor snapshot.
        code, report, _ = self.run_collection(snapshot_recovery_counter_delta=0)
        self.assertEqual(code, 0)
        self.assertNotIn("canary_snapshot_recovery_not_observed", report["failed_gates"])
        canary = report["evidence"]["deployments"][0]
        self.assertTrue(canary["snapshot_recovered"])
        self.assertGreaterEqual(
            canary["full_snapshot_recovered_at"], canary["reconnect_observed_at"]
        )

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
        self.assertEqual(
            gateway["published_events"],
            {"delta": 4, "counter_reset": False, "invalid_samples": 0},
        )
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
            {"delta": 3, "counter_reset": True, "invalid_samples": 0},
        )

    def test_mid_window_counter_reset_preserves_post_reset_delta(self) -> None:
        from scripts.collect_release_acceptance import _metric_window

        samples = [
            {"metrics": {
                "vpn_dashboard_telemetry_gateway_events_total_published": 10,
                "vpn_dashboard_redis_publish_total_failure": 5,
                "vpn_dashboard_integration_outbox_storage_failures_total": 8,
            }},
            {"metrics": {
                "vpn_dashboard_telemetry_gateway_events_total_published": 2,
                "vpn_dashboard_redis_publish_total_failure": 1,
                "vpn_dashboard_integration_outbox_storage_failures_total": 2,
            }},
            {"metrics": {
                "vpn_dashboard_telemetry_gateway_events_total_published": 8,
                "vpn_dashboard_redis_publish_total_failure": 4,
                "vpn_dashboard_integration_outbox_storage_failures_total": 5,
            }},
        ]
        summary = _metric_window(samples, 0, 1)
        self.assertEqual(
            summary["telemetry_gateway"]["published_events"],
            {"delta": 8, "counter_reset": True, "invalid_samples": 0},
        )
        self.assertEqual(summary["redis_publish_failure_delta"], 4)
        self.assertTrue(summary["redis_publish_failure_counter_reset"])
        self.assertEqual(summary["outbox_storage_failure_delta"], 5)
        self.assertTrue(summary["outbox_storage_failure_counter_reset"])

    def test_sqlite_outbox_storage_failure_during_window_fails_acceptance(self) -> None:
        code, report, _ = self.run_collection(outbox_storage_failure_delta=1)

        self.assertEqual(code, 1)
        self.assertIn("canary_outbox_storage_failures_during_window", report["failed_gates"])
        self.assertEqual(
            report["deployments"][0]["metrics"]["outbox_storage_failure_delta"], 1
        )

    def test_sqlite_outbox_storage_failure_present_at_first_sample_fails_acceptance(self) -> None:
        code, report, _ = self.run_collection(outbox_storage_failure_initial=1)

        self.assertEqual(code, 1)
        self.assertIn(
            "canary_outbox_storage_failure_present_at_window_start",
            report["failed_gates"],
        )
        self.assertEqual(
            report["deployments"][0]["metrics"]["outbox_storage_failure_initial"],
            1,
        )

    def test_sqlite_outbox_storage_failure_counter_reset_fails_acceptance(self) -> None:
        code, report, _ = self.run_collection(outbox_storage_failure_counter_reset=True)

        self.assertEqual(code, 1)
        self.assertIn("canary_outbox_storage_failure_counter_reset", report["failed_gates"])

    def test_process_restart_during_collection_fails_acceptance(self) -> None:
        code, report, _ = self.run_collection(process_restart_observed=True)

        self.assertEqual(code, 1)
        self.assertIn("canary_process_restarted_during_window", report["failed_gates"])

    def test_process_start_after_window_start_is_detected_before_first_scrape(self) -> None:
        from scripts.collect_release_acceptance import _metric_window

        sample_at = datetime.fromtimestamp(110, tz=timezone.utc)
        summary = _metric_window(
            [{"at": sample_at, "metrics": {"vpn_dashboard_process_start_time_seconds": 106}}],
            100,
            110,
        )

        self.assertTrue(summary["process_started_during_window"])

    def test_negative_counter_samples_are_reported_invalid(self) -> None:
        from scripts.collect_release_acceptance import _metric_window

        counter = "vpn_dashboard_integration_outbox_storage_failures_total"
        summary = _metric_window(
            [
                {"metrics": {counter: 4}},
                {"metrics": {counter: -1}},
                {"metrics": {counter: 9}},
            ],
            100,
            110,
        )

        self.assertEqual(summary["counter_metric_invalid_samples"], 1)
        self.assertEqual(summary["outbox_storage_failure_delta"], 5)

    def test_negative_counter_metric_fails_acceptance(self) -> None:
        code, report, _ = self.run_collection(outbox_storage_failure_initial=-1)

        self.assertEqual(code, 1)
        self.assertIn("canary_counter_metric_invalid_samples", report["failed_gates"])

    def test_negative_process_start_metric_fails_acceptance(self) -> None:
        code, report, _ = self.run_collection(process_start_time_override=-1)

        self.assertEqual(code, 1)
        self.assertIn("canary_process_start_time_invalid", report["failed_gates"])

    def test_process_start_within_clock_tolerance_of_window_start_fails_closed(self) -> None:
        from scripts.collect_release_acceptance import _metric_window

        sample_at = datetime.fromtimestamp(102, tz=timezone.utc)
        summary = _metric_window(
            [{"at": sample_at, "metrics": {"vpn_dashboard_process_start_time_seconds": 102}}],
            100,
            110,
        )

        self.assertTrue(summary["process_start_window_start_ambiguous"])
        self.assertFalse(summary["process_started_during_window"])

    def test_ambiguous_process_start_baseline_fails_acceptance(self) -> None:
        window_start = datetime(2026, 10, 2, tzinfo=timezone.utc).timestamp()
        code, report, _ = self.run_collection(process_start_time_override=window_start + 1)

        self.assertEqual(code, 1)
        self.assertIn(
            "canary_process_start_time_ambiguous_at_window_start",
            report["failed_gates"],
        )

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
        self.assertEqual(production["image"], image_ref("c" * 40, PRIOR_DIGEST))
        self.assertTrue(production["app_ready"])

    def test_pre_promotion_candidate_does_not_require_old_production_metrics(self) -> None:
        for include_production_metrics in (False, True):
            with self.subTest(include_production_metrics=include_production_metrics):
                code, report, seen = self.run_collection(
                    phase="canary-prepromotion",
                    production_revision="c" * 40,
                    include_production_metrics=include_production_metrics,
                    clear_prior_production_runtime_evidence=True,
                )

                self.assertEqual(code, 0)
                self.assertEqual(report["evidence"]["deployments"][1]["redis_publish_verified"], False)
                self.assertEqual(report["evidence"]["deployments"][1]["digest"], PRIOR_DIGEST)
                self.assertEqual(report["deployments"][1]["metrics_sample_count"], 0)
                self.assertFalse(any(url == "https://private.example/metrics" for url, _, _ in seen))
                self.assertEqual(
                    report["evidence"]["collection"]["registry_digest_verification_scope"],
                    "canary-and-production",
                )
                self.assertEqual(
                    [item["environment"] for item in report["evidence"]["collection"]["registry_digest_verification"]],
                    ["canary", "production"],
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
                collected_evidence["collection"]["browser_origin_readiness"].update({
                    "observation_started_at": started,
                    "observation_ended_at": ended,
                })
                collected_evidence["collection"]["sqlite_restore_verification"]["checks"][0][
                    "checked_at"
                ] = "2026-10-02T10:50:00Z"
                stream_evidence = collected_evidence["collection"]["stream_acceptance"]
                stream_evidence["stream_observation"].update({
                    "started_at": started, "ended_at": ended, "duration_seconds": 1800,
                })
                stream_evidence["browser_telemetry"].update({
                    "observation_started_at": started, "observation_ended_at": ended,
                })
                for deployment in collected_evidence["deployments"]:
                    deployment.update({
                        "observation_started_at": started,
                        "observation_ended_at": ended,
                        "reconnect_observed_at": 1790937000,
                        "full_snapshot_recovered_at": 1790937001,
                        "session_event_latency_started_at": "2026-10-02T10:35:00Z",
                        "session_event_latency_ended_at": "2026-10-02T10:45:00Z",
                        "sqlite_restore_verified_at": "2026-10-02T10:50:00Z",
                        "health_sample_count": 30,
                        "max_sample_gap_seconds": 60,
                    })
                collected_evidence["deployments"][0].update({
                    "rollback_drill_at": "2026-10-02T10:51:00Z",
                    "production_protection_observed_at": "2026-10-02T10:52:00Z",
                })
                from scripts.collect_release_acceptance import attach_routeros_resource_evidence

                routeros_report = {
                    "format": "vpn-dashboard-routeros-acceptance-v3",
                    "passed": True,
                    "failed_gates": [],
                    "credentials_or_raw_router_data_written": False,
                    "observation_started_at": "2026-10-02T10:25:10Z",
                    "observation_ended_at": "2026-10-02T10:55:10Z",
                    "duration_seconds": 1800,
                    "sample_count": 31,
                    "successful_sample_count": 31,
                    "failed_sample_count": 0,
                    "rest_parity_successful_sample_count": 31,
                    "rest_parity_failed_sample_count": 0,
                    "active_vpn_sessions_min": 0,
                    "active_vpn_sessions_max": 1,
                    "read_only_rest_paths": ["/rest/system/resource", "/rest/container", "/rest/ppp/active"],
                    "max_sample_gap_seconds": 60,
                    "router_cpu_peak_percent": 20,
                    "router_memory_peak_percent": 25,
                    "router_storage_peak_percent": 30,
                    "containers": {
                        "canary": {
                            "healthy_for_all_successful_samples": True,
                            "observed_source_revisions": [REVISION],
                        },
                        "production": {
                            "healthy_for_all_successful_samples": True,
                            "observed_source_revisions": ["c" * 40],
                        },
                    },
                }
                attach_routeros_resource_evidence(collected_evidence, routeros_report)
                accepted, final_report = evaluate(
                    collected_evidence,
                    now=datetime(2026, 10, 2, 11, tzinfo=timezone.utc),
                )
                self.assertEqual(accepted, 0, final_report["failed_gates"])
                self.assertFalse(final_report["production_accepted"])
                self.assertEqual(final_report["deployments"][1]["digest"], PRIOR_DIGEST)
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

    def test_pre_promotion_fails_closed_when_prior_production_digest_is_unavailable(self) -> None:
        with self.assertRaisesRegex(ValueError, "production digest must be a sha256 OCI digest"):
            self.run_collection(
                phase="canary-prepromotion",
                production_revision="c" * 40,
                clear_prior_production_runtime_evidence=True,
                omit_prior_production_digest=True,
            )

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
