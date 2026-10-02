from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import unittest

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

    def clock(self) -> datetime:
        return self.current

    def sleep(self, seconds: float) -> None:
        self.elapsed += seconds
        self.current += timedelta(seconds=seconds)

    def monotonic(self) -> float:
        return self.elapsed


class ReleaseCollectionTests(unittest.TestCase):
    def run_collection(self, *, ready: bool = True) -> tuple[int, dict[str, object], list[tuple[str, str | None]]]:
        time = FakeTime()
        seen: list[tuple[str, str | None]] = []

        def probe(url: str, *, cookie: str | None, timeout: float) -> tuple[int, bytes]:
            del timeout
            seen.append((url, cookie))
            if url.endswith("/healthz"):
                return (200 if ready else 503), b'{"status":"ok"}'
            if url.endswith("/readyz"):
                payload = {"status": "ready", "revision": REVISION if ready else "f" * 40}
                return 200, json.dumps(payload).encode()
            now = time.clock().timestamp()
            payload = (
                "vpn_dashboard_redis_configured 1\n"
                "vpn_dashboard_redis_last_observed_available 1\n"
                "vpn_dashboard_redis_publish_total{outcome=\"success\"} 7\n"
                "vpn_dashboard_redis_publish_total{outcome=\"failure\"} 0\n"
                f"vpn_dashboard_redis_last_publish_success_timestamp_seconds {now}\n"
                "vpn_dashboard_integration_outbox_pending 0\n"
                "vpn_dashboard_integration_outbox_oldest_age_seconds 0\n"
                "vpn_dashboard_info{revision=\"private-label\"} 1\n"
            )
            return 200, payload.encode()

        code, report = collect(
            evidence(),
            readyz_urls={"canary": "http://192.168.1.2", "production": "https://private.example"},
            metrics_urls={"canary": "https://192.168.1.2", "production": "https://private.example"},
            cookie="session=secret-cookie",
            duration_seconds=1,
            interval_seconds=0.5,
            probe=probe,
            clock=time.clock,
            sleep=time.sleep,
            monotonic=time.monotonic,
            minimum_soak_seconds=1,
            minimum_health_samples=2,
        )
        return code, report, seen

    def test_collects_health_window_and_authenticated_aggregate_metrics(self) -> None:
        code, report, seen = self.run_collection()
        self.assertEqual(code, 0)
        collected = report["evidence"]
        self.assertEqual(collected["collection"]["format"], "vpn-dashboard-release-collection-v1")
        self.assertEqual(len(collected["deployments"]), 2)
        self.assertGreaterEqual(collected["deployments"][0]["health_sample_count"], 2)
        self.assertTrue(collected["deployments"][0]["redis_publish_verified"])
        self.assertEqual(report["deployments"][0]["metrics"]["outbox_pending_last"], 0)
        self.assertTrue(all(cookie == "session=secret-cookie" for url, cookie in seen if url.endswith("/metrics")))
        serialized = json.dumps(report)
        self.assertNotIn("must-not-appear-in-output", serialized)
        self.assertNotIn("private-label", serialized)
        self.assertNotIn("session=secret-cookie", serialized)
        self.assertNotIn("192.168.1.2", serialized)

    def test_readiness_or_revision_mismatch_fails_closed(self) -> None:
        code, report, _ = self.run_collection(ready=False)
        self.assertEqual(code, 1)
        deployment = report["evidence"]["deployments"][0]
        self.assertFalse(deployment["container_healthy"])
        self.assertFalse(deployment["app_ready"])
        self.assertGreater(deployment["health_failures"], 0)

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

    def test_authenticated_metrics_cannot_send_cookies_over_http(self) -> None:
        with self.assertRaisesRegex(ValueError, "require HTTPS"):
            collect(
                evidence(),
                readyz_urls={"canary": "http://192.168.1.2", "production": "https://private.example"},
                metrics_urls={"canary": "http://192.168.1.2"},
                cookie="session=secret-cookie",
                duration_seconds=1,
                minimum_soak_seconds=1,
            )


if __name__ == "__main__":
    unittest.main()
