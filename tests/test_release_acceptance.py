from __future__ import annotations

import unittest

from scripts.release_acceptance import evaluate


class ReleaseAcceptanceTests(unittest.TestCase):
    def setUp(self) -> None:
        revision = "a" * 40
        self.evidence = {
            "format": "vpn-dashboard-release-evidence-v1",
            "deployments": [
                {
                    "environment": environment,
                    "image": f"ghcr.io/example/vpn:sha-{revision}-arm64",
                    "digest": "sha256:" + "b" * 64,
                    "container_healthy": True,
                    "app_ready": True,
                    "transport": "asgi-websocket",
                    "rest_fallback": True,
                    "redis_configured": True,
                    "redis_publish_verified": True,
                    "reconnect_recovered": True,
                    "snapshot_recovered": True,
                    "sqlite_restore_verified": True,
                    "session_event_p95_ms": 450,
                    "traffic_sample_age_seconds": 1.2,
                }
                for environment in ("canary", "production")
            ],
        }

    def test_matching_healthy_canary_and_production_pass(self) -> None:
        code, report = evaluate(self.evidence)
        self.assertEqual(code, 0)
        self.assertTrue(report["passed"])
        self.assertEqual(report["deployments"][0]["digest"], "sha256:" + "b" * 64)
        self.assertNotIn("details", report["deployments"][0])

    def test_mismatched_production_digest_fails_closed(self) -> None:
        self.evidence["deployments"][1]["digest"] = "sha256:" + "c" * 64
        code, report = evaluate(self.evidence)
        self.assertEqual(code, 1)
        self.assertIn("canary_production_digest_mismatch", report["failed_gates"])

    def test_stale_data_and_redis_failure_are_reported_without_raw_input(self) -> None:
        self.evidence["deployments"][1]["traffic_sample_age_seconds"] = 2.1
        self.evidence["deployments"][1]["redis_publish_verified"] = False
        code, report = evaluate(self.evidence)
        self.assertEqual(code, 1)
        self.assertIn("production_traffic_sample_stale", report["failed_gates"])
        self.assertIn("production_redis_publish_unverified", report["failed_gates"])

    def test_incorrect_deployment_order_is_rejected(self) -> None:
        self.evidence["deployments"].reverse()
        with self.assertRaisesRegex(ValueError, "ordered canary"):
            evaluate(self.evidence)


if __name__ == "__main__":
    unittest.main()
