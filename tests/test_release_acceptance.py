from __future__ import annotations

import unittest
from copy import deepcopy

from scripts.release_acceptance import evaluate


class ReleaseAcceptanceTests(unittest.TestCase):
    def setUp(self) -> None:
        revision = "a" * 40
        self.evidence = {
            "format": "vpn-dashboard-release-evidence-v2",
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
                    "rollback_drill_passed": True,
                    "production_untouched_on_canary_failure": True,
                    "session_event_p95_ms": 450,
                    "traffic_sample_age_seconds": 1.2,
                    "observation_started_at": "2026-10-02T10:00:00Z",
                    "observation_ended_at": "2026-10-02T10:30:00Z",
                    "health_sample_count": 30,
                    "max_sample_gap_seconds": 60,
                    "health_failures": 0,
                    "stale_sample_count": 0,
                    "lost_event_count": 0,
                    "duplicate_event_count": 0,
                    "out_of_order_event_count": 0,
                    "redis_delivery_failure_count": 0,
                    "router_cpu_peak_percent": 25,
                    "router_memory_peak_percent": 40,
                    "router_storage_peak_percent": 20,
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

    def test_failed_live_collection_cannot_be_overridden_by_deployment_claims(self) -> None:
        evidence = deepcopy(self.evidence)
        evidence["collection"] = {
            "format": "vpn-dashboard-release-collection-v1",
            "passed": False,
            "failed_gates": ["canary_traffic_sample_stale"],
        }

        code, report = evaluate(evidence)

        self.assertEqual(code, 1)
        self.assertFalse(report["passed"])
        self.assertEqual(report["failed_gates"], ["live_collection_failed"])

    def test_passing_live_collection_is_accepted_and_malformed_collection_is_rejected(self) -> None:
        evidence = deepcopy(self.evidence)
        evidence["collection"] = {
            "format": "vpn-dashboard-release-collection-v1",
            "passed": True,
            "failed_gates": [],
        }
        code, report = evaluate(evidence)
        self.assertEqual(code, 0)
        self.assertTrue(report["passed"])

        evidence["collection"]["passed"] = "true"
        with self.assertRaisesRegex(ValueError, "passed must be boolean"):
            evaluate(evidence)

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

    def test_short_or_interrupted_soak_fails_closed(self) -> None:
        evidence = deepcopy(self.evidence)
        evidence["deployments"][0]["observation_ended_at"] = "2026-10-02T10:10:00Z"
        evidence["deployments"][1]["lost_event_count"] = 1
        code, report = evaluate(evidence)
        self.assertEqual(code, 1)
        self.assertIn("canary_soak_window_too_short", report["failed_gates"])
        self.assertIn("production_soak_failures_observed", report["failed_gates"])

    def test_missing_resource_and_rollback_evidence_is_rejected(self) -> None:
        evidence = deepcopy(self.evidence)
        del evidence["deployments"][0]["router_cpu_peak_percent"]
        with self.assertRaisesRegex(ValueError, "router_cpu_peak_percent"):
            evaluate(evidence)
        evidence = deepcopy(self.evidence)
        evidence["deployments"][0]["rollback_drill_passed"] = False
        code, report = evaluate(evidence)
        self.assertEqual(code, 1)
        self.assertIn("canary_rollback_drill_failed", report["failed_gates"])

    def test_observation_timestamps_must_include_timezone(self) -> None:
        evidence = deepcopy(self.evidence)
        evidence["deployments"][0]["observation_started_at"] = "2026-10-02T10:00:00"
        with self.assertRaisesRegex(ValueError, "include a timezone"):
            evaluate(evidence)


if __name__ == "__main__":
    unittest.main()
