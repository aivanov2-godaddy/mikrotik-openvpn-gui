from __future__ import annotations

from datetime import datetime, timezone
import unittest

from scripts.redis_recovery_acceptance import (
    REPORT_FORMAT,
    REQUIRED_TEST_NAMES,
    validate_report,
)


class RedisRecoveryAcceptanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.report = {
            "format": REPORT_FORMAT,
            "source_revision": "a" * 40,
            "started_at": "2026-10-01T10:00:00Z",
            "ended_at": "2026-10-01T10:01:00Z",
            "test_results": {name: "passed" for name in REQUIRED_TEST_NAMES},
            "scope": "source-integration-tests",
            "runtime_image_digest_verified": False,
            "private": "must-not-appear-in-projection",
        }
        self.now = datetime(2026, 10, 2, tzinfo=timezone.utc)

    def test_complete_source_report_is_projected_without_untrusted_fields(self) -> None:
        self.report.pop("private")
        safe, failures = validate_report(self.report, expected_revision="a" * 40, now=self.now)

        self.assertEqual(failures, [])
        self.assertEqual(safe["source_revision"], "a" * 40)
        self.assertEqual(len(safe["test_results"]), len(REQUIRED_TEST_NAMES))
        self.assertIs(safe["runtime_image_digest_verified"], False)
        self.assertNotIn("private", safe)

    def test_revision_mismatch_cannot_be_relabelled_for_another_candidate(self) -> None:
        self.report.pop("private")
        safe, failures = validate_report(self.report, expected_revision="b" * 40, now=self.now)

        self.assertIsNone(safe)
        self.assertIn("redis_recovery_ci_candidate_mismatch", failures)

    def test_failed_or_skipped_scenario_fails_closed(self) -> None:
        self.report.pop("private")
        self.report["test_results"][next(iter(REQUIRED_TEST_NAMES))] = "skipped"

        safe, failures = validate_report(self.report, expected_revision="a" * 40, now=self.now)

        self.assertIsNone(safe)
        self.assertIn("redis_recovery_ci_tests_failed", failures)

    def test_report_must_not_claim_exact_runtime_digest_tested(self) -> None:
        self.report.pop("private")
        self.report["runtime_image_digest_verified"] = True

        safe, failures = validate_report(self.report, expected_revision="a" * 40, now=self.now)

        self.assertIsNone(safe)
        self.assertIn("redis_recovery_ci_scope_invalid", failures)

    def test_stale_report_is_rejected(self) -> None:
        self.report.pop("private")
        self.report["started_at"] = "2026-09-01T10:00:00Z"
        self.report["ended_at"] = "2026-09-01T10:01:00Z"

        safe, failures = validate_report(self.report, expected_revision="a" * 40, now=self.now)

        self.assertIsNone(safe)
        self.assertIn("redis_recovery_ci_stale", failures)


if __name__ == "__main__":
    unittest.main()
