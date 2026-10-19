from __future__ import annotations

import copy
import unittest

from scripts.rollback_acceptance import REPORT_FORMAT, summarize_rollback_report, validate_rollback_report


REVISION = "a" * 40
CANDIDATE = f"ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-{REVISION}-arm64"
PRIOR = f"ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-{'c' * 40}-arm64"
DIGEST = "sha256:" + "b" * 64
START = "2026-10-02T10:00:00Z"
END = "2026-10-02T10:30:00Z"


def report() -> dict[str, object]:
    return {
        "format": REPORT_FORMAT,
        "candidate_image": CANDIDATE,
        "candidate_digest": DIGEST,
        "production_before": {
            "environment": "production", "observed_at": "2026-10-02T09:50:00Z",
            "image": CANDIDATE, "healthy": True, "ready": True,
        },
        "canary_before": {
            "environment": "canary", "observed_at": "2026-10-02T09:51:00Z",
            "image": PRIOR, "healthy": True, "ready": True,
        },
        "canary_candidate": {
            "environment": "canary", "observed_at": "2026-10-02T09:52:00Z",
            "image": CANDIDATE, "healthy": True, "ready": True,
        },
        "canary_after_rollback": {
            "environment": "canary", "observed_at": "2026-10-02T09:53:00Z",
            "image": PRIOR, "healthy": True, "ready": True,
        },
        "production_after": {
            "environment": "production", "observed_at": "2026-10-02T09:54:00Z",
            "image": CANDIDATE, "healthy": True, "ready": True,
        },
        "canary_candidate_restored": {
            "environment": "canary", "observed_at": "2026-10-02T09:55:00Z",
            "image": CANDIDATE, "healthy": True, "ready": True,
        },
    }


class RollbackAcceptanceTests(unittest.TestCase):
    def validate(self, value: object):
        return validate_rollback_report(
            value,
            candidate_image=CANDIDATE,
            candidate_digest=DIGEST,
            production_image=CANDIDATE,
            collection_started_at=START,
            collection_ended_at=END,
        )

    def test_ordered_readbacks_prove_rollback_target_and_unchanged_production(self) -> None:
        validated, failures = self.validate(report())

        self.assertEqual(failures, [])
        safe = summarize_rollback_report(validated)
        self.assertTrue(safe["production_unchanged"])
        self.assertEqual(safe["rollback_target_image"], PRIOR)
        self.assertIs(safe["router_runtime_digest_verified"], False)
        self.assertTrue(safe["candidate_restored_before_soak"])
        self.assertEqual(safe["readbacks"]["canary_after_rollback"]["revision"], "c" * 40)

    def test_candidate_must_be_restored_after_rollback_before_soak(self) -> None:
        value = report()
        value["canary_candidate_restored"]["image"] = PRIOR

        safe, failures = self.validate(value)

        self.assertIsNone(safe)
        self.assertIn("rollback_candidate_restore_readback_mismatch", failures)

    def test_normalized_report_can_be_validated_again_without_schema_drift(self) -> None:
        normalized, failures = self.validate(report())

        self.assertEqual(failures, [])
        normalized_again, failures = self.validate(normalized)

        self.assertEqual(failures, [])
        self.assertEqual(normalized_again, normalized)

    def test_readbacks_older_than_24_hours_are_rejected(self) -> None:
        value = report()
        for name in (
            "production_before", "canary_before", "canary_candidate", "canary_after_rollback",
            "production_after", "canary_candidate_restored",
        ):
            value[name]["observed_at"] = "2026-09-30T09:00:00Z"

        safe, failures = self.validate(value)

        self.assertIsNone(safe)
        self.assertIn("rollback_readback_outside_window", failures)

        value = report()
        value["production_after"]["observed_at"] = "2026-10-02T10:00:01Z"
        safe, failures = self.validate(value)

        self.assertIsNone(safe)
        self.assertIn("rollback_readback_outside_window", failures)

    def test_candidate_and_registry_digest_must_match_exact_deployment(self) -> None:
        value = report()
        value["candidate_image"] = PRIOR
        safe, failures = self.validate(value)

        self.assertIsNone(safe)
        self.assertIn("rollback_candidate_identity_mismatch", failures)

    def test_production_tag_change_fails_even_if_canary_rollback_succeeds(self) -> None:
        value = report()
        value["production_after"]["image"] = PRIOR
        safe, failures = self.validate(value)

        self.assertIsNone(safe)
        self.assertIn("production_image_changed_during_canary_rollback", failures)

    def test_rollback_must_return_to_the_observed_pre_candidate_image(self) -> None:
        value = report()
        value["canary_after_rollback"]["image"] = CANDIDATE
        safe, failures = self.validate(value)

        self.assertIsNone(safe)
        self.assertIn("rollback_target_readback_mismatch", failures)

    def test_unhealthy_or_out_of_window_readbacks_fail_closed(self) -> None:
        value = copy.deepcopy(report())
        value["canary_after_rollback"]["ready"] = False
        safe, failures = self.validate(value)
        self.assertIsNone(safe)
        self.assertIn("rollback_readback_unhealthy", failures)

        value = copy.deepcopy(report())
        value["production_before"]["observed_at"] = "2026-10-01T09:59:00Z"
        safe, failures = self.validate(value)
        self.assertIsNone(safe)
        self.assertIn("rollback_readback_outside_window", failures)


if __name__ == "__main__":
    unittest.main()
