from __future__ import annotations

import copy
import json
from pathlib import Path
import unittest

from scripts.rollback_acceptance import REPORT_FORMAT, summarize_rollback_report, validate_rollback_report


REVISION = "a" * 40
DIGEST = "sha256:" + "b" * 64
PRIOR_DIGEST = "sha256:" + "c" * 64
CANDIDATE = f"ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-{REVISION}-arm64@{DIGEST}"
PRIOR = f"ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-{'c' * 40}-arm64@{PRIOR_DIGEST}"
START = "2026-10-02T10:00:00Z"
END = "2026-10-02T10:30:00Z"


def readback(environment: str, observed_at: str, image: str) -> dict[str, object]:
    image_revision = image.split(":sha-", 1)[1].split("-arm64", 1)[0]
    canary_revision = image_revision if environment == "canary" else "c" * 40
    production_revision = image_revision if environment == "production" else REVISION
    return {
        "environment": environment,
        "observed_at": observed_at,
        "image": image,
        "healthy": True,
        "ready": True,
        "source": {
            "collector": "authenticated-routeros-api-rest-readyz-v1",
            "captured_at": observed_at,
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
        },
    }


def report() -> dict[str, object]:
    return {
        "format": REPORT_FORMAT,
        "candidate_image": CANDIDATE,
        "candidate_digest": DIGEST,
        "production_before": readback("production", "2026-10-02T09:50:00Z", CANDIDATE),
        "canary_before": readback("canary", "2026-10-02T09:51:00Z", PRIOR),
        "canary_candidate": readback("canary", "2026-10-02T09:52:00Z", CANDIDATE),
        "canary_after_rollback": readback("canary", "2026-10-02T09:53:00Z", PRIOR),
        "production_after": readback("production", "2026-10-02T09:54:00Z", CANDIDATE),
        "canary_candidate_restored": readback("canary", "2026-10-02T09:55:00Z", CANDIDATE),
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
        self.assertEqual(safe["evidence_basis"], "operator-attested-unsigned")
        self.assertTrue(safe["production_unchanged"])
        self.assertEqual(safe["rollback_target_image"], PRIOR)
        self.assertIs(safe["router_runtime_digest_verified"], False)
        self.assertTrue(safe["candidate_restored_before_soak"])
        self.assertEqual(safe["readbacks"]["canary_after_rollback"]["revision"], "c" * 40)

    def test_documented_example_matches_the_source_bound_schema(self) -> None:
        example_path = Path(__file__).resolve().parents[1] / "docs" / "rollback-rehearsal-evidence.example.json"
        value = json.loads(example_path.read_text(encoding="utf-8"))

        validated, failures = validate_rollback_report(
            value,
            candidate_image=value["candidate_image"],
            candidate_digest=value["candidate_digest"],
            production_image=value["production_before"]["image"],
            collection_started_at="2026-10-19T12:00:00Z",
            collection_ended_at="2026-10-19T12:30:00Z",
        )

        self.assertEqual(failures, [])
        self.assertIsNotNone(validated)

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
            value[name]["source"]["captured_at"] = "2026-09-30T09:00:00Z"

        safe, failures = self.validate(value)

        self.assertIsNone(safe)
        self.assertIn("rollback_readback_outside_window", failures)

        value = report()
        value["production_after"]["observed_at"] = "2026-10-02T10:00:01Z"
        value["production_after"]["source"]["captured_at"] = "2026-10-02T10:00:01Z"
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
        value["production_before"]["source"]["captured_at"] = "2026-10-01T09:59:00Z"
        safe, failures = self.validate(value)
        self.assertIsNone(safe)
        self.assertIn("rollback_readback_outside_window", failures)

    def test_manual_or_unbound_readback_is_rejected(self) -> None:
        value = report()
        value["canary_candidate"]["source"].pop("rest_parity_verified")

        safe, failures = self.validate(value)

        self.assertIsNone(safe)
        self.assertIn("rollback_readback_invalid", failures)

    def test_production_state_is_bound_across_every_checkpoint(self) -> None:
        value = report()
        value["canary_candidate"]["source"]["production_revision"] = "e" * 40

        safe, failures = self.validate(value)

        self.assertIsNone(safe)
        self.assertIn("production_image_changed_during_canary_rollback", failures)


if __name__ == "__main__":
    unittest.main()
