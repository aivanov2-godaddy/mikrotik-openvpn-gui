from __future__ import annotations

from datetime import datetime, timezone
import unittest

from scripts.stream_acceptance import (
    CANARY_ORIGIN,
    VERIFICATION_FIELDS,
    browser_acceptance_projection,
    validate_stream_acceptance,
)


START = "2026-10-02T10:00:00Z"
END = "2026-10-02T10:30:00Z"
NOW = datetime(2026, 10, 2, 10, 31, tzinfo=timezone.utc)


def reports() -> tuple[dict[str, object], dict[str, object]]:
    observer = {
        "format": "vpn-dashboard-telemetry-stream-observation-v1",
        "started_at": START,
        "ended_at": END,
        "duration_seconds": 1800,
        "origin_role": "canary",
        "origin": CANARY_ORIGIN,
        "candidate_revision": "a" * 40,
        "observed_revision": "a" * 40,
        "transport": "socketio-websocket",
        "connections": 2,
        "disconnects": 1,
        "reconnects": 1,
        "stream_connected_at_end": True,
        "event_count": 3,
        "event_counts": {"telemetry.snapshot": 2, "vpn.session.updated": 1},
        "snapshot_count": 2,
        "reconnect_snapshot_count": 1,
        "sequence_gaps": 0,
        "duplicate_sequences": 0,
        "out_of_order_sequences": 0,
        "rejected_frames": 0,
        "raw_frames_written": False,
        "identities_or_addresses_written": False,
        "credentials_written": False,
        "latency_measured": False,
        "latency_note": "not measured; client/server clock offset is not established",
        "failed_gates": [],
        "observed_stream_healthy": True,
    }
    browser = {
        "format": "vpn-dashboard-telemetry-acceptance-v2",
        "origin": CANARY_ORIGIN,
        "candidate_revision": "a" * 40,
        "observed_revision": "a" * 40,
        "identity_verified": True,
        "healthy": True,
        "failed_gates": [],
        "observation_started_at": START,
        "observation_ended_at": END,
        "session_transition_count": 2,
        "session_transition_visible_count": 2,
        "connected_transition_observed": True,
        "disconnected_transition_observed": True,
        "ordered_connect_disconnect_observed": True,
        "session_event_latency_p95_ms": 450,
        "session_event_age_max_seconds": 0.8,
        "traffic_update_count": 2,
        "traffic_update_visible_count": 2,
        "traffic_sample_age_max_seconds": 1.2,
        "event_sequence_observation_count": 30,
        "event_sequence_gap_count": 0,
        "duplicate_event_count": 0,
        "out_of_order_event_count": 0,
        "reconnect_test_count": 1,
        "reconnect_success_count": 1,
        "security_tests": 1,
        "verification": {name: True for name in VERIFICATION_FIELDS},
    }
    return observer, browser


class StreamAcceptanceTests(unittest.TestCase):
    def validate(self, observer: object, browser: object) -> tuple[dict[str, object], list[str]]:
        return validate_stream_acceptance(
            observer,
            browser,
            collection_started_at=START,
            collection_ended_at=END,
            now=NOW,
            expected_candidate_revision="a" * 40,
        )

    def test_complete_redacted_browser_and_stream_evidence_passes(self) -> None:
        safe, failures = self.validate(*reports())
        self.assertEqual(failures, [])
        self.assertEqual(safe["format"], "vpn-dashboard-stream-acceptance-v2")
        self.assertEqual(safe["stream_observation"]["reconnect_snapshot_count"], 1)
        self.assertEqual(safe["browser_telemetry"]["session_event_latency_p95_ms"], 450)
        self.assertEqual(safe["browser_telemetry"]["security_tests"], 1)
        self.assertEqual(safe["browser_telemetry"]["verification"], {name: True for name in VERIFICATION_FIELDS})

    def test_self_declared_browser_identity_fails_without_independent_readyz_binding(self) -> None:
        observer, browser = reports()
        browser["identity_verified"] = False

        _safe, failures = self.validate(observer, browser)

        self.assertIn("browser_candidate_identity_mismatch", failures)

    def test_missing_reports_fail_closed(self) -> None:
        _, failures = self.validate(None, None)
        self.assertIn("stream_observation_missing", failures)
        self.assertIn("browser_telemetry_evidence_missing", failures)

    def test_stale_or_outside_window_reports_fail(self) -> None:
        observer, browser = reports()
        observer["ended_at"] = "2026-10-02T09:59:00Z"
        browser["observation_ended_at"] = "2026-10-02T10:31:00Z"
        _, failures = self.validate(observer, browser)
        self.assertIn("stream_observation_window_invalid", failures)
        self.assertIn("browser_telemetry_window_invalid", failures)

        observer, browser = reports()
        safe, failures = validate_stream_acceptance(
            observer, browser, collection_started_at=START, collection_ended_at=END,
            now=datetime(2026, 10, 2, 10, 46, tzinfo=timezone.utc),
            expected_candidate_revision="a" * 40,
        )
        self.assertIn("stream_observation_stale", failures)
        self.assertIn("browser_telemetry_stale", failures)
        self.assertNotIn("PRIVATE", str(safe))

    def test_shorter_subwindow_does_not_match_a_longer_release_collection(self) -> None:
        observer, browser = reports()
        _, failures = validate_stream_acceptance(
            observer,
            browser,
            collection_started_at=START,
            collection_ended_at="2026-10-02T11:00:00Z",
            now=NOW,
            expected_candidate_revision="a" * 40,
        )
        self.assertIn("stream_observation_window_invalid", failures)
        self.assertIn("browser_telemetry_window_invalid", failures)

    def test_stream_gaps_duplicates_and_missing_reconnect_snapshot_fail(self) -> None:
        observer, browser = reports()
        observer["sequence_gaps"] = 1
        observer["duplicate_sequences"] = 2
        observer["reconnect_snapshot_count"] = 0
        _, failures = self.validate(observer, browser)
        self.assertIn("stream_sequence_integrity_failed", failures)
        self.assertIn("stream_reconnect_snapshot_missing", failures)

    def test_browser_latency_freshness_visibility_and_reconnect_fail_closed(self) -> None:
        observer, browser = reports()
        browser["session_event_latency_p95_ms"] = None
        browser["session_event_age_max_seconds"] = 2.01
        browser["traffic_sample_age_max_seconds"] = 2.01
        browser["session_transition_visible_count"] = 1
        browser["reconnect_success_count"] = 0
        _, failures = self.validate(observer, browser)
        self.assertIn("browser_event_latency_missing", failures)
        self.assertIn("browser_session_event_stale", failures)
        self.assertIn("browser_traffic_sample_stale", failures)
        self.assertIn("browser_session_visibility_incomplete", failures)
        self.assertIn("browser_reconnect_evidence_failed", failures)

    def test_browser_duplicate_and_gap_evidence_fail_closed(self) -> None:
        observer, browser = reports()
        browser["event_sequence_gap_count"] = 1
        browser["duplicate_event_count"] = 1
        _, failures = self.validate(observer, browser)
        self.assertIn("browser_event_integrity_failed", failures)

    def test_browser_future_dated_metrics_and_unordered_transitions_fail_closed(self) -> None:
        observer, browser = reports()
        browser["session_event_latency_p95_ms"] = -1
        browser["session_event_age_max_seconds"] = -0.01
        browser["traffic_sample_age_max_seconds"] = -0.01
        browser["ordered_connect_disconnect_observed"] = False
        _, failures = self.validate(observer, browser)
        self.assertIn("browser_event_latency_invalid", failures)
        self.assertIn("browser_session_event_future_dated", failures)
        self.assertIn("browser_traffic_sample_future_dated", failures)
        self.assertIn("browser_session_visibility_incomplete", failures)

    def test_unknown_fields_are_rejected_and_never_copied(self) -> None:
        observer, browser = reports()
        browser["session_name"] = "PRIVATE-SENTINEL"
        safe, failures = self.validate(observer, browser)
        self.assertIn("browser_telemetry_schema_invalid", failures)
        self.assertNotIn("PRIVATE-SENTINEL", str(safe))

    def test_stream_origin_and_runtime_revision_must_match_candidate(self) -> None:
        observer, browser = reports()
        observer["origin"] = "https://vpn-dev.attacker.example"
        observer["observed_revision"] = "b" * 40
        safe, failures = self.validate(observer, browser)
        self.assertIn("stream_candidate_identity_mismatch", failures)
        self.assertIsNone(safe["stream_observation"]["origin"])
        self.assertEqual(safe["stream_observation"]["observed_revision"], "b" * 40)

    def test_browser_evidence_must_be_bound_to_the_canary_candidate(self) -> None:
        observer, browser = reports()
        browser["origin"] = "https://vpn.wanted.sx"
        browser["observed_revision"] = "b" * 40

        safe, failures = self.validate(observer, browser)

        self.assertIn("browser_candidate_identity_mismatch", failures)
        self.assertIsNone(safe["browser_telemetry"]["origin"])
        self.assertEqual(safe["browser_telemetry"]["observed_revision"], "b" * 40)

    def test_browser_projection_keeps_only_allowlisted_verification_details(self) -> None:
        projection = browser_acceptance_projection({
            "format": "vpn-dashboard-telemetry-acceptance-v2",
            "security_tests": 2,
            "verification": {**{name: True for name in VERIFICATION_FIELDS}, "private": "secret"},
            "private": "PRIVATE-SENTINEL",
        })
        self.assertEqual(projection["security_tests"], 2)
        self.assertEqual(projection["verification"], {name: True for name in VERIFICATION_FIELDS})
        self.assertNotIn("PRIVATE-SENTINEL", str(projection))

    def test_missing_or_false_verification_details_fail_closed(self) -> None:
        observer, browser = reports()
        browser["verification"]["secret_scan_complete"] = False
        _, failures = self.validate(observer, browser)
        self.assertIn("browser_security_verification_incomplete", failures)

        observer, browser = reports()
        browser.pop("verification")
        _, failures = self.validate(observer, browser)
        self.assertIn("browser_security_verification_incomplete", failures)

    def test_failed_stream_and_browser_evaluations_cannot_be_overridden(self) -> None:
        observer, browser = reports()
        observer["observed_stream_healthy"] = False
        observer["failed_gates"] = ["stream_observation_failed"]
        browser["healthy"] = False
        browser["failed_gates"] = ["event_loss"]
        _, failures = self.validate(observer, browser)
        self.assertIn("stream_observation_failed", failures)
        self.assertIn("browser_telemetry_failed", failures)


if __name__ == "__main__":
    unittest.main()
