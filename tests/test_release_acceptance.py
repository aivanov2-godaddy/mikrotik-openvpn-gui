from __future__ import annotations

import io
import json
import sys
import unittest
from contextlib import redirect_stdout
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from scripts.release_acceptance import evaluate, main
from scripts.redis_recovery_acceptance import (
    REPORT_FORMAT as REDIS_RECOVERY_FORMAT,
    REQUIRED_TEST_NAMES,
    CI_REPOSITORY,
    CI_WORKFLOW_PATH,
    report_projection_sha256,
    validate_report as validate_redis_report,
)
from scripts.rollback_acceptance import REPORT_FORMAT as ROLLBACK_REPORT_FORMAT


def image_ref(revision: str, digest: str = "sha256:" + "b" * 64) -> str:
    return f"ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-{revision}-arm64@{digest}"


class ReleaseAcceptanceTests(unittest.TestCase):
    NOW = datetime(2026, 10, 2, 10, 31, tzinfo=timezone.utc)

    @staticmethod
    def _rollback_readbacks(revision: str, digest: str, production_image: str) -> dict[str, object]:
        candidate = image_ref(revision, digest)
        prior = image_ref("c" * 40, "sha256:" + "f" * 64)

        def readback(environment: str, observed_at: str, image: str) -> dict[str, object]:
            observed_revision = image.split(":sha-", 1)[1].split("-arm64", 1)[0]
            production_revision = production_image.split(":sha-", 1)[1].split("-arm64", 1)[0]
            canary_revision = observed_revision if environment == "canary" else prior.split(":sha-", 1)[1].split("-arm64", 1)[0]
            return {
                "environment": environment, "observed_at": observed_at,
                "image": image, "healthy": True, "ready": True,
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

        return {
            "format": ROLLBACK_REPORT_FORMAT,
            "candidate_image": candidate,
            "candidate_digest": digest,
            "production_before": readback("production", "2026-10-02T09:50:00Z", production_image),
            "canary_before": readback("canary", "2026-10-02T09:51:00Z", prior),
            "canary_candidate": readback("canary", "2026-10-02T09:52:00Z", candidate),
            "canary_after_rollback": readback("canary", "2026-10-02T09:53:00Z", prior),
            "production_after": readback("production", "2026-10-02T09:54:00Z", production_image),
            "canary_candidate_restored": readback("canary", "2026-10-02T09:55:00Z", candidate),
        }

    @staticmethod
    def _routeros_resource_evidence() -> dict[str, object]:
        return {
            "format": "vpn-dashboard-routeros-acceptance-v3",
            "observation_started_at": "2026-10-02T10:00:10Z",
            "observation_ended_at": "2026-10-02T10:30:10Z",
            "sample_count": 31,
            "rest_parity_successful_sample_count": 31,
            "rest_parity_failed_sample_count": 0,
            "active_vpn_sessions_min": 0,
            "active_vpn_sessions_max": 1,
            "max_sample_gap_seconds": 60,
            "resource_peaks": {
                "router_cpu_peak_percent": 25,
                "router_memory_peak_percent": 40,
                "router_storage_peak_percent": 20,
            },
            "container_revisions_matched": True,
        }

    @staticmethod
    def _certificate_lifecycle_acceptance() -> dict[str, object]:
        revision = "a" * 40
        return {
            "format": "vpn-dashboard-certificate-lifecycle-acceptance-v1",
            "environment": "canary",
            "candidate_image": image_ref(revision),
            "candidate_digest": "sha256:" + "b" * 64,
            "replacement_tested_before_retirement": True,
            "replacement_tested_at": "2026-10-02T09:40:00Z",
            "failed_renewal_rollback_read_back_verified": True,
            "failed_renewal_rollback_read_back_at": "2026-10-02T09:41:00Z",
            "routeros_revocation_read_back_verified": True,
            "routeros_revocation_read_back_at": "2026-10-02T09:42:00Z",
            "crl_fresh_and_loaded_verified": True,
            "crl_fresh_loaded_at": "2026-10-02T09:43:00Z",
            "existing_session_read_back_verified": True,
            "existing_session_outcome": "remained_active",
            "existing_session_read_back_at": "2026-10-02T09:44:00Z",
            "fresh_connection_rejection_verified": True,
            "fresh_connection_rejection_at": "2026-10-02T09:45:00Z",
            "dashboard_status_distinctions_verified": True,
            "dashboard_status_distinctions_verified_at": "2026-10-02T09:46:00Z",
            "private_material_or_profile_contents_in_evidence": False,
            "raw_logs_in_evidence": False,
        }

    def setUp(self) -> None:
        revision = "a" * 40
        self.evidence = {
            "format": "vpn-dashboard-release-evidence-v2",
            "collection": {
                "format": "vpn-dashboard-release-collection-v2",
                "phase": "postpromotion",
                "passed": True,
                "failed_gates": [],
                "started_at": "2026-10-02T10:00:00Z",
                "ended_at": "2026-10-02T10:30:00Z",
                "browser_origin_readiness": {
                    "origin": "https://vpn-dev.wanted.sx",
                    "candidate_revision": revision,
                    "observed_revision": revision,
                    "observation_started_at": "2026-10-02T10:00:00Z",
                    "observation_ended_at": "2026-10-02T10:30:00Z",
                    "ready_sample_count": 31,
                    "matching_sample_count": 31,
                    "all_samples_ready_for_candidate": True,
                },
                "certificate_lifecycle_acceptance": self._certificate_lifecycle_acceptance(),
                "registry_digest_verification": [
                    {
                        "environment": environment,
                        "image": image_ref(revision),
                        "expected_digest": "sha256:" + "b" * 64,
                        "observed_digest": "sha256:" + "b" * 64,
                        "verified": True,
                    }
                    for environment in ("canary", "production")
                ],
                "redis_recovery_verification": {
                    "format": REDIS_RECOVERY_FORMAT,
                    "source_revision": revision,
                    "started_at": "2026-10-01T23:50:00Z",
                    "ended_at": "2026-10-01T23:51:00Z",
                    "test_results": {name: "passed" for name in REQUIRED_TEST_NAMES},
                    "scope": "source-integration-tests",
                    "runtime_image_digest_verified": False,
                    "ci_provenance": {
                        "repository": CI_REPOSITORY,
                        "workflow_path": CI_WORKFLOW_PATH,
                        "event": "push",
                        "branch": "main",
                        "status": "completed",
                        "conclusion": "success",
                        "head_sha": revision,
                        "run_id": "123456789",
                        "artifact_id": "987654321",
                        "artifact_name": f"redis-recovery-{revision}",
                        "attestation_verified_during_collection": True,
                        "report_sha256": "d" * 64,
                    },
                },
                "rollback_rehearsal": self._rollback_readbacks(
                    revision, "sha256:" + "b" * 64, image_ref(revision)
                ),
                "sqlite_restore_verification": {
                    "format": "vpn-dashboard-sqlite-restore-verification-v3",
                    "checks": [
                        {
                            "environment": environment,
                            "candidate_image": image_ref(revision),
                            "candidate_revision": revision,
                            "candidate_digest": "sha256:" + "b" * 64,
                            "checked_at": "2026-10-02T10:24:00Z",
                            "verified": True,
                            "source_opened_read_only": True,
                            "restored_integrity": True,
                            "required_schema_present": True,
                            "restored_data_counts_match": True,
                            "temporary_copy_removed": True,
                            "failure_code": None,
                        }
                        for environment in ("canary", "production")
                    ],
                },
                "routeros_resource_evidence": self._routeros_resource_evidence(),
            },
            "deployments": [
                {
                    "environment": environment,
                    "image": image_ref(revision),
                    "digest": "sha256:" + "b" * 64,
                    "container_healthy": True,
                    "app_ready": True,
                    "transport": "asgi-websocket",
                    "rest_fallback": True,
                    "redis_configured": True,
                    "redis_publish_verified": True,
                    "reconnect_recovered": True,
                    "snapshot_recovered": True,
                    "reconnect_recovery_counter_delta": 1,
                    "reconnect_recovery_counter_reset": False,
                    "reconnect_observed_at": 1790935500,
                    "full_snapshot_recovered_at": 1790935801,
                    "sqlite_restore_verified": True,
                    "sqlite_restore_verified_at": "2026-10-02T10:24:00Z",
                    "rollback_drill_passed": True,
                    "rollback_drill_at": "2026-10-02T10:26:00Z",
                    "production_untouched_on_canary_failure": True,
                    "production_protection_observed_at": "2026-10-02T10:27:00Z",
                    "session_event_p95_ms": 450,
                    "session_event_max_ms": 650,
                    "session_event_latency_started_at": "2026-10-02T10:10:00Z",
                    "session_event_latency_ended_at": "2026-10-02T10:20:00Z",
                    "session_event_max_age_seconds": 0.5,
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
        redis_report = self.evidence["collection"]["redis_recovery_verification"]
        raw_redis_report = dict(redis_report)
        raw_redis_report.pop("ci_provenance")
        safe_redis_report, redis_failures = validate_redis_report(
            raw_redis_report, expected_revision=revision, now=self.NOW
        )
        if redis_failures or safe_redis_report is None:
            raise AssertionError("release test Redis report fixture is invalid")
        redis_report["ci_provenance"]["report_sha256"] = report_projection_sha256(safe_redis_report)
        from scripts.stream_acceptance import CANARY_ORIGIN, VERIFICATION_FIELDS, validate_stream_acceptance

        start = "2026-10-02T10:00:00Z"
        end = "2026-10-02T10:30:00Z"
        observer = {
            "format": "vpn-dashboard-telemetry-stream-observation-v1",
            "started_at": start, "ended_at": end, "duration_seconds": 1800,
            "origin_role": "canary", "origin": CANARY_ORIGIN,
            "candidate_revision": revision, "observed_revision": revision,
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
        browser = {
            "format": "vpn-dashboard-telemetry-acceptance-v3", "healthy": True,
            "origin": "https://vpn-dev.wanted.sx",
            "candidate_revision": revision, "observed_revision": revision,
            "identity_verified": True,
            "failed_gates": [], "observation_started_at": start,
            "observation_ended_at": end, "session_transition_count": 2,
            "session_transition_visible_count": 2, "connected_transition_observed": True,
            "disconnected_transition_observed": True,
            "ordered_connect_disconnect_observed": True,
            "session_event_latency_p95_ms": 450,
            "session_event_latency_max_ms": 650,
            "session_event_age_max_seconds": 0.5,
            "traffic_update_count": 2, "traffic_update_visible_count": 2,
            "traffic_sample_age_max_seconds": 1.2, "event_sequence_observation_count": 30,
            "event_sequence_gap_count": 0, "duplicate_event_count": 0,
            "out_of_order_event_count": 0, "reconnect_test_count": 1,
            "reconnect_success_count": 1,
            "security_tests": 1,
            "verification": {name: True for name in VERIFICATION_FIELDS},
        }
        safe_stream, failures = validate_stream_acceptance(
            observer, browser, collection_started_at=start, collection_ended_at=end,
            now=self.NOW, expected_candidate_revision=revision,
        )
        self.assertEqual(failures, [])
        self.evidence["collection"]["stream_acceptance"] = safe_stream

    def test_matching_healthy_canary_and_production_pass(self) -> None:
        code, report = evaluate(self.evidence, now=self.NOW)
        self.assertEqual(code, 0)
        self.assertTrue(report["passed"])
        self.assertEqual(report["deployments"][0]["digest"], "sha256:" + "b" * 64)
        self.assertNotIn("details", report["deployments"][0])
        self.assertTrue(report["registry_tag_digests_verified"])
        self.assertFalse(report["router_runtime_digest_verified"])
        self.assertEqual(report["stream_acceptance"]["format"], "vpn-dashboard-stream-acceptance-v3")
        self.assertEqual(
            report["evidence_authenticity"],
            {
                "redis_recovery": "github-attestation-claim-verified-during-collection-not-reverified-offline",
                "rollback_readbacks": "operator-attested-unsigned",
                "final_report": "unsigned-local-report",
            },
        )
        self.assertEqual(
            report["certificate_lifecycle_acceptance"]["candidate_digest"],
            self.evidence["deployments"][0]["digest"],
        )
        self.assertEqual(
            report["certificate_lifecycle_acceptance"]["evidence_provenance"],
            "operator_attested",
        )
        self.assertFalse(report["certificate_lifecycle_acceptance"]["independently_observed"])

    def test_passing_collection_requires_joined_routeros_soak_evidence(self) -> None:
        evidence = deepcopy(self.evidence)
        del evidence["collection"]["routeros_resource_evidence"]

        code, report = evaluate(evidence, now=self.NOW)

        self.assertEqual(code, 1)
        self.assertFalse(report["promotion_eligible"])
        self.assertFalse(report["production_accepted"])
        self.assertIn("routeros_resource_evidence_missing", report["failed_gates"])

    def test_routeros_resource_evidence_is_preserved_only_when_it_matches_the_soak(self) -> None:
        evidence = deepcopy(self.evidence)
        evidence["collection"]["routeros_resource_evidence"] = {
            "format": "vpn-dashboard-routeros-acceptance-v3",
            "observation_started_at": "2026-10-02T10:00:10Z",
            "observation_ended_at": "2026-10-02T10:30:10Z",
            "sample_count": 31,
            "rest_parity_successful_sample_count": 31,
            "rest_parity_failed_sample_count": 0,
            "active_vpn_sessions_min": 0,
            "active_vpn_sessions_max": 1,
            "max_sample_gap_seconds": 60,
            "resource_peaks": {
                "router_cpu_peak_percent": 25,
                "router_memory_peak_percent": 40,
                "router_storage_peak_percent": 20,
            },
            "container_revisions_matched": True,
        }

        code, report = evaluate(evidence, now=self.NOW)

        self.assertEqual(code, 0)
        self.assertEqual(report["routeros_resource_evidence"]["sample_count"], 31)
        self.assertEqual(report["routeros_resource_evidence"]["rest_parity_successful_sample_count"], 31)
        self.assertEqual(report["routeros_resource_evidence"]["resource_peaks"]["router_cpu_peak_percent"], 25)

        evidence["collection"]["routeros_resource_evidence"]["observation_ended_at"] = "2026-10-02T10:31:11Z"
        code, report = evaluate(evidence, now=self.NOW)
        self.assertEqual(code, 1)
        self.assertIn("routeros_resource_evidence_invalid", report["failed_gates"])

        evidence = deepcopy(self.evidence)
        evidence["collection"]["routeros_resource_evidence"] = {
            "format": "vpn-dashboard-routeros-acceptance-v3",
            "observation_started_at": "2026-10-02T10:00:10Z",
            "observation_ended_at": "2026-10-02T10:30:10Z",
            "sample_count": 31,
            "rest_parity_successful_sample_count": 30,
            "rest_parity_failed_sample_count": 1,
            "active_vpn_sessions_min": 0,
            "active_vpn_sessions_max": 1,
            "max_sample_gap_seconds": 60,
            "resource_peaks": {
                "router_cpu_peak_percent": 25,
                "router_memory_peak_percent": 40,
                "router_storage_peak_percent": 20,
            },
            "container_revisions_matched": True,
        }
        code, report = evaluate(evidence, now=self.NOW)
        self.assertEqual(code, 1)
        self.assertIn("routeros_resource_evidence_invalid", report["failed_gates"])

    def test_routeros_soak_without_any_active_vpn_session_fails(self) -> None:
        evidence = deepcopy(self.evidence)
        evidence["collection"]["routeros_resource_evidence"] = self._routeros_resource_evidence()
        evidence["collection"]["routeros_resource_evidence"]["active_vpn_sessions_max"] = 0

        code, report = evaluate(evidence, now=self.NOW)

        self.assertEqual(code, 1)
        self.assertIn("vpn_test_session_not_observed", report["failed_gates"])

    def test_failed_live_collection_cannot_be_overridden_by_deployment_claims(self) -> None:
        evidence = deepcopy(self.evidence)
        evidence["collection"] = {
            "format": "vpn-dashboard-release-collection-v2",
            "phase": "postpromotion",
            "passed": False,
            "failed_gates": ["canary_traffic_sample_stale"],
            "started_at": "2026-10-02T10:00:00Z",
            "ended_at": "2026-10-02T10:30:00Z",
            "registry_digest_verification": deepcopy(self.evidence["collection"]["registry_digest_verification"]),
        }

        code, report = evaluate(evidence, now=self.NOW)

        self.assertEqual(code, 1)
        self.assertFalse(report["passed"])
        self.assertIn("live_collection_failed", report["failed_gates"])
        self.assertIn("redis_recovery_ci_evidence_missing", report["failed_gates"])
        self.assertIn("rollback_readback_evidence_missing", report["failed_gates"])

    def test_passing_live_collection_is_accepted_and_malformed_collection_is_rejected(self) -> None:
        evidence = deepcopy(self.evidence)
        evidence["collection"] = {
            "format": "vpn-dashboard-release-collection-v2",
            "phase": "postpromotion",
            "passed": True,
            "failed_gates": [],
            "started_at": "2026-10-02T10:00:00Z",
            "ended_at": "2026-10-02T10:30:00Z",
            "browser_origin_readiness": deepcopy(self.evidence["collection"]["browser_origin_readiness"]),
            "registry_digest_verification": deepcopy(self.evidence["collection"]["registry_digest_verification"]),
            "redis_recovery_verification": deepcopy(self.evidence["collection"]["redis_recovery_verification"]),
            "rollback_rehearsal": deepcopy(self.evidence["collection"]["rollback_rehearsal"]),
            "sqlite_restore_verification": deepcopy(
                self.evidence["collection"]["sqlite_restore_verification"]
            ),
            "routeros_resource_evidence": self._routeros_resource_evidence(),
            "certificate_lifecycle_acceptance": self._certificate_lifecycle_acceptance(),
            "stream_acceptance": deepcopy(self.evidence["collection"]["stream_acceptance"]),
        }
        code, report = evaluate(evidence, now=self.NOW)
        self.assertEqual(code, 0)
        self.assertTrue(report["passed"])

        evidence["collection"]["passed"] = "true"
        with self.assertRaisesRegex(ValueError, "passed must be boolean"):
            evaluate(evidence, now=self.NOW)

    def test_certificate_lifecycle_evidence_is_required_and_candidate_bound(self) -> None:
        evidence = deepcopy(self.evidence)
        del evidence["collection"]["certificate_lifecycle_acceptance"]
        code, report = evaluate(evidence, now=self.NOW)
        self.assertEqual(code, 1)
        self.assertFalse(report["promotion_eligible"])
        self.assertIn("certificate_lifecycle_acceptance_missing", report["failed_gates"])

        evidence = deepcopy(self.evidence)
        evidence["collection"]["certificate_lifecycle_acceptance"]["candidate_digest"] = (
            "sha256:" + "c" * 64
        )
        code, report = evaluate(evidence, now=self.NOW)
        self.assertEqual(code, 1)
        self.assertIn("certificate_lifecycle_acceptance_invalid", report["failed_gates"])

        evidence = deepcopy(self.evidence)
        evidence["collection"]["certificate_lifecycle_acceptance"]["candidate_image"] = (
            "ghcr.io/example/vpn:sha-" + "c" * 40 + "-arm64"
        )
        code, report = evaluate(evidence, now=self.NOW)
        self.assertEqual(code, 1)
        self.assertIn("certificate_lifecycle_acceptance_invalid", report["failed_gates"])

    def test_certificate_lifecycle_evidence_rejects_bad_sequence_staleness_and_extra_data(self) -> None:
        evidence = deepcopy(self.evidence)
        evidence["collection"]["certificate_lifecycle_acceptance"][
            "fresh_connection_rejection_at"
        ] = "2026-10-02T09:42:30Z"
        code, report = evaluate(evidence, now=self.NOW)
        self.assertEqual(code, 1)
        self.assertIn("certificate_lifecycle_acceptance_invalid", report["failed_gates"])

        evidence = deepcopy(self.evidence)
        evidence["collection"]["certificate_lifecycle_acceptance"]["replacement_tested_at"] = (
            "2026-10-01T09:59:00Z"
        )
        code, report = evaluate(evidence, now=self.NOW)
        self.assertEqual(code, 1)
        self.assertIn("certificate_lifecycle_acceptance_invalid", report["failed_gates"])

        evidence = deepcopy(self.evidence)
        evidence["collection"]["certificate_lifecycle_acceptance"]["certificate_serial"] = "redacted"
        code, report = evaluate(evidence, now=self.NOW)
        self.assertEqual(code, 1)
        self.assertIn("certificate_lifecycle_acceptance_invalid", report["failed_gates"])

    def test_passing_collection_requires_valid_same_window_stream_and_browser_evidence(self) -> None:
        evidence = deepcopy(self.evidence)
        del evidence["collection"]["stream_acceptance"]
        code, report = evaluate(evidence, now=self.NOW)
        self.assertEqual(code, 1)
        self.assertIn("stream_acceptance_missing_or_invalid", report["failed_gates"])

        evidence = deepcopy(self.evidence)
        evidence["collection"]["stream_acceptance"]["browser_telemetry"][
            "observation_ended_at"
        ] = "2026-10-02T09:00:00Z"
        code, report = evaluate(evidence, now=self.NOW)
        self.assertEqual(code, 1)
        self.assertIn("browser_telemetry_window_invalid", report["failed_gates"])

    def test_missing_stale_and_future_collection_evidence_cannot_pass(self) -> None:
        evidence = deepcopy(self.evidence)
        del evidence["collection"]
        code, report = evaluate(evidence, now=self.NOW)
        self.assertEqual(code, 1)
        self.assertIn("live_collection_missing", report["failed_gates"])

        evidence = deepcopy(self.evidence)
        evidence["collection"].update({
            "started_at": "2026-10-02T09:30:00Z",
            "ended_at": "2026-10-02T10:00:00Z",
        })
        code, report = evaluate(evidence, now=self.NOW)
        self.assertEqual(code, 1)
        self.assertIn("live_collection_stale", report["failed_gates"])

        evidence = deepcopy(self.evidence)
        evidence["collection"].update({
            "started_at": "2026-10-02T10:30:00Z",
            "ended_at": "2026-10-02T11:00:00Z",
        })
        code, report = evaluate(evidence, now=self.NOW)
        self.assertEqual(code, 1)
        self.assertIn("live_collection_future_dated", report["failed_gates"])

    def test_mismatched_production_digest_fails_closed(self) -> None:
        production_digest = "sha256:" + "c" * 64
        production_image = image_ref("a" * 40, production_digest)
        self.evidence["deployments"][1]["image"] = production_image
        self.evidence["deployments"][1]["digest"] = production_digest
        self.evidence["collection"]["registry_digest_verification"][1].update({
            "image": production_image,
            "expected_digest": production_digest,
            "observed_digest": production_digest,
        })
        code, report = evaluate(self.evidence, now=self.NOW)
        self.assertEqual(code, 1)
        self.assertIn("canary_production_digest_mismatch", report["failed_gates"])

    def test_operator_recovery_claims_cannot_override_missing_reconnect_counter(self) -> None:
        evidence = deepcopy(self.evidence)
        evidence["deployments"][0]["reconnect_recovery_counter_delta"] = 0
        code, report = evaluate(evidence, now=self.NOW)
        self.assertEqual(code, 1)
        self.assertIn("canary_reconnect_recovery_failed", report["failed_gates"])

        evidence = deepcopy(self.evidence)
        del evidence["deployments"][0]["reconnect_recovery_counter_delta"]
        code, report = evaluate(evidence, now=self.NOW)
        self.assertEqual(code, 1)
        self.assertIn("canary_reconnect_recovery_failed", report["failed_gates"])

    def test_recovery_counter_reset_fails_closed(self) -> None:
        evidence = deepcopy(self.evidence)
        evidence["deployments"][0]["reconnect_recovery_counter_reset"] = True
        code, report = evaluate(evidence, now=self.NOW)
        self.assertEqual(code, 1)
        self.assertIn("canary_reconnect_recovery_failed", report["failed_gates"])

    def test_recovery_claims_require_same_window_ordered_timestamps(self) -> None:
        evidence = deepcopy(self.evidence)
        del evidence["deployments"][0]["reconnect_observed_at"]
        code, report = evaluate(evidence, now=self.NOW)
        self.assertEqual(code, 1)
        self.assertIn("canary_reconnect_recovery_failed", report["failed_gates"])

        evidence = deepcopy(self.evidence)
        evidence["deployments"][0]["full_snapshot_recovered_at"] = 1790935499
        code, report = evaluate(evidence, now=self.NOW)
        self.assertEqual(code, 1)
        self.assertIn("canary_reconnect_recovery_failed", report["failed_gates"])

        evidence = deepcopy(self.evidence)
        evidence["deployments"][0]["reconnect_observed_at"] = 1790934000
        code, report = evaluate(evidence, now=self.NOW)
        self.assertEqual(code, 1)
        self.assertIn("canary_reconnect_recovery_failed", report["failed_gates"])

    def test_stale_or_missing_session_event_age_fails_closed(self) -> None:
        for age in (2.01, None):
            with self.subTest(age=age):
                evidence = deepcopy(self.evidence)
                evidence["deployments"][0]["session_event_max_age_seconds"] = age
                code, report = evaluate(evidence, now=self.NOW)
                self.assertEqual(code, 1)
                self.assertIn("canary_session_event_stale", report["failed_gates"])

    def test_any_session_event_over_one_second_fails_even_when_p95_passes(self) -> None:
        evidence = deepcopy(self.evidence)
        evidence["deployments"][0]["session_event_p95_ms"] = 900
        evidence["deployments"][0]["session_event_max_ms"] = 1001

        code, report = evaluate(evidence, now=self.NOW)

        self.assertEqual(code, 1)
        self.assertIn("canary_session_event_latency_max_exceeded", report["failed_gates"])

    def test_manual_latency_restore_and_rollback_evidence_must_be_fresh(self) -> None:
        evidence = deepcopy(self.evidence)
        evidence["deployments"][0]["session_event_p95_ms"] = None
        evidence["deployments"][0]["session_event_max_ms"] = None
        code, report = evaluate(evidence, now=self.NOW)
        self.assertEqual(code, 1)
        self.assertIn("canary_session_event_latency_unobserved", report["failed_gates"])

        evidence = deepcopy(self.evidence)
        evidence["deployments"][0]["session_event_latency_ended_at"] = "2026-10-02T10:31:00Z"
        code, report = evaluate(evidence, now=self.NOW)
        self.assertEqual(code, 1)
        self.assertIn("canary_session_event_latency_evidence_stale_or_outside_window", report["failed_gates"])

        evidence = deepcopy(self.evidence)
        evidence["deployments"][0]["sqlite_restore_verified_at"] = "2026-09-30T10:24:00Z"
        evidence["deployments"][0]["rollback_drill_at"] = "2026-09-30T10:26:00Z"
        evidence["deployments"][0]["production_protection_observed_at"] = "2026-09-30T10:27:00Z"
        evidence["collection"]["rollback_rehearsal"]["canary_after_rollback"][
            "observed_at"
        ] = "2026-09-30T10:26:00Z"
        evidence["collection"]["rollback_rehearsal"]["production_after"][
            "observed_at"
        ] = "2026-09-30T10:27:00Z"
        code, report = evaluate(evidence, now=self.NOW)
        self.assertEqual(code, 1)
        self.assertIn("canary_sqlite_restore_evidence_stale_or_outside_window", report["failed_gates"])
        self.assertIn("canary_rollback_evidence_stale_or_outside_window", report["failed_gates"])
        self.assertIn("production_protection_evidence_stale_or_outside_window", report["failed_gates"])

    def test_recent_manual_exercises_before_the_soak_are_accepted(self) -> None:
        evidence = deepcopy(self.evidence)
        canary = evidence["deployments"][0]
        canary["session_event_latency_started_at"] = "2026-10-02T09:50:00Z"
        canary["session_event_latency_ended_at"] = "2026-10-02T09:55:00Z"
        canary["sqlite_restore_verified_at"] = "2026-10-02T09:30:00Z"
        evidence["collection"]["sqlite_restore_verification"]["checks"][0][
            "checked_at"
        ] = "2026-10-02T09:30:00Z"
        canary["rollback_drill_at"] = "2026-10-02T09:40:00Z"
        canary["production_protection_observed_at"] = "2026-10-02T09:41:00Z"
        code, report = evaluate(evidence, now=self.NOW)
        self.assertEqual(code, 0, report["failed_gates"])

    def test_unverified_registry_digest_fails_closed(self) -> None:
        verification = self.evidence["collection"]["registry_digest_verification"][0]
        verification["observed_digest"] = "sha256:" + "c" * 64
        verification["verified"] = False

        code, report = evaluate(self.evidence, now=self.NOW)

        self.assertEqual(code, 1)
        self.assertIn("canary_registry_digest_unverified", report["failed_gates"])

    def test_missing_restore_rehearsal_result_fails_closed_despite_true_input_flags(self) -> None:
        del self.evidence["collection"]["sqlite_restore_verification"]

        code, report = evaluate(self.evidence, now=self.NOW)

        self.assertEqual(code, 1)
        self.assertIn("sqlite_restore_verification_missing", report["failed_gates"])

    def test_inconsistent_restore_rehearsal_result_is_rejected(self) -> None:
        self.evidence["collection"]["sqlite_restore_verification"]["checks"][0][
            "restored_integrity"
        ] = False

        code, report = evaluate(self.evidence, now=self.NOW)

        self.assertEqual(code, 1)
        self.assertIn("sqlite_restore_verification_invalid", report["failed_gates"])
        self.assertIsNone(report["sqlite_restore_verification"])

    def test_restore_report_must_match_candidate_image_revision_and_digest(self) -> None:
        check = self.evidence["collection"]["sqlite_restore_verification"]["checks"][0]
        check["candidate_revision"] = "c" * 40

        code, report = evaluate(self.evidence, now=self.NOW)

        self.assertEqual(code, 1)
        self.assertIn("sqlite_restore_verification_invalid", report["failed_gates"])

    def test_redis_recovery_ci_evidence_is_bound_to_candidate_source_revision(self) -> None:
        self.evidence["collection"]["redis_recovery_verification"]["source_revision"] = "c" * 40

        code, report = evaluate(self.evidence, now=self.NOW)

        self.assertEqual(code, 1)
        self.assertIn("redis_recovery_ci_candidate_mismatch", report["failed_gates"])

    def test_structured_rollback_readbacks_fail_if_production_image_changes(self) -> None:
        self.evidence["collection"]["rollback_rehearsal"]["production_after"]["image"] = (
            image_ref("c" * 40, "sha256:" + "c" * 64)
        )

        code, report = evaluate(self.evidence, now=self.NOW)

        self.assertEqual(code, 1)
        self.assertIn("production_image_changed_during_canary_rollback", report["failed_gates"])
        self.assertIsNone(report["rollback_rehearsal"])

    def test_pre_promotion_collection_passes_gate_without_claiming_production_acceptance(self) -> None:
        self.evidence["collection"]["phase"] = "canary-prepromotion"
        self.evidence["collection"]["sqlite_restore_verification"]["checks"] = self.evidence[
            "collection"
        ]["sqlite_restore_verification"]["checks"][:1]
        previous_image = f"ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-{'c' * 40}-arm64"
        production = self.evidence["deployments"][1]
        production["image"] = previous_image
        production["digest"] = "sha256:" + "c" * 64
        self.evidence["collection"]["rollback_rehearsal"] = self._rollback_readbacks(
            "a" * 40, "sha256:" + "b" * 64, previous_image
        )
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
            production.pop(field)
        self.evidence["collection"]["registry_digest_verification"][1].update({
            "image": previous_image,
            "expected_digest": production["digest"],
            "observed_digest": production["digest"],
        })

        code, report = evaluate(self.evidence, now=self.NOW)

        self.assertEqual(code, 0)
        self.assertTrue(report["promotion_eligible"])
        self.assertFalse(report["production_accepted"])
        self.assertEqual(report["phase"], "canary-prepromotion")
        self.assertEqual(report["registry_digest_verification_scope"], "canary-and-production")
        self.assertEqual(
            report["certificate_lifecycle_acceptance"]["candidate_image"],
            report["deployments"][0]["image"],
        )
        accepted_production = report["deployments"][1]
        self.assertEqual(accepted_production["digest"], "sha256:" + "c" * 64)
        self.assertIsNone(accepted_production["transport"])
        self.assertIsNone(accepted_production["session_event_p95_ms"])
        self.assertIsNone(accepted_production["session_event_max_ms"])
        self.assertIsNone(accepted_production["router_cpu_peak_percent"])
        self.assertIsNone(accepted_production["stale_sample_count"])
        self.assertIsNone(accepted_production["rollback_drill_passed"])

    def test_collected_pre_promotion_evidence_is_evaluable_with_socketio_baseline(self) -> None:
        self.evidence["collection"]["phase"] = "canary-prepromotion"
        self.evidence["collection"]["sqlite_restore_verification"]["checks"] = self.evidence[
            "collection"
        ]["sqlite_restore_verification"]["checks"][:1]
        previous_image = f"ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-{'c' * 40}-arm64"
        previous_digest = "sha256:" + "c" * 64
        production = self.evidence["deployments"][1]
        production["image"] = previous_image
        production["digest"] = previous_digest
        production["transport"] = "socketio"
        self.evidence["collection"]["rollback_rehearsal"] = self._rollback_readbacks(
            "a" * 40, "sha256:" + "b" * 64, previous_image
        )
        self.evidence["collection"]["registry_digest_verification"][1].update({
            "image": previous_image,
            "expected_digest": previous_digest,
            "observed_digest": previous_digest,
        })

        _, collected_projection = evaluate(self.evidence, now=self.NOW)
        collected_evidence = {
            **self.evidence,
            "deployments": collected_projection["deployments"],
        }

        code, report = evaluate(collected_evidence, now=self.NOW)

        self.assertEqual(code, 0)
        self.assertFalse(report["production_accepted"])
        self.assertIsNone(report["deployments"][1]["transport"])

    def test_pre_promotion_cannot_pass_when_production_already_uses_candidate(self) -> None:
        self.evidence["collection"]["phase"] = "canary-prepromotion"
        self.evidence["collection"]["sqlite_restore_verification"]["checks"] = self.evidence[
            "collection"
        ]["sqlite_restore_verification"]["checks"][:1]
        code, report = evaluate(self.evidence, now=self.NOW)

        self.assertEqual(code, 1)
        self.assertIn("prepromotion_production_not_on_prior_image", report["failed_gates"])

    def test_stale_data_and_redis_failure_are_reported_without_raw_input(self) -> None:
        self.evidence["deployments"][1]["traffic_sample_age_seconds"] = 2.1
        self.evidence["deployments"][1]["redis_publish_verified"] = False
        code, report = evaluate(self.evidence, now=self.NOW)
        self.assertEqual(code, 1)
        self.assertIn("production_traffic_sample_stale", report["failed_gates"])
        self.assertIn("production_redis_publish_unverified", report["failed_gates"])

    def test_incorrect_deployment_order_is_rejected(self) -> None:
        self.evidence["deployments"].reverse()
        with self.assertRaisesRegex(ValueError, "ordered canary"):
            evaluate(self.evidence, now=self.NOW)

    def test_non_project_image_cannot_become_promotion_eligible(self) -> None:
        self.evidence["deployments"][0]["image"] = (
            f"ghcr.io/another-owner/another-project:sha-{'a' * 40}-arm64@sha256:{'b' * 64}"
        )

        with self.assertRaisesRegex(ValueError, "this project's"):
            evaluate(self.evidence, now=self.NOW)

    def test_short_or_interrupted_soak_fails_closed(self) -> None:
        evidence = deepcopy(self.evidence)
        evidence["deployments"][0]["observation_ended_at"] = "2026-10-02T10:10:00Z"
        evidence["deployments"][1]["lost_event_count"] = 1
        code, report = evaluate(evidence, now=self.NOW)
        self.assertEqual(code, 1)
        self.assertIn("canary_soak_window_too_short", report["failed_gates"])
        self.assertIn("production_soak_failures_observed", report["failed_gates"])

    def test_missing_resource_and_rollback_evidence_is_rejected(self) -> None:
        evidence = deepcopy(self.evidence)
        del evidence["deployments"][0]["router_cpu_peak_percent"]
        with self.assertRaisesRegex(ValueError, "router_cpu_peak_percent"):
            evaluate(evidence, now=self.NOW)
        evidence = deepcopy(self.evidence)
        evidence["collection"]["rollback_rehearsal"]["canary_after_rollback"]["healthy"] = False
        code, report = evaluate(evidence, now=self.NOW)
        self.assertEqual(code, 1)
        self.assertIn("canary_rollback_drill_failed", report["failed_gates"])

    def test_observation_timestamps_must_include_timezone(self) -> None:
        evidence = deepcopy(self.evidence)
        evidence["deployments"][0]["observation_started_at"] = "2026-10-02T10:00:00"
        with self.assertRaisesRegex(ValueError, "include a timezone"):
            evaluate(evidence, now=self.NOW)

    def test_cli_redacts_private_input_path_when_file_cannot_be_read(self) -> None:
        with TemporaryDirectory(prefix="private-path-sentinel-") as directory:
            missing_input = Path(directory) / "missing-evidence.json"
            output = io.StringIO()
            with (
                patch.object(sys, "argv", ["release_acceptance.py", "--input", str(missing_input)]),
                redirect_stdout(output),
            ):
                exit_code = main()

        self.assertEqual(exit_code, 2)
        rendered = output.getvalue()
        self.assertNotIn("private-path-sentinel", rendered)
        self.assertNotIn(str(missing_input), rendered)
        self.assertEqual(
            json.loads(rendered),
            {
                "passed": False,
                "failed_gates": ["invalid_input"],
                "error": "acceptance input is invalid or unreadable; details redacted",
            },
        )


if __name__ == "__main__":
    unittest.main()
