from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from scripts.redis_recovery_acceptance import (
    CI_REPOSITORY,
    CI_WORKFLOW_PATH,
    REPORT_FORMAT,
    REQUIRED_TEST_NAMES,
    report_projection_sha256,
    validate_report,
    validate_ci_provenance,
    download_verified_ci_report,
    run,
)


class RedisRecoveryAcceptanceTests(unittest.TestCase):
    @staticmethod
    def provenance(revision: str = "a" * 40) -> dict[str, object]:
        return {
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
        }

    def test_ci_provenance_requires_successful_main_push_for_exact_candidate(self) -> None:
        safe, failures = validate_ci_provenance(self.provenance(), expected_revision="a" * 40)
        self.assertEqual(failures, [])
        self.assertIsNotNone(safe)

        for field, value in (("event", "pull_request"), ("branch", "feature/test"), ("head_sha", "b" * 40)):
            with self.subTest(field=field):
                provenance = self.provenance()
                provenance[field] = value
                safe, failures = validate_ci_provenance(provenance, expected_revision="a" * 40)
                self.assertIsNone(safe)
                self.assertIn("redis_recovery_ci_provenance_invalid", failures)

    def test_download_binds_report_to_successful_main_run_and_github_artifact_metadata(self) -> None:
        payload = json.dumps({key: value for key, value in self.report.items() if key != "private"}).encode()
        run_metadata = {
            "id": 123456789,
            "repository": {"full_name": CI_REPOSITORY},
            "path": CI_WORKFLOW_PATH,
            "event": "push",
            "head_branch": "main",
            "status": "completed",
            "conclusion": "success",
            "head_sha": "a" * 40,
        }
        artifact_metadata = {
            "artifacts": [{
                "id": 987654321,
                "name": f"redis-recovery-{'a' * 40}",
                "expired": False,
                "digest": "sha256:" + "e" * 64,
                "workflow_run": {"id": 123456789, "head_sha": "a" * 40},
            }]
        }

        commands = []

        def fake_gh(arguments, **kwargs):
            commands.append(arguments)
            command = arguments[1:]
            if command[0] == "api" and command[-1].endswith("/artifacts?per_page=100"):
                stdout = json.dumps(artifact_metadata)
            elif command[0] == "api":
                stdout = json.dumps(run_metadata)
            elif command[:2] == ["attestation", "verify"]:
                stdout = json.dumps([{"verificationResult": {"verified": True}}])
            else:
                output_directory = Path(command[command.index("--dir") + 1])
                (output_directory / "redis-recovery-acceptance.json").write_bytes(payload)
                stdout = ""
            return subprocess.CompletedProcess(arguments, 0, stdout=stdout, stderr="")

        with patch("scripts.redis_recovery_acceptance.subprocess.run", side_effect=fake_gh):
            report, provenance = download_verified_ci_report(
                "123456789", expected_revision="a" * 40, now=self.now
            )

        self.assertEqual(report["source_revision"], "a" * 40)
        self.assertEqual(provenance["artifact_id"], "987654321")
        attestation_command = next(command for command in commands if command[1:3] == ["attestation", "verify"])
        self.assertIn("--signer-workflow", attestation_command)
        self.assertIn("--source-ref", attestation_command)
        self.assertIn("--source-digest", attestation_command)
        self.assertTrue(provenance["attestation_verified_during_collection"])
        safe_report, failures = validate_report(
            report, expected_revision="a" * 40, now=self.now
        )
        self.assertEqual(failures, [])
        self.assertEqual(provenance["report_sha256"], report_projection_sha256(safe_report))

    def test_ci_provenance_requires_verified_artifact_attestation(self) -> None:
        provenance = self.provenance()
        provenance["attestation_verified_during_collection"] = False

        safe, failures = validate_ci_provenance(provenance, expected_revision="a" * 40)

        self.assertIsNone(safe)
        self.assertIn("redis_recovery_ci_provenance_invalid", failures)

    def test_download_fails_closed_when_attestation_verification_fails(self) -> None:
        payload = json.dumps({key: value for key, value in self.report.items() if key != "private"}).encode()
        run_metadata = {
            "id": 123456789,
            "repository": {"full_name": CI_REPOSITORY},
            "path": CI_WORKFLOW_PATH,
            "event": "push",
            "head_branch": "main",
            "status": "completed",
            "conclusion": "success",
            "head_sha": "a" * 40,
        }
        artifact_metadata = {
            "artifacts": [{
                "id": 987654321,
                "name": f"redis-recovery-{'a' * 40}",
                "expired": False,
                "workflow_run": {"id": 123456789, "head_sha": "a" * 40},
            }]
        }

        def fake_gh(arguments, **kwargs):
            command = arguments[1:]
            if command[0] == "api" and command[-1].endswith("/artifacts?per_page=100"):
                return subprocess.CompletedProcess(arguments, 0, json.dumps(artifact_metadata), "")
            if command[0] == "api":
                return subprocess.CompletedProcess(arguments, 0, json.dumps(run_metadata), "")
            if command[:2] == ["attestation", "verify"]:
                return subprocess.CompletedProcess(arguments, 1, "", "verification failed")
            output_directory = Path(command[command.index("--dir") + 1])
            (output_directory / "redis-recovery-acceptance.json").write_bytes(payload)
            return subprocess.CompletedProcess(arguments, 0, "", "")

        with patch("scripts.redis_recovery_acceptance.subprocess.run", side_effect=fake_gh):
            with self.assertRaisesRegex(ValueError, "lacks a valid CI artifact attestation"):
                download_verified_ci_report("123456789", expected_revision="a" * 40, now=self.now)

    def test_report_projection_hash_detects_offline_edit_when_provenance_is_retained(self) -> None:
        raw = {key: value for key, value in self.report.items() if key != "private"}
        safe, failures = validate_report(raw, expected_revision="a" * 40, now=self.now)
        self.assertEqual(failures, [])
        provenance = self.provenance()
        provenance["report_sha256"] = report_projection_sha256(safe)
        raw["ci_provenance"] = provenance
        raw["started_at"] = "2026-10-01T10:00:01Z"

        verified, failures = validate_report(raw, expected_revision="a" * 40, now=self.now)

        self.assertIsNone(verified)
        self.assertEqual(failures, ["redis_recovery_ci_report_hash_mismatch"])

    def test_target_suite_imports_when_invoked_from_scripts_directory(self) -> None:
        script_directory = Path(__file__).resolve().parents[1] / "scripts"
        probe = subprocess.run(
            [
                sys.executable,
                "-c",
                "from redis_recovery_acceptance import _iter_cases, _suite; "
                "print(len(list(_iter_cases(_suite()))))",
            ],
            cwd=script_directory,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

        self.assertEqual(probe.returncode, 0, probe.stderr)
        self.assertEqual(probe.stdout.strip(), str(len(REQUIRED_TEST_NAMES)))

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

    def test_runner_never_marks_a_skipped_required_case_as_passed(self) -> None:
        skipped_name = sorted(REQUIRED_TEST_NAMES)[0]
        methods = {}
        for name in sorted(REQUIRED_TEST_NAMES):
            def scenario(self, test_name=name):
                if test_name == skipped_name:
                    self.skipTest("simulated unavailable Redis prerequisite")

            scenario.__name__ = name
            methods[name] = scenario
        test_case = type("RedisOutboxRecoveryTests", (unittest.TestCase,), methods)
        suite = unittest.TestSuite(test_case(name) for name in sorted(REQUIRED_TEST_NAMES))

        with tempfile.TemporaryDirectory(prefix="redis-evidence-skip-") as directory:
            output = Path(directory) / "report.json"
            with (
                patch("scripts.redis_recovery_acceptance._source_revision", return_value="a" * 40),
                patch("scripts.redis_recovery_acceptance._suite", return_value=suite),
            ):
                exit_code = run(output)
            report = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(exit_code, 1)
        self.assertEqual(report["test_results"][skipped_name], "skipped")
        self.assertTrue(all(
            value == "passed" for name, value in report["test_results"].items() if name != skipped_name
        ))

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
