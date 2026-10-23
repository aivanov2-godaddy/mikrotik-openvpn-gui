from __future__ import annotations

import hashlib
import io
import json
from contextlib import redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from scripts import compare_routeros_updater


class CompareRouterOSUpdaterTests(unittest.TestCase):
    def test_exact_match_reports_hashes_zero_changes_and_candidate_flags(self) -> None:
        content = b":local updater \"reviewed\"\n"

        report = compare_routeros_updater.compare_scripts(content, content)

        self.assertEqual(report["reference_sha256"], hashlib.sha256(content).hexdigest())
        self.assertEqual(report["candidate_sha256"], hashlib.sha256(content).hexdigest())
        self.assertTrue(report["exact_match"])
        self.assertEqual(report["changed_line_count"], 0)
        self.assertEqual(
            report["risk_flags"],
            {
                "credential_marker_added": False,
                "private_key_marker_added": False,
                "destructive_operation_marker_added": False,
                "fetch_or_download_marker_added": False,
            },
        )

    def test_reviewed_template_does_not_flag_its_existing_markers(self) -> None:
        content = compare_routeros_updater.TEMPLATE_PATH.read_bytes()

        report = compare_routeros_updater.compare_scripts(content, content)

        self.assertTrue(report["exact_match"])
        self.assertFalse(any(report["risk_flags"].values()))

    def test_difference_counts_removed_and_added_lines(self) -> None:
        reference = b"first\nreviewed-value\nlast\n"
        candidate = b"first\nchanged-value\nlast\n"

        report = compare_routeros_updater.compare_scripts(reference, candidate)

        self.assertFalse(report["exact_match"])
        self.assertEqual(report["changed_line_count"], 2)

    def test_sensitive_markers_and_paths_are_not_echoed(self) -> None:
        reference = b"# reviewed\n"
        candidate = (
            b':local password "SENSITIVE-PASSWORD-SENTINEL"\n'
            b"# -----BEGIN PRIVATE KEY----- SENSITIVE-KEY-SENTINEL\n"
            b"/file/remove [find where name=probe]\n"
            b"/tool/fetch url=https://example.invalid\n"
        )
        with TemporaryDirectory() as directory:
            candidate_path = Path(directory) / "PRIVATE-PATH-SENTINEL.rsc"
            candidate_path.write_bytes(candidate)
            reference_path = Path(directory) / "reference.rsc"
            reference_path.write_bytes(reference)
            output = io.StringIO()
            with patch.object(compare_routeros_updater, "TEMPLATE_PATH", reference_path):
                with redirect_stdout(output):
                    exit_code = compare_routeros_updater.main([str(candidate_path)])

        rendered = output.getvalue()
        report = json.loads(rendered)
        self.assertEqual(exit_code, 1)
        self.assertTrue(report["risk_flags"]["credential_marker_added"])
        self.assertTrue(report["risk_flags"]["private_key_marker_added"])
        self.assertTrue(report["risk_flags"]["destructive_operation_marker_added"])
        self.assertTrue(report["risk_flags"]["fetch_or_download_marker_added"])
        for marker in (
            "SENSITIVE-PASSWORD-SENTINEL",
            "SENSITIVE-KEY-SENTINEL",
            "PRIVATE-PATH-SENTINEL",
            "/file/remove",
            "example.invalid",
        ):
            self.assertNotIn(marker, rendered)

    def test_bad_and_missing_input_emit_json_errors_without_paths(self) -> None:
        with TemporaryDirectory() as directory:
            missing = Path(directory) / "DO-NOT-ECHO-MISSING-PATH.rsc"
            missing_output = io.StringIO()
            with redirect_stdout(missing_output):
                missing_exit = compare_routeros_updater.main([str(missing)])

            invalid = Path(directory) / "invalid.rsc"
            invalid.write_bytes(b"\xff\x00")
            invalid_output = io.StringIO()
            with redirect_stdout(invalid_output):
                invalid_exit = compare_routeros_updater.main([str(invalid)])

            oversized = Path(directory) / "oversized.rsc"
            oversized.write_bytes(b"a" * (compare_routeros_updater._MAX_SCRIPT_BYTES + 1))
            oversized_output = io.StringIO()
            with redirect_stdout(oversized_output):
                oversized_exit = compare_routeros_updater.main([str(oversized)])

            too_many_lines = Path(directory) / "too-many-lines.rsc"
            too_many_lines.write_bytes(b"line\n" * (compare_routeros_updater._MAX_SCRIPT_LINES + 1))
            too_many_lines_output = io.StringIO()
            with redirect_stdout(too_many_lines_output):
                too_many_lines_exit = compare_routeros_updater.main([str(too_many_lines)])

        self.assertEqual(missing_exit, 2)
        self.assertEqual(json.loads(missing_output.getvalue()), {"error": "candidate_unavailable"})
        self.assertNotIn("DO-NOT-ECHO-MISSING-PATH", missing_output.getvalue())
        self.assertEqual(invalid_exit, 2)
        self.assertEqual(json.loads(invalid_output.getvalue()), {"error": "candidate_unavailable"})

        self.assertEqual(oversized_exit, 2)
        self.assertEqual(json.loads(oversized_output.getvalue()), {"error": "candidate_unavailable"})
        self.assertEqual(too_many_lines_exit, 2)
        self.assertEqual(
            json.loads(too_many_lines_output.getvalue()), {"error": "candidate_unavailable"}
        )

        remote_output = io.StringIO()
        with redirect_stdout(remote_output):
            remote_exit = compare_routeros_updater.main([r"\\server\share\updater.rsc"])
        self.assertEqual(remote_exit, 2)
        self.assertEqual(json.loads(remote_output.getvalue()), {"error": "candidate_unavailable"})

        bad_arguments = io.StringIO()
        with redirect_stdout(bad_arguments):
            argument_exit = compare_routeros_updater.main([])
        self.assertEqual(argument_exit, 2)
        self.assertEqual(json.loads(bad_arguments.getvalue()), {"error": "invalid_arguments"})


if __name__ == "__main__":
    unittest.main()
