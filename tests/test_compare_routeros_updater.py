from __future__ import annotations

import contextlib
import errno
import hashlib
import io
import json
import os
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
            b"# -----BEGIN " b"PRIVATE KEY----- SENSITIVE-KEY-SENTINEL\n"
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

    def test_inventory_compares_each_copy_and_counts_direct_bindings(self) -> None:
        reference = b":local updater \"reviewed\"\n"
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "copy-a.rsc").write_bytes(reference)
            (root / "copy-identical.rsc").write_bytes(reference)
            (root / "copy-b.rsc").write_bytes(b":local updater \"other\"\n")
            inventory_path = root / "inventory.json"
            inventory_path.write_text("{}", encoding="utf-8")
            manifest = {
                "schema_version": 1,
                "scripts": [
                    {"id": "copy-a", "path": "copy-a.rsc"},
                    {"id": "copy-identical", "path": "copy-identical.rsc"},
                    {"id": "copy-b", "path": "copy-b.rsc"},
                ],
                "schedulers": [
                    {"id": "startup", "script_id": "copy-a"},
                    {"id": "watchdog", "script_id": "copy-a"},
                    {"id": "second-startup", "script_id": "copy-identical"},
                ],
            }
            report = compare_routeros_updater.compare_inventory(
                reference, json.dumps(manifest).encode(), inventory_path
            )

        self.assertEqual(report["script_count"], 3)
        self.assertEqual(report["scheduler_count"], 3)
        self.assertEqual(report["inventory_schema_version"], 1)
        self.assertEqual(report["scheduler_inventory_scope"], "direct_updater_bindings_only")
        self.assertFalse(report["scheduler_inventory_classified"])
        self.assertIsNone(report["enabled_scheduler_count"])
        self.assertIsNone(report["opaque_scheduler_event_count"])
        self.assertEqual(report["inventory_scope"], "manifest_listed_only")
        self.assertEqual(report["inventory_exhaustiveness"], "not_verified")
        self.assertTrue(report["listed_bindings_resolved"])
        copies = report["scripts"]
        self.assertTrue(copies[0]["exact_match"])
        self.assertEqual(copies[0]["scheduler_binding_count"], 2)
        self.assertTrue(copies[1]["exact_match"])
        self.assertEqual(copies[1]["scheduler_binding_count"], 1)
        self.assertFalse(copies[2]["exact_match"])
        self.assertEqual(copies[2]["scheduler_binding_count"], 0)

    def test_inventory_v2_classifies_all_listed_scheduler_entries_without_event_text(self) -> None:
        reference = b":local updater \"reviewed\"\n"
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "copy-a.rsc").write_bytes(reference)
            (root / "copy-b.rsc").write_bytes(reference)
            inventory_path = root / "inventory.json"
            inventory_path.write_text("{}", encoding="utf-8")
            manifest = {
                "schema_version": 2,
                "scripts": [
                    {"id": "copy-a", "path": "copy-a.rsc"},
                    {"id": "copy-b", "path": "copy-b.rsc"},
                ],
                "schedulers": [
                    {
                        "id": "active-updater",
                        "enabled": True,
                        "target_kind": "listed_script",
                        "script_id": "copy-a",
                    },
                    {
                        "id": "disabled-updater",
                        "enabled": False,
                        "target_kind": "listed_script",
                        "script_id": "copy-a",
                    },
                    {"id": "disabled-other", "enabled": False, "target_kind": "opaque"},
                    {"id": "active-opaque", "enabled": True, "target_kind": "opaque"},
                ],
            }
            report = compare_routeros_updater.compare_inventory(
                reference, json.dumps(manifest).encode(), inventory_path
            )

        self.assertEqual(report["inventory_schema_version"], 2)
        self.assertEqual(report["scheduler_inventory_scope"], "all_manifest_listed_entries")
        self.assertTrue(report["scheduler_inventory_classified"])
        self.assertEqual(report["scheduler_count"], 4)
        self.assertEqual(report["enabled_scheduler_count"], 2)
        self.assertEqual(report["disabled_scheduler_count"], 2)
        self.assertEqual(report["opaque_scheduler_event_count"], 2)
        self.assertEqual(report["enabled_opaque_scheduler_event_count"], 1)
        self.assertTrue(report["listed_bindings_resolved"])
        scripts = report["scripts"]
        self.assertEqual(scripts[0]["scheduler_binding_count"], 2)
        self.assertEqual(scripts[0]["enabled_scheduler_binding_count"], 1)
        self.assertEqual(scripts[0]["disabled_scheduler_binding_count"], 1)
        self.assertEqual(scripts[1]["scheduler_binding_count"], 0)
        rendered = json.dumps(report)
        for marker in ("active-updater", "disabled-updater", "disabled-other", "active-opaque"):
            self.assertNotIn(marker, rendered)

    def test_inventory_v2_cli_keeps_opaque_event_values_out_of_report(self) -> None:
        reference = b":local updater \"reviewed\"\n"
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "copy-a.rsc").write_bytes(reference)
            manifest_path = root / "inventory.json"
            manifest_path.write_text(
                json.dumps(
                    {
                        "schema_version": 2,
                        "scripts": [{"id": "copy-a", "path": "copy-a.rsc"}],
                        "schedulers": [
                            {"id": "private-scheduler-id", "enabled": False, "target_kind": "opaque"}
                        ],
                    }
                ),
                encoding="utf-8",
            )
            stdout, stderr = io.StringIO(), io.StringIO()
            with patch.object(compare_routeros_updater, "TEMPLATE_PATH", root / "reference.rsc"):
                (root / "reference.rsc").write_bytes(reference)
                with redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                    exit_code = compare_routeros_updater.main(["--inventory", str(manifest_path)])

        report = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertEqual(report["opaque_scheduler_event_count"], 1)
        self.assertEqual(report["enabled_opaque_scheduler_event_count"], 0)
        self.assertNotIn("private-scheduler-id", stdout.getvalue())
        self.assertEqual(stderr.getvalue(), "")

    def test_inventory_v2_rejects_invalid_scheduler_classification(self) -> None:
        invalid_schedulers = (
            {"id": "entry", "enabled": "false", "target_kind": "opaque"},
            {"id": "entry", "enabled": 0, "target_kind": "opaque"},
            {"id": "entry", "enabled": False, "target_kind": "unknown"},
            {"id": "entry", "enabled": False, "target_kind": ["opaque"]},
            {"id": "entry", "enabled": True, "target_kind": "listed_script"},
            {
                "id": "entry",
                "enabled": True,
                "target_kind": "listed_script",
                "script_id": "missing",
            },
            {
                "id": "entry",
                "enabled": False,
                "target_kind": "opaque",
                "script_id": "copy-a",
            },
            {
                "id": "entry",
                "enabled": False,
                "target_kind": "opaque",
                "on_event": "PRIVATE-RAW-ROUTEROS-EVENT",
            },
        )
        for scheduler in invalid_schedulers:
            with self.subTest(scheduler=scheduler):
                with TemporaryDirectory() as directory:
                    root = Path(directory)
                    (root / "copy-a.rsc").write_bytes(b"safe\n")
                    manifest_path = root / "inventory.json"
                    manifest_path.write_text(
                        json.dumps(
                            {
                                "schema_version": 2,
                                "scripts": [{"id": "copy-a", "path": "copy-a.rsc"}],
                                "schedulers": [scheduler],
                            }
                        ),
                        encoding="utf-8",
                    )
                    stdout, stderr = io.StringIO(), io.StringIO()
                    with patch.object(compare_routeros_updater, "TEMPLATE_PATH", root / "reference.rsc"):
                        (root / "reference.rsc").write_bytes(b"safe\n")
                        with redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                            exit_code = compare_routeros_updater.main(["--inventory", str(manifest_path)])
                self.assertEqual(exit_code, 2)
                self.assertEqual(json.loads(stdout.getvalue()), {"error": "invalid_inventory"})
                self.assertNotIn("PRIVATE-RAW-ROUTEROS-EVENT", stdout.getvalue())
                self.assertEqual(stderr.getvalue(), "")

    def test_inventory_cli_emits_redacted_report_and_no_stderr(self) -> None:
        reference = b":local updater \"reviewed\"\n"
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "SOURCE-PATH-SENTINEL.rsc").write_bytes(
                b':local password "SOURCE-TEXT-SENTINEL"\n'
            )
            manifest_path = root / "inventory.json"
            manifest_path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "scripts": [{"id": "SAFE-ID-SENTINEL", "path": "SOURCE-PATH-SENTINEL.rsc"}],
                        "schedulers": [{"id": "SCHEDULER-NAME-SENTINEL", "script_id": "SAFE-ID-SENTINEL"}],
                    }
                ),
                encoding="utf-8",
            )
            stdout, stderr = io.StringIO(), io.StringIO()
            with patch.object(compare_routeros_updater, "TEMPLATE_PATH", root / "reference.rsc"):
                (root / "reference.rsc").write_bytes(reference)
                with redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                    exit_code = compare_routeros_updater.main(["--inventory", str(manifest_path)])

        rendered = stdout.getvalue()
        report = json.loads(rendered)
        self.assertEqual(exit_code, 1)
        self.assertEqual(report["inventory_scope"], "manifest_listed_only")
        self.assertEqual(report["inventory_exhaustiveness"], "not_verified")
        self.assertTrue(report["listed_bindings_resolved"])
        self.assertTrue(report["scripts"][0]["risk_flags"]["credential_marker_added"])
        self.assertEqual(stderr.getvalue(), "")
        for marker in (
            "SOURCE-PATH-SENTINEL",
            "SOURCE-TEXT-SENTINEL",
            "SAFE-ID-SENTINEL",
            "SCHEDULER-NAME-SENTINEL",
        ):
            self.assertNotIn(marker, rendered)

    def test_inventory_rejects_ambiguous_bindings_and_unknown_fields(self) -> None:
        invalid_manifests = (
            {
                "schema_version": 1,
                "scripts": [{"id": "copy-a", "path": "copy-a.rsc"}],
                "schedulers": [{"id": "startup", "script_id": "missing"}],
            },
            {
                "schema_version": 1,
                "scripts": [{"id": "copy-a", "path": "copy-a.rsc"}],
                "schedulers": [{"id": "startup", "on_event": "/system/script/run"}],
            },
            {
                "schema_version": 1,
                "scripts": [
                    {"id": "copy-a", "path": "copy-a.rsc"},
                    {"id": "copy-a", "path": "copy-b.rsc"},
                ],
                "schedulers": [],
            },
        )
        for manifest in invalid_manifests:
            with self.subTest(manifest=manifest):
                with TemporaryDirectory() as directory:
                    root = Path(directory)
                    (root / "copy-a.rsc").write_bytes(b"safe\n")
                    (root / "copy-b.rsc").write_bytes(b"safe\n")
                    path = root / "inventory.json"
                    path.write_text(json.dumps(manifest), encoding="utf-8")
                    stdout, stderr = io.StringIO(), io.StringIO()
                    with patch.object(compare_routeros_updater, "TEMPLATE_PATH", root / "reference.rsc"):
                        (root / "reference.rsc").write_bytes(b"safe\n")
                        with redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                            exit_code = compare_routeros_updater.main(["--inventory", str(path)])
                self.assertEqual(exit_code, 2)
                self.assertEqual(json.loads(stdout.getvalue()), {"error": "invalid_inventory"})
                self.assertEqual(stderr.getvalue(), "")

    def test_inventory_rejects_path_escape_and_duplicate_json_keys(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            outside = root / "outside.rsc"
            outside.write_bytes(b"safe\n")
            subdir = root / "inventory"
            subdir.mkdir()
            manifest_path = subdir / "inventory.json"
            reference_path = root / "reference.rsc"
            reference_path.write_bytes(b"safe\n")

            escape = {
                "schema_version": 1,
                "scripts": [{"id": "copy-a", "path": "../outside.rsc"}],
                "schedulers": [],
            }
            manifest_path.write_text(json.dumps(escape), encoding="utf-8")
            stdout = io.StringIO()
            with patch.object(compare_routeros_updater, "TEMPLATE_PATH", reference_path):
                with redirect_stdout(stdout):
                    escape_exit = compare_routeros_updater.main(["--inventory", str(manifest_path)])
            self.assertEqual(escape_exit, 2)
            self.assertEqual(json.loads(stdout.getvalue()), {"error": "invalid_inventory"})

            manifest_path.write_text(
                '{"schema_version":1,"schema_version":1,"scripts":[],"schedulers":[]}',
                encoding="utf-8",
            )
            duplicate_stdout = io.StringIO()
            with patch.object(compare_routeros_updater, "TEMPLATE_PATH", reference_path):
                with redirect_stdout(duplicate_stdout):
                    duplicate_exit = compare_routeros_updater.main(["--inventory", str(manifest_path)])
            self.assertEqual(duplicate_exit, 2)
            self.assertEqual(json.loads(duplicate_stdout.getvalue()), {"error": "invalid_inventory"})

    def test_inventory_rejects_mapped_or_unverified_network_filesystems(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            manifest_path = root / "inventory.json"
            manifest_path.write_text("{}", encoding="utf-8")
            output = io.StringIO()
            with patch.object(compare_routeros_updater, "_is_local_filesystem", return_value=False):
                with redirect_stdout(output):
                    exit_code = compare_routeros_updater.main(["--inventory", str(manifest_path)])
        self.assertEqual(exit_code, 2)
        self.assertEqual(json.loads(output.getvalue()), {"error": "inventory_unavailable"})

    def test_windows_locality_check_resolves_relative_anchor_and_rejects_remote_links(self) -> None:
        with patch.object(compare_routeros_updater.sys, "platform", "win32"):
            with (
                patch.object(compare_routeros_updater, "_windows_drive_type", return_value=3) as drive_type,
                patch.object(compare_routeros_updater, "_has_reparse_point", return_value=False) as reparse,
            ):
                self.assertTrue(compare_routeros_updater._is_local_filesystem(Path("relative/source.rsc")))
                self.assertTrue(drive_type.call_args.args[0])
                reparse.assert_called_once()

            with patch.object(compare_routeros_updater, "_windows_drive_type", return_value=4):
                with patch.object(compare_routeros_updater, "_has_reparse_point") as reparse:
                    self.assertFalse(compare_routeros_updater._is_local_filesystem(Path("Z:/remote/source.rsc")))
                    reparse.assert_not_called()

            with patch.object(compare_routeros_updater, "_windows_drive_type", return_value=3):
                with patch.object(compare_routeros_updater, "_has_reparse_point", return_value=True):
                    self.assertFalse(compare_routeros_updater._is_local_filesystem(Path("C:/junction/source.rsc")))

    def test_posix_inventory_reader_rejects_fifo_without_blocking(self) -> None:
        if not hasattr(os, "mkfifo"):
            self.skipTest("FIFO creation is unavailable")
        with TemporaryDirectory() as directory:
            root = Path(directory)
            fifo = root / "source.fifo"
            os.mkfifo(fifo)
            with self.assertRaises((OSError, ValueError)):
                compare_routeros_updater._read_local_file(fifo, 128)

    def test_inventory_rejects_symlink_that_escapes_its_directory(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            inventory_dir = root / "inventory"
            inventory_dir.mkdir()
            outside = root / "outside.rsc"
            outside.write_bytes(b"safe\n")
            candidate = inventory_dir / "candidate.rsc"
            try:
                candidate.symlink_to(outside)
            except (OSError, NotImplementedError):
                self.skipTest("symlink creation is unavailable")
            manifest_path = inventory_dir / "inventory.json"
            manifest_path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "scripts": [{"id": "copy-a", "path": "candidate.rsc"}],
                        "schedulers": [],
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaises((OSError, ValueError)) as raised:
                compare_routeros_updater.compare_inventory(b"safe\n", manifest_path.read_bytes(), manifest_path)
            if isinstance(raised.exception, OSError):
                self.assertEqual(raised.exception.errno, errno.ELOOP)


if __name__ == "__main__":
    unittest.main()
