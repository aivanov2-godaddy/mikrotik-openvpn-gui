from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from routeros_binary import RouterOSReply
from scripts import collect_routeros_updater_inventory as inventory


class FakeConnection:
    def __init__(self, script_replies, scheduler_replies) -> None:
        self.script_replies = script_replies
        self.scheduler_replies = scheduler_replies
        self.calls: list[tuple[str, tuple[str, ...]]] = []
        self.closed = False

    def execute(self, path: str, *, query=()):
        self.calls.append((path, tuple(query)))
        if path == inventory.SCRIPT_PATH:
            return self.script_replies
        if path == inventory.SCHEDULER_PATH:
            return self.scheduler_replies
        raise AssertionError("unexpected RouterOS path")

    def connect(self, username: str, password: str) -> None:
        self.login = (username, password)

    def close(self) -> None:
        self.closed = True


def _script(name: str, source: str, **extra: str) -> RouterOSReply:
    return RouterOSReply("re", {"name": name, "source": source, **extra})


def _scheduler(name: str, event: str, disabled: str = "false", **extra: str) -> RouterOSReply:
    return RouterOSReply("re", {"name": name, "on-event": event, "disabled": disabled, **extra})


def _done() -> RouterOSReply:
    return RouterOSReply("done", {})


class CollectRouterOSUpdaterInventoryTests(unittest.TestCase):
    def test_reads_only_allowlisted_properties_and_redacts_private_values(self) -> None:
        reference = b":local updater \"reviewed\"\n"
        scripts = [
            _script("UPDATER-NAME-SENTINEL", reference.decode(), **{".id": "SCRIPT-ID-SENTINEL"}),
            _script("other-script", ':local password "SOURCE-SECRET-SENTINEL"\n'),
            _done(),
        ]
        schedulers = [
            _scheduler("SCHEDULER-NAME-SENTINEL", "UPDATER-NAME-SENTINEL"),
            _scheduler("inline", ':global token "EVENT-SECRET-SENTINEL"', "true"),
            _done(),
        ]
        connection = FakeConnection(scripts, schedulers)

        report = inventory.collect_inventory(connection, reference, collected_at="fixed")

        self.assertEqual(
            connection.calls,
            [
                (inventory.SCRIPT_PATH, (f".proplist={inventory.SCRIPT_PROPLIST}",)),
                (inventory.SCHEDULER_PATH, (f".proplist={inventory.SCHEDULER_PROPLIST}",)),
            ],
        )
        rendered = json.dumps(report)
        for secret in (
            "UPDATER-NAME-SENTINEL",
            "SCRIPT-ID-SENTINEL",
            "SOURCE-SECRET-SENTINEL",
            "SCHEDULER-NAME-SENTINEL",
            "EVENT-SECRET-SENTINEL",
        ):
            self.assertNotIn(secret, rendered)
        self.assertTrue(report["api_print_responses_complete"])
        self.assertEqual(report["script_count"], 2)
        self.assertEqual(report["exact_template_match_count"], 1)
        self.assertEqual(report["direct_scheduler_binding_count"], 1)
        self.assertEqual(report["opaque_scheduler_count"], 1)
        self.assertEqual(report["schedulers"][0]["script_index"], 1)
        self.assertEqual(report["schedulers"][1]["target_kind"], "opaque")
        self.assertTrue(report["raw_script_source_written"] is False)
        self.assertTrue(report["raw_scheduler_event_written"] is False)
        self.assertTrue(report["credential_values_written"] is False)
        self.assertTrue(report["report_contains_source_fingerprints"])

    def test_routeros_extra_properties_are_ignored(self) -> None:
        connection = FakeConnection(
            [_script("copy", "safe\n", password="DO-NOT-REPORT"), _done()],
            [_scheduler("scheduler", "copy", comment="DO-NOT-REPORT"), _done()],
        )

        report = inventory.collect_inventory(connection, b"safe\n")

        self.assertNotIn("DO-NOT-REPORT", json.dumps(report))
        self.assertEqual(report["direct_scheduler_binding_count"], 1)

    def test_duplicate_script_names_make_scheduler_binding_opaque(self) -> None:
        connection = FakeConnection(
            [_script("duplicate", "one"), _script("duplicate", "two"), _done()],
            [_scheduler("scheduler", "duplicate"), _done()],
        )

        report = inventory.collect_inventory(connection, b"reviewed")

        self.assertEqual(report["ambiguous_script_name_count"], 1)
        self.assertEqual(report["opaque_scheduler_count"], 1)
        self.assertEqual(report["schedulers"][0]["target_kind"], "opaque")

    def test_incomplete_or_malformed_routeros_responses_fail_closed(self) -> None:
        invalid_responses = [
            ([_script("copy", "source")], [_done()]),
            ([_script("copy", "source"), RouterOSReply("done", {}), _script("late", "source")], [_done()]),
            ([_script("copy", "source"), _done()], [_scheduler("schedule", "copy", "unknown"), _done()]),
            ([RouterOSReply("trap", {"message": "PRIVATE-ERROR-SENTINEL"})], [_done()]),
        ]
        for scripts, schedulers in invalid_responses:
            with self.subTest(scripts=scripts, schedulers=schedulers):
                with self.assertRaises(ValueError):
                    inventory.collect_inventory(FakeConnection(scripts, schedulers), b"reviewed")

    def test_bounds_on_record_counts_and_source_size(self) -> None:
        too_many_scripts = [_script(f"s{index}", "x") for index in range(inventory.MAX_SCRIPTS + 1)] + [_done()]
        with self.assertRaises(ValueError):
            inventory.collect_inventory(FakeConnection(too_many_scripts, [_done()]), b"reviewed")

        oversized_source = "x" * (inventory.MAX_SOURCE_BYTES + 1)
        with self.assertRaises(ValueError):
            inventory.collect_inventory(
                FakeConnection([_script("large", oversized_source), _done()], [_done()]), b"reviewed"
            )

    def test_report_writer_refuses_repository_paths(self) -> None:
        repository_report = inventory.TEMPLATE_PATH.resolve().parents[1] / "private-inventory.json"
        with self.assertRaises(ValueError):
            inventory._write_report(repository_report, {"collected": True})

    def test_report_writer_rejects_nonlocal_parent_before_resolving_path(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "private-report.json"
            with (
                patch.object(inventory, "_is_local_filesystem", return_value=False),
                patch.object(Path, "resolve", side_effect=AssertionError("path must not be resolved")),
            ):
                with self.assertRaises(ValueError):
                    inventory._write_report(path, {"collected": True})

    def test_main_writes_private_report_and_closes_read_only_connection(self) -> None:
        reference = inventory.TEMPLATE_PATH.read_bytes()
        fake_connection = FakeConnection(
            [_script("private-name", reference.decode()), _done()],
            [_scheduler("private-scheduler", "private-name"), _done()],
        )
        with TemporaryDirectory() as directory:
            report_path = Path(directory) / "private-report.json"
            stdout = io.StringIO()
            environ = {
                "ROUTEROS_INVENTORY_HOST": "private-host.example",
                "ROUTEROS_INVENTORY_USERNAME": "private-user",
                "ROUTEROS_INVENTORY_PASSWORD": "PRIVATE-PASSWORD-SENTINEL",
            }
            with (
                patch.dict(os.environ, environ, clear=True),
                patch.object(inventory, "RouterOSBinaryConnection", return_value=fake_connection) as constructor,
                contextlib.redirect_stdout(stdout),
            ):
                exit_code = inventory.main(["--output", str(report_path)])

            report_text = report_path.read_text(encoding="utf-8")
            self.assertEqual(exit_code, 0)
            self.assertTrue(fake_connection.closed)
            self.assertEqual(fake_connection.login, ("private-user", "PRIVATE-PASSWORD-SENTINEL"))
            constructor.assert_called_once_with(
                "private-host.example", port=8729, ca_file=None, timeout=10
            )
            self.assertNotIn("private-host", report_text)
            self.assertNotIn("private-user", report_text)
            self.assertNotIn("PRIVATE-PASSWORD-SENTINEL", report_text)
            self.assertNotIn("private-name", report_text)
            self.assertNotIn("private-scheduler", report_text)
            self.assertNotIn("PRIVATE-PASSWORD-SENTINEL", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
