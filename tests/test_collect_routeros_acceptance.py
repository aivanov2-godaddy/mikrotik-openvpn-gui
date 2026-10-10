from __future__ import annotations

from datetime import datetime, timedelta, timezone
import unittest
from unittest.mock import Mock

from routeros_binary import RouterOSReply
from scripts.collect_routeros_acceptance import (
    CONTAINER_NAMES,
    _snapshot,
    collect,
)


class RouterOSAcceptanceSamplerTests(unittest.TestCase):
    def _fake_connection(self):
        connection = Mock()
        revision = "a" * 40

        def execute(path, *, query=()):
            query = tuple(query)
            if path == "/system/resource/print":
                self.assertEqual(query, (".proplist=cpu-load,total-memory,free-memory,total-hdd-space,free-hdd-space,uptime",))
                return [
                    RouterOSReply("re", {"cpu-load": "23", "total-memory": "1000", "free-memory": "600", "total-hdd-space": "10000", "free-hdd-space": "7000", "uptime": "1d"}),
                    RouterOSReply("done", {}),
                ]
            if path == "/container/print":
                self.assertEqual(query, (".proplist=name,status,remote-image",))
                return [
                    RouterOSReply("re", {"name": name, "status": "running", "remote-image": f"ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-{revision}-arm64", "root-dir": "/must-not-leak"})
                    for name in CONTAINER_NAMES.values()
                ] + [RouterOSReply("done", {})]
            if path == "/ppp/active/print":
                self.assertEqual(query, (".proplist=.id",))
                return [RouterOSReply("re", {".id": "*1", "name": "private-user", "address": "10.0.0.2"}), RouterOSReply("done", {})]
            self.fail(f"unexpected RouterOS path: {path}")

        connection.execute.side_effect = execute
        return connection

    def test_snapshot_only_returns_allowlisted_aggregate_values(self):
        report = _snapshot(self._fake_connection())
        self.assertEqual(report["router_cpu_percent"], 23)
        self.assertEqual(report["router_memory_used_percent"], 40.0)
        self.assertEqual(report["router_storage_used_percent"], 30.0)
        self.assertEqual(report["active_vpn_sessions"], 1)
        self.assertNotIn("private-user", repr(report))
        self.assertNotIn("/must-not-leak", repr(report))

    def test_collector_closes_connection_and_redacts_raw_router_data(self):
        connection = self._fake_connection()
        now = datetime(2026, 10, 10, tzinfo=timezone.utc)
        elapsed = [0.0]
        report = collect(
            connection,
            username="reader",
            password="do-not-log",
            expected_revisions={name: "a" * 40 for name in CONTAINER_NAMES},
            duration_seconds=1800,
            interval_seconds=60,
            clock=lambda: now + timedelta(seconds=elapsed[0]),
            monotonic=lambda: elapsed[0],
            sleep=lambda delay: elapsed.__setitem__(0, elapsed[0] + delay),
        )
        self.assertTrue(report["passed"])
        self.assertTrue(report["credentials_or_raw_router_data_written"] is False)
        self.assertNotIn("reader", repr(report))
        self.assertNotIn("do-not-log", repr(report))
        self.assertNotIn("private-user", repr(report))
        self.assertTrue(all(item["healthy_for_all_successful_samples"] for item in report["containers"].values()))
        self.assertEqual(report["failed_gates"], [])
        connection.close.assert_called_once_with()

    def test_bad_window_is_rejected(self):
        connection = self._fake_connection()
        with self.assertRaises(ValueError):
            collect(
                connection,
                username="reader",
                password="secret",
                expected_revisions={name: "a" * 40 for name in CONTAINER_NAMES},
                duration_seconds=60,
            )
        connection.connect.assert_not_called()

    def test_missing_expected_container_fails_closed(self):
        connection = self._fake_connection()
        connection.execute.side_effect = lambda path, **kwargs: (
            [RouterOSReply("re", {"cpu-load": "1", "total-memory": "100", "free-memory": "50", "total-hdd-space": "100", "free-hdd-space": "50"}), RouterOSReply("done", {})]
            if path == "/system/resource/print"
            else [RouterOSReply("done", {})]
        )
        with self.assertRaises(ValueError):
            _snapshot(connection)


if __name__ == "__main__":
    unittest.main()
