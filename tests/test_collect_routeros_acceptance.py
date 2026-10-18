from __future__ import annotations

from datetime import datetime, timedelta, timezone
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from urllib.parse import urlsplit, parse_qs
from unittest.mock import Mock, patch

from routeros_binary import RouterOSReply
from scripts.collect_routeros_acceptance import (
    CONTAINER_NAMES,
    LEGACY_CONTAINER_PROPLIST,
    MODERN_CONTAINER_PROPLIST,
    PARITY_TOLERANCE,
    RouterOSRestAcceptanceReader,
    _container_proplist_for_version,
    _snapshot,
    collect,
    main,
)


class RouterOSAcceptanceSamplerTests(unittest.TestCase):
    def _fake_connection(
        self,
        *,
        version="7.24.5 (stable)",
        lifecycle=None,
        active_sessions=1,
        session_sequence=None,
    ):
        connection = Mock()
        revision = "a" * 40
        try:
            modern = _container_proplist_for_version(version) == MODERN_CONTAINER_PROPLIST
        except ValueError:
            modern = True
        state = lifecycle if lifecycle is not None else (
            {"running": "true", "healthy": "true"} if modern else {"status": "running"}
        )
        session_samples = session_sequence or [active_sessions]
        session_index = 0

        def execute(path, *, query=()):
            nonlocal session_index
            query = tuple(query)
            if path == "/system/resource/print":
                self.assertEqual(query, (".proplist=cpu-load,total-memory,free-memory,total-hdd-space,free-hdd-space,uptime,version",))
                return [
                    RouterOSReply("re", {"cpu-load": "23", "total-memory": "1000", "free-memory": "600", "total-hdd-space": "10000", "free-hdd-space": "7000", "uptime": "1d", "version": version}),
                    RouterOSReply("done", {}),
                ]
            if path == "/container/print":
                expected_proplist = MODERN_CONTAINER_PROPLIST if modern else LEGACY_CONTAINER_PROPLIST
                self.assertEqual(query, (f".proplist={expected_proplist}",))
                return [
                    RouterOSReply("re", {"name": name, **state, "remote-image": f"ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-{revision}-arm64", "root-dir": "/must-not-leak"})
                    for name in CONTAINER_NAMES.values()
                ] + [RouterOSReply("done", {})]
            if path == "/ppp/active/print":
                self.assertEqual(query, (".proplist=.id",))
                session_count = session_samples[min(session_index, len(session_samples) - 1)]
                session_index += 1
                return [
                    *[
                        RouterOSReply("re", {".id": f"*{index + 1}", "name": "private-user", "address": "10.0.0.2"})
                        for index in range(session_count)
                    ],
                    RouterOSReply("done", {}),
                ]
            self.fail(f"unexpected RouterOS path: {path}")

        connection.execute.side_effect = execute
        return connection

    def _fake_rest_reader(self, *, mismatch=False, active_sessions=1, session_sequence=None):
        reader = Mock()
        revision = "a" * 40
        snapshot = {
            "router_cpu_percent": 23 if not mismatch else 99,
            "router_memory_used_percent": 40.0,
            "router_storage_used_percent": 30.0,
            "active_vpn_sessions": active_sessions,
            "containers": {
                name: {"healthy": True, "revision": revision}
                for name in CONTAINER_NAMES
            },
        }
        if session_sequence:
            session_index = 0

            def next_snapshot():
                nonlocal session_index
                session_count = session_sequence[min(session_index, len(session_sequence) - 1)]
                session_index += 1
                return {**snapshot, "active_vpn_sessions": session_count}

            reader.snapshot.side_effect = next_snapshot
        else:
            reader.snapshot.return_value = snapshot
        return reader

    def test_snapshot_only_returns_allowlisted_aggregate_values(self):
        report = _snapshot(self._fake_connection())
        self.assertEqual(report["router_cpu_percent"], 23)
        self.assertEqual(report["router_memory_used_percent"], 40.0)
        self.assertEqual(report["router_storage_used_percent"], 30.0)
        self.assertEqual(report["active_vpn_sessions"], 1)
        self.assertNotIn("private-user", repr(report))
        self.assertNotIn("/must-not-leak", repr(report))

    def test_legacy_routeros_uses_status_property(self):
        report = _snapshot(self._fake_connection(version="7.19.10 (stable)"))
        self.assertTrue(all(item["healthy"] for item in report["containers"].values()))

    def test_unknown_routeros_version_fails_closed_before_container_query(self):
        connection = self._fake_connection(version="unknown")
        with self.assertRaises(ValueError):
            _snapshot(connection)
        self.assertEqual(
            [call.args[0] for call in connection.execute.call_args_list],
            ["/system/resource/print"],
        )

    def test_modern_unhealthy_or_missing_lifecycle_state_fails_closed(self):
        for lifecycle in (
            {"running": "true", "healthy": "false"},
            {"running": "true", "stopped": "true"},
            {},
        ):
            with self.subTest(lifecycle=lifecycle):
                report = _snapshot(self._fake_connection(lifecycle=lifecycle))
                self.assertTrue(all(not item["healthy"] for item in report["containers"].values()))

    def test_collector_closes_connection_and_redacts_raw_router_data(self):
        connection = self._fake_connection()
        rest_reader = self._fake_rest_reader()
        now = datetime(2026, 10, 10, tzinfo=timezone.utc)
        elapsed = [0.0]
        report = collect(
            connection,
            rest_reader=rest_reader,
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
        rest_reader.close.assert_called_once_with()
        self.assertEqual(report["rest_parity_successful_sample_count"], report["sample_count"])
        self.assertEqual(report["rest_parity_failed_sample_count"], 0)

    def test_rest_binary_mismatch_fails_acceptance_without_payload_data(self):
        connection = self._fake_connection()
        rest_reader = self._fake_rest_reader(mismatch=True)
        now = datetime(2026, 10, 10, tzinfo=timezone.utc)
        elapsed = [0.0]
        report = collect(
            connection,
            rest_reader=rest_reader,
            username="reader",
            password="do-not-log",
            expected_revisions={name: "a" * 40 for name in CONTAINER_NAMES},
            duration_seconds=1800,
            interval_seconds=60,
            clock=lambda: now + timedelta(seconds=elapsed[0]),
            monotonic=lambda: elapsed[0],
            sleep=lambda delay: elapsed.__setitem__(0, elapsed[0] + delay),
        )
        self.assertFalse(report["passed"])
        self.assertIn("routeros_rest_parity_unavailable_or_mismatched", report["failed_gates"])
        self.assertEqual(report["rest_parity_failed_sample_count"], report["sample_count"])
        self.assertNotIn("99", repr(report))
        self.assertNotIn("private-user", repr(report))

    def test_soak_requires_a_vpn_session_to_be_observed_at_least_once(self):
        connection = self._fake_connection(active_sessions=0)
        now = datetime(2026, 10, 10, tzinfo=timezone.utc)
        elapsed = [0.0]

        report = collect(
            connection,
            rest_reader=self._fake_rest_reader(active_sessions=0),
            username="reader",
            password="do-not-log",
            expected_revisions={name: "a" * 40 for name in CONTAINER_NAMES},
            duration_seconds=1800,
            interval_seconds=60,
            clock=lambda: now + timedelta(seconds=elapsed[0]),
            monotonic=lambda: elapsed[0],
            sleep=lambda delay: elapsed.__setitem__(0, elapsed[0] + delay),
        )

        self.assertFalse(report["passed"])
        self.assertIn("vpn_test_session_not_observed", report["failed_gates"])
        self.assertEqual(report["active_vpn_sessions_max"], 0)

    def test_soak_allows_controlled_disconnect_after_observing_a_vpn_session(self):
        session_counts = [1] * 31
        session_counts[15] = 0
        connection = self._fake_connection(session_sequence=session_counts)
        now = datetime(2026, 10, 10, tzinfo=timezone.utc)
        elapsed = [0.0]

        report = collect(
            connection,
            rest_reader=self._fake_rest_reader(session_sequence=session_counts),
            username="reader",
            password="do-not-log",
            expected_revisions={name: "a" * 40 for name in CONTAINER_NAMES},
            duration_seconds=1800,
            interval_seconds=60,
            clock=lambda: now + timedelta(seconds=elapsed[0]),
            monotonic=lambda: elapsed[0],
            sleep=lambda delay: elapsed.__setitem__(0, elapsed[0] + delay),
        )

        self.assertTrue(report["passed"], report["failed_gates"])
        self.assertEqual(report["active_vpn_sessions_min"], 0)
        self.assertEqual(report["active_vpn_sessions_max"], 1)

    def test_rest_reader_rejects_non_https_and_embedded_credentials(self):
        for url in ("http://router.example", "https://reader:secret@router.example", "https://router.example/rest?x=1"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                RouterOSRestAcceptanceReader(url, "reader", "secret")

    def test_rest_reader_uses_only_bounded_allowlisted_gets(self):
        reader = RouterOSRestAcceptanceReader("https://router.example/rest", "reader", "secret")
        opener = Mock()
        payloads = {
            "/rest/system/resource": [{
                "cpu-load": "23", "total-memory": "1000", "free-memory": "600",
                "total-hdd-space": "10000", "free-hdd-space": "7000", "uptime": "1d",
                "version": "7.24.5 (stable)",
            }],
            "/rest/container": [
                {"name": name, "running": "true", "healthy": "true", "remote-image": f"ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-{'a' * 40}-arm64"}
                for name in CONTAINER_NAMES.values()
            ],
            "/rest/ppp/active": [{".id": "*1", "name": "private-user", "address": "10.0.0.2"}],
        }

        def open_request(request, *, timeout):
            self.assertEqual(timeout, 10)
            self.assertEqual(request.get_method(), "GET")
            self.assertEqual(request.get_header("Accept"), "application/json")
            self.assertEqual(request.get_header("Authorization"), "Basic cmVhZGVyOnNlY3JldA==")
            parsed = urlsplit(request.full_url)
            self.assertEqual(parsed.scheme, "https")
            query = parse_qs(parsed.query)
            self.assertEqual(len(query), 1)
            if parsed.path == "/rest/container":
                version = payloads["/rest/system/resource"][0]["version"]
                expected_container_proplist = (
                    MODERN_CONTAINER_PROPLIST
                    if _container_proplist_for_version(version) == MODERN_CONTAINER_PROPLIST
                    else LEGACY_CONTAINER_PROPLIST
                )
                expected_proplist = expected_container_proplist
            else:
                expected_proplist = {
                    "/rest/system/resource": "cpu-load,total-memory,free-memory,total-hdd-space,free-hdd-space,uptime,version",
                    "/rest/ppp/active": ".id",
                }[parsed.path]
            self.assertEqual(query, {".proplist": [expected_proplist]})
            self.assertIn(parsed.path, payloads)
            response = Mock()
            response.status = 200
            response.__enter__ = Mock(return_value=response)
            response.__exit__ = Mock(return_value=False)
            response.read.return_value = json.dumps(payloads[parsed.path]).encode()
            return response

        opener.open.side_effect = open_request
        reader._opener = opener
        snapshot = reader.snapshot()
        self.assertEqual(snapshot["active_vpn_sessions"], 1)
        self.assertTrue(all(item["healthy"] for item in snapshot["containers"].values()))
        self.assertNotIn("private-user", repr(snapshot))
        self.assertEqual(opener.open.call_count, 3)

        payloads["/rest/system/resource"][0]["version"] = "7.19.10 (stable)"
        payloads["/rest/container"] = [
            {"name": name, "status": "running", "remote-image": f"ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-{'a' * 40}-arm64"}
            for name in CONTAINER_NAMES.values()
        ]
        legacy_snapshot = reader.snapshot()
        self.assertTrue(all(item["healthy"] for item in legacy_snapshot["containers"].values()))
        self.assertEqual(opener.open.call_count, 6)

        payloads["/rest/system/resource"][0]["version"] = "unknown"
        with self.assertRaises(ValueError):
            reader.snapshot()
        self.assertEqual(opener.open.call_count, 7)
        reader.close()
        self.assertEqual(reader._authorization, "")

    def test_parity_tolerances_are_small_and_explicit(self):
        self.assertEqual(PARITY_TOLERANCE["router_cpu_percent"], 10.0)
        self.assertEqual(PARITY_TOLERANCE["router_memory_used_percent"], 1.0)
        self.assertEqual(PARITY_TOLERANCE["router_storage_used_percent"], 1.0)

    def test_bad_window_is_rejected(self):
        connection = self._fake_connection()
        with self.assertRaises(ValueError):
            collect(
                connection,
                rest_reader=self._fake_rest_reader(),
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

    def test_cli_failure_replaces_stale_pass_report_with_redacted_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "acceptance.json"
            output.write_text('{"passed": true, "failed_gates": []}\n', encoding="utf-8")
            argv = [
                "collect_routeros_acceptance.py",
                "--output",
                str(output),
                "--canary-revision",
                "a" * 40,
                "--production-revision",
                "b" * 40,
            ]
            environment = {
                "ROUTEROS_ACCEPTANCE_HOST": "router-secret.invalid",
                "ROUTEROS_ACCEPTANCE_USERNAME": "acceptance-reader",
                "ROUTEROS_ACCEPTANCE_PASSWORD": "password-must-not-leak",
                "ROUTEROS_ACCEPTANCE_REST_URL": "https://router-secret.invalid",
                "ROUTEROS_ACCEPTANCE_REST_USERNAME": "acceptance-reader",
                "ROUTEROS_ACCEPTANCE_REST_PASSWORD": "password-must-not-leak",
            }
            stdout = io.StringIO()
            with (
                patch.object(sys, "argv", argv),
                patch.dict(os.environ, environment, clear=True),
                patch("scripts.collect_routeros_acceptance.RouterOSBinaryConnection", side_effect=OSError("router-secret.invalid password-must-not-leak")),
                redirect_stdout(stdout),
            ):
                exit_code = main()

            report_text = output.read_text(encoding="utf-8")
            report = json.loads(report_text)
            self.assertEqual(exit_code, 2)
            self.assertFalse(report["collected"])
            self.assertFalse(report["passed"])
            self.assertEqual(report["failed_gates"], ["collection_failed"])
            self.assertEqual(report["error"], "OSError")
            self.assertFalse(report["credentials_or_raw_router_data_written"])
            self.assertNotIn("router-secret.invalid", report_text)
            self.assertNotIn("password-must-not-leak", report_text)
            self.assertNotIn("router-secret.invalid", stdout.getvalue())
            self.assertNotIn("password-must-not-leak", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
