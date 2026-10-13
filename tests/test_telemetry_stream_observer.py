from __future__ import annotations

import asyncio
import importlib.util
import socket
import unittest

from scripts.telemetry_stream_observer import (
    TelemetryStreamRecorder,
    observe,
    validate_canary_origin,
)


def _session_frame(sequence: int, *, password: str | None = None) -> dict[str, object]:
    session: dict[str, object] = {
        "id": "private-session-id",
        "name": "private-user",
        "vpn_address": "10.8.0.10",
        "source_address": "192.0.2.10",
        "uptime": "1m",
        "encoding": "AES-256-GCM",
        "service": "ovpn",
        "rx_bytes": 1,
        "tx_bytes": 2,
        "rx_packets": 3,
        "tx_packets": 4,
        "counter_complete": True,
    }
    if password is not None:
        session["password"] = password
    return {
        "protocol_version": 1,
        "event": "vpn.session.updated",
        "sequence": sequence,
        "router_timestamp": 1000,
        "payload": session,
    }


class TelemetryStreamObserverTests(unittest.TestCase):
    def test_authenticated_socketio_client_writes_only_aggregate_evidence(self) -> None:
        if not all(importlib.util.find_spec(name) for name in ("socketio", "uvicorn")):
            self.skipTest("Socket.IO observer runtime dependencies are not installed")

        import socketio
        import uvicorn

        async def exercise() -> None:
            server_io = socketio.AsyncServer(async_mode="asgi", cors_allowed_origins=None)

            @server_io.on("connect", namespace="/telemetry")
            async def on_connect(sid: str, environ: dict[str, object], auth: object = None) -> bool:
                async def publish() -> None:
                    await asyncio.sleep(0.05)
                    await server_io.emit(
                        "vpn.session.updated",
                        {
                            "protocol_version": 1,
                            "event": "vpn.session.updated",
                            "sequence": 1,
                            "router_timestamp": 1000,
                            "payload": {
                                "name": "PRIVATE-USER-SENTINEL",
                                "source_address": "192.0.2.10",
                            },
                        },
                        to=sid,
                        namespace="/telemetry",
                    )
                    await server_io.emit(
                        "vpn.session.updated",
                        {
                            "protocol_version": 1,
                            "event": "vpn.session.updated",
                            "sequence": 2,
                            "router_timestamp": 1001,
                            "payload": {"password": "PRIVATE-SECRET-SENTINEL"},
                        },
                        to=sid,
                        namespace="/telemetry",
                    )

                asyncio.create_task(publish())
                return True

            application = socketio.ASGIApp(server_io, socketio_path="socket.io")
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", 0))
            listener.listen(16)
            listener.setblocking(False)
            port = listener.getsockname()[1]
            server = uvicorn.Server(
                uvicorn.Config(application, log_level="critical", lifespan="off")
            )
            server_task = asyncio.create_task(server.serve(sockets=[listener]))
            try:
                deadline = asyncio.get_running_loop().time() + 5
                while not server.started and not server_task.done():
                    if asyncio.get_running_loop().time() >= deadline:
                        self.fail("test Socket.IO server did not start")
                    await asyncio.sleep(0.01)
                report = await observe(
                    f"http://127.0.0.1:{port}",
                    "vpn_session=test-only-cookie",
                    0.25,
                )
            finally:
                server.should_exit = True
                await asyncio.wait_for(server_task, timeout=5)

            self.assertEqual(report["connections"], 1)
            self.assertEqual(report["event_count"], 1)
            self.assertEqual(report["disconnects"], 0)
            self.assertIs(report["stream_connected_at_end"], True)
            self.assertEqual(report["rejected_frames"], 1)
            self.assertNotIn("PRIVATE-USER-SENTINEL", str(report))
            self.assertNotIn("192.0.2.10", str(report))
            self.assertNotIn("PRIVATE-SECRET-SENTINEL", str(report))
            self.assertIs(report["credentials_written"], False)
            self.assertIn("unrecognized_or_unredacted_frame", report["failed_gates"])

        asyncio.run(exercise())

    def test_origin_requires_https_and_explicit_canary_or_dev_subdomain(self) -> None:
        self.assertEqual(
            validate_canary_origin("https://vpn-dev.example.test/"),
            "https://vpn-dev.example.test",
        )
        for origin in (
            "http://vpn-dev.example.test",
            "https://vpn.example.test",
            "https://vpn-dev.example.test/path",
            "https://user:password@vpn-dev.example.test",
            "https://vpn-dev.example.test/?token=secret",
        ):
            with self.subTest(origin=origin), self.assertRaises(ValueError):
                validate_canary_origin(origin)

    def test_records_only_aggregate_names_and_sequence_facts(self) -> None:
        recorder = TelemetryStreamRecorder()
        recorder.on_connect()
        recorder.record("vpn.session.updated", _session_frame(1))
        recorder.record("telemetry.health", {"state": "healthy", "stream_connected": True})
        report = recorder.report(
            started_at="2026-01-01T00:00:00+00:00",
            ended_at="2026-01-01T00:01:00+00:00",
            duration=60,
        )
        rendered = str(report)
        for sensitive in ("private-session-id", "private-user", "10.8.0.10", "192.0.2.10"):
            self.assertNotIn(sensitive, rendered)
        self.assertEqual(report["event_count"], 2)
        self.assertEqual(report["event_counts"], {"telemetry.health": 1, "vpn.session.updated": 1})
        self.assertIs(report["raw_frames_written"], False)
        self.assertIs(report["identities_or_addresses_written"], False)
        self.assertIs(report["credentials_written"], False)
        self.assertIs(report["latency_measured"], False)
        self.assertIs(report["observed_stream_healthy"], True)

    def test_secret_or_unexpected_fields_are_rejected_without_persisting_values(self) -> None:
        recorder = TelemetryStreamRecorder()
        recorder.on_connect()
        recorder.record(
            "vpn.session.updated",
            _session_frame(1, password="WS-SECRET-SENTINEL"),
        )
        report = recorder.report(
            started_at="start", ended_at="end", duration=1,
        )
        self.assertEqual(report["rejected_frames"], 1)
        self.assertNotIn("WS-SECRET-SENTINEL", str(report))
        self.assertIn("unrecognized_or_unredacted_frame", report["failed_gates"])

    def test_detects_sequence_gap_duplicate_and_out_of_order_events(self) -> None:
        recorder = TelemetryStreamRecorder()
        recorder.on_connect()
        for sequence in (1, 2, 4, 4, 3):
            recorder.record("vpn.session.updated", _session_frame(sequence))
        report = recorder.report(started_at="start", ended_at="end", duration=1)
        self.assertEqual(report["sequence_gaps"], 1)
        self.assertEqual(report["duplicate_sequences"], 1)
        self.assertEqual(report["out_of_order_sequences"], 1)
        self.assertTrue(
            {"event_sequence_gap", "duplicate_event_sequence", "out_of_order_event_sequence"}
            <= set(report["failed_gates"])
        )

    def test_reconnect_starts_a_new_sequence_epoch(self) -> None:
        recorder = TelemetryStreamRecorder()
        recorder.on_connect()
        recorder.record("telemetry.snapshot", {
            "protocol_version": 1,
            "event": "telemetry.snapshot",
            "sequence": 20,
            "router_timestamp": 1000,
            "payload": {"sessions": []},
        })
        recorder.on_disconnect()
        recorder.on_connect()
        recorder.record("telemetry.snapshot", {
            "protocol_version": 1,
            "event": "telemetry.snapshot",
            "sequence": 1,
            "router_timestamp": 1001,
            "payload": {"sessions": []},
        })
        report = recorder.report(started_at="start", ended_at="end", duration=1)
        self.assertEqual(report["connections"], 2)
        self.assertEqual(report["reconnects"], 1)
        self.assertEqual(report["snapshot_count"], 2)
        self.assertEqual(report["sequence_gaps"], 0)
        self.assertEqual(report["duplicate_sequences"], 0)
        self.assertEqual(report["out_of_order_sequences"], 0)


if __name__ == "__main__":
    unittest.main()
