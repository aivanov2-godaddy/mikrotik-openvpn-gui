from __future__ import annotations

import asyncio
import socket
import time
import unittest

from asgi import DashboardHTTPASGI
from security import SessionStore
from telemetry_runtime import TelemetryRuntime


class ASGIContractTests(unittest.TestCase):
    def test_native_socketio_metrics_are_secret_free_and_track_lifecycle(self) -> None:
        from asgi import NativeSocketIO

        native = object.__new__(NativeSocketIO)
        native._subscriptions = {}
        native._connections_total = 0
        native._disconnects_total = 0
        native._rejected_connections_total = 0
        native._events_emitted_total = 0

        self.assertEqual(native.metrics()["engine"], "asgi")
        self.assertEqual(native.metrics()["active_connections"], 0)
        self.assertNotIn("password", str(native.metrics()).lower())

    def test_live_pump_disconnects_when_session_is_revoked(self) -> None:
        from asgi import NativeSocketIO

        class RevokedRuntime:
            @staticmethod
            def principal_for_session(_session_id: str) -> None:
                return None

        class FakeServer:
            def __init__(self) -> None:
                self.disconnected: list[tuple[str, str]] = []

            async def disconnect(self, sid: str, *, namespace: str) -> None:
                self.disconnected.append((sid, namespace))

        native = object.__new__(NativeSocketIO)
        native.runtime = RevokedRuntime()
        native.server = FakeServer()
        native._subscriptions = {"socket-1": "subscription-1"}
        native._session_ids = {"socket-1": "revoked-session"}
        native._events_emitted_total = 0

        asyncio.run(native._pump("socket-1", "subscription-1"))

        self.assertEqual(native.server.disconnected, [("socket-1", "/telemetry")])
        self.assertEqual(native._events_emitted_total, 0)

    def test_live_pump_disconnects_when_session_loses_stream_capability(self) -> None:
        from asgi import NativeSocketIO
        from telemetry_gateway import TelemetryPrincipal

        class RestrictedRuntime:
            @staticmethod
            def principal_for_session(_session_id: str) -> TelemetryPrincipal:
                return TelemetryPrincipal(
                    True,
                    auth_method="routeros",
                    role="read_only",
                    capabilities=frozenset(),
                )

        class FakeServer:
            def __init__(self) -> None:
                self.disconnected: list[tuple[str, str]] = []

            async def disconnect(self, sid: str, *, namespace: str) -> None:
                self.disconnected.append((sid, namespace))

        native = object.__new__(NativeSocketIO)
        native.runtime = RestrictedRuntime()
        native.server = FakeServer()
        native._subscriptions = {"socket-2": "subscription-2"}
        native._session_ids = {"socket-2": "role-changed-session"}
        native._events_emitted_total = 0

        asyncio.run(native._pump("socket-2", "subscription-2"))

        self.assertEqual(native.server.disconnected, [("socket-2", "/telemetry")])
        self.assertEqual(native._events_emitted_total, 0)

    def test_expired_live_session_is_disconnected_without_emitting_telemetry(self) -> None:
        from asgi import NativeSocketIO

        sessions = SessionStore(idle_seconds=1, absolute_seconds=60)
        expired = sessions.create("operator", "router-password-marker")
        expired.last_seen = time.time() - 2
        runtime = object.__new__(TelemetryRuntime)
        runtime.sessions = sessions

        class FakeServer:
            def __init__(self) -> None:
                self.disconnected: list[tuple[str, str]] = []

            async def disconnect(self, sid: str, *, namespace: str) -> None:
                self.disconnected.append((sid, namespace))

        native = object.__new__(NativeSocketIO)
        native.runtime = runtime
        native.server = FakeServer()
        native._subscriptions = {"socket-expired": "subscription-expired"}
        native._session_ids = {"socket-expired": expired.session_id}
        native._events_emitted_total = 0

        asyncio.run(native._pump("socket-expired", "subscription-expired"))

        self.assertIsNone(sessions.get(expired.session_id))
        self.assertEqual(native.server.disconnected, [("socket-expired", "/telemetry")])
        self.assertEqual(native._events_emitted_total, 0)
        self.assertNotIn("router-password-marker", repr(runtime.principal_for_session(expired.session_id)))

    def test_live_pump_rechecks_capabilities_on_the_current_session(self) -> None:
        from asgi import NativeSocketIO
        from telemetry_gateway import TelemetryPrincipal

        sessions = SessionStore()
        session = sessions.create("operator", "router-password-marker", role="administrator")
        runtime = object.__new__(TelemetryRuntime)
        runtime.sessions = sessions

        class FakeServer:
            def __init__(self) -> None:
                self.disconnected: list[tuple[str, str]] = []

            async def disconnect(self, sid: str, *, namespace: str) -> None:
                self.disconnected.append((sid, namespace))

        native = object.__new__(NativeSocketIO)
        native.runtime = runtime
        native.server = FakeServer()
        native._subscriptions = {"socket-downgraded": "subscription-downgraded"}
        native._session_ids = {"socket-downgraded": session.session_id}
        native._events_emitted_total = 0

        last_seen = session.last_seen
        self.assertTrue(TelemetryPrincipal.from_session(runtime.principal_for_session(session.session_id)).may_stream)
        self.assertEqual(session.last_seen, last_seen, "stream revalidation must not count as user activity")
        session.capabilities = frozenset()
        asyncio.run(native._pump("socket-downgraded", "subscription-downgraded"))

        self.assertEqual(native.server.disconnected, [("socket-downgraded", "/telemetry")])
        self.assertEqual(native._events_emitted_total, 0)
        principal = runtime.principal_for_session(session.session_id)
        self.assertIsNotNone(principal)
        self.assertNotIn(session.session_id, repr(principal))
        self.assertNotIn("router-password-marker", repr(principal))

    def test_http_adapter_preserves_cookie_and_body_without_hop_by_hop_headers(self) -> None:
        request = DashboardHTTPASGI._request_bytes(
            {
                "method": "POST",
                "raw_path": b"/api/example",
                "query_string": b"a=1",
                "headers": [
                    (b"host", b"dashboard.example"),
                    (b"cookie", b"vpn_session=opaque"),
                    (b"connection", b"keep-alive"),
                    (b"transfer-encoding", b"chunked"),
                ],
            },
            b"{}",
        )
        self.assertIn(b"POST /api/example?a=1 HTTP/1.1", request)
        self.assertIn(b"cookie: vpn_session=opaque", request)
        self.assertIn(b"Content-Length: 2", request)
        self.assertNotIn(b"keep-alive", request)
        self.assertNotIn(b"chunked", request)

    def test_stream_response_finishes_from_content_length_without_socket_eof(self) -> None:
        client, server = socket.socketpair()
        messages: list[dict[str, object]] = []

        async def send(message: dict[str, object]) -> None:
            messages.append(message)

        try:
            server.sendall(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Length: 5\r\n"
                b"Connection: keep-alive\r\n\r\n"
                b"hello"
            )
            response = DashboardHTTPASGI._stream_response(client, send)
            self.assertIsNotNone(response)
            asyncio.run(response)
        finally:
            client.close()
            server.close()

        self.assertEqual(messages[0]["type"], "http.response.start")
        self.assertEqual(messages[1], {"type": "http.response.body", "body": b"hello", "more_body": True})
        self.assertEqual(messages[2], {"type": "http.response.body", "body": b""})


if __name__ == "__main__":
    unittest.main()
