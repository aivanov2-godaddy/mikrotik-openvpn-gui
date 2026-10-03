from __future__ import annotations

import asyncio
import importlib.util
import socket
import time
import unittest

from asgi import DashboardHTTPASGI
from security import SessionStore
from telemetry_runtime import TelemetryRuntime


class ASGIContractTests(unittest.TestCase):
    @unittest.skipUnless(importlib.util.find_spec("socketio"), "optional Socket.IO runtime is not installed")
    def test_socketio_does_not_disable_engineio_same_origin_validation(self) -> None:
        from asgi import NativeSocketIO

        native = NativeSocketIO(object())

        # python-engineio interprets [] as "disable origin handling"; None
        # retains its default same-origin check for HTTP and WebSocket requests.
        engineio = native.server.eio
        self.assertIsNone(engineio.cors_allowed_origins)
        environ = {
            "wsgi.url_scheme": "https",
            "HTTP_HOST": "vpn.example.test",
            "HTTP_ORIGIN": "https://attacker.example",
        }
        allowed_origins = engineio._cors_allowed_origins(environ)
        self.assertEqual(allowed_origins, ["https://vpn.example.test"])
        self.assertNotIn(environ["HTTP_ORIGIN"], allowed_origins)
        self.assertIn(
            "https://vpn.example.test",
            engineio._cors_allowed_origins({**environ, "HTTP_ORIGIN": "https://vpn.example.test"}),
        )

    @unittest.skipUnless(importlib.util.find_spec("socketio"), "optional Socket.IO runtime is not installed")
    def test_socketio_asgi_rejects_foreign_origin_at_http_handshake(self) -> None:
        import socketio

        from asgi import NativeSocketIO

        native = NativeSocketIO(object())
        application = socketio.ASGIApp(native.server, socketio_path="socket.io")
        messages: list[dict[str, object]] = []
        request_sent = False

        async def receive() -> dict[str, object]:
            nonlocal request_sent
            if request_sent:
                return {"type": "http.disconnect"}
            request_sent = True
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(message: dict[str, object]) -> None:
            messages.append(message)

        asyncio.run(application(
            {
                "type": "http",
                "asgi": {"version": "3.0"},
                "http_version": "1.1",
                "method": "GET",
                "scheme": "https",
                "path": "/socket.io/",
                "raw_path": b"/socket.io/",
                "query_string": b"EIO=4&transport=polling",
                "headers": [
                    (b"host", b"vpn.example.test"),
                    (b"origin", b"https://attacker.example"),
                ],
                "client": ("192.0.2.10", 54321),
                "server": ("vpn.example.test", 443),
            },
            receive,
            send,
        ))

        response = next(message for message in messages if message["type"] == "http.response.start")
        self.assertEqual(response["status"], 400)
        self.assertNotIn("access-control-allow-origin", {
            key.decode("latin1").lower()
            for key, _ in response.get("headers", [])
        })

    @unittest.skipUnless(importlib.util.find_spec("socketio"), "optional Socket.IO runtime is not installed")
    def test_socketio_asgi_rejects_foreign_origin_at_websocket_handshake(self) -> None:
        import socketio

        from asgi import NativeSocketIO

        native = NativeSocketIO(object())
        application = socketio.ASGIApp(native.server, socketio_path="socket.io")
        messages: list[dict[str, object]] = []
        connected = False

        async def receive() -> dict[str, object]:
            nonlocal connected
            if connected:
                return {"type": "websocket.disconnect", "code": 1000}
            connected = True
            return {"type": "websocket.connect"}

        async def send(message: dict[str, object]) -> None:
            messages.append(message)

        asyncio.run(application(
            {
                "type": "websocket",
                "asgi": {"version": "3.0"},
                "http_version": "1.1",
                "scheme": "wss",
                "path": "/socket.io/",
                "raw_path": b"/socket.io/",
                "query_string": b"EIO=4&transport=websocket",
                "headers": [
                    (b"host", b"vpn.example.test"),
                    (b"origin", b"https://attacker.example"),
                    (b"sec-websocket-key", b"dGhlIHNhbXBsZSBub25jZQ=="),
                    (b"sec-websocket-version", b"13"),
                ],
                "client": ("192.0.2.10", 54321),
                "server": ("vpn.example.test", 443),
                "subprotocols": [],
            },
            receive,
            send,
        ))

        self.assertNotIn("websocket.accept", [message["type"] for message in messages])
        self.assertIn("websocket.close", [message["type"] for message in messages])

    def test_socketio_reconnect_rejects_expired_cookie_even_if_auth_claims_identity(self) -> None:
        from asgi import NativeSocketIO

        sessions = SessionStore(idle_seconds=1, absolute_seconds=60)
        expired = sessions.create("operator", "router-password-marker")
        expired.last_seen = time.time() - 2
        runtime = object.__new__(TelemetryRuntime)
        runtime.sessions = sessions

        native = object.__new__(NativeSocketIO)
        native.runtime = runtime
        native._subscriptions = {}
        native._session_ids = {}
        native._tasks = {}
        native._connections_total = 0
        native._rejected_connections_total = 0

        accepted = asyncio.run(
            native.connect(
                "reconnected-socket",
                {
                    "asgi.scope": {
                        "headers": [
                            (b"cookie", f"vpn_session={expired.session_id}".encode("ascii")),
                        ],
                    },
                },
                # Client-provided handshake claims must never replace the
                # server-side session cookie as the authorization source.
                auth={"username": "operator", "role": "owner", "session_id": "forged"},
            )
        )

        self.assertFalse(accepted)
        self.assertEqual(native._subscriptions, {})
        self.assertEqual(native._tasks, {})
        self.assertEqual(native._connections_total, 0)
        self.assertEqual(native._rejected_connections_total, 1)
        self.assertIsNone(sessions.get(expired.session_id))

    @unittest.skipUnless(importlib.util.find_spec("socketio"), "optional Socket.IO runtime is not installed")
    def test_repeated_socketio_connect_is_idempotent_and_disconnect_closes_once(self) -> None:
        from asgi import NativeSocketIO

        class Principal:
            may_stream = True

        class Runtime:
            gateway = None

            @staticmethod
            def principal_for_session(session_id: str) -> Principal | None:
                return Principal() if session_id == "valid-session" else None

        class Gateway:
            def __init__(self) -> None:
                self.opened = 0
                self.closed: list[str] = []

            def open(self, _principal: Principal) -> str:
                self.opened += 1
                return "subscription-1"

            def close(self, subscription: str) -> None:
                self.closed.append(subscription)

            def poll(self, _subscription: str) -> list[dict[str, object]]:
                return []

        gateway = Gateway()
        runtime = Runtime()
        runtime.gateway = gateway
        native = object.__new__(NativeSocketIO)
        native.runtime = runtime
        native._subscriptions = {}
        native._session_ids = {}
        native._tasks = {}
        native._connections_total = 0
        native._disconnects_total = 0
        native._rejected_connections_total = 0

        environ = {
            "asgi.scope": {
                "headers": [(b"cookie", b"vpn_session=valid-session")],
            },
        }

        async def exercise() -> None:
            self.assertTrue(await native.connect("socket-1", environ))
            task = native._tasks["socket-1"]
            self.assertTrue(await native.connect("socket-1", environ))
            self.assertIs(native._tasks["socket-1"], task)
            await native.disconnect("socket-1")

        asyncio.run(exercise())

        self.assertEqual(gateway.opened, 1)
        self.assertEqual(gateway.closed, ["subscription-1"])
        self.assertEqual(native._connections_total, 1)
        self.assertEqual(native._disconnects_total, 1)
        self.assertEqual(native._subscriptions, {})

    def test_slow_socket_client_does_not_block_gateway_event_ingestion(self) -> None:
        from asgi import NativeSocketIO
        from telemetry_broker import TelemetryBroker, TelemetryEvent
        from telemetry_gateway import TelemetryGatewayContract, TelemetryPrincipal

        principal = TelemetryPrincipal(
            True,
            auth_method="routeros",
            role="owner",
            capabilities=None,
        )
        gateway = TelemetryGatewayContract(TelemetryBroker(clock=lambda: 100), clock=lambda: 100)
        subscription = gateway.open(principal)
        gateway.publish([TelemetryEvent("telemetry.reconciled", 1, 100, {"status": "online"})])

        class Runtime:
            @staticmethod
            def principal_for_session(_session_id: str) -> TelemetryPrincipal:
                return principal

        class SlowServer:
            def __init__(self) -> None:
                self.emit_started = asyncio.Event()
                self.release_emit = asyncio.Event()

            async def emit(self, _event, _payload, *, to, namespace) -> None:
                self.emit_started.set()
                await self.release_emit.wait()

        native = object.__new__(NativeSocketIO)
        native.runtime = Runtime()
        native.runtime.gateway = gateway
        native.server = SlowServer()
        native._subscriptions = {"slow-client": subscription}
        native._session_ids = {"slow-client": "opaque-session"}
        native._events_emitted_total = 0

        async def exercise() -> None:
            pump = asyncio.create_task(native._pump("slow-client", subscription))
            try:
                await asyncio.wait_for(native.server.emit_started.wait(), timeout=1)
                await asyncio.wait_for(
                    asyncio.to_thread(
                        gateway.publish,
                        [TelemetryEvent("telemetry.reconciled", 2, 101, {"status": "online"})],
                    ),
                    timeout=1,
                )
                self.assertEqual(gateway.metrics()["published_events"], 2)
            finally:
                pump.cancel()
                await asyncio.gather(pump, return_exceptions=True)

        asyncio.run(exercise())

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

    def test_live_pump_stops_a_polled_batch_when_session_is_revoked_mid_send(self) -> None:
        from asgi import NativeSocketIO

        state = {"authorized": True}

        class Principal:
            may_stream = True

        class Runtime:
            gateway = None

            @staticmethod
            def principal_for_session(_session_id: str) -> Principal | None:
                return Principal() if state["authorized"] else None

        class Gateway:
            @staticmethod
            def poll(_subscription: str) -> list[dict[str, object]]:
                return [
                    {"event": "vpn.session.updated", "sequence": 1},
                    {"event": "vpn.session.updated", "sequence": 2},
                ]

        class FakeServer:
            def __init__(self) -> None:
                self.emitted: list[int] = []
                self.disconnected: list[tuple[str, str]] = []

            async def emit(self, _event, payload, *, to, namespace) -> None:
                self.emitted.append(int(payload["sequence"]))
                state["authorized"] = False

            async def disconnect(self, sid: str, *, namespace: str) -> None:
                self.disconnected.append((sid, namespace))

        runtime = Runtime()
        runtime.gateway = Gateway()
        native = object.__new__(NativeSocketIO)
        native.runtime = runtime
        native.server = FakeServer()
        native._subscriptions = {"socket-revoked-mid-batch": "subscription"}
        native._session_ids = {"socket-revoked-mid-batch": "session"}
        native._events_emitted_total = 0

        asyncio.run(native._pump("socket-revoked-mid-batch", "subscription"))

        self.assertEqual(native.server.emitted, [1])
        self.assertEqual(
            native.server.disconnected,
            [("socket-revoked-mid-batch", "/telemetry")],
        )
        self.assertEqual(native._events_emitted_total, 1)

    def test_socketio_subscribe_stops_a_polled_batch_when_capability_is_revoked(self) -> None:
        from asgi import NativeSocketIO

        state = {"authorized": True}

        class Principal:
            may_stream = True

        class Runtime:
            gateway = None

            @staticmethod
            def principal_for_session(_session_id: str) -> Principal | None:
                return Principal() if state["authorized"] else None

        class Gateway:
            @staticmethod
            def poll(_subscription: str, *, after_sequence=None) -> list[dict[str, object]]:
                return [
                    {"event": "vpn.session.updated", "sequence": 1},
                    {"event": "vpn.session.updated", "sequence": 2},
                ]

        class FakeServer:
            def __init__(self) -> None:
                self.emitted: list[int] = []
                self.disconnected: list[tuple[str, str]] = []

            async def emit(self, _event, payload, *, to, namespace) -> None:
                self.emitted.append(int(payload["sequence"]))
                state["authorized"] = False

            async def disconnect(self, sid: str, *, namespace: str) -> None:
                self.disconnected.append((sid, namespace))

        runtime = Runtime()
        runtime.gateway = Gateway()
        native = object.__new__(NativeSocketIO)
        native.runtime = runtime
        native.server = FakeServer()
        native._subscriptions = {"socket-subscribe": "subscription"}
        native._session_ids = {"socket-subscribe": "session"}
        native._events_emitted_total = 0

        response = asyncio.run(native.subscribe("socket-subscribe"))

        self.assertEqual(native.server.emitted, [1])
        self.assertEqual([item["sequence"] for item in response["frames"]], [1])
        self.assertEqual(native._events_emitted_total, 1)
        self.assertEqual(native.server.disconnected, [("socket-subscribe", "/telemetry")])

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
