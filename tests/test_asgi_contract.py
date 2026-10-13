from __future__ import annotations

import asyncio
import importlib.util
import json
import socket
import time
import unittest

from asgi import DashboardHTTPASGI
from routeros_binary import RouterOSReply
from security import SessionStore
from telemetry_runtime import TelemetryRuntime


class ASGIContractTests(unittest.TestCase):
    def test_native_websocket_preserves_telemetry_redaction_allowlists(self) -> None:
        if not all(importlib.util.find_spec(name) for name in ("socketio", "uvicorn")):
            self.skipTest("native WebSocket runtime dependencies are not installed")

        import socketio
        import uvicorn
        import websockets

        from asgi import NativeSocketIO
        from telemetry_broker import TelemetryBroker, TelemetryEvent
        from telemetry_gateway import TelemetryGatewayContract, TelemetryPrincipal

        async def exercise() -> None:
            sessions = SessionStore(idle_seconds=60, absolute_seconds=300)
            session = sessions.create("operator", "test-only-router-password", role="owner")
            broker = TelemetryBroker(clock=lambda: 100)
            gateway = TelemetryGatewayContract(broker, clock=lambda: 100)
            gateway.publish(broker.apply(
                RouterOSReply(
                    "re",
                    {
                        ".id": "*secret-session-id",
                        "name": "test-user",
                        "address": "10.8.0.9",
                        "caller-id": "192.0.2.9",
                        "uptime": "1m",
                        "encoding": "AES-256-GCM",
                        "service": "ovpn",
                        "rx-byte": "10",
                        "tx-byte": "20",
                        "rx-packet": "1",
                        "tx-packet": "2",
                        "password": "WS-ROUTER-PASSWORD-SENTINEL",
                        "private-key": "WS-PRIVATE-KEY-SENTINEL",
                        "profile-archive": "WS-PROFILE-SENTINEL",
                        "unexpected": "WS-UNEXPECTED-FIELD-SENTINEL",
                    },
                ),
                now=101,
            ))

            class Runtime:
                def principal_for_session(self, session_id: str) -> TelemetryPrincipal | None:
                    current = sessions.get(session_id, touch=False)
                    return TelemetryPrincipal.from_session(current) if current is not None else None

            runtime = Runtime()
            runtime.gateway = gateway
            native = NativeSocketIO(runtime)
            application = socketio.ASGIApp(native.server, socketio_path="socket.io")
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", 0))
            listener.listen(128)
            listener.setblocking(False)
            port = listener.getsockname()[1]
            server = uvicorn.Server(uvicorn.Config(application, log_level="critical", lifespan="off"))
            server_task = asyncio.create_task(server.serve(sockets=[listener]))

            async def receive_until(ws, predicate, timeout: float = 5) -> str:
                deadline = asyncio.get_running_loop().time() + timeout
                while asyncio.get_running_loop().time() < deadline:
                    packet = await asyncio.wait_for(
                        ws.recv(), timeout=max(0.1, deadline - asyncio.get_running_loop().time())
                    )
                    if packet == "2":
                        await ws.send("3")
                        continue
                    if predicate(str(packet)):
                        return str(packet)
                self.fail("timed out waiting for telemetry WebSocket packet")

            try:
                deadline = asyncio.get_running_loop().time() + 5
                while not server.started and not server_task.done():
                    if asyncio.get_running_loop().time() >= deadline:
                        self.fail("test ASGI server did not start")
                    await asyncio.sleep(0.01)
                self.assertTrue(server.started)

                ws_url = f"ws://127.0.0.1:{port}/socket.io/?EIO=4&transport=websocket"
                cookie = f"vpn_session={session.session_id}"
                async with websockets.connect(
                    ws_url,
                    additional_headers={"Cookie": cookie},
                    open_timeout=5,
                    ping_interval=None,
                ) as ws:
                    self.assertTrue((await asyncio.wait_for(ws.recv(), timeout=5)).startswith("0{"))
                    await ws.send("40/telemetry,")
                    connected = await receive_until(
                        ws, lambda packet: packet.startswith(("40/telemetry,", "44/telemetry,"))
                    )
                    self.assertTrue(connected.startswith("40/telemetry,"), connected)

                    connected_packet = await receive_until(
                        ws, lambda packet: packet.startswith("42/telemetry,")
                    )
                    update_events = broker.apply(
                        RouterOSReply(
                            "re",
                            {
                                ".id": "*secret-session-id",
                                "name": "test-user",
                                "address": "10.8.0.9",
                                "caller-id": "192.0.2.9",
                                "uptime": "2m",
                                "encoding": "AES-256-GCM",
                                "service": "ovpn",
                                "rx-byte": "30",
                                "tx-byte": "40",
                                "rx-packet": "3",
                                "tx-packet": "4",
                                "password": "WS-ROUTER-PASSWORD-SENTINEL",
                                "private-key": "WS-PRIVATE-KEY-SENTINEL",
                                "unexpected": "WS-UNEXPECTED-FIELD-SENTINEL",
                            },
                        ),
                    )
                    snapshot_event = TelemetryEvent(
                        "telemetry.snapshot",
                        broker.sequence,
                        103,
                        {
                            "sessions": [
                                {
                                    "id": "*secret-session-id",
                                    "name": "test-user",
                                    "vpn_address": "10.8.0.9",
                                    "source_address": "192.0.2.9",
                                    "uptime": "2m",
                                    "encoding": "AES-256-GCM",
                                    "service": "ovpn",
                                    "rx_bytes": 30,
                                    "tx_bytes": 40,
                                    "rx_packets": 3,
                                    "tx_packets": 4,
                                    "counter_complete": True,
                                    "password": "WS-ROUTER-PASSWORD-SENTINEL",
                                    "private_key": "WS-PRIVATE-KEY-SENTINEL",
                                    "profile_archive": "WS-PROFILE-SENTINEL",
                                    "unexpected": "WS-UNEXPECTED-FIELD-SENTINEL",
                                }
                            ]
                        },
                    )
                    gateway.publish([*update_events, snapshot_event])
                    updated_packet = await receive_until(
                        ws,
                        lambda packet: packet.startswith("42/telemetry,") and "vpn.session.updated" in packet,
                    )
                    snapshot_packet = await receive_until(
                        ws,
                        lambda packet: packet.startswith("42/telemetry,") and "telemetry.snapshot" in packet,
                    )

                expected_session_fields = {
                    "id", "name", "vpn_address", "source_address", "uptime", "encoding",
                    "service", "rx_bytes", "tx_bytes", "rx_packets", "tx_packets", "counter_complete",
                }
                for packet, expected_event in (
                    (connected_packet, "vpn.session.connected"),
                    (updated_packet, "vpn.session.updated"),
                    (snapshot_packet, "telemetry.snapshot"),
                ):
                    self.assertNotIn("WS-ROUTER-PASSWORD-SENTINEL", packet)
                    self.assertNotIn("WS-PRIVATE-KEY-SENTINEL", packet)
                    self.assertNotIn("WS-PROFILE-SENTINEL", packet)
                    self.assertNotIn("WS-UNEXPECTED-FIELD-SENTINEL", packet)
                    socket_event, frame = json.loads(packet[len("42/telemetry,"):])
                    self.assertEqual(socket_event, expected_event)
                    self.assertEqual(frame["event"], expected_event)
                    session_payload = (
                        frame["payload"]["sessions"][0]
                        if expected_event == "telemetry.snapshot"
                        else frame["payload"]
                    )
                    self.assertEqual(set(session_payload), expected_session_fields)
            finally:
                server.should_exit = True
                await asyncio.wait_for(server_task, timeout=5)

        asyncio.run(exercise())

    def test_native_websocket_revocation_closes_stream_and_blocks_reconnect(self) -> None:
        self._exercise_native_websocket_lifecycle("revoke")

    def test_native_websocket_capability_change_closes_stream(self) -> None:
        self._exercise_native_websocket_lifecycle("capability-change")

    def test_native_websocket_expiry_closes_stream_and_blocks_reconnect(self) -> None:
        self._exercise_native_websocket_lifecycle("expiry")

    def _exercise_native_websocket_lifecycle(self, transition: str) -> None:
        if not all(importlib.util.find_spec(name) for name in ("socketio", "uvicorn")):
            self.skipTest("native WebSocket runtime dependencies are not installed")

        import uvicorn
        import websockets

        from asgi import NativeSocketIO
        from telemetry_gateway import TelemetryPrincipal

        class Gateway:
            def __init__(self) -> None:
                self.opened: list[str] = []
                self.closed: list[str] = []
                self.frames = 0

            def open(self, _principal: TelemetryPrincipal) -> str:
                subscription = f"subscription-{len(self.opened) + 1}"
                self.opened.append(subscription)
                return subscription

            def close(self, subscription: str) -> None:
                self.closed.append(subscription)

            def poll(self, _subscription: str, after_sequence: int | None = None) -> list[dict[str, object]]:
                if self.frames:
                    return []
                self.frames += 1
                return [{"event": "telemetry.snapshot", "sequence": 1, "payload": {"sessions": []}}]

        async def exercise() -> None:
            sessions = SessionStore(idle_seconds=60, absolute_seconds=300)
            session = sessions.create("operator", "test-only-router-password", role="owner")
            gateway = Gateway()

            class Runtime:
                def principal_for_session(self, session_id: str) -> TelemetryPrincipal | None:
                    current = sessions.get(session_id, touch=False)
                    return TelemetryPrincipal.from_session(current) if current is not None else None

            runtime = Runtime()
            runtime.gateway = gateway
            native = NativeSocketIO(runtime)
            import socketio

            application = socketio.ASGIApp(native.server, socketio_path="socket.io")
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", 0))
            listener.listen(128)
            listener.setblocking(False)
            port = listener.getsockname()[1]
            config = uvicorn.Config(application, log_level="critical", lifespan="off")
            server = uvicorn.Server(config)
            server_task = asyncio.create_task(server.serve(sockets=[listener]))
            try:
                deadline = asyncio.get_running_loop().time() + 5
                while not server.started and not server_task.done():
                    if asyncio.get_running_loop().time() >= deadline:
                        self.fail("test ASGI server did not start")
                    await asyncio.sleep(0.01)
                self.assertTrue(server.started)

                cookie = f"vpn_session={session.session_id}"
                ws_url = f"ws://127.0.0.1:{port}/socket.io/?EIO=4&transport=websocket"

                async def receive_until(ws, predicate, timeout: float = 5) -> str:
                    deadline = asyncio.get_running_loop().time() + timeout
                    while asyncio.get_running_loop().time() < deadline:
                        packet = await asyncio.wait_for(ws.recv(), timeout=max(0.1, deadline - asyncio.get_running_loop().time()))
                        if packet == "2":
                            await ws.send("3")
                            continue
                        if predicate(str(packet)):
                            return str(packet)
                    self.fail("timed out waiting for Socket.IO WebSocket packet")

                async with websockets.connect(
                    ws_url,
                    additional_headers={"Cookie": cookie},
                    open_timeout=5,
                    ping_interval=None,
                ) as ws:
                    self.assertTrue((await asyncio.wait_for(ws.recv(), timeout=5)).startswith("0{"))
                    await ws.send("40/telemetry,")
                    connect_ack = await receive_until(ws, lambda packet: packet.startswith(("40/telemetry,", "44/telemetry,")))
                    self.assertTrue(connect_ack.startswith("40/telemetry,"), connect_ack)
                    self.assertEqual(gateway.opened, ["subscription-1"])

                    snapshot = await receive_until(ws, lambda packet: packet.startswith("42/telemetry,"))
                    self.assertIn("telemetry.snapshot", snapshot)
                    if transition == "revoke":
                        self.assertTrue(sessions.revoke(session.session_id))
                    elif transition == "expiry":
                        current = sessions.get(session.session_id, touch=False)
                        self.assertIsNotNone(current)
                        current.last_seen = time.time() - sessions.idle_seconds - 1
                    else:
                        # Keep the opaque session valid but remove its live-stream grant.
                        current = sessions.get(session.session_id, touch=False)
                        self.assertIsNotNone(current)
                        current.capabilities = frozenset()

                    disconnect_packet = await receive_until(ws, lambda packet: packet.startswith("41/telemetry,"), timeout=3)
                    self.assertTrue(disconnect_packet.startswith("41/telemetry,"))
                    self.assertEqual(gateway.closed, ["subscription-1"])
                    self.assertEqual(native.metrics()["active_connections"], 0)

                if transition in {"revoke", "expiry"}:
                    async with websockets.connect(
                        ws_url,
                        additional_headers={"Cookie": cookie},
                        open_timeout=5,
                        ping_interval=None,
                    ) as reconnect:
                        self.assertTrue((await asyncio.wait_for(reconnect.recv(), timeout=5)).startswith("0{"))
                        await reconnect.send("40/telemetry,")
                        rejection = await receive_until(reconnect, lambda packet: packet.startswith("44/telemetry,"))
                        self.assertTrue(rejection.startswith("44/telemetry,"), rejection)
                    self.assertEqual(gateway.opened, ["subscription-1"])
                    self.assertEqual(native.metrics()["rejected_connections_total"], 1)
                    if transition == "expiry":
                        self.assertIsNone(sessions.get(session.session_id, touch=False))
                else:
                    self.assertIsNotNone(sessions.get(session.session_id, touch=False))
                    self.assertEqual(native.metrics()["rejected_connections_total"], 0)
            finally:
                server.should_exit = True
                await asyncio.wait_for(server_task, timeout=5)

        asyncio.run(exercise())

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

    def test_socketio_reconnect_uses_current_server_session_capabilities(self) -> None:
        from asgi import NativeSocketIO

        class Gateway:
            def __init__(self) -> None:
                self.opened = 0
                self.closed: list[str] = []

            def open(self, _principal: object) -> str:
                self.opened += 1
                return f"subscription-{self.opened}"

            def close(self, subscription: str) -> None:
                self.closed.append(subscription)

            def poll(self, _subscription: str) -> list[dict[str, object]]:
                return []

        sessions = SessionStore()
        session = sessions.create("operator", "router-password-marker", role="owner")
        gateway = Gateway()
        runtime = object.__new__(TelemetryRuntime)
        runtime.sessions = sessions
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
                "headers": [(b"cookie", f"vpn_session={session.session_id}".encode("ascii"))],
            },
        }

        async def exercise() -> bool:
            self.assertTrue(await native.connect("socket-before-change", environ))
            await native.disconnect("socket-before-change")

            # Keep the opaque session valid, but remove its live-read grant.
            # A new transport SID must re-derive authorization from the
            # current server-side session, not handshake-supplied claims.
            session.capabilities = frozenset()
            return await native.connect(
                "socket-after-change",
                environ,
                auth={"username": "operator", "role": "owner", "capabilities": ["*"]},
            )

        accepted = asyncio.run(exercise())

        self.assertFalse(accepted)
        self.assertIsNotNone(sessions.get(session.session_id))
        self.assertEqual(gateway.opened, 1)
        self.assertEqual(gateway.closed, ["subscription-1"])
        self.assertEqual(native._connections_total, 1)
        self.assertEqual(native._disconnects_total, 1)
        self.assertEqual(native._rejected_connections_total, 1)
        self.assertEqual(native._subscriptions, {})
        self.assertEqual(native._session_ids, {})
        self.assertEqual(native._tasks, {})

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
        self.assertEqual(native.metrics()["health_heartbeats_total"], 0)
        self.assertNotIn("password", str(native.metrics()).lower())

    def test_socketio_health_payload_contains_only_upstream_state(self) -> None:
        from asgi import NativeSocketIO

        class Supervisor:
            class Health:
                status = "healthy"
                last_error_code = "must-not-leak"

            @staticmethod
            def health():
                return Supervisor.Health()

        native = object.__new__(NativeSocketIO)
        native.runtime = type("Runtime", (), {"supervisor": Supervisor()})()

        self.assertEqual(
            native._health_payload(),
            {"state": "healthy", "stream_connected": True},
        )

    def test_live_pump_emits_authenticated_health_heartbeat_without_session_data(self) -> None:
        from asgi import NativeSocketIO
        from telemetry_gateway import TelemetryPrincipal

        principal = TelemetryPrincipal(True, auth_method="routeros", role="owner")

        class Supervisor:
            class Health:
                status = "healthy"

            @staticmethod
            def health():
                return Supervisor.Health()

        class Runtime:
            supervisor = Supervisor()

            @staticmethod
            def principal_for_session(_session_id: str):
                return principal

        class Gateway:
            @staticmethod
            def poll(_subscription: str):
                return []

        class FakeServer:
            def __init__(self) -> None:
                self.emitted = []

            async def emit(self, event, payload, *, to, namespace) -> None:
                self.emitted.append((event, payload, to, namespace))
                native._subscriptions.pop(to, None)

            async def disconnect(self, *_args, **_kwargs) -> None:
                raise AssertionError("unexpected disconnect")

        native = object.__new__(NativeSocketIO)
        native.runtime = Runtime()
        native.runtime.gateway = Gateway()
        native.server = FakeServer()
        native._subscriptions = {"socket-healthy": "subscription"}
        native._session_ids = {"socket-healthy": "opaque-session"}
        native._events_emitted_total = 0
        native._health_heartbeats_total = 0

        asyncio.run(native._pump("socket-healthy", "subscription"))

        self.assertEqual(
            native.server.emitted,
            [("telemetry.health", {"state": "healthy", "stream_connected": True}, "socket-healthy", "/telemetry")],
        )
        self.assertEqual(native._health_heartbeats_total, 1)
        self.assertEqual(native._events_emitted_total, 0)

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

    def test_live_pump_revalidates_routeros_role_changes_on_the_active_asgi_stream(self) -> None:
        from asgi import NativeSocketIO

        sessions = SessionStore()
        session = sessions.create("operator", "router-password-marker", role="owner")
        routeros_state = {"role": "owner", "enabled": True}

        def resolve_role(_session) -> str | None:
            return routeros_state["role"] if routeros_state["enabled"] else None

        runtime = TelemetryRuntime(
            sessions=sessions,
            rest_url="https://router.example.test",
            ca_file=None,
            insecure_tls=False,
            api_ssl_port=8729,
            requested_transport="binary",
            role_resolver=resolve_role,
        )
        sessions._role_checked_at[session.session_id] = 0
        principal = runtime.principal_for_session(session.session_id)
        self.assertIsNotNone(principal)
        self.assertTrue(principal.may_stream)
        subscription = runtime.gateway.open(principal)
        runtime._publish(runtime.broker.reconcile([
            {
                ".id": "*test-session",
                "name": "vpn-test-user",
                "address": "10.8.0.2",
                "caller-id": "192.0.2.10",
                "uptime": "1m",
                "encoding": "AES-256-GCM/[null-digest]",
                "service": "ovpn",
            },
        ], now=100))

        class FakeServer:
            def __init__(self) -> None:
                self.emitted: list[int] = []
                self.disconnected: list[tuple[str, str]] = []

            async def emit(self, _event, payload, *, to, namespace) -> None:
                self.emitted.append(int(payload["sequence"]))
                if len(self.emitted) == 1:
                    # The RouterOS-derived downgrade removes write/admin
                    # permissions but intentionally retains sessions.read.
                    routeros_state["role"] = "read_only"
                    sessions._role_checked_at[session.session_id] = 0
                else:
                    # Once RouterOS no longer resolves the account, the same
                    # established stream must be closed before another frame.
                    routeros_state["enabled"] = False
                    sessions._role_checked_at[session.session_id] = 0

            async def disconnect(self, sid: str, *, namespace: str) -> None:
                self.disconnected.append((sid, namespace))

        native = object.__new__(NativeSocketIO)
        native.runtime = runtime
        native.server = FakeServer()
        native._subscriptions = {"socket-role-change": subscription}
        native._session_ids = {"socket-role-change": session.session_id}
        native._events_emitted_total = 0

        asyncio.run(native._pump("socket-role-change", subscription))

        self.assertEqual(session.role, "read_only")
        self.assertEqual(native.server.emitted, [1, 2])
        self.assertEqual(native.server.disconnected, [("socket-role-change", "/telemetry")])
        self.assertEqual(native._events_emitted_total, 2)

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
