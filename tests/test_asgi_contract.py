from __future__ import annotations

import asyncio
import importlib.util
import json
import socket
import threading
import time
import unittest
from email.message import Message
from types import SimpleNamespace
from unittest import mock

from asgi import DashboardHTTPASGI
from app import DashboardHandler, MAX_REQUEST_BODY_BYTES
from routeros_binary import RouterOSReply
from security import SessionStore
from telemetry_runtime import TelemetryRuntime


class ASGIContractTests(unittest.TestCase):
    def test_socketio_requires_active_session_before_engineio_handshake(self) -> None:
        from asgi import SocketIOLiveSendASGI

        sessions = SessionStore()
        active_session = sessions.create("operator", "test-only-router-password", role="owner")
        expired_session = sessions.create("expired", "test-only-password", role="owner")
        expired_session.last_seen = time.time() - 3601
        expired_session.last_seen_monotonic = time.monotonic() - 3601
        revoked_session = sessions.create("revoked", "test-only-password", role="owner")
        sessions.revoke(revoked_session.session_id)
        adapter = DashboardHTTPASGI(SimpleNamespace(telemetry_runtime=SimpleNamespace(sessions=sessions)))
        delegated: list[str] = []

        async def inner(scope, _receive, _send) -> None:
            delegated.append(scope["type"])

        application = SocketIOLiveSendASGI(inner, adapter)

        async def exercise() -> list[list[dict[str, object]]]:
            results: list[list[dict[str, object]]] = []
            denied_cookies = (
                None,
                b"__Host-vpn_session=unknown-session",
                f"__Host-vpn_session={expired_session.session_id}".encode("ascii"),
                f"__Host-vpn_session={revoked_session.session_id}".encode("ascii"),
            )
            for scope_type, cookie in (
                (scope_type, cookie)
                for scope_type in ("http", "websocket")
                for cookie in denied_cookies
            ):
                messages: list[dict[str, object]] = []
                headers = [(b"host", b"vpn.example.test")]
                if cookie is not None:
                    headers.append((b"cookie", cookie))
                scope = {
                    "type": scope_type,
                    "method": "GET",
                    "path": "/socket.io/",
                    "query_string": b"EIO=4&transport=polling",
                    "headers": headers,
                }

                async def receive() -> dict[str, object]:
                    return (
                        {"type": "websocket.connect"}
                        if scope_type == "websocket"
                        else {"type": "http.request", "body": b"", "more_body": False}
                    )

                async def send(message: dict[str, object]) -> None:
                    messages.append(message)

                await application(scope, receive, send)
                results.append(messages)

            valid_messages: list[dict[str, object]] = []
            valid_scope = {
                "type": "http",
                "method": "GET",
                "path": "/socket.io/",
                "query_string": b"EIO=4&transport=polling",
                "headers": [
                    (b"host", b"vpn.example.test"),
                    (
                        b"cookie",
                        f"__Host-vpn_session={active_session.session_id}".encode("ascii"),
                    ),
                ],
            }

            async def receive_valid() -> dict[str, object]:
                return {"type": "http.request", "body": b"", "more_body": False}

            async def send_valid(message: dict[str, object]) -> None:
                valid_messages.append(message)

            await application(valid_scope, receive_valid, send_valid)
            results.append(valid_messages)

            fallback_messages: list[dict[str, object]] = []
            fallback_runtime = SimpleNamespace(
                cached_principal_for_session=lambda _session_id: (True, SimpleNamespace(authenticated=False))
            )
            fallback_application = SocketIOLiveSendASGI(
                inner,
                DashboardHTTPASGI(SimpleNamespace(telemetry_runtime=fallback_runtime)),
            )
            fallback_scope = {
                **valid_scope,
                "headers": [
                    (b"host", b"vpn.example.test"),
                    (b"cookie", b"__Host-vpn_session=cached-session"),
                ],
            }

            async def send_fallback(message: dict[str, object]) -> None:
                fallback_messages.append(message)

            await fallback_application(fallback_scope, receive_valid, send_fallback)
            results.append(fallback_messages)
            return results

        results = asyncio.run(exercise())

        self.assertEqual(delegated, ["http"])
        for messages in results[:4]:
            self.assertEqual(
                [message.get("status") for message in messages if message.get("type") == "http.response.start"],
                [403],
            )
        for messages in results[4:8]:
            self.assertEqual([message.get("type") for message in messages], ["websocket.close"])
        self.assertEqual(
            [message.get("status") for message in results[9] if message.get("type") == "http.response.start"],
            [403],
        )

    def test_socketio_asgi_rejects_duplicate_origins_for_http_and_websocket(self) -> None:
        from asgi import SocketIOLiveSendASGI

        async def exercise() -> None:
            delegated: list[str] = []

            async def inner(scope, _receive, _send) -> None:
                delegated.append(scope["type"])

            application = SocketIOLiveSendASGI(inner, DashboardHTTPASGI(object()))
            origin_pairs = (
                (b"https://vpn.example.test", b"https://attacker.example"),
                (b"https://attacker.example", b"https://vpn.example.test"),
                (b"https://vpn.example.test", b"https://vpn.example.test"),
            )
            for scope_type in ("http", "websocket"):
                for first, second in origin_pairs:
                    messages: list[dict[str, object]] = []

                    async def receive() -> dict[str, object]:
                        return {"type": "http.request", "body": b"", "more_body": False}

                    async def send(message: dict[str, object]) -> None:
                        messages.append(message)

                    scope = {
                        "type": scope_type,
                        "path": "/socket.io/",
                        "headers": [(b"origin", first), (b"origin", second)],
                    }
                    await application(scope, receive, send)
                    self.assertEqual(delegated, [])
                    if scope_type == "http":
                        response = next(
                            message for message in messages
                            if message["type"] == "http.response.start"
                        )
                        self.assertEqual(response["status"], 403)
                    else:
                        self.assertEqual(
                            [message["type"] for message in messages],
                            ["websocket.close"],
                        )

        asyncio.run(exercise())

    def test_native_websocket_preserves_telemetry_redaction_allowlists(self) -> None:
        if not all(importlib.util.find_spec(name) for name in ("socketio", "uvicorn")):
            self.skipTest("native WebSocket runtime dependencies are not installed")

        import socketio
        import uvicorn
        import websockets

        from asgi import NativeSocketIO, SocketIOLiveSendASGI
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
                def role_check_lock_for_session(self, session_id: str):
                    return sessions.role_check_lock(session_id)

                def cached_principal_for_session(
                    self, session_id: str, *, role_check_lock_held: bool = False
                ):
                    current = sessions.get(
                        session_id,
                        touch=False,
                        role_check_lock_held=role_check_lock_held,
                        wait_for_role_check_lock=False,
                    )
                    return True, TelemetryPrincipal.from_session(current)

                def principal_for_session(
                    self, session_id: str, *, force_role_check: bool = False
                ) -> TelemetryPrincipal | None:
                    current = sessions.get(session_id, touch=False)
                    return TelemetryPrincipal.from_session(current) if current is not None else None

            runtime = Runtime()
            runtime.gateway = gateway
            native = NativeSocketIO(runtime)
            http_adapter = DashboardHTTPASGI(SimpleNamespace(telemetry_runtime=runtime))
            application = SocketIOLiveSendASGI(
                socketio.ASGIApp(native.server, socketio_path="socket.io"),
                http_adapter,
            )
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
                cookie = f"__Host-vpn_session={session.session_id}"
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

    def test_native_websocket_revalidates_routeros_role_change_and_account_disable(self) -> None:
        if not all(importlib.util.find_spec(name) for name in ("socketio", "uvicorn")):
            self.skipTest("native WebSocket runtime dependencies are not installed")

        import socketio
        import uvicorn
        import websockets

        from asgi import NativeSocketIO, SocketIOLiveSendASGI

        async def exercise() -> None:
            sessions = SessionStore(idle_seconds=60, absolute_seconds=300)
            session = sessions.create("operator", "test-only-router-password", role="owner")
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
            runtime._publish(runtime.broker.reconcile(
                [{
                    ".id": "*synthetic-session",
                    "name": "synthetic-user",
                    "address": "10.8.0.2",
                    "caller-id": "192.0.2.10",
                    "uptime": "1m",
                    "encoding": "AES-256-GCM",
                    "service": "ovpn",
                    "rx-byte": "10",
                    "tx-byte": "20",
                    "rx-packet": "1",
                    "tx-packet": "2",
                }],
                now=100,
            ))
            native = NativeSocketIO(runtime)
            http_adapter = DashboardHTTPASGI(SimpleNamespace(telemetry_runtime=runtime))
            application = SocketIOLiveSendASGI(
                socketio.ASGIApp(native.server, socketio_path="socket.io"),
                http_adapter,
            )
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

                cookie = f"__Host-vpn_session={session.session_id}"
                ws_url = f"ws://127.0.0.1:{port}/socket.io/?EIO=4&transport=websocket"
                async with websockets.connect(
                    ws_url,
                    additional_headers={"Cookie": cookie},
                    open_timeout=5,
                    ping_interval=None,
                ) as ws:
                    self.assertTrue((await asyncio.wait_for(ws.recv(), timeout=5)).startswith("0{"))
                    await ws.send("40/telemetry,")
                    accepted = await receive_until(
                        ws, lambda packet: packet.startswith(("40/telemetry,", "44/telemetry,"))
                    )
                    self.assertTrue(accepted.startswith("40/telemetry,"), accepted)
                    snapshot = await receive_until(
                        ws,
                        lambda packet: packet.startswith("42/telemetry,") and "telemetry.snapshot" in packet,
                    )
                    self.assertIn("synthetic-user", snapshot)

                    # A RouterOS-derived downgrade retains sessions.read, so
                    # this established connection may continue receiving only
                    # the session telemetry its new role still permits.
                    routeros_state["role"] = "read_only"
                    sessions._role_checked_monotonic[session.session_id] = 0
                    runtime._publish(runtime.broker.apply(RouterOSReply(
                        "re",
                        {
                            ".id": "*synthetic-session",
                            "name": "synthetic-user",
                            "address": "10.8.0.2",
                            "caller-id": "192.0.2.10",
                            "uptime": "2m",
                            "encoding": "AES-256-GCM",
                            "service": "ovpn",
                            "rx-byte": "30",
                            "tx-byte": "40",
                            "rx-packet": "3",
                            "tx-packet": "4",
                        },
                    ), now=101))
                    updated = await receive_until(
                        ws,
                        lambda packet: packet.startswith("42/telemetry,") and "vpn.session.updated" in packet,
                    )
                    self.assertIn("vpn.session.updated", updated)
                    self.assertEqual(session.role, "read_only")

                    # A missing/disabled account revokes the server session;
                    # the open socket closes before another telemetry frame.
                    routeros_state["enabled"] = False
                    sessions._role_checked_monotonic[session.session_id] = 0
                    disconnected = await receive_until(
                        ws, lambda packet: packet.startswith("41/telemetry,"), timeout=3
                    )
                    self.assertTrue(disconnected.startswith("41/telemetry,"))
                    self.assertIsNone(sessions.get(session.session_id, touch=False))
                    emitted_before_reconnect = native.metrics()["events_emitted_total"]

                with self.assertRaises(websockets.exceptions.InvalidStatus) as denied:
                    async with websockets.connect(
                        ws_url,
                        additional_headers={"Cookie": cookie},
                        open_timeout=5,
                        ping_interval=None,
                    ):
                        self.fail("revoked session must not allocate a new Engine.IO transport")
                self.assertEqual(denied.exception.response.status_code, 403)

                self.assertEqual(native.metrics()["events_emitted_total"], emitted_before_reconnect)
                self.assertEqual(native.metrics()["active_connections"], 0)
            finally:
                server.should_exit = True
                await asyncio.wait_for(server_task, timeout=5)

        asyncio.run(exercise())

    def _exercise_native_websocket_lifecycle(self, transition: str) -> None:
        if not all(importlib.util.find_spec(name) for name in ("socketio", "uvicorn")):
            self.skipTest("native WebSocket runtime dependencies are not installed")

        import uvicorn
        import websockets

        from asgi import NativeSocketIO, SocketIOLiveSendASGI
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
                def role_check_lock_for_session(self, session_id: str):
                    return sessions.role_check_lock(session_id)

                def cached_principal_for_session(
                    self, session_id: str, *, role_check_lock_held: bool = False
                ):
                    current = sessions.get(
                        session_id,
                        touch=False,
                        role_check_lock_held=role_check_lock_held,
                        wait_for_role_check_lock=False,
                    )
                    return True, TelemetryPrincipal.from_session(current)

                def principal_for_session(
                    self, session_id: str, *, force_role_check: bool = False
                ) -> TelemetryPrincipal | None:
                    current = sessions.get(session_id, touch=False)
                    return TelemetryPrincipal.from_session(current) if current is not None else None

            runtime = Runtime()
            runtime.gateway = gateway
            native = NativeSocketIO(runtime)
            import socketio

            http_adapter = DashboardHTTPASGI(SimpleNamespace(telemetry_runtime=runtime))
            application = SocketIOLiveSendASGI(
                socketio.ASGIApp(native.server, socketio_path="socket.io"),
                http_adapter,
            )
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

                cookie = f"__Host-vpn_session={session.session_id}"
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
                        self.assertTrue(
                            await asyncio.to_thread(sessions.revoke, session.session_id)
                        )
                    elif transition == "expiry":
                        current = await asyncio.to_thread(
                            sessions.get, session.session_id, touch=False
                        )
                        self.assertIsNotNone(current)
                        await asyncio.to_thread(
                            setattr,
                            current,
                            "last_seen",
                            time.time() - sessions.idle_seconds - 1,
                        )
                        await asyncio.to_thread(
                            setattr,
                            current,
                            "last_seen_monotonic",
                            time.monotonic() - sessions.idle_seconds - 1,
                        )
                    else:
                        # Keep the opaque session valid but remove its live-stream grant.
                        current = await asyncio.to_thread(
                            sessions.get, session.session_id, touch=False
                        )
                        self.assertIsNotNone(current)
                        await asyncio.to_thread(
                            setattr, current, "capabilities", frozenset()
                        )

                    disconnect_packet = await receive_until(ws, lambda packet: packet.startswith("41/telemetry,"), timeout=3)
                    self.assertTrue(disconnect_packet.startswith("41/telemetry,"))
                    self.assertEqual(gateway.closed, ["subscription-1"])
                    self.assertEqual(native.metrics()["active_connections"], 0)

                if transition in {"revoke", "expiry"}:
                    with self.assertRaises(websockets.exceptions.InvalidStatus) as denied:
                        async with websockets.connect(
                            ws_url,
                            additional_headers={"Cookie": cookie},
                            open_timeout=5,
                            ping_interval=None,
                        ):
                            self.fail("revoked or expired session must not allocate an Engine.IO transport")
                    self.assertEqual(denied.exception.response.status_code, 403)
                    self.assertEqual(gateway.opened, ["subscription-1"])
                    self.assertEqual(native.metrics()["rejected_connections_total"], 0)
                    self.assertEqual(native.metrics()["active_connections"], 0)
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
                            (b"cookie", f"__Host-vpn_session={expired.session_id}".encode("ascii")),
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
                "headers": [(b"cookie", f"__Host-vpn_session={session.session_id}".encode("ascii"))],
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

    def test_socketio_connection_forces_routeros_revalidation_with_warm_cache(self) -> None:
        from asgi import NativeSocketIO

        for existing_sid in (False, True):
            with self.subTest(existing_sid=existing_sid):
                sessions = SessionStore()
                session = sessions.create("operator", "router-password-marker", role="owner")
                routeros_state = {"enabled": True}
                role_lookups = 0

                def resolve_role(_session) -> str | None:
                    nonlocal role_lookups
                    role_lookups += 1
                    return "owner" if routeros_state["enabled"] else None

                runtime = TelemetryRuntime(
                    sessions=sessions,
                    rest_url="https://router.example.test",
                    ca_file=None,
                    insecure_tls=False,
                    api_ssl_port=8729,
                    requested_transport="sse",
                    role_resolver=resolve_role,
                )
                principal = runtime.principal_for_session(
                    session.session_id, force_role_check=True
                )
                self.assertIsNotNone(principal)
                self.assertEqual(role_lookups, 1)
                # Keep the role cache warm: connect must not depend on callers
                # clearing this state when RouterOS disables the account.
                self.assertGreater(sessions._role_checked_monotonic[session.session_id], 0)
                routeros_state["enabled"] = False

                sid = "socket-reconnect" if existing_sid else "socket-new"
                native = object.__new__(NativeSocketIO)
                native.runtime = runtime
                native._subscriptions = {}
                native._session_ids = {}
                native._tasks = {}
                native._connections_total = 0
                native._disconnects_total = 0
                native._rejected_connections_total = 0
                if existing_sid:
                    native._subscriptions[sid] = runtime.gateway.open(principal)
                    native._session_ids[sid] = session.session_id

                environ = {
                    "asgi.scope": {
                        "headers": [
                            (b"cookie", f"__Host-vpn_session={session.session_id}".encode("ascii"))
                        ],
                    },
                }

                async def attempt() -> bool:
                    accepted = await native.connect(sid, environ)
                    if accepted:
                        await native.disconnect(sid)
                    return accepted

                accepted = asyncio.run(attempt())

                self.assertFalse(accepted)
                self.assertEqual(role_lookups, 2)
                self.assertIsNone(sessions.get(session.session_id, touch=False))
                self.assertEqual(runtime.gateway.client_count, 0)
                self.assertEqual(native._rejected_connections_total, 1)
                self.assertEqual(native._subscriptions, {})
                self.assertEqual(native._session_ids, {})
                self.assertEqual(native._tasks, {})
                self.assertEqual(native._disconnects_total, int(existing_sid))

    def test_socketio_connect_runs_role_lookup_off_loop_and_fails_closed_at_capacity(self) -> None:
        import threading

        from asgi import (
            NativeSocketIO,
            _SOCKETIO_ROLE_CHECK_LIMIT,
            _SOCKETIO_ROLE_CHECK_SLOTS,
        )

        class Principal:
            may_stream = False

        class Runtime:
            calls = 0
            lookup_thread_id = 0
            forced = False

            def principal_for_session(
                self, _session_id: str, *, force_role_check: bool = False
            ) -> Principal:
                self.calls += 1
                self.lookup_thread_id = threading.get_ident()
                self.forced = force_role_check
                return Principal()

        runtime = Runtime()
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
                "headers": [(b"cookie", b"__Host-vpn_session=valid-session")],
            },
        }
        event_loop_thread_id = 0

        async def attempt() -> bool:
            nonlocal event_loop_thread_id
            event_loop_thread_id = threading.get_ident()
            return await native.connect("socket-1", environ)

        self.assertFalse(asyncio.run(attempt()))
        self.assertTrue(runtime.forced)
        self.assertNotEqual(runtime.lookup_thread_id, event_loop_thread_id)
        self.assertEqual(native._rejected_connections_total, 1)

        acquired = 0
        try:
            for _ in range(_SOCKETIO_ROLE_CHECK_LIMIT):
                self.assertTrue(_SOCKETIO_ROLE_CHECK_SLOTS.acquire(blocking=False))
                acquired += 1
            runtime.calls = 0
            self.assertFalse(asyncio.run(native.connect("socket-2", environ)))
            self.assertEqual(runtime.calls, 0)
        finally:
            for _ in range(acquired):
                _SOCKETIO_ROLE_CHECK_SLOTS.release()

    def test_socketio_fresh_role_cache_bypasses_worker_capacity(self) -> None:
        from asgi import (
            NativeSocketIO,
            _SOCKETIO_ROLE_CHECK_LIMIT,
            _SOCKETIO_ROLE_CHECK_SLOTS,
        )

        sessions = SessionStore()
        session = sessions.create("operator", "test-only-secret", role="owner")
        role_lookups = 0

        def resolve_role(_session) -> str:
            nonlocal role_lookups
            role_lookups += 1
            return "owner"

        runtime = TelemetryRuntime(
            sessions=sessions,
            rest_url="https://router.example.test",
            ca_file=None,
            insecure_tls=False,
            api_ssl_port=8729,
            requested_transport="sse",
            role_resolver=resolve_role,
        )
        self.assertIsNotNone(
            runtime.principal_for_session(session.session_id, force_role_check=True)
        )
        self.assertEqual(role_lookups, 1)

        native = object.__new__(NativeSocketIO)
        native.runtime = runtime
        acquired = 0
        try:
            for _ in range(_SOCKETIO_ROLE_CHECK_LIMIT):
                self.assertTrue(_SOCKETIO_ROLE_CHECK_SLOTS.acquire(blocking=False))
                acquired += 1

            principal = asyncio.run(
                native._principal_for_session_async(
                    session.session_id, wait_for_capacity=True
                )
            )

            self.assertIsNotNone(principal)
            self.assertTrue(principal.may_stream)
            self.assertEqual(role_lookups, 1)
        finally:
            for _ in range(acquired):
                _SOCKETIO_ROLE_CHECK_SLOTS.release()

    def test_socketio_stale_role_refresh_waits_for_capacity_without_denial(self) -> None:
        import threading

        from asgi import (
            NativeSocketIO,
            _SOCKETIO_ROLE_CHECK_LIMIT,
            _SOCKETIO_ROLE_CHECK_SLOTS,
        )

        class Principal:
            may_stream = True

        principal = Principal()

        class Runtime:
            calls = 0
            lookup_thread_id = 0

            def cached_principal_for_session(self, _session_id: str):
                return False, None

            def principal_for_session(
                self, _session_id: str, *, force_role_check: bool = False
            ) -> Principal:
                self.calls += 1
                self.lookup_thread_id = threading.get_ident()
                return principal

        runtime = Runtime()
        native = object.__new__(NativeSocketIO)
        native.runtime = runtime
        loop_thread_id = 0
        acquired = 0

        async def attempt() -> Principal | None:
            nonlocal acquired, loop_thread_id
            loop_thread_id = threading.get_ident()
            task = asyncio.create_task(
                native._principal_for_session_async(
                    "active-session", wait_for_capacity=True
                )
            )
            await asyncio.sleep(0.05)
            self.assertFalse(task.done())
            self.assertEqual(runtime.calls, 0)

            _SOCKETIO_ROLE_CHECK_SLOTS.release()
            acquired -= 1
            return await asyncio.wait_for(task, timeout=1)

        try:
            for _ in range(_SOCKETIO_ROLE_CHECK_LIMIT):
                self.assertTrue(_SOCKETIO_ROLE_CHECK_SLOTS.acquire(blocking=False))
                acquired += 1

            resolved = asyncio.run(attempt())
            self.assertIs(resolved, principal)
            self.assertEqual(runtime.calls, 1)
            self.assertNotEqual(runtime.lookup_thread_id, loop_thread_id)
        finally:
            for _ in range(acquired):
                _SOCKETIO_ROLE_CHECK_SLOTS.release()

    def test_socketio_cache_waits_for_inflight_forced_refresh_and_denial(self) -> None:
        import threading

        from asgi import NativeSocketIO

        sessions = SessionStore()
        session = sessions.create("operator", "test-only-secret", role="owner")
        resolver_started = threading.Event()
        release_resolver = threading.Event()
        role_lookups = 0

        def resolve_role(_session) -> str | None:
            nonlocal role_lookups
            role_lookups += 1
            if role_lookups == 1:
                return "owner"
            resolver_started.set()
            release_resolver.wait(timeout=2)
            return None

        runtime = TelemetryRuntime(
            sessions=sessions,
            rest_url="https://router.example.test",
            ca_file=None,
            insecure_tls=False,
            api_ssl_port=8729,
            requested_transport="sse",
            role_resolver=resolve_role,
        )
        self.assertIsNotNone(
            runtime.principal_for_session(session.session_id, force_role_check=True)
        )
        native = object.__new__(NativeSocketIO)
        native.runtime = runtime

        async def exercise() -> None:
            forced_refresh = asyncio.create_task(
                native._principal_for_session_async(
                    session.session_id, force_role_check=True
                )
            )
            stream_refresh = None
            try:
                self.assertTrue(await asyncio.to_thread(resolver_started.wait, 1))
                authoritative, cached = runtime.cached_principal_for_session(
                    session.session_id
                )
                self.assertFalse(authoritative)
                self.assertIsNone(cached)

                stream_refresh = asyncio.create_task(
                    native._principal_for_session_async(
                        session.session_id, wait_for_capacity=True
                    )
                )
                await asyncio.sleep(0.05)
                self.assertFalse(stream_refresh.done())

                release_resolver.set()
                results = await asyncio.wait_for(
                    asyncio.gather(forced_refresh, stream_refresh), timeout=1
                )
                self.assertEqual(results, [None, None])
                self.assertIsNone(sessions.get(session.session_id, touch=False))
            finally:
                release_resolver.set()
                pending = [forced_refresh]
                if stream_refresh is not None:
                    pending.append(stream_refresh)
                await asyncio.gather(*pending, return_exceptions=True)

        asyncio.run(exercise())

    def test_socketio_event_enqueue_is_serialized_with_role_refresh(self) -> None:
        import threading

        from asgi import NativeSocketIO

        sessions = SessionStore()
        session = sessions.create("operator", "test-only-secret", role="owner")
        role_lookups = 0
        forced_lookup_started = threading.Event()

        def resolve_role(_session) -> str:
            nonlocal role_lookups
            role_lookups += 1
            if role_lookups > 1:
                forced_lookup_started.set()
            return "owner"

        runtime = TelemetryRuntime(
            sessions=sessions,
            rest_url="https://router.example.test",
            ca_file=None,
            insecure_tls=False,
            api_ssl_port=8729,
            requested_transport="sse",
            role_resolver=resolve_role,
        )
        self.assertIsNotNone(
            runtime.principal_for_session(session.session_id, force_role_check=True)
        )

        class Server:
            def __init__(self) -> None:
                self.emit_started = asyncio.Event()
                self.release_emit = asyncio.Event()
                self.emitted: list[str] = []

            async def emit(self, event, _payload, *, to, namespace) -> None:
                self.emit_started.set()
                await self.release_emit.wait()
                self.emitted.append(event)

        server = Server()
        native = object.__new__(NativeSocketIO)
        native.runtime = runtime
        native.server = server
        native._events_emitted_total = 0

        async def exercise() -> None:
            emission = asyncio.create_task(
                native._emit_authorized(
                    "socket-1",
                    session.session_id,
                    "telemetry.reconciled",
                    {"status": "online"},
                )
            )
            forced_refresh = None
            try:
                await asyncio.wait_for(server.emit_started.wait(), timeout=1)
                forced_refresh = asyncio.create_task(
                    native._principal_for_session_async(
                        session.session_id, force_role_check=True
                    )
                )
                await asyncio.sleep(0.05)
                self.assertFalse(forced_lookup_started.is_set())
                self.assertFalse(forced_refresh.done())

                server.release_emit.set()
                self.assertTrue(await asyncio.wait_for(emission, timeout=1))
                self.assertIsNotNone(await asyncio.wait_for(forced_refresh, timeout=1))
                self.assertEqual(server.emitted, ["telemetry.reconciled"])
                self.assertEqual(role_lookups, 2)
            finally:
                server.release_emit.set()
                pending = [emission]
                if forced_refresh is not None:
                    pending.append(forced_refresh)
                await asyncio.gather(*pending, return_exceptions=True)

        asyncio.run(exercise())

    def test_socketio_event_delivery_is_serialized_with_session_invalidation(self) -> None:
        import threading

        from asgi import NativeSocketIO

        invalidators = (
            "destroy",
            "revoke",
            "rotate",
            "idle_expiry",
            "absolute_expiry",
            "purge",
            "revoke_all_except",
        )
        for invalidator in invalidators:
            with self.subTest(invalidator=invalidator):
                sessions = SessionStore(idle_seconds=60, absolute_seconds=600)
                session = sessions.create("operator", "test-only-secret", role="owner")
                other_session = None
                keep_session = None
                if invalidator == "revoke_all_except":
                    other_session = sessions.create(
                        "operator-two", "test-only-secret", role="owner"
                    )
                    keep_session = sessions.create(
                        "operator-keep", "test-only-secret", role="owner"
                    )
                runtime = TelemetryRuntime(
                    sessions=sessions,
                    rest_url="https://router.example.test",
                    ca_file=None,
                    insecure_tls=False,
                    api_ssl_port=8729,
                    requested_transport="sse",
                )

                class Server:
                    def __init__(self) -> None:
                        self.emit_started = asyncio.Event()
                        self.two_emits_started = asyncio.Event()
                        self.release_emit = asyncio.Event()
                        self.emitted: list[str] = []
                        self.order: list[str] = []
                        self.emit_count = 0

                    async def emit(self, event, _payload, *, to, namespace) -> None:
                        self.emit_count += 1
                        self.emit_started.set()
                        if self.emit_count == 2:
                            self.two_emits_started.set()
                        await self.release_emit.wait()
                        self.emitted.append(event)
                        self.order.append("emit-complete")

                server = Server()
                native = object.__new__(NativeSocketIO)
                native.runtime = runtime
                native.server = server
                native._events_emitted_total = 0
                invalidation_started = threading.Event()

                def invalidate_session():
                    invalidation_started.set()
                    if invalidator == "destroy":
                        result = sessions.destroy(session.session_id)
                    elif invalidator == "revoke":
                        result = sessions.revoke(session.session_id)
                    elif invalidator == "rotate":
                        result = sessions.rotate(
                            session.session_id,
                            "replacement-test-secret",
                            role="owner",
                        )
                    elif invalidator == "idle_expiry":
                        result = sessions.get(
                            session.session_id,
                            now=session.last_seen + sessions.idle_seconds,
                            touch=False,
                        )
                    elif invalidator == "absolute_expiry":
                        result = sessions.get(
                            session.session_id,
                            now=session.created_at + sessions.absolute_seconds,
                            touch=False,
                        )
                    elif invalidator == "revoke_all_except":
                        result = sessions.revoke_all_except(keep_session.session_id)
                    else:
                        result = sessions.purge(
                            now=session.last_seen + sessions.idle_seconds
                        )
                    server.order.append("invalidation-complete")
                    return result

                async def exercise() -> None:
                    emissions = [asyncio.create_task(
                        native._emit_authorized(
                            "socket-session-invalidation",
                            session.session_id,
                            "telemetry.reconciled",
                            {"status": "online"},
                        )
                    )]
                    invalidation = None
                    try:
                        await asyncio.wait_for(server.emit_started.wait(), timeout=1)
                        if other_session is not None:
                            emissions.append(asyncio.create_task(
                                native._emit_authorized(
                                    "socket-session-invalidation-other",
                                    other_session.session_id,
                                    "telemetry.reconciled",
                                    {"status": "online"},
                                )
                            ))
                            await asyncio.wait_for(
                                server.two_emits_started.wait(), timeout=1
                            )
                        invalidation = asyncio.create_task(
                            asyncio.to_thread(invalidate_session)
                        )
                        self.assertTrue(
                            await asyncio.to_thread(invalidation_started.wait, 1),
                            "invalidation worker must start before checking its wait",
                        )
                        await asyncio.sleep(0.05)
                        self.assertFalse(
                            invalidation.done(),
                            "session invalidation must wait for an in-flight authorized emit",
                        )

                        server.release_emit.set()
                        emit_results = await asyncio.wait_for(
                            asyncio.gather(*emissions), timeout=1
                        )
                        self.assertTrue(all(emit_results))
                        result = await asyncio.wait_for(invalidation, timeout=1)
                        self.assertEqual(server.order[-1], "invalidation-complete")
                        self.assertEqual(
                            server.order.count("emit-complete"), len(emissions)
                        )
                        if invalidator == "rotate":
                            self.assertIsNotNone(result)
                            self.assertIsNone(
                                sessions.get(session.session_id, touch=False)
                            )
                            self.assertIsNotNone(
                                sessions.get(result.session_id, touch=False)
                            )
                        elif invalidator == "revoke_all_except":
                            self.assertEqual(result, 2)
                            self.assertIsNone(
                                sessions.get(session.session_id, touch=False)
                            )
                            self.assertIsNone(
                                sessions.get(other_session.session_id, touch=False)
                            )
                            self.assertIsNotNone(
                                sessions.get(keep_session.session_id, touch=False)
                            )
                        else:
                            if invalidator == "revoke":
                                self.assertTrue(result)
                            elif invalidator == "purge":
                                self.assertEqual(result, 1)
                            self.assertIsNone(
                                sessions.get(session.session_id, touch=False)
                            )

                        self.assertFalse(
                            await native._emit_authorized(
                                "socket-session-invalidation",
                                session.session_id,
                                "telemetry.reconciled",
                                {"status": "offline"},
                            )
                        )
                        if other_session is not None:
                            self.assertFalse(
                                await native._emit_authorized(
                                    "socket-session-invalidation-other",
                                    other_session.session_id,
                                    "telemetry.reconciled",
                                    {"status": "offline"},
                                )
                            )
                        self.assertEqual(
                            server.emitted,
                            ["telemetry.reconciled"] * len(emissions),
                        )
                    finally:
                        server.release_emit.set()
                        pending = list(emissions)
                        if invalidation is not None:
                            pending.append(invalidation)
                        await asyncio.gather(*pending, return_exceptions=True)

                asyncio.run(exercise())

    def test_socketio_event_delivery_fails_closed_without_session_gate(self) -> None:
        from asgi import NativeSocketIO

        class Principal:
            may_stream = True

        class Runtime:
            def principal_for_session(
                self, _session_id: str, *, force_role_check: bool = False
            ) -> Principal:
                return Principal()

        class Server:
            def __init__(self) -> None:
                self.emitted: list[str] = []

            async def emit(self, event, _payload, *, to, namespace) -> None:
                self.emitted.append(event)

        native = object.__new__(NativeSocketIO)
        native.runtime = Runtime()
        native.server = Server()
        native._events_emitted_total = 0

        emitted = asyncio.run(
            native._emit_authorized(
                "socket-1", "session-without-gate", "telemetry.reconciled", {}
            )
        )

        self.assertFalse(emitted)
        self.assertEqual(native.server.emitted, [])

    def test_sync_invalidation_fails_fast_on_event_loop_and_async_helper_waits(self) -> None:
        from asgi import NativeSocketIO

        sessions = SessionStore()
        session = sessions.create("operator", "test-only-secret", role="owner")
        keep_session = sessions.create(
            "operator-keep", "test-only-secret", role="owner"
        )
        runtime = TelemetryRuntime(
            sessions=sessions,
            rest_url="https://router.example.test",
            ca_file=None,
            insecure_tls=False,
            api_ssl_port=8729,
            requested_transport="sse",
        )

        class Server:
            def __init__(self) -> None:
                self.emit_started = asyncio.Event()
                self.release_emit = asyncio.Event()

            async def emit(self, _event, _payload, *, to, namespace) -> None:
                self.emit_started.set()
                await self.release_emit.wait()

        server = Server()
        native = object.__new__(NativeSocketIO)
        native.runtime = runtime
        native.server = server
        native._events_emitted_total = 0

        async def exercise() -> None:
            emission = asyncio.create_task(
                native._emit_authorized(
                    "socket-1",
                    session.session_id,
                    "telemetry.reconciled",
                    {"status": "online"},
                )
            )
            invalidation = None
            try:
                await asyncio.wait_for(server.emit_started.wait(), timeout=1)
                with self.assertRaisesRegex(RuntimeError, "asyncio.to_thread"):
                    sessions.revoke(session.session_id)
                with self.assertRaisesRegex(RuntimeError, "asyncio.to_thread"):
                    sessions.revoke_all_except(keep_session.session_id)
                self.assertIsNotNone(sessions.get(session.session_id, touch=False))
                self.assertIsNotNone(
                    sessions.get(keep_session.session_id, touch=False)
                )

                invalidation = asyncio.create_task(
                    sessions.revoke_all_except_async(keep_session.session_id)
                )
                await asyncio.sleep(0.05)
                self.assertFalse(
                    invalidation.done(),
                    "the async helper must leave the event loop responsive while waiting",
                )
                server.release_emit.set()
                self.assertTrue(await asyncio.wait_for(emission, timeout=1))
                self.assertEqual(await asyncio.wait_for(invalidation, timeout=1), 1)
                self.assertIsNone(sessions.get(session.session_id, touch=False))
                self.assertIsNotNone(
                    sessions.get(keep_session.session_id, touch=False)
                )
            finally:
                server.release_emit.set()
                pending = [emission]
                if invalidation is not None:
                    pending.append(invalidation)
                await asyncio.gather(*pending, return_exceptions=True)

        asyncio.run(exercise())

    def test_bulk_revoke_covers_session_rotated_while_waiting_for_emit(self) -> None:
        from asgi import NativeSocketIO

        sessions = SessionStore()
        session = sessions.create("operator", "test-only-secret", role="owner")
        keep_session = sessions.create(
            "operator-keep", "test-only-secret", role="owner"
        )
        runtime = TelemetryRuntime(
            sessions=sessions,
            rest_url="https://router.example.test",
            ca_file=None,
            insecure_tls=False,
            api_ssl_port=8729,
            requested_transport="sse",
        )

        class Server:
            def __init__(self) -> None:
                self.emit_started = asyncio.Event()
                self.release_emit = asyncio.Event()

            async def emit(self, _event, _payload, *, to, namespace) -> None:
                self.emit_started.set()
                await self.release_emit.wait()

        server = Server()
        native = object.__new__(NativeSocketIO)
        native.runtime = runtime
        native.server = server
        native._events_emitted_total = 0

        async def exercise() -> None:
            emission = asyncio.create_task(
                native._emit_authorized(
                    "socket-1",
                    session.session_id,
                    "telemetry.reconciled",
                    {"status": "online"},
                )
            )
            rotation = None
            bulk_revoke = None
            try:
                await asyncio.wait_for(server.emit_started.wait(), timeout=1)
                rotation = asyncio.create_task(
                    sessions.rotate_async(
                        session.session_id,
                        "replacement-test-secret",
                        role="owner",
                    )
                )

                deadline = asyncio.get_running_loop().time() + 1
                while sessions.get(session.session_id, touch=False) is not None:
                    if asyncio.get_running_loop().time() >= deadline:
                        self.fail("rotation did not acquire the session-set gate")
                    await asyncio.sleep(0.01)
                self.assertTrue(sessions._session_set_lock.locked())

                bulk_started = threading.Event()

                def bulk_revoke_from_worker() -> int:
                    bulk_started.set()
                    return sessions.revoke_all_except(keep_session.session_id)

                bulk_revoke = asyncio.create_task(
                    asyncio.to_thread(bulk_revoke_from_worker)
                )
                self.assertTrue(await asyncio.to_thread(bulk_started.wait, 1))
                await asyncio.sleep(0.05)
                self.assertFalse(
                    bulk_revoke.done(),
                    "bulk revocation must serialize behind the in-flight rotation",
                )

                server.release_emit.set()
                replacement = await asyncio.wait_for(rotation, timeout=1)
                self.assertIsNotNone(replacement)
                self.assertEqual(await asyncio.wait_for(bulk_revoke, timeout=1), 1)
                self.assertIsNone(sessions.get(session.session_id, touch=False))
                self.assertIsNone(sessions.get(replacement.session_id, touch=False))
                self.assertIsNotNone(
                    sessions.get(keep_session.session_id, touch=False)
                )
            finally:
                server.release_emit.set()
                pending = [emission]
                if rotation is not None:
                    pending.append(rotation)
                if bulk_revoke is not None:
                    pending.append(bulk_revoke)
                await asyncio.gather(*pending, return_exceptions=True)

        asyncio.run(exercise())

    def test_socketio_cancelled_emit_drains_child_enqueue_before_revoke(self) -> None:
        import threading

        from asgi import NativeSocketIO

        sessions = SessionStore()
        session = sessions.create("operator", "test-only-secret", role="owner")
        runtime = TelemetryRuntime(
            sessions=sessions,
            rest_url="https://router.example.test",
            ca_file=None,
            insecure_tls=False,
            api_ssl_port=8729,
            requested_transport="sse",
        )

        class Server:
            def __init__(self) -> None:
                self.child_started = asyncio.Event()
                self.release_child = asyncio.Event()
                self.queued: list[str] = []

            async def emit(self, event, _payload, *, to, namespace) -> None:
                # Mirror AsyncManager.emit: child sends continue if its waiter
                # is cancelled unless the caller drains the manager task.
                child = asyncio.create_task(self._enqueue(event))
                await asyncio.wait((child,))

            async def _enqueue(self, event: str) -> None:
                self.child_started.set()
                await self.release_child.wait()
                self.queued.append(event)

        server = Server()
        native = object.__new__(NativeSocketIO)
        native.runtime = runtime
        native.server = server
        native._events_emitted_total = 0
        invalidation_started = threading.Event()

        async def exercise() -> None:
            emission = asyncio.create_task(
                native._emit_authorized(
                    "socket-1",
                    session.session_id,
                    "telemetry.reconciled",
                    {"status": "online"},
                )
            )
            invalidation = None
            try:
                await asyncio.wait_for(server.child_started.wait(), timeout=1)
                emission.cancel()

                def revoke():
                    invalidation_started.set()
                    return sessions.revoke(session.session_id)

                invalidation = asyncio.create_task(asyncio.to_thread(revoke))
                self.assertTrue(
                    await asyncio.to_thread(invalidation_started.wait, 1),
                    "revoke worker must start before checking its wait",
                )
                await asyncio.sleep(0.05)
                self.assertFalse(
                    invalidation.done(),
                    "revoke must wait for a child enqueue started by a cancelled emit",
                )

                server.release_child.set()
                with self.assertRaises(asyncio.CancelledError):
                    await asyncio.wait_for(emission, timeout=1)
                self.assertTrue(await asyncio.wait_for(invalidation, timeout=1))
                self.assertEqual(server.queued, ["telemetry.reconciled"])
            finally:
                server.release_child.set()
                pending = [emission]
                if invalidation is not None:
                    pending.append(invalidation)
                await asyncio.gather(*pending, return_exceptions=True)

        asyncio.run(exercise())

    def test_socketio_cancelled_connect_keeps_role_check_slot_until_worker_finishes(self) -> None:
        import threading

        from asgi import (
            NativeSocketIO,
            _SOCKETIO_ROLE_CHECK_LIMIT,
            _SOCKETIO_ROLE_CHECK_SLOTS,
        )

        started = threading.Event()
        finish = threading.Event()

        class Principal:
            may_stream = False

        class Runtime:
            def principal_for_session(
                self, _session_id: str, *, force_role_check: bool = False
            ) -> Principal:
                started.set()
                finish.wait(timeout=2)
                return Principal()

        native = object.__new__(NativeSocketIO)
        native.runtime = Runtime()
        native._subscriptions = {}
        native._session_ids = {}
        native._tasks = {}
        native._connections_total = 0
        native._disconnects_total = 0
        native._rejected_connections_total = 0
        environ = {
            "asgi.scope": {
                "headers": [(b"cookie", b"__Host-vpn_session=valid-session")],
            },
        }

        async def exercise() -> None:
            task = asyncio.create_task(native.connect("socket-cancelled", environ))
            self.assertTrue(await asyncio.to_thread(started.wait, 1))
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task

            acquired = 0
            try:
                for _ in range(_SOCKETIO_ROLE_CHECK_LIMIT - 1):
                    self.assertTrue(_SOCKETIO_ROLE_CHECK_SLOTS.acquire(blocking=False))
                    acquired += 1
                self.assertFalse(_SOCKETIO_ROLE_CHECK_SLOTS.acquire(blocking=False))
                finish.set()
                for _ in range(100):
                    if _SOCKETIO_ROLE_CHECK_SLOTS.acquire(blocking=False):
                        acquired += 1
                        break
                    await asyncio.sleep(0.01)
                self.assertEqual(acquired, _SOCKETIO_ROLE_CHECK_LIMIT)
            finally:
                for _ in range(acquired):
                    _SOCKETIO_ROLE_CHECK_SLOTS.release()

        try:
            asyncio.run(exercise())
        finally:
            finish.set()

    def test_socketio_subscription_and_pump_revalidate_off_loop(self) -> None:
        import threading

        from asgi import NativeSocketIO

        class Principal:
            may_stream = False

        class Runtime:
            def __init__(self) -> None:
                self.lookup_thread_ids: list[int] = []
                self.force_checks: list[bool] = []

            def principal_for_session(
                self, _session_id: str, *, force_role_check: bool = False
            ) -> Principal:
                self.lookup_thread_ids.append(threading.get_ident())
                self.force_checks.append(force_role_check)
                return Principal()

        class Server:
            def __init__(self) -> None:
                self.disconnects: list[tuple[str, str]] = []

            async def disconnect(self, sid: str, *, namespace: str) -> None:
                self.disconnects.append((sid, namespace))

        runtime = Runtime()
        server = Server()
        native = object.__new__(NativeSocketIO)
        native.runtime = runtime
        native.server = server
        native._subscriptions = {"socket-1": "subscription-1"}
        native._session_ids = {"socket-1": "valid-session"}
        native._tasks = {}
        loop_thread_id = 0

        async def exercise() -> dict[str, object]:
            nonlocal loop_thread_id
            loop_thread_id = threading.get_ident()
            subscription_result = await native.subscribe("socket-1")
            await native._pump("socket-1", "subscription-1")
            return subscription_result

        self.assertEqual(
            asyncio.run(exercise()), {"protocol_version": 2, "frames": []}
        )
        self.assertEqual(len(runtime.lookup_thread_ids), 2)
        self.assertTrue(all(thread_id != loop_thread_id for thread_id in runtime.lookup_thread_ids))
        self.assertEqual(runtime.force_checks, [False, False])
        self.assertEqual(server.disconnects, [("socket-1", NativeSocketIO.namespace)])

    @unittest.skipUnless(importlib.util.find_spec("socketio"), "optional Socket.IO runtime is not installed")
    def test_repeated_socketio_connect_revalidates_session_and_closes_namespace(self) -> None:
        import socketio

        from asgi import NativeSocketIO

        class Principal:
            may_stream = True

        class Runtime:
            gateway = None

            def __init__(self) -> None:
                self.authorized = True

            def principal_for_session(
                self, session_id: str, *, force_role_check: bool = False
            ) -> Principal | None:
                return Principal() if self.authorized and session_id == "valid-session" else None

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
        native = NativeSocketIO(runtime)

        environ = {
            "asgi.scope": {
                "headers": [(b"cookie", b"__Host-vpn_session=valid-session")],
            },
        }

        async def exercise() -> None:
            self.assertTrue(await native.connect("socket-1", environ))
            task = native._tasks["socket-1"]
            self.assertTrue(await native.connect("socket-1", environ))
            self.assertIs(native._tasks["socket-1"], task)

            runtime.authorized = False
            server = native.server
            server.environ["engine-1"] = environ
            manager_disconnects: list[tuple[str, str, bool]] = []
            packets: list[tuple[str, object]] = []

            async def manager_connect(_engine_sid: str, _namespace: str) -> str:
                return "socket-1"

            async def manager_disconnect(
                sid: str, namespace: str, *, ignore_queue: bool = False
            ) -> None:
                manager_disconnects.append((sid, namespace, ignore_queue))

            async def send_packet(engine_sid: str, packet: object) -> None:
                packets.append((engine_sid, packet))

            server.manager.connect = manager_connect
            server.manager.disconnect = manager_disconnect
            server._send_packet = send_packet
            await server._handle_connect("engine-1", native.namespace, None)

            self.assertNotIn("socket-1", native._subscriptions)
            self.assertNotIn("socket-1", native._session_ids)
            self.assertNotIn("socket-1", native._tasks)
            self.assertEqual(manager_disconnects, [("socket-1", native.namespace, True)])
            self.assertEqual(len(packets), 1)
            self.assertEqual(packets[0][0], "engine-1")
            self.assertIsInstance(packets[0][1], socketio.packet.Packet)
            self.assertEqual(packets[0][1].packet_type, socketio.packet.CONNECT_ERROR)
            self.assertEqual(packets[0][1].namespace, native.namespace)

        asyncio.run(exercise())

        self.assertEqual(gateway.opened, 1)
        self.assertEqual(gateway.closed, ["subscription-1"])
        self.assertEqual(native._connections_total, 1)
        self.assertEqual(native._disconnects_total, 1)
        self.assertEqual(native._rejected_connections_total, 1)
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
            delivery_lock = threading.Lock()

            @staticmethod
            def role_check_lock_for_session(_session_id: str):
                return Runtime.delivery_lock

            @staticmethod
            def cached_principal_for_session(
                _session_id: str, *, role_check_lock_held: bool = False
            ):
                return True, principal

            @staticmethod
            def principal_for_session(
                _session_id: str, *, force_role_check: bool = False
            ) -> TelemetryPrincipal:
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
                native.server.release_emit.set()
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
            delivery_lock = threading.Lock()

            @staticmethod
            def role_check_lock_for_session(_session_id: str):
                return Runtime.delivery_lock

            @staticmethod
            def cached_principal_for_session(
                _session_id: str, *, role_check_lock_held: bool = False
            ):
                return True, principal

            @staticmethod
            def principal_for_session(
                _session_id: str, *, force_role_check: bool = False
            ):
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
            def principal_for_session(
                _session_id: str, *, force_role_check: bool = False
            ) -> None:
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
            def principal_for_session(
                _session_id: str, *, force_role_check: bool = False
            ) -> TelemetryPrincipal:
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

    def test_expired_live_session_uses_monotonic_deadline_after_wall_clock_rollback(self) -> None:
        from asgi import NativeSocketIO

        clock = SimpleNamespace(wall=1000.0, monotonic_now=100.0)
        clock.time = lambda: clock.wall
        clock.monotonic = lambda: clock.monotonic_now
        sessions = SessionStore(idle_seconds=1, absolute_seconds=60)

        class FakeServer:
            def __init__(self) -> None:
                self.disconnected: list[tuple[str, str]] = []

            async def disconnect(self, sid: str, *, namespace: str) -> None:
                self.disconnected.append((sid, namespace))

        with mock.patch("security.time", clock):
            expired = sessions.create("operator", "router-password-marker")
            runtime = object.__new__(TelemetryRuntime)
            runtime.sessions = sessions
            native = object.__new__(NativeSocketIO)
            native.runtime = runtime
            native.server = FakeServer()
            native._subscriptions = {"socket-clock-rollback": "subscription-clock-rollback"}
            native._session_ids = {"socket-clock-rollback": expired.session_id}
            native._events_emitted_total = 0

            # Wall time is now earlier than session creation; only monotonic
            # elapsed time can prove that the idle deadline has passed.
            clock.wall = 900.0
            clock.monotonic_now = 102.0
            asyncio.run(native._pump("socket-clock-rollback", "subscription-clock-rollback"))

        self.assertIsNone(sessions.get(expired.session_id))
        self.assertEqual(native.server.disconnected, [("socket-clock-rollback", "/telemetry")])
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
        sessions._role_checked_monotonic[session.session_id] = 0
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
                    sessions._role_checked_monotonic[session.session_id] = 0
                else:
                    # Once RouterOS no longer resolves the account, the same
                    # established stream must be closed before another frame.
                    routeros_state["enabled"] = False
                    sessions._role_checked_monotonic[session.session_id] = 0

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
            delivery_lock = threading.Lock()

            @staticmethod
            def role_check_lock_for_session(_session_id: str):
                return Runtime.delivery_lock

            @staticmethod
            def cached_principal_for_session(
                _session_id: str, *, role_check_lock_held: bool = False
            ):
                return True, Principal() if state["authorized"] else None

            @staticmethod
            def principal_for_session(
                _session_id: str, *, force_role_check: bool = False
            ) -> Principal | None:
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
            delivery_lock = threading.Lock()

            @staticmethod
            def role_check_lock_for_session(_session_id: str):
                return Runtime.delivery_lock

            @staticmethod
            def cached_principal_for_session(
                _session_id: str, *, role_check_lock_held: bool = False
            ):
                return True, Principal() if state["authorized"] else None

            @staticmethod
            def principal_for_session(
                _session_id: str, *, force_role_check: bool = False
            ) -> Principal | None:
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
        self.assertEqual(response, {"protocol_version": 2, "frames": []})
        self.assertEqual(native._events_emitted_total, 1)
        self.assertEqual(native.server.disconnected, [("socket-subscribe", "/telemetry")])

    def test_http_adapter_preserves_duplicate_origin_and_csrf_fields_for_handler(self) -> None:
        request = DashboardHTTPASGI._request_bytes(
            {
                "method": "GET",
                "raw_path": b"/api/events",
                "headers": [
                    (b"origin", b"https://vpn.example.test"),
                    (b"origin", b"https://attacker.example"),
                    (b"x-csrf-token", b"valid-csrf-token"),
                    (b"x-csrf-token", b"attacker-supplied-token"),
                ],
            },
            b"",
        )
        header_block = request.split(b"\r\n", 1)[1].split(b"\r\n\r\n", 1)[0]
        parsed_headers = Message()
        for line in header_block.split(b"\r\n"):
            name, value = line.split(b":", 1)
            parsed_headers[name.decode("latin-1")] = value.strip().decode("latin-1")

        self.assertEqual(
            parsed_headers.get_all("Origin"),
            ["https://vpn.example.test", "https://attacker.example"],
        )
        self.assertEqual(
            parsed_headers.get_all("X-CSRF-Token"),
            ["valid-csrf-token", "attacker-supplied-token"],
        )

    def test_http_adapter_preserves_cookie_and_body_without_hop_by_hop_headers(self) -> None:
        request = DashboardHTTPASGI._request_bytes(
            {
                "method": "POST",
                "raw_path": b"/api/example",
                "query_string": b"a=1",
                "headers": [
                    (b"host", b"dashboard.example"),
                    (b"cookie", b"__Host-vpn_session=opaque"),
                    (b"connection", b"keep-alive"),
                    (b"transfer-encoding", b"chunked"),
                ],
            },
            b"{}",
        )
        self.assertIn(b"POST /api/example?a=1 HTTP/1.1", request)
        self.assertIn(b"cookie: __Host-vpn_session=opaque", request)
        self.assertIn(b"Content-Length: 2", request)
        self.assertNotIn(b"keep-alive", request)
        self.assertNotIn(b"chunked", request)

    def test_http_adapter_gates_only_live_telemetry_get_responses(self) -> None:
        self.assertTrue(DashboardHTTPASGI._requires_live_body_gate(
            {"method": "GET", "path": "/api/events"}
        ))
        self.assertFalse(DashboardHTTPASGI._requires_live_body_gate(
            {"method": "POST", "path": "/socket.io/"}
        ))
        self.assertFalse(DashboardHTTPASGI._requires_live_body_gate(
            {"method": "GET", "path": "/socket.io/"}
        ))
        self.assertFalse(DashboardHTTPASGI._requires_live_body_gate(
            {"method": "GET", "path": "/dashboard"}
        ))
        self.assertFalse(DashboardHTTPASGI._requires_live_body_gate(
            {"method": "POST", "path": "/api/events"}
        ))
        self.assertTrue(DashboardHTTPASGI._requires_live_send_timeout(
            {"method": "POST", "path": "/api/events"}
        ))
        self.assertFalse(DashboardHTTPASGI._requires_live_send_timeout(
            {"method": "GET", "path": "/dashboard"}
        ))

    def test_asgi_cookie_selection_matches_http_handler_for_duplicate_headers(self) -> None:
        from asgi import _session_id

        cases = (
            ("__Host-vpn_session=first-session", "__Host-vpn_session=second-session", "first-session"),
            ("__Host-vpn_session=second-session", "__Host-vpn_session=first-session", "second-session"),
        )
        for first, second, expected in cases:
            with self.subTest(first=first, second=second):
                headers = Message()
                headers.add_header("Cookie", first)
                headers.add_header("Cookie", second)
                handler_principal = DashboardHandler._session_id(
                    SimpleNamespace(headers=headers)
                )
                asgi_principal = _session_id({
                    "headers": [
                        (b"cookie", first.encode("ascii")),
                        (b"cookie", second.encode("ascii")),
                    ]
                })
                self.assertEqual(handler_principal, expected)
                self.assertEqual(asgi_principal, handler_principal)

        legacy_cookie = "vpn_session=legacy-session"
        legacy_headers = Message()
        legacy_headers.add_header("Cookie", legacy_cookie)
        self.assertEqual(
            DashboardHandler._session_id(SimpleNamespace(headers=legacy_headers)),
            "",
        )
        self.assertEqual(
            _session_id({"headers": [(b"cookie", legacy_cookie.encode("ascii"))]}),
            "",
        )

    def test_http_adapter_rejects_oversized_declared_body_before_reading(self) -> None:
        application = DashboardHTTPASGI(object())
        messages: list[dict[str, object]] = []
        receive_calls = 0

        async def receive() -> dict[str, object]:
            nonlocal receive_calls
            receive_calls += 1
            raise AssertionError("oversized declared bodies must be rejected before receive")

        async def send(message: dict[str, object]) -> None:
            messages.append(message)

        scope = {
            "type": "http",
            "http_version": "1.1",
            "method": "POST",
            "raw_path": b"/api/example",
            "headers": [
                (b"content-length", b"0"),
                (b"Content-Length", str(MAX_REQUEST_BODY_BYTES + 1).encode("ascii")),
            ],
        }
        with mock.patch.object(DashboardHTTPASGI, "_request_bytes") as request_bytes:
            asyncio.run(application(scope, receive, send))

        self.assertEqual(receive_calls, 0)
        request_bytes.assert_not_called()
        self.assertEqual(messages[0]["status"], 413)
        headers = dict(messages[0]["headers"])
        self.assertEqual(headers[b"content-length"], b"0")
        self.assertEqual(headers[b"connection"], b"close")
        self.assertEqual(messages[1], {"type": "http.response.body", "body": b""})

    def test_http_adapter_accepts_body_at_exact_limit(self) -> None:
        application = DashboardHTTPASGI(object())
        fake_client, fake_handler_socket = socket.socketpair()
        receive_calls = 0
        body_messages = 0

        async def receive() -> dict[str, object]:
            nonlocal receive_calls, body_messages
            receive_calls += 1
            if receive_calls == 1:
                body_messages += 1
                return {
                    "type": "http.request",
                    "body": b"x" * MAX_REQUEST_BODY_BYTES,
                    "more_body": False,
                }
            await asyncio.Future()

        async def send(message: dict[str, object]) -> None:
            raise AssertionError(f"unexpected ASGI response: {message!r}")

        scope = {
            "type": "http",
            "http_version": "1.1",
            "method": "POST",
            "raw_path": b"/api/example",
            "headers": [(b"content-length", str(MAX_REQUEST_BODY_BYTES).encode("ascii"))],
        }
        async def run_application() -> None:
            with (
                mock.patch("asgi.socket.socketpair", return_value=(fake_client, fake_handler_socket)),
                mock.patch("asgi.DashboardHandler"),
                mock.patch.object(
                    DashboardHTTPASGI, "_request_bytes", return_value=b"request"
                ) as request_bytes,
                mock.patch.object(DashboardHTTPASGI, "_stream_response", return_value=None),
            ):
                await application(scope, receive, send)
                request_bytes.assert_called_once()
                self.assertEqual(len(request_bytes.call_args.args[1]), MAX_REQUEST_BODY_BYTES)

        try:
            asyncio.run(run_application())
            # One receive delivers the request body. Depending on scheduler
            # timing, the disconnect watcher may or may not begin its next
            # receive before the response has completed.
            self.assertEqual(body_messages, 1)
            self.assertIn(receive_calls, (1, 2))
            fake_handler_socket.settimeout(1)
            self.assertEqual(fake_handler_socket.recv(7), b"request")
            self.assertEqual(fake_client.fileno(), -1)
        finally:
            fake_handler_socket.close()

    def test_http_adapter_caps_streamed_body_and_stops_receiving_on_overflow(self) -> None:
        application = DashboardHTTPASGI(object())
        messages: list[dict[str, object]] = []
        chunks = [
            {"type": "http.request", "body": b"x" * MAX_REQUEST_BODY_BYTES, "more_body": True},
            {"type": "http.request", "body": b"y", "more_body": True},
            {"type": "http.request", "body": b"unused", "more_body": False},
        ]
        receive_calls = 0

        async def receive() -> dict[str, object]:
            nonlocal receive_calls
            message = chunks[receive_calls]
            receive_calls += 1
            return message

        async def send(message: dict[str, object]) -> None:
            messages.append(message)

        scope = {
            "type": "http",
            "http_version": "1.1",
            "method": "POST",
            "raw_path": b"/api/example",
            "headers": [(b"content-length", b"not-a-number")],
        }
        with mock.patch.object(DashboardHTTPASGI, "_request_bytes") as request_bytes:
            asyncio.run(application(scope, receive, send))

        self.assertEqual(receive_calls, 2)
        request_bytes.assert_not_called()
        self.assertEqual(messages[0]["status"], 413)
        headers = dict(messages[0]["headers"])
        self.assertEqual(headers[b"content-length"], b"0")
        self.assertEqual(headers[b"connection"], b"close")
        self.assertEqual(messages[1], {"type": "http.response.body", "body": b""})

    def test_http_adapter_rejects_single_oversized_stream_chunk(self) -> None:
        application = DashboardHTTPASGI(object())
        messages: list[dict[str, object]] = []
        receive_calls = 0

        async def receive() -> dict[str, object]:
            nonlocal receive_calls
            receive_calls += 1
            return {
                "type": "http.request",
                "body": b"x" * (MAX_REQUEST_BODY_BYTES + 1),
                "more_body": True,
            }

        async def send(message: dict[str, object]) -> None:
            messages.append(message)

        scope = {
            "type": "http",
            "http_version": "1.1",
            "method": "POST",
            "raw_path": b"/api/example",
            "headers": [],
        }
        with mock.patch.object(DashboardHTTPASGI, "_request_bytes") as request_bytes:
            asyncio.run(application(scope, receive, send))

        self.assertEqual(receive_calls, 1)
        request_bytes.assert_not_called()
        self.assertEqual(messages[0]["status"], 413)
        self.assertEqual(dict(messages[0]["headers"])[b"connection"], b"close")

    def test_http_adapter_closes_http11_connection_after_early_413(self) -> None:
        if not importlib.util.find_spec("uvicorn"):
            self.skipTest("Uvicorn is not installed")

        import uvicorn

        async def exercise() -> bytes:
            application = DashboardHTTPASGI(object())
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", 0))
            listener.listen(128)
            listener.setblocking(False)
            host, port = listener.getsockname()
            server = uvicorn.Server(
                uvicorn.Config(application, log_level="critical", lifespan="off", access_log=False)
            )
            server_task = asyncio.create_task(server.serve(sockets=[listener]))
            writer: asyncio.StreamWriter | None = None
            try:
                deadline = asyncio.get_running_loop().time() + 5
                while not server.started and not server_task.done():
                    if asyncio.get_running_loop().time() >= deadline:
                        self.fail("test ASGI server did not start")
                    await asyncio.sleep(0.01)

                reader, writer = await asyncio.open_connection(host, port)
                body = b"x" * (MAX_REQUEST_BODY_BYTES + 1)
                writer.write(
                    b"POST /api/example HTTP/1.1\r\n"
                    b"Host: localhost\r\n"
                    + f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
                    + body
                )
                await writer.drain()
                return await asyncio.wait_for(reader.read(), timeout=5)
            finally:
                if writer is not None:
                    writer.close()
                    await writer.wait_closed()
                server.should_exit = True
                await asyncio.wait_for(server_task, timeout=5)

        response = asyncio.run(exercise())
        headers, body = response.split(b"\r\n\r\n", 1)
        self.assertIn(b"HTTP/1.1 413", headers)
        self.assertIn(b"connection: close", headers.lower())
        self.assertEqual(body, b"")

    def test_http_adapter_uses_asgi_peer_for_trusted_proxy_resolution_and_client_identity(self) -> None:
        from app import DashboardHandler

        application = DashboardHTTPASGI(object())
        context = SimpleNamespace(config=SimpleNamespace(
            trusted_proxy_header="X-Forwarded-For",
            trusted_proxy_sources=("192.0.2.10",),
        ))
        observed: list[tuple[str, str]] = []
        current_headers: list[tuple[bytes, bytes]] = []

        class CapturingHandler:
            def __init__(
                self,
                request: socket.socket,
                client_address: tuple[str, int],
                _server: object,
            ) -> None:
                self.client_address = client_address
                self.server = SimpleNamespace(context=context)
                self.headers = Message()
                for name, value in current_headers:
                    self.headers.add_header(name.decode("latin-1"), value.decode("latin-1"))
                observed.append((client_address[0], DashboardHandler._client_ip(self)))
                request.recv(65536)
                request.sendall(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )
                request.close()

        async def exercise() -> list[int]:
            statuses: list[int] = []
            cases = (
                ("192.0.2.10", "198.51.100.10, 203.0.113.42"),
                ("198.51.100.77", "203.0.113.43"),
                (None, "203.0.113.44"),
            )
            with mock.patch("asgi.DashboardHandler", CapturingHandler):
                for peer, forwarded in cases:
                    current_headers[:] = [
                        (b"host", b"dashboard.example"),
                        (b"x-forwarded-for", forwarded.encode("ascii")),
                    ]
                    scope = {
                        "type": "http",
                        "asgi": {"version": "3.0"},
                        "http_version": "1.1",
                        "method": "GET",
                        "scheme": "https",
                        "path": "/",
                        "raw_path": b"/",
                        "query_string": b"",
                        "headers": current_headers.copy(),
                        "client": (peer, 54321) if peer is not None else None,
                        "server": ("dashboard.example", 443),
                    }
                    request_received = False
                    messages: list[dict[str, object]] = []

                    async def receive() -> dict[str, object]:
                        nonlocal request_received
                        if not request_received:
                            request_received = True
                            return {"type": "http.request", "body": b"", "more_body": False}
                        await asyncio.Future()

                    async def send(message: dict[str, object]) -> None:
                        messages.append(message)

                    await application(scope, receive, send)
                    statuses.append(next(
                        int(message["status"])
                        for message in messages
                        if message.get("type") == "http.response.start"
                    ))
            return statuses

        self.assertEqual(asyncio.run(exercise()), [200, 200, 200])
        self.assertEqual(
            observed,
            [
                ("192.0.2.10", "203.0.113.42"),
                ("198.51.100.77", "198.51.100.77"),
                ("unknown", "unknown"),
            ],
        )
        self.assertNotEqual(observed[0][1], observed[1][1])

    def test_uvicorn_proxy_header_rewriting_is_disabled(self) -> None:
        from asgi import DashboardHTTPASGI
        self.assertEqual(
            DashboardHTTPASGI._uvicorn_proxy_options(),
            {"proxy_headers": False, "forwarded_allow_ips": ""},
        )

    def test_trusted_proxy_scheme_middleware_preserves_configured_client_header(self) -> None:
        from app import DashboardHandler
        from asgi import DashboardHTTPASGI, TrustedProxySchemeASGI

        http_adapter = DashboardHTTPASGI(object())
        context = SimpleNamespace(config=SimpleNamespace(
            trusted_proxy_header="CF-Connecting-IP",
            trusted_proxy_sources=("192.0.2.10",),
        ))
        observed_clients: list[tuple[str, str]] = []
        observed_schemes: list[str] = []
        current_headers: list[tuple[bytes, bytes]] = []

        class CapturingHandler:
            def __init__(
                self,
                request: socket.socket,
                client_address: tuple[str, int],
                _server: object,
            ) -> None:
                self.client_address = client_address
                self.server = SimpleNamespace(context=context)
                self.headers = Message()
                for name, value in current_headers:
                    self.headers.add_header(name.decode("latin-1"), value.decode("latin-1"))
                observed_clients.append((client_address[0], DashboardHandler._client_ip(self)))
                request.recv(65536)
                request.sendall(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )
                request.close()

        async def record_scope(scope, receive, send) -> None:
            observed_schemes.append(str(scope["scheme"]))
            await http_adapter(scope, receive, send)

        application = TrustedProxySchemeASGI(record_scope, ("192.0.2.10",))

        async def exercise() -> list[int]:
            statuses: list[int] = []
            cases = (
                ("192.0.2.10", "203.0.113.50", "198.51.100.50", "https"),
                ("192.0.2.10", "203.0.113.51", "malformed-xff", "https"),
                ("198.51.100.77", "203.0.113.52", "203.0.113.53", "https"),
                (None, "203.0.113.54", "203.0.113.55", "https"),
            )
            with mock.patch("asgi.DashboardHandler", CapturingHandler):
                for peer, cf_address, forwarded, proto in cases:
                    current_headers[:] = [
                        (b"host", b"dashboard.example"),
                        (b"cf-connecting-ip", cf_address.encode("ascii")),
                        (b"x-forwarded-for", forwarded.encode("ascii")),
                        (b"x-forwarded-proto", proto.encode("ascii")),
                    ]
                    scope = {
                        "type": "http",
                        "asgi": {"version": "3.0"},
                        "http_version": "1.1",
                        "method": "GET",
                        "scheme": "http",
                        "path": "/",
                        "raw_path": b"/",
                        "query_string": b"",
                        "headers": current_headers.copy(),
                        "client": (peer, 54321) if peer is not None else None,
                        "server": ("dashboard.example", 443),
                    }
                    request_received = False
                    messages: list[dict[str, object]] = []

                    async def receive() -> dict[str, object]:
                        nonlocal request_received
                        if not request_received:
                            request_received = True
                            return {"type": "http.request", "body": b"", "more_body": False}
                        await asyncio.Future()

                    async def send(message: dict[str, object]) -> None:
                        messages.append(message)

                    await application(scope, receive, send)
                    statuses.append(next(
                        int(message["status"])
                        for message in messages
                        if message.get("type") == "http.response.start"
                    ))
            return statuses

        self.assertEqual(asyncio.run(exercise()), [200, 200, 200, 200])
        self.assertEqual(
            observed_clients,
            [
                ("192.0.2.10", "203.0.113.50"),
                ("192.0.2.10", "203.0.113.51"),
                ("198.51.100.77", "198.51.100.77"),
                ("unknown", "unknown"),
            ],
        )
        self.assertEqual(observed_schemes, ["https", "https", "http", "http"])

    def test_trusted_proxy_scheme_middleware_maps_websocket_scheme_only_for_trusted_peer(self) -> None:
        from asgi import TrustedProxySchemeASGI

        observed: list[tuple[object, str]] = []

        async def capture_scope(scope, _receive, _send) -> None:
            observed.append((scope.get("client"), str(scope["scheme"])))

        application = TrustedProxySchemeASGI(capture_scope, ("192.0.2.10",))

        async def exercise() -> None:
            for peer in ("192.0.2.10", "198.51.100.77"):
                await application(
                    {
                        "type": "websocket",
                        "scheme": "ws",
                        "client": (peer, 3000),
                        "headers": [(b"x-forwarded-proto", b"https")],
                    },
                    None,
                    None,
                )

        asyncio.run(exercise())
        self.assertEqual(
            observed,
            [
                (("192.0.2.10", 3000), "wss"),
                (("198.51.100.77", 3000), "ws"),
            ],
        )

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

    def test_asgi_live_body_serializes_revocation_with_actual_send(self) -> None:
        from telemetry_gateway import TelemetryPrincipal

        sessions = SessionStore(idle_seconds=60, absolute_seconds=300)
        session = sessions.create("operator", "test-only-password", role="owner")

        class Runtime:
            @staticmethod
            def role_check_lock_for_session(session_id: str):
                return sessions.role_check_lock(session_id)

            @staticmethod
            def cached_principal_for_session(
                session_id: str, *, role_check_lock_held: bool = False
            ):
                current = sessions.get(
                    session_id,
                    touch=False,
                    role_check_lock_held=role_check_lock_held,
                    wait_for_role_check_lock=False,
                )
                return True, TelemetryPrincipal.from_session(current)

            @staticmethod
            def principal_for_session(
                session_id: str, *, force_role_check: bool = False
            ):
                current = sessions.get(session_id, touch=False)
                return TelemetryPrincipal.from_session(current)

        application = DashboardHTTPASGI(
            SimpleNamespace(telemetry_runtime=Runtime())
        )
        client, handler_socket = socket.socketpair()
        handler_socket.sendall(
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Length: 5\r\n"
            b"Connection: close\r\n\r\n"
            b"frame"
        )
        handler_socket.shutdown(socket.SHUT_WR)
        send_started = asyncio.Event()
        release_send = asyncio.Event()
        sent: list[dict[str, object]] = []
        revocation: asyncio.Task[bool] | None = None

        async def send(message: dict[str, object]) -> None:
            if message.get("body") == b"frame":
                send_started.set()
                await release_send.wait()
            sent.append(message)

        async def authorize(message: dict[str, object]) -> bool:
            return await application._send_authorized_live_message(
                session.session_id, message, send
            )

        async def exercise() -> None:
            nonlocal revocation
            try:
                response = await asyncio.to_thread(
                    DashboardHTTPASGI._stream_response,
                    client,
                    send,
                    authorize,
                )
                self.assertIsNotNone(response)
                stream = asyncio.create_task(response)
                await asyncio.wait_for(send_started.wait(), timeout=1)
                revocation = asyncio.create_task(
                    asyncio.to_thread(sessions.revoke, session.session_id)
                )
                await asyncio.sleep(0.05)
                self.assertFalse(revocation.done())
                release_send.set()
                await asyncio.wait_for(stream, timeout=1)
                self.assertTrue(await asyncio.wait_for(revocation, timeout=1))
            finally:
                release_send.set()
                client.close()
                handler_socket.close()

        asyncio.run(exercise())
        self.assertEqual(
            sum(message.get("body") == b"frame" for message in sent),
            1,
        )

        denied_client, denied_handler = socket.socketpair()
        denied_handler.sendall(
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nframe"
        )
        denied_handler.shutdown(socket.SHUT_WR)
        denied_messages: list[dict[str, object]] = []

        async def denied_send(message: dict[str, object]) -> None:
            denied_messages.append(message)

        async def denied_authorize(message: dict[str, object]) -> bool:
            return await application._send_authorized_live_message(
                session.session_id, message, denied_send
            )

        async def deny_revoked_session() -> None:
            try:
                response = await asyncio.to_thread(
                    DashboardHTTPASGI._stream_response,
                    denied_client,
                    denied_send,
                    denied_authorize,
                )
                self.assertIsNotNone(response)
                await asyncio.wait_for(response, timeout=1)
            finally:
                denied_client.close()
                denied_handler.close()

        asyncio.run(deny_revoked_session())
        self.assertNotIn(b"frame", [message.get("body") for message in denied_messages])
        self.assertEqual(denied_messages[-1], {"type": "http.response.body", "body": b""})

    def test_http_adapter_wires_live_route_to_asgi_send_gate(self) -> None:
        from telemetry_gateway import TelemetryPrincipal

        sessions = SessionStore(idle_seconds=60, absolute_seconds=300)
        session = sessions.create("operator", "test-only-password", role="owner")

        class Runtime:
            @staticmethod
            def role_check_lock_for_session(session_id: str):
                return sessions.role_check_lock(session_id)

            @staticmethod
            def cached_principal_for_session(
                session_id: str, *, role_check_lock_held: bool = False
            ):
                current = sessions.get(
                    session_id,
                    touch=False,
                    role_check_lock_held=role_check_lock_held,
                    wait_for_role_check_lock=False,
                )
                return True, TelemetryPrincipal.from_session(current)

            @staticmethod
            def principal_for_session(
                session_id: str, *, force_role_check: bool = False
            ):
                return TelemetryPrincipal.from_session(
                    sessions.get(session_id, touch=False)
                )

        class Handler:
            def __init__(self, request: socket.socket, _peer, _server) -> None:
                request.recv(4096)
                request.sendall(b"HTTP/1.1 200 OK\r\n\r\nframe")
                request.close()

        application = DashboardHTTPASGI(
            SimpleNamespace(telemetry_runtime=Runtime())
        )
        scope = {
            "type": "http",
            "http_version": "1.1",
            "method": "GET",
            "path": "/api/events",
            "raw_path": b"/api/events",
            "query_string": b"",
            "headers": [
                (b"host", b"dashboard.example"),
                (b"cookie", f"__Host-vpn_session={session.session_id}".encode("ascii")),
            ],
            "client": ("127.0.0.1", 12345),
        }
        request_sent = False
        send_started = asyncio.Event()
        release_send = asyncio.Event()
        messages: list[dict[str, object]] = []

        async def receive() -> dict[str, object]:
            nonlocal request_sent
            if not request_sent:
                request_sent = True
                return {"type": "http.request", "body": b"", "more_body": False}
            await asyncio.Future()

        async def send(message: dict[str, object]) -> None:
            if message.get("body") == b"frame":
                send_started.set()
                await release_send.wait()
            messages.append(message)

        async def exercise() -> None:
            with mock.patch("asgi.DashboardHandler", Handler):
                request = asyncio.create_task(application(scope, receive, send))
                revocation: asyncio.Task[bool] | None = None
                try:
                    await asyncio.wait_for(send_started.wait(), timeout=1)
                    revocation = asyncio.create_task(
                        asyncio.to_thread(sessions.revoke, session.session_id)
                    )
                    await asyncio.sleep(0.05)
                    self.assertFalse(revocation.done())
                    release_send.set()
                    await asyncio.wait_for(request, timeout=1)
                    self.assertTrue(await asyncio.wait_for(revocation, timeout=1))
                finally:
                    release_send.set()
                    if not request.done():
                        request.cancel()
                    await asyncio.gather(request, return_exceptions=True)

        asyncio.run(exercise())
        self.assertEqual(
            sum(message.get("body") == b"frame" for message in messages),
            1,
        )

    def test_asgi_live_body_drains_cancelled_send_before_releasing_session_lock(self) -> None:
        from telemetry_gateway import TelemetryPrincipal

        sessions = SessionStore(idle_seconds=60, absolute_seconds=300)
        session = sessions.create("operator", "test-only-password", role="owner")

        class Runtime:
            @staticmethod
            def role_check_lock_for_session(session_id: str):
                return sessions.role_check_lock(session_id)

            @staticmethod
            def cached_principal_for_session(
                session_id: str, *, role_check_lock_held: bool = False
            ):
                current = sessions.get(
                    session_id,
                    touch=False,
                    role_check_lock_held=role_check_lock_held,
                    wait_for_role_check_lock=False,
                )
                return True, TelemetryPrincipal.from_session(current)

            @staticmethod
            def principal_for_session(
                session_id: str, *, force_role_check: bool = False
            ):
                return TelemetryPrincipal.from_session(
                    sessions.get(session_id, touch=False)
                )

        application = DashboardHTTPASGI(
            SimpleNamespace(telemetry_runtime=Runtime())
        )
        send_started = asyncio.Event()
        release_send = asyncio.Event()
        sent: list[dict[str, object]] = []

        async def send(message: dict[str, object]) -> None:
            send_started.set()
            await release_send.wait()
            sent.append(message)

        async def exercise() -> None:
            delivery = asyncio.create_task(
                application._send_authorized_live_message(
                    session.session_id,
                    {"type": "http.response.body", "body": b"frame"},
                    send,
                )
            )
            revocation: asyncio.Task[bool] | None = None
            try:
                await asyncio.wait_for(send_started.wait(), timeout=1)
                delivery.cancel()
                await asyncio.sleep(0.05)
                revocation = asyncio.create_task(
                    asyncio.to_thread(sessions.revoke, session.session_id)
                )
                await asyncio.sleep(0.05)
                self.assertFalse(revocation.done())
                release_send.set()
                result = await asyncio.gather(delivery, return_exceptions=True)
                self.assertIsInstance(result[0], asyncio.CancelledError)
                self.assertTrue(await asyncio.wait_for(revocation, timeout=1))
            finally:
                release_send.set()
                if not delivery.done():
                    delivery.cancel()
                await asyncio.gather(delivery, return_exceptions=True)

        asyncio.run(exercise())
        self.assertEqual(
            sent,
            [{"type": "http.response.body", "body": b"frame"}],
        )

    def test_asgi_live_send_timeout_cancels_child_before_releasing_session_lock(self) -> None:
        from telemetry_gateway import TelemetryPrincipal

        sessions = SessionStore(idle_seconds=60, absolute_seconds=300)
        session = sessions.create("operator", "test-only-password", role="owner")

        class Runtime:
            @staticmethod
            def role_check_lock_for_session(session_id: str):
                return sessions.role_check_lock(session_id)

            @staticmethod
            def cached_principal_for_session(
                session_id: str, *, role_check_lock_held: bool = False
            ):
                current = sessions.get(
                    session_id,
                    touch=False,
                    role_check_lock_held=role_check_lock_held,
                    wait_for_role_check_lock=False,
                )
                return True, TelemetryPrincipal.from_session(current)

            @staticmethod
            def principal_for_session(
                session_id: str, *, force_role_check: bool = False
            ):
                return TelemetryPrincipal.from_session(
                    sessions.get(session_id, touch=False)
                )

        application = DashboardHTTPASGI(
            SimpleNamespace(telemetry_runtime=Runtime())
        )
        send_started = asyncio.Event()
        send_cancelled = asyncio.Event()

        async def blocked_send(_message: dict[str, object]) -> None:
            send_started.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                send_cancelled.set()
                raise

        async def exercise() -> None:
            with mock.patch("asgi._ASGI_LIVE_BODY_SEND_TIMEOUT_SECONDS", 0.05):
                delivery = asyncio.create_task(
                    application._send_authorized_live_message(
                        session.session_id,
                        {"type": "http.response.body", "body": b"frame"},
                        blocked_send,
                    )
                )
                revocation: asyncio.Task[bool] | None = None
                try:
                    await asyncio.wait_for(send_started.wait(), timeout=1)
                    revocation = asyncio.create_task(
                        asyncio.to_thread(sessions.revoke, session.session_id)
                    )
                    await asyncio.sleep(0.02)
                    self.assertFalse(revocation.done())
                    with self.assertRaises(TimeoutError):
                        await delivery
                    self.assertTrue(send_cancelled.is_set())
                    self.assertTrue(await asyncio.wait_for(revocation, timeout=1))
                finally:
                    if not delivery.done():
                        delivery.cancel()
                    await asyncio.gather(delivery, return_exceptions=True)

    def test_asgi_live_send_failure_aborts_without_terminal_body_send(self) -> None:
        client, producer = socket.socketpair()
        producer.sendall(b"HTTP/1.1 200 OK\r\n\r\nframe")
        producer.shutdown(socket.SHUT_WR)
        sent: list[dict[str, object]] = []

        async def send(message: dict[str, object]) -> None:
            sent.append(message)

        async def fail_body_send(_message: dict[str, object]) -> bool:
            raise TimeoutError("simulated ASGI send timeout")

        async def exercise() -> None:
            response = DashboardHTTPASGI._stream_response(
                client,
                send,
                protected_body_send=fail_body_send,
            )
            self.assertIsNotNone(response)
            if response is not None:
                with self.assertRaisesRegex(TimeoutError, "simulated ASGI send timeout"):
                    await response

        try:
            asyncio.run(exercise())
        finally:
            client.close()
            producer.close()

        self.assertEqual(
            sent,
            [{"type": "http.response.start", "status": 200, "headers": []}],
        )

    def test_asgi_live_terminal_send_timeout_cancels_denied_and_eof_sends(self) -> None:
        for scenario in ("denied", "eof"):
            with self.subTest(scenario=scenario):
                client, producer = socket.socketpair()
                response = (
                    b"HTTP/1.1 200 OK\r\n\r\nframe"
                    if scenario == "denied"
                    else b"HTTP/1.1 200 OK\r\n\r\n"
                )
                producer.sendall(response)
                producer.shutdown(socket.SHUT_WR)
                sent: list[dict[str, object]] = []
                terminal_started = asyncio.Event()
                terminal_cancelled = asyncio.Event()
                protected_body_calls = 0

                async def send(message: dict[str, object]) -> None:
                    sent.append(message)
                    if message.get("type") != "http.response.body" or message.get("body"):
                        return
                    terminal_started.set()
                    try:
                        await asyncio.Event().wait()
                    except asyncio.CancelledError:
                        terminal_cancelled.set()
                        raise

                async def allow_body_send(_message: dict[str, object]) -> bool:
                    nonlocal protected_body_calls
                    protected_body_calls += 1
                    return scenario != "denied"

                async def exercise() -> None:
                    with mock.patch("asgi._ASGI_LIVE_BODY_SEND_TIMEOUT_SECONDS", 0.05):
                        stream = DashboardHTTPASGI._stream_response(
                            client,
                            send,
                            protected_body_send=allow_body_send,
                        )
                        self.assertIsNotNone(stream)
                        if stream is not None:
                            with self.assertRaises(TimeoutError):
                                await stream
                    self.assertTrue(terminal_started.is_set())
                    self.assertTrue(terminal_cancelled.is_set())

                try:
                    asyncio.run(exercise())
                finally:
                    client.close()
                    producer.close()

                self.assertEqual(
                    protected_body_calls,
                    1 if scenario == "denied" else 0,
                )
                self.assertEqual(
                    sent,
                    [
                        {"type": "http.response.start", "status": 200, "headers": []},
                        {"type": "http.response.body", "body": b""},
                    ],
                )

    def test_asgi_live_error_responses_bound_start_and_body_sends(self) -> None:
        for stalled_stage in ("start", "body"):
            with self.subTest(stalled_stage=stalled_stage):
                client, producer = socket.socketpair()
                producer.sendall(
                    b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 5\r\n\r\nerror"
                )
                producer.shutdown(socket.SHUT_WR)
                sent: list[dict[str, object]] = []
                send_started = asyncio.Event()
                send_cancelled = asyncio.Event()
                auth_calls = 0

                async def send(message: dict[str, object]) -> None:
                    sent.append(message)
                    current_stage = (
                        "start"
                        if message.get("type") == "http.response.start"
                        else "body"
                    )
                    if current_stage != stalled_stage:
                        return
                    send_started.set()
                    try:
                        await asyncio.Event().wait()
                    except asyncio.CancelledError:
                        send_cancelled.set()
                        raise

                async def authorize(_message: dict[str, object]) -> bool:
                    nonlocal auth_calls
                    auth_calls += 1
                    return True

                async def exercise() -> None:
                    with mock.patch("asgi._ASGI_LIVE_BODY_SEND_TIMEOUT_SECONDS", 0.05):
                        stream = DashboardHTTPASGI._stream_response(
                            client,
                            send,
                            protected_body_send=authorize,
                        )
                        self.assertIsNotNone(stream)
                        if stream is not None:
                            with self.assertRaises(TimeoutError):
                                await stream
                    self.assertTrue(send_started.is_set())
                    self.assertTrue(send_cancelled.is_set())

                try:
                    asyncio.run(exercise())
                finally:
                    client.close()
                    producer.close()

                self.assertEqual(auth_calls, 0)
                self.assertFalse(
                    any(
                        message.get("type") == "http.response.body"
                        and not message.get("body")
                        for message in sent
                    )
                )

    def test_socketio_websocket_send_gate_withholds_queued_frame_after_revocation(self) -> None:
        from asgi import SocketIOLiveSendASGI
        from telemetry_gateway import TelemetryPrincipal

        sessions = SessionStore(idle_seconds=60, absolute_seconds=300)
        session = sessions.create("operator", "test-only-password", role="owner")

        class Runtime:
            @staticmethod
            def role_check_lock_for_session(session_id: str):
                return sessions.role_check_lock(session_id)

            @staticmethod
            def cached_principal_for_session(
                session_id: str, *, role_check_lock_held: bool = False
            ):
                current = sessions.get(
                    session_id,
                    touch=False,
                    role_check_lock_held=role_check_lock_held,
                    wait_for_role_check_lock=False,
                )
                return (
                    True,
                    TelemetryPrincipal.from_session(current) if current else None,
                )

            @staticmethod
            def principal_for_session(
                session_id: str, *, force_role_check: bool = False
            ):
                current = sessions.get(session_id, touch=False)
                return TelemetryPrincipal.from_session(current) if current else None

        runtime = Runtime()
        http_adapter = DashboardHTTPASGI(SimpleNamespace(telemetry_runtime=runtime))
        send_started = asyncio.Event()
        release_send = asyncio.Event()
        revoke_finished = asyncio.Event()
        sent: list[dict[str, object]] = []

        async def inner(_scope, _receive, send) -> None:
            await send({"type": "websocket.accept"})
            await send({"type": "websocket.send", "text": "before-revocation"})
            await revoke_finished.wait()
            await send({"type": "websocket.send", "text": "queued-after-revocation"})
            await send({"type": "websocket.send", "text": "41/telemetry,"})

        gate = SocketIOLiveSendASGI(inner, http_adapter)

        async def send(message: dict[str, object]) -> None:
            if message.get("type") == "websocket.send":
                send_started.set()
                if message.get("text") == "before-revocation":
                    await release_send.wait()
            sent.append(message)

        scope = {
            "type": "websocket",
            "path": "/socket.io/extra",
            "headers": [(b"cookie", f"__Host-vpn_session={session.session_id}".encode("ascii"))],
        }

        async def exercise() -> None:
            transport = asyncio.create_task(gate(scope, asyncio.Future, send))
            await asyncio.wait_for(send_started.wait(), timeout=1)
            revocation = asyncio.create_task(asyncio.to_thread(sessions.revoke, session.session_id))
            await asyncio.sleep(0.02)
            self.assertFalse(revocation.done())
            release_send.set()
            self.assertTrue(await asyncio.wait_for(revocation, timeout=1))
            revoke_finished.set()
            await asyncio.wait_for(transport, timeout=1)

        asyncio.run(exercise())
        self.assertIn(
            {"type": "websocket.send", "text": "before-revocation"},
            sent,
        )
        self.assertNotIn(
            {"type": "websocket.send", "text": "queued-after-revocation"},
            sent,
        )
        self.assertIn(
            {"type": "websocket.send", "text": "41/telemetry,"},
            sent,
        )

    def test_socketio_polling_send_gate_withholds_queued_frame_after_revocation(self) -> None:
        from asgi import SocketIOLiveSendASGI
        from telemetry_gateway import TelemetryPrincipal

        sessions = SessionStore(idle_seconds=60, absolute_seconds=300)
        session = sessions.create("operator", "test-only-password", role="owner")

        class Runtime:
            @staticmethod
            def role_check_lock_for_session(session_id: str):
                return sessions.role_check_lock(session_id)

            @staticmethod
            def cached_principal_for_session(
                session_id: str, *, role_check_lock_held: bool = False
            ):
                current = sessions.get(
                    session_id,
                    touch=False,
                    role_check_lock_held=role_check_lock_held,
                    wait_for_role_check_lock=False,
                )
                return (
                    True,
                    TelemetryPrincipal.from_session(current) if current else None,
                )

            @staticmethod
            def principal_for_session(
                session_id: str, *, force_role_check: bool = False
            ):
                current = sessions.get(session_id, touch=False)
                return TelemetryPrincipal.from_session(current) if current else None

        runtime = Runtime()
        runtime.sessions = sessions
        http_adapter = DashboardHTTPASGI(SimpleNamespace(telemetry_runtime=runtime))
        sent: list[dict[str, object]] = []
        private_marker = "polling-frame-after-revocation"
        sessions.revoke(session.session_id)

        async def inner(_scope, _receive, send) -> None:
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({
                "type": "http.response.body",
                "body": private_marker.encode("ascii"),
                "more_body": True,
            })
            await send({"type": "http.response.body", "body": b""})

        async def send(message: dict[str, object]) -> None:
            sent.append(message)

        gate = SocketIOLiveSendASGI(inner, http_adapter)
        scope = {
            "type": "http",
            "method": "GET",
            "path": "/socket.io/extra",
            "headers": [(b"cookie", f"__Host-vpn_session={session.session_id}".encode("ascii"))],
        }
        asyncio.run(gate(scope, asyncio.Future, send))

        self.assertFalse(
            any(private_marker.encode("ascii") in message.get("body", b"") for message in sent)
        )
        self.assertEqual(len(sent), 2)
        self.assertEqual(sent[0]["status"], 403)
        self.assertEqual(sent[-1], {"type": "http.response.body", "body": b""})

    def test_socketio_engine_sid_is_bound_to_originating_session(self) -> None:
        from asgi import SocketIOLiveSendASGI

        session_id = "session-before-rotation"
        replacement_session_id = "session-after-rotation"
        engine_sid = "engine-session-id"
        inner_scopes: list[dict[str, object]] = []

        async def inner(scope, _receive, send) -> None:
            inner_scopes.append(dict(scope))
            await send({"type": "http.response.start", "status": 200, "headers": []})
            body = (
                f'0{{"sid":"{engine_sid}","upgrades":[]}}'.encode("ascii")
                if b"sid=" not in bytes(scope.get("query_string", b""))
                else b'42/telemetry,["private-frame"]'
            )
            await send({"type": "http.response.body", "body": body, "more_body": True})
            await send({"type": "http.response.body", "body": b""})

        async def authorized_send(
            current_session_id: str, message: dict[str, object], send
        ) -> bool:
            if current_session_id != session_id:
                return False
            await DashboardHTTPASGI._send_and_drain(send, message)
            return True

        class ActiveSessions:
            @staticmethod
            def get(candidate_session_id: str, *, touch: bool, wait_for_role_check_lock: bool):
                return object() if candidate_session_id == session_id else None

        adapter = SimpleNamespace(
            _send_authorized_live_message=authorized_send,
            server=SimpleNamespace(telemetry_runtime=SimpleNamespace(sessions=ActiveSessions())),
        )
        gate = SocketIOLiveSendASGI(inner, adapter)
        sent: list[dict[str, object]] = []

        async def send(message: dict[str, object]) -> None:
            sent.append(message)

        def scope(scope_type: str, cookie_session_id: str) -> dict[str, object]:
            return {
                "type": scope_type,
                "method": "GET",
                "path": "/socket.io/",
                "query_string": b"EIO=4&transport=polling",
                "headers": [
                    (b"cookie", f"__Host-vpn_session={cookie_session_id}".encode("ascii"))
                ],
            }

        async def exercise() -> None:
            # Initial Engine.IO handshake is allowed only through the live send gate.
            await gate(scope("http", session_id), asyncio.Future, send)
            self.assertTrue(gate._session_matches_engine_sid(engine_sid, session_id))

            mismatch = scope("http", replacement_session_id)
            mismatch["path"] = "/socket.io/extra"
            mismatch["query_string"] = f"EIO=4&transport=polling&sid={engine_sid}".encode()
            await gate(mismatch, asyncio.Future, send)
            self.assertEqual(sent[-2]["status"], 403)
            self.assertEqual(len(inner_scopes), 1)

            websocket_upgrade = scope("websocket", replacement_session_id)
            websocket_upgrade["path"] = "/socket.io/extra"
            websocket_upgrade["query_string"] = f"EIO=4&transport=websocket&sid={engine_sid}".encode()
            await gate(websocket_upgrade, asyncio.Future, send)
            self.assertEqual(sent[-1], {"type": "websocket.close", "code": 1008})
            self.assertEqual(len(inner_scopes), 1)

            same_session = scope("http", session_id)
            same_session["query_string"] = f"EIO=4&transport=polling&sid={engine_sid}".encode()
            await gate(same_session, asyncio.Future, send)
            self.assertEqual(len(inner_scopes), 2)
            self.assertTrue(any(
                b"private-frame" in message.get("body", b"")
                for message in sent
            ))

        asyncio.run(exercise())

    def test_socketio_polling_sid_binding_uses_real_engineio_handshake(self) -> None:
        if not all(importlib.util.find_spec(name) for name in ("socketio", "uvicorn")):
            self.skipTest("native Socket.IO runtime dependencies are not installed")

        import http.client
        import socketio
        import uvicorn

        from asgi import NativeSocketIO, SocketIOLiveSendASGI
        from telemetry_gateway import TelemetryPrincipal

        async def exercise() -> None:
            sessions = SessionStore(idle_seconds=60, absolute_seconds=300)
            original = sessions.create("original", "test-only-password", role="owner")
            replacement = sessions.create("replacement", "test-only-password", role="owner")
            engineio_requests = 0

            class Runtime:
                @staticmethod
                def role_check_lock_for_session(session_id: str):
                    return sessions.role_check_lock(session_id)

                @staticmethod
                def cached_principal_for_session(
                    session_id: str, *, role_check_lock_held: bool = False
                ):
                    current = sessions.get(
                        session_id,
                        touch=False,
                        role_check_lock_held=role_check_lock_held,
                        wait_for_role_check_lock=False,
                    )
                    principal = TelemetryPrincipal.from_session(current) if current else None
                    return True, principal

                @staticmethod
                def principal_for_session(
                    session_id: str, *, force_role_check: bool = False
                ):
                    current = sessions.get(session_id, touch=False)
                    return TelemetryPrincipal.from_session(current) if current else None

            runtime = Runtime()
            native = NativeSocketIO(runtime)
            adapter = DashboardHTTPASGI(SimpleNamespace(telemetry_runtime=runtime))
            engineio_application = socketio.ASGIApp(
                native.server, socketio_path="socket.io"
            )

            async def counted_engineio_app(scope, receive, send) -> None:
                nonlocal engineio_requests
                engineio_requests += 1
                await engineio_application(scope, receive, send)

            application = SocketIOLiveSendASGI(
                counted_engineio_app,
                adapter,
            )
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", 0))
            listener.listen(128)
            listener.setblocking(False)
            port = listener.getsockname()[1]
            server = uvicorn.Server(
                uvicorn.Config(application, log_level="critical", lifespan="off")
            )
            server_task = asyncio.create_task(server.serve(sockets=[listener]))

            def request(path: str, cookie_session_id: str) -> tuple[int, bytes]:
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                try:
                    connection.request(
                        "GET",
                        path,
                        headers={"Cookie": f"__Host-vpn_session={cookie_session_id}"},
                    )
                    response = connection.getresponse()
                    return response.status, response.read()
                finally:
                    connection.close()

            try:
                deadline = asyncio.get_running_loop().time() + 5
                while not server.started and not server_task.done():
                    if asyncio.get_running_loop().time() >= deadline:
                        self.fail("test ASGI server did not start")
                    await asyncio.sleep(0.01)
                self.assertTrue(server.started)

                status, handshake = await asyncio.to_thread(
                    request,
                    "/socket.io/?EIO=4&transport=polling&t=initial",
                    original.session_id,
                )
                self.assertEqual(status, 200)
                self.assertTrue(handshake.startswith(b"0{"), handshake)
                self.assertEqual(engineio_requests, 1)
                engine_sid = json.loads(handshake[1:].decode("utf-8"))["sid"]
                self.assertTrue(application._session_matches_engine_sid(
                    engine_sid, original.session_id
                ))

                # Engine.IO accepts slash-delimited path suffixes. The wrapper
                # must reject a different valid dashboard session before the
                # polling request reaches Engine.IO.
                status, response_body = await asyncio.to_thread(
                    request,
                    f"/socket.io/extra?EIO=4&transport=polling&sid={engine_sid}&t=reuse",
                    replacement.session_id,
                )
                self.assertEqual(status, 403)
                self.assertEqual(response_body, b"")
                self.assertEqual(engineio_requests, 1)
                self.assertTrue(application._session_matches_engine_sid(
                    engine_sid, original.session_id
                ))
            finally:
                server.should_exit = True
                await asyncio.wait_for(server_task, timeout=5)

        asyncio.run(exercise())

    def test_socketio_engine_sid_rejects_unknown_malformed_and_expired_ids(self) -> None:
        from asgi import SocketIOLiveSendASGI

        calls = 0

        async def inner(_scope, _receive, _send) -> None:
            nonlocal calls
            calls += 1

        gate = SocketIOLiveSendASGI(inner, object())
        self.assertTrue(gate._bind_engine_sid("expired-engine-sid", "session-a"))
        messages: list[dict[str, object]] = []

        async def send(message: dict[str, object]) -> None:
            messages.append(message)

        async def exercise() -> None:
            for query in (
                b"EIO=4&transport=polling&sid=unknown-engine-sid",
                b"EIO=4&transport=polling&sid=duplicate&sid=duplicate",
                b"EIO=4&transport=polling&sid=",
            ):
                await gate(
                    {
                        "type": "http",
                        "method": "GET",
                        "path": "/socket.io/",
                        "query_string": query,
                        "headers": [(b"cookie", b"__Host-vpn_session=session-a")],
                    },
                    asyncio.Future,
                    send,
                )
            with mock.patch("asgi.time.monotonic", return_value=time.monotonic() + 121):
                await gate(
                    {
                        "type": "http",
                        "method": "GET",
                        "path": "/socket.io/",
                        "query_string": b"EIO=4&transport=polling&sid=expired-engine-sid",
                        "headers": [(b"cookie", b"__Host-vpn_session=session-a")],
                    },
                    asyncio.Future,
                    send,
                )

        asyncio.run(exercise())
        self.assertEqual(calls, 0)
        self.assertEqual([message.get("status") for message in messages if message.get("type") == "http.response.start"], [403] * 4)
        self.assertNotIn("expired-engine-sid", gate._session_bindings)

    def test_http_adapter_bounds_non_get_live_route_responses(self) -> None:
        client, handler = socket.socketpair()
        handler.sendall(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
        handler.shutdown(socket.SHUT_WR)
        cancelled: list[bool] = []

        async def blocked_send(_message: dict[str, object]) -> None:
            try:
                await asyncio.Future()
            finally:
                cancelled.append(True)

        async def exercise() -> None:
            try:
                response = await asyncio.to_thread(
                    DashboardHTTPASGI._stream_response,
                    client,
                    blocked_send,
                    None,
                    True,
                )
                self.assertIsNotNone(response)
                with self.assertRaises(TimeoutError):
                    await response
                with self.assertRaises(TimeoutError):
                    await DashboardHTTPASGI._reject_oversized_body(
                        {
                            "type": "http",
                            "http_version": "1.1",
                            "method": "POST",
                            "path": "/api/events",
                        },
                        blocked_send,
                    )
            finally:
                client.close()
                handler.close()

        with mock.patch("asgi._ASGI_LIVE_BODY_SEND_TIMEOUT_SECONDS", 0.01):
            asyncio.run(exercise())
        self.assertEqual(cancelled, [True, True])

    def test_threaded_live_write_timeout_unblocks_session_revocation(self) -> None:
        from telemetry_gateway import TelemetryPrincipal

        sessions = SessionStore(idle_seconds=60, absolute_seconds=300)
        session = sessions.create("operator", "test-only-password", role="owner")

        class Runtime:
            @staticmethod
            def role_check_lock_for_session(session_id: str):
                return sessions.role_check_lock(session_id)

            @staticmethod
            def cached_principal_for_session(
                session_id: str, *, role_check_lock_held: bool = False
            ):
                current = sessions.get(
                    session_id,
                    touch=False,
                    role_check_lock_held=role_check_lock_held,
                    wait_for_role_check_lock=False,
                )
                return True, TelemetryPrincipal.from_session(current)

            @staticmethod
            def principal_for_session(
                session_id: str, *, force_role_check: bool = False
            ):
                return TelemetryPrincipal.from_session(
                    sessions.get(session_id, touch=False)
                )

        class FakeConnection:
            timeout: float | None = None

            def gettimeout(self) -> float | None:
                return self.timeout

            def settimeout(self, value: float | None) -> None:
                self.timeout = value

        connection = FakeConnection()
        write_started = threading.Event()

        class BlockingWriter:
            def write(self, _payload: bytes) -> int:
                write_started.set()
                if not threading.Event().wait(connection.gettimeout()):
                    raise TimeoutError("simulated stalled socket write")
                return 0

            @staticmethod
            def flush() -> None:
                return

        handler = object.__new__(DashboardHandler)
        handler.server = SimpleNamespace(telemetry_runtime=Runtime())
        handler.connection = connection
        handler.wfile = BlockingWriter()
        revocation_completed = threading.Event()
        outcomes: list[str] = []

        def blocked_write() -> None:
            handler.wfile.write(b"x" * 1024)
            handler.wfile.flush()

        def write_response() -> None:
            try:
                handler._write_authorized_live_payload(session.session_id, blocked_write)
                outcomes.append("sent")
            except TimeoutError:
                outcomes.append("timed_out")

        def revoke_session() -> None:
            sessions.revoke(session.session_id)
            revocation_completed.set()

        writer = threading.Thread(target=write_response, daemon=True)
        revoker: threading.Thread | None = None
        try:
            with mock.patch("app.LIVE_RESPONSE_WRITE_TIMEOUT_SECONDS", 0.05):
                writer.start()
                self.assertTrue(write_started.wait(timeout=1))
                revoker = threading.Thread(target=revoke_session, daemon=True)
                revoker.start()
                self.assertFalse(revocation_completed.wait(timeout=0.02))
                writer.join(timeout=2)
                self.assertFalse(writer.is_alive())
                self.assertTrue(revocation_completed.wait(timeout=1))
                revoker.join(timeout=1)
        finally:
            writer.join(timeout=1)
            if revoker is not None:
                revoker.join(timeout=1)

        self.assertEqual(outcomes, ["timed_out"])
        self.assertIsNone(connection.gettimeout())
        self.assertIsNotNone(revoker)
        if revoker is not None:
            self.assertFalse(revoker.is_alive())


if __name__ == "__main__":
    unittest.main()
