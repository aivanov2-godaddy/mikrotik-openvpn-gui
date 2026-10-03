"""ASGI runtime with native WebSocket Socket.IO delivery.

The application routes remain owned by the existing, heavily tested
``DashboardHandler``.  ``DashboardHTTPASGI`` adapts those routes to ASGI while
the optional python-socketio server owns only ``/socket.io``.  This keeps the
mutation path and the REST/SSE fallback unchanged during the transport move.
"""

from __future__ import annotations

import asyncio
import os
import socket
import threading
from http.cookies import SimpleCookie
from typing import Any, Awaitable, Callable, Mapping

from app import DashboardHandler, DashboardServer, RedirectHandler, build_context, drop_runtime_privileges


ASGIMessage = dict[str, Any]
Send = Callable[[ASGIMessage], Awaitable[None]]
Receive = Callable[[], Awaitable[ASGIMessage]]


def _header_map(scope: Mapping[str, Any]) -> dict[str, str]:
    return {
        bytes(key).decode("latin-1").lower(): bytes(value).decode("latin-1")
        for key, value in scope.get("headers", [])
    }


def _session_id(scope: Mapping[str, Any]) -> str:
    cookies = SimpleCookie()
    cookies.load(_header_map(scope).get("cookie", ""))
    morsel = cookies.get("vpn_session")
    return morsel.value if morsel else ""


class DashboardHTTPASGI:
    """Run the existing request handler behind an ASGI HTTP boundary."""

    def __init__(self, server: DashboardServer) -> None:
        self.server = server

    async def __call__(self, scope: Mapping[str, Any], receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await send({
                "type": "http.response.start",
                "status": 404,
                "headers": [(b"content-length", b"0")],
            })
            await send({"type": "http.response.body", "body": b""})
            return
        body = bytearray()
        while True:
            message = await receive()
            if message.get("type") == "http.disconnect":
                return
            if message.get("type") != "http.request":
                continue
            body.extend(message.get("body", b""))
            if not message.get("more_body", False):
                break
        request = self._request_bytes(scope, bytes(body))
        client, handler_socket = socket.socketpair()
        thread = threading.Thread(
            target=DashboardHandler,
            args=(handler_socket, ("asgi", 0), self.server),
            daemon=True,
        )
        thread.start()
        disconnect_task = asyncio.create_task(self._close_on_disconnect(receive, client))
        try:
            client.sendall(request)
            client.shutdown(socket.SHUT_WR)
            response = await asyncio.to_thread(self._stream_response, client, send)
            if response is not None:
                await response
        finally:
            disconnect_task.cancel()
            client.close()
            thread.join(timeout=2)

    @staticmethod
    def _request_bytes(scope: Mapping[str, Any], body: bytes) -> bytes:
        method = str(scope.get("method", "GET"))
        raw_path = bytes(scope.get("raw_path", b"/"))
        query = bytes(scope.get("query_string", b""))
        target = raw_path + (b"?" + query if query else b"")
        headers = []
        for key, value in scope.get("headers", []):
            name = bytes(key).decode("latin-1")
            if name.casefold() in {"connection", "content-length", "transfer-encoding"}:
                continue
            headers.append(f"{name}: {bytes(value).decode('latin-1')}\r\n".encode("latin-1"))
        headers.append(f"Content-Length: {len(body)}\r\n".encode("ascii"))
        return method.encode("ascii") + b" " + target + b" HTTP/1.1\r\n" + b"".join(headers) + b"Connection: close\r\n\r\n" + body

    @staticmethod
    def _stream_response(client: socket.socket, send: Send) -> Awaitable[None] | None:
        # This method only performs blocking reads; the returned coroutine
        # sends the parsed response on the event loop.
        buffer = bytearray()
        while b"\r\n\r\n" not in buffer:
            try:
                chunk = client.recv(65536)
            except (OSError, ValueError):
                # The disconnect watcher closes the socket when the browser
                # goes away.  Treat that race as an ordinary end-of-stream;
                # it must not become an ASGI application exception.
                return None
            if not chunk:
                return None
            buffer.extend(chunk)
        raw_headers, body = bytes(buffer).split(b"\r\n\r\n", 1)
        lines = raw_headers.split(b"\r\n")
        status = int(lines[0].split(b" ", 2)[1])
        headers: list[tuple[bytes, bytes]] = []
        for line in lines[1:]:
            if b":" not in line:
                continue
            name, value = line.split(b":", 1)
            headers.append((name.strip().lower(), value.strip()))

        content_length: int | None = None
        for name, value in headers:
            if name == b"content-length":
                try:
                    content_length = int(value)
                except ValueError:
                    content_length = None
                break

        # DashboardHandler uses HTTP/1.1 and normally leaves the socket open
        # after writing a Content-Length-delimited response.  Reading until
        # EOF here therefore makes every ordinary ASGI request hang forever:
        # the wrapped handler is invoked directly, so socketserver never gets
        # a chance to close the request socket.  Read exactly the declared
        # response body instead.  Streaming responses without Content-Length
        # (for example SSE) retain the EOF/disconnect behavior below.
        if content_length is not None:
            body = bytearray(body)
            while len(body) < content_length:
                try:
                    chunk = client.recv(min(65536, content_length - len(body)))
                except (OSError, ValueError):
                    return None
                if not chunk:
                    break
                body.extend(chunk)
            body = bytes(body[:content_length])

        async def send_response() -> None:
            await send({"type": "http.response.start", "status": status, "headers": headers})
            if body:
                await send({"type": "http.response.body", "body": body, "more_body": True})
            if content_length is not None:
                await send({"type": "http.response.body", "body": b""})
                return
            while True:
                try:
                    chunk = await asyncio.to_thread(client.recv, 65536)
                except (OSError, ValueError):
                    # A concurrent http.disconnect may close the socket
                    # while this read is in flight.
                    return
                if not chunk:
                    break
                await send({"type": "http.response.body", "body": chunk, "more_body": True})
            await send({"type": "http.response.body", "body": b""})

        return send_response()

    @staticmethod
    async def _close_on_disconnect(receive: Receive, client: socket.socket) -> None:
        try:
            while True:
                message = await receive()
                if message.get("type") == "http.disconnect":
                    client.close()
                    return
        except asyncio.CancelledError:
            return


class NativeSocketIO:
    """Attach the authenticated gateway to python-socketio's ASGI server."""

    namespace = "/telemetry"

    def __init__(self, runtime: Any) -> None:
        import socketio

        self.runtime = runtime
        self.server = socketio.AsyncServer(
            async_mode="asgi",
            # None preserves Engine.IO's default same-origin validation.
            # An empty list disables its CORS/origin handling entirely.
            cors_allowed_origins=None,
            transports=["websocket", "polling"],
            ping_interval=25,
            ping_timeout=20,
            max_http_buffer_size=1_000_000,
        )
        self._subscriptions: dict[str, str] = {}
        self._session_ids: dict[str, str] = {}
        self._tasks: dict[str, asyncio.Task[None]] = {}
        self._connections_total = 0
        self._disconnects_total = 0
        self._rejected_connections_total = 0
        self._events_emitted_total = 0
        self._register_handlers()

    def metrics(self) -> dict[str, int | str]:
        """Return secret-free ASGI Socket.IO connection metrics."""

        return {
            "engine": "asgi",
            "active_connections": len(self._subscriptions),
            "connections_total": self._connections_total,
            "disconnects_total": self._disconnects_total,
            "rejected_connections_total": self._rejected_connections_total,
            "events_emitted_total": self._events_emitted_total,
        }

    def _register_handlers(self) -> None:
        self.server.on("connect", self.connect, namespace=self.namespace)
        self.server.on("disconnect", self.disconnect, namespace=self.namespace)
        self.server.on("telemetry.subscribe", self.subscribe, namespace=self.namespace)

    async def connect(self, sid: str, environ: Mapping[str, Any], auth: Any = None) -> bool:
        # Engine.IO/Socket.IO may retry a namespace connect while the transport
        # is recovering. Keep one gateway subscription and pump per client SID.
        if sid in self._subscriptions:
            return True
        scope = environ.get("asgi.scope", {})
        principal = self.runtime.principal_for_session(_session_id(scope))
        if principal is None or not principal.may_stream:
            self._rejected_connections_total += 1
            return False
        try:
            subscription = self.runtime.gateway.open(principal)
        except Exception:  # noqa: BLE001 - refuse a subscription safely
            self._rejected_connections_total += 1
            return False
        self._subscriptions[sid] = subscription
        self._session_ids[sid] = _session_id(scope)
        self._tasks[sid] = asyncio.create_task(self._pump(sid, subscription))
        self._connections_total += 1
        return True

    async def disconnect(self, sid: str) -> None:
        was_connected = sid in self._subscriptions
        task = self._tasks.pop(sid, None)
        if task:
            task.cancel()
        subscription = self._subscriptions.pop(sid, None)
        self._session_ids.pop(sid, None)
        if subscription:
            self.runtime.gateway.close(subscription)
        if was_connected:
            self._disconnects_total += 1

    async def subscribe(self, sid: str, data: Any = None) -> dict[str, Any]:
        subscription = self._subscriptions.get(sid)
        session_id = self._session_ids.get(sid)
        principal = self.runtime.principal_for_session(session_id or "")
        if not subscription or principal is None or not principal.may_stream:
            return {"protocol_version": 1, "frames": []}
        after = data.get("after_sequence") if isinstance(data, Mapping) else None
        frames = self.runtime.gateway.poll(subscription, after_sequence=after)
        for frame in frames:
            await self._emit(frame["event"], frame, to=sid)
        return {"protocol_version": 1, "frames": frames}

    async def _emit(self, event: str, payload: Mapping[str, Any], *, to: str) -> None:
        await self.server.emit(event, payload, to=to, namespace=self.namespace)
        self._events_emitted_total += 1

    async def _pump(self, sid: str, subscription: str) -> None:
        try:
            while sid in self._subscriptions:
                session_id = self._session_ids.get(sid, "")
                principal = self.runtime.principal_for_session(session_id)
                if principal is None or not principal.may_stream:
                    await self.server.disconnect(sid, namespace=self.namespace)
                    return
                for frame in self.runtime.gateway.poll(subscription):
                    await self._emit(frame["event"], frame, to=sid)
                await asyncio.sleep(0.25)
        except (asyncio.CancelledError, RuntimeError):
            return


def create_application() -> tuple[Any, DashboardServer, Any]:
    try:
        import socketio
        import uvicorn  # noqa: F401 - validates the optional runtime at startup
    except ImportError as error:
        raise RuntimeError("ASGI runtime dependencies are not installed") from error
    context = build_context()
    drop_runtime_privileges(context.store.path)
    server = DashboardServer(("127.0.0.1", 0), context)
    RedirectHandler.public_origin = context.public_origin
    redirect_server = __import__("http.server", fromlist=["ThreadingHTTPServer"]).ThreadingHTTPServer(
        (os.environ.get("LISTEN_ADDRESS", "0.0.0.0"), int(os.environ.get("REDIRECT_PORT", "8081"))),
        RedirectHandler,
    )
    threading.Thread(target=redirect_server.serve_forever, daemon=True).start()
    socketio_server = NativeSocketIO(server.telemetry_runtime)
    server.native_socketio = socketio_server
    http_app = DashboardHTTPASGI(server)
    application = socketio.ASGIApp(socketio_server.server, other_asgi_app=http_app, socketio_path="socket.io")
    return application, server, redirect_server


def main() -> None:
    import uvicorn

    application, server, redirect_server = create_application()
    try:
        uvicorn.run(
            application,
            host=os.environ.get("LISTEN_ADDRESS", "0.0.0.0"),
            port=int(os.environ.get("APP_PORT", "8080")),
            log_level="info",
        )
    finally:
        redirect_server.shutdown()
        server.close()


if __name__ == "__main__":
    main()
