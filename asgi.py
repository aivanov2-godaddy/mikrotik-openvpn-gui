"""ASGI runtime with native WebSocket Socket.IO delivery.

The application routes remain owned by the existing, heavily tested
``DashboardHandler``.  ``DashboardHTTPASGI`` adapts those routes to ASGI while
the optional python-socketio server owns only ``/socket.io``.  This keeps the
mutation path and the REST/SSE fallback unchanged during the transport move.
"""

from __future__ import annotations

import asyncio
import ipaddress
import os
import socket
import threading
from http.cookies import SimpleCookie
from typing import Any, Awaitable, Callable, Mapping

from app import (
    MAX_REQUEST_BODY_BYTES,
    DashboardHandler,
    DashboardServer,
    RedirectHandler,
    build_context,
    drop_runtime_privileges,
)
from security import SECURITY_HEADERS


ASGIMessage = dict[str, Any]
Send = Callable[[ASGIMessage], Awaitable[None]]
Receive = Callable[[], Awaitable[ASGIMessage]]
_SOCKETIO_ROLE_CHECK_LIMIT = 4
_SOCKETIO_ROLE_CHECK_SLOTS = threading.BoundedSemaphore(_SOCKETIO_ROLE_CHECK_LIMIT)


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

    @staticmethod
    def _client_address(scope: Mapping[str, Any]) -> tuple[str, int]:
        """Return the validated network peer supplied by the ASGI server.

        The adapter uses a socket pair internally, so the HTTP handler cannot
        infer the original network peer from that socket. Preserve the ASGI
        peer explicitly; an absent or malformed peer fails closed and cannot
        make a forwarded header trusted.
        """
        client = scope.get("client")
        if not isinstance(client, (tuple, list)) or len(client) < 2:
            return "unknown", 0
        host, port = client[0], client[1]
        if (
            not isinstance(host, str)
            or isinstance(port, bool)
            or not isinstance(port, int)
            or not 0 <= port <= 65535
        ):
            return "unknown", 0
        try:
            peer = ipaddress.ip_address(host).compressed
        except ValueError:
            return "unknown", 0
        return peer, port

    @staticmethod
    def _uvicorn_proxy_options() -> dict[str, Any]:
        """Disable Uvicorn's independent X-Forwarded-For client rewriting."""
        return {"proxy_headers": False, "forwarded_allow_ips": ""}

    @staticmethod
    def _declared_body_exceeds_limit(scope: Mapping[str, Any]) -> bool:
        for key, value in scope.get("headers", []):
            if bytes(key).lower() != b"content-length":
                continue
            try:
                length = int(bytes(value).strip(), 10)
            except (TypeError, ValueError):
                continue
            if length > MAX_REQUEST_BODY_BYTES:
                return True
        return False

    @staticmethod
    async def _reject_oversized_body(scope: Mapping[str, Any], send: Send) -> None:
        headers = [
            (b"content-length", b"0"),
            (b"cache-control", b"no-store"),
            *(
                (key.lower().encode("latin-1"), value.encode("latin-1"))
                for key, value in SECURITY_HEADERS.items()
            ),
        ]
        if scope.get("http_version") in {"1.0", "1.1"}:
            # The ASGI server may otherwise keep reading a rejected, unread body
            # on a persistent HTTP/1 connection after we have sent the response.
            headers.append((b"connection", b"close"))
        await send({"type": "http.response.start", "status": 413, "headers": headers})
        await send({"type": "http.response.body", "body": b""})

    async def __call__(self, scope: Mapping[str, Any], receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await send({
                "type": "http.response.start",
                "status": 404,
                "headers": [(b"content-length", b"0")],
            })
            await send({"type": "http.response.body", "body": b""})
            return
        if self._declared_body_exceeds_limit(scope):
            await self._reject_oversized_body(scope, send)
            return
        body = bytearray()
        while True:
            message = await receive()
            if message.get("type") == "http.disconnect":
                return
            if message.get("type") != "http.request":
                continue
            chunk = message.get("body", b"")
            if len(body) + len(chunk) > MAX_REQUEST_BODY_BYTES:
                await self._reject_oversized_body(scope, send)
                return
            body.extend(chunk)
            if not message.get("more_body", False):
                break
        request = self._request_bytes(scope, bytes(body))
        client, handler_socket = socket.socketpair()
        thread = threading.Thread(
            target=DashboardHandler,
            args=(handler_socket, self._client_address(scope), self.server),
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
        self._health_heartbeats_total = 0
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
            "health_heartbeats_total": getattr(self, "_health_heartbeats_total", 0),
        }

    def _register_handlers(self) -> None:
        self.server.on("connect", self.connect, namespace=self.namespace)
        self.server.on("disconnect", self.disconnect, namespace=self.namespace)
        self.server.on("telemetry.subscribe", self.subscribe, namespace=self.namespace)

    async def _principal_for_session_async(
        self,
        session_id: str,
        *,
        force_role_check: bool = False,
        wait_for_capacity: bool = False,
    ) -> Any | None:
        """Revalidate an ASGI session without blocking the event loop.

        Fresh local role-cache hits need no worker slot. RouterOS role
        resolution is synchronous, so network checks are bounded per process.
        Established streams may wait asynchronously for a slot; new connects
        fail closed when capacity is unavailable. The slot is released when
        the worker actually finishes, even if its Socket.IO task is cancelled.
        """
        if not force_role_check:
            cached_lookup = getattr(self.runtime, "cached_principal_for_session", None)
            if callable(cached_lookup):
                try:
                    cache_is_authoritative, principal = cached_lookup(session_id)
                except Exception:  # noqa: BLE001 - cache failures fail closed
                    return None
                if cache_is_authoritative:
                    return principal

        loop = asyncio.get_running_loop()
        if wait_for_capacity:
            while not _SOCKETIO_ROLE_CHECK_SLOTS.acquire(blocking=False):
                await asyncio.sleep(0.025)
        elif not _SOCKETIO_ROLE_CHECK_SLOTS.acquire(blocking=False):
            return None

        def lookup_principal() -> Any | None:
            try:
                return self.runtime.principal_for_session(
                    session_id, force_role_check=force_role_check
                )
            except Exception:  # noqa: BLE001 - resolver failures fail closed
                return None
            finally:
                _SOCKETIO_ROLE_CHECK_SLOTS.release()

        try:
            lookup = loop.run_in_executor(None, lookup_principal)
        except Exception:
            _SOCKETIO_ROLE_CHECK_SLOTS.release()
            return None
        try:
            return await asyncio.shield(lookup)
        except asyncio.CancelledError:
            raise
        except Exception:
            return None

    async def connect(self, sid: str, environ: Mapping[str, Any], auth: Any = None) -> bool:
        # Engine.IO/Socket.IO may retry a namespace connect while the transport
        # is recovering. Keep one gateway subscription and pump per client SID.
        if sid in self._subscriptions:
            scope = environ.get("asgi.scope", {})
            session_id = _session_id(scope)
            bound_session_id = self._session_ids.get(sid, "")
            principal = await self._principal_for_session_async(
                bound_session_id,
                force_role_check=True,
                wait_for_capacity=True,
            )
            if (
                not bound_session_id
                or session_id != bound_session_id
                or principal is None
                or not principal.may_stream
            ):
                self._rejected_connections_total += 1
                await self.disconnect(sid)
                return False
            return True
        scope = environ.get("asgi.scope", {})
        principal = await self._principal_for_session_async(
            _session_id(scope), force_role_check=True
        )
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
        if not subscription or not session_id:
            return {"protocol_version": 1, "frames": []}
        principal = await self._principal_for_session_async(
            session_id, wait_for_capacity=True
        )
        if principal is None or not principal.may_stream:
            return {"protocol_version": 1, "frames": []}
        after = data.get("after_sequence") if isinstance(data, Mapping) else None
        frames = []
        for frame in self.runtime.gateway.poll(subscription, after_sequence=after):
            # A single poll can return a backlog. Serialize the final
            # authorization check with RouterOS role refresh through enqueue.
            emitted = await self._emit_authorized(
                sid, session_id, frame["event"], frame
            )
            if not emitted:
                await self.server.disconnect(sid, namespace=self.namespace)
                break
            frames.append(frame)
        return {"protocol_version": 1, "frames": frames}

    async def _emit_authorized(
        self,
        sid: str,
        session_id: str,
        event: str,
        payload: Mapping[str, Any],
    ) -> bool:
        """Hold the role-check lock across the final check and event enqueue."""
        lock_for_session = getattr(self.runtime, "role_check_lock_for_session", None)
        if not callable(lock_for_session):
            return False

        while True:
            role_lock = lock_for_session(session_id)
            if role_lock is None:
                return False
            while not role_lock.acquire(blocking=False):
                await asyncio.sleep(0.025)
            try:
                cache_lookup = getattr(
                    self.runtime, "cached_principal_for_session", None
                )
                if not callable(cache_lookup):
                    return False
                cache_is_authoritative, principal = cache_lookup(
                    session_id, role_check_lock_held=True
                )
                if cache_is_authoritative:
                    if principal is None or not principal.may_stream:
                        return False
                    await self._emit_and_drain(
                        event,
                        payload,
                        to=sid,
                        count_event=event != "telemetry.health",
                    )
                    return True
            except Exception:  # noqa: BLE001 - authorization failures fail closed
                return False
            finally:
                role_lock.release()

            # Release the role lock before a potentially blocking RouterOS
            # lookup, then loop and reacquire it before emitting any payload.
            principal = await self._principal_for_session_async(
                session_id, wait_for_capacity=True
            )
            if principal is None or not principal.may_stream:
                return False

    async def _emit_and_drain(
        self,
        event: str,
        payload: Mapping[str, Any],
        *,
        to: str,
        count_event: bool = True,
    ) -> None:
        """Keep the session gate until Socket.IO's child sends have drained.

        AsyncManager.emit can leave child send tasks running when its waiter is
        cancelled. Shield the manager call and, on cancellation, retain the
        per-session gate until that call finishes so invalidation cannot report
        completion while an earlier enqueue is still in progress.
        """
        emission = asyncio.create_task(
            self._emit(event, payload, to=to, count_event=count_event)
        )
        try:
            await asyncio.shield(emission)
        except asyncio.CancelledError:
            while not emission.done():
                try:
                    await asyncio.shield(emission)
                except asyncio.CancelledError:
                    continue
                except Exception:  # noqa: BLE001 - consume failed child send before releasing gate
                    break
            try:
                emission.result()
            except (Exception, asyncio.CancelledError):
                pass
            raise

    async def _emit(
        self,
        event: str,
        payload: Mapping[str, Any],
        *,
        to: str,
        count_event: bool = True,
    ) -> None:
        await self.server.emit(event, payload, to=to, namespace=self.namespace)
        if count_event:
            self._events_emitted_total += 1

    def _health_payload(self) -> dict[str, Any]:
        """Return only the upstream stream state needed for a live indicator."""

        supervisor = getattr(self.runtime, "supervisor", None)
        if supervisor is None:
            return {"state": "degraded", "stream_connected": False}
        try:
            status = str(supervisor.health().status)
        except Exception:  # noqa: BLE001 - health reporting must fail closed
            status = "degraded"
        if status == "healthy":
            return {"state": "healthy", "stream_connected": True}
        if status in {"connecting", "stopped"}:
            return {"state": "connecting", "stream_connected": False}
        return {"state": "degraded", "stream_connected": False}

    async def _pump(self, sid: str, subscription: str) -> None:
        next_health_heartbeat = 0.0
        try:
            while sid in self._subscriptions:
                session_id = self._session_ids.get(sid, "")
                principal = await self._principal_for_session_async(
                    session_id, wait_for_capacity=True
                )
                if principal is None or not principal.may_stream:
                    await self.server.disconnect(sid, namespace=self.namespace)
                    return
                for frame in self.runtime.gateway.poll(subscription):
                    # Do not let an already-polled backlog outlive its session
                    # or streaming capability if authorization changes mid-batch.
                    emitted = await self._emit_authorized(
                        sid, session_id, frame["event"], frame
                    )
                    if not emitted:
                        await self.server.disconnect(sid, namespace=self.namespace)
                        return
                now = asyncio.get_running_loop().time()
                if now >= next_health_heartbeat:
                    # A quiet RouterOS listen stream can be healthy even when
                    # no session event has changed recently. Send a small,
                    # redacted health heartbeat so the UI distinguishes that
                    # from a disconnected or degraded upstream stream.
                    emitted = await self._emit_authorized(
                        sid,
                        session_id,
                        "telemetry.health",
                        self._health_payload(),
                    )
                    if not emitted:
                        await self.server.disconnect(sid, namespace=self.namespace)
                        return
                    self._health_heartbeats_total = getattr(self, "_health_heartbeats_total", 0) + 1
                    next_health_heartbeat = now + 5.0
                await asyncio.sleep(0.25)
        except (asyncio.CancelledError, RuntimeError):
            return


class TrustedProxySchemeASGI:
    """Honor the forwarded scheme only from explicitly trusted proxy peers.

    Uvicorn's proxy middleware rewrites ``scope["client"]`` from X-Forwarded-For
    regardless of the application's configured client-address header. Keep the
    original peer intact so ``DashboardHandler`` can apply that configured
    header itself; this wrapper only adapts the external scheme used by
    same-origin checks.
    """

    def __init__(self, app: Any, trusted_proxy_sources: tuple[str, ...]) -> None:
        self.app = app
        self.trusted_proxy_sources = frozenset(trusted_proxy_sources)

    async def __call__(self, scope: Mapping[str, Any], receive: Receive, send: Send) -> None:
        scope_type = scope.get("type")
        if scope_type not in {"http", "websocket"}:
            await self.app(scope, receive, send)
            return

        peer, _ = DashboardHTTPASGI._client_address(scope)
        proto_values = [
            bytes(value).decode("latin-1").strip().casefold()
            for name, value in scope.get("headers", [])
            if bytes(name).lower() == b"x-forwarded-proto"
        ]
        if peer not in self.trusted_proxy_sources or len(proto_values) != 1:
            await self.app(scope, receive, send)
            return

        proto = proto_values[0]
        if scope_type == "http" and proto in {"http", "https"}:
            scheme = proto
        elif scope_type == "websocket" and proto in {"http", "ws"}:
            scheme = "ws"
        elif scope_type == "websocket" and proto in {"https", "wss"}:
            scheme = "wss"
        else:
            await self.app(scope, receive, send)
            return

        forwarded_scope = dict(scope)
        forwarded_scope["scheme"] = scheme
        await self.app(forwarded_scope, receive, send)


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
    application = TrustedProxySchemeASGI(
        application,
        context.config.trusted_proxy_sources,
    )
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
            **DashboardHTTPASGI._uvicorn_proxy_options(),
        )
    finally:
        redirect_server.shutdown()
        server.close()


if __name__ == "__main__":
    main()
