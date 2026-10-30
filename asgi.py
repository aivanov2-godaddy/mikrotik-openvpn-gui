"""ASGI runtime with native WebSocket Socket.IO delivery.

The application routes remain owned by the existing, heavily tested
``DashboardHandler``.  ``DashboardHTTPASGI`` adapts those routes to ASGI while
the optional python-socketio server owns only ``/socket.io``.  This keeps the
mutation path and the REST/SSE fallback unchanged during the transport move.
"""

from __future__ import annotations

import asyncio
import contextvars
import hmac
import ipaddress
import json
import math
import os
import socket
import threading
import time
import urllib.parse
from collections import OrderedDict
from http.cookies import SimpleCookie
from typing import Any, Awaitable, Callable, Mapping

from app import (
    MAX_REQUEST_BODY_BYTES,
    DashboardHandler,
    DashboardServer,
    RedirectHandler,
    _same_origin,
    build_context,
    drop_runtime_privileges,
)
from security import SECURITY_HEADERS, disable_process_core_dumps


ASGIMessage = dict[str, Any]
Send = Callable[[ASGIMessage], Awaitable[None]]
Receive = Callable[[], Awaitable[ASGIMessage]]
_SOCKETIO_ROLE_CHECK_LIMIT = 4
_SOCKETIO_ROLE_CHECK_SLOTS = threading.BoundedSemaphore(_SOCKETIO_ROLE_CHECK_LIMIT)
_ASGI_LIVE_BODY_SEND_TIMEOUT_SECONDS = 10.0
_ASGI_AUTHORIZATION_WAIT_TIMEOUT_DEFAULT_SECONDS = 0.5
_ASGI_AUTHORIZATION_WAIT_TIMEOUT_MAX_SECONDS = 5.0
_ASGI_AUTHORIZATION_WAIT_TIMEOUT_ENV = "ASGI_AUTHORIZATION_WAIT_TIMEOUT_SECONDS"
_SOCKETIO_SESSION_BINDING_TTL_SECONDS = 120.0
# Bound Engine.IO allocations to 128 per process and 8 per authenticated
# dashboard session. Pending reservations remain counted until the handshake
# task exits, including cancellation-resistant cleanup after a timeout.
_SOCKETIO_MAX_SESSION_BINDINGS = 128
_SOCKETIO_MAX_ENGINEIO_CONNECTIONS = 128
_SOCKETIO_MAX_ENGINEIO_CONNECTIONS_PER_SESSION = 8
_SOCKETIO_ENGINEIO_HANDSHAKE_TIMEOUT_SECONDS = 15.0
_SOCKETIO_ENGINEIO_CANCEL_GRACE_SECONDS = 0.1
_SOCKETIO_MAX_HANDSHAKE_BUFFER_BYTES = 1_000_000
_SOCKETIO_MAX_PENDING_HANDSHAKE_BUFFER_BYTES = 4_000_000
_ASGI_AUTHORIZATION_WAIT_POLL_SECONDS = 0.025


class _EngineIOHandshakeBufferLimit(Exception):
    """Raised when pending Engine.IO handshake buffering reaches its limit."""


def _same_origin_referer(headers: Any, public_origin: Any) -> bool:
    """Require one valid same-origin Referer when a polling GET omits Origin."""
    referers = [
        bytes(value).decode("latin-1")
        for key, value in headers
        if bytes(key).lower() == b"referer"
    ]
    if len(referers) != 1:
        return False
    try:
        parsed = urllib.parse.urlsplit(referers[0])
        if (
            parsed.scheme.casefold() not in {"http", "https"}
            or not parsed.netloc
            or parsed.username is not None
            or parsed.password is not None
        ):
            return False
        # Accessing port validates malformed port syntax before comparison.
        _ = parsed.port
    except ValueError:
        return False
    return isinstance(public_origin, str) and _same_origin(
        f"{parsed.scheme}://{parsed.netloc}", public_origin
    )


def _configured_authorization_wait_timeout() -> float:
    """Return a finite, short authorization acquisition timeout.

    Invalid, non-finite, or non-positive settings use the safe default; larger
    finite settings are capped so configuration cannot turn the wait unbounded
    in practice.
    """
    try:
        configured = float(os.environ[_ASGI_AUTHORIZATION_WAIT_TIMEOUT_ENV])
    except (KeyError, TypeError, ValueError):
        return _ASGI_AUTHORIZATION_WAIT_TIMEOUT_DEFAULT_SECONDS
    if not math.isfinite(configured) or configured <= 0:
        return _ASGI_AUTHORIZATION_WAIT_TIMEOUT_DEFAULT_SECONDS
    return min(configured, _ASGI_AUTHORIZATION_WAIT_TIMEOUT_MAX_SECONDS)


_ASGI_AUTHORIZATION_WAIT_TIMEOUT_SECONDS = _configured_authorization_wait_timeout()


async def _acquire_before_deadline(lock: Any, deadline: float) -> bool:
    """Try a thread lock/semaphore asynchronously until the finite deadline."""
    loop = asyncio.get_running_loop()
    while True:
        remaining = deadline - loop.time()
        if remaining <= 0:
            return False
        if lock.acquire(blocking=False):
            return True
        await asyncio.sleep(min(_ASGI_AUTHORIZATION_WAIT_POLL_SECONDS, remaining))


def _session_id(scope: Mapping[str, Any]) -> str:
    # Match BaseHTTPRequestHandler.headers.get("Cookie"), which selects the
    # first Cookie field forwarded by _request_bytes. ASGI may preserve
    # duplicate fields; taking the last here could gate a different session
    # from the one that actually serves the request.
    cookie_header = ""
    for key, value in scope.get("headers", []):
        if bytes(key).lower() == b"cookie":
            cookie_header = bytes(value).decode("latin-1")
            break
    cookies = SimpleCookie()
    try:
        cookies.load(cookie_header)
    except Exception:  # noqa: BLE001 - malformed cookies are unauthenticated
        return ""
    morsel = cookies.get("__Host-vpn_session")
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
        messages = (
            {"type": "http.response.start", "status": 413, "headers": headers},
            {"type": "http.response.body", "body": b""},
        )
        if DashboardHTTPASGI._requires_live_send_timeout(scope):
            for message in messages:
                await DashboardHTTPASGI._send_and_drain(send, message)
        else:
            for message in messages:
                await send(message)

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
        protect_live_response = self._requires_live_body_gate(scope)
        bound_live_response_sends = self._requires_live_send_timeout(scope)
        session_id = _session_id(scope) if protect_live_response else ""

        async def send_authorized_live_body(message: ASGIMessage) -> bool:
            return await self._send_authorized_live_message(session_id, message, send)

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
            response = await asyncio.to_thread(
                self._stream_response,
                client,
                send,
                send_authorized_live_body if protect_live_response else None,
                bound_live_response_sends,
            )
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
    def _requires_live_body_gate(scope: Mapping[str, Any]) -> bool:
        """Protect HTTP bodies that can carry live telemetry to a client."""
        return (
            str(scope.get("method", "")).upper() == "GET"
            and str(scope.get("path", "")) == "/api/events"
        )

    @staticmethod
    def _requires_live_send_timeout(scope: Mapping[str, Any]) -> bool:
        """Bound sends for every response on the long-lived live route."""
        return str(scope.get("path", "")) == "/api/events"

    @staticmethod
    def _stream_response(
        client: socket.socket,
        send: Send,
        protected_body_send: Callable[[ASGIMessage], Awaitable[bool]] | None = None,
        bound_response_sends: bool = False,
    ) -> Awaitable[None] | None:
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
            response_start = {
                "type": "http.response.start",
                "status": status,
                "headers": headers,
            }
            if bound_response_sends or protected_body_send is not None:
                await DashboardHTTPASGI._send_and_drain(send, response_start)
            else:
                await send(response_start)

            async def send_body(message: ASGIMessage) -> bool:
                payload = message.get("body", b"")
                if status == 200 and payload and protected_body_send is not None:
                    if not await protected_body_send(message):
                        # Stop the handler's socket-pair writer and finish this
                        # response without forwarding the now-unauthorized body.
                        client.close()
                        await send_terminal_body()
                        return False
                    # The authorizer owns the real awaited send while holding
                    # the shared session lock; do not send the same body again.
                    return True
                if bound_response_sends or protected_body_send is not None:
                    await DashboardHTTPASGI._send_and_drain(send, message)
                else:
                    await send(message)
                return True

            async def send_terminal_body() -> None:
                message = {"type": "http.response.body", "body": b""}
                if bound_response_sends or protected_body_send is not None:
                    await DashboardHTTPASGI._send_and_drain(send, message)
                else:
                    await send(message)

            if body:
                if not await send_body(
                    {"type": "http.response.body", "body": body, "more_body": True}
                ):
                    return
            if content_length is not None:
                await send_terminal_body()
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
                if not await send_body(
                    {"type": "http.response.body", "body": chunk, "more_body": True}
                ):
                    return
            await send_terminal_body()

        return send_response()

    async def _send_authorized_live_message(
        self,
        session_id: str,
        message: ASGIMessage,
        send: Send,
    ) -> bool:
        """Serialize live HTTP delivery with session invalidation at ASGI send.

        The wrapped HTTP handler writes to an internal socket pair, and the
        Socket.IO manager can queue transport output before the external send.
        Their authorization locks therefore end before the ASGI ``send`` call.
        Hold the same per-session lock through that actual awaited send so
        logout, expiry, and revocation cannot complete in the check-to-send gap.
        """
        runtime = getattr(self.server, "telemetry_runtime", None)
        lock_resolver = getattr(runtime, "role_check_lock_for_session", None)
        principal_resolver = getattr(runtime, "cached_principal_for_session", None)
        refresh_resolver = getattr(runtime, "principal_for_session", None)
        if (
            not session_id
            or not callable(lock_resolver)
            or not callable(principal_resolver)
            or not callable(refresh_resolver)
        ):
            return False

        loop = asyncio.get_running_loop()
        deadline = loop.time() + _ASGI_AUTHORIZATION_WAIT_TIMEOUT_SECONDS
        while loop.time() < deadline:
            role_lock = lock_resolver(session_id)
            if role_lock is None:
                return False
            if not await _acquire_before_deadline(role_lock, deadline):
                return False

            cache_is_authoritative = False
            try:
                try:
                    cache_is_authoritative, principal = principal_resolver(
                        session_id,
                        role_check_lock_held=True,
                    )
                except asyncio.CancelledError:
                    raise
                except Exception:  # noqa: BLE001 - authorization fails closed
                    return False
                if cache_is_authoritative:
                    if principal is None or not principal.may_stream:
                        return False
                    await self._send_and_drain(send, message)
                    return True
            finally:
                role_lock.release()

            # Role data is stale. Refresh outside the delivery lock, with the
            # same bounded worker capacity used by the native Socket.IO path,
            # then loop and recheck under the lock before sending.
            if not await _acquire_before_deadline(
                _SOCKETIO_ROLE_CHECK_SLOTS, deadline
            ):
                return False

            def refresh_principal() -> Any | None:
                try:
                    return refresh_resolver(session_id, force_role_check=True)
                finally:
                    _SOCKETIO_ROLE_CHECK_SLOTS.release()

            try:
                refresh = loop.run_in_executor(None, refresh_principal)
            except Exception:  # noqa: BLE001 - release capacity if scheduling fails
                _SOCKETIO_ROLE_CHECK_SLOTS.release()
                return False
            try:
                principal = await asyncio.shield(refresh)
            except asyncio.CancelledError:
                while not refresh.done():
                    try:
                        await asyncio.shield(refresh)
                    except asyncio.CancelledError:
                        continue
                    except Exception:  # noqa: BLE001 - worker owns slot release
                        break
                try:
                    refresh.result()
                except (Exception, asyncio.CancelledError):
                    pass
                raise
            except Exception:  # noqa: BLE001 - authorization fails closed
                return False
            if principal is None or not principal.may_stream:
                return False

        return False

    @staticmethod
    async def _send_and_drain(send: Send, message: ASGIMessage) -> None:
        """Request cancellation on timeout, retaining the role lock until send exits.

        This is a cooperative timeout: ASGI has no portable transport-abort
        primitive, so a send callable that suppresses cancellation can delay
        session revocation until that callable returns.
        """
        sending = asyncio.ensure_future(send(message))
        try:
            await asyncio.wait_for(
                asyncio.shield(sending),
                timeout=_ASGI_LIVE_BODY_SEND_TIMEOUT_SECONDS,
            )
        except asyncio.TimeoutError:
            sending.cancel()
            await DashboardHTTPASGI._drain_send(sending)
            raise TimeoutError("ASGI live-response send timed out") from None
        except asyncio.CancelledError:
            await DashboardHTTPASGI._drain_send(sending)
            raise

    @staticmethod
    async def _drain_send(sending: asyncio.Future[Any]) -> None:
        """Wait for the child send to exit before releasing its authorization lock."""
        while not sending.done():
            try:
                await asyncio.shield(sending)
            except asyncio.CancelledError:
                continue
            except Exception:  # noqa: BLE001 - drain failures before unlock
                break
        try:
            sending.result()
        except (Exception, asyncio.CancelledError):
            pass

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


class SocketIOLiveSendASGI:
    """Revalidate native Socket.IO payloads at the external ASGI send edge."""

    def __init__(self, app: Any, http_adapter: DashboardHTTPASGI) -> None:
        self.app = app
        self.http_adapter = http_adapter
        self._session_bindings: OrderedDict[str, tuple[str, float]] = OrderedDict()
        self._active_websocket_sids: set[str] = set()
        self._pending_websocket_upgrades: dict[str, int] = {}
        self._pending_engine_handshakes: dict[object, str] = {}
        self._engineio_disconnect_tasks: dict[str, asyncio.Task[None]] = {}
        self._engineio_teardown_completed: dict[str, str] = {}
        self._pending_handshake_buffer_bytes = 0
        self._session_bindings_lock = threading.Lock()
        self._engineio_sid_context: contextvars.ContextVar[
            Callable[[str], None] | None
        ] = contextvars.ContextVar(f"engineio_sid_capture_{id(self)}", default=None)
        self._install_engineio_sid_capture()

    def _install_engineio_sid_capture(self) -> None:
        socketio_server = getattr(self.app, "engineio_server", None)
        engineio_server = getattr(socketio_server, "eio", None)
        handlers = getattr(engineio_server, "handlers", None)
        on = getattr(engineio_server, "on", None)
        original_connect = handlers.get("connect") if isinstance(handlers, dict) else None
        if not callable(original_connect) or not callable(on):
            return

        async def capture_engineio_connect(sid: str, environ: Mapping[str, Any]) -> Any:
            capture = self._engineio_sid_context.get()
            if callable(capture):
                capture(sid)
            result = original_connect(sid, environ)
            if hasattr(result, "__await__"):
                return await result
            return result

        # Engine.IO's public connect event runs after its SID enters the server
        # socket table but before the open packet is returned to the client.
        # Preserve python-socketio's handler while recording that SID locally.
        on("connect", capture_engineio_connect)

    @staticmethod
    def _socketio_path(path: str) -> bool:
        return path == "/socket.io" or path.startswith("/socket.io/")

    @staticmethod
    def _engine_sid_from_scope(
        scope: Mapping[str, Any],
    ) -> tuple[bool, str | None, bool]:
        query = bytes(scope.get("query_string", b""))
        if len(query) > 8192:
            return False, None, False
        try:
            parameters = urllib.parse.parse_qs(
                query.decode("latin-1"),
                keep_blank_values=True,
                max_num_fields=64,
            )
        except (UnicodeError, ValueError):
            return False, None, False
        # Engine.IO consumes the first value and defaults a missing transport
        # to polling. Reject ambiguous protocol keys on every request and
        # implicit transports on new handshakes before dispatch, so Engine.IO
        # cannot allocate an unreserved SID.
        if any(len(parameters.get(name, [])) > 1 for name in ("EIO", "transport")):
            return False, None, False
        protocol_versions = parameters.get("EIO", [])
        transports = parameters.get("transport", [])
        values = parameters.get("sid", [])
        if (
            not values
            and protocol_versions == ["4"]
            and transports not in (["polling"], ["websocket"])
        ):
            return False, None, False
        if not values:
            return False, None, True
        if len(values) != 1 or not values[0] or len(values[0]) > 256:
            return True, None, False
        return True, values[0], True

    def _prune_session_bindings(self, now: float) -> None:
        cutoff = now - _SOCKETIO_SESSION_BINDING_TTL_SECONDS
        for sid, (_session_id, last_seen) in tuple(self._session_bindings.items()):
            if (
                last_seen <= cutoff
                and sid not in self._active_websocket_sids
                and sid not in self._pending_websocket_upgrades
                and sid not in self._engineio_disconnect_tasks
            ):
                self._session_bindings.pop(sid, None)

    @staticmethod
    def _same_dashboard_session(first: str, second: str) -> bool:
        return hmac.compare_digest(first.encode("utf-8"), second.encode("utf-8"))

    @staticmethod
    def _is_new_engineio_handshake(
        scope: Mapping[str, Any], *, has_sid: bool, valid_query: bool
    ) -> bool:
        scope_type = scope.get("type")
        method = (
            "GET"
            if scope_type == "websocket"
            else str(scope.get("method", "")).upper()
        )
        if (
            has_sid
            or not valid_query
            or method != "GET"
            or scope_type not in {"http", "websocket"}
        ):
            return False
        query = bytes(scope.get("query_string", b""))
        if len(query) > 8192:
            return False
        try:
            parameters = urllib.parse.parse_qs(
                query.decode("latin-1"),
                keep_blank_values=True,
                max_num_fields=64,
            )
        except (UnicodeError, ValueError):
            return False
        return (
            parameters.get("EIO") == ["4"]
            and parameters.get("transport") in (["polling"], ["websocket"])
        )

    def _session_binding_count(self, session_id: str) -> int:
        return sum(
            1
            for bound_session_id, _last_seen in self._session_bindings.values()
            if self._same_dashboard_session(bound_session_id, session_id)
        )

    def _pending_handshake_count(self, session_id: str | None = None) -> int:
        if session_id is None:
            return len(self._pending_engine_handshakes)
        return sum(
            1
            for pending_session_id in self._pending_engine_handshakes.values()
            if self._same_dashboard_session(pending_session_id, session_id)
        )

    def _reserve_engine_handshake(self, session_id: str) -> object | None:
        now = time.monotonic()
        with self._session_bindings_lock:
            self._prune_session_bindings(now)
            if (
                len(self._session_bindings) + len(self._pending_engine_handshakes)
                >= _SOCKETIO_MAX_ENGINEIO_CONNECTIONS
                or self._session_binding_count(session_id)
                + self._pending_handshake_count(session_id)
                >= _SOCKETIO_MAX_ENGINEIO_CONNECTIONS_PER_SESSION
            ):
                return None
            reservation = object()
            self._pending_engine_handshakes[reservation] = session_id
            return reservation

    def _release_engine_handshake(self, reservation: object) -> None:
        with self._session_bindings_lock:
            self._pending_engine_handshakes.pop(reservation, None)

    def _reserve_handshake_buffer_bytes(self, size: int) -> bool:
        if size < 0:
            return False
        with self._session_bindings_lock:
            if (
                self._pending_handshake_buffer_bytes + size
                > _SOCKETIO_MAX_PENDING_HANDSHAKE_BUFFER_BYTES
            ):
                return False
            self._pending_handshake_buffer_bytes += size
            return True

    def _release_handshake_buffer_bytes(self, size: int) -> None:
        if size <= 0:
            return
        with self._session_bindings_lock:
            self._pending_handshake_buffer_bytes = max(
                0, self._pending_handshake_buffer_bytes - size
            )

    @staticmethod
    def _handshake_response_header_buffer_size(headers: Any) -> int | None:
        """Estimate retained ASGI header memory, rejecting malformed/unbounded lists."""
        if not isinstance(headers, (list, tuple)):
            return None
        # Include tuple/list/reference overhead as well as the raw header bytes.
        # Bound the count before iterating so empty headers cannot consume CPU.
        per_header_overhead = 64
        if len(headers) > _SOCKETIO_MAX_HANDSHAKE_BUFFER_BYTES // per_header_overhead:
            return _SOCKETIO_MAX_HANDSHAKE_BUFFER_BYTES + 1
        total = 0
        for header in headers:
            if (
                not isinstance(header, (list, tuple))
                or len(header) != 2
                or not isinstance(header[0], (bytes, bytearray))
                or not isinstance(header[1], (bytes, bytearray))
            ):
                return None
            total += len(header[0]) + len(header[1]) + per_header_overhead
            if total > _SOCKETIO_MAX_HANDSHAKE_BUFFER_BYTES:
                return total
        return total

    def _promote_engine_handshake(
        self, reservation: object, sid: str, session_id: str
    ) -> bool:
        if not sid or len(sid) > 256 or not session_id:
            self._release_engine_handshake(reservation)
            return False
        now = time.monotonic()
        with self._session_bindings_lock:
            self._prune_session_bindings(now)
            reserved = self._pending_engine_handshakes.pop(reservation, None)
            if reserved is None or not self._same_dashboard_session(reserved, session_id):
                return False
            existing = self._session_bindings.get(sid)
            if existing is not None and not self._same_dashboard_session(
                existing[0], session_id
            ):
                return False
            self._session_bindings[sid] = (session_id, now)
            self._session_bindings.move_to_end(sid)
            return True

    def _release_engine_sid(self, sid: str, session_id: str) -> None:
        if not sid or not session_id:
            return
        with self._session_bindings_lock:
            binding = self._session_bindings.get(sid)
            if binding is None:
                self._active_websocket_sids.discard(sid)
                self._engineio_teardown_completed.pop(sid, None)
                return
            if not self._same_dashboard_session(binding[0], session_id):
                return
            if self._pending_websocket_upgrades.get(sid, 0) > 0:
                # Engine.IO can finish teardown while an upgrade handler is
                # still running. Keep its SID binding and quota until that
                # handler exits and releases its pending-upgrade claim.
                self._engineio_teardown_completed[sid] = session_id
                return
            self._engineio_teardown_completed.pop(sid, None)
            self._active_websocket_sids.discard(sid)
            self._session_bindings.pop(sid, None)

    def _mark_websocket_sid_active(self, sid: str, active: bool) -> bool:
        if not sid:
            return False
        with self._session_bindings_lock:
            if active:
                if sid in self._active_websocket_sids:
                    return False
                self._active_websocket_sids.add(sid)
            else:
                self._active_websocket_sids.discard(sid)
        return True

    def _begin_websocket_sid_upgrade(self, sid: str, session_id: str) -> bool:
        if not sid or not session_id:
            return False
        now = time.monotonic()
        with self._session_bindings_lock:
            self._prune_session_bindings(now)
            # A prior transport may still be completing asynchronous Engine.IO
            # teardown. Do not let a new WebSocket claim this SID before that
            # teardown callback releases its binding and active guard.
            if (
                sid in self._engineio_disconnect_tasks
                or sid in self._engineio_teardown_completed
            ):
                return False
            binding = self._session_bindings.get(sid)
            if binding is None or not self._same_dashboard_session(
                binding[0], session_id
            ):
                return False
            self._pending_websocket_upgrades[sid] = (
                self._pending_websocket_upgrades.get(sid, 0) + 1
            )
            self._session_bindings[sid] = (binding[0], now)
            self._session_bindings.move_to_end(sid)
            return True

    def _end_websocket_sid_upgrade(self, sid: str) -> None:
        if not sid:
            return
        teardown_session: str | None = None
        with self._session_bindings_lock:
            pending = self._pending_websocket_upgrades.get(sid, 0)
            if pending <= 1:
                self._pending_websocket_upgrades.pop(sid, None)
                teardown_session = self._engineio_teardown_completed.pop(sid, None)
            else:
                self._pending_websocket_upgrades[sid] = pending - 1
        if teardown_session is not None:
            self._release_engine_sid(sid, teardown_session)

    def _engine_sid_belongs_to_session(self, sid: str, session_id: str) -> bool:
        if not sid or not session_id:
            return False
        now = time.monotonic()
        with self._session_bindings_lock:
            self._prune_session_bindings(now)
            binding = self._session_bindings.get(sid)
            return binding is not None and self._same_dashboard_session(
                binding[0], session_id
            )

    def _session_matches_engine_sid(self, sid: str, session_id: str) -> bool:
        if not sid or not session_id:
            return False
        now = time.monotonic()
        with self._session_bindings_lock:
            self._prune_session_bindings(now)
            binding = self._session_bindings.get(sid)
            if binding is None or not self._same_dashboard_session(
                binding[0], session_id
            ):
                return False
            self._session_bindings[sid] = (binding[0], now)
            self._session_bindings.move_to_end(sid)
            return True

    def _refresh_engine_sid_for_active_session(self, sid: str, session_id: str) -> bool:
        if not self._has_active_dashboard_session(session_id):
            with self._session_bindings_lock:
                if (
                    sid not in self._active_websocket_sids
                    and sid not in self._pending_websocket_upgrades
                ):
                    binding = self._session_bindings.get(sid)
                    if binding is not None and self._same_dashboard_session(
                        binding[0], session_id
                    ):
                        self._session_bindings.pop(sid, None)
            return False
        return self._session_matches_engine_sid(sid, session_id)

    def _has_active_dashboard_session(self, session_id: str) -> bool:
        """Require a live server-side session before allocating Engine.IO state.

        Socket.IO namespace authorization still performs the full current-role
        check. This early check only prevents anonymous or expired cookies from
        consuming transport resources before that later authorization step.
        """
        if not session_id:
            return False
        server = getattr(self.http_adapter, "server", None)
        runtime = getattr(server, "telemetry_runtime", None)
        sessions = getattr(runtime, "sessions", None)
        active_check = getattr(sessions, "is_active_nonblocking", None)
        if callable(active_check):
            try:
                return active_check(session_id) is True
            except Exception:  # noqa: BLE001 - unavailable session store fails closed
                return False

        lookup = getattr(sessions, "get", None)
        if callable(lookup):
            try:
                return (
                    lookup(
                        session_id,
                        touch=False,
                        wait_for_role_check_lock=False,
                    )
                    is not None
                )
            except Exception:  # noqa: BLE001 - unavailable session store fails closed
                return False

        cached_lookup = getattr(runtime, "cached_principal_for_session", None)
        if not callable(cached_lookup):
            return False
        try:
            _authoritative, principal = cached_lookup(session_id)
            return getattr(principal, "authenticated", False) is True
        except Exception:  # noqa: BLE001 - unavailable session resolver fails closed
            return False

    def _bind_engine_sid(self, sid: str, session_id: str) -> bool:
        if not sid or len(sid) > 256 or not session_id:
            return False
        now = time.monotonic()
        with self._session_bindings_lock:
            self._prune_session_bindings(now)
            existing = self._session_bindings.get(sid)
            if existing is not None and not self._same_dashboard_session(
                existing[0], session_id
            ):
                return False
            if existing is None and (
                len(self._session_bindings) + len(self._pending_engine_handshakes)
                >= _SOCKETIO_MAX_ENGINEIO_CONNECTIONS
                or self._session_binding_count(session_id)
                + self._pending_handshake_count(session_id)
                >= _SOCKETIO_MAX_ENGINEIO_CONNECTIONS_PER_SESSION
            ):
                return False
            self._session_bindings[sid] = (session_id, now)
            self._session_bindings.move_to_end(sid)
            while len(self._session_bindings) > _SOCKETIO_MAX_SESSION_BINDINGS:
                self._session_bindings.popitem(last=False)
            return True

    @staticmethod
    def _engine_sid_from_packet(packet: Any) -> str | None:
        if isinstance(packet, Mapping):
            chunks = [packet.get("text")]
            if isinstance(packet.get("body"), (bytes, bytearray)):
                try:
                    chunks.append(bytes(packet["body"]).decode("utf-8"))
                except UnicodeDecodeError:
                    pass
        else:
            chunks = []
        for chunk in chunks:
            if not isinstance(chunk, str):
                continue
            for frame in chunk.split("\x1e"):
                if not frame.startswith("0{"):
                    continue
                try:
                    payload = json.loads(frame[1:])
                except (TypeError, ValueError):
                    continue
                sid = payload.get("sid") if isinstance(payload, dict) else None
                if isinstance(sid, str) and sid and len(sid) <= 256:
                    return sid
        return None

    @staticmethod
    async def _reject_http(send: Send, *, status: int = 403) -> None:
        headers = [
            (b"content-length", b"0"),
            (b"cache-control", b"no-store"),
            *([(b"retry-after", b"1")] if status in {429, 503} else []),
            *(
                (key.lower().encode("latin-1"), value.encode("latin-1"))
                for key, value in SECURITY_HEADERS.items()
            ),
        ]
        await DashboardHTTPASGI._send_and_drain(
            send,
            {"type": "http.response.start", "status": status, "headers": headers},
        )
        await DashboardHTTPASGI._send_and_drain(
            send,
            {"type": "http.response.body", "body": b""},
        )

    def _start_engineio_sid_disconnect(self, sid: str) -> asyncio.Task[None] | None:
        pending = self._engineio_disconnect_tasks.get(sid)
        if pending is not None and not pending.done():
            return pending
        socketio_server = getattr(self.app, "engineio_server", None)
        engineio_server = getattr(socketio_server, "eio", None)
        disconnect = getattr(engineio_server, "disconnect", None)
        if not callable(disconnect):
            return None

        async def disconnect_with_retry() -> None:
            retry_delay = 0.1
            while True:
                try:
                    await disconnect(sid)
                    return
                except asyncio.CancelledError:
                    raise
                except Exception:  # noqa: BLE001 - keep the SID quota until teardown succeeds
                    await asyncio.sleep(retry_delay)
                    retry_delay = min(retry_delay * 2, 30.0)

        try:
            task = asyncio.create_task(disconnect_with_retry())
        except Exception:  # noqa: BLE001 - retain the quota binding if teardown fails
            return None
        self._engineio_disconnect_tasks[sid] = task
        return task

    def _release_engine_sid_after_disconnect(
        self,
        sid: str,
        session_id: str,
        task: asyncio.Task[None],
        reservation: object | None = None,
    ) -> None:
        def release_after_disconnect(completed: asyncio.Task[None]) -> None:
            if self._engineio_disconnect_tasks.get(sid) is completed:
                self._engineio_disconnect_tasks.pop(sid, None)
            if completed.cancelled():
                # Cancellation is reserved for process/loop shutdown. Keep
                # admission state until shutdown instead of respawning work on
                # a loop that is already closing.
                return
            try:
                completed.result()
            except Exception:  # noqa: BLE001 - keep the binding if teardown failed
                retry = self._start_engineio_sid_disconnect(sid)
                if retry is not None:
                    self._release_engine_sid_after_disconnect(
                        sid, session_id, retry, reservation
                    )
                return
            self._release_engine_sid(sid, session_id)
            if reservation is not None:
                self._release_engine_handshake(reservation)

        if task.done():
            release_after_disconnect(task)
        else:
            task.add_done_callback(release_after_disconnect)

    def _disconnect_engineio_sid_after_handshake_failure(
        self,
        sid: str,
        session_id: str,
        reservation: object | None = None,
    ) -> bool:
        """Keep an allocated SID or handshake slot counted until teardown succeeds."""
        task = self._start_engineio_sid_disconnect(sid)
        if task is None:
            return False
        self._release_engine_sid_after_disconnect(sid, session_id, task, reservation)
        return True

    @staticmethod
    def _is_engineio_polling_get(scope: Mapping[str, Any]) -> bool:
        if scope.get("type") != "http" or str(scope.get("method", "")).upper() != "GET":
            return False
        try:
            parameters = urllib.parse.parse_qs(
                bytes(scope.get("query_string", b"")).decode("latin-1"),
                keep_blank_values=True,
                max_num_fields=64,
            )
        except (UnicodeError, ValueError):
            return False
        return parameters.get("transport") == ["polling"]

    @staticmethod
    async def _reject_websocket(
        send: Send,
        scope: Mapping[str, Any],
        *,
        status: int = 403,
    ) -> None:
        extensions = scope.get("extensions", {})
        if isinstance(extensions, Mapping) and "websocket.http.response" in extensions:
            headers = [
                (b"content-length", b"0"),
                (b"cache-control", b"no-store"),
                *([(b"retry-after", b"1")] if status in {429, 503} else []),
                *(
                    (key.lower().encode("latin-1"), value.encode("latin-1"))
                    for key, value in SECURITY_HEADERS.items()
                ),
            ]
            await DashboardHTTPASGI._send_and_drain(
                send,
                {
                    "type": "websocket.http.response.start",
                    "status": status,
                    "headers": headers,
                },
            )
            await DashboardHTTPASGI._send_and_drain(
                send,
                {"type": "websocket.http.response.body", "body": b""},
            )
            return

        # Without the optional ASGI denial-response extension, a close before
        # accept is surfaced as an HTTP handshake rejection; close codes such
        # as 1013 are not observable by WebSocket clients at this stage.
        await DashboardHTTPASGI._send_and_drain(
            send,
            {"type": "websocket.close", "code": 1008},
        )

    @staticmethod
    def _has_engineio_close_packet(message: ASGIMessage) -> bool:
        chunks: list[Any] = [message.get("text"), message.get("body"), message.get("bytes")]
        for chunk in chunks:
            if isinstance(chunk, (bytes, bytearray)):
                try:
                    chunk = bytes(chunk).decode("utf-8")
                except UnicodeDecodeError:
                    continue
            if isinstance(chunk, str) and any(
                packet == "1" for packet in chunk.split("\x1e")
            ):
                return True
        return False

    @staticmethod
    def _has_telemetry_namespace_disconnect(message: ASGIMessage) -> bool:
        chunks: list[Any] = [message.get("text"), message.get("body"), message.get("bytes")]
        for chunk in chunks:
            if isinstance(chunk, (bytes, bytearray)):
                try:
                    chunk = bytes(chunk).decode("utf-8")
                except UnicodeDecodeError:
                    continue
            if isinstance(chunk, str) and any(
                packet in {"41/telemetry", "41/telemetry,"}
                for packet in chunk.split("\x1e")
            ):
                return True
        return False

    @staticmethod
    def _safe_socketio_control_packet(message: ASGIMessage) -> bool:
        text = message.get("text")
        return isinstance(text, str) and (
            text.startswith(("0{", "41/telemetry,", "44/telemetry,"))
            or text == "1"
        )

    @staticmethod
    def _safe_polling_control_payload(payload: Any) -> bytes:
        if not isinstance(payload, (bytes, bytearray)):
            return b""
        try:
            packets = bytes(payload).decode("utf-8").split("\x1e")
        except UnicodeDecodeError:
            return b""
        safe_packets = [
            packet
            for packet in packets
            if packet.startswith(("0{", "41/telemetry,", "44/telemetry,"))
            or packet == "1"
        ]
        return "\x1e".join(safe_packets).encode("utf-8")

    async def __call__(self, scope: Mapping[str, Any], receive: Receive, send: Send) -> None:
        scope_type = scope.get("type")
        path = str(scope.get("path", ""))
        if not self._socketio_path(path) or scope_type not in {"http", "websocket"}:
            await self.app(scope, receive, send)
            return

        origins = [
            bytes(value).decode("latin-1")
            for key, value in scope.get("headers", [])
            if bytes(key).lower() == b"origin"
        ]
        public_origin = getattr(
            getattr(getattr(self.http_adapter, "server", None), "context", None),
            "public_origin",
            None,
        )
        method = str(scope.get("method", "")).upper()
        # Engine.IO may derive its allowed origin from forwarded host/proto
        # headers. They are not an authority for this browser origin boundary.
        # Browser WebSocket handshakes must carry exactly one Origin so the
        # configured public origin can be checked before Engine.IO allocation.
        # HTTP GET polling may omit Origin only with exactly one matching
        # same-origin Referer; no browser evidence is rejected before Engine.IO
        # can allocate a transport SID. Other HTTP methods require Origin.
        missing_required_origin = not origins and (
            scope_type == "websocket"
            or (
                scope_type == "http"
                and (
                    method != "GET"
                    or not _same_origin_referer(scope.get("headers", []), public_origin)
                )
            )
        )
        invalid_supplied_origin = bool(origins) and (
            len(origins) > 1
            or not isinstance(public_origin, str)
            or not _same_origin(origins[0], public_origin)
        )
        if missing_required_origin or invalid_supplied_origin:
            if scope_type == "websocket":
                await self._reject_websocket(send, scope)
            else:
                await self._reject_http(send)
            return

        session_id = _session_id(scope)
        has_sid, engine_sid, valid_query = self._engine_sid_from_scope(scope)
        if not valid_query:
            if scope_type == "websocket":
                await self._reject_websocket(send, scope)
            else:
                await self._reject_http(send)
            return

        websocket_upgrade_sid: str | None = None
        if not self._has_active_dashboard_session(session_id):
            if (
                scope_type == "http"
                and has_sid
                and engine_sid is not None
                and self._is_engineio_polling_get(scope)
                and self._engine_sid_belongs_to_session(engine_sid, session_id)
            ):
                # Engine.IO waits for a polling GET to consume its queued close
                # packet. Start teardown, delegate only this read-only poll,
                # and filter its body to control packets before releasing the
                # quota binding once the server-side socket is gone.
                disconnect_task = self._start_engineio_sid_disconnect(engine_sid)
                if disconnect_task is None:
                    await self._reject_http(send)
                    return
                self._release_engine_sid_after_disconnect(
                    engine_sid, session_id, disconnect_task
                )

                async def send_close_controls(message: ASGIMessage) -> None:
                    if message.get("type") == "http.response.start":
                        filtered = dict(message)
                        filtered["headers"] = [
                            (key, value)
                            for key, value in message.get("headers", [])
                            if bytes(key).lower()
                            not in {b"content-length", b"content-encoding", b"content-md5"}
                        ]
                        await send(filtered)
                    elif message.get("type") == "http.response.body":
                        filtered = dict(message)
                        filtered["body"] = self._safe_polling_control_payload(
                            message.get("body", b"")
                        )
                        await send(filtered)
                    else:
                        await send(message)

                # Engine.IO may gzip polling payloads. The close-packet filter
                # needs the plaintext frame, so suppress compression only for
                # this revoked-session poll before delegating it.
                close_scope = dict(scope)
                close_scope["headers"] = [
                    (key, value)
                    for key, value in scope.get("headers", [])
                    if bytes(key).lower() != b"accept-encoding"
                ]
                try:
                    await self.app(close_scope, receive, send_close_controls)
                finally:
                    if not disconnect_task.done():
                        await asyncio.wait({disconnect_task}, timeout=0.1)
                return
            if (
                scope_type == "websocket"
                and has_sid
                and engine_sid is not None
                and self._engine_sid_belongs_to_session(engine_sid, session_id)
            ):
                # A WebSocket upgrade can share the SID with an existing
                # polling transport; reject the upgrade but keep that SID
                # counted until the original transport closes or expires.
                await self._reject_websocket(send, scope)
                return
            if scope_type == "websocket":
                await self._reject_websocket(send, scope)
            else:
                await self._reject_http(send)
            return

        # Check the server-side session before touching an existing SID's
        # activity timestamp. Otherwise a revoked cookie can keep rejected
        # transport bindings alive and consume the bounded admission slots.
        if has_sid and (
            engine_sid is None
            or not self._session_matches_engine_sid(engine_sid, session_id)
        ):
            if scope_type == "websocket":
                await self._reject_websocket(send, scope)
            else:
                await self._reject_http(send)
            return

        if scope_type == "websocket" and has_sid:
            if engine_sid is None or not self._begin_websocket_sid_upgrade(
                engine_sid, session_id
            ):
                await self._reject_websocket(send, scope)
                return
            websocket_upgrade_sid = engine_sid

        new_handshake = self._is_new_engineio_handshake(
            scope, has_sid=has_sid, valid_query=valid_query
        )
        reservation = (
            self._reserve_engine_handshake(session_id) if new_handshake else None
        )
        if new_handshake and reservation is None:
            if scope_type == "websocket":
                await self._reject_websocket(send, scope, status=429)
            else:
                await self._reject_http(send, status=429)
            return
        buffer_existing_poll_response = (
            not new_handshake
            and scope_type == "http"
            and has_sid
            and engine_sid is not None
            and self._is_engineio_polling_get(scope)
        )

        promoted_sid: str | None = None
        internal_engine_sid: str | None = engine_sid if has_sid else None

        def record_internal_engine_sid(sid: str) -> None:
            nonlocal internal_engine_sid
            if isinstance(sid, str) and sid and len(sid) <= 256:
                internal_engine_sid = sid

        engine_close_seen = False
        session_invalidated = False
        dashboard_session_revoked = False
        handshake_ready = asyncio.Event()
        websocket_accepted = False
        websocket_guard_sid: str | None = None
        response_started = False
        response_complete = False
        response_status = 0
        handshake_timed_out = False
        handshake_binding_failed = False
        sid_cleanup_scheduled = False
        pending_response_start: ASGIMessage | None = None
        pending_handshake_header_reserved_bytes = 0
        pending_handshake_body = bytearray()
        pending_handshake_body_message: ASGIMessage | None = None
        pending_handshake_body_reserved_bytes = 0
        pending_poll_body = bytearray()
        pending_poll_body_message: ASGIMessage | None = None
        pending_poll_body_reserved_bytes = 0
        pending_poll_header_reserved_bytes = 0

        async def ensure_active_engine_sid(sid: str) -> bool:
            nonlocal dashboard_session_revoked, session_invalidated, engine_close_seen
            if session_invalidated:
                return False
            if self._refresh_engine_sid_for_active_session(sid, session_id):
                return True
            dashboard_session_revoked = not self._has_active_dashboard_session(
                session_id
            )
            session_invalidated = True
            engine_close_seen = True
            await send({"type": "websocket.close", "code": 1008})
            return False

        async def receive_with_lifecycle() -> ASGIMessage:
            nonlocal promoted_sid, reservation, engine_close_seen
            if session_invalidated or handshake_timed_out:
                if scope_type == "websocket":
                    return {"type": "websocket.disconnect", "code": 1008}
                return {"type": "http.disconnect"}
            message = await receive()
            message_type = message.get("type")
            if scope_type == "websocket" and message_type == "websocket.disconnect":
                # A direct WebSocket owns its promoted SID, while an upgrade
                # request reuses a SID owned by the original polling transport.
                # Keep admission counted until Engine.IO's ASGI call exits; a
                # disconnect alone does not prove a non-cooperative handler
                # has released its server-side resources.
                if reservation is None and not has_sid and promoted_sid is not None:
                    engine_close_seen = True
            elif self._has_engineio_close_packet(message):
                engine_close_seen = True
            active_engine_sid = engine_sid if has_sid else promoted_sid
            if (
                scope_type == "websocket"
                and message_type == "websocket.receive"
                and active_engine_sid is not None
            ):
                if not await ensure_active_engine_sid(active_engine_sid):
                    return {"type": "websocket.disconnect", "code": 1008}
            return message

        async def send_to_client(message: ASGIMessage) -> None:
            nonlocal engine_close_seen, response_complete
            nonlocal session_invalidated, websocket_accepted, websocket_guard_sid
            if session_invalidated or handshake_timed_out:
                return
            active_engine_sid = engine_sid if has_sid else promoted_sid
            if scope_type == "websocket" and active_engine_sid is not None:
                if not await ensure_active_engine_sid(active_engine_sid):
                    return
            closes_engine_session = self._has_engineio_close_packet(message)
            if closes_engine_session:
                engine_close_seen = True
            if scope_type == "websocket" and message.get("type") == "websocket.accept":
                if active_engine_sid is not None:
                    if not self._mark_websocket_sid_active(active_engine_sid, True):
                        # A duplicate upgrade cannot take ownership of the
                        # active guard held by the existing WebSocket.
                        session_invalidated = True
                        await send({"type": "websocket.close", "code": 1008})
                        return
                    websocket_guard_sid = active_engine_sid
                websocket_accepted = True
            await send(message)
            if (
                scope_type == "http"
                and message.get("type") == "http.response.body"
                and not message.get("more_body", False)
            ):
                response_complete = True
            if self._has_telemetry_namespace_disconnect(message):
                if scope_type == "websocket":
                    session_invalidated = True
                    engine_close_seen = True
                    await send({"type": "websocket.close", "code": 1008})

        async def flush_pending_http_handshake_response() -> None:
            nonlocal pending_handshake_header_reserved_bytes
            nonlocal pending_handshake_body_reserved_bytes
            nonlocal pending_handshake_body_message, pending_response_start
            nonlocal response_started
            filtered_handshake_payload: bytes | None = None
            if pending_handshake_body_message is not None and response_status == 200:
                payload = bytes(pending_handshake_body)
                filtered_handshake_payload = self._safe_polling_control_payload(payload)
            if pending_response_start is not None:
                response_start = dict(pending_response_start)
                pending_response_start = None
                if (
                    filtered_handshake_payload is not None
                    and filtered_handshake_payload != bytes(pending_handshake_body)
                ):
                    response_start["headers"] = [
                        (key, value)
                        for key, value in response_start.get("headers", [])
                        if bytes(key).lower()
                        not in {
                            b"content-length",
                            b"content-encoding",
                            b"content-md5",
                        }
                    ]
                response_started = True
                await send_to_client(response_start)
                self._release_handshake_buffer_bytes(
                    pending_handshake_header_reserved_bytes
                )
                pending_handshake_header_reserved_bytes = 0
            if pending_handshake_body_message is not None:
                body_message = dict(pending_handshake_body_message)
                payload = bytes(pending_handshake_body)
                if filtered_handshake_payload is not None:
                    # A handshake buffer may contain control frames accumulated
                    # before the SID was complete. Filter at flush time so
                    # earlier chunks cannot bypass a later authorization denial.
                    payload = filtered_handshake_payload
                body_message["body"] = payload
                await send_to_client(body_message)
                self._release_handshake_buffer_bytes(
                    pending_handshake_body_reserved_bytes
                )
                pending_handshake_body_reserved_bytes = 0
                pending_handshake_body.clear()
                pending_handshake_body_message = None

        async def flush_pending_poll_response(
            message: ASGIMessage, *, strip_entity_headers: bool = False
        ) -> None:
            nonlocal pending_poll_body_message, pending_poll_body_reserved_bytes
            nonlocal pending_poll_header_reserved_bytes, pending_response_start
            nonlocal response_started
            if pending_response_start is not None:
                response_start = dict(pending_response_start)
                pending_response_start = None
                if strip_entity_headers:
                    response_start["headers"] = [
                        (key, value)
                        for key, value in response_start.get("headers", [])
                        if bytes(key).lower()
                        not in {
                            b"content-length",
                            b"content-encoding",
                            b"content-md5",
                        }
                    ]
                response_started = True
                await send_to_client(response_start)
                self._release_handshake_buffer_bytes(
                    pending_poll_header_reserved_bytes
                )
                pending_poll_header_reserved_bytes = 0
            await send_to_client(message)
            self._release_handshake_buffer_bytes(pending_poll_body_reserved_bytes)
            pending_poll_body_reserved_bytes = 0
            pending_poll_body.clear()
            pending_poll_body_message = None

        async def bind_engine_sid_then_send(message: ASGIMessage) -> None:
            nonlocal handshake_binding_failed, pending_handshake_body_message
            nonlocal pending_handshake_body_reserved_bytes, promoted_sid, reservation
            nonlocal session_invalidated, websocket_guard_sid
            if handshake_timed_out:
                return
            packet_message = message
            if (
                scope_type == "http"
                and new_handshake
                and promoted_sid is None
                and message.get("type") == "http.response.body"
            ):
                payload = message.get("body", b"")
                if not isinstance(payload, (bytes, bytearray)):
                    raise _EngineIOHandshakeBufferLimit
                payload_size = len(payload)
                available_body_bytes = max(
                    0,
                    _SOCKETIO_MAX_HANDSHAKE_BUFFER_BYTES
                    - pending_handshake_header_reserved_bytes
                    - len(pending_handshake_body),
                )
                if (
                    payload_size > available_body_bytes
                    or not self._reserve_handshake_buffer_bytes(payload_size)
                ):
                    # If the open frame fits in the permitted prefix, bind it
                    # before rejecting the oversized response so teardown can
                    # account for the Engine.IO allocation.
                    candidate = bytes(
                        pending_handshake_body
                        + payload[:available_body_bytes]
                    )
                    oversized_sid = self._engine_sid_from_packet(
                        {"type": "http.response.body", "body": candidate}
                    )
                    if oversized_sid is not None and reservation is not None:
                        if self._promote_engine_handshake(
                            reservation, oversized_sid, session_id
                        ):
                            promoted_sid = oversized_sid
                            reservation = None
                            handshake_ready.set()
                        else:
                            reservation = None
                            handshake_binding_failed = True
                    raise _EngineIOHandshakeBufferLimit
                pending_handshake_body.extend(payload)
                pending_handshake_body_reserved_bytes += payload_size
                pending_handshake_body_message = dict(message)
                packet_message = {
                    "type": "http.response.body",
                    "body": bytes(pending_handshake_body),
                }
            allocated_sid = self._engine_sid_from_packet(packet_message)
            if allocated_sid is not None:
                if new_handshake:
                    if reservation is None:
                        return
                    bound = self._promote_engine_handshake(
                        reservation, allocated_sid, session_id
                    )
                    reservation = None
                    if bound:
                        promoted_sid = allocated_sid
                        if scope_type == "websocket" and websocket_accepted:
                            if not self._mark_websocket_sid_active(allocated_sid, True):
                                handshake_binding_failed = True
                                session_invalidated = True
                                await send({"type": "websocket.close", "code": 1008})
                                return
                            websocket_guard_sid = allocated_sid
                        handshake_ready.set()
                    else:
                        handshake_binding_failed = True
                else:
                    bound = self._bind_engine_sid(allocated_sid, session_id)
                if not bound:
                    return
            if (
                scope_type == "http"
                and new_handshake
                and message.get("type") == "http.response.body"
                and pending_handshake_body_message is not None
            ):
                if allocated_sid is None:
                    return
                await flush_pending_http_handshake_response()
                return
            await send_to_client(message)

        if scope_type == "websocket":
            authorization_failed = False

            async def gated_send(message: ASGIMessage) -> None:
                nonlocal authorization_failed
                if session_invalidated or handshake_timed_out:
                    return
                message_type = message.get("type")
                if message_type == "websocket.send":
                    if authorization_failed:
                        if self._safe_socketio_control_packet(message):
                            await DashboardHTTPASGI._send_and_drain(
                                bind_engine_sid_then_send, message
                            )
                        return
                    allowed = await self.http_adapter._send_authorized_live_message(
                        session_id,
                        message,
                        bind_engine_sid_then_send,
                    )
                    if allowed:
                        return
                    authorization_failed = True
                    if self._safe_socketio_control_packet(message):
                        await DashboardHTTPASGI._send_and_drain(
                            bind_engine_sid_then_send, message
                        )
                    return
                await DashboardHTTPASGI._send_and_drain(send_to_client, message)

            async def app_send(message: ASGIMessage) -> None:
                await gated_send(message)
        else:
            async def app_send(message: ASGIMessage) -> None:
                nonlocal pending_handshake_header_reserved_bytes
                nonlocal pending_poll_body_message, pending_poll_body_reserved_bytes
                nonlocal pending_poll_header_reserved_bytes
                nonlocal pending_response_start, response_started, response_status
                if handshake_timed_out:
                    return
                message_type = message.get("type")
                if message_type == "http.response.start":
                    response_status = int(message.get("status", 0))
                    if new_handshake:
                        header_size = self._handshake_response_header_buffer_size(
                            message.get("headers", [])
                        )
                        if (
                            header_size is None
                            or header_size > _SOCKETIO_MAX_HANDSHAKE_BUFFER_BYTES
                            or not self._reserve_handshake_buffer_bytes(header_size)
                        ):
                            raise _EngineIOHandshakeBufferLimit
                        pending_handshake_header_reserved_bytes = header_size
                        pending_response_start = dict(message)
                        return
                    if buffer_existing_poll_response:
                        header_size = self._handshake_response_header_buffer_size(
                            message.get("headers", [])
                        )
                        if (
                            header_size is None
                            or header_size > _SOCKETIO_MAX_HANDSHAKE_BUFFER_BYTES
                            or not self._reserve_handshake_buffer_bytes(header_size)
                        ):
                            raise _EngineIOHandshakeBufferLimit
                        pending_poll_header_reserved_bytes = header_size
                        pending_response_start = dict(message)
                        return
                    response_started = True
                if (
                    buffer_existing_poll_response
                    and message_type == "http.response.body"
                    and pending_response_start is not None
                ):
                    payload = message.get("body", b"")
                    if not isinstance(payload, (bytes, bytearray)):
                        raise _EngineIOHandshakeBufferLimit
                    buffered_size = len(pending_poll_body) + len(payload)
                    if (
                        buffered_size + pending_poll_header_reserved_bytes
                        > _SOCKETIO_MAX_HANDSHAKE_BUFFER_BYTES
                        or not self._reserve_handshake_buffer_bytes(len(payload))
                    ):
                        raise _EngineIOHandshakeBufferLimit
                    pending_poll_body.extend(payload)
                    pending_poll_body_reserved_bytes += len(payload)
                    pending_poll_body_message = dict(message)
                    if message.get("more_body", False):
                        return
                    buffered_message = dict(pending_poll_body_message)
                    buffered_message["body"] = bytes(pending_poll_body)
                    buffered_message["more_body"] = False
                    if response_status == 200 and buffered_message["body"]:
                        allowed = await self.http_adapter._send_authorized_live_message(
                            session_id,
                            buffered_message,
                            flush_pending_poll_response,
                        )
                        if allowed:
                            return
                        buffered_message["body"] = self._safe_polling_control_payload(
                            buffered_message["body"]
                        )
                        await flush_pending_poll_response(
                            buffered_message, strip_entity_headers=True
                        )
                    else:
                        await flush_pending_poll_response(buffered_message)
                    return
                if (
                    new_handshake
                    and message_type == "http.response.body"
                    and (
                        response_status != 200
                        or not message.get("body", b"")
                    )
                ):
                    await DashboardHTTPASGI._send_and_drain(
                        bind_engine_sid_then_send, message
                    )
                    return
                if (
                    message_type == "http.response.body"
                    and response_status == 200
                    and message.get("body", b"")
                ):
                    allowed = await self.http_adapter._send_authorized_live_message(
                        session_id,
                        message,
                        bind_engine_sid_then_send,
                    )
                    if allowed:
                        return
                    filtered_message = dict(message)
                    if not new_handshake:
                        filtered_message["body"] = self._safe_polling_control_payload(
                            message.get("body", b"")
                        )
                    fallback_send = (
                        bind_engine_sid_then_send
                        if new_handshake
                        else send_to_client
                    )
                    await DashboardHTTPASGI._send_and_drain(
                        fallback_send, filtered_message
                    )
                    return
                await DashboardHTTPASGI._send_and_drain(send_to_client, message)

        def schedule_failed_handshake_sid_cleanup(sid: str) -> None:
            nonlocal reservation, sid_cleanup_scheduled
            with self._session_bindings_lock:
                completed_session = self._engineio_teardown_completed.get(sid)
            if completed_session is not None and self._same_dashboard_session(
                completed_session, session_id
            ):
                if reservation is not None:
                    self._release_engine_handshake(reservation)
                    reservation = None
                sid_cleanup_scheduled = True
                return
            held_reservation = reservation
            if held_reservation is None and new_handshake and promoted_sid is None:
                held_reservation = self._reserve_engine_handshake(session_id)
                if held_reservation is None:
                    self._bind_engine_sid(sid, session_id)
            reservation = None
            sid_cleanup_scheduled = True
            self._disconnect_engineio_sid_after_handshake_failure(
                sid, session_id, held_reservation
            )

        async def cancel_engineio_task(task: asyncio.Task[None]) -> None:
            nonlocal reservation, sid_cleanup_scheduled
            task.cancel()
            done, _ = await asyncio.wait(
                {task}, timeout=_SOCKETIO_ENGINEIO_CANCEL_GRACE_SECONDS
            )
            sid_after_task = promoted_sid or internal_engine_sid
            if task in done:
                try:
                    task.result()
                except BaseException:  # noqa: BLE001 - consume cancellation/cleanup failure
                    pass
                if sid_after_task is not None:
                    schedule_failed_handshake_sid_cleanup(sid_after_task)
                return

            held_reservation = reservation
            if held_reservation is None and sid_after_task is None and new_handshake:
                held_reservation = self._reserve_engine_handshake(session_id)
            reservation = None
            if held_reservation is None and sid_after_task is None:
                return
            sid_cleanup_scheduled = True

            def release_when_task_finishes(completed: asyncio.Task[None]) -> None:
                try:
                    completed.exception()
                except BaseException:  # noqa: BLE001 - consume eventual cancellation/error
                    pass
                completed_sid = promoted_sid or internal_engine_sid
                if completed_sid is not None:
                    if held_reservation is not None:
                        self._disconnect_engineio_sid_after_handshake_failure(
                            completed_sid, session_id, held_reservation
                        )
                    else:
                        schedule_failed_handshake_sid_cleanup(completed_sid)
                elif held_reservation is not None:
                    self._release_engine_handshake(held_reservation)

            task.add_done_callback(release_when_task_finishes)

        # Quota rejection is intentionally retryable: HTTP and ASGI WebSocket
        # denial-response clients receive 429 + Retry-After. Servers without
        # that optional extension receive a pre-accept handshake rejection.
        app_task: asyncio.Task[None] | None = None
        handshake_ready_task: asyncio.Task[bool] | None = None
        try:
            if new_handshake:
                capture_token = self._engineio_sid_context.set(
                    record_internal_engine_sid
                )
                try:
                    app_task = asyncio.create_task(
                        self.app(scope, receive_with_lifecycle, app_send)
                    )
                finally:
                    self._engineio_sid_context.reset(capture_token)
                handshake_ready_task = asyncio.create_task(handshake_ready.wait())
                completed, _ = await asyncio.wait(
                    {app_task, handshake_ready_task},
                    timeout=_SOCKETIO_ENGINEIO_HANDSHAKE_TIMEOUT_SECONDS,
                    return_when=asyncio.FIRST_COMPLETED,
                )
                if not completed:
                    handshake_timed_out = True
                    await cancel_engineio_task(app_task)
                    if scope_type == "websocket":
                        if websocket_accepted:
                            await send({"type": "websocket.close", "code": 1013})
                        else:
                            await self._reject_websocket(send, scope, status=503)
                    else:
                        await self._reject_http(send, status=503)
                    return
                # Shield the Engine.IO handler so cancellation of this outer
                # request reaches our bounded teardown path immediately. A
                # handler that suppresses cancellation must not hold the
                # request task open or release its quota prematurely.
                await asyncio.shield(app_task)
                if new_handshake and not handshake_ready.is_set():
                    failed_sid = promoted_sid or internal_engine_sid
                    if failed_sid is not None:
                        schedule_failed_handshake_sid_cleanup(failed_sid)
                        promoted_sid = None
                    if handshake_binding_failed:
                        pending_response_start = None
                        if scope_type == "websocket":
                            if websocket_accepted:
                                await send({"type": "websocket.close", "code": 1013})
                            else:
                                await self._reject_websocket(send, scope, status=503)
                        else:
                            await self._reject_http(send, status=503)
                    elif scope_type == "http":
                        if response_status == 200:
                            pending_response_start = None
                            await self._reject_http(send, status=503)
                        else:
                            await flush_pending_http_handshake_response()
                            if response_started and not response_complete:
                                await send({"type": "http.response.body", "body": b""})
            else:
                app_task = asyncio.create_task(
                    self.app(scope, receive_with_lifecycle, app_send)
                )
                await asyncio.shield(app_task)
                if buffer_existing_poll_response and pending_response_start is not None:
                    if (
                        pending_poll_body_message is not None
                        and pending_poll_body_message.get("more_body", False)
                    ):
                        raise RuntimeError(
                            "Engine.IO polling response ended before its final body chunk"
                        )
                    await flush_pending_poll_response(
                        {"type": "http.response.body", "body": b""}
                    )
        except _EngineIOHandshakeBufferLimit:
            handshake_timed_out = True
            if app_task is not None:
                await cancel_engineio_task(app_task)
            elif promoted_sid is not None or internal_engine_sid is not None:
                failed_sid = promoted_sid or internal_engine_sid
                if failed_sid is not None:
                    schedule_failed_handshake_sid_cleanup(failed_sid)
                promoted_sid = None
            elif buffer_existing_poll_response and engine_sid is not None:
                self._disconnect_engineio_sid_after_handshake_failure(
                    engine_sid, session_id
                )
            await self._reject_http(send, status=503)
            return
        except BaseException:
            if app_task is not None:
                handshake_timed_out = True
                await cancel_engineio_task(app_task)
            elif promoted_sid is not None or internal_engine_sid is not None:
                failed_sid = promoted_sid or internal_engine_sid
                if failed_sid is not None:
                    schedule_failed_handshake_sid_cleanup(failed_sid)
                promoted_sid = None
            elif buffer_existing_poll_response and engine_sid is not None:
                self._disconnect_engineio_sid_after_handshake_failure(
                    engine_sid, session_id
                )
            raise
        finally:
            if handshake_ready_task is not None and not handshake_ready_task.done():
                handshake_ready_task.cancel()
                try:
                    await handshake_ready_task
                except asyncio.CancelledError:
                    pass
            if pending_handshake_body_reserved_bytes:
                self._release_handshake_buffer_bytes(
                    pending_handshake_body_reserved_bytes
                )
                pending_handshake_body_reserved_bytes = 0
            if pending_handshake_header_reserved_bytes:
                self._release_handshake_buffer_bytes(
                    pending_handshake_header_reserved_bytes
                )
                pending_handshake_header_reserved_bytes = 0
            if pending_poll_body_reserved_bytes:
                self._release_handshake_buffer_bytes(pending_poll_body_reserved_bytes)
                pending_poll_body_reserved_bytes = 0
            if pending_poll_header_reserved_bytes:
                self._release_handshake_buffer_bytes(pending_poll_header_reserved_bytes)
                pending_poll_header_reserved_bytes = 0
            if reservation is not None:
                self._release_engine_handshake(reservation)
            if dashboard_session_revoked and not sid_cleanup_scheduled:
                revoked_sid = engine_sid if has_sid else (promoted_sid or internal_engine_sid)
                if revoked_sid is not None:
                    if app_task is not None and not app_task.done():
                        sid_cleanup_scheduled = True
                        app_task.add_done_callback(
                            lambda _completed: schedule_failed_handshake_sid_cleanup(
                                revoked_sid
                            )
                        )
                    else:
                        schedule_failed_handshake_sid_cleanup(revoked_sid)
            if scope_type == "websocket":
                if websocket_guard_sid is not None:
                    # Release only the guard this scope acquired. A rejected
                    # duplicate upgrade must not clear another socket's claim.
                    # A cancellation-resistant direct Engine.IO handler still
                    # owns its claim after the outer handshake timed out.
                    if app_task is not None and not app_task.done():
                        owned_sid = websocket_guard_sid
                        app_task.add_done_callback(
                            lambda _completed: self._mark_websocket_sid_active(
                                owned_sid, False
                            )
                        )
                    else:
                        self._mark_websocket_sid_active(websocket_guard_sid, False)
                elif (
                    promoted_sid is not None
                    and app_task is not None
                    and app_task.done()
                    and not engine_close_seen
                    and not sid_cleanup_scheduled
                ):
                    # If a direct WebSocket handler exits without an Engine.IO
                    # close packet, keep quota until server-side teardown ends.
                    schedule_failed_handshake_sid_cleanup(promoted_sid)
            if (
                engine_close_seen
                and (app_task is None or app_task.done())
                and not sid_cleanup_scheduled
            ):
                closed_sid = engine_sid if has_sid else promoted_sid
                if closed_sid is not None:
                    self._release_engine_sid(closed_sid, session_id)
            if websocket_upgrade_sid is not None:
                if app_task is not None and not app_task.done():
                    app_task.add_done_callback(
                        lambda _completed: self._end_websocket_sid_upgrade(
                            websocket_upgrade_sid
                        )
                    )
                else:
                    self._end_websocket_sid_upgrade(websocket_upgrade_sid)


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
        Established streams may wait asynchronously for a slot up to the
        configured authorization-wait deadline; timeout fails closed. The slot
        is released when the worker actually finishes, even if its Socket.IO
        task is cancelled.
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
            deadline = loop.time() + _ASGI_AUTHORIZATION_WAIT_TIMEOUT_SECONDS
            if not await _acquire_before_deadline(
                _SOCKETIO_ROLE_CHECK_SLOTS, deadline
            ):
                return None
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
            return {"protocol_version": 2, "frames": []}
        principal = await self._principal_for_session_async(
            session_id, wait_for_capacity=True
        )
        if principal is None or not principal.may_stream:
            return {"protocol_version": 2, "frames": []}
        after = data.get("after_sequence") if isinstance(data, Mapping) else None
        for frame in self.runtime.gateway.poll(subscription, after_sequence=after):
            # A single poll can return a backlog. Serialize the final
            # authorization check with RouterOS role refresh through enqueue.
            emitted = await self._emit_authorized(
                sid, session_id, frame["event"], frame
            )
            if not emitted:
                await self.server.disconnect(sid, namespace=self.namespace)
                break
        # Event payloads are delivered only through _emit_authorized, which
        # holds the session gate through Socket.IO's send queue. Returning the
        # same frames in the RPC acknowledgement would create a second,
        # ungated delivery path after that lock has been released. Version 2
        # defines pushed event delivery; version 1 returned replay frames in
        # the acknowledgement and is intentionally not emitted by this server.
        return {"protocol_version": 2, "frames": []}

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

        loop = asyncio.get_running_loop()
        deadline = loop.time() + _ASGI_AUTHORIZATION_WAIT_TIMEOUT_SECONDS
        while True:
            role_lock = lock_for_session(session_id)
            if role_lock is None:
                return False
            if not await _acquire_before_deadline(role_lock, deadline):
                return False
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
    application = SocketIOLiveSendASGI(application, http_app)
    application = TrustedProxySchemeASGI(
        application,
        context.config.trusted_proxy_sources,
    )
    return application, server, redirect_server


def main() -> None:
    disable_process_core_dumps()
    import uvicorn

    application, server, redirect_server = create_application()
    try:
        uvicorn.run(
            application,
            host=os.environ.get("LISTEN_ADDRESS", "0.0.0.0"),
            port=int(os.environ.get("APP_PORT", "8080")),
            log_level="info",
            # Profile-share bearer tokens are embedded in URL paths; Uvicorn's
            # default access logger records request paths.
            access_log=False,
            **DashboardHTTPASGI._uvicorn_proxy_options(),
        )
    finally:
        redirect_server.shutdown()
        server.close()


if __name__ == "__main__":
    main()
