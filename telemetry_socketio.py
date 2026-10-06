"""Optional Socket.IO delivery adapter for the live telemetry contract.

The application still serves REST/SSE by default.  This module contains the
small adapter boundary needed by a future Socket.IO server (for example,
``python-socketio``) without importing that optional dependency or changing
the RouterOS mutation path.  A caller must explicitly attach a Socket.IO
server and provide a session resolver; unauthenticated or non-RouterOS
sessions are rejected before a subscription is created and revalidated before
every client poll and server-pushed frame.
"""

from __future__ import annotations

from typing import Any, Callable, Mapping

from telemetry_broker import TelemetryEvent
from telemetry_gateway import (
    TelemetryGatewayContract,
    TelemetryPrincipal,
    TelemetrySubscriptionError,
)


class SocketIOTelemetryError(RuntimeError):
    """Base error returned by the optional adapter."""


class SocketIOTelemetryAdapter:
    """Bridge gateway frames to a Socket.IO-compatible server object.

    The server is deliberately duck-typed.  It must expose ``on`` and
    ``emit`` methods matching the common python-socketio API.  This keeps the
    immutable production image dependency-free while allowing a canary image
    to install and attach a real Socket.IO implementation explicitly.
    """

    namespace = "/telemetry"

    def __init__(
        self,
        gateway: TelemetryGatewayContract,
        session_resolver: Callable[[str, Mapping[str, Any] | None], TelemetryPrincipal | None],
    ) -> None:
        self._gateway = gateway
        self._session_resolver = session_resolver
        self._subscriptions: dict[str, str] = {}
        self._server: Any | None = None

    @property
    def client_count(self) -> int:
        return len(self._subscriptions)

    def attach(self, server: Any) -> None:
        """Register handlers on an already-created Socket.IO server."""

        required_methods = ("on", "emit", "get_environ", "disconnect")
        if any(not callable(getattr(server, method, None)) for method in required_methods):
            raise TypeError(
                "Socket.IO server must provide on(), emit(), get_environ(), and disconnect()"
            )
        self._server = server
        server.on("connect", self.on_connect, namespace=self.namespace)
        server.on("disconnect", self.on_disconnect, namespace=self.namespace)
        server.on("telemetry.subscribe", self.on_subscribe, namespace=self.namespace)
        server.on("telemetry.poll", self.on_poll, namespace=self.namespace)

    def on_connect(
        self,
        sid: str,
        environ: Mapping[str, Any] | None = None,
        _auth: Any = None,
    ) -> bool:
        """Authenticate a server-side dashboard session before subscribing."""

        # The transport's auth payload is client-controlled. Authentication is
        # resolved only from the server-provided request environment.
        facts = dict(environ or {})
        principal = self._session_resolver(str(sid), facts)
        if principal is None or not principal.may_stream:
            return False
        try:
            self._subscriptions[str(sid)] = self._gateway.open(principal)
        except (TelemetrySubscriptionError, RuntimeError):
            return False
        return True

    def on_disconnect(self, sid: str) -> None:
        subscription = self._subscriptions.pop(str(sid), None)
        if subscription:
            self._gateway.close(subscription)

    def on_subscribe(self, sid: str, data: Any = None) -> dict[str, Any]:
        """Return a bounded replay from the subscription's current cursor."""

        subscription = self._authorized_subscription(sid)
        after = data.get("after_sequence") if isinstance(data, Mapping) else None
        frames = self._gateway.poll(subscription, after_sequence=after)
        return {"protocol_version": 1, "frames": frames}

    def on_poll(self, sid: str, data: Any = None) -> dict[str, Any]:
        """Return replay frames and optionally emit them to the same client."""

        response = self.on_subscribe(sid, data)
        if self._server is not None and response["frames"]:
            for frame in response["frames"]:
                self._authorized_subscription(sid)
                self._server.emit(frame["event"], frame, to=str(sid), namespace=self.namespace)
        return response

    def publish(self, events: list[TelemetryEvent]) -> int:
        """Publish redacted broker events to connected Socket.IO clients."""

        count = self._gateway.publish(events)
        if self._server is None:
            return count
        for sid, subscription in list(self._subscriptions.items()):
            try:
                self._authorized_subscription(sid)
            except SocketIOTelemetryError:
                continue
            for frame in self._gateway.poll(subscription):
                try:
                    self._authorized_subscription(sid)
                except SocketIOTelemetryError:
                    break
                self._server.emit(frame["event"], frame, to=sid, namespace=self.namespace)
        return count

    def _subscription(self, sid: str) -> str:
        subscription = self._subscriptions.get(str(sid))
        if not subscription:
            raise SocketIOTelemetryError("telemetry subscription is not active")
        return subscription

    def _authorized_subscription(self, sid: str) -> str:
        """Revalidate the server-side session before returning telemetry."""

        sid = str(sid)
        subscription = self._subscription(sid)
        try:
            facts = self._server.get_environ(sid, namespace=self.namespace)
            principal = (
                self._session_resolver(sid, dict(facts))
                if isinstance(facts, Mapping)
                else None
            )
        except Exception:
            # Missing session state and resolver failures both fail closed.
            principal = None
        if principal is None or not principal.may_stream:
            self.on_disconnect(sid)
            try:
                self._server.disconnect(sid, namespace=self.namespace)
            except Exception:
                # The subscription has already been closed; a concurrent
                # transport disconnect must not restore access or leak frames.
                pass
            raise SocketIOTelemetryError("telemetry authorization is no longer active")
        return subscription
