"""Optional Socket.IO delivery adapter for the live telemetry contract.

The application still serves REST/SSE by default.  This module contains the
small adapter boundary needed by a future Socket.IO server (for example,
``python-socketio``) without importing that optional dependency or changing
the RouterOS mutation path.  A caller must explicitly attach a Socket.IO
server and provide a session resolver; unauthenticated or non-RouterOS
sessions are rejected before a subscription is created.
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

        if not callable(getattr(server, "on", None)) or not callable(getattr(server, "emit", None)):
            raise TypeError("Socket.IO server must provide on() and emit()")
        self._server = server
        server.on("connect", self.on_connect, namespace=self.namespace)
        server.on("disconnect", self.on_disconnect, namespace=self.namespace)
        server.on("telemetry.subscribe", self.on_subscribe, namespace=self.namespace)
        server.on("telemetry.poll", self.on_poll, namespace=self.namespace)

    def on_connect(self, sid: str, environ: Mapping[str, Any] | None = None, auth: Any = None) -> bool:
        """Authenticate a dashboard session before opening a subscription."""

        facts = dict(environ or {})
        if isinstance(auth, Mapping):
            facts.update({str(key): value for key, value in auth.items()})
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

        subscription = self._subscription(sid)
        after = data.get("after_sequence") if isinstance(data, Mapping) else None
        frames = self._gateway.poll(subscription, after_sequence=after)
        return {"protocol_version": 1, "frames": frames}

    def on_poll(self, sid: str, data: Any = None) -> dict[str, Any]:
        """Return replay frames and optionally emit them to the same client."""

        response = self.on_subscribe(sid, data)
        if self._server is not None and response["frames"]:
            for frame in response["frames"]:
                self._server.emit(frame["event"], frame, to=str(sid), namespace=self.namespace)
        return response

    def publish(self, events: list[TelemetryEvent]) -> int:
        """Publish redacted broker events to connected Socket.IO clients."""

        count = self._gateway.publish(events)
        if self._server is None:
            return count
        for sid, subscription in list(self._subscriptions.items()):
            for frame in self._gateway.poll(subscription):
                self._server.emit(frame["event"], frame, to=sid, namespace=self.namespace)
        return count

    def _subscription(self, sid: str) -> str:
        subscription = self._subscriptions.get(str(sid))
        if not subscription:
            raise SocketIOTelemetryError("telemetry subscription is not active")
        return subscription
