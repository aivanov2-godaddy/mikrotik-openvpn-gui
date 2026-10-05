"""Minimal Engine.IO v4 polling bridge for the dashboard's Socket.IO client.

The project intentionally keeps its existing threaded HTTP server.  This
bridge implements the small Socket.IO polling surface needed by the dashboard
without adding a second listener or a WebSocket proxy.  The official client
    can upgrade to WebSocket when the front proxy supports it; polling remains a
    correct, authenticated transport and uses the same event contract.
"""

from __future__ import annotations

import json
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from telemetry_gateway import TelemetryGatewayContract, TelemetrySubscriptionError


@dataclass(slots=True)
class PollingClient:
    sid: str
    session_id: str
    last_activity: float
    subscription: str | None = None
    namespace_connected: bool = False
    pending: list[str] = field(default_factory=list)


class SocketIOPollingBridge:
    """Authenticate and service the Engine.IO polling handshake."""

    protocol_version = 4

    def __init__(
        self,
        gateway: TelemetryGatewayContract,
        principal_resolver: Any,
        *,
        idle_timeout_seconds: float = 45.0,
        clock: Any = time.monotonic,
    ) -> None:
        self.gateway = gateway
        self.principal_resolver = principal_resolver
        self.idle_timeout_seconds = max(0.0, float(idle_timeout_seconds))
        self.clock = clock
        self._clients: dict[str, PollingClient] = {}
        self._lock = threading.RLock()
        self._state_changed = threading.Condition(self._lock)

    def handshake(self, session_id: str) -> tuple[str, str] | None:
        principal = self.principal_resolver(session_id)
        if principal is None or not principal.may_stream:
            return None
        sid = secrets.token_urlsafe(18)
        with self._lock:
            now = self.clock()
            self._expire_idle_locked(now)
            self._clients[sid] = PollingClient(sid, session_id, now)
        packet = "0" + json.dumps(
            {
                "sid": sid,
                "upgrades": [],
                "pingInterval": 25000,
                "pingTimeout": 20000,
                "maxPayload": 1_000_000,
            },
            separators=(",", ":"),
        )
        return sid, packet

    def post(self, sid: str, session_id: str, body: bytes) -> bool:
        principal = self.principal_resolver(session_id)
        if principal is None or not principal.may_stream:
            self._close_if_owned(sid, session_id)
            return False
        with self._state_changed:
            self._expire_idle_locked(self.clock())
            client = self._clients.get(sid)
            if client is None:
                return False
            if not secrets.compare_digest(client.session_id, session_id):
                return False
            client.last_activity = self.clock()
            packets = body.decode("utf-8", "replace").split("\x1e")
            for packet in packets:
                if packet.startswith("40"):
                    if not client.namespace_connected or not client.subscription:
                        try:
                            client.subscription = self.gateway.open(principal)
                        except TelemetrySubscriptionError:
                            return False
                        client.namespace_connected = True
                        client.pending.append("40/telemetry,")
                    self._state_changed.notify_all()
                elif packet.startswith("42") and client.namespace_connected:
                    # The dashboard's subscribe request is advisory.  The
                    # gateway cursor is authoritative and is advanced by poll.
                    continue
                elif packet == "3" or packet.startswith("3/"):
                    continue
                elif packet.startswith("1"):
                    self._close_locked(sid)
        return True

    def poll(self, sid: str, session_id: str) -> str | None:
        principal = self.principal_resolver(session_id)
        if principal is None or not principal.may_stream:
            self._close_if_owned(sid, session_id)
            return None
        with self._state_changed:
            self._expire_idle_locked(self.clock())
            client = self._clients.get(sid)
            if client is None:
                return None
            if not secrets.compare_digest(client.session_id, session_id):
                return None
            client.last_activity = self.clock()
            # The Socket.IO client starts its first poll as soon as the
            # Engine.IO handshake completes, in parallel with the namespace
            # connect POST.  Do not answer that race with an Engine.IO ping:
            # some clients process the ping before the namespace-open packet
            # and close the connection.  Wait briefly for the POST instead.
            if not client.namespace_connected:
                self._state_changed.wait(timeout=1.0)
                client = self._clients.get(sid)
                if client is None:
                    return None
            if client.pending:
                return "\x1e".join(client.pending.pop(0) for _ in range(len(client.pending)))
            if not client.namespace_connected or not client.subscription:
                return "2"
            frames = self.gateway.poll(client.subscription)
            packets = []
            for frame in frames:
                current_principal = self.principal_resolver(session_id)
                if current_principal is None or not current_principal.may_stream:
                    self._close_locked(sid)
                    break
                packets.append(
                    "42/telemetry," + json.dumps([frame["event"], frame], separators=(",", ":"))
                )
            return "\x1e".join(packets) if packets else "2"

    def close(self, sid: str) -> None:
        with self._lock:
            self._close_locked(sid)

    def _close_if_owned(self, sid: str, session_id: str) -> None:
        """Reap an invalid client's own SID, never a SID supplied by another session."""
        with self._lock:
            client = self._clients.get(sid)
            if client and secrets.compare_digest(client.session_id, session_id):
                self._close_locked(sid)

    def _close_locked(self, sid: str) -> None:
        client = self._clients.pop(sid, None)
        if client and client.subscription:
            self.gateway.close(client.subscription)
        self._state_changed.notify_all()

    def _expire_idle_locked(self, now: float) -> None:
        expired = [
            sid
            for sid, client in self._clients.items()
            if now - client.last_activity >= self.idle_timeout_seconds
        ]
        for sid in expired:
            self._close_locked(sid)
