"""Minimal Engine.IO v4 polling bridge for the dashboard's Socket.IO client.

The project intentionally keeps its existing threaded HTTP server.  This
bridge implements the small Socket.IO polling surface needed by the dashboard
without adding a second listener or a WebSocket proxy.  The official client
can upgrade to WebSocket when the front proxy supports it; polling remains a
correct, authenticated fallback and uses the same event contract.
"""

from __future__ import annotations

import json
import secrets
import threading
from dataclasses import dataclass, field
from typing import Any

from telemetry_gateway import TelemetryGatewayContract, TelemetrySubscriptionError


@dataclass(slots=True)
class PollingClient:
    sid: str
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
    ) -> None:
        self.gateway = gateway
        self.principal_resolver = principal_resolver
        self._clients: dict[str, PollingClient] = {}
        self._lock = threading.RLock()

    def handshake(self, session_id: str) -> tuple[str, str] | None:
        principal = self.principal_resolver(session_id)
        if principal is None or not principal.may_stream:
            return None
        sid = secrets.token_urlsafe(18)
        with self._lock:
            self._clients[sid] = PollingClient(sid)
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
            return False
        with self._lock:
            client = self._clients.get(sid)
            if client is None:
                return False
            packets = body.decode("utf-8", "replace").split("\x1e")
            for packet in packets:
                if packet.startswith("40"):
                    try:
                        client.subscription = self.gateway.open(principal)
                    except TelemetrySubscriptionError:
                        return False
                    client.namespace_connected = True
                    client.pending.append("40/telemetry,")
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
            self.close(sid)
            return None
        with self._lock:
            client = self._clients.get(sid)
            if client is None:
                return None
            if client.pending:
                return "\x1e".join(client.pending.pop(0) for _ in range(len(client.pending)))
            if not client.namespace_connected or not client.subscription:
                return "2"
            frames = self.gateway.poll(client.subscription)
            packets = [
                "42/telemetry," + json.dumps([frame["event"], frame], separators=(",", ":"))
                for frame in frames
            ]
            return "\x1e".join(packets) if packets else "2"

    def close(self, sid: str) -> None:
        with self._lock:
            self._close_locked(sid)

    def _close_locked(self, sid: str) -> None:
        client = self._clients.pop(sid, None)
        if client and client.subscription:
            self.gateway.close(client.subscription)
