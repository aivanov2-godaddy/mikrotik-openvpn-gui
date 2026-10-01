"""Dependency-free gateway contract for the live telemetry migration.

This module is deliberately not a Socket.IO server.  It defines the boundary
that a future same-origin Socket.IO adapter must implement: authenticate the
existing dashboard session, keep a bounded replay window, and publish only
versioned, redacted broker events.  The REST/SSE runtime does not import or
enable this contract yet.
"""

from __future__ import annotations

import copy
import time
import uuid
from collections import deque
from dataclasses import dataclass
from typing import Any, Callable, Iterable

from security import has_capability, normalize_role
from telemetry_broker import TelemetryBroker, TelemetryEvent


PROTOCOL_VERSION = 1
SUPPORTED_EVENTS = frozenset(
    {
        "telemetry.snapshot",
        "vpn.session.connected",
        "vpn.session.updated",
        "vpn.session.disconnected",
        "vpn.interface.counters",
        "telemetry.counter_reset",
        "router.capacity.updated",
        "router.health.updated",
        "telemetry.reconciled",
    }
)
_SESSION_FIELDS = frozenset(
    {
        "id",
        "name",
        "vpn_address",
        "source_address",
        "uptime",
        "encoding",
        "service",
        "rx_bytes",
        "tx_bytes",
        "rx_packets",
        "tx_packets",
    }
)


class TelemetryGatewayError(RuntimeError):
    """Base error for the future delivery adapter."""


class TelemetryAuthorizationError(TelemetryGatewayError):
    """Raised when a dashboard session cannot receive live router events."""


class TelemetrySubscriptionError(TelemetryGatewayError):
    """Raised when a subscription is missing or the client limit is reached."""


@dataclass(frozen=True, slots=True)
class TelemetryPrincipal:
    """The non-secret authorization facts needed by a telemetry gateway.

    A principal intentionally contains no password, cookie, token, or session
    object.  The HTTP/Socket.IO adapter should derive it from the current
    dashboard session and re-check the session before opening a subscription.
    """

    authenticated: bool
    auth_method: str = ""
    role: str = "read_only"
    capabilities: frozenset[str] | None = None

    @classmethod
    def from_session(cls, session: Any | None) -> "TelemetryPrincipal":
        if session is None:
            return cls(False)
        raw_capabilities = getattr(session, "capabilities", None)
        capabilities = (
            frozenset(str(item) for item in raw_capabilities)
            if raw_capabilities is not None
            else None
        )
        return cls(
            authenticated=True,
            auth_method=str(getattr(session, "auth_method", "")),
            role=normalize_role(str(getattr(session, "role", "read_only"))),
            capabilities=capabilities,
        )

    @property
    def can_read_sessions(self) -> bool:
        if self.capabilities is not None:
            return "sessions.read" in self.capabilities or "*" in self.capabilities
        return has_capability(self.role, "sessions.read")

    @property
    def may_stream(self) -> bool:
        return self.authenticated and self.auth_method == "routeros" and self.can_read_sessions


@dataclass(slots=True)
class TelemetrySubscription:
    subscription_id: str
    created_at: int
    last_seen_sequence: int = 0


class TelemetryGatewayContract:
    """Bounded, redacted event queue for a future Socket.IO transport.

    It is safe to exercise in tests and can be used by a future adapter without
    changing the REST mutation path.  It stores only event frames and opaque
    subscription identifiers; it never stores RouterOS credentials or session
    objects.  ``poll`` is intentionally transport-neutral so the first gateway
    implementation can choose Socket.IO without changing event semantics.
    """

    def __init__(
        self,
        broker: TelemetryBroker,
        *,
        clock: Callable[[], float] = time.time,
        max_replay: int = 256,
        max_clients: int = 128,
    ) -> None:
        self._broker = broker
        self._clock = clock
        self._events: deque[dict[str, Any]] = deque(maxlen=max(1, int(max_replay)))
        self._clients: dict[str, TelemetrySubscription] = {}
        self._max_clients = max(1, int(max_clients))

    @staticmethod
    def _authorize(principal: TelemetryPrincipal) -> None:
        if not principal.may_stream:
            raise TelemetryAuthorizationError(
                "an authenticated RouterOS session with sessions.read is required"
            )

    @staticmethod
    def _redact_session(value: Any) -> dict[str, Any]:
        if not isinstance(value, dict):
            return {}
        return {key: copy.deepcopy(value[key]) for key in _SESSION_FIELDS if key in value}

    @classmethod
    def _frame(cls, event: TelemetryEvent) -> dict[str, Any]:
        if event.name not in SUPPORTED_EVENTS:
            raise TelemetryGatewayError(f"unsupported telemetry event: {event.name}")
        payload = event.payload if isinstance(event.payload, dict) else {}
        if event.name == "telemetry.snapshot":
            safe_payload = {
                "sessions": [cls._redact_session(item) for item in payload.get("sessions", [])]
            }
        elif event.name == "vpn.interface.counters":
            safe_payload = {
                key: copy.deepcopy(value)
                for key, value in payload.items()
                if key in {
                    "id", "name", "rx_bytes", "tx_bytes", "rx_packets", "tx_packets",
                    "rx_bytes_per_second", "tx_bytes_per_second",
                    "rx_packets_per_second", "tx_packets_per_second",
                }
            }
        elif event.name == "telemetry.counter_reset":
            safe_payload = {
                key: copy.deepcopy(value)
                for key, value in payload.items()
                if key in {"scope", "id", "name", "fields"}
            }
        elif event.name in {"router.capacity.updated", "router.health.updated", "telemetry.reconciled"}:
            safe_payload = {
                key: copy.deepcopy(value)
                for key, value in payload.items()
                if key in {"cpu_percent", "memory_percent", "storage_percent", "status", "age_seconds"}
            }
        else:
            safe_payload = {
                key: copy.deepcopy(value)
                for key, value in payload.items()
                if key in _SESSION_FIELDS
            }
        return {
            "protocol_version": PROTOCOL_VERSION,
            "event": event.name,
            "sequence": int(event.sequence),
            "router_timestamp": int(event.router_timestamp),
            "payload": safe_payload,
        }

    def open(self, principal: TelemetryPrincipal) -> str:
        """Authorize and create an opaque subscription identifier."""

        self._authorize(principal)
        if len(self._clients) >= self._max_clients:
            raise TelemetrySubscriptionError("telemetry client limit reached")
        subscription_id = uuid.uuid4().hex
        self._clients[subscription_id] = TelemetrySubscription(
            subscription_id=subscription_id,
            created_at=int(self._clock()),
        )
        return subscription_id

    def close(self, subscription_id: str) -> bool:
        return self._clients.pop(subscription_id, None) is not None

    def publish(self, events: Iterable[TelemetryEvent]) -> int:
        """Append broker events after applying the gateway privacy boundary."""

        count = 0
        for event in events:
            self._events.append(self._frame(event))
            count += 1
        return count

    def _snapshot_frame(self) -> dict[str, Any]:
        sequence = self._broker.sequence
        return self._frame(
            TelemetryEvent(
                "telemetry.snapshot",
                sequence,
                int(self._clock()),
                {"sessions": self._broker.snapshot()},
            )
        )

    def poll(self, subscription_id: str, *, after_sequence: int | None = None) -> list[dict[str, Any]]:
        """Return new frames, recovering with a snapshot when replay is stale."""

        subscription = self._clients.get(subscription_id)
        if subscription is None:
            raise TelemetrySubscriptionError("telemetry subscription is not active")
        cursor = subscription.last_seen_sequence if after_sequence is None else int(after_sequence)
        frames = list(self._events)
        if frames and cursor < frames[0]["sequence"] - 1:
            result = [self._snapshot_frame()]
        else:
            result = [frame for frame in frames if frame["sequence"] > cursor]
        if result:
            subscription.last_seen_sequence = max(frame["sequence"] for frame in result)
        return copy.deepcopy(result)

    @property
    def client_count(self) -> int:
        return len(self._clients)
