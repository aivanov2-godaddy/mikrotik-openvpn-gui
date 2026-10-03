"""Dependency-free, redacted gateway contract used by live telemetry.

The Socket.IO adapter authenticates the existing dashboard session and uses
this transport-neutral boundary for bounded replay and snapshot recovery. Only
versioned, redacted broker events are retained here.
"""

from __future__ import annotations

import copy
import threading
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
        monotonic_clock: Callable[[], float] = time.monotonic,
        max_replay: int = 256,
        max_clients: int = 128,
    ) -> None:
        self._broker = broker
        self._clock = clock
        self._monotonic_clock = monotonic_clock
        self._events: deque[tuple[dict[str, Any], float]] = deque(
            maxlen=max(1, int(max_replay))
        )
        self._clients: dict[str, TelemetrySubscription] = {}
        self._max_clients = max(1, int(max_clients))
        self._delivery_queue_ages: deque[float] = deque(maxlen=512)
        self._lock = threading.RLock()
        self._published_events = 0
        self._replayed_events = 0
        self._snapshot_recoveries = 0
        self._rejected_clients = 0

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

        with self._lock:
            try:
                self._authorize(principal)
            except TelemetryAuthorizationError:
                self._rejected_clients += 1
                raise
            if len(self._clients) >= self._max_clients:
                self._rejected_clients += 1
                raise TelemetrySubscriptionError("telemetry client limit reached")
            subscription_id = uuid.uuid4().hex
            self._clients[subscription_id] = TelemetrySubscription(
                subscription_id=subscription_id,
                created_at=int(self._clock()),
            )
            return subscription_id

    def close(self, subscription_id: str) -> bool:
        with self._lock:
            return self._clients.pop(subscription_id, None) is not None

    def publish(self, events: Iterable[TelemetryEvent]) -> int:
        """Append broker events after applying the gateway privacy boundary."""

        with self._lock:
            count = 0
            for event in events:
                self._events.append((self._frame(event), self._monotonic_clock()))
                count += 1
            self._published_events += count
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

        with self._lock:
            subscription = self._clients.get(subscription_id)
            if subscription is None:
                raise TelemetrySubscriptionError("telemetry subscription is not active")
            cursor = subscription.last_seen_sequence if after_sequence is None else int(after_sequence)
            frames = list(self._events)
            queued_frames = [frame for frame, _published_at in frames]
            # Broker sequence numbers are process-local. After a restart the
            # client can reconnect with a cursor from the previous process,
            # which may be ahead of this broker's current sequence. Treat
            # that as an epoch change and replace client state with a snapshot
            # instead of returning an empty replay forever.
            if cursor > self._broker.sequence or (
                queued_frames and cursor < queued_frames[0]["sequence"] - 1
            ):
                result = [(self._snapshot_frame(), self._monotonic_clock())]
                self._snapshot_recoveries += 1
            else:
                result = [item for item in frames if item[0]["sequence"] > cursor]
                self._replayed_events += len(result)
            if result:
                subscription.last_seen_sequence = max(
                    frame["sequence"] for frame, _published_at in result
                )
                observed_at = self._monotonic_clock()
                self._delivery_queue_ages.extend(
                    max(0.0, observed_at - published_at)
                    for _frame, published_at in result
                )
            return copy.deepcopy([frame for frame, _published_at in result])

    def metrics(self) -> dict[str, int | float]:
        """Return bounded, aggregate delivery metrics without client/event IDs."""

        with self._lock:
            ages = sorted(self._delivery_queue_ages)
            p95_index = max(0, (len(ages) * 95 + 99) // 100 - 1)
            return {
                "active_clients": len(self._clients),
                "buffered_events": len(self._events),
                "published_events": self._published_events,
                "replayed_events": self._replayed_events,
                "snapshot_recoveries": self._snapshot_recoveries,
                "rejected_clients": self._rejected_clients,
                "delivery_observations": len(self._delivery_queue_ages),
                "delivery_queue_age_seconds": self._delivery_queue_ages[-1]
                if self._delivery_queue_ages
                else -1.0,
                "delivery_queue_age_p95_seconds": ages[p95_index] if ages else -1.0,
            }

    @property
    def client_count(self) -> int:
        with self._lock:
            return len(self._clients)
