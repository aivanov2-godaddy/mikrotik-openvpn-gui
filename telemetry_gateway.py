"""Dependency-free, redacted gateway contract used by live telemetry.

The Socket.IO adapter authenticates the existing dashboard session and uses
this transport-neutral boundary for bounded replay and snapshot recovery. Only
versioned, redacted broker events are retained here.
"""

from __future__ import annotations

import copy
import json
import math
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass
from typing import Any, Callable, Iterable

from security import has_capability, normalize_role
from telemetry_broker import (
    MAX_CACHED_INTERFACES,
    MAX_CACHED_SESSIONS,
    MAX_TELEMETRY_TEXT_BYTES,
    TelemetryBroker,
    TelemetryEvent,
)


PROTOCOL_VERSION = 1
MAX_FRAME_BYTES = 8 << 20
MAX_REPLAY_BYTES = 8 << 20
MAX_REPLAY_EVENTS = 256
MAX_COUNTER_VALUE = (1 << 64) - 1
MAX_FRAME_NUMBER = (1 << 63) - 1
MAX_RATE_VALUE = 1e15
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
        "counter_complete",
    }
)
_INTERFACE_COUNTER_FIELDS = frozenset(
    {
        "id",
        "name",
        "rx_bytes",
        "tx_bytes",
        "rx_packets",
        "tx_packets",
        "rx_bytes_per_second",
        "tx_bytes_per_second",
        "rx_packets_per_second",
        "tx_packets_per_second",
    }
)
_SESSION_TEXT_FIELDS = frozenset(
    {"id", "name", "vpn_address", "source_address", "uptime", "encoding", "service"}
)
_SESSION_COUNTER_FIELDS = frozenset({"rx_bytes", "tx_bytes", "rx_packets", "tx_packets"})
_RESET_FIELDS = _SESSION_COUNTER_FIELDS
_ROUTER_METRIC_FIELDS = frozenset(
    {"cpu_percent", "memory_percent", "storage_percent", "status", "age_seconds"}
)


class TelemetryGatewayError(RuntimeError):
    """Base error for the future delivery adapter."""


class TelemetryAuthorizationError(TelemetryGatewayError):
    """Raised when a dashboard session cannot receive live router events."""


class TelemetrySubscriptionError(TelemetryGatewayError):
    """Raised when a subscription is missing or the client limit is reached."""


def _bounded_text(value: Any) -> str:
    if not isinstance(value, str):
        raise TelemetryGatewayError("telemetry text field has an invalid type")
    if len(value) > MAX_TELEMETRY_TEXT_BYTES:
        raise TelemetryGatewayError("telemetry text field exceeds configured safety limit")
    try:
        encoded_length = len(value.encode("utf-8"))
    except UnicodeEncodeError as error:
        raise TelemetryGatewayError("telemetry text field is not valid UTF-8") from error
    if encoded_length > MAX_TELEMETRY_TEXT_BYTES:
        raise TelemetryGatewayError("telemetry text field exceeds configured safety limit")
    return value


def _bounded_counter(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= MAX_COUNTER_VALUE:
        raise TelemetryGatewayError("telemetry counter has an invalid value")
    return value


def _bounded_number(value: Any, *, maximum: float = MAX_RATE_VALUE) -> int | float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TelemetryGatewayError("telemetry number has an invalid type")
    if value < 0 or value > maximum:
        raise TelemetryGatewayError("telemetry number exceeds configured safety limit")
    if isinstance(value, float) and not math.isfinite(value):
        raise TelemetryGatewayError("telemetry number exceeds configured safety limit")
    return value


def _bounded_sequence(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= MAX_FRAME_NUMBER:
        raise TelemetryGatewayError("telemetry frame sequence is invalid")
    return value


def redact_session(value: Any) -> dict[str, Any]:
    """Project a RouterOS session row onto the public live-telemetry schema."""
    if not isinstance(value, dict):
        return {}
    result: dict[str, Any] = {}
    for key in _SESSION_FIELDS:
        if key not in value:
            continue
        field_value = value[key]
        if key in _SESSION_TEXT_FIELDS:
            result[key] = _bounded_text(field_value)
        elif key in _SESSION_COUNTER_FIELDS:
            result[key] = _bounded_counter(field_value)
        elif key == "counter_complete":
            if not isinstance(field_value, bool):
                raise TelemetryGatewayError("telemetry completion flag has an invalid type")
            result[key] = field_value
    return result


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
        capabilities = frozenset(str(item) for item in raw_capabilities) if raw_capabilities is not None else None
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
    client_cursor_seen: bool = False


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
        max_frame_bytes: int = MAX_FRAME_BYTES,
        max_replay_bytes: int = MAX_REPLAY_BYTES,
    ) -> None:
        self._broker = broker
        self._clock = clock
        self._monotonic_clock = monotonic_clock
        self._max_replay = min(MAX_REPLAY_EVENTS, max(1, int(max_replay)))
        self._max_replay_bytes = min(MAX_REPLAY_BYTES, max(1, int(max_replay_bytes)))
        self._max_frame_bytes = min(
            MAX_FRAME_BYTES,
            self._max_replay_bytes,
            max(1, int(max_frame_bytes)),
        )
        self._events: deque[tuple[dict[str, Any], float, int]] = deque()
        self._retained_frame_bytes = 0
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
            raise TelemetryAuthorizationError("an authenticated RouterOS session with sessions.read is required")

    @staticmethod
    def _redact_session(value: Any) -> dict[str, Any]:
        return redact_session(value)

    @staticmethod
    def _redact_interface(value: Any) -> dict[str, Any]:
        if not isinstance(value, dict):
            return {}
        result: dict[str, Any] = {}
        for key in _INTERFACE_COUNTER_FIELDS:
            if key not in value:
                continue
            field_value = value[key]
            if key in {"id", "name"}:
                result[key] = _bounded_text(field_value)
            elif key in _SESSION_COUNTER_FIELDS:
                result[key] = _bounded_counter(field_value)
            else:
                result[key] = _bounded_number(field_value)
        return result

    @classmethod
    def _build_frame(cls, event: TelemetryEvent) -> tuple[dict[str, Any], int]:
        if not isinstance(event.name, str) or event.name not in SUPPORTED_EVENTS:
            raise TelemetryGatewayError("unsupported telemetry event")
        payload = event.payload if isinstance(event.payload, dict) else {}
        if event.name == "telemetry.snapshot":
            sessions = payload.get("sessions", [])
            if not isinstance(sessions, list) or len(sessions) > MAX_CACHED_SESSIONS:
                raise TelemetryGatewayError("telemetry snapshot exceeds configured session limit")
            safe_payload = {"sessions": [cls._redact_session(item) for item in sessions]}
            if "interfaces" in payload:
                interfaces = payload.get("interfaces")
                if not isinstance(interfaces, list) or len(interfaces) > MAX_CACHED_INTERFACES:
                    raise TelemetryGatewayError("telemetry snapshot exceeds configured interface limit")
                safe_payload["interfaces"] = [cls._redact_interface(item) for item in interfaces]
        elif event.name == "vpn.interface.counters":
            interface_payload = payload.get("interface", payload)
            if not isinstance(interface_payload, dict):
                interface_payload = {}
            safe_payload = cls._redact_interface(interface_payload)
        elif event.name == "telemetry.counter_reset":
            safe_payload = {}
            if "scope" in payload:
                scope = _bounded_text(payload["scope"])
                if scope not in {"session", "interface"}:
                    raise TelemetryGatewayError("telemetry reset scope is invalid")
                safe_payload["scope"] = scope
            for key in ("id", "name"):
                if key in payload:
                    safe_payload[key] = _bounded_text(payload[key])
            if "fields" in payload:
                fields = payload["fields"]
                if (
                    not isinstance(fields, list)
                    or len(fields) > len(_RESET_FIELDS)
                    or any(not isinstance(field, str) or field not in _RESET_FIELDS for field in fields)
                ):
                    raise TelemetryGatewayError("telemetry reset fields are invalid")
                safe_payload["fields"] = list(fields)
        elif event.name in {"router.capacity.updated", "router.health.updated", "telemetry.reconciled"}:
            safe_payload = {}
            for key in _ROUTER_METRIC_FIELDS:
                if key not in payload:
                    continue
                value = payload[key]
                if key == "status":
                    safe_payload[key] = _bounded_text(value)
                else:
                    maximum = 100 if key.endswith("_percent") else MAX_RATE_VALUE
                    safe_payload[key] = _bounded_number(value, maximum=maximum)
        else:
            safe_payload = cls._redact_session(payload)
        frame = {
            "protocol_version": PROTOCOL_VERSION,
            "event": event.name,
            "sequence": _bounded_sequence(event.sequence),
            "router_timestamp": _bounded_sequence(event.router_timestamp),
            "payload": safe_payload,
        }
        try:
            frame_size = len(json.dumps(frame, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8"))
        except (TypeError, ValueError, OverflowError) as error:
            raise TelemetryGatewayError("telemetry frame is not safely serializable") from error
        if frame_size > MAX_FRAME_BYTES:
            raise TelemetryGatewayError("telemetry frame exceeds configured byte limit")
        return frame, frame_size

    @classmethod
    def _frame(cls, event: TelemetryEvent) -> dict[str, Any]:
        return cls._build_frame(event)[0]

    def _bounded_frame(self, event: TelemetryEvent) -> tuple[dict[str, Any], int]:
        frame, frame_size = self._build_frame(event)
        if frame_size > self._max_frame_bytes:
            raise TelemetryGatewayError("telemetry frame exceeds configured byte limit")
        return frame, frame_size

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
                frame, frame_size = self._bounded_frame(event)
                if frame_size > self._max_replay_bytes:
                    raise TelemetryGatewayError("telemetry frame exceeds configured replay byte budget")
                while self._events and (
                    len(self._events) >= self._max_replay
                    or self._retained_frame_bytes + frame_size > self._max_replay_bytes
                ):
                    _old_frame, _published_at, old_size = self._events.popleft()
                    self._retained_frame_bytes -= old_size
                self._events.append((frame, self._monotonic_clock(), frame_size))
                self._retained_frame_bytes += frame_size
                count += 1
            self._published_events += count
            return count

    def _snapshot_frame_entry(self) -> tuple[dict[str, Any], float, int]:
        snapshot = self._broker.recovery_snapshot()
        frame, frame_size = self._bounded_frame(
            TelemetryEvent(
                "telemetry.snapshot",
                int(snapshot["sequence"]),
                int(self._clock()),
                {"sessions": snapshot["sessions"], "interfaces": snapshot["interfaces"]},
            )
        )
        return frame, self._monotonic_clock(), frame_size

    def _snapshot_frame(self) -> dict[str, Any]:
        """Return a bounded recovery snapshot frame."""
        return self._snapshot_frame_entry()[0]

    def poll(self, subscription_id: str, *, after_sequence: int | None = None) -> list[dict[str, Any]]:
        """Return new frames, recovering when replay is stale or epoch-ambiguous.

        Sequence numbers do not identify a broker process. The first explicit
        client cursor therefore receives a current snapshot; later polls use
        only the monotonic server-side cursor for bounded replay.
        """

        with self._lock:
            subscription = self._clients.get(subscription_id)
            if subscription is None:
                raise TelemetrySubscriptionError("telemetry subscription is not active")
            # Client cursors are not epoch-bound and must never advance or
            # rewind a cursor after the initial recovery snapshot. The server
            # tracks exactly what it has delivered to this subscription.
            cursor = subscription.last_seen_sequence
            frames = list(self._events)
            queued_frames = [frame for frame, _published_at, _size in frames]
            # The browser cursor contains no broker epoch. Its first resume
            # cursor can belong to a previous process whose sequence numbers
            # overlap this broker's, even if the background pump already made
            # an empty poll. Replace client state with a snapshot; subsequent
            # polls use the monotonic server-tracked sequence for bounded replay.
            unbound_client_cursor = after_sequence is not None and not subscription.client_cursor_seen
            if (
                unbound_client_cursor
                or cursor < 0
                or cursor > self._broker.sequence
                or (queued_frames and cursor < min(frame["sequence"] for frame in queued_frames) - 1)
            ):
                result = [self._snapshot_frame_entry()]
                self._snapshot_recoveries += 1
            else:
                result = [item for item in frames if item[0]["sequence"] > cursor]
                # Multiple event types may legitimately share one broker
                # sequence. Compare distinct sequence numbers so that a
                # dropped event batch (including a hole inside the retained
                # replay window) cannot silently advance a client past state
                # it never received. Sorting also makes an out-of-order
                # adapter publish recover deterministically.
                available = sorted({frame["sequence"] for frame, _published_at, _size in result})
                complete = (
                    len(available) == self._broker.sequence - cursor
                    and (not available or available[0] == cursor + 1)
                    and (not available or available[-1] == self._broker.sequence)
                    and all(following == previous + 1 for previous, following in zip(available, available[1:]))
                )
                if not complete:
                    result = [self._snapshot_frame_entry()]
                    self._snapshot_recoveries += 1
                else:
                    result.sort(key=lambda item: item[0]["sequence"])
                    self._replayed_events += len(result)
            if result:
                subscription.last_seen_sequence = max(frame["sequence"] for frame, _published_at, _size in result)
                observed_at = self._monotonic_clock()
                self._delivery_queue_ages.extend(
                    max(0.0, observed_at - published_at) for _frame, published_at, _size in result
                )
            if after_sequence is not None:
                subscription.client_cursor_seen = True
            return copy.deepcopy([frame for frame, _published_at, _size in result])

    def metrics(self) -> dict[str, int | float]:
        """Return bounded, aggregate delivery metrics without client/event IDs."""

        with self._lock:
            ages = sorted(self._delivery_queue_ages)
            p95_index = max(0, (len(ages) * 95 + 99) // 100 - 1)
            return {
                "active_clients": len(self._clients),
                "buffered_events": len(self._events),
                "buffered_frame_bytes": self._retained_frame_bytes,
                "buffered_frame_bytes_limit": self._max_replay_bytes,
                "published_events": self._published_events,
                "replayed_events": self._replayed_events,
                "snapshot_recoveries": self._snapshot_recoveries,
                "rejected_clients": self._rejected_clients,
                "delivery_observations": len(self._delivery_queue_ages),
                "delivery_queue_age_seconds": self._delivery_queue_ages[-1] if self._delivery_queue_ages else -1.0,
                "delivery_queue_age_p95_seconds": ages[p95_index] if ages else -1.0,
            }

    @property
    def client_count(self) -> int:
        with self._lock:
            return len(self._clients)
