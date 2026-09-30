"""Read-only, redacted telemetry state for the Binary API migration.

The broker deliberately has no RouterOS mutation methods and is not wired into
the runtime yet.  It turns Binary API ``!re`` records (or a REST reconciliation
snapshot) into a small, versionable event model for the future Socket.IO
gateway.  Only fields already safe to display in the dashboard are retained.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Mapping

from routeros_binary import RouterOSReply


_MISSING = object()


@dataclass(frozen=True, slots=True)
class TelemetryEvent:
    """A redacted event ready for a browser delivery adapter."""

    name: str
    sequence: int
    router_timestamp: int
    payload: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {
            "event": self.name,
            "sequence": self.sequence,
            "router_timestamp": self.router_timestamp,
            "payload": dict(self.payload),
        }


def _text(record: Mapping[str, Any], *keys: str) -> str:
    for key in keys:
        value = record.get(key, _MISSING)
        if value is not _MISSING and value is not None:
            return str(value).strip()
    return ""


def _counter(record: Mapping[str, Any], *keys: str) -> int:
    value = _text(record, *keys)
    if not value:
        return 0
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def normalize_session(record: Mapping[str, Any]) -> dict[str, Any] | None:
    """Return only dashboard-safe fields from one RouterOS session record."""

    session_id = _text(record, ".id", "id")
    username = _text(record, "name", "user", "username")
    vpn_address = _text(record, "address", "remote-address", "vpn-address")
    source_address = _text(record, "caller-id", "source-address", "source")
    if not session_id:
        # Reconciliation sources occasionally omit ``.id``.  A deterministic
        # fallback still lets the broker detect updates without persisting any
        # credential or profile material.
        session_id = "|".join((username, vpn_address, source_address))
    if not session_id or not username:
        return None
    return {
        "id": session_id,
        "name": username,
        "vpn_address": vpn_address,
        "source_address": source_address,
        "uptime": _text(record, "uptime"),
        "encoding": _text(record, "encoding", "encryption"),
        "service": _text(record, "service"),
        "rx_bytes": _counter(record, "rx-byte", "rx_bytes"),
        "tx_bytes": _counter(record, "tx-byte", "tx_bytes"),
        "rx_packets": _counter(record, "rx-packet", "rx_packets"),
        "tx_packets": _counter(record, "tx-packet", "tx_packets"),
    }


def normalize_interface(record: Mapping[str, Any]) -> dict[str, Any] | None:
    """Return the small, dashboard-safe interface counter record.

    RouterOS exposes many interface fields (including comments and dynamic
    metadata).  Only the stable identity and monotonic counters cross this
    boundary.  The function accepts both Binary API names and the equivalent
    REST-style names so reconciliation sources can be compared directly.
    """

    interface_id = _text(record, ".id", "id")
    name = _text(record, "name", "interface")
    if not interface_id or not name:
        return None
    return {
        "id": interface_id,
        "name": name,
        "rx_bytes": _counter(record, "rx-byte", "rx_bytes"),
        "tx_bytes": _counter(record, "tx-byte", "tx_bytes"),
        "rx_packets": _counter(record, "rx-packet", "rx_packets"),
        "tx_packets": _counter(record, "tx-packet", "tx_packets"),
    }


class TelemetryBroker:
    """Maintain a redacted, in-memory RouterOS session cache.

    The broker is intentionally transport-agnostic.  Binary API ``listen``
    records are accepted through :meth:`apply`; periodic REST/Binary snapshots
    are accepted through :meth:`reconcile`.  It never writes to RouterOS or
    SQLite, and all returned payloads are copies safe for a delivery layer.
    """

    def __init__(
        self,
        *,
        clock: Callable[[], float] = time.time,
        max_sessions: int = 4096,
        max_interfaces: int = 1024,
    ) -> None:
        self._clock = clock
        self._max_sessions = max(1, int(max_sessions))
        self._max_interfaces = max(1, int(max_interfaces))
        self._lock = threading.RLock()
        self._sessions: dict[str, dict[str, Any]] = {}
        self._interfaces: dict[str, dict[str, Any]] = {}
        self._sequence = 0
        self._counter_resets = 0
        self._interface_counter_resets = 0

    def _timestamp(self, now: int | None) -> int:
        return int(self._clock() if now is None else now)

    def _event(self, name: str, payload: dict[str, Any], now: int) -> TelemetryEvent:
        self._sequence += 1
        return TelemetryEvent(name, self._sequence, now, dict(payload))

    def _counter_reset_event(
        self,
        previous: Mapping[str, Any] | None,
        current: Mapping[str, Any],
        now: int,
    ) -> TelemetryEvent | None:
        if previous is None:
            return None
        fields = [
            field
            for field in ("rx_bytes", "tx_bytes", "rx_packets", "tx_packets")
            if int(current.get(field, 0) or 0) < int(previous.get(field, 0) or 0)
        ]
        if not fields:
            return None
        self._counter_resets += 1
        return self._event(
            "telemetry.counter_reset",
            {
                "id": str(current.get("id", "")),
                "name": str(current.get("name", "")),
                "fields": fields,
            },
            now,
        )

    def _interface_reset_event(
        self,
        previous: Mapping[str, Any] | None,
        current: Mapping[str, Any],
        now: int,
    ) -> TelemetryEvent | None:
        if previous is None:
            return None
        fields = [
            field
            for field in ("rx_bytes", "tx_bytes", "rx_packets", "tx_packets")
            if int(current.get(field, 0) or 0) < int(previous.get(field, 0) or 0)
        ]
        if not fields:
            return None
        self._interface_counter_resets += 1
        return self._event(
            "telemetry.counter_reset",
            {
                "scope": "interface",
                "id": str(current.get("id", "")),
                "name": str(current.get("name", "")),
                "fields": fields,
            },
            now,
        )

    @staticmethod
    def _payload(session: Mapping[str, Any]) -> dict[str, Any]:
        # This allow-list is the privacy boundary.  Do not add RouterOS record
        # passthrough or credentials here; the future Socket.IO gateway relies
        # on this method to keep event payloads redacted.
        return {
            "id": str(session.get("id", "")),
            "name": str(session.get("name", "")),
            "vpn_address": str(session.get("vpn_address", "")),
            "source_address": str(session.get("source_address", "")),
            "uptime": str(session.get("uptime", "")),
            "encoding": str(session.get("encoding", "")),
            "service": str(session.get("service", "")),
            "rx_bytes": int(session.get("rx_bytes", 0) or 0),
            "tx_bytes": int(session.get("tx_bytes", 0) or 0),
            "rx_packets": int(session.get("rx_packets", 0) or 0),
            "tx_packets": int(session.get("tx_packets", 0) or 0),
        }

    def apply(self, reply: RouterOSReply, *, now: int | None = None) -> list[TelemetryEvent]:
        """Apply one Binary API reply and return the corresponding events."""

        if reply.kind != "re":
            return []
        observed_at = self._timestamp(now)
        with self._lock:
            session_id = _text(reply.attributes, ".id", "id")
            if reply.dead:
                if not session_id or session_id not in self._sessions:
                    return []
                previous = self._sessions.pop(session_id)
                return [self._event("vpn.session.disconnected", self._payload(previous), observed_at)]

            session = normalize_session(reply.attributes)
            if session is None:
                return []
            session["observed_at"] = observed_at
            previous = self._sessions.get(str(session["id"]))
            self._sessions[str(session["id"])] = session
            if len(self._sessions) > self._max_sessions:
                oldest = min(self._sessions, key=lambda key: self._sessions[key].get("observed_at", 0))
                self._sessions.pop(oldest, None)
            event_name = "vpn.session.connected" if previous is None else "vpn.session.updated"
            events: list[TelemetryEvent] = []
            reset = self._counter_reset_event(previous, session, observed_at)
            if reset is not None:
                events.append(reset)
            events.append(self._event(event_name, self._payload(session), observed_at))
            return events

    def reconcile(
        self, records: Iterable[Mapping[str, Any]], *, now: int | None = None
    ) -> list[TelemetryEvent]:
        """Replace the cache from a safe snapshot and emit transition events."""

        observed_at = self._timestamp(now)
        incoming: dict[str, dict[str, Any]] = {}
        for record in records:
            session = normalize_session(record)
            if session is not None:
                session["observed_at"] = observed_at
                incoming[str(session["id"])] = session
        with self._lock:
            events: list[TelemetryEvent] = []
            for session_id, previous in self._sessions.items():
                if session_id not in incoming:
                    events.append(self._event("vpn.session.disconnected", self._payload(previous), observed_at))
            for session_id, session in incoming.items():
                event_name = "vpn.session.connected" if session_id not in self._sessions else "vpn.session.updated"
                reset = self._counter_reset_event(self._sessions.get(session_id), session, observed_at)
                if reset is not None:
                    events.append(reset)
                events.append(self._event(event_name, self._payload(session), observed_at))
            self._sessions = dict(list(incoming.items())[-self._max_sessions :])
            snapshot = [self._payload(item) for item in self._sessions.values()]
            events.append(self._event("telemetry.snapshot", {"sessions": snapshot}, observed_at))
            return events

    @staticmethod
    def _interface_payload(interface: Mapping[str, Any], *, elapsed: float | None = None) -> dict[str, Any]:
        """Build an allow-listed counter payload, optionally with safe rates."""

        payload: dict[str, Any] = {
            "id": str(interface.get("id", "")),
            "name": str(interface.get("name", "")),
            "rx_bytes": int(interface.get("rx_bytes", 0) or 0),
            "tx_bytes": int(interface.get("tx_bytes", 0) or 0),
            "rx_packets": int(interface.get("rx_packets", 0) or 0),
            "tx_packets": int(interface.get("tx_packets", 0) or 0),
        }
        if elapsed is not None and elapsed > 0:
            payload.update(
                {
                    "rx_bytes_per_second": max(0.0, float(interface.get("rx_delta", 0)) / elapsed),
                    "tx_bytes_per_second": max(0.0, float(interface.get("tx_delta", 0)) / elapsed),
                    "rx_packets_per_second": max(0.0, float(interface.get("rx_packet_delta", 0)) / elapsed),
                    "tx_packets_per_second": max(0.0, float(interface.get("tx_packet_delta", 0)) / elapsed),
                }
            )
        return payload

    def reconcile_interfaces(
        self, records: Iterable[Mapping[str, Any]], *, now: int | None = None
    ) -> list[TelemetryEvent]:
        """Reconcile read-only interface counters and calculate safe rates.

        Rates use only monotonic counter deltas.  A reset produces an explicit
        event and zeroes the corresponding rate rather than reporting a
        misleading negative spike.
        """

        observed_at = self._timestamp(now)
        incoming: dict[str, dict[str, Any]] = {}
        for record in records:
            interface = normalize_interface(record)
            if interface is not None:
                interface["observed_at"] = observed_at
                incoming[str(interface["id"])] = interface
        with self._lock:
            events: list[TelemetryEvent] = []
            for interface_id, interface in incoming.items():
                previous = self._interfaces.get(interface_id)
                reset = self._interface_reset_event(previous, interface, observed_at)
                if reset is not None:
                    events.append(reset)
                elapsed = None
                if previous is not None:
                    elapsed = max(0.0, observed_at - float(previous.get("observed_at", observed_at)))
                    interface["rx_delta"] = int(interface["rx_bytes"]) - int(previous.get("rx_bytes", 0))
                    interface["tx_delta"] = int(interface["tx_bytes"]) - int(previous.get("tx_bytes", 0))
                    interface["rx_packet_delta"] = int(interface["rx_packets"]) - int(previous.get("rx_packets", 0))
                    interface["tx_packet_delta"] = int(interface["tx_packets"]) - int(previous.get("tx_packets", 0))
                self._interfaces[interface_id] = interface
                events.append(
                    self._event(
                        "vpn.interface.counters",
                        {"interface": self._interface_payload(interface, elapsed=elapsed)},
                        observed_at,
                    )
                )
            self._interfaces = dict(list(incoming.items())[-self._max_interfaces :])
            return events

    def interfaces_snapshot(self) -> list[dict[str, Any]]:
        """Return the latest redacted interface counters for reconnects."""

        with self._lock:
            return [self._interface_payload(self._interfaces[key]) for key in sorted(self._interfaces)]

    def snapshot(self) -> list[dict[str, Any]]:
        """Return a stable, redacted snapshot for a reconnecting client."""

        with self._lock:
            return [self._payload(self._sessions[key]) for key in sorted(self._sessions)]

    @property
    def sequence(self) -> int:
        with self._lock:
            return self._sequence

    @property
    def counter_resets(self) -> int:
        with self._lock:
            return self._counter_resets

    @property
    def interface_counter_resets(self) -> int:
        with self._lock:
            return self._interface_counter_resets
