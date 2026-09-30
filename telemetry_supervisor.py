"""Read-only Binary API telemetry supervision.

This module is deliberately an orchestration boundary, not a second RouterOS
client.  It authenticates an injected :class:`RouterOSBinaryConnection`,
subscribes only to the active-PPP listen resource, and feeds redacted replies
to :class:`telemetry_broker.TelemetryBroker`.  The default configuration is
disabled so the existing REST/SSE runtime remains the production path until a
separate canary enables it.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Mapping, Protocol

from routeros_binary import RouterOSReply
from telemetry_broker import TelemetryBroker, TelemetryEvent


class TelemetryConnection(Protocol):
    """The read-only subset of the Binary API connection used by the supervisor."""

    def connect(self, username: str, password: str) -> None:
        ...

    def listen(self, path: str, *, query: Iterable[str] = ()) -> Iterable[RouterOSReply]:
        ...


class TelemetrySupervisorError(RuntimeError):
    """Raised when a read-only telemetry attempt cannot be completed."""


@dataclass(frozen=True, slots=True)
class TelemetrySupervisorConfig:
    """Safe, bounded supervisor settings.

    ``enabled`` is intentionally false by default.  A canary deployment must
    opt in explicitly; no environment variable or mutable image tag can turn
    this on in the normal production path by accident.
    """

    enabled: bool = False
    snapshot_timeout: float = 5.0
    initial_backoff: float = 1.0
    max_backoff: float = 30.0

    def __post_init__(self) -> None:
        if self.snapshot_timeout <= 0:
            raise ValueError("snapshot_timeout must be positive")
        if self.initial_backoff <= 0:
            raise ValueError("initial_backoff must be positive")
        if self.max_backoff < self.initial_backoff:
            raise ValueError("max_backoff must be at least initial_backoff")


@dataclass(frozen=True, slots=True)
class TelemetryHealth:
    """Redacted operational state suitable for an admin health endpoint."""

    status: str
    enabled: bool
    attempts: int
    reconnects: int
    failures: int
    events: int
    last_connected_at: int | None
    last_event_at: int | None
    last_snapshot_at: int | None
    last_error_code: str | None
    backoff_seconds: float
    broker_sequence: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "enabled": self.enabled,
            "attempts": self.attempts,
            "reconnects": self.reconnects,
            "failures": self.failures,
            "events": self.events,
            "last_connected_at": self.last_connected_at,
            "last_event_at": self.last_event_at,
            "last_snapshot_at": self.last_snapshot_at,
            "last_error_code": self.last_error_code,
            "backoff_seconds": self.backoff_seconds,
            "broker_sequence": self.broker_sequence,
        }


class TelemetrySupervisor:
    """Supervise a read-only Binary API stream with bounded reconnects."""

    LISTEN_PATH = "/ppp/active"

    def __init__(
        self,
        connection_factory: Callable[[], TelemetryConnection],
        credentials_provider: Callable[[], tuple[str, str]],
        *,
        broker: TelemetryBroker | None = None,
        snapshot_reader: Callable[[TelemetryConnection], Iterable[Mapping[str, Any]]] | None = None,
        config: TelemetrySupervisorConfig | None = None,
        clock: Callable[[], float] = time.time,
        sleep: Callable[[float], None] = time.sleep,
        stop_event: threading.Event | None = None,
        on_events: Callable[[list[TelemetryEvent]], None] | None = None,
    ) -> None:
        self._connection_factory = connection_factory
        self._credentials_provider = credentials_provider
        self._broker = broker or TelemetryBroker(clock=clock)
        self._snapshot_reader = snapshot_reader
        self._config = config or TelemetrySupervisorConfig()
        self._clock = clock
        self._sleep = sleep
        self._stop_event = stop_event or threading.Event()
        self._on_events = on_events
        self._lock = threading.RLock()
        self._status = "disabled" if not self._config.enabled else "stopped"
        self._attempts = 0
        self._reconnects = 0
        self._failures = 0
        self._events = 0
        self._last_connected_at: int | None = None
        self._last_event_at: int | None = None
        self._last_snapshot_at: int | None = None
        self._last_error_code: str | None = None
        self._backoff_seconds = self._config.initial_backoff

    @property
    def broker(self) -> TelemetryBroker:
        return self._broker

    @property
    def stop_event(self) -> threading.Event:
        return self._stop_event

    def stop(self) -> None:
        """Request a graceful stop; this never changes RouterOS state."""

        self._stop_event.set()
        with self._lock:
            self._status = "stopped"

    def health(self) -> TelemetryHealth:
        """Return a copy of metrics without credentials, tokens, or records."""

        with self._lock:
            return TelemetryHealth(
                status=self._status,
                enabled=self._config.enabled,
                attempts=self._attempts,
                reconnects=self._reconnects,
                failures=self._failures,
                events=self._events,
                last_connected_at=self._last_connected_at,
                last_event_at=self._last_event_at,
                last_snapshot_at=self._last_snapshot_at,
                last_error_code=self._last_error_code,
                backoff_seconds=self._backoff_seconds,
                broker_sequence=self._broker.sequence,
            )

    def run_attempt(self) -> None:
        """Run one connection/listen attempt.

        The method returns only when the stream ends.  A stream ending is
        treated as a failure so :meth:`run_forever` can reconnect.  Tests and a
        canary runner can call this method directly without starting a thread.
        """

        if not self._config.enabled:
            with self._lock:
                self._status = "disabled"
            return
        if self._stop_event.is_set():
            return

        with self._lock:
            self._attempts += 1
            self._status = "connecting"
            self._last_error_code = None
        connection = self._connection_factory()
        try:
            username, password = self._credentials_provider()
            connection.connect(username, password)
            with self._lock:
                self._status = "healthy"
                self._last_connected_at = int(self._clock())
                self._reconnects = max(0, self._attempts - 1)
                self._backoff_seconds = self._config.initial_backoff

            if self._snapshot_reader is not None:
                started = self._clock()
                records = list(self._snapshot_reader(connection))
                elapsed = self._clock() - started
                if elapsed > self._config.snapshot_timeout:
                    raise TelemetrySupervisorError("snapshot_timeout")
                self._publish(self._broker.reconcile(records, now=int(self._clock())), snapshot=True)

            for reply in connection.listen(self.LISTEN_PATH):
                if self._stop_event.is_set():
                    return
                if not isinstance(reply, RouterOSReply):
                    raise TelemetrySupervisorError("invalid_reply")
                self._publish(self._broker.apply(reply, now=int(self._clock())))
            raise TelemetrySupervisorError("listen_ended")
        finally:
            close = getattr(connection, "close", None)
            if callable(close):
                close()

    def run_forever(self, *, max_attempts: int | None = None) -> None:
        """Reconnect with capped exponential backoff until stopped."""

        if not self._config.enabled:
            with self._lock:
                self._status = "disabled"
            return
        attempts = 0
        while not self._stop_event.is_set() and (max_attempts is None or attempts < max_attempts):
            attempts += 1
            try:
                self.run_attempt()
            except Exception as error:  # noqa: BLE001 - boundary must reconnect safely
                with self._lock:
                    self._failures += 1
                    self._status = "degraded"
                    self._last_error_code = self._error_code(error)
                    delay = self._backoff_seconds
                    self._backoff_seconds = min(self._config.max_backoff, delay * 2)
                if self._stop_event.wait(delay):
                    break
            else:
                # A clean return only occurs after a stop request.
                break
        if self._stop_event.is_set():
            with self._lock:
                self._status = "stopped"

    def _publish(self, events: list[TelemetryEvent], *, snapshot: bool = False) -> None:
        if not events:
            return
        now = int(self._clock())
        with self._lock:
            self._events += len(events)
            self._last_event_at = now
            if snapshot:
                self._last_snapshot_at = now
        if self._on_events is not None:
            self._on_events(list(events))

    @staticmethod
    def _error_code(error: Exception) -> str:
        if isinstance(error, TelemetrySupervisorError):
            return str(error)[:64] or "supervisor_error"
        if isinstance(error, TimeoutError):
            return "timeout"
        if isinstance(error, OSError):
            return "connection_error"
        return "stream_error"
