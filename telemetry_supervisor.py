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
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Mapping, Protocol

from routeros_binary import RouterOSReply
from telemetry_broker import TelemetryBroker, TelemetryEvent


class TelemetryConnection(Protocol):
    """The read-only subset of the Binary API connection used by the supervisor."""

    def connect(self, username: str, password: str) -> None:
        ...

    def execute(self, path: str, *, query: Iterable[str] = ()) -> Iterable[RouterOSReply]:
        ...

    def listen(self, path: str, *, query: Iterable[str] = ()) -> Iterable[RouterOSReply]:
        ...


INTERFACE_COUNTER_PROPLIST = ".proplist=.id,name,rx-byte,tx-byte,rx-packet,tx-packet"
DEFAULT_INTERFACE_SAMPLE_INTERVAL_SECONDS = 1.0


def read_interface_counters(connection: TelemetryConnection) -> list[Mapping[str, str]]:
    """Read only interface counters through the Binary API.

    The narrow proplist is the privacy and load boundary.  Non-record replies
    are ignored; RouterOS errors still propagate to the supervisor so the
    existing reconnect/backoff policy handles them.
    """

    replies = connection.execute("/interface/print", query=(INTERFACE_COUNTER_PROPLIST,))
    return [dict(reply.attributes) for reply in replies if reply.kind == "re"]


class TelemetrySupervisorError(RuntimeError):
    """Raised when a read-only telemetry attempt cannot be completed."""


def _require_authorized(
    authorization_check: Callable[[str, str], bool] | None,
    credentials: tuple[str, str],
) -> None:
    """Stop processing when the RouterOS credential source is no longer valid."""

    if authorization_check is not None and not authorization_check(*credentials):
        raise TelemetrySupervisorError("credentials_unavailable")


def _require_authorization_ref(
    authorization_ref_check: Callable[[str], bool] | None,
    authorization_ref: str,
) -> None:
    """Fail closed if a lease's source dashboard session is no longer active."""

    if authorization_ref_check is None or not authorization_ref_check(authorization_ref):
        raise TelemetrySupervisorError("credentials_unavailable")


@dataclass(slots=True)
class TelemetryCredentialLease:
    """Short-lived credentials plus an opaque internal authorization reference.

    The reference is security-sensitive process state: keep it out of logs,
    metrics, and client-visible telemetry.
    """

    username: str = field(repr=False)
    password: str = field(repr=False)
    authorization_ref: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class TelemetrySupervisorConfig:
    """Safe, bounded supervisor settings.

    ``enabled`` is intentionally false by default.  A canary deployment must
    opt in explicitly; no environment variable or mutable image tag can turn
    this on in the normal production path by accident.
    """

    enabled: bool = False
    snapshot_timeout: float = 5.0
    authorization_poll_interval: float = 1.0
    initial_backoff: float = 1.0
    max_backoff: float = 30.0

    def __post_init__(self) -> None:
        if self.snapshot_timeout <= 0:
            raise ValueError("snapshot_timeout must be positive")
        if self.authorization_poll_interval <= 0:
            raise ValueError("authorization_poll_interval must be positive")
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
        credentials_provider: Callable[[], tuple[str, str] | TelemetryCredentialLease],
        *,
        broker: TelemetryBroker | None = None,
        snapshot_reader: Callable[[TelemetryConnection], Iterable[Mapping[str, Any]]] | None = None,
        config: TelemetrySupervisorConfig | None = None,
        clock: Callable[[], float] = time.time,
        sleep: Callable[[float], None] = time.sleep,
        stop_event: threading.Event | None = None,
        on_events: Callable[[list[TelemetryEvent]], None] | None = None,
        on_events_after_dispatch: Callable[[list[TelemetryEvent]], None] | None = None,
        authorization_check: Callable[[str, str], bool] | None = None,
        authorization_ref_check: Callable[[str], bool] | None = None,
        authorization_ref_dispatch: Callable[[str, Callable[[], None]], bool] | None = None,
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
        self._on_events_after_dispatch = on_events_after_dispatch
        self._authorization_check = authorization_check
        self._authorization_ref_check = authorization_ref_check
        self._authorization_ref_dispatch = authorization_ref_dispatch
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

    def _connect(
        self, connection: TelemetryConnection
    ) -> tuple[str, str | None, tuple[str, str] | None]:
        """Authenticate and release provider-held password references promptly."""

        provided = self._credentials_provider()
        if isinstance(provided, TelemetryCredentialLease):
            username = provided.username
            authorization_ref = provided.authorization_ref
            try:
                connection.connect(username, provided.password)
            finally:
                provided.password = ""
            return username, authorization_ref, None

        username, password = provided
        credentials = (username, password)
        connection.connect(username, password)
        return username, None, credentials

    def _require_attempt_authorized(
        self,
        authorization_ref: str | None,
        credentials: tuple[str, str] | None,
    ) -> None:
        if authorization_ref is not None:
            _require_authorization_ref(
                self._authorization_ref_check, authorization_ref
            )
        elif credentials is not None:
            _require_authorized(self._authorization_check, credentials)

    def _watch_authorization(
        self,
        connection: TelemetryConnection,
        authorization_ref: str,
        finished: threading.Event,
    ) -> None:
        """Close an idle API stream promptly when its dashboard session ends."""

        while not finished.wait(self._config.authorization_poll_interval):
            try:
                _require_authorization_ref(
                    self._authorization_ref_check, authorization_ref
                )
            except Exception:  # noqa: BLE001 - authorization failure must close the stream
                close = getattr(connection, "close", None)
                if callable(close):
                    try:
                        close()
                    except Exception:  # noqa: BLE001 - best-effort cross-thread shutdown
                        pass
                return

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
        monitor_finished = threading.Event()
        monitor: threading.Thread | None = None
        try:
            _username, authorization_ref, credentials = self._connect(connection)
            if authorization_ref is not None:
                monitor = threading.Thread(
                    target=self._watch_authorization,
                    args=(connection, authorization_ref, monitor_finished),
                    name="vpn-dashboard-telemetry-auth-watch",
                    daemon=True,
                )
                monitor.start()
            self._require_attempt_authorized(authorization_ref, credentials)
            with self._lock:
                self._status = "connecting" if self._snapshot_reader is not None else "healthy"
                if self._last_connected_at is not None:
                    self._reconnects += 1
                self._last_connected_at = int(self._clock())

            if self._snapshot_reader is not None:
                self._require_attempt_authorized(authorization_ref, credentials)
                started = self._clock()
                records = list(self._snapshot_reader(connection))
                self._require_attempt_authorized(authorization_ref, credentials)
                elapsed = self._clock() - started
                if elapsed > self._config.snapshot_timeout:
                    raise TelemetrySupervisorError("snapshot_timeout")
                self._publish(
                    lambda: self._broker.reconcile(records, now=int(self._clock())),
                    snapshot=True,
                    credentials=credentials,
                    authorization_ref=authorization_ref,
                )
                with self._lock:
                    self._status = "healthy"

            with self._lock:
                self._backoff_seconds = self._config.initial_backoff

            for reply in connection.listen(self.LISTEN_PATH):
                if self._stop_event.is_set():
                    return
                self._require_attempt_authorized(authorization_ref, credentials)
                if not isinstance(reply, RouterOSReply):
                    raise TelemetrySupervisorError("invalid_reply")
                self._publish(
                    lambda: self._broker.apply(reply, now=int(self._clock())),
                    credentials=credentials,
                    authorization_ref=authorization_ref,
                )
            raise TelemetrySupervisorError("listen_ended")
        finally:
            monitor_finished.set()
            if monitor is not None:
                monitor.join(
                    timeout=max(1.0, self._config.authorization_poll_interval * 2)
                )
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

    def _publish(
        self,
        event_factory: Callable[[], list[TelemetryEvent]],
        *,
        snapshot: bool = False,
        credentials: tuple[str, str] | None = None,
        authorization_ref: str | None = None,
    ) -> None:
        events: list[TelemetryEvent] = []

        def dispatch() -> None:
            nonlocal events
            # Keep broker mutation inside the same authorization dispatch as
            # publication. A denied producer must not leave state behind for
            # a later subscriber's recovery snapshot.
            events = event_factory()
            if self._on_events is not None and events:
                self._on_events(list(events))

        if authorization_ref is not None and self._authorization_ref_dispatch is not None:
            if not self._authorization_ref_dispatch(authorization_ref, dispatch):
                raise TelemetrySupervisorError("credentials_unavailable")
        elif authorization_ref is not None and self._on_events is not None:
            raise TelemetrySupervisorError("credentials_unavailable")
        else:
            # Legacy providers have no lockable authorization reference; do
            # their final check immediately before cache mutation.
            self._require_attempt_authorized(authorization_ref, credentials)
            dispatch()
        if not events:
            return
        now = int(self._clock())
        with self._lock:
            self._events += len(events)
            self._last_event_at = now
            if snapshot:
                self._last_snapshot_at = now
        if self._on_events_after_dispatch is not None:
            self._on_events_after_dispatch(list(events))

    @staticmethod
    def _error_code(error: Exception) -> str:
        if isinstance(error, TelemetrySupervisorError):
            return str(error)[:64] or "supervisor_error"
        if isinstance(error, TimeoutError):
            return "timeout"
        if isinstance(error, OSError):
            return "connection_error"
        return "stream_error"


class TelemetryInterfaceSampler:
    """Sample interface counters over a separate read-only API connection.

    RouterOS allows one long-lived ``listen`` sentence per connection.  The
    sampler therefore uses a separate connection factory instead of issuing a
    competing request on the active-session stream.  TelemetryRuntime
    constructs it when binary or auto transport is enabled and starts its
    sampling worker with the session supervisor.  This code-level wiring does
    not establish that a particular deployment enables either mode.  It issues
    read-only requests and has no RouterOS mutation methods.
    """

    def __init__(
        self,
        connection_factory: Callable[[], TelemetryConnection],
        credentials_provider: Callable[[], tuple[str, str] | TelemetryCredentialLease],
        broker: TelemetryBroker,
        *,
        interval: float = DEFAULT_INTERFACE_SAMPLE_INTERVAL_SECONDS,
        sleep: Callable[[float], None] = time.sleep,
        stop_event: threading.Event | None = None,
        on_sample: Callable[[], None] | None = None,
        on_events: Callable[[list[TelemetryEvent]], None] | None = None,
        authorization_check: Callable[[str, str], bool] | None = None,
        authorization_ref_check: Callable[[str], bool] | None = None,
        authorization_ref_dispatch: Callable[[str, Callable[[], None]], bool] | None = None,
    ) -> None:
        if interval <= 0:
            raise ValueError("interval must be positive")
        self._connection_factory = connection_factory
        self._credentials_provider = credentials_provider
        self._broker = broker
        self.interval_seconds = float(interval)
        self._sleep = sleep
        self._stop_event = stop_event or threading.Event()
        self._on_sample = on_sample
        self._on_events = on_events
        self._authorization_check = authorization_check
        self._authorization_ref_check = authorization_ref_check
        self._authorization_ref_dispatch = authorization_ref_dispatch

    def stop(self) -> None:
        self._stop_event.set()

    def sample_once(self) -> list[TelemetryEvent]:
        """Read one narrow interface snapshot and publish redacted events."""

        connection = self._connection_factory()
        try:
            provided = self._credentials_provider()
            if isinstance(provided, TelemetryCredentialLease):
                username = provided.username
                authorization_ref = provided.authorization_ref
                try:
                    connection.connect(username, provided.password)
                finally:
                    provided.password = ""
                credentials = None
            else:
                username, password = provided
                credentials = (username, password)
                authorization_ref = None
                connection.connect(username, password)

            if authorization_ref is not None:
                _require_authorization_ref(
                    self._authorization_ref_check, authorization_ref
                )
            else:
                _require_authorized(self._authorization_check, credentials)
            records = read_interface_counters(connection)
            if authorization_ref is not None:
                _require_authorization_ref(
                    self._authorization_ref_check, authorization_ref
                )
            else:
                _require_authorized(self._authorization_check, credentials)

            events: list[TelemetryEvent] = []

            def dispatch() -> None:
                nonlocal events
                # The broker keeps wall-clock event timestamps separate from
                # monotonic rate intervals; passing wall time here would
                # reintroduce rounded, clock-adjustment-sensitive rates.
                events = self._broker.reconcile_interfaces(records)
                # Freshness describes a successful RouterOS observation, not
                # only a counter delta. Quiet polls still advance freshness.
                if self._on_sample is not None:
                    self._on_sample()
                if self._on_events is not None:
                    self._on_events(list(events))

            if authorization_ref is not None:
                if self._authorization_ref_dispatch is None or not self._authorization_ref_dispatch(
                    authorization_ref, dispatch
                ):
                    raise TelemetrySupervisorError("credentials_unavailable")
            else:
                # Legacy tuple providers have no opaque session reference to
                # serialize with revocation, so retain the final best-effort
                # check immediately before dispatch.
                _require_authorized(self._authorization_check, credentials)
                dispatch()
            return events
        finally:
            close = getattr(connection, "close", None)
            if callable(close):
                close()

    def run_forever(self, *, max_samples: int | None = None) -> None:
        samples = 0
        while not self._stop_event.is_set() and (max_samples is None or samples < max_samples):
            started_at = time.monotonic()
            self.sample_once()
            samples += 1
            elapsed = max(0.0, time.monotonic() - started_at)
            self._stop_event.wait(max(0.0, self.interval_seconds - elapsed))
