"""Thread-safe, redacted runtime status for live telemetry.

This state is deliberately separate from RouterOS credentials and the SQLite
store.  It reports only transport health and timestamps so the dashboard can
explain whether live data is fresh without exposing router or VPN material.
"""

from __future__ import annotations

import threading
import time
from typing import Any, Callable


class TelemetryRuntimeState:
    """Track the effective live transport and freshness of its observations."""

    def __init__(
        self,
        requested_transport: str = "rest",
        *,
        effective_transport: str = "sse",
        socketio_enabled: bool = False,
        clock: Callable[[], float] = time.time,
        stale_after_seconds: int = 10,
    ) -> None:
        self._clock = clock
        self._stale_after_seconds = max(1, int(stale_after_seconds))
        self._lock = threading.RLock()
        self._requested_transport = requested_transport
        self._effective_transport = effective_transport
        self._socketio_enabled = bool(socketio_enabled)
        self._last_event_at: int | None = None
        self._last_reconciliation_at: int | None = None
        self._event_count = 0
        self._last_session_event_at: float | None = None
        self._last_traffic_sample_at: float | None = None
        self._session_events = 0
        self._traffic_samples = 0
        self._reconnects = 0
        self._last_error: str | None = None

    def mark_event(self, *, reconciliation: bool = False, now: int | None = None) -> None:
        observed_at = int(self._clock() if now is None else now)
        with self._lock:
            self._last_event_at = observed_at
            self._last_session_event_at = float(observed_at)
            self._session_events += 1
            if reconciliation:
                self._last_reconciliation_at = observed_at
            self._event_count += 1
            self._last_error = None

    def mark_session_events(
        self, count: int = 1, *, reconciliation: bool = False, now: float | None = None
    ) -> None:
        """Record aggregate session-event freshness without retaining event data."""
        observed_at = float(self._clock() if now is None else now)
        with self._lock:
            self._last_event_at = int(observed_at)
            self._last_session_event_at = observed_at
            self._session_events += max(0, int(count))
            if reconciliation:
                self._last_reconciliation_at = int(observed_at)
            self._event_count += max(0, int(count))
            self._last_error = None

    def mark_traffic_samples(self, count: int = 1, *, now: float | None = None) -> None:
        """Record freshness of aggregate interface-counter samples."""
        observed_at = float(self._clock() if now is None else now)
        with self._lock:
            self._last_traffic_sample_at = observed_at
            self._traffic_samples += max(0, int(count))

    def mark_reconnect(self) -> None:
        with self._lock:
            self._reconnects += 1

    def mark_error(self, code: str) -> None:
        safe_code = str(code).strip()[:64] or "telemetry_error"
        with self._lock:
            self._last_error = safe_code

    def as_dict(self, *, now: float | None = None) -> dict[str, Any]:
        current_exact = float(self._clock() if now is None else now)
        current = int(current_exact)
        with self._lock:
            event_age = (
                max(0, current - self._last_event_at)
                if self._last_event_at is not None
                else None
            )
            reconciliation_age = (
                max(0, current - self._last_reconciliation_at)
                if self._last_reconciliation_at is not None
                else None
            )
            session_event_age = (
                max(0.0, current_exact - self._last_session_event_at)
                if self._last_session_event_at is not None
                else None
            )
            traffic_sample_age = (
                max(0.0, current_exact - self._last_traffic_sample_at)
                if self._last_traffic_sample_at is not None
                else None
            )
            if self._last_error:
                state = "error"
            elif event_age is None or event_age > self._stale_after_seconds:
                state = "stale"
            else:
                state = "healthy"
            return {
                "requested_transport": self._requested_transport,
                "transport": self._effective_transport,
                "socketio_enabled": self._socketio_enabled,
                "namespace": "/telemetry",
                "fallback": "sse",
                "state": state,
                "last_event_at": self._last_event_at,
                "last_reconciliation_at": self._last_reconciliation_at,
                "event_age_seconds": event_age,
                "reconciliation_age_seconds": reconciliation_age,
                "event_count": self._event_count,
                "last_session_event_at": self._last_session_event_at,
                "session_event_age_seconds": session_event_age,
                "session_events": self._session_events,
                "last_traffic_sample_at": self._last_traffic_sample_at,
                "traffic_sample_age_seconds": traffic_sample_age,
                "traffic_samples": self._traffic_samples,
                "reconnects": self._reconnects,
                "last_error": self._last_error,
            }
