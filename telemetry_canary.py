"""Read-only canary comparison for Binary API telemetry.

The canary compares a new redacted snapshot with the existing REST snapshot.
It never writes to RouterOS, SQLite, certificates, profiles, or user data.
Production must keep the legacy transport unless a policy reports a healthy
comparison for the configured number of consecutive samples.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Mapping


@dataclass(frozen=True, slots=True)
class CanaryPolicy:
    max_age_seconds: float = 10.0
    max_missing_sessions: int = 0
    max_extra_sessions: int = 0
    required_consecutive: int = 3

    def __post_init__(self) -> None:
        if self.max_age_seconds <= 0:
            raise ValueError("max_age_seconds must be positive")
        if self.max_missing_sessions < 0 or self.max_extra_sessions < 0:
            raise ValueError("session limits cannot be negative")
        if self.required_consecutive <= 0:
            raise ValueError("required_consecutive must be positive")


@dataclass(frozen=True, slots=True)
class CanaryResult:
    healthy: bool
    observed_at: int
    age_seconds: float
    missing_sessions: tuple[str, ...]
    extra_sessions: tuple[str, ...]
    reason: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "healthy": self.healthy,
            "observed_at": self.observed_at,
            "age_seconds": round(self.age_seconds, 3),
            "missing_sessions": list(self.missing_sessions),
            "extra_sessions": list(self.extra_sessions),
            "reason": self.reason,
        }


def _ids(records: Iterable[Mapping[str, Any]]) -> set[str]:
    return {str(item.get("id", "")).strip() for item in records if str(item.get("id", "")).strip()}


def compare_snapshots(
    legacy: Iterable[Mapping[str, Any]],
    binary: Iterable[Mapping[str, Any]],
    *,
    observed_at: int | None = None,
    binary_timestamp: int | None = None,
    policy: CanaryPolicy | None = None,
    clock: Callable[[], float] = time.time,
) -> CanaryResult:
    """Compare only redacted session identifiers and freshness metadata."""

    selected = policy or CanaryPolicy()
    now = float(clock())
    observed = int(now if observed_at is None else observed_at)
    age = max(0.0, now - int(binary_timestamp or observed))
    legacy_ids = _ids(legacy)
    binary_ids = _ids(binary)
    missing = tuple(sorted(legacy_ids - binary_ids))
    extra = tuple(sorted(binary_ids - legacy_ids))
    healthy = (
        age <= selected.max_age_seconds
        and len(missing) <= selected.max_missing_sessions
        and len(extra) <= selected.max_extra_sessions
    )
    if age > selected.max_age_seconds:
        reason = "binary_snapshot_stale"
    elif missing or extra:
        reason = "session_set_mismatch"
    else:
        reason = "ok"
    return CanaryResult(healthy, observed, age, missing, extra, reason)


class TelemetryCanary:
    """Run bounded read-only comparisons and track promotion readiness."""

    def __init__(self, policy: CanaryPolicy | None = None) -> None:
        self.policy = policy or CanaryPolicy()
        self.consecutive_healthy = 0
        self.last_result: CanaryResult | None = None

    @property
    def ready_to_promote(self) -> bool:
        return self.consecutive_healthy >= self.policy.required_consecutive

    def observe(
        self,
        legacy: Iterable[Mapping[str, Any]],
        binary: Iterable[Mapping[str, Any]],
        **kwargs: Any,
    ) -> CanaryResult:
        result = compare_snapshots(legacy, binary, policy=self.policy, **kwargs)
        self.last_result = result
        self.consecutive_healthy = self.consecutive_healthy + 1 if result.healthy else 0
        return result

