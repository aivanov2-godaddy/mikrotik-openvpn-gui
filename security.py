from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
from dataclasses import dataclass


SESSION_IDLE_SECONDS = 30 * 60
SESSION_ABSOLUTE_SECONDS = 8 * 60 * 60


@dataclass(slots=True)
class Session:
    session_id: str
    username: str
    password: str
    csrf_token: str
    created_at: float
    last_seen: float
    role: str = "owner"


class SessionStore:
    """In-memory credential store. RouterOS passwords are never persisted."""

    def __init__(
        self,
        idle_seconds: int = SESSION_IDLE_SECONDS,
        absolute_seconds: int = SESSION_ABSOLUTE_SECONDS,
    ) -> None:
        self.idle_seconds = idle_seconds
        self.absolute_seconds = absolute_seconds
        self._sessions: dict[str, Session] = {}
        self._lock = threading.RLock()

    def create(
        self,
        username: str,
        password: str,
        now: float | None = None,
        role: str = "owner",
    ) -> Session:
        current = time.time() if now is None else now
        session = Session(
            session_id=secrets.token_urlsafe(32),
            username=username,
            password=password,
            csrf_token=secrets.token_urlsafe(32),
            created_at=current,
            last_seen=current,
            role=role,
        )
        with self._lock:
            self._sessions[session.session_id] = session
        return session

    def get(self, session_id: str, now: float | None = None) -> Session | None:
        if not session_id:
            return None
        current = time.time() if now is None else now
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return None
            idle_expired = current - session.last_seen > self.idle_seconds
            absolute_expired = current - session.created_at > self.absolute_seconds
            if idle_expired or absolute_expired:
                self._sessions.pop(session_id, None)
                return None
            session.last_seen = current
            return session

    def destroy(self, session_id: str) -> None:
        with self._lock:
            self._sessions.pop(session_id, None)

    def purge(self, now: float | None = None) -> int:
        current = time.time() if now is None else now
        with self._lock:
            expired = [
                key
                for key, value in self._sessions.items()
                if current - value.last_seen > self.idle_seconds
                or current - value.created_at > self.absolute_seconds
            ]
            for key in expired:
                self._sessions.pop(key, None)
            return len(expired)

    def active(self, now: float | None = None) -> list[Session]:
        """Return a snapshot for in-memory background work without exposing storage."""
        current = time.time() if now is None else now
        self.purge(current)
        with self._lock:
            return list(self._sessions.values())


class LoginRateLimiter:
    def __init__(self, limit: int = 5, window_seconds: int = 300) -> None:
        self.limit = limit
        self.window_seconds = window_seconds
        self._attempts: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def allow(self, identity: str, now: float | None = None) -> bool:
        current = time.time() if now is None else now
        threshold = current - self.window_seconds
        with self._lock:
            attempts = [stamp for stamp in self._attempts.get(identity, []) if stamp > threshold]
            self._attempts[identity] = attempts
            return len(attempts) < self.limit

    def fail(self, identity: str, now: float | None = None) -> None:
        current = time.time() if now is None else now
        with self._lock:
            self._attempts.setdefault(identity, []).append(current)

    def success(self, identity: str) -> None:
        with self._lock:
            self._attempts.pop(identity, None)


def csrf_matches(expected: str, supplied: str) -> bool:
    return bool(expected and supplied and hmac.compare_digest(expected, supplied))


def stable_actor_hash(username: str) -> str:
    return hashlib.sha256(username.encode("utf-8")).hexdigest()[:16]


SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; "
        "form-action 'self'; object-src 'none'; img-src 'self' data:; "
        "style-src 'self'; script-src 'self'"
    ),
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    "Referrer-Policy": "no-referrer",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
}
