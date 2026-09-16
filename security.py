from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
from dataclasses import dataclass


SESSION_IDLE_SECONDS = 30 * 60
SESSION_ABSOLUTE_SECONDS = 8 * 60 * 60

# Dashboard roles are deliberately derived from the authenticated RouterOS
# account.  They are capabilities, not another password database, so the
# router remains the source of truth for identity and account membership.
ROLE_LABELS = {
    "owner": "Owner",
    "security_operator": "Security operator",
    "administrator": "Administrator",
    "auditor": "Auditor",
    "read_only": "Read-only",
}

ROLE_ALIASES = {
    "operator": "administrator",
    "viewer": "read_only",
    "read": "read_only",
    "readonly": "read_only",
    "read-only": "read_only",
    "security-operator": "security_operator",
    "security": "security_operator",
    "audit": "auditor",
}

# Keep the matrix small and explicit.  ``*`` is reserved for the owner and is
# checked in ``has_capability`` so adding a new capability cannot accidentally
# remove owner access.
ROLE_CAPABILITIES = {
    "owner": frozenset({"*"}),
    "security_operator": frozenset({
        "health.read", "users.read", "profiles.read", "sessions.read", "audit.read",
        "security.manage", "device.manage", "profiles.manage", "session.manage",
    }),
    "administrator": frozenset({
        "health.read", "users.read", "profiles.read", "sessions.read", "audit.read",
        "users.manage", "profiles.manage", "policies.manage", "backup.manage",
        "session.manage", "alert.manage",
    }),
    "auditor": frozenset({
        "health.read", "users.read", "profiles.read", "sessions.read", "audit.read",
    }),
    "read_only": frozenset({
        "health.read", "users.read", "profiles.read", "sessions.read",
    }),
}


def normalize_role(role: str) -> str:
    """Return one of the five public dashboard roles.

    Unknown values fail closed to ``read_only``.  RouterOS authentication has
    already succeeded at this point, but an unrecognised group must never gain
    owner privileges because of a spelling mistake or a future RouterOS group.
    """
    candidate = str(role or "").strip().casefold().replace(" ", "_")
    candidate = ROLE_ALIASES.get(candidate, candidate)
    return candidate if candidate in ROLE_CAPABILITIES else "read_only"


def role_label(role: str) -> str:
    return ROLE_LABELS[normalize_role(role)]


def role_capabilities(role: str) -> frozenset[str]:
    return ROLE_CAPABILITIES[normalize_role(role)]


def has_capability(role: str, capability: str) -> bool:
    capabilities = role_capabilities(role)
    return "*" in capabilities or capability in capabilities


@dataclass(slots=True)
class Session:
    session_id: str
    username: str
    password: str
    csrf_token: str
    created_at: float
    last_seen: float
    role: str = "owner"
    source_address: str = ""
    user_agent: str = ""
    auth_method: str = "routeros"
    token_id: str = ""
    capabilities: frozenset[str] | None = None


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
        source_address: str = "",
        user_agent: str = "",
    ) -> Session:
        current = time.time() if now is None else now
        session = Session(
            session_id=secrets.token_urlsafe(32),
            username=username,
            password=password,
            csrf_token=secrets.token_urlsafe(32),
            created_at=current,
            last_seen=current,
            role=normalize_role(role),
            source_address=str(source_address or ""),
            user_agent=str(user_agent or "")[:256],
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

    def snapshot(
        self,
        *,
        current_session_id: str = "",
        now: float | None = None,
        include_identifiers: bool = False,
    ) -> list[dict[str, object]]:
        """Return safe administrator-session metadata without credentials.

        Raw session IDs are bearer material, so they are included only for a
        caller that has an explicit session-management capability. Everyone
        else receives a short stable hash suitable for inventory/audit views.
        """
        current = time.time() if now is None else now
        sessions = self.active(current)
        result: list[dict[str, object]] = []
        for session in sessions:
            result.append({
                "id": session.session_id if include_identifiers else "",
                "id_hash": hashlib.sha256(session.session_id.encode("utf-8")).hexdigest()[:16],
                "username": session.username,
                "role": normalize_role(session.role),
                "created_at": int(session.created_at),
                "last_seen": int(session.last_seen),
                "idle_seconds": max(0, int(current - session.last_seen)),
                "idle_remaining": max(0, int(self.idle_seconds - (current - session.last_seen))),
                "absolute_remaining": max(0, int(self.absolute_seconds - (current - session.created_at))),
                "source_address": session.source_address or "unknown",
                "user_agent": session.user_agent or "unknown",
                "auth_method": session.auth_method,
                "current": bool(session.session_id and session.session_id == current_session_id),
            })
        return result

    def revoke(self, session_id: str) -> bool:
        """Revoke one dashboard session and report whether it existed."""
        with self._lock:
            return self._sessions.pop(session_id, None) is not None

    def revoke_all_except(self, session_id: str) -> int:
        """Revoke every dashboard session except the caller's session."""
        with self._lock:
            candidates = [key for key in self._sessions if key != session_id]
            for key in candidates:
                self._sessions.pop(key, None)
            return len(candidates)


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
