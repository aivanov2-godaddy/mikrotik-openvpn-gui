from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
from dataclasses import dataclass


SESSION_IDLE_SECONDS = 30 * 60
SESSION_ABSOLUTE_SECONDS = 8 * 60 * 60
SESSION_ROLE_REVALIDATION_SECONDS = 15
MAX_SESSIONS_PER_ACCOUNT = 8


class ConcurrentSessionLimitReached(ValueError):
    """Raised when an account already has its maximum active dashboard sessions."""

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
        "health.read", "users.read", "profiles.read", "sessions.read", "audit.read", "policies.read",
        "security.manage", "device.manage", "profiles.manage", "session.manage",
    }),
    "administrator": frozenset({
        "health.read", "users.read", "profiles.read", "sessions.read", "audit.read", "policies.read",
        "users.manage", "profiles.manage", "policies.manage", "backup.manage",
        "session.manage", "alert.manage",
    }),
    "auditor": frozenset({
        "health.read", "users.read", "profiles.read", "sessions.read", "audit.read", "policies.read",
    }),
    "read_only": frozenset({
        "health.read", "users.read", "profiles.read", "sessions.read", "policies.read",
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
        max_sessions_per_account: int = MAX_SESSIONS_PER_ACCOUNT,
    ) -> None:
        if max_sessions_per_account < 1:
            raise ValueError("max_sessions_per_account must be positive")
        self.idle_seconds = idle_seconds
        self.absolute_seconds = absolute_seconds
        self.max_sessions_per_account = max_sessions_per_account
        self._sessions: dict[str, Session] = {}
        self._lock = threading.RLock()
        self._role_checked_at: dict[str, float] = {}
        self._role_check_locks: dict[str, threading.Lock] = {}

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
            self.purge(current)
            account_sessions = sum(
                existing.username.casefold() == username.casefold()
                for existing in self._sessions.values()
            )
            if account_sessions >= self.max_sessions_per_account:
                raise ConcurrentSessionLimitReached
            self._sessions[session.session_id] = session
            self._role_checked_at[session.session_id] = current
        return session

    def get(
        self,
        session_id: str,
        now: float | None = None,
        *,
        touch: bool = True,
    ) -> Session | None:
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
                self._role_checked_at.pop(session_id, None)
                self._role_check_locks.pop(session_id, None)
                return None
            if touch:
                session.last_seen = current
            return session

    @staticmethod
    def _role_is_subset(left: str, right: str) -> bool:
        left_capabilities = role_capabilities(left)
        right_capabilities = role_capabilities(right)
        return "*" in right_capabilities or (
            "*" not in left_capabilities and left_capabilities <= right_capabilities
        )

    def revalidate_role(
        self,
        session_id: str,
        role_resolver,
        *,
        now: float | None = None,
        interval_seconds: int = SESSION_ROLE_REVALIDATION_SECONDS,
    ) -> Session | None:
        """Refresh RouterOS-derived authorization without extending session idle time.

        Role decreases take effect on the existing session. Role increases do not
        silently elevate an already-authenticated dashboard session. If RouterOS
        reports an incompatible capability change or the account is gone, revoke
        the session and require a fresh login.
        """
        session = self.get(session_id, now=now, touch=False)
        if session is None or session.auth_method != "routeros":
            return session
        current = time.time() if now is None else now
        with self._lock:
            checked_at = self._role_checked_at.get(session_id, session.created_at)
            if current - checked_at < max(0, interval_seconds):
                return session
            check_lock = self._role_check_locks.setdefault(session_id, threading.Lock())

        check_lock.acquire()
        try:
            session = self.get(session_id, now=now, touch=False)
            if session is None or session.auth_method != "routeros":
                return session
            current = time.time() if now is None else now
            with self._lock:
                checked_at = self._role_checked_at.get(session_id, session.created_at)
                if current - checked_at < max(0, interval_seconds):
                    return session

            try:
                resolved_role = role_resolver(session)
            except Exception:
                # RouterOS could not prove the prior privilege set. Retain only
                # the safe read-only capability set until the next check/login.
                resolved_role = "read_only"
            checked_at = time.time() if now is None else now
            if resolved_role is None:
                self.destroy(session_id)
                return None

            current_role = normalize_role(session.role)
            resolved_role = normalize_role(resolved_role)
            if self._role_is_subset(resolved_role, current_role):
                session.role = resolved_role
            elif not self._role_is_subset(current_role, resolved_role):
                self.destroy(session_id)
                return None
            # A role increase leaves the established privilege set unchanged;
            # the operator must sign in again to obtain the new permissions.
            with self._lock:
                if self._sessions.get(session_id) is not session:
                    return None
                self._role_checked_at[session_id] = checked_at
            return session
        finally:
            check_lock.release()

    def destroy(self, session_id: str) -> None:
        with self._lock:
            self._sessions.pop(session_id, None)
            self._role_checked_at.pop(session_id, None)
            self._role_check_locks.pop(session_id, None)

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
                self._role_checked_at.pop(key, None)
                self._role_check_locks.pop(key, None)
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
            existed = self._sessions.pop(session_id, None) is not None
            self._role_checked_at.pop(session_id, None)
            self._role_check_locks.pop(session_id, None)
            return existed

    def revoke_all_except(self, session_id: str) -> int:
        """Revoke every dashboard session except the caller's session."""
        with self._lock:
            candidates = [key for key in self._sessions if key != session_id]
            for key in candidates:
                self._sessions.pop(key, None)
                self._role_checked_at.pop(key, None)
                self._role_check_locks.pop(key, None)
            return len(candidates)


class LoginRateLimiter:
    def __init__(self, limit: int = 5, window_seconds: int = 300) -> None:
        self.limit = limit
        self.window_seconds = window_seconds
        self._attempts: dict[str, list[float]] = {}
        self._reservations: dict[str, str] = {}
        self._lock = threading.Lock()

    def reserve(self, identity: str, now: float | None = None) -> str | None:
        """Atomically reserve an authentication attempt, or return ``None`` if limited.

        Reservations count against the limit while RouterOS verification is in
        flight, closing the check-then-record race between concurrent requests.
        Call :meth:`finish` exactly once when verification completes.
        """
        current = time.time() if now is None else now
        threshold = current - self.window_seconds
        with self._lock:
            attempts = [stamp for stamp in self._attempts.get(identity, []) if stamp > threshold]
            self._attempts[identity] = attempts
            reservations = sum(owner == identity for owner in self._reservations.values())
            if len(attempts) + reservations >= self.limit:
                return None
            reservation = secrets.token_urlsafe(18)
            self._reservations[reservation] = identity
            return reservation

    def finish(self, reservation: str, *, failed: bool | None, now: float | None = None) -> None:
        """Release a reservation and optionally update the failure history.

        Set ``failed=True`` for rejected credentials, ``False`` for verified
        success, and ``None`` when verification could not be completed (for
        example, RouterOS was unavailable).
        """
        current = time.time() if now is None else now
        with self._lock:
            identity = self._reservations.pop(reservation, None)
            if identity is None:
                return
            if failed is True:
                self._attempts.setdefault(identity, []).append(current)
            elif failed is False:
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
