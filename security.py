from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
import os
import secrets
import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field


def disable_process_core_dumps() -> None:
    """Fail closed if POSIX process core-file limits cannot be disabled."""
    if os.name != "posix":
        return

    try:
        import resource

        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (AttributeError, ImportError, OSError, ValueError):
        raise SystemExit("Unable to disable process core dumps") from None


SESSION_IDLE_SECONDS = 30 * 60
SESSION_ABSOLUTE_SECONDS = 8 * 60 * 60
SESSION_ROLE_REVALIDATION_SECONDS = 15
LIVE_STREAM_ROLE_REVALIDATION_SECONDS = 1
SENSITIVE_ACTION_STEP_UP_SECONDS = 300
MAX_SESSIONS_PER_ACCOUNT = 8
LOGGER = logging.getLogger(__name__)


class ConcurrentSessionLimitReached(ValueError):
    """Raised when an account already has its maximum active dashboard sessions."""


class SessionAuthorizationChanged(RuntimeError):
    """Raised when account authorization changed while a login was in flight."""


class SessionStoreLockUnavailable(RuntimeError):
    """Raised when synchronous session work cannot block an event-loop thread."""

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
    session_id: str = field(repr=False)
    username: str
    password: str = field(repr=False)
    csrf_token: str = field(repr=False)
    created_at: float
    last_seen: float
    revocation_ref: str = field(
        default_factory=lambda: secrets.token_urlsafe(24), repr=False
    )
    authorization_ref: str = field(
        default_factory=lambda: secrets.token_urlsafe(24), repr=False
    )
    created_monotonic: float = field(default_factory=time.monotonic, repr=False)
    last_seen_monotonic: float = field(default_factory=time.monotonic, repr=False)
    role: str = "owner"
    source_address: str = field(default="", repr=False)
    user_agent: str = field(default="", repr=False)
    auth_method: str = "routeros"
    token_id: str = ""
    capabilities: frozenset[str] | None = None
    reauthenticated_at: float = 0.0


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
        self._revocation_sessions: dict[str, str] = {}
        self._lock = threading.RLock()
        self._role_checked_monotonic: dict[str, float] = {}
        self._role_check_locks: dict[str, threading.Lock] = {}
        self._invalidating: dict[str, int] = {}
        self._invalidating_usernames: dict[str, int] = {}
        self._pending_account_revocation_retries: dict[str, int] = {}
        self._running_account_revocation_retries: set[str] = set()
        self._account_revocation_generations: dict[str, int] = {}
        # Serializes mutations that can introduce a new session ID against
        # bulk revocation, so a concurrent rotate/login cannot escape it.
        self._session_set_lock = threading.Lock()

    @staticmethod
    def _running_in_event_loop() -> bool:
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return False
        return True

    @classmethod
    def _acquire_sync_lock(
        cls, check_lock: threading.Lock, *, blocking: bool = True
    ) -> bool:
        if not blocking:
            return check_lock.acquire(blocking=False)
        if cls._running_in_event_loop():
            if check_lock.acquire(blocking=False):
                return True
            raise SessionStoreLockUnavailable(
                "SessionStore is synchronous; await its async helper or offload "
                "the call with asyncio.to_thread() from an event loop"
            )
        check_lock.acquire()
        return True

    @classmethod
    def _acquire_role_check_locks_in_event_loop(
        cls, check_locks: list[threading.Lock]
    ) -> list[threading.Lock] | None:
        if not cls._running_in_event_loop():
            return None
        acquired: list[threading.Lock] = []
        for check_lock in check_locks:
            if check_lock.acquire(blocking=False):
                acquired.append(check_lock)
                continue
            for held_lock in reversed(acquired):
                held_lock.release()
            raise SessionStoreLockUnavailable(
                "SessionStore is synchronous; await its async helper or offload "
                "the call with asyncio.to_thread() from an event loop"
            )
        return acquired

    def _role_lock_for_mutation(
        self, session_id: str, *, routeros_only: bool = False
    ) -> tuple[threading.Lock, bool] | None:
        """Return the delivery lock without holding the store lock while waiting."""
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None or (routeros_only and session.auth_method != "routeros"):
                return None
            check_lock = self._role_check_locks.setdefault(
                session_id, threading.Lock()
            )
            acquired = False
            if self._running_in_event_loop():
                if not check_lock.acquire(blocking=False):
                    raise SessionStoreLockUnavailable(
                        "SessionStore is synchronous; await its async helper or "
                        "offload the call with asyncio.to_thread() from an event loop"
                    )
                acquired = True
            self._mark_invalidating_locked((session_id,))
            return check_lock, acquired

    def _mark_invalidating_locked(self, session_ids: Iterable[str]) -> None:
        for session_id in session_ids:
            self._invalidating[session_id] = self._invalidating.get(session_id, 0) + 1

    def _clear_invalidating_locked(self, session_ids: Iterable[str]) -> None:
        for session_id in session_ids:
            count = self._invalidating.get(session_id, 0)
            if count <= 1:
                self._invalidating.pop(session_id, None)
            else:
                self._invalidating[session_id] = count - 1

    def _is_expired(
        self, session: Session, current: float, monotonic_current: float
    ) -> bool:
        return (
            current - session.last_seen >= self.idle_seconds
            or current - session.created_at >= self.absolute_seconds
            or monotonic_current - session.last_seen_monotonic >= self.idle_seconds
            or monotonic_current - session.created_monotonic >= self.absolute_seconds
        )

    @staticmethod
    def _clear_session_secrets(session: Session) -> None:
        # Python strings cannot be securely erased, and in-flight/local copies
        # may remain alive; drop the references owned by this store.
        session.password = ""
        session.csrf_token = ""
        session.authorization_ref = ""
        session.revocation_ref = ""

    def _drop_session_locked(self, session_id: str) -> None:
        session = self._sessions.pop(session_id, None)
        if session is not None:
            self._revocation_sessions.pop(session.revocation_ref, None)
            self._clear_session_secrets(session)
        self._role_checked_monotonic.pop(session_id, None)
        self._role_check_locks.pop(session_id, None)

    def _session_is_invalidating_locked(
        self, session_id: str, session: Session
    ) -> bool:
        return (
            session_id in self._invalidating
            or self._invalidating_usernames.get(session.username.casefold(), 0) > 0
        )

    def _mark_account_invalidating_locked(self, username_key: str) -> None:
        # Publish denial before waiting on any session-set or delivery lock.
        # In-flight create/rotate operations recheck this marker before commit.
        count = self._invalidating_usernames.get(username_key, 0)
        if count == 0:
            self._account_revocation_generations[username_key] = (
                self._account_revocation_generations.get(username_key, 0) + 1
            )
        self._invalidating_usernames[username_key] = count + 1

    def _clear_account_invalidating_locked(self, username_key: str) -> None:
        count = self._invalidating_usernames.get(username_key, 0)
        if count <= 1:
            self._invalidating_usernames.pop(username_key, None)
        else:
            self._invalidating_usernames[username_key] = count - 1

    def account_revocation_generation(self, username: str) -> int:
        """Return the generation a newly authenticated login must bind to."""
        if not isinstance(username, str):
            return 0
        username_key = username.strip().casefold()
        with self._lock:
            return self._account_revocation_generations.get(username_key, 0)

    def create(
        self,
        username: str,
        password: str,
        now: float | None = None,
        role: str = "owner",
        source_address: str = "",
        user_agent: str = "",
        expected_account_revocation_generation: int | None = None,
        before_commit: Callable[[Session], None] | None = None,
    ) -> Session:
        self._acquire_sync_lock(self._session_set_lock)
        try:
            return self._create_with_session_set_lock(
                username,
                password,
                now=now,
                role=role,
                source_address=source_address,
                user_agent=user_agent,
                expected_account_revocation_generation=expected_account_revocation_generation,
                before_commit=before_commit,
            )
        finally:
            self._session_set_lock.release()

    def _create_with_session_set_lock(
        self,
        username: str,
        password: str,
        now: float | None = None,
        role: str = "owner",
        source_address: str = "",
        user_agent: str = "",
        expected_account_revocation_generation: int | None = None,
        before_commit: Callable[[Session], None] | None = None,
    ) -> Session:
        current = time.time() if now is None else now
        monotonic_current = time.monotonic()
        session = Session(
            session_id=secrets.token_urlsafe(32),
            username=username,
            password=password,
            csrf_token=secrets.token_urlsafe(32),
            created_at=current,
            last_seen=current,
            created_monotonic=monotonic_current,
            last_seen_monotonic=monotonic_current,
            role=normalize_role(role),
            source_address=str(source_address or ""),
            user_agent=str(user_agent or "")[:256],
            reauthenticated_at=current,
        )
        self.purge(current)
        with self._lock:
            username_key = username.strip().casefold()
            if (
                self._invalidating_usernames.get(username_key, 0) > 0
                or (
                    expected_account_revocation_generation is not None
                    and self._account_revocation_generations.get(username_key, 0)
                    != expected_account_revocation_generation
                )
            ):
                self._clear_session_secrets(session)
                raise SessionAuthorizationChanged
            account_sessions = sum(
                existing.username.casefold() == username.casefold()
                for existing in self._sessions.values()
            )
            if account_sessions >= self.max_sessions_per_account:
                raise ConcurrentSessionLimitReached

        committed = False
        try:
            if before_commit is not None:
                before_commit(session)
            with self._lock:
                if (
                    self._invalidating_usernames.get(username_key, 0) > 0
                    or (
                        expected_account_revocation_generation is not None
                        and self._account_revocation_generations.get(username_key, 0)
                        != expected_account_revocation_generation
                    )
                ):
                    raise SessionAuthorizationChanged
                account_sessions = sum(
                    existing.username.casefold() == username.casefold()
                    for existing in self._sessions.values()
                )
                if account_sessions >= self.max_sessions_per_account:
                    raise ConcurrentSessionLimitReached
                self._sessions[session.session_id] = session
                self._revocation_sessions[session.revocation_ref] = session.session_id
                self._role_checked_monotonic[session.session_id] = monotonic_current
                committed = True
                return session
        finally:
            if not committed:
                self._clear_session_secrets(session)

    def get(
        self,
        session_id: str,
        now: float | None = None,
        *,
        touch: bool = True,
        role_check_lock_held: bool = False,
        wait_for_role_check_lock: bool = True,
    ) -> Session | None:
        if not session_id:
            return None
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None or self._session_is_invalidating_locked(session_id, session):
                return None
            current = time.time() if now is None else now
            monotonic_current = time.monotonic()
            if not self._is_expired(session, current, monotonic_current):
                if touch:
                    session.last_seen = current
                    session.last_seen_monotonic = monotonic_current
                return session
            check_lock = self._role_check_locks.setdefault(
                session_id, threading.Lock()
            )

        if role_check_lock_held:
            with self._lock:
                session = self._sessions.get(session_id)
                if session is None or self._session_is_invalidating_locked(session_id, session):
                    return None
                current = time.time() if now is None else now
                monotonic_current = time.monotonic()
                if self._is_expired(session, current, monotonic_current):
                    self._drop_session_locked(session_id)
                    return None
                if touch:
                    session.last_seen = current
                    session.last_seen_monotonic = monotonic_current
                return session

        if not self._acquire_sync_lock(
            check_lock, blocking=wait_for_role_check_lock
        ):
            return None
        try:
            with self._lock:
                session = self._sessions.get(session_id)
                if session is None or self._session_is_invalidating_locked(session_id, session):
                    return None
                current = time.time() if now is None else now
                monotonic_current = time.monotonic()
                if self._is_expired(session, current, monotonic_current):
                    self._drop_session_locked(session_id)
                    return None
                if touch:
                    session.last_seen = current
                    session.last_seen_monotonic = monotonic_current
                return session
        finally:
            check_lock.release()

    def is_active_nonblocking(self, session_id: str) -> bool:
        """Check session presence and expiry without waiting on the store lock.

        This is intended for event-loop admission paths: lock contention fails
        closed instead of stalling the ASGI loop, and the idle deadline is not
        refreshed by the check.
        """
        if not session_id or not self._lock.acquire(blocking=False):
            return False
        try:
            session = self._sessions.get(session_id)
            if session is None or self._session_is_invalidating_locked(session_id, session):
                return False
            return not self._is_expired(session, time.time(), time.monotonic())
        finally:
            self._lock.release()

    def cached_role_session(
        self,
        session_id: str,
        *,
        now: float | None = None,
        interval_seconds: int = SESSION_ROLE_REVALIDATION_SECONDS,
        role_check_lock_held: bool = False,
    ) -> tuple[bool, Session | None]:
        """Return the session only when its RouterOS role cache is still fresh.

        The boolean distinguishes a cache miss (which needs a RouterOS lookup)
        from a missing or expired session (which is already a definitive denial).
        This read never contacts RouterOS and never extends the idle lifetime.
        """
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return True, None
            if self._session_is_invalidating_locked(session_id, session):
                return True, None
            current = time.time() if now is None else now
            monotonic_current = time.monotonic()
            check_lock = self._role_check_locks.get(session_id)
            if (
                check_lock is not None
                and check_lock.locked()
                and not role_check_lock_held
            ):
                return False, None
            if self._is_expired(session, current, monotonic_current):
                self._drop_session_locked(session_id)
                return True, None
            if session.auth_method != "routeros":
                return True, session
            checked_monotonic = self._role_checked_monotonic.get(
                session_id, session.created_monotonic
            )
            elapsed = monotonic_current - checked_monotonic
            fresh = 0 <= elapsed < max(0, interval_seconds)
            return (True, session) if fresh else (False, None)

    def role_check_lock(self, session_id: str) -> threading.Lock | None:
        """Return the per-session lock shared by role refresh and delivery."""
        if not session_id:
            return None
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return None
            return self._role_check_locks.setdefault(session_id, threading.Lock())

    def rotate(
        self,
        session_id: str,
        password: str,
        *,
        role: str,
        now: float | None = None,
        before_commit: Callable[[Session], None] | None = None,
    ) -> Session | None:
        self._acquire_sync_lock(self._session_set_lock)
        try:
            return self._rotate_with_session_set_lock(
                session_id, password, role=role, now=now,
                before_commit=before_commit,
            )
        finally:
            self._session_set_lock.release()

    def _rotate_with_session_set_lock(
        self,
        session_id: str,
        password: str,
        *,
        role: str,
        now: float | None = None,
        before_commit: Callable[[Session], None] | None = None,
    ) -> Session | None:
        """Replace a live RouterOS session after successful re-authentication.

        The old reference and CSRF tokens are invalidated in the same critical
        section that installs the replacement, so rotation works even when an
        account is already at its concurrent-session limit.
        """
        if not session_id:
            return None
        lock_and_state = self._role_lock_for_mutation(
            session_id, routeros_only=True
        )
        if lock_and_state is None:
            return None
        check_lock, acquired = lock_and_state
        if not acquired:
            self._acquire_sync_lock(check_lock)
        replacement = None
        username_key = ""
        committed = False
        try:
            with self._lock:
                existing = self._sessions.get(session_id)
                if existing is None:
                    return None
                username_key = existing.username.strip().casefold()
                if self._invalidating_usernames.get(username_key, 0) > 0:
                    return None
                current = time.time() if now is None else now
                monotonic_current = time.monotonic()
                if self._is_expired(existing, current, monotonic_current):
                    self._drop_session_locked(session_id)
                    return None

                replacement = Session(
                    session_id=secrets.token_urlsafe(32),
                    username=existing.username,
                    password=password,
                    csrf_token=secrets.token_urlsafe(32),
                    created_at=current,
                    last_seen=current,
                    created_monotonic=monotonic_current,
                    last_seen_monotonic=monotonic_current,
                    role=normalize_role(role),
                    source_address=existing.source_address,
                    user_agent=existing.user_agent,
                    reauthenticated_at=current,
                )
            if before_commit is not None:
                before_commit(replacement)

            with self._lock:
                if (
                    self._sessions.get(session_id) is not existing
                    or self._invalidating.get(session_id, 0) > 1
                    or self._invalidating_usernames.get(username_key, 0) > 0
                ):
                    return None
                self._drop_session_locked(session_id)
                self._sessions[replacement.session_id] = replacement
                self._revocation_sessions[replacement.revocation_ref] = replacement.session_id
                self._role_checked_monotonic[replacement.session_id] = monotonic_current
                committed = True
                return replacement
        finally:
            if replacement is not None and not committed:
                self._clear_session_secrets(replacement)
            with self._lock:
                self._clear_invalidating_locked((session_id,))
            check_lock.release()

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
        silently elevate an already-authenticated dashboard session. If role
        lookup fails, identity is missing, or RouterOS reports an incompatible
        capability change, revoke the session and require a fresh login.
        """
        session = self.get(session_id, now=now, touch=False)
        if session is None or session.auth_method != "routeros":
            return session
        monotonic_current = time.monotonic()
        with self._lock:
            if (
                self._sessions.get(session_id) is not session
                or self._session_is_invalidating_locked(session_id, session)
            ):
                return None
            checked_monotonic = self._role_checked_monotonic.get(
                session_id, session.created_monotonic
            )
            elapsed = monotonic_current - checked_monotonic
            check_lock = self._role_check_locks.setdefault(session_id, threading.Lock())
            if (
                0 <= elapsed < max(0, interval_seconds)
                and not check_lock.locked()
            ):
                return session
            acquired = check_lock.acquire(blocking=False)

        if not acquired:
            self._acquire_sync_lock(check_lock)
        invalidating_username = ""
        try:
            session = self.get(
                session_id,
                now=now,
                touch=False,
                role_check_lock_held=True,
            )
            if session is None or session.auth_method != "routeros":
                return session
            monotonic_current = time.monotonic()
            with self._lock:
                if (
                    self._sessions.get(session_id) is not session
                    or self._session_is_invalidating_locked(session_id, session)
                ):
                    return None
                checked_monotonic = self._role_checked_monotonic.get(
                    session_id, session.created_monotonic
                )
                elapsed = monotonic_current - checked_monotonic
                if 0 <= elapsed < max(0, interval_seconds):
                    return session

            try:
                resolved_role = role_resolver(session)
            except Exception:
                # RouterOS is the source of truth for every session role. If it
                # cannot verify the account, retaining even read-only access
                # would keep telemetry streams authorized from stale identity.
                self.destroy(session_id, role_check_lock_held=True)
                return None
            session = self.get(
                session_id,
                now=now,
                touch=False,
                role_check_lock_held=True,
            )
            if session is None:
                return None
            checked_monotonic = time.monotonic()
            if resolved_role is None:
                invalidating_username = session.username.casefold()
                with self._lock:
                    self._mark_account_invalidating_locked(invalidating_username)
                return None

            current_role = normalize_role(session.role)
            resolved_role = normalize_role(resolved_role)
            if self._role_is_subset(resolved_role, current_role):
                session.role = resolved_role
            elif not self._role_is_subset(current_role, resolved_role):
                self.destroy(session_id, role_check_lock_held=True)
                return None
            # A role increase leaves the established privilege set unchanged;
            # the operator must sign in again to obtain the new permissions.
            with self._lock:
                if (
                    self._sessions.get(session_id) is not session
                    or self._session_is_invalidating_locked(session_id, session)
                ):
                    return None
                self._role_checked_monotonic[session_id] = checked_monotonic
            return session
        finally:
            check_lock.release()
            if invalidating_username:
                self.revoke_account_sessions(
                    invalidating_username, already_invalidating=True
                )

    def destroy(self, session_id: str, *, role_check_lock_held: bool = False) -> None:
        check_lock = None
        if not role_check_lock_held:
            lock_and_state = self._role_lock_for_mutation(session_id)
            if lock_and_state is None:
                return
            check_lock, acquired = lock_and_state
            if not acquired:
                self._acquire_sync_lock(check_lock)
        try:
            with self._lock:
                self._drop_session_locked(session_id)
        finally:
            if check_lock is not None:
                with self._lock:
                    self._clear_invalidating_locked((session_id,))
                check_lock.release()

    def purge(self, now: float | None = None) -> int:
        with self._lock:
            current = time.time() if now is None else now
            monotonic_current = time.monotonic()
            expired = sorted(
                key
                for key, value in self._sessions.items()
                if self._is_expired(value, current, monotonic_current)
            )
            locks: list[threading.Lock] = []
            for key in expired:
                locks.append(
                    self._role_check_locks.setdefault(key, threading.Lock())
                )
            acquired = self._acquire_role_check_locks_in_event_loop(locks)
            if acquired is not None:
                try:
                    self._mark_invalidating_locked(expired)
                    for key in expired:
                        self._drop_session_locked(key)
                    return len(expired)
                finally:
                    self._clear_invalidating_locked(expired)
                    for check_lock in reversed(acquired):
                        check_lock.release()
            self._mark_invalidating_locked(expired)
        for check_lock in locks:
            check_lock.acquire()
        try:
            removed = 0
            with self._lock:
                for key in expired:
                    if key in self._sessions:
                        self._drop_session_locked(key)
                        removed += 1
            return removed
        finally:
            with self._lock:
                self._clear_invalidating_locked(expired)
            for check_lock in reversed(locks):
                check_lock.release()

    def active(self, now: float | None = None) -> list[Session]:
        """Return a snapshot for in-memory background work without exposing storage."""
        current = time.time() if now is None else now
        self.purge(current)
        with self._lock:
            return [
                session
                for session_id, session in self._sessions.items()
                if not self._session_is_invalidating_locked(session_id, session)
            ]

    def dispatch_if_active_authorization_ref(
        self, authorization_ref: str, dispatch: Callable[[], None]
    ) -> bool:
        """Serialize telemetry publication against session expiry and revocation.

        The dispatch callback runs under the session-store lock. A concurrent
        revoke either invalidates the ref first and suppresses dispatch, or
        waits until an already-authorized event has been dispatched.
        """

        if not authorization_ref:
            return False
        reference = authorization_ref.encode("utf-8")
        with self._lock:
            current = time.time()
            monotonic_current = time.monotonic()
            for session_id, session in tuple(self._sessions.items()):
                if (
                    session.auth_method == "routeros"
                    and hmac.compare_digest(
                        session.authorization_ref.encode("utf-8"), reference
                    )
                ):
                    if self._session_is_invalidating_locked(session_id, session):
                        return False
                    if self._is_expired(session, current, monotonic_current):
                        self._drop_session_locked(session_id)
                        return False
                    dispatch()
                    return True
        return False

    def snapshot(
        self,
        *,
        current_session_id: str = "",
        now: float | None = None,
        include_revocation_refs: bool = False,
    ) -> list[dict[str, object]]:
        """Return session metadata without exposing cookie bearer identifiers.

        A separately generated reference is included only for callers with an
        explicit session-management capability. It selects a target for a
        privileged revoke operation but is never accepted for authentication.
        Other callers receive a short stable hash for inventory/audit views.
        """
        current = time.time() if now is None else now
        sessions = self.active(current)
        monotonic_current = time.monotonic()
        result: list[dict[str, object]] = []
        with self._lock:
            for session in sessions:
                if (
                    self._sessions.get(session.session_id) is not session
                    or self._session_is_invalidating_locked(session.session_id, session)
                ):
                    continue
                if now is None:
                    idle_elapsed = monotonic_current - session.last_seen_monotonic
                    absolute_elapsed = monotonic_current - session.created_monotonic
                else:
                    idle_elapsed = current - session.last_seen
                    absolute_elapsed = current - session.created_at
                result.append({
                    "id": session.revocation_ref if include_revocation_refs else "",
                    "id_hash": hashlib.sha256(session.revocation_ref.encode("utf-8")).hexdigest()[:16],
                    "username": session.username,
                    "role": normalize_role(session.role),
                    "created_at": int(session.created_at),
                    "last_seen": int(session.last_seen),
                    "idle_seconds": max(0, int(idle_elapsed)),
                    "idle_remaining": max(0, int(self.idle_seconds - idle_elapsed)),
                    "absolute_remaining": max(0, int(self.absolute_seconds - absolute_elapsed)),
                    "source_address": session.source_address or "unknown",
                    "user_agent": session.user_agent or "unknown",
                    "auth_method": session.auth_method,
                    "current": bool(session.session_id and session.session_id == current_session_id),
                })
        return result

    def revoke_by_reference(self, revocation_ref: str) -> bool:
        """Revoke the session selected by a non-authenticating reference."""
        if not isinstance(revocation_ref, str) or not revocation_ref:
            return False
        with self._lock:
            session_id = self._revocation_sessions.get(revocation_ref)
        return self.revoke(session_id) if session_id else False

    def revoke(self, session_id: str) -> bool:
        """Revoke one dashboard session after any authorized emit completes."""
        lock_and_state = self._role_lock_for_mutation(session_id)
        if lock_and_state is None:
            return False
        check_lock, acquired = lock_and_state
        if not acquired:
            self._acquire_sync_lock(check_lock)
        try:
            with self._lock:
                existed = session_id in self._sessions
                self._drop_session_locked(session_id)
                return existed
        finally:
            with self._lock:
                self._clear_invalidating_locked((session_id,))
            check_lock.release()

    def revoke_account_sessions(
        self, username: str, *, already_invalidating: bool = False
    ) -> int:
        """Revoke every active RouterOS dashboard session for one account.

        The account is denied from the moment invalidation begins. Session-set
        locking prevents a concurrent login or rotation from escaping the
        sweep, and each per-session delivery lock drains already-authorized
        live sends before credentials are dropped.
        """
        if not isinstance(username, str):
            return 0
        username_key = username.strip().casefold()
        if not username_key:
            return 0

        if not already_invalidating:
            with self._lock:
                self._mark_account_invalidating_locked(username_key)

        candidates: list[str] = []
        check_locks: list[threading.Lock] = []
        acquired: list[threading.Lock] = []
        session_set_acquired = False
        revocation_complete = False
        try:
            try:
                self._acquire_sync_lock(self._session_set_lock)
            except SessionStoreLockUnavailable:
                self._schedule_account_revocation_retry(username_key)
                return 0
            session_set_acquired = True
            with self._lock:
                candidates = sorted(
                    session_id
                    for session_id, session in self._sessions.items()
                    if session.auth_method == "routeros"
                    and session.username.casefold() == username_key
                )
                self._mark_invalidating_locked(candidates)
                check_locks = [
                    self._role_check_locks.setdefault(session_id, threading.Lock())
                    for session_id in candidates
                ]
                try:
                    acquired_in_loop = self._acquire_role_check_locks_in_event_loop(
                        check_locks
                    )
                except SessionStoreLockUnavailable:
                    self._schedule_account_revocation_retry(username_key)
                    return 0
                if acquired_in_loop is not None:
                    acquired.extend(acquired_in_loop)

            if acquired_in_loop is None:
                for check_lock in check_locks:
                    check_lock.acquire()
                    acquired.append(check_lock)
            with self._lock:
                current = [
                    session_id
                    for session_id, session in self._sessions.items()
                    if session.auth_method == "routeros"
                    and session.username.casefold() == username_key
                ]
                for session_id in current:
                    self._drop_session_locked(session_id)
                revocation_complete = True
                return len(current)
        finally:
            try:
                with self._lock:
                    self._clear_invalidating_locked(candidates)
                    if revocation_complete:
                        self._clear_account_invalidating_locked(username_key)
            finally:
                for check_lock in reversed(acquired):
                    check_lock.release()
                if session_set_acquired:
                    self._session_set_lock.release()

    def _schedule_account_revocation_retry(self, username_key: str) -> None:
        """Finish a fail-closed revocation off-loop, retrying without cancellation."""
        with self._lock:
            self._pending_account_revocation_retries[username_key] = (
                self._pending_account_revocation_retries.get(username_key, 0) + 1
            )
        self._start_account_revocation_retry(username_key)

    def _start_account_revocation_retry(self, username_key: str) -> None:
        with self._lock:
            if (
                username_key in self._running_account_revocation_retries
                or self._pending_account_revocation_retries.get(username_key, 0) <= 0
            ):
                return
            self._running_account_revocation_retries.add(username_key)
        worker = threading.Thread(
            target=self._run_account_revocation_retries,
            args=(username_key,),
            daemon=True,
            name="session-revocation-retry",
        )
        try:
            worker.start()
        except Exception as error:
            with self._lock:
                self._running_account_revocation_retries.discard(username_key)
            LOGGER.warning(
                "Could not start deferred session revocation (%s); account remains denied",
                type(error).__name__,
            )
            asyncio.get_running_loop().call_later(
                1.0, self._start_account_revocation_retry, username_key
            )

    def _run_account_revocation_retries(self, username_key: str) -> None:
        delay = 0.05
        while True:
            with self._lock:
                retries = self._pending_account_revocation_retries.get(
                    username_key, 0
                )
                if retries <= 0:
                    self._running_account_revocation_retries.discard(username_key)
                    return
            try:
                self.revoke_account_sessions(
                    username_key, already_invalidating=True
                )
            except Exception:
                LOGGER.warning(
                    "Deferred session revocation sweep failed; account remains denied"
                )
                time.sleep(delay)
                delay = min(delay * 2, 30)
                continue
            with self._lock:
                retries = self._pending_account_revocation_retries.get(
                    username_key, 0
                )
                if retries <= 1:
                    self._pending_account_revocation_retries.pop(username_key, None)
                else:
                    self._pending_account_revocation_retries[username_key] = retries - 1

    async def revoke_account_sessions_async(self, username: str) -> int:
        return await asyncio.to_thread(self.revoke_account_sessions, username)

    def revoke_account_sessions_except(
        self, username: str, keep_session_id: str
    ) -> int | None:
        """Revoke other account sessions only while the caller is still active.

        ``None`` means the caller disappeared, rotated, or began invalidation
        before the sweep acquired the session-set lock. Returning without
        revocation prevents a stale caller ID from accidentally revoking its
        replacement session.
        """
        if not isinstance(username, str) or not isinstance(keep_session_id, str):
            return 0
        username_key = username.strip().casefold()
        if not username_key or not keep_session_id:
            return 0

        self._acquire_sync_lock(self._session_set_lock)
        try:
            with self._lock:
                caller = self._sessions.get(keep_session_id)
                if (
                    caller is None
                    or caller.auth_method != "routeros"
                    or caller.username.casefold() != username_key
                    or self._session_is_invalidating_locked(keep_session_id, caller)
                ):
                    return None
                candidates = sorted(
                    session_id
                    for session_id, session in self._sessions.items()
                    if session_id != keep_session_id
                    and session.auth_method == "routeros"
                    and session.username.casefold() == username_key
                )
                locks = [
                    self._role_check_locks.setdefault(session_id, threading.Lock())
                    for session_id in candidates
                ]
                acquired_in_loop = self._acquire_role_check_locks_in_event_loop(locks)
                if acquired_in_loop is not None:
                    try:
                        self._mark_invalidating_locked(candidates)
                        current = [key for key in candidates if key in self._sessions]
                        for session_id in current:
                            self._drop_session_locked(session_id)
                        return len(current)
                    finally:
                        self._clear_invalidating_locked(candidates)
                        for check_lock in reversed(acquired_in_loop):
                            check_lock.release()
                self._mark_invalidating_locked(candidates)

            acquired: list[threading.Lock] = []
            try:
                for check_lock in locks:
                    check_lock.acquire()
                    acquired.append(check_lock)
                with self._lock:
                    current = [key for key in candidates if key in self._sessions]
                    for session_id in current:
                        self._drop_session_locked(session_id)
                    return len(current)
            finally:
                with self._lock:
                    self._clear_invalidating_locked(candidates)
                for check_lock in reversed(acquired):
                    check_lock.release()
        finally:
            self._session_set_lock.release()

    async def revoke_account_sessions_except_async(
        self, username: str, keep_session_id: str
    ) -> int | None:
        return await asyncio.to_thread(
            self.revoke_account_sessions_except, username, keep_session_id
        )

    def revoke_all_except(self, session_id: str) -> int:
        self._acquire_sync_lock(self._session_set_lock)
        try:
            return self._revoke_all_except_with_session_set_lock(session_id)
        finally:
            self._session_set_lock.release()

    def _revoke_all_except_with_session_set_lock(self, session_id: str) -> int:
        """Revoke every dashboard session except the caller's session."""
        with self._lock:
            candidates = sorted(key for key in self._sessions if key != session_id)
            locks: list[threading.Lock] = []
            for key in candidates:
                locks.append(
                    self._role_check_locks.setdefault(key, threading.Lock())
                )
            acquired = self._acquire_role_check_locks_in_event_loop(locks)
            if acquired is not None:
                try:
                    self._mark_invalidating_locked(candidates)
                    for key in candidates:
                        self._drop_session_locked(key)
                    return len(candidates)
                finally:
                    self._clear_invalidating_locked(candidates)
                    for check_lock in reversed(acquired):
                        check_lock.release()
            self._mark_invalidating_locked(candidates)
        for check_lock in locks:
            check_lock.acquire()
        try:
            with self._lock:
                existing = [key for key in candidates if key in self._sessions]
                for key in existing:
                    self._drop_session_locked(key)
                return len(existing)
        finally:
            with self._lock:
                self._clear_invalidating_locked(candidates)
            for check_lock in reversed(locks):
                check_lock.release()

    async def get_async(
        self, session_id: str, now: float | None = None, *, touch: bool = True
    ) -> Session | None:
        """Run the synchronous lookup off-loop when expiry may wait on delivery."""
        return await asyncio.to_thread(self.get, session_id, now, touch=touch)

    async def destroy_async(self, session_id: str) -> None:
        await asyncio.to_thread(self.destroy, session_id)

    async def rotate_async(
        self,
        session_id: str,
        password: str,
        *,
        role: str,
        now: float | None = None,
    ) -> Session | None:
        return await asyncio.to_thread(
            self.rotate, session_id, password, role=role, now=now
        )

    async def purge_async(self, now: float | None = None) -> int:
        return await asyncio.to_thread(self.purge, now)

    async def revoke_async(self, session_id: str) -> bool:
        return await asyncio.to_thread(self.revoke, session_id)

    async def revoke_all_except_async(self, session_id: str) -> int:
        return await asyncio.to_thread(self.revoke_all_except, session_id)


class LoginRateLimiter:
    RATE_LIMITED_LOGIN_AUDIT_INTERVAL_SECONDS = 60.0
    ADMIN_ACCOUNT_RATE_LIMITED_AUDIT_INTERVAL_SECONDS = 60.0
    MAX_SUPPRESSED_LOGIN_AUDIT_COUNT = 1_000_000_000

    def __init__(
        self,
        limit: int = 5,
        window_seconds: int = 300,
        *,
        max_tracked_identities: int = 4096,
        max_in_flight: int = 256,
        rate_limited_login_audit_interval_seconds: float = RATE_LIMITED_LOGIN_AUDIT_INTERVAL_SECONDS,
    ) -> None:
        self.limit = limit
        self.window_seconds = window_seconds
        self.max_tracked_identities = max(1, int(max_tracked_identities))
        self.max_in_flight = max(1, int(max_in_flight))
        self.rate_limited_login_audit_interval_seconds = max(
            1.0, float(rate_limited_login_audit_interval_seconds)
        )
        self._attempts: dict[str, list[float]] = {}
        self._reservations: dict[str, str] = {}
        self._last_rate_limited_login_audit_at: float | None = None
        self._suppressed_rate_limited_login_audits = 0
        self._rate_limited_login_audit_in_flight = False
        self._reserved_rate_limited_login_audit_count = 0
        self._suppressed_during_rate_limited_login_audit = 0
        self._last_admin_account_rate_limited_audit_at: float | None = None
        self._lock = threading.Lock()

    def reserve_admin_account_rate_limited_audit(self, now: float | None = None) -> bool:
        """Allow at most one admin-account rate-limit audit event per interval."""
        current = time.monotonic() if now is None else float(now)
        with self._lock:
            previous = self._last_admin_account_rate_limited_audit_at
            if (
                previous is not None
                and current - previous < self.ADMIN_ACCOUNT_RATE_LIMITED_AUDIT_INTERVAL_SECONDS
            ):
                return False
            self._last_admin_account_rate_limited_audit_at = current
            return True

    def reserve_rate_limited_login_audit(self, now: float | None = None) -> int | None:
        """Coalesce public login-limit audit writes to one per interval.

        Return the number of suppressed attempts accumulated since the previous
        audit when a caller may persist an aggregate event. The reservation must
        be completed with :meth:`complete_rate_limited_login_audit` after the
        persistence attempt. Return ``None`` for requests inside the current
        interval or while a write is in flight. State is constant-sized and
        shared across identities so a source-address spray cannot grow it.
        """
        current = time.monotonic() if now is None else float(now)
        with self._lock:
            previous = self._last_rate_limited_login_audit_at
            if self._rate_limited_login_audit_in_flight:
                self._suppressed_during_rate_limited_login_audit = min(
                    self._suppressed_during_rate_limited_login_audit + 1,
                    self.MAX_SUPPRESSED_LOGIN_AUDIT_COUNT,
                )
                return None
            if (
                previous is not None
                and current - previous < self.rate_limited_login_audit_interval_seconds
            ):
                self._suppressed_rate_limited_login_audits = min(
                    self._suppressed_rate_limited_login_audits + 1,
                    self.MAX_SUPPRESSED_LOGIN_AUDIT_COUNT,
                )
                return None

            suppressed = self._suppressed_rate_limited_login_audits
            self._suppressed_rate_limited_login_audits = 0
            self._last_rate_limited_login_audit_at = current
            self._rate_limited_login_audit_in_flight = True
            self._reserved_rate_limited_login_audit_count = suppressed
            self._suppressed_during_rate_limited_login_audit = 0
            return suppressed

    def complete_rate_limited_login_audit(self, *, succeeded: bool) -> None:
        """Commit or release a reserved aggregate audit write.

        Keep its suppressed count pending until persistence succeeds. A failed
        write itself is added to the next aggregate, and the reservation time
        remains in place to bound retries to one per interval.
        """
        with self._lock:
            if not self._rate_limited_login_audit_in_flight:
                return

            reserved_count = self._reserved_rate_limited_login_audit_count
            suppressed_during_write = self._suppressed_during_rate_limited_login_audit
            if succeeded:
                self._suppressed_rate_limited_login_audits = suppressed_during_write
            else:
                self._suppressed_rate_limited_login_audits = min(
                    reserved_count + suppressed_during_write + 1,
                    self.MAX_SUPPRESSED_LOGIN_AUDIT_COUNT,
                )
            self._rate_limited_login_audit_in_flight = False
            self._reserved_rate_limited_login_audit_count = 0
            self._suppressed_during_rate_limited_login_audit = 0

    def reserve(self, identity: str, now: float | None = None) -> str | None:
        """Atomically reserve an authentication attempt, or return ``None`` if limited.

        Reservations count against the limit while RouterOS verification is in
        flight, closing the check-then-record race between concurrent requests.
        Call :meth:`finish` exactly once when verification completes.
        """
        current = time.time() if now is None else now
        threshold = current - self.window_seconds
        with self._lock:
            tracked_identities = set(self._reservations.values())
            for tracked_identity, history in tuple(self._attempts.items()):
                recent = [stamp for stamp in history if stamp > threshold]
                if recent:
                    self._attempts[tracked_identity] = recent
                    tracked_identities.add(tracked_identity)
                else:
                    self._attempts.pop(tracked_identity, None)

            if len(self._reservations) >= self.max_in_flight:
                return None
            if (
                identity not in tracked_identities
                and len(tracked_identities) >= self.max_tracked_identities
            ):
                return None

            attempts = [stamp for stamp in self._attempts.get(identity, []) if stamp > threshold]
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
    "Referrer-Policy": "same-origin",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
}
