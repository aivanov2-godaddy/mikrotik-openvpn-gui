"""Runtime wiring for the read-only live telemetry migration.

The existing REST client remains the mutation and fallback path.  This module
only owns a short-lived, in-memory Binary API-SSL connection and a redacted
telemetry broker.  RouterOS credentials are read from an already authenticated
dashboard session and are never copied into the broker or delivery layer.
"""

from __future__ import annotations

import hmac
import threading
from urllib.parse import urlsplit
from typing import Any, Callable, Iterable, Mapping

from routeros_binary import RouterOSBinaryConnection
from security import (
    LIVE_STREAM_ROLE_REVALIDATION_SECONDS,
    SESSION_ROLE_REVALIDATION_SECONDS,
    SessionStore,
)
from telemetry_broker import TelemetryBroker, TelemetryEvent
from telemetry_gateway import TelemetryGatewayContract, TelemetryPrincipal
from telemetry_state import TelemetryRuntimeState
from telemetry_supervisor import (
    TelemetryInterfaceSampler,
    TelemetryCredentialLease,
    TelemetrySupervisor,
    TelemetrySupervisorConfig,
)

MAX_CONCURRENT_LIVE_ROLE_REFRESHES = 4


class TelemetryRuntime:
    """Start and stop the Binary API telemetry workers for one dashboard."""

    _live_role_refresh_slots = threading.BoundedSemaphore(
        MAX_CONCURRENT_LIVE_ROLE_REFRESHES
    )

    def __init__(
        self,
        *,
        sessions: SessionStore,
        rest_url: str,
        ca_file: str | None,
        insecure_tls: bool,
        api_ssl_port: int,
        requested_transport: str,
        role_resolver: Callable[[Any], str | None] | None = None,
        on_session_snapshot: Callable[[list[dict[str, Any]]], None] | None = None,
    ) -> None:
        self.sessions = sessions
        self.role_resolver = role_resolver
        self.on_session_snapshot = on_session_snapshot
        self.requested_transport = requested_transport
        self.enabled = requested_transport in {"binary", "auto"}
        parsed = urlsplit(rest_url)
        self.host = parsed.hostname or "127.0.0.1"
        self.ca_file = ca_file
        self.insecure_tls = insecure_tls
        self.api_ssl_port = int(api_ssl_port)
        self.state = TelemetryRuntimeState(
            requested_transport,
            effective_transport="socketio" if self.enabled else "sse",
            socketio_enabled=self.enabled,
        )
        self.broker = TelemetryBroker()
        self.gateway = TelemetryGatewayContract(self.broker)
        self._stop = threading.Event()
        self._workers: list[threading.Thread] = []
        self.supervisor: TelemetrySupervisor | None = None
        self.sampler: TelemetryInterfaceSampler | None = None

        if self.enabled:
            self.supervisor = TelemetrySupervisor(
                self._connection,
                self._credential_lease,
                broker=self.broker,
                snapshot_reader=self._session_snapshot,
                config=TelemetrySupervisorConfig(enabled=True),
                stop_event=self._stop,
                on_events=self._publish,
                on_events_after_dispatch=self._persist_session_snapshot,
                authorization_ref_check=self._authorization_ref_valid,
                authorization_ref_dispatch=self._dispatch_authorized_events,
            )
            self.sampler = TelemetryInterfaceSampler(
                self._connection,
                self._credential_lease,
                self.broker,
                interval=5.0,
                stop_event=self._stop,
                on_sample=self.state.mark_traffic_samples,
                on_events=self._publish,
                authorization_ref_check=self._authorization_ref_valid,
                authorization_ref_dispatch=self._dispatch_authorized_events,
            )

    def start(self) -> None:
        if not self.enabled:
            return
        assert self.supervisor is not None
        assert self.sampler is not None
        self._workers = [
            threading.Thread(target=self.supervisor.run_forever, name="vpn-dashboard-binary", daemon=True),
            threading.Thread(target=self._run_sampler, name="vpn-dashboard-interface-sampler", daemon=True),
        ]
        for worker in self._workers:
            worker.start()

    def stop(self) -> None:
        self._stop.set()
        if self.supervisor is not None:
            self.supervisor.stop()
        if self.sampler is not None:
            self.sampler.stop()
        for worker in self._workers:
            worker.join(timeout=2)

    def status(self) -> dict[str, Any]:
        value = self.state.as_dict()
        value["gateway"] = self.gateway.metrics()
        if self.supervisor is not None:
            value["supervisor"] = self.supervisor.health().as_dict()
        return value

    def principal_for_session(
        self, session_id: str, *, force_role_check: bool = False
    ) -> TelemetryPrincipal | None:
        # Live-stream authorization is a read-only revalidation, not evidence
        # of operator activity. Otherwise an unattended socket could keep an
        # otherwise-idle dashboard session alive indefinitely.
        session = self.revalidate_session(
            session_id,
            force_role_check=force_role_check,
            role_revalidation_interval_seconds=LIVE_STREAM_ROLE_REVALIDATION_SECONDS,
        )
        if session is None:
            return None
        return TelemetryPrincipal.from_session(session)

    def cached_principal_for_session(
        self, session_id: str, *, role_check_lock_held: bool = False
    ) -> tuple[bool, TelemetryPrincipal | None]:
        """Resolve only from local state, reporting whether it is authoritative.

        A false first element means a RouterOS role refresh is due; callers
        must perform that refresh before authorizing or emitting telemetry.
        """
        if getattr(self, "role_resolver", None) is None:
            session = self.sessions.get(
                session_id,
                touch=False,
                role_check_lock_held=role_check_lock_held,
                wait_for_role_check_lock=False,
            )
            return True, TelemetryPrincipal.from_session(session)
        fresh, session = self.sessions.cached_role_session(
            session_id,
            interval_seconds=LIVE_STREAM_ROLE_REVALIDATION_SECONDS,
            role_check_lock_held=role_check_lock_held,
        )
        principal = TelemetryPrincipal.from_session(session) if session is not None else None
        return fresh, principal

    def role_check_lock_for_session(self, session_id: str) -> threading.Lock | None:
        """Return the lock that serializes RouterOS role refresh and delivery."""
        return self.sessions.role_check_lock(session_id)

    def revalidate_session(
        self,
        session_id: str,
        *,
        force_role_check: bool = False,
        role_revalidation_interval_seconds: int = SESSION_ROLE_REVALIDATION_SECONDS,
    ):
        """Re-check a dashboard session and its RouterOS-derived role.

        Ordinary authenticated requests retain the standard role-cache
        interval; live transports pass their shorter interval explicitly.
        Session role checks are bounded and do not extend idle lifetime. Tests
        or embedders without RouterOS access may omit the resolver; production
        wires the existing RouterOS REST client.
        """
        role_resolver = getattr(self, "role_resolver", None)
        if role_resolver is None:
            return self.sessions.get(session_id, touch=False)
        is_live_check = (
            role_revalidation_interval_seconds
            <= LIVE_STREAM_ROLE_REVALIDATION_SECONDS
        )
        if is_live_check and not force_role_check:
            fresh, cached_session = self.sessions.cached_role_session(
                session_id,
                interval_seconds=role_revalidation_interval_seconds,
            )
            if fresh:
                return cached_session

        if is_live_check and not self._live_role_refresh_slots.acquire(
            blocking=False
        ):
            return None
        try:
            return self.sessions.revalidate_role(
                session_id,
                role_resolver,
                interval_seconds=(
                    0 if force_role_check else role_revalidation_interval_seconds
                ),
            )
        finally:
            if is_live_check:
                self._live_role_refresh_slots.release()

    def _connection(self) -> RouterOSBinaryConnection:
        return RouterOSBinaryConnection(
            self.host,
            port=self.api_ssl_port,
            ca_file=self.ca_file,
            timeout=10.0,
            insecure_tls=self.insecure_tls,
        )

    def _credentials(self) -> tuple[str, str]:
        for session in self.sessions.active():
            if session.auth_method != "routeros":
                continue
            try:
                return self._credentials_for_session(session)
            except RuntimeError:
                continue
        raise RuntimeError("credentials_unavailable")

    def _credential_lease(self) -> TelemetryCredentialLease:
        for session in self.sessions.active():
            if session.auth_method != "routeros":
                continue
            try:
                current = self._validated_session(session)
            except RuntimeError:
                continue
            return TelemetryCredentialLease(
                current.username, current.password, current.authorization_ref
            )
        raise RuntimeError("credentials_unavailable")

    def _authorization_ref_valid(self, authorization_ref: str) -> bool:
        """Authorize a stream by its sensitive, internal source-session reference."""

        if not authorization_ref:
            return False
        for session in self.sessions.active():
            if session.auth_method != "routeros" or not hmac.compare_digest(
                session.authorization_ref.encode("utf-8"),
                authorization_ref.encode("utf-8"),
            ):
                continue
            try:
                current = self._validated_session(session)
            except RuntimeError:
                return False
            return hmac.compare_digest(
                current.authorization_ref.encode("utf-8"),
                authorization_ref.encode("utf-8"),
            )
        return False

    def _dispatch_authorized_events(
        self, authorization_ref: str, dispatch: Callable[[], None]
    ) -> bool:
        """Publish only while the source session is atomically still active."""

        return self.sessions.dispatch_if_active_authorization_ref(
            authorization_ref, dispatch
        )

    def _credentials_valid(self, username: str, password: str) -> bool:
        """Confirm the exact RouterOS credential pair still has a live session."""

        for session in self.sessions.active():
            if session.auth_method != "routeros":
                continue
            try:
                current_username, current_password = self._credentials_for_session(session)
            except RuntimeError:
                continue
            if hmac.compare_digest(
                current_username.encode("utf-8"), username.encode("utf-8")
            ) and hmac.compare_digest(current_password.encode("utf-8"), password.encode("utf-8")):
                return True
        return False

    def _credentials_for_session(self, session: Any) -> tuple[str, str]:
        """Revalidate one session without extending its idle lifetime."""

        current = self._validated_session(session)
        return current.username, current.password

    def _validated_session(self, session: Any) -> Any:
        """Return the exact active RouterOS session after role revalidation."""

        if self.role_resolver is None:
            current = self.sessions.get(session.session_id, touch=False)
        else:
            current = self.sessions.revalidate_role(
                session.session_id,
                self.role_resolver,
                interval_seconds=5,
            )
        if (
            current is None
            or current.auth_method != "routeros"
            or not current.username
            or not current.password
        ):
            raise RuntimeError("credentials_unavailable")
        return current

    @staticmethod
    def _session_snapshot(connection: RouterOSBinaryConnection) -> Iterable[Mapping[str, Any]]:
        query = (
            ".proplist=.id,name,address,caller-id,uptime,encoding,service,rx-byte,tx-byte,rx-packet,tx-packet",
        )
        replies = connection.execute("/ppp/active/print", query=query)
        return [dict(reply.attributes) for reply in replies if reply.kind == "re"]

    def _publish(self, events: list[TelemetryEvent]) -> None:
        if not events:
            return
        self.gateway.publish(events)

        session_events = sum(
            event.name.startswith("vpn.session.") or event.name == "telemetry.snapshot"
            for event in events
        )
        if session_events:
            self.state.mark_session_events(
                session_events,
                reconciliation=any(event.name == "telemetry.snapshot" for event in events),
            )

    def _persist_session_snapshot(self, events: list[TelemetryEvent]) -> None:
        history_error = False
        if self.on_session_snapshot is not None:
            for event in events:
                if event.name != "telemetry.snapshot":
                    continue
                payload = event.payload if isinstance(event.payload, dict) else {}
                sessions = payload.get("sessions", [])
                if not isinstance(sessions, list):
                    continue
                try:
                    self.on_session_snapshot(sessions)
                except Exception:  # noqa: BLE001 - persistence must not stop live delivery
                    history_error = True
        if history_error:
            self.state.mark_error("session_history_unavailable")

    def _run_sampler(self) -> None:
        assert self.sampler is not None
        while not self._stop.is_set():
            try:
                self.sampler.sample_once()
            except Exception as error:  # noqa: BLE001 - telemetry must not stop the dashboard
                self.state.mark_error(self._error_code(error))
                self._stop.wait(5)
            else:
                self._stop.wait(5)

    @staticmethod
    def _error_code(error: Exception) -> str:
        text = str(error).strip().lower()
        if "credential" in text:
            return "credentials_unavailable"
        if isinstance(error, TimeoutError):
            return "timeout"
        return "binary_api_unavailable"
