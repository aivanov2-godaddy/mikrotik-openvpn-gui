"""Runtime wiring for the read-only live telemetry migration.

The existing REST client remains the mutation and fallback path.  This module
only owns a short-lived, in-memory Binary API-SSL connection and a redacted
telemetry broker.  RouterOS credentials are read from an already authenticated
dashboard session and are never copied into the broker or delivery layer.
"""

from __future__ import annotations

import threading
from urllib.parse import urlsplit
from typing import Any, Iterable, Mapping

from routeros_binary import RouterOSBinaryConnection
from security import SessionStore
from telemetry_broker import TelemetryBroker, TelemetryEvent
from telemetry_gateway import TelemetryGatewayContract, TelemetryPrincipal
from telemetry_state import TelemetryRuntimeState
from telemetry_supervisor import (
    TelemetryInterfaceSampler,
    TelemetrySupervisor,
    TelemetrySupervisorConfig,
)


class TelemetryRuntime:
    """Start and stop the Binary API telemetry workers for one dashboard."""

    def __init__(
        self,
        *,
        sessions: SessionStore,
        rest_url: str,
        ca_file: str | None,
        insecure_tls: bool,
        api_ssl_port: int,
        requested_transport: str,
    ) -> None:
        self.sessions = sessions
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
                self._credentials,
                broker=self.broker,
                snapshot_reader=self._session_snapshot,
                config=TelemetrySupervisorConfig(enabled=True),
                stop_event=self._stop,
                on_events=self._publish,
            )
            self.sampler = TelemetryInterfaceSampler(
                self._connection,
                self._credentials,
                self.broker,
                interval=5.0,
                stop_event=self._stop,
                on_events=self._publish,
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

    def principal_for_session(self, session_id: str) -> TelemetryPrincipal | None:
        # Live-stream authorization is a read-only revalidation, not evidence
        # of operator activity. Otherwise an unattended socket could keep an
        # otherwise-idle dashboard session alive indefinitely.
        session = self.sessions.get(session_id, touch=False)
        if session is None:
            return None
        return TelemetryPrincipal.from_session(session)

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
            if session.auth_method == "routeros" and session.username and session.password:
                return session.username, session.password
        raise RuntimeError("credentials_unavailable")

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
        traffic_samples = sum(event.name == "vpn.interface.counters" for event in events)
        if session_events:
            self.state.mark_session_events(
                session_events,
                reconciliation=any(event.name == "telemetry.snapshot" for event in events),
            )
        if traffic_samples:
            self.state.mark_traffic_samples(traffic_samples)

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
