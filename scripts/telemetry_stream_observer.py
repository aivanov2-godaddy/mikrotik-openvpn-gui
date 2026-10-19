"""Observe a canary Socket.IO telemetry stream and write redacted evidence.

This read-only operator tool records event names, sequence integrity, and
connection lifecycle only. It deliberately discards event payloads and never
connects to a production-looking origin. RouterOS credentials and APIs are
not used. A short-lived dashboard cookie is read from a named environment
variable and is never printed or persisted.
"""

from __future__ import annotations

import argparse
import asyncio
from collections import Counter
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import re
import tempfile
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


NAMESPACE = "/telemetry"
CANARY_HOST = "vpn-dev.wanted.sx"
CANARY_ORIGIN = f"https://{CANARY_HOST}"
REVISION_PATTERN = re.compile(r"^[0-9a-f]{40}$")
MAX_DURATION_SECONDS = 1800
MAX_COOKIE_LENGTH = 8192
MAX_SEQUENCES_PER_EPOCH = 100_000
SESSION_FIELDS = frozenset(
    {
        "id",
        "name",
        "vpn_address",
        "source_address",
        "uptime",
        "encoding",
        "service",
        "rx_bytes",
        "tx_bytes",
        "rx_packets",
        "tx_packets",
        "counter_complete",
    }
)
COUNTER_FIELDS = frozenset(
    {
        "id",
        "name",
        "rx_bytes",
        "tx_bytes",
        "rx_packets",
        "tx_packets",
        "rx_bytes_per_second",
        "tx_bytes_per_second",
        "rx_packets_per_second",
        "tx_packets_per_second",
    }
)
REQUIRED_COUNTER_FIELDS = frozenset({"id", "name", "rx_bytes", "tx_bytes", "rx_packets", "tx_packets"})
SUPPORTED_EVENTS = frozenset(
    {
        "telemetry.snapshot",
        "vpn.session.connected",
        "vpn.session.updated",
        "vpn.session.disconnected",
        "vpn.interface.counters",
        "telemetry.counter_reset",
        "router.capacity.updated",
        "router.health.updated",
        "telemetry.reconciled",
    }
)
HEALTH_STATES = frozenset({"healthy", "connecting", "degraded"})
SAFE_EVENT_NAME = re.compile(r"^[a-z][a-z0-9_.]{0,63}$")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def validate_canary_origin(value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("origin must be a credential-free HTTPS origin")
    try:
        port = parsed.port
    except ValueError as error:
        raise ValueError("origin port is invalid") from error
    if parsed.hostname.casefold().rstrip(".") != CANARY_HOST or port not in {None, 443}:
        raise ValueError("origin must exactly match the approved canary host")
    return CANARY_ORIGIN


def validate_revision(value: str) -> str:
    if not isinstance(value, str) or not REVISION_PATTERN.fullmatch(value):
        raise ValueError("candidate revision must be a full lowercase Git SHA")
    return value


class _RejectRedirects(HTTPRedirectHandler):
    """Never forward a session cookie through an HTTP redirect."""

    def redirect_request(self, req: Request, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


def fetch_runtime_revision(origin: str, cookie: str) -> str:
    """Read only the authenticated runtime revision from the pinned canary."""
    approved_origin = validate_canary_origin(origin)
    request = Request(
        f"{approved_origin}/api/observability",
        headers={"Accept": "application/json", "Cookie": cookie, "Origin": approved_origin},
        method="GET",
    )
    opener = build_opener(_RejectRedirects())
    try:
        with opener.open(request, timeout=15) as response:
            if response.status != 200:
                raise ValueError("runtime revision endpoint was not authorized")
            body = response.read(65_537)
    except (HTTPError, URLError, OSError) as error:
        raise ValueError("runtime revision endpoint could not be verified") from error
    if len(body) > 65_536:
        raise ValueError("runtime revision response exceeded its size limit")
    try:
        payload = json.loads(body)
        revision = payload["current"]["revision"]
    except (json.JSONDecodeError, KeyError, TypeError) as error:
        raise ValueError("runtime revision response was invalid") from error
    return validate_revision(revision)


def _non_negative_int(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{name} must be a non-negative integer")
    return value


def _validate_session(value: Any) -> None:
    if not isinstance(value, dict) or set(value) - SESSION_FIELDS:
        raise ValueError("session frame is outside the redacted field allowlist")


def validate_frame(event_name: str, frame: Any) -> tuple[int | None, str]:
    """Validate an incoming event without returning or retaining its payload."""
    if event_name == "telemetry.health":
        if (
            not isinstance(frame, dict)
            or set(frame) != {"state", "stream_connected"}
            or frame.get("state") not in HEALTH_STATES
            or not isinstance(frame.get("stream_connected"), bool)
        ):
            raise ValueError("health frame is outside the redacted field allowlist")
        return None, event_name

    if event_name not in SUPPORTED_EVENTS or not SAFE_EVENT_NAME.fullmatch(event_name):
        raise ValueError("unsupported telemetry event")
    if not isinstance(frame, dict) or set(frame) != {
        "protocol_version",
        "event",
        "sequence",
        "router_timestamp",
        "payload",
    }:
        raise ValueError("telemetry frame schema is invalid")
    if frame.get("protocol_version") != 1 or frame.get("event") != event_name:
        raise ValueError("telemetry protocol or event name is invalid")
    sequence = _non_negative_int(frame.get("sequence"), "sequence")
    _non_negative_int(frame.get("router_timestamp"), "router_timestamp")
    payload = frame.get("payload")
    if not isinstance(payload, dict):
        raise ValueError("telemetry payload is invalid")

    if event_name == "telemetry.snapshot":
        if set(payload) != {"sessions"} or not isinstance(payload["sessions"], list):
            raise ValueError("snapshot frame schema is invalid")
        for session in payload["sessions"]:
            _validate_session(session)
    elif event_name in {"vpn.session.connected", "vpn.session.updated", "vpn.session.disconnected"}:
        _validate_session(payload)
    elif event_name == "vpn.interface.counters":
        if set(payload) - COUNTER_FIELDS or not REQUIRED_COUNTER_FIELDS.issubset(payload):
            raise ValueError("interface frame is outside the redacted field allowlist")
        if (
            not isinstance(payload["id"], str)
            or not payload["id"]
            or not isinstance(payload["name"], str)
            or not payload["name"]
        ):
            raise ValueError("interface identity is invalid")
        for field in ("rx_bytes", "tx_bytes", "rx_packets", "tx_packets"):
            _non_negative_int(payload[field], field)
    elif event_name == "telemetry.counter_reset":
        if set(payload) - {"scope", "id", "name", "fields"}:
            raise ValueError("counter-reset frame is outside the redacted field allowlist")
    else:
        if set(payload) - {"cpu_percent", "memory_percent", "storage_percent", "status", "age_seconds"}:
            raise ValueError("health frame is outside the redacted field allowlist")
    return sequence, event_name


class TelemetryStreamRecorder:
    """Bounded in-memory sequence observer; payload values are never retained."""

    def __init__(self) -> None:
        self.connected = False
        self.connections = 0
        self.disconnects = 0
        self.reconnects = 0
        self.rejected_frames = 0
        self.events = 0
        self.snapshots = 0
        self.reconnect_snapshot_count = 0
        self._awaiting_reconnect_snapshot = False
        self.sequence_gaps = 0
        self.duplicate_sequences = 0
        self.out_of_order_sequences = 0
        self._counts: Counter[str] = Counter()
        self._epoch = -1
        self._last_sequence: int | None = None
        self._seen_sequences: set[int] = set()
        self._sequences_in_epoch = 0

    def on_connect(self) -> None:
        if self.connected:
            return
        if self.connections:
            self.reconnects += 1
            self._awaiting_reconnect_snapshot = True
        self.connections += 1
        self.connected = True
        self._epoch += 1
        self._last_sequence = None
        self._seen_sequences.clear()
        self._sequences_in_epoch = 0

    def on_disconnect(self, *, unexpected: bool = True) -> None:
        if self.connected:
            self.disconnects += int(unexpected)
        self.connected = False

    def record(self, event_name: str, frame: Any) -> None:
        try:
            sequence, name = validate_frame(event_name, frame)
        except (TypeError, ValueError):
            self.rejected_frames += 1
            return
        self.events += 1
        self._counts[name] += 1
        if name == "telemetry.snapshot":
            self.snapshots += 1
            if self._awaiting_reconnect_snapshot:
                self.reconnect_snapshot_count += 1
                self._awaiting_reconnect_snapshot = False
        if sequence is None:
            return
        self._sequences_in_epoch += 1
        if self._sequences_in_epoch > MAX_SEQUENCES_PER_EPOCH:
            self.rejected_frames += 1
            self._counts[name] -= 1
            self.events -= 1
            self._sequences_in_epoch -= 1
            return
        if sequence in self._seen_sequences:
            self.duplicate_sequences += 1
        if self._last_sequence is not None:
            if sequence > self._last_sequence + 1:
                self.sequence_gaps += sequence - self._last_sequence - 1
            elif sequence < self._last_sequence:
                self.out_of_order_sequences += 1
        self._seen_sequences.add(sequence)
        if self._last_sequence is None or sequence > self._last_sequence:
            self._last_sequence = sequence

    def report(
        self,
        *,
        started_at: str,
        ended_at: str,
        duration: float,
        connected_at_end: bool | None = None,
    ) -> dict[str, Any]:
        failed_gates = []
        if self.connections == 0:
            failed_gates.append("stream_never_connected")
        if self.events == 0:
            failed_gates.append("no_telemetry_events_observed")
        if self.rejected_frames:
            failed_gates.append("unrecognized_or_unredacted_frame")
        if self.sequence_gaps:
            failed_gates.append("event_sequence_gap")
        if self.duplicate_sequences:
            failed_gates.append("duplicate_event_sequence")
        if self.out_of_order_sequences:
            failed_gates.append("out_of_order_event_sequence")
        return {
            "format": "vpn-dashboard-telemetry-stream-observation-v1",
            "started_at": started_at,
            "ended_at": ended_at,
            "duration_seconds": round(max(0.0, duration), 3),
            "origin_role": "canary",
            "transport": "socketio-websocket",
            "connections": self.connections,
            "disconnects": self.disconnects,
            "reconnects": self.reconnects,
            "stream_connected_at_end": self.connected if connected_at_end is None else connected_at_end,
            "event_count": self.events,
            "event_counts": dict(sorted(self._counts.items())),
            "snapshot_count": self.snapshots,
            "reconnect_snapshot_count": self.reconnect_snapshot_count,
            "sequence_gaps": self.sequence_gaps,
            "duplicate_sequences": self.duplicate_sequences,
            "out_of_order_sequences": self.out_of_order_sequences,
            "rejected_frames": self.rejected_frames,
            "raw_frames_written": False,
            "identities_or_addresses_written": False,
            "credentials_written": False,
            "latency_measured": False,
            "latency_note": "not measured; client/server clock offset is not established",
            "failed_gates": sorted(set(failed_gates)),
            "observed_stream_healthy": not failed_gates,
        }


def _write_atomically(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temporary = Path(stream.name)
            stream.write(json.dumps(report, sort_keys=True, indent=2) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


async def observe(
    origin: str,
    cookie: str,
    duration_seconds: float,
    *,
    expected_revision: str | None = None,
) -> dict[str, Any]:
    import websockets
    from websockets.exceptions import InvalidStatus, WebSocketException

    parsed_origin = urlsplit(origin)
    local_test_origin = (
        parsed_origin.scheme == "http"
        and parsed_origin.hostname in {"127.0.0.1", "localhost", "::1"}
        and expected_revision is None
    )
    if local_test_origin:
        if parsed_origin.path not in {"", "/"} or parsed_origin.query or parsed_origin.fragment:
            raise ValueError("test observer origin must be a bare loopback origin")
    else:
        origin = validate_canary_origin(origin)
        if expected_revision is None:
            raise ValueError("candidate revision is required for live canary observation")
        expected_revision = validate_revision(expected_revision)

    recorder = TelemetryStreamRecorder()
    started_at = _utc_now()
    started = time.monotonic()
    observed_revision: str | None = None
    if expected_revision is not None:
        try:
            observed_revision = await asyncio.to_thread(fetch_runtime_revision, origin, cookie)
        except ValueError:
            failed = recorder.report(
                started_at=started_at,
                ended_at=_utc_now(),
                duration=time.monotonic() - started,
                connected_at_end=False,
            )
            failed.update({
                "origin": origin,
                "candidate_revision": expected_revision,
                "observed_revision": None,
            })
            failed["failed_gates"] = sorted(set(failed["failed_gates"]) | {"candidate_runtime_revision_unverified"})
            failed["observed_stream_healthy"] = False
            return failed
        if observed_revision != expected_revision:
            failed = recorder.report(
                started_at=started_at,
                ended_at=_utc_now(),
                duration=time.monotonic() - started,
                connected_at_end=False,
            )
            failed.update({
                "origin": origin,
                "candidate_revision": expected_revision,
                "observed_revision": observed_revision,
            })
            failed["failed_gates"] = sorted(set(failed["failed_gates"]) | {"candidate_runtime_revision_mismatch"})
            failed["observed_stream_healthy"] = False
            return failed
    parsed = urlsplit(origin)
    scheme = "wss" if parsed.scheme == "https" else "ws"
    websocket_url = f"{scheme}://{parsed.netloc}/socket.io/?EIO=4&transport=websocket"
    deadline = started + duration_seconds
    retry_delay = 0.5
    connected_at_end = False

    while time.monotonic() < deadline:
        websocket = None
        try:
            websocket = await websockets.connect(
                websocket_url,
                additional_headers={"Cookie": cookie, "Origin": origin},
                open_timeout=15,
                ping_interval=None,
                max_size=1_000_000,
            )
            opening_packet = await asyncio.wait_for(websocket.recv(), timeout=15)
            if not isinstance(opening_packet, str) or not opening_packet.startswith("0{"):
                raise ValueError("Engine.IO opening packet is invalid")
            opening = json.loads(opening_packet[1:])
            if not isinstance(opening, dict) or not opening.get("sid"):
                raise ValueError("Engine.IO opening packet is invalid")
            await websocket.send("40/telemetry,")
            namespace_packet = await asyncio.wait_for(websocket.recv(), timeout=15)
            if not isinstance(namespace_packet, str) or namespace_packet.startswith("44/telemetry,"):
                raise ValueError("telemetry namespace was rejected")
            if not namespace_packet.startswith("40/telemetry,"):
                raise ValueError("telemetry namespace acknowledgement is invalid")
            recorder.on_connect()
            retry_delay = 0.5
            while time.monotonic() < deadline:
                try:
                    packet = await asyncio.wait_for(
                        websocket.recv(), timeout=min(1.0, max(0.05, deadline - time.monotonic()))
                    )
                except asyncio.TimeoutError:
                    continue
                if not isinstance(packet, str):
                    recorder.rejected_frames += 1
                    continue
                if packet.startswith("2"):
                    await websocket.send("3" + packet[1:])
                elif packet.startswith("42/telemetry,"):
                    try:
                        event = json.loads(packet[len("42/telemetry,") :])
                    except json.JSONDecodeError:
                        recorder.rejected_frames += 1
                        continue
                    if not isinstance(event, list) or len(event) != 2 or not isinstance(event[0], str):
                        recorder.rejected_frames += 1
                        continue
                    recorder.record(event[0], event[1])
                elif packet.startswith("41/telemetry,") or packet == "1":
                    break
                elif packet.startswith("44/telemetry,"):
                    recorder.rejected_frames += 1
                    break
        except InvalidStatus as error:
            response = getattr(error, "response", None)
            status = getattr(response, "status_code", None)
            if status in {401, 403, 404}:
                break
        except (OSError, ValueError, WebSocketException, asyncio.TimeoutError):
            pass
        finally:
            connected_at_end = recorder.connected
            if recorder.connected:
                recorder.on_disconnect(unexpected=time.monotonic() < deadline)
            if websocket is not None:
                try:
                    await websocket.close()
                except WebSocketException:
                    pass
        if time.monotonic() < deadline:
            await asyncio.sleep(min(retry_delay, max(0.0, deadline - time.monotonic())))
            retry_delay = min(5.0, retry_delay * 2)
    ended = time.monotonic()
    report = recorder.report(
        started_at=started_at,
        ended_at=_utc_now(),
        duration=ended - started,
        connected_at_end=connected_at_end,
    )
    report.update({
        "origin": origin,
        "candidate_revision": expected_revision,
        "observed_revision": observed_revision,
    })
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--canary-origin", required=True, help="must be https://vpn-dev.wanted.sx")
    parser.add_argument("--expected-revision", required=True, help="full lowercase candidate Git SHA")
    parser.add_argument(
        "--cookie-env", required=True, help="environment variable holding the short-lived Cookie header"
    )
    parser.add_argument("--duration-seconds", type=float, default=1800)
    parser.add_argument("--output", required=True, help="private local JSON report path")
    args = parser.parse_args(argv)
    output = Path(args.output)
    origin: str | None = None
    candidate_revision: str | None = None
    try:
        origin = validate_canary_origin(args.canary_origin)
        candidate_revision = validate_revision(args.expected_revision)
        if not math.isfinite(args.duration_seconds) or not 30 <= args.duration_seconds <= MAX_DURATION_SECONDS:
            raise ValueError("duration must be between 30 and 1800 seconds")
        cookie = os.environ.get(args.cookie_env, "")
        if not cookie or len(cookie) > MAX_COOKIE_LENGTH or "\r" in cookie or "\n" in cookie:
            raise ValueError("the named short-lived Cookie environment variable is unset or invalid")
        report = asyncio.run(observe(
            origin, cookie, args.duration_seconds, expected_revision=candidate_revision
        ))
    except Exception:
        now = _utc_now()
        report = TelemetryStreamRecorder().report(
            started_at=now, ended_at=now, duration=0, connected_at_end=False
        )
        report.update({
            "origin": origin,
            "candidate_revision": candidate_revision,
            "observed_revision": None,
        })
        report["failed_gates"] = sorted(set(report["failed_gates"]) | {"stream_observation_failed"})
        report["observed_stream_healthy"] = False
        print(json.dumps({"observed_stream_healthy": False, "failed_gates": report["failed_gates"]}))
        try:
            _write_atomically(output, report)
        except OSError:
            pass
        return 2
    try:
        _write_atomically(output, report)
    except OSError:
        print(json.dumps({"observed_stream_healthy": False, "failed_gates": ["report_write_failed"]}))
        return 2
    print(json.dumps(report, sort_keys=True))
    return 0 if report["observed_stream_healthy"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
