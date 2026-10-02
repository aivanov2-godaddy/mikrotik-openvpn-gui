"""Durable, provider-neutral outbound integration delivery."""

from __future__ import annotations

import hashlib
import hmac
import json
import queue
import threading
import time
import urllib.request
import uuid
from typing import Any, Protocol

from event_safety import sanitize_payload


class IntegrationOutbox(Protocol):
    """The small persistence interface required by the delivery worker."""

    def pending_integration_events(self, limit: int = 20, *, now: int | None = None) -> list[dict[str, Any]]:
        ...

    def mark_integration_delivered(self, event_id: str, *, now: int | None = None) -> None:
        ...

    def mark_integration_failed(self, event_id: str, error: str, *, retry_at: int) -> None:
        ...


class RedisStreamPublisher:
    """Optional Redis Streams sink with bounded, at-least-once delivery.

    Redis is intentionally imported only when this adapter is constructed.  A
    normal single-container installation therefore has no Redis dependency or
    connection overhead. Consumers must deduplicate on ``event_id``.
    """

    def __init__(
        self,
        url: str,
        stream: str = "vpn-dashboard.events",
        *,
        maxlen: int = 10_000,
        client: Any | None = None,
    ) -> None:
        self.stream = str(stream)
        self.maxlen = max(100, min(int(maxlen), 1_000_000))
        self._metrics_lock = threading.Lock()
        self._publish_successes = 0
        self._publish_failures = 0
        self._last_publish_success = 0
        self._last_publish_succeeded: bool | None = None
        if client is not None:
            self._client = client
            return
        try:
            import redis  # type: ignore[import-not-found]
        except ImportError as error:
            raise RuntimeError(
                "Redis Streams is configured but the optional Redis dependency is not installed"
            ) from error
        self._client = redis.Redis.from_url(
            str(url),
            decode_responses=True,
            socket_connect_timeout=3,
            socket_timeout=3,
            health_check_interval=30,
        )

    def publish(self, event: dict[str, Any]) -> str:
        payload = sanitize_payload(event)
        event_id = str(payload.get("event_id") or uuid.uuid4())
        payload["event_id"] = event_id
        try:
            stream_id = self._client.xadd(
                self.stream,
                {
                    "event_id": event_id,
                    "event_type": str(payload.get("event", "audit")),
                    "payload": json.dumps(payload, separators=(",", ":"), sort_keys=True),
                },
                maxlen=self.maxlen,
                approximate=True,
            )
        except Exception:
            with self._metrics_lock:
                self._publish_failures += 1
                self._last_publish_succeeded = False
            raise
        with self._metrics_lock:
            self._publish_successes += 1
            self._last_publish_success = int(time.time())
            self._last_publish_succeeded = True
        return str(stream_id)

    def metrics(self) -> dict[str, int]:
        """Return aggregate delivery health; never probes Redis or exposes config."""

        with self._metrics_lock:
            observed = self._last_publish_succeeded
            return {
                "configured": 1,
                "available": -1 if observed is None else int(observed),
                "publish_successes": self._publish_successes,
                "publish_failures": self._publish_failures,
                "last_publish_success": self._last_publish_success,
            }


class WebhookDispatcher:
    """Deliver sanitized events from SQLite with retries and circuit breaking.

    The SQLite outbox is written in the same transaction as the audit record.
    Delivery is therefore at-least-once and survives process restarts. A
    receiver must deduplicate using ``event_id`` because a successful delivery
    followed by a process crash can be retried.
    """

    def __init__(
        self,
        url: str | None,
        secret: str | None,
        *,
        store: IntegrationOutbox | None = None,
        redis_publisher: RedisStreamPublisher | None = None,
        queue_size: int = 100,
        base_backoff: float = 1.0,
        max_backoff: float = 60.0,
        circuit_threshold: int = 3,
        circuit_cooldown: float = 60.0,
    ) -> None:
        self._url = url
        self._secret = secret.encode("utf-8") if secret else None
        self._store = store
        self._redis = redis_publisher
        self._queue: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=max(1, int(queue_size)))
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._base_backoff = max(0.1, float(base_backoff))
        self._max_backoff = max(self._base_backoff, float(max_backoff))
        self._circuit_threshold = max(1, int(circuit_threshold))
        self._circuit_cooldown = max(1.0, float(circuit_cooldown))
        self._failure_streak = 0
        self._circuit_open_until = 0.0
        self._metrics_lock = threading.Lock()
        self._delivery_successes = 0
        self._delivery_failures = 0
        self._last_delivery_success = 0
        self._thread: threading.Thread | None = None
        if self.enabled:
            self._thread = threading.Thread(target=self._run, name="vpn-integration", daemon=True)
            self._thread.start()

    @property
    def enabled(self) -> bool:
        return bool((self._url and self._secret) or self._redis)

    def publish(self, event: dict[str, Any]) -> None:
        """Wake the persistent worker without putting secrets in memory queues."""

        if not self.enabled:
            return
        if self._store is not None:
            self._wake.set()
            return
        try:
            self._queue.put_nowait(sanitize_payload(event))
        except queue.Full:
            # The durable app path always supplies a store. This fallback is
            # observational and must never block control-plane requests.
            return

    def stop(self, timeout: float = 2.0) -> None:
        self._stop.set()
        self._wake.set()
        if self._thread is not None:
            self._thread.join(max(0.0, float(timeout)))

    def metrics(self) -> dict[str, int]:
        """Return secret-free integration configuration and process counters."""

        with self._metrics_lock:
            values = {
                "enabled": int(self.enabled),
                "webhook_configured": int(bool(self._url and self._secret)),
                "redis_configured": int(self._redis is not None),
                "delivery_successes": self._delivery_successes,
                "delivery_failures": self._delivery_failures,
                "last_delivery_success": self._last_delivery_success,
            }
        redis_values = self._redis.metrics() if self._redis is not None else {
            "configured": 0,
            "available": -1,
            "publish_successes": 0,
            "publish_failures": 0,
            "last_publish_success": 0,
        }
        return {**values, **{f"redis_{key}": value for key, value in redis_values.items()}}

    def _run(self) -> None:
        while not self._stop.is_set():
            if self._circuit_open_until > time.monotonic():
                self._stop.wait(1.0)
                continue
            if self._store is None:
                try:
                    event = self._queue.get(timeout=1.0)
                except queue.Empty:
                    continue
                try:
                    self._deliver_with_retries(event)
                except Exception:
                    pass
                finally:
                    self._queue.task_done()
                continue

            pending = self._store.pending_integration_events(20)
            if not pending:
                self._wake.wait(1.0)
                self._wake.clear()
                continue
            for record in pending:
                if self._stop.is_set():
                    return
                event_id = str(record.get("event_id", ""))
                payload = record.get("payload") if isinstance(record.get("payload"), dict) else {}
                payload["event_id"] = event_id
                try:
                    self._deliver_with_retries(payload)
                except Exception as error:  # noqa: BLE001 - boundary records and retries safely
                    retry_delay = (
                        self._circuit_cooldown
                        if self._failure_streak >= self._circuit_threshold
                        else self._backoff_for_attempt(int(record.get("attempts", 1)))
                    )
                    self._store.mark_integration_failed(
                        event_id, type(error).__name__, retry_at=int(time.time() + retry_delay)
                    )
                else:
                    self._store.mark_integration_delivered(event_id)

    def _deliver_with_retries(self, event: dict[str, Any]) -> None:
        last_error: Exception | None = None
        for attempt in range(1, 4):
            try:
                self._deliver(event, attempt=attempt)
            except Exception as error:  # noqa: BLE001 - integration boundary
                last_error = error
                if attempt < 3:
                    time.sleep(self._backoff_for_attempt(attempt))
                continue
            self._failure_streak = 0
            self._circuit_open_until = 0.0
            with self._metrics_lock:
                self._delivery_successes += 1
                self._last_delivery_success = int(time.time())
            return
        self._failure_streak += 1
        with self._metrics_lock:
            self._delivery_failures += 1
        if self._failure_streak >= self._circuit_threshold:
            self._circuit_open_until = time.monotonic() + self._circuit_cooldown
        raise last_error or RuntimeError("integration delivery failed")

    def _deliver(self, event: dict[str, Any], *, attempt: int) -> None:
        payload = sanitize_payload(event)
        if not isinstance(payload, dict):
            raise ValueError("integration payload must be an object")
        event_id = str(payload.get("event_id") or uuid.uuid4())
        payload["event_id"] = event_id
        body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        timestamp = str(int(time.time()))
        if self._url and self._secret:
            signed = f"{timestamp}.".encode("ascii") + body
            signature = hmac.new(self._secret, signed, hashlib.sha256).hexdigest()
            request = urllib.request.Request(
                self._url,
                data=body,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "MikroTik-OpenVPN-GUI/1",
                    "X-VPN-Dashboard-Event": str(payload.get("event", "audit")),
                    "X-VPN-Dashboard-Event-ID": event_id,
                    "X-VPN-Dashboard-Timestamp": timestamp,
                    "X-VPN-Dashboard-Delivery": f"{event_id}-{attempt}",
                    "X-VPN-Dashboard-Signature": f"sha256={signature}",
                },
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=3) as response:  # nosec B310: HTTPS config validated
                if not 200 <= int(getattr(response, "status", 200)) < 300:
                    raise OSError(f"webhook_http_{getattr(response, 'status', 'unknown')}")
                response.read(1)
        if self._redis is not None:
            self._redis.publish(payload)

    def _backoff_for_attempt(self, attempt: int) -> float:
        return min(self._max_backoff, self._base_backoff * (2 ** max(0, int(attempt) - 1)))
