"""Durable, provider-neutral outbound integration delivery."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import queue
import sqlite3
import threading
import time
import urllib.request
import uuid
import contextlib
from typing import Any, Protocol
from urllib.parse import urlsplit

from config import ConfigurationError, validate_redis_stream_url
from event_safety import sanitize_integration_event


_LOGGER = logging.getLogger(__name__)


class IntegrationOutbox(Protocol):
    """The small persistence interface required by the delivery worker."""

    def pending_integration_events(self, limit: int = 20, *, now: int | None = None) -> list[dict[str, Any]]:
        ...

    def mark_integration_delivered(self, event_id: str, *, now: int | None = None) -> None:
        ...

    def mark_integration_failed(self, event_id: str, error: str, *, retry_at: int) -> None:
        ...

    def mark_integration_dead_lettered(self, event_id: str, reason: str) -> None:
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
        validated_url = validate_redis_stream_url(str(url))
        if validated_url is None:
            raise ConfigurationError("REDIS_STREAM_URL is required when Redis Streams are enabled")
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
        options: dict[str, Any] = {
            "decode_responses": True,
            "socket_connect_timeout": 3,
            "socket_timeout": 3,
            "health_check_interval": 30,
        }
        if urlsplit(validated_url).scheme == "rediss":
            options.update({"ssl_cert_reqs": "required", "ssl_check_hostname": True})
        self._client = redis.Redis.from_url(validated_url, **options)

    def publish(self, event: dict[str, Any]) -> str:
        payload = sanitize_integration_event(event)
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

    def review_coordinator(self) -> RedisReviewCoordinator:
        """Share the configured Redis connection for cross-instance review state."""
        return RedisReviewCoordinator(self._client)


class RedisReviewCoordinationError(RuntimeError):
    """Redis could not safely coordinate a sensitive mutation review."""


class _RedisReviewLock:
    _RENEW = "if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('pexpire', KEYS[1], ARGV[2]) else return 0 end"
    _ASSERT = "if redis.call('get', KEYS[1]) == ARGV[1] then return 1 else return 0 end"
    _RELEASE = "if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) else return 0 end"

    def __init__(self, client: Any, key: str, token: str, lease_ms: int) -> None:
        self._client = client
        self._key = key
        self._token = token
        self._lease_ms = lease_ms
        self._lost = threading.Event()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._heartbeat, name="redis-review-lock", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def renew(self) -> None:
        if self._lost.is_set():
            raise RedisReviewCoordinationError("Redis review coordination is unavailable")
        try:
            renewed = self._client.eval(self._RENEW, 1, self._key, self._token, self._lease_ms)
        except Exception:
            self._lost.set()
            raise RedisReviewCoordinationError(
                "Redis review coordination is unavailable"
            ) from None
        if int(renewed or 0) != 1:
            self._lost.set()
            raise RedisReviewCoordinationError(
                "The VPN user update lock was lost; retry the reviewed change"
            )

    def assert_owned(self) -> None:
        if self._lost.is_set():
            raise RedisReviewCoordinationError(
                "The VPN user update lock was lost; retry the reviewed change"
            )
        try:
            owned = self._client.eval(self._ASSERT, 1, self._key, self._token)
        except Exception:
            self._lost.set()
            raise RedisReviewCoordinationError(
                "Redis review coordination is unavailable"
            ) from None
        if int(owned or 0) != 1:
            self._lost.set()
            raise RedisReviewCoordinationError(
                "The VPN user update lock was lost; retry the reviewed change"
            )

    def close(self) -> None:
        self._stop.set()
        self._thread.join(timeout=min(5.0, max(1.0, self._lease_ms / 1000)))
        try:
            self._client.eval(self._RELEASE, 1, self._key, self._token)
        except Exception:
            # The lease expires automatically; never mask a RouterOS outcome.
            pass

    def _heartbeat(self) -> None:
        interval = max(0.1, self._lease_ms / 3000)
        while not self._stop.wait(interval):
            try:
                self.renew()
            except RedisReviewCoordinationError:
                return


class RedisReviewCoordinator:
    """Cross-process lock and revision store for reviewed VPN-user mutations."""

    _EPOCH_KEY = "vpn-dashboard.review.epoch"
    _ADVANCE_REVISION = (
        "if redis.call('get', KEYS[1]) ~= ARGV[1] then return -1 end; "
        "local current = redis.call('get', KEYS[2]); "
        "if not current or tonumber(current) ~= tonumber(ARGV[2]) then return 0 end; "
        "return redis.call('incr', KEYS[2])"
    )

    def __init__(
        self,
        client: Any,
        *,
        lock_wait_seconds: float = 3.0,
        lock_lease_ms: int = 900_000,
    ) -> None:
        self._client = client
        self._lock_wait_seconds = max(0.1, float(lock_wait_seconds))
        self._lock_lease_ms = max(60_000, int(lock_lease_ms))
        self._state_lock = threading.Lock()
        self._observed_epoch: str | None = None
        self._observed_server_run_id: str | None = None
        self._observed_revision_keys: set[str] = set()
        self._observed_revision_high_water: dict[str, int] = {}

    @staticmethod
    def _resource_digest(resource_key: str) -> str:
        return hashlib.sha256(resource_key.encode("utf-8")).hexdigest()

    @classmethod
    def _revision_key(cls, resource_key: str) -> str:
        return f"vpn-dashboard.review.revision:{cls._resource_digest(resource_key)}"

    @classmethod
    def _lock_key(cls, resource_key: str) -> str:
        return f"vpn-dashboard.review.lock:{cls._resource_digest(resource_key)}"

    def current_epoch(self) -> str:
        """Return the Redis data-generation marker, failing closed on its loss."""
        with self._state_lock:
            try:
                server_info = self._client.info("server")
                server_run_id = str(server_info.get("run_id", ""))
                if not server_run_id:
                    raise ValueError("Redis server identity is unavailable")
                if (
                    self._observed_server_run_id is not None
                    and server_run_id != self._observed_server_run_id
                ):
                    raise ValueError("Redis server process changed")
                self._observed_server_run_id = server_run_id
                value = self._client.get(self._EPOCH_KEY)
                if value is None and self._observed_epoch is None:
                    self._client.set(self._EPOCH_KEY, uuid.uuid4().hex, nx=True)
                    value = self._client.get(self._EPOCH_KEY)
                if value is None:
                    raise ValueError("Redis coordination epoch disappeared")
                epoch = str(value)
                if self._observed_epoch is not None and epoch != self._observed_epoch:
                    raise ValueError("Redis coordination epoch changed")
                self._observed_epoch = epoch
                return epoch
            except Exception:
                raise RedisReviewCoordinationError(
                    "Redis review coordination state changed; restart the dashboard before retrying"
                ) from None

    def current_revision(self, resource_key: str) -> int:
        self.current_epoch()
        key = self._revision_key(resource_key)
        with self._state_lock:
            try:
                value = self._client.get(key)
                if value is None:
                    if key in self._observed_revision_keys:
                        raise ValueError("Redis review revision disappeared")
                    self._client.set(key, "0", nx=True)
                    value = self._client.get(key)
                revision = int(value)
                high_water = self._observed_revision_high_water.get(key, -1)
                if revision < 0 or revision < high_water:
                    raise ValueError("Redis review revision moved backwards")
                self._observed_revision_keys.add(key)
                self._observed_revision_high_water[key] = revision
                return revision
            except Exception:
                raise RedisReviewCoordinationError(
                    "Redis review coordination state changed; restart the dashboard before retrying"
                ) from None

    def advance_if_current(
        self,
        resource_key: str,
        expected_revision: int,
        expected_epoch: str,
    ) -> bool:
        key = self._revision_key(resource_key)
        try:
            self.current_epoch()
            with self._state_lock:
                high_water = self._observed_revision_high_water.get(key, -1)
                if int(expected_revision) < high_water:
                    raise RedisReviewCoordinationError(
                        "Redis review coordination state changed; restart the dashboard before retrying"
                    )
                result = self._client.eval(
                    self._ADVANCE_REVISION,
                    2,
                    self._EPOCH_KEY,
                    key,
                    expected_epoch,
                    int(expected_revision),
                )
                advanced = int(result or 0) == int(expected_revision) + 1
                if advanced:
                    self._observed_revision_high_water[key] = max(
                        high_water, int(expected_revision) + 1,
                    )
                    self._observed_revision_keys.add(key)
                return advanced
        except RedisReviewCoordinationError:
            raise
        except Exception:
            raise RedisReviewCoordinationError(
                "Redis review coordination is unavailable"
            ) from None

    @contextlib.contextmanager
    def resource_lock(self, resource_key: str):
        lock_key = self._lock_key(resource_key)
        token = uuid.uuid4().hex
        deadline = time.monotonic() + self._lock_wait_seconds
        acquired = False
        while not acquired:
            try:
                acquired = bool(
                    self._client.set(
                        lock_key,
                        token,
                        nx=True,
                        px=self._lock_lease_ms,
                    )
                )
            except Exception:
                raise RedisReviewCoordinationError(
                    "Redis review coordination is unavailable"
                ) from None
            if acquired:
                break
            if time.monotonic() >= deadline:
                raise RedisReviewCoordinationError(
                    "Another review for this VPN user is still being applied"
                )
            time.sleep(0.05)

        try:
            lock = _RedisReviewLock(self._client, lock_key, token, self._lock_lease_ms)
            lock.start()
            yield lock
        finally:
            if "lock" in locals():
                lock.close()


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
        max_outbox_attempts: int = 10,
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
        self._max_outbox_attempts = max(1, min(int(max_outbox_attempts), 100))
        self._failure_streak = 0
        self._circuit_open_until = 0.0
        self._metrics_lock = threading.Lock()
        self._delivery_successes = 0
        self._delivery_failures = 0
        self._last_delivery_success = 0
        self._outbox_storage_failures = 0
        self._outbox_storage_failure_streak = 0
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
            self._queue.put_nowait(sanitize_integration_event(event))
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
                "outbox_storage_failures": self._outbox_storage_failures,
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

            try:
                batch_succeeded, retry_deadline = self._dispatch_outbox_batch()
            except sqlite3.Error as error:
                batch_succeeded = False
                retry_deadline = time.monotonic() + self._record_outbox_storage_failure(error)
            else:
                if batch_succeeded:
                    self._outbox_storage_failure_streak = 0
            if retry_deadline is not None:
                self._wake.wait(max(0.0, retry_deadline - time.monotonic()))
                self._wake.clear()

    def _dispatch_outbox_batch(self) -> tuple[bool, float | None]:
        store = self._store
        if store is None:
            return True, None
        pending = store.pending_integration_events(20)
        if not pending:
            self._wake.wait(1.0)
            self._wake.clear()
            return True, None
        storage_failure = False
        retry_deadline: float | None = None
        storage_retry_deadline: float | None = None

        def next_retry_deadline() -> float | None:
            outstanding = [
                deadline
                for deadline in (retry_deadline, storage_retry_deadline)
                if deadline is not None
            ]
            return min(outstanding) if outstanding else None

        for record in pending:
            if self._stop.is_set():
                return not storage_failure, next_retry_deadline()
            event_id = str(record.get("event_id", ""))
            try:
                if record.get("payload_error"):
                    store.mark_integration_dead_lettered(
                        event_id, f"malformed_payload_{record['payload_error']}"
                    )
                    continue
                payload = record.get("payload") if isinstance(record.get("payload"), dict) else {}
                payload["event_id"] = event_id
                try:
                    self._deliver_with_retries(payload)
                except Exception as error:  # noqa: BLE001 - boundary records and retries safely
                    if int(record.get("attempts", 1)) >= self._max_outbox_attempts:
                        store.mark_integration_dead_lettered(
                            event_id, f"retry_limit_{type(error).__name__}"
                        )
                    else:
                        event_retry_delay = (
                            self._circuit_cooldown
                            if self._failure_streak >= self._circuit_threshold
                            else self._backoff_for_attempt(int(record.get("attempts", 1)))
                        )
                        event_retry_deadline = time.monotonic() + event_retry_delay
                        retry_deadline = (
                            event_retry_deadline
                            if retry_deadline is None
                            else min(retry_deadline, event_retry_deadline)
                        )
                        store.mark_integration_failed(
                            event_id, type(error).__name__, retry_at=int(time.time() + event_retry_delay)
                        )
                else:
                    store.mark_integration_delivered(event_id)
            except sqlite3.Error as error:
                storage_failure = True
                event_retry_delay = self._record_outbox_storage_failure(error)
                event_retry_deadline = time.monotonic() + event_retry_delay
                storage_retry_deadline = (
                    event_retry_deadline
                    if storage_retry_deadline is None
                    else min(storage_retry_deadline, event_retry_deadline)
                )
                try:
                    store.mark_integration_failed(
                        event_id,
                        "SQLiteStorageError",
                        retry_at=int(time.time() + event_retry_delay),
                    )
                except sqlite3.Error as release_error:
                    release_retry_delay = self._record_outbox_storage_failure(release_error)
                    release_retry_deadline = time.monotonic() + release_retry_delay
                    storage_retry_deadline = (
                        release_retry_deadline
                        if storage_retry_deadline is None
                        else min(storage_retry_deadline, release_retry_deadline)
                    )
        return not storage_failure, next_retry_deadline()

    def _record_outbox_storage_failure(self, error: sqlite3.Error) -> float:
        self._outbox_storage_failure_streak += 1
        delay = self._backoff_for_attempt(self._outbox_storage_failure_streak)
        with self._metrics_lock:
            self._outbox_storage_failures += 1
        _LOGGER.warning(
            "SQLite integration outbox operation failed (%s); retrying in %.2f seconds",
            type(error).__name__,
            delay,
        )
        return delay

    def _deliver_with_retries(self, event: dict[str, Any]) -> None:
        normalized_event = sanitize_integration_event(event)
        normalized_event["event_id"] = str(normalized_event.get("event_id") or uuid.uuid4())
        last_error: Exception | None = None
        for attempt in range(1, 4):
            try:
                self._deliver(normalized_event, attempt=attempt)
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
        payload = sanitize_integration_event(event)
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
