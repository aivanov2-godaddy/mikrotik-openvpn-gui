"""Optional, provider-neutral outbound integration delivery."""

from __future__ import annotations

import hashlib
import hmac
import json
import queue
import threading
import urllib.request
from typing import Any


class WebhookDispatcher:
    """Deliver sanitized audit events without delaying dashboard requests."""

    def __init__(self, url: str | None, secret: str | None) -> None:
        self._url = url
        self._secret = secret.encode("utf-8") if secret else None
        self._queue: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=100)
        if self.enabled:
            threading.Thread(target=self._run, name="vpn-webhook", daemon=True).start()

    @property
    def enabled(self) -> bool:
        return bool(self._url and self._secret)

    def publish(self, event: dict[str, Any]) -> None:
        if not self.enabled:
            return
        try:
            self._queue.put_nowait(event)
        except queue.Full:
            # Integrations are observational; a slow receiver must never block VPN control.
            return

    def _run(self) -> None:
        while True:
            event = self._queue.get()
            try:
                body = json.dumps(event, separators=(",", ":"), sort_keys=True).encode("utf-8")
                signature = hmac.new(self._secret or b"", body, hashlib.sha256).hexdigest()
                request = urllib.request.Request(
                    self._url or "",
                    data=body,
                    headers={
                        "Content-Type": "application/json",
                        "User-Agent": "MikroTik-OpenVPN-GUI/1",
                        "X-VPN-Dashboard-Event": "audit",
                        "X-VPN-Dashboard-Signature": f"sha256={signature}",
                    },
                    method="POST",
                )
                with urllib.request.urlopen(request, timeout=3) as response:  # nosec B310: URL is HTTPS-validated config
                    response.read(1)
            except Exception:
                # Delivery failures remain isolated from RouterOS and are intentionally not
                # re-audited (which would create a retry loop and disclose endpoint state).
                pass
            finally:
                self._queue.task_done()
