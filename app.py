from __future__ import annotations

import csv
import base64
import datetime as dt
import hashlib
import hmac
import io
import json
import mimetypes
import os
import re
import secrets
import threading
import time
import urllib.parse
import ipaddress
import zipfile
from dataclasses import dataclass
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from automation import AutomationMixin, simultaneous_session_sources  # noqa: F401
from config import ConfigurationError, RuntimeConfig
from favicon import FAVICON_SVG, ico_bytes
from integrations import WebhookDispatcher
from routeros import ProvisionedProfile, RouterOSClient, RouterOSCredentials, RouterOSError
from qr import svg as qr_svg
from security import LoginRateLimiter, SECURITY_HEADERS, Session, SessionStore, csrf_matches
from store import MetadataStore
from templates import dashboard_page, login_page


ROOT = Path(__file__).resolve().parent
STATIC = ROOT / "static"
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.@-]{1,64}$")
EMAIL_PATTERN = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
POLICY_VALUES = {"full-tunnel", "lan-only", "internet-only"}
DNS_VALUES = {"router", "cloudflare"}
EXPIRY_SECONDS = {"1h": 3600, "1d": 86400, "7d": 604800, "30d": 2592000}
QUOTA_VALUES_MB = {0, 1024, 5120, 10240, 25600, 51200, 102400}
SCHEDULE_VALUES = {"always", "weekdays", "daytime"}
IMMUTABLE_IMAGE_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._/-]*:sha-[a-f0-9]{40,64}(?:-(?:arm64|amd64))?$", re.I)
ROUTEROS_NAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{1,48}$")
VPN_ENDPOINT_PATTERN = re.compile(r"^[A-Za-z0-9.-]{1,253}$")


def container_image_target(architecture: Any) -> dict[str, Any]:
    """Describe the published image target for a RouterOS architecture.

    RouterOS reports several architecture names, but the public image is only
    validated for ARM64 hardware and x86/CHR (published as AMD64).  Keeping
    this mapping server-side prevents the installation wizard from suggesting
    an image tag that the router cannot execute.
    """
    detected = str(architecture or "unknown").strip().lower()
    targets = {
        "arm64": ("arm64", "ARM64 production image"),
        "amd64": ("amd64", "AMD64 evaluation image"),
        "x86": ("amd64", "AMD64 evaluation image"),
    }
    target = targets.get(detected)
    if target:
        suffix, label = target
        return {
            "architecture": detected,
            "image_suffix": suffix,
            "supported": True,
            "status": "pass",
            "label": label,
            "detail": f"Use the immutable image tag ending in -{suffix}.",
        }
    return {
        "architecture": detected,
        "image_suffix": None,
        "supported": False,
        "status": "fail",
        "label": "Unsupported container target",
        "detail": (
            f"RouterOS reports {detected}; this release publishes only arm64 and amd64 images. "
            "Do not install a different architecture tag."
        ),
    }


def _used_percent(free: Any, total: Any) -> int:
    """Return a bounded used percentage from RouterOS capacity fields."""
    try:
        total_value = int(total or 0)
        free_value = int(free or 0)
    except (TypeError, ValueError):
        return 0
    if total_value <= 0:
        return 0
    return max(0, min(100, round((total_value - free_value) * 100 / total_value)))


def _certificate_expiry_epoch(value: Any) -> int | None:
    """Parse the ISO-like expiry values returned by RouterOS certificates."""
    raw = str(value or "").strip()
    for pattern in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return int(time.mktime(time.strptime(raw[:19 if " " in pattern else 10], pattern)))
        except (TypeError, ValueError, OverflowError):
            continue
    return None


def service_health_snapshot(
    *,
    router: dict[str, Any] | None,
    ovpn_server: dict[str, Any] | None,
    certificate_settings: dict[str, Any] | None,
    certificates: list[dict[str, Any]] | None,
    config: RuntimeConfig,
    database_ready: bool,
    unavailable_reason: str = "",
) -> dict[str, Any]:
    """Build a non-mutating readiness view from already-fetched state.

    The response intentionally exposes useful operational guidance without
    disclosing RouterOS errors, credentials, or local storage paths.
    """
    if unavailable_reason:
        return {
            "overall": "unavailable",
            "checked_at": int(time.time()),
            "checks": [{
                "id": "routeros-rest",
                "name": "RouterOS REST connection",
                "status": "unavailable",
                "impact": "Live VPN health cannot be verified until the router responds.",
                "remediation": "Confirm the dashboard container can reach RouterOS REST over HTTPS, then refresh.",
            }],
        }

    router = router or {}
    ovpn_server = ovpn_server or {}
    certificate_settings = certificate_settings or {}
    certificates = certificates or []
    checks: list[dict[str, str]] = []

    def add(identifier: str, name: str, status: str, impact: str, remediation: str) -> None:
        checks.append({"id": identifier, "name": name, "status": status, "impact": impact, "remediation": remediation})

    add(
        "routeros-rest", "RouterOS REST connection", "healthy",
        "The dashboard can read the router and apply only reviewed changes.",
        "No action needed.",
    )
    add(
        "dashboard-storage", "Dashboard data store", "healthy" if database_ready else "unavailable",
        "Profiles, user controls, alerts, and change history are persistent." if database_ready else "Dashboard changes cannot be stored safely.",
        "No action needed." if database_ready else "Verify the container's persistent storage mount and available disk space, then refresh.",
    )
    if not ovpn_server.get("name"):
        add("openvpn-service", "OpenVPN server", "unavailable", "New VPN connections cannot be accepted.", "Create or select the RouterOS OpenVPN server, then refresh.")
    elif not ovpn_server.get("enabled"):
        add("openvpn-service", "OpenVPN server", "warning", "The configured OpenVPN server is currently disabled.", "Enable the selected OpenVPN server in WinBox after reviewing its configuration.")
    else:
        add("openvpn-service", "OpenVPN server", "healthy", "The configured OpenVPN server is enabled.", "No action needed.")

    try:
        config.topology.require_profile_generation(policy="full-tunnel", dns_mode="router")
    except ConfigurationError:
        add("profile-issuing", "Profile issuing prerequisites", "warning", "The dashboard may be unable to generate a complete phone profile.", "Set the required OVPN topology values in the container environment, then restart the dashboard.")
    else:
        add("profile-issuing", "Profile issuing prerequisites", "healthy", "New device profiles can be generated from the configured topology.", "No action needed.")

    if certificate_settings.get("crl_ready"):
        add("certificate-revocation", "Certificate revocation checks", "healthy", "RouterOS is enforcing revocation using an active CRL for the configured OpenVPN CA.", "No action needed.")
    elif certificate_settings.get("crl_use"):
        add("certificate-revocation", "Certificate revocation checks", "warning", "CRL enforcement is enabled but no usable CRL is available for the configured OpenVPN CA.", "Restore the CA's CRL publication path before relying on certificate revocation.")
    else:
        add("certificate-revocation", "Certificate revocation checks", "warning", "Revoked client certificates may not be rejected automatically.", "Review Certificate Settings in WinBox and enable CRL use when your CA publishes a revocation list.")

    if certificates:
        now = int(time.time())
        expiring = []
        expired = []
        for certificate in certificates:
            if certificate.get("revoked"):
                continue
            expiry = _certificate_expiry_epoch(certificate.get("invalid_after") or certificate.get("expires_after"))
            if expiry is None:
                continue
            days = (expiry - now) // 86400
            if days < 0:
                expired.append(str(certificate.get("name", "certificate")))
            elif days <= 30:
                expiring.append(str(certificate.get("name", "certificate")))
        if expired:
            add("certificate-inventory", "Client certificate inventory", "warning", f"{len(expired)} active client certificate(s) have expired.", "Open Device Profiles and use Add another device to issue a replacement profile, then revoke the expired device.")
        elif expiring:
            add("certificate-inventory", "Client certificate inventory", "warning", f"{len(expiring)} active client certificate(s) expire within 30 days.", "Open Device Profiles and use Add another device to issue a replacement profile before expiry.")
        else:
            add("certificate-inventory", "Client certificate inventory", "healthy", f"{len(certificates)} OpenVPN client certificate(s) are visible to the dashboard.", "No action needed.")
    else:
        add("certificate-inventory", "Client certificate inventory", "warning", "No OpenVPN client certificates were found for the configured CA.", "Issue a device profile or verify the configured CA name before distributing access.")

    capacity = max(
        _used_percent(router.get("free-memory"), router.get("total-memory")),
        _used_percent(router.get("free-hdd-space"), router.get("total-hdd-space")),
        max(0, min(100, int(router.get("cpu-load", 0) or 0))),
    )
    if capacity >= 95:
        capacity_status, capacity_impact = "warning", "Router capacity is critically high and may affect VPN reliability."
    elif capacity >= 85:
        capacity_status, capacity_impact = "warning", "Router capacity is elevated; monitor VPN performance."
    else:
        capacity_status, capacity_impact = "healthy", "Router CPU, memory, and storage are within the dashboard threshold."
    add("router-capacity", "Router capacity", capacity_status, capacity_impact, "Review CPU, memory, and storage in WinBox; reduce load or free storage before VPN users are affected." if capacity_status == "warning" else "No action needed.")

    statuses = {item["status"] for item in checks}
    overall = "unavailable" if "unavailable" in statuses else ("warning" if "warning" in statuses else "healthy")
    return {"overall": overall, "checked_at": int(time.time()), "checks": checks}


def baked_release_value(name: str) -> str:
    """Read one explicit, non-secret release value baked into the image."""
    try:
        value = (ROOT / name).read_text(encoding="utf-8").strip()
    except OSError:
        return "unknown"
    return value or "unknown"


def resolve_client_ip(
    peer: str,
    forwarded_header: str,
    *,
    trusted_proxy_header: str | None,
    trusted_proxy_sources: tuple[str, ...],
) -> str:
    if trusted_proxy_header and peer in trusted_proxy_sources:
        try:
            return ipaddress.ip_address(forwarded_header.split(",", 1)[0].strip()).compressed
        except ValueError:
            pass
    return peer


@dataclass(slots=True)
class AppContext:
    router: RouterOSClient
    store: MetadataStore
    sessions: SessionStore
    limiter: LoginRateLimiter
    config: RuntimeConfig
    release_version: str = "unknown"
    release_revision: str = "unknown"

    @property
    def public_origin(self) -> str:
        return self.config.public_origin


@dataclass(slots=True)
class SharedProfile:
    payload: bytes
    filename: str
    expires_at: float
    downloads: int = 0


class ProfileShareStore:
    """Bounded, in-memory profile shares used by QR/download hand-off links."""

    ttl_seconds = 600
    max_downloads = 3

    def __init__(self) -> None:
        self._items: dict[str, SharedProfile] = {}
        self._lock = threading.Lock()

    def put(self, payload: bytes, filename: str) -> tuple[str, int]:
        now = time.time()
        token = secrets.token_urlsafe(32)
        with self._lock:
            self._purge(now)
            self._items[token] = SharedProfile(
                payload=payload,
                filename=filename,
                expires_at=now + self.ttl_seconds,
            )
        return token, self.ttl_seconds

    def take(self, token: str) -> SharedProfile | None:
        now = time.time()
        with self._lock:
            self._purge(now)
            item = self._items.get(token)
            if item is None:
                return None
            item.downloads += 1
            if item.downloads >= self.max_downloads:
                self._items.pop(token, None)
            return SharedProfile(item.payload, item.filename, item.expires_at, item.downloads)

    def _purge(self, now: float) -> None:
        for token, item in list(self._items.items()):
            if item.expires_at <= now:
                self._items.pop(token, None)


class DashboardServer(AutomationMixin, ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], context: AppContext) -> None:
        super().__init__(address, DashboardHandler)
        self.context = context
        self.profile_shares = ProfileShareStore()
        self._telemetry_stop = threading.Event()
        self._telemetry_thread = threading.Thread(
            target=self._telemetry_loop,
            name="vpn-dashboard-telemetry",
            daemon=True,
        )
        self._telemetry_thread.start()

    def shutdown(self) -> None:
        self._telemetry_stop.set()
        super().shutdown()
        self._telemetry_thread.join(timeout=2)


class DashboardHandler(BaseHTTPRequestHandler):
    server: DashboardServer
    protocol_version = "HTTP/1.1"

    def log_message(self, message: str, *args: Any) -> None:
        safe_path = self.path.split("?", 1)[0]
        print(f"http method={self.command} path={safe_path} peer={self._client_ip()}")

    def _client_ip(self) -> str:
        peer = self.client_address[0]
        context = self.server.context
        header = context.config.trusted_proxy_header
        return resolve_client_ip(
            peer,
            self.headers.get(header, "") if header else "",
            trusted_proxy_header=header,
            trusted_proxy_sources=context.config.trusted_proxy_sources,
        )

    def _headers(
        self,
        status: int,
        content_type: str,
        length: int,
        *,
        extra: dict[str, str] | None = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(length))
        self.send_header("Cache-Control", "no-store")
        for key, value in SECURITY_HEADERS.items():
            self.send_header(key, value)
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()

    def _bytes(
        self,
        payload: bytes,
        *,
        status: int = 200,
        content_type: str = "text/plain; charset=utf-8",
        extra: dict[str, str] | None = None,
    ) -> None:
        self._headers(status, content_type, len(payload), extra=extra)
        self.wfile.write(payload)

    def _html(self, document: str, status: int = 200, extra: dict[str, str] | None = None) -> None:
        self._bytes(
            document.encode("utf-8"),
            status=status,
            content_type="text/html; charset=utf-8",
            extra=extra,
        )

    def _json(self, value: Any, status: int = 200) -> None:
        payload = json.dumps(value, separators=(",", ":")).encode("utf-8")
        self._bytes(payload, status=status, content_type="application/json; charset=utf-8")

    def _json_download(self, filename: str, value: Any) -> None:
        payload = json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")
        self._bytes(
            payload,
            content_type="application/json; charset=utf-8",
            extra={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    def _csv(self, filename: str, headers: list[str], rows: list[list[Any]]) -> None:
        stream = io.StringIO(newline="")
        writer = csv.writer(stream)
        writer.writerow(headers)
        writer.writerows(rows)
        self._bytes(
            stream.getvalue().encode("utf-8-sig"),
            content_type="text/csv; charset=utf-8",
            extra={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    def _redirect(self, location: str, *, cookie: str | None = None) -> None:
        headers = {"Location": location}
        if cookie:
            headers["Set-Cookie"] = cookie
        self._headers(HTTPStatus.SEE_OTHER, "text/plain; charset=utf-8", 0, extra=headers)

    def _read_body(self, maximum: int = 64 * 1024) -> bytes:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            raise ValueError("Invalid Content-Length") from None
        if length < 0 or length > maximum:
            raise ValueError("Request body is too large")
        return self.rfile.read(length)

    def _read_form(self) -> dict[str, str]:
        body = self._read_body().decode("utf-8")
        parsed = urllib.parse.parse_qs(body, keep_blank_values=True, strict_parsing=False)
        return {key: values[-1] for key, values in parsed.items()}

    def _read_json(self) -> dict[str, Any]:
        try:
            value = json.loads(self._read_body().decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            raise ValueError("Invalid JSON request") from None
        if not isinstance(value, dict):
            raise ValueError("JSON body must be an object")
        return value

    def _session_id(self) -> str:
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie", ""))
        except Exception:
            return ""
        morsel = cookie.get("vpn_session")
        return morsel.value if morsel else ""

    def _session(self) -> Session | None:
        return self.server.context.sessions.get(self._session_id())

    def _require_session(self, *, api: bool = False) -> Session | None:
        session = self._session()
        if session:
            return session
        if api:
            self._json({"error": "Authentication required"}, status=HTTPStatus.UNAUTHORIZED)
        else:
            self._redirect("/login")
        return None

    def _require_csrf(self, session: Session, body_token: str = "") -> bool:
        supplied = self.headers.get("X-CSRF-Token", "") or body_token
        if csrf_matches(session.csrf_token, supplied):
            return True
        self._json({"error": "CSRF validation failed"}, status=HTTPStatus.FORBIDDEN)
        return False

    def _require_operator(self, session: Session) -> bool:
        if session.role in {"owner", "operator"}:
            return True
        self._json({"error": "This RouterOS account is read-only."}, status=HTTPStatus.FORBIDDEN)
        return False

    def _require_target_confirmation(self, data: dict[str, Any], target: str) -> bool:
        """Require the exact RouterOS target name for an irreversible action."""
        confirmation = str(data.get("confirmation", "")).strip()
        if hmac.compare_digest(confirmation, target):
            return True
        self._json(
            {"error": f"Type the exact target name '{target}' to confirm this action."},
            status=HTTPStatus.BAD_REQUEST,
        )
        return False

    def _checkpoint(self, session: Session, action: str) -> bool:
        """Create a non-sensitive RouterOS export before configuration changes."""
        try:
            filename = self.server.context.router.create_configuration_export(
                self._credentials(session),
                name=f"vpn-dashboard-before-{action}-{int(time.time())}",
            )
        except RouterOSError as error:
            self.server.context.store.audit(
                actor=session.username,
                action="checkpoint.create",
                target=action,
                status="failed",
                details={"reason": type(error).__name__},
            )
            self._json(
                {"error": "RouterOS configuration checkpoint failed; no change was applied."},
                status=HTTPStatus.BAD_GATEWAY,
            )
            return False
        self.server.context.store.audit(
            actor=session.username,
            action="checkpoint.create",
            target=action,
            status="success",
            details={"file": filename},
        )
        return True

    @staticmethod
    def _credentials(session: Session) -> RouterOSCredentials:
        return RouterOSCredentials(session.username, session.password)

    @staticmethod
    def _validate_username(value: str) -> str:
        if not USERNAME_PATTERN.fullmatch(value):
            raise ValueError("Username may contain letters, digits, dot, underscore, @, and hyphen")
        return value

    @staticmethod
    def _validate_secret(value: str, label: str) -> str:
        if not 8 <= len(value) <= 256:
            raise ValueError(f"{label} must be between 8 and 256 characters")
        return value

    @staticmethod
    def _validate_device(value: str) -> str:
        cleaned = value.strip()
        if not 1 <= len(cleaned) <= 64:
            raise ValueError("Device name must be between 1 and 64 characters")
        return cleaned

    @staticmethod
    def _validate_email(value: str) -> str:
        cleaned = value.strip().lower()
        if len(cleaned) > 254 or not EMAIL_PATTERN.fullmatch(cleaned):
            raise ValueError("Enter a valid email address")
        return cleaned

    @staticmethod
    def _parse_controls(
        data: dict[str, Any],
        current: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        existing = current or {
            "policy": "full-tunnel", "expires_at": None, "max_sessions": 5,
            "rate_limit_kbps": 0, "dns_mode": "router", "notifications": True,
            "quota_mb": 0, "schedule": "always",
        }
        policy = str(data.get("policy", existing.get("policy", "full-tunnel")))
        if policy not in POLICY_VALUES:
            raise ValueError("Choose a valid traffic policy")
        dns_mode = str(data.get("dns_mode", existing.get("dns_mode", "router")))
        if dns_mode not in DNS_VALUES:
            raise ValueError("Choose a valid DNS mode")
        expiry = str(data.get("expiry", ""))
        if expiry:
            if expiry == "keep":
                expires_at = existing.get("expires_at")
            elif expiry == "never":
                expires_at = None
            elif expiry in EXPIRY_SECONDS:
                expires_at = int(time.time()) + EXPIRY_SECONDS[expiry]
            else:
                raise ValueError("Choose a valid access expiration")
        else:
            expires_at = existing.get("expires_at")
        try:
            max_sessions = int(data.get("max_sessions", existing.get("max_sessions", 5)) or 5)
            rate_limit_kbps = int(data.get("rate_limit_kbps", existing.get("rate_limit_kbps", 0)) or 0)
        except (TypeError, ValueError):
            raise ValueError("Connection limits must be numbers") from None
        if not 1 <= max_sessions <= 5:
            raise ValueError("Maximum devices must be between 1 and 5")
        # Keep the two earlier presets readable for existing records, while
        # exposing the larger enterprise-friendly choices in the UI.
        if rate_limit_kbps not in {0, 512, 1024, 5120, 10240, 25600, 51200, 102400}:
            raise ValueError("Choose a valid speed limit")
        try:
            quota_mb = int(data.get("quota_mb", existing.get("quota_mb", 0)) or 0)
        except (TypeError, ValueError):
            raise ValueError("Data quota must be a number") from None
        if quota_mb not in QUOTA_VALUES_MB:
            raise ValueError("Choose a valid data quota")
        schedule = str(data.get("schedule", existing.get("schedule", "always")))
        if schedule not in SCHEDULE_VALUES:
            raise ValueError("Choose a valid access schedule")
        notifications = data.get("notifications", existing.get("notifications", True))
        if isinstance(notifications, str):
            notifications = notifications.lower() in {"1", "true", "yes", "on"}
        return {
            "policy": policy,
            "expires_at": expires_at,
            "max_sessions": max_sessions,
            "rate_limit_kbps": rate_limit_kbps,
            "dns_mode": dns_mode,
            "notifications": bool(notifications),
            "quota_mb": quota_mb,
            "schedule": schedule,
        }

    def _users_with_metadata(
        self, credentials: RouterOSCredentials
    ) -> list[dict[str, Any]]:
        emails = self.server.context.store.user_emails()
        assignments = self.server.context.store.user_template_assignments()
        templates = {item["id"]: item for item in self.server.context.store.list_policy_templates()}
        period_start = DashboardServer._quota_period_start(int(time.time()))
        values = []
        for user in self.server.context.router.list_ovpn_users(credentials):
            username = str(user.get("name", ""))
            controls = self.server.context.store.user_controls(username)
            controls["quota_used_bytes"] = self.server.context.store.quota_usage(username, period_start)
            assignment = assignments.get(username)
            template = templates.get(str(assignment.get("template_id", ""))) if assignment else None
            values.append({
                **user, "email": emails.get(username, ""), "controls": controls,
                "template": ({"id": template["id"], "name": template["name"],
                              "group_name": template["group_name"], "overrides": assignment["overrides"]}
                             if template and assignment else None),
            })
        return values

    def _service_health(self, credentials: RouterOSCredentials) -> dict[str, Any]:
        """Collect health inputs without changing RouterOS or dashboard state."""
        try:
            router = self.server.context.router.verify_credentials(credentials)
        except RouterOSError:
            return service_health_snapshot(
                router=None,
                ovpn_server=None,
                certificate_settings=None,
                certificates=None,
                config=self.server.context.config,
                database_ready=False,
                unavailable_reason="router",
            )

        try:
            self.server.context.store.verify_readiness()
            database_ready = True
        except Exception as error:
            print(f"service health data store unavailable reason={type(error).__name__}")
            database_ready = False

        try:
            ovpn_server = self.server.context.router.get_ovpn_server_status(credentials)
        except RouterOSError:
            ovpn_server = {}
        try:
            certificate_settings = self.server.context.router.get_certificate_settings(credentials)
        except RouterOSError:
            certificate_settings = {}
        try:
            certificates = self.server.context.router.list_ovpn_client_certificates(credentials)
        except RouterOSError:
            certificates = []
        self._record_certificate_expiry_alerts(certificates)
        return service_health_snapshot(
            router=router,
            ovpn_server=ovpn_server,
            certificate_settings=certificate_settings,
            certificates=certificates,
            config=self.server.context.config,
            database_ready=database_ready,
        )

    def _record_certificate_expiry_alerts(self, certificates: list[dict[str, Any]]) -> None:
        """Persist actionable certificate expiry alerts without storing secrets.

        Service health is polled by the dashboard, so this is the right place
        to turn RouterOS inventory data into a durable alert.  The metadata
        store deduplicates an alert for an hour; repeated live polls therefore
        remain cheap while an operator still sees the warning after a refresh.
        Only the certificate name and expiry date are recorded.
        """
        now = int(time.time())
        for certificate in certificates or []:
            expiry = _certificate_expiry_epoch(
                certificate.get("invalid_after") or certificate.get("expires_after")
            )
            if expiry is None:
                continue
            name = str(certificate.get("name") or "unnamed certificate")
            expiry_text = time.strftime("%Y-%m-%d %H:%M:%S %z", time.localtime(expiry))
            days = (expiry - now) // 86400
            if expiry <= now:
                self.server.context.store.add_alert(
                    severity="critical",
                    action="certificate.expired",
                    target=name,
                    title="OpenVPN certificate expired",
                    details=f"{name} expired on {expiry_text}. Issue a replacement profile and revoke the expired device.",
                    now=now,
                )
            elif days <= 30:
                self.server.context.store.add_alert(
                    severity="warning",
                    action="certificate.expiring",
                    target=name,
                    title="OpenVPN certificate expires soon",
                    details=f"{name} expires on {expiry_text} ({max(0, days)} days remaining). Issue a replacement profile before expiry.",
                    now=now,
                )

    def do_GET(self) -> None:
        parsed_url = urllib.parse.urlsplit(self.path)
        path = parsed_url.path
        query = urllib.parse.parse_qs(parsed_url.query)
        if path == "/healthz":
            self._json({"status": "ok"})
            return
        if path == "/readyz":
            try:
                self.server.context.store.verify_readiness()
            except Exception as error:
                print(f"readiness unavailable reason={type(error).__name__}")
                self._json(
                    {"status": "unavailable"},
                    status=HTTPStatus.SERVICE_UNAVAILABLE,
                )
                return
            self._json(
                {
                    "status": "ready",
                    "version": self.server.context.release_version,
                    "revision": self.server.context.release_revision,
                }
            )
            return
        if path == "/favicon.svg":
            self._bytes(
                FAVICON_SVG.encode("utf-8"),
                content_type="image/svg+xml",
                extra={"Cache-Control": "public, max-age=86400"},
            )
            return
        if path == "/favicon.ico":
            self._bytes(
                ico_bytes(),
                content_type="image/x-icon",
                extra={"Cache-Control": "public, max-age=86400"},
            )
            return
        share_match = re.fullmatch(r"/share/([A-Za-z0-9_-]{32,64})", path)
        if share_match:
            self._shared_profile(share_match.group(1))
            return
        if path.startswith("/static/"):
            self._serve_static(path)
            return
        if path == "/":
            self._redirect("/dashboard" if self._session() else "/login")
            return
        if path == "/login":
            if self._session():
                self._redirect("/dashboard")
            else:
                self._html(
                    login_page(
                        dashboard_name=self.server.context.config.dashboard_name,
                        router_display_name=self.server.context.config.router_display_name,
                    )
                )
            return
        if path == "/dashboard":
            self._dashboard()
            return
        if path == "/api/policy-templates":
            session = self._require_session(api=True)
            if not session:
                return
            self._json({
                "templates": self.server.context.store.list_policy_templates(),
                "assignments": self.server.context.store.user_template_assignments(),
            })
            return
        if path == "/api/users":
            session = self._require_session(api=True)
            if not session:
                return
            try:
                users = self._users_with_metadata(self._credentials(session))
                self._json({"users": users})
            except RouterOSError as error:
                self._json({"error": str(error)}, status=HTTPStatus.BAD_GATEWAY)
            return
        if path == "/api/status":
            session = self._require_session(api=True)
            if not session:
                return
            try:
                credentials = self._credentials(session)
                router = self.server.context.router.verify_credentials(credentials)
                active_sessions = self.server.context.router.list_active_ovpn_sessions(credentials)
                self.server.context.store.observe_sessions(active_sessions)
                self._json(
                    {
                        "users": self._users_with_metadata(credentials),
                        "sessions": active_sessions,
                        "connections": self.server.context.store.recent_connections(50),
                        "alerts": self.server.context.store.recent_alerts(20),
                        "role": session.role,
                        "router": router,
                        "generated_at": int(time.time()),
                    }
                )
            except RouterOSError as error:
                self._json({"error": str(error)}, status=HTTPStatus.BAD_GATEWAY)
            return
        if path == "/api/service-health":
            session = self._require_session(api=True)
            if not session:
                return
            self._json(self._service_health(self._credentials(session)))
            return
        if path == "/api/setup-preflight":
            session = self._require_session(api=True)
            if not session:
                return
            try:
                credentials = self._credentials(session)
                inventory = self.server.context.router.get_bootstrap_inventory(credentials)
                router = inventory["resource"]
                servers = inventory.get("ovpn_servers") or []
                profiles = inventory.get("ppp_profiles") or []
                certificates = inventory.get("certificates") or []
                topology = self.server.context.config.topology
                configured_server = next((item for item in servers if item.get("name") == topology.server_name), {})
                configured_profile = next((item for item in profiles if item.get("name") == topology.ppp_profile), {})
                ca_certificate = next(
                    (
                        item for item in certificates
                        if item.get("name") == topology.ca_name
                        and "key-cert-sign" in str(item.get("key-usage", ""))
                    ),
                    {},
                )
                server_certificate = next(
                    (item for item in certificates if item.get("name") == configured_server.get("certificate")),
                    {},
                )
                architecture = str(router.get("architecture-name", "unknown"))
                version = str(router.get("version", "unknown"))
                image_target = container_image_target(architecture)
                try:
                    major_version = int(version.split(".", 1)[0])
                except (TypeError, ValueError):
                    major_version = 0
                checks = [
                    {
                        "name": "RouterOS version",
                        "status": "pass" if major_version >= 7 else "fail",
                        "detail": f"Detected RouterOS {version}; version 7 or newer is required.",
                    },
                    {
                        "name": "Container architecture",
                        "status": image_target["status"],
                        "detail": image_target["detail"],
                    },
                    {
                        "name": "Container package and device mode",
                        "status": "manual",
                        "detail": "Confirm the matching Container package is installed and device-mode is enabled in WinBox.",
                    },
                    {
                        "name": "OpenVPN server",
                        "status": "pass" if configured_server and str(configured_server.get("disabled", "no")).lower() not in {"yes", "true"} else "fail",
                        "detail": "Configured server is enabled." if configured_server else "Configured OpenVPN server was not found.",
                    },
                    {
                        "name": "PPP profile",
                        "status": "pass" if configured_profile else "fail",
                        "detail": "Configured profile exists." if configured_profile else "Configured PPP profile was not found.",
                    },
                    {
                        "name": "Certificate authority",
                        "status": "pass" if ca_certificate else "fail",
                        "detail": "A signing CA is available." if ca_certificate else "Configured CA is missing or cannot sign client certificates.",
                    },
                    {
                        "name": "OpenVPN server certificate",
                        "status": "pass" if server_certificate else "fail",
                        "detail": "The server certificate is present." if server_certificate else "The configured server certificate is missing.",
                    },
                    {
                        "name": "DNS and firewall review",
                        "status": "manual",
                        "detail": "Confirm public DNS, UDP access to the OpenVPN port, and RouterOS firewall rules during the maintenance window.",
                    },
                    {
                        "name": "Persistent storage",
                        "status": "manual",
                        "detail": "Confirm dedicated external storage for /data and /config with sufficient free space.",
                    },
                ]
                self._json({
                    "router": {
                        "architecture": architecture,
                        "version": version,
                        "free_storage": str(router.get("free-hdd-space", "unknown")),
                    },
                    "image_target": image_target,
                    "openvpn": {"name": configured_server.get("name", ""), "enabled": bool(configured_server)},
                    "checks": checks,
                })
            except RouterOSError as error:
                self._json({"error": str(error)}, status=HTTPStatus.BAD_GATEWAY)
            return
        if path == "/api/audit.csv":
            if not self._require_session(api=True):
                return
            try:
                start_at, end_at = self._report_range(query)
            except ValueError as error:
                self._json({"error": str(error)}, status=HTTPStatus.BAD_REQUEST)
                return
            rows = self.server.context.store.recent_audit(100, start_at=start_at, end_at=end_at)
            self._csv(
                "vpn-change-history.csv",
                ["timestamp", "operator", "action", "target", "result", "details"],
                [
                    [
                        time.strftime("%Y-%m-%d %H:%M:%S %z", time.localtime(int(item["created_at"]))),
                        item["actor"], item["action"], item["target"], item["status"], item["details"],
                    ]
                    for item in rows
                ],
            )
            return
        if path == "/api/audit.json":
            if not self._require_session(api=True):
                return
            try:
                start_at, end_at = self._report_range(query)
            except ValueError as error:
                self._json({"error": str(error)}, status=HTTPStatus.BAD_REQUEST)
                return
            rows = self.server.context.store.recent_audit(100, start_at=start_at, end_at=end_at)
            self._json_download("vpn-change-history.json", {"entries": rows, "generated_at": int(time.time())})
            return
        if path == "/api/backups/metadata.zip":
            session = self._require_session(api=True)
            if not session or not self._require_operator(session):
                return
            self._metadata_backup(session)
            return
        if path == "/api/connections.csv":
            if not self._require_session(api=True):
                return
            try:
                start_at, end_at = self._report_range(query)
            except ValueError as error:
                self._json({"error": str(error)}, status=HTTPStatus.BAD_REQUEST)
                return
            rows = self.server.context.store.recent_connections(250, start_at=start_at, end_at=end_at)
            self._csv(
                "vpn-connection-history.csv",
                [
                    "user", "connected", "disconnected", "source_ip", "vpn_ip",
                    "encryption", "received_bytes", "sent_bytes", "received_packets", "sent_packets",
                ],
                [
                    [
                        item["vpn_user"],
                        time.strftime("%Y-%m-%d %H:%M:%S %z", time.localtime(int(item["connected_at"]))),
                        (
                            time.strftime("%Y-%m-%d %H:%M:%S %z", time.localtime(int(item["disconnected_at"])))
                            if item.get("disconnected_at") else "connected"
                        ),
                        item["source_address"], item["vpn_address"], item["encoding"],
                        item["rx_bytes"], item["tx_bytes"], item["rx_packets"], item["tx_packets"],
                    ]
                    for item in rows
                ],
            )
            return
        if path == "/api/usage.csv":
            if not self._require_session(api=True):
                return
            period_start = DashboardServer._quota_period_start(int(time.time()))
            usage = self.server.context.store.usage_summary(period_start)
            rows = []
            for username, item in usage.items():
                controls = self.server.context.store.user_controls(username)
                total_bytes = int(item.get("rx_bytes", 0) or 0) + int(item.get("tx_bytes", 0) or 0)
                quota_mb = int(controls.get("quota_mb", 0) or 0)
                rows.append(
                    [
                        username,
                        time.strftime("%Y-%m-%d", time.localtime(period_start)),
                        item.get("connection_count", 0),
                        item.get("rx_bytes", 0),
                        item.get("tx_bytes", 0),
                        total_bytes,
                        quota_mb or "unlimited",
                        time.strftime("%Y-%m-%d %H:%M:%S %z", time.localtime(int(item.get("last_seen_at", 0) or 0))) if item.get("last_seen_at") else "never",
                    ]
                )
            self._csv(
                "vpn-monthly-usage.csv",
                ["user", "period_start", "connections", "received_bytes", "sent_bytes", "total_bytes", "quota_mb", "last_seen"],
                rows,
            )
            return
        self._json({"error": "Not found"}, status=HTTPStatus.NOT_FOUND)

    @staticmethod
    def _report_range(query: dict[str, list[str]]) -> tuple[int | None, int | None]:
        """Parse inclusive calendar dates into a UTC range without accepting timestamps."""
        def parse(name: str, *, inclusive_end: bool = False) -> int | None:
            raw = (query.get(name) or [""])[0]
            if not raw:
                return None
            try:
                day = dt.date.fromisoformat(raw)
            except ValueError as error:
                raise ValueError(f"{name} must be a date in YYYY-MM-DD format") from error
            if inclusive_end:
                day += dt.timedelta(days=1)
            return int(dt.datetime.combine(day, dt.time.min, tzinfo=dt.timezone.utc).timestamp())

        start_at, end_at = parse("from"), parse("to", inclusive_end=True)
        if start_at is not None and end_at is not None and start_at >= end_at:
            raise ValueError("from must be on or before to")
        return start_at, end_at

    def _metadata_backup(self, session: Session) -> None:
        """Download a self-verifying backup without copying RouterOS secrets."""
        created_at = int(time.time())
        metadata = json.dumps(
            self.server.context.store.backup_snapshot(), separators=(",", ":"), sort_keys=True
        ).encode("utf-8")
        manifest = json.dumps({
            "format": "mikrotik-openvpn-gui-backup",
            "version": 1,
            "created_at": created_at,
            "files": {"metadata.json": hashlib.sha256(metadata).hexdigest()},
            "contains": "dashboard metadata only; no RouterOS configuration, passwords, keys, or profiles",
        }, separators=(",", ":"), sort_keys=True).encode("utf-8")
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("manifest.json", manifest)
            archive.writestr("metadata.json", metadata)
        self.server.context.store.audit(
            actor=session.username, action="backup.export", target="dashboard-metadata", status="success",
            details={"format_version": 1},
        )
        self._bytes(
            stream.getvalue(), content_type="application/zip",
            extra={"Content-Disposition": f'attachment; filename="vpn-dashboard-backup-{created_at}.zip"'},
        )

    def _serve_static(self, path: str) -> None:
        name = path.removeprefix("/static/")
        if name not in {"app.css", "app.js"}:
            self._json({"error": "Not found"}, status=HTTPStatus.NOT_FOUND)
            return
        target = STATIC / name
        payload = target.read_bytes()
        content_type = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        self._bytes(
            payload,
            content_type=content_type + ("; charset=utf-8" if content_type.startswith("text/") else ""),
            extra={"Cache-Control": "public, max-age=3600"},
        )

    def _shared_profile(self, token: str) -> None:
        shared = self.server.profile_shares.take(token)
        if shared is None:
            self._bytes(
                b"This profile link is expired or has already been used.",
                status=HTTPStatus.GONE,
                content_type="text/plain; charset=utf-8",
            )
            return
        self._bytes(
            shared.payload,
            content_type="application/zip",
            extra={"Content-Disposition": f'attachment; filename="{shared.filename}"'},
        )

    def _dashboard(self) -> None:
        session = self._require_session()
        if not session:
            return
        credentials = self._credentials(session)
        try:
            router = self.server.context.router.verify_credentials(credentials)
        except RouterOSError:
            self.server.context.sessions.destroy(session.session_id)
            self._redirect("/login")
            return

        warnings: list[str] = []

        def optional_router_data(label: str, default: Any, operation: Any) -> Any:
            try:
                return operation()
            except RouterOSError:
                warnings.append(label)
                return default

        users = optional_router_data(
            "VPN users are temporarily unavailable.",
            [],
            lambda: self._users_with_metadata(credentials),
        )
        active_sessions = optional_router_data(
            "Live connection data is temporarily unavailable.",
            [],
            lambda: self.server.context.router.list_active_ovpn_sessions(credentials),
        )
        self.server.context.store.observe_sessions(active_sessions)
        ovpn_server = optional_router_data(
            "OpenVPN security policy is temporarily unavailable.",
            {},
            lambda: self.server.context.router.get_ovpn_server_status(credentials),
        )
        certificate_settings = optional_router_data(
            "Certificate revocation status is temporarily unavailable.",
            {},
            lambda: self.server.context.router.get_certificate_settings(credentials),
        )
        certificates = optional_router_data(
            "Certificate inventory is temporarily unavailable.",
            [],
            lambda: self.server.context.router.list_ovpn_client_certificates(credentials),
        )
        endpoint = optional_router_data(
            "RouterOS public endpoint is temporarily unavailable.",
            {},
            lambda: self.server.context.router.get_public_endpoint(credentials),
        )
        public_ip = str(endpoint.get("public_ip", ""))
        try:
            self.server.context.store.verify_readiness()
            database_ready = True
        except Exception as error:
            print(f"dashboard data store health unavailable reason={type(error).__name__}")
            warnings.append("Dashboard data store health is temporarily unavailable.")
            database_ready = False
        health = service_health_snapshot(
            router=router,
            ovpn_server=ovpn_server,
            certificate_settings=certificate_settings,
            certificates=certificates,
            config=self.server.context.config,
            database_ready=database_ready,
        )
        self._html(
            dashboard_page(
                actor=session.username,
                csrf=session.csrf_token,
                users=users,
                sessions=active_sessions,
                devices=self.server.context.store.active_devices(),
                connections=self.server.context.store.recent_connections(50),
                connection_summaries=self.server.context.store.connection_summaries(),
                certificates=certificates,
                ovpn_server=ovpn_server,
                certificate_settings=certificate_settings,
                warnings=warnings,
                audit=self.server.context.store.recent_audit(100),
                alerts=self.server.context.store.recent_alerts(20),
                policy_templates=self.server.context.store.list_policy_templates(),
                admin_role=session.role,
                router=router,
                dashboard_name=self.server.context.config.dashboard_name,
                router_display_name=self.server.context.config.router_display_name,
                vpn_host=self.server.context.config.topology.host,
                public_ip=public_ip,
                router_dns=self.server.context.config.topology.router_dns,
                access_layer_label=self.server.context.config.access_layer_label,
                health=health,
            )
        )

    def do_POST(self) -> None:
        path = urllib.parse.urlsplit(self.path).path
        if path == "/login":
            self._login()
            return
        if path == "/logout":
            self._logout()
            return
        if path == "/api/users":
            self._create_user()
            return
        if path == "/api/setup-plan":
            self._setup_plan()
            return
        if path == "/api/openvpn-foundation-plan":
            self._openvpn_foundation_plan()
            return
        if path == "/api/backups/preflight":
            self._backup_preflight()
            return
        if path == "/api/backups/validate":
            self._backup_validate_archive()
            return
        if path == "/api/backups/restore-plan":
            self._backup_restore_plan()
            return
        if path == "/api/policy-templates":
            self._create_policy_template()
            return
        match = re.fullmatch(r"/api/policy-templates/([A-Za-z0-9_-]{1,64})/(preview|apply)", path)
        if match:
            self._policy_template_action(match.group(1), match.group(2))
            return
        match = re.fullmatch(r"/api/users/([^/]+)/(suspend|restore)", path)
        if match:
            self._set_user_access(
                urllib.parse.unquote(match.group(1)),
                suspended=match.group(2) == "suspend",
            )
            return
        match = re.fullmatch(r"/api/users/([^/]+)/profiles", path)
        if match:
            self._create_profile(urllib.parse.unquote(match.group(1)))
            return
        match = re.fullmatch(r"/api/devices/([^/]+)/revoke", path)
        if match:
            self._revoke_device(urllib.parse.unquote(match.group(1)))
            return
        match = re.fullmatch(r"/api/users/([^/]+)/duplicate", path)
        if match:
            self._duplicate_user(urllib.parse.unquote(match.group(1)))
            return
        match = re.fullmatch(r"/api/alerts/(\d+)/ack", path)
        if match:
            self._ack_alert(int(match.group(1)))
            return
        self._json({"error": "Not found"}, status=HTTPStatus.NOT_FOUND)

    def _setup_plan(self) -> None:
        """Generate an intentionally non-executable installation review plan."""
        session = self._require_session(api=True)
        if not session or not self._require_csrf(session):
            return
        try:
            data = self._read_json()
            origin = str(data.get("origin", "")).strip().rstrip("/")
            image = str(data.get("image", "")).strip()
            storage = str(data.get("storage", "")).strip()
            subnet = ipaddress.ip_network(str(data.get("subnet", "")).strip(), strict=True)
            lan = ipaddress.ip_network(str(data.get("lan", "")).strip(), strict=True)
        except (ValueError, TypeError):
            self._json({"error": "Use valid IPv4 or IPv6 CIDRs for the container and LAN networks."}, status=HTTPStatus.BAD_REQUEST)
            return
        if not origin.startswith(("https://", "http://")):
            self._json({"error": "Dashboard origin must be an http:// or https:// URL."}, status=HTTPStatus.BAD_REQUEST)
            return
        if origin.startswith("http://") and not re.match(r"^http://(?:127\.0\.0\.1|localhost|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)", origin):
            self._json({"error": "Public dashboard origins require HTTPS; plain HTTP is limited to private/local setup."}, status=HTTPStatus.BAD_REQUEST)
            return
        if not IMMUTABLE_IMAGE_PATTERN.fullmatch(image):
            self._json({"error": "Use an immutable sha- image tag; mutable tags such as latest or edge are rejected."}, status=HTTPStatus.BAD_REQUEST)
            return
        if not storage.startswith("/") or ".." in storage or storage in {"/", "/flash"}:
            self._json({"error": "Choose a dedicated absolute external-storage path, without '..' or /flash."}, status=HTTPStatus.BAD_REQUEST)
            return
        if (
            subnet.version != lan.version
            or subnet.num_addresses < 4
            or subnet.overlaps(lan)
        ):
            self._json(
                {"error": "The container and LAN CIDRs must use the same IPv4 or IPv6 family, provide two usable addresses, and not overlap."},
                status=HTTPStatus.BAD_REQUEST,
            )
            return
        # Do not materialise ``network.hosts()``: IPv6 /64 networks are
        # enormous.  RouterOS needs only deterministic gateway/veth addresses.
        gateway_address = subnet.network_address + 1
        veth_address = subnet.network_address + 2
        plan = "\n".join([
            "# REVIEW ONLY — do not paste until each placeholder is reviewed.",
            "# This plan intentionally omits passwords, tokens, private keys, and profile files.",
            f"# Dashboard origin: {origin}",
            f"# Immutable image: {image}",
            f"# Dedicated external storage: {storage}",
            f"# Container subnet: {subnet} ({'IPv6' if subnet.version == 6 else 'IPv4'}; non-overlapping with LAN {lan})",
            "",
            "# Manual gates before any apply:",
            "# 1. Install the matching RouterOS Container package and complete physical device-mode confirmation.",
            "# 2. Confirm free external storage, DNS, and HTTPS access to the chosen registry.",
            "# 3. Review existing bridges, firewall rules, OpenVPN objects, certificates, and REST TLS.",
            "# 4. If an OpenVPN foundation is missing, create it deliberately in WinBox first:",
            "#    - create/import a trusted CA and server certificate;",
            "#    - create an enabled OpenVPN server bound to the intended UDP port;",
            "#    - create a PPP profile with the intended address pool and DNS;",
            "#    - add the required input/NAT rules, restricted to the chosen public endpoint.",
            "# 5. Back up the router and test one disposable client before issuing real profiles.",
            "",
            "# Idempotent dashboard container skeleton (replace <...> only after a backup and maintenance window):",
            f"/container/config/set tmpdir={storage}/tmp",
            f"/interface/veth/add name=<veth-vpn-dashboard> address={veth_address}/{subnet.prefixlen} gateway={gateway_address}",
            "# Attach the veth to a reviewed dedicated bridge; do not change WAN firewall automatically.",
            f"/container/add remote-image={image} interface=<veth-vpn-dashboard> root-dir={storage}/root",
            f"# Mount persistent dashboard data at {storage}/data -> /data; configure non-secret environment values separately.",
            "# Start the canary, verify /healthz and /readyz over the local bridge, then publish HTTPS only after certificate validation.",
        ])
        self._json({"plan": plan, "origin": origin, "image": image})

    def _openvpn_foundation_plan(self) -> None:
        """Create a non-mutating OpenVPN-foundation plan for an empty router.

        The normal container installation path deliberately remains separate.
        This advanced helper returns copyable RouterOS commands only after
        checking that it would not overwrite an existing VPN foundation.
        """
        session = self._require_session(api=True)
        if not session or not self._require_csrf(session) or not self._require_operator(session):
            return
        try:
            data = self._read_json()
            endpoint = str(data.get("endpoint", "")).strip().rstrip(".")
            lan = ipaddress.ip_network(str(data.get("lan", "")).strip(), strict=True)
            vpn_subnet = ipaddress.ip_network(str(data.get("vpn_subnet", "")).strip(), strict=True)
            dns_server = ipaddress.ip_address(str(data.get("dns_server", "")).strip())
            port = int(str(data.get("port", "1194")).strip())
            names = {
                key: str(data.get(key, "")).strip()
                for key in ("ca_name", "server_certificate", "server_name", "ppp_profile", "pool_name")
            }
        except (TypeError, ValueError):
            self._json({"error": "Use a valid endpoint, IPv4 LAN/VPN CIDRs, DNS server, and UDP port."}, status=HTTPStatus.BAD_REQUEST)
            return
        if not VPN_ENDPOINT_PATTERN.fullmatch(endpoint) or endpoint.startswith(("-", ".")):
            self._json({"error": "VPN endpoint must be a hostname or IP address without a URL scheme."}, status=HTTPStatus.BAD_REQUEST)
            return
        if any(not ROUTEROS_NAME_PATTERN.fullmatch(value) for value in names.values()):
            self._json({"error": "RouterOS object names may contain only letters, numbers, dot, dash, and underscore (maximum 48 characters)."}, status=HTTPStatus.BAD_REQUEST)
            return
        if (
            lan.version != 4
            or vpn_subnet.version != 4
            or vpn_subnet.num_addresses < 8
            or lan.overlaps(vpn_subnet)
            or dns_server.version != 4
            or not 1 <= port <= 65535
        ):
            self._json({"error": "Use non-overlapping IPv4 LAN/VPN CIDRs, a VPN subnet with at least six usable addresses, an IPv4 DNS server, and a valid UDP port."}, status=HTTPStatus.BAD_REQUEST)
            return
        try:
            credentials = self._credentials(session)
            inventory = self.server.context.router.get_bootstrap_inventory(credentials)
        except RouterOSError as error:
            self._json({"error": str(error)}, status=HTTPStatus.BAD_GATEWAY)
            return
        existing_servers = inventory.get("ovpn_servers") or []
        existing_profiles = {str(item.get("name", "")) for item in inventory.get("ppp_profiles") or []}
        existing_certificates = {str(item.get("name", "")) for item in inventory.get("certificates") or []}
        if existing_servers:
            self._json({"error": "OpenVPN bootstrap is available only when the router has no existing OpenVPN server. Use the normal installer for an existing VPN."}, status=HTTPStatus.CONFLICT)
            return
        conflicts = sorted(
            set(names.values()).intersection(existing_profiles | existing_certificates)
        )
        if conflicts:
            self._json({"error": f"Bootstrap would reuse existing RouterOS objects: {', '.join(conflicts)}. Choose different names or review the router manually."}, status=HTTPStatus.CONFLICT)
            return
        # Avoid materialising ``network.hosts()``: a valid IPv4 network can
        # contain millions of addresses, while this plan needs only its edges.
        local_address = ipaddress.IPv4Address(int(vpn_subnet.network_address) + 1)
        pool_start = ipaddress.IPv4Address(int(vpn_subnet.network_address) + 2)
        pool_end = ipaddress.IPv4Address(int(vpn_subnet.broadcast_address) - 1)
        checkpoint = f"vpn-bootstrap-before-{int(time.time())}"
        plan = "\n".join([
            "# REVIEW-ONLY OPENVPN FOUNDATION PLAN — no command is executed by the dashboard.",
            "# Supported only for an otherwise unconfigured OpenVPN router.",
            "# This plan contains no passwords, private keys, tokens, user accounts, or dashboard data.",
            "",
            "# 1. Make a rollback checkpoint before changing RouterOS.",
            f"/export file={checkpoint} compact",
            "",
            "# 2. Create the dedicated client-address pool and PPP profile.",
            f"/ip/pool/add name={names['pool_name']} ranges={pool_start}-{pool_end} comment=\"VPN Dashboard bootstrap\"",
            f"/ppp/profile/add name={names['ppp_profile']} local-address={local_address} remote-address={names['pool_name']} dns-server={dns_server} only-one=yes comment=\"VPN Dashboard bootstrap\"",
            "",
            "# 3. Create a local CA and server certificate. Keep private keys on the router.",
            f"/certificate/add name={names['ca_name']} common-name={names['ca_name']} key-usage=key-cert-sign,crl-sign days-valid=3650 key-size=2048 digest-algorithm=sha256",
            f"/certificate/sign {names['ca_name']}",
            f"/certificate/set {names['ca_name']} trusted=yes",
            f"/certificate/add name={names['server_certificate']} common-name={endpoint} key-usage=tls-server days-valid=1825 key-size=2048 digest-algorithm=sha256",
            f"/certificate/sign {names['server_certificate']} ca={names['ca_name']}",
            f"/certificate/set {names['server_certificate']} trusted=yes",
            "",
            "# 4. Create the OpenVPN server disabled. Inspect it before enabling it.",
            f"/interface/ovpn-server/server/add name={names['server_name']} disabled=yes protocol=udp port={port} mode=ip certificate={names['server_certificate']} default-profile={names['ppp_profile']} require-client-certificate=yes tls-version=only-1.2 auth=null cipher=aes256-gcm redirect-gateway=def1",
            "",
            "# 5. Firewall placement is topology-specific. Add this disabled rule, then move it above the reviewed WAN drop rule before enabling it.",
            f"/ip/firewall/filter/add chain=input action=accept protocol=udp dst-port={port} disabled=yes comment=\"VPN Dashboard bootstrap: review placement before enable\"",
            "",
            "# 6. Verify the certificate dates, server settings, route/NAT policy, and firewall position in WinBox.",
            "#    Enable the firewall rule first, then enable the server only after a maintenance-window test.",
            "# /ip/firewall/filter/enable [find comment=\"VPN Dashboard bootstrap: review placement before enable\"]",
            f"# /interface/ovpn-server/server/enable [find name={names['server_name']}]",
            "",
            f"# Endpoint for generated profiles: {endpoint}:{port}/udp",
            f"# LAN route to review: {lan}; VPN client network: {vpn_subnet}.",
            "# If the router does not already masquerade this VPN pool to WAN, add a reviewed source-NAT rule manually.",
        ])
        self.server.context.store.audit(
            actor=session.username,
            action="bootstrap.foundation-plan",
            target=names["server_name"],
            status="success",
            details={"port": port, "vpn_subnet": str(vpn_subnet), "endpoint": endpoint},
        )
        self._json({"plan": plan, "checkpoint": checkpoint, "server_name": names["server_name"]})

    def _backup_preflight(self) -> None:
        """Validate a backup manifest only; this route never restores data."""
        session = self._require_session(api=True)
        if not session or not self._require_csrf(session) or not self._require_operator(session):
            return
        try:
            value = self._read_json()
            manifest = value.get("manifest")
            metadata_sha256 = str(value.get("metadata_sha256", ""))
            if not isinstance(manifest, dict):
                raise ValueError("Backup manifest is required")
            if manifest.get("format") != "mikrotik-openvpn-gui-backup" or manifest.get("version") != 1:
                raise ValueError("This backup format is not supported")
            expected = str((manifest.get("files") or {}).get("metadata.json", ""))
            if not re.fullmatch(r"[a-f0-9]{64}", expected) or not secrets.compare_digest(expected, metadata_sha256):
                raise ValueError("Metadata checksum does not match the backup manifest")
        except ValueError as error:
            self._json({"compatible": False, "error": str(error)}, status=HTTPStatus.BAD_REQUEST)
            return
        self.server.context.store.audit(
            actor=session.username, action="backup.preflight", target="dashboard-metadata", status="success",
            details={"format_version": 1},
        )
        self._json({
            "compatible": True,
            "restore_available": False,
            "message": "Backup is compatible. Restore remains review-first and is not applied automatically.",
        })

    def _backup_validate_archive(self) -> None:
        """Validate an uploaded local backup archive without restoring or persisting it."""
        session = self._require_session(api=True)
        if not session or not self._require_csrf(session) or not self._require_operator(session):
            return
        try:
            value = self._read_json()
            encoded = value.get("archive_base64")
            if not isinstance(encoded, str) or not encoded:
                raise ValueError("Backup archive is required")
            if len(encoded) > 48 * 1024:
                raise ValueError("Backup archive is too large")
            archive_bytes = base64.b64decode(encoded, validate=True)
            if len(archive_bytes) > 36 * 1024:
                raise ValueError("Backup archive is too large")
            with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
                names = set(archive.namelist())
                if names != {"manifest.json", "metadata.json"}:
                    raise ValueError("Backup must contain only manifest.json and metadata.json")
                manifest = json.loads(archive.read("manifest.json").decode("utf-8"))
                metadata = archive.read("metadata.json")
            if not isinstance(manifest, dict) or manifest.get("format") != "mikrotik-openvpn-gui-backup" or manifest.get("version") != 1:
                raise ValueError("This backup format is not supported")
            expected = str((manifest.get("files") or {}).get("metadata.json", ""))
            actual = hashlib.sha256(metadata).hexdigest()
            if not re.fullmatch(r"[a-f0-9]{64}", expected) or not secrets.compare_digest(expected, actual):
                raise ValueError("Metadata checksum does not match the backup manifest")
        except (ValueError, OSError, zipfile.BadZipFile, json.JSONDecodeError, UnicodeDecodeError) as error:
            self._json({"compatible": False, "error": str(error)}, status=HTTPStatus.BAD_REQUEST)
            return
        self.server.context.store.audit(
            actor=session.username, action="backup.validate", target="dashboard-metadata", status="success",
            details={"format_version": 1, "metadata_bytes": len(metadata)},
        )
        self._json({
            "compatible": True,
            "restore_available": False,
            "metadata_bytes": len(metadata),
            "message": "Backup is valid and compatible. No data was restored or changed.",
        })

    def _backup_restore_plan(self) -> None:
        """Return a review-only restore plan for a validated metadata archive.

        The public dashboard never restores automatically.  This endpoint is
        intentionally limited to safe metadata counts and explicit operator
        steps; the archive is decoded in memory and discarded after the
        response is built.
        """
        session = self._require_session(api=True)
        if not session or not self._require_csrf(session) or not self._require_operator(session):
            return
        try:
            value = self._read_json()
            encoded = value.get("archive_base64")
            if not isinstance(encoded, str) or not encoded:
                raise ValueError("Backup archive is required")
            if len(encoded) > 48 * 1024:
                raise ValueError("Backup archive is too large")
            archive_bytes = base64.b64decode(encoded, validate=True)
            if len(archive_bytes) > 36 * 1024:
                raise ValueError("Backup archive is too large")
            with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
                if set(archive.namelist()) != {"manifest.json", "metadata.json"}:
                    raise ValueError("Backup must contain only manifest.json and metadata.json")
                manifest = json.loads(archive.read("manifest.json").decode("utf-8"))
                metadata_bytes = archive.read("metadata.json")
            if not isinstance(manifest, dict) or manifest.get("format") != "mikrotik-openvpn-gui-backup" or manifest.get("version") != 1:
                raise ValueError("This backup format is not supported")
            expected = str((manifest.get("files") or {}).get("metadata.json", ""))
            actual = hashlib.sha256(metadata_bytes).hexdigest()
            if not re.fullmatch(r"[a-f0-9]{64}", expected) or not secrets.compare_digest(expected, actual):
                raise ValueError("Metadata checksum does not match the backup manifest")
            metadata = json.loads(metadata_bytes.decode("utf-8"))
            if not isinstance(metadata, dict):
                raise ValueError("Backup metadata must be an object")
        except (ValueError, OSError, zipfile.BadZipFile, json.JSONDecodeError, UnicodeDecodeError) as error:
            self._json({"compatible": False, "error": str(error)}, status=HTTPStatus.BAD_REQUEST)
            return
        users = metadata.get("users") if isinstance(metadata.get("users"), list) else []
        self.server.context.store.audit(
            actor=session.username, action="backup.restore-plan", target="dashboard-metadata", status="success",
            details={"format_version": 1, "metadata_bytes": len(metadata_bytes), "user_count": len(users)},
        )
        self._json({
            "compatible": True,
            "restore_available": False,
            "metadata_sha256": actual,
            "metadata_bytes": len(metadata_bytes),
            "summary": {"users": len(users)},
            "steps": [
                "Create a fresh encrypted RouterOS backup and stop the dashboard container.",
                "Copy the current /data directory to a private rollback checkpoint.",
                "Restore metadata.json into the router-local /data store using a reviewed maintenance script.",
                "Start the container and verify /readyz, user counts, and Change History.",
                "Keep the pre-restore checkpoint until the observation window closes.",
            ],
            "message": "Plan generated. No data was restored or persisted.",
        })

    def do_PATCH(self) -> None:
        path = urllib.parse.urlsplit(self.path).path
        match = re.fullmatch(r"/api/policy-templates/([A-Za-z0-9_-]{1,64})", path)
        if match:
            self._update_policy_template(match.group(1))
            return
        match = re.fullmatch(r"/api/users/([^/]+)", path)
        if not match:
            self._json({"error": "Not found"}, status=HTTPStatus.NOT_FOUND)
            return
        self._update_user(urllib.parse.unquote(match.group(1)))

    def do_DELETE(self) -> None:
        path = urllib.parse.urlsplit(self.path).path
        match = re.fullmatch(r"/api/sessions/([^/]+)", path)
        if match:
            self._terminate_session(urllib.parse.unquote(match.group(1)))
            return
        match = re.fullmatch(r"/api/users/([^/]+)", path)
        if not match:
            self._json({"error": "Not found"}, status=HTTPStatus.NOT_FOUND)
            return
        self._delete_user(urllib.parse.unquote(match.group(1)))

    def _login(self) -> None:
        identity = self._client_ip()
        if not self.server.context.limiter.allow(identity):
            self.server.context.store.audit(
                actor="unknown", action="login.rate_limited", target="dashboard",
                status="failed", details={"source": identity},
            )
            self._html(
                login_page(
                    "Too many attempts. Try again in a few minutes.",
                    dashboard_name=self.server.context.config.dashboard_name,
                    router_display_name=self.server.context.config.router_display_name,
                ),
                status=429,
            )
            return
        try:
            form = self._read_form()
            username = self._validate_username(form.get("username", ""))
            password = form.get("password", "")
            if not password:
                raise ValueError("Password is required")
            credentials = RouterOSCredentials(username, password)
            self.server.context.router.verify_credentials(credentials)
        except (ValueError, RouterOSError):
            self.server.context.limiter.fail(identity)
            self.server.context.store.audit(
                actor=username if "username" in locals() else "unknown",
                action="login.failure", target="dashboard", status="failed",
                details={"source": identity},
            )
            self._html(
                login_page(
                    "MikroTik authentication failed.",
                    dashboard_name=self.server.context.config.dashboard_name,
                    router_display_name=self.server.context.config.router_display_name,
                ),
                status=HTTPStatus.UNAUTHORIZED,
            )
            return
        self.server.context.limiter.success(identity)
        role = self.server.context.router.get_admin_role(credentials)
        session = self.server.context.sessions.create(username, password, role=role)
        cookie = (
            f"vpn_session={session.session_id}; Path=/; Max-Age=28800; "
            "Secure; HttpOnly; SameSite=Strict"
        )
        self.server.context.store.audit(
            actor=username, action="login", target="dashboard", status="success",
            details={"role": role},
        )
        self._redirect("/dashboard", cookie=cookie)

    def _logout(self) -> None:
        session = self._require_session()
        if not session:
            return
        try:
            form = self._read_form()
        except ValueError:
            self._json({"error": "Invalid request"}, status=HTTPStatus.BAD_REQUEST)
            return
        if not self._require_csrf(session, form.get("csrf", "")):
            return
        self.server.context.sessions.destroy(session.session_id)
        cookie = "vpn_session=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict"
        self._redirect("/login", cookie=cookie)

    def _find_user(self, credentials: RouterOSCredentials, user_id: str) -> dict[str, Any]:
        for user in self.server.context.router.list_ovpn_users(credentials):
            if user.get("id") == user_id:
                return user
        raise ValueError("VPN user was not found")

    def _find_session(self, credentials: RouterOSCredentials, session_id: str) -> dict[str, Any]:
        for item in self.server.context.router.list_active_ovpn_sessions(credentials):
            if item.get("id") == session_id:
                return item
        raise ValueError("OpenVPN session is no longer active")

    def _profile_response(self, profile: ProvisionedProfile, filename: str) -> None:
        safe_filename = re.sub(r"[^A-Za-z0-9_.-]+", "-", filename).strip("-") or "openvpn.ovpn"
        self._bytes(
            profile.profile,
            content_type="application/x-openvpn-profile",
            extra={"Content-Disposition": f'attachment; filename="{safe_filename}"'},
        )

    @staticmethod
    def _profile_archive(profile: ProvisionedProfile, filename: str) -> tuple[bytes, str]:
        safe_filename = re.sub(r"[^A-Za-z0-9_.-]+", "-", filename).strip("-") or "openvpn.ovpn"
        if not safe_filename.lower().endswith(".ovpn"):
            safe_filename += ".ovpn"
        archive_name = f"{safe_filename[:-5]}.zip"
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(safe_filename, profile.profile)
        return stream.getvalue(), archive_name

    def _profile_archive_response(self, profile: ProvisionedProfile, filename: str) -> None:
        payload, archive_name = self._profile_archive(profile, filename)
        self._bytes(
            payload,
            content_type="application/zip",
            extra={"Content-Disposition": f'attachment; filename="{archive_name}"'},
        )

    def _profile_share_response(self, profile: ProvisionedProfile, filename: str) -> None:
        payload, archive_name = self._profile_archive(profile, filename)
        token, ttl = self.server.profile_shares.put(payload, archive_name)
        share_url = f"{self.server.context.public_origin.rstrip('/')}/share/{token}"
        self._json(
            {
                "download_url": share_url,
                "filename": archive_name,
                "expires_in": ttl,
                "qr_svg": qr_svg(share_url),
            }
        )

    def _deliver_profile(self, profile: ProvisionedProfile, filename: str, delivery: str) -> None:
        if delivery == "qr":
            self._profile_share_response(profile, filename)
        elif delivery == "zip":
            self._profile_archive_response(profile, filename)
        else:
            self._profile_response(profile, filename)

    def _record_profile(
        self,
        *,
        session: Session,
        vpn_user: str,
        device_name: str,
        profile: ProvisionedProfile,
    ) -> None:
        self.server.context.store.add_device(
            device_id=secrets.token_urlsafe(12),
            vpn_user=vpn_user,
            device_name=device_name,
            certificate_name=profile.certificate_name,
            certificate_id=profile.certificate_id,
            fingerprint=profile.fingerprint,
        )
        self.server.context.store.audit(
            actor=session.username,
            action="profile.create",
            target=vpn_user,
            status="success",
            details={"device": device_name, "certificate": profile.certificate_name},
        )

    def _provision_user(
        self,
        *,
        session: Session,
        data: dict[str, Any],
        audit_action: str,
        source_name: str | None = None,
    ) -> None:
        credentials = self._credentials(session)
        user_id: str | None = None
        username = ""
        try:
            username = self._validate_username(str(data.get("username", "")))
            password = self._validate_secret(str(data.get("password", "")), "VPN password")
            device_name = self._validate_device(str(data.get("device_name", "")))
            email = self._validate_email(str(data.get("email", "")))
            delivery = str(data.get("delivery", "ovpn"))
            if delivery not in {"ovpn", "zip", "qr"}:
                raise ValueError("Choose a valid profile delivery method")
            comment = str(data.get("comment", "")).strip()[:96]
            controls = self._parse_controls(data)
            self.server.context.config.topology.require_profile_generation(
                policy=controls["policy"], dns_mode=controls["dns_mode"]
            )
            if not self._checkpoint(session, audit_action):
                return
            router_profile = self.server.context.router.ensure_rate_profile(
                credentials,
                username=username,
                rate_limit_kbps=int(controls["rate_limit_kbps"]),
            )
            created = self.server.context.router.create_user(
                credentials,
                username=username,
                password=password,
                comment=comment or f"Managed by VPN Dashboard · {device_name}",
                profile=router_profile,
            )
            user_id = created.get(".id") or created.get("id")
            if not user_id:
                user_id = next(
                    (user["id"] for user in self.server.context.router.list_ovpn_users(credentials) if user["name"] == username),
                    None,
                )
            self.server.context.store.set_user_email(username, email)
            self.server.context.store.set_user_controls(username, **controls)
            profile = self.server.context.router.provision_profile(
                credentials,
                vpn_user=username,
                device_name=device_name,
                key_passphrase=password,
                policy=controls["policy"],
                dns_mode=controls["dns_mode"],
            )
            self._record_profile(
                session=session,
                vpn_user=username,
                device_name=device_name,
                profile=profile,
            )
            self.server.context.store.audit(
                actor=session.username,
                action=audit_action,
                target=username,
                status="success",
                details={"device": device_name, "email": email, **({"source": source_name} if source_name else {})},
            )
            self._deliver_profile(profile, f"{username}-{device_name}.ovpn", delivery)
        except (ValueError, RouterOSError) as error:
            if user_id:
                try:
                    self.server.context.router.delete_user(credentials, user_id=user_id)
                except RouterOSError:
                    pass
            if username:
                self.server.context.store.delete_user_email(username)
                self.server.context.store.delete_user_controls(username)
            self.server.context.store.audit(
                actor=session.username,
                action=audit_action,
                target=username or "invalid",
                status="failed",
                details={"reason": type(error).__name__},
            )
            self._json({"error": str(error)}, status=HTTPStatus.BAD_REQUEST)

    def _create_user(self) -> None:
        session = self._require_session(api=True)
        if not session or not self._require_csrf(session) or not self._require_operator(session):
            return
        try:
            data = self._read_json()
        except ValueError as error:
            self._json({"error": str(error)}, status=HTTPStatus.BAD_REQUEST)
            return
        self._provision_user(session=session, data=data, audit_action="user.create")

    def _duplicate_user(self, source_id: str) -> None:
        session = self._require_session(api=True)
        if not session or not self._require_csrf(session) or not self._require_operator(session):
            return
        credentials = self._credentials(session)
        try:
            source = self._find_user(credentials, source_id)
            data = self._read_json()
            source_controls = self.server.context.store.user_controls(str(source["name"]))
            for key in (
                "policy", "max_sessions", "rate_limit_kbps", "dns_mode", "notifications",
                "quota_mb", "schedule",
            ):
                data.setdefault(key, source_controls.get(key))
            if not str(data.get("comment", "")).strip():
                source_comment = str(source.get("comment", "")).strip()
                data["comment"] = f"Copy of {source['name']} · {source_comment}"[:96]
        except (ValueError, RouterOSError) as error:
            self._json({"error": str(error)}, status=HTTPStatus.BAD_REQUEST)
            return
        self._provision_user(
            session=session,
            data=data,
            audit_action="user.duplicate",
            source_name=str(source["name"]),
        )

    def _create_profile(self, user_id: str) -> None:
        session = self._require_session(api=True)
        if not session or not self._require_csrf(session) or not self._require_operator(session):
            return
        credentials = self._credentials(session)
        try:
            data = self._read_json()
            device_name = self._validate_device(str(data.get("device_name", "")))
            passphrase = self._validate_secret(
                str(data.get("key_passphrase", "")), "Private-key passphrase"
            )
            delivery = str(data.get("delivery", "ovpn"))
            if delivery not in {"ovpn", "zip", "qr"}:
                raise ValueError("Choose a valid profile delivery method")
            user = self._find_user(credentials, user_id)
            controls = self.server.context.store.user_controls(str(user["name"]))
            self.server.context.config.topology.require_profile_generation(
                policy=str(controls.get("policy", "full-tunnel")),
                dns_mode=str(controls.get("dns_mode", "router")),
            )
            if not self._checkpoint(session, "profile.create"):
                return
            profile = self.server.context.router.provision_profile(
                credentials,
                vpn_user=str(user["name"]),
                device_name=device_name,
                key_passphrase=passphrase,
                policy=str(controls.get("policy", "full-tunnel")),
                dns_mode=str(controls.get("dns_mode", "router")),
            )
            self._record_profile(
                session=session,
                vpn_user=str(user["name"]),
                device_name=device_name,
                profile=profile,
            )
            self._deliver_profile(profile, f"{user['name']}-{device_name}.ovpn", delivery)
        except (ValueError, RouterOSError) as error:
            self._json({"error": str(error)}, status=HTTPStatus.BAD_REQUEST)

    def _update_user(self, user_id: str) -> None:
        session = self._require_session(api=True)
        if not session or not self._require_csrf(session) or not self._require_operator(session):
            return
        credentials = self._credentials(session)
        try:
            data = self._read_json()
            user = self._find_user(credentials, user_id)
            password_raw = str(data.get("password", ""))
            password = self._validate_secret(password_raw, "VPN password") if password_raw else None
            email = (
                self._validate_email(str(data.get("email", "")))
                if "email" in data
                else None
            )
            comment = str(data.get("comment", "")).strip()[:96]
            disabled = bool(data.get("disabled", False))
            controls = self._parse_controls(
                data, self.server.context.store.user_controls(str(user["name"]))
            )
            if not self._checkpoint(session, "user.update"):
                return
            router_profile = self.server.context.router.ensure_rate_profile(
                credentials,
                username=str(user["name"]),
                rate_limit_kbps=int(controls["rate_limit_kbps"]),
            )
            self.server.context.router.update_user(
                credentials,
                user_id=user_id,
                password=password,
                comment=comment,
                disabled=disabled,
                profile=router_profile,
            )
            self.server.context.store.set_enforcement_state(str(user["name"]), "")
            if email is not None:
                self.server.context.store.set_user_email(str(user["name"]), email)
            self.server.context.store.set_user_controls(str(user["name"]), **controls)
            # A direct per-user edit is intentional. Keep the template link so
            # the UI can show exactly which settings now override the group.
            assignment = self.server.context.store.user_template_assignments().get(str(user["name"]))
            if assignment:
                template = self.server.context.store.policy_template(str(assignment["template_id"]))
                if template:
                    template_controls = dict(template.get("controls") or {})
                    override_keys = [
                        key for key in controls
                        if controls.get(key) != template_controls.get(key)
                    ]
                    self.server.context.store.assign_policy_template(
                        str(user["name"]), str(template["id"]), overrides=override_keys,
                    )
            self.server.context.store.audit(
                actor=session.username,
                action="user.update",
                target=str(user["name"]),
                status="success",
                details={
                    "password_changed": bool(password), "email_changed": email is not None,
                    "disabled": disabled, "policy": controls["policy"],
                    "expires_at": controls["expires_at"],
                    "max_sessions": controls["max_sessions"],
                    "quota_mb": controls["quota_mb"], "schedule": controls["schedule"],
                },
            )
            self._json({"ok": True})
        except (ValueError, RouterOSError) as error:
            self._json({"error": str(error)}, status=HTTPStatus.BAD_REQUEST)

    @staticmethod
    def _template_identity(data: dict[str, Any]) -> tuple[str, str, str]:
        name = re.sub(r"\s+", " ", str(data.get("name", "")).strip())
        description = str(data.get("description", "")).strip()
        group_name = re.sub(r"\s+", " ", str(data.get("group_name", "")).strip())
        if not 2 <= len(name) <= 48:
            raise ValueError("Template name must be between 2 and 48 characters")
        if not 1 <= len(description) <= 180:
            raise ValueError("Give the template a short description")
        if not 2 <= len(group_name) <= 48:
            raise ValueError("Group name must be between 2 and 48 characters")
        return name, description, group_name

    def _create_policy_template(self) -> None:
        session = self._require_session(api=True)
        if not session or not self._require_csrf(session) or not self._require_operator(session):
            return
        try:
            data = self._read_json()
            name, description, group_name = self._template_identity(data)
            controls = self._parse_controls(data)
            template = self.server.context.store.save_policy_template(
                template_id=f"custom-{secrets.token_hex(8)}", name=name, description=description,
                group_name=group_name, controls=controls,
            )
            self.server.context.store.audit(
                actor=session.username, action="policy_template.create", target=template["id"],
                status="success", details={"name": name, "group": group_name},
            )
            self._json({"template": template}, status=HTTPStatus.CREATED)
        except (ValueError, RouterOSError) as error:
            self._json({"error": str(error)}, status=HTTPStatus.BAD_REQUEST)

    def _update_policy_template(self, template_id: str) -> None:
        session = self._require_session(api=True)
        if not session or not self._require_csrf(session) or not self._require_operator(session):
            return
        try:
            data = self._read_json()
            existing = self.server.context.store.policy_template(template_id)
            if not existing:
                raise ValueError("Policy template was not found")
            name, description, group_name = self._template_identity(data)
            controls = self._parse_controls(data, dict(existing.get("controls") or {}))
            template = self.server.context.store.save_policy_template(
                template_id=template_id, name=name, description=description,
                group_name=group_name, controls=controls,
            )
            self.server.context.store.audit(
                actor=session.username, action="policy_template.update", target=template_id,
                status="success", details={"name": name, "group": group_name},
            )
            self._json({"template": template})
        except (ValueError, RouterOSError) as error:
            self._json({"error": str(error)}, status=HTTPStatus.BAD_REQUEST)

    def _policy_template_action(self, template_id: str, action: str) -> None:
        session = self._require_session(api=True)
        if not session or not self._require_csrf(session) or not self._require_operator(session):
            return
        try:
            data = self._read_json()
            requested_ids = data.get("user_ids")
            if not isinstance(requested_ids, list) or not requested_ids or len(requested_ids) > 100:
                raise ValueError("Select between 1 and 100 VPN users before continuing")
            requested = {str(value) for value in requested_ids if str(value)}
            if len(requested) != len(requested_ids):
                raise ValueError("Each selected VPN user must be unique")
            template = self.server.context.store.policy_template(template_id)
            if not template:
                raise ValueError("Policy template was not found")
            controls = dict(template.get("controls") or {})
            # Re-use the exact same validation as the normal user editor.
            controls = self._parse_controls(controls)
            credentials = self._credentials(session)
            users = {str(item.get("id", "")): item for item in self.server.context.router.list_ovpn_users(credentials)}
            missing = requested.difference(users)
            if missing:
                raise ValueError("One or more selected VPN users no longer exist; refresh and try again")
            preview = []
            control_keys = ("policy", "expires_at", "max_sessions", "rate_limit_kbps", "dns_mode", "notifications", "quota_mb", "schedule")
            for user_id in sorted(requested):
                user = users[user_id]
                current = self.server.context.store.user_controls(str(user["name"]))
                changes = [key for key in control_keys if current.get(key) != controls.get(key)]
                preview.append({"id": user_id, "username": str(user["name"]), "changes": changes})
            if action == "preview":
                self._json({"template": template, "users": preview, "changed_users": sum(bool(item["changes"]) for item in preview)})
                return
            if not self._checkpoint(session, "policy-template-apply"):
                return
            applied: list[str] = []
            for item in preview:
                if not item["changes"]:
                    self.server.context.store.assign_policy_template(item["username"], template_id)
                    continue
                router_profile = self.server.context.router.ensure_rate_profile(
                    credentials, username=item["username"], rate_limit_kbps=int(controls["rate_limit_kbps"]),
                )
                self.server.context.router.update_user(
                    credentials, user_id=item["id"], profile=router_profile,
                )
                self.server.context.store.set_enforcement_state(item["username"], "")
                self.server.context.store.set_user_controls(item["username"], **controls)
                self.server.context.store.assign_policy_template(item["username"], template_id)
                applied.append(item["username"])
            self.server.context.store.audit(
                actor=session.username, action="policy_template.apply", target=template_id,
                status="success", details={"group": template["group_name"], "users": applied, "selected": len(preview)},
            )
            self._json({"ok": True, "template": template, "applied": applied, "selected": len(preview)})
        except (ValueError, RouterOSError) as error:
            self.server.context.store.audit(
                actor=session.username, action=f"policy_template.{action}", target=template_id,
                status="failed", details={"reason": type(error).__name__},
            )
            self._json({"error": str(error)}, status=HTTPStatus.BAD_REQUEST)

    def _set_user_access(self, user_id: str, *, suspended: bool) -> None:
        session = self._require_session(api=True)
        if not session or not self._require_csrf(session) or not self._require_operator(session):
            return
        credentials = self._credentials(session)
        try:
            data = self._read_json()
            user = self._find_user(credentials, user_id)
            username = str(user["name"])
            if suspended and not self._require_target_confirmation(data, username):
                return
            if not self._checkpoint(session, "user.suspend" if suspended else "user.restore"):
                return
            self.server.context.router.update_user(
                credentials,
                user_id=user_id,
                disabled=suspended,
            )
            # A manual action always takes precedence over a previous
            # automated quota/schedule state. The next telemetry poll will
            # re-evaluate the policy if the restriction still applies.
            self.server.context.store.set_enforcement_state(username, "")

            disconnected = 0
            remaining: int | None = 0
            if suspended:
                try:
                    active_sessions = self.server.context.router.list_active_ovpn_sessions(credentials)
                    for active in active_sessions:
                        if str(active.get("name", "")) != username:
                            continue
                        try:
                            self.server.context.router.terminate_session(
                                credentials, session_id=str(active["id"])
                            )
                            disconnected += 1
                        except RouterOSError:
                            pass
                    refreshed = self.server.context.router.list_active_ovpn_sessions(credentials)
                    remaining = sum(
                        1 for active in refreshed
                        if str(active.get("name", "")) == username
                    )
                    self.server.context.store.observe_sessions(refreshed)
                except RouterOSError:
                    remaining = None

            action = "user.suspend" if suspended else "user.restore"
            audit_status = "success" if remaining == 0 else "partial"
            self.server.context.store.audit(
                actor=session.username,
                action=action,
                target=username,
                status=audit_status,
                details={
                    "disconnected_sessions": disconnected,
                    "remaining_sessions": remaining if remaining is not None else "verification unavailable",
                },
            )
            self._json(
                {
                    "ok": True,
                    "disabled": suspended,
                    "disconnected": disconnected,
                    "remaining": remaining,
                }
            )
        except (ValueError, RouterOSError) as error:
            self._json({"error": str(error)}, status=HTTPStatus.BAD_REQUEST)

    def _delete_user(self, user_id: str) -> None:
        session = self._require_session(api=True)
        if not session or not self._require_csrf(session) or not self._require_operator(session):
            return
        credentials = self._credentials(session)
        try:
            data = self._read_json()
            user = self._find_user(credentials, user_id)
            username = str(user["name"])
            if not self._require_target_confirmation(data, username):
                return
            devices = self.server.context.store.devices_for_user(username)
            if not self._checkpoint(session, "user.delete"):
                return
            self.server.context.router.delete_user(credentials, user_id=user_id)
            for device in devices:
                certificate_id = device.get("certificate_id")
                if certificate_id:
                    try:
                        self.server.context.router.revoke_certificate(
                            credentials, certificate_id=str(certificate_id)
                        )
                    except RouterOSError:
                        pass
                self.server.context.store.mark_revoked(str(device["id"]))
            self.server.context.store.delete_user_email(username)
            self.server.context.store.delete_user_controls(username)
            self.server.context.store.audit(
                actor=session.username,
                action="user.delete",
                target=username,
                status="success",
                details={"retired_devices": len(devices)},
            )
            self._json({"ok": True})
        except (ValueError, RouterOSError) as error:
            self._json({"error": str(error)}, status=HTTPStatus.BAD_REQUEST)

    def _revoke_device(self, device_id: str) -> None:
        """Retire one dashboard-managed certificate after exact confirmation."""
        session = self._require_session(api=True)
        if not session or not self._require_csrf(session) or not self._require_operator(session):
            return
        credentials = self._credentials(session)
        try:
            data = self._read_json()
            device = self.server.context.store.device_by_id(device_id)
            if not device:
                raise ValueError("Device profile was not found")
            if device.get("revoked_at"):
                raise ValueError("This device profile is already revoked")
            device_name = str(device.get("device_name") or "Unnamed device")
            if not self._require_target_confirmation(data, device_name):
                return
            certificate_id = str(device.get("certificate_id") or "")
            if not certificate_id:
                raise ValueError("This device has no revocable certificate identity")
            if not self._checkpoint(session, "device.revoke"):
                return
            self.server.context.router.revoke_certificate(credentials, certificate_id=certificate_id)
            self.server.context.store.mark_revoked(device_id)
            self.server.context.store.audit(
                actor=session.username,
                action="device.revoke",
                target=device_name,
                status="success",
                details={"vpn_user": str(device.get("vpn_user", "")), "certificate": str(device.get("certificate_name", ""))},
            )
            self._json({"ok": True, "device": device_name})
        except (ValueError, RouterOSError) as error:
            self._json({"error": str(error)}, status=HTTPStatus.BAD_REQUEST)

    def _terminate_session(self, session_id: str) -> None:
        session = self._require_session(api=True)
        if not session or not self._require_csrf(session) or not self._require_operator(session):
            return
        credentials = self._credentials(session)
        try:
            data = self._read_json()
            active = self._find_session(credentials, session_id)
            if not self._require_target_confirmation(data, str(active["name"])):
                return
            if not self._checkpoint(session, "session.terminate"):
                return
            self.server.context.router.terminate_session(
                credentials, session_id=session_id
            )
            self.server.context.store.audit(
                actor=session.username,
                action="session.terminate",
                target=str(active["name"]),
                status="success",
                details={
                    "source_address": active.get("source_address", ""),
                    "vpn_address": active.get("vpn_address", ""),
                },
            )
            self._json({"ok": True})
        except (ValueError, RouterOSError) as error:
            self._json({"error": str(error)}, status=HTTPStatus.BAD_REQUEST)

    def _ack_alert(self, alert_id: int) -> None:
        session = self._require_session(api=True)
        if not session or not self._require_csrf(session):
            return
        self.server.context.store.acknowledge_alert(alert_id)
        self.server.context.store.audit(
            actor=session.username,
            action="alert.acknowledge",
            target=str(alert_id),
            status="success",
        )
        self._json({"ok": True})


class RedirectHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    public_origin = "http://localhost"

    def do_GET(self) -> None:
        target = self.public_origin.rstrip("/") + urllib.parse.urlsplit(self.path).path
        self.send_response(HTTPStatus.PERMANENT_REDIRECT)
        self.send_header("Location", target)
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    def log_message(self, message: str, *args: Any) -> None:
        return


def build_context() -> AppContext:
    config = RuntimeConfig.from_environ()
    store = MetadataStore(config.database_path)
    store.set_audit_hook(WebhookDispatcher(config.webhook_url, config.webhook_secret).publish)
    store.prune_history(before=int(time.time()) - config.history_retention_days * 86400)
    router = RouterOSClient(
        config.routeros_rest_url,
        ca_file=config.routeros_ca_file,
        insecure_tls=config.routeros_insecure_tls,
        topology=config.topology,
    )
    return AppContext(
        router=router,
        store=store,
        sessions=SessionStore(),
        limiter=LoginRateLimiter(),
        config=config,
        release_version=baked_release_value("VERSION"),
        release_revision=baked_release_value("REVISION"),
    )


def drop_runtime_privileges(database_path: Path) -> None:
    """Prepare writable state as root, then run the network service as an unprivileged UID."""
    if os.name != "posix" or os.environ.get("DROP_PRIVILEGES", "false").lower() != "true":
        return
    if os.geteuid() != 0:
        return
    uid = int(os.environ.get("RUN_UID", "65534"))
    gid = int(os.environ.get("RUN_GID", "65534"))
    targets = [database_path.parent, database_path]
    targets.extend(database_path.parent.glob(f"{database_path.name}-*"))
    for target in targets:
        if target.exists():
            os.chown(target, uid, gid)
    os.chmod(database_path.parent, 0o700)
    os.chmod(database_path, 0o600)
    os.setgroups([])
    os.setgid(gid)
    os.setuid(uid)


def main() -> None:
    listen = os.environ.get("LISTEN_ADDRESS", "0.0.0.0")
    app_port = int(os.environ.get("APP_PORT", "8080"))
    redirect_port = int(os.environ.get("REDIRECT_PORT", "8081"))
    context = build_context()
    drop_runtime_privileges(context.store.path)
    RedirectHandler.public_origin = context.public_origin
    app_server = DashboardServer((listen, app_port), context)
    redirect_server = ThreadingHTTPServer((listen, redirect_port), RedirectHandler)
    threading.Thread(target=redirect_server.serve_forever, daemon=True).start()
    print(f"vpn-dashboard ready app={listen}:{app_port} redirect={listen}:{redirect_port}")
    try:
        app_server.serve_forever()
    finally:
        redirect_server.shutdown()
        app_server.server_close()


if __name__ == "__main__":
    main()
