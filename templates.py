from __future__ import annotations

import html
import json
import re
import time
from typing import Any

from icons import icon_sprite


def _icon(name: str, extra_class: str = "") -> str:
    class_name = f"wb-icon {extra_class}".strip()
    return (
        f'<svg class="{html.escape(class_name, quote=True)}" aria-hidden="true" '
        f'focusable="false"><use href="#i-{html.escape(name, quote=True)}"></use></svg>'
    )


def _page(title: str, body: str, *, script: bool = False, csrf: str = "") -> str:
    safe_title = html.escape(title)
    csrf_meta = (
        f'<meta name="csrf-token" content="{html.escape(csrf, quote=True)}">'
        if csrf
        else ""
    )
    asset_version = "20260904-qr-devices-v1"
    script_tag = f'<script src="/static/app.js?v={asset_version}" defer></script>' if script else ""
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="dark">
  <meta name="theme-color" content="#121a21">
  <link rel="icon" type="image/svg+xml" href="/favicon.svg?v=20260905">
  <link rel="alternate icon" type="image/x-icon" href="/favicon.ico?v=20260905">
  {csrf_meta}
  <title>{safe_title}</title>
  <link rel="stylesheet" href="/static/app.css?v={asset_version}">
  {script_tag}
</head>
<body>{icon_sprite()}{body}</body>
</html>"""


def _bytes(value: Any) -> str:
    amount = max(0, int(value or 0))
    units = ("B", "KB", "MB", "GB", "TB")
    size = float(amount)
    unit = units[0]
    for unit in units:
        if size < 1024 or unit == units[-1]:
            break
        size /= 1024
    precision = 0 if size >= 100 or unit == "B" else 1
    return f"{size:.{precision}f} {unit}"


def _duration(seconds: int) -> str:
    remaining = max(0, int(seconds))
    days, remaining = divmod(remaining, 86400)
    hours, remaining = divmod(remaining, 3600)
    minutes, _ = divmod(remaining, 60)
    if days:
        return f"{days}d {hours}h"
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"


def _router_uptime(value: Any) -> str:
    raw = str(value or "").strip()
    match = re.fullmatch(
        r"(?:(\d+)w)?(?:(\d+)d)?(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?",
        raw,
    )
    if not raw or not match:
        return raw or "unknown"
    weeks, days, hours, minutes, seconds = (int(part or 0) for part in match.groups())
    day_total = weeks * 7 + days
    clock = f"{hours:02d}:{minutes:02d}:{seconds:02d}s"
    return f"{day_total}d {clock}" if day_total else clock


def _policy_label(value: Any) -> str:
    return {
        "full-tunnel": "Full tunnel",
        "lan-only": "LAN only",
        "internet-only": "Internet only",
    }.get(str(value), "Full tunnel")


def _expiry_label(value: Any) -> str:
    try:
        timestamp = int(value)
    except (TypeError, ValueError):
        timestamp = 0
    return "Never" if timestamp <= 0 else f"Until {time.strftime('%d %b %H:%M', time.localtime(timestamp))}"


def _quota_label(quota_mb: Any, used_bytes: Any) -> str:
    try:
        quota = int(quota_mb or 0)
    except (TypeError, ValueError):
        quota = 0
    if quota <= 0:
        return "Unlimited"
    quota_label = f"{quota / 1024:g} GB" if quota >= 1024 and quota % 1024 == 0 else f"{quota} MB"
    return f"{_bytes(used_bytes)} / {quota_label}"


def _schedule_label(value: Any) -> str:
    return {
        "always": "Always",
        "weekdays": "Weekdays · 09:00–18:00",
        "daytime": "Every day · 08:00–22:00",
    }.get(str(value), "Always")


def _certificate_expiry(value: Any, now: int | None = None) -> tuple[str, str]:
    """Return a readable certificate lifecycle label and CSS state."""
    raw = str(value or "").strip()
    expiry = 0
    for pattern in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            expiry = int(time.mktime(time.strptime(raw[:19 if " " in pattern else 10], pattern)))
            break
        except (TypeError, ValueError, OverflowError):
            continue
    if not expiry:
        return ("Expiry unknown", "warning")
    days = (expiry - int(time.time() if now is None else now)) // 86400
    if days < 0:
        return ("Expired", "expired")
    if days == 0:
        return ("Expires today", "warning")
    if days <= 30:
        return (f"Expires in {days} days", "warning")
    return (f"Valid · {time.strftime('%d %b %Y', time.localtime(expiry))}", "")


def _used_percent(free: Any, total: Any) -> int:
    total_value = max(0, int(total or 0))
    free_value = max(0, int(free or 0))
    if not total_value:
        return 0
    return max(0, min(100, round((total_value - free_value) * 100 / total_value)))


def _relative_time(timestamp: Any, now: int | None = None) -> str:
    value = int(timestamp or 0)
    if not value:
        return "Never connected"
    seconds = max(0, int(time.time() if now is None else now) - value)
    if seconds < 90:
        return "Just now"
    if seconds < 3600:
        return f"{seconds // 60} minutes ago"
    if seconds < 86400:
        return f"{seconds // 3600} hours ago"
    if seconds < 604800:
        return f"{seconds // 86400} days ago"
    return time.strftime("%d %b %Y", time.localtime(value))


def _session_card(session: dict[str, Any]) -> str:
    session_id = html.escape(str(session.get("id", "")), quote=True)
    source = html.escape(str(session.get("source_address", "—")) or "—")
    address = html.escape(str(session.get("vpn_address", "—")) or "—")
    uptime = html.escape(str(session.get("uptime", "—")) or "—")
    encoding = html.escape(str(session.get("encoding", "—")) or "—")
    rx_bytes = int(session.get("rx_bytes", 0) or 0)
    tx_bytes = int(session.get("tx_bytes", 0) or 0)
    rx_packets = int(session.get("rx_packets", 0) or 0)
    tx_packets = int(session.get("tx_packets", 0) or 0)
    username = html.escape(str(session.get("name", "Unknown user")) or "Unknown user")
    return f"""
    <article class="session-card" data-session-id="{session_id}" data-session-user="{html.escape(str(session.get('name', '')), quote=True)}" data-rx="{rx_bytes}" data-tx="{tx_bytes}" data-rx-packets="{rx_packets}" data-tx-packets="{tx_packets}">
      <div class="session-main">
        <div class="live-orb" aria-hidden="true">{_icon('session')}</div>
        <div><strong>{username}</strong><small>Connected securely · {encoding}</small></div>
      </div>
      <dl class="session-facts">
        <div><dt>VPN address</dt><dd>{address}</dd></div>
        <div><dt>Source</dt><dd>{source}</dd></div>
        <div><dt>Uptime</dt><dd data-session-uptime>{uptime}</dd></div>
        <div><dt>Traffic</dt><dd><span class="rx-rate" data-rx-rate>↓ 0 bps</span> · <span class="tx-rate" data-tx-rate>↑ 0 bps</span><small class="traffic-totals">↓ {_bytes(rx_bytes)} · ↑ {_bytes(tx_bytes)}</small></dd></div>
      </dl>
      <button class="terminate-button" type="button" data-terminate data-session-id="{session_id}">{_icon('remove')}<span>Terminate</span></button>
      <div class="session-graphs" aria-label="Live connection traffic">
        <section class="traffic-graph">
          <header><strong>Byte Graph</strong><span>Live · 5 second samples</span></header>
          <canvas data-byte-graph aria-label="Transmit and receive traffic rate graph">Live byte-rate graph</canvas>
          <div class="graph-legend"><span class="graph-tx"><i></i><strong data-graph-tx-rate>0 bps</strong><small>Tx</small></span><span class="graph-rx"><i></i><strong data-graph-rx-rate>0 bps</strong><small>Rx</small></span></div>
        </section>
        <section class="traffic-graph">
          <header><strong>Packet Graph</strong><span>Live · 5 second samples</span></header>
          <canvas data-packet-graph aria-label="Transmit and receive packet rate graph">Live packet-rate graph</canvas>
          <div class="graph-legend"><span class="graph-tx"><i></i><strong data-graph-tx-packets>0 p/s</strong><small>Tx Packet</small></span><span class="graph-rx"><i></i><strong data-graph-rx-packets>0 p/s</strong><small>Rx Packet</small></span></div>
        </section>
      </div>
    </article>"""


def login_page(
    error: str = "",
    *,
    dashboard_name: str = "MikroTik OpenVPN GUI",
    router_display_name: str = "RouterOS",
) -> str:
    notice = (
        f'<p class="notice error" role="alert">{html.escape(error)}</p>' if error else ""
    )
    body = f"""
<main class="login-shell">
  <section class="login-card" aria-labelledby="login-title">
    <header class="login-titlebar"><div class="mikrotik-wordmark"><span class="mikrotik-mark">{_icon('logo')}</span><strong>MIKROTIK</strong><span class="brand-host">{html.escape(router_display_name)}</span></div><span>{html.escape(dashboard_name)}</span></header>
    <div class="login-tabs"><span class="active">Connect</span></div>
    <div class="login-content">
    <p class="eyebrow">ROUTEROS CONTROL PLANE</p>
    <h1 id="login-title">Connect to VPN Dashboard</h1>
    <p class="lede">Use the same management credentials as WinBox. Authentication is verified directly by RouterOS.</p>
    {notice}
    <form method="post" action="/login" class="stack">
      <label><span>Login</span><input name="username" autocomplete="username" required maxlength="64" autofocus></label>
      <label><span>Password</span><input type="password" name="password" autocomplete="current-password" required maxlength="256"></label>
      <div class="login-actions"><span class="login-security">{_icon('lock')} Secure RouterOS session</span><button class="primary" type="submit">Connect</button></div>
    </form>
    </div>
    <footer class="login-status"><span class="status-led"></span><span>Secure RouterOS sign-in</span><span>RouterOS 7</span></footer>
  </section>
</main>"""
    return _page(f"{dashboard_name} · Sign in", body)


def dashboard_page(
    *,
    actor: str,
    csrf: str,
    users: list[dict[str, Any]],
    sessions: list[dict[str, Any]],
    devices: list[dict[str, Any]],
    connections: list[dict[str, Any]],
    connection_summaries: dict[str, dict[str, Any]],
    certificates: list[dict[str, Any]],
    ovpn_server: dict[str, Any],
    certificate_settings: dict[str, Any],
    warnings: list[str],
    audit: list[dict[str, Any]],
    alerts: list[dict[str, Any]],
    policy_templates: list[dict[str, Any]],
    admin_role: str,
    router: dict[str, Any],
    dashboard_name: str = "MikroTik OpenVPN GUI",
    router_display_name: str = "RouterOS",
    vpn_host: str = "",
    public_ip: str = "",
    reverse_dns: str = "",
    router_dns: str = "",
    access_layer_label: str = "Direct HTTPS",
    health: dict[str, Any] | None = None,
) -> str:
    device_counts: dict[str, int] = {}
    for device in devices:
        username = str(device.get("vpn_user", ""))
        device_counts[username] = device_counts.get(username, 0) + 1

    sessions_by_user: dict[str, list[dict[str, Any]]] = {}
    for active in sessions:
        sessions_by_user.setdefault(str(active.get("name", "")), []).append(active)

    can_mutate = admin_role in {"owner", "operator"}
    add_user_button = (
        f'<button class="primary" type="button" data-open-add>{_icon("plus")}<span>Add VPN user</span></button>'
        if can_mutate
        else '<span class="read-only-note">Read-only RouterOS account</span>'
    )
    add_phone_button = (
        f'<button class="primary wide" type="button" data-open-add>{_icon("plus")} Add a person and phone</button>'
        if can_mutate
        else '<span class="read-only-note">Read-only RouterOS account · changes are disabled</span>'
    )
    template_options = "".join(
        f'<option value="{html.escape(str(item["id"]), quote=True)}">'
        f'{html.escape(str(item["name"]))} · {html.escape(str(item["group_name"]))}</option>'
        for item in policy_templates
    )
    template_cards = "".join(
        f'''<article class="policy-template" data-policy-template
              data-template-id="{html.escape(str(item["id"]), quote=True)}"
              data-template-name="{html.escape(str(item["name"]), quote=True)}"
              data-template-controls="{html.escape(json.dumps(item["controls"], separators=(",", ":")), quote=True)}">
          <header><div><strong>{html.escape(str(item["name"]))}</strong><small>{html.escape(str(item["group_name"]))}</small></div>
          <span class="{'posture-badge' if item.get("protected") else 'template-custom'}">{'Built in' if item.get("protected") else 'Custom'}</span></header>
          <p>{html.escape(str(item["description"]))}</p>
          <dl><div><dt>Route</dt><dd>{html.escape(_policy_label(item["controls"].get("policy")))}</dd></div><div><dt>Devices</dt><dd>{int(item["controls"].get("max_sessions", 5))}</dd></div><div><dt>Speed</dt><dd>{'Unlimited' if not int(item["controls"].get("rate_limit_kbps", 0)) else str(int(item["controls"].get("rate_limit_kbps", 0)) // 1024) + ' Mbps'}</dd></div></dl>
          <button type="button" class="quiet" data-select-template="{html.escape(str(item["id"]), quote=True)}">Use this template</button>
        </article>'''
        for item in policy_templates
    ) or '<div class="empty"><strong>No policy templates yet</strong></div>'
    rows: list[str] = []
    for user in users:
        name = str(user.get("name", ""))
        user_id = str(user.get("id", ""))
        comment = str(user.get("comment", "")) or "No description"
        email = str(user.get("email", "")) or "Email not assigned"
        disabled = bool(user.get("disabled"))
        controls = user.get("controls") or {}
        policy = str(controls.get("policy", "full-tunnel"))
        expiry = int(controls.get("expires_at", 0) or 0)
        max_sessions = max(1, min(5, int(controls.get("max_sessions", 5) or 5)))
        quota_mb = int(controls.get("quota_mb", 0) or 0)
        quota_used = int(controls.get("quota_used_bytes", 0) or 0)
        schedule = str(controls.get("schedule", "always"))
        current_sessions = sessions_by_user.get(name, [])
        connected = bool(current_sessions)
        activity = connection_summaries.get(name, {})
        connection_count = int(activity.get("connection_count", 0) or 0)
        total_bytes = int(activity.get("total_bytes", 0) or 0)
        last_source = str(activity.get("last_source_address", "")) or "No source recorded"
        last_activity = "Connected now" if connected else _relative_time(activity.get("last_seen_at"))
        access_health = "Suspended" if disabled else ("Online" if connected else ("Ready · never used" if not connection_count else "Ready"))
        if can_mutate:
            access_action = (
                f'<button type="button" class="restore-item" data-restore>{_icon("enable")}<span>Restore access</span></button>'
                if disabled
                else f'<button type="button" class="danger-item" data-suspend>{_icon("disable")}<span>Suspend access now</span></button>'
            )
            action_markup = (
                f'<button type="button" data-profile>{_icon("plus")}<span>Add another device</span></button>'
                f'<button type="button" data-download-profile>{_icon("download")}<span>Download profile (.zip)</span></button>'
                f'<button type="button" data-qr-profile>{_icon("qr")}<span>Show QR code</span></button>'
                f'<button type="button" data-duplicate>{_icon("copy")}<span>Add similar user</span></button>'
                f'{access_action}'
                f'<button type="button" data-edit>{_icon("edit")}<span>Edit user</span></button>'
                f'<button type="button" class="danger-item" data-delete>{_icon("trash")}<span>Remove user</span></button>'
            )
        else:
            action_markup = '<span class="read-only-menu">Read-only access</span>'
        rows.append(
            f"""
        <article class="user-card" data-user-id="{html.escape(user_id, quote=True)}" data-user-name="{html.escape(name, quote=True)}" data-user-comment="{html.escape(comment, quote=True)}" data-user-email="{html.escape(email, quote=True)}" data-user-disabled="{'true' if disabled else 'false'}" data-user-policy="{html.escape(policy, quote=True)}" data-user-expires="{expiry}" data-user-max-sessions="{max_sessions}" data-user-rate-limit="{int(controls.get('rate_limit_kbps', 0) or 0)}" data-user-dns="{html.escape(str(controls.get('dns_mode', 'router')), quote=True)}" data-user-notifications="{'true' if controls.get('notifications', True) else 'false'}" data-user-quota="{quota_mb}" data-user-schedule="{html.escape(schedule, quote=True)}" data-user-template-id="{html.escape(str((user.get('template') or {}).get('id', '')), quote=True)}">
          <header class="user-card-header">
            <div class="identity">
              <span class="avatar">{html.escape((name[:1] or "?").upper())}</span>
              <div class="identity-copy"><div class="identity-title"><strong>{html.escape(name)}</strong><span class="account-badge {'disabled' if disabled else 'enabled'}" data-account-status>{'Disabled' if disabled else 'Enabled'}</span></div><small>{html.escape(comment)}</small><small class="identity-email">{html.escape(email)}</small></div>
            </div>
            <button class="connection-badge {'online' if connected else 'offline'}" type="button" data-connection-status {'data-view-target="live-sessions"' if connected else 'disabled'}><i></i><span>{'Connected' if connected else 'Offline'}</span></button>
            <div class="profile-count"><strong>{device_counts.get(name, 0)}</strong><span>managed profile{'s' if device_counts.get(name, 0) != 1 else ''}</span></div>
            <details class="action-menu">
              <summary aria-label="Actions for {html.escape(name, quote=True)}">{_icon('menu')}<span>Actions</span>{_icon('chevron', 'chevron')}</summary>
              <div class="action-popover">
                <button type="button" data-copy-username>{_icon('copy')}<span>Copy username</span></button>
                {action_markup}
              </div>
            </details>
          </header>
          <div class="user-activity" aria-label="Activity summary for {html.escape(name, quote=True)}">
            <div><span>Access health</span><strong class="{'activity-suspended' if disabled else ('activity-online' if connected else '')}">{html.escape(access_health)}</strong></div>
            <div><span>Last activity</span><strong>{html.escape(last_activity)}</strong></div>
            <div><span>Connections</span><strong>{connection_count}</strong></div>
            <div><span>Transferred</span><strong>{html.escape(_bytes(total_bytes))}</strong></div>
            <div><span>Last source</span><strong class="mono-value">{html.escape(last_source)}</strong></div>
            <div><span>Policy</span><strong>{html.escape(_policy_label(policy))}</strong></div>
            <div><span>Access expires</span><strong>{html.escape(_expiry_label(expiry))}</strong></div>
            <div><span>Data quota</span><strong>{html.escape(_quota_label(quota_mb, quota_used))}</strong></div>
            <div><span>Schedule</span><strong>{html.escape(_schedule_label(schedule))}</strong></div>
            <div><span>Concurrent devices</span><strong>{max_sessions}</strong></div>
            <div><span>Policy group</span><strong>{html.escape(str((user.get('template') or {}).get('group_name', 'Custom')))}</strong></div>
          </div>
        </article>"""
        )
    user_markup = "".join(rows) or """
      <div class="empty"><span>{_icon('users')}</span><strong>No OpenVPN users yet</strong><p>Create your first identity and download its device profile.</p></div>"""

    live_session_markup = "".join(_session_card(item) for item in sessions)
    if not live_session_markup:
        live_session_markup = f"""
        <div class="empty session-empty"><span>{_icon('session')}</span><strong>No devices connected</strong><p>Connections will appear here automatically. Nothing needs to be refreshed manually.</p></div>"""

    now = int(time.time())
    connection_rows: list[str] = []
    for item in connections:
        connected_at = int(item.get("connected_at", 0) or 0)
        disconnected_at = int(item.get("disconnected_at", 0) or 0)
        live = not disconnected_at
        ended_at = disconnected_at or int(item.get("last_seen_at", now) or now)
        username = str(item.get("vpn_user", "")) or "Unknown"
        source_address = str(item.get("source_address", "")) or "—"
        vpn_address = str(item.get("vpn_address", "")) or "—"
        encoding = str(item.get("encoding", "")) or "—"
        connected_text = time.strftime("%d %b %Y · %H:%M", time.localtime(connected_at))
        end_text = "Connected now" if live else time.strftime("%d %b %Y · %H:%M", time.localtime(disconnected_at))
        traffic = int(item.get("rx_bytes", 0) or 0) + int(item.get("tx_bytes", 0) or 0)
        search_text = f"{username} {source_address} {vpn_address} {encoding} {connected_text} {end_text}"
        connection_rows.append(
            f"""<tr data-connection-row data-connection-search="{html.escape(search_text.lower(), quote=True)}">
              <td><span class="history-action"><i class="audit-icon{' live' if live else ''}"></i><strong>{html.escape(username)}</strong></span></td>
              <td><time>{html.escape(connected_text)}</time><small class="table-secondary">{html.escape(end_text)}</small></td>
              <td>{html.escape(_duration(ended_at - connected_at))}</td>
              <td><span class="address-pair"><strong>{html.escape(source_address)}</strong><small>{html.escape(vpn_address)} VPN</small></span></td>
              <td>{html.escape(_bytes(traffic))}<small class="table-secondary">{html.escape(encoding)}</small></td>
              <td><span class="history-status{' connected' if live else ''}">{'Connected' if live else 'Ended'}</span></td>
            </tr>"""
        )
    connection_markup = "".join(connection_rows) or '<tr><td colspan="6" class="table-empty">No connection history has been recorded yet.</td></tr>'

    action_labels = {
        "login": "Signed in",
        "user.create": "Created VPN user",
        "user.duplicate": "Copied VPN user",
        "user.update": "Updated VPN user",
        "user.suspend": "Suspended VPN access",
        "user.restore": "Restored VPN access",
        "user.delete": "Removed VPN user",
        "profile.create": "Added device profile",
        "session.terminate": "Disconnected device",
        "session.multiple_sources": "Detected multiple active sources",
        "login.failure": "Failed dashboard sign-in",
        "login.rate_limited": "Rate-limited dashboard sign-in",
        "checkpoint.create": "Created safety checkpoint",
        "user.expire": "Expired VPN access",
        "session.limit": "Applied connection limit",
        "user.auto_disable": "Applied automatic access restriction",
        "user.auto_restore": "Restored scheduled access",
        "alert.acknowledge": "Acknowledged alert",
    }
    audit_rows: list[str] = []
    for item in audit:
        when = time.strftime("%d %b %Y · %H:%M", time.localtime(int(item.get("created_at", 0))))
        raw_action = str(item.get("action", ""))
        action = action_labels.get(raw_action, raw_action.replace(".", " ").title())
        status = str(item.get("status", "success"))
        try:
            details = json.loads(str(item.get("details", "{}")))
        except (TypeError, ValueError, json.JSONDecodeError):
            details = {}
        detail_items = "".join(
            f"<li><span>{html.escape(str(key).replace('_', ' ').title())}</span><strong>{html.escape(str(value))}</strong></li>"
            for key, value in details.items()
        ) or "<li><span>Details</span><strong>—</strong></li>"
        target = str(item.get("target", "")) or "—"
        actor_name = str(item.get("actor", "")) or "system"
        search_text = f"{when} {action} {target} {actor_name} {status} {details}"
        audit_rows.append(
            f"""<tr data-history-row data-history-search="{html.escape(search_text.lower(), quote=True)}">
              <td><time>{html.escape(when)}</time></td>
              <td><span class="history-action"><i class="audit-icon {html.escape(status, quote=True)}"></i><strong>{html.escape(action)}</strong></span></td>
              <td>{html.escape(target)}</td><td>{html.escape(actor_name)}</td>
              <td><span class="history-status {html.escape(status, quote=True)}">{html.escape(status.title())}</span></td>
              <td><ul class="history-details">{detail_items}</ul></td>
            </tr>"""
        )
    audit_markup = "".join(audit_rows) or '<tr><td colspan="6" class="table-empty">No changes have been recorded yet.</td></tr>'

    alert_rows = []
    for alert in alerts:
        alert_id = int(alert.get("id", 0) or 0)
        severity = str(alert.get("severity", "info"))
        title = str(alert.get("title", "VPN alert"))
        details = str(alert.get("details", ""))
        created = time.strftime("%d %b %Y · %H:%M", time.localtime(int(alert.get("created_at", 0) or 0)))
        alert_rows.append(
            f'<li class="alert-item {html.escape(severity, quote=True)}" data-alert-id="{alert_id}"><i></i><div><strong>{html.escape(title)}</strong><small>{html.escape(details)}</small></div><time>{html.escape(created)}</time><button type="button" class="table-action" data-alert-ack="{alert_id}">Acknowledge</button></li>'
        )
    alert_markup = "".join(alert_rows) or '<li class="alert-empty">No active alerts. Automated checks will appear here when action is needed.</li>'

    user_ids = {str(item.get("name", "")): str(item.get("id", "")) for item in users}
    device_rows: list[str] = []
    for device in devices:
        owner = str(device.get("vpn_user", "")) or "—"
        device_name = str(device.get("device_name", "")) or "Unnamed device"
        certificate = str(device.get("certificate_name", "")) or "—"
        fingerprint = str(device.get("fingerprint", "")) or "—"
        short_fingerprint = fingerprint if len(fingerprint) <= 24 else f"{fingerprint[:12]}…{fingerprint[-8:]}"
        created = time.strftime("%d %b %Y", time.localtime(int(device.get("created_at", 0))))
        device_rows.append(
            f"""<tr>
              <td><span class="device-name">{_icon('device')}<span><strong>{html.escape(device_name)}</strong><small>{html.escape(owner)}</small></span></span></td>
              <td><span class="device-status"><i></i>Ready</span></td>
              <td><strong class="certificate-name">{html.escape(certificate)}</strong><small class="fingerprint">{html.escape(short_fingerprint)}</small></td>
              <td>{html.escape(created)}</td>
              <td><button type="button" class="table-action" data-create-device data-user-id="{html.escape(user_ids.get(owner, ''), quote=True)}" data-user-name="{html.escape(owner, quote=True)}">{_icon('plus')}<span>Add another device</span></button><button type="button" class="table-action danger" data-device-revoke data-device-id="{html.escape(str(device.get('id', '')), quote=True)}" data-device-name="{html.escape(device_name, quote=True)}">{_icon('remove')}<span>Revoke device</span></button></td>
            </tr>"""
        )
    device_markup = "".join(device_rows) or f'<tr><td colspan="5" class="table-empty">{_icon("device")}<strong>No dashboard-managed devices yet</strong><span>Add a device from the OpenVPN Users page.</span><button type="button" class="primary" data-view-target="vpn-users">Open users</button></td></tr>'

    devices_by_certificate = {
        str(item.get("certificate_name", "")): item for item in devices
        if item.get("certificate_name")
    }
    certificate_rows: list[str] = []
    for certificate in certificates:
        certificate_name = str(certificate.get("name", "")) or "—"
        metadata = devices_by_certificate.get(certificate_name, {})
        common_name = str(certificate.get("common_name", "")) or "—"
        owner = str(metadata.get("vpn_user", ""))
        if not owner:
            owner = next(
                (
                    str(user.get("name", ""))
                    for user in users
                    if common_name.startswith(f"{str(user.get('name', ''))}-")
                ),
                "RouterOS",
            )
        device_label = str(metadata.get("device_name", "")) or "Existing client profile"
        fingerprint = str(certificate.get("fingerprint", "")) or "—"
        short_fingerprint = fingerprint if len(fingerprint) <= 30 else f"{fingerprint[:14]}…{fingerprint[-10:]}"
        expiry = str(certificate.get("invalid_after", "")) or str(certificate.get("expires_after", "")) or "Unknown"
        revoked = bool(certificate.get("revoked"))
        lifecycle_label, lifecycle_state = _certificate_expiry(expiry)
        certificate_state = "revoked" if revoked else lifecycle_state
        certificate_state_label = "Revoked" if revoked else lifecycle_label
        certificate_rows.append(
            f"""<tr>
              <td><span class="device-name">{_icon('certificate')}<span><strong>{html.escape(certificate_name)}</strong><small>{html.escape(common_name)}</small></span></span></td>
              <td><strong>{html.escape(owner)}</strong><small class="table-secondary">{html.escape(device_label)}</small></td>
              <td><span class="device-status {html.escape(certificate_state, quote=True)}"><i></i>{html.escape(certificate_state_label)}</span></td>
              <td><strong>{html.escape(expiry)}</strong><small class="table-secondary">{html.escape(certificate_state_label)}</small></td>
              <td><span class="fingerprint">{html.escape(short_fingerprint)}</span></td>
            </tr>"""
        )
    certificate_markup = "".join(certificate_rows) or '<tr><td colspan="5" class="table-empty">No OpenVPN client certificates were found.</td></tr>'

    version = html.escape(str(router.get("version", "unknown")))
    board = html.escape(str(router.get("board-name", "MikroTik")))
    actor_safe = html.escape(actor)
    active_users = len({str(item.get("name", "")) for item in sessions})
    rx_total = sum(int(item.get("rx_bytes", 0) or 0) for item in sessions)
    tx_total = sum(int(item.get("tx_bytes", 0) or 0) for item in sessions)
    cpu_load = max(0, min(100, int(router.get("cpu-load", 0) or 0)))
    memory_used = _used_percent(router.get("free-memory"), router.get("total-memory"))
    storage_used = _used_percent(router.get("free-hdd-space"), router.get("total-hdd-space"))
    uptime = _router_uptime(router.get("uptime", "unknown"))
    crl_ready = bool(certificate_settings.get("crl_use"))
    server_enabled = bool(ovpn_server.get("enabled"))
    client_certificates = bool(ovpn_server.get("require_client_certificate"))
    strong_cipher = "aes256-gcm" in str(ovpn_server.get("cipher", "")).lower()
    tls_restricted = str(ovpn_server.get("tls_version", "")).lower() == "only-1.2"
    full_tunnel = "def1" in str(ovpn_server.get("redirect_gateway", "")).lower()
    dashboard_name_safe = html.escape(dashboard_name)
    router_display_name_safe = html.escape(router_display_name)
    vpn_host_safe = html.escape(vpn_host or "not configured")
    endpoint_ip = public_ip or "Unavailable"
    endpoint_rdns = reverse_dns or "Unavailable"
    endpoint_copy_value = f"Public IP: {endpoint_ip}\nReverse DNS: {endpoint_rdns}"
    endpoint_copy = (
        f'<div class="vpn-endpoint"><span>Public IP address</span><code>{html.escape(endpoint_ip)}</code>'
        f'<span>Reverse DNS</span><b>{html.escape(endpoint_rdns)}</b>'
        f'<button type="button" class="table-action" data-copy-vpn-endpoint="{html.escape(endpoint_copy_value, quote=True)}">{_icon("copy")}<span>Copy endpoint</span></button></div>'
        if vpn_host
        else '<div class="vpn-endpoint"><span>Public endpoint</span><strong>Not configured</strong></div>'
    )
    router_dns_safe = html.escape(router_dns or "not configured")
    access_layer = html.escape(access_layer_label)
    warning_markup = ""
    if warnings:
        warning_items = "".join(f"<li>{html.escape(item)}</li>" for item in warnings)
        warning_markup = f"""<section class="degraded-notice" role="status">{_icon('refresh')}<div><strong>You are connected, but some RouterOS data could not be loaded.</strong><ul>{warning_items}</ul><small>Refresh the page to try again. Your login remains active.</small></div></section>"""
    alert_markup_panel = f'<section class="panel alerts-panel"><div class="panel-heading"><div>{_icon("shield")}<span><strong>Security and access alerts</strong><small>Automated checks from the dashboard control plane</small></span></div><span class="muted-label">{len(alerts)} open</span></div><ul class="alert-list" data-alert-list>{alert_markup}</ul></section>' if alerts else ''
    health = health or {"overall": "unavailable", "checks": []}
    health_checks = list(health.get("checks") or [])
    health_counts = {state: sum(1 for item in health_checks if item.get("status") == state) for state in ("healthy", "warning", "unavailable")}
    health_overall = str(health.get("overall", "unavailable"))
    health_overall_label = {"healthy": "Operational", "warning": "Attention needed", "unavailable": "Unavailable"}.get(health_overall, "Unavailable")
    health_rows = "".join(
        f'''<article class="service-health-check {html.escape(str(item.get("status", "unavailable")), quote=True)}"><span class="health-check-led" aria-hidden="true"></span><div><strong>{html.escape(str(item.get("name", "Health check")))}</strong><small>{html.escape(str(item.get("impact", "")))}</small><p><b>Safe next step:</b> {html.escape(str(item.get("remediation", "No action needed.")))}</p></div></article>'''
        for item in health_checks
    ) or '<div class="empty"><strong>No health data is available yet.</strong><span>Refresh this view to check the current router state.</span></div>'

    body = f"""
<div class="winbox-shell">
  <header class="winbox-menubar">
    <a class="mikrotik-wordmark" href="/dashboard"><span class="mikrotik-mark">{_icon('logo')}</span><strong>MIKROTIK</strong><span class="brand-host">{router_display_name_safe}</span></a>
    <div class="menubar-spacer"></div>
    <span class="safe-mode">{_icon('shield')} Access protected</span>
    <span class="router-pill"><i></i><span>{board}</span><small>RouterOS {version} · {html.escape(admin_role.title())}</small></span>
    <button type="button" class="sync-status" data-full-refresh hidden title="A dashboard list changed and can be refreshed when convenient">{_icon('refresh')}<span>Refresh to apply changes</span></button>
    <form method="post" action="/logout" class="top-logout"><input type="hidden" name="csrf" value="{html.escape(csrf, quote=True)}"><button type="submit" title="Sign out {actor_safe}">{_icon('logout')}<span>Sign out</span></button></form>
  </header>

  <aside class="winbox-sidebar" aria-label="VPN Dashboard navigation">
    <a href="#overview" class="active" data-view-target="overview">{_icon('dashboard')}<span>Dashboard</span></a>
    <a href="#vpn-users" data-view-target="vpn-users">{_icon('users')}<span>VPN Users</span></a>
    <a href="#live-sessions" data-view-target="live-sessions">{_icon('session')}<span>Connections</span><strong class="nav-count" data-nav-session-count>{len(sessions)}</strong></a>
    <a href="#profile-security" data-view-target="profile-security">{_icon('device')}<span>Device Profiles</span></a>
    <a href="#policy-templates" data-view-target="policy-templates">{_icon('shield')}<span>Policy Templates</span></a>
    <a href="#service-health" data-view-target="service-health">{_icon('system')}<span>Service Health</span></a>
    <span class="nav-section-title">AUDIT LOG</span>
    <a href="#audit-log" class="nav-subitem" data-view-target="audit-log">{_icon('log')}<span>Change History</span></a>
    <span class="nav-section-title">SETUP</span>
    <a href="#setup-planner" class="nav-subitem" data-view-target="setup-planner">{_icon('system')}<span>Setup Planner</span></a>
  </aside>

  <section class="winbox-main">
    <main class="workspace-content">
      {warning_markup}
      <section class="app-view" id="overview" data-view="overview">
        <header class="view-heading"><div><p class="eyebrow">VPN DASHBOARD</p><h1>VPN at a glance</h1><p>Everything important, without RouterOS terminology.</p></div><div class="heading-actions"><span class="live-refresh" data-live-indicator><i></i><span>Live · updated now</span></span>{add_user_button}</div></header>
        <section class="metric-grid" aria-label="VPN overview">
          <button class="metric" type="button" data-view-target="vpn-users"><div class="metric-icon" aria-hidden="true">{_icon('users')}</div><div><small>VPN users</small><strong data-user-total>{len(users)}</strong><span>{sum(1 for user in users if not user.get('disabled'))} ready to connect</span></div></button>
          <button class="metric live-metric" type="button" data-view-target="live-sessions"><div class="metric-icon pulse-icon" aria-hidden="true">{_icon('session')}</div><div><small>Connected now</small><strong data-session-total>{len(sessions)}</strong><span data-active-users>{active_users} connected user{'s' if active_users != 1 else ''}</span></div></button>
          <button class="metric" type="button" data-view-target="profile-security"><div class="metric-icon" aria-hidden="true">{_icon('device')}</div><div><small>Device profiles</small><strong>{len(devices)}</strong><span>Protected individually</span></div></button>
          <article class="metric"><div class="metric-icon" aria-hidden="true">{_icon('traffic')}</div><div><small>Traffic this connection</small><strong class="traffic-total" data-traffic-total>↓ {_bytes(rx_total)} · ↑ {_bytes(tx_total)}</strong><span>Internet and home network protected</span></div></article>
        </section>
        {alert_markup_panel}
        <section class="enterprise-grid" aria-label="Service health and security posture">
          <article class="panel operations-panel"><div class="panel-heading"><div>{_icon('system')}<span><strong>Service health</strong><small>Live MikroTik capacity and VPN availability</small></span></div><div class="panel-heading-actions"><span class="posture-badge">{health_overall_label}</span><button type="button" class="quiet" data-view-target="service-health">Open checks</button></div></div><div class="health-grid">
            <div class="health-item"><span>VPN service</span><strong class="health-state {'good' if server_enabled else 'bad'}"><i></i>{'Online' if server_enabled else 'Offline'}</strong><small>{html.escape(str(ovpn_server.get('protocol', '')).upper())} {int(ovpn_server.get('port', 0) or 0)}</small>{endpoint_copy}</div>
            <div class="health-item"><span>Router CPU</span><strong data-router-cpu>{cpu_load}%</strong><progress data-router-cpu-progress max="100" value="{cpu_load}"></progress></div>
            <div class="health-item"><span>Memory used</span><strong data-router-memory>{memory_used}%</strong><progress data-router-memory-progress max="100" value="{memory_used}"></progress></div>
            <div class="health-item"><span>Storage used</span><strong data-router-storage>{storage_used}%</strong><progress data-router-storage-progress max="100" value="{storage_used}"></progress></div>
            <div class="health-item"><span>Router uptime</span><strong data-router-uptime>{html.escape(uptime)}</strong><small>No bad storage blocks detected</small></div>
          </div></article>
          <article class="panel security-posture-panel"><div class="panel-heading"><div>{_icon('shield')}<span><strong>Security posture</strong><small>Controls verified against RouterOS now</small></span></div><span class="posture-score">{sum((server_enabled, client_certificates, strong_cipher, tls_restricted, full_tunnel))}/5 enforced</span></div><ul class="posture-list"><li class="{'pass' if client_certificates else 'fail'}"><i></i><span><strong>Device certificate required</strong><small>Stolen VPN passwords alone cannot connect.</small></span></li><li class="{'pass' if strong_cipher else 'fail'}"><i></i><span><strong>AES-256-GCM encryption</strong><small>Strong authenticated tunnel encryption is enforced.</small></span></li><li class="{'pass' if tls_restricted else 'fail'}"><i></i><span><strong>TLS restricted</strong><small>{html.escape(str(ovpn_server.get('tls_version', 'Unknown')))} accepted by the server.</small></span></li><li class="{'pass' if full_tunnel else 'fail'}"><i></i><span><strong>Full-tunnel routing</strong><small>Phone internet and LAN access travel through MikroTik.</small></span></li><li class="pass"><i></i><span><strong>HTTPS dashboard access</strong><small>{access_layer}; RouterOS credentials authorize dashboard actions.</small></span></li></ul></article>
        </section>
        <section class="overview-grid">
          <article class="panel quick-start-panel"><div class="panel-heading"><div>{_icon('enable')}<span><strong>Connect a new phone</strong><small>Three simple steps</small></span></div></div><ol class="simple-steps"><li><strong>1</strong><span><b>Add the person</b><small>The dashboard creates everything automatically.</small></span></li><li><strong>2</strong><span><b>Download the profile</b><small>Send the downloaded file to the phone.</small></span></li><li><strong>3</strong><span><b>Open it with OpenVPN</b><small>Enter the VPN username and password, then connect.</small></span></li></ol>{add_phone_button}</article>
          <article class="panel updates-panel"><div class="panel-heading"><div>{_icon('log')}<span><strong>What changed</strong><small>6 August 2026 access policy release</small></span></div></div><ul class="update-bullets"><li>Every user now shows live activity, traffic totals, policy, quota usage, access expiry, and schedule.</li><li>Traffic presets can create full-tunnel, LAN-only, or internet-only profiles with RouterOS or Cloudflare DNS.</li><li>Optional expiry, maximum-device, speed-limit, monthly-quota, and scheduled-access controls are enforced automatically.</li><li>Quota, schedule, expiry, and session-limit notices appear here and can be acknowledged without touching the VPN connection.</li><li>Every automated restriction creates a non-sensitive RouterOS export checkpoint before the account changes.</li><li>Read-only RouterOS accounts can inspect the dashboard while operator/owner accounts retain change controls.</li></ul></article>
        </section>
        <section class="panel architecture-panel"><div class="panel-heading"><div>{_icon('traffic')}<span><strong>What happens under the hood</strong><small>Two separate paths keep administration and VPN traffic simple and secure</small></span></div><span class="posture-badge">Automatic</span></div><div class="architecture-paths">
          <article><header>{_icon('lock')}<span><strong>Managing the VPN website</strong><small>Control plane</small></span></header><ol><li><b>1</b><span>{access_layer} protects the dashboard.</span></li><li><b>2</b><span>RouterOS verifies the same credentials as WinBox.</span></li><li><b>3</b><span>The dashboard applies changes through the private RouterOS REST service.</span></li></ol></article>
          <article><header>{_icon('device')}<span><strong>A phone using the VPN</strong><small>Encrypted data plane</small></span></header><ol><li><b>1</b><span>The phone connects directly to {vpn_host_safe} on the configured OpenVPN port.</span></li><li><b>2</b><span>RouterOS requires its device certificate and VPN username/password.</span></li><li><b>3</b><span>RouterOS routes LAN and internet traffic through the encrypted tunnel.</span></li></ol></article>
        </div><footer><strong>Important:</strong> The dashboard and VPN data plane are separate. OpenVPN phone traffic goes directly to MikroTik.</footer></section>
      </section>

      <section class="app-view" id="vpn-users" data-view="vpn-users" hidden>
        <header class="view-heading"><div><p class="eyebrow">ACCESS</p><h1>VPN Users</h1><p>Add people, update their access, or create a profile for another device.</p></div><div class="heading-actions"><label class="page-search">{_icon('search')}<input type="search" data-user-search placeholder="Find a user" aria-label="Find VPN user"></label>{add_user_button}</div></header>
        <section class="panel user-panel"><div class="panel-heading"><div>{_icon('users')}<span><strong>OpenVPN Users</strong><small>Name, owner, connection status, and managed devices</small></span></div><div class="legend"><span><i class="online-dot"></i>Connected</span><span><i></i>Offline</span></div></div><div class="user-table-head"><span>Name / owner</span><span>Status</span><span>Devices</span><span>Actions</span></div><div class="user-list" data-user-list>{user_markup}</div></section>
      </section>

      <section class="app-view" id="live-sessions" data-view="live-sessions" hidden>
        <header class="view-heading"><div><p class="eyebrow">LIVE</p><h1>Connected Devices</h1><p>See who is online. Traffic graphs update automatically every five seconds.</p></div><div class="heading-actions"><span class="live-refresh" data-live-indicator><i></i><span>Live · updated now</span></span><a class="quiet" href="/api/usage.csv">{_icon('download')}<span>Monthly usage</span></a><a class="quiet" href="/api/connections.csv">{_icon('download')}<span>Export history</span></a><button class="quiet" type="button" data-refresh>{_icon('refresh')}<span>Refresh now</span></button></div></header>
        <section class="connection-summary"><span class="connection-summary-icon">{_icon('session')}</span><div><strong><span data-session-total>{len(sessions)}</span> connected device{'s' if len(sessions) != 1 else ''}</strong><small>Disconnecting asks for confirmation. A user can reconnect while their account remains enabled.</small></div></section>
        <section class="standalone-session-list" data-active-session-list>{live_session_markup}</section>
        <section class="panel table-panel history-panel" data-connection-history data-open-count="{sum(1 for item in connections if not item.get('disconnected_at'))}"><div class="panel-heading"><div>{_icon('log')}<span><strong>Connection history</strong><small>Active and recently ended tunnels · up to 50 shown</small></span></div><label class="page-search compact-search">{_icon('search')}<input type="search" data-connection-search placeholder="Find a connection" aria-label="Find a connection"></label></div><div class="responsive-table"><table class="history-table connection-history-table"><thead><tr><th>User</th><th>Connected / ended</th><th>Duration</th><th>Source / VPN address</th><th>Traffic / encryption</th><th>Status</th></tr></thead><tbody>{connection_markup}</tbody></table></div></section>
      </section>

      <section class="app-view" id="profile-security" data-view="profile-security" hidden>
        <header class="view-heading"><div><p class="eyebrow">DEVICES</p><h1>Device Profiles</h1><p>Each phone gets its own protected OpenVPN profile.</p></div><button class="primary" type="button" data-view-target="vpn-users">{_icon('plus')}<span>Add a device</span></button></header>
        <section class="panel table-panel"><div class="panel-heading"><div>{_icon('device')}<span><strong>Managed devices</strong><small>Profiles created by this dashboard</small></span></div><span class="posture-badge">Protected automatically</span></div><div class="responsive-table"><table class="device-table"><thead><tr><th>Device / owner</th><th>Status</th><th>Protection ID</th><th>Created</th><th>Action</th></tr></thead><tbody>{device_markup}</tbody></table></div></section>
        <section class="panel table-panel"><div class="panel-heading"><div>{_icon('certificate')}<span><strong>RouterOS certificate inventory</strong><small>All client identities accepted by this OpenVPN CA</small></span></div><span class="muted-label">{len(certificates)} certificates</span></div><div class="responsive-table"><table class="certificate-table"><thead><tr><th>Certificate / identity</th><th>Owner / device</th><th>Status</th><th>Expires</th><th>Fingerprint</th></tr></thead><tbody>{certificate_markup}</tbody></table></div></section>
        <section class="panel protection-summary"><div class="panel-heading compact"><div>{_icon('shield')}<span><strong>Protection handled for you</strong><small>No certificate knowledge required</small></span></div></div><ul class="checks"><li><span>{_icon('check')}</span><div><strong>Separate protection per device</strong><small>Each downloaded profile receives a separate certificate.</small></div></li><li><span>{_icon('check')}</span><div><strong>Private key encrypted</strong><small>The password you choose protects the downloaded profile.</small></div></li><li><span>{_icon('check')}</span><div><strong>Correct server verified</strong><small>The profile accepts only {vpn_host_safe}.</small></div></li><li><span>{_icon('check')}</span><div><strong>Temporary files removed</strong><small>Setup files are cleaned automatically after download.</small></div></li><li class="{'ready' if crl_ready else 'warning'}"><span>{_icon('shield')}</span><div><strong>{'Certificate revocation enforced' if crl_ready else 'Per-device revocation needs CA migration'}</strong><small>{'RouterOS CRL checking is active.' if crl_ready else 'The current CA has no active CRL distribution point. A planned CA rotation is required before a lost profile can be reliably revoked.'}</small></div></li></ul></section>
      </section>

      <section class="app-view" id="service-health" data-view="service-health" hidden>
        <header class="view-heading"><div><p class="eyebrow">OPERATIONS</p><h1>Service health</h1><p>Read-only checks with clear impact and safe next steps. Nothing is repaired automatically.</p></div><div class="heading-actions"><button type="button" class="quiet" data-service-health-refresh>{_icon('refresh')}<span>Refresh checks</span></button></div></header>
        <section class="metric-grid service-health-summary" aria-label="Service health summary">
          <article class="metric"><div class="metric-icon">{_icon('system')}</div><div><small>Overall state</small><strong data-service-health-overall>{health_overall_label}</strong><span data-service-health-checked>{len(health_checks)} checks completed</span></div></article>
          <article class="metric"><div class="metric-icon">{_icon('enable')}</div><div><small>Healthy</small><strong data-service-health-count="healthy">{health_counts['healthy']}</strong><span>Operating as expected</span></div></article>
          <article class="metric"><div class="metric-icon">{_icon('shield')}</div><div><small>Needs review</small><strong data-service-health-count="warning">{health_counts['warning']}</strong><span>Review before changing RouterOS</span></div></article>
          <article class="metric"><div class="metric-icon">{_icon('disable')}</div><div><small>Unavailable</small><strong data-service-health-count="unavailable">{health_counts['unavailable']}</strong><span>Could not be verified</span></div></article>
        </section>
        <section class="panel service-health-panel"><div class="panel-heading"><div>{_icon('system')}<span><strong>Current checks</strong><small>Fresh RouterOS and dashboard readiness, without configuration changes</small></span></div></div><div class="service-health-list" data-service-health-list>{health_rows}</div></section>
      </section>

      <section class="app-view" id="policy-templates" data-view="policy-templates" hidden>
        <header class="view-heading"><div><p class="eyebrow">ACCESS GOVERNANCE</p><h1>Policy Templates</h1><p>Apply repeatable access settings to selected users after reviewing the exact differences.</p></div><button type="button" class="primary" data-open-template-create>{_icon('plus')}<span>New custom template</span></button></header>
        <section class="policy-intro"><span>{_icon('shield')}</span><div><strong>Nothing changes until you apply it.</strong><small>Templates group users for easy management. Applying one creates a RouterOS checkpoint, updates the selected accounts only, and records the change history.</small></div></section>
        <section class="policy-template-grid">{template_cards}</section>
        <section class="panel template-apply-panel"><div class="panel-heading"><div>{_icon('users')}<span><strong>Preview and apply</strong><small>Select a template and the people it should affect. Direct user edits remain visible as overrides.</small></span></div></div><form data-template-apply><label><span>Template</span><select name="template_id" required><option value="">Select a template</option>{template_options}</select></label><fieldset><legend>Selected VPN users</legend><div class="template-user-list">{''.join(f'<label><input type="checkbox" name="user_ids" value="{html.escape(str(user.get("id", "")), quote=True)}"><span><strong>{html.escape(str(user.get("name", "")))}</strong><small>{html.escape(str((user.get("template") or {}).get("group_name", "No group")))}</small></span></label>' for user in users)}</div></fieldset><p class="form-status" role="status"></p><div class="template-preview" hidden data-template-preview></div><footer><button type="button" class="quiet" data-template-preview-button>Preview changes</button><button type="submit" class="primary" disabled data-template-apply-button>Apply to selected users</button></footer></form></section>
      </section>

      <section class="app-view" id="audit-log" data-view="audit-log" hidden>
        <header class="view-heading"><div><p class="eyebrow">AUDIT LOG</p><h1>Change History</h1><p>A read-only record of dashboard sign-ins and every access change.</p></div><div class="heading-actions"><label class="page-search">{_icon('search')}<input type="search" data-history-search placeholder="Find a change" aria-label="Find a history entry"></label><form class="report-export" method="get" action="/api/audit.csv"><label>From<input type="date" name="from" aria-label="Report start date"></label><label>To<input type="date" name="to" aria-label="Report end date"></label><button class="quiet" type="submit">{_icon('download')}<span>Export CSV</span></button><button class="quiet" type="submit" formaction="/api/audit.json">{_icon('download')}<span>JSON</span></button></form></div></header>
        <section class="history-notice">{_icon('shield')}<span><strong>Passwords and private keys are never written here.</strong><small>History records the action, target, operator, result, and safe details only. Exports honour the selected inclusive date range.</small></span></section>
        <section class="panel capability-panel"><div class="panel-heading"><div>{_icon('users')}<span><strong>Administrator capabilities</strong><small>Permissions come directly from the signed-in RouterOS account.</small></span></div></div><div class="responsive-table"><table class="capability-table"><thead><tr><th>Role</th><th>Inspect and export</th><th>Manage access</th><th>Destructive actions</th></tr></thead><tbody><tr><td><strong>Read-only</strong></td><td>Allowed</td><td>Not allowed</td><td>Not allowed</td></tr><tr><td><strong>Operator</strong></td><td>Allowed</td><td>Allowed</td><td>Exact target confirmation</td></tr><tr><td><strong>Owner</strong></td><td>Allowed</td><td>Allowed</td><td>Exact target confirmation</td></tr></tbody></table></div></section>
        <section class="panel table-panel"><div class="panel-heading"><div>{_icon('log')}<span><strong>System history</strong><small>Newest changes first · up to 100 entries</small></span></div><span class="muted-label">{len(audit)} recorded</span></div><div class="responsive-table"><table class="history-table"><thead><tr><th>When</th><th>Change</th><th>Target</th><th>By</th><th>Result</th><th>Details</th></tr></thead><tbody>{audit_markup}</tbody></table></div></section>
      </section>

      <section class="app-view" id="setup-planner" data-view="setup-planner" hidden>
        <header class="view-heading"><div><p class="eyebrow">REVIEW-FIRST SETUP</p><h1>Installation planner</h1><p>Create a safe, non-secret RouterOS plan. Nothing is applied from this page.</p></div></header>
        <section class="panel setup-planner-panel"><div class="panel-heading"><div>{_icon('shield')}<span><strong>Read-only preflight</strong><small>Checks router reachability and OpenVPN availability; package, device-mode, storage, DNS, and TLS gates remain explicit manual checks.</small></span></div><button type="button" class="quiet" data-setup-preflight>{_icon('refresh')}<span>Run preflight</span></button></div><ul class="setup-checks" data-setup-checks><li><i></i><span>Run preflight to check the currently connected router. No configuration is read or changed beyond the normal dashboard status calls.</span></li></ul></section>
        <section class="panel setup-planner-panel"><div class="panel-heading"><div>{_icon('system')}<span><strong>Generate a review plan</strong><small>Use an immutable published image and a dedicated external-storage path.</small></span></div><span class="posture-badge">No apply action</span></div><form class="setup-form" data-setup-plan><label><span>Dashboard URL</span><input name="origin" required value="{html.escape(str(dashboard_name and 'https://dashboard.example.com'), quote=True)}" placeholder="https://vpn.example.com"><small>HTTPS is required for public access. Private/local HTTP is accepted only for RFC1918 or localhost setup.</small></label><label><span>Immutable image</span><input name="image" required placeholder="ghcr.io/owner/mikrotik-openvpn-gui:sha-&lt;commit&gt;-arm64"><small>Only full immutable <code>sha-</code> tags are accepted.</small></label><label><span>Dedicated external storage</span><input name="storage" required value="/disk1/vpn-dashboard" placeholder="/disk1/vpn-dashboard"><small>Never use <code>/flash</code> or a shared root.</small></label><label><span>Container subnet</span><input name="subnet" required value="172.31.250.0/30" placeholder="172.31.250.0/30"></label><label><span>Existing LAN CIDR</span><input name="lan" required value="{html.escape(str(router.get('local-address', '') or '192.168.88.0/24'), quote=True)}" placeholder="192.168.88.0/24"><small>The generator rejects overlap with the container subnet.</small></label><p class="form-status" role="status"></p><footer><button type="submit" class="primary">Generate review plan</button></footer></form></section>
        <section class="panel setup-planner-panel"><div class="panel-heading"><div>{_icon('shield')}<span><strong>Dashboard metadata backup</strong><small>Download a local, checksummed recovery archive before upgrades. It contains dashboard metadata only.</small></span></div><a class="quiet" href="/api/backups/metadata.zip">{_icon('download')}<span>Download backup</span></a></div><p class="backup-safety-note">Never includes RouterOS configuration, VPN passwords, private keys, issued profiles, or active sessions. Verify an archive locally before considering a review-first restore.</p><form class="backup-verify" data-backup-verify><label><span>Verify an existing backup</span><input type="file" name="backup" accept=".zip,application/zip" required><small>The archive is checked in memory and never stored or restored automatically.</small></label><p class="form-status" role="status"></p><button class="quiet" type="submit">Verify backup</button></form></section>
        <section class="panel setup-planner-panel" hidden data-setup-output><div class="panel-heading"><div>{_icon('log')}<span><strong>Reviewable RouterOS plan</strong><small>Copy only after completing the manual gates above.</small></span></div><button type="button" class="quiet" data-copy-setup>{_icon('copy')}<span>Copy plan</span></button></div><pre class="setup-plan-output" data-setup-plan-output></pre></section>
      </section>

      <footer class="app-footer"><span>{dashboard_name_safe}</span><span>RouterOS authentication</span></footer>
    </main>

    <footer class="winbox-statusbar" id="system-status"><span class="status-led"></span><strong>{router_display_name_safe}</strong><span>{board} / arm64 / RouterOS {version}</span><span class="status-spacer"></span><span>{len(users)} users</span><span>{len(sessions)} active</span><span>{actor_safe}</span><time>{time.strftime('%Y-%m-%d %H:%M')}</time></footer>
  </section>
</div>

<div class="toast-region" aria-live="polite" aria-atomic="true"></div>

<dialog id="add-dialog"><form id="add-form" method="dialog" class="dialog-card"><header><div><p class="eyebrow">NEW ACCESS</p><h2>Add a person and phone</h2><p>The dashboard prepares the secure profile automatically.</p></div><button type="button" class="icon" data-close aria-label="Close">×</button></header><div class="dialog-fields"><label><span>VPN username</span><input name="username" required maxlength="64" pattern="[A-Za-z0-9_.@-]+" placeholder="e.g. maria"></label><label><span>Owner email</span><input type="email" name="email" required maxlength="254" autocomplete="email" placeholder="maria@example.com"><small>Used to identify who owns this access.</small></label><label><span>VPN password</span><input type="password" name="password" required minlength="8" maxlength="256" autocomplete="new-password"><small>The same password protects the downloaded file automatically.</small></label><label><span>Phone or device</span><input name="device_name" required maxlength="64" placeholder="Pixel 10 Pro XL"></label><label><span>Note <i>Optional</i></span><input name="comment" maxlength="96" placeholder="Owner or purpose"></label></div><p class="form-status" role="status"></p><footer><button type="button" class="quiet" data-close>Cancel</button><button type="submit" class="quiet" data-delivery="qr">Create and show QR</button><button type="submit" class="primary" data-delivery="zip">Create and download .zip</button></footer></form></dialog>

<dialog id="profile-dialog"><form id="profile-form" method="dialog" class="dialog-card"><header><div><p class="eyebrow">NEW DEVICE</p><h2 data-profile-title>Add another device</h2><p data-profile-description>A ready-to-import OpenVPN file will download automatically.</p></div><button type="button" class="icon" data-close aria-label="Close">×</button></header><input type="hidden" name="user_id"><input type="hidden" name="delivery" value="zip"><div class="selected-user">Adding a device for <strong data-profile-user></strong></div><div class="dialog-fields"><label><span>Phone or device</span><input name="device_name" required maxlength="64" placeholder="Work tablet"></label><label><span>Protect file with</span><input type="password" name="key_passphrase" required minlength="8" maxlength="256" autocomplete="new-password"><small>OpenVPN asks for this password when the file is imported. It is never stored.</small></label></div><p class="form-status" role="status"></p><footer><button type="button" class="quiet" data-close>Cancel</button><button type="submit" class="primary" data-profile-submit>Create and download .zip</button></footer></form></dialog>

<dialog id="duplicate-dialog"><form id="duplicate-form" method="dialog" class="dialog-card"><header><div><p class="eyebrow">COPY ACCESS</p><h2>Add someone with the same access</h2><p>The new person receives separate credentials and a separate device file.</p></div><button type="button" class="icon" data-close aria-label="Close">×</button></header><input type="hidden" name="source_id"><div class="selected-user">Using the same settings as <strong data-duplicate-source></strong></div><div class="dialog-fields"><label><span>New username</span><input name="username" required maxlength="64" pattern="[A-Za-z0-9_.@-]+"></label><label><span>Owner email</span><input type="email" name="email" required maxlength="254" autocomplete="email"></label><label><span>VPN password</span><input type="password" name="password" required minlength="8" maxlength="256" autocomplete="new-password"></label><label><span>Phone or device</span><input name="device_name" required maxlength="64"></label><label><span>Note <i>Optional</i></span><input name="comment" maxlength="96"></label></div><p class="form-status" role="status"></p><footer><button type="button" class="quiet" data-close>Cancel</button><button type="submit" class="primary">Create and download</button></footer></form></dialog>

<dialog id="edit-dialog"><form id="edit-form" method="dialog" class="dialog-card"><header><div><p class="eyebrow">VPN ACCESS</p><h2>Edit VPN user</h2><p>Simple presets apply safely through RouterOS and new device profiles.</p></div><button type="button" class="icon" data-close aria-label="Close">×</button></header><input type="hidden" name="user_id"><div class="selected-user">Editing <strong data-edit-user></strong></div><div class="dialog-fields"><label><span>Owner email</span><input type="email" name="email" required maxlength="254" autocomplete="email"></label><label><span>New password <i>Optional</i></span><input type="password" name="password" minlength="8" maxlength="256" autocomplete="new-password"><small>Leave blank to keep the current password.</small></label><label><span>Note</span><input name="comment" maxlength="96"></label><label><span>Traffic policy</span><select name="policy"><option value="full-tunnel">Full tunnel</option><option value="lan-only">LAN only</option><option value="internet-only">Internet only</option></select><small>New profiles use this route policy. Existing files continue using their original policy.</small></label><label><span>Access expires</span><select name="expiry"><option value="never">Never</option><option value="1h">In 1 hour</option><option value="1d">In 1 day</option><option value="7d">In 7 days</option><option value="30d">In 30 days</option></select></label><label><span>Concurrent devices</span><select name="max_sessions"><option value="1">1 device</option><option value="2">2 devices</option><option value="3">3 devices</option><option value="4">4 devices</option><option value="5" selected>5 devices (default)</option></select><small>Additional devices are disconnected automatically when the limit is reached.</small></label><label><span>Speed limit</span><select name="rate_limit_kbps"><option value="0">Unlimited</option><option value="5120">5 Mbps</option><option value="10240">10 Mbps</option><option value="25600">25 Mbps</option><option value="51200">50 Mbps</option><option value="102400">100 Mbps</option></select></label><label><span>Data quota</span><select name="quota_mb"><option value="0">Unlimited</option><option value="1024">1 GB / month</option><option value="5120">5 GB / month</option><option value="10240">10 GB / month</option><option value="25600">25 GB / month</option><option value="51200">50 GB / month</option><option value="102400">100 GB / month</select><small>Usage is counted from the first day of each month.</small></label><label><span>Access schedule</span><select name="schedule"><option value="always">Always allowed</option><option value="weekdays">Weekdays · 09:00–18:00</option><option value="daytime">Every day · 08:00–22:00</option></select><small>Router local time is used. Access outside the window is blocked automatically.</small></label><label><span>VPN DNS</span><select name="dns_mode"><option value="router">RouterOS DNS (10.10.10.1)</option><option value="cloudflare">Cloudflare DNS (1.1.1.1)</option></select></label><label class="toggle"><input type="checkbox" name="notifications" checked><span><strong>Show automated alerts</strong><small>Keep access, quota, and schedule notices visible in the dashboard.</small></span></label><label class="toggle"><input type="checkbox" name="disabled"><span><strong>Block new connections</strong><small>A currently connected device stays online until you disconnect it.</small></span></label></div><p class="form-status" role="status"></p><footer><button type="button" class="quiet" data-close>Cancel</button><button type="submit" class="primary">Save changes</button></footer></form></dialog>

<dialog id="terminate-dialog"><form id="terminate-form" method="dialog" class="dialog-card warning-dialog"><header><div><p class="eyebrow danger-text">LIVE SESSION</p><h2>Terminate connection?</h2><p>The device will be disconnected immediately. It can reconnect while the account remains enabled.</p></div><button type="button" class="icon" data-close aria-label="Close">×</button></header><input type="hidden" name="session_id"><div class="warning-summary"><span class="warning-symbol">!</span><div><strong data-terminate-user></strong><small data-terminate-detail></small></div></div><label class="confirmation-input"><span>Type <b data-confirm-target></b> to confirm</span><input name="confirmation" required autocomplete="off" spellcheck="false"></label><p class="form-status" role="status"></p><footer><button type="button" class="quiet" data-close>Keep connected</button><button type="submit" class="danger">Terminate session</button></footer></form></dialog>

<dialog id="suspend-dialog"><form id="suspend-form" method="dialog" class="dialog-card warning-dialog"><header><div><p class="eyebrow danger-text">EMERGENCY ACCESS CONTROL</p><h2>Suspend VPN access now?</h2><p>RouterOS will block new logins and disconnect every active tunnel for this user.</p></div><button type="button" class="icon" data-close aria-label="Close">×</button></header><input type="hidden" name="user_id"><div class="warning-summary"><span class="warning-symbol">!</span><div><strong data-suspend-user></strong><small>Device profiles remain available and can be restored later.</small></div></div><ul class="confirmation-steps"><li>Disable the PPP/OpenVPN account on MikroTik.</li><li>Terminate every currently active session for this username.</li><li>Verify remaining sessions and write the result to Change History.</li></ul><label class="confirmation-input"><span>Type <b data-confirm-target></b> to confirm</span><input name="confirmation" required autocomplete="off" spellcheck="false"></label><p class="form-status" role="status"></p><footer><button type="button" class="quiet" data-close>Keep access</button><button type="submit" class="danger">Suspend and disconnect</button></footer></form></dialog>

<dialog id="delete-dialog"><form id="delete-form" method="dialog" class="dialog-card warning-dialog"><header><div><p class="eyebrow danger-text">ACCESS REMOVAL</p><h2>Remove VPN user?</h2><p>This action changes RouterOS and cannot be undone.</p></div><button type="button" class="icon" data-close aria-label="Close">×</button></header><input type="hidden" name="user_id"><div class="warning-summary"><span class="warning-symbol">!</span><div><strong data-delete-user></strong><small>User access and dashboard-managed certificates will be retired.</small></div></div><label class="confirmation-input"><span>Type <b data-confirm-target></b> to permanently remove this access</span><input name="confirmation" required autocomplete="off" spellcheck="false"></label><p class="form-status" role="status"></p><footer><button type="button" class="quiet" data-close>Cancel</button><button type="submit" class="danger">Remove access</button></footer></form></dialog>
<dialog id="revoke-device-dialog"><form id="revoke-device-form" method="dialog" class="dialog-card warning-dialog"><header><div><p class="eyebrow danger-text">DEVICE SECURITY</p><h2>Revoke this device?</h2><p>The certificate will stop authenticating immediately. Other devices for this user remain unaffected.</p></div><button type="button" class="icon" data-close aria-label="Close">×</button></header><input type="hidden" name="device_id"><div class="warning-summary"><span class="warning-symbol">!</span><div><strong data-revoke-device-name></strong><small>The downloaded profile will no longer connect.</small></div></div><label class="confirmation-input"><span>Type <b data-confirm-target></b> to confirm</span><input name="confirmation" required autocomplete="off" spellcheck="false"></label><p class="form-status" role="status"></p><footer><button type="button" class="quiet" data-close>Cancel</button><button type="submit" class="danger">Revoke device</button></footer></form></dialog>
<dialog id="qr-dialog"><form method="dialog" class="dialog-card qr-dialog"><header><div><p class="eyebrow">SECURE PROFILE</p><h2>Scan to download</h2><p data-qr-description>Scan this code with the phone camera to download the OpenVPN profile.</p></div><button type="button" class="icon" data-close aria-label="Close">×</button></header><div class="qr-code-frame"><img data-qr-image alt="OpenVPN profile download QR code"></div><label class="share-link"><span>Download link</span><input type="text" data-qr-url readonly></label><p class="qr-help">The link expires in 10 minutes and can be downloaded up to three times. The archive contains the encrypted OpenVPN profile.</p><footer><button type="button" class="quiet" data-copy-share>{_icon('copy')}<span>Copy link</span></button><button type="button" class="primary" data-close>Done</button></footer></form></dialog>
<dialog id="template-dialog"><form id="template-form" method="dialog" class="dialog-card"><header><div><p class="eyebrow">ACCESS GOVERNANCE</p><h2>Create custom policy template</h2><p>Save a reusable set of VPN access controls. It does not alter users yet.</p></div><button type="button" class="icon" data-close aria-label="Close">×</button></header><div class="dialog-fields"><label><span>Template name</span><input name="name" required minlength="2" maxlength="48" placeholder="e.g. Field team"></label><label><span>Group name</span><input name="group_name" required minlength="2" maxlength="48" placeholder="e.g. Contractors"></label><label><span>Description</span><input name="description" required minlength="1" maxlength="180" placeholder="Explain who this policy is for"></label><label><span>Traffic policy</span><select name="policy"><option value="full-tunnel">Full tunnel</option><option value="lan-only">LAN only</option><option value="internet-only">Internet only</option></select></label><label><span>Concurrent devices</span><select name="max_sessions"><option value="1">1 device</option><option value="2">2 devices</option><option value="3">3 devices</option><option value="4">4 devices</option><option value="5" selected>5 devices</option></select></label><label><span>Speed limit</span><select name="rate_limit_kbps"><option value="0">Unlimited</option><option value="5120">5 Mbps</option><option value="10240">10 Mbps</option><option value="25600">25 Mbps</option><option value="51200">50 Mbps</option><option value="102400">100 Mbps</option></select></label><label><span>Data quota</span><select name="quota_mb"><option value="0">Unlimited</option><option value="1024">1 GB / month</option><option value="5120">5 GB / month</option><option value="10240">10 GB / month</option><option value="25600">25 GB / month</option><option value="51200">50 GB / month</option><option value="102400">100 GB / month</option></select></label><label><span>Schedule</span><select name="schedule"><option value="always">Always allowed</option><option value="weekdays">Weekdays · 09:00–18:00</option><option value="daytime">Every day · 08:00–22:00</option></select></label><label><span>VPN DNS</span><select name="dns_mode"><option value="router">RouterOS DNS</option><option value="cloudflare">Cloudflare DNS</option></select></label><label class="toggle"><input type="checkbox" name="notifications" checked><span><strong>Show automated alerts</strong><small>Keep quota, schedule, and access notices visible.</small></span></label></div><p class="form-status" role="status"></p><footer><button type="button" class="quiet" data-close>Cancel</button><button type="submit" class="primary">Save template</button></footer></form></dialog>
"""
    # The edit dialog is an intentionally compact static fragment. Substitute
    # its RouterOS DNS label after construction so it always reflects the
    # configured topology rather than the sample network used in older builds.
    body = body.replace("RouterOS DNS (10.10.10.1)", f"RouterOS DNS ({router_dns_safe})")
    return _page(f"{dashboard_name} · Dashboard", body, script=True, csrf=csrf)
