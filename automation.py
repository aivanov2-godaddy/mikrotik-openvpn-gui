from __future__ import annotations

import time
from typing import Any

from routeros import RouterOSCredentials, RouterOSError


def simultaneous_session_sources(sessions: list[dict[str, Any]]) -> dict[str, tuple[str, ...]]:
    """Group active sessions that put one VPN account on multiple sources."""
    grouped: dict[str, set[str]] = {}
    for item in sessions:
        username = str(item.get("name", "")).strip()
        source = str(item.get("source_address", "")).strip()
        if not username or not source:
            continue
        grouped.setdefault(username, set()).add(source)
    return {
        username: tuple(sorted(sources))
        for username, sources in grouped.items()
        if len(sources) > 1
    }


class AutomationMixin:
    @staticmethod
    def _quota_period_start(now: int) -> int:
        local = time.localtime(now)
        return int(time.mktime((local.tm_year, local.tm_mon, 1, 0, 0, 0, -1, -1, -1)))

    @staticmethod
    def _schedule_allows(schedule: str, now: int) -> bool:
        if schedule == "always":
            return True
        local = time.localtime(now)
        minutes = local.tm_hour * 60 + local.tm_min
        if schedule == "weekdays":
            return local.tm_wday < 5 and 9 * 60 <= minutes < 18 * 60
        if schedule == "daytime":
            return 8 * 60 <= minutes < 22 * 60
        return True

    def _automation_state(
        self, username: str, control: dict[str, Any], now: int
    ) -> tuple[str, str]:
        if control.get("expires_at") and int(control["expires_at"]) <= now:
            return "expired", "The configured access expiry has been reached."
        quota_mb = int(control.get("quota_mb", 0) or 0)
        if quota_mb:
            used = self.context.store.quota_usage(username, self._quota_period_start(now))
            if used >= quota_mb * 1024 * 1024:
                return "quota", f"The monthly {quota_mb:g} MB data quota has been reached."
        schedule = str(control.get("schedule", "always"))
        if not self._schedule_allows(schedule, now):
            labels = {
                "weekdays": "Weekdays 09:00–18:00",
                "daytime": "Every day 08:00–22:00",
            }
            return "schedule", f"Access is outside the {labels.get(schedule, schedule)} window."
        return "", ""

    def _apply_automation_access(
        self,
        credentials: RouterOSCredentials,
        user: dict[str, Any],
        active: list[dict[str, Any]],
        control: dict[str, Any],
        state: str,
        reason: str,
        now: int,
    ) -> list[dict[str, Any]]:
        username = str(user.get("name", ""))
        previous = str(control.get("enforcement_state", ""))
        auto_states = {"expired", "quota", "schedule"}
        if not state:
            if previous == "expired":
                return active
            if previous not in {"quota", "schedule"}:
                return active
            try:
                self.context.router.create_configuration_export(
                    credentials, name=f"vpn-dashboard-before-restore-{username}-{now}"
                )
                self.context.router.update_user(credentials, user_id=str(user["id"]), disabled=False)
                self.context.store.set_enforcement_state(username, "")
                self.context.store.audit(
                    actor="automation", action="user.auto_restore", target=username,
                    status="success", details={"previous_state": previous},
                )
                if control.get("notifications", True):
                    self.context.store.add_alert(
                        severity="info", action="user.auto_restore", target=username,
                        title=f"Access restored for {username}",
                        details="The configured schedule is open again and the account was re-enabled.",
                    )
            except RouterOSError as error:
                self.context.store.add_alert(
                    severity="critical", action="user.auto_restore.failed", target=username,
                    title=f"Could not restore {username}", details=str(error),
                )
            return active
        # A manually suspended account is not changed by automation. An
        # administrator can restore it explicitly; policy enforcement will then
        # run again on the next poll if the restriction still applies.
        if bool(user.get("disabled")) and previous == "":
            return active
        if previous == state and bool(user.get("disabled")):
            return active
        if previous in auto_states and bool(user.get("disabled")):
            self.context.store.set_enforcement_state(username, state)
            return active
        try:
            self.context.router.create_configuration_export(
                credentials, name=f"vpn-dashboard-before-enforcement-{username}-{now}"
            )
            self.context.router.update_user(credentials, user_id=str(user["id"]), disabled=True)
            disconnected = 0
            remaining = []
            for item in active:
                if str(item.get("name", "")) != username:
                    remaining.append(item)
                    continue
                try:
                    self.context.router.terminate_session(credentials, session_id=str(item["id"]))
                    disconnected += 1
                except RouterOSError:
                    remaining.append(item)
            self.context.store.set_enforcement_state(username, state)
            self.context.store.audit(
                actor="automation", action="user.auto_disable", target=username,
                status="success", details={"reason": state, "disconnected_sessions": disconnected},
            )
            if control.get("notifications", True):
                self.context.store.add_alert(
                    severity="warning", action=f"user.auto_disable.{state}", target=username,
                    title=f"Access restricted for {username}", details=reason,
                )
            return remaining
        except RouterOSError as error:
            self.context.store.add_alert(
                severity="critical", action=f"user.auto_disable.{state}.failed", target=username,
                title=f"Could not restrict {username}", details=str(error),
            )
            return active

    def _telemetry_loop(self) -> None:
        # Credentials remain in the existing in-memory session store only. We do
        # not persist RouterOS passwords just to make telemetry continuous.
        while not self._telemetry_stop.wait(30):
            for session in self.context.sessions.active():
                credentials = RouterOSCredentials(session.username, session.password)
                try:
                    users = self.context.router.list_ovpn_users(credentials)
                    active = self.context.router.list_active_ovpn_sessions(credentials)
                    self.context.store.observe_sessions(active)
                    controls = self.context.store.all_user_controls()
                    now = int(time.time())
                    for username, sources in simultaneous_session_sources(active).items():
                        control = controls.get(username, self.context.store.user_controls(username))
                        if not control.get("notifications", True):
                            continue
                        alert_created = self.context.store.add_alert(
                            severity="warning",
                            action="session.multiple_sources",
                            target=username,
                            title=f"Multiple active sources for {username}",
                            details=(
                                f"The account is connected from {len(sources)} source addresses. "
                                "Review the Connections view if this is unexpected."
                            ),
                        )
                        if alert_created:
                            self.context.store.audit(
                                actor="telemetry",
                                action="session.multiple_sources",
                                target=username,
                                status="warning",
                                details={"source_count": len(sources)},
                            )
                    for user in users:
                        username = str(user.get("name", ""))
                        control = controls.get(username, self.context.store.user_controls(username))
                        state, reason = self._automation_state(username, control, now)
                        active = self._apply_automation_access(
                            credentials, user, active, control, state, reason, now
                        )
                        limit = int(control.get("max_sessions", 5) or 5)
                        matching = [item for item in active if str(item.get("name", "")) == username]
                        if limit > 0 and len(matching) > limit:
                            for item in matching[limit:]:
                                try:
                                    self.context.router.terminate_session(
                                        credentials, session_id=str(item["id"])
                                    )
                                except RouterOSError:
                                    pass
                            self.context.store.audit(
                                actor="automation",
                                action="session.limit",
                                target=username,
                                status="success",
                                details={"limit": limit, "disconnected_sessions": len(matching) - limit},
                            )
                            if control.get("notifications", True):
                                self.context.store.add_alert(
                                    severity="warning",
                                    action="session.limit",
                                    target=username,
                                    title=f"Connection limit applied to {username}",
                                    details=f"The account is limited to {limit} active device(s).",
                                )
                except RouterOSError:
                    # A transient poll must not kill the worker.
                    continue
