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

    @staticmethod
    def _automation_user_matches(left: dict[str, Any], right: dict[str, Any]) -> bool:
        """Compare only stable, non-secret RouterOS fields before an automated write."""
        fields = ("id", "name", "profile", "comment", "disabled")
        return all(str(left.get(field, "")) == str(right.get(field, "")) for field in fields)

    @staticmethod
    def _automation_session_matches(left: dict[str, Any], right: dict[str, Any]) -> bool:
        """Avoid terminating a reused RouterOS row ID for a different live session."""
        if str(left.get("id", "")) != str(right.get("id", "")):
            return False
        for field in ("name", "session_id", "source_address", "vpn_address"):
            old = str(left.get(field, ""))
            current = str(right.get(field, ""))
            if old and current and old != current:
                return False
        return True

    def _automation_user_readback(
        self, credentials: RouterOSCredentials, expected: dict[str, Any], disabled: bool
    ) -> tuple[str, dict[str, Any] | None]:
        """Read the exact account state; return verified, mismatch, stale, or unknown."""
        try:
            users = self.context.router.list_ovpn_users(credentials)
        except RouterOSError:
            return "unknown", None
        current = next(
            (item for item in users if str(item.get("id", "")) == str(expected.get("id", ""))),
            None,
        )
        if current is None:
            return "unknown", None
        if str(current.get("name", "")) != str(expected.get("name", "")):
            return "stale", current
        if bool(current.get("disabled")) is disabled:
            return "verified", current
        return "mismatch", current

    def _automation_fresh_user(
        self, credentials: RouterOSCredentials, expected: dict[str, Any]
    ) -> tuple[str, dict[str, Any] | None]:
        """Reject enforcement if the account changed since the telemetry snapshot."""
        try:
            users = self.context.router.list_ovpn_users(credentials)
        except RouterOSError:
            return "unknown", None
        current = next(
            (item for item in users if str(item.get("id", "")) == str(expected.get("id", ""))),
            None,
        )
        if current is None:
            return "unknown", None
        return ("fresh", current) if self._automation_user_matches(expected, current) else ("stale", current)

    def _automation_fresh_sessions(
        self, credentials: RouterOSCredentials
    ) -> list[dict[str, Any]] | None:
        try:
            return self.context.router.list_active_ovpn_sessions(credentials)
        except RouterOSError:
            return None

    def _automation_terminate_sessions(
        self,
        credentials: RouterOSCredentials,
        username: str,
        targets: list[dict[str, Any]],
        *,
        max_sessions: int | None = None,
    ) -> tuple[list[dict[str, Any]] | None, dict[str, int]]:
        """Terminate only fresh exact sessions and classify each result by read-back."""
        counts = {"attempted": 0, "verified": 0, "failed": 0, "unknown": 0, "stale": 0}
        current = self._automation_fresh_sessions(credentials)
        if current is None:
            counts["unknown"] = len(targets)
            return None, counts
        for target in targets:
            current = self._automation_fresh_sessions(credentials)
            if current is None:
                counts["unknown"] += 1
                continue
            matching = [item for item in current if str(item.get("name", "")) == username]
            exact = next(
                (item for item in matching if self._automation_session_matches(target, item)),
                None,
            )
            if exact is None:
                counts["stale"] += 1
                continue
            if max_sessions is not None:
                excess = matching[max_sessions:]
                if not any(self._automation_session_matches(target, item) for item in excess):
                    counts["stale"] += 1
                    continue
            counts["attempted"] += 1
            try:
                self.context.router.terminate_session(credentials, session_id=str(exact["id"]))
            except RouterOSError:
                pass  # Read-back resolves whether RouterOS committed the disconnect.
            readback = self._automation_fresh_sessions(credentials)
            if readback is None:
                counts["unknown"] += 1
                continue
            still_active = any(
                self._automation_session_matches(target, item)
                for item in readback
                if str(item.get("name", "")) == username
            )
            if not still_active:
                counts["verified"] += 1
            else:
                counts["failed"] += 1
            current = readback
        return current, counts

    def _automation_alert(self, *, action: str, target: str, title: str, details: str) -> None:
        """Store fixed, secret-free operator guidance; never persist RouterOS exception text."""
        self.context.store.add_alert(
            severity="critical", action=action, target=target, title=title, details=details
        )

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
        pending = previous.startswith("pending:")
        if pending:
            previous = previous.removeprefix("pending:")
        if not state:
            if previous == "expired":
                if not pending:
                    return active
                # Expiry is terminal: once a disable intent was persisted, a
                # later control edit must not silently restore the account.
                state = "expired"
                reason = "The configured access expiry was reached."
            if not state:
                if previous not in {"quota", "schedule"}:
                    return active
                freshness, current_user = self._automation_fresh_user(credentials, user)
                if pending and freshness == "fresh" and current_user is not None and not bool(current_user.get("disabled")):
                    # A prior disable intent is resolved: RouterOS confirms the
                    # account is enabled, so no compensating write is needed.
                    self.context.store.set_enforcement_state(username, "")
                    self.context.store.audit(
                        actor="automation", action="user.auto_restore", target=username,
                        status="success", details={"previous_state": previous, "readback": "already_enabled"},
                    )
                    return active
                if freshness != "fresh" or current_user is None or not bool(current_user.get("disabled")):
                    status = "unknown" if freshness == "unknown" else "stale"
                    self.context.store.audit(
                        actor="automation", action="user.auto_restore", target=username,
                        status=status, details={"reason": "account_changed_since_observation"},
                    )
                    self._automation_alert(
                        action="user.auto_restore.review", target=username,
                        title=f"Review access restoration for {username}",
                        details="The RouterOS account changed or could not be re-read. No automatic access change was made.",
                    )
                    return active
                try:
                    self.context.router.create_configuration_export(
                        credentials, name=f"vpn-dashboard-before-restore-{username}-{now}"
                    )
                except RouterOSError:
                    self.context.store.audit(
                        actor="automation", action="user.auto_restore", target=username,
                        status="failed", details={"reason": "checkpoint_failed"},
                    )
                    self._automation_alert(
                        action="user.auto_restore.failed", target=username,
                        title=f"Could not restore {username}",
                        details="A RouterOS checkpoint could not be created. No access change was applied.",
                    )
                    return active
                freshness, checked_user = self._automation_fresh_user(credentials, current_user)
                if freshness != "fresh" or checked_user is None:
                    self.context.store.audit(
                        actor="automation", action="user.auto_restore", target=username,
                        status="unknown" if freshness == "unknown" else "stale",
                        details={"reason": "account_changed_after_checkpoint"},
                    )
                    self._automation_alert(
                        action="user.auto_restore.review", target=username,
                        title=f"Review access restoration for {username}",
                        details="The RouterOS account changed after the checkpoint. No automatic access change was made.",
                    )
                    return active
                current_user = checked_user
                try:
                    self.context.router.update_user(credentials, user_id=str(user["id"]), disabled=False)
                except RouterOSError as error:
                    mutation_error = error
                else:
                    mutation_error = None
                result, _readback = self._automation_user_readback(credentials, current_user, disabled=False)
                if result == "verified":
                    self.context.store.set_enforcement_state(username, "")
                    self.context.store.audit(
                        actor="automation", action="user.auto_restore", target=username,
                        status="success", details={"previous_state": previous, "readback": "verified"},
                    )
                    if control.get("notifications", True):
                        self.context.store.add_alert(
                            severity="info", action="user.auto_restore", target=username,
                            title=f"Access restored for {username}",
                            details="The configured schedule is open again and RouterOS confirms the account is enabled.",
                        )
                else:
                    outcome = "unknown" if result == "unknown" else "failed"
                    self.context.store.audit(
                        actor="automation", action="user.auto_restore", target=username,
                        status=outcome,
                        details={"previous_state": previous, "readback": result,
                                 "request_error": mutation_error is not None},
                    )
                    self._automation_alert(
                        action="user.auto_restore.failed", target=username,
                        title=f"Could not verify restored access for {username}",
                        details="RouterOS did not confirm that the account is enabled. The automatic restriction remains recorded.",
                    )
                return active
        # A manually suspended account is not changed by automation. An
        # administrator can restore it explicitly; policy enforcement will then
        # run again on the next poll if the restriction still applies.
        if bool(user.get("disabled")) and previous == "":
            return active
        freshness, current_user = self._automation_fresh_user(credentials, user)
        if freshness != "fresh" or current_user is None:
            status = "unknown" if freshness == "unknown" else "stale"
            self.context.store.audit(
                actor="automation", action="user.auto_disable", target=username,
                status=status, details={"reason": "account_changed_since_observation"},
            )
            self._automation_alert(
                action=f"user.auto_disable.{state}.review", target=username,
                title=f"Review access restriction for {username}",
                details="The RouterOS account changed or could not be re-read. No automatic account change was made.",
            )
            return active
        if bool(current_user.get("disabled")) and previous == "":
            # A manually disabled account remains under operator control.
            return active
        should_disable = not bool(current_user.get("disabled"))
        fresh_sessions = self._automation_fresh_sessions(credentials)
        if fresh_sessions is None:
            self.context.store.audit(
                actor="automation", action="user.auto_disable", target=username,
                status="unknown", details={"reason": "session_snapshot_unavailable"},
            )
            self._automation_alert(
                action=f"user.auto_disable.{state}.unknown", target=username,
                title=f"Could not inspect sessions for {username}",
                details="RouterOS session state could not be read. No automatic account change was made.",
            )
            return active
        targets = [item for item in fresh_sessions if str(item.get("name", "")) == username]
        if not should_disable and previous == state and not targets:
            if pending:
                self.context.store.set_enforcement_state(username, state)
            return fresh_sessions
        if should_disable:
            try:
                self.context.router.create_configuration_export(
                    credentials, name=f"vpn-dashboard-before-enforcement-{username}-{now}"
                )
            except RouterOSError:
                self.context.store.audit(
                    actor="automation", action="user.auto_disable", target=username,
                    status="failed", details={"reason": "checkpoint_failed"},
                )
                self._automation_alert(
                    action=f"user.auto_disable.{state}.failed", target=username,
                    title=f"Could not restrict {username}",
                    details="A RouterOS checkpoint could not be created. No account change was applied.",
                )
                return active
            freshness, checked_user = self._automation_fresh_user(credentials, current_user)
            if freshness != "fresh" or checked_user is None:
                self.context.store.audit(
                    actor="automation", action="user.auto_disable", target=username,
                    status="unknown" if freshness == "unknown" else "stale",
                    details={"reason": "account_changed_after_checkpoint"},
                )
                self._automation_alert(
                    action=f"user.auto_disable.{state}.review", target=username,
                    title=f"Review access restriction for {username}",
                    details="The RouterOS account changed after the checkpoint. No automatic account change was made.",
                )
                return active
            current_user = checked_user
            try:
                # Persist intent before the RouterOS write. If the worker exits
                # or read-back is unavailable, the next poll can reconcile this
                # exact policy action instead of mistaking it for a manual disable.
                self.context.store.set_enforcement_state(username, f"pending:{state}")
            except Exception:  # noqa: BLE001 - fail closed if recovery intent cannot be persisted
                self._automation_alert(
                    action=f"user.auto_disable.{state}.failed", target=username,
                    title=f"Could not record restriction for {username}",
                    details="The local recovery intent could not be saved. No RouterOS account change was applied.",
                )
                return active
            request_failed = False
            try:
                self.context.router.update_user(credentials, user_id=str(user["id"]), disabled=True)
            except RouterOSError:
                request_failed = True
                pass  # Exact RouterOS read-back below resolves ambiguous responses.
            result, _readback = self._automation_user_readback(credentials, current_user, disabled=True)
            if result != "verified":
                outcome = "unknown" if result == "unknown" else "failed"
                self.context.store.audit(
                    actor="automation", action="user.auto_disable", target=username,
                    status=outcome,
                    details={"reason": state, "readback": result,
                             "request_error": request_failed},
                )
                self._automation_alert(
                    action=f"user.auto_disable.{state}.failed", target=username,
                    title=f"Could not verify access restriction for {username}",
                    details="RouterOS did not confirm that the account is disabled. Session termination was not attempted.",
                )
                if result != "unknown":
                    self.context.store.set_enforcement_state(username, "")
                return active
        # Save the reason only after RouterOS confirms the disabled state. On
        # later polls, still retry any sessions that remain connected.
        self.context.store.set_enforcement_state(username, state)
        # Re-snapshot after the account is confirmed disabled so a session
        # arriving during the disable request is included in the cleanup pass.
        post_disable = self._automation_fresh_sessions(credentials)
        counts = {"attempted": 0, "verified": 0, "failed": 0, "unknown": 0, "stale": 0}
        remaining = post_disable
        if post_disable is None:
            counts["unknown"] = 1
        else:
            targets = [item for item in post_disable if str(item.get("name", "")) == username]
            remaining, counts = self._automation_terminate_sessions(credentials, username, targets)
        # The final point-in-time snapshot is authoritative for current live
        # sessions, including identities that changed or appeared during cleanup.
        final_sessions = self._automation_fresh_sessions(credentials)
        if final_sessions is not None:
            remaining = final_sessions
        active_remaining = (
            sum(1 for item in final_sessions if str(item.get("name", "")) == username)
            if final_sessions is not None else None
        )
        has_session_failures = active_remaining is None or active_remaining > 0
        audit_status = "partial" if has_session_failures else "success"
        self.context.store.audit(
            actor="automation", action="user.auto_disable", target=username,
            status=audit_status,
            details={
                "reason": state,
                "account_readback": "verified",
                "session_attempted": counts["attempted"],
                "sessions_disconnected_verified": counts["verified"],
                "sessions_failed": counts["failed"],
                "sessions_unknown": counts["unknown"],
                "sessions_still_active": active_remaining,
                "final_session_readback": "verified" if final_sessions is not None else "unknown",
            },
        )
        if control.get("notifications", True):
            severity = "critical" if has_session_failures else "warning"
            action = f"user.auto_disable.{state}.partial" if has_session_failures else f"user.auto_disable.{state}"
            detail = reason
            if has_session_failures:
                detail += " The account is confirmed disabled, but active sessions remain or their state could not be read; the worker will retry."
            self.context.store.add_alert(
                severity=severity, action=action, target=username,
                title=f"Access restriction {'partially applied' if has_session_failures else 'applied'} for {username}",
                details=detail,
            )
        return remaining

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
                            remaining, counts = self._automation_terminate_sessions(
                                credentials, username, matching[limit:], max_sessions=limit
                            )
                            if remaining is not None:
                                active = remaining
                            still_over = sum(
                                1 for item in (remaining or []) if str(item.get("name", "")) == username
                            ) > limit
                            partial = bool(counts["failed"] or counts["unknown"] or still_over)
                            self.context.store.audit(
                                actor="automation",
                                action="session.limit",
                                target=username,
                                status="partial" if partial else "success",
                                details={
                                    "limit": limit,
                                    "sessions_attempted": counts["attempted"],
                                    "sessions_disconnected_verified": counts["verified"],
                                    "sessions_failed": counts["failed"],
                                    "sessions_unknown": counts["unknown"],
                                    "still_over_limit": still_over,
                                },
                            )
                            if control.get("notifications", True):
                                self.context.store.add_alert(
                                    severity="critical" if partial else "warning",
                                    action="session.limit.partial" if partial else "session.limit",
                                    target=username,
                                    title=(
                                        f"Connection limit needs review for {username}"
                                        if partial else f"Connection limit applied to {username}"
                                    ),
                                    details=(
                                        f"The worker could not verify that the account is within its {limit}-session limit. It will retry."
                                        if partial else f"RouterOS confirms the account is within its {limit}-session limit."
                                    ),
                                )
                except RouterOSError:
                    # A transient poll must not kill the worker.
                    continue
