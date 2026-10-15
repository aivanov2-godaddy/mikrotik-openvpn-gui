# Dashboard session lifetime rationale

The dashboard uses a 30-minute idle timeout and an 8-hour absolute timeout by
default (`security.py`). These are application-session limits; they do not
claim to set or synchronize Cloudflare Access's separate session lifetime.

The dashboard is a single-router administration surface authenticated against
RouterOS. A 30-minute idle limit provides a practical window for an operator
working through review-and-confirm workflows while limiting how long an
abandoned browser session remains usable. The 8-hour absolute cap bounds the
maximum lifetime of a continuously active session to a normal work shift and
requires a fresh RouterOS login even if background activity continues. Live
telemetry, authorization revalidation, and the dashboard's automatic status
and certificate-settings polling do not refresh the idle deadline, so an
unattended open dashboard cannot stay authenticated solely because its stream
or background refreshes remain active.

The server enforces idle and absolute limits with a monotonic process clock as
well as the wall-clock timestamps retained for audit and deterministic tests.
Consequently, a backward system-clock correction cannot extend an in-memory
session's lifetime. A forward wall-clock correction may expire a session early;
expiry deliberately fails closed. Sessions are process-local and are discarded
on restart, so monotonic deadlines are not persisted across boots.

These values are a usability/security compromise, not a claim that a session
cookie remains safe on an unlocked or compromised device. Operators should
sign out on shared devices; the application also supports server-side session
revocation. Cloudflare Access is an additional edge control, but its lifetime
and termination behavior have not been included in this rationale because the
deployed policy has not been independently verified. The limits should be
reassessed if the app becomes multi-instance, adds non-RouterOS operator
accounts, or if measured operator workflows show that the current window is
inadequate.

Deterministic coverage is in
`tests/test_security.py::test_session_idle_and_absolute_expiry`,
`tests/test_security.py::test_session_timeouts_use_monotonic_time_when_wall_clock_moves_backward`,
`tests/test_security.py::test_session_activity_resets_monotonic_idle_deadline`,
`tests/test_security.py::test_session_snapshot_countdowns_use_monotonic_time`,
`tests/test_security.py::test_session_snapshot_preserves_explicit_wall_clock_injection`,
`tests/test_security.py::test_role_revalidation_does_not_return_a_session_expired_during_lookup`,
`tests/test_security.py::test_read_only_session_revalidation_does_not_extend_idle_timeout`,
and the SSE/Socket.IO live-expiry regressions listed in
[`SECURITY_ASSURANCE.md`](SECURITY_ASSURANCE.md). These establish application
behavior, not production or proxy timing.
