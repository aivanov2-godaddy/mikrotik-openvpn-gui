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
revocation. The limits should be reassessed if the app becomes multi-instance,
adds non-RouterOS operator accounts, or if measured operator workflows show
that the current window is inadequate.

## Cloudflare Access and dashboard session coordination

Cloudflare Access and the dashboard create separate sessions. Access is the
edge gate for reaching the origin; the dashboard session is a RouterOS-backed
`__Host-vpn_session` cookie that the application validates independently.
Neither layer copies its timeout into the other, and the application does not
receive an Access session-lifecycle event.

- Access has a global identity-provider session and a separate token for each
  protected application. When an application token expires, Access rechecks the
  identity against policy and can issue a replacement without an IdP prompt if
  the global session remains valid and policy still allows access. If the
  global session has also expired, Access prompts for IdP authentication.
  Therefore, an application-token timeout alone does not guarantee a visible
  sign-in prompt or invalidate the dashboard cookie. Access authentication
  itself does not create, revoke, extend, or refresh the dashboard session. The
  application accepts its cookie only while its own idle/absolute deadlines
  and current RouterOS role checks pass.
- Revoking existing Access application tokens terminates current edge access;
  if policy and identity still allow the user, Access can issue a new token on a
  later request. End-user Access logout clears the Access cookie across
  applications; Cloudflare documents that previously issued tokens may take
  20–30 seconds to stop being accepted. The deployed policy and revocation
  settings determine the actual edge behavior.
- Dashboard logout, application-session expiry, server-side revocation, or an
  application restart invalidates the dashboard session under the application
  rules, even while Access remains authenticated. Dashboard logout does not
  terminate the separate Access session.
- Ending both sessions requires ending/revoking the dashboard session and
  separately terminating the Access session using the configured edge or
  identity-provider controls. Because the dashboard does not bind its session
  to an Access identity, an operator who changes Access identity or policy must
  terminate the existing dashboard session and perform a fresh RouterOS login.
- The deployment must keep every dashboard, API, SSE, and Socket.IO route behind
  the Access gate. Edge enforcement is required even for routes that do not
  need an application cookie.

The configured global, application, policy, and MFA session durations,
logout/termination behavior, identity change behavior, and enforcement across
all routes remain deployment evidence items. They have not been independently
verified on the deployed Access application. The coordination rules above are
the expected operating contract, not proof of the current edge configuration.
See [Cloudflare Access session management](https://developers.cloudflare.com/cloudflare-one/access-controls/access-settings/session-management/)
for the documented token lifetimes, revocation, and logout behavior.

NIST SP 800-63B Section 5.2 describes overall and inactivity timeouts, requires a
session to end when either timeout expires, and says timeout choices depend on
the authentication assurance level and deployment context. This project has
not assigned a NIST Authentication Assurance Level to RouterOS-backed
dashboard sessions and does not claim NIST conformance; the 30-minute and
8-hour values above are this product's documented risk decision, not a NIST
prescription. See the [current NIST SP 800-63B session guidance](https://pages.nist.gov/800-63-4/sp800-63b.html).

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
