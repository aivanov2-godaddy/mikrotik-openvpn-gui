# Security assurance: authentication and live sessions

**Scope:** focused, repository-level evidence for dashboard authentication,
session lifecycle, authorization, and live telemetry authorization. This is not
a security certification, penetration test, or a claim that every OWASP ASVS
requirement is met. The mapping below uses OWASP ASVS 5.0.0 requirement IDs;
only the named implementation paths and tests are in scope.

## Evidence map

The V7 references follow the [OWASP ASVS 5.0 session management requirements](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x16-V7-Session-Management.md).

| ASVS 5.0.0 requirement | In-scope implementation | Automated evidence | Result / limit |
| --- | --- | --- | --- |
| V7.2.1, V7.2.2, V7.2.3 | Backend `SessionStore` validates opaque, CSPRNG-generated reference tokens. | `tests/test_security.py::test_session_tokens_are_fresh_csprng_reference_values`; `tests/test_app.py::test_login_health_and_authentication_boundaries` | Covered by unit/in-process tests; no external security assessment. |
| V7.3.1, V7.3.2 | 30-minute idle and 8-hour absolute lifetime defaults; expiry enforced by `SessionStore.get`. Live-stream revalidation does not refresh the idle timer. | `tests/test_security.py::test_session_idle_and_absolute_expiry`; `tests/test_security.py::test_read_only_session_revalidation_does_not_extend_idle_timeout`; `tests/test_asgi_contract.py::test_expired_live_session_is_disconnected_without_emitting_telemetry`; `tests/test_asgi_contract.py::test_live_pump_rechecks_capabilities_on_the_current_session` | Covered in deterministic/in-process tests; production timeout behavior not observed in this change. |
| V7.4.1 | Logout destroys the server-side session; live Socket.IO pump re-checks its principal before sending. | `tests/test_app.py::test_login_health_and_authentication_boundaries`; `tests/test_asgi_contract.py::test_live_pump_disconnects_when_session_is_revoked`; `tests/test_asgi_contract.py::test_expired_live_session_is_disconnected_without_emitting_telemetry` | Covered for logout/revocation and expiry in tests; no claim about unrelated downstream systems. |
| V7.4.5, V7.5.2 | Capability-protected session inventory and revocation endpoints; current session cannot revoke itself. | `tests/test_app.py::test_auth_audit_events_are_detailed_but_secret_free`; `tests/test_security.py::test_session_snapshot_is_safe_and_revoke_is_scoped` | Partial: route-level authorization and user experience have not had an independent review. |
| V7.5.1 | Sensitive dashboard mutations require the existing authenticated session and CSRF validation. | `tests/test_app.py::test_user_profile_lifecycle_and_csrf`; `tests/test_security.py::test_csrf_comparison` | Partial: representative paths only; this is not a complete route-by-route mutation audit. |
| V4 authorization (role/capability boundary) | Explicit role capability matrix; unknown roles default to read-only; telemetry principal contains authorization facts, not the session object. | `tests/test_security.py::test_dashboard_role_capability_matrix_fails_closed`; `tests/test_asgi_contract.py::test_live_pump_rechecks_capabilities_on_the_current_session` | Covered for tested capability behavior. Full authorization matrix across every route remains open. |

Run focused evidence locally:

```powershell
python -m unittest tests.test_security tests.test_asgi_contract tests.test_app
```

CI remains the authoritative repository test result for a proposed commit. A
passing suite only establishes the assertions in those tests; it is not a
blanket pass for ASVS, OWASP, or production security.

## Security design notes and residual risks

- RouterOS remains the identity and credential authority. After successful
  dashboard login, the application retains the RouterOS username/password in
  process memory for authenticated router operations. Passwords are not
  written to the dashboard session inventory or telemetry principal. This
  creates an in-memory exposure window: process dumps, host compromise, or
  application-level memory disclosure could expose the credential. The
  current RouterOS API integration requires reusable credentials; replacing
  that model needs a RouterOS-supported alternative and is not solved here.
- Browser sessions are process-local and reference-token based. Restarting the
  app invalidates them. Multi-instance session sharing is not in scope.
- Browser session cookies are emitted with `Secure`, `HttpOnly`, and
  `SameSite=Strict`; state-changing routes use CSRF validation. These code-level
  facts do not establish correct reverse-proxy/TLS behavior in the deployed
  environment.
- Automated live-stream evidence covers Socket.IO pump revalidation in-process.
  It does not prove an actual browser reconnect, cross-origin behavior at the
  deployed proxy, or revocation timing on a physical router.
- The SSE endpoint has a bounded response loop and requires an authenticated
  RouterOS session at entry. Its end-to-end revocation behavior through real
  browsers and reverse proxies has not been separately exercised by this
  partial.

## Explicitly unverified live-router / deployment evidence

No RouterOS, production service, credentials, cookies, router names, IP
addresses, or raw records were read or changed for this assurance work. The
following remain **NOT VERIFIED** and require an authorized controlled test
window:

- Observe logout, server-side revocation, idle expiry, and absolute expiry on
  the deployed image while an authenticated live stream is open; verify the
  stream stops without refresh and reconnect requires authentication.
- Verify proxy TLS termination, secure-cookie handling, same-origin policy,
  and expected cross-origin denial using the actual public deployment.
- Review RouterOS user permissions and credential-memory exposure on the
  physical host; this code-only change cannot inspect host process memory or
  router policy.
- Verify no credentials, cookies, session identifiers, private addresses,
  router names, or raw records appear in deployed logs, exports, crash dumps,
  or telemetry payloads.
- Complete an independent, requirement-by-requirement ASVS review and any
  required penetration testing before making a compliance claim.

## Non-goals

This document is a narrow evidence index for the session/live-stream area. It
does not assert full ASVS Level 1 or Level 2 conformance, and it does not
replace the project’s existing release acceptance or RouterOS operational
acceptance procedures.
