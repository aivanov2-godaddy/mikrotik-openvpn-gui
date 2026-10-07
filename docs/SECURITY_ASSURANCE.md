# Security assurance: authentication and live sessions

**Scope:** focused, repository-level evidence for dashboard authentication,
session lifecycle, authorization, and live telemetry authorization. This is not
a security certification, penetration test, or a claim that every OWASP ASVS
requirement is met. The mapping below uses OWASP ASVS 5.0.0 requirement IDs;
only the named implementation paths and tests are in scope.

## Scoped ASVS control matrix

This matrix covers every requirement in ASVS 5.0.0 V7 (Session Management),
V8 (Authorization), and V4.4 (WebSocket) for this review's scope. It does not
cover the rest of ASVS or establish conformance. `TESTED` means repository
tests directly exercise the stated behavior; `PARTIAL` means an implementation
or test exists but the full requirement is not established; `GAP` means the
current product does not satisfy the requirement; `N/A` is a documented
product-scope exclusion; and `EXTERNAL` requires evidence from the deployed
proxy, RouterOS, or host. External and partial results are not passes.

| ASVS 5.0.0 control | Status | Scoped finding and evidence |
| --- | --- | --- |
| V7.1.1 | PARTIAL | Idle and absolute lifetimes are documented and tested, but the risk-based rationale for the selected values is not recorded. See V7.3.1–V7.3.2 below. |
| V7.1.2 | GAP | No documented maximum for concurrent dashboard sessions or defined behavior when that maximum is reached. |
| V7.1.3 | EXTERNAL | Cloudflare Access is an independent edge-authentication layer; its session lifetime/termination relationship to the app session has not been verified from deployment configuration. |
| V7.2.1–V7.2.3 | TESTED | Backend reference-session validation and CSPRNG token generation are covered by `test_session_tokens_are_fresh_csprng_reference_values` and login-boundary tests. |
| V7.2.4 | PARTIAL | Each successful login creates a new server-side reference session; no regression proves that a prior session is terminated on re-authentication because the app has no re-authentication flow. |
| V7.3.1–V7.3.2 | PARTIAL | 30-minute idle and 8-hour absolute defaults and in-process expiry/live-delivery behavior are tested. Risk justification and production/proxy timing remain unverified. |
| V7.4.1 | TESTED | Logout, expiry, and server-side revocation stop subsequent session use and live delivery in deterministic tests. |
| V7.4.2 | TESTED | Disabled/missing RouterOS account regressions revoke the corresponding existing dashboard session. |
| V7.4.3 | N/A | The dashboard does not change authentication factors for its operator accounts; RouterOS credential/factor lifecycle is outside this app session-management scope. |
| V7.4.4 | PARTIAL | A sign-out control is present in the shared authenticated header. There is no human usability evidence confirming visibility across every authenticated view. |
| V7.4.5 | TESTED | Administrative session inventory and scoped revocation are covered by session-store and route tests, including `DashboardIntegrationTests.test_admin_session_revocation_is_csrf_protected_scoped_and_audited`. |
| V7.5.1 | N/A | The app does not edit authentication/recovery attributes of dashboard operator accounts. VPN-user profile edits are a separate RouterOS identity domain. |
| V7.5.2 | TESTED | Terminating another administrator session requires the current RouterOS account password to be verified again; the supplied password is not persisted and failed attempts are rate-limited. |
| V7.5.3 | GAP | Review receipts, CSRF, and rationale protect sensitive operations, but the app does not require a second authentication factor/step-up before highly sensitive operations. No ASVS Level 3 claim is made. |
| V7.6.1 | EXTERNAL | The app does not coordinate an IdP/RP session itself; Cloudflare Access session behavior and termination propagation require deployment evidence. |
| V7.6.2 | TESTED | App session creation follows an explicit login request; login/CSRF/origin boundary tests cover the app-side entry point. |
| V8.1.1 | TESTED | Function/data authorization rules are documented in [ROUTE_AUTHORIZATION.md](ROUTE_AUTHORIZATION.md) and exercised by route/capability matrices. |
| V8.1.2 | PARTIAL | Capability-filtered fields and export scopes have targeted tests, but no exhaustive field-by-field authorization inventory has been independently reviewed. |
| V8.1.3–V8.1.4 | N/A | The app does not make adaptive risk decisions from location, time, device posture, or similar environmental context. Edge-provider policy is outside this repository's evidence. |
| V8.2.1 | PARTIAL | Server-side function authorization and representative role/capability route families are tested; the route/method/token-scope cross-product is not exhaustive. |
| V8.2.2 | PARTIAL | Resource ownership/state checks exist on sensitive mutations, but data-specific authorization has not received an exhaustive independent review. |
| V8.2.3 | PARTIAL | Selected API/export fields are capability-filtered and tested; an exhaustive read/write field-level map is not available. |
| V8.2.4 | N/A | Adaptive environmental/contextual authorization is not a product feature; no Level 3 adaptive-control claim is made. |
| V8.3.1 | TESTED | Authorization is enforced server-side; client-side visibility is not the enforcement boundary. Negative route tests verify denials precede RouterOS/state mutation. |
| V8.3.2 | PARTIAL | RouterOS account/group changes are revalidated at up to 15-second intervals and live delivery rechecks authorization; immediate physical-router enforcement and deployed latency are unmeasured. |
| V8.3.3 | PARTIAL | Current RouterOS-session capabilities are re-derived for live delivery; a complete end-to-end subject-vs-intermediary authorization review remains outstanding. |
| V8.4.1 | N/A | Multi-tenant architecture is explicitly excluded from the single-router product scope. |
| V8.4.2 | PARTIAL | App-side RouterOS role revalidation and the Cloudflare Access edge provide separate controls, but deployed configuration, device-posture checks, and contextual risk controls are unverified. |
| V4.4.1 | EXTERNAL | The public app uses HTTPS, but deployed WebSocket transport/TLS termination has not been independently verified; a Socket.IO status label alone is not proof of WSS. |
| V4.4.2 | TESTED | Same-origin checks cover the Socket.IO polling path; ASGI handshake tests reject foreign WebSocket origins. Deployed proxy behavior is unverified. |
| V4.4.3–V4.4.4 | N/A | Live connections use the standard authenticated app session rather than a separate WebSocket token; separate-token acquisition/validation requirements are therefore not applicable to the implemented path. |

The `N/A` entries are limited to the stated product boundary; they are not
claims that an external proxy, RouterOS, or the whole deployment satisfies
those controls. The gaps and external checks above remain open acceptance work.

## Evidence map

The V7 references follow the [OWASP ASVS 5.0.0 session-management requirements](https://github.com/OWASP/ASVS/blob/v5.0.0_release/5.0/en/0x16-V7-Session-Management.md). Authorization controls use [ASVS 5.0.0 V8](https://github.com/OWASP/ASVS/blob/v5.0.0_release/5.0/en/0x17-V8-Authorization.md); the WebSocket origin control is [V4.4.2](https://github.com/OWASP/ASVS/blob/v5.0.0_release/5.0/en/0x13-V4-API-and-Web-Service.md#v44-websocket). These references are version-qualified because control identifiers differ across ASVS versions.

| ASVS 5.0.0 requirement | In-scope implementation | Automated evidence | Result / limit |
| --- | --- | --- | --- |
| V7.2.1, V7.2.2, V7.2.3 | Backend `SessionStore` validates opaque, CSPRNG-generated reference tokens. | `tests/test_security.py::test_session_tokens_are_fresh_csprng_reference_values`; `tests/test_app.py::test_login_health_and_authentication_boundaries` | Covered by unit/in-process tests; no external security assessment. |
| V7.3.1, V7.3.2 | 30-minute idle and 8-hour absolute lifetime defaults; expiry enforced by `SessionStore.get`. Live-stream revalidation does not refresh the idle timer. | `tests/test_security.py::test_session_idle_and_absolute_expiry`; `tests/test_security.py::test_read_only_session_revalidation_does_not_extend_idle_timeout`; `tests/test_asgi_contract.py::test_expired_live_session_is_disconnected_without_emitting_telemetry`; `tests/test_asgi_contract.py::test_live_pump_rechecks_capabilities_on_the_current_session` | Covered in deterministic/in-process tests; production timeout behavior not observed in this change. |
| V7.4.1 | Logout destroys the server-side session; the active Socket.IO pump and polling bridge re-check the current session before each frame in a polled batch; SSE checks the supplied Origin before RouterOS I/O and re-checks the current effective capability before each telemetry write without extending idle expiry. The optional legacy Socket.IO adapter likewise re-resolves the server-side session before polls and each pushed frame and closes on missing or revoked authorization; it is not wired into the active production runtime. | `tests/test_app.py::test_login_health_and_authentication_boundaries`; `tests/test_app.py::DashboardIntegrationTests.test_sse_rejects_foreign_origin_before_router_fetch`; `tests/test_app.py::DashboardIntegrationTests.test_sse_stops_emitting_when_server_session_is_revoked`; `tests/test_app.py::DashboardIntegrationTests.test_sse_stops_emitting_when_idle_session_expires`; `tests/test_app.py::DashboardIntegrationTests.test_sse_stops_emitting_when_absolute_session_lifetime_expires`; `tests/test_app.py::DashboardIntegrationTests.test_sse_stops_when_effective_session_capability_is_narrowed`; `tests/test_asgi_contract.py::test_live_pump_disconnects_when_session_is_revoked`; `tests/test_asgi_contract.py::test_expired_live_session_is_disconnected_without_emitting_telemetry`; `tests/test_asgi_contract.py::test_live_pump_stops_a_polled_batch_when_session_is_revoked_mid_send`; `tests/test_asgi_contract.py::test_socketio_subscribe_stops_a_polled_batch_when_capability_is_revoked`; `tests/test_telemetry_socketio_polling.py::SocketIOPollingBridgeTests.test_poll_stops_batch_when_stream_authorization_is_revoked`; `tests/test_telemetry_socketio_polling.py::SocketIOPollingBridgeTests.test_poll_closes_when_authenticated_session_expires`; `tests/test_telemetry_socketio.py::SocketIOTelemetryAdapterTests.test_publish_closes_stream_when_authorization_is_revoked`; `tests/test_telemetry_socketio.py::SocketIOTelemetryAdapterTests.test_poll_revalidates_before_emitting_each_frame`; `tests/test_telemetry_socketio.py::SocketIOTelemetryAdapterTests.test_poll_fails_closed_when_session_environment_disappears` | Covered by deterministic in-process tests for logout/revocation, expiry, per-frame authorization, and missing session state. The SSE origin regression proves a foreign origin is rejected before any RouterOS session read; Origin-less clients still need valid authentication and capability. This does not verify deployment behind the live proxy or router; the optional adapter's tests are not evidence that it is in production use. |
| V7.4.5 | Capability-protected session inventory and revocation endpoints; current session cannot revoke itself. | `tests/test_app.py::test_auth_audit_events_are_detailed_but_secret_free`; `tests/test_security.py::test_session_snapshot_is_safe_and_revoke_is_scoped`; `tests/test_app.py::DashboardIntegrationTests.test_read_only_role_cannot_cross_audit_or_mutation_capability_boundaries` | Curated negative tests cover audit/token reads and sensitive mutations for read-only sessions; not an independent authorization review. |
| V7.5.2 | Session inventory is available to authorized operators; revoking another administrator session requires a fresh RouterOS password verification for the current account, is rate-limited on failure, and never records the password. | `tests/test_app.py::DashboardIntegrationTests.test_admin_session_revocation_is_csrf_protected_scoped_and_audited`; `tests/test_app.py::DashboardIntegrationTests.test_admin_session_reauthentication_is_rate_limited`; rendered live-session revocation regression in `browser-tests/realtime-recovery.spec.js` | Application behavior is regression-tested. This does not constitute the independent security review or verify deployment-side authentication/proxy behavior. |
| V7.5.1 | Sensitive dashboard mutations require the existing authenticated session and CSRF validation. | `tests/test_app.py::test_user_profile_lifecycle_and_csrf`; `tests/test_security.py::test_csrf_comparison`; `tests/test_app.py::DashboardIntegrationTests.test_sensitive_route_matrix_fails_closed_for_anonymous_requests` | Literal GET/POST and regex-dispatched POST/PATCH/DELETE API forms are matched to the exercised route tuples. Anonymous and missing-CSRF denials are checked before RouterOS/persistent state changes. The maintained [route authorization inventory](ROUTE_AUTHORIZATION.md) describes capability groups and scope limits. |
| V8 authorization (role/capability boundary); V4.4.2 WebSocket Origin validation | Explicit role capability matrix; API-token scopes are enforced on connection/usage exports and the combined compliance export; unknown roles default to read-only; telemetry principal contains authorization facts, not the session object. Socket.IO retains python-engineio's default same-origin validation and re-derives authorization from the current server-side session on reconnect. SSE separately rejects a supplied foreign Origin before RouterOS reads; this is an application safeguard, not a WebSocket control. RouterOS-backed sessions also re-check the account's enabled state and group-derived role at most every 15 seconds on authenticated requests and live SSE/Socket.IO authorization checks. A downgrade takes effect on the existing session; an increase requires a fresh login; a missing/disabled account revokes; lookup failures reduce to read-only. | `tests/test_security.py::test_dashboard_role_capability_matrix_fails_closed`; `tests/test_security.py::test_every_role_matches_the_complete_declared_capability_matrix`; `tests/test_app.py::DashboardIntegrationTests.test_role_capability_denials_precede_every_guarded_route_family`; `tests/test_app.py::DashboardIntegrationTests.test_sse_rejects_foreign_origin_before_router_fetch`; `tests/test_security.py::test_routeros_role_revalidation_downgrades_without_extending_idle_lifetime`; `tests/test_security.py::test_routeros_role_revalidation_never_elevates_an_existing_session`; `tests/test_security.py::test_routeros_role_revalidation_revokes_missing_or_incomparable_identity`; `tests/test_security.py::test_routeros_role_lookup_error_falls_back_to_read_only`; `tests/test_routeros.py::RouterOSClientTests.test_admin_role_lookup_fails_closed_for_unknown_disabled_or_unreadable_accounts`; `tests/test_app.py::DashboardIntegrationTests.test_routeros_group_downgrade_takes_effect_on_existing_dashboard_session`; `tests/test_app.py::DashboardIntegrationTests.test_disabled_routeros_account_revokes_existing_live_session`; `tests/test_app.py::DashboardIntegrationTests.test_read_only_role_cannot_cross_audit_or_mutation_capability_boundaries`; `tests/test_app.py::DashboardIntegrationTests.test_enterprise_foundations_are_scoped_and_read_only_where_expected`; `tests/test_asgi_contract.py::test_live_pump_rechecks_capabilities_on_the_current_session`; `tests/test_asgi_contract.py::test_socketio_reconnect_uses_current_server_session_capabilities`; `tests/test_asgi_contract.py::test_socketio_does_not_disable_engineio_same_origin_validation`; `tests/test_asgi_contract.py::test_socketio_asgi_rejects_foreign_origin_at_http_handshake`; `tests/test_asgi_contract.py::test_socketio_asgi_rejects_foreign_origin_at_websocket_handshake` | All five role grants are now locked against the complete declared capability set, including fail-closed checks for non-owner roles and the owner's intentional wildcard. Nine high-impact route families have 23 denied role/capability pairings exercised with valid CSRF, and the regression asserts denials cause no RouterOS mutation requests. `/dashboard` omits audit rows and Change History navigation without `audit.read`; `/api/observability` requires `health.read` and conditionally includes audit/session fields for `audit.read` / `sessions.read`. Session-history exports require `sessions.read`, and compliance export requires both `audit.read` and `sessions.read`. This remains representative route-family coverage, not an exhaustive route-by-role/token-scope cross-product. Safe plans/diagnostics are explicitly distinguished from mutations. The 15-second recheck is a repository behavior, not measured physical-router revocation latency; the inventory is not an independent authorization audit, and deployed proxy origin behavior is not verified here. |

The API-token scope regression now exercises each standalone read scope and
the combined read scopes against the documented token-readable endpoint
families. It verifies that missing scopes are denied, RouterOS-session-only
routes reject scoped tokens before any RouterOS request, and dashboard
management capabilities cannot be obtained through API-token scopes. This is
representative scope-boundary coverage, not an exhaustive route/method/query
cross-product.

The polling bridge binds every Engine.IO SID to its creating server-side
session. PR [#483](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/483)
adds regressions proving that foreign-session and anonymous SID probes cannot
read or close the owner's stream, while an owner whose stream capability is
revoked is cleaned up on its next request:
`SocketIOPollingBridgeTests.test_polling_sid_is_bound_to_the_session_that_opened_it`,
`SocketIOPollingBridgeTests.test_unauthenticated_sid_probe_cannot_close_another_session_stream`,
and `SocketIOPollingBridgeTests.test_post_closes_owners_stream_after_session_loses_stream_capability`.

Run focused evidence locally:

```powershell
python -m unittest tests.test_security tests.test_asgi_contract tests.test_app tests.test_telemetry_socketio_polling
```

## Repository revalidation — 2026-10-05

The authorization and live-session paths were re-read at baseline commit
`5d31e8737fe55bea0ac65e0d30f3b1aa14c5c26c`. The review covered the route
dispatch inventory, token-scope matrix, metrics and export guards, SSE
write-boundary revalidation, Socket.IO origin/session handling, ASGI live
delivery, and polling SID ownership. The polling ownership check prevents a
foreign or anonymous request from closing another session's subscription;
the owning session still releases its subscription after revocation.

The same review included managed-certificate retirement. The handler requires
`device.manage`, an authenticated RouterOS session, CSRF validation, exact
target-name confirmation, a printable operator reason, and a single-use
session-bound review receipt over the intent and current certificate state.
For a migration, it requires recorded import and operator-test steps, an
active replacement associated with the same VPN user and configured CA, and
an active source certificate. Expiry validation requires RouterOS's relative
`expires-after` remaining-time value; it fails closed if that value is absent
or unparseable, avoiding an assumption that the app host and router share a
timezone. Expiry health alerts and device posture also use this relative value;
the timezone-less absolute `invalid-after` string is shown only as reported and
is not used to decide certificate validity. RouterOS cannot attribute the observed
VPN-user session to a particular client certificate, so the test step is not
cryptographic proof that the replacement authenticated. The replacement must
also have a confirmed positive remaining validity. Before mutation, the
current RouterOS state is bound to a single-use review. Afterward, read-back must confirm both
that the exact source certificate is revoked and that the reviewed replacement
remains unchanged, active, associated with the same user/current CA, and
unexpired. If source revocation is confirmed but replacement verification
fails, the result is reported and persisted as partial, local source state
records the confirmed revocation, and the dashboard continues to show that the
replacement needs review instead of labeling the migration completed. Tests
cover missing live-test evidence, successful review/retirement, expiry and
RouterOS date/duration parsing, a replacement changing during retirement,
partial-state presentation, lost mutation responses, and unavailable or
mismatching read-back. Revocation does not terminate a session already
connected.

The focused command above passed all 187 tests locally on the baseline before
the additional replacement-state guards. The nine focused follow-up tests
then passed locally, covering expiry parsing, expiry rejection, retirement
read-back races, partial-state presentation, and additive SQLite migration.
The repository pre-commit validation also passed its secret scan, compilation,
full unit/mock-integration suite, and JavaScript syntax check on the proposed
change. This is internal repository evidence, not an independent security
review. It does not establish deployed proxy behavior, physical-router
revocation latency, or an external ASVS/penetration-test result. Those live
and independent-review items remain open below.

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
- Creating or deleting shared saved views requires both a valid CSRF token and
  `sessions.read`; regression coverage verifies denied writes leave the saved
  view store unchanged.
- The 15-second role revalidation interval bounds how long an existing
  dashboard session can retain a role after a RouterOS account/group change,
  provided RouterOS returns the current `/user` state. A failed role lookup
  cannot retain Owner privileges; the session is reduced to read-only. A
  RouterOS-reported missing/disabled account or HTTP 401 revokes it. RouterOS
  API policy-session renewal behavior may have its own timing; no immediate
  physical-device enforcement claim is made.
- Browser session cookies are emitted with `Secure`, `HttpOnly`, and
  `SameSite=Strict`; state-changing routes use CSRF validation. These code-level
  facts do not establish correct reverse-proxy/TLS behavior in the deployed
  environment.
- Automated live-stream evidence covers Socket.IO pump revalidation in-process.
  It does not prove an actual browser reconnect, cross-origin behavior at the
  deployed proxy, or revocation timing on a physical router. The application
  leaves python-engineio origin handling enabled; an empty allowed-origin list
  would disable that check and is intentionally not used.
- The legacy Socket.IO polling bridge also compares a supplied `Origin` with
  the configured `PUBLIC_ORIGIN` on handshake/poll requests and requires an
  exact configured origin on POST. GET without `Origin` remains supported for
  clients that omit it; such requests still require the session-bound bridge
  identity. HTTP-dispatch regression tests verify foreign-origin GET/POST
  requests are denied before bridge methods run. This repository evidence does
  not establish behavior at the deployed reverse proxy.
- The SSE endpoint has a bounded response loop and requires an authenticated
  RouterOS session with `sessions.read` at entry. It checks the same server-side
  session and capability before each telemetry write without extending idle
  lifetime. When an `Origin` header is supplied, it now must match the
  configured dashboard origin before SSE performs RouterOS reads; clients that
  omit the header still face the same session/capability checks. Real-browser
  and reverse-proxy revocation timing remain untested.

## Repository hardening and export privacy — 2026-10-05

- `POST /login` requires an exact same-origin `Origin`, or an exact same-origin
  `Referer` when Origin is absent or serialized as the opaque value `null`.
  The login page alone uses `Referrer-Policy: same-origin` so native form
  submissions can provide this evidence without disclosing referrers cross-site.
  Foreign or absent origin evidence returns `403` before RouterOS credential
  verification. Regressions cover foreign Origin precedence, missing evidence,
  same-origin fallback, the opaque-Origin browser case, and the login response
  policy.
- Application access logs now contain only an allowlisted HTTP method and
  parsed response status. They no longer include request paths, short-lived
  profile-share bearer tokens, query values, or peer addresses. This is a
  code-level logger guarantee; reverse-proxy and host logging remain separate.
- `GET /api/users` explicitly requires `users.read` as well as a
  RouterOS-authenticated dashboard session. API tokens remain rejected before
  contacting RouterOS.
- Authorized exports are intentionally not described as fully redacted.
  Connection CSV and the compliance ZIP include VPN usernames, client/VPN
  addresses, timestamps, encryption labels, and traffic totals; compliance
  audit rows may include the operator source address. The
  `backup.manage` metadata archive also includes connection-history session
  identifiers and operator/client/VPN addresses, plus VPN-user emails,
  device/certificate identifiers, policy/control settings, and
  alert/audit/deployment/health records. Its manifest now discloses this scope.
  These files exclude RouterOS credentials/configuration, private keys, and
  client profile files, but are sensitive data and must be handled accordingly.
  The compliance ZIP requires both `audit.read` and `sessions.read`; metadata
  backup requires `backup.manage`; connection CSV
  requires `sessions.read`.
- Synthetic-data regressions assert the expected IP/session-identifier
  inclusions and credential/private-key exclusions in those exports, plus
  verify that the access log does not reveal a synthetic share token or peer
  address.

## Explicitly unverified live-router / deployment evidence

No RouterOS or production state was changed for this assurance work. On
2026-10-04, unauthenticated HTTPS GET requests to `/`, `/api/events`,
`/api/observability`, `/api/operations-timeline.json`, and `/metrics` on the
public dashboard origin each returned HTTP 302 before following redirects. The
browser showed the redirect flow is Cloudflare Access. This is evidence that
the public edge gated these requests at that time; it does not prove the
application's own anonymous-route behavior, authenticated authorization,
cross-origin handling, or live-stream revocation. No redirect query, cookies,
credentials, telemetry payloads, or router identifiers are recorded here.

On 2026-10-06, the same unauthenticated, no-cookie HTTPS GET check was repeated
for `/`, `/metrics`, `/api/events`, and `/api/users`; each returned HTTP 302.
Redirects were not followed, and response bodies/destinations were not retained.
This confirms only the public edge redirect behavior at that observation time.
It does not verify backend authorization, authenticated session expiry or
revocation, WebSocket TLS/origin behavior through the proxy, or host/proxy log
contents. A simultaneous authenticated dashboard observation showed
`Connection data delayed`, so no live-telemetry acceptance pass is claimed.

The following remain **NOT VERIFIED** and require an authorized controlled
test window:

- Observe logout, server-side revocation, idle expiry, and absolute expiry on
  the deployed image behind the actual reverse proxy while a live stream is
  open; verify reconnect requires authentication.
- Verify proxy TLS termination, secure-cookie handling, same-origin policy,
  and expected cross-origin denial using the actual public deployment.
- Review RouterOS user permissions and credential-memory exposure on the
  physical host; this code-only change cannot inspect host process memory or
  router policy.
- Verify deployed application, reverse-proxy, and host logs do not expose
  credentials, session cookies, or profile-share bearer URLs. Repository tests
  cover only the application's sanitized access logger, not external log
  layers.
- Verify crash-dump and live telemetry behavior on the deployed image. In
  particular, do not treat authorized exports as data-free: they intentionally
  contain the fields documented above. Production backup storage, access, and
  retention handling still require operational evidence.
- Complete an independent, requirement-by-requirement ASVS review and any
  required penetration testing before making a compliance claim.

## Non-goals

This document is a narrow evidence index for the session/live-stream area. It
does not assert full ASVS Level 1 or Level 2 conformance, and it does not
replace the project’s existing release acceptance or RouterOS operational
acceptance procedures.
