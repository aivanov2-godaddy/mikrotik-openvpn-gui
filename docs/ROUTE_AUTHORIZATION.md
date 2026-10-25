# Dashboard route authorization inventory

This is a repository-maintained index, not an independent security review.
`SecurityAssuranceDocumentContractTests.test_route_document_is_reconciled_to_security_sensitive_dispatch_forms`
mechanically compares method-bound route families in this document with every
literal or regex `/api` dispatch, `/metrics`, and the primary login, dashboard,
health, and profile-share entry paths. A missing or stale family fails CI. This
is an inventory-completeness check only; it does not prove that an individual
authorization decision is correct or replace live deployment review.
`DashboardIntegrationTests.test_sensitive_route_matrix_fails_closed_for_anonymous_requests`
compares the literal/regex API dispatch forms in `DashboardHandler` with its
exercised route tuples and sends anonymous requests to every listed GET, POST,
PATCH, and DELETE route. Every listed write is also sent with a valid cookie but
without CSRF and must be denied before RouterOS or persistent state changes.
`DashboardHandler._require_csrf` also rejects a missing token, a duplicate
`Origin`, or an explicitly foreign `Origin` before dispatch. The opaque
`Origin: null` case is accepted only when a same-origin `Referer` is present;
reauthentication retains the same fallback when `Origin` is absent. For other
routes, an absent `Origin` remains compatible only when the request carries the
valid session CSRF token. The exhaustive role/capability test sends every
current non-GET API dispatch both a forged token with the configured same-origin
value and a valid token with a foreign Origin; both cases must return `403`
without RouterOS mutations or non-audit persistent-state changes. The logout
route has its own valid-token/foreign- and duplicate-Origin regressions. This
does not prove that the deployed proxy preserves or sanitizes origin headers
correctly. Rejected CSRF-origin requests emit a bounded diagnostic containing
only the Origin/Referer header counts and coarse relations (`same`, `other`,
`null`, `invalid`, `duplicate`, or `absent`). Raw header values, URLs, cookies,
CSRF tokens, and request identities are not included; this diagnostic helps
separate deployed proxy/header-shape cases without relaxing the guard.
`DashboardIntegrationTests.test_api_dispatch_has_exhaustive_role_capability_inventory`
maintains a separate capability declaration and valid-CSRF request example for
every literal/regex API dispatch form. It checks all five dashboard roles:
roles missing a declared capability receive `403` without RouterOS mutation or
non-audit persistent-state changes; permitted roles pass the capability gate
(later validation may reject an incomplete request). The test also compares its
declared forms with the handler dispatch table so newly added dispatch forms
fail until classified. Long-lived authorized SSE delivery is covered by the
focused streaming tests rather than this cross-product test. This is an
exhaustive automated matrix over the current dispatch forms, not an independent
handler security review or proof of deployed proxy behavior.
`DashboardIntegrationTests.test_reauthentication_rotates_cookie_csrf_and_uses_current_routeros_capabilities`,
`test_reauthentication_failure_keeps_session_and_rate_limits_bad_passwords`,
and `test_sse_stops_emitting_when_session_is_rotated_by_reauthentication` in
`tests/test_app.py` exercise re-authentication rotation, failed-password and
rate-limit behavior, current RouterOS-derived role capabilities, old-cookie
rejection, foreign-Origin and duplicate-Origin logout denial, and SSE
revocation; `browser-tests/session-reauth.spec.js` covers the Administrator
sessions UI, password clearing, in-memory CSRF adoption, and no document reload.
`FrontendLiveUpdateContractTests` checks that the UI caller, mutable CSRF state,
and this route's authorization documentation remain mapped.
`DashboardIntegrationTests.test_scoped_api_tokens_follow_the_route_scope_matrix`
also checks every current literal GET `/api` dispatch form is assigned to a
scoped-token route, a RouterOS-session-only route, or an explicitly
ungrantable-capability route. Across every nonempty combination of the four
grantable token scopes, it verifies each classified route's allow/deny outcome;
new regex GET dispatches fail until deliberately classified. This matrix does
not authorize bearer tokens for POST, PATCH, or DELETE routes.
Safe, non-mutating diagnostics and plans may intentionally be available to
read-only roles; an HTTP POST alone does not make a route a RouterOS mutation.

## Public, bearer-link, and browser-session routes

| Route | Access boundary | Data and limits |
| --- | --- | --- |
| `GET /` | Public | Redirects to `/dashboard` for an authenticated session or `/login` otherwise; it does not return dashboard data. |
| `GET /login` | Public; an existing session is redirected to `/dashboard` | Returns only the sign-in form and public dashboard labels. |
| `GET /dashboard` | Existing, non-expired RouterOS-authenticated dashboard session | Renders the operator view using server-side role and capability projections; API tokens are not accepted. |
| `GET /healthz`, `/readyz` | Public, no dashboard session | Minimal health state; `/readyz` also reports the application version/revision. These endpoints do not return RouterOS or VPN records. |
| `GET /api/telemetry` | Existing RouterOS-authenticated dashboard session, including the `read_only` role; API tokens are rejected | Transport status only. It does not return VPN-session records and does not require `sessions.read`. |
| `POST /login` | No pre-existing session; requires one same-origin `Origin`, or one same-origin `Referer` when Origin is absent/opaque (`null`), before RouterOS credential verification | Duplicate `Origin` fields and duplicate fallback `Referer` fields are rejected before RouterOS authentication; requests with foreign or absent origin evidence are also rejected. |
| `POST /logout` | Existing, non-expired RouterOS-authenticated dashboard session and a valid form `csrf` token; `_require_csrf` rejects foreign or duplicate `Origin` fields, accepts `Origin: null` only with a same-origin `Referer`, and permits an absent `Origin` only with the valid token | Destroys only the calling dashboard session, writes a secret-free logout audit event, expires the session cookie, and redirects to `/login`. It does not terminate other sessions for the same RouterOS account. |
| `POST /api/setup-plan` | Existing dashboard session and valid CSRF token; no RouterOS role capability is required | Returns a non-executable setup plan. It does not apply RouterOS commands or persist the requested plan. |
| `POST /api/auth/reauthenticate` | Existing non-expired RouterOS-authenticated browser session; valid `X-CSRF-Token`; same-origin `Origin`, or same-origin `Referer` only when Origin is absent or `null` | Uses the session username and submitted password (1–256 characters) for a fresh RouterOS credential check, then reads the account's current enabled state and role/group. It uses the same per-client-IP login rate limiter; rejected credentials consume a failed attempt, success clears the failure state, and RouterOS availability failures do not count as bad credentials. It does not require a role capability because it refreshes the caller's own authentication. Success atomically rotates the in-memory session ID and CSRF token, updates its RouterOS-derived role, and sets a replacement `__Host-vpn_session` cookie (`Secure; HttpOnly; SameSite=Strict`). The prior session is removed immediately; failed checks leave it unchanged. Existing SSE streams stop at their next server-side session revalidation, and Socket.IO polling is rejected against the old session binding. The browser adopts the returned CSRF token in memory and lets the existing transport reconnect with the replacement cookie; this action does not force a document reload, pause telemetry, or close streams manually. The password is retained only in the replacement session's existing in-memory RouterOS credential model; no separate password store or disk/audit persistence is added. |
| `GET /share/{token}` | Bearer-link capability; token is the authorization | Profile ZIP download link expires after 10 minutes and allows at most three downloads. Anyone possessing the link can use it during that window; access logs intentionally omit request paths/tokens and peer addresses. |

Treat profile-share links as secrets despite their short lifetime. Do not paste
them into support logs or issue reports.

For native Socket.IO/Engine.IO, every transport request requires an active
dashboard session and the configured same-origin boundary. A polling GET that
omits `Origin` must carry exactly one same-origin `Referer`; missing, duplicate,
or foreign browser-origin evidence is rejected before allocating an Engine.IO
SID. A new Engine.IO SID is bound to that dashboard session before its
handshake packet is sent to the client; subsequent polling or WebSocket
requests must present the same bound session. Regression coverage checks the
origin boundary, SID binding at the downstream ASGI send boundary, and a real
HTTP Engine.IO handshake.

## Capability-protected route families

| Capability | Route families | Notes |
| --- | --- | --- |
| `health.read` | `GET /metrics`, `/api/status`, `/api/service-health`, `/api/observability`, `/api/setup-preflight`, `/api/release/verify`, `/api/reports/diagnostics.zip`; `POST /api/connection-doctor`, `/api/security/exposure-doctor` | Read-only health, redacted diagnostics, and exposure probes. `/api/release/verify` validates only this project's architecture-specific digest-pinned reference and its tag/revision match; it reports `reference_valid`, while `verified` remains false because the endpoint does not resolve GHCR or verify provenance. `/api/status` additionally requires `users.read` and `sessions.read` because its aggregate response includes user, session, connection, and health data; these checks occur before its status data reads. After the RouterOS reads, the handler revalidates the session and all required capabilities before returning the snapshot, denying a response if authorization changed mid-request. It remains RouterOS-session-only and is not a token endpoint. `/api/observability` requires `health.read`; audit and session-history fields are independently included only with `audit.read` and `sessions.read`. |
| `users.read` | `GET /api/users`, `/api/status` | Requires both a RouterOS-authenticated dashboard session and this explicit capability check. `/api/status` also requires `sessions.read` and `health.read` for its aggregate response. API tokens are not accepted. |
| `sessions.read` | `GET /api/admin/sessions`, `/api/events`, `/api/status`, `/api/connections.csv`, `/api/usage.csv`, `/api/bulk/views`, `POST /api/bulk/views`, `DELETE /api/bulk/views/{id}`; with `audit.read`, `GET /api/operations-timeline.json` | Operations timeline export combines audit and session history and therefore requires both capabilities. `/api/status` also requires `users.read` and `health.read` for its aggregate response. SSE additionally requires a RouterOS-authenticated dashboard session, rejects an explicitly foreign `Origin` before RouterOS reads, and revalidates its effective capability set while streaming. Origin-less clients remain subject to the same session and capability checks. Saved-view definitions and user filters are not available to health-only tokens; saved-view creation/deletion also checks `sessions.read` after CSRF validation. Administrator-session rows include safe inventory metadata; the cookie bearer is never returned. A separately generated, non-authenticating revocation reference appears only with `session.manage`; RouterOS-backed sessions are force-revalidated before that projection, and a failed role lookup revokes the session and denies the request. Query parameters cannot elevate this field access. |
| RouterOS-authenticated session | `POST /api/auth/sessions/revoke-others` | A user may sign out other dashboard sessions for their own case-insensitive RouterOS account only. The UI shows the affected session count and clarifies that the current session is preserved. The route requires CSRF, same-origin validation, a typed confirmation, rate-limited fresh RouterOS-password verification, and session revalidation; it accepts no target account or session ID. Audit records contain only the actor, operation scope, and count. VPN tunnels and API tokens are unaffected. Browser regressions verify the confirmation flow and that the current page remains authenticated. |
| `policies.read` | `GET /api/policy-templates` | Reveals saved policy-template definitions and assignments; separate from `policies.manage`. |
| `session.manage` | `DELETE /api/admin/sessions/{revocation_ref}`, `POST /api/sessions/{id}/preview`, `DELETE /api/sessions/{id}` | Revoking another dashboard session requires CSRF, `session.manage`, and a fresh verification of the current RouterOS account password; attempts are rate-limited and the password is neither persisted nor audited. The revocation reference selects a target but does not authenticate, and the current session cannot revoke itself. VPN-session termination remains a separate review-first RouterOS mutation: preview is non-mutating and apply rechecks the reviewed state. Review receipts are one-time, bound to the issuing dashboard session and exact reviewed intent/state; another session cannot apply them. |
| `users.manage` | `POST /api/users*`, `PATCH /api/users/{id}`, `DELETE /api/users/{id}`, `POST /api/users/{id}/suspend`, `/restore`, `POST /api/bulk/{preview,apply}` for `suspend`/`tag` | User/profile-issuing account changes. Bulk action selects its capability from the validated action. |
| `profiles.read` / `profiles.manage` | `GET /api/certificate-settings`; `POST /api/profile/diagnose`; `POST /api/users/{id}/profiles*`; `POST /api/profile-migrations/{old-certificate}/steps/{imported,tested}` | Certificate settings and profile diagnosis are read-only; profile issuance is a RouterOS mutation. Migration-step writes are operator attestations: the handler verifies both certificates are currently active and the replacement is under the configured CA, but RouterOS cannot prove which client certificate a particular VPN session used. |
| `device.manage` | `POST /api/devices/{id}/revoke*`, `POST /api/profile-migrations/{legacy_certificate}/revoke*`, `POST /api/bulk/{preview,apply}` for `revoke` | Revocation requires an authenticated RouterOS session, CSRF validation, exact target-name confirmation, a reason, and a session-bound review of current RouterOS state. A migration replacement must be imported and marked tested while an active session for the VPN user is observed; this test step is explicitly an operator attestation, because RouterOS cannot attribute a session to a specific certificate. The replacement must match the configured CA and VPN-user identity and have a parseable positive RouterOS `expires-after` duration; missing or unknown remaining validity fails closed. After revocation, RouterOS read-back must confirm the old certificate is revoked and the reviewed replacement remains unchanged, active, and unexpired; otherwise the partial result is persisted and shown as “replacement needs review,” while local state reflects the confirmed old-certificate revocation. Revocation does not terminate an existing VPN session. |
| `policies.manage` | `POST /api/policy-templates*`, `PATCH /api/policy-templates*`, `POST /api/network/segment-plan` | Template apply and segment planning are review-first; the plan endpoint itself does not change RouterOS. |
| `security.manage` | `GET /api/admin/api-tokens`, `POST /api/admin/api-tokens*`, `DELETE /api/admin/api-tokens*`, `POST /api/admin/break-glass/plan`, `POST /api/openvpn-foundation-plan` | Token creation and revocation also require a RouterOS password reauthentication no more than five minutes old; missing/stale step-up is denied with HTTP 428. Break-glass/foundation endpoints return plans and do not apply commands. |
| `audit.read` | `GET /api/audit.csv`, `/api/audit.json`, `/api/reports/compliance.zip`; with `sessions.read`, `GET /api/operations-timeline.json` | Compliance and operations-timeline exports also require `sessions.read`. Compliance ZIP audit rows may include operator source addresses; connection rows include VPN usernames, client/VPN addresses, timestamps, encryption labels, and traffic totals. Treat the export as sensitive. Timeline correlation omits session IDs and addresses. |
| `backup.manage` | `GET /api/backups/metadata.zip`, `POST /api/backups/{preflight,validate,restore-plan}` | Metadata backup includes VPN-user emails, device/certificate identifiers, policy/control settings, alert/audit/deployment/health records, and connection history, including operator/client/VPN addresses and RouterOS session identifiers. It excludes RouterOS configuration, credentials, private keys, and client profile files. Store the archive as sensitive data. Validation and restore-plan routes do not restore data. |
| `alert.manage` | `POST /api/alerts/{id}/ack` | Acknowledges a dashboard alert. |

Authenticated, non-mutating routes such as `GET /api/users` and the review-only
`POST /api/setup-plan` are session-gated; they do not imply RouterOS write
permission.
Creating or revoking a scoped API token additionally requires a successful
RouterOS password re-authentication within the preceding five minutes. The
server enforces this window (HTTP 428 when missing or stale); the dashboard
uses the existing session-rotation dialog before the mutation, adopts the new
CSRF token, and keeps the current page and live transport in place. Initial
RouterOS login counts as recent authentication for that same five-minute
window. Token scopes remain read-only and expire within 30 days.
The diagnostics bundle is explicitly `health.read`-gated. `/api/service-health`
and `/api/setup-preflight` enforce that capability. `/api/status` requires a
RouterOS-authenticated dashboard session. `/api/users` requires that session
and the explicit `users.read` capability; both reject API tokens before
contacting RouterOS. The user-list response is an explicit allowlist (`id`,
`name`, `profile`, `comment`, `disabled`, plus dashboard-owned email, controls,
tags, and template metadata); unexpected RouterOS adapter fields are discarded.
Saved-view reads require `sessions.read`;
policy-template reads require `policies.read`. Browser-cookie mutations
additionally require CSRF. API-token access is restricted by the token's
stored scopes. Unknown roles fail closed through the central capability
matrix.

For `GET /api/admin/sessions`, `sessions.read` permits the session inventory
fields `id_hash`, `username`, `role`, `created_at`, `last_seen`, `idle_seconds`,
`idle_remaining`, `absolute_remaining`, `source_address`, `user_agent`,
`auth_method`, and `current`; the `id` field is empty unless the caller also
has `session.manage`. Before disclosure to a RouterOS-authenticated session,
the server forces a fresh RouterOS role check rather than relying on the
ordinary role-cache interval. A failed RouterOS lookup or a missing/disabled
account revokes the session; only an enabled account with a missing or
unrecognized group is reduced to the safe read-only capability set. The
dashboard reuses that fresh role snapshot for other
sensitive projections in the same response. Query parameters do not change the
decision. The endpoint omits passwords and CSRF tokens. Regression coverage
verifies the exact response keys for a `sessions.read`-only API token and an
owner, identifier projection across all five RouterOS roles, query-parameter
resistance, warm role downgrades across multiple live sessions in both API and
dashboard responses, fail-closed role-lookup errors, and one forced role check
per dashboard response.

`GET /api/telemetry` is intentionally limited to a RouterOS-authenticated
dashboard session, including the `read_only` role, and returns transport
health/status only. It does not return VPN session records and does not require
`sessions.read`; API-token sessions are not accepted by this endpoint. The
read-only role boundary test verifies this explicit exception.

## Limits of this evidence

Automated route tests establish current dispatch-form coverage, anonymous/CSRF,
all current GET API-token route/scope combinations, and route-by-role capability
assertions. The ASGI HTTP adapter passes `scope["client"]` to the existing
handler instead of the adapter's internal socket-pair label. Uvicorn's
automatic client-address rewriting is disabled so it cannot override the
application's configured forwarded-client header. A small ASGI wrapper adjusts
only the external scheme for an exact configured proxy peer, preserving the
original client address for the existing resolver. Regression coverage verifies
the configured Cloudflare header wins when it differs from X-Forwarded-For,
untrusted or missing peers cannot spoof client identity or scheme, and HTTP and
WebSocket schemes are mapped correctly. These tests do not replace a code-owner
review of every handler, provide an external penetration test, or verify
behavior behind the production proxy.
The high-impact router mutation workflow is tracked separately in
[mutation safety](ROADMAP.md#acceptance-principles).

## Independent code review record — 2026-10-04

An independent AI-assisted review of `origin/main` commit `bb3ff5e` traced the
GET/POST/PATCH/DELETE route families, token scopes, dashboard session checks,
and SSE/Socket.IO authorization paths. It found no demonstrated privilege
escalation or unauthorized RouterOS operation in the reviewed paths. It did
find that a valid API token on `GET /api/telemetry` returned no HTTP response
instead of a deliberate denial. PR #405 fixed this by reusing the
RouterOS-session guard and adding a token regression; v2.6.1 is the deployed
patch. The independent reviewer ran 26 focused tests; the subsequent local app,
security, and ASGI run passed 158 tests, and hosted CI passed before release.

This internal code review is not an external penetration test or compliance
assessment. Role-derived authorization for ordinary authenticated reads is
rechecked at most every 15 seconds; already-open live streams use a separate
one-second application cache. Each new or repeated Socket.IO namespace connect
forces an immediate RouterOS role lookup.
Socket.IO connect, poll, and pump authorization lookups run off the ASGI event
loop, with at most four in flight per process; checks fail closed when all
worker slots are occupied. Privileged management actions also force an
immediate role lookup. An exhaustive all-dispatch route-by-role and
route-by-token-scope inventory, maximum physical-router revocation latency, and
independently verified authenticated production-proxy behavior remain
unverified.

## Independent handler review — 2026-10-08

A separate read-only AI-assisted review of `origin/main` commit
`ab537fa1fef7f053aad53bebf27e412c2c8c494e` traced the current GET, POST,
PATCH, and DELETE dispatch forms to their session, CSRF, RouterOS-session, and
capability checks. It also examined the authenticated SSE and Socket.IO
polling paths and the short-lived, download-limited profile-share capability.
The reviewer found no concrete unauthorized RouterOS operation or privilege
escalation in those paths. Existing route/role, token-scope, and focused stream
authorization tests were inspected. The main agent separately ran
`py -3 -m unittest tests.test_app` after this review; all 155 tests passed.
That application-suite result is local regression evidence, not an independent
execution of the full repository CI matrix.

This is a bounded source review, not an external penetration test, formal
ASVS assessment, or verification of production reverse-proxy/configuration
behavior. Live role changes, session expiry/revocation timing on the deployed
router, proxy/origin behavior, RouterOS permission review, and independent
external assessment remain open acceptance items. No production or router
state was accessed or changed for this review.

## Bounded current-main review — 2026-10-14

Two separate read-only AI-assisted reviewers inspected the authorization
inventory and live-stream evidence on source commit
`68bfb6ddf82c2ca89b0b449afe0416bb61f785b1`. The route/role matrix covers the
current dispatch forms and all five dashboard roles; the literal GET API-token
scope matrix is separately exercised. This is not an exhaustive query/resource
state or read/write-field cross-product, and it is not a full independent
requirement-by-requirement ASVS assessment.

The review found that the ASVS evidence summary did not point to the Binary API
session stream and interface-sampler revocation tests, despite those behaviors
being implemented and described elsewhere. The evidence map now references the
credential-refusal, event/snapshot publish denial, sampler post-read denial, and
reconnect-with-snapshot regressions. The review also confirmed that active HTTP,
SSE, and Socket.IO role checks used the 15-second session-role cache at the
source revision reviewed then. Current live streams have a separate one-second
application cache while ordinary HTTP checks retain 15 seconds. The
deterministic live-stream regression proves the configured app bound only;
physical RouterOS response latency and whether RouterOS applies group-policy
changes promptly remain unverified.

## Follow-up reconnect review — 2026-10-14

A bounded read-only review of the authorization source found that the route
inventory omitted `GET /api/certificate-settings` and did not name the
session-gated, review-only `POST /api/setup-plan`. It also found that a Socket.IO
namespace connection could reuse a warm 15-second RouterOS-role cache. A
disabled account could therefore reconnect before the next periodic role
lookup. The current implementation now forces a RouterOS role lookup for both
initial and repeated namespace connects; a regression leaves the cache warm,
disables the account, and verifies both connection forms fail closed in
`test_socketio_connection_forces_routeros_revalidation_with_warm_cache`.
Already-open streams use a separate one-second application role-cache
interval; this is a freshness threshold, not a one-second polling timer. The
SSE handler checks on its two-second loop, so an expired cache is refreshed on
the next loop plus RouterOS REST response time. Socket.IO checks on its
connect/poll/pump/send paths. A process-wide runtime semaphore caps live
RouterOS role refreshes across SSE, threaded polling, and ASGI at four
concurrent checks; stale authorization fails closed when capacity is
saturated. ASGI also keeps its own bounded worker-thread gate, and a cancelled
ASGI lookup retains that worker slot until the blocking lookup finishes. A
negative monotonic elapsed time is treated as stale rather than extending the
cache. Regressions cover the cache boundary, fail-closed saturation, and
cancellation-safe ASGI slot release.

The review also found one omitted traceability row in the ASVS evidence map and
confirmed the in-memory RouterOS-password exposure remains an explicitly
unaccepted residual risk. These documentation/test changes do not establish
physical-router revocation latency, deployed proxy behavior, or a formal risk
acceptance; those remain open under #200.

The focused application/session/ASGI/polling suites passed 272 tests; the
telemetry-runtime and supervisor suites passed 20 tests after adding the cache
boundary regression. These are local repository tests, not deployment evidence.
Production proxy/TLS/origin behavior, live RouterOS revocation latency, resource
state and field-level authorization completeness, and external security review
remain outstanding. No router or production state was accessed or changed.
