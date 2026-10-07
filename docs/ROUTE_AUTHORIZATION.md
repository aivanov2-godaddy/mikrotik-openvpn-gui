# Dashboard route authorization inventory

This is a repository-maintained index, not an independent security review.
`DashboardIntegrationTests.test_sensitive_route_matrix_fails_closed_for_anonymous_requests`
compares the literal/regex API dispatch forms in `DashboardHandler` with its
exercised route tuples and sends anonymous requests to every listed GET, POST,
PATCH, and DELETE route. Every listed write is also sent with a valid cookie but
without CSRF and must be denied before RouterOS or persistent state changes.
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
| `GET /healthz`, `/readyz` | Public, no dashboard session | Minimal health state; `/readyz` also reports the application version/revision. These endpoints do not return RouterOS or VPN records. |
| `POST /login` | No pre-existing session; requires a same-origin `Origin`, or a same-origin `Referer` when Origin is absent/opaque (`null`), before RouterOS credential verification | The login page permits same-origin referrers only; requests with foreign or absent origin evidence are rejected before contacting RouterOS. |
| `GET /share/{token}` | Bearer-link capability; token is the authorization | Profile ZIP download link expires after 10 minutes and allows at most three downloads. Anyone possessing the link can use it during that window; access logs intentionally omit request paths/tokens and peer addresses. |

Treat profile-share links as secrets despite their short lifetime. Do not paste
them into support logs or issue reports.

## Capability-protected route families

| Capability | Route families | Notes |
| --- | --- | --- |
| `health.read` | `GET /metrics`, `/api/service-health`, `/api/observability`, `/api/setup-preflight`, `/api/release/verify`, `/api/reports/diagnostics.zip`; `POST /api/connection-doctor`, `/api/security/exposure-doctor` | Read-only health, redacted diagnostics, and exposure probes. `/api/observability` requires `health.read`; audit and session-history fields are independently included only with `audit.read` and `sessions.read`. `/api/status` is session-gated and returns the operator's normal dashboard data; it is not a token endpoint. |
| `users.read` | `GET /api/users` | Requires both a RouterOS-authenticated dashboard session and this explicit capability check. API tokens are not accepted. |
| `sessions.read` | `GET /api/admin/sessions`, `/api/events`, `/api/connections.csv`, `/api/usage.csv`, `/api/bulk/views`, `POST /api/bulk/views`, `DELETE /api/bulk/views/{id}`; with `audit.read`, `GET /api/operations-timeline.json` | Operations timeline export combines audit and session history and therefore requires both capabilities. SSE additionally requires a RouterOS-authenticated dashboard session, rejects an explicitly foreign `Origin` before RouterOS reads, and revalidates its effective capability set while streaming. Origin-less clients remain subject to the same session and capability checks. Saved-view definitions and user filters are not available to health-only tokens; saved-view creation/deletion also checks `sessions.read` after CSRF validation. |
| `policies.read` | `GET /api/policy-templates` | Reveals saved policy-template definitions and assignments; separate from `policies.manage`. |
| `session.manage` | `DELETE /api/admin/sessions/{id}`, `POST /api/sessions/{id}/preview`, `DELETE /api/sessions/{id}` | Revoking another dashboard session requires CSRF, `session.manage`, and a fresh verification of the current RouterOS account password; attempts are rate-limited and the password is neither persisted nor audited. The current session cannot revoke itself. VPN-session termination remains a separate review-first RouterOS mutation: preview is non-mutating and apply rechecks the reviewed state. |
| `users.manage` | `POST /api/users*`, `PATCH /api/users/{id}`, `DELETE /api/users/{id}`, `POST /api/users/{id}/suspend`, `/restore`, `POST /api/bulk/{preview,apply}` for `suspend`/`tag` | User/profile-issuing account changes. Bulk action selects its capability from the validated action. |
| `profiles.read` / `profiles.manage` | `POST /api/profile/diagnose`; `POST /api/users/{id}/profiles*`; `POST /api/profile-migrations/{old-certificate}/steps/{imported,tested}` | Profile diagnosis is non-mutating; profile issuance is a RouterOS mutation. Migration-step writes are operator attestations: the handler verifies both certificates are currently active and the replacement is under the configured CA, but RouterOS cannot prove which client certificate a particular VPN session used. |
| `device.manage` | `POST /api/devices/{id}/revoke*`, `POST /api/profile-migrations/{legacy_certificate}/revoke*`, `POST /api/bulk/{preview,apply}` for `revoke` | Revocation requires an authenticated RouterOS session, CSRF validation, exact target-name confirmation, a reason, and a session-bound review of current RouterOS state. A migration replacement must be imported and marked tested while an active session for the VPN user is observed; this test step is explicitly an operator attestation, because RouterOS cannot attribute a session to a specific certificate. The replacement must match the configured CA and VPN-user identity and have a parseable positive RouterOS `expires-after` duration; missing or unknown remaining validity fails closed. After revocation, RouterOS read-back must confirm the old certificate is revoked and the reviewed replacement remains unchanged, active, and unexpired; otherwise the partial result is persisted and shown as “replacement needs review,” while local state reflects the confirmed old-certificate revocation. Revocation does not terminate an existing VPN session. |
| `policies.manage` | `POST`/`PATCH /api/policy-templates*`, `POST /api/network/segment-plan` | Template apply and segment planning are review-first; the plan endpoint itself does not change RouterOS. |
| `security.manage` | `GET /api/admin/api-tokens`, `POST`/`DELETE /api/admin/api-tokens*`, `POST /api/admin/break-glass/plan`, `POST /api/openvpn-foundation-plan` | Break-glass/foundation endpoints return plans and do not apply commands. |
| `audit.read` | `GET /api/audit.csv`, `/api/audit.json`, `/api/reports/compliance.zip`; with `sessions.read`, `GET /api/operations-timeline.json` | Compliance and operations-timeline exports also require `sessions.read`. Compliance ZIP audit rows may include operator source addresses; connection rows include VPN usernames, client/VPN addresses, timestamps, encryption labels, and traffic totals. Treat the export as sensitive. Timeline correlation omits session IDs and addresses. |
| `backup.manage` | `GET /api/backups/metadata.zip`, `POST /api/backups/{preflight,validate,restore-plan}` | Metadata backup includes VPN-user emails, device/certificate identifiers, policy/control settings, alert/audit/deployment/health records, and connection history, including operator/client/VPN addresses and RouterOS session identifiers. It excludes RouterOS configuration, credentials, private keys, and client profile files. Store the archive as sensitive data. Validation and restore-plan routes do not restore data. |
| `alert.manage` | `POST /api/alerts/{id}/ack` | Acknowledges a dashboard alert. |

Authenticated, non-mutating routes such as `GET /api/users` and review-only
setup plans are session-gated; they do not imply RouterOS write permission.
The diagnostics bundle is explicitly `health.read`-gated. `/api/service-health`
and `/api/setup-preflight` enforce that capability. `/api/status` requires a
RouterOS-authenticated dashboard session. `/api/users` requires that session
and the explicit `users.read` capability; both reject API tokens before
contacting RouterOS. Saved-view reads require `sessions.read`;
policy-template reads require `policies.read`. Browser-cookie mutations
additionally require CSRF. API-token access is restricted by the token's
stored scopes. Unknown roles fail closed through the central capability
matrix.

`GET /api/telemetry` is intentionally limited to a RouterOS-authenticated
dashboard session, including the `read_only` role, and returns transport
health/status only. It does not return VPN session records and does not require
`sessions.read`; API-token sessions are not accepted by this endpoint. The
read-only role boundary test verifies this explicit exception.

## Limits of this evidence

Automated route tests establish current dispatch-form coverage, anonymous/CSRF,
all current GET API-token route/scope combinations, and route-by-role capability
assertions. They do not replace a code-owner review of every handler, provide
an external penetration test, or verify behavior behind the production proxy.
The high-impact router mutation workflow is tracked separately in
[mutation safety](ROADMAP.md#phase-4-release-and-security-assurance).

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
assessment. Role-derived authorization for ordinary authenticated reads and
live streams is rechecked at most every 15 seconds; privileged management
actions force an immediate role lookup. An exhaustive all-dispatch route-by-role
and route-by-token-scope inventory, maximum physical-router revocation latency,
and independently verified authenticated production-proxy behavior remain
unverified.
