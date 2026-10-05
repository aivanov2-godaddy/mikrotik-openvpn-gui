# Dashboard route authorization inventory

This is a repository-maintained index, not an independent security review.
`DashboardIntegrationTests.test_sensitive_route_matrix_fails_closed_for_anonymous_requests`
compares the literal/regex API dispatch forms in `DashboardHandler` with its
exercised route tuples and sends anonymous requests to every listed GET, POST,
PATCH, and DELETE route. Every listed write is also sent with a valid cookie but
without CSRF and must be denied before RouterOS or persistent state changes.
This dispatch/anonymous-CSRF coverage does **not** mean every route has a
complete route-to-capability matrix or exhaustive role-by-role tests; the table
below is a maintained summary, and targeted capability tests cover selected
high-risk boundaries.

The additional role-boundary tests send valid-CSRF requests to sensitive route
families as a `read_only` role. A `403` is expected where the capability is not
granted. Safe, non-mutating diagnostics and plans may intentionally be
available to read-only roles; an HTTP POST alone does not make a route a
RouterOS mutation.

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
| `sessions.read` | `GET /api/admin/sessions`, `/api/events`, `/api/connections.csv`, `/api/usage.csv`, `/api/bulk/views`, `POST /api/bulk/views`, `DELETE /api/bulk/views/{id}`; with `audit.read`, `GET /api/operations-timeline.json` | Operations timeline export combines audit and session history and therefore requires both capabilities. SSE additionally requires a RouterOS-authenticated dashboard session and revalidates its effective capability set while streaming. Saved-view definitions and user filters are not available to health-only tokens; saved-view creation/deletion also checks `sessions.read` after CSRF validation. |
| `policies.read` | `GET /api/policy-templates` | Reveals saved policy-template definitions and assignments; separate from `policies.manage`. |
| `session.manage` | `DELETE /api/admin/sessions/{id}`, `POST /api/sessions/{id}/preview`, `DELETE /api/sessions/{id}` | Revokes a dashboard session, or reviews then terminates a RouterOS VPN session. The preview is non-mutating but requires CSRF, a live RouterOS session, and `session.manage`; apply rechecks the reviewed state. |
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

Automated route tests establish the listed dispatch and role-denial assertions;
they do not replace a code-owner review of every handler, an external
penetration test, or verification behind the production proxy. The high-impact
router mutation workflow is tracked separately in [mutation safety](ROADMAP.md#phase-4-release-and-security-assurance).

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
actions force an immediate role lookup. Full route-by-role/token-scope
cross-product coverage, maximum physical-router revocation latency, and
authenticated production-proxy behavior remain unverified.
