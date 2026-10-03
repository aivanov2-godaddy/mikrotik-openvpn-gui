# Dashboard route authorization inventory

This is a repository-maintained index, not an independent security review.
All `/api/*` dispatch entries are inventoried by
`DashboardIntegrationTests.test_sensitive_route_matrix_fails_closed_for_anonymous_requests`.
That test compares the literal/regex dispatch forms in `DashboardHandler` with
the exercised route tuples and sends anonymous requests to every listed GET,
POST, PATCH, and DELETE route. Every listed write is also sent with a valid
cookie but without CSRF and must be denied before RouterOS or persistent state
changes.

The additional role-boundary tests send valid-CSRF requests to sensitive route
families as a `read_only` role. A `403` is expected where the capability is not
granted. Safe, non-mutating diagnostics and plans may intentionally be
available to read-only roles; an HTTP POST alone does not make a route a
RouterOS mutation.

## Capability-protected route families

| Capability | Route families | Notes |
| --- | --- | --- |
| `health.read` | `GET /api/status`, `/api/service-health`, `/api/observability`, `/api/setup-preflight`, `/api/release/verify`; `POST /api/connection-doctor`, `/api/security/exposure-doctor` | Read-only health and exposure probes. |
| `sessions.read` | `GET /api/admin/sessions`, `/api/events`, `/api/connections.csv`, `/api/usage.csv`, `/api/bulk/views`; with `audit.read`, `GET /api/operations-timeline.json` | Operations timeline export combines audit and session history and therefore requires both capabilities. SSE additionally requires a RouterOS-authenticated dashboard session and revalidates its effective capability set while streaming. Saved-view definitions and user filters are not available to health-only tokens. |
| `policies.read` | `GET /api/policy-templates` | Reveals saved policy-template definitions and assignments; separate from `policies.manage`. |
| `session.manage` | `DELETE /api/admin/sessions/{id}`, `DELETE /api/sessions/{id}` | Revokes a dashboard session or terminates a RouterOS VPN session, respectively. |
| `users.manage` | `POST /api/users*`, `PATCH /api/users/{id}`, `DELETE /api/users/{id}`, `POST /api/users/{id}/suspend`, `/restore`, `POST /api/bulk/{preview,apply}` for `suspend`/`tag` | User/profile-issuing account changes. Bulk action selects its capability from the validated action. |
| `profiles.read` / `profiles.manage` | `POST /api/profile/diagnose`; `POST /api/users/{id}/profiles*` | Profile diagnosis is non-mutating; profile issuance is a RouterOS mutation. |
| `device.manage` | `POST /api/devices/{id}/revoke*`, `POST /api/bulk/{preview,apply}` for `revoke` | Certificate revocation is distinct from terminating active sessions. |
| `policies.manage` | `POST`/`PATCH /api/policy-templates*`, `POST /api/network/segment-plan` | Template apply and segment planning are review-first; the plan endpoint itself does not change RouterOS. |
| `security.manage` | `GET /api/admin/api-tokens`, `POST`/`DELETE /api/admin/api-tokens*`, `POST /api/admin/break-glass/plan`, `POST /api/openvpn-foundation-plan` | Break-glass/foundation endpoints return plans and do not apply commands. |
| `audit.read` | `GET /api/audit.csv`, `/api/audit.json`, `/api/reports/compliance.zip`; with `sessions.read`, `GET /api/operations-timeline.json` | Compliance and operations-timeline exports also require `sessions.read`; timeline correlation omits session IDs and addresses. |
| `backup.manage` | `GET /api/backups/metadata.zip`, `POST /api/backups/{preflight,validate,restore-plan}` | Validation and restore-plan routes do not restore data. |
| `alert.manage` | `POST /api/alerts/{id}/ack` | Acknowledges a dashboard alert. |

Authenticated, non-mutating routes such as the diagnostics bundle,
`GET /api/users`, and review-only setup plans are session-gated; they do not
imply RouterOS write permission. Saved-view reads require `sessions.read`;
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
