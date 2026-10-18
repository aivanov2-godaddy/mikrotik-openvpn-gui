# Security assurance: authentication and live sessions

**Scope:** focused, repository-level evidence for dashboard authentication,
session lifecycle, authorization, and live telemetry authorization. This is not
a security certification, penetration test, or a claim that every OWASP ASVS
requirement is met. The mapping below uses OWASP ASVS 5.0.0 requirement IDs;
only the named implementation paths and tests are in scope.

## Scoped ASVS control matrix

This matrix covers every requirement in ASVS 5.0.0 V7 (Session Management),
V8 (Authorization), and V4.4 (WebSocket) for this review's scope, plus the
selected applicable controls V3.3.1–V3.3.5 (Cookie Setup) and V3.5.1 (Browser
Origin Separation). It does not cover the rest of ASVS or establish conformance. `TESTED` means repository
tests directly exercise the stated behavior; `PARTIAL` means an implementation
or test exists but the full requirement is not established; `GAP` means the
current product does not satisfy the requirement; `N/A` is a documented
product-scope exclusion; and `EXTERNAL` requires evidence from the deployed
proxy, RouterOS, or host. External and partial results are not passes.

The rationale for the configured idle and absolute session limits is recorded
in [SESSION_LIFETIME_RATIONALE.md](SESSION_LIFETIME_RATIONALE.md). V7.1.1
remains partial pending independent validation. V7.3.1–V7.3.2 remain partial
because deployed Cloudflare Access coordination and production timing are
external acceptance items.

| ASVS 5.0.0 control | Status | Scoped finding and evidence |
| --- | --- | --- |
| V3.3.1 | TESTED | The dashboard session cookie uses the `__Host-` prefix and `Secure`. Login and reauthentication regressions verify the prefix, secure attributes, and host-bound path. This is repository evidence, not deployed-proxy evidence. |
| V3.3.2 | TESTED | `SameSite=Strict` is set on session cookie creation, rotation, and deletion; the authenticated login and reauthentication integration tests assert it. |
| V3.3.3 | TESTED | Session cookies use `__Host-`, `Path=/`, and no `Domain` attribute; login and reauthentication tests assert these required host-only properties. A regression rejects the previous unprefixed cookie name. |
| V3.3.4 | TESTED | Session cookies are `HttpOnly`, and the session identifier is absent from login and reauthentication response bodies; it is returned in `Set-Cookie`. Application tests assert the header attributes and body boundary. |
| V3.3.5 | TESTED | The issued session-cookie name/value pair is bounded below 4096 bytes in the authenticated login regression. |
| V3.5.1 | PARTIAL | Every current non-GET API dispatch is tested with a valid browser CSRF token and a foreign `Origin`, and with a forged token plus the configured same-origin value; both must be denied without RouterOS mutations or non-audit persistent-state changes. Logout has valid-token foreign/duplicate-Origin and duplicate-CSRF-header regressions. Explicit foreign or duplicate `Origin` values and duplicate `X-CSRF-Token` fields are rejected centrally by `_require_csrf`; the ASGI adapter preserves repeated Origin and CSRF fields for that check (`tests/test_asgi_contract.py::ASGIContractTests.test_http_adapter_preserves_duplicate_origin_and_csrf_fields_for_handler`). Opaque `Origin: null` is accepted only with a same-origin `Referer`, and a missing `Origin` is accepted only with a valid CSRF token (reauthentication also requires same-origin Referer evidence when Origin is absent). Login rejects duplicate Origin fields and duplicate fallback Referer fields. Deployed proxy behavior and independent review remain outstanding. |
| V7.1.1 | PARTIAL | The 30-minute idle and 8-hour absolute defaults have a documented risk rationale. Session expiry checks use monotonic elapsed time so backward wall-clock corrections cannot extend process-local sessions; deterministic regressions cover rollback and activity-based idle reset. Independent validation remains outstanding. |
| V7.1.2 | TESTED | At most eight active dashboard sessions are allowed per RouterOS account in this single-process deployment. A valid login above the limit is denied with HTTP 429 and recovery guidance; existing sessions are never evicted. Idle and absolute expiry are enforced at the exact deadline (`>=`) by session lookup, rotation, and purge tests; expired sessions are purged before admission. Client-aware rate limiting trusts forwarded addresses only from an exact configured proxy peer; `X-Forwarded-For` is resolved right-to-left across valid addresses while skipping configured proxy hops, and malformed chains or multi-valued single-address headers fall back to the transport peer. `ProxyTrustTests` cover spoofed prefixes, duplicate header fields, malformed/all-trusted chains, and untrusted peers. ASGI tests verify original-peer propagation, that Uvicorn address rewriting is disabled, that the configured Cloudflare client header wins over a conflicting XFF value, and that only an exact trusted peer can set the HTTP/WebSocket scheme. Deployed proxy sanitization remains an external check. |
| V7.1.3 | EXTERNAL | Cloudflare Access is an independent edge-authentication layer; its session lifetime/termination relationship to the app session has not been verified from deployment configuration. |
| V7.2.1–V7.2.3 | TESTED | Backend reference-session validation and CSPRNG token generation are covered by `test_session_tokens_are_fresh_csprng_reference_values` and login-boundary tests. |
| V7.2.4 | TESTED | A CSRF- and same-origin-protected re-authentication endpoint verifies the current account's RouterOS password, derives its current RouterOS group role, then atomically replaces the in-memory session and CSRF tokens and revokes the old reference. Failed verification leaves the session unchanged and uses the existing login rate limiter; no second password store is introduced. Session-store and integration tests cover rotation at the account session limit, old-cookie API rejection, current-capability enforcement, and stopping active SSE/Socket.IO delivery. This is deterministic repository evidence only; deployed proxy/router behavior and independent review remain unverified. |
| V7.3.1–V7.3.2 | PARTIAL | The 30-minute idle and 8-hour absolute defaults, documented rationale, and in-process expiry/live-delivery behavior are tested, including equality at both expiry deadlines, backward wall-clock correction, and expiry during RouterOS role lookup. Monotonic checks prevent clock rollback from extending a process-local session and keep the displayed timeout countdowns aligned with enforcement. Automatic dashboard status and certificate-settings polling do not refresh or revive an expired idle session. Production/proxy timing and Cloudflare Access coordination remain unverified. |
| V7.4.1 | TESTED | Logout, expiry, and server-side revocation stop subsequent session use and live delivery in deterministic tests. A loopback active-ASGI WebSocket test covers role downgrade, account disable, stream closure, and rejected reconnect. SSE reconnect rejects revoked/expired sessions before RouterOS reads; the threaded handler serializes writes, and the ASGI adapter holds the same session lock through the actual awaited SSE body send. The optional threaded polling bridge also gates its successful GET packet write. The native Socket.IO ASGI boundary revalidates WebSocket frames and polling bodies at actual sends, so packets queued before revocation are withheld if not yet sent. Native Socket.IO `telemetry.subscribe` uses protocol version 2: acknowledgements return an empty `frames` list and telemetry is delivered only as pushed event frames, avoiding a second unguarded copy. Clients that consumed replay frames from version-1 acknowledgements must migrate to event handlers. ASGI body and terminal SSE sends and threaded body writes have bounded timeouts; cancelled ASGI sends are drained before unlocking. Duplicate Cookie headers are resolved identically by the adapter and handler. The ordering is at server-side send completion; already accepted network bytes cannot be recalled, and this is not deployed-router timing evidence. |
| V7.4.2 | TESTED | Disabled/missing RouterOS account regressions revoke the corresponding existing dashboard session. |
| V7.4.3 | N/A | The dashboard does not change authentication factors for its operator accounts; RouterOS credential/factor lifecycle is outside this app session-management scope. |
| V7.4.4 | PARTIAL | A sign-out control is present in the shared authenticated header. There is no human usability evidence confirming visibility across every authenticated view. |
| V7.4.5 | TESTED | Administrative session inventory and scoped revocation are covered by session-store and route tests, including `DashboardIntegrationTests.test_admin_session_revocation_is_csrf_protected_scoped_and_audited`. |
| V7.5.1 | N/A | The app does not edit authentication/recovery attributes of dashboard operator accounts. VPN-user profile edits are a separate RouterOS identity domain. |
| V7.5.2 | TESTED | Terminating another administrator session requires the current RouterOS account password to be verified again; the supplied password is not persisted and failed attempts are rate-limited. |
| V7.5.3 | PARTIAL | Fresh RouterOS-password checks protect revoking another dashboard session and creating/revoking scoped API tokens. Token mutations require reauthentication within five minutes, enforced server-side. Other high-impact mutations use intent-bound review receipts rather than password step-up; sensitive exports use capability gates. The action-by-action assessment below is repository evidence, not independent policy approval or deployed verification; no ASVS Level 3 claim is made. |
| V7.6.1 | EXTERNAL | The app does not coordinate an IdP/RP session itself; Cloudflare Access session behavior and termination propagation require deployment evidence. |
| V7.6.2 | TESTED | App session creation follows an explicit login request; login/CSRF/origin boundary tests cover the app-side entry point. |
| V8.1.1 | TESTED | Function/data authorization rules are documented in [ROUTE_AUTHORIZATION.md](ROUTE_AUTHORIZATION.md) and exercised by route/capability matrices. |
| V8.1.2 | PARTIAL | Capability-filtered fields and export scopes have targeted tests. `test_native_websocket_preserves_telemetry_redaction_allowlists` exercises connected, updated, and snapshot frames over a real loopback WebSocket and asserts the exact session-field allowlist with secret sentinels absent. An exhaustive field-by-field authorization inventory has not been independently reviewed. |
| V8.1.3–V8.1.4 | N/A | The app does not make adaptive risk decisions from location, time, device posture, or similar environmental context. Edge-provider policy is outside this repository's evidence. |
| V8.2.1 | PARTIAL | Every current literal/regex API dispatch form is bound to a role/capability inventory, and declared gates are exercised across all five dashboard roles. Current non-GET API routes are also exercised with forged CSRF and valid-CSRF/foreign-Origin requests; query/resource-state combinations and independent review are not exhaustive. |
| V8.2.2 | PARTIAL | Resource ownership/state checks exist on sensitive mutations, but data-specific authorization has not received an exhaustive independent review. |
| V8.2.3 | PARTIAL | Selected API/export fields are capability-filtered and tested; the native WebSocket integration test also checks exact session-field allowlists across connected, updated, and snapshot frames. An exhaustive read/write field-level map is not available. |
| V8.2.4 | N/A | Adaptive environmental/contextual authorization is not a product feature; no Level 3 adaptive-control claim is made. |
| V8.3.1 | TESTED | Authorization is enforced server-side; client-side visibility is not the enforcement boundary. Negative route tests verify denials precede RouterOS/state mutation. |
| V8.3.2 | PARTIAL | Routine RouterOS account/group changes on active streams are revalidated at up to 15-second intervals; fresh/repeated Socket.IO connects force an immediate role lookup, and ASGI connect/poll/pump lookups run in bounded workers. The ASGI HTTP adapter checks the current principal under the shared session lock and holds it through actual SSE body sends; the Socket.IO ASGI wrapper does the same for native WebSocket and polling output. Stale roles refresh in bounded workers, and cancelled sends drain before unlock. ASGI body/terminal sends and threaded SSE/polling writes time out after 10 seconds; the latter reset the socket timeout after writing. HTTP requests disclosing `audit.read` data also force a fresh check. Tests cover bounded capacity, cancellation, duplicate-cookie selection, simulated blocked threaded/ASGI writes, clock rollback, role downgrade, queued-frame suppression, and send/revocation ordering. Physical-router enforcement, client receipt timing, and deployed latency remain unmeasured. |
| V8.3.3 | PARTIAL | Current RouterOS-session capabilities are re-derived for live delivery; a complete end-to-end subject-vs-intermediary authorization review remains outstanding. |
| V8.4.1 | N/A | Multi-tenant architecture is explicitly excluded from the single-router product scope. |
| V8.4.2 | PARTIAL | App-side RouterOS role revalidation and the Cloudflare Access edge provide separate controls, but deployed configuration, device-posture checks, and contextual risk controls are unverified. |
| V4.4.1 | EXTERNAL | The public app uses HTTPS, but deployed WebSocket transport/TLS termination has not been independently verified; a Socket.IO status label alone is not proof of WSS. |
| V4.4.2 | TESTED | Same-origin checks cover the Socket.IO polling path; ASGI handshake tests reject foreign WebSocket origins. Deployed proxy behavior is unverified. |
| V4.4.3–V4.4.4 | N/A | Live connections use the standard authenticated app session rather than a separate WebSocket token; separate-token acquisition/validation requirements are therefore not applicable to the implemented path. |

The ASGI send-boundary regressions additionally verify that Engine.IO SIDs
remain bound to the dashboard session that opened them, including polling and
WebSocket upgrade attempts after a cookie/session change. Malformed, unknown,
and expired SIDs fail closed; Socket.IO path suffixes remain behind the same
send gate. Every response on `/api/events` has bounded ASGI sends regardless
of HTTP method, while live telemetry authorization remains limited to the GET
body. These are deterministic repository checks only, not deployed-proxy or
client-receipt evidence (`tests/test_asgi_contract.py::test_socketio_engine_sid_is_bound_to_originating_session`,
`tests/test_asgi_contract.py::test_socketio_engine_sid_rejects_unknown_malformed_and_expired_ids`,
`tests/test_asgi_contract.py::test_socketio_polling_sid_binding_uses_real_engineio_handshake`,
`tests/test_asgi_contract.py::test_http_adapter_bounds_non_get_live_route_responses`).

## High-impact action and step-up assessment

This inventory distinguishes fresh authentication from CSRF, role checks, and
review receipts; those controls are not interchangeable. It is a source-level
assessment, not an external policy approval or a claim about the deployed
router.

| Action family | Current safeguard | Fresh-password step-up | Assessment / remaining evidence |
| --- | --- | --- | --- |
| Revoke another dashboard administrator session | `session.manage`, CSRF, current RouterOS password verification, rate limit, and audit | Required for the operation | Automated request/response tests cover denial and success; deployed proxy behavior remains unverified. |
| Create or revoke a scoped API token | `security.manage`, CSRF, read-only allowlisted scopes, one-time plaintext display, hashed storage, bounded expiry | Required within five minutes; server rejects stale/missing reauthentication with HTTP 428 | Integration and browser tests cover stale denial, successful rotation, create/revoke, and no page reload. This is application evidence only. |
| VPN-session termination, account suspend/delete, profile issuance, certificate revocation, and policy apply | Capability + CSRF; high-impact operations use target/state-bound review receipts, explicit reason/target confirmation where applicable, and RouterOS read-back/checkpointing | Not separately required | Review receipts guard exact intent and stale state, but are not password step-up. Whether to require fresh authentication for each class remains a risk-policy decision; live RouterOS failure/rollback evidence remains open. |
| Certificate-migration `imported` / `tested` attestations | Capability + CSRF and current certificate/session-state checks | Not required | These are operator attestations; RouterOS cannot identify the certificate used by a particular active VPN session. They do not prove cryptographic replacement use and remain a residual workflow risk. |
| Audit, connection, usage, compliance, and metadata-backup exports | Specific read/backup capability; exact disclosed data scope documented below | Not required | Exports intentionally contain sensitive operational data. Evaluate deployed operator/session controls and retention; a capability gate is not a step-up control. |
| Saved views and alert acknowledgement | Read/manage capability + CSRF; local dashboard metadata only | Not required | Low-impact, reversible actions; no separate step-up is justified by the current scope. |

This assessment closes the repository's inventory gap for the named action
families only. It does not decide that password step-up is unnecessary for all
other actions, replace independent review, or establish live deployment
behavior. The broader ASVS and external checks remain open.

## Field-level disclosure contract (selected sensitive read surfaces)

This is an explicit, test-backed field inventory for the sensitive observability
and reporting surfaces below; it is not a claim that every application response
has received a complete field-level authorization review. Tests compare exact
key/header sets so an added field requires an intentional contract update.

| Surface | Allowed response fields / columns | Capability boundary and limit |
| --- | --- | --- |
| `GET /api/policy-templates` | Root: `templates`, `assignments`. `templates[]`: `id`, `name`, `description`, `group_name`, `controls`, `protected`, `created_at`, `updated_at`; `controls`: `policy`, `expires_at`, `max_sessions`, `rate_limit_kbps`, `dns_mode`, `notifications`, `quota_mb`, `schedule`. `assignments[username]`: `vpn_user`, `template_id`, `overrides`, `assigned_at`, `updated_at`; overrides are limited to supported control names. | Requires `policies.read`. Storage rows and nested JSON are projected to fixed allowlists at the HTTP boundary. Regression tests assert exact field sets and reject injected top-level, nested-control, assignment, and override sentinels. |
| `GET /api/observability` | Top level: `current`, `deployments`, `health_timeline`, `operations_timeline`, `rollback`, `generated_at`. `current`: `version`, `revision`, `status`. `rollback`: `available`, `revision`, `version`, `message`, `data_preserved`. | Requires `health.read`. The operations timeline includes dashboard audit and status-only integration delivery events only with `audit.read`, and session-snapshot events only with `sessions.read`; session events omit RouterOS session IDs and peer/VPN addresses. Deployment and health rows are bounded status summaries. A synthetic HTTP regression checks all 15 non-empty combinations of the four API-token scopes, exact response/event field sets, denied requests without `health.read`, and query parameters that attempt to widen scope or request unapproved fields. |
| `GET /api/setup-preflight` | Root: `router`, `image_target`, `openvpn`, `checks`. `router`: `architecture`, `version`, `free_storage`. `openvpn`: `name`, `enabled`. `checks[]`: `name`, `status`, `detail`. | Authenticated dashboard read. The response projects RouterOS inventory onto this fixed schema; a regression injects private-key and collection-field sentinels and asserts they are absent. |
| `GET /api/operations-timeline.json` | Root: `events`, `generated_at`, `coverage`; coverage: `complete`, `message`. Event fields are the tested allowlist: `id`, `occurred_at`, `source`, `type`, `actor`, `target`, `outcome`, `severity`, `summary`, `clock_skew_seconds`, `age_seconds`, `related_events`, `relationship_summary`; only session rows add `timestamp_quality`. Relationship fields: `event_id`, `source`, `relation`, `delta_seconds`. | Requires both `audit.read` and `sessions.read`. The report deliberately omits raw audit details, integration payloads, database/session IDs, and source/VPN addresses; correlation is context, not proof of cause. |
| `GET /api/connections.csv` | `user`, `connected`, `disconnected`, `source_ip`, `vpn_ip`, `encryption`, `received_bytes`, `sent_bytes`, `received_packets`, `sent_packets`. | Requires `sessions.read`; addresses and usernames are intentionally present, so treat the export as sensitive. |
| `GET /api/usage.csv` | `user`, `period_start`, `connections`, `received_bytes`, `sent_bytes`, `total_bytes`, `quota_mb`, `last_seen`. | Requires `sessions.read`; contains per-user usage and quota information. |
| `GET /api/status` | Root: `users`, `sessions`, `connections`, `alerts`, `role`, `role_label`, `capabilities`, `router`, `observability`, `telemetry`, `generated_at`. `users[]`: `id`, `name`, `profile`, `comment`, `disabled`, `email`, `controls`, `tags`, `template`; `controls`: `vpn_user`, `policy`, `expires_at`, `max_sessions`, `rate_limit_kbps`, `dns_mode`, `notifications`, `quota_mb`, `schedule`, `enforcement_state`, `updated_at`, `quota_used_bytes`; `template`: `id`, `name`, `group_name`, `overrides`; `tags[]`: strings. `sessions[]`: `id`, `name`, `vpn_address`, `source_address`, `uptime`, `encoding`, `service`, `rx_bytes`, `tx_bytes`, `rx_packets`, `tx_packets`, `counter_complete`. `router`: `cpu-load`, `free-memory`, `total-memory`, `free-hdd-space`, `total-hdd-space`, `uptime`. `connections[]`: `id`, `session_id`, `vpn_user`, `source_address`, `vpn_address`, `encoding`, `connected_at`, `last_seen_at`, `disconnected_at`, `rx_bytes`, `tx_bytes`, `rx_packets`, `tx_packets`. `alerts[]`: `id`, `severity`, `title`, `details`, `created_at`, `last_seen_at`, `occurrence_count`. | Requires a RouterOS-authenticated dashboard session and explicit `users.read`, `sessions.read`, and `health.read` capabilities before its status data reads. Session revalidation may consult RouterOS before those capability checks. All returned records are projected onto fixed allowlists before serialization. Regression tests assert exact nested user/control/template and other response field sets, and a negative test denies each required capability before status data fetches. |
| `GET /api/service-health` | Root: `overall`, `checked_at`, `checks`. `checks[]`: `id`, `name`, `status`, `impact`, `remediation`. | Requires `health.read`. The HTTP boundary projects both root and check records onto these fixed fields; a regression test injects unapproved root/check fields containing password, certificate, and address sentinels and asserts exact field sets plus absence of those sentinels. |
| `GET /api/admin/sessions` | Root: `sessions`, `idle_timeout_seconds`, `absolute_timeout_seconds`, `generated_at`. `sessions[]`: `id`, `id_hash`, `username`, `role`, `created_at`, `last_seen`, `idle_seconds`, `idle_remaining`, `absolute_remaining`, `source_address`, `user_agent`, `auth_method`, `current`. | Requires `sessions.read`; raw session IDs are returned only when the caller also has `session.manage`, otherwise `id` is empty and only the short hash is provided. RouterOS-backed sessions are force-revalidated before this sensitive projection; a failed role lookup revokes the session and returns an authentication failure, as does a missing account. Source address and user agent are sensitive operator metadata. HTTP regressions assert the exact field set, query-parameter resistance, warm role-downgrade redaction on API and dashboard responses, lookup-failure behavior, and a single forced role check per dashboard response. |
| `GET /api/admin/api-tokens` | Root: `tokens`. `tokens[]`: `id`, `label`, `actor`, `capabilities`, `created_at`, `expires_at`, `last_used_at`, `revoked_at`. | Requires `security.manage`. The response exposes bounded token metadata only; plaintext bearer tokens and stored token hashes are never listed. An HTTP regression asserts the exact response field set and checks plaintext/hash sentinels are absent. |
| `GET /api/reports/compliance.zip` | `summary.json`: `format`, `version`, `generated_at`, `range` (`from`, `to`), `counts` (`audit_entries`, `connection_entries`, `failed_audit_entries`), `redaction`; `audit.csv`: `timestamp`, `operator`, `action`, `target`, `result`, `details`; `connections.csv`: `user`, `connected`, `disconnected`, `source_ip`, `vpn_ip`, `encryption`, `received_bytes`, `sent_bytes`. | Requires both `audit.read` and `sessions.read`. The CSVs intentionally contain identifying operational data described in the redaction notice; they are not anonymous. |

For `/api/status`, `observability.current` is `version`, `revision`, `status`;
`deployments[]` is `id`, `version`, `revision`, `status`, `channel`,
`created_at`; deployment `details` are omitted. `health_timeline[]` is `id`,
`overall`, `healthy_count`, `warning_count`, `unavailable_count`, `checks`,
`created_at` with each check projected to `id`, `status`; unapproved root and
nested fields are omitted.
`operations_timeline` is `events`, `generated_at`,
`coverage`; and `rollback` is `available`, `revision`, `version`, `message`,
`data_preserved`. `telemetry` is `requested_transport`, `transport`,
`socketio_enabled`, `namespace`, `fallback`, `state`, `last_event_at`,
`last_reconciliation_at`, `event_age_seconds`, `reconciliation_age_seconds`,
`event_count`, `last_session_event_at`, `session_event_age_seconds`,
`session_events`, `last_traffic_sample_at`, `traffic_sample_age_seconds`,
`traffic_samples`, `reconnects`, `last_error`, `socketio_engine`,
`protocol_version`, `gateway`; the gateway exposes `active_clients`,
`buffered_events`, `published_events`, `replayed_events`, `snapshot_recoveries`,
`rejected_clients`, `delivery_observations`, `delivery_queue_age_seconds`, and
`delivery_queue_age_p95_seconds`. The projection test asserts these exact sets.

The exact contract is guarded by
`OperationsTimelineTests.test_sensitive_timeline_fields_match_the_allowlisted_contract`,
`DashboardIntegrationTests.test_status_projects_operational_records_to_allowlisted_fields`,
`DashboardIntegrationTests.test_admin_api_token_response_uses_metadata_only_allowlist`,
`DashboardIntegrationTests.test_admin_session_response_fields_are_capability_gated_at_http_boundary`,
`DashboardIntegrationTests.test_user_list_api_drops_unapproved_routeros_fields`,
`DashboardIntegrationTests.test_service_health_response_projects_exact_allowlisted_fields`,
`DashboardIntegrationTests.test_policy_template_api_projects_storage_records_to_allowlisted_fields`,
`DashboardIntegrationTests.test_observability_api_tokens_filter_audit_and_session_rows` (all non-empty scope combinations and adversarial query variants),
`DashboardIntegrationTests.test_setup_preflight_projects_allowlisted_schema_and_omits_inventory_secrets`,
and `DashboardIntegrationTests.test_sensitive_exports_disclose_their_real_data_scope`.
This inventory supplements, but does not replace, the broader independent
handler/field review and deployment checks listed below.

For `/api/status`, the nested `users[]` field contract is `id`, `name`,
`profile`, `comment`, `disabled`, `email`, `controls`, `tags`, and `template`;
`controls` is restricted to `vpn_user`, `policy`, `expires_at`,
`max_sessions`, `rate_limit_kbps`, `dns_mode`, `notifications`, `quota_mb`,
`schedule`, `enforcement_state`, `updated_at`, and `quota_used_bytes`;
`template` is restricted to `id`, `name`, `group_name`, and `overrides`.

The `N/A` entries are limited to the stated product boundary; they are not
claims that an external proxy, RouterOS, or the whole deployment satisfies
those controls. The gaps and external checks above remain open acceptance work.

## Evidence map

The V7 references follow the [OWASP ASVS 5.0.0 session-management requirements](https://github.com/OWASP/ASVS/blob/v5.0.0_release/5.0/en/0x16-V7-Session-Management.md). Authorization controls use [ASVS 5.0.0 V8](https://github.com/OWASP/ASVS/blob/v5.0.0_release/5.0/en/0x17-V8-Authorization.md); the WebSocket origin control is [V4.4.2](https://github.com/OWASP/ASVS/blob/v5.0.0_release/5.0/en/0x13-V4-API-and-Web-Service.md#v44-websocket). These references are version-qualified because control identifiers differ across ASVS versions.

| ASVS 5.0.0 requirement | In-scope implementation | Automated evidence | Result / limit |
| --- | --- | --- | --- |
| V3.5.1 | Login, reauthentication, logout, non-GET API dispatches, SSE, Socket.IO polling, and ASGI Socket.IO reject disallowed or duplicate origin evidence before protected work or dispatch. The exhaustive API mutation matrix also rejects a valid CSRF token paired with a foreign Origin without RouterOS or non-audit state mutation. | `tests/test_app.py::DashboardIntegrationTests.test_login_rejects_duplicate_origin_and_fallback_referer_headers`; `tests/test_app.py::DashboardIntegrationTests.test_logout_rejects_duplicate_origin_headers_even_with_valid_csrf_token`; `tests/test_app.py::DashboardIntegrationTests.test_socketio_polling_rejects_duplicate_origins_before_dispatch`; `tests/test_app.py::DashboardIntegrationTests.test_sse_rejects_duplicate_origins_before_router_fetch`; `tests/test_app.py::DashboardIntegrationTests.test_api_dispatch_has_exhaustive_role_capability_inventory`; `tests/test_asgi_contract.py::ASGIContractTests.test_socketio_asgi_rejects_duplicate_origins_for_http_and_websocket` | Repository regressions only; reverse-proxy normalization and deployed behavior remain unverified, as does independent review. |
| V4.4.2 | Engine.IO retains same-origin validation for polling; duplicate Origin fields are rejected before polling dispatch and at the ASGI HTTP/WebSocket boundaries. Foreign origins are rejected at both ASGI handshake types. | `tests/test_app.py::DashboardIntegrationTests.test_socketio_polling_rejects_foreign_origin_before_handshake`; `tests/test_app.py::DashboardIntegrationTests.test_socketio_polling_rejects_duplicate_origins_before_dispatch`; `tests/test_asgi_contract.py::ASGIContractTests.test_socketio_asgi_rejects_foreign_origin_at_http_handshake`; `tests/test_asgi_contract.py::ASGIContractTests.test_socketio_asgi_rejects_foreign_origin_at_websocket_handshake`; `tests/test_asgi_contract.py::ASGIContractTests.test_socketio_asgi_rejects_duplicate_origins_for_http_and_websocket` | Repository tests only; deployed proxy behavior remains unverified. |
| V7.1.2 | `SessionStore` atomically limits each case-insensitive RouterOS username to eight active sessions per application process. At the limit, a valid login receives HTTP 429; no existing session is revoked, and the login page directs the operator to sign out/revoke an existing session or wait for expiry. | `tests/test_security.py::test_session_limit_is_per_account_and_expired_sessions_free_a_slot`; `tests/test_security.py::test_session_limit_must_be_positive`; `tests/test_app.py::DashboardIntegrationTests.test_login_denies_valid_account_at_concurrent_session_limit` | The bound is process-local, consistent with the current single-container session store; it is not a distributed limit for multi-instance deployments. Eight is a generous single-router operator allowance while bounding session accumulation. Admission refuses the new session rather than unexpectedly terminating an active operator session. |
| V7.2.1, V7.2.2, V7.2.3 | Backend `SessionStore` validates opaque, CSPRNG-generated reference tokens. | `tests/test_security.py::test_session_tokens_are_fresh_csprng_reference_values`; `tests/test_app.py::test_login_health_and_authentication_boundaries` | Covered by unit/in-process tests; no external security assessment. |
| V7.2.4 | Successful RouterOS-password reauthentication rotates the opaque dashboard session token and CSRF token; the prior session token is invalidated. Session removal on expiry, purge, revoke, or replacement clears the removed object's password, CSRF token, and internal telemetry authorization reference. The Binary API supervisor polls that reference while listening, closes the RouterOS connection when the source session is no longer valid, and serializes gateway event dispatch against session removal. Persistence of snapshot history happens after the atomic dispatch. | `tests/test_app.py::DashboardIntegrationTests.test_reauthentication_rotates_cookie_csrf_and_uses_current_routeros_capabilities`; `tests/test_app.py::DashboardIntegrationTests.test_socketio_stream_stops_after_session_reauthentication_rotates_cookie`; `tests/test_security.py::SecurityTests.test_session_reauthentication_rotates_tokens_atomically_at_account_limit`; `tests/test_security.py::SecurityTests.test_session_purge_expires_at_idle_and_absolute_boundaries`; `tests/test_security.py::SecurityTests.test_session_snapshot_is_safe_and_revoke_is_scoped`; `tests/test_security.py::SecurityTests.test_telemetry_dispatch_is_atomic_with_session_revocation`; `tests/test_security.py::SecurityTests.test_telemetry_dispatch_rechecks_expiry_after_waiting_for_store_lock`; `tests/test_telemetry_supervisor.py::TelemetrySupervisorTests.test_idle_stream_connection_closes_when_source_session_is_revoked`; `tests/test_routeros_binary.py::RouterOSBinaryCodecTests.test_concurrent_close_does_not_race_reader_state` | Covered by application integration and store/supervisor/transport tests; watcher polling is bounded by its configured 1-second interval, although scheduler delay may add latency. Field clearing drops references but is not secure erasure; there is no external security assessment. |
| V7.3.1, V7.3.2 | 30-minute idle and 8-hour absolute lifetime defaults; expiry enforced by both wall and monotonic elapsed time in `SessionStore.get`. Live-stream revalidation and automatic status/certificate-settings polling do not refresh the idle timer. | `tests/test_security.py::test_session_idle_and_absolute_expiry`; `tests/test_security.py::test_session_timeouts_use_monotonic_time_when_wall_clock_moves_backward`; `tests/test_security.py::test_session_activity_resets_monotonic_idle_deadline`; `tests/test_security.py::test_session_snapshot_countdowns_use_monotonic_time`; `tests/test_security.py::test_session_snapshot_preserves_explicit_wall_clock_injection`; `tests/test_security.py::test_role_revalidation_does_not_return_a_session_expired_during_lookup`; `tests/test_security.py::test_read_only_session_revalidation_does_not_extend_idle_timeout`; `tests/test_app.py::DashboardIntegrationTests.test_automatic_dashboard_polls_do_not_extend_or_revive_idle_session`; `tests/test_asgi_contract.py::test_expired_live_session_is_disconnected_without_emitting_telemetry`; `tests/test_asgi_contract.py::test_live_pump_rechecks_capabilities_on_the_current_session` | Covered in deterministic/in-process tests; production timeout behavior not observed in this change. |
| V7.4.1 | Logout destroys the server-side session; the active Socket.IO pump serializes emissions with invalidation. Threaded SSE checks Origin before RouterOS I/O and holds the shared session lock through its socket write; the ASGI adapter repeats authorization at the external SSE body-send boundary and drains cancelled sends before unlock. The optional threaded polling bridge applies the same gate to GET packet writes. The native Socket.IO ASGI send wrapper revalidates WebSocket frames and polling bodies at the external transport boundary, suppressing queued packets after revocation. Native Socket.IO `telemetry.subscribe` protocol version 2 returns an empty `frames` list; clients receive telemetry through pushed event frames only, and version-1 replay-ack clients must migrate to event handlers. ASGI body, terminal, and error sends and threaded writes are bounded. Duplicate Cookie header parsing matches the wrapped handler. | `tests/test_app.py::DashboardIntegrationTests.test_sse_serializes_final_frame_with_session_revocation`; `tests/test_app.py::DashboardIntegrationTests.test_socketio_poll_suppresses_packet_if_session_is_revoked_before_http_write`; `tests/test_asgi_contract.py::test_http_adapter_wires_live_route_to_asgi_send_gate`; `tests/test_asgi_contract.py::test_asgi_cookie_selection_matches_http_handler_for_duplicate_headers`; `tests/test_asgi_contract.py::test_asgi_live_body_serializes_revocation_with_actual_send`; `tests/test_asgi_contract.py::test_asgi_live_body_drains_cancelled_send_before_releasing_session_lock`; `tests/test_asgi_contract.py::test_asgi_live_send_timeout_cancels_child_before_releasing_session_lock`; `tests/test_asgi_contract.py::test_asgi_live_send_failure_aborts_without_terminal_body_send`; `tests/test_asgi_contract.py::test_asgi_live_terminal_send_timeout_cancels_denied_and_eof_sends`; `tests/test_asgi_contract.py::test_asgi_live_error_responses_bound_start_and_body_sends`; `tests/test_asgi_contract.py::test_threaded_live_write_timeout_unblocks_session_revocation`; `tests/test_asgi_contract.py::test_socketio_websocket_send_gate_withholds_queued_frame_after_revocation`; `tests/test_asgi_contract.py::test_socketio_polling_send_gate_withholds_queued_frame_after_revocation`; `tests/test_asgi_contract.py::test_socketio_subscribe_stops_a_polled_batch_when_capability_is_revoked` | Deterministic tests cover direct threaded writes, real ASGI SSE routing, native WebSocket and polling send-boundary gating, a concurrent revoke waiting for awaited send completion, withholding of queued payloads after revocation, duplicate-header identity, and cancellation/timeout draining before lock release. These tests do not prove browser receipt or deployed proxy/router behavior. |
| V7.4.5 | Capability-protected session inventory and revocation endpoints; current session cannot revoke itself. | `tests/test_app.py::test_auth_audit_events_are_detailed_but_secret_free`; `tests/test_security.py::test_session_snapshot_is_safe_and_revoke_is_scoped`; `tests/test_app.py::DashboardIntegrationTests.test_read_only_role_cannot_cross_audit_or_mutation_capability_boundaries` | Curated negative tests cover audit/token reads and sensitive mutations for read-only sessions; not an independent authorization review. |
| V7.5.2 | Session inventory is available to authorized operators; revoking another administrator session requires a fresh RouterOS password verification for the current account, is rate-limited on failure, and never records the password. | `tests/test_app.py::DashboardIntegrationTests.test_admin_session_revocation_is_csrf_protected_scoped_and_audited`; `tests/test_app.py::DashboardIntegrationTests.test_admin_session_reauthentication_is_rate_limited`; rendered live-session revocation regression in `browser-tests/realtime-recovery.spec.js` | Application behavior is regression-tested. This does not constitute the independent security review or verify deployment-side authentication/proxy behavior. |
| V7.5.1 | N/A for the current product boundary: dashboard operator authentication/recovery attributes are not editable in the app; VPN-user profile lifecycle is a separate RouterOS identity domain. | — | Reassess if the app adds operator-account email, phone, MFA, or recovery-attribute management. |
| V7.5.3 | Fresh RouterOS-password verification protects revoking another dashboard session; creating/revoking API tokens additionally requires server-verified reauthentication within five minutes. Other high-impact RouterOS mutations use intent-bound review receipts, not fresh-password step-up. | `tests/test_app.py::DashboardIntegrationTests.test_admin_session_revocation_is_csrf_protected_scoped_and_audited`; `tests/test_app.py::DashboardIntegrationTests.test_admin_session_reauthentication_is_rate_limited`; `tests/test_app.py::DashboardIntegrationTests.test_api_token_mutations_require_fresh_routeros_reauthentication`; `browser-tests/session-reauth.spec.js` | Token step-up has application-level integration/browser evidence. The broader risk assessment is in the high-impact action inventory; other action classes, deployed proxy behavior, and independent security review remain open. |
| V8 authorization (role/capability boundary); V4.4.2 WebSocket Origin validation | Explicit role capability matrix; API-token scopes are enforced on connection/usage exports and the combined compliance export; unknown roles default to read-only; telemetry principal contains authorization facts, not the session object. Socket.IO retains python-engineio's default same-origin validation and re-derives authorization from the current server-side session on reconnect. New and repeated namespace connects force a fresh RouterOS role lookup; connect, subscription/poll, and live pump checks all use bounded worker-thread execution (four concurrent checks per process, fail-closed on saturation). Already-open streams periodically revalidate using a 15-second cache measured with a monotonic clock, so wall-clock stalls or corrections cannot extend cache freshness. SSE separately rejects a supplied foreign Origin before RouterOS reads; this is an application safeguard, not a WebSocket control. RouterOS-backed sessions re-check the account's enabled state and group-derived role on authenticated requests and live SSE/Socket.IO authorization checks. A downgrade takes effect on the existing session; an increase requires a fresh login; a missing/disabled account or failed RouterOS role lookup revokes the session. | `tests/test_security.py::test_dashboard_role_capability_matrix_fails_closed`; `tests/test_security.py::test_every_role_matches_the_complete_declared_capability_set`; `tests/test_app.py::DashboardIntegrationTests.test_role_capability_denials_precede_every_guarded_route_family`; `tests/test_app.py::DashboardIntegrationTests.test_sse_rejects_foreign_origin_before_router_fetch`; `tests/test_app.py::DashboardIntegrationTests.test_socketio_stream_revalidates_routeros_role_change_on_real_session`; `tests/test_security.py::test_routeros_role_revalidation_downgrades_without_extending_idle_lifetime`; `tests/test_security.py::test_routeros_role_revalidation_never_elevates_an_existing_session`; `tests/test_security.py::test_routeros_role_revalidation_treats_clock_rollback_as_stale`; `tests/test_security.py::test_role_cache_expires_when_wall_clock_stalls`; `tests/test_security.py::test_routeros_role_revalidation_revokes_missing_or_incomparable_identity`; `tests/test_security.py::test_routeros_role_lookup_error_revokes_session`; `tests/test_routeros.py::RouterOSClientTests.test_admin_role_lookup_fails_closed_for_unknown_disabled_or_unavailable_accounts`; `tests/test_app.py::DashboardIntegrationTests.test_routeros_role_lookup_failure_revokes_session_before_admin_sessions_response`; `tests/test_app.py::DashboardIntegrationTests.test_socketio_stream_revokes_session_when_routeros_role_lookup_fails`; `tests/test_app.py::DashboardIntegrationTests.test_routeros_group_downgrade_takes_effect_on_existing_dashboard_session`; `tests/test_app.py::DashboardIntegrationTests.test_disabled_routeros_account_revokes_existing_live_session`; `tests/test_app.py::DashboardIntegrationTests.test_read_only_role_cannot_cross_audit_or_mutation_capability_boundaries`; `tests/test_app.py::DashboardIntegrationTests.test_enterprise_foundations_are_scoped_and_read_only_where_expected`; `tests/test_asgi_contract.py::test_live_pump_rechecks_capabilities_on_the_current_session`; `tests/test_asgi_contract.py::test_socketio_reconnect_uses_current_server_session_capabilities`; `tests/test_asgi_contract.py::test_socketio_connection_forces_routeros_revalidation_with_warm_cache`; `tests/test_asgi_contract.py::test_socketio_connect_runs_role_lookup_off_loop_and_fails_closed_at_capacity`; `tests/test_asgi_contract.py::test_socketio_cancelled_connect_keeps_role_check_slot_until_worker_finishes`; `tests/test_asgi_contract.py::test_socketio_subscription_and_pump_revalidate_off_loop`; `tests/test_asgi_contract.py::test_socketio_does_not_disable_engineio_same_origin_validation`; `tests/test_asgi_contract.py::test_socketio_asgi_rejects_foreign_origin_at_http_handshake`; `tests/test_asgi_contract.py::test_socketio_asgi_rejects_foreign_origin_at_websocket_handshake` | All five role grants are locked against the complete declared capability set, including fail-closed checks for non-owner roles and the owner's intentional wildcard. Every current API dispatch form is bound to the role/capability inventory; the declared role gates are exercised across all five dashboard roles, and nine high-impact route families have 23 denied pairings tested with valid CSRF and no RouterOS mutation requests. The scoped-token matrix classifies all current literal GET API dispatch forms and checks each grantable scope combination, while new regex GET routes fail until classified. This is not an exhaustive query/resource-state cross-product or independent authorization review. `/dashboard` omits audit rows and Change History navigation without `audit.read`; `/api/observability` requires `health.read` and conditionally includes audit/session fields for `audit.read` / `sessions.read`. Session-history exports require `sessions.read`, and compliance export requires both `audit.read` and `sessions.read`. Safe plans/diagnostics are explicitly distinguished from mutations. The 15-second recheck is a repository behavior, not measured physical-router revocation latency; deployed proxy origin behavior remains unverified. |

`tests/test_asgi_contract.py::test_native_websocket_revalidates_routeros_role_change_and_account_disable`
is a loopback integration test of the active ASGI Socket.IO WebSocket app. It
uses a deterministic RouterOS role resolver to verify that an owner-to-read-only
downgrade keeps only the still-authorized session stream, then an account-disable
result closes the stream and rejects reconnect. This is not a physical-router
or deployed-proxy observation.

The Binary API session stream and interface sampler also enforce the source
dashboard session. Regression tests verify refusal of the exact RouterOS
credential pair after source-session revocation, closure before publishing
session events or reconciled snapshots, and suppression of a counter sample when
authorization is revoked after the read. A separate recovery test verifies that
a transient stream failure reconnects with a full snapshot before resuming
events. Evidence: `tests/test_telemetry_runtime.py::test_binary_credentials_are_refused_after_source_session_revocation`,
`tests/test_telemetry_runtime.py::TelemetryRuntimeFreshnessTests.test_live_stream_role_downgrade_is_applied_at_15_second_cache_deadline`,
`tests/test_telemetry_supervisor.py::test_revoked_source_session_blocks_event_publish_and_closes_connection`,
`tests/test_telemetry_supervisor.py::test_revoked_source_session_blocks_snapshot_reconciliation_publish`,
`tests/test_telemetry_supervisor.py::test_sampler_revocation_after_read_does_not_mark_sample_fresh_or_publish`,
and `tests/test_telemetry_supervisor.py::test_transient_stream_failure_reconnects_snapshots_then_resumes_events`.
The cache-boundary test uses a deterministic role resolver to prove that a role
downgrade becomes effective on the first authorization check at the 15-second
boundary; it does not simulate or measure RouterOS/network response time. These
are repository tests, not physical-router revocation-latency or deployed-session
evidence.

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

## Repository revalidation — 2026-10-14

At source commit `213ff6a155bb9bacce74c06797ff9473f95a432c`, the following
focused suites passed locally:

- `python -m unittest tests.test_asgi_contract` — 28 tests passed.
- `python -m unittest tests.test_security` — 42 tests passed.
- Five targeted `DashboardIntegrationTests` for CSRF-safe logout, SSE revocation
  and reconnect, Socket.IO revocation, and RouterOS role-change revalidation —
  all passed.
- `python -m unittest tests.test_app.DevicePostureTests tests.test_app.CertificateExpiryParsingTests`
  — 4 tests passed.
- `python -m unittest tests.test_routeros` — 36 tests passed.

These are repository-level results only. No live RouterOS, public-proxy,
Cloudflare Access, host-memory, or deployed-log checks were performed in this
run. The external items below therefore remain **NOT VERIFIED**; this update
does not claim production acceptance or close issue #200.

### Post-merge revalidation — PR #755 — 2026-10-15

PR [#755](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/755)
merged as `f16fe17cc2251939bcdfc10eeb26e8c0be85e9c1`. Its merged tree is
identical to the tested PR head `389da14e65423c6e9a1206375867493835e3f590`.
The local full unittest suite passed with 760 tests and 14 optional skips.
Hosted PR checks
[#38818742230](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/38818742230)
completed successfully, including Python 3.13/3.14, security and Redis
recovery checks, rendered browser/accessibility tests, and ARM64 image smoke.
The subsequent published-runtime and artifact evidence is recorded in
[`RELEASES.md`](RELEASES.md).

This establishes repository and build evidence for the tested source tree only.
It does not establish deployed proxy/session behavior, physical RouterOS
permissions, host-memory or external-log exposure, or a formal credential-memory
risk decision. Issue #200 remains open for those operational and independent
review gates.

### Post-merge revalidation — PR #720 — 2026-10-14

PR [#720](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/720)
merged as `6dd53022523766a5371628dfe158286072494bf4`. It serializes authorized
Socket.IO live telemetry delivery with session invalidation, covering the
logout, revocation, rotation, expiry, purge, and bulk-logout races addressed
by the change. Publisher run
[#38620869138](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/38620869138)
completed with every job successful, including rendered browser/accessibility
checks, ARM64 and AMD64 image publication, attestation verification, runtime
smoke tests, and stable-manifest publication. The immutable image digests are
listed in [`RELEASES.md`](RELEASES.md).

This is merged-source and CI evidence only. It does not establish deployment on
RouterOS, live proxy/session behavior, physical-router revocation latency, or
full ASVS conformance; issue #200 and its live acceptance gates remain open.

## Security design notes and residual risks

- RouterOS remains the identity and credential authority. After successful
  dashboard login, the application retains the RouterOS username/password in
  process memory for authenticated router operations. Passwords are not
  written to the dashboard session inventory or telemetry principal, and the
  session dataclass excludes both the password and CSRF token from its default
  representation to reduce accidental debug/log disclosure. The low-level
  `RouterOSCredentials` value object also excludes its password from its
  default representation. Session IDs, source addresses, and user-agent values
  are also excluded from the session's default representation. When a session
  expires, is revoked, or is replaced, the session object's password and CSRF
  token fields are cleared to drop those references if the object is retained.
  The long-lived Binary API telemetry supervisor receives a credential lease
  only for connection authentication, clears the lease's password field after
  the connect call, and checks subsequent stream authorization using an opaque
  random internal reference to the still-active dashboard session. The
  reference is security-sensitive process state and must not be logged or
  exposed in metrics, telemetry, or client responses. This limits the
  supervisor's own retained credential references; RouterOS request handling,
  the authenticated dashboard session, in-flight calls, and the Python
  allocator may still retain copies while needed.
  These safeguards reduce accidental debug/log disclosure and shorten the
  application's references; they are not secure erasure. The credential
  still exists as a Python string in process memory while needed, and copies
  held by in-flight operations or allocator pages may remain: process dumps, host
  compromise, or application-level memory disclosure could expose it, and
  Python string handling cannot provide reliable secure erasure. The current
  RouterOS API integration requires reusable credentials; replacing that
  model needs a RouterOS-supported alternative and is not solved here.
  **Risk decision status: unresolved.** The repository records this trade-off
  but contains no named risk owner, formal acceptance, or review date; deployment
  or continued use must not be interpreted as risk acceptance. Revisit before
  making any compliance claim and whenever the RouterOS authentication model,
  container privilege, process-dump policy, or credential lifecycle changes.
- Browser sessions are process-local and reference-token based. Restarting the
  app invalidates them. Multi-instance session sharing is not in scope.
- Creating or deleting shared saved views requires both a valid CSRF token and
  `sessions.read`; regression coverage verifies denied writes leave the saved
  view store unchanged.
- Routine dashboard role checks use a 15-second revalidation interval. Each
  HTTP request that can disclose `audit.read` data forces a fresh RouterOS role
  check once per request, so a warm auditor session cannot retain audit access
  after a downgrade. Binary API telemetry workers use a separate five-second
  role revalidation interval and require the exact credential pair to remain backed
  by an active RouterOS dashboard session before accepting or publishing
  snapshots, session events, or traffic samples. The upstream socket has a
  10-second read timeout, which bounds how long an idle listen can remain open
  before it observes revocation; this is not instantaneous physical-device
  enforcement. A failed role lookup revokes the dashboard session; stale
  read-only access would still authorize telemetry and is therefore not kept.
  A RouterOS-reported missing/disabled account also revokes it.
- Browser session cookies are emitted with `Secure`, `HttpOnly`, and
  `SameSite=Strict`; state-changing routes use CSRF validation. These code-level
  facts do not establish correct reverse-proxy/TLS behavior in the deployed
  environment.
- Automated live-stream evidence covers the native ASGI Socket.IO WebSocket
  transport in a loopback integration test: an authenticated client receives a
  telemetry frame; revocation, expiry, or removal of `sessions.read` closes the
  active namespace; and reconnect after revocation/expiry is rejected. A
  repeated namespace-connect regression verifies that a revoked bound session is
  rejected with a Socket.IO `CONNECT_ERROR` and removed from the server manager.
  Exact idle/absolute expiry equality is also covered across lookup, rotation,
  and purge. Separate
  ASGI handshake tests reject foreign HTTP and WebSocket origins. CI installs
  the pinned runtime dependencies before the test suite, so these checks run
  rather than silently skipping there. A separate Playwright regression verifies
  that a local browser's EventSource reconnect receives HTTP 401 after an
  administrator revokes its session and emits no further telemetry frames; this
  does not exercise the deployed proxy or a physical router. The
  application leaves python-engineio origin handling enabled; an empty
  allowed-origin list would disable that check and is intentionally not used.
- Binary API supervisor and sampler tests also verify source-session revocation
  across connection setup, snapshot recovery, session-event delivery, and
  counter sampling. These deterministic checks establish code behavior only;
  they do not establish live-router revocation timing or deployed telemetry
  behavior.
- The legacy Socket.IO polling bridge also compares a supplied `Origin` with
  the configured `PUBLIC_ORIGIN` on handshake/poll requests and requires an
  exact configured origin on POST. GET without `Origin` remains supported for
  clients that omit it; such requests still require the session-bound bridge
  identity. HTTP-dispatch regression tests verify foreign-origin GET/POST
  requests are denied before bridge methods run. This repository evidence does
  not establish behavior at the deployed reverse proxy.
- The SSE endpoint has a bounded response loop and requires an authenticated
  RouterOS session with `sessions.read` at entry. Its initial session lookup
  and subsequent stream revalidation do not refresh the idle timestamp; other
  authenticated dashboard requests retain their normal activity semantics.
  It checks the same server-side session and capability before each telemetry
  write. When an `Origin` header is supplied, it now must match the
  configured dashboard origin before SSE performs RouterOS reads; clients that
  omit the header still face the same session/capability checks. A loopback
  integration regression also verifies an active SSE stream revalidates an
  owner-to-read-only RouterOS role change while continuing the `sessions.read`
  stream that the downgraded role is still authorized to receive. The local
  Playwright reconnect check above does not establish behavior through the
  deployed reverse proxy or revocation timing on a physical router.
- The ASGI HTTP adapter shares the existing 64 KiB request-body bound. It rejects
  an oversized declared `Content-Length` before reading and enforces the same cap
  over actual ASGI chunks, including requests with malformed or absent length
  metadata. Overflow returns HTTP 413; HTTP/1.0 and HTTP/1.1 responses close the
  connection rather than draining an unbounded unread body. Boundary, duplicate
  header, streamed overflow, and pinned-Uvicorn connection-close regressions are
  in `tests/test_asgi_contract.py`. This is repository-level availability
  hardening, not an additional ASVS conformance claim; reverse-proxy and
  deployed-server request limits still require operational verification.

## RouterOS error redaction — 2026-10-15

- RouterOS REST error bodies and transport exception strings are not included in
  `RouterOSError` messages returned by authenticated API routes. The HTTP status
  and typed timeout/TLS classification remain available, while response
  `detail`/`message` text, private endpoint names, and transport-specific
  diagnostics are discarded. Synthetic regressions cover both upstream JSON
  error fields and TLS, timeout, and host/IP-bearing transport failures.

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

This public document contains no live-router, proxy, or operator-session
observations. Repository tests establish only the behaviors they exercise; they
do not verify the deployed access-control policy, reverse-proxy routing, TLS
termination, live session state, or RouterOS permissions. Keep any such
deployment evidence in operator-controlled storage.

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
