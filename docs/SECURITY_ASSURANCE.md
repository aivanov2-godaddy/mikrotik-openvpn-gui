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

## Contextual inputs used in application decisions

For login and RouterOS-password reauthentication throttling, the application
uses the resolved client IP as the limiter identity and the timestamps of
failed credential checks within a rolling 300-second window. The default
policy admits at most five attempts for one resolved IP in that window,
including in-flight checks; further checks are denied with HTTP 429 while the
limit is reached. A verified success clears that IP's failure history, while
a RouterOS availability failure releases its reservation without counting as
a bad credential. Client-IP resolution uses the transport peer unless a
forwarded header is explicitly trusted from the configured proxy peer; see
[EXPOSURE.md](EXPOSURE.md) for the forwarded-header trust rules. The application
also evaluates browser `Origin` and, only in the documented absent/opaque-origin
cases, `Referer` for login, CSRF-protected writes, and live-stream origin
boundaries. The route-specific rules and fail-closed cases are documented in
[ROUTE_AUTHORIZATION.md](ROUTE_AUTHORIZATION.md). The application does not use
geolocation, time of day, device posture, browser fingerprint, or behavioral
scoring for authentication or authorization decisions. The separate Cloudflare
Access policy is outside repository control and has not been verified as part
of this matrix. Session idle and absolute timeouts are documented separately
in [SESSION_LIFETIME_RATIONALE.md](SESSION_LIFETIME_RATIONALE.md).

| ASVS 5.0.0 control | Status | Scoped finding and evidence |
| --- | --- | --- |
| V3.3.1 | TESTED | The dashboard session cookie uses the `__Host-` prefix and `Secure`. `tests/test_app.py::DashboardIntegrationTests.test_login_session_cookie_has_required_host_security_and_size_properties` asserts those attributes. This is repository evidence, not deployed-proxy evidence. |
| V3.3.2 | TESTED | `SameSite=Strict` is set on session cookie creation, rotation, and deletion; `tests/test_app.py::DashboardIntegrationTests.test_login_session_cookie_has_required_host_security_and_size_properties` and `tests/test_app.py::DashboardIntegrationTests.test_reauthentication_rotates_cookie_csrf_and_uses_current_routeros_capabilities` assert it. |
| V3.3.3 | TESTED | Session cookies use `__Host-`, `Path=/`, and no `Domain` attribute; `tests/test_app.py::DashboardIntegrationTests.test_login_session_cookie_has_required_host_security_and_size_properties` asserts these required host-only properties. `tests/test_app.py::DashboardIntegrationTests.test_legacy_unprefixed_session_cookie_is_not_accepted` rejects the previous unprefixed cookie name. |
| V3.3.4 | TESTED | The cookie bearer is returned only in `Set-Cookie`, not in session inventory JSON. Session-management views expose a separately generated, non-authenticating revocation reference. `tests/test_app.py::DashboardIntegrationTests.test_admin_session_response_fields_are_capability_gated_at_http_boundary` verifies that the reference cannot authenticate as a session cookie; `tests/test_app.py::DashboardIntegrationTests.test_admin_session_revocation_reference_projection_matches_all_routeros_roles` verifies cookie bearers are absent from inventory for every RouterOS role. |
| V3.3.5 | TESTED | The issued session-cookie name/value pair is bounded below 4096 bytes in `tests/test_app.py::DashboardIntegrationTests.test_login_session_cookie_has_required_host_security_and_size_properties`. |
| V3.5.1 | PARTIAL | Every current non-GET API dispatch is tested with a valid browser CSRF token and a foreign `Origin`, and with a forged token plus the configured same-origin value; both must be denied without RouterOS mutations or non-audit persistent-state changes. Logout has valid-token foreign/duplicate-Origin and duplicate-CSRF-header regressions. Explicit foreign or duplicate `Origin` values and duplicate `X-CSRF-Token` fields are rejected centrally by `_require_csrf`; the ASGI adapter preserves repeated Origin and CSRF fields for that check (`tests/test_asgi_contract.py::ASGIContractTests.test_http_adapter_preserves_duplicate_origin_and_csrf_fields_for_handler`). Opaque `Origin: null` is accepted only with a same-origin `Referer`, and a missing `Origin` is accepted only with a valid CSRF token (reauthentication also requires same-origin Referer evidence when Origin is absent). Login rejects duplicate Origin fields and duplicate fallback Referer fields. Deployed proxy behavior and independent review remain outstanding. |
| V7.1.1 | PARTIAL | The 30-minute idle and 8-hour absolute defaults have a documented risk rationale. Session expiry checks use monotonic elapsed time so backward wall-clock corrections cannot extend process-local sessions; deterministic regressions cover rollback and activity-based idle reset. Independent validation remains outstanding. |
| V7.1.2 | TESTED | At most eight active dashboard sessions are allowed per RouterOS account in this single-process deployment. A valid login above the limit is denied with HTTP 429 and recovery guidance; existing sessions are never evicted. Idle and absolute expiry are enforced at the exact deadline (`>=`) by session lookup, rotation, and purge tests; expired sessions are purged before admission. Client-aware rate limiting trusts forwarded addresses only from an exact configured proxy peer; `X-Forwarded-For` is resolved right-to-left across valid addresses while skipping configured proxy hops, and malformed chains or multi-valued single-address headers fall back to the transport peer. `ProxyTrustTests` cover spoofed prefixes, duplicate header fields, malformed/all-trusted chains, and untrusted peers. ASGI tests verify original-peer propagation, that Uvicorn address rewriting is disabled, that the configured Cloudflare client header wins over a conflicting XFF value, and that only an exact trusted peer can set the HTTP/WebSocket scheme. Deployed proxy sanitization remains an external check. |
| V7.1.3 | EXTERNAL | Cloudflare Access is an independent edge-authentication layer; its session lifetime/termination relationship to the app session has not been verified from deployment configuration. |
| V7.2.1–V7.2.3 | TESTED | Backend reference-session validation and CSPRNG token generation are covered by `test_session_tokens_are_fresh_csprng_reference_values` and login-boundary tests. |
| V7.2.4 | TESTED | A CSRF- and same-origin-protected re-authentication endpoint verifies the current account's RouterOS password, derives its current RouterOS group role, then atomically replaces the in-memory session and CSRF tokens and revokes the old reference. Failed verification leaves the session unchanged and uses the existing login rate limiter; no second password store is introduced. Session-store and integration tests cover rotation at the account session limit, old-cookie API rejection, current-capability enforcement, and stopping active SSE/Socket.IO delivery. This is deterministic repository evidence only; deployed proxy/router behavior and independent review remain unverified. |
| V7.3.1–V7.3.2 | PARTIAL | The 30-minute idle and 8-hour absolute defaults, documented rationale, and in-process expiry/live-delivery behavior are tested, including equality at both expiry deadlines, backward wall-clock correction, and expiry during RouterOS role lookup. Monotonic checks prevent clock rollback from extending a process-local session and keep the displayed timeout countdowns aligned with enforcement. Automatic dashboard status and certificate-settings polling do not refresh or revive an expired idle session. Production/proxy timing and Cloudflare Access coordination remain unverified. |
| V7.4.1 | TESTED | Logout, expiry, and server-side revocation stop subsequent session use and live delivery in deterministic tests. A loopback active-ASGI WebSocket test covers role downgrade, account disable, stream closure, and rejected reconnect. SSE reconnect rejects revoked/expired sessions before RouterOS reads; the threaded handler serializes writes, and the ASGI adapter holds the same session lock through the actual awaited SSE body send. The optional threaded polling bridge also gates its successful GET packet write. The native Socket.IO ASGI boundary revalidates WebSocket frames and polling bodies at actual sends, so packets queued before revocation are withheld if not yet sent. Native Socket.IO `telemetry.subscribe` uses protocol version 2: acknowledgements return an empty `frames` list and telemetry is delivered only as pushed event frames, avoiding a second unguarded copy. Clients that consumed replay frames from version-1 acknowledgements must migrate to event handlers. ASGI body and terminal SSE sends and threaded body writes have bounded timeouts; cancelled ASGI sends are drained before unlocking. Duplicate Cookie headers are resolved identically by the adapter and handler. The ordering is at server-side send completion; already accepted network bytes cannot be recalled, and this is not deployed-router timing evidence. |
| V7.4.2 | PARTIAL | A disabled or missing RouterOS account is detected when an existing session is revalidated, and that session is revoked. The application does not proactively invalidate every session for the account at the instant RouterOS disables or deletes it; each other session remains subject to its own next revalidation. |
| V7.4.3 | N/A | The dashboard does not change authentication factors for its operator accounts; RouterOS credential/factor lifecycle is outside this app session-management scope. |
| V7.4.4 | TESTED | `browser-tests/operator-views.spec.js` (`shared Sign out stays visible and keyboard reachable on every operator view at 539 CSS px`) verifies visible Sign out access, viewport bounds, keyboard reachability, and visible focus across all 10 authenticated views at a narrow/zoom-equivalent width. This is rendered repository evidence; no human usability study is claimed. |
| V7.4.5 | PARTIAL | An authorized administrator can inspect sessions and revoke one selected session, covered by `DashboardIntegrationTests.test_admin_session_revocation_is_csrf_protected_scoped_and_audited`. There is no operation to terminate all sessions belonging to one user or all users, as this control requires. |
| V7.5.1 | N/A | The app does not edit authentication/recovery attributes of dashboard operator accounts. VPN-user profile edits are a separate RouterOS identity domain. |
| V7.5.2 | PARTIAL | An authorized operator can view sessions and terminate one selected session after verifying the current RouterOS password; the supplied password is not persisted and failed attempts are rate-limited. There is no terminate-all action, and the interface does not establish that each user can terminate any or all of their own sessions as the full control requires. |
| V7.5.3 | PARTIAL | Fresh RouterOS-password checks protect revoking another dashboard session and creating/revoking scoped API tokens. Token mutations require reauthentication within five minutes, enforced server-side. Other high-impact mutations use intent-bound review receipts rather than password step-up; sensitive exports use capability gates. The action-by-action assessment below is repository evidence, not independent policy approval or deployed verification; no ASVS Level 3 claim is made. |
| V7.6.1 | EXTERNAL | The app does not coordinate an IdP/RP session itself; Cloudflare Access session behavior and termination propagation require deployment evidence. |
| V7.6.2 | TESTED | `tests/test_app.py::DashboardIntegrationTests.test_login_page_uses_same_origin_referrer_policy_for_form_submission` verifies that merely loading `/login` creates no session cookie and that session creation requires submitting the explicit POST login form. `tests/test_app.py::DashboardIntegrationTests.test_login_rejects_foreign_or_missing_origin_before_routeros_authentication` covers the protected entry point. |
| V8.1.1 | PARTIAL | Function/data authorization rules and the browser logout boundary are documented in [ROUTE_AUTHORIZATION.md](ROUTE_AUTHORIZATION.md). CI now mechanically reconciles every literal/regex `/api` dispatch and `/metrics`, plus primary login, dashboard, health, and profile-share entry paths, against method-bound route families. This completeness check does not independently prove every authorization decision is correct; data-specific authorization and independent review remain outstanding. |
| V8.1.2 | PARTIAL | Capability-filtered fields and export scopes have targeted tests. Exact safe-payload projections and secret-sentinel absence are unit-tested for all nine supported telemetry events; the acceptance observer also rejects interface frames missing identity/base counters or carrying invalid cumulative counters. `test_native_websocket_preserves_telemetry_redaction_allowlists` additionally exercises connected, updated, and snapshot frames over a real loopback WebSocket. An exhaustive field-by-field authorization inventory has not been independently reviewed. |
| V8.1.3–V8.1.4 | PARTIAL | The application's contextual decisions are documented above: resolved client IP and failed-attempt timestamps drive the five-attempt/300-second login and reauthentication limit, while browser `Origin`/`Referer` values govern the documented CSRF and live-stream boundaries. Repository tests cover the limiter behavior and route-document contract. No geolocation, time-of-day, device-posture, fingerprint, or behavioral scoring is used; Cloudflare Access can apply separate edge decisions that are not verified here. |
| V8.2.1 | PARTIAL | Every current literal/regex API dispatch form is bound to a role/capability inventory, and declared gates are exercised across all five dashboard roles. Current non-GET API routes are also exercised with forged CSRF and valid-CSRF/foreign-Origin requests; query/resource-state combinations and independent review are not exhaustive. |
| V8.2.2 | PARTIAL | Resource ownership/state checks exist on sensitive mutations, but data-specific authorization has not received an exhaustive independent review. |
| V8.2.3 | PARTIAL | Selected API/export fields are capability-filtered and tested. Exact safe-payload projections and secret-sentinel absence are unit-tested for all nine supported telemetry events, including nested broker interface counters; the acceptance observer rejects incomplete or invalid cumulative counter frames, and the native WebSocket integration test checks connected, updated, and snapshot frames. An exhaustive API read/write field-level map is not available. |
| V8.2.4 | N/A | Adaptive environmental/contextual authorization is not a product feature; no Level 3 adaptive-control claim is made. |
| V8.3.1 | TESTED | Authorization is enforced server-side; client-side visibility is not the enforcement boundary. Negative route tests verify denials precede RouterOS/state mutation. |
| V8.3.2 | GAP | A RouterOS user reassignment/disable is read on a later REST request, then subject to the application's 15-second stream-role cache. Separately, the current [MikroTik REST API manual](https://manual.mikrotik.com/docs/developer-guides/rest-api/) says changes to a group's policies take effect when the REST server renews its API login, up to 10 minutes later; this documented behavior is not verified on the deployed RouterOS 7.24.5. Effective authorization on an already-open stream may therefore remain stale beyond the application's cache interval. Fresh/repeated Socket.IO connects force a role lookup but cannot invalidate a RouterOS-side cached REST login. The product has no immediate RouterOS change notification or mitigation that alerts on a now-unauthorized action and reverts it; even that mitigation would not prevent information leakage under this ASVS control. Physical-router enforcement, client receipt timing, and deployed latency remain unmeasured. |
| V8.3.3 | PARTIAL | Current RouterOS-session capabilities are re-derived for live delivery; a complete end-to-end subject-vs-intermediary authorization review remains outstanding. |
| V8.4.1 | N/A | Multi-tenant architecture is explicitly excluded from the single-router product scope. |
| V8.4.2 | PARTIAL | Application-side RouterOS role revalidation is implemented and tested. Whether a separate Cloudflare Access layer, device-posture checks, or contextual risk controls are configured is unverified deployment evidence. |
| V4.4.1 | EXTERNAL | Production HTTPS/WSS termination must be verified from deployment evidence; repository and ASGI tests do not establish the public transport, and a Socket.IO status label alone is not proof of WSS. |
| V4.4.2 | PARTIAL | WebSocket handshakes require exactly one Origin matching configured PUBLIC_ORIGIN before Engine.IO; missing, foreign, or duplicate values are rejected. HTTP polling GET may omit Origin only when exactly one same-origin Referer is present; missing, duplicate, or foreign evidence is rejected before Engine.IO SID allocation. Regression tests pin these behaviors. Deployed proxy behavior and independent full-scope review remain unverified. |
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
| `GET /api/admin/sessions` | Root: `sessions`, `idle_timeout_seconds`, `absolute_timeout_seconds`, `generated_at`. `sessions[]`: `id`, `id_hash`, `username`, `role`, `created_at`, `last_seen`, `idle_seconds`, `idle_remaining`, `absolute_remaining`, `source_address`, `user_agent`, `auth_method`, `current`. | Requires `sessions.read`; `id` is a separately generated, non-authenticating revocation reference only when the caller also has `session.manage`, otherwise `id` is empty and only the short hash of that reference is provided. The cookie bearer is never included. Revocation uses the reference only to select a target, then still requires CSRF, `session.manage`, a fresh RouterOS password check, and role revalidation; the reference is not accepted as a session cookie. RouterOS-backed sessions are force-revalidated before this sensitive projection; a failed role lookup revokes the session and returns an authentication failure, as does a missing account. Source address and user agent are sensitive operator metadata. HTTP regressions assert the exact field set, query-parameter resistance, bearer absence, reference non-authentication, warm role-downgrade redaction on API and dashboard responses, lookup-failure behavior, and a single forced role check per dashboard response. |
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
| V4.4.2 | The ASGI boundary requires exactly one WebSocket Origin matching configured PUBLIC_ORIGIN, without accepting forwarded host/proto values as its authority; Engine.IO retains its additional same-origin validation. HTTP polling GET may omit Origin only when exactly one same-origin Referer is present; absent, duplicate, or foreign evidence is rejected before SID allocation. | `tests/test_app.py::DashboardIntegrationTests.test_socketio_polling_rejects_missing_origin_and_referer_before_handshake`; `tests/test_app.py::DashboardIntegrationTests.test_socketio_polling_accepts_missing_origin_with_same_origin_referer`; `tests/test_app.py::DashboardIntegrationTests.test_socketio_polling_rejects_missing_origin_with_foreign_referer`; `tests/test_app.py::DashboardIntegrationTests.test_socketio_polling_rejects_duplicate_origins_before_dispatch`; `tests/test_asgi_contract.py::ASGIContractTests.test_socketio_asgi_rejects_originless_polling_get_without_same_origin_referer`; `tests/test_asgi_contract.py::ASGIContractTests.test_socketio_asgi_allows_originless_polling_get_with_same_origin_referer`; `tests/test_asgi_contract.py::ASGIContractTests.test_socketio_asgi_rejects_missing_origin_for_websocket_handshake_and_reconnect`; `tests/test_asgi_contract.py::ASGIContractTests.test_socketio_asgi_rejects_duplicate_origins_for_http_and_websocket` | Repository tests only; deployed proxy behavior and independent full-scope review remain unverified. |
| V8.1.1 | Route authorization documentation records public, browser-session, capability, CSRF, field-projection, and live-transport boundaries; logout's per-session behavior is explicit. | `tests/test_security_assurance_contract.py::SecurityAssuranceDocumentContractTests.test_route_document_explicitly_covers_logout_authorization`; `tests/test_security_assurance_contract.py::SecurityAssuranceDocumentContractTests.test_route_document_is_reconciled_to_security_sensitive_dispatch_forms`; `tests/test_app.py::DashboardIntegrationTests.test_api_dispatch_has_exhaustive_role_capability_inventory` | The route inventory is mechanically reconciled, but this does not independently prove every authorization decision is correct; the requirement remains partial. |
| V8.1.3–V8.1.4 | Contextual inputs are resolved client IP and failed-attempt timestamps for authentication throttling, and browser Origin/Referer for CSRF and live-stream boundaries. | `tests/test_security.py::test_rate_limit`; `tests/test_security.py::test_unavailable_completion_releases_reservation_and_preserves_failure_history`; `tests/test_app.py::DashboardIntegrationTests.test_login_rate_limit_uses_resolved_client_ip`; `tests/test_app.py::DashboardIntegrationTests.test_login_rejects_foreign_or_missing_origin_before_routeros_authentication`; `tests/test_security_assurance_contract.py::SecurityAssuranceDocumentContractTests.test_documented_contextual_login_limit_matches_runtime_defaults` | Threshold, action, and inputs are documented and regression-tested. Cloudflare Access has a separate policy that was not examined, so this is partial. |
| V7.1.2 | `SessionStore` atomically limits each case-insensitive RouterOS username to eight active sessions per application process. At the limit, a valid login receives HTTP 429; no existing session is revoked, and the login page directs the operator to sign out/revoke an existing session or wait for expiry. | `tests/test_security.py::test_session_limit_is_per_account_and_expired_sessions_free_a_slot`; `tests/test_security.py::test_session_limit_must_be_positive`; `tests/test_app.py::DashboardIntegrationTests.test_login_denies_valid_account_at_concurrent_session_limit` | The bound is process-local, consistent with the current single-container session store; it is not a distributed limit for multi-instance deployments. Eight is a generous single-router operator allowance while bounding session accumulation. Admission refuses the new session rather than unexpectedly terminating an active operator session. |
| V7.2.1, V7.2.2, V7.2.3 | Backend `SessionStore` validates opaque, CSPRNG-generated reference tokens. | `tests/test_security.py::test_session_tokens_are_fresh_csprng_reference_values`; `tests/test_app.py::test_login_health_and_authentication_boundaries` | Covered by unit/in-process tests; no external security assessment. |
| V7.2.4 | Successful RouterOS-password reauthentication rotates the opaque dashboard session token and CSRF token; the prior session token is invalidated. Session removal on expiry, purge, revoke, or replacement clears the removed object's password, CSRF token, and internal telemetry authorization reference. The Binary API supervisor polls that reference while listening, closes the RouterOS connection when the source session is no longer valid, and serializes gateway event dispatch against session removal. Persistence of snapshot history happens after the atomic dispatch. | `tests/test_app.py::DashboardIntegrationTests.test_reauthentication_rotates_cookie_csrf_and_uses_current_routeros_capabilities`; `tests/test_app.py::DashboardIntegrationTests.test_socketio_stream_stops_after_session_reauthentication_rotates_cookie`; `tests/test_security.py::SecurityTests.test_session_reauthentication_rotates_tokens_atomically_at_account_limit`; `tests/test_security.py::SecurityTests.test_session_purge_expires_at_idle_and_absolute_boundaries`; `tests/test_security.py::SecurityTests.test_session_snapshot_is_safe_and_revoke_is_scoped`; `tests/test_security.py::SecurityTests.test_telemetry_dispatch_is_atomic_with_session_revocation`; `tests/test_security.py::SecurityTests.test_telemetry_dispatch_rechecks_expiry_after_waiting_for_store_lock`; `tests/test_telemetry_supervisor.py::TelemetrySupervisorTests.test_idle_stream_connection_closes_when_source_session_is_revoked`; `tests/test_routeros_binary.py::RouterOSBinaryCodecTests.test_concurrent_close_does_not_race_reader_state` | Covered by application integration and store/supervisor/transport tests; watcher polling is bounded by its configured 1-second interval, although scheduler delay may add latency. Field clearing drops references but is not secure erasure; there is no external security assessment. |
| V7.3.1, V7.3.2 | 30-minute idle and 8-hour absolute lifetime defaults; expiry enforced by both wall and monotonic elapsed time in `SessionStore.get`. Live-stream revalidation and automatic status/certificate-settings polling do not refresh the idle timer. | `tests/test_security.py::test_session_idle_and_absolute_expiry`; `tests/test_security.py::test_session_timeouts_use_monotonic_time_when_wall_clock_moves_backward`; `tests/test_security.py::test_session_activity_resets_monotonic_idle_deadline`; `tests/test_security.py::test_session_snapshot_countdowns_use_monotonic_time`; `tests/test_security.py::test_session_snapshot_preserves_explicit_wall_clock_injection`; `tests/test_security.py::test_role_revalidation_does_not_return_a_session_expired_during_lookup`; `tests/test_security.py::test_read_only_session_revalidation_does_not_extend_idle_timeout`; `tests/test_app.py::DashboardIntegrationTests.test_automatic_dashboard_polls_do_not_extend_or_revive_idle_session`; `tests/test_asgi_contract.py::test_expired_live_session_is_disconnected_without_emitting_telemetry`; `tests/test_asgi_contract.py::test_live_pump_rechecks_capabilities_on_the_current_session` | Covered in deterministic/in-process tests; production timeout behavior not observed in this change. |
| V7.4.1 | Logout destroys the server-side session; the active Socket.IO pump serializes emissions with invalidation. Threaded SSE checks Origin before RouterOS I/O and holds the shared session lock through its socket write; the ASGI adapter repeats authorization at the external SSE body-send boundary and drains cancelled sends before unlock. The optional threaded polling bridge applies the same gate to GET packet writes. The native Socket.IO ASGI send wrapper revalidates WebSocket frames and polling bodies at the external transport boundary, suppressing queued packets after revocation. Native Socket.IO `telemetry.subscribe` protocol version 2 returns an empty `frames` list; clients receive telemetry through pushed event frames only, and version-1 replay-ack clients must migrate to event handlers. ASGI body, terminal, and error sends and threaded writes are bounded. Duplicate Cookie header parsing matches the wrapped handler. | `tests/test_app.py::DashboardIntegrationTests.test_sse_serializes_final_frame_with_session_revocation`; `tests/test_app.py::DashboardIntegrationTests.test_socketio_poll_suppresses_packet_if_session_is_revoked_before_http_write`; `tests/test_asgi_contract.py::test_http_adapter_wires_live_route_to_asgi_send_gate`; `tests/test_asgi_contract.py::test_asgi_cookie_selection_matches_http_handler_for_duplicate_headers`; `tests/test_asgi_contract.py::test_asgi_live_body_serializes_revocation_with_actual_send`; `tests/test_asgi_contract.py::test_asgi_live_body_drains_cancelled_send_before_releasing_session_lock`; `tests/test_asgi_contract.py::test_asgi_live_send_timeout_cancels_child_before_releasing_session_lock`; `tests/test_asgi_contract.py::test_asgi_live_send_failure_aborts_without_terminal_body_send`; `tests/test_asgi_contract.py::test_asgi_live_terminal_send_timeout_cancels_denied_and_eof_sends`; `tests/test_asgi_contract.py::test_asgi_live_error_responses_bound_start_and_body_sends`; `tests/test_asgi_contract.py::test_threaded_live_write_timeout_unblocks_session_revocation`; `tests/test_asgi_contract.py::test_socketio_websocket_send_gate_withholds_queued_frame_after_revocation`; `tests/test_asgi_contract.py::test_socketio_polling_send_gate_withholds_queued_frame_after_revocation`; `tests/test_asgi_contract.py::test_socketio_subscribe_stops_a_polled_batch_when_capability_is_revoked` | Deterministic tests cover direct threaded writes, real ASGI SSE routing, native WebSocket and polling send-boundary gating, a concurrent revoke waiting for awaited send completion, withholding of queued payloads after revocation, duplicate-header identity, and cancellation/timeout draining before lock release. These tests do not prove browser receipt or deployed proxy/router behavior. |
| V7.4.2 | Disabled/missing RouterOS-account revalidation revokes the session being checked, including an established live session. | `tests/test_app.py::DashboardIntegrationTests.test_disabled_routeros_account_revokes_existing_live_session`; `tests/test_app.py::DashboardIntegrationTests.test_socketio_stream_revokes_session_when_routeros_role_lookup_fails` | These tests do not establish proactive invalidation of every session for the account; the control remains partial. |
| V7.4.5 | Capability-protected session inventory and single-session revocation; the current session cannot revoke itself. No user-wide or all-user termination action is implemented. | `tests/test_app.py::DashboardIntegrationTests.test_admin_session_revocation_is_csrf_protected_scoped_and_audited`; `tests/test_security.py::test_session_snapshot_is_safe_and_revoke_is_scoped`; `tests/test_app.py::DashboardIntegrationTests.test_read_only_role_cannot_cross_audit_or_mutation_capability_boundaries` | Repository tests establish the narrower single-session action only; the ASVS control remains partial and has not received an independent authorization review. |
| V7.5.2 | Session inventory is available to authorized operators; revoking one selected administrator session requires a fresh RouterOS password verification for the current account, is rate-limited on failure, and never records the password. | `tests/test_app.py::DashboardIntegrationTests.test_admin_session_revocation_is_csrf_protected_scoped_and_audited`; `tests/test_app.py::DashboardIntegrationTests.test_admin_session_reauthentication_is_rate_limited`; rendered live-session revocation regression in `browser-tests/realtime-recovery.spec.js` | The user-facing any/all active-session termination requirement is not established: there is no terminate-all action, and selected-session revocation is administrator-scoped. This remains PARTIAL, in addition to unverified deployment behavior and independent review. |
| V7.5.1 | N/A for the current product boundary: dashboard operator authentication/recovery attributes are not editable in the app; VPN-user profile lifecycle is a separate RouterOS identity domain. | — | Reassess if the app adds operator-account email, phone, MFA, or recovery-attribute management. |
| V7.5.3 | Fresh RouterOS-password verification protects revoking another dashboard session; creating/revoking API tokens additionally requires server-verified reauthentication within five minutes. Other high-impact RouterOS mutations use intent-bound review receipts, not fresh-password step-up. | `tests/test_app.py::DashboardIntegrationTests.test_admin_session_revocation_is_csrf_protected_scoped_and_audited`; `tests/test_app.py::DashboardIntegrationTests.test_admin_session_reauthentication_is_rate_limited`; `tests/test_app.py::DashboardIntegrationTests.test_api_token_mutations_require_fresh_routeros_reauthentication`; `browser-tests/session-reauth.spec.js` | Token step-up has application-level integration/browser evidence. The broader risk assessment is in the high-impact action inventory; other action classes, deployed proxy behavior, and independent security review remain open. |
| V8 authorization (role/capability boundary); V4.4.2 WebSocket Origin validation | Explicit role capability matrix; API-token scopes are enforced on connection/usage exports and the combined compliance export; unknown roles default to read-only; telemetry principal contains authorization facts, not the session object. Socket.IO retains python-engineio's default same-origin validation and re-derives authorization from the current server-side session on reconnect. New and repeated namespace connects force a fresh RouterOS role lookup; connect, subscription/poll, and live pump checks all use bounded worker-thread execution (four concurrent checks per process, fail-closed on saturation). Already-open streams periodically revalidate using a 15-second cache measured with a monotonic clock, so wall-clock stalls or corrections cannot extend cache freshness. SSE separately rejects a supplied foreign Origin before RouterOS reads; this is an application safeguard, not a WebSocket control. RouterOS-backed sessions re-check the account's enabled state and group-derived role on authenticated requests and live SSE/Socket.IO authorization checks. A downgrade takes effect on the existing session; an increase requires a fresh login; a missing/disabled account or failed RouterOS role lookup revokes the session. | `tests/test_security.py::test_dashboard_role_capability_matrix_fails_closed`; `tests/test_security.py::test_every_role_matches_the_complete_declared_capability_set`; `tests/test_app.py::DashboardIntegrationTests.test_role_capability_denials_precede_every_guarded_route_family`; `tests/test_app.py::DashboardIntegrationTests.test_sse_rejects_foreign_origin_before_router_fetch`; `tests/test_app.py::DashboardIntegrationTests.test_socketio_stream_revalidates_routeros_role_change_on_real_session`; `tests/test_security.py::test_routeros_role_revalidation_downgrades_without_extending_idle_lifetime`; `tests/test_security.py::test_routeros_role_revalidation_never_elevates_an_existing_session`; `tests/test_security.py::test_routeros_role_revalidation_treats_clock_rollback_as_stale`; `tests/test_security.py::test_role_cache_expires_when_wall_clock_stalls`; `tests/test_security.py::test_routeros_role_revalidation_revokes_missing_or_incomparable_identity`; `tests/test_security.py::test_routeros_role_lookup_error_revokes_session`; `tests/test_routeros.py::RouterOSClientTests.test_admin_role_lookup_fails_closed_for_unknown_disabled_or_unavailable_accounts`; `tests/test_app.py::DashboardIntegrationTests.test_routeros_role_lookup_failure_revokes_session_before_admin_sessions_response`; `tests/test_app.py::DashboardIntegrationTests.test_socketio_stream_revokes_session_when_routeros_role_lookup_fails`; `tests/test_app.py::DashboardIntegrationTests.test_routeros_group_downgrade_takes_effect_on_existing_dashboard_session`; `tests/test_app.py::DashboardIntegrationTests.test_disabled_routeros_account_revokes_existing_live_session`; `tests/test_app.py::DashboardIntegrationTests.test_read_only_role_cannot_cross_audit_or_mutation_capability_boundaries`; `tests/test_app.py::DashboardIntegrationTests.test_enterprise_foundations_are_scoped_and_read_only_where_expected`; `tests/test_asgi_contract.py::test_live_pump_rechecks_capabilities_on_the_current_session`; `tests/test_asgi_contract.py::test_socketio_reconnect_uses_current_server_session_capabilities`; `tests/test_asgi_contract.py::test_socketio_connection_forces_routeros_revalidation_with_warm_cache`; `tests/test_asgi_contract.py::test_socketio_connect_runs_role_lookup_off_loop_and_fails_closed_at_capacity`; `tests/test_asgi_contract.py::test_socketio_cancelled_connect_keeps_role_check_slot_until_worker_finishes`; `tests/test_asgi_contract.py::test_socketio_subscription_and_pump_revalidate_off_loop`; `tests/test_asgi_contract.py::test_socketio_does_not_disable_engineio_same_origin_validation`; `tests/test_asgi_contract.py::test_socketio_asgi_rejects_foreign_origin_at_http_handshake`; `tests/test_asgi_contract.py::test_socketio_asgi_rejects_foreign_origin_at_websocket_handshake` | All five role grants are locked against the complete declared capability set, including fail-closed checks for non-owner roles and the owner's intentional wildcard. Every current API dispatch form is bound to the role/capability inventory; the declared role gates are exercised across all five dashboard roles, and nine high-impact route families have 23 denied pairings tested with valid CSRF and no RouterOS mutation requests. The scoped-token matrix classifies all current literal GET API dispatch forms and checks each grantable scope combination, while new regex GET routes fail until classified. This is not an exhaustive query/resource-state cross-product or independent authorization review. `/dashboard` omits audit rows and Change History navigation without `audit.read`; `/api/observability` requires `health.read` and conditionally includes audit/session fields for `audit.read` / `sessions.read`. Session-history exports require `sessions.read`, and compliance export requires both `audit.read` and `sessions.read`. Safe plans/diagnostics are explicitly distinguished from mutations. The 15-second recheck is a repository behavior, not measured physical-router revocation latency; deployed proxy origin behavior remains unverified. |

The repository's 15-second application role-cache interval is not immediate
revocation. The current [MikroTik REST API manual](https://manual.mikrotik.com/docs/developer-guides/rest-api/)
distinguishes a user-record change (applied on the next request) from a group
policy edit (applied when the REST server renews its API login, up to 10 minutes
later). That manual is newer than the deployed RouterOS 7.24.5 and this
behavior has not been verified on the device. Fresh application checks cannot
claim immediate effect while the RouterOS REST layer may still use its cached
login. There is no immediate RouterOS change notification or alert-and-revert
control; therefore V8.3.2 remains a known product gap, not merely an
unverified deployment result.

`tests/test_asgi_contract.py::test_native_websocket_revalidates_routeros_role_change_and_account_disable`
is a loopback integration test of the active ASGI Socket.IO WebSocket app. It
uses a deterministic RouterOS role resolver to verify that an owner-to-read-only
downgrade keeps only the still-authorized session stream, then an account-disable
result closes the stream and rejects reconnect. This is not a physical-router
or deployed-proxy observation.

`tests/test_asgi_contract.py::ASGIContractTests.test_native_socketio_websocket_revalidates_at_natural_deadline_and_denies_reconnect`
is a separate loopback integration test that leaves the live connection open
until the real monotonic role-cache interval expires, verifies at least 15
seconds between RouterOS role checks, and confirms revocation and reconnect
denial. This remains source/runtime evidence, not physical-router latency.

Established ASGI authorization waits to acquire role-check capacity or the
per-session authorization gate fail closed after
`ASGI_AUTHORIZATION_WAIT_TIMEOUT_SECONDS` (default 0.5 seconds, capped at 5
seconds; read at process startup, with invalid values using the default).
`tests/test_asgi_contract.py::ASGIContractTests.test_established_socketio_repeat_connect_fails_closed_on_capacity_timeout`
verifies saturated-slot failure cleans up an existing subscription, while
`tests/test_asgi_contract.py::ASGIContractTests.test_live_pump_disconnects_when_session_gate_wait_times_out`
verifies a held per-session gate disconnects the stream without emitting.
This deadline covers acquisition only: a running RouterOS lookup retains its
worker slot until it finishes, and a non-cooperative ASGI send can still delay
revocation as described below.

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

The ASGI wrapper also validates that the initial Engine.IO handshake carries a
currently active server-side dashboard session before dispatching it to
Engine.IO. Missing, unknown, expired, or revoked sessions fail closed (HTTP
403 for polling; WebSocket policy close); the nonblocking store-lock probe
fails closed under contention and does not refresh the session's idle deadline.
Authenticated namespace connection still performs the current RouterOS-role
and capability checks. Regressions in
`test_socketio_requires_active_session_before_engineio_handshake`,
`test_native_websocket_revalidates_routeros_role_change_and_account_disable`,
and `test_socketio_polling_send_gate_withholds_queued_frame_after_revocation`
cover missing and unknown cookies, revoked-session reconnect, and an active
session reaching the transport. This limits unauthenticated transport
allocation; it is not a rate-limit or public-edge denial-of-service guarantee.

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

### Post-merge revalidation — PR #778 — 2026-10-23

PR [#778](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/778)
adds redacted diagnostics for CSRF Origin/Referer rejection and binds the
Engine.IO transport SID to the active dashboard session before the handshake
packet is sent. Regression coverage verifies the send boundary, and the
diagnostics do not log raw header values. Main CI and the ARM64 publisher
completed successfully; provenance and SPDX SBOM attestations verified for
the exact source commit. The published ARM64 image digest is
`sha256:f518688d46cb7b1c089ad63d2310263076e7f067b4ada597a651dd4e349ba832`.

PR #778 has not been staged on RouterOS. Its deployed-origin behavior and
live logout result are therefore unverified; issue #200 remains open for
candidate-specific acceptance, physical RouterOS review, the credential-
memory risk decision, and independent scoped ASVS review.

### Previous published source boundary — PR #793 — 2026-10-23

PR [#793](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/793)
was the latest published mainline image before PR #794. Its CI and publisher workflows passed
for both architectures, including runtime smoke and detached provenance/SBOM
verification; the exact tags and digests are recorded in
[`RELEASES.md`](RELEASES.md). The two bounded source reviews described above
examined PR #791's commit, not the changed source in PR #793. Therefore this
publication is not an independent security review, deployed-proxy validation,
or RouterOS acceptance. Issue #200 remains open for those gates.

### Latest published mainline security changes — PR #794 — 2026-10-23

PR [#794](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/794)
is merged and published; no post-publication RouterOS staging is recorded.
Publisher run
[#39984997106](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/39984997106)
passed both architecture builds, runtime smoke, provenance/SBOM verification,
and stable-manifest read-back. It
requires exactly one configured same-origin `Origin` for WebSocket handshakes
before Engine.IO allocation, retains the session-bound HTTP polling GET
compatibility path, and uses separate non-authenticating revocation references
instead of exposing dashboard session-cookie bearers in the admin inventory.
CI passed the targeted Socket.IO security contract, Python 3.13/3.14 suites,
pre-commit hooks, secret/dependency checks, browser/accessibility regression,
and ARM64 image smoke build. Publication is artifact evidence only; it does
not establish deployed proxy behavior, session-revocation timing on RouterOS,
or the independent scoped ASVS review required by issue #200.

### ASGI live-send cancellation boundary — 2026-10-23

The live-send timeout is cooperative, not a hard transport-abort deadline. On
timeout the application requests cancellation and keeps the per-session role
lock until the ASGI `send` coroutine exits. This prevents a later authorization
change from racing a still-running send, but an ASGI server or test transport
that suppresses cancellation can delay logout/revocation without a fixed upper
bound. Regression coverage proves this fail-safe behavior and that no new frame
is sent after revocation completes (`tests/test_asgi_contract.py::ASGIContractTests.test_asgi_noncooperative_send_delays_revocation_but_blocks_later_delivery`);
it does not prove hard-bounded revocation.
A portable ASGI transport-abort mechanism is not available in the current
adapter. Treat hard-bounded revocation as unresolved for issue #200 and do not
claim that the configured timeout guarantees it.

The session-termination review receipt store now validates expiry, issuing
session, and intent while holding its lock before deleting a receipt. A
cross-session denial therefore leaves the owner's valid receipt usable; the
regression `DashboardIntegrationTests.test_session_termination_review_receipt_is_bound_to_issuing_session`
verifies the denied attempt makes no RouterOS mutation and the owner can still
complete the reviewed action.

### Post-merge revalidation — PR #776 — 2026-10-23

PR [#776](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/776)
ensures the server-side session is revoked before a logout audit write, so an
audit-storage failure cannot leave the session active. The regression is
`tests/test_app.py::DashboardIntegrationTests.test_logout_revokes_live_access_when_audit_write_fails`;
the required PR checks and published artifact verification passed. See
[`RELEASES.md`](RELEASES.md) for the immutable image identities and attestation
evidence.

On 2026-10-23, RouterOS read-back confirmed the exact #776 ARM64 tag and marked
the canary healthy after start. A later authenticated dashboard observation
showed the connected-user count change without a manual refresh; exact event
latency was not timed. A canary sign-out attempt was rejected by the origin
check and did not revoke the session. The configured canary `PUBLIC_ORIGIN`
matched the expected origin, but the rejected request's origin/header shape was
not captured. Do not weaken origin or CSRF validation; deployed logout and
session-revocation acceptance remains open pending diagnosis. The updater is no
longer active and no completed 30-minute sample record was verified, so the
readiness soak is not passed. Production remains on its prior image. This is
candidate startup/live-display evidence only, not security acceptance.
Physical RouterOS permissions and credential-memory exposure, the formal
credential-memory risk decision, and independent external ASVS review remain
open under issue #200.

### Post-merge revalidation — PR #767 — 2026-10-19

PR [#767](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/767)
changes static asset cache identity to content-hashed URLs so clients can load
the current bundle after an update. It does not change authentication,
authorization, session, telemetry payload, or RouterOS policy behavior. The
published ARM64 artifact and provenance are recorded in
[`RELEASES.md`](RELEASES.md).

The exact ARM64 tag was read back from the isolated canary and RouterOS
reported it healthy. The authenticated dashboard and Connections page loaded
with a Socket.IO live indicator. RouterOS and the rendered page both showed
zero active sessions/devices and an empty active-device list. No live
session-event, expiry/revocation, reconnect, or cross-origin transport test was
performed in this staging check. Production was left on its prior image. This
is deployment/readiness evidence only, not a security acceptance result.
Physical RouterOS permissions and credential-memory exposure, the formal
credential-memory risk decision, and independent external ASVS review remain
open under issue #200.

### Post-merge revalidation — PR #761 — 2026-10-18

PR [#761](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/pull/761)
merged as `e8af615c42145b9b6a1ea44bee9b217ffc5dc4be`. The ASGI Engine.IO
boundary now requires an active server-side dashboard session before creating
polling or WebSocket transport state. The check fails closed for missing,
unknown, expired, revoked, or lock-contended sessions; it does not update the
session idle deadline. Existing role/capability enforcement remains in place.
Regression coverage is in `tests/test_asgi_contract.py` and
`tests/test_security.py`. All required PR checks passed. Publisher run
[#39168925504](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/actions/runs/39168925504)
published the immutable ARM64/AMD64 images and verified their runtime smoke,
attestations, SBOMs, and stable-manifest read-back; their digests are recorded
in [`RELEASES.md`](RELEASES.md).

This is repository and publication evidence only for PR #761. At the time of
this entry, that image had not been verified on the RouterOS canary. No live
proxy/session acceptance is claimed for that candidate. Physical RouterOS
permissions and credential-memory exposure, the formal credential-memory risk
decision, and independent external ASVS review remain open under issue #200.

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
  The production entrypoint sets both POSIX RLIMIT_CORE limits to zero before
  importing the application; the direct HTTP and ASGI runtime main functions
  also apply the guard before server startup. Startup fails closed if the
  process limit cannot be applied. This is defense in depth against ordinary
  per-process core files, not proof that host dumps are disabled: Linux ignores
  RLIMIT_CORE when its kernel core pattern pipes dumps to a collector, and this
  setting does not prevent privileged host memory inspection or other dump
  mechanisms. See the
  [Linux resource-limit](https://man7.org/linux/man-pages/man2/getrlimit.2.html)
  and [core-dump](https://man7.org/linux/man-pages/man5/core.5.html)
  documentation. Regressions cover limit application and failure, plus startup
  ordering in the entrypoint, HTTP runtime, and ASGI runtime:
  tests/test_entrypoint.py::ProcessCoreDumpTests.test_posix_runtime_sets_soft_and_hard_core_limits_to_zero,
  tests/test_entrypoint.py::ProcessCoreDumpTests.test_posix_runtime_fails_closed_when_limit_cannot_be_set,
  tests/test_entrypoint.py::ProcessCoreDumpTests.test_core_dump_guard_runs_before_runtime_imported_main,
  tests/test_entrypoint.py::ProcessCoreDumpTests.test_http_runtime_guards_before_building_application, and
  tests/test_entrypoint.py::ProcessCoreDumpTests.test_asgi_runtime_guards_before_creating_application;
  the deployed host's
  collector/core-pattern policy remains unverified.
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
- The legacy Socket.IO polling bridge compares a supplied `Origin` with the
  configured `PUBLIC_ORIGIN` on handshake/poll requests and requires an exact
  configured origin on POST. A GET without `Origin` is supported only with one
  same-origin `Referer`; requests without browser-origin evidence or with a
  foreign/duplicate `Referer` are denied before bridge methods run and cannot
  allocate polling SIDs. HTTP-dispatch regressions pin the behavior. This
  repository evidence does not establish behavior at the deployed reverse
  proxy.
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

## RouterOS credential lifecycle review — 2026-10-23

- RouterOS credentials are held in the authenticated server-side session in
  process memory; this review found no path that persists the RouterOS
  password to the metadata database. Logout, expiry, and session rotation clear
  the session's credential fields, but Python strings and in-flight request
  copies cannot be reliably zeroed. This remains a host/process-memory risk,
  not a claim of secure erasure.
- The separate local immutable-release deployer reads `ROUTEROS_DEPLOY_USERNAME`
  and `ROUTEROS_DEPLOY_PASSWORD` from its process environment and constructs
  per-request Basic Authorization headers. The source path does not persist
  those values locally or include them in its sanitized errors. This does not
  protect them from host-level environment inspection, process memory, tracing,
  or crash capture; those controls remain unverified.
- RouterOS REST calls use certificate verification by default. The explicit
  insecure-TLS override weakens that guarantee and must remain disabled in
  production. Redirects are rejected in both the application REST client and
  local release deployer so an authenticated request cannot forward its Basic
  Authorization header to a different redirect target. Regressions in
  `tests.test_routeros.RouterOSClientTests.test_routeros_credentials_are_not_forwarded_to_redirect_target`
  and `tests.test_deploy_routeros_release.DeploymentTests.test_deployer_credentials_are_not_forwarded_to_redirect_target`
  start separate local redirect and capture servers and verify the capture
  endpoint receives no request.
- The application access logger excludes request paths and peer addresses, but
  this does not establish the behavior of the reverse proxy, container runtime,
  RouterOS, or host logging and crash collection. Those layers, effective
  process-dump controls, router API reachability, and least-privilege RouterOS
  permissions still require live operational review.
- Profile diagnostics may report the host and port contained in the submitted
  client profile to the authenticated caller with the relevant diagnostics
  capability. Treat those diagnostics and exported operational records as
  private network data; this review did not establish their handling by
  external log or webhook destinations.

## Independent internal source review — 2026-10-23

A separate read-only reviewer examined the authentication, session/live-stream,
origin, and RouterOS credential-handling paths at merged source commit
`8c3a46df3a7e0e8b0dac9e5ed7a979aa06e855f7`. No Critical or High source-level
finding was identified within that bounded review; this is not proof that no
such issue exists outside the reviewed paths.

- The documented in-memory credential trade-off is confirmed: RouterOS
  passwords are ordinary Python strings while an authenticated session or
  in-flight request needs them. Clearing references on teardown does not
  securely erase copies from process memory. Host-level memory access, dump
  collection, and external logging remain unverified.
- RouterOS user-role changes are revalidated through REST using a 15-second
  application cache. The current MikroTik REST manual says a user-record
  change applies on the next request, but group-policy edits may wait until the
  REST API login is renewed, up to 10 minutes. That server-side behavior is
  not verified on deployed RouterOS 7.24.5, so the 15-second interval is not
  the complete physical-router authorization-freshness bound. Disabling an
  account also does not proactively invalidate every other session.
- In the reviewed merged source at `8c3a46df3a7e0e8b0dac9e5ed7a979aa06e855f7`,
  read-only SSE and HTTP polling GETs retain compatibility with clients that
  omit `Origin` while still requiring the appropriate live dashboard session.
  Explicit foreign or duplicate origins are rejected, Socket.IO control POSTs
  require origin evidence, and mutating HTTP routes require CSRF protection.
  However, that merged source still permits a WebSocket handshake with no
  `Origin`; this gap was not covered by the first bounded review. A later
  review identified it, and this follow-up adds a requirement for exactly one
  configured same-origin `Origin` before Engine.IO allocation, with
  handshake/reconnect and no-Origin polling regressions. This change is not
  part of the cited merged commit. Actual proxy/browser behavior remains an
  external acceptance check.
- Focused local validation passed 147 tests across
  `test_security_assurance_contract`, `test_security`, and
  `test_asgi_contract`. The merged commit's required GitHub CI also passed.

This internal review is narrower than a requirement-by-requirement independent
ASVS assessment and is not a penetration test, deployment review, or compliance
attestation. It does not change the **Residual-risk decision: OPEN** below.

Two follow-up independent, read-only reviews examined the ASVS evidence
mapping and the SSE/Socket.IO authorization paths at source commit
`0002ce431fd8be0a66801725fbfb371f01ce7567`; neither found a confirmed
authorization bypass in its reviewed paths. They confirmed the 15-second
role-revalidation bound and identified that V4.4.2 had been marked TESTED even
though an absent WebSocket `Origin` was permitted without regression coverage.
The follow-up rejects missing WebSocket Origin values before Engine.IO
allocation and pins that behavior in handshake/reconnect tests; no-Origin HTTP
polling GET remains session-bound. V4.4.2 stays PARTIAL pending deployed proxy
verification and the complete ASVS allowlist review. These remain
bounded source reviews, not a complete independent ASVS assessment or
deployment sign-off.

The 15-second application runtime deadline is covered both by
`tests/test_telemetry_runtime.py::TelemetryRuntimeFreshnessTests.test_live_stream_role_downgrade_is_applied_at_15_second_cache_deadline`
using a controlled monotonic clock and by the live-stream integration test
above, which naturally crosses the 15-second deadline. Those tests use a
deterministic role resolver; they do not model RouterOS REST's documented
group-policy login cache or establish physical-router revocation latency. A
separate canary check must measure user-group reassignment and, in a disposable
test setup, group-policy edits on the exact deployed RouterOS version.

**Residual-risk decision: OPEN.** No deployment-level credential-memory or
logging review, complete independent requirement-by-requirement ASVS review,
or named owner risk acceptance is recorded here. Do not interpret bounded
source reviews as a production sign-off.

## Repository hardening and export privacy — 2026-10-05

- `POST /login` requires an exact same-origin `Origin`, or an exact same-origin
  `Referer` when Origin is absent or serialized as the opaque value `null`.
  Login and dashboard documents use `Referrer-Policy: same-origin`: this lets
  same-origin native form submissions and originless polling GETs provide the
  required evidence, while suppressing Referer on cross-origin requests.
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

The post-merge canary entry above records limited, point-in-time deployment and
readiness observations, including candidate health/tag readback and an
authenticated dashboard/session-state readback. These historical observations
are not controlled security or operational acceptance tests and do not close
issue #200. That entry omits client identifiers, addresses, credentials, and
raw telemetry. Repository tests establish only the behaviors they exercise;
neither those tests nor the limited canary observations verify the deployed
access-control policy, reverse-proxy routing, TLS termination, full live
session lifecycle, or RouterOS permissions. Keep detailed deployment evidence
in operator-controlled storage.

The following remain **NOT VERIFIED** and require an authorized controlled
test window:

- Observe logout, server-side revocation, idle expiry, and absolute expiry on
  the deployed image behind the actual reverse proxy while a live stream is
  open; verify reconnect requires authentication.
- Verify proxy TLS termination, secure-cookie handling, same-origin policy,
  and expected cross-origin denial using the actual public deployment.
- Review RouterOS user permissions and credential-memory exposure on the
  physical host, including the host core-dump collector policy; this code-only
  change cannot inspect host process memory or router policy.
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
