# Router mutation safety contract

This is the operator-facing inventory for high-impact RouterOS changes. API
authorization and CSRF are enforced server-side; hidden buttons are not a
security boundary. The exhaustive route-dispatch/authentication checks live in
`tests/test_app.py` (`test_sensitive_route_matrix_fails_closed_for_anonymous_requests`)
and the capability index is in [ROUTE_AUTHORIZATION.md](ROUTE_AUTHORIZATION.md).

## RouterOS mutations

| Workflow | Review → apply | Verification and recovery contract | Important limit |
| --- | --- | --- | --- |
| Create VPN account | `POST /api/users/preview` → `POST /api/users`; the apply consumes the current session's one-use review receipt, including the destination's generated PPP rate-profile state when rate limiting is requested. | Generated rate-profile writes verify the exact RouterOS `rate-limit`; re-read the account after apply; failed provisioning compensates for the exact account/certificate created and reports cleanup as verified, partial, or unknown. It also compares the generated PPP profile with the reviewed state and reports `rate_profile_recovery` when residue or uncertainty remains. | Password values are not rendered in the review; password changes cannot be verified by read-back. Shared PPP profiles are never automatically deleted during compensation; operators must inspect references before cleanup. |
| Edit VPN account | `POST /api/users/{id}/preview` → `PATCH /api/users/{id}` with the receipt, including generated PPP rate-profile identity/rate-limit state. | Reject stale profile state; verify the exact RouterOS `rate-limit` and read back RouterOS account fields before committing local metadata; reconcile a lost account-update response from RouterOS state. | A changed password is explicitly partial/unverifiable, never reported as read-back verified. A rate-profile write may remain if the later account update fails. |
| Duplicate VPN account | `POST /api/users/{id}/duplicate/preview` → `POST /api/users/{id}/duplicate` with a receipt bound to the source's copied settings and requested intent. | Reject stale source settings; verify created account and compensate exact partial records on failure. | Secrets are excluded from the preview. |
| Suspend / restore account | `POST /api/users/{id}/suspend/preview` or `/restore/preview` → `POST /api/users/{id}/suspend` or `/restore`. | Bind the receipt to current disabled state and active session set; verify disabled state, terminate/recheck sessions for suspension, and preserve local enforcement on unknown read-back. | New sessions can race the initial preview; the account is disabled before session cleanup and the handler reports remaining sessions. |
| Delete account | `POST /api/users/{id}/delete/preview` → `DELETE /api/users/{id}` with exact managed-certificate and local-metadata scope in a one-use receipt. | Revoke/read back only managed certificates, then delete/read back the account; clear local metadata only after confirmed absence. Preserve local state and report partial/unknown on uncertainty. | Certificate revocation is not reversible by the dashboard; a revoked device may need a newly issued profile. |
| Issue device profile | `POST /api/users/{id}/profiles/preview` → `POST /api/users/{id}/profiles` with a one-use receipt bound to user, device label, effective policy, delivery, migration target, and certificate inventory. | If local recording fails, revoke/read back the uniquely created certificate; unresolved RouterOS residue is reported, not hidden. | A replacement profile does not retire a legacy certificate automatically. Private-key passphrases never enter the preview or receipt. |
| Revoke one device certificate | `POST /api/devices/{id}/revoke/preview` → `POST /api/devices/{id}/revoke` with reason, exact confirmation, and a one-use receipt. | Read back the exact certificate revocation timestamp; mismatch/unavailable remains failed/unknown without committing local state. | Revocation blocks future authentication; it does not terminate a tunnel already using that certificate. |
| Bulk suspend / revoke / tag | `POST /api/bulk/preview` → `POST /api/bulk/apply` with an atomic one-use receipt bound to selected users and relevant account/session/certificate/tag state. Bulk suspension/revocation also requires a 12–240 character rationale bound into the receipt and written to the audit outcome. | Re-read before apply; report each item as applied, skipped, partial, or failed; preserve verified partial progress and make safe retries idempotent. | The selection or rationale can become stale; any binding change requires a new preview. Suspend/revoke checkpoint where supported. |
| Apply policy template | `POST /api/policy-templates/{id}/preview` → `/apply` with receipt bound to template, selected IDs, current user profiles, generated PPP rate-profile identity/rate-limit state, and dashboard controls. | Reject stale state; checkpoint where supported; generated rate-profile writes verify the exact RouterOS `rate-limit` by read-back; verify each user profile and retain local assignments only after read-back. | There is no universal RouterOS transaction; partial results are reported per user. A profile write can succeed before a later user assignment fails; that partial router state is not automatically rolled back. |
| Terminate live VPN session | `POST /api/sessions/{id}/preview` → `DELETE /api/sessions/{id}` with a 12–240 character operator rationale and exact target confirmation. The single-use receipt binds both the rationale and exact live-session identity; changing either requires a new review. | Re-read the exact session before termination and read back absence even if the DELETE response is lost; report verified success only when absent, failure if still active, and unknown if read-back is unavailable. Audit stores the bounded rationale and outcome, not session addresses. | Disconnection cannot be rolled back; the account can reconnect if still enabled. |

## Background access-policy enforcement

Expiry, quota, schedule, and per-account session limits are explicit local
operator policy. The 30-second worker treats RouterOS as authoritative for the
account and live-session state: it re-reads the account before acting, creates
a RouterOS export checkpoint before changing `disabled`, rechecks the account
after the checkpoint, and verifies the exact disabled state after the write.
It persists a pending enforcement intent before a disable so an ambiguous
RouterOS response or worker restart can be reconciled on the next poll. Expiry
is terminal and is never automatically undone; quota and schedule restrictions
may be restored only when their condition clears and RouterOS confirms the
account remains disabled by the recorded automation state.

The worker checks exact session identity before disconnecting, resolves lost
DELETE responses by reading sessions again, and records verified, failed,
unknown, or partial outcomes. Residual or unreadable sessions are retried on a
later poll and are not reported as successfully removed. Alerts and audit
records contain fixed safe guidance and aggregate counts, not RouterOS error
text, credentials, or session addresses. This is point-in-time verification,
not a RouterOS transaction: a concurrent administrator or a connection racing
the check can still change state, so the worker rechecks on later polls and
cannot guarantee atomicity across account and session resources.

The deterministic regression coverage is in `tests/test_automation.py`.

## Dashboard-only writes and plan endpoints

These endpoints change dashboard-local state rather than RouterOS:

- `POST /api/admin/api-tokens` and `DELETE /api/admin/api-tokens/{id}` create or revoke a scoped dashboard token.
- `DELETE /api/admin/sessions/{id}` revokes a dashboard login, not an OpenVPN tunnel.
- `POST /api/bulk/views` and `DELETE /api/bulk/views/{id}` save or remove a filter view.
- `POST /api/alerts/{id}/ack` acknowledges a dashboard alert.
- `POST /api/policy-templates` and `PATCH /api/policy-templates/{id}` create or edit a local template; only its
  separate `/{id}/apply` action changes RouterOS.

They still require their route-specific capability and CSRF/session
authorization; they do not claim a RouterOS checkpoint or RouterOS read-back.
Setup, network
segment, break-glass, OpenVPN-foundation, backup-preflight, and backup-restore
plan endpoints are review/read-only operations and do not execute their plan.
There is no dashboard route that silently applies a restore plan.

## Evidence and outstanding assurance

The mock integration suite covers route denial, review freshness, receipt
replay, RouterOS response loss, read-back mismatch/unavailability, cleanup,
redaction, and partial progress. Search the tests by the workflow names above;
the broader tests intentionally use deterministic RouterOS mocks.

This matrix is not a hardware acceptance result. Remaining evidence is live
RouterOS exercise of every supported release/model, measured behavior under
response loss and competing operators, and confirmation that the deployed
proxy/session boundary matches repository assumptions. RouterOS does not
provide one atomic transaction across the account, certificate, and dashboard
SQLite changes; recovery is compensating and may correctly remain partial or
unknown. Never retry an ambiguous destructive operation until its exact target
state has been read back.
