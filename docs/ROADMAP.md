# Public roadmap

The project is developed public-first: generic features are designed, tested,
and released here before an operator optionally evaluates them in a private
canary. This source repository never receives router credentials, live user
data, deployment runners, or production network details.

## v1.1 — Installation Wizard ✅

An offline, review-only installer that validates non-secret answers and renders
a RouterOS `.rsc` plan. It keeps Container package installation, device-mode
physical confirmation, TLS, storage checks, firewall/DNS work, and applying
commands explicitly manual.

## v1.2 — Policy templates and groups ✅

Protected `standard`, `contractor`, and `administrator` templates, plus custom
templates. Selected users receive a preview before an explicit, checkpointed
apply; later direct edits are retained as visible per-user overrides.

## v1.3 — Health and actionable alerts (implemented)

The dashboard now brings RouterOS REST reachability, dashboard storage,
OpenVPN service, profile-issuance prerequisites, certificate state, and router
capacity into one read-only view. Each result explains its impact and a safe
next step; it never changes RouterOS automatically. Per-user quota and schedule
alerts remain visible in the normal dashboard alert list.

## v1.4 — Reports and audit (implemented)

The audit page now supports readable date-range exports in redacted CSV and
JSON formats, in-page filtering, and bounded automatic retention. Exported
records contain action metadata only; passwords, private keys, profiles, and
RouterOS secrets are excluded.

## v1.5 — Backup and restore safety (implemented)

The setup planner can download a local metadata-only archive and verify an
existing archive's structure, format, and SHA-256 checksum entirely in memory.
Compatibility results are recorded in Change History; restore remains an
explicit review-only operation and is never applied automatically. Backups
remain local to the operator.

## v1.6 — Administrator guardrails (implemented)

Clear capability matrix, explicit destructive-action confirmations, and richer
audit rationale without a second administrator-password database.

## v1.7 — Opt-in integrations (implemented)

The dashboard supports provider-neutral HTTPS webhooks for sanitized audit
events, signed with HMAC-SHA256 and delivered asynchronously through a bounded
queue. `/healthz` and `/readyz` provide lightweight monitoring probes. Both
integrations are disabled unless explicitly configured; provider-specific
services remain optional adapters rather than hard dependencies.

## v1.9 — Review-first OpenVPN foundations (implemented)

The installer retains its short path for routers that already run OpenVPN. An
opt-in advanced planner is being added for a supported router with no existing
OpenVPN server: it validates that boundary and creates a copyable, non-secret
plan for the CA, server certificate, address pool, PPP profile, OpenVPN server,
and a disabled firewall rule. The plan includes a RouterOS checkpoint command
and requires the operator to review firewall placement, NAT, and enabling the
server in a maintenance window. It never changes RouterOS automatically. The
release also includes a full first-install playbook and a redacted real-router
canary acceptance procedure, so a maintainer can verify the public image before
it is promoted by their router-local deployment controller.

## v2.0 — Device posture checks (phase 1) ✅

The Device Profiles view evaluates each managed profile against the RouterOS
certificate inventory already read by the dashboard. A profile is marked
**Approved** only when its certificate is present, non-revoked, and issued by
the configured current CA; missing, revoked, or legacy-CA identities are
marked **Needs review** with an explanatory reason. This is deliberately
read-only: it does not rotate the CA, alter certificates, or change RouterOS.
Explicit device revocation remains the separate, confirmed action.

## v2.0 — Production observability (implemented)

Service Health now includes a local deployment history, a compact health
timeline, and rollback visibility for immutable releases. The authenticated
`/api/observability` endpoint and the normal live-status payload expose the same
metadata to the UI. Observations stay on the router-hosted database, are
retention-pruned, and never include CA material, credentials, profiles, or
RouterOS configuration.

## v2.1 — Mobile administrator workflows (implemented)

The same dashboard is optimized for phones and tablets. Responsive navigation,
touch-sized controls, safe-area spacing, viewport-safe dialogs, stacked action
groups, readable health cards, and bounded horizontal tables keep
administrative workflows usable in portrait and landscape without adding a
native app or changing the OpenVPN client experience. These are
presentation-only changes: APIs, RouterOS state, certificates, CA material,
and the router-hosted data boundary remain unchanged.

The follow-up polish pass adds an adaptive navigation treatment, stronger
mobile hierarchy, rounded card grouping, thumb-sized primary actions, clearer
live-session facts and graph containers, and keyboard-safe dialog surfaces.
Active navigation scrolls into view when a dashboard card opens another view;
all existing keyboard and screen-reader semantics remain intact.

Appearance preferences are available from the top bar on every dashboard view:
Standard preserves the slate WinBox baseline, Dark is tuned for low-light use,
Light provides a high-contrast daylight surface, and System follows the device
preference. The choice is browser-local and presentation-only.

## v2.2 — Administrator roles and authentication audit (implemented)

RouterOS groups map to Owner, Security operator, Administrator, Auditor, and
Read-only roles. A shared capability matrix is enforced by every API mutation
and mirrored by the UI, while the router remains the identity source and no
second dashboard-password database is introduced. Change History records
successful and failed sign-ins, role assignment, denied capabilities, and
dashboard-session revocation with safe metadata only. This release does not
modify CA material, certificates, issued profiles, RouterOS configuration, or
router-hosted VPN data.

Every roadmap item gets a focused issue, pull request, passing CI, and squash
merge. This milestone shipped in PR #137. See the live GitHub
[roadmap issue](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/4).

## v2.3 — Enterprise operations foundations (implemented)

This release starts the next enterprise-grade layer while preserving the
review-first and router-data boundaries:

- **Administrator session center:** safe session inventory with source,
  authentication method, idle/absolute expiry, and explicit revocation. The
  current session cannot revoke itself.
- **Break-glass recovery planning:** owner/security-operator users can produce
  a time-limited, reason-bound RouterOS recovery checklist. It is a plan only;
  it creates no credentials and changes no RouterOS state.
- **Signed release verification:** immutable GHCR SHA tags are checked against
  the reported revision before promotion. Mutable tags are rejected and the
  CA/data preservation gate is shown in the result.
- **Real-time telemetry:** an authenticated Server-Sent Events stream supplies
  connection snapshots, with the existing five-second polling path retained as
  a resilient fallback.
- **Profile diagnostics:** uploaded profiles are parsed in memory for endpoint,
  protocol, certificate blocks, and modern TLS safeguards; profile contents and
  private keys are never persisted or echoed.
- **Segmentation planning:** LAN/internet/full-tunnel zones and CIDRs can be
  reviewed as a deterministic plan before any future RouterOS implementation.
- **Metrics and compliance:** `/metrics` exposes secret-free Prometheus
  counters; a bounded compliance ZIP contains redacted summary, audit, and
  connection data.
- **Scoped API tokens:** short-lived, read-only bearer tokens can be issued,
  listed, and revoked by security-capable operators. Only a one-time plaintext
  token is shown; storage retains a hash and metadata only.
- **Accessible mobile/PWA foundation:** touch-safe controls, reduced-motion
  support, consistent labels, and an installable web-app manifest improve
  phone workflows without changing the OpenVPN client experience.

All controls are capability-gated and audited. No item in this foundation
release rotates or deletes CA material, certificates, profiles, RouterOS
configuration, or router-resident VPN data. This milestone shipped in PR #138;
the feature remains release-tagged separately from the published v2.0.0 image
until the next release checklist is completed.
