# Public roadmap

The project is developed public-first: generic features are designed, tested,
and released here before an operator optionally evaluates them in a private
canary. This source repository never receives router credentials, live user
data, deployment runners, or production network details.

## v1.1 — Installation Wizard

An offline, review-only installer that validates non-secret answers and renders
a RouterOS `.rsc` plan. It keeps Container package installation, device-mode
physical confirmation, TLS, storage checks, firewall/DNS work, and applying
commands explicitly manual.

## v1.2 — Policy templates and groups (implemented)

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

Every roadmap item gets a focused issue, pull request, passing CI, and squash
merge. See the live GitHub [roadmap issue](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/4).
