# Deployment security model

## Assets to protect

- RouterOS administrator and VPN credentials;
- CA and client private keys, generated profile archives, and QR hand-off payloads;
- GitHub, GHCR, and Cloudflare tokens;
- owner emails, source addresses, usage counters, and audit metadata;
- RouterOS exports, backups, container environment lists, and support files.

## Required controls

### GitHub

- Keep repository and GHCR package visibility private.
- Require multi-factor authentication for every collaborator.
- Protect the default branch with pull requests, review, required checks, conversation resolution, and blocked force pushes/deletions.
- Keep Actions permissions read-only by default; grant `packages: write` only to the image-publish job. The RouterOS deployment job receives no package or repository write permission.
- Pin Actions to full commit SHAs and let Dependabot propose reviewed updates.
- Enable private vulnerability reporting, Dependabot alerts, secret scanning, and push protection where the account plan supports them.
- Never place production credentials in repository variables, workflow output, artifacts, or build arguments.

The publish workflow uses the job-scoped `GITHUB_TOKEN`; it does not require a stored registry password.

### GHCR pull identity

Use a separate, expiring token with `read:packages` only. Its account must have read access to the private package and no RouterOS or Cloudflare privilege. Store it only in RouterOS container registry configuration and an approved password manager. Review exports and support data as though they could contain it.

### RouterOS REST TLS

- Mount a trusted public CA certificate under the configuration-only `/config` path. RouterOS cannot mark this mount read-only, so protect it through management policy and keep secrets out of the directory.

The GitHub deployment workflow uses a separate base64-encoded copy of that public CA in the protected `production` environment. It refuses HTTP, credential-bearing URLs, mutable image tags, missing container names, and untrusted certificates. Keep the REST endpoint on a private path; GitHub-hosted runner source addresses are dynamic and must not be added as a broad RouterOS allowlist.
- Use a REST URL whose hostname is present exactly in the server certificate Subject Alternative Name.
- If the URL uses an IP literal, the certificate needs the matching IP SAN; a DNS SAN or Common Name is not equivalent.
- Keep `ROUTEROS_INSECURE_TLS=false` in every environment.
- Replace or reissue a mismatched certificate. Do not disable verification.

### Network

- Keep the dashboard and RouterOS REST endpoints on private container/management networks.
- Restrict public origin ports to the approved reverse proxy or edge egress networks.
- Permit forwarded client headers only from the exact RouterOS proxy addresses listed in `TRUSTED_PROXY_SOURCES`.
- Keep OpenVPN data traffic separate from the web control plane.
- Restrict WinBox, SSH, REST, and container management to explicitly approved management sources.

### Container

- Deploy an immutable GHCR `sha-` tag and the RouterOS container's built-in `update` command. The workflow stops the configured container, updates only its image reference, waits for a running state, and automatically restores the prior image on failure. It does not upload source or modify mounts, environment, interfaces, firewall rules, or persistent data.
- Do not mount host content over `/app`.
- Mount `/data` persistently and reserve `/config` for non-secret trust material; do not put private keys into application code or image layers.
- Keep privilege dropping enabled and enforce RouterOS memory/storage limits.
- Give canaries a separate network address, root directory, and database volume.

## Administrator authorization

The dashboard verifies the credentials presented at login against RouterOS. Prefer a dedicated RouterOS group with only the policy needed by dashboard operations after that policy has been tested against every supported action. Avoid routine use of a full RouterOS owner account. Cloudflare Access can provide an independent first factor and identity allowlist, but it does not replace RouterOS authorization.

## Build and release integrity

Pull requests run pre-commit hygiene and lint hooks, secret-pattern checks, tests, and a clean ARM64 build. CodeQL should be enabled when GitHub Advanced Security is available for the private repository; until then it is not represented as a passing control. The publishing workflow reruns the same checks before it can push, and the post-merge deploy workflow uses only the published full-commit image. Attached SBOM/provenance manifests are disabled on the deployable image because RouterOS 7 does not document support for the resulting OCI indexes; they may be evaluated only through an isolated canary on the installed RouterOS release. Operators must compare the selected workflow commit, immutable GHCR tag, and RouterOS deployment record after each automated update.

## Secret exposure response

1. Revoke or rotate the credential immediately.
2. Restrict affected service access and preserve evidence privately.
3. Determine whether images, caches, artifacts, logs, exports, forks, or backups contain the value.
4. Purge affected derived artifacts after evidence collection.
5. Rewrite Git history only after revocation; history rewriting is not remediation by itself.
6. Add a high-confidence detection rule or regression check when practical.
