# Deployment security model

## Assets to protect

- RouterOS administrator and VPN credentials;
- CA and client private keys, generated profile archives, and QR hand-off payloads;
- GitHub, GHCR, and Cloudflare tokens;
- owner emails, source addresses, usage counters, and audit metadata;
- RouterOS exports, backups, container environment lists, and support files.

## Required controls

### GitHub

- Keep instance configuration and deployment credentials on the router (or in
  approved private recovery storage). The public source repository and its
  image package may be public when anonymous pulls are part of the operating
  model.
- Require multi-factor authentication for every collaborator.
- Protect the default branch with pull requests, review, required checks, conversation resolution, and blocked force pushes/deletions.
- Keep Actions permissions read-only by default; grant `packages: write` only to the image-publish job. Public workflows must never receive RouterOS deployment permission.
- Pin Actions to full commit SHAs and let Dependabot propose reviewed updates.
- Enable private vulnerability reporting, Dependabot alerts, secret scanning, and push protection where the account plan supports them.
- Never place production credentials in repository variables, workflow output, artifacts, or build arguments.

The publish workflow uses the job-scoped `GITHUB_TOKEN`; it does not require a stored registry password.

### GHCR pull identity

For a private image package, use a separate, expiring token with
`read:packages` only. Its account must have no RouterOS or Cloudflare privilege.
Store it only in RouterOS container registry configuration and an approved
password manager. Public packages do not require a registry token.

### Router-local release controller

The supported automatic updater is a reviewed static RouterOS scheduler script
installed locally. It may fetch a public JSON release manifest over validated
HTTPS, but it must not download, import, or execute RouterOS code from the
network. It must accept only the configured GHCR package prefix and a complete
architecture-qualified SHA tag, lock concurrent runs, validate a separate
canary, and retain a local last-known-good production tag.

The public manifest is an approval pointer, not a substitute for repository
integrity. Protect the public default branch, release workflow, package
visibility, and maintainer accounts because anyone able to publish a release
can publish application code. The controller must not trust `edge`, `latest`,
branches, abbreviated SHAs, arbitrary manifest fields, or any router-specific
value supplied by the public repository.

All of the following remain router-local: domain and IP data, RouterOS
credentials and env lists, Cloudflare settings, webhook secrets, SQLite data
and audit history, OpenVPN certificates/private keys/profiles, RouterOS
configuration, and the update journal.

### RouterOS REST TLS

- Mount a trusted public CA certificate under the configuration-only `/config` path. RouterOS cannot mark this mount read-only, so protect it through management policy and keep secrets out of the directory.

The local deployment client refuses HTTP, credential-bearing URLs, mutable image
tags, missing container names, and untrusted certificates. Keep the REST
endpoint on a private path. Do not give a public GitHub Actions workflow a path
to your router or add GitHub-hosted runner ranges to a RouterOS allowlist.
- Use a REST URL whose hostname is present exactly in the server certificate Subject Alternative Name.
- If the URL uses an IP literal, the certificate needs the matching IP SAN; a DNS SAN or Common Name is not equivalent.
- Keep `ROUTEROS_INSECURE_TLS=false` in every environment.
- Replace or reissue a mismatched certificate. Do not disable verification.

### Network

- Keep the dashboard and RouterOS REST endpoints on private container/management networks.
- Restrict public origin ports to the approved reverse proxy or edge egress networks.
- Permit a forwarded client-IP header only from the exact immediate reverse-proxy addresses in `TRUSTED_PROXY_SOURCES`; set `TRUSTED_PROXY_HEADER` to the one header that proxy supplies. The dashboard accepts only `CF-Connecting-IP` and `X-Forwarded-For`, and ignores either header from every other peer.
- Keep OpenVPN data traffic separate from the web control plane.
- Restrict WinBox, SSH, REST, and container management to explicitly approved management sources.

### Container

- Deploy an immutable GHCR `sha-` tag with RouterOS's built-in `update` command, the local deployment client, or the router-local controller. Preserve the current image as an explicit rollback point. Neither path should upload source or modify mounts, environment, interfaces, firewall rules, or persistent data during a routine application update.
- Do not mount host content over `/app`.
- Mount `/data` persistently and reserve `/config` for non-secret trust material; do not put private keys into application code or image layers.
- Keep privilege dropping enabled and enforce RouterOS memory/storage limits.
- Give canaries a separate network address, root directory, and database volume.

## Administrator authorization

The dashboard verifies the credentials presented at login against RouterOS. Prefer a dedicated RouterOS group with only the policy needed by dashboard operations after that policy has been tested against every supported action. Avoid routine use of a full RouterOS owner account. An optional identity perimeter such as Cloudflare Access can provide an independent first factor and identity allowlist, but it does not replace RouterOS authorization.

## Build and release integrity

Pull requests run pre-commit hygiene and lint hooks, secret-pattern checks, tests, and a clean ARM64 build. CodeQL should be enabled when available; until then it is not represented as a passing control. The publishing workflow reruns the same checks before it can push. RouterOS deployment uses only a published full-commit image and happens through an operator-controlled manual path or a router-local canary controller; public workflows never contact a router. Attached SBOM/provenance manifests are disabled on the deployable image because RouterOS 7 does not document support for the resulting OCI indexes; they may be evaluated only through an isolated canary on the installed RouterOS release. Operators must compare the selected workflow commit, immutable GHCR tag, and local RouterOS deployment record after each promotion.

## Secret exposure response

1. Revoke or rotate the credential immediately.
2. Restrict affected service access and preserve evidence privately.
3. Determine whether images, caches, artifacts, logs, exports, forks, or backups contain the value.
4. Purge affected derived artifacts after evidence collection.
5. Rewrite Git history only after revocation; history rewriting is not remediation by itself.
6. Add a high-confidence detection rule or regression check when practical.
