# RouterOS deployment from private GHCR

This runbook uses GitHub as the source of application code and GHCR as the image registry. A merge to `main` builds an immutable image and, after the publish workflow succeeds, **Deploy production to RouterOS** pulls and runs the exact full-commit image through the RouterOS HTTPS REST API. The workflow is fail-closed until the private REST path and protected environment secrets are configured.

Routine application-only changes use the automated path. Schema, data, RouterOS-policy, or topology changes still require the canary-first procedure below and should not be merged until the canary and rollback gates are complete.

## Automated post-merge deployment

The workflow `.github/workflows/deploy-production.yml` listens for a successful **Publish container** run on `main`. It checks out the published commit, verifies the full SHA, stops the exact configured container, sets its `remote-image` to `ghcr.io/<owner>/<repo>:sha-<full-sha>`, invokes RouterOS `/container/update`, starts the container, and waits for `status=running`. If any update or start gate fails, it attempts to restore the previous immutable image and start it again. It never uploads source files or changes mounts, environment lists, interfaces, firewall rules, or persistent data.

Configure these as **environment secrets** under a protected GitHub environment named `production`:

| Secret | Required value |
| --- | --- |
| `ROUTEROS_REST_URL` | Credential-free `https://.../rest` URL whose certificate SAN matches its hostname |
| `ROUTEROS_DEPLOY_USERNAME` | Dedicated RouterOS account with only the container read/write actions required for deployment |
| `ROUTEROS_DEPLOY_PASSWORD` | Password for that account |
| `ROUTEROS_CONTAINER_NAME` | Exact production container name; do not use a display label or mutable tag |
| `ROUTEROS_REST_CA_B64` | Base64 of the public CA certificate that signs the REST server certificate |

The deploy job runs on the repository-scoped Windows runner labeled `routeros-private` inside the management network. GitHub-hosted runner IP addresses change; do not open RouterOS REST to all GitHub ranges. Keep that runner dedicated to this repository, online only on the trusted management workstation, and patched like a production administrator endpoint. If the runner is unavailable, use an approved narrowly scoped, authenticated deployment relay instead. Keep `www-ssl` enabled and `www` disabled, restrict the service to the runner's management path, and retain RouterOS firewall logging for denied attempts.

Test the path with **workflow_dispatch** and an already-published full commit before relying on automatic post-merge updates. A missing secret, non-HTTPS URL, invalid CA, ambiguous container name, mutable image, or unreachable REST endpoint fails without changing RouterOS.

Replace every value in angle brackets. Never commit the resulting commands, exports, or credentials.

## Prerequisites

- RouterOS 7 with the Container package enabled and a CPU architecture matching the published `linux/arm64` image.
- Container mode enabled through the RouterOS physical-presence procedure.
- Sufficient external storage for image extraction, two application roots during canary, an immutable database checkpoint, and a separate green working copy. If the existing installation is on internal storage, treat that as a documented risk exception and verify the full capacity budget before every pull.
- A private GHCR package linked to this repository.
- A dedicated classic GitHub token with `read:packages` only, an owner-approved expiration, and access to this private package.
- A configuration-only directory containing the trusted public CA certificate used to verify RouterOS REST. RouterOS container mounts are writable, so protect the source through management policy and keep secrets out of it.
- A RouterOS REST certificate whose Subject Alternative Name contains the exact DNS hostname used by `ROUTEROS_REST_URL` (or an exact IP SAN when an IP URL is unavoidable).
- A tested database backup and the identity/digest of the current working container.

Do not use a GitHub account password, full repository token, Actions token, SSH deploy key, or administrator PAT as the router's registry credential.

## Offline plan helper

`deploy_routeros_canary.py` renders the canary network, mount, environment, and immutable image commands without opening a socket or changing RouterOS. Start with:

```powershell
python deploy_routeros_canary.py --help
```

Every environment-specific value is required explicitly. The helper rejects short or mutable image references, non-HTTPS URLs, a REST hostname that differs from the confirmed certificate SAN, unsafe RouterOS names and paths, inconsistent proxy trust, and a gateway outside the canary subnet. It prints a review-only plan with `start-on-boot=no` and stops before starting or exposing the container.

The legacy `update_routeros_app.py` source uploader is permanently fail closed and has no override. It must not be used for deployment.

## 1. Select a release

1. Open the completed **Publish container** workflow run for the desired default-branch commit.
2. Confirm its test job and image publication succeeded.
3. Record the full commit SHA and published image digest in the change ticket.
4. Use `<owner>/mikrotik-openvpn-gui:sha-<full-commit>` relative to the configured `https://ghcr.io` registry.
5. Do not deploy `edge`.

## 2. Record current state

In a private operator record, capture:

```routeros
/system/resource/print
/container/print detail
/container/mounts/print detail
/container/envs/print detail
/interface/veth/print detail
/ip/address/print detail
```

Do not paste unredacted output into GitHub. Container environment output, network addresses, user names, and registry configuration are operationally sensitive.

Before changing `/container/config`, record its non-secret registry URL and temporary directory. RouterOS container registry configuration is global, so a change can affect updates for other containers.

## 3. Back up persistent state

The consistent method is a short maintenance stop:

1. Stop the current dashboard container.
2. Copy its complete persistent data directory to a timestamped, immutable directory on the same external disk.
3. Create a second, distinct green working copy from that stopped snapshot. The candidate must never mount either the live blue directory or the immutable rollback checkpoint.
4. Start the current dashboard again and verify `/readyz` before continuing.
5. Copy the immutable checkpoint off-router through an approved encrypted channel.

The copy must include `dashboard.sqlite` and any SQLite sidecar files present. Do not copy only the database while writes are active.

## 4. Configure private registry access

Set the global registry only for the pull window:

```routeros
/container/config/set registry-url=https://ghcr.io username="<github-user>" password="<read-packages-token>" tmpdir="<external-disk>/containers/tmp"
```

The token will be stored as sensitive RouterOS configuration. Restrict RouterOS management access, exports, backups, and support files accordingly. After the image has been pulled, restore the prior registry URL if other containers depend on it. Keep the credential only if controlled future GHCR updates require it.

## 5. Prepare immutable mounts

Create distinct canary state; never point an untested image at the production database.

```routeros
/container/mounts/add list=vpn-gui-canary-mounts src="<external-disk>/vpn-gui/canary-data" dst=/data
/container/mounts/add list=vpn-gui-canary-mounts src="<external-disk>/vpn-gui/config" dst=/config
```

Place only the RouterOS REST public CA and non-secret configuration under the config source directory. RouterOS does not expose a read-only flag for this mount; restrict router/container administration accordingly. The recommended environment values are:

```routeros
/container/envs/add list=vpn-gui-canary-env key=PUBLIC_ORIGIN value="https://vpn.example.com"
/container/envs/add list=vpn-gui-canary-env key=ROUTEROS_REST_URL value="https://<router-hostname-present-in-certificate-san>:<rest-port>/rest"
/container/envs/add list=vpn-gui-canary-env key=ROUTEROS_CA_FILE value=/config/routeros-ca.crt
/container/envs/add list=vpn-gui-canary-env key=ROUTEROS_INSECURE_TLS value=false
/container/envs/add list=vpn-gui-canary-env key=DATABASE_PATH value=/data/dashboard.sqlite
/container/envs/add list=vpn-gui-canary-env key=DROP_PRIVILEGES value=true
/container/envs/add list=vpn-gui-canary-env key=TRUST_CLOUDFLARE value=true
/container/envs/add list=vpn-gui-canary-env key=TRUSTED_PROXY_SOURCES value="<router-proxy-address>"
```

There is intentionally no mount whose destination is `/app`. Application files come from the image.

Validate the REST certificate chain and hostname before the canary pull. A certificate that contains only a Common Name, or whose SAN contains a different public hostname, is not sufficient. Issue the correct certificate or select a URL already covered by its SAN; never set `ROUTEROS_INSECURE_TLS=true` as a workaround.

## 6. Create an isolated canary

Create a dedicated VETH address and a private router address on the application bridge. Choose an unused subnet that does not overlap LAN, VPN pools, routes, or another container. Review the resolved values before applying them.

```routeros
/interface/veth/add name=veth-vpn-gui-canary address=<canary-address>/<prefix> gateway=<router-canary-address>
/interface/bridge/port/add bridge=<container-bridge> interface=veth-vpn-gui-canary
/ip/address/add address=<router-canary-address>/<prefix> interface=<container-bridge> comment="VPN GUI canary gateway"
```

Add the canary with a separate root directory and the immutable image reference:

```routeros
/container/add remote-image=<owner>/mikrotik-openvpn-gui:sha-<full-commit> interface=veth-vpn-gui-canary root-dir="<external-disk>/containers/vpn-gui-canary" mountlists=vpn-gui-canary-mounts envlists=vpn-gui-canary-env start-on-boot=no logging=yes comment="VPN GUI canary <short-commit>"
```

Wait for extraction to finish, then start the exact canary record. Do not expose it through the public proxy yet.

RouterOS documents `remote-image` relative to `/container/config registry-url`, which is the assumed path above. A fully qualified registry reference or digest reference may be tested in an isolated canary on the installed RouterOS version, but do not make production depend on it until that behavior is verified.

## 7. Validate before cutover

At minimum:

- container state is running and stable;
- `http://<canary-address>:8080/healthz` returns HTTP 200 and `{"status":"ok"}` for process liveness;
- `/readyz` returns HTTP 200, `{"status":"ready"}`, a successful cached SQLite quick-check/write-rollback probe, and the exact full commit SHA selected from the workflow;
- no TLS, database, permission, or restart errors appear in the RouterOS log;
- the login page renders through a private operator path;
- a dedicated read-only test RouterOS account can authenticate through a TLS path; never send RouterOS administrator credentials to the canary over plaintext HTTP;
- read-only pages show users and sessions;
- the existing mock/unit CI run corresponds to the deployed commit;
- no live user, session, certificate, firewall, reverse-proxy, or DNS change is made by the smoke test.

Only after the read-only checks pass should an approved test identity exercise a reversible create/edit/remove flow.

## 8. Promote

1. Stop blue and green and verify both are stopped before copying SQLite.
2. Copy blue's complete data directory twice: one immutable rollback checkpoint and one distinct green working directory. Verify names and sizes recursively and run SQLite integrity checks against the green copy.
3. Rebind the already-tested green image to the green working directory and the shared configuration-only mount. Canary data is never promoted.
4. Start green privately and require `/readyz` with the approved revision, then verify a read-only RouterOS status request through TLS.
5. Set green `start-on-boot=yes`. Keep blue stopped but `start-on-boot=yes` until traffic commit succeeds because it owns a separate, frozen data directory.
6. Change the stateless HTTP redirect NAT target, then change the HTTPS reverse-proxy target. Preserve SNI, certificate, ports, rule order, and source restrictions.
7. Verify HTTP-to-HTTPS redirect, TLS, Cloudflare Access, RouterOS login, user/session reads, and one approved reversible action.
8. Set blue `start-on-boot=no`, but do not remove its record, root directory, mount list, environment list, or frozen data during the observation window.
9. Observe logs, CPU, memory, storage, login failures, and session refresh for the agreed window.

Do not delete the old container or backup during the observation window. Follow [ROLLBACK.md](ROLLBACK.md) on any failed gate.

## 9. Close the change

- Record the deployed commit SHA, image digest, workflow run, operator, time, tests, and rollback checkpoint.
- Remove the isolated canary after the observation window.
- Rotate the package-read token if it was exposed to shell history, logs, exports, screenshots, or support data.
- Restore the previous global registry configuration if other RouterOS containers require it.
