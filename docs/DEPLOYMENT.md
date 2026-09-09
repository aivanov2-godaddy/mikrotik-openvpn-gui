# Updating a RouterOS installation

This repository publishes validated container images and a generic, public
release manifest. It never receives a router address, RouterOS credential,
production environment, or self-hosted management runner. The optional
automatic path is a static scheduler script that runs **on the router** and
uses only an approved immutable image. A pull request or fork has no direct
network path to an operator's router.

Use the documented local procedure below after you have completed the
[first-time installation](INSTALLATION.md). Test on a canary router or an
isolated second container before replacing a production dashboard. For the
router-local automatic procedure and migration plan, see
[ROUTER_LOCAL_AUTOMATION.md](ROUTER_LOCAL_AUTOMATION.md).

## 1. Pick a release image

Use an immutable tag from the public package, matching your architecture:

```text
ghcr.io/<owner>/mikrotik-openvpn-gui-public:sha-<40-character-commit>-arm64
ghcr.io/<owner>/mikrotik-openvpn-gui-public:sha-<40-character-commit>-amd64
```

`arm64` is the validated RouterOS target. `amd64` is intended for CHR/x86
evaluation and must be tested on the exact RouterOS version you operate. Do not
configure RouterOS to follow `edge`; it is mutable and cannot provide a reliable
rollback point.

If the package is public, RouterOS can pull it anonymously. If you publish your
own private fork, configure an expiring read-only package token through
`/container/config`; never add it to a repository, script, or exported
configuration.

## 2. Record the current image

In WinBox, open **Container**, select the dashboard container, and copy the
current `remote-image`. Keep it as the rollback value. Confirm the container
has a persistent `/data` mount and that `/config` contains only public trust
material such as the RouterOS REST CA certificate.

## 3. Update deliberately

Use WinBox **Container → Update** for the selected dashboard container, choose
the immutable image tag, wait for extraction to complete, then start the
container. Do not modify mounts, environment lists, virtual Ethernet, firewall
rules, or the SQLite directory as part of a routine application update.

Advanced operators can use the strict local client:

```powershell
python scripts/deploy_routeros_release.py `
  --rest-url https://router.example.com/rest `
  --ca-file .\routeros-ca.crt `
  --username deployer `
  --container-name vpn-dashboard `
  --image ghcr.io/<owner>/mikrotik-openvpn-gui-public:sha-<commit>-arm64
```

The client requires TLS certificate validation and a full immutable `sha-` tag.
Supply credentials through your normal local secret-management method, not on a
command line saved to history. Review `python scripts/deploy_routeros_release.py --help`
before using it. It only updates the named container and restores the previous
image if its start gate fails.

## 4. Validate

After the container reports `running`, verify from a trusted management path:

1. `https://<dashboard-origin>/readyz` returns `status: ready`.
2. The login page loads over HTTPS and RouterOS authentication succeeds.
3. A read-only router status view works with the configured CA.
4. An existing OpenVPN user can connect without profile changes.
5. The audit log records expected operator actions without secret values.

## 5. Roll back

If extraction, startup, health, or login fails, stop the new container, restore
the exact image tag recorded in step 2, start it, and validate again. Preserve
the persistent `/data` directory unless you have a tested database backup and a
documented migration plan. See [ROLLBACK.md](ROLLBACK.md) for the full checklist.

## Canary pattern

For a production estate, create a second container with its own VETH address,
external storage path, and test-only dashboard origin. Point it at a copy of
the production configuration only after redacting credentials. Run the target
image there, validate RouterOS REST TLS and a disposable VPN account, then stop
the canary before promoting the same immutable tag to production.

The offline `deploy_routeros_canary.py` helper prints a reviewable RouterOS
configuration plan; it has no network or apply mode:

```powershell
python deploy_routeros_canary.py --help
```

Never expose RouterOS REST or the container port directly to the public
internet. Put the dashboard behind an HTTPS reverse proxy as described in
[EXPOSURE.md](EXPOSURE.md).

## Router-local automatic path

Use the router-local controller only after its canary and rollback behavior has
been tested. It may poll a public release manifest, but it must promote only a
complete, architecture-qualified `sha-<40-character-commit>` image from this
package. It must never follow `edge`, `latest`, a branch, an unsigned command,
or an arbitrary registry URL.

The controller preserves the production container's root directory, mounts,
environment list, VETH, RouterOS configuration, and `/data` SQLite database.
It validates canary first, promotes the exact same image to production, and
records the previous image locally for rollback. See the full state boundary,
promotion protocol, and private-to-public migration checklist in
[ROUTER_LOCAL_AUTOMATION.md](ROUTER_LOCAL_AUTOMATION.md).
