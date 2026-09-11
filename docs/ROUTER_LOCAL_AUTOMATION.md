# Router-local automatic updates

This guide describes the supported automatic-update model for a public
installation. Source code and container images are public; the running router
remains the authority for its own configuration and data.

```text
public GitHub repository -> public GHCR image -> router-local release controller
                                                       |
                                                   canary gate
                                                       |
                                                   production

router only: environment list, RouterOS configuration, /data, /config,
             VPN users, certificates, profiles, firewall, proxy, update journal
```

The release controller is a static RouterOS scheduler script installed and
reviewed by the operator. It is **not** downloaded or replaced from GitHub. It
only reads a public, data-free release manifest and changes the remote image of
the two predeclared dashboard containers.

## What the public release contains

The public repository and its GHCR image may contain application source, tests,
generic installer assets, documentation, and a release manifest. They must not
contain an installation's domain, IP addresses, RouterOS credentials, Cloudflare
configuration, webhook secret, RouterOS export, environment list, SQLite data,
audit history, VPN user data, certificates, private keys, or issued profiles.

Every promotable image is architecture-specific and pinned to a full Git commit:

```text
ghcr.io/<owner>/mikrotik-openvpn-gui:sha-<40-character-commit>-arm64
```

The release manifest is declarative JSON, not RouterOS code. Its contract is a
`schema` number, a full `commit` SHA, and an `images` object whose `arm64`
member is the exact image reference. It never contains an endpoint, token, or
other operator-specific value. A public stable manifest is an approval pointer,
not a mutable container tag: the controller rejects `edge`, `latest`, branches,
abbreviated SHAs, alternate registries, and images outside the configured
public package prefix.

## Router-local state

The controller keeps all state on the router or its approved external storage:

- the production and canary container names, interfaces, root directories,
  mount lists, and environment lists;
- the production `/data` SQLite mount and its audit history;
- the independent canary `/data` mount;
- `/config` trust material, such as the public RouterOS REST CA;
- RouterOS OpenVPN configuration, users, certificates, firewall, and proxy;
- a local update journal containing the last-known-good image, commit, and
  successful-promotion timestamp.

Routine releases change only `remote-image` and run the RouterOS container
update/start lifecycle. They do not recreate containers or change mounts,
environment lists, VETH interfaces, firewall rules, proxy configuration,
RouterOS configuration, or persistent directories. Never attach canary and
production to the same SQLite file: one database must have one writer.

## Promotion sequence

1. The scheduler takes a local lock so two runs cannot overlap.
2. It fetches the approved public manifest through HTTPS with certificate
   validation and checks its schema, architecture, image prefix, and complete
   SHA-tag format. The request carries a router-clock cache-busting query so a
   replaced GitHub release asset cannot be served stale by an intermediary;
   this query contains no configuration or credentials, and the response is
   still data-only and redirect-bounded.
3. If production already runs the candidate, it exits without changing either
   container.
4. It records the current production image in memory before any container
   action. The operator remains responsible for regular consistent SQLite
   backups; image rollback deliberately never restores or overwrites data.
5. It updates the canary with the exact candidate image and waits for RouterOS
   lifecycle state plus the canary's `/readyz` response to report the same
   revision. The manifest is always fetched over certificate-validated HTTPS.
   The readiness endpoint may use the same HTTPS protection or a literal
   RFC1918 address on the router's private VETH network over HTTP. The latter
   is limited to port 8080 and the exact `/readyz` path; it cannot use a DNS
   name, public address, loopback, link-local, multicast address, query, or
   fragment. This allows a router-local probe where TLS is terminated by a
   separate local proxy without weakening the public-release trust boundary.
6. It runs the configured non-destructive canary checks. On failure, it restores
   the canary's last-known-good image, records the failure locally, and leaves
   production untouched.
7. On success, it updates production with that same immutable image, verifies
   production `/readyz`, and records it as last known good locally.
8. If production cannot start or become ready, it restores the previously
   recorded production image and rechecks it. Restoring an image never restores
   or overwrites `/data`; database restoration is a separate, explicit disaster
   recovery operation.

The recommended watchdog cadence is every **5 minutes**. The manifest is tiny,
and an unchanged SHA is a no-op that never touches either container. A
candidate that fails three times is quarantined locally, so a broken release
cannot cause repeated disruptive restarts; the operator must review and clear
that local failure marker before retrying it.

## Initial migration from an existing private image

Perform this once during a maintenance window:

1. Record the current private production and canary image tags, container
   details, mount lists, environment-list names, root directories, and VETH
   settings. Do not export secrets into a ticket or public file.
2. Make an encrypted RouterOS backup and a consistent off-router checkpoint of
   the production `/data` directory, including SQLite sidecar files.
3. Confirm that the public ARM64 package can be pulled anonymously and choose a
   reviewed full-SHA image from a successful public build.
4. Keep the existing canary's independent mounts and environment list, update
   only its image to the public SHA, and validate login, RouterOS REST TLS,
   existing VPN access, profile/QR download, and data persistence.
5. Install and test the router-local controller in dry-run mode. Its first
   observed candidate must be the canary image already tested.
6. Promote production by changing only its image. Preserve the existing
   production root directory, `/data` mount, `/config` mount, environment list,
   VETH, proxy, firewall, OpenVPN configuration, certificates, and users.
7. Observe production and one scheduled no-op/upgrade cycle. Confirm the local
   journal has a last-known-good public SHA and that rollback works on canary.
8. Only after the observation period, disable the former private deployment
   controller and archive the private repository. Archive rather than delete it
   until recovery procedures have been exercised.

## Operator checklist

- Use only the validated target architecture (`arm64` for supported RouterOS
  hardware).
- Keep GHCR public for anonymous pulls. Do not add a package token unless your
  fork is intentionally private; a private token belongs only in RouterOS
  container configuration.
- Keep RouterOS REST private, HTTPS-only, and certificate-validated.
- Keep the public release-manifest URL HTTPS-only. If the dashboard's local
  VETH health endpoint is HTTP, use only a literal RFC1918 container address
  and the strict `:8080/readyz` form accepted by the controller.
- Protect the public default branch and release workflow with review and required
  checks. Public source integrity is the release-controller trust boundary.
- Review RouterOS scheduler output and the local journal after every promotion.
- Keep the previous known-good image and an encrypted data checkpoint through
  the observation window.

For manual recovery and the compatibility update path, see
[DEPLOYMENT.md](DEPLOYMENT.md) and [ROLLBACK.md](ROLLBACK.md).
