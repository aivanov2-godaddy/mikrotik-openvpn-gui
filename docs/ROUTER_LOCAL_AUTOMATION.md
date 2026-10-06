# Router-local automatic updates

This guide describes the supported automatic-update model for a public
installation. Source code and container images are public; the running router
remains the authority for its own configuration and data.

```text
public GitHub repository -> public GHCR image -> RouterOS canary staging
                                                       |
                                   private 30-minute acceptance evidence
                                                       |
                           local evidence-gated promotion controller
                                                       |
                                                   production

router only: environment list, RouterOS configuration, /data, /config,
             VPN users, certificates, profiles, firewall, proxy, update journal
```

The RouterOS updater is a static scheduler script installed and reviewed by
the operator. It is **not** downloaded or replaced from GitHub. It reads a
public, data-free release manifest and stages the candidate on the isolated
canary only. It never changes production. Production changes only through the
local `scripts/promote_routeros_release.py` controller after it re-evaluates a
fresh passing acceptance report and matches the live canary and production
images to that report.

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
  successful-promotion timestamp;
- a small pending-candidate record containing the staged immutable image and
  prior production image, used to keep scheduled canary staging idempotent;
- a bounded local history log containing only release image identities and
  lifecycle outcomes (`canary-staged`, `promoted`, or `failed`).

Routine releases change only `remote-image` and run the RouterOS container
update/start lifecycle. They do not recreate containers or change mounts,
environment lists, VETH interfaces, firewall rules, proxy configuration,
RouterOS configuration, or persistent directories. Never attach canary and
production to the same SQLite file: one database must have one writer.

## Promotion sequence

1. The updater counts active RouterOS script jobs to prevent overlap. RouterOS
   job state is authoritative; the legacy global lock is diagnostic only and
   may remain set after an interrupted run without blocking a later recovery
   attempt (PR #278).
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
   The updater records bounded readiness result classes (`fetch-error`, HTTP
   status, incomplete response, not-ready response, or revision mismatch) for
   failed attempts. It never writes the response body, fetch error text, or
   readiness URL to the log; `check-error` indicates an unexpected script-side
   failure while evaluating the probe.
6. It requires at least 30 successful `/readyz` samples spaced at least 60
   seconds apart before staging (a minimum 30-minute readiness soak). Each
   response must identify the exact immutable candidate revision. Any failed,
   incomplete, or mismatched response rejects the canary, restores its
   last-known-good image, records the failure locally, and leaves production
   untouched. The script rejects settings below the minimum sample count or
   cadence before it changes even the canary.
7. This readiness soak is a minimum canary guard, not the complete release
   acceptance report: it does not collect telemetry latency/freshness percentiles,
   Redis delivery history, RouterOS resource samples, API reconnect/snapshot
   evidence, or event-integrity evidence. Those remain separate required
   acceptance checks; passing `/readyz` alone cannot establish them. On success
   the updater writes a pending-candidate record and leaves production
   untouched. If the same candidate and production baseline are already staged,
   later scheduler runs are no-ops and do not restart canary.
8. Run the read-only collector and evaluator. The evaluator must report
   `promotion_eligible: true` for the fresh `canary-prepromotion` window.
9. Run the local promotion controller with that exact collected evidence. It
   re-evaluates freshness and every acceptance gate, verifies the expected
   project ARM64 image and pending-candidate record, confirms that RouterOS
   still has the candidate on canary and the same baseline on production, and
   checks both private `/readyz` endpoints immediately before mutation. Its
   `--check-only` mode performs those checks without writes.
10. Only after all checks pass does the controller update the named production
    container. It verifies the candidate revision on production, updates the
    router-local last-known-good journal, and restores the prior image if
    startup, readiness, or journal persistence fails. A failed candidate is
    locally quarantined so the scheduler will not repeatedly restage it.
11. Run a fresh `postpromotion` collection. The pre-promotion result does not
    mark production accepted. Image rollback never restores or overwrites
    `/data`; database restoration is a separate, explicit disaster-recovery
    operation.

The recommended staging watchdog cadence is every **5 minutes**. The manifest
is tiny, and an unchanged SHA or already-staged candidate is a no-op that never
touches production or restarts canary. A candidate rejected during canary
staging or production promotion is quarantined locally, so a broken release
cannot cause repeated disruptive restarts; the operator must review and clear
that local failure marker before retrying it. The example also keeps a bounded
`routeros-update-history.log` on the router's external storage for review and
incident recovery; it never uploads this journal to GitHub.

To restrict canary staging to a maintenance window, set
`maintenanceWindowEnabled` to `true` in the reviewed local script and choose
`maintenanceStartHour`/`maintenanceEndHour` in RouterOS local time. The start
hour is inclusive, the end hour is exclusive, and equal hours mean a window
that is open all day. Windows that cross midnight are supported. Outside the
window the scheduler exits before fetching or changing a container, then tries
again on its next five-minute run.

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

- Use only the observed production architecture (`arm64`) unless a separate
  redacted canary acceptance record verifies another RouterOS target.
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

### Manual one-click rollback

The updater writes the last successful immutable image to the router-only
`routeros-update-state.txt` journal. If a promotion later needs to be undone,
copy `scripts/routeros/rollback-last-good.rsc.example` to the router, replace
only its public package prefix and private readiness address, review it, and
run it from the RouterOS terminal. It validates the full SHA-tagged ARM64
image, changes only the production container, and requires a healthy `/readyz`
response before reporting success. Mounts, environment lists, certificates,
RouterOS configuration, and `/data` are never changed.

For manual recovery and the compatibility update path, see
[DEPLOYMENT.md](DEPLOYMENT.md) and [ROLLBACK.md](ROLLBACK.md).
