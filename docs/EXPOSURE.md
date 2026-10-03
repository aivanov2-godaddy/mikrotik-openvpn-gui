# Supported dashboard exposure modes

The dashboard image is portable: its public name and perimeter are instance
configuration, not image properties. It is an HTTPS application behind a
reverse proxy. Keep the dashboard container and RouterOS REST endpoint on
private networks; expose only the selected TLS proxy on ports 80 and 443.

## Choose one mode

| Mode | Use it when | Public endpoint | Dashboard environment |
| --- | --- | --- | --- |
| Direct HTTPS | You have a domain and do not want Cloudflare. **Recommended non-Cloudflare mode.** | A TLS reverse proxy such as Caddy | `TRUST_CLOUDFLARE=false`, exact proxy address, `X-Forwarded-For` |
| Cloudflare perimeter | You want Cloudflare DNS/proxy, Access, WAF, or edge policy. | Your existing Cloudflare/origin proxy path | `TRUST_CLOUDFLARE=true`, exact immediate proxy address, `CF-Connecting-IP` |
| Local development | You are testing only on the router or a local workstation. | Loopback only | `PUBLIC_ORIGIN=http://localhost`; do not publish it |

Public HTTP is not a supported mode. `PUBLIC_ORIGIN` refuses HTTP except for
loopback development. A public DNS name is preferred: ordinary browsers cannot
generally establish a publicly trusted TLS connection to a raw IP address. A
private/local IP can use a locally trusted CA only when that CA is installed on
every client.

## RouterOS management API and account boundary

Keep the RouterOS management endpoint reachable only from the dashboard's
private container network and explicitly trusted operator networks. Do not
publish RouterOS REST, API, or API-SSL ports to the internet. Use the encrypted
REST endpoint (`www-ssl`) and, when Binary API telemetry is enabled, the
encrypted API endpoint (`api-ssl`); do not enable plain HTTP/REST or plain API
for production. A RouterOS service `available-from` allowlist (called
`address` by older RouterOS releases) and a RouterOS user `address` restriction
are useful layers, but neither proves the effective firewall or upstream
network boundary. Verify the input-chain policy separately.

The dashboard's **Connection Doctor → RouterOS access and exposure** check is
read-only. It reports derived account/group/service facts, redacts source
ranges and service ports, reads both current and legacy service-property names,
and deliberately marks firewall enforcement
**unknown**. A restricted source field proves only that a restriction is
configured, not that it matches the dashboard's actual source address or that
the route is otherwise unreachable.

RouterOS group policy flags are broad platform permissions, not per-dashboard
feature scopes. The documented `read` flag grants configuration visibility;
`write` permits configuration changes (except user management); `api` and
`rest-api` permit their respective management transports. RouterOS documents
that default groups include privileges beyond their names—for example, the
default `read` group includes `reboot`, `test`, `sniff`, and `sensitive`.
Prefer a reviewed custom group over assuming a built-in group's name describes
its effective privileges. The dashboard's VPN management workflows need
configuration read/write access, so its account is highly privileged even when
the dashboard role is read-only. Dashboard roles limit application actions;
they do not narrow the RouterOS account's platform permissions.

This repository does **not** publish a copy-paste “minimum RouterOS group”
recipe: the exact per-operation permission behavior must be exercised against
each supported RouterOS release, including certificate and file operations,
before claiming least privilege. Do not grant `full`, `policy`, or other broad
permissions as a generic troubleshooting step. Treat missing/unsupported policy
fields as unknown, and validate a proposed custom group on a non-production
router or controlled canary before using it.

References: [MikroTik User and group policies](https://manual.mikrotik.com/docs/authentication-authorization-accounting/user/),
[RouterOS REST API](https://manual.mikrotik.com/docs/developer-guides/rest-api/),
[RouterOS `/ip/service` reference](https://manual.mikrotik.com/docs/cli-reference/ip/service/),
and [RouterOS firewall input chain](https://manual.mikrotik.com/docs/firewall-and-quality-of-service/firewall/filter/).

## Direct HTTPS with a domain

Run a maintained TLS reverse proxy on a host or container that can reach the
private dashboard address. Caddy is one supported example because a public DNS
name automatically obtains and renews TLS certificates and redirects port 80
to 443 when its DNS and ports are reachable. Keep its certificate storage
persistent.

Example `Caddyfile` (replace both placeholders):

```caddyfile
vpn.example.com {
    reverse_proxy <dashboard-private-address>:8080
}
```

The dashboard configuration must trust only the exact address it sees as that
proxy peer, not an internet range or the visitor's address:

```text
PUBLIC_ORIGIN=https://vpn.example.com
TRUST_CLOUDFLARE=false
TRUSTED_PROXY_SOURCES=<caddy-address-seen-by-dashboard>
TRUSTED_PROXY_HEADER=X-Forwarded-For
ACCESS_LAYER_LABEL=Direct HTTPS
```

`X-Forwarded-For` is read only when the TCP peer exactly matches
`TRUSTED_PROXY_SOURCES`; the dashboard uses the first address in that header.
If client-address-aware rate limiting is not needed, leave both
`TRUSTED_PROXY_SOURCES` and `TRUSTED_PROXY_HEADER` unset instead of trusting a
guess.

## Optional Cloudflare perimeter

Cloudflare remains optional. When used, its access/WAF/country controls belong
at the edge and its origin path must still terminate encrypted traffic. Keep
the existing production perimeter unchanged while introducing this image
version. Configure the dashboard only with the immediate trusted proxy address
that it sees:

```text
PUBLIC_ORIGIN=https://vpn.example.com
TRUST_CLOUDFLARE=true
TRUSTED_PROXY_SOURCES=<immediate-proxy-address-seen-by-dashboard>
# Optional: this is the backward-compatible default in Cloudflare mode.
TRUSTED_PROXY_HEADER=CF-Connecting-IP
ACCESS_LAYER_LABEL=Cloudflare Access
```

Do not send RouterOS REST management traffic or OpenVPN UDP through Cloudflare.
Cloudflare credentials, country policy, firewall/NAT rules, and identity rules
remain outside the dashboard image and repository.

### Optional Cloudflare helper

`cloudflare.py` is an offline operator helper; it is not part of the container
image and never runs during installation or deployment. Set credentials only in
your local process environment, then name the exact dashboard hostname to
inspect or change. Nothing is inferred from this repository.

```powershell
$env:CLOUDFLARE_API_TOKEN = '<local token>'
$env:CLOUDFLARE_ZONE_ID = '<zone id>'
python cloudflare.py --hostname vpn.example.com --check
```

To opt into strict TLS, an explicit country allowlist, and proxying that one A
record, add all of the requested actions deliberately:

```powershell
python cloudflare.py --hostname vpn.example.com --allow-country BG --apply-edge --proxy-dns
```

Omit `--allow-country` to leave country policy untouched. Omit `--proxy-dns`
to leave DNS unchanged. These choices are independent, so the helper cannot
silently alter a pre-existing Cloudflare hostname.

## Validation and rollback

1. Confirm the proxy has a valid certificate for `PUBLIC_ORIGIN` and that HTTP
   redirects to HTTPS.
2. Confirm the dashboard private address and RouterOS REST address are not
   publicly reachable.
3. Sign in, then verify the request log records the expected client address.
   Send a forged forwarding header directly to the dashboard; it must be
   ignored.
4. Keep the prior RouterOS environment-list values. To roll back, restore those
   values and restart only the dashboard container; persistent VPN data is not
   changed by an exposure-mode switch.
