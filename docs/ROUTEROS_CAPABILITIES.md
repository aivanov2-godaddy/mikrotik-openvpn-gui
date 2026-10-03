# RouterOS OpenVPN capability reference

Connection Doctor intentionally evaluates only facts it can observe over the
read-only RouterOS API. It does not change configuration or claim to test a
client's internet, DNS, firewall, or destination reachability.

The compatibility checks follow the current [MikroTik RouterOS OpenVPN manual](https://manual.mikrotik.com/docs/virtual-private-networks/openvpn/) and [OpenVPN server CLI reference](https://manual.mikrotik.com/docs/cli-reference/interface/ovpn-server/server/):

- RouterOS v7 documents both TCP and UDP OpenVPN transport. A v6 device using
  UDP is reported unsupported; unknown/malformed versions remain unknown.
- Documented server ciphers are `aes128-cbc`, `aes128-gcm`, `aes192-cbc`,
  `aes192-gcm`, `aes256-cbc`, `aes256-gcm`, `blowfish128`, and `null`.
- Documented authentication methods are `md5`, `sha1`, `sha256`, `sha384`, `sha512`,
  and `null`. This is a compatibility allowlist, not a recommendation that
  legacy algorithms be enabled.
- Push routes are documented from RouterOS 7.14; IPv6 push-route support is
  documented from 7.21_ab220. TLS-crypt support is documented from 7.17rc3
  with specific authentication and key-direction requirements.
- RouterOS implements only a subset of OpenVPN features. In particular, the
  manual notes that compression is unsupported and cipher negotiation must be
  explicit in the client profile. Connection Doctor does not infer that an
  unsupported feature is in use unless the corresponding setting is observable.
- GCM with non-null authentication is version-sensitive: MikroTik documents
  support beginning with 7.17beta5. Earlier versions receive a warning; the
  diagnostic does not recommend weakening the cipher policy.

Every result reports its source, observation time, freshness, and confidence.
Missing permissions, malformed data, or unavailable RouterOS responses become
`unknown`, never an inferred pass. Any improvement to this map must cite the
current MikroTik manual and add tests for the relevant RouterOS version bounds.

Certificate inventory treats RouterOS' `revoked` property as a revocation
timestamp: any populated value means revoked, while an empty value or an
explicit `no`/`false` means not revoked. This follows the current
[MikroTik certificate reference](https://manual.mikrotik.com/docs/authentication-authorization-accounting/certificates/).

## Management account and service exposure diagnostics

The read-only Exposure Doctor reports derived facts about the signed-in
RouterOS account, its group policy flags, and the `www`, `www-ssl`, `api`,
`api-ssl`, `telnet`, `ftp`, `ssh`, and `winbox` service records. The RouterOS
`/ip service` `address` property is a service-level source allowlist; MikroTik
documents that non-matching connections are denied by the service, but also
recommends firewall rules to block untrusted or external sources. Therefore a
configured service allowlist is not reported as proof of the effective
firewall/network boundary. The diagnostic deliberately leaves that check
`unknown` until the input-chain and upstream policy are independently
verified.

RouterOS user-group `policy` flags are a coarse RouterOS permission boundary,
not a per-dashboard-feature authorization map. The diagnostic shows only a
small explanation of recognized effective flags; it does not recommend
granting `write`, `policy`, or other broad permissions as a generic fix. If a
new RouterOS version returns an unrecognized policy token or omits required
fields, the permission posture is `unknown`, not a complete/verified result.
Raw account, group, service, address, certificate, and firewall records are
not included in the report.

This interpretation follows MikroTik's current primary references for
[`/ip/service`](https://manual.mikrotik.com/docs/cli-reference/ip/service/)
and [RouterOS users and groups](https://manual.mikrotik.com/docs/authentication-authorization-accounting/user/).
The diagnostic reads the current `available-from` service property and retries
the deprecated `address` spelling when an older RouterOS version rejects it.
In either case only the derived restriction status is exposed, never the range.
Because RouterOS service properties and permission behavior can vary by
version, the diagnostic is advisory and read-only; verify effective access at
the router and network boundary before treating exposure as resolved.
