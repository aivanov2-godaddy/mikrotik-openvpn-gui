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
