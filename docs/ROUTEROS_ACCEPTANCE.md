# RouterOS canary acceptance test

Use this procedure after public CI has passed and before an operator promotes a
new immutable image from canary to production. It is a repeatable, redacted
hardware-in-the-loop check; it complements the repository's automated tests.

The procedure is deliberately read-only except for the disposable canary
container and a disposable VPN profile. Do not paste router exports, passwords,
private keys, certificates, profile archives, public IP addresses, or real
domain names into an issue, pull request, or test result.

## Scope and prerequisites

- Use one immutable candidate such as
  `ghcr.io/<owner>/mikrotik-openvpn-gui:sha-<40-character-commit>-arm64`.
  Record the exact tag and digest. The `/readyz` revision must identify that
  same candidate.
- Use RouterOS 7 with the Container package enabled. ARM64 hardware uses the
  `-arm64` image; CHR/x86 evaluation uses `-amd64`. ARM32 is unsupported.
- Use a canary router, CHR, or an isolated maintenance window. Take an
  encrypted RouterOS backup first.
- Keep `/data` (SQLite state) and `/config` (trust material) on dedicated
  router storage mounts. Reuse neither a production mount nor a root filesystem
  path for the canary.
- Use a disposable dashboard account and VPN profile. Keep management access on
  HTTPS and keep the router REST service private.

## Record the environment

Redact names, addresses, serials, and mount paths before attaching results.
Record only the facts needed to reproduce a compatibility result:

```routeros
/system/resource/print
/system/package/print where name~"container"
/container/print detail
```

Include RouterOS version, architecture, candidate tag/digest, and whether the
test is physical ARM64 or CHR/x86.

## Acceptance checklist

| Check | Pass condition | Evidence to record |
| --- | --- | --- |
| Image and state | Container reaches `running` using the exact pinned candidate. | Tag, digest, and redacted container state. |
| Readiness | Private `/readyz` reports `ready` and the expected immutable revision. | Status and revision only. |
| Router reachability | Dashboard service-health view can read RouterOS through the configured private path. | Pass/review/fail only. |
| Dashboard exposure | HTTPS or direct-IP access matches the chosen installation path; REST is not public. | Chosen path and pass/fail. |
| OpenVPN inventory | Existing service and certificate inventory load without mutation. | Counts only. |
| Disposable profile | Create, download, and validate one disposable profile; then remove or suspend it. | Action outcomes, never the profile. |
| Persistence | Restart the canary container; dashboard state remains on its mounted `/data`. | Restart and pass/fail. |
| Rollback | Previous immutable candidate can be selected and started. | Previous revision and pass/fail. |

For a private VETH path, probe only from an approved management host or the
router-local controller. An example is:

```text
http://<private-container-address>:8080/readyz
```

Do not expose that probe to the public internet. A production controller should
validate the revision before it promotes the candidate.

## Rollback rehearsal

Keep the previous immutable image reference before updating the canary. If the
candidate does not pass, stop it and restore that exact prior reference:

```routeros
/container/stop [find where name="vpn-dashboard-canary"]
/container/set [find where name="vpn-dashboard-canary"] remote-image="ghcr.io/<owner>/mikrotik-openvpn-gui:sha-<previous-commit>-arm64"
/container/update [find where name="vpn-dashboard-canary"]
/container/start [find where name="vpn-dashboard-canary"]
```

Replace the examples locally. Do not commit real values. Confirm the restored
container becomes ready before ending the maintenance window.

## Redacted result template

```text
Candidate revision: sha-<40-character-commit>
Image digest: sha256:<digest>
RouterOS: <major.minor.patch> / <architecture>
Environment: physical ARM64 | CHR/x86
Readiness: pass | review | fail
Dashboard-to-RouterOS read: pass | review | fail
Disposable profile lifecycle: pass | review | fail
Persistence after restart: pass | review | fail
Rollback rehearsal: pass | review | fail
Notes: <no credentials, addresses, hosts, profiles, or exports>
```

Promote only a fully passing candidate through the operator-installed
[router-local automation](ROUTER_LOCAL_AUTOMATION.md). If a check needs review,
leave production on its current immutable image and investigate in the local
router environment.
