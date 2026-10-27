# Redis Streams ACL migration and credential rotation on RouterOS

This procedure moves the dashboard publisher from Redis's shared `default`
ACL identity to a dedicated least-privilege `vpn-dashboard` identity, then
describes future password rotations for that dedicated user. It does not put
a password in the repository, a support ticket, or chat. The migration keeps
the current identity as a temporary rollback path until both publishers use
the new one. Schedule Redis restarts in a quiet maintenance window.

## Before starting

- Confirm the Redis ACL file is mounted into the Redis container and is the
  file configured as its ACL file. Paths and container names are installation
  specific; use the existing setup rather than creating a second Redis service.
- Confirm Redis persistence and its data mount, and take a tested backup if
  retained stream history matters. Restarting Redis disconnects publishers;
  SQLite retries pending outbox events, but it cannot reconstruct stream
  entries already acknowledged before Redis lost them.
- Use an authenticated RouterOS account limited to the required container,
  file, and environment-list operations. RouterOS container environment values
  contain the Redis URL in plaintext even with TLS; restrict who may inspect it.
- The dashboard app appends sanitized events to `vpn-dashboard.events` and
  coordinates reviewed RouterOS user mutations across instances. Give its
  dedicated `vpn-dashboard` ACL identity access only to the event stream and
  `vpn-dashboard.review.*` coordination keys. It needs `HELLO` for its RESP3
  handshake, `PING`, `XADD`, `GET`, `SET`, `INCR`, `DEL`, `EVAL`, `PEXPIRE`,
  and `INFO`. redis-py 8.1.0 also attempts optional `CLIENT SETINFO`; allow the
  `setinfo` subcommand on Redis 7.2 or newer. The client tolerates denial on
  older Redis versions. Do not grant the broad `+@connection` category. `INFO`
  detects a Redis process restart; the dashboard fails closed until restarted.
  Do not leave the application on Redis's `default` identity after migration.
- Do not continue if the Redis ACL file, data directory, or persistence mode
  cannot be identified. Do not paste passwords or hashes into screenshots,
  tickets, issues, pull requests, or chat.

## Redis transport and command permissions

The application pins `redis-py==8.1.0`. Its default RESP3 handshake uses
`HELLO`; with the documented `/0` URL, it does not issue `SELECT`. The publisher
uses `PING` and `XADD`; the shared mutation coordinator also uses `GET`, `SET`,
`INCR`, `DEL`, `EVAL`, `PEXPIRE`, and `INFO`. Grant only those commands and
scope keys to `vpn-dashboard.events` and `vpn-dashboard.review.*`.

On Redis 7.2 and newer, redis-py may also send optional `CLIENT SETINFO`; add
`+client|setinfo`. On Redis 6.0 through 7.1, omit that subcommand grant. A
denied or unsupported `CLIENT SETINFO` response is ignored by redis-py. Do not
grant `+@connection`, which includes unrelated connection and client-control
commands.

`redis://` remains supported for existing deployments on an isolated, trusted
private container network. It does not encrypt credentials or event data in
transit; startup logs a warning without exposing the URL. Use it only when
Redis is not reachable from an untrusted network. `rediss://` enables TLS
transport. The dashboard client explicitly requires certificate validation and
hostname checking; configure a trusted CA when needed. The startup log reports
the TLS mode without exposing the URL. TLS does not encrypt the URL stored in
RouterOS environment configuration.

## Generate a replacement password locally

In Windows PowerShell, paste this entire block at once and press Enter. It
prints a 256-bit random password as 64 URL-safe hexadecimal characters and the
SHA-256 digest Redis needs for its ACL file. The password and digest are
different values; keep them paired privately.

```powershell
$bytes = New-Object byte[] 32
$rng = [Security.Cryptography.RandomNumberGenerator]::Create()
$sha = [Security.Cryptography.SHA256]::Create()
try {
    $rng.GetBytes($bytes)
    $password = [BitConverter]::ToString($bytes).Replace('-', '').ToLowerInvariant()
    $digest = [BitConverter]::ToString(
        $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($password))
    ).Replace('-', '').ToLowerInvariant()
    Write-Output ("REDIS_PASSWORD=" + $password)
    Write-Output ("REDIS_SHA256=" + $digest)
}
finally {
    [Array]::Clear($bytes, 0, $bytes.Length)
    $rng.Dispose()
    $sha.Dispose()
    Remove-Variable password, digest -ErrorAction SilentlyContinue
}
```

The `REDIS_PASSWORD` value goes only in the RouterOS `REDIS_STREAM_URL` value
for user `vpn-dashboard`. The `REDIS_SHA256` value goes after `#` in that
user's Redis ACL rule. Do not paste the labels (`REDIS_PASSWORD=` or
`REDIS_SHA256=`) into either destination. The 64-character hex password needs
no URL escaping. Avoid PowerShell transcription/screen recording; clear
clipboard and terminal scrollback after the changes, and do not save either
value in a scratch file.

## Migrate from the current `default` ACL identity

Perform this once if either dashboard environment currently uses the Redis
`default` username. Keep the current `default` ACL rule unchanged as rollback
until both publishers have been switched and verified. Add a second rule for
the app-specific account:

```text
<EXACT_EXISTING_DEFAULT_RULE>
user vpn-dashboard on #NEW_SHA256 ~vpn-dashboard.events ~vpn-dashboard.review.* +hello +ping +xadd +get +set +incr +del +eval +pexpire +info +client|setinfo
```

Replace `<EXACT_EXISTING_DEFAULT_RULE>` with the complete current `default`
line, byte-for-byte; do not change its permissions during this migration. The
app user is scoped to the event and review key patterns and the commands it
needs. If Redis is older than 7.2, omit `+client|setinfo`. Preserve all other
ACL lines too. RouterOS Terminal can write a CRLF between the lines using the
documented `\r\n` string escape:

```routeros
:local eol "\r\n"; /file set [find where name="<REDIS_FOLDER>/acl.txt"] contents=("<EXACT_EXISTING_DEFAULT_RULE>".$eol."user vpn-dashboard on #NEW_SHA256 ~vpn-dashboard.events ~vpn-dashboard.review.* +hello +ping +xadd +get +set +incr +del +eval +pexpire +info +client|setinfo")
```

Replace the path, existing-rule placeholder, and digest locally. If Redis is
older than 7.2, omit `+client|setinfo`. Verify the complete file contents
before loading the ACL. Apply
the file using the configured trusted Redis administrative path, or restart
Redis after confirming its data directory, persistence, backup, and maintenance
window. A file edit alone does not prove the running Redis process loaded it.

Switch canary first, using a URL with the dedicated username:

```text
redis://vpn-dashboard:<NEW_PASSWORD>@<PRIVATE_REDIS_HOST>:6379/0
```

Restart only canary; wait for RouterOS healthy status and verify an authenticated
Redis publish-success metric. If it fails, restore canary's old `default` URL
while the old ACL rule is still active. When canary passes, update and restart
production and repeat the checks. Keep production on its existing URL until
canary has passed.

After both environments use `vpn-dashboard` successfully, replace the old
`default` rule with `user default off` and apply the ACL. If any separate Redis
administrative workflow depends on the `default` user, first establish and
test a different restricted administrative path; do not disable the only
maintenance access. Restart Redis so existing authenticated `default` sessions
are closed, then verify Redis healthy and both dashboard publishers reconnect
as `vpn-dashboard`. SQLite retains pending events across the restart, but Redis
cannot reconstruct entries already acknowledged before data loss.

## Stage the ACL change

For future rotations, preserve the dedicated username, stream key, command set,
and file path. The `vpn-dashboard` rule should temporarily contain both
SHA-256 hashes, for example:

```text
user vpn-dashboard on #OLD_SHA256 #NEW_SHA256 ~vpn-dashboard.events ~vpn-dashboard.review.* +hello +ping +xadd +get +set +incr +del +eval +pexpire +info +client|setinfo
```

Replace `OLD_SHA256` with the old digest for user `vpn-dashboard` and
`NEW_SHA256` with the newly generated digest; do not type the placeholder
labels or angle brackets. Keep the leading `#` before each digest. The `~`
before the stream key is literal: do not add a backslash. `#` is part of the
ACL hash rule, not a comment when it appears on this `user` line.
If Redis is older than 7.2, omit `+client|setinfo`.

If editing through RouterOS Terminal, use the actual RouterOS property name
`name` (not Markdown bold markers like `**name**`) and paste the command as a
single line. Substitute only the path and generated digest values:

```routeros
/file set [find where name="<REDIS_FOLDER>/acl.txt"] contents="user vpn-dashboard on #OLD_SHA256 #NEW_SHA256 ~vpn-dashboard.events ~vpn-dashboard.review.* +hello +ping +xadd +get +set +incr +del +eval +pexpire +info +client|setinfo"
```

Use the existing exact file path; do not create a second ACL file or alter the
stream key/permissions during credential rotation. Redis supports multiple
active passwords per ACL user, allowing this overlap. Apply the file through
the existing authorized mechanism: use `ACL LOAD` through a trusted Redis
administrative channel if one is configured, or restart the Redis container
after verifying persistence/backup and entering the maintenance window. A
plain file edit alone does not prove the running Redis process loaded it.

## Switch one dashboard container at a time

1. Change only the canary environment list's `REDIS_STREAM_URL` to use the new
   password. Keep the dedicated username `vpn-dashboard`, private Redis
   address, port, and database number. For an isolated private network, the URI
   shape is `redis://vpn-dashboard:<NEW_PASSWORD>@<PRIVATE_REDIS_HOST>:6379/0`;
   it does not encrypt traffic. Use `rediss://` for a TLS-enabled endpoint with
   a trusted certificate.
   If you cannot use the RouterOS environment-list editor, the equivalent
   RouterOS Terminal form is below. Replace the placeholders; do not type the
   angle brackets. This command contains the plaintext password and may remain
   in RouterOS command history, so use a restricted operator session and
   remove that history entry after the change if your local policy requires it.

   ```routeros
   /container/envs/set [find where list="<CANARY_ENV_LIST>" and key="REDIS_STREAM_URL"] value="redis://vpn-dashboard:NEW_PASSWORD@<PRIVATE_REDIS_HOST>:6379/0"
   ```

2. Restart only the canary dashboard container so it reads its updated
   environment. In RouterOS Terminal, substitute its exact container name:

   ```routeros
   /container/stop [find where name="<CANARY_CONTAINER>"]
   /container/start [find where name="<CANARY_CONTAINER>"]
   ```

   Wait for RouterOS status `H` and for the dashboard to publish a normal
   audit/outbox event.
3. In authenticated metrics, verify
   `vpn_dashboard_redis_last_observed_available 1`; check that
   `vpn_dashboard_redis_publish_total{outcome="failure"}` does not increase.
   A value of `-1` means no publish has tested the connection yet, so it is not
   a successful rotation check. Do not use container health alone as proof of
   Redis authentication.
4. If canary passes, apply the same environment update and restart to
   production, substituting the production environment-list and container
   names; repeat the checks. If canary fails, restore its previous URL while
   the old hash is still present, restart canary, and investigate before
   touching production.

When both dashboard containers use the new password and publish successfully,
remove the old hash from the ACL file, leaving only the new one:

```text
user vpn-dashboard on #NEW_SHA256 ~vpn-dashboard.events ~vpn-dashboard.review.* +hello +ping +xadd +get +set +incr +del +eval +pexpire +info +client|setinfo
```

Apply the changed ACL file. Removing an old password prevents new
authentications with it, but does not by itself disconnect clients already
authenticated under that user. Revoke those old connections using a trusted
Redis administrative channel (`CLIENT KILL USER vpn-dashboard`) or restart Redis
after confirming persistence/backup. This disconnects both dashboard
publishers briefly; verify canary and production reconnect using the new URL
and repeat the authenticated Redis metrics checks. Do not disable the only
administrative Redis access path while applying this procedure.

## Verify and clean up

- Confirm canary and production have the intended environment-list names,
  their containers return to healthy status, Redis publish success is observed,
  and failure counts remain stable.
- Check that no temporary ACL copy or exported file contains a plaintext
  password. Keep only the current ACL hash in the mounted ACL file.
- Clear the clipboard and terminal scrollback and close any scratch editor used
  to pair the password with its hash.
- Keep the previous password out of active config and delete obsolete copies
  of its hash from the ACL file after successful validation.

## References

- MikroTik [Container](https://manual.mikrotik.com/docs/containers/) documents
  RouterOS container environment lists; [Files](https://manual.mikrotik.com/docs/system-information-and-utilities/files/)
  and [Scripting](https://help.mikrotik.com/docs/spaces/ROS/pages/47579229/Scripting)
  document RouterOS file operations and `\r\n` string escapes.
- Redis [ACL documentation](https://redis.io/docs/latest/management/security/acl/)
  documents SHA-256 ACL hashes, multiple active passwords, and reloading an
  ACL file; [`ACL SETUSER`](https://redis.io/docs/latest/commands/acl-setuser/)
  documents password and connection behavior.
- Redis [`XADD`](https://redis.io/docs/latest/commands/xadd/) is the stream
  append command used by this publisher.
- The pinned [redis-py 8.1.0 connection setup](https://github.com/redis/redis-py/blob/v8.1.0/redis/connection.py)
  and [RESP default](https://github.com/redis/redis-py/blob/v8.1.0/redis/utils.py)
  document its HELLO negotiation, optional client metadata, and database
  selection behavior used to derive the command grants above.
