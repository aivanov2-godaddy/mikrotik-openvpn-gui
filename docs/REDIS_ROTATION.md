# Redis Streams credential rotation on RouterOS

This procedure rotates the Redis credential used by this dashboard without
putting a password in the repository, a support ticket, or chat. It uses a
temporary overlap: Redis accepts both passwords while canary and production
are switched, then the old password is removed and old Redis connections are
closed. Schedule the Redis restart in a quiet maintenance window.

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
  contain the Redis URL in plaintext; restrict who may inspect that config.
- Do not continue if the Redis ACL file, data directory, or persistence mode
  cannot be identified. Do not paste passwords or hashes into screenshots,
  tickets, issues, pull requests, or chat.

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

The `REDIS_PASSWORD` value goes only in the RouterOS `REDIS_STREAM_URL` value.
The `REDIS_SHA256` value goes after `#` in the Redis ACL file. Do not paste
the labels (`REDIS_PASSWORD=` or `REDIS_SHA256=`) into either destination.
The 64-character hex password needs no URL escaping. Avoid PowerShell
transcription/screen recording; clear clipboard and terminal scrollback after
the changes, and do not save either value in a scratch file.

## Stage the ACL change

Preserve the current username, stream key, command set, and file path. For the
existing `default` ACL user, the file's single user line should temporarily
contain both SHA-256 hashes, for example:

```text
user default on #OLD_SHA256 #NEW_SHA256 ~vpn-dashboard.events +@connection +xadd +ping
```

Replace `OLD_SHA256` with the digest already in the ACL file and `NEW_SHA256`
with the newly generated digest; do not type the placeholder labels or angle
brackets. Keep the leading `#` before each digest. The `~` before the stream
key is literal: do not add a backslash. `#` is part of the ACL hash rule, not a
comment when it appears on this `user` line.

If editing through RouterOS Terminal, use the actual RouterOS property name
`name` (not Markdown bold markers like `**name**`) and paste the command as a
single line. Substitute only the path and generated digest values:

```routeros
/file set [find where name="<REDIS_FOLDER>/acl.txt"] contents="user default on #OLD_SHA256 #NEW_SHA256 ~vpn-dashboard.events +@connection +xadd +ping"
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
   password. Keep the existing username, private Redis address, port, and
   database number. For the `default` ACL user, the URI shape is
   `redis://default:<NEW_PASSWORD>@<PRIVATE_REDIS_HOST>:6379/0`.
   If you cannot use the RouterOS environment-list editor, the equivalent
   RouterOS Terminal form is below. Replace the placeholders; do not type the
   angle brackets. This command contains the plaintext password and may remain
   in RouterOS command history, so use a restricted operator session and
   remove that history entry after the change if your local policy requires it.

   ```routeros
   /container/envs/set [find where list="<CANARY_ENV_LIST>" and key="REDIS_STREAM_URL"] value="redis://default:NEW_PASSWORD@<PRIVATE_REDIS_HOST>:6379/0"
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
user default on #NEW_SHA256 ~vpn-dashboard.events +@connection +xadd +ping
```

Apply the changed ACL file. Removing an old password prevents new
authentications with it, but does not by itself disconnect clients already
authenticated under that user. Revoke those old connections using a trusted
Redis administrative channel (`CLIENT KILL USER default`) or restart Redis
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
  and [Scripting examples](https://manual.mikrotik.com/docs/developer-guides/scripting/scripting-examples/)
  document RouterOS file operations.
- Redis [ACL documentation](https://redis.io/docs/latest/management/security/acl/)
  documents SHA-256 ACL hashes, multiple active passwords, and reloading an
  ACL file; [`ACL SETUSER`](https://redis.io/docs/latest/commands/acl-setuser/)
  documents password and connection behavior.
- Redis [`XADD`](https://redis.io/docs/latest/commands/xadd/) is the stream
  append command used by this publisher.
