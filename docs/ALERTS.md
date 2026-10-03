# Dashboard alerts

The dashboard turns read-only RouterOS checks into persistent, dismissible
alerts. Alerts are stored in the router-local SQLite metadata database; they
are not published to GitHub and do not contain passwords, private keys, VPN
profiles, or RouterOS configuration.

## Certificate expiry alerts

Each service-health refresh reads the configured OpenVPN client-certificate
inventory. A certificate that has expired creates a critical alert. A
certificate with 30 days or less remaining creates a warning. Alerts include
only the certificate name, expiry timestamp, and the safe replacement action.

The dashboard groups an unacknowledged alert with the same action and target
for one hour. Recurrences update the latest safe title/details, last-seen time,
and observation count on that alert; out-of-order older observations increase
the count without replacing newer details, and a higher severity is retained
instead of being downgraded. The row shows when it was last seen and exposes
the first-seen time in its accessible label and hover text, so operators can
distinguish a continuing incident from a new alert. Acknowledging closes the
group; a later observation starts a new alert. Each action is also capped at
ten new alert records per minute, so repeated live polls and bursts across many
targets do not overwhelm the alert list. Grouping and alert throttling never
suppress durable audit or integration outbox writes. Alert targets remain in
the authenticated dashboard alert record and are not emitted as metric labels
or log fields. Use **Acknowledge** after
the replacement profile has been issued and the old certificate has been
revoked. The check is read-only: it never changes RouterOS certificates
automatically.

## Operational guarantees

- The inventory is queried using the authenticated RouterOS REST session.
- Alert state stays on the mounted `/data` volume with the rest of the local
  metadata.
- A missing or temporarily unavailable inventory does not create a false
  expiry alert; service health reports the unavailable check instead.
- The alert endpoint requires an authenticated dashboard session and CSRF
  protection.
