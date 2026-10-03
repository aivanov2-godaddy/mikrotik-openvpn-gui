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

The dashboard deduplicates the same alert for one hour and caps each alert
action at ten new notifications per minute, so repeated live polls and bursts
across many targets do not overwhelm the alert list. Alert throttling applies
only to actionable alerts; it does not alter the durable audit or integration
outbox paths. Alert targets remain in the authenticated dashboard alert record
and are not emitted as metric labels or log fields. Use **Acknowledge** after
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
