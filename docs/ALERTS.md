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

The dashboard deduplicates the same alert for one hour, so the live five-second
poll does not fill the database with duplicates. Use **Acknowledge** after the
replacement profile has been issued and the old certificate has been revoked.
The check is read-only: it never changes RouterOS certificates automatically.

## Operational guarantees

- The inventory is queried using the authenticated RouterOS REST session.
- Alert state stays on the mounted `/data` volume with the rest of the local
  metadata.
- A missing or temporarily unavailable inventory does not create a false
  expiry alert; service health reports the unavailable check instead.
- The alert endpoint requires an authenticated dashboard session and CSRF
  protection.
