# Canary telemetry stream observer

`scripts/telemetry_stream_observer.py` passively observes the authenticated
Socket.IO/WebSocket stream for the configured canary deployment. It does not
call RouterOS, modify configuration, disconnect clients, or write event
payloads. The report contains aggregate event counts, connection lifecycle,
and sequence-gap/duplicate/order checks only.

The observer accepts only the exact HTTPS origin `https://vpn-dev.wanted.sx`
(with an optional trailing slash or explicit default port 443). Lookalike
domains, alternate ports, paths, query strings, and credentials are rejected
before any request is made. Supply a short-lived dashboard `Cookie` header
through a named environment variable, not a command-line argument. The
observer first reads only the authenticated `/api/observability` runtime
revision, refuses redirects, and does not start the stream unless the revision
matches the candidate SHA. It then sends the cookie only to that pinned host;
the cookie and API response are never written to the report or logs. Keep the
output file private because it records deployment timing and operational
evidence.

Example invocation (provide the cookie through the operating system's secret
or environment injection mechanism, not shell history):

```text
python scripts/telemetry_stream_observer.py --canary-origin https://vpn-dev.wanted.sx --expected-revision <40-character-candidate-sha> --cookie-env VPN_CANARY_COOKIE --duration-seconds 1800 --output private-canary-stream.json
```

This is partial evidence, not a release-acceptance pass. The observer does not
measure RouterOS-to-dashboard latency: the client/server clock offset is not
established. It also cannot prove that a human-visible page updated without a
refresh, that REST/Binary snapshots match, or that counter reset and
unauthenticated-access tests passed. The browser acceptance projection retains
the allowlisted verification map and security-test count so missing or false
checks remain visible and fail closed; these values are still operator-collected
evidence and must not be represented as an independent security assessment.

Unknown event names or payload fields are rejected fail-closed. Raw event
frames, usernames, addresses, identifiers, and credential values are not
included in its output.
