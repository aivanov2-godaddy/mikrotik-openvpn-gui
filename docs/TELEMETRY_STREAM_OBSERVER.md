# Canary telemetry stream observer

`scripts/telemetry_stream_observer.py` passively observes the authenticated
Socket.IO/WebSocket stream for a canary or development deployment. It does not
call RouterOS, modify configuration, disconnect clients, or write event
payloads. The report contains aggregate event counts, connection lifecycle,
and sequence-gap/duplicate/order checks only.

The observer accepts only HTTPS origins whose first hostname label contains
`dev` or `canary`; a production-looking host such as `vpn.example.test` is
rejected. Supply a short-lived dashboard `Cookie` header through a named
environment variable, not a command-line argument. That cookie is sent only to
the explicitly supplied HTTPS origin and is never written to the report or
logs. Keep the output file private because it records deployment timing and
operational evidence.

Example invocation (provide the cookie through the operating system's secret
or environment injection mechanism, not shell history):

```text
python scripts/telemetry_stream_observer.py --canary-origin https://vpn-dev.example.test --cookie-env VPN_CANARY_COOKIE --duration-seconds 1800 --output private-canary-stream.json
```

This is partial evidence, not a release-acceptance pass. The observer does not
measure RouterOS-to-dashboard latency: the client/server clock offset is not
established. It also cannot prove that a human-visible page updated without a
refresh, that REST/Binary snapshots match, or that counter reset and
unauthenticated-access tests passed. Those checks must be collected by the
separate acceptance procedures; missing evidence must remain a failure.

Unknown event names or payload fields are rejected fail-closed. Raw event
frames, usernames, addresses, identifiers, and credential values are not
included in its output.
