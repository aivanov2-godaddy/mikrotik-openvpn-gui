from __future__ import annotations

import argparse
import tempfile

from app import AppContext, DashboardServer
from config import RuntimeConfig
from routeros import RouterOSClient
from security import LoginRateLimiter, SessionStore
from store import MetadataStore
from tests.mock_routeros import MockRouterOS


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=18080)
    arguments = parser.parse_args()

    with tempfile.TemporaryDirectory() as temporary, MockRouterOS() as mock:
        config = RuntimeConfig.from_environ(
            {
                "PUBLIC_ORIGIN": f"http://127.0.0.1:{arguments.port}",
                "ROUTEROS_REST_URL": "https://router.example.test:8443/rest",
                "OVPN_PPP_PROFILE": "vpn-full-tunnel",
                "OVPN_SERVER_NAME": "vpn-server",
                "OVPN_CA_NAME": "vpn-ca",
                "OVPN_HOST": "vpn.example.test",
                "VPN_LAN_CIDR": "192.0.2.0/24",
                "VPN_ROUTER_DNS": "192.0.2.1",
            }
        )
        context = AppContext(
            router=RouterOSClient(mock.url, topology=config.topology),
            store=MetadataStore(f"{temporary}/dashboard.sqlite"),
            sessions=SessionStore(),
            limiter=LoginRateLimiter(),
            config=config,
        )
        # Synthetic, redacted-only history for the rendered correlation-link
        # regression. The fixture never leaves the local mock server.
        context.store.set_audit_hook(lambda _event: None)
        context.store.audit(
            actor="mock-owner", action="user.update", target="user-two", status="success",
        )
        context.store.observe_sessions([{
            "id": "*A1", "name": "user-two", "source_address": "192.0.2.8",
            "vpn_address": "10.8.0.8", "encoding": "AES-256-GCM",
            "uptime": "1m", "rx_bytes": 1024, "tx_bytes": 2048,
            "rx_packets": 10, "tx_packets": 20,
        }])
        server = DashboardServer(("127.0.0.1", arguments.port), context)
        print(f"mock dashboard ready at http://127.0.0.1:{arguments.port}", flush=True)
        try:
            server.serve_forever()
        finally:
            server.server_close()


if __name__ == "__main__":
    main()
