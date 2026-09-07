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
                "PUBLIC_ORIGIN": "http://localhost",
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
        server = DashboardServer(("127.0.0.1", arguments.port), context)
        print(f"mock dashboard ready at http://127.0.0.1:{arguments.port}", flush=True)
        try:
            server.serve_forever()
        finally:
            server.server_close()


if __name__ == "__main__":
    main()
