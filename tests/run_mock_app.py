from __future__ import annotations

import argparse
import tempfile

from app import AppContext, DashboardServer
from routeros import RouterOSClient
from security import LoginRateLimiter, SessionStore
from store import MetadataStore
from tests.mock_routeros import MockRouterOS


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=18080)
    arguments = parser.parse_args()

    with tempfile.TemporaryDirectory() as temporary, MockRouterOS() as mock:
        context = AppContext(
            router=RouterOSClient(mock.url),
            store=MetadataStore(f"{temporary}/dashboard.sqlite"),
            sessions=SessionStore(),
            limiter=LoginRateLimiter(),
            public_origin="https://vpn.wanted.sx",
        )
        server = DashboardServer(("127.0.0.1", arguments.port), context)
        print(f"mock dashboard ready at http://127.0.0.1:{arguments.port}", flush=True)
        try:
            server.serve_forever()
        finally:
            server.server_close()


if __name__ == "__main__":
    main()
