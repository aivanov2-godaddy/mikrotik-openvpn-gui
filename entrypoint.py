"""Select the production HTTP runtime without changing application routes."""

from __future__ import annotations

import os


def main() -> int:
    engine = os.environ.get("SOCKETIO_ENGINE", "asgi").strip().casefold()
    if engine == "asgi":
        from asgi import main as asgi_main

        asgi_main()
        return 0
    if engine == "polling":
        from app import main as app_main

        app_main()
        return 0
    raise SystemExit("SOCKETIO_ENGINE must be asgi or polling")


if __name__ == "__main__":
    raise SystemExit(main())
