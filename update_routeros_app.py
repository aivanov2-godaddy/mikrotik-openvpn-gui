"""Retired entry point for the unsafe host-mounted source update workflow."""

from __future__ import annotations

import sys


RETIREMENT_MESSAGE = """Direct source-file deployment is retired and no changes were made.

This project now ships as immutable architecture-specific images from GHCR. The
legacy updater modified a host-mounted /app directory and restarted a container
in place, bypassing CI, image identity, canary isolation, and reliable rollback.

Use deploy_routeros_canary.py to render an offline immutable-image canary plan,
then follow docs/DEPLOYMENT.md and docs/ROLLBACK.md. This command has no override.
"""


def main() -> int:
    print(RETIREMENT_MESSAGE, file=sys.stderr)
    return 64


if __name__ == "__main__":
    raise SystemExit(main())
