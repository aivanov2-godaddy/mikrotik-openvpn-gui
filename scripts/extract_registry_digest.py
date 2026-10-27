"""Extract one unambiguous OCI image digest from Docker push output."""

from __future__ import annotations

import re
import sys


DIGEST_PATTERN = re.compile(r"\bdigest:\s*(sha256:[0-9a-f]{64})(?=\s|$)")


def extract_registry_digest(output: str) -> str:
    """Return the sole digest emitted by Docker, tolerating tag-prefixed lines."""
    digests = set(DIGEST_PATTERN.findall(output))
    if not digests:
        raise ValueError("Docker push output did not contain a canonical SHA-256 digest")
    if len(digests) != 1:
        raise ValueError("Docker push output contained multiple different image digests")
    return digests.pop()


def main() -> int:
    try:
        digest = extract_registry_digest(sys.stdin.read())
    except ValueError as error:
        print(str(error), file=sys.stderr)
        return 1
    print(digest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
