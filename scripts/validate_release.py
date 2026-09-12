"""Validate the repository release version against an optional git tag."""

from __future__ import annotations

import argparse
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SEMVER = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")


def read_version() -> str:
    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    if not SEMVER.fullmatch(version):
        raise SystemExit(f"VERSION must contain semantic version MAJOR.MINOR.PATCH, got {version!r}")
    return version


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", help="optional tag to validate, for example v1.10.0")
    args = parser.parse_args()
    version = read_version()
    if args.tag and args.tag != f"v{version}":
        raise SystemExit(f"release tag {args.tag!r} does not match VERSION v{version}")
    print(f"release version: v{version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
