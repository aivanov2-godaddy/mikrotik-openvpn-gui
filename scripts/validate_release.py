"""Validate the repository release version against an optional git tag."""

from __future__ import annotations

import argparse
import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SEMVER = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")


def read_version() -> str:
    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    if not SEMVER.fullmatch(version):
        raise SystemExit(f"VERSION must contain semantic version MAJOR.MINOR.PATCH, got {version!r}")
    return version


def validate_main_ancestry(main_ref: str) -> None:
    result = subprocess.run(
        ["git", "merge-base", "--is-ancestor", "HEAD", main_ref],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode == 1:
        raise SystemExit(f"release commit is not reachable from {main_ref}")
    if result.returncode != 0:
        raise SystemExit(f"could not verify release commit ancestry against {main_ref}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", help="optional tag to validate, for example v1.10.0")
    parser.add_argument(
        "--main-ref",
        help="require HEAD to be an ancestor of this verified default-branch ref",
    )
    args = parser.parse_args()
    version = read_version()
    if args.tag and args.tag != f"v{version}":
        raise SystemExit(f"release tag {args.tag!r} does not match VERSION v{version}")
    if args.main_ref:
        validate_main_ancestry(args.main_ref)
    print(f"release version: v{version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
