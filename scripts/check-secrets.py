"""Fail on high-confidence secret material without printing the matched value."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SKIP_DIRECTORIES = {
    ".git",
    ".secrets",
    ".venv",
    "__pycache__",
    "data",
    "dist",
    "exports",
    "venv",
}
SKIP_SUFFIXES = {
    ".db",
    ".gif",
    ".ico",
    ".jpeg",
    ".jpg",
    ".log",
    ".ovpn",
    ".p12",
    ".pfx",
    ".png",
    ".pyc",
    ".sqlite",
    ".sqlite3",
    ".zip",
}
MAX_TEXT_BYTES = 2 * 1024 * 1024

PATTERNS = (
    ("private-key block", re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----")),
    ("Cloudflare API token", re.compile(r"\bcfat_[A-Za-z0-9_-]{20,}\b")),
    ("GitHub token", re.compile(r"\bgh(?:p|o|u|s|r)_[A-Za-z0-9]{20,}\b")),
    ("GitHub fine-grained token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b")),
    ("GitLab token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
    ("AWS access key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("Stripe live key", re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{16,}\b")),
)


def candidate_files() -> list[Path]:
    """Return tracked files when possible, otherwise safe workspace text candidates."""
    try:
        result = subprocess.run(
            ["git", "ls-files", "-z"],
            cwd=ROOT,
            check=True,
            capture_output=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        result = None

    if result and result.stdout:
        return [ROOT / name.decode("utf-8") for name in result.stdout.split(b"\0") if name]

    return [
        path
        for path in ROOT.rglob("*")
        if path.is_file() and not any(part in SKIP_DIRECTORIES for part in path.relative_to(ROOT).parts)
    ]


def scan(path: Path) -> list[tuple[int, str]]:
    if path.suffix.lower() in SKIP_SUFFIXES or path.stat().st_size > MAX_TEXT_BYTES:
        return []
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []

    findings: list[tuple[int, str]] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        for label, pattern in PATTERNS:
            if pattern.search(line):
                findings.append((line_number, label))
    return findings


def main() -> int:
    findings: list[tuple[Path, int, str]] = []
    for path in candidate_files():
        try:
            relative = path.relative_to(ROOT)
            findings.extend((relative, line, label) for line, label in scan(path))
        except (OSError, ValueError):
            continue

    if findings:
        print("Potential committed secret material detected; values are intentionally hidden:", file=sys.stderr)
        for path, line, label in findings:
            print(f"- {path}:{line}: {label}", file=sys.stderr)
        return 1

    print("No high-confidence secret patterns detected.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
