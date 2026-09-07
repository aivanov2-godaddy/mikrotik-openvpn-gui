"""Run the repository's fast, dependency-free pre-commit checks."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PYTHON_FILES = [
    "app.py",
    "automation.py",
    "cloudflare.py",
    "deploy_routeros_canary.py",
    "deployment.py",
    "favicon.py",
    "icons.py",
    "install_routeros.py",
    "qr.py",
    "routeros.py",
    "security.py",
    "store.py",
    "templates.py",
    "update_routeros_app.py",
    "scripts/check-secrets.py",
    "scripts/deploy_routeros_release.py",
    "scripts/pre_commit_checks.py",
    "tests/mock_routeros.py",
]


def run(label: str, *command: str) -> None:
    print(f"== {label} ==")
    subprocess.run(command, cwd=ROOT, check=True)


def main() -> int:
    run("secret-pattern scan", sys.executable, "scripts/check-secrets.py")
    run("Python compilation", sys.executable, "-m", "compileall", "-q", *PYTHON_FILES)
    run("Python unit and mock integration tests", sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v")
    node = "node"
    try:
        run("JavaScript syntax", node, "--check", "static/app.js")
    except FileNotFoundError:
        print("node is not installed; JavaScript syntax check must run in CI", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
