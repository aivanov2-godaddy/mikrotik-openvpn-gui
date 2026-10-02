"""Run the repository's fast, dependency-free pre-commit checks."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PYTHON_FILES = [
    "app.py",
    "asgi.py",
    "entrypoint.py",
    "automation.py",
    "cloudflare.py",
    "error_guidance.py",
    "exposure_doctor.py",
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
    "telemetry_broker.py",
    "telemetry_canary.py",
    "telemetry_gateway.py",
    "telemetry_runtime.py",
    "telemetry_socketio.py",
    "telemetry_socketio_polling.py",
    "telemetry_state.py",
    "telemetry_supervisor.py",
    "routeros_binary.py",
    "update_routeros_app.py",
    "scripts/check-secrets.py",
    "scripts/deploy_routeros_release.py",
    "scripts/pre_commit_checks.py",
    "scripts/telemetry_canary.py",
    "scripts/telemetry_acceptance.py",
    "scripts/release_acceptance.py",
    "scripts/validate_release.py",
    "tests/mock_routeros.py",
    "tests/test_routeros_binary.py",
    "tests/test_telemetry_broker.py",
    "tests/test_telemetry_canary.py",
    "tests/test_telemetry_acceptance.py",
    "tests/test_release_acceptance.py",
    "tests/test_asgi_contract.py",
    "tests/test_error_guidance.py",
    "tests/test_exposure_doctor.py",
    "tests/test_telemetry_gateway.py",
    "tests/test_telemetry_socketio.py",
    "tests/test_telemetry_socketio_polling.py",
    "tests/test_telemetry_supervisor.py",
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
