"""Read-only OpenVPN profile diagnostics.

The parser intentionally returns only structural findings.  It never echoes
profile contents, certificates, keys, passwords, or private material.
"""

from __future__ import annotations

import re
from typing import Any


_REMOTE = re.compile(r"^remote\s+(\S+)(?:\s+(\d+))?(?:\s+(\S+))?\s*$", re.I)
_VERIFY_NAME = re.compile(r"^verify-x509-name\s+(\S+)", re.I)


def diagnose_profile(profile: str) -> dict[str, Any]:
    lines = str(profile).splitlines()
    directives: dict[str, list[str]] = {}
    blocks: dict[str, int] = {}
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("<") and line.endswith(">"):
            blocks[line.casefold()] = blocks.get(line.casefold(), 0) + 1
            continue
        key = line.split(None, 1)[0].casefold()
        directives.setdefault(key, []).append(line)

    checks: list[dict[str, str]] = []

    def add(identifier: str, status: str, message: str) -> None:
        checks.append({"id": identifier, "status": status, "message": message})

    remote = next((line for line in directives.get("remote", []) if _REMOTE.match(line)), "")
    if remote:
        match = _REMOTE.match(remote)
        host = match.group(1) if match else ""
        port = match.group(2) if match else "default"
        add("remote", "pass", f"Server endpoint is present ({host}:{port}).")
    else:
        add("remote", "error", "The profile has no valid remote server endpoint.")

    proto_line = (directives.get("proto") or [""])[0]
    proto_parts = proto_line.split(None, 1)
    proto = proto_parts[1].casefold() if len(proto_parts) == 2 else ""
    add("protocol", "pass", f"Transport protocol is {proto}." if proto else "Protocol uses the OpenVPN default.")
    if proto and proto not in {"udp", "tcp", "tcp-client"}:
        add("protocol", "warning", "The transport protocol is unusual for this dashboard.")

    required_blocks = {"<ca>": "CA certificate", "<cert>": "client certificate", "<key>": "client private key"}
    for block, label in required_blocks.items():
        count = blocks.get(block, 0)
        add(block[1:-1], "pass" if count == 1 else "error", f"Embedded {label} is present." if count == 1 else f"Expected exactly one embedded {label} block.")

    if "auth-nocache" in directives:
        add("auth-nocache", "pass", "VPN credentials are not cached by the client.")
    else:
        add("auth-nocache", "warning", "The profile does not explicitly disable credential caching.")

    verify_line = next((line for line in directives.get("verify-x509-name", []) if _VERIFY_NAME.match(line)), "")
    if verify_line:
        add("server-identity", "pass", "The server certificate identity is pinned.")
    else:
        add("server-identity", "warning", "The profile does not pin a server certificate identity.")

    if "cipher" in directives or "data-ciphers" in directives:
        add("encryption", "pass", "An explicit data-cipher policy is present.")
    else:
        add("encryption", "warning", "No explicit data-cipher directive was found.")

    errors = sum(1 for item in checks if item["status"] == "error")
    warnings = sum(1 for item in checks if item["status"] == "warning")
    return {
        "status": "fail" if errors else ("warning" if warnings else "pass"),
        "summary": {"errors": errors, "warnings": warnings, "checks": len(checks)},
        "checks": checks,
        "redaction": "Profile contents and all certificate, key, password, and credential material were omitted.",
    }
