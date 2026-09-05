from __future__ import annotations

import os
import ssl
from pathlib import Path
from typing import Any

PROJECT = Path(__file__).resolve().parent

import routeros_api  # noqa: E402

from deploy_routeros_canary import first, wait_for_container  # noqa: E402


CONTAINER_COMMENT = "VPN Dashboard"
UPLOADS = {
    PROJECT / "app.py": "vpn-dashboard/app/app.py",
    PROJECT / "favicon.py": "vpn-dashboard/app/favicon.py",
    PROJECT / "routeros.py": "vpn-dashboard/app/routeros.py",
    PROJECT / "security.py": "vpn-dashboard/app/security.py",
    PROJECT / "store.py": "vpn-dashboard/app/store.py",
    PROJECT / "templates.py": "vpn-dashboard/app/templates.py",
    PROJECT / "automation.py": "vpn-dashboard/app/automation.py",
    PROJECT / "icons.py": "vpn-dashboard/app/icons.py",
    PROJECT / "qr.py": "vpn-dashboard/app/qr.py",
    PROJECT / "static" / "app.css": "vpn-dashboard/app/static/app.css",
    PROJECT / "static" / "app.js": "vpn-dashboard/app/static/app.js",
}


def remote_contents(files: Any, remote: str) -> str:
    records = files.get(name=remote)
    record = first(records, remote)
    result = files.call(
        "get", {"number": record["id"], "value-name": "contents"}
    )
    done = getattr(result, "done_message", {})
    if not isinstance(done, dict) or "ret" not in done:
        raise RuntimeError(f"Could not create in-memory rollback copy of {remote}")
    return str(done["ret"])


def upload_contents(files: Any, remote: str, contents: str) -> None:
    records = files.get(name=remote)
    if not records:
        files.add(name=remote, type="file")
        records = files.get(name=remote)
    record = first(records, remote)
    files.set(id=record["id"], contents=contents)
    stored = first(files.get(name=remote), remote)
    stored_size = int(stored.get("size", "-1"))
    expected_size = len(contents.encode("utf-8"))
    if stored_size not in {expected_size, expected_size + 1}:
        raise RuntimeError(f"Upload verification failed for {remote}")


def restart(containers: Any) -> None:
    current = first(containers.get(comment=CONTAINER_COMMENT), "dashboard container")
    if current.get("running") == "true":
        containers.call("stop", {"numbers": current["id"]})
    stopped = wait_for_container(containers, {"stopped"}, 120)
    containers.call("start", {"numbers": stopped["id"]})
    wait_for_container(containers, {"running"}, 90)


def main() -> None:
    ca_file = os.environ.get("ROUTER_API_CA_FILE", "").strip()
    if not ca_file:
        raise RuntimeError("ROUTER_API_CA_FILE is required for verified API TLS")
    ssl_context = ssl.create_default_context(cafile=ca_file)
    pool = routeros_api.RouterOsApiPool(
        os.environ["ROUTER_API_HOST"],
        username=os.environ.get("ROUTER_USER", "admin"),
        password=os.environ["ROUTER_PASSWORD"],
        port=int(os.environ.get("ROUTER_API_PORT", "8729")),
        use_ssl=True,
        ssl_context=ssl_context,
        plaintext_login=True,
    )
    modified = False
    rollback: dict[str, str] = {}
    created: list[str] = []
    try:
        api = pool.get_api()
        resource = first(api.get_resource("/system/resource").get(), "system resource")
        if resource.get("architecture-name") != "arm64":
            raise RuntimeError("Unexpected router architecture; refusing deployment")
        containers = api.get_resource("/container")
        current = first(containers.get(comment=CONTAINER_COMMENT), "dashboard container")
        if current.get("running") != "true":
            raise RuntimeError("Dashboard container is not healthy before deployment")
        files = api.get_resource("/file")
        rollback = {
            remote: remote_contents(files, remote)
            for remote in UPLOADS.values()
            if files.get(name=remote)
        }
        print("captured in-memory rollback copy", flush=True)

        for local, remote in UPLOADS.items():
            if not files.get(name=remote):
                created.append(remote)
            modified = True
            upload_contents(files, remote, local.read_text(encoding="utf-8"))
            print(f"verified {remote}", flush=True)
        restart(containers)
        print("dashboard container restarted successfully", flush=True)
    except Exception:
        if modified and rollback:
            print("deployment failed; restoring previous application files", flush=True)
            for remote, contents in rollback.items():
                upload_contents(files, remote, contents)
            for remote in created:
                records = files.get(name=remote)
                if records:
                    files.remove(id=first(records, remote)["id"])
            restart(containers)
            print("rollback completed", flush=True)
        raise
    finally:
        pool.disconnect()


if __name__ == "__main__":
    main()
