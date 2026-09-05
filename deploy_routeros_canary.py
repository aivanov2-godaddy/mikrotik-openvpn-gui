from __future__ import annotations

import os
import ssl
import time
from pathlib import Path
from typing import Any

PROJECT = Path(__file__).resolve().parent
import routeros_api  # noqa: E402


ROUTER_API_PORT = 8728
CONTAINER_COMMENT = "VPN Dashboard"


def first(records: list[dict[str, Any]], label: str) -> dict[str, Any]:
    if len(records) != 1:
        raise RuntimeError(f"Expected exactly one {label}, found {len(records)}")
    return records[0]


def ensure_record(resource: Any, query: dict[str, str], values: dict[str, str], label: str) -> dict[str, Any]:
    records = resource.get(**query)
    if not records:
        resource.add(**values)
        records = resource.get(**query)
    return first(records, label)


def remove_records(resource: Any, **query: str) -> None:
    for record in resource.get(**query):
        resource.remove(id=record["id"])


def upload_text(files: Any, local: Path, remote: str) -> None:
    contents = local.read_text(encoding="utf-8")
    records = files.get(name=remote)
    if not records:
        files.add(name=remote, type="file")
        records = files.get(name=remote)
    record = first(records, remote)
    files.set(id=record["id"], contents=contents)
    stored = first(files.get(name=remote), remote)
    stored_size = int(stored.get("size", "-1"))
    source_size = len(contents.encode())
    # RouterOS file sizes include one terminating byte for text written through
    # /file set, while /file get value-name=contents returns the original text.
    if stored_size not in {source_size, source_size + 1}:
        raise RuntimeError(f"Upload verification failed for {remote}")
    print(f"uploaded {remote} ({len(contents.encode())} bytes)", flush=True)


def wait_for_container(containers: Any, wanted: set[str], timeout: int) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    previous = None
    while time.monotonic() < deadline:
        records = containers.get(comment=CONTAINER_COMMENT)
        if records:
            record = records[0]
            status = str(record.get("status", "unknown"))
            for flag in ("running", "stopped", "starting", "extracting", "downloading"):
                if record.get(flag) == "true":
                    status = flag
                    break
            if status != previous:
                print(f"container status={status}", flush=True)
                previous = status
            if status in wanted:
                return record
            if (
                status in {"error", "failed"}
                or status.startswith("error")
                or record.get("download/extract failed") == "true"
            ):
                raise RuntimeError(f"Container failed: {record}")
        time.sleep(2)
    raise TimeoutError(f"Container did not reach {sorted(wanted)} in {timeout}s")


def main() -> None:
    host = os.environ["ROUTER_API_HOST"]
    port = int(os.environ.get("ROUTER_API_PORT", "8729"))
    username = os.environ.get("ROUTER_USER", "admin")
    password = os.environ["ROUTER_PASSWORD"]
    api_ca_file = Path(os.environ["ROUTER_API_CA_FILE"]).resolve()
    ovpn_ca_file = Path(os.environ["OVPN_CA_FILE"]).resolve()
    if not api_ca_file.is_file():
        raise RuntimeError(f"Router API CA file does not exist: {api_ca_file}")
    if not ovpn_ca_file.is_file():
        raise RuntimeError(f"OpenVPN CA file does not exist: {ovpn_ca_file}")
    ssl_context = ssl.create_default_context(cafile=str(api_ca_file))

    pool = routeros_api.RouterOsApiPool(
        host,
        username=username,
        password=password,
        port=port,
        use_ssl=True,
        ssl_context=ssl_context,
        plaintext_login=True,
    )
    try:
        api = pool.get_api()
        resource = first(api.get_resource("/system/resource").get(), "system resource")
        if resource.get("architecture-name") != "arm64":
            raise RuntimeError(f"Unexpected architecture: {resource.get('architecture-name')}")
        print(f"router version={resource.get('version')} architecture=arm64", flush=True)

        print("pre-vpn-dashboard-20260804.backup already created", flush=True)

        bridges = api.get_resource("/interface/bridge")
        ensure_record(
            bridges,
            {"name": "br-vpn-dashboard"},
            {"name": "br-vpn-dashboard", "comment": "VPN Dashboard"},
            "dashboard bridge",
        )
        veth = api.get_resource("/interface/veth")
        ensure_record(
            veth,
            {"name": "veth-vpn-dashboard"},
            {
                "name": "veth-vpn-dashboard",
                "address": "172.31.255.2/30",
                "gateway": "172.31.255.1",
            },
            "dashboard veth",
        )
        bridge_ports = api.get_resource("/interface/bridge/port")
        ensure_record(
            bridge_ports,
            {"interface": "veth-vpn-dashboard"},
            {"bridge": "br-vpn-dashboard", "interface": "veth-vpn-dashboard"},
            "dashboard bridge port",
        )
        addresses = api.get_resource("/ip/address")
        ensure_record(
            addresses,
            {"address": "172.31.255.1/30"},
            {
                "address": "172.31.255.1/30",
                "interface": "br-vpn-dashboard",
                "comment": "VPN Dashboard",
            },
            "dashboard router address",
        )
        print("private bridge/veth ready", flush=True)

        certificates = api.get_resource("/certificate")
        rest_records = certificates.get(name="vpn-dashboard-rest")
        if not rest_records:
            certificates.add(
                name="vpn-dashboard-rest",
                common_name="172.31.255.1",
                subject_alt_name="IP:172.31.255.1",
                key_size="2048",
                digest_algorithm="sha256",
                days_valid="1825",
                key_usage="tls-server",
            )
            rest_record = first(certificates.get(name="vpn-dashboard-rest"), "REST certificate")
            certificates.call("sign", {"numbers": rest_record["id"], "ca": "ovpn-ca-2026"})
        rest_record = first(certificates.get(name="vpn-dashboard-rest"), "REST certificate")
        signing_ca = rest_record.get("ca") or rest_record.get("issuer")
        if signing_ca != "ovpn-ca-2026" or rest_record.get("issued") != "true":
            raise RuntimeError(f"REST certificate was not signed by ovpn-ca-2026: {rest_record}")
        services = api.get_resource("/ip/service")
        www_ssl = first(services.get(name="www-ssl"), "www-ssl service")
        services.set(id=www_ssl["id"], port="8443", certificate="vpn-dashboard-rest", disabled="no")
        print("www-ssl REST certificate replaced on port 8443", flush=True)

        files = api.get_resource("/file")
        for directory in ("vpn-dashboard", "vpn-dashboard/app", "vpn-dashboard/app/static", "vpn-dashboard/data", "vpn-dashboard/tmp"):
            if not files.get(name=directory):
                files.add(name=directory, type="directory")

        uploads = {
            PROJECT / "app.py": "vpn-dashboard/app/app.py",
            PROJECT / "routeros.py": "vpn-dashboard/app/routeros.py",
            PROJECT / "security.py": "vpn-dashboard/app/security.py",
            PROJECT / "store.py": "vpn-dashboard/app/store.py",
            PROJECT / "templates.py": "vpn-dashboard/app/templates.py",
            PROJECT / "automation.py": "vpn-dashboard/app/automation.py",
            PROJECT / "icons.py": "vpn-dashboard/app/icons.py",
            PROJECT / "favicon.py": "vpn-dashboard/app/favicon.py",
            PROJECT / "qr.py": "vpn-dashboard/app/qr.py",
            PROJECT / "static" / "app.css": "vpn-dashboard/app/static/app.css",
            PROJECT / "static" / "app.js": "vpn-dashboard/app/static/app.js",
            ovpn_ca_file: "vpn-dashboard/app/ovpn-ca-2026.crt",
        }
        for local, remote in uploads.items():
            upload_text(files, local, remote)

        mounts = api.get_resource("/container/mounts")
        remove_records(mounts, list="vpn-dashboard-mounts")
        mounts.add(list="vpn-dashboard-mounts", src="vpn-dashboard/app", dst="/app")
        mounts.add(list="vpn-dashboard-mounts", src="vpn-dashboard/data", dst="/data")

        envs = api.get_resource("/container/envs")
        remove_records(envs, list="vpn-dashboard-env")
        environment = {
            "PUBLIC_ORIGIN": "https://vpn.wanted.sx",
            "ROUTEROS_REST_URL": "https://172.31.255.1:8443/rest",
            "ROUTEROS_CA_FILE": "/app/ovpn-ca-2026.crt",
            "ROUTEROS_INSECURE_TLS": "false",
            "DATABASE_PATH": "/data/dashboard.sqlite",
            "TRUST_CLOUDFLARE": "true",
            "TRUSTED_PROXY_SOURCES": "172.31.255.1",
            "DROP_PRIVILEGES": "true",
        }
        for key, value in environment.items():
            envs.add(list="vpn-dashboard-env", key=key, value=value)

        config = api.get_resource("/container/config")
        config.set(
            registry_url="https://registry-1.docker.io",
            layer_dir="vpn-dashboard/layers",
            tmpdir="vpn-dashboard/tmp",
        )
        print("application mounts and environment staged", flush=True)

        containers = api.get_resource("/container")
        existing = containers.get(comment=CONTAINER_COMMENT)
        for failed in existing:
            if failed.get("download/extract failed") == "true":
                print(f"removing failed canary record id={failed['id']}", flush=True)
                containers.remove(id=failed["id"])
        existing = containers.get(comment=CONTAINER_COMMENT)
        if not existing:
            print("pulling python:3.14-alpine for arm64", flush=True)
            containers.add(
                remote_image="python:3.14-alpine",
                interface="veth-vpn-dashboard",
                root_dir="vpn-dashboard/root",
                mountlists="vpn-dashboard-mounts",
                envlists="vpn-dashboard-env",
                entrypoint="python3",
                cmd="-B /app/app.py",
                workdir="/app",
                logging="yes",
                memory_high="134217728",
                memory_max="201326592",
                start_on_boot="yes",
                comment=CONTAINER_COMMENT,
            )
        else:
            current = existing[0]
            if current.get("running") == "true":
                print("stopping existing dashboard container for an idempotent update", flush=True)
                containers.call("stop", {"numbers": current["id"]})
        stopped = wait_for_container(containers, {"stopped"}, 480)
        print("starting private canary container", flush=True)
        containers.call("start", {"numbers": stopped["id"]})
        running = wait_for_container(containers, {"running"}, 90)
        print(f"private canary running id={running['id']}", flush=True)
    finally:
        pool.disconnect()


if __name__ == "__main__":
    main()
