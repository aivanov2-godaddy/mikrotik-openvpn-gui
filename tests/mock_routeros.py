from __future__ import annotations

import base64
import json
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


VALID_AUTH = "Basic " + base64.b64encode(b"admin:routerpass").decode("ascii")


class State:
    def __init__(self) -> None:
        self.users: dict[str, dict[str, Any]] = {
            "*1": {
                ".id": "*1",
                "name": "user-one",
                "service": "ovpn",
                "profile": "vpn-full-tunnel",
                "comment": "Android test device",
                "disabled": "no",
            },
            "*2": {
                ".id": "*2",
                "name": "user-two",
                "service": "ovpn",
                "profile": "vpn-full-tunnel",
                "comment": "Tablet test device",
                "disabled": "no",
            },
        }
        self.profiles: dict[str, dict[str, Any]] = {
            "*P0": {".id": "*P0", "name": "vpn-full-tunnel", "rate-limit": ""}
        }
        self.certificates: dict[str, dict[str, Any]] = {
            "*CA": {
                ".id": "*CA",
                "name": "vpn-ca",
                "common-name": "vpn-ca",
                "fingerprint": "CA:FAKE",
                "trusted": "yes",
                "key-usage": "key-cert-sign,crl-sign",
                "invalid-after": "2036-08-03 00:00:00",
            },
            "*CL1": {
                ".id": "*CL1",
                "name": "ovpn-user-one-device-a",
                "common-name": "user-one-android-test-device",
                "fingerprint": "A1:EX:26",
                "issuer": "vpn-ca",
                "ca": "vpn-ca",
                "trusted": "yes",
                "revoked": "no",
                "key-usage": "tls-client",
                "invalid-after": "2031-08-03 00:00:00",
                "expires-after": "260w",
            },
            "*CL2": {
                ".id": "*CL2",
                "name": "ovpn-user-two-device-b",
                "common-name": "user-two-tablet-test-device",
                "fingerprint": "NU:LL:10",
                "issuer": "vpn-ca",
                "ca": "vpn-ca",
                "trusted": "yes",
                "revoked": "no",
                "key-usage": "tls-client",
                "invalid-after": "2031-08-04 00:00:00",
                "expires-after": "260w",
            },
        }
        self.ovpn_servers = [{
            ".id": "*OVPN1",
            "name": "vpn-server",
            "disabled": "no",
            "protocol": "udp",
            "port": "1194",
            "require-client-certificate": "yes",
            "tls-version": "only-1.2",
            "auth": "sha256",
            "cipher": "aes256-gcm",
            "redirect-gateway": "def1",
            "user-auth-method": "mschap2",
            "reneg-sec": "3600",
            "certificate": "ovpn-server-2026",
        }]
        self.certificate_settings = [{
            "crl-download": "true",
            "crl-use": "false",
            "crl-store": "system",
        }]
        self.fail_certificate_inventory = False
        self.certificate_queries: list[dict[str, list[str]]] = []
        self.active_sessions: dict[str, dict[str, Any]] = {
            "*A1": {
                ".id": "*A1",
                "name": "user-two",
                "service": "ovpn",
                "caller-id": "198.51.100.40",
                "address": "198.18.0.48",
                "uptime": "8m12s",
                "encoding": "AES-256-GCM/[user-two-digest]",
                "session-id": "0x81E0000B",
                "comment": "Tablet test device",
            }
        }
        self.interfaces: dict[str, dict[str, Any]] = {
            "*I1": {
                ".id": "*I1",
                "name": "<ovpn-user-two>",
                "type": "ovpn-in",
                "running": "true",
                "dynamic": "true",
                "actual-mtu": "1500",
                "rx-byte": "69988",
                "tx-byte": "192455",
                "rx-packet": "387",
                "tx-packet": "825",
                "rx-drop": "0",
                "tx-drop": "0",
                "rx-error": "0",
                "tx-error": "0",
            }
        }
        self.files: dict[str, dict[str, Any]] = {
            "vpn-ca.crt": {
                ".id": "*F0",
                "name": "vpn-ca.crt",
                "type": ".crt file",
                "size": "64",
                "contents": "-----BEGIN CERTIFICATE-----\nFAKE-CA\n-----END CERTIFICATE-----\n",
            }
        }
        self.next_user = 3
        self.next_cert = 1
        self.next_file = 1
        self.admin_group = "full"
        self.lock = threading.RLock()

    def file(self, name: str, contents: str, file_type: str) -> dict[str, Any]:
        record = {
            ".id": f"*F{self.next_file}",
            "name": name,
            "type": file_type,
            "size": str(len(contents.encode("utf-8"))),
            "contents": contents,
            "last-modified": "2026-08-04 03:00:00",
        }
        self.next_file += 1
        self.files[name] = record
        return record


class MockHandler(BaseHTTPRequestHandler):
    server: "MockServer"

    def log_message(self, message: str, *args: Any) -> None:
        return

    def _json(self, value: Any, status: int = 200) -> None:
        payload = json.dumps(value, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _empty(self, status: int = 204) -> None:
        self.send_response(status)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _auth(self) -> bool:
        if self.headers.get("Authorization") == VALID_AUTH:
            return True
        self._json({"error": 401, "message": "unauthorized"}, 401)
        return False

    def _body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        return json.loads(self.rfile.read(length) or b"{}")

    def _parts(self) -> tuple[str, dict[str, list[str]]]:
        parsed = urllib.parse.urlsplit(self.path)
        return parsed.path.removeprefix("/rest"), urllib.parse.parse_qs(parsed.query)

    def do_GET(self) -> None:
        if not self._auth():
            return
        path, query = self._parts()
        state = self.server.state
        with state.lock:
            if path == "/system/resource":
                self._json([{
                    "version": "7.23.3", "architecture-name": "arm64", "board-name": "router-test-board",
                    "cpu-load": "7", "free-memory": "805306368", "total-memory": "1073741824",
                    "free-hdd-space": "943718400", "total-hdd-space": "1073741824",
                    "uptime": "1d6h12m", "bad-blocks": "0",
                }])
            elif path == "/system/package":
                self._json([{"name": "container", "version": "7.23.3", "disabled": "no"}])
            elif path == "/user":
                self._json([{"name": "admin", "group": state.admin_group, "disabled": "no"}])
            elif path == "/ppp/secret":
                self._json(list(state.users.values()))
            elif path == "/ppp/profile":
                records = list(state.profiles.values())
                if query.get("name"):
                    records = [item for item in records if item.get("name") == query["name"][0]]
                self._json(records)
            elif path == "/ppp/active":
                self._json(list(state.active_sessions.values()))
            elif path == "/interface":
                self._json(list(state.interfaces.values()))
            elif path == "/interface/ovpn-server/server":
                self._json(state.ovpn_servers)
            elif path == "/certificate/settings":
                self._json(state.certificate_settings)
            elif path == "/certificate":
                state.certificate_queries.append(query)
                if state.fail_certificate_inventory and query.get("ca"):
                    self._json({"error": "certificate inventory unavailable"}, 500)
                    return
                records = list(state.certificates.values())
                if query.get("name"):
                    records = [item for item in records if item.get("name") == query["name"][0]]
                if query.get("ca"):
                    records = [item for item in records if item.get("ca") == query["ca"][0]]
                self._json(records)
            elif path == "/ip/dns":
                self._json([{"servers": "192.0.2.1", "allow-remote-requests": "yes"}])
            elif path == "/ip/firewall/filter":
                self._json([{"chain": "input", "action": "accept", "protocol": "udp", "dst-port": "1194", "disabled": "no", "comment": "OpenVPN"}])
            elif path == "/file":
                records = list(state.files.values())
                if query.get("name"):
                    records = [item for item in records if item.get("name") == query["name"][0]]
                self._json(records)
            else:
                self._json({"error": "not found"}, 404)

    def do_PUT(self) -> None:
        if not self._auth():
            return
        path, _ = self._parts()
        body = self._body()
        state = self.server.state
        with state.lock:
            if path == "/ppp/secret":
                if any(item["name"] == body.get("name") for item in state.users.values()):
                    self._json({"error": "duplicate"}, 400)
                    return
                record = {".id": f"*{state.next_user}", **body, "disabled": "no"}
                state.next_user += 1
                state.users[record[".id"]] = record
                self._json(record, 201)
            elif path == "/ppp/profile":
                record = {".id": f"*P{len(state.profiles)}", **body}
                state.profiles[record[".id"]] = record
                self._json(record, 201)
            elif path == "/certificate":
                record = {
                    ".id": f"*C{state.next_cert}",
                    **body,
                    "fingerprint": f"FA:KE:{state.next_cert:02d}",
                    "trusted": "no",
                    "revoked": "no",
                    "invalid-after": "2031-08-05 00:00:00",
                    "expires-after": "260w",
                }
                state.next_cert += 1
                state.certificates[record[".id"]] = record
                self._json(record, 201)
            else:
                self._json({"error": "not found"}, 404)

    def do_PATCH(self) -> None:
        if not self._auth():
            return
        path, _ = self._parts()
        body = self._body()
        state = self.server.state
        with state.lock:
            if path.startswith("/ppp/secret/"):
                record = state.users.get(urllib.parse.unquote(path.rsplit("/", 1)[1]))
            elif path.startswith("/ppp/profile/"):
                record = state.profiles.get(urllib.parse.unquote(path.rsplit("/", 1)[1]))
            elif path.startswith("/certificate/"):
                record = state.certificates.get(urllib.parse.unquote(path.rsplit("/", 1)[1]))
            else:
                record = None
            if not record:
                self._json({"error": "not found"}, 404)
                return
            record.update(body)
            self._json(record)

    def do_DELETE(self) -> None:
        if not self._auth():
            return
        path, _ = self._parts()
        state = self.server.state
        with state.lock:
            if path.startswith("/ppp/secret/"):
                state.users.pop(urllib.parse.unquote(path.rsplit("/", 1)[1]), None)
            elif path.startswith("/ppp/active/"):
                session_id = urllib.parse.unquote(path.rsplit("/", 1)[1])
                if session_id not in state.active_sessions:
                    self._json({"error": "not found"}, 404)
                    return
                state.active_sessions.pop(session_id)
                for interface_id, item in list(state.interfaces.items()):
                    if item.get("name") == "<ovpn-user-two>":
                        state.interfaces.pop(interface_id)
            elif path.startswith("/certificate/"):
                state.certificates.pop(urllib.parse.unquote(path.rsplit("/", 1)[1]), None)
            elif path.startswith("/file/"):
                file_id = urllib.parse.unquote(path.rsplit("/", 1)[1])
                for name, item in list(state.files.items()):
                    if item[".id"] == file_id:
                        state.files.pop(name, None)
            else:
                self._json({"error": "not found"}, 404)
                return
            self._empty()

    def do_POST(self) -> None:
        if not self._auth():
            return
        path, _ = self._parts()
        body = self._body()
        state = self.server.state
        with state.lock:
            if path == "/certificate/sign":
                state.certificates[body["number"]]["issuer"] = "vpn-ca"
                state.certificates[body["number"]]["ca"] = body["ca"]
                self._empty()
            elif path == "/certificate/export-certificate":
                cert = state.certificates[body["numbers"]]
                name = cert["name"]
                if name == "vpn-ca":
                    state.file("vpn-ca.crt", "-----BEGIN CERTIFICATE-----\nFAKE-CA\n-----END CERTIFICATE-----\n", ".crt file")
                else:
                    state.file(f"cert_export_{name}.crt", f"-----BEGIN CERTIFICATE-----\n{name}\n-----END CERTIFICATE-----\n", ".crt file")
                    mock_key = (
                        "-----BEGIN ENCRYPTED "
                        f"PRIVATE KEY-----\n{name}\n"
                        "-----END ENCRYPTED "
                        "PRIVATE KEY-----\n"
                    )
                    state.file(f"cert_export_{name}.key", mock_key, ".key file")
                self._empty()
            elif path == "/interface/ovpn-server/server/export-client-configuration":
                cert = state.files[body["client-certificate"]]["contents"]
                key = state.files[body["client-cert-key"]]["contents"]
                ca = state.files[body["ca-certificate"]]["contents"]
                profile = (
                    "client\ndev tun\nremote vpn.example.test 1194 udp\nauth-user-pass\nremote-cert-tls server\n"
                    f"<ca>\n{ca}</ca>\n<cert>\n{cert}</cert>\n<key>\n{key}</key>\n"
                )
                state.file(f"client{state.next_file}.ovpn", profile, ".ovpn file")
                self._empty()
            elif path == "/export":
                filename = str(body.get("file", "vpn-dashboard-checkpoint.rsc"))
                state.file(filename, "/ip service print\n", ".rsc file")
                self._empty()
            elif path == "/file/get":
                record = next(
                    (
                        item
                        for item in state.files.values()
                        if item[".id"] == body.get("number")
                    ),
                    None,
                )
                if not record or body.get("value-name") != "contents":
                    self._json({"error": "not found"}, 404)
                else:
                    self._json({"ret": record["contents"]})
            else:
                self._json({"error": "not found"}, 404)


class MockServer(ThreadingHTTPServer):
    def __init__(self) -> None:
        self.state = State()
        super().__init__(("127.0.0.1", 0), MockHandler)


class MockRouterOS:
    def __init__(self) -> None:
        self.server = MockServer()
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_port}/rest"

    @property
    def state(self) -> State:
        return self.server.state

    def __enter__(self) -> "MockRouterOS":
        self.thread.start()
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
