"""Resolve a public GHCR image to a verified ARM64/AMD64 OCI identity.

The resolver is deliberately limited to this repository's GHCR image. It
checks the registry's manifest digest against the returned bytes, follows an
index only to the requested Linux architecture, verifies the config blob, and
returns only public OCI digests and platform metadata. The parent-process
wrapper enforces a hard wall-clock deadline.
"""

from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
import re
import subprocess
import sys
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


IMAGE = re.compile(
    r"^(?:ghcr\.io/)?aivanov2-godaddy/mikrotik-openvpn-gui:"
    r"sha-[0-9a-f]{40}-(?P<architecture>arm64|amd64)"
    r"(?:@(?P<digest>sha256:[0-9a-f]{64}))?$"
)
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
REPOSITORY = "aivanov2-godaddy/mikrotik-openvpn-gui"
MAX_TOKEN_BYTES = 65_536
MAX_MANIFEST_BYTES = 65_536
MAX_CONFIG_BYTES = 4_194_304
MAX_LAYERS = 128
SUPPORTED_MANIFEST_TYPES = {
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
}
SUPPORTED_INDEX_TYPES = {
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
}
MANIFEST_ACCEPT = ", ".join(sorted(SUPPORTED_MANIFEST_TYPES | SUPPORTED_INDEX_TYPES))


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class _GitHubBlobRedirectHandler(HTTPRedirectHandler):
    """Follow one GHCR config-blob redirect without forwarding registry auth."""

    def __init__(self) -> None:
        super().__init__()
        self.redirect_count = 0

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        source = urlsplit(req.full_url)
        target = urlsplit(newurl)
        if (
            self.redirect_count != 0
            or source.scheme != "https"
            or source.hostname != "ghcr.io"
            or target.scheme != "https"
            or target.hostname != "pkg-containers.githubusercontent.com"
            or target.port not in (None, 443)
            or target.username is not None
            or target.password is not None
            or target.fragment
            or len(newurl) > 8192
            or code not in {301, 302, 303, 307, 308}
        ):
            return None
        self.redirect_count += 1
        # The redirected URL is a short-lived bearer capability. Do not send
        # the GHCR Authorization header or any request headers to this host.
        return Request(newurl, headers={"Accept-Encoding": "identity"}, method="GET")


def _read_limited(response: Any, limit: int, deadline: float) -> bytes | None:
    body = bytearray()
    socket = getattr(getattr(getattr(response, "fp", None), "raw", None), "_sock", None)
    read = getattr(response, "read1", response.read)
    while len(body) <= limit:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        if socket is not None and socket.fileno() >= 0:
            socket.settimeout(remaining)
        chunk = read(min(8192, limit + 1 - len(body)))
        if not chunk:
            break
        body.extend(chunk)
    if len(body) > limit or time.monotonic() > deadline:
        return None
    return bytes(body)


def _request(
    method: str,
    path: str,
    *,
    token: str | None,
    accept: str,
    timeout: float,
    max_bytes: int,
    allow_github_blob_redirect: bool = False,
) -> tuple[dict[str, str], bytes] | None:
    if not math.isfinite(timeout) or timeout <= 0 or not path.startswith("/"):
        return None
    headers = {"Accept": accept, "Accept-Encoding": "identity"}
    if token is not None:
        if not token or len(token) > 16_384 or "\r" in token or "\n" in token:
            return None
        headers["Authorization"] = f"Bearer {token}"
    request = Request(f"https://ghcr.io{path}", headers=headers, method=method)
    deadline = time.monotonic() + timeout
    opener = build_opener(
        _GitHubBlobRedirectHandler() if allow_github_blob_redirect else _NoRedirectHandler()
    )
    try:
        with opener.open(request, timeout=timeout) as response:
            if response.status != 200:
                return None
            body = _read_limited(response, max_bytes, deadline)
            if body is None:
                return None
            response_headers = {
                key.lower(): value.strip()
                for key, value in response.headers.items()
                if isinstance(key, str) and isinstance(value, str)
            }
            return response_headers, body
    except (HTTPError, URLError, OSError, TimeoutError, ValueError):
        return None


def _json_object(payload: bytes) -> dict[str, Any] | None:
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _body_digest(payload: bytes, expected: Any) -> bool:
    return (
        isinstance(expected, str)
        and DIGEST.fullmatch(expected) is not None
        and hashlib.sha256(payload).hexdigest() == expected.removeprefix("sha256:")
    )


def _verified_manifest(
    repository: str,
    reference: str,
    token: str,
    timeout: float,
) -> tuple[str, dict[str, Any]] | None:
    response = _request(
        "GET",
        f"/v2/{repository}/manifests/{reference}",
        token=token,
        accept=MANIFEST_ACCEPT,
        timeout=timeout,
        max_bytes=MAX_MANIFEST_BYTES,
    )
    if response is None:
        return None
    headers, body = response
    digest = headers.get("docker-content-digest")
    if not _body_digest(body, digest):
        return None
    document = _json_object(body)
    if document is None:
        return None
    media_type = document.get("mediaType")
    if media_type not in SUPPORTED_MANIFEST_TYPES | SUPPORTED_INDEX_TYPES:
        return None
    return digest, document


def _manifest_for_platform(
    repository: str,
    reference: str,
    token: str,
    architecture: str,
    timeout: float,
) -> tuple[str, dict[str, Any]] | None:
    top = _verified_manifest(repository, reference, token, timeout)
    if top is None:
        return None
    top_digest, document = top
    if document.get("mediaType") in SUPPORTED_MANIFEST_TYPES:
        return top_digest, document

    descriptors = document.get("manifests")
    if not isinstance(descriptors, list) or not descriptors or len(descriptors) > 128:
        return None
    matching = []
    for descriptor in descriptors:
        if not isinstance(descriptor, dict):
            return None
        platform = descriptor.get("platform")
        if not isinstance(platform, dict):
            continue
        if platform.get("os") == "linux" and platform.get("architecture") == architecture:
            matching.append(descriptor)
    if len(matching) != 1:
        return None
    descriptor = matching[0]
    child_digest = descriptor.get("digest")
    if not isinstance(child_digest, str) or DIGEST.fullmatch(child_digest) is None:
        return None
    if descriptor.get("mediaType") not in SUPPORTED_MANIFEST_TYPES:
        return None
    child = _verified_manifest(repository, child_digest, token, timeout)
    if child is None or child[0] != child_digest:
        return None
    if child[1].get("mediaType") not in SUPPORTED_MANIFEST_TYPES:
        return None
    return top_digest, child[1]


def resolve_image_identity_request(image: str, *, timeout: float = 8.0) -> dict[str, Any] | None:
    """Resolve an exact project reference; network failures return no proof."""
    match = IMAGE.fullmatch(image) if isinstance(image, str) else None
    if match is None or not math.isfinite(timeout) or not 1 <= timeout <= 30:
        return None
    architecture = match.group("architecture")
    reference = match.group("digest") or image.rsplit(":", 1)[1].split("@", 1)[0]
    token_response = _request(
        "GET",
        "/token?" + urlencode({"scope": f"repository:{REPOSITORY}:pull"}),
        token=None,
        accept="application/json",
        timeout=timeout,
        max_bytes=MAX_TOKEN_BYTES,
    )
    if token_response is None:
        return None
    token_document = _json_object(token_response[1])
    if token_document is None:
        return None
    token = token_document.get("token") or token_document.get("access_token")
    if not isinstance(token, str) or not token or len(token) > 16_384:
        return None
    resolved = _manifest_for_platform(REPOSITORY, reference, token, architecture, timeout)
    if resolved is None:
        return None
    manifest_digest, manifest = resolved
    config = manifest.get("config")
    layers = manifest.get("layers")
    if (
        not isinstance(config, dict)
        or not isinstance(config.get("digest"), str)
        or DIGEST.fullmatch(config["digest"]) is None
        or not isinstance(layers, list)
        or not layers
        or len(layers) > MAX_LAYERS
    ):
        return None
    layer_digests = []
    for layer in layers:
        if not isinstance(layer, dict) or not isinstance(layer.get("digest"), str):
            return None
        layer_digest = layer["digest"]
        if DIGEST.fullmatch(layer_digest) is None:
            return None
        layer_digests.append(layer_digest)
    if len(set(layer_digests)) != len(layer_digests):
        return None

    config_response = _request(
        "GET",
        f"/v2/{REPOSITORY}/blobs/{config['digest']}",
        token=token,
        accept="application/vnd.oci.image.config.v1+json, application/vnd.docker.container.image.v1+json",
        timeout=timeout,
        max_bytes=MAX_CONFIG_BYTES,
        allow_github_blob_redirect=True,
    )
    if config_response is None or not _body_digest(config_response[1], config["digest"]):
        return None
    config_document = _json_object(config_response[1])
    if config_document is None:
        return None
    if config_document.get("os") != "linux" or config_document.get("architecture") != architecture:
        return None
    return {
        "manifest_digest": manifest_digest,
        "config_digest": config["digest"],
        "layer_digests": layer_digests,
        "os": "linux",
        "architecture": architecture,
    }


def resolve_image_identity(image: str, *, timeout: float = 8.0) -> dict[str, Any] | None:
    """Resolve through a child process so the full network operation is bounded."""
    if not math.isfinite(timeout) or not 1 <= timeout <= 30 or IMAGE.fullmatch(image or "") is None:
        return None
    try:
        result = subprocess.run(
            [sys.executable, str(Path(__file__).resolve()), "--internal-resolve", image, str(timeout)],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=timeout + 0.5,
            text=True,
            encoding="utf-8",
        )
    except (OSError, subprocess.SubprocessError, TimeoutError):
        return None
    if result.returncode != 0 or len(result.stdout) > 32_768:
        return None
    try:
        identity = json.loads(result.stdout)
    except json.JSONDecodeError:
        return None
    if not isinstance(identity, dict) or set(identity) != {
        "manifest_digest", "config_digest", "layer_digests", "os", "architecture"
    }:
        return None
    if (
        not isinstance(identity.get("manifest_digest"), str)
        or DIGEST.fullmatch(identity["manifest_digest"]) is None
        or not isinstance(identity.get("config_digest"), str)
        or DIGEST.fullmatch(identity["config_digest"]) is None
        or not isinstance(identity.get("layer_digests"), list)
        or not identity["layer_digests"]
        or len(identity["layer_digests"]) > MAX_LAYERS
        or any(not isinstance(item, str) or DIGEST.fullmatch(item) is None for item in identity["layer_digests"])
        or len(set(identity["layer_digests"])) != len(identity["layer_digests"])
        or identity.get("os") != "linux"
        or identity.get("architecture") != IMAGE.fullmatch(image).group("architecture")
    ):
        return None
    return identity


def runtime_identity_matches(
    image_id: Any,
    layer_digests: Any,
    identity: Any,
) -> bool:
    """Compare RouterOS identifiers in memory without returning raw values."""
    if not isinstance(identity, dict):
        return False
    config = identity.get("config_digest")
    expected_layers = identity.get("layer_digests")
    if not isinstance(config, str) or DIGEST.fullmatch(config) is None:
        return False
    if not isinstance(expected_layers, list) or any(
        not isinstance(value, str) or DIGEST.fullmatch(value) is None for value in expected_layers
    ):
        return False
    raw_image_id = image_id.strip() if isinstance(image_id, str) else ""
    actual_image_digest = raw_image_id if DIGEST.fullmatch(raw_image_id) else (
        f"sha256:{raw_image_id}" if re.fullmatch(r"[0-9a-f]{64}", raw_image_id) else None
    )
    if actual_image_digest != config:
        return False
    if isinstance(layer_digests, str):
        actual_layers = [value.strip() for value in layer_digests.split(",")]
    elif isinstance(layer_digests, list):
        actual_layers = [value.strip() for value in layer_digests if isinstance(value, str)]
        if len(actual_layers) != len(layer_digests):
            return False
    else:
        return False
    if not actual_layers or any(not value for value in actual_layers):
        return False
    normalized_layers = [
        value if DIGEST.fullmatch(value) else (f"sha256:{value}" if re.fullmatch(r"[0-9a-f]{64}", value) else None)
        for value in actual_layers
    ]
    return normalized_layers == expected_layers


def _internal_main(argv: list[str]) -> int:
    if len(argv) != 4 or argv[1] != "--internal-resolve":
        return 2
    try:
        timeout = float(argv[3])
    except ValueError:
        return 2
    identity = resolve_image_identity_request(argv[2], timeout=timeout)
    if identity is None:
        return 1
    sys.stdout.write(json.dumps(identity, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(_internal_main(sys.argv))
