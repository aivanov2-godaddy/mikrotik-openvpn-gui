from __future__ import annotations

import hashlib
import json
import unittest
from unittest.mock import patch
from urllib.request import Request

from scripts.oci_registry_identity import (
    _GitHubBlobRedirectHandler,
    resolve_image_identity_request,
    runtime_identity_matches,
)


REVISION = "a" * 40
IMAGE = f"ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-{REVISION}-arm64"
CONFIG = {"os": "linux", "architecture": "arm64", "rootfs": {"type": "layers", "diff_ids": []}}
LAYER_DIGESTS = ["sha256:" + "b" * 64, "sha256:" + "c" * 64]


def sha256(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def manifest_document(config_digest: str, layer_digests: list[str]) -> bytes:
    return json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": config_digest,
                "size": 123,
            },
            "layers": [
                {
                    "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                    "digest": digest,
                    "size": 456,
                }
                for digest in layer_digests
            ],
        },
        separators=(",", ":"),
    ).encode()


class OCIRegistryIdentityTests(unittest.TestCase):
    def _responses(self, *, manifest_body: bytes | None = None):
        config_body = json.dumps(CONFIG, separators=(",", ":")).encode()
        config_digest = sha256(config_body)
        manifest_body = manifest_body or manifest_document(config_digest, LAYER_DIGESTS)
        manifest_digest = sha256(manifest_body)
        return config_body, config_digest, manifest_body, manifest_digest

    def test_verifies_manifest_bytes_config_blob_platform_and_ordered_layers(self) -> None:
        config_body, config_digest, manifest_body, manifest_digest = self._responses()
        with patch(
            "scripts.oci_registry_identity._request",
            side_effect=[
                ({}, b'{"token":"private-token"}'),
                ({"docker-content-digest": manifest_digest}, manifest_body),
                ({}, config_body),
            ],
        ) as request:
            identity = resolve_image_identity_request(IMAGE)

        self.assertEqual(
            identity,
            {
                "manifest_digest": manifest_digest,
                "config_digest": config_digest,
                "layer_digests": LAYER_DIGESTS,
                "os": "linux",
                "architecture": "arm64",
            },
        )
        self.assertEqual(request.call_count, 3)
        self.assertNotIn("private-token", repr(identity))

    def test_rejects_manifest_header_that_does_not_hash_to_body(self) -> None:
        _config_body, _config_digest, manifest_body, _manifest_digest = self._responses()
        with patch(
            "scripts.oci_registry_identity._request",
            side_effect=[
                ({}, b'{"token":"private-token"}'),
                ({"docker-content-digest": "sha256:" + "0" * 64}, manifest_body),
            ],
        ):
            self.assertIsNone(resolve_image_identity_request(IMAGE))

    def test_rejects_config_blob_digest_mismatch_and_wrong_platform(self) -> None:
        config_body, _config_digest, manifest_body, manifest_digest = self._responses()
        with patch(
            "scripts.oci_registry_identity._request",
            side_effect=[
                ({}, b'{"token":"private-token"}'),
                ({"docker-content-digest": manifest_digest}, manifest_body),
                ({}, config_body + b" "),
            ],
        ):
            self.assertIsNone(resolve_image_identity_request(IMAGE))

        amd64_config = json.dumps({**CONFIG, "architecture": "amd64"}, separators=(",", ":")).encode()
        amd64_digest = sha256(amd64_config)
        amd64_manifest = manifest_document(amd64_digest, LAYER_DIGESTS)
        with patch(
            "scripts.oci_registry_identity._request",
            side_effect=[
                ({}, b'{"token":"private-token"}'),
                ({"docker-content-digest": sha256(amd64_manifest)}, amd64_manifest),
                ({}, amd64_config),
            ],
        ):
            self.assertIsNone(resolve_image_identity_request(IMAGE))

    def test_resolves_exact_linux_arm64_child_from_index(self) -> None:
        config_body, config_digest, child_body, child_digest = self._responses()
        index_body = json.dumps(
            {
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.index.v1+json",
                "manifests": [
                    {
                        "mediaType": "application/vnd.oci.image.manifest.v1+json",
                        "digest": "sha256:" + "e" * 64,
                        "size": len(child_body),
                        "platform": {"os": "linux", "architecture": "amd64"},
                    },
                    {
                        "mediaType": "application/vnd.oci.image.manifest.v1+json",
                        "digest": child_digest,
                        "size": len(child_body),
                        "platform": {"os": "linux", "architecture": "arm64"},
                    },
                ],
            },
            separators=(",", ":"),
        ).encode()
        index_digest = sha256(index_body)
        with patch(
            "scripts.oci_registry_identity._request",
            side_effect=[
                ({}, b'{"token":"private-token"}'),
                ({"docker-content-digest": index_digest}, index_body),
                ({"docker-content-digest": child_digest}, child_body),
                ({}, config_body),
            ],
        ):
            identity = resolve_image_identity_request(IMAGE)

        self.assertEqual(identity["manifest_digest"], index_digest)
        self.assertEqual(identity["config_digest"], config_digest)
        self.assertEqual(identity["layer_digests"], LAYER_DIGESTS)

    def test_runtime_comparison_is_ordered_and_accepts_routeros_hex_form(self) -> None:
        identity = {
            "config_digest": "sha256:" + "a" * 64,
            "layer_digests": LAYER_DIGESTS,
        }
        self.assertTrue(
            runtime_identity_matches("a" * 64, ["b" * 64, "c" * 64], identity)
        )
        self.assertFalse(
            runtime_identity_matches("a" * 64, ["c" * 64, "b" * 64], identity)
        )
        self.assertFalse(
            runtime_identity_matches("a" * 64, ["b" * 64, "c" * 64, "d" * 64], identity)
        )

    def test_rejects_other_repositories_without_network_access(self) -> None:
        with patch("scripts.oci_registry_identity._request") as request:
            self.assertIsNone(resolve_image_identity_request("https://example.test/image:latest"))
        request.assert_not_called()

    def test_config_blob_redirect_is_one_hop_and_drops_registry_authorization(self) -> None:
        handler = _GitHubBlobRedirectHandler()
        source = Request("https://ghcr.io/v2/example/blobs/sha256:abc", headers={"Authorization": "Bearer secret"})
        redirected = handler.redirect_request(
            source, None, 307, "Temporary Redirect", {}, "https://pkg-containers.githubusercontent.com/blob?signature=opaque"
        )

        self.assertIsNotNone(redirected)
        self.assertIsNone(redirected.get_header("Authorization"))
        self.assertEqual(redirected.get_header("Accept-encoding"), "identity")
        self.assertIsNone(
            handler.redirect_request(
                source, None, 307, "Temporary Redirect", {}, "https://pkg-containers.githubusercontent.com/second-hop"
            )
        )

    def test_config_blob_redirect_rejects_other_hosts_and_insecure_urls(self) -> None:
        invalid_targets = [
            "https://pkg-containers.githubusercontent.com.evil.test/blob",
            "http://pkg-containers.githubusercontent.com/blob",
            "https://user@pkg-containers.githubusercontent.com/blob",
            "https://pkg-containers.githubusercontent.com:444/blob",
        ]
        for target in invalid_targets:
            with self.subTest(target=target):
                self.assertIsNone(
                    _GitHubBlobRedirectHandler().redirect_request(
                        Request("https://ghcr.io/v2/example/blobs/sha256:abc"),
                        None,
                        307,
                        "Temporary Redirect",
                        {},
                        target,
                    )
                )


if __name__ == "__main__":
    unittest.main()
