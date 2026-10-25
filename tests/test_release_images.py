from __future__ import annotations

import unittest

from scripts.release_images import (
    PROJECT_REPOSITORY,
    image_digest,
    parse_project_image,
    pin_project_image,
    registry_relative_image,
)


REVISION = "a" * 40
ARM64_DIGEST = "sha256:" + "b" * 64
AMD64_DIGEST = "sha256:" + "c" * 64


class ReleaseImageTests(unittest.TestCase):
    def test_parses_digest_pinned_architecture_specific_project_references(self) -> None:
        for architecture, digest in (("arm64", ARM64_DIGEST), ("amd64", AMD64_DIGEST)):
            with self.subTest(architecture=architecture):
                reference = f"{PROJECT_REPOSITORY}:sha-{REVISION}-{architecture}@{digest}"
                identity = parse_project_image(reference, architecture=architecture)
                self.assertEqual(identity.revision, REVISION)
                self.assertEqual(identity.architecture, architecture)
                self.assertEqual(identity.digest, digest)
                self.assertEqual(image_digest(reference), digest)

    def test_normalizes_registry_relative_routeros_reference(self) -> None:
        relative = f"aivanov2-godaddy/mikrotik-openvpn-gui:sha-{REVISION}-arm64@{ARM64_DIGEST}"
        self.assertEqual(registry_relative_image(relative), relative)
        self.assertEqual(registry_relative_image(f"ghcr.io/{relative}"), relative)

    def test_pins_legacy_tag_only_reference_after_digest_verification(self) -> None:
        relative_tag = f"aivanov2-godaddy/mikrotik-openvpn-gui:sha-{REVISION}-arm64"
        full_tag = f"{PROJECT_REPOSITORY}:sha-{REVISION}-arm64"

        self.assertEqual(
            pin_project_image(relative_tag, ARM64_DIGEST),
            f"{PROJECT_REPOSITORY}:sha-{REVISION}-arm64@{ARM64_DIGEST}",
        )
        self.assertEqual(
            pin_project_image(full_tag, ARM64_DIGEST),
            f"{PROJECT_REPOSITORY}:sha-{REVISION}-arm64@{ARM64_DIGEST}",
        )

    def test_rejects_tag_only_when_digest_is_required(self) -> None:
        with self.assertRaisesRegex(ValueError, "include its SHA-256 digest"):
            parse_project_image(f"{PROJECT_REPOSITORY}:sha-{REVISION}-arm64")

    def test_rejects_wrong_repository_architecture_and_digest(self) -> None:
        with self.assertRaisesRegex(ValueError, "this project's"):
            parse_project_image(f"ghcr.io/other/project:sha-{REVISION}-arm64@{ARM64_DIGEST}")
        with self.assertRaisesRegex(ValueError, "architecture"):
            parse_project_image(
                f"{PROJECT_REPOSITORY}:sha-{REVISION}-amd64@{AMD64_DIGEST}",
                architecture="arm64",
            )
        with self.assertRaises(ValueError):
            parse_project_image(f"{PROJECT_REPOSITORY}:sha-{REVISION}-arm64@sha256:" + "B" * 64)

    def test_refuses_conflicting_existing_digest(self) -> None:
        pinned = f"{PROJECT_REPOSITORY}:sha-{REVISION}-arm64@{ARM64_DIGEST}"
        with self.assertRaisesRegex(ValueError, "do not match"):
            pin_project_image(pinned, AMD64_DIGEST)


if __name__ == "__main__":
    unittest.main()
