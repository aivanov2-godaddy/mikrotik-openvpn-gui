"""Tests for parsing immutable image digests from Docker CLI output."""

from __future__ import annotations

import unittest

from scripts.extract_registry_digest import extract_registry_digest


class RegistryDigestTests(unittest.TestCase):
    def test_extracts_digest_from_tag_prefixed_push_line(self) -> None:
        digest = "sha256:" + "a" * 64
        output = f"layer: Pushed\nsha-arm64: digest: {digest} size: 1234\n"

        self.assertEqual(extract_registry_digest(output), digest)

    def test_rejects_output_without_digest(self) -> None:
        with self.assertRaisesRegex(ValueError, "did not contain"):
            extract_registry_digest("image: pushed\n")

    def test_rejects_ambiguous_multiple_digests(self) -> None:
        first = "sha256:" + "a" * 64
        second = "sha256:" + "b" * 64
        with self.assertRaisesRegex(ValueError, "multiple different"):
            extract_registry_digest(f"one: digest: {first}\ntwo: digest: {second}\n")


if __name__ == "__main__":
    unittest.main()
