"""Regression checks for the public v1.0 release boundary."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class ReleaseContractTests(unittest.TestCase):
    def test_public_repository_has_no_router_deployment_workflow(self) -> None:
        workflows = ROOT / ".github" / "workflows"
        self.assertFalse((workflows / "deploy-production.yml").exists())
        self.assertFalse((workflows / "validate-routeros-canary.yml").exists())

        publish = (workflows / "container.yml").read_text(encoding="utf-8")
        self.assertIn("ghcr.io/${{ github.repository }}", publish)
        self.assertNotIn("deploy_routeros_release.py", publish)
        self.assertNotIn("self-hosted", publish)
        self.assertNotIn("ROUTEROS_", publish)

    def test_release_documentation_describes_the_safe_boundary(self) -> None:
        release_notes = (ROOT / "docs/RELEASES.md").read_text(encoding="utf-8")
        deployment = (ROOT / "docs/DEPLOYMENT.md").read_text(encoding="utf-8")
        installation = (ROOT / "docs/INSTALLATION.md").read_text(encoding="utf-8")

        self.assertIn("Public-source boundary", release_notes)
        self.assertIn("never deploys them to", deployment)
        self.assertIn("your router", deployment)
        self.assertIn("separate private", installation)
        self.assertIn("deployment repository", installation)
        self.assertIn("canary", deployment.casefold())

    def test_preview_assets_do_not_contain_instance_identities(self) -> None:
        assets = (
            ROOT / "docs/screenshots/dashboard-navigation.svg",
            ROOT / "docs/screenshots/dashboard-sections.svg",
        )
        prohibited = (
            "core" + ".wanted" + ".sx",
            "al" + "ex",
            "sam" + "sung s26 ultra",
        )
        rendered = "\n".join(asset.read_text(encoding="utf-8").lower() for asset in assets)
        for marker in prohibited:
            with self.subTest(marker=marker):
                self.assertNotIn(marker, rendered)

    def test_installation_documents_use_portable_examples(self) -> None:
        documents = (
            ROOT / "README.md",
            ROOT / "docs/INSTALLATION.md",
            ROOT / "docs/REPOSITORY_SETUP.md",
        )
        prohibited = (
            "wanted" + ".sx",
            "rb" + "5009upr+s+",
            "172.31." + "255.",
        )
        rendered = "\n".join(document.read_text(encoding="utf-8").lower() for document in documents)
        for marker in prohibited:
            with self.subTest(marker=marker):
                self.assertNotIn(marker, rendered)


if __name__ == "__main__":
    unittest.main()
