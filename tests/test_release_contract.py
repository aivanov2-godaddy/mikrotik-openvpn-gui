"""Regression checks for the public-release deployment boundary."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class ReleaseContractTests(unittest.TestCase):
    def test_routeros_deploy_is_explicit_by_default(self) -> None:
        workflow = (ROOT / ".github/workflows/deploy-production.yml").read_text(encoding="utf-8")
        canary = (ROOT / ".github/workflows/validate-routeros-canary.yml").read_text(encoding="utf-8")

        self.assertIn("confirm_production:", workflow)
        self.assertIn("inputs.confirm_production == 'DEPLOY'", workflow)
        self.assertIn("vars.ENABLE_ROUTEROS_AUTODEPLOY == 'true'", workflow)
        self.assertIn("github.event.workflow_run.head_repository.full_name == github.repository", workflow)
        self.assertNotIn("branches: [main]", workflow)
        self.assertIn("git merge-base --is-ancestor", workflow)
        self.assertIn("sha-${{ env.RELEASE_COMMIT }}-${{ env.RELEASE_ARCHITECTURE }}", workflow)
        self.assertIn('workflows: ["Validate RouterOS canary"]', workflow)
        self.assertIn("github.event.workflow_run.event == 'workflow_run'", workflow)
        self.assertIn('workflows: ["Publish container"]', canary)
        self.assertIn("CANARY_BASELINE_IMAGE", canary)
        self.assertIn("RouterOS canary gate", canary)
        self.assertIn("$normalizedCa = $env:ROUTEROS_REST_CA_B64", canary)
        self.assertIn("[Convert]::FromBase64String($normalizedCa)", canary)
        self.assertNotIn("FromBase64String($env:ROUTEROS_REST_CA_B64", canary)
        self.assertNotIn("CANARY_READY_URL", canary)
        self.assertNotIn("check_deployment_health.py", canary)

        publish = (ROOT / ".github/workflows/container.yml").read_text(encoding="utf-8")
        self.assertNotIn('"scripts/deploy_routeros_release.py"', publish)
        self.assertNotIn('".github/workflows/container.yml"', publish)
        self.assertNotIn('"*.py"', publish)

    def test_release_documentation_describes_fork_safe_opt_in(self) -> None:
        release_notes = (ROOT / "docs/RELEASES.md").read_text(encoding="utf-8")
        deployment = (ROOT / "docs/DEPLOYMENT.md").read_text(encoding="utf-8")
        installation = (ROOT / "docs/INSTALLATION.md").read_text(encoding="utf-8")

        self.assertIn("Fork-safe deployment boundary", release_notes)
        self.assertIn("ENABLE_ROUTEROS_AUTODEPLOY=true", release_notes)
        self.assertIn("Public-source boundary", release_notes)
        self.assertIn("Type `DEPLOY`", deployment)
        self.assertIn("manual promotion", installation)
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
            "aivanov2" + "-godaddy",
            "rb" + "5009upr+s+",
            "172.31." + "255.",
        )
        rendered = "\n".join(document.read_text(encoding="utf-8").lower() for document in documents)
        for marker in prohibited:
            with self.subTest(marker=marker):
                self.assertNotIn(marker, rendered)


if __name__ == "__main__":
    unittest.main()
