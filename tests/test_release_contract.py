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
        self.assertIn("check_deployment_health.py", canary)
        self.assertIn("CANARY_READY_URL", canary)

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


if __name__ == "__main__":
    unittest.main()
