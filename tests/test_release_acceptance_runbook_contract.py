from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OPERATIONS = ROOT / "docs" / "OPERATIONS.md"
CANDIDATE_SHA = "8fb7a6d3d64f5d57f5ed5f74cdaae121dc0ad6ee"
REDIS_RUN_ID = "39931754294"


class ReleaseAcceptanceRunbookContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        text = OPERATIONS.read_text(encoding="utf-8")
        start = text.index("### Release acceptance evidence")
        end = text.index("## Credential and certificate rotation", start)
        cls.section = text[start:end]

    def test_redis_recovery_run_is_successful_and_candidate_bound(self) -> None:
        self.assertIn(CANDIDATE_SHA, self.section)
        self.assertIn(REDIS_RUN_ID, self.section)
        self.assertIn(f"--redis-recovery-run-id {REDIS_RUN_ID}", self.section)
        self.assertIn("successful main-branch CI run", self.section)
        self.assertIn(f"redis-recovery-{CANDIDATE_SHA}", self.section)

    def test_redacted_rollback_and_certificate_reports_have_documented_sources(self) -> None:
        self.assertIn("--rollback-report private-rollback-rehearsal.json", self.section)
        self.assertIn("scripts/collect_rollback_acceptance.py", self.section)
        self.assertRegex(self.section, r"operator performs the\s+ordered rollback stages on canary only")
        self.assertIn("--certificate-lifecycle-report private-certificate-lifecycle.json", self.section)
        self.assertIn("certificate-lifecycle-acceptance.example.json", self.section)
        self.assertIn("operator-attested report", self.section)
        self.assertRegex(self.section, r"does\s+not\s+independently observe the certificate actions")

    def test_powershell_examples_keep_evidence_outside_repo_and_avoid_angle_placeholders(self) -> None:
        self.assertIn("VPN_ACCEPTANCE_EVIDENCE_DIR", self.section)
        self.assertIn("$evidenceDir.StartsWith($repoPrefix", self.section)
        self.assertIn("$env:GH_TOKEN = $ghToken", self.section)
        self.assertIn("Remove-Item Env:GH_TOKEN", self.section)
        self.assertIn("gh auth token", self.section)
        self.assertIn("process-scoped environment", self.section)
        self.assertIn("never write them to files, reports, or command arguments", self.section)
        blocks = re.findall(r"```powershell\s*\n(.*?)```", self.section, flags=re.DOTALL)
        self.assertGreaterEqual(len(blocks), 2)
        for block in blocks:
            with self.subTest(block=block[:80]):
                self.assertNotRegex(block, r"<[^>\r\n]+>")


if __name__ == "__main__":
    unittest.main()
