from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OPERATIONS = ROOT / "docs" / "OPERATIONS.md"
CANDIDATE_SHA = "beba66c0f36231511ec1b9cc664f2be39a128750"
REDIS_RUN_ID = "39984997001"


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
        self.assertIn("[IO.FileAttributes]::ReparsePoint", self.section)
        self.assertIn("while ($cursorPath)", self.section)
        self.assertGreaterEqual(self.section.count("[IO.FileAttributes]::ReparsePoint"), 2)
        self.assertIn("$env:GH_TOKEN = $ghToken", self.section)
        self.assertIn("Remove-Item Env:GH_TOKEN", self.section)
        self.assertIn(
            "Remove-Item Env:VPN_ACCEPTANCE_CANARY_TOKEN, Env:VPN_ACCEPTANCE_PRODUCTION_TOKEN",
            self.section,
        )
        self.assertIn("if ($locationPushed) { Pop-Location }", self.section)
        self.assertIn("gh auth token", self.section)
        self.assertNotIn("After both collection phases", self.section)
        self.assertIn("process-scoped environment", self.section)
        self.assertIn("never write them to files, reports, or command arguments", self.section)
        blocks = re.findall(r"```powershell\s*\n(.*?)```", self.section, flags=re.DOTALL)
        self.assertGreaterEqual(len(blocks), 2)
        for block in blocks:
            with self.subTest(block=block[:80]):
                self.assertNotRegex(block, r"<[^>\r\n]+>")

    def test_promotion_gate_uses_prepromotion_evidence_and_outputs_are_distinct(self) -> None:
        collect_pre = self.section.index("--phase canary-prepromotion")
        evaluate_pre = self.section.index("private-acceptance-report-prepromotion.json")
        promotion_gate = self.section.index("--check-only")
        collect_post = self.section.index("--phase postpromotion")
        evaluate_post = self.section.index("private-acceptance-report-postpromotion.json")

        self.assertLess(collect_pre, evaluate_pre)
        self.assertLess(evaluate_pre, promotion_gate)
        self.assertLess(promotion_gate, collect_post)
        self.assertLess(collect_post, evaluate_post)
        self.assertIn("private-collected-evidence-prepromotion.json", self.section)
        self.assertIn("private-collected-evidence-postpromotion.json", self.section)
        self.assertIn("Never use post-promotion evidence as the promotion input.", self.section)
        self.assertNotIn("private-collected-evidence.json'", self.section)

    def test_latest_published_candidate_is_distinguished_from_recorded_canary(self) -> None:
        report = " ".join(
            (ROOT / "docs" / "LIVE_TELEMETRY_ACCEPTANCE_REPORT.md")
            .read_text(encoding="utf-8")
            .split()
        )
        self.assertIn(
            "historical acceptance record for candidate PR #776", report
        )
        self.assertIn(
            "The earlier qualitative live-UI check was on PR #806 and does not provide evidence for this candidate.",
            report,
        )
        self.assertIn(
            "PR #871 (`eb29581c8430ec862a8b47ee62268a74fec14518`) is the latest published image source",
            report,
        )
        self.assertIn(
            "The latest confirmed candidate-bound read-back is PR #862",
            report,
        )
        self.assertIn("digest prefix matching its published ARM64 digest", report)
        self.assertIn("PR #871 has not been staged", report)
        self.assertIn("exact `/readyz` revision claim remains unverified", report)
        self.assertNotIn("PR #862 has not been read back on RouterOS", report)
        self.assertNotIn("PR #791 has been published but not staged", report)


if __name__ == "__main__":
    unittest.main()
