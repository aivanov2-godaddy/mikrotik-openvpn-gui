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
            "Historical canary checkpoint — PR #806 — 2026-10-24",
            report,
        )
        self.assertIn(
            "This checkpoint is historical; the latest post-publication RouterOS point read-back is recorded near the top of this report",
            report,
        )
        self.assertIn(
            "PR #971 (`ec760fcfd4ed1cffa5e6ba067d997865fd27e03e`) is the latest published image source",
            report,
        )
        self.assertIn("Latest canary healthcheck point read — 2026-11-13 16:26:58 UTC", report)
        self.assertIn("Latest published candidate and RouterOS read-back — 2026-11-13 14:28–15:45 UTC", report)
        self.assertIn("Previous RouterOS read-back — 2026-11-13 11:03–11:29 UTC", report)
        self.assertIn("At 11:28:59 UTC, a fresh read-only WinBox container-list view showed the", report)
        self.assertIn("It classified production as `good` with its healthy field true", report)
        self.assertIn(
            "The PR #965 `--check-only` preflight blocked at `baseline / canary_unhealthy`",
            report,
        )
        self.assertIn("Direct private canary GETs at 11:10:21 UTC returned HTTP 200", report)
        self.assertIn(
            "the canary still configured with PR #894's pinned ARM64 digest",
            report,
        )
        self.assertIn("PR #971 remains unstaged", report)
        self.assertIn("Bounded in-container HTTP requests to both `/healthz` and `/readyz` timed out", report)
        self.assertIn("After an authorized restart of canary only, RouterOS reported a healthy marker again", report)
        self.assertIn("No authenticated readiness response was captured after that restart, so the running revision and sustained recovery remain unverified", report)
        self.assertIn(
            "no synchronized event timestamps were captured",
            report,
        )
        self.assertIn(
            "The disposable client later reconnected automatically",
            report,
        )
        self.assertIn(
            "A later read-only WinBox listing on 2026-10-30 reconfirmed PR #862's exact ARM64 tag and digest with a healthy marker",
            report,
        )
        self.assertIn(
            "the production row still showed the PR #788 ARM64 tag. RouterOS showed one active test tunnel",
            report,
        )
        self.assertIn("digest prefix matching the published PR #862 ARM64 digest", report)
        self.assertIn(
            "At that time, PR #893 was the latest published image and no post-publication RouterOS read-back was available",
            report,
        )
        self.assertIn(
            "returned PR #862 revision `445c1d5ca0f28174629be8e8cd94f04de132f0fc`, confirming that the canary was not running PR #885",
            report,
        )
        self.assertNotIn("PR #862 has not been read back on RouterOS", report)
        self.assertNotIn("PR #791 has been published but not staged", report)

    def test_pr806_canary_references_are_explicitly_historical(self) -> None:
        roadmap = " ".join(
            (ROOT / "docs" / "ROADMAP.md").read_text(encoding="utf-8").split()
        )
        self.assertIn(
            "Historical note: PR #806 was the latest digest-bound canary read-back at that time",
            roadmap,
        )
        self.assertIn("The latest documented canary checkpoint is PR #894", roadmap)
        self.assertNotIn(
            "The last digest-bound canary read-back is PR #806", roadmap
        )

        report = " ".join(
            (ROOT / "docs" / "LIVE_TELEMETRY_ACCEPTANCE_REPORT.md")
            .read_text(encoding="utf-8")
            .split()
        )
        self.assertIn(
            "At the time that record was updated, PR #806 was the staged canary",
            report,
        )
        self.assertIn(
            "That checkpoint was later superseded by the PR #894 checkpoint at the top of this report",
            report,
        )
        self.assertNotIn(
            "PR #806 is staged on the canary with healthy revision read-back recorded above",
            report,
        )

        releases = " ".join(
            (ROOT / "docs" / "RELEASES.md").read_text(encoding="utf-8").split()
        )
        for stale_claim in (
            "Current PR #806",
            "current PR #806 state",
            "the current PR #806",
        ):
            self.assertNotIn(stale_claim, releases)
        self.assertIn(
            "That checkpoint was later superseded by the PR #894 checkpoint at the top of this file",
            releases,
        )

        routeros = " ".join(
            (ROOT / "docs" / "ROUTEROS_ACCEPTANCE.md")
            .read_text(encoding="utf-8")
            .split()
        )
        self.assertIn(
            "PR #806 was the last candidate-bound read-back when this section was written",
            routeros,
        )
        self.assertIn("superseded by PR #894 above", routeros)

    def test_current_inventory_group_policy_does_not_relabel_old_report(self) -> None:
        roadmap = " ".join(
            (ROOT / "docs" / "ROADMAP.md").read_text(encoding="utf-8").split()
        )
        acceptance = " ".join(
            (ROOT / "docs" / "ROUTEROS_ACCEPTANCE.md")
            .read_text(encoding="utf-8")
            .split()
        )
        for document in (roadmap, acceptance):
            self.assertIn("`read,api,rest-api`", document)
            self.assertIn("one existing group member", document)
            self.assertIn("predates this policy change", document)
            self.assertIn("No account was created and no password was changed", document)
        self.assertIn(
            "the configured target is therefore resolved within the exported set",
            roadmap,
        )
        self.assertIn(
            "This resolves the configured target in the exported set", acceptance
        )
        self.assertIn("the scheduler is disabled and was not", acceptance)


if __name__ == "__main__":
    unittest.main()
