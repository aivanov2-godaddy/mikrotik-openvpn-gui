from __future__ import annotations

import contextlib
import io
import subprocess
import tempfile
import unittest
from pathlib import Path

from scripts.check_history import main, scan_history


class HistoryScanTests(unittest.TestCase):
    @staticmethod
    def _git(repository: Path, *arguments: str) -> None:
        subprocess.run(
            ["git", "-C", str(repository), *arguments],
            check=True,
            capture_output=True,
            text=True,
        )

    def _repository_with_deleted_secret(
        self, marker: str = ""
    ) -> tuple[tempfile.TemporaryDirectory[str], Path, str]:
        temporary = tempfile.TemporaryDirectory[str]()
        repository = Path(temporary.name)
        self._git(repository, "init", "--quiet")
        self._git(repository, "config", "user.name", "History Test")
        self._git(repository, "config", "user.email", "history@example.test")
        token = "ghp_" + "A" * 36
        (repository / "retired.txt").write_text(f"{token}\n{marker}", encoding="utf-8")
        self._git(repository, "add", "retired.txt")
        self._git(repository, "commit", "--quiet", "-m", "add temporary credential")
        (repository / "retired.txt").write_text("removed", encoding="utf-8")
        self._git(repository, "add", "retired.txt")
        self._git(repository, "commit", "--quiet", "-m", "remove temporary credential")
        return temporary, repository, token

    def test_detects_a_secret_that_exists_only_in_deleted_history(self) -> None:
        temporary, repository, _ = self._repository_with_deleted_secret()
        self.addCleanup(temporary.cleanup)

        findings = scan_history(repository)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].path, "retired.txt")
        self.assertEqual(findings[0].rule, "GitHub token")

    def test_marker_findings_and_cli_output_redact_the_marker_value(self) -> None:
        marker = "private-" + "instance-marker"
        temporary, repository, token = self._repository_with_deleted_secret(marker)
        self.addCleanup(temporary.cleanup)

        findings = scan_history(repository, markers=(marker,))
        self.assertTrue(any(finding.rule == "custom marker 1" for finding in findings))

        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            status = main(["--repo", str(repository), "--marker", marker])
        rendered = stderr.getvalue()
        self.assertEqual(status, 1)
        self.assertNotIn(marker, rendered)
        self.assertNotIn(token, rendered)


if __name__ == "__main__":
    unittest.main()
