"""Tests for version and source-ancestry release validation."""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "scripts" / "validate_release.py"
VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()


class ValidateReleaseTests(unittest.TestCase):
    def run_validator(self, repository: Path, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(VALIDATOR), *args],
            cwd=repository,
            check=False,
            capture_output=True,
            text=True,
        )

    @staticmethod
    def git(repository: Path, *args: str) -> str:
        result = subprocess.run(
            ["git", *args],
            cwd=repository,
            check=True,
            capture_output=True,
            text=True,
        )
        return result.stdout.strip()

    def test_release_tag_must_match_version(self) -> None:
        current = self.run_validator(ROOT, "--tag", f"v{VERSION}")
        mismatch = self.run_validator(ROOT, "--tag", f"v{VERSION}-wrong")

        self.assertEqual(current.returncode, 0, current.stderr)
        self.assertNotEqual(mismatch.returncode, 0)
        self.assertIn("does not match VERSION", mismatch.stderr)

    def test_release_commit_must_be_reachable_from_main_ref(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            self.git(repository, "init")
            self.git(repository, "config", "user.name", "Release contract test")
            self.git(repository, "config", "user.email", "release-contract@example.invalid")
            (repository / "tracked.txt").write_text("main commit 1\n", encoding="utf-8")
            self.git(repository, "add", "tracked.txt")
            self.git(repository, "commit", "-m", "main commit 1")
            first_main_commit = self.git(repository, "rev-parse", "HEAD")
            self.git(repository, "branch", "-M", "main")
            (repository / "tracked.txt").write_text("main commit 2\n", encoding="utf-8")
            self.git(repository, "commit", "-am", "main commit 2")

            self.git(repository, "checkout", "--detach", first_main_commit)
            ancestor = self.run_validator(
                repository,
                "--tag",
                f"v{VERSION}",
                "--main-ref",
                "refs/heads/main",
            )
            self.assertEqual(ancestor.returncode, 0, ancestor.stderr)

            self.git(repository, "checkout", "main")
            self.git(repository, "checkout", "--orphan", "off-main")
            self.git(repository, "rm", "-r", "-f", ".")
            (repository / "off-main.txt").write_text("not on main\n", encoding="utf-8")
            self.git(repository, "add", "off-main.txt")
            self.git(repository, "commit", "-m", "unreviewed release source")
            off_branch = self.run_validator(
                repository,
                "--tag",
                f"v{VERSION}",
                "--main-ref",
                "refs/heads/main",
            )

            self.assertNotEqual(off_branch.returncode, 0)
            self.assertIn("not reachable from", off_branch.stderr)


if __name__ == "__main__":
    unittest.main()
