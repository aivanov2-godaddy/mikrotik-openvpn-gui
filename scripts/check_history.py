"""Scan all reachable Git history without printing secret or marker values."""

from __future__ import annotations

import argparse
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


DEFAULT_RULES = (
    ("private-key block", r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----"),
    ("Cloudflare API token", r"\bcfat_[A-Za-z0-9_-]{20,}\b"),
    ("GitHub token", r"\bgh(?:p|o|u|s|r)_[A-Za-z0-9]{20,}\b"),
    ("GitHub fine-grained token", r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    ("GitLab token", r"\bglpat-[A-Za-z0-9_-]{20,}\b"),
    ("Slack token", r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
    ("AWS access key", r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
)


class HistoryScanError(RuntimeError):
    """Raised when the local Git history cannot be inspected safely."""


@dataclass(frozen=True, slots=True)
class HistoryFinding:
    commit: str
    path: str
    rule: str


def _git(repository: Path, arguments: Iterable[str], *, no_match_is_ok: bool = False) -> str:
    result = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        return result.stdout
    if no_match_is_ok and result.returncode == 1:
        return ""
    raise HistoryScanError("Git history scan could not complete for the selected repository")


def reachable_commits(repository: Path) -> tuple[str, ...]:
    commits = _git(repository, ("rev-list", "--all")).splitlines()
    if not commits:
        raise HistoryScanError("The selected repository has no reachable commits")
    return tuple(commits)


def _matching_paths(
    repository: Path, commit: str, pattern: str, *, fixed: bool
) -> tuple[str, ...]:
    # The credential expressions use Python/PCRE constructs such as `(?:...)`.
    # Git's default extended-regexp engine cannot parse them, so use PCRE for
    # those trusted built-in patterns and literal matching for user markers.
    mode = "-F" if fixed else "-P"
    output = _git(
        repository,
        ("grep", "-I", "-l", mode, "-e", pattern, commit),
        no_match_is_ok=True,
    )
    prefix = f"{commit}:"
    return tuple(
        path.removeprefix(prefix) for path in output.splitlines() if path
    )


def scan_history(
    repository: Path, *, markers: tuple[str, ...] = ()
) -> tuple[HistoryFinding, ...]:
    """Return redacted locations for credential patterns and supplied markers.

    The marker strings are passed to Git only as search inputs. They are never
    saved, logged, or included in `HistoryFinding` values.
    """
    repo = repository.resolve()
    commits = reachable_commits(repo)
    rules = [(*rule, False) for rule in DEFAULT_RULES]
    rules.extend(
        (f"custom marker {index}", marker, True)
        for index, marker in enumerate(markers, start=1)
        if marker
    )
    findings: list[HistoryFinding] = []
    for commit in commits:
        for label, pattern, fixed in rules:
            for path in _matching_paths(repo, commit, pattern, fixed=fixed):
                findings.append(HistoryFinding(commit[:12], path, label))
    return tuple(findings)


def main(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Scan every reachable Git commit without revealing matched values."
    )
    parser.add_argument("--repo", default=".", help="local Git repository to scan")
    parser.add_argument(
        "--marker",
        action="append",
        default=[],
        help="private instance marker to detect; the value is never printed",
    )
    args = parser.parse_args(arguments)
    try:
        findings = scan_history(Path(args.repo), markers=tuple(args.marker))
    except HistoryScanError as error:
        print(str(error), file=sys.stderr)
        return 2

    if findings:
        print("Reachable-history findings (matched values are intentionally hidden):", file=sys.stderr)
        for finding in findings:
            print(f"- {finding.commit}:{finding.path}: {finding.rule}", file=sys.stderr)
        return 1

    print("No configured credential patterns or private markers found in reachable history.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
