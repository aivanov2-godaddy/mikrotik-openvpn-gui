"""Compare a local RouterOS updater export with the reviewed repository template.

This command is offline and read-only. It never connects to RouterOS, executes
either script, or emits source text or matched values.
"""

from __future__ import annotations

import difflib
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Sequence


TEMPLATE_PATH = (
    Path(__file__).resolve().parents[1]
    / "scripts"
    / "routeros"
    / "immutable-release-updater.rsc.example"
)

_CREDENTIAL_MARKER = re.compile(
    rb"(?i)(?<![a-z0-9])(?:password|passwd|secret|credential|token|api[-_ ]?key|private[-_ ]?key)(?![a-z0-9])"
)
_PRIVATE_KEY_MARKER = re.compile(rb"(?i)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")
_DESTRUCTIVE_OPERATION = re.compile(
    rb"(?i)(?:/(?:[a-z0-9_-]+/)*(?:remove|delete|reboot|shutdown|reset-configuration|format)\b)"
    rb"|\b(?:remove|delete|reboot|shutdown|reset-configuration|format)\b"
)
_FETCH_OR_DOWNLOAD = re.compile(rb"(?i)\b(?:fetch|download)\b|/tool/fetch\b")
_MAX_SCRIPT_BYTES = 1_048_576
_MAX_SCRIPT_LINES = 2_048


def _has_additional_marker(pattern: re.Pattern[bytes], reference: bytes, candidate: bytes) -> bool:
    """Flag marker counts added beyond those in the reviewed reference."""
    return len(pattern.findall(candidate)) > len(pattern.findall(reference))


def _validate_text(data: bytes) -> None:
    if len(data) > _MAX_SCRIPT_BYTES:
        raise ValueError("script too large")
    text = data.decode("utf-8")
    if "\x00" in text or len(text.splitlines()) > _MAX_SCRIPT_LINES:
        raise ValueError("invalid text")


def compare_scripts(reference: bytes, candidate: bytes) -> dict[str, object]:
    """Return redacted, deterministic evidence for two UTF-8 script files."""
    _validate_text(reference)
    _validate_text(candidate)
    matcher = difflib.SequenceMatcher(
        a=reference.splitlines(keepends=True),
        b=candidate.splitlines(keepends=True),
        autojunk=False,
    )
    changed_line_count = sum(
        (reference_end - reference_start) + (candidate_end - candidate_start)
        for operation, reference_start, reference_end, candidate_start, candidate_end in matcher.get_opcodes()
        if operation != "equal"
    )
    return {
        "reference_sha256": hashlib.sha256(reference).hexdigest(),
        "candidate_sha256": hashlib.sha256(candidate).hexdigest(),
        "exact_match": reference == candidate,
        "changed_line_count": changed_line_count,
        "risk_flags": {
            "credential_marker_added": _has_additional_marker(_CREDENTIAL_MARKER, reference, candidate),
            "private_key_marker_added": _has_additional_marker(_PRIVATE_KEY_MARKER, reference, candidate),
            "destructive_operation_marker_added": _has_additional_marker(
                _DESTRUCTIVE_OPERATION, reference, candidate
            ),
            "fetch_or_download_marker_added": _has_additional_marker(
                _FETCH_OR_DOWNLOAD, reference, candidate
            ),
        },
    }


def _emit_error(code: str) -> int:
    print(json.dumps({"error": code}, sort_keys=True))
    return 2


def _is_local_path(value: str) -> bool:
    return not value.startswith(("\\\\", "//")) and re.match(r"(?i)^[a-z][a-z0-9+.-]*://", value) is None


def main(argv: Sequence[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 1:
        return _emit_error("invalid_arguments")
    if not _is_local_path(arguments[0]):
        return _emit_error("candidate_unavailable")

    try:
        candidate_path = Path(arguments[0])
        if not candidate_path.is_file():
            return _emit_error("candidate_unavailable")
        with candidate_path.open("rb") as source:
            candidate = source.read(_MAX_SCRIPT_BYTES + 1)
        _validate_text(candidate)
    except (OSError, UnicodeError, ValueError):
        return _emit_error("candidate_unavailable")

    try:
        reference = TEMPLATE_PATH.read_bytes()
        _validate_text(reference)
    except (OSError, UnicodeError, ValueError):
        return _emit_error("reference_unavailable")

    try:
        report = compare_scripts(reference, candidate)
    except Exception:
        return _emit_error("comparison_failed")
    print(json.dumps(report, sort_keys=True))
    return 0 if report["exact_match"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
