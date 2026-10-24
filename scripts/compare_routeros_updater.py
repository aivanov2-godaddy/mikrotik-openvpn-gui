"""Compare a local RouterOS updater export with the reviewed repository template.

This command is offline and read-only. It never connects to RouterOS, executes
either script, or emits source text or matched values.
"""

from __future__ import annotations

import difflib
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path
from pathlib import PurePosixPath, PureWindowsPath
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
_MAX_INVENTORY_BYTES = 262_144
_MAX_INVENTORY_SCRIPTS = 128
_MAX_INVENTORY_SCHEDULERS = 512
_INVENTORY_ID = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,63}$")


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


def _windows_drive_type(anchor: str) -> int:
    try:
        import ctypes

        return int(ctypes.windll.kernel32.GetDriveTypeW(anchor))
    except Exception:
        return 0


def _has_reparse_point(path: Path) -> bool:
    """Reject Windows links/mount points before descending through them."""
    absolute = path.absolute()
    current = Path(absolute.anchor)
    for component in absolute.parts[len(current.parts) :]:
        current = current / component
        try:
            attributes = getattr(current.lstat(), "st_file_attributes", 0)
        except FileNotFoundError:
            return False
        except OSError:
            return True
        if attributes & 0x400:  # FILE_ATTRIBUTE_REPARSE_POINT
            return True
    return False


def _is_local_filesystem(path: Path) -> bool:
    """Reject Windows remote drives and reparse points that could leave the local disk."""
    if sys.platform != "win32":
        return True
    absolute = path.absolute()
    if not absolute.anchor or _windows_drive_type(absolute.anchor) not in {2, 3, 5, 6}:
        return False
    return not _has_reparse_point(absolute)


def _read_windows_file(path: Path, limit: int, expected_root: Path | None) -> tuple[bytes, Path]:
    """Open once without following the final reparse point; validate and read that handle."""
    import ctypes
    import msvcrt
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    class FileAttributeTagInfo(ctypes.Structure):
        _fields_ = [("attributes", wintypes.DWORD), ("reparse_tag", wintypes.DWORD)]

    create_file = kernel32.CreateFileW
    create_file.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    create_file.restype = wintypes.HANDLE
    expected_path = path.absolute()
    handle = create_file(
        str(expected_path),
        0x80000000,  # GENERIC_READ
        0x00000001,  # FILE_SHARE_READ; deny concurrent writes/deletes
        None,
        3,  # OPEN_EXISTING
        0x00200080,  # FILE_FLAG_OPEN_REPARSE_POINT | FILE_ATTRIBUTE_NORMAL
        None,
    )
    handle_value = handle if isinstance(handle, int) else handle.value
    if handle_value in (None, ctypes.c_void_p(-1).value):
        raise OSError(ctypes.get_last_error(), "safe file open failed")

    try:
        get_info = kernel32.GetFileInformationByHandleEx
        get_info.argtypes = (wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD)
        get_info.restype = wintypes.BOOL
        info = FileAttributeTagInfo()
        if not get_info(handle, 9, ctypes.byref(info), ctypes.sizeof(info)):  # FileAttributeTagInfo
            raise OSError(ctypes.get_last_error(), "file attributes unavailable")
        if info.attributes & (0x400 | 0x10):  # REPARSE_POINT | DIRECTORY
            raise ValueError("file is not a regular local file")

        get_final_path = kernel32.GetFinalPathNameByHandleW
        get_final_path.argtypes = (wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD)
        get_final_path.restype = wintypes.DWORD
        final_buffer = ctypes.create_unicode_buffer(32768)
        final_length = get_final_path(handle, final_buffer, len(final_buffer), 0)
        if not final_length or final_length >= len(final_buffer):
            raise OSError(ctypes.get_last_error(), "file location unavailable")
        final_text = final_buffer.value
        if final_text.casefold().startswith("\\\\?\\unc\\"):
            raise ValueError("remote file rejected")
        if final_text.startswith("\\\\?\\"):
            final_text = final_text[4:]
        final_path = Path(final_text)
        if _windows_drive_type(final_path.anchor) not in {2, 3, 5, 6}:
            raise ValueError("remote or unknown volume rejected")
        if final_path != expected_path:
            raise ValueError("opened file differs from requested path")
        if expected_root is not None:
            try:
                final_path.relative_to(expected_root)
            except ValueError as error:
                raise ValueError("file escaped inventory directory") from error

        descriptor = msvcrt.open_osfhandle(handle_value, os.O_RDONLY | os.O_BINARY)
        handle_value = None
        with os.fdopen(descriptor, "rb") as source:
            data = source.read(limit + 1)
        if len(data) > limit:
            raise ValueError("file too large")
        return data, final_path
    finally:
        if handle_value is not None:
            kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
            kernel32.CloseHandle.restype = wintypes.BOOL
            kernel32.CloseHandle(handle)


def _read_posix_file(path: Path, limit: int, expected_root: Path | None) -> tuple[bytes, Path]:
    """Walk from a directory descriptor without following symlinks, then read the pinned fd."""
    absolute = path.absolute()
    root = (expected_root or absolute.parent).absolute()
    try:
        relative = absolute.relative_to(root)
    except ValueError as error:
        raise ValueError("file escaped inventory directory") from error
    if not relative.parts or any(part in ("", ".", "..") for part in relative.parts):
        raise ValueError("invalid relative file path")

    no_follow = getattr(os, "O_NOFOLLOW", None)
    nonblocking = getattr(os, "O_NONBLOCK", None)
    directory = getattr(os, "O_DIRECTORY", None)
    if (
        no_follow is None
        or nonblocking is None
        or directory is None
        or os.open not in getattr(os, "supports_dir_fd", set())
    ):
        raise OSError("symlink-safe local file access is unavailable")
    directory_flags = os.O_RDONLY | directory | no_follow
    file_flags = os.O_RDONLY | no_follow | nonblocking
    directory_fd = os.open(root.anchor or os.sep, directory_flags)
    try:
        for component in root.parts[1:]:
            next_fd = os.open(component, directory_flags, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        for component in relative.parts[:-1]:
            next_fd = os.open(component, directory_flags, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        file_fd = os.open(relative.parts[-1], file_flags, dir_fd=directory_fd)
        with os.fdopen(file_fd, "rb") as source:
            if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
                raise ValueError("candidate is not a regular file")
            data = source.read(limit + 1)
        if len(data) > limit:
            raise ValueError("file too large")
        return data, root / relative
    finally:
        os.close(directory_fd)


def _read_local_file(path: Path, limit: int, expected_root: Path | None = None) -> tuple[bytes, Path]:
    if not _is_local_filesystem(path):
        raise ValueError("non-local path")
    if sys.platform == "win32":
        return _read_windows_file(path, limit, expected_root)
    return _read_posix_file(path, limit, expected_root)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _parse_inventory(data: bytes) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    if len(data) > _MAX_INVENTORY_BYTES:
        raise ValueError("inventory too large")
    text = data.decode("utf-8")
    if "\x00" in text:
        raise ValueError("invalid inventory text")
    document = json.loads(text, object_pairs_hook=_unique_object)
    if not isinstance(document, dict) or set(document) != {"schema_version", "scripts", "schedulers"}:
        raise ValueError("invalid inventory shape")
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        raise ValueError("unsupported inventory schema")

    scripts_value = document["scripts"]
    schedulers_value = document["schedulers"]
    if (
        not isinstance(scripts_value, list)
        or not scripts_value
        or len(scripts_value) > _MAX_INVENTORY_SCRIPTS
        or not isinstance(schedulers_value, list)
        or len(schedulers_value) > _MAX_INVENTORY_SCHEDULERS
    ):
        raise ValueError("invalid inventory counts")

    scripts: list[dict[str, str]] = []
    script_ids: set[str] = set()
    source_paths: set[str] = set()
    for item in scripts_value:
        if not isinstance(item, dict) or set(item) != {"id", "path"}:
            raise ValueError("invalid script entry")
        script_id, source_path = item["id"], item["path"]
        if not isinstance(script_id, str) or _INVENTORY_ID.fullmatch(script_id) is None:
            raise ValueError("invalid script id")
        if script_id in script_ids:
            raise ValueError("duplicate script id")
        if not isinstance(source_path, str) or not source_path or "\x00" in source_path or "\\" in source_path:
            raise ValueError("invalid script path")
        posix_path = PurePosixPath(source_path)
        windows_path = PureWindowsPath(source_path)
        if (
            posix_path.is_absolute()
            or windows_path.is_absolute()
            or windows_path.drive
            or ":" in source_path
            or any(part in ("", ".", "..") for part in posix_path.parts)
        ):
            raise ValueError("non-local script path")
        normalized_path = posix_path.as_posix().casefold()
        if normalized_path in source_paths:
            raise ValueError("duplicate script path")
        source_paths.add(normalized_path)
        script_ids.add(script_id)
        scripts.append({"id": script_id, "path": source_path})

    schedulers: list[dict[str, str]] = []
    scheduler_ids: set[str] = set()
    for item in schedulers_value:
        if not isinstance(item, dict) or set(item) != {"id", "script_id"}:
            raise ValueError("invalid scheduler entry")
        scheduler_id, script_id = item["id"], item["script_id"]
        if not isinstance(scheduler_id, str) or _INVENTORY_ID.fullmatch(scheduler_id) is None:
            raise ValueError("invalid scheduler id")
        if scheduler_id in scheduler_ids:
            raise ValueError("duplicate scheduler id")
        if not isinstance(script_id, str) or script_id not in script_ids:
            raise ValueError("unresolved scheduler binding")
        scheduler_ids.add(scheduler_id)
        schedulers.append({"id": scheduler_id, "script_id": script_id})
    return scripts, schedulers


def compare_inventory(reference: bytes, data: bytes, inventory_path: Path) -> dict[str, object]:
    """Compare each manifest-listed local copy and validate direct scheduler bindings.

    The manifest is a normalized operator transcription, not a RouterOS export
    parser and not proof that its contents match the live device.
    """
    _validate_text(reference)
    scripts, schedulers = _parse_inventory(data)
    inventory_path = inventory_path.absolute()
    if not _is_local_filesystem(inventory_path):
        raise ValueError("inventory is not on a local filesystem")
    inventory_root = inventory_path.parent
    binding_counts = {script["id"]: 0 for script in scripts}
    for scheduler in schedulers:
        binding_counts[scheduler["script_id"]] += 1

    comparisons: list[dict[str, object]] = []
    for index, script in enumerate(scripts, start=1):
        relative = script["path"]
        local_candidate_path = inventory_root / relative
        candidate, candidate_path = _read_local_file(local_candidate_path, _MAX_SCRIPT_BYTES, inventory_root)
        try:
            candidate_path.relative_to(inventory_root)
        except ValueError as error:
            raise ValueError("candidate outside inventory directory") from error
        if candidate_path == inventory_path:
            raise ValueError("manifest cannot be a script candidate")
        report = compare_scripts(reference, candidate)
        comparisons.append(
            {
                "script_index": index,
                "candidate_sha256": report["candidate_sha256"],
                "exact_match": report["exact_match"],
                "changed_line_count": report["changed_line_count"],
                "scheduler_binding_count": binding_counts[script["id"]],
                "risk_flags": report["risk_flags"],
            }
        )
    return {
        "script_count": len(scripts),
        "scheduler_count": len(schedulers),
        "listed_bindings_resolved": True,
        "scripts": comparisons,
    }


def _run_inventory(manifest_arg: str) -> int:
    if not _is_local_path(manifest_arg):
        return _emit_error("inventory_unavailable")
    manifest_path = Path(manifest_arg)
    try:
        data, manifest_final_path = _read_local_file(manifest_path, _MAX_INVENTORY_BYTES)
    except (OSError, ValueError):
        return _emit_error("inventory_unavailable")

    try:
        reference, _ = _read_local_file(TEMPLATE_PATH, _MAX_SCRIPT_BYTES)
        _validate_text(reference)
    except (OSError, UnicodeError, ValueError):
        return _emit_error("reference_unavailable")

    try:
        report = compare_inventory(reference, data, manifest_final_path)
    except (OSError, UnicodeError, ValueError):
        return _emit_error("invalid_inventory")
    except Exception:
        return _emit_error("comparison_failed")

    print(json.dumps(report, sort_keys=True))
    exact = all(bool(item["exact_match"]) for item in report["scripts"])
    return 0 if exact else 1


def main(argv: Sequence[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) == 2 and arguments[0] == "--inventory":
        return _run_inventory(arguments[1])
    if len(arguments) != 1:
        return _emit_error("invalid_arguments")
    if not _is_local_path(arguments[0]):
        return _emit_error("candidate_unavailable")

    try:
        candidate_path = Path(arguments[0])
        candidate, _ = _read_local_file(candidate_path, _MAX_SCRIPT_BYTES)
        _validate_text(candidate)
    except (OSError, UnicodeError, ValueError):
        return _emit_error("candidate_unavailable")

    try:
        reference, _ = _read_local_file(TEMPLATE_PATH, _MAX_SCRIPT_BYTES)
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
