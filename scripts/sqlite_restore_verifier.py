"""Safely rehearse restoring a private SQLite backup into a temporary copy."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import sqlite3
import stat
import subprocess
import tempfile
import time
from datetime import datetime
from typing import Any, Callable


MAX_BACKUP_BYTES = 512 * 1024 * 1024
MAX_RESTORE_SECONDS = 30.0
REQUIRED_TABLES = frozenset({"devices", "audit", "user_metadata"})
FAILURE_CODES = frozenset({
    "backup_missing",
    "backup_symlink",
    "backup_not_file",
    "backup_empty",
    "backup_too_large",
    "backup_unreadable",
    "temporary_space_unavailable",
    "insufficient_temporary_space",
    "temporary_directory_permissions_failed",
    "temporary_copy_permissions_failed",
    "invalid_sqlite",
    "required_schema_missing",
    "restore_timeout",
    "restore_failed",
    "restored_schema_mismatch",
    "restored_data_mismatch",
    "integrity_check_failed",
    "temporary_copy_cleanup_failed",
    "invalid_backup_path",
})
RESTORE_REPORT_FORMAT = "vpn-dashboard-sqlite-restore-verification-v2"
RESTORE_CHECK_FIELDS = frozenset({
    "environment",
    "checked_at",
    "verified",
    "source_opened_read_only",
    "restored_integrity",
    "required_schema_present",
    "restored_data_counts_match",
    "temporary_copy_removed",
    "failure_code",
})


def _schema(connection: sqlite3.Connection) -> tuple[tuple[str, str, str, str], ...]:
    rows = connection.execute(
        "SELECT type, name, tbl_name, sql FROM sqlite_master "
        "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"
    ).fetchall()
    return tuple(tuple("" if value is None else str(value) for value in row) for row in rows)


def _tables(schema: tuple[tuple[str, str, str, str], ...]) -> set[str]:
    return {name for kind, name, _, _ in schema if kind == "table"}


class _RestoreDeadline:
    def __init__(self, seconds: float, clock: Callable[[], float]) -> None:
        self._clock = clock
        self._expires_at = clock() + seconds

    def expired(self) -> bool:
        return self._clock() >= self._expires_at

    def remaining(self) -> float:
        return max(0.0, self._expires_at - self._clock())

    def check(self) -> None:
        if self.expired():
            raise TimeoutError("restore deadline exceeded")

    def sqlite_progress(self) -> int:
        return int(self.expired())


class _BackupTooLarge(Exception):
    """Raised when SQLite's logical backup exceeds the configured size cap."""


def _row_counts(
    connection: sqlite3.Connection,
    schema: tuple[tuple[str, str, str, str], ...],
    deadline: _RestoreDeadline,
) -> tuple[int, ...]:
    counts: list[int] = []
    for table in sorted(_tables(schema)):
        deadline.check()
        quoted_table = '"' + table.replace('"', '""') + '"'
        row = connection.execute(f"SELECT COUNT(*) FROM {quoted_table}").fetchone()
        deadline.check()
        if not row or not isinstance(row[0], int):
            raise sqlite3.DatabaseError("invalid table row count")
        counts.append(row[0])
    return tuple(counts)


def _secure_temporary_path(path: Path) -> bool:
    """Set and verify a private ACL before writing or copying database data."""

    if path.is_symlink() or not (path.is_dir() or path.is_file()):
        return False
    if os.name == "nt":
        script = Path(__file__).with_name("secure_sqlite_temp_directory.ps1")
        powershell = shutil.which("powershell.exe") or shutil.which("powershell")
        if not powershell:
            system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
            fallback = system_root / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
            powershell = str(fallback) if fallback.is_file() else None
        if not powershell or not script.is_file():
            return False
        try:
            completed = subprocess.run(
                [
                    powershell,
                    "-NoProfile",
                    "-NonInteractive",
                    "-File",
                    str(script),
                    "-Path",
                    str(path),
                ],
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=10,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return False
        return completed.returncode == 0 and completed.stdout.strip() == "PRIVATE"
    if os.name == "posix":
        try:
            expected_mode = 0o700 if path.is_dir() else 0o600
            os.chmod(path, expected_mode)
            return stat.S_IMODE(path.stat().st_mode) == expected_mode
        except OSError:
            return False
    return False


def verify_sqlite_restore(
    path: str | os.PathLike[str] | None,
    *,
    monotonic: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    """Restore a backup without writing to its source and return only safe facts.

    The database can contain user metadata. Neither paths, schema text, values,
    nor exception messages are returned. A passing result means the source was
    opened in SQLite read-only mode, copied with SQLite's Backup API, the copy
    passed a full integrity check, the required application schema and per-table
    row counts survived, and the secured temporary copy was removed.
    """

    result: dict[str, Any] = {
        "verified": False,
        "source_opened_read_only": False,
        "restored_integrity": False,
        "required_schema_present": False,
        "restored_data_counts_match": False,
        "temporary_copy_removed": True,
        "failure_code": None,
    }

    if path is None or (isinstance(path, str) and not path.strip()):
        result["failure_code"] = "backup_missing"
        return result

    deadline = _RestoreDeadline(MAX_RESTORE_SECONDS, monotonic)

    try:
        source_path = Path(path)
    except (TypeError, ValueError, OSError):
        result["failure_code"] = "invalid_backup_path"
        return result

    if source_path.is_symlink():
        result["failure_code"] = "backup_symlink"
        return result
    try:
        source_stat = source_path.stat()
    except FileNotFoundError:
        result["failure_code"] = "backup_missing"
        return result
    except OSError:
        result["failure_code"] = "backup_unreadable"
        return result
    if not source_path.is_file():
        result["failure_code"] = "backup_not_file"
        return result
    if source_stat.st_size <= 0:
        result["failure_code"] = "backup_empty"
        return result
    if source_stat.st_size > MAX_BACKUP_BYTES:
        result["failure_code"] = "backup_too_large"
        return result

    try:
        free_bytes = shutil.disk_usage(tempfile.gettempdir()).free
    except OSError:
        result["failure_code"] = "temporary_space_unavailable"
        return result
    if free_bytes < source_stat.st_size + 1024 * 1024:
        result["failure_code"] = "insufficient_temporary_space"
        return result

    source: sqlite3.Connection | None = None
    restored: sqlite3.Connection | None = None
    temporary: tempfile.TemporaryDirectory[str] | None = None
    temporary_root: Path | None = None
    restored_path: Path | None = None
    failure_code: str | None = None
    try:
        deadline.check()
        resolved_source = source_path.resolve(strict=True)
        source = sqlite3.connect(
            f"{resolved_source.as_uri()}?mode=ro",
            uri=True,
            timeout=min(2, deadline.remaining()),
        )
        source.execute("PRAGMA query_only=ON")
        result["source_opened_read_only"] = True
        deadline.check()
        source.set_progress_handler(deadline.sqlite_progress, 1000)
        busy_timeout_ms = max(1, min(2000, int(deadline.remaining() * 1000)))
        source.execute(f"PRAGMA busy_timeout={busy_timeout_ms}")
        source.execute("BEGIN")
        deadline.check()
        source_schema = _schema(source)
        deadline.check()
        if not REQUIRED_TABLES.issubset(_tables(source_schema)):
            failure_code = "required_schema_missing"
        else:
            source_row_counts = _row_counts(source, source_schema, deadline)
            temporary = tempfile.TemporaryDirectory(prefix="vpn-dashboard-sqlite-restore-")
            temporary_root = Path(temporary.name)
            if not _secure_temporary_path(temporary_root):
                failure_code = "temporary_directory_permissions_failed"
            else:
                deadline.check()
                descriptor, restored_name = tempfile.mkstemp(
                    prefix="restored-", suffix=".sqlite3", dir=temporary.name
                )
                os.close(descriptor)
                restored_path = Path(restored_name)
                if not _secure_temporary_path(restored_path):
                    failure_code = "temporary_copy_permissions_failed"
                else:
                    deadline.check()
                    restored = sqlite3.connect(
                        restored_path,
                        timeout=min(2, deadline.remaining()),
                    )
                    restored.set_progress_handler(deadline.sqlite_progress, 1000)
                    page_size_row = source.execute("PRAGMA page_size").fetchone()
                    if not page_size_row or not isinstance(page_size_row[0], int):
                        raise sqlite3.DatabaseError("invalid SQLite page size")
                    page_size = page_size_row[0]

                    def check_backup_progress(_status: int, _remaining: int, total: int) -> None:
                        deadline.check()
                        if total * page_size > MAX_BACKUP_BYTES:
                            raise _BackupTooLarge

                    source.backup(restored, pages=128, progress=check_backup_progress, sleep=0.05)
                    deadline.check()
                    restored.commit()
                    deadline.check()
                    integrity_rows = restored.execute("PRAGMA integrity_check").fetchall()
                    deadline.check()
                    result["restored_integrity"] = integrity_rows == [("ok",)]
                    restored_schema = _schema(restored)
                    deadline.check()
                    result["required_schema_present"] = (
                        REQUIRED_TABLES.issubset(_tables(restored_schema))
                        and restored_schema == source_schema
                    )
                    restored_row_counts = _row_counts(restored, restored_schema, deadline)
                    result["restored_data_counts_match"] = (
                        result["required_schema_present"]
                        and restored_row_counts == source_row_counts
                    )
                    if not result["restored_integrity"]:
                        failure_code = "integrity_check_failed"
                    elif not result["required_schema_present"]:
                        failure_code = "restored_schema_mismatch"
                    elif not result["restored_data_counts_match"]:
                        failure_code = "restored_data_mismatch"
    except _BackupTooLarge:
        failure_code = "backup_too_large"
    except TimeoutError:
        failure_code = "restore_timeout"
    except sqlite3.Error as error:
        if deadline.expired():
            failure_code = "restore_timeout"
        elif isinstance(error, sqlite3.DatabaseError):
            failure_code = "invalid_sqlite"
        else:
            failure_code = "restore_failed"
    except FileNotFoundError:
        failure_code = "backup_missing"
    except OSError:
        failure_code = "backup_unreadable"
    except Exception:
        failure_code = "restore_failed"
    finally:
        for connection in (restored, source):
            if connection is not None:
                try:
                    connection.close()
                except sqlite3.Error:
                    failure_code = failure_code or "restore_failed"
        if temporary is not None:
            try:
                temporary.cleanup()
            except OSError:
                failure_code = "temporary_copy_cleanup_failed"
            result["temporary_copy_removed"] = temporary_root is None or not temporary_root.exists()
            if not result["temporary_copy_removed"]:
                failure_code = "temporary_copy_cleanup_failed"

    result["failure_code"] = failure_code
    result["verified"] = (
        failure_code is None
        and result["source_opened_read_only"] is True
        and result["restored_integrity"] is True
        and result["required_schema_present"] is True
        and result["restored_data_counts_match"] is True
        and result["temporary_copy_removed"] is True
    )
    return result


def validate_restore_verification(
    report: Any,
    *,
    phase: str,
    deployments: list[dict[str, Any]],
    now: datetime,
) -> tuple[dict[str, Any], list[str]]:
    """Validate and project the collector's safe restore-verification report."""

    environments = ("canary",) if phase == "canary-prepromotion" else ("canary", "production")
    if phase not in {"canary-prepromotion", "postpromotion"}:
        raise ValueError("invalid collection phase")
    if not isinstance(report, dict) or set(report) != {"format", "checks"}:
        raise ValueError("invalid restore verification")
    checks = report.get("checks")
    if report.get("format") != RESTORE_REPORT_FORMAT or not isinstance(checks, list):
        raise ValueError("invalid restore verification")
    if len(checks) != len(environments) or len(deployments) != 2:
        raise ValueError("invalid restore verification count")
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("verification clock must include a timezone")

    safe_checks: list[dict[str, Any]] = []
    stale_environments: list[str] = []
    for check, environment in zip(checks, environments):
        if not isinstance(check, dict) or set(check) != RESTORE_CHECK_FIELDS:
            raise ValueError("invalid restore verification check")
        if check.get("environment") != environment:
            raise ValueError("restore verification environment mismatch")
        checked_at_value = check.get("checked_at")
        if not isinstance(checked_at_value, str):
            raise ValueError("restore verification timestamp is missing")
        try:
            checked_at = datetime.fromisoformat(checked_at_value.replace("Z", "+00:00"))
        except ValueError as error:
            raise ValueError("invalid restore verification timestamp") from error
        if checked_at.tzinfo is None or checked_at.utcoffset() is None:
            raise ValueError("restore verification timestamp needs a timezone")

        boolean_fields = (
            "verified",
            "source_opened_read_only",
            "restored_integrity",
            "required_schema_present",
            "restored_data_counts_match",
            "temporary_copy_removed",
        )
        if any(not isinstance(check.get(field), bool) for field in boolean_fields):
            raise ValueError("invalid restore verification result")
        failure_code = check.get("failure_code")
        if failure_code is not None and (
            not isinstance(failure_code, str) or failure_code not in FAILURE_CODES
        ):
            raise ValueError("invalid restore verification failure code")
        verified_from_checks = (
            check["source_opened_read_only"]
            and check["restored_integrity"]
            and check["required_schema_present"]
            and check["restored_data_counts_match"]
            and check["temporary_copy_removed"]
            and failure_code is None
        )
        if check["verified"] is not verified_from_checks:
            raise ValueError("inconsistent restore verification result")

        deployment = deployments[0 if environment == "canary" else 1]
        if deployment.get("sqlite_restore_verified") is not check["verified"]:
            raise ValueError("restore verification does not match deployment evidence")
        deployment_timestamp = deployment.get("sqlite_restore_verified_at")
        if check["verified"]:
            if not isinstance(deployment_timestamp, str):
                raise ValueError("verified restore timestamp is missing")
            try:
                parsed_deployment_timestamp = datetime.fromisoformat(
                    deployment_timestamp.replace("Z", "+00:00")
                )
            except ValueError as error:
                raise ValueError("invalid deployment restore timestamp") from error
            if (
                parsed_deployment_timestamp.tzinfo is None
                or parsed_deployment_timestamp.utcoffset() is None
                or parsed_deployment_timestamp != checked_at
            ):
                raise ValueError("restore timestamps do not match")
        elif deployment_timestamp is not None:
            raise ValueError("unverified restore cannot carry a verified timestamp")

        age = (now - checked_at).total_seconds()
        if age > 86_400 or age < -300:
            stale_environments.append(environment)
        safe_checks.append({
            "environment": environment,
            "checked_at": checked_at.isoformat(),
            **{field: check[field] for field in boolean_fields},
            "failure_code": failure_code,
        })

    return {"format": RESTORE_REPORT_FORMAT, "checks": safe_checks}, stale_environments
