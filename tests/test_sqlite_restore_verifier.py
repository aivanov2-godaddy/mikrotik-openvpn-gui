from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from scripts.sqlite_restore_verifier import verify_sqlite_restore
from store import MetadataStore


class SqliteRestoreVerifierTests(unittest.TestCase):
    def test_rehearses_application_backup_without_changing_or_disclosing_source(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = MetadataStore(str(root / "live.sqlite3"))
            connection = sqlite3.connect(store.path)
            connection.execute(
                "INSERT INTO user_metadata(vpn_user, email, created_at, updated_at) "
                "VALUES (?, ?, ?, ?)",
                ("private-user", "private-marker@example.invalid", 1, 1),
            )
            connection.commit()
            connection.close()

            backup = root / "private-backup.sqlite3"
            store.backup_database(str(backup))
            original_bytes = hashlib.sha256(backup.read_bytes()).hexdigest()
            original_modified_ns = backup.stat().st_mtime_ns

            result = verify_sqlite_restore(backup)

            self.assertEqual(result, {
                "verified": True,
                "source_opened_read_only": True,
                "restored_integrity": True,
                "required_schema_present": True,
                "restored_data_counts_match": True,
                "temporary_copy_removed": True,
                "failure_code": None,
            })
            self.assertEqual(hashlib.sha256(backup.read_bytes()).hexdigest(), original_bytes)
            self.assertEqual(backup.stat().st_mtime_ns, original_modified_ns)
            serialized = json.dumps(result)
            self.assertNotIn(str(backup), serialized)
            self.assertNotIn("private-user", serialized)
            self.assertNotIn("private-marker@example.invalid", serialized)

    def test_missing_and_corrupt_backups_fail_closed_without_echoing_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing-private-backup.sqlite3"
            corrupt = Path(directory) / "corrupt-private-backup.sqlite3"
            corrupt.write_bytes(b"not a sqlite database")

            missing_result = verify_sqlite_restore(missing)
            corrupt_result = verify_sqlite_restore(corrupt)

            self.assertFalse(missing_result["verified"])
            self.assertEqual(missing_result["failure_code"], "backup_missing")
            self.assertFalse(corrupt_result["verified"])
            self.assertEqual(corrupt_result["failure_code"], "invalid_sqlite")
            self.assertNotIn(str(missing), json.dumps(missing_result))
            self.assertNotIn(str(corrupt), json.dumps(corrupt_result))

    def test_non_application_database_fails_without_being_called_a_restore(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "empty.sqlite3"
            connection = sqlite3.connect(database)
            connection.execute("CREATE TABLE unrelated (id INTEGER PRIMARY KEY)")
            connection.commit()
            connection.close()

            result = verify_sqlite_restore(database)

        self.assertFalse(result["verified"])
        self.assertEqual(result["failure_code"], "required_schema_missing")
        self.assertFalse(result["required_schema_present"])
        self.assertTrue(result["temporary_copy_removed"])

    def test_symlink_backup_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.sqlite3"
            source.write_bytes(b"unused")
            link = root / "backup-link.sqlite3"
            try:
                link.symlink_to(source)
            except OSError:
                self.skipTest("symlink creation is unavailable on this host")

            result = verify_sqlite_restore(link)

        self.assertFalse(result["verified"])
        self.assertEqual(result["failure_code"], "backup_symlink")

    def test_backup_size_limit_is_enforced_before_opening_database(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            backup = Path(directory) / "backup.sqlite3"
            backup.write_bytes(b"too large")

            with patch("scripts.sqlite_restore_verifier.MAX_BACKUP_BYTES", 1):
                result = verify_sqlite_restore(backup)

        self.assertFalse(result["verified"])
        self.assertFalse(result["source_opened_read_only"])
        self.assertEqual(result["failure_code"], "backup_too_large")

    def test_temporary_permission_failure_fails_closed_before_copying_data(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = MetadataStore(str(root / "live.sqlite3"))
            backup = root / "backup.sqlite3"
            store.backup_database(str(backup))

            with patch("scripts.sqlite_restore_verifier._secure_temporary_path", return_value=False):
                result = verify_sqlite_restore(backup)

        self.assertFalse(result["verified"])
        self.assertEqual(result["failure_code"], "temporary_directory_permissions_failed")
        self.assertTrue(result["temporary_copy_removed"])

    def test_temporary_database_file_permission_failure_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = MetadataStore(str(root / "live.sqlite3"))
            backup = root / "backup.sqlite3"
            store.backup_database(str(backup))

            with patch(
                "scripts.sqlite_restore_verifier._secure_temporary_path",
                side_effect=[True, False],
            ):
                result = verify_sqlite_restore(backup)

        self.assertFalse(result["verified"])
        self.assertEqual(result["failure_code"], "temporary_copy_permissions_failed")
        self.assertTrue(result["temporary_copy_removed"])

    def test_restore_timeout_is_reported_without_disclosing_source(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = MetadataStore(str(root / "live.sqlite3"))
            backup = root / "backup.sqlite3"
            store.backup_database(str(backup))

            with patch("scripts.sqlite_restore_verifier.MAX_RESTORE_SECONDS", 0):
                result = verify_sqlite_restore(backup)

        self.assertFalse(result["verified"])
        self.assertEqual(result["failure_code"], "restore_timeout")
        self.assertNotIn(str(backup), json.dumps(result))

    def test_deadline_interrupts_integrity_phase(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = MetadataStore(str(root / "live.sqlite3"))
            backup = root / "backup.sqlite3"
            store.backup_database(str(backup))
            now = [0.0]
            integrity_started: list[bool] = []
            sqlite_connect = sqlite3.connect

            class DeadlineConnection(sqlite3.Connection):
                def execute(self, sql: str, *args: object, **kwargs: object) -> sqlite3.Cursor:
                    if sql == "PRAGMA integrity_check":
                        integrity_started.append(True)
                        now[0] = 31.0
                    return super().execute(sql, *args, **kwargs)

            def connect(*args: object, **kwargs: object) -> sqlite3.Connection:
                kwargs["factory"] = DeadlineConnection
                return sqlite_connect(*args, **kwargs)

            with patch("scripts.sqlite_restore_verifier.sqlite3.connect", side_effect=connect):
                result = verify_sqlite_restore(backup, monotonic=lambda: now[0])

        self.assertEqual(integrity_started, [True])
        self.assertFalse(result["verified"])
        self.assertEqual(result["failure_code"], "restore_timeout")

    def test_restored_row_count_mismatch_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = MetadataStore(str(root / "live.sqlite3"))
            backup = root / "backup.sqlite3"
            store.backup_database(str(backup))
            with patch(
                "scripts.sqlite_restore_verifier._row_counts",
                side_effect=[(1, 2, 3), (1, 2, 4)],
            ):
                result = verify_sqlite_restore(backup)

        self.assertFalse(result["verified"])
        self.assertFalse(result["restored_data_counts_match"])
        self.assertEqual(result["failure_code"], "restored_data_mismatch")


if __name__ == "__main__":
    unittest.main()
