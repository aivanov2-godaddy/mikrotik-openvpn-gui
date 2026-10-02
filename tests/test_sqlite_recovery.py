from __future__ import annotations

import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from store import MetadataStore


class SQLiteRecoveryTests(unittest.TestCase):
    def test_write_lock_contention_times_out_and_store_recovers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "dashboard.sqlite"
            store = MetadataStore(str(database))
            store.audit(actor="test", action="before.lock", target="local", status="success")
            lock_holder = sqlite3.connect(database, timeout=1, isolation_level=None)
            try:
                lock_holder.execute("BEGIN IMMEDIATE")
                started = time.monotonic()
                with self.assertRaisesRegex(sqlite3.OperationalError, "locked"):
                    store.audit(
                        actor="test",
                        action="contended.write",
                        target="local",
                        status="success",
                    )
                elapsed = time.monotonic() - started
                self.assertGreaterEqual(elapsed, 4.5)
                self.assertLess(elapsed, 8)
            finally:
                lock_holder.rollback()
                lock_holder.close()

            store.verify_readiness()
            store.audit(actor="test", action="after.lock", target="local", status="success")
            actions = {item["action"] for item in store.recent_audit(10)}
            self.assertIn("before.lock", actions)
            self.assertIn("after.lock", actions)
            self.assertNotIn("contended.write", actions)

    def test_passive_checkpoint_respects_reader_and_completes_after_reader_closes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "dashboard.sqlite"
            store = MetadataStore(str(database))
            reader = sqlite3.connect(database, isolation_level=None)
            try:
                reader.execute("BEGIN")
                reader.execute("SELECT COUNT(*) FROM audit").fetchone()
                for index in range(20):
                    store.audit(
                        actor="checkpoint-test",
                        action="checkpoint.write",
                        target=f"row-{index}",
                        status="success",
                        details={"index": index},
                    )

                while_reader_open = store.checkpoint_wal("PASSIVE")
                self.assertEqual(while_reader_open["mode"], "PASSIVE")
                self.assertGreaterEqual(while_reader_open["log_frames"], 0)
                self.assertGreaterEqual(while_reader_open["checkpointed_frames"], 0)
                self.assertLessEqual(
                    while_reader_open["checkpointed_frames"], while_reader_open["log_frames"]
                )
            finally:
                reader.rollback()
                reader.close()

            after_reader_close = store.checkpoint_wal("PASSIVE")
            self.assertEqual(after_reader_close["mode"], "PASSIVE")
            self.assertEqual(after_reader_close["busy"], 0)
            self.assertEqual(
                after_reader_close["checkpointed_frames"], after_reader_close["log_frames"]
            )
            store.verify_readiness()

    def test_backup_rejects_live_database_and_wal_sidecars(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "dashboard.sqlite"
            store = MetadataStore(str(database))
            store.audit(actor="test", action="preserve.me", target="local", status="success")

            for destination in (database, Path(f"{database}-wal"), Path(f"{database}-shm")):
                with self.subTest(destination=destination.name):
                    original = destination.read_bytes() if destination.exists() else None
                    with self.assertRaisesRegex(ValueError, "live database or its sidecars"):
                        store.backup_database(str(destination))
                    if original is not None:
                        self.assertEqual(destination.read_bytes(), original)

            store.verify_readiness()
            self.assertEqual(store.recent_audit(1)[0]["action"], "preserve.me")

    def test_failed_atomic_replace_preserves_previous_backup_and_cleans_temp(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            store = MetadataStore(str(root / "dashboard.sqlite"))
            destination = root / "backups" / "dashboard.sqlite"
            destination.parent.mkdir()
            previous_backup = b"previous verified backup"
            destination.write_bytes(previous_backup)

            with mock.patch("store.os.replace", side_effect=OSError("injected replace failure")):
                with self.assertRaisesRegex(OSError, "injected replace failure"):
                    store.backup_database(str(destination))

            self.assertEqual(destination.read_bytes(), previous_backup)
            self.assertEqual(list(destination.parent.glob(f".{destination.name}.*.tmp")), [])
            store.verify_readiness()

    def test_backup_storage_failure_preserves_previous_backup_and_cleans_temp(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = root / "dashboard.sqlite"
            store = MetadataStore(str(database))
            store.audit(actor="test", action="backup.before.failure", target="local", status="success")
            destination = root / "backups" / "dashboard.sqlite"
            destination.parent.mkdir()
            previous_backup = b"previous verified backup"
            destination.write_bytes(previous_backup)

            sqlite_connect = sqlite3.connect

            def fail_backup_target(path: str | Path, *args: object, **kwargs: object) -> sqlite3.Connection:
                if Path(path).parent == destination.parent:
                    raise sqlite3.OperationalError("database or disk is full")
                return sqlite_connect(path, *args, **kwargs)

            with mock.patch("store.sqlite3.connect", side_effect=fail_backup_target):
                with self.assertRaisesRegex(sqlite3.OperationalError, "disk is full"):
                    store.backup_database(str(destination))

            self.assertEqual(destination.read_bytes(), previous_backup)
            self.assertEqual(list(destination.parent.glob(f".{destination.name}.*.tmp")), [])
            store.verify_readiness()
            self.assertEqual(store.recent_audit(1)[0]["action"], "backup.before.failure")

    def test_backup_is_consistent_while_an_independent_writer_is_active(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "dashboard.sqlite"
            backup = Path(temporary) / "backup" / "dashboard.sqlite"
            store = MetadataStore(str(database))
            writer = MetadataStore(str(database))
            started = threading.Event()
            errors: list[BaseException] = []

            def write_rows() -> None:
                try:
                    for index in range(400):
                        writer.audit(
                            actor="backup-test",
                            action="backup.concurrent",
                            target=f"row-{index}",
                            status="success",
                            details={"index": index},
                        )
                        if index == 0:
                            started.set()
                        if index % 5 == 0:
                            time.sleep(0.002)
                except BaseException as error:
                    errors.append(error)

            thread = threading.Thread(target=write_rows)
            thread.start()
            self.assertTrue(started.wait(5))
            result = store.backup_database(str(backup))
            thread.join(10)
            self.assertFalse(thread.is_alive(), "writer thread did not finish")
            self.assertFalse(errors, str(errors))
            self.assertGreater(result["bytes"], 0)

            connection = sqlite3.connect(backup)
            try:
                self.assertEqual(connection.execute("PRAGMA integrity_check").fetchone()[0], "ok")
                count = connection.execute(
                    "SELECT COUNT(*) FROM audit WHERE action='backup.concurrent'"
                ).fetchone()[0]
                self.assertGreater(count, 0)
                self.assertLessEqual(count, 400)
            finally:
                connection.close()

    def test_backup_restore_rehearsal_recovers_a_consistent_point_in_time_copy(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_path = root / "dashboard.sqlite"
            backup_path = root / "backup" / "dashboard.sqlite"
            source = MetadataStore(str(source_path))
            source.audit(actor="restore-test", action="before.backup", target="local", status="success")

            result = source.backup_database(str(backup_path))
            self.assertGreater(result["bytes"], 0)

            # Continue writing after the snapshot, then open the backup as a
            # separate database to rehearse restore without replacing the live
            # source or copying WAL/SHM sidecars by hand.
            source.audit(actor="restore-test", action="after.backup", target="local", status="success")
            restored = MetadataStore(str(backup_path))
            restored.verify_readiness()
            actions = {item["action"] for item in restored.recent_audit(10)}
            self.assertIn("before.backup", actions)
            self.assertNotIn("after.backup", actions)

            connection = sqlite3.connect(backup_path)
            try:
                self.assertEqual(connection.execute("PRAGMA integrity_check").fetchone()[0], "ok")
            finally:
                connection.close()
            source.verify_readiness()

    def test_process_death_during_transaction_rolls_back_and_store_recovers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "dashboard.sqlite"
            store = MetadataStore(str(database))
            store.audit(actor="test", action="before.crash", target="local", status="success")
            crashing_writer = (
                "import os, sqlite3, sys; "
                "db=sqlite3.connect(sys.argv[1]); "
                "db.execute('PRAGMA journal_mode=WAL'); "
                "db.execute('BEGIN IMMEDIATE'); "
                "db.execute(\"INSERT INTO audit(actor,action,target,status,details,created_at) "
                "VALUES ('test','interrupted.write','local','success','{}',1)\"); "
                "os._exit(73)"
            )
            result = subprocess.run(
                [sys.executable, "-c", crashing_writer, str(database)],
                check=False,
                capture_output=True,
                timeout=10,
            )
            self.assertEqual(result.returncode, 73)

            recovered = MetadataStore(str(database))
            recovered.verify_readiness()
            actions = [item["action"] for item in recovered.recent_audit(20)]
            self.assertIn("before.crash", actions)
            self.assertNotIn("interrupted.write", actions)
            recovered.audit(actor="test", action="after.recovery", target="local", status="success")
            self.assertEqual(recovered.recent_audit(1)[0]["action"], "after.recovery")

    def test_page_limit_disk_full_error_leaves_database_recoverable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "dashboard.sqlite"
            store = MetadataStore(str(database))
            store.audit(actor="test", action="before.full", target="local", status="success")
            connection = sqlite3.connect(database)
            try:
                page_count = int(connection.execute("PRAGMA page_count").fetchone()[0])
                connection.execute(f"PRAGMA max_page_count={page_count}")
                with self.assertRaisesRegex(sqlite3.OperationalError, "full"):
                    connection.execute(
                        "INSERT INTO audit(actor,action,target,status,details,created_at) VALUES (?,?,?,?,?,?)",
                        ("test", "disk.full", "local", "success", "x" * 500_000, 1),
                    )
            finally:
                connection.close()

            recovered = MetadataStore(str(database))
            recovered.verify_readiness()
            self.assertEqual(recovered.recent_audit(1)[0]["action"], "before.full")

    def test_database_metrics_report_sizes_without_paths_or_contents(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = MetadataStore(str(Path(temporary) / "dashboard.sqlite"))
            metrics = store.database_metrics()

            self.assertGreater(metrics["database_bytes"], 0)
            self.assertGreaterEqual(metrics["wal_bytes"], 0)
            self.assertGreaterEqual(metrics["shm_bytes"], 0)
            self.assertGreater(metrics["volume_free_bytes"], 0)
            self.assertNotIn("path", metrics)
            self.assertNotIn("payload", metrics)


if __name__ == "__main__":
    unittest.main()
