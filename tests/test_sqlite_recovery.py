from __future__ import annotations

import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

from store import MetadataStore


class SQLiteRecoveryTests(unittest.TestCase):
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
