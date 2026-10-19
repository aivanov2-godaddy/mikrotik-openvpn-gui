from __future__ import annotations

import os
import sys
import unittest
from types import ModuleType, SimpleNamespace
from unittest.mock import Mock, patch

import app
import asgi
import entrypoint
import security


class ProcessCoreDumpTests(unittest.TestCase):
    def test_non_posix_runtime_does_not_import_resource(self) -> None:
        with patch.object(security.os, "name", "nt"), patch.dict(sys.modules, {"resource": None}):
            security.disable_process_core_dumps()

    def test_posix_runtime_sets_soft_and_hard_core_limits_to_zero(self) -> None:
        resource = SimpleNamespace(RLIMIT_CORE=7, setrlimit=Mock())
        with (
            patch.object(security.os, "name", "posix"),
            patch.dict(sys.modules, {"resource": resource}),
        ):
            security.disable_process_core_dumps()

        resource.setrlimit.assert_called_once_with(7, (0, 0))

    def test_posix_runtime_fails_closed_when_limit_cannot_be_set(self) -> None:
        resource = SimpleNamespace(RLIMIT_CORE=7, setrlimit=Mock(side_effect=OSError("private detail")))
        with (
            patch.object(security.os, "name", "posix"),
            patch.dict(sys.modules, {"resource": resource}),
        ):
            with self.assertRaisesRegex(SystemExit, "Unable to disable process core dumps") as raised:
                security.disable_process_core_dumps()

        self.assertNotIn("private detail", str(raised.exception))
        resource.setrlimit.assert_called_once_with(7, (0, 0))

    def test_core_dump_guard_runs_before_runtime_imported_main(self) -> None:
        events: list[str] = []
        runtime = ModuleType("asgi")

        def run_runtime() -> None:
            events.append("runtime")

        runtime.main = run_runtime

        with (
            patch.object(entrypoint, "disable_process_core_dumps", side_effect=lambda: events.append("guard")),
            patch.dict(os.environ, {"SOCKETIO_ENGINE": "asgi"}),
            patch.dict(sys.modules, {"asgi": runtime}),
        ):
            self.assertEqual(entrypoint.main(), 0)

        self.assertEqual(events, ["guard", "runtime"])

    def test_http_runtime_guards_before_building_application(self) -> None:
        events: list[str] = []

        def build_context() -> None:
            events.append("build")
            raise RuntimeError("stop before server startup")

        with (
            patch.object(app, "disable_process_core_dumps", side_effect=lambda: events.append("guard")),
            patch.object(app, "build_context", side_effect=build_context),
        ):
            with self.assertRaisesRegex(RuntimeError, "stop before server startup"):
                app.main()

        self.assertEqual(events, ["guard", "build"])

    def test_asgi_runtime_guards_before_creating_application(self) -> None:
        events: list[str] = []
        fake_uvicorn = ModuleType("uvicorn")

        def create_application() -> None:
            events.append("create")
            raise RuntimeError("stop before server startup")

        with (
            patch.object(asgi, "disable_process_core_dumps", side_effect=lambda: events.append("guard")),
            patch.object(asgi, "create_application", side_effect=create_application),
            patch.dict(sys.modules, {"uvicorn": fake_uvicorn}),
        ):
            with self.assertRaisesRegex(RuntimeError, "stop before server startup"):
                asgi.main()

        self.assertEqual(events, ["guard", "create"])


if __name__ == "__main__":
    unittest.main()
