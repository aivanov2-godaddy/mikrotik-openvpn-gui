from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scripts.prune_runtime_build_tools import prune_build_tools


class RuntimePythonToolPruningTests(unittest.TestCase):
    def test_removes_base_packaging_tools_but_preserves_app_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            site_packages = root / "python" / "site-packages"
            scripts = root / "python" / "bin"
            standard_library = root / "python" / "stdlib"
            app_runtime = root / "app" / "runtime"
            for path in (
                site_packages / "pip" / "_vendor" / "urllib3",
                site_packages / "pip-25.0.dist-info",
                site_packages / "setuptools" / "_vendor",
                site_packages / "setuptools-70.3.0.dist-info",
                site_packages / "pkg_resources",
                site_packages / "_distutils_hack",
                site_packages / "msgpack",
                site_packages / "msgpack-1.1.2.dist-info",
                site_packages / "urllib3" / "connection.py",
                site_packages / "urllib3-2.7.0.dist-info",
                site_packages / "uvicorn" / "__init__.py",
                scripts / "pip3.15",
                scripts / "easy_install-3.15",
                standard_library / "ensurepip" / "__init__.py",
                app_runtime / "msgpack" / "__init__.py",
                app_runtime / "urllib3" / "__init__.py",
            ):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("fixture", encoding="utf-8")

            removed = prune_build_tools(
                package_directories=(site_packages,),
                script_directories=(scripts,),
                standard_library_directories=(standard_library,),
            )

            self.assertGreaterEqual(len(removed), 10)
            for removed_path in (
                site_packages / "pip",
                site_packages / "pip-25.0.dist-info",
                site_packages / "setuptools",
                site_packages / "setuptools-70.3.0.dist-info",
                site_packages / "pkg_resources",
                site_packages / "_distutils_hack",
                site_packages / "msgpack",
                site_packages / "msgpack-1.1.2.dist-info",
                site_packages / "urllib3",
                site_packages / "urllib3-2.7.0.dist-info",
                scripts / "pip3.15",
                scripts / "easy_install-3.15",
                standard_library / "ensurepip",
            ):
                with self.subTest(path=removed_path):
                    self.assertFalse(removed_path.exists())
            self.assertTrue((site_packages / "uvicorn" / "__init__.py").is_file())
            self.assertTrue((app_runtime / "msgpack" / "__init__.py").is_file())
            self.assertTrue((app_runtime / "urllib3" / "__init__.py").is_file())

    def test_build_only_metadata_match_is_package_scoped(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            site_packages = Path(temporary_directory)
            for name in ("pip-25.0.dist-info", "my-pip-helper-1.0.dist-info", "redis-8.1.0.dist-info"):
                path = site_packages / name
                path.mkdir()
                (path / "METADATA").write_text("fixture", encoding="utf-8")

            prune_build_tools(
                package_directories=(site_packages,),
                script_directories=(),
                standard_library_directories=(),
            )

            self.assertFalse((site_packages / "pip-25.0.dist-info").exists())
            self.assertTrue((site_packages / "my-pip-helper-1.0.dist-info").exists())
            self.assertTrue((site_packages / "redis-8.1.0.dist-info").exists())


if __name__ == "__main__":
    unittest.main()
