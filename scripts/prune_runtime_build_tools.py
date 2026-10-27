"""Remove package-management tooling from the final RouterOS runtime rootfs."""

from __future__ import annotations

import shutil
import sysconfig
from pathlib import Path


_BUILD_ONLY_PACKAGES = frozenset(
    {
        "_distutils_hack",
        "msgpack",
        "pip",
        "pkg_resources",
        "setuptools",
        "urllib3",
    }
)
_METADATA_SUFFIXES = (".dist-info", ".egg-info")
_SCRIPT_PREFIXES = ("easy_install", "pip")


def _is_build_only_artifact(name: str) -> bool:
    if name in _BUILD_ONLY_PACKAGES:
        return True
    return any(
        name.startswith(f"{package}-") and name.endswith(_METADATA_SUFFIXES)
        for package in _BUILD_ONLY_PACKAGES
    )


def _is_build_only_script(name: str) -> bool:
    return name in _SCRIPT_PREFIXES or name.startswith(("easy_install-3", "pip3"))


def prune_build_tools(
    *,
    package_directories: tuple[Path, ...],
    script_directories: tuple[Path, ...],
    standard_library_directories: tuple[Path, ...],
) -> list[str]:
    """Remove only known build tools from the base interpreter installation."""
    removed: list[str] = []
    for directory in package_directories:
        if not directory.is_dir():
            continue
        for artifact in directory.iterdir():
            if not _is_build_only_artifact(artifact.name):
                continue
            if artifact.is_dir() and not artifact.is_symlink():
                shutil.rmtree(artifact)
            else:
                artifact.unlink()
            removed.append(artifact.name)

    for directory in script_directories:
        if not directory.is_dir():
            continue
        for artifact in directory.iterdir():
            if not _is_build_only_script(artifact.name):
                continue
            if artifact.is_dir() and not artifact.is_symlink():
                shutil.rmtree(artifact)
            else:
                artifact.unlink()
            removed.append(artifact.name)

    for directory in standard_library_directories:
        ensurepip = directory / "ensurepip"
        if ensurepip.is_dir():
            shutil.rmtree(ensurepip)
            removed.append("ensurepip")
        elif ensurepip.exists():
            ensurepip.unlink()
            removed.append("ensurepip")
    return removed


def main() -> int:
    paths = sysconfig.get_paths()
    package_directories = tuple(
        Path(paths[key]) for key in ("purelib", "platlib") if paths.get(key)
    )
    removed = prune_build_tools(
        package_directories=package_directories,
        script_directories=(Path(paths["scripts"]),),
        standard_library_directories=(Path(paths["stdlib"]),),
    )
    print(f"Removed {len(removed)} build-only Python artifacts from the runtime rootfs.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
