"""Create a consistent, atomic backup of the dashboard SQLite database."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from store import MetadataStore


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", required=True, help="live dashboard SQLite path")
    parser.add_argument("--destination", required=True, help="atomic backup destination path")
    arguments = parser.parse_args()
    store = MetadataStore(arguments.database)
    result = store.backup_database(arguments.destination)
    print(
        f"SQLite backup created path={result['path']} bytes={result['bytes']} "
        f"created_at={result['created_at']}"
    )


if __name__ == "__main__":
    main()
