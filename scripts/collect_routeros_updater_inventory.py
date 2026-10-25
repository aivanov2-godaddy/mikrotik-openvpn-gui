"""Collect a redacted, read-only RouterOS updater and scheduler inventory.

Only the reviewed updater source and scheduler binding fields are requested.
Raw source, event text, names, IDs, credentials, and router identity stay in
process memory and are never written to the report.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

if __package__ in {None, ""}:  # Support the documented `python scripts/...py` invocation.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.compare_routeros_updater import TEMPLATE_PATH, _is_local_filesystem, compare_scripts
from routeros_binary import RouterOSBinaryConnection, RouterOSBinaryError, RouterOSReply


FORMAT = "vpn-dashboard-routeros-updater-inventory-v1"
SCRIPT_PATH = "/system/script/print"
SCHEDULER_PATH = "/system/scheduler/print"
SCRIPT_PROPLIST = "name,source"
SCHEDULER_PROPLIST = "name,on-event,disabled"
MAX_SCRIPTS = 128
MAX_SCHEDULERS = 512
MAX_SOURCE_BYTES = 1_048_576
MAX_TOTAL_SOURCE_BYTES = 8_388_608
MAX_NAME_CHARS = 256
MAX_EVENT_CHARS = 4_096


def _rows(replies: Iterable[RouterOSReply], required: frozenset[str]) -> list[dict[str, str]]:
    """Validate a fully terminated print response and discard unrelated fields."""
    response = list(replies)
    if not response or response[-1].kind not in {"done", "empty"}:
        raise ValueError("incomplete RouterOS print response")
    if any(reply.kind not in {"re", "done", "empty"} for reply in response):
        raise ValueError("unexpected RouterOS print response")
    if any(reply.kind in {"done", "empty"} for reply in response[:-1]):
        raise ValueError("unexpected RouterOS response ordering")
    if response[-1].kind == "empty" and len(response) != 1:
        raise ValueError("unexpected RouterOS empty response")

    result: list[dict[str, str]] = []
    for reply in response[:-1] if response[-1].kind == "done" else ():
        if reply.dead or not required.issubset(reply.attributes):
            raise ValueError("incomplete RouterOS record")
        result.append({key: reply.attributes[key] for key in required})
    return result


def _text(value: object, *, limit: int, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or "\x00" in value or "\ufffd" in value:
        raise ValueError("invalid RouterOS text field")
    if (not value and not allow_empty) or len(value) > limit:
        raise ValueError("RouterOS text field outside limits")
    return value


def _enabled(value: str) -> bool:
    normalized = value.casefold()
    if normalized in {"false", "no"}:
        return True
    if normalized in {"true", "yes"}:
        return False
    raise ValueError("invalid RouterOS scheduler state")


def collect_inventory(
    connection: RouterOSBinaryConnection,
    reference: bytes,
    *,
    collected_at: str | None = None,
) -> dict[str, Any]:
    """Read all returned script/scheduler rows and compare source in memory."""
    script_rows = _rows(
        connection.execute(SCRIPT_PATH, query=(f".proplist={SCRIPT_PROPLIST}",)),
        frozenset({"name", "source"}),
    )
    scheduler_rows = _rows(
        connection.execute(SCHEDULER_PATH, query=(f".proplist={SCHEDULER_PROPLIST}",)),
        frozenset({"name", "on-event", "disabled"}),
    )
    if len(script_rows) > MAX_SCRIPTS or len(scheduler_rows) > MAX_SCHEDULERS:
        raise ValueError("RouterOS inventory exceeds the bounded record count")

    scripts: list[dict[str, Any]] = []
    indexes_by_name: dict[str, list[int]] = {}
    total_source_bytes = 0
    for index, row in enumerate(script_rows, start=1):
        name = _text(row["name"], limit=MAX_NAME_CHARS)
        source = _text(row["source"], limit=MAX_SOURCE_BYTES, allow_empty=True)
        source_bytes = source.encode("utf-8")
        total_source_bytes += len(source_bytes)
        if total_source_bytes > MAX_TOTAL_SOURCE_BYTES:
            raise ValueError("RouterOS script sources exceed the bounded size")
        comparison = compare_scripts(reference, source_bytes)
        scripts.append(
            {
                "script_index": index,
                "source_sha256": comparison["candidate_sha256"],
                "exact_template_match": comparison["exact_match"],
                "changed_line_count": comparison["changed_line_count"],
                "risk_flags": comparison["risk_flags"],
            }
        )
        indexes_by_name.setdefault(name, []).append(index)

    schedulers: list[dict[str, Any]] = []
    direct_binding_count = 0
    opaque_scheduler_count = 0
    enabled_scheduler_count = 0
    disabled_scheduler_count = 0
    for index, row in enumerate(scheduler_rows, start=1):
        _text(row["name"], limit=MAX_NAME_CHARS)
        event = _text(row["on-event"], limit=MAX_EVENT_CHARS, allow_empty=True)
        enabled = _enabled(row["disabled"])
        enabled_scheduler_count += int(enabled)
        disabled_scheduler_count += int(not enabled)
        matches = indexes_by_name.get(event, []) if event else []
        if len(matches) == 1:
            schedulers.append(
                {"scheduler_index": index, "enabled": enabled, "target_kind": "listed_script", "script_index": matches[0]}
            )
            direct_binding_count += 1
        else:
            schedulers.append(
                {"scheduler_index": index, "enabled": enabled, "target_kind": "opaque"}
            )
            opaque_scheduler_count += 1

    exact_match_count = sum(bool(item["exact_template_match"]) for item in scripts)
    return {
        "format": FORMAT,
        "collected": True,
        "collected_at": collected_at or datetime.now(timezone.utc).isoformat(),
        "api_print_responses_complete": True,
        "api_scope_note": "Completed print responses; caller authorization and router-side visibility are not verified.",
        "script_count": len(scripts),
        "exact_template_match_count": exact_match_count,
        "scheduler_count": len(schedulers),
        "scheduler_enabled_count": enabled_scheduler_count,
        "scheduler_disabled_count": disabled_scheduler_count,
        "direct_scheduler_binding_count": direct_binding_count,
        "opaque_scheduler_count": opaque_scheduler_count,
        "scheduler_binding_scope": "exact on-event name matches only; other events are opaque",
        "ambiguous_script_name_count": sum(len(indexes) > 1 for indexes in indexes_by_name.values()),
        "scripts": scripts,
        "schedulers": schedulers,
        "read_only_api_paths": [SCRIPT_PATH, SCHEDULER_PATH],
        "raw_script_source_written": False,
        "raw_scheduler_event_written": False,
        "credential_values_written": False,
        "report_contains_source_fingerprints": True,
        "review_status": "inventory_collected_review_required",
    }


def _write_report(path: Path, report: Mapping[str, Any]) -> None:
    """Atomically write only to a local path outside the checked-out repository."""
    path = path.absolute()
    if path.suffix.casefold() != ".json" or not _is_local_filesystem(path):
        raise ValueError("private report path is not an approved local JSON file")
    repository_root = TEMPLATE_PATH.resolve().parents[2]
    try:
        path.resolve().relative_to(repository_root)
    except ValueError:
        pass
    except (OSError, RuntimeError) as error:
        raise ValueError("private report path cannot be safely resolved") from error
    else:
        raise ValueError("private report must be outside the repository")

    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent,
            prefix=f".{path.name}.", suffix=".tmp", delete=False,
        ) as temporary:
            temporary_path = Path(temporary.name)
            temporary.write(json.dumps(report, indent=2, sort_keys=True) + "\n")
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_path, path)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, help="private local JSON report path outside the repository")
    parser.add_argument("--host-env", default="ROUTEROS_INVENTORY_HOST")
    parser.add_argument("--username-env", default="ROUTEROS_INVENTORY_USERNAME")
    parser.add_argument("--password-env", default="ROUTEROS_INVENTORY_PASSWORD")
    parser.add_argument("--ca-file-env", default="ROUTEROS_INVENTORY_CA_FILE")
    parser.add_argument("--port", type=int, default=8729, help="TLS Binary API port")
    args = parser.parse_args(argv)

    connection: RouterOSBinaryConnection | None = None
    try:
        host = os.environ.get(args.host_env, "")
        username = os.environ.get(args.username_env, "")
        password = os.environ.get(args.password_env, "") or getpass.getpass("RouterOS read-only API password: ")
        if not host or not username or not password or not 1 <= args.port <= 65535:
            raise ValueError("required RouterOS inventory settings are missing")
        reference = TEMPLATE_PATH.read_bytes()
        connection = RouterOSBinaryConnection(
            host,
            port=args.port,
            ca_file=os.environ.get(args.ca_file_env) or None,
            timeout=10,
        )
        connection.connect(username, password)
        report = collect_inventory(connection, reference)
        _write_report(Path(args.output), report)
        print(json.dumps({
            "collected": True,
            "script_count": report["script_count"],
            "exact_template_match_count": report["exact_template_match_count"],
            "scheduler_count": report["scheduler_count"],
            "direct_scheduler_binding_count": report["direct_scheduler_binding_count"],
            "opaque_scheduler_count": report["opaque_scheduler_count"],
            "report_written": True,
        }, sort_keys=True))
        return 0
    except (OSError, ValueError, RouterOSBinaryError) as error:
        failure_report = {
            "format": FORMAT,
            "collected": False,
            "error": type(error).__name__,
            "raw_script_source_written": False,
            "raw_scheduler_event_written": False,
            "credential_values_written": False,
            "review_status": "collection_failed",
        }
        try:
            _write_report(Path(args.output), failure_report)
        except (OSError, ValueError):
            pass
        print(json.dumps({"collected": False, "error": type(error).__name__}, sort_keys=True))
        return 2
    finally:
        if connection is not None:
            connection.close()


if __name__ == "__main__":
    raise SystemExit(main())
