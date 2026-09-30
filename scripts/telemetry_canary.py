"""Run a local, redacted telemetry canary comparison.

Input is newline-delimited JSON produced by a private operator harness. Each
line contains ``legacy`` and ``binary`` session arrays and an optional
``binary_timestamp``. The command prints counts and health only; it never
prints session identifiers or raw records.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Iterable, TextIO

# When invoked as ``python scripts/telemetry_canary.py``, Python puts the
# scripts directory ahead of the repository root.  Put the library root first
# so this CLI imports the production comparator rather than itself.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from telemetry_canary import CanaryPolicy, TelemetryCanary


def _source(path: str) -> TextIO:
    if path == "-":
        return sys.stdin
    return Path(path).open("r", encoding="utf-8")


def run(lines: Iterable[str], *, policy: CanaryPolicy) -> tuple[int, dict[str, Any]]:
    canary = TelemetryCanary(policy)
    samples = 0
    for line in lines:
        if not line.strip():
            continue
        sample = json.loads(line)
        if not isinstance(sample, dict):
            raise ValueError("each sample must be a JSON object")
        canary.observe(
            sample.get("legacy", []),
            sample.get("binary", []),
            observed_at=sample.get("observed_at"),
            binary_timestamp=sample.get("binary_timestamp"),
        )
        samples += 1
    if not samples:
        raise ValueError("at least one canary sample is required")
    last = canary.last_result
    assert last is not None
    summary = {
        "samples": samples,
        "healthy": last.healthy,
        "reason": last.reason,
        "age_seconds": round(last.age_seconds, 3),
        "missing_count": len(last.missing_sessions),
        "extra_count": len(last.extra_sessions),
        "consecutive_healthy": canary.consecutive_healthy,
        "ready_to_promote": canary.ready_to_promote,
    }
    return (0 if canary.ready_to_promote else 1), summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", default="-", help="NDJSON sample file, or - for stdin")
    parser.add_argument("--max-age", type=float, default=10.0)
    parser.add_argument("--required-consecutive", type=int, default=3)
    args = parser.parse_args()
    source: TextIO | None = None
    try:
        policy = CanaryPolicy(max_age_seconds=args.max_age, required_consecutive=args.required_consecutive)
        source = _source(args.input)
        code, summary = run(source, policy=policy)
    except (OSError, ValueError) as error:
        print(json.dumps({"healthy": False, "reason": "invalid_input", "error": str(error)[:120]}))
        return 2
    finally:
        if source is not None and source is not sys.stdin:
            source.close()
    print(json.dumps(summary, sort_keys=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
