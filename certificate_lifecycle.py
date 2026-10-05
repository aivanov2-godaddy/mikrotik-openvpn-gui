"""Timezone-independent helpers for RouterOS certificate lifecycle values."""

from __future__ import annotations

import re
from typing import Any


def remaining_seconds(value: Any) -> int | None:
    """Parse RouterOS relative time values such as ``3w2d4h5m6s``."""
    raw = str(value or "").strip()
    if not raw or len(raw) > 64:
        return None
    match = re.fullmatch(r"(-)?(?:(\d+)w)?(?:(\d+)d)?(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?", raw, re.I)
    if not match or not any(part is not None for part in match.groups()[1:]):
        return None
    try:
        weeks, days, hours, minutes, seconds = (int(part or 0) for part in match.groups()[1:])
    except ValueError:
        return None
    total = weeks * 604800 + days * 86400 + hours * 3600 + minutes * 60 + seconds
    return -total if match.group(1) else total
