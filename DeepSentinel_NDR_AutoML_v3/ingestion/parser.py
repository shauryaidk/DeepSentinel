"""Strict parser and normalizer for Zeek JSON log lines."""

from __future__ import annotations

import json
from typing import Any


def parse_zeek_line(line: str) -> dict[str, Any] | None:
    """
    Parse one Zeek JSON log line.

    Returns:
        dict: Valid Zeek event.
        None: Blank, metadata, malformed, or non-object line.
    """

    line = line.strip()

    # Ignore blank lines and Zeek metadata lines.
    if not line or line.startswith("#"):
        return None

    try:
        value = json.loads(line)
    except json.JSONDecodeError:
        return None

    # Every Zeek event must be a JSON object.
    if not isinstance(value, dict):
        return None

    return value