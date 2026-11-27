# SPDX-License-Identifier: AGPL-3.0-or-later
"""Identifier helpers. UUIDv7 per RFC 9562 §5.7 (Python 3.13 has no uuid.uuid7)."""

import os
import re
import time
import uuid

UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")


def uuid7() -> str:
    unix_ms = time.time_ns() // 1_000_000
    rand = int.from_bytes(os.urandom(10), "big")
    value = (unix_ms & ((1 << 48) - 1)) << 80
    value |= 0x7 << 76
    value |= ((rand >> 62) & 0xFFF) << 64
    value |= 0b10 << 62
    value |= rand & ((1 << 62) - 1)
    return str(uuid.UUID(int=value))


def require_uuid(value: str, what: str) -> str:
    if not UUID_RE.fullmatch(value):
        raise ValueError(f"{what} must be a canonical lowercase UUID")
    return value
