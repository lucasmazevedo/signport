# SPDX-License-Identifier: AGPL-3.0-or-later
"""Injectable clock. All persisted times are RFC 3339 UTC with 'Z' and second precision."""

import datetime as dt
from typing import Protocol


class Clock(Protocol):
    def now(self) -> dt.datetime: ...


class SystemClock:
    def now(self) -> dt.datetime:
        return dt.datetime.now(dt.UTC).replace(microsecond=0)


def to_rfc3339(value: dt.datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("naive datetime")
    return value.astimezone(dt.UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def from_rfc3339(value: str) -> dt.datetime:
    parsed = dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    return parsed.replace(tzinfo=dt.UTC)
