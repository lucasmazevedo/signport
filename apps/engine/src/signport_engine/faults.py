# SPDX-License-Identifier: AGPL-3.0-or-later
"""Named fault-injection points for failure testing. No-op in production."""

from typing import Protocol

FAULT_POINTS = frozenset(
    {
        "after_prepared_blob",  # prepared PDF sealed on disk, no DB row yet
        "after_claim",  # prepared -> completing committed, CMS not built
        "before_artifact_write",  # signed PDF built and verified, nothing on disk
        "after_artifact_write",  # artifact published on disk, completed not committed
        "rewrap_after_blob",  # a blob was re-sealed with the new key, DB not yet updated
    }
)


class FaultPoints(Protocol):
    def hit(self, name: str) -> None: ...


class NoFaults:
    def hit(self, name: str) -> None:
        if name not in FAULT_POINTS:
            raise ValueError(f"unknown fault point {name!r}")
