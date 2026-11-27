# SPDX-License-Identifier: AGPL-3.0-or-later
"""Cross-process maintenance lock (review REV-10).

Normal operations (prepare, complete, cancel, recover, cleanup) hold a SHARED lock;
maintenance (rewrap, key retirement, restore recovery) needs the EXCLUSIVE lock, i.e. a
maintenance window with no concurrent normal operation. ``fcntl.flock`` on a file in the
private data directory (local filesystem only, like SQLite WAL). Acquisition is bounded:
on timeout the caller gets SERVICE_UNAVAILABLE and may retry; nothing is half-done.
"""

import contextlib
import fcntl
import os
import time
from collections.abc import Generator
from pathlib import Path

from signport_engine.errors import EngineError, ErrorCode

_POLL_SECONDS = 0.02


class MaintenanceLock:
    def __init__(self, data_dir: Path, *, timeout_seconds: float) -> None:
        self._path = data_dir / "maintenance.lock"
        self._timeout = timeout_seconds
        fd = os.open(self._path, os.O_WRONLY | os.O_CREAT, 0o600)
        os.close(fd)

    @contextlib.contextmanager
    def _hold(self, mode: int, what: str) -> Generator[None]:
        fd = os.open(self._path, os.O_RDONLY)
        try:
            deadline = time.monotonic() + self._timeout
            while True:
                try:
                    fcntl.flock(fd, mode | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise EngineError(ErrorCode.SERVICE_UNAVAILABLE, f"{what}; retry later.") from None
                    time.sleep(_POLL_SECONDS)
            try:
                yield
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    def shared(self) -> contextlib.AbstractContextManager[None]:
        return self._hold(fcntl.LOCK_SH, "Engine maintenance in progress")

    def exclusive(self) -> contextlib.AbstractContextManager[None]:
        return self._hold(fcntl.LOCK_EX, "Engine busy; maintenance needs exclusive access")
