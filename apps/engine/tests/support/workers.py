# SPDX-License-Identifier: AGPL-3.0-or-later
"""Module-level worker functions for multi-process tests (spawn start method).

Inter-process messages are plain tuples of str/bytes passed by multiprocessing in
tests only; the Engine itself never uses pickle.
"""

import asyncio
import time
from multiprocessing.synchronize import Barrier, Event
from typing import Any

from signport_engine.errors import EngineError
from signport_engine.service import open_engine

DOCUMENT_VERSION_ID = "01936f3c-0000-7000-8000-000000000007"


def prepare_worker(
    env: dict[str, str], pdf: bytes, sha: str, cert: bytes, chain: tuple[bytes, ...], out: Any
) -> None:
    svc = open_engine(env)
    view = asyncio.run(
        svc.prepare(
            pdf,
            document_version_id=DOCUMENT_VERSION_ID,
            expected_document_sha256=sha,
            certificate_der=cert,
            chain_der=chain,
            policy="icpbr-pades-rb",
        )
    )
    out.put((view.record.preparation_id, view.signed_attributes_digest_b64, view.record.certificate_sha256))


def complete_worker(
    env: dict[str, str], pid: str, attempt: str, sig: bytes, cert_sha: str, barrier: Barrier | None, out: Any
) -> None:
    svc = open_engine(env)
    if barrier is not None:
        barrier.wait(timeout=60)
    try:
        result = asyncio.run(
            svc.complete(
                pid,
                attempt_id=attempt,
                signature=sig,
                signature_algorithm="RSA_PKCS1_V1_5",
                certificate_sha256=cert_sha,
            )
        )
        out.put(("ok", result.record.artifact_sha256))
    except EngineError as exc:
        out.put(("error", exc.code.value))


class _HangAt:
    def __init__(self, point: str, reached: Event) -> None:
        self.point, self.reached = point, reached

    def hit(self, name: str) -> None:
        if name == self.point:
            self.reached.set()
            time.sleep(3600)  # until SIGKILL


def hang_worker(
    env: dict[str, str], pid: str, attempt: str, sig: bytes, cert_sha: str, point: str, reached: Event
) -> None:
    svc = open_engine(env, faults=_HangAt(point, reached))
    asyncio.run(
        svc.complete(
            pid,
            attempt_id=attempt,
            signature=sig,
            signature_algorithm="RSA_PKCS1_V1_5",
            certificate_sha256=cert_sha,
        )
    )


def reserve_worker(env: dict[str, str], count: int, barrier: Barrier, out: Any) -> None:
    from pathlib import Path

    from signport_engine.config import EngineSettings
    from signport_engine.crypto.keys import Purpose, load_keyring
    from signport_engine.persistence.sqlite import SqlitePreparationRepository

    settings = EngineSettings.from_env(env)
    repo = SqlitePreparationRepository(
        settings.data_dir / "engine.sqlite3",
        instance_id=settings.instance_id,
        keyring=load_keyring(env, Path(env["ENGINE_DATA_DIR"]), env["ENGINE_INSTANCE_ID"]),
        busy_timeout_ms=settings.busy_timeout_ms,
    )
    barrier.wait(timeout=60)
    size = 10
    starts = [
        repo.reserve_nonce_block(env["ENGINE_STATE_KEY_ID"], Purpose.STATE, size)
        for _ in range(count // size)
    ]
    out.put([c for start in starts for c in range(start, start + size)])


class _StallAt:
    """Reach a point, signal, then wait for an explicit resume (process is SIGSTOPped meanwhile)."""

    def __init__(self, point: str, reached: Event, resume: Event) -> None:
        self.point, self.reached, self.resume = point, reached, resume

    def hit(self, name: str) -> None:
        if name == self.point:
            self.reached.set()
            self.resume.wait(300)


def stall_worker(
    env: dict[str, str],
    pid: str,
    attempt: str,
    sig: bytes,
    cert_sha: str,
    point: str,
    reached: Event,
    resume: Event,
    out: Any,
) -> None:
    svc = open_engine(env, faults=_StallAt(point, reached, resume))
    try:
        result = asyncio.run(
            svc.complete(
                pid,
                attempt_id=attempt,
                signature=sig,
                signature_algorithm="RSA_PKCS1_V1_5",
                certificate_sha256=cert_sha,
            )
        )
        out.put(("ok", result.record.artifact_sha256, result.record.state_version))
    except EngineError as exc:
        out.put(("error", exc.code.value, 0))


def cleanup_loop_worker(env: dict[str, str], stop: Event, out: Any) -> None:
    svc = open_engine(env)
    runs = 0
    while not stop.is_set():
        try:
            svc.cleanup()
            runs += 1
        except EngineError:
            pass  # busy storage under contention is acceptable; retry
    out.put(runs)


def rewrap_hold_worker(env: dict[str, str], reached: Event, resume: Event) -> None:
    svc = open_engine(env, faults=_StallAt("rewrap_after_blob", reached, resume))
    svc.rewrap(batch=1)
