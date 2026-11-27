# SPDX-License-Identifier: AGPL-3.0-or-later
"""Fault injection between filesystem and SQLite (plan E3-E6 §10, F1-F4 and preparation crash)."""

import errno
import os
from pathlib import Path

import pytest
from conftest import run
from support.engine import (
    ALG,
    ATTEMPT_ID,
    DOCUMENT_VERSION_ID,
    CrashAt,
    FakeClock,
    SimulatedCrash,
    engine_env,
    service,
    sign_view,
)
from support.pki import LabPki

from signport_engine.errors import EngineError, ErrorCode
from signport_engine.pdf.external_signing import sha256_hex
from signport_engine.persistence.repository import PreparationStatus
from signport_engine.service import PreparationService, PreparationView
from signport_engine.storage.blobs import EncryptedBlobStore


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def env(tmp_path: Path) -> dict[str, str]:
    return engine_env(tmp_path / "engine", ENGINE_COMPLETION_WAIT_MS="0")


def prepare(svc: PreparationService, pki: LabPki, pdf: bytes) -> PreparationView:
    return run(
        svc.prepare(
            pdf,
            document_version_id=DOCUMENT_VERSION_ID,
            expected_document_sha256=sha256_hex(pdf),
            certificate_der=pki.signer.der,
            chain_der=pki.chain_der,
            policy="icpbr-pades-rb",
        )
    )


def complete(svc: PreparationService, view: PreparationView, sig: bytes) -> object:
    return run(
        svc.complete(
            view.record.preparation_id,
            attempt_id=ATTEMPT_ID,
            signature=sig,
            signature_algorithm=ALG,
            certificate_sha256=view.record.certificate_sha256,
        )
    )


def artifacts(env: dict[str, str]) -> list[Path]:
    return sorted((Path(env["ENGINE_DATA_DIR"]) / "artifacts").rglob("*.bin"))


def test_f1_crash_after_claim_then_retry_after_lease(
    env: dict[str, str], clock: FakeClock, pki: LabPki, pdf: bytes
) -> None:
    view = prepare(service(env, clock=clock), pki, pdf)
    sig = sign_view(pki.signer, view)
    with pytest.raises(SimulatedCrash):
        complete(service(env, clock=clock, faults=CrashAt("after_claim")), view, sig)
    fresh = service(env, clock=clock)
    assert fresh.get(view.record.preparation_id).record.status is PreparationStatus.COMPLETING
    with pytest.raises(EngineError) as err:  # lease still held: no double work, retry later
        complete(fresh, view, sig)
    assert err.value.code is ErrorCode.SERVICE_UNAVAILABLE
    clock.advance(61)
    result = complete(fresh, view, sig)
    assert result.record.status is PreparationStatus.COMPLETED  # type: ignore[attr-defined]
    assert len(artifacts(env)) == 1


def test_f2_crash_after_artifact_write_then_client_retry(
    env: dict[str, str], clock: FakeClock, pki: LabPki, pdf: bytes
) -> None:
    view = prepare(service(env, clock=clock), pki, pdf)
    sig = sign_view(pki.signer, view)
    with pytest.raises(SimulatedCrash):
        complete(service(env, clock=clock, faults=CrashAt("after_artifact_write")), view, sig)
    published = artifacts(env)
    assert len(published) == 1
    before = published[0].read_bytes()
    clock.advance(61)
    result = complete(service(env, clock=clock), view, sig)
    assert artifacts(env) == published  # deterministic: same file, never rewritten
    assert published[0].read_bytes() == before
    assert result.record.artifact_ref == published[0].relative_to(Path(env["ENGINE_DATA_DIR"])).as_posix()  # type: ignore[attr-defined]


def test_f2_crash_after_artifact_write_then_background_recovery(
    env: dict[str, str], clock: FakeClock, pki: LabPki, pdf: bytes
) -> None:
    view = prepare(service(env, clock=clock), pki, pdf)
    with pytest.raises(SimulatedCrash):
        complete(
            service(env, clock=clock, faults=CrashAt("after_artifact_write")),
            view,
            sign_view(pki.signer, view),
        )
    fresh = service(env, clock=clock)
    assert run(fresh.recover_stale()) == []  # lease not expired yet
    clock.advance(61)
    assert run(fresh.recover_stale()) == [view.record.preparation_id]
    record = fresh.get(view.record.preparation_id).record
    assert record.status is PreparationStatus.COMPLETED
    assert sha256_hex(fresh.read_artifact(view.record.preparation_id)) == record.artifact_sha256


def test_f2_recovery_never_publishes_a_tampered_artifact(
    env: dict[str, str], clock: FakeClock, pki: LabPki, pdf: bytes
) -> None:
    view = prepare(service(env, clock=clock), pki, pdf)
    with pytest.raises(SimulatedCrash):
        complete(
            service(env, clock=clock, faults=CrashAt("after_artifact_write")),
            view,
            sign_view(pki.signer, view),
        )
    (path,) = artifacts(env)
    path.chmod(0o640)
    data = bytearray(path.read_bytes())
    data[-1] ^= 1
    path.write_bytes(bytes(data))
    clock.advance(61)
    fresh = service(env, clock=clock)
    assert run(fresh.recover_stale()) == []
    assert fresh.get(view.record.preparation_id).record.status is PreparationStatus.COMPLETING


def test_f3_crash_before_artifact_write_leaves_nothing_published(
    env: dict[str, str], clock: FakeClock, pki: LabPki, pdf: bytes
) -> None:
    view = prepare(service(env, clock=clock), pki, pdf)
    sig = sign_view(pki.signer, view)
    with pytest.raises(SimulatedCrash):
        complete(service(env, clock=clock, faults=CrashAt("before_artifact_write")), view, sig)
    assert artifacts(env) == []
    assert not list((Path(env["ENGINE_DATA_DIR"]) / "tmp").iterdir())
    clock.advance(61)
    assert complete(service(env, clock=clock), view, sig).record.status is PreparationStatus.COMPLETED  # type: ignore[attr-defined]


def test_f3_interrupted_link_leaves_no_partial_final_file(
    env: dict[str, str], clock: FakeClock, pki: LabPki, pdf: bytes, monkeypatch: pytest.MonkeyPatch
) -> None:
    view = prepare(service(env, clock=clock), pki, pdf)
    sig = sign_view(pki.signer, view)

    def crash_link(*_a: object) -> None:
        raise SimulatedCrash("os.link")

    monkeypatch.setattr(os, "link", crash_link)
    with pytest.raises(SimulatedCrash):
        complete(service(env, clock=clock), view, sig)
    monkeypatch.undo()
    assert artifacts(env) == []
    assert not list((Path(env["ENGINE_DATA_DIR"]) / "tmp").iterdir())  # temp removed in finally
    clock.advance(61)
    assert complete(service(env, clock=clock), view, sig).record.status is PreparationStatus.COMPLETED  # type: ignore[attr-defined]


def test_f4_disk_full_is_transient(
    env: dict[str, str], clock: FakeClock, pki: LabPki, pdf: bytes, monkeypatch: pytest.MonkeyPatch
) -> None:
    view = prepare(service(env, clock=clock), pki, pdf)
    sig = sign_view(pki.signer, view)
    original = EncryptedBlobStore.put

    def full(*_a: object, **_k: object) -> str:
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(EncryptedBlobStore, "put", full)
    with pytest.raises(EngineError) as err:
        complete(service(env, clock=clock), view, sig)
    assert err.value.code is ErrorCode.SERVICE_UNAVAILABLE
    monkeypatch.setattr(EncryptedBlobStore, "put", original)
    fresh = service(env, clock=clock)
    assert fresh.get(view.record.preparation_id).record.status is PreparationStatus.COMPLETING
    clock.advance(61)
    assert complete(fresh, view, sig).record.status is PreparationStatus.COMPLETED  # type: ignore[attr-defined]


def test_crash_during_prepare_leaves_only_an_orphan_that_cleanup_removes(
    env: dict[str, str], clock: FakeClock, pki: LabPki, pdf: bytes
) -> None:
    with pytest.raises(SimulatedCrash):
        prepare(service(env, clock=clock, faults=CrashAt("after_prepared_blob")), pki, pdf)
    prepared = list((Path(env["ENGINE_DATA_DIR"]) / "prepared").glob("*.bin"))
    assert len(prepared) == 1
    assert b"%PDF" not in prepared[0].read_bytes()  # even the orphan is encrypted
    os.utime(prepared[0], (1_000_000_000, 1_000_000_000))
    assert service(env, clock=clock).cleanup()["orphans_removed"] == 0  # intent still young (REV-07)
    clock.advance(3601)
    assert service(env, clock=clock).cleanup()["orphans_removed"] == 1
    assert not prepared[0].exists()


def test_abandoned_completion_without_artifact_fails_after_expiry(
    env: dict[str, str], clock: FakeClock, pki: LabPki, pdf: bytes
) -> None:
    view = prepare(service(env, clock=clock), pki, pdf)
    with pytest.raises(SimulatedCrash):
        complete(service(env, clock=clock, faults=CrashAt("after_claim")), view, sign_view(pki.signer, view))
    fresh = service(env, clock=clock)
    clock.advance(61)
    assert run(fresh.recover_stale()) == []
    assert (
        fresh.get(view.record.preparation_id).record.status is PreparationStatus.COMPLETING
    )  # still retryable
    clock.advance(600 + 300)  # past expires_at + completion grace (REV-09)
    run(fresh.recover_stale())
    record = fresh.get(view.record.preparation_id).record
    assert record.status is PreparationStatus.FAILED
    assert record.failure_reason == "expired_during_completion"
