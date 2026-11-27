# SPDX-License-Identifier: AGPL-3.0-or-later
"""Real OS processes (spawn): cross-process resume, concurrent completion, SIGKILL recovery."""

import base64
import multiprocessing
import os
import signal
import time
from pathlib import Path
from typing import Any

import pytest
from conftest import run
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, utils
from support import workers
from support.engine import ATTEMPT_ID, OTHER_ATTEMPT_ID, engine_env, service
from support.openssl import openssl_available, openssl_cms_verify
from support.pki import LabPki
from support.validation import validate_all

from signport_engine.errors import EngineError
from signport_engine.pdf.external_signing import sha256_hex
from signport_engine.persistence.repository import PreparationStatus

CTX = multiprocessing.get_context("spawn")
OPENSSL_RUNNABLE = openssl_available() or os.environ.get("SIGNPORT_REQUIRE_OPENSSL") == "1"


def _get(q: Any) -> Any:
    return q.get(timeout=120)


def _prepare_in_child(env: dict[str, str], pki: LabPki, pdf: bytes) -> tuple[str, bytes, str]:
    q = CTX.Queue()
    p = CTX.Process(
        target=workers.prepare_worker, args=(env, pdf, sha256_hex(pdf), pki.signer.der, pki.chain_der, q)
    )
    p.start()
    pid, digest_b64, cert_sha = _get(q)
    p.join(60)
    assert p.exitcode == 0
    sig = pki.signer.key.sign(
        base64.b64decode(digest_b64), padding.PKCS1v15(), utils.Prehashed(hashes.SHA256())
    )
    return pid, sig, cert_sha


def _artifacts(env: dict[str, str]) -> list[Path]:
    return sorted((Path(env["ENGINE_DATA_DIR"]) / "artifacts").rglob("*.bin"))


def test_prepare_in_one_process_complete_in_another(
    tmp_path: Path, pki: LabPki, pdf: bytes, crls: list[x509.CertificateRevocationList]
) -> None:
    env = engine_env(tmp_path / "engine")
    pid, sig, cert_sha = _prepare_in_child(env, pki, pdf)
    q = CTX.Queue()
    p = CTX.Process(target=workers.complete_worker, args=(env, pid, ATTEMPT_ID, sig, cert_sha, None, q))
    p.start()
    status, sha = _get(q)
    p.join(60)
    assert (status, p.exitcode) == ("ok", 0)
    signed = service(env).read_artifact(pid)  # read back in a third process (this one)
    assert sha256_hex(signed) == sha
    (result,) = run(validate_all(signed, [pki.root.cert], crls))
    assert result.status.bottom_line
    if OPENSSL_RUNNABLE:
        assert openssl_cms_verify(signed, pki.root.pem, tmp_path).returncode == 0


def test_concurrent_identical_completions_produce_one_artifact(
    tmp_path: Path, pki: LabPki, pdf: bytes
) -> None:
    env = engine_env(tmp_path / "engine")
    pid, sig, cert_sha = _prepare_in_child(env, pki, pdf)
    n = 4
    barrier, q = CTX.Barrier(n), CTX.Queue()
    procs = [
        CTX.Process(target=workers.complete_worker, args=(env, pid, ATTEMPT_ID, sig, cert_sha, barrier, q))
        for _ in range(n)
    ]
    for p in procs:
        p.start()
    results = [_get(q) for _ in procs]
    for p in procs:
        p.join(60)
    assert {r[0] for r in results} == {"ok"}
    assert len({r[1] for r in results}) == 1  # everyone got the same artifact
    assert len(_artifacts(env)) == 1
    record = service(env).get(pid).record
    assert record.status is PreparationStatus.COMPLETED
    assert record.state_version == 3  # created, claimed, completed: no extra transitions


def test_concurrent_divergent_completions_are_excluded(tmp_path: Path, pki: LabPki, pdf: bytes) -> None:
    env = engine_env(tmp_path / "engine")
    pid, sig, cert_sha = _prepare_in_child(env, pki, pdf)
    barrier, q = CTX.Barrier(2), CTX.Queue()
    procs = [
        CTX.Process(target=workers.complete_worker, args=(env, pid, attempt, sig, cert_sha, barrier, q))
        for attempt in (ATTEMPT_ID, OTHER_ATTEMPT_ID)
    ]
    for p in procs:
        p.start()
    results = sorted(_get(q) for _ in procs)
    for p in procs:
        p.join(60)
    assert [r[0] for r in results] == ["error", "ok"]
    assert results[0][1] == "CONFLICT"
    assert len(_artifacts(env)) == 1


def test_sigkill_while_holding_the_lease_is_recovered(tmp_path: Path, pki: LabPki, pdf: bytes) -> None:
    env = engine_env(tmp_path / "engine", ENGINE_COMPLETION_LEASE_SECONDS="5", ENGINE_COMPLETION_WAIT_MS="0")
    pid, sig, cert_sha = _prepare_in_child(env, pki, pdf)
    reached = CTX.Event()
    p = CTX.Process(
        target=workers.hang_worker, args=(env, pid, ATTEMPT_ID, sig, cert_sha, "after_claim", reached)
    )
    p.start()
    assert reached.wait(120)
    os.kill(p.pid or 0, signal.SIGKILL)
    p.join(30)
    assert p.exitcode == -signal.SIGKILL
    svc = service(env)
    assert svc.get(pid).record.status is PreparationStatus.COMPLETING
    with pytest.raises(EngineError):  # lease still valid -> retry later, no double signing
        run(
            svc.complete(
                pid,
                attempt_id=ATTEMPT_ID,
                signature=sig,
                signature_algorithm="RSA_PKCS1_V1_5",
                certificate_sha256=cert_sha,
            )
        )
    time.sleep(5.5)
    result = run(
        svc.complete(
            pid,
            attempt_id=ATTEMPT_ID,
            signature=sig,
            signature_algorithm="RSA_PKCS1_V1_5",
            certificate_sha256=cert_sha,
        )
    )
    assert result.record.status is PreparationStatus.COMPLETED
    assert len(_artifacts(env)) == 1


def test_sigkill_after_artifact_write_is_recovered_in_background(
    tmp_path: Path, pki: LabPki, pdf: bytes
) -> None:
    env = engine_env(tmp_path / "engine", ENGINE_COMPLETION_LEASE_SECONDS="5")
    pid, sig, cert_sha = _prepare_in_child(env, pki, pdf)
    reached = CTX.Event()
    p = CTX.Process(
        target=workers.hang_worker,
        args=(env, pid, ATTEMPT_ID, sig, cert_sha, "after_artifact_write", reached),
    )
    p.start()
    assert reached.wait(120)
    os.kill(p.pid or 0, signal.SIGKILL)
    p.join(30)
    assert len(_artifacts(env)) == 1
    time.sleep(5.5)
    svc = service(env)
    assert run(svc.recover_stale()) == [pid]
    assert svc.get(pid).record.status is PreparationStatus.COMPLETED


def test_durable_nonce_reservation_is_unique_across_processes(tmp_path: Path) -> None:
    env = engine_env(tmp_path / "engine")
    service(env)  # create and migrate the database
    n, count = 4, 250
    barrier, q = CTX.Barrier(n), CTX.Queue()
    procs = [CTX.Process(target=workers.reserve_worker, args=(env, count, barrier, q)) for _ in range(n)]
    for p in procs:
        p.start()
    reserved = [c for _ in procs for c in _get(q)]
    for p in procs:
        p.join(60)
    assert sorted(reserved) == list(range(n * count))  # no counter handed out twice, none lost
