# SPDX-License-Identifier: AGPL-3.0-or-later
"""Regression tests for the E3-E4 code review findings REV-01 .. REV-14.

Each test names the finding it covers; see docs/architecture/notes/P1-E3-E4-code-review.md.
"""

import base64
import contextlib
import datetime as dt
import json
import multiprocessing
import os
import signal
import sqlite3
import threading
import time
from collections.abc import Callable, Generator
from pathlib import Path
from typing import Any

import pytest
from conftest import PROTOCOL_ROOT, run
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, utils
from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012
from support import workers
from support.engine import (
    ALG,
    ATTEMPT_ID,
    DOCUMENT_VERSION_ID,
    CrashAt,
    FakeClock,
    SimulatedCrash,
    engine_env,
    new_key,
    repository,
    service,
    sign_view,
)
from support.forge import artifact_aad, blob_store, forge_signed_pdf, load_prepared
from support.pki import LabPki, reissue_same_key

from signport_engine.cms.bindings import verify_preparation_bindings
from signport_engine.crypto.envelope import EnvelopeKind
from signport_engine.crypto.keys import Keyring, Purpose, load_keyring
from signport_engine.errors import ConfigurationError, EngineError, ErrorCode, StateIntegrityError
from signport_engine.pdf.external_signing import complete_external_signature, sha256_hex
from signport_engine.pdf.signature_field import bind_signature_field
from signport_engine.persistence.repository import ClaimKind, FencingToken, PreparationStatus
from signport_engine.service import PreparationService, PreparationView, completion_binding

CTX = multiprocessing.get_context("spawn")
INSTANCE = "01936f3c-0000-7000-8000-0000000000aa"


def prepare(svc: PreparationService, pki: LabPki, pdf: bytes, cert: bytes | None = None) -> PreparationView:
    return run(
        svc.prepare(
            pdf,
            document_version_id=DOCUMENT_VERSION_ID,
            expected_document_sha256=sha256_hex(pdf),
            certificate_der=cert or pki.signer.der,
            chain_der=pki.chain_der,
            policy="icpbr-pades-rb",
        )
    )


def complete(svc: PreparationService, view: PreparationView, sig: bytes, **kw: str) -> Any:
    args = {"signature_algorithm": ALG, "certificate_sha256": view.record.certificate_sha256} | kw
    return run(svc.complete(view.record.preparation_id, attempt_id=ATTEMPT_ID, signature=sig, **args))


def keyfile(path: Path, active: str, keys: dict[str, str]) -> str:
    path.write_text(json.dumps({"active_key_id": active, "keys": keys}))
    path.chmod(0o600)
    return str(path)


def base_env(tmp_path: Path, **extra: str) -> dict[str, str]:
    return {"ENGINE_DATA_DIR": str(tmp_path / "engine"), "ENGINE_INSTANCE_ID": INSTANCE, **extra}


@contextlib.contextmanager
def raw_db(env: dict[str, str]) -> Generator[sqlite3.Connection]:
    conn = sqlite3.connect(Path(env["ENGINE_DATA_DIR"]) / "engine.sqlite3")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def events(env: dict[str, str], pid: str) -> int:
    with raw_db(env) as conn:
        return int(
            conn.execute(
                "SELECT count(*) FROM preparation_events WHERE preparation_id = ?", (pid,)
            ).fetchone()[0]
        )


# ---------------------------------------------------------------------------------- REV-01


def test_rev01_rewrap_pages_through_more_rows_than_the_batch(tmp_path: Path, pki: LabPki, pdf: bytes) -> None:
    k1, k2 = new_key(), new_key()
    old = service(base_env(tmp_path, ENGINE_STATE_KEY_FILE=keyfile(tmp_path / "a.json", "k1", {"k1": k1})))
    views = [prepare(old, pki, pdf) for _ in range(7)]
    complete(old, views[0], sign_view(pki.signer, views[0]))
    rotated = service(
        base_env(tmp_path, ENGINE_STATE_KEY_FILE=keyfile(tmp_path / "b.json", "k2", {"k1": k1, "k2": k2}))
    )
    assert rotated.rewrap(batch=3) == 7
    assert rotated.key_ids_in_use() == {"k2"}
    versions = {
        v.record.preparation_id: rotated.get(v.record.preparation_id).record.state_version for v in views
    }
    counts = {v.record.preparation_id: events(base_env(tmp_path), v.record.preparation_id) for v in views}
    assert rotated.rewrap(batch=3) == 0  # nothing left: no version bump, no event, no updated_at change
    for v in views:
        r = rotated.get(v.record.preparation_id).record
        assert r.state_version == versions[r.preparation_id]
        assert events(base_env(tmp_path), r.preparation_id) == counts[r.preparation_id]


def test_rev01_replace_sealed_with_current_values_is_a_no_op(tmp_path: Path, pki: LabPki, pdf: bytes) -> None:
    """Directly exercises the no-op guard: an already-current row is not re-versioned or re-chained."""
    env = engine_env(tmp_path / "engine")
    view = prepare(service(env), pki, pdf)
    pid = view.record.preparation_id
    repo = repository(env)
    before = repo.get(pid)
    after = repo.replace_sealed(
        pid,
        expected_version=before.state_version,
        state_envelope=before.state_envelope,
        state_key_id=before.state_key_id,
        prepared_key_id=before.prepared_key_id,
        artifact_key_id=before.artifact_key_id,
        now=before.updated_at + dt.timedelta(hours=1),
    )
    assert after == before
    reread = repo.get(pid)
    assert (reread.state_version, reread.updated_at) == (before.state_version, before.updated_at)
    assert events(env, pid) == 1


def test_rev01_rewrap_interrupted_and_resumed(tmp_path: Path, pki: LabPki, pdf: bytes) -> None:
    k1, k2 = new_key(), new_key()
    old = service(base_env(tmp_path, ENGINE_STATE_KEY_FILE=keyfile(tmp_path / "a.json", "k1", {"k1": k1})))
    views = [prepare(old, pki, pdf) for _ in range(3)]
    env2 = base_env(tmp_path, ENGINE_STATE_KEY_FILE=keyfile(tmp_path / "b.json", "k2", {"k1": k1, "k2": k2}))
    with pytest.raises(SimulatedCrash):
        service(env2, faults=CrashAt("rewrap_after_blob")).rewrap(batch=1)
    resumed = service(env2)
    assert resumed.rewrap(batch=1) == 3
    assert resumed.key_ids_in_use() == {"k2"}
    for v in views:  # everything still decrypts and completes after the interrupted rotation
        assert complete(resumed, v, sign_view(pki.signer, v)).record.status is PreparationStatus.COMPLETED


# ---------------------------------------------------------------------------------- REV-02


def test_rev02_historic_reuse_of_key_material_under_another_id_is_refused(tmp_path: Path) -> None:
    k1 = new_key()
    service(base_env(tmp_path, ENGINE_STATE_KEY=k1, ENGINE_STATE_KEY_ID="k1"))
    with pytest.raises(ConfigurationError, match="previously registered under another key id"):
        service(base_env(tmp_path, ENGINE_STATE_KEY=k1, ENGINE_STATE_KEY_ID="k9"))


def test_rev02_material_swap_under_the_same_id_is_refused(tmp_path: Path) -> None:
    service(base_env(tmp_path, ENGINE_STATE_KEY=new_key(), ENGINE_STATE_KEY_ID="k1"))
    with pytest.raises(ConfigurationError, match="different key material"):
        service(base_env(tmp_path, ENGINE_STATE_KEY=new_key(), ENGINE_STATE_KEY_ID="k1"))


def test_rev02_tampered_nonce_counter_fails_closed(tmp_path: Path, pki: LabPki, pdf: bytes) -> None:
    env = engine_env(tmp_path / "engine")
    svc = service(env)
    prepare(svc, pki, pdf)
    with raw_db(env) as conn:
        conn.execute("UPDATE nonce_counters SET next_counter = 0")  # attempt to rewind
    with pytest.raises(EngineError) as err:
        prepare(service(env), pki, pdf)  # a fresh process must reserve a new block
    assert err.value.code is ErrorCode.INTERNAL_ERROR


def test_rev02_subkeys_are_bound_to_the_installation() -> None:
    raw = base64.urlsafe_b64decode(new_key() + "=")
    a = Keyring("k1", {"k1": raw}, instance_id=INSTANCE)
    b = Keyring("k1", {"k1": raw}, instance_id="01936f3c-0000-7000-8000-0000000000ff")
    for p in Purpose:
        assert a.subkey("k1", p) != b.subkey("k1", p)
    assert a.fingerprint("k1") != b.fingerprint("k1")


def test_rev02_no_secret_is_stored_in_the_key_registry(tmp_path: Path) -> None:
    key = new_key()
    env = base_env(tmp_path, ENGINE_STATE_KEY=key, ENGINE_STATE_KEY_ID="k1")
    service(env)
    with raw_db(env) as conn:
        dump = "\n".join(conn.iterdump())
    raw = base64.urlsafe_b64decode(key + "=")
    assert key not in dump
    assert raw.hex() not in dump


# ---------------------------------------------------------------------------------- REV-03


def test_rev03_reads_see_one_consistent_snapshot_during_transitions(
    tmp_path: Path, pki: LabPki, pdf: bytes
) -> None:
    env = engine_env(tmp_path / "engine")
    view = prepare(service(env), pki, pdf)
    repo = repository(env)
    pid = view.record.preparation_id
    t0 = dt.datetime(2030, 1, 1, tzinfo=dt.UTC)
    far = t0 + dt.timedelta(days=3650)
    expires = view.record.expires_at
    errors: list[BaseException] = []
    stop = threading.Event()

    def writer() -> None:
        try:
            now = expires - dt.timedelta(seconds=500)
            repo.claim_completion(
                pid, binding="b", attempt_id=ATTEMPT_ID, owner="o0", now=now, lease_until=now, deadline=far
            )
            for i in range(1, 300):  # every iteration is a legitimate takeover transition
                now += dt.timedelta(seconds=1)
                repo.claim_completion(
                    pid,
                    binding="b",
                    attempt_id=ATTEMPT_ID,
                    owner=f"o{i}",
                    now=now,
                    lease_until=now,
                    deadline=far,
                )
        except BaseException as exc:  # noqa: BLE001 - collected for the assertion
            errors.append(exc)
        finally:
            stop.set()

    def reader() -> None:
        while not stop.is_set():
            try:
                repo.get(pid)
            except StateIntegrityError as exc:
                errors.append(exc)
                return
            except EngineError:
                continue  # transient busy is acceptable; integrity errors are not

    threads = [threading.Thread(target=writer), *(threading.Thread(target=reader) for _ in range(3))]
    for t in threads:
        t.start()
    for t in threads:
        t.join(120)
    assert errors == []
    assert repo.get(pid).state_version == 301


# ---------------------------------------------------------------------------------- REV-04


def test_rev04_coordinated_rollback_of_row_and_chain_passes_local_checks(
    tmp_path: Path, pki: LabPki, pdf: bytes
) -> None:
    """Documented residual risk: restoring a preparation TOGETHER WITH its earlier authenticated
    event chain is indistinguishable locally from the original state."""
    env = engine_env(tmp_path / "engine")
    svc = service(env)
    pid = prepare(svc, pki, pdf).record.preparation_id
    with raw_db(env) as conn:
        row = conn.execute("SELECT * FROM preparations WHERE preparation_id = ?", (pid,)).fetchone()
        evs = conn.execute("SELECT * FROM preparation_events WHERE preparation_id = ?", (pid,)).fetchall()
        cols = [d[1] for d in conn.execute("PRAGMA table_info(preparations)")]
    svc.cancel(pid)
    with raw_db(env) as conn:
        conn.execute("DELETE FROM preparation_events WHERE preparation_id = ?", (pid,))
        conn.execute("DELETE FROM preparations WHERE preparation_id = ?", (pid,))
        # column names come from PRAGMA table_info (the schema itself), never from input
        insert = f"INSERT INTO preparations ({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))})"  # noqa: S608
        conn.execute(insert, row)
        conn.executemany("INSERT INTO preparation_events VALUES (?, ?, ?, ?, ?, ?, ?, ?)", evs)
    assert service(env).get(pid).record.status is PreparationStatus.PREPARED  # rolled back, undetected


# ---------------------------------------------------------------------------------- REV-05


def _completing_with_crash(
    env: dict[str, str], clock: FakeClock, pki: LabPki, pdf: bytes
) -> tuple[PreparationView, bytes]:
    view = prepare(service(env, clock=clock), pki, pdf)
    sig = sign_view(pki.signer, view)
    with pytest.raises(SimulatedCrash):
        complete(service(env, clock=clock, faults=CrashAt("after_claim")), view, sig)
    return view, sig


def _plant(env: dict[str, str], pid: str, signed: bytes) -> str:
    r = repository(env).get(pid)
    sha = sha256_hex(signed)
    ref = f"artifacts/{pid}/{sha}.bin"
    blob_store(env).put(ref, EnvelopeKind.SIGNED_ARTIFACT, signed, artifact_aad(env, r, sha))
    return ref


@pytest.mark.parametrize(
    "variant", ["other-key-signature", "foreign-signed-attrs", "other-certificate", "garbage-signature"]
)
def test_rev05_authentic_but_semantically_invalid_artifacts_are_never_adopted(
    tmp_path: Path, pki: LabPki, pdf: bytes, variant: str
) -> None:
    env, clock = engine_env(tmp_path / "engine"), FakeClock()
    view, sig = _completing_with_crash(env, clock, pki, pdf)
    r = repository(env).get(view.record.preparation_id)
    prepared = load_prepared(env, r)
    if variant == "other-key-signature":
        bad = pki.other_signer.key.sign(
            prepared.signed_attributes_digest, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256())
        )
        signed = run(forge_signed_pdf(prepared, signature=bad))
    elif variant == "foreign-signed-attrs":
        other = load_prepared(
            env, repository(env).get(prepare(service(env, clock=clock), pki, pdf).record.preparation_id)
        )
        signed = run(forge_signed_pdf(prepared, signature=sig, signed_attrs_der=other.signed_attrs_der))
    elif variant == "other-certificate":
        signed = run(forge_signed_pdf(prepared, signature=sig, certificate_der=pki.other_signer.der))
    else:
        signed = run(forge_signed_pdf(prepared, signature=os.urandom(256)))
    _plant(env, r.preparation_id, signed)
    clock.advance(61)
    fresh = service(env, clock=clock)
    assert run(fresh.recover_stale()) == []
    assert fresh.get(r.preparation_id).record.status is PreparationStatus.COMPLETING


def test_rev05_valid_artifact_not_matching_the_claimed_binding_is_not_adopted(
    tmp_path: Path, pki: LabPki, pdf: bytes
) -> None:
    env, clock = engine_env(tmp_path / "engine"), FakeClock()
    svc = service(env, clock=clock)
    view = prepare(svc, pki, pdf)
    sig = sign_view(pki.signer, view)
    pid = view.record.preparation_id
    now = clock.now()
    fake_binding = completion_binding(
        pid, ATTEMPT_ID, view.record.certificate_sha256, "SHA-256", ALG, b"another-signature"
    )
    repository(env).claim_completion(
        pid,
        binding=fake_binding,
        attempt_id=ATTEMPT_ID,
        owner="x",
        now=now,
        lease_until=now,
        deadline=now + dt.timedelta(hours=1),
    )
    prepared = load_prepared(env, repository(env).get(pid))
    genuine = run(
        complete_external_signature(
            prepared, signature=sig, signature_algorithm=ALG, certificate_sha256=prepared.certificate_sha256
        )
    )
    _plant(env, pid, genuine)
    clock.advance(1)
    assert run(service(env, clock=clock).recover_stale()) == []


# ---------------------------------------------------------------------------------- REV-06


def test_rev06_stale_token_and_expired_lease_cannot_commit(tmp_path: Path, pki: LabPki, pdf: bytes) -> None:
    env = engine_env(tmp_path / "engine")
    view = prepare(service(env), pki, pdf)
    repo, pid = repository(env), view.record.preparation_id
    now = view.record.created_at
    far = now + dt.timedelta(hours=1)
    first = repo.claim_completion(
        pid,
        binding="b",
        attempt_id=ATTEMPT_ID,
        owner="A",
        now=now,
        lease_until=now + dt.timedelta(seconds=10),
        deadline=far,
    )
    from signport_engine.persistence.repository import ArtifactInfo

    art = ArtifactInfo("artifacts/x/y.bin", "0" * 64, 1, "k1")
    with pytest.raises(EngineError):  # lease expired, no takeover yet: the old owner may NOT commit
        repo.mark_completed(
            pid,
            token=first.token,
            binding="b",
            artifact=art,
            deadline=far,
            now=now + dt.timedelta(seconds=11),
        )
    later = now + dt.timedelta(seconds=11)
    second = repo.claim_completion(
        pid,
        binding="b",
        attempt_id=ATTEMPT_ID,
        owner="B",
        now=later,
        lease_until=later + dt.timedelta(seconds=10),
        deadline=far,
    )
    assert second.kind is ClaimKind.TAKEN_OVER
    for token in (first.token, FencingToken("B", first.token.state_version)):  # old owner / stale version
        with pytest.raises(EngineError):
            repo.mark_completed(pid, token=token, binding="b", artifact=art, deadline=far, now=later)
    assert (
        repo.mark_completed(
            pid, token=second.token, binding="b", artifact=art, deadline=far, now=later
        ).status
        is PreparationStatus.COMPLETED
    )


def test_rev06_sigstop_takeover_sigcont_cannot_replace_the_result(
    tmp_path: Path, pki: LabPki, pdf: bytes
) -> None:
    env = engine_env(tmp_path / "engine", ENGINE_COMPLETION_LEASE_SECONDS="5", ENGINE_COMPLETION_WAIT_MS="0")
    view = prepare(service(env), pki, pdf)
    sig, pid = sign_view(pki.signer, view), view.record.preparation_id
    reached, resume, q = CTX.Event(), CTX.Event(), CTX.Queue()
    p = CTX.Process(
        target=workers.stall_worker,
        args=(env, pid, ATTEMPT_ID, sig, view.record.certificate_sha256, "after_claim", reached, resume, q),
    )
    p.start()
    assert reached.wait(120)
    os.kill(p.pid or 0, signal.SIGSTOP)
    try:
        time.sleep(5.5)  # the stopped process's lease expires
        done = complete(service(env), view, sig)  # takeover by a live process
        assert done.record.status is PreparationStatus.COMPLETED
        committed_version = done.record.state_version
    finally:
        os.kill(p.pid or 0, signal.SIGCONT)
        resume.set()
    status, sha, _ = q.get(timeout=120)
    p.join(60)
    assert status == "ok"
    assert sha == done.record.artifact_sha256  # it gets the existing result
    final = service(env).get(pid).record
    assert final.state_version == committed_version  # the stale process committed nothing
    assert len(list((Path(env["ENGINE_DATA_DIR"]) / "artifacts").rglob("*.bin"))) == 1


# ---------------------------------------------------------------------------------- REV-07


def test_rev07_reference_is_removed_before_the_file(
    tmp_path: Path, pki: LabPki, pdf: bytes, monkeypatch: pytest.MonkeyPatch
) -> None:
    from signport_engine.storage.blobs import EncryptedBlobStore

    env, clock = engine_env(tmp_path / "engine", ENGINE_ORPHAN_GRACE_SECONDS="0"), FakeClock()
    svc = service(env, clock=clock)
    view = prepare(svc, pki, pdf)
    svc.cancel(view.record.preparation_id)
    real_delete = EncryptedBlobStore.delete

    def crash(*_a: object) -> None:
        raise SimulatedCrash("delete")

    monkeypatch.setattr(EncryptedBlobStore, "delete", crash)
    with pytest.raises(SimulatedCrash):
        service(env, clock=clock).cleanup()
    monkeypatch.setattr(EncryptedBlobStore, "delete", real_delete)
    record = repository(env).get(view.record.preparation_id)
    assert record.prepared_blob is None  # no persistent reference to a file about to be removed
    path = Path(env["ENGINE_DATA_DIR"]) / "prepared" / f"{view.record.preparation_id}.bin"
    assert path.exists()  # unreferenced leftover...
    service(env, clock=clock).cleanup()
    assert not path.exists()  # ...removed by the next run under the reference check


def test_rev07_selection_does_not_starve(tmp_path: Path, pki: LabPki, pdf: bytes) -> None:
    env, clock = engine_env(tmp_path / "engine"), FakeClock()
    svc = service(env, clock=clock)
    for _ in range(4):
        svc.cancel(prepare(svc, pki, pdf).record.preparation_id)
    svc.cleanup(limit=10)  # already discarded rows must not occupy later batches
    fresh = [prepare(svc, pki, pdf).record.preparation_id for _ in range(2)]
    for pid in fresh:
        svc.cancel(pid)
    assert svc.cleanup(limit=2)["discarded"] == 2
    assert all(repository(env).get(pid).prepared_blob is None for pid in fresh)


def test_rev07_cleanup_concurrent_with_prepare_complete_and_recovery(
    tmp_path: Path, pki: LabPki, pdf: bytes
) -> None:
    env = engine_env(tmp_path / "engine", ENGINE_ORPHAN_GRACE_SECONDS="0")
    svc = service(env)
    ready, stop, q = CTX.Event(), CTX.Event(), CTX.Queue()
    p = CTX.Process(target=workers.cleanup_loop_worker, args=(env, ready, stop, q))
    p.start()
    try:
        assert ready.wait(120)  # the cleanup loop is really running before the workload starts
        done = []
        for _ in range(6):
            view = prepare(svc, pki, pdf)
            done.append(complete(svc, view, sign_view(pki.signer, view)).record.preparation_id)
            run(svc.recover_stale())
    finally:
        stop.set()
    runs, errors = q.get(timeout=120)
    assert runs >= 1, errors
    p.join(60)
    for pid in done:  # nothing referenced was ever deleted underneath
        assert svc.read_artifact(pid)
    data = Path(env["ENGINE_DATA_DIR"])
    with raw_db(env) as conn:
        for (ref,) in conn.execute("SELECT prepared_blob FROM preparations WHERE prepared_blob IS NOT NULL"):
            assert (data / ref).exists()


# ---------------------------------------------------------------------------------- REV-08


def test_rev08_directories_and_fast_path_are_made_durable(
    tmp_path: Path, pki: LabPki, pdf: bytes, monkeypatch: pytest.MonkeyPatch
) -> None:
    import signport_engine.storage.blobs as blobs_module

    calls: list[str] = []
    real_dir, real_file = blobs_module.fsync_dir, blobs_module.fsync_file

    def spy_dir(path: Path) -> None:
        calls.append(f"dir:{Path(path).name}")
        real_dir(path)

    def spy_file(path: Path) -> None:
        calls.append(f"file:{Path(path).name}")
        real_file(path)

    monkeypatch.setattr(blobs_module, "fsync_dir", spy_dir)
    monkeypatch.setattr(blobs_module, "fsync_file", spy_file)
    env, clock = engine_env(tmp_path / "engine"), FakeClock()
    svc = service(env, clock=clock)
    view = prepare(svc, pki, pdf)
    calls.clear()
    complete(svc, view, sign_view(pki.signer, view))
    pid = view.record.preparation_id
    assert f"dir:{pid}" in calls  # the new artifacts/<pid>/ directory...
    assert "dir:artifacts" in calls  # ...and its parent entry
    store = blob_store(env)
    record = repository(env).get(pid)
    signed = svc.read_artifact(pid)
    calls.clear()
    assert record.artifact_ref is not None
    store.put(
        record.artifact_ref,
        EnvelopeKind.SIGNED_ARTIFACT,
        signed,
        artifact_aad(env, record, sha256_hex(signed)),
    )
    assert any(c.startswith("file:") for c in calls)  # the fast path fsyncs the existing file...
    assert f"dir:{pid}" in calls  # ...and its directory


def test_rev08_recovery_makes_the_artifact_durable_before_committing(
    tmp_path: Path, pki: LabPki, pdf: bytes, monkeypatch: pytest.MonkeyPatch
) -> None:
    from signport_engine.persistence.sqlite import SqlitePreparationRepository
    from signport_engine.storage.blobs import EncryptedBlobStore

    env, clock = engine_env(tmp_path / "engine"), FakeClock()
    view = prepare(service(env, clock=clock), pki, pdf)
    with pytest.raises(SimulatedCrash):
        complete(
            service(env, clock=clock, faults=CrashAt("after_artifact_write")),
            view,
            sign_view(pki.signer, view),
        )
    order: list[str] = []
    real_durable, real_mark = EncryptedBlobStore.ensure_durable, SqlitePreparationRepository.mark_completed

    def spy_durable(self: EncryptedBlobStore, rel: str) -> None:
        order.append("durable")
        real_durable(self, rel)

    def spy_mark(self: SqlitePreparationRepository, *a: Any, **k: Any) -> Any:
        order.append("commit")
        return real_mark(self, *a, **k)

    monkeypatch.setattr(EncryptedBlobStore, "ensure_durable", spy_durable)
    monkeypatch.setattr(SqlitePreparationRepository, "mark_completed", spy_mark)
    clock.advance(61)
    assert run(service(env, clock=clock).recover_stale()) == [view.record.preparation_id]
    assert order == ["durable", "commit"]


# ---------------------------------------------------------------------------------- REV-09


def test_rev09_claim_started_in_time_may_finish_within_grace_only(
    tmp_path: Path, pki: LabPki, pdf: bytes
) -> None:
    env, clock = engine_env(tmp_path / "engine", ENGINE_COMPLETION_WAIT_MS="0"), FakeClock()
    view, sig = _completing_with_crash(env, clock, pki, pdf)
    clock.advance(600 + 100)  # after expires_at, inside the 300 s grace
    assert complete(service(env, clock=clock), view, sig).record.status is PreparationStatus.COMPLETED

    other, sig2 = _completing_with_crash(env, clock, pki, pdf)
    clock.advance(600 + 300)  # at the deadline: no takeover, no completion
    with pytest.raises(EngineError) as err:
        complete(service(env, clock=clock), other, sig2)
    assert err.value.code is ErrorCode.PREPARATION_EXPIRED
    record = repository(env).get(other.record.preparation_id)
    assert (record.status, record.failure_reason) == (PreparationStatus.FAILED, "expired_during_completion")


def test_rev09_cleanup_fails_completions_past_the_deadline(tmp_path: Path, pki: LabPki, pdf: bytes) -> None:
    env, clock = engine_env(tmp_path / "engine"), FakeClock()
    view, _ = _completing_with_crash(env, clock, pki, pdf)
    clock.advance(600 + 300)
    assert service(env, clock=clock).cleanup()["failed_past_deadline"] == 1
    assert repository(env).get(view.record.preparation_id).status is PreparationStatus.FAILED


# ---------------------------------------------------------------------------------- REV-10


def test_rev10_premature_retirement_is_refused_and_history_is_kept(
    tmp_path: Path, pki: LabPki, pdf: bytes
) -> None:
    k1, k2 = new_key(), new_key()
    old = service(base_env(tmp_path, ENGINE_STATE_KEY_FILE=keyfile(tmp_path / "a.json", "k1", {"k1": k1})))
    view = prepare(old, pki, pdf)
    complete(old, view, sign_view(pki.signer, view))
    env2 = base_env(tmp_path, ENGINE_STATE_KEY_FILE=keyfile(tmp_path / "b.json", "k2", {"k1": k1, "k2": k2}))
    rotated = service(env2)
    with pytest.raises(ConfigurationError, match="still in use"):
        rotated.retire_key("k1")
    with pytest.raises(ConfigurationError, match="active key"):
        rotated.retire_key("k2")
    rotated.rewrap()
    rotated.retire_key("k1")
    assert repository(env2).registered_keys()["k1"] is not None  # history preserved
    assert rotated.read_artifact(view.record.preparation_id)
    with pytest.raises(ConfigurationError, match="retired"):
        service(
            base_env(tmp_path, ENGINE_STATE_KEY_FILE=keyfile(tmp_path / "c.json", "k1", {"k1": k1, "k2": k2}))
        )


def test_rev10_files_on_disk_count_as_key_usage(tmp_path: Path, pki: LabPki, pdf: bytes) -> None:
    k1, k2 = new_key(), new_key()
    old_env = base_env(tmp_path, ENGINE_STATE_KEY_FILE=keyfile(tmp_path / "a.json", "k1", {"k1": k1}))
    old = service(old_env)
    store = blob_store(old_env)
    from signport_engine.crypto.envelope import AadContext

    store.put(
        "prepared/01936f3c-0000-7000-8000-0000000000cd.bin",
        EnvelopeKind.PREPARED_PDF,
        b"orphan",
        AadContext(INSTANCE, "01936f3c-0000-7000-8000-0000000000cd", ()),
    )
    del old
    rotated = service(
        base_env(tmp_path, ENGINE_STATE_KEY_FILE=keyfile(tmp_path / "b.json", "k2", {"k1": k1, "k2": k2}))
    )
    assert "k1" in rotated.key_ids_in_use()  # not referenced by the DB, but still on disk
    with pytest.raises(ConfigurationError, match="still in use"):
        rotated.retire_key("k1")


def test_rev10_maintenance_is_exclusive_across_processes(tmp_path: Path, pki: LabPki, pdf: bytes) -> None:
    k1, k2 = new_key(), new_key()
    old = service(base_env(tmp_path, ENGINE_STATE_KEY_FILE=keyfile(tmp_path / "a.json", "k1", {"k1": k1})))
    for _ in range(2):
        prepare(old, pki, pdf)
    env2 = base_env(
        tmp_path,
        ENGINE_LOCK_TIMEOUT_MS="200",
        ENGINE_STATE_KEY_FILE=keyfile(tmp_path / "b.json", "k2", {"k1": k1, "k2": k2}),
    )
    svc = service(env2)  # opened (registry synced) before the maintenance starts
    reached, resume = CTX.Event(), CTX.Event()
    p = CTX.Process(target=workers.rewrap_hold_worker, args=(env2, reached, resume))
    p.start()
    try:
        assert reached.wait(120)
        with pytest.raises(EngineError) as opening:  # startup registry sync also waits for it
            service(env2)
        assert opening.value.code is ErrorCode.SERVICE_UNAVAILABLE
        for action in (lambda: svc.rewrap(), lambda: prepare(svc, pki, pdf), svc.cleanup):
            with pytest.raises(EngineError) as err:
                action()
            assert err.value.code is ErrorCode.SERVICE_UNAVAILABLE
    finally:
        resume.set()
        p.join(120)
    assert p.exitcode == 0
    assert service(env2).rewrap() >= 0
    assert service(env2).key_ids_in_use() == {"k2"}


def test_rev10_processes_with_an_outdated_keyring_stop_sealing(
    tmp_path: Path, pki: LabPki, pdf: bytes
) -> None:
    """A long-lived process keeps its keyring and reserved nonce blocks in memory. Once another
    process changes the registry, the stale process must not seal, authenticate or run
    maintenance until it is restarted with the new keyring (REV-16)."""
    k1, k2 = new_key(), new_key()
    old = service(base_env(tmp_path, ENGINE_STATE_KEY_FILE=keyfile(tmp_path / "a.json", "k1", {"k1": k1})))
    prepare(old, pki, pdf)  # warms an in-memory nonce block for k1
    rotated = service(
        base_env(tmp_path, ENGINE_STATE_KEY_FILE=keyfile(tmp_path / "b.json", "k2", {"k1": k1, "k2": k2}))
    )
    stale: list[Callable[[], object]] = [
        lambda: prepare(old, pki, pdf),
        old.cleanup,
        old.rewrap,
        lambda: old.retire_key("k2"),
        old.recover_after_restore,
    ]
    for action in stale:
        with pytest.raises(EngineError, match="keyring is outdated") as err:
            action()
        assert err.value.code is ErrorCode.SERVICE_UNAVAILABLE
    assert rotated.rewrap() == 1
    rotated.retire_key("k1")
    prepare(rotated, pki, pdf)  # the process that retired the key stays current
    for action in stale:
        with pytest.raises(EngineError, match="keyring is outdated"):
            action()
    # A restarted process holding only the retired key is refused at startup.
    with pytest.raises(ConfigurationError):
        service(base_env(tmp_path, ENGINE_STATE_KEY_FILE=keyfile(tmp_path / "c.json", "k1", {"k1": k1})))
    assert rotated.key_ids_in_use() == {"k2"}


def test_rev16_same_keyring_processes_must_restart_after_maintenance(
    tmp_path: Path, pki: LabPki, pdf: bytes
) -> None:
    """Detection uses the authenticated generation, not the set of key ids: a peer with the very
    same keyring is refused after another process retires a key, including for maintenance."""
    k1, k2 = new_key(), new_key()
    env = base_env(tmp_path, ENGINE_STATE_KEY_FILE=keyfile(tmp_path / "a.json", "k1", {"k1": k1}))
    prepare(service(env), pki, pdf)
    env2 = base_env(tmp_path, ENGINE_STATE_KEY_FILE=keyfile(tmp_path / "b.json", "k2", {"k1": k1, "k2": k2}))
    admin, peer = service(env2), service(env2)
    assert admin.rewrap() == 1
    admin.retire_key("k1")
    for action in (lambda: prepare(peer, pki, pdf), peer.rewrap, peer.recover_after_restore):
        with pytest.raises(EngineError, match="keyring is outdated"):
            action()
    prepare(service(env2), pki, pdf)  # restarted: current again


# ---------------------------------------------------------------------------------- REV-12


@pytest.fixture(scope="module")
def registry() -> Registry:
    docs = (json.loads(p.read_text()) for p in sorted((PROTOCOL_ROOT / "schemas").rglob("*.schema.json")))
    return Registry().with_resources(
        [(d["$id"], Resource.from_contents(d, default_specification=DRAFT202012)) for d in docs]
    )


def _valid(registry: Registry, ref: str, body: dict[str, Any]) -> None:
    v = Draft202012Validator({"$ref": "https://signport.invalid/schemas/v1/" + ref}, registry=registry)
    assert list(v.iter_errors(body)) == []


def test_rev12_contracts_hold_in_every_state_and_after_cleanup(
    tmp_path: Path, pki: LabPki, pdf: bytes, registry: Registry, monkeypatch: pytest.MonkeyPatch
) -> None:
    import signport_engine.service as service_module

    env, clock = engine_env(tmp_path / "engine", ENGINE_COMPLETION_WAIT_MS="0"), FakeClock()
    svc = service(env, clock=clock)
    ref = "engine/api.schema.json#/$defs/Preparation"
    prepared = prepare(svc, pki, pdf)
    cancelled = prepare(svc, pki, pdf)
    svc.cancel(cancelled.record.preparation_id)
    expired = prepare(svc, pki, pdf)
    completing, _ = _completing_with_crash(env, clock, pki, pdf)
    done = prepare(svc, pki, pdf)
    result = complete(svc, done, sign_view(pki.signer, done))
    _valid(registry, "engine/api.schema.json#/$defs/CompletePreparationResponse", result.to_p0())
    failed = prepare(svc, pki, pdf)

    async def overflow(*_a: object, **_k: object) -> bytes:
        raise EngineError(ErrorCode.CMS_RESERVATION_EXCEEDED, "simulated")

    monkeypatch.setattr(service_module, "complete_external_signature", overflow)
    with pytest.raises(EngineError):
        complete(svc, failed, sign_view(pki.signer, failed))
    monkeypatch.undo()
    clock.advance(601)
    svc.cleanup()  # expires, discards sensitive state
    statuses = set()
    for v in (prepared, cancelled, expired, completing, done, failed):
        body = svc.get(v.record.preparation_id).to_p0()
        statuses.add(body["status"])
        _valid(registry, ref, body)
    assert statuses == {"expired", "cancelled", "completing", "completed", "failed"}
    clock.advance(7 * 86400 + 1)
    svc.cleanup()  # artifact removal and purge: every remaining row still honours the contract
    with raw_db(env) as conn:
        remaining = [r[0] for r in conn.execute("SELECT preparation_id FROM preparations")]
    for pid in remaining:
        _valid(registry, ref, svc.get(pid).to_p0())


def test_rev12_retention_removal_differs_from_unexpected_loss(
    tmp_path: Path, pki: LabPki, pdf: bytes
) -> None:
    env = engine_env(tmp_path / "engine", ENGINE_TERMINAL_RETENTION_SECONDS="999999")
    clock = FakeClock()
    svc = service(env, clock=clock)
    kept, lost = prepare(svc, pki, pdf), prepare(svc, pki, pdf)
    for v in (kept, lost):
        complete(svc, v, sign_view(pki.signer, v))
    lost_ref = repository(env).get(lost.record.preparation_id).artifact_ref
    assert lost_ref is not None
    (Path(env["ENGINE_DATA_DIR"]) / lost_ref).unlink()
    with pytest.raises(EngineError) as err:
        svc.read_artifact(lost.record.preparation_id)
    assert err.value.code is ErrorCode.INTERNAL_ERROR  # unexpected loss = integrity failure
    clock.advance(7 * 86400 + 1)
    svc.cleanup()
    with pytest.raises(EngineError) as err:
        svc.read_artifact(kept.record.preparation_id)
    assert err.value.code is ErrorCode.NOT_FOUND  # removed by retention, reported as such
    assert svc.get(kept.record.preparation_id).record.artifact_removed_at is not None


# ---------------------------------------------------------------------------------- REV-13


def test_rev13_structural_binding_rejects_decoys_and_gap_changes(pki: LabPki, pdf: bytes) -> None:
    from signport_engine.pdf.external_signing import prepare_external_signature

    p = run(
        prepare_external_signature(
            pdf,
            expected_document_sha256=sha256_hex(pdf),
            certificate_der=pki.signer.der,
            chain_der=pki.chain_der,
        )
    )
    s, e, n = p.reserved_region_start, p.reserved_region_end, len(p.prepared_pdf)
    declared = f"/ByteRange [0 {s} {e} {n - e}]".encode()
    text = b"SignPort synthetic test document - not a real report"
    assert len(declared) <= len(text)
    assert p.prepared_pdf.count(text) == 1
    # Decoy with the CORRECT values inside a content stream (same length: offsets unchanged)...
    decoyed = p.prepared_pdf.replace(text, declared.ljust(len(text)), 1)
    bind_signature_field(decoyed, p.field_name, start=s, end=e)  # still bound to the real field
    # ...while the real signature dictionary declares something else (same width).
    real = f"{n - e}".encode()
    forged_value = (
        str(int(real) + 1).encode() if len(str(int(real) + 1)) == len(real) else str(int(real) - 1).encode()
    )
    idx = decoyed.rfind(b"/ByteRange")
    tampered = decoyed[:idx] + decoyed[idx:].replace(real + b"]", forged_value + b"]", 1)
    assert tampered.count(declared) == 1  # a raw-bytes search would still find a perfect match
    with pytest.raises(StateIntegrityError):
        bind_signature_field(tampered, p.field_name, start=s, end=e)
    non_hex_gap = p.prepared_pdf[: s + 3] + b"G" + p.prepared_pdf[s + 4 :]
    with pytest.raises(StateIntegrityError):
        bind_signature_field(non_hex_gap, p.field_name, start=s, end=e)
    # A hex change inside the gap stays structurally consistent with the field's own /Contents,
    # so the zero-placeholder check of the preparation bindings is what must reject it.
    import dataclasses

    hex_gap = p.prepared_pdf[: s + 3] + b"A" + p.prepared_pdf[s + 4 :]
    bind_signature_field(hex_gap, p.field_name, start=s, end=e)
    q = dataclasses.replace(p, prepared_pdf=hex_gap, prepared_pdf_sha256=sha256_hex(hex_gap))
    with pytest.raises(StateIntegrityError, match="placeholder"):
        verify_preparation_bindings(
            q,
            persisted_certificate_sha256=q.certificate_sha256,
            persisted_prepared_pdf_sha256=q.prepared_pdf_sha256,
            persisted_digest_algorithm="SHA-256",
            persisted_signature_algorithm=ALG,
            requested_certificate_sha256=q.certificate_sha256,
            requested_signature_algorithm=ALG,
            requested_digest_algorithm="SHA-256",
        )


# ---------------------------------------------------------------------------------- REV-14


def _with_whitespace(k: str) -> str:
    return k[:20] + " " + k[21:]


def _standard_alphabet(k: str) -> str:
    return "+" + k[1:]  # '+' / '/' belong to standard Base64, not base64url


def _non_canonical(k: str) -> str:
    return k[:-1] + chr(ord(k[-1]) + 1)  # same 32 bytes, non-zero unused trailing bits


def _double_padding(k: str) -> str:
    return k + "=="


@pytest.mark.parametrize("value", [_with_whitespace, _standard_alphabet, _non_canonical, _double_padding])
def test_rev14_strict_base64_key_configuration(tmp_path: Path, value: Callable[[str], str]) -> None:
    with pytest.raises(ConfigurationError):
        load_keyring({"ENGINE_STATE_KEY": value(new_key()), "ENGINE_STATE_KEY_ID": "k1"}, tmp_path, INSTANCE)


def test_rev14_keyring_is_immutable() -> None:
    raw = {"k1": base64.urlsafe_b64decode(new_key() + "=")}
    ring = Keyring("k1", raw, instance_id=INSTANCE)
    raw["k2"] = b"x" * 32  # mutating the caller's dict has no effect
    assert ring.key_ids == {"k1"}
    with pytest.raises(AttributeError):
        ring._active = "k2"  # type: ignore[misc]
    with pytest.raises(TypeError):
        ring._keys["k3"] = b"y" * 32  # type: ignore[index]


def test_rev14_startup_refuses_keyrings_missing_keys_used_by_data(
    tmp_path: Path, pki: LabPki, pdf: bytes
) -> None:
    k1, k2 = new_key(), new_key()
    old = service(base_env(tmp_path, ENGINE_STATE_KEY_FILE=keyfile(tmp_path / "a.json", "k1", {"k1": k1})))
    prepare(old, pki, pdf)
    with pytest.raises(ConfigurationError, match="missing from the keyring"):
        service(base_env(tmp_path, ENGINE_STATE_KEY_FILE=keyfile(tmp_path / "b.json", "k2", {"k2": k2})))


def test_rev14_read_artifact_decrypts_once(
    tmp_path: Path, pki: LabPki, pdf: bytes, monkeypatch: pytest.MonkeyPatch
) -> None:
    from signport_engine.crypto.envelope import EnvelopeCipher

    env = engine_env(tmp_path / "engine")
    svc = service(env)
    view = prepare(svc, pki, pdf)
    complete(svc, view, sign_view(pki.signer, view))
    calls: list[EnvelopeKind] = []
    real = EnvelopeCipher.open

    def spy_open(self: EnvelopeCipher, kind: EnvelopeKind, data: bytes, aad: Any) -> bytes:
        calls.append(kind)
        return real(self, kind, data, aad)

    monkeypatch.setattr(EnvelopeCipher, "open", spy_open)
    svc.read_artifact(view.record.preparation_id)
    assert calls == [EnvelopeKind.SIGNED_ARTIFACT]


def test_rev14_incompatible_pyhanko_version_is_rejected(
    tmp_path: Path, pki: LabPki, pdf: bytes, monkeypatch: pytest.MonkeyPatch
) -> None:
    import signport_engine.state.model as model

    env = engine_env(tmp_path / "engine")
    svc = service(env)
    monkeypatch.setattr(model, "current_pyhanko_version", lambda: "0.0.1")
    view = prepare(svc, pki, pdf)  # state records pyHanko 0.0.1
    monkeypatch.undo()
    with pytest.raises(EngineError) as err:
        complete(svc, view, sign_view(pki.signer, view))
    assert err.value.code is ErrorCode.CONFLICT
    assert svc.get(view.record.preparation_id).record.status is PreparationStatus.PREPARED


def test_rev14_corrupted_database_fails_closed(tmp_path: Path) -> None:
    env = engine_env(tmp_path / "engine")
    service(env)
    db = Path(env["ENGINE_DATA_DIR"]) / "engine.sqlite3"
    db.write_bytes(b"\x00" * 4096)
    with pytest.raises((StateIntegrityError, ConfigurationError, EngineError)):
        service(env)


def test_rev14_distinct_certificates_sharing_one_public_key(tmp_path: Path, pki: LabPki, pdf: bytes) -> None:
    twin = reissue_same_key(pki.signer, pki.intermediate)
    env = engine_env(tmp_path / "engine")
    svc = service(env)
    view = prepare(svc, pki, pdf)
    sig = sign_view(pki.signer, view)  # a valid signature for BOTH certificates' key
    with pytest.raises(EngineError) as err:
        complete(svc, view, sig, certificate_sha256=sha256_hex(twin.der))
    assert err.value.code is ErrorCode.CERTIFICATE_MISMATCH
    prepared = load_prepared(env, repository(env).get(view.record.preparation_id))
    import dataclasses

    swapped = dataclasses.replace(prepared, certificate_der=twin.der, certificate_sha256=sha256_hex(twin.der))
    with pytest.raises(EngineError) as err:
        verify_preparation_bindings(
            swapped,
            persisted_certificate_sha256=swapped.certificate_sha256,
            persisted_prepared_pdf_sha256=swapped.prepared_pdf_sha256,
            persisted_digest_algorithm="SHA-256",
            persisted_signature_algorithm=ALG,
            requested_certificate_sha256=swapped.certificate_sha256,
            requested_signature_algorithm=ALG,
            requested_digest_algorithm="SHA-256",
        )
    assert err.value.code is ErrorCode.CERTIFICATE_MISMATCH  # signingCertificateV2 pins the original
    assert complete(svc, view, sig).record.status is PreparationStatus.COMPLETED


def test_rev07_create_refuses_to_reference_a_blob_whose_intent_was_reclaimed(
    tmp_path: Path, pki: LabPki, pdf: bytes
) -> None:
    """Regression for the race found while testing REV-07: a slow prepare must fail, never dangle."""
    import dataclasses

    env = engine_env(tmp_path / "engine")
    svc = service(env)
    template = prepare(svc, pki, pdf).record
    repo = repository(env)
    pid = "01936f3c-0000-7000-8000-0000000000ef"
    ref = f"prepared/{pid}.bin"
    now = dt.datetime(2026, 11, 27, 12, 0, tzinfo=dt.UTC)
    repo.register_intent(ref, now=now)
    deleted: list[str] = []
    assert repo.delete_if_unreferenced(
        ref, intent_older_than=now + dt.timedelta(days=1), delete=deleted.append
    )
    record = dataclasses.replace(template, preparation_id=pid, prepared_blob=ref)
    with pytest.raises(EngineError) as err:
        repo.create(record, intent=ref)
    assert err.value.code is ErrorCode.SERVICE_UNAVAILABLE
    with pytest.raises(EngineError):
        repo.get(pid)  # nothing was created


# ---------------------------------------------------------------------------------- REV-15


def _retired_history(tmp_path: Path, pki: LabPki, pdf: bytes) -> tuple[str, str]:
    """k1 used, rotated to k2, rewrapped and retired; returns the k2-only keyring file and k2."""
    k1, k2 = new_key(), new_key()
    old = service(base_env(tmp_path, ENGINE_STATE_KEY_FILE=keyfile(tmp_path / "a.json", "k1", {"k1": k1})))
    prepare(old, pki, pdf)
    rotated = service(
        base_env(tmp_path, ENGINE_STATE_KEY_FILE=keyfile(tmp_path / "b.json", "k2", {"k1": k1, "k2": k2}))
    )
    assert rotated.rewrap() == 1
    rotated.retire_key("k1")
    return keyfile(tmp_path / "c.json", "k2", {"k2": k2}), k2


def test_rev15_history_stays_authenticated_after_the_old_material_is_gone(
    tmp_path: Path, pki: LabPki, pdf: bytes
) -> None:
    only_new, _ = _retired_history(tmp_path, pki, pdf)
    env = base_env(tmp_path, ENGINE_STATE_KEY_FILE=only_new)
    svc = service(env)  # k1's material is no longer configured, yet its history verifies
    state = repository(env).registry_state()
    assert set(state.keys) == {"k1", "k2"}
    assert state.keys["k1"] is not None
    assert state.keys["k2"] is None
    assert state.active_key_id == "k2"
    prepare(svc, pki, pdf)


@pytest.mark.parametrize(
    "tamper",
    [
        "UPDATE key_registry SET retired_at = NULL WHERE key_id = 'k1'",
        "UPDATE key_registry SET first_seen_at = '2000-01-01T00:00:00Z' WHERE key_id = 'k1'",
        "DELETE FROM nonce_counters WHERE key_id = 'k1' AND purpose = 'state'",
        "DELETE FROM key_registry WHERE key_id = 'k1'",
        "INSERT INTO key_registry VALUES ('k7', 'f7', '2026-01-01T00:00:00Z', NULL, x'00')",
        "UPDATE engine_meta SET value = replace(value, '\"g\": 3', '\"g\": 4') WHERE key = 'key_catalog'",
        "DELETE FROM engine_meta WHERE key = 'key_catalog'",
    ],
)
def test_rev15_isolated_tampering_with_retired_history_fails_closed(
    tmp_path: Path, pki: LabPki, pdf: bytes, tamper: str
) -> None:
    only_new, _ = _retired_history(tmp_path, pki, pdf)
    env = base_env(tmp_path, ENGINE_STATE_KEY_FILE=only_new)
    svc = service(env)
    with raw_db(env) as conn:
        conn.execute("PRAGMA foreign_keys = OFF")
        assert conn.execute(tamper).rowcount == 1
    with pytest.raises(StateIntegrityError):
        service(env)  # a restarted process refuses to start
    with pytest.raises(EngineError) as err:  # a running one refuses to operate
        prepare(svc, pki, pdf)
    assert err.value.code in (ErrorCode.INTERNAL_ERROR, ErrorCode.SERVICE_UNAVAILABLE)


def test_rev15_catalog_generation_in_the_initial_state(tmp_path: Path) -> None:
    env = engine_env(tmp_path / "engine")
    service(env)
    state = repository(env).registry_state()
    assert (state.generation, state.active_key_id, dict(state.keys)) == (1, "k1", {"k1": None})


# ---------------------------------------------------------------------------------- REV-17


def test_rev17_registry_cannot_change_during_a_protected_operation(
    tmp_path: Path, pki: LabPki, pdf: bytes
) -> None:
    k1, k2 = new_key(), new_key()
    env = base_env(
        tmp_path,
        ENGINE_COMPLETION_LEASE_SECONDS="60",
        ENGINE_STATE_KEY_FILE=keyfile(tmp_path / "a.json", "k1", {"k1": k1}),
    )
    view = prepare(service(env), pki, pdf)
    sig, pid = sign_view(pki.signer, view), view.record.preparation_id
    reached, resume, q = CTX.Event(), CTX.Event(), CTX.Queue()
    p = CTX.Process(
        target=workers.stall_worker,
        args=(env, pid, ATTEMPT_ID, sig, view.record.certificate_sha256, "after_claim", reached, resume, q),
    )
    p.start()
    rotate = base_env(
        tmp_path,
        ENGINE_LOCK_TIMEOUT_MS="300",
        ENGINE_STATE_KEY_FILE=keyfile(tmp_path / "b.json", "k2", {"k1": k1, "k2": k2}),
    )
    try:
        assert reached.wait(120)  # the child holds the shared lock in the middle of complete()
        before = repository(env).registry_state()
        with pytest.raises(EngineError) as err:  # registering k2 needs effective exclusion
            service(rotate)
        assert err.value.code is ErrorCode.SERVICE_UNAVAILABLE
        assert repository(env).registry_state() == before  # nothing changed underneath the child
    finally:
        resume.set()
    assert q.get(timeout=120)[0] == "ok"
    p.join(60)
    assert p.exitcode == 0
    service(rotate)  # now the registry change goes through
    after = repository(rotate).registry_state()
    assert (after.generation, after.active_key_id) == (before.generation + 1, "k2")


def test_rev17_startup_with_an_unchanged_registry_is_read_only(tmp_path: Path) -> None:
    env = engine_env(tmp_path / "engine")
    service(env)
    with raw_db(env) as conn:
        before = conn.execute("SELECT value FROM engine_meta WHERE key = 'key_catalog'").fetchone()
    service(env)
    with raw_db(env) as conn:
        assert conn.execute("SELECT value FROM engine_meta WHERE key = 'key_catalog'").fetchone() == before


# ---------------------------------------------------------------------------------- REV-18


def test_rev18_counters_exist_from_key_registration(tmp_path: Path) -> None:
    env = engine_env(tmp_path / "engine")
    service(env)
    with raw_db(env) as conn:
        rows = sorted(conn.execute("SELECT key_id, purpose, next_counter FROM nonce_counters").fetchall())
    assert rows == [("k1", "artifact", 0), ("k1", "state", 0)]
    assert repository(env).nonce_key_ids() == set()  # registered, never used


def test_rev18_deleting_a_used_counter_never_restarts_the_sequence(
    tmp_path: Path, pki: LabPki, pdf: bytes
) -> None:
    env = engine_env(tmp_path / "engine")
    svc = service(env)
    prepare(svc, pki, pdf)  # state and artifact counters now advanced
    with raw_db(env) as conn:
        assert conn.execute("DELETE FROM nonce_counters WHERE purpose = 'state'").rowcount == 1
    with pytest.raises(StateIntegrityError, match="nonce counter is missing"):
        repository(env).reserve_nonce_block("k1", Purpose.STATE, 8)  # direct reservation
    with pytest.raises(StateIntegrityError):
        service(env)  # process restart
    with pytest.raises(EngineError) as err:  # running process with a warm in-memory block
        prepare(svc, pki, pdf)
    assert err.value.code is ErrorCode.INTERNAL_ERROR


# ---------------------------------------------------------------------------------- REV-19


def test_rev19_lease_never_outlives_the_deadline(tmp_path: Path, pki: LabPki, pdf: bytes) -> None:
    env = engine_env(tmp_path / "engine")
    view = prepare(service(env), pki, pdf)
    now = view.record.created_at
    deadline = now + dt.timedelta(seconds=30)
    claim = repository(env).claim_completion(
        view.record.preparation_id,
        binding="b",
        attempt_id=ATTEMPT_ID,
        owner="A",
        now=now,
        lease_until=now + dt.timedelta(hours=1),
        deadline=deadline,
    )
    assert claim.record.lease_expires_at == deadline


def test_rev19_commit_is_refused_at_the_deadline_even_with_a_live_lease(
    tmp_path: Path, pki: LabPki, pdf: bytes
) -> None:
    from signport_engine.persistence.repository import ArtifactInfo

    env = engine_env(tmp_path / "engine")
    svc = service(env)
    art = ArtifactInfo("artifacts/x/y.bin", "0" * 64, 1, "k1")
    repo = repository(env)
    for offset, ok in ((-1, True), (0, False)):
        view = prepare(svc, pki, pdf)
        pid, now = view.record.preparation_id, view.record.created_at
        claim = repo.claim_completion(
            pid,
            binding="b",
            attempt_id=ATTEMPT_ID,
            owner="A",
            now=now,
            lease_until=now + dt.timedelta(hours=1),
            deadline=now + dt.timedelta(hours=2),
        )
        deadline = now + dt.timedelta(seconds=10)  # tighter than the lease
        at = deadline + dt.timedelta(seconds=offset)
        if ok:
            done = repo.mark_completed(
                pid, token=claim.token, binding="b", artifact=art, deadline=deadline, now=at
            )
            assert done.status is PreparationStatus.COMPLETED
        else:
            with pytest.raises(EngineError) as err:
                repo.mark_completed(
                    pid, token=claim.token, binding="b", artifact=art, deadline=deadline, now=at
                )
            assert err.value.code is ErrorCode.CONFLICT


def test_rev19_time_is_read_after_waiting_for_the_write_lock(tmp_path: Path, pki: LabPki, pdf: bytes) -> None:
    """A claim that waited on SQLite's write lock past expires_at must see the late time."""
    env = engine_env(tmp_path / "engine")
    clock = FakeClock()
    view = prepare(service(env, clock=clock), pki, pdf)
    repo = repository(env, clock=clock)
    outcome: list[Any] = []
    blocker = sqlite3.connect(Path(env["ENGINE_DATA_DIR"]) / "engine.sqlite3", isolation_level=None)
    blocker.execute("BEGIN IMMEDIATE")

    def claimer() -> None:
        outcome.append(
            repo.claim_completion(
                view.record.preparation_id,
                binding="b",
                attempt_id=ATTEMPT_ID,
                owner="A",
                lease=dt.timedelta(seconds=60),
                deadline=view.record.expires_at + dt.timedelta(seconds=300),
            )
        )

    t = threading.Thread(target=claimer)
    t.start()
    time.sleep(0.5)  # the claim is now waiting for the write lock
    clock.current = view.record.expires_at + dt.timedelta(seconds=1)
    blocker.execute("COMMIT")
    blocker.close()
    t.join(30)
    assert outcome[0].kind is ClaimKind.EXPIRED
