# SPDX-License-Identifier: AGPL-3.0-or-later
"""SQLite repository: pragmas, migrations, installation binding, integrity, no plaintext at rest."""

import contextlib
import shutil
import sqlite3
from collections.abc import Generator
from pathlib import Path

import pytest
from conftest import run
from support.engine import (
    DOCUMENT_VERSION_ID,
    INSTANCE_ID,
    FakeClock,
    cipher,
    engine_env,
    keyring,
    new_key,
    repository,
    service,
)
from support.pki import LabPki

from signport_engine.crypto.envelope import AadContext, EnvelopeKind
from signport_engine.errors import ConfigurationError, EngineError, ErrorCode, StateIntegrityError
from signport_engine.pdf.external_signing import sha256_hex
from signport_engine.persistence.sqlite import MIGRATIONS, ensure_local_filesystem
from signport_engine.service import PreparationService


def prepare(svc: PreparationService, pki: LabPki, pdf: bytes) -> str:
    view = run(
        svc.prepare(
            pdf,
            document_version_id=DOCUMENT_VERSION_ID,
            expected_document_sha256=sha256_hex(pdf),
            certificate_der=pki.signer.der,
            chain_der=pki.chain_der,
            policy="icpbr-pades-rb",
        )
    )
    return view.record.preparation_id


@pytest.fixture
def env(tmp_path: Path) -> dict[str, str]:
    return engine_env(tmp_path / "engine")


@contextlib.contextmanager
def db(env: dict[str, str]) -> Generator[sqlite3.Connection]:
    """Raw access as an attacker/operator would have it; always committed and closed."""
    conn = sqlite3.connect(Path(env["ENGINE_DATA_DIR"]) / "engine.sqlite3")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def test_pragmas_and_migrations(env: dict[str, str]) -> None:
    service(env)  # first start creates and migrates the database
    repo = repository(env)
    assert repo.pragmas() == {
        "secure_delete": 1,
        "journal_mode": "wal",
        "synchronous": 2,
        "foreign_keys": 1,
        "busy_timeout": 5000,
    }
    assert repo.schema_version() == len(MIGRATIONS)
    service(env)  # reopening applies nothing twice
    assert repo.schema_version() == len(MIGRATIONS)
    with db(env) as conn:
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {
        "preparations",
        "preparation_events",
        "nonce_counters",
        "engine_meta",
        "schema_migrations",
    } <= tables


def test_busy_timeout_is_configurable(tmp_path: Path) -> None:
    custom = engine_env(tmp_path / "e", ENGINE_SQLITE_BUSY_TIMEOUT_MS="1234")
    service(custom)
    assert repository(custom).pragmas()["busy_timeout"] == 1234


def test_installation_binding(env: dict[str, str]) -> None:
    service(env)
    with pytest.raises(ConfigurationError, match="ENGINE_INSTANCE_ID"):
        service(env | {"ENGINE_INSTANCE_ID": "01936f3c-0000-7000-8000-0000000000ff"})


def test_engine_refuses_to_start_without_valid_configuration(tmp_path: Path) -> None:
    good = engine_env(tmp_path / "e")
    for broken in (
        {k: v for k, v in good.items() if k != "ENGINE_STATE_KEY"},
        good | {"ENGINE_INSTANCE_ID": "not-a-uuid"},
        good | {"ENGINE_DATA_DIR": "relative/path"},
        good | {"ENGINE_SQLITE_BUSY_TIMEOUT_MS": "-1"},
    ):
        with pytest.raises(ConfigurationError):
            service(broken)


def test_network_filesystem_is_refused(tmp_path: Path) -> None:
    mountinfo = tmp_path / "mountinfo"
    mountinfo.write_text(f"36 1 0:30 / {tmp_path} rw,relatime - nfs4 server:/export rw\n")
    with pytest.raises(ConfigurationError, match="network filesystem"):
        ensure_local_filesystem(tmp_path, mountinfo)
    mountinfo.write_text(f"36 1 0:30 / {tmp_path} rw,relatime - ext4 /dev/sda1 rw\n")
    ensure_local_filesystem(tmp_path, mountinfo)


def test_no_plaintext_document_or_personal_data_at_rest(env: dict[str, str], pki: LabPki, pdf: bytes) -> None:
    svc = service(env)
    prepare(svc, pki, pdf)
    data_dir = Path(env["ENGINE_DATA_DIR"])
    everything = b"".join(p.read_bytes() for p in data_dir.rglob("*") if p.is_file())
    assert b"%PDF" not in everything
    assert pki.signer.der not in everything
    assert b"TITULAR SINTETICO" not in everything
    assert env["ENGINE_STATE_KEY"].encode() not in everything  # key never stored with data
    assert not list((data_dir / "tmp").iterdir())


def test_tampered_row_fails_closed(env: dict[str, str], pki: LabPki, pdf: bytes) -> None:
    svc = service(env)
    pid = prepare(svc, pki, pdf)
    with db(env) as conn:
        conn.execute(
            "UPDATE preparations SET expires_at = '2099-01-01T00:00:00Z' WHERE preparation_id = ?", (pid,)
        )
    with pytest.raises(EngineError) as err:
        svc.get(pid)
    assert err.value.code is ErrorCode.INTERNAL_ERROR


def test_partial_row_rollback_without_its_chain_fails_closed(
    env: dict[str, str], pki: LabPki, pdf: bytes
) -> None:
    """Restoring only an older row while its later events remain is detected by the event chain.

    This does NOT remove later events: a coordinated rollback of row AND chain is a documented
    residual risk (see test_rev04_coordinated_rollback_of_row_and_chain_passes_local_checks).
    """
    svc = service(env)
    pid = prepare(svc, pki, pdf)
    with db(env) as conn:
        old_row = conn.execute("SELECT * FROM preparations WHERE preparation_id = ?", (pid,)).fetchone()
    svc.cancel(pid)
    with db(env) as conn:  # restore only the row, keep the cancellation event
        cols = [d[1] for d in conn.execute("PRAGMA table_info(preparations)")]
        # Raw connection: foreign keys are off, so the later events survive the row swap.
        conn.execute("DELETE FROM preparations WHERE preparation_id = ?", (pid,))
        # Column names come from the schema itself (PRAGMA table_info), not from input.
        insert = f"INSERT INTO preparations ({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))})"  # noqa: S608
        conn.execute(insert, old_row)
    with pytest.raises(EngineError) as err:
        svc.get(pid)
    assert err.value.code is ErrorCode.INTERNAL_ERROR


def test_event_chain_tampering_fails_closed(env: dict[str, str], pki: LabPki, pdf: bytes) -> None:
    svc = service(env)
    pid = prepare(svc, pki, pdf)
    with db(env) as conn:
        conn.execute("UPDATE preparation_events SET reason = 'forged' WHERE preparation_id = ?", (pid,))
    with pytest.raises(EngineError):
        svc.get(pid)


def test_envelope_swapped_between_preparations_fails_closed(
    env: dict[str, str], pki: LabPki, pdf: bytes
) -> None:
    svc = service(env)
    a, b = prepare(svc, pki, pdf), prepare(svc, pki, pdf)
    with db(env) as conn:
        env_b = conn.execute(
            "SELECT state_envelope FROM preparations WHERE preparation_id = ?", (b,)
        ).fetchone()[0]
    # An attacker with DB write access could bypass the row MAC; the AEAD still binds the
    # envelope to its own preparation: b's envelope never opens under a's context.
    record_a = repository(env).get(a)
    aad_a = AadContext(
        INSTANCE_ID,
        a,
        (record_a.document_sha256, record_a.certificate_sha256, record_a.prepared_pdf_sha256),
    )
    with pytest.raises(StateIntegrityError, match="authentication failed"):
        cipher(env).open(EnvelopeKind.PREPARATION_STATE, env_b, aad_a)


def test_full_storage_restore_is_not_detectable_locally(
    env: dict[str, str], pki: LabPki, pdf: bytes, tmp_path: Path
) -> None:
    """Documented residual risk: a consistent restore of the whole data dir passes integrity checks."""
    svc = service(env)
    pid = prepare(svc, pki, pdf)
    snapshot = tmp_path / "snapshot"
    shutil.copytree(env["ENGINE_DATA_DIR"], snapshot)
    svc.cancel(pid)
    shutil.rmtree(env["ENGINE_DATA_DIR"])
    shutil.copytree(snapshot, env["ENGINE_DATA_DIR"])
    assert service(env).get(pid).record.status.value == "prepared"  # rolled back, undetected


def test_busy_database_is_reported_without_partial_state(
    env: dict[str, str], pki: LabPki, pdf: bytes
) -> None:
    svc = service(env | {"ENGINE_SQLITE_BUSY_TIMEOUT_MS": "100"})
    pid = prepare(svc, pki, pdf)
    blocker = sqlite3.connect(Path(env["ENGINE_DATA_DIR"]) / "engine.sqlite3", isolation_level=None)
    blocker.execute("BEGIN IMMEDIATE")
    try:
        with pytest.raises(EngineError) as err:
            svc.cancel(pid)
        assert err.value.code is ErrorCode.SERVICE_UNAVAILABLE
    finally:
        blocker.execute("ROLLBACK")
        blocker.close()
    assert svc.get(pid).record.status.value == "prepared"
    assert svc.cancel(pid).status.value == "cancelled"


def test_clock_is_injected(env: dict[str, str], pki: LabPki, pdf: bytes) -> None:
    clock = FakeClock()
    svc = service(env, clock=clock)
    view = svc.get(prepare(svc, pki, pdf))
    assert view.record.created_at == clock.current
    assert (view.record.expires_at - view.record.created_at).total_seconds() == 600


def test_key_material_never_in_repr(env: dict[str, str]) -> None:
    ring = keyring(env)
    assert env["ENGINE_STATE_KEY"] not in repr(ring)
    assert new_key() not in repr(ring)
