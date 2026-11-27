# SPDX-License-Identifier: AGPL-3.0-or-later
"""PreparationService: state machine, idempotency, conflicts, expiry, rotation, recovery, cleanup."""

import json
import os
from pathlib import Path
from typing import Any

import pytest
from conftest import PROTOCOL_ROOT, run
from cryptography import x509
from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012
from support.engine import (
    ALG,
    ATTEMPT_ID,
    DOCUMENT_VERSION_ID,
    OTHER_ATTEMPT_ID,
    FakeClock,
    engine_env,
    new_key,
    repository,
    service,
    sign_view,
)
from support.openssl import openssl_available, openssl_cms_verify
from support.pki import LabPki
from support.validation import validate_all

from signport_engine.errors import ConfigurationError, EngineError, ErrorCode
from signport_engine.pdf.external_signing import sha256_hex
from signport_engine.persistence.repository import PreparationStatus
from signport_engine.service import CompletionResult, PreparationService, PreparationView

OPENSSL_RUNNABLE = openssl_available() or os.environ.get("SIGNPORT_REQUIRE_OPENSSL") == "1"


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def env(tmp_path: Path) -> dict[str, str]:
    return engine_env(tmp_path / "engine")


@pytest.fixture
def svc(env: dict[str, str], clock: FakeClock) -> PreparationService:
    return service(env, clock=clock)


def prepare(svc: PreparationService, pki: LabPki, pdf: bytes, **kw: object) -> PreparationView:
    return run(
        svc.prepare(
            pdf,
            document_version_id=DOCUMENT_VERSION_ID,
            expected_document_sha256=sha256_hex(pdf),
            certificate_der=pki.signer.der,
            chain_der=pki.chain_der,
            policy="icpbr-pades-rb",
            **kw,  # type: ignore[arg-type]
        )
    )


def complete(
    svc: PreparationService, view: PreparationView, signature: bytes, attempt: str = ATTEMPT_ID, **kw: str
) -> CompletionResult:
    args = {"signature_algorithm": ALG, "certificate_sha256": view.record.certificate_sha256} | kw
    return run(svc.complete(view.record.preparation_id, attempt_id=attempt, signature=signature, **args))


def code_of(fn: object) -> ErrorCode:
    with pytest.raises(EngineError) as err:
        fn()  # type: ignore[operator]
    return err.value.code


# ---------------------------------------------------------------- happy path + P0 contracts


@pytest.fixture(scope="module")
def registry() -> Registry:
    resources = [
        (doc["$id"], Resource.from_contents(doc, default_specification=DRAFT202012))
        for doc in (
            json.loads(p.read_text()) for p in sorted((PROTOCOL_ROOT / "schemas").rglob("*.schema.json"))
        )
    ]
    return Registry().with_resources(resources)


def assert_schema(registry: Registry, ref: str, body: dict[str, Any]) -> None:
    v = Draft202012Validator({"$ref": "https://signport.invalid/schemas/v1/" + ref}, registry=registry)
    assert list(v.iter_errors(body)) == []


def test_prepare_complete_and_contracts(
    svc: PreparationService,
    pki: LabPki,
    pdf: bytes,
    registry: Registry,
    crls: list[x509.CertificateRevocationList],
    tmp_path: Path,
) -> None:
    view = prepare(svc, pki, pdf)
    assert view.record.status is PreparationStatus.PREPARED
    assert_schema(registry, "engine/api.schema.json#/$defs/Preparation", view.to_p0())
    result = complete(svc, view, sign_view(pki.signer, view))
    assert result.record.status is PreparationStatus.COMPLETED
    assert_schema(registry, "engine/api.schema.json#/$defs/CompletePreparationResponse", result.to_p0())
    assert_schema(
        registry, "engine/api.schema.json#/$defs/Preparation", svc.get(view.record.preparation_id).to_p0()
    )
    signed = svc.read_artifact(view.record.preparation_id)
    assert sha256_hex(signed) == result.record.artifact_sha256
    assert len(signed) == result.record.artifact_size
    (status,) = run(validate_all(signed, [pki.root.cert], crls))
    assert status.status.bottom_line
    if OPENSSL_RUNNABLE:
        assert openssl_cms_verify(signed, pki.root.pem, tmp_path).returncode == 0


def test_artifact_file_is_immutable_and_encrypted(
    svc: PreparationService, env: dict[str, str], pki: LabPki, pdf: bytes
) -> None:
    view = prepare(svc, pki, pdf)
    result = complete(svc, view, sign_view(pki.signer, view))
    path = Path(env["ENGINE_DATA_DIR"]) / str(result.record.artifact_ref)
    assert oct(path.stat().st_mode & 0o777) == "0o440"
    assert b"%PDF" not in path.read_bytes()


# ---------------------------------------------------------------- idempotency and conflicts


def test_valid_repetition_returns_the_existing_artifact(
    svc: PreparationService, pki: LabPki, pdf: bytes
) -> None:
    view = prepare(svc, pki, pdf)
    sig = sign_view(pki.signer, view)
    first, second = complete(svc, view, sig), complete(svc, view, sig)
    assert first.record.artifact_sha256 == second.record.artifact_sha256
    assert first.record.state_version == second.record.state_version


@pytest.mark.parametrize("change", ["attempt", "signature"])
def test_divergent_completion_is_a_conflict(
    svc: PreparationService, pki: LabPki, pdf: bytes, change: str
) -> None:
    view = prepare(svc, pki, pdf)
    complete(svc, view, sign_view(pki.signer, view))
    other_sig = sign_view(pki.signer, prepare(svc, pki, pdf))  # valid signature, other preparation
    if change == "attempt":
        assert (
            code_of(lambda: complete(svc, view, sign_view(pki.signer, view), attempt=OTHER_ATTEMPT_ID))
            is ErrorCode.CONFLICT
        )
    else:
        assert code_of(lambda: complete(svc, view, other_sig)) in {
            ErrorCode.CONFLICT,
            ErrorCode.SIGNATURE_INVALID,
        }


def test_invalid_signature_does_not_consume_the_preparation(
    svc: PreparationService, pki: LabPki, pdf: bytes
) -> None:
    view = prepare(svc, pki, pdf)
    bad = sign_view(pki.other_signer, view)
    assert code_of(lambda: complete(svc, view, bad)) is ErrorCode.SIGNATURE_INVALID
    record = svc.get(view.record.preparation_id).record
    assert record.status is PreparationStatus.PREPARED
    assert record.state_version == 1
    assert complete(svc, view, sign_view(pki.signer, view)).record.status is PreparationStatus.COMPLETED


@pytest.mark.parametrize(
    ("kw", "expected"),
    [
        ({"certificate_sha256": "0" * 64}, ErrorCode.CERTIFICATE_MISMATCH),
        ({"signature_algorithm": "RSA_PSS"}, ErrorCode.UNSUPPORTED_ALGORITHM),
    ],
)
def test_binding_mismatches_are_rejected_before_claim(
    svc: PreparationService, pki: LabPki, pdf: bytes, kw: dict[str, str], expected: ErrorCode
) -> None:
    view = prepare(svc, pki, pdf)
    assert code_of(lambda: complete(svc, view, sign_view(pki.signer, view), **kw)) is expected
    assert svc.get(view.record.preparation_id).record.status is PreparationStatus.PREPARED


def test_unknown_preparation(svc: PreparationService) -> None:
    assert code_of(lambda: svc.get("01936f3c-0000-7000-8000-00000000dead")) is ErrorCode.NOT_FOUND


# ---------------------------------------------------------------- expiry, cancel, reservation


def test_expired_preparation_cannot_be_completed(
    svc: PreparationService, clock: FakeClock, pki: LabPki, pdf: bytes
) -> None:
    view = prepare(svc, pki, pdf)
    clock.advance(601)
    assert code_of(lambda: complete(svc, view, sign_view(pki.signer, view))) is ErrorCode.PREPARATION_EXPIRED
    assert svc.get(view.record.preparation_id).record.status is PreparationStatus.EXPIRED
    assert code_of(lambda: complete(svc, view, sign_view(pki.signer, view))) is ErrorCode.PREPARATION_EXPIRED


def test_expiry_window_is_bounded(svc: PreparationService, clock: FakeClock, pki: LabPki, pdf: bytes) -> None:
    import datetime as dt

    for bad in (clock.current, clock.current + dt.timedelta(hours=2)):
        assert code_of(lambda bad=bad: prepare(svc, pki, pdf, expires_at=bad)) is ErrorCode.VALIDATION_FAILED


def test_cancel_rules(svc: PreparationService, pki: LabPki, pdf: bytes) -> None:
    view = prepare(svc, pki, pdf)
    assert svc.cancel(view.record.preparation_id).status is PreparationStatus.CANCELLED
    assert svc.cancel(view.record.preparation_id).status is PreparationStatus.CANCELLED  # idempotent
    assert code_of(lambda: complete(svc, view, sign_view(pki.signer, view))) is ErrorCode.CONFLICT
    done = prepare(svc, pki, pdf)
    complete(svc, done, sign_view(pki.signer, done))
    assert code_of(lambda: svc.cancel(done.record.preparation_id)) is ErrorCode.CONFLICT


def test_reservation_exceeded_fails_terminally(
    svc: PreparationService, pki: LabPki, pdf: bytes, monkeypatch: pytest.MonkeyPatch
) -> None:
    import signport_engine.service as service_module

    view = prepare(svc, pki, pdf)

    async def overflow(*_a: object, **_k: object) -> bytes:
        raise EngineError(ErrorCode.CMS_RESERVATION_EXCEEDED, "simulated")

    monkeypatch.setattr(service_module, "complete_external_signature", overflow)
    assert (
        code_of(lambda: complete(svc, view, sign_view(pki.signer, view)))
        is ErrorCode.CMS_RESERVATION_EXCEEDED
    )
    record = svc.get(view.record.preparation_id).record
    assert record.status is PreparationStatus.FAILED
    assert record.failure_reason == "cms_reservation_exceeded"


def test_policy_and_ids_are_validated(svc: PreparationService, pki: LabPki, pdf: bytes) -> None:
    def unsupported_policy() -> None:
        run(
            svc.prepare(
                pdf,
                document_version_id=DOCUMENT_VERSION_ID,
                expected_document_sha256=sha256_hex(pdf),
                certificate_der=pki.signer.der,
                chain_der=(),
                policy="pades-b",
            )
        )

    assert code_of(unsupported_policy) is ErrorCode.VALIDATION_FAILED
    view = prepare(svc, pki, pdf)
    with pytest.raises(ValueError, match="attempt_id"):
        complete(svc, view, sign_view(pki.signer, view), attempt="not-a-uuid")


# ---------------------------------------------------------------- keys: rotation, rewrap, restore recovery


def _keyfile(path: Path, active: str, keys: dict[str, str]) -> str:
    path.write_text(json.dumps({"active_key_id": active, "keys": keys}))
    path.chmod(0o600)
    return str(path)


def test_rotation_reads_old_data_and_rewrap_allows_retiring_the_old_key(
    tmp_path: Path, pki: LabPki, pdf: bytes
) -> None:
    k1, k2 = new_key(), new_key()
    base = {
        "ENGINE_DATA_DIR": str(tmp_path / "engine"),
        "ENGINE_INSTANCE_ID": engine_env(tmp_path)["ENGINE_INSTANCE_ID"],
    }
    old = service(base | {"ENGINE_STATE_KEY_FILE": _keyfile(tmp_path / "k1.json", "k1", {"k1": k1})})
    done = prepare(old, pki, pdf)
    complete(old, done, sign_view(pki.signer, done))
    pending = prepare(old, pki, pdf)

    rotated = service(
        base | {"ENGINE_STATE_KEY_FILE": _keyfile(tmp_path / "k12.json", "k2", {"k1": k1, "k2": k2})}
    )
    assert rotated.read_artifact(done.record.preparation_id)  # old artifact readable with previous key
    assert (
        complete(rotated, pending, sign_view(pki.signer, pending)).record.status
        is PreparationStatus.COMPLETED
    )
    assert rotated.rewrap() >= 2
    assert rotated.key_ids_in_use() == {"k2"}

    only_new = service(base | {"ENGINE_STATE_KEY_FILE": _keyfile(tmp_path / "k2.json", "k2", {"k2": k2})})
    assert only_new.read_artifact(done.record.preparation_id) == rotated.read_artifact(
        done.record.preparation_id
    )


def test_missing_old_key_fails_closed(tmp_path: Path, pki: LabPki, pdf: bytes) -> None:
    env1 = engine_env(tmp_path / "engine")
    view = prepare(service(env1), pki, pdf)
    env2 = env1 | {"ENGINE_STATE_KEY": new_key(), "ENGINE_STATE_KEY_ID": "k1"}  # same id, other material
    with pytest.raises(ConfigurationError, match="different key material"):  # refused at startup (REV-02)
        service(env2)
    assert service(env1).get(view.record.preparation_id).record.status is PreparationStatus.PREPARED


def test_restore_recovery_requires_a_fresh_key_and_invalidates_pending(
    tmp_path: Path, pki: LabPki, pdf: bytes
) -> None:
    k1, k2 = new_key(), new_key()
    base = {
        "ENGINE_DATA_DIR": str(tmp_path / "engine"),
        "ENGINE_INSTANCE_ID": engine_env(tmp_path)["ENGINE_INSTANCE_ID"],
    }
    svc1 = service(base | {"ENGINE_STATE_KEY_FILE": _keyfile(tmp_path / "a.json", "k1", {"k1": k1})})
    pending = prepare(svc1, pki, pdf)
    with pytest.raises(ConfigurationError, match="never-used"):
        svc1.recover_after_restore()
    svc2 = service(
        base | {"ENGINE_STATE_KEY_FILE": _keyfile(tmp_path / "b.json", "k2", {"k1": k1, "k2": k2})}
    )
    assert svc2.recover_after_restore() == [pending.record.preparation_id]
    record = svc2.get(pending.record.preparation_id).record
    assert record.status is PreparationStatus.FAILED
    assert record.failure_reason == "invalidated_after_restore"


# ---------------------------------------------------------------- cleanup


def test_cleanup_expires_discards_removes_and_purges(
    svc: PreparationService, env: dict[str, str], clock: FakeClock, pki: LabPki, pdf: bytes
) -> None:
    data = Path(env["ENGINE_DATA_DIR"])
    stale = prepare(svc, pki, pdf)
    done = prepare(svc, pki, pdf)
    complete(svc, done, sign_view(pki.signer, done))
    clock.advance(601)
    stats = svc.cleanup()
    assert stats["expired"] == 1
    assert stats["discarded"] == 2
    for pid in (stale.record.preparation_id, done.record.preparation_id):
        record = repository(env).get(pid)
        assert record.state_envelope is None
        assert record.prepared_blob is None
    assert not (data / "prepared" / f"{stale.record.preparation_id}.bin").exists()
    assert svc.read_artifact(done.record.preparation_id)  # artifact kept until its retention
    clock.advance(7 * 86400 + 1)
    stats = svc.cleanup()  # retention counts from terminal_at, not from the last change (REV-07)
    assert stats["artifacts_removed"] == 1
    assert stats["purged"] == 2
    assert code_of(lambda: svc.get(stale.record.preparation_id)) is ErrorCode.NOT_FOUND
    assert not list((data / "artifacts").rglob("*.bin"))
    assert not list((data / "prepared").glob("*.bin"))


def test_cleanup_removes_orphans_after_grace(svc: PreparationService, env: dict[str, str]) -> None:
    orphan = Path(env["ENGINE_DATA_DIR"]) / "prepared" / "01936f3c-0000-7000-8000-0000000000cc.bin"
    orphan.write_bytes(b"SPE1-orphan")
    tmp = Path(env["ENGINE_DATA_DIR"]) / "tmp" / "x.tmp"
    tmp.write_bytes(b"partial")
    assert svc.cleanup()["orphans_removed"] == 0  # within grace
    old = 1_000_000_000
    os.utime(orphan, (old, old))
    os.utime(tmp, (old, old))
    assert svc.cleanup()["orphans_removed"] == 2
    assert not orphan.exists()
    assert not tmp.exists()
