# SPDX-License-Identifier: AGPL-3.0-or-later
"""E2 spike: interrupted PAdES signing with an external raw RSA signer."""

import ast
import dataclasses
import hashlib
import os
from collections.abc import Callable
from io import BytesIO
from pathlib import Path

import pytest
from asn1crypto import cms
from conftest import run
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, utils
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign.validation.status import SignatureCoverageLevel
from support.openssl import extract_last_signature, openssl_available, openssl_cms_verify
from support.pdfs import MALFORMED_PDF, NOT_A_PDF, encrypted_pdf
from support.pki import LabPki, make_crl, make_end_entity, make_root
from support.validation import validate_all

from signport_engine.errors import EngineError, ErrorCode
from signport_engine.pdf.external_signing import (
    PreparedSignature,
    complete_external_signature,
    prepare_external_signature,
    sha256_hex,
)

Prepare = Callable[..., PreparedSignature]
# In CI (SIGNPORT_REQUIRE_OPENSSL=1) a missing openssl must fail, never skip.
OPENSSL_RUNNABLE = openssl_available() or os.environ.get("SIGNPORT_REQUIRE_OPENSSL") == "1"
ALG = "RSA_PKCS1_V1_5"


def external_sign(pki: LabPki, prepared: PreparedSignature) -> bytes:
    """Simulates Desktop/Bird ID: SignHash over the CMS signed-attributes digest only."""
    return pki.signer.key.sign(
        prepared.signed_attributes_digest, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256())
    )


def complete(prepared: PreparedSignature, signature: bytes, **kw: str) -> bytes:
    args = {"signature_algorithm": ALG, "certificate_sha256": prepared.certificate_sha256} | kw
    return run(complete_external_signature(prepared, signature=signature, **args))


@pytest.fixture
def signed(pki: LabPki, prepare: Prepare) -> tuple[PreparedSignature, bytes]:
    prepared = prepare()
    return prepared, complete(prepared, external_sign(pki, prepared))


# ---------------------------------------------------------------- positive path


def test_three_digests_are_distinct(prepare: Prepare, pdf: bytes) -> None:
    p = prepare()
    assert p.document_sha256 == sha256_hex(pdf)
    values = {p.document_sha256, p.byte_range_digest.hex(), p.signed_attributes_digest.hex()}
    assert len(values) == 3
    assert len(p.byte_range_digest) == 32
    assert len(p.signed_attributes_digest) == 32


def test_preparation_is_incremental_and_does_not_touch_the_original(prepare: Prepare, pdf: bytes) -> None:
    p = prepare()
    assert p.prepared_pdf.startswith(pdf)  # incremental update appended after the original bytes
    assert b"/ByteRange" in p.prepared_pdf[len(pdf) :]
    assert p.reserved_hex_capacity > 0


def test_signed_attributes_follow_pades(prepare: Prepare) -> None:
    attrs = cms.CMSAttributes.load(prepare().signed_attrs_der)
    types = [a["type"].native for a in attrs]
    assert types == ["content_type", "message_digest", "signing_certificate_v2"]
    assert "signing_time" not in types  # PAdES: time goes to /M, not signingTime


def test_message_digest_attribute_is_the_byte_range_digest(prepare: Prepare) -> None:
    p = prepare()
    attrs = {a["type"].native: a["values"][0].native for a in cms.CMSAttributes.load(p.signed_attrs_der)}
    assert attrs["message_digest"] == p.byte_range_digest


def test_exact_signed_attributes_are_preserved_in_the_final_cms(
    signed: tuple[PreparedSignature, bytes],
) -> None:
    prepared, out = signed
    content = cms.ContentInfo.load(extract_last_signature(out).cms_der)
    signer_info = content["content"]["signer_infos"][0]
    assert signer_info["signed_attrs"].untag().dump() == prepared.signed_attrs_der
    # OID 1.2.840.113549.1.1.11 = sha256WithRSAEncryption, i.e. RSASSA-PKCS1-v1_5 (never PSS)
    assert signer_info["signature_algorithm"]["algorithm"].dotted == "1.2.840.113549.1.1.11"
    assert signer_info["digest_algorithm"]["algorithm"].native == "sha256"


def test_byte_range_is_unchanged_by_completion(signed: tuple[PreparedSignature, bytes]) -> None:
    prepared, out = signed
    br = extract_last_signature(out).byte_range
    assert br[0] == 0
    assert br[1] == prepared.reserved_region_start
    assert br[2] == prepared.reserved_region_end
    assert len(out) == len(prepared.prepared_pdf)
    assert out[: br[1]] == prepared.prepared_pdf[: br[1]]
    assert out[br[2] :] == prepared.prepared_pdf[br[2] :]


def test_pyhanko_validation_is_intact_valid_and_trusted(
    pki: LabPki, crls: list[x509.CertificateRevocationList], signed: tuple[PreparedSignature, bytes]
) -> None:
    (result,) = run(validate_all(signed[1], [pki.root.cert], crls))
    st = result.status
    assert st.intact
    assert st.valid
    assert st.trusted
    assert st.coverage is SignatureCoverageLevel.ENTIRE_FILE
    assert st.bottom_line


@pytest.mark.openssl
@pytest.mark.skipif(not OPENSSL_RUNNABLE, reason="openssl CLI not installed")
def test_independent_openssl_verification(
    pki: LabPki, signed: tuple[PreparedSignature, bytes], tmp_path: Path
) -> None:
    result = openssl_cms_verify(signed[1], pki.root.pem, tmp_path)
    assert result.returncode == 0, result.stderr
    assert "Verification successful" in result.stderr


# ---------------------------------------------------------------- negative: completion


def test_double_hashed_signature_is_rejected_at_completion(pki: LabPki, prepare: Prepare) -> None:
    p = prepare()
    double = pki.signer.key.sign(p.signed_attributes_digest, padding.PKCS1v15(), hashes.SHA256())
    with pytest.raises(EngineError) as err:
        complete(p, double)
    assert err.value.code is ErrorCode.SIGNATURE_INVALID


def test_signature_over_document_hash_is_rejected(pki: LabPki, prepare: Prepare) -> None:
    p = prepare()
    wrong = pki.signer.key.sign(
        bytes.fromhex(p.document_sha256), padding.PKCS1v15(), utils.Prehashed(hashes.SHA256())
    )
    with pytest.raises(EngineError) as err:
        complete(p, wrong)
    assert err.value.code is ErrorCode.SIGNATURE_INVALID


def test_signature_over_byte_range_digest_is_rejected(pki: LabPki, prepare: Prepare) -> None:
    p = prepare()
    wrong = pki.signer.key.sign(p.byte_range_digest, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256()))
    with pytest.raises(EngineError) as err:
        complete(p, wrong)
    assert err.value.code is ErrorCode.SIGNATURE_INVALID


def test_signature_from_another_key_is_rejected(pki: LabPki, prepare: Prepare) -> None:
    p = prepare()
    other = pki.other_signer.key.sign(
        p.signed_attributes_digest, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256())
    )
    with pytest.raises(EngineError) as err:
        complete(p, other)
    assert err.value.code is ErrorCode.SIGNATURE_INVALID


def test_divergent_certificate_fingerprint_is_rejected(pki: LabPki, prepare: Prepare) -> None:
    p = prepare()
    with pytest.raises(EngineError) as err:
        complete(p, external_sign(pki, p), certificate_sha256=sha256_hex(pki.other_signer.der))
    assert err.value.code is ErrorCode.CERTIFICATE_MISMATCH


def test_unsupported_algorithm_is_rejected_at_completion(pki: LabPki, prepare: Prepare) -> None:
    p = prepare()
    with pytest.raises(EngineError) as err:
        complete(p, external_sign(pki, p), signature_algorithm="RSA_PSS")
    assert err.value.code is ErrorCode.UNSUPPORTED_ALGORITHM


def test_tampered_prepared_document_is_rejected(pki: LabPki, prepare: Prepare) -> None:
    p = prepare()
    tampered = dataclasses.replace(p, prepared_pdf=p.prepared_pdf.replace(b"page 1", b"page 9", 1))
    with pytest.raises(EngineError) as err:
        complete(tampered, external_sign(pki, p))
    assert err.value.code is ErrorCode.INTERNAL_ERROR


def test_tampered_signed_attributes_are_rejected(pki: LabPki, prepare: Prepare) -> None:
    p = prepare()
    sig = external_sign(pki, p)
    der = bytearray(p.signed_attrs_der)
    der[-1] ^= 0x01
    with pytest.raises(EngineError) as err:
        complete(dataclasses.replace(p, signed_attrs_der=bytes(der)), sig)
    assert err.value.code is ErrorCode.SIGNATURE_INVALID


def test_signed_attributes_not_bound_to_the_byte_range_are_rejected(pki: LabPki, prepare: Prepare) -> None:
    """A validly signed attribute set whose messageDigest is not this preparation's ByteRange digest."""
    p = prepare()
    other = prepare()  # same input, different prepared bytes -> different ByteRange digest
    assert other.byte_range_digest != p.byte_range_digest
    mixed = dataclasses.replace(p, signed_attrs_der=other.signed_attrs_der)
    sig = pki.signer.key.sign(
        mixed.signed_attributes_digest, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256())
    )
    with pytest.raises(EngineError) as err:
        complete(mixed, sig)
    assert err.value.code is ErrorCode.INTERNAL_ERROR


def test_cms_larger_than_reservation_is_rejected(pki: LabPki, prepare: Prepare) -> None:
    p = prepare()
    small = dataclasses.replace(p, reserved_region_end=p.reserved_region_start + 1002)
    with pytest.raises(EngineError) as err:
        complete(small, external_sign(pki, p))
    assert err.value.code is ErrorCode.CMS_RESERVATION_EXCEEDED


# ---------------------------------------------------------------- negative: preparation


def test_document_hash_mismatch_is_rejected(prepare: Prepare) -> None:
    with pytest.raises(EngineError) as err:
        prepare(expected_document_sha256="0" * 64)
    assert err.value.code is ErrorCode.DOCUMENT_HASH_MISMATCH


@pytest.mark.parametrize("document", [MALFORMED_PDF, NOT_A_PDF], ids=["malformed", "not-a-pdf"])
def test_invalid_documents_are_rejected(prepare: Prepare, document: bytes) -> None:
    with pytest.raises(EngineError) as err:
        prepare(document)
    assert err.value.code is ErrorCode.DOCUMENT_INVALID


def test_encrypted_document_is_rejected(prepare: Prepare) -> None:
    document = encrypted_pdf()
    with pytest.raises(EngineError) as err:
        prepare(document)
    assert err.value.code is ErrorCode.DOCUMENT_INVALID


def test_oversized_document_is_rejected(prepare: Prepare, pdf: bytes) -> None:
    with pytest.raises(EngineError) as err:
        prepare(pdf, max_pdf_bytes=len(pdf) - 1)
    assert err.value.code is ErrorCode.DOCUMENT_INVALID


def test_invalid_certificate_der_is_rejected(prepare: Prepare) -> None:
    with pytest.raises(EngineError) as err:
        prepare(certificate_der=b"\x30\x03\x02\x01\x00")
    assert err.value.code is ErrorCode.CERTIFICATE_INVALID


def test_unsupported_algorithm_is_rejected_at_preparation(prepare: Prepare) -> None:
    with pytest.raises(EngineError) as err:
        prepare(digest_algorithm="SHA-1")
    assert err.value.code is ErrorCode.UNSUPPORTED_ALGORITHM


def test_preparation_is_deterministic_only_where_expected(prepare: Prepare) -> None:
    """Same input twice: document hash equal; prepared bytes may differ (IDs/times) and that is fine."""
    a, b = prepare(), prepare()
    assert a.document_sha256 == b.document_sha256
    assert a.certificate_sha256 == b.certificate_sha256


# ---------------------------------------------------------------- negative: post-signing validation


def test_modification_after_signing_breaks_integrity(
    pki: LabPki, crls: list[x509.CertificateRevocationList], signed: tuple[PreparedSignature, bytes]
) -> None:
    out = signed[1].replace(b"page 1", b"page 2", 1)
    (result,) = run(validate_all(out, [pki.root.cert], crls))
    assert not result.status.intact
    assert not result.status.bottom_line


@pytest.mark.openssl
@pytest.mark.skipif(not OPENSSL_RUNNABLE, reason="openssl CLI not installed")
def test_modification_after_signing_fails_openssl(
    pki: LabPki, signed: tuple[PreparedSignature, bytes], tmp_path: Path
) -> None:
    out = signed[1].replace(b"page 1", b"page 2", 1)
    assert openssl_cms_verify(out, pki.root.pem, tmp_path).returncode != 0


def test_incremental_update_after_signing_is_detected(
    pki: LabPki, crls: list[x509.CertificateRevocationList], signed: tuple[PreparedSignature, bytes]
) -> None:
    writer = IncrementalPdfFileWriter(BytesIO(signed[1]))
    writer.root["/SignPortSyntheticTamper"] = writer.root["/Pages"]
    writer.update_root()
    out = BytesIO()
    writer.write(out)
    (result,) = run(validate_all(out.getvalue(), [pki.root.cert], crls))
    assert result.status.intact  # the signed revision itself is untouched...
    assert (
        result.status.coverage is not SignatureCoverageLevel.ENTIRE_FILE
    )  # ...but no longer covers the file


def test_untrusted_root_is_not_trusted(
    crls: list[x509.CertificateRevocationList], signed: tuple[PreparedSignature, bytes]
) -> None:
    (result,) = run(validate_all(signed[1], [make_root("SYNTHETIC UNRELATED ROOT").cert], crls))
    assert result.status.intact
    assert not result.status.trusted
    assert not result.status.bottom_line


def test_revoked_signer_is_not_accepted(pki: LabPki, signed: tuple[PreparedSignature, bytes]) -> None:
    revoked = [make_crl(pki.root), make_crl(pki.intermediate, revoked=[pki.signer.cert])]
    (result,) = run(validate_all(signed[1], [pki.root.cert], revoked))
    assert result.status.intact
    assert not result.status.bottom_line


def test_missing_revocation_data_is_not_accepted(
    pki: LabPki, signed: tuple[PreparedSignature, bytes]
) -> None:
    (result,) = run(validate_all(signed[1], [pki.root.cert], []))
    assert not result.status.bottom_line


def test_legacy_hard_fail_mode_skips_crls_without_distribution_points(pki: LabPki, pdf: bytes) -> None:
    """Regression guard for the E2 finding: legacy 'hard-fail' (CHECK_IF_DECLARED) ignores
    supplied CRLs when the certificate declares no CRL distribution point, so a revoked
    signer passes. The strict 'require' policy rejects it."""
    bare = make_end_entity(pki.intermediate, "SYNTHETIC NO CRLDP", crl_dp=False)
    p = run(
        prepare_external_signature(
            pdf, expected_document_sha256=sha256_hex(pdf), certificate_der=bare.der, chain_der=pki.chain_der
        )
    )
    out = complete(
        p, bare.key.sign(p.signed_attributes_digest, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256()))
    )
    revoked = [make_crl(pki.root), make_crl(pki.intermediate, revoked=[bare.cert])]
    (legacy,) = run(validate_all(out, [pki.root.cert], revoked, revocation_mode="hard-fail"))
    (strict,) = run(validate_all(out, [pki.root.cert], revoked))
    assert legacy.status.bottom_line  # unsafe legacy behaviour: revoked certificate accepted
    assert not strict.status.bottom_line


def test_completion_uses_only_the_prepared_state(pki: LabPki, pdf: bytes) -> None:
    """Prepare with one call, complete with a reconstructed object built only from stored fields."""
    p = run(
        prepare_external_signature(
            pdf,
            expected_document_sha256=sha256_hex(pdf),
            certificate_der=pki.signer.der,
            chain_der=pki.chain_der,
        )
    )
    rebuilt = PreparedSignature(**{f.name: getattr(p, f.name) for f in dataclasses.fields(p)})
    out = complete(rebuilt, external_sign(pki, p))
    assert extract_last_signature(out).cms_der


# ---------------------------------------------------------------- independence of the OpenSSL path


def test_independent_extraction_covers_exactly_the_byte_range(
    signed: tuple[PreparedSignature, bytes],
) -> None:
    """SHA-256 of the bytes extracted WITHOUT pyHanko equals the messageDigest the CMS signs."""
    prepared, out = signed
    ex = extract_last_signature(out)
    a, b, c, d = ex.byte_range
    assert a == 0
    assert len(ex.signed_content) == b + d == len(out) - (c - b)
    assert hashlib.sha256(ex.signed_content).digest() == prepared.byte_range_digest


def test_openssl_helper_does_not_use_pyhanko() -> None:
    tree = ast.parse((Path(__file__).parents[1] / "support" / "openssl.py").read_text())
    imported = {
        (n.module or "") if isinstance(n, ast.ImportFrom) else alias.name
        for n in ast.walk(tree)
        if isinstance(n, ast.Import | ast.ImportFrom)
        for alias in n.names
    }
    assert not any(
        name.split(".")[0] in {"pyhanko", "pyhanko_certvalidator", "signport_engine"} for name in imported
    )


def test_independent_extraction_rejects_a_tampered_gap(signed: tuple[PreparedSignature, bytes]) -> None:
    prepared, out = signed
    start = prepared.reserved_region_start
    tampered = out[: start + 1] + b"Z" + out[start + 2 :]  # non-hex byte inside /Contents
    with pytest.raises(ValueError, match="gap"):
        extract_last_signature(tampered)
