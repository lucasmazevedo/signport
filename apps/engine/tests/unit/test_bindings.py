# SPDX-License-Identifier: AGPL-3.0-or-later
"""One dedicated negative test per finalization binding check (plan P1 §12.1)."""

import dataclasses
import os
from collections.abc import Callable
from typing import Any

import pytest
from asn1crypto import cms
from conftest import run
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, utils
from support.forge import forge_signed_pdf
from support.pki import LabPki, make_end_entity

from signport_engine.cms.bindings import verify_preparation_bindings, verify_signed_artifact
from signport_engine.errors import EngineError, ErrorCode, StateIntegrityError
from signport_engine.pdf.byte_range import check_reserved_region
from signport_engine.pdf.external_signing import PreparedSignature, complete_external_signature, sha256_hex
from signport_engine.pdf.signature_field import bind_signature_field
from signport_engine.state.model import decode_state, encode_state

Prepare = Callable[..., PreparedSignature]
ALG = "RSA_PKCS1_V1_5"


def kwargs(p: PreparedSignature, **over: str) -> dict[str, Any]:
    base = {
        "persisted_certificate_sha256": p.certificate_sha256,
        "persisted_prepared_pdf_sha256": p.prepared_pdf_sha256,
        "persisted_digest_algorithm": "SHA-256",
        "persisted_signature_algorithm": ALG,
        "requested_certificate_sha256": p.certificate_sha256,
        "requested_signature_algorithm": ALG,
        "requested_digest_algorithm": "SHA-256",
    }
    return base | over


def test_valid_preparation_passes_all_checks(prepare: Prepare) -> None:
    p = prepare()
    region = verify_preparation_bindings(p, **kwargs(p))
    assert (region.start, region.end) == (p.reserved_region_start, p.reserved_region_end)


# 1. certificate fingerprint recomputed from the persisted certificate
def test_1_persisted_certificate_swapped(pki: LabPki, prepare: Prepare) -> None:
    p = prepare()
    swapped = dataclasses.replace(p, certificate_der=pki.other_signer.der)
    with pytest.raises(StateIntegrityError, match="fingerprint"):
        verify_preparation_bindings(swapped, **kwargs(p))


def test_1_requested_certificate_differs(pki: LabPki, prepare: Prepare) -> None:
    p = prepare()
    with pytest.raises(EngineError) as err:
        verify_preparation_bindings(
            p, **kwargs(p, requested_certificate_sha256=sha256_hex(pki.other_signer.der))
        )
    assert err.value.code is ErrorCode.CERTIFICATE_MISMATCH


# 2. signingCertificateV2 must reference exactly the certificate
def test_2_signing_certificate_v2_references_another_certificate(pki: LabPki, prepare: Prepare) -> None:
    p, other = prepare(), prepare(certificate_der=pki.other_signer.der)
    mixed = dataclasses.replace(
        other, signed_attrs_der=_replace_scv2(other.signed_attrs_der, p.signed_attrs_der)
    )
    with pytest.raises((EngineError, StateIntegrityError)):
        verify_preparation_bindings(mixed, **kwargs(other))


def test_2_same_key_but_different_serial_is_rejected(pki: LabPki, prepare: Prepare) -> None:
    """A re-issued certificate (other serial) must not match the ESSCertIDv2 of the original."""
    p = prepare()
    twin = make_end_entity(pki.intermediate, "TITULAR SINTETICO DE TESTE")
    q = dataclasses.replace(p, certificate_der=twin.der, certificate_sha256=sha256_hex(twin.der))
    with pytest.raises(EngineError) as err:
        verify_preparation_bindings(q, **kwargs(q))
    assert err.value.code is ErrorCode.CERTIFICATE_MISMATCH


# 3. algorithms bound to the preparation
@pytest.mark.parametrize(
    "over",
    [
        {"requested_signature_algorithm": "RSA_PSS"},
        {"requested_digest_algorithm": "SHA-1"},
        {"persisted_signature_algorithm": "RSA_PSS"},
    ],
)
def test_3_algorithms(prepare: Prepare, over: dict[str, str]) -> None:
    p = prepare()
    with pytest.raises((EngineError, StateIntegrityError)):
        verify_preparation_bindings(p, **kwargs(p, **over))


# 4. reserved region offsets
@pytest.mark.parametrize(
    "shift",
    [(0, 1), (1, 0), (-1, 0), (0, -1), (0, 10**9)],
    ids=["end+1", "start+1", "start-1", "end-1", "end-out-of-file"],
)
def test_4_offsets(prepare: Prepare, shift: tuple[int, int]) -> None:
    p = prepare()
    bad = dataclasses.replace(
        p,
        reserved_region_start=p.reserved_region_start + shift[0],
        reserved_region_end=p.reserved_region_end + shift[1],
    )
    with pytest.raises(StateIntegrityError):
        verify_preparation_bindings(bad, **kwargs(p))


def test_4_placeholder_must_be_zero_filled(prepare: Prepare) -> None:
    p = prepare()
    pdf = bytearray(p.prepared_pdf)
    pdf[p.reserved_region_start + 5] = ord("A")
    with pytest.raises(StateIntegrityError, match="zero-filled"):
        check_reserved_region(bytes(pdf), p.reserved_region_start, p.reserved_region_end, placeholder=True)


# 5. persisted offsets == /ByteRange written in the file
def test_5_declared_byte_range_must_match(prepare: Prepare) -> None:
    p = prepare()
    region = check_reserved_region(
        p.prepared_pdf, p.reserved_region_start, p.reserved_region_end, placeholder=True
    )
    bind_signature_field(p.prepared_pdf, p.field_name, start=region.start, end=region.end)
    tampered = p.prepared_pdf.replace(b"/ByteRange [", b"/ByteRange [1 ", 1)
    with pytest.raises(StateIntegrityError):
        bind_signature_field(tampered, p.field_name, start=region.start, end=region.end)
    with pytest.raises(StateIntegrityError, match="not found"):
        bind_signature_field(p.prepared_pdf, "OtherField", start=region.start, end=region.end)


# 6. recomputed ByteRange digest
def test_6_persisted_byte_range_digest_differs(prepare: Prepare) -> None:
    p = prepare()
    with pytest.raises(StateIntegrityError, match="ByteRange digest"):
        verify_preparation_bindings(dataclasses.replace(p, byte_range_digest=bytes(32)), **kwargs(p))


def test_6_covered_byte_changed(prepare: Prepare) -> None:
    p = prepare()
    pdf = p.prepared_pdf.replace(b"page 1", b"page 7", 1)
    q = dataclasses.replace(p, prepared_pdf=pdf, prepared_pdf_sha256=sha256_hex(pdf))
    with pytest.raises(StateIntegrityError, match="ByteRange digest"):
        verify_preparation_bindings(q, **kwargs(q))


# 7. messageDigest == recomputed digest
def test_7_message_digest_not_bound(prepare: Prepare) -> None:
    p, other = prepare(), prepare()
    with pytest.raises(StateIntegrityError, match="messageDigest"):
        verify_preparation_bindings(
            dataclasses.replace(p, signed_attrs_der=other.signed_attrs_der), **kwargs(p)
        )


def test_prepared_pdf_hash_is_recomputed(prepare: Prepare) -> None:
    p = prepare()
    with pytest.raises(StateIntegrityError, match="prepared document"):
        verify_preparation_bindings(p, **kwargs(p, persisted_prepared_pdf_sha256="0" * 64))


# 8. no covered byte modified by finalization
def test_8_finalization_output_checks(pki: LabPki, prepare: Prepare) -> None:
    p = prepare()
    region = verify_preparation_bindings(p, **kwargs(p))
    sig = pki.signer.key.sign(
        p.signed_attributes_digest, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256())
    )
    signed = run(
        complete_external_signature(
            p, signature=sig, signature_algorithm=ALG, certificate_sha256=p.certificate_sha256
        )
    )
    verify_signed_artifact(p, region, signed, expected_signature_sha256=None)
    for bad in (
        signed + b"\n",
        signed.replace(b"page 1", b"page 3", 1),
        signed[: region.start + 1] + b"G" + signed[region.start + 2 :],
    ):
        with pytest.raises(StateIntegrityError):
            verify_signed_artifact(p, region, bad, expected_signature_sha256=None)


def test_8_cms_signature_value_is_verified(pki: LabPki, prepare: Prepare) -> None:
    """Every other field is authentic; only the RSA signature value is wrong (REV-05)."""
    p = prepare()
    region = verify_preparation_bindings(p, **kwargs(p))
    for bad_sig in (
        os.urandom(256),
        pki.other_signer.key.sign(
            p.signed_attributes_digest, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256())
        ),
    ):
        forged = run(forge_signed_pdf(p, signature=bad_sig))
        with pytest.raises(StateIntegrityError):
            verify_signed_artifact(p, region, forged, expected_signature_sha256=None)


def _replace_scv2(target_der: bytes, source_der: bytes) -> bytes:
    target, source = cms.CMSAttributes.load(target_der), cms.CMSAttributes.load(source_der)
    scv2 = next(a for a in source if a["type"].native == "signing_certificate_v2")
    rebuilt = [a if a["type"].native != "signing_certificate_v2" else scv2 for a in target]
    return cms.CMSAttributes(rebuilt).dump()


# ------------------------------------------------------------------ state model (no pickle, strict)


def test_state_roundtrip(prepare: Prepare) -> None:
    p = prepare()
    decoded, pyhanko_version = decode_state(encode_state(p), p.prepared_pdf)
    assert decoded == p
    assert pyhanko_version == "0.38.2"


def _bad_schema(s: bytes) -> bytes:
    return s.replace(b'"schema":"', b'"schema":"x', 1)


def _extra_member(s: bytes) -> bytes:
    return s[:-1] + b',"extra":1}'


def _wrong_type(s: bytes) -> bytes:
    return s.replace(b'"reserved_region_start":', b'"reserved_region_start":"1","_x":', 1)


def _duplicate_member(s: bytes) -> bytes:
    return s.replace(b'{"byte_range_digest_b64"', b'{"field_name":"a","byte_range_digest_b64"', 1)


def _bad_base64(s: bytes) -> bytes:
    return s.replace(b'"certificate_der_b64":"', b'"certificate_der_b64":"!', 1)


def _bad_utf8(s: bytes) -> bytes:
    return b"\xff" + s


@pytest.mark.parametrize(
    "mutate", [_bad_schema, _extra_member, _wrong_type, _duplicate_member, _bad_base64, _bad_utf8]
)
def test_state_strict_parsing(prepare: Prepare, mutate: Callable[[bytes], bytes]) -> None:
    p = prepare()
    with pytest.raises(StateIntegrityError):
        decode_state(mutate(encode_state(p)), p.prepared_pdf)
