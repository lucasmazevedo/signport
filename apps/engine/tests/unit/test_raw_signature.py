# SPDX-License-Identifier: AGPL-3.0-or-later
"""Raw RSA verification: SignHash semantics, no double hashing (SPEC §5)."""

import base64
import hashlib
import json
from collections.abc import Callable

import pytest
from conftest import PROTOCOL_ROOT
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils
from support.pki import LabPki, make_end_entity

from signport_engine.cms.raw_signature import (
    require_supported_algorithms,
    signed_attributes_digest,
    verify_raw_rsa_signature,
)
from signport_engine.errors import EngineError, ErrorCode

DATA = b"SYNTHETIC stand-in for DER signed attributes"


def sign_hash(pki: LabPki, digest: bytes) -> bytes:
    """What the Desktop does: RSA.SignHash(digest, SHA256, Pkcs1)."""
    return pki.signer.key.sign(digest, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256()))


def test_signhash_of_digest_verifies(pki: LabPki) -> None:
    verify_raw_rsa_signature(pki.signer.cert, DATA, sign_hash(pki, signed_attributes_digest(DATA)))


def test_double_hashed_signature_is_rejected(pki: LabPki) -> None:
    double = pki.signer.key.sign(signed_attributes_digest(DATA), padding.PKCS1v15(), hashes.SHA256())
    with pytest.raises(EngineError) as err:
        verify_raw_rsa_signature(pki.signer.cert, DATA, double)
    assert err.value.code is ErrorCode.SIGNATURE_INVALID


def _truncated(s: bytes) -> bytes:
    return s[:-1]


def _extended(s: bytes) -> bytes:
    return s + b"\x00"


def _bit_flip(s: bytes) -> bytes:
    return bytes([s[0] ^ 1]) + s[1:]


def _zeros(s: bytes) -> bytes:
    return bytes(len(s))


@pytest.mark.parametrize("mutate", [_truncated, _extended, _bit_flip, _zeros])
def test_tampered_signature_is_rejected(pki: LabPki, mutate: Callable[[bytes], bytes]) -> None:
    sig = mutate(sign_hash(pki, signed_attributes_digest(DATA)))
    with pytest.raises(EngineError) as err:
        verify_raw_rsa_signature(pki.signer.cert, DATA, sig)
    assert err.value.code is ErrorCode.SIGNATURE_INVALID


def test_signature_of_other_data_is_rejected(pki: LabPki) -> None:
    sig = sign_hash(pki, hashlib.sha256(b"other").digest())
    with pytest.raises(EngineError):
        verify_raw_rsa_signature(pki.signer.cert, DATA, sig)


def test_signature_by_other_key_is_rejected(pki: LabPki) -> None:
    sig = pki.other_signer.key.sign(
        signed_attributes_digest(DATA), padding.PKCS1v15(), utils.Prehashed(hashes.SHA256())
    )
    with pytest.raises(EngineError):
        verify_raw_rsa_signature(pki.signer.cert, DATA, sig)


def test_pss_signature_is_rejected(pki: LabPki) -> None:
    pss = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)
    sig = pki.signer.key.sign(signed_attributes_digest(DATA), pss, utils.Prehashed(hashes.SHA256()))
    with pytest.raises(EngineError):
        verify_raw_rsa_signature(pki.signer.cert, DATA, sig)


def test_short_rsa_key_is_rejected(pki: LabPki) -> None:
    weak = make_end_entity(pki.intermediate, "SYNTHETIC WEAK", bits=1024)
    sig = weak.key.sign(signed_attributes_digest(DATA), padding.PKCS1v15(), utils.Prehashed(hashes.SHA256()))
    with pytest.raises(EngineError) as err:
        verify_raw_rsa_signature(weak.cert, DATA, sig)
    assert err.value.code is ErrorCode.CERTIFICATE_INVALID


def test_non_rsa_certificate_is_rejected(pki: LabPki) -> None:
    ec_key = ec.generate_private_key(ec.SECP256R1())
    cert = (
        x509.CertificateBuilder()
        .subject_name(pki.signer.cert.subject)
        .issuer_name(pki.intermediate.cert.subject)
        .public_key(ec_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(pki.signer.cert.not_valid_before_utc)
        .not_valid_after(pki.signer.cert.not_valid_after_utc)
        .sign(pki.intermediate.key, hashes.SHA256())
    )
    with pytest.raises(EngineError) as err:
        verify_raw_rsa_signature(cert, DATA, b"\x00" * 64)
    assert err.value.code is ErrorCode.UNSUPPORTED_ALGORITHM


@pytest.mark.parametrize(
    ("digest", "signature"),
    [("SHA-1", "RSA_PKCS1_V1_5"), ("SHA-256", "RSA_PSS"), ("sha256", "RSA_PKCS1_V1_5")],
)
def test_only_sha256_pkcs1v15_is_accepted(digest: str, signature: str) -> None:
    with pytest.raises(EngineError) as err:
        require_supported_algorithms(digest, signature)
    assert err.value.code is ErrorCode.UNSUPPORTED_ALGORITHM


def test_p0_known_answer_vector_cross_language() -> None:
    """The P0 vector (generated with Node.js crypto) must behave identically here."""
    vec = json.loads((PROTOCOL_ROOT / "fixtures/v1/crypto/rsa-signhash.vector.json").read_text())
    key = serialization.load_der_public_key(base64.b64decode(vec["public_key_spki_der_b64"]))
    message = base64.b64decode(vec["message_b64"])
    assert base64.b64encode(signed_attributes_digest(message)).decode() == vec["digest_b64"]
    signature = base64.b64decode(vec["signature_b64"])
    double = base64.b64decode(vec["double_hashed_signature_b64"])
    assert isinstance(key, rsa.RSAPublicKey)
    key.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
    key.verify(
        signature, base64.b64decode(vec["digest_b64"]), padding.PKCS1v15(), utils.Prehashed(hashes.SHA256())
    )
    with pytest.raises(InvalidSignature):
        key.verify(double, message, padding.PKCS1v15(), hashes.SHA256())
