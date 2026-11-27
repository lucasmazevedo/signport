# SPDX-License-Identifier: AGPL-3.0-or-later
"""Verification of raw RSA signatures produced outside the Engine (SPEC §5 step 7).

The signer (Desktop ``SignHash``, Bird ID RAW) signs ``signed_attributes_digest`` =
SHA-256(DER of the CMS signed attributes, encoded as ``SET OF``). Verifying with
``cryptography`` over the DER bytes with SHA-256 is mathematically identical to
verifying ``SignHash(digest)``; a signature computed as ``SignData(digest)``
(double hashing) does not verify.
"""

import hashlib

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from signport_engine.errors import EngineError, ErrorCode

SUPPORTED_SIGNATURE_ALGORITHM = "RSA_PKCS1_V1_5"
SUPPORTED_DIGEST_ALGORITHM = "SHA-256"
MIN_RSA_BITS = 2048
MAX_RSA_BITS = 4096


def signed_attributes_digest(signed_attrs_der: bytes) -> bytes:
    """SHA-256 of the exact DER bytes that the external signer must sign."""
    return hashlib.sha256(signed_attrs_der).digest()


def require_supported_algorithms(digest_algorithm: str, signature_algorithm: str) -> None:
    if digest_algorithm != SUPPORTED_DIGEST_ALGORITHM or signature_algorithm != SUPPORTED_SIGNATURE_ALGORITHM:
        raise EngineError(ErrorCode.UNSUPPORTED_ALGORITHM, "Only SHA-256 with RSA_PKCS1_V1_5 is supported.")


def rsa_public_key(cert: x509.Certificate) -> rsa.RSAPublicKey:
    key = cert.public_key()
    if not isinstance(key, rsa.RSAPublicKey):
        raise EngineError(ErrorCode.UNSUPPORTED_ALGORITHM, "Signer certificate key is not RSA.")
    if not MIN_RSA_BITS <= key.key_size <= MAX_RSA_BITS:
        raise EngineError(ErrorCode.CERTIFICATE_INVALID, "RSA key size outside the supported range.")
    return key


def verify_raw_rsa_signature(cert: x509.Certificate, signed_attrs_der: bytes, signature: bytes) -> None:
    """Raise SIGNATURE_INVALID unless ``signature`` is RSASSA-PKCS1-v1_5/SHA-256 over ``signed_attrs_der``."""
    key = rsa_public_key(cert)
    if len(signature) != (key.key_size + 7) // 8:
        raise EngineError(ErrorCode.SIGNATURE_INVALID, "Signature length does not match the RSA modulus.")
    try:
        key.verify(signature, signed_attrs_der, padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature:
        raise EngineError(
            ErrorCode.SIGNATURE_INVALID, "Signature does not verify against the bound certificate."
        ) from None
