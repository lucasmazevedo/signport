# SPDX-License-Identifier: AGPL-3.0-or-later
"""Interrupted PAdES signing with an external raw RSA signer (SPEC §5, ENG-01/02/04).

prepare_external_signature():
    incremental update + CMS placeholder, ByteRange digest (messageDigest) and
    the exact DER signed attributes, frozen once.
complete_external_signature():
    verifies the raw signature over the frozen signed attributes BEFORE building
    the CMS, embeds it without touching the ByteRange, and re-checks the result.

The returned ``PreparedSignature`` holds only bytes and integers — no live pyHanko
objects — so P1/E3 can persist it in an explicit versioned format.
Scope limits of this module (P1/E2): no timestamps, no LTV/DSS (post-sign
instructions must be empty), no visual appearance, no signature policy (E7).
"""

import base64
import hashlib
from dataclasses import dataclass
from io import BytesIO
from typing import cast

from asn1crypto import algos, cms
from asn1crypto import x509 as asn1_x509
from cryptography import x509
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.misc import PdfError
from pyhanko.sign import fields, signers
from pyhanko.sign.signers.pdf_byterange import PreparedByteRangeDigest
from pyhanko.sign.signers.pdf_cms import ExternalSigner
from pyhanko.sign.signers.pdf_signer import PdfTBSDocument
from pyhanko_certvalidator.registry import SimpleCertificateStore

from signport_engine.cms.raw_signature import (
    SUPPORTED_DIGEST_ALGORITHM,
    SUPPORTED_SIGNATURE_ALGORITHM,
    require_supported_algorithms,
    rsa_public_key,
    signed_attributes_digest,
    verify_raw_rsa_signature,
)
from signport_engine.errors import EngineError, ErrorCode

DEFAULT_FIELD_NAME = "SignPortSignature1"
DEFAULT_MAX_PDF_BYTES = 20 * 1024 * 1024
_MD = "sha256"
# RSASSA-PKCS1-v1_5 with SHA-256 (OID 1.2.840.113549.1.1.11), never PSS.
_MECHANISM = algos.SignedDigestAlgorithm({"algorithm": "sha256_rsa"})


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


@dataclass(frozen=True, slots=True)
class PreparedSignature:
    """Everything needed to finish the signature later; immutable bytes/ints only."""

    field_name: str
    document_sha256: str  # hex, original PDF (audit)
    prepared_pdf: bytes  # incremental update with zero-filled /Contents placeholder
    prepared_pdf_sha256: str
    byte_range_digest: bytes  # messageDigest attribute value
    reserved_region_start: int
    reserved_region_end: int
    signed_attrs_der: bytes  # exact bytes to be signed (SET OF encoding)
    certificate_der: bytes
    chain_der: tuple[bytes, ...]
    certificate_sha256: str
    digest_algorithm: str = SUPPORTED_DIGEST_ALGORITHM
    signature_algorithm: str = SUPPORTED_SIGNATURE_ALGORITHM

    @property
    def signed_attributes_digest(self) -> bytes:
        return signed_attributes_digest(self.signed_attrs_der)

    @property
    def signed_attributes_digest_b64(self) -> str:
        return b64(self.signed_attributes_digest)

    @property
    def byte_range_digest_b64(self) -> str:
        return b64(self.byte_range_digest)

    @property
    def reserved_hex_capacity(self) -> int:
        return self.reserved_region_end - self.reserved_region_start - 2


def _load_certificates(
    certificate_der: bytes, chain_der: tuple[bytes, ...]
) -> tuple[x509.Certificate, asn1_x509.Certificate, list[asn1_x509.Certificate]]:
    try:
        crypto_cert = x509.load_der_x509_certificate(certificate_der)
        signer_cert = asn1_x509.Certificate.load(certificate_der)
        chain = [asn1_x509.Certificate.load(der) for der in chain_der]
        for c in (signer_cert, *chain):
            _ = c.native  # force full parse
    except Exception:  # noqa: BLE001 - any parse failure is a client error
        raise EngineError(ErrorCode.CERTIFICATE_INVALID, "Certificate or chain is not valid DER.") from None
    rsa_public_key(crypto_cert)
    return crypto_cert, signer_cert, chain


def _external_signer(
    signer_cert: asn1_x509.Certificate, chain: list[asn1_x509.Certificate], signature_value: bytes | int
) -> ExternalSigner:
    return ExternalSigner(
        signing_cert=signer_cert,
        cert_registry=SimpleCertificateStore.from_certs([signer_cert, *chain]),
        signature_value=signature_value,
        signature_mechanism=_MECHANISM,
    )


def _open_incremental(pdf: bytes) -> IncrementalPdfFileWriter:
    try:
        writer = IncrementalPdfFileWriter(BytesIO(pdf), strict=True)
    except (PdfError, ValueError, KeyError, TypeError):
        raise EngineError(ErrorCode.DOCUMENT_INVALID, "PDF is malformed or unsupported.") from None
    if writer.prev.encrypted:
        raise EngineError(ErrorCode.DOCUMENT_INVALID, "Encrypted PDFs are not supported.")
    return writer


async def prepare_external_signature(
    pdf: bytes,
    *,
    expected_document_sha256: str,
    certificate_der: bytes,
    chain_der: tuple[bytes, ...] = (),
    digest_algorithm: str = SUPPORTED_DIGEST_ALGORITHM,
    signature_algorithm: str = SUPPORTED_SIGNATURE_ALGORITHM,
    field_name: str = DEFAULT_FIELD_NAME,
    max_pdf_bytes: int = DEFAULT_MAX_PDF_BYTES,
) -> PreparedSignature:
    require_supported_algorithms(digest_algorithm, signature_algorithm)
    if len(pdf) > max_pdf_bytes:
        raise EngineError(ErrorCode.DOCUMENT_INVALID, "PDF exceeds the configured size limit.")
    document_sha256 = sha256_hex(pdf)
    if document_sha256 != expected_document_sha256:
        raise EngineError(
            ErrorCode.DOCUMENT_HASH_MISMATCH, "Stored document hash differs from the expected one."
        )

    crypto_cert, signer_cert, chain = _load_certificates(certificate_der, chain_der)
    modulus_bytes = (rsa_public_key(crypto_cert).key_size + 7) // 8
    ext_signer = _external_signer(signer_cert, chain, signature_value=modulus_bytes)

    pdf_signer = signers.PdfSigner(
        signers.PdfSignatureMetadata(
            field_name=field_name,
            md_algorithm=_MD,
            subfilter=fields.SigSeedSubFilter.PADES,
        ),
        signer=ext_signer,
    )
    writer = _open_incremental(pdf)
    try:
        prep_digest, tbs_document, output = await pdf_signer.async_digest_doc_for_signing(writer)
    except (PdfError, ValueError, KeyError, TypeError):
        raise EngineError(ErrorCode.DOCUMENT_INVALID, "PDF could not be prepared for signing.") from None
    if tbs_document.post_sign_instructions is not None:  # LTV/timestamps are out of P1 scope
        raise EngineError(ErrorCode.INTERNAL_ERROR, "Unexpected post-signing instructions.")

    signed_attrs = await ext_signer.signed_attrs(prep_digest.document_digest, _MD, use_pades=True)
    output.seek(0)
    prepared_pdf = output.read()
    return PreparedSignature(
        field_name=field_name,
        document_sha256=document_sha256,
        prepared_pdf=prepared_pdf,
        prepared_pdf_sha256=sha256_hex(prepared_pdf),
        byte_range_digest=prep_digest.document_digest,
        reserved_region_start=prep_digest.reserved_region_start,
        reserved_region_end=prep_digest.reserved_region_end,
        signed_attrs_der=signed_attrs.dump(),
        certificate_der=certificate_der,
        chain_der=chain_der,
        certificate_sha256=sha256_hex(certificate_der),
    )


async def complete_external_signature(
    prepared: PreparedSignature,
    *,
    signature: bytes,
    signature_algorithm: str,
    certificate_sha256: str,
    digest_algorithm: str = SUPPORTED_DIGEST_ALGORITHM,
) -> bytes:
    """Verify ``signature`` and return the signed PDF. Never regenerates signed attributes."""
    require_supported_algorithms(digest_algorithm, signature_algorithm)
    if certificate_sha256 != prepared.certificate_sha256:
        raise EngineError(
            ErrorCode.CERTIFICATE_MISMATCH, "Certificate differs from the one bound to the preparation."
        )
    if sha256_hex(prepared.prepared_pdf) != prepared.prepared_pdf_sha256:
        raise EngineError(ErrorCode.INTERNAL_ERROR, "Prepared document integrity check failed.")

    crypto_cert, signer_cert, chain = _load_certificates(prepared.certificate_der, prepared.chain_der)
    verify_raw_rsa_signature(crypto_cert, prepared.signed_attrs_der, signature)

    signed_attrs = cms.CMSAttributes.load(prepared.signed_attrs_der)
    message_digests = [a["values"][0].native for a in signed_attrs if a["type"].native == "message_digest"]
    if message_digests != [prepared.byte_range_digest]:
        raise EngineError(
            ErrorCode.INTERNAL_ERROR, "Signed attributes are not bound to the prepared ByteRange."
        )
    ext_signer = _external_signer(signer_cert, chain, signature_value=signature)
    sig_cms = await ext_signer.async_sign_prescribed_attributes(_MD, signed_attrs=signed_attrs)
    cms_der = sig_cms.dump()

    signed_data = cast(cms.SignedData, sig_cms["content"])
    signer_infos = cast(cms.SignerInfos, signed_data["signer_infos"])
    signer_info = cast(cms.SignerInfo, signer_infos[0])
    if signer_info["signed_attrs"].untag().dump() != prepared.signed_attrs_der:
        raise EngineError(ErrorCode.INTERNAL_ERROR, "Signed attributes changed during CMS assembly.")
    if signer_info["signature"].native != signature:
        raise EngineError(ErrorCode.INTERNAL_ERROR, "Signature value changed during CMS assembly.")
    if 2 * len(cms_der) > prepared.reserved_hex_capacity:
        raise EngineError(
            ErrorCode.CMS_RESERVATION_EXCEEDED, "CMS does not fit the reserved space; prepare again."
        )

    output = BytesIO(prepared.prepared_pdf)
    prep_digest = PreparedByteRangeDigest(
        document_digest=prepared.byte_range_digest,
        reserved_region_start=prepared.reserved_region_start,
        reserved_region_end=prepared.reserved_region_end,
    )
    await PdfTBSDocument.async_finish_signing(output, prep_digest, sig_cms)
    return output.getvalue()
