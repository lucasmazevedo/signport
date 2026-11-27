# SPDX-License-Identifier: AGPL-3.0-or-later
"""pyHanko documental validation used by the E2 spike tests.

Offline and strict: trust anchors only from the synthetic root, revocation data
supplied as CRLs, fetching disabled, revocation mode 'require' (revocation info
mandatory for every non-anchor certificate). NOTE (E2 finding): the legacy
'hard-fail' mode means CHECK_IF_DECLARED and silently skips supplied CRLs when a
certificate declares no distribution point; never use 'hard-fail'/'soft-fail'.
The production mapping to ValidationReport is E5.
"""

from dataclasses import dataclass
from io import BytesIO

from asn1crypto import crl as asn1_crl
from asn1crypto import x509 as asn1_x509
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import async_validate_pdf_signature
from pyhanko.sign.validation.status import PdfSignatureStatus
from pyhanko_certvalidator import ValidationContext


@dataclass(frozen=True)
class SignatureCheck:
    field_name: str
    status: PdfSignatureStatus


def _asn1_cert(cert: x509.Certificate) -> asn1_x509.Certificate:
    return asn1_x509.Certificate.load(cert.public_bytes(serialization.Encoding.DER))


def _asn1_crl(crl: x509.CertificateRevocationList) -> asn1_crl.CertificateList:
    return asn1_crl.CertificateList.load(crl.public_bytes(serialization.Encoding.DER))


def validation_context(
    trust_roots: list[x509.Certificate],
    crls: list[x509.CertificateRevocationList],
    revocation_mode: str = "require",
) -> ValidationContext:
    return ValidationContext(
        trust_roots=[_asn1_cert(c) for c in trust_roots],
        crls=[_asn1_crl(c) for c in crls],
        allow_fetching=False,
        revocation_mode=revocation_mode,
    )


async def validate_all(
    pdf: bytes,
    trust_roots: list[x509.Certificate],
    crls: list[x509.CertificateRevocationList],
    revocation_mode: str = "require",
) -> list[SignatureCheck]:
    reader = PdfFileReader(BytesIO(pdf), strict=True)
    results: list[SignatureCheck] = []
    for embedded in reader.embedded_signatures:
        status = await async_validate_pdf_signature(
            embedded, signer_validation_context=validation_context(trust_roots, crls, revocation_mode)
        )
        results.append(SignatureCheck(embedded.field_name, status))
    return results
