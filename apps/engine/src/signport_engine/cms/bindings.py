# SPDX-License-Identifier: AGPL-3.0-or-later
"""Cryptographic binding checks re-run from persisted state (plan P1 §12.1; review REV-05, REV-13).

- ``verify_preparation_bindings``: before any state transition (checks 1-7).
- ``verify_signed_artifact``: after CMS assembly AND when recovering an artifact found on disk
  (checks 8-9 plus full semantic CMS verification). One function for both paths.

Persisted-state inconsistencies raise StateIntegrityError; client-visible mismatches raise
EngineError with the P0 code. Every check fails closed. Revocation is out of scope (E5).
"""

import hashlib
from typing import cast

from asn1crypto import algos, cms, tsp
from asn1crypto import x509 as asn1_x509
from cryptography import x509

from signport_engine.cms.raw_signature import require_supported_algorithms, verify_raw_rsa_signature
from signport_engine.errors import EngineError, ErrorCode, StateIntegrityError
from signport_engine.pdf.byte_range import ByteRange, check_reserved_region
from signport_engine.pdf.external_signing import PreparedSignature, sha256_hex
from signport_engine.pdf.signature_field import bind_signature_field, extract_cms

_EXPECTED_ATTRS = ("content_type", "message_digest", "signing_certificate_v2")
SHA256_WITH_RSA_OID = "1.2.840.113549.1.1.11"


def _single_values(signed_attrs_der: bytes) -> dict[str, object]:
    try:
        attrs = cms.CMSAttributes.load(signed_attrs_der)
        types = [a["type"].native for a in attrs]
        if sorted(types) != sorted(_EXPECTED_ATTRS) or len(set(types)) != len(types):
            raise StateIntegrityError("unexpected signed attribute set")
        out: dict[str, object] = {}
        for a in attrs:
            values = a["values"]
            if len(values) != 1:
                raise StateIntegrityError("signed attribute must have exactly one value")
            out[a["type"].native] = values[0]
        return out
    except StateIntegrityError:
        raise
    except Exception:  # noqa: BLE001 - any ASN.1 decoding problem is an integrity failure
        raise StateIntegrityError("signed attributes are not valid DER") from None


def verify_signing_certificate_v2(value: object, certificate_der: bytes) -> None:
    """ESSCertIDv2 must reference exactly this certificate: SHA-256 hash and issuerSerial."""
    cert = asn1_x509.Certificate.load(certificate_der)
    scv2 = cast(tsp.SigningCertificateV2, value)
    certs = cast(tsp.ESSCertIDv2s, scv2["certs"])
    if len(certs) < 1:
        raise StateIntegrityError("signingCertificateV2 has no certificate reference")
    ess = cast(tsp.ESSCertIDv2, certs[0])
    hash_algorithm = cast(algos.DigestAlgorithm, ess["hash_algorithm"])
    if hash_algorithm["algorithm"].native != "sha256":
        raise StateIntegrityError("signingCertificateV2 must use SHA-256")
    if ess["cert_hash"].native != hashlib.sha256(certificate_der).digest():
        raise EngineError(
            ErrorCode.CERTIFICATE_MISMATCH, "signingCertificateV2 does not reference the certificate."
        )
    issuer_serial = cast(tsp.IssuerSerial, ess["issuer_serial"])
    if issuer_serial.native is None:
        raise StateIntegrityError("signingCertificateV2 lacks issuerSerial")
    general_names = cast(asn1_x509.GeneralNames, issuer_serial["issuer"])
    names = [gn.chosen for gn in general_names if gn.name == "directory_name"]
    # directoryName is [4] EXPLICIT: compare the exact DER of the untagged Name.
    if len(names) != 1 or names[0].untag().dump() != cert.issuer.dump():
        raise EngineError(ErrorCode.CERTIFICATE_MISMATCH, "signingCertificateV2 issuer does not match.")
    if issuer_serial["serial_number"].native != cert.serial_number:
        raise EngineError(ErrorCode.CERTIFICATE_MISMATCH, "signingCertificateV2 serial does not match.")


def verify_preparation_bindings(
    prepared: PreparedSignature,
    *,
    persisted_certificate_sha256: str,
    persisted_prepared_pdf_sha256: str,
    persisted_digest_algorithm: str,
    persisted_signature_algorithm: str,
    requested_certificate_sha256: str,
    requested_signature_algorithm: str,
    requested_digest_algorithm: str,
) -> ByteRange:
    """Checks 1-7 of plan P1 §12.1 on the decrypted state, before any state transition."""
    # 1. certificate fingerprint recomputed from the persisted DER
    actual_cert_sha = sha256_hex(prepared.certificate_der)
    if actual_cert_sha != prepared.certificate_sha256 or actual_cert_sha != persisted_certificate_sha256:
        raise StateIntegrityError("persisted certificate fingerprint mismatch")
    if requested_certificate_sha256 != actual_cert_sha:
        raise EngineError(
            ErrorCode.CERTIFICATE_MISMATCH, "Certificate differs from the one bound to the preparation."
        )
    # 3. algorithms bound to the preparation, the request and the supported policy
    require_supported_algorithms(requested_digest_algorithm, requested_signature_algorithm)
    persisted = (persisted_digest_algorithm, persisted_signature_algorithm)
    if (prepared.digest_algorithm, prepared.signature_algorithm) != persisted:
        raise StateIntegrityError("persisted algorithms mismatch")
    if (requested_digest_algorithm, requested_signature_algorithm) != persisted:
        raise EngineError(ErrorCode.UNSUPPORTED_ALGORITHM, "Algorithms differ from the preparation.")
    # prepared document integrity (already AEAD-protected; recomputed as an independent check)
    actual_pdf_sha = sha256_hex(prepared.prepared_pdf)
    if actual_pdf_sha != prepared.prepared_pdf_sha256 or actual_pdf_sha != persisted_prepared_pdf_sha256:
        raise StateIntegrityError("prepared document hash mismatch")
    # 4. reserved region offsets and zero placeholder
    region = check_reserved_region(
        prepared.prepared_pdf, prepared.reserved_region_start, prepared.reserved_region_end, placeholder=True
    )
    # 5. the expected field's signature dictionary declares exactly these offsets (structural)
    bound = bind_signature_field(
        prepared.prepared_pdf, prepared.field_name, start=region.start, end=region.end
    )
    if any(bound.contents):
        raise StateIntegrityError("prepared /Contents placeholder is not empty")
    # 6. recompute the digest of the covered bytes independently
    recomputed = region.digest(prepared.prepared_pdf)
    if recomputed != prepared.byte_range_digest:
        raise StateIntegrityError("ByteRange digest mismatch")
    # 7. messageDigest == recomputed digest; 2. signingCertificateV2 == certificate
    values = _single_values(prepared.signed_attrs_der)
    if cast(cms.ContentType, values["content_type"]).native != "data":
        raise StateIntegrityError("content-type attribute must be id-data")
    if cast(cms.OctetString, values["message_digest"]).native != recomputed:
        raise StateIntegrityError("messageDigest does not match the recomputed ByteRange digest")
    verify_signing_certificate_v2(values["signing_certificate_v2"], prepared.certificate_der)
    return region


def _sid_matches(sid: cms.SignerIdentifier, cert: asn1_x509.Certificate) -> bool:
    if sid.name == "issuer_and_serial_number":
        ias = cast(cms.IssuerAndSerialNumber, sid.chosen)
        return (
            ias["issuer"].dump() == cert.issuer.dump() and ias["serial_number"].native == cert.serial_number
        )
    if sid.name == "subject_key_identifier":
        return cert.key_identifier is not None and sid.chosen.native == cert.key_identifier
    return False


def verify_signed_artifact(
    prepared: PreparedSignature,
    region: ByteRange,
    signed_pdf: bytes,
    *,
    expected_signature_sha256: str | None,
) -> bytes:
    """Checks 8-9 and full semantic CMS verification. Returns the raw RSA signature.

    Used both after normal CMS assembly and before adopting an artifact found on disk
    during recovery; an AEAD-authentic artifact is NOT trusted without these checks.
    """
    # 8. no covered byte changed; only the reserved region was filled
    if len(signed_pdf) != len(prepared.prepared_pdf):
        raise StateIntegrityError("finalization changed the document size")
    if region.covered(signed_pdf) != region.covered(prepared.prepared_pdf):
        raise StateIntegrityError("finalization modified bytes covered by the ByteRange")
    check_reserved_region(signed_pdf, region.start, region.end, placeholder=False)
    if region.digest(signed_pdf) != prepared.byte_range_digest:
        raise StateIntegrityError("ByteRange digest changed during finalization")
    bound = bind_signature_field(signed_pdf, prepared.field_name, start=region.start, end=region.end)
    cms_der = extract_cms(bound.contents)
    try:
        content_info = cms.ContentInfo.load(cms_der, strict=True)
        if content_info["content_type"].native != "signed_data":
            raise StateIntegrityError("CMS is not SignedData")
        signed_data = cast(cms.SignedData, content_info["content"])
        encap = cast(cms.EncapsulatedContentInfo, signed_data["encap_content_info"])
        if encap["content_type"].native != "data" or encap["content"].native is not None:
            raise StateIntegrityError("CMS must be detached id-data")
        digest_algorithms = [a["algorithm"].native for a in signed_data["digest_algorithms"]]
        if digest_algorithms != ["sha256"]:
            raise StateIntegrityError("unexpected CMS digest algorithms")
        signer_infos = cast(cms.SignerInfos, signed_data["signer_infos"])
        if len(signer_infos) != 1:
            raise StateIntegrityError("CMS must have exactly one SignerInfo")
        info = cast(cms.SignerInfo, signer_infos[0])
        cert = asn1_x509.Certificate.load(prepared.certificate_der)
        embedded = [c.chosen.dump() for c in signed_data["certificates"] if c.name == "certificate"]
        if prepared.certificate_der not in embedded:
            raise StateIntegrityError("CMS does not embed the bound certificate")
        if not _sid_matches(cast(cms.SignerIdentifier, info["sid"]), cert):
            raise StateIntegrityError("SignerInfo does not identify the bound certificate")
        if cast(algos.DigestAlgorithm, info["digest_algorithm"])["algorithm"].native != "sha256":
            raise StateIntegrityError("SignerInfo digest algorithm must be SHA-256")
        signature_algorithm = cast(algos.SignedDigestAlgorithm, info["signature_algorithm"])
        if (
            cast(algos.SignedDigestAlgorithmId, signature_algorithm["algorithm"]).dotted
            != SHA256_WITH_RSA_OID
        ):
            raise StateIntegrityError("SignerInfo signature algorithm must be sha256WithRSAEncryption")
        if info["unsigned_attrs"].native is not None:
            raise StateIntegrityError("unsigned attributes are not expected in P1")
        if info["signed_attrs"].untag().dump() != prepared.signed_attrs_der:
            raise StateIntegrityError("CMS signed attributes differ from the frozen ones")
        signature = cast(bytes, info["signature"].native)
    except StateIntegrityError:
        raise
    except Exception:  # noqa: BLE001 - malformed CMS is an integrity failure
        raise StateIntegrityError("CMS in /Contents is not valid") from None
    try:
        verify_raw_rsa_signature(
            x509.load_der_x509_certificate(prepared.certificate_der), prepared.signed_attrs_der, signature
        )
    except EngineError:
        raise StateIntegrityError("CMS signature does not verify") from None
    if (
        expected_signature_sha256 is not None
        and hashlib.sha256(signature).hexdigest() != expected_signature_sha256
    ):
        raise StateIntegrityError("CMS signature differs from the expected one")
    return signature
