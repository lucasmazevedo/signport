# SPDX-License-Identifier: AGPL-3.0-or-later
"""Test-only forgery helpers (REV-05): build signed PDFs WITHOUT the Engine's checks, and read
an Engine preparation's decrypted state through public building blocks only."""

from collections.abc import Mapping
from io import BytesIO
from pathlib import Path

from asn1crypto import algos, cms
from asn1crypto import x509 as asn1_x509
from pyhanko.sign.signers.pdf_byterange import PreparedByteRangeDigest
from pyhanko.sign.signers.pdf_cms import ExternalSigner
from pyhanko.sign.signers.pdf_signer import PdfTBSDocument
from pyhanko_certvalidator.registry import SimpleCertificateStore
from support.engine import cipher

from signport_engine.crypto.envelope import AadContext, EnvelopeKind
from signport_engine.pdf.external_signing import PreparedSignature
from signport_engine.persistence.repository import PreparationRecord
from signport_engine.state.model import decode_state
from signport_engine.storage.blobs import EncryptedBlobStore


def blob_store(env: Mapping[str, str]) -> EncryptedBlobStore:
    return EncryptedBlobStore(Path(env["ENGINE_DATA_DIR"]), cipher(env))


def load_prepared(env: Mapping[str, str], r: PreparationRecord) -> PreparedSignature:
    assert r.state_envelope is not None
    assert r.prepared_blob is not None
    c = cipher(env)
    inst = env["ENGINE_INSTANCE_ID"]
    state = c.open(
        EnvelopeKind.PREPARATION_STATE,
        r.state_envelope,
        AadContext(inst, r.preparation_id, (r.document_sha256, r.certificate_sha256, r.prepared_pdf_sha256)),
    )
    pdf = blob_store(env).get(
        r.prepared_blob,
        EnvelopeKind.PREPARED_PDF,
        AadContext(inst, r.preparation_id, (r.prepared_pdf_sha256,)),
    )
    return decode_state(state, pdf)[0]


async def forge_signed_pdf(
    prepared: PreparedSignature,
    *,
    signature: bytes,
    signed_attrs_der: bytes | None = None,
    certificate_der: bytes | None = None,
) -> bytes:
    """Embed an arbitrary CMS into the prepared PDF, bypassing every Engine verification."""
    cert = asn1_x509.Certificate.load(certificate_der or prepared.certificate_der)
    chain = [asn1_x509.Certificate.load(d) for d in prepared.chain_der]
    signer = ExternalSigner(
        signing_cert=cert,
        cert_registry=SimpleCertificateStore.from_certs([cert, *chain]),
        signature_value=signature,
        signature_mechanism=algos.SignedDigestAlgorithm({"algorithm": "sha256_rsa"}),
    )
    attrs = cms.CMSAttributes.load(signed_attrs_der or prepared.signed_attrs_der)
    sig_cms = await signer.async_sign_prescribed_attributes("sha256", signed_attrs=attrs)
    out = BytesIO(prepared.prepared_pdf)
    digest = PreparedByteRangeDigest(
        prepared.byte_range_digest, prepared.reserved_region_start, prepared.reserved_region_end
    )
    await PdfTBSDocument.async_finish_signing(out, digest, sig_cms)
    return out.getvalue()


def artifact_aad(env: Mapping[str, str], r: PreparationRecord, sha: str) -> AadContext:
    return AadContext(env["ENGINE_INSTANCE_ID"], r.preparation_id, (r.completion_binding or "", sha))
