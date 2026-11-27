# SPDX-License-Identifier: AGPL-3.0-or-later
"""Explicit, versioned plaintext of the preparation-state envelope (no pickle).

The prepared PDF is stored separately as its own encrypted blob; the state carries
its SHA-256. Compatibility policy (REV-14): a preparation may only be completed by the
exact pyHanko version that created it (``COMPATIBLE_PYHANKO_VERSIONS`` lists extra
versions explicitly verified to produce identical CMS/PDF bytes; empty in P1).
Parsing is strict: exact member set, no duplicates, typed values, strict Base64.
"""

import base64
import binascii
import json
from importlib.metadata import version
from typing import Any

from signport_engine.errors import StateIntegrityError
from signport_engine.pdf.external_signing import PreparedSignature

SCHEMA = "signport-engine/preparation-state/v1"
COMPATIBLE_PYHANKO_VERSIONS: frozenset[str] = frozenset()


def current_pyhanko_version() -> str:
    return version("pyhanko")


def is_compatible_pyhanko(stored: str) -> bool:
    return stored == current_pyhanko_version() or stored in COMPATIBLE_PYHANKO_VERSIONS


_STR = (
    "schema",
    "pyhanko_version",
    "field_name",
    "document_sha256",
    "prepared_pdf_sha256",
    "certificate_sha256",
    "digest_algorithm",
    "signature_algorithm",
    "byte_range_digest_b64",
    "signed_attrs_der_b64",
    "certificate_der_b64",
)
_INT = ("reserved_region_start", "reserved_region_end")
_KEYS = frozenset((*_STR, *_INT, "chain_der_b64"))


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(value: object) -> bytes:
    if not isinstance(value, str):
        raise StateIntegrityError("state field is not a string")
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise StateIntegrityError("state field is not strict Base64") from None


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise StateIntegrityError("duplicate member in state")
        out[k] = v
    return out


def encode_state(prepared: PreparedSignature) -> bytes:
    doc = {
        "schema": SCHEMA,
        "pyhanko_version": current_pyhanko_version(),
        "field_name": prepared.field_name,
        "document_sha256": prepared.document_sha256,
        "prepared_pdf_sha256": prepared.prepared_pdf_sha256,
        "byte_range_digest_b64": _b64(prepared.byte_range_digest),
        "reserved_region_start": prepared.reserved_region_start,
        "reserved_region_end": prepared.reserved_region_end,
        "signed_attrs_der_b64": _b64(prepared.signed_attrs_der),
        "certificate_der_b64": _b64(prepared.certificate_der),
        "chain_der_b64": [_b64(c) for c in prepared.chain_der],
        "certificate_sha256": prepared.certificate_sha256,
        "digest_algorithm": prepared.digest_algorithm,
        "signature_algorithm": prepared.signature_algorithm,
    }
    return json.dumps(doc, sort_keys=True, separators=(",", ":")).encode("utf-8")


def decode_state(data: bytes, prepared_pdf: bytes) -> tuple[PreparedSignature, str]:
    """Return the prepared signature and the pyHanko version that produced it."""
    try:
        doc = json.loads(data.decode("utf-8"), object_pairs_hook=_no_duplicates)
    except (UnicodeDecodeError, ValueError):
        raise StateIntegrityError("state is not valid JSON") from None
    if not isinstance(doc, dict) or frozenset(doc) != _KEYS or doc["schema"] != SCHEMA:
        raise StateIntegrityError("unexpected state schema")
    if not all(isinstance(doc[k], str) for k in _STR):
        raise StateIntegrityError("state string field has wrong type")
    if not all(type(doc[k]) is int and doc[k] >= 0 for k in _INT):
        raise StateIntegrityError("state integer field has wrong type")
    chain = doc["chain_der_b64"]
    if not isinstance(chain, list):
        raise StateIntegrityError("state chain has wrong type")
    prepared = PreparedSignature(
        field_name=doc["field_name"],
        document_sha256=doc["document_sha256"],
        prepared_pdf=prepared_pdf,
        prepared_pdf_sha256=doc["prepared_pdf_sha256"],
        byte_range_digest=_unb64(doc["byte_range_digest_b64"]),
        reserved_region_start=doc["reserved_region_start"],
        reserved_region_end=doc["reserved_region_end"],
        signed_attrs_der=_unb64(doc["signed_attrs_der_b64"]),
        certificate_der=_unb64(doc["certificate_der_b64"]),
        chain_der=tuple(_unb64(c) for c in chain),  # pyright: ignore[reportUnknownVariableType]
        certificate_sha256=doc["certificate_sha256"],
        digest_algorithm=doc["digest_algorithm"],
        signature_algorithm=doc["signature_algorithm"],
    )
    return prepared, doc["pyhanko_version"]
