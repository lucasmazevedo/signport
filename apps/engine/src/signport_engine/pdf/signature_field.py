# SPDX-License-Identifier: AGPL-3.0-or-later
"""Structural binding of the expected signature field to its ByteRange and Contents (REV-13).

Uses pyHanko's PDF reader (object graph, AcroForm, xref) instead of searching the raw bytes
for '/ByteRange': the field is looked up by its fully qualified name, its /V signature
dictionary supplies the ByteRange and Contents values, and the excluded gap must contain
exactly the hex encoding of that same /Contents value (the rule pyHanko applies in its own
coverage check). The ByteRange digest is still recomputed independently by the caller.
"""

import binascii
from dataclasses import dataclass
from io import BytesIO

from pyhanko.pdf_utils import generic
from pyhanko.pdf_utils.misc import PdfError
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.fields import enumerate_sig_fields

from signport_engine.errors import StateIntegrityError
from signport_engine.pdf.byte_range import ByteRange


@dataclass(frozen=True, slots=True)
class BoundSignature:
    region: ByteRange
    contents: bytes  # decoded /Contents of the field's signature dictionary (with padding)


def bind_signature_field(pdf: bytes, field_name: str, *, start: int, end: int) -> BoundSignature:
    try:
        reader = PdfFileReader(BytesIO(pdf), strict=True)
        fields = [(name, value) for name, value, _ in enumerate_sig_fields(reader, filled_status=None)]
        matching = [value for name, value in fields if name == field_name]
        if len(matching) != 1 or matching[0] is None:
            raise StateIntegrityError("expected signature field not found exactly once")
        sig = matching[0].get_object()
        if not isinstance(sig, generic.DictionaryObject):
            raise StateIntegrityError("signature value is not a dictionary")
        if sig.get("/Type") not in (None, "/Sig") or sig.get("/SubFilter") != "/ETSI.CAdES.detached":
            raise StateIntegrityError("unexpected signature dictionary type or subfilter")
        byte_range = [int(v) for v in sig["/ByteRange"]]
        contents = sig.raw_get("/Contents")
        if not isinstance(contents, (generic.ByteStringObject, generic.TextStringObject)):
            raise StateIntegrityError("/Contents is not a string")
        contents_bytes = contents.original_bytes
    except StateIntegrityError:
        raise
    except (PdfError, KeyError, TypeError, ValueError, AttributeError):
        raise StateIntegrityError("signature dictionary could not be read structurally") from None

    if byte_range != [0, start, end, len(pdf) - end]:
        raise StateIntegrityError("field /ByteRange does not match the persisted offsets")
    gap = pdf[start:end]
    if len(gap) != 2 * len(contents_bytes) + 2 or gap[:1] != b"<" or gap[-1:] != b">":
        raise StateIntegrityError("ByteRange gap is not exactly the field's /Contents string")
    try:
        if binascii.unhexlify(gap[1:-1]) != contents_bytes:
            raise StateIntegrityError("ByteRange gap does not hold the field's /Contents")
    except binascii.Error:
        raise StateIntegrityError("ByteRange gap is not hex") from None
    return BoundSignature(ByteRange(start, end, len(pdf)), contents_bytes)


def extract_cms(contents: bytes) -> bytes:
    """DER CMS from /Contents: definite-length SEQUENCE followed only by zero padding."""
    if len(contents) < 2 or contents[0] != 0x30:
        raise StateIntegrityError("/Contents does not start with a DER SEQUENCE")
    first = contents[1]
    if first < 0x80:
        total = 2 + first
    else:
        n = first & 0x7F
        if n == 0 or n > 4 or len(contents) < 2 + n:
            raise StateIntegrityError("unsupported DER length in /Contents")
        total = 2 + n + int.from_bytes(contents[2 : 2 + n], "big")
    if total > len(contents) or any(contents[total:]):
        raise StateIntegrityError("/Contents padding must be zero bytes after the CMS")
    return contents[:total]
