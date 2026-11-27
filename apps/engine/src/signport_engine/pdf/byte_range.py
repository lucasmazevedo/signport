# SPDX-License-Identifier: AGPL-3.0-or-later
"""Byte-level checks of the reserved region and independent ByteRange digest.

Offsets and gap shape are validated here; the structural binding of the expected
signature field to its /ByteRange and /Contents is ``pdf.signature_field`` (REV-13).
The digest of the covered bytes is always recomputed from scratch.
"""

import hashlib
import re
from dataclasses import dataclass

from signport_engine.errors import StateIntegrityError

_HEX = re.compile(rb"[0-9A-Fa-f]*")


@dataclass(frozen=True, slots=True)
class ByteRange:
    start: int  # == length of the first covered segment
    end: int  # first byte after the gap
    total: int

    def covered(self, pdf: bytes) -> bytes:
        return pdf[: self.start] + pdf[self.end :]

    def digest(self, pdf: bytes) -> bytes:
        return hashlib.sha256(self.covered(pdf)).digest()


def check_reserved_region(pdf: bytes, start: int, end: int, *, placeholder: bool) -> ByteRange:
    """Validate offsets and gap delimiters; with ``placeholder`` the gap must be all zeros."""
    if not 0 < start < end < len(pdf):  # both covered segments must be non-empty
        raise StateIntegrityError("reserved region offsets out of bounds")
    capacity = end - start - 2
    if capacity <= 0 or capacity % 2:
        raise StateIntegrityError("reserved region capacity must be positive and even")
    gap = pdf[start:end]
    if gap[:1] != b"<" or gap[-1:] != b">" or not _HEX.fullmatch(gap[1:-1]):
        raise StateIntegrityError("reserved region is not a hex string")
    if placeholder and gap[1:-1].strip(b"0"):
        raise StateIntegrityError("reserved region placeholder is not zero-filled")
    return ByteRange(start, end, len(pdf))
