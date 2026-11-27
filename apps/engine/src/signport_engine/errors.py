# SPDX-License-Identifier: AGPL-3.0-or-later
"""Engine errors mapped 1:1 to the canonical taxonomy (packages/protocol/errors/registry.json)."""

from enum import StrEnum


class ErrorCode(StrEnum):
    VALIDATION_FAILED = "VALIDATION_FAILED"
    DOCUMENT_INVALID = "DOCUMENT_INVALID"
    DOCUMENT_HASH_MISMATCH = "DOCUMENT_HASH_MISMATCH"
    CERTIFICATE_INVALID = "CERTIFICATE_INVALID"
    CERTIFICATE_MISMATCH = "CERTIFICATE_MISMATCH"
    UNSUPPORTED_ALGORITHM = "UNSUPPORTED_ALGORITHM"
    SIGNATURE_INVALID = "SIGNATURE_INVALID"
    CMS_RESERVATION_EXCEEDED = "CMS_RESERVATION_EXCEEDED"
    INTERNAL_ERROR = "INTERNAL_ERROR"


class EngineError(Exception):
    """Domain error. ``message`` is safe for clients: no stack traces, keys, PINs or document content."""

    def __init__(self, code: ErrorCode, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
