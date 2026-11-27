# SPDX-License-Identifier: AGPL-3.0-or-later
"""Versioned AES-256-GCM envelopes for everything sensitive the Engine persists.

Format v2 (binary, big-endian). v1 (pre-release, installation-independent subkeys) is
rejected; there was no public release, so no migration path is kept:

    magic "SPE1" (4) | version=2 (1) | kind (1) | len(key_id) (1) | key_id (ASCII)
    | nonce (12) | ciphertext || tag (16)

- Cipher: ``cryptography`` AESGCM with the HKDF subkey of the envelope's purpose.
- Nonce: 4 random bytes || 8-byte counter. The counter is reserved durably (committed)
  per (key_id, purpose) BEFORE use, so concurrent processes and crashes never reuse it;
  the random prefix is defence in depth if a restored backup rewinds the counter (the
  mandatory procedure is still to rotate to a never-used key after a restore).
- AAD: length-prefixed components binding installation, kind, preparation and the
  kind-specific context; the header bytes are authenticated too.
"""

import os
import struct
import threading
from collections.abc import Sequence
from dataclasses import dataclass
from enum import IntEnum
from typing import Protocol

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from signport_engine.crypto.keys import Keyring, Purpose
from signport_engine.errors import StateIntegrityError

MAGIC = b"SPE1"
VERSION = 2
NONCE_BYTES = 12
TAG_BYTES = 16
# Limits per (key, purpose) subkey (review REV-02):
# - invocations: at most 2**32 envelopes (policy bound, far below the 2**64 counter space;
#   keeps the random 32-bit prefix meaningful as defence in depth); rotate long before;
# - volume: one envelope <= 2**36 - 32 bytes (GCM per-message bound, ~64 GiB); Engine PDFs are
#   capped by ENGINE_MAX_PDF_BYTES (<= 200 MiB), so the total per subkey stays below 2**60 bytes.
MAX_INVOCATIONS_PER_KEY = 2**32


class EnvelopeKind(IntEnum):
    PREPARATION_STATE = 1
    PREPARED_PDF = 2
    SIGNED_ARTIFACT = 3

    @property
    def purpose(self) -> Purpose:
        return Purpose.STATE if self is EnvelopeKind.PREPARATION_STATE else Purpose.ARTIFACT


class NonceReservation(Protocol):
    def reserve_nonce_block(self, key_id: str, purpose: Purpose, size: int) -> int:
        """Durably reserve ``size`` never-used counters for (key_id, purpose); return the first.

        The reservation is committed before any counter is used, so concurrent processes get
        disjoint ranges and counters of a block lost in a crash are never handed out again.
        """
        ...


class KeyExhaustedError(Exception):
    """The active key reached its invocation bound; rotation is required."""


@dataclass(frozen=True, slots=True)
class AadContext:
    instance_id: str
    preparation_id: str
    bindings: Sequence[str] = ()

    def encode(self, kind: EnvelopeKind) -> bytes:
        parts = [
            b"signport-engine/aad/v1",
            kind.name.encode(),
            self.instance_id.encode(),
            self.preparation_id.encode(),
        ]
        parts += [b.encode("utf-8") for b in self.bindings]
        return b"".join(struct.pack(">I", len(p)) + p for p in parts)


def _header(kind: EnvelopeKind, key_id: str) -> bytes:
    kid = key_id.encode("ascii")
    return MAGIC + bytes([VERSION, int(kind), len(kid)]) + kid


@dataclass(frozen=True, slots=True)
class ParsedEnvelope:
    kind: EnvelopeKind
    key_id: str
    header: bytes
    nonce: bytes
    ciphertext: bytes


def parse_envelope(data: bytes) -> ParsedEnvelope:
    try:
        if data[:4] != MAGIC or data[4] != VERSION:
            raise ValueError
        kind = EnvelopeKind(data[5])
        klen = data[6]
        key_id = data[7 : 7 + klen].decode("ascii")
        if not key_id or len(key_id) != klen:
            raise ValueError
        offset = 7 + klen
        nonce = data[offset : offset + NONCE_BYTES]
        ciphertext = data[offset + NONCE_BYTES :]
        if len(nonce) != NONCE_BYTES or len(ciphertext) < TAG_BYTES:
            raise ValueError
    except (IndexError, ValueError, UnicodeDecodeError):
        raise StateIntegrityError("malformed envelope") from None
    return ParsedEnvelope(kind, key_id, data[:offset], nonce, ciphertext)


class EnvelopeCipher:
    def __init__(self, keyring: Keyring, nonces: NonceReservation, *, block_size: int = 64) -> None:
        if not 1 <= block_size <= 4096:
            raise ValueError("block_size out of range")
        self._keyring = keyring
        self._nonces = nonces
        self._block_size = block_size
        self._blocks: dict[tuple[str, Purpose], list[int]] = {}  # (next, end) per subkey
        self._lock = threading.Lock()
        self._pid = os.getpid()

    def _next_counter(self, key_id: str, purpose: Purpose) -> int:
        if os.getpid() != self._pid:
            # A forked child inherits the parent's reserved blocks; using them would repeat
            # nonces. Drop them (and a lock possibly held at fork time) and reserve afresh.
            self._lock = threading.Lock()
            self._blocks = {}
            self._pid = os.getpid()
        with self._lock:
            block = self._blocks.get((key_id, purpose))
            if block is None or block[0] >= block[1]:
                start = self._nonces.reserve_nonce_block(key_id, purpose, self._block_size)
                block = [start, start + self._block_size]
                self._blocks[(key_id, purpose)] = block
            counter = block[0]
            block[0] += 1
            return counter

    @property
    def active_key_id(self) -> str:
        return self._keyring.active_key_id

    def seal(self, kind: EnvelopeKind, plaintext: bytes, aad: AadContext) -> bytes:
        key_id = self._keyring.active_key_id
        counter = self._next_counter(key_id, kind.purpose)
        if not 0 <= counter < MAX_INVOCATIONS_PER_KEY:
            raise KeyExhaustedError(key_id)
        nonce = os.urandom(4) + counter.to_bytes(8, "big")
        header = _header(kind, key_id)
        aesgcm = AESGCM(self._keyring.subkey(key_id, kind.purpose))
        return header + nonce + aesgcm.encrypt(nonce, plaintext, header + aad.encode(kind))

    def open(self, kind: EnvelopeKind, data: bytes, aad: AadContext) -> bytes:
        env = parse_envelope(data)
        if env.kind is not kind:
            raise StateIntegrityError("envelope kind mismatch")
        if not self._keyring.has(env.key_id):
            raise StateIntegrityError("envelope key id not in keyring")
        aesgcm = AESGCM(self._keyring.subkey(env.key_id, kind.purpose))
        try:
            return aesgcm.decrypt(env.nonce, env.ciphertext, env.header + aad.encode(kind))
        except InvalidTag:
            raise StateIntegrityError("envelope authentication failed") from None
