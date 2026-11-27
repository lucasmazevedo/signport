# SPDX-License-Identifier: AGPL-3.0-or-later
"""AES-256-GCM envelope v2: format, tampering, context swap, wrong key, rotation, nonces."""

import base64
import os
from dataclasses import dataclass, field
from pathlib import Path

import pytest
from support.engine import engine_env, keyring, new_key, repository, service

from signport_engine.crypto.envelope import (
    MAGIC,
    MAX_INVOCATIONS_PER_KEY,
    AadContext,
    EnvelopeCipher,
    EnvelopeKind,
    KeyExhaustedError,
    parse_envelope,
)
from signport_engine.crypto.keys import Keyring, Purpose
from signport_engine.errors import StateIntegrityError

INSTANCE = "01936f3c-0000-7000-8000-0000000000aa"
PREP = "01936f3c-0000-7000-8000-000000000005"


@dataclass
class Counters:
    values: dict[tuple[str, Purpose], int] = field(default_factory=dict)

    def reserve_nonce_block(self, key_id: str, purpose: Purpose, size: int) -> int:
        n = self.values.get((key_id, purpose), 0)
        self.values[(key_id, purpose)] = n + size
        return n


def ring(*ids: str, active: str | None = None) -> Keyring:
    return Keyring(
        active or ids[0], {i: base64.urlsafe_b64decode(new_key() + "=") for i in ids}, instance_id=INSTANCE
    )


AAD = AadContext(INSTANCE, PREP, ("doc-sha", "cert-sha"))


def test_roundtrip_and_header_layout() -> None:
    cipher = EnvelopeCipher(ring("k1"), Counters())
    env = cipher.seal(EnvelopeKind.PREPARATION_STATE, b"secret state", AAD)
    parsed = parse_envelope(env)
    assert env[:4] == MAGIC
    assert env[4] == 2
    assert parsed.kind is EnvelopeKind.PREPARATION_STATE
    assert parsed.key_id == "k1"
    assert len(parsed.nonce) == 12
    assert b"secret state" not in env
    assert cipher.open(EnvelopeKind.PREPARATION_STATE, env, AAD) == b"secret state"


@pytest.mark.parametrize("offset", [0, 4, 5, 6, 7, 9, 12, 20, -1])
def test_any_flipped_byte_fails_closed(offset: int) -> None:
    cipher = EnvelopeCipher(ring("k1"), Counters())
    env = bytearray(cipher.seal(EnvelopeKind.PREPARATION_STATE, b"x" * 64, AAD))
    env[offset] ^= 0x01
    with pytest.raises(StateIntegrityError):
        cipher.open(EnvelopeKind.PREPARATION_STATE, bytes(env), AAD)


@pytest.mark.parametrize(
    "other",
    [
        AadContext("01936f3c-0000-7000-8000-0000000000ff", PREP, ("doc-sha", "cert-sha")),
        AadContext(INSTANCE, "01936f3c-0000-7000-8000-0000000000ee", ("doc-sha", "cert-sha")),
        AadContext(INSTANCE, PREP, ("doc-sha", "other-cert")),
        AadContext(INSTANCE, PREP, ("doc-sha",)),
        AadContext(INSTANCE, PREP, ("doc-shacert-sha",)),  # length-prefixing prevents concatenation ambiguity
    ],
    ids=["other-installation", "other-preparation", "other-binding", "missing-binding", "concatenated"],
)
def test_context_swap_fails_closed(other: AadContext) -> None:
    cipher = EnvelopeCipher(ring("k1"), Counters())
    env = cipher.seal(EnvelopeKind.PREPARATION_STATE, b"state", AAD)
    with pytest.raises(StateIntegrityError):
        cipher.open(EnvelopeKind.PREPARATION_STATE, env, other)


def test_kind_and_purpose_swap_fails_closed() -> None:
    cipher = EnvelopeCipher(ring("k1"), Counters())
    env = cipher.seal(EnvelopeKind.PREPARED_PDF, b"%PDF", AAD)
    with pytest.raises(StateIntegrityError):
        cipher.open(EnvelopeKind.SIGNED_ARTIFACT, env, AAD)  # same subkey purpose, different kind
    with pytest.raises(StateIntegrityError):
        cipher.open(EnvelopeKind.PREPARATION_STATE, env, AAD)


def test_wrong_key_and_unknown_key_id_fail_closed() -> None:
    a = EnvelopeCipher(ring("k1"), Counters())
    b = EnvelopeCipher(ring("k1"), Counters())  # same id, different material
    c = EnvelopeCipher(ring("k2"), Counters())
    env = a.seal(EnvelopeKind.PREPARATION_STATE, b"state", AAD)
    with pytest.raises(StateIntegrityError):
        b.open(EnvelopeKind.PREPARATION_STATE, env, AAD)
    with pytest.raises(StateIntegrityError, match="key id"):
        c.open(EnvelopeKind.PREPARATION_STATE, env, AAD)


def test_rotation_reads_with_previous_key_and_seals_with_active() -> None:
    k1 = base64.urlsafe_b64decode(new_key() + "=")
    k2 = base64.urlsafe_b64decode(new_key() + "=")
    env = EnvelopeCipher(Keyring("k1", {"k1": k1}, instance_id=INSTANCE), Counters()).seal(
        EnvelopeKind.SIGNED_ARTIFACT, b"artifact", AAD
    )
    rotated = Keyring("k2", {"k1": k1, "k2": k2}, instance_id=INSTANCE)
    cipher = EnvelopeCipher(rotated, Counters())
    assert cipher.open(EnvelopeKind.SIGNED_ARTIFACT, env, AAD) == b"artifact"
    assert parse_envelope(cipher.seal(EnvelopeKind.SIGNED_ARTIFACT, b"a", AAD)).key_id == "k2"


def test_malformed_envelopes_fail_closed() -> None:
    cipher = EnvelopeCipher(ring("k1"), Counters())
    for data in (
        b"",
        b"SPE1",
        b"XXXX" + bytes(40),
        b"SPE1\x01\x01\x02k1" + bytes(40),
        b"SPE1\x01\x09\x02k1" + bytes(40),
    ):
        with pytest.raises(StateIntegrityError):
            cipher.open(EnvelopeKind.PREPARATION_STATE, data, AAD)


def test_nonces_are_unique_and_counter_based() -> None:
    counters = Counters()
    cipher = EnvelopeCipher(ring("k1"), counters)
    nonces = [parse_envelope(cipher.seal(EnvelopeKind.PREPARED_PDF, b"x", AAD)).nonce for _ in range(20_000)]
    assert len(set(nonces)) == len(nonces)
    counters_used = [int.from_bytes(n[4:], "big") for n in nonces]
    assert counters_used == list(range(20_000))  # every reserved counter used exactly once


def test_counters_are_independent_per_purpose() -> None:
    counters = Counters()
    cipher = EnvelopeCipher(ring("k1"), counters)
    cipher.seal(EnvelopeKind.PREPARATION_STATE, b"x", AAD)
    cipher.seal(EnvelopeKind.PREPARED_PDF, b"x", AAD)
    assert counters.values == {("k1", Purpose.STATE): 64, ("k1", Purpose.ARTIFACT): 64}


def test_crash_after_reservation_never_reuses_the_block() -> None:
    """A new process (new cipher) after a crash starts after the whole reserved block."""
    counters, keys = Counters(), ring("k1")
    first = parse_envelope(EnvelopeCipher(keys, counters).seal(EnvelopeKind.PREPARED_PDF, b"x", AAD)).nonce
    # the first process "crashes" holding counters 1..63 unused
    second = parse_envelope(EnvelopeCipher(keys, counters).seal(EnvelopeKind.PREPARED_PDF, b"x", AAD)).nonce
    assert int.from_bytes(first[4:], "big") == 0
    assert int.from_bytes(second[4:], "big") == 64


def test_encryption_failure_after_reservation_does_not_reuse_the_counter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    cipher = EnvelopeCipher(ring("k1"), Counters())
    original = AESGCM.encrypt

    def boom(*_a: object, **_k: object) -> bytes:
        raise MemoryError("simulated failure inside encryption")

    monkeypatch.setattr(AESGCM, "encrypt", boom)
    with pytest.raises(MemoryError):
        cipher.seal(EnvelopeKind.PREPARED_PDF, b"x", AAD)
    monkeypatch.setattr(AESGCM, "encrypt", original)
    nonce = parse_envelope(cipher.seal(EnvelopeKind.PREPARED_PDF, b"x", AAD)).nonce
    assert int.from_bytes(nonce[4:], "big") == 1  # counter 0 was consumed by the failed attempt


def test_key_exhaustion_requires_rotation() -> None:
    counters = Counters({("k1", Purpose.STATE): MAX_INVOCATIONS_PER_KEY})
    with pytest.raises(KeyExhaustedError):
        EnvelopeCipher(ring("k1"), counters).seal(EnvelopeKind.PREPARATION_STATE, b"x", AAD)


@pytest.mark.skipif(not hasattr(os, "fork"), reason="fork() not available")
def test_forked_child_never_reuses_the_parents_reserved_block(tmp_path: Path) -> None:
    """Blocks live in memory; a fork copies them. The child must reserve its own block."""
    env = engine_env(tmp_path / "engine")
    service(env)  # create the database and register the key
    c = EnvelopeCipher(keyring(env), repository(env), block_size=8)
    aad = AadContext(env["ENGINE_INSTANCE_ID"], "p", ())
    parent = [parse_envelope(c.seal(EnvelopeKind.PREPARATION_STATE, b"x", aad)).nonce[4:]]
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:  # pragma: no cover - child process
        try:
            child = parse_envelope(c.seal(EnvelopeKind.PREPARATION_STATE, b"y", aad)).nonce[4:]
            os.write(w, child)
        finally:
            os._exit(0)
    os.close(w)
    child_counter = os.read(r, 8)
    os.close(r)
    os.waitpid(pid, 0)
    parent += [parse_envelope(c.seal(EnvelopeKind.PREPARATION_STATE, b"z", aad)).nonce[4:] for _ in range(8)]
    assert len(child_counter) == 8
    assert child_counter not in parent
    assert int.from_bytes(child_counter, "big") >= 8  # from a freshly reserved block
