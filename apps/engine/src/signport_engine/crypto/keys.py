# SPDX-License-Identifier: AGPL-3.0-or-later
"""State-key keyring and per-purpose subkeys (E3, plan §§4, 15.2; review REV-02, REV-14).

Configuration (exactly one form, otherwise the Engine refuses to start):
- ``ENGINE_STATE_KEY`` (strict, canonical base64url of 32 random bytes) + ``ENGINE_STATE_KEY_ID``; or
- ``ENGINE_STATE_KEY_FILE``: JSON keyring ``{"active_key_id": "...", "keys": {"<id>": "<b64url>"}}``,
  mode <= 0600, owned by the current user, outside ``ENGINE_DATA_DIR``.

Keys are never generated here, never written next to the encrypted data and never
appear in ``repr``/logs. Subkeys are derived with HKDF-SHA256 bound to the
installation (salt) and to the purpose (info). ``fingerprint()`` is a one-way,
installation-bound identity of the key material, stored in the authenticated key
registry so the same material can never reappear under another key id and an id
can never be re-bound to other material.
"""

import base64
import binascii
import json
import os
import re
import stat
from collections.abc import Mapping
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from signport_engine.errors import ConfigurationError

KEY_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_B64URL_KEY = re.compile(r"^[A-Za-z0-9_-]{43}=?$")
KEY_BYTES = 32


class Purpose(StrEnum):
    """Cryptographic separation of purposes; one HKDF subkey each."""

    STATE = "state"  # preparation state envelopes
    ARTIFACT = "artifact"  # prepared and signed PDFs stored by the Engine
    METADATA_MAC = "metadata-mac"  # row_mac, event chain, nonce counters, key registry


def _decode_key(value: str, where: str) -> bytes:
    """Strict canonical base64url (43 chars, optional single '='), 32 bytes, not all zero."""
    if not _B64URL_KEY.fullmatch(value):
        raise ConfigurationError(f"{where}: key must be 32 bytes in canonical base64url")
    body = value.rstrip("=")
    try:
        raw = base64.urlsafe_b64decode(body + "=")
    except (binascii.Error, ValueError):
        raise ConfigurationError(f"{where}: key is not valid base64url") from None
    if len(raw) != KEY_BYTES or base64.urlsafe_b64encode(raw).decode().rstrip("=") != body:
        raise ConfigurationError(f"{where}: key must be 32 bytes in canonical base64url")
    if raw == bytes(KEY_BYTES):
        raise ConfigurationError(f"{where}: all-zero key rejected")
    return raw


def _check_key_id(key_id: str, where: str) -> str:
    if not KEY_ID_RE.fullmatch(key_id):
        raise ConfigurationError(f"{where}: invalid key id")
    return key_id


class Keyring:
    """Immutable set of master keys bound to one installation."""

    __slots__ = ("_active", "_instance", "_keys")

    def __init__(self, active_key_id: str, keys: Mapping[str, bytes], *, instance_id: str) -> None:
        if not keys:
            raise ConfigurationError("keyring is empty")
        if active_key_id not in keys:
            raise ConfigurationError("active key id is not present in the keyring")
        if len(set(keys.values())) != len(keys):
            raise ConfigurationError("the same key material appears under two ids")
        self._active = active_key_id
        self._instance = instance_id
        self._keys: Mapping[str, bytes] = MappingProxyType({k: bytes(v) for k, v in keys.items()})

    def __setattr__(self, name: str, value: object) -> None:
        if hasattr(self, name):
            raise AttributeError("Keyring is immutable")
        object.__setattr__(self, name, value)

    @property
    def active_key_id(self) -> str:
        return self._active

    @property
    def instance_id(self) -> str:
        return self._instance

    @property
    def key_ids(self) -> frozenset[str]:
        return frozenset(self._keys)

    def has(self, key_id: str) -> bool:
        return key_id in self._keys

    def _derive(self, key_id: str, info: bytes) -> bytes:
        master = self._keys.get(key_id)
        if master is None:
            raise KeyError(key_id)
        salt = b"signport-engine/keyring/v2\x00" + self._instance.encode("ascii")
        return HKDF(algorithm=hashes.SHA256(), length=KEY_BYTES, salt=salt, info=info).derive(master)

    def subkey(self, key_id: str, purpose: Purpose) -> bytes:
        return self._derive(key_id, b"signport-engine:subkey:" + purpose.value.encode("ascii"))

    def fingerprint(self, key_id: str) -> str:
        """Non-secret, one-way identity of the key material within this installation."""
        return self._derive(key_id, b"signport-engine:key-fingerprint").hex()

    def __repr__(self) -> str:
        return f"Keyring(active_key_id={self._active!r}, key_ids={sorted(self._keys)!r})"


def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    out: dict[str, object] = {}
    for k, v in pairs:
        if k in out:
            raise ConfigurationError("duplicate member in key file")
        out[k] = v
    return out


def _load_key_file(path: Path, data_dir: Path, instance_id: str) -> Keyring:
    where = "ENGINE_STATE_KEY_FILE"
    try:
        resolved = path.resolve(strict=True)
        st = resolved.stat()
    except OSError:
        raise ConfigurationError(f"{where}: file not readable") from None
    if not stat.S_ISREG(st.st_mode):
        raise ConfigurationError(f"{where}: not a regular file")
    if st.st_mode & 0o077:
        raise ConfigurationError(f"{where}: permissions must be 0600 or stricter")
    if st.st_uid != os.geteuid():
        raise ConfigurationError(f"{where}: must be owned by the Engine user")
    if resolved.is_relative_to(data_dir.resolve()):
        raise ConfigurationError(f"{where}: keys must not be stored inside ENGINE_DATA_DIR")
    try:
        doc = json.loads(resolved.read_text("utf-8"), object_pairs_hook=_reject_duplicates)
    except (ValueError, UnicodeDecodeError):
        raise ConfigurationError(f"{where}: invalid JSON") from None
    if not isinstance(doc, dict) or set(doc) != {"active_key_id", "keys"}:  # pyright: ignore[reportUnknownArgumentType]
        raise ConfigurationError(f"{where}: expected exactly 'active_key_id' and 'keys'")
    active, keys = doc["active_key_id"], doc["keys"]
    if not isinstance(active, str) or not isinstance(keys, dict) or not keys:
        raise ConfigurationError(f"{where}: malformed keyring")
    decoded: dict[str, bytes] = {}
    for kid, value in keys.items():  # pyright: ignore[reportUnknownVariableType]
        if not isinstance(kid, str) or not isinstance(value, str):
            raise ConfigurationError(f"{where}: malformed key entry")
        decoded[_check_key_id(kid, where)] = _decode_key(value, where)
    return Keyring(_check_key_id(active, where), decoded, instance_id=instance_id)


def load_keyring(env: Mapping[str, str], data_dir: Path, instance_id: str) -> Keyring:
    inline_key, inline_id, key_file = (
        env.get("ENGINE_STATE_KEY"),
        env.get("ENGINE_STATE_KEY_ID"),
        env.get("ENGINE_STATE_KEY_FILE"),
    )
    if key_file and (inline_key or inline_id):
        raise ConfigurationError("configure either ENGINE_STATE_KEY(_ID) or ENGINE_STATE_KEY_FILE, not both")
    if key_file:
        return _load_key_file(Path(key_file), data_dir, instance_id)
    if inline_key and inline_id:
        key_id = _check_key_id(inline_id, "ENGINE_STATE_KEY_ID")
        return Keyring(key_id, {key_id: _decode_key(inline_key, "ENGINE_STATE_KEY")}, instance_id=instance_id)
    raise ConfigurationError("no state key configured; the Engine refuses to start without one")
