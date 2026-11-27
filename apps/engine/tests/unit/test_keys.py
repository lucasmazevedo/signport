# SPDX-License-Identifier: AGPL-3.0-or-later
"""Keyring configuration: fail safe, no key next to data, purpose separation."""

import base64
import json
import os
from pathlib import Path

import pytest
from support.engine import new_key

from signport_engine.crypto.keys import Keyring, Purpose, load_keyring
from signport_engine.errors import ConfigurationError

INSTANCE = "01936f3c-0000-7000-8000-0000000000aa"


def _write_keyring(path: Path, doc: object, mode: int = 0o600) -> Path:
    path.write_text(json.dumps(doc) if not isinstance(doc, str) else doc)
    path.chmod(mode)
    return path


def test_inline_key(tmp_path: Path) -> None:
    ring = load_keyring(
        {"ENGINE_STATE_KEY": new_key(), "ENGINE_STATE_KEY_ID": "k1"}, tmp_path / "data", INSTANCE
    )
    assert ring.active_key_id == "k1"


@pytest.mark.parametrize(
    "env",
    [
        {},
        {"ENGINE_STATE_KEY": new_key()},
        {"ENGINE_STATE_KEY_ID": "k1"},
        {"ENGINE_STATE_KEY": new_key(), "ENGINE_STATE_KEY_ID": "k1", "ENGINE_STATE_KEY_FILE": "/x"},
        {"ENGINE_STATE_KEY": "c2hvcnQ", "ENGINE_STATE_KEY_ID": "k1"},
        {"ENGINE_STATE_KEY": "not base64 !!", "ENGINE_STATE_KEY_ID": "k1"},
        {"ENGINE_STATE_KEY": "A" * 43, "ENGINE_STATE_KEY_ID": "k1"},  # all-zero key
        {"ENGINE_STATE_KEY": new_key(), "ENGINE_STATE_KEY_ID": "bad id/../x"},
    ],
    ids=["none", "key-without-id", "id-without-key", "both-forms", "short", "not-b64", "all-zero", "bad-id"],
)
def test_invalid_configuration_fails_safe(tmp_path: Path, env: dict[str, str]) -> None:
    with pytest.raises(ConfigurationError):
        load_keyring(env, tmp_path / "data", INSTANCE)


def test_key_file_keyring_with_rotation(tmp_path: Path) -> None:
    path = _write_keyring(
        tmp_path / "keys.json", {"active_key_id": "k2", "keys": {"k1": new_key(), "k2": new_key()}}
    )
    ring = load_keyring({"ENGINE_STATE_KEY_FILE": str(path)}, tmp_path / "data", INSTANCE)
    assert ring.active_key_id == "k2"
    assert ring.key_ids == {"k1", "k2"}


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o604])
def test_key_file_permissions_must_be_private(tmp_path: Path, mode: int) -> None:
    path = _write_keyring(tmp_path / "keys.json", {"active_key_id": "k1", "keys": {"k1": new_key()}}, mode)
    with pytest.raises(ConfigurationError, match="permissions"):
        load_keyring({"ENGINE_STATE_KEY_FILE": str(path)}, tmp_path / "data", INSTANCE)


def test_key_file_inside_data_dir_is_rejected(tmp_path: Path) -> None:
    data = tmp_path / "data"
    data.mkdir()
    path = _write_keyring(data / "keys.json", {"active_key_id": "k1", "keys": {"k1": new_key()}})
    with pytest.raises(ConfigurationError, match="inside ENGINE_DATA_DIR"):
        load_keyring({"ENGINE_STATE_KEY_FILE": str(path)}, data, INSTANCE)


@pytest.mark.parametrize(
    "doc",
    [
        {"active_key_id": "k9", "keys": {"k1": "KEY"}},
        {"active_key_id": "k1", "keys": {}},
        {"active_key_id": "k1", "keys": {"k1": "KEY"}, "extra": 1},
        '{"active_key_id": "k1", "keys": {"k1": "KEY", "k1": "KEY"}}',
        "not json",
    ],
    ids=["active-missing", "empty", "extra-member", "duplicate-member", "invalid-json"],
)
def test_malformed_key_file_is_rejected(tmp_path: Path, doc: object) -> None:
    key = new_key()
    rendered = json.dumps(doc).replace("KEY", key) if not isinstance(doc, str) else doc.replace("KEY", key)
    path = _write_keyring(tmp_path / "keys.json", rendered)
    with pytest.raises(ConfigurationError):
        load_keyring({"ENGINE_STATE_KEY_FILE": str(path)}, tmp_path / "data", INSTANCE)


def test_same_material_under_two_ids_is_rejected(tmp_path: Path) -> None:
    key = new_key()
    path = _write_keyring(tmp_path / "keys.json", {"active_key_id": "k1", "keys": {"k1": key, "k2": key}})
    with pytest.raises(ConfigurationError, match="same key material"):
        load_keyring({"ENGINE_STATE_KEY_FILE": str(path)}, tmp_path / "data", INSTANCE)


def test_subkeys_are_separated_by_purpose_and_key() -> None:
    raw = {kid: base64.urlsafe_b64decode(new_key() + "=") for kid in ("k1", "k2")}
    ring = Keyring("k1", raw, instance_id=INSTANCE)
    subkeys = {(k, p): ring.subkey(k, p) for k in raw for p in Purpose}
    assert len(set(subkeys.values())) == len(subkeys) == 6
    assert all(len(v) == 32 for v in subkeys.values())
    assert raw["k1"] not in subkeys.values()  # master never used directly


def test_keyring_repr_never_contains_key_material() -> None:
    secret = base64.urlsafe_b64decode(new_key() + "=")
    ring = Keyring("k1", {"k1": secret}, instance_id=INSTANCE)
    text = repr(ring) + str(ring)
    assert secret.hex() not in text
    assert base64.urlsafe_b64encode(secret).decode().rstrip("=") not in text
    assert "k1" in text


def test_key_file_must_be_owned_by_the_engine_user(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = _write_keyring(tmp_path / "keys.json", {"active_key_id": "k1", "keys": {"k1": new_key()}})
    real = os.geteuid()
    monkeypatch.setattr(os, "geteuid", lambda: real + 1)
    with pytest.raises(ConfigurationError, match="owned"):
        load_keyring({"ENGINE_STATE_KEY_FILE": str(path)}, tmp_path / "data", INSTANCE)
