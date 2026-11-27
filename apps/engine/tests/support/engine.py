# SPDX-License-Identifier: AGPL-3.0-or-later
"""Test helpers for the persistent Engine (E3/E4). Synthetic keys only, per test."""

import base64
import datetime as dt
import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, utils
from support.pki import Issued

from signport_engine.config import EngineSettings
from signport_engine.crypto.envelope import EnvelopeCipher
from signport_engine.crypto.keys import Keyring, load_keyring
from signport_engine.persistence.sqlite import SqlitePreparationRepository
from signport_engine.service import PreparationService, PreparationView, open_engine

INSTANCE_ID = "01936f3c-0000-7000-8000-0000000000aa"
DOCUMENT_VERSION_ID = "01936f3c-0000-7000-8000-000000000007"
ATTEMPT_ID = "01936f3c-0000-7000-8000-000000000004"
OTHER_ATTEMPT_ID = "01936f3c-0000-7000-8000-0000000000bb"
ALG = "RSA_PKCS1_V1_5"


def new_key() -> str:
    return base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("=")


def engine_env(data_dir: Path, *, key: str | None = None, key_id: str = "k1", **extra: str) -> dict[str, str]:
    env = {
        "ENGINE_DATA_DIR": str(data_dir),
        "ENGINE_INSTANCE_ID": INSTANCE_ID,
        "ENGINE_STATE_KEY": key or new_key(),
        "ENGINE_STATE_KEY_ID": key_id,
    }
    env.update(extra)
    return env


@dataclass
class FakeClock:
    current: dt.datetime = field(default_factory=lambda: dt.datetime(2026, 11, 27, 12, 0, tzinfo=dt.UTC))

    def now(self) -> dt.datetime:
        return self.current

    def advance(self, seconds: float) -> None:
        self.current += dt.timedelta(seconds=seconds)


class SimulatedCrash(BaseException):
    """Raised at a fault point; BaseException so production code cannot swallow it."""


@dataclass
class CrashAt:
    point: str
    hits: list[str] = field(default_factory=list)

    def hit(self, name: str) -> None:
        self.hits.append(name)
        if name == self.point:
            raise SimulatedCrash(name)


@dataclass
class OsErrorAt:
    point: str
    errno_value: int

    def hit(self, name: str) -> None:
        if name == self.point:
            raise OSError(self.errno_value, os.strerror(self.errno_value))


def service(env: Mapping[str, str], **kw: object) -> PreparationService:
    return open_engine(env, **kw)  # type: ignore[arg-type]


def keyring(env: Mapping[str, str]) -> Keyring:
    return load_keyring(env, Path(env["ENGINE_DATA_DIR"]), env["ENGINE_INSTANCE_ID"])


def repository(env: Mapping[str, str]) -> SqlitePreparationRepository:
    """Open the same repository the service uses (operator/test view), via public API only."""
    settings = EngineSettings.from_env(env)
    return SqlitePreparationRepository(
        settings.data_dir / "engine.sqlite3",
        instance_id=settings.instance_id,
        keyring=keyring(env),
        busy_timeout_ms=settings.busy_timeout_ms,
    )


def cipher(env: Mapping[str, str]) -> EnvelopeCipher:
    return EnvelopeCipher(keyring(env), repository(env))


def sign_view(signer: Issued, view: PreparationView) -> bytes:
    digest = base64.b64decode(view.signed_attributes_digest_b64)
    return signer.key.sign(digest, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256()))
