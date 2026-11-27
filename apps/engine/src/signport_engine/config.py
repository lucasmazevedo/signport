# SPDX-License-Identifier: AGPL-3.0-or-later
"""Engine settings from the environment. Invalid configuration fails closed."""

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from signport_engine.errors import ConfigurationError
from signport_engine.ids import UUID_RE

MIB = 1024 * 1024


def _int(env: Mapping[str, str], name: str, default: int, lo: int, hi: int) -> int:
    raw = env.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        raise ConfigurationError(f"{name} must be an integer") from None
    if not lo <= value <= hi:
        raise ConfigurationError(f"{name} must be between {lo} and {hi}")
    return value


@dataclass(frozen=True, slots=True)
class EngineSettings:
    data_dir: Path
    instance_id: str
    busy_timeout_ms: int = 5000
    lease_seconds: int = 60
    completion_wait_seconds: float = 30.0
    preparation_ttl_seconds: int = 600
    max_preparation_ttl_seconds: int = 3600
    terminal_retention_seconds: int = 7 * 86400
    artifact_retention_seconds: int = 7 * 86400
    orphan_grace_seconds: int = 3600  # defence in depth only; references are re-checked under lock (REV-07)
    completion_grace_seconds: int = (
        300  # max time after expires_at to finish a claim started in time (REV-09)
    )
    lock_timeout_seconds: float = 30.0
    max_pdf_bytes: int = 20 * MIB

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> "EngineSettings":
        raw_dir = env.get("ENGINE_DATA_DIR")
        if not raw_dir or not Path(raw_dir).is_absolute():
            raise ConfigurationError("ENGINE_DATA_DIR must be an absolute path")
        instance_id = env.get("ENGINE_INSTANCE_ID", "")
        if not UUID_RE.fullmatch(instance_id):
            raise ConfigurationError("ENGINE_INSTANCE_ID must be a canonical lowercase UUID")
        return cls(
            data_dir=Path(raw_dir),
            instance_id=instance_id,
            busy_timeout_ms=_int(env, "ENGINE_SQLITE_BUSY_TIMEOUT_MS", 5000, 0, 120_000),
            lease_seconds=_int(env, "ENGINE_COMPLETION_LEASE_SECONDS", 60, 5, 3600),
            completion_wait_seconds=_int(env, "ENGINE_COMPLETION_WAIT_MS", 30_000, 0, 120_000) / 1000,
            preparation_ttl_seconds=_int(env, "SIGNING_PREPARATION_TTL", 600, 30, 3600),
            terminal_retention_seconds=_int(
                env, "ENGINE_TERMINAL_RETENTION_SECONDS", 7 * 86400, 0, 365 * 86400
            ),
            artifact_retention_seconds=_int(
                env, "ENGINE_ARTIFACT_RETENTION_SECONDS", 7 * 86400, 0, 365 * 86400
            ),
            max_pdf_bytes=_int(env, "ENGINE_MAX_PDF_BYTES", 20 * MIB, 1024, 200 * MIB),
            orphan_grace_seconds=_int(env, "ENGINE_ORPHAN_GRACE_SECONDS", 3600, 0, 86400),
            completion_grace_seconds=_int(env, "ENGINE_COMPLETION_GRACE_SECONDS", 300, 0, 3600),
            lock_timeout_seconds=_int(env, "ENGINE_LOCK_TIMEOUT_MS", 30_000, 0, 600_000) / 1000,
        )
