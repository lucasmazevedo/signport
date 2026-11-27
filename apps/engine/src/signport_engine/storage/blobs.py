# SPDX-License-Identifier: AGPL-3.0-or-later
"""Encrypted, immutable blob store on the Engine's private filesystem (REV-08).

- Plaintext never touches the disk: data is sealed in memory (AES-256-GCM envelope)
  before the first write.
- Atomic publication: exclusive temp file (0600) in ``tmp/`` -> write + fsync ->
  ``os.link`` to the final name (fails if it exists) -> fsync of the final directory
  (and of its parent when the directory was just created) -> unlink temp.
- Immutable: an existing final file is never overwritten; re-publishing identical
  plaintext is idempotent. That fast path still fsyncs the existing file and its
  directory, because a previous process may have crashed after ``link`` and before the
  directory fsync; ``ensure_durable`` does the same before recovery adopts a file.
- Paths are server-generated relative paths validated against traversal.

Durability limits: fsync guarantees depend on the filesystem and the storage stack
honouring flushes (no volatile write cache without power-loss protection). On a
filesystem that lies about fsync, a power loss can still lose recently committed files;
SQLite then references a missing blob, which reads report as an integrity failure
(never as success).
"""

import contextlib
import hashlib
import os
import re
import stat
from pathlib import Path

from signport_engine.crypto.envelope import AadContext, EnvelopeCipher, EnvelopeKind, parse_envelope
from signport_engine.errors import StateIntegrityError

_SEGMENT = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_FILE_MODE = 0o440
_DIR_MODE = 0o700
TOPS = ("prepared", "artifacts")


def fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def fsync_file(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class EncryptedBlobStore:
    def __init__(self, root: Path, cipher: EnvelopeCipher) -> None:
        self._root = root
        self._tmp = root / "tmp"
        self._cipher = cipher
        for directory in (root, self._tmp, *(root / t for t in TOPS)):
            self._mkdir_durable(directory)

    @property
    def root(self) -> Path:
        return self._root

    def _mkdir_durable(self, directory: Path) -> None:
        if directory.is_dir():
            if stat.S_IMODE(directory.stat().st_mode) & 0o077:
                directory.chmod(_DIR_MODE)
            return
        if directory != self._root and not directory.parent.is_dir():
            self._mkdir_durable(directory.parent)
        try:
            directory.mkdir(mode=_DIR_MODE)
        except FileExistsError:
            return
        fsync_dir(directory)
        fsync_dir(directory.parent)

    def path(self, relpath: str) -> Path:
        parts = relpath.split("/")
        if not parts or not all(_SEGMENT.fullmatch(p) for p in parts) or parts[0] not in TOPS:
            raise ValueError("invalid blob path")
        return self._root.joinpath(*parts)

    def _write_temp(self, sealed: bytes) -> Path:
        tmp = self._tmp / f"{os.getpid()}-{os.urandom(8).hex()}.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb", closefd=True) as fh:
            fh.write(sealed)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, _FILE_MODE)
        return tmp

    def put(self, relpath: str, kind: EnvelopeKind, plaintext: bytes, aad: AadContext) -> str:
        """Publish ``plaintext`` sealed under ``relpath``; returns its SHA-256 (hex)."""
        final = self.path(relpath)
        digest = hashlib.sha256(plaintext).hexdigest()
        if final.exists():
            self._require_same(final, kind, aad, digest)
            self.ensure_durable(relpath)
            return digest
        self._mkdir_durable(final.parent)
        tmp = self._write_temp(self._cipher.seal(kind, plaintext, aad))
        try:
            try:
                os.link(tmp, final)
            except FileExistsError:
                self._require_same(final, kind, aad, digest)
            fsync_dir(final.parent)
        finally:
            with contextlib.suppress(FileNotFoundError):
                tmp.unlink()
        return digest

    def ensure_durable(self, relpath: str) -> None:
        final = self.path(relpath)
        fsync_file(final)
        fsync_dir(final.parent)

    def _require_same(self, final: Path, kind: EnvelopeKind, aad: AadContext, digest: str) -> None:
        existing = self._cipher.open(kind, final.read_bytes(), aad)
        if hashlib.sha256(existing).hexdigest() != digest:
            raise StateIntegrityError("immutable blob already exists with different content")

    def get(self, relpath: str, kind: EnvelopeKind, aad: AadContext) -> bytes:
        try:
            data = self.path(relpath).read_bytes()
        except FileNotFoundError:
            raise StateIntegrityError("blob missing") from None
        return self._cipher.open(kind, data, aad)

    def exists(self, relpath: str) -> bool:
        return self.path(relpath).exists()

    def key_id(self, relpath: str) -> str:
        with self.path(relpath).open("rb") as fh:
            head = fh.read(256)
        return parse_envelope(head).key_id

    def delete(self, relpath: str) -> None:
        path = self.path(relpath)
        with contextlib.suppress(FileNotFoundError):
            path.unlink()
        if path.parent.exists():
            fsync_dir(path.parent)

    def replace(self, relpath: str, kind: EnvelopeKind, plaintext: bytes, aad: AadContext) -> None:
        """Re-seal an existing blob (key rotation): atomic rename over the old file."""
        final = self.path(relpath)
        tmp = self._write_temp(self._cipher.seal(kind, plaintext, aad))
        os.replace(tmp, final)
        fsync_dir(final.parent)

    def all_blobs(self) -> list[str]:
        out: list[str] = []
        for top in TOPS:
            for path in (self._root / top).rglob("*"):
                if path.is_file():
                    out.append(path.relative_to(self._root).as_posix())
        return sorted(out)

    def mtime(self, relpath: str) -> float:
        return self.path(relpath).stat().st_mtime

    def stale_temporaries(self, older_than_epoch: float) -> list[Path]:
        return [p for p in self._tmp.iterdir() if p.is_file() and p.stat().st_mtime < older_than_epoch]
