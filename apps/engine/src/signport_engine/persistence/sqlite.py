# SPDX-License-Identifier: AGPL-3.0-or-later
"""SQLite implementation of PreparationRepository (E3/E4; review REV-01..REV-14).

Pragmas: journal_mode=WAL (verified), synchronous=FULL, foreign_keys=ON, secure_delete=ON,
busy_timeout (default 5000 ms). One short-lived connection per operation. Reads run in an
explicit read transaction (one consistent WAL snapshot for row + events, REV-03); writes use
BEGIN IMMEDIATE so compare-and-set transitions are serialized.

Integrity (all HMAC-SHA256 with the metadata subkey):
- ``row_mac`` over every column of a preparation;
- ``chain_mac`` chaining every event; reads verify the chain ends at the row's version/status;
- ``nonce_counters.mac`` over (installation, key id, key fingerprint, purpose, counter);
- ``key_registry`` binds key id <-> non-secret key fingerprint (no secret stored).
Limits (documented, REV-02/REV-04): these detect tampering and inconsistent partial
rollback. They do NOT detect a coordinated restore of authenticated rows (e.g. a
preparation together with its earlier event chain, or older counter rows), nor a restore
of the whole database. Mitigation: controlled restore procedure with key rotation.

Limitations: single host, local filesystem only (no NFS/SMB: WAL needs shared memory),
one writer at a time. Deleted rows are overwritten in the main file (secure_delete) but
may persist in the WAL until checkpoint, in backups and in storage remanence (REV-11).
"""

import contextlib
import dataclasses
import datetime as dt
import hashlib
import hmac
import json
import sqlite3
from collections.abc import Callable, Generator
from pathlib import Path
from typing import Any

from signport_engine.clock import Clock, SystemClock, from_rfc3339, to_rfc3339
from signport_engine.crypto.envelope import NonceReservation
from signport_engine.crypto.keys import Keyring, Purpose
from signport_engine.errors import ConfigurationError, EngineError, ErrorCode, StateIntegrityError
from signport_engine.persistence.repository import (
    TERMINAL,
    ArtifactInfo,
    ClaimKind,
    ClaimOutcome,
    FencingToken,
    PreparationRecord,
    PreparationStatus,
    RegistryState,
)

_GENESIS = bytes(32)
_UNSAFE_FILESYSTEMS = frozenset(
    {"nfs", "nfs4", "cifs", "smb3", "smbfs", "fuse.sshfs", "9p", "afs", "glusterfs"}
)

# Pre-release initial schema (no public release yet, so v1 is still the baseline).
MIGRATIONS: tuple[str, ...] = (
    """
    CREATE TABLE engine_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL) STRICT;
    CREATE TABLE key_registry (
      key_id TEXT PRIMARY KEY,
      fingerprint TEXT NOT NULL UNIQUE,
      first_seen_at TEXT NOT NULL,
      retired_at TEXT,
      mac BLOB NOT NULL
    ) STRICT;
    CREATE TABLE preparations (
      preparation_id TEXT PRIMARY KEY,
      status TEXT NOT NULL CHECK (status IN
        ('prepared','completing','completed','cancelled','expired','failed')),
      state_version INTEGER NOT NULL CHECK (state_version >= 1),
      document_version_id TEXT NOT NULL,
      document_sha256 TEXT NOT NULL,
      certificate_sha256 TEXT NOT NULL,
      prepared_pdf_sha256 TEXT NOT NULL,
      byte_range_digest_b64 TEXT NOT NULL,
      signed_attributes_digest_b64 TEXT NOT NULL,
      digest_algorithm TEXT NOT NULL,
      signature_algorithm TEXT NOT NULL,
      policy TEXT NOT NULL,
      created_at TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      state_envelope BLOB,
      state_key_id TEXT,
      prepared_blob TEXT,
      prepared_key_id TEXT,
      lease_owner TEXT,
      lease_expires_at TEXT,
      completion_binding TEXT,
      completion_attempt_id TEXT,
      artifact_ref TEXT,
      artifact_sha256 TEXT,
      artifact_size INTEGER,
      artifact_key_id TEXT,
      artifact_removed_at TEXT,
      terminal_at TEXT,
      failure_reason TEXT,
      mac_key_id TEXT NOT NULL,
      row_mac BLOB NOT NULL
    ) STRICT;
    CREATE INDEX preparations_status_expires ON preparations(status, expires_at);
    CREATE INDEX preparations_status_terminal ON preparations(status, terminal_at);
    CREATE TABLE preparation_events (
      preparation_id TEXT NOT NULL REFERENCES preparations(preparation_id) ON DELETE CASCADE,
      seq INTEGER NOT NULL,
      from_status TEXT,
      to_status TEXT NOT NULL,
      reason TEXT,
      at TEXT NOT NULL,
      mac_key_id TEXT NOT NULL,
      chain_mac BLOB NOT NULL,
      PRIMARY KEY (preparation_id, seq)
    ) STRICT;
    CREATE TABLE nonce_counters (
      key_id TEXT NOT NULL REFERENCES key_registry(key_id),
      purpose TEXT NOT NULL,
      next_counter INTEGER NOT NULL CHECK (next_counter >= 0),
      mac BLOB NOT NULL,
      PRIMARY KEY (key_id, purpose)
    ) STRICT;
    CREATE TABLE blob_intents (path TEXT PRIMARY KEY, created_at TEXT NOT NULL) STRICT;
    """,
)

_COLUMNS = [f.name for f in dataclasses.fields(PreparationRecord)]
_INSERT_COLUMNS = ", ".join([*_COLUMNS, "mac_key_id", "row_mac"])
_TIME_FIELDS = {
    "created_at",
    "expires_at",
    "updated_at",
    "lease_expires_at",
    "artifact_removed_at",
    "terminal_at",
}
_PREP_SELECT = "SELECT * FROM preparations WHERE preparation_id = ?"
_ENVELOPE_PURPOSES = (Purpose.STATE, Purpose.ARTIFACT)


def ensure_local_filesystem(path: Path, mountinfo: Path = Path("/proc/self/mountinfo")) -> None:
    """Refuse network filesystems for the WAL database (best effort, Linux)."""
    try:
        lines = mountinfo.read_text().splitlines()
    except OSError:
        return
    target, best, fstype = str(path.resolve()), "", ""
    for line in lines:
        left, _, right = line.partition(" - ")
        fields = left.split()
        if len(fields) < 5 or not right:
            continue
        mount_point = fields[4]
        inside = target == mount_point or target.startswith(mount_point.rstrip("/") + "/")
        if inside and len(mount_point) > len(best):
            best, fstype = mount_point, right.split()[0]
    if fstype in _UNSAFE_FILESYSTEMS:
        raise ConfigurationError(
            f"ENGINE_DATA_DIR is on a network filesystem ({fstype}); SQLite WAL needs local storage"
        )


@contextlib.contextmanager
def _db_errors() -> Generator[None]:
    """Normalize SQLite errors (REV-14): busy/locked/I/O -> SERVICE_UNAVAILABLE; corruption -> integrity."""
    try:
        yield
    except sqlite3.OperationalError:
        raise EngineError(
            ErrorCode.SERVICE_UNAVAILABLE, "Engine storage is busy or unavailable; retry later."
        ) from None
    except sqlite3.DatabaseError:
        raise StateIntegrityError("database error") from None


class _Macs:
    def __init__(self, keyring: Keyring) -> None:
        self._keyring = keyring

    @property
    def active_key_id(self) -> str:
        return self._keyring.active_key_id

    def tag(self, key_id: str, label: bytes, data: bytes) -> bytes:
        if not self._keyring.has(key_id):
            raise StateIntegrityError("metadata MAC key id not in keyring")
        return hmac.new(
            self._keyring.subkey(key_id, Purpose.METADATA_MAC), label + data, hashlib.sha256
        ).digest()

    def verify(self, key_id: str, label: bytes, data: bytes, tag: bytes) -> None:
        if not hmac.compare_digest(self.tag(key_id, label, data), tag):
            raise StateIntegrityError("metadata authentication failed")


def _canonical(values: dict[str, Any]) -> bytes:
    return json.dumps(values, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


class SqlitePreparationRepository(NonceReservation):
    def __init__(
        self,
        db_path: Path,
        *,
        instance_id: str,
        keyring: Keyring,
        busy_timeout_ms: int = 5000,
        clock: Clock | None = None,
    ) -> None:
        if busy_timeout_ms < 0:
            raise ConfigurationError("busy_timeout must be >= 0")
        if keyring.instance_id != instance_id:
            raise ConfigurationError("keyring is bound to a different installation")
        self._path = db_path
        self._instance_id = instance_id
        self._busy_timeout_ms = busy_timeout_ms
        self._keyring = keyring
        self._macs = _Macs(keyring)
        self._clock = clock or SystemClock()
        ensure_local_filesystem(db_path.parent)
        self._initialize()

    # ------------------------------------------------------------------ connections
    def _connect(self) -> sqlite3.Connection:
        with _db_errors():
            conn = sqlite3.connect(self._path, isolation_level=None, timeout=self._busy_timeout_ms / 1000)
            try:
                conn.row_factory = sqlite3.Row
                conn.execute(f"PRAGMA busy_timeout = {int(self._busy_timeout_ms)}")
                conn.execute("PRAGMA foreign_keys = ON")
                conn.execute("PRAGMA synchronous = FULL")
                conn.execute("PRAGMA secure_delete = ON")
            except BaseException:
                conn.close()  # never leak a connection when the database cannot be configured
                raise
            return conn

    @contextlib.contextmanager
    def _transaction(self, begin: str) -> Generator[sqlite3.Connection]:
        conn = self._connect()
        try:
            with _db_errors():
                conn.execute(begin)
            try:
                yield conn
            except BaseException:
                with contextlib.suppress(sqlite3.Error):
                    conn.execute("ROLLBACK")
                raise
            with _db_errors():
                try:
                    conn.execute("COMMIT")
                except sqlite3.Error:
                    with contextlib.suppress(sqlite3.Error):
                        conn.execute("ROLLBACK")
                    raise
        finally:
            conn.close()

    def _tx(self) -> contextlib.AbstractContextManager[sqlite3.Connection]:
        return self._transaction("BEGIN IMMEDIATE")

    def _read(self) -> contextlib.AbstractContextManager[sqlite3.Connection]:
        """One consistent snapshot for related queries (REV-03)."""
        return self._transaction("BEGIN DEFERRED")

    def _rows(self, sql: str, params: tuple[Any, ...]) -> list[Any]:
        with self._read() as conn, _db_errors():
            return list(conn.execute(sql, params))

    def _initialize(self) -> None:
        conn = self._connect()
        try:
            with _db_errors():
                mode = conn.execute("PRAGMA journal_mode = WAL").fetchone()[0]
            if str(mode).lower() != "wal":
                raise ConfigurationError("SQLite WAL journal mode is unavailable on this filesystem")
        finally:
            conn.close()
        with self._tx() as conn, _db_errors():
            conn.execute(
                "CREATE TABLE IF NOT EXISTS schema_migrations "
                "(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL) STRICT"
            )
            applied = {r[0] for r in conn.execute("SELECT version FROM schema_migrations")}
            for version, sql in enumerate(MIGRATIONS, start=1):
                if version not in applied:
                    for statement in filter(str.strip, sql.split(";")):
                        conn.execute(statement)
                    conn.execute(
                        "INSERT INTO schema_migrations VALUES (?, ?)",
                        (version, to_rfc3339(dt.datetime.now(dt.UTC))),
                    )
            row = conn.execute("SELECT value FROM engine_meta WHERE key = 'instance_id'").fetchone()
            if row is None:
                conn.execute("INSERT INTO engine_meta VALUES ('instance_id', ?)", (self._instance_id,))
            elif row[0] != self._instance_id:
                raise ConfigurationError(
                    "ENGINE_INSTANCE_ID does not match the one bound to this data directory"
                )

    def schema_version(self) -> int:
        return int(self._rows("SELECT max(version) FROM schema_migrations", ())[0][0])

    def pragmas(self) -> dict[str, object]:
        conn = self._connect()
        try:
            with _db_errors():
                return {
                    name: conn.execute(f"PRAGMA {name}").fetchone()[0]
                    for name in (
                        "journal_mode",
                        "synchronous",
                        "foreign_keys",
                        "busy_timeout",
                        "secure_delete",
                    )
                }
        finally:
            conn.close()

    # ------------------------------------------------------------------ key registry (REV-02, REV-15, REV-17)
    def _registry_mac(self, key_id: str, fingerprint: str, first_seen: str, retired: str | None) -> bytes:
        data = _canonical(
            {"i": self._instance_id, "k": key_id, "f": fingerprint, "s": first_seen, "r": retired}
        )
        return self._macs.tag(key_id, b"key-registry\x00", data)

    @staticmethod
    def _registry_contents(conn: sqlite3.Connection) -> tuple[list[list[Any]], list[list[str]]]:
        entries = [
            [r["key_id"], r["fingerprint"], r["first_seen_at"], r["retired_at"]]
            for r in conn.execute("SELECT * FROM key_registry ORDER BY key_id")
        ]
        counters = [
            [r[0], r[1]] for r in conn.execute("SELECT key_id, purpose FROM nonce_counters ORDER BY 1, 2")
        ]
        return entries, counters

    def _write_catalog(self, conn: sqlite3.Connection, generation: int, active_key_id: str) -> None:
        """REV-15: one catalog of the WHOLE key history (retired keys included), authenticated by the
        active key's metadata subkey and re-authenticated on every registry change. It lists every
        registry entry and every nonce counter row, so removing or altering one in isolation is
        detected even after the retired key's material left the keyring. A coordinated rollback of
        the catalog together with the rows it lists is NOT detected (accepted risk, REV-04)."""
        entries, counters = self._registry_contents(conn)
        doc = {
            "v": 1,
            "i": self._instance_id,
            "g": generation,
            "a": active_key_id,
            "k": active_key_id,
            "e": entries,
            "c": counters,
        }
        mac = self._macs.tag(active_key_id, b"key-catalog\x00", _canonical(doc))
        conn.execute(
            "INSERT INTO engine_meta VALUES ('key_catalog', ?) "
            "ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            (json.dumps({"doc": doc, "mac": mac.hex()}, sort_keys=True),),
        )

    def _verify_catalog(self, conn: sqlite3.Connection) -> dict[str, Any] | None:
        """The verified catalog, or None for a brand-new data directory (never for lost history)."""
        row = conn.execute("SELECT value FROM engine_meta WHERE key = 'key_catalog'").fetchone()
        if row is None:
            used = any(
                conn.execute(f"SELECT 1 FROM {table} LIMIT 1").fetchone()  # noqa: S608 - fixed names
                for table in ("key_registry", "nonce_counters", "preparations")
            )
            if used:
                raise StateIntegrityError("key catalog is missing")
            return None
        try:
            stored = json.loads(row[0])
            doc, mac = stored["doc"], bytes.fromhex(stored["mac"])
            mac_key = doc["k"]
        except (ValueError, KeyError, TypeError):
            raise StateIntegrityError("key catalog is malformed") from None
        if not isinstance(mac_key, str) or not self._keyring.has(mac_key):
            raise ConfigurationError("the key registry is authenticated by a key missing from the keyring")
        self._macs.verify(mac_key, b"key-catalog\x00", _canonical(doc), mac)
        entries, counters = self._registry_contents(conn)
        if doc.get("i") != self._instance_id or doc.get("e") != entries or doc.get("c") != counters:
            raise StateIntegrityError("key registry does not match its authenticated catalog")
        return dict(doc)

    def _check_keyring(self, conn: sqlite3.Connection, keyring: Keyring) -> bool:
        """Validate the keyring against the verified registry. True when no change is needed."""
        rows = {r["key_id"]: r for r in conn.execute("SELECT * FROM key_registry")}
        by_fp = {r["fingerprint"]: r["key_id"] for r in rows.values()}
        current = True
        for kid in sorted(keyring.key_ids):
            fp = keyring.fingerprint(kid)
            row = rows.get(kid)
            if row is None:
                if fp in by_fp:
                    raise ConfigurationError("key material was previously registered under another key id")
                current = False
                continue
            if row["fingerprint"] != fp:
                raise ConfigurationError("key id is registered with different key material")
            expected = self._registry_mac(kid, fp, row["first_seen_at"], row["retired_at"])
            if not hmac.compare_digest(expected, row["mac"]):
                raise StateIntegrityError("key registry entry failed authentication")
        active = rows.get(keyring.active_key_id)
        if active is not None and active["retired_at"] is not None:
            raise ConfigurationError("the active key id was retired and cannot be used again")
        # Identity errors above are reported first (clearer diagnostics); every path fails closed.
        doc = self._verify_catalog(conn)
        return current and doc is not None and doc["a"] == keyring.active_key_id

    def verify_key_registry(self, keyring: Keyring) -> bool:
        """Read-only startup check (REV-17); True when the registry already matches the keyring."""
        with self._read() as conn, _db_errors():
            current = self._check_keyring(conn, keyring)
        missing = self.key_ids_referenced() - keyring.key_ids
        if missing:
            raise ConfigurationError(
                "persisted data is sealed or authenticated with keys missing from the keyring"
            )
        return current

    def sync_key_registry(self, keyring: Keyring, *, now: dt.datetime) -> None:
        """Register new keys (with their nonce counters, REV-18) and the active key, bumping the
        authenticated generation. Callers hold the EXCLUSIVE maintenance lock (REV-17)."""
        with self._tx() as conn, _db_errors():
            if self._check_keyring(conn, keyring):
                return
            doc = self._verify_catalog(conn)
            registered = {r[0] for r in conn.execute("SELECT key_id FROM key_registry")}
            first = to_rfc3339(now)
            for kid in sorted(keyring.key_ids - registered):
                fp = keyring.fingerprint(kid)
                conn.execute(
                    "INSERT INTO key_registry VALUES (?, ?, ?, NULL, ?)",
                    (kid, fp, first, self._registry_mac(kid, fp, first, None)),
                )
                for purpose in _ENVELOPE_PURPOSES:
                    conn.execute(
                        "INSERT INTO nonce_counters VALUES (?, ?, 0, ?)",
                        (kid, purpose.value, self._counter_mac(kid, fp, purpose.value, 0)),
                    )
            self._write_catalog(conn, (doc["g"] if doc else 0) + 1, keyring.active_key_id)
        if not self.verify_key_registry(keyring):
            raise StateIntegrityError("key registry did not converge")

    def registry_state(self) -> RegistryState:
        """The verified registry (REV-15): generation, active key and the full key history."""
        with self._read() as conn, _db_errors():
            doc = self._verify_catalog(conn)
        if doc is None:
            raise StateIntegrityError("key registry was never initialized")
        return RegistryState(
            generation=int(doc["g"]),
            active_key_id=str(doc["a"]),
            keys={e[0]: (from_rfc3339(e[3]) if e[3] else None) for e in doc["e"]},
        )

    def retire_key(self, key_id: str, *, now: dt.datetime) -> None:
        """Callers hold the exclusive maintenance lock. History is kept; the generation is bumped."""
        with self._tx() as conn, _db_errors():
            doc = self._verify_catalog(conn)
            if doc is None:
                raise StateIntegrityError("key registry was never initialized")
            row = conn.execute("SELECT * FROM key_registry WHERE key_id = ?", (key_id,)).fetchone()
            if row is None:
                raise ConfigurationError("unknown key id")
            if row["retired_at"] is not None:
                return
            if key_id == doc["a"]:
                raise ConfigurationError("the active key cannot be retired")
            retired = to_rfc3339(now)
            conn.execute(
                "UPDATE key_registry SET retired_at = ?, mac = ? WHERE key_id = ?",
                (
                    retired,
                    self._registry_mac(key_id, row["fingerprint"], row["first_seen_at"], retired),
                    key_id,
                ),
            )
            self._write_catalog(conn, int(doc["g"]) + 1, str(doc["a"]))

    def registered_keys(self) -> dict[str, dt.datetime | None]:
        return dict(self.registry_state().keys)

    # ------------------------------------------------------------------ nonce reservation (REV-02)
    def _counter_mac(self, key_id: str, fingerprint: str, purpose: str, value: int) -> bytes:
        data = _canonical({"i": self._instance_id, "k": key_id, "f": fingerprint, "p": purpose, "n": value})
        return self._macs.tag(key_id, b"nonce-counter\x00", data)

    def reserve_nonce_block(self, key_id: str, purpose: Purpose, size: int) -> int:
        if size < 1:
            raise ValueError("size must be positive")
        with self._tx() as conn, _db_errors():
            reg = conn.execute(
                "SELECT fingerprint, retired_at FROM key_registry WHERE key_id = ?", (key_id,)
            ).fetchone()
            if reg is None or reg["retired_at"] is not None:
                raise StateIntegrityError("encryption key is not registered or was retired")
            if reg["fingerprint"] != self._keyring.fingerprint(key_id):
                raise StateIntegrityError("encryption key does not match its registered identity")
            row = conn.execute(
                "SELECT next_counter, mac FROM nonce_counters WHERE key_id = ? AND purpose = ?",
                (key_id, purpose.value),
            ).fetchone()
            if row is None:  # created with the key (REV-18): absence means loss or tampering
                raise StateIntegrityError("nonce counter is missing")
            current = int(row["next_counter"])
            self._macs.verify(
                key_id,
                b"nonce-counter\x00",
                _canonical(
                    {
                        "i": self._instance_id,
                        "k": key_id,
                        "f": reg["fingerprint"],
                        "p": purpose.value,
                        "n": current,
                    }
                ),
                row["mac"],
            )
            nxt = current + size
            conn.execute(
                "UPDATE nonce_counters SET next_counter = ?, mac = ? WHERE key_id = ? AND purpose = ?",
                (
                    nxt,
                    self._counter_mac(key_id, reg["fingerprint"], purpose.value, nxt),
                    key_id,
                    purpose.value,
                ),
            )
        return current

    def nonce_key_ids(self) -> set[str]:
        """Keys that ever reserved a nonce block (counter rows exist from registration at 0)."""
        return {
            r[0] for r in self._rows("SELECT DISTINCT key_id FROM nonce_counters WHERE next_counter > 0", ())
        }

    def key_ids_referenced(self) -> set[str]:
        ids: set[str] = set()
        with self._read() as conn, _db_errors():
            for col in ("state_key_id", "prepared_key_id", "mac_key_id"):
                ids |= {
                    r[0]
                    # fixed column names from the tuple above, never input
                    for r in conn.execute(f"SELECT DISTINCT {col} FROM preparations WHERE {col} IS NOT NULL")  # noqa: S608
                }
            ids |= {
                r[0]
                for r in conn.execute(
                    "SELECT DISTINCT artifact_key_id FROM preparations "
                    "WHERE artifact_key_id IS NOT NULL AND artifact_removed_at IS NULL"
                )
            }
            ids |= {r[0] for r in conn.execute("SELECT DISTINCT mac_key_id FROM preparation_events")}
        return ids

    # ------------------------------------------------------------------ rows, MACs and the event chain
    def _row_values(self, record: PreparationRecord) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for name in _COLUMNS:
            value = getattr(record, name)
            if name in _TIME_FIELDS and value is not None:
                value = to_rfc3339(value)
            elif isinstance(value, bytes):
                value = hashlib.sha256(value).hexdigest()
            elif isinstance(value, PreparationStatus):
                value = value.value
            out[name] = value
        out["__instance_id"] = self._instance_id
        return out

    def _from_row(self, row: sqlite3.Row) -> PreparationRecord:
        kwargs: dict[str, Any] = {}
        for name in _COLUMNS:
            value = row[name]
            if name in _TIME_FIELDS and value is not None:
                value = from_rfc3339(value)
            if name == "status":
                value = PreparationStatus(value)
            kwargs[name] = value
        record = PreparationRecord(**kwargs)
        self._macs.verify(row["mac_key_id"], b"row\x00", _canonical(self._row_values(record)), row["row_mac"])
        return record

    def _event_bytes(self, preparation_id: str, seq: int, ev: sqlite3.Row | dict[str, Any]) -> bytes:
        return _canonical(
            {
                "instance": self._instance_id,
                "preparation_id": preparation_id,
                "seq": seq,
                "from": ev["from_status"],
                "to": ev["to_status"],
                "reason": ev["reason"],
                "at": ev["at"],
            }
        )

    def _verify_chain(self, conn: sqlite3.Connection, record: PreparationRecord) -> bytes:
        events = conn.execute(
            "SELECT * FROM preparation_events WHERE preparation_id = ? ORDER BY seq", (record.preparation_id,)
        ).fetchall()
        prev = _GENESIS
        for expected_seq, ev in enumerate(events, start=1):
            if ev["seq"] != expected_seq:
                raise StateIntegrityError("event chain has gaps")
            data = prev + self._event_bytes(record.preparation_id, ev["seq"], ev)
            self._macs.verify(ev["mac_key_id"], b"event\x00", data, ev["chain_mac"])
            prev = ev["chain_mac"]
        if (
            not events
            or len(events) != record.state_version
            or events[-1]["to_status"] != record.status.value
        ):
            raise StateIntegrityError(
                "event chain does not match the row (inconsistent rollback or tampering)"
            )
        return prev

    def _load(self, conn: sqlite3.Connection, preparation_id: str) -> tuple[PreparationRecord, bytes]:
        row = conn.execute(_PREP_SELECT, (preparation_id,)).fetchone()
        if row is None:
            raise EngineError(ErrorCode.NOT_FOUND, "Preparation not found.")
        record = self._from_row(row)
        return record, self._verify_chain(conn, record)

    def _append_event(
        self,
        conn: sqlite3.Connection,
        record: PreparationRecord,
        prev_mac: bytes,
        from_status: PreparationStatus | None,
        reason: str | None,
    ) -> None:
        ev = {
            "from_status": from_status.value if from_status else None,
            "to_status": record.status.value,
            "reason": reason,
            "at": to_rfc3339(record.updated_at),
        }
        key_id = self._macs.active_key_id
        data = prev_mac + self._event_bytes(record.preparation_id, record.state_version, ev)
        conn.execute(
            "INSERT INTO preparation_events VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                record.preparation_id,
                record.state_version,
                ev["from_status"],
                ev["to_status"],
                reason,
                ev["at"],
                key_id,
                self._macs.tag(key_id, b"event\x00", data),
            ),
        )

    def _db_values(self, record: PreparationRecord) -> list[Any]:
        values: list[Any] = []
        for name in _COLUMNS:
            value = getattr(record, name)
            if name in _TIME_FIELDS and value is not None:
                value = to_rfc3339(value)
            elif isinstance(value, PreparationStatus):
                value = value.value
            values.append(value)
        key_id = self._macs.active_key_id
        return [*values, key_id, self._macs.tag(key_id, b"row\x00", _canonical(self._row_values(record)))]

    def _write(self, conn: sqlite3.Connection, old: PreparationRecord, new: PreparationRecord) -> None:
        assignments = ", ".join(f"{c} = ?" for c in [*_COLUMNS, "mac_key_id", "row_mac"])
        cur = conn.execute(
            f"UPDATE preparations SET {assignments} WHERE preparation_id = ? AND state_version = ?",  # noqa: S608
            [*self._db_values(new), old.preparation_id, old.state_version],
        )
        if cur.rowcount != 1:
            raise StateIntegrityError("concurrent modification detected")

    def _transition(
        self,
        conn: sqlite3.Connection,
        old: PreparationRecord,
        prev_mac: bytes,
        *,
        to: PreparationStatus,
        now: dt.datetime,
        reason: str | None = None,
        **changes: Any,
    ) -> PreparationRecord:
        if old.status in TERMINAL and to is not old.status:
            raise StateIntegrityError("terminal states never change")
        if to in TERMINAL and old.status not in TERMINAL:
            changes.setdefault("terminal_at", now)
        new = dataclasses.replace(
            old, status=to, state_version=old.state_version + 1, updated_at=now, **changes
        )
        self._write(conn, old, new)
        self._append_event(conn, new, prev_mac, old.status, reason)
        return new

    def _rechain(self, conn: sqlite3.Connection, preparation_id: str) -> bytes:
        """Re-authenticate an already verified event chain with the active key (rotation)."""
        events = conn.execute(
            "SELECT * FROM preparation_events WHERE preparation_id = ? ORDER BY seq", (preparation_id,)
        ).fetchall()
        prev, key_id = _GENESIS, self._macs.active_key_id
        for ev in events:
            mac = self._macs.tag(
                key_id, b"event\x00", prev + self._event_bytes(preparation_id, ev["seq"], ev)
            )
            conn.execute(
                "UPDATE preparation_events SET mac_key_id = ?, chain_mac = ? "
                "WHERE preparation_id = ? AND seq = ?",
                (key_id, mac, preparation_id, ev["seq"]),
            )
            prev = mac
        return prev

    def _update_in_place(
        self, preparation_id: str, now: dt.datetime, *, reason: str, rechain: bool = False, **changes: Any
    ) -> tuple[PreparationRecord, PreparationRecord]:
        """Non-transition update; returns (old, new). Bumps state_version and appends an event."""
        with self._tx() as conn, _db_errors():
            rec, prev = self._load(conn, preparation_id)
            if rechain:
                prev = self._rechain(conn, preparation_id)
            return rec, self._transition(conn, rec, prev, to=rec.status, now=now, reason=reason, **changes)

    # ------------------------------------------------------------------ lifecycle
    def register_intent(self, relpath: str, *, now: dt.datetime) -> None:
        with self._tx() as conn, _db_errors():
            conn.execute("INSERT INTO blob_intents VALUES (?, ?)", (relpath, to_rfc3339(now)))

    def create(self, record: PreparationRecord, *, intent: str) -> None:
        if record.status is not PreparationStatus.PREPARED or record.state_version != 1:
            raise ValueError("new preparations start as prepared/v1")
        placeholders = ", ".join("?" for _ in range(len(_COLUMNS) + 2))
        with self._tx() as conn:
            try:
                conn.execute(
                    f"INSERT INTO preparations ({_INSERT_COLUMNS}) VALUES ({placeholders})",  # noqa: S608
                    self._db_values(record),
                )
            except sqlite3.IntegrityError:
                raise EngineError(ErrorCode.CONFLICT, "Preparation already exists.") from None
            with _db_errors():
                # The file is only protected by its intent until this commit: if cleanup removed the
                # intent (and therefore possibly the file), never create a dangling reference (REV-07).
                cur = conn.execute("DELETE FROM blob_intents WHERE path = ?", (intent,))
                if cur.rowcount != 1:
                    raise EngineError(ErrorCode.SERVICE_UNAVAILABLE, "Preparation raced with cleanup; retry.")
                self._append_event(conn, record, _GENESIS, None, "created")

    def get(self, preparation_id: str) -> PreparationRecord:
        with self._read() as conn, _db_errors():
            return self._load(conn, preparation_id)[0]

    def claim_completion(
        self,
        preparation_id: str,
        *,
        binding: str,
        attempt_id: str,
        owner: str,
        deadline: dt.datetime,
        lease: dt.timedelta | None = None,
        lease_until: dt.datetime | None = None,
        now: dt.datetime | None = None,
    ) -> ClaimOutcome:
        """``now`` defaults to the clock read AFTER the write lock is acquired (REV-19), so a long
        wait for the lock never yields a stale timestamp. The lease never outlives ``deadline``."""
        if (lease is None) == (lease_until is None):
            raise ValueError("pass exactly one of lease / lease_until")
        with self._tx() as conn, _db_errors():
            now = now or self._clock.now()
            lease_until = min(lease_until or now + (lease or dt.timedelta()), deadline)
            rec, prev = self._load(conn, preparation_id)
            if rec.status is PreparationStatus.PREPARED:
                if now >= rec.expires_at:  # first signature after expiry is always rejected (REV-09)
                    new = self._transition(
                        conn, rec, prev, to=PreparationStatus.EXPIRED, now=now, reason="expired"
                    )
                    return ClaimOutcome(ClaimKind.EXPIRED, new)
                new = self._transition(
                    conn,
                    rec,
                    prev,
                    to=PreparationStatus.COMPLETING,
                    now=now,
                    reason="claimed",
                    lease_owner=owner,
                    lease_expires_at=lease_until,
                    completion_binding=binding,
                    completion_attempt_id=attempt_id,
                )
                return ClaimOutcome(ClaimKind.CLAIMED, new)
            if rec.completion_binding != binding:
                return ClaimOutcome(ClaimKind.CONFLICT, rec)
            if rec.status is PreparationStatus.COMPLETED:
                return ClaimOutcome(ClaimKind.ALREADY_COMPLETED, rec)
            if rec.status is PreparationStatus.COMPLETING:
                if rec.lease_expires_at is None:
                    raise StateIntegrityError("completing preparation without a lease")
                if now >= deadline:  # no indefinite takeover (REV-09)
                    new = self._transition(
                        conn,
                        rec,
                        prev,
                        to=PreparationStatus.FAILED,
                        now=now,
                        reason="expired_during_completion",
                        lease_owner=None,
                        lease_expires_at=None,
                        failure_reason="expired_during_completion",
                    )
                    return ClaimOutcome(ClaimKind.DEADLINE_PASSED, new)
                if now < rec.lease_expires_at:
                    return ClaimOutcome(ClaimKind.IN_PROGRESS, rec)
                new = self._transition(
                    conn,
                    rec,
                    prev,
                    to=PreparationStatus.COMPLETING,
                    now=now,
                    reason="lease_taken_over",
                    lease_owner=owner,
                    lease_expires_at=lease_until,
                )
                return ClaimOutcome(ClaimKind.TAKEN_OVER, new)
            return ClaimOutcome(ClaimKind.CONFLICT, rec)

    def _require_fence(
        self,
        rec: PreparationRecord,
        token: FencingToken,
        now: dt.datetime,
        deadline: dt.datetime | None = None,
    ) -> None:
        """REV-06: only the live lease holder at the exact claimed version may commit.
        REV-19: and never at or after the completion deadline, whatever the lease says."""
        valid = (
            rec.status is PreparationStatus.COMPLETING
            and rec.lease_owner == token.owner
            and rec.state_version == token.state_version
            and rec.lease_expires_at is not None
            and now < rec.lease_expires_at
            and (deadline is None or now < deadline)
        )
        if not valid:
            raise EngineError(ErrorCode.CONFLICT, "Completion lease is no longer held by this request.")

    def mark_completed(
        self,
        preparation_id: str,
        *,
        token: FencingToken,
        binding: str,
        artifact: ArtifactInfo,
        deadline: dt.datetime,
        now: dt.datetime | None = None,
    ) -> PreparationRecord:
        with self._tx() as conn, _db_errors():
            now = now or self._clock.now()  # read after the write lock is held (REV-19)
            rec, prev = self._load(conn, preparation_id)
            if rec.completion_binding != binding:
                raise EngineError(ErrorCode.CONFLICT, "Preparation is bound to a different completion.")
            self._require_fence(rec, token, now, deadline)
            return self._transition(
                conn,
                rec,
                prev,
                to=PreparationStatus.COMPLETED,
                now=now,
                reason="completed",
                lease_owner=None,
                lease_expires_at=None,
                artifact_ref=artifact.ref,
                artifact_sha256=artifact.sha256,
                artifact_size=artifact.size,
                artifact_key_id=artifact.key_id,
            )

    def mark_failed(
        self, preparation_id: str, *, token: FencingToken, reason: str, now: dt.datetime
    ) -> PreparationRecord:
        with self._tx() as conn, _db_errors():
            rec, prev = self._load(conn, preparation_id)
            self._require_fence(rec, token, now)
            return self._transition(
                conn,
                rec,
                prev,
                to=PreparationStatus.FAILED,
                now=now,
                reason=reason,
                lease_owner=None,
                lease_expires_at=None,
                failure_reason=reason,
            )

    def cancel(self, preparation_id: str, *, now: dt.datetime) -> PreparationRecord:
        with self._tx() as conn, _db_errors():
            rec, prev = self._load(conn, preparation_id)
            if rec.status is PreparationStatus.CANCELLED:
                return rec
            if rec.status is not PreparationStatus.PREPARED:
                raise EngineError(ErrorCode.CONFLICT, "Only prepared preparations can be cancelled.")
            return self._transition(
                conn, rec, prev, to=PreparationStatus.CANCELLED, now=now, reason="cancelled"
            )

    def _ids(self, sql: str, params: tuple[Any, ...]) -> list[str]:
        return [r[0] for r in self._rows(sql, params)]

    def expire_due(self, *, now: dt.datetime, limit: int) -> list[str]:
        ids = self._ids(
            "SELECT preparation_id FROM preparations WHERE status = 'prepared' AND expires_at <= ? "
            "ORDER BY expires_at LIMIT ?",
            (to_rfc3339(now), limit),
        )
        expired: list[str] = []
        for pid in ids:
            with self._tx() as conn, _db_errors():
                rec, prev = self._load(conn, pid)
                if rec.status is PreparationStatus.PREPARED and rec.expires_at <= now:
                    self._transition(conn, rec, prev, to=PreparationStatus.EXPIRED, now=now, reason="expired")
                    expired.append(pid)
        return expired

    def fail_past_deadline(self, *, now: dt.datetime, grace: dt.timedelta, limit: int) -> list[str]:
        ids = self._ids(
            "SELECT preparation_id FROM preparations WHERE status = 'completing' AND expires_at <= ? "
            "ORDER BY expires_at LIMIT ?",
            (to_rfc3339(now - grace), limit),
        )
        failed: list[str] = []
        for pid in ids:
            with self._tx() as conn, _db_errors():
                rec, prev = self._load(conn, pid)
                if rec.status is PreparationStatus.COMPLETING and now >= rec.expires_at + grace:
                    self._transition(
                        conn,
                        rec,
                        prev,
                        to=PreparationStatus.FAILED,
                        now=now,
                        reason="expired_during_completion",
                        lease_owner=None,
                        lease_expires_at=None,
                        failure_reason="expired_during_completion",
                    )
                    failed.append(pid)
        return failed

    def stale_completing(self, *, now: dt.datetime, limit: int) -> list[str]:
        return self._ids(
            "SELECT preparation_id FROM preparations WHERE status = 'completing' AND lease_expires_at <= ? "
            "ORDER BY lease_expires_at LIMIT ?",
            (to_rfc3339(now), limit),
        )

    # ------------------------------------------------------------------ cleanup selections (REV-07, REV-11)
    def discard_due(self, *, limit: int) -> list[str]:
        return self._ids(
            "SELECT preparation_id FROM preparations "
            "WHERE status IN ('completed','cancelled','expired','failed') "
            "AND (state_envelope IS NOT NULL OR prepared_blob IS NOT NULL) ORDER BY terminal_at LIMIT ?",
            (limit,),
        )

    def discard_sensitive_state(self, preparation_id: str, *, now: dt.datetime) -> PreparationRecord:
        """Logical removal first (references dropped in a transaction); returns the OLD record so the
        caller can delete the files afterwards. A crash in between leaves only unreferenced files."""
        rec = self.get(preparation_id)
        if rec.status not in TERMINAL:
            raise EngineError(
                ErrorCode.CONFLICT, "Only terminal preparations can have their state discarded."
            )
        if rec.state_envelope is None and rec.prepared_blob is None:
            return rec
        old, _ = self._update_in_place(
            preparation_id,
            now,
            reason="sensitive_state_discarded",
            state_envelope=None,
            state_key_id=None,
            prepared_blob=None,
            prepared_key_id=None,
        )
        return old

    def artifacts_due(self, *, terminal_before: dt.datetime, limit: int) -> list[str]:
        return self._ids(
            "SELECT preparation_id FROM preparations WHERE status = 'completed' AND artifact_ref IS NOT NULL "
            "AND artifact_removed_at IS NULL AND terminal_at <= ? ORDER BY terminal_at LIMIT ?",
            (to_rfc3339(terminal_before), limit),
        )

    def remove_artifact(self, preparation_id: str, *, now: dt.datetime) -> PreparationRecord:
        rec = self.get(preparation_id)
        if rec.artifact_ref is None or rec.artifact_removed_at is not None:
            return rec
        old, _ = self._update_in_place(
            preparation_id,
            now,
            reason="artifact_removed_by_retention",
            artifact_removed_at=now,
            artifact_key_id=None,
        )
        return old

    def purge_due(self, *, terminal_before: dt.datetime, limit: int) -> list[str]:
        return self._ids(
            "SELECT preparation_id FROM preparations "
            "WHERE status IN ('completed','cancelled','expired','failed') "
            "AND state_envelope IS NULL AND prepared_blob IS NULL "
            "AND (artifact_ref IS NULL OR artifact_removed_at IS NOT NULL) AND terminal_at <= ? "
            "ORDER BY terminal_at LIMIT ?",
            (to_rfc3339(terminal_before), limit),
        )

    def purge(self, preparation_id: str) -> None:
        with self._tx() as conn, _db_errors():
            rec, _ = self._load(conn, preparation_id)
            removable = rec.artifact_ref is None or rec.artifact_removed_at is not None
            if (
                rec.status not in TERMINAL
                or rec.state_envelope is not None
                or rec.prepared_blob
                or not removable
            ):
                raise EngineError(ErrorCode.CONFLICT, "Only discarded terminal preparations can be purged.")
            conn.execute("DELETE FROM preparations WHERE preparation_id = ?", (preparation_id,))

    def delete_if_unreferenced(
        self, relpath: str, *, intent_older_than: dt.datetime, delete: Callable[[str], None]
    ) -> bool:
        """Physical removal only under the write lock after re-checking every reference (REV-07)."""
        with self._tx() as conn, _db_errors():
            intent = conn.execute("SELECT created_at FROM blob_intents WHERE path = ?", (relpath,)).fetchone()
            if intent is not None:
                if from_rfc3339(intent[0]) > intent_older_than:
                    return False
                conn.execute("DELETE FROM blob_intents WHERE path = ?", (relpath,))
            if conn.execute("SELECT 1 FROM preparations WHERE prepared_blob = ?", (relpath,)).fetchone():
                return False
            parts = relpath.split("/")
            if parts[0] == "artifacts" and len(parts) == 3:
                row = conn.execute(
                    "SELECT status, artifact_ref, artifact_removed_at FROM preparations "
                    "WHERE preparation_id = ?",
                    (parts[1],),
                ).fetchone()
                if row is not None and (
                    row["status"] == "completing"
                    or (row["artifact_ref"] == relpath and row["artifact_removed_at"] is None)
                ):
                    return False
            delete(relpath)
            return True

    # ------------------------------------------------------------------ rotation (REV-01, REV-10)
    def rewrap_candidates(self, *, active_key_id: str, limit: int) -> list[str]:
        """Only rows that actually need rotation, so repeated batches always make progress."""
        return self._ids(
            "SELECT p.preparation_id FROM preparations p WHERE "
            "(p.state_key_id IS NOT NULL AND p.state_key_id != ?1) "
            "OR (p.prepared_key_id IS NOT NULL AND p.prepared_key_id != ?1) "
            "OR (p.artifact_key_id IS NOT NULL AND p.artifact_removed_at IS NULL "
            "AND p.artifact_key_id != ?1) "
            "OR p.mac_key_id != ?1 "
            "OR EXISTS (SELECT 1 FROM preparation_events e WHERE e.preparation_id = p.preparation_id "
            "AND e.mac_key_id != ?1) ORDER BY p.preparation_id LIMIT ?2",
            (active_key_id, limit),
        )

    def replace_sealed(
        self,
        preparation_id: str,
        *,
        expected_version: int,
        state_envelope: bytes | None,
        state_key_id: str | None,
        prepared_key_id: str | None,
        artifact_key_id: str | None,
        now: dt.datetime,
    ) -> PreparationRecord:
        with self._tx() as conn, _db_errors():
            rec, prev = self._load(conn, preparation_id)
            if rec.state_version != expected_version:
                raise EngineError(ErrorCode.CONFLICT, "Preparation changed during rewrap; retry.")
            active = self._macs.active_key_id
            events_current = not conn.execute(
                "SELECT 1 FROM preparation_events WHERE preparation_id = ? AND mac_key_id != ?",
                (preparation_id, active),
            ).fetchone()
            unchanged = (
                state_envelope == rec.state_envelope
                and (state_key_id, prepared_key_id, artifact_key_id)
                == (rec.state_key_id, rec.prepared_key_id, rec.artifact_key_id)
                and conn.execute(
                    "SELECT mac_key_id FROM preparations WHERE preparation_id = ?", (preparation_id,)
                ).fetchone()[0]
                == active
                and events_current
            )
            if unchanged:  # REV-01: no version bump, no event, no updated_at change
                return rec
            prev = self._rechain(conn, preparation_id)
            return self._transition(
                conn,
                rec,
                prev,
                to=rec.status,
                now=now,
                reason="rewrapped",
                state_envelope=state_envelope,
                state_key_id=state_key_id,
                prepared_key_id=prepared_key_id,
                artifact_key_id=artifact_key_id,
            )

    def invalidate_non_terminal(self, *, reason: str, now: dt.datetime) -> list[str]:
        ids = self._ids(
            "SELECT preparation_id FROM preparations WHERE status IN ('prepared','completing')", ()
        )
        for pid in ids:
            with self._tx() as conn, _db_errors():
                rec, prev = self._load(conn, pid)
                if rec.status not in TERMINAL:
                    self._transition(
                        conn,
                        rec,
                        prev,
                        to=PreparationStatus.FAILED,
                        now=now,
                        reason=reason,
                        lease_owner=None,
                        lease_expires_at=None,
                        failure_reason=reason,
                    )
        return ids
