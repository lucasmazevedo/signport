# SPDX-License-Identifier: AGPL-3.0-or-later
"""Storage-independent persistence contract for preparations (E3/E4, review REV-01..REV-12).

Implementations must provide: consistent read snapshots; atomic compare-and-set
transitions fenced by (lease owner, state_version); an append-only authenticated event
chain; durable, authenticated nonce reservation; an authenticated key registry; and
reference checks under the write lock before any physical blob removal. The only
implementation in P1 is SQLite (``persistence.sqlite``); PostgreSQL is a future adapter.
"""

import datetime as dt
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from signport_engine.crypto.envelope import NonceReservation
from signport_engine.crypto.keys import Keyring


class PreparationStatus(StrEnum):  # mirrors P0 engine PreparationStatus
    PREPARED = "prepared"
    COMPLETING = "completing"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    EXPIRED = "expired"
    FAILED = "failed"


TERMINAL = frozenset(
    {
        PreparationStatus.COMPLETED,
        PreparationStatus.CANCELLED,
        PreparationStatus.EXPIRED,
        PreparationStatus.FAILED,
    }
)


@dataclass(frozen=True, slots=True)
class PreparationRecord:
    preparation_id: str
    status: PreparationStatus
    state_version: int
    document_version_id: str
    document_sha256: str
    certificate_sha256: str
    prepared_pdf_sha256: str
    byte_range_digest_b64: str  # public digests kept for the P0 view in every state (REV-12)
    signed_attributes_digest_b64: str
    digest_algorithm: str
    signature_algorithm: str
    policy: str
    created_at: dt.datetime
    expires_at: dt.datetime
    updated_at: dt.datetime
    state_envelope: bytes | None  # None after sensitive state is discarded
    state_key_id: str | None  # key id sealing state_envelope (selection index, REV-10)
    prepared_blob: str | None  # relative path of the encrypted prepared PDF
    prepared_key_id: str | None
    lease_owner: str | None = None
    lease_expires_at: dt.datetime | None = None
    completion_binding: str | None = None  # SHA-256 over (preparation, attempt, context, signature hash)
    completion_attempt_id: str | None = None
    artifact_ref: str | None = None
    artifact_sha256: str | None = None  # SHA-256 of the signed PDF plaintext
    artifact_size: int | None = None
    artifact_key_id: str | None = None
    artifact_removed_at: dt.datetime | None = None  # removed by retention (metadata kept)
    terminal_at: dt.datetime | None = None  # retention timers start here, not at updated_at
    failure_reason: str | None = None  # internal reason code, never client data


@dataclass(frozen=True, slots=True)
class FencingToken:
    """Proof of the current claim: only (owner, state_version) of the live lease may commit."""

    owner: str
    state_version: int


class ClaimKind(StrEnum):
    CLAIMED = "claimed"  # prepared -> completing by this owner
    TAKEN_OVER = "taken_over"  # completing with expired lease, same binding, before the deadline
    IN_PROGRESS = "in_progress"  # completing, same binding, lease still valid
    ALREADY_COMPLETED = "already_completed"  # completed with the same binding
    CONFLICT = "conflict"  # different binding or non-claimable terminal state
    EXPIRED = "expired"  # prepared but past expires_at (now marked expired)
    DEADLINE_PASSED = "deadline_passed"  # completing past expires_at + grace (now marked failed)


@dataclass(frozen=True, slots=True)
class ClaimOutcome:
    kind: ClaimKind
    record: PreparationRecord

    @property
    def token(self) -> FencingToken:
        if self.record.lease_owner is None:
            raise ValueError("no lease")
        return FencingToken(self.record.lease_owner, self.record.state_version)


@dataclass(frozen=True, slots=True)
class ArtifactInfo:
    ref: str
    sha256: str
    size: int
    key_id: str


class PreparationRepository(NonceReservation, Protocol):
    # keys
    def sync_key_registry(self, keyring: Keyring, *, now: dt.datetime) -> None: ...
    def retire_key(self, key_id: str, *, now: dt.datetime) -> None: ...
    def registered_keys(self) -> dict[str, dt.datetime | None]: ...
    def nonce_key_ids(self) -> set[str]: ...
    def key_ids_referenced(self) -> set[str]: ...
    # lifecycle
    def register_intent(self, relpath: str, *, now: dt.datetime) -> None: ...
    def create(self, record: PreparationRecord, *, intent: str) -> None: ...
    def get(self, preparation_id: str) -> PreparationRecord: ...
    def claim_completion(
        self,
        preparation_id: str,
        *,
        binding: str,
        attempt_id: str,
        owner: str,
        now: dt.datetime,
        lease_until: dt.datetime,
        deadline: dt.datetime,
    ) -> ClaimOutcome: ...
    def mark_completed(
        self,
        preparation_id: str,
        *,
        token: FencingToken,
        binding: str,
        artifact: ArtifactInfo,
        now: dt.datetime,
    ) -> PreparationRecord: ...
    def mark_failed(
        self, preparation_id: str, *, token: FencingToken, reason: str, now: dt.datetime
    ) -> PreparationRecord: ...
    def cancel(self, preparation_id: str, *, now: dt.datetime) -> PreparationRecord: ...
    def expire_due(self, *, now: dt.datetime, limit: int) -> list[str]: ...
    def fail_past_deadline(self, *, now: dt.datetime, grace: dt.timedelta, limit: int) -> list[str]: ...
    def stale_completing(self, *, now: dt.datetime, limit: int) -> list[str]: ...
    # cleanup (specialised selections, REV-07)
    def discard_due(self, *, limit: int) -> list[str]: ...
    def discard_sensitive_state(self, preparation_id: str, *, now: dt.datetime) -> PreparationRecord: ...
    def artifacts_due(self, *, terminal_before: dt.datetime, limit: int) -> list[str]: ...
    def remove_artifact(self, preparation_id: str, *, now: dt.datetime) -> PreparationRecord: ...
    def purge_due(self, *, terminal_before: dt.datetime, limit: int) -> list[str]: ...
    def purge(self, preparation_id: str) -> None: ...
    def delete_if_unreferenced(
        self, relpath: str, *, intent_older_than: dt.datetime, delete: Callable[[str], None]
    ) -> bool: ...
    # rotation (REV-01, REV-10)
    def rewrap_candidates(self, *, active_key_id: str, limit: int) -> list[str]: ...
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
    ) -> PreparationRecord: ...
    def invalidate_non_terminal(self, *, reason: str, now: dt.datetime) -> list[str]: ...
