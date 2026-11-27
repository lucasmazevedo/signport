# SPDX-License-Identifier: AGPL-3.0-or-later
"""PreparationService: persistent preparation and finalization (P1 E3/E4, review REV-01..REV-14).

State machine: prepared -> completing -> completed | failed; prepared -> cancelled | expired.
- Everything is verified BEFORE any transition; an invalid signature never consumes a preparation.
- Idempotency binding = SHA-256 over (preparation, attempt, certificate, algorithms, signature hash).
- Fencing (REV-06): a claim yields (lease owner, state_version); only the live holder of that exact
  token may commit, and only while its lease is valid. Stale processes can neither commit nor
  replace results; their artifacts stay unreferenced until verified recovery or safe cleanup.
- Expiry (REV-09): a first signature at/after ``expires_at`` is rejected; a claim started in time may
  finish, be taken over or be recovered until ``expires_at + completion_grace``; then it fails.
- The artifact is published immutably on disk BEFORE ``completed`` is committed; completion is
  deterministic, so retries and recovery reproduce identical bytes. Recovery re-verifies the CMS
  semantically and the binding (REV-05) before adopting anything.
- ``completed`` means "signed and cryptographically bound", never "normatively valid": validation
  (E5/E7) and the Hub decide release.
"""

import asyncio
import contextlib
import dataclasses
import datetime as dt
import hashlib
import json
import os
import socket
import time
import uuid
from collections.abc import Generator, Mapping
from dataclasses import dataclass

from cryptography import x509

from signport_engine.clock import Clock, SystemClock, to_rfc3339
from signport_engine.cms.bindings import verify_preparation_bindings, verify_signed_artifact
from signport_engine.cms.raw_signature import (
    SUPPORTED_DIGEST_ALGORITHM,
    SUPPORTED_SIGNATURE_ALGORITHM,
    require_supported_algorithms,
    verify_raw_rsa_signature,
)
from signport_engine.config import EngineSettings
from signport_engine.crypto.envelope import AadContext, EnvelopeCipher, EnvelopeKind, parse_envelope
from signport_engine.crypto.keys import Keyring, load_keyring
from signport_engine.errors import ConfigurationError, EngineError, ErrorCode, StateIntegrityError
from signport_engine.faults import FaultPoints, NoFaults
from signport_engine.ids import require_uuid, uuid7
from signport_engine.locking import MaintenanceLock
from signport_engine.pdf.byte_range import ByteRange
from signport_engine.pdf.external_signing import (
    PreparedSignature,
    complete_external_signature,
    prepare_external_signature,
    sha256_hex,
)
from signport_engine.persistence.repository import (
    TERMINAL,
    ArtifactInfo,
    ClaimKind,
    PreparationRecord,
    PreparationRepository,
    PreparationStatus,
)
from signport_engine.persistence.sqlite import SqlitePreparationRepository
from signport_engine.state.model import decode_state, encode_state, is_compatible_pyhanko
from signport_engine.storage.blobs import EncryptedBlobStore

SUPPORTED_POLICIES = frozenset({"icpbr-pades-rb"})  # declared only; policy attributes arrive in E7
_POLL_SECONDS = 0.05
_TMP_MIN_AGE_SECONDS = 300  # temp files are never referenced; only age protects in-flight writes
# Intents protect a prepared blob between its write and the row insert. Cleanup may only expire an
# intent after this fixed minimum age (independent of the configured orphan grace); create() also
# refuses to commit if its intent vanished, so a slow prepare can fail but never dangle (REV-07).
_INTENT_MIN_AGE_SECONDS = 3600
_MAX_REWRAP_ROUNDS = 10_000


@dataclass(frozen=True, slots=True)
class PreparationView:
    record: PreparationRecord

    @property
    def signed_attributes_digest_b64(self) -> str:
        return self.record.signed_attributes_digest_b64

    def to_p0(self) -> dict[str, object]:
        """Body of P0 engine ``Preparation`` — valid in every state, also after cleanup (REV-12)."""
        r = self.record
        return {
            "preparation_id": r.preparation_id,
            "status": r.status.value,
            "document_version_id": r.document_version_id,
            "document_sha256": r.document_sha256,
            "byte_range_digest_b64": r.byte_range_digest_b64,
            "signed_attributes_digest_b64": r.signed_attributes_digest_b64,
            "digest_algorithm": r.digest_algorithm,
            "signature_algorithm": r.signature_algorithm,
            "certificate_sha256": r.certificate_sha256,
            "policy": r.policy,
            "created_at": to_rfc3339(r.created_at),
            "expires_at": to_rfc3339(r.expires_at),
        }


@dataclass(frozen=True, slots=True)
class CompletionResult:
    record: PreparationRecord

    def to_p0(self) -> dict[str, object]:
        """Body of P0 engine ``CompletePreparationResponse``."""
        r = self.record
        return {
            "preparation_id": r.preparation_id,
            "attempt_id": r.completion_attempt_id,
            "status": "completed",
            "artifact": {
                "artifact_ref": r.artifact_ref,
                "sha256": r.artifact_sha256,
                "size_bytes": r.artifact_size,
            },
        }


def completion_binding(
    preparation_id: str,
    attempt_id: str,
    certificate_sha256: str,
    digest_algorithm: str,
    signature_algorithm: str,
    signature: bytes,
) -> str:
    doc = {
        "v": 1,
        "preparation_id": preparation_id,
        "attempt_id": attempt_id,
        "certificate_sha256": certificate_sha256,
        "digest_algorithm": digest_algorithm,
        "signature_algorithm": signature_algorithm,
        "signature_sha256": hashlib.sha256(signature).hexdigest(),
    }
    return hashlib.sha256(json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


@contextlib.contextmanager
def _guard() -> Generator[None]:
    """Normalize errors at the service boundary (REV-14): no internal detail leaks to clients."""
    try:
        yield
    except StateIntegrityError:
        raise EngineError(ErrorCode.INTERNAL_ERROR, "Persisted state failed integrity checks.") from None
    except OSError:
        raise EngineError(ErrorCode.SERVICE_UNAVAILABLE, "Engine storage unavailable; retry later.") from None


class PreparationService:
    def __init__(
        self,
        settings: EngineSettings,
        repository: PreparationRepository,
        cipher: EnvelopeCipher,
        blobs: EncryptedBlobStore,
        keyring: Keyring,
        lock: MaintenanceLock,
        *,
        clock: Clock | None = None,
        faults: FaultPoints | None = None,
    ) -> None:
        self._s = settings
        self._repo = repository
        self._cipher = cipher
        self._blobs = blobs
        self._keyring = keyring
        self._lock = lock
        self._clock = clock or SystemClock()
        self._faults = faults or NoFaults()
        self._owner_prefix = f"{socket.gethostname()}:{os.getpid()}"
        with lock.shared():  # the generation this process was started against (REV-17)
            if not repository.verify_key_registry(keyring):
                raise EngineError(
                    ErrorCode.SERVICE_UNAVAILABLE, "Key registry changed during startup; retry."
                )
            self._generation = repository.registry_state().generation

    # ------------------------------------------------------------------ helpers
    def _require_current(self) -> None:
        """REV-16/REV-17: refuse a process whose keyring predates a registry change made elsewhere
        (new key, active key change, retirement). Detected by the authenticated generation and
        active key, independently of the set of key ids. Called with the maintenance lock held, so
        the registry cannot change until the operation ends. In-memory nonce blocks are dropped."""
        try:
            state = self._repo.registry_state()
        except ConfigurationError:  # catalog authenticated by a key this process does not have
            state = None
        if (
            state is None
            or state.generation != self._generation
            or state.active_key_id != self._keyring.active_key_id
        ):
            self._cipher.discard_reserved()
            raise EngineError(
                ErrorCode.SERVICE_UNAVAILABLE,
                "Engine keyring is outdated (key registry changed); restart with the current keyring.",
            )

    @contextlib.contextmanager
    def _shared(self) -> Generator[None]:
        """Normal operations: shared maintenance lock plus the freshness check, for the whole call."""
        with self._lock.shared():
            self._require_current()
            yield

    @contextlib.contextmanager
    def _exclusive(self) -> Generator[None]:
        """Maintenance (rewrap, retirement, restore recovery): exclusive lock plus the same check."""
        with self._lock.exclusive():
            self._require_current()
            yield

    def _owner(self) -> str:
        return f"{self._owner_prefix}:{uuid.uuid4().hex}"

    def _grace(self) -> dt.timedelta:
        return dt.timedelta(seconds=self._s.completion_grace_seconds)

    def _aad(self, preparation_id: str, *bindings: str) -> AadContext:
        return AadContext(self._s.instance_id, preparation_id, bindings)

    def _state_aad(self, r: PreparationRecord) -> AadContext:
        return self._aad(r.preparation_id, r.document_sha256, r.certificate_sha256, r.prepared_pdf_sha256)

    def _artifact_aad(self, r: PreparationRecord, artifact_sha256: str) -> AadContext:
        return self._aad(r.preparation_id, r.completion_binding or "", artifact_sha256)

    def _load_prepared(self, r: PreparationRecord) -> PreparedSignature:
        if r.state_envelope is None or r.prepared_blob is None:
            raise StateIntegrityError("preparation state was discarded")
        state = self._cipher.open(EnvelopeKind.PREPARATION_STATE, r.state_envelope, self._state_aad(r))
        pdf = self._blobs.get(
            r.prepared_blob, EnvelopeKind.PREPARED_PDF, self._aad(r.preparation_id, r.prepared_pdf_sha256)
        )
        prepared, pyhanko_version = decode_state(state, pdf)
        if not is_compatible_pyhanko(pyhanko_version):  # REV-14: never finish with another engine build
            raise EngineError(
                ErrorCode.CONFLICT, "Prepared by an incompatible Engine version; prepare again."
            )
        return prepared

    def _verify_for(
        self, r: PreparationRecord, prepared: PreparedSignature, *, cert: str, sig_alg: str, dig_alg: str
    ) -> ByteRange:
        return verify_preparation_bindings(
            prepared,
            persisted_certificate_sha256=r.certificate_sha256,
            persisted_prepared_pdf_sha256=r.prepared_pdf_sha256,
            persisted_digest_algorithm=r.digest_algorithm,
            persisted_signature_algorithm=r.signature_algorithm,
            requested_certificate_sha256=cert,
            requested_signature_algorithm=sig_alg,
            requested_digest_algorithm=dig_alg,
        )

    # ------------------------------------------------------------------ prepare / get
    async def prepare(
        self,
        pdf: bytes,
        *,
        document_version_id: str,
        expected_document_sha256: str,
        certificate_der: bytes,
        chain_der: tuple[bytes, ...],
        policy: str,
        digest_algorithm: str = SUPPORTED_DIGEST_ALGORITHM,
        signature_algorithm: str = SUPPORTED_SIGNATURE_ALGORITHM,
        expires_at: dt.datetime | None = None,
    ) -> PreparationView:
        require_uuid(document_version_id, "document_version_id")
        require_supported_algorithms(digest_algorithm, signature_algorithm)
        if policy not in SUPPORTED_POLICIES:
            raise EngineError(ErrorCode.VALIDATION_FAILED, "Unsupported policy.")
        now = self._clock.now()
        expires = expires_at or now + dt.timedelta(seconds=self._s.preparation_ttl_seconds)
        if not now < expires <= now + dt.timedelta(seconds=self._s.max_preparation_ttl_seconds):
            raise EngineError(ErrorCode.VALIDATION_FAILED, "expires_at outside the allowed window.")
        prepared = await prepare_external_signature(
            pdf,
            expected_document_sha256=expected_document_sha256,
            certificate_der=certificate_der,
            chain_der=chain_der,
            digest_algorithm=digest_algorithm,
            signature_algorithm=signature_algorithm,
            max_pdf_bytes=self._s.max_pdf_bytes,
        )
        with _guard(), self._shared():
            pid = uuid7()
            pdf_ref = f"prepared/{pid}.bin"
            self._repo.register_intent(pdf_ref, now=now)  # protects the file before it exists (REV-07)
            self._blobs.put(
                pdf_ref,
                EnvelopeKind.PREPARED_PDF,
                prepared.prepared_pdf,
                self._aad(pid, prepared.prepared_pdf_sha256),
            )
            self._faults.hit("after_prepared_blob")
            record = PreparationRecord(
                preparation_id=pid,
                status=PreparationStatus.PREPARED,
                state_version=1,
                document_version_id=document_version_id,
                document_sha256=prepared.document_sha256,
                certificate_sha256=prepared.certificate_sha256,
                prepared_pdf_sha256=prepared.prepared_pdf_sha256,
                byte_range_digest_b64=prepared.byte_range_digest_b64,
                signed_attributes_digest_b64=prepared.signed_attributes_digest_b64,
                digest_algorithm=digest_algorithm,
                signature_algorithm=signature_algorithm,
                policy=policy,
                created_at=now,
                expires_at=expires,
                updated_at=now,
                state_envelope=None,
                state_key_id=None,
                prepared_blob=pdf_ref,
                prepared_key_id=self._blobs.key_id(pdf_ref),
            )
            envelope = self._cipher.seal(
                EnvelopeKind.PREPARATION_STATE, encode_state(prepared), self._state_aad(record)
            )
            record = dataclasses.replace(
                record, state_envelope=envelope, state_key_id=parse_envelope(envelope).key_id
            )
            self._repo.create(record, intent=pdf_ref)
            return PreparationView(record)

    def get(self, preparation_id: str) -> PreparationView:
        with _guard():
            return PreparationView(self._repo.get(preparation_id))

    # ------------------------------------------------------------------ complete
    async def complete(
        self,
        preparation_id: str,
        *,
        attempt_id: str,
        signature: bytes,
        signature_algorithm: str,
        certificate_sha256: str,
        digest_algorithm: str = SUPPORTED_DIGEST_ALGORITHM,
    ) -> CompletionResult:
        require_uuid(attempt_id, "attempt_id")
        binding = completion_binding(
            preparation_id, attempt_id, certificate_sha256, digest_algorithm, signature_algorithm, signature
        )
        with _guard(), self._shared():
            return await self._complete(
                preparation_id,
                attempt_id,
                binding,
                signature,
                signature_algorithm,
                certificate_sha256,
                digest_algorithm,
            )

    async def _complete(
        self,
        pid: str,
        attempt_id: str,
        binding: str,
        signature: bytes,
        signature_algorithm: str,
        certificate_sha256: str,
        digest_algorithm: str,
    ) -> CompletionResult:
        record = self._repo.get(pid)
        if record.status is PreparationStatus.COMPLETED:
            if record.completion_binding == binding:
                return self._existing(record)[0]
            raise EngineError(ErrorCode.CONFLICT, "Preparation already completed with a different signature.")
        if record.status is PreparationStatus.EXPIRED or record.failure_reason == "expired_during_completion":
            raise EngineError(ErrorCode.PREPARATION_EXPIRED, "Preparation expired; prepare again.")
        if record.status in TERMINAL:
            raise EngineError(ErrorCode.CONFLICT, "Preparation is in a terminal state.")
        if record.status is PreparationStatus.COMPLETING and record.completion_binding != binding:
            raise EngineError(
                ErrorCode.CONFLICT, "Preparation is being completed with a different signature."
            )

        # 1) Verify everything before any state transition (plan P1 §12.1, checks 1-7).
        prepared = self._load_prepared(record)
        region = self._verify_for(
            record, prepared, cert=certificate_sha256, sig_alg=signature_algorithm, dig_alg=digest_algorithm
        )
        verify_raw_rsa_signature(
            x509.load_der_x509_certificate(prepared.certificate_der), prepared.signed_attrs_der, signature
        )

        # 2) Claim. Wait boundedly if another process holds a live lease.
        owner = self._owner()
        wait_until = time.monotonic() + self._s.completion_wait_seconds
        while True:
            outcome = self._repo.claim_completion(
                pid,
                binding=binding,
                attempt_id=attempt_id,
                owner=owner,
                lease=dt.timedelta(seconds=self._s.lease_seconds),
                deadline=record.expires_at + self._grace(),
            )
            if outcome.kind in (ClaimKind.CLAIMED, ClaimKind.TAKEN_OVER):
                break
            if outcome.kind is ClaimKind.ALREADY_COMPLETED:
                return self._existing(outcome.record)[0]
            if outcome.kind in (ClaimKind.EXPIRED, ClaimKind.DEADLINE_PASSED):
                raise EngineError(ErrorCode.PREPARATION_EXPIRED, "Preparation expired; prepare again.")
            if outcome.kind is ClaimKind.CONFLICT:
                raise EngineError(ErrorCode.CONFLICT, "Preparation is bound to a different completion.")
            if time.monotonic() >= wait_until:
                raise EngineError(
                    ErrorCode.SERVICE_UNAVAILABLE, "Completion in progress elsewhere; retry later."
                )
            await asyncio.sleep(_POLL_SECONDS)
        token, claimed = outcome.token, outcome.record
        self._faults.hit("after_claim")

        # 3) Build the CMS (deterministic) and verify the output semantically (checks 8-9, REV-05).
        try:
            signed = await complete_external_signature(
                prepared,
                signature=signature,
                signature_algorithm=signature_algorithm,
                certificate_sha256=certificate_sha256,
                digest_algorithm=digest_algorithm,
            )
        except EngineError as exc:
            if exc.code is ErrorCode.CMS_RESERVATION_EXCEEDED:
                self._repo.mark_failed(
                    pid, token=token, reason="cms_reservation_exceeded", now=self._clock.now()
                )
            raise
        verify_signed_artifact(
            prepared, region, signed, expected_signature_sha256=hashlib.sha256(signature).hexdigest()
        )
        artifact_sha = sha256_hex(signed)
        ref = f"artifacts/{pid}/{artifact_sha}.bin"
        self._faults.hit("before_artifact_write")
        self._blobs.put(ref, EnvelopeKind.SIGNED_ARTIFACT, signed, self._artifact_aad(claimed, artifact_sha))
        self._faults.hit("after_artifact_write")

        # 4) Atomic publication, fenced by the claim token (REV-06).
        artifact = ArtifactInfo(
            ref=ref, sha256=artifact_sha, size=len(signed), key_id=self._blobs.key_id(ref)
        )
        try:
            done = self._repo.mark_completed(
                pid,
                token=token,
                binding=binding,
                artifact=artifact,
                deadline=record.expires_at + self._grace(),
            )
        except EngineError as exc:
            if exc.code is not ErrorCode.CONFLICT:
                raise
            current = self._repo.get(pid)  # our lease was lost (expired / taken over)
            if current.status is PreparationStatus.COMPLETED and current.completion_binding == binding:
                return self._existing(current)[0]
            raise EngineError(ErrorCode.SERVICE_UNAVAILABLE, "Completion lease lost; retry later.") from None
        return CompletionResult(done)

    def _existing(self, record: PreparationRecord) -> tuple[CompletionResult, bytes]:
        """Decrypt once (REV-14) and distinguish retention removal from unexpected loss (REV-12)."""
        if record.artifact_removed_at is not None:
            raise EngineError(ErrorCode.NOT_FOUND, "Signed artifact was removed by the retention policy.")
        if record.artifact_ref is None or record.artifact_sha256 is None:
            raise StateIntegrityError("completed preparation without artifact")
        data = self._blobs.get(
            record.artifact_ref,
            EnvelopeKind.SIGNED_ARTIFACT,
            self._artifact_aad(record, record.artifact_sha256),
        )
        if sha256_hex(data) != record.artifact_sha256 or len(data) != record.artifact_size:
            raise StateIntegrityError("artifact does not match the recorded hash")
        return CompletionResult(record), data

    def read_artifact(self, preparation_id: str) -> bytes:
        """Decrypt the stored signed PDF (for delivery to the Hub in E9)."""
        with _guard(), self._shared():
            record = self._repo.get(preparation_id)
            if record.status is not PreparationStatus.COMPLETED:
                raise EngineError(ErrorCode.CONFLICT, "Preparation is not completed.")
            return self._existing(record)[1]

    def cancel(self, preparation_id: str) -> PreparationRecord:
        with _guard(), self._shared():
            return self._repo.cancel(preparation_id, now=self._clock.now())

    # ------------------------------------------------------------------ recovery (REV-05/06/08/09)
    def _verified_artifact(self, record: PreparationRecord, ref: str) -> bytes:
        """Adopt nothing on AEAD authenticity alone: full semantic and binding verification."""
        if record.completion_binding is None or record.completion_attempt_id is None:
            raise StateIntegrityError("completing preparation without binding")
        sha = ref.rsplit("/", 1)[1].removesuffix(".bin")
        signed = self._blobs.get(ref, EnvelopeKind.SIGNED_ARTIFACT, self._artifact_aad(record, sha))
        if sha256_hex(signed) != sha:
            raise StateIntegrityError("artifact hash mismatch")
        prepared = self._load_prepared(record)
        region = self._verify_for(
            record,
            prepared,
            cert=record.certificate_sha256,
            sig_alg=record.signature_algorithm,
            dig_alg=record.digest_algorithm,
        )
        signature = verify_signed_artifact(prepared, region, signed, expected_signature_sha256=None)
        recovered = completion_binding(
            record.preparation_id,
            record.completion_attempt_id,
            record.certificate_sha256,
            record.digest_algorithm,
            record.signature_algorithm,
            signature,
        )
        if recovered != record.completion_binding:
            raise StateIntegrityError("artifact signature does not match the claimed completion")
        return signed

    async def recover_stale(self, *, limit: int = 100) -> list[str]:
        """Finish completions whose process died after publishing a verifiable artifact."""
        recovered: list[str] = []
        with _guard(), self._shared():
            for pid in self._repo.stale_completing(now=self._clock.now(), limit=limit):
                record = self._repo.get(pid)
                if record.completion_binding is None or record.completion_attempt_id is None:
                    continue
                now = self._clock.now()  # per row: never a timestamp from before earlier slow work
                lease = dt.timedelta(seconds=self._s.lease_seconds)
                deadline = record.expires_at + self._grace()
                candidates = [b for b in self._blobs.all_blobs() if b.startswith(f"artifacts/{pid}/")]
                if now >= deadline or len(candidates) != 1:
                    if now >= deadline:  # claim marks it failed: no indefinite recovery (REV-09)
                        self._repo.claim_completion(
                            pid,
                            binding=record.completion_binding,
                            attempt_id=record.completion_attempt_id,
                            owner=self._owner(),
                            lease=lease,
                            deadline=deadline,
                        )
                    continue
                ref = candidates[0]
                try:
                    signed = self._verified_artifact(record, ref)
                except (StateIntegrityError, EngineError):
                    continue  # never publish anything that fails re-verification
                self._blobs.ensure_durable(ref)  # REV-08: durable before it becomes referenced
                claim = self._repo.claim_completion(
                    pid,
                    binding=record.completion_binding,
                    attempt_id=record.completion_attempt_id,
                    owner=self._owner(),
                    lease=lease,
                    deadline=deadline,
                )
                if claim.kind is ClaimKind.TAKEN_OVER:
                    sha = ref.rsplit("/", 1)[1].removesuffix(".bin")
                    self._repo.mark_completed(
                        pid,
                        token=claim.token,
                        binding=record.completion_binding,
                        artifact=ArtifactInfo(ref, sha, len(signed), self._blobs.key_id(ref)),
                        deadline=deadline,
                    )
                    recovered.append(pid)
        return recovered

    # ------------------------------------------------------------------ cleanup (REV-07, REV-11)
    def cleanup(self, *, limit: int = 500) -> dict[str, int]:
        """Expire, discard sensitive state, remove retained artifacts, purge rows, remove orphans.

        References are always removed in a transaction BEFORE the file; orphan files are only
        deleted under the write lock after re-checking every reference and intent.
        """
        with _guard(), self._shared():
            now = self._clock.now()
            stats = {
                "expired": len(self._repo.expire_due(now=now, limit=limit)),
                "failed_past_deadline": len(
                    self._repo.fail_past_deadline(now=now, grace=self._grace(), limit=limit)
                ),
                "discarded": 0,
                "artifacts_removed": 0,
                "purged": 0,
                "orphans_removed": 0,
            }
            for pid in self._repo.discard_due(limit=limit):
                old = self._repo.discard_sensitive_state(pid, now=now)
                if old.prepared_blob:
                    self._blobs.delete(old.prepared_blob)
                stats["discarded"] += 1
            artifact_cutoff = now - dt.timedelta(seconds=self._s.artifact_retention_seconds)
            for pid in self._repo.artifacts_due(terminal_before=artifact_cutoff, limit=limit):
                old = self._repo.remove_artifact(pid, now=now)
                if old.artifact_ref:
                    self._blobs.delete(old.artifact_ref)
                stats["artifacts_removed"] += 1
            purge_cutoff = now - dt.timedelta(seconds=self._s.terminal_retention_seconds)
            for pid in self._repo.purge_due(terminal_before=purge_cutoff, limit=limit):
                self._repo.purge(pid)
                stats["purged"] += 1
            grace = self._s.orphan_grace_seconds
            young = time.time() - grace
            intent_cutoff = now - dt.timedelta(seconds=max(grace, _INTENT_MIN_AGE_SECONDS))
            for rel in self._blobs.all_blobs():
                try:
                    if grace and self._blobs.mtime(rel) >= young:
                        continue  # defence in depth only
                except FileNotFoundError:
                    continue
                if self._repo.delete_if_unreferenced(
                    rel, intent_older_than=intent_cutoff, delete=self._blobs.delete
                ):
                    stats["orphans_removed"] += 1
            for tmp in self._blobs.stale_temporaries(time.time() - max(grace, _TMP_MIN_AGE_SECONDS)):
                tmp.unlink(missing_ok=True)
                stats["orphans_removed"] += 1
            return stats

    # ------------------------------------------------------------------ keys (REV-01, REV-02, REV-10)
    def key_ids_in_use(self) -> set[str]:
        """Every key id still needed: DB envelopes/MACs/events AND every blob header on disk."""
        with _guard():
            ids = set(self._repo.key_ids_referenced())
            for rel in self._blobs.all_blobs():
                with contextlib.suppress(FileNotFoundError):
                    ids.add(self._blobs.key_id(rel))
            return ids

    def rewrap(self, *, batch: int = 100) -> int:
        """Re-seal everything sealed with a non-active key; resumable, idempotent, exclusive."""
        with _guard(), self._exclusive():
            active, done = self._keyring.active_key_id, 0
            for _ in range(_MAX_REWRAP_ROUNDS):
                ids = self._repo.rewrap_candidates(active_key_id=active, limit=batch)
                if not ids:
                    return done
                for pid in ids:
                    self._rewrap_one(pid, active)
                    done += 1
            raise EngineError(ErrorCode.INTERNAL_ERROR, "Rewrap did not converge.")

    def _rewrap_one(self, pid: str, active: str) -> None:
        r = self._repo.get(pid)
        state, state_key = r.state_envelope, r.state_key_id
        if state is not None and parse_envelope(state).key_id != active:
            plain = self._cipher.open(EnvelopeKind.PREPARATION_STATE, state, self._state_aad(r))
            state = self._cipher.seal(EnvelopeKind.PREPARATION_STATE, plain, self._state_aad(r))
            state_key = active
        prepared_key = r.prepared_key_id
        if r.prepared_blob:
            if self._blobs.key_id(r.prepared_blob) != active:
                aad = self._aad(pid, r.prepared_pdf_sha256)
                data = self._blobs.get(r.prepared_blob, EnvelopeKind.PREPARED_PDF, aad)
                self._blobs.replace(r.prepared_blob, EnvelopeKind.PREPARED_PDF, data, aad)
                self._faults.hit("rewrap_after_blob")
            prepared_key = active
        artifact_key = r.artifact_key_id
        if r.artifact_ref and r.artifact_sha256 and r.artifact_removed_at is None:
            if self._blobs.key_id(r.artifact_ref) != active:
                aad = self._artifact_aad(r, r.artifact_sha256)
                data = self._blobs.get(r.artifact_ref, EnvelopeKind.SIGNED_ARTIFACT, aad)
                self._blobs.replace(r.artifact_ref, EnvelopeKind.SIGNED_ARTIFACT, data, aad)
            artifact_key = active
        self._repo.replace_sealed(
            pid,
            expected_version=r.state_version,
            state_envelope=state,
            state_key_id=state_key,
            prepared_key_id=prepared_key,
            artifact_key_id=artifact_key,
            now=self._clock.now(),
        )

    def retire_key(self, key_id: str) -> None:
        """Retire a key only when nothing (DB or filesystem) still depends on it. History is kept."""
        with _guard(), self._exclusive():
            if key_id == self._keyring.active_key_id:
                raise ConfigurationError("the active key cannot be retired")
            if key_id in self.key_ids_in_use():
                raise ConfigurationError("key is still in use; run rewrap first")
            self._repo.retire_key(key_id, now=self._clock.now())
            self._generation = self._repo.registry_state().generation  # this process stays current

    def recover_after_restore(self) -> list[str]:
        """Mandatory after restoring a backup: counters may have rewound, so the active key must be
        one never used before; every non-terminal preparation is invalidated (Hub reconciliation)."""
        with _guard(), self._exclusive():
            active = self._keyring.active_key_id
            if active in self._repo.nonce_key_ids() or active in self.key_ids_in_use():
                raise ConfigurationError("restore recovery requires rotating to a never-used state key first")
            return self._repo.invalidate_non_terminal(
                reason="invalidated_after_restore", now=self._clock.now()
            )


def open_engine(
    env: Mapping[str, str], *, clock: Clock | None = None, faults: FaultPoints | None = None
) -> PreparationService:
    """Build the service from the environment. Fails closed on any invalid configuration,
    including keys inconsistent with the persisted key registry or data (REV-02, REV-14)."""
    settings = EngineSettings.from_env(env)
    settings.data_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    keyring = load_keyring(env, settings.data_dir, settings.instance_id)
    repo = SqlitePreparationRepository(
        settings.data_dir / "engine.sqlite3",
        instance_id=settings.instance_id,
        keyring=keyring,
        busy_timeout_ms=settings.busy_timeout_ms,
        clock=clock,
    )
    lock = MaintenanceLock(settings.data_dir, timeout_seconds=settings.lock_timeout_seconds)
    with lock.shared():  # read-only verification (REV-17)
        current = repo.verify_key_registry(keyring)
    if not current:  # registering keys or changing the active key needs effective exclusion
        with lock.exclusive():
            repo.sync_key_registry(keyring, now=(clock or SystemClock()).now())
    cipher = EnvelopeCipher(keyring, repo)
    blobs = EncryptedBlobStore(settings.data_dir, cipher)
    return PreparationService(settings, repo, cipher, blobs, keyring, lock, clock=clock, faults=faults)
