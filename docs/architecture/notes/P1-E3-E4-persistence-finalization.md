# P1/E3–E4 — Persistence and finalization: implementation notes

Date: 27/11/2026 (revised after the code review, `P1-E3-E4-code-review.md`). Scope: plan `docs/plans/P1-E3-E6-persistence-finalization-validation.md` §§1–7, 10 and 15. Synthetic PKI and documents only. No normative validity is claimed: E5 and E7 are pending.

## Modules (`apps/engine/src/signport_engine`)
| Module | Role |
|---|---|
| `service.py` | `PreparationService`: prepare, get, complete, read_artifact, cancel, recover_stale, cleanup, rewrap, retire_key, key_ids_in_use, recover_after_restore; `open_engine(env)` |
| `persistence/repository.py` | Storage-independent `PreparationRepository` protocol, records, `FencingToken` |
| `persistence/sqlite.py` | SQLite implementation: schema, pragmas, read snapshots, compare-and-set transitions, row MAC, event chain, key registry, authenticated nonce blocks, intents, reference-checked deletion |
| `crypto/keys.py` | Immutable keyring; installation-bound HKDF subkeys and key fingerprints |
| `crypto/envelope.py` | AES-256-GCM envelope v2, durable nonce blocks |
| `storage/blobs.py` | Encrypted immutable blob store with directory durability |
| `locking.py` | Cross-process maintenance lock (shared / exclusive) |
| `pdf/signature_field.py`, `pdf/byte_range.py`, `cms/bindings.py` | Structural field binding, independent ByteRange digest, shared semantic CMS verification |
| `state/model.py` | Explicit versioned JSON state (no pickle), pyHanko version policy |
| `config.py`, `clock.py`, `ids.py`, `faults.py` | Settings, injectable clock, UUIDv7, fault points |

## Data model (initial schema; pre-release, so still migration v1; the key catalog lives in `engine_meta`)
- `preparations`: id, status (`prepared|completing|completed|cancelled|expired|failed`), `state_version`, document/certificate/prepared-PDF hashes, public digests (`byte_range_digest_b64`, `signed_attributes_digest_b64`), algorithms, policy, times, `state_envelope` + `state_key_id`, `prepared_blob` + `prepared_key_id`, lease, completion binding and attempt, artifact ref/sha/size/key id, `artifact_removed_at`, `terminal_at`, internal `failure_reason`, `mac_key_id`, `row_mac`.
- `preparation_events`: append-only `(preparation_id, seq)`, transition, reason, time, `mac_key_id`, `chain_mac`.
- `key_registry(key_id, fingerprint UNIQUE, first_seen_at, retired_at, mac)`: no secret material.
- `nonce_counters(key_id → key_registry, purpose, next_counter, mac)`, `blob_intents(path, created_at)`, `engine_meta(instance_id)`, `schema_migrations`.
- Pragmas (verified): `journal_mode=wal`, `synchronous=FULL`, `foreign_keys=ON`, `secure_delete=ON`, `busy_timeout=5000` (configurable).

## Envelope v2
`"SPE1" | version=2 | kind | len(key_id) | key_id | nonce(12) | ciphertext‖tag(16)`. Kinds: preparation state, prepared PDF, signed artifact.
- **Subkeys:** HKDF-SHA256 with salt = label ‖ installation id and info = purpose (`state`, `artifact`, `metadata-mac`).
- **AAD:** the header plus length-prefixed components: label, kind, installation id, preparation id, and kind-specific bindings.
- **Nonce:** 4 random bytes ‖ 64-bit counter taken from a block of 64 counters reserved durably (one authenticated transaction) per (key, purpose). A block is committed durably before any counter from it is used. Blocks are disjoint across processes; counters of a block lost in a crash or failed encryption are never reused. A forked child discards the blocks inherited from its parent and reserves its own.
- **Limits:** ≤ 2^32 envelopes per (key, purpose); ≤ 2^36−32 bytes per envelope (Engine PDFs ≤ 200 MiB).

## Key management
- **Configuration:** inline (`ENGINE_STATE_KEY` + `_ID`, strict canonical base64url) or a keyring file (`ENGINE_STATE_KEY_FILE`: 0600, owned by the Engine user, outside `ENGINE_DATA_DIR`).
- **Startup refuses:**
  - no key;
  - malformed or non-canonical keys;
  - an id re-bound to other material;
  - material previously registered under another id;
  - a retired key as the active key;
  - data that references keys missing from the keyring.
- **Rotation:** add the new key as active and keep the old ones; run `rewrap()` (exclusive, paged, resumable, a no-op for rows already current, re-authenticates the event chains); then `retire_key(old)`. Retirement refuses while any DB reference or blob header on disk still uses the key, and history is kept.
- **Key catalog (REV-15):** `engine_meta.key_catalog` holds the installation id, an authenticated generation, the active key id, every registry entry (retired keys included) and every nonce counter row. It is MACed with the active key's metadata subkey and re-authenticated on every registry change, so the history stays verifiable after retired material leaves the keyring. Isolated removal, insertion or alteration fails closed; a coordinated rollback does not (accepted risk).
- **Nonce counters (REV-18):** created at 0 together with the key; a missing row is an integrity failure, never a restart at 0.
- **Startup (REV-17):** read-only `verify_key_registry()` under the shared lock. Only when keys must be registered or the active key changes does `sync_key_registry()` run, under the **exclusive** lock, bumping the generation.
- **Processes with an outdated keyring (REV-16):**
  - Every normal operation (shared lock) and every maintenance operation (exclusive lock) first re-reads the verified catalog.
  - A process whose start-time generation or active key no longer matches is refused (`SERVICE_UNAVAILABLE`) and drops its in-memory nonce blocks. The same applies when the catalog is authenticated by a key it lacks.
  - After any registry change, every other process must restart.
- **After a backup restore:** rotate to a never-used key, then call `recover_after_restore()`, which invalidates every non-terminal preparation before any new encryption. Later, reconcile with the Hub.

## Finalization
1. Verify everything first: the eleven checks of plan P1 §12.1 and the raw RSA signature.
2. Claim with compare-and-set, which yields a `FencingToken(owner, state_version)` and a lease.
3. Assemble the CMS deterministically.
4. Run the shared semantic CMS verification (`verify_signed_artifact`).
5. Publish the immutable artifact durably.
6. Commit `completed`, fenced by the token and a still-valid lease.

Rules:
- An invalid signature never consumes a preparation.
- Same binding → the existing artifact is returned (decrypted once). A different binding → `CONFLICT`.
- A live lease held elsewhere → bounded wait, then `SERVICE_UNAVAILABLE`. Lost lease → retry; stale processes cannot commit or replace results.
- Expiry: a first signature at or after `expires_at` is rejected. A claim started in time may finish, be taken over or be recovered until `expires_at + ENGINE_COMPLETION_GRACE_SECONDS`, then it fails (`expired_during_completion`).
- Recovery adopts an artifact found on disk only after the same semantic verification, recomputation of the binding from the recovered signature, and fsync of the file and its directory.

## Cleanup
1. Expire due preparations and fail completions past their deadline.
2. **Logically remove sensitive state** of terminal rows: the reference is dropped in a transaction first, then the file is deleted.
3. Remove artifacts whose retention (counted from `terminal_at`) has elapsed, keeping metadata and `artifact_removed_at`.
4. Purge rows past the metadata retention.
5. Remove orphan files only under the write lock after re-checking intents and references. The orphan grace is defence in depth only; intents expire after a fixed minimum of 1 h, and `create()` refuses to commit when its intent vanished.

## Configuration added by E3–E4
`ENGINE_DATA_DIR`, `ENGINE_INSTANCE_ID`, `ENGINE_STATE_KEY`/`ENGINE_STATE_KEY_ID` or `ENGINE_STATE_KEY_FILE`, `ENGINE_SQLITE_BUSY_TIMEOUT_MS` (5000), `ENGINE_COMPLETION_LEASE_SECONDS` (60), `ENGINE_COMPLETION_WAIT_MS` (30000), `ENGINE_COMPLETION_GRACE_SECONDS` (300), `ENGINE_LOCK_TIMEOUT_MS` (30000), `SIGNING_PREPARATION_TTL` (600), `ENGINE_TERMINAL_RETENTION_SECONDS` and `ENGINE_ARTIFACT_RETENTION_SECONDS` (7 days), `ENGINE_ORPHAN_GRACE_SECONDS` (3600), `ENGINE_MAX_PDF_BYTES` (20 MiB).

## Residual risks and limitations
1. **Coordinated restores are not detectable locally:** a whole-storage restore, or restoring a preparation together with its earlier authenticated chain (or older authenticated counter rows). Row MAC and event chain detect tampering and *inconsistent* partial rollback only; no absolute rollback protection is claimed. Mitigations: the restore procedure above and future Hub reconciliation.
2. **SQLite limits:** single host, local filesystem only (network filesystems refused best-effort), one writer at a time; the maintenance lock is local and advisory. PostgreSQL would need an ADR and demonstrated need.
3. **Durability** depends on the storage stack honouring fsync. A blob lost after a power loss reads as an integrity failure, never as success.
4. **Remanence:** removed state may persist in the WAL until checkpoint, in backups and in storage remanence; it stays protected only by the state key (no per-preparation key is destroyed).
5. An attacker with write access to `ENGINE_DATA_DIR` **and** the key defeats all local protections.
6. Leases are clamped to the completion deadline. Claim, commit and `mark_failed` read the clock after acquiring the write lock, and commit and `mark_failed` refuse at or after the deadline (REV-19).
7. A crash after the claim and before the artifact leaves the preparation retryable until its deadline; the Engine cannot finish without the signature.
8. `completed` means "signed and cryptographically bound" only. Release requires validation (E5/E7) and the Hub.
