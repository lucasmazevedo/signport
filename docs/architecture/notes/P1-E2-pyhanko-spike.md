# P1/E2 — pyHanko interrupted-signing spike: findings

Date: 27/11/2026. Scope: E0–E2 of `docs/plans/P1-engine-cryptographic-core.md`. Synthetic PKI and documents only.
Verdict: **go** for pyHanko as the primary engine for the external RSA flow. Java DSS remains a contingency (ADR-0003); nothing in E2 justifies a migration proposal.

## Versions
pyHanko 0.38.2, pyhanko-certvalidator 0.33.0, cryptography 50.0.2, asn1crypto 1.5.1, CPython 3.13.18 (uv 0.13.10), OpenSSL 3.0.13 (independent verifier).

## Verified behaviour (installed code, not only docs)
| Point | Observation | Consequence |
|---|---|---|
| Bytes signed by pyHanko | `Signer.async_sign_prescribed_attributes` calls `async_sign_raw(signed_attrs.dump(), …)`; `CMSAttributes.dump()` is the `SET OF` (0x31) encoding | `signed_attributes_digest = SHA-256(signed_attrs.dump())` is exactly the `SignHash` input |
| Signed attributes (`use_pades=True`, no CAdES spec) | `content_type`, `message_digest`, `signing_certificate_v2`; **no** `signingTime` | PAdES-shaped; `signature-policy-identifier` must be added explicitly in E7 |
| `messageDigest` | Equals `PreparedByteRangeDigest.document_digest` | The three digests are distinct by construction (tested) |
| Post-sign instructions | `PostSignInstructions` is created **only** when `use_pades and embed_validation_info` | With LTV/TS off, the whole preparation state is bytes + ints → serialisable without pickle (E3) |
| Reservation | Estimated from the known certificate; example run: CMS 5,550 bytes DER = 11,100 hex chars, capacity 16,650 | ~33% margin observed — experimental evidence, not a universal guarantee. Overflow → `CMS_RESERVATION_EXCEEDED`, new preparation and new authorization; the ByteRange is never changed after signing |
| Completion | `PdfTBSDocument.async_finish_signing(output, PreparedByteRangeDigest, cms)` only fills the reserved region | ByteRange and all bytes outside `/Contents` unchanged (tested) |
| Signature algorithm in CMS | OID 1.2.840.113549.1.1.11 (sha256WithRSAEncryption = RSASSA-PKCS1-v1_5) | Never PSS (tested) |

## Example evidence (one run; values change every run because keys are ephemeral)
```
document_sha256 (hex)        : 3b76e782839cdd3d8ba4ffe5a69bc23cdbaf61bee67dd26188bb71e095580e33
byte_range_digest_b64        : auuBqAqJOXwd529YRDOSK15qUAfUkaTv3df9ka8MpmA=
signed_attributes_digest_b64 : jTZtOyAZ1zmxHu0Ybsym/+jEFcqlxrOA8PQO1UFojhM=
ByteRange                    : [0 1465 18117 506]  (file 18,623 bytes)
signed attrs byte-identical  : True (prepared DER == SignerInfo.signedAttrs in final CMS)
pyHanko                      : intact=True valid=True trusted=True coverage=ENTIRE_FILE bottom_line=True
openssl cms -verify          : 0 "CMS Verification successful"
SignData(digest) double hash : SIGNATURE_INVALID
```

## Findings that affect later stages
1. **CRITICAL RISK — legacy revocation modes are unsafe (to be resolved in E5).** In pyhanko-certvalidator 0.33.0, `revocation_mode="hard-fail"` maps to `CHECK_IF_DECLARED`: supplied CRLs are *not* checked when the certificate declares no CRL distribution point, so a revoked signer validated as `bottom_line=True`. `soft-fail` is weaker still. The Engine must use an explicit `RevocationCheckingPolicy` requiring revocation info (equivalent of `"require"`). Regression test (must be preserved): `test_legacy_hard_fail_mode_skips_crls_without_distribution_points`. E5 requirements: require valid revocation evidence; absence of information is never valid; no silent fallback to soft-fail; distinguish revoked / evidence unavailable / evidence invalid; use the relevant validation time; explicit trust stores only (no implicit certifi roots); separate synthetic and ICP-Brasil trust stores; indeterminate results never released automatically.
2. **Default trust roots.** `certifi` (MPL-2.0, transitive) ships the Mozilla web PKI roots. The Engine must always pass explicit trust roots from the versioned trust bundle and never rely on defaults (E5).
3. **No policy semantics.** pyHanko embeds `signature_policy_identifier` "at face value" (documented). AD-RB conformance checks are SignPort's responsibility (E7); VALIDAR acceptance is evidence, not formal conformity.
4. **Chain embedding.** `ExternalSigner(embed_roots=True)` (default) puts the root into the CMS; acceptable for ICP-Brasil practice, revisit in E7.
5. **Provenance check of uv.** The uv archive was verified by the SHA-256 published with the GitHub release (same origin). `gh attestation verify` was not available on this machine (old `gh`); CI pins the same SHA-256 via `setup-uv`'s `checksum` input. Accepted for this stage; additional provenance verification (artifact attestation) is a pending item before any release (docs/release-gates.md).

## Reproduce
```bash
cd apps/engine
uv sync --locked
uv run --locked ruff check . && uv run --locked ruff format --check .
uv run --locked pyright
SIGNPORT_REQUIRE_OPENSSL=1 uv run --locked pytest -ra
```
