# @signport/protocol

Canonical SignPort contracts (ADR-0007, ADR-0013, ADR-0014). License: Apache-2.0 (copyright holder pending, SPEC §23 L01). Contracts only: no service is implemented here.

## Contents
| Path | Contract |
|---|---|
| `schemas/v1/common.schema.json` | Shared primitives and encodings |
| `schemas/v1/errors.schema.json`, `errors/registry.json` | Error taxonomy (native, Hub, Engine) |
| `schemas/v1/native/` | Native Messaging protocol 1: request, response, per-action results |
| `schemas/v1/authorization/` | Local authorization JWS header and claims, consent manifest, JWKS, P1.5 API bodies |
| `schemas/v1/engine/api.schema.json` | Engine internal API bodies |
| `openapi/engine.v1.yaml` | Engine internal API (12 canonical routes, ADR-0014) |
| `openapi/hub-authorization.v1.yaml` | Hub Authorization Foundation, P1.5 (ADR-0013) |
| `fixtures/v1/**/*.cases.json` | Synthetic valid cases and negative cases (RFC 6902 patches over a valid case, each with a reason) |
| `fixtures/v1/crypto/` | Synthetic ES256 authorization vectors (incl. duplicate members, DER-vs-R||S, algorithm confusion), RFC 8785 JCS vectors and an RSA "no double hashing" known-answer vector |

## Encoding rules
- Document hashes and certificate fingerprints: lowercase hex SHA-256 (`*_sha256`).
- Cryptographic digests and raw signatures: standard padded Base64 (`*_b64`); digests are exactly 32 bytes.
- Three values are never interchangeable: `document_sha256` (original PDF, audit), `byte_range_digest_b64` (CMS messageDigest) and `signed_attributes_digest_b64` (the only value signed; `SignHash` input).
- Field casing: Native Messaging uses camelCase (SPEC §8.4); HTTP APIs and JWS claims use snake_case.
- IDs: lowercase canonical UUID. Times: RFC 3339 UTC `Z` (HTTP) or integer NumericDate (JWS).
- `$id` namespace `https://signport.invalid/schemas/v1/...` (approved provisionally): identifiers only, never fetched; validators load schemas locally. Migration to the official domain, if any, is decided before the first stable public release.

## Local authorization JWS profile
ES256 only (other algorithms rejected), `typ` `signport-local-authz+jwt`, `aud` `org.signport.nativehost`; `iss`/`kid` bound to a previously authorized installation in the host's local store; no keys accepted from the JWS. Signatures are 64-byte R||S (RFC 7518 §3.4), not DER (PHP `openssl_sign` needs conversion; .NET `ECDsa` defaults to P1363). Duplicate JSON members are rejected after unescaping. The consent manifest hash uses RFC 8785 JCS; every implementation must pass `fixtures/v1/crypto/jcs.vectors.json` (alphabetical sorting is not enough). Host order and online consumption rules: `schemas/v1/authorization/claims.schema.json`.

## Versioning
| Version | Example |
|---|---|
| Specification | 2.3.1 |
| Software release | 0.1.0 |
| REST API | v1 |
| Native Messaging protocol | 1 |
| Individual schema | own field when needed (e.g. `manifest_version`) |

- Negotiation: the extension first sends `getVersion` with protocol 1 (frozen shape) and receives `applicationVersion`, `supportedProtocolVersions` and `capabilities`; it uses the highest common protocol, otherwise reports `VERSION_UNSUPPORTED` with both lists. Hosts answer unsupported protocol numbers with a protocol-1 `VERSION_UNSUPPORTED` error carrying `supportedProtocolVersions`. Never fail silently.
- Native Messaging: integer `protocol` (currently 1). Messages are closed in both directions; any field change requires a new protocol number. Hosts advertise supported protocols in `getVersion.supportedProtocolVersions` (N/N-1).
- HTTP APIs: path version `/v1`. Request bodies are closed (servers reject unknown fields). Response schemas are closed for producer conformance; consumers must ignore unknown response fields, and adding optional response fields is a minor change. Removing or changing fields requires `/v2` and a migration period.
- JWS: `typ` `signport-local-authz+jwt` and fixed `ES256`; incompatible claim changes require a new `typ`.
- Pending PoC (P1): ICP-Brasil policy OIDs, CMS attributes and reservation size, timestamping, CPF extraction rules. `signBatch` and batch manifests are reserved for a later protocol.

## Commands
Requires Node.js >= 22.12 and pnpm (version pinned in `packageManager`).

```bash
pnpm install --frozen-lockfile
pnpm run check            # Redocly lint (recommended-strict) + Vitest contract tests
pnpm run fixtures:crypto  # regenerate synthetic crypto vectors (ephemeral keys, never written)
```

Dev dependencies are not distributed with the contracts. `lightningcss` (MPL-2.0) arrives transitively through Vitest as a dev-only tool; all other transitive dev dependencies are MIT, ISC, BSD-3-Clause or Apache-2.0 (`pnpm licenses list`).

`tests/support/reference-host-verifier.mjs` and `tests/support/strict-json.mjs` are an executable specification of the native-host authorization checks for tests only; they are not the Desktop implementation and performs no online consumption.
