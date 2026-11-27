# ADR-0014 — Canonical Engine API contracts
Status: Accepted (27/11/2026, founder decision). Technical gates open.

## Context
SPEC v2.3 described two incompatible Engine APIs (§7 `/v1/preparations`, §25.2 `/v1/pdf/prepare`, `/health`, `/ready`). No API has been published.

## Decision
The internal Engine API is exactly:

| Method | Path |
|---|---|
| POST | /v1/pdf/preparations |
| GET | /v1/pdf/preparations/{id} |
| POST | /v1/pdf/preparations/{id}/complete |
| DELETE | /v1/pdf/preparations/{id} |
| POST | /v1/pdf/validations |
| GET | /v1/pdf/validations/{id} |
| POST | /v1/certificates/inspect |
| POST | /v1/certificates/validate |
| GET | /v1/policies |
| GET | /v1/capabilities |
| GET | /health/live |
| GET | /health/ready |

`packages/protocol/openapi/engine.v1.yaml` is the canonical source. No legacy aliases or competing routes. Digest fields are named by purpose: `document_sha256` (hex, original PDF, audit), `byte_range_digest_b64` (messageDigest attribute) and `signed_attributes_digest_b64` (input of the RSA operation). A contract test enforces the route list.

## Alternatives
Keep either earlier route set or both with aliases: rejected (ambiguity, no published consumers).

## Security and licensing impact
Engine stays on a private network, authenticated by service credential or mTLS. Storage references are authorized keys, never URLs or user paths. Contracts Apache-2.0; Engine AGPL-3.0-or-later.

## Consequences
SDKs and Hub client code target only these routes. ICP-Brasil policy identifiers/OIDs remain pending the P1 PoC.

## Validation evidence
P0 contract test `engine route set matches ADR-0014` (see packages/protocol tests).
