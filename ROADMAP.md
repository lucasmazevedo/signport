# Roadmap — execution backlog
Canonical implementation order (ADR-0013). SPEC.md §§13, 21 and 28 detail gates and releases and must follow this file. No gate is complete without recorded evidence.

- [x] P0 — Protocol: schemas, error taxonomy, native envelope, authorization contracts, OpenAPI (Engine and P1.5 Hub endpoints), fixtures and contract checks. Evidence: PR #1 merged as `d736a88` (27/11/2026), 279 contract tests, 4 CI checks green.
- [ ] P1 — Engine PoC: synthetic certificate, external CMS digest, signed PDF, independent verification and policy report. Plan: `docs/plans/P1-engine-cryptographic-core.md` (approved 27/11/2026); E0–E2 in review.
- [ ] P1.5 — Authorization Foundation (inside `apps/hub`, no new service): Laravel bootstrap, installation identity, JWS issuance/validation, JWKS, authorization persistence, atomic single-use online consumption, expiration, revocation, binding to preparation/digest/algorithm/certificate/user/tenant/attempt, minimal audit, concurrency and replay tests. Also evaluate external reconciliation and anchoring of Engine state in the Hub, which addresses the accepted risk of coordinated rollback (E3–E4 review, REV-02/REV-04).
- [ ] P2 — Desktop: A1/A3 Windows, consent, authorized digest, SoftHSM and real token; VALIDAR evidence.
- [ ] P3 — Extension: Chrome/Edge, Native Messaging, multi-instance trust/revocation and security tests.
- [ ] P4 — SDK JS: independent browser/REST integration.
- [ ] P5 — Hub: expands P1.5 with tenants, documents, workflow, audit, queues and recovery.
- [ ] P6 — Bird ID: contract/credentials gate, OAuth2 and RAW homologation.
- [ ] P7 — SDK PHP: PSR client and external integration example.
- [ ] P8 — Distribution: Compose, WiX/MSI installer, signed artifacts, SBOM, source corresponding to release.
- [ ] P9 — Public beta: docs, legal/security review, supported platform matrix.

## Release mapping (SPEC §21)
| Release | Phases |
|---|---|
| v0.1.0 | P0 + P1 |
| v0.2.0 | P1.5 + P2 + P3 + P4 |
| v0.3.0 | P5 |
| v0.4.0 | P6 |
| v0.5.0 | P7 (+ batches) |
| v0.9.0 | P8 + P9 |
| v1.0.0 | All P0 gates, homologation, operations and documentation |

Each phase is implemented incrementally and reviewed before the next.
