# ADR-0013 — Authorization Foundation and implementation sequencing
Status: Accepted (27/11/2026, founder decision). Technical gates open.

## Context
The Desktop host (P2) must consume a single-use JWS authorization online at the Hub before any private-key operation (SPEC §§8.5, 27.2). In the previous order the Hub only arrived in P5, so P2 could not be implemented or tested without a fake authorization service, which AGENTS.md forbids ("no stub may return false success"). SPEC §13 and ROADMAP.md also disagreed on phase order.

## Decision
1. ROADMAP.md is the canonical implementation order. SPEC §§13, 21 and 28 are harmonized with it.
2. New phase **P1.5 — Authorization Foundation**, between P1 and P2, implemented inside `apps/hub` (Laravel). No new microservice. Scope: Laravel bootstrap; installation identity; JWS issuance and validation; JWKS publication; authorization persistence; atomic single-use online consumption; expiration; revocation; binding to preparation, CMS signed-attributes digest, algorithm, certificate, user, tenant and attempt; minimal audit; concurrency and replay tests.
3. Endpoints: `GET /.well-known/jwks.json`, `GET /api/v1/instance`, `POST /api/v1/local/authorizations`, `POST /api/v1/local/authorizations/consume`, `POST /api/v1/local/authorizations/{id}/revoke`. Contracts live in `packages/protocol/openapi/hub-authorization.v1.yaml` (defined in P0).
4. Issuance requires an authenticated web session and an authorized context (active attempt, consent recorded). Consumption happens after native local consent and before the cryptographic operation; consumption is never idempotent (a second call is a replay).
5. P5 expands this Hub; it does not replace it. Release v0.2.0 includes P1.5.

## Alternatives
- Separate authorization microservice: rejected (extra deployment, contradicts monolith ADR-0002).
- Lab-only stub issuer: rejected (risk of false success, duplicated logic later).
- Implement the full Hub before Desktop: rejected (delays hardware risk discovery).

## Security and licensing impact
JWS private key is dedicated (ES256, separate from webhook keys). JWKS publication does not replace trusted key bootstrap in the host (SPEC §27.1). Hub code remains AGPL-3.0-or-later; contracts Apache-2.0.

## Consequences
Hub bootstrap happens earlier with a deliberately narrow scope; tenancy and users exist only as needed to bind authorizations and must be expanded, not rewritten, in P5.

## Validation evidence
Pending: P1.5 concurrency (HUB-13) and replay tests in CI.
