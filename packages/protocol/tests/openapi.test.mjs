// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { parse } from 'yaml';
import { describe, expect, it } from 'vitest';
import { ID_BASE, ROOT, ajv } from './support/schemas.mjs';

const load = (name) => parse(readFileSync(join(ROOT, 'openapi', name), 'utf8'));
const engine = load('engine.v1.yaml');
const hub = load('hub-authorization.v1.yaml');
const METHODS = ['get', 'post', 'put', 'patch', 'delete'];

function operations(doc) {
  const ops = [];
  for (const [path, item] of Object.entries(doc.paths)) {
    for (const m of METHODS) if (item[m]) ops.push({ key: `${m.toUpperCase()} ${path}`, path, method: m, item, op: item[m] });
  }
  return ops;
}

const paramNames = (doc, { item, op }) =>
  [...(item.parameters ?? []), ...(op.parameters ?? [])].map((p) =>
    p.$ref ? doc.components.parameters[p.$ref.split('/').pop()].name : p.name,
  );

function externalRefs(node, out = []) {
  if (node && typeof node === 'object') {
    for (const [k, v] of Object.entries(node)) {
      if (k === '$ref' && typeof v === 'string' && !v.startsWith('#')) out.push(v);
      else externalRefs(v, out);
    }
  }
  return out;
}

describe('Engine OpenAPI (ADR-0014)', () => {
  it('is OpenAPI 3.1 with Apache-2.0 license', () => {
    expect(engine.openapi).toBe('3.1.0');
    expect(engine.info.license.identifier).toBe('Apache-2.0');
  });

  it('exposes exactly the canonical route set, without aliases', () => {
    const expected = [
      'POST /v1/pdf/preparations',
      'GET /v1/pdf/preparations/{preparation_id}',
      'POST /v1/pdf/preparations/{preparation_id}/complete',
      'DELETE /v1/pdf/preparations/{preparation_id}',
      'POST /v1/pdf/validations',
      'GET /v1/pdf/validations/{validation_id}',
      'POST /v1/certificates/inspect',
      'POST /v1/certificates/validate',
      'GET /v1/policies',
      'GET /v1/capabilities',
      'GET /health/live',
      'GET /health/ready',
    ];
    expect(operations(engine).map((o) => o.key).sort()).toEqual(expected.sort());
  });

  it('requires service authentication everywhere except health probes', () => {
    expect(engine.security).toEqual([{ serviceToken: [] }, { mutualTLS: [] }]);
    for (const o of operations(engine)) {
      if (o.path.startsWith('/health/')) expect(o.op.security, o.key).toEqual([]);
      else expect(o.op.security, o.key).toBeUndefined();
    }
  });

  it('accepts Idempotency-Key on mutating POSTs', () => {
    for (const key of ['POST /v1/pdf/preparations', 'POST /v1/pdf/preparations/{preparation_id}/complete', 'POST /v1/pdf/validations']) {
      const o = operations(engine).find((x) => x.key === key);
      expect(paramNames(engine, o), key).toContain('Idempotency-Key');
    }
  });
});

describe('Hub Authorization Foundation OpenAPI (ADR-0013)', () => {
  it('exposes exactly the P1.5 endpoints', () => {
    expect(operations(hub).map((o) => o.key).sort()).toEqual(
      [
        'GET /.well-known/jwks.json',
        'GET /api/v1/instance',
        'POST /api/v1/local/authorizations',
        'POST /api/v1/local/authorizations/consume',
        'POST /api/v1/local/authorizations/{authorization_id}/revoke',
      ].sort(),
    );
  });

  it('requires an authenticated session with CSRF to issue or revoke', () => {
    for (const key of ['POST /api/v1/local/authorizations', 'POST /api/v1/local/authorizations/{authorization_id}/revoke']) {
      const o = operations(hub).find((x) => x.key === key);
      expect(o.op.security, key).toEqual([{ sessionCookie: [], csrfHeader: [] }]);
    }
  });

  it('authenticates consume only by the JWS and never makes it idempotent', () => {
    const o = operations(hub).find((x) => x.key === 'POST /api/v1/local/authorizations/consume');
    expect(o.op.security).toEqual([]);
    expect(paramNames(hub, o)).not.toContain('Idempotency-Key');
    expect(Object.keys(o.op.responses)).toEqual(expect.arrayContaining(['200', '401', '409', '410']));
  });

  it('serves JWKS and instance metadata without authentication', () => {
    for (const key of ['GET /.well-known/jwks.json', 'GET /api/v1/instance']) {
      expect(operations(hub).find((x) => x.key === key).op.security, key).toEqual([]);
    }
  });
});

describe('OpenAPI documents', () => {
  for (const [name, doc] of [['engine.v1.yaml', engine], ['hub-authorization.v1.yaml', hub]]) {
    it(`${name}: every external $ref resolves to a compiled schema`, () => {
      const refs = externalRefs(doc);
      expect(refs.length).toBeGreaterThan(0);
      for (const ref of refs) {
        const [file, fragment] = ref.split('#');
        expect(file.startsWith('../schemas/v1/'), ref).toBe(true);
        const id = ID_BASE + file.replace('../', '') + (fragment ? `#${fragment}` : '');
        expect(ajv().getSchema(id), ref).toBeTypeOf('function');
      }
    });

    it(`${name}: every operation has an operationId and documented error responses`, () => {
      for (const o of operations(doc)) {
        expect(o.op.operationId, o.key).toMatch(/^[a-z][A-Za-z]+$/);
        expect(Object.keys(o.op.responses).some((c) => /^[45]/.test(c)), o.key).toBe(true);
      }
    });
  }
});
