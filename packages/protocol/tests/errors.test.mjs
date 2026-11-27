// SPDX-License-Identifier: Apache-2.0
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { ROOT, readJson } from './support/schemas.mjs';

const registry = readJson(join(ROOT, 'errors/registry.json')).errors;
const schema = readJson(join(ROOT, 'schemas/v1/errors.schema.json')).$defs;
const sorted = (a) => [...a].sort();

describe('error taxonomy', () => {
  it('has unique UPPER_SNAKE_CASE codes', () => {
    const codes = registry.map((e) => e.code);
    expect(new Set(codes).size).toBe(codes.length);
    for (const c of codes) expect(c).toMatch(/^[A-Z][A-Z0-9_]*$/);
  });

  it('schema enums mirror the registry', () => {
    expect(sorted(schema.ErrorCode.enum)).toEqual(sorted(registry.map((e) => e.code)));
    expect(sorted(schema.NativeErrorCode.enum)).toEqual(
      sorted(registry.filter((e) => e.surfaces.includes('native')).map((e) => e.code)),
    );
    expect(sorted(schema.HttpErrorCode.enum)).toEqual(
      sorted(
        registry
          .filter((e) => e.http_status !== null && (e.surfaces.includes('hub') || e.surfaces.includes('engine')))
          .map((e) => e.code),
      ),
    );
  });

  it('includes every Native Messaging error listed in SPEC §8.4', () => {
    const spec = [
      'EXTENSION_MISSING', 'HOST_MISSING', 'VERSION_UNSUPPORTED', 'ORIGIN_DENIED', 'INVALID_MESSAGE',
      'AUTHORIZATION_INVALID', 'AUTHORIZATION_EXPIRED', 'REPLAY', 'CERT_NOT_FOUND', 'TOKEN_REMOVED',
      'PIN_CANCELLED', 'PIN_BLOCKED', 'DRIVER_UNAVAILABLE', 'UNSUPPORTED_ALGORITHM', 'NATIVE_DISCONNECTED', 'TIMEOUT',
    ];
    expect(spec.filter((c) => !schema.NativeErrorCode.enum.includes(c))).toEqual([]);
  });

  it('declares consistent surfaces, origins and HTTP statuses', () => {
    for (const e of registry) {
      expect(e.surfaces.length, e.code).toBeGreaterThan(0);
      const http = e.surfaces.includes('hub') || e.surfaces.includes('engine');
      if (http) expect(e.http_status, e.code).toBeGreaterThanOrEqual(400);
      else expect(e.http_status, e.code).toBeNull();
      if (e.surfaces.includes('native')) expect(e.origins.length, e.code).toBeGreaterThan(0);
      for (const o of e.origins) expect(['sdk', 'extension', 'host']).toContain(o);
      expect(e.description.length, e.code).toBeGreaterThan(10);
    }
  });

  it('never marks ambiguous signing outcomes or PIN failures as retryable', () => {
    const mustNotRetry = [
      'TIMEOUT', 'NATIVE_DISCONNECTED', 'AUTHORIZATION_CONSUME_FAILED', 'REPLAY',
      'PIN_CANCELLED', 'PIN_BLOCKED', 'TOKEN_REMOVED', 'CONSENT_DECLINED',
    ];
    for (const code of mustNotRetry) expect(registry.find((e) => e.code === code).retryable, code).toBe(false);
  });
});
