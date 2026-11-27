// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { ROOT, readJson, validatorFor, walk } from './support/schemas.mjs';

const S = 'https://signport.invalid/schemas/v1/';
const NATIVE_LIMIT = 256 * 1024;
const bytes = (o) => Buffer.byteLength(JSON.stringify(o), 'utf8');

describe('Native Messaging size limits (256 KiB)', () => {
  it('largest schema-valid readCertificate response fits', () => {
    const der = `M${'A'.repeat(16383)}`; // 16384 chars, valid DerBase64
    const result = {
      certificateSha256: 'a'.repeat(64),
      certificateDerB64: der,
      chainDerB64: Array(10).fill(der),
    };
    expect(validatorFor(`${S}native/results.schema.json#/$defs/ReadCertificateResult`)(result)).toBe(true);
    expect(bytes({ protocol: 1, requestId: '01936f3c-0000-7000-8000-00000000000b', success: true, result })).toBeLessThan(NATIVE_LIMIT);
  });

  it('largest schema-valid listCertificates response fits (worst case: 4-byte UTF-8 characters)', () => {
    const text = '😀'.repeat(250); // 500 UTF-16 units = maxLength, 1000 bytes
    const cert = {
      certificateSha256: 'a'.repeat(64),
      subject: text,
      issuer: text,
      serialNumberHex: 'f'.repeat(64),
      notBefore: '2026-01-01T00:00:00.000000Z',
      notAfter: '2027-01-01T00:00:00.000000Z',
      keyAlgorithm: 'OTHER',
      keySizeBits: 16384,
      hasPrivateKey: true,
      eligibility: 'not_yet_valid',
    };
    const result = { certificates: Array(100).fill(cert) };
    const v = validatorFor(`${S}native/results.schema.json#/$defs/ListCertificatesResult`);
    expect(v(result), JSON.stringify(v.errors)).toBe(true);
    expect(bytes({ protocol: 1, requestId: '01936f3c-0000-7000-8000-00000000000b', success: true, result })).toBeLessThan(NATIVE_LIMIT);
  });

  it('every native fixture is far below the limit', () => {
    for (const f of walk(join(ROOT, 'fixtures/v1/native'), (x) => x.endsWith('.json'))) {
      for (const c of readJson(f).valid) expect(bytes(c.data)).toBeLessThan(NATIVE_LIMIT);
    }
  });
});

describe('license independence (Apache-2.0 contracts)', () => {
  const pkg = readJson(join(ROOT, 'package.json'));

  it('declares Apache-2.0 and has no runtime dependencies', () => {
    expect(pkg.license).toBe('Apache-2.0');
    expect(pkg.dependencies ?? {}).toEqual({});
  });

  it('does not reference copyleft components of the monorepo', () => {
    const files = walk(ROOT, (f) => !f.includes('node_modules') && /\.(json|ya?ml|mjs)$/.test(f) && !f.endsWith('pnpm-lock.yaml'));
    const offenders = files.filter((f) => /(\.\.\/)+(apps|providers)\//.test(readFileSync(f, 'utf8')));
    expect(offenders).toEqual([]);
  });
});
