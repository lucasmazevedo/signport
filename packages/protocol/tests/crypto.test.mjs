// SPDX-License-Identifier: Apache-2.0
import { createHash, createPublicKey, verify } from 'node:crypto';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import canonicalize from 'canonicalize';
import { consentManifestHash, verifyLocalAuthorization } from './support/reference-host-verifier.mjs';
import { StrictJsonError, parseStrictJson } from './support/strict-json.mjs';
import { ROOT, readJson, validatorFor } from './support/schemas.mjs';

const S = 'https://signport.invalid/schemas/v1/';
const rsa = readJson(join(ROOT, 'fixtures/v1/crypto/rsa-signhash.vector.json'));
const authz = readJson(join(ROOT, 'fixtures/v1/crypto/authorization-jws.vectors.json'));
const claims = readJson(join(ROOT, 'fixtures/v1/authorization/claims.cases.json')).valid[0].data;
const buf = (b64) => Buffer.from(b64, 'base64');
const jcs = readJson(join(ROOT, 'fixtures/v1/crypto/jcs.vectors.json'));

describe('RSA SignHash known-answer vector (no double hashing)', () => {
  const key = createPublicKey({ key: buf(rsa.public_key_spki_der_b64), format: 'der', type: 'spki' });

  it('digest is SHA-256 of the signed bytes and matches the contract encoding', () => {
    expect(createHash('sha256').update(buf(rsa.message_b64)).digest('base64')).toBe(rsa.digest_b64);
    expect(validatorFor(`${S}common.schema.json#/$defs/Sha256Base64`)(rsa.digest_b64)).toBe(true);
    expect(validatorFor(`${S}common.schema.json#/$defs/RsaSignatureBase64`)(rsa.signature_b64)).toBe(true);
    expect(buf(rsa.signature_b64).length).toBe(rsa.modulus_bits / 8);
  });

  it('signature verifies over the signed bytes', () => {
    expect(verify('sha256', buf(rsa.message_b64), key, buf(rsa.signature_b64))).toBe(true);
  });

  it('double-hashed signature is rejected for the signed bytes', () => {
    expect(verify('sha256', buf(rsa.message_b64), key, buf(rsa.double_hashed_signature_b64))).toBe(false);
    // ...because it actually signs SHA-256(digest):
    expect(verify('sha256', buf(rsa.digest_b64), key, buf(rsa.double_hashed_signature_b64))).toBe(true);
  });
});

describe('consent manifest hash', () => {
  it('claims fixture binds the RFC 8785 (JCS) hash of the consent manifest', () => {
    expect(consentManifestHash(claims.consent)).toBe(claims.consent_manifest_sha256);
  });

  it('document hash and CMS digest are distinct values and encodings', () => {
    expect(Buffer.from(claims.signed_attributes_digest_b64, 'base64').toString('hex')).not.toBe(claims.document.document_sha256);
  });
});

describe('local authorization JWS vectors (reference host checks)', () => {
  it('publish only public keys in a schema-valid JWKS', () => {
    expect(validatorFor(`${S}authorization/jwks.schema.json`)(authz.trust.jwks)).toBe(true);
    for (const k of authz.trust.jwks.keys) expect(k).not.toHaveProperty('d');
  });

  it('covers a valid case and every expected rejection code', () => {
    expect(authz.cases.filter((c) => c.expect === 'valid')).toHaveLength(1);
    expect(new Set(authz.cases.map((c) => c.expect))).toEqual(
      new Set(['valid', 'AUTHORIZATION_INVALID', 'AUTHORIZATION_EXPIRED', 'INSTANCE_UNTRUSTED', 'ORIGIN_DENIED']),
    );
  });

  it.each(authz.cases.map((c) => [c.name, c]))('%s', async (_n, c) => {
    const result = await verifyLocalAuthorization(c.jws, {
      trust: authz.trust,
      now: c.verify_at,
      senderOrigin: c.sender_origin ?? authz.sender_origin,
      command: { ...authz.command, ...(c.command_override ?? {}) },
    });
    if (c.expect === 'valid') expect(result, JSON.stringify(result)).toMatchObject({ ok: true });
    else expect(result).toMatchObject({ ok: false, code: c.expect });
  });

  it('valid vector is usable as a signHash payload', () => {
    const valid = authz.cases.find((c) => c.expect === 'valid');
    const request = {
      protocol: 1,
      requestId: '01936f3c-0000-7000-8000-00000000000b',
      action: 'signHash',
      payload: { ...authz.command, authorization: valid.jws },
    };
    const v = validatorFor(`${S}native/request.schema.json`);
    expect(v(request), JSON.stringify(v.errors)).toBe(true);
  });
});

describe('RFC 8785 JCS cross-language vectors', () => {
  it.each(jcs.cases.map((c) => [c.name, c]))('%s', (_n, c) => {
    expect(canonicalize(JSON.parse(c.input_json))).toBe(c.canonical);
    expect(createHash('sha256').update(c.canonical, 'utf8').digest('hex')).toBe(c.canonical_utf8_sha256);
  });

  it('plain code-point key sorting is not JCS', () => {
    const c = jcs.cases.find((x) => x.name.includes('sorting'));
    const obj = JSON.parse(c.input_json);
    const naive = `{${Object.keys(obj)
      .sort((a, b) => a.codePointAt(0) - b.codePointAt(0))
      .map((k) => `${JSON.stringify(k)}:${JSON.stringify(obj[k])}`)
      .join(',')}}`;
    expect(naive).not.toBe(c.canonical);
  });
});

describe('strict JSON (duplicate members)', () => {
  it('parses valid JSON like JSON.parse', () => {
    const text = JSON.stringify(claims);
    expect(parseStrictJson(text)).toEqual(JSON.parse(text));
  });

  it.each([
    ['plain duplicate', '{"a":1,"a":2}'],
    ['escaped duplicate', '{"a":1,"\\u0061":2}'],
    ['nested duplicate', '{"x":{"k":1,"k":1}}'],
    ['trailing data', '{"a":1} {}'],
    ['raw control character in string', '{"a":"\u0001"}'],
  ])('rejects %s', (_n, text) => {
    expect(() => parseStrictJson(text)).toThrow(StrictJsonError);
  });

  it('treats __proto__ as an ordinary member', () => {
    const v = parseStrictJson('{"__proto__":{"polluted":true}}');
    expect(Object.hasOwn(v, '__proto__')).toBe(true);
    expect({}.polluted).toBeUndefined();
  });
});

describe('ES256 signature encoding', () => {
  it('DER-encoded signature is rejected by an explicit encoding check, not only by the library', async () => {
    const c = authz.cases.find((x) => x.name.includes('ASN.1 DER'));
    expect(Buffer.from(c.jws.split('.')[2], 'base64url').length).not.toBe(64);
    const r = await verifyLocalAuthorization(c.jws, {
      trust: authz.trust,
      now: c.verify_at,
      senderOrigin: authz.sender_origin,
      command: authz.command,
    });
    expect(r).toMatchObject({ ok: false, code: 'AUTHORIZATION_INVALID', detail: 'signature encoding' });
  });

  it('valid vector uses 64-byte R||S', () => {
    const valid = authz.cases.find((c) => c.expect === 'valid');
    expect(Buffer.from(valid.jws.split('.')[2], 'base64url')).toHaveLength(64);
  });
});
