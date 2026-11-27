// SPDX-License-Identifier: Apache-2.0
// Generates synthetic cryptographic vectors for contract tests and for other
// components (Hub, Desktop, Engine). Private keys are ephemeral: they exist only
// in memory during this run and are never written. Re-running changes keys and
// signatures (ES256 and new RSA keys are randomized); commit the regenerated set
// together. All data is synthetic.
import { KeyObject, createHash, generateKeyPairSync, sign as nodeSign, webcrypto } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import canonicalize from 'canonicalize';
import { CompactSign, exportJWK, generateKeyPair } from 'jose';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const out = (name) => join(root, 'fixtures/v1/crypto', name);
const b64 = (buf) => Buffer.from(buf).toString('base64');
const enc = new TextEncoder();

const claimsCases = JSON.parse(readFileSync(join(root, 'fixtures/v1/authorization/claims.cases.json'), 'utf8'));
const baseClaims = claimsCases.valid[0].data;
const KID = 'synthetic-2026-11-a';
const header = { alg: 'ES256', typ: 'signport-local-authz+jwt', kid: KID };

async function es256(claims, hdr, key) {
  return new CompactSign(enc.encode(JSON.stringify(claims))).setProtectedHeader(hdr).sign(key);
}

// Signs exact header/payload bytes (needed for duplicate-member vectors that
// object-based APIs cannot express). WebCrypto ECDSA returns IEEE P1363 R||S.
async function es256Raw(headerText, payloadText, key) {
  const input = `${Buffer.from(headerText).toString('base64url')}.${Buffer.from(payloadText).toString('base64url')}`;
  const sig = await webcrypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, enc.encode(input));
  return `${input}.${Buffer.from(sig).toString('base64url')}`;
}

async function authorizationVectors() {
  const trusted = await generateKeyPair('ES256', { extractable: true });
  const attacker = await generateKeyPair('ES256', { extractable: true });
  const publicJwk = { ...(await exportJWK(trusted.publicKey)), kid: KID, use: 'sig', alg: 'ES256' };
  const attackerJwk = await exportJWK(attacker.publicKey);
  const cases = [];
  const add = (name, jws, expect, verifyAt, extra = {}) => cases.push({ name, jws, expect, verify_at: verifyAt, ...extra });
  const t0 = baseClaims.iat + 30;

  const valid = await es256(baseClaims, header, trusted.privateKey);
  add('valid', valid, 'valid', t0);

  const [h, , s] = valid.split('.');
  const tamperedPayload = Buffer.from(
    JSON.stringify({ ...baseClaims, signed_attributes_digest_b64: 'JNdMGc/tNt+VOGJKyWKnwGKpAmgmVX/PU8T65xkBEjA=' }),
  ).toString('base64url');
  add('payload tampered after signing', `${h}.${tamperedPayload}.${s}`, 'AUTHORIZATION_INVALID', t0);

  add('signed by untrusted key with trusted kid', await es256(baseClaims, header, attacker.privateKey), 'AUTHORIZATION_INVALID', t0);
  add('unknown kid', await es256(baseClaims, { ...header, kid: 'unknown-kid' }, trusted.privateKey), 'INSTANCE_UNTRUSTED', t0);
  add(
    'embedded attacker jwk header',
    await es256(baseClaims, { ...header, jwk: attackerJwk }, attacker.privateKey),
    'AUTHORIZATION_INVALID',
    t0,
  );

  const noneHeader = Buffer.from(JSON.stringify({ alg: 'none', typ: header.typ, kid: KID })).toString('base64url');
  const payload = Buffer.from(JSON.stringify(baseClaims)).toString('base64url');
  add('alg none', `${noneHeader}.${payload}.`, 'AUTHORIZATION_INVALID', t0);

  const hmacSecret = enc.encode(JSON.stringify(publicJwk));
  add(
    'HS256 with public key as secret (algorithm confusion)',
    await new CompactSign(enc.encode(JSON.stringify(baseClaims))).setProtectedHeader({ ...header, alg: 'HS256' }).sign(hmacSecret),
    'AUTHORIZATION_INVALID',
    t0,
  );

  add('generic JWT typ', await es256(baseClaims, { ...header, typ: 'JWT' }, trusted.privateKey), 'AUTHORIZATION_INVALID', t0);
  add('expired', valid, 'AUTHORIZATION_EXPIRED', baseClaims.exp + 120);
  add('not yet valid', valid, 'AUTHORIZATION_EXPIRED', baseClaims.nbf - 120);
  add('wrong audience', await es256({ ...baseClaims, aud: 'other.host' }, header, trusted.privateKey), 'AUTHORIZATION_INVALID', t0);
  add(
    'ttl above host maximum',
    await es256({ ...baseClaims, exp: baseClaims.iat + 86400 }, header, trusted.privateKey),
    'AUTHORIZATION_INVALID',
    t0,
  );
  add(
    'untrusted issuer',
    await es256({ ...baseClaims, iss: 'https://evil.example.invalid' }, header, trusted.privateKey),
    'INSTANCE_UNTRUSTED',
    t0,
  );
  add(
    'consent manifest hash mismatch',
    await es256({ ...baseClaims, consent_manifest_sha256: '0'.repeat(64) }, header, trusted.privateKey),
    'AUTHORIZATION_INVALID',
    t0,
  );
  add(
    'consent shows a different document than claims',
    await es256(
      { ...baseClaims, document: { ...baseClaims.document, document_sha256: 'f'.repeat(64) } },
      header,
      trusted.privateKey,
    ),
    'AUTHORIZATION_INVALID',
    t0,
  );
  const claimsText = JSON.stringify(baseClaims);
  const dupPayload = claimsText.replace(
    '"signed_attributes_digest_b64":',
    '"signed_attributes_digest_b64":"JNdMGc/tNt+VOGJKyWKnwGKpAmgmVX/PU8T65xkBEjA=","signed_attributes_digest_b64":',
  );
  add('duplicate claim member (parser differential)', await es256Raw(JSON.stringify(header), dupPayload, trusted.privateKey), 'AUTHORIZATION_INVALID', t0);
  const escapedDup = claimsText.replace('"aud":', '"\\u0061ud":"other.host","aud":');
  add('duplicate claim via escaped member name', await es256Raw(JSON.stringify(header), escapedDup, trusted.privateKey), 'AUTHORIZATION_INVALID', t0);
  const dupHeader = `{"alg":"HS256","alg":"ES256","typ":"${header.typ}","kid":"${KID}"}`;
  add('duplicate header member', await es256Raw(dupHeader, claimsText, trusted.privateKey), 'AUTHORIZATION_INVALID', t0);
  const signingInput = valid.split('.').slice(0, 2).join('.');
  const derSig = nodeSign('sha256', enc.encode(signingInput), { key: KeyObject.from(trusted.privateKey), dsaEncoding: 'der' });
  add('ECDSA signature in ASN.1 DER instead of R||S', `${signingInput}.${derSig.toString('base64url')}`, 'AUTHORIZATION_INVALID', t0);

  add('valid JWS, command digest differs', valid, 'AUTHORIZATION_INVALID', t0, {
    command_override: { signedAttributesDigestB64: 'JNdMGc/tNt+VOGJKyWKnwGKpAmgmVX/PU8T65xkBEjA=' },
  });
  add('valid JWS, command certificate differs', valid, 'AUTHORIZATION_INVALID', t0, {
    command_override: { certificateSha256: 'e'.repeat(64) },
  });
  add('valid JWS, sender origin differs', valid, 'ORIGIN_DENIED', t0, { sender_origin: 'https://evil.example.invalid' });

  return {
    description:
      'Synthetic ES256 local-authorization vectors. JWS ES256 signatures are 64-byte R||S (RFC 7518 §3.4), never ASN.1 DER; header and payload must be parsed with duplicate-member rejection. Trust configuration below models the host instance store (SPEC §27.1); the JWKS is NOT a trust bootstrap. Expected outcomes follow claims.schema.json semantic rules. Private keys were ephemeral and discarded.',
    trust: {
      issuer: baseClaims.iss,
      instance_id: baseClaims.instance_id,
      jwks: { keys: [publicJwk] },
      max_ttl_seconds: 600,
      clock_skew_seconds: 30,
    },
    sender_origin: baseClaims.origin,
    command: {
      attemptId: baseClaims.attempt_id,
      signedAttributesDigestB64: baseClaims.signed_attributes_digest_b64,
      digestAlgorithm: baseClaims.digest_algorithm,
      signatureAlgorithm: baseClaims.signature_algorithm,
      certificateSha256: baseClaims.certificate_sha256,
    },
    cases,
  };
}

function rsaSignHashVector() {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const message = Buffer.from('SYNTHETIC stand-in for DER-encoded CMS signed attributes (P0 vector, not a real CMS).', 'utf8');
  const digest = createHash('sha256').update(message).digest();
  // RSASSA-PKCS1-v1_5 over SHA-256(message): identical to SignHash(digest) on the host.
  const signature = nodeSign('sha256', message, privateKey);
  // The classic mistake: hashing the digest again (SignData(digest)).
  const doubleHashed = nodeSign('sha256', digest, privateKey);
  return {
    description:
      'Known-answer vector for "no double hashing" (SPEC §5). signature_b64 = RSASSA-PKCS1-v1_5/SHA-256 over message, i.e. SignHash(digest_b64). double_hashed_signature_b64 = SignData(digest) and MUST be rejected as a signature of message. Synthetic ephemeral key; private key discarded.',
    algorithm: 'RSA_PKCS1_V1_5',
    digest_algorithm: 'SHA-256',
    modulus_bits: 2048,
    public_key_spki_der_b64: b64(publicKey.export({ type: 'spki', format: 'der' })),
    message_b64: b64(message),
    digest_b64: b64(digest),
    signature_b64: b64(signature),
    double_hashed_signature_b64: b64(doubleHashed),
  };
}

function jcsVectors() {
  // Expected outputs for the RFC 8785 cases are copied from the RFC (independent of
  // the library); the manifest case is computed. Plain alphabetical sorting fails
  // the 'sorting' case (UTF-16 code-unit order) and number formatting fails 'numbers'.
  const cases = [
    {
      name: 'RFC 8785 §3.2.4 example (numbers, escapes, literals)',
      input_json:
        '{"numbers":[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001],"string":"\\u20ac$\\u000F\\u000aA\'\\u0042\\u0022\\u005c\\\\\\"\\/","literals":[null,true,false]}',
      canonical: '{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}',
    },
    {
      name: 'RFC 8785 §3.2.3 sorting by UTF-16 code units',
      input_json:
        '{"\\u20ac":"Euro Sign","\\r":"Carriage Return","\\ufb33":"Hebrew Letter Dalet With Dagesh","1":"One","\\ud83d\\ude00":"Emoji: Grinning Face","\\u0080":"Control","\\u00f6":"Latin Small Letter O With Diaeresis"}',
      canonical:
        '{"\\r":"Carriage Return","1":"One","\u0080":"Control","\u00f6":"Latin Small Letter O With Diaeresis","\u20ac":"Euro Sign","\ud83d\ude00":"Emoji: Grinning Face","\ufb33":"Hebrew Letter Dalet With Dagesh"}',
    },
    {
      name: 'nested objects and arrays keep array order',
      input_json: '[56,{"d":true,"10":null,"1":[]}]',
      canonical: '[56,{"1":[],"10":null,"d":true}]',
    },
    { name: 'consent manifest fixture', input_json: JSON.stringify(baseClaims.consent), canonical: canonicalize(baseClaims.consent) },
  ];
  for (const c of cases) {
    if (canonicalize(JSON.parse(c.input_json)) !== c.canonical) throw new Error(`JCS mismatch: ${c.name}`);
    c.canonical_utf8_sha256 = createHash('sha256').update(c.canonical, 'utf8').digest('hex');
  }
  return {
    description:
      'RFC 8785 (JCS) cross-language vectors. Every implementation (PHP Hub, .NET Desktop, JS tests) must produce canonical exactly and the same SHA-256 over its UTF-8 bytes.',
    cases,
  };
}

const write = (name, data) => writeFileSync(out(name), `${JSON.stringify(data, null, 2)}\n`);
write('authorization-jws.vectors.json', await authorizationVectors());
write('rsa-signhash.vector.json', rsaSignHashVector());
write('jcs.vectors.json', jcsVectors());
console.log('crypto fixtures written to fixtures/v1/crypto');
