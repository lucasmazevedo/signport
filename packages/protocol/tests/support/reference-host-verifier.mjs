// SPDX-License-Identifier: Apache-2.0
// Executable specification of the native-host authorization checks
// (claims.schema.json description, SPEC §§8.5, 27.2, DESK-08). Test-only
// reference: it is NOT the Desktop implementation and NOT a library to ship.
// It performs no online consumption; that step belongs to the Hub (P1.5).
import { createHash } from 'node:crypto';
import canonicalize from 'canonicalize';
import { compactVerify, importJWK } from 'jose';
import { validatorFor } from './schemas.mjs';
import { parseStrictJson } from './strict-json.mjs';

const S = 'https://signport.invalid/schemas/v1/';
const fail = (code, detail) => ({ ok: false, code, detail });
const utf8 = new TextDecoder('utf-8', { fatal: true });
const decodeJsonSegment = (bytes) => parseStrictJson(utf8.decode(bytes));

export function consentManifestHash(consent) {
  return createHash('sha256').update(canonicalize(consent), 'utf8').digest('hex');
}

/**
 * @param {string} jws compact JWS from the signHash payload
 * @param {object} ctx { trust: {issuer, instance_id, jwks, max_ttl_seconds, clock_skew_seconds}, now, senderOrigin, command }
 */
export async function verifyLocalAuthorization(jws, ctx) {
  if (!validatorFor(`${S}common.schema.json#/$defs/CompactJws`)(jws)) return fail('AUTHORIZATION_INVALID', 'compact form');

  let header;
  try {
    // Duplicate members are rejected after unescaping (RFC 7515 §4, RFC 7493).
    header = decodeJsonSegment(Buffer.from(jws.split('.')[0], 'base64url'));
  } catch {
    return fail('AUTHORIZATION_INVALID', 'header decode');
  }
  if (!validatorFor(`${S}authorization/jws-header.schema.json`)(header)) return fail('AUTHORIZATION_INVALID', 'header schema');

  // ES256 JWS signatures are exactly 64 bytes R||S (RFC 7518 §3.4), never DER.
  if (Buffer.from(jws.split('.')[2], 'base64url').length !== 64) return fail('AUTHORIZATION_INVALID', 'signature encoding');

  // Only locally trusted keys; never keys or URLs from the message.
  const jwk = ctx.trust.jwks.keys.find((k) => k.kid === header.kid);
  if (!jwk) return fail('INSTANCE_UNTRUSTED', 'unknown kid');

  let payload;
  try {
    const key = await importJWK(jwk, 'ES256');
    ({ payload } = await compactVerify(jws, key, { algorithms: ['ES256'] }));
  } catch {
    return fail('AUTHORIZATION_INVALID', 'signature');
  }

  let claims;
  try {
    claims = decodeJsonSegment(payload);
  } catch {
    return fail('AUTHORIZATION_INVALID', 'payload json');
  }
  if (!validatorFor(`${S}authorization/claims.schema.json`)(claims)) return fail('AUTHORIZATION_INVALID', 'claims schema');

  if (claims.iss !== ctx.trust.issuer || claims.instance_id !== ctx.trust.instance_id)
    return fail('INSTANCE_UNTRUSTED', 'issuer/instance');

  const skew = ctx.trust.clock_skew_seconds;
  if (claims.exp - claims.iat > ctx.trust.max_ttl_seconds || claims.nbf > claims.exp || claims.iat > claims.exp)
    return fail('AUTHORIZATION_INVALID', 'lifetime');
  if (ctx.now + skew < claims.nbf || ctx.now - skew >= claims.exp) return fail('AUTHORIZATION_EXPIRED', 'time window');

  if (claims.origin !== ctx.senderOrigin) return fail('ORIGIN_DENIED', 'origin');

  const c = ctx.command;
  const bound =
    c.attemptId === claims.attempt_id &&
    c.signedAttributesDigestB64 === claims.signed_attributes_digest_b64 &&
    c.digestAlgorithm === claims.digest_algorithm &&
    c.signatureAlgorithm === claims.signature_algorithm &&
    c.certificateSha256 === claims.certificate_sha256;
  if (!bound) return fail('AUTHORIZATION_INVALID', 'command binding');

  const m = claims.consent;
  const consistent =
    m.instance.instance_id === claims.instance_id &&
    m.instance.origin === claims.origin &&
    m.document.document_sha256 === claims.document.document_sha256 &&
    m.certificate.certificate_sha256 === claims.certificate_sha256 &&
    m.purpose === claims.purpose;
  if (!consistent) return fail('AUTHORIZATION_INVALID', 'consent consistency');
  if (consentManifestHash(m) !== claims.consent_manifest_sha256) return fail('AUTHORIZATION_INVALID', 'consent hash');

  // Only now may the host display claims.consent (exactly the signed data), then
  // consume online at the Hub, and only after a confirmed consumption call SignHash.
  return { ok: true, claims, next: ['display_consent', 'consume_online', 'sign_hash'] };
}
