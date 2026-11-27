// SPDX-License-Identifier: Apache-2.0
// Strict RFC 8259 parser that rejects duplicate object member names after
// unescaping (I-JSON, RFC 7493 §2.3), as required for JWS headers/claims and
// Native Messaging messages. Test-support reference; production components use
// their platform's parser configured to reject duplicates.

const WS = /[ \t\n\r]*/y;
const STRING = /"(?:[^"\\\u0000-\u001F]|\\(?:["\\/bfnrt]|u[0-9A-Fa-f]{4}))*"/y;
const NUMBER = /-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/y;

export class StrictJsonError extends Error {}

export function parseStrictJson(text) {
  let i = 0;
  const fail = (msg) => {
    throw new StrictJsonError(`${msg} at offset ${i}`);
  };
  const ws = () => {
    WS.lastIndex = i;
    WS.exec(text);
    i = WS.lastIndex;
  };
  const match = (re) => {
    re.lastIndex = i;
    const m = re.exec(text);
    if (!m) return null;
    i = re.lastIndex;
    return m[0];
  };
  const value = (depth) => {
    if (depth > 64) fail('nesting too deep');
    ws();
    const ch = text[i];
    if (ch === '{') {
      i++;
      const obj = {};
      const seen = new Set();
      ws();
      if (text[i] === '}') {
        i++;
        return obj;
      }
      for (;;) {
        ws();
        const raw = match(STRING) ?? fail('expected member name');
        const key = JSON.parse(raw);
        if (seen.has(key)) fail(`duplicate member "${key}"`);
        seen.add(key);
        ws();
        if (text[i++] !== ':') fail('expected ":"');
        Object.defineProperty(obj, key, { value: value(depth + 1), enumerable: true, writable: true, configurable: true });
        ws();
        if (text[i] === ',') i++;
        else if (text[i] === '}') {
          i++;
          return obj;
        } else fail('expected "," or "}"');
      }
    }
    if (ch === '[') {
      i++;
      const arr = [];
      ws();
      if (text[i] === ']') {
        i++;
        return arr;
      }
      for (;;) {
        arr.push(value(depth + 1));
        ws();
        if (text[i] === ',') i++;
        else if (text[i] === ']') {
          i++;
          return arr;
        } else fail('expected "," or "]"');
      }
    }
    if (ch === '"') return JSON.parse(match(STRING) ?? fail('invalid string'));
    for (const [lit, v] of [['true', true], ['false', false], ['null', null]]) {
      if (text.startsWith(lit, i)) {
        i += lit.length;
        return v;
      }
    }
    const num = match(NUMBER);
    if (num !== null) return Number(num);
    return fail('unexpected token');
  };
  const result = value(0);
  ws();
  if (i !== text.length) fail('trailing data');
  return result;
}
