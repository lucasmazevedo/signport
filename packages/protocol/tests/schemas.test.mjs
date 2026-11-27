// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';
import { ID_BASE, ajv, readJson, rel, schemaFiles } from './support/schemas.mjs';

const files = schemaFiles();

describe('JSON Schema files', () => {
  it('exist', () => {
    expect(files.length).toBeGreaterThan(5);
  });

  it.each(files.map((f) => [rel(f), f]))('%s declares 2020-12 and an $id matching its path', (path, file) => {
    const s = readJson(file);
    expect(s.$schema).toBe('https://json-schema.org/draft/2020-12/schema');
    expect(s.$id).toBe(ID_BASE + path);
  });

  it.each(files.map((f) => [rel(f), f]))('%s compiles in strict mode, including every $defs entry', (_path, file) => {
    const s = readJson(file);
    if (s.type || s.oneOf || s.properties) expect(ajv().getSchema(s.$id)).toBeTypeOf('function');
    for (const name of Object.keys(s.$defs ?? {})) {
      expect(ajv().getSchema(`${s.$id}#/$defs/${name}`), name).toBeTypeOf('function');
    }
  });

  it('closes every object schema (deny unknown fields by default)', () => {
    const open = [];
    const visit = (node, where) => {
      if (!node || typeof node !== 'object') return;
      if (node.type === 'object' && node.additionalProperties !== false) open.push(where);
      for (const [k, v] of Object.entries(node)) visit(v, `${where}/${k}`);
    };
    for (const f of files) visit(readJson(f), rel(f));
    // Generic placeholders refined by oneOf / per-action result schemas:
    const allowed = [
      'schemas/v1/native/request.schema.json/properties/payload',
      'schemas/v1/native/response.schema.json/properties/result',
    ];
    expect(open.filter((p) => !allowed.includes(p))).toEqual([]);
  });
});
