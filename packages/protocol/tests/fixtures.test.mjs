// SPDX-License-Identifier: Apache-2.0
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { ROOT, applyPatch, readJson, rel, validatorFor, walk } from './support/schemas.mjs';

const caseFiles = walk(join(ROOT, 'fixtures'), (f) => f.endsWith('.cases.json'));

describe('fixture case files', () => {
  it('cover native, authorization, engine and common contracts', () => {
    const areas = new Set(caseFiles.map((f) => rel(f).split('/')[2]));
    expect([...areas].sort()).toEqual(['authorization', 'common', 'engine', 'native']);
  });

  for (const file of caseFiles) {
    const suite = readJson(file);
    describe(rel(file), () => {
      const validate = validatorFor(suite.schema);

      it('has at least one valid and one invalid case', () => {
        expect(suite.valid.length).toBeGreaterThan(0);
        expect(suite.invalid.length).toBeGreaterThan(0);
      });

      it.each(suite.valid.map((c) => [c.name, c]))('accepts: %s', (_n, c) => {
        const ok = validate(c.data);
        expect(ok, JSON.stringify(validate.errors)).toBe(true);
      });

      it.each(suite.invalid.map((c) => [c.name, c]))('rejects: %s', (_n, c) => {
        expect(c.reason, 'every negative case documents its reason').toBeTruthy();
        const data = 'data' in c ? c.data : applyPatch(suite.valid[c.base].data, c.patch);
        expect(validate(data)).toBe(false);
      });
    });
  }
});
