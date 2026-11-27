// SPDX-License-Identifier: Apache-2.0
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';

export const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
export const ID_BASE = 'https://signport.invalid/';

export function walk(dir, predicate) {
  const out = [];
  for (const name of readdirSync(dir).sort()) {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) out.push(...walk(full, predicate));
    else if (predicate(full)) out.push(full);
  }
  return out;
}

export const readJson = (file) => JSON.parse(readFileSync(file, 'utf8'));
export const rel = (file) => relative(ROOT, file).split(sep).join('/');

export function schemaFiles() {
  return walk(join(ROOT, 'schemas'), (f) => f.endsWith('.schema.json'));
}

export function createAjv() {
  // strictRequired/strictTypes are relaxed only because oneOf branches constrain
  // properties declared on the parent object (discriminated envelopes).
  const ajv = new Ajv2020({ strict: true, strictRequired: false, strictTypes: false, allErrors: true });
  addFormats(ajv);
  for (const file of schemaFiles()) ajv.addSchema(readJson(file));
  return ajv;
}

let shared;
export function ajv() {
  shared ??= createAjv();
  return shared;
}

export function validatorFor(ref) {
  const v = ajv().getSchema(ref);
  if (!v) throw new Error(`schema not found: ${ref}`);
  return v;
}

// Minimal RFC 6902 (add, remove, replace) used by negative fixtures.
function parsePointer(pointer) {
  if (pointer === '') return [];
  if (!pointer.startsWith('/')) throw new Error(`invalid pointer ${pointer}`);
  return pointer
    .slice(1)
    .split('/')
    .map((t) => t.replace(/~1/g, '/').replace(/~0/g, '~'));
}

export function applyPatch(doc, ops) {
  let out = structuredClone(doc);
  for (const op of ops) {
    const tokens = parsePointer(op.path);
    if (tokens.length === 0) {
      if (op.op === 'remove') throw new Error('cannot remove root');
      out = structuredClone(op.value);
      continue;
    }
    const last = tokens.pop();
    let parent = out;
    for (const t of tokens) {
      parent = parent[Array.isArray(parent) ? Number(t) : t];
      if (parent === undefined) throw new Error(`path not found: ${op.path}`);
    }
    const isArr = Array.isArray(parent);
    const key = isArr ? (last === '-' ? parent.length : Number(last)) : last;
    if (op.op === 'add') {
      if (isArr) parent.splice(key, 0, structuredClone(op.value));
      else parent[key] = structuredClone(op.value);
    } else if (op.op === 'replace' || op.op === 'remove') {
      if (!(isArr ? key < parent.length : Object.hasOwn(parent, key))) throw new Error(`path not found: ${op.path}`);
      if (op.op === 'remove') {
        if (isArr) parent.splice(key, 1);
        else delete parent[key];
      } else parent[key] = structuredClone(op.value);
    } else throw new Error(`unsupported op ${op.op}`);
  }
  return out;
}
