import { describe, expect, it } from 'vitest';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { bufReader } from '../core/reader';
import { run } from '../core/registry';
import { recycleBin } from './recyclebin';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURE_DIR = join(__dirname, '../../fixtures/recyclebin');

function loadFixture(name: string): Uint8Array {
  return new Uint8Array(readFileSync(join(FIXTURE_DIR, name)));
}

function loadExpected(): Record<string, unknown[]> {
  const raw = readFileSync(join(FIXTURE_DIR, 'expected.json'), 'utf-8');
  return JSON.parse(raw);
}

function normalizeRows(rows: Record<string, unknown>[]): Record<string, unknown>[] {
  return rows.map((r) => {
    const out: Record<string, unknown> = { ...r };
    if (out.deletedOn instanceof Date) {
      out.deletedOn = out.deletedOn.toISOString();
    }
    return out;
  });
}

describe('recyclebin parser', () => {
  const expected = loadExpected();

  for (const [name, expRows] of Object.entries(expected)) {
    if (name === '_comment') continue;
    it(`parses ${name} correctly`, async () => {
      const buf = loadFixture(name);
      const reader = bufReader(buf, name);
      const outcome = await run(recycleBin, reader);
      const got = normalizeRows(outcome.rows);
      expect(got).toEqual(expRows);
    });
  }

  describe('truncation tests', () => {
    for (const name of Object.keys(expected)) {
      if (name === '_comment') continue;
      it(`does not throw on truncated ${name}`, async () => {
        const buf = loadFixture(name);
        const lengths = [10, 30, Math.floor(buf.length / 2)];
        for (const len of lengths) {
          if (len >= buf.length) continue;
          const truncated = buf.subarray(0, len);
          const reader = bufReader(truncated, name);
          const outcome = await run(recycleBin, reader);
          expect(outcome.rows.length).toBeLessThanOrEqual(expected[name].length);
        }
      });
    }
  });

  describe('garbage test', () => {
    it('does not throw on random bytes with valid $I version', async () => {
      const buf = new Uint8Array(4096);
      crypto.getRandomValues(buf);
      new DataView(buf.buffer).setBigUint64(0, 1n, true);
      const reader = bufReader(buf, '$Igarbage');
      const outcome = await run(recycleBin, reader);
      expect(outcome.rows).toBeDefined();
    });

    it('does not throw on random bytes with valid $I version 2', async () => {
      const buf = new Uint8Array(4096);
      crypto.getRandomValues(buf);
      new DataView(buf.buffer).setBigUint64(0, 2n, true);
      new DataView(buf.buffer).setUint32(24, 100, true);
      const reader = bufReader(buf, '$Igarbage2');
      const outcome = await run(recycleBin, reader);
      expect(outcome.rows).toBeDefined();
    });
  });
});