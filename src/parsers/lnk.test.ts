import { describe, expect, it } from 'vitest';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { bufReader } from '../core/reader';
import { run } from '../core/registry';
import { lnk } from './lnk';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURE_DIR = join(__dirname, '../../fixtures/lnk');

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
    if (out.targetCreated instanceof Date) out.targetCreated = out.targetCreated.toISOString();
    if (out.targetModified instanceof Date) out.targetModified = out.targetModified.toISOString();
    if (out.targetAccessed instanceof Date) out.targetAccessed = out.targetAccessed.toISOString();
    return out;
  });
}

describe('lnk parser', () => {
  const expected = loadExpected();

  for (const [name, expRows] of Object.entries(expected)) {
    if (name === '_comment') continue;
    it(`parses ${name} correctly`, async () => {
      const buf = loadFixture(name);
      const reader = bufReader(buf, name);
      const outcome = await run(lnk, reader);
      const got = normalizeRows(outcome.rows);
      expect(got).toEqual(expRows);
    });
  }

  describe('truncation tests', () => {
    for (const name of Object.keys(expected)) {
      if (name === '_comment') continue;
      it(`does not throw on truncated ${name}`, async () => {
        const buf = loadFixture(name);
        const lengths = [20, 76, 200, Math.floor(buf.length / 2)];
        for (const len of lengths) {
          if (len >= buf.length) continue;
          const truncated = buf.subarray(0, len);
          const reader = bufReader(truncated, name);
          const outcome = await run(lnk, reader);
          expect(outcome.rows.length).toBeLessThanOrEqual(expected[name].length);
        }
      });
    }
  });

  describe('garbage test', () => {
    it('does not throw on random bytes with valid header', async () => {
      const buf = new Uint8Array(4096);
      crypto.getRandomValues(buf);
      buf[0] = 0x4c;
      buf[1] = 0x00;
      buf[2] = 0x00;
      buf[3] = 0x00;
      buf[4] = 0x01;
      buf[5] = 0x14;
      buf[6] = 0x02;
      buf[7] = 0x00;
      buf[8] = 0x00;
      buf[9] = 0x00;
      buf[10] = 0x00;
      buf[11] = 0x00;
      buf[12] = 0xc0;
      buf[13] = 0x00;
      buf[14] = 0x00;
      buf[15] = 0x00;
      buf[16] = 0x00;
      buf[17] = 0x00;
      buf[18] = 0x00;
      buf[19] = 0x46;
      const reader = bufReader(buf, 'garbage.lnk');
      const outcome = await run(lnk, reader);
      expect(outcome.rows).toBeDefined();
    });
  });
});