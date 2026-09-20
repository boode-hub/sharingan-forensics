import { describe, expect, it } from 'vitest';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { bufReader } from '../core/reader';
import { run } from '../core/registry';
import { evtx } from './evtx';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURE_DIR = join(__dirname, '../../fixtures/evtx');

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
    if (out.writtenTime instanceof Date) {
      out.writtenTime = out.writtenTime.toISOString();
    }
    return out;
  });
}

describe('evtx parser', () => {
  const expected = loadExpected();

  for (const [name, expRows] of Object.entries(expected)) {
    it(`parses ${name} correctly`, async () => {
      const buf = loadFixture(name);
      const reader = bufReader(buf, name);
      const outcome = await run(evtx, reader);
      const got = normalizeRows(outcome.rows);
      expect(got).toEqual(expRows);
    });
  }

  describe('truncation tests', () => {
    it('never throws or hangs across several truncation points', async () => {
      const buf = loadFixture('Synthetic.evtx');
      const lengths = [100, 4096, 5000, Math.floor(buf.length / 2)];
      for (const len of lengths) {
        const truncated = buf.subarray(0, len);
        const reader = bufReader(truncated, 'Synthetic.evtx');
        const outcome = await run(evtx, reader);
        expect(outcome.rows).toBeDefined();
      }
    });

    it('produces zero rows and a warning with no chunks at all', async () => {
      const buf = loadFixture('Synthetic.evtx');
      const truncated = buf.subarray(0, 4096);
      const reader = bufReader(truncated, 'Synthetic.evtx');
      const outcome = await run(evtx, reader);
      expect(outcome.rows.length).toBe(0);
      expect(outcome.warnings.length).toBeGreaterThan(0);
    });
  });

  describe('garbage test', () => {
    it('does not throw or hang on random bytes with ElfFile\\0 at offset 0', async () => {
      const buf = new Uint8Array(70000);
      for (let i = 0; i < buf.length; i += 65536) {
        crypto.getRandomValues(buf.subarray(i, Math.min(i + 65536, buf.length)));
      }
      const sig = 'ElfFile\0';
      for (let i = 0; i < sig.length; i++) buf[i] = sig.charCodeAt(i);
      const reader = bufReader(buf, 'garbage.evtx');
      const outcome = await run(evtx, reader);
      expect(outcome.rows).toBeDefined();
    });
  });
});
