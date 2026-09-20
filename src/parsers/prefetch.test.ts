import { describe, expect, it } from 'vitest';
import { existsSync, readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { bufReader } from '../core/reader';
import { run } from '../core/registry';
import { prefetch } from './prefetch';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURE_DIR = join(__dirname, '../../fixtures/prefetch');

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
    if (out.runTime instanceof Date) {
      out.runTime = out.runTime.toISOString();
    }
    if (out.volumeCreated instanceof Date) {
      out.volumeCreated = out.volumeCreated.toISOString();
    }
    return out;
  });
}

describe('prefetch parser', () => {
  const expected = loadExpected();

  for (const [name, expRows] of Object.entries(expected)) {
    if (name === '_comment') continue;
    it(`parses ${name} correctly`, async () => {
      const buf = loadFixture(name);
      const reader = bufReader(buf, name);
      const outcome = await run(prefetch, reader);
      const got = normalizeRows(outcome.rows);
      expect(got).toEqual(expRows);
    });
  }

  describe('truncation tests', () => {
    for (const name of Object.keys(expected)) {
      if (name === '_comment') continue;
      it(`does not throw on truncated ${name}`, async () => {
        const buf = loadFixture(name);
        const lengths = [50, 200, Math.floor(buf.length / 2)];
        for (const len of lengths) {
          if (len >= buf.length) continue;
          const truncated = buf.subarray(0, len);
          const reader = bufReader(truncated, name);
          const outcome = await run(prefetch, reader);
          expect(outcome.rows.length).toBeLessThanOrEqual(expected[name].length);
        }
      });
    }
  });

  describe('garbage test', () => {
    it('does not throw on random bytes with SCCA at offset 4', async () => {
      const buf = new Uint8Array(4096);
      crypto.getRandomValues(buf);
      // Write SCCA at offset 4
      buf[4] = 0x53; // S
      buf[5] = 0x43; // C
      buf[6] = 0x43; // C
      buf[7] = 0x41; // A
      // Also write a plausible version at offset 0
      buf[0] = 0x1f; // 31
      buf[1] = 0x00;
      buf[2] = 0x00;
      buf[3] = 0x00;
      const reader = bufReader(buf, 'garbage.pf');
      const outcome = await run(prefetch, reader);
      expect(outcome.rows).toBeDefined();
    });
  });
});

/**
 * Synthetic fixtures prove the layout; only a real file proves the parser.
 * Read from the local machine and never committed — real Prefetch names the
 * executables an analyst ran. Skipped wherever absent, including CI.
 */
const REAL_PF = 'C:/Windows/Prefetch/ANTIGRAVITY.EXE-6247EA31.pf';

describe.skipIf(!existsSync(REAL_PF))('real Windows 11 Prefetch', () => {
  it('parses a MAM-compressed v31 file', async () => {
    const buf = new Uint8Array(readFileSync(REAL_PF));
    const { rows, warnings } = await run(prefetch, bufReader(buf, 'ANTIGRAVITY.EXE-6247EA31.pf'));

    // Only first-chunk fields are asserted. The loaded-file list and volume
    // block come from later chunks, which the decompressor does not yet decode
    // correctly (see the note in src/core/xpress.ts), so the parser warns about
    // them and this test deliberately does not check them.
    expect(rows.length).toBe(8);
    expect(rows[0].executable).toBe('ANTIGRAVITY.EXE');
    // The hash in the body matching the hash in the filename is an independent
    // check that the first chunk decompressed byte-for-byte.
    expect(rows[0].hash).toBe('6247EA31');
    expect(rows[0].version).toBe(31);
    expect(rows[0].runCount).toBe(29);

    const times = rows.map((r) => (r.runTime as Date).getTime());
    expect(times).toEqual([...times].sort((a, b) => b - a));
    expect(times.every((t) => t > Date.parse('2000-01-01'))).toBe(true);

    // The multi-chunk caveat must be surfaced, never silently swallowed.
    expect(warnings.some((w) => w.message.includes('must not be relied on'))).toBe(true);
  });
});