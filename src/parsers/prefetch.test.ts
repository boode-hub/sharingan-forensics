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

/** Every Date becomes an ISO string, so expected.json can stay plain JSON. */
function normalizeRows(rows: Record<string, unknown>[]): Record<string, unknown>[] {
  return rows.map((r) =>
    Object.fromEntries(
      Object.entries(r).map(([k, v]) => [k, v instanceof Date ? v.toISOString() : v]),
    ),
  );
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
    // Windows rewrites this file every time the executable runs, so anything
    // that counts executions is a moving target. Assert the shape, not a value
    // that increments while the tests are being written.
    expect(rows.length).toBeGreaterThan(0);
    expect(rows.length).toBeLessThanOrEqual(8);
    expect(rows[0].executable).toBe('ANTIGRAVITY.EXE');
    // The hash in the body matching the hash in the filename is an independent
    // check that the first chunk decompressed byte-for-byte.
    expect(rows[0].hash).toBe('6247EA31');
    expect(rows[0].version).toBe(31);
    expect(rows[0].runCount).toBeGreaterThan(0);

    // Windows does not keep the eight run-time slots strictly ordered — a real
    // file here had 11:03:52.589 followed by 11:03:53.184 — so assert only that
    // every slot holds a plausible date, not that they descend.
    const times = rows.map((r) => (r.runTime as Date).getTime());
    expect(times.every((t) => t > Date.parse('2000-01-01') && t < Date.now() + 864e5)).toBe(true);

    // The multi-chunk caveat is gone: the decompressor now decodes every chunk,
    // so the loaded-file list and volume block are reliable and no warning is
    // emitted for spanning multiple chunks.
    expect(warnings.some((w) => w.message.includes('must not be relied on'))).toBe(false);
  });
});