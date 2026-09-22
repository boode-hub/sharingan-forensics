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

const expected = JSON.parse(readFileSync(join(FIXTURE_DIR, 'expected.json'), 'utf-8'));

const FIXTURES = ['notepad.lnk', 'local.directory.seven.lnk', 'PhotosApp.lnk'];

describe('lnk parser', () => {
  it('carries the properties notepad.lnk was created with', async () => {
    const outcome = await run(lnk, bufReader(loadFixture('notepad.lnk'), 'notepad.lnk'));
    const target = outcome.rows.find((r) => r.entryType === 'Target') as Record<string, unknown>;
    expect(target).toBeDefined();

    for (const [key, want] of Object.entries(expected['notepad.lnk'] as Record<string, unknown>)) {
      const got = target[key];
      expect(got instanceof Date ? got.toISOString() : got, `field ${key}`).toBe(want);
    }
    expect(outcome.warnings).toEqual([]);
  });

  it('emits one row per entry, not one per file', async () => {
    const outcome = await run(lnk, bufReader(loadFixture('notepad.lnk'), 'notepad.lnk'));
    expect(outcome.rows.some((r) => r.entryType === 'Target')).toBe(true);
    expect(outcome.rows.length).toBeGreaterThan(1);
  });

  describe('truncation', () => {
    for (const name of FIXTURES) {
      it(`does not throw or invent rows on a truncated ${name}`, async () => {
        const buf = loadFixture(name);
        const full = await run(lnk, bufReader(buf, name));
        for (const len of [20, 76, 200, Math.floor(buf.length / 2)]) {
          if (len >= buf.length) continue;
          const outcome = await run(lnk, bufReader(buf.subarray(0, len), name));
          expect(outcome.rows.length).toBeLessThanOrEqual(full.rows.length);
        }
      });
    }
  });

  describe('sniff', () => {
    const buf = loadFixture('notepad.lnk');

    it('returns true for notepad.lnk', () => {
      expect(lnk.sniff(buf, 'notepad.lnk')).toBe(true);
    });

    it('returns true for a carved shortcut with no .lnk extension', () => {
      expect(lnk.sniff(buf, 'carved-0001.bin')).toBe(true);
    });

    it('returns false for random bytes with the wrong CLSID', () => {
      const garbage = new Uint8Array(20);
      garbage.set([0x4c, 0x00, 0x00, 0x00], 0);
      expect(lnk.sniff(garbage, 'random.bin')).toBe(false);
    });
  });

  describe('garbage test', () => {
    it('does not throw on random bytes behind a valid header', async () => {
      const buf = new Uint8Array(4096);
      crypto.getRandomValues(buf);
      buf.set([0x4c, 0x00, 0x00, 0x00], 0);
      // The link CLSID as it sits on disk.
      buf.set(
        [0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46],
        4,
      );
      const outcome = await run(lnk, bufReader(buf, 'garbage.lnk'));
      expect(outcome.rows).toBeDefined();
    });
  });
});
