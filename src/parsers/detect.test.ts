import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { bufReader } from '../core/reader';
import { detect, parsers } from '../core/registry';
import '.';

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), '../../fixtures');

/**
 * Guards the gap between "the parser works" and "the app can find it".
 * Every parser test drives its parser directly, so a parser missing from
 * src/parsers/index.ts passes its whole suite while the shipped app reports
 * the file as unrecognised. That happened once; this stops it happening again.
 */
describe('registry detection', () => {
  const dirs = readdirSync(FIXTURES, { withFileTypes: true })
    .filter((d) => d.isDirectory())
    .map((d) => d.name);

  it('has a fixture directory for every registered parser', () => {
    expect(dirs.sort()).toEqual(parsers.map((p) => p.id).sort());
  });

  for (const dir of dirs) {
    const samples = readdirSync(join(FIXTURES, dir)).filter(
      (f) => !f.endsWith('.json') && !f.endsWith('.mjs') && !f.endsWith('.md'),
    );

    it(`${dir}: every sample is detected as "${dir}"`, async () => {
      expect(samples.length).toBeGreaterThan(0);
      for (const s of samples) {
        const buf = new Uint8Array(readFileSync(join(FIXTURES, dir, s)));
        const parser = await detect(bufReader(buf, s));
        expect(parser?.id, `${dir}/${s} was not detected`).toBe(dir);
      }
    });
  }

  it('returns null for a file nothing claims, rather than guessing', async () => {
    const junk = new Uint8Array(600).fill(0x41);
    expect(await detect(bufReader(junk, 'notes.txt'))).toBeNull();
  });
});
