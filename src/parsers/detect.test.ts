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
    // One direction only. A fixture directory with no parser yet is normal —
    // fixtures are written first, on purpose, so the oracle exists before the
    // parser that has to satisfy it.
    const missing = parsers.map((p) => p.id).filter((id) => !dirs.includes(id));
    expect(missing).toEqual([]);
  });

  for (const p of parsers.filter((x) => x.manual)) {
    it(`${p.id}: is never chosen automatically`, async () => {
      // A manual parser reads a structure inside another artifact, so the file
      // it reads belongs to a different parser. Claiming it would take that
      // artifact away from the parser that owns it.
      const samples = readdirSync(join(FIXTURES, p.id)).filter(
        (f) => !f.endsWith('.json') && !f.endsWith('.mjs') && !f.endsWith('.md'),
      );
      expect(samples.length).toBeGreaterThan(0);
      for (const s of samples) {
        const buf = new Uint8Array(readFileSync(join(FIXTURES, p.id, s)));
        const chosen = await detect(bufReader(buf, s));
        expect(chosen?.id, `${p.id}/${s}`).not.toBe(p.id);
      }
    });
  }

  for (const dir of dirs.filter((d) =>
    parsers.some((p) => p.id === d && !p.manual),
  )) {
    // A fixture directory may carry a reject.json naming samples that detect()
    // must deliberately NOT claim, such as a PE executable filed with the
    // registry hives to prove the signature check works.
    let rejected: string[] = [];
    try {
      rejected = JSON.parse(readFileSync(join(FIXTURES, dir, 'reject.json'), 'utf8')).reject ?? [];
    } catch {
      // no reject.json; every sample is expected to be detected
    }
    const samples = readdirSync(join(FIXTURES, dir)).filter(
      (f) =>
        !f.endsWith('.json') && !f.endsWith('.mjs') && !f.endsWith('.md') && !rejected.includes(f),
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
