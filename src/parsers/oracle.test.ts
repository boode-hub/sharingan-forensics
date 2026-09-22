/**
 * Compares our rendered XML against Windows' own, record by record.
 *
 * wevtutil renders the same records through the OS's BinXML implementation, so
 * it is the only ground truth available that is not another reimplementation.
 * This test is opt-in: it needs exported logs and their wevtutil dumps, which
 * are real evidence and never committed. Set ORACLE_DIR to run it.
 */
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { bufReader } from '../core/reader';
import { run } from '../core/registry';
import { evtx } from './evtx';

const dir = process.env.ORACLE_DIR;

/**
 * Differences that are presentation, not content: attribute quoting, the
 * xmlns declaration the reader adds, and self-closing spacing. Everything
 * else must match character for character.
 */
function normalize(xml: string): string {
  return xml
    .replace(/\r?\n/g, '')
    .replace(/'/g, '"')
    .replace(/\s*\/>/g, '/>')
    .replace(/\s+xmlns="[^"]*"/g, '')
    .trim();
}

const suite = dir ? describe : describe.skip;

suite('rendered XML matches what Windows renders', () => {
  const files = dir
    ? readdirSync(dir).filter((f) => f.endsWith('.groundtruth.xml'))
    : [];

  for (const gt of files) {
    const base = gt.replace('.groundtruth.xml', '');

    it(`${base}`, async () => {
      const truth = new Map<string, string>();
      for (const m of readFileSync(join(dir as string, gt), 'utf8').matchAll(
        /<Event[\s>][\s\S]*?<\/Event>/g,
      )) {
        const id = m[0].match(/<EventRecordID>(\d+)<\/EventRecordID>/);
        if (id) truth.set(id[1], normalize(m[0]));
      }
      if (truth.size === 0) return; // a channel with no events exports nothing

      const buf = new Uint8Array(readFileSync(join(dir as string, 'logs', `${base}.evtx`)));
      const outcome = await run(evtx, bufReader(buf, `${base}.evtx`));

      let compared = 0;
      const mismatches: string[] = [];
      for (const row of outcome.rows) {
        const want = truth.get(String(row.eventRecordId));
        if (want === undefined) continue;
        compared++;
        const got = normalize(String(row.xml ?? ''));
        if (got !== want && mismatches.length < 3) {
          mismatches.push(`record ${row.eventRecordId}\n  want: ${want}\n  got:  ${got}`);
        }
      }

      expect(compared).toBeGreaterThan(0);
      expect(mismatches.join('\n\n')).toBe('');
    }, 600_000);
  }
});
