/**
 * Whole-corpus regression run against real artifacts.
 *
 * Opt-in: set CORPUS to a directory holding the sample sets. The inputs are
 * real evidence and his test corpora, neither of which belongs in this
 * repository, so this never runs in CI. It exists to catch the failure the
 * fixtures cannot: a parser that is correct on four hand-made samples and
 * wrong on the thousandth real one.
 */
import { readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { bufReader } from '../core/reader';
import { detect, run } from '../core/registry';
import './index';

const root = process.env.CORPUS;
const suite = root ? describe : describe.skip;

function walk(dir: string, out: string[] = []): string[] {
  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    return out;
  }
  for (const e of entries) {
    const p = join(dir, e);
    let st;
    try {
      st = statSync(p);
    } catch {
      continue;
    }
    if (st.isDirectory()) walk(p, out);
    else if (st.size > 0) out.push(p);
  }
  return out;
}

suite('every artifact in the corpus parses', () => {
  it('produces rows and no unexpected warnings', async () => {
    const files = walk(root as string);
    const byParser = new Map<string, { files: number; rows: number; warned: number }>();
    const problems: string[] = [];
    let skipped = 0;

    for (const f of files) {
      const name = f.split(/[\\/]/).pop() as string;
      let buf: Uint8Array;
      try {
        buf = new Uint8Array(readFileSync(f));
      } catch {
        continue;
      }
      const reader = bufReader(buf, name);
      const parser = await detect(reader);
      if (!parser) {
        skipped++;
        continue;
      }

      let outcome;
      try {
        outcome = await run(parser, reader);
      } catch (e) {
        problems.push(`${name}: threw ${(e as Error).message}`);
        continue;
      }

      const stat = byParser.get(parser.id) ?? { files: 0, rows: 0, warned: 0 };
      stat.files++;
      stat.rows += outcome.rows.length;
      if (outcome.warnings.length > 0) stat.warned++;
      byParser.set(parser.id, stat);

      if (outcome.rows.length === 0 && outcome.warnings.length === 0) {
        problems.push(`${name}: ${parser.id} produced no rows and said nothing`);
      }
      for (const row of outcome.rows) {
        if (row.offset !== undefined && Number(row.offset) < 0) {
          problems.push(`${name}: negative offset ${row.offset}`);
          break;
        }
      }
    }

    const summary = [...byParser.entries()]
      .map(([id, s]) => `${id}: ${s.files} files, ${s.rows.toLocaleString()} rows, ${s.warned} warned`)
      .join('\n');
    if (process.env.CORPUS_OUT) {
      writeFileSync(
        process.env.CORPUS_OUT,
        `${summary}\nunrecognised: ${skipped}\n\n${problems.join('\n')}`,
      );
    }

    expect(problems.slice(0, 10).join('\n')).toBe('');
    expect(byParser.size).toBeGreaterThan(0);
  }, 3_600_000);
});
