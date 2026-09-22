/**
 * The SigmaHQ repository's own regression suite, run through this tool.
 *
 * SigmaHQ ships, beside its rules, a real .evtx file for each of hundreds of
 * rules and the number of events in it that the rule must match. That makes it
 * an oracle for two things at once: the EVTX parser, which has to recover the
 * events and their fields exactly, and the Sigma engine, which has to evaluate
 * the rule as the specification says. Neither is being compared with itself.
 *
 * Opt-in, because it needs a clone of https://github.com/SigmaHQ/sigma:
 *   SIGMA_REPO=path/to/sigma npx vitest run src/ui/sigma.regression.test.ts
 */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { parse } from 'yaml';
import { bufReader } from '../core/reader';
import { run } from '../core/registry';
import { evtx } from '../parsers/evtx';
import { compileSigma } from './sigma';

const root = process.env.SIGMA_REPO;
const suite = root ? describe : describe.skip;

function walk(dir: string, ext: string, out: string[] = []): string[] {
  for (const e of readdirSync(dir)) {
    const p = join(dir, e);
    if (statSync(p).isDirectory()) walk(p, ext, out);
    else if (e.endsWith(ext)) out.push(p);
  }
  return out;
}

suite('SigmaHQ regression data', () => {
  it('matches every case exactly as SigmaHQ expects', async () => {
    const rules = new Map<string, string>();
    for (const dir of readdirSync(root as string).filter((d) => d.startsWith('rules'))) {
      for (const f of walk(join(root as string, dir), '.yml')) {
        const text = readFileSync(f, 'utf8');
        const id = /^id:\s*([0-9a-f-]{36})/m.exec(text)?.[1];
        if (id) rules.set(id, text);
      }
    }

    const failures: string[] = [];
    let cases = 0;
    for (const info of walk(join(root as string, 'regression_data'), 'info.yml')) {
      const meta = parse(readFileSync(info, 'utf8'));
      const ruleId = meta.rule_metadata?.[0]?.id;
      const title = meta.rule_metadata?.[0]?.title;
      for (const t of meta.regression_tests_info ?? []) {
        if (t.type !== 'evtx') continue;
        cases++;
        const text = rules.get(ruleId);
        if (!text) {
          failures.push(`${title}: rule ${ruleId} not found`);
          continue;
        }
        const buf = new Uint8Array(readFileSync(join(root as string, t.path)));
        const { rows } = await run(evtx, bufReader(buf, 'case.evtx'));
        const rule = await compileSigma(text, evtx.columns);
        const got = rows.filter(rule.test).length;
        // As SigmaHQ's own runner judges it: no count given means at least one.
        const ok = t.match_count === undefined ? got > 0 : got === t.match_count;
        if (!ok) failures.push(`${title}: expected ${t.match_count ?? '>0'}, got ${got}`);
      }
    }

    expect(cases).toBeGreaterThan(0);
    expect(failures).toEqual([]);
  }, 1_800_000);
});
