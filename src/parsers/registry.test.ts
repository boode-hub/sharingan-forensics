import { describe, expect, it } from 'vitest';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { bufReader } from '../core/reader';
import { run } from '../core/registry';
import { registry } from './registry';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURE_DIR = join(__dirname, '../../fixtures/registry');

function loadFixture(name: string): Uint8Array {
  return new Uint8Array(readFileSync(join(FIXTURE_DIR, name)));
}

const ROOT_NAME = 'CsiTool-CreateHive-{00000000-0000-0000-0000-000000000000}';

/** Distinct immediate subkey paths under `parent`. */
function immediateSubkeyPaths(rows: { keyPath: string }[], parent: string): Set<string> {
  const prefix = parent === '' ? '' : parent + '\\';
  const out = new Set<string>();
  for (const r of rows) {
    if (!r.keyPath.startsWith(prefix)) continue;
    const rest = r.keyPath.slice(prefix.length);
    if (rest === '' || rest.includes('\\')) continue;
    out.add(r.keyPath);
  }
  return out;
}

function valuesAt(rows: { keyPath: string; valueName: string | null }[], keyPath: string): number {
  return rows.filter((r) => r.keyPath === keyPath && r.valueName !== null).length;
}

describe('registry parser', () => {
  it('rejects NotAHive in sniff()', () => {
    const buf = loadFixture('NotAHive');
    expect(registry.sniff(buf.subarray(0, 512), 'NotAHive')).toBe(false);
  });

  it('accepts SAM in sniff()', () => {
    const buf = loadFixture('SAM');
    expect(registry.sniff(buf.subarray(0, 512), 'SAM')).toBe(true);
  });

  it('parses NotAHive to zero rows plus a warning instead of throwing', async () => {
    const buf = loadFixture('NotAHive');
    const outcome = await run(registry, bufReader(buf, 'NotAHive'));
    expect(outcome.rows.length).toBe(0);
    expect(outcome.warnings.length).toBeGreaterThan(0);
  });

  describe('golden — SAM oracle', () => {
    const buf = loadFixture('SAM');
    let outcome: Awaited<ReturnType<typeof run>>;

    it('parses without throwing and yields rows', async () => {
      outcome = await run(registry, bufReader(buf, 'SAM'));
      expect(outcome.rows.length).toBeGreaterThan(0);
    });

    it('emits the root key with its name and last-written time', async () => {
      const rootRows = outcome.rows.filter((r) => (r as { keyPath: string }).keyPath === ROOT_NAME);
      expect(rootRows.length).toBeGreaterThan(0);
      const rootRow = rootRows[0] as { lastWritten: Date };
      expect(rootRow.lastWritten.toISOString()).toBe('2014-07-03T18:05:37.590Z');
    });

    it('walks the first-child chain SAM\\Domains\\Account', async () => {
      const paths = new Set(outcome.rows.map((r) => (r as { keyPath: string }).keyPath));
      expect(paths.has(`${ROOT_NAME}\\SAM`)).toBe(true);
      expect(paths.has(`${ROOT_NAME}\\SAM\\Domains`)).toBe(true);
      expect(paths.has(`${ROOT_NAME}\\SAM\\Domains\\Account`)).toBe(true);
    });

    it('reports the subkey and value counts at each level', async () => {
      const typed = outcome.rows as unknown as {
        keyPath: string;
        valueName: string | null;
      }[];

      // Root: 1 stable subkey, 0 values.
      expect(immediateSubkeyPaths(typed, ROOT_NAME).size).toBe(1);
      expect(valuesAt(typed, ROOT_NAME)).toBe(0);

      const sam = `${ROOT_NAME}\\SAM`;
      expect(immediateSubkeyPaths(typed, sam).size).toBe(3);
      expect(valuesAt(typed, sam)).toBe(2);

      const domains = `${sam}\\Domains`;
      expect(immediateSubkeyPaths(typed, domains).size).toBe(2);
      expect(valuesAt(typed, domains)).toBe(1);

      const account = `${domains}\\Account`;
      expect(immediateSubkeyPaths(typed, account).size).toBe(3);
      expect(valuesAt(typed, account)).toBe(2);
    });
  });

  describe('truncation tests', () => {
    it('does not throw or hang on truncated SAM', async () => {
      const buf = loadFixture('SAM');
      for (const n of [100, 4096, 40000]) {
        if (n >= buf.length) continue;
        const outcome = await run(registry, bufReader(buf.subarray(0, n), 'SAM'));
        expect(outcome.rows.length).toBeGreaterThanOrEqual(0);
      }
    });
  });

  describe('garbage test', () => {
    it('does not throw or hang on random bytes with regf magic', async () => {
      const buf = new Uint8Array(200000);
      for (let i = 0; i < buf.length; i += 65536) {
        crypto.getRandomValues(buf.subarray(i, Math.min(i + 65536, buf.length)));
      }
      buf[0] = 0x72;
      buf[1] = 0x65;
      buf[2] = 0x67;
      buf[3] = 0x66;
      const outcome = await run(registry, bufReader(buf, 'garbage'));
      expect(outcome.rows.length).toBeGreaterThanOrEqual(0);
    });
  });
});
