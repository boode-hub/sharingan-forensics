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

    it('emits resident values (bit 31 set in data length) with decoded inline data', () => {
      const typed = outcome.rows as unknown as {
        keyPath: string;
        valueName: string | null;
        valueType: string | null;
        valueData: string | null;
      }[];
      const sdu = typed.find(
        (r) => r.keyPath === `${ROOT_NAME}\\SAM` && r.valueName === 'ServerDomainUpdates',
      );
      expect(sdu).toBeDefined();
      expect(sdu?.valueType).toBe('REG_BINARY');
      expect(sdu?.valueData).toBe('FE 0F');

      const fpr = typed.filter((r) => r.valueName === 'ForcePasswordReset');
      expect(fpr.length).toBeGreaterThan(0);
      for (const r of fpr) {
        expect(r.valueType).toBe('REG_BINARY');
        expect(r.valueData).toBe('00 00 00 00');
      }
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

  describe('resident and big-data synthetic hive tests', () => {
    it('correctly handles resident DWORD, SZ, BINARY and big-data values', async () => {
      const hbinSize = 61440;
      const buf = new Uint8Array(4096 + hbinSize);
      const view = new DataView(buf.buffer);

      // Hive header at offset 0
      buf[0] = 0x72; buf[1] = 0x65; buf[2] = 0x67; buf[3] = 0x66; // 'regf'
      view.setUint32(4, 1, true);
      view.setUint32(8, 1, true);
      view.setUint32(20, 1, true); // major = 1
      view.setUint32(24, 5, true); // minor = 5
      view.setUint32(36, 0x20, true); // rootRel = 0x20
      view.setUint32(40, hbinSize, true); // hbinLength

      // HBIN at offset 4096
      buf[4096] = 0x68; buf[4097] = 0x62; buf[4098] = 0x69; buf[4099] = 0x6e; // 'hbin'
      view.setUint32(4096 + 4, 0, true);
      view.setUint32(4096 + 8, hbinSize, true);

      let curRel = 0x20;
      function allocCell(size: number): number {
        const rel = curRel;
        const abs = 4096 + rel;
        view.setInt32(abs, -size, true); // negative size = allocated
        curRel += size;
        return rel;
      }

      // 1. Root NK cell at rel 0x20, size 0x60 (96 bytes)
      const rootRel = allocCell(0x60);
      const rootAbs = 4096 + rootRel;
      buf[rootAbs + 4] = 0x6e; buf[rootAbs + 5] = 0x6b; // 'nk'
      view.setUint16(rootAbs + 6, 0x0024, true); // flags: ROOT (0x04) | COMPRESSED_NAME (0x20)
      view.setUint16(rootAbs + 0x4c, 4, true); // nameLen
      buf[rootAbs + 0x50] = 0x52; buf[rootAbs + 0x51] = 0x6f; buf[rootAbs + 0x52] = 0x6f; buf[rootAbs + 0x53] = 0x74; // 'Root'

      // 2. VK cell: Resident DWORD
      const vkDwordRel = allocCell(0x28);
      const vkDwordAbs = 4096 + vkDwordRel;
      buf[vkDwordAbs + 4] = 0x76; buf[vkDwordAbs + 5] = 0x6b; // 'vk'
      view.setUint16(vkDwordAbs + 6, 8, true); // name length
      view.setUint32(vkDwordAbs + 8, 0x80000004, true); // resident 4 bytes
      view.setUint32(vkDwordAbs + 12, 123456, true); // inline data (DWORD)
      view.setUint32(vkDwordAbs + 16, 4, true); // REG_DWORD
      view.setUint16(vkDwordAbs + 20, 1, true); // name present ASCII
      new TextEncoder().encodeInto('ResDword', buf.subarray(vkDwordAbs + 24));

      // 3. VK cell: Resident String
      const vkSzRel = allocCell(0x28);
      const vkSzAbs = 4096 + vkSzRel;
      buf[vkSzAbs + 4] = 0x76; buf[vkSzAbs + 5] = 0x6b; // 'vk'
      view.setUint16(vkSzAbs + 6, 5, true); // name length
      view.setUint32(vkSzAbs + 8, 0x80000004, true); // resident 4 bytes
      buf[vkSzAbs + 12] = 0x41; buf[vkSzAbs + 13] = 0x00; buf[vkSzAbs + 14] = 0x42; buf[vkSzAbs + 15] = 0x00;
      view.setUint32(vkSzAbs + 16, 1, true); // REG_SZ
      view.setUint16(vkSzAbs + 20, 1, true); // name present ASCII
      new TextEncoder().encodeInto('ResSz', buf.subarray(vkSzAbs + 24));

      // 4. VK cell: Big Data (db) value
      // 20,000 bytes split across two segments: 16344 + 3656
      const seg1Size = 4 + 16344;
      const seg1Rel = allocCell(seg1Size);
      const seg1Abs = 4096 + seg1Rel;
      buf.fill(0xaa, seg1Abs + 4, seg1Abs + 4 + 16344);

      const seg2Size = 4 + 3656;
      const seg2Rel = allocCell(seg2Size);
      const seg2Abs = 4096 + seg2Rel;
      buf.fill(0xbb, seg2Abs + 4, seg2Abs + 4 + 3656);

      // Offsets list cell: 4-byte header + 2 * 4-byte relative offsets
      const offsetsListRel = allocCell(16);
      const offsetsListAbs = 4096 + offsetsListRel;
      view.setUint32(offsetsListAbs + 4, seg1Rel, true);
      view.setUint32(offsetsListAbs + 8, seg2Rel, true);

      // DB cell: size = 16
      const dbRel = allocCell(16);
      const dbAbs = 4096 + dbRel;
      buf[dbAbs + 4] = 0x64; buf[dbAbs + 5] = 0x62; // 'db'
      view.setUint16(dbAbs + 6, 2, true); // 2 entries
      view.setUint32(dbAbs + 8, offsetsListRel, true); // offsetToOffsets

      // VK for big data
      const vkBigRel = allocCell(0x28);
      const vkBigAbs = 4096 + vkBigRel;
      buf[vkBigAbs + 4] = 0x76; buf[vkBigAbs + 5] = 0x6b; // 'vk'
      view.setUint16(vkBigAbs + 6, 6, true);
      view.setUint32(vkBigAbs + 8, 20000, true); // length = 20000 (> 16344)
      view.setUint32(vkBigAbs + 12, dbRel, true); // points to db cell
      view.setUint32(vkBigAbs + 16, 3, true); // REG_BINARY
      view.setUint16(vkBigAbs + 20, 1, true);
      new TextEncoder().encodeInto('BigVal', buf.subarray(vkBigAbs + 24));

      // Value list cell for root: holds vkDwordRel, vkSzRel, vkBigRel
      const valListRel = allocCell(16);
      const valListAbs = 4096 + valListRel;
      view.setUint32(valListAbs + 4, vkDwordRel, true);
      view.setUint32(valListAbs + 8, vkSzRel, true);
      view.setUint32(valListAbs + 12, vkBigRel, true);

      // Set value list pointer on root NK
      view.setUint32(rootAbs + 0x28, 3, true); // valueListCount = 3
      view.setUint32(rootAbs + 0x2c, valListRel, true); // valueListRel

      const outcome = await run(registry, bufReader(buf, 'synthetic'));
      expect(outcome.rows.length).toBe(3);

      const dwordRow = outcome.rows.find((r) => (r as { valueName: string }).valueName === 'ResDword') as {
        valueType: string;
        valueData: string;
      };
      expect(dwordRow).toBeDefined();
      expect(dwordRow.valueType).toBe('REG_DWORD');
      expect(dwordRow.valueData).toBe('123456');

      const szRow = outcome.rows.find((r) => (r as { valueName: string }).valueName === 'ResSz') as {
        valueType: string;
        valueData: string;
      };
      expect(szRow).toBeDefined();
      expect(szRow.valueType).toBe('REG_SZ');
      expect(szRow.valueData).toBe('AB');

      const bigRow = outcome.rows.find((r) => (r as { valueName: string }).valueName === 'BigVal') as {
        valueType: string;
        valueData: string;
      };
      expect(bigRow).toBeDefined();
      expect(bigRow.valueType).toBe('REG_BINARY');
      expect(bigRow.valueData.startsWith('AA AA AA')).toBe(true);
      expect(bigRow.valueData.endsWith('BB BB BB')).toBe(true);
      expect(bigRow.valueData.split(' ').length).toBe(20000);
    });
  });
});
