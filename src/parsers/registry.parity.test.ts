/**
 * Registry parity against Eric Zimmerman's own test assertions.
 *
 * The key paths and values below are copied from Registry.Test
 * (TestVKCellRecord.cs and TestRegistryHive.cs in
 * https://github.com/EricZimmerman/Registry), run against the SAM hive from
 * that same MIT-licensed corpus, which this repository already carries.
 */
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { bufReader } from '../core/reader';
import { run } from '../core/registry';
import { registry } from './registry';

const ROOT = 'CsiTool-CreateHive-{00000000-0000-0000-0000-000000000000}';

async function sam() {
  const buf = new Uint8Array(readFileSync(new URL('../../fixtures/registry/SAM', import.meta.url)));
  return run(registry, bufReader(buf, 'SAM'));
}

describe('the SAM hive from his test corpus', () => {
  it('identifies the hive from the name it carries, not the file name', async () => {
    const outcome = await sam();
    expect(outcome.rows[0].hiveType).toBe('Sam');
    expect(outcome.rows[0].sourceFile).toBe('SAM');
  });

  it('builds key paths from the root key name, as his KeyPath does', async () => {
    const outcome = await sam();
    // His ShouldFindAKeyWithoutRootKeyName test proves SAM\Domains exists; his
    // KeyPath property includes the root key name, so ours does too.
    const domains = outcome.rows.filter((r) => r.keyPath === `${ROOT}\\SAM\\Domains`);
    expect(domains.length).toBeGreaterThan(0);
  });

  it('reads the REG_BINARY value F where his TestVkRecordRegBinary finds it', async () => {
    const outcome = await sam();
    const row = outcome.rows.find(
      (r) => r.keyPath === `${ROOT}\\SAM\\Domains\\Account` && r.valueName === 'F',
    );
    expect(row).toBeDefined();
    expect(row?.valueType).toBe('REG_BINARY');
    expect(row?.isDeleted).toBe(false);
  });

  it('reads the resident REG_DWORD default value his TestVkRecordRegDWord checks', async () => {
    const outcome = await sam();
    const row = outcome.rows.find(
      (r) => r.keyPath === `${ROOT}\\SAM\\LastSkuUpgrade` && r.valueName === '(default)',
    );
    expect(row).toBeDefined();
    expect(row?.valueType).toBe('REG_DWORD');
    // He asserts ValueData equals "7".
    expect(row?.valueData).toBe('7');
  });

  it('parses without warnings, as his SoftParsingErrors and HardParsingErrors of 0 require', async () => {
    const outcome = await sam();
    const real = outcome.warnings.filter((w) => !/recovered \d+ deleted/.test(String(w.message)));
    expect(real).toEqual([]);
  });
});

describe('deleted key and value recovery', () => {
  it('marks recovered rows rather than mixing them with live ones', async () => {
    const outcome = await sam();
    const deleted = outcome.rows.filter((r) => r.isDeleted);
    const live = outcome.rows.filter((r) => !r.isDeleted);

    expect(live.length).toBeGreaterThan(0);
    // This hive has one unreferenced key cell; the point of the assertion is
    // that recovery runs and is reported separately, not the exact count.
    expect(deleted.length).toBeGreaterThan(0);
    expect(deleted.every((r) => r.isDeleted === true)).toBe(true);

    // A recovered row must still be attributable to somewhere in the file.
    for (const r of deleted) {
      expect(Number(r.offset)).toBeGreaterThan(4096);
    }
  });

  it('says in a warning that recovered rows are present', async () => {
    const outcome = await sam();
    expect(outcome.warnings.some((w) => /recovered \d+ deleted key/.test(String(w.message)))).toBe(
      true,
    );
  });
});
