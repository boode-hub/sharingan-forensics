/**
 * Replaying a registry hive's transaction logs.
 *
 * A hive copied from a running machine is almost always behind its logs.
 * Reading it without them gives an answer that was true when the hive was last
 * flushed, and nothing about the output says so, which is the dangerous part:
 * it does not fail, it just reports history.
 */
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { bufReader } from '../core/reader';
import { run } from '../core/registry';
import { registry } from './registry';
import { marvin, parseLog } from './registry/translog';

function fixture(name: string): Uint8Array {
  return new Uint8Array(readFileSync(new URL(`../../fixtures/registry-log/${name}`, import.meta.url)));
}

const HIVE = 'SYNTHETIC.DAT';
const LOG = 'SYNTHETIC.DAT.LOG1';

describe('a dirty hive read on its own', () => {
  it('gives the value as it was last flushed, and says it is behind', async () => {
    const outcome = await run(registry, bufReader(fixture(HIVE), HIVE));

    const row = outcome.rows.find((r) => r.valueName === 'Status');
    expect(row?.valueData).toBe('OLD');
    expect(
      outcome.warnings.some((w) => /hive is dirty/.test(String(w.message))),
    ).toBe(true);
  });
});

describe('the same hive read with its log', () => {
  it('gives the value the machine would have seen', async () => {
    const outcome = await run(
      registry,
      bufReader(fixture(HIVE), HIVE),
      undefined,
      [bufReader(fixture(LOG), LOG)],
    );

    const row = outcome.rows.find((r) => r.valueName === 'Status');
    expect(row?.valueData).toBe('NEW');
  });

  it('says what it replayed, so the rows are not silently different', async () => {
    const outcome = await run(
      registry,
      bufReader(fixture(HIVE), HIVE),
      undefined,
      [bufReader(fixture(LOG), LOG)],
    );

    const said = outcome.warnings.map((w) => String(w.message)).join(' ');
    expect(said).toMatch(/replayed 1 log entry/);
    expect(said).toContain(LOG);
    // Having replayed, it must not also claim the hive is dirty.
    expect(said).not.toMatch(/hive is dirty/);
  });

  it('ignores a sibling that is not a transaction log', async () => {
    const notALog = new Uint8Array(4096);
    const outcome = await run(
      registry,
      bufReader(fixture(HIVE), HIVE),
      undefined,
      [bufReader(notALog, 'random.bin')],
    );

    expect(outcome.rows.find((r) => r.valueName === 'Status')?.valueData).toBe('OLD');
    expect(outcome.warnings.some((w) => /not a registry transaction log/.test(String(w.message)))).toBe(
      true,
    );
  });
});

describe('log entry verification', () => {
  it('reads the entry and both its hashes check out', () => {
    const entries = parseLog(fixture(LOG));
    expect(entries.length).toBe(1);
    expect(entries[0].valid).toBe(true);
    expect(entries[0].sequenceNumber).toBe(3);
    expect(entries[0].pages.length).toBe(1);
  });

  it('rejects an entry whose bytes were altered after it was written', async () => {
    // An entry that was not written completely would corrupt the hive if it
    // were applied, so it has to be skipped rather than trusted.
    const tampered = fixture(LOG);
    tampered[0x200 + 60] ^= 0xff;

    expect(parseLog(tampered)[0].valid).toBe(false);

    const outcome = await run(
      registry,
      bufReader(fixture(HIVE), HIVE),
      undefined,
      [bufReader(tampered, LOG)],
    );
    expect(outcome.rows.find((r) => r.valueName === 'Status')?.valueData).toBe('OLD');
    expect(
      outcome.warnings.some((w) => /failed hash verification/.test(String(w.message))),
    ).toBe(true);
  });

  it('hashes the same bytes the same way twice, and different bytes differently', () => {
    const a = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9]);
    const b = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 10]);
    expect(marvin(a)).toBe(marvin(a));
    expect(marvin(a)).not.toBe(marvin(b));
    // Trailing zeroes must change the hash; a length-blind implementation
    // would give the same answer for both.
    expect(marvin(new Uint8Array([1, 2, 3]))).not.toBe(marvin(new Uint8Array([1, 2, 3, 0])));
  });
});
