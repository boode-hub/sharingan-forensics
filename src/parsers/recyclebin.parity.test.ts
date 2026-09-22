/**
 * Recycle Bin parity against Eric Zimmerman's own test corpus.
 *
 * His RecycleBin.Test asserts only that names are non-empty, so the stronger
 * check here is the one his sample makes possible: a real INFO2 from a Windows
 * XP machine, where every field of every record has to be coherent. Reading
 * the header as 16 bytes instead of 20 shifts every record by four and still
 * produces output, so a test that only asks "did we get rows" cannot catch it.
 */
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { bufReader } from '../core/reader';
import { run } from '../core/registry';
import { recycleBin } from './recyclebin';

async function load(name: string) {
  const buf = new Uint8Array(
    readFileSync(new URL(`../../fixtures/recyclebin/${name}`, import.meta.url)),
  );
  return run(recycleBin, bufReader(buf, name));
}

describe('a real Windows XP INFO2', () => {
  it('reads the one record it holds, with every field coherent', async () => {
    const outcome = await load('INFO2-winxp');

    expect(outcome.rows.length).toBe(1);
    const r = outcome.rows[0];

    expect(r.fileType).toBe('INFO2');
    expect(r.version).toBe(5);
    expect(r.originalPath).toBe('Z:\\WINDOWS\\explorer.exe');
    expect(r.fileName).toBe('explorer.exe');
    expect(r.recordIndex).toBe(1);
    // Drive 25 is Z, which has to agree with the path the same record carries.
    expect(r.driveLetter).toBe('Z:');
    expect(r.fileSize).toBe(1005568);
    expect(r.offset).toBe(20);
    expect(outcome.warnings).toEqual([]);
  });

  it('places the first record at offset 20, where the header ends', async () => {
    // Guards the specific defect: at offset 16 the parser still returns a row,
    // but the drive letter, size and path all come from the wrong bytes.
    const outcome = await load('INFO2-winxp');
    expect(outcome.rows[0].offset).toBe(20);
    expect(outcome.rows[0].driveLetter).not.toBe('B:');
  });
});

describe('his $I samples across Windows versions', () => {
  for (const [name, expected] of Object.entries({
    'Win10-$IFATB0K': { version: 2 },
    'Win7-$I6SODDB': { version: 1 },
    'Win81-$I3VPA17': { version: 1 },
  })) {
    it(`parses ${name}`, async () => {
      const outcome = await load(name);
      expect(outcome.rows.length).toBe(1);
      const r = outcome.rows[0];
      expect(r.fileType).toBe('$I');
      expect(r.version).toBe(expected.version);
      // His own test asserts only that these are populated and plausible.
      expect(String(r.originalPath).length).toBeGreaterThan(0);
      expect(r.originalPath).toMatch(/^[A-Za-z]:\\/);
      expect(Number(r.fileSize)).toBeGreaterThan(0);
      expect(r.deletedOn).toBeInstanceOf(Date);
      expect(outcome.warnings).toEqual([]);
    });
  }
});
