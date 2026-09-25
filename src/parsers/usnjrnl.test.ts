import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { bufReader } from '../core/reader';
import { detect, run } from '../core/registry';
import type { Row } from '../core/types';
import { usnJrnl } from './usnjrnl';
import './index';

// fixtures/usnjrnl/$J is built by fixtures/usnjrnl/make.mjs; its parent
// references point into fixtures/mft/$MFT. Expectations are what MFTECmd
// writes for those records, from his Usn library and ProcessJ.
const buf = new Uint8Array(readFileSync('fixtures/usnjrnl/$J'));
const mftBuf = new Uint8Array(readFileSync('fixtures/mft/$MFT'));
const LEAD = 16 * 0x1000;
const load = (withMft: boolean) =>
  run(usnJrnl, bufReader(buf, '$J'), undefined, withMft ? [bufReader(mftBuf, '$MFT')] : undefined);
const named = (rows: Row[], name: string) => {
  const r = rows.find((x) => x.Name === name);
  if (!r) throw new Error(`no row for ${name}`);
  return r;
};

describe('$J (MFTECmd)', () => {
  it('is recognised by name when it starts sparse, and by its first record when not', async () => {
    expect((await detect(bufReader(buf, '$J')))?.id).toBe('usnjrnl');
    expect((await detect(bufReader(buf, '$UsnJrnl%3A$J')))?.id).toBe('usnjrnl');
    expect((await detect(bufReader(buf, 'zeros.bin')))?.id).not.toBe('usnjrnl');
    expect((await detect(bufReader(buf.subarray(LEAD), 'journal.bin')))?.id).toBe('usnjrnl');
  });

  it('writes his JEntryOut columns in declaration order', () => {
    expect(usnJrnl.columns.map((c) => c.key).join(',')).toBe(
      'Name,Extension,EntryNumber,SequenceNumber,ParentEntryNumber,ParentSequenceNumber,ParentPath,UpdateSequenceNumber,UpdateTimestamp,UpdateReasons,FileAttributes,OffsetToData,SourceFile',
    );
  });

  it('finds where the sparse run ends and walks every page he would', async () => {
    const { rows } = await load(false);
    const names = rows.map((r) => r.Name as string);
    // Page A: six records then 41 filler; page B (version 3 first) and page C
    // (junk) are skipped whole; page D: one record then 45 filler; then the cut-off one.
    expect(names.slice(0, 6)).toEqual(['report.docx', 'gone.txt', 'NewFolder', 'far.txt', 'odd.bin', 'zero']);
    expect(names.filter((n) => n.startsWith('fill-'))).toHaveLength(41 + 45);
    expect(names).not.toContain('v3.txt');
    expect(names.includes('fill-0041.tmp')).toBe(false); // page B's own filler
    expect(names.slice(-2)).toEqual(['fill-0130.tmp', 'ab']);
    expect(rows[0].OffsetToData).toBe(LEAD);
    expect(rows[0].UpdateSequenceNumber).toBe(LEAD);
  });

  it('reads each field as his UsnEntry does', async () => {
    const { rows } = await load(false);
    const r = named(rows, 'report.docx');
    expect(r).toMatchObject({
      Extension: '.docx',
      EntryNumber: 7,
      SequenceNumber: 2,
      ParentEntryNumber: 6,
      ParentSequenceNumber: 1,
      ParentPath: '',
      UpdateReasons: 'FileCreate|Close',
      FileAttributes: 'Archive',
      SourceFile: '$J',
    });
    expect((r.UpdateTimestamp as Date).toISOString()).toBe('2024-03-01T10:00:00.123Z');
    expect(named(rows, 'gone.txt')).toMatchObject({ UpdateReasons: 'FileDelete|Close', FileAttributes: 'Archive|NotContentIndexed' });
    expect(named(rows, 'NewFolder')).toMatchObject({ Extension: '', UpdateReasons: 'FileCreate', FileAttributes: 'Directory' });
    expect(named(rows, 'far.txt')).toMatchObject({ ParentEntryNumber: 16777221, UpdateReasons: 'RenameOldName|RenameNewName' });
    // .NET prints a flags value with an unnamed bit as a number, and zero as "0" when no member is zero.
    expect(named(rows, 'odd.bin')).toMatchObject({ UpdateReasons: String(0x81000000), FileAttributes: String(0x80020) });
    expect(named(rows, 'zero')).toMatchObject({ UpdateReasons: '0', FileAttributes: '0' });
  });

  it('takes parent paths from a $MFT opened with it', async () => {
    const { rows } = await load(true);
    expect(named(rows, 'report.docx').ParentPath).toBe('.\\LongFolderName');
    expect(named(rows, 'gone.txt').ParentPath).toBe('.\\LongFolderName\\OldDir');
    expect(named(rows, 'NewFolder').ParentPath).toBe('.');
    expect(named(rows, 'far.txt').ParentPath).toBe('.\\PathUnknown\\Directory with ID 0x01000005-00000001');
  });

  it('reads a record cut off by the end of the file as zeros, and says so', async () => {
    const { rows, warnings } = await load(false);
    expect(named(rows, 'ab')).toMatchObject({ EntryNumber: 42, OffsetToData: LEAD + 4 * 0x1000 });
    expect(warnings.map((w) => w.message)).toEqual([expect.stringMatching(/cut off by the end of the file \(64 of 72 bytes\)/)]);
  });

  it('reads nothing from a journal that is all zeros', async () => {
    const { rows, warnings } = await run(usnJrnl, bufReader(new Uint8Array(0x10000), '$J'));
    expect(rows).toEqual([]);
    expect(warnings[0].message).toMatch(/nothing but zeros/);
  });
});
