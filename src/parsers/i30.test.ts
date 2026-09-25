import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { bufReader } from '../core/reader';
import { detect, run } from '../core/registry';
import type { Row } from '../core/types';
import { i30 } from './i30';
import './index';

// fixtures/i30/*.$I30 are the three samples from his MFT test corpus (MIT):
// one directory's index at the start, after a first deletion and after a
// second. His tests assert nothing about them, so these tests check the
// first entry against values read off the hex by hand, and the deletions
// against each other.
const load = async (name: string) =>
  run(i30, bufReader(new Uint8Array(readFileSync(`fixtures/i30/${name}.$I30`)), '$I30'));
const active = (rows: Row[]) => rows.filter((r) => !r.FromSlack).map((r) => r.FileName as string);
const slack = (rows: Row[]) => rows.filter((r) => r.FromSlack).map((r) => r.FileName as string);

describe('$I30 (MFTECmd)', () => {
  it('is recognised by its INDX signature', async () => {
    const buf = new Uint8Array(readFileSync('fixtures/i30/Start.$I30'));
    expect((await detect(bufReader(buf, 'index.bin')))?.id).toBe('i30');
  });

  it('writes his I30Out columns in declaration order', () => {
    expect(i30.columns.map((c) => c.key).join(',')).toBe(
      'Offset,FromSlack,SelfMftEntry,SelfMftSequence,FileName,Flags,NameType,ParentMftEntry,ParentMftSequence,CreatedOn,ContentModifiedOn,RecordModifiedOn,LastAccessedOn,PhysicalSize,LogicalSize,SourceFile',
    );
  });

  it('reads the first active entry as the hex has it', async () => {
    const { rows } = await load('Start');
    // Page 0: data starts at 0x18 + 0x28. Entry: self 52 cd 01 00 00 00 1c 00,
    // parent 44 d0 01 00 00 00 12 00, four times e0 d2 e8 ba d5 dd d5 01,
    // flags 00 00 00 10, name length 7, type 3, "Folder1".
    const t = '2020-02-07T16:43:31.089Z';
    expect({
      ...rows[0],
      CreatedOn: (rows[0].CreatedOn as Date).toISOString(),
      ContentModifiedOn: (rows[0].ContentModifiedOn as Date).toISOString(),
      RecordModifiedOn: (rows[0].RecordModifiedOn as Date).toISOString(),
      LastAccessedOn: (rows[0].LastAccessedOn as Date).toISOString(),
    }).toEqual({
      Offset: 0x40,
      FromSlack: false,
      SelfMftEntry: 0x1cd52,
      SelfMftSequence: 0x1c,
      FileName: 'Folder1',
      Flags: 'IsDirectory',
      NameType: 'DosWindows',
      ParentMftEntry: 0x1d044,
      ParentMftSequence: 0x12,
      CreatedOn: t,
      ContentModifiedOn: t,
      RecordModifiedOn: t,
      LastAccessedOn: t,
      PhysicalSize: 0,
      LogicalSize: 0,
      SourceFile: '$I30',
    });
  });

  it('recovers from slack only entries the directory really held, deleted ones among them', async () => {
    // Deleting an entry shifts the ones after it down over it, so only what
    // lands past the new end of the data survives in slack - not every
    // deleted name. What does appear must have been a live entry before.
    const [start, first, second] = await Promise.all(['Start', 'FirstDelete', 'SecondDelete'].map(load));
    for (const [before, after, deleted] of [
      [start, first, ['Folder5', 'SOE7F0~1.TXT', 'SomeFile12.txt']],
      [first, second, ['SO5D72~1.TXT', 'SO82F4~1.TXT', 'SOBCB0~1.TXT', 'SomeFile20.txt']],
    ] as const) {
      const fresh = slack(after.rows).filter((n) => !slack(before.rows).includes(n));
      for (const n of fresh) expect(active(before.rows)).toContain(n);
      const gone = active(before.rows).filter((n) => !active(after.rows).includes(n));
      expect(fresh.filter((n) => gone.includes(n)).sort()).toEqual([...deleted].sort());
    }
  });

  it('keeps a slack entry once, however many pages repeat it', async () => {
    const { rows } = await load('SecondDelete');
    const keys = rows.filter((r) => r.FromSlack).map((r) => `${r.Offset}`);
    expect(new Set(keys).size).toBe(keys.length);
  });
});
