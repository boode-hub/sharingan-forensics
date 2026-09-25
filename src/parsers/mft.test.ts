import { existsSync, readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { bufReader } from '../core/reader';
import { detect, run } from '../core/registry';
import type { Row } from '../core/types';
import { mft } from './mft';
import './index';

// fixtures/mft/$MFT is built by fixtures/mft/make.mjs. Each expectation below
// is what MFTECmd writes for the record as make.mjs describes it, worked out
// from his GetCsvData and the MFT library rather than from this parser.
const buf = new Uint8Array(readFileSync('fixtures/mft/$MFT'));
const load = () => run(mft, bufReader(buf, '$MFT'));
const iso = (d: unknown) => (d instanceof Date ? d.toISOString() : d);
const named = (rows: Row[], name: string) => {
  const r = rows.find((x) => x.FileName === name);
  if (!r) throw new Error(`no row for ${name}`);
  return r;
};

describe('$MFT (MFTECmd)', () => {
  it('is recognised by its first FILE record, whatever the file is called', async () => {
    expect((await detect(bufReader(buf, 'evidence.bin')))?.id).toBe('mft');
  });

  it('writes his column order', () => {
    expect(mft.columns.map((c) => c.label).join(',')).toBe(
      'Entry Number,Sequence Number,In Use,Parent Entry Number,Parent Sequence Number,Parent Path,File Name,Extension,File Size,Reference Count,Reparse Target,Is Directory,Has Ads,Is Ads,SI<FN,u Sec Zeros,Copied,Si Flags,Name Type,Created0x10,Created0x30,Last Modified0x10,Last Modified0x30,Last Record Change0x10,Last Record Change0x30,Last Access0x10,Last Access0x30,Update Sequence Number,Logfile Sequence Number,Security Id,Object Id File Droid,Logged Util Stream,Zone Id Contents,Source File,Resident Data Base64,Resident Data Hex,Resident Data ASCII,Offset',
    );
  });

  it('writes in-use records then free ones, a row per long name, streams after their file', async () => {
    const { rows } = await load();
    expect(rows.map((r) => r.FileName)).toEqual([
      '$MFT',
      '.',
      'LongFolderName',
      'report.docx',
      'report.docx:Zone.Identifier',
      'b.txt', // Posix sorts before Windows
      'a.txt',
      'orphan.txt',
      'big.bin',
      'big.bin:stream', // its second run piece (VCN 10) is not a second stream
      'link.txt',
      'Junction',
      'nosi.txt',
      'far.txt',
      'odd.bin',
      'found.txt',
      'OldDir',
      'gone.txt',
    ]);
    // DOS names, BAAD and blank records, the extension record and the repeated key write nothing.
    expect(rows.some((r) => /~1|dupe/.test(String(r.FileName)))).toBe(false);
  });

  it('builds parent paths from the directory records, deleted ones included', async () => {
    const { rows } = await load();
    expect(named(rows, '$MFT').ParentPath).toBe('.');
    expect(named(rows, '.').ParentPath).toBe('.');
    expect(named(rows, 'report.docx').ParentPath).toBe('.\\LongFolderName');
    expect(named(rows, 'gone.txt')).toMatchObject({
      InUse: false,
      ParentEntryNumber: 9,
      ParentSequenceNumber: 2,
      ParentPath: '.\\LongFolderName\\OldDir',
    });
    expect(named(rows, 'OldDir')).toMatchObject({ InUse: false, IsDirectory: true, SequenceNumber: 3 });
    expect(named(rows, 'orphan.txt').ParentPath).toBe('.\\PathUnknown\\Directory with ID 0x00000063-00000001');
    // An extension record whose base is gone still names its directory.
    expect(named(rows, 'found.txt').ParentPath).toBe('.\\Lost');
    // His MftEntryInfo: 5 + 1 * 2^24.
    expect(named(rows, 'far.txt')).toMatchObject({
      ParentEntryNumber: 16777221,
      ParentPath: '.\\PathUnknown\\Directory with ID 0x01000005-00000001',
    });
  });

  it('reads the timestamps and his flags on them', async () => {
    const { rows } = await load();
    const r = named(rows, 'report.docx');
    expect(r).toMatchObject({
      EntryNumber: 7,
      SequenceNumber: 2,
      Extension: '.docx',
      FileSize: 110,
      ReferenceCount: 1,
      HasAds: true,
      IsAds: false,
      Timestomped: true,
      uSecZeros: true,
      Copied: false,
      SiFlags: 'Hidden|System|Archive',
      NameType: 'Windows',
      SecurityId: 0x105,
      UpdateSequenceNumber: 0x1234,
      LogfileSequenceNumber: 0x100007,
      ObjectIdFileDroid: '33221100-5544-7766-8899-aabbccddeeff',
      SourceFile: '$MFT',
    });
    expect(
      Object.fromEntries(
        ['Created0x10', 'Created0x30', 'LastModified0x10', 'LastModified0x30', 'LastRecordChange0x10', 'LastRecordChange0x30', 'LastAccess0x10', 'LastAccess0x30'].map(
          (k) => [k, iso(r[k])],
        ),
      ),
    ).toEqual({
      Created0x10: '2024-03-01T10:00:00.123Z',
      Created0x30: '2024-03-02T11:30:00.456Z',
      LastModified0x10: '2024-03-05T09:15:30.000Z',
      LastModified0x30: null, // same as the SI time, so not repeated
      LastRecordChange0x10: '2024-03-06T12:00:00.789Z',
      LastRecordChange0x30: null,
      LastAccess0x10: '2024-03-06T12:00:00.789Z',
      LastAccess0x30: '2024-03-02T11:30:00.456Z',
    });

    const b = named(rows, 'b.txt');
    expect(b).toMatchObject({ Copied: true, uSecZeros: false, ReferenceCount: 2, NameType: 'Posix', FileSize: 77 });
    expect(named(rows, 'a.txt')).toMatchObject({ ParentPath: '.', NameType: 'Windows', FileSize: 77 });
  });

  it('fills the SI columns from the file name when a record has no $STANDARD_INFORMATION', async () => {
    const r = named((await load()).rows, 'nosi.txt');
    expect(r.SiFlags).toBe('None');
    expect(r.SecurityId).toBe(0);
    expect(iso(r.Created0x10)).toBe(null);
    expect(iso(r.Created0x30)).toBe('2022-01-01T01:01:01.001Z');
    expect(iso(r.LastModified0x10)).toBe('2022-02-02T02:02:02.002Z');
    expect(iso(r.LastRecordChange0x10)).toBe('2022-03-03T03:03:03.003Z');
    expect(iso(r.LastAccess0x10)).toBe('2022-04-04T04:04:04.004Z');
  });

  it('writes a row per alternate data stream, with Zone.Identifier text read across a fixup', async () => {
    const { rows } = await load();
    expect(named(rows, 'report.docx:Zone.Identifier')).toMatchObject({
      IsAds: true,
      HasAds: false,
      FileSize: 26,
      Extension: '.Identifier',
      ZoneIdContents: '[ZoneTransfer]\r\nZoneId=3\r\n',
    });
    expect(named(rows, 'big.bin:stream')).toMatchObject({ IsAds: true, FileSize: 300000, Extension: '' });
  });

  it('merges extension records into their base record', async () => {
    const r = named((await load()).rows, 'big.bin');
    expect(r).toMatchObject({ EntryNumber: 12, FileSize: 5000000, HasAds: true, ParentPath: '.' });
  });

  it('reads reparse targets as he does', async () => {
    const { rows } = await load();
    // His offset rule reads a symbolic link's print name plus "\??\", then strips the "\??\".
    expect(named(rows, 'link.txt')).toMatchObject({ ReparseTarget: 'C:\\Target\\file.txt', SiFlags: 'Archive|ReparsePoint' });
    expect(named(rows, 'Junction')).toMatchObject({
      ReparseTarget: 'C:\\Users',
      IsDirectory: true,
      Extension: null,
      SiFlags: 'Directory|ReparsePoint',
    });
  });

  it('writes an unnamed flag bit as .NET does, as a number', async () => {
    const r = named((await load()).rows, 'odd.bin');
    expect(r.SiFlags).toBe(String(0x800020));
    expect(r.LoggedUtilStream).toBe('$EFS');
  });

  it('warns about the torn sector and the repeated key, and keeps going', async () => {
    const { warnings } = await load();
    expect(warnings.map((w) => w.message)).toEqual([
      expect.stringMatching(/FILE record with key 00000007-00000002 already exists/),
      expect.stringMatching(/entry\/seq 0x15\/0x1: fixup value does not match/),
    ]);
  });
});

// EZ's own test MFTs (github.com/EricZimmerman/MFT, MFT.Test/TestFiles), when cloned into .refs.
describe.skipIf(!existsSync('.refs/MFT/MFT.Test/TestFiles/xw/$MFT'))('$MFT: his test files', () => {
  for (const name of ['NIST/DFR-16', 'xw']) {
    it(`${name}: every in-use record has a rooted path`, async () => {
      const file = new Uint8Array(readFileSync(`.refs/MFT/MFT.Test/TestFiles/${name}/$MFT`));
      const { rows, warnings } = await run(mft, bufReader(file, '$MFT'));
      expect(rows.length).toBeGreaterThan(0);
      expect(rows[0]).toMatchObject({ EntryNumber: 0, FileName: '$MFT', ParentPath: '.' });
      const unknown = rows.filter((r) => r.InUse && String(r.ParentPath).includes('PathUnknown'));
      expect(unknown.map((r) => r.FileName)).toEqual([]);
      expect(warnings.filter((w) => !/fixup|already exists/.test(w.message))).toEqual([]);
    });
  }
});
