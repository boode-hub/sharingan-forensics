import { readFileSync, readdirSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { openCfb } from '../core/cfb';
import { bufReader } from '../core/reader';
import { detect, run } from '../core/registry';
import type { Row } from '../core/types';
import { jumplist } from './jumplist';
import { lnk } from './lnk';
import './index';

const read = (name: string) => new Uint8Array(readFileSync(`fixtures/jumplist/${name}`));
const load = (name: string) => run(jumplist, bufReader(read(name), name));
const automatic = readdirSync('fixtures/jumplist').filter((f) => f.endsWith('.automaticDestinations-ms'));

describe('automatic jump lists (his JumpList test files)', () => {
  it('is what a file named as a jump list opens as', async () => {
    const name = '1b4dd67f29cb1962.win7.automaticDestinations-ms';
    expect((await detect(bufReader(read(name), name)))?.id).toBe('jumplist');
    // A compound file with some other name is not claimed as one.
    expect((await detect(bufReader(read(name), 'report.doc')))?.id).not.toBe('jumplist');
  });

  it('has one entry per shortcut stream in every file, as his AutoTests assert', async () => {
    // His assertion: DestListCount == DestListEntries.Count == Directory.Count - 2.
    for (const name of automatic) {
      const { rows } = await load(name);
      const cfb = openCfb(read(name), () => {});
      const streams = cfb?.entries.filter((e) => e.type === 2 && e.name !== 'DestList').length;
      expect(rows.filter((r) => r.Notes === '').length, name).toBe(streams);
      expect(rows.some((r) => r.Notes !== ''), name).toBe(false);
    }
  });

  it('agrees with each entry’s own shortcut about where it points', async () => {
    for (const name of automatic) {
      for (const r of (await load(name)).rows) {
        const path = String(r.Path);
        if (path.startsWith('::') || path.startsWith('knownfolder') || !r.LocalPath) continue;
        expect(path.toLowerCase(), `${name} entry ${r.EntryNumber}`).toBe(String(r.LocalPath).toLowerCase());
      }
    }
  });

  it('reads a Windows 10 DestList: pins, interaction counts, droids and the MFT reference', async () => {
    const { rows, warnings } = await load('f01b4d95cf55d32a.win10.automaticDestinations-ms');
    expect(warnings).toEqual([]);
    expect(rows).toHaveLength(9);
    const temp = rows.find((r) => r.EntryNumber === '7') as Row;
    expect(temp).toMatchObject({
      AppId: 'f01b4d95cf55d32a',
      AppIdDescription: 'Windows Explorer Windows 8.1',
      DestListVersion: 3,
      MRU: 0,
      Path: 'C:\\Temp',
      Hostname: 'desktop-annfp9d',
      MacAddress: '00:15:5d:01:6d:02',
      InteractionCount: 2,
      PinStatus: false,
      TargetIDAbsolutePath: 'This PC\\C:\\Temp',
      TargetMFTEntryNumber: '0xC0',
      DriveType: 'Fixed storage media (Hard drive)',
    });
    expect((temp.CreationTime as Date).toISOString()).toBe('2015-11-24T18:39:02.491Z');
    const desktop = rows.find((r) => r.EntryNumber === '1') as Row;
    expect(desktop).toMatchObject({ PinStatus: true, TargetMFTEntryNumber: '0xF725', InteractionCount: 3 });
    // A known folder path is named from his GUID table.
    expect(rows.find((r) => r.EntryNumber === '2')?.Path).toBe(
      'knownfolder:{374DE290-123F-4565-9164-39C4925E467B} ==> Downloads',
    );
  });

  it('reads a Windows 7 DestList and names shell namespace paths', async () => {
    const { rows } = await load('1b4dd67f29cb1962.win7.automaticDestinations-ms');
    const videos = rows.find((r) => r.EntryNumber === '4') as Row;
    expect(videos).toMatchObject({
      AppIdDescription: 'Windows Explorer Pinned and Recent.',
      DestListVersion: 1,
      Hostname: 'win7x64',
      InteractionCount: 0,
      Path: '::{031E4825-7B94-4DC3-B131-E946B44C8DD5}\\Videos.library-ms ==> UsersLibraries\\Videos.library-ms',
      // The library shell item is a property view naming a known folder.
      TargetIDAbsolutePath: 'UsersLibraries\\VideosLibrary',
    });
  });

  it('says when a jump list has nothing in it', async () => {
    const { rows, warnings } = await load('5f7b5f1e01b83767.win10.automaticDestinations-ms');
    expect(rows).toEqual([]);
    expect(warnings.map((w) => w.message)).toEqual([
      'the DestList is empty: the application has no recent or pinned items in this jump list',
    ]);
  });
});

describe('custom jump lists', () => {
  it('reads each category and each shortcut in it, as the .lnk parser reads the same shortcut', async () => {
    const { rows, warnings } = await load('9b9cdc69c1c24e2b.customDestinations-ms');
    expect(warnings).toEqual([]);
    expect(rows.map((r) => [r.table, r.EntryName])).toEqual([
      ['custom', 'Frequent'],
      ['custom', 'Frequent'],
      ['custom', ''],
    ]);
    expect(rows[0].AppIdDescription).toBe('Notepad 64-bit');

    for (const [i, name] of ['WordPad.lnk', 'Windows Update.lnk', 'remote.file.xp.lnk'].entries()) {
      const own = await run(lnk, bufReader(new Uint8Array(readFileSync(`fixtures/lnk/${name}`)), name));
      const target = own.rows[0];
      expect(rows[i], name).toMatchObject({
        LocalPath: target.localPath,
        CommonPath: target.commonPath,
        RelativePath: target.relativePath,
        VolumeSerialNumber: target.volumeSerialNumber,
        MachineID: target.machineId,
        FileSize: target.fileSize,
      });
    }
    expect(rows[1].TargetMFTEntryNumber).toBe('0x9A84');
  });
});
