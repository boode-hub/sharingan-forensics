/**
 * Eric Zimmerman's own Prefetch unit-test assertions, run against our parser.
 *
 * The values below are copied from Prefetch.Test (TestVersion17, TestVersion23,
 * TestVersion26 and TestVersion30 in https://github.com/EricZimmerman/Prefetch),
 * and the four sample files are his, from the same MIT-licensed repository.
 * They cover every prefetch version the format has had, which matters because
 * the file information block, the volume entry and the run-time slots all move
 * between versions.
 *
 * His timestamps are written as -07:00; they are given here in UTC, which is
 * the same instant.
 */
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { bufReader } from '../core/reader';
import { run } from '../core/registry';
import { prefetch } from './prefetch';

async function load(name: string) {
  const buf = new Uint8Array(readFileSync(new URL(`../../fixtures/prefetch/${name}`, import.meta.url)));
  const outcome = await run(prefetch, bufReader(buf, name));
  const of = (type: string) => outcome.rows.filter((r) => r.entryType === type);
  return {
    outcome,
    runs: of('Run'),
    files: of('File'),
    dirs: of('Directory'),
    volumes: of('Volume'),
    refs: of('File Reference'),
    header: outcome.rows[0],
  };
}

describe('version 17 (Windows XP / Server 2003)', () => {
  it('matches his CMD.EXE-087B4001 assertions', async () => {
    const { header, runs, volumes, dirs, files, refs, outcome } = await load('CMD.EXE-087B4001.pf');

    expect(header.executable).toBe('CMD.EXE');
    // Note the missing leading zero: he formats the hash with "X", not "X8".
    expect(header.hash).toBe('87B4001');
    expect(header.size).toBe(6002);
    expect(header.runCount).toBe(3);
    expect((runs[0].runTime as Date).toISOString()).toBe('2016-01-15T23:01:40.875Z');

    expect(volumes.length).toBe(1);
    expect(volumes[0].volumeDevice).toBe('\\DEVICE\\HARDDISKVOLUME1');
    expect(volumes[0].volumeSerial).toBe('64BB3469');
    expect((volumes[0].volumeCreated as Date).toISOString()).toBe('2016-01-15T15:45:15.890Z');

    expect(dirs.length).toBe(4);
    expect(dirs[3].path).toBe('\\DEVICE\\HARDDISKVOLUME1\\WINDOWS\\SYSTEM32\\');

    expect(refs.length).toBe(20);
    expect(refs[5].mftEntry).toBe(250);
    expect(refs[5].mftSequence).toBe(1);

    expect(files.length).toBe(16);
    expect(files[3].path).toBe('\\DEVICE\\HARDDISKVOLUME1\\WINDOWS\\SYSTEM32\\LOCALE.NLS');

    expect(outcome.warnings).toEqual([]);
  });
});

describe('version 23 (Windows Vista / 7)', () => {
  it('matches his EXPLORER.EXE-7A3328DA assertions', async () => {
    const { header, runs, volumes, dirs, files, refs, outcome } = await load('EXPLORER.EXE-7A3328DA.pf');

    expect(header.executable).toBe('EXPLORER.EXE');
    expect(header.hash).toBe('7A3328DA');
    expect(header.size).toBe(38470);
    expect(header.runCount).toBe(1);
    expect((runs[0].runTime as Date).toISOString()).toBe('2016-01-16T20:02:00.832Z');

    expect(volumes.length).toBe(1);
    expect(volumes[0].volumeDevice).toBe('\\DEVICE\\HARDDISKVOLUME1');
    expect(volumes[0].volumeSerial).toBe('E8EAB8B5');
    expect((volumes[0].volumeCreated as Date).toISOString()).toBe('2016-01-16T20:53:13.109Z');

    expect(dirs.length).toBe(13);
    expect(dirs[3].path).toBe('\\DEVICE\\HARDDISKVOLUME1\\USERS\\PUBLIC');

    expect(refs.length).toBe(84);
    expect(refs[1].mftEntry).toBe(352);
    // He reports a zero sequence number as absent rather than as zero.
    expect(refs[1].mftSequence).toBeNull();

    expect(files.length).toBe(66);
    expect(files[3].path).toBe('\\DEVICE\\HARDDISKVOLUME1\\WINDOWS\\SYSTEM32\\ADVAPI32.DLL');

    expect(outcome.warnings).toEqual([]);
  });
});

describe('version 26 (Windows 8.x / Server 2012 R2)', () => {
  it('matches his _CMD.EXE-4A81B364 assertions', async () => {
    const { header, runs, volumes, dirs, files, refs, outcome } = await load('_CMD.EXE-4A81B364.pf');

    expect(header.executable).toBe('CMD.EXE');
    expect(header.hash).toBe('4A81B364');
    expect(header.size).toBe(8590);
    expect(header.runCount).toBe(2);
    expect((runs[0].runTime as Date).toISOString()).toBe('2016-01-16T21:25:41.534Z');

    expect(volumes.length).toBe(1);
    expect(volumes[0].volumeDevice).toBe('\\DEVICE\\HARDDISKVOLUME2');
    expect(volumes[0].volumeSerial).toBe('A26E529A');
    expect((volumes[0].volumeCreated as Date).toISOString()).toBe('2016-01-16T22:15:38.297Z');

    expect(dirs.length).toBe(8);
    expect(dirs[3].path).toBe('\\DEVICE\\HARDDISKVOLUME2\\WINDOWS\\BRANDING\\BASEBRD\\EN-US');

    expect(refs.length).toBe(20);
    expect(refs[1].mftEntry).toBe(44760);
    expect(refs[1].mftSequence).toBeNull();

    expect(files.length).toBe(12);
    expect(files[3].path).toBe('\\DEVICE\\HARDDISKVOLUME2\\WINDOWS\\SYSTEM32\\KERNELBASE.DLL');

    expect(outcome.warnings).toEqual([]);
  });
});

describe('version 30 (Windows 10) across two volumes', () => {
  it('matches his DCODEDCODE... assertions', async () => {
    const { header, runs, volumes, dirs, files, outcome } = await load(
      'DCODEDCODEDCODEDCODEDCODEDCOD-E65B9FE8.pf',
    );

    expect(header.executable).toBe('DCODEDCODEDCODEDCODEDCODEDCOD');
    expect(header.hash).toBe('E65B9FE8');
    expect(header.size).toBe(33606);
    expect(header.runCount).toBe(2);
    expect((runs[0].runTime as Date).toISOString()).toBe('2016-01-13T22:47:25.748Z');

    expect(volumes.length).toBe(2);
    expect(volumes[0].volumeDevice).toBe('\\VOLUME{01d12173f395296c-66f451bc}');
    expect(volumes[0].volumeSerial).toBe('66F451BC');
    expect((volumes[0].volumeCreated as Date).toISOString()).toBe('2015-11-17T20:10:06.204Z');
    expect(volumes[1].volumeDevice).toBe('\\VOLUME{01d1217a9c4c6779-8c9f49ec}');
    expect(volumes[1].volumeSerial).toBe('8C9F49EC');
    expect((volumes[1].volumeCreated as Date).toISOString()).toBe('2015-11-17T20:57:46.243Z');

    // Directories belong to a volume, so they are checked per volume.
    const vol0Dirs = dirs.filter((d) => d.volumeSerial === '66F451BC');
    const vol1Dirs = dirs.filter((d) => d.volumeSerial === '8C9F49EC');
    expect(vol0Dirs.length).toBe(1);
    expect(vol0Dirs[0].path).toBe('\\VOLUME{01d12173f395296c-66f451bc}\\TEMP');
    expect(vol1Dirs.length).toBe(19);

    const vol0Refs = outcome.rows.filter(
      (r) => r.entryType === 'File Reference' && r.volumeSerial === '66F451BC',
    );
    const vol1Refs = outcome.rows.filter(
      (r) => r.entryType === 'File Reference' && r.volumeSerial === '8C9F49EC',
    );
    expect(vol0Refs.length).toBe(2);
    expect(vol1Refs.length).toBe(85);

    expect(files.length).toBe(57);

    expect(outcome.warnings).toEqual([]);
  });

  it('pairs every loaded file with its own MFT record', async () => {
    // The file metrics array runs parallel to the filename list, so entry i
    // describes filename i. Getting this wrong would attach the wrong MFT
    // record to a path, which is worse than attaching none.
    const { files } = await load('DCODEDCODEDCODEDCODEDCODEDCOD-E65B9FE8.pf');
    expect(files.every((f) => f.mftEntry !== null)).toBe(true);
    const kernel32 = files.find((f) => String(f.path).endsWith('KERNEL32.DLL'));
    expect(kernel32?.mftEntry).toBeGreaterThan(0);
  });
});
