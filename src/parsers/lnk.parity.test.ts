/**
 * Eric Zimmerman's own Lnk unit-test assertions, run against our parser.
 *
 * The values below are copied from Lnk.Test/TestMain.cs in
 * https://github.com/EricZimmerman/Lnk, and the two sample files are his, from
 * the same MIT-licensed repository. One is a Windows 7 shortcut to a directory
 * with a full target ID list, a tracker block and a known folder block; the
 * other is a Windows 8.1 store-app shortcut with no link info at all, which is
 * the case where the target ID list is all an analyst has.
 */
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { bufReader } from '../core/reader';
import { run } from '../core/registry';
import { lnk } from './lnk';

async function load(name: string) {
  const buf = new Uint8Array(readFileSync(new URL(`../../fixtures/lnk/${name}`, import.meta.url)));
  const outcome = await run(lnk, bufReader(buf, name));
  return {
    outcome,
    target: outcome.rows.find((r) => r.entryType === 'Target') as Record<string, unknown>,
    items: outcome.rows.filter((r) => r.entryType === 'Shell Item'),
    blocks: outcome.rows.filter((r) => r.entryType === 'Extra Block'),
  };
}

describe('a Windows 7 shortcut to a directory', () => {
  it('matches his local.directory.seven assertions', async () => {
    const { target, outcome } = await load('local.directory.seven.lnk');

    expect(target.relativePath).toBe('..\\..\\Administrator');
    expect(target.driveType).toBe('DriveFixed');
    expect(target.volumeSerialNumber).toBe('502E1A8A');
    expect(target.volumeLabel).toBe('SSD-WIN7');
    expect(target.localPath).toBe('C:\\Users\\');

    expect(target.machineId).toBe('netbook');
    expect(target.machineMacAddress).toBe('00:13:77:d3:4a:59');

    // He asserts the parts separately; this is the same instant.
    expect((target.trackerCreatedOn as Date).toISOString()).toMatch(
      /^2010-07-10T20:59:48/,
    );

    expect(outcome.warnings).toEqual([]);
  });

  it('decodes the target ID list into the path the shell resolved', async () => {
    const { target, items } = await load('local.directory.seven.lnk');

    expect(items.map((i) => `${i.itemKind}:${i.path}`)).toEqual([
      'Root folder: GUID:This PC',
      'Drive letter:C:',
      'Directory:Users',
      'Directory:Administrator',
    ]);
    expect(target.targetIdAbsolutePath).toBe('This PC\\C:\\Users\\Administrator');
  });

  it('lists every extra data block the file carries', async () => {
    const { blocks } = await load('local.directory.seven.lnk');
    expect(blocks.map((b) => b.itemKind)).toEqual([
      'KnownFolderDataBlock',
      'PropertyStoreDataBlock',
      'TrackerDataBaseBlock',
    ]);
  });
});

describe('a Windows 8.1 store-app shortcut with no link info', () => {
  it('matches his PhotosApp assertions', async () => {
    const { target, outcome } = await load('PhotosApp.lnk');

    expect(target.relativePath).toBeNull();
    // He asserts VolumeInfo is null; for us that is every volume field unset.
    expect(target.driveType).toBeNull();
    expect(target.volumeSerialNumber).toBeNull();
    expect(target.volumeLabel).toBeNull();

    expect(target.iconLocation).toBe('%windir%\\FileManager\\PhotosApp.exe');
    expect(String(target.extraBlocksPresent)).toContain('EnvironmentVariableDataBlock');
    expect(outcome.warnings).toEqual([]);
  });

  it('reads the environment variable block, which is the only path there is', async () => {
    const { blocks } = await load('PhotosApp.lnk');
    const env = blocks.find((b) => b.itemKind === 'EnvironmentVariableDataBlock');
    expect(env?.path).toBe('%windir%\\FileManager\\PhotosApp.exe');
  });
});
