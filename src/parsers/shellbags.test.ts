/**
 * Shell bags, read from a real UsrClass.dat.
 *
 * The fixture is from Eric Zimmerman's MIT-licensed Registry test corpus. It
 * holds a small, hand-made folder tree, which is what makes it useful: the
 * expected shape is obvious from the paths themselves, so a parser that
 * mis-nests or mis-orders entries is visible rather than merely different.
 */
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { bufReader } from '../core/reader';
import { detect, run } from '../core/registry';
import { shellbags } from './shellbags';
import './index';

function hive(): Uint8Array {
  return new Uint8Array(readFileSync(new URL('../../fixtures/shellbags/UsrClass.dat', import.meta.url)));
}

async function bags() {
  return run(shellbags, bufReader(hive(), 'UsrClass.dat'));
}

describe('reading shell bags from a UsrClass hive', () => {
  it('rebuilds the folder tree the user browsed', async () => {
    const outcome = await bags();
    const paths = outcome.rows.map((r) => r.absolutePath);

    expect(paths).toContain('CONFIDENTIAL');
    expect(paths).toContain('CONFIDENTIAL\\X');
    expect(paths).toContain('CONFIDENTIAL\\X\\1\\iii');
    expect(paths).toContain('CONFIDENTIAL\\Y\\1\\iii');
    expect(outcome.warnings).toEqual([]);
  });

  it('carries the timestamps and MFT record of each folder', async () => {
    const outcome = await bags();
    const row = outcome.rows.find((r) => r.absolutePath === 'CONFIDENTIAL\\X');

    expect(row?.shellType).toBe('Directory');
    expect(row?.modified).toBeInstanceOf(Date);
    expect((row!.modified as Date).toISOString()).toBe('2013-11-03T02:38:08.000Z');
    expect(row?.mftEntry).toBe(65985);
    expect(row?.mftSequence).toBe(1);
    expect(row?.fileSystemHint).toBe('NTFS');
  });

  it('reports the node slot and the most-recently-used ordering', async () => {
    const outcome = await bags();
    const row = outcome.rows.find((r) => r.absolutePath === 'CONFIDENTIAL');

    // NodeSlot ties the bag to its view settings in the Bags key; MRU position
    // is the order Explorer last saw them in.
    expect(row?.nodeSlot).toBe(16);
    expect(typeof row?.mruPosition).toBe('number');
    expect(row?.bagPath).toMatch(/BagMRU/);
  });

  it('names a GUID folder rather than printing the GUID', async () => {
    const outcome = await bags();
    const named = outcome.rows.find((r) => r.shellType === 'Root folder: GUID');
    expect(named?.value).toBe('Shared Documents Folder (Users Files)');
  });

  it('names property views from their property store or GUID, as his ShellBag0X00 does', async () => {
    const outcome = await bags();
    const byPath = (p: string) => outcome.rows.find((r) => r.absolutePath === p);
    // 0x23FEBBEE property views carry a known folder GUID.
    expect(byPath('Shared Documents Folder (Users Files)\\Downloads')?.shellType).toBe('Variable');
    expect(byPath('UsersLibraries\\VideosLibrary')?.value).toBe('VideosLibrary');
    // A full property store: the name is System.ItemNameDisplay (property 10).
    expect(
      byPath('ControlPanelHome\\All Control Panel Items\\User Accounts\\Change Your Name')?.shellType,
    ).toBe('Variable: Users property view');
  });
});

describe('a hive with no shell bags in it', () => {
  it('says so rather than returning an empty grid', async () => {
    const outcome = await run(
      shellbags,
      bufReader(new Uint8Array(readFileSync(new URL('../../fixtures/registry/SAM', import.meta.url))), 'SAM'),
    );
    expect(outcome.rows).toEqual([]);
    expect(outcome.warnings.some((w) => /no BagMRU key/.test(String(w.message)))).toBe(true);
  });

  it('refuses something that is not a hive at all', async () => {
    const outcome = await run(shellbags, bufReader(new Uint8Array(600).fill(0x41), 'notes.txt'));
    expect(outcome.rows).toEqual([]);
    expect(outcome.warnings.some((w) => /not a registry hive/.test(String(w.message)))).toBe(true);
  });
});

describe('it does not take hives away from the registry parser', () => {
  it('a UsrClass.dat still opens as a hive by default', async () => {
    const chosen = await detect(bufReader(hive(), 'UsrClass.dat'));
    expect(chosen?.id).toBe('registry');
  });
});
