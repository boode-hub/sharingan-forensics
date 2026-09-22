/**
 * Shimcache, from the two layouts that cover almost every machine in use.
 *
 * The fixtures are small SYSTEM-shaped hives built from the documented layout,
 * so the expected entries are the ones make.mjs put there rather than the ones
 * the parser happens to find. Real hives of every vintage are covered by the
 * opt-in corpus run.
 */
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { bufReader } from '../core/reader';
import { run } from '../core/registry';
import { appCompatCache } from './appcompatcache';

function hive(name: string): Uint8Array {
  return new Uint8Array(
    readFileSync(new URL(`../../fixtures/appcompatcache/${name}`, import.meta.url)),
  );
}

async function cache(name: string) {
  return run(appCompatCache, bufReader(hive(name), name));
}

for (const [name, expectedOs] of Object.entries({
  'SYSTEM-win10': 'Windows 10',
  'SYSTEM-win81': 'Windows 8.1 or Server 2012 R2',
})) {
  describe(`${name}`, () => {
    it('reads every entry, in the order the cache holds them', async () => {
      const outcome = await cache(name);
      expect(outcome.rows.map((r) => r.path)).toEqual([
        'SYSVOL\\Windows\\System32\\cmd.exe',
        'SYSVOL\\Users\\suspect\\Downloads\\tool.exe',
        'SYSVOL\\Windows\\System32\\notepad.exe',
      ]);
      // Position is the cache's own ordering, which is roughly most recent
      // first and is evidence in itself.
      expect(outcome.rows.map((r) => r.position)).toEqual([0, 1, 2]);
      expect(outcome.warnings).toEqual([]);
    });

    it('identifies the layout it found', async () => {
      const outcome = await cache(name);
      expect(outcome.rows[0].osVersion).toBe(expectedOs);
      expect(outcome.rows[0].controlSet).toBe(1);
    });

    it('carries the last modified time of each entry', async () => {
      const outcome = await cache(name);
      expect((outcome.rows[0].lastModified as Date).toISOString()).toBe(
        '2021-03-04T05:06:07.000Z',
      );
      expect((outcome.rows[1].lastModified as Date).toISOString()).toBe(
        '2022-07-08T09:10:11.000Z',
      );
    });

    it('reports execution as the entry records it', async () => {
      const outcome = await cache(name);
      expect(outcome.rows.map((r) => r.executed)).toEqual(['Yes', 'Yes', 'No']);
    });
  });
}

describe('a hive with no shimcache in it', () => {
  it('says so rather than returning an empty grid', async () => {
    const outcome = await run(
      appCompatCache,
      bufReader(
        new Uint8Array(readFileSync(new URL('../../fixtures/registry/SAM', import.meta.url))),
        'SAM',
      ),
    );
    expect(outcome.rows).toEqual([]);
    expect(outcome.warnings.some((w) => /no ControlSet keys/.test(String(w.message)))).toBe(true);
  });

  it('refuses something that is not a hive at all', async () => {
    const outcome = await run(appCompatCache, bufReader(new Uint8Array(600).fill(0x41), 'notes.txt'));
    expect(outcome.rows).toEqual([]);
    expect(outcome.warnings.some((w) => /not a registry hive/.test(String(w.message)))).toBe(true);
  });
});
