import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { bufReader } from '../core/reader';
import { detect, run } from '../core/registry';
import { recentFileCache } from './recentfilecache';
import './index';

// fixtures/recentfilecache/ holds the three files from his test corpus (MIT),
// and these are his RecentFileCacheTests assertions.
const load = (name: string) =>
  run(recentFileCache, bufReader(new Uint8Array(readFileSync(`fixtures/recentfilecache/${name}`)), name));

describe('RecentFileCache.bcf (RecentFileCacheParser)', () => {
  it('reads his first sample: six names, the last c:\\windows\\bcuninstall.exe', async () => {
    const { rows, warnings } = await load('RecentFileCache.bcf');
    const names = rows.map((r) => r.Filename as string);
    expect(warnings).toEqual([]);
    expect(names).toHaveLength(6);
    expect(names.some((n) => n.includes('wipesvc.exe'))).toBe(true);
    expect(names.some((n) => n.includes('TotallyMadeUp.exe'))).toBe(false);
    expect(names.at(-1)).toBe('c:\\windows\\bcuninstall.exe');
    expect(rows[0]).toMatchObject({ SourceFile: 'RecentFileCache.bcf', SourceCreated: null });
  });

  it('reads his second sample: two names, the last c:\\windows\\system32\\tasklist.exe', async () => {
    const names = (await load('RecentFileCache 2.bcf')).rows.map((r) => r.Filename as string);
    expect(names).toHaveLength(2);
    expect(names.at(-1)).toBe('c:\\windows\\system32\\tasklist.exe');
  });

  it('leaves his not-a-cache sample to the parser it belongs to', async () => {
    const buf = new Uint8Array(readFileSync('fixtures/recentfilecache/NotARecentFileCache.bcf'));
    expect((await detect(bufReader(buf, 'NotARecentFileCache.bcf')))?.id).toBe('lnk');
    const { rows, warnings } = await load('NotARecentFileCache.bcf');
    expect(rows).toEqual([]);
    expect(warnings[0].message).toMatch(/invalid header/);
  });
});
