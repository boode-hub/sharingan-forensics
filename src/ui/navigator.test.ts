import { describe, expect, it } from 'vitest';
import { buildTree, categoryOf, entryFilter, extOf, fuzzyScore, sortEntries, type Entry } from './navigator';

const e = (path: string, kind: string | null, size = 1000, kindName = kind ?? ''): Entry => {
  const name = path.split('/').pop() as string;
  return { key: path, path, name, dir: path.slice(0, path.length - name.length - 1), ext: extOf(name), size, kind, kindName, opened: false };
};

const all = [
  e('C/Windows/System32/winevt/Logs/Security.evtx', 'evtx', 20 * 1024 ** 2, 'Event log'),
  e('C/Windows/System32/winevt/Logs/System.evtx', 'evtx', 5 * 1024 ** 2, 'Event log'),
  e('C/Windows/Prefetch/CMD.EXE-087B4001.pf', 'prefetch', 4000, 'Prefetch'),
  e('C/Windows/System32/config/SOFTWARE', 'registry', 130 * 1024 ** 2, 'Registry hive'),
  e('C/Users/bob/NTUSER.DAT', 'registry', 8 * 1024 ** 2, 'Registry hive'),
  e('C/Users/bob/AppData/Local/Temp/notes.txt', null, 10),
];
const paths = (q: string) => all.filter(entryFilter(q)).map((x) => x.name);

describe('the navigator filter', () => {
  it('matches text anywhere in the path, ignoring case', () => {
    expect(paths('prefetch')).toEqual(['CMD.EXE-087B4001.pf']);
    expect(paths('BOB')).toEqual(['NTUSER.DAT', 'notes.txt']);
  });

  it('takes an extension in any of its spellings', () => {
    for (const q of ['ext:evtx', 'ext:.evtx', '*.evtx', '.evtx']) expect(paths(q)).toEqual(['Security.evtx', 'System.evtx']);
  });

  it('takes a folder, a kind or category, and a size', () => {
    expect(paths('in:config')).toEqual(['SOFTWARE']);
    expect(paths('type:registry')).toEqual(['SOFTWARE', 'NTUSER.DAT']);
    expect(paths('type:execution')).toEqual(['CMD.EXE-087B4001.pf']);
    expect(paths('type:unrecognised')).toEqual(['notes.txt']);
    expect(paths('size>10mb')).toEqual(['Security.evtx', 'SOFTWARE']);
    expect(paths('size<=4000')).toEqual(['CMD.EXE-087B4001.pf', 'notes.txt']);
  });

  it('ANDs words, negates with a minus and keeps quoted phrases together', () => {
    expect(paths('ext:evtx -security')).toEqual(['System.evtx']);
    expect(paths('in:windows type:registry')).toEqual(['SOFTWARE']);
    expect(paths('"local/temp"')).toEqual(['notes.txt']);
  });

  it('files an unknown parser under Other, and nothing recognised under Unrecognised', () => {
    expect(categoryOf('evtx').label).toBe('Event logs');
    expect(categoryOf('something-new').id).toBe('other');
    expect(categoryOf(null).id).toBe('unrecognised');
  });
});

describe('the folder tree', () => {
  it('counts every level and joins single-child folders into one line', () => {
    const t = buildTree(all);
    expect(t.count).toBe(6);
    expect(t.folders.map((f) => [f.name, f.count])).toEqual([['C', 6]]);
    const c = t.folders[0];
    expect(c.folders.map((f) => [f.name, f.count])).toEqual([
      ['Users/bob', 2],
      ['Windows', 4],
    ]);
    const bob = c.folders[0];
    expect(bob.entries.map((x) => x.name)).toEqual(['NTUSER.DAT']);
    expect(bob.folders.map((f) => f.name)).toEqual(['AppData/Local/Temp']);
    expect(c.folders[1].folders.map((f) => f.name)).toEqual(['Prefetch', 'System32']);
  });

  it('treats folders as Windows does, ignoring case', () => {
    const w = buildTree([...all, e('C/windows/prefetch/X.EXE-1.pf', 'prefetch')]).folders[0].folders[1];
    expect(w.name).toBe('Windows');
    expect(w.folders.map((f) => [f.name, f.entries.length])).toEqual([
      ['Prefetch', 2],
      ['System32', 0],
    ]);
  });
});

describe('sorting and the quick switcher', () => {
  it('sorts by size largest first, and by type then path', () => {
    expect(sortEntries(all, 'size')[0].name).toBe('SOFTWARE');
    expect(sortEntries(all, 'type').map((x) => x.kindName)).toEqual(['', 'Event log', 'Event log', 'Prefetch', 'Registry hive', 'Registry hive']);
  });

  it('matches the characters in order and ranks file-name and word-start matches first', () => {
    expect(fuzzyScore('xyz', 'C/Windows/Prefetch/CMD.EXE-087B4001.pf')).toBe(null);
    const sec = fuzzyScore('secevtx', 'C/Windows/System32/winevt/Logs/Security.evtx') as number;
    const sys = fuzzyScore('secevtx', 'C/Windows/System32/winevt/Logs/System.evtx');
    expect(sec).toBeGreaterThan(0);
    expect(sys === null || sec > sys).toBe(true);
    expect(fuzzyScore('ntuser', 'C/Users/bob/NTUSER.DAT')! > fuzzyScore('ntuser', 'C/Users/bob/AppData/nt/useless.txt')!).toBe(true);
  });
});
