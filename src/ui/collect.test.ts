import { describe, expect, it } from 'vitest';
import { parsers } from '../core/registry';
import '../parsers';
import { casePath, caveat, dialogPath, expandBundle, findTargets, kapeCommand } from './collect';
import { KAPE_BUNDLES, KAPE_TARGETS, type KapeEntry } from './kapeTargets';

const entry = (path: string, mask: string | null, reads: string[] = []): KapeEntry => ({
  name: '',
  category: '',
  path,
  mask,
  recursive: false,
  reads,
});
const here = { source: '', user: '' };

describe('where to pick from', () => {
  it('opens a system folder as KAPE names it, or on the chosen drive', () => {
    const pf = entry('C:\\Windows\\prefetch\\', '*.pf');
    expect(dialogPath(pf, here)).toBe('C:\\Windows\\prefetch\\');
    expect(dialogPath(pf, { source: 'E:\\', user: '' })).toBe('E:\\Windows\\prefetch\\');
  });

  it('opens a profile folder as %USERPROFILE% here, the named user, or Users on an image', () => {
    const jl = entry('C:\\Users\\%user%\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\AutomaticDestinations\\', null);
    expect(dialogPath(jl, here)).toBe('%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\AutomaticDestinations\\');
    expect(dialogPath(jl, { source: '', user: 'bob' })).toBe('C:\\Users\\bob\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\AutomaticDestinations\\');
    expect(dialogPath(jl, { source: 'F:', user: '' })).toBe('F:\\Users\\');
  });

  it('stops at the first wildcard, which no dialog can open', () => {
    const chrome = entry('C:\\Users\\%user%\\AppData\\Local\\Google\\Chrome\\User Data\\*\\', 'History*');
    expect(dialogPath(chrome, { source: '', user: 'bob' })).toBe('C:\\Users\\bob\\AppData\\Local\\Google\\Chrome\\User Data\\');
  });
});

describe('where a picked file goes in the case', () => {
  const pf = entry('C:\\Windows\\prefetch\\', '*.pf');
  it('keeps it where Windows had it', () => {
    expect(casePath(pf, here, 'CMD.EXE-087B4001.pf')).toBe('C/Windows/prefetch/CMD.EXE-087B4001.pf');
    expect(casePath(pf, here, 'prefetch/CMD.EXE-087B4001.pf')).toBe('C/Windows/prefetch/CMD.EXE-087B4001.pf');
  });
  it('keeps a subfolder picked below the artifact, and names the profile', () => {
    const chrome = entry('C:\\Users\\%user%\\AppData\\Local\\Google\\Chrome\\User Data\\*\\', 'History*');
    expect(casePath(chrome, { source: '', user: 'bob' }, 'Default/History')).toBe('C/Users/bob/AppData/Local/Google/Chrome/User Data/Default/History');
    expect(casePath(chrome, here, 'History')).toBe('C/Users/user/AppData/Local/Google/Chrome/User Data/History');
  });
});

describe('what cannot be picked', () => {
  it('says NTFS metadata needs KAPE and hives are locked', () => {
    expect(caveat(entry('C:\\', '$MFT', ['mft']))).toMatch(/NTFS metadata/);
    expect(caveat(entry('C:\\Windows\\System32\\config\\', 'SYSTEM', ['registry']))).toMatch(/In use/);
    expect(caveat(entry('C:\\Windows\\prefetch\\', '*.pf', ['prefetch']))).toBe('May need administrator.');
    expect(caveat(entry('C:\\Users\\%user%\\Desktop\\', '*.LNK', ['lnk']))).toBeNull();
  });

  it('writes the KAPE command, quoting what cmd would split', () => {
    expect(kapeCommand(['Prefetch', '$MFT'], '', '')).toBe('kape.exe --tsource C: --tdest X:\\KAPE --target Prefetch,$MFT');
    expect(kapeCommand(['A'], 'E:\\', 'D:\\My Cases')).toBe('kape.exe --tsource E: --tdest "D:\\My Cases" --target A');
  });
});

describe('the KAPE targets', () => {
  it('covers every parser here, and names only parsers that exist', () => {
    const ids = new Set(parsers.map((p) => p.id));
    const read = new Set(KAPE_TARGETS.flatMap((t) => t.entries.flatMap((e) => e.reads)));
    expect([...ids].filter((id) => !read.has(id))).toEqual([]);
    expect([...read].filter((id) => !ids.has(id))).toEqual([]);
  });

  it('expands a bundle into targets that exist', () => {
    const names = new Set(KAPE_TARGETS.map((t) => t.name));
    const triage = expandBundle('KapeTriage', KAPE_BUNDLES);
    expect(triage).toContain('Prefetch');
    expect(triage).toContain('$MFT');
    expect(triage.filter((n) => !names.has(n))).toEqual([]);
  });

  it('finds targets by any word, in a group, or only those read here', () => {
    expect(findTargets(KAPE_TARGETS, 'prefetch', '', false).map((t) => t.name)).toContain('Prefetch');
    expect(findTargets(KAPE_TARGETS, '', 'Browsers', false).every((t) => t.group === 'Browsers')).toBe(true);
    const read = findTargets(KAPE_TARGETS, '', '', true);
    expect(read.length).toBeLessThan(KAPE_TARGETS.length);
    expect(read.every((t) => t.entries.some((e) => e.reads.length))).toBe(true);
  });
});
