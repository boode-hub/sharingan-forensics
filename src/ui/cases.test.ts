import { describe, expect, it } from 'vitest';
import { baseName, dirName, isArtifactList, isCaseList, isPairedLog, logsFor, newCase } from './cases';

const a = (path: string) => ({ path });

describe('case artifacts', () => {
  it('pairs a hive with its transaction logs, and only its own', () => {
    const all = [
      a('C/Users/bob/NTUSER.DAT'),
      a('C/Users/bob/ntuser.dat.LOG1'),
      a('C/Users/bob/NTUSER.DAT.LOG2'),
      a('C/Users/eve/NTUSER.DAT'),
      a('C/Users/eve/NTUSER.DAT.LOG1'),
      a('C/Users/bob/NTUSER.DAT.bak'),
    ];
    expect(logsFor(all[0], all).map((x) => x.path)).toEqual([
      'C/Users/bob/ntuser.dat.LOG1',
      'C/Users/bob/NTUSER.DAT.LOG2',
    ]);
    expect(logsFor(all[3], all).map((x) => x.path)).toEqual(['C/Users/eve/NTUSER.DAT.LOG1']);
    expect(all.filter((x) => isPairedLog(x, all)).map((x) => x.path)).toEqual([
      'C/Users/bob/ntuser.dat.LOG1',
      'C/Users/bob/NTUSER.DAT.LOG2',
      'C/Users/eve/NTUSER.DAT.LOG1',
    ]);
  });

  it('keeps a log listed when its hive is not in the case', () => {
    const all = [a('SYSTEM.LOG1')];
    expect(isPairedLog(all[0], all)).toBe(false);
  });

  it('splits stored paths whichever separator they use', () => {
    expect(baseName('C\\Windows\\System32\\winevt\\Logs\\Security.evtx')).toBe('Security.evtx');
    expect(dirName('C/Windows/Prefetch/CMD.EXE-1.pf')).toBe('C/Windows/Prefetch');
    expect(dirName('Security.evtx')).toBe('');
  });
});

describe('stored case data', () => {
  it('accepts what it wrote and rejects anything else', () => {
    // Storage can be edited or damaged outside the app; a bad file must fall
    // back to nothing rather than break the page.
    const c = newCase({ name: 'ACME breach', customer: 'ACME', reference: 'IR-42', examiner: '', notes: '' });
    expect(isCaseList([c])).toBe(true);
    expect(isCaseList([{ ...c, name: 5 }])).toBe(false);
    expect(isCaseList({})).toBe(false);

    const art = { id: 'x', path: 'p', size: 1, lastModified: 0, added: 't', detected: null, parserId: 'evtx' };
    expect(isArtifactList([art])).toBe(true);
    expect(isArtifactList([{ ...art, size: 'big' }])).toBe(false);
    expect(isArtifactList([{ ...art, detected: 3 }])).toBe(false);
  });
});
