import { describe, expect, it } from 'vitest';
import type { Column, Row } from '../core/types';
import { compileQuery } from './query';

const columns: Column[] = [
  { key: 'eventId', label: 'Event Id', type: 'num' },
  { key: 'timeCreated', label: 'Time Created', type: 'date' },
  { key: 'computer', label: 'Computer', type: 'str' },
  { key: 'payload', label: 'Payload', type: 'str' },
];

function event(eventId: number, time: string, user: string, logonType: string, extra = ''): Row {
  return {
    eventId,
    timeCreated: new Date(time),
    computer: 'PC02.example.corp',
    payload:
      `<EventData><Data Name="TargetUserName">${user}</Data>` +
      `<Data Name="LogonType">${logonType}</Data>` +
      `<Data Name="CommandLine">${extra}</Data></EventData>`,
  };
}

const rows: Row[] = [
  event(4624, '2019-02-13T15:00:00Z', 'admin', '10', 'powershell.exe -enc SQBFAFgA'),
  event(4625, '2019-02-13T16:00:00Z', 'admin', '3'),
  event(4624, '2019-02-14T09:00:00Z', 'svchost', '5'),
  event(4634, '2019-02-15T09:00:00Z', 'bob', '2', 'C:\\Windows\\System32\\cmd.exe /c whoami'),
];

/** Which rows (by position) a filter keeps. */
function keep(q: string, defaultField?: string): number[] {
  const test = compileQuery(q, columns, defaultField);
  return rows.flatMap((r, i) => (test(r) ? [i] : []));
}

describe('searching for text', () => {
  it('finds a word anywhere in the row', () => {
    expect(keep('svchost')).toEqual([2]);
  });

  it('treats words next to each other as AND', () => {
    expect(keep('admin 4625')).toEqual([1]);
  });

  it('searches a quoted phrase as one piece, spaces and all', () => {
    expect(keep('"cmd.exe /c"')).toEqual([3]);
  });

  it('reads a Windows path as text, not as a field called C', () => {
    expect(keep('C:\\Windows\\System32')).toEqual([3]);
  });

  it('reads a URL as text, not as a field called http', () => {
    const withUrl: Row = { ...rows[0], computer: 'http://evil.example/x' };
    expect(compileQuery('http://evil.example', columns)(withUrl)).toBe(true);
    expect(compileQuery('http://evil.example', columns)(rows[1])).toBe(false);
  });
});

describe('combining conditions', () => {
  it('ORs', () => {
    expect(keep('4625 OR 4634')).toEqual([1, 3]);
  });

  it('ANDs, in any case', () => {
    expect(keep('4624 AND admin')).toEqual([0]);
    expect(keep('4624 and admin')).toEqual([0]);
    expect(keep('4624 && admin')).toEqual([0]);
  });

  it('excludes with -, NOT or !', () => {
    expect(keep('4624 -svchost')).toEqual([0]);
    expect(keep('4624 NOT svchost')).toEqual([0]);
    expect(keep('4624 !svchost')).toEqual([0]);
  });

  it('groups with parentheses', () => {
    expect(keep('(4625 OR 4634) -bob')).toEqual([1]);
  });

  it('gives AND tighter binding than OR, as everywhere else', () => {
    // 4634, or (4624 and svchost)
    expect(keep('4634 OR 4624 AND svchost')).toEqual([2, 3]);
  });

  it('keeps the dashes inside a date instead of treating them as NOT', () => {
    expect(keep('TimeCreated>=2019-02-14')).toEqual([2, 3]);
  });

  it('searches for a value that starts with a dash when it is quoted', () => {
    expect(keep('"-enc"')).toEqual([0]);
  });
});

describe('fields', () => {
  it('filters a column by its key or its label', () => {
    expect(keep('eventId:4625')).toEqual([1]);
    expect(keep('"Event Id":4625'.replace('"Event Id"', 'EventId'))).toEqual([1]);
  });

  it('distinguishes contains from exact', () => {
    const r: Row = { ...rows[0], eventId: 14624 };
    expect(compileQuery('EventId:4624', columns)(r)).toBe(true);
    expect(compileQuery('EventId=4624', columns)(r)).toBe(false);
  });

  it('reaches fields inside the event payload by name', () => {
    expect(keep('TargetUserName=admin')).toEqual([0, 1]);
    expect(keep('TargetUserName=admin LogonType=10')).toEqual([0]);
  });

  it('compares payload numbers as numbers, not text', () => {
    // As text "10" < "3"; as numbers it is not.
    expect(keep('LogonType>=5')).toEqual([0, 2]);
  });

  it('supports contains, startswith and endswith as words', () => {
    expect(keep('CommandLine contains whoami')).toEqual([3]);
    expect(keep('CommandLine startswith powershell')).toEqual([0]);
    expect(keep('CommandLine endswith whoami')).toEqual([3]);
  });

  it('supports wildcards', () => {
    expect(keep('CommandLine:*cmd.exe*')).toEqual([3]);
    expect(keep('TargetUserName=ad?in')).toEqual([0, 1]);
  });

  it('reads != as not equal', () => {
    expect(keep('TargetUserName!=admin')).toEqual([2, 3]);
  });

  it('compares dates as instants in UTC', () => {
    expect(keep('TimeCreated>=2019-02-13T15:30 TimeCreated<2019-02-15')).toEqual([1, 2]);
  });
});

describe('column filters', () => {
  it('apply a bare term to their own column', () => {
    expect(keep('4624 OR 4625', 'eventId')).toEqual([0, 1, 2]);
  });

  it('keep their old operators', () => {
    expect(keep('>=4625', 'eventId')).toEqual([1, 3]);
    expect(keep('=4624', 'eventId')).toEqual([0, 2]);
    expect(keep('!4624', 'eventId')).toEqual([1, 3]);
  });

  it('combine a range with AND', () => {
    expect(keep('>=2019-02-13T15:30 AND <2019-02-15', 'timeCreated')).toEqual([1, 2]);
  });
});

describe('mistakes', () => {
  it('reports an unclosed bracket rather than guessing', () => {
    expect(() => compileQuery('(4624 OR 4625', columns)).toThrow(/never closed/);
  });

  it('reports a stray closing bracket', () => {
    expect(() => compileQuery('4624)', columns)).toThrow(/no "\(" to close/);
  });

  it('reports an operator with nothing after it', () => {
    expect(() => compileQuery('4624 OR', columns)).toThrow();
  });

  it('treats an empty filter as no filter', () => {
    expect(keep('   ')).toEqual([0, 1, 2, 3]);
  });
});

describe('filtering on time', () => {
  const zoned = (q: string, zone: string) => {
    const test = compileQuery(q, columns, undefined, zone);
    return rows.flatMap((r, i) => (test(r) ? [i] : []));
  };

  it('reads a time without a zone as UTC, whatever the machine running it', () => {
    // With a space instead of T, JavaScript alone would take this as local time.
    expect(keep('TimeCreated>="2019-02-13 16:00"')).toEqual([1, 2, 3]);
    expect(keep('TimeCreated<"2019-02-13 16:00"')).toEqual([0]);
  });

  it('reads it in the zone times are shown in, and honours a written offset', () => {
    // 11:00 in New York on 13 February is 16:00 UTC.
    expect(zoned('TimeCreated>=2019-02-13T11:00', 'America/New_York')).toEqual([1, 2, 3]);
    expect(zoned('TimeCreated>=2019-02-13T16:00Z', 'America/New_York')).toEqual([1, 2, 3]);
  });

  it('matches text as it is shown', () => {
    expect(zoned('TimeCreated contains 2019-02-13T10:00', 'America/New_York')).toEqual([0]);
    expect(keep('TimeCreated contains 2019-02-13T15:00:00.0000000Z')).toEqual([0]);
  });
});
