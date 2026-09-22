import { describe, expect, it } from 'vitest';
import type { Column, Row } from '../core/types';
import { compileSigma, SigmaError } from './sigma';

const columns: Column[] = [
  { key: 'eventId', label: 'Event Id', type: 'num' },
  { key: 'channel', label: 'Channel', type: 'str' },
  { key: 'provider', label: 'Provider', type: 'str' },
  { key: 'computer', label: 'Computer', type: 'str' },
  { key: 'payload', label: 'Payload', type: 'str' },
];

/** A row the way the EVTX parser produces one. */
function ev(channel: string, eventId: number, data: Record<string, string>): Row {
  const payload =
    '<EventData>' +
    Object.entries(data)
      .map(([k, v]) => `<Data Name="${k}">${v.replace(/&/g, '&amp;').replace(/</g, '&lt;')}</Data>`)
      .join('') +
    '</EventData>';
  return { eventId, channel, provider: 'test', computer: 'PC02', payload };
}

const SYSMON = 'Microsoft-Windows-Sysmon/Operational';

const logonRdpLocal = ev('Security', 4624, {
  TargetUserName: 'admin',
  LogonType: '10',
  IpAddress: '127.0.0.1',
});
const logonNetwork = ev('Security', 4624, {
  TargetUserName: 'svc_backup',
  LogonType: '3',
  IpAddress: '10.20.30.40',
});
const logonSystemLog = ev('System', 4624, { LogonType: '10', IpAddress: '127.0.0.1' });
const encodedPs = ev(SYSMON, 1, {
  Image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
  CommandLine: 'powershell.exe -NoP -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA',
  ParentImage: 'C:\\Windows\\explorer.exe',
});
const slashPs = ev(SYSMON, 1, {
  Image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
  CommandLine: 'powershell.exe /enc SQBFAFgA',
  ParentImage: 'C:\\Windows\\System32\\cmd.exe',
});
const auditedCmd = ev('Security', 4688, {
  NewProcessName: 'C:\\Windows\\System32\\cmd.exe',
  ParentProcessName: 'C:\\Program Files\\Microsoft Office\\WINWORD.EXE',
  CommandLine: 'cmd.exe /c whoami',
});
const sysmonNet = ev(SYSMON, 3, { DestinationIp: '192.168.10.5', DestinationPort: '4444' });

const all = [logonRdpLocal, logonNetwork, logonSystemLog, encodedPs, slashPs, auditedCmd, sysmonNet];

async function hits(yaml: string): Promise<Row[]> {
  const rule = await compileSigma(yaml, columns);
  return all.filter(rule.test);
}

describe('rule metadata', () => {
  it('reads the title, level and tags', async () => {
    const rule = await compileSigma(
      `title: RDP Login from Localhost
id: 51e33403-2a37-4d66-a574-1fda1782cc31
status: test
level: high
tags:
  - attack.lateral-movement
  - attack.t1021.001
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4624
  condition: selection
`,
      columns,
    );
    expect(rule.title).toBe('RDP Login from Localhost');
    expect(rule.level).toBe('high');
    expect(rule.tags).toEqual(['attack.lateral-movement', 'attack.t1021.001']);
    expect(rule.notes).toEqual([]);
  });
});

describe('selections and conditions', () => {
  it('ANDs the fields of a selection and ORs the values of a field', async () => {
    const found = await hits(`title: t
logsource: { product: windows, service: security }
detection:
  selection:
    EventID: 4624
    LogonType: 10
    IpAddress:
      - '::1'
      - '127.0.0.1'
  condition: selection
`);
    expect(found).toEqual([logonRdpLocal]);
  });

  it('respects the logsource, so a Security rule ignores other logs', async () => {
    // logonSystemLog has the same fields but is in the System log.
    const found = await hits(`title: t
logsource: { product: windows, service: security }
detection:
  selection: { LogonType: 10, IpAddress: 127.0.0.1 }
  condition: selection
`);
    expect(found).toEqual([logonRdpLocal]);
  });

  it('evaluates and, or, not and brackets', async () => {
    const found = await hits(`title: t
logsource: { product: windows }
detection:
  logon: { EventID: 4624 }
  local: { IpAddress: 127.0.0.1 }
  service: { TargetUserName|startswith: svc_ }
  condition: logon and not (local or service)
`);
    expect(found).toEqual([]);
    const found2 = await hits(`title: t
logsource: { product: windows }
detection:
  logon: { EventID: 4624 }
  service: { TargetUserName|startswith: svc_ }
  condition: logon and not service
`);
    expect(found2).toEqual([logonRdpLocal, logonSystemLog]);
  });

  it('supports 1 of and all of with a pattern, and them', async () => {
    const rule = `title: t
logsource: { product: windows, category: process_creation }
detection:
  selection_img: { Image|endswith: '\\powershell.exe' }
  selection_enc: { CommandLine|contains: ' -enc ' }
  condition: all of selection_*
`;
    expect(await hits(rule)).toEqual([encodedPs]);
    expect(await hits(rule.replace('all of selection_*', '1 of selection_*'))).toEqual([encodedPs, slashPs]);
    expect(await hits(rule.replace('all of selection_*', 'all of them'))).toEqual([encodedPs]);
  });

  it('treats a list of maps as alternatives', async () => {
    const found = await hits(`title: t
logsource: { product: windows }
detection:
  selection:
    - { EventID: 3, DestinationPort: 4444 }
    - { EventID: 4624, LogonType: 3 }
  condition: selection
`);
    expect(found).toEqual([logonNetwork, sysmonNet]);
  });

  it('accepts a list of conditions as alternatives', async () => {
    const found = await hits(`title: t
logsource: { product: windows }
detection:
  a: { EventID: 3 }
  b: { EventID: 4688 }
  condition:
    - a
    - b
`);
    expect(found).toEqual([auditedCmd, sysmonNet]);
  });
});

describe('value modifiers', () => {
  it('matches case-insensitively by default, and exactly with |cased', async () => {
    const base = `title: t
logsource: { product: windows }
detection:
  s: { TargetUserName: ADMIN }
  condition: s
`;
    expect(await hits(base)).toEqual([logonRdpLocal]);
    expect(await hits(base.replace('TargetUserName:', 'TargetUserName|cased:'))).toEqual([]);
  });

  it('supports wildcards, and escapes them', async () => {
    // In the rule text this is C:\Windows\\*\powershell.exe: a backslash
    // followed by a wildcard has to be written \\*, because \* on its own is a
    // literal asterisk. That is the specification, and how SigmaHQ writes
    // paths such as C:\Users\\*\AppData.
    expect(
      await hits(`title: t
logsource: { product: windows }
detection:
  s: { Image: 'C:\\Windows\\\\*\\powershell.exe' }
  condition: s
`),
    ).toEqual([encodedPs, slashPs]);
    expect(
      await hits(`title: t
logsource: { product: windows }
detection:
  s: { Image: 'C:\\Windows\\*\\powershell.exe' }
  condition: s
`),
    ).toEqual([]);
    expect(
      await hits(`title: t
logsource: { product: windows }
detection:
  s: { CommandLine|contains: 'whoam\\?' }
  condition: s
`),
    ).toEqual([]);
  });

  it('does not let a trailing backslash escape the wildcard a modifier adds', async () => {
    // '\System32\' is how Sigma writes a directory. Built naively, |contains
    // turns it into \System32\* - and \* is a literal asterisk. This one bug
    // made 71 of SigmaHQ's own regression cases miss.
    expect(
      await hits(`title: t
logsource: { product: windows, category: process_creation }
detection:
  s: { Image|contains: '\\System32\\' }
  condition: s
`),
    ).toEqual([encodedPs, slashPs, auditedCmd]);
    expect(
      await hits(`title: t
logsource: { product: windows }
detection:
  keywords: ['\\System32\\']
  condition: keywords
`),
    ).toEqual([encodedPs, slashPs, auditedCmd]);
  });

  it('accepts a PCRE inline flag at the start of a regular expression', async () => {
    expect(
      await hits(`title: t
logsource: { product: windows }
detection:
  s: { CommandLine|re: '(?i)WHOAMI$' }
  condition: s
`),
    ).toEqual([auditedCmd]);
  });

  it('supports |all', async () => {
    expect(
      await hits(`title: t
logsource: { product: windows }
detection:
  s:
    CommandLine|contains|all: [' -NoP ', ' -w hidden ', ' -enc ']
  condition: s
`),
    ).toEqual([encodedPs]);
  });

  it('supports |re with its flags', async () => {
    expect(
      await hits(`title: t
logsource: { product: windows }
detection:
  s: { CommandLine|re: '-[Ee][Nn][Cc] [A-Za-z0-9+/=]{8,}' }
  condition: s
`),
    ).toEqual([encodedPs]);
    expect(
      await hits(`title: t
logsource: { product: windows }
detection:
  s: { CommandLine|re|i: 'WHOAMI$' }
  condition: s
`),
    ).toEqual([auditedCmd]);
  });

  it('supports |windash, so /enc matches a rule written for -enc', async () => {
    expect(
      await hits(`title: t
logsource: { product: windows, category: process_creation }
detection:
  s: { CommandLine|windash|contains: ' -enc ' }
  condition: s
`),
    ).toEqual([encodedPs, slashPs]);
  });

  it('supports |cidr for IPv4 and IPv6', async () => {
    expect(
      await hits(`title: t
logsource: { product: windows }
detection:
  s: { IpAddress|cidr: 10.0.0.0/8 }
  condition: s
`),
    ).toEqual([logonNetwork]);
    const v6 = ev('Security', 4624, { IpAddress: 'fe80::1c2b:3a4d' });
    const rule = await compileSigma(
      `title: t
logsource: { product: windows }
detection:
  s: { IpAddress|cidr: 'fe80::/10' }
  condition: s
`,
      columns,
    );
    expect(rule.test(v6)).toBe(true);
    expect(rule.test(logonNetwork)).toBe(false);
  });

  it('supports |base64offset|contains, finding a phrase inside encoded data', async () => {
    // "IEX (New-Object" encoded as UTF-16LE is inside the -enc argument above.
    expect(
      await hits(`title: t
logsource: { product: windows }
detection:
  s: { CommandLine|base64offset|contains|utf16le: 'IEX (New-Object' }
  condition: s
`),
    ).toEqual([encodedPs]);
  });

  it('supports |gt and friends for numbers', async () => {
    expect(
      await hits(`title: t
logsource: { product: windows }
detection:
  s: { LogonType|gte: 10 }
  condition: s
`),
    ).toEqual([logonRdpLocal, logonSystemLog]);
  });

  it('supports |exists and null', async () => {
    expect(
      await hits(`title: t
logsource: { product: windows }
detection:
  s: { DestinationPort|exists: true }
  condition: s
`),
    ).toEqual([sysmonNet]);
    expect(
      await hits(`title: t
logsource: { product: windows, service: security }
detection:
  s: { EventID: 4624, CommandLine: null }
  condition: s
`),
    ).toEqual([logonRdpLocal, logonNetwork]);
  });

  it('supports keyword searches', async () => {
    expect(
      await hits(`title: t
logsource: { product: windows }
detection:
  keywords:
    - 'WINWORD.EXE'
    - '4444'
  condition: keywords
`),
    ).toEqual([auditedCmd, sysmonNet]);
  });
});

describe('logsource', () => {
  it('runs a process_creation rule against Security 4688, with its field names', async () => {
    // The rule is written in Sysmon terms; 4688 calls these fields
    // NewProcessName and ParentProcessName.
    const found = await hits(`title: Office spawning a shell
logsource: { product: windows, category: process_creation }
detection:
  selection:
    ParentImage|endswith: '\\WINWORD.EXE'
    Image|endswith: '\\cmd.exe'
  condition: selection
`);
    expect(found).toEqual([auditedCmd]);
  });

  it('restricts a Sysmon category to its event id', async () => {
    const found = await hits(`title: t
logsource: { product: windows, category: network_connection }
detection:
  s: { DestinationPort: 4444 }
  condition: s
`);
    expect(found).toEqual([sysmonNet]);
  });

  it('says so when a rule is for another platform', async () => {
    const rule = await compileSigma(
      `title: t
logsource: { product: linux, service: auditd }
detection:
  s: { EventID: 4624 }
  condition: s
`,
      columns,
    );
    expect(all.filter(rule.test)).toEqual([]);
    expect(rule.notes.join(' ')).toMatch(/for linux/);
  });

  it('runs a rule with an unknown category everywhere, and says so', async () => {
    const rule = await compileSigma(
      `title: t
logsource: { product: windows, category: something_new }
detection:
  s: { EventID: 4624 }
  condition: s
`,
      columns,
    );
    expect(all.filter(rule.test).length).toBe(3);
    expect(rule.notes.join(' ')).toMatch(/no mapping/);
  });
});

describe('what the engine cannot do is said, not hidden', () => {
  it('runs a rule with an aggregation without it, and notes that', async () => {
    const rule = await compileSigma(
      `title: t
logsource: { product: windows, service: security }
detection:
  s: { EventID: 4624 }
  timeframe: 5m
  condition: s | count(TargetUserName) by IpAddress > 5
`,
      columns,
    );
    expect(all.filter(rule.test).length).toBe(2);
    expect(rule.notes.some((n) => /aggregation/.test(n))).toBe(true);
    expect(rule.notes.some((n) => /timeframe/.test(n))).toBe(true);
  });
});

describe('mistakes in a rule', () => {
  const bad = async (yaml: string) => {
    try {
      await compileSigma(yaml, columns);
      return null;
    } catch (e) {
      expect(e).toBeInstanceOf(SigmaError);
      return (e as Error).message;
    }
  };

  it('reports YAML that does not parse', async () => {
    expect(await bad('title: [unclosed')).toMatch(/not valid YAML/);
  });

  it('reports a missing detection or condition', async () => {
    expect(await bad('title: t\nlogsource: {}\n')).toMatch(/no detection/);
    expect(await bad('title: t\ndetection:\n  s: { EventID: 1 }\n')).toMatch(/no condition/);
  });

  it('reports a condition naming a selection that does not exist', async () => {
    expect(await bad('title: t\ndetection:\n  s: { EventID: 1 }\n  condition: s and missing\n')).toMatch(
      /"missing", which is not defined/,
    );
  });

  it('reports an unknown modifier', async () => {
    expect(await bad('title: t\ndetection:\n  s: { EventID|nonsense: 1 }\n  condition: s\n')).toMatch(
      /unknown modifier \|nonsense/,
    );
  });

  it('reports a regular expression that does not compile', async () => {
    expect(await bad("title: t\ndetection:\n  s: { CommandLine|re: '(' }\n  condition: s\n")).toMatch(
      /does not compile/,
    );
  });
});
