import { describe, expect, it } from 'vitest';
import { applyMap } from './binxml';
import { EVENT_MAPS, findMap, type EventMap } from './maps';
import { parseXml, selectSingleNode } from './xpath';

const SECURITY_4624 = `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing" Guid="54849625-5478-4994-a5ba-3e3b0328c30d"/><EventID>4624</EventID><Level>0</Level><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime="2019-02-13T15:14:52.409Z"/><EventRecordID>5278</EventRecordID><Correlation ActivityID="{11111111-2222-3333-4444-555555555555}"/><Execution ProcessID="480" ThreadID="1716"/><Channel>Security</Channel><Computer>PC02.example.corp</Computer><Security/></System><EventData><Data Name="SubjectUserName">PC02$</Data><Data Name="SubjectDomainName">EXAMPLE</Data><Data Name="TargetUserName">SYSTEM</Data><Data Name="TargetDomainName">NT AUTHORITY</Data><Data Name="TargetLogonId">0x3E7</Data><Data Name="LogonType">5</Data><Data Name="LogonProcessName">Advapi</Data><Data Name="AuthenticationPackageName">Negotiate</Data><Data Name="WorkstationName"></Data><Data Name="ProcessName">C:\\Windows\\System32\\services.exe</Data><Data Name="IpAddress">-</Data></EventData></Event>`;

describe('the map data survived conversion from his YAML', () => {
  it('has a value binding for every property, which is what makes a map do anything', () => {
    const empty = EVENT_MAPS.flatMap((m) =>
      m.properties.filter((p) => p.values.length === 0).map(() => m.eventId),
    );
    expect(empty).toEqual([]);
  });

  it('keeps single backslashes in templates rather than YAML-escaped pairs', () => {
    const m = findMap(4624, 'Security', 'Microsoft-Windows-Security-Auditing');
    expect(m?.properties[0].template).toBe('%domain%\\%user%');
  });

  it('keys a lookup by the literal string, so hex and decimal forms both survive', () => {
    const withBoth = EVENT_MAPS.find((m) =>
      m.lookups?.some((l) => Object.keys(l.values).some((k) => k.toLowerCase().startsWith('0x'))),
    );
    expect(withBoth).toBeDefined();
  });

  it('only ever targets the nine properties his validator allows', () => {
    const allowed = /^(UserName|RemoteHost|ExecutableInfo|PayloadData[1-6])$/i;
    const bad = EVENT_MAPS.flatMap((m) =>
      m.properties.map((p) => p.property).filter((p) => !allowed.test(p)),
    );
    expect(bad).toEqual([]);
  });
});

describe('map lookup requires an exact event/channel/provider match', () => {
  it('finds the map when all three agree', () => {
    expect(findMap(4624, 'security', 'MICROSOFT-WINDOWS-SECURITY-AUDITING')?.description).toBe(
      'Successful logon',
    );
  });

  it('does not fall back to a different provider, which would mislabel the event', () => {
    expect(findMap(4624, 'Security', 'Some-Other-Provider')).toBeUndefined();
    expect(findMap(4624, null, null)).toBeUndefined();
  });
});

describe('path selection', () => {
  const root = parseXml(SECURITY_4624);

  it('selects a named Data element', () => {
    expect(selectSingleNode(root, '/Event/EventData/Data[@Name="TargetUserName"]')).toBe('SYSTEM');
  });

  it('selects by position, 1-based as XPath counts', () => {
    expect(selectSingleNode(root, '/Event/EventData/Data[2]')).toBe('EXAMPLE');
  });

  it('selects an attribute', () => {
    expect(selectSingleNode(root, '/Event/System/Correlation/@ActivityID')).toBe(
      '{11111111-2222-3333-4444-555555555555}',
    );
  });

  it('returns null for a path that is not there', () => {
    expect(selectSingleNode(root, '/Event/EventData/Data[@Name="Nope"]')).toBeNull();
    expect(selectSingleNode(root, '/Event/UserData/EventInfo/Username')).toBeNull();
  });

  it('returns an empty string for an element that is present but empty', () => {
    // Distinct from null: a present-but-empty node still substitutes.
    expect(selectSingleNode(root, '/Event/EventData/Data[@Name="WorkstationName"]')).toBe('');
  });

  it('decodes entities, so a path never yields raw &amp;', () => {
    const r = parseXml('<Event><A>a &amp; b &lt;c&gt; &#65;</A></Event>');
    expect(selectSingleNode(r, '/Event/A')).toBe('a & b <c> A');
  });
});

describe('applying a map matches EvtxECmd', () => {
  const root = parseXml(SECURITY_4624);
  const map = findMap(4624, 'Security', 'Microsoft-Windows-Security-Auditing') as EventMap;
  const out = applyMap(root, map);

  it('fills the templates from the event data', () => {
    expect(out.UserName).toBe('EXAMPLE\\PC02$');
    expect(out.PayloadData1).toBe('Target: NT AUTHORITY\\SYSTEM');
    expect(out.PayloadData2).toBe('LogonType 5');
    expect(out.ExecutableInfo).toBe('C:\\Windows\\System32\\services.exe');
  });

  it('substitutes an empty value rather than dropping the property', () => {
    // EvtxECmd renders this literally, empty workstation and all; matching it
    // means an analyst comparing the two tools sees the same string.
    expect(out.RemoteHost).toBe(' (-)');
  });

  it('leaves untargeted properties unset', () => {
    expect(out.PayloadData6).toBeUndefined();
  });

  it('joins every regex hit with " | " as his Refine does', () => {
    const refined: EventMap = {
      eventId: 1,
      channel: 'c',
      provider: 'p',
      description: '',
      properties: [
        {
          property: 'PayloadData1',
          template: '%x%',
          values: [
            { name: 'x', path: '/Event/EventData/Data[@Name="TargetUserName"]', refine: 'S|Y' },
          ],
        },
      ],
    };
    expect(applyMap(root, refined).PayloadData1).toBe('S | Y | S');
  });

  it('renders an unlisted value as "Default (original)"', () => {
    const looked: EventMap = {
      eventId: 1,
      channel: 'c',
      provider: 'p',
      description: '',
      properties: [
        {
          property: 'PayloadData1',
          template: '%LogonType%',
          values: [{ name: 'LogonType', path: '/Event/EventData/Data[@Name="LogonType"]' }],
        },
      ],
      lookups: [{ name: 'LogonType', defaultVal: 'Unknown', values: { '3': 'Network' } }],
    };
    expect(applyMap(root, looked).PayloadData1).toBe('Unknown (5)');
  });
});
