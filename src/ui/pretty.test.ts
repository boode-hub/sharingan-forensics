import { describe, expect, it } from 'vitest';
import { pretty, prettyJson, prettyXml } from './pretty';

describe('laying out event XML', () => {
  it('puts each Data value on a line of its own', () => {
    const one =
      '<EventData><Data Name="TargetUserName">admin</Data><Data Name="LogonType">10</Data>' +
      '<Data Name="WorkstationName"></Data></EventData>';
    expect(prettyXml(one)).toBe(
      [
        '<EventData>',
        '  <Data Name="TargetUserName">admin</Data>',
        '  <Data Name="LogonType">10</Data>',
        '  <Data Name="WorkstationName"/>',
        '</EventData>',
      ].join('\n'),
    );
  });

  it('indents nested elements', () => {
    expect(prettyXml('<Event><System><EventID>4624</EventID></System></Event>')).toBe(
      ['<Event>', '  <System>', '    <EventID>4624</EventID>', '  </System>', '</Event>'].join('\n'),
    );
  });

  it('keeps special characters escaped, so the result is still XML', () => {
    expect(prettyXml('<Data Name="CommandLine">a &amp;&amp; b &lt;c&gt;</Data>')).toBe(
      '<Data Name="CommandLine">a &amp;&amp; b &lt;c&gt;</Data>',
    );
  });

  it('keeps attributes', () => {
    expect(prettyXml('<Provider Name="Microsoft-Windows-Security-Auditing" Guid="{1}"/>')).toBe(
      '<Provider Name="Microsoft-Windows-Security-Auditing" Guid="{1}"/>',
    );
  });

  it('leaves text that is not XML alone', () => {
    expect(prettyXml('C:\\Windows\\System32\\cmd.exe')).toBeNull();
    expect(pretty('4624')).toBeNull();
    expect(pretty(4624)).toBeNull();
  });
});

describe('laying out JSON', () => {
  it('indents an object', () => {
    expect(prettyJson('{"a":1,"b":[2,3]}')).toBe('{\n  "a": 1,\n  "b": [\n    2,\n    3\n  ]\n}');
  });

  it('leaves invalid JSON alone rather than guessing', () => {
    expect(prettyJson('{not json}')).toBeNull();
  });
});
