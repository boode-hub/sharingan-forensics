import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { bufReader } from '../core/reader';
import { detect, run } from '../core/registry';
import { sds } from './sds';
import './index';

// fixtures/sds/$SDS is built by fixtures/sds/make.mjs. The expected rows are
// what his Sds walk and SdsOut make of the descriptors it writes.
const buf = new Uint8Array(readFileSync('fixtures/sds/$SDS'));

const first = {
  Hash: '44332211',
  Id: 0x100,
  Offset: 0,
  OwnerSid: 'S-1-5-32-544',
  GroupSid: 'S-1-5-18',
  Control: 'SeDaclPresent|SeSelfRelative',
  SaclAceCount: 0,
  UniqueSaclAceTypes: null,
  DaclAceCount: 2,
  UniqueDaclAceTypes: 'AccessAllowed',
};
const second = {
  Hash: 'D4C3B2A1',
  Id: 0x101,
  Offset: 128,
  OwnerSid: 'S-1-5-21-2127521184-1604012920-1887927527-72713',
  GroupSid: 'S-1-5-21-2127521184-1604012920-1887927527-513',
  Control: 'SeDaclPresent|SeSaclPresent|SeDaclAutoInherited|SeDaclProtected|SeSelfRelative',
  SaclAceCount: 2,
  UniqueSaclAceTypes: 'SystemMandatoryLabel|SystemAudit',
  DaclAceCount: 3,
  UniqueDaclAceTypes: 'AccessAllowed|AccessDenied',
};
const fourth = {
  Hash: '04030201',
  Id: 0x102,
  Offset: 416,
  OwnerSid: 'S-1-5-18',
  GroupSid: 'S-1-5-32-544',
  Control: 'SeSelfRelative',
  SaclAceCount: 0,
  UniqueSaclAceTypes: null,
  DaclAceCount: 0,
  UniqueDaclAceTypes: null,
};

describe('$SDS (MFTECmd)', () => {
  it('is recognised by name, or by a first entry holding a self-relative descriptor', async () => {
    expect((await detect(bufReader(buf, '$Secure_$SDS')))?.id).toBe('sds');
    expect((await detect(bufReader(buf, 'stream.bin')))?.id).toBe('sds');
  });

  it('writes his SdsOut rows, the mirror block included, stepping over security id 0', async () => {
    const { rows, warnings } = await run(sds, bufReader(buf, '$SDS'));
    expect(warnings).toEqual([]);
    const src = { SourceFile: '$SDS' };
    expect(rows).toEqual([
      { ...first, FileOffset: 0, ...src },
      { ...second, FileOffset: 128, ...src },
      { ...fourth, FileOffset: 416, ...src },
      { ...first, FileOffset: 0x40000, ...src },
      { ...second, FileOffset: 0x40000 + 128, ...src },
      { ...fourth, FileOffset: 0x40000 + 416, ...src },
    ]);
  });

  it('moves past an entry with no offset or size on a block boundary, where his walk would never finish', async () => {
    const b = new Uint8Array(0x40010);
    b.set([1, 2, 3, 4, 5, 0, 0, 0]); // a hash and security id 5, offset 0, size 0
    const { rows, warnings } = await run(sds, bufReader(b, '$SDS'));
    expect(rows).toEqual([]);
    expect(warnings.map((w) => w.message)).toEqual([expect.stringMatching(/no offset or size on a block boundary/)]);
  });
});
