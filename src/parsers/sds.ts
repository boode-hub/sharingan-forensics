/**
 * $Secure:$SDS, the stream of every security descriptor on an NTFS volume.
 * A file's $STANDARD_INFORMATION security id ($MFT SecurityId) names one.
 *
 * Ported from Eric Zimmerman's Secure library and descriptor classes
 * (https://github.com/EricZimmerman/MFT: SDS/Sds.cs, SDS/SdsEntry.cs,
 * MFT/Attributes/SKSecurityDescriptor.cs, xACLRecord.cs, ACERecord.cs and
 * Helpers.ConvertHexStringToSidString) and MFTECmd's ProcessSds and SdsOut
 * (https://github.com/EricZimmerman/MFTECmd).
 *
 * The stream is written in 256 KB blocks, each followed by a mirror copy of
 * itself; his walk reads both, so each descriptor appears twice, the second
 * time with its FileOffset in the mirror.
 */
import type { Column, ColType, Ctx, Parser, Reader, Row } from '../core/types';
import { dotnetFlags } from './mft';

// SdsOut, automapped in declaration order.
const columns: Column[] = [
  ['Hash'],
  ['Id', 'num'],
  ['Offset', 'num'],
  ['OwnerSid'],
  ['GroupSid'],
  ['Control'],
  ['SaclAceCount', 'num'],
  ['UniqueSaclAceTypes'],
  ['DaclAceCount', 'num'],
  ['UniqueDaclAceTypes'],
  ['FileOffset', 'num'],
  ['SourceFile'],
].map(([key, type = 'str']) => ({ key, label: key.replace(/([a-z])([A-Z])/g, '$1 $2'), type: type as ColType }));

// His SkSecurityDescriptor.ControlEnum, in ascending value order.
const CONTROL: Array<[number, string]> = [
  [0x1, 'SeOwnerDefaulted'],
  [0x2, 'SeGroupDefaulted'],
  [0x4, 'SeDaclPresent'],
  [0x8, 'SeDaclDefaulted'],
  [0x10, 'SeSaclPresent'],
  [0x20, 'SeSaclDefaulted'],
  [0x40, 'SeDaclUntrusted'],
  [0x80, 'SeServerSecurity'],
  [0x100, 'SeDaclAutoInheritReq'],
  [0x200, 'SeSaclAutoInheritReq'],
  [0x400, 'SeDaclAutoInherited'],
  [0x800, 'SeSaclAutoInherited'],
  [0x1000, 'SeDaclProtected'],
  [0x2000, 'SeSaclProtected'],
  [0x4000, 'SeRmControlValid'],
  [0x8000, 'SeSelfRelative'],
];

// His AceRecord.AceTypeEnum by type byte; anything else is Unknown.
const ACE_TYPES = [
  'AccessAllowed',
  'AccessDenied',
  'SystemAudit',
  'SystemAlarm',
  'AccessAllowedCompound',
  'AccessAllowedObject',
  'AccessDeniedObject',
  'SystemAuditObject',
  'SystemAlarmObject',
  'AccessAllowedCallback',
  'AccessDeniedCallback',
  'AccessAllowedCallbackObject',
  'AccessDeniedCallbackObject',
  'SystemAuditCallback',
  'SystemAlarmCallback',
  'SystemAuditCallbackObject',
  'SystemAlarmCallbackObject',
  'SystemMandatoryLabel',
  'SystemResourceAttribute',
  'SystemScopedPolicyId',
  'SystemProcessTrustLabel',
];

/**
 * His ConvertHexStringToSidString. It ignores the sub-authority count and
 * reads four-byte sub-authorities to the end of whatever it is given, and
 * takes the authority from bytes 4-7 only.
 */
function sidString(b: Uint8Array): string {
  if (b.length < 12) return '';
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  let sid = `S-${b[0]}-${dv.getInt32(4, false)}`;
  for (let i = 8; i + 4 <= b.length; i += 4) sid += `-${dv.getUint32(i, true)}`;
  return sid;
}

/** His XAclRecord: the ACE count from the header, and each ACE's type, walked by the low byte of its size. */
function acl(b: Uint8Array): { count: number; types: string } {
  if (b.length === 0) return { count: 0, types: '' };
  const count = b.length >= 6 ? b[4] | (b[5] << 8) : 0;
  const types = new Set<string>();
  let at = 8;
  for (let i = 0; i < count && at + 2 < b.length; i++) {
    const size = b[at + 2];
    if (size > 0 && at + size <= b.length) types.add(ACE_TYPES[b[at]] ?? 'Unknown');
    at += size;
  }
  return { count, types: [...types].join('|') };
}

/**
 * His SkSecurityDescriptor. Each part's length is the gap to the part he
 * expects next - SACL, DACL, owner, group, the order NTFS writes them in.
 */
function descriptor(sd: Uint8Array) {
  const dv = new DataView(sd.buffer, sd.byteOffset, sd.byteLength);
  const control = dv.getUint16(2, true);
  const owner = dv.getUint32(4, true);
  const group = dv.getUint32(8, true);
  const saclAt = dv.getUint32(12, true);
  const daclAt = dv.getUint32(16, true);
  const part = (at: number, len: number) => (len >= 0 && at + len <= sd.length ? sd.subarray(at, at + len) : null);
  const row: Row = {
    OwnerSid: sidString(part(owner, group - owner) ?? new Uint8Array(0)),
    GroupSid: sidString(part(group, sd.length - group) ?? new Uint8Array(0)),
    Control: dotnetFlags(control, CONTROL),
    SaclAceCount: 0,
    UniqueSaclAceTypes: null,
    DaclAceCount: 0,
    UniqueDaclAceTypes: null,
  };
  // He drops a SACL longer than 1000 bytes.
  const sacl = control & 0x10 && daclAt - saclAt <= 1000 ? part(saclAt, daclAt - saclAt) : null;
  if (sacl && sacl.length > 0) {
    const a = acl(sacl);
    row.SaclAceCount = a.count;
    row.UniqueSaclAceTypes = a.types;
  }
  const dacl = control & 0x4 ? part(daclAt, owner - daclAt) : null;
  if (dacl) {
    const a = acl(dacl);
    row.DaclAceCount = a.count;
    row.UniqueDaclAceTypes = a.types;
  }
  return row;
}

const BLOCK = 0x40000;

export const sds: Parser = {
  id: 'sds',
  name: '$SDS (security descriptors)',
  ezTool: 'MFTECmd',
  extensions: [],
  columns,
  sniff(head: Uint8Array, filename: string): boolean {
    if (/\$sds/i.test(filename)) return true;
    if (head.length < 0x28) return false;
    const dv = new DataView(head.buffer, head.byteOffset, head.byteLength);
    // A first entry at offset 0, holding a self-relative revision 1 descriptor.
    const size = dv.getUint32(16, true);
    return (
      dv.getBigUint64(8, true) === 0n &&
      dv.getUint32(4, true) > 0 &&
      size >= 0x28 &&
      size < 0x10000 &&
      head[0x14] === 1 &&
      (dv.getUint16(0x16, true) & 0x8000) !== 0
    );
  },
  async *parse(reader: Reader, ctx: Ctx): AsyncGenerator<Row> {
    const length = reader.size;
    let win: Uint8Array = new Uint8Array(0);
    let winAt = 0;
    const view = async (pos: number, len: number) => {
      if (pos < winAt || pos + len > winAt + win.length) {
        win = await reader.bytes(pos, Math.max(len, 1 << 20));
        winAt = pos;
      }
      return win.subarray(pos - winAt, pos - winAt + len);
    };

    // His Sds constructor.
    let index = 0;
    let lastOffset = 0;
    while (index < length) {
      if (ctx.signal?.aborted) return;
      if (index + 16 > length) break;
      // The header is 0x14 bytes; within 4 bytes of the end his read runs past it, taken here as zeros.
      const h = new Uint8Array(0x14);
      h.set(await view(index, 0x14));
      const hv = new DataView(h.buffer);
      const hash = [...h.subarray(0, 4)].map((x) => x.toString(16).toUpperCase().padStart(2, '0')).join('');
      const id = hv.getUint32(4, true);
      const offset = Number(hv.getBigUint64(8, true));
      let size = hv.getUint32(16, true);
      if (index === lastOffset && hash === '00000000' && id === 0 && offset === 0 && size === 0) {
        index += BLOCK; // nothing here, go to the next block
        continue;
      }
      lastOffset = index;
      if ((offset === 0 && size === 0) || offset > length) {
        // The rest of this block is empty. On a block boundary with anything
        // but zeros in the header, his walk reads the same entry for ever; this
        // moves on a block instead.
        const next = Math.ceil(index / BLOCK) * BLOCK;
        if (next === index && (hash !== '00000000' || id !== 0)) ctx.warn(index, 'an entry with no offset or size on a block boundary; skipping the block');
        index = next === index ? index + BLOCK : next;
        continue;
      }
      if (id > 0 && offset < length) {
        const dataSize = size - 0x14;
        if (dataSize < 0 || dataSize > length - lastOffset) {
          ctx.warn(index, `entry ${id} claims ${size} bytes, more than is left; his walk stops here`);
          break;
        }
        if (offset + 0x14 + dataSize > length) {
          ctx.warn(index, `entry ${id} points past the end of the stream (0x${offset.toString(16)}); stopping as his walk would`);
          break;
        }
        yield {
          Hash: hash,
          Id: id,
          Offset: offset,
          ...descriptor(await view(offset + 0x14, dataSize)),
          FileOffset: lastOffset,
          SourceFile: reader.name,
        };
      }
      if (size === 0) size = 16;
      index = Math.ceil((index + size) / 16) * 16;
    }
  },
};
