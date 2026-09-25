/**
 * $I30, a directory's index allocation: 4 KB INDX pages holding an entry for
 * each file in the directory, with entries for files since removed often
 * still readable in the slack past each page's live data.
 *
 * Ported from Eric Zimmerman's I30 library (https://github.com/EricZimmerman/MFT:
 * I30/I30.cs, MFT/Other/IndexEntryI30.cs, FileRecord.GetSlackFileEntries and
 * GetUnicodeHits) and MFTECmd's ProcessI30 and I30Out
 * (https://github.com/EricZimmerman/MFTECmd).
 */
import type { Column, ColType, Ctx, Parser, Reader, Row } from '../core/types';
import { magic } from '../core/binary';
import { dotnetFlags, entryInfo, fileInfo, NAME_TYPES, SI_FLAGS, toDate, type FileNameAttr } from './mft';

// I30Out, automapped in declaration order.
const columns: Column[] = [
  ['Offset', 'num'],
  ['FromSlack', 'bool'],
  ['SelfMftEntry', 'num'],
  ['SelfMftSequence', 'num'],
  ['FileName'],
  ['Flags'],
  ['NameType'],
  ['ParentMftEntry', 'num'],
  ['ParentMftSequence', 'num'],
  ['CreatedOn', 'date'],
  ['ContentModifiedOn', 'date'],
  ['RecordModifiedOn', 'date'],
  ['LastAccessedOn', 'date'],
  ['PhysicalSize', 'num'],
  ['LogicalSize', 'num'],
  ['SourceFile'],
].map(([key, type = 'str']) => ({ key, label: key.replace(/([a-z])([A-Z])/g, '$1 $2'), type: type as ColType }));

const PAGE = 0x1000;
const INDX = 0x58444e49;

function row(fi: FileNameAttr, offset: number, self: { entry: number; seq: number } | null, source: string): Row {
  return {
    Offset: offset,
    FromSlack: self === null,
    SelfMftEntry: self?.entry ?? null,
    SelfMftSequence: self?.seq ?? null,
    FileName: fi.name,
    Flags: dotnetFlags(fi.flags, SI_FLAGS, 'None'),
    NameType: NAME_TYPES[fi.nameType] ?? String(fi.nameType),
    ParentMftEntry: fi.parentEntry,
    ParentMftSequence: fi.parentSeq,
    CreatedOn: toDate(fi.created),
    ContentModifiedOn: toDate(fi.modified),
    RecordModifiedOn: toDate(fi.record),
    LastAccessedOn: toDate(fi.accessed),
    PhysicalSize: Number(fi.physicalSize),
    LogicalSize: Number(fi.logicalSize),
    SourceFile: source,
  };
}

const UTF16 = new TextDecoder('utf-16le');

/**
 * His GetSlackFileEntries. Slack is decoded as UTF-16 and searched for runs
 * of three or more printable ASCII characters; each run is taken to be a file
 * name, whose length byte sits two bytes before it and whose $FILE_NAME body
 * starts 0x42 bytes before it.
 */
function* slackEntries(slack: Uint8Array, startOffset: number) {
  for (const m of UTF16.decode(slack).matchAll(/[\x20-\x7e]{3,}/g)) {
    if (m[0].trim().length === 0) continue;
    const hit = (m.index ?? 0) * 2;
    if (hit === 0) continue; // nothing before it to read a length from
    const start = hit - 0x42;
    const end = hit + slack[hit - 2] * 2;
    if (start < 0 || end > slack.length) continue;
    const buf = slack.subarray(start, end);
    const fi = fileInfo(buf);
    // His clean-up of what is not plausibly a name.
    if (buf[0x40] === 0 || fi.flags < 0) continue;
    yield { buf, fi, offset: startOffset + start - 0x10 };
  }
}

export const i30: Parser = {
  id: 'i30',
  name: '$I30 (directory index)',
  ezTool: 'MFTECmd',
  extensions: [],
  columns,
  sniff: (head: Uint8Array, filename: string) => magic(head, 'INDX', 0) || /\$i30/i.test(filename),
  async *parse(reader: Reader, ctx: Ctx): AsyncGenerator<Row> {
    // Slack entries seen on an earlier page are not repeated; he keys them by MD5, this by their bytes.
    const seen = new Set<string>();
    for (let page = 0; page * PAGE < reader.size; page++) {
      if (ctx.signal?.aborted) return;
      const b = (await reader.bytes(page * PAGE, PAGE)).slice();
      const at = page * PAGE;
      if (b.length < 4) break;
      const dv = new DataView(b.buffer);
      const sig = dv.getInt32(0, true);
      if (sig === 0) {
        ctx.warn(at, `empty page at 0x${at.toString(16)}; skipped`);
        continue;
      }
      if (sig !== INDX) {
        // His reader stops the whole file here; this skips the page.
        ctx.warn(at, `page at 0x${at.toString(16)} does not start with INDX; skipped`);
        continue;
      }
      if (b.length < 0x28) {
        ctx.warn(at, `the last page is cut off after ${b.length} bytes`);
        break;
      }
      const pairs = dv.getInt16(6, true);
      const dataStart = dv.getInt32(0x18, true);
      const dataSize = dv.getInt32(0x1c, true);
      // He reads the fixup array from just after the header, 0x28, and the
      // entries from the next 8-byte boundary after it.
      const fixups = b.subarray(0x28, 0x28 + Math.max(0, pairs) * 2);
      const rawAt = Math.ceil((0x28 + fixups.length) / 8) * 8;
      const raw = b.subarray(rawAt);
      const rv = new DataView(raw.buffer, raw.byteOffset, raw.byteLength);
      // Sector ends are found relative to where the entries are said to start (0x18 + dataStart).
      for (let i = 1, counter = 512 - dataStart - 0x18; i < pairs; i++, counter += 512) {
        const off = counter - 2;
        if (off < 0 || off + 2 > raw.length || 2 * i + 2 > fixups.length) break;
        if (rv.getInt16(off, true) !== ((fixups[0] | (fixups[1] << 8)) << 16) >> 16) {
          ctx.warn(at + rawAt + off, `fixup value does not match at 0x${off.toString(16)} of page ${page}`);
        }
        raw[off] = fixups[2 * i];
        raw[off + 1] = fixups[2 * i + 1];
      }

      const activeLen = dataSize - dataStart;
      if (activeLen < 0 || activeLen > raw.length) {
        ctx.warn(at, `page ${page} claims ${dataSize} bytes of entries, more than the page holds; skipped`);
        continue;
      }
      const active = raw.subarray(0, activeLen);
      const av = new DataView(active.buffer, active.byteOffset, active.byteLength);
      for (let pos = 0; pos < active.length; ) {
        const offset = at + 0x18 + dataStart + pos;
        if (pos + 10 > active.length) break;
        const size = av.getInt16(pos + 8, true);
        const entry = active.subarray(pos, pos + Math.max(0, size));
        if (size <= 0) {
          ctx.warn(offset, `index entry of size ${size}; the rest of page ${page} is not read`);
          break;
        }
        pos += size;
        const self = entryInfo(new DataView(entry.buffer, entry.byteOffset, entry.byteLength), 0);
        if (self.entry === 0) continue; // the node's closing entry
        if (entry.length < 0x10 + 0x42) {
          ctx.warn(offset, `index entry of ${entry.length} bytes is too short to hold a file name; the rest of page ${page} is not read`);
          break;
        }
        yield row(fileInfo(entry.subarray(0x10)), offset, self, reader.name);
      }

      for (const s of slackEntries(raw.subarray(activeLen), at + 0x18 + dataStart + activeLen)) {
        const key = [...s.buf].join(',');
        if (seen.has(key)) continue;
        seen.add(key);
        yield row(s.fi, s.offset, null, reader.name);
      }
    }
  },
};
